#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/string.h>
#include <linux/numa.h>
#include <linux/highmem.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/bio.h>
#include <linux/crypto.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <linux/random.h>
#include <linux/debugfs.h>

#define ERD_NAME "enc_ramdisk"
#define ERD_SECTOR_SHIFT 9
#define ERD_SECTOR_SIZE (1U << ERD_SECTOR_SHIFT)
#define ERD_MINORS 1
#define ERD_KEY_SIZE 64

static unsigned long erd_size_mb = 64;
module_param(erd_size_mb, ulong, 0444);
MODULE_PARM_DESC(erd_size_mb, "Size of the encrypted RAM disk in megabytes");

struct erd_device {
	struct gendisk *disk;
	struct blk_mq_tag_set tag_set;
	spinlock_t lock;
	void *data;
	sector_t capacity;
	struct crypto_skcipher *tfm;
	u8 key[ERD_KEY_SIZE];
};

static int erd_major;
static struct erd_device *erd_dev;
static struct dentry *erd_debugfs_dir;

static int erd_crypt_sector(struct erd_device *dev, sector_t sector,
			     void *dst, void *src, bool encrypt)
{
	struct skcipher_request *req;
	struct scatterlist sg_src, sg_dst;
	DECLARE_CRYPTO_WAIT(wait);
	u8 iv[16];
	int ret;

	req = skcipher_request_alloc(dev->tfm, GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	memset(iv, 0, sizeof(iv));
	*(__le64 *)iv = cpu_to_le64((u64)sector);

	sg_init_one(&sg_src, src, ERD_SECTOR_SIZE);
	sg_init_one(&sg_dst, dst, ERD_SECTOR_SIZE);

	skcipher_request_set_callback(req,
		CRYPTO_TFM_REQ_MAY_SLEEP | CRYPTO_TFM_REQ_MAY_BACKLOG,
		crypto_req_done, &wait);
	skcipher_request_set_crypt(req, &sg_src, &sg_dst, ERD_SECTOR_SIZE, iv);

	ret = crypto_wait_req(encrypt ? crypto_skcipher_encrypt(req)
				      : crypto_skcipher_decrypt(req), &wait);

	skcipher_request_free(req);
	return ret;
}

static blk_status_t erd_queue_rq(struct blk_mq_hw_ctx *hctx,
				  const struct blk_mq_queue_data *bd)
{
	struct request *rq = bd->rq;
	struct erd_device *dev = hctx->queue->queuedata;
	struct bio_vec bvec;
	struct req_iterator iter;
	sector_t sector = blk_rq_pos(rq);
	blk_status_t status = BLK_STS_OK;
	int ret = 0;

	blk_mq_start_request(rq);

	rq_for_each_segment(bvec, rq, iter) {
		void *page_addr = kmap_local_page(bvec.bv_page);
		void *buf = page_addr + bvec.bv_offset;
		unsigned int len = bvec.bv_len;
		unsigned int off = 0;

		while (off < len) {
			void *disk_ptr = dev->data + (sector << ERD_SECTOR_SHIFT);

			if (rq_data_dir(rq) == WRITE)
				ret = erd_crypt_sector(dev, sector, disk_ptr, buf + off, true);
			else
				ret = erd_crypt_sector(dev, sector, buf + off, disk_ptr, false);

			if (ret)
				break;

			sector++;
			off += ERD_SECTOR_SIZE;
		}

		kunmap_local(page_addr);

		if (ret)
			break;
	}

	if (ret)
		status = BLK_STS_IOERR;

	blk_mq_end_request(rq, status);
	return BLK_STS_OK;
}

static const struct blk_mq_ops erd_mq_ops = {
	.queue_rq = erd_queue_rq,
};

static const struct block_device_operations erd_fops = {
	.owner = THIS_MODULE,
};

static ssize_t erd_raw_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	struct erd_device *dev = file->private_data;
	loff_t max = (loff_t)dev->capacity << ERD_SECTOR_SHIFT;

	return simple_read_from_buffer(buf, count, ppos, dev->data, max);
}

static int erd_raw_open(struct inode *inode, struct file *file)
{
	file->private_data = erd_dev;
	return 0;
}

static const struct file_operations erd_raw_fops = {
	.owner = THIS_MODULE,
	.open = erd_raw_open,
	.read = erd_raw_read,
};

static int erd_setup_crypto(struct erd_device *dev)
{
	int ret;

	dev->tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
	if (IS_ERR(dev->tfm))
		return PTR_ERR(dev->tfm);

	get_random_bytes(dev->key, ERD_KEY_SIZE);

	ret = crypto_skcipher_setkey(dev->tfm, dev->key, ERD_KEY_SIZE);
	if (ret) {
		crypto_free_skcipher(dev->tfm);
		return ret;
	}

	return 0;
}

static int __init erd_init(void)
{
	int ret;

	if (erd_size_mb == 0)
		return -EINVAL;

	erd_dev = kzalloc(sizeof(*erd_dev), GFP_KERNEL);
	if (!erd_dev)
		return -ENOMEM;

	spin_lock_init(&erd_dev->lock);
	erd_dev->capacity = (erd_size_mb * 1024UL * 1024UL) >> ERD_SECTOR_SHIFT;

	erd_dev->data = vzalloc((size_t)erd_dev->capacity << ERD_SECTOR_SHIFT);
	if (!erd_dev->data) {
		ret = -ENOMEM;
		goto out_free_dev;
	}

	ret = erd_setup_crypto(erd_dev);
	if (ret)
		goto out_free_data;

	erd_major = register_blkdev(0, ERD_NAME);
	if (erd_major < 0) {
		ret = erd_major;
		goto out_free_crypto;
	}

	erd_dev->tag_set.ops = &erd_mq_ops;
	erd_dev->tag_set.nr_hw_queues = 1;
	erd_dev->tag_set.queue_depth = 128;
	erd_dev->tag_set.numa_node = NUMA_NO_NODE;
	erd_dev->tag_set.flags = BLK_MQ_F_SHOULD_MERGE | BLK_MQ_F_BLOCKING;

	ret = blk_mq_alloc_tag_set(&erd_dev->tag_set);
	if (ret)
		goto out_unregister;

	erd_dev->disk = blk_mq_alloc_disk(&erd_dev->tag_set, erd_dev);
	if (IS_ERR(erd_dev->disk)) {
		ret = PTR_ERR(erd_dev->disk);
		goto out_free_tags;
	}

	erd_dev->disk->major = erd_major;
	erd_dev->disk->first_minor = 0;
	erd_dev->disk->minors = ERD_MINORS;
	erd_dev->disk->flags |= GENHD_FL_NO_PART;
	erd_dev->disk->fops = &erd_fops;
	erd_dev->disk->private_data = erd_dev;
	snprintf(erd_dev->disk->disk_name, DISK_NAME_LEN, "%s0", ERD_NAME);

	set_capacity(erd_dev->disk, erd_dev->capacity);
	blk_queue_logical_block_size(erd_dev->disk->queue, ERD_SECTOR_SIZE);
	blk_queue_physical_block_size(erd_dev->disk->queue, ERD_SECTOR_SIZE);
	blk_queue_flag_set(QUEUE_FLAG_NONROT, erd_dev->disk->queue);

	ret = add_disk(erd_dev->disk);
	if (ret)
		goto out_cleanup_disk;

	erd_debugfs_dir = debugfs_create_dir(ERD_NAME, NULL);
	debugfs_create_file("raw_ciphertext", 0400, erd_debugfs_dir,
			     erd_dev, &erd_raw_fops);

	pr_info("%s: loaded, capacity=%llu sectors (%lu MB), cipher=xts(aes)\n",
		ERD_NAME, (unsigned long long)erd_dev->capacity, erd_size_mb);

	return 0;

out_cleanup_disk:
	put_disk(erd_dev->disk);
out_free_tags:
	blk_mq_free_tag_set(&erd_dev->tag_set);
out_unregister:
	unregister_blkdev(erd_major, ERD_NAME);
out_free_crypto:
	crypto_free_skcipher(erd_dev->tfm);
out_free_data:
	vfree(erd_dev->data);
out_free_dev:
	kfree(erd_dev);
	return ret;
}

static void __exit erd_exit(void)
{
	debugfs_remove_recursive(erd_debugfs_dir);
	del_gendisk(erd_dev->disk);
	put_disk(erd_dev->disk);
	blk_mq_free_tag_set(&erd_dev->tag_set);
	unregister_blkdev(erd_major, ERD_NAME);
	crypto_free_skcipher(erd_dev->tfm);
	memzero_explicit(erd_dev->key, ERD_KEY_SIZE);
	vfree(erd_dev->data);
	kfree(erd_dev);
	pr_info("%s: unloaded\n", ERD_NAME);
}

module_init(erd_init);
module_exit(erd_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("AES-XTS encrypted volatile RAM-backed block device");
