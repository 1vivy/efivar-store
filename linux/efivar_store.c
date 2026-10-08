// SPDX-License-Identifier: GPL-2.0-only
/* Kernel ABI only; the allocation-free Rust engine owns EFVS validation. */
#include <linux/blkdev.h>
#include <linux/ctype.h>
#include <linux/efi.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/unaligned.h>
#include <linux/vmalloc.h>

#define MAX_IMAGE (16 * 1024 * 1024)
#define MAX_NAME 512
extern size_t efvs_ctx_size(void);
extern unsigned long efvs_scratch_size(const u8 *, size_t, size_t *);
extern unsigned long efvs_load(void *, u8 *, size_t, u8 *, size_t);
extern unsigned long efvs_get(const void *, const u8 *, size_t, const void *, u32 *, const u8 **,
			      size_t *);
extern unsigned long efvs_next(const void *, const u8 *, size_t, const void *, const u8 **,
			       size_t *, void *);
extern unsigned long efvs_set(void *, const u8 *, size_t, const void *, u32, const u8 *, size_t,
			      size_t *, size_t *);
extern unsigned long efvs_query(const void *, u32, u64 *, u64 *, u64 *);
void __noreturn efvs_panic(void);
void __noreturn efvs_panic(void)
{
	panic("efivar_store: engine invariant failure");
}

static char *dev, *partuuid;
module_param(dev, charp, 0);
MODULE_PARM_DESC(dev, "Backing block device as major:minor");
module_param(partuuid, charp, 0);
MODULE_PARM_DESC(partuuid, "Backing partition unique GUID");
static DEFINE_MUTEX(store_lock);
static struct file *store_file;
static void *context;
static u8 *image, *scratch;
static size_t image_len, scratch_len;
static bool ready;
static struct efivars vars;

static int match_partition(struct device *device, const void *value)
{
	struct block_device *bdev = dev_to_bdev(device);
	return bdev->bd_meta_info && !strncasecmp(bdev->bd_meta_info->uuid, value, 36);
}
static int uuid_device(const char *uuid, dev_t *result)
{
	struct device *device;
	int i;
	if (strlen(uuid) != 36)
		return -EINVAL;
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (uuid[i] != '-')
				return -EINVAL;
		} else if (!isxdigit(uuid[i]))
			return -EINVAL;
	}
	device = class_find_device(&block_class, NULL, uuid, match_partition);
	if (!device)
		return -ENODEV;
	*result = dev_to_bdev(device)->bd_dev;
	put_device(device);
	return 0;
}
static int discover_device(dev_t *result)
{
	struct device_node *chosen;
	const char *uuid;
	unsigned int major = 0, minor = 0;
	const char *p;
	int rc;
	if (dev && partuuid)
		return -EINVAL;
	if (dev) {
		p = dev;
		if (!isdigit(*p))
			return -EINVAL;
		while (isdigit(*p)) {
			if (major > 0xfff / 10)
				return -EINVAL;
			major = major * 10 + (*p++ - '0');
		}
		if (*p++ != ':' || !isdigit(*p))
			return -EINVAL;
		while (isdigit(*p)) {
			if (minor > 0xfffff / 10)
				return -EINVAL;
			minor = minor * 10 + (*p++ - '0');
		}
		if (*p || !major || major > 0xfff || minor > 0xfffff)
			return -EINVAL;
		*result = MKDEV(major, minor);
		return 0;
	}
	if (partuuid)
		return uuid_device(partuuid, result);
	chosen = of_find_node_by_path("/chosen");
	if (!chosen)
		return -ENODEV;
	rc = of_property_read_string(chosen, "efivar-store,partuuid", &uuid);
	rc = rc ? -ENODEV : uuid_device(uuid, result);
	of_node_put(chosen);
	return rc;
}
static int read_bytes(size_t offset, void *buffer, size_t len)
{
	loff_t pos = offset;
	ssize_t n = kernel_read(store_file, buffer, len, &pos);
	return n == len ? 0 : n < 0 ? n : -EIO;
}
static int reload(void)
{
	ready = false;
	if (read_bytes(0, image, image_len))
		return -EIO;
	if (efvs_load(context, image, image_len, scratch, scratch_len))
		return -EINVAL;
	ready = true;
	return 0;
}
static int load(void)
{
	u8 header[64];
	size_t offset, length = 0;
	u64 n;
	int shift, rc;
	/* Both headers, including small stores and a torn A header. */
	for (shift = 8; shift <= 16; shift++) {
		offset = shift == 8 ? 0 : 1UL << shift;
		if (read_bytes(offset, header, sizeof(header)))
			continue;
		if (memcmp(header, "EFVS", 4))
			continue;
		n = get_unaligned_le64(header + 8);
		if (n >= offset + sizeof(header) && n <= MAX_IMAGE)
			length = max_t(size_t, length, n);
	}
	if (!length)
		return -EINVAL;
	image_len = length;
	image = kvmalloc(image_len, GFP_KERNEL);
	if (!image)
		return -ENOMEM;
	rc = read_bytes(0, image, image_len);
	if (rc)
		return rc;
	if (efvs_scratch_size(image, image_len, &scratch_len))
		return -EINVAL;
	scratch = kvmalloc(scratch_len, GFP_KERNEL);
	context = kzalloc(efvs_ctx_size(), GFP_KERNEL);
	if (!scratch || !context)
		return -ENOMEM;
	return reload();
}
static void release_store(void)
{
	ready = false;
	kfree(context);
	kvfree(scratch);
	kvfree(image);
	if (store_file)
		fput(store_file);
}
static int name_length(const u16 *name, size_t bound)
{
	size_t i;
	if (!name)
		return -1;
	for (i = 0; i < bound; i++)
		if (!name[i])
			return i;
	return -1;
}
static efi_status_t get_variable(efi_char16_t *name, efi_guid_t *guid, u32 *attr,
				 unsigned long *size, void *data)
{
	const u8 *value;
	size_t length, available;
	u32 attributes;
	efi_status_t status;
	int units = name_length(name, MAX_NAME);
	if (!guid || !size || units <= 0)
		return EFI_INVALID_PARAMETER;
	mutex_lock(&store_lock);
	status = ready
		     ? efvs_get(context, (u8 *)name, units * 2, guid, &attributes, &value, &length)
		     : EFI_DEVICE_ERROR;
	if (!status) {
		available = *size;
		*size = length;
		if (attr)
			*attr = attributes;
		if (available < length)
			status = EFI_BUFFER_TOO_SMALL;
		else if (!data && length)
			status = EFI_INVALID_PARAMETER;
		else if (length)
			memcpy(data, value, length);
	}
	mutex_unlock(&store_lock);
	return status;
}
static efi_status_t next_variable(unsigned long *size, efi_char16_t *name, efi_guid_t *guid)
{
	const u8 *next;
	efi_guid_t next_guid;
	size_t length, available;
	efi_status_t status;
	int units;
	if (!size || !name || !guid || *size < 2 || *size % 2)
		return EFI_INVALID_PARAMETER;
	available = *size;
	units = name_length(name, min_t(size_t, available / 2, MAX_NAME));
	if (units < 0)
		return EFI_INVALID_PARAMETER;
	mutex_lock(&store_lock);
	status = ready ? efvs_next(context, (u8 *)name, units * 2, guid, &next, &length, &next_guid)
		       : EFI_DEVICE_ERROR;
	if (!status) {
		*size = length + 2;
		if (available < length + 2)
			status = EFI_BUFFER_TOO_SMALL;
		else {
			memcpy(name, next, length);
			name[length / 2] = 0;
			*guid = next_guid;
		}
	}
	mutex_unlock(&store_lock);
	return status;
}
static efi_status_t set_variable(efi_char16_t *name, efi_guid_t *guid, u32 attr, unsigned long size,
				 void *data)
{
	static const u8 empty;
	u8 verify[512];
	size_t start, end, pos, chunk;
	loff_t offset;
	ssize_t n;
	efi_status_t status;
	int units = name_length(name, MAX_NAME);
	if (!guid || (size && !data) || size > MAX_IMAGE || units <= 0)
		return EFI_INVALID_PARAMETER;
	mutex_lock(&store_lock);
	status = ready ? efvs_set(context, (u8 *)name, units * 2, guid, attr, size ? data : &empty,
				  size, &start, &end)
		       : EFI_DEVICE_ERROR;
	if (!status) {
		offset = start;
		n = kernel_write(store_file, image + start, end - start, &offset);
		if (n != end - start || vfs_fsync(store_file, 0))
			goto io_error;
		/* Verify exactly the appended range, without another large allocation. */
		for (pos = start; pos < end; pos += chunk) {
			chunk = min_t(size_t, sizeof(verify), end - pos);
			if (read_bytes(pos, verify, chunk) || memcmp(verify, image + pos, chunk))
				goto io_error;
		}
	}
	goto out;
io_error:
	reload(); /* A failed reload leaves callbacks disabled. */
	status = EFI_DEVICE_ERROR;
out:
	mutex_unlock(&store_lock);
	return status;
}
static efi_status_t query_info(u32 attr, u64 *capacity, u64 *remaining, u64 *largest)
{
	efi_status_t status;
	if (!capacity || !remaining || !largest)
		return EFI_INVALID_PARAMETER;
	if (attr != 7)
		return attr & ~7 ? EFI_UNSUPPORTED : EFI_INVALID_PARAMETER;
	mutex_lock(&store_lock);
	status = ready ? efvs_query(context, attr, capacity, remaining, largest) : EFI_DEVICE_ERROR;
	mutex_unlock(&store_lock);
	return status;
}
static const struct efivar_operations ops = {
    .get_variable = get_variable,
    .get_next_variable = next_variable,
    .set_variable = set_variable,
    .query_variable_info = query_info,
};
static int __init efivar_store_init(void)
{
	dev_t device;
	int rc = discover_device(&device);
	if (rc)
		return rc;
	store_file = bdev_file_open_by_dev(device, BLK_OPEN_READ | BLK_OPEN_WRITE, NULL, NULL);
	if (IS_ERR(store_file)) {
		rc = PTR_ERR(store_file);
		store_file = NULL;
		return rc;
	}
	rc = load();
	if (rc) {
		pr_err("efivar_store: no usable EFVS store; firmware must initialize blank "
		       "partitions (no bytes written)\n");
		release_store();
		return rc;
	}
	efivars_generic_ops_unregister();
	rc = efivars_register(&vars, &ops);
	if (rc) {
		efivars_generic_ops_register();
		release_store();
		return rc;
	}
	pr_info("efivar_store: registered block-backed efivars (dev=%u:%u)\n", MAJOR(device),
		MINOR(device));
	return 0;
}
static void __exit efivar_store_exit(void)
{
	efivars_unregister(&vars);
	efivars_generic_ops_register();
	mutex_lock(&store_lock);
	release_store();
	mutex_unlock(&store_lock);
}
module_init(efivar_store_init);
module_exit(efivar_store_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("efivar-store contributors");
MODULE_DESCRIPTION("Block-backed EFI variable service using the efivar-store Rust engine");
