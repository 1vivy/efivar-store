// SPDX-License-Identifier: GPL-2.0-only
/*
 * Kernel ABI only; the allocation-free Rust engine owns EFVS validation.
 * Backing I/O uses the credentials attached to the file by its opener.
 */
#include <linux/blkdev.h>
#include <linux/cred.h>
#include <linux/ctype.h>
#include <linux/efi.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/kernfs.h>
#include <linux/limits.h>
#include <linux/sysfs.h>
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
static char selected_uuid[37];
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
module_param(ready, bool, 0444);
MODULE_PARM_DESC(ready, "validated backing and registered EFI callbacks (read-only)");
MODULE_INFO(kernelsu_esp_name, "efivar_store");
MODULE_INFO(kernelsu_esp_version, "1");
MODULE_INFO(kernelsu_esp_abi, "1");
MODULE_INFO(kernelsu_esp_critical, "1");
static struct kobject *store_efi_kobj;
static bool own_mountpoint;

static void release_sysfs(void)
{
	if (own_mountpoint)
		sysfs_remove_mount_point(store_efi_kobj, "efivars");
	own_mountpoint = false;
	/* A native EFI object was only referenced, never removed. */
	kobject_put(store_efi_kobj);
	store_efi_kobj = NULL;
}

static int acquire_sysfs(void)
{
	struct kernfs_node *node;
	int rc;

	/* Native EFI sysfs is boot-lifetime; reference it through exported APIs. */
	node = sysfs_get_dirent(firmware_kobj->sd, "efi");
	if (node) {
		if (kernfs_type(node) != KERNFS_DIR || !node->priv) {
			sysfs_put(node);
			return -EINVAL;
		}
		store_efi_kobj = kobject_get_unless_zero(node->priv);
		sysfs_put(node);
	} else {
		store_efi_kobj = kobject_create_and_add("efi", firmware_kobj);
	}
	if (!store_efi_kobj)
		return -ENOMEM;
	rc = sysfs_create_mount_point(store_efi_kobj, "efivars");
	if (!rc)
		own_mountpoint = true;
	else if (rc != -EEXIST) {
		release_sysfs();
		return rc;
	}
	return 0;
}
static struct efivars vars;

struct block_scan {
	struct dir_context context;
	char name[NAME_MAX + 1];
	bool selected;
};

static bool next_block(struct dir_context *context, const char *name, int length,
		       loff_t offset, u64 inode, unsigned int type)
{
	struct block_scan *scan = container_of(context, struct block_scan, context);

	if (scan->selected)
		return false;
	if ((length == 1 && name[0] == '.') ||
	    (length == 2 && name[0] == '.' && name[1] == '.'))
		return true;
	if (length > NAME_MAX)
		return false;
	memcpy(scan->name, name, length);
	scan->name[length] = 0;
	scan->selected = true;
	return true;
}

static void put_lookup_file(struct file *file)
{
	const struct cred *old = override_creds(file->f_cred);

	fput(file);
	revert_creds(old);
}

static int partition_event(const char *name, const char *uuid, char *buffer, dev_t *result)
{
	char path[sizeof("/sys/class/block//uevent") + NAME_MAX];
	char *field, *cursor;
	struct file *file;
	const struct cred *old;
	loff_t pos = 0;
	ssize_t length;
	unsigned int major = 0, minor = 0;
	bool matched = false, have_uuid = false, have_major = false, have_minor = false;
	int rc = -ENODEV;

	snprintf(path, sizeof(path), "/sys/class/block/%s/uevent", name);
	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file) == -ENOENT ? -ENODEV : PTR_ERR(file);
	old = override_creds(file->f_cred);
	length = kernel_read(file, buffer, PAGE_SIZE - 1, &pos);
	revert_creds(old);
	put_lookup_file(file);
	if (length < 0)
		return length;
	if (length == PAGE_SIZE - 1)
		return -EOVERFLOW;
	buffer[length] = 0;
	cursor = buffer;
	while ((field = strsep(&cursor, "\n"))) {
		if (!strncmp(field, "PARTUUID=", 9)) {
			if (have_uuid)
				return -EINVAL;
			have_uuid = true;
			matched = strlen(field + 9) == 36 &&
				  !strncasecmp(field + 9, uuid, 36);
		} else if (!strncmp(field, "MAJOR=", 6)) {
			if (have_major || !field[6] ||
			    strspn(field + 6, "0123456789") != strlen(field + 6) ||
			    kstrtouint(field + 6, 10, &major))
				return -EINVAL;
			have_major = true;
		} else if (!strncmp(field, "MINOR=", 6)) {
			if (have_minor || !field[6] ||
			    strspn(field + 6, "0123456789") != strlen(field + 6) ||
			    kstrtouint(field + 6, 10, &minor))
				return -EINVAL;
			have_minor = true;
		}
	}
	if (matched) {
		if (!have_major || !have_minor || !major || major > 0xfff || minor > 0xfffff)
			rc = -EINVAL;
		else {
			*result = MKDEV(major, minor);
			rc = 0;
		}
	}
	return rc;
}

static int uuid_device(const char *uuid, dev_t *result)
{
	struct block_scan scan = { .context.actor = next_block };
	struct file *directory;
	const struct cred *old;
	char *buffer;
	dev_t candidate = 0, selected = 0;
	bool found = false;
	int i, rc;

	if (strlen(uuid) != 36)
		return -EINVAL;
	for (i = 0; i < 36; i++) {
		if (i == 8 || i == 13 || i == 18 || i == 23) {
			if (uuid[i] != '-')
				return -EINVAL;
		} else if (!isxdigit(uuid[i]))
			return -EINVAL;
	}
	directory = filp_open("/sys/class/block", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(directory))
		return PTR_ERR(directory);
	buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
	if (!buffer) {
		put_lookup_file(directory);
		return -ENOMEM;
	}
	for (;;) {
		scan.selected = false;
		old = override_creds(directory->f_cred);
		rc = iterate_dir(directory, &scan.context);
		revert_creds(old);
		if (rc)
			break;
		if (!scan.selected) {
			rc = found ? 0 : -ENODEV;
			if (found) {
				*result = selected;
				memcpy(selected_uuid, uuid, sizeof(selected_uuid));
			}
			break;
		}
		/* Never open/read another sysfs node inside its readdir lock. */
		rc = partition_event(scan.name, uuid, buffer, &candidate);
		if (!rc) {
			if (found) {
				rc = -EEXIST;
				break;
			}
			selected = candidate;
			found = true;
		} else if (rc != -ENODEV) {
			break;
		}
	}
	kfree(buffer);
	put_lookup_file(directory);
	return rc;
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
/* Override only actual backing-file I/O, never the EFI caller's other work. */
static int read_bytes(size_t offset, void *buffer, size_t len)
{
	loff_t pos = offset;
	const struct cred *old = override_creds(store_file->f_cred);
	ssize_t n = kernel_read(store_file, buffer, len, &pos);

	revert_creds(old);

	if (n == len)
		return 0;
	pr_err_ratelimited("efivar_store: kernel_read offset=%zu length=%zu returned %zd\n", offset,
			   len, n);
	return n < 0 ? n : -EIO;
}
static int write_bytes(size_t start, size_t end)
{
	loff_t pos = start;
	const struct cred *old = override_creds(store_file->f_cred);
	ssize_t n = kernel_write(store_file, image + start, end - start, &pos);
	int rc;

	revert_creds(old);

	if (n != end - start) {
		pr_err_ratelimited(
		    "efivar_store: kernel_write offset=%zu length=%zu returned %zd\n", start,
		    end - start, n);
		return n < 0 ? n : -EIO;
	}
	old = override_creds(store_file->f_cred);
	rc = vfs_fsync(store_file, 0);
	revert_creds(old);
	if (rc)
		pr_err_ratelimited("efivar_store: vfs_fsync failed: %d\n", rc);
	return rc;
}
static int reload(void)
{
	unsigned long status;
	int rc;

	ready = false;
	rc = read_bytes(0, image, image_len);
	if (rc) {
		pr_err_ratelimited("efivar_store: reload read failed: %d; callbacks disabled\n",
				   rc);
		return rc;
	}
	status = efvs_load(context, image, image_len, scratch, scratch_len);
	if (status) {
		pr_err_ratelimited(
		    "efivar_store: reload replay failed: EFI status=%#lx; callbacks disabled\n",
		    status);
		return -EINVAL;
	}
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
	if (store_file) {
		const struct cred *old = override_creds(store_file->f_cred);

		fput(store_file);
		store_file = NULL;
		revert_creds(old);
	}
	release_sysfs();
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
	efi_status_t status;
	int units = name_length(name, MAX_NAME);
	if (!guid || (size && !data) || size > MAX_IMAGE || units <= 0)
		return EFI_INVALID_PARAMETER;
	mutex_lock(&store_lock);
	status = ready ? efvs_set(context, (u8 *)name, units * 2, guid, attr, size ? data : &empty,
				  size, &start, &end)
		       : EFI_DEVICE_ERROR;
	if (status)
		goto out;
	if (write_bytes(start, end))
		goto io_error;
	/* Verify exactly the appended range, without another large allocation. */
	for (pos = start; pos < end; pos += chunk) {
		chunk = min_t(size_t, sizeof(verify), end - pos);
		if (read_bytes(pos, verify, chunk)) {
			pr_err_ratelimited("efivar_store: verify read failed at offset=%zu\n", pos);
			goto io_error;
		}
		if (memcmp(verify, image + pos, chunk)) {
			pr_err_ratelimited("efivar_store: verify mismatch offset=%zu length=%zu\n",
					   pos, chunk);
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
	struct block_device *backing;
	int rc = discover_device(&device);
	/* Output-only even if the loader supplies ready=1. */
	ready = false;
	if (rc)
		return rc;
	/* Own the backing for the callback lifetime, like other block consumers. */
	store_file = bdev_file_open_by_dev(device, BLK_OPEN_READ | BLK_OPEN_WRITE,
					 THIS_MODULE, NULL);
	if (IS_ERR(store_file)) {
		rc = PTR_ERR(store_file);
		pr_err("efivar_store: backing device open failed: %d\n", rc);
		store_file = NULL;
		release_store();
		return rc;
	}
	/* A hotplug/reused dev_t must not turn UUID selection into another store. */
	backing = file_bdev(store_file);
	if (selected_uuid[0] &&
	    (!backing->bd_meta_info ||
	     strncasecmp(backing->bd_meta_info->uuid, selected_uuid, 36))) {
		release_store();
		return -ENODEV;
	}
	rc = load();
	if (rc) {
		pr_err("efivar_store: no usable EFVS store; firmware must initialize blank "
		       "partitions (no bytes written)\n");
		release_store();
		return rc;
	}
	rc = acquire_sysfs();
	if (rc) {
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
MODULE_INFO(import_ns, "VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
MODULE_AUTHOR("efivar-store contributors");
MODULE_DESCRIPTION("Block-backed EFI variable service using the efivar-store Rust engine");
