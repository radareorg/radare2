/* radare - LGPL - Copyright 2015 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

typedef struct boot_img_hdr BootImage;

#define BOOT_MAGIC "ANDROID!"
#define BOOT_MAGIC_SIZE 8
#define BOOT_NAME_SIZE 16
#define BOOT_ARGS_SIZE 512
#define BOOT_EXTRA_ARGS_SIZE 1024

struct boot_img_hdr {
	ut8 magic[BOOT_MAGIC_SIZE];

	ut32 kernel_size;  /* size in bytes */
	ut32 kernel_addr;  /* physical load addr */

	ut32 ramdisk_size; /* size in bytes */
	ut32 ramdisk_addr; /* physical load addr */

	ut32 second_size;  /* size in bytes */
	ut32 second_addr;  /* physical load addr */

	ut32 tags_addr;    /* physical addr for kernel tags */
	ut32 page_size;    /* flash page size we assume */
	ut32 unused[2];    /* future expansion: should be 0 */
	ut8 name[BOOT_NAME_SIZE]; /* asciiz product name */
	ut8 cmdline[BOOT_ARGS_SIZE];
	ut32 id[8]; /* timestamp / checksum / sha1 / etc */

	/* Supplemental command line data; kept here to maintain
	 * binary compatibility with older versions of mkbootimg */
	ut8 extra_cmdline[BOOT_EXTRA_ARGS_SIZE];
} __attribute__((packed));

typedef struct {
	Sdb *kv;
	BootImage bi;
} BootImageObj;

static int bootimg_header_load(BootImage *bi, RBuffer *buf, Sdb *db) {
	char *n;
	int i;
	if (r_buf_size (buf) < sizeof (BootImage)) {
		return false;
	}
	// TODO make it endian-safe (void)r_buf_fread_at (buf, 0, (ut8*)bi, "IIiiiiiiiiiiii", 1);
	(void)r_buf_read_at (buf, 0, (ut8*)bi, sizeof (BootImage)); 
	if ((n = r_str_ndup ((char*)bi->name, BOOT_NAME_SIZE))) {
		sdb_set (db, "name", n, 0);
		free (n);
	}
	if ((n = r_str_ndup ((char*)bi->cmdline, BOOT_ARGS_SIZE))) {
		sdb_set (db, "cmdline", n, 0);
		free (n);
	}
	for (i=0; i<8; i++) {
		sdb_num_set (db, "id", (ut64)bi->id[i], 0);
	}
	if ((n = r_str_ndup ((char*)bi->extra_cmdline, BOOT_EXTRA_ARGS_SIZE))) {
		sdb_set (db, "extra_cmdline", n, 0);
		free (n);
	}
	return true;
}

static Sdb* get_sdb (RBinObject *o) {
	BootImageObj *ao;
	if (!o) return NULL;
	ao = o->bin_obj;
	if (!ao) return NULL;
	return ao->kv;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 la, Sdb *sdb) {
	BootImageObj *bio = R_NEW0 (BootImageObj);
	if (!bio) return NULL;
	bio->kv = sdb_new0 ();
	if (!bio->kv) {
		free (bio);
		return NULL;
	}
	bootimg_header_load (&bio->bi, arch->buf, bio->kv);
	sdb_ns_set (sdb, "info", bio->kv);
	return bio;
}

static int load(RBinFile *arch) {
	return true;
}

static int destroy(RBinFile *arch) {
	return true;
}

static ut64 baddr(RBinFile *arch) {
	BootImageObj *bio = arch->o->bin_obj;
	return bio? bio->bi.kernel_addr: 0;
}

static RList *strings(RBinFile *arch) {
	return NULL;
}

static RBinInfo* info(RBinFile *arch) {
	//BootImageObj *bio;
	RBinInfo *ret;
	if (!arch || !arch->o || !arch->o->bin_obj)
		return NULL;
	ret = R_NEW0 (RBinInfo);
	if (!ret) return NULL;

	ret->lang = NULL;
	ret->file = arch->file? strdup (arch->file): NULL;
	ret->type = strdup ("Android Boot Image");
	ret->os = strdup ("android");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("arm");
	ret->arch = strdup ("arm");
	ret->has_va = 1;
	ret->has_pi = 0;
	ret->bits = 16; // 32? 64?
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->rclass = strdup ("image");
	#if 0
	//bootimg_header_load (&art, arch->buf);
	bio = arch->o->bin_obj;
	#endif
	return ret;
}

static int check_bytes(const ut8 *buf, ut64 length) {
	return (buf && length>12 && !strncmp ((const char *)buf, "ANDROID!", 8));
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static RList* entries(RBinFile *arch) {
	BootImageObj *bio = arch->o->bin_obj;
	RBinAddr *ptr = NULL;
	if (!bio) return NULL;
	BootImage *bi = &bio->bi;
	RList *ret;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr)))
		return ret;
	ptr->paddr = bi->page_size;
	ptr->vaddr = bi->kernel_addr;
	r_list_append (ret, ptr);
	return ret;
}

static RList* sections(RBinFile *arch) {
	ut64 base;
	BootImageObj *bio = arch->o->bin_obj;
	if (!bio) return NULL;
	BootImage *bi = &bio->bi;
	RList *ret = NULL;
	RBinSection *ptr = NULL;

	if (!(ret = r_list_new ()))
		return NULL;
	ret->free = free;

	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	strncpy (ptr->name, "header", R_BIN_SIZEOF_STRINGS);
	ptr->size = sizeof (BootImage);
	ptr->vsize = bi->page_size;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP; // r--
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection)))
		return ret;
	base = bi->page_size;
	strncpy (ptr->name, "kernel", R_BIN_SIZEOF_STRINGS);
	ptr->size = bi->kernel_size;
	ptr->vsize = ptr->size + (ptr->size % bi->page_size);
	ptr->paddr = base;
	ptr->vaddr = bi->kernel_addr;
	ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_MAP; // r--
	ptr->add = true;
	r_list_append (ret, ptr);

	if (bi->ramdisk_size > 0) {
		base = ((bi->kernel_size + 2*bi->page_size -1) / bi->page_size) * bi->page_size;
		if (!(ptr = R_NEW0 (RBinSection)))
			return ret;
		strncpy (ptr->name, "ramdisk", R_BIN_SIZEOF_STRINGS);
		ptr->size = bi->ramdisk_size;
		ptr->vsize = bi->ramdisk_size + (bi->ramdisk_size % bi->page_size);
		ptr->paddr = base;
		ptr->vaddr = bi->ramdisk_addr;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	if (bi->second_size>0) {
		base = ((bi->kernel_size + bi->ramdisk_size + 2*bi->page_size -1) / bi->page_size) * bi->page_size;
		if (!(ptr = R_NEW0 (RBinSection)))
			return ret;
		strncpy (ptr->name, "second", R_BIN_SIZEOF_STRINGS);
		ptr->size = bi->second_size;
		ptr->vsize = bi->second_size + (bi->second_size % bi->page_size);
		ptr->paddr = base;
		ptr->vaddr = bi->second_addr;
		ptr->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP; // r-x
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	return ret;
}

struct r_bin_plugin_t r_bin_plugin_bootimg = {
	.name = "bootimg",
	.desc = "Android Boot Image",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.sections = &sections,
	.entries = entries,
	.strings = &strings,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bootimg,
	.version = R2_VERSION
};
#endif
