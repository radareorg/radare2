/* radare - LGPL - Copyright 2015-2019 - pancake */

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

#define ADD_REMAINDER(val, aln) ((val) + ((aln) != 0 ? ((val) % (aln)) : 0))
#define ROUND_DOWN(val, aln) ((aln) != 0 ? (((val) / (aln)) * (aln)) : (val))

R_PACKED (
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
});

typedef struct {
	Sdb *kv;
	BootImage bi;
	RBuffer *buf;
} BootImageObj;

static int bootimg_header_load(BootImageObj *obj, Sdb *db) {
	char *n;
	int i;
	if (r_buf_size (obj->buf) < sizeof (BootImage)) {
		return false;
	}
	// TODO make it endian-safe (void)r_buf_fread_at (buf, 0, (ut8*)bi, "IIiiiiiiiiiiii", 1);
	BootImage *bi = &obj->bi;
	(void) r_buf_read_at (obj->buf, 0, (ut8 *)bi, sizeof (BootImage));
	if ((n = r_str_ndup ((char *) bi->name, BOOT_NAME_SIZE))) {
		sdb_set (db, "name", n, 0);
		free (n);
	}
	if ((n = r_str_ndup ((char *) bi->cmdline, BOOT_ARGS_SIZE))) {
		sdb_set (db, "cmdline", n, 0);
		free (n);
	}
	for (i = 0; i < 8; i++) {
		sdb_num_set (db, "id", (ut64) bi->id[i], 0);
	}
	if ((n = r_str_ndup ((char *) bi->extra_cmdline, BOOT_EXTRA_ARGS_SIZE))) {
		sdb_set (db, "extra_cmdline", n, 0);
		free (n);
	}
	return true;
}

static Sdb *get_sdb(RBinFile *bf) {
	RBinObject *o = bf->o;
	BootImageObj *ao;
	if (!o) {
		return NULL;
	}
	ao = o->bin_obj;
	return ao? ao->kv: NULL;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	BootImageObj *bio = R_NEW0 (BootImageObj);
	if (!bio) {
		return false;
	}
	bio->kv = sdb_new0 ();
	if (!bio->kv) {
		free (bio);
		return false;
	}
	bio->buf = r_buf_ref (buf);
	if (!bootimg_header_load (bio, bio->kv)) {
		free (bio);
		return false;
	}
	sdb_ns_set (sdb, "info", bio->kv);
	*bin_obj = bio;
	return true;
}

static void destroy(RBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	r_buf_free (bio->buf);
	R_FREE (bf->o->bin_obj);
}

static ut64 baddr(RBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	return bio? bio->bi.kernel_addr: 0;
}

static RList *strings(RBinFile *bf) {
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret;
	if (!bf || !bf->o || !bf->o->bin_obj) {
		return NULL;
	}
	ret = R_NEW0 (RBinInfo);
	if (!ret) {
		return NULL;
	}

	ret->lang = NULL;
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("Android Boot Image");
	ret->os = strdup ("android");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("arm");
	ret->arch = strdup ("arm");
	ret->has_va = 1;
	ret->has_pi = 0;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	ret->rclass = strdup ("image");
	return ret;
}

static bool check_buffer(RBuffer *buf) {
	ut8 tmp[13];
	int r = r_buf_read_at (buf, 0, tmp, sizeof (tmp));
	return r > 12 && !strncmp ((const char *)tmp, "ANDROID!", 8);
}

static RList *entries(RBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	RBinAddr *ptr = NULL;
	if (!bio) {
		return NULL;
	}
	BootImage *bi = &bio->bi;
	RList *ret;

	if (!(ret = r_list_newf (free))) {
		return NULL;
	}
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = bi->page_size;
	ptr->vaddr = bi->kernel_addr;
	r_list_append (ret, ptr);
	return ret;
}

static RList *sections(RBinFile *bf) {
	BootImageObj *bio = bf->o->bin_obj;
	if (!bio) {
		return NULL;
	}
	BootImage *bi = &bio->bi;
	RList *ret = NULL;
	RBinSection *ptr = NULL;

	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("header");
	ptr->size = sizeof (BootImage);
	ptr->vsize = bi->page_size;
	ptr->paddr = 0;
	ptr->vaddr = 0;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);

	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("kernel");
	ptr->size = bi->kernel_size;
	ptr->vsize = ADD_REMAINDER (ptr->size, bi->page_size);
	ptr->paddr = bi->page_size;
	ptr->vaddr = bi->kernel_addr;
	ptr->perm = R_PERM_R; // r--
	ptr->add = true;
	r_list_append (ret, ptr);

	if (bi->ramdisk_size > 0) {
		ut64 base = bi->kernel_size + 2 * bi->page_size - 1;
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("ramdisk");
		ptr->size = bi->ramdisk_size;
		ptr->vsize = ADD_REMAINDER (bi->ramdisk_size, bi->page_size);
		ptr->paddr = ROUND_DOWN (base, bi->page_size);
		ptr->vaddr = bi->ramdisk_addr;
		ptr->perm = R_PERM_RX; // r-x
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	if (bi->second_size > 0) {
		ut64 base = bi->kernel_size + bi->ramdisk_size + 2 * bi->page_size - 1;
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("second");
		ptr->size = bi->second_size;
		ptr->vsize = ADD_REMAINDER (bi->second_size, bi->page_size);
		ptr->paddr = ROUND_DOWN (base, bi->page_size);
		ptr->vaddr = bi->second_addr;
		ptr->perm = R_PERM_RX; // r-x
		ptr->add = true;
		r_list_append (ret, ptr);
	}

	return ret;
}

RBinPlugin r_bin_plugin_bootimg = {
	.name = "bootimg",
	.desc = "Android Boot Image",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.sections = &sections,
	.entries = entries,
	.strings = &strings,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bootimg,
	.version = R2_VERSION
};
#endif
