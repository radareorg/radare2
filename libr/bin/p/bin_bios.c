/* radare - LGPL - Copyright 2013-2018 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static bool check_bytes(const ut8 *buf, ut64 length) {
	if (buf && length > 0xffff && buf[0] != 0xcf && buf[0] != 0x7f) {
		const ut32 ep = length - 0x10000 + 0xfff0; /* F000:FFF0 address */
		/* hacky check to avoid detecting multidex bins as bios */
		/* need better fix for this */
		if (!memcmp (buf, "dex", 3)) {
			return false;
		}
		/* Check if this a 'jmp' opcode */
		if ((buf[ep] == 0xea) || (buf[ep] == 0xe9)) {
			return true;
		}
	}
	return false;
}

static bool load_bytes(RBinFile *bf, void **bin_obj, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb) {
	return check_bytes (buf, sz);
}

static bool load(RBinFile *bf) {
	const ut8 *bytes = bf? r_buf_buffer (bf->buf): NULL;
	ut64 sz = bf? r_buf_size (bf->buf): 0;
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *bf) {
	// r_bin_bios_free ((struct r_bin_bios_obj_t*)bf->o->bin_obj);
	return true;
}

static ut64 baddr(RBinFile *bf) {
	return 0;
}

/* accelerate binary load */
static RList *strings(RBinFile *bf) {
	return NULL;
}

static RBinInfo *info(RBinFile *bf) {
	RBinInfo *ret = NULL;
	if (!(ret = R_NEW0 (RBinInfo))) {
		return NULL;
	}
	ret->lang = NULL;
	ret->file = bf->file? strdup (bf->file): NULL;
	ret->type = strdup ("bios");
	ret->bclass = strdup ("1.0");
	ret->rclass = strdup ("bios");
	ret->os = strdup ("any");
	ret->subsystem = strdup ("unknown");
	ret->machine = strdup ("pc");
	ret->arch = strdup ("x86");
	ret->has_va = 1;
	ret->bits = 16;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *ptr = NULL;

	if (!(ret = r_list_newf ((RListFree) free))) {
		return NULL;
	}
	// program headers is another section
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	strcpy (ptr->name, "bootblk"); // Maps to 0xF000:0000 segment
	ptr->vsize = ptr->size = 0x10000;
	ptr->paddr = bf->buf->length - ptr->size;
	ptr->vaddr = 0xf0000;
	ptr->perm = R_PERM_RWX;
	ptr->add = true;
	r_list_append (ret, ptr);
	// If image bigger than 128K - add one more section
	if (bf->size >= 0x20000) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		strcpy (ptr->name, "_e000"); // Maps to 0xE000:0000 segment
		ptr->vsize = ptr->size = 0x10000;
		ptr->paddr = bf->buf->length - 2 * ptr->size;
		ptr->vaddr = 0xe0000;
		ptr->perm = R_PERM_RWX;
		ptr->add = true;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RList *entries(RBinFile *bf) {
	RList *ret;
	RBinAddr *ptr = NULL;
	if (!(ret = r_list_new ())) {
		return NULL;
	}
	ret->free = free;
	if (!(ptr = R_NEW0 (RBinAddr))) {
		return ret;
	}
	ptr->paddr = 0; // 0x70000;
	ptr->vaddr = 0xffff0;
	r_list_append (ret, ptr);
	return ret;
}

RBinPlugin r_bin_plugin_bios = {
	.name = "bios",
	.desc = "BIOS bin plugin",
	.license = "LGPL",
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.entries = entries,
	.sections = sections,
	.strings = &strings,
	.info = &info,
};

#ifndef CORELIB
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bios,
	.version = R2_VERSION
};
#endif
