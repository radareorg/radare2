/* radare - LGPL - Copyright 2013-2019 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "../i/private.h"

static bool check_buffer(RBuffer *buf) {
	r_return_val_if_fail (buf, false);

	ut64 sz = r_buf_size (buf);
	if (sz <= 0xffff) {
		return false;
	}

	ut8 b0 = r_buf_read8_at (buf, 0);
	if (b0 == 0xcf || b0 == 0x7f) {
		return false;
	}

	const ut32 ep = sz - 0x10000 + 0xfff0; /* F000:FFF0 address */
	/* hacky check to avoid detecting multidex or MZ bins as bios */
	/* need better fix for this */
	ut8 tmp[3];
	int r = r_buf_read_at (buf, 0, tmp, sizeof (tmp));
	if (r <= 0 || !memcmp (tmp, "dex", 3) || !memcmp (tmp, "MZ", 2)) {
		return false;
	}

	/* Check if this a 'jmp' opcode */
	ut8 bep = r_buf_read8_at (buf, ep);
	return bep == 0xea || bep == 0xe9;
}

static bool load_buffer(RBinFile *bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	if (!check_buffer (buf)) {
		return false;
	}
	*bin_obj = r_buf_ref (buf);
	return true;
}

static void destroy(RBinFile *bf) {
	r_buf_free (bf->o->bin_obj);
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
	RBuffer *obj = bf->o->bin_obj;

	if (!(ret = r_list_newf ((RListFree) r_bin_section_free))) {
		return NULL;
	}
	// program headers is another section
	if (!(ptr = R_NEW0 (RBinSection))) {
		return ret;
	}
	ptr->name = strdup ("bootblk"); // Maps to 0xF000:0000 segment
	ptr->vsize = ptr->size = 0x10000;
	ptr->paddr = r_buf_size (bf->buf) - ptr->size;
	ptr->vaddr = 0xf0000;
	ptr->perm = R_PERM_RWX;
	ptr->add = true;
	r_list_append (ret, ptr);
	// If image bigger than 128K - add one more section
	if (bf->size >= 0x20000) {
		if (!(ptr = R_NEW0 (RBinSection))) {
			return ret;
		}
		ptr->name = strdup ("_e000"); // Maps to 0xE000:0000 segment
		ptr->vsize = ptr->size = 0x10000;
		ptr->paddr = r_buf_size (obj) - 2 * ptr->size;
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
	.load_buffer = &load_buffer,
	.destroy = &destroy,
	.check_buffer = &check_buffer,
	.baddr = &baddr,
	.entries = entries,
	.sections = sections,
	.strings = &strings,
	.info = &info,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_bios,
	.version = R2_VERSION
};
#endif
