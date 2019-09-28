/* radare - LGPL - 2014-2019 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/gba.h"

static bool check_buffer(RBuffer *b) {
	ut8 lict[156];
	r_return_val_if_fail (b, false);
	r_buf_read_at (b, 4, (ut8*)lict, sizeof (lict));
	return !memcmp (lict, lic_gba, 156);
}

static bool load_buffer(RBinFile * bf, void **bin_obj, RBuffer *buf, ut64 loadaddr, Sdb *sdb) {
	return check_buffer (buf);
}

static RList *entries(RBinFile *bf) {
	RList *ret = r_list_newf (free);
	RBinAddr *ptr = NULL;

	if (bf && bf->buf) {
		if (!ret) {
			return NULL;
		}
		if (!(ptr = R_NEW0 (RBinAddr))) {
			return ret;
		}
		ptr->paddr = ptr->vaddr = 0x8000000;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RBinInfo *info(RBinFile *bf) {
	ut8 rom_info[16];
	RBinInfo *ret = R_NEW0 (RBinInfo);

	if (!ret) {
		return NULL;
	}

	if (!bf || !bf->buf) {
		free (ret);
		return NULL;
	}

	ret->lang = NULL;
	r_buf_read_at (bf->buf, 0xa0, rom_info, 16);
	ret->file = r_str_ndup ((const char *) rom_info, 12);
	ret->type = r_str_ndup ((char *) &rom_info[12], 4);
	ret->machine = strdup ("GameBoy Advance");
	ret->os = strdup ("any");
	ret->arch = strdup ("arm");
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

static RList *sections(RBinFile *bf) {
	RList *ret = NULL;
	RBinSection *s = R_NEW0 (RBinSection);
	ut64 sz = r_buf_size (bf->buf);
	if (!(ret = r_list_new ())) {
		free (s);
		return NULL;
	}
	s->name = strdup ("ROM");
	s->paddr = 0;
	s->vaddr = 0x8000000;
	s->size = sz;
	s->vsize = 0x2000000;
	s->perm = R_PERM_RX;
	s->add = true;

	r_list_append (ret, s);
	return ret;
}

RBinPlugin r_bin_plugin_ningba = {
	.name = "ningba",
	.desc = "Game Boy Advance format r_bin plugin",
	.license = "LGPL3",
	.load_buffer = &load_buffer,
	.check_buffer = &check_buffer,
	.entries = &entries,
	.info = &info,
	.sections = &sections,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningba,
	.version = R2_VERSION
};
#endif
