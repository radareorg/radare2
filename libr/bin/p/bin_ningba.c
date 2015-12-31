/* radare - LGPL - 2014-2015 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/gba.h"

static int check(RBinFile *arch);
int check_bytes(const ut8 *buf, ut64 length);

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);

}

int check_bytes(const ut8 *buf, ut64 length) {
	ut8 lict[156];
	if (!buf || length < 160)
		return 0;
	memcpy (lict, buf+0x4, 156);
	return (!memcmp (lict, lic_gba, 156))? 1: 0;
}

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	//struct r_bin_[NAME]_obj_t *bin = (struct r_bin_r_bin_[NAME]_obj_t *) o->bin_obj;
	//if (bin->kv) return kv;
	return NULL;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) return false;
	arch->rbin->maxstrbuf = 0x20000000;
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return true;
}

static RList* entries(RBinFile *arch) {
	RList *ret = r_list_new ();
	RBinAddr *ptr = NULL;

	if (arch && arch->buf) {
		if (!ret)
			return NULL;
		ret->free = free;
		if (!(ptr = R_NEW0 (RBinAddr)))
			return ret;
		ptr->paddr = ptr->vaddr = 0x8000000;
		r_list_append (ret, ptr);
	}
	return ret;
}

static RBinInfo* info(RBinFile *arch) {
	ut8 rom_info[16];
	RBinInfo *ret = R_NEW0 (RBinInfo);

	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free (ret);
		return NULL;
	}

	ret->lang = NULL;
	r_buf_read_at (arch->buf, 0xa0, rom_info, 16);
	ret->file = r_str_ndup ((const char *)rom_info, 12);
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

static RList* sections(RBinFile *arch) {
	RList *ret = NULL;
	RBinSection* s = R_NEW0 (RBinSection);
	ut64 sz = r_buf_size (arch->buf);

	if (!(ret = r_list_new ())) {
		free (s);
		return NULL;
	}
	strcpy (s->name, "ROM");
	s->paddr = 0;
	s->vaddr = 0x8000000;
	s->size = sz;
	s->vsize = 0x2000000;
	s->srwx = R_BIN_SCN_READABLE | R_BIN_SCN_EXECUTABLE | R_BIN_SCN_MAP;

	r_list_append (ret, s);
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_ningba = {
	.name = "ningba",
	.desc = "Game Boy Advance format r_bin plugin",
	.license = "LGPL3",
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.entries = &entries,
	.info = &info,
	.sections = &sections,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningba,
	.version = R2_VERSION
};
#endif
