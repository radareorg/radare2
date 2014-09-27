/* radare - LGPL - 2014 - condret@runas-racer.com */

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
	if (!arch || !arch->o) return R_FALSE;
	return check_bytes (bytes, sz);
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0LL;
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
		ptr->paddr = ptr->vaddr = 0x0;
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
	strncpy (ret->file, (char *) rom_info, 12);
	strncpy (ret->type, (char *) &rom_info[12], 4);
	strncpy (ret->machine, "Gameboy Advanced", sizeof (ret->machine)-1);
	strncpy (ret->os, "any", sizeof (ret->os)-1);
	strcpy (ret->arch, "arm");
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}

struct r_bin_plugin_t r_bin_plugin_ningba = {
	.name = "ningba",
	.desc = "Gameboy Advanced format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_bytes,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = NULL,
	.entries = &entries,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.create = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningba
};
#endif
