/* radare2 - LGPL - Copyright 2009-2016 - nibble, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int check(RBinFile *arch);
static int check_bytes(const ut8 *buf, ut64 length);

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_bytes (bytes, sz);
}

static bool dyld64 = false;

static int check_bytes(const ut8 *buf, ut64 length) {
	bool rc = false;
	if (buf && length >= 32) {
		char arch[9] = {0};
		strncpy (arch, (const char *)buf+9, R_MIN (length, sizeof (arch)-1));
		rc = !memcmp (buf, "\x64\x79\x6c\x64", 4);
		if (rc) {
			dyld64 = strstr (arch, "64") != NULL;
			eprintf ("Arch: %s\n", arch);
		}
	}
	return rc;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return (void*)(size_t)check_bytes (buf, sz);
}

static int load(RBinFile *arch) {
	return check(arch);
}

static RList* entries(RBinFile *arch) {
	RBinAddr *ptr = NULL;
	RList* ret = r_list_newf (free);
	if (!ret) return NULL;
	if ((ptr = R_NEW0 (RBinAddr))) {
		r_list_append (ret, ptr);
	}
	return ret;
}


static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = NULL;
	bool big_endian = 0;
	if (!(ret = R_NEW0 (RBinInfo)))
		return NULL;
	ret->file = strdup (arch->file);
	ret->bclass = strdup ("dyldcache");
	ret->rclass = strdup ("ios");
	ret->os = strdup ("iOS");
	ret->arch = strdup ("arm");
	ret->machine = strdup (ret->arch);
	ret->subsystem = strdup ("xnu");
	ret->type = strdup ("LIBRARY CACHE");
	ret->bits = dyld64? 64: 32;
	ret->has_va = true;
	ret->big_endian = big_endian;
	ret->dbg_info = 0;
	ret->dbg_info = 0;
	return ret;
}

#if 0
static ut64 size(RBinFile *arch) {
	ut64 text, data, syms, spsz;
	int big_endian;
	if (!arch->o->info)
		arch->o->info = info (arch);
	if (!arch->o->info) return 0;
	big_endian = arch->o->info->big_endian;
	// TODO: reuse section list
	text = r_mem_get_num (arch->buf->buf+4, 4, big_endian);
	data = r_mem_get_num (arch->buf->buf+8, 4, big_endian);
	syms = r_mem_get_num (arch->buf->buf+16, 4, big_endian);
	spsz = r_mem_get_num (arch->buf->buf+24, 4, big_endian);
	return text+data+syms+spsz+(6*4);
}
#endif

struct r_bin_plugin_t r_bin_plugin_dyldcache = {
	.name = "dyldcache",
	.desc = "dyldcache bin plugin",
	.license = "LGPL3",
//	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
//	.size = &size,
	.entries = &entries,
	.check = &check,
	.check_bytes = &check_bytes,
	.info = &info,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dyldcache,
	.version = R2_VERSION
};
#endif
