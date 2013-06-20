/* radare - LGPL - Copyright 2009-2012 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/dyldcache.h"

static int check(RBin *bin) {
	int size, ret = R_FALSE;
	ut8 *filebuf = (ut8*)r_file_slurp_range (bin->file, 0, 4, &size);
	if (filebuf && size == 4) {
		if (!memcmp (filebuf, "\x64\x79\x6c\x64", 4))
			ret = R_TRUE;
		free (filebuf);
	}
	return ret;
}

// TODO: destroy must be void?
static int destroy(RBin *bin) {
	r_bin_dyldcache_free ((struct r_bin_dyldcache_obj_t*)bin->bin_obj);
	return R_TRUE;
}

static int load(RBin *bin) {
	return ((bin->bin_obj = r_bin_dyldcache_new (bin->file)))? R_TRUE: R_FALSE;
}

static int extract(RBin *bin, int idx) {
	int nlib = 0;
	struct r_bin_dyldcache_lib_t *lib = r_bin_dyldcache_extract (
		(struct r_bin_dyldcache_obj_t*)bin->bin_obj, idx, &nlib);
	if (lib) {
		bin->cur.file = strdup (lib->path);
		bin->cur.offset = lib->offset;
		bin->cur.buf = lib->b;
		bin->cur.size = lib->size;
		free (lib);
	}
	return nlib;
}

struct r_bin_xtr_plugin_t r_bin_xtr_plugin_dyldcache = {
	.name = "dyldcache",
	.desc = "dyld cache bin extractor plugin",
	.init = NULL,
	.fini = NULL,
	.check = &check,
	.load = &load,
	.extract = &extract,
	.destroy = &destroy,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_dyldcache
};
#endif
