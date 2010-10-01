/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/dyldcache.h"

static int check(RBin *bin) {
	ut8 *filebuf;
	int size, ret = R_FALSE;

	filebuf = (ut8*)r_file_slurp_range (bin->file, 0, 4, &size);
	if (filebuf && size == 4) {
		if (!memcmp (filebuf, "\x64\x79\x6c\x64", 4))
			ret = R_TRUE;
		free (filebuf);
	}
	return ret;
}

static int destroy(RBin *bin) {
	r_bin_dyldcache_free ((struct r_bin_dyldcache_obj_t*)bin->bin_obj);
	return R_TRUE;
}

static int extract(RBin *bin) {
	struct r_bin_dyldcache_lib_t *libs;
	int i;

	if(!(bin->bin_obj = r_bin_dyldcache_new(bin->file)))
		return 0;
	libs = r_bin_dyldcache_extract ((struct r_bin_dyldcache_obj_t*)bin->bin_obj);
	if (!libs)
		return 0;
	for (i = 0; !libs[i].last; i++) {
		bin->arch[i].file = strdup (libs[i].path);
		bin->arch[i].buf = libs[i].b;
		bin->arch[i].size = libs[i].size;
	}
	free (libs);
	return i;
}

struct r_bin_xtr_plugin_t r_bin_xtr_plugin_dyldcache = {
	.name = "dyldcache",
	.desc = "dyld cache bin extractor plugin",
	.init = NULL,
	.fini = NULL,
	.check = &check,
	.extract = &extract,
	.destroy = &destroy,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_dyldcache
};
#endif
