/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/fatmach0.h"

static int check(RBin *bin) {
	ut8 *buf;
	int n, ret = R_FALSE;

	if ((buf = (ut8*)r_file_slurp_range (bin->file, 0, 8, &n))) {
		if (n == 8)
		/* XXX HACK to avoid conflicts with java class */
		if (!memcmp (buf, "\xca\xfe\xba\xbe\x00\x00\x00\x02", 8))
			ret = R_TRUE;
		free (buf);
	}
	return ret;
}

static int destroy(RBin *bin) {
	r_bin_fatmach0_free ((struct r_bin_fatmach0_obj_t*)bin->bin_obj);
	return R_TRUE;
}

static int load(RBin *bin) {
	if(!(bin->bin_obj = r_bin_fatmach0_new(bin->file)))
		return R_FALSE;
	bin->size = ((struct r_bin_fatmach0_obj_t*)(bin->bin_obj))->size;
	bin->buf = ((struct r_bin_fatmach0_obj_t*)(bin->bin_obj))->b;
	eprintf ("Warning: fat mach-o, use rabin2 -x to extract the bins\n");
	return R_TRUE;
}

static int extract(RBin *bin) {
	return r_bin_fatmach0_extract ((struct r_bin_fatmach0_obj_t*)bin->bin_obj);
}

struct r_bin_plugin_t r_bin_plugin_fatmach0 = {
	.name = "fatmach0",
	.desc = "fat mach0 bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.extract = &extract,
	.destroy = &destroy,
	.check = &check,
	.baddr = NULL,
	.main = NULL,
	.entries = NULL,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = NULL,
	.info = NULL,
	.fields = NULL,
	.libs = NULL,
	.meta = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_fatmach0
};
#endif
