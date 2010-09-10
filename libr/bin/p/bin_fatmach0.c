/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "mach0/fatmach0.h"

static int check(RBin *bin) {
	ut8 *filebuf, buf[4];
	int off, filesize, ret = R_FALSE;

	if ((filebuf = (ut8*)r_file_slurp (bin->file, &filesize))) {
		if (!memcmp (filebuf, "\xca\xfe\xba\xbe", 4)) {
			memcpy (&off, filebuf+4*sizeof(int), sizeof(int));
			r_mem_copyendian ((ut8*)&off, (ut8*)&off, sizeof(int), !LIL_ENDIAN);
			if (off > 0 && off < filesize) {
				memcpy (buf, filebuf+off, 4);
				if (!memcmp (buf, "\xce\xfa\xed\xfe", 4) ||
					!memcmp (buf, "\xfe\xed\xfa\xce", 4) ||
					!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
					!memcmp (buf, "\xcf\xfa\xed\xfe", 4))
					ret = R_TRUE;
			}
		}
		free (filebuf);
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
	.relocs = NULL,
	.meta = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_fatmach0
};
#endif
