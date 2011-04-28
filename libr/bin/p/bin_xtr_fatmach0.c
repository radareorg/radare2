/* radare - LGPL - Copyright 2009-2010 nibble<.ds@gmail.com> */

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
	if((bin->bin_obj = r_bin_fatmach0_new(bin->file)))
		return R_TRUE;
	return R_FALSE;
}

static int extract(RBin *bin, int idx) {
	struct r_bin_fatmach0_arch_t *arch;
	int narch;

	arch = r_bin_fatmach0_extract ((struct r_bin_fatmach0_obj_t*)bin->bin_obj, idx, &narch);
	if (!arch)
		return 0;
	bin->curarch.file = strdup (bin->file);
	bin->curarch.buf = arch->b;
	bin->curarch.size = arch->size;
	free (arch);
	return narch;
}

struct r_bin_xtr_plugin_t r_bin_xtr_plugin_fatmach0 = {
	.name = "fatmach0",
	.desc = "fat mach0 bin extractor plugin",
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
	.data = &r_bin_xtr_plugin_fatmach0
};
#endif
