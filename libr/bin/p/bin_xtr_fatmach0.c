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

static int extract(RBin *bin) {
	struct r_bin_fatmach0_arch_t *archs;
	int i;

	if(!(bin->bin_obj = r_bin_fatmach0_new(bin->file)))
		return 0;
	archs = r_bin_fatmach0_extract ((struct r_bin_fatmach0_obj_t*)bin->bin_obj);
	if (!archs)
		return 0;
	for (i = 0; !archs[i].last; i++) {
		bin->arch[i].file = strdup (bin->file);
		bin->arch[i].buf = archs[i].b;
		bin->arch[i].size = archs[i].size;
	}
	free (archs);
	return i;
}

struct r_bin_xtr_plugin_t r_bin_xtr_plugin_fatmach0 = {
	.name = "fatmach0",
	.desc = "fat mach0 bin extractor plugin",
	.init = NULL,
	.fini = NULL,
	.check = &check,
	.extract = &extract,
	.destroy = &destroy,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN_XTR,
	.data = &r_bin_xtr_plugin_fatmach0
};
#endif
