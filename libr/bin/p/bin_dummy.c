/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "java/java.h"

static int load(RBin *bin) {
	int ret = R_FALSE;
	ut8* buf;
	if ((buf = (ut8*)r_file_slurp (bin->file, &bin->size))) {
		bin->buf = r_buf_new ();
		if (r_buf_set_bytes (bin->buf, buf, bin->size))
			ret = R_TRUE;
		free (buf);
	}
	return ret;
}

static int destroy(RBin *bin) {
	r_buf_free(bin->buf);
	return R_TRUE;
}

static ut64 baddr(RBin *bin) {
	return 0LL;
}

struct r_bin_plugin_t r_bin_plugin_dummy = {
	.name = "dummy",
	.desc = "dummy bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.extract = NULL,
	.destroy = &destroy,
	.check = NULL,
	.baddr = &baddr,
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
	.data = &r_bin_plugin_dummy
};
#endif
