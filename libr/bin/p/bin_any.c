/* radare - LGPL - Copyright 2009-2013 - nibble */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int load(RBinFile *arch) {
	return R_TRUE;
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0LL;
}

struct r_bin_plugin_t r_bin_plugin_any = {
	.name = "any",
	.desc = "Dummy format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = NULL,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = NULL,
	.entries = NULL,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = NULL,
	.info = NULL,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.dbginfo = NULL,
	.create = NULL,
	.write = NULL,
	.minstrlen = 0,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_any
};
#endif
