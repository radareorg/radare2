/* radare - LGPL - Copyright 2009-2011 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>

static int load(RBinArch *arch) {
	return R_TRUE;
}

static int destroy(RBinArch *arch) {
	r_buf_free (arch->buf);
	return R_TRUE;
}

static ut64 baddr(RBinArch *arch) {
	return 0LL;
}

struct r_bin_plugin_t r_bin_plugin_any = {
	.name = "any",
	.desc = "Dummy format r_bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = NULL,
	.baddr = &baddr,
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
	.meta = NULL,
	.create = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_any
};
#endif
