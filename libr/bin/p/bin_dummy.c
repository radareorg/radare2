/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_lib.h>
#include <r_bin.h>
#include "java/java.h"

static int bopen(struct r_bin_t *bin)
{
	if ((bin->fd = open(bin->file, 0)) == -1) {
		fprintf(stderr, "Cannot open file\n");
		return R_FALSE;
	} else return bin->fd;
}

static int bclose(struct r_bin_t *bin)
{
	return close(bin->fd);
}

struct r_bin_handle_t r_bin_plugin_dummy = {
	.name = "bin_dummy",
	.desc = "dummy bin plugin",
	.init = NULL,
	.fini = NULL,
	.open = &bopen,
	.close = &bclose,
	.check = NULL,
	.baddr = NULL,
	.entry = NULL,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = NULL,
	.info = NULL,
	.fields = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_dummy
};
#endif
