/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include "java/java.h"

static int load(struct r_bin_t *bin)
{
	ut8* buf;

	if (!(buf = (ut8*)r_file_slurp (bin->file, &bin->size))) 
		return R_FALSE;
	bin->buf = r_buf_new ();
	if (!r_buf_set_bytes (bin->buf, buf, bin->size))
		return R_FALSE;
	free (buf);
	return R_TRUE;
}

static int destroy(struct r_bin_t *bin)
{
	r_buf_free(bin->buf);
	return R_TRUE;
}

static ut64 baddr(struct r_bin_t *bin)
{
	return 0LL;
}

struct r_bin_handle_t r_bin_plugin_dummy = {
	.name = "dummy",
	.desc = "dummy bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = NULL,
	.baddr = &baddr,
	.entries = NULL,
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
