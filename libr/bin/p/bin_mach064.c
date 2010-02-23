/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#define R_BIN_MACH064 1
#include "bin_mach0.c"

static int check(RBin *bin)
{
	ut8 *buf;
	int ret = R_FALSE;

	if (!(buf = (ut8*)r_file_slurp_range (bin->file, 0, 4)))
		return R_FALSE;
	if (!memcmp (buf, "\xfe\xed\xfa\xcf", 4) ||
		!memcmp (buf, "\xcf\xfa\xed\xfe", 4))
		ret = R_TRUE;
	free (buf);
	
	return ret;
}

struct r_bin_handle_t r_bin_plugin_mach064 = {
	.name = "mach064",
	.desc = "mach064 bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = &libs,
	.meta = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_mach064
};
#endif
