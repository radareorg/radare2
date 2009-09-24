/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#define R_BIN_PE64 1
#include "bin_pe.c"

static int check(struct r_bin_t *bin)
{
	ut8 buf[1024];

	if ((bin->fd = open(bin->file, 0)) == -1)
		return R_FALSE;
	lseek(bin->fd, 0, SEEK_SET);
	read(bin->fd, buf, 1024);
	close(bin->fd);

	if (!memcmp(buf, "\x4d\x5a", 2) &&
		!memcmp(buf+(buf[0x3c]|(buf[0x3d]<<8)), "\x50\x45", 2) && 
		!memcmp(buf+(buf[0x3c]|buf[0x3d]<<8)+0x18, "\x0b\x02", 2))
		return R_TRUE;

		return R_FALSE;
	}

struct r_bin_handle_t r_bin_plugin_pe64 = {
	.name = "pe64",
	.desc = "PE64 (PE32+) bin plugin",
	.init = NULL,
	.fini = NULL,
	.open = &bopen,
	.close = &bclose,
	.check = &check,
	.baddr = &baddr,
	.entry = &entry,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_pe64
};
#endif
