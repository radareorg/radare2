/* radare - GPL3 - Copyright 2009 nibble<.ds@gmail.com> */

#define R_BIN_ELF64 1
#include "bin_elf.c"

static int check(struct r_bin_t *bin)
{
	ut8 buf[1024];

	if ((bin->fd = open(bin->file, 0)) == -1)
		return R_FALSE;
	lseek(bin->fd, 0, SEEK_SET);
	read(bin->fd, buf, 1024);
	close(bin->fd);

	if (!memcmp(buf, "\x7F\x45\x4c\x46", 4) &&
		buf[4] == 2)  /* buf[EI_CLASS] == ELFCLASS64 */
		return R_TRUE;
	
	return R_FALSE;
}

struct r_bin_handle_t r_bin_plugin_elf64 = {
	.name = "bin_elf64",
	.desc = "elf64 bin plugin",
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
	.fields = &fields,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf64
};
#endif
