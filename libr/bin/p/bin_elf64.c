/* radare - GPL3 - Copyright 2009-2010 nibble<.ds@gmail.com> */

#define R_BIN_ELF64 1
#include "bin_elf.c"

static int check(RBinArch *arch) {
	if (!memcmp (arch->buf->buf, "\x7F\x45\x4c\x46\x02", 5))
		return R_TRUE;
	return R_FALSE;
}

extern struct r_bin_meta_t r_bin_meta_elf64;
extern struct r_bin_write_t r_bin_write_elf64;

struct r_bin_plugin_t r_bin_plugin_elf64 = {
	.name = "elf64",
	.desc = "elf64 bin plugin",
	.init = NULL,
	.fini = NULL,
	.load = &load,
	.destroy = &destroy,
	.check = &check,
	.baddr = &baddr,
	.main = &binmain,
	.entries = &entries,
	.sections = &sections,
	.symbols = &symbols,
	.imports = &imports,
	.strings = NULL,
	.info = &info,
	.fields = &fields,
	.libs = &libs,
	.relocs = &relocs,
	.meta = &r_bin_meta_elf64,
	.write = &r_bin_write_elf64,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_elf64
};
#endif
