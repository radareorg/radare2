/* radare - LGPL - Copyright 2022 - pancake */

#include <r_arch.h>
#include <r_util.h>


static char* regs(RArchSession *as) {
	const char* profile =
		"=PC	pc\n"
		"=SP	sp\n"
		"=SN	r0\n";
	return strdup (profile);
}

RArchPlugin r_arch_plugin_null = {
	.name = "null",
	.desc = "Fallback/Null arch plugin",
	.arch = "none",
	.license = "LGPL3",
	.bits = R_SYS_BITS_PACK4 (8, 16, 32, 64),
	.regs = regs
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_null,
	.version = R2_VERSION
};
#endif
