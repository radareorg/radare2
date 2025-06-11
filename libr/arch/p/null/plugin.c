/* radare - LGPL - Copyright 2022-2023 - pancake */

#include <r_arch.h>
#include <r_util.h>

#if 0
static char* regs(RArchSession *as) {
	const char* profile =
		"=PC	null0\n"
		"=SP	null1\n"
		"=SN	null0\n"
		"=A0	null0\n"
		"gpr	null0	.32	?0   0\n"
		"gpr	null1	.32	?1   0\n";
	return strdup (profile);
}
#endif

const RArchPlugin r_arch_plugin_null = {
	.meta = {
		.name = "null",
		.desc = "nothing",
		.license = "LGPL-3.0-only",
	},
	.arch = "none",
	.bits = R_SYS_BITS_PACK4 (8, 16, 32, 64),
//	.regs = regs
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_null,
	.version = R2_VERSION
};
#endif
