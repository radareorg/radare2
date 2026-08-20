/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_arch.h>

#include "sass.inc.c"

static int archinfo(RArchSession *as, ut32 q) {
	return 16;
}

const RArchPlugin r_arch_plugin_ptx = {
	.meta = {
		.name = "ptx",
		.author = "pancake",
		.desc = "nvidia sass ptx instruction assembler/disassembler",
		.license = "MIT",
	},
	.arch = "ptx",
	.bits = R_SYS_BITS_PACK1 (64),
	.regs = regs,
	.cpus = "sm_50,sm_52,sm_53,sm_60,sm_61,sm_62,sm_70,sm_72,sm_75,sm_80,sm_86,sm_87,sm_89,sm_90,sm_100,sm_110",
	.info = archinfo,
	.decode = &decode,
	.encode = &encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_ptx,
	.version = R2_VERSION
};
#endif
