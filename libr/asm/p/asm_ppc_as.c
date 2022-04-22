/* radare - LGPL - Copyright 2020 eagleoflqj */

#include <r_lib.h>
#include "../binutils_as.h"

#define ASSEMBLER "R2_PPC_AS"

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
#if __powerpc__
	char *as = "as";
#else
	char *as = "";
#endif
	char cmd_opt[4096];
	snprintf (cmd_opt, sizeof (cmd_opt), "-mregnames -a%d %s",
		a->config->bits, a->config->big_endian ? "-be" : "-le");
	return binutils_assemble (a, op, buf, as, ASSEMBLER, "", cmd_opt);
}

RAsmPlugin r_asm_plugin_ppc_as = {
	.name = "ppc.as",
	.desc = "as PPC Assembler (use "ASSEMBLER" environment)",
	.arch = "ppc",
	.author = "eagleoflqj",
	.license = "LGPL3",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ppc_as,
	.version = R2_VERSION
};
#endif
