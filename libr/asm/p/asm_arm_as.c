/* radare - LGPL - Copyright 2015-2022 pancake */

#include <r_lib.h>
#include "../binutils_as.h"

#define ASSEMBLER32 "R2_ARM32_AS"
#define ASSEMBLER64 "R2_ARM64_AS"

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	const int bits = a->config->bits;
	char *as = "";
#if __arm__
	if (bits <= 32) {
		as = "as";
	}
#elif __aarch64__
	if (bits == 64) {
		as = "as";
	}
#endif
	char cmd_opt[4096];
	snprintf (cmd_opt, sizeof (cmd_opt), "%s %s",
		bits == 16 ? "-mthumb" : "",
		a->config->big_endian ? "-EB" : "-EL");
	return binutils_assemble (a, op, buf, as,
		bits == 64 ? ASSEMBLER64 : ASSEMBLER32,
		bits <= 32 ? ".syntax unified\n" : "", cmd_opt);
}

RAsmPlugin r_asm_plugin_arm_as = {
	.name = "arm.as",
	.desc = "as ARM Assembler (use "ASSEMBLER32" and "ASSEMBLER64" environment)",
	.arch = "arm",
	.author = "pancake",
	.license = "LGPL3",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_as,
	.version = R2_VERSION
};
#endif
