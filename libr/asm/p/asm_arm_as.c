/* radare - LGPL - Copyright 2015-2022 pancake */

#include <r_lib.h>
#include "../binutils_as.h"

#define ASSEMBLER32 "R2_ARM32_AS"
#define ASSEMBLER64 "R2_ARM64_AS"

static bool encode(RArchSession *a, RAnalOp *op, ut32 mask) {
	const ut8 *const buf = op->mnemonic;
	const int bits = a->config->bits;
	const char *as = "";
#if __arm__
	if (bits <= 32) {
		as = "as";
	}
#elif __aarch64__
	if (bits == 64) {
		as = "as";
	}
#endif
	char cmd_opt[16];
	snprintf (cmd_opt, sizeof (cmd_opt), "%s %s",
		bits == 16 ? "-mthumb" : "",
		R_ARCH_CONFIG_IS_BIG_ENDIAN (a->config) ? "-EB" : "-EL");
	bool ret = binutils_encode (a, op, buf, as,
		bits == 64 ? ASSEMBLER64 : ASSEMBLER32,
		bits <= 32 ? ".syntax unified\n" : "", cmd_opt);
	return ret > 0;
}

RAsmPlugin r_asm_plugin_arm_as = {
	.name = "arm.as",
	.desc = "as ARM Assembler (use "ASSEMBLER32" and "ASSEMBLER64" environment)",
	.arch = "arm",
	.author = "pancake",
	.license = "LGPL3",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.encode = &encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_as,
	.version = R2_VERSION
};
#endif
