/* radare - LGPL - Copyright 2011-2022 pancake */

#include <r_lib.h>
#include "../binutils_as.h"

#define ASSEMBLER "R2_X86_AS"

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
#if __i386__ || __x86_64__
	const char *as = "as";
#else
	const char *as = "";
#endif
	const char *syntaxstr = "";
	switch (a->config->syntax) {
	case R_ASM_SYNTAX_INTEL:
		syntaxstr = ".intel_syntax noprefix\n";
		break;
	case R_ASM_SYNTAX_ATT:
		syntaxstr = ".att_syntax\n";
		break;
	}

	char header[4096];
	snprintf (header, sizeof (header), "%s.code%i\n", // .org 0x%"PFMT64x"\n"
		syntaxstr, a->config->bits);
	return binutils_assemble (a, op, buf, as, ASSEMBLER, header, "");
}

RAsmPlugin r_asm_plugin_x86_as = {
	.name = "x86.as",
	.desc = "Intel X86 GNU Assembler (Use "ASSEMBLER" env)",
	.arch = "x86",
	.license = "LGPL3",
	// NOTE: 64bits is not supported on OSX's nasm :(
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_as,
	.version = R2_VERSION
};
#endif
