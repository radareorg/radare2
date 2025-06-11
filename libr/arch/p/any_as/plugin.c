/* Copyright (C) 2008-2024 - pancake */

#include <r_arch.h>
#include "binutils_as.c"

static const char *_mycpu(RArchSession *s) {
	const char *cpu = s->config->cpu;
	return cpu? cpu: R_SYS_ARCH;
}

#define ASSEMBLER32 "R2_ARM32_AS"
#define ASSEMBLER64 "R2_ARM64_AS"
static bool as_encode(RArchSession *s, RAnalOp *op, RArchEncodeMask mask) {
	int len = 0;
	char *gas = r_sys_getenv ("RASM2_AS");
	if (!gas) {
		// TODO: find in PATH
		gas = strdup ("as");
	}
	const char *cpu = _mycpu (s);
	if (!strcmp (cpu, "ppc")) {
		char cmd_opt[4096];
		snprintf (cmd_opt, sizeof (cmd_opt), "-mregnames -a%d %s", s->config->bits,
			R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config) ? "-be" : "-le");
		// TODO the R2_PPC_AS arg should be removed
		return binutils_assemble (s, op, op->mnemonic, gas, "R2_PPC_AS", "", cmd_opt);
#if __linux__
	} else if (!strcmp (cpu, "arm")) {
		const int bits = s->config->bits;
		char cmd_opt[4096];
		snprintf (cmd_opt, sizeof (cmd_opt), "%s %s",
			bits == 16 ? "-mthumb" : "",
			R_ARCH_CONFIG_IS_BIG_ENDIAN (s->config) ? "-EB" : "-EL");
		return binutils_assemble (s, op, op->mnemonic, gas,
			bits == 64 ? ASSEMBLER64 : ASSEMBLER32,
			bits <= 32 ? ".syntax unified\n" : "", cmd_opt);
#endif
	} else if (!strcmp (cpu, "gas")) { // x86 alternative
		char *cmd = r_str_newf (
			"gas /dev/stdin -o /dev/stdout <<__\n"
			"BITS %i\nORG 0x%"PFMT64x"\n%s\n__",
			s->config->bits, op->addr, op->mnemonic);
		ut8 *out = (ut8 *)r_sys_cmd_str (cmd, "", &len);
		if (out) {
			r_anal_op_set_bytes (op, op->addr, out, len);
			free (out);
		}
		op->size = len;
	} else if (!strcmp (cpu, "x86")) {
		// macos-arm64  NO
		const char *syntaxstr = "";
		switch (s->config->syntax) {
		case R_ARCH_SYNTAX_INTEL:
			syntaxstr = ".intel_syntax noprefix\n";
			break;
		case R_ARCH_SYNTAX_ATT:
			syntaxstr = ".att_syntax\n";
			break;
		}
		char header[4096];
		snprintf (header, sizeof (header), "%s.code%i\n", // .org 0x%"PFMT64x"\n"
			syntaxstr, s->config->bits);
		return binutils_assemble (s, op, op->mnemonic, gas, NULL, header, "");
	} else {
		// macos-arm64  YES
		char *cmd = r_str_newf (
			"%s -o a.out /dev/stdin <<__\n%s\n__\n"
			"rabin2 -rO 'd/S/*text' a.out; rm -f a.out\n",
			gas, op->mnemonic);
		ut8 *out = (ut8 *)r_sys_cmd_str (cmd, NULL, &len);
		if (out) {
			r_anal_op_set_bytes (op, op->addr, out, len);
			free (out);
		}
		free (cmd);
	}
	op->size = len;
	return len > 0;
}

const RArchPlugin r_arch_plugin_any_as = {
	.meta = {
		.name = "any.as",
		.desc = "System GNU/LLVM Assembler",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	// TODO: add the "any" architecture to support any, instead of using null
	.arch = "any", // on purpose because that's a multi-arch plugin
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.endian = R_SYS_ENDIAN_LITTLE,
	.encode = &as_encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_any_as,
	.version = R2_VERSION
};
#endif
