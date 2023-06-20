/* radare - LGPL - Copyright 2021-2022 - pancake */

#include <r_arch.h>

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	int len = 0;
	const char *cpu = R_UNWRAP3 (as, config, cpu);
	if (!cpu) {
		cpu = R_SYS_ARCH;
	}
	char *cmd = r_str_newf (
		"r2pm -r vasm%s_std -Fbin -quiet -o /dev/stdout /dev/stdin <<__\n"
		".org 0x%"PFMT64x"\n%s\n__", cpu, op->addr, op->mnemonic);
	ut8 *out = (ut8 *)r_sys_cmd_str (cmd, "", &len);
	free (cmd);
	if (out) {
		op->size = len;
		r_anal_op_set_bytes (op, op->addr, out, len);
		free (out);
		return true;
	}
	return false;
}

#define DESC "Use -a arm.vasm, 6502.vasm, 6809, c16x, jagrisc, m68k, pdp11, ppc, qnice, tr3200, vidcore, x86, z80"

const RArchPlugin r_arch_plugin_any_vasm = {
	.meta = {
		.name = "any.vasm",
		.desc = DESC,
		.author = "http://sun.hasenbraten.de/vasm/ (r2pm -ci vasm)",
		.license = "MIT",
	},
	.arch = "any", // on purpose because that's a multi-arch plugin
	.bits = R_SYS_BITS_PACK4 (8, 16, 32, 64),
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.encode = &encode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_any_vasm,
	.version = R2_VERSION
};
#endif
