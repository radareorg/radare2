/* radare - LGPL - Copyright 2021 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int len = 0;
	const char *cpu = a->config->cpu? a->config->cpu: "x86";
	char *cmd = r_str_newf (
		"r2pm -r vasm%s_std -Fbin -quiet -o /dev/stdout /dev/stdin <<__\n"
		".org 0x%"PFMT64x"\n%s\n__", cpu, a->pc, buf);
	ut8 *out = (ut8 *)r_sys_cmd_str (cmd, "", &len);
	if (out) {
		r_asm_op_set_buf (op, out, len);
		free (out);
	}
	op->size = len;
	free (cmd);
	return len;
}

RAsmPlugin r_asm_plugin_vasm = {
	.name = "vasm",
	.arch = NULL, // null on purpose
	.license = "MIT",
	.desc = "Use -a arm.vasm, 6502.vasm, 6809, c16x, jagrisc, m68k, pdp11, ppc, qnice, tr3200, vidcore, x86, z80",
	.author = "http://sun.hasenbraten.de/vasm/",
	.bits = 8 | 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE,
	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_vasm,
	.version = R2_VERSION
};
#endif
