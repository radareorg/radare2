/* radare - LGPL - Copyright 2012-2018 - pancake */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <v850_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct v850_cmd cmd = {
		.addr = a->pc,
		.instr = "",
		.operands = ""
	};
	if (len < 2) {
		return -1;
	}
	int ret = v850_decode_command (buf, len, &cmd);
	if (ret > 0) {
		r_asm_op_set_asm (op, sdb_fmt ("%s %s", cmd.instr, cmd.operands));
	}
	return op->size = ret;
}

RAsmPlugin r_asm_plugin_v850 = {
	.name = "v850",
	.license = "LGPL3",
	.desc = "v850 disassembly plugin",
	.arch = "v850",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_v850,
	.version = R2_VERSION
};
#endif
