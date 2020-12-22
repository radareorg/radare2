/* radare - LGPL - Copyright 2014 - fedor.sakharov */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <propeller_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	const char *buf_asm;
	struct propeller_cmd cmd;
	int ret = propeller_decode_command (buf, &cmd);
	if (cmd.prefix[0] && cmd.operands[0]) {
		buf_asm = sdb_fmt ("%s %s %s", cmd.prefix, cmd.instr, cmd.operands);
	} else if (cmd.operands[0]) {
		buf_asm = sdb_fmt ("%s %s", cmd.instr, cmd.operands);
	} else {
		buf_asm = sdb_fmt ("%s", cmd.instr);
	}
	r_asm_op_set_asm (op, buf_asm);
	op->size = 4;
	return ret;
}

RAsmPlugin r_asm_plugin_propeller = {
	.name = "propeller",
	.license = "LGPL3",
	.desc = "propeller disassembly plugin",
	.arch = "propeller",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_propeller,
	.version = R2_VERSION
};
#endif
