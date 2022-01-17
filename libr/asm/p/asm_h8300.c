/* radare - LGPL - Copyright 2014-2022 - fedor.sakharov */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <h8300_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct h8300_cmd cmd;
	int ret = h8300_decode_command(buf, &cmd);
	r_strf_var (opstr, 256, "%s %s", cmd.instr, cmd.operands);
	r_strbuf_set (&op->buf_asm, opstr);
	return op->size = ret;
}

RAsmPlugin r_asm_plugin_h8300 = {
	.name = "h8300",
	.license = "LGPL3",
	.desc = "H8/300 disassembly plugin",
	.arch = "h8300",
	.bits = 16,
	.endian = R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_h8300,
	.version = R2_VERSION
};
#endif
