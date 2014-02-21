#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <h8300_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	int ret = 1;
	struct h8300_cmd cmd;

	ret = h8300_decode_command(buf, &cmd);

	snprintf(op->buf_asm, R_ASM_BUFSIZE, "%s %s", cmd.instr, cmd.operands);
	op->size = ret;

	return ret;
}

RAsmPlugin r_asm_plugin_h8300 = {
	.name = "h8300",
	.license = "LGPL3",
	.desc = "H8/300 disassembly plugin",
	.arch = "h8300",
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_h8300
};
#endif
