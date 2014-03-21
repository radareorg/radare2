#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <cr16_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	int ret = 1;
	struct cr16_cmd cmd;

	ret = cr16_decode_command(buf, &cmd);

	snprintf(op->buf_asm, R_ASM_BUFSIZE, "%s %s", cmd.instr, cmd.operands);
	op->size = ret;

	return ret;
}

RAsmPlugin r_asm_plugin_cr16 = {
	.name = "cr16",
	.license = "LGPL3",
	.desc = "cr16 disassembly plugin",
	.arch = "cr16",
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
	.data = &r_asm_plugin_cr16
};
#endif
