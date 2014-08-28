#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <propeller_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	int ret;
	struct propeller_cmd cmd;

	ret = propeller_decode_command (buf, &cmd);

	if (cmd.prefix[0] && cmd.operands[0]) {
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %s %s", cmd.prefix, cmd.instr, cmd.operands);
	} else if (cmd.operands[0]) {
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %s", cmd.instr, cmd.operands);
	} else {
		snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s", cmd.instr);
	}

	op->size = 4;

	return ret;
}

RAsmPlugin r_asm_plugin_propeller = {
	.name = "propeller",
	.license = "LGPL3",
	.desc = "propeller disassembly plugin",
	.arch = "propeller",
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_propeller
};
#endif
