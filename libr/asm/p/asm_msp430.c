#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <msp430_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len)
{
	int ret;
	struct msp430_cmd cmd;

	ret = msp430_decode_command (buf, &cmd);

	if (ret > 0) {
		if (cmd.operands[0]) {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s %s", cmd.instr, cmd.operands);
		} else {
			snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s", cmd.instr);
		}
	}

	op->size = ret;

	return ret;
}

RAsmPlugin r_asm_plugin_msp430 = {
	.name = "msp430",
	.license = "LGPL3",
	.desc = "msp430 disassembly plugin",
	.arch = "msp430",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_msp430,
	.version = R2_VERSION
};
#endif
