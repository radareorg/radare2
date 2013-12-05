/* radare - LGPL - Copyright 2012-2013 - pancake
	2013 - Fedor Sakharov <fedor.sakharov@gmail.com> */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <ebc_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int ret = 1;
	ebc_command_t cmd;

	ret = ebc_decode_command(buf, &cmd);

	if (cmd.operands && *cmd.operands)
		snprintf(op->buf_asm, R_ASM_BUFSIZE, "%s %s", cmd.instr, cmd.operands);
	else snprintf(op->buf_asm, R_ASM_BUFSIZE, "%s", cmd.instr);

	op->inst_len = ret;
	return ret;
}

RAsmPlugin r_asm_plugin_ebc = {
	.name = "ebc",
	.license = "LGPL3",
	.desc = "EFI Byte Code disassembly plugin",
	.arch = "ebc",
	.bits = (int[]){ 32, 64 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ebc
};
#endif
