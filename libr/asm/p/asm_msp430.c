/* radare - LGPL - Copyright 2014-2015 - fedor.sakharov */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include <msp430_disas.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct msp430_cmd cmd;
	int ret = msp430_decode_command (buf, len, &cmd);
	if (ret > 0) {
		if (cmd.operands[0]) {
			r_strbuf_set (&op->buf_asm, sdb_fmt ("%s %s", cmd.instr, cmd.operands));
		} else {
			r_strbuf_set (&op->buf_asm, sdb_fmt ("%s", cmd.instr));
		}
	}
	if (a->syntax != R_ASM_SYNTAX_ATT) {
		char *ba = (char *)r_strbuf_get (&op->buf_asm);
		r_str_replace_ch (ba, '#', 0, 1);
		// r_str_replace_ch (ba, "$", "$$", 1);
		r_str_replace_ch (ba, '&', 0, 1);
		r_str_replace_ch (ba, '%', 0, 1);
	}

	return op->size = ret;
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_msp430,
	.version = R2_VERSION
};
#endif
