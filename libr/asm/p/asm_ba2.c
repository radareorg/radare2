#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../asm/arch/ba2/ba2_disas.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	struct op_cmd cmd = {
		.instr = "",
		.operands = ""
	};
	int ret = ba2_decode_opcode (a->pc, buf, len, &cmd, NULL, NULL);
	if((len < ret) || (!ret && len<6)){ 
		r_strbuf_set (&op->buf_asm, "truncated");
		op->size = 0; 
		return 0;
	}
	if (ret > 0) {
		snprintf (op->buf_asm.buf, sizeof(op->buf_asm.buf), "%s %s", cmd.instr, cmd.operands);
	}else{
		r_strbuf_set (&op->buf_asm, "invalid");
		return -1;
	}
	return op->size = ret;
}

RAsmPlugin r_asm_plugin_ba2 = {
	.name = "ba2",
	.license = "LGPL3",
	.desc = "Beyond Architecture 2 disassembly plugin",
	.arch = "ba2",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_ba2,
	.version = R2_VERSION
};
#endif

