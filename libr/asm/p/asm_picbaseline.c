/* radare2 - LGPL - Copyright 2017 - thestr4ng3r */

#include <r_asm.h>
#include <r_lib.h>

static int asm_picbaseline_disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	if (!b || l<2) {
		strncpy (op->buf_asm, "invalid", R_ASM_BUFSIZE);
		op->size = l;
		return -1;
	}

	ut16 instr = r_read_le16(b);
	op->size = 2;
	snprintf (op->buf_asm, sizeof(op->buf_asm), "opcode %#x", instr);
	return op->size;
}

RAsmPlugin r_asm_plugin_picbaseline = {
	.name = "picbaseline",
	.arch = "picbaseline",
	.bits = 8,
	.license = "LGPL3",
	.desc = "PIC Baseline (PIC10/12/16) disassembler",
	.disassemble = &asm_picbaseline_disassemble
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_picbaseline
};
#endif
