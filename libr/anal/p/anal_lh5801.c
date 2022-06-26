/* radare2, Sharp LH5801 disassembler.
 * (C) Copyright 2014-2015 jn, published under the LGPLv3 */

#include "../arch/lh5801/lh5801.c"
#include <r_anal.h>
#include <r_types.h>
#include <r_lib.h>

static int lh5801_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	struct lh5801_insn insn = {0};
	if (!op) {
		return 0;
	}
	int consumed = lh5801_decode (&insn, buf, len);
	if (consumed == -1 || consumed == 0) {
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		op->size = 1;
		return 0;
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		const int buf_len = 128;
		char *buf_asm = calloc (buf_len, 1);
		if (buf_asm) {
			lh5801_print_insn (buf_asm, buf_len, &insn);
			op->mnemonic = buf_asm;
		}
	}
	op->size = consumed;
	//op->payload = lh5801_insn_descs[insn.type].format & 3;
	// ^ MAYBE?
	return op->size;
}

RAnalPlugin r_anal_plugin_lh5801 = {
	.name = "lh5801",
	.arch = "LH5801",
	.license = "LGPL3",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "SHARP LH5801 disassembler",
	.op = &lh5801_op
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_lh5801,
	.version = R2_VERSION
};
#endif
