/* radare2, Sharp LH5801 disassembler.
 * (C) Copyright 2014-2015 jn, published under the LGPLv3 */

#include "./lh5801.c"
#include <r_arch.h>

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	struct lh5801_insn insn = {0};
	const int len = op->size;
	const ut8 *buf = op->bytes;
	if (!op || len < 1) {
		return false;
	}

	int consumed = lh5801_decode (&insn, buf, len);
	if (consumed == -1 || consumed == 0) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		op->size = 1;
		return false;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
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
	return op->size > 0;
}

static int info(RArchSession *as, ut32 q) {
	return 0;
}

static char* regs(RArchSession *as) {
	const char *reg =
		"=PC	PC\n"
		"=A0	A\n"
		"=A1	UH\n"
		"=A2	UL\n"
		"=A3	XH\n"
		"=A4	XL\n"
		"=A5	YH\n"
		"=A6	YL\n"

		"gpr	PC	.16	0	0\n"
		"gpr	A	.8	2	0\n"
		"flg	F	.8	3	0\n"
		"flg	H	.1	4.4	0\n"
		"flg	V	.1	4.5	0\n"
		"flg	Z	.1	4.6	0\n"
		"flg	C	.1	4.8	0\n"
		"gpr	U	.16	4	0\n"
		"gpr	UH	.8	4	0\n"
		"gpr	UL	.8	5	0\n"
		"gpr	X	.16	6	0\n"
		"gpr	XH	.8	6	0\n"
		"gpr	XL	.8	7	0\n"
		"gpr	Y	.16	8	0\n"
		"gpr	YH	.8	8	0\n"
		"gpr	YL	.8	9	0\n";

	return strdup (reg);
}

const RArchPlugin r_arch_plugin_lh5801 = {
	.meta = {
		.name = "lh5801",
		.author = "jn",
		.license = "LGPL-3.0-only",
		.desc = "SHARP LH5801 microprocessor",
	},
	.arch = "LH5801",
	.bits = R_SYS_BITS_PACK1 (8),
	.endian = R_SYS_ENDIAN_NONE,
	.decode = &decode,
	.info = info,
	.regs = regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_lh5801,
	.version = R2_VERSION
};
#endif
