/* radare - GPL - Copyright 2016-2026 - pancake */

#define R_LOG_ORIGIN "arch.stm8"

#include <r_arch.h>
#include "gmtdisas/asm.c"

static bool stm8_op(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	int len = 0;
	ut64 jump = UT64_MAX;
	op->type = R_ANAL_OP_TYPE_ILL;
	// op->type = R_ANAL_OP_TYPE_NOP;
	op->mnemonic = stm8_disasm (op->addr, op->bytes, op->size, &op->type, &jump, &len);
	if (op->mnemonic) {
		const char *ox = strstr (op->mnemonic, " 0x");
		if (ox) {
			ut64 v = r_num_get (NULL, ox);
			if (v && v != UT64_MAX && v != op->jump) {
				op->val = v;
			}
		}
		ox = strstr (op->mnemonic, "[0x");
		if (ox) {
			ut64 v = r_num_get (NULL, ox + 1);
			if (v != UT64_MAX) {
				// we need to use op->ptr.. but disable icod refs for stm8 only
				op->ptr = v;
				if (op->type == R_ANAL_OP_TYPE_LOAD || op->type == R_ANAL_OP_TYPE_CJMP || r_str_startswith (op->mnemonic, "cp ") || r_str_startswith (op->mnemonic, "cpw ") || r_str_startswith (op->mnemonic, "tnz ") || r_str_startswith (op->mnemonic, "tnzw ") || r_str_startswith (op->mnemonic, "bcp ")) {
					op->direction = R_ANAL_OP_DIR_READ;
				} else if (op->type == R_ANAL_OP_TYPE_STORE || r_str_startswith (op->mnemonic, "clr ") || r_str_startswith (op->mnemonic, "mov ")) {
					op->direction = R_ANAL_OP_DIR_WRITE;
				} else {
					op->direction = R_ANAL_OP_DIR_RW;
				}
			}
		}
	}
	if (jump != UT64_MAX && (op->type == R_ANAL_OP_TYPE_JMP || op->type == R_ANAL_OP_TYPE_CJMP || op->type == R_ANAL_OP_TYPE_CALL || op->type == R_ANAL_OP_TYPE_SWI)) {
		op->jump = jump;
		op->fail = UT64_MAX;
		switch (op->type) {
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			op->fail = op->addr + len; // not for non-conditional
			break;
		}
	}
	op->size = len;
	return op->size;
}

static char *regs(RArchSession *as) {
	const char *const p =
	"=PC	pc\n"
	"=SP	sp\n"
	"=SN	x\n"
	"=A0	x\n"
	"=A1	y\n"
	"=A2	a\n"
	"=R0	a\n"
	"gpr	pc	.24	0	0\n"
	"gpr	sp	.16	8	0\n"
	"gpr	x	.16	16	0\n"
	"gpr	y	.16	18	0\n"
	"gpr	a	.8	20	0\n"
	"gpr	xh	.8	17	0\n"
	"gpr	xl	.8	16	0\n"
	"gpr	yh	.8	19	0\n"
	"gpr	yl	.8	18	0\n"
	"gpr	cc	.8	21	0\n"
	;
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_WODST:
		return 0;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 5;
	case R_ARCH_INFO_MINOP_SIZE:
		return 1;
	}
	return 1; /* :D */
}

const RArchPlugin r_arch_plugin_stm8 = {
	.meta = {
		.name = "stm8",
		.desc = "STMicroelectronics 8-bit microcontroller unit",
		.author = "pancake",
		.license = "GPL-3.0-only",
	},
	.arch = "stm8",
	.endian = R_SYS_ENDIAN_LITTLE,
	.bits = R_SYS_BITS_PACK2 (8, 16),
	.info = archinfo,
	.decode = &stm8_op,
	.regs = &regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_stm8,
	.version = R2_VERSION
};
#endif
