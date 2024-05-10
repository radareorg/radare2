/* radare - LGPL - Copyright 2024 - pancake */

#define R_LOG_ORIGIN "arch.stm8"

#include <r_arch.h>
#include "gmtdisas/asm.c"

static bool stm8_op(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	int len = 0;
	ut64 jump = UT64_MAX;
	op->type = R_ANAL_OP_TYPE_ILL;
	// op->type = R_ANAL_OP_TYPE_NOP;
	op->mnemonic = stm8_disasm (op->addr, op->bytes, op->size, &op->type, &jump, &len);
	if (jump != UT64_MAX) {
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
	"=BP	r31\n"
	"=A0	x\n"
	"=A1	y\n"
	"=A2	a\n"
	"gpr	pc	.64	0	0\n" // 24bit
	"gpr	sp	.64	8	0\n" // 16bit
	"gpr	x	.16	16	0\n" // 16
	"gpr	y	.16	18	0\n" // 16
	"gpr	a	.8	20	0\n" // 8
	"gpr	xh	.8	16	0\n"
	"gpr	xl	.8	17	0\n"
	"gpr	yh	.8	18	0\n"
	"gpr	yl	.8	19	0\n"
	"gpr	cc	.16	20	0\n"
	;
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
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
		.desc = "STM8 microprocessor",
		.author = "pancake",
		.license = "GPL3",
	},
	.arch = "stm8",
	.cpus = NULL,
	.endian = R_SYS_ENDIAN_LITTLE,
	.bits = R_SYS_BITS_PACK (32),
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
