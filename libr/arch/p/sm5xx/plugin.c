/* radare2 - LGPL - Copyright 2023 - pancake */

#include <r_arch.h>
#include "sm5xx.h"

static bool decode(RArchSession *a, RAnalOp *op, RArchDecodeMask mask) {
	enum sm5xx_cpu cpu = CPU_SM500;
	RStrBuf *sb = r_strbuf_new ("");
	int type = 0;
	int size = sm5xx_disassemble (cpu, sb, 0, op->bytes, &type);
	op->mnemonic = r_strbuf_drain (sb);
	switch (type) {
	case STEP_COND:
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case STEP_OVER:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case STEP_OUT:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	}
	op->size = size;
	return true;
}

static char *regs(RArchSession *as) {
	const char *const p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	y\n"
		"=A1	y\n"
		"gpr	acc	.8	0	0\n"
		"gpr	bl	.8	1	0\n"
		"gpr	bm	.8	2	0\n"
		"gpr	bmask	.8	2	0\n"
		"gpr	c	.8	2	0\n"
		"gpr	skip	.8	2	0\n"
		"gpr	w	.8	2	0\n"
		"gpr	r	.8	2	0\n"
	// u8 m_r_out;
	// int m_r_mask_option;
	// bool m_ext_wakeup;
	// bool m_halt;
	// int m_clk_div;
		"gpr	C	.1	.24	0\n"
		"gpr	Z	.1	.25	0\n"
		"gpr	I	.1	.26	0\n"
		"gpr	D	.1	.27	0\n"
		"gpr	V	.1	.30	0\n"
		"gpr	N	.1	.31	0\n"
		"gpr	sp	.8	4	0\n"
		"gpr	pc	.64	5	0\n";
	return strdup (p);
}

static int archinfo(RArchSession *a, ut32 q) {
	return 1;
}

RArchPlugin r_arch_plugin_sm5xx = {
	.name = "sm5xx",
	.desc = "Sharp SM 5XX family MCUs",
	.license = "BSD",
	.bits = 4,
	.regs = regs,
	.arch = "sm5xx",
	.cpus = "5a,500,510,511,530,590",
	.info = archinfo,
	.decode = &decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_sm5xx,
	.version = R2_VERSION
};
#endif
