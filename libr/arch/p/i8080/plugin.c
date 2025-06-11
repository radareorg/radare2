/* radare - LGPL - Copyright 2012-2024 - pancake */

// This file is based on the Z80 analyser and modified for
// the Intel 8080 disassembler by Alexander Demin, 2012.

#include <r_arch.h>
#include "i8080.h"

static bool decode (RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
//	if (op->size < 3) {
//		op->mnemonic = strdup ("invalid");
//		return false;
//	}
	RStrBuf *sb = r_strbuf_new ("");
	i8080_disasm (op, sb);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = r_strbuf_drain (sb);
	} else {
		r_strbuf_free (sb);
	}
	return op->size > 0;
}

static char *get_reg_profile (RArchSession *as) {
	const char p[] =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	sp\n" // XXX
		"=SN	a\n"
		"=R0	a\n"
		"=A0	a\n"
		"=A1	b\n"
		"=A2	c\n"
		"=A3	d\n"
		"gpr	psw	.8	0	0\n"
		"gpr	a	.8	1	0\n" // r14
		"gpr	b	.8	2	0\n" // r15
		"gpr	c	.8	3	0\n" // r16 // out of context
		"gpr	d	.8	4	0\n" // like rbp on x86 // out of context
		"gpr	e	.8	5	0\n"
		"gpr	h	.8	6	0\n"
		"gpr	l	.8	7	0\n"
		"gpr	sp	.64	8	0\n"
		"gpr	pc	.64	16	0\n"
		"flg	sf	.1	0	0\n"
		"flg	zf	.1	.1	0\n"
		"flg	hf	.1	.3	0\n"
		"flg	pf	.1	.5	0\n"
		"flg	cf	.1	.7	0\n";
	return strdup (p);
}

static int archinfo (RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MAXOP_SIZE:
		return 3;
	}
	return 1;
}

const RArchPlugin r_arch_plugin_i8080 = {
	.meta = {
		.name = "i8080",
		.author = "pancake",
		.desc = "Intel 8080",
		.license = "LGPL-3.0-only",
	},
	.arch = "i8080",
	.bits = R_SYS_BITS_PACK1 (16),
	.endian = R_SYS_ENDIAN_LITTLE,
	.decode = &decode,
	.info = archinfo,
	.regs = get_reg_profile
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_i8080,
	.version = R2_VERSION
};
#endif
