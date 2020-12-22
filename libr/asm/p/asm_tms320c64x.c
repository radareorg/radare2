/* radare2 - LGPL - Copyright 2017-2018 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>
static csh cd = 0;
#include "cs_mnemonics.c"

#ifdef CAPSTONE_TMS320C64X_H
#define CAPSTONE_HAS_TMS320C64X 1
#else
#define CAPSTONE_HAS_TMS320C64X 0
#warning Cannot find capstone-tms320c64x support
#endif

#if CAPSTONE_HAS_TMS320C64X

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	cs_insn* insn;
	int n = -1, ret = -1;
	int mode = 0;
	if (op) {
		memset (op, 0, sizeof (RAsmOp));
		op->size = 4;
	}
	if (cd != 0) {
		cs_close (&cd);
	}
	ret = cs_open (CS_ARCH_TMS320C64X, mode, &cd);
	if (ret) {
		goto fin;
	}
	cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	if (!op) {
		return 0;
	}
	n = cs_disasm (cd, buf, len, a->pc, 1, &insn);
	if (n < 1) {
		r_asm_op_set_asm (op, "invalid");
		op->size = 4;
		ret = -1;
		goto beach;
	} else {
		ret = 4;
	}
	if (insn->size < 1) {
		goto beach;
	}
	op->size = insn->size;
	r_asm_op_set_asm (op, sdb_fmt ("%s%s%s",
		insn->mnemonic, insn->op_str[0]? " ": "",
		insn->op_str));
	r_str_replace_char (r_strbuf_get (&op->buf_asm), '%', 0);
	r_str_case (r_strbuf_get (&op->buf_asm), false);
	cs_free (insn, n);
	beach:
	// cs_close (&cd);
	fin:
	return ret;
}

RAsmPlugin r_asm_plugin_tms320c64x = {
	.name = "tms320c64x",
	.desc = "Capstone TMS320c64x disassembler",
	.license = "BSD",
	.arch = "tms320c64x",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG | R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.mnemonics = mnemonics
};

#else

RAsmPlugin r_asm_plugin_tms320c64x = {
	.name = "tms320c64x",
	.desc = "Capstone TMS320c64x disassembler (unsupported)",
	.license = "BSD",
	.arch = "tms320c64x",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE,
	.mnemonics = mnemonics
};

#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_tms320c64x,
	.version = R2_VERSION
};
#endif
