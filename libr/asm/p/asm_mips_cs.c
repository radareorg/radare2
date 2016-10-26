/* radare2 - LGPL - Copyright 2013-2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>
#define R_IPI static
#include "../arch/mips/mipsasm.c"

static csh cd = 0;
#include "cs_mnemonics.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	cs_insn* insn;
	int mode, n, ret = -1;
	mode = (a->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (a->cpu && *a->cpu) {
		if (!strcmp (a->cpu, "micro")) {
			mode |= CS_MODE_MICRO;
		} else if (!strcmp (a->cpu, "r6")) {
			mode |= CS_MODE_MIPS32R6;
		} else if (!strcmp (a->cpu, "v3")) {
			mode |= CS_MODE_MIPS3;
		}
	}
	mode |= (a->bits == 64)? CS_MODE_64: CS_MODE_32;
	if (op) {
		memset (op, 0, sizeof (RAsmOp));
		op->size = 4;
	}
	if (cd != 0) {
		cs_close (&cd);
	}
	ret = cs_open (CS_ARCH_MIPS, mode, &cd);
	if (ret) {
		goto fin;
	}
	if (a->syntax == R_ASM_SYNTAX_REGNUM) {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}
	cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	if (!op) {
		return 0;
	}
	n = cs_disasm (cd, (ut8*)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		strcpy (op->buf_asm, "invalid");
		op->size = 4;
		goto beach;
	} else {
		ret = 4;
	}
	if (insn->size < 1) {
		goto beach;
	}
	op->size = insn->size;
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
		insn->mnemonic, insn->op_str[0]? " ": "",
		insn->op_str);
	// remove the '$'<registername> in the string
	r_str_replace_char (op->buf_asm, '$', 0);
	cs_free (insn, n);
beach:
	// cs_close (&cd);
fin:
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	int ret = mips_assemble (str, a->pc, op->buf);
	if (a->big_endian) {
		ut8 tmp = op->buf[0];
		op->buf[0] = op->buf[3];
		op->buf[3] = tmp;
		tmp = op->buf[1];
		op->buf[1] = op->buf[2];
		op->buf[2] = tmp;
	}
	return ret;
}

RAsmPlugin r_asm_plugin_mips_cs = {
	.name = "mips",
	.desc = "Capstone MIPS disassembler",
	.license = "BSD",
	.arch = "mips",
	.cpus = "gp64,micro,r6,v3",
	.bits = 16|32|64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.mnemonics = mnemonics,
	.assemble = &assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mips_cs,
	.version = R2_VERSION
};
#endif
