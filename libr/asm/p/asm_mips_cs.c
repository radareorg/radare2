/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>
#define R_IPI static
#include "../arch/mips/mipsasm.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	csh handle;
	cs_insn* insn;
	int mode, n, ret = -1;
	mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (a->cpu && *a->cpu) {
		if (!strcmp (a->cpu, "gp64")) {
			mode |= CS_MODE_MIPSGP64;
		} else if (!strcmp (a->cpu, "micro")) {
			mode |= CS_MODE_MICRO;
		} else if (!strcmp (a->cpu, "r6")) {
			mode |= CS_MODE_MIPS32R6;
		} else if (!strcmp (a->cpu, "v3")) {
			mode |= CS_MODE_MIPS3;
		}
	}
	mode |= (a->bits==64)? CS_MODE_64: CS_MODE_32;
	memset (op, 0, sizeof (RAsmOp));
	op->size = 4;
	ret = cs_open (CS_ARCH_MIPS, mode, &handle);
	if (ret) goto fin;
	if (a->syntax == R_ASM_SYNTAX_REGNUM) {
		cs_option (handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else cs_option (handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
	n = cs_disasm (handle, (ut8*)buf, len, a->pc, 1, &insn);
	if (n<1) {
		strcpy (op->buf_asm, "invalid");
		op->size = 4;
		ret = -1;
		goto beach;
	} else ret = 4;
	if (insn->size<1)
		goto beach;
	op->size = insn->size;
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
		insn->mnemonic, insn->op_str[0]? " ": "",
		insn->op_str);
	// remove the '$'<registername> in the string
	r_str_replace_char (op->buf_asm, '$', 0);
	cs_free (insn, n);
	beach:
	cs_close (&handle);
	fin:
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	int ret = mips_assemble (str, a->pc, op->buf);
	r_mem_copyendian (op->buf, op->buf, 4, !a->big_endian);
	return ret;
}

RAsmPlugin r_asm_plugin_mips_cs = {
	.name = "mips",
	.desc = "Capstone MIPS disassembler",
	.license = "BSD",
	.arch = "mips",
	.cpus = "gp64,micro,r6,v3",
	.bits = 16|32|64,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = assemble
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mips_cs
};
#endif
