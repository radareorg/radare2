/* radare2 - LGPL - Copyright 2019-2021 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include "cs_version.h"

#if CS_API_MAJOR >= 5

static csh cd = 0;
#include "cs_mnemonics.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	cs_insn* insn;
	int mode = (a->config->bits == 64)? CS_MODE_RISCV64 : CS_MODE_RISCV32;
	op->size = 4;
	if (cd != 0) {
		cs_close (&cd);
	}
	int ret = cs_open (CS_ARCH_RISCV, mode, &cd);
	if (ret) {
		goto fin;
	}
#if 0
	if (a->syntax == R_ASM_SYNTAX_REGNUM) {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}
	cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
#endif
	int n = cs_disasm (cd, (ut8*)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		r_asm_op_set_asm (op, "invalid");
		op->size = 2;
		goto beach;
	}
	if (insn->size < 1) {
		goto beach;
	}
	op->size = insn->size;
	char *str = r_str_newf ("%s%s%s", insn->mnemonic, insn->op_str[0]? " ": "", insn->op_str);
	if (str) {
		r_str_replace_char (str, '$', 0);
		// remove the '$'<registername> in the string
		r_asm_op_set_asm (op, str);
		free (str);
	}
	cs_free (insn, n);
beach:
	// cs_close (&cd);
fin:
	return op->size;
}

RAsmPlugin r_asm_plugin_riscv_cs = {
	.name = "riscv.cs",
	.desc = "Capstone "CAPSTONE_VERSION_STRING" RISCV disassembler",
	.license = "BSD",
	.arch = "riscv",
	.cpus = "",
	.bits = 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.mnemonics = mnemonics,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_riscv_cs,
	.version = R2_VERSION
};
#endif

#else
RAsmPlugin r_asm_plugin_riscv_cs = {
	0
};
#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.version = R2_VERSION
};
#endif

#endif
