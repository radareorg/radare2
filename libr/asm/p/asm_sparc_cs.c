/* radare2 - LGPL - Copyright 2014-2016 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone/capstone.h>
static csh cd = 0;
#include "cs_mnemonics.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	cs_insn* insn;
	int n, ret = -1;
	int mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (a->cpu && *a->cpu) {
		if (!strcmp (a->cpu, "v9")) {
			mode |= CS_MODE_V9;
		}
	}
	if (op) {
		memset (op, 0, sizeof (RAsmOp));
		op->size = 4;
	}
	if (cd != 0) {
		cs_close (&cd);
	}
	ret = cs_open (CS_ARCH_SPARC, mode, &cd);
	if (ret) {
		goto fin;
	}
	cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	if (!op) {
		return 0;
	}
	n = cs_disasm (cd, buf, len, a->pc, 1, &insn);
	if (n < 1) {
		strcpy (op->buf_asm, "invalid");
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
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
		insn->mnemonic, insn->op_str[0]? " ": "",
		insn->op_str);
	// TODO: remove the '$'<registername> in the string
	cs_free (insn, n);
	beach:
	// cs_close (&cd);
	fin:
	return ret;
}

RAsmPlugin r_asm_plugin_sparc_cs = {
	.name = "sparc",
	.desc = "Capstone SPARC disassembler",
	.license = "BSD",
	.arch = "sparc",
	.cpus = "v9",
	.bits = 32|64,
	.endian = R_SYS_ENDIAN_BIG | R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.mnemonics = mnemonics
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_sparc_cs,
	.version = R2_VERSION
};
#endif
