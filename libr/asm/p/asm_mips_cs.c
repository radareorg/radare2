/* radare2 - LGPL - Copyright 2013-2021 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include "cs_version.h"

R_IPI int mips_assemble(const char *str, ut64 pc, ut8 *out);

static csh cd = 0;
#include "cs_mnemonics.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	cs_insn* insn;
	int mode, n, ret = -1;
	mode = (a->config->big_endian)? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	if (!op) {
		return 0;
	}
	const char *cpu = a->config->cpu;
	if (R_STR_ISNOTEMPTY (cpu)) {
		if (!strcmp (cpu, "micro")) {
			mode |= CS_MODE_MICRO;
		} else if (!strcmp (cpu, "r6")) {
			mode |= CS_MODE_MIPS32R6;
		} else if (!strcmp (cpu, "v3")) {
			mode |= CS_MODE_MIPS3;
		} else if (!strcmp (cpu, "v2")) {
#if CS_API_MAJOR > 3
			mode |= CS_MODE_MIPS2;
#endif
		}
	}
	mode |= (a->config->bits == 64)? CS_MODE_MIPS64 : CS_MODE_MIPS32;
	memset (op, 0, sizeof (RAsmOp));
	op->size = 4;
	if (cd != 0) {
		cs_close (&cd);
	}
	ret = cs_open (CS_ARCH_MIPS, mode, &cd);
	if (ret) {
		goto fin;
	}
	if (a->config->syntax == R_ASM_SYNTAX_REGNUM) {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}
	cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	n = cs_disasm (cd, (ut8*)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		r_asm_op_set_asm (op, "invalid");
		op->size = 4;
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

static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	ut8 *opbuf = (ut8*)r_strbuf_get (&op->buf);
	int ret = mips_assemble (str, a->pc, opbuf);
	if (a->config->big_endian) {
		ut8 *buf = opbuf;
		ut8 tmp = buf[0];
		buf[0] = buf[3];
		buf[3] = tmp;
		tmp = buf[1];
		buf[1] = buf[2];
		buf[2] = tmp;
	}
	return ret;
}

RAsmPlugin r_asm_plugin_mips_cs = {
	.name = "mips",
	.desc = "Capstone "CAPSTONE_VERSION_STRING" MIPS disassembler",
	.license = "BSD",
	.arch = "mips",
	.cpus = "mips32/64,micro,r6,v3,v2",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
	.mnemonics = mnemonics,
	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_mips_cs,
	.version = R2_VERSION
};
#endif
