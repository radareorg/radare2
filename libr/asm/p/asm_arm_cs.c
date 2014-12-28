/* radare2 - LGPL - Copyright 2013-2014 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	cs_insn* insn = NULL;
	cs_mode mode = 0;
	int ret, n = 0;
	csh cd;
	mode = (a->bits==16)? CS_MODE_THUMB: CS_MODE_ARM;
	if (a->big_endian)
		mode |= CS_MODE_BIG_ENDIAN;
	else
		mode |= CS_MODE_LITTLE_ENDIAN;

	if (a->cpu && strstr (a->cpu, "m"))
		mode |= CS_MODE_MCLASS;
	if (a->cpu && strstr (a->cpu, "v8"))
		mode |= CS_MODE_V8;
	op->size = 4;
	op->buf_asm[0] = 0;
	ret = (a->bits==64)?
		cs_open (CS_ARCH_ARM64, mode, &cd):
		cs_open (CS_ARCH_ARM, mode, &cd);
	if (ret) {
		ret = -1;
		goto beach;
	}
	if (a->syntax == R_ASM_SYNTAX_REGNUM) {
		cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else cs_option (cd, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	cs_option (cd, CS_OPT_DETAIL, CS_OPT_OFF);
	n = cs_disasm (cd, buf, R_MIN (4, len),
		a->pc, 1, &insn);
	if (n<1) {
		ret = -1;
		goto beach;
	}
	if (insn->size<1) {
		ret = -1;
		goto beach;
	}
	op->size = insn->size;
	snprintf (op->buf_asm, R_ASM_BUFSIZE, "%s%s%s",
		insn->mnemonic,
		insn->op_str[0]?" ":"",
		insn->op_str);
	r_str_rmch (op->buf_asm, '#');
	cs_free (insn, n);
	beach:
	cs_close (&cd);
	if (!op->buf_asm[0])
		strcpy (op->buf_asm, "invalid");
	return op->size;
}

RAsmPlugin r_asm_plugin_arm_cs = {
	.name = "arm",
	.desc = "Capstone ARM disassembler",
	.cpus = "v8,cortex-m",
	.license = "BSD",
	.arch = "arm",
	.bits = 16|32|64,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_cs
};
#endif
