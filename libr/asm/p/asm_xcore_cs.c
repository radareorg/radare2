/* radare2 - LGPL - Copyright 2014 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	csh handle;
	cs_insn* insn;
	int mode, n, ret = -1;
	mode = a->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	memset (op, 0, sizeof (RAsmOp));
	op->size = 4;
	ret = cs_open (CS_ARCH_XCORE, mode, &handle);
	if (ret) goto fin;
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
	// TODO: remove the '$'<registername> in the string
	beach:
	cs_free (insn, n);
	cs_close (&handle);
	fin:
	return ret;
}

RAsmPlugin r_asm_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "Capstone XCore disassembler",
	.license = "BSD",
	.arch = "xcore",
	.cpus = NULL,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_xcore_cs
};
#endif
