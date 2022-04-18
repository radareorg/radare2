/* radare2 - LGPL - Copyright 2014-2021 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include "cs_version.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	csh handle;
	cs_insn* insn;
	int mode, n, ret = -1;
	mode = a->config->big_endian? CS_MODE_BIG_ENDIAN: CS_MODE_LITTLE_ENDIAN;
	memset (op, 0, sizeof (RAsmOp));
	op->size = 4;
	ret = cs_open (CS_ARCH_XCORE, mode, &handle);
	if (ret) {
		goto fin;
	}
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
	n = cs_disasm (handle, (ut8*)buf, len, a->pc, 1, &insn);
	if (n < 1) {
		r_asm_op_set_asm (op, "invalid");
		op->size = 4;
		ret = -1;
		goto beach;
	}
	ret = 4;
	if (insn->size < 1) {
		goto beach;
	}
	op->size = insn->size;
	r_strf_buffer (256);
	r_asm_op_set_asm (op, r_strf ("%s%s%s",
		insn->mnemonic, insn->op_str[0]? " ": "",
		insn->op_str));
	// TODO: remove the '$'<registername> in the string
	beach:
	cs_free (insn, n);
	cs_close (&handle);
	fin:
	return ret;
}

RAsmPlugin r_asm_plugin_xcore_cs = {
	.name = "xcore",
	.desc = "Capstone "CAPSTONE_VERSION_STRING" XCore disassembler",
	.license = "BSD",
	.author = "pancake",
	.arch = "xcore",
	.bits = 32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_xcore_cs,
	.version = R2_VERSION
};
#endif
