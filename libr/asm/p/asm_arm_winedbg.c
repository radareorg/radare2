/* radare - LGPL - Copyright 2009-2022 - nibble, pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/arm/winedbg/be_arm.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut8 buf2[4];
	struct winedbg_arm_insn *arminsn = arm_new();
	arm_set_pc (arminsn, a->pc);
	arm_set_thumb (arminsn, a->config->bits == 16);
	if (a->config->big_endian && a->config->bits == 32) {
		r_mem_swapendian (buf2, buf, 4);
		arm_set_input_buffer (arminsn, buf2);
	} else {
		arm_set_input_buffer (arminsn, buf);
	}
	op->size = arm_disasm_one_insn (arminsn);
	const char *asmstr = winedbg_arm_insn_asm (arminsn);
	if (asmstr) {
		r_strbuf_set (&op->buf_asm, asmstr);
		r_asm_op_set_hex (op, winedbg_arm_insn_hex (arminsn));
	} else {
		r_strbuf_set (&op->buf_asm, "invalid");
		r_strbuf_set (&op->buf, "");
	}
	arm_free (arminsn);
	return op->size;
}

RAsmPlugin r_asm_plugin_arm_winedbg = {
	.name = "arm.winedbg",
	.arch = "arm",
	.bits = 16 | 32,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "WineDBG's ARM disassembler",
	.disassemble = &disassemble,
	.license = "LGPL2"
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_winedbg,
	.version = R2_VERSION
};
#endif
