/* radare - LGPL - Copyright 2009-2014 - nibble */

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
	arm_set_thumb (arminsn, a->bits == 16);
	if (a->big_endian && a->bits == 32) {
		r_mem_copyendian (buf2, buf, 4, 0);
		arm_set_input_buffer (arminsn, buf2);
	} else {
		arm_set_input_buffer (arminsn, buf);
	}
	op->size = arm_disasm_one_insn (arminsn);
	strncpy (op->buf_asm, winedbg_arm_insn_asm (arminsn), R_ASM_BUFSIZE-1);
	strncpy (op->buf_hex, winedbg_arm_insn_hex (arminsn), R_ASM_BUFSIZE-1);
	arm_free (arminsn);
	return op->size;
}

RAsmPlugin r_asm_plugin_arm_winedbg = {
	.name = "arm.winedbg",
	.arch = "arm",
	.bits = 16|32,
	.desc = "WineDBG's ARM disassembler",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL,
	.license = "LGPL2"
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_arm_winedbg
};
#endif
