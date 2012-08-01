/* radare2 - LGPL - Copyright 2012 pancake<nopcode.org> */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/dcpu16/dcpu16.h"

// ut64 for length here is overkill!
static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len) {
	if (len<2) return -1; // at least 2 bytes!
	op->inst_len = dcpu16_disasm (op->buf_asm, (const ut16*)buf, len, NULL);
	if (op->inst_len == -1)
		strcpy (op->buf_asm, " (data)");
	return op->inst_len;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return dcpu16_assemble (op->buf, buf);
}

RAsmPlugin r_asm_plugin_dcpu16 = {
	.name = "dcpu16",
	.arch = "dpcu",
	.bits = (int[]){ 16, 0 },
	.desc = "DCPU16 assembler/disassembler",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_dcpu16
};
#endif
