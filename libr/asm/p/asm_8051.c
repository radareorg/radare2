/* radare2 - LGPL - Copyright 2013 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/8051/8051.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	Op8051 o = do8051struct (buf, len);
	*op->buf_asm = 0;
	if (!o.name) return 0; // invalid instruction
	do8051disasm (o, a->pc, op->buf_asm, sizeof (op->buf_asm));
	return (op->inst_len = o.length);
}

RAsmPlugin r_asm_plugin_8051 = {
	.name = "8051",
	.arch = "8051",
	.bits = (int[]){ 16, 0 },
	.desc = "8051 assembler/disassembler",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL,
	.license = "PD"
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_8051
};
#endif
