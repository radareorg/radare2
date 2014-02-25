/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/avr/disasm.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return op->size = avrdis (op->buf_asm, a->pc, buf, len);
}

RAsmPlugin r_asm_plugin_avr = {
	.name = "avr",
	.arch = "avr",
	.license = "GPL",
	.bits = 16|32,
	.desc = "AVR Atmel",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_avr
};
#endif
