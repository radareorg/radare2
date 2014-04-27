/* radare2 - LGPL - Copyright 2012-2014 pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/dcpu16/dcpu16.h"
#include "../arch/dcpu16/dis.c"
#include "../arch/dcpu16/asm.c"

// ut64 for length here is overkill!
static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	if (len<2) return -1; // at least 2 bytes!
	op->size = dcpu16_disasm (op->buf_asm, (const ut16*)buf, len, NULL);
	if (op->size == -1)
		strcpy (op->buf_asm, " (data)");
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return dcpu16_assemble (op->buf, buf);
}

RAsmPlugin r_asm_plugin_dcpu16 = {
	.name = "dcpu16",
	.arch = "dpcu",
	.bits = 16,
	.desc = "Mojang's DCPU-16",
	.license = "PD",
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
