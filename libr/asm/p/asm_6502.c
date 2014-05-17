/* radare - LGPL - Copyright 2012-2014 - pancake
	2014 - condret					*/

// copypasta from asm_gb.c

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/6502/6502dis.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int dlen = _6502Disass (op, buf, len);
	if(dlen<0) dlen=0;
	op->size = dlen;
	return dlen;
}

RAsmPlugin r_asm_plugin_6502 = {
	.name = "6502",
	.desc = "6502/NES/C64/T-1000 CPU",
	.arch = "6502",
	.bits = 8|16,
	.init = NULL,
	.fini = NULL,
	.license = "LGPL3",
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_6502
};
#endif
