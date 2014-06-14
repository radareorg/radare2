/* radare - LGPL - Copyright 2012-2014 - pancake
	2014 - condret					*/

// fork of asm_z80.c

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/spc700/spc700dis.c"

static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, int len) {
	int dlen = spc700Disass(r_op, buf, len);
	if(dlen < 0) dlen=0;
	r_op->size = dlen;
	return dlen;
}

RAsmPlugin r_asm_plugin_spc700 = {
	.name = "spc700",
	.desc = "spc700, snes' sound-chip",
	.arch = "spc700",
	.license = "LGPL3",
	.bits = 16,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_spc700
};
#endif
