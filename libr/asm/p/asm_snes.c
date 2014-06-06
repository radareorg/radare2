/* radare - LGPL - Copyright 2012-2014 - condret, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/snes/snesdis.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int dlen = snesDisass(op,buf,len);
	if (dlen<0) dlen=0;
	op->size = dlen;
	return dlen;
}

RAsmPlugin r_asm_plugin_snes = {
	.name = "snes",
	.desc = "SuperNES CPU",
	.arch = "snes",
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
	.data = &r_asm_plugin_snes
};
#endif
