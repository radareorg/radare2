/* radare - LGPL - Copyright 2012-2013 - pancake
	2013 - condret					*/

// copypasta from asm_gb.c

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/snes/snesdis.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len) {
	int dlen = snesDisass(op,buf,len);
	if(dlen<0) dlen=0;
	op->inst_len=dlen;
	return dlen;
}

RAsmPlugin r_asm_plugin_snes = {
	.name = "snes",
	.desc = "SNES disassembly plugin",
	.arch = "snes",
	.bits = (int[]){ 16, 8, 0 }, /* supported wordsizes */
	.init = NULL,
	.fini = NULL,
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
