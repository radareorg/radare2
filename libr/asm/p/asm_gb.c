/* radare - LGPL - Copyright 2012-2013 - pancake
	2013 - condret					*/

// fork of asm_z80.c

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/gb/gbdis.c"

static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, ut64 len) {
	int dlen = gbDisass(r_op,buf,len);
	if(dlen<0) dlen=0;
	r_op->inst_len=dlen;
	return dlen;
}

RAsmPlugin r_asm_plugin_gb = {
	.name = "gb",
	.desc = "GB disassembly plugin",
	.arch = "z80",				//?
	.license = "LGPL3",
	.bits = (int[]){ 8, 0 }, /* supported wordsizes */
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_gb
};
#endif
