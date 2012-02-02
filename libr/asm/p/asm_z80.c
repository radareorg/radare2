/* radare - LGPL - Copyright 2012 pancake<nopcode.org> */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int len = 0;
	eprintf ("TODO\n");
	op->inst_len = len;
	return len;
}

RAsmPlugin r_asm_plugin_z80 = {
	.name = "z80",
	.desc = "z80 assembler plugin",
	.arch = "z80",
	.bits = (int[]){ 8, 0 },
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL,
	.assemble = &assemble, 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_z80
};
#endif
