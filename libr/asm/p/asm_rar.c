/* radare - LGPL - Copyright 2012 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, ut64 len) {
	// TODO: support bitsize opcodes
	return 0;
}

// XXX: This is wrong, some opcodes are 32bit in thumb mode
static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return 0;
}

RAsmPlugin r_asm_plugin_rar = {
	.name = "rar",
	.arch = "rar",
	.bits = (int[]){ 32, 0 },
	.desc = "RAR VM disassembly plugin",
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.assemble = &assemble 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_rar
};
#endif
