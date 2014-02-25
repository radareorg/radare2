/* radare - LGPL - Copyright 2012-2014 - pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../../shlr/rar/all.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	// TODO: support bitsize opcodes
	// rarvm_disassemble (&b, str);
	return 0;
}

// XXX: This is wrong, some opcodes are 32bit in thumb mode
static int assemble(RAsm *a, RAsmOp *op, const char *str) {
	Bitbuf b = {.out = op->buf, .bits = 0};
	return op->size = rarvm_assemble (&b, str);
}

RAsmPlugin r_asm_plugin_rar = {
	.name = "rar",
	.arch = "rar",
	.license = "LGPL3",
	.bits = 1,
	.desc = "RAR VM",
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
