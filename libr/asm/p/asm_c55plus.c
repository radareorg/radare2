/* radare - LGPL - Copyright 2009-2013 - th0rpe, pancake */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

#include "dis-asm.h"

int c55plus_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len);

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return c55plus_disassemble (a, op, buf, len);
}

RAsmPlugin r_asm_plugin_c55plus = {
	.name = "c55+",
	.desc = "c55+ disassembly plugin",
	.arch = "c55+",
	.bits = (int[]){ 32, 40 },
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_c55plus
};
#endif
