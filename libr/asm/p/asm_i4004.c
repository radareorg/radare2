/* radare - LGPL - Copyright 2014 - condret	*/

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/i4004/i4004dis.c"

static int disassemble (RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return i4004dis (op,buf,len);
}

RAsmPlugin r_asm_plugin_i4004 = {
	.name = "i4004",
	.desc = "Intel 4004 microprocessor",
	.arch = "i4004",
	.license = "LGPL3",
	.bits = 4,
	.init = NULL,
	.fini = NULL,
	.disassemble = &disassemble,
	.modify = NULL,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_i4004
};
#endif
