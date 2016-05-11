/* radare - LGPL - Copyright 2014-2015 - condret, pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/z80_cr/z80_cr.c"

static int do_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return op->size = z80Disass (op, buf, len);
}

RAsmPlugin r_asm_plugin_z80_cr = {
	.name = "z80.cr",
	.desc = "Zilog Z80",
	.license = "LGPL",
	.arch = "z80",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &do_disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_z80_cr,
	.version = R2_VERSION
};
#endif
