/* radare - LGPL - Copyright 2012-2013 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/z80/z80.c"

static int do_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return op->size = z80asm (op->buf, buf);
}

static int do_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int dlen = z80dis (0, buf, op->buf_asm, len);
	if (dlen<0) dlen = 0;
	op->size = dlen;
	return op->size;
}

RAsmPlugin r_asm_plugin_z80 = {
	.name = "z80",
	.desc = "Zilog Z80",
	.license = "NC-GPL2", //NON-COMMERCIAL",
	.arch = "z80",
	.bits = 8,
	.init = NULL,
	.fini = NULL,
	.disassemble = do_disassemble,
	.assemble = &do_assemble, 
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_z80
};
#endif
