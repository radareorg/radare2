/* radare - LGPL - Copyright 2012-2013 - Alexander */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/i8080/i8080dis.c"

static int do_disassemble(RAsm *a, struct r_asm_op_t *op, const ut8 *buf, int len) {
	int dlen = i8080_disasm (buf, op->buf_asm, len);
	if (dlen<0) dlen = 0;
	op->size = dlen;
	return op->size;
}

RAsmPlugin r_asm_plugin_i8080 = {
	.name = "i8080",
	.desc = "Intel 8080 CPU",
	.arch = "i8080",
	.license = "BSD",
	.bits = 8,
	.init = NULL,
	.fini = NULL,
	.disassemble = do_disassemble,
	.assemble = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_i8080
};
#endif
