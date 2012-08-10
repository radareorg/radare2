/* radare - LGPL - Copyright 2012 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/z80/z80.c"

static int do_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return op->inst_len = z80asm (op->buf, buf);
}

static int do_disassemble(struct r_asm_t *a, struct r_asm_op_t *op, const ut8 *buf, ut64 len) {
	int dlen = z80dis (0, buf, op->buf_asm, len);
	if (dlen<0) dlen = 0;
	op->inst_len = dlen;
	return op->inst_len;
}

RAsmPlugin r_asm_plugin_z80 = {
	.name = "z80",
	.desc = "z80 assembler plugin",
	.arch = "z80",
	.bits = (int[]){ 8, 0 },
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
