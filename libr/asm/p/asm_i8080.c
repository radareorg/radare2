/* radare - LGPL - Copyright 2012 - Alexander */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/i8080/i8080dis.c"

static int do_disassemble(struct r_asm_t *a, struct r_asm_op_t *op, const ut8 *buf, ut64 len) {
	int dlen = i8080_disasm (buf, op->buf_asm, len);
	if (dlen<0) dlen = 0;
	op->inst_len = dlen;
	return op->inst_len;
}

RAsmPlugin r_asm_plugin_i8080 = {
	.name = "i8080",
	.desc = "i8080 disassembler plugin",
	.arch = "i8080",
	.bits = (int[]){ 8, 0 },
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
