/* radare - LGPL - Copyright 2017 - pancake */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/evm/evm.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	EvmOp eop = {0};
	evm_dis (&eop, buf, len);
	strncpy (op->buf_asm, eop.txt, sizeof (op->buf_asm));
	op->buf_asm[sizeof (op->buf_asm) - 1] = 0;
	op->size = eop.len;
	return eop.len;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	op->size = evm_asm (buf, op->buf, sizeof (op->buf));
	return op->size;
}

RAsmPlugin r_asm_plugin_evm = {
	.name = "evm",
	.author = "pancake",
	.version = "0.0.1",
	.arch = "evm",
	.license = "MIT",
	.bits = 32,
	.endian = R_SYS_ENDIAN_BIG,
	.desc = "evm",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_evm,
	.version = R2_VERSION
};
#endif
