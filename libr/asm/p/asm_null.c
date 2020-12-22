/* radare - LGPL - Copyright 2019 - pancake */

#include <stdio.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int opsz = 0;
	r_strbuf_set (&op->buf_asm, "");
	op->size = opsz;
	return opsz;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return 0;
}

RAsmPlugin r_asm_plugin_null = {
	.name = "null",
	.author = "pancake",
	.version = "1.0.0",
	.arch = "null",
	.license = "MIT",
	.bits = 16 | 32 | 64,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "no disassemble",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_null,
	.version = R2_VERSION
};
#endif
