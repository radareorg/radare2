/* radare - LGPL - Copyright 2012-2018 - Alexander */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/i8080/i8080dis.c"

static int do_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	int dlen = i8080_disasm (buf, r_strbuf_get (&op->buf_asm), len);
	return op->size = R_MAX (0, dlen);
}

RAsmPlugin r_asm_plugin_i8080 = {
	.name = "i8080",
	.desc = "Intel 8080 CPU",
	.arch = "i8080",
	.license = "BSD",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &do_disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_i8080,
	.version = R2_VERSION
};
#endif
