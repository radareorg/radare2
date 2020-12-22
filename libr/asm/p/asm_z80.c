/* radare - LGPL - Copyright 2012-2018 - pancake */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/z80/z80.c"
#include "../arch/z80/z80asm.c"

static int do_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	return op->size = z80Disass (op, buf, len);
}

static int do_assemble(RAsm *a, RAsmOp *op, const char *buf) {
	return op->size = z80asm ((ut8*)r_strbuf_get (&op->buf), buf);
}

RAsmPlugin r_asm_plugin_z80 = {
	.name = "z80",
	.desc = "Zilog Z80",
	.license = "GPL",
	.author = "condret",
	.arch = "z80",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.disassemble = &do_disassemble,
	.assemble = &do_assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_z80,
	.version = R2_VERSION
};
#endif
