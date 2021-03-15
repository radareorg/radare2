/* radare2 - LGPL - Copyright 2012-2021 pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include "../arch/dcpu16/dcpu16.h"
#include "../arch/dcpu16/dis.c"
#include "../arch/dcpu16/asm.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char buf_asm[96];
	if (len < 2) {
		return -1; // at least 2 bytes!
	}
	op->size = dcpu16_disasm (buf_asm, sizeof (buf_asm), (const ut16*)buf, len, NULL);
	r_strbuf_set (&op->buf_asm, (op->size > 0) ? buf_asm: "(data)");
	return op->size;
}

static int assemble(RAsm *a, RAsmOp *op, const char *buf) {
	int len = dcpu16_assemble ((ut8*)r_strbuf_get (&op->buf), buf);
	op->buf.len = len;
	return len;
}

RAsmPlugin r_asm_plugin_dcpu16 = {
	.name = "dcpu16",
	.arch = "dpcu",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "Mojang's DCPU-16",
	.license = "PD",
	.disassemble = &disassemble,
	.assemble = &assemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_dcpu16,
	.version = R2_VERSION
};
#endif
