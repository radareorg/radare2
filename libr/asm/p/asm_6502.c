/* radare - LGPL - Copyright 2012-2022 - pancake, condret */

// copypasta from asm_gb.c
#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/6502/6502dis.c"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	ut8 data[8];
	size_t min = R_MIN (len, sizeof (data));
	memcpy (data, buf, min);
	int dlen = _6502Disass (a->pc, op, data, min);
	return op->size = R_MAX (dlen, 0);
}

RAsmPlugin r_asm_plugin_6502 = {
	.name = "6502",
	.desc = "6502/NES/C64/Tamagotchi/T-1000 CPU",
	.arch = "6502",
	.bits = 8|16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.license = "LGPL3",
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_6502,
	.version = R2_VERSION
};
#endif
