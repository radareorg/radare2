/* radare - LGPL - Copyright 2012-2018 - pancake, condret */

// fork of asm_z80.c

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/gb/gbdis.c"
#include "../arch/gb/gbasm.c"

static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, int len) {
	int dlen = gbDisass(r_op,buf,len);
	return r_op->size = R_MAX (0, dlen);
}

static int assemble(RAsm *a, RAsmOp *r_op, const char *buf) {
	return gbAsm (a, r_op, buf);
}

RAsmPlugin r_asm_plugin_gb = {
	.name = "gb",
	.desc = "GameBoy(TM) (z80-like)",
	.arch = "z80",
	.author = "condret",
	.license = "LGPL3",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
	.assemble = &assemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_gb,
	.version = R2_VERSION
};
#endif
