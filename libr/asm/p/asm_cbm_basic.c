/* radare - LGPL - Copyright 2020 - thestr4ng3r */

#include "../arch/cbm_basic/cbm_basic_dis.h"

#include <r_asm.h>
#include <r_lib.h>

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	if (!len) {
		return 0;
	}
	RBuffer *buffer = r_buf_new_with_bytes (buf, len);
	if (!buffer) {
		return 0;
	}
	op->size = r_cbm_basic_disassemble (&op->buf_asm, buffer, true);
	r_buf_free (buffer);
	return op->size;
}

RAsmPlugin r_asm_plugin_cbm_basic = {
	.name = "cbm-basic",
	.arch = "cbm-basic",
	.cpus = "c64",
	.license = "LGPL3",
	.author = "thestr4ng3r",
	.bits = 8,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "Commodore Basic (C64, VIC-20, PET, etc.)",
	.disassemble = &disassemble
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_avr,
	.version = R2_VERSION
};
#endif
