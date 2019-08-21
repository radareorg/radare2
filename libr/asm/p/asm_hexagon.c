/* radare - LGPL - Copyright 2018 - xvilka */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "hexagon.h"
#include "hexagon_insn.h"

static int disassemble (RAsm *a, RAsmOp *op, const ut8 *buf, int l) {
	HexInsn hi = {0};
	ut32 data = r_read_le32 (buf);
	op->size = hexagon_disasm_instruction (data, &hi, (ut32) a->pc);
	r_strbuf_set (&op->buf_asm, hi.mnem);
	return op->size;
}

RAsmPlugin r_asm_plugin_hexagon = {
	.name = "hexagon",
	.arch = "hexagon",
	.author = "xvilka",
	.license = "LGPL3",
	.bits = 32,
	.desc = "Qualcomm Hexagon (QDSP6) V6",
	.disassemble = &disassemble,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_hexagon
};
#endif
