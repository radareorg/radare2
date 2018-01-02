/* radare2 - LGPL - Copyright 2018 - thestr4ng3r */

#include <r_asm.h>
#include <r_lib.h>

#include "../arch/pic/pic_baseline.h"

static int asm_pic_disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	return pic_baseline_disassemble(a, op, b, l);
}

RAsmPlugin r_asm_plugin_pic = {
	.name = "pic",
	.arch = "pic",
	.bits = 8,
	.license = "LGPL3",
	.desc = "PIC disassembler",
	.disassemble = &asm_pic_disassemble
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pic
};
#endif
