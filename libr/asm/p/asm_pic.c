/* radare2 - LGPL - Copyright 2018 - thestr4ng3r, courk */

#include <r_asm.h>
#include <r_lib.h>

#include "../arch/pic/pic_baseline.h"
#include "../arch/pic/pic_pic18.h"
#include "../arch/pic/pic_midrange.h"

static int asm_pic_disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	if (a->cpu && strcasecmp (a->cpu, "baseline") == 0) {
		return pic_baseline_disassemble (a, op, b, l);
	}
	if (a->cpu && strcasecmp (a->cpu, "midrange") == 0) {
		return pic_midrange_disassemble (a, op, b, l);
	}
	if (a->cpu && strcasecmp (a->cpu, "pic18") == 0) {
		return pic_pic18_disassemble (a, op, b, l);
	}

	snprintf (op->buf_asm, R_ASM_BUFSIZE - 1, "Unknown asm.cpu");
	return op->size = -1;
}

RAsmPlugin r_asm_plugin_pic = {
	.name = "pic",
	.arch = "pic",
	.cpus = "baseline,midrange,pic18",
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
