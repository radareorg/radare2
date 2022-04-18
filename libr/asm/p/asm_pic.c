/* radare2 - LGPL - Copyright 2018-2022 - thestr4ng3r, courk */

#include <r_asm.h>
#include <r_lib.h>

#include "../arch/pic/pic_baseline.h"
#include "../arch/pic/pic_pic18.h"
#include "../arch/pic/pic_midrange.h"

static int asm_pic_disassemble(RAsm *a, RAsmOp *op, const ut8 *b, int l) {
	int res = -1;
	char opbuf[128];
	const char *opstr = opbuf;
	strcpy (opbuf, "invalid");
	const char *cpu = a->config->cpu;
	if (R_STR_ISNOTEMPTY (cpu)) {
		if (strcasecmp (cpu, "baseline") == 0) {
			res = pic_baseline_disassemble (op, opbuf, b, l);
		} else if (strcasecmp (cpu, "midrange") == 0) {
			res = pic_midrange_disassemble (op, opbuf, b, l);
		} else if (strcasecmp (cpu, "pic18") == 0) {
			res = pic_pic18_disassemble (op, opbuf, b, l);
		}
	}
	r_asm_op_set_asm (op, opstr);
	return op->size = res;
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_pic
};
#endif
