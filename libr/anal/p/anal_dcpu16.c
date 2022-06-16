/* radare2 - LGPL - Copyright 2012-2021 pancake */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_anal.h>
#include "../arch/dcpu16/dcpu16.h"
#include "../arch/dcpu16/dis.c"
#include "../arch/dcpu16/asm.c"

static int dcpu16_op(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	char buf_asm[96];
	if (len < 2) {
		return -1; // at least 2 bytes!
	}
	op->size = dcpu16_disasm (buf_asm, sizeof (buf_asm), (const ut16*)buf, len, NULL);
	if (mask & R_ANAL_OP_MASK_DISASM) {
		op->mnemonic = strdup ((op->size > 0)? buf_asm: "data");
	}
	return op->size;
}

static int dcpu16_opasm(RAnal *a, ut64 addr, const char *str, ut8 *outbuf, int outsize) {
	return dcpu16_assemble (outbuf, str);
}

RAnalPlugin r_anal_plugin_dcpu16 = {
	.name = "dcpu16",
	.arch = "dpcu",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.desc = "Mojang's DCPU-16",
	.license = "PD",
	.op = &dcpu16_op,
	.opasm = &dcpu16_opasm
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_dcpu16,
	.version = R2_VERSION
};
#endif
