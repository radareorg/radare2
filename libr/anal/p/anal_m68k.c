/* radare - LGPL - Copyright 2012-2014 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int m68k_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len) {
	if (op == NULL)
		return 4;
	op->size = 4;
	switch(b[0] &0xf0) {
	case 0xb0:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0x50:
		// TODO:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0xe0:
		// TODO:
		op->type = R_ANAL_OP_TYPE_SHL;
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case 0x80:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0x60: {
		int off = 0;
		ut8 *boff = (ut8*)&off;
		op->type = R_ANAL_OP_TYPE_CALL;
		off = b[1] | (b[2]<<8) | (b[3]<<16);
		if ((b[1]&0x80) == 0xf0) // negative offset
			*boff=0xff;
		op->jump += off;
		op->fail = addr + 4;
		} break;
	case 0x30:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_UNK;
		break;
	}
	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_m68k = {
	.name = "m68k",
	.desc = "Motorola 68000",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_M68K,
	.bits = 16|32,
	.init = NULL,
	.fini = NULL,
	.op = &m68k_op,
	.set_reg_profile = NULL,
	.fingerprint_bb = NULL,
	.fingerprint_fcn = NULL,
	.diff_bb = NULL,
	.diff_fcn = NULL,
	.diff_eval = NULL
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_m68k
};
#endif
