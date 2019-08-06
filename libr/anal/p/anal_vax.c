/* radare - LGPL - Copyright 2015 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

// XXX: this is just a PoC
// XXX: do not hardcode size/type here, use proper decoding table
// http://hotkosc.ru:8080/method-vax.doc

static int vax_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	op->size = 1;
	if (len < 1) {
		return -1;
	}
	op->type = R_ANAL_OP_TYPE_UNK;
	switch (buf[0]) {
	case 0xd0:
	case 0x2e:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->size = 8;
		break;
	case 0x78:
		op->type = R_ANAL_OP_TYPE_SHL;
		op->size = 8;
		break;
	case 0xc0:
	case 0xd8:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = 8;
		break;
	case 0x00:
		op->type = R_ANAL_OP_TYPE_TRAP; // HALT
		break;
	case 0x01:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case 0x51:
	case 0x73:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0xac:
		op->type = R_ANAL_OP_TYPE_XOR;
		op->size = 4;
		break;
	case 0x5a:
		op->size = 2;
		break;
	case 0x11:
	case 0x18:
		op->size = 2;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case 0x31:
	case 0xe9:
		op->size = 3;
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case 0xc6:
	case 0xc7:
		op->size = 8;
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case 0xd6:
	case 0x61:
		op->size = 2;
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case 0x62:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0xff:
		op->size = 2;
		break;
	}
	return op->size;
}

RAnalPlugin r_anal_plugin_vax = {
	.name = "vax",
	.desc = "VAX code analysis plugin",
	.license = "LGPL3",
	.arch = "vax",
	.esil = true,
	.bits = 8 | 32,
	.op = &vax_op,
	#if 0
	.archinfo = archinfo,
	.set_reg_profile = &set_reg_profile,
	.esil_init = esil_vax_init,
	.esil_fini = esil_vax_fini,
	#endif
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_vax,
	.version = R2_VERSION
};
#endif
