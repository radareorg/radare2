/* radare - LGPL - Copyright 2015 - condret */

#include <r_anal.h>
#include <r_types.h>
#include <r_lib.h>

static int mal_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len, RAnalOpMask mask) {
	memset (op, '\0', sizeof (RAnalOp));
	if (len) {
		switch ((data[0] + addr) % 94) {
		case 4:
			op->type = R_ANAL_OP_TYPE_UJMP;
			break;
		case 5:
		case 23:
			op->type = R_ANAL_OP_TYPE_IO;
			break;
		case 39:
			op->type = R_ANAL_OP_TYPE_ROR;
			op->type2 = R_ANAL_OP_TYPE_LOAD;
			break;
		case 40:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 62:
			op->type = R_ANAL_OP_TYPE_XOR;
			op->type2 = R_ANAL_OP_TYPE_LOAD;
			break;
		case 81:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_NOP;
		}
		return op->size = 1;
	}
	return false;
}

RAnalPlugin r_anal_plugin_malbolge = {
	.name = "malbolge",
	.desc = "Malbolge analysis plugin",
	.arch = "malbolge",
	.license = "LGPL3",
	.bits = 32,
	.op = &mal_anal,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_malbolge,
	.version = R2_VERSION
};
#endif
