#include <r_anal.h>
#include <r_types.h>
#include <r_lib.h>

static int mal_anal(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len)
{
	memset(op, '\0', sizeof(RAnalOp));
	if(len) {
		switch ((data[0]+addr)%94) {
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
	return R_FALSE;
}

struct r_anal_plugin_t r_anal_plugin_malbolge = {
	.name = "malbolge",
	.desc = "Malbolge analysis plugin",
	.arch = R_SYS_ARCH_BF,
	.license = "LGPL3",
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &mal_anal,
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
	.data = &r_anal_plugin_malbolge
};
#endif
