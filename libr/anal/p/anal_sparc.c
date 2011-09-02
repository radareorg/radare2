/* radare - LGPL - Copyright 2011 -- pancake<nopcode.org> */

#include <string.h>

#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

// TODO: this implementation is just a fast hack. needs to be rewritten and completed
static int sparc_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int sz = 4;
	memset (op, 0, sizeof (RAnalOp));
	switch (data[0]) {
	case 0x40:
	case 0x60:
	case 0x70:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0x9c:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case 0x90:
	case 0xac:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case 0xaa:
	case 0x92:
	case 0x94:
	case 0x96:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case 0x81:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case 0x80:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case 0x10:
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 0x22: // 
	case 0x12: // BNE
	case 0x02:
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case 0x01:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	}
	return sz;
}

struct r_anal_plugin_t r_anal_plugin_sparc = {
	.name = "sparc",
	.desc = "SPARC analysis plugin",
	.arch = R_SYS_ARCH_SPARC,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &sparc_op,
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
	.data = &r_anal_plugin_sparc
};
#endif
