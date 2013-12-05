/* radare - LGPL - Copyright 2011 - pancake<nopcode.org> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int bf_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	if (op == NULL)
		return 1;
	memset (op, 0, sizeof (RAnalOp));
	op->length = 1;
	op->esil[0] = 0;
	switch (buf[0]) {
	case '[': op->type = R_ANAL_OP_TYPE_CMP; break;
	case ']': op->type = R_ANAL_OP_TYPE_UJMP; break;
	case '>': op->type = R_ANAL_OP_TYPE_ADD;
		strcpy (op->esil, "ptr++");
		break;
	case '<': op->type = R_ANAL_OP_TYPE_SUB;
		strcpy (op->esil, "ptr--");
		break;
	case '+': op->type = R_ANAL_OP_TYPE_ADD;
		strcpy (op->esil, "*ptr++");
		break;
	case '-': op->type = R_ANAL_OP_TYPE_SUB;
		strcpy (op->esil, "*ptr--");
		break;
	case '.': op->type = R_ANAL_OP_TYPE_STORE;
		strcpy (op->esil, "=*ptr");
		break;
	case ',': op->type = R_ANAL_OP_TYPE_LOAD; break;
	case 0x00:
	case 0xff:
		op->type = R_ANAL_OP_TYPE_TRAP; break;
	default: op->type = R_ANAL_OP_TYPE_NOP; break;
	}
	return op->length;
}

struct r_anal_plugin_t r_anal_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_BF,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &bf_op,
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
	.data = &r_anal_plugin_bf
};
#endif
