/* radare2 - LGPL - Copyright 2014 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int nios2_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *b, int len) {
	if (op == NULL)
		return 1;
	/* Ayeeee! What's inside op? Do we have an initialized RAnalOp? Are we going to have a leak here? :-( */
	memset (op, 0, sizeof (RAnalOp)); /* We need to refactorize this. Something like r_anal_op_init would be more appropiate */
	r_strbuf_init (&op->esil);
	op->size = 4;

	if ((b[0]&0xff) == 0x3a) {
		// XXX
		op->type = R_ANAL_OP_TYPE_RET;
	} else
	if ((b[0]&0xf) == 0xa) {
		op->type = R_ANAL_OP_TYPE_JMP;
	} else
	if ((b[0]&0xf) == 4) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else
	if ((b[0]&0xf) == 5) {
		op->type = R_ANAL_OP_TYPE_STORE;
	} else
	if ((b[0]&0xf) == 6) {
		// blt, r19, r5, 0x8023480
		op->type = R_ANAL_OP_TYPE_CJMP;
		// TODO: address
	} else
	if ((b[0]&0xf) == 7) {
		// blt, r19, r5, 0x8023480
		op->type = R_ANAL_OP_TYPE_LOAD;
		// TODO: address
	} else
	switch (b[0]) {
	case 0x3a:
		if (b[1]>=0xa0 && b[1]<=0xaf && b[3]==0x3d) {
			op->type = R_ANAL_OP_TYPE_TRAP;
		} else
		if ((b[1]>=0xe0&&b[1]<=0xe7) && b[2]==0x3e && !b[3]) {
			// nextpc ra
			op->type = R_ANAL_OP_TYPE_RET;
		}
		break;
	case 0x01:
		// jmpi
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case 0x00:
	case 0x20:
	case 0x40:
	case 0x80:
	case 0xc0:
		// 
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	case 0x26:
		// beq
		break;
	case 0x07:
	case 0x47:
	case 0x87:
	case 0xc7:
		// ldb
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x0d:
	case 0x2d:
	case 0x4d:
	case 0x8d:
	case 0xcd:
		// sth && sthio
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case 0x06:
	case 0x46:
	case 0x86:
	case 0xc6:
		// br
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
	}
	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_nios2 = {
	.name = "nios2",
	.desc = "NIOS II code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_BF,
	.esil = R_TRUE,
	.bits = 32,
	.init = NULL,
	.fini = NULL,
	.op = &nios2_op,
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
	.data = &r_anal_plugin_nios2
};
#endif
