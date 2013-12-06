/* radare - LGPL - Copyright 2011 - pancake<nopcode.org>, Roc Vallès <vallesroc@gmail.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

ut32 get_ins_len(ut8 opcode);

static int c55plus_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ut16 *ins = (ut16*)buf;
	ut32 ins_len;

	if (buf == NULL || len <= 0)
		return 0;

	ins_len = get_ins_len(buf[0]);
	if(ins_len == 0)
		return 0;

	memset (op, 0, sizeof (RAnalOp));
	op->type = R_ANAL_OP_TYPE_UNK;
	op->addr = addr;
	op->jump = op->fail = -1;
	op->ptr = op->val = -1;
        op->size = ins_len;

	if (ins_len >= 1 && *ins == 0x20) {
		op->type = R_ANAL_OP_TYPE_NOP;

	} else if (ins_len >= 4 && buf[0] == 0xD8) { //  BCC conditional absolute jump
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];

	} else if (ins_len >= 2 && buf[0] == 0x6A) { //  BCC conditional relative jump
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + ((st8)buf[1]) + ins_len;

	} else if (ins_len >= 3 && buf[0] == 0x9A) { // BCC conditional relative jump
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;

	} else if (ins_len >= 4 && buf[0] == 0x9C) { // B unconditional absolute jump
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];

	} else if (ins_len >= 3 && buf[0] == 0x68) { // B unconditional relative jump
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;

 	} else if (ins_len == 2 && buf[0] == 0x02) { // CALL unconditional absolute call with acumulator register ACx

		op->type = R_ANAL_OP_TYPE_UCALL;
		op->fail = addr + ins_len;

 	} else if (ins_len >= 3 && buf[0] == 0x69) { // CALL unconditional relative call

		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;

 	} else if (ins_len >= 3 && buf[0] == 0x9D) { // CALL unconditional absolute call
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];

 	} else if (ins_len >= 3 && buf[0] == 0x9B) { // CALLCC conditional relative call
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;

 	} else if (ins_len >= 4 && buf[0] == 0xD9) { // CALLCC conditional absolute call
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];

	} else {
		op->type = R_ANAL_OP_TYPE_UNK;
	}

	return op->size;
}

struct r_anal_plugin_t r_anal_plugin_c55plus = {
	.name = "c55+",
	.desc = "C55+ code analysis plugin",
	.arch = R_SYS_ARCH_C55PLUS,
	.license = "LGPL3",
	.bits = 32 | 40,
	.init = NULL,
	.fini = NULL,
	.op = &c55plus_op,
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
	.data = &r_anal_plugin_c55plus
};
#endif
