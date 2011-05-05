/* radare - LGPL - Copyright 2011 - pancake<nopcode.org>, Roc Vallès vallesroc@gmail.com */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int avr_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ut16 *ins = (ut16*)buf;
	if (op == NULL)
		return 2;
	memset (op, 0, sizeof (RAnalOp));
	op->length = 2;
	if (*ins == 0) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else
	if (buf[1]>=0x0c && buf[1]<=0x0f) { // hacky
		op->type = R_ANAL_OP_TYPE_ADD;
	} else
	if (buf[1]>=0x18 && buf[1]<=0x1b) { // hacky
		op->type = R_ANAL_OP_TYPE_SUB;
	} else
	if ((buf[1] & 0xf0 ) == 0x80) {
		op->type = R_ANAL_OP_TYPE_CALL; // call (absolute)
		// TODO: calculate dest address
	} else
	if ((buf[1] & 0xf0 ) == 0xd0) {
		op->addr=addr;
		op->type = R_ANAL_OP_TYPE_CALL; // rcall (relative)
		op->fail = (op->addr)+2;
		short ofst = *ins<<4;
		ofst>>=4;
		ofst*=2;
		op->jump=addr+ofst+2;
		//eprintf("addr: %x inst: %x ofst: %d dest: %x fail:%x\n", op->addr, *ins, ofst, op->jump, op->fail);
	} else
	if ((buf[1] & 0xf0 ) == 0xf0) {
		op->type = R_ANAL_OP_TYPE_CJMP; // breq
		// TODO: calculate dest address
	} else
	if ((buf[1] & 0xf0 ) == 0xc0) { // rjmp (relative)
		op->addr=addr;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->fail = (op->addr)+2;
		short ofst = *ins<<4;
		ofst>>=4;
		ofst*=2;
		op->jump=addr+ofst+2;
		//eprintf("addr: %x inst: %x ofst: %d dest: %x fail:%x\n", op->addr, *ins, ofst, op->jump, op->fail);
	} else
	if (*ins == 0x9508) { // ret
		//eprintf("ret at addr: %x\n", addr);
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = R_TRUE;
		//op->stackptr =
	} else op->type = R_ANAL_OP_TYPE_UNK;
	return op->length;
}

struct r_anal_plugin_t r_anal_plugin_avr = {
	.name = "avr",
	.desc = "AVR code analysis plugin",
	.init = NULL,
	.fini = NULL,
	.op = &avr_op,
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
	.data = &r_anal_plugin_avr
};
#endif
