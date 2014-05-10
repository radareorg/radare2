/* radare - LGPL - Copyright 2011 - pancake<nopcode.org>, Roc Vallès <vallesroc@gmail.com> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int avr_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	short ofst;
	ut8 kbuf[2];
	ut16 *k = (ut16*)&kbuf;
	ut16 *ins = (ut16*)buf;

	if (op == NULL)
		return 2;
	op->size = 2;
	op->delay = 0;
	if (*ins == 0) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else
	if (buf[1]>=0x0c && buf[1]<=0x0f) { // hacky
		op->type = R_ANAL_OP_TYPE_ADD;
	} else
	if (buf[1]>=0x18 && buf[1]<=0x1b) { // hacky
		op->type = R_ANAL_OP_TYPE_SUB;
	} else
	//if (((buf[1] & 0x94) == 0x94) && ((buf[0] & 0x0e)==0x0e)) {
	if (!memcmp (buf, "\x0e\x94", 2)) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_CALL; // call (absolute)
		op->fail = (op->addr)+4;
// override even if len<4 wtf
		len = 4;
		if (len>3) {
			memcpy (kbuf, buf+2, 2);
			op->size = 4;
			//anal->iob.read_at (anal->iob.io, addr+2, kbuf, 2);
			op->jump = *k*2;
		} else {
			op->size = 0;
			return -1;
			return op->size;
		}
		//eprintf("addr: %x inst: %x dest: %x fail:%x\n", op->addr, *ins, op->jump, op->fail);
	} else
	if ((buf[1] & 0xf0) == 0xd0) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_CALL; // rcall (relative)
		op->fail = (op->addr)+2;
		ofst = *ins<<4;
		ofst>>=4;
		ofst*=2;
		op->jump = addr+ofst+2;
		//eprintf("addr: %x inst: %x ofst: %d dest: %x fail:%x\n", op->addr, *ins, ofst, op->jump, op->fail);
	} else
	if (((buf[1] & 0xfe) == 0x94) && ((buf[0] & 0x0e)==0x0c)) {
		op->addr = addr;
		op->type = R_ANAL_OP_TYPE_CJMP; // breq, jmp (absolute)
		op->fail = (op->addr)+4;
		anal->iob.read_at (anal->iob.io, addr+2, kbuf, 2);
		// TODO: check return value
		op->jump = *k*2;
		//eprintf("addr: %x inst: %x dest: %x fail:%x\n", op->addr, *ins, op->jump, op->fail);
	} else
	if ((buf[1] & 0xf0) == 0xc0) { // rjmp (relative)
		op->addr=addr;
		op->type = R_ANAL_OP_TYPE_JMP;
		op->fail = (op->addr)+2;
		ofst = *ins<<4;
		ofst>>=4;
		ofst*=2;
		op->jump = addr+ofst+2;
		//eprintf("addr: %x inst: %x ofst: %d dest: %x fail:%x\n", op->addr, *ins, ofst, op->jump, op->fail);
	} else
	if (*ins == 0x9508) { // ret
		//eprintf("ret at addr: %x\n", addr);
		op->type = R_ANAL_OP_TYPE_RET;
		op->eob = R_TRUE;
		//op->stackptr =
	} else op->type = R_ANAL_OP_TYPE_UNK;
	return op->size;
}

RAnalPlugin r_anal_plugin_avr = {
	.name = "avr",
	.desc = "AVR code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_AVR,
	.bits = 16|32,
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
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_avr
};
#endif
