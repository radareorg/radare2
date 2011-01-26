/* radare - LGPL - Copyright 2011 - pancake<nopcode.org> */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *buf, int len) {
	ut16 *ins = (ut16*)buf;
	if (aop == NULL)
		return 2;

	aop->length = 2;
	if (*ins == 0) {
		aop->type = R_ANAL_OP_TYPE_NOP;
	} else
	if (buf[1]>=0x0c && buf[1]<=0x0f) { // hacky
		aop->type = R_ANAL_OP_TYPE_ADD;
	} else
	if (buf[1]>=0x18 && buf[1]<=0x1b) { // hacky
		aop->type = R_ANAL_OP_TYPE_SUB;
	} else
	if ((buf[1] & 0xf0 ) == 0x80) {
		aop->type = R_ANAL_OP_TYPE_CALL; // call (absolute)
		// TODO: calculate dest address
	} else
	if ((buf[1] & 0xf0 ) == 0xd0) {
		aop->type = R_ANAL_OP_TYPE_CALL; // rcall (relative)
		// TODO: calculate dest address
	} else
	if ((buf[1] & 0xf0 ) == 0xf0) {
		aop->type = R_ANAL_OP_TYPE_CJMP; // breq
		// TODO: calculate dest address
	} else
	if ((buf[1] & 0xf0 ) == 0xc0) {
		aop->type = R_ANAL_OP_TYPE_JMP;
		// TODO: calculate dest address
	} else aop->type = R_ANAL_OP_TYPE_UNK;
	return aop->length;
}

struct r_anal_plugin_t r_anal_plugin_avr = {
	.name = "avr",
	.desc = "AVR code analysis plugin",
	.init = NULL,
	.fini = NULL,
	.aop = &aop
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_avr
};
#endif
