/* radare - LGPL - Copyright 2013 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include "../../asm/arch/8051/8051.c"

static int i8051_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	char buf_asm[64];
	Op8051 o = do8051struct (buf, len);
	if (!o.name) return 0; // invalid instruction
	do8051disasm (o, addr, buf_asm, sizeof (buf_asm));
	if (buf_asm[0]=='p') {
		op->type = buf_asm[1]=='u'?
			R_ANAL_OP_TYPE_PUSH:
			R_ANAL_OP_TYPE_POP;
	} else
	if (!strncmp (buf_asm, "nop", 3)) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else
	if (!strncmp (buf_asm, "inv", 3)) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else
	if (!strncmp (buf_asm, "inc", 3)) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else
	if (!strncmp (buf_asm, "dec", 3)) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else
	if (!strncmp (buf_asm+1, "call", 4)) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = o.addr;
		op->fail = addr+o.length;
	} else
	if (!strncmp (buf_asm, "ret", 3)) {
		op->type = R_ANAL_OP_TYPE_RET;
	} else
	if (buf_asm[0]=='j' || buf_asm[1] == 'j') {
		op->type = R_ANAL_OP_TYPE_JMP;
		if (o.operand == OFFSET)
			op->jump = o.addr+addr+o.length;
		else
		op->jump = o.addr;
		op->fail = addr+o.length;
	}
	return op->length = o.length;
}

struct r_anal_plugin_t r_anal_plugin_8051 = {
	.name = "8051",
	.arch = R_SYS_ARCH_8051,
	.bits = 16,
	.desc = "8051 CPU code analysis plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.op = &i8051_op,
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
	.data = &r_anal_plugin_8051
};
#endif
