/* radare - LGPL - Copyright 2013 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

#include <8051_disas.h>

// TODO: Cleanup the code, remove unneeded data copies

static int i8051_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	char *tmp =  NULL;
	char buf_asm[64];
	op->delay = 0;
	r_8051_op o = r_8051_decode (buf, len);
	memset(buf_asm, 0, sizeof (buf_asm));
	if (!o.name) return 0; // invalid instruction
	tmp = r_8051_disasm (o, addr, buf_asm, sizeof (buf_asm));
	if (tmp) {
		if (strlen (tmp) < sizeof (buf_asm)) {
			strncpy (buf_asm, tmp, strlen (tmp));
		} else {
			eprintf ("8051 analysis: too big opcode!\n");
			free (tmp);
			op->size = -1;
			return -1;
		}
		free (tmp);
	}
	if (!strncmp (buf_asm, "push", 4)) {
		op->type = R_ANAL_OP_TYPE_UPUSH;
		op->ptr = 0;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 1;
	} else
	if (!strncmp (buf_asm, "pop", 3)) {
		op->type = R_ANAL_OP_TYPE_POP;
		op->ptr = 0;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -1;
	} else
	if (!strncmp (buf_asm, "ret", 3)) {
		op->type = R_ANAL_OP_TYPE_RET;
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -2;
	} else
	if (!strncmp (buf_asm, "nop", 3)) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else
	if (!strncmp (buf_asm, "inv", 3)) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else
	if ((!strncmp (buf_asm, "inc", 3)) ||
		(!strncmp (buf_asm, "add", 3))) {
		op->type = R_ANAL_OP_TYPE_ADD;
	} else
	if ((!strncmp (buf_asm, "dec", 3)) ||
		(!strncmp (buf_asm, "sub", 3))) {
		op->type = R_ANAL_OP_TYPE_SUB;
	} else
	if (!strncmp (buf_asm, "mov", 3)) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else
	if (*buf_asm && !strncmp (buf_asm+1, "call", 4)) {
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = o.addr;
		op->fail = addr+o.length;
	} else
		/* CJNE, DJNZ, JC, JNC, JZ, JB, JNB, LJMP, SJMP */
	if (buf_asm[0]=='j' || (buf_asm[0] && buf_asm[1] == 'j'))
	{
		op->type = R_ANAL_OP_TYPE_JMP;
		if (o.operand == OFFSET)
			op->jump = o.addr+addr+o.length;
		else
		op->jump = o.addr;
		op->fail = addr+o.length;
	}
	return op->size = o.length;
}

struct r_anal_plugin_t r_anal_plugin_8051 = {
	.name = "8051",
	.arch = R_SYS_ARCH_8051,
	.bits = 8,
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
