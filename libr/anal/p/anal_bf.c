/* radare2 - LGPL - Copyright 2011-2013 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int bf_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ut64 dst = 0LL;
	if (op == NULL)
		return 1;
	/* Ayeeee! What's inside op? Do we have an initialized RAnalOp? Are we going to have a leak here? :-( */
	memset (op, 0, sizeof (RAnalOp)); /* We need to refactorize this. Something like r_anal_op_init would be more appropiate */
	r_strbuf_init (&op->esil);
	op->size = 1;
	switch (buf[0]) {
	case '[': op->type = R_ANAL_OP_TYPE_CJMP;
		  op->fail = addr+1;
		  {
			 const ut8 *p = buf + 1;
			 int lev = 0, i = 1;
			 while (*p && i<len) {
				 if (*p == '[')
					 lev++;
				 if (*p == ']') {
					 lev--;
					 if (lev==-1) {
						 dst = addr + (size_t)(p-buf);
						 op->jump = dst;
						 r_strbuf_setf (&op->esil,
							"if (!*ptr) pc=0x%"PFMT64x, dst);
						 break;
					 }
				 }
				 p++;
				i++;
			 }
		  }
	// ?1[ptr],pc=${NEW_PC
	break;
	case ']': op->type = R_ANAL_OP_TYPE_UJMP; break;
	case '>': op->type = R_ANAL_OP_TYPE_ADD;
		r_strbuf_set (&op->esil, "ptr++");
		break;
	case '<': op->type = R_ANAL_OP_TYPE_SUB;
		r_strbuf_set (&op->esil, "ptr--");
		break;
	case '+': op->type = R_ANAL_OP_TYPE_ADD;
		r_strbuf_set (&op->esil, "*ptr++");
		break;
	case '-': op->type = R_ANAL_OP_TYPE_SUB;
		r_strbuf_set (&op->esil, "*ptr--");
		break;
	case '.': op->type = R_ANAL_OP_TYPE_STORE;
		r_strbuf_set (&op->esil, "=*ptr");
		break;
	case ',': op->type = R_ANAL_OP_TYPE_LOAD; break;
	case 0x00:
	case 0xff:
		op->type = R_ANAL_OP_TYPE_TRAP; break;
	default: op->type = R_ANAL_OP_TYPE_NOP; break;
	}
	return op->size;
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
