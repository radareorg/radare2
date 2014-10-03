/* radare2 - LGPL - Copyright 2011-2014 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int countChar (const ut8 *buf, int len, char ch) {
	int i;
	for (i=0; i<len; i++) {
		if (buf[i] != ch)
			break;
	}
	return i;
}

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
						 dst ++;
						 op->jump = dst;
						 r_strbuf_setf (&op->esil,
							"pc,brk,=[1],brk,++=,"
						 	"ptr,[1],!,?{,0x%"PFMT64x",pc,=,brk,--=,}", dst);
						 break;
					 }
				 }
				 p++;
				 i++;
			 }
		  }
	// ?1[ptr],pc=${NEW_PC
	break;
	case ']': op->type = R_ANAL_OP_TYPE_UJMP;
		// XXX This is wrong esil
		r_strbuf_set (&op->esil, "brk,--=,brk,[1],pc,=");
		break;
	case '>':
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = countChar (buf, len, '>');
		r_strbuf_setf (&op->esil, "%d,ptr,+=", op->size);
		break;
	case '<':
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = countChar (buf, len, '<');
		r_strbuf_setf (&op->esil, "%d,ptr,-=", op->size);
		break;
	case '+':
		op->size = countChar (buf, len, '+');
		op->type = R_ANAL_OP_TYPE_ADD;
		r_strbuf_setf (&op->esil, "ptr,[1],%d,+,ptr,=[1]", op->size);
		break;
	case '-':
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = countChar (buf, len, '-');
		r_strbuf_setf (&op->esil, "ptr,[1],%d,-,ptr,=[1]", op->size);
		break;
	case '.':
		// print element in stack to screen
		op->type = R_ANAL_OP_TYPE_STORE;
		r_strbuf_set (&op->esil, "ptr,[1],scr,=[1],scr,++=");
		break;
	case ',':
		op->type = R_ANAL_OP_TYPE_LOAD;
		r_strbuf_set (&op->esil, "kbd,[1],ptr,=[1],kbd,++=");
		break;
	case 0x00:
	case 0xff:
		op->type = R_ANAL_OP_TYPE_TRAP;
		break;
	default:
		op->type = R_ANAL_OP_TYPE_NOP;
		r_strbuf_set (&op->esil, ",");
		break;
	}
	return op->size;
}

static int set_reg_profile(RAnal *anal) {
	const char *p = \
		"=pc	pc\n"
		"=bp	brk\n"
		"=sp	ptr\n"
		"=a0	rax\n"
		"=a1	rbx\n"
		"=a2	rcx\n"
		"=a3	rdx\n"
		"gpr	ptr	.32	0	0\n" // data pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	brk	.32	8	0\n" // brackets
		"gpr	scr	.32	12	0\n" // screen
		"gpr	kbd	.32	16	0\n"; // keyboard
	return r_reg_set_profile_string (anal->reg, p);
}

struct r_anal_plugin_t r_anal_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck code analysis plugin",
	.license = "LGPL3",
	.arch = R_SYS_ARCH_BF,
	.bits = 8,
	.init = NULL,
	.fini = NULL,
	.esil = R_TRUE,
	.op = &bf_op,
	.set_reg_profile = set_reg_profile,
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
