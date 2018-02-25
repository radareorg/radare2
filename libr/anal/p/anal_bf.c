/* radare2 - LGPL - Copyright 2011-2016 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static int countChar (const ut8 *buf, int len, char ch) {
	int i;
	for (i = 0; i < len; i++) {
		if (buf[i] != ch)
			break;
	}
	return i;
}

static int getid (char ch) {
	const char *keys = "[]<>+-,.";
	const char *cidx = strchr (keys, ch);
	return cidx? cidx - keys + 1: 0;
}

#define BUFSIZE_INC 32
static int bf_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len) {
	ut64 dst = 0LL;
	if (!op) {
		return 1;
	}
	/* Ayeeee! What's inside op? Do we have an initialized RAnalOp? Are we going to have a leak here? :-( */
	memset (op, 0, sizeof (RAnalOp)); /* We need to refactorize this. Something like r_anal_op_init would be more appropiate */
	r_strbuf_init (&op->esil);
	op->size = 1;
	op->id = getid (buf[0]);
	switch (buf[0]) {
	case '[':
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = addr+1;
		buf = r_mem_dup ((void *)buf, len);
		if (!buf) {
			break;
		}
		{
			const ut8 *p = buf + 1;
			int lev = 0, i = 1;
			len--;
			while (i < len && *p) {
				if (*p == '[')
					lev++;
				if (*p == ']') {
					lev--;
					if (lev==-1) {
						dst = addr + (size_t)(p-buf);
						dst ++;
						op->jump = dst;
						r_strbuf_setf (&op->esil,
								"$$,brk,=[1],brk,++=,"
								"ptr,[1],!,?{,0x%"PFMT64x",pc,=,brk,--=,}", dst);
						goto beach;
					}
				}
				if (*p == 0x00 || *p == 0xff) {
					op->type = R_ANAL_OP_TYPE_ILL;
					goto beach;
				}
				if (i == len - 1 && anal->cb.modify_read_window) {
					const ut8 *new_buf = anal->cb.modify_read_window (anal, addr, len + 1 + BUFSIZE_INC);
					if (new_buf) {
						free ((ut8 *)buf);
						buf = new_buf;
						p = buf + i;
						len += BUFSIZE_INC;
					}
				}
				p++;
				i++;
			}
		}
beach:
		free ((ut8 *)buf);
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
		r_strbuf_setf (&op->esil, "%d,ptr,+=[1]", op->size);
		break;
	case '-':
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = countChar (buf, len, '-');
		r_strbuf_setf (&op->esil, "%d,ptr,-=[1]", op->size);
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

static char *get_reg_profile(RAnal *anal) {
	return strdup (
		"=PC	pc\n"
		"=BP	brk\n"
		"=SP	ptr\n"
		"=A0	rax\n"
		"=A1	rbx\n"
		"=A2	rcx\n"
		"=A3	rdx\n"
		"gpr	ptr	.32	0	0\n" // data pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	brk	.32	8	0\n" // brackets
		"gpr	scr	.32	12	0\n" // screen
		"gpr	kbd	.32	16	0\n" // keyboard
	);
}

RAnalPlugin r_anal_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck code analysis plugin",
	.license = "LGPL3",
	.arch = "bf",
	.bits = 8,
	.esil = true,
	.op = &bf_op,
	.get_reg_profile = get_reg_profile,
};

#ifndef CORELIB
RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bf,
	.version = R2_VERSION
};
#endif
