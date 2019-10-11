/* radare2 - LGPL - Copyright 2011-2019 - pancake */

#include <r_anal.h>

static int __countChar(const ut8 *buf, int len, char ch) {
	int i;
	for (i = 0; i < len; i++) {
		if (buf[i] != ch) {
			break;
		}
	}
	return i;
}

static int __getid(char ch) {
	const char *keys = "[]<>+-,.";
	const char *cidx = strchr (keys, ch);
	return cidx? cidx - keys + 1: 0;
}

#define BUFSIZE_INC 32
static int bf_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	const ut8 *p = buf + 1;
	int lev = 0, i = 1;
	ut64 dst = 0LL;
	if (!op) {
		return 1;
	}
	op->size = 1;
	op->id = __getid (buf[0]);
	switch (buf[0]) {
	case '[':
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->fail = addr + 1;
		buf = r_mem_dup ((void *)buf, len);
		if (!buf) {
			break;
		}
		len--;
		while (i < len && *p) {
			if (*p == '[') {
				lev++;
			}
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
			if (i == len - 1 && anal->read_at) {
				int new_buf_len = len + 1 + BUFSIZE_INC;
				ut8 *new_buf = calloc (new_buf_len, 1);
				if (new_buf) {
					free ((ut8 *)buf);
					(void)anal->read_at (anal, addr, new_buf, new_buf_len);
					buf = new_buf;
					p = buf + i;
					len += BUFSIZE_INC;
				}
			}
			p++;
			i++;
		}
beach:
		free ((ut8 *)buf);
		break;
	case ']':
		op->type = R_ANAL_OP_TYPE_UJMP;
		// XXX This is wrong esil
		r_strbuf_set (&op->esil, "brk,--=,brk,[1],pc,=");
		break;
	case '>':
		op->type = R_ANAL_OP_TYPE_ADD;
		op->size = __countChar (buf, len, '>');
		r_strbuf_setf (&op->esil, "%d,ptr,+=", op->size);
		break;
	case '<':
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = __countChar (buf, len, '<');
		r_strbuf_setf (&op->esil, "%d,ptr,-=", op->size);
		break;
	case '+':
		op->size = __countChar (buf, len, '+');
		op->type = R_ANAL_OP_TYPE_ADD;
		r_strbuf_setf (&op->esil, "%d,ptr,+=[1]", op->size);
		break;
	case '-':
		op->type = R_ANAL_OP_TYPE_SUB;
		op->size = __countChar (buf, len, '-');
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

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bf,
	.version = R2_VERSION
};
#endif
