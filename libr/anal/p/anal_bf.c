/* radare2 - LGPL - Copyright 2011-2022 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>

static size_t countChar(const ut8 *buf, int len, char ch) {
	int i;
	for (i = 0; i < len; i++) {
		if (buf[i] != ch) {
			break;
		}
	}
	return i;
}

static int getid(char ch) {
	const char *keys = "[]<>+-,.";
	const char *cidx = strchr (keys, ch);
	return cidx? cidx - keys + 1: 0;
}

static int disassemble(RAnalOp *op, const ut8 *buf, int len) {
	const ut8 *b;
	size_t rep = 1;

	/* Count repetitions of the current instruction, unless it's a trap. */
	if (*buf != 0x00 && *buf != 0xff) {
		for (b = &buf[1]; b < buf + len && *b == *buf; b++) {
			rep++;
		}
	}
	const char *buf_asm = "invalid";
	switch (*buf) {
	case '[':
		buf_asm = "while [ptr]";
		break;
	case ']':
		buf_asm = "loop";
		break;
	case '>':
		buf_asm = (rep > 1)? "add ptr": "inc ptr";
		break;
	case '<':
		buf_asm = (rep > 1)? "sub ptr": "dec ptr";
		break;
	case '+':
		buf_asm = (rep > 1)? "add [ptr]": "inc [ptr]";
		break;
	case '-':
		buf_asm = (rep > 1)? "sub [ptr]": "dec [ptr]";
		break;
	case ',':
		buf_asm = "in [ptr]";
		break;
	case '.':
		buf_asm = "out [ptr]";
		break;
	case 0xff:
	case 0x00:
		buf_asm = "trap";
		break;
	default:
		buf_asm = "nop";
		break;
	}

	char buf_asm_local[256];
	if (rep > 1) {
		/* Note: snprintf's source and destination buffers may not overlap. */
		const char *fmt = strchr (buf_asm, ' ')? "%s, %d": "%s %d";
		snprintf (buf_asm_local, sizeof (buf_asm_local), fmt, buf_asm, rep);
		buf_asm = buf_asm_local;
	}
	op->mnemonic = strdup (buf_asm);
	op->size = rep;
	return rep;
}

static bool _write_asm(ut8 *outbuf, int outbufsz, int value, int n) {
	memset (outbuf, value, R_MIN (n, outbufsz));
	return n > outbufsz;
}

static int assemble(const char *buf, ut8 *outbuf, int outbufsz) {
	int n = 0;
	if (buf[0] && buf[1] == ' ') {
		buf += 2;
	}
	const char *arg = strchr (buf, ',');
	const char *ref = strchr (buf, '[');
	bool write_err = false;
	if (arg) {
		n = atoi (arg + 1);
	} else {
		n = 1;
	}
	if (!strncmp (buf, "trap", 4)) {
		write_err = _write_asm (outbuf, outbufsz, 0xcc, n);
	} else if (!strncmp (buf, "nop", 3)) {
		write_err = _write_asm (outbuf, outbufsz, 0x90, n);
	} else if (!strncmp (buf, "inc", 3)) {
		char ch = ref? '+': '>';
		n = 1;
		write_err = _write_asm (outbuf, outbufsz, ch, n);
	} else if (!strncmp (buf, "dec", 3)) {
		char ch = ref? '-': '<';
		n = 1;
		write_err = _write_asm (outbuf, outbufsz, ch, n);
	} else if (!strncmp (buf, "sub", 3)) {
		char ch = ref? '-': '<';
		write_err = _write_asm (outbuf, outbufsz, ch, n);
	} else if (!strncmp (buf, "add", 3)) {
		char ch = ref? '+': '>';
		write_err = _write_asm (outbuf, outbufsz, ch, n);
	} else if (!strncmp (buf, "while", 5)) {
		n = 1;
		write_err = _write_asm (outbuf, outbufsz, '[', 1);
	} else if (!strncmp (buf, "loop", 4)) {
		n = 1;
		write_err = _write_asm (outbuf, outbufsz, ']', 1);
	} else if (!strncmp (buf, "in", 2)) {
		write_err = _write_asm (outbuf, outbufsz, ',', n);
	} else if (!strncmp (buf, "out", 3)) {
		write_err = _write_asm (outbuf, outbufsz, '.', n);
	} else {
		n = 0;
	}
	if (write_err) {
		return 0;
	}
	return n;
}

#define BUFSIZE_INC 32
static int bf_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	ut64 dst = 0LL;
	if (!op) {
		return 1;
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		(void) disassemble (op, buf, len);
	}
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

static int bf_opasm(RAnal *a, ut64 addr, const char *str, ut8 *outbuf, int outsize) {
	return assemble (str, outbuf, outsize);
}

RAnalPlugin r_anal_plugin_bf = {
	.name = "bf",
	.desc = "brainfuck code analysis plugin",
	.license = "LGPL3",
	.arch = "bf",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.esil = true,
	.op = &bf_op,
	.opasm = &bf_opasm,
	.get_reg_profile = get_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_bf,
	.version = R2_VERSION
};
#endif
