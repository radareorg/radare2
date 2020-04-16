/* radare - LGPL - Copyright 2020 - pancake, nibble */

#include <r_arch.h>
#include <r_anal.h> // just to get the R_ANAL_OP_TYPE_xx

// TODO: move into r_arch
#define has(y) (opt & R_ARCH_OPTION_##y)

#define BUFSIZE_INC 32

static size_t countChar(const ut8 *buf, int len, const char ch) {
	size_t i;
	for (i = 0; i < len; i++) {
		if (buf[i] != ch) {
			break;
		}
	}
	return i;
}

static int getid(const char ch) {
	const char *keys = "[]<>+-,.";
	const char *cidx = strchr (keys, ch);
	return cidx? cidx - keys + 1: 0;
}

static bool decode(RArch *a, RArchInstruction *ins, RArchOptions opt) {
	bool use_buf_heap = false;
	ut64 dst = 0LL;
	r_return_val_if_fail (a && ins, false);
	int len;
	const ut8 *buf = r_strbuf_getbin (&ins->data, &len);
	ins->type = R_ANAL_OP_TYPE_NOP;
	ins->size = 1;
	ins->opid = getid (buf[0]);
	const char ch = buf[0];

	const char *buf_asm = "nop"; // invalid instructions do nothing in bfvm
	switch (ch) {
	case '[':
		{
			ins->type = R_ANAL_OP_TYPE_CJMP;
			buf_asm = "while [ptr]";
			char *data = r_mem_dup ((void *)buf, len);
			if (!data) {
				break;
			}
			const char *p = data + 1;
			int lev = 0, i = 1;
			len--;
			while (i < len && *p) {
				if (*p == '[') {
					lev++;
				}
				if (*p == ']') {
					lev--;
					if (lev == -1) {
						dst = ins->addr + (size_t)(p - data) + 1;
						ut64 jump = ins->addr + 1;
						ut64 fail = dst;
						ut64 *jumps = r_vector_reserve (&ins->dest, 2);
						jumps[0] = jump;
						jumps[1] = fail;
						if (has (ESIL)) {
							r_strbuf_setf (&ins->esil,
									"$$,brk,=[1],brk,++=,"
									"ptr,[1],!,?{,0x%"PFMT64x",pc,=,brk,--=,}", dst);
						}
						goto beach;
					}
				}
				if (!*p || *p == -1) {
					ins->type = R_ANAL_OP_TYPE_ILL;
					break;
				}
				if (i == len - 1) {
					// instruction truncated we need access to io to pull data to make this work
					if (a->iob.io) {
						int new_buf_len = len + 1 + BUFSIZE_INC;
						ut8 *new_buf = calloc (new_buf_len, 1);
						if (new_buf) {
							if (use_buf_heap) {
								free ((void*)buf);
							}
							(void)a->iob.read_at (a->iob.io, ins->addr, new_buf, new_buf_len);
							buf = new_buf;
							free (data);
							data = (char *)buf;
							p = (char *)buf + i;
							len += BUFSIZE_INC;
							use_buf_heap = true;
						}
						
					}
				}
				p++;
				i++;
			}
beach:
			if (use_buf_heap) {
				//free ((void*)buf);
			}
			free (data);
		}
		break;
	case ']':
		buf_asm = "loop";
		ins->type = R_ANAL_OP_TYPE_UJMP;
		// XXX This is wrong esil
		if (has (ESIL)) {
			r_strbuf_set (&ins->esil, "brk,--=,brk,[1],pc,=");
		}
		break;
	case '>':
		ins->type = R_ANAL_OP_TYPE_ADD;
		ins->size = countChar (buf, len, '>');
		buf_asm = (ins->size > 1)? "add ptr": "inc ptr";
		if (has (ESIL)) {
			r_strbuf_setf (&ins->esil, "%d,ptr,+=", ins->size);
		}
		break;
	case '<':
		ins->type = R_ANAL_OP_TYPE_SUB;
		ins->size = countChar (buf, len, '<');
		buf_asm = (ins->size > 1)? "sub ptr": "dec ptr";
		if (has (ESIL)) {
			r_strbuf_setf (&ins->esil, "%d,ptr,-=", ins->size);
		}
		break;
	case '+':
		ins->size = countChar (buf, len, '+');
		ins->type = R_ANAL_OP_TYPE_ADD;
		buf_asm = (ins->size > 1)? "add [ptr]": "inc [ptr]";
		if (has (ESIL)) {
			r_strbuf_setf (&ins->esil, "%d,ptr,+=[1]", ins->size);
		}
		break;
	case '-':
		ins->type = R_ANAL_OP_TYPE_SUB;
		ins->size = countChar (buf, len, '-');
		buf_asm = (ins->size > 1)? "sub [ptr]": "dec [ptr]";
		if (has (ESIL)) {
			r_strbuf_setf (&ins->esil, "%d,ptr,-=[1]", ins->size);
		}
		break;
	case '.':
		// print element in stack to screen
		buf_asm = "out [ptr]";
		ins->type = R_ANAL_OP_TYPE_STORE;
		if (has (ESIL)) {
			r_strbuf_set (&ins->esil, "ptr,[1],scr,=[1],scr,++=");
		}
		break;
	case ',':
		buf_asm = "in [ptr]";
		ins->type = R_ANAL_OP_TYPE_LOAD;
		if (has (ESIL)) {
			r_strbuf_set (&ins->esil, "kbd,[1],ptr,=[1],kbd,++=");
		}
		break;
	case 0:
	case -1:
		buf_asm = "trap";
		ins->type = R_ANAL_OP_TYPE_TRAP;
		if (has (ESIL)) {
			r_strbuf_set (&ins->esil, ",");
		}
		break;
	default:
		ins->type = R_ANAL_OP_TYPE_NOP;
		if (has (ESIL)) {
			r_strbuf_set (&ins->esil, ",");
		}
		break;
	}
	if (ins->size > 1) {
		/* Note: snprintf's source and destination buffers may not
		* overlap. */
		const char *fmt = strchr (buf_asm, ' ')? "%s, %d": "%s %d";
		buf_asm = sdb_fmt (fmt, buf_asm, ins->size);
	}

	r_strbuf_set (&ins->code, buf_asm);
	return true;
}

static bool assemble(RArch *a, RArchInstruction *ins) {
	const char *asmstr = r_strbuf_get (&ins->code);
	int n = 0;
	if (asmstr[0] && asmstr[1] == ' ') {
		asmstr += 2;
	}
	const char *arg = strchr (asmstr, ',');
	const char *ref = strchr (asmstr, '[');
	ut8 opbuf[32];
	if (!strncmp (asmstr, "trap", 4)) {
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, 0xcc, n);
		} else {
			opbuf[0] = 0x90;
			n = 1;
		}
	} else if (!strncmp (asmstr, "nop", 3)) {
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, 0x90, n);
		} else {
			opbuf[0] = 0x90;
			n = 1;
		}
	} else if (!strncmp (asmstr, "inc", 3)) {
		char ch = ref? '+': '>';
		opbuf[0] = ch;
		n = 1;
	} else if (!strncmp (asmstr, "dec", 3)) {
		char ch = ref? '-': '<';
		opbuf[0] = ch;
		n = 1;
	} else if (!strncmp (asmstr, "sub", 3)) {
		char ch = ref? '-': '<';
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, ch, n);
		} else {
			opbuf[0] = '<';
			n = 1;
		}
	} else if (!strncmp (asmstr, "add", 3)) {
		char ch = ref? '+': '>';
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, ch, n);
		} else {
			opbuf[0] = '<';
			n = 1;
		}
	} else if (!strncmp (asmstr, "while", 5)) {
		opbuf[0] = '[';
		n = 1;
	} else if (!strncmp (asmstr, "loop", 4)) {
		opbuf[0] = ']';
		n = 1;
	} else if (!strncmp (asmstr, "in", 2)) {
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, ',', n);
		} else {
			opbuf[0] = ',';
			n = 1;
		}
	} else if (!strncmp (asmstr, "out", 3)) {
		if (arg) {
			n = atoi (arg + 1);
			memset (opbuf, '.', n);
		} else {
			opbuf[0] = '.';
			n = 1;
		}
	}
	r_strbuf_setbin (&ins->data, opbuf, n);
	ins->size = n;
	return true;
}

static bool encode(RArch *a, RArchInstruction *ins, RArchOptions opt) {
	bool ret = false;
	// encode the disasm into bytes?
	if (opt & R_ARCH_OPTION_CODE) {
		ret = assemble (a, ins);
	}
	return ret;
}

static char *registers(RArch *a) {
	return strdup (
		"=PC	pc\n"
		"=BP	brk\n"
		"=SP	ptr\n"
		"=A0	ptr\n"
		"gpr	ptr	.32	0	0\n" // data pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	brk	.32	8	0\n" // brackets
		"gpr	scr	.32	12	0\n" // screen
		"gpr	kbd	.32	16	0\n" // keyboard
	);
}

RArchPlugin r_arch_plugin_bf = {
	.name = "bf",
	.arch = "bf",
	.author = "pancake",
	.version = "4.0.0",
	.license = "LGPL3",
	.bits = 8,
	.endian = R_SYS_ENDIAN_NONE,
	.desc = "Brainfuck",
	.decode = decode,
	.encode = encode,
	.registers = registers 
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_bf,
	.version = R2_VERSION
};
#endif
