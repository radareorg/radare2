/* radare2 - LGPL - Copyright 2011-2024 - pancake */

#include <r_arch.h>

static size_t countChar(const ut8 *buf, int len, char ch) {
	size_t i;
	for (i = 0; i < len; i++) {
		if (buf[i] != ch) {
			break;
		}
	}
	return i;
}

static int getid(char ch) {
	const char *const keys = "[]<>+-,.";
	const char *const cidx = strchr (keys, ch);
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

static void _write_asm(ut8 *outbuf, size_t outbufsz, int value, int n) {
	memset (outbuf, value, R_MIN (n, outbufsz));
}

static int assemble(const char *buf, ut8 **outbuf) {
	int n = 0;
	if (buf[0] && buf[1] == ' ') {
		buf += 2;
	}
	const char *arg = strchr (buf, ',');
	const char *ref = strchr (buf, '[');
	if (arg) {
		n = atoi (arg + 1);
	} else {
		n = 1;
	}

	size_t outbufsz = n;
	*outbuf = malloc (outbufsz);
	if (!(*outbuf)) {
		return 0;
	}

	if (r_str_startswith (buf, "trap")) {
		_write_asm (*outbuf, outbufsz, 0xcc, n);
	} else if (r_str_startswith (buf, "nop")) {
		_write_asm (*outbuf, outbufsz, 0x90, n);
	} else if (r_str_startswith (buf, "inc")) {
		char ch = ref? '+': '>';
		n = 1;
		_write_asm (*outbuf, outbufsz, ch, n);
	} else if (r_str_startswith (buf, "dec")) {
		char ch = ref? '-': '<';
		n = 1;
		_write_asm (*outbuf, outbufsz, ch, n);
	} else if (r_str_startswith (buf, "sub")) {
		char ch = ref? '-': '<';
		_write_asm (*outbuf, outbufsz, ch, n);
	} else if (r_str_startswith (buf, "add")) {
		char ch = ref? '+': '>';
		_write_asm (*outbuf, outbufsz, ch, n);
	} else if (r_str_startswith (buf, "while")) {
		n = 1;
		_write_asm (*outbuf, outbufsz, '[', 1);
	} else if (r_str_startswith (buf, "loop")) {
		n = 1;
		_write_asm (*outbuf, outbufsz, ']', 1);
	} else if (r_str_startswith (buf, "in")) {
		_write_asm (*outbuf, outbufsz, ',', n);
	} else if (r_str_startswith (buf, "out")) {
		_write_asm (*outbuf, outbufsz, '.', n);
	} else {
		R_FREE (*outbuf);
		n = 0;
	}
	return n;
}

#define BUFSIZE_INC 32
static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	int len = op->size;
	if (len < 1) {
		return false;
	}
	ut8 *buf = op->bytes;
	const ut64 addr = op->addr;
	ut64 dst = 0LL;
	if (!op) {
		return 1;
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		(void) disassemble (op, buf, len);
	}
	r_strbuf_init (&op->esil);
	op->size = 1;
	op->id = getid (buf[0]);
	switch (buf[0]) {
	case '[':
		op->type = R_ANAL_OP_TYPE_CJMP;
		// read ahead to find the ] bracket
		op->jump = dst;
		op->fail = addr + 1;
		RArch *a = as->arch;
		RIOReadAt read_at = NULL;
		RBin *bin = R_UNWRAP2 (a, binb.bin);
		if (bin && bin->iob.read_at) {
			RIOReadAt read_at = bin->iob.read_at;
			buf = malloc (0xff);
			read_at (bin->iob.io, op->addr, buf, 0xff);
		}
		r_strbuf_set (&op->esil, "1,pc,-,brk,=[4],4,brk,+=");
#if 1
		if (len > 1) {
			const ut8 *p = buf + 1;
			int lev = 0, i = 1;
			len--;
			while (i < len && *p) {
				switch (*p) {
				case '[':
					lev++;
					break;
				case ']':
					lev--;
					if (lev < 1) {
						size_t delta = p - buf;
						dst = addr + (size_t)delta + 1;
						op->jump = dst;
						r_strbuf_set (&op->esil, "1,pc,-,brk,=[4],4,brk,+=,");
						goto beach;
					}
					break;
				case 0:
				case 0xff:
					op->type = R_ANAL_OP_TYPE_ILL;
					goto beach;
				}
				if (read_at && i == len - 1) {
#if 0
					// XXX unnecessary just break
					int new_buf_len = len + 1 + BUFSIZE_INC;
					ut8 *new_buf = calloc (new_buf_len, 1);
					if (new_buf) {
						free (buf);
						memcpy (new_buf, op->bytes, new_buf_len);
						buf = new_buf;
						read_at (bin->iob.io, op->addr + i, buf + i, 0xff);
						p = buf + i;
						len += BUFSIZE_INC;
					}
#else
					break;
#endif
				}
				p++;
				i++;
			}
		}
beach:
		free (buf);
#endif
		break;
	case ']':
		op->type = R_ANAL_OP_TYPE_UJMP;
		r_strbuf_set (&op->esil, "4,brk,-=,ptr,[1],?{,brk,[4],pc,=,}");
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
		r_strbuf_set (&op->esil, "ptr,[1],scr,=[1],1,scr,+=");
		break;
	case ',':
		op->type = R_ANAL_OP_TYPE_LOAD;
		r_strbuf_set (&op->esil, "kbd,[1],ptr,=[1],1,kbd,+=");
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

static char *regs(RArchSession *as) {
	if (as->config->bits == 8) {
		return strdup (
		"=PC	pc\n"
		"=BP	brk\n"
		"=SP	ptr\n"
		"=A0	tmp\n"
		"=A1	tmp\n"
		"=A2	tmp\n"
		"=A3	tmp\n"
		"gpr	ptr	.8	0	0\n" // data pointer
		"gpr	pc	.8	4	0\n" // program counter
		"gpr	brk	.8	8	0\n" // brackets
		"gpr	scr	.32	12	0\n" // screen
		"gpr	kbd	.32	16	0\n" // keyboard
		"gpr	tmp	.32	20	0\n" // keyboard
		);
	}
	return strdup (
		"=PC	pc\n"
		"=BP	brk\n"
		"=SP	ptr\n"
		"=A0	ptr\n"
		"=A1	ptr\n"
		"=A2	ptr\n"
		"=A3	ptr\n"
		"gpr	ptr	.32	0	0\n" // data pointer
		"gpr	pc	.32	4	0\n" // program counter
		"gpr	brk	.32	8	0\n" // brackets
		"gpr	scr	.32	12	0\n" // screen
		"gpr	kbd	.32	16	0\n" // keyboard
	);
}

static bool encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	ut8 *outbuf = NULL;
	int size = assemble (op->mnemonic, &outbuf);
	free (op->bytes);
	op->bytes = outbuf;
	op->size = size;
	return size > 0;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_ISVM:
		return R_ARCH_INFO_ISVM;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 0xff;
		// return 32;
	}
	return 1;
}

const RArchPlugin r_arch_plugin_bf = {
	.meta = {
		.name = "bf",
		.desc = "brainfuck",
		.license = "LGPL-3.0-only",
		.author = "pancake"
	},
	.arch = "bf",
	.bits = R_SYS_BITS_PACK (32),
	.endian = R_SYS_ENDIAN_NONE,
	.decode = &decode,
	.encode = &encode,
	.regs = regs,
	.info = &archinfo
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_bf,
	.version = R2_VERSION
};
#endif
