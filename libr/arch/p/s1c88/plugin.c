/* radare - LGPL - Copyright 2026 - xXAbieGamingXx */

#define R_LOG_ORIGIN "arch.s1c88"

#include <r_arch.h>
#include <ctype.h>
#include "s1c88_tab.h"

static char *s1c88_regs(RArchSession *as) {
	const char p[] =
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	ix\n"
		"=A0	a\n"
		"=A1	b\n"
		"=A2	hl\n"
		"=A3	ix\n"
		"=R0	ba\n"
		"=SN	a\n"
		"gpr	ba	.16	0	0\n"
		"gpr	a	.8	0	0\n"
		"gpr	b	.8	1	0\n"
		"gpr	hl	.16	2	0\n"
		"gpr	l	.8	2	0\n"
		"gpr	h	.8	3	0\n"
		"gpr	ix	.16	4	0\n"
		"gpr	iy	.16	6	0\n"
		"gpr	sp	.16	8	0\n"
		"gpr	pc	.24	10	0\n"
		"gpr	pcl	.16	10	0\n"
		"gpr	cb	.8	12	0\n"
		"gpr	nb	.8	13	0\n"
		"gpr	br	.8	14	0\n"
		"gpr	ep	.8	15	0\n"
		"gpr	xp	.8	16	0\n"
		"gpr	yp	.8	17	0\n"
		"gpr	sc	.8	18	0\n"
		"flg	z	.1	.144	0\n"
		"flg	c	.1	.145	0\n"
		"flg	v	.1	.146	0\n"
		"flg	n	.1	.147	0\n"
		"flg	d	.1	.148	0\n"
		"flg	u	.1	.149	0\n"
		"flg	i0	.1	.150	0\n"
		"flg	i1	.1	.151	0\n"
		"gpr	cc	.8	19	0\n"
		"flg	f0	.1	.152	0\n"
		"flg	f1	.1	.153	0\n"
		"flg	f2	.1	.154	0\n"
		"flg	f3	.1	.155	0\n";
	return strdup (p);
}

/* start of variable bank area in logic space, 0x0-0x7fff is static */
#define S1C88_BANK 0x8000

static inline ut64 s1c88_phys(ut8 cb, ut16 pc) {
	return (pc < S1C88_BANK)? pc: (((ut64)cb << 15) | (pc & (S1C88_BANK - 1)));
}

/* pc holds address in logic space */
static inline ut16 s1c88_pc(ut64 addr) {
	return (addr < S1C88_BANK)? (ut16)addr: (ut16) (S1C88_BANK | (addr & (S1C88_BANK - 1)));
}

static inline ut8 s1c88_cb(ut64 addr) {
	return (addr < S1C88_BANK)? 1: (ut8) (addr >> 15);
}

static const s1c88_opcode *s1c88_lookup(const ut8 *b, int len, int *plen) {
	if (len < 1) {
		return NULL;
	}
	if (b[0] == 0xce || b[0] == 0xcf) {
		if (len < 2) {
			return NULL;
		}
		const s1c88_opcode *t = (b[0] == 0xce)? s1c88_op_ce: s1c88_op_cf;
		*plen = 2;
		return &t[b[1]];
	}
	*plen = 1;
	return &s1c88_op[b[0]];
}

static bool s1c88_decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	R_RETURN_VAL_IF_FAIL (as && op, false);
	const ut8 *b = op->bytes;
	const int len = op->size;
	int plen = 0;
	const s1c88_opcode *e = s1c88_lookup (b, len, &plen);
	if (!e) {
		return false;
	}
	const int arg = e->type & S1C88_ARG_MASK;
	const int size = plen + s1c88_arglen[arg];
	if (size > len) {
		return false;
	}
	if (e->optype == R_ANAL_OP_TYPE_ILL) {
		op->size = 1;
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		return true;
	}
	op->size = size;
	op->nopcode = plen;
	op->type = e->optype;

	const ut8 *a = b + plen;
	switch (arg) {
	case S1C88_ARG_I8:
		op->val = a[0];
		break;
	case S1C88_ARG_S8:
		op->val = a[0];
		if (! (e->type & S1C88_REL)) {
			op->disp = (st8)a[0];
		}
		break;
	case S1C88_ARG_I16:
	case S1C88_ARG_S16:
		op->val = a[0] | (a[1] << 8);
		break;
	case S1C88_ARG_I8I8:
		op->val = a[1];
		op->disp = a[0];
		break;
	}

	if (e->type & S1C88_REL) {
		const st64 disp = (arg == S1C88_ARG_S16)? (st64) (st16) (a[0] | (a[1] << 8)): (st64) (st8)a[0];
		const ut8 cb = s1c88_cb (op->addr);
		const ut16 pc = s1c88_pc (op->addr);
		op->jump = s1c88_phys (cb, (ut16) (pc + size - 1 + disp)); /* displacements count from the last byte of the opcode */
		if (e->type & S1C88_COND) {
			op->fail = s1c88_phys (cb, (ut16) (pc + size));
		}
	}

	op->eob = (e->type & S1C88_RET) || ((e->type & S1C88_JUMP) && ! (e->type & (S1C88_COND | S1C88_CALL)));

	if (mask & R_ARCH_OP_MASK_DISASM) {
		switch (arg) {
		case S1C88_ARG_NONE:
			op->mnemonic = strdup (e->name);
			break;
		case S1C88_ARG_I8:
			op->mnemonic = r_str_newf (e->name, a[0]);
			break;
		case S1C88_ARG_S8:
			if (e->type & S1C88_REL) {
				op->mnemonic = r_str_newf (e->name, (ut32)op->jump);
			} else {
				const int d = (st8)a[0];
				op->mnemonic = r_str_newf (e->name, (d < 0)? "-": "+", (ut32)R_ABS (d));
			}
			break;
		case S1C88_ARG_I16:
			op->mnemonic = r_str_newf (e->name, (ut32) (a[0] | (a[1] << 8)));
			break;
		case S1C88_ARG_S16:
			op->mnemonic = r_str_newf (e->name, (ut32)op->jump);
			break;
		case S1C88_ARG_I8I8:
			op->mnemonic = r_str_newf (e->name, a[0], a[1]);
			break;
		}
	}
	return true;
}

static inline char s1c88_tail(RStrBuf *sb) {
	const int len = r_strbuf_length (sb);
	return (len > 0)? r_strbuf_get (sb)[len - 1]: 0;
}

static char *s1c88_norm(const char *s, bool numbers) {
	R_RETURN_VAL_IF_FAIL (s, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	const char *p = s;
	while (*p) {
		const char last = s1c88_tail (sb);
		if (isspace ((ut8)*p)) {
			while (isspace ((ut8)*p)) {
				p++;
			}

			if (!last || !*p || strchr (",][+-", *p) || strchr (",[+-", last)) {
				continue;
			}
			r_strbuf_append (sb, " ");
			continue;
		}

		if (numbers && isdigit ((ut8)*p) && !isalnum ((ut8)last)) {
			ut64 v;
			char *end = NULL;
			if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
				v = strtoull (p + 2, &end, 16);
			} else {
				v = strtoull (p, &end, 10);
			}
			if (end && end != p) {
				r_strbuf_appendf (sb, "0x%" PFMT64x, v);
				p = end;
				continue;
			}
		}
		r_strbuf_append_n (sb, p++, 1);
	}
	return r_strbuf_drain (sb);
}

static int s1c88_match(const char *fmt, const char *in, ut64 *vals) {
	int n = 0;
	bool neg = false;
	while (*fmt) {
		if (fmt[0] == '%' && fmt[1] == 's') {
			if (*in != '+' && *in != '-') {
				return -1;
			}
			neg = (*in++ == '-');
			fmt += 2;
			continue;
		}
		if (fmt[0] == '0' && fmt[1] == 'x' && fmt[2] == '%') {
			if (in[0] != '0' || in[1] != 'x' || n > 1) {
				return -1;
			}
			in += 2;
			if (!isxdigit ((ut8)*in)) {
				return -1;
			}
			ut64 v = 0;
			while (isxdigit ((ut8)*in)) {
				const int c = (ut8)*in++;
				v = (v << 4) | (ut64) (isdigit (c)? c - '0': (c | 32) - 'a' + 10);
			}
			vals[n++] = neg? 0 - v: v; /* two's complement, checked when emitted */
			neg = false;
			fmt += 3;
			while (*fmt && *fmt != 'x') {
				fmt++;
			}
			if (*fmt == 'x') {
				fmt++;
			}
			continue;
		}
		if (*fmt++ != *in++) {
			return -1;
		}
	}
	return *in? -1: n;
}

static int s1c88_emit(ut8 *out, const s1c88_opcode *e, int prefix, ut8 opcode, const ut64 *v, ut64 addr) {
	const int arg = e->type & S1C88_ARG_MASK;
	int plen = 0;
	if (prefix >= 0) {
		out[plen++] = (ut8)prefix;
	}
	out[plen++] = opcode;
	const int size = plen + s1c88_arglen[arg];

	if (e->type & S1C88_REL) {
		const ut8 cb = s1c88_cb (addr);
		const ut16 target = s1c88_pc (v[0]);
		if (s1c88_phys (cb, target) != v[0]) {
			return -1; /* not reachable from this code bank */
		}
		const st64 disp = (st64) (st16) (ut16) (target - (s1c88_pc (addr) + size - 1));
		if (arg == S1C88_ARG_S8) {
			if (disp < -128 || disp > 127) {
				return -1;
			}
			out[plen] = (ut8)disp;
		} else {
			out[plen] = (ut8) (disp & 0xff);
			out[plen + 1] = (ut8) ((disp >> 8) & 0xff);
		}
		return size;
	}
	switch (arg) {
	case S1C88_ARG_I8:
		if (v[0] > 0xff) {
			return -1;
		}
		out[plen] = (ut8)v[0];
		break;
	case S1C88_ARG_S8:
		if ((st64)v[0] < -128 || (st64)v[0] > 127) {
			return -1;
		}
		out[plen] = (ut8) (st8)v[0];
		break;
	case S1C88_ARG_I16:
	case S1C88_ARG_S16:
		if (v[0] > 0xffff) {
			return -1;
		}
		out[plen] = (ut8) (v[0] & 0xff);
		out[plen + 1] = (ut8) ((v[0] >> 8) & 0xff);
		break;
	case S1C88_ARG_I8I8:
		if (v[0] > 0xff || v[1] > 0xff) {
			return -1;
		}
		out[plen] = (ut8)v[0];
		out[plen + 1] = (ut8)v[1];
		break;
	}
	return size;
}

static int s1c88_asm_exact(ut8 *out, const char *in, ut64 addr) {
	const struct {
		const s1c88_opcode *t;
		int prefix;
	} pages[] = {
		{ s1c88_op, -1 }, { s1c88_op_ce, 0xce }, { s1c88_op_cf, 0xcf }
	};
	size_t pi;
	int op;
	for (pi = 0; pi < R_ARRAY_SIZE (pages); pi++) {
		for (op = 0; op < 256; op++) {
			const s1c88_opcode *e = &pages[pi].t[op];
			if (!e->name || !*e->name || e->optype == R_ANAL_OP_TYPE_ILL) {
				continue;
			}
			char *f = s1c88_norm (e->name, false);
			if (!f) {
				continue;
			}
			ut64 v[2] = { 0, 0 };
			const int n = s1c88_match (f, in, v);
			free (f);
			if (n < 0) {
				continue;
			}
			const int len = s1c88_emit (out, e, pages[pi].prefix, (ut8)op, v, addr);
			if (len > 0) {
				return len;
			}
		}
	}
	return -1;
}

static int s1c88_asm(ut8 *out, const char *str, ut64 addr) {
	char *in = s1c88_norm (str, true);
	if (!in) {
		return -1;
	}
	int ret = s1c88_asm_exact (out, in, addr);
	if (ret < 1) {
		const char *rest = NULL, *sf = NULL, *lf = NULL;
		if (r_str_startswith (in, "jr ")) {
			rest = in + 3;
			sf = "jrs";
			lf = "jrl";
		} else if (r_str_startswith (in, "car ")) {
			rest = in + 4;
			sf = "cars";
			lf = "carl";
		}
		if (rest) {
			char *t = r_str_newf ("%s %s", sf, rest);
			ret = t? s1c88_asm_exact (out, t, addr): -1;
			free (t);
			if (ret < 1) {
				t = r_str_newf ("%s %s", lf, rest);
				ret = t? s1c88_asm_exact (out, t, addr): -1;
				free (t);
			}
		}
	}
	free (in);
	return ret;
}

static bool s1c88_encode(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	R_RETURN_VAL_IF_FAIL (as && op, false);
	if (R_STR_ISEMPTY (op->mnemonic)) {
		return false;
	}
	ut8 data[4] = { 0 };
	const int len = s1c88_asm (data, op->mnemonic, op->addr);
	if (len < 1) {
		return false;
	}
	r_anal_op_set_bytes (op, op->addr, data, len);
	return true;
}

static int s1c88_archinfo(RArchSession *as, ut32 q) {
	if (q == R_ARCH_INFO_MAXOP_SIZE) {
		return 4;
	}
	return 1;
}

const RArchPlugin r_arch_plugin_s1c88 = {
	.meta = {
		.name = "s1c88",
		.desc = "Seiko Epson S1C88",
		.author = "xXAbieGamingXx",
		.license = "LGPL-3.0-only",
	},
	.arch = "s1c88",
	.endian = R_SYS_ENDIAN_LITTLE,
	.bits = R_SYS_BITS_PACK1 (8),
	.addr_bits = R_SYS_BITS_PACK1 (24),
	.info = &s1c88_archinfo,
	.decode = &s1c88_decode,
	.encode = &s1c88_encode,
	.regs = &s1c88_regs,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = (void *)&r_arch_plugin_s1c88,
	.version = R2_VERSION,
};
#endif
