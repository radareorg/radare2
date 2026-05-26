/* radare - LGPL - Copyright 2026 - radare2 contributors */
/* PowerPC ragg2 emitter. Emits text for ppc.nz; compiled twice for 32 and 64-bit. */

#include <r_egg.h>

#ifdef ARCH_PPC_64
# define EMIT_NAME emit_ppc64
# define R_ARCH "ppc64"
# define R_SZ 8
# define R_LOAD "ld"
# define R_STORE "std"
# define R_STOREU "stdu"
# define R_CMP "cmpd"
# define R_MUL "mulld"
# define R_DIV "divd"
# define R_LR_OFF 16
# define R_MIN_FRAME 32
#else
# define EMIT_NAME emit_ppc
# define R_ARCH "ppc"
# define R_SZ 4
# define R_LOAD "lwz"
# define R_STORE "stw"
# define R_STOREU "stwu"
# define R_CMP "cmpw"
# define R_MUL "mullw"
# define R_DIV "divw"
# define R_LR_OFF 4
# define R_MIN_FRAME 16
#endif

#define R_SP "r1"
#define R_AX "r3"
#define R_TMP "r11"
#define R_GP { "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10" }
#define R_NGP 8

static char *regs[] = R_GP;
static int lastarg = 0;
static char lastargs[16][32];

/* PPC operands "D(rA)" contain a paren, register names start with 'r'. */
static inline bool is_memref(const char *str) {
	return str && strchr (str, '(');
}

static inline bool is_reg(const char *str) {
	if (!str || !*str) {
		return false;
	}
	if (str[0] == 'r' || str[0] == 'R') {
		return isdigit ((unsigned char)str[1]);
	}
	return false;
}

static void load_value(REgg *egg, const char *reg, const char *src) {
	src = r_str_trim_head_ro (src);
	if (is_memref (src)) {
		r_egg_printf (egg, "  %s %s, %s\n", R_LOAD, reg, src);
		return;
	}
	if (is_reg (src)) {
		if (strcmp (reg, src)) {
			r_egg_printf (egg, "  mr %s, %s\n", reg, src);
		}
		return;
	}
	if (*src == '$') {
		src++;
	}
	r_egg_printf (egg, "  li %s, %s\n", reg, src);
}

static void load_deref(REgg *egg, const char *reg, const char *src, int sz) {
	load_value (egg, reg, src);
	if (sz == 'b') {
		r_egg_printf (egg, "  lbz %s, 0(%s)\n", reg, reg);
	} else {
		r_egg_printf (egg, "  %s %s, 0(%s)\n", R_LOAD, reg, reg);
	}
}

static void load_ptr(REgg *egg, const char *reg, const char *src) {
	/* PPC variables come from get_var as "OFFSET(rA)"; emit addi to materialise the address. */
	const char *lp = strchr (src, '(');
	if (!lp) {
		load_value (egg, reg, src);
		return;
	}
	char disp[32], base[16];
	size_t dlen = R_MIN ((size_t)(lp - src), sizeof (disp) - 1);
	memcpy (disp, src, dlen);
	disp[dlen] = '\0';
	r_str_trim (disp);
	const char *bend = strchr (lp + 1, ')');
	if (!bend) {
		return;
	}
	size_t blen = R_MIN ((size_t)(bend - lp - 1), sizeof (base) - 1);
	memcpy (base, lp + 1, blen);
	base[blen] = '\0';
	r_str_trim (base);
	if (!strcmp (disp, "0")) {
		r_egg_printf (egg, "  mr %s, %s\n", reg, base);
	} else {
		r_egg_printf (egg, "  addi %s, %s, %s\n", reg, base, disp);
	}
}

static void store_slot(REgg *egg, const char *src, const char *dst, int sz) {
	if (sz == 'b') {
		r_egg_printf (egg, "  stb %s, %s\n", src, dst);
	} else {
		r_egg_printf (egg, "  %s %s, %s\n", R_STORE, src, dst);
	}
}

static void set_arg_slot(char *out, size_t outlen, int num) {
	snprintf (out, outlen, "%d(%s)", R_MIN_FRAME + (num - 1) * R_SZ, R_SP);
}

static void save_arg(REgg *egg, int num, const char *reg) {
	set_arg_slot (lastargs[num - 1], sizeof (lastargs[0]), num);
	store_slot (egg, reg, lastargs[num - 1], 'l');
}

static void load_arg_regs(REgg *egg, int nargs) {
	int i;
	for (i = 0; i < nargs; i++) {
		int regidx = nargs - 1 - i;
		if (regidx < 0 || regidx >= R_NGP || !lastargs[i][0]) {
			continue;
		}
		r_egg_printf (egg, "  %s %s, %s\n", R_LOAD, regs[regidx], lastargs[i]);
		lastargs[i][0] = '\0';
	}
	lastarg = 0;
}

static void emit_init(REgg *egg) {
	/* no-op */
}

static char *emit_syscall(REgg *egg, int num) {
	/* Linux PPC: syscall number in r0, args r3-r8, `sc` instruction. */
	return r_str_newf (": li r0, `.arg`\n: sc\n");
}

/* Always reserve the parameter save area: egg can't tell us if the function makes calls. */
static int ppc_frame_size(int sz) {
	int locals = (sz > 0)? ((sz + 15) & ~15): 0;
	return R_MIN_FRAME + R_NGP * R_SZ + locals;
}

static void emit_frame(REgg *egg, int sz) {
	int n = ppc_frame_size (sz);
	r_egg_printf (egg, "  mflr r0\n");
	r_egg_printf (egg, "  %s r0, %d(%s)\n", R_STORE, R_LR_OFF, R_SP);
	r_egg_printf (egg, "  %s %s, -%d(%s)\n", R_STOREU, R_SP, n, R_SP);
}

static void emit_frame_end(REgg *egg, int sz, int ctx) {
	int n = ppc_frame_size (sz);
	r_egg_printf (egg, "  addi %s, %s, %d\n", R_SP, R_SP, n);
	if (ctx > 0) {
		r_egg_printf (egg, "  %s r0, %d(%s)\n", R_LOAD, R_LR_OFF, R_SP);
		r_egg_printf (egg, "  mtlr r0\n");
		r_egg_printf (egg, "  blr\n");
	}
}

static void emit_comment(REgg *egg, const char *fmt, ...) {
	va_list ap;
	char buf[1024];
	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf), fmt, ap);
	r_egg_printf (egg, "# %s\n", buf);
	va_end (ap);
}

static void emit_equ(REgg *egg, const char *key, const char *value) {
	r_egg_printf (egg, ".equ %s, %s\n", key, value);
}

static void emit_syscall_args(REgg *egg, int nargs) {
	load_arg_regs (egg, nargs);
}

static void emit_set_string(REgg *egg, const char *dstvar, const char *str, int j) {
	/* No PC-relative load on PPC; full inline-string support deferred. */
	char *s = r_str_escape (str);
	r_egg_printf (egg, "  # set_string '%s' not implemented for ppc\n", s);
	free (s);
}

/* Indirect branch via CTR. branch is "bctr" (jmp) or "bctrl" (call). */
static void emit_indirect(REgg *egg, const char *str, const char *branch) {
	r_egg_printf (egg, "  %s r0, %s\n", R_LOAD, str);
	r_egg_printf (egg, "  mtctr r0\n");
	r_egg_printf (egg, "  %s\n", branch);
}

static void emit_jmp(REgg *egg, const char *str, int atr) {
	if (atr) {
		emit_indirect (egg, str, "bctr");
	} else {
		r_egg_printf (egg, "  b %s\n", str);
	}
}

static void emit_call(REgg *egg, const char *str, int atr) {
	load_arg_regs (egg, lastarg);
	if (atr) {
		emit_indirect (egg, str, "bctrl");
	} else {
		r_egg_printf (egg, "  bl %s\n", str);
	}
}

static void emit_arg(REgg *egg, int xs, int num, const char *str) {
	lastarg = num;
	switch (xs) {
	case 0:
		if (is_memref (str)) {
			strncpy (lastargs[num - 1], str, sizeof (lastargs[0]) - 1);
			lastargs[num - 1][sizeof (lastargs[0]) - 1] = '\0';
		} else {
			load_value (egg, R_AX, str);
			save_arg (egg, num, R_AX);
		}
		break;
	case '*':
		load_deref (egg, R_AX, str, 'l');
		save_arg (egg, num, R_AX);
		break;
	case '&':
		load_ptr (egg, R_AX, str);
		save_arg (egg, num, R_AX);
		break;
	}
}

static void emit_get_result(REgg *egg, const char *ocn) {
	if (is_memref (ocn)) {
		store_slot (egg, R_AX, ocn, 'l');
	} else {
		r_egg_printf (egg, "  mr %s, %s\n", ocn, R_AX);
	}
}

static void emit_restore_stack(REgg *egg, int size) {
	/* frame_end handles stack restoration; nothing to do here. */
}

static void emit_get_while_end(REgg *egg, RStrBuf *out, const char *ctxpush, const char *label) {
	r_strbuf_setf (out, "  b %s\n", label);
}

static void emit_while_end(REgg *egg, const char *labelback) {
	/* Mirrors ARM's broken behaviour: pop, compare-against-self, beq.
	 * The cmpw self-compare always sets EQ — same TODO as emit_arm. */
	r_egg_printf (egg,
		"  %s " R_AX ", 0(" R_SP ")\n"
		"  addi " R_SP ", " R_SP ", %d\n"
		"  " R_CMP " " R_AX ", " R_AX "\n"
		"  beq %s\n",
		R_LOAD, R_SZ, labelback);
}

static void emit_get_var(REgg *egg, int type, RStrBuf *out, int idx) {
	switch (type) {
	case 0:
		r_strbuf_setf (out, "%d(%s)", (idx - 1) & ~(R_SZ - 1), R_SP);
		break;
	case 1:
		r_strbuf_setf (out, "r%d", 3 + (((idx - 4) / 4) & 7));
		break;
	case 2:
		r_strbuf_setf (out, "r%d", 3 + (((idx - 12) / 4) & 7));
		break;
	default:
		r_strbuf_set (out, "");
		break;
	}
}

static void emit_trap(REgg *egg) {
	r_egg_printf (egg, "  trap\n");
}

static void emit_load_ptr(REgg *egg, const char *dst) {
	load_ptr (egg, R_AX, dst);
}

static void emit_branch(REgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst) {
	char *p, str[64];
	char *arg = NULL;
	const char *op = "beq";
	if (b) {
		*b = '\0';
		op = e? "bgt": "bge";
		arg = b + 1;
	} else if (g) {
		*g = '\0';
		op = e? "blt": "ble";
		arg = g + 1;
	}
	if (!arg) {
		if (e) {
			arg = e + 1;
			op = n? "beq": "bne";
		} else {
			arg = "0";
			op = n? "bne": "beq";
		}
	}
	if (*arg == '=') {
		arg++;
	}
	p = r_egg_mkvar (egg, str, arg, 0);
	if (lastargs[0][0]) {
		load_value (egg, R_AX, lastargs[0]);
	} else {
		r_egg_printf (egg, "  li " R_AX ", 0\n");
	}
	load_value (egg, R_TMP, p);
	r_egg_printf (egg, "  " R_CMP " " R_AX ", " R_TMP "\n");
	r_egg_printf (egg, "  %s %s\n", op, dst);
	lastargs[0][0] = '\0';
	lastarg = 0;
	free (p);
}

static void emit_load(REgg *egg, const char *dst, int sz) {
	load_deref (egg, R_AX, dst, sz);
}

static void emit_mathop(REgg *egg, int ch, int vs, int type, const char *eq, const char *p) {
	const char *op = NULL;
	switch (ch) {
	case '^': op = "xor"; break;
	case '&': op = "and"; break;
	case '|': op = "or"; break;
	case '-': op = "subf"; break;
	case '+': op = "add"; break;
	case '*': op = R_MUL; break;
	case '/': op = R_DIV; break;
	}
	if (!eq) {
		eq = R_AX;
	}
	if (!p) {
		p = R_AX;
	}
	if (ch == '=' && is_memref (p)) {
		load_value (egg, R_TMP, eq);
		store_slot (egg, R_TMP, p, vs);
		return;
	}
	if (!op) {
		/* plain assignment */
		if (type == '*') {
			r_egg_printf (egg, "  %s %s, 0(%s)\n", R_LOAD, p, eq);
		} else {
			load_value (egg, p, eq);
		}
		return;
	}
	if (type == '*') {
		r_egg_printf (egg, "  %s " R_TMP ", 0(%s)\n", R_LOAD, eq);
		if (!strcmp (op, "subf")) {
			r_egg_printf (egg, "  subf %s, " R_TMP ", %s\n", p, p);
		} else {
			r_egg_printf (egg, "  %s %s, %s, " R_TMP "\n", op, p, p);
		}
		return;
	}
	/* PPC arithmetic mnemonics take three register operands. When eq is a
	 * literal, dropping it into the rB slot is wrong: ppc.nz parses bare
	 * digits 0-31 as register names, so `add r4, r4, 1` silently encodes
	 * as `add r4, r4, r1`. Use D-form addi for +/- with a literal, and
	 * materialise the literal into R_TMP for the other ops. */
	bool eq_is_literal = !is_reg (eq) && !is_memref (eq);
	if (ch == '+' && eq_is_literal) {
		r_egg_printf (egg, "  addi %s, %s, %s\n", p, p, eq);
	} else if (ch == '-' && eq_is_literal) {
		/* p - (-N) == p + N: flip the literal's sign instead of producing `--N`. */
		if (*eq == '-') {
			r_egg_printf (egg, "  addi %s, %s, %s\n", p, p, eq + 1);
		} else {
			r_egg_printf (egg, "  addi %s, %s, -%s\n", p, p, eq);
		}
	} else if (eq_is_literal) {
		load_value (egg, R_TMP, eq);
		if (!strcmp (op, "subf")) {
			r_egg_printf (egg, "  subf %s, " R_TMP ", %s\n", p, p);
		} else {
			r_egg_printf (egg, "  %s %s, %s, " R_TMP "\n", op, p, p);
		}
	} else if (!strcmp (op, "subf")) {
		/* PPC subf rT, rA, rB := rB - rA; want p = p - eq,
		 * so emit subf p, eq, p. */
		r_egg_printf (egg, "  subf %s, %s, %s\n", p, eq, p);
	} else {
		r_egg_printf (egg, "  %s %s, %s, %s\n", op, p, p, eq);
	}
}

static const char *emit_regs(REgg *egg, int idx) {
	return regs[idx % R_NGP];
}

static void emit_get_arg(REgg *egg, RStrBuf *out, int idx) {
	if (idx >= 0 && idx < R_NGP) {
		r_strbuf_set (out, regs[idx]);
	} else {
		r_strbuf_set (out, "");
	}
}

REggEmit EMIT_NAME = {
	.retvar = R_AX,
	.arch = R_ARCH,
	.size = R_SZ,
	.jmp = emit_jmp,
	.call = emit_call,
	.init = emit_init,
	.equ = emit_equ,
	.regs = emit_regs,
	.trap = emit_trap,
	.frame = emit_frame,
	.frame_end = emit_frame_end,
	.comment = emit_comment,
	.push_arg = emit_arg,
	.restore_stack = emit_restore_stack,
	.get_result = emit_get_result,
	.syscall_args = emit_syscall_args,
	.set_string = emit_set_string,
	.get_arg = emit_get_arg,
	.get_var = emit_get_var,
	.while_end = emit_while_end,
	.get_while_end = emit_get_while_end,
	.branch = emit_branch,
	.load = emit_load,
	.load_ptr = emit_load_ptr,
	.mathop = emit_mathop,
	.syscall = emit_syscall,
};
