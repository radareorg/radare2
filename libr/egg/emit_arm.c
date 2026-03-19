/* pancake // nopcode.org 2010-2026 -- arm emiter */

#include <r_egg.h>
#define attsyntax 0

#define EMIT_NAME emit_arm
#define R_ARCH "arm"
#define R_SZ 8
#define R_SP "sp"
#define R_BP "fp"
#define R_AX "r7"
#define R_GP { "r0", "r1", "r2", "r3", "r4" }
#define R_TMP "r9"
#define R_NGP 5

// no attsyntax for arm
static char *regs[] = R_GP;
static int lastarg = 0;
static char lastargs[16][32];

static inline bool is_memref(const char *str) {
	return str && strchr (str, ',');
}

static inline bool is_reg(const char *str) {
	if (!str || !*str) {
		return false;
	}
	if (!strcmp (str, "sp") || !strcmp (str, "fp") || !strcmp (str, "lr") || !strcmp (str, "pc")) {
		return true;
	}
	return str[0] == 'r' && str[1] >= '0' && str[1] <= '9';
}

static void load_value(REgg *egg, const char *reg, const char *src) {
	src = r_str_trim_head_ro (src);
	if (is_memref (src)) {
		r_egg_printf (egg, "  ldr %s, [%s]\n", reg, src);
		return;
	}
	if (is_reg (src)) {
		if (strcmp (reg, src)) {
			r_egg_printf (egg, "  mov %s, %s\n", reg, src);
		}
		return;
	}
	if (*src == '$') {
		src++;
	}
	r_egg_printf (egg, "  mov %s, %s\n", reg, src);
}

static void load_deref(REgg *egg, const char *reg, const char *src, int sz) {
	load_value (egg, reg, src);
	r_egg_printf (egg, "  %s %s, [%s]\n", sz == 'b'? "ldrb": "ldr", reg, reg);
}

static void load_ptr(REgg *egg, const char *reg, const char *src) {
	const char *off;
	const char *comma = strchr (src, ',');
	char base[16];
	size_t len;

	if (!comma) {
		load_value (egg, reg, src);
		return;
	}
	len = R_MIN ((size_t)(comma - src), sizeof (base) - 1);
	memcpy (base, src, len);
	base[len] = '\0';
	r_str_trim (base);
	off = r_str_trim_head_ro (comma + 1);
	if (!strcmp (off, "0")) {
		r_egg_printf (egg, "  mov %s, %s\n", reg, base);
	} else {
		r_egg_printf (egg, "  add %s, %s, %s\n", reg, base, off);
	}
}

static void store_slot(REgg *egg, const char *src, const char *dst, int sz) {
	r_egg_printf (egg, "  %s %s, [%s]\n", sz == 'b'? "strb": "str", src, dst);
}

static void set_arg_slot(char *out, size_t outlen, int num) {
	snprintf (out, outlen, "sp, %d", 8 + (num * 4));
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
		r_egg_printf (egg, "  ldr %s, [%s]\n", regs[regidx], lastargs[i]);
		lastargs[i][0] = '\0';
	}
	lastarg = 0;
}

static void emit_init(REgg *egg) {
	/* TODO */
}

static char *emit_syscall(REgg *egg, int num) {
	int svc = 0;
	switch (egg->os) {
	case R_EGG_OS_DARWIN:
	case R_EGG_OS_OSX:
	case R_EGG_OS_IOS:
	case R_EGG_OS_MACOS:
		svc = 0x80;
		break;
	case R_EGG_OS_WATCHOS:
		svc = 0x8000;
		break;
	case R_EGG_OS_LINUX:
		svc = 0;
		break;
	}
	return r_str_newf (": mov " R_AX ", `.arg`\n: svc 0x%x\n", svc);
}

static void emit_frame(REgg *egg, int sz) {
	r_egg_printf (egg, "  push {fp,lr}\n");
	if (sz > 0) {
		r_egg_printf (egg,
			// "  mov "R_BP", "R_SP"\n"
			"  add fp, sp, 4\n" // size of arguments
			"  sub sp, sp, %d\n",
			sz); // size of stackframe 8, 16, ..
	}
}

static void emit_frame_end(REgg *egg, int sz, int ctx) {
	if (sz > 0) {
		r_egg_printf (egg, "  add sp, fp, %d\n", sz);
	}
	if (ctx > 0) {
		r_egg_printf (egg, "  pop {fp,pc}\n");
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
	int slen = strlen (str) + 1;
	int rest = (slen % 4);
	if (rest) {
		rest = 4 - rest;
	}
	int total_data = slen + rest;
	char *s = r_str_escape (str);
	if (egg->bits == 16) {
		// Thumb: use adr to get string address, then branch over data
		r_egg_printf (egg, "  adr r0, 4\n");
		r_egg_printf (egg, "  b %d\n", 4 + total_data); // skip over data
	} else {
		// ARM32: add pc skips over inline data (pc reads as +8)
		int off = total_data - 4;
		r_egg_printf (egg, "  add pc, %d\n", off);
	}
	r_egg_printf (egg, ".string \"%s\"\n", s);
	free (s);
	if (rest) {
		r_egg_printf (egg, ".fill %d, 1, 0\n", rest);
	}
	if (egg->bits != 16) {
		// ARM32: calculate string address relative to pc
		r_egg_printf (egg, "  sub r0, pc, %d\n", total_data + 4);
	}
	{
		char str[32], *p = r_egg_mkvar (egg, str, dstvar, 0);
		r_egg_printf (egg, "  str r0, [%s]\n", p);
		free (p);
	}
}

static void emit_jmp(REgg *egg, const char *str, int atr) {
	if (atr) {
		r_egg_printf (egg, "  ldr r0, %s", str);
		r_egg_printf (egg, "  bx r0\n");
	} else {
		r_egg_printf (egg, "  b %s\n", str);
	}
}

static void emit_call(REgg *egg, const char *str, int atr) {
	load_arg_regs (egg, lastarg);

	if (atr) {
		r_egg_printf (egg, "  ldr r0, %s", str);
		r_egg_printf (egg, "  blx r0\n");
	} else {
		r_egg_printf (egg, "  bl %s\n", str);
	}
}

static void emit_arg(REgg *egg, int xs, int num, const char *str) {
	lastarg = num;
	switch (xs) {
	case 0:
		if (strchr (str, ',')) {
			strncpy (lastargs[num - 1], str, sizeof (lastargs[0]) - 1);
			lastargs[num - 1][sizeof (lastargs[0]) - 1] = '\0';
		} else {
			load_value (egg, "r0", str);
			save_arg (egg, num, "r0");
		}
		break;
	case '*':
		load_deref (egg, "r0", str, 'l');
		save_arg (egg, num, "r0");
		break;
	case '&':
		load_ptr (egg, "r0", str);
		save_arg (egg, num, "r0");
		break;
	}
}

static void emit_get_result(REgg *egg, const char *ocn) {
	if (is_memref (ocn)) {
		store_slot (egg, "r0", ocn, 'l');
	} else {
		r_egg_printf (egg, "  mov %s, r0\n", ocn);
	}
}

static void emit_restore_stack(REgg *egg, int size) {
	// XXX: must die.. or add emit_store_stack. not needed by ARM
	// r_egg_printf (egg, "  add sp, %d\n", size);
}

static void emit_get_while_end(REgg *egg, char *str, const char *ctxpush, const char *label) {
	snprintf (str, 32, "  b %s\n", label);
}

static void emit_while_end(REgg *egg, const char *labelback) {
	r_egg_printf (egg,
		"  pop {" R_AX "}\n"
		"  cmp " R_AX ", " R_AX "\n" // XXX MUST SUPPORT != 0 COMPARE HERE
		"  beq %s\n",
		labelback);
}

static void emit_get_var(REgg *egg, int type, char *out, int idx) {
	switch (type) {
	case 0: snprintf (out, 32, "sp, %d", (idx - 1) & ~3); break; /* variable, 4-byte aligned */
	case 1:
		snprintf (out, 32, "r%d", ((idx - 4) / 4) & 3);
		break; /* registers */
	case 2:
		snprintf (out, 32, "r%d", ((idx - 12) / 4) & 3);
		break; /* registers */
	}
}

static void emit_trap(REgg *egg) {
	r_egg_printf (egg, "  udf 16\n");
}

static void emit_load_ptr(REgg *egg, const char *dst) {
	load_ptr (egg, "r0", dst);
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
		arg++; /* for <=, >=, ... */
	}
	p = r_egg_mkvar (egg, str, arg, 0);
	if (lastargs[0][0]) {
		load_value (egg, R_AX, lastargs[0]);
	} else {
		r_egg_printf (egg, "  mov " R_AX ", 0\n");
	}
	load_value (egg, R_TMP, p);
	r_egg_printf (egg, "  cmp " R_AX ", " R_TMP "\n");
	r_egg_printf (egg, "  %s %s\n", op, dst);
	lastargs[0][0] = '\0';
	lastarg = 0;
	free (p);
}

static void emit_load(REgg *egg, const char *dst, int sz) {
	load_deref (egg, R_AX, dst, sz);
}

static void emit_mathop(REgg *egg, int ch, int vs, int type, const char *eq, const char *p) {
	char *op;
	switch (ch) {
	case '^': op = "eor"; break;
	case '&': op = "and"; break;
	case '|': op = "orr"; break;
	case '-': op = "sub"; break;
	case '+': op = "add"; break;
	case '*': op = "mul"; break;
	case '/': op = "div"; break;
	default: op = "mov"; break;
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
	if (type == '*') {
		r_egg_printf (egg, "  %s %s, [%s]\n", op, p, eq);
	} else {
		r_egg_printf (egg, "  %s %s, %s\n", op, p, eq);
	}
}

static const char *emit_regs(REgg *egg, int idx) {
	return regs[idx % R_NGP];
}

static void emit_get_arg(REgg *egg, char *out, int idx) {
	const char *regs[] = {"r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7"};
	if (idx >= 0 && idx < 8) {
		strcpy (out, regs[idx]);
	}
}

REggEmit EMIT_NAME = {
	.retvar = "r0",
	.arch = R_ARCH,
	.size = R_SZ,
	.jmp = emit_jmp,
	.call = emit_call,
	.init = emit_init,
	.equ = emit_equ,
	.regs = emit_regs,
	// .sc = emit_sc,
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
