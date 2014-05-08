/* pancake // nopcode.org 2011 -- trace emiter */

#include <r_egg.h>
#define attsyntax 0

#define EMIT_NAME emit_trace
#define R_ARCH "trace"
#define R_SZ 8
#define R_SP "sp"
#define R_BP "bp"
#define R_AX "a0"
#define R_GP { "a0", "a1", "a2", "a3", "a4" }
#define R_TMP "t0"
#define R_NGP 5

// no attsyntax for arm
static char *regs[] = R_GP;

static void emit_init (REgg *egg) {
	/* TODO */
}

static char *emit_syscall (REgg *egg, int num) {
	char buf[32];
	snprintf (buf, sizeof (buf), "syscall (%d)\n", num);
	return strdup (buf);
}

static void emit_frame (REgg *egg, int sz) {
	r_egg_printf (egg, "frame (%d)\n", sz);
}

static void emit_frame_end (REgg *egg, int sz, int ctx) {
	r_egg_printf (egg, "frame_end (%d, %d)\n", sz, ctx);
}

static void emit_comment(REgg *egg, const char *fmt, ...) {
	va_list ap;
	char buf[1024];
	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf), fmt, ap);
	r_egg_printf (egg, "# %s\n", buf);
	va_end (ap);
}

static void emit_equ (REgg *egg, const char *key, const char *value) {
	r_egg_printf (egg, "equ (%s, %s)\n", key, value);
}

static void emit_syscall_args(REgg *egg, int nargs) {
	r_egg_printf (egg, "syscall_args (%d)\n", nargs);
}

static void emit_set_string(REgg *egg, const char *dstvar, const char *str, int j) {
	// what is j?
	r_egg_printf (egg, "set (\"%s\", \"%s\", %d)\n", dstvar, str, j);
}

static void emit_call(REgg *egg, const char *str, int atr) {
	if (atr) r_egg_printf (egg, "call ([%s])\n", str);
	else r_egg_printf (egg, "call (%s)\n", str);
}

static void emit_jmp(REgg *egg, const char *str, int atr) {
	if (atr) r_egg_printf (egg, "goto ([%s])\n", str);
	else r_egg_printf (egg, "goto (%s)\n", str);
}

static void emit_arg (REgg *egg, int xs, int num, const char *str) {
	// TODO: enhace output here
	r_egg_printf (egg, "arg.%d.%d=%s\n", xs, num, str);
}

static void emit_get_result(REgg *egg, const char *ocn) {
	r_egg_printf (egg, "get_result (%s)\n", ocn);
}

static void emit_restore_stack (REgg *egg, int size) {
	r_egg_printf (egg, "restore_stack (%d)\n", size);
	// XXX: must die.. or add emit_store_stack. not needed by ARM
	// r_egg_printf (egg, "  add sp, %d\n", size);
}

static void emit_get_while_end (REgg *egg, char *str, const char *ctxpush, const char *label) {
	r_egg_printf (egg, "get_while_end (%s, %s, %s)\n", str, ctxpush, label);
}

static void emit_while_end (REgg *egg, const char *labelback) {
	r_egg_printf (egg, "while_end (%s)\n", labelback);
}

static void emit_get_var (REgg *egg, int type, char *out, int idx) {
	switch (type) {
	case 0: sprintf (out, "fp,$%d", -idx); break; /* variable */
	case 1: sprintf (out, "sp,$%d", idx); break; /* argument */ // XXX: MUST BE r0, r1, r2, ..
	}
}

static void emit_trap (REgg *egg) {
	r_egg_printf (egg, "trap\n");
}

// TODO atoi here?
static void emit_load_ptr(REgg *egg, const char *dst) {
	r_egg_printf (egg, "loadptr (%s)\n", dst);
}

static void emit_branch(REgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst) {
	// This function signature is crap
	char *p, str[64];
	char *arg = NULL;
	char *op = "beq";
	/* NOTE that jb/ja are inverted to fit cmp opcode */
	if (b) {
		*b = '\0';
		op = e?"bge":"bgt";
		arg = b+1;
	} else
	if (g) {
		*g = '\0';
		op = e?"ble":"blt";
		arg = g+1;
	}
	if (arg == NULL) {
		if (e) {
			arg = e+1;
			op = "bne";
		} else {
			arg = "0";
			op = n?"bne":"beq";
		}
	}

	if (*arg=='=') arg++; /* for <=, >=, ... */
	p = r_egg_mkvar (egg, str, arg, 0);
	r_egg_printf (egg, "%s (%s) => (%s)\n", op, p, dst);
	free (p);
}

// XXX: sz must be char
static void emit_load(REgg *egg, const char *dst, int sz) {
	r_egg_printf (egg, "load (\"%s\", %c)\n", dst, sz);
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
	default:  op = "mov"; break;
	}
	if (eq == NULL) eq = R_AX;
	if (p == NULL) p = R_AX;
#if 0
	// TODO:
	eprintf ("TYPE = %c\n", type);
	eprintf ("  %s%c %c%s, %s\n", op, vs, type, eq, p);
	eprintf ("  %s %s, [%s]\n", op, p, eq);
#endif
	if (type == '*')
		r_egg_printf (egg, "%s (%s, [%s])\n", op, p, eq);
	else r_egg_printf (egg, "%s (%s, %s)\n", op, p, eq);
}

static const char* emit_regs(REgg *egg, int idx) {
	return regs[idx%R_NGP];
}

REggEmit EMIT_NAME = {
	.retvar = "a0",
	.arch = R_ARCH,
	.size = R_SZ,
	.jmp = emit_jmp,
	.call = emit_call,
	.init = emit_init,
	.equ = emit_equ,
	.regs = emit_regs,
	//.sc = emit_sc,
	.trap = emit_trap,
	.frame = emit_frame,
	.frame_end = emit_frame_end,
	.comment = emit_comment,
	.push_arg = emit_arg,
	.restore_stack = emit_restore_stack,
	.get_result = emit_get_result,
	.syscall_args = emit_syscall_args,
	.set_string = emit_set_string,
	.get_var = emit_get_var,
	.while_end = emit_while_end,
	.get_while_end = emit_get_while_end,
	.branch = emit_branch,
	.load = emit_load,
	.load_ptr = emit_load_ptr,
	.mathop = emit_mathop,
	.syscall = emit_syscall,
};
