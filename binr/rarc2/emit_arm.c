// TODO: The arm support is not done. only few callbacks
/* pancake // nopcode.org 2010 -- emit module for rcc */

#include "rarc2.h"

#define EMIT_NAME emit_arm
#define R_ARCH "arm"
#define R_SZ 8
#define R_SP "sp"
#define R_BP "fp"
#define R_AX "r0"
#define R_GP { "r0", "r1", "r2", "r3", "r4" }
#define R_TMP "r9"
#define R_NGP 5

// no attsyntax for arm
static char *regs[] = R_GP;

static char *emit_syscall (int num) {
	return strdup (": mov "R_AX", `.arg`\n: svc 0x8000\n");
}

static void emit_frame (int sz) {
	if (sz>0) rcc_printf (
		"  push {fp,lr}\n"
		//"  mov "R_BP", "R_SP"\n"
		"  add fp, sp, 4\n" // huh?
		"  sub sp, %d\n", sz); // 8, 16, ..
}

static void emit_frame_end (int sz, int ctx) {
	if (sz>0) rcc_printf ("  add "R_SP", %d\n", sz);
	if (ctx>0) rcc_puts ("  pop {fp,pc}\n");
}

static void emit_comment(const char *fmt, ...) {
	va_list ap;
	char buf[1024];
	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf), fmt, ap);
	rcc_printf ("# %s\n", buf);
	va_end (ap);
}

static void emit_equ (const char *key, const char *value) {
	rcc_printf (".equ %s,%s\n", key, value);
}

static void emit_syscall_args(int nargs) {
	int j, k;
	for (j=0; j<nargs; j++) {
		k = j*R_SZ;
		rcc_printf ("  ldr %s, ["R_SP", #%c%d]\n", regs[j+1], k>0?'+':' ', k);
	}
}

static void emit_set_string(const char *dstvar, const char *str, int j) {
	int off = 0;
	// TODO: branch string+off
	off = strlen (str);
	off += (off%4);
	rcc_printf ("  add pc, %d\n", off);
	// XXX: does not handle \n and so on.. must use r_util
	rcc_printf (".string \"%s\"\n", str);
	if (off%4) rcc_printf (".fill %d, 1, 0\n", (off%4));
	rcc_printf ("  sub r0, pc, %d\n", off);
}

static void emit_call(const char *str, int atr) {
	if (atr) {
		rcc_printf("  ldr r0, %s", str);
		rcc_printf("  blx r0\n");
	} else rcc_printf("  bl %s\n", str);
}

static void emit_arg (int xs, int num, const char *str) {
	int d = atoi (str);
	if (!attsyntax && (*str=='$'))
		str++;
	switch (xs) {
	case 0:
		rcc_printf ("  push {%s}\n", str);
		break;
	case '*':
		rcc_printf ("  push {%s}\n", str);
		break;
	case '&':
		if (d) rcc_printf ("  add "R_BP", %d\n", d);
		rcc_printf ("  push {"R_BP"}\n");
		if (d) rcc_printf ("  sub "R_BP", %d\n", d);
		break;
	}
}

static void emit_get_result(const char *ocn) {
	rcc_printf ("  mov %s, r0\n", ocn);
}

static void emit_restore_stack (int size) {
	rcc_printf("  add sp, %d\n", size);
}

static void emit_get_while_end (char *str, const char *ctxpush, const char *label) {
	sprintf (str, "  push {%s}\n  b %s\n", ctxpush, label);
}

static void emit_while_end (const char *labelback) {
	rcc_printf ("  pop "R_AX"\n");
	rcc_printf ("  cmp "R_AX", "R_AX"\n"); // XXX MUST SUPPORT != 0 COMPARE HERE
	rcc_printf ("  beq %s\n", labelback);
}

static void emit_get_var (int type, char *out, int idx) {
	switch (type) {
	case 0: sprintf (out, "fp,%c%d", idx>0?' ':'+', -idx); break; /* variable */
	case 1: sprintf (out, "sp,%c%d", idx>0?'+':' ', idx); break; /* argument */
	}
}

static void emit_trap () {
	rcc_printf ("  svc 3\n");
}

static void emit_load_ptr(const char *dst) {
	int d = atoi (dst);
	eprintf ("HACK HACK HACK\n");
	// XXX: 32/64bit care
	rcc_printf ("  ldr "R_AX", ["R_BP", %d]\n", d);
	//rcc_printf ("  movl %%"R_BP", %%"R_AX"\n");
	//rcc_printf ("  addl $%d, %%"R_AX"\n", d);
}

static void emit_branch(char *b, char *g, char *e, char *n, int sz, const char *dst) {
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
	p = mk_var (str, arg, 0);
	if (attsyntax) {
		rcc_printf ("  pop %%"R_AX"\n"); /* TODO: add support for more than one arg get arg0 */
		rcc_printf ("  cmp%c %s, %%"R_AX"\n", sz, p);
	} else {
		rcc_printf ("  pop "R_AX"\n"); /* TODO: add support for more than one arg get arg0 */
		rcc_printf ("  cmp %s, "R_AX"\n", p);
	}
	// if (context>0)
	rcc_printf ("  %s %s\n", op, dst);
}

static void emit_load(const char *dst, int sz) {
	switch (sz) {
	case 'l':
		rcc_printf ("  mov "R_AX", %s\n", dst);
		rcc_printf ("  mov "R_AX", ["R_AX"]\n");
	case 'b':
		rcc_printf ("  mov "R_AX", %s\n", dst);
		rcc_printf ("  movz "R_AX", ["R_AX"]\n");
		break;
	default:
		// TODO: unhandled?!?
		rcc_printf ("  mov "R_AX", %s\n", dst);
		rcc_printf ("  mov "R_AX", ["R_AX"]\n");
	}
}

static void emit_mathop(int ch, int vs, int type, const char *eq, const char *p) {
	char *op;
	switch (ch) {
	case '^': op = "xor"; break;
	case '&': op = "and"; break;
	case '|': op = "or";  break;
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
	if (type == '*') rcc_printf ("  %s %s, [%s]\n", op, p, eq);
	else rcc_printf ("  %s %s, %s\n", op, p, eq);
}

static const char* emit_regs(int idx) {
	return regs[idx%R_NGP];
}

struct emit_t EMIT_NAME = {
	.arch = R_ARCH,
	.size = R_SZ,
	.call = emit_call,
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
