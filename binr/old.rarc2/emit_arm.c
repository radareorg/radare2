/* pancake // nopcode.org 2010 -- arm emiter */

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
static int lastarg = 0;
static char lastargs[16][32];

static char *emit_syscall (int num) {
	return strdup (": mov "R_AX", `.arg`\n: svc 0x8000\n");
}

static void emit_frame (int sz) {
	rcc_printf ("  push {fp,lr}\n");
	if (sz>0) rcc_printf (
		//"  mov "R_BP", "R_SP"\n"
		"  add fp, sp, $4\n" // size of arguments
		"  sub sp, $%d\n", sz); // size of stackframe 8, 16, ..
}

static void emit_frame_end (int sz, int ctx) {
	if (sz>0) rcc_printf ("  add sp, fp, $%d\n", sz);
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
		rcc_printf ("  ldr %s, [sp, #%c%d]\n", regs[j+1], k>0?'+':' ', k);
	}
}

static void emit_set_string(const char *dstvar, const char *str, int j) {
	int rest, off = 0;
	off = strlen (str)+1;
	rest = (off%4);
	if (rest) rest = 4-rest;
	off += rest-8;
	rcc_printf ("  add pc, $%d\n", (off));
	// XXX: does not handle \n and so on.. must use r_util
	rcc_printf (".string \"%s\"\n", str);
	if (rest) rcc_printf (".fill %d, 1, 0\n", (rest));
	rcc_printf ("  sub r0, pc, $%d\n", off+16);
	{
		char str[32], *p = mk_var (str, dstvar, 0);
		//rcc_printf("DSTVAR=%s --> %s\n", dstvar, p);
		rcc_printf ("  str r0, [%s]\n", p);
	}
}

static void emit_call(const char *str, int atr) {
	int i;
	//rcc_printf(" ARGS=%d CALL(%s,%d)\n", lastarg, str, atr);
	for(i=0;i<lastarg;i++) {
		rcc_printf ("  ldr r%d, [%s]\n", lastarg-1-i, lastargs[i]);
		lastargs[i][0] = 0;
	}

	if (atr) {
		rcc_printf("  ldr r0, %s", str);
		rcc_printf("  blx r0\n");
	} else rcc_printf("  bl %s\n", str);
}

static void emit_arg (int xs, int num, const char *str) {
	int d = atoi (str);
	if (!attsyntax && (*str=='$'))
		str++;
	lastarg = num;
	switch (xs) {
	case 0:
		if (strchr(str, ',')) {
			//rcc_printf (".  str r0, [%s]\n", str);
			strncpy (lastargs[num-1], str, sizeof(lastargs[0]));
		} else {
			if (!atoi (str)) eprintf ("WARNING: probably a bug?\n");
			rcc_printf ("  mov r0, $%s\n", str);
			snprintf( lastargs[num-1], sizeof (lastargs[0]), "fp, $-%d", 8+(num*4));
			rcc_printf ("  str r0, [%s]\n", lastargs[num-1]);
		}
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
	// XXX: must die.. or add emit_store_stack. not needed by ARM
	// rcc_printf("  add sp, %d\n", size);
}

static void emit_get_while_end (char *str, const char *ctxpush, const char *label) {
	sprintf (str, "  push {%s}\n  b %s\n", ctxpush, label);
}

static void emit_while_end (const char *labelback) {
	rcc_printf (
		"  pop "R_AX"\n"
		"  cmp "R_AX", "R_AX"\n" // XXX MUST SUPPORT != 0 COMPARE HERE
		"  beq %s\n", labelback);
}

static void emit_get_var (int type, char *out, int idx) {
	switch (type) {
	case 0: sprintf (out, "fp,$%d", -idx); break; /* variable */
	case 1: sprintf (out, "sp,$%d", idx); break; /* argument */ // XXX: MUST BE r0, r1, r2, ..
	}
}

static void emit_trap () {
	rcc_printf ("  svc 3\n");
}

static void emit_load_ptr(const char *dst) {
	rcc_printf ("  ldr r0, [fp, %d]\n", atoi (dst));
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
	rcc_printf ("  pop "R_AX"\n"); /* TODO: add support for more than one arg get arg0 */
	rcc_printf ("  cmp %s, "R_AX"\n", p);
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
