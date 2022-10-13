/* pancake // nopcode.org 2010-2011 -- arm emiter */

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
	return r_str_newf (": mov "R_AX ", `.arg`\n: svc 0x%x\n", svc);
}

static void emit_frame(REgg *egg, int sz) {
	r_egg_printf (egg, "  push {fp,lr}\n");
	if (sz > 0) {
		r_egg_printf (egg,
			// "  mov "R_BP", "R_SP"\n"
			"  add fp, sp, $4\n"	// size of arguments
			"  sub sp, %d\n", sz);	// size of stackframe 8, 16, ..
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
	int j, k;
	for (j = 0; j < nargs; j++) {
		k = j * R_SZ;
		r_egg_printf (egg, "  ldr %s, [sp, %d]\n",
			regs[j + 1], k? k + 4: k + 8);
	}
}

static void emit_set_string(REgg *egg, const char *dstvar, const char *str, int j) {
	int rest, off = 0;
	off = strlen (str) + 1;
	rest = (off % 4);
	if (rest) {
		rest = 4 - rest;
	}
	off += rest - 4;
	r_egg_printf (egg, "  add pc, %d\n", (off));
	// XXX: does not handle \n and so on.. must use r_util
	// use r_str_escape to handle \n
	// do not forget mem leak
	r_egg_printf (egg, ".string \"%s\"\n", str = r_str_escape (str));
	free ((char *) str);
	if (rest) {
		r_egg_printf (egg, ".fill %d, 1, 0\n", (rest));
	}
	r_egg_printf (egg, "  sub r0, pc, %d\n", off + 12);
	{
		char str[32], *p = r_egg_mkvar (egg, str, dstvar, 0);
		// r_egg_printf (egg, "DSTVAR=%s --> %s\n", dstvar, p);
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
	int i;
	// r_egg_printf (egg, " ARGS=%d CALL(%s,%d)\n", lastarg, str, atr);
	for (i = 0; i < lastarg; i++) {
		r_egg_printf (egg, "  ldr r%d, [%s]\n", lastarg - 1 - i, lastargs[i]);
		lastargs[i][0] = 0;
	}

	if (atr) {
		r_egg_printf (egg, "  ldr r0, %s", str);
		r_egg_printf (egg, "  blx r0\n");
	} else {
		r_egg_printf (egg, "  bl %s\n", str);
	}
}

static void emit_arg(REgg *egg, int xs, int num, const char *str) {
	int d = atoi (str);
	if (!attsyntax && (*str == '$')) {
		str++;
	}
	lastarg = num;
	switch (xs) {
	case 0:
		if (strchr (str, ',')) {
			// r_egg_printf (egg, ".  str r0, [%s]\n", str);
			strncpy (lastargs[num - 1], str, sizeof (lastargs[0]) - 1);
		} else {
			if (!atoi (str)) {
				R_LOG_WARN ("probably a bug?");
			}
			r_egg_printf (egg, "  mov r0, %s\n", str);
			snprintf (lastargs[num - 1], sizeof (lastargs[0]), "sp, %d", 8 + (num * 4));
			r_egg_printf (egg, "  str r0, [%s]\n", lastargs[num - 1]);
		}
		break;
	case '*':
		r_egg_printf (egg, "  push {%s}\n", str);
		break;
	case '&':
		if (d) {
			r_egg_printf (egg, "  add "R_BP ", %d\n", d);
		}
		r_egg_printf (egg, "  push { "R_BP " }\n");
		if (d) {
			r_egg_printf (egg, "  sub "R_BP ", %d\n", d);
		}
		break;
	}
}

static void emit_get_result(REgg *egg, const char *ocn) {
	r_egg_printf (egg, "  mov %s, r0\n", ocn);
}

static void emit_restore_stack(REgg *egg, int size) {
	// XXX: must die.. or add emit_store_stack. not needed by ARM
	// r_egg_printf (egg, "  add sp, %d\n", size);
}

static void emit_get_while_end(REgg *egg, char *str, const char *ctxpush, const char *label) {
	sprintf (str, "  push {%s}\n  b %s\n", ctxpush, label);
}

static void emit_while_end(REgg *egg, const char *labelback) {
	r_egg_printf (egg,
		"  pop "R_AX "\n"
		"  cmp "R_AX ", "R_AX "\n"	// XXX MUST SUPPORT != 0 COMPARE HERE
		"  beq %s\n", labelback);
}

static void emit_get_var(REgg *egg, int type, char *out, int idx) {
	switch (type) {
	case 0: sprintf (out, "sp, %d", idx - 1); break;/* variable */
	case 1: sprintf (out, "r%d", idx); break;	/* registers */
// sp,$%d", idx); break; /* argument */ // XXX: MUST BE r0, r1, r2, ..
	}
}

static void emit_trap(REgg *egg) {
	r_egg_printf (egg, "  udf 16\n");
}

static void emit_load_ptr(REgg *egg, const char *dst) {
	r_egg_printf (egg, "  ldr r0, [fp, %d]\n", atoi (dst));
}

static void emit_branch(REgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst) {
	char *p, str[64];
	char *arg = NULL;
	char *op = "beq";
	/* NOTE that jb/ja are inverted to fit cmp opcode */
	if (b) {
		*b = '\0';
		op = e? "bge": "bgt";
		arg = b + 1;
	} else if (g) {
		*g = '\0';
		op = e? "ble": "blt";
		arg = g + 1;
	}
	if (!arg) {
		if (e) {
			arg = e + 1;
			op = "bne";
		} else {
			arg = "0";
			op = n? "bne": "beq";
		}
	}

	if (*arg == '=') {
		arg++;		/* for <=, >=, ... */
	}
	p = r_egg_mkvar (egg, str, arg, 0);
	r_egg_printf (egg, "  pop "R_AX "\n");	/* TODO: add support for more than one arg get arg0 */
	r_egg_printf (egg, "  cmp %s, "R_AX "\n", p);
	// if (context>0)
	r_egg_printf (egg, "  %s %s\n", op, dst);
	free (p);
}

static void emit_load(REgg *egg, const char *dst, int sz) {
	switch (sz) {
	case 'l':
		r_egg_printf (egg, "  mov "R_AX ", %s\n", dst);
		r_egg_printf (egg, "  mov "R_AX ", ["R_AX "]\n");
		break;
	case 'b':
		r_egg_printf (egg, "  mov "R_AX ", %s\n", dst);
		r_egg_printf (egg, "  movz "R_AX ", ["R_AX "]\n");
		break;
	default:
		// TODO: unhandled?!?
		r_egg_printf (egg, "  mov "R_AX ", %s\n", dst);
		r_egg_printf (egg, "  mov "R_AX ", ["R_AX "]\n");
	}
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
	if (!eq) {
		eq = R_AX;
	}
	if (!p) {
		p = R_AX;
	}
#if 0
	// TODO:
	eprintf ("TYPE = %c\n", type);
	eprintf ("  %s%c %c%s, %s\n", op, vs, type, eq, p);
	eprintf ("  %s %s, [%s]\n", op, p, eq);
#endif
	if (type == '*') {
		r_egg_printf (egg, "  %s %s, [%s]\n", op, p, eq);
	} else {
		r_egg_printf (egg, "  %s %s, %s\n", op, p, eq);
	}
}

static const char *emit_regs(REgg *egg, int idx) {
	return regs[idx % R_NGP];
}

REggEmit EMIT_NAME = {
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
	.get_var = emit_get_var,
	.while_end = emit_while_end,
	.get_while_end = emit_get_while_end,
	.branch = emit_branch,
	.load = emit_load,
	.load_ptr = emit_load_ptr,
	.mathop = emit_mathop,
	.syscall = emit_syscall,
};
