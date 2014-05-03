/* pancake // nopcode.org 2010-2013 -- emit module for rcc */

#include <r_egg.h>
#include <r_types.h>

/* hardcoded */
#define attsyntax 0

#ifdef ARCH_X86_64
# define EMIT_NAME emit_x64
# define R_ARCH "x64"
# define R_SZ 8
# define R_SP "rsp"
# define R_BP "rbp"
# define R_AX "rax"
# define R_GP { "rax", "rdi", "rsi", "rdx" }
# define R_NGP 4
# define SYSCALL_ATT "syscall"
# define SYSCALL_INTEL "syscall"
#else
# define EMIT_NAME emit_x86
# define R_ARCH "x86"
# define R_SZ 4
# define R_SP "esp"
# define R_BP "ebp"
# define R_AX "eax"
# define R_GP { "eax", "ebx", "ecx", "edx" }
# define R_NGP 4
# define SYSCALL_ATT "int $0x80"
# define SYSCALL_INTEL "int 0x80"
#endif

static char *regs[] = R_GP;

static void emit_init (REgg *egg) {
// TODO: add 'andb rsp, 0xf0'
	if (attsyntax) r_egg_printf (egg, "mov %%"R_SP", %%"R_BP"\n");
	else r_egg_printf (egg, "mov "R_BP", "R_SP"\n");
}

static char *emit_syscall (REgg *egg, int nargs) {
	char p[512];
	if (attsyntax)
		return strdup (": mov $`.arg`, %"R_AX"\n: "SYSCALL_ATT"\n");
	switch (egg->os) {
	case R_EGG_OS_LINUX:
		strcpy (p, "\n : mov "R_AX", `.arg`\n : "SYSCALL_INTEL "\n");
		break;
	case R_EGG_OS_OSX:
	case R_EGG_OS_MACOS:
	case R_EGG_OS_DARWIN:
#if ARCH_X86_64
		snprintf (p, sizeof (p), "\n"
			"  : mov rax, `.arg`\n"
			"  : syscall\n");
#else
		snprintf (p, sizeof (p), "\n"
			"  : mov eax, `.arg`\n"
			"  : push eax\n"
			"  : int 0x80\n"
			"  : add esp, %d\n",
			4); //(nargs+2)*(egg->bits/8));
#endif
		break;
	default:
		return NULL;
	}
	return strdup (p);
}

static void emit_frame (REgg *egg, int sz) {
	if (sz<1)
		return;
	if (attsyntax)
		r_egg_printf (egg,
		"  push %%"R_BP"\n"
		"  mov %%"R_SP", %%"R_BP"\n"
		"  sub $%d, %%"R_SP"\n", sz);
	else r_egg_printf (egg,
		"  push "R_BP"\n"
		"  mov "R_BP", "R_SP"\n"
		"  sub "R_SP", %d\n", sz);
}

static void emit_frame_end (REgg *egg, int sz, int ctx) {
	if (sz>0) {
		if (attsyntax) {
			r_egg_printf (egg, "  add $%d, %%"R_SP"\n", sz);
			r_egg_printf (egg, "  pop %%"R_BP"\n");
		} else {
			r_egg_printf (egg, "  add "R_SP", %d\n", sz);
			r_egg_printf (egg, "  pop "R_BP"\n");
		}
	}
	if (ctx>0)
		r_egg_printf (egg, "  ret\n");
}

static void emit_comment(REgg *egg, const char *fmt, ...) {
	va_list ap;
	char buf[1024];
	va_start (ap, fmt);
	vsnprintf (buf, sizeof (buf), fmt, ap);
	if (attsyntax) r_egg_printf (egg, "  /* %s */\n", buf);
	else r_egg_printf (egg, "# %s\n", buf);
	va_end (ap);
}

static void emit_equ (REgg *egg, const char *key, const char *value) {
	r_egg_printf (egg, ".equ %s,%s\n", key, value);
}

static void emit_syscall_args(REgg *egg, int nargs) {
	int j, k;
	for (j=0; j<nargs; j++) {
		k = j*R_SZ;
		if (attsyntax)
			r_egg_printf (egg, "  mov %d(%%"R_SP"), %%%s\n", k, regs[j+1]);
		else {
			if (k>0)
				r_egg_printf (egg, "  mov %s, ["R_SP"+%d]\n", regs[j+1], k);
			else if (k<0)
				r_egg_printf (egg, "  mov %s, ["R_SP"%d]\n", regs[j+1], k);
			else r_egg_printf (egg, "  mov %s, ["R_SP"]\n", regs[j+1]);
		}
	}
}

static void emit_string(REgg *egg, const char *dstvar, const char *str, int j) {
	char *p, *s, str2[64];
	int i, len, oj = j;

	len = strlen (str);
	s = malloc (len+4);
	memcpy (s, str, len);
	memset (s+len, 0, 4);

	/* XXX: Hack: Adjust offset in R_BP correctly for 64b addresses */
#define BPOFF R_SZ-4
#define M32(x) (unsigned int)((x) & 0xffffffff)
	/* XXX: Assumes sizeof(ut32) == 4 */
	for (i=4; i<=oj; i+=4) {
		/* XXX endian issues (non-portable asm) */
		ut32 *n = (ut32 *)(s+i-4);
		p = r_egg_mkvar (egg, str2, dstvar, i+BPOFF);
		if (attsyntax) r_egg_printf (egg, "  movl $0x%x, %s\n", M32(*n), p);
		else r_egg_printf (egg, "  mov %s, 0x%x\n", p, M32(*n));
		free (p);
		j -= 4;
	}
#undef M32

	/* zero */
	p = r_egg_mkvar (egg, str2, dstvar, i+BPOFF);
	if (attsyntax) r_egg_printf (egg, "  movl $0, %s\n", p);
	else r_egg_printf (egg, "  mov %s, 0\n", p);
	free (p);

	/* store pointer */
	p = r_egg_mkvar (egg, str2, dstvar, j+4+BPOFF);
	if (attsyntax) r_egg_printf (egg, "  lea %s, %%"R_AX"\n", p);
	else r_egg_printf (egg, "  lea "R_AX", %s\n", p);
	free (p);

	p = r_egg_mkvar (egg, str2, dstvar, 0);
	if (attsyntax) r_egg_printf (egg, "  mov %%"R_AX", %s\n", p);
	else r_egg_printf (egg, "  mov %s, "R_AX"\n", p);
	free (p);

#undef BPOFF
#if 0
	char *p, str2[64];
	int i, oj = j;
	for (i=0; i<oj; i+=4) {
		/* XXX endian and 32/64bit issues */
		int *n = (int *)(str+i);
		p = r_egg_mkvar (egg, str2, dstvar, j);
		if (attsyntax) r_egg_printf (egg, "  movl $0x%x, %s\n", *n, p);
		else r_egg_printf (egg, "  mov %s, 0x%x\n", p, *n);
		j -= 4;
	}
	p = r_egg_mkvar (egg, str2, dstvar, oj);
	if (attsyntax) r_egg_printf (egg, "  lea %s, %%"R_AX"\n", p);
	else r_egg_printf (egg, "  lea "R_AX", %s\n", p);
	p = r_egg_mkvar (egg, str2, dstvar, 0);
	if (attsyntax) r_egg_printf (egg, "  mov %%"R_AX", %s\n", p);
	else r_egg_printf (egg, "  mov %s, "R_AX"\n", p);
#endif
	free (s);
}

static void emit_call(REgg *egg, const char *str, int atr) {
	if (atr) {
		if (attsyntax) r_egg_printf (egg, "  call *%s\n", str);
		else r_egg_printf (egg, "  call [%s]\n", str);
	} else r_egg_printf (egg, "  call %s\n", str);
}

static void emit_jmp(REgg *egg, const char *str, int atr) {
	if (atr) {
		if (attsyntax) r_egg_printf (egg, "  jmp *%s\n", str);
		else r_egg_printf (egg, "  jmp [%s]\n", str);
	} else r_egg_printf (egg, "  jmp %s\n", str);
}

static void emit_arg (REgg *egg, int xs, int num, const char *str) {
	int d = atoi (str);
	if (!attsyntax && (*str=='$'))
		str = str +1;
	switch (xs) {
	case 0:
		r_egg_printf (egg, "  push %s\n", str);
		break;
	case '*':
		if (attsyntax) r_egg_printf (egg, "  push (%s)\n", str);
		else r_egg_printf (egg, "  push [%s]\n", str);
		break;
	case '&':
		if (attsyntax) {
			if (d != 0) r_egg_printf (egg, "  addl $%d, %%"R_BP"\n", d);
			r_egg_printf (egg, "  pushl %%"R_BP"\n");
			if (d != 0) r_egg_printf (egg, "  subl $%d, %%"R_BP"\n", d);
		} else {
			if (d != 0) r_egg_printf (egg, "  add "R_BP", %d\n", d);
			r_egg_printf (egg, "  push "R_BP"\n");
			if (d != 0) r_egg_printf (egg, "  sub "R_BP", %d\n", d);
		}
		break;
	}
}

static void emit_get_result(REgg *egg, const char *ocn) {
	if (attsyntax) r_egg_printf (egg, "  mov %%"R_AX", %s\n", ocn);
	else r_egg_printf (egg, "  mov %s, "R_AX"\n", ocn);
}

static void emit_restore_stack (REgg *egg, int size) {
	if (attsyntax) r_egg_printf (egg, "  add $%d, %%"R_SP" /* args */\n", size);
	else r_egg_printf (egg, "  add "R_SP", %d\n", size);
}

static void emit_get_while_end (REgg *egg, char *str, const char *ctxpush, const char *label) {
	sprintf (str, "  push %s\n  jmp %s\n", ctxpush, label);
}

static void emit_while_end (REgg *egg, const char *labelback) {
#if 0
	if (attsyntax) {
		r_egg_printf (egg, "  pop %%"R_AX"\n");
		r_egg_printf (egg, "  cmp $0, %%"R_AX"\n"); // XXX MUST SUPPORT != 0 COMPARE HERE
		r_egg_printf (egg, "  jnz %s\n", labelback);
	} else {
#endif
		r_egg_printf (egg, "  pop "R_AX"\n");
		r_egg_printf (egg, "  test "R_AX", "R_AX"\n"); // XXX MUST SUPPORT != 0 COMPARE HERE
		r_egg_printf (egg, "  jnz %s\n", labelback);
//	}
}

// XXX: this is wrong
static void emit_get_var (REgg *egg, int type, char *out, int idx) {
	switch (type) {
	case 0:  /* variable */
		if (idx>0) sprintf (out, "["R_BP"+%d]", idx);
		else if (idx<0) sprintf (out, "["R_BP"%d]", idx);
		else strcpy (out, "["R_BP"]");
		break;
	case 1: /* argument */
// OMG WE CANT stuff found in relative address in stack in the stack
		eprintf ("WARNING: Using stack vars in naked functions\n");
		idx = 8; // HACK to make arg0, arg4, ... work
		if (idx>0) sprintf (out, "["R_SP"+%d]", idx);
		else if (idx<0) sprintf (out, "["R_SP"%d]", idx);
		else strcpy (out, "["R_SP"]");
		break;
	case 2:
		if (idx>0) sprintf (out, "["R_BP"+%d]", idx);
		else if (idx<0) sprintf (out, "["R_BP"%d]", idx);
		else strcpy (out, "["R_BP"]");
		break;
	}
}

static void emit_trap (REgg *egg) {
	r_egg_printf (egg, "  int3\n");
}

static void emit_load_ptr(REgg *egg, const char *dst) {
	int d = atoi (dst);
	if (d == 0) { // hack to handle stackvarptrz
		char *p = strchr (dst, '+');
		if (p) d = atoi (p+1);
	}
	//eprintf ("emit_load_ptr: HACK\n");
	// XXX: 32/64bit care
	//r_egg_printf (egg, "# DELTA IS (%s)\n", dst);
	if (attsyntax) r_egg_printf (egg, "  leal %d(%%"R_BP"), %%"R_AX"\n", d);
	else r_egg_printf (egg, "  lea "R_AX", ["R_BP"+%d]\n", d);
	//r_egg_printf (egg, "  movl %%"R_BP", %%"R_AX"\n");
	//r_egg_printf (egg, "  addl $%d, %%"R_AX"\n", d);
}

static void emit_branch(REgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst) {
	char *p, str[64];
	char *arg = NULL;
	char *op = "jz";
	int signed_value = 1; // XXX: add support for signed/unsigned variables
	/* NOTE that jb/ja are inverted to fit cmp opcode */
	if (b) {
		*b = '\0';
		if (signed_value) {
			if (e) op = "jge";
			else op = "jg";
		} else {
			if (e) op = "jae";
			else op = "ja";
		}
		arg = b+1;
	} else
	if (g) {
		*g = '\0';
		if (signed_value) {
			if (e) op = "jle";
			else op = "jl";
		} else {
			if (e) op = "jbe";
			else op = "jb";
		}
		arg = g+1;
	}
	if (arg == NULL) {
		if (e) {
			arg = e+1;
			op = "jne";
		} else {
			arg = attsyntax? "$0": "0";
			if (n) op = "jnz";
			else op ="jz";
		}
	}

	if (*arg=='=') arg++; /* for <=, >=, ... */
	p = r_egg_mkvar (egg, str, arg, 0);
	if (attsyntax) {
		r_egg_printf (egg, "  pop %%"R_AX"\n"); /* TODO: add support for more than one arg get arg0 */
		r_egg_printf (egg, "  cmp%c %s, %%"R_AX"\n", sz, p);
	} else {
		r_egg_printf (egg, "  pop "R_AX"\n"); /* TODO: add support for more than one arg get arg0 */
		r_egg_printf (egg, "  cmp "R_AX", %s\n", p);
	}
	// if (context>0)
	free (p);
	r_egg_printf (egg, "  %s %s\n", op, dst);
}

static void emit_load(REgg *egg, const char *dst, int sz) {
	if (attsyntax) {
		switch (sz) {
		case 'l':
			r_egg_printf (egg, "  movl %s, %%"R_AX"\n", dst);
			r_egg_printf (egg, "  movl (%%"R_AX"), %%"R_AX"\n");
		case 'b':
			r_egg_printf (egg, "  movl %s, %%"R_AX"\n", dst);
			r_egg_printf (egg, "  movzb (%%"R_AX"), %%"R_AX"\n");
			break;
		default:
			// TODO: unhandled?!?
			r_egg_printf (egg, "  mov%c %s, %%"R_AX"\n", sz, dst);
			r_egg_printf (egg, "  mov%c (%%"R_AX"), %%"R_AX"\n", sz);
		}
	} else {
		switch (sz) {
		case 'l':
			r_egg_printf (egg, "  mov "R_AX", %s\n", dst);
			r_egg_printf (egg, "  mov "R_AX", ["R_AX"]\n");
		case 'b':
			r_egg_printf (egg, "  mov "R_AX", %s\n", dst);
			r_egg_printf (egg, "  movz "R_AX", ["R_AX"]\n");
			break;
		default:
			// TODO: unhandled?!?
			r_egg_printf (egg, "  mov "R_AX", %s\n", dst);
			r_egg_printf (egg, "  mov "R_AX", ["R_AX"]\n");
		}
	}
}

static void emit_mathop(REgg *egg, int ch, int vs, int type, const char *eq, const char *p) {
	char *op;
	switch(ch) {
	case '^': op = "xor"; break;
	case '&': op = "and"; break;
	case '|': op = "or";  break;
	case '-': op = "sub"; break;
	case '+': op = "add"; break;
	case '*': op = "mul"; break;
	case '/': op = "div"; break;
	default:  op = "mov"; break;
	}
	if (attsyntax) {
		if (eq == NULL) eq = "%"R_AX;
		if (p == NULL) p = "%"R_AX;
		r_egg_printf (egg, "  %s%c %c%s, %s\n", op, vs, type, eq, p);
	} else {
		if (eq == NULL) eq = R_AX;
		if (p == NULL) p = R_AX;
	// TODO:
#if 0
		eprintf ("TYPE = %c\n", type);
		eprintf ("  %s%c %c%s, %s\n", op, vs, type, eq, p);
		eprintf ("  %s %s, [%s]\n", op, p, eq);
#endif
		if (type == '*') r_egg_printf (egg, "  %s %s, [%s]\n", op, p, eq);
		else r_egg_printf (egg, "  %s %s, %s\n", op, p, eq);
	}
}

static const char* emit_regs(REgg *egg, int idx) {
	return regs[idx%R_NGP];
}

REggEmit EMIT_NAME = {
	.retvar = R_AX,
	.arch = R_ARCH,
	.size = R_SZ,
	.init = emit_init,
	.jmp = emit_jmp,
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
	.set_string = emit_string,
	.get_var = emit_get_var,
	.while_end = emit_while_end,
	.get_while_end = emit_get_while_end,
	.branch = emit_branch,
	.load = emit_load,
	.load_ptr = emit_load_ptr,
	.mathop = emit_mathop,
	.syscall = emit_syscall,
};
