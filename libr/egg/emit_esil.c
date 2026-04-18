/* radare2 - LGPL - Copyright 2022-2026 - pancake */
/* ESIL emitter for the r_egg compiler.
 *
 * Translates the high-level .r egg language into ESIL
 * (Evaluable Strings Intermediate Language) expressions.
 *
 * Local variables become abstract ESIL registers named v<idx>.
 * Function arguments become a<idx>. Temporaries use r0..r4.
 * The return value lives in "a0".
 *
 * The comma separated ESIL tokens are emitted inline, each group
 * of tokens forming a "statement" is terminated with a comma too
 * so the output can be concatenated into a larger ESIL string.
 */

#include <r_egg.h>

#define EMIT_NAME emit_esil
#define R_ARCH "esil"
#define R_SZ 8
#define R_SP "SP"
#define R_BP "FP"
#define R_PC "PC"
#define R_AX "a0"
#define R_GP { "r0", "r1", "r2", "r3", "r4" }
#define R_NGP 5

static char *regs[] = R_GP;

/* Peephole state: remember a pending "0,<reg>,:=" init so we can drop it
 * when the next op overwrites the same register with a plain assignment.
 * The r_egg library is not thread-safe, so a file-local static is fine. */
static int g_pending_zero = 0;
static char g_pending_zero_reg[16];

static void flush_pending_zero(REgg *egg) {
	if (g_pending_zero) {
		r_egg_printf (egg, "0,%s,:=,", g_pending_zero_reg);
		g_pending_zero = 0;
	}
}

static void emit_init(REgg *egg) {
	g_pending_zero = 0;
}

static char *emit_syscall(REgg *egg, int num) {
	flush_pending_zero (egg);
	/* The string returned here is fed back through the egg parser, so it
	 * must be valid .r syntax. Use the ":" prefix to escape into raw mode
	 * and terminate with a newline so the parser leaves raw mode cleanly.
	 * The syscall number is injected through the `.arg` backtick expansion
	 * which the parser resolves from the current @syscall declaration.
	 * Note: no space after ":" so the raw line does not add a leading space. */
	return strdup ("\n:`.arg`,$,\n");
}

static void emit_frame(REgg *egg, int sz) {
	/* no explicit frame setup for ESIL - variables are abstract */
}

static void emit_frame_end(REgg *egg, int sz, int ctx) {
	/* ESIL does not model real function returns. Emit nothing;
	 * the parser will insert labels that delimit function bodies. */
	flush_pending_zero (egg);
}

static void emit_comment(REgg *egg, const char *fmt, ...) {
	/* ESIL has no comment syntax, drop comments silently */
}

static void emit_equ(REgg *egg, const char *key, const char *value) {
	/* .equ aliases are resolved at parse time, nothing to emit */
}

static void emit_syscall_args(REgg *egg, int nargs) {
	/* syscall args are already in a1..aN registers, nothing to do */
}

static void emit_set_string(REgg *egg, const char *dstvar, const char *str, int j) {
	flush_pending_zero (egg);
	/* store the string address into the destination variable.
	 * Encode the literal as a comment-like token so downstream tooling
	 * can still resolve it; ESIL has no native string literal.
	 */
	r_egg_printf (egg, "\"%s\",%s,:=,", str, dstvar);
}

static void emit_jmp(REgg *egg, const char *str, int atr) {
	if (!str) {
		return;
	}
	flush_pending_zero (egg);
	if (atr) {
		r_egg_printf (egg, "%s,[%d],PC,:=,", str, (egg->bits == 64) ? 8 : 4);
	} else {
		r_egg_printf (egg, "%s,PC,:=,", str);
	}
}

static void emit_call(REgg *egg, const char *str, int atr) {
	/* a call is represented as a direct PC assignment. Real return
	 * semantics are left to higher-level analysis tooling. */
	if (!str) {
		return;
	}
	flush_pending_zero (egg);
	if (atr) {
		r_egg_printf (egg, "%s,[%d],PC,:=,", str, (egg->bits == 64) ? 8 : 4);
	} else {
		r_egg_printf (egg, "%s,PC,:=,", str);
	}
}

static void emit_arg(REgg *egg, int xs, int num, const char *str) {
	/* arguments are passed via a1..aN abstract registers.
	 * xs is 0 (value), '*' (deref), or '&' (address-of). */
	char target[16];
	flush_pending_zero (egg);
	snprintf (target, sizeof (target), "a%d", num);
	switch (xs) {
	case 0:
		r_egg_printf (egg, "%s,%s,:=,", str, target);
		break;
	case '*':
		r_egg_printf (egg, "%s,[%d],%s,:=,", str, R_SZ, target);
		break;
	case '&':
		/* address-of: emit the name as-is */
		r_egg_printf (egg, "%s,%s,:=,", str, target);
		break;
	}
}

static void emit_get_result(REgg *egg, const char *ocn) {
	if (ocn) {
		flush_pending_zero (egg);
		r_egg_printf (egg, "a0,%s,:=,", ocn);
	}
}

static void emit_restore_stack(REgg *egg, int size) {
	/* no explicit stack in ESIL abstract output */
}

static void emit_get_while_end(REgg *egg, char *str, const char *ctxpush, const char *label) {
	/* Inserted at the end of a while-loop body: re-push the loop
	 * condition value (copy ctxpush into a1) and unconditionally
	 * jump back to the begin label, where emit_branch will re-check
	 * the comparison against the fresh value. */
	if (ctxpush && label) {
		snprintf (str, 64, "%s,a1,:=,%s,PC,:=,", ctxpush, label);
	} else if (label) {
		snprintf (str, 64, "%s,PC,:=,", label);
	} else {
		*str = '\0';
	}
}

static void emit_while_end(REgg *egg, const char *labelback) {
	if (labelback) {
		flush_pending_zero (egg);
		r_egg_printf (egg, "%s,PC,:=,", labelback);
	}
}

static void emit_get_var(REgg *egg, int type, char *out, int idx) {
	switch (type) {
	case 0:
		/* local variable: map by frame offset */
		snprintf (out, 32, "v%d", idx);
		break;
	case 1:
		/* function argument (naked function) */
		snprintf (out, 32, "a%d", idx);
		break;
	case 2:
		/* framed function argument */
		snprintf (out, 32, "v%d", idx);
		break;
	default:
		*out = '\0';
		break;
	}
}

static void emit_trap(REgg *egg) {
	flush_pending_zero (egg);
	r_egg_printf (egg, "0,$$,");
}

static void emit_load_ptr(REgg *egg, const char *dst) {
	if (dst) {
		/* Writes the address into r0; keeps any pending zero init alive. */
		r_egg_printf (egg, "%s,r0,:=,", dst);
	}
}

static void emit_branch(REgg *egg, char *b, char *g, char *e, char *n, int sz, const char *dst) {
	flush_pending_zero (egg);
	/* The parser has pushed the LHS of the condition via push_arg,
	 * which in this backend copies it into a1. emit_branch jumps to
	 * dst when the condition is FALSE (it is the "skip the body"
	 * branch), so the operator is the negation of the source cmp.
	 *
	 * ESIL comparison semantics:
	 *   a,b,>    pushes 1 if b > a  (ditto for <, >=, <=)
	 *   a,b,==   sets $z = (a == b), pushes nothing useful
	 *   X,!      pushes !X (logical not)
	 */
	const char *op = NULL;
	char *arg = NULL;
	int equality = 0;   /* 1 = test via $z, 0 = ordered comparison */
	int invert = 0;     /* 1 = invert result (for skip-when-equal) */
	if (b) {
		*b = '\0';
		/* source: < or <=, skip on >= or > */
		op = e ? ">" : ">=";
		arg = b + 1;
	} else if (g) {
		*g = '\0';
		/* source: > or >=, skip on <= or < */
		op = e ? "<" : "<=";
		arg = g + 1;
	} else if (e) {
		/* source: == or !=, branch on equality */
		arg = e + 1;
		equality = 1;
		/* n != NULL means source was "!=", so skip when equal;
		 * n == NULL means source was "==", so skip when not equal. */
		invert = (n == NULL) ? 1 : 0;
	} else {
		/* bare `if(x)` (skip when x == 0) or `if(!x)` (skip when x != 0) */
		arg = (char *)"0";
		equality = 1;
		/* n != NULL means source had '!', so skip when x != 0 (invert).
		 * n == NULL means bare `if(x)`, so skip when x == 0 (no invert). */
		invert = n ? 1 : 0;
	}
	if (arg && *arg == '=') {
		arg++;  /* step over the second char of <=, >= */
	}
	while (arg && (*arg == ' ' || *arg == '\t')) {
		arg++;   /* drop any whitespace between the operator and the RHS */
	}
	if (!arg || !*arg) {
		arg = (char *)"0";
	}
	if (equality) {
		r_egg_printf (egg, "%s,a1,==,$z,%s?{,%s,PC,:=,},",
			arg, invert ? "!," : "", dst);
	} else {
		r_egg_printf (egg, "%s,a1,%s,?{,%s,PC,:=,},",
			arg, op, dst);
	}
}

static void emit_load(REgg *egg, const char *dst, int sz) {
	int width;
	switch (sz) {
	case 'b': width = 1; break;
	case 'q': width = 8; break;
	default:  width = 4; break;
	}
	/* The load writes to r0 and never reads the accumulator; any
	 * pending zero init for r1 is preserved so it can still be
	 * peepholed out by a following plain assignment to r1. */
	r_egg_printf (egg, "%s,[%d],r0,:=,", dst, width);
}

static void emit_mathop(REgg *egg, int ch, int vs, int type, const char *eq, const char *p) {
	const char *op;
	if (!eq) {
		eq = R_AX;
	}
	if (!p) {
		p = R_AX;
	}
	switch (ch) {
	case '^': op = "^="; break;
	case '&': op = "&="; break;
	case '|': op = "|="; break;
	case '-': op = "-="; break;
	case '+': op = "+="; break;
	case '*': op = "*="; break;
	case '/': op = "/="; break;
	default:  op = NULL; break; /* plain assignment */
	}
	if (!op) {
		/* Peephole: queue the "0,reg,:=" init the parser emits before
		 * every expression. The init is only needed when the accumulator
		 * is read before being overwritten (e.g. for unary minus).
		 * We drop it when a later plain assignment writes the same
		 * register, and flush it when someone reads from it. */
		if (type == '$' && !strcmp (eq, "0") && !g_pending_zero) {
			g_pending_zero = 1;
			strncpy (g_pending_zero_reg, p, sizeof (g_pending_zero_reg) - 1);
			g_pending_zero_reg[sizeof (g_pending_zero_reg) - 1] = '\0';
			return;
		}
		if (g_pending_zero) {
			if (eq && !strcmp (eq, g_pending_zero_reg)) {
				/* reads pending reg: we must emit the init first */
				flush_pending_zero (egg);
			} else if (!strcmp (p, g_pending_zero_reg)) {
				/* overwrites pending reg: drop the dead init */
				g_pending_zero = 0;
			}
		}
		/* plain assignment: eq -> p (or *eq -> p if type == '*') */
		if (type == '*') {
			int width = (vs == 'b') ? 1 : (vs == 'q' ? 8 : 4);
			r_egg_printf (egg, "%s,[%d],%s,:=,", eq, width, p);
		} else {
			r_egg_printf (egg, "%s,%s,:=,", eq, p);
		}
	} else {
		/* compound assignment reads and writes p; it may also read eq */
		if (g_pending_zero) {
			if (!strcmp (p, g_pending_zero_reg)
			    || (eq && !strcmp (eq, g_pending_zero_reg))) {
				flush_pending_zero (egg);
			}
		}
		/* compound assignment: p = p <op> eq */
		r_egg_printf (egg, "%s,%s,%s,", eq, p, op);
	}
}

static const char *emit_regs(REgg *egg, int idx) {
	return regs[idx % R_NGP];
}

static void emit_get_arg(REgg *egg, char *out, int idx) {
	snprintf (out, 32, "a%d", idx);
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
