/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_asm.h>
#include "lua53.h"

static bool operand(const char *s, int *value, char *expr, size_t size) {
	const char *prefix = "r";
	bool wrapped = false;
	if (r_str_startswith (s, "K(")) {
		s += 2;
		prefix = "K[";
		wrapped = true;
	} else if (r_str_startswith (s, "Kst(")) {
		s += 4;
		prefix = "K[";
		wrapped = true;
	} else if (r_str_startswith (s, "KPROTO(")) {
		s += 7;
		prefix = "proto[";
		wrapped = true;
	}
	char *end;
	long n = strtol (s, &end, 10);
	if (s == end || n < -MAXARG_Ax || n > MAXARG_Ax || (wrapped? strcmp (end, ")"): *end != 0)) {
		return false;
	}
	*value = n;
	snprintf (expr, size, "%s%d%s", prefix, *value, wrapped? "]": "");
	return true;
}

static char *reglist(int first, int count) {
	RStrBuf *s = r_strbuf_new ("");
	if (count < 0) {
		r_strbuf_appendf (s, "r%d..top", first);
	} else {
		int i;
		for (i = 0; i < count; i++) {
			r_strbuf_appendf (s, "%sr%d", i? ", ": "", first + i);
		}
	}
	return r_strbuf_drain (s);
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	char name[32], args[4][32], extra;
	int argc = sscanf (data, "%31s %31s %31s %31s %31s %c", name, args[0], args[1], args[2], args[3], &extra) - 1;
	if (argc < 1 || argc > 4) {
		return NULL;
	}
	int op;
	for (op = 0; instruction_names[op]; op++) {
		if (!strcmp (name, instruction_names[op])) {
			break;
		}
	}
	if (!instruction_names[op]) {
		return NULL;
	}
	int expected = op == OP_SETLIST && argc == 4? 4: 3;
	switch (op) {
	case OP_MOVE: case OP_LOADK: case OP_LOADKX: case OP_LOADNIL:
	case OP_GETUPVAL: case OP_SETUPVAL: case OP_UNM: case OP_BNOT:
	case OP_NOT: case OP_LEN: case OP_JMP: case OP_TEST: case OP_RETURN:
	case OP_FORLOOP: case OP_FORPREP: case OP_TFORCALL: case OP_TFORLOOP:
	case OP_CLOSURE: case OP_VARARG:
		expected = 2;
		break;
	case OP_EXTRAARG:
		expected = 1;
		break;
	}
	if (argc != expected) {
		return NULL;
	}
	int values[4] = {0};
	char expr[4][32];
	int i;
	for (i = 0; i < argc; i++) {
		if (!operand (args[i], &values[i], expr[i], sizeof (expr[i]))) {
			return NULL;
		}
	}
	const int a = values[0], b = values[1], c = values[2];
	if (a < 0 || a > MAXARG_A || b < -MAXARG_sBx || b > (op == OP_LOADKX? MAXARG_Ax: MAXARG_Bx) || c < 0 || c > MAXARG_C) {
		return NULL;
	}
	if (op != OP_JMP && op != OP_FORLOOP && op != OP_FORPREP && op != OP_TFORLOOP && b < 0) {
		return NULL;
	}
	const ut64 pc = aps->rasm->pc;
	const ut64 target = pc + 4 + (st64)b * 4;
	const char *rb = expr[1], *rc = expr[2];
	switch (op) {
	case OP_MOVE:
		return r_str_newf ("r%d = r%d", a, b);
	case OP_LOADK:
	case OP_LOADKX:
		return r_str_newf ("r%d = %s", a, rb);
	case OP_LOADBOOL:
		return c? r_str_newf ("r%d = %s\ngoto 0x%08"PFMT64x, a, b? "true": "false", pc + 8)
			: r_str_newf ("r%d = %s", a, b? "true": "false");
	case OP_LOADNIL: {
		if (b > MAXARG_B) {
			return NULL;
		}
		char *list = reglist (a, b + 1);
		char *s = r_str_newf ("%s = nil", list);
		free (list);
		return s;
	}
	case OP_GETUPVAL:
		return r_str_newf ("r%d = upvalue[%d]", a, b);
	case OP_GETTABUP:
		return r_str_newf ("r%d = upvalue[%d][%s]", a, b, rc);
	case OP_GETTABLE:
		return r_str_newf ("r%d = r%d[%s]", a, b, rc);
	case OP_SETTABUP:
		return r_str_newf ("upvalue[%d][%s] = %s", a, rb, rc);
	case OP_SETUPVAL:
		return r_str_newf ("upvalue[%d] = r%d", b, a);
	case OP_SETTABLE:
		return r_str_newf ("r%d[%s] = %s", a, rb, rc);
	case OP_NEWTABLE:
		return r_str_newf ("r%d = {}", a);
	case OP_SELF:
		return r_str_newf ("r%d = r%d; r%d = r%d[%s]", a + 1, b, a, b, rc);
	case OP_ADD: case OP_SUB: case OP_MUL: case OP_MOD: case OP_POW:
	case OP_DIV: case OP_IDIV: case OP_BAND: case OP_BOR: case OP_BXOR:
	case OP_SHL: case OP_SHR: {
		static const char * const operators[] = { "+", "-", "*", "%", "**", "/", "//", "&", "|", "^", "<<", ">>" };
		return op == OP_IDIV? r_str_newf ("r%d = floor_div(%s, %s)", a, rb, rc)
			: r_str_newf ("r%d = %s %s %s", a, rb, operators[op - OP_ADD], rc);
	}
	case OP_UNM:
		return r_str_newf ("r%d = -r%d", a, b);
	case OP_BNOT:
		return r_str_newf ("r%d = ~r%d", a, b);
	case OP_NOT:
		return r_str_newf ("r%d = !truthy(r%d)", a, b);
	case OP_LEN:
		return r_str_newf ("r%d = length(r%d)", a, b);
	case OP_CONCAT:
		return r_str_newf ("r%d = concat(r%d..r%d)", a, b, c);
	case OP_JMP:
		return a? r_str_newf ("close_upvalues(r%d)\ngoto 0x%08"PFMT64x, a - 1, target)
			: r_str_newf ("goto 0x%08"PFMT64x, target);
	case OP_EQ: case OP_LT: case OP_LE: {
		static const char * const comparisons[] = { "==", "<", "<=" };
		return r_str_newf ("if (%s(%s %s %s)) goto 0x%08"PFMT64x, a? "!": "", rb, comparisons[op - OP_EQ], rc, pc + 8);
	}
	case OP_TEST:
		return r_str_newf ("if (%struthy(r%d)) goto 0x%08"PFMT64x, b? "!": "", a, pc + 8);
	case OP_TESTSET:
		return r_str_newf ("if ((truthy(r%d) != %s) || ((r%d = r%d), false)) goto 0x%08"PFMT64x, b, c? "true": "false", a, b, pc + 8);
	case OP_CALL:
	case OP_TAILCALL: {
		if (b > MAXARG_B) {
			return NULL;
		}
		char *args = reglist (a + 1, b? b - 1: -1);
		char *results = reglist (a, c? c - 1: -1);
		char *s = op == OP_TAILCALL? r_str_newf ("return r%d(%s)", a, args)
			: c == 1? r_str_newf ("r%d(%s)", a, args)
			: r_str_newf ("%s = r%d(%s)", results, a, args);
		free (args);
		free (results);
		return s;
	}
	case OP_RETURN:
	case OP_VARARG: {
		if (b > MAXARG_B) {
			return NULL;
		}
		char *list = reglist (a, b? b - 1: -1);
		char *s = op == OP_RETURN? r_str_newf ("return%s%s", *list? " ": "", list)
			: b == 1? strdup ("nop") : r_str_newf ("%s = ...", list);
		free (list);
		return s;
	}
	case OP_FORPREP:
		return r_str_newf ("r%d -= r%d\ngoto 0x%08"PFMT64x, a, a + 2, target);
	case OP_FORLOOP:
		return r_str_newf ("if (for_step(&r%d, &r%d, r%d, r%d)) goto 0x%08"PFMT64x, a, a + 3, a + 1, a + 2, target);
	case OP_TFORCALL: {
		if (b > MAXARG_C) {
			return NULL;
		}
		char *list = reglist (a + 3, b);
		char *s = r_str_newf ("%s = r%d(r%d, r%d)", list, a, a + 1, a + 2);
		free (list);
		return s;
	}
	case OP_TFORLOOP:
		return r_str_newf ("if (r%d != nil && ((r%d = r%d), true)) goto 0x%08"PFMT64x, a + 1, a, a + 1, target);
	case OP_SETLIST: {
		const int block = c? c: values[3];
		if (b > MAXARG_B || block < 1 || (argc == 4 && c)) {
			return NULL;
		}
		char *list = reglist (a + 1, b? b: -1);
		char *s = r_str_newf ("setlist(r%d, %"PFMT64u", %s)", a, (ut64)(block - 1) * 50 + 1, list);
		free (list);
		return s;
	}
	case OP_CLOSURE:
		return r_str_newf ("r%d = closure(%s)", a, rb);
	}
	return NULL;
}

RAsmPlugin r_asm_plugin_lua = {
	.meta = {
		.name = "lua",
		.desc = "Lua 5.3 pseudo syntax",
		.author = "pancake",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_lua,
	.version = R2_VERSION
};
#endif
