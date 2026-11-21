/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_asm.h>
#include "lua53.h"

static const char *pseudo_rules[] = {
	"move/2/r$1 = r$2",
	"loadk/2/r$1 = $2",
	"loadkx/2/r$1 = $2",
	"getupval/2/r$1 = upvalue[$2]",
	"gettabup/3/r$1 = upvalue[$2][$3]",
	"gettable/3/r$1 = r$2[$3]",
	"settabup/3/upvalue[$1][$2] = $3",
	"setupval/2/upvalue[$2] = r$1",
	"settable/3/r$1[$2] = $3",
	"newtable/3/r$1 = {}",
	"add/3/r$1 = $2 + $3",
	"sub/3/r$1 = $2 - $3",
	"mul/3/r$1 = $2 * $3",
	"mod/3/r$1 = $2 % $3",
	"pow/3/r$1 = $2 ** $3",
	"div/3/r$1 = $2 / $3",
	"idiv/3/r$1 = floor_div($2, $3)",
	"band/3/r$1 = $2 & $3",
	"bor/3/r$1 = $2 | $3",
	"bxor/3/r$1 = $2 ^ $3",
	"shl/3/r$1 = $2 << $3",
	"shr/3/r$1 = $2 >> $3",
	"unm/2/r$1 = -r$2",
	"bnot/2/r$1 = ~r$2",
	"not/2/r$1 = !truthy(r$2)",
	"len/2/r$1 = length(r$2)",
	"concat/3/r$1 = concat(r$2..r$3)",
	"closure/2/r$1 = closure($2)",
	NULL
};

static bool operand(const char *s, int *value, char *expr, size_t size) {
	const char *prefix = "r";
	bool wrapped = false;
	if (r_str_startswith (s, "K(") || r_str_startswith (s, "Kst(") || r_str_startswith (s, "KPROTO(")) {
		prefix = r_str_startswith (s, "KPROTO(")? "proto[": "K[";
		s = strchr (s, '(') + 1;
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
	const int expected = op == OP_SETLIST && argc == 4? 4: lua53_nargs (op);
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
	const bool relative = op == OP_JMP || op == OP_FORLOOP || op == OP_FORPREP || op == OP_TFORLOOP;
	const int maxb = relative? MAXARG_sBx + 1: op == OP_LOADKX? MAXARG_Ax: op == OP_LOADK || op == OP_CLOSURE? MAXARG_Bx: MAXARG_B;
	if (a < 0 || a > MAXARG_A || b < (relative? -MAXARG_sBx: 0) || b > maxb || c < 0 || c > MAXARG_C) {
		return NULL;
	}
	const ut64 pc = aps->rasm->pc;
	const ut64 target = pc + 4 + (st64)b * 4;
	const char *rb = expr[1], *rc = expr[2];
	switch (op) {
	case OP_LOADBOOL:
		return c? r_str_newf ("r%d = %s\ngoto 0x%08"PFMT64x, a, b? "true": "false", pc + 8)
			: r_str_newf ("r%d = %s", a, b? "true": "false");
	case OP_LOADNIL: {
		char *list = reglist (a, b + 1);
		char *s = r_str_newf ("%s = nil", list);
		free (list);
		return s;
	}
	case OP_SELF:
		return r_str_newf ("r%d = r%d; r%d = r%d[%s]", a + 1, b, a, b, rc);
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
		char *list = reglist (a + 3, b);
		char *s = b? r_str_newf ("%s = r%d(r%d, r%d)", list, a, a + 1, a + 2)
			: r_str_newf ("r%d(r%d, r%d)", a, a + 1, a + 2);
		free (list);
		return s;
	}
	case OP_TFORLOOP:
		return r_str_newf ("if (r%d != nil && ((r%d = r%d), true)) goto 0x%08"PFMT64x, a + 1, a, a + 1, target);
	case OP_SETLIST: {
		const int block = c? c: values[3];
		if (block < 1 || (argc == 4 && c)) {
			return NULL;
		}
		char *list = reglist (a + 1, b? b: -1);
		char *s = r_str_newf ("setlist(r%d, %"PFMT64u", %s)", a, (ut64)(block - 1) * 50 + 1, list);
		free (list);
		return s;
	}
	case OP_EXTRAARG:
		return NULL;
	}
	RStrBuf *input = r_strbuf_new (name);
	for (i = 0; i < argc; i++) {
		bool rk = (i == 1 && lua53_rkb (op)) || (i == 2 && lua53_rkc (op));
		r_strbuf_appendf (input, "%s%s", i? ", ": " ", rk || args[i][0] == 'K'? expr[i]: args[i]);
	}
	char *result = r_str_pseudo_transform (pseudo_rules, r_strbuf_get (input));
	r_strbuf_free (input);
	return result;
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
