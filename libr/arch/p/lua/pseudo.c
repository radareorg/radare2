/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_asm.h>
#include "lua53.h"
#include "lua_bc.h"

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

static char *call_expr(int a, int b, int c, bool tail) {
	char *args = reglist (a + 1, b? b - 1: -1);
	char *results = reglist (a, c? c - 1: -1);
	char *s = tail? r_str_newf ("return r%d(%s)", a, args)
		: c == 1? r_str_newf ("r%d(%s)", a, args)
		: r_str_newf ("%s = r%d(%s)", results, a, args);
	free (args);
	free (results);
	return s;
}

static char *values_expr(int a, int count, bool ret) {
	char *list = reglist (a, count);
	char *s = ret? r_str_newf ("return%s%s", *list? " ": "", list)
		: !count? strdup ("nop"): r_str_newf ("%s = ...", list);
	free (list);
	return s;
}

static char *parse_bc(RAsmPluginSession *aps, const LuaBCVersion *v, const char *data) {
	ut32 words[2] = {0};
	int size;
	if (!lua_bc_assemble (v, data, words, &size)) {
		return NULL;
	}
	const ut32 word = words[0], next = words[1];
	const int op = lua_bc_id (v, word);
	const int a = lua_bc_get (word, LUA_ARG_A), b = lua_bc_get (word, LUA_ARG_B), c = lua_bc_get (word, LUA_ARG_C);
	const int k = lua_bc_get (word, LUA_ARG_K), bx = lua_bc_get (word, LUA_ARG_BX);
	const ut64 pc = aps->rasm->pc, forward = pc + 4 + (ut64)bx * 4, backward = pc + 4 - (ut64)bx * 4;
	const bool pair = size == 8 && lua_bc_pair (v, word, next);
	char expr[4][32] = {{0}};
	const ut8 *args = lua_bc_args (v, op);
	int i;
	for (i = 0; i < 4 && args[i]; i++) {
		const int kind = args[i], n = lua_bc_get (kind == LUA_ARG_KAX? next: word, kind);
		const LuaBCField *f = &lua_bc_fields[kind];
		const bool constant = f->wrap && (kind != LUA_ARG_RKC || k);
		snprintf (expr[i], sizeof (expr[i]), constant? (kind == LUA_ARG_PBX? "proto[%d]": "K[%d]"): f->reg? "r%d": "%d", n);
	}
	const char *alias = lua_bc_ops[op].alias;
	if (pair && op >= LUA_OP_ADDI && op <= LUA_OP_SHR) {
		const int mm = lua_bc_id (v, next), event = lua_bc_get (next, LUA_ARG_C);
		alias = lua_bc_ops[LUA_OP_ADD + event - 6].alias;
		snprintf (expr[1], sizeof (expr[1]), "r%d", lua_bc_get (next, LUA_ARG_A));
		snprintf (expr[2], sizeof (expr[2]), mm == LUA_OP_MMBIN? "r%d": mm == LUA_OP_MMBINK? "K[%d]": "%d",
			lua_bc_get (next, mm == LUA_OP_MMBINI? LUA_ARG_SB: LUA_ARG_B));
		if (mm != LUA_OP_MMBIN && lua_bc_get (next, LUA_ARG_K)) {
			char temp[32];
			memcpy (temp, expr[1], sizeof (temp));
			memcpy (expr[1], expr[2], sizeof (temp));
			memcpy (expr[2], temp, sizeof (temp));
		}
		i = 3;
	}
	char *result = NULL;
	switch (op) {
	case LUA_OP_LOADI: case LUA_OP_LOADF:
		return r_str_newf ("r%d = %d%s", a, lua_bc_get (word, LUA_ARG_SBX), op == LUA_OP_LOADF? ".0": "");
	case LUA_OP_LOADFALSE: case LUA_OP_LOADTRUE:
		return r_str_newf ("r%d = %s", a, op == LUA_OP_LOADTRUE? "true": "false");
	case LUA_OP_LFALSESKIP:
		return r_str_newf ("r%d = false\ngoto 0x%08"PFMT64x, a, pc + 8);
	case LUA_OP_LOADNIL: {
		char *list = reglist (a, b + 1);
		result = r_str_newf ("%s = nil", list);
		free (list);
		return result;
	}
	case LUA_OP_SELF:
		return r_str_newf ("r%d = r%d; r%d = r%d[%s]", a + 1, b, a, b, expr[2]);
	case LUA_OP_SHLI:
		if (!pair) {
			return r_str_newf ("r%d = %d << r%d", a, lua_bc_get (word, LUA_ARG_SC), b);
		}
		break;
	case LUA_OP_CONCAT:
		return r_str_newf ("r%d = concat(r%d..r%d)", a, a, a + b - 1);
	case LUA_OP_CLOSE: case LUA_OP_TBC:
		return r_str_newf ("%s(r%d)", op == LUA_OP_CLOSE? "close_upvalues": "to_be_closed", a);
	case LUA_OP_JMP:
		return r_str_newf ("goto 0x%08"PFMT64x, pc + 4 + (st64)lua_bc_get (word, LUA_ARG_SJ) * 4);
	case LUA_OP_EQ: case LUA_OP_LT: case LUA_OP_LE:
	case LUA_OP_EQK: case LUA_OP_EQI: case LUA_OP_LTI: case LUA_OP_LEI: case LUA_OP_GTI: case LUA_OP_GEI: {
		const char *cmp = op == LUA_OP_LT || op == LUA_OP_LTI? "<": op == LUA_OP_LE || op == LUA_OP_LEI? "<=": op == LUA_OP_GTI? ">": op == LUA_OP_GEI? ">=": "==";
		char rhs[32];
		snprintf (rhs, sizeof (rhs), op <= LUA_OP_LE? "r%d": op == LUA_OP_EQK? "K[%d]": c? "%d.0": "%d", op <= LUA_OP_EQK? b: lua_bc_get (word, LUA_ARG_SB));
		return r_str_newf ("if (%s(r%d %s %s)) goto 0x%08"PFMT64x, k? "!": "", a, cmp, rhs, pc + 8);
	}
	case LUA_OP_TEST:
		return r_str_newf ("if (%struthy(r%d)) goto 0x%08"PFMT64x, k? "!": "", a, pc + 8);
	case LUA_OP_TESTSET:
		return r_str_newf ("if ((truthy(r%d) != %s) || ((r%d = r%d), false)) goto 0x%08"PFMT64x, b, k? "true": "false", a, b, pc + 8);
	case LUA_OP_CALL: case LUA_OP_TAILCALL:
		result = call_expr (a, b, c, op == LUA_OP_TAILCALL);
		break;
	case LUA_OP_RETURN: case LUA_OP_RETURN0: case LUA_OP_RETURN1:
		result = values_expr (a, op == LUA_OP_RETURN0? 0: op == LUA_OP_RETURN1? 1: b? b - 1: -1, true);
		break;
	case LUA_OP_VARARG:
		return values_expr (a, c? c - 1: -1, false);
	case LUA_OP_VARARGPREP:
		return r_str_newf ("prepare_varargs(%d)", a);
	case LUA_OP_FORPREP:
		return r_str_newf ("if (for_prepare(&r%d, &r%d, &r%d, &r%d)) goto 0x%08"PFMT64x, a, a + 1, a + 2, a + 3, forward + 4);
	case LUA_OP_FORLOOP:
		return r_str_newf ("if (for_next(&r%d, &r%d, r%d, &r%d)) goto 0x%08"PFMT64x, a, a + 1, a + 2, a + 3, backward);
	case LUA_OP_TFORPREP:
		return r_str_newf ("to_be_closed(r%d)\ngoto 0x%08"PFMT64x, a + 3, forward);
	case LUA_OP_TFORCALL: {
		char *list = reglist (a + 4, c);
		result = r_str_newf ("%s%s r%d(r%d, r%d)", list, c? " =": "", a, a + 1, a + 2);
		free (list);
		return result;
	}
	case LUA_OP_TFORLOOP:
		return r_str_newf ("if (r%d != nil && ((r%d = r%d), true)) goto 0x%08"PFMT64x, a + 4, a + 2, a + 4, backward);
	case LUA_OP_SETLIST: {
		if (k && !pair) {
			return NULL;
		}
		char *list = reglist (a + 1, b? b: -1);
		result = r_str_newf ("setlist(r%d, %"PFMT64u", %s)", a, (ut64)c + (k? (ut64)lua_bc_get (next, LUA_ARG_AX) * 256: 0) + 1, list);
		free (list);
		return result;
	}
	case LUA_OP_NEWTABLE:
		return r_str_newf ("r%d = {}", a);
	case LUA_OP_LOADKX:
		if (!pair) {
			return NULL;
		}
		break;
	case LUA_OP_MMBIN: case LUA_OP_MMBINI: case LUA_OP_MMBINK:
		return r_str_newf ("metamethod(%d, r%d, %s%d%s, %d)", c, a, op == LUA_OP_MMBIN? "r": op == LUA_OP_MMBINK? "K[": "", op == LUA_OP_MMBINI? lua_bc_get (word, LUA_ARG_SB): b, op == LUA_OP_MMBINK? "]": "", k);
	case LUA_OP_EXTRAARG:
		return NULL;
	default:
		break;
	}
	if (result) {
		if (k && (op == LUA_OP_RETURN || op == LUA_OP_TAILCALL)) {
			char *closed = r_str_newf ("close_upvalues(r0)\n%s", result);
			free (result);
			return closed;
		}
		return result;
	}
	if (!alias) {
		return NULL;
	}
	RStrBuf *input = r_strbuf_new (alias);
	int n;
	for (n = 0; n < i; n++) {
		r_strbuf_appendf (input, "%s%s", n? ", ": " ", expr[n]);
	}
	result = r_str_pseudo_transform (pseudo_rules, r_strbuf_get (input));
	r_strbuf_free (input);
	return result;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	const LuaBCVersion *v = lua_bc_version (aps->rasm->config->cpu);
	if (v) {
		return parse_bc (aps, v, data);
	}
	if (!lua_bc_is53 (aps->rasm->config->cpu)) {
		return NULL;
	}
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
	case OP_TAILCALL:
		return call_expr (a, b, c, op == OP_TAILCALL);
	case OP_RETURN:
	case OP_VARARG:
		return values_expr (a, b? b - 1: -1, op == OP_RETURN);
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
		.desc = "Lua 5.3 and 5.4 pseudo syntax",
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
