/* radare2 - LGPL-3.0-only - Copyright 2026 - pancake */

#ifndef R_LUA_BC_H
#define R_LUA_BC_H

#include <errno.h>

typedef enum {
	LUA_OP_MOVE,
	LUA_OP_LOADI,
	LUA_OP_LOADF,
	LUA_OP_LOADK,
	LUA_OP_LOADKX,
	LUA_OP_LOADFALSE,
	LUA_OP_LFALSESKIP,
	LUA_OP_LOADTRUE,
	LUA_OP_LOADNIL,
	LUA_OP_GETUPVAL,
	LUA_OP_SETUPVAL,
	LUA_OP_GETTABUP,
	LUA_OP_GETTABLE,
	LUA_OP_GETI,
	LUA_OP_GETFIELD,
	LUA_OP_SETTABUP,
	LUA_OP_SETTABLE,
	LUA_OP_SETI,
	LUA_OP_SETFIELD,
	LUA_OP_NEWTABLE,
	LUA_OP_SELF,
	LUA_OP_ADDI,
	LUA_OP_ADDK,
	LUA_OP_SUBK,
	LUA_OP_MULK,
	LUA_OP_MODK,
	LUA_OP_POWK,
	LUA_OP_DIVK,
	LUA_OP_IDIVK,
	LUA_OP_BANDK,
	LUA_OP_BORK,
	LUA_OP_BXORK,
	LUA_OP_SHRI,
	LUA_OP_SHLI,
	LUA_OP_ADD,
	LUA_OP_SUB,
	LUA_OP_MUL,
	LUA_OP_MOD,
	LUA_OP_POW,
	LUA_OP_DIV,
	LUA_OP_IDIV,
	LUA_OP_BAND,
	LUA_OP_BOR,
	LUA_OP_BXOR,
	LUA_OP_SHL,
	LUA_OP_SHR,
	LUA_OP_MMBIN,
	LUA_OP_MMBINI,
	LUA_OP_MMBINK,
	LUA_OP_UNM,
	LUA_OP_BNOT,
	LUA_OP_NOT,
	LUA_OP_LEN,
	LUA_OP_CONCAT,
	LUA_OP_CLOSE,
	LUA_OP_TBC,
	LUA_OP_JMP,
	LUA_OP_EQ,
	LUA_OP_LT,
	LUA_OP_LE,
	LUA_OP_EQK,
	LUA_OP_EQI,
	LUA_OP_LTI,
	LUA_OP_LEI,
	LUA_OP_GTI,
	LUA_OP_GEI,
	LUA_OP_TEST,
	LUA_OP_TESTSET,
	LUA_OP_CALL,
	LUA_OP_TAILCALL,
	LUA_OP_RETURN,
	LUA_OP_RETURN0,
	LUA_OP_RETURN1,
	LUA_OP_FORLOOP,
	LUA_OP_FORPREP,
	LUA_OP_TFORPREP,
	LUA_OP_TFORCALL,
	LUA_OP_TFORLOOP,
	LUA_OP_SETLIST,
	LUA_OP_CLOSURE,
	LUA_OP_VARARG,
	LUA_OP_VARARGPREP,
	LUA_OP_EXTRAARG,
	LUA_OP_GETVARG,
	LUA_OP_ERRNNIL,
	LUA_OP_COUNT
} LuaBCOpcode;

typedef enum {
	LUA_ARG_NONE,
	LUA_ARG_A,
	LUA_ARG_B,
	LUA_ARG_C,
	LUA_ARG_K,
	LUA_ARG_BX,
	LUA_ARG_SBX,
	LUA_ARG_AX,
	LUA_ARG_SJ,
	LUA_ARG_SB,
	LUA_ARG_SC,
	LUA_ARG_KB,
	LUA_ARG_KC,
	LUA_ARG_RKC,
	LUA_ARG_KBX,
	LUA_ARG_KAX,
	LUA_ARG_PBX,
	LUA_ARG_RB,
	LUA_ARG_RC,
	LUA_ARG_VB,
	LUA_ARG_VC,
} LuaBCArg;

typedef struct {
	ut8 shift, bits;
	int bias;
	const char *wrap;
	bool reg;
} LuaBCField;

static const LuaBCField lua_bc_fields[] = {
	{ 0, 0, 0, NULL, false },
	{ 7, 8, 0, NULL, false },
	{ 16, 8, 0, NULL, false },
	{ 24, 8, 0, NULL, false },
	{ 15, 1, 0, NULL, false },
	{ 15, 17, 0, NULL, false },
	{ 15, 17, 65535, NULL, false },
	{ 7, 25, 0, NULL, false },
	{ 7, 25, 16777215, NULL, false },
	{ 16, 8, 127, NULL, false },
	{ 24, 8, 127, NULL, false },
	{ 16, 8, 0, "K(", false },
	{ 24, 8, 0, "K(", false },
	{ 24, 8, 0, "K(", true },
	{ 15, 17, 0, "Kst(", false },
	{ 7, 25, 0, "Kst(", false },
	{ 15, 17, 0, "KPROTO(", false },
	{ 16, 8, 0, NULL, true },
	{ 24, 8, 0, NULL, true },
	{ 16, 6, 0, NULL, false },
	{ 22, 10, 0, NULL, false },
};

typedef struct {
	const char *name;
	ut32 type;
	const char *alias;
	ut8 args[4];
} LuaBCOp;

static const LuaBCOp lua_bc_ops[] = {
	{ "move", R_ANAL_OP_TYPE_MOV, "move", { LUA_ARG_A, LUA_ARG_B } },
	{ "loadi", R_ANAL_OP_TYPE_MOV, NULL, { LUA_ARG_A, LUA_ARG_SBX } },
	{ "loadf", R_ANAL_OP_TYPE_MOV, NULL, { LUA_ARG_A, LUA_ARG_SBX } },
	{ "loadk", R_ANAL_OP_TYPE_LOAD, "loadk", { LUA_ARG_A, LUA_ARG_KBX } },
	{ "loadkx", R_ANAL_OP_TYPE_LOAD, "loadkx", { LUA_ARG_A, LUA_ARG_KAX } },
	{ "loadfalse", R_ANAL_OP_TYPE_MOV, NULL, { LUA_ARG_A } },
	{ "lfalseskip", R_ANAL_OP_TYPE_JMP, NULL, { LUA_ARG_A } },
	{ "loadtrue", R_ANAL_OP_TYPE_MOV, NULL, { LUA_ARG_A } },
	{ "loadnil", R_ANAL_OP_TYPE_MOV, NULL, { LUA_ARG_A, LUA_ARG_B } },
	{ "getupval", R_ANAL_OP_TYPE_LOAD, "getupval", { LUA_ARG_A, LUA_ARG_B } },
	{ "setupval", R_ANAL_OP_TYPE_STORE, "setupval", { LUA_ARG_A, LUA_ARG_B } },
	{ "gettabup", R_ANAL_OP_TYPE_LOAD, "gettabup", { LUA_ARG_A, LUA_ARG_B, LUA_ARG_KC } },
	{ "gettable", R_ANAL_OP_TYPE_LOAD, "gettable", { LUA_ARG_A, LUA_ARG_B, LUA_ARG_RC } },
	{ "geti", R_ANAL_OP_TYPE_LOAD, "gettable", { LUA_ARG_A, LUA_ARG_B, LUA_ARG_C } },
	{ "getfield", R_ANAL_OP_TYPE_LOAD, "gettable", { LUA_ARG_A, LUA_ARG_B, LUA_ARG_KC } },
	{ "settabup", R_ANAL_OP_TYPE_STORE, "settabup", { LUA_ARG_A, LUA_ARG_KB, LUA_ARG_RKC } },
	{ "settable", R_ANAL_OP_TYPE_STORE, "settable", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RKC } },
	{ "seti", R_ANAL_OP_TYPE_STORE, "settable", { LUA_ARG_A, LUA_ARG_B, LUA_ARG_RKC } },
	{ "setfield", R_ANAL_OP_TYPE_STORE, "settable", { LUA_ARG_A, LUA_ARG_KB, LUA_ARG_RKC } },
	{ "newtable", R_ANAL_OP_TYPE_NEW, "newtable", { LUA_ARG_A, LUA_ARG_B, LUA_ARG_C, LUA_ARG_K } },
	{ "self", R_ANAL_OP_TYPE_LOAD, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_RKC } },
	{ "addi", R_ANAL_OP_TYPE_ADD, "add", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_SC } },
	{ "addk", R_ANAL_OP_TYPE_ADD, "add", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "subk", R_ANAL_OP_TYPE_SUB, "sub", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "mulk", R_ANAL_OP_TYPE_MUL, "mul", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "modk", R_ANAL_OP_TYPE_MOD, "mod", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "powk", R_ANAL_OP_TYPE_UNK, "pow", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "divk", R_ANAL_OP_TYPE_DIV, "div", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "idivk", R_ANAL_OP_TYPE_DIV, "idiv", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "bandk", R_ANAL_OP_TYPE_AND, "band", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "bork", R_ANAL_OP_TYPE_OR, "bor", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "bxork", R_ANAL_OP_TYPE_XOR, "bxor", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_KC } },
	{ "shri", R_ANAL_OP_TYPE_SHR, "shr", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_SC } },
	{ "shli", R_ANAL_OP_TYPE_SHL, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_SC } },
	{ "add", R_ANAL_OP_TYPE_ADD, "add", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "sub", R_ANAL_OP_TYPE_SUB, "sub", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "mul", R_ANAL_OP_TYPE_MUL, "mul", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "mod", R_ANAL_OP_TYPE_MOD, "mod", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "pow", R_ANAL_OP_TYPE_UNK, "pow", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "div", R_ANAL_OP_TYPE_DIV, "div", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "idiv", R_ANAL_OP_TYPE_DIV, "idiv", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "band", R_ANAL_OP_TYPE_AND, "band", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "bor", R_ANAL_OP_TYPE_OR, "bor", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "bxor", R_ANAL_OP_TYPE_XOR, "bxor", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "shl", R_ANAL_OP_TYPE_SHL, "shl", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "shr", R_ANAL_OP_TYPE_SHR, "shr", { LUA_ARG_A, LUA_ARG_RB, LUA_ARG_RC } },
	{ "mmbin", R_ANAL_OP_TYPE_RCALL, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_C } },
	{ "mmbini", R_ANAL_OP_TYPE_RCALL, NULL, { LUA_ARG_A, LUA_ARG_SB, LUA_ARG_C, LUA_ARG_K } },
	{ "mmbink", R_ANAL_OP_TYPE_RCALL, NULL, { LUA_ARG_A, LUA_ARG_KB, LUA_ARG_C, LUA_ARG_K } },
	{ "unm", R_ANAL_OP_TYPE_UNK, "unm", { LUA_ARG_A, LUA_ARG_B } },
	{ "bnot", R_ANAL_OP_TYPE_CPL, "bnot", { LUA_ARG_A, LUA_ARG_B } },
	{ "not", R_ANAL_OP_TYPE_NOT, "not", { LUA_ARG_A, LUA_ARG_B } },
	{ "len", R_ANAL_OP_TYPE_UNK, "len", { LUA_ARG_A, LUA_ARG_B } },
	{ "concat", R_ANAL_OP_TYPE_UNK, NULL, { LUA_ARG_A, LUA_ARG_B } },
	{ "close", R_ANAL_OP_TYPE_UNK, NULL, { LUA_ARG_A } },
	{ "tbc", R_ANAL_OP_TYPE_UNK, NULL, { LUA_ARG_A } },
	{ "jmp", R_ANAL_OP_TYPE_JMP, NULL, { LUA_ARG_SJ } },
	{ "eq", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_K } },
	{ "lt", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_K } },
	{ "le", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_K } },
	{ "eqk", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_KB, LUA_ARG_K } },
	{ "eqi", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_SB, LUA_ARG_C, LUA_ARG_K } },
	{ "lti", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_SB, LUA_ARG_C, LUA_ARG_K } },
	{ "lei", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_SB, LUA_ARG_C, LUA_ARG_K } },
	{ "gti", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_SB, LUA_ARG_C, LUA_ARG_K } },
	{ "gei", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_SB, LUA_ARG_C, LUA_ARG_K } },
	{ "test", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_K } },
	{ "testset", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_K } },
	{ "call", R_ANAL_OP_TYPE_RCALL, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_C } },
	{ "tailcall", R_ANAL_OP_TYPE_RET, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_C, LUA_ARG_K } },
	{ "return", R_ANAL_OP_TYPE_RET, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_C, LUA_ARG_K } },
	{ "return0", R_ANAL_OP_TYPE_RET, NULL, { 0 } },
	{ "return1", R_ANAL_OP_TYPE_RET, NULL, { LUA_ARG_A } },
	{ "forloop", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_BX } },
	{ "forprep", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_BX } },
	{ "tforprep", R_ANAL_OP_TYPE_JMP, NULL, { LUA_ARG_A, LUA_ARG_BX } },
	{ "tforcall", R_ANAL_OP_TYPE_RCALL, NULL, { LUA_ARG_A, LUA_ARG_C } },
	{ "tforloop", R_ANAL_OP_TYPE_CJMP, NULL, { LUA_ARG_A, LUA_ARG_BX } },
	{ "setlist", R_ANAL_OP_TYPE_STORE, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_C, LUA_ARG_K } },
	{ "closure", R_ANAL_OP_TYPE_NEW, "closure", { LUA_ARG_A, LUA_ARG_PBX } },
	{ "vararg", R_ANAL_OP_TYPE_MOV, NULL, { LUA_ARG_A, LUA_ARG_C } },
	{ "varargprep", R_ANAL_OP_TYPE_UNK, NULL, { LUA_ARG_A } },
	{ "extraarg", R_ANAL_OP_TYPE_UNK, NULL, { LUA_ARG_AX } },
	{ "getvarg", R_ANAL_OP_TYPE_LOAD, NULL, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_RC } },
	{ "errnnil", R_ANAL_OP_TYPE_UNK, NULL, { LUA_ARG_A, LUA_ARG_BX } },
};

typedef struct {
	bool present;
	ut8 args[4];
} LuaBCArgset;

typedef struct {
	const char *cpu;
	const ut8 *opcodes;
	int count;
	int extraarg;
	const LuaBCArgset *args;
} LuaBCVersion;

static const ut8 lua_bc_55_opcodes[] = {
	LUA_OP_MOVE, LUA_OP_LOADI, LUA_OP_LOADF, LUA_OP_LOADK, LUA_OP_LOADKX,
	LUA_OP_LOADFALSE, LUA_OP_LFALSESKIP, LUA_OP_LOADTRUE, LUA_OP_LOADNIL, LUA_OP_GETUPVAL,
	LUA_OP_SETUPVAL, LUA_OP_GETTABUP, LUA_OP_GETTABLE, LUA_OP_GETI, LUA_OP_GETFIELD,
	LUA_OP_SETTABUP, LUA_OP_SETTABLE, LUA_OP_SETI, LUA_OP_SETFIELD, LUA_OP_NEWTABLE,
	LUA_OP_SELF, LUA_OP_ADDI, LUA_OP_ADDK, LUA_OP_SUBK, LUA_OP_MULK,
	LUA_OP_MODK, LUA_OP_POWK, LUA_OP_DIVK, LUA_OP_IDIVK, LUA_OP_BANDK,
	LUA_OP_BORK, LUA_OP_BXORK, LUA_OP_SHLI, LUA_OP_SHRI, LUA_OP_ADD,
	LUA_OP_SUB, LUA_OP_MUL, LUA_OP_MOD, LUA_OP_POW, LUA_OP_DIV,
	LUA_OP_IDIV, LUA_OP_BAND, LUA_OP_BOR, LUA_OP_BXOR, LUA_OP_SHL,
	LUA_OP_SHR, LUA_OP_MMBIN, LUA_OP_MMBINI, LUA_OP_MMBINK, LUA_OP_UNM,
	LUA_OP_BNOT, LUA_OP_NOT, LUA_OP_LEN, LUA_OP_CONCAT, LUA_OP_CLOSE,
	LUA_OP_TBC, LUA_OP_JMP, LUA_OP_EQ, LUA_OP_LT, LUA_OP_LE,
	LUA_OP_EQK, LUA_OP_EQI, LUA_OP_LTI, LUA_OP_LEI, LUA_OP_GTI,
	LUA_OP_GEI, LUA_OP_TEST, LUA_OP_TESTSET, LUA_OP_CALL, LUA_OP_TAILCALL,
	LUA_OP_RETURN, LUA_OP_RETURN0, LUA_OP_RETURN1, LUA_OP_FORLOOP, LUA_OP_FORPREP,
	LUA_OP_TFORPREP, LUA_OP_TFORCALL, LUA_OP_TFORLOOP, LUA_OP_SETLIST, LUA_OP_CLOSURE,
	LUA_OP_VARARG, LUA_OP_GETVARG, LUA_OP_ERRNNIL, LUA_OP_VARARGPREP, LUA_OP_EXTRAARG,
};

static const LuaBCArgset lua_bc_55_args[LUA_OP_COUNT] = {
	[LUA_OP_NEWTABLE] = { true, { LUA_ARG_A, LUA_ARG_VB, LUA_ARG_VC, LUA_ARG_K } },
	[LUA_OP_SETLIST] = { true, { LUA_ARG_A, LUA_ARG_VB, LUA_ARG_VC, LUA_ARG_K } },
	[LUA_OP_SELF] = { true, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_KC } },
	[LUA_OP_VARARG] = { true, { LUA_ARG_A, LUA_ARG_B, LUA_ARG_C, LUA_ARG_K } },
	[LUA_OP_VARARGPREP] = { true, { 0 } },
};

static const LuaBCVersion lua_bc_54 = { "5.4", NULL, LUA_OP_EXTRAARG + 1, LUA_OP_EXTRAARG, NULL };

static const LuaBCVersion lua_bc_55 = { "5.5", lua_bc_55_opcodes, R_ARRAY_SIZE (lua_bc_55_opcodes), 84, lua_bc_55_args };

static inline const LuaBCVersion *lua_bc_version(const char *cpu) {
	return cpu && !strcmp (cpu, "5.5")? &lua_bc_55: cpu && !strcmp (cpu, "5.4")? &lua_bc_54: NULL;
}

static inline bool lua_bc_is53(const char *cpu) {
	return !cpu || !*cpu || !strcmp (cpu, "5.3");
}

static inline int lua_bc_id(const LuaBCVersion *v, ut32 word) {
	const int code = word & 0x7f;
	return code < v->count? (v->opcodes? v->opcodes[code]: code): LUA_OP_COUNT;
}

static inline const ut8 *lua_bc_args(const LuaBCVersion *v, int id) {
	return v->args && v->args[id].present? v->args[id].args: lua_bc_ops[id].args;
}

static inline int lua_bc_get(ut32 word, int arg) {
	const LuaBCField *f = &lua_bc_fields[arg];
	return (int)((word >> f->shift) & ((1U << f->bits) - 1)) - f->bias;
}

static inline bool lua_bc_parse_word(const LuaBCVersion *v, char *text, ut32 words[2], int *size) {
	char *save = NULL;
	const char *name = r_str_tok_r (text, " \t,", &save);
	if (!name) {
		return false;
	}
	int code;
	for (code = 0; code < v->count; code++) {
		const int id = v->opcodes? v->opcodes[code]: code;
		if (!r_str_casecmp (name, lua_bc_ops[id].name)) {
			break;
		}
	}
	if (code == v->count) {
		return false;
	}
	words[0] = code;
	*size = 4;
	const int id = lua_bc_id (v, words[0]);
	const ut8 *args = lua_bc_args (v, id);
	int i;
	for (i = 0; i < 4 && args[i]; i++) {
		const int kind = args[i];
		const LuaBCField *f = &lua_bc_fields[kind];
		const char *s = r_str_tok_r (NULL, " \t,", &save);
		if (!s) {
			if (kind == LUA_ARG_KAX) {
				break;
			}
			return false;
		}
		const bool wrapped = f->wrap && !r_str_ncasecmp (s, f->wrap, strlen (f->wrap));
		if (wrapped) {
			s += strlen (f->wrap);
		}
		char *end;
		errno = 0;
		st64 n = strtoll (s, &end, 0);
		if (errno || end == s || (wrapped? strcmp (end, ")"): *end != 0)) {
			return false;
		}
		if (n < -f->bias || n > (st64)((1U << f->bits) - 1) - f->bias) {
			return false;
		}
		const st64 encoded = n + f->bias;
		ut32 *word = words;
		if (kind == LUA_ARG_KAX) {
			words[1] = v->extraarg;
			word++;
			*size = 8;
		}
		*word |= (ut32)encoded << f->shift;
		if (kind == LUA_ARG_RKC && wrapped) {
			words[0] |= 1U << 15;
		}
	}
	return !r_str_tok_r (NULL, " \t,", &save);
}

static inline bool lua_bc_assemble(const LuaBCVersion *v, const char *text, ut32 words[2], int *size) {
	char *copy = strdup (text);
	if (!copy) {
		return false;
	}
	char *tail = strchr (copy, ';');
	if (tail) {
		*tail++ = 0;
	}
	bool ok = lua_bc_parse_word (v, copy, words, size);
	if (ok && tail) {
		ut32 next[2];
		int n;
		ok = *size == 4 && lua_bc_parse_word (v, tail, next, &n) && n == 4;
		if (ok) {
			words[1] = next[0];
			*size = 8;
		}
	}
	free (copy);
	return ok;
}

static inline char *lua_bc_disasm_word(const LuaBCVersion *v, ut32 word, ut32 extra, bool pair) {
	const int id = lua_bc_id (v, word);
	RStrBuf *s = r_strbuf_new (lua_bc_ops[id].name);
	const ut8 *args = lua_bc_args (v, id);
	int i;
	for (i = 0; i < 4 && args[i]; i++) {
		const int kind = args[i];
		if (kind == LUA_ARG_KAX && !pair) {
			break;
		}
		const char *wrap = lua_bc_fields[kind].wrap;
		if (kind == LUA_ARG_RKC && !lua_bc_get (word, LUA_ARG_K)) {
			wrap = NULL;
		}
		r_strbuf_appendf (s, " %s%d%s", wrap? wrap: "", lua_bc_get (kind == LUA_ARG_KAX? extra: word, kind), wrap? ")": "");
	}
	return r_strbuf_drain (s);
}

static inline bool lua_bc_pair(const LuaBCVersion *v, ut32 word, ut32 next) {
	const int id = lua_bc_id (v, word), mm = lua_bc_id (v, next);
	if (id == LUA_OP_LOADKX || id == LUA_OP_NEWTABLE || (id == LUA_OP_SETLIST && lua_bc_get (word, LUA_ARG_K))) {
		return mm == LUA_OP_EXTRAARG;
	}
	if (lua_bc_get (word, LUA_ARG_B) != lua_bc_get (next, LUA_ARG_A)) {
		return false;
	}
	const int event = lua_bc_get (next, LUA_ARG_C);
	if (id >= LUA_OP_ADD && id <= LUA_OP_SHR) {
		return mm == LUA_OP_MMBIN && event == 6 + id - LUA_OP_ADD
			&& lua_bc_get (word, LUA_ARG_C) == lua_bc_get (next, LUA_ARG_B);
	}
	if (id >= LUA_OP_ADDK && id <= LUA_OP_BXORK) {
		return mm == LUA_OP_MMBINK && event == 6 + id - LUA_OP_ADDK
			&& lua_bc_get (word, LUA_ARG_C) == lua_bc_get (next, LUA_ARG_B);
	}
	if (mm != LUA_OP_MMBINI) {
		return false;
	}
	const int imm = lua_bc_get (word, LUA_ARG_SC), original = lua_bc_get (next, LUA_ARG_SB);
	const bool flip = lua_bc_get (next, LUA_ARG_K);
	return (id == LUA_OP_ADDI && ((event == 6 && imm == original) || (event == 7 && imm == -original && !flip)))
		|| (id == LUA_OP_SHRI && !flip && ((event == 17 && imm == original) || (event == 16 && imm == -original)))
		|| (id == LUA_OP_SHLI && event == 16 && flip && imm == original);
}

#endif
