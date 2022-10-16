/* radare - LGPL - Copyright 2010-2022 - pancake, nibble, condret */

#include <r_arch.h>
#include <r_util.h>
#include <r_list.h>

// XXX this is unused


#if 0
R_API RAnalOp *r_arch_op_new(void) {
	RAnalOp *op = R_NEW (RAnalOp);
	r_arch_op_init (op);
	return op;
}

R_API void r_arch_op_init(RAnalOp *op) {
	if (op) {
		memset (op, 0, sizeof (*op));
		op->addr = UT64_MAX;
		op->jump = UT64_MAX;
		op->fail = UT64_MAX;
		op->ptr = UT64_MAX;
		op->refptr = 0;
		op->val = UT64_MAX;
		op->disp = UT64_MAX;

		op->srcs = r_vector_new (sizeof (RArchValue), NULL, NULL);
		op->dsts = r_vector_new (sizeof (RArchValue), NULL, NULL);
	}
}

R_API void r_arch_op_fini(RAnalOp *op) {
	if (!op) {
		return;
	}
	r_vector_free (op->srcs);
	r_vector_free (op->dsts);
	op->srcs = NULL;
	op->dsts = NULL;
	r_list_free (op->access);
	op->access = NULL;
	r_strbuf_fini (&op->opex);
	r_strbuf_fini (&op->esil);
	r_arch_switch_op_free (op->switch_op);
	op->switch_op = NULL;
	R_FREE (op->mnemonic);
}

R_API void r_arch_op_free(void *_op) {
	if (!_op) {
		return;
	}
	r_arch_op_fini (_op);
	free (_op);
}

R_API RAnalOp *r_arch_op_copy(RAnalOp *op) {
	RAnalOp *nop = R_NEW0 (RAnalOp);
	if (!nop) {
		return NULL;
	}
	*nop = *op;
	if (op->mnemonic) {
		nop->mnemonic = strdup (op->mnemonic);
		if (!nop->mnemonic) {
			free (nop);
			return NULL;
		}
	} else {
		nop->mnemonic = NULL;
	}
	nop->srcs = r_vector_clone (op->srcs);
	nop->dsts = r_vector_clone (op->dsts);
	if (op->access) {
		RListIter *it;
		RArchValue *val;
		RList *naccess = r_list_newf ((RListFree)r_arch_value_free);
		r_list_foreach (op->access, it, val) {
			r_list_append (naccess, r_arch_value_copy (val));
		}
		nop->access = naccess;
	}
	r_strbuf_init (&nop->esil);
	r_strbuf_copy (&nop->esil, &op->esil);
	return nop;
}

static struct optype {
	const int type;
	const char *name;
} optypes[] = {
	{ R_ARCH_OP_TYPE_IO, "io" },
	{ R_ARCH_OP_TYPE_ACMP, "acmp" },
	{ R_ARCH_OP_TYPE_ADD, "add" },
	{ R_ARCH_OP_TYPE_SYNC, "sync" },
	{ R_ARCH_OP_TYPE_AND, "and" },
	{ R_ARCH_OP_TYPE_CALL, "call" },
	{ R_ARCH_OP_TYPE_CCALL, "ccall" },
	{ R_ARCH_OP_TYPE_CJMP, "cjmp" },
	{ R_ARCH_OP_TYPE_MJMP, "mjmp" },
	{ R_ARCH_OP_TYPE_CMP, "cmp" },
	{ R_ARCH_OP_TYPE_ILL, "ill" },
	{ R_ARCH_OP_TYPE_JMP, "jmp" },
	{ R_ARCH_OP_TYPE_LEA, "lea" },
	{ R_ARCH_OP_TYPE_LEAVE, "leave" },
	{ R_ARCH_OP_TYPE_LOAD, "load" },
	{ R_ARCH_OP_TYPE_NEW, "new" },
	{ R_ARCH_OP_TYPE_MOD, "mod" },
	{ R_ARCH_OP_TYPE_CMOV, "cmov" },
	{ R_ARCH_OP_TYPE_MOV, "mov" },
	{ R_ARCH_OP_TYPE_CAST, "cast" },
	{ R_ARCH_OP_TYPE_MUL, "mul" },
	{ R_ARCH_OP_TYPE_DIV, "div" },
	{ R_ARCH_OP_TYPE_NOP, "nop" },
	{ R_ARCH_OP_TYPE_NOT, "not" },
	{ R_ARCH_OP_TYPE_NULL, "null" },
	{ R_ARCH_OP_TYPE_OR, "or" },
	{ R_ARCH_OP_TYPE_POP, "pop" },
	{ R_ARCH_OP_TYPE_PUSH, "push" },
	{ R_ARCH_OP_TYPE_REP, "rep" },
	{ R_ARCH_OP_TYPE_RET, "ret" },
	{ R_ARCH_OP_TYPE_CRET, "cret" },
	{ R_ARCH_OP_TYPE_ROL, "rol" },
	{ R_ARCH_OP_TYPE_ROR, "ror" },
	{ R_ARCH_OP_TYPE_SAL, "sal" },
	{ R_ARCH_OP_TYPE_SAR, "sar" },
	{ R_ARCH_OP_TYPE_SHL, "shl" },
	{ R_ARCH_OP_TYPE_SHR, "shr" },
	{ R_ARCH_OP_TYPE_STORE, "store" },
	{ R_ARCH_OP_TYPE_SUB, "sub" },
	{ R_ARCH_OP_TYPE_SWI, "swi" },
	{ R_ARCH_OP_TYPE_CSWI, "cswi" },
	{ R_ARCH_OP_TYPE_SWITCH, "switch" },
	{ R_ARCH_OP_TYPE_TRAP, "trap" },
	{ R_ARCH_OP_TYPE_UCALL, "ucall" },
	{ R_ARCH_OP_TYPE_RCALL, "rcall" },
	{ R_ARCH_OP_TYPE_ICALL, "icall" },
	{ R_ARCH_OP_TYPE_IRCALL, "ircall" },
	{ R_ARCH_OP_TYPE_UCCALL, "ucccall" },
	{ R_ARCH_OP_TYPE_UCJMP, "ucjmp" },
	{ R_ARCH_OP_TYPE_UJMP, "ujmp" },
	{ R_ARCH_OP_TYPE_RJMP, "rjmp" },
	{ R_ARCH_OP_TYPE_IJMP, "ijmp" },
	{ R_ARCH_OP_TYPE_IRJMP, "irjmp" },
	{ R_ARCH_OP_TYPE_UNK, "unk" },
	{ R_ARCH_OP_TYPE_UPUSH, "upush" },
	{ R_ARCH_OP_TYPE_RPUSH, "rpush" },
	{ R_ARCH_OP_TYPE_XCHG, "xchg" },
	{ R_ARCH_OP_TYPE_XOR, "xor" },
	{ R_ARCH_OP_TYPE_CASE, "case" },
	{ R_ARCH_OP_TYPE_CPL, "cpl" },
	{ R_ARCH_OP_TYPE_CRYPTO, "crypto" },
	{0,NULL}
};

R_API int r_arch_optype_from_string(const char *type) {
	int i;
	for  (i = 0; optypes[i].name;i++) {
		if (!strcmp (optypes[i].name, type)) {
			return optypes[i].type;
		}
	}
	return -1;
}

R_API const char *r_arch_optype_to_string(int t) {
	bool once = true;
repeat:
	// TODO: delete
	switch (t) {
	case R_ARCH_OP_TYPE_IO    : return "io";
	case R_ARCH_OP_TYPE_ACMP  : return "acmp";
	case R_ARCH_OP_TYPE_ADD   : return "add";
	case R_ARCH_OP_TYPE_SYNC  : return "sync";
	case R_ARCH_OP_TYPE_AND   : return "and";
	case R_ARCH_OP_TYPE_CALL  : return "call";
	case R_ARCH_OP_TYPE_CCALL : return "ccall";
	case R_ARCH_OP_TYPE_CJMP  : return "cjmp";
	case R_ARCH_OP_TYPE_MJMP  : return "mjmp";
	case R_ARCH_OP_TYPE_CMP   : return "cmp";
	case R_ARCH_OP_TYPE_CRET  : return "cret";
	case R_ARCH_OP_TYPE_DIV   : return "div";
	case R_ARCH_OP_TYPE_ILL   : return "ill";
	case R_ARCH_OP_TYPE_JMP   : return "jmp";
	case R_ARCH_OP_TYPE_LEA   : return "lea";
	case R_ARCH_OP_TYPE_LEAVE : return "leave";
	case R_ARCH_OP_TYPE_LOAD  : return "load";
	case R_ARCH_OP_TYPE_NEW   : return "new";
	case R_ARCH_OP_TYPE_MOD   : return "mod";
	case R_ARCH_OP_TYPE_CMOV  : return "cmov";
	case R_ARCH_OP_TYPE_MOV   : return "mov";
	case R_ARCH_OP_TYPE_CAST  : return "cast";
	case R_ARCH_OP_TYPE_MUL   : return "mul";
	case R_ARCH_OP_TYPE_NOP   : return "nop";
	case R_ARCH_OP_TYPE_NOT   : return "not";
	case R_ARCH_OP_TYPE_NULL  : return "null";
	case R_ARCH_OP_TYPE_OR    : return "or";
	case R_ARCH_OP_TYPE_POP   : return "pop";
	case R_ARCH_OP_TYPE_PUSH  : return "push";
	case R_ARCH_OP_TYPE_RPUSH : return "rpush";
	case R_ARCH_OP_TYPE_REP   : return "rep";
	case R_ARCH_OP_TYPE_RET   : return "ret";
	case R_ARCH_OP_TYPE_ROL   : return "rol";
	case R_ARCH_OP_TYPE_ROR   : return "ror";
	case R_ARCH_OP_TYPE_SAL   : return "sal";
	case R_ARCH_OP_TYPE_SAR   : return "sar";
	case R_ARCH_OP_TYPE_SHL   : return "shl";
	case R_ARCH_OP_TYPE_SHR   : return "shr";
	case R_ARCH_OP_TYPE_STORE : return "store";
	case R_ARCH_OP_TYPE_SUB   : return "sub";
	case R_ARCH_OP_TYPE_SWI   : return "swi";
	case R_ARCH_OP_TYPE_CSWI  : return "cswi";
	case R_ARCH_OP_TYPE_SWITCH: return "switch";
	case R_ARCH_OP_TYPE_TRAP  : return "trap";
	case R_ARCH_OP_TYPE_UCALL : return "ucall";
	case R_ARCH_OP_TYPE_RCALL : return "rcall";
	case R_ARCH_OP_TYPE_ICALL : return "icall";
	case R_ARCH_OP_TYPE_IRCALL: return "ircall";
	case R_ARCH_OP_TYPE_UCCALL: return "uccall";
	case R_ARCH_OP_TYPE_UCJMP : return "ucjmp";
	case R_ARCH_OP_TYPE_MCJMP : return "mcjmp";
	case R_ARCH_OP_TYPE_RCJMP : return "rcjmp";
	case R_ARCH_OP_TYPE_UJMP  : return "ujmp";
	case R_ARCH_OP_TYPE_RJMP  : return "rjmp";
	case R_ARCH_OP_TYPE_IJMP  : return "ijmp";
	case R_ARCH_OP_TYPE_IRJMP : return "irjmp";
	case R_ARCH_OP_TYPE_UNK   : return "unk";
	case R_ARCH_OP_TYPE_UPUSH : return "upush";
	case R_ARCH_OP_TYPE_XCHG  : return "xchg";
	case R_ARCH_OP_TYPE_XOR   : return "xor";
	case R_ARCH_OP_TYPE_CASE  : return "case";
	case R_ARCH_OP_TYPE_CPL   : return "cpl";
	case R_ARCH_OP_TYPE_CRYPTO: return "crypto";
	case R_ARCH_OP_TYPE_LENGTH: return "lenght";
	case R_ARCH_OP_TYPE_ABS   : return "abs";
	}
	if (once) {
		once = false;
		t &= R_ARCH_OP_TYPE_MASK; // ignore the modifier bits... we don't want this!
		goto repeat;
	}
	return "undefined";
}

R_API const char *r_arch_stackop_to_string(int s) {
	switch (s) {
	case R_ARCH_STACK_NULL:
		return "null";
	case R_ARCH_STACK_NOP:
		return "nop";
	case R_ARCH_STACK_INC:
		return "inc";
	case R_ARCH_STACK_GET:
		return "get";
	case R_ARCH_STACK_SET:
		return "set";
	case R_ARCH_STACK_RESET:
		return "reset";
	}
	return "unk";
}

R_API const char *r_arch_op_family_to_string(int n) {
	switch (n) {
	case R_ARCH_OP_FAMILY_UNKNOWN: return "unk";
	case R_ARCH_OP_FAMILY_CPU: return "cpu";
	case R_ARCH_OP_FAMILY_SECURITY: return "sec";
	case R_ARCH_OP_FAMILY_FPU: return "fpu";
	case R_ARCH_OP_FAMILY_MMX: return "mmx";
	case R_ARCH_OP_FAMILY_SSE: return "sse";
	case R_ARCH_OP_FAMILY_PRIV: return "priv";
	case R_ARCH_OP_FAMILY_THREAD: return "thrd";
	case R_ARCH_OP_FAMILY_CRYPTO: return "crpt";
	case R_ARCH_OP_FAMILY_IO: return "io";
	case R_ARCH_OP_FAMILY_VIRT: return "virt";
	}
	return NULL;
}

struct op_family {
	const char *name;
	int id;
};
static const struct op_family of[] = {
	{ "cpu", R_ARCH_OP_FAMILY_CPU},
	{ "fpu", R_ARCH_OP_FAMILY_FPU},
	{ "mmx", R_ARCH_OP_FAMILY_MMX},
	{ "sse", R_ARCH_OP_FAMILY_SSE},
	{ "priv", R_ARCH_OP_FAMILY_PRIV},
	{ "virt", R_ARCH_OP_FAMILY_VIRT},
	{ "crpt", R_ARCH_OP_FAMILY_CRYPTO},
	{ "io", R_ARCH_OP_FAMILY_IO},
	{ "sec", R_ARCH_OP_FAMILY_SECURITY},
	{ "thread", R_ARCH_OP_FAMILY_THREAD},
};

R_API int r_arch_op_family_from_string(const char *f) {
	int i;
	for (i = 0; i < sizeof (of) / sizeof (of[0]); i ++) {
		if (!strcmp (f, of[i].name)) {
			return of[i].id;
		}
	}
	return R_ARCH_OP_FAMILY_UNKNOWN;
}

R_API const char *r_arch_op_direction_to_string(RAnalOp *op) {
	if (!op) {
		return "none";
	}
	int d = op->direction;
	return d == 1 ? "read"
		: d == 2 ? "write"
		: d == 4 ? "exec"
		: d == 8 ? "ref": "none";
}

#endif
