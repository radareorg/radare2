/* radare - LGPL - Copyright 2010-2024 - pancake, nibble, condret */

#include <r_arch.h>

// XXX this is unused

R_API bool r_anal_op_set_mnemonic(RAnalOp *op, ut64 addr, const char *s) {
	char *news = strdup (s);
	if (news) {
		free (op->mnemonic);
		op->mnemonic = news;
		op->addr = addr;
		return true;
	}
	return false;
}

R_API bool r_anal_op_set_bytes(RAnalOp *op, ut64 addr, const ut8* data, int size) {
	if (op) {
		// TODO: use maxopsz from archbits
		op->addr = addr;
		if (op->weakbytes) {
			op->weakbytes = false;
		} else {
			if (op->bytes != op->bytes_buf) {
				free (op->bytes);
			}
		}
#if 0
		if (size > 512) {
			R_LOG_DEBUG ("large opsetbytes of %d. check backtrace to fix", size);
		}
#endif
		size = R_MIN (size, 64); // sizeof (op->bytes_buf));
		if (size <= sizeof (op->bytes_buf)) {
			op->weakbytes = true;
			op->bytes = op->bytes_buf;
			memcpy (op->bytes_buf, data, size);
		} else {
			op->bytes = r_mem_dup (data, size);
			op->weakbytes = false;
		}
		op->size = size;
		return true;
	}
	return false;
}

R_API RAnalOp *r_anal_op_new(void) {
	RAnalOp *op = R_NEW (RAnalOp);
	r_anal_op_init (op);
	return op;
}

R_API RAnalOp *r_anal_op_clone(RAnalOp *op) {
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
	RVecRArchValue_init (&nop->srcs);
	RVecRArchValue_init (&nop->dsts);
	RVecRArchValue_append (&nop->srcs, &op->srcs, NULL);
	RVecRArchValue_append (&nop->dsts, &op->dsts, NULL);
	if (op->access) {
		RListIter *it;
		RArchValue *val;
		RList *naccess = r_list_newf ((RListFree)r_anal_value_free);
		r_list_foreach (op->access, it, val) {
			r_list_append (naccess, r_anal_value_clone(val));
		}
		nop->access = naccess;
	}
	r_strbuf_init (&nop->esil);
	r_strbuf_copy (&nop->esil, &op->esil);
	r_strbuf_init (&nop->opex);
	r_strbuf_copy (&nop->opex, &op->opex);
	return nop;
}

#if 0
R_API RList *r_anal_op_list_new(void) {
	return r_list_newf (r_anal_op_free);
}
#endif

R_API void r_anal_op_init(RAnalOp *op) {
	if (op) {
		memset (op, 0, sizeof (*op));
		op->addr = UT64_MAX;
		op->jump = UT64_MAX;
		op->fail = UT64_MAX;
		op->ptr = UT64_MAX;
		op->refptr = 0;
		op->val = UT64_MAX;
		op->disp = UT64_MAX;

		RVecRArchValue_init (&op->srcs);
		RVecRArchValue_init (&op->dsts);
#if 0
		RVecRArchValue_reserve (&op->srcs, 3);
		RVecRArchValue_reserve (&op->dsts, 1);
#endif
	}
}

R_API void r_anal_op_fini(RAnalOp *op) {
	if (!op) {
		return;
	}
	// should be a static vector not a pointer
	RVecRArchValue_fini (&op->srcs);
	RVecRArchValue_fini (&op->dsts);
	r_list_free (op->access);
	op->access = NULL;
	if (!op->weakbytes) {
		R_FREE (op->bytes);
	}
	r_strbuf_fini (&op->opex);
	r_strbuf_fini (&op->esil);
	r_anal_switch_op_free (op->switch_op);
	op->switch_op = NULL;
	R_FREE (op->mnemonic);
}

R_API void r_anal_op_free(void *_op) {
	if (!_op) {
		return;
	}
	r_anal_op_fini (_op);
	memset (_op, 0, sizeof (RAnalOp));
	free (_op);
}

static const struct {
	int type;
	const char *name;
} optypes[] = {
	{ R_ANAL_OP_TYPE_IO, "io" },
	{ R_ANAL_OP_TYPE_ACMP, "acmp" },
	{ R_ANAL_OP_TYPE_ADD, "add" },
	{ R_ANAL_OP_TYPE_SYNC, "sync" },
	{ R_ANAL_OP_TYPE_AND, "and" },
	{ R_ANAL_OP_TYPE_CALL, "call" },
	{ R_ANAL_OP_TYPE_CCALL, "ccall" },
	{ R_ANAL_OP_TYPE_CJMP, "cjmp" },
	{ R_ANAL_OP_TYPE_MJMP, "mjmp" },
	{ R_ANAL_OP_TYPE_CMP, "cmp" },
	{ R_ANAL_OP_TYPE_ILL, "ill" },
	{ R_ANAL_OP_TYPE_JMP, "jmp" },
	{ R_ANAL_OP_TYPE_LEA, "lea" },
	{ R_ANAL_OP_TYPE_LEAVE, "leave" },
	{ R_ANAL_OP_TYPE_LOAD, "load" },
	{ R_ANAL_OP_TYPE_NEW, "new" },
	{ R_ANAL_OP_TYPE_MOD, "mod" },
	{ R_ANAL_OP_TYPE_CMOV, "cmov" },
	{ R_ANAL_OP_TYPE_MOV, "mov" },
	{ R_ANAL_OP_TYPE_CAST, "cast" },
	{ R_ANAL_OP_TYPE_MUL, "mul" },
	{ R_ANAL_OP_TYPE_DIV, "div" },
	{ R_ANAL_OP_TYPE_NOP, "nop" },
	{ R_ANAL_OP_TYPE_NOT, "not" },
	{ R_ANAL_OP_TYPE_NULL, "null" },
	{ R_ANAL_OP_TYPE_OR, "or" },
	{ R_ANAL_OP_TYPE_POP, "pop" },
	{ R_ANAL_OP_TYPE_PUSH, "push" },
	{ R_ANAL_OP_TYPE_REP, "rep" },
	{ R_ANAL_OP_TYPE_RET, "ret" },
	{ R_ANAL_OP_TYPE_CRET, "cret" },
	{ R_ANAL_OP_TYPE_ROL, "rol" },
	{ R_ANAL_OP_TYPE_ROR, "ror" },
	{ R_ANAL_OP_TYPE_SAL, "sal" },
	{ R_ANAL_OP_TYPE_SAR, "sar" },
	{ R_ANAL_OP_TYPE_SHL, "shl" },
	{ R_ANAL_OP_TYPE_SHR, "shr" },
	{ R_ANAL_OP_TYPE_STORE, "store" },
	{ R_ANAL_OP_TYPE_SUB, "sub" },
	{ R_ANAL_OP_TYPE_SWI, "swi" },
	{ R_ANAL_OP_TYPE_CSWI, "cswi" },
	{ R_ANAL_OP_TYPE_SWITCH, "switch" },
	{ R_ANAL_OP_TYPE_TRAP, "trap" },
	{ R_ANAL_OP_TYPE_UCALL, "ucall" },
	{ R_ANAL_OP_TYPE_RCALL, "rcall" },
	{ R_ANAL_OP_TYPE_ICALL, "icall" },
	{ R_ANAL_OP_TYPE_IRCALL, "ircall" },
	{ R_ANAL_OP_TYPE_UCCALL, "ucccall" },
	{ R_ANAL_OP_TYPE_UCJMP, "ucjmp" },
	{ R_ANAL_OP_TYPE_UJMP, "ujmp" },
	{ R_ANAL_OP_TYPE_RJMP, "rjmp" },
	{ R_ANAL_OP_TYPE_IJMP, "ijmp" },
	{ R_ANAL_OP_TYPE_IRJMP, "irjmp" },
	{ R_ANAL_OP_TYPE_UNK, "unk" },
	{ R_ANAL_OP_TYPE_UPUSH, "upush" },
	{ R_ANAL_OP_TYPE_RPUSH, "rpush" },
	{ R_ANAL_OP_TYPE_XCHG, "xchg" },
	{ R_ANAL_OP_TYPE_XOR, "xor" },
	{ R_ANAL_OP_TYPE_CASE, "case" },
	{ R_ANAL_OP_TYPE_CPL, "cpl" },
	{ R_ANAL_OP_TYPE_CRYPTO, "crypto" },
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

R_API const char *r_arch_optype_tostring(int t) {
	bool once = true;
repeat:
	// TODO: delete
	switch (t) {
	case R_ANAL_OP_TYPE_IO    : return "io";
	case R_ANAL_OP_TYPE_ACMP  : return "acmp";
	case R_ANAL_OP_TYPE_ADD   : return "add";
	case R_ANAL_OP_TYPE_SYNC  : return "sync";
	case R_ANAL_OP_TYPE_AND   : return "and";
	case R_ANAL_OP_TYPE_CALL  : return "call";
	case R_ANAL_OP_TYPE_CCALL : return "ccall";
	case R_ANAL_OP_TYPE_CJMP  : return "cjmp";
	case R_ANAL_OP_TYPE_MJMP  : return "mjmp";
	case R_ANAL_OP_TYPE_CMP   : return "cmp";
	case R_ANAL_OP_TYPE_CRET  : return "cret";
	case R_ANAL_OP_TYPE_DIV   : return "div";
	case R_ANAL_OP_TYPE_ILL   : return "ill";
	case R_ANAL_OP_TYPE_JMP   : return "jmp";
	case R_ANAL_OP_TYPE_LEA   : return "lea";
	case R_ANAL_OP_TYPE_LEAVE : return "leave";
	case R_ANAL_OP_TYPE_LOAD  : return "load";
	case R_ANAL_OP_TYPE_NEW   : return "new";
	case R_ANAL_OP_TYPE_MOD   : return "mod";
	case R_ANAL_OP_TYPE_CMOV  : return "cmov";
	case R_ANAL_OP_TYPE_MOV   : return "mov";
	case R_ANAL_OP_TYPE_CAST  : return "cast";
	case R_ANAL_OP_TYPE_MUL   : return "mul";
	case R_ANAL_OP_TYPE_NOP   : return "nop";
	case R_ANAL_OP_TYPE_NOT   : return "not";
	case R_ANAL_OP_TYPE_NULL  : return "null";
	case R_ANAL_OP_TYPE_OR    : return "or";
	case R_ANAL_OP_TYPE_POP   : return "pop";
	case R_ANAL_OP_TYPE_PUSH  : return "push";
	case R_ANAL_OP_TYPE_RPUSH : return "rpush";
	case R_ANAL_OP_TYPE_REP   : return "rep";
	case R_ANAL_OP_TYPE_RET   : return "ret";
	case R_ANAL_OP_TYPE_ROL   : return "rol";
	case R_ANAL_OP_TYPE_ROR   : return "ror";
	case R_ANAL_OP_TYPE_SAL   : return "sal";
	case R_ANAL_OP_TYPE_SAR   : return "sar";
	case R_ANAL_OP_TYPE_SHL   : return "shl";
	case R_ANAL_OP_TYPE_SHR   : return "shr";
	case R_ANAL_OP_TYPE_STORE : return "store";
	case R_ANAL_OP_TYPE_SUB   : return "sub";
	case R_ANAL_OP_TYPE_SWI   : return "swi";
	case R_ANAL_OP_TYPE_CSWI  : return "cswi";
	case R_ANAL_OP_TYPE_SWITCH: return "switch";
	case R_ANAL_OP_TYPE_TRAP  : return "trap";
	case R_ANAL_OP_TYPE_UCALL : return "ucall";
	case R_ANAL_OP_TYPE_RCALL : return "rcall";
	case R_ANAL_OP_TYPE_ICALL : return "icall";
	case R_ANAL_OP_TYPE_IRCALL: return "ircall";
	case R_ANAL_OP_TYPE_UCCALL: return "uccall";
	case R_ANAL_OP_TYPE_UCJMP : return "ucjmp";
	case R_ANAL_OP_TYPE_MCJMP : return "mcjmp";
	case R_ANAL_OP_TYPE_RCJMP : return "rcjmp";
	case R_ANAL_OP_TYPE_UJMP  : return "ujmp";
	case R_ANAL_OP_TYPE_RJMP  : return "rjmp";
	case R_ANAL_OP_TYPE_IJMP  : return "ijmp";
	case R_ANAL_OP_TYPE_IRJMP : return "irjmp";
	case R_ANAL_OP_TYPE_UNK   : return "unk";
	case R_ANAL_OP_TYPE_UPUSH : return "upush";
	case R_ANAL_OP_TYPE_XCHG  : return "xchg";
	case R_ANAL_OP_TYPE_XOR   : return "xor";
	case R_ANAL_OP_TYPE_CASE  : return "case";
	case R_ANAL_OP_TYPE_CPL   : return "cpl";
	case R_ANAL_OP_TYPE_CRYPTO: return "crypto";
	case R_ANAL_OP_TYPE_LENGTH: return "lenght";
	case R_ANAL_OP_TYPE_ABS   : return "abs";
	}
	if (once) {
		once = false;
		t &= R_ANAL_OP_TYPE_MASK; // ignore the modifier bits... we don't want this!
		goto repeat;
	}
	return "undefined";
}

R_API const char *r_arch_stackop_tostring(int s) {
	switch (s) {
	case R_ANAL_STACK_NULL:
		return "null";
	case R_ANAL_STACK_NOP:
		return "nop";
	case R_ANAL_STACK_INC:
		return "inc";
	case R_ANAL_STACK_GET:
		return "get";
	case R_ANAL_STACK_SET:
		return "set";
	case R_ANAL_STACK_RESET:
		return "reset";
	}
	return "unk";
}

R_API const char *r_arch_op_family_tostring(int n) {
	switch (n) {
	case R_ANAL_OP_FAMILY_UNKNOWN: return "unk";
	case R_ANAL_OP_FAMILY_CPU: return "cpu";
	case R_ANAL_OP_FAMILY_SECURITY: return "sec";
	case R_ANAL_OP_FAMILY_FPU: return "fpu";
	case R_ANAL_OP_FAMILY_VEC: return "vec";
	case R_ANAL_OP_FAMILY_PRIV: return "priv";
	case R_ANAL_OP_FAMILY_THREAD: return "thrd";
	case R_ANAL_OP_FAMILY_CRYPTO: return "crpt";
	case R_ANAL_OP_FAMILY_IO: return "io";
	case R_ANAL_OP_FAMILY_VIRT: return "virt";
	case R_ANAL_OP_FAMILY_SIMD: return "simd";
	}
	return NULL;
}

struct op_family {
	const char *name;
	int id;
};
static const struct op_family of[] = {
	{ "cpu", R_ANAL_OP_FAMILY_CPU},
	{ "fpu", R_ANAL_OP_FAMILY_FPU},
	{ "mmx", R_ANAL_OP_FAMILY_SIMD},
	{ "sse", R_ANAL_OP_FAMILY_SIMD},
	{ "priv", R_ANAL_OP_FAMILY_PRIV},
	{ "virt", R_ANAL_OP_FAMILY_VIRT},
	{ "crpt", R_ANAL_OP_FAMILY_CRYPTO},
	{ "io", R_ANAL_OP_FAMILY_IO},
	{ "sec", R_ANAL_OP_FAMILY_SECURITY},
	{ "thread", R_ANAL_OP_FAMILY_THREAD},
	{ "simd", R_ANAL_OP_FAMILY_SIMD},
	{ "vec", R_ANAL_OP_FAMILY_VEC},
};

R_API int r_arch_op_family_from_string(const char *f) {
	int i;
	for (i = 0; i < sizeof (of) / sizeof (of[0]); i ++) {
		if (!strcmp (f, of[i].name)) {
			return of[i].id;
		}
	}
	return R_ANAL_OP_FAMILY_UNKNOWN;
}

R_API const char *r_arch_op_direction_tostring(RAnalOp *op) {
	if (!op) {
		return "none";
	}
	int d = op->direction;
	return d == 1 ? "read"
		: d == 2 ? "write"
		: d == 4 ? "exec"
		: d == 8 ? "ref": "none";
}
