/* radare - LGPL - Copyright 2010-2016 - pancake, nibble */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

#define SDB_VARUSED_FMT "qzdq"
struct VarUsedType {
	ut64 fcn_addr;
	char *type;
	ut32 scope;
	st64 delta;
};

R_API RAnalOp *r_anal_op_new () {
	RAnalOp *op = R_NEW0 (RAnalOp);
	if (op) {
		op->addr = UT64_MAX;
		op->jump = UT64_MAX;
		op->fail = UT64_MAX;
		op->ptr = UT64_MAX;
		op->val = UT64_MAX;
		r_strbuf_init (&op->esil);
	}
	return op;
}

R_API RList *r_anal_op_list_new() {
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	list->free = &r_anal_op_free;
	return list;
}

R_API bool r_anal_op_fini(RAnalOp *op) {
	if (!op) {
		return false;
	}
	r_anal_var_free (op->var);
	op->var = NULL;
	r_anal_value_free (op->src[0]);
	r_anal_value_free (op->src[1]);
	r_anal_value_free (op->src[2]);
	op->src[0] = NULL;
	op->src[1] = NULL;
	op->src[2] = NULL;
	r_anal_value_free (op->dst);
	op->dst = NULL;
	r_strbuf_fini (&op->esil);
	r_anal_switch_op_free (op->switch_op);
	R_FREE (op->mnemonic);
	return true;
}

R_API void r_anal_op_free(void *_op) {
	if (!_op) {
		return;
	}
	r_anal_op_fini (_op);
	memset (_op, 0, sizeof (RAnalOp));
	free (_op);
}

static RAnalVar *get_used_var(RAnal *anal, RAnalOp *op) {
	char *inst_key = sdb_fmt (0, "inst.0x%"PFMT64x".vars", op->addr);
	const char *var_def = sdb_const_get (anal->sdb_fcns, inst_key, 0);
	struct VarUsedType vut;
	RAnalVar *res;

	if (sdb_fmt_tobin (var_def, SDB_VARUSED_FMT, &vut) != 4) {
		return NULL;
	}
	res = r_anal_var_get (anal, vut.fcn_addr, vut.type[0], vut.scope, vut.delta);
	sdb_fmt_free (&vut, SDB_VARUSED_FMT);
	return res;
}

R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	int ret = 0;
	RAnalVar *tmp;

	//len will end up in memcmp so check for negative	
	if (!anal || len < 0) {
		return -1;
	}
	if (anal->pcalign) {
		if (addr % anal->pcalign) {
			memset (op, 0, sizeof (RAnalOp));
			op->type = R_ANAL_OP_TYPE_ILL;
			op->addr = addr;
			op->size = 1;
			return -1;
		}
	}
	memset (op, 0, sizeof (RAnalOp));
	if (len > 0 && anal->cur && anal->cur->op) {
		ret = anal->cur->op (anal, op, addr, data, len);
		op->addr = addr;
		//free the previous var in op->var
		tmp = get_used_var (anal, op);
		if (tmp) {
			r_anal_var_free (op->var);
			op->var = tmp;
		}
		if (ret < 1) {
			op->type = R_ANAL_OP_TYPE_ILL;
		}
	} else {
		if (!memcmp (data, "\xff\xff\xff\xff", R_MIN (4, len))) {
			op->type = R_ANAL_OP_TYPE_ILL;
			ret = R_MIN (2, len); // HACK
		} else {
			op->type = R_ANAL_OP_TYPE_MOV;
			ret = R_MIN (2, len); // HACK
		}
	}
	return ret;
}

R_API RAnalOp *r_anal_op_copy (RAnalOp *op) {
	RAnalOp *nop = R_NEW0 (RAnalOp);
	if (!nop) return NULL;
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
	nop->src[0] = r_anal_value_copy (op->src[0]);
	nop->src[1] = r_anal_value_copy (op->src[1]);
	nop->src[2] = r_anal_value_copy (op->src[2]);
	nop->dst = r_anal_value_copy (op->dst);
	r_strbuf_init (&nop->esil);
	r_strbuf_set (&nop->esil, r_strbuf_get (&op->esil));
	return nop;
}

// TODO: return RAnalException *
R_API int r_anal_op_execute (RAnal *anal, RAnalOp *op) {
	while (op) {
		if (op->delay > 0) {
			anal->queued = r_anal_op_copy (op);
			return false;
		}
		switch (op->type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_RJMP:
		case R_ANAL_OP_TYPE_IJMP:
		case R_ANAL_OP_TYPE_IRJMP:
		case R_ANAL_OP_TYPE_CALL:
			break;
		case R_ANAL_OP_TYPE_ADD:
			// dst = src[0] + src[1] + src[2]
			r_anal_value_set_ut64 (anal, op->dst,
				r_anal_value_to_ut64 (anal, op->src[0]) +
				r_anal_value_to_ut64 (anal, op->src[1]) +
				r_anal_value_to_ut64 (anal, op->src[2]));
			break;
		case R_ANAL_OP_TYPE_SUB:
			// dst = src[0] + src[1] + src[2]
			r_anal_value_set_ut64 (anal, op->dst,
				r_anal_value_to_ut64 (anal, op->src[0]) -
				r_anal_value_to_ut64 (anal, op->src[1]) -
				r_anal_value_to_ut64 (anal, op->src[2]));
			break;
		case R_ANAL_OP_TYPE_DIV:
			{
			ut64 div = r_anal_value_to_ut64 (anal, op->src[1]);
			if (div == 0) {
				eprintf ("r_anal_op_execute: division by zero\n");
				eprintf ("TODO: throw RAnalException\n");
			} else r_anal_value_set_ut64 (anal, op->dst,
				r_anal_value_to_ut64 (anal, op->src[0])/div);
			}
			break;
		case R_ANAL_OP_TYPE_MUL:
			r_anal_value_set_ut64 (anal, op->dst,
				r_anal_value_to_ut64 (anal, op->src[0])*
				r_anal_value_to_ut64 (anal, op->src[1]));
			break;
		case R_ANAL_OP_TYPE_MOV:
			// dst = src[0]
			r_anal_value_set_ut64 (anal, op->dst,
				r_anal_value_to_ut64 (anal, op->src[0]));
			break;
		case R_ANAL_OP_TYPE_NOP:
			// do nothing
			break;
		}
		op = op->next;
	}

	if (anal->queued) {
		anal->queued->delay--;
		if (anal->queued->delay == 0) {
			r_anal_op_execute (anal, anal->queued);
			r_anal_op_free (anal->queued);
			anal->queued = NULL;
		}
	}
	return true;
}

R_API const char *r_anal_optype_to_string(int t) {
	t &= R_ANAL_OP_TYPE_MASK; // ignore the modifier bits
	switch (t) {
	case R_ANAL_OP_TYPE_IO    : return "io";
	case R_ANAL_OP_TYPE_ACMP  : return "acmp";
	case R_ANAL_OP_TYPE_ADD   : return "add";
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
	case R_ANAL_OP_TYPE_MOD   : return "mod";
	case R_ANAL_OP_TYPE_CMOV  : return "cmov";
	case R_ANAL_OP_TYPE_MOV   : return "mov";
	case R_ANAL_OP_TYPE_MUL   : return "mul";
	case R_ANAL_OP_TYPE_NOP   : return "nop";
	case R_ANAL_OP_TYPE_NOT   : return "not";
	case R_ANAL_OP_TYPE_NULL  : return "null";
	case R_ANAL_OP_TYPE_OR    : return "or";
	case R_ANAL_OP_TYPE_POP   : return "pop";
	case R_ANAL_OP_TYPE_PUSH  : return "push";
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
	case R_ANAL_OP_TYPE_SWITCH: return "switch";
	case R_ANAL_OP_TYPE_TRAP  : return "trap";
	case R_ANAL_OP_TYPE_UCALL : return "ucall";
	case R_ANAL_OP_TYPE_RCALL : return "ucall"; // needs to be changed
	case R_ANAL_OP_TYPE_ICALL : return "ucall"; // needs to be changed
	case R_ANAL_OP_TYPE_IRCALL: return "ucall"; // needs to be changed
	case R_ANAL_OP_TYPE_UCCALL: return "uccall";
	case R_ANAL_OP_TYPE_UCJMP : return "ucjmp";
	case R_ANAL_OP_TYPE_UJMP  : return "ujmp";
	case R_ANAL_OP_TYPE_RJMP  : return "ujmp"; // needs to be changed
	case R_ANAL_OP_TYPE_IJMP  : return "ujmp"; // needs to be changed
	case R_ANAL_OP_TYPE_IRJMP : return "ujmp"; // needs to be changed
	case R_ANAL_OP_TYPE_UNK   : return "unk";
	case R_ANAL_OP_TYPE_UPUSH : return "upush";
	case R_ANAL_OP_TYPE_XCHG  : return "xchg";
	case R_ANAL_OP_TYPE_XOR   : return "xor";
	case R_ANAL_OP_TYPE_CASE  : return "case";
	case R_ANAL_OP_TYPE_CPL   : return "cpl";
	case R_ANAL_OP_TYPE_CRYPTO: return "crypto";
	}
	return "undefined";
}

R_API const char *r_anal_op_to_esil_string(RAnal *anal, RAnalOp *op) {
	return r_strbuf_get (&op->esil);
}

// TODO: use esil here?
R_API char *r_anal_op_to_string(RAnal *anal, RAnalOp *op) {
	RAnalBlock *bb;
	RAnalFunction *f;
	char ret[128];
	char *cstr;
	char *r0 = r_anal_value_to_string (op->dst);
	char *a0 = r_anal_value_to_string (op->src[0]);
	char *a1 = r_anal_value_to_string (op->src[1]);
	if (!r0) r0 = strdup ("?");
	if (!a0) a0 = strdup ("?");
	if (!a1) a1 = strdup ("?");

	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
		snprintf (ret, sizeof (ret), "%s = %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_CJMP:
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = r_anal_cond_to_string (bb->cond);
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, cstr, op->jump);
			free (cstr);
		} else {
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, "?", op->jump);
		}
		break;
	case R_ANAL_OP_TYPE_JMP:
		snprintf (ret, sizeof (ret), "goto 0x%"PFMT64x, op->jump);
		break;
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_IJMP:
	case R_ANAL_OP_TYPE_IRJMP:
		snprintf (ret, sizeof (ret), "goto %s", r0);
		break;
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH:
		snprintf (ret, sizeof (ret), "push %s", a0);
		break;
	case R_ANAL_OP_TYPE_POP:
		snprintf (ret, sizeof (ret), "pop %s", r0);
		break;
	case R_ANAL_OP_TYPE_UCALL:
	case R_ANAL_OP_TYPE_RCALL:
	case R_ANAL_OP_TYPE_ICALL:
	case R_ANAL_OP_TYPE_IRCALL:
		snprintf (ret, sizeof (ret), "%s()", r0);
		break;
	case R_ANAL_OP_TYPE_CALL:
		f = r_anal_get_fcn_in (anal, op->jump, R_ANAL_FCN_TYPE_NULL);
		if (f) snprintf (ret, sizeof (ret), "%s()", f->name);
		else  snprintf (ret, sizeof (ret), "0x%"PFMT64x"()", op->jump);
		break;
	case R_ANAL_OP_TYPE_CCALL:
		f = r_anal_get_fcn_in (anal, op->jump, R_ANAL_FCN_TYPE_NULL);
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = r_anal_cond_to_string (bb->cond);
			if (f) snprintf (ret, sizeof (ret), "if (%s) %s()", cstr, f->name);
			else snprintf (ret, sizeof (ret), "if (%s) 0x%"PFMT64x"()", cstr, op->jump);
			free (cstr);
		} else {
			if (f) snprintf (ret, sizeof (ret), "if (unk) %s()", f->name);
			else snprintf (ret, sizeof (ret), "if (unk) 0x%"PFMT64x"()", op->jump);
		}
		break;
	case R_ANAL_OP_TYPE_ADD:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s += %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s + %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_SUB:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s -= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s - %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_MUL:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s *= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s * %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_DIV:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s /= %s", r0, a0);
		} else snprintf (ret, sizeof (ret), "%s = %s / %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_AND:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s &= %s", r0, a0);
		} else snprintf (ret, sizeof (ret), "%s = %s & %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_OR:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s |= %s", r0, a0);
		} else snprintf (ret, sizeof (ret), "%s = %s | %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_XOR:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s ^= %s", r0, a0);
		} else snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_LEA:
		snprintf (ret, sizeof (ret), "%s -> %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_CMP:
		memcpy (ret, ";", 2);
		break;
	case R_ANAL_OP_TYPE_NOP:
		memcpy (ret, "nop", 4);
		break;
	case R_ANAL_OP_TYPE_RET:
		memcpy (ret, "ret", 4);
		break;
	case R_ANAL_OP_TYPE_CRET:
		if ((bb = r_anal_bb_from_offset (anal, op->addr))) {
			cstr = r_anal_cond_to_string (bb->cond);
			snprintf (ret, sizeof (ret), "if (%s) ret", cstr);
			free (cstr);
		} else {
			strcpy (ret, "if (unk) ret");
		}
		break;
	case R_ANAL_OP_TYPE_LEAVE:
		memcpy (ret, "leave", 6);
		break;
	case R_ANAL_OP_TYPE_MOD:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "%s %%= %s", r0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s %% %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_XCHG:
		if (!a1 || !strcmp (a0, a1)) {
			snprintf (ret, sizeof (ret), "tmp = %s; %s = %s; %s = tmp", r0, r0, a0, a0);
		} else {
			snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
		}
		break;
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_SWITCH:
	case R_ANAL_OP_TYPE_CASE:
		eprintf ("Command not implemented.\n");
		free (r0);
		free (a0);
		free (a1);
		return NULL;
	default:
		free (r0);
		free (a0);
		free (a1);
		return NULL;
	}
	free (r0);
	free (a0);
	free (a1);
	return strdup (ret);
}

R_API const char *r_anal_stackop_tostring(int s) {
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

R_API const char *r_anal_op_family_to_string(int n) {
	static char num[32];
	switch (n) {
	case R_ANAL_OP_FAMILY_UNKNOWN: return "unk";
	case R_ANAL_OP_FAMILY_CPU: return "cpu";
	case R_ANAL_OP_FAMILY_FPU: return "fpu";
	case R_ANAL_OP_FAMILY_MMX: return "mmx";
	case R_ANAL_OP_FAMILY_PRIV: return "priv";
	case R_ANAL_OP_FAMILY_VIRT: return "virt";
	default:
		snprintf (num, sizeof (num), "%d", n);
		break;
	}
	return num;
}

R_API int r_anal_op_family_from_string(const char *f) {
	if (!strcmp (f, "cpu")) return R_ANAL_OP_FAMILY_CPU;
	if (!strcmp (f, "fpu")) return R_ANAL_OP_FAMILY_FPU;
	if (!strcmp (f, "mmx")) return R_ANAL_OP_FAMILY_MMX;
	if (!strcmp (f, "priv")) return R_ANAL_OP_FAMILY_PRIV;
	if (!strcmp (f, "virt")) return R_ANAL_OP_FAMILY_VIRT;
	return R_ANAL_OP_FAMILY_UNKNOWN;
}
