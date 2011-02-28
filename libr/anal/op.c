/* radare - LGPL - Copyright 2010-2011 */
/*   nibble<.ds@gmail.com> + pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalOp *r_anal_op_new() {
	RAnalOp *op = R_NEW (RAnalOp);
	if (op) {
		memset (op, 0, sizeof (RAnalOp));
		op->mnemonic = NULL;
		op->addr = -1;
		op->jump = -1;
		op->fail = -1;
		op->ref = -1;
		op->value = -1;
	}
	return op;
}

R_API RList *r_anal_op_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_op_free;
	return list;
}

R_API void r_anal_op_free(void *_op) {
	if (_op) {
		RAnalOp *op = _op;
		r_anal_value_free (op->src[0]);
		r_anal_value_free (op->src[1]);
		r_anal_value_free (op->src[2]);
		r_anal_value_free (op->dst);
		free (op->mnemonic);
		free (op);
	}
}

R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	if (anal && op && anal->cur && anal->cur->op)
		return anal->cur->op (anal, op, addr, data, len);
	return R_FALSE;
}

// TODO: return RAnalException *
R_API int r_anal_op_execute (RAnal *anal, RAnalOp *op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_ADD:
		// dst = src[0] + src[1] + src[2]
		break;
	case R_ANAL_OP_TYPE_SUB:
		// dst = src[0] + src[1] + src[2]
		break;
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_MUL:
		// not yet implemented
		break;
	case R_ANAL_OP_TYPE_NOP:
		// do nothing
		break;
	}
	return R_TRUE;
}

R_API char *r_anal_op_to_string(RAnal *anal, RAnalOp *op) {
	RAnalFcn *f;
	int retsz = 128;
	char *cstr, *ret = malloc (128);
	char *r0 = r_anal_value_to_string (op->dst);
	char *a0 = r_anal_value_to_string (op->src[0]);
	char *a1 = r_anal_value_to_string (op->src[1]);

	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
		snprintf (ret, retsz, "%s = %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_CJMP:
		{
		RAnalBlock *bb = r_anal_bb_from_offset (anal, op->addr);
		if (bb) {
			cstr = r_anal_cond_to_string (bb->cond);
			snprintf (ret, retsz, "if (%s) goto 0x%"PFMT64x, cstr, op->jump);
			free (cstr);
		} else snprintf (ret, retsz, "if (%s) goto 0x%"PFMT64x, "unk", op->jump);
		}
		break;
	case R_ANAL_OP_TYPE_JMP:
		snprintf (ret, retsz, "goto 0x%"PFMT64x, op->jump);
		break;
	case R_ANAL_OP_TYPE_PUSH:
	case R_ANAL_OP_TYPE_UPUSH:
		snprintf (ret, retsz, "push %s", a0);
		break;
	case R_ANAL_OP_TYPE_POP:
		snprintf (ret, retsz, "pop %s", r0);
		break;
	case R_ANAL_OP_TYPE_UCALL:
		snprintf (ret, retsz, "%s()", r0);
		break;
	case R_ANAL_OP_TYPE_CALL:
		f = r_anal_fcn_find (anal, op->jump, R_ANAL_FCN_TYPE_NULL);
		if (f) snprintf (ret, retsz, "%s()", f->name);
		else  snprintf (ret, retsz, "0x%"PFMT64x"()", op->jump);
		break;
	case R_ANAL_OP_TYPE_ADD:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s += %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s + %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_SUB:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s -= %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s - %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_MUL:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s *= %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s * %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_DIV:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s /= %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s / %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_AND:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s &= %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s & %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_OR:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s |= %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s | %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_XOR:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s ^= %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s ^ %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_CMP:
		ret[0] = '\0';
		break;
	case R_ANAL_OP_TYPE_NOP:
		sprintf (ret, "nop");
		break;
	case R_ANAL_OP_TYPE_RET:
		sprintf (ret, "ret");
		break;
	default:
		sprintf (ret, "// ?");
		break;
	}
	free (r0);
	free (a0);
	free (a1);
	return ret;
}
