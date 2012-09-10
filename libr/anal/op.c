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
		op->next = NULL;
	}
	return op;
}

R_API RList *r_anal_op_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_op_free;
	return list;
}

R_API void r_anal_op_fini(RAnalOp *op) {
	if (op->src[0]) r_anal_value_free (op->src[0]);
	if (op->src[1]) r_anal_value_free (op->src[1]);
	if (op->src[2]) r_anal_value_free (op->src[2]);
	if (op->dst) r_anal_value_free (op->dst);
	free (op->mnemonic);
	op->mnemonic = NULL;
	//op->src[0] = op->src[1] = op->src[2] = op->dst = NULL;
	memset (op, 0, sizeof (RAnalOp));
}

R_API void r_anal_op_free(void *_op) {
	if (!_op) return;
	r_anal_op_fini (_op);
	free (_op);
}

R_API int r_anal_op(RAnal *anal, RAnalOp *op, ut64 addr, const ut8 *data, int len) {
	if (len>0 && anal && op && anal->cur && anal->cur->op)
		return anal->cur->op (anal, op, addr, data, len);
	return R_FALSE;
}

R_API RAnalOp *r_anal_op_copy (RAnalOp *op) {
	RAnalOp *nop = R_NEW (RAnalOp);
	memcpy (nop, op, sizeof (RAnalOp));
	nop->mnemonic = strdup (op->mnemonic);
	nop->src[0] = r_anal_value_copy (op->src[0]);
	nop->src[1] = r_anal_value_copy (op->src[1]);
	nop->src[2] = r_anal_value_copy (op->src[2]);
	nop->dst = r_anal_value_copy (op->dst);
	return nop;
}

// TODO: return RAnalException *
R_API int r_anal_op_execute (RAnal *anal, RAnalOp *op) {
	while (op) {
		if (op->delay>0) {
			anal->queued = r_anal_op_copy (op);
			return R_FALSE;
		}
		switch (op->type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_UJMP:
		case R_ANAL_OP_TYPE_CALL:
			break;
		case R_ANAL_OP_TYPE_ADD:
			// dst = src[0] + src[1] + src[2]
			r_anal_value_set_ut64 (anal, op->dst,
				r_anal_value_to_ut64 (anal, op->src[0])+
				r_anal_value_to_ut64 (anal, op->src[1])+
				r_anal_value_to_ut64 (anal, op->src[2]));
			break;
		case R_ANAL_OP_TYPE_SUB:
			// dst = src[0] + src[1] + src[2]
			r_anal_value_set_ut64 (anal, op->dst,
				r_anal_value_to_ut64 (anal, op->src[0])-
				r_anal_value_to_ut64 (anal, op->src[1])-
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
		if (op && op->delay>0) {
			eprintf ("Exception! two consecutive delayed instructions\n");
			return R_FALSE;
		}
		anal->queued->delay--;
		if (anal->queued->delay == 0) {
			r_anal_op_execute (anal, anal->queued);
			r_anal_op_free (anal->queued);
			anal->queued = NULL;
		}
	}
	return R_TRUE;
}

R_API char *r_anal_op_to_string(RAnal *anal, RAnalOp *op) {
	RAnalFunction *f;
	char ret[128];
	char *cstr;
	char *r0 = r_anal_value_to_string (op->dst);
	char *a0 = r_anal_value_to_string (op->src[0]);
	char *a1 = r_anal_value_to_string (op->src[1]);

	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
		snprintf (ret, sizeof (ret), "%s = %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_CJMP:
		{
		RAnalBlock *bb = r_anal_bb_from_offset (anal, op->addr);
		if (bb) {
			cstr = r_anal_cond_to_string (bb->cond);
			snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, cstr, op->jump);
			free (cstr);
		} else snprintf (ret, sizeof (ret), "if (%s) goto 0x%"PFMT64x, "unk", op->jump);
		}
		break;
	case R_ANAL_OP_TYPE_JMP:
		snprintf (ret, sizeof (ret), "goto 0x%"PFMT64x, op->jump);
		break;
	case R_ANAL_OP_TYPE_UJMP:
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
		snprintf (ret, sizeof (ret), "%s()", r0);
		break;
	case R_ANAL_OP_TYPE_CALL:
		f = r_anal_fcn_find (anal, op->jump, R_ANAL_FCN_TYPE_NULL);
		if (f) snprintf (ret, sizeof (ret), "%s()", f->name);
		else  snprintf (ret, sizeof (ret), "0x%"PFMT64x"()", op->jump);
		break;
	case R_ANAL_OP_TYPE_ADD:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, sizeof (ret), "%s += %s", r0, a0);
		else snprintf (ret, sizeof (ret), "%s = %s + %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_SUB:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, sizeof (ret), "%s -= %s", r0, a0);
		else snprintf (ret, sizeof (ret), "%s = %s - %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_MUL:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, sizeof (ret), "%s *= %s", r0, a0);
		else snprintf (ret, sizeof (ret), "%s = %s * %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_DIV:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, sizeof (ret), "%s /= %s", r0, a0);
		else snprintf (ret, sizeof (ret), "%s = %s / %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_AND:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, sizeof (ret), "%s &= %s", r0, a0);
		else snprintf (ret, sizeof (ret), "%s = %s & %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_OR:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, sizeof (ret), "%s |= %s", r0, a0);
		else snprintf (ret, sizeof (ret), "%s = %s | %s", r0, a0, a1);
		break;
	case R_ANAL_OP_TYPE_XOR:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, sizeof (ret), "%s ^= %s", r0, a0);
		else snprintf (ret, sizeof (ret), "%s = %s ^ %s", r0, a0, a1);
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
	case R_ANAL_OP_TYPE_LEAVE:
		memcpy (ret, "leave", 6);
		break;
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
