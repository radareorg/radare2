/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalOp *r_anal_aop_new() {
	RAnalOp *aop = R_NEW (RAnalOp);
	if (aop) {
		memset (aop, 0, sizeof (RAnalOp));
		aop->mnemonic = NULL;
		aop->addr = -1;
		aop->jump = -1;
		aop->fail = -1;
	}
	return aop;
}

R_API RList *r_anal_aop_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_aop_free;
	return list;
}

R_API void r_anal_aop_free(void *_aop) {
	if (_aop) {
		RAnalOp *aop = _aop;
		r_anal_value_free (aop->src[0]);
		r_anal_value_free (aop->src[1]);
		r_anal_value_free (aop->src[2]);
		r_anal_value_free (aop->dst);
		free (aop->mnemonic);
		free (aop);
	}
}

R_API int r_anal_aop(RAnal *anal, RAnalOp *aop, ut64 addr, const ut8 *data, int len) {
	if (anal && aop && anal->cur && anal->cur->aop)
		return anal->cur->aop (anal, aop, addr, data, len);
	return 0;
}

R_API char *r_anal_aop_to_string(RAnal *anal, RAnalOp *op) {
	int retsz = 128;
	char *cstr, *ret = malloc (128);
	char *r0 = r_anal_value_to_string (op->dst);
	char *a0 = r_anal_value_to_string (op->src[0]);
	char *a1 = r_anal_value_to_string (op->src[1]);

	switch (op->type) {
	case R_ANAL_OP_TYPE_MOV:
		snprintf (ret, retsz, "%s = %s", r0, a0);
		break;
	case R_ANAL_OP_TYPE_ADD:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s += %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s + %s", r0, a0, a1);
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
	case R_ANAL_OP_TYPE_CJMP:
		cstr = r_anal_cond_to_string (op->cond);
		snprintf (ret, retsz, "if (%s) goto 0x%08llx", cstr, op->jump);
		//free (cstr);
		break;
	case R_ANAL_OP_TYPE_JMP:
		snprintf (ret, retsz, "goto 0x%08llx", op->jump);
		break;
	case R_ANAL_OP_TYPE_CALL:
		// XXX: resolve flag name
		snprintf (ret, retsz, "0x%08llx()", op->jump);
		break;
	case R_ANAL_OP_TYPE_SUB:
		if (a1 == NULL || !strcmp (a0, a1))
			snprintf (ret, retsz, "%s -= %s", r0, a0);
		else snprintf (ret, retsz, "%s = %s - %s", r0, a0, a1);
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
