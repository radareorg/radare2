/* radare - LGPL - Copyright 2010-2011 */
/*   pancake<nopcode.org> */

#include <r_anal.h>

R_API RAnalCond *r_anal_cond_new() {
	RAnalCond *cond = R_NEW (RAnalCond);
	memset (cond, 0, sizeof (RAnalCond));
	return cond;
}

// XXX?
R_API RAnalCond *r_anal_cond_clone(RAnalCond *cond) {
	RAnalCond *c = R_NEW (RAnalCond);
	memcpy (c, cond, sizeof (RAnalCond));
	return c;
}

static inline const char *condstring(RAnalCond *cond) {
	const char *condstr_single[] = { "!", "", "0<", "0<=", "0>", "0>=" };
	const char *condstr[] = { "==", "!=", ">=", ">", "<=", "<" };
	if (cond)
	return (cond->arg[1])?condstr [cond->type%sizeof (condstr)]:
		condstr_single [cond->type%sizeof (condstr_single)];
	return "";
}

R_API int r_anal_cond_eval(RAnal *anal, RAnalCond *cond) {
	ut64 arg0 = r_anal_value_to_ut64 (anal, cond->arg[0]);
	if (cond->arg[1]) {
		ut64 arg1 = r_anal_value_to_ut64 (anal, cond->arg[1]);
		switch (cond->type) {
		case R_ANAL_COND_EQ:
			return arg0 == arg1;
		case R_ANAL_COND_NE:
			return arg0 != arg1;
		case R_ANAL_COND_GE:
			return arg0 >= arg1;
		case R_ANAL_COND_GT:
			return arg0 > arg1;
		case R_ANAL_COND_LE:
			return arg0 <= arg1;
		case R_ANAL_COND_LT:
			return arg0 < arg1;
		}
	} else {
		switch (cond->type) {
		case R_ANAL_COND_EQ:
			return !arg0;
		case R_ANAL_COND_NE:
			return arg0;
		case R_ANAL_COND_GT:
			return arg0>0;
		case R_ANAL_COND_GE:
			return arg0>=0;
		case R_ANAL_COND_LT:
			return arg0<0;
		case R_ANAL_COND_LE:
			return arg0<=0;
		}
	}
	return R_FALSE;
}

R_API char *r_anal_cond_to_string(RAnalCond *cond) {
	char *val0, *val1, *out = NULL;
	const char *cnd;
	if (cond == NULL)
		return "?=";
	cnd = condstring (cond);
	val0 = r_anal_value_to_string (cond->arg[0]);
	val1 = r_anal_value_to_string (cond->arg[1]);
	if (val0) {
		if (R_ANAL_COND_SINGLE(cond)) {
			if ( (out = malloc (strlen (val0) + 10)) )
				sprintf (out, "%s%s", cnd, val0);
		} else if ( (out = malloc (strlen (val0) + strlen (val1)+10)) )
			sprintf (out, "%s %s %s", val0, cnd, val1);
	}
	free (val0);
	free (val1);
	return out;
}

R_API RAnalCond *r_anal_cond_new_from_op(RAnalOp *op) {
	RAnalCond *cond;
	if (!(cond = r_anal_cond_new()))
		return NULL;
	//v->reg[0] = op->src[0];
	//v->reg[1] = op->src[1];
	cond->arg[0] = op->src[0];
	op->src[0] = NULL;
	cond->arg[1] = op->src[1];
	op->src[1] = NULL;
	// TODO: moar!
	//cond->arg[1] = op->src[1];
	return cond;
}

R_API RAnalCond *r_anal_cond_new_from_string(const char *str) {
	RAnalCond *cond = R_NEW (RAnalCond);
	// TODO: find '<','=','>','!'...
	return cond;
}
