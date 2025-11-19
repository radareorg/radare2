/* radare - LGPL - Copyright 2010-2025 - pancake */

#include <r_anal.h>

// Both contdypestr and condtypestr_expr should be in the same order,
// depending on the values defined at RAnalCondType
static const char *condtypestr[] = {
	"al", "eq", "ne", "ge", "gt", "le", "lt", "nv",
	"hs", "lo", "mi", "pl", "vs", "vc", "hi", "ls"
};

static const char *condtypestr_expr[] = {
	".any", "==", "!=", ">=", ">", "<=", "<", ".never",
	".carry", ".carryclr", "-", "+", ".ovf", ".novf", ".uhi", ".ulo"
};

R_API const char *r_anal_cond_type_tostring(int cc) {
	R_RETURN_VAL_IF_FAIL (cc >= 0, NULL);
	if (cc < R_ANAL_CONDTYPE_LAST) {
		return condtypestr[cc];
	}
	return "??";
}

R_API const char *r_anal_cond_typeexpr_tostring(int cc) {
	R_RETURN_VAL_IF_FAIL (cc >= 0, NULL);
	if (cc < R_ANAL_CONDTYPE_LAST) {
		return condtypestr_expr[cc];
	}
	return "??";
}

R_API RAnalCondType r_anal_cond_type_fromstring(const char *type) {
	R_RETURN_VAL_IF_FAIL (type, R_ANAL_CONDTYPE_ERR);
	int i;
	for (i = 0; i < R_ANAL_CONDTYPE_LAST; i++) {
		if (!strcmp (type, condtypestr[i])) {
			return i;
		}
		if (!strcmp (type, condtypestr_expr[i])) {
			return i;
		}
	}
	return R_ANAL_CONDTYPE_ERR;
}

R_API RAnalCond *r_anal_cond_new(void) {
	return R_NEW0 (RAnalCond);
}

R_API void r_anal_cond_fini(RAnalCond *c) {
	R_RETURN_IF_FAIL (c);
	r_anal_value_free (c->left);
	r_anal_value_free (c->right);
	c->left = c->right = NULL;
}

R_API void r_anal_cond_free(RAnalCond * R_NULLABLE c) {
	if (c) {
		r_anal_cond_fini (c);
		free (c);
	}
}

R_API RAnalCond *r_anal_cond_clone(RAnalCond *cond) {
	R_RETURN_VAL_IF_FAIL (cond, NULL);
	RAnalCond *c = R_NEW (RAnalCond);
	if (R_LIKELY (c)) {
		c->type = cond->type;
		c->left = r_anal_value_clone (cond->left);
		c->right = r_anal_value_clone (cond->right);
		return c;
	}
	return NULL;
}

R_API int r_anal_cond_eval(RAnal *anal, RAnalCond *cond) {
	R_RETURN_VAL_IF_FAIL (anal && cond, false);
	// XXX: sign issue here?
	st64 arg0 = (st64) r_anal_value_to_ut64 (anal, cond->left);
	if (cond->right) {
		st64 arg1 = (st64) r_anal_value_to_ut64 (anal, cond->right);
		switch (cond->type) {
		case R_ANAL_CONDTYPE_EQ: return arg0 == arg1;
		case R_ANAL_CONDTYPE_NE: return arg0 != arg1;
		case R_ANAL_CONDTYPE_GE: return arg0 >= arg1;
		case R_ANAL_CONDTYPE_GT: return arg0 > arg1;
		case R_ANAL_CONDTYPE_LE: return arg0 <= arg1;
		case R_ANAL_CONDTYPE_LT: return arg0 < arg1;
		}
	} else {
		switch (cond->type) {
		case R_ANAL_CONDTYPE_EQ: return !arg0;
		case R_ANAL_CONDTYPE_NE: return arg0;
		case R_ANAL_CONDTYPE_GT: return arg0 > 0;
		case R_ANAL_CONDTYPE_GE: return arg0 >= 0;
		case R_ANAL_CONDTYPE_LT: return arg0 < 0;
		case R_ANAL_CONDTYPE_LE: return arg0 <= 0;
		}
	}
	return false;
}

R_API char *r_anal_cond_tostring(RAnalCond *cond) {
	R_RETURN_VAL_IF_FAIL (cond, NULL);
	const char *cnd = r_anal_cond_typeexpr_tostring (cond->type);
	char *val0 = r_anal_value_tostring (cond->left);
	char *out = NULL;
	if (val0) {
		if (R_ANAL_CONDTYPE_SINGLE (cond)) {
			out = r_str_newf ("%s%s", cnd, val0);
		} else {
			char *val1 = r_anal_value_tostring (cond->right);
			if (val1) {
				out = r_str_newf ("%s %s %s", val0, cnd, val1);
				free (val1);
			}
		}
		free (val0);
	}
	return out? out: strdup ("?");
}

R_API RAnalCond *r_anal_cond_new_from_op(RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (op, NULL);
	RAnalCond *cond = r_anal_cond_new ();
	if (!cond) {
		return NULL;
	}
	RAnalValue *src0 = r_vector_at (&op->srcs, 0);
	RAnalValue *src1 = r_vector_at (&op->srcs, 1);
	if (!src0 || !src1) {
		r_anal_cond_free (cond);
		return NULL;
	}
	// TODO: use r_ref
	cond->left = r_anal_value_clone (src0);
	cond->right = r_anal_value_clone (src1);
	return cond;
}

R_API RAnalCond *r_anal_cond_new_from_string(const char *str) {
	R_RETURN_VAL_IF_FAIL (str, NULL);
	int i, type = -1;
	char *substr = NULL;
	for (i = 0; i < R_ANAL_CONDTYPE_LAST; i++) {
		substr = strstr(str, condtypestr_expr[i]);
		if (substr) {
			type = i;
			break;
		}
	}
	if (type < 0) {
		return NULL;
	}
	RAnalCond *cond = r_anal_cond_new ();
	cond->type = r_anal_cond_type_fromstring (condtypestr_expr[i]);
	char *left = r_str_ndup (substr, substr - str);
	char *right = strdup (substr + strlen (condtypestr_expr[i]));
	cond->left = r_anal_value_new_from_string (left);
	cond->right = r_anal_value_new_from_string (right);
	free (left);
	free (right);
	return cond;
}
