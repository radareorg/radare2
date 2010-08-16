/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalFcn *r_anal_fcn_new() {
	RAnalFcn *fcn = R_NEW (RAnalFcn);
	if (fcn) {
		memset (fcn, 0, sizeof (RAnalFcn));
		fcn->addr = -1;
		fcn->stack = 0;
		fcn->vars = r_anal_var_list_new ();
		fcn->refs = r_anal_ref_list_new ();
		fcn->xrefs = r_anal_ref_list_new ();
		fcn->diff = R_ANAL_DIFF_NULL;
		fcn->fingerprint = r_big_new (NULL);
	}
	return fcn;
}

R_API RList *r_anal_fcn_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_fcn_free;
	return list;
}

R_API void r_anal_fcn_free(void *fcn) {
	if (fcn) {
		if (((RAnalFcn*)fcn)->name)
			free (((RAnalFcn*)fcn)->name);
		if (((RAnalFcn*)fcn)->refs)
			r_list_free (((RAnalFcn*)fcn)->refs);
		if (((RAnalFcn*)fcn)->xrefs)
			r_list_free (((RAnalFcn*)fcn)->xrefs);
		if (((RAnalFcn*)fcn)->vars)
			r_list_free (((RAnalFcn*)fcn)->vars);
		if (((RAnalFcn*)fcn)->fingerprint)
			r_big_free (((RAnalFcn*)fcn)->fingerprint);
	}
	free (fcn);
}

R_API int r_anal_fcn(RAnal *anal, RAnalFcn *fcn, ut64 addr, ut8 *buf, ut64 len) {
	RAnalOp aop;
	RAnalRef *ref;
	char *varname;
	int oplen, idx = 0;
	if (fcn->addr == -1)
		fcn->addr = addr;
	while (idx < len) {
		if ((oplen = r_anal_aop (anal, &aop, addr+idx, buf+idx, len-idx)) == 0) {
			if (idx == 0)
				return R_ANAL_RET_ERROR;
			break;
		}
		fcn->ninstr++;
		idx += oplen;
		fcn->size += oplen;
		/* TODO: Parse fastargs (R_ANAL_VAR_ARGREG), check negative ref meaning */
		switch (aop.stackop) {
		case R_ANAL_STACK_INCSTACK:
			fcn->stack += aop.value;
			break;
		case R_ANAL_STACK_SET:
			if (aop.ref > 0) {
				varname = r_str_dup_printf ("arg_%x", aop.ref);
				r_anal_var_add (anal, fcn, aop.addr, aop.ref, R_ANAL_VAR_TYPE_ARG,
						NULL, varname, 1);
			} else {
				varname = r_str_dup_printf ("local_%x", -aop.ref);
				r_anal_var_add (anal, fcn, aop.addr, -aop.ref, R_ANAL_VAR_TYPE_LOCAL,
						NULL, varname, 1);
			}
			free (varname);
			break;
		case R_ANAL_STACK_GET:
			if (aop.ref > 0) {
				varname = r_str_dup_printf ("arg_%x", aop.ref);
				r_anal_var_add (anal, fcn, aop.addr, aop.ref, R_ANAL_VAR_TYPE_ARG,
						NULL, varname, 0);
			} else {
				varname = r_str_dup_printf ("local_%x", -aop.ref);
				r_anal_var_add (anal, fcn, aop.addr, -aop.ref, R_ANAL_VAR_TYPE_LOCAL,
						NULL, varname, 0);
			}
			free (varname);
			break;
		}
		switch (aop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			if (!(ref = r_anal_ref_new ())) {
				eprintf ("Error: new (ref)\n");
				return R_ANAL_RET_ERROR;
			}
			ref = R_NEW (RAnalRef);
			ref->type = R_ANAL_REF_TYPE_CODE;
			ref->at = aop.addr;
			ref->addr = aop.jump;
			r_list_append (fcn->refs, ref);
			break;
		case R_ANAL_OP_TYPE_RET:
			return R_ANAL_RET_END;
		}
	}
	return fcn->size;
}

R_API int r_anal_fcn_add(RAnal *anal, ut64 addr, ut64 size, const char *name, int diff) {
	RAnalFcn *fcn = NULL, *fcni;
	RListIter *iter;
	int append = 0;
	r_list_foreach (anal->fcns, iter, fcni)
		if (addr == fcni->addr) {
			fcn = fcni;
			break;
		}
	if (fcn == NULL) {
		if (!(fcn = r_anal_fcn_new ()))
			return R_FALSE;
		append = 1;
	}
	fcn->addr = addr;
	fcn->size = size;
	free (fcn->name);
	fcn->name = strdup (name);
	fcn->diff = diff;
	if (append) r_list_append (anal->fcns, fcn);
	return R_TRUE;
}

R_API int r_anal_fcn_del(RAnal *anal, ut64 addr) {
	RAnalFcn *fcni;
	RListIter *iter;
	if (addr == 0) {
		r_list_free (anal->fcns);
		if (!(anal->fcns = r_anal_fcn_list_new ()))
			return R_FALSE;
	} else r_list_foreach (anal->fcns, iter, fcni)
		if (addr >= fcni->addr && addr < fcni->addr+fcni->size)
			r_list_unlink (anal->fcns, fcni);
	return R_TRUE;
}

R_API RList *r_anal_fcn_bb_list(RAnal *anal, RAnalFcn *fcn) {
	RAnalBlock *bbi;
	RListIter *iter;
	RList *list = r_list_new ();
	r_list_foreach (anal->bbs, iter, bbi) {
		if (bbi->addr>=fcn->addr && bbi->addr<(fcn->addr+fcn->size))
			r_list_append (list, bbi);
	}
	return list;
}

R_API RAnalFcn *r_anal_fcn_find(RAnal *anal, ut64 addr) {
	RAnalFcn *fcn;
	RListIter *iter;
	r_list_foreach (anal->fcns, iter, fcn) {
		if (addr >= fcn->addr && addr < fcn->addr+fcn->size)
			return fcn;
	}
	return NULL;
}

R_API RAnalVar *r_anal_fcn_get_var(RAnalFcn *fs, int num, int dir) {
	RAnalVar *var;
	RListIter *iter;
	int count = 0;
	// vars are sorted by delta in r_anal_var_add()
	r_list_foreach (fs->vars, iter, var) {
		if (dir & var->dir)
			if (count++ == num)
				return var;
	}
	return NULL;
}

R_API char *r_anal_fcn_to_string(RAnal *a, RAnalFcn* fs) {
	int i;
	char *sign;
	RAnalVar *arg, *ret = r_anal_fcn_get_var (fs, 0, R_ANAL_VAR_OUT);
	if (ret) sign = r_str_newf ("%s %s (", ret->name, fs->name);
	else sign = r_str_newf ("void %s (", fs->name);
	for (i=0;;i++) {
		if (!(arg = r_anal_fcn_get_var (fs, i, R_ANAL_VAR_IN)))
			break;
		if (arg->array>1) {
			if (i) sign = r_str_concatf (sign, ", %s %s[%d]", arg->vartype, arg->name, arg->array);
			else sign = r_str_concatf (sign, "%s %s[%d]", arg->vartype, arg->name, arg->array);
		} else {
			if (i) sign = r_str_concatf (sign, ", %s %s", arg->vartype, arg->name);
			else sign = r_str_concatf (sign, "%s %s", arg->vartype, arg->name);
		}
	}
	return (sign = r_str_concatf (sign, ");"));
}

R_API int r_anal_fcn_from_string(RAnal *a, RAnalFcn *f, const char *_str) {
	char *str = strdup (_str);
	char *p, *q, *r;
	int arg;
// TODO: This function is not fully implemented
	if (!a || !f) {
		eprintf ("r_anal_fcn_from_string: No function received\n");
		return R_FALSE;
	}
	/* TODO : implement parser */
	//r_list_destroy (fs->vars);
	//set: fs->vars = r_list_new ();
	//set: fs->name
	printf("ORIG=(%s)\n", _str);
	p = strchr (str, '(');
	if (!p) goto parsefail;
	*p = 0;
	q = strrchr (str, ' ');
	if (!q) goto parsefail;
	*q = 0;
	printf ("RET=(%s)\n", str);
	printf ("NAME=(%s)\n", q+1);
	/* set function name */
	free (f->name);
	f->name = strdup (q+1);
	/* set return value */
	// TODO: simplify this complex api usage
	r_anal_var_add (a, f, 0LL, 0, R_ANAL_VAR_TYPE_RET, str, "ret", 1);

	/* parse arguments */
	for (arg=0,p++;;) {
		q = strchr (p, ',');
		if (!q) {
			q = strchr (p, ')');
			if (!q) break;
		}
		*q = 0;
		p = r_str_chop (p);
		r = strrchr (p, ' ');
		if (!r) goto parsefail;
		*r = 0;
		r = r_str_chop (r+1);
		printf ("VAR %d=(%s)(%s)\n", arg, p, r);
		// TODO : increment arg by var size
		r_anal_var_add (a, f, 0LL, arg, R_ANAL_VAR_TYPE_RET, p, r, 1);
		arg++;
		p=q+1;
	}
	// r_anal_fcn_set_var (fs, 0, R_ANAL_VAR_OUT, );
	free (str);
	return R_TRUE;

	parsefail:
	eprintf ("Function string parse fail\n");
	return R_FALSE;
}
