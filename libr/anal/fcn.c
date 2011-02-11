/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

#define VERBOSE if(0)

R_API RAnalFcn *r_anal_fcn_new() {
	RAnalFcn *fcn = R_NEW (RAnalFcn);
	if (fcn) {
		memset (fcn, 0, sizeof (RAnalFcn));
		fcn->addr = -1;
		fcn->stack = 0;
		fcn->vars = r_anal_var_list_new ();
		fcn->refs = r_anal_ref_list_new ();
		fcn->xrefs = r_anal_ref_list_new ();
		fcn->bbs = r_anal_bb_list_new ();
		fcn->fingerprint = NULL;
		fcn->diff = r_anal_diff_new ();
	}
	return fcn;
}

R_API RList *r_anal_fcn_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_fcn_free;
	return list;
}

R_API void r_anal_fcn_free(void *_fcn) {
	RAnalFcn *fcn = _fcn;
	if (fcn) {
		if (fcn->name)
			free (fcn->name);
		if (fcn->refs)
			r_list_free (fcn->refs);
		if (fcn->xrefs)
			r_list_free (fcn->xrefs);
		if (fcn->vars)
			r_list_free (fcn->vars);
		if (fcn->bbs)
			r_list_free (fcn->bbs);
		if (fcn->fingerprint)
			free (fcn->fingerprint);
		if (fcn->diff)
			r_anal_diff_free (fcn->diff);
	}
	free (fcn);
}

R_API int r_anal_fcn(RAnal *anal, RAnalFcn *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype) {
	RAnalOp aop;
	RAnalRef *ref;
	char *varname;
	int oplen, idx = 0;
	if (fcn->addr == -1)
		fcn->addr = addr;
	if (reftype == R_ANAL_REF_TYPE_CODE)
		fcn->type = R_ANAL_FCN_TYPE_LOC;
	else fcn->type = R_ANAL_FCN_TYPE_FCN;
	while (idx < len) {
		if ((oplen = r_anal_aop (anal, &aop, addr+idx, buf+idx, len-idx)) == 0) {
			if (idx == 0) {
				VERBOSE eprintf ("Unknown opcode at 0x%08"PFMT64x"\n", addr+idx);
				return R_ANAL_RET_END;
			} else break;
		}
		fcn->ninstr++;
		idx += oplen;
		fcn->size += oplen;
		/* TODO: Parse fastargs (R_ANAL_VAR_ARGREG) */
		switch (aop.stackop) {
		case R_ANAL_STACK_INCSTACK:
			fcn->stack += aop.value;
			break;
		case R_ANAL_STACK_SET:
			if (aop.ref > 0) {
				varname = r_str_dup_printf ("arg_%x", aop.ref);
				r_anal_var_add (anal, fcn, aop.addr, aop.ref,
						R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_DIR_IN, NULL, varname, 1);
			} else {
				varname = r_str_dup_printf ("local_%x", -aop.ref);
				r_anal_var_add (anal, fcn, aop.addr, -aop.ref,
						R_ANAL_VAR_TYPE_LOCAL|R_ANAL_VAR_DIR_NONE, NULL, varname, 1);
			}
			free (varname);
			break;
		case R_ANAL_STACK_GET:
			if (aop.ref > 0) {
				varname = r_str_dup_printf ("arg_%x", aop.ref);
				r_anal_var_add (anal, fcn, aop.addr, aop.ref,
						R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_DIR_IN, NULL, varname, 0);
			} else {
				varname = r_str_dup_printf ("local_%x", -aop.ref);
				r_anal_var_add (anal, fcn, aop.addr, -aop.ref,
						R_ANAL_VAR_TYPE_LOCAL|R_ANAL_VAR_DIR_NONE, NULL, varname, 0);
			}
			free (varname);
			break;
		}
		switch (aop.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			/* TODO: loc's should end with jmp too? */
			if (!(ref = r_anal_ref_new ())) {
				eprintf ("Error: new (ref)\n");
				return R_ANAL_RET_ERROR;
			}
			ref = R_NEW (RAnalRef);
			ref->type = aop.type == R_ANAL_OP_TYPE_CALL?
				R_ANAL_REF_TYPE_CALL : R_ANAL_REF_TYPE_CODE;
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

R_API int r_anal_fcn_add(RAnal *anal, ut64 addr, ut64 size, const char *name, int type, RAnalDiff *diff) {
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
	fcn->type = type;
	if (diff) {
		fcn->diff->type = diff->type;
		fcn->diff->addr = diff->addr;
		R_FREE (fcn->diff->name);
		if (diff->name)
			fcn->diff->name = strdup (diff->name);
	}
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

R_API RAnalFcn *r_anal_fcn_find(RAnal *anal, ut64 addr, int type) {
	RAnalFcn *fcn, *ret = NULL;
	RListIter *iter;
	r_list_foreach (anal->fcns, iter, fcn) {
		if (type == R_ANAL_FCN_TYPE_NULL || fcn->type & type)
		if (addr == fcn->addr ||
			(ret == NULL && (addr > fcn->addr && addr < fcn->addr+fcn->size)))
			ret = fcn; 
	}
	return ret;
}

R_API int r_anal_fcn_add_bb(RAnalFcn *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, int type, RAnalDiff *diff) {
	RAnalBlock *bb = NULL, *bbi;
	RListIter *iter;
	int append = 0, mid = 0;

	r_list_foreach (fcn->bbs, iter, bbi) {
		if (addr == bbi->addr) {
			bb = bbi;
			mid = 0;
			break;
		} else if (addr > bbi->addr && addr < bbi->addr+bbi->size)
			mid = 1;
	}
	if (mid)
		return R_FALSE;
	if (bb == NULL) {
		if (!(bb = r_anal_bb_new ()))
			return R_FALSE;
		append = 1;
	}
	bb->addr = addr;
	bb->size = size;
	bb->jump = jump;
	bb->fail = fail;
	bb->type = type;
	if (diff) {
		bb->diff->type = diff->type;
		bb->diff->addr = diff->addr;
		R_FREE (bb->diff->name);
		if (diff->name)
			bb->diff->name = strdup (diff->name);
	}
	if (append) r_list_append (fcn->bbs, bb);
	return R_TRUE;
}

R_API int r_anal_fcn_split_bb(RAnalFcn *fcn, RAnalBlock *bb, ut64 addr) {
	RAnalBlock *bbi;
	RAnalOp *aopi;
	RListIter *iter;

	r_list_foreach (fcn->bbs, iter, bbi)
		if (addr == bbi->addr)
			return R_ANAL_RET_DUP;
		else if (addr > bbi->addr && addr < bbi->addr + bbi->size) {
			r_list_append (fcn->bbs, bb);
			bb->addr = addr;
			bb->size = bbi->addr + bbi->size - addr;
			bb->jump = bbi->jump;
			bb->fail = bbi->fail;
			bb->conditional = bbi->conditional;
			bbi->size = addr - bbi->addr;
			bbi->jump = addr;
			bbi->fail = -1;
			bbi->conditional = R_FALSE;
			if (bbi->type&R_ANAL_BB_TYPE_HEAD) {
				bb->type = bbi->type^R_ANAL_BB_TYPE_HEAD;
				bbi->type = R_ANAL_BB_TYPE_HEAD;
			} else {
				bb->type = bbi->type;
				bbi->type = R_ANAL_BB_TYPE_BODY;
			}
			iter = r_list_iterator (bbi->aops);
			while (r_list_iter_next (iter)) {
				aopi = r_list_iter_get (iter);
				if (aopi->addr >= addr) {
					r_list_split (bbi->aops, aopi);
					bbi->ninstr--;
					r_list_append (bb->aops, aopi);
					bb->ninstr++;
				}
			}
			return R_ANAL_RET_END;
		}
	return R_ANAL_RET_NEW;
}

R_API int r_anal_fcn_overlap_bb(RAnalFcn *fcn, RAnalBlock *bb) {
	RAnalBlock *bbi;
	RAnalOp *aopi;
	RListIter *iter;

	r_list_foreach (fcn->bbs, iter, bbi)
		if (bb->addr+bb->size > bbi->addr && bb->addr+bb->size <= bbi->addr+bbi->size) {
			bb->size = bbi->addr - bb->addr;
			bb->jump = bbi->addr;
			bb->fail = -1;
			bb->conditional = R_FALSE;
			if (bbi->type&R_ANAL_BB_TYPE_HEAD) {
				bb->type = R_ANAL_BB_TYPE_HEAD;
				bbi->type = bbi->type^R_ANAL_BB_TYPE_HEAD;
			} else bb->type = R_ANAL_BB_TYPE_BODY;
			r_list_foreach (bb->aops, iter, aopi)
				if (aopi->addr >= bbi->addr)
					r_list_unlink (bb->aops, aopi);
			r_list_append (fcn->bbs, bb);
			return R_ANAL_RET_END;
		}
	return R_ANAL_RET_NEW;
}

R_API int r_anal_fcn_cc(RAnalFcn *fcn) {
	struct r_anal_bb_t *bbi;
	RListIter *iter;
	int ret = 0, retbb;

	r_list_foreach (fcn->bbs, iter, bbi) {
		if ((bbi->type & R_ANAL_BB_TYPE_LAST))
			retbb = 1;
		else retbb = 0;
		ret += bbi->conditional + retbb;
	}
	return ret;
}

R_API RAnalVar *r_anal_fcn_get_var(RAnalFcn *fs, int num, int type) {
	RAnalVar *var;
	RListIter *iter;
	int count = 0;
	// vars are sorted by delta in r_anal_var_add()
	r_list_foreach (fs->vars, iter, var) {
		if (type & var->type)
			if (count++ == num)
				return var;
	}
	return NULL;
}

R_API char *r_anal_fcn_to_string(RAnal *a, RAnalFcn* fs) {
	int i;
	char *sign;
	if (fs->type != R_ANAL_FCN_TYPE_FCN || fs->type != R_ANAL_FCN_TYPE_SYM)
		return NULL;
	RAnalVar *arg, *ret = r_anal_fcn_get_var (fs, 0, R_ANAL_VAR_TYPE_RET);
	if (ret) sign = r_str_newf ("%s %s (", ret->name, fs->name);
	else sign = r_str_newf ("void %s (", fs->name);
	for (i=0;;i++) {
		if (!(arg = r_anal_fcn_get_var (fs, i,
						R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_TYPE_ARGREG)))
			break;
		if (arg->array>1) {
			if (i) sign = r_str_concatf (sign, ", %s %s:%02x[%d]", arg->vartype, arg->name, arg->delta, arg->array);
			else sign = r_str_concatf (sign, "%s %s:%02x[%d]", arg->vartype, arg->name, arg->delta, arg->array);
		} else {
			if (i) sign = r_str_concatf (sign, ", %s %s:%02x", arg->vartype, arg->name, arg->delta);
			else sign = r_str_concatf (sign, "%s %s:%02x", arg->vartype, arg->name, arg->delta);
		}
	}
	return (sign = r_str_concatf (sign, ");"));
}

R_API int r_anal_fcn_from_string(RAnal *a, RAnalFcn *f, const char *_str) {
	RAnalVar *var;
	char *str = strdup (_str);
	char *p, *q, *r;
	int i, arg;
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
	r_anal_var_add (a, f, 0LL, 0,
			R_ANAL_VAR_TYPE_RET|R_ANAL_VAR_DIR_OUT, str, "ret", 1);

	/* parse arguments */
	for (i=arg=0,p++;;p=q+1,i++) {
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
		if ((var = r_anal_fcn_get_var (f, i, R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_TYPE_ARGREG))) {
			free (var->name); var->name = strdup (r);
			free (var->vartype); var->vartype = strdup (p);
		} else r_anal_var_add (a, f, 0LL, arg, R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_DIR_IN, p, r, 0);
		arg++;
	}
	// r_anal_fcn_set_var (fs, 0, R_ANAL_VAR_DIR_OUT, );
	free (str);
	return R_TRUE;

	parsefail:
	eprintf ("Function string parse fail\n");
	return R_FALSE;
}
