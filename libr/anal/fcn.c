/* radare - LGPL - Copyright 2010-2011 */
/*   nibble<.ds@gmail.com> + pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

/* work in progress */
#define USE_NEW_FCN_STORE 0
/* faster retrival, slower storage */

R_API RAnalFcn *r_anal_fcn_new() {
	RAnalFcn *fcn = R_NEW (RAnalFcn);
	if (!fcn) return NULL;
	memset (fcn, 0, sizeof (RAnalFcn));
	fcn->addr = -1;
	fcn->stack = 0;
	fcn->vars = r_anal_var_list_new ();
	fcn->refs = r_anal_ref_list_new ();
	fcn->xrefs = r_anal_ref_list_new ();
	fcn->bbs = r_anal_bb_list_new ();
	fcn->fingerprint = NULL;
	fcn->diff = r_anal_diff_new ();
	return fcn;
}

R_API RList *r_anal_fcn_list_new() {
	RList *list = r_list_new ();
	if (!list) return NULL;
	list->free = &r_anal_fcn_free;
	return list;
}

R_API void r_anal_fcn_free(void *_fcn) {
	RAnalFcn *fcn = _fcn;
	if (!_fcn) return;
	free (fcn->name);
	r_list_free (fcn->refs);
	r_list_free (fcn->xrefs);
	r_list_free (fcn->vars);
	r_list_free (fcn->bbs);
	free (fcn->fingerprint);
	r_anal_diff_free (fcn->diff);
	free (fcn);
}

R_API int r_anal_fcn_xref_add (RAnal *anal, RAnalFcn *fcn, ut64 at, ut64 addr, int type) {
	RAnalRef *ref;
	if (!fcn || !anal)
		return R_FALSE;
	if (!(ref = r_anal_ref_new ()))
		return R_FALSE;
	ref->type = type;
	ref->at = at;
	ref->addr = addr;
	// TODO: ensure we are not dupping xrefs
	r_list_append (fcn->refs, ref);
	return R_TRUE;
}

R_API int r_anal_fcn_xref_del (RAnal *anal, RAnalFcn *fcn, ut64 at, ut64 addr, int type) {
	RAnalRef *ref;
	RListIter *iter;
	r_list_foreach (fcn->xrefs, iter, ref) {
		if ((type != -1 || type == ref->type)  &&
			(at == 0LL || at == ref->at) &&
			(addr == 0LL || addr == ref->addr)) {
				r_list_delete (fcn->xrefs, iter);
				return R_TRUE;
		}
	}
	return R_FALSE;
}

R_API int r_anal_fcn(RAnal *anal, RAnalFcn *fcn, ut64 addr, ut8 *buf, ut64 len, int reftype) {
	RAnalOp op = {0};
	char *varname;
	int oplen, idx = 0;
	if (fcn->addr == -1)
		fcn->addr = addr;
	fcn->type = (reftype==R_ANAL_REF_TYPE_CODE)?
		R_ANAL_FCN_TYPE_LOC: R_ANAL_FCN_TYPE_FCN;
	len -= 16; // XXX: hack to avoid buffer overflow by reading >64 bytes..
	while (idx < len) {
		r_anal_op_fini (&op);
		if ((oplen = r_anal_op (anal, &op, addr+idx, buf+idx, len-idx)) == 0) {
			if (idx == 0) {
				// eprintf ("Unknown opcode at 0x%08"PFMT64x"\n", addr+idx);
				r_anal_op_fini (&op);
				return R_ANAL_RET_END;
			} else break;
		}
		fcn->ninstr++;
		idx += oplen;
		fcn->size += oplen;
		/* TODO: Parse fastargs (R_ANAL_VAR_ARGREG) */
		switch (op.stackop) {
		case R_ANAL_STACK_INCSTACK:
			fcn->stack += op.value;
			break;
		case R_ANAL_STACK_SET:
			if (op.ref > 0) {
				varname = r_str_dup_printf ("arg_%x", op.ref);
				r_anal_var_add (anal, fcn, op.addr, op.ref,
						R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_DIR_IN, NULL, varname, 1);
			} else {
				varname = r_str_dup_printf ("local_%x", -op.ref);
				r_anal_var_add (anal, fcn, op.addr, -op.ref,
						R_ANAL_VAR_TYPE_LOCAL|R_ANAL_VAR_DIR_NONE, NULL, varname, 1);
			}
			free (varname);
			break;
		case R_ANAL_STACK_GET:
			if (op.ref > 0) {
				varname = r_str_dup_printf ("arg_%x", op.ref);
				r_anal_var_add (anal, fcn, op.addr, op.ref,
						R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_DIR_IN, NULL, varname, 0);
			} else {
				varname = r_str_dup_printf ("local_%x", -op.ref);
				r_anal_var_add (anal, fcn, op.addr, -op.ref,
						R_ANAL_VAR_TYPE_LOCAL|R_ANAL_VAR_DIR_NONE, NULL, varname, 0);
			}
			free (varname);
			break;
		}
		switch (op.type) {
		case R_ANAL_OP_TYPE_JMP:
		case R_ANAL_OP_TYPE_CJMP:
		case R_ANAL_OP_TYPE_CALL:
			if (!r_anal_fcn_xref_add (anal, fcn, op.addr, op.jump,
					op.type == R_ANAL_OP_TYPE_CALL?
					R_ANAL_REF_TYPE_CALL : R_ANAL_REF_TYPE_CODE)) {
				r_anal_op_fini (&op);
				return R_ANAL_RET_ERROR;
			}
			break;
		case R_ANAL_OP_TYPE_RET:
			r_anal_op_fini (&op);
			return R_ANAL_RET_END;
		}
	}
	r_anal_op_fini (&op);
	return fcn->size;
}

// TODO: need to implement r_anal_fcn_remove(RAnal *anal, RAnalFcn *fcn);
R_API int r_anal_fcn_insert(RAnal *anal, RAnalFcn *fcn) {
#if USE_NEW_FCN_STORE
	r_listrange_add (anal->fcnstore, fcn);
	// HUH? store it here .. for backweird compatibility
	r_list_append (anal->fcns, fcn);
#else
	r_list_append (anal->fcns, fcn);
#endif
	return R_TRUE;
}

R_API int r_anal_fcn_add(RAnal *anal, ut64 addr, ut64 size, const char *name, int type, RAnalDiff *diff) {
	int append = 0;
	RAnalFcn *fcn = r_anal_fcn_find (anal, addr, R_ANAL_FCN_TYPE_ROOT);
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
	return append? r_anal_fcn_insert (anal, fcn): R_TRUE;
}

R_API int r_anal_fcn_del(RAnal *anal, ut64 addr) {
	if (addr == 0) {
#if USE_NEW_FCN_STORE
		r_listrange_free (anal->fcnstore);
		anal->fcnstore = r_listrange_new ();
#else
		r_list_free (anal->fcns);
		if (!(anal->fcns = r_anal_fcn_list_new ()))
			return R_FALSE;
#endif
	} else {
#if USE_NEW_FCN_STORE
		// XXX: must only get the function if starting at 0?
		RAnalFcn *f = r_listrange_find_in_range (anal->fcnstore, addr);
		if (f) r_listrange_del (anal->fcnstore, f);
#else
		RAnalFcn *fcni;
		RListIter it, *iter;
		r_list_foreach (anal->fcns, iter, fcni) {
			if (addr >= fcni->addr && addr < fcni->addr+fcni->size) {
				it.n = iter->n;
				r_list_delete (anal->fcns, iter);
				iter = &it;
			}
		}
#endif
	}
	return R_TRUE;
}

R_API RAnalFcn *r_anal_fcn_find(RAnal *anal, ut64 addr, int type) {
#if USE_NEW_FCN_STORE
	// TODO: type is ignored here? wtf.. we need more work on fcnstore
	if (root) return r_listrange_find_root (anal->fcnstore, addr);
	return r_listrange_find_in_range (anal->fcnstore, addr);
#else
	RAnalFcn *fcn, *ret = NULL;
	RListIter *iter;
	if (type == R_ANAL_FCN_TYPE_ROOT) {
		r_list_foreach (anal->fcns, iter, fcn) {
			if (addr == fcn->addr)
				return fcn;
		}
		return NULL;
	}
	r_list_foreach (anal->fcns, iter, fcn) {
		if (!type || (fcn->type & type)) {
			if (addr == fcn->addr || (ret == NULL && (addr > fcn->addr && addr < fcn->addr+fcn->size)))
				ret = fcn; 
		}
	}
	return ret;
#endif
}

/* rename RAnalFcnBB.add() */
R_API int r_anal_fcn_add_bb(RAnalFcn *fcn, ut64 addr, ut64 size, ut64 jump, ut64 fail, int type, RAnalDiff *diff) {
	RAnalBlock *bb = NULL, *bbi;
	RListIter *iter;
	int append = 0, mid = 0;

	r_list_foreach (fcn->bbs, iter, bbi) {
		if (addr == bbi->addr) {
			bb = bbi;
			mid = 0;
			break;
		} else
		if (addr > bbi->addr && addr < bbi->addr+bbi->size)
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

// TODO: rename fcn_bb_split()
R_API int r_anal_fcn_split_bb(RAnalFcn *fcn, RAnalBlock *bb, ut64 addr) {
	RAnalBlock *bbi;
#if R_ANAL_BB_HAS_OPS
	RAnalOp *opi;
#endif
	RListIter *iter;

	r_list_foreach (fcn->bbs, iter, bbi) {
		if (addr == bbi->addr)
			return R_ANAL_RET_DUP;
		if (addr > bbi->addr && addr < bbi->addr + bbi->size) {
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
#if R_ANAL_BB_HAS_OPS
			if (bbi->ops) {
				iter = r_list_iterator (bbi->ops);
				while (r_list_iter_next (iter)) {
					opi = r_list_iter_get (iter);
					if (opi->addr >= addr) {
						r_list_split (bbi->ops, opi);
						bbi->ninstr--;
						r_list_append (bb->ops, opi);
						bb->ninstr++;
					}
				}
			}
#endif
			return R_ANAL_RET_END;
		}
	}
	return R_ANAL_RET_NEW;
}

// TODO: rename fcn_bb_overlap()
R_API int r_anal_fcn_overlap_bb(RAnalFcn *fcn, RAnalBlock *bb) {
	RAnalBlock *bbi;
	RListIter *iter;
#if R_ANAL_BB_HAS_OPS
	RListIter nit; // hack to make r_list_unlink not fail that hard
	RAnalOp *opi;
#endif

	r_list_foreach (fcn->bbs, iter, bbi)
		if (bb->addr+bb->size > bbi->addr && bb->addr+bb->size <= bbi->addr+bbi->size) {
			bb->size = bbi->addr - bb->addr;
			bb->jump = bbi->addr;
			bb->fail = -1;
			bb->conditional = R_FALSE;
			if (bbi->type & R_ANAL_BB_TYPE_HEAD) {
				bb->type = R_ANAL_BB_TYPE_HEAD;
				bbi->type = bbi->type^R_ANAL_BB_TYPE_HEAD;
			} else bb->type = R_ANAL_BB_TYPE_BODY;
#if R_ANAL_BB_HAS_OPS
			r_list_foreach (bb->ops, iter, opi) {
				if (opi->addr >= bbi->addr) {
					nit.n = iter->n;
			//		eprintf ("Must delete opi %p\n", iter);
					r_list_delete (bb->ops, iter);
					iter = &nit;
				}
			}
#endif
			//r_list_unlink (bb->ops, opi);
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
		retbb = ((bbi->type & R_ANAL_BB_TYPE_LAST))? 1: 0;
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
	RAnalVar *arg, *ret;
	if (fs->type != R_ANAL_FCN_TYPE_FCN || fs->type != R_ANAL_FCN_TYPE_SYM)
		return NULL;
	ret = r_anal_fcn_get_var (fs, 0, R_ANAL_VAR_TYPE_RET);
	sign = ret? r_str_newf ("%s %s (", ret->name, fs->name):
		r_str_newf ("void %s (", fs->name);
	for (i=0; ; i++) {
		if (!(arg = r_anal_fcn_get_var (fs, i,
				R_ANAL_VAR_TYPE_ARG|R_ANAL_VAR_TYPE_ARGREG)))
			break;
		if (arg->array>1)
			sign = r_str_concatf (sign, i?", %s %s:%02x[%d]":"%s %s:%02x[%d]",
				arg->vartype, arg->name, arg->delta, arg->array);
		else sign = r_str_concatf (sign, i?", %s %s:%02x":"%s %s:%02x",
				arg->vartype, arg->name, arg->delta);
	}
	return (sign = r_str_concatf (sign, ");"));
}

// TODO: This function is not fully implemented
/* set function signature from string */
R_API int r_anal_fcn_from_string(RAnal *a, RAnalFcn *f, const char *sig) {
	char *p, *q, *r, *str;
	RAnalVar *var;
	int i, arg;

	if (!a || !f || !sig) {
		eprintf ("r_anal_fcn_from_string: No function received\n");
		return R_FALSE;
	}
	str = strdup (sig);
	/* TODO : implement parser */
	//r_list_destroy (fs->vars);
	//set: fs->vars = r_list_new ();
	//set: fs->name
	eprintf ("ORIG=(%s)\n", sig);
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
	free (str);
	eprintf ("Function string parse fail\n");
	return R_FALSE;
}

R_API RAnalFcn *r_anal_get_fcn_at(RAnal *anal, ut64 addr) {
	RAnalFcn *fcni;
	RListIter *iter;
//eprintf ("DEPRECATED: get-at\n");
	r_list_foreach (anal->fcns, iter, fcni)
		//if (fcni->addr == addr)
		if (addr >= fcni->addr && addr < (fcni->addr+fcni->size))
			return fcni;
	return NULL;
}
