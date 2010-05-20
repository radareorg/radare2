/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalFcn *r_anal_fcn_new() {
	RAnalFcn *fcn;

	fcn = R_NEW (RAnalFcn);
	if (fcn) {
		memset (fcn, 0, sizeof (RAnalFcn));
		fcn->addr = -1;
		fcn->stack = 0;
		fcn->vars = r_anal_var_list_new ();
		fcn->refs = r_anal_ref_list_new ();
		fcn->xrefs = r_anal_ref_list_new ();
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
			r_list_destroy (((RAnalFcn*)fcn)->refs);
		if (((RAnalFcn*)fcn)->xrefs)
			r_list_destroy (((RAnalFcn*)fcn)->xrefs);
		if (((RAnalFcn*)fcn)->vars)
			r_list_destroy (((RAnalFcn*)fcn)->vars);
	}
	free (fcn);
}

R_API int r_anal_fcn(RAnal *anal, RAnalFcn *fcn, ut64 addr, ut8 *buf, ut64 len) {
	RAnalRef *ref, *refi;
	RListIter *iter;
	RAnalAop aop;
	ut64 *jump;
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
		case R_ANAL_OP_TYPE_CALL:
			r_list_foreach (fcn->refs, iter, refi) {
				jump = (ut64*)refi;
				if (aop.jump == *jump)
					goto _dup_ref;
			}
			if (!(ref = r_anal_ref_new ())) {
				eprintf ("Error: new (ref)\n");
				return R_ANAL_RET_ERROR;
			}
			*ref = aop.jump;
			r_list_append (fcn->refs, ref);
		_dup_ref:
			break;
		case R_ANAL_OP_TYPE_RET:
			return R_ANAL_RET_END;
		}
	}
	return fcn->size;
}

R_API int r_anal_fcn_add(RAnal *anal, ut64 addr, ut64 size, const char *name) {
	RAnalFcn *fcn, *fcni;
	RListIter *iter;

	r_list_foreach (anal->fcns, iter, fcni)
		if (addr >= fcni->addr && addr < fcni->addr+fcni->size)
			return R_FALSE;
	if (!(fcn = r_anal_fcn_new ()))
		return R_FALSE;
	fcn->addr = addr;
	fcn->size = size;
	fcn->name = strdup (name);
	r_list_append (anal->fcns, fcn);
	return R_TRUE;
}

R_API int r_anal_fcn_del(RAnal *anal, ut64 addr) {
	RAnalFcn *fcni;
	RListIter *iter;

	if (addr == 0) {
		r_list_destroy (anal->fcns);
		if (!(anal->fcns = r_anal_fcn_list_new ()))
			return R_FALSE;
	} else r_list_foreach (anal->fcns, iter, fcni)
			if (addr >= fcni->addr && addr < fcni->addr+fcni->size)
				r_list_unlink (anal->fcns, fcni);
	return R_TRUE;
}

R_API RList *r_anal_fcn_bb_list(RAnal *anal, RAnalFcn *fcn) {
	RAnalBB *bbi;
	RListIter *iter;
	RList *list = r_list_new ();
	r_list_foreach (anal->bbs, iter, bbi) {
		if (bbi->addr>=fcn->addr && bbi->addr<(fcn->addr+fcn->size))
			r_list_append (list, bbi);
	}
	return list;
}
