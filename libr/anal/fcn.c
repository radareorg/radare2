/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalysisFcn *r_anal_fcn_new() {
	return r_anal_fcn_init (MALLOC_STRUCT (RAnalysisFcn));
}

R_API RList *r_anal_fcn_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_fcn_free;
	return list;
}

R_API void r_anal_fcn_free(void *fcn) {
	if (fcn) {
		if (((RAnalysisFcn*)fcn)->name)
			free (((RAnalysisFcn*)fcn)->name);
		if (((RAnalysisFcn*)fcn)->refs)
			r_list_destroy (((RAnalysisFcn*)fcn)->refs);
		if (((RAnalysisFcn*)fcn)->xrefs)
			r_list_destroy (((RAnalysisFcn*)fcn)->xrefs);
		if (((RAnalysisFcn*)fcn)->vars)
			r_list_destroy (((RAnalysisFcn*)fcn)->vars);
	}
	free (fcn);
}

R_API RAnalysisFcn *r_anal_fcn_init(RAnalysisFcn *fcn) {
	if (fcn) {
		memset (fcn, 0, sizeof (RAnalysisFcn));
		fcn->addr = -1;
		fcn->vars = r_anal_var_list_new ();
		fcn->refs = r_anal_ref_list_new ();
		fcn->xrefs = r_anal_ref_list_new ();
	}
	return fcn;
}

R_API int r_anal_fcn(RAnalysis *anal, RAnalysisFcn *fcn, ut64 addr, ut8 *buf, ut64 len) {
	RAnalysisRef *ref, *refi;
	RListIter *iter;
	RAnalysisAop aop;
	ut64 *jump;
	char *varname;
	int oplen, idx = 0;

	if (fcn->addr == -1)
		fcn->addr = addr;
	while (idx < len) {
		if ((oplen = r_anal_aop (anal, &aop, addr+idx, buf+idx, len-idx)) == 0) {
			if (idx == 0)
				return R_ANAL_RET_ERROR;
			else break;
		}
		idx += oplen;
		fcn->size += oplen;
		/* TODO: Parse fastargs (R_ANAL_VAR_ARGREG), check negative ref meaning */
		switch (aop.stackop) {
		case R_ANAL_STACK_LOCAL_SET:
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
		case R_ANAL_STACK_ARG_SET:
			varname = r_str_dup_printf ("arg_%x", r_num_abs (aop.ref));
			r_anal_var_add (anal, fcn, aop.addr, r_num_abs (aop.ref), R_ANAL_VAR_TYPE_ARG,
					NULL, varname, 1);
			free (varname);
			break;
		case R_ANAL_STACK_ARG_GET:
			varname = r_str_dup_printf ("arg_%x", r_num_abs (aop.ref));
			r_anal_var_add (anal, fcn, aop.addr, r_num_abs (aop.ref), R_ANAL_VAR_TYPE_ARG,
					NULL, varname, 0);
			free (varname);
			break;
		case R_ANAL_STACK_LOCAL_GET:
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
			if (!(ref = r_anal_ref_new())) {
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
