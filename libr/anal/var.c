/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalysisVar *r_anal_var_new() {
	return r_anal_var_init (R_NEW (RAnalysisVar));
}

R_API RAnalysisVarType *r_anal_var_type_new() {
	return r_anal_var_type_init (R_NEW (RAnalysisVarType));
}

R_API RAnalysisVarAccess *r_anal_var_access_new() {
	return r_anal_var_access_init (R_NEW (RAnalysisVarAccess));
}

R_API RList *r_anal_var_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_var_free;
	return list;
}

R_API RList *r_anal_var_type_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_var_type_free;
	return list;
}

R_API RList *r_anal_var_access_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_var_access_free;
	return list;
}

R_API void r_anal_var_free(void *var) {
	if (var) {
		if (((RAnalysisVar*)var)->name)
			free (((RAnalysisVar*)var)->name);
		if (((RAnalysisVar*)var)->vartype)
			free (((RAnalysisVar*)var)->vartype);
		if (((RAnalysisVar*)var)->accesses)
			r_list_destroy (((RAnalysisVar*)var)->accesses);
	}
	free (var);
}

R_API void r_anal_var_type_free(void *vartype) {
	if (vartype) {
		if (((RAnalysisVarType*)vartype)->name)
			free (((RAnalysisVarType*)vartype)->name);
		if (((RAnalysisVarType*)vartype)->fmt)
			free (((RAnalysisVarType*)vartype)->fmt);
	}
	free (vartype);
}

R_API void r_anal_var_access_free(void *access) {
	free (access);
}

R_API RAnalysisVar *r_anal_var_init(RAnalysisVar *var) {
	if (var) {
		memset (var, 0, sizeof (RAnalysisVar));
		var->accesses = r_anal_var_access_list_new ();
	}
	return var;
}

R_API RAnalysisVarType *r_anal_var_type_init(RAnalysisVarType *vartype) {
	if (vartype)
		memset (vartype, 0, sizeof (RAnalysisVarType));
	return vartype;
}

R_API RAnalysisVarAccess *r_anal_var_access_init(RAnalysisVarAccess *access) {
	if (access)
		memset (access, 0, sizeof (RAnalysisVarAccess));
	return access;
}

R_API int r_anal_var_type_add(RAnalysis *anal, const char *name, int size, const char *fmt) {
	RAnalysisVarType *t;

	if (!(t = r_anal_var_type_new ()))
		return R_FALSE;
	if (name)
		t->name = strdup (name);
	if (fmt)
		t->fmt = strdup (fmt);
	t->size = size;
	r_list_append (anal->vartypes, t);
	return R_TRUE;
}

R_API int r_anal_var_type_del(RAnalysis *anal, const char *name) {
	RAnalysisVarType *vti;
	RListIter *iter;

	r_list_foreach(anal->vartypes, iter, vti)
		if (!strcmp (name, vti->name)) {
			r_list_unlink (anal->vartypes, vti);
			return R_TRUE;
		}
	return R_FALSE;
}

R_API RAnalysisVarType *r_anal_var_type_get(RAnalysis *anal, const char *name) {
	RAnalysisVarType *vti;
	RListIter *iter;

	r_list_foreach(anal->vartypes, iter, vti)
		if (!strcmp (name, vti->name))
			return vti;
	return NULL;
}

R_API int r_anal_var_add(RAnalysis *anal, RAnalysisFcn *fcn, ut64 from, int delta, int type, const char *vartype, const char *name, int set) {
	RAnalysisVar *var, *vari;
	RListIter *iter;

	r_list_foreach(fcn->vars, iter, vari)
		if (vari->type == type && vari->delta == delta)
			return r_anal_var_access_add (anal, vari, from, set);
	if (!(var = r_anal_var_new ()))
		return R_FALSE;
	if (name)
		var->name = strdup (name);
	if (vartype)
		var->vartype = strdup (vartype);
	var->type = type;
	var->delta = delta;
	r_anal_var_access_add (anal, var, from, set);
	r_list_append (fcn->vars, var);
	return R_TRUE;
}

R_API int r_anal_var_del(RAnalysis *anal, RAnalysisFcn *fcn, int delta, int type) {
	RAnalysisVar *vari;
	RListIter *iter;

	r_list_foreach(fcn->vars, iter, vari)
		if (vari->type == type && vari->delta == delta) {
			r_list_unlink (fcn->vars, vari);
			return R_TRUE;
		}
	return R_FALSE;
}

R_API RAnalysisVar *r_anal_var_get(RAnalysis *anal, RAnalysisFcn *fcn, int delta, int type) {
	RAnalysisVar *vari;
	RListIter *iter;

	r_list_foreach(fcn->vars, iter, vari)
		if (vari->type == type && vari->delta == delta)
			return vari;
	return NULL;
}

R_API const char *r_anal_var_type_to_str (RAnalysis *anal, int type) {
	switch(type) {
	case R_ANAL_VAR_TYPE_GLOBAL: return "global";
	case R_ANAL_VAR_TYPE_LOCAL:  return "local";
	case R_ANAL_VAR_TYPE_ARG:    return "arg";
	case R_ANAL_VAR_TYPE_ARGREG: return "fastarg";
	}
	return "(?)";
}

R_API int r_anal_var_access_add(RAnalysis *anal, RAnalysisVar *var, ut64 from, int set) {
	RAnalysisVarAccess *acc, *acci;
	RListIter *iter;

	r_list_foreach(var->accesses, iter, acci)
		if (acci->addr == from)
			return R_TRUE;
	if (!(acc = r_anal_var_access_new ()))
		return R_FALSE;
	acc->addr = from;
	acc->set = set;
	r_list_append (var->accesses, acc);
	return R_TRUE;
}

R_API int r_anal_var_access_del(RAnalysis *anal, RAnalysisVar *var, ut64 from) {
	RAnalysisVarAccess *acci;
	RListIter *iter;

	r_list_foreach(var->accesses, iter, acci)
		if (acci->addr == from) {
			r_list_unlink (var->accesses, acci);
			return R_TRUE;
		}
	return R_TRUE;
}

R_API RAnalysisVarAccess *r_anal_var_access_get(RAnalysis *anal, RAnalysisVar *var, ut64 from) {
	RAnalysisVarAccess *acci;
	RListIter *iter;

	r_list_foreach(var->accesses, iter, acci)
		if (acci->addr == from)
			return acci;
	return NULL;
}
