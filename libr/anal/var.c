/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_list.h>

R_API RAnalVar *r_anal_var_new() {
	RAnalVar *var = R_NEW (RAnalVar);
	if (var) {
		memset (var, 0, sizeof (RAnalVar));
		var->accesses = r_anal_var_access_list_new ();
	}
	return var;
}

R_API RAnalVarType *r_anal_var_type_new() {
	RAnalVarType *vartype = R_NEW (RAnalVarType);
	if (vartype)
		memset (vartype, 0, sizeof (RAnalVarType));
	return vartype;
}

R_API RAnalVarAccess *r_anal_var_access_new() {
	RAnalVarAccess *access;

	access = R_NEW (RAnalVarAccess);
	if (access)
		memset (access, 0, sizeof (RAnalVarAccess));
	return access;
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
		if (((RAnalVar*)var)->name)
			free (((RAnalVar*)var)->name);
		if (((RAnalVar*)var)->vartype)
			free (((RAnalVar*)var)->vartype);
		if (((RAnalVar*)var)->accesses)
			r_list_free (((RAnalVar*)var)->accesses);
	}
	free (var);
}

R_API void r_anal_var_type_free(void *vartype) {
	if (vartype) {
		if (((RAnalVarType*)vartype)->name)
			free (((RAnalVarType*)vartype)->name);
		if (((RAnalVarType*)vartype)->fmt)
			free (((RAnalVarType*)vartype)->fmt);
	}
	free (vartype);
}

R_API void r_anal_var_access_free(void *access) {
	free (access);
}

R_API int r_anal_var_type_add(RAnal *anal, const char *name, int size, const char *fmt) {
	RAnalVarType *t;
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

R_API int r_anal_var_type_del(RAnal *anal, const char *name) {
	RAnalVarType *vti;
	RListIter *iter;

	r_list_foreach(anal->vartypes, iter, vti)
		if (!strcmp (name, vti->name)) {
			r_list_unlink (anal->vartypes, vti);
			return R_TRUE;
		}
	return R_FALSE;
}

R_API RAnalVarType *r_anal_var_type_get(RAnal *anal, const char *name) {
	RAnalVarType *vti;
	RListIter *iter;

	r_list_foreach(anal->vartypes, iter, vti)
		if (!strcmp (name, vti->name))
			return vti;
	return NULL;
}

R_API int r_anal_var_add(RAnal *anal, RAnalFcn *fcn, ut64 from, int delta, int type, const char *vartype, const char *name, int set) {
	RAnalVar *var, *vari;
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

R_API int r_anal_var_del(RAnal *anal, RAnalFcn *fcn, int delta, int type) {
	RAnalVar *vari;
	RListIter *iter;

	r_list_foreach(fcn->vars, iter, vari)
		if (vari->type == type && vari->delta == delta) {
			r_list_unlink (fcn->vars, vari);
			return R_TRUE;
		}
	return R_FALSE;
}

R_API RAnalVar *r_anal_var_get(RAnal *anal, RAnalFcn *fcn, int delta, int type) {
	RAnalVar *vari;
	RListIter *iter;

	r_list_foreach(fcn->vars, iter, vari)
		if (vari->type == type && vari->delta == delta)
			return vari;
	return NULL;
}

R_API const char *r_anal_var_type_to_str (RAnal *anal, int type) {
	switch(type) {
	case R_ANAL_VAR_TYPE_GLOBAL: return "global";
	case R_ANAL_VAR_TYPE_LOCAL:  return "local";
	case R_ANAL_VAR_TYPE_ARG:    return "arg";
	case R_ANAL_VAR_TYPE_ARGREG: return "fastarg";
	}
	return "(?)";
}

R_API int r_anal_var_access_add(RAnal *anal, RAnalVar *var, ut64 from, int set) {
	RAnalVarAccess *acc, *acci;
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

R_API int r_anal_var_access_del(RAnal *anal, RAnalVar *var, ut64 from) {
	RAnalVarAccess *acci;
	RListIter *iter;

	r_list_foreach(var->accesses, iter, acci)
		if (acci->addr == from) {
			r_list_unlink (var->accesses, acci);
			return R_TRUE;
		}
	return R_TRUE;
}

R_API RAnalVarAccess *r_anal_var_access_get(RAnal *anal, RAnalVar *var, ut64 from) {
	RAnalVarAccess *acci;
	RListIter *iter;

	r_list_foreach(var->accesses, iter, acci)
		if (acci->addr == from)
			return acci;
	return NULL;
}
