/* radare - LGPL - Copyright 2010 */
/*   nibble<.ds@gmail.com> */
/*   pancake<nopcode.org> */

#include <r_anal.h>
#include <r_util.h>
#include <r_cons.h>
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
	RAnalVarAccess *access = R_NEW (RAnalVarAccess);
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
		free (var);
	}
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
	r_list_foreach (anal->vartypes, iter, vti)
		if (!strcmp (name, vti->name))
			return vti;
	return NULL;
}

static int cmpdelta(RAnalVar *a, RAnalVar *b) {
	return (a->delta - b->delta);
}

R_API int r_anal_var_add(RAnal *anal, RAnalFcn *fcn, ut64 from, int delta, int type, const char *vartype, const char *name, int set) {
	RAnalVar *var, *vari;
	RListIter *iter;
	if (from != 0LL)
	r_list_foreach (fcn->vars, iter, vari)
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
	if (from != 0LL)
		r_anal_var_access_add (anal, var, from, set);
	r_list_add_sorted (fcn->vars, var, (RListComparator)cmpdelta);
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
	r_list_foreach (fcn->vars, iter, vari)
		if ((type==-1||vari->type == type) && vari->delta == delta)
			return vari;
	return NULL;
}

// XXX: rename function type? i think this is 'scope' 
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
	r_list_foreach (var->accesses, iter, acci)
		if (acci->addr == from)
			return acci;
	return NULL;
}


// XXX: move into core_anal?
R_API int r_anal_var_list_show(RAnal *anal, RAnalFcn *fcn, ut64 addr) {
	RAnalVar *v;
	RListIter *iter;

	if (!fcn || !fcn->vars) {
		eprintf ("No function here\n");
		return R_FALSE;
	}
	r_list_foreach (fcn->vars, iter, v) {
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			//ut32 value = r_var_dbg_read(v->delta);
			if (v->array>1)
				r_cons_printf("%s %s %s[%d] = ",
					r_anal_var_type_to_str(anal, v->type), v->vartype,
					v->array, v->name);
			else r_cons_printf("%s %s %s = ", r_anal_var_type_to_str (anal, v->type),
				v->vartype, v->name);
			// TODO: implement r_var_dbg_read using r_vm or r_num maybe?? sounds dupped
			// XXX: not fully implemented
			r_cons_printf ("0x%"PFMT64x, 0LL);
			//r_var_print_value(anal, v);
			/* TODO: detect pointer to strings and so on */
			//if (string_flag_offset(NULL, buf, value, 0))
			//	r_cons_printf(" ; %s\n", buf);
			//else 
			r_cons_newline();
		}
	}

	return R_TRUE;
}

/* 0,0 to list all */
R_API int r_anal_var_list(RAnal *anal, RAnalFcn *fcn, ut64 addr, int delta) {
	RAnalVarAccess *x;
	RAnalVar *v;
	RListIter *iter, *iter2;

	if (!fcn || !fcn->vars) {
		eprintf ("No function here\n");
		return R_FALSE;
	}
	r_list_foreach (fcn->vars, iter, v) {
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
			r_cons_printf("0x%08llx - 0x%08llx type=%s type=%s name=%s delta=%d array=%d\n",
				v->addr, v->eaddr, r_anal_var_type_to_str(anal, v->type),
				v->vartype, v->name, v->delta, v->array);
			r_list_foreach (v->accesses, iter2, x) {
				r_cons_printf("  0x%08llx %s\n", x->addr, x->set?"set":"get");
			}
		}
	}

	return 0;
}
