/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_cons.h>
#include <r_list.h>

// Use sdb_vars ?
#define DB a->sdb_fcns

#define EXISTS(x,y...) snprintf (key, sizeof(key)-1,x,##y),sdb_exists(DB,key)
#define SETKEY(x,y...) snprintf (key, sizeof (key)-1, x,##y);
// DUPPED FUNCTIONALITY
// kind = char? 'a'rg 'v'var (local, in frame), 'A' fast arg, register
R_API int r_anal_fcn_var_add (RAnal *a, ut64 fna, const char kind, int scope, ut32 index, const char *name, const char *type) {
#if FCN_SDB
#if 0
  fcn.0x80480.locals=8,16,24
  fcn.0x80480.locals.8=name,type
#endif
	char key[1024], val[1024], *e;
	if (EXISTS("fcn.0x%08"PFMT64x, fna)) {
		SETKEY("fcn.0x%08"PFMT64x".%c", fna, kind);
		if (sdb_array_contains_num (DB, key, index, 0))
			return R_FALSE;
		e = sdb_encode (name, -1);
		if (e) {
			sdb_array_push (DB, key, e, 0);
			sdb_array_push_num (DB, key, index, 0);
			free (e);
		} else {
			eprintf ("Cannot encode string\n");
		}
	} else {
		eprintf ("r_anal_fcn_local_add: cannot find function.\n");
		return R_FALSE;
	}
#endif
	return R_TRUE;
}

R_API int r_anal_fcn_var_del_byindex (RAnal *a, ut64 fna, const char kind, int scope, ut32 index) {
	char key[128], val[128], *v;
	SETKEY("fcn.0x%08"PFMT64x".%c", fna, kind);
	v = sdb_itoa (val, index, 10);
	int idx = sdb_array_indexof (DB, key, v,0);
	if (idx != -1) {
		sdb_array_delete (DB, key, idx, 0);
		SETKEY("fcn.0x%08"PFMT64x".%c.%d", fna, kind, index);
		sdb_unset (DB, key, 0);
	}
	return R_FALSE;
}

// ---------------
// TODO: limit recursivity

R_API RAnalVar *r_anal_var_new() {
	RAnalVar *var = R_NEW0 (RAnalVar);
	if (var)
		var->accesses = r_anal_var_access_list_new ();
	return var;
}

R_API RAnalVarAccess *r_anal_var_access_new() {			//Makro or inline
	return R_NEW0 (RAnalVarAccess);
}

R_API RList *r_anal_var_list_new() {
	RList *list = r_list_new ();
	list->free = &r_anal_var_free;
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
		if (((RAnalVar*)var)->type)
			free (((RAnalVar*)var)->type);
		if (((RAnalVar*)var)->accesses)
			r_list_free (((RAnalVar*)var)->accesses);
		free (var);
	}
}

R_API void r_anal_var_access_free(void *access) {
	free (access);
}

static int cmpdelta(RAnalVar *a, RAnalVar *b) {
	return (a->delta - b->delta);
}

/* Add local variable for selected function */
R_API int r_anal_var_add(RAnal *anal, RAnalFunction *fcn, ut64 from, int delta, int scope, RAnalType *type, const char *name, int set) {
	RAnalVar *var, *vari;
	RListIter *iter;
	if (!fcn) {
		return R_FALSE;
	}
	if (from != 0LL)
	r_list_foreach (fcn->vars, iter, vari)
		if (vari->type == type && vari->delta == delta)
			return r_anal_var_access_add (anal, vari, from, set);
// TODO r_anal_fcn_var_add
	if (!(var = r_anal_var_new ()))
		return R_FALSE;
	if (name)
		var->name = strdup (name);
	if (type)
		var->type = type;
	var->type = type;
	if ((scope & R_ANAL_VAR_SCOPE_ARG) || (scope & R_ANAL_VAR_SCOPE_ARGREG))
		fcn->nargs++;
	var->delta = delta;
	if (from != 0LL)
		r_anal_var_access_add (anal, var, from, set);
	r_list_add_sorted (fcn->vars, var, (RListComparator)cmpdelta);
	return R_TRUE;
}

/* Remove local variable from selected function */
R_API int r_anal_var_del(RAnal *anal, RAnalFunction *fcn, int delta, int scope) {
	RAnalVar *vari;
	RListIter *iter;
	/* No _safe loop necessary because we return immediately after the delete. */
	r_list_foreach(fcn->vars, iter, vari)
		if (vari->scope == scope && vari->delta == delta) {
			r_list_unlink (fcn->vars, vari);
			return R_TRUE;
		}
	return R_FALSE;
}

R_API RAnalVar *r_anal_var_get(RAnal *anal, RAnalFunction *fcn, int delta, int scope) {
	RAnalVar *vari;
	RListIter *iter;

	r_list_foreach (fcn->vars, iter, vari)
	if ((scope==-1||vari->scope == scope) && vari->delta == delta)
		return vari;

	return NULL;
}

R_API const char *r_anal_var_scope_to_str (RAnal *anal, int scope) {
	if (scope & R_ANAL_VAR_SCOPE_GLOBAL)
		return "global";
	else if (scope & R_ANAL_VAR_SCOPE_LOCAL)
		return "local";
	else if (scope & R_ANAL_VAR_SCOPE_ARG)
		return "arg";
	else if (scope & R_ANAL_VAR_SCOPE_ARGREG)
		return "fastarg";
	else if (scope & R_ANAL_VAR_SCOPE_RET)
		return "ret";
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
	/* No _safe loop necessary because we return immediately after the delete. */
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
R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, ut64 addr) {
	RAnalVar *v;
	RListIter *iter;
	if (fcn && fcn->vars)
	r_list_foreach (fcn->vars, iter, v) {
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
#if 0
			char *s = r_anal_type_field_to_string (anal, fcn->addr, v->name);
			var a = ("frame.${addr}.${name}")
			a[0] = "type"
			a[1] = offset
			a[2] = arraysize
			eprintf ("%s\n", s);
			free (s);
			//ut32 value = r_var_dbg_read(v->delta);
			if (v->type->type == R_ANAL_TYPE_ARRAY)
				eprintf ("%s %s %s[%d] = ",
					r_anal_var_scope_to_str (anal, v->scope),
					r_anal_type_to_str (anal, v->type, ""),
					v->name, (int)v->type->custom.a->count);
			else
				eprintf ("%s %s %s = ", r_anal_var_scope_to_str (anal, v->scope),
					r_anal_type_to_str (anal, v->type, ""), v->name);
			// TODO: implement r_var_dbg_read using r_vm or r_num maybe?? sounds dupped
			// XXX: not fully implemented
			eprintf ("0x%"PFMT64x, 0LL);
			//r_var_print_value(anal, v);
			/* TODO: detect pointer to strings and so on */
			//if (string_flag_offset(NULL, buf, value, 0))
			//	r_cons_printf(" ; %s\n", buf);
			//else
			eprintf ("\n"); //r_cons_newline();
#endif
		}
	}
}

/* 0,0 to list all */
R_API void r_anal_var_list(RAnal *anal, RAnalFunction *fcn, ut64 addr, int delta) {
	RAnalVarAccess *x;
	RAnalVar *v;
	RListIter *iter, *iter2;
	if (fcn && fcn->vars)
	r_list_foreach (fcn->vars, iter, v) {
		if (addr == 0 || (addr >= v->addr && addr <= v->eaddr)) {
eprintf ("TODO\n");
#if 0
			if (v->type->type == R_ANAL_TYPE_ARRAY)
				eprintf ("0x%08"PFMT64x" - 0x%08"PFMT64x" type=%s type=%s name=%s delta=%d array=%d\n",
					v->addr, v->eaddr, r_anal_var_scope_to_str(anal, v->scope),
					r_anal_type_to_str (anal, v->type, ""), v->name, v->delta, (int)v->type->custom.a->count);
			else
				eprintf ("0x%08"PFMT64x" - 0x%08"PFMT64x" type=%s type=%s name=%s delta=%d\n",
					v->addr, v->eaddr, r_anal_var_scope_to_str(anal, v->scope),
					r_anal_type_to_str(anal, v->type, ""), v->name, v->delta);

			r_list_foreach (v->accesses, iter2, x) {
				eprintf ("  0x%08"PFMT64x" %s\n", x->addr, x->set?"set":"get");
			}
#endif
		}
	}
}
