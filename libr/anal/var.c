/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_cons.h>
#include <r_list.h>

#define DB a->sdb_fcns

struct VarType {
	char kind;
	char *type;
	int size;
	char *name;
};

#define SDB_VARTYPE_FMT "czdz"

// WHAT ABOUT REGISTER VARIABLES?

#define EXISTS(x,y...) snprintf (key, sizeof (key)-1, x, ##y), sdb_exists(DB,key)
#define SETKEY(x,y...) snprintf (key, sizeof (key)-1, x, ##y);
#define SETKEY2(x,y...) snprintf (key2, sizeof (key)-1, x, ##y);
#define SETVAL(x,y...) snprintf (val, sizeof (val)-1, x, ##y);

#if 0
// DUPPED FUNCTIONALITY
// kind = char? 'a'rg 'v'var (local, in frame), 'A' fast arg, register
#endif

R_API int r_anal_fcn_arg_add (RAnal *a, ut64 fna, int scope, int delta, const char *type, const char *name) {
	return r_anal_var_add (a, fna, scope, delta, 'a', type, 4, name);
}

R_API int r_anal_fcn_var_add (RAnal *a, ut64 fna, int scope, int delta, const char *type, const char *name) {
	return r_anal_var_add (a, fna, scope, delta, 'v', type, 4, name);
}

R_API int r_anal_var_add (RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, const char *name) {
	char *var_def;
	if (!kind) kind ='v';
	if (!type) type = "int";
//eprintf ("VAR ADD 0x%llx  - %d\n", addr, delta);
	switch (kind) {
	case 'a':
	case 'r':
	case 'v':
		break;
	default:
		eprintf ("Invalid var kind '%c'\n", kind);
		return R_FALSE;
	}
	var_def = sdb_fmt (0,"%c,%s,%d,%s", kind, type, size, name);
	if (scope>0) {
		/* local variable */
		char *fcn_key = sdb_fmt (1, "fcn.0x%"PFMT64x".%c", addr, kind);
		char *var_key = sdb_fmt (2, "var.0x%"PFMT64x".%c.%d.%d", addr, kind, scope, delta);
		char *name_key = sdb_fmt (3, "var.0x%"PFMT64x".%c.%d.%s", addr, kind, scope, name);
		char *shortvar = sdb_fmt (4, "%d.%d", scope, delta);
		sdb_array_add (DB, fcn_key, shortvar, 0);
		sdb_set (DB, var_key, var_def, 0);
		sdb_num_set (DB, name_key, delta, 0);
	} else {
		/* global variable */
		char *var_global = sdb_fmt (1, "var.0x%"PFMT64x, addr);
		char *var_def = sdb_fmt (2,"%c.%s,%d,%s", kind, type, size, name);
		sdb_array_add (DB, var_global, var_def, 0);
	}
	return R_TRUE;
}

R_API int r_anal_var_delete (RAnal *a, ut64 var_addr, const char kind, int scope, int delta) {
	if (scope>0) {
		// TODO
	} else {
		// TODO
	}
	r_anal_var_access_clear (a, var_addr, scope, delta);
	return R_TRUE;
}

R_API RAnalVar *r_anal_var_get (RAnal *a, ut64 addr, char kind, int scope, int delta) {
	RAnalVar *av;
	struct VarType vt;
	RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, 0);
	if (!fcn)
		return NULL;
	if (delta<0) {
		kind = 'v';
		delta = -delta;
	}
	char *vardef = sdb_get (DB,
		sdb_fmt (0, "var.0x%"PFMT64x".%c.%d.%d",
			fcn->addr, kind, scope, delta), 0);
	if (!vardef)
		return NULL;
	sdb_fmt_tobin (vardef, SDB_VARTYPE_FMT, &vt);

	av = R_NEW0 (RAnalVar);
	av->addr = addr;
	av->scope = scope;
	av->delta = delta;
	av->name = strdup (vt.name);
	av->size = vt.size;
	av->type = strdup (vt.type);

	sdb_fmt_free (&vt, SDB_VARTYPE_FMT);
	// TODO:
	// get name from sdb
	// get size from sdb
	// get type from sdb
	return av;
}

R_API void r_anal_var_free (RAnalVar *av) {
	free (av);
}

/* (columns) elements in the array value */
#define R_ANAL_VAR_SDB_KIND 0 /* char */
#define R_ANAL_VAR_SDB_TYPE 1 /* string */
#define R_ANAL_VAR_SDB_SIZE 2 /* number */
#define R_ANAL_VAR_SDB_NAME 3 /* string */

R_API int r_anal_var_check_name(const char *name) {
	// restrict length
	// name is not base64'd . because no specials can be contained
	// TODO: check that new_name is valid. this is a hack
	if (*name=='0' || atoi (name)>0) return 0;
	if (strchr (name, '.')) return 0;
	if (strchr (name, ',')) return 0;
	if (strchr (name, ' ')) return 0;
	if (strchr (name, '=')) return 0;
	if (strchr (name, '/')) return 0;
	return 1;
}

// afvn local_48 counter
R_API int r_anal_var_rename (RAnal *a, ut64 var_addr, int scope, char kind, const char *old_name, const char *new_name) {
	char key[128];
	char *stored_name;
	int delta;
	if (!r_anal_var_check_name (new_name))
		return 0;
	if (scope>0) { // local
		SETKEY ("var.0x%"PFMT64x".%c.%d.%s", var_addr, kind, scope, old_name);
		delta = sdb_num_get (DB, key, 0);
		if (!delta) return 0;
		sdb_unset (DB, key, 0);
		SETKEY ("var.0x%"PFMT64x".%c.%d.%s", var_addr, kind, scope, new_name);
		sdb_num_set (DB, key, delta, 0);
		SETKEY ("var.0x%"PFMT64x".%c.%d.%d", var_addr, kind, scope, delta);
		sdb_array_set (DB, key, R_ANAL_VAR_SDB_NAME, new_name, 0);
	} else { // global
		SETKEY ("var.0x%"PFMT64x, var_addr);
		stored_name = sdb_array_get (DB, key, R_ANAL_VAR_SDB_NAME, 0);
		if (!stored_name) return 0;
		if (stored_name != old_name) return 0;
		sdb_unset (DB, key, 0);
		SETKEY ("var.0x%"PFMT64x, var_addr);
		sdb_array_set (DB, key, R_ANAL_VAR_SDB_NAME, new_name, 0);
	}
	// var.sdb_hash(old_name)=var_addr.scope.delta
	return 1;
}

#define R_ANAL_VAR_KIND_ARG 'a'
#define R_ANAL_VAR_KIND_VAR 'v'
#define R_ANAL_VAR_KIND_REG 'r'

// avr
R_API int r_anal_var_access (RAnal *a, ut64 var_addr, char kind, int scope, int delta, int xs_type, ut64 xs_addr) {
	const char *var_global;
	const char *xs_type_str = xs_type? "writes": "reads";
// TODO: kind is not used
	if (scope>0) { // local
		char *var_local = sdb_fmt (0, "var.0x%"PFMT64x".%d.%d.%s",
			var_addr, scope, delta, xs_type_str);
		return sdb_array_add_num (DB, var_local, xs_addr, 0);
	}
	// global
	sdb_add (DB, sdb_fmt (0,"var.0x%"PFMT64x, var_addr), "a,", 0);
	var_global = sdb_fmt (0, "var.0x%"PFMT64x".%s", var_addr, xs_type_str);
	return sdb_array_add_num (DB, var_global, xs_addr, 0);
}

R_API void r_anal_var_access_clear (RAnal *a, ut64 var_addr, int scope, int delta) {
	char key[128], key2[128];
	if (scope>0) { // local arg or var
		SETKEY ("var.0x%"PFMT64x".%d.%d.%s", var_addr, scope, delta, "writes");
		SETKEY2 ("var.0x%"PFMT64x".%d.%d.%s", var_addr, scope, delta, "reads");
	} else { // global
		SETKEY ("var.0x%"PFMT64x".%s", var_addr, "writes");
		SETKEY2 ("var.0x%"PFMT64x".%s", var_addr, "reads");
	}
	sdb_unset (DB, key, 0);
	sdb_unset (DB, key2, 0);
}

#if 0
#if FCN_SDB
#if 0
  fcn.0x80480.v=8,16,24
  fcn.0x80480.v.8=name,type
#endif
	char key[1024], val[1024], *e;
	if (EXISTS("fcn.0x%08"PFMT64x, fna)) {
		SETKEY("fcn.0x%08"PFMT64x".%c", fna, kind);
		if (sdb_array_contains_num (DB, key, delta, 0))
			return R_FALSE;
		e = sdb_encode (name, -1);
		if (e) {
			sdb_array_push (DB, key, e, 0);
			sdb_array_push_num (DB, key, delta, 0);
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
#endif

R_API int r_anal_fcn_var_del_bydelta (RAnal *a, ut64 fna, const char kind, int scope, ut32 delta) {
	int idx;
	char key[128], val[128], *v;
	SETKEY("fcn.0x%08"PFMT64x".%c", fna, kind);
	v = sdb_itoa (delta, val, 10);
	idx = sdb_array_indexof (DB, key, v, 0);
	if (idx != -1) {
		sdb_array_delete (DB, key, idx, 0);
		SETKEY ("fcn.0x%08"PFMT64x".%c.%d", fna, kind, delta);
		sdb_unset (DB, key, 0);
	}
	return R_FALSE;
}

R_API RList *r_anal_var_list(RAnal *a, RAnalFunction *fcn, int kind) {
	char *varlist;
	RList *list = r_list_new ();
	if (!a|| !fcn)
		return list;
	if (!kind) kind = 'v'; // by default show vars
	varlist = sdb_get (DB, sdb_fmt (0, "fcn.0x%"PFMT64x".%c",
		fcn->addr, kind), 0);
	if (varlist) {
		char *next, *ptr = varlist;
		if (varlist && *varlist) {
			do {
				struct VarType vt;
				char *word = sdb_anext (ptr, &next);
				char *vardef = sdb_get (DB, sdb_fmt (1,
					"var.0x%"PFMT64x".%c.%s",
					fcn->addr, kind, word), 0);
				int delta = atoi (word+2);
				if (vardef) {
					sdb_fmt_init (&vt, SDB_VARTYPE_FMT);
					sdb_fmt_tobin (vardef, SDB_VARTYPE_FMT, &vt);
					RAnalVar *av;
					av = R_NEW0 (RAnalVar);
					av->delta = delta;
					av->kind = kind;
					av->name = strdup (vt.name);
					av->size = vt.size;
					av->type = strdup (vt.type);
					r_list_append (list, av);
					sdb_fmt_free (&vt, SDB_VARTYPE_FMT);
					free (vardef);
				} else {
					eprintf ("Cannot find '%s'\n", word);
				}
				ptr = next;
			} while (next);
		}
	}
	free (varlist);
	return list;
}

R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, int kind) {
	RList *list = r_anal_var_list(anal, fcn, kind);
	RAnalVar *var;
	RListIter *iter;
	r_list_foreach (list, iter, var) {
		if (var->kind == kind)
			anal->printf ("%s %s %s @ %s%s0x%x\n",
				kind=='v'?"var":"arg",
				var->type,
				var->name,
				anal->reg->name[R_REG_NAME_BP],
				(kind=='v')?"-":"+",
				var->delta
			);
	}
}
