/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <r_anal.h>
#include <r_util.h>
#include <r_cons.h>
#include <r_list.h>

// Use sdb_vars ?
#define DB a->sdb_fcns

// WHAT ABOUT REGISTER VARIABLES?

#define EXISTS(x,y...) snprintf (key, sizeof (key)-1, x, ##y), sdb_exists(DB,key)
#define SETKEY(x,y...) snprintf (key, sizeof (key)-1, x, ##y);
#define SETKEY2(x,y...) snprintf (key2, sizeof (key)-1, x, ##y);
#define SETVAL(x,y...) snprintf (val, sizeof (val)-1, x, ##y);

// DUPPED FUNCTIONALITY
// kind = char? 'a'rg 'v'var (local, in frame), 'A' fast arg, register
R_API int r_anal_fcn_var_add (RAnal *a, ut64 fna, const char kind, int scope, ut32 delta, const char *type, const char *name) {
	eprintf ("r_anal_fcn_var_add is deprecated");
	return r_anal_var_add (a, fna, scope, delta, kind, type, 4, name);
}

R_API int r_anal_var_add (RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, const char *name) {
	char key[128], key2[128], val[128];
	switch (kind) {
	case 'a':
	case 'r':
	case 'v':
		break;
	default:
		eprintf ("Invalid var kind\n");
		return R_FALSE;
	}
	if (scope>0) {
		// local
		SETKEY("fcn.0x%"PFMT64x".%c", addr, kind);
		SETVAL("var.0x%"PFMT64x".%c.%d.%d", addr, kind, scope, delta);
		sdb_array_add (DB, key, val, 0);
		strcpy (key, val);
		SETVAL("%s,%d,%s", type, size, name);
		sdb_set (DB, key, val, 0);
#if 0
	fcn.0x80480.a=1.8,1.16
	fcn.0x80480.a.1.8=type,size,name
	fcn.0x80480.a.1.16=type,size,name
#endif
		SETKEY("var.0x%"PFMT64x".%d.%d", addr, scope, delta);
		// TODO: link to function
		// fcn.<addr>.kind+=var.0x%"PFMT64x"..
	} else {
		// global
		snprintf (key, "var.0x%"PFMT64x, addr);
	}
	sdb_array_add (DB, key, val, 0);
	return R_TRUE;
}

R_API int r_anal_var_delete (RAnal *a, ut64 var_addr, const char *kind, int scope, int delta) {
	if (scope>0) {
		// TODO
	} else {
		// TODO
	}
	r_anal_var_access_clear (a, var_addr, scope, delta);
	return R_TRUE;
}

R_API RAnalVar *r_anal_var_get (RAnal *a, ut64 addr, const char *kind, int scope, int delta) {
	RAnalVar *av = R_NEW0 (RAnalVar);
	av->addr = addr;
	av->scope = scope;
	av->delta = delta;
	// TODO:
	// get name from sdb
	// get size from sdb
	// get type from sdb
	return av;
}

R_API void r_anal_var_free (RAnalVar *av) {
	free (av);
}

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

// avr 1,4 counter @ var_addr
R_API int r_anal_var_rename (RAnal *a, ut64 var_addr, int scope, int delta, const char *new_name) {
	ut32 hash;
	char key[128], *old_name, val[128];
	if (!r_anal_var_check_name (new_name))
		return 0;
	if (scope>0) { // local
		SETKEY ("var.0x%"PFMT64x".%d.%d", var_addr, scope, delta);
		old_name = sdb_array_get (DB, key, R_ANAL_VAR_SDB_NAME, 0);
		if (!old_name) return 0;
		SETKEY ("var.%s.%d", old_name, scope);
		sdb_unset (DB, key, 0);
		free (old_name);
		SETKEY ("var.%s.%d", new_name, scope);
		sdb_num_set (DB, key, var_addr, 0);
		SETKEY ("var.0x%"PFMT64x".%d.%d", hash, scope, delta);
		sdb_array_set (DB, key, R_ANAL_VAR_SDB_NAME, new_name, 0);
	} else { // global
		SETKEY ("var.0x%"PFMT64x, var_addr);
		old_name = sdb_array_get (DB, key, R_ANAL_VAR_SDB_NAME, 0);
		if (!old_name) return 0;
		SETKEY ("var.%s", old_name);
		sdb_unset (DB, key, 0);
		free (old_name);
		SETKEY ("var.%s.%d", new_name, scope);
		sdb_num_set (DB, key, var_addr, 0);
		SETKEY ("var.0x%"PFMT64x".%d.%d", hash, scope, delta);
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
	const char *xs_type_str = xs_type? "writes": "reads";
	char key[128];
// TODO: kind is not used
	if (scope>0) { // local
		SETKEY ("var.0x%"PFMT64x, var_addr);
		//sdb_add (DB, key, var, 0);
		SETKEY ("var.0x%"PFMT64x".%d.%d.%s", var_addr, scope, delta, xs_type_str);
	} else { // global
		SETKEY ("var.0x%"PFMT64x, var_addr);
		sdb_add (DB, key, "a,", 0);
		SETKEY ("var.0x%"PFMT64x".%s", var_addr, xs_type_str);
	}
	return sdb_array_add_num (DB, key, xs_addr, 0);
}

// DONE
// avx-
R_API void r_anal_var_access_clear (RAnal *a, ut64 var_addr, int scope, int delta) {
	char key[128], key2[128];
	if (scope>0) { // local
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
  fcn.0x80480.locals=8,16,24
  fcn.0x80480.locals.8=name,type
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
	char key[128], val[128], *v;
	SETKEY("fcn.0x%08"PFMT64x".%c", fna, kind);
	v = sdb_itoa (val, delta, 10);
	int idx = sdb_array_indexof (DB, key, v, 0);
	free (v);
	if (idx != -1) {
		sdb_array_delete (DB, key, idx, 0);
		SETKEY("fcn.0x%08"PFMT64x".%c.%d", fna, kind, delta);
		sdb_unset (DB, key, 0);
	}
	free (v);
	return R_FALSE;
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
