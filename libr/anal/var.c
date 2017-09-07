/* radare - LGPL - Copyright 2010-2017 - pancake, oddcoder */

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

#define EXISTS(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__), sdb_exists (DB, key)
#define SETKEY(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__);
#define SETKEY2(x, ...) snprintf (key2, sizeof (key) - 1, x, ## __VA_ARGS__);
#define SETVAL(x, ...) snprintf (val, sizeof (val) - 1, x, ## __VA_ARGS__);
R_API bool r_anal_var_display(RAnal *anal, int delta, char kind, const char *type) {
	char *fmt = r_anal_type_format (anal, type);
	RRegItem *i;
	if (!fmt) {
		eprintf ("type:%s doesn't exist\n", type);
		return false;
	}
	bool usePxr = !strcmp (type, "int"); // hacky but useful
	switch (kind) {
	case R_ANAL_VAR_KIND_REG:
		i = r_reg_index_get (anal->reg, delta);
		if (i) {
			if (usePxr) {
				anal->cb_printf ("pxr $w @r:%s\n", i->name);
			} else {
				anal->cb_printf ("pf r (%s)\n", i->name);
			}
		} else {
			eprintf ("register not found\n");
		}
		break;
	case R_ANAL_VAR_KIND_BPV:
		if (delta > 0) {
			if (usePxr) {
				anal->cb_printf ("pxr $w @%s+0x%x\n", anal->reg->name[R_REG_NAME_BP], delta);
			} else {
				anal->cb_printf ("pf %s @%s+0x%x\n", fmt, anal->reg->name[R_REG_NAME_BP], delta);
			}
		} else {
			if (usePxr) {
				anal->cb_printf ("pxr $w @%s-0x%x\n", anal->reg->name[R_REG_NAME_BP], -delta);
			} else {
				anal->cb_printf ("pf %s @%s-0x%x\n", fmt, anal->reg->name[R_REG_NAME_BP], -delta);
			}
		}
		break;
	case R_ANAL_VAR_KIND_SPV:
		if (usePxr) {
			anal->cb_printf ("pxr $w @%s+0x%x\n", anal->reg->name[R_REG_NAME_SP], delta);
		} else {
			anal->cb_printf ("pf %s @ %s+0x%x\n", fmt, anal->reg->name[R_REG_NAME_SP], delta);
		}
		break;
	}
	free (fmt);
	return true;
}

R_API bool r_anal_var_add(RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, const char *name) {
	if (!a) {
		return false;
	}
	if (!kind) {
		kind = R_ANAL_VAR_KIND_BPV;
	}
	if (!type) {
		type = "int";
	}
	switch (kind) {
	case R_ANAL_VAR_KIND_BPV: // base pointer var/args
	case R_ANAL_VAR_KIND_SPV: // stack pointer var/args
	case R_ANAL_VAR_KIND_REG: // registers args
		break;
	default:
		eprintf ("Invalid var kind '%c'\n", kind);
		return false;
	}
	const char *var_def = sdb_fmt (0, "%c,%s,%d,%s", kind, type, size, name);
	if (scope > 0) {
		const char *sign = "";
		if (delta < 0) {
			delta = -delta;
			sign = "_";
		}
		/* local variable */
		const char *fcn_key = sdb_fmt (1, "fcn.0x%"PFMT64x ".%c", addr, kind);
		const char *var_key = sdb_fmt (2, "var.0x%"PFMT64x ".%c.%d.%s%d", addr, kind, scope, sign, delta);
		const char *name_key = sdb_fmt (3, "var.0x%"PFMT64x ".%d.%s", addr, scope, name);
		const char *shortvar = sdb_fmt (4, "%d.%s%d", scope, sign, delta);
		sdb_array_add (DB, fcn_key, shortvar, 0);
		sdb_set (DB, var_key, var_def, 0);
		if (*sign) {
			delta = -delta;
		}
		const char *name_val = sdb_fmt (5, "%c,%d", kind, delta);
		sdb_set (DB, name_key, name_val, 0);
	} else {
		/* global variable */
		const char *var_global = sdb_fmt (1, "var.0x%"PFMT64x, addr);
		const char *var_def = sdb_fmt (2, "%c.%s,%d,%s", kind, type, size, name);
		sdb_array_add (DB, var_global, var_def, 0);
	}
// ls_sort (DB->ht->list, mystrcmp);
	return true;
}

R_API int r_anal_var_retype(RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, const char *name) {
	if (!a) {
		return false;
	}
	if (kind < 1) {
		kind = R_ANAL_VAR_KIND_BPV;
	}
	if (!type) {
		type = "int";
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, 0);
	if (!fcn) {
		eprintf ("Cant find function here\n");
		return false;
	}
	if (size == -1) {
		RList *list = r_anal_var_list (a, fcn, kind);
		RListIter *iter;
		RAnalVar *var;
		r_list_foreach (list, iter, var) {
			if (delta == -1 && !strcmp (var->name, name)) {
				delta = var->delta;
				size = var->size;
				break;
			}
		}
		r_list_free (list);
	}
	switch (kind) {
	case R_ANAL_VAR_KIND_REG:
	case R_ANAL_VAR_KIND_BPV:
	case R_ANAL_VAR_KIND_SPV:
		break;
	default:
		eprintf ("Invalid var kind '%c'\n", kind);
		return false;
	}
	const char *var_def = sdb_fmt (0, "%c,%s,%d,%s", kind, type, size, name);
	if (scope > 0) {
		char *sign = delta> 0? "": "_";
		/* local variable */
		const char *fcn_key = sdb_fmt (1, "fcn.0x%"PFMT64x ".%c", fcn->addr, kind);
		const char *var_key = sdb_fmt (2, "var.0x%"PFMT64x ".%c.%d.%s%d", fcn->addr, kind, scope, sign, R_ABS(delta));
		const char *name_key = sdb_fmt (3, "var.0x%"PFMT64x ".%d.%s", fcn->addr, scope, name);
		const char *shortvar = sdb_fmt (4, "%d.%s%d", scope, sign, R_ABS(delta));
		const char *name_val = sdb_fmt (5, "%c,%d", kind, delta);
		sdb_array_add (DB, fcn_key, shortvar, 0);
		sdb_set (DB, var_key, var_def, 0);
		sdb_set (DB, name_key, name_val, 0);
		Sdb *TDB = a->sdb_types;
		const char *type_kind = sdb_const_get (TDB, type, 0);
		if (type_kind && r_str_startswith (type_kind, "struct")) {
			char *field;
			int field_n;
			char *type_key = r_str_newf ("%s.%s", type_kind, type);
			for (field_n = 0; (field = sdb_array_get (TDB, type_key, field_n, NULL)); field_n++) {
				char *field_key = r_str_newf ("%s.%s", type_key, field);
				char *field_type = sdb_array_get (TDB, field_key, 0, NULL);
				ut64 field_offset = sdb_array_get_num (TDB, field_key, 1, NULL);
				if (field_offset != 0) { // delete variables which are overlayed by structure
					r_anal_var_delete (a, addr, kind, scope, delta + field_offset);
				}
				free (field_type);
				free (field_key);
				free (field);
			}
			free (type_key);
		}
	} else {
		/* global variable */
		const char *var_global = sdb_fmt (1, "var.0x%"PFMT64x, fcn->addr);
		sdb_array_add (DB, var_global, var_def, 0);
	}
	return true;
}

R_API int r_anal_var_delete_all(RAnal *a, ut64 addr, const char kind) {
	RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, 0);
	if (fcn) {
		RAnalVar *v;
		RListIter *iter;
		RList *list = r_anal_var_list (a, fcn, kind);
		r_list_foreach (list, iter, v) {
			// r_anal_var_delete (a, addr, kind, v->scope, v->delta);
			r_anal_var_delete (a, addr, kind, 1, v->delta);
		}
		// XXX: i dont think we want to alocate and free by hand. r_anal_var_delete should be the list->free already
		r_list_free (list);
	}
	return 0;
}

R_API int r_anal_var_delete(RAnal *a, ut64 addr, const char kind, int scope, int delta) {
	RAnalVar *av = r_anal_var_get (a, addr, kind, scope, delta);
	if (!av) {
		return false;
	}
	if (scope > 0) {
		char *sign = "";
		if (delta < 0) {
			delta = -delta;
			sign = "_";
		}
		char *fcn_key = sdb_fmt (1, "fcn.0x%"PFMT64x ".%c", addr, kind);
		char *var_key = sdb_fmt (2, "var.0x%"PFMT64x ".%c.%d.%s%d", addr, kind, scope, sign, delta);
		char *name_key = sdb_fmt (3, "var.0x%"PFMT64x ".%d.%s", addr, scope, av->name);
		char *shortvar = sdb_fmt (4, "%d.%s%d", scope, sign, delta);
		sdb_array_remove (DB, fcn_key, shortvar, 0);
		sdb_unset (DB, var_key, 0);
		sdb_unset (DB, name_key, 0);
		if (*sign) {
			delta = -delta;
		}
	} else {
		char *var_global = sdb_fmt (1, "var.0x%"PFMT64x, addr);
		char *var_def = sdb_fmt (2, "%c.%s,%d,%s", kind, av->type, av->size, av->name);
		sdb_array_remove (DB, var_global, var_def, 0);
	}
	r_anal_var_free (av);
	r_anal_var_access_clear (a, addr, scope, delta);
	return true;
}

R_API bool r_anal_var_delete_byname(RAnal *a, RAnalFunction *fcn, int kind, const char *name) {
	char *varlist;
	if (!a || !fcn) {
		return false;
	}
	varlist = sdb_get (DB, sdb_fmt (0, "fcn.0x%"PFMT64x ".%c",
			fcn->addr, kind), 0);
	if (varlist) {
		char *next, *ptr = varlist;
		if (varlist && *varlist) {
			do {
				char *word = sdb_anext (ptr, &next);
				char *sign = strstr (word, "_");
				const char *vardef = sdb_const_get (DB, sdb_fmt (1,
						"var.0x%"PFMT64x ".%c.%s",
						fcn->addr, kind, word), 0);
				if (sign) {
					*sign = '-';
				}
				int delta = strlen (word) < 3? -1: atoi (word + 2);
				if (vardef) {
					const char *p = strchr (vardef, ',');
					if (p) {
						p = strchr (p + 1, ',');
						if (p) {
							p = strchr (p + 1, ',');
							if (p) {
								int mykind = vardef[0];
								if (!strcmp (p + 1, name)) {
									return r_anal_var_delete (a, fcn->addr,
										mykind, 1, delta);
								}
							}
						}
					}
				} else {
					eprintf ("Inconsistent Sdb storage, Cannot find '%s'\n", word);
				}
				ptr = next;
			} while (next);
		}
	}
	free (varlist);
	return false;
}

R_API RAnalVar *r_anal_var_get_byname(RAnal *a, RAnalFunction *fcn, const char *name) {
	if (!fcn || !a || !name) {
		// eprintf ("No something\n");
		return NULL;
	}
	char *name_key = sdb_fmt (-1, "var.0x%"PFMT64x ".%d.%s", fcn->addr, 1, name);
	const char *name_value = sdb_const_get (DB, name_key, 0);
	if (!name_value) {
		// eprintf ("Cant find key for %s\n", name_key);
		return NULL;
	}
	const char *comma = strchr (name_value, ',');
	if (comma) {
		int delta = r_num_math (NULL, comma + 1);
		// eprintf ("Silently failing (%s)\n", name_value);
		return r_anal_var_get (a, fcn->addr, *name_value, 1, delta);
	}
	return NULL;
}

R_API RAnalVar *r_anal_var_get(RAnal *a, ut64 addr, char kind, int scope, int delta) {
	RAnalVar *av;
	struct VarType vt = {
		0
	};
	char *sign = "";
	RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, 0);
	if (!fcn) {
		return NULL;
	}
	if (delta < 0) {
		delta = -delta;
		sign = "_";
	}
	const char *varkey = sdb_fmt (-1, "var.0x%"PFMT64x ".%c.%d.%s%d",
			fcn->addr, kind, scope, sign, delta);
	const char *vardef = sdb_const_get (DB, varkey, 0);
	if (!vardef) {
		return NULL;
	}
	if (*sign) {
		delta = -delta;
	}
	sdb_fmt_init (&vt, SDB_VARTYPE_FMT);
	sdb_fmt_tobin (vardef, SDB_VARTYPE_FMT, &vt);

	av = R_NEW0 (RAnalVar);
	if (!av) {
		sdb_fmt_free (&vt, SDB_VARTYPE_FMT);
		return NULL;
	}
	av->addr = fcn->addr;
	av->scope = scope;
	av->delta = delta;
	av->name = vt.name? strdup (vt.name): strdup ("unkown_var");
	av->size = vt.size;
	av->type = vt.type? strdup (vt.type): strdup ("unkown_type");
	av->kind = kind;
	sdb_fmt_free (&vt, SDB_VARTYPE_FMT);
	// TODO:
	// get name from sdb
	// get size from sdb
	// get type from sdb
	return av;
}

R_API void r_anal_var_free(RAnalVar *av) {
	if (av) {
		free (av->name);
		free (av->type);
		R_FREE (av);
	}
}

/* (columns) elements in the array value */
#define R_ANAL_VAR_SDB_KIND 0 /* char */
#define R_ANAL_VAR_SDB_TYPE 1 /* string */
#define R_ANAL_VAR_SDB_SIZE 2 /* number */
#define R_ANAL_VAR_SDB_NAME 3 /* string */

#define IS_NUMBER(x) ((x) >= '0' && (x) <= '9')

R_API bool r_anal_var_check_name(const char *name) {
	return !IS_NUMBER (*name) && strcspn (name, "., =/");
}

// afvn local_48 counter
R_API int r_anal_var_rename(RAnal *a, ut64 var_addr, int scope, char kind, const char *old_name, const char *new_name) {
	char key[128], *stored_name;
	int delta;

	if (!r_anal_var_check_name (new_name)) {
		// eprintf ("Invalid name\n");
		return 0;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (a, var_addr, 0);
	RAnalVar *v1 = r_anal_var_get_byname (a, fcn, new_name);
	if (v1) {
		r_anal_var_free (v1);
		eprintf ("variable or arg with name `%s` already exist\n", new_name);
		return false;
	}
	// XXX: This is hardcoded because ->kind seems to be 0
	scope = 1;
	// XXX. this is pretty weak, because oldname may not exist  too and error returned.
	if (scope > 0) { // local
		const char *sign = "";
		SETKEY ("var.0x%"PFMT64x ".%d.%s", var_addr, scope, old_name);
		char *name_val = sdb_get (DB, key, 0);
		char *comma = strchr (name_val, ',');
		if (comma) {
			delta = r_num_math (NULL, comma + 1);
			sdb_unset (DB, key, 0);
			SETKEY ("var.0x%"PFMT64x ".%d.%s", var_addr, scope, new_name);
			sdb_set (DB, key, name_val, 0);
			free (name_val);
			if (delta < 0) {
				delta = -delta;
				sign = "_";
			}
			SETKEY ("var.0x%"PFMT64x ".%c.%d.%s%d", var_addr, kind, scope, sign, delta);
			sdb_array_set (DB, key, R_ANAL_VAR_SDB_NAME, new_name, 0);
		}
	} else { // global
		SETKEY ("var.0x%"PFMT64x, var_addr);
		stored_name = sdb_array_get (DB, key, R_ANAL_VAR_SDB_NAME, 0);
		if (!stored_name) {
			eprintf ("Cannot find key in storage.\n");
			return 0;
		}
		if (!old_name) {
			old_name = stored_name;
		} else if (strcmp (stored_name, old_name)) {
			eprintf ("Old name missmatch %s vs %s.\n", stored_name, old_name);
			return 0;
		}
		sdb_unset (DB, key, 0);
		SETKEY ("var.0x%"PFMT64x, var_addr);
		sdb_array_set (DB, key, R_ANAL_VAR_SDB_NAME, new_name, 0);
	}
	// var.sdb_hash(old_name)=var_addr.scope.delta
	return 1;
}

// avr
R_API int r_anal_var_access(RAnal *a, ut64 var_addr, char kind, int scope, int delta, int xs_type, ut64 xs_addr) {
	const char *var_global;
	const char *xs_type_str = xs_type? "writes": "reads";
	// TODO: kind is not used
	if (scope > 0) { // local
		const char *var_local = sdb_fmt (0, "var.0x%"PFMT64x ".%d.%d.%s",
			var_addr, scope, delta, xs_type_str);
		const char *inst_key = sdb_fmt (1, "inst.0x%"PFMT64x ".vars", xs_addr);
		const char *var_def = sdb_fmt (2, "0x%"PFMT64x ",%c,0x%x,0x%x", var_addr,
			kind, scope, delta);
		sdb_set (DB, inst_key, var_def, 0);
		return sdb_array_add_num (DB, var_local, xs_addr, 0);
	}
	// global
	sdb_add (DB, sdb_fmt (0, "var.0x%"PFMT64x, var_addr), "a,", 0);
	var_global = sdb_fmt (0, "var.0x%"PFMT64x ".%s", var_addr, xs_type_str);
	return sdb_array_add_num (DB, var_global, xs_addr, 0);
}

R_API void r_anal_var_access_clear(RAnal *a, ut64 var_addr, int scope, int delta) {
	char key[128], key2[128];
	if (scope > 0) { // local arg or var
		SETKEY ("var.0x%"PFMT64x ".%d.%d.%s", var_addr, scope, delta, "writes");
		SETKEY2 ("var.0x%"PFMT64x ".%d.%d.%s", var_addr, scope, delta, "reads");
	} else { // global
		SETKEY ("var.0x%"PFMT64x ".%s", var_addr, "writes");
		SETKEY2 ("var.0x%"PFMT64x ".%s", var_addr, "reads");
	}
	sdb_unset (DB, key, 0);
	sdb_unset (DB, key2, 0);
}

R_API int r_anal_fcn_var_del_bydelta(RAnal *a, ut64 fna, const char kind, int scope, ut32 delta) {
	int idx;
	char key[128], val[128], *v;
	SETKEY ("fcn.0x%08"PFMT64x ".%c", fna, kind);
	v = sdb_itoa (delta, val, 10);
	idx = sdb_array_indexof (DB, key, v, 0);
	if (idx != -1) {
		sdb_array_delete (DB, key, idx, 0);
		SETKEY ("fcn.0x%08"PFMT64x ".%c.%d", fna, kind, delta);
		sdb_unset (DB, key, 0);
	}
	return false;
}

R_API int r_anal_var_count(RAnal *a, RAnalFunction *fcn, int kind, int type) {
	// type { local: 0, arg: 1 };
	RList *list = r_anal_var_list (a, fcn, kind);
	RAnalVar *var;
	RListIter *iter;
	int count[2] = {
		0
	};
	r_list_foreach (list, iter, var) {
		if (kind == R_ANAL_VAR_KIND_REG) {
			count[1]++;
			continue;
		}
		count[(kind == R_ANAL_VAR_KIND_BPV && var->delta > 0) || (kind == R_ANAL_VAR_KIND_SPV && var->delta > fcn->maxstack)]++;
	}
	r_list_free (list);
	return count[type];
}

static void var_add_structure_fields_to_list(RAnal *a, RAnalVar *av, const char *base_name, int delta, RList *list) {
	/* ATTENTION: av->name might be freed and reassigned */
	Sdb *TDB = a->sdb_types;
	const char *type_kind = sdb_const_get (TDB, av->type, 0);
	if (type_kind && r_str_startswith (type_kind, "struct")) {
		char *field_name, *new_name;
		int field_n;
		char *type_key = r_str_newf ("%s.%s", type_kind, av->type);
		for (field_n = 0; (field_name = sdb_array_get (TDB, type_key, field_n, NULL)); field_n++) {
			char *field_key = r_str_newf ("%s.%s", type_key, field_name);
			char *field_type = sdb_array_get (TDB, field_key, 0, NULL);
			ut64 field_offset = sdb_array_get_num (TDB, field_key, 1, NULL);
			int field_count = sdb_array_get_num (TDB, field_key, 2, NULL);
			int field_size = r_anal_type_get_size (a, field_type) * (field_count? field_count: 1);
			new_name = r_str_newf ( "%s.%s", base_name, field_name);
			if (field_offset == 0) {
				free (av->name);
				av->name = new_name;
			} else {
				RAnalVar *fav = R_NEW0 (RAnalVar);
				if (!fav) {
					free (field_key);
					free (new_name);
					continue;
				}
				fav->delta = delta + field_offset;
				fav->kind = av->kind;
				fav->name = new_name;
				fav->size = field_size;
				fav->type = strdup (field_type);
				r_list_append (list, fav);
			}
			free (field_type);
			free (field_key);
			free (field_name);
		}
		free (type_key);
	}
}

static RList *var_generate_list(RAnal *a, RAnalFunction *fcn, int kind, bool dynamicVars) {
	if (!a || !fcn) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree) r_anal_var_free);
	if (kind < 1) {
		kind = R_ANAL_VAR_KIND_BPV; // by default show vars
	}
	char *varlist = sdb_get (DB, sdb_fmt (0, "fcn.0x%"PFMT64x ".%c", fcn->addr, kind), 0);
	if (varlist && *varlist) {
		char *next, *ptr = varlist;
		do {
			char *word = sdb_anext (ptr, &next);
			if (r_str_nlen (word, 3) < 3) {
				return NULL;
			}
			const char *vardef = sdb_const_get (DB, sdb_fmt (1,
				"var.0x%"PFMT64x ".%c.%s",
				fcn->addr, kind, word), 0);
			if (word[2] == '_') {
				word[2] = '-';
			}
			int delta = atoi (word + 2);
			if (vardef) {
				struct VarType vt = { 0 };
				sdb_fmt_init (&vt, SDB_VARTYPE_FMT);
				sdb_fmt_tobin (vardef, SDB_VARTYPE_FMT, &vt);
				RAnalVar *av = R_NEW0 (RAnalVar);
				if (!av) {
					free (varlist);
					r_list_free (list);
					return NULL;
				}
				if (!vt.name || !vt.type) {
					// This should be properly fixed
					eprintf ("Warning null var in fcn.0x%"PFMT64x ".%c.%s\n",
						fcn->addr, kind, word);
					free (av);
					continue;
				}
				av->delta = delta;
				av->kind = kind;
				av->name = strdup (vt.name);
				av->size = vt.size;
				av->type = strdup (vt.type);
				r_list_append (list, av);
				if (dynamicVars) { // make dynamic variables like structure fields
					var_add_structure_fields_to_list (a, av, vt.name, delta, list);
				}
				sdb_fmt_free (&vt, SDB_VARTYPE_FMT);
			} else {
				eprintf ("Cannot find var definition for '%s'\n", word);
			}
			ptr = next;
		} while (next);
	}
	free (varlist);
	return list;
}

R_API RList *r_anal_var_all_list(RAnal *anal, RAnalFunction *fcn) {
	// r_anal_var_list if there are not vars with that kind returns a list with
	// zero element.. which is an unnecessary loss of cpu time
	RList *list = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_ARG);
	if (!list) {
		return NULL;
	}
	r_list_join (list, r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_REG));
	r_list_join (list, r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_BPV));
	r_list_join (list, r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_SPV));
	return list;
}

R_API RList *r_anal_var_list(RAnal *a, RAnalFunction *fcn, int kind) {
	return var_generate_list (a, fcn, kind, false);
}

R_API RList *r_anal_var_list_dynamic(RAnal *a, RAnalFunction *fcn, int kind) {
	return var_generate_list (a, fcn, kind, true);
}

static int var_comparator(const RAnalVar *a, const RAnalVar *b){
	// avoid NULL dereference
	return (a && b)? a->delta > b->delta: false;
}

R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, int kind, int mode) {
	RList *list = r_anal_var_list (anal, fcn, kind);
	r_list_sort (list, (RListComparator) var_comparator);
	RAnalVar *var;
	RListIter *iter;
	if (mode == 'j') {
		anal->cb_printf ("[");
	}
	r_list_foreach (list, iter, var) {
		if (var->kind != kind) {
			continue;
		}
		switch (mode) {
		case '*':
			// we cant express all type info here :(
			if (kind == R_ANAL_VAR_KIND_REG) { // registers
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					eprintf ("Register not found");
					break;
				}
				anal->cb_printf ("afv%c %s %s %s @ 0x%"PFMT64x "\n",
					kind, i->name, var->name, var->type, fcn->addr);
			} else {
				anal->cb_printf ("afv%c %d %s %s @ 0x%"PFMT64x "\n",
					kind, var->delta, var->name, var->type,
					fcn->addr);
			}
			break;
		case 'j':
			switch (var->kind) {
			case R_ANAL_VAR_KIND_BPV:
				if (var->delta > 0) {
					anal->cb_printf ("{\"name\":\"%s\","
						"\"kind\":\"arg\",\"type\":\"%s\",\"ref\":"
						"{\"base\":\"%s\", \"offset\":%"PFMT64d "}}",
						var->name, var->type, anal->reg->name[R_REG_NAME_BP],
						var->delta);
				} else {
					anal->cb_printf ("{\"name\":\"%s\","
						"\"kind\":\"var\",\"type\":\"%s\",\"ref\":"
						"{\"base\":\"%s\", \"offset\":-%"PFMT64d "}}",
						var->name, var->type, anal->reg->name[R_REG_NAME_BP],
						-var->delta);
				}
				break;
			case R_ANAL_VAR_KIND_REG: {
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					eprintf ("Register not found");
					break;
				}
				anal->cb_printf ("{\"name\":\"%s\","
					"\"kind\":\"reg\",\"type\":\"%s\",\"ref\":\"%s\"}",
					var->name, var->type, i->name, anal->reg->name[var->delta]);
			}
				break;
			case R_ANAL_VAR_KIND_SPV:
				if (var->delta < fcn->maxstack) {
					anal->cb_printf ("{\"name\":\"%s\","
						"\"kind\":\"arg\",\"type\":\"%s\",\"ref\":"
						"{\"base\":\"%s\", \"offset\":%"PFMT64d "}}",
						var->name, var->type, anal->reg->name[R_REG_NAME_SP],
						var->delta);
				} else {
					anal->cb_printf ("{\"name\":\"%s\","
						"\"kind\":\"var\",\"type\":\"%s\",\"ref\":"
						"{\"base\":\"%s\", \"offset\":-%"PFMT64d "}}",
						var->name, var->type, anal->reg->name[R_REG_NAME_SP],
						var->delta);
				}
				break;
			}
			if (iter->n) {
				anal->cb_printf (",");
			}
			break;
		default:
			switch (kind) {
			case R_ANAL_VAR_KIND_BPV:
				if (var->delta > 0) {
					anal->cb_printf ("arg %s %s @ %s+0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_BP],
						var->delta);
				} else {
					anal->cb_printf ("var %s %s @ %s-0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_BP],
						-var->delta);
				}
				break;
			case R_ANAL_VAR_KIND_REG: {
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					eprintf ("Register not found");
					break;
				}
				anal->cb_printf ("reg %s %s @ %s\n",
					var->type, var->name, i->name);
				}
				break;
			case R_ANAL_VAR_KIND_SPV:
				if (var->delta < fcn->maxstack) {
					anal->cb_printf ("var %s %s @ %s+0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_SP],
						var->delta);
				} else {
					anal->cb_printf ("arg %s %s @ %s+0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_SP],
						var->delta);

				}
				break;
			}
		}
	}
	if (mode == 'j') {
		anal->cb_printf ("]\n");
	}
	r_list_free (list);
}
