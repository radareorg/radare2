/* radare - LGPL - Copyright 2010-2016 - pancake, oddcoder */

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
	case 'a': // base pointer var/args
	case 'v': // stack pointer var/args
	case 'e': // registers args
		break;
	default:
		eprintf ("Invalid var kind '%c'\n", kind);
		return false;
	}
	var_def = sdb_fmt (0,"%c,%s,%d,%s", kind, type, size, name);
	if (scope>0) {
		char *sign = "";
		if (delta < 0) {
			delta = -delta;
			sign = "n";
		}
		/* local variable */
		char *fcn_key = sdb_fmt (1, "fcn.0x%"PFMT64x".%c", addr, kind);
		char *var_key = sdb_fmt (2, "var.0x%"PFMT64x".%c.%d.%s%d", addr, kind, scope, sign, delta);
		char *name_key = sdb_fmt (3, "var.0x%"PFMT64x".%c.%d.%s", addr, kind, scope, name);
		char *shortvar = sdb_fmt (4, "%d.%s%d", scope, sign, delta);
		sdb_array_add (DB, fcn_key, shortvar, 0);
		sdb_set (DB, var_key, var_def, 0);
		if (*sign) {
			delta = -delta;
		}
		sdb_num_set (DB, name_key, delta, 0);
	} else {
		/* global variable */
		char *var_global = sdb_fmt (1, "var.0x%"PFMT64x, addr);
		char *var_def = sdb_fmt (2,"%c.%s,%d,%s", kind, type, size, name);
		sdb_array_add (DB, var_global, var_def, 0);
	}
//	ls_sort (DB->ht->list, mystrcmp);
	return true;
}

R_API int r_anal_var_retype (RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, const char *name) {
	char *var_def;
	if (!kind) kind ='v';
	if (!type) type = "int";
	if (size==-1) {
		RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, 0);
		RList *list = r_anal_var_list (a, fcn, kind);
		RListIter *iter;
		RAnalVar *var;
		r_list_foreach (list, iter, var) {
			if (delta == -1) {
				if (!strcmp (var->name, name)) {
					delta = var->delta;
					size = var->size;
					break;
				}
			}
		}
		r_list_free (list);
	}
	switch (kind) {
	case 'a':
	case 'v':
	case 'e':
		break;
	default:
		eprintf ("Invalid var kind '%c'\n", kind);
		return false;
	}
	var_def = sdb_fmt (0,"%c,%s,%d,%s", kind, type, size, name);
	if (scope > 0) {
		char *sign = "";
		if (delta < 0) {
			delta = -delta;
			sign = "n";
		}
		/* local variable */
		const char *fcn_key = sdb_fmt (1, "fcn.0x%"PFMT64x".%c", addr, kind);
		const char *var_key = sdb_fmt (2, "var.0x%"PFMT64x".%c.%d.%s%d", addr, kind, scope, sign, delta);
		const char *name_key = sdb_fmt (3, "var.0x%"PFMT64x".%c.%d.%s", addr, kind, scope, name);
		const char *shortvar = sdb_fmt (4, "%d.%s%d", scope, sign, delta);
		sdb_array_add (DB, fcn_key, shortvar, 0);
		sdb_set (DB, var_key, var_def, 0);
		if (*sign) {
			delta = -delta;
		}
		sdb_num_set (DB, name_key, delta, 0);
	} else {
		/* global variable */
		const char *var_global = sdb_fmt (1, "var.0x%"PFMT64x, addr);
		sdb_array_add (DB, var_global, var_def, 0);
	}
	return true;
}

R_API int r_anal_var_delete_all (RAnal *a, ut64 addr, const char kind) {
	RAnalFunction *fcn;
	fcn = r_anal_get_fcn_in (a, addr, 0);
	if (fcn) {
		RAnalVar *v;
		RListIter *iter;
		RList *list = r_anal_var_list (a, fcn, kind);
		r_list_foreach (list, iter, v) {
			//r_anal_var_delete (a, addr, kind, v->scope, v->delta);
			r_anal_var_delete (a, addr, kind, 1, v->delta);
		}
		r_list_free (list);
	}
	return 0;
}

R_API int r_anal_var_delete (RAnal *a, ut64 addr, const char kind, int scope, int delta) {
	RAnalVar *av;
	av = r_anal_var_get (a, addr, kind, scope, delta);
	if (!av) {
		return false;
	}
	if (scope>0) {
		char *sign = "";
		if (delta < 0) {
			delta = -delta;
			sign = "n";
		}
		char *fcn_key = sdb_fmt (1, "fcn.0x%"PFMT64x".%c", addr, kind);
		char *var_key = sdb_fmt (2, "var.0x%"PFMT64x".%c.%d.%s%d", addr, kind, scope, sign, delta);
		char *name_key = sdb_fmt (3, "var.0x%"PFMT64x".%c.%d.%s", addr, kind, scope, av->name);
		char *shortvar = sdb_fmt (4, "%d.%s%d", scope, sign, delta);
		sdb_array_remove (DB, fcn_key, shortvar, 0);
		sdb_unset (DB, var_key, 0);
		sdb_unset (DB, name_key, 0);
		if (*sign) {
			delta = -delta;
		}
	} else {
		char *var_global = sdb_fmt (1, "var.0x%"PFMT64x, addr);
		char *var_def = sdb_fmt (2,"%c.%s,%d,%s", kind, av->type, av->size, av->name);
		sdb_array_remove (DB, var_global, var_def, 0);
	}
	r_anal_var_access_clear (a, addr, scope, delta);
	return true;
}

R_API bool r_anal_var_delete_byname (RAnal *a, RAnalFunction *fcn, int kind, const char *name) {
	char *varlist;
	if (!a || !fcn) {
		return false;
	}
	varlist = sdb_get (DB, sdb_fmt (0, "fcn.0x%"PFMT64x".%c",
		fcn->addr, kind), 0);
	if (varlist) {
		char *next, *ptr = varlist;
		if (varlist && *varlist) {
			do {
				char *word = sdb_anext (ptr, &next);
				char *sign = strstr (word, "n");
				const char *vardef = sdb_const_get (DB, sdb_fmt (1,
					"var.0x%"PFMT64x".%c.%s",
					fcn->addr, kind, word), 0);
				if (sign) {
					*sign = '-';
				}
				int delta = strlen (word) < 3 ? -1 : atoi (word + 2);
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

R_API RAnalVar *r_anal_var_get_byname(RAnal *anal, RAnalFunction *fcn, char kind, const char* name) {
	RList *var_list;
	RListIter *iter;
	RAnalVar *var = NULL, *itervar;
	if (!fcn || !anal || !name) {
		return 0;
	}
	var_list = r_anal_var_list (anal, fcn, kind);
	r_list_foreach (var_list, iter, itervar) {
		if (!strcmp (name, itervar->name)) {
			var = calloc (1, sizeof(RAnalVar));
			if (!var) return 0;
			memcpy (var, itervar, sizeof(RAnalVar));
			var->name = strdup (itervar->name);
			var->type = strdup (itervar->type);
			var->accesses = r_list_clone (itervar->accesses);
			var->stores = r_list_clone (itervar->stores);
			break;
		} 
	}
	r_list_free (var_list);
	if (!var || strcmp (name, var->name)) {
		return 0;
	}
	return var;
}
R_API RAnalVar *r_anal_var_get (RAnal *a, ut64 addr, char kind, int scope, int delta) {
	RAnalVar *av;
	struct VarType vt;
	char *sign = "";
	RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, 0);
	if (!fcn)
		return NULL;
	if (delta < 0) {
		delta = -delta;
		sign = "n";
	}
	const char *vardef = sdb_const_get (DB,
		sdb_fmt (0, "var.0x%"PFMT64x".%c.%d.%s%d",
			fcn->addr, kind, scope, sign, delta), 0);
	if (*sign) {
		delta = -delta;
	}
	if (!vardef) {
		return NULL;
	}
	sdb_fmt_tobin (vardef, SDB_VARTYPE_FMT, &vt);

	av = R_NEW0 (RAnalVar);
	if (!av) {
		sdb_fmt_free (&vt, SDB_VARTYPE_FMT);
		return NULL;
	}
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
	if (av) {
		free (av->name);
		free (av->type);
		free (av);
	}
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
	char key[128], *stored_name;
	int delta;

	if (!r_anal_var_check_name (new_name)) {
		return 0;
	}
	if (scope>0) { // local
		char *sign = "";
		SETKEY ("var.0x%"PFMT64x".%c.%d.%s", var_addr, kind, scope, old_name);
		delta = sdb_num_get (DB, key, 0);
		sdb_unset (DB, key, 0);
		SETKEY ("var.0x%"PFMT64x".%c.%d.%s", var_addr, kind, scope, new_name);
		sdb_num_set (DB, key, delta, 0);
		if (delta < 0) {
			delta = -delta;
			sign = "n";
		}
		SETKEY ("var.0x%"PFMT64x".%c.%d.%s%d", var_addr, kind, scope, sign, delta);
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

// avr
R_API int r_anal_var_access (RAnal *a, ut64 var_addr, char kind, int scope, int delta, int xs_type, ut64 xs_addr) {
	const char *var_global;
	const char *xs_type_str = xs_type? "writes": "reads";
	// TODO: kind is not used
	if (scope > 0) { // local
		char *var_local = sdb_fmt (0, "var.0x%"PFMT64x".%d.%d.%s",
			var_addr, scope, delta, xs_type_str);
		char *inst_key = sdb_fmt (1, "inst.0x%"PFMT64x".vars", xs_addr);
		char *var_def = sdb_fmt(2, "0x%"PFMT64x",%c,0x%x,0x%x", var_addr,
			kind, scope, delta);
		sdb_set (DB, inst_key, var_def, 0);
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
	return false;
}

R_API int r_anal_var_count(RAnal *a, RAnalFunction *fcn, int kind) {
	char *varlist;
	int count = 0;
	if (!a || !fcn) {
		return 0;
	}
	if (!kind) kind = 'v'; // by default show vars
	varlist = sdb_get (DB, sdb_fmt (0, "fcn.0x%"PFMT64x".%c",
		fcn->addr, kind), 0);
	if (varlist) {
		char *next, *ptr = varlist;
		if (varlist && *varlist) {
			do {
				char *word = sdb_anext (ptr, &next);
				const char *vardef = sdb_const_get (DB, sdb_fmt (1,
					"var.0x%"PFMT64x".%c.%s",
					fcn->addr, kind, word), 0);
				if (vardef) {
					count ++;
				} else {
					eprintf ("Cannot find var '%s'\n", word);
				}
				ptr = next;
			} while (next);
		}
	}
	free (varlist);
	return count;
}

R_API RList *r_anal_var_list(RAnal *a, RAnalFunction *fcn, int kind) {
	char *varlist;
	RList *list = NULL;
	if (!a || !fcn) {
		return NULL;
	}
	list = r_list_new ();
	if (!kind) kind = 'v'; // by default show vars
	varlist = sdb_get (DB, sdb_fmt (0, "fcn.0x%"PFMT64x".%c",
		fcn->addr, kind), 0);
	if (varlist) {
		char *next, *ptr = varlist;
		if (varlist && *varlist) {
			do {
				struct VarType vt;
				char *word = sdb_anext (ptr, &next);
				const char *vardef = sdb_const_get (DB, sdb_fmt (1,
					"var.0x%"PFMT64x".%c.%s",
					fcn->addr, kind, word), 0);
				if (word[2] == 'n') {
					word[2] = '-';
				}
				int delta = atoi (word+2);
				if (vardef) {
					sdb_fmt_init (&vt, SDB_VARTYPE_FMT);
					sdb_fmt_tobin (vardef, SDB_VARTYPE_FMT, &vt);
					RAnalVar *av;
					av = R_NEW0 (RAnalVar);
					if (!av) {
						free (varlist);
						r_list_free (list);
						return NULL;
					}
					av->delta = delta;
					av->kind = kind;
					av->name = strdup (vt.name);
					av->size = vt.size;
					av->type = strdup (vt.type);
					r_list_append (list, av);
					sdb_fmt_free (&vt, SDB_VARTYPE_FMT);
				} else {
					// eprintf ("Cannot find var definition for '%s'\n", word);
				}
				ptr = next;
			} while (next);
		}
	}
	free (varlist);
	list->free = (RListFree)r_anal_var_free;
	return list;
}

static int var_comparator (const RAnalVar *a, const RAnalVar *b){
	//avoid NULL dereference
	return (a && b) ? a->delta > b->delta : false;
}

R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, int kind, int mode) {
	RList *list = r_anal_var_list (anal, fcn, kind);
	r_list_sort (list, (RListComparator)var_comparator);
	RAnalVar *var;
	RListIter *iter;
	if (mode=='j') {
		anal->cb_printf ("[");
	}
	r_list_foreach (list, iter, var) {
		if (var->kind != kind) {
			continue;
		}
		switch (mode) {
		case '*':
			// we cant express all type info here :(
			if (kind == 'v') { //registers
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					eprintf ("Register not found");
					break;
				}
				anal->cb_printf ("af%c %s %s %s @ 0x%"PFMT64x"\n",
					kind, i->name, var->name, var->type, fcn->addr);

			} else {
				anal->cb_printf ("af%c %d %s %s @ 0x%"PFMT64x"\n",
					kind, var->delta, var->name, var->type,
					fcn->addr);
			}
			break;
		case 'j':
			switch (var->kind) {
			case 'a':
				if (var->delta > 0) {
					anal->cb_printf ("{\"name\":\"%s\","
						"\"kind\":\"arg\",\"type\":\"%s\",\"ref\":\"%s+0x%x\"}",
						var->name, var->type,anal->reg->name[R_REG_NAME_BP],
						var->delta);
				} else {
					anal->cb_printf ("{\"name\":\"%s\","
						"\"kind\":\"var\",\"type\":\"%s\",\"ref\":\"%s-0x%x\"}",
						var->name, var->type,anal->reg->name[R_REG_NAME_BP],
						-var->delta);

				}
				break;
			case 'v':{
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
			case 'e':
				if (var->delta < fcn->stack) {
					anal->cb_printf ("{\"name\":\"%s\","
						"\"kind\":\"var\",\"type\":\"%s\",\"ref\":\"%s+0x%x\"}",
						var->name, var->type,anal->reg->name[R_REG_NAME_SP],
						var->delta);
				} else {
					anal->cb_printf ("{\"name\":\"%s\","
						"\"kind\":\"arg\",\"type\":\"%s\",\"ref\":\"%s-0x%x\"}",
						var->name, var->type,anal->reg->name[R_REG_NAME_SP],
						var->delta);
				}
				break;
			}
			if (iter->n)  {
				anal->cb_printf (",");
			}
			break;
		default:
			switch (kind) {
			case 'a':
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
			case 'v': {
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					eprintf("Register not found");
					break;
				}

				anal->cb_printf ("reg %s %s @ %s\n",
					var->type, var->name, i->name);
				}
				break;
			case 'e':
				if ( var->delta < fcn->stack) {
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
