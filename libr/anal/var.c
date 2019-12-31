/* radare - LGPL - Copyright 2010-2019 - pancake, oddcoder */

#include <r_anal.h>
#include <r_util.h>
#include <r_cons.h>
#include <r_list.h>

#define DB a->sdb_fcns

struct VarType {
	bool isarg;
	char *type;
	int size;
	char *name;
	char *regname;
};

#define SDB_VARTYPE_FMT "bzdzz"

#define EXISTS(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__), sdb_exists (DB, key)
#define SETKEY(x, ...) snprintf (key, sizeof (key) - 1, x, ## __VA_ARGS__);
#define SETKEY2(x, ...) snprintf (key2, sizeof (key) - 1, x, ## __VA_ARGS__);
#define SETVAL(x, ...) snprintf (val, sizeof (val) - 1, x, ## __VA_ARGS__);
R_API bool r_anal_var_display(RAnal *anal, int delta, char kind, const char *type) {
	char *fmt = r_type_format (anal->sdb_types, type);
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

static const char *__int_type_from_size(int size) {
	switch (size) {
	case 1: return "int8_t";
	case 2: return "int16_t";
	case 4: return "int32_t";
	case 8: return "int64_t";
	default: return NULL;
	}
}

R_API bool r_anal_var_rebase(RAnal *a, RAnalFunction *fcn, ut64 diff) {
	r_return_val_if_fail (a && fcn, false);
	RListIter *it;
	RAnalVar *var;
	RList *var_list = r_anal_var_all_list (a, fcn);
	r_return_val_if_fail (var_list, false);

	r_list_foreach (var_list, it, var) {
		const char *var_access = sdb_fmt ("var.0x%"PFMT64x ".%d.%d.access", var->addr, 1, var->delta);
		char *access = sdb_get (a->sdb_fcns, var_access, NULL);
		r_anal_var_delete (a, var->addr, var->kind, 1, var->delta);

		// Resync delta in case the registers list changed
		if (var->isarg && var->kind == 'r') {
			RRegItem *reg = r_reg_get (a->reg, var->regname, -1);
			if (reg) {
				if (var->delta != reg->index) {
					var->delta = reg->index;
				}
			}
		}

		var->addr += diff;

		r_anal_var_add (a, var->addr, 1, var->delta, var->kind, var->type, var->size, var->isarg, var->name);
		var_access = sdb_fmt ("var.0x%"PFMT64x ".%d.%d.access", var->addr, 1, var->delta);
		sdb_set (a->sdb_fcns, var_access, access, 0);
		free (access);
	}

	r_list_free (var_list);
	return true;
}

R_API bool r_anal_var_add(RAnal *a, ut64 addr, int scope, int delta, char kind, R_NULLABLE const char *type, int size, bool isarg, R_NONNULL const char *name) {
	r_return_val_if_fail (a && name, false);
	RRegItem *reg = NULL;
	if (!kind) {
		kind = R_ANAL_VAR_KIND_BPV;
	}
	if (!type) {
		type = __int_type_from_size (size);
		if (!type) {
			type = __int_type_from_size (a->bits);
		}
		if (!type) {
			type = "int32_t";
		}
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
	if (kind == 'r') {
		reg = r_reg_index_get (a->reg, R_ABS (delta));
		if (!reg) {
			eprintf ("Register wasn't found at the given delta\n");
			return false;
		}
	}
	const char *var_def = sdb_fmt ("%d,%s,%d,%s,%s", isarg, type, size, name, reg? reg->name : NULL);
	if (scope > 0) {
		const char *sign = "";
		if (delta < 0) {
			delta = -delta;
			sign = "_";
		}
		/* local variable */
		const char *fcn_key = sdb_fmt ("fcn.0x%"PFMT64x ".%c", addr, kind);
		const char *var_key = sdb_fmt ("var.0x%"PFMT64x ".%c.%d.%s%d", addr, kind, scope, sign, delta);
		const char *name_key = sdb_fmt ("var.0x%"PFMT64x ".%d.%s", addr, scope, name);
		const char *shortvar = sdb_fmt ("%d.%s%d", scope, sign, delta);
		sdb_array_add (DB, fcn_key, shortvar, 0);
		sdb_set (DB, var_key, var_def, 0);
		if (*sign) {
			delta = -delta;
		}
		char *name_val = r_str_newf ("%c,%d", kind, delta);
		sdb_set (DB, name_key, name_val, 0);
		free (name_val);
	} else {
		/* global variable */
		const char *var_global = sdb_fmt ("var.0x%"PFMT64x, addr);
		const char *var_def = sdb_fmt ("%c.%s,%d,%s", kind, type, size, name);
		sdb_array_add (DB, var_global, var_def, 0);
	}
	return true;
}

R_API int r_anal_var_retype(RAnal *a, ut64 addr, int scope, int delta, char kind, const char *type, int size, 
		bool isarg, const char *name) {
	RRegItem *reg = NULL;
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
		return false;
	}
	if ((size == -1) && (delta == -1)) {
		RList *list = r_anal_var_list (a, fcn, kind);
		RListIter *iter;
		RAnalVar *var;
		r_list_foreach (list, iter, var) {
			if (!strcmp (var->name, name)) {
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
	if (kind == 'r') {
		reg = r_reg_index_get (a->reg, R_ABS (delta));
		if (!reg) {
			eprintf ("Register wasn't found at the given delta\n");
			return false;
		}
	}
	const char *var_def = sdb_fmt ("%d,%s,%d,%s,%s", isarg, type, size, name, reg ? reg->name : NULL);
	if (scope > 0) {
		char *sign = delta >= 0 ? "": "_";
		/* local variable */
		const char *fcn_key = sdb_fmt ("fcn.0x%"PFMT64x ".%c", fcn->addr, kind);
		const char *var_key = sdb_fmt ("var.0x%"PFMT64x ".%c.%d.%s%d", fcn->addr, kind, scope, sign, R_ABS (delta));
		const char *name_key = sdb_fmt ("var.0x%"PFMT64x ".%d.%s", fcn->addr, scope, name);
		const char *shortvar = sdb_fmt ("%d.%s%d", scope, sign, R_ABS (delta));
		const char *name_val = sdb_fmt ("%c,%d", kind, delta);
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
				if (field_offset != 0) { // delete variables which are overlaid by structure
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
		const char *var_global = sdb_fmt ("var.0x%"PFMT64x, fcn->addr);
		sdb_array_add (DB, var_global, var_def, 0);
	}
	return true;
}

R_API int r_anal_var_delete_all(RAnal *a, ut64 addr, const char kind) {
	r_return_val_if_fail (a, 0);
	RAnalFunction *fcn = r_anal_get_fcn_in (a, addr, 0);
	if (fcn) {
		RAnalVar *v;
		RListIter *iter;
		RList *list = r_anal_var_list (a, fcn, kind);
		r_list_foreach (list, iter, v) {
			// r_anal_var_delete (a, addr, kind, v->scope, v->delta);
			r_anal_var_delete (a, addr, kind, 1, v->delta);
		}
		// XXX: i don't think we want to allocate and free by hand. r_anal_var_delete should be the list->free already
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
		char *fcn_key = sdb_fmt ("fcn.0x%"PFMT64x ".%c", addr, kind);
		char *var_key = sdb_fmt ("var.0x%"PFMT64x ".%c.%d.%s%d", addr, kind, scope, sign, delta);
		char *name_key = sdb_fmt ("var.0x%"PFMT64x ".%d.%s", addr, scope, av->name);
		char *shortvar = sdb_fmt ("%d.%s%d", scope, sign, delta);
		sdb_array_remove (DB, fcn_key, shortvar, 0);
		sdb_unset (DB, var_key, 0);
		sdb_unset (DB, name_key, 0);
		if (*sign) {
			delta = -delta;
		}
	} else {
		const char *var_global = sdb_fmt ("var.0x%"PFMT64x, addr);
		const char *var_def = sdb_fmt ("%c.%s,%d,%s", kind, av->type, av->size, av->name);
		sdb_array_remove (DB, var_global, var_def, 0);
	}
	r_anal_var_free (av);
	r_anal_var_access_clear (a, addr, scope, delta);
	return true;
}

R_API bool r_anal_var_delete_byname(RAnal *a, RAnalFunction *fcn, int kind, const char *name) {
	if (!a || !fcn) {
		return false;
	}
	bool ret = false;
	RAnalVar *var = r_anal_var_get_byname (a, fcn->addr, name);
	if (var) {
		ret = r_anal_var_delete (a, fcn->addr, var->kind, 1, var->delta);
		r_anal_var_free (var);
	}
	return ret;
}

R_API RAnalVar *r_anal_var_get_byname(RAnal *a, ut64 addr, const char *name) {
	if (!a || !name) {
		// eprintf ("No something\n");
		return NULL;
	}
	char *name_key = sdb_fmt ("var.0x%"PFMT64x ".%d.%s", addr, 1, name);
	char *name_value = sdb_get (DB, name_key, 0);
	if (!name_value) {
		// eprintf ("Can't find key for %s\n", name_key);
		return NULL;
	}
	const char *comma = strchr (name_value, ',');
	if (comma && *comma) {
		int delta = r_num_math (NULL, comma + 1);
		RAnalVar *res = r_anal_var_get (a, addr, *name_value, 1, delta);
		free (name_value);
		return res;
	}
	free (name_value);
	return NULL;
}

R_API RAnalVar *r_anal_var_get(RAnal *a, ut64 addr, char kind, int scope, int delta) {
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
	const char *varkey = sdb_fmt ("var.0x%"PFMT64x ".%c.%d.%s%d",
			fcn->addr, kind, scope, sign, delta);
	char *vardef = sdb_get (DB, varkey, 0);
	if (!vardef) {
		return NULL;
	}
	if (*sign) {
		delta = -delta;
	}
	sdb_fmt_init (&vt, SDB_VARTYPE_FMT);
	sdb_fmt_tobin (vardef, SDB_VARTYPE_FMT, &vt);
	free (vardef);

	RAnalVar *av = R_NEW0 (RAnalVar);
	if (!av) {
		sdb_fmt_free (&vt, SDB_VARTYPE_FMT);
		return NULL;
	}
	av->addr = fcn->addr;
	av->scope = scope;
	av->delta = delta;
	av->isarg = vt.isarg;
	av->name = strdup (vt.name ? vt.name : "unkown_var");
	av->size = vt.size;
	av->type = strdup (vt.type ? vt.type : "unkown_type");
	av->regname = strdup (vt.regname ? vt.regname : "unkown_regname");
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
		free (av->regname);
		free (av->type);
		free (av);
	}
}

R_API ut64 r_anal_var_addr(RAnal *a, RAnalFunction *fcn, const char *name) {
	const char *regname = NULL;
	ut64 ret = UT64_MAX;
	if (!a || !fcn) {
		return ret;
	}
	RAnalVar *v1 = r_anal_var_get_byname (a, fcn->addr, name);
	if (v1) {
		if (v1->kind == R_ANAL_VAR_KIND_BPV) {
			regname = r_reg_get_name (a->reg, R_REG_NAME_BP);
		} else if (v1->kind == R_ANAL_VAR_KIND_SPV) {
			regname = r_reg_get_name (a->reg, R_REG_NAME_SP);
		}
		ret = r_reg_getv (a->reg, regname) + v1->delta;
	}
	r_anal_var_free (v1);
	return ret;
}

/* (columns) elements in the array value */
#define R_ANAL_VAR_SDB_KIND 0 /* char */
#define R_ANAL_VAR_SDB_TYPE 1 /* string */
#define R_ANAL_VAR_SDB_SIZE 2 /* number */
#define R_ANAL_VAR_SDB_NAME 3 /* string */

R_API bool r_anal_var_check_name(const char *name) {
	return !isdigit (*name) && strcspn (name, "., =/");
}

// afvn local_48 counter
R_API int r_anal_var_rename(RAnal *a, ut64 addr, int scope, char kind, const char *old_name, const char *new_name, bool verbose) {
	char key[128];

	if (!r_anal_var_check_name (new_name)) {
		return 0;
	}
	RAnalVar *v1 = r_anal_var_get_byname (a, addr, new_name);
	if (v1) {
		r_anal_var_free (v1);
		if (verbose) {
			eprintf ("variable or arg with name `%s` already exist\n", new_name);
		}
		return false;
	}
	// XXX: This is hardcoded because ->kind seems to be 0
	scope = 1;
	// XXX. this is pretty weak, because oldname may not exist  too and error returned.
	if (scope > 0) { // local
		const char *sign = "";
		SETKEY ("var.0x%"PFMT64x ".%d.%s", addr, scope, old_name);
		char *name_val = sdb_get (DB, key, 0);
		if (!name_val) {
			return 0;
		}
		char *comma = strchr (name_val, ',');
		if (comma) {
			int delta = r_num_math (NULL, comma + 1);
			sdb_unset (DB, key, 0);
			SETKEY ("var.0x%"PFMT64x ".%d.%s", addr, scope, new_name);
			sdb_set (DB, key, name_val, 0);
			free (name_val);
			if (delta < 0) {
				delta = -delta;
				sign = "_";
			}
			SETKEY ("var.0x%"PFMT64x ".%c.%d.%s%d", addr, kind, scope, sign, delta);
			sdb_array_set (DB, key, R_ANAL_VAR_SDB_NAME, new_name, 0);
		}
	} else { // global
		SETKEY ("var.0x%"PFMT64x, addr);
		char *stored_name = sdb_array_get (DB, key, R_ANAL_VAR_SDB_NAME, 0);
		if (!stored_name) {
			return 0;
		}
		if (!old_name) {
			old_name = stored_name;
		}
		if (strcmp (stored_name, old_name)) {
			return 0;
		}
		sdb_unset (DB, key, 0);
		SETKEY ("var.0x%"PFMT64x, addr);
		sdb_array_set (DB, key, R_ANAL_VAR_SDB_NAME, new_name, 0);
	}
	return 1;
}

// Used for linking reg based arg and local-var like "mov [local_8h], rsi"
static void r_anal_var_link(RAnal *a, ut64 addr, RAnalVar *var) {
	const char *inst_key = sdb_fmt ("inst.0x%" PFMT64x ".lvar", addr);
	const char *var_def = sdb_fmt ("0x%" PFMT64x ",%c,0x%x,0x%x", var->addr,
		var->kind, var->scope, var->delta);
	sdb_set (DB, inst_key, var_def, 0);
}

// avr
R_API int r_anal_var_access(RAnal *a, ut64 var_addr, char kind, int scope, int delta, int ptr, int xs_type, ut64 xs_addr) {
	const char *var_global;
	const char *xs_type_str = xs_type? "writes": "reads";
	// TODO: kind is not used
	if (scope > 0) { // local
		const char *var_local = sdb_fmt ("var.0x%"PFMT64x ".%d.%d.access",
			var_addr, scope, delta);
		sdb_array_add (DB, var_local, sdb_fmt ("0x%"PFMT64x".%d", xs_addr - var_addr, ptr), 0);
		var_local = sdb_fmt ("var.0x%"PFMT64x ".%d.%d.%s",
			var_addr, scope, delta, xs_type_str);
		const char *inst_key = sdb_fmt ("inst.0x%"PFMT64x ".vars", xs_addr);
		const char *var_def = sdb_fmt ("0x%"PFMT64x ",%c,0x%x,0x%x", var_addr,
			kind, scope, delta);
		sdb_set (DB, inst_key, var_def, 0);
		return sdb_array_add_num (DB, var_local, xs_addr, 0);
	}
	// global
	sdb_add (DB, sdb_fmt ("var.0x%"PFMT64x, var_addr), "a,", 0);
	var_global = sdb_fmt ("var.0x%"PFMT64x ".%s", var_addr, xs_type_str);
	return sdb_array_add_num (DB, var_global, xs_addr, 0);
}

R_API void r_anal_var_access_clear(RAnal *a, ut64 var_addr, int scope, int delta) {
	char key[128], key2[128];
	if (scope > 0) { // local arg or var
		SETKEY ("var.0x%"PFMT64x ".%d.%d.%s", var_addr, scope, delta, "writes");
		SETKEY2 ("var.0x%"PFMT64x ".%d.%d.%s", var_addr, scope, delta, "reads");
		sdb_unset (DB, sdb_fmt ("var.0x%"PFMT64x ".%d.%d.access", var_addr, scope, delta), 0);
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
		count[var->isarg]++;
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
			int field_size = r_type_get_bitsize (TDB, field_type) * (field_count? field_count: 1);
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
				fav->regname = strdup (av->regname);
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


//Variable recovery functions
static char *get_varname(RAnal *a, RAnalFunction *fcn, char type, const char *pfx, int delta) {
	char *varname = r_str_newf ("%s_%xh", pfx, R_ABS (delta));
	int i = 2;
	int v_delta = 0;
	while (1) {
		char *name_key = sdb_fmt ("var.0x%"PFMT64x ".%d.%s", fcn->addr, 1, varname);
		char *name_value = sdb_get (a->sdb_fcns, name_key, 0);
		if (!name_value) {
			break;
		}
		const char *comma = strchr (name_value, ',');
		if (comma && *comma) {
			v_delta = r_num_math (NULL, comma + 1);
		}
		if (v_delta == delta) {
			free (name_value);
			return varname;
		}
		free (varname);
		free (name_value);
		varname = r_str_newf ("%s_%xh_%d", pfx, R_ABS (delta), i);
		i++;
	}
	return varname;
}

static const char *get_regname(RAnal *anal, RAnalValue *value) {
	const char *name = NULL;
	if (value && value->reg && value->reg->name) {
		name = value->reg->name;
		RRegItem *ri = r_reg_get (anal->reg, value->reg->name, -1);
		if (ri && (ri->size == 32) && (anal->bits == 64)) {
			name = r_reg_32_to_64 (anal->reg, value->reg->name);
		}
	}
	return name;
}

static void extract_arg(RAnal *anal, RAnalFunction *fcn, RAnalOp *op, const char *reg, const char *sign, char type) {
	st64 ptr;
	char *addr;

	r_return_if_fail (anal && fcn && op);

	const char *op_esil = r_strbuf_get (&op->esil);
	if (!op_esil) {
		return;
	}
	char *esil_buf = strdup (op_esil);
	if (!esil_buf) {
		return;
	}
	char *ptr_end = strstr (esil_buf, sdb_fmt (",%s,%s", reg, sign));
	if (!ptr_end) {
		free (esil_buf);
		return;
	}
	*ptr_end = 0;
	addr = ptr_end;
	while ((addr[0] != '0' || addr[1] != 'x') && addr >= esil_buf + 1 && *addr != ',') {
		addr--;
	}
	if (strncmp (addr, "0x", 2)) {
		//XXX: This is a workaround for inconsistent esil
		if (!op->stackop && op->dst) {
			const char *sp = r_reg_get_name (anal->reg, R_REG_NAME_SP);
			const char *bp = r_reg_get_name (anal->reg, R_REG_NAME_BP);
			const char *rn = op->dst[0].reg ? op->dst[0].reg->name : NULL;
			if (rn && ((bp && !strcmp (bp, rn)) || (sp && !strcmp (sp, rn)))) {
				if (anal->verbose) {
					eprintf ("Warning: Analysis didn't fill op->stackop for instruction that alters stack at 0x%"PFMT64x".\n", op->addr);
				}
				goto beach;
			}
		}
		if (*addr == ',') {
			addr++;
		}
		if (!op->stackop && op->type != R_ANAL_OP_TYPE_PUSH && op->type != R_ANAL_OP_TYPE_POP 
			&& op->type != R_ANAL_OP_TYPE_RET && r_str_isnumber (addr)) {
			ptr = (st64)r_num_get (NULL, addr);
			if (ptr && op->src[0] && ptr == op->src[0]->imm) {
				goto beach;
			}
		} else if ((op->stackop == R_ANAL_STACK_SET) || (op->stackop == R_ANAL_STACK_GET)) {
			if (op->ptr % 4) {
				goto beach;
			}
			ptr = R_ABS (op->ptr);
		} else {
			goto beach;
		}
	} else {
		ptr = (st64)r_num_get (NULL, addr);
	}

	int rw = (op->direction == R_ANAL_OP_DIR_WRITE) ? 1 : 0;
	if (*sign == '+') {
		const bool isarg = fcn->bp_frame && ((ptr >= fcn->stack) || (type != 's'));
		const char *pfx = isarg ? ARGPREFIX : VARPREFIX;
		ut64 bp_off = R_ABS (ptr);
		if (type == 's') {
			bp_off = ptr - fcn->stack;
		}
		char *varname = get_varname (anal, fcn, type, pfx, bp_off);
		if (varname) {
			r_anal_var_add (anal, fcn->addr, 1, bp_off, type, NULL, anal->bits / 8, isarg, varname);
			r_anal_var_access (anal, fcn->addr, type, 1, bp_off, ptr, rw, op->addr);
			free (varname);
		}
	} else {
		char *varname = get_varname (anal, fcn, type, VARPREFIX, -ptr);
		if (varname) {
			r_anal_var_add (anal, fcn->addr, 1, -ptr, type, NULL, anal->bits / 8, 0, varname);
			r_anal_var_access (anal, fcn->addr, type, 1, -ptr, -ptr, rw, op->addr);
			free (varname);
		}
	}
beach:
	free (esil_buf);
}

static bool is_reg_in_src (const char *regname, RAnal *anal, RAnalOp *op);

static bool is_used_like_arg(const char *regname, const char *opsreg, const char *opdreg, RAnalOp *op, RAnal *anal) {
	#define STR_EQUAL(s1, s2) s1 && s2 && !strcmp (s1, s2)
	RAnalValue *dst = op->dst;
	RAnalValue *src = op->src[0];
	switch (op->type) {
	case R_ANAL_OP_TYPE_POP:
		return false;
	case R_ANAL_OP_TYPE_MOV:
		return (is_reg_in_src (regname, anal, op)) || (STR_EQUAL (opdreg, regname) && dst->memref);
	case R_ANAL_OP_TYPE_CMOV:
		if (STR_EQUAL (opdreg, regname)) {
			return false;
		}
		if (is_reg_in_src (regname, anal, op)) {
			return true;
		}
		return false;
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_LOAD:
		if (is_reg_in_src (regname, anal, op)) {
			return true;
		}
		if (STR_EQUAL (opdreg, regname)) {
			return false;
		}
    		return false;
	case R_ANAL_OP_TYPE_XOR:
		if (STR_EQUAL (opsreg, opdreg) && !src->memref && !dst->memref) {
			return false;
		}
		//fallthrough
	default:
		if ((op->type == R_ANAL_OP_TYPE_ADD || op->type == R_ANAL_OP_TYPE_SUB) && STR_EQUAL (anal->cur->arch, "arm")) {
			if (STR_EQUAL (opdreg, regname)) {
				return false;
			}
			if (is_reg_in_src (regname, anal, op)) {
				return true;
			}
		}
		return ((STR_EQUAL (opdreg, regname)) || (is_reg_in_src (regname, anal, op)));
	}
}

static bool is_reg_in_src (const char *regname, RAnal *anal, RAnalOp *op) {
	const char* opsreg0 = op->src[0] ? get_regname (anal, op->src[0]) : NULL;
	const char* opsreg1 = op->src[1] ? get_regname (anal, op->src[1]) : NULL;
	const char* opsreg2 = op->src[2] ? get_regname (anal, op->src[2]) : NULL;
	return (STR_EQUAL (regname, opsreg0)) || (STR_EQUAL (regname, opsreg1)) || (STR_EQUAL (regname, opsreg2));
}

R_API void r_anal_extract_rarg(RAnal *anal, RAnalOp *op, RAnalFunction *fcn, int *reg_set, int *count) {
	int i, argc = 0;
	r_return_if_fail (anal && op && fcn);
	const char *opsreg = op->src[0] ? get_regname (anal, op->src[0]) : NULL;
	const char *opdreg = op->dst ? get_regname (anal, op->dst) : NULL;
	if (!fcn->cc) {
		R_LOG_DEBUG ("No calling convention for function '%s' to extract register arguments\n", fcn->name);
		return;
	}
	char *fname = fcn->name;
	Sdb *TDB = anal->sdb_types;
	int max_count = r_anal_cc_max_arg (anal, fcn->cc);
	if (!max_count || (*count >= max_count)) {
		return;
	}
	if (fname) {
		char *tmp = strchr (fname, '.');
		if (tmp) {
			fname = tmp + 1;
		}
		argc = r_type_func_args_count (TDB, fname);
	}
	for (i = 0; i < max_count; i++) {
		const char *regname = r_anal_cc_arg (anal, fcn->cc, i);
		if (regname) {
			bool is_used_like_an_arg = is_used_like_arg (regname, opsreg, opdreg, op, anal);
			if (reg_set[i] != 2 && is_used_like_an_arg) {
				const char *vname = NULL;
				char *type = NULL;
				char *name = NULL;
				int delta = 0;
				RRegItem *ri = r_reg_get (anal->reg, regname, -1);
				if (ri) {
					delta = ri->index;
				}
				if ((i < argc) && fname) {
					type = r_type_func_args_type (TDB, fname, i);
					vname = r_type_func_args_name (TDB, fname, i);
				}
				if (!vname) {
					name = r_str_newf ("%s%d", "arg", i + 1);
					vname = name;
				}
				r_anal_var_add (anal, fcn->addr, 1, delta, R_ANAL_VAR_KIND_REG, type,
						anal->bits / 8, 1, vname);
				if (op->var && op->var->kind != R_ANAL_VAR_KIND_REG) {
					r_anal_var_link (anal, op->addr, op->var);
				}
				r_anal_var_access (anal, fcn->addr, R_ANAL_VAR_KIND_REG, 1, delta, 0, 0, op->addr);
				r_meta_set_string (anal, R_META_TYPE_VARTYPE, op->addr, vname);
				free (name);
				free (type);
				(*count)++;
			} else {
				if (is_reg_in_src (regname, anal, op)) {
					reg_set[i] = 2;
				}
				if (STR_EQUAL (opdreg, regname)) {
					reg_set[i] = 2;
				}
				continue;
			}
			if (is_reg_in_src (regname, anal, op)) {
				reg_set[i] = 1;
			}
			if (STR_EQUAL (regname, opdreg)) {
				reg_set[i] = 1;
			}
		}
	}
}

R_API void r_anal_extract_vars(RAnal *anal, RAnalFunction *fcn, RAnalOp *op) {
	r_return_if_fail (anal && fcn && op);

	const char *BP = anal->reg->name[R_REG_NAME_BP];
	const char *SP = anal->reg->name[R_REG_NAME_SP];
	extract_arg (anal, fcn, op, BP, "+", 'b');
	extract_arg (anal, fcn, op, BP, "-", 'b');
	extract_arg (anal, fcn, op, SP, "+", 's');
}

static RList *var_generate_list(RAnal *a, RAnalFunction *fcn, int kind, bool dynamicVars) {
	if (!a || !fcn) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree) r_anal_var_free);
	if (kind < 1) {
		kind = R_ANAL_VAR_KIND_BPV; // by default show vars
	}
	char *varlist = sdb_get (DB, sdb_fmt ("fcn.0x%"PFMT64x ".%c", fcn->addr, kind), 0);
	if (varlist && *varlist) {
		char *next, *ptr = varlist;
		do {
			char *word = sdb_anext (ptr, &next);
			if (r_str_nlen (word, 3) < 3) {
				return NULL;
			}
			const char *vardef = sdb_const_get (DB, sdb_fmt (
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
				av->addr = fcn->addr;
				av->delta = delta;
				av->kind = kind;
				av->name = strdup (vt.name);
				av->isarg = vt.isarg;
				av->regname = strdup (vt.regname);
				av->size = vt.size;
				av->type = strdup (vt.type);
				if (av->isarg && kind == R_ANAL_VAR_KIND_REG) {
					bool found = false;
					RRegItem *reg = r_reg_get (a->reg, vt.regname, -1);
					if (reg) {
						int i;
						int arg_max = fcn->cc ? r_anal_cc_max_arg (a, fcn->cc) : 0;
						for (i = 0; i < arg_max; i++) {
							if (!strcmp (reg->name, r_anal_cc_arg (a, fcn->cc, i))) {
								if (delta != reg->index) {
									delta = reg->index;
								}
								av->argnum = i;
								found = true;
								break;
							}
						}
					}
					if (!found) {
						av->argnum = delta;
					}
				}
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
	RList *reg_vars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_REG);
	RList *bpv_vars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_BPV);
	RList *spv_vars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_SPV);
	r_list_join (list, reg_vars);
	r_list_join (list, bpv_vars);
	r_list_join (list, spv_vars);
	r_list_free (reg_vars);
	r_list_free (bpv_vars);
	r_list_free (spv_vars);
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

static int regvar_comparator(const RAnalVar *a, const RAnalVar *b){
	// avoid NULL dereference
	return (a && b)? a->argnum > b->argnum: false;
}

R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, int kind, int mode, PJ *pj) {
	RList *list = r_anal_var_list (anal, fcn, kind);
	RAnalVar *var;
	RListIter *iter;
	if (!pj && mode == 'j') {
		return;
	}
	if (mode == 'j') {
		pj_a (pj);
	}
	if (!list) {
		if (mode == 'j') {
			pj_end (pj);
		}
		return;
	}
	r_list_sort (list, (RListComparator) var_comparator);
	r_list_foreach (list, iter, var) {
		if (var->kind != kind) {
			continue;
		}
		switch (mode) {
		case '*':
			// we can't express all type info here :(
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
					pj_o (pj);
					pj_ks (pj, "name" ,var->name);
					pj_ks (pj, "kind", "arg");
					pj_ks (pj, "type", var->type);
					pj_k (pj, "ref");
					pj_o (pj);
					pj_ks (pj, "base", anal->reg->name[R_REG_NAME_BP]);
					pj_kn (pj, "offset", (st64)var->delta);
					pj_end (pj);
					pj_end (pj);
				} else {
					pj_o (pj);
					pj_ks (pj, "name" ,var->name);
					pj_ks (pj, "kind", "var");
					pj_ks (pj, "type", var->type);
					pj_k (pj, "ref");
					pj_o (pj);
					pj_ks (pj, "base", anal->reg->name[R_REG_NAME_BP]);
					pj_kn (pj, "offset", (st64)-R_ABS (var->delta));
					pj_end (pj);
					pj_end (pj);
				}
				break;
			case R_ANAL_VAR_KIND_REG: {
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					eprintf ("Register not found");
					break;
				}
				pj_o (pj);
				pj_ks (pj, "name", var->name);
				pj_ks (pj, "kind", "reg");
				pj_ks (pj, "type", var->type);
				pj_ks (pj, "ref", i->name);
				pj_end (pj);
			}
				break;
			case R_ANAL_VAR_KIND_SPV:
				if (var->isarg) {
					pj_o (pj);
					pj_ks (pj, "name", var->name);
					pj_ks (pj, "kind", "arg");
					pj_ks (pj, "type", var->type);
					pj_k (pj, "ref");
					pj_o (pj);
					pj_ks (pj, "base", anal->reg->name[R_REG_NAME_SP]);
					pj_kn (pj, "offset", var->delta);
					pj_end (pj);
					pj_end (pj);
				} else {
					pj_o (pj);
					pj_ks (pj, "name", var->name);
					pj_ks (pj, "kind", "var");
					pj_ks (pj, "type", var->type);
					pj_k (pj, "ref");
					pj_o (pj);
					pj_ks (pj, "base", anal->reg->name[R_REG_NAME_SP]);
					pj_kn (pj, "offset", (st64)(-R_ABS (var->delta)));
					pj_end (pj);
					pj_end (pj);
				}
				break;
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
				anal->cb_printf ("arg %s %s @ %s\n",
					var->type, var->name, i->name);
				}
				break;
			case R_ANAL_VAR_KIND_SPV:
			{
				int delta = fcn->maxstack + var->delta;
				if (!var->isarg) {
					anal->cb_printf ("var %s %s @ %s+0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_SP],
						delta);
				} else {
					anal->cb_printf ("arg %s %s @ %s+0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_SP],
						delta);

				}
			}
				break;
			}
		}
	}
	if (mode == 'j') {
		pj_end (pj);
	}
	r_list_free (list);
}

R_API void r_anal_fcn_vars_cache_init(RAnal *anal, RAnalFcnVarsCache *cache, RAnalFunction *fcn) {
	cache->bvars = r_anal_var_list (anal, fcn, 'b');
	cache->rvars = r_anal_var_list (anal, fcn, 'r');
	cache->svars = r_anal_var_list (anal, fcn, 's');
	r_list_sort (cache->bvars, (RListComparator)var_comparator);
	r_list_sort (cache->rvars, (RListComparator)regvar_comparator);
	r_list_sort (cache->svars, (RListComparator)var_comparator);
}

R_API void r_anal_fcn_vars_cache_fini(RAnalFcnVarsCache *cache) {
	if (!cache) {
		return;
	}
	r_list_free (cache->bvars);
	r_list_free (cache->rvars);
	r_list_free (cache->svars);
}

R_API char *r_anal_fcn_format_sig(R_NONNULL RAnal *anal, R_NONNULL RAnalFunction *fcn, R_NULLABLE char *fcn_name,
		R_NULLABLE RAnalFcnVarsCache *reuse_cache, R_NULLABLE const char *fcn_name_pre, R_NULLABLE const char *fcn_name_post) {
	RAnalFcnVarsCache *cache = NULL;

	if (!fcn_name) {
		fcn_name = fcn->name;
		if (!fcn_name) {
			return NULL;
		}
	}

	RStrBuf *buf = r_strbuf_new (NULL);
	if (!buf) {
		return NULL;
	}

	Sdb *TDB = anal->sdb_types;
	char *type_fcn_name = r_type_func_guess (TDB, fcn_name);
	if (type_fcn_name && r_type_func_exist (TDB, type_fcn_name)) {
		const char *fcn_type = r_type_func_ret (anal->sdb_types, type_fcn_name);
		if (fcn_type) {
			const char *sp = " ";
			if (*fcn_type && (fcn_type[strlen (fcn_type) - 1] == '*')) {
				sp = "";
			}
			r_strbuf_appendf (buf, "%s%s", fcn_type, sp);
		}
	}

	if (fcn_name_pre) {
		r_strbuf_append (buf, fcn_name_pre);
	}
	r_strbuf_append (buf, fcn_name);
	if (fcn_name_post) {
		r_strbuf_append (buf, fcn_name_post);
	}
	r_strbuf_append (buf, " (");

	if (type_fcn_name && r_type_func_exist (TDB, type_fcn_name)) {
		int i, argc = r_type_func_args_count (TDB, type_fcn_name);
		bool comma = true;
		// This avoids false positives present in argument recovery
		// and straight away print arguments fetched from types db
		for (i = 0; i < argc; i++) {
			char *type = r_type_func_args_type (TDB, type_fcn_name, i);
			const char *name = r_type_func_args_name (TDB, type_fcn_name, i);
			if (!type || !name) {
				eprintf ("Missing type for %s\n", type_fcn_name);
				goto beach;
			}
			if (i == argc - 1) {
				comma = false;
			}
			size_t len = strlen (type);
			const char *tc = len > 0 && type[len - 1] == '*'? "": " ";
			r_strbuf_appendf (buf, "%s%s%s%s", type, tc, name, comma? ", ": "");
			free (type);
		}
		goto beach;
	}
	R_FREE (type_fcn_name);


	cache = reuse_cache;
	if (!cache) {
		cache = R_NEW0 (RAnalFcnVarsCache);
		if (!cache) {
			type_fcn_name = NULL;
			goto beach;
		}
		r_anal_fcn_vars_cache_init (anal, cache, fcn);
	}

	bool comma = true;
	bool arg_bp = false;
	size_t tmp_len;
	RAnalVar *var;
	RListIter *iter;

	r_list_foreach (cache->rvars, iter, var) {
		tmp_len = strlen (var->type);
		r_strbuf_appendf (buf, "%s%s%s%s", var->type,
			tmp_len && var->type[tmp_len - 1] == '*' ? "" : " ",
			var->name, iter->n ? ", " : "");
	}

	r_list_foreach (cache->bvars, iter, var) {
		if (var->delta > 0) {
			if (!r_list_empty (cache->rvars) && comma) {
				r_strbuf_append (buf, ", ");
				comma = false;
			}
			arg_bp = true;
			tmp_len = strlen (var->type);
			r_strbuf_appendf (buf, "%s%s%s%s", var->type,
				tmp_len && var->type[tmp_len - 1] =='*' ? "" : " ",
				var->name, iter->n ? ", " : "");
		}
	}

	comma = true;
	const char *maybe_comma = ", ";
	r_list_foreach (cache->svars, iter, var) {
		if (var->isarg) {
			if (!*maybe_comma || ((arg_bp || !r_list_empty (cache->rvars)) && comma)) {
				comma = false;
				r_strbuf_append (buf, ", ");
			}
			tmp_len = strlen (var->type);
			if (iter->n && ((RAnalVar *)iter->n->data)->isarg) {
				maybe_comma = ", ";
			} else {
				maybe_comma = "";
			}
			r_strbuf_appendf (buf, "%s%s%s%s", var->type,
				tmp_len && var->type[tmp_len - 1] =='*' ? "" : " ",
				var->name, maybe_comma);
		}
	}

beach:
	r_strbuf_append (buf, ");");
	R_FREE (type_fcn_name);
	if (!reuse_cache) {
		// !reuse_cache => we created our own cache
		r_anal_fcn_vars_cache_fini (cache);
		free (cache);
	}
	return r_strbuf_drain (buf);
}
