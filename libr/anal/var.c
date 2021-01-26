/* radare - LGPL - Copyright 2010-2020 - pancake, oddcoder */

#include <r_anal.h>
#include <r_util.h>
#include <r_cons.h>
#include <r_core.h>
#include <r_list.h>

#define ACCESS_CMP(x, y) ((st64)((ut64)(x) - ((RAnalVarAccess *)y)->offset))

R_API bool r_anal_var_display(RAnal *anal, RAnalVar *var) {
	char *fmt = r_type_format (anal->sdb_types, var->type);
	RRegItem *i;
	if (!fmt) {
		eprintf ("type:%s doesn't exist\n", var->type);
		return false;
	}
	bool usePxr = !strcmp (var->type, "int"); // hacky but useful
	switch (var->kind) {
	case R_ANAL_VAR_KIND_REG:
		i = r_reg_index_get (anal->reg, var->delta);
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
	case R_ANAL_VAR_KIND_BPV: {
		const st32 real_delta = var->delta + var->fcn->bp_off;
		const ut32 udelta = R_ABS (real_delta);
		const char sign = real_delta >= 0 ? '+' : '-';
		if (usePxr) {
			anal->cb_printf ("pxr $w @%s%c0x%x\n", anal->reg->name[R_REG_NAME_BP], sign, udelta);
		} else {
			anal->cb_printf ("pf %s @%s%c0x%x\n", fmt, anal->reg->name[R_REG_NAME_BP], sign, udelta);
		}
	}
		break;
	case R_ANAL_VAR_KIND_SPV: {
		ut32 udelta = R_ABS (var->delta + var->fcn->maxstack);
		if (usePxr) {
			anal->cb_printf ("pxr $w @%s+0x%x\n", anal->reg->name[R_REG_NAME_SP], udelta);
		} else {
			anal->cb_printf ("pf %s @ %s+0x%x\n", fmt, anal->reg->name[R_REG_NAME_SP], udelta);
		}
		break;
	}
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

R_API bool r_anal_function_rebase_vars(RAnal *a, RAnalFunction *fcn) {
	r_return_val_if_fail (a && fcn, false);
	RListIter *it;
	RAnalVar *var;
	RList *var_list = r_anal_var_all_list (a, fcn);
	r_return_val_if_fail (var_list, false);

	r_list_foreach (var_list, it, var) {
		// Resync delta in case the registers list changed
		if (var->isarg && var->kind == 'r') {
			RRegItem *reg = r_reg_get (a->reg, var->regname, -1);
			if (reg) {
				if (var->delta != reg->index) {
					var->delta = reg->index;
				}
			}
		}
	}

	r_list_free (var_list);
	return true;
}

// If the type of var is a struct,
// remove all other vars that are overlapped by var and are at the offset of one of its struct members
static void shadow_var_struct_members(RAnalVar *var) {
	Sdb *TDB = var->fcn->anal->sdb_types;
	const char *type_kind = sdb_const_get (TDB, var->type, 0);
	if (type_kind && r_str_startswith (type_kind, "struct")) {
		char *field;
		int field_n;
		char *type_key = r_str_newf ("%s.%s", type_kind, var->type);
		for (field_n = 0; (field = sdb_array_get (TDB, type_key, field_n, NULL)); field_n++) {
			char field_key[0x300];
			if (snprintf (field_key, sizeof (field_key), "%s.%s", type_key, field) < 0) {
				continue;
			}
			char *field_type = sdb_array_get (TDB, field_key, 0, NULL);
			ut64 field_offset = sdb_array_get_num (TDB, field_key, 1, NULL);
			if (field_offset != 0) { // delete variables which are overlaid by structure
				RAnalVar *other = r_anal_function_get_var (var->fcn, var->kind, var->delta + field_offset);
				if (other && other != var) {
					r_anal_var_delete (other);
				}
			}
			free (field_type);
			free (field);
		}
		free (type_key);
	}
}

R_API RAnalVar *r_anal_function_set_var(RAnalFunction *fcn, int delta, char kind, R_NULLABLE const char *type, int size, bool isarg, R_NONNULL const char *name) {
	r_return_val_if_fail (fcn && name, NULL);
	RAnalVar *existing = r_anal_function_get_var_byname (fcn, name);
	if (existing && (existing->kind != kind || existing->delta != delta)) {
		// var name already exists at a different kind+delta
		return NULL;
	}
	RRegItem *reg = NULL;
	if (!kind) {
		kind = R_ANAL_VAR_KIND_BPV;
	}
	if (!type) {
		type = __int_type_from_size (size);
		if (!type) {
			type = __int_type_from_size (fcn->anal->bits);
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
		return NULL;
	}
	if (kind == R_ANAL_VAR_KIND_REG) {
		reg = r_reg_index_get (fcn->anal->reg, R_ABS (delta));
		if (!reg) {
			eprintf ("Register wasn't found at the given delta\n");
			return NULL;
		}
	}
	RAnalVar *var = r_anal_function_get_var (fcn, kind, delta);
	if (!var) {
		var = R_NEW0 (RAnalVar);
		if (!var) {
			return NULL;
		}
		r_pvector_push (&fcn->vars, var);
		var->fcn = fcn;
		r_vector_init (&var->accesses, sizeof (RAnalVarAccess), NULL, NULL);
		r_vector_init (&var->constraints, sizeof (RAnalVarConstraint), NULL, NULL);
	} else {
		free (var->name);
		free (var->regname);
		free (var->type);
	}
	var->name = strdup (name);
	var->regname = reg ? strdup (reg->name) : NULL; // TODO: no strdup here? pool? or not keep regname at all?
	var->type = strdup (type);
	var->kind = kind;
	var->isarg = isarg;
	var->delta = delta;
	shadow_var_struct_members (var);
	return var;
}

R_API void r_anal_var_set_type(RAnalVar *var, const char *type) {
	char *nt = strdup (type);
	if (!nt) {
		return;
	}
	free (var->type);
	var->type = nt;
	shadow_var_struct_members (var);
}

static void var_free(RAnalVar *var) {
	if (!var) {
		return;
	}
	r_anal_var_clear_accesses (var);
	r_vector_fini (&var->constraints);
	free (var->name);
	free (var->regname);
	free (var->type);
	free (var->comment);
	free (var);
}

R_API void r_anal_var_delete(RAnalVar *var) {
	r_return_if_fail (var);
	RAnalFunction *fcn = var->fcn;
	size_t i;
	for (i = 0; i < r_pvector_len (&fcn->vars); i++) {
		RAnalVar *v = r_pvector_at (&fcn->vars, i);
		if (v == var) {
			r_pvector_remove_at (&fcn->vars, i);
			var_free (v);
			return;
		}
	}
}

R_API void r_anal_function_delete_vars_by_kind(RAnalFunction *fcn, RAnalVarKind kind) {
	r_return_if_fail (fcn);
	size_t i;
	for (i = 0; i < r_pvector_len (&fcn->vars);) {
		RAnalVar *var = r_pvector_at (&fcn->vars, i);
		if (var->kind == kind) {
			r_pvector_remove_at (&fcn->vars, i);
			var_free (var);
			continue;
		}
		i++;
	}
}

R_API void r_anal_function_delete_all_vars(RAnalFunction *fcn) {
	void **it;
	r_pvector_foreach (&fcn->vars, it) {
		var_free (*it);
	}
	r_pvector_clear (&fcn->vars);
}

R_API void r_anal_function_delete_unused_vars(RAnalFunction *fcn) {
	void **v;
	RPVector *vars_clone = (RPVector *)r_vector_clone ((RVector *)&fcn->vars);
	r_pvector_foreach (vars_clone, v) {
		RAnalVar *var = *v;
		if (r_vector_empty (&var->accesses)) {
			r_anal_function_delete_var (fcn, var);
		}
	}
	r_pvector_free (vars_clone);
}

R_API void r_anal_function_delete_var(RAnalFunction *fcn, RAnalVar *var) {
	r_return_if_fail (fcn && var);
	r_pvector_remove_data (&fcn->vars, var);
	var_free (var);
}

R_API R_BORROW RAnalVar *r_anal_function_get_var_byname(RAnalFunction *fcn, const char *name) {
	r_return_val_if_fail (fcn && name, NULL);
	void **it;
	r_pvector_foreach (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (!strcmp (var->name, name)) {
			return var;
		}
	}
	return NULL;
}

R_API RAnalVar *r_anal_function_get_var(RAnalFunction *fcn, char kind, int delta) {
	void **it;
	r_pvector_foreach (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (var->kind == kind && var->delta == delta) {
			return var;
		}
	}
	return NULL;
}

R_API ut64 r_anal_var_addr(RAnalVar *var) {
	r_return_val_if_fail (var, UT64_MAX);
	RAnal *anal = var->fcn->anal;
	const char *regname = NULL;
	if (var->kind == R_ANAL_VAR_KIND_BPV) {
		regname = r_reg_get_name (anal->reg, R_REG_NAME_BP);
		return r_reg_getv (anal->reg, regname) + var->delta + var->fcn->bp_off;
	} else if (var->kind == R_ANAL_VAR_KIND_SPV) {
		regname = r_reg_get_name (anal->reg, R_REG_NAME_SP);
		return r_reg_getv (anal->reg, regname) + var->delta;
	}
	return 0;
}

R_API st64 r_anal_function_get_var_stackptr_at(RAnalFunction *fcn, st64 delta, ut64 addr) {
	st64 offset = addr - fcn->addr;
	RPVector *inst_accesses = ht_up_find (fcn->inst_vars, offset, NULL);
	if (!inst_accesses) {
		return ST64_MAX;
	}
	RAnalVar *var = NULL;
	void **it;
	r_pvector_foreach (inst_accesses, it) {
		RAnalVar *v = *it;
		if (v->delta == delta) {
			var = v;
			break;
		}
	}
	if (!var) {
		return ST64_MAX;
	}
	size_t index;
	r_vector_lower_bound (&var->accesses, offset, index, ACCESS_CMP);
	RAnalVarAccess *acc = NULL;
	if (index < var->accesses.len) {
		acc = r_vector_index_ptr (&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		return ST64_MAX;
	}
	return acc->stackptr;
}

R_API const char *r_anal_function_get_var_reg_at(RAnalFunction *fcn, st64 delta, ut64 addr) {
	st64 offset = addr - fcn->addr;
	RPVector *inst_accesses = ht_up_find (fcn->inst_vars, offset, NULL);
	if (!inst_accesses) {
		return NULL;
	}
	RAnalVar *var = NULL;
	void **it;
	r_pvector_foreach (inst_accesses, it) {
		RAnalVar *v = *it;
		if (v->delta == delta) {
			var = v;
			break;
		}
	}
	if (!var) {
		return NULL;
	}
	size_t index;
	r_vector_lower_bound (&var->accesses, offset, index, ACCESS_CMP);
	RAnalVarAccess *acc = NULL;
	if (index < var->accesses.len) {
		acc = r_vector_index_ptr (&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		return NULL;
	}
	return acc->reg;
}

R_API bool r_anal_var_check_name(const char *name) {
	return !isdigit ((unsigned char)*name) && strcspn (name, "., =/");
}

R_API bool r_anal_var_rename(RAnalVar *var, const char *new_name, bool verbose) {
	r_return_val_if_fail (var, false);
	if (!r_anal_var_check_name (new_name)) {
		return false;
	}
	RAnalVar *v1 = r_anal_function_get_var_byname (var->fcn, new_name);
	if (v1) {
		if (verbose) {
			eprintf ("variable or arg with name `%s` already exist\n", new_name);
		}
		return false;
	}
	char *nn = strdup (new_name);
	if (!nn) {
		return false;
	}
	free (var->name);
	var->name = nn;
	return true;
}

R_API int r_anal_var_get_argnum(RAnalVar *var) {
	r_return_val_if_fail (var, -1);
	RAnal *anal = var->fcn->anal;
	if (!var->isarg || var->kind != R_ANAL_VAR_KIND_REG) { // TODO: support bp and sp too
		return -1;
	}
	if (!var->regname) {
		return -1;
	}
	RRegItem *reg = r_reg_get (anal->reg, var->regname, -1);
	if (!reg) {
		return -1;
	}
	int i;
	int arg_max = var->fcn->cc ? r_anal_cc_max_arg (anal, var->fcn->cc) : 0;
	for (i = 0; i < arg_max; i++) {
		const char *reg_arg = r_anal_cc_arg (anal, var->fcn->cc, i);
		if (reg_arg && !strcmp (reg->name, reg_arg)) {
			return i;
		}
	}
	return -1;
}

R_API R_BORROW RPVector *r_anal_function_get_vars_used_at(RAnalFunction *fcn, ut64 op_addr) {
	r_return_val_if_fail (fcn, NULL);
	return ht_up_find (fcn->inst_vars, op_addr - fcn->addr, NULL);
}

R_API R_DEPRECATE RAnalVar *r_anal_get_used_function_var(RAnal *anal, ut64 addr) {
	RList *fcns = r_anal_get_functions_in (anal, addr);
	if (!fcns) {
		return NULL;
	}
	RAnalVar *var = NULL;
	RListIter *it;
	RAnalFunction *fcn;
	r_list_foreach (fcns, it, fcn) {
		RPVector *used_vars = r_anal_function_get_vars_used_at (fcn, addr);
		if (used_vars && !r_pvector_empty (used_vars)) {
			var = r_pvector_at (used_vars, 0);
			break;
		}
	}
	r_list_free (fcns);
	return var;
}

R_API RAnalVar *r_anal_var_get_dst_var(RAnalVar *var) {
	r_return_val_if_fail (var, NULL);
	RAnalVarAccess *acc;
	r_vector_foreach (&var->accesses, acc) {
		if (!(acc->type & R_ANAL_VAR_ACCESS_TYPE_READ)) {
			continue;
		}
		ut64 addr = var->fcn->addr + acc->offset;
		RPVector *used_vars = r_anal_function_get_vars_used_at (var->fcn, addr);
		void **it;
		r_pvector_foreach (used_vars, it) {
			RAnalVar *used_var = *it;
			if (used_var == var) {
				continue;
			}
			RAnalVarAccess *other_acc = r_anal_var_get_access_at (used_var, addr);
			if (other_acc && other_acc->type & R_ANAL_VAR_ACCESS_TYPE_WRITE) {
				return used_var;
			}
		}
	}
	return NULL;
}

R_API void r_anal_var_set_access(RAnalVar *var, const char *reg, ut64 access_addr, int access_type, st64 stackptr) {
	r_return_if_fail (var);
	st64 offset = access_addr - var->fcn->addr;

	// accesses are stored ordered by offset, use binary search to get the matching existing or the index to insert a new one
	size_t index;
	r_vector_lower_bound (&var->accesses, offset, index, ACCESS_CMP);
	RAnalVarAccess *acc = NULL;
	if (index < var->accesses.len) {
		acc = r_vector_index_ptr (&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		acc = r_vector_insert (&var->accesses, index, NULL);
		acc->offset = offset;
		acc->type = 0;
	}

	acc->type |= (ut8)access_type;
	acc->stackptr = stackptr;
	acc->reg = r_str_constpool_get (&var->fcn->anal->constpool, reg);

	// add the inverse reference from the instruction to the var
	RPVector *inst_accesses = ht_up_find (var->fcn->inst_vars, (ut64)offset, NULL);
	if (!inst_accesses) {
		inst_accesses = r_pvector_new (NULL);
		if (!inst_accesses) {
			return;
		}
		ht_up_insert (var->fcn->inst_vars, (ut64)offset, inst_accesses);
	}
	if (!r_pvector_contains (inst_accesses, var)) {
		r_pvector_push (inst_accesses, var);
	}
}

R_API void r_anal_var_remove_access_at(RAnalVar *var, ut64 address) {
	r_return_if_fail (var);
	st64 offset = address - var->fcn->addr;
	size_t index;
	r_vector_lower_bound (&var->accesses, offset, index, ACCESS_CMP);
	if (index >= var->accesses.len) {
		return;
	}
	RAnalVarAccess *acc = r_vector_index_ptr (&var->accesses, index);
	if (acc->offset == offset) {
		r_vector_remove_at (&var->accesses, index, NULL);
		RPVector *inst_accesses = ht_up_find (var->fcn->inst_vars, (ut64)offset, NULL);
		r_pvector_remove_data (inst_accesses, var);
	}
}

R_API void r_anal_var_clear_accesses(RAnalVar *var) {
	r_return_if_fail (var);
	RAnalFunction *fcn = var->fcn;
	if (fcn->inst_vars) {
		// remove all inverse references to the var's accesses
		RAnalVarAccess *acc;
		r_vector_foreach (&var->accesses, acc) {
			RPVector *inst_accesses = ht_up_find (fcn->inst_vars, (ut64)acc->offset, NULL);
			if (!inst_accesses) {
				continue;
			}
			r_pvector_remove_data (inst_accesses, var);
		}
	}
	r_vector_clear (&var->accesses);
}

R_API RAnalVarAccess *r_anal_var_get_access_at(RAnalVar *var, ut64 addr) {
	r_return_val_if_fail (var, NULL);
	st64 offset = addr - var->fcn->addr;
	size_t index;
	r_vector_lower_bound (&var->accesses, offset, index, ACCESS_CMP);
	if (index >= var->accesses.len) {
		return NULL;
	}
	RAnalVarAccess *acc = r_vector_index_ptr (&var->accesses, index);
	if (acc->offset == offset) {
		return acc;
	}
	return NULL;
}

R_API void r_anal_var_add_constraint(RAnalVar *var, R_BORROW RAnalVarConstraint *constraint) {
	r_vector_push (&var->constraints, constraint);
}

R_API char *r_anal_var_get_constraints_readable(RAnalVar *var) {
	size_t n = var->constraints.len;
	if (!n) {
		return NULL;
	}
	bool low = false, high = false;
	RStrBuf sb;
	r_strbuf_init (&sb);
	size_t i;
	for (i = 0; i < n; i += 1) {
		RAnalVarConstraint *constr = r_vector_index_ptr (&var->constraints, i);
		switch (constr->cond) {
		case R_ANAL_COND_LE:
			if (high) {
				r_strbuf_append (&sb, " && ");
			}
			r_strbuf_appendf (&sb, "<= 0x%"PFMT64x "", constr->val);
			low = true;
			break;
		case R_ANAL_COND_LT:
			if (high) {
				r_strbuf_append (&sb, " && ");
			}
			r_strbuf_appendf (&sb, "< 0x%"PFMT64x "", constr->val);
			low = true;
			break;
		case R_ANAL_COND_GE:
			r_strbuf_appendf (&sb, ">= 0x%"PFMT64x "", constr->val);
			high = true;
			break;
		case R_ANAL_COND_GT:
			r_strbuf_appendf (&sb, "> 0x%"PFMT64x "", constr->val);
			high = true;
			break;
		default:
			break;
		}
		if (low && high && i != n - 1) {
			r_strbuf_append (&sb, " || ");
			low = false;
			high = false;
		}
	}
	return r_strbuf_drain_nofree (&sb);
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

static bool var_add_structure_fields_to_list(RAnal *a, RAnalVar *av, RList *list) {
	Sdb *TDB = a->sdb_types;
	const char *type_kind = sdb_const_get (TDB, av->type, 0);
	if (type_kind && !strcmp (type_kind, "struct")) {
		char *field_name, *new_name;
		int field_n;
		char *type_key = r_str_newf ("%s.%s", type_kind, av->type);
		for (field_n = 0; (field_name = sdb_array_get (TDB, type_key, field_n, NULL)); field_n++) {
			char *field_key = r_str_newf ("%s.%s", type_key, field_name);
			char *field_type = sdb_array_get (TDB, field_key, 0, NULL);
			ut64 field_offset = sdb_array_get_num (TDB, field_key, 1, NULL);
			new_name = r_str_newf ("%s.%s", av->name, field_name);
			RAnalVarField *field = R_NEW0 (RAnalVarField);
			field->name = new_name;
			field->delta = av->delta + field_offset;
			field->field = true;
			r_list_append (list, field);
			free (field_type);
			free (field_key);
			free (field_name);
		}
		free (type_key);
		return true;
	}
	return false;
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

R_API R_OWN char *r_anal_function_autoname_var(RAnalFunction *fcn, char kind, const char *pfx, int ptr) {
	void **it;
	const ut32 uptr = R_ABS (ptr);
	char *varname = r_str_newf ("%s_%xh", pfx, uptr);
	r_pvector_foreach (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (!strcmp (varname, var->name)) {
			if (var->kind != kind) {
				const char *k = kind == R_ANAL_VAR_KIND_SPV ? "sp" : "bp";
				free (varname);
				varname = r_str_newf ("%s_%s_%xh", pfx, k, uptr);
				return varname;
			}
			int i = 2;
			do {
				free (varname);
				varname = r_str_newf ("%s_%xh_%u", pfx, uptr, i++);
			} while (r_anal_function_get_var_byname (fcn, varname));
			return varname;
		}
	}
	return varname;
}

static RAnalVar *get_stack_var(RAnalFunction *fcn, int delta) {
	void **it;
	r_pvector_foreach (&fcn->vars, it) {
		RAnalVar *var = *it;
		bool is_stack = var->kind == R_ANAL_VAR_KIND_SPV || var->kind == R_ANAL_VAR_KIND_BPV;
		if (is_stack && var->delta == delta) {
			return var;
		}
	}
	return NULL;
}

static void extract_arg(RAnal *anal, RAnalFunction *fcn, RAnalOp *op, const char *reg, const char *sign, char type) {
	st64 ptr = 0;
	char *addr, *esil_buf = NULL;

	r_return_if_fail (anal && fcn && op && reg);

	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (op->src); i++) {
		if (op->src[i] && op->src[i]->reg && op->src[i]->reg->name) {
			if (!strcmp (reg, op->src[i]->reg->name)) {
				st64 delta = op->src[i]->delta;
				if ((delta > 0 && *sign == '+') || (delta < 0 && *sign == '-')) {
					ptr = R_ABS (op->src[i]->delta);
					break;
				}
			}
		}
	}

	if (!ptr) {
		const char *op_esil = r_strbuf_get (&op->esil);
		if (!op_esil) {
			return;
		}
		esil_buf = strdup (op_esil);
		if (!esil_buf) {
			return;
		}
		char *ptr_end = strstr (esil_buf, sdb_fmt (",%s,%s,", reg, sign));
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
				const char *rn = op->dst->reg ? op->dst->reg->name : NULL;
				if (rn && ((bp && !strcmp (bp, rn)) || (sp && !strcmp (sp, rn)))) {
					if (anal->verbose) {
						eprintf ("Warning: Analysis didn't fill op->stackop for instruction that alters stack at 0x%" PFMT64x ".\n", op->addr);
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
	}

	if (anal->verbose && (!op->src[0] || !op->dst)) {
		eprintf ("Warning: Analysis didn't fill op->src/dst at 0x%" PFMT64x ".\n", op->addr);
	}

	int rw = (op->direction == R_ANAL_OP_DIR_WRITE) ? R_ANAL_VAR_ACCESS_TYPE_WRITE : R_ANAL_VAR_ACCESS_TYPE_READ;
	if (*sign == '+') {
		const bool isarg = type == R_ANAL_VAR_KIND_SPV ? ptr >= fcn->stack : ptr >= fcn->bp_off;
		const char *pfx = isarg ? ARGPREFIX : VARPREFIX;
		st64 frame_off;
		if (type == R_ANAL_VAR_KIND_SPV) {
			frame_off = ptr - fcn->stack;
		} else {
			frame_off = ptr - fcn->bp_off;
		}
		RAnalVar *var = get_stack_var (fcn, frame_off);
		if (var) {
			r_anal_var_set_access (var, reg, op->addr, rw, ptr);
			goto beach;
		}
		char *varname = NULL, *vartype = NULL;
		if (isarg) {
			const char *place = fcn->cc ? r_anal_cc_arg (anal, fcn->cc, ST32_MAX) : NULL;
			bool stack_rev = place ? !strcmp (place, "stack_rev") : false;
			char *fname = r_type_func_guess (anal->sdb_types, fcn->name);
			if (fname) {
				ut64 sum_sz = 0;
				size_t from, to, i;
				if (stack_rev) {
					const size_t cnt = r_type_func_args_count (anal->sdb_types, fname);
					from = cnt ? cnt - 1 : cnt;
					to = fcn->cc ? r_anal_cc_max_arg (anal, fcn->cc) : 0;
				} else {
					from = fcn->cc ? r_anal_cc_max_arg (anal, fcn->cc) : 0;
					to = r_type_func_args_count (anal->sdb_types, fname);
				}
				const int bytes = (fcn->bits ? fcn->bits : anal->bits) / 8;
				for (i = from; stack_rev ? i >= to : i < to; stack_rev ? i-- : i++) {
					char *tp = r_type_func_args_type (anal->sdb_types, fname, i);
					if (!tp) {
						break;
					}
					if (sum_sz == frame_off) {
						vartype = tp;
						varname = strdup (r_type_func_args_name (anal->sdb_types, fname, i));
						break;
					}
					ut64 bit_sz = r_type_get_bitsize (anal->sdb_types, tp);
					sum_sz += bit_sz ? bit_sz / 8 : bytes;
					sum_sz = R_ROUND (sum_sz, bytes);
					free (tp);
				}
				free (fname);
			}
		}
		if (!varname) {
			if (anal->opt.varname_stack) {
				varname = r_str_newf ("%s_%" PFMT64x "h", pfx, R_ABS (frame_off));
			} else {
				varname = r_anal_function_autoname_var (fcn, type, pfx, ptr);
			}
		}
		if (varname) {
			RAnalVar *var = r_anal_function_set_var (fcn, frame_off, type, vartype, anal->bits / 8, isarg, varname);
			if (var) {
				r_anal_var_set_access (var, reg, op->addr, rw, ptr);
			}
			free (varname);
		}
		free (vartype);
	} else {
		st64 frame_off = -(ptr + fcn->bp_off);
		RAnalVar *var = get_stack_var (fcn, frame_off);
		if (var) {
			r_anal_var_set_access (var, reg, op->addr, rw, -ptr);
			goto beach;
		}
		char *varname = anal->opt.varname_stack
			? r_str_newf ("%s_%" PFMT64x "h", VARPREFIX, R_ABS (frame_off))
			: r_anal_function_autoname_var (fcn, type, VARPREFIX, -ptr);
		if (varname) {
			RAnalVar *var = r_anal_function_set_var (fcn, frame_off, type, NULL, anal->bits / 8, false, varname);
			if (var) {
				r_anal_var_set_access (var, reg, op->addr, rw, -ptr);
			}
			free (varname);
		}
	}
beach:
	free (esil_buf);
}

static bool is_reg_in_src(const char *regname, RAnal *anal, RAnalOp *op);

static inline bool op_affect_dst(RAnalOp* op) {
	switch (op->type) {
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_NOR:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_CAST:
		return true;
	default:
		return false;
	}
}

#define STR_EQUAL(s1, s2) (s1 && s2 && !strcmp (s1, s2))

static inline bool arch_destroys_dst(const char *arch) {
	return (STR_EQUAL (arch, "arm") || STR_EQUAL (arch, "riscv") || STR_EQUAL (arch, "ppc"));
}

static bool is_used_like_arg(const char *regname, const char *opsreg, const char *opdreg, RAnalOp *op, RAnal *anal) {
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
		if (op_affect_dst (op) && arch_destroys_dst (anal->cur->arch)) {
			if (is_reg_in_src (regname, anal, op)) {
				return true;
			}
			return false;
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
	const int size = (fcn->bits ? fcn->bits : anal->bits) / 8;
	if (!fcn->cc) {
		R_LOG_DEBUG ("No calling convention for function '%s' to extract register arguments\n", fcn->name);
		return;
	}
	char *fname = r_type_func_guess (anal->sdb_types, fcn->name);
	Sdb *TDB = anal->sdb_types;
	int max_count = r_anal_cc_max_arg (anal, fcn->cc);
	if (!max_count || (*count >= max_count)) {
		free (fname);
		return;
	}
	if (fname) {
		argc = r_type_func_args_count (TDB, fname);
	}

	bool is_call = (op->type & 0xf) == R_ANAL_OP_TYPE_CALL || (op->type & 0xf) == R_ANAL_OP_TYPE_UCALL;
	if (is_call && *count < max_count) {
		RList *callee_rargs_l = NULL;
		int callee_rargs = 0;
		char *callee = NULL;
		ut64 offset = op->jump == UT64_MAX ? op->ptr : op->jump;
		RAnalFunction *f = r_anal_get_function_at (anal, offset);
		if (!f) {
			RCore *core = (RCore *)anal->coreb.core;
			RFlagItem *flag = r_flag_get_by_spaces (core->flags, offset, R_FLAGS_FS_IMPORTS, NULL);
			if (flag) {
				callee = r_type_func_guess (TDB, flag->name);
				if (callee) {
					const char *cc = r_anal_cc_func (anal, callee);
					if (cc && !strcmp (fcn->cc, cc)) {
						callee_rargs = R_MIN (max_count, r_type_func_args_count (TDB, callee));
					}
				}
			}
		} else if (!f->is_variadic && !strcmp (fcn->cc, f->cc)) {
			callee = r_type_func_guess (TDB, f->name);
			if (callee) {
				callee_rargs = R_MIN (max_count, r_type_func_args_count (TDB, callee));
			}
			callee_rargs = callee_rargs 
				? callee_rargs
				: r_anal_var_count (anal, f, R_ANAL_VAR_KIND_REG, 1);
			callee_rargs_l = r_anal_var_list (anal, f, R_ANAL_VAR_KIND_REG);
		}
		size_t i;
		for (i = 0; i < callee_rargs; i++) {
			if (reg_set[i]) {
				continue;
			}
			const char *vname = NULL;
			char *type = NULL;
			char *name = NULL;
			int delta = 0;
			const char *regname = r_anal_cc_arg (anal, fcn->cc, i);
			RRegItem *ri = r_reg_get (anal->reg, regname, -1);
			if (ri) {
				delta = ri->index;
			}
			if (fname) {
				type = r_type_func_args_type (TDB, fname, i);
				vname = r_type_func_args_name (TDB, fname, i);
			}
			if (!vname && callee) {
				type = r_type_func_args_type (TDB, callee, i);
				vname = r_type_func_args_name (TDB, callee, i);
			}
			if (vname) {
				reg_set[i] = 1;
			} else {
				RListIter *it;
				RAnalVar *arg, *found_arg = NULL;
				r_list_foreach (callee_rargs_l, it, arg) {
					if (r_anal_var_get_argnum (arg) == i) {
						found_arg = arg;
						break;
					}
				}
				if (found_arg) {
					type = strdup (found_arg->type);
					vname = name = strdup (found_arg->name);
				}
			}
			if (!vname) {
				name = r_str_newf ("arg%u", (int)i + 1);
				vname = name;
			}
			r_anal_function_set_var (fcn, delta, R_ANAL_VAR_KIND_REG, type, size, true, vname);
			(*count)++;
			free (name);
			free (type);
		}
		free (callee);
		r_list_free (callee_rargs_l);
		free (fname);
		return;
	}

	for (i = 0; i < max_count; i++) {
		const char *regname = r_anal_cc_arg (anal, fcn->cc, i);
		if (regname) {
			int delta = 0;
			RRegItem *ri = NULL;
			RAnalVar *var = NULL;
			bool is_used_like_an_arg = is_used_like_arg (regname, opsreg, opdreg, op, anal);
			if (reg_set[i] != 2 && is_used_like_an_arg) {
				ri = r_reg_get (anal->reg, regname, -1);
				if (ri) {
					delta = ri->index;
				}
			}
			if (reg_set[i] == 1 && is_used_like_an_arg) {
				var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, delta);
			} else if (reg_set[i] != 2 && is_used_like_an_arg) {
				const char *vname = NULL;
				char *type = NULL;
				char *name = NULL;
				if ((i < argc) && fname) {
					type = r_type_func_args_type (TDB, fname, i);
					vname = r_type_func_args_name (TDB, fname, i);
				}
				if (!vname) {
					name = r_str_newf ("arg%d", i + 1);
					vname = name;
				}
				var = r_anal_function_set_var (fcn, delta, R_ANAL_VAR_KIND_REG, type, size, true, vname);
				free (name);
				free (type);
				(*count)++;
			} else {
				if (is_reg_in_src (regname, anal, op) || STR_EQUAL (opdreg, regname)) {
					reg_set[i] = 2;
				}
				continue;
			}
			if (is_reg_in_src (regname, anal, op) || STR_EQUAL (regname, opdreg)) {
				reg_set[i] = 1;
			}
			if (var) {
				r_anal_var_set_access (var, var->regname, op->addr, R_ANAL_VAR_ACCESS_TYPE_READ, 0);
				r_meta_set_string (anal, R_META_TYPE_VARTYPE, op->addr, var->name);
			}
		}
	}

	const char *selfreg = r_anal_cc_self (anal, fcn->cc);
	if (selfreg) {
		bool is_used_like_an_arg = is_used_like_arg (selfreg, opsreg, opdreg, op, anal);
		if (reg_set[i] != 2 && is_used_like_an_arg) {
			int delta = 0;
			char *vname = strdup ("self");
			RRegItem *ri = r_reg_get (anal->reg, selfreg, -1);
			if (ri) {
				delta = ri->index;
			}
			RAnalVar *newvar = r_anal_function_set_var (fcn, delta, R_ANAL_VAR_KIND_REG, 0, size, true, vname);
			if (newvar) {
				r_anal_var_set_access (newvar, newvar->regname, op->addr, R_ANAL_VAR_ACCESS_TYPE_READ, 0);
			}
			r_meta_set_string (anal, R_META_TYPE_VARTYPE, op->addr, vname);
			free (vname);
			(*count)++;
		} else {
			if (is_reg_in_src (selfreg, anal, op) || STR_EQUAL (opdreg, selfreg)) {
				reg_set[i] = 2;
			}
		}
		i++;
	}

	const char *errorreg = r_anal_cc_error (anal, fcn->cc);
	if (errorreg) {
		if (reg_set[i] == 0 && STR_EQUAL (opdreg, errorreg)) {
			int delta = 0;
			char *vname = strdup ("error");
			RRegItem *ri = r_reg_get (anal->reg, errorreg, -1);
			if (ri) {
				delta = ri->index;
			}
			RAnalVar *newvar = r_anal_function_set_var (fcn, delta, R_ANAL_VAR_KIND_REG, 0, size, true, vname);
			if (newvar) {
				r_anal_var_set_access (newvar, newvar->regname, op->addr, R_ANAL_VAR_ACCESS_TYPE_READ, 0);
			}
			r_meta_set_string (anal, R_META_TYPE_VARTYPE, op->addr, vname);
			free (vname);
			(*count)++;
			reg_set[i] = 2;
		}
	}
	free (fname);
}

R_API void r_anal_extract_vars(RAnal *anal, RAnalFunction *fcn, RAnalOp *op) {
	r_return_if_fail (anal && fcn && op);

	const char *BP = anal->reg->name[R_REG_NAME_BP];
	const char *SP = anal->reg->name[R_REG_NAME_SP];
	if (BP) {
		extract_arg (anal, fcn, op, BP, "+", R_ANAL_VAR_KIND_BPV);
		extract_arg (anal, fcn, op, BP, "-", R_ANAL_VAR_KIND_BPV);
	}
	extract_arg (anal, fcn, op, SP, "+", R_ANAL_VAR_KIND_SPV);
}

static RList *var_generate_list(RAnal *a, RAnalFunction *fcn, int kind) {
	if (!a || !fcn) {
		return NULL;
	}
	RList *list = r_list_new ();
	if (kind < 1) {
		kind = R_ANAL_VAR_KIND_BPV; // by default show vars
	}
	void **it;
	r_pvector_foreach (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (var->kind == kind) {
			r_list_push (list, var);
		}
	}
	return list;
}

R_API RList *r_anal_var_all_list(RAnal *anal, RAnalFunction *fcn) {
	// r_anal_var_list if there are not vars with that kind returns a list with
	// zero element.. which is an unnecessary loss of cpu time
	RList *list = r_list_new ();
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
	return var_generate_list (a, fcn, kind);
}

static void var_field_free(RAnalVarField *field) {
	if (!field) {
		return;
	}
	free (field->name);
	free (field);
}

R_API RList *r_anal_function_get_var_fields(RAnalFunction *fcn, int kind) {
	if (!fcn) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)var_field_free);
	if (kind < 1) {
		kind = R_ANAL_VAR_KIND_BPV; // by default show vars
	}
	void **it;
	r_pvector_foreach (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (var->kind != kind) {
			continue;
		}
		if (var_add_structure_fields_to_list (fcn->anal, var, list)) {
			// this var is a struct and var_add_structure_fields_to_list added all the fields
			continue;
		}
		RAnalVarField *field = R_NEW0 (RAnalVarField);
		if (!field) {
			break;
		}
		field->name = strdup (var->name);
		if (!field->name) {
			var_field_free (field);
			break;
		}
		field->delta = var->delta;
		r_list_push (list, field);
	}
	return list;
}

static int var_comparator(const RAnalVar *a, const RAnalVar *b){
	// avoid NULL dereference
	return (a && b)? (a->delta > b->delta) - (a->delta < b->delta) : 0;
}

static int regvar_comparator(const RAnalVar *a, const RAnalVar *b){
	// avoid NULL dereference
	return (a && b)? (a->argnum > b->argnum) - (a->argnum < b->argnum): 0;
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
				int delta = kind == R_ANAL_VAR_KIND_BPV
					? var->delta + fcn->bp_off
					: var->delta;
				anal->cb_printf ("afv%c %d %s %s @ 0x%"PFMT64x "\n",
					kind, delta, var->name, var->type,
					fcn->addr);
			}
			break;
		case 'j':
			switch (var->kind) {
			case R_ANAL_VAR_KIND_BPV: {
				st64 delta = (st64)var->delta + fcn->bp_off;
				pj_o (pj);
				pj_ks (pj, "name", var->name);
				if (var->isarg) {
					pj_ks (pj, "kind", "arg");
				} else {
					pj_ks (pj, "kind", "var");
				}
				pj_ks (pj, "type", var->type);
				pj_k (pj, "ref");
				pj_o (pj);
				pj_ks (pj, "base", anal->reg->name[R_REG_NAME_BP]);
				pj_kN (pj, "offset", delta);
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
			case R_ANAL_VAR_KIND_SPV: {
				st64 delta = (st64)var->delta + fcn->maxstack;
				pj_o (pj);
				pj_ks (pj, "name", var->name);
				if (var->isarg) {
					pj_ks (pj, "kind", "arg");
				} else {				
					pj_ks (pj, "kind", "var");			
				}
				pj_ks (pj, "type", var->type);
				pj_k (pj, "ref");
				pj_o (pj);
				pj_ks (pj, "base", anal->reg->name[R_REG_NAME_SP]);
				pj_kN (pj, "offset", delta);
				pj_end (pj);
				pj_end (pj);
			}
				break;
			}
			break;
		default:
			switch (kind) {
			case R_ANAL_VAR_KIND_BPV:
			{
				int delta = var->delta + fcn->bp_off;
				if (var->isarg) {
					anal->cb_printf ("arg %s %s @ %s+0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_BP],
						delta);
				} else {
					char sign = (-var->delta <= fcn->bp_off) ? '+' : '-';
					anal->cb_printf ("var %s %s @ %s%c0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_BP],
						sign, R_ABS (delta));
				}
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
					char sign = (-var->delta <= fcn->maxstack) ? '+' : '-';
					anal->cb_printf ("var %s %s @ %s%c0x%x\n",
						var->type, var->name,
						anal->reg->name[R_REG_NAME_SP],
						sign, R_ABS (delta));
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
	cache->bvars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_BPV);
	cache->rvars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_REG);
	cache->svars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_SPV);
	r_list_sort (cache->bvars, (RListComparator)var_comparator);
	RListIter *it;
	RAnalVar *var;
	r_list_foreach (cache->rvars, it, var) {
		var->argnum = r_anal_var_get_argnum (var);
	}
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
		// assume self, error are always the last
		if (!strcmp (var->name, "self") || !strcmp (var->name, "error")) {
			r_strbuf_slice (buf, 0, r_strbuf_length (buf) - 2);
			break;
		}
		tmp_len = strlen (var->type);
		r_strbuf_appendf (buf, "%s%s%s%s", var->type,
			tmp_len && var->type[tmp_len - 1] == '*' ? "" : " ",
			var->name, iter->n ? ", " : "");
	}

	r_list_foreach (cache->bvars, iter, var) {
		if (var->isarg) {
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
