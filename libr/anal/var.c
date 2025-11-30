/* radare - LGPL - Copyright 2010-2025 - pancake, oddcoder */

#define R_LOG_ORIGIN "anal.var"

#include <r_core.h>

#define ACCESS_CMP(x, y) ((st64)((ut64)(x) - ((RAnalVarAccess *)y)->offset))

static int anal_var_access_compare(const RAnalVarAccess *a, const RAnalVarAccess *b) {
	const st64 diff = a->offset - b->offset;
	if (diff < 0) {
		return -1;
	}
	if (diff > 0) {
		return 1;
	}
	return 0;
}
// XXX this helper function is crap and shouldnt be used
#define STR_EQUAL(s1, s2) (s1 && s2 && !strcmp (s1, s2))

#define ANAL_VAR_PTR_AT(vec, idx) RVecAnalVarPtr_at ((vec), (idx))

static inline void anal_var_ptr_remove_at(RVecAnalVarPtr *vec, ut64 idx) {
	R_RETURN_IF_FAIL (vec);
	ut64 len = RVecAnalVarPtr_length (vec);
	if (idx >= len) {
		return;
	}
	RAnalVar **start = R_VEC_START_ITER (vec);
	RAnalVar **pos = start + idx;
	RAnalVar **end = R_VEC_END_ITER (vec);
	if (pos + 1 < end) {
		memmove (pos, pos + 1, (size_t)(end - pos - 1) * sizeof (*pos));
	}
	vec->_end--;
}

static inline void anal_var_ptr_remove(RVecAnalVarPtr *vec, RAnalVar *var) {
	RAnalVar **it;
	ut64 idx = 0;
	R_VEC_FOREACH (vec, it) {
		if (*it == var) {
			anal_var_ptr_remove_at (vec, idx);
			return;
		}
		idx++;
	}
}

static inline bool anal_var_ptr_contains(RVecAnalVarPtr *vec, RAnalVar *var) {
	RAnalVar **it;
	R_VEC_FOREACH (vec, it) {
		if (*it == var) {
			return true;
		}
	}
	return false;
}

static RVecAnalVarPtr *anal_var_ptr_clone(RVecAnalVarPtr *src) {
	RVecAnalVarPtr *dst = RVecAnalVarPtr_new ();
	if (!dst) {
		return NULL;
	}
	const ut64 len = RVecAnalVarPtr_length (src);
	if (!RVecAnalVarPtr_reserve (dst, len)) {
		RVecAnalVarPtr_free (dst);
		return NULL;
	}
	RAnalVar **it;
	R_VEC_FOREACH (src, it) {
		RAnalVar *v = *it;
		RVecAnalVarPtr_push_back (dst, &v);
	}
	return dst;
}


R_API bool r_anal_var_display(RAnal *anal, RAnalVar *var) {
	R_RETURN_VAL_IF_FAIL (anal && var, false);
	const char *type = var->type;
	if (r_str_startswith (var->type, "signed ")) {
		type = var->type + 7;
	}
	char *fmt = r_type_format (anal->sdb_types, type);
	RRegItem *ri;
	if (!fmt) {
		R_LOG_ERROR ("type:%s doesn't exist", var->type);
		return false;
	}
	bool usePxr = !strcmp (var->type, "int"); // hacky but useful
	switch (var->kind) {
	case R_ANAL_VAR_KIND_REG:
		ri = r_reg_index_get (anal->reg, var->delta);
		if (ri) {
			if (usePxr) {
				anal->cb_printf ("pxr $w @r:%s\n", ri->name);
			} else {
				anal->cb_printf ("pf r (%s)\n", ri->name);
			}
		} else {
			R_LOG_ERROR ("register '%s' not found", var->type);
		}
		break;
	case R_ANAL_VAR_KIND_BPV:
		{
			const st32 real_delta = var->delta + var->fcn->bp_off;
			const ut32 udelta = R_ABS (real_delta);
			const char sign = real_delta >= 0 ? '+' : '-';
			const char *bpreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
			if (usePxr) {
				anal->cb_printf ("pxr $w @%s%c0x%x\n", bpreg, sign, udelta);
			} else {
				anal->cb_printf ("pf %s @%s%c0x%x\n", fmt, bpreg, sign, udelta);
			}
		}
		break;
	case R_ANAL_VAR_KIND_SPV:
		{
			ut32 udelta = R_ABS (var->delta + var->fcn->maxstack);
			const char *spreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
			if (usePxr) {
				anal->cb_printf ("pxr $w @%s+0x%x\n", spreg, udelta);
			} else {
				anal->cb_printf ("pf %s @ %s+0x%x\n", fmt, spreg, udelta);
			}
		}
		break;
	}
	free (fmt);
	return true;
}

static const char * const int_type(int size) {
	switch (size) {
	case 1: return "int8_t";
	case 2: return "int16_t";
	case 4: return "int32_t";
	case 8: return "int64_t";
	default: return NULL;
	}
}

R_API bool r_anal_function_rebase_vars(RAnal *a, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (a && fcn, false);
	RListIter *it;
	RAnalVar *var;
	RList *var_list = r_anal_var_all_list (a, fcn);
	r_list_foreach (var_list, it, var) {
		// Resync delta in case the registers list changed
		// XXX imho this is wrong. as it needs to be reordered by the calling convention not by register index
		if (var->isarg && var->kind == 'r') {
			RRegItem *ri = r_reg_get (a->reg, var->regname, -1);
			if (ri) {
				if (var->delta != ri->index) {
					var->delta = ri->index;
				}
				r_unref (ri);
			}
		}
	}
	r_list_free (var_list);
	return true;
}

// If the type of var is a struct,
// remove all other vars that are overlapped by var and are at the offset of one of its struct members
static void shadow_var_struct_members(RAnal *anal, RAnalVar *var) {
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
					r_anal_var_delete (anal, other);
				}
			}
			free (field_type);
			free (field);
		}
		free (type_key);
	}
}

static inline bool valid_var_kind(char kind) {
	switch (kind) {
	case R_ANAL_VAR_KIND_BPV: // base pointer var/args
	case R_ANAL_VAR_KIND_SPV: // stack pointer var/args
	case R_ANAL_VAR_KIND_REG: // registers args
		return true;
	default:
		return false;
	}
}

R_API RAnalVar *r_anal_function_set_var(RAnalFunction *fcn, int delta, char kind, const char * R_NULLABLE type, int size, bool isarg, const char * R_NONNULL name) {
	R_RETURN_VAL_IF_FAIL (fcn && name, NULL);
	R_LOG_DEBUG ("fcn.setvar 0x%llx delta=%d kind=%c type=%s size=%d isarg=%d name=%s", fcn->addr, delta, kind, type, size, isarg, name);
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
		type = int_type (size);
		if (!type) {
			type = int_type (fcn->anal->config->bits);
		}
		if (!type) {
			type = "int32_t";
		}
	}
	if (!valid_var_kind (kind)) {
		R_LOG_ERROR ("Invalid var kind '%c'", kind);
		return NULL;
	}
	if (kind == R_ANAL_VAR_KIND_REG) {
		reg = r_reg_index_get (fcn->anal->reg, R_ABS (delta));
		if (!reg) {
			R_LOG_DEBUG ("No register at index %d", delta);
			return NULL;
		}
	}
	RAnalVar *var = r_anal_function_get_var (fcn, kind, delta);
	if (!var) {
		var = R_NEW0 (RAnalVar);
		RVecAnalVarPtr_push_back (&fcn->vars, &var);
		var->fcn = fcn;
		RVecAnalVarAccess_init (&var->accesses);
		RVecAnalVarConstraint_init (&var->constraints);
		var->argnum = -1;
	} else {
		free (var->name);
		free (var->regname);
		free (var->type);
	}
	R_DIRTY_SET (fcn->anal);
	var->name = strdup (name);
	var->regname = reg? strdup (reg->name): NULL; // TODO: no strdup here? pool? or not keep regname at all?
	var->type = strdup (type);
	var->kind = kind;
	var->isarg = isarg;
	var->delta = delta;
	shadow_var_struct_members (fcn->anal, var);
	return var;
}

R_API bool r_anal_function_set_var_prot(RAnalFunction *fcn, RList *l) {
	R_RETURN_VAL_IF_FAIL (fcn && l, false);
	RListIter *iter;
	RAnalVarProt *vp;
	r_list_foreach (l, iter, vp) {
		if (!r_anal_function_set_var (fcn, vp->delta, vp->kind, vp->type, -1, vp->isarg, vp->name)) {
			return false;
		}
	}
	R_DIRTY_SET (fcn->anal);
	return true;
}

R_API void r_anal_var_set_type(RAnal *anal, RAnalVar *var, const char * const type) {
	char *nt = strdup (type);
	if (nt) {
		free (var->type);
		var->type = nt;
		R_LOG_DEBUG ("set type %s for %s", type, var->name);
		shadow_var_struct_members (anal, var);
		{
			REventVariable event = { .fcn = var->fcn, .var = var, .type = type };
			r_event_send (anal->ev, R_EVENT_VARIABLE_TYPE_CHANGED, &event);
		}
	}
}

static void var_free(RAnalVar *var) {
	if (R_LIKELY (var)) {
		r_anal_var_clear_accesses (var);
		RVecAnalVarConstraint_fini (&var->constraints);
		free (var->name);
		free (var->regname);
		free (var->type);
		free (var->comment);
		free (var);
	}
}

static void r_anal_var_proto_free(RAnalVarProt *vp) {
	if (vp) {
		free (vp->name);
		free (vp->type);
		free (vp);
	}
}

R_API bool r_anal_var_delete(RAnal *anal, RAnalVar *var) {
	R_RETURN_VAL_IF_FAIL (var, false);
	RAnalFunction *fcn = var->fcn;
	int i;
	bool found = false;
	const ut64 vlen = RVecAnalVarPtr_length (&fcn->vars);
	for (i = (int)vlen - 1; i >= 0; i--) {
		RAnalVar **vptr = ANAL_VAR_PTR_AT (&fcn->vars, i);
		RAnalVar *v = vptr? *vptr: NULL;
		if (v == var) {
			anal_var_ptr_remove_at (&fcn->vars, i);
			found = true;
		}
	}
	if (found) {
		REventVariable event = { .fcn = fcn, .var = var };
		r_event_send (anal->ev, R_EVENT_VARIABLE_DELETED, &event);
		var_free (var);
		return true;
	}
	return false;
}

R_API void r_anal_function_delete_vars_by_kind(RAnalFunction *fcn, RAnalVarKind kind) {
	R_RETURN_IF_FAIL (fcn);
	size_t i;
	for (i = 0; i < RVecAnalVarPtr_length (&fcn->vars);) {
		RAnalVar **varptr = ANAL_VAR_PTR_AT (&fcn->vars, i);
		RAnalVar *var = varptr? *varptr: NULL;
		if (var && var->kind == kind) {
			anal_var_ptr_remove_at (&fcn->vars, i);
			var_free (var);
			continue;
		}
		i++;
	}
}

R_API void r_anal_function_delete_all_vars(RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (fcn);
	if (RVecAnalVarPtr_length (&fcn->vars) > 0) {
		RAnalVar **it;
		R_VEC_FOREACH (&fcn->vars, it) {
			var_free (*it);
		}
	}
	RVecAnalVarPtr_clear (&fcn->vars);
}

R_API void r_anal_function_delete_unused_vars(RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (fcn);
	RAnalVar **v;
	RVecAnalVarPtr *vars_clone = anal_var_ptr_clone (&fcn->vars);
	if (!vars_clone) {
		return;
	}
	R_VEC_FOREACH (vars_clone, v) {
		RAnalVar *var = *v;
		if (var && RVecAnalVarAccess_empty (&var->accesses)) {
			r_anal_function_delete_var (fcn, var);
		}
	}
	RVecAnalVarPtr_free (vars_clone);
}

R_API void r_anal_function_delete_var(RAnalFunction *fcn, RAnalVar *var) {
	R_RETURN_IF_FAIL (fcn && var);
	int i;
	bool found = false;
	const ut64 vlen = RVecAnalVarPtr_length (&fcn->vars);
	for (i = (int)vlen - 1; i >= 0; i--) {
		RAnalVar **vptr = ANAL_VAR_PTR_AT (&fcn->vars, i);
		if (vptr && *vptr == var) {
			anal_var_ptr_remove_at (&fcn->vars, i);
			found = true;
		}
	}
	if (found) {
		var_free (var);
	}
}

R_API RList *r_anal_var_deserialize(const char *ser) {
	R_RETURN_VAL_IF_FAIL (ser, NULL);
	RList *ret = r_list_newf ((RListFree)r_anal_var_proto_free);
	while (*ser) {
		RAnalVarProt *v = R_NEW0 (RAnalVarProt);
		r_list_append (ret, v);
		if (!v) {
			goto bad_serial;
		}

		// isarg
		switch (*ser) {
		case 't':
			v->isarg = true;
			break;
		case 'f':
			v->isarg = false;
			break;
		default:
			goto bad_serial;
		}
		ser++;

		// kind
		if (!valid_var_kind (*ser)) {
			goto bad_serial;
		}
		v->kind = *ser++;

		// delta
		char *nxt;
		v->delta = strtol (ser, &nxt, 10);
		if ((!v->delta && nxt == ser) || *nxt != ':') {
			goto bad_serial;
		}
		nxt++;
		ser = nxt;

		// name
		int i;
		for (i = 0; *nxt != ':'; i++) {
			if (*nxt == ',' || !*nxt) {
				goto bad_serial;
			}
			nxt++;
		}
		v->name = R_STR_NDUP (ser, i);
		if (!v->name) {
			goto bad_serial;
		}
		nxt++;
		ser = nxt;

		// type
		for (i = 0; *nxt && *nxt != ','; i++) {
			nxt++;
		}
		v->type = R_STR_NDUP (ser, i);
		if (!v->type) {
			goto bad_serial;
		}
		ser = nxt;
		if (*ser == ',') {
			ser++;
		}
		while (*ser == ' ') {
			ser++;
		}
	}
	return ret;
bad_serial:
	r_list_free (ret);
	return NULL;
}

static inline void sanitize_var_serial(char *name, bool colon) {
	R_RETURN_IF_FAIL (name);
	for (; *name; name++) {
		switch (*name) {
		case ':':
			if (colon) {
				break;
			}
		case '`':
		case '$':
		case '{':
		case '}':
		case '~':
		case '|':
		case '#':
		case '@':
		case '&':
		case '<':
		case '>':
		case ',':
			*name = '_';
			continue;
		}
	}
}

static inline bool serialize_single_var(RAnalVarProt *vp, RStrBuf *sb) {
	R_RETURN_VAL_IF_FAIL (vp && sb, false);
	// shouldn't have special chars in them anyways, so replace in place
	sanitize_var_serial (vp->name, false);
	sanitize_var_serial (vp->type, true);
	const char b = vp->isarg? 't': 'f';
	if (!valid_var_kind (vp->kind)) {
		return false;
	}
	return r_strbuf_appendf (sb, "%c%c%d:%s:%s", b, vp->kind, vp->delta, vp->name, vp->type);
}

R_API char *r_anal_var_prot_serialize(RList *l, bool spaces) {
	R_RETURN_VAL_IF_FAIL (l, NULL);
	if (l->length == 0) {
		return NULL;
	}

	RStrBuf *sb = r_strbuf_new ("");
	if (!sb) {
		return NULL;
	}
	r_strbuf_reserve (sb, r_list_length (l) * 0x10);

	const char * const sep = spaces? ", ": ",";
	size_t len = strlen (sep);
	RAnalVarProt *v;
	RAnalVarProt *top = (RAnalVarProt *)r_list_last (l);
	RListIter *iter;
	r_list_foreach (l, iter, v) {
		if (!serialize_single_var (v, sb) || (v != top && !r_strbuf_append_n (sb, sep, len))) {
			r_strbuf_free (sb);
			return NULL;
		}
	}
	return r_strbuf_drain (sb);
}

R_API RList *r_anal_var_get_prots(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
	RList *ret = r_list_newf ((RListFree)r_anal_var_proto_free);
	if (ret) {
		RAnalVar **p;
		R_VEC_FOREACH (&fcn->vars, p) {
			RAnalVar *var = *p;
			RAnalVarProt *vp = R_NEW0 (RAnalVarProt);
			vp->isarg = var->isarg;
			vp->name = strdup (var->name);
			vp->type = strdup (var->type);
			vp->kind = var->kind;
			vp->delta = var->delta;
			r_list_append (ret, vp);
		}
	}
	return ret;
}

R_API R_BORROW RAnalVar *r_anal_function_get_var_byname(RAnalFunction *fcn, const char *name) {
	R_RETURN_VAL_IF_FAIL (fcn && name, NULL);
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (!strcmp (var->name, name)) {
			return var;
		}
	}
	return NULL;
}

R_API RAnalVar *r_anal_function_get_var(RAnalFunction *fcn, char kind, int delta) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (var->kind == kind && var->delta == delta) {
			return var;
		}
	}
	return NULL;
}

R_API ut64 r_anal_var_addr(RAnalVar *var) {
	R_RETURN_VAL_IF_FAIL (var, UT64_MAX);
	RAnal *anal = var->fcn->anal;
	const char *regname = NULL;
	if (var->kind == R_ANAL_VAR_KIND_BPV) {
		regname = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
		return r_reg_getv (anal->reg, regname) + var->delta + var->fcn->bp_off;
	}
	if (var->kind == R_ANAL_VAR_KIND_SPV) {
		regname = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
		return r_reg_getv (anal->reg, regname) + var->delta;
	}
	return 0;
}

R_API st64 r_anal_function_get_var_stackptr_at(RAnalFunction *fcn, st64 delta, ut64 addr) {
	st64 offset = addr - fcn->addr;
	RVecAnalVarPtr *inst_accesses = ht_up_find (fcn->inst_vars, offset, NULL);
	if (!inst_accesses) {
		return ST64_MAX;
	}
	RAnalVar *var = NULL;
	RAnalVar **it;
	R_VEC_FOREACH (inst_accesses, it) {
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
	RAnalVarAccess needle = { .offset = offset };
	index = RVecAnalVarAccess_lower_bound (&var->accesses, &needle, anal_var_access_compare);
	RAnalVarAccess *acc = NULL;
	if (index < RVecAnalVarAccess_length (&var->accesses)) {
		acc = RVecAnalVarAccess_at (&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		return ST64_MAX;
	}
	return acc->stackptr;
}

R_API const char *r_anal_function_get_var_reg_at(RAnalFunction *fcn, st64 delta, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
	st64 offset = addr - fcn->addr;
	RVecAnalVarPtr *inst_accesses = ht_up_find (fcn->inst_vars, offset, NULL);
	if (!inst_accesses) {
		return NULL;
	}
	RAnalVar *var = NULL;
	RAnalVar **it;
	R_VEC_FOREACH (inst_accesses, it) {
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
	RAnalVarAccess needle = { .offset = offset };
	index = RVecAnalVarAccess_lower_bound (&var->accesses, &needle, anal_var_access_compare);
	RAnalVarAccess *acc = NULL;
	if (index < RVecAnalVarAccess_length (&var->accesses)) {
		acc = RVecAnalVarAccess_at (&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		return NULL;
	}
	return acc->reg;
}

R_API bool r_anal_var_check_name(const char *name) {
	return !isdigit ((unsigned char)*name) && strcspn (name, "., =/");
}

R_API bool r_anal_var_rename(RAnal *anal, RAnalVar *var, const char *new_name) {
	R_RETURN_VAL_IF_FAIL (anal && var, false);
	if (!r_anal_var_check_name (new_name)) {
		return false;
	}
	RAnalVar *v1 = r_anal_function_get_var_byname (var->fcn, new_name);
	if (v1) {
		R_LOG_DEBUG ("variable or arg with name `%s` already exist", new_name);
		return false;
	}
	char *nn = strdup (new_name);
	if (!nn) {
		return false;
	}
	free (var->name);
	var->name = nn;
	{
		REventVariable event = { .fcn = var->fcn, .var = var, .name = nn };
		r_event_send (anal->ev, R_EVENT_VARIABLE_NAME_CHANGED, &event);
	}
	return true;
}

static int cc_reg_index(RAnal *anal, const char *callconv, const char *regname) {
	if (!callconv || !regname) {
		return -1;
	}
	const int arg_max = r_anal_cc_max_arg (anal, callconv);
	int i;
	for (i = 0; i < arg_max; i++) {
		const char *reg_arg = r_anal_cc_arg (anal, callconv, i, 0);
		if (reg_arg && !strcmp (regname, reg_arg)) {
			return i;
		}
	}
	return -1;
}

R_API int r_anal_var_get_argnum(RAnalVar *var) {
	R_RETURN_VAL_IF_FAIL (var, -1);
	if (var->argnum >= 0) {
		return var->argnum;
	}
	RAnal *anal = var->fcn->anal;
	if (!var->isarg || var->kind != R_ANAL_VAR_KIND_REG) { // TODO: support bp and sp too
		return -1;
	}
	if (!var->regname) {
		return -1;
	}
	RRegItem *ri = r_reg_get (anal->reg, var->regname, -1);
	if (!ri) {
		return -1;
	}
	char *ri_name = strdup (ri->name);
	r_unref (ri);
	char *callconv = var->fcn->callconv ? strdup (var->fcn->callconv): NULL;
	const int idx = cc_reg_index (anal, callconv, ri_name);
	free (callconv);
	free (ri_name);
	return idx;
}

R_API R_BORROW RVecAnalVarPtr *r_anal_function_get_vars_used_at(RAnalFunction *fcn, ut64 op_addr) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
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
		RVecAnalVarPtr *used_vars = r_anal_function_get_vars_used_at (fcn, addr);
		if (used_vars && !RVecAnalVarPtr_empty (used_vars)) {
			RAnalVar **first = RVecAnalVarPtr_at (used_vars, 0);
			var = first? *first: NULL;
			if (R_STR_ISEMPTY (var->name)) {
				var = NULL;
			}
			break;
		}
	}
	r_list_free (fcns);
	return var;
}

R_API RAnalVar *r_anal_var_get_dst_var(RAnalVar *var) {
	R_RETURN_VAL_IF_FAIL (var, NULL);
	RAnalVarAccess *acc;
	R_VEC_FOREACH (&var->accesses, acc) {
		if (!(acc->type & R_PERM_R)) {
			continue;
		}
		ut64 addr = var->fcn->addr + acc->offset;
		RVecAnalVarPtr *used_vars = r_anal_function_get_vars_used_at (var->fcn, addr);
		RAnalVar **it;
		R_VEC_FOREACH (used_vars, it) {
			RAnalVar *used_var = *it;
			if (used_var == var) {
				continue;
			}
			RAnalVarAccess *other_acc = r_anal_var_get_access_at (used_var, addr);
			if (other_acc && other_acc->type & R_PERM_W) {
				return used_var;
			}
		}
	}
	return NULL;
}

R_API bool r_anal_var_set_access(RAnal *anal, RAnalVar *var, const char *reg, ut64 access_addr, int access_type, st64 stackptr) {
	R_RETURN_VAL_IF_FAIL (var, false);
	st64 offset = access_addr - var->fcn->addr;

	// accesses are stored ordered by offset, use binary search to get the matching existing or the index to insert a new one
	size_t index;
	RAnalVarAccess needle = { .offset = offset };
	index = RVecAnalVarAccess_lower_bound (&var->accesses, &needle, anal_var_access_compare);
	RAnalVarAccess *acc = NULL;
	const ut64 acc_len = RVecAnalVarAccess_length (&var->accesses);
	if (index < acc_len) {
		acc = RVecAnalVarAccess_at (&var->accesses, index);
	}
	if (!acc || acc->offset != offset) {
		RAnalVarAccess *new_slot = RVecAnalVarAccess_emplace_back (&var->accesses);
		if (!new_slot) {
			return false;
		}
		if (index < acc_len) {
			RAnalVarAccess *dst = RVecAnalVarAccess_at (&var->accesses, index);
			if (!dst) {
				return false;
			}
			memmove (dst + 1, dst, (acc_len - index) * sizeof (RAnalVarAccess));
			acc = dst;
		} else {
			acc = new_slot;
		}
		acc->offset = offset;
		acc->type = 0;
	}

	acc->type |= (ut8)access_type;
	acc->stackptr = stackptr;
	acc->reg = r_str_constpool_get (&var->fcn->anal->constpool, reg);

	// add the inverse reference from the instruction to the var
	RVecAnalVarPtr *inst_accesses = ht_up_find (var->fcn->inst_vars, (ut64)offset, NULL);
	if (!inst_accesses) {
		inst_accesses = RVecAnalVarPtr_new ();
		if (!inst_accesses) {
			return false;
		}
		ht_up_insert (var->fcn->inst_vars, (ut64)offset, inst_accesses);
	}
	if (!anal_var_ptr_contains (inst_accesses, var)) {
		RVecAnalVarPtr_push_back (inst_accesses, &var);
	}
	return true;
}

R_API void r_anal_var_remove_access_at(RAnalVar *var, ut64 address) {
	R_RETURN_IF_FAIL (var);
	st64 offset = address - var->fcn->addr;
	size_t index;
	RAnalVarAccess needle = { .offset = offset };
	index = RVecAnalVarAccess_lower_bound (&var->accesses, &needle, anal_var_access_compare);
	if (index >= RVecAnalVarAccess_length (&var->accesses)) {
		return;
	}
	RAnalVarAccess *acc = RVecAnalVarAccess_at (&var->accesses, index);
	if (acc->offset == offset) {
		RVecAnalVarAccess_remove (&var->accesses, index);
		RVecAnalVarPtr *inst_accesses = ht_up_find (var->fcn->inst_vars, (ut64)offset, NULL);
		anal_var_ptr_remove (inst_accesses, var);
	}
	R_DIRTY_SET (var->fcn->anal);
}

R_API void r_anal_var_clear_accesses(RAnalVar *var) {
	R_RETURN_IF_FAIL (var);
	RAnalFunction *fcn = var->fcn;
	if (fcn->inst_vars) {
		// remove all inverse references to the var's accesses
		RAnalVarAccess *acc;
		R_VEC_FOREACH (&var->accesses, acc) {
			RVecAnalVarPtr *inst_accesses = ht_up_find (fcn->inst_vars, (ut64)acc->offset, NULL);
			if (!inst_accesses) {
				continue;
			}
			anal_var_ptr_remove (inst_accesses, var);
		}
	}
	RVecAnalVarAccess_clear (&var->accesses);
	R_DIRTY_SET (var->fcn->anal);
}

R_API RAnalVarAccess *r_anal_var_get_access_at(RAnalVar *var, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (var, NULL);
	st64 offset = addr - var->fcn->addr;
	size_t index;
	RAnalVarAccess needle = { .offset = offset };
	index = RVecAnalVarAccess_lower_bound (&var->accesses, &needle, anal_var_access_compare);
	if (index >= RVecAnalVarAccess_length (&var->accesses)) {
		return NULL;
	}
	RAnalVarAccess *acc = RVecAnalVarAccess_at (&var->accesses, index);
	if (acc->offset == offset) {
		return acc;
	}
	return NULL;
}

R_API void r_anal_var_add_constraint(RAnalVar *var, R_BORROW RAnalVarConstraint *constraint) {
	RVecAnalVarConstraint_push_back (&var->constraints, constraint);
}

R_API char *r_anal_var_get_constraints_readable(RAnalVar *var) {
	size_t n = (size_t)RVecAnalVarConstraint_length (&var->constraints);
	if (!n) {
		return NULL;
	}
	bool low = false, high = false;
	RStrBuf sb;
	r_strbuf_init (&sb);
	size_t i;
	for (i = 0; i < n; i += 1) {
		RAnalVarConstraint *constr = RVecAnalVarConstraint_at (&var->constraints, i);
		switch (constr->cond) {
		case R_ANAL_CONDTYPE_LE:
			if (high) {
				r_strbuf_append (&sb, " && ");
			}
			r_strbuf_appendf (&sb, "<= 0x%"PFMT64x, constr->val);
			low = true;
			break;
		case R_ANAL_CONDTYPE_LT:
			if (high) {
				r_strbuf_append (&sb, " && ");
			}
			r_strbuf_appendf (&sb, "< 0x%"PFMT64x, constr->val);
			low = true;
			break;
		case R_ANAL_CONDTYPE_GE:
			r_strbuf_appendf (&sb, ">= 0x%"PFMT64x, constr->val);
			high = true;
			break;
		case R_ANAL_CONDTYPE_GT:
			r_strbuf_appendf (&sb, "> 0x%"PFMT64x, constr->val);
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
	R_RETURN_VAL_IF_FAIL (fcn && a && type >= 0 && type <= 1, -1);
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

R_API int r_anal_var_count_all(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	return (int)RVecAnalVarPtr_length (&fcn->vars);
}

R_API int r_anal_var_count_args(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0); // No function implies no variables, but probably mistake
	int args = 0;
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (var->isarg) {
			args++;
		}
	}
	return args;
}

R_API int r_anal_var_count_locals(RAnalFunction *fcn) {
	// if it's not an arg then it's local
	const int args = r_anal_var_count_args (fcn);
	return r_anal_var_count_all (fcn) - args;
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

#if 0
static const char *get_regname(RAnal *anal, RAnalValue *value) {
	return value? value->reg: NULL;
}
#else
static const char *get_regname(RAnal *anal, RAnalValue *value) {
	// R2_590 - this is underperforming hard
	const char *name = NULL;
#if 0
	if (value && value->reg) {
		name = (const char *)value->reg;
	}
#else
	if (value && value->reg) {
		name = value->reg;
		RRegItem *ri = r_reg_get (anal->reg, value->reg, -1);
		if (ri && (ri->size == 32) && (anal->config->bits == 64)) {
			name = r_reg_32_to_64 (anal->reg, value->reg);
		}
	}
#endif
	return name;
}
#endif

R_API R_OWN char *r_anal_function_autoname_var(RAnalFunction *fcn, char kind, const char *pfx, int ptr) {
	const ut32 uptr = R_ABS (ptr);
	char *varname = r_str_newf ("%s_%xh", pfx, uptr);
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
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
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
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
	const st64 maxstackframe = 1024 * 8;
	RAnalValue *val = NULL;

	R_RETURN_IF_FAIL (anal && fcn && op && reg);

	R_VEC_FOREACH (&op->srcs, val) {
		if (val && val->reg && !strcmp (reg, val->reg)) {
			st64 delta = val->delta;
			if ((delta > 0 && *sign == '+') || (delta < 0 && *sign == '-')) {
				ptr = R_ABS (val->delta);
				break;
			}
		}
	}

	if (!ptr) {
		const char *op_esil = r_strbuf_get (&op->esil);
		if (!op_esil) {
			return;
		}
		char *esil_buf = strdup (op_esil);
		if (!esil_buf) {
			return;
		}
		r_strf_var (esilexpr, 64, ",%s,%s,", reg, sign);
		char *ptr_end = strstr (esil_buf, esilexpr);
		if (!ptr_end) {
			free (esil_buf);
			return;
		}
		*ptr_end = 0;
		char *addr = ptr_end;
		while ((addr[0] != '0' || addr[1] != 'x') && addr >= esil_buf + 1 && *addr != ',') {
			addr--;
		}
		if (r_str_startswith (addr, "0x")) {
			ptr = (st64)r_num_get (NULL, addr);
		} else {
			//XXX: This is a workaround for inconsistent esil
			val = RVecRArchValue_at (&op->dsts, 0);
			if (!op->stackop && val) {
				const char *sp = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
				const char *bp = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
				const char *rn = val? val->reg: NULL;
				if (rn && ((bp && !strcmp (bp, rn)) || (sp && !strcmp (sp, rn)))) {
					if (anal->verbose) {
						R_LOG_WARN ("Analysis didn't fill op->stackop for instruction that alters stack at 0x%" PFMT64x, op->addr);
					}
					free (esil_buf);
					goto beach;
				}
			}
			if (*addr == ',') {
				addr++;
			}
			if (!op->stackop && op->type != R_ANAL_OP_TYPE_PUSH && op->type != R_ANAL_OP_TYPE_POP
				&& op->type != R_ANAL_OP_TYPE_RET && r_str_isnumber (addr)) {
				ptr = (st64)r_num_get (NULL, addr);
				val = RVecRArchValue_at (&op->srcs, 0);
				if (ptr && val && ptr == val->imm) {
					free (esil_buf);
					goto beach;
				}
			} else if ((op->stackop == R_ANAL_STACK_SET) || (op->stackop == R_ANAL_STACK_GET)) {
				if (op->ptr % 4) {
					free (esil_buf);
					goto beach;
				}
				ptr = R_ABS (op->ptr);
			} else {
				free (esil_buf);
				goto beach;
			}
		}
		free (esil_buf);
	}

	if (anal->verbose && (!RVecRArchValue_at (&op->srcs, 0) || !RVecRArchValue_at (&op->dsts, 0))) {
		R_LOG_WARN ("Analysis didn't fill op->src/dst at 0x%" PFMT64x, op->addr);
	}

	const int maxarg = 32; // TODO: use maxarg ?
	int rw = (op->direction == R_ANAL_OP_DIR_WRITE) ? R_PERM_W : R_PERM_R;
	if (*sign == '+') {
		const bool isarg = type == R_ANAL_VAR_KIND_SPV ? ptr >= fcn->stack : ptr >= fcn->bp_off;
		const char *pfx = isarg ? ARGPREFIX : VARPREFIX;
		st64 frame_off;
		if (type == R_ANAL_VAR_KIND_SPV) {
			frame_off = ptr - fcn->stack;
		} else {
			frame_off = ptr - fcn->bp_off;
		}
		if (maxstackframe != 0 && (frame_off > maxstackframe || frame_off < -maxstackframe)) {
			goto beach;
		}
		RAnalVar *var = get_stack_var (fcn, frame_off);
		if (var) {
			r_anal_var_set_access (anal, var, reg, op->addr, rw, ptr);
			goto beach;
		}
		char *varname = NULL, *vartype = NULL;
		if (isarg) {
			const char *place = fcn->callconv ? r_anal_cc_arg (anal, fcn->callconv, maxarg, -1) : NULL;
			bool stack_rev = place ? !strcmp (place, "stack_rev") : false;
			char *fname = r_type_func_guess (anal->sdb_types, fcn->name);
			if (fname) {
				ut64 sum_sz = 0;
				size_t from, to, i;
				if (stack_rev) {
					const size_t cnt = r_type_func_args_count (anal->sdb_types, fname);
					from = cnt ? cnt - 1 : cnt;
					to = fcn->callconv ? r_anal_cc_max_arg (anal, fcn->callconv) : 0;
				} else {
					from = fcn->callconv ? r_anal_cc_max_arg (anal, fcn->callconv) : 0;
					to = r_type_func_args_count (anal->sdb_types, fname);
				}
				const int bytes = (fcn->bits ? fcn->bits : anal->config->bits) / 8;
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
			RAnalVar *var = r_anal_function_set_var (fcn, frame_off, type, vartype, anal->config->bits / 8, isarg, varname);
			if (var) {
				r_anal_var_set_access (anal, var, reg, op->addr, rw, ptr);
			}
			free (varname);
		}
		free (vartype);
	} else {
		st64 frame_off = -(ptr + fcn->bp_off);
		if (maxstackframe > 0 && (frame_off > maxstackframe || frame_off < -maxstackframe)) {
			goto beach;
		}
		RAnalVar *var = get_stack_var (fcn, frame_off);
		if (var) {
			r_anal_var_set_access (anal, var, reg, op->addr, rw, -ptr);
			goto beach;
		}
		char *varname = anal->opt.varname_stack
			? r_str_newf ("%s_%" PFMT64x "h", VARPREFIX, R_ABS (frame_off))
			: r_anal_function_autoname_var (fcn, type, VARPREFIX, -ptr);
		if (varname) {
			RAnalVar *var = r_anal_function_set_var (fcn, frame_off, type, NULL, anal->config->bits / 8, false, varname);
			if (var) {
				r_anal_var_set_access (anal, var, reg, op->addr, rw, -ptr);
			}
			free (varname);
		}
	}
beach:
	;
}

#if 0
static bool is_reg_in_src(const char *regname, RAnal *anal, RAnalOp *op) {
	RAnalValue *src0 = RVecRArchValue_at (&op->srcs, 0);
	RAnalValue *src1 = RVecRArchValue_at (&op->srcs, 1);
	RAnalValue *src2 = RVecRArchValue_at (&op->srcs, 2);
	const char* opsreg0 = src0 ? get_regname (anal, src0) : NULL;
	const char* opsreg1 = src1 ? get_regname (anal, src1) : NULL;
	const char* opsreg2 = src2 ? get_regname (anal, src2) : NULL;
	return (STR_EQUAL (regname, opsreg0)) || (STR_EQUAL (regname, opsreg1)) || (STR_EQUAL (regname, opsreg2));
}
#else
static bool is_reg_in_src(const char *regname, RAnal *anal, RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (regname && anal && op, false);
	int i;
	for (i = 0; i < 3; i++) {
		RAnalValue *src = RVecRArchValue_at (&op->srcs, i);
		if (!src) {
			return false;
		}
		const char *srcreg = get_regname (anal, src);
		if (srcreg && !strcmp (regname, srcreg)) {
			return true;
		}
	}
	return false;
}
#endif

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

static inline bool arch_destroys_dst(const char *arch) {
	R_RETURN_VAL_IF_FAIL (arch, false);
	return (!strcmp (arch, "arm") || !strcmp (arch, "riscv") || !strcmp (arch, "ppc"));
}

static bool is_used_like_arg(const char *regname, const char *opsreg, const char *opdreg, RAnalOp *op, RAnal *anal) {
	RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
	RAnalValue *src = RVecRArchValue_at (&op->srcs, 0);
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
		if (op_affect_dst (op) && arch_destroys_dst (anal->config->arch)) {
			if (is_reg_in_src (regname, anal, op)) {
				return true;
			}
			return false;
		}
		return ((STR_EQUAL (opdreg, regname)) || (is_reg_in_src (regname, anal, op)));
	}
}

R_API void r_anal_extract_rarg(RAnal *anal, RAnalOp *op, RAnalFunction *fcn, int *reg_set, int *count) {
	int i, argc = 0;
	R_RETURN_IF_FAIL (anal && op && fcn);
	RAnalValue *src = RVecRArchValue_at (&op->srcs, 0);
	RAnalValue *dst = RVecRArchValue_at (&op->dsts, 0);
	const char *opsreg = src ? get_regname (anal, src) : NULL;
	const char *opdreg = dst ? get_regname (anal, dst) : NULL;
	const int size = (fcn->bits ? fcn->bits : anal->config->bits) / 8;
	if (!fcn->callconv) {
		R_LOG_DEBUG ("No calling convention for function '%s' to extract register arguments", fcn->name);
		return;
	}
	char *fname = r_type_func_guess (anal->sdb_types, fcn->name);
	Sdb *TDB = anal->sdb_types;
	int max_count = r_anal_cc_max_arg (anal, fcn->callconv);
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
			RFlagItem *flag = r_flag_get_by_spaces (core->flags, false, offset, R_FLAGS_FS_IMPORTS, NULL);
			if (flag) {
				callee = r_type_func_guess (TDB, flag->name);
				if (callee) {
					const char *cc = r_anal_cc_func (anal, callee);
					if (cc && !strcmp (fcn->callconv, cc)) {
						callee_rargs = R_MIN (max_count, r_type_func_args_count (TDB, callee));
					}
				}
			}
		} else if (!f->is_variadic && fcn->callconv && f->callconv && !strcmp (fcn->callconv, f->callconv)) {
			callee = r_type_func_guess (TDB, f->name);
			if (callee) {
				callee_rargs = R_MIN (max_count, r_type_func_args_count (TDB, callee));
			}
			callee_rargs = callee_rargs
				? callee_rargs
				: r_anal_var_count (anal, f, R_ANAL_VAR_KIND_REG, 1);
			callee_rargs_l = r_anal_var_list (anal, f, R_ANAL_VAR_KIND_REG);
		}
		int i;
		const int total = callee_rargs;
		for (i = 0; i < callee_rargs; i++) {
			if (reg_set[i]) {
				continue;
			}
			const char *vname = NULL;
			char *type = NULL;
			char *name = NULL;
			int delta = 0;
			const char *regname = r_anal_cc_arg (anal, fcn->callconv, i, total);
			if (regname) {
				RRegItem *ri = r_reg_get (anal->reg, regname, -1);
				if (ri) {
					delta = ri->index;
					r_unref (ri);
				}
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
			RAnalVar *var = r_anal_function_set_var (fcn, delta, R_ANAL_VAR_KIND_REG, type, size, true, vname);
			if (var && var->argnum < 0) {
				var->argnum = *count;
			}
			(*count)++;
			free (name);
			free (type);
		}
		free (callee);
		r_list_free (callee_rargs_l);
		free (fname);
		return;
	}

	const int total = 0; // TODO: pass argn
	for (i = 0; i < max_count; i++) {
		const char *regname = r_anal_cc_arg (anal, fcn->callconv, i, total);
		if (!regname) {
		// WIP	break;
		} else {
			int delta = 0;
			RRegItem *ri = NULL;
			RAnalVar *var = NULL;
			const bool is_arg = is_used_like_arg (regname, opsreg, opdreg, op, anal);
			if (is_arg && reg_set[i] != 2) {
				ri = r_reg_get (anal->reg, regname, -1);
				if (ri) {
					delta = ri->index;
					r_unref (ri);
				}
			}
			if (is_arg && reg_set[i] == 1) {
				var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, delta);
			} else if (is_arg && reg_set[i] != 2) {
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
				if (var && var->argnum < 0) {
					var->argnum = *count;
				}
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
				r_anal_var_set_access (anal, var, var->regname, op->addr, R_PERM_R, 0);
				r_meta_set_string (anal, R_META_TYPE_VARTYPE, op->addr, var->name);
			}
		}
	}

	const char *selfreg = r_anal_cc_self (anal, fcn->callconv);
	if (selfreg) {
		bool is_arg = is_used_like_arg (selfreg, opsreg, opdreg, op, anal);
		if (is_arg && reg_set[i] != 2) {
			int delta = 0;
			char *vname = strdup ("self");
			RRegItem *ri = r_reg_get (anal->reg, selfreg, -1);
			if (ri) {
				delta = ri->index;
				r_unref (ri);
			}
			RAnalVar *newvar = r_anal_function_set_var (fcn, delta, R_ANAL_VAR_KIND_REG, 0, size, true, vname);
			if (newvar) {
				r_anal_var_set_access (anal, newvar, newvar->regname, op->addr, R_PERM_R, 0);
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

	const char *errorreg = r_anal_cc_error (anal, fcn->callconv);
	if (errorreg) {
		if (reg_set[i] == 0 && STR_EQUAL (opdreg, errorreg)) {
			int delta = 0;
			char *vname = strdup ("error");
			RRegItem *ri = r_reg_get (anal->reg, errorreg, -1);
			if (ri) {
				delta = ri->index;
				r_unref (ri);
			}
			RAnalVar *newvar = r_anal_function_set_var (fcn, delta, R_ANAL_VAR_KIND_REG, 0, size, true, vname);
			if (newvar) {
				r_anal_var_set_access (anal, newvar, newvar->regname, op->addr, R_PERM_R, 0);
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
	R_RETURN_IF_FAIL (anal && fcn && op);

	const char *bpreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
	if (bpreg) {
		extract_arg (anal, fcn, op, bpreg, "+", R_ANAL_VAR_KIND_BPV);
		extract_arg (anal, fcn, op, bpreg, "-", R_ANAL_VAR_KIND_BPV);
	}
	const char *spreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
	if (spreg) {
		extract_arg (anal, fcn, op, spreg, "+", R_ANAL_VAR_KIND_SPV);
	}
}

static RList *var_generate_list(RAnal *a, RAnalFunction *fcn, int kind) {
	R_RETURN_VAL_IF_FAIL (a && fcn, NULL);
	RList *list = r_list_new ();
	if (kind < 1) {
		kind = R_ANAL_VAR_KIND_BPV; // by default show vars
	}
	if (RVecAnalVarPtr_length (&fcn->vars) > 0) {
		RAnalVar **it;
		R_VEC_FOREACH (&fcn->vars, it) {
			RAnalVar *var = *it;
			if (var->kind == kind) {
				r_list_push (list, var);
			}
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
	if (field) {
		free (field->name);
		free (field);
	}
}

R_API RList *r_anal_function_get_var_fields(RAnalFunction *fcn, int kind) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
	RList *list = r_list_newf ((RListFree)var_field_free);
	if (kind < 1) {
		kind = R_ANAL_VAR_KIND_BPV; // by default show vars
	}
	R_CRITICAL_ENTER (fcn->anal);
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (!var) {
			break;
		}
		if (var->kind != kind) {
			continue;
		}
		if (var_add_structure_fields_to_list (fcn->anal, var, list)) {
			// this var is a struct and var_add_structure_fields_to_list added all the fields
			continue;
		}
		RAnalVarField *field = R_NEW0 (RAnalVarField);
		field->name = strdup (var->name);
		if (!field->name) {
			var_field_free (field);
			break;
		}
		field->delta = var->delta;
		r_list_push (list, field);
	}
	R_CRITICAL_LEAVE (fcn->anal);
	return list;
}

static int var_comparator(const RAnalVar *a, const RAnalVar *b) {
	if (a && b) {
		if (a->isarg && !b->isarg) {
			return -1;
		}
		if (!a->isarg && b->isarg) {
			return 1;
		}
		if (a->kind == R_ANAL_VAR_KIND_REG && a->kind == b->kind) {
			if (a->argnum > b->argnum) {
				return 1;
			}
			if (a->argnum < b->argnum) {
				return -1;
			}
			return 0;
		}
		if (a->kind == b->kind && a->fcn) { // && a->fcn->bits == 32) {
			if (a->kind == R_ANAL_VAR_KIND_BPV) {
				if (a->isarg && b->isarg) {
					if (a->delta > b->delta) {
						return 1;
					}
					if (a->delta < b->delta) {
						return -1;
					}
				}
				if (a->delta > b->delta) {
					return -1;
				}
				if (a->delta < b->delta) {
					return 1;
				}
			}
		}
		if (a->delta > b->delta) {
			return 1;
		}
		if (a->delta < b->delta) {
			return -1;
		}
		return 0;
	} else if (a) {
		return 1;
	} else if (b) {
		return -1;
	}
	return 0;
	// avoid NULL dereference
	// return (a && b)? (a->delta > b->delta) - (a->delta < b->delta) : 0;
}

R_API void r_anal_var_list_show(RAnal *anal, RAnalFunction *fcn, int kind, int mode, PJ *pj) {
	R_RETURN_IF_FAIL (anal && fcn);
	bool newstack = anal->opt.var_newstack;
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
	//s- at the end of the loop
	if (mode == '*' && !r_list_empty (list)) {
		anal->cb_printf ("s 0x%" PFMT64x "\n", fcn->addr);
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
					R_LOG_ERROR ("Register not found");
					break;
				}
				anal->cb_printf ("'afv%c %s %s %s\n",
					kind, i->name, var->name, var->type);
			} else {
				int delta = kind == R_ANAL_VAR_KIND_BPV
					? var->delta + fcn->bp_off
					: var->delta;
				anal->cb_printf ("'afv%c %d %s %s\n",
					kind, delta, var->name, var->type);
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
				{
					const char *bpreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
					pj_ks (pj, "base", bpreg? bpreg: "BP");
				}
				pj_kN (pj, "offset", delta);
				pj_end (pj);
				pj_end (pj);
			}
				break;
			case R_ANAL_VAR_KIND_REG: {
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					R_LOG_ERROR ("Register not found");
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
				{
					const char *spreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
					pj_ks (pj, "base", spreg? spreg: "SP");
				}
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
				const char *bpreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP);
				if (var->isarg) {
					anal->cb_printf ("arg %s %s @ %s+0x%x\n",
						var->type, var->name, bpreg? bpreg: "BP", delta);
				} else {
					char sign = (-var->delta <= fcn->bp_off) ? '+' : '-';
					anal->cb_printf ("var %s %s @ %s%c0x%x\n",
						var->type, var->name, bpreg? bpreg: "BP",
						sign, R_ABS (delta));
				}
			}
				break;
			case R_ANAL_VAR_KIND_REG: {
				RRegItem *i = r_reg_index_get (anal->reg, var->delta);
				if (!i) {
					R_LOG_ERROR ("Register not found");
					break;
				}
				anal->cb_printf ("arg %s %s @ %s\n",
					var->type, var->name, i->name);
				}
				break;
			case R_ANAL_VAR_KIND_SPV:
			{
				int delta = newstack? var->delta: fcn->maxstack + var->delta;
				const char *spreg = r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP);
				if (!var->isarg) {
					char sign = (-var->delta <= fcn->maxstack) ? '+' : '-';
					anal->cb_printf ("var %s %s @ %s%c0x%x\n",
						var->type, var->name, spreg? spreg: "SP", sign, R_ABS (delta));
				} else {
					anal->cb_printf ("arg %s %s @ %s+0x%x\n",
						var->type, var->name, spreg? spreg: "SP", delta);

				}
			}
				break;
			}
		}
	}
	if (mode == '*' && !r_list_empty (list)) {
		anal->cb_printf ("s-\n");
	}
	if (mode == 'j') {
		pj_end (pj);
	}
	r_list_free (list);
}

static bool is_default_argname(const char *name) {
	return r_str_startswith (name, "arg") && IS_DIGIT (name[3]);
}

static void assign_reg_argnums(RAnal *anal, RAnalFunction *fcn, RList *rvars) {
	RListIter *it;
	RAnalVar *var;
	r_list_foreach (rvars, it, var) {
		if (!var->isarg) {
			var->argnum = -1;
			continue;
		}
		const char *regname = var->regname;
		RRegItem *ri = NULL;
		if (!regname) {
			ri = r_reg_index_get (anal->reg, var->delta);
			regname = ri? ri->name: NULL;
		}
		var->argnum = cc_reg_index (anal, fcn->callconv, regname);
		r_unref (ri);
	}
	r_list_sort (rvars, (RListComparator)var_comparator);
	int dense = 0;
	r_list_foreach (rvars, it, var) {
		if (var->argnum < 0) {
			continue;
		}
		var->argnum = dense++;
		if (is_default_argname (var->name)) {
			char *newname = r_str_newf ("arg%d", var->argnum + 1);
			r_anal_var_rename (anal, var, newname);
			free (newname);
		}
	}
}

R_API void r_anal_function_vars_cache_init(RAnal *anal, RAnalFcnVarsCache *cache, RAnalFunction *fcn) {
	cache->bvars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_BPV);
	cache->rvars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_REG);
	cache->svars = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_SPV);
	r_list_sort (cache->bvars, (RListComparator)var_comparator);
	assign_reg_argnums (anal, fcn, cache->rvars);
	r_list_sort (cache->svars, (RListComparator)var_comparator);
}

R_API void r_anal_function_vars_cache_fini(RAnalFcnVarsCache *cache) {
	if (!cache) {
		return;
	}
	r_list_free (cache->bvars);
	r_list_free (cache->rvars);
	r_list_free (cache->svars);
}

R_API char *r_anal_function_format_sig(RAnal * R_NONNULL anal, RAnalFunction * R_NONNULL fcn, char * R_NULLABLE fcn_name,
		RAnalFcnVarsCache * R_NULLABLE reuse_cache, const char * R_NULLABLE fcn_name_pre, const char * R_NULLABLE fcn_name_post) {
	RAnalFcnVarsCache *cache = NULL;

	const char *comma = "";
	if (!fcn_name) {
		fcn_name = fcn->name;
		if (!fcn_name) {
			return NULL;
		}
	}

	RStrBuf *buf = r_strbuf_new (NULL);
	Sdb *TDB = anal->sdb_types;
	char *type_fcn_name = r_type_func_guess (TDB, fcn_name);
	if (type_fcn_name && r_type_func_exist (TDB, type_fcn_name)) {
		const char *fcn_type = r_type_func_ret (anal->sdb_types, type_fcn_name);
		if (R_STR_ISNOTEMPTY (fcn_type)) {
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
		// This avoids false positives present in argument recovery
		// and straight away print arguments fetched from types db
#if 1
		for (i = 0; i < argc; i++) {
			char *type = r_type_func_args_type (TDB, type_fcn_name, i);
			const char *name = r_type_func_args_name (TDB, type_fcn_name, i);
			if (R_STR_ISEMPTY (type) && !strcmp (name, "...")) {
				R_LOG_DEBUG ("Detected, but unhandled vararg type"); // TODO implement vararg support
				// this is vararg type!
				free (type);
				type = strdup ("vararg");
			}
			if (R_STR_ISEMPTY (type)) {
				R_LOG_WARN ("Missing type for arg %d of function '%s'", i, type_fcn_name);
				free (type);
				goto beach;
			}
			size_t len = strlen (type);
			const char *tc = len > 0 && type[len - 1] == '*'? "": " ";
			r_strbuf_appendf (buf, "%s%s%s%s", comma, type, tc, name);
			comma = ", ";
			free (type);
		}
#endif
		goto beach;
	}
	R_FREE (type_fcn_name);

	cache = reuse_cache;
	if (!cache) {
		cache = R_NEW0 (RAnalFcnVarsCache);
		r_anal_function_vars_cache_init (anal, cache, fcn);
	}

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
		if (tmp_len > 0) {
			r_strbuf_appendf (buf, "%s%s%s%s", comma, var->type,
				tmp_len && var->type[tmp_len - 1] == '*' ? "" : " ",
				var->name);
			comma = ", ";
		}
	}
	r_list_foreach (cache->bvars, iter, var) {
		if (var->isarg) {
			tmp_len = strlen (var->type);
			if (tmp_len > 0) {
				r_strbuf_appendf (buf, "%s%s%s%s", comma, var->type,
						tmp_len && var->type[tmp_len - 1] == '*' ? "" : " ",
						var->name);
				comma = ", ";
			}
		}
	}
	r_list_foreach (cache->svars, iter, var) {
		if (var->isarg) {
			tmp_len = strlen (var->type);
			if (tmp_len > 0) {
				r_strbuf_appendf (buf, "%s%s%s%s", comma, var->type,
					tmp_len && var->type[tmp_len - 1] == '*'? "": " ",
					var->name);
				comma = ", ";
			}
		}
	}
beach:
	r_strbuf_append (buf, ");");
	R_FREE (type_fcn_name);
		if (!reuse_cache) {
			// !reuse_cache => we created our own cache
			r_anal_function_vars_cache_fini (cache);
			free (cache);
		}
		return r_strbuf_drain (buf);
	}
