/* radare - LGPL - Copyright 2019-2025 - pancake, thestr4ng3r */

#include <r_anal_priv.h>
#include <r_util/r_json.h>

static bool get_functions_block_cb(RAnalBlock *block, void *user) {
	RList *list = user;
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (block->fcns, iter, fcn) {
		if (r_list_contains (list, fcn)) {
			continue;
		}
		r_list_push (list, fcn);
	}
	return true;
}

R_API RList *r_anal_get_functions_in(RAnal *anal, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RList *list = r_list_new ();
	if (list) {
		r_anal_blocks_foreach_in (anal, addr, get_functions_block_cb, list);
	}
	return list;
}

static bool __fcn_exists(RAnal *anal, const char *name, ut64 addr) {
	// check if name is already registered
	bool found = false;
	if (addr == UT64_MAX) {
		R_LOG_ERROR ("Invalid function address (-1) '%s'", name);
		return true;
	}
	if (!name) {
		R_LOG_ERROR ("TODO: Empty function name, we must auto generate one");
		return true;
	}
	RAnalFunction *f = ht_pp_find (anal->ht_name_fun, name, &found);
	if (f && found) {
		if (f->addr != addr) {
			const char *const nopskipmsg = (anal->opt.nopskip)? "Try disabling `e anal.nopskip=false`": "";
			R_LOG_WARN ("Unaligned function '%s' at 0x%08"PFMT64x" (vs 0x%08"PFMT64x")%s", name, addr, f->addr, nopskipmsg);
		}
		return true;
	}
	// check if there's a function already in the given address
	found = false;
	f = ht_up_find (anal->ht_addr_fun, addr, &found);
	if (f && found) {
		R_LOG_DEBUG ("Function already defined in 0x%08"PFMT64x" as '%s'; ignoring duplicate '%s'",
			addr, f->name? f->name: "", name);
		return true;
	}
	return false;
}

R_IPI void r_anal_var_free(RAnalVar *av);

static void inst_vars_kv_free(HtUPKv *kv) {
	RVecAnalVarPtr *vec = kv->value;
	RVecAnalVarPtr_free (vec);
}

static void labels_kv_free(HtUPKv *kv) {
	if (kv) {
		free (kv->value);
	}
}

static void label_addrs_kv_free(HtPPKv *kv) {
	if (kv) {
		free (kv->key);
		free (kv->value);
	}
}

R_API RAnalFunction *r_anal_function_new(RAnal *anal) {
	// XXX fcn->name is null because its r_anal_create_function the one that must be called
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	RAnalFunction *fcn = R_NEW0 (RAnalFunction);
	fcn->anal = anal;
	fcn->addr = UT64_MAX;
	fcn->callconv = r_str_constpool_get (&anal->constpool, r_anal_cc_default (anal));
	fcn->bits = anal->config->bits;
	fcn->bbs = r_list_new ();
	fcn->diff = r_anal_diff_new ();
	fcn->has_changed = true;
	fcn->bp_frame = true;
	fcn->is_noreturn = false;
	fcn->meta._min = UT64_MAX;
	fcn->meta.numrefs = -1;
	fcn->meta.numcallrefs = -1;
	RVecAnalVarPtr_init (&fcn->vars);
	fcn->inst_vars = ht_up_new (NULL, inst_vars_kv_free, NULL);
	fcn->labels = ht_up_new (NULL, labels_kv_free, NULL);
	fcn->label_addrs = ht_pp_new (NULL, label_addrs_kv_free, NULL);
	fcn->ts = r_time_now ();
	return fcn;
}

R_API void r_anal_function_free(RAnalFunction *fcn) {
	if (!fcn) {
		return;
	}

	RAnalBlock *block;
	RListIter *iter, *iter2;
	r_list_foreach_safe (fcn->bbs, iter, iter2, block) {
		r_anal_function_remove_block (fcn, block);
		// r_list_delete_data (block->fcns, fcn);
		// r_anal_block_unref (block);
	}
	// fcn->bbs->free = r_anal_block_unref;
	r_list_free (fcn->bbs);

	RAnal *anal = fcn->anal;
	if (ht_up_find (anal->ht_addr_fun, fcn->addr, NULL) == fcn) {
		ht_up_delete (anal->ht_addr_fun, fcn->addr);
	}
	if (ht_pp_find (anal->ht_name_fun, fcn->name, NULL) == fcn) {
		ht_pp_delete (anal->ht_name_fun, fcn->name);
	}

	ht_up_free (fcn->inst_vars);
	fcn->inst_vars = NULL;
	r_anal_function_delete_all_vars (fcn);
	RVecAnalVarPtr_fini (&fcn->vars);

	ht_up_free (fcn->labels);
	ht_pp_free (fcn->label_addrs);

	free (fcn->name);
	free (fcn->realname);
	free (fcn->pin);
	free (fcn->assumptions_json);
	fcn->bbs = NULL;
	free (fcn->fingerprint);
	r_anal_diff_free (fcn->diff);
	r_list_free (fcn->imports);
	free (fcn);
}

R_API bool r_anal_add_function(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, false);
	if (R_STR_ISEMPTY (fcn->name)) {
		R_LOG_WARN ("Unnamed function at 0x%08"PFMT64x, fcn->addr);
		// r_sys_breakpoint ();
		free (fcn->name);
		const char *fcnprefix = r_anal_fcn_prefix_at (anal, fcn->addr);
		if (R_STR_ISEMPTY (fcnprefix)) {
			fcn->name = r_str_newf ("fcn_%08"PFMT64x, fcn->addr);
		} else {
			fcn->name = r_str_newf ("%s.%"PFMT64x, fcnprefix, fcn->addr);
		}
	}
	if (__fcn_exists (anal, fcn->name, fcn->addr)) {
		return false;
	}
	if (anal->cb.on_fcn_new) {
		anal->cb.on_fcn_new (anal, anal->user, fcn);
	}
	if (anal->flg_fcn_set) {
		anal->flg_fcn_set (anal->flb.f, fcn->name, fcn->addr, r_anal_function_size_from_entry (fcn));
	}
	fcn->is_noreturn = r_anal_noreturn_at_addr (anal, fcn->addr);
	r_list_append (anal->fcns, fcn);
	ht_pp_insert (anal->ht_name_fun, fcn->name, fcn);
	ht_up_insert (anal->ht_addr_fun, fcn->addr, fcn);
	{
		REventFunction event = { .addr = fcn->addr, .fcn = fcn };
		r_event_send (anal->ev, R_EVENT_FUNCTION_ADDED, &event);
	}
	return true;
}

R_API RAnalFunction *r_anal_create_function(RAnal *anal, const char *name, ut64 addr, int type, RAnalDiff *diff) {
	R_RETURN_VAL_IF_FAIL (anal && addr != UT64_MAX, NULL);
	RAnalFunction *fcn = r_anal_function_new (anal);
	fcn->addr = addr;
	fcn->type = type;
	fcn->callconv = r_str_constpool_get (&anal->constpool, r_anal_cc_default (anal));
	fcn->bits = anal->config->bits;
	if (name) {
		free (fcn->name);
		fcn->name = strdup (name);
	} else {
		const char *fcnprefix = r_anal_fcn_prefix_at (anal, fcn->addr);
		if (R_STR_ISEMPTY (fcnprefix)) {
			fcn->name = r_str_newf ("fcn_%08"PFMT64x, fcn->addr);
		} else {
			fcn->name = r_str_newf ("%s.%08"PFMT64x, fcnprefix, fcn->addr);
		}
	}
	if (diff) {
		fcn->diff->type = diff->type;
		fcn->diff->addr = diff->addr;
		R_FREE (fcn->diff->name);
		if (diff->name) {
			fcn->diff->name = strdup (diff->name);
		}
	}
	if (!r_anal_add_function (anal, fcn)) {
		r_anal_function_free (fcn);
		return NULL;
	}
	return fcn;
}

R_API bool r_anal_function_delete(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, false);
	ut64 fcn_addr = fcn->addr;
	bool found = r_list_delete_data (fcn->anal->fcns, fcn);
	if (found) {
		REventFunction event = { .addr = fcn_addr };
		r_event_send (anal->ev, R_EVENT_FUNCTION_DELETED, &event);
	}
	return found;
}

R_API RAnalFunction *r_anal_get_function_at(RAnal *anal, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	bool found = false;
	RAnalFunction *f = ht_up_find (anal->ht_addr_fun, addr, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

R_API bool r_anal_function_relocate(RAnalFunction *fcn, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (fcn, false);
	if (fcn->addr == addr) {
		return true;
	}
	if (r_anal_get_function_at (fcn->anal, addr)) {
		return false;
	}
	ht_up_delete (fcn->anal->ht_addr_fun, fcn->addr);
	fcn->addr = addr;
	ht_up_insert (fcn->anal->ht_addr_fun, addr, fcn);
	return true;
}

R_API bool r_anal_function_rename(RAnalFunction *fcn, const char *name) {
	R_RETURN_VAL_IF_FAIL (fcn && R_STR_ISNOTEMPTY (name), false);
	RAnal *anal = fcn->anal;
	RAnalFunction *existing = ht_pp_find (anal->ht_name_fun, name, NULL);
	if (existing) {
		if (existing == fcn) {
			// fcn->name == name, nothing to do
			return true;
		}
		return false;
	}
	char *newname = strdup (name);
	if (R_LIKELY (newname)) {
		bool in_tree = ht_pp_delete (anal->ht_name_fun, fcn->name);
		free (fcn->name);
		fcn->name = newname;
		if (in_tree) {
			// only re-insert if it really was in the tree before
			ht_pp_insert (anal->ht_name_fun, fcn->name, fcn);
		}
		{
			// TODO: maybe we want to know which was the old name?
			REventFunction event = { .addr = fcn->addr, .fcn = fcn };
			r_event_send (anal->ev, R_EVENT_FUNCTION_RENAMED, &event);
		}
		return true;
	}
	return false;
}

R_API void r_anal_function_add_block(RAnalFunction *fcn, RAnalBlock *bb) {
	R_RETURN_IF_FAIL (fcn && bb);
	if (r_list_contains (bb->fcns, fcn)) {
		return;
	}
	r_list_append (bb->fcns, fcn);
	r_list_append (fcn->bbs, r_ref (bb));

	if (fcn->meta._min != UT64_MAX) {
		if (bb->addr + bb->size > fcn->meta._max) {
			fcn->meta._max = bb->addr + bb->size;
		}
		if (bb->addr < fcn->meta._min) {
			fcn->meta._min = bb->addr;
		}
	}

	if (fcn->anal->cb.on_fcn_bb_new) {
		fcn->anal->cb.on_fcn_bb_new (fcn->anal, fcn->anal->user, fcn, bb);
	}
}

R_API void r_anal_function_remove_block(RAnalFunction *fcn, RAnalBlock *bb) {
	R_RETURN_IF_FAIL (fcn && bb);
	r_list_delete_data (bb->fcns, fcn);

	if (fcn->meta._min != UT64_MAX
		&& (fcn->meta._min == bb->addr || fcn->meta._max == bb->addr + bb->size)) {
		// If a block is removed at the beginning or end, updating min/max is not trivial anymore, just invalidate
		fcn->meta._min = UT64_MAX;
	}

	r_list_delete_data (fcn->bbs, bb);
	r_unref (bb);
}

static void ensure_fcn_range(RAnalFunction *fcn) {
	if (fcn->meta._min != UT64_MAX) { // recalculate only if invalid
		return;
	}
	ut64 minval = UT64_MAX;
	ut64 maxval = UT64_MIN;
	RAnalBlock *block;
	RListIter *iter;
	r_list_foreach (fcn->bbs, iter, block) {
		if (block->addr < minval) {
			minval = block->addr;
		}
		if (block->addr + block->size > maxval) {
			maxval = block->addr + block->size;
		}
	}
	fcn->meta._min = minval;
	fcn->meta._max = minval == UT64_MAX ? UT64_MAX : maxval;
}

R_API ut64 r_anal_function_linear_size(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	ensure_fcn_range (fcn);
	return fcn->meta._max - fcn->meta._min;
}

R_API ut64 r_anal_function_min_addr(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	ensure_fcn_range (fcn);
	return fcn->meta._min;
}

R_API ut64 r_anal_function_max_addr(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	ensure_fcn_range (fcn);
	return fcn->meta._max;
}



R_API ut64 r_anal_function_size_from_entry(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	ensure_fcn_range (fcn);
	return fcn->meta._min == UT64_MAX ? 0 : fcn->meta._max - fcn->addr;
}

R_API ut64 r_anal_function_realsize(const RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, UT64_MAX);
	RListIter *iter;
	RAnalBlock *bb;
	ut64 sz = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		sz += bb->size;
	}
	return sz;
}

static bool fcn_in_cb(RAnalBlock *block, void *user) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (block->fcns, iter, fcn) {
		if (fcn == user) {
			return false;
		}
	}
	return true;
}

R_API bool r_anal_function_contains(RAnalFunction *fcn, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (fcn, false);
	if (addr == UT64_MAX) {
		return false;
	}
	// fcn_in_cb breaks with false if it finds the fcn
	return !r_anal_blocks_foreach_in (fcn->anal, addr, fcn_in_cb, fcn);
}

R_API bool r_anal_function_was_modified(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, false);
	RListIter *it;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, it, bb) {
		if (r_anal_block_was_modified (bb)) {
			return true;
		}
	}
	return false;
}

R_API int r_anal_function_coverage(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	int total = r_list_length (fcn->bbs);
	if (total == 0) {
		return 0;
	}
	RListIter *iter;
	RAnalBlock *bb;
	int traced = 0;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->traced != 0) {
			traced++;
		}
	}
	return (traced * 100) / total;
}

static void fcn_context_reg_arg_free(RAnalFcnRegArg *arg) {
	if (!arg) {
		return;
	}
	free (arg->name);
	free (arg->type);
	free (arg->reg);
	free (arg);
}

static void fcn_context_slot_free(RAnalFcnSlot *slot) {
	if (!slot) {
		return;
	}
	free (slot->name);
	free (slot->type);
	free (slot->base_name);
	free (slot->arg_name);
	free (slot->home_reg);
	free (slot);
}

static char *fcn_context_dup_var_regname(RAnal *anal, const RAnalVar *var) {
	if (R_STR_ISNOTEMPTY (var->regname)) {
		return strdup (var->regname);
	}
	if (var->kind == R_ANAL_VAR_KIND_REG) {
		RRegItem *ri = r_reg_index_get (anal->reg, R_ABS (var->delta));
		if (ri) {
			char *name = strdup (ri->name);
			r_unref (ri);
			return name;
		}
	}
	return NULL;
}

static st64 fcn_context_stack_offset(const RAnalFunction *fcn, const RAnalVar *var) {
	R_RETURN_VAL_IF_FAIL (fcn && var, 0);
	switch (var->kind) {
	case R_ANAL_VAR_KIND_BPV:
		return (st64)var->delta + fcn->bp_off;
	case R_ANAL_VAR_KIND_SPV:
		return var->delta;
	default:
		return var->delta;
	}
}

static RAnalVar *fcn_context_find_register_home_source(RVecAnalVarPtr *rvars, RAnalVar *slot) {
	if (!rvars) {
		return NULL;
	}
	RAnalVar **it;
	R_VEC_FOREACH (rvars, it) {
		RAnalVar *var = *it;
		if (var && var->isarg && var->kind == R_ANAL_VAR_KIND_REG) {
			RAnalVar *dst = r_anal_var_get_dst_var (var);
			if (dst == slot) {
				return var;
			}
		}
	}
	return NULL;
}

static RAnalFcnSlotRole fcn_context_classify_slot(const RAnalVar *var, RAnalVar *home_source) {
	R_RETURN_VAL_IF_FAIL (var, R_ANAL_FCN_SLOT_UNKNOWN);
	if (home_source) {
		return R_ANAL_FCN_SLOT_HOME;
	}
	if (var->isarg) {
		return R_ANAL_FCN_SLOT_ARG;
	}
	if (var->kind == R_ANAL_VAR_KIND_BPV || var->kind == R_ANAL_VAR_KIND_SPV) {
		return R_ANAL_FCN_SLOT_LOCAL;
	}
	return R_ANAL_FCN_SLOT_UNKNOWN;
}

static RAnalFcnRegArg *fcn_context_collect_reg_arg(RAnal *anal, const RAnalFcnContext *ctx, RAnalVar *var) {
	R_RETURN_VAL_IF_FAIL (anal && ctx && var, NULL);
	RAnalFcnRegArg *arg = R_NEW0 (RAnalFcnRegArg);
	const int arg_index = r_anal_var_get_argnum (var);
	const RAnalFunctionParam *signature_param = (ctx->signature && arg_index >= 0)
		? r_list_get_n (ctx->signature->params, arg_index)
		: NULL;
	arg->arg_index = arg_index;
	if (signature_param && R_STR_ISNOTEMPTY (signature_param->name) && r_anal_var_is_default_argname (var->name)) {
		arg->name = strdup (signature_param->name);
	} else if (R_STR_ISNOTEMPTY (var->name)) {
		arg->name = strdup (var->name);
	}
	if (R_STR_ISNOTEMPTY (var->type)) {
		arg->type = strdup (var->type);
	} else if (signature_param && R_STR_ISNOTEMPTY (signature_param->type)) {
		arg->type = strdup (signature_param->type);
	}
	arg->reg = fcn_context_dup_var_regname (anal, var);
	if ((R_STR_ISNOTEMPTY (var->name) && !arg->name)
		|| (R_STR_ISNOTEMPTY (var->type) && !arg->type)
		|| !arg->reg) {
		fcn_context_reg_arg_free (arg);
		return NULL;
	}
	return arg;
}

static RAnalFcnSlot *fcn_context_collect_slot(RAnal *anal, const RAnalFcnContext *ctx, RAnalFunction *fcn, RAnalVar *var, RAnalVar *home_source) {
	const RAnalFunctionParam *signature_param = NULL;

	R_RETURN_VAL_IF_FAIL (anal && ctx && fcn && var, NULL);
	RAnalFcnSlot *slot = R_NEW0 (RAnalFcnSlot);
	int arg_index = -1;
	if (R_STR_ISNOTEMPTY (var->name)) {
		slot->name = strdup (var->name);
	}
	if (R_STR_ISNOTEMPTY (var->type)) {
		slot->type = strdup (var->type);
	}
	slot->base = (var->kind == R_ANAL_VAR_KIND_BPV)? R_ANAL_FCN_BASE_BP: R_ANAL_FCN_BASE_SP;
	slot->offset = fcn_context_stack_offset (fcn, var);
	slot->role = fcn_context_classify_slot (var, home_source);

	if (home_source) {
		arg_index = r_anal_var_get_argnum (home_source);
		signature_param = (ctx->signature && arg_index >= 0)? r_list_get_n (ctx->signature->params, arg_index): NULL;
		slot->arg_index = arg_index;
		slot->home_reg = fcn_context_dup_var_regname (anal, home_source);
		if (signature_param && R_STR_ISNOTEMPTY (signature_param->name)) {
			slot->arg_name = strdup (signature_param->name);
		} else if (R_STR_ISNOTEMPTY (home_source->name)) {
			slot->arg_name = strdup (home_source->name);
		}
		if (!slot->type && signature_param && R_STR_ISNOTEMPTY (signature_param->type)) {
			slot->type = strdup (signature_param->type);
		}
	} else if (var->isarg) {
		arg_index = r_anal_var_get_argnum (var);
		slot->arg_index = arg_index;
		if (arg_index >= 0) {
			signature_param = ctx->signature? r_list_get_n (ctx->signature->params, arg_index): NULL;
			if (signature_param && R_STR_ISNOTEMPTY (signature_param->name)) {
				slot->arg_name = strdup (signature_param->name);
			} else if (R_STR_ISNOTEMPTY (var->name)) {
				slot->arg_name = strdup (var->name);
			}
			if (!slot->type && signature_param && R_STR_ISNOTEMPTY (signature_param->type)) {
				slot->type = strdup (signature_param->type);
			}
		}
	} else {
		slot->arg_index = -1;
	}

	if ((R_STR_ISNOTEMPTY (var->name) && !slot->name)
		|| (R_STR_ISNOTEMPTY (var->type) && !slot->type)
		|| (home_source && !slot->home_reg)) {
		fcn_context_slot_free (slot);
		return NULL;
	}
	return slot;
}

static RAnalFunctionSignature *fcn_context_collect_signature(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
	RAnalFunctionSignature *signature = r_anal_function_get_signature (fcn);
	if (signature || (!R_STR_ISNOTEMPTY (fcn->callconv) && !fcn->is_noreturn)) {
		return signature;
	}
	signature = R_NEW0 (RAnalFunctionSignature);
	signature->params = r_list_new ();
	if (!signature->params) {
		r_anal_function_signature_free (signature);
		return NULL;
	}
	if (R_STR_ISNOTEMPTY (fcn->callconv)) {
		signature->callconv = strdup (fcn->callconv);
		if (!signature->callconv) {
			r_anal_function_signature_free (signature);
			return NULL;
		}
	}
	signature->noreturn = fcn->is_noreturn;
	return signature;
}

static bool assumption_json_emit(PJ *pj, const RJson *json) {
	R_RETURN_VAL_IF_FAIL (pj && json, false);
	const RJson *child;
	switch (json->type) {
	case R_JSON_NULL:
		pj_null (pj);
		return true;
	case R_JSON_OBJECT:
		pj_o (pj);
		for (child = json->children.first; child; child = child->next) {
			if (!child->key) {
				return false;
			}
			pj_k (pj, child->key);
			if (!assumption_json_emit (pj, child)) {
				return false;
			}
		}
		pj_end (pj);
		return true;
	case R_JSON_ARRAY:
		pj_a (pj);
		for (child = json->children.first; child; child = child->next) {
			if (!assumption_json_emit (pj, child)) {
				return false;
			}
		}
		pj_end (pj);
		return true;
	case R_JSON_STRING:
		pj_s (pj, json->str_value? json->str_value: "");
		return true;
	case R_JSON_INTEGER:
		if (json->num.s_value < 0) {
			pj_N (pj, json->num.s_value);
		} else {
			pj_n (pj, json->num.u_value);
		}
		return true;
	case R_JSON_DOUBLE: {
		char numstr[64];
		snprintf (numstr, sizeof (numstr), "%.17g", json->num.dbl_value);
		pj_j (pj, numstr);
		return true;
	}
	case R_JSON_BOOLEAN:
		pj_b (pj, json->num.u_value != 0);
		return true;
	default:
		return false;
	}
}

static char *assumption_json_fragment(const RJson *json) {
	R_RETURN_VAL_IF_FAIL (json, NULL);
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}
	if (!assumption_json_emit (pj, json)) {
		pj_free (pj);
		return NULL;
	}
	return pj_drain (pj);
}

static char *assumption_json_field_dup(const RJson *json, const char *key) {
	const RJson *field = r_json_get (json, key);
	return field? assumption_json_fragment (field): NULL;
}

static const char *assumption_target_from_subject(const RJson *json) {
	const RJson *subject = r_json_get (json, "subject");
	if (!subject || subject->type != R_JSON_OBJECT) {
		return NULL;
	}
	const RJson *reg = r_json_get (subject, "register");
	if (reg && reg->type == R_JSON_OBJECT) {
		const char *name = r_json_get_str (reg, "name");
		if (R_STR_ISNOTEMPTY (name)) {
			return name;
		}
	}
	const RJson *stack = r_json_get (subject, "stack");
	if (stack && stack->type == R_JSON_OBJECT) {
		const char *name = r_json_get_str (stack, "name");
		if (R_STR_ISNOTEMPTY (name)) {
			return name;
		}
	}
	return NULL;
}

R_API void r_anal_function_assumption_free(RAnalFunctionAssumption *assumption) {
	if (!assumption) {
		return;
	}
	free (assumption->kind);
	free (assumption->target);
	free (assumption->scope);
	free (assumption->provenance);
	free (assumption->subject_json);
	free (assumption->value_json);
	free (assumption->payload_json);
	free (assumption);
}

static RAnalFunctionAssumption *assumption_new_from_json(const RJson *json) {
	if (!json || json->type != R_JSON_OBJECT) {
		return NULL;
	}
	const char *kind = r_json_get_str (json, "kind");
	if (R_STR_ISEMPTY (kind)) {
		kind = "analysis";
	}
	RAnalFunctionAssumption *assumption = R_NEW0 (RAnalFunctionAssumption);
	if (!assumption) {
		return NULL;
	}
	assumption->kind = strdup (kind);
	const char *target = r_json_get_str (json, "target");
	if (R_STR_ISEMPTY (target)) {
		target = assumption_target_from_subject (json);
	}
	const char *scope = r_json_get_str (json, "scope");
	const char *provenance = r_json_get_str (json, "provenance");
	assumption->target = R_STR_ISNOTEMPTY (target)? strdup (target): NULL;
	assumption->scope = R_STR_ISNOTEMPTY (scope)? strdup (scope): NULL;
	assumption->provenance = R_STR_ISNOTEMPTY (provenance)? strdup (provenance): NULL;
	assumption->subject_json = assumption_json_field_dup (json, "subject");
	assumption->value_json = assumption_json_field_dup (json, "value");
	assumption->payload_json = assumption_json_fragment (json);
	if (!assumption->kind || !assumption->payload_json
		|| (R_STR_ISNOTEMPTY (target) && !assumption->target)
		|| (R_STR_ISNOTEMPTY (scope) && !assumption->scope)
		|| (R_STR_ISNOTEMPTY (provenance) && !assumption->provenance)) {
		r_anal_function_assumption_free (assumption);
		return NULL;
	}
	return assumption;
}

static RAnalFunctionAssumption *assumption_clone(const RAnalFunctionAssumption *assumption) {
	if (!assumption || R_STR_ISEMPTY (assumption->kind)) {
		return NULL;
	}
	RAnalFunctionAssumption *clone = R_NEW0 (RAnalFunctionAssumption);
	if (!clone) {
		return NULL;
	}
	clone->kind = strdup (assumption->kind);
	clone->target = R_STR_ISNOTEMPTY (assumption->target)? strdup (assumption->target): NULL;
	clone->scope = R_STR_ISNOTEMPTY (assumption->scope)? strdup (assumption->scope): NULL;
	clone->provenance = R_STR_ISNOTEMPTY (assumption->provenance)? strdup (assumption->provenance): NULL;
	clone->subject_json = R_STR_ISNOTEMPTY (assumption->subject_json)? strdup (assumption->subject_json): NULL;
	clone->value_json = R_STR_ISNOTEMPTY (assumption->value_json)? strdup (assumption->value_json): NULL;
	clone->payload_json = R_STR_ISNOTEMPTY (assumption->payload_json)? strdup (assumption->payload_json): NULL;
	if (!clone->kind
		|| (R_STR_ISNOTEMPTY (assumption->target) && !clone->target)
		|| (R_STR_ISNOTEMPTY (assumption->scope) && !clone->scope)
		|| (R_STR_ISNOTEMPTY (assumption->provenance) && !clone->provenance)
		|| (R_STR_ISNOTEMPTY (assumption->subject_json) && !clone->subject_json)
		|| (R_STR_ISNOTEMPTY (assumption->value_json) && !clone->value_json)
		|| (R_STR_ISNOTEMPTY (assumption->payload_json) && !clone->payload_json)) {
		r_anal_function_assumption_free (clone);
		return NULL;
	}
	return clone;
}

static bool assumption_json_fragment_valid(const char *json) {
	if (R_STR_ISEMPTY (json)) {
		return false;
	}
	RJson *parsed = r_json_parsedup (json);
	if (!parsed) {
		return false;
	}
	r_json_free (parsed);
	return true;
}

static bool assumption_payload_emit(PJ *pj, const RAnalFunctionAssumption *assumption) {
	R_RETURN_VAL_IF_FAIL (pj && assumption && R_STR_ISNOTEMPTY (assumption->kind), false);
	if (R_STR_ISNOTEMPTY (assumption->payload_json)) {
		RJson *parsed = r_json_parsedup (assumption->payload_json);
		if (!parsed || parsed->type != R_JSON_OBJECT) {
			r_json_free (parsed);
			return false;
		}
		r_json_free (parsed);
		pj_j (pj, assumption->payload_json);
		return true;
	}
	pj_o (pj);
	pj_ks (pj, "kind", assumption->kind);
	if (R_STR_ISNOTEMPTY (assumption->target)) {
		pj_ks (pj, "target", assumption->target);
	}
	if (R_STR_ISNOTEMPTY (assumption->scope)) {
		pj_ks (pj, "scope", assumption->scope);
	}
	if (R_STR_ISNOTEMPTY (assumption->provenance)) {
		pj_ks (pj, "provenance", assumption->provenance);
	}
	if (R_STR_ISNOTEMPTY (assumption->subject_json)) {
		if (!assumption_json_fragment_valid (assumption->subject_json)) {
			return false;
		}
		pj_k (pj, "subject");
		pj_j (pj, assumption->subject_json);
	}
	if (R_STR_ISNOTEMPTY (assumption->value_json)) {
		if (!assumption_json_fragment_valid (assumption->value_json)) {
			return false;
		}
		pj_k (pj, "value");
		pj_j (pj, assumption->value_json);
	}
	pj_end (pj);
	return true;
}

static bool assumption_same_key(const RAnalFunctionAssumption *assumption, const char *kind, const char *target) {
	if (!assumption || R_STR_ISEMPTY (kind) || strcmp (assumption->kind, kind)) {
		return false;
	}
	if (!target) {
		return true;
	}
	return !strcmp (r_str_get (assumption->target), target);
}

static char *assumptions_list_to_json(RList *assumptions) {
	R_RETURN_VAL_IF_FAIL (assumptions, NULL);
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}
	pj_a (pj);
	RListIter *iter;
	RAnalFunctionAssumption *assumption;
	r_list_foreach (assumptions, iter, assumption) {
		if (!assumption_payload_emit (pj, assumption)) {
			pj_free (pj);
			return NULL;
		}
	}
	pj_end (pj);
	return pj_drain (pj);
}

R_API void r_anal_function_context_free(RAnalFcnContext *ctx) {
	if (!ctx) {
		return;
	}
	r_anal_function_signature_free (ctx->signature);
	r_list_free (ctx->reg_args);
	r_list_free (ctx->fcn_slots);
	r_list_free (ctx->assumptions);
	free (ctx->assumptions_json);
	free (ctx);
}

R_API ut64 r_anal_function_dirty_epoch(const RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	return fcn->dirty_epoch;
}

R_API ut64 r_anal_function_bump_dirty_epoch(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	fcn->dirty_epoch++;
	if (!fcn->dirty_epoch) {
		fcn->dirty_epoch++;
	}
	fcn->has_changed = true;
	return fcn->dirty_epoch;
}

static ut64 function_context_hash_mix(ut64 hash, ut64 value) {
	hash ^= value + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
	return hash;
}

static ut64 function_context_hash_string(ut64 hash, const char *value) {
	return function_context_hash_mix (hash, R_STR_ISNOTEMPTY (value)? r_str_hash64 (value): 0);
}

R_API ut64 r_anal_function_context_hash(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, 0);
	ut64 hash = 0xcbf29ce484222325ULL;
	hash = function_context_hash_mix (hash, fcn->addr);
	hash = function_context_hash_mix (hash, r_anal_function_linear_size (fcn));
	hash = function_context_hash_mix (hash, r_anal_function_dirty_epoch (fcn));
	hash = function_context_hash_mix (hash, (ut64)fcn->bits);
	hash = function_context_hash_mix (hash, (ut64)fcn->maxstack);
	hash = function_context_hash_string (hash, fcn->name);
	hash = function_context_hash_string (hash, fcn->callconv);
	hash = function_context_hash_string (hash, fcn->assumptions_json);
	hash = function_context_hash_mix (hash, r_anal_types_context_hash (anal));
	RAnalVar **it;
	R_VEC_FOREACH (&fcn->vars, it) {
		RAnalVar *var = *it;
		if (!var) {
			continue;
		}
		hash = function_context_hash_string (hash, var->name);
		hash = function_context_hash_string (hash, var->type);
		hash = function_context_hash_string (hash, var->regname);
		hash = function_context_hash_mix (hash, (ut64)(ut8)var->kind);
		hash = function_context_hash_mix (hash, (ut64)(st64)var->delta);
		hash = function_context_hash_mix (hash, var->isarg? 1: 0);
	}
	return hash;
}

R_API char *r_anal_function_get_assumptions_json(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	return strdup (R_STR_ISNOTEMPTY (fcn->assumptions_json)? fcn->assumptions_json: "[]");
}

R_API RList *r_anal_function_list_assumptions(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	RList *list = r_list_newf ((RListFree)r_anal_function_assumption_free);
	if (!list) {
		return NULL;
	}
	const char *json = R_STR_ISNOTEMPTY (fcn->assumptions_json)? fcn->assumptions_json: "[]";
	RJson *parsed = r_json_parsedup (json);
	if (!parsed || parsed->type != R_JSON_ARRAY) {
		r_json_free (parsed);
		r_list_free (list);
		return NULL;
	}
	const RJson *child;
	for (child = parsed->children.first; child; child = child->next) {
		RAnalFunctionAssumption *assumption = assumption_new_from_json (child);
		if (!assumption || !r_list_append (list, assumption)) {
			r_anal_function_assumption_free (assumption);
			r_json_free (parsed);
			r_list_free (list);
			return NULL;
		}
	}
	r_json_free (parsed);
	return list;
}

R_API RAnalFunctionAssumption *r_anal_function_get_assumption(RAnal *anal, RAnalFunction *fcn, const char *kind, const char *target) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && R_STR_ISNOTEMPTY (kind), NULL);
	RList *list = r_anal_function_list_assumptions (anal, fcn);
	if (!list) {
		return NULL;
	}
	RListIter *iter;
	RAnalFunctionAssumption *assumption;
	RAnalFunctionAssumption *result = NULL;
	r_list_foreach (list, iter, assumption) {
		if (assumption_same_key (assumption, kind, target)) {
			result = assumption_clone (assumption);
			break;
		}
	}
	r_list_free (list);
	return result;
}

R_API bool r_anal_function_set_assumptions(RAnal *anal, RAnalFunction *fcn, RList *assumptions) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && assumptions, false);
	char *json = assumptions_list_to_json (assumptions);
	if (!json) {
		return false;
	}
	bool ok = r_anal_function_set_assumptions_json (anal, fcn, json);
	free (json);
	return ok;
}

R_API bool r_anal_function_set_assumption(RAnal *anal, RAnalFunction *fcn, const RAnalFunctionAssumption *assumption) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && assumption && R_STR_ISNOTEMPTY (assumption->kind), false);
	RList *current = r_anal_function_list_assumptions (anal, fcn);
	RList *next = r_list_newf ((RListFree)r_anal_function_assumption_free);
	if (!current || !next) {
		r_list_free (current);
		r_list_free (next);
		return false;
	}
	RListIter *iter;
	RAnalFunctionAssumption *item;
	r_list_foreach (current, iter, item) {
		if (assumption_same_key (item, assumption->kind, assumption->target)) {
			continue;
		}
		RAnalFunctionAssumption *clone = assumption_clone (item);
		if (!clone || !r_list_append (next, clone)) {
			r_anal_function_assumption_free (clone);
			r_list_free (current);
			r_list_free (next);
			return false;
		}
	}
	RAnalFunctionAssumption *clone = assumption_clone (assumption);
	if (!clone || !r_list_append (next, clone)) {
		r_anal_function_assumption_free (clone);
		r_list_free (current);
		r_list_free (next);
		return false;
	}
	bool ok = r_anal_function_set_assumptions (anal, fcn, next);
	r_list_free (current);
	r_list_free (next);
	return ok;
}

R_API bool r_anal_function_delete_assumption(RAnal *anal, RAnalFunction *fcn, const char *kind, const char *target) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && R_STR_ISNOTEMPTY (kind), false);
	RList *current = r_anal_function_list_assumptions (anal, fcn);
	RList *next = r_list_newf ((RListFree)r_anal_function_assumption_free);
	if (!current || !next) {
		r_list_free (current);
		r_list_free (next);
		return false;
	}
	bool removed = false;
	RListIter *iter;
	RAnalFunctionAssumption *item;
	r_list_foreach (current, iter, item) {
		if (assumption_same_key (item, kind, target)) {
			removed = true;
			continue;
		}
		RAnalFunctionAssumption *clone = assumption_clone (item);
		if (!clone || !r_list_append (next, clone)) {
			r_anal_function_assumption_free (clone);
			r_list_free (current);
			r_list_free (next);
			return false;
		}
	}
	bool ok = true;
	if (removed) {
		ok = r_anal_function_set_assumptions (anal, fcn, next);
	}
	r_list_free (current);
	r_list_free (next);
	return ok;
}

R_API bool r_anal_function_set_assumptions_json(RAnal *anal, RAnalFunction *fcn, const char *json) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && json, false);
	char *trimmed = r_str_trim_dup (json);
	if (!trimmed) {
		return false;
	}
	if (R_STR_ISEMPTY (trimmed)) {
		free (trimmed);
		trimmed = strdup ("[]");
		if (!trimmed) {
			return false;
		}
	}
	RJson *parsed = r_json_parsedup (trimmed);
	if (!parsed || parsed->type != R_JSON_ARRAY) {
		r_json_free (parsed);
		free (trimmed);
		return false;
	}
	const RJson *child;
	for (child = parsed->children.first; child; child = child->next) {
		RAnalFunctionAssumption *assumption = assumption_new_from_json (child);
		if (!assumption) {
			r_json_free (parsed);
			free (trimmed);
			return false;
		}
		r_anal_function_assumption_free (assumption);
	}
	r_json_free (parsed);
	free (fcn->assumptions_json);
	fcn->assumptions_json = trimmed;
	r_anal_function_bump_dirty_epoch (fcn);
	return true;
}

R_API bool r_anal_function_clear_assumptions(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, false);
	R_FREE (fcn->assumptions_json);
	r_anal_function_bump_dirty_epoch (fcn);
	return true;
}

R_API bool r_anal_function_set_callconv(RAnal *anal, RAnalFunction *fcn, const char *callconv) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && R_STR_ISNOTEMPTY (callconv), false);
	if (!r_anal_cc_exist (anal, callconv)) {
		return false;
	}
	const char *pooled = r_str_constpool_get (&anal->constpool, callconv);
	if (!pooled) {
		return false;
	}
	if (fcn->callconv && !strcmp (fcn->callconv, pooled)) {
		return true;
	}
	fcn->callconv = pooled;
	r_anal_function_bump_dirty_epoch (fcn);
	return true;
}

R_API bool r_anal_function_set_signature_string(RAnal *anal, RAnalFunction *fcn, const char *signature) {
	R_RETURN_VAL_IF_FAIL (anal && fcn && R_STR_ISNOTEMPTY (signature), false);
	if (!r_anal_str_to_fcn (anal, fcn, signature)) {
		return false;
	}
	r_anal_function_bump_dirty_epoch (fcn);
	return true;
}

static bool r_anal_apply_one_mutation(RAnal *anal, const RAnalMutation *mutation) {
	R_RETURN_VAL_IF_FAIL (anal && mutation, false);
	switch (mutation->kind) {
	case R_ANAL_MUTATION_SIGNATURE:
		if (mutation->signature) {
			return r_anal_function_set_signature (anal, mutation->fcn, mutation->signature);
		}
		return r_anal_function_set_signature_string (anal, mutation->fcn, mutation->signature_string);
	case R_ANAL_MUTATION_CALLCONV:
		return r_anal_function_set_callconv (anal, mutation->fcn, mutation->callconv);
	case R_ANAL_MUTATION_VAR:
		return mutation->fcn && mutation->name && mutation->size <= INT_MAX
			&& r_anal_function_set_var (mutation->fcn, mutation->delta, mutation->var_kind,
				mutation->type, (int)mutation->size, mutation->is_arg, mutation->name);
	case R_ANAL_MUTATION_VAR_RENAME: {
		RAnalVar *var = mutation->var;
		if (!var && mutation->fcn && R_STR_ISNOTEMPTY (mutation->old_name)) {
			var = r_anal_function_get_var_byname (mutation->fcn, mutation->old_name);
		}
		return var && R_STR_ISNOTEMPTY (mutation->name)
			&& r_anal_var_rename (anal, var, mutation->name);
	}
	case R_ANAL_MUTATION_VAR_TYPE: {
		RAnalVar *var = mutation->var;
		if (!var && mutation->fcn && R_STR_ISNOTEMPTY (mutation->old_name)) {
			var = r_anal_function_get_var_byname (mutation->fcn, mutation->old_name);
		}
		if (!var || R_STR_ISEMPTY (mutation->type)) {
			return false;
		}
		r_anal_var_set_type (anal, var, mutation->type);
		return true;
	}
	case R_ANAL_MUTATION_XREF:
		return r_anal_xrefs_setf (anal, mutation->fcn, mutation->from, mutation->to, mutation->ref_type);
	case R_ANAL_MUTATION_COMMENT:
		return R_STR_ISNOTEMPTY (mutation->text)
			&& r_meta_set_string (anal, R_META_TYPE_COMMENT, mutation->addr, mutation->text);
	case R_ANAL_MUTATION_FLAG:
		return anal->flb.f && anal->flb.set && R_STR_ISNOTEMPTY (mutation->name) && mutation->size <= UT32_MAX
			&& anal->flb.set (anal->flb.f, mutation->name, mutation->addr,
				mutation->size? (ut32)mutation->size: 1);
	case R_ANAL_MUTATION_TYPE_DECL: {
		char *errmsg = NULL;
		if (R_STR_ISEMPTY (mutation->text)) {
			return false;
		}
		bool ok = r_anal_import_c_decls (anal, mutation->text, &errmsg);
		free (errmsg);
		return ok;
	}
	case R_ANAL_MUTATION_TYPE_LINK:
		if (!anal->sdb_types || R_STR_ISEMPTY (mutation->type) || !mutation->addr) {
			return false;
		}
		return r_anal_types_set_link (anal, mutation->type, mutation->addr)
			|| r_anal_types_set_link_offset (anal, mutation->type, mutation->addr);
	default:
		return false;
	}
}

R_API bool r_anal_apply_mutations(RAnal *anal, const RAnalMutation *mutations, size_t mutation_count, RAnalMutationResult *result) {
	size_t i;
	RAnalMutationResult local = {0};

	R_RETURN_VAL_IF_FAIL (anal && (mutations || !mutation_count), false);
	for (i = 0; i < mutation_count; i++) {
		local.attempted++;
		if (r_anal_apply_one_mutation (anal, &mutations[i])) {
			local.applied++;
		} else {
			local.failed++;
		}
	}
	if (result) {
		*result = local;
	}
	return local.failed == 0;
}

R_API RAnalFcnContext *r_anal_function_context_collect(RAnal *anal, RAnalFunction *fcn) {
	RAnalFcnContext *ctx;
	RAnalFcnVarsCache cache = {0};

	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	r_anal_types_ensure_loaded (anal);

	ctx = R_NEW0 (RAnalFcnContext);
	ctx->signature = fcn_context_collect_signature (fcn);
	ctx->reg_args = r_list_newf ((RListFree)fcn_context_reg_arg_free);
	ctx->fcn_slots = r_list_newf ((RListFree)fcn_context_slot_free);
	ctx->assumptions = r_anal_function_list_assumptions (anal, fcn);
	ctx->assumptions_json = strdup (R_STR_ISNOTEMPTY (fcn->assumptions_json)? fcn->assumptions_json: "[]");
	if (!ctx->reg_args || !ctx->fcn_slots || !ctx->assumptions || !ctx->assumptions_json) {
		r_anal_function_context_free (ctx);
		return NULL;
	}

	r_anal_function_vars_cache_init (anal, &cache, fcn);
	RAnalVar **it;
	R_VEC_FOREACH (cache.rvars, it) {
		RAnalVar *var = *it;
		if (!var || !var->isarg || var->kind != R_ANAL_VAR_KIND_REG) {
			continue;
		}
		RAnalFcnRegArg *arg = fcn_context_collect_reg_arg (anal, ctx, var);
		if (!arg) {
			r_anal_function_vars_cache_fini (&cache);
			r_anal_function_context_free (ctx);
			return NULL;
		}
		r_list_append (ctx->reg_args, arg);
	}

	R_VEC_FOREACH (cache.bvars, it) {
		RAnalVar *var = *it;
		if (!var) {
			continue;
		}
		RAnalVar *home_source = fcn_context_find_register_home_source (cache.rvars, var);
		RAnalFcnSlot *slot = fcn_context_collect_slot (anal, ctx, fcn, var, home_source);
		if (!slot) {
			r_anal_function_vars_cache_fini (&cache);
			r_anal_function_context_free (ctx);
			return NULL;
		}
		r_list_append (ctx->fcn_slots, slot);
	}
	R_VEC_FOREACH (cache.svars, it) {
		RAnalVar *var = *it;
		if (!var) {
			continue;
		}
		RAnalVar *home_source = fcn_context_find_register_home_source (cache.rvars, var);
		RAnalFcnSlot *slot = fcn_context_collect_slot (anal, ctx, fcn, var, home_source);
		if (!slot) {
			r_anal_function_vars_cache_fini (&cache);
			r_anal_function_context_free (ctx);
			return NULL;
		}
		r_list_append (ctx->fcn_slots, slot);
	}
	r_anal_function_vars_cache_fini (&cache);
	return ctx;
}

R_API RGraph *r_anal_function_get_graph(RAnalFunction *fcn, RGraphNode **node_ptr, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (fcn && fcn->bbs && r_list_length (fcn->bbs), NULL);
	HtUP *nodes = ht_up_new0 ();
	RGraph *g = r_graph_new ();
	if (node_ptr) {
		*node_ptr = NULL;
	}
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		RGraphNode *node = r_graph_add_node (g, bb);
		if (node_ptr && !node_ptr[0] && bb->addr <= addr && addr < (bb->addr + bb->size)) {
			*node_ptr = node;
		}
		ht_up_insert (nodes, bb->addr, node);
	}
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->jump == UT64_MAX  &&
			(!bb->switch_op || !bb->switch_op->cases || !r_list_length (bb->switch_op->cases))) {
			continue;
		}
		RGraphNode *node = (RGraphNode *)ht_up_find (nodes, bb->addr, NULL);
		if (bb->jump != UT64_MAX) {
			RGraphNode *_node = NULL;
			_node = (RGraphNode *)ht_up_find (nodes, bb->jump, NULL);
			if (!_node) {
				R_LOG_ERROR ("Broken fcn");
				ht_up_free (nodes);
				r_graph_free (g);
				if (node_ptr) {
					*node_ptr = NULL;
				}
				return NULL;
			}
			r_graph_add_edge (g, node, _node);
		}
		if (bb->fail != UT64_MAX) {
			RGraphNode *_node = NULL;
			_node = (RGraphNode *)ht_up_find (nodes, bb->fail, NULL);
			if (!_node) {
				R_LOG_ERROR ("Broken fcn");
				ht_up_free (nodes);
				r_graph_free (g);
				if (node_ptr) {
					*node_ptr = NULL;
				}
				return NULL;
			}
			r_graph_add_edge (g, node, _node);
		}
		if (bb->switch_op && bb->switch_op->cases && r_list_length (bb->switch_op->cases)) {
			RListIter *ator;
			RAnalCaseOp *co;
			r_list_foreach (bb->switch_op->cases, ator, co) {
				RGraphNode *_node = NULL;
				_node = (RGraphNode *)ht_up_find (nodes, co->addr, NULL);
				if (!_node) {
					R_LOG_ERROR ("Broken fcn");
					ht_up_free (nodes);
					r_graph_free (g);
					if (node_ptr) {
						*node_ptr = NULL;
					}
					return NULL;
				}
				r_graph_add_edge (g, node, _node);
			}
		}
	}
	ht_up_free (nodes);
	return g;
}

R_API bool r_anal_function_switches_foreach(RAnalFunction *fcn, RAnalFunctionSwitchCb cb, void *user) {
	R_RETURN_VAL_IF_FAIL (fcn && cb, false);
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (!bb || !bb->switch_op) {
			continue;
		}
		if (!cb (fcn, bb, bb->switch_op, user)) {
			return false;
		}
	}
	return true;
}
