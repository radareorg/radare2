/* radare - LGPL - Copyright 2019-2025 - pancake, thestr4ng3r */

#include <r_anal_priv.h>
#include <r_util/r_json.h>
#include "function_snapshot.h"

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
	fcn->meta.stack_pop = R_ANAL_CC_STACK_POP_UNKNOWN;
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
	R_RETURN_VAL_IF_FAIL (anal && fcn && fcn->anal == anal, false);
	if (r_anal_get_function_at (anal, fcn->addr) != fcn) {
		return false;
	}
	if (anal->cb.on_fcn_delete
			&& anal->cb.on_fcn_delete (anal, anal->user, fcn)
				== R_ANAL_FUNCTION_DELETE_REFUSE) {
		return false;
	}
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
	r_anal_function_bump_dirty_epoch (fcn);
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
		r_anal_function_bump_dirty_epoch (fcn);
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

static void fcn_context_callee_free(RAnalFcnCallee *callee) {
	if (!callee) {
		return;
	}
	free (callee->name);
	r_anal_function_signature_free (callee->signature);
	free (callee);
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

static RRegItem *fcn_context_var_regitem(RAnal *anal, const RAnalVar *var) {
	if (R_STR_ISNOTEMPTY (var->regname)) {
		return r_reg_get (anal->reg, var->regname, -1);
	}
	if (var->kind == R_ANAL_VAR_KIND_REG) {
		return r_reg_index_get (anal->reg, R_ABS (var->delta));
	}
	return NULL;
}

static bool fcn_context_stack_offset(const RAnalFunction *fcn, const RAnalVar *var, st64 *offset) {
	R_RETURN_VAL_IF_FAIL (fcn && var && offset, false);
	switch (var->kind) {
	case R_ANAL_VAR_KIND_BPV:
		return !r_add_overflow ((st64)var->delta, fcn->bp_off, offset);
	case R_ANAL_VAR_KIND_SPV:
		*offset = var->delta;
		return true;
	default:
		*offset = var->delta;
		return false;
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

static int fcn_context_raw_register_arg_index(RAnal *anal, RAnalFunction *fcn, const RAnalVar *var) {
	if (!var || !var->isarg || var->kind != R_ANAL_VAR_KIND_REG
		|| R_STR_ISEMPTY (fcn->callconv)) {
		return -1;
	}
	RRegItem *reg = fcn_context_var_regitem (anal, var);
	if (!reg) {
		return -1;
	}
	const int maximum = r_anal_cc_max_arg (anal, fcn->callconv);
	int index;
	for (index = 0; index < maximum; index++) {
		const char *location = r_anal_cc_argloc (
			anal, fcn->callconv, index, 0, 0);
		if (location && r_anal_cc_location_uses (anal, location, reg->name)) {
			r_unref (reg);
			return index;
		}
	}
	r_unref (reg);
	return -1;
}

static int fcn_context_register_arg_index(RAnal *anal, RAnalFunction *fcn, RVecAnalVarPtr *rvars, RAnalVar *target) {
	const int raw_index = fcn_context_raw_register_arg_index (anal, fcn, target);
	if (raw_index < 0 || !rvars) {
		return -1;
	}
	int dense_index = 0;
	bool found = false;
	RAnalVar **it;
	R_VEC_FOREACH (rvars, it) {
		RAnalVar *var = *it;
		const int other_index = fcn_context_raw_register_arg_index (anal, fcn, var);
		if (var == target) {
			found = true;
			continue;
		}
		if (other_index >= 0 && (other_index < raw_index
				|| (other_index == raw_index && !found))) {
			dense_index++;
		}
	}
	return found? dense_index: -1;
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

static RAnalFcnRegArg *fcn_context_collect_reg_arg(RAnal *anal, const RAnalFcnContext *ctx, RAnalVar *var, int arg_index) {
	R_RETURN_VAL_IF_FAIL (anal && ctx && var, NULL);
	RAnalFcnRegArg *arg = R_NEW0 (RAnalFcnRegArg);
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

static RAnalFcnSlot *fcn_context_collect_slot(RAnal *anal, const RAnalFcnContext *ctx, RAnalFunction *fcn, RAnalVar *var, RAnalVar *home_source, int arg_index) {
	const RAnalFunctionParam *signature_param = NULL;

	R_RETURN_VAL_IF_FAIL (anal && ctx && fcn && var, NULL);
	RAnalFcnSlot *slot = R_NEW0 (RAnalFcnSlot);
	if (R_STR_ISNOTEMPTY (var->name)) {
		slot->name = strdup (var->name);
	}
	if (R_STR_ISNOTEMPTY (var->type)) {
		slot->type = strdup (var->type);
	}
	switch (var->kind) {
	case R_ANAL_VAR_KIND_BPV:
		slot->base = R_ANAL_FCN_BASE_BP;
		break;
	case R_ANAL_VAR_KIND_SPV:
		slot->base = R_ANAL_FCN_BASE_SP;
		break;
	default:
		slot->base = R_ANAL_FCN_BASE_NAMED;
		break;
	}
	const RRegAlias base_alias = slot->base == R_ANAL_FCN_BASE_BP
		? R_REG_ALIAS_BP: R_REG_ALIAS_SP;
	const char *base_name = slot->base == R_ANAL_FCN_BASE_NAMED
		? NULL: r_reg_alias_getname (anal->reg, base_alias);
	if (R_STR_ISNOTEMPTY (base_name)) {
		RRegItem *base_reg = r_reg_get (anal->reg, base_name, -1);
		if (base_reg && base_reg->offset >= 0 && !(base_reg->offset % 8)
			&& base_reg->size > 0
			&& !(base_reg->size % 8) && base_reg->size / 8 <= UT32_MAX) {
			slot->base_name = strdup (base_name);
			if (!slot->base_name) {
				r_unref (base_reg);
				fcn_context_slot_free (slot);
				return NULL;
			}
			slot->base_offset = (ut64)(base_reg->offset / 8);
			slot->base_size = (ut32)(base_reg->size / 8);
		}
		r_unref (base_reg);
	}
	slot->offset_valid = fcn_context_stack_offset (fcn, var, &slot->offset);
	slot->role = fcn_context_classify_slot (var, home_source);

	if (home_source) {
		signature_param = (ctx->signature && arg_index >= 0)? r_list_get_n (ctx->signature->params, arg_index): NULL;
		slot->arg_index = arg_index;
		RRegItem *home_reg = fcn_context_var_regitem (anal, home_source);
		if (home_reg && home_reg->offset >= 0 && !(home_reg->offset % 8)
			&& home_reg->size > 0
			&& !(home_reg->size % 8) && home_reg->size / 8 <= UT32_MAX) {
			slot->home_reg = strdup (r_str_get (home_reg->name));
			if (!slot->home_reg) {
				r_unref (home_reg);
				fcn_context_slot_free (slot);
				return NULL;
			}
			slot->home_reg_offset = (ut64)(home_reg->offset / 8);
			slot->home_reg_size = (ut32)(home_reg->size / 8);
		}
		r_unref (home_reg);
		if (signature_param && R_STR_ISNOTEMPTY (signature_param->name)) {
			slot->arg_name = strdup (signature_param->name);
		} else if (R_STR_ISNOTEMPTY (home_source->name)) {
			slot->arg_name = strdup (home_source->name);
		}
		if (!slot->type && signature_param && R_STR_ISNOTEMPTY (signature_param->type)) {
			slot->type = strdup (signature_param->type);
		}
	} else if (var->isarg) {
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
	if (R_STR_ISNOTEMPTY (slot->type)) {
		ut64 bits = r_anal_type_bitsize (anal, slot->type);
		if (bits && !(bits % 8) && bits / 8 <= UT32_MAX) {
			slot->size = (ut32)(bits / 8);
		}
	}

	if ((R_STR_ISNOTEMPTY (var->name) && !slot->name)
		|| (R_STR_ISNOTEMPTY (var->type) && !slot->type)) {
		fcn_context_slot_free (slot);
		return NULL;
	}
	return slot;
}

static int fcn_context_reg_arg_compare(const void *left, const void *right) {
	const RAnalFcnRegArg *a = left;
	const RAnalFcnRegArg *b = right;
	if (a->arg_index != b->arg_index) {
		return a->arg_index < b->arg_index? -1: 1;
	}
	return strcmp (r_str_get (a->reg), r_str_get (b->reg));
}

static RAnalFunctionSignature *fcn_context_collect_signature(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
	RAnalFunctionSignature *signature = r_anal_function_get_signature_current (fcn);
	const char *fcncc = fcn->callconv;
	if (signature || (!R_STR_ISNOTEMPTY (fcncc) && !fcn->is_noreturn)) {
		return signature;
	}
	signature = R_NEW0 (RAnalFunctionSignature);
	signature->params = r_list_new ();
	if (!signature->params) {
		r_anal_function_signature_free (signature);
		return NULL;
	}
	if (R_STR_ISNOTEMPTY (fcncc)) {
		signature->callconv = strdup (fcncc);
		if (!signature->callconv) {
			r_anal_function_signature_free (signature);
			return NULL;
		}
	}
	signature->noreturn = fcn->is_noreturn;
	return signature;
}

static bool fcn_context_callee_symbol_is_imported(RAnal *anal, ut64 addr) {
	RBinSymbol *sym;
	if (!anal || !anal->binb.bin || !anal->binb.get_symbol_at) {
		return false;
	}
	sym = anal->binb.get_symbol_at (anal->binb.bin, addr);
	return sym && sym->is_imported;
}

static char *fcn_context_callee_symbol_name(RAnal *anal, ut64 addr) {
	RBinSymbol *sym;
	const char *name;
	if (!anal || !anal->binb.bin || !anal->binb.get_symbol_at) {
		return NULL;
	}
	sym = anal->binb.get_symbol_at (anal->binb.bin, addr);
	if (!sym || !sym->name) {
		return NULL;
	}
	name = sym->name->name;
	if (!name) {
		name = sym->name->oname;
	}
	if (!name) {
		name = sym->name->fname;
	}
	return R_STR_ISNOTEMPTY (name)? strdup (name): NULL;
}

static RAnalFcnCalleeLinkage fcn_context_resolve_callee_linkage(RAnal *anal, ut64 addr) {
	RAnalFunction *callee_fcn;
	R_RETURN_VAL_IF_FAIL (anal, R_ANAL_FCN_CALLEE_UNKNOWN);
	if (fcn_context_callee_symbol_is_imported (anal, addr)) {
		return R_ANAL_FCN_CALLEE_IMPORTED;
	}
	callee_fcn = r_anal_get_fcn_in (anal, addr, R_ANAL_FCN_TYPE_ANY);
	if (!callee_fcn) {
		return R_ANAL_FCN_CALLEE_UNKNOWN;
	}
	if (callee_fcn->type & R_ANAL_FCN_TYPE_IMP) {
		return R_ANAL_FCN_CALLEE_IMPORTED;
	}
	return R_ANAL_FCN_CALLEE_INTERNAL;
}

static char *fcn_context_resolve_callee_name(RAnal *anal, ut64 addr) {
	RAnalFunction *callee_fcn;
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	callee_fcn = r_anal_get_fcn_in (anal, addr, R_ANAL_FCN_TYPE_ANY);
	if (callee_fcn && R_STR_ISNOTEMPTY (callee_fcn->name)) {
		return strdup (callee_fcn->name);
	}
	return fcn_context_callee_symbol_name (anal, addr);
}

static RAnalFunctionSignature *fcn_context_resolve_callee_signature(RAnal *anal, ut64 addr) {
	RAnalFunction *callee_fcn;
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	callee_fcn = r_anal_get_fcn_in (anal, addr, R_ANAL_FCN_TYPE_ANY);
	return callee_fcn? r_anal_function_get_signature_current (callee_fcn): NULL;
}

static bool fcn_context_has_callee(RList *callees, ut64 call_addr, ut64 addr) {
	RListIter *iter;
	RAnalFcnCallee *callee;
	r_list_foreach (callees, iter, callee) {
		if (callee && callee->call_addr == call_addr && callee->addr == addr) {
			return true;
		}
	}
	return false;
}

static bool fcn_context_append_callee(RAnal *anal, RList *callees, ut64 call_addr, ut64 addr) {
	RAnalFcnCallee *callee;
	R_RETURN_VAL_IF_FAIL (anal && callees, false);
	if (addr == UT64_MAX || fcn_context_has_callee (callees, call_addr, addr)) {
		return true;
	}
	callee = R_NEW0 (RAnalFcnCallee);
	if (!callee) {
		return false;
	}
	callee->call_addr = call_addr;
	callee->addr = addr;
	callee->name = fcn_context_resolve_callee_name (anal, addr);
	callee->linkage = fcn_context_resolve_callee_linkage (anal, addr);
	callee->signature = fcn_context_resolve_callee_signature (anal, addr);
	r_list_append (callees, callee);
	return true;
}

static int function_image_target_classify(const RAnalFunctionImageSnapshot *image, ut64 target);

static RList *fcn_context_collect_callees(RAnal *anal, const RAnalFunctionImageSnapshot *image) {
	RVecAnalRef *refs;
	RList *callees;
	size_t i, len;

	R_RETURN_VAL_IF_FAIL (anal && image, NULL);
	callees = r_list_newf ((RListFree)fcn_context_callee_free);
	if (!callees) {
		return NULL;
	}
	refs = r_anal_refs_get (anal, UT64_MAX);
	if (refs) {
		len = RVecAnalRef_length (refs);
		for (i = 0; i < len; i++) {
			RAnalRef *ref = RVecAnalRef_at (refs, i);
			if (!ref || R_ANAL_REF_TYPE_MASK (ref->type) != R_ANAL_REF_TYPE_CALL
				|| function_image_target_classify (image, ref->at) == 0) {
				continue;
			}
			if (!fcn_context_append_callee (anal, callees, ref->at, ref->addr)) {
				RVecAnalRef_free (refs);
				r_list_free (callees);
				return NULL;
			}
		}
		RVecAnalRef_free (refs);
	}
	return callees;
}

static void function_image_snapshot_fini(RAnalFunctionImageSnapshot *image) {
	if (!image) {
		return;
	}
	size_t i;
	for (i = 0; i < image->num_blocks; i++) {
		free (image->blocks[i].bytes);
		free (image->blocks[i].successors);
	}
	free (image->blocks);
	free (image->external_exits);
	{
		size_t literal;
		for (literal = 0; literal < image->num_string_literals; literal++) {
			free (image->string_literals[literal].text);
		}
		free (image->string_literals);
		size_t table;
		for (table = 0; table < image->num_code_pointer_tables; table++) {
			free (image->code_pointer_tables[table].targets);
		}
		free (image->code_pointer_tables);
	}
	memset (image, 0, sizeof (*image));
}

static int snapshot_successor_compare(const void *left, const void *right) {
	const RAnalSnapshotSuccessor *a = left;
	const RAnalSnapshotSuccessor *b = right;
	if (a->kind != b->kind) {
		return a->kind < b->kind? -1: 1;
	}
	if (a->case_value != b->case_value) {
		return a->case_value < b->case_value? -1: 1;
	}
	if (a->target_addr != b->target_addr) {
		return a->target_addr < b->target_addr? -1: 1;
	}
	return 0;
}

static int snapshot_block_compare(const void *left, const void *right) {
	const RAnalSnapshotBlock *a = left;
	const RAnalSnapshotBlock *b = right;
	if (a->addr != b->addr) {
		return a->addr < b->addr? -1: 1;
	}
	if (a->size != b->size) {
		return a->size < b->size? -1: 1;
	}
	return 0;
}

static int snapshot_addr_compare(const void *left, const void *right) {
	const ut64 a = *(const ut64 *)left;
	const ut64 b = *(const ut64 *)right;
	return a == b? 0: a < b? -1: 1;
}

typedef enum {
	SNAPSHOT_TERMINAL_SEQUENTIAL,
	SNAPSHOT_TERMINAL_DIRECT,
	// The block ends by transferring control somewhere the analysis did not
	// resolve, so any successor recorded for it is not supported by the
	// instruction.
	SNAPSHOT_TERMINAL_UNKNOWN_EXIT,
	SNAPSHOT_TERMINAL_REJECT,
} SnapshotTerminalFlow;

static SnapshotTerminalFlow snapshot_terminal_flow(const RAnalOp *op, ut64 target) {
	const int type = op->type & R_ANAL_OP_TYPE_MASK;
	if (op->type == R_ANAL_OP_TYPE_JMP) {
		return op->jump == target
			? SNAPSHOT_TERMINAL_DIRECT: SNAPSHOT_TERMINAL_REJECT;
	}
	// An unconditional transfer to an address the analysis could not resolve
	// exits the block without naming where it goes, so a recorded successor is
	// a placeholder rather than something the instruction supports.
	if (!(op->type & R_ANAL_OP_TYPE_COND)
		&& (type == R_ANAL_OP_TYPE_UJMP
			|| type == R_ANAL_OP_TYPE_TRAP
			|| type == R_ANAL_OP_TYPE_ILL
			|| type == R_ANAL_OP_TYPE_UNK
			|| type == R_ANAL_OP_TYPE_SWI)) {
		return SNAPSHOT_TERMINAL_UNKNOWN_EXIT;
	}
	switch (type) {
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_CJMP:
	case R_ANAL_OP_TYPE_UCJMP:
	case R_ANAL_OP_TYPE_RET:
	case R_ANAL_OP_TYPE_CRET:
	case R_ANAL_OP_TYPE_TRAP:
	case R_ANAL_OP_TYPE_ILL:
	case R_ANAL_OP_TYPE_UNK:
	case R_ANAL_OP_TYPE_SWI:
		return SNAPSHOT_TERMINAL_REJECT;
	default:
		return op->eob? SNAPSHOT_TERMINAL_REJECT: SNAPSHOT_TERMINAL_SEQUENTIAL;
	}
}

static bool snapshot_block_sequential_jump_normalize(RAnal *anal, RAnalSnapshotBlock *block) {
	R_RETURN_VAL_IF_FAIL (anal && block, false);
	if (block->switch_addr != UT64_MAX || block->num_successors != 1) {
		return true;
	}
	RAnalSnapshotSuccessor *successor = block->successors;
	if (successor->kind != R_ANAL_SNAPSHOT_SUCCESSOR_DIRECT
		|| successor->target_addr != block->addr + block->size) {
		return true;
	}
	RArchSession *live = R_UNWRAP3 (anal, arch, session);
	if (!live || !live->config || !live->plugin) {
		return false;
	}
	RArchConfig *config = r_arch_config_clone (live->config);
	RArchSession *decoder = config
		? r_arch_session (anal->arch, config, live->plugin): NULL;
	r_arch_config_free (config);
	if (!decoder) {
		return false;
	}
	SnapshotTerminalFlow delayed_flow = SNAPSHOT_TERMINAL_SEQUENTIAL;
	int delay_remaining = 0;
	size_t offset = 0;
	while (offset < block->size) {
		RAnalOp op = {0};
		const size_t remaining = (size_t)block->size - offset;
		const ut64 addr = block->addr + offset;
		const int codealign = decoder->config->codealign;
		const RAnalOpMask mask = R_ARCH_OP_MASK_BASIC
			| (anal->opt.stateful? R_ARCH_OP_MASK_STATEFUL: 0);
		r_anal_op_init (&op);
		const bool decoded = (codealign <= 1 || !(addr % codealign))
			&& r_anal_op_set_bytes (&op, addr, block->bytes + offset, (int)remaining)
			&& r_arch_session_decode (decoder, &op, mask);
		const int length = op.size;
		if (!decoded || length < 1 || (size_t)length > remaining) {
			r_anal_op_fini (&op);
			goto fail;
		}
		offset += (size_t)length;
		const SnapshotTerminalFlow flow = snapshot_terminal_flow (
			&op, successor->target_addr);
		if (delay_remaining) {
			if (op.delay > 0 || flow != SNAPSHOT_TERMINAL_SEQUENTIAL) {
				r_anal_op_fini (&op);
				goto fail;
			}
			delay_remaining--;
			if (!delay_remaining && offset != block->size) {
				r_anal_op_fini (&op);
				goto fail;
			}
		} else if (op.delay > 0) {
			if (flow == SNAPSHOT_TERMINAL_SEQUENTIAL || offset == block->size) {
				r_anal_op_fini (&op);
				goto fail;
			}
			delayed_flow = flow;
			delay_remaining = op.delay;
		} else if (flow != SNAPSHOT_TERMINAL_SEQUENTIAL && offset != block->size) {
			r_anal_op_fini (&op);
			goto fail;
		} else if (offset == block->size) {
			delayed_flow = flow;
		}
		r_anal_op_fini (&op);
	}
	if (delay_remaining || delayed_flow == SNAPSHOT_TERMINAL_REJECT) {
		goto fail;
	}
	if (delayed_flow == SNAPSHOT_TERMINAL_UNKNOWN_EXIT) {
		// The recorded edge to the next address is not something this
		// terminator does. Drop it rather than capture a transfer the
		// instruction contradicts, and rather than refuse the whole function
		// over one unresolved branch.
		R_FREE (block->successors);
		block->num_successors = 0;
		r_unref (decoder);
		return true;
	}
	if (delayed_flow == SNAPSHOT_TERMINAL_SEQUENTIAL) {
		successor->kind = R_ANAL_SNAPSHOT_SUCCESSOR_FALLTHROUGH;
	}
	r_unref (decoder);
	return true;

fail:
	r_unref (decoder);
	return false;
}

static bool snapshot_switch_cases_target(const RAnalSwitchOp *switch_op, ut64 addr) {
	RListIter *iter;
	RAnalCaseOp *case_op;
	r_list_foreach (switch_op->cases, iter, case_op) {
		if (case_op && case_op->jump == addr) {
			return true;
		}
	}
	return false;
}

static bool snapshot_block_successors_collect(const RAnalBlock *source, RAnalSnapshotBlock *block, size_t *total_successors, const RAnalFunctionSnapshotLimits *limits) {
	size_t count = 0;
	ut64 default_addr = UT64_MAX;
	bool jump_is_distinct = false;
	if (source->switch_op) {
		const RAnalSwitchOp *switch_op = source->switch_op;
		const int listed_cases = switch_op->cases? r_list_length (switch_op->cases): 0;
		if (listed_cases <= 0) {
			return false;
		}
		// A snapshot describes the graph the function analysis built, not the
		// architecture metadata it was built from, so the block fail edge is the
		// authority for the default target and switch_op->def_val is only a
		// cross-check. A switch with no default is a complete description rather
		// than a missing one, so its absence is not a failure; the two views
		// disagreeing is, because then the block has no single default.
		default_addr = source->fail;
		if (default_addr != UT64_MAX && switch_op->def_val != UT64_MAX
			&& switch_op->def_val != default_addr) {
			return false;
		}
		count = (size_t)listed_cases;
		if (default_addr != UT64_MAX
			&& r_add_overflow_size_t (count, 1, &count)) {
			return false;
		}
		// Some architectures leave the linear flow edge on a dispatch block in
		// addition to the case list. Keep it only when it names a target the
		// case list and the default do not already cover.
		if (source->jump != UT64_MAX && source->jump != default_addr
			&& !snapshot_switch_cases_target (switch_op, source->jump)) {
			jump_is_distinct = true;
			if (r_add_overflow_size_t (count, 1, &count)) {
				return false;
			}
		}
		block->switch_addr = switch_op->jump_addr != UT64_MAX
			? switch_op->jump_addr: switch_op->addr;
		const ut64 block_end = source->addr + source->size;
		if (block->switch_addr < source->addr || block->switch_addr >= block_end) {
			return false;
		}
	} else {
		block->switch_addr = UT64_MAX;
		count = (source->jump != UT64_MAX? 1: 0)
			+ (source->fail != UT64_MAX? 1: 0);
	}
	size_t next_total;
	if (r_add_overflow_size_t (*total_successors, count, &next_total)
		|| next_total > limits->max_function_successors) {
		return false;
	}
	*total_successors = next_total;
	if (!count) {
		return true;
	}
	size_t allocation_size;
	if (r_mul_overflow (count, sizeof (RAnalSnapshotSuccessor), &allocation_size)) {
		return false;
	}
	block->successors = calloc (1, allocation_size);
	if (!block->successors) {
		return false;
	}
	block->num_successors = count;
	if (source->switch_op) {
		RListIter *iter;
		RAnalCaseOp *case_op;
		size_t index = 0;
		r_list_foreach (source->switch_op->cases, iter, case_op) {
			if (!case_op || case_op->jump == UT64_MAX || index >= count) {
				return false;
			}
			block->successors[index++] = (RAnalSnapshotSuccessor) {
				.kind = R_ANAL_SNAPSHOT_SUCCESSOR_SWITCH_CASE,
				.target_addr = case_op->jump,
				.case_value = case_op->value,
			};
		}
		if (default_addr != UT64_MAX) {
			if (index >= count) {
				return false;
			}
			block->successors[index++] = (RAnalSnapshotSuccessor) {
				.kind = R_ANAL_SNAPSHOT_SUCCESSOR_SWITCH_DEFAULT,
				.target_addr = default_addr,
			};
		}
		if (jump_is_distinct) {
			if (index >= count) {
				return false;
			}
			block->successors[index++] = (RAnalSnapshotSuccessor) {
				.kind = R_ANAL_SNAPSHOT_SUCCESSOR_DIRECT,
				.target_addr = source->jump,
			};
		}
		if (index != count) {
			return false;
		}
	} else {
		size_t index = 0;
		if (source->jump != UT64_MAX) {
			block->successors[index++] = (RAnalSnapshotSuccessor) {
				.kind = R_ANAL_SNAPSHOT_SUCCESSOR_DIRECT,
				.target_addr = source->jump,
			};
		}
		if (source->fail != UT64_MAX) {
			block->successors[index++] = (RAnalSnapshotSuccessor) {
				.kind = R_ANAL_SNAPSHOT_SUCCESSOR_FALLTHROUGH,
				.target_addr = source->fail,
			};
		}
	}
	qsort (block->successors, count, sizeof (RAnalSnapshotSuccessor),
		snapshot_successor_compare);
	size_t i;
	for (i = 1; i < count; i++) {
		const RAnalSnapshotSuccessor *previous = &block->successors[i - 1];
		const RAnalSnapshotSuccessor *current = &block->successors[i];
		if (previous->kind == R_ANAL_SNAPSHOT_SUCCESSOR_SWITCH_CASE
			&& current->kind == R_ANAL_SNAPSHOT_SUCCESSOR_SWITCH_CASE
			&& previous->case_value == current->case_value) {
			return false;
		}
	}
	return true;
}

// Returns one for an exact block start, zero outside the image, and -1 for
// an address inside a block which is not a valid basic-block destination.
static int function_image_target_classify(const RAnalFunctionImageSnapshot *image, ut64 target) {
	size_t lower = 0;
	size_t upper = image->num_blocks;
	while (lower < upper) {
		const size_t middle = lower + (upper - lower) / 2;
		if (image->blocks[middle].addr <= target) {
			lower = middle + 1;
		} else {
			upper = middle;
		}
	}
	if (!lower) {
		return 0;
	}
	const RAnalSnapshotBlock *block = &image->blocks[lower - 1];
	if (block->addr == target) {
		return 1;
	}
	return target < block->addr + block->size? -1: 0;
}

#define IMAGE_REFUSE(why) do { refusal = (why); goto fail; } while (0)

/* String literals the function refers to, taken from the `Cs` metadata radare2
 * already keeps. A consumer holding only the snapshot can read the address a
 * constant carries but not what is stored there, so without this a call can be
 * named and still have to spell its argument as a number. */
// A word counts as a code pointer when a function starts there. Anything looser
// -- inside a function, or merely in an executable map -- admits alignment
// padding and offsets into the middle of instructions, and a table that carries
// those is worse than no table at all.
static bool snapshot_addr_starts_function(RAnal *anal, ut64 addr) {
	return addr && addr != UT64_MAX && r_anal_get_function_at (anal, addr) != NULL;
}

#define SNAPSHOT_MAX_CODE_POINTER_TABLES 16
#define SNAPSHOT_MAX_CODE_POINTER_TABLE_ENTRIES 256

// The table is read until it stops looking like one. A run of code pointers
// ends at the first word that does not begin a function, which is where the
// next datum starts; carrying past it would report neighbouring data as
// reachable code.
static bool function_image_code_pointer_table_collect(RAnal *anal,
		RAnalFunctionImageSnapshot *image, ut64 addr, ut32 entry_size) {
	size_t existing;
	for (existing = 0; existing < image->num_code_pointer_tables; existing++) {
		if (image->code_pointer_tables[existing].addr == addr) {
			return true;
		}
	}
	if (image->num_code_pointer_tables >= SNAPSHOT_MAX_CODE_POINTER_TABLES) {
		return true;
	}
	ut64 *targets = NULL;
	size_t num_targets = 0;
	while (num_targets < SNAPSHOT_MAX_CODE_POINTER_TABLE_ENTRIES) {
		ut8 word[8] = {0};
		const ut64 at = addr + (ut64)num_targets * entry_size;
		if (!anal->iob.read_at || !anal->iob.read_at (anal->iob.io, at, word, entry_size)) {
			break;
		}
		const ut64 target = entry_size == 8
			? r_read_le64 (word)
			: (ut64)r_read_le32 (word);
		if (!snapshot_addr_starts_function (anal, target)) {
			break;
		}
		ut64 *grown = realloc (targets, (num_targets + 1) * sizeof (*grown));
		if (!grown) {
			free (targets);
			return false;
		}
		targets = grown;
		targets[num_targets++] = target;
	}
	if (num_targets < 2) {
		// One pointer is a variable holding a function, not a table to index.
		free (targets);
		return true;
	}
	RAnalSnapshotCodePointerTable *grown = realloc (image->code_pointer_tables,
		(image->num_code_pointer_tables + 1) * sizeof (*grown));
	if (!grown) {
		free (targets);
		return false;
	}
	image->code_pointer_tables = grown;
	RAnalSnapshotCodePointerTable *table =
		&image->code_pointer_tables[image->num_code_pointer_tables++];
	table->addr = addr;
	table->entry_size = entry_size;
	table->targets = targets;
	table->num_targets = num_targets;
	return true;
}

static bool function_image_code_pointer_tables_collect(RAnal *anal,
		RAnalFunctionImageSnapshot *image) {
	const ut32 entry_size = anal->config && anal->config->bits == 32? 4: 8;
	size_t index;
	for (index = 0; index < image->num_blocks; index++) {
		const RAnalSnapshotBlock *block = &image->blocks[index];
		ut64 offset;
		for (offset = 0; offset < block->size; offset++) {
			RVecAnalRef *refs = r_anal_xrefs_get_from (anal, block->addr + offset);
			if (!refs) {
				continue;
			}
			RAnalRef *ref;
			R_VEC_FOREACH (refs, ref) {
				const int type = R_ANAL_REF_TYPE_MASK (ref->type);
				if (type != R_ANAL_REF_TYPE_DATA && type != R_ANAL_REF_TYPE_ICOD) {
					continue;
				}
				if (!function_image_code_pointer_table_collect (anal, image, ref->addr, entry_size)) {
					RVecAnalRef_free (refs);
					return false;
				}
			}
			RVecAnalRef_free (refs);
		}
	}
	return true;
}

static bool function_image_string_literals_collect(RAnal *anal,
		RAnalFunctionImageSnapshot *image,
		const RAnalFunctionSnapshotLimits *limits) {
	size_t index;
	for (index = 0; index < image->num_blocks; index++) {
		const RAnalSnapshotBlock *block = &image->blocks[index];
		ut64 offset;
		for (offset = 0; offset < block->size; offset++) {
			RVecAnalRef *refs = r_anal_xrefs_get_from (anal, block->addr + offset);
			if (!refs) {
				continue;
			}
			RAnalRef *ref;
			R_VEC_FOREACH (refs, ref) {
				const char *text = r_meta_get_string (anal, R_META_TYPE_STRING, ref->addr);
				if (!text || !*text) {
					continue;
				}
				size_t existing;
				bool known = false;
				for (existing = 0; existing < image->num_string_literals; existing++) {
					if (image->string_literals[existing].addr == ref->addr) {
						known = true;
						break;
					}
				}
				if (known) {
					continue;
				}
				if (image->num_string_literals >= limits->max_function_successors) {
					RVecAnalRef_free (refs);
					return false;
				}
				RAnalSnapshotStringLiteral *grown = realloc (image->string_literals,
					(image->num_string_literals + 1) * sizeof (*grown));
				if (!grown) {
					RVecAnalRef_free (refs);
					return false;
				}
				image->string_literals = grown;
				RAnalSnapshotStringLiteral *literal =
					&image->string_literals[image->num_string_literals];
				literal->addr = ref->addr;
				literal->text = strdup (text);
				if (!literal->text) {
					RVecAnalRef_free (refs);
					return false;
				}
				image->num_string_literals++;
			}
			RVecAnalRef_free (refs);
		}
	}
	return true;
}

static bool function_image_snapshot_collect(RAnal *anal, const RAnalFunction *fcn, const RAnalFunctionSnapshotLimits *limits, RAnalFunctionImageSnapshot *image, const char **reason) {
	const char *refusal = "the function image is not coherent";
	R_RETURN_VAL_IF_FAIL (anal && fcn && limits && image, false);
	if (fcn->anal != anal || !anal->iob.nread_at || !fcn->bbs) {
		IMAGE_REFUSE ("the function does not belong to this analysis or has no blocks");
	}
	const int listed_blocks = r_list_length (fcn->bbs);
	if (listed_blocks <= 0 || (size_t)listed_blocks > limits->max_function_blocks) {
		IMAGE_REFUSE ("the block count is zero or past its limit");
	}
	const size_t count = (size_t)listed_blocks;
	size_t allocation_size;
	if (r_mul_overflow (count, sizeof (RAnalSnapshotBlock), &allocation_size)) {
		IMAGE_REFUSE ("the block table size overflows");
	}
	image->blocks = calloc (1, allocation_size);
	if (!image->blocks) {
		IMAGE_REFUSE ("out of memory allocating the block table");
	}
	image->num_blocks = count;
	image->entry_addr = fcn->addr;
	size_t total_successors = 0;
	size_t total_source_bytes = 0;
	size_t index = 0;
	RListIter *iter;
	RAnalBlock *source;
	r_list_foreach (fcn->bbs, iter, source) {
		if (!source || index >= count || !source->size
			|| source->size > (ut64)SIZE_MAX || source->size > (ut64)INT_MAX
			|| source->size > (ut64)limits->max_block_source_bytes
			|| source->addr > UT64_MAX - source->size) {
			IMAGE_REFUSE ("a block is empty, oversized, or wraps its address");
		}
		const size_t source_size = (size_t)source->size;
		size_t next_source_bytes;
		if (r_add_overflow_size_t (
				total_source_bytes, source_size, &next_source_bytes)
			|| next_source_bytes > limits->max_function_source_bytes) {
			IMAGE_REFUSE ("the total block bytes exceed the function limit");
		}
		total_source_bytes = next_source_bytes;
		RAnalSnapshotBlock *block = &image->blocks[index++];
		block->addr = source->addr;
		block->size = source->size;
		block->switch_addr = UT64_MAX;
		if (!snapshot_block_successors_collect (
				source, block, &total_successors, limits)) {
			IMAGE_REFUSE ("the block successors are not coherent");
		}
	}
	if (index != count) {
		IMAGE_REFUSE ("the block list changed while it was read");
	}
	image->total_source_bytes = total_source_bytes;
	qsort (image->blocks, count, sizeof (RAnalSnapshotBlock), snapshot_block_compare);
	ut64 previous_end = 0;
	for (index = 0; index < count; index++) {
		RAnalSnapshotBlock *block = &image->blocks[index];
		if (index && block->addr < previous_end) {
			IMAGE_REFUSE ("two blocks overlap");
		}
		previous_end = block->addr + block->size;
		block->bytes = malloc ((size_t)block->size);
		if (!block->bytes) {
			IMAGE_REFUSE ("out of memory allocating block bytes");
		}
		const int block_size = (int)block->size;
		if (anal->iob.nread_at (anal->iob.io, block->addr, block->bytes, block_size) != block_size) {
			IMAGE_REFUSE ("the block bytes could not be read from io");
		}
		if (!snapshot_block_sequential_jump_normalize (anal, block)) {
			IMAGE_REFUSE ("a sequential jump could not be normalized");
		}
	}
	if (function_image_target_classify (image, image->entry_addr) != 1) {
		IMAGE_REFUSE ("the entry address is not a block start");
	}
	if (total_successors) {
		if (r_mul_overflow (total_successors, sizeof (ut64), &allocation_size)) {
			IMAGE_REFUSE ("the external exit table size overflows");
		}
		image->external_exits = malloc (allocation_size);
		if (!image->external_exits) {
			IMAGE_REFUSE ("out of memory allocating external exits");
		}
	}
	for (index = 0; index < count; index++) {
		RAnalSnapshotBlock *block = &image->blocks[index];
		size_t successor_index;
		for (successor_index = 0;
			successor_index < block->num_successors; successor_index++) {
			RAnalSnapshotSuccessor *successor = &block->successors[successor_index];
			const int target_class = function_image_target_classify (
				image, successor->target_addr);
			if (target_class < 0) {
				IMAGE_REFUSE ("a successor targets the middle of a block");
			}
			if (!target_class) {
				successor->external = true;
				image->external_exits[image->num_external_exits++] = successor->target_addr;
			}
		}
	}
	if (image->num_external_exits) {
		qsort (image->external_exits, image->num_external_exits,
			sizeof (ut64), snapshot_addr_compare);
		size_t unique = 1;
		for (index = 1; index < image->num_external_exits; index++) {
			if (image->external_exits[index] != image->external_exits[unique - 1]) {
				image->external_exits[unique++] = image->external_exits[index];
			}
		}
		image->num_external_exits = unique;
	}
	if (!function_image_code_pointer_tables_collect (anal, image)) {
		return false;
	}
	if (!function_image_string_literals_collect (anal, image, limits)) {
		IMAGE_REFUSE ("the referenced string literals are not coherent");
	}
	return true;

fail:
	function_image_snapshot_fini (image);
	if (reason) {
		*reason = refusal;
	}
	return false;
}

#undef IMAGE_REFUSE

static bool function_image_snapshot_equal(const RAnalFunctionImageSnapshot *left, const RAnalFunctionImageSnapshot *right) {
	if (left->entry_addr != right->entry_addr
		|| left->num_blocks != right->num_blocks
		|| left->num_external_exits != right->num_external_exits
		|| left->total_source_bytes != right->total_source_bytes) {
		return false;
	}
	if (left->num_external_exits && memcmp (left->external_exits,
			right->external_exits,
			left->num_external_exits * sizeof (ut64))) {
		return false;
	}
	size_t i;
	for (i = 0; i < left->num_blocks; i++) {
		const RAnalSnapshotBlock *a = &left->blocks[i];
		const RAnalSnapshotBlock *b = &right->blocks[i];
		if (a->addr != b->addr || a->size != b->size
			|| a->switch_addr != b->switch_addr
			|| a->num_successors != b->num_successors
			|| memcmp (a->bytes, b->bytes, (size_t)a->size)) {
			return false;
		}
		size_t j;
		for (j = 0; j < a->num_successors; j++) {
			const RAnalSnapshotSuccessor *as = &a->successors[j];
			const RAnalSnapshotSuccessor *bs = &b->successors[j];
			if (as->kind != bs->kind || as->target_addr != bs->target_addr
				|| as->case_value != bs->case_value
				|| as->external != bs->external) {
				return false;
			}
		}
	}
	return true;
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

static void function_context_fini(RAnalFcnContext *ctx) {
	r_anal_function_signature_free (ctx->signature);
	r_list_free (ctx->reg_args);
	r_list_free (ctx->fcn_slots);
	r_list_free (ctx->callees);
	r_list_free (ctx->assumptions);
	free (ctx->assumptions_json);
}

static void snapshot_register_storage_fini(RAnalSnapshotRegisterStorage *storage) {
	free (storage->name);
	memset (storage, 0, sizeof (*storage));
}

static void function_interface_snapshot_fini(RAnalFunctionInterfaceSnapshot *interface) {
	size_t i;
	for (i = 0; i < interface->num_parameters; i++) {
		free (interface->parameters[i].name);
		snapshot_register_storage_fini (&interface->parameters[i].storage);
	}
	free (interface->parameters);
	free (interface->calling_convention);
	for (size_t slot = 0; slot < interface->num_convention_argument_slots; slot++) {
		snapshot_register_storage_fini (&interface->convention_argument_slots[slot]);
	}
	R_FREE (interface->convention_argument_slots);
	interface->num_convention_argument_slots = 0;
	snapshot_register_storage_fini (&interface->convention_result_slot);
	snapshot_register_storage_fini (&interface->return_storage);
	snapshot_register_storage_fini (&interface->return_address_storage);
	snapshot_register_storage_fini (&interface->stack_pointer_storage);
}

static void snapshot_type_graph_fini(RAnalSnapshotTypeGraph *graph) {
	size_t i;
	for (i = 0; i < graph->num_aggregates; i++) {
		RAnalSnapshotAggregateLayout *aggregate = &graph->aggregates[i];
		size_t j;
		for (j = 0; j < aggregate->num_members; j++) {
			free (aggregate->members[j].name);
		}
		free (aggregate->members);
		free (aggregate->name);
	}
	free (graph->aggregates);
	free (graph->types);
	memset (graph, 0, sizeof (*graph));
}

static void call_site_interface_snapshot_fini(RAnalCallSiteInterfaceSnapshot *interface) {
	size_t i;
	for (i = 0; i < interface->num_arguments; i++) {
		free (interface->arguments[i].name);
		snapshot_register_storage_fini (&interface->arguments[i].storage);
	}
	free (interface->arguments);
	free (interface->target_name);
	free (interface->calling_convention);
	snapshot_register_storage_fini (&interface->result_storage);
}

R_IPI void r_anal_function_snapshot_free(RAnalFunctionSnapshot *snapshot) {
	if (!snapshot) {
		return;
	}
	size_t callee;
	for (callee = 0; callee < snapshot->num_callee_snapshots; callee++) {
		r_anal_function_snapshot_free (snapshot->callee_snapshots[callee]);
	}
	free (snapshot->callee_snapshots);
	function_context_fini (&snapshot->context);
	function_interface_snapshot_fini (&snapshot->function_interface);
	snapshot_register_storage_fini (&snapshot->frame_pointer_storage);
	size_t i;
	for (i = 0; i < snapshot->num_call_site_interfaces; i++) {
		call_site_interface_snapshot_fini (&snapshot->call_site_interfaces[i]);
	}
	free (snapshot->call_site_interfaces);
	snapshot_type_graph_fini (&snapshot->type_graph);
	function_image_snapshot_fini (&snapshot->image);
	r_anal_types_snapshot_free (snapshot->base_types);
	free (snapshot->arch_id);
	free (snapshot->cpu_id);
	free (snapshot->function_name);
	free (snapshot);
}

R_API bool r_anal_function_snapshot_view(const RAnalFunctionSnapshot *snapshot, RAnalFunctionSnapshotView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	*view = (RAnalFunctionSnapshotView) {
		.schema_version = snapshot->schema_version,
		.struct_size = sizeof (*view),
		.capabilities = snapshot->capabilities,
		.function_addr = snapshot->function_addr,
		.function_size = snapshot->function_size,
		.bits = snapshot->bits,
		.endian = snapshot->endian,
		.maxstack = snapshot->maxstack,
		.arch_id_length = strlen (snapshot->arch_id),
		.cpu_id_length = strlen (snapshot->cpu_id),
		.function_name_length = strlen (snapshot->function_name),
		.num_base_types = snapshot->base_types? (size_t)r_list_length (snapshot->base_types): 0,
		.type_context_hash = snapshot->type_context_hash,
		.num_call_site_interfaces = snapshot->num_call_site_interfaces,
		.num_stack_slots = snapshot->context.fcn_slots
			? (size_t)r_list_length (snapshot->context.fcn_slots)
			: 0,
		.revision_identity = snapshot->revision_identity,
		.num_types = snapshot->type_graph.num_types,
		.num_aggregates = snapshot->type_graph.num_aggregates,
		.num_blocks = snapshot->image.num_blocks,
		.num_external_exits = snapshot->image.num_external_exits,
		.num_string_literals = snapshot->image.num_string_literals,
		.total_source_bytes = snapshot->image.total_source_bytes,
		.num_callee_snapshots = snapshot->num_callee_snapshots,
		.num_code_pointer_tables = snapshot->image.num_code_pointer_tables,
	};
	return true;
}

static bool snapshot_owned_string_copy(const char *string, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (string && buffer, false);
	size_t length = strlen (string);
	if (buffer_size <= length) {
		return false;
	}
	memcpy (buffer, string, length + 1);
	return true;
}

R_API bool r_anal_function_snapshot_arch_id(const RAnalFunctionSnapshot *snapshot, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	return snapshot_owned_string_copy (snapshot->arch_id, buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_cpu_id(const RAnalFunctionSnapshot *snapshot, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	return snapshot_owned_string_copy (snapshot->cpu_id, buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_function_name(const RAnalFunctionSnapshot *snapshot, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	return snapshot_owned_string_copy (snapshot->function_name, buffer, buffer_size);
}

static RAnalSnapshotRegisterStorageView snapshot_register_storage_view(const RAnalSnapshotRegisterStorage *storage) {
	return (RAnalSnapshotRegisterStorageView) {
		.name_length = strlen (r_str_get (storage->name)),
		.offset = storage->offset,
		.size = storage->size,
	};
}

static RAnalSnapshotParameterView snapshot_parameter_view(const RAnalSnapshotParameter *parameter) {
	return (RAnalSnapshotParameterView) {
		.index = parameter->index,
		.name_length = strlen (r_str_get (parameter->name)),
		.storage = snapshot_register_storage_view (&parameter->storage),
		.logical_type_id = parameter->logical_type_id,
		.carrier = parameter->carrier,
	};
}

R_API bool r_anal_function_snapshot_interface_view(const RAnalFunctionSnapshot *snapshot, RAnalFunctionInterfaceSnapshotView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	const RAnalFunctionInterfaceSnapshot *interface = &snapshot->function_interface;
	*view = (RAnalFunctionInterfaceSnapshotView) {
		.calling_convention_length = strlen (r_str_get (interface->calling_convention)),
		.num_parameters = interface->num_parameters,
		.return_kind = interface->return_kind,
		.return_storage = snapshot_register_storage_view (&interface->return_storage),
		.return_address_storage = snapshot_register_storage_view (&interface->return_address_storage),
		.stack_pointer_storage = snapshot_register_storage_view (&interface->stack_pointer_storage),
		.variadic = interface->variadic,
		.noreturn = interface->noreturn,
		.stack_resources_complete = interface->stack_resources_complete,
		.stack_slot_roles_complete = interface->stack_slot_roles_complete,
		.complete = interface->complete,
		.return_type_id = interface->return_type_id,
		.return_carrier = interface->return_carrier,
		.logical_types_complete = interface->logical_types_complete,
		.stack_pointer_preserved_across_calls =
			interface->stack_pointer_preserved_across_calls,
		.frame_pointer_preserved_across_calls =
			interface->frame_pointer_preserved_across_calls,
		.num_convention_argument_slots = interface->num_convention_argument_slots,
		.convention_result_slot =
			snapshot_register_storage_view (&interface->convention_result_slot),
		.convention_slots_known = interface->convention_slots_known,
	};
	return true;
}

R_API bool r_anal_function_snapshot_interface_return_mechanism(const RAnalFunctionSnapshot *snapshot, RAnalSnapshotReturnMechanismView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	*view = (RAnalSnapshotReturnMechanismView) {0};
	if (!(snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_RETURN_MECHANISM)) {
		return false;
	}
	*view = snapshot->return_mechanism;
	return true;
}

R_API bool r_anal_function_snapshot_interface_frame_pointer_storage(const RAnalFunctionSnapshot *snapshot, RAnalSnapshotRegisterStorageView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	*view = (RAnalSnapshotRegisterStorageView) {0};
	if (!(snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FRAME_POINTER_STORAGE)) {
		return false;
	}
	*view = snapshot_register_storage_view (&snapshot->frame_pointer_storage);
	return true;
}

R_API bool r_anal_function_snapshot_interface_stack_allocation_contract(const RAnalFunctionSnapshot *snapshot, RAnalSnapshotStackAllocationContractView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	*view = (RAnalSnapshotStackAllocationContractView) {0};
	if (!(snapshot->capabilities
			& R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_ALLOCATION_CONTRACT)) {
		return false;
	}
	*view = snapshot->stack_allocation_contract;
	return true;
}

R_API bool r_anal_function_snapshot_interface_calling_convention(const RAnalFunctionSnapshot *snapshot, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	return snapshot_owned_string_copy (r_str_get (snapshot->function_interface.calling_convention), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_interface_storage_name(const RAnalFunctionSnapshot *snapshot, RAnalSnapshotInterfaceStorageKind kind, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	const RAnalSnapshotRegisterStorage *storage;
	switch (kind) {
	case R_ANAL_SNAPSHOT_INTERFACE_STORAGE_RETURN:
		storage = &snapshot->function_interface.return_storage;
		break;
	case R_ANAL_SNAPSHOT_INTERFACE_STORAGE_RETURN_ADDRESS:
		storage = &snapshot->function_interface.return_address_storage;
		break;
	case R_ANAL_SNAPSHOT_INTERFACE_STORAGE_STACK_POINTER:
		storage = &snapshot->function_interface.stack_pointer_storage;
		break;
	case R_ANAL_SNAPSHOT_INTERFACE_STORAGE_FRAME_POINTER:
		storage = &snapshot->frame_pointer_storage;
		break;
	default:
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (storage->name), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_convention_argument_slot(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotRegisterStorageView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	const RAnalFunctionInterfaceSnapshot *interface = &snapshot->function_interface;
	if (!interface->convention_slots_known
		|| index >= interface->num_convention_argument_slots) {
		return false;
	}
	*view = snapshot_register_storage_view (&interface->convention_argument_slots[index]);
	return true;
}

R_API bool r_anal_function_snapshot_parameter_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotParameterView *parameter) {
	R_RETURN_VAL_IF_FAIL (snapshot && parameter, false);
	if (index >= snapshot->function_interface.num_parameters) {
		return false;
	}
	*parameter = snapshot_parameter_view (&snapshot->function_interface.parameters[index]);
	return true;
}

R_API bool r_anal_function_snapshot_parameter_name(const RAnalFunctionSnapshot *snapshot, size_t index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (index >= snapshot->function_interface.num_parameters) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (snapshot->function_interface.parameters[index].name), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_parameter_storage_name(const RAnalFunctionSnapshot *snapshot, size_t index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (index >= snapshot->function_interface.num_parameters) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (snapshot->function_interface.parameters[index].storage.name), buffer, buffer_size);
}

static bool snapshot_signature_view_of(const RAnalFunctionSignature *signature, RAnalSnapshotSignatureView *view) {
	if (!signature) {
		return false;
	}
	*view = (RAnalSnapshotSignatureView) {
		.num_parameters = signature->params
			? (size_t)r_list_length (signature->params): 0,
		.return_type_length = strlen (r_str_get (signature->ret_type)),
		.calling_convention_length = strlen (r_str_get (signature->callconv)),
		.noreturn = signature->noreturn,
	};
	return true;
}

static bool snapshot_signature_string_of(const RAnalFunctionSignature *signature, RAnalSnapshotSignatureStringKind kind, size_t index, char *buffer, size_t buffer_size) {
	if (!signature) {
		return false;
	}
	const RAnalFunctionParam *param = NULL;
	if (kind == R_ANAL_SNAPSHOT_SIGNATURE_STRING_PARAMETER_TYPE
		|| kind == R_ANAL_SNAPSHOT_SIGNATURE_STRING_PARAMETER_NAME) {
		if (!signature->params || index > INT_MAX
			|| index >= (size_t)r_list_length (signature->params)) {
			return false;
		}
		param = r_list_get_n (signature->params, (int)index);
		if (!param) {
			return false;
		}
	}
	const char *string;
	switch (kind) {
	case R_ANAL_SNAPSHOT_SIGNATURE_STRING_RETURN_TYPE:
		string = signature->ret_type;
		break;
	case R_ANAL_SNAPSHOT_SIGNATURE_STRING_CALLING_CONVENTION:
		string = signature->callconv;
		break;
	case R_ANAL_SNAPSHOT_SIGNATURE_STRING_PARAMETER_TYPE:
		string = param->type;
		break;
	case R_ANAL_SNAPSHOT_SIGNATURE_STRING_PARAMETER_NAME:
		string = param->name;
		break;
	default:
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (string), buffer, buffer_size);
}

// The signature is only offered when the capability says it was recovered, so
// an absent one reads as absent rather than as an empty prototype.
static const RAnalFunctionSignature *snapshot_signature(const RAnalFunctionSnapshot *snapshot) {
	if (!snapshot
		|| !(snapshot->capabilities & R_ANAL_FUNCTION_SNAPSHOT_CAP_SIGNATURE)) {
		return NULL;
	}
	return snapshot->context.signature;
}

R_API bool r_anal_function_snapshot_code_pointer_table_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotCodePointerTableView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	if (index >= snapshot->image.num_code_pointer_tables) {
		return false;
	}
	const RAnalSnapshotCodePointerTable *table = &snapshot->image.code_pointer_tables[index];
	*view = (RAnalSnapshotCodePointerTableView) {
		.addr = table->addr,
		.entry_size = table->entry_size,
		.num_targets = table->num_targets,
	};
	return true;
}

R_API bool r_anal_function_snapshot_code_pointer_table_target(const RAnalFunctionSnapshot *snapshot, size_t index, size_t target_index, ut64 *target) {
	R_RETURN_VAL_IF_FAIL (snapshot && target, false);
	if (index >= snapshot->image.num_code_pointer_tables) {
		return false;
	}
	const RAnalSnapshotCodePointerTable *table = &snapshot->image.code_pointer_tables[index];
	if (target_index >= table->num_targets) {
		return false;
	}
	*target = table->targets[target_index];
	return true;
}

R_API const RAnalFunctionSnapshot *r_anal_function_snapshot_callee_snapshot(const RAnalFunctionSnapshot *snapshot, size_t index) {
	R_RETURN_VAL_IF_FAIL (snapshot, NULL);
	if (index >= snapshot->num_callee_snapshots) {
		return NULL;
	}
	return snapshot->callee_snapshots[index];
}

R_API bool r_anal_function_snapshot_signature_view(const RAnalFunctionSnapshot *snapshot, RAnalSnapshotSignatureView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	return snapshot_signature_view_of (snapshot_signature (snapshot), view);
}

R_API bool r_anal_function_snapshot_signature_string(const RAnalFunctionSnapshot *snapshot, RAnalSnapshotSignatureStringKind kind, size_t index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot && buffer, false);
	return snapshot_signature_string_of (snapshot_signature (snapshot), kind, index, buffer, buffer_size);
}

// The prototype of the function a call site targets, which is where a spelling
// like `size_t` for an argument comes from.
static const RAnalFunctionSignature *snapshot_call_site_signature(const RAnalFunctionSnapshot *snapshot, size_t index) {
	if (!snapshot || index >= snapshot->num_call_site_interfaces
		|| !snapshot->context.callees) {
		return NULL;
	}
	const RAnalCallSiteInterfaceSnapshot *call = &snapshot->call_site_interfaces[index];
	RListIter *iter;
	RAnalFcnCallee *callee;
	r_list_foreach (snapshot->context.callees, iter, callee) {
		if (callee && callee->call_addr == call->instruction_addr
			&& callee->addr == call->target_addr) {
			return callee->signature;
		}
	}
	return NULL;
}

R_API bool r_anal_function_snapshot_call_site_signature_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotSignatureView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	return snapshot_signature_view_of (snapshot_call_site_signature (snapshot, index), view);
}

R_API bool r_anal_function_snapshot_call_site_signature_string(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotSignatureStringKind kind, size_t parameter_index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot && buffer, false);
	return snapshot_signature_string_of (snapshot_call_site_signature (snapshot, index), kind, parameter_index, buffer, buffer_size);
}

static const RAnalFcnSlot *snapshot_stack_slot(const RAnalFunctionSnapshot *snapshot, size_t index) {
	if (!snapshot || !snapshot->context.fcn_slots || index > INT_MAX
		|| index >= (size_t)r_list_length (snapshot->context.fcn_slots)) {
		return NULL;
	}
	return r_list_get_n (snapshot->context.fcn_slots, (int)index);
}

R_API bool r_anal_function_snapshot_stack_slot_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotStackSlotView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	const RAnalFcnSlot *slot = snapshot_stack_slot (snapshot, index);
	if (!slot) {
		return false;
	}
	*view = (RAnalSnapshotStackSlotView) {
		.name_length = strlen (r_str_get (slot->name)),
		.type_length = strlen (r_str_get (slot->type)),
		.base = slot->base,
		.base_name_length = strlen (r_str_get (slot->base_name)),
		.base_offset = slot->base_offset,
		.base_size = slot->base_size,
		.offset = slot->offset,
		.size = slot->size,
		.offset_valid = slot->offset_valid,
		.role = slot->role,
		.arg_index = slot->arg_index,
		.arg_name_length = strlen (r_str_get (slot->arg_name)),
		.home_reg_length = strlen (r_str_get (slot->home_reg)),
		.home_reg_offset = slot->home_reg_offset,
		.home_reg_size = slot->home_reg_size,
	};
	return true;
}

R_API bool r_anal_function_snapshot_stack_slot_string(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotStackSlotStringKind kind, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot && buffer, false);
	const RAnalFcnSlot *slot = snapshot_stack_slot (snapshot, index);
	if (!slot) {
		return false;
	}
	const char *string;
	switch (kind) {
	case R_ANAL_SNAPSHOT_STACK_SLOT_STRING_NAME:
		string = slot->name;
		break;
	case R_ANAL_SNAPSHOT_STACK_SLOT_STRING_TYPE:
		string = slot->type;
		break;
	case R_ANAL_SNAPSHOT_STACK_SLOT_STRING_BASE_NAME:
		string = slot->base_name;
		break;
	case R_ANAL_SNAPSHOT_STACK_SLOT_STRING_ARG_NAME:
		string = slot->arg_name;
		break;
	case R_ANAL_SNAPSHOT_STACK_SLOT_STRING_HOME_REGISTER:
		string = slot->home_reg;
		break;
	default:
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (string), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_call_site_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalCallSiteInterfaceSnapshotView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	if (index >= snapshot->num_call_site_interfaces) {
		return false;
	}
	const RAnalCallSiteInterfaceSnapshot *call = &snapshot->call_site_interfaces[index];
	*view = (RAnalCallSiteInterfaceSnapshotView) {
		.instruction_addr = call->instruction_addr,
		.target_addr = call->target_addr,
		.target_name_length = strlen (r_str_get (call->target_name)),
		.calling_convention_length = strlen (r_str_get (call->calling_convention)),
		.num_arguments = call->num_arguments,
		.result_kind = call->result_kind,
		.result_storage = snapshot_register_storage_view (&call->result_storage),
		.variadic = call->variadic,
		.noreturn = call->noreturn,
		.complete = call->complete,
	};
	return true;
}

R_API bool r_anal_function_snapshot_call_site_target_name(const RAnalFunctionSnapshot *snapshot, size_t index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (index >= snapshot->num_call_site_interfaces) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (snapshot->call_site_interfaces[index].target_name), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_call_site_calling_convention(const RAnalFunctionSnapshot *snapshot, size_t index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (index >= snapshot->num_call_site_interfaces) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (snapshot->call_site_interfaces[index].calling_convention), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_call_site_result_storage_name(const RAnalFunctionSnapshot *snapshot, size_t index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (index >= snapshot->num_call_site_interfaces) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (snapshot->call_site_interfaces[index].result_storage.name), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_call_argument_view(const RAnalFunctionSnapshot *snapshot, size_t call_index, size_t argument_index, RAnalSnapshotParameterView *argument) {
	R_RETURN_VAL_IF_FAIL (snapshot && argument, false);
	if (call_index >= snapshot->num_call_site_interfaces) {
		return false;
	}
	const RAnalCallSiteInterfaceSnapshot *call = &snapshot->call_site_interfaces[call_index];
	if (argument_index >= call->num_arguments) {
		return false;
	}
	*argument = snapshot_parameter_view (&call->arguments[argument_index]);
	return true;
}

R_API bool r_anal_function_snapshot_call_argument_storage_name(const RAnalFunctionSnapshot *snapshot, size_t call_index, size_t argument_index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (call_index >= snapshot->num_call_site_interfaces) {
		return false;
	}
	const RAnalCallSiteInterfaceSnapshot *call = &snapshot->call_site_interfaces[call_index];
	if (argument_index >= call->num_arguments) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (call->arguments[argument_index].storage.name), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_type_graph_view(const RAnalFunctionSnapshot *snapshot, RAnalSnapshotTypeGraphView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	*view = (RAnalSnapshotTypeGraphView) {
		.num_types = snapshot->type_graph.num_types,
		.num_aggregates = snapshot->type_graph.num_aggregates,
		.complete = snapshot->type_graph.complete,
	};
	return true;
}

R_API bool r_anal_function_snapshot_type_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotType *type) {
	R_RETURN_VAL_IF_FAIL (snapshot && type, false);
	if (index >= snapshot->type_graph.num_types) {
		return false;
	}
	*type = snapshot->type_graph.types[index];
	return true;
}

R_API bool r_anal_function_snapshot_aggregate_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotAggregateLayoutView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	if (index >= snapshot->type_graph.num_aggregates) {
		return false;
	}
	const RAnalSnapshotAggregateLayout *aggregate = &snapshot->type_graph.aggregates[index];
	*view = (RAnalSnapshotAggregateLayoutView) {
		.id = aggregate->id,
		.type_id = aggregate->type_id,
		.size_bits = aggregate->size_bits,
		.align_bits = aggregate->align_bits,
		.name_length = strlen (r_str_get (aggregate->name)),
		.num_members = aggregate->num_members,
		.complete = aggregate->complete,
		.c_layout_compatible = aggregate->c_layout_compatible,
	};
	return true;
}

R_API bool r_anal_function_snapshot_aggregate_name(const RAnalFunctionSnapshot *snapshot, size_t index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (index >= snapshot->type_graph.num_aggregates) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (snapshot->type_graph.aggregates[index].name), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_aggregate_member_view(const RAnalFunctionSnapshot *snapshot, size_t aggregate_index, size_t member_index, RAnalSnapshotAggregateMemberView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	if (aggregate_index >= snapshot->type_graph.num_aggregates) {
		return false;
	}
	const RAnalSnapshotAggregateLayout *aggregate = &snapshot->type_graph.aggregates[aggregate_index];
	if (member_index >= aggregate->num_members) {
		return false;
	}
	const RAnalSnapshotAggregateMember *member = &aggregate->members[member_index];
	*view = (RAnalSnapshotAggregateMemberView) {
		.member_id = member->member_id,
		.type_id = member->type_id,
		.offset_bits = member->offset_bits,
		.size_bits = member->size_bits,
		.count = member->count,
		.name_length = strlen (r_str_get (member->name)),
	};
	return true;
}

R_API bool r_anal_function_snapshot_aggregate_member_name(const RAnalFunctionSnapshot *snapshot, size_t aggregate_index, size_t member_index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (aggregate_index >= snapshot->type_graph.num_aggregates) {
		return false;
	}
	const RAnalSnapshotAggregateLayout *aggregate = &snapshot->type_graph.aggregates[aggregate_index];
	if (member_index >= aggregate->num_members) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (aggregate->members[member_index].name), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_block_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotBlockView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	if (index >= snapshot->image.num_blocks) {
		return false;
	}
	const RAnalSnapshotBlock *block = &snapshot->image.blocks[index];
	*view = (RAnalSnapshotBlockView) {
		.addr = block->addr,
		.size = block->size,
		.num_successors = block->num_successors,
		.switch_addr = block->switch_addr,
	};
	return true;
}

R_API bool r_anal_function_snapshot_block_bytes(const RAnalFunctionSnapshot *snapshot, size_t index, size_t offset, ut8 *buffer, size_t length) {
	R_RETURN_VAL_IF_FAIL (snapshot && buffer, false);
	if (index >= snapshot->image.num_blocks) {
		return false;
	}
	const RAnalSnapshotBlock *block = &snapshot->image.blocks[index];
	if (offset > block->size || length > block->size - offset) {
		return false;
	}
	memcpy (buffer, block->bytes + offset, length);
	return true;
}

R_API bool r_anal_function_snapshot_string_literal_view(const RAnalFunctionSnapshot *snapshot, size_t index, RAnalSnapshotStringLiteralView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	if (index >= snapshot->image.num_string_literals) {
		return false;
	}
	const RAnalSnapshotStringLiteral *literal = &snapshot->image.string_literals[index];
	*view = (RAnalSnapshotStringLiteralView) {
		.addr = literal->addr,
		.text_length = strlen (r_str_get (literal->text)),
	};
	return true;
}

R_API bool r_anal_function_snapshot_string_literal_text(const RAnalFunctionSnapshot *snapshot, size_t index, char *buffer, size_t buffer_size) {
	R_RETURN_VAL_IF_FAIL (snapshot, false);
	if (index >= snapshot->image.num_string_literals) {
		return false;
	}
	return snapshot_owned_string_copy (r_str_get (snapshot->image.string_literals[index].text), buffer, buffer_size);
}

R_API bool r_anal_function_snapshot_successor_view(const RAnalFunctionSnapshot *snapshot, size_t block_index, size_t successor_index, RAnalSnapshotSuccessorView *view) {
	R_RETURN_VAL_IF_FAIL (snapshot && view, false);
	if (block_index >= snapshot->image.num_blocks) {
		return false;
	}
	const RAnalSnapshotBlock *block = &snapshot->image.blocks[block_index];
	if (successor_index >= block->num_successors) {
		return false;
	}
	const RAnalSnapshotSuccessor *successor = &block->successors[successor_index];
	*view = (RAnalSnapshotSuccessorView) {
		.kind = successor->kind,
		.target_addr = successor->target_addr,
		.case_value = successor->case_value,
		.external = successor->external,
	};
	return true;
}

R_API bool r_anal_function_snapshot_external_exit(const RAnalFunctionSnapshot *snapshot, size_t index, ut64 *target) {
	R_RETURN_VAL_IF_FAIL (snapshot && target, false);
	if (index >= snapshot->image.num_external_exits) {
		return false;
	}
	*target = snapshot->image.external_exits[index];
	return true;
}

R_API void r_anal_function_context_free(RAnalFcnContext *ctx) {
	if (!ctx) {
		return;
	}
	function_context_fini (ctx);
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

static ut64 function_snapshot_hash_signature(ut64 hash, const RAnalFunctionSignature *signature) {
	if (!signature) {
		return function_context_hash_mix (hash, 0);
	}
	hash = function_context_hash_string (hash, signature->signature);
	hash = function_context_hash_string (hash, signature->ret_type);
	hash = function_context_hash_string (hash, signature->callconv);
	hash = function_context_hash_mix (hash, signature->noreturn? 1: 0);
	RListIter *iter;
	RAnalFunctionParam *param;
	r_list_foreach (signature->params, iter, param) {
		hash = function_context_hash_string (hash, param? param->name: NULL);
		hash = function_context_hash_string (hash, param? param->type: NULL);
	}
	return hash;
}

static ut64 function_snapshot_hash_base_types(ut64 hash, const RList *base_types) {
	RListIter *iter;
	RAnalBaseType *type;
	r_list_foreach (base_types, iter, type) {
		if (!type) {
			hash = function_context_hash_mix (hash, 0);
			continue;
		}
		hash = function_context_hash_string (hash, type->name);
		hash = function_context_hash_string (hash, type->type);
		hash = function_context_hash_mix (hash, (ut64)type->size);
		hash = function_context_hash_mix (hash, (ut64)type->kind);
		switch (type->kind) {
		case R_ANAL_BASE_TYPE_KIND_STRUCT: {
			RAnalStructMember *member;
			R_VEC_FOREACH (&type->struct_data.members, member) {
				hash = function_context_hash_string (hash, member->name);
				hash = function_context_hash_string (hash, member->type);
				hash = function_context_hash_mix (hash, (ut64)member->offset);
				hash = function_context_hash_mix (hash, (ut64)member->bitsize);
				hash = function_context_hash_mix (hash, (ut64)member->count);
			}
			break;
		}
		case R_ANAL_BASE_TYPE_KIND_UNION: {
			RAnalUnionMember *member;
			R_VEC_FOREACH (&type->union_data.members, member) {
				hash = function_context_hash_string (hash, member->name);
				hash = function_context_hash_string (hash, member->type);
				hash = function_context_hash_mix (hash, (ut64)member->offset);
				hash = function_context_hash_mix (hash, (ut64)member->bitsize);
				hash = function_context_hash_mix (hash, (ut64)member->count);
			}
			break;
		}
		case R_ANAL_BASE_TYPE_KIND_ENUM: {
			RAnalEnumCase *cas;
			R_VEC_FOREACH (&type->enum_data.cases, cas) {
				hash = function_context_hash_string (hash, cas->name);
				hash = function_context_hash_mix (hash, (ut64)(st64)cas->val);
			}
			break;
		}
		default:
			break;
		}
	}
	return hash;
}

static ut64 function_snapshot_hash_storage(ut64 hash, const RAnalSnapshotRegisterStorage *storage) {
	hash = function_context_hash_string (hash, storage->name);
	hash = function_context_hash_mix (hash, storage->offset);
	return function_context_hash_mix (hash, storage->size);
}

static ut64 function_snapshot_hash_interface(ut64 hash, const RAnalFunctionInterfaceSnapshot *interface) {
	hash = function_context_hash_string (hash, interface->calling_convention);
	hash = function_context_hash_mix (hash, interface->num_parameters);
	size_t i;
	for (i = 0; i < interface->num_parameters; i++) {
		const RAnalSnapshotParameter *parameter = &interface->parameters[i];
		hash = function_context_hash_mix (hash, parameter->index);
		hash = function_snapshot_hash_storage (hash, &parameter->storage);
		hash = function_context_hash_mix (hash, parameter->logical_type_id);
		hash = function_context_hash_mix (hash, parameter->carrier.kind);
		hash = function_context_hash_mix (hash, parameter->carrier.offset_bits);
		hash = function_context_hash_mix (hash, parameter->carrier.size_bits);
	}
	hash = function_context_hash_mix (hash, interface->return_kind);
	hash = function_snapshot_hash_storage (hash, &interface->return_storage);
	hash = function_snapshot_hash_storage (hash, &interface->return_address_storage);
	hash = function_snapshot_hash_storage (hash, &interface->stack_pointer_storage);
	hash = function_context_hash_mix (hash, interface->variadic? 1: 0);
	hash = function_context_hash_mix (hash, interface->noreturn? 1: 0);
	hash = function_context_hash_mix (hash, interface->stack_resources_complete? 1: 0);
	hash = function_context_hash_mix (hash, interface->stack_slot_roles_complete? 1: 0);
	hash = function_context_hash_mix (hash, interface->complete? 1: 0);
	hash = function_context_hash_mix (hash, interface->return_type_id);
	hash = function_context_hash_mix (hash, interface->return_carrier.kind);
	hash = function_context_hash_mix (hash, interface->return_carrier.offset_bits);
	hash = function_context_hash_mix (hash, interface->return_carrier.size_bits);
	hash = function_context_hash_mix (hash,
		interface->stack_pointer_preserved_across_calls? 1: 0);
	hash = function_context_hash_mix (hash,
		interface->frame_pointer_preserved_across_calls? 1: 0);
	return function_context_hash_mix (hash, interface->logical_types_complete? 1: 0);
}

static ut64 function_snapshot_hash_return_mechanism(ut64 hash, const RAnalSnapshotReturnMechanismView *mechanism) {
	hash = function_context_hash_mix (hash, mechanism->kind);
	hash = function_context_hash_mix (hash, (ut64)mechanism->entry_sp_offset);
	hash = function_context_hash_mix (hash, mechanism->slot_size);
	return function_context_hash_mix (hash, (ut64)mechanism->exit_sp_delta);
}

static ut64 function_snapshot_hash_stack_allocation_contract(ut64 hash, const RAnalSnapshotStackAllocationContractView *contract) {
	hash = function_context_hash_mix (hash, contract->growth);
	return function_context_hash_mix (hash, contract->implicit_active_sp_bytes);
}

static ut64 function_snapshot_hash_type_graph(ut64 hash, const RAnalSnapshotTypeGraph *graph) {
	hash = function_context_hash_mix (hash, graph->num_types);
	size_t i;
	for (i = 0; i < graph->num_types; i++) {
		const RAnalSnapshotType *type = &graph->types[i];
		hash = function_context_hash_mix (hash, type->id);
		hash = function_context_hash_mix (hash, type->kind);
		hash = function_context_hash_mix (hash, type->size_bits);
		hash = function_context_hash_mix (hash, type->align_bits);
		hash = function_context_hash_mix (hash, type->target_type_id);
		hash = function_context_hash_mix (hash, type->aggregate_id);
	}
	hash = function_context_hash_mix (hash, graph->num_aggregates);
	for (i = 0; i < graph->num_aggregates; i++) {
		const RAnalSnapshotAggregateLayout *aggregate = &graph->aggregates[i];
		hash = function_context_hash_mix (hash, aggregate->id);
		hash = function_context_hash_mix (hash, aggregate->type_id);
		hash = function_context_hash_mix (hash, aggregate->size_bits);
		hash = function_context_hash_mix (hash, aggregate->align_bits);
		hash = function_context_hash_string (hash, aggregate->name);
		hash = function_context_hash_mix (hash, aggregate->num_members);
		size_t j;
		for (j = 0; j < aggregate->num_members; j++) {
			const RAnalSnapshotAggregateMember *member = &aggregate->members[j];
			hash = function_context_hash_mix (hash, member->member_id);
			hash = function_context_hash_mix (hash, member->type_id);
			hash = function_context_hash_mix (hash, member->offset_bits);
			hash = function_context_hash_mix (hash, member->size_bits);
			hash = function_context_hash_mix (hash, member->count);
			hash = function_context_hash_string (hash, member->name);
		}
		hash = function_context_hash_mix (hash, aggregate->complete? 1: 0);
		hash = function_context_hash_mix (hash, aggregate->c_layout_compatible? 1: 0);
	}
	return function_context_hash_mix (hash, graph->complete? 1: 0);
}

static ut64 function_snapshot_hash_call_interface(ut64 hash, const RAnalCallSiteInterfaceSnapshot *interface) {
	hash = function_context_hash_mix (hash, interface->instruction_addr);
	hash = function_context_hash_mix (hash, interface->target_addr);
	hash = function_context_hash_string (hash, interface->calling_convention);
	hash = function_context_hash_mix (hash, interface->num_arguments);
	size_t i;
	for (i = 0; i < interface->num_arguments; i++) {
		hash = function_context_hash_mix (hash, interface->arguments[i].index);
		hash = function_snapshot_hash_storage (hash, &interface->arguments[i].storage);
		hash = function_context_hash_mix (hash, interface->arguments[i].logical_type_id);
		hash = function_context_hash_mix (hash, interface->arguments[i].carrier.kind);
		hash = function_context_hash_mix (hash, interface->arguments[i].carrier.offset_bits);
		hash = function_context_hash_mix (hash, interface->arguments[i].carrier.size_bits);
	}
	hash = function_context_hash_mix (hash, interface->result_kind);
	hash = function_snapshot_hash_storage (hash, &interface->result_storage);
	hash = function_context_hash_mix (hash, interface->variadic? 1: 0);
	hash = function_context_hash_mix (hash, interface->noreturn? 1: 0);
	return function_context_hash_mix (hash, interface->complete? 1: 0);
}

static ut64 function_snapshot_hash_image(ut64 hash, const RAnalFunctionImageSnapshot *image) {
	hash = function_context_hash_mix (hash, image->entry_addr);
	hash = function_context_hash_mix (hash, image->num_blocks);
	hash = function_context_hash_mix (hash, image->total_source_bytes);
	size_t i;
	for (i = 0; i < image->num_blocks; i++) {
		const RAnalSnapshotBlock *block = &image->blocks[i];
		hash = function_context_hash_mix (hash, block->addr);
		hash = function_context_hash_mix (hash, block->size);
		hash = function_context_hash_mix (hash, block->switch_addr);
		hash = function_context_hash_mix (hash, block->num_successors);
		size_t byte_index;
		for (byte_index = 0; byte_index < (size_t)block->size; byte_index++) {
			hash = function_context_hash_mix (hash, block->bytes[byte_index]);
		}
		size_t successor_index;
		for (successor_index = 0;
			successor_index < block->num_successors; successor_index++) {
			const RAnalSnapshotSuccessor *successor =
				&block->successors[successor_index];
			hash = function_context_hash_mix (hash, successor->kind);
			hash = function_context_hash_mix (hash, successor->target_addr);
			hash = function_context_hash_mix (hash, successor->case_value);
			hash = function_context_hash_mix (hash, successor->external? 1: 0);
		}
	}
	hash = function_context_hash_mix (hash, image->num_external_exits);
	for (i = 0; i < image->num_external_exits; i++) {
		hash = function_context_hash_mix (hash, image->external_exits[i]);
	}
	return hash;
}

static ut64 function_snapshot_hash(const RAnalFunctionSnapshot *snapshot) {
	ut64 hash = 0xcbf29ce484222325ULL;
	hash = function_context_hash_mix (hash, snapshot->schema_version);
	hash = function_context_hash_mix (hash, snapshot->struct_size);
	hash = function_context_hash_mix (hash, snapshot->capabilities);
	hash = function_context_hash_mix (hash, snapshot->function_addr);
	hash = function_context_hash_mix (hash, snapshot->function_size);
	hash = function_context_hash_mix (hash, snapshot->context.function_dirty_epoch);
	hash = function_context_hash_mix (hash, snapshot->context.type_dirty_epoch);
	hash = function_context_hash_mix (hash, snapshot->type_context_hash);
	hash = function_context_hash_mix (hash, (ut64)snapshot->bits);
	hash = function_context_hash_mix (hash, snapshot->endian);
	hash = function_context_hash_mix (hash, (ut64)snapshot->maxstack);
	hash = function_context_hash_string (hash, snapshot->arch_id);
	hash = function_context_hash_string (hash, snapshot->cpu_id);
	hash = function_context_hash_string (hash, snapshot->function_name);
	hash = function_snapshot_hash_base_types (hash, snapshot->base_types);
	hash = function_snapshot_hash_interface (hash, &snapshot->function_interface);
	hash = function_snapshot_hash_return_mechanism (hash, &snapshot->return_mechanism);
	hash = function_snapshot_hash_storage (hash, &snapshot->frame_pointer_storage);
	hash = function_snapshot_hash_stack_allocation_contract (
		hash, &snapshot->stack_allocation_contract);
	hash = function_snapshot_hash_type_graph (hash, &snapshot->type_graph);
	hash = function_snapshot_hash_image (hash, &snapshot->image);
	size_t call_index;
	for (call_index = 0; call_index < snapshot->num_call_site_interfaces; call_index++) {
		hash = function_snapshot_hash_call_interface (
			hash, &snapshot->call_site_interfaces[call_index]);
	}
	hash = function_context_hash_string (hash, snapshot->context.assumptions_json);
	hash = function_snapshot_hash_signature (hash, snapshot->context.signature);
	RListIter *iter;
	RAnalFcnRegArg *reg_arg;
	r_list_foreach (snapshot->context.reg_args, iter, reg_arg) {
		hash = function_context_hash_string (hash, reg_arg? reg_arg->name: NULL);
		hash = function_context_hash_string (hash, reg_arg? reg_arg->type: NULL);
		hash = function_context_hash_string (hash, reg_arg? reg_arg->reg: NULL);
		hash = function_context_hash_mix (hash, reg_arg? (ut64)(st64)reg_arg->arg_index: 0);
	}
	RAnalFcnSlot *slot;
	r_list_foreach (snapshot->context.fcn_slots, iter, slot) {
		hash = function_context_hash_string (hash, slot? slot->name: NULL);
		hash = function_context_hash_string (hash, slot? slot->type: NULL);
		hash = function_context_hash_mix (hash, slot? (ut64)slot->base: 0);
		hash = function_context_hash_string (hash, slot? slot->base_name: NULL);
		hash = function_context_hash_mix (hash, slot? slot->base_offset: 0);
		hash = function_context_hash_mix (hash, slot? slot->base_size: 0);
		hash = function_context_hash_mix (hash, slot? (ut64)slot->offset: 0);
		hash = function_context_hash_mix (hash, slot? slot->size: 0);
		hash = function_context_hash_mix (hash, slot && slot->offset_valid? 1: 0);
		hash = function_context_hash_mix (hash, slot? (ut64)slot->role: 0);
		hash = function_context_hash_mix (hash, slot? (ut64)(st64)slot->arg_index: 0);
		hash = function_context_hash_string (hash, slot? slot->arg_name: NULL);
		hash = function_context_hash_string (hash, slot? slot->home_reg: NULL);
		hash = function_context_hash_mix (hash, slot? slot->home_reg_offset: 0);
		hash = function_context_hash_mix (hash, slot? slot->home_reg_size: 0);
	}
	RAnalFcnCallee *callee;
	r_list_foreach (snapshot->context.callees, iter, callee) {
		hash = function_context_hash_mix (hash, callee? callee->call_addr: 0);
		hash = function_context_hash_mix (hash, callee? callee->addr: 0);
		hash = function_context_hash_mix (hash, callee? (ut64)callee->linkage: 0);
		hash = function_context_hash_string (hash, callee? callee->name: NULL);
		hash = function_snapshot_hash_signature (hash, callee? callee->signature: NULL);
	}
	RAnalFunctionAssumption *assumption;
	r_list_foreach (snapshot->context.assumptions, iter, assumption) {
		hash = function_context_hash_string (hash, assumption? assumption->kind: NULL);
		hash = function_context_hash_string (hash, assumption? assumption->target: NULL);
		hash = function_context_hash_string (hash, assumption? assumption->scope: NULL);
		hash = function_context_hash_string (hash, assumption? assumption->provenance: NULL);
		hash = function_context_hash_string (hash, assumption? assumption->subject_json: NULL);
		hash = function_context_hash_string (hash, assumption? assumption->value_json: NULL);
		hash = function_context_hash_string (hash, assumption? assumption->payload_json: NULL);
	}
	return hash? hash: 1;
}

R_API ut64 r_anal_function_context_hash(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, 0);
	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	if (!snapshot) {
		return 0;
	}
	ut64 revision_identity = snapshot->revision_identity;
	r_anal_function_snapshot_free (snapshot);
	return revision_identity;
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

static bool r_anal_function_set_signature_string(RAnal *anal, RAnalFunction *fcn, const char *signature) {
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
		if (!anal->sdb_types || R_STR_ISEMPTY (mutation->type)) {
			return false;
		}
		if (r_type_func_exist (anal->sdb_types, mutation->type)) {
			return r_anal_function_type_link_set (anal, mutation->type, mutation->addr);
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

typedef struct {
	RAnalMutationKind kind;
	RAnalFunction *fcn;
	bool changed;
	bool applied;
	union {
		struct {
			const char *requested;
			const char *old_value;
			const char *new_value;
		} callconv;
		struct {
			RAnalVar *var;
			const char *requested;
			char *old_value;
			char *new_value;
		} rename;
	} value;
} RAnalPreparedAtomicMutation;

static RAnalMutationAtomicResult atomic_mutation_result(RAnalMutationAtomicStatus status, size_t failed_index) {
	RAnalMutationAtomicResult result = {
		.status = status,
		.failed_index = failed_index,
	};
	return result;
}

static bool atomic_mutation_kind_supported(RAnalMutationKind kind) {
	return kind == R_ANAL_MUTATION_CALLCONV || kind == R_ANAL_MUTATION_VAR_RENAME;
}

static bool atomic_mutation_validate_callconv(RAnal *anal, const RAnalMutation *mutation, RAnalPreparedAtomicMutation *prepared) {
	RAnalFunction *fcn = mutation->fcn;
	if (!fcn || fcn->anal != anal || R_STR_ISEMPTY (mutation->callconv)
			|| !r_anal_cc_exist (anal, mutation->callconv)) {
		return false;
	}
	prepared->kind = mutation->kind;
	prepared->fcn = fcn;
	prepared->value.callconv.requested = mutation->callconv;
	prepared->value.callconv.old_value = fcn->callconv;
	prepared->changed = !fcn->callconv || strcmp (fcn->callconv, mutation->callconv);
	return true;
}

static bool atomic_mutation_validate_rename(RAnal *anal, const RAnalMutation *mutation, RAnalPreparedAtomicMutation *prepared) {
	RAnalVar *var = mutation->var;
	if (!var && mutation->fcn && R_STR_ISNOTEMPTY (mutation->old_name)) {
		var = r_anal_function_get_var_byname (mutation->fcn, mutation->old_name);
	}
	if (!var || !var->fcn || var->fcn->anal != anal
			|| (mutation->fcn && mutation->fcn != var->fcn)
			|| R_STR_ISEMPTY (var->name) || !r_anal_var_check_name (mutation->name)) {
		return false;
	}
	RAnalVar *existing = r_anal_function_get_var_byname (var->fcn, mutation->name);
	if (existing && existing != var) {
		return false;
	}
	prepared->kind = mutation->kind;
	prepared->fcn = var->fcn;
	prepared->value.rename.var = var;
	prepared->value.rename.requested = mutation->name;
	prepared->value.rename.old_value = var->name;
	prepared->changed = strcmp (var->name, mutation->name);
	return true;
}

static bool atomic_mutation_validate(RAnal *anal, const RAnalMutation *mutation, RAnalPreparedAtomicMutation *prepared) {
	switch (mutation->kind) {
	case R_ANAL_MUTATION_CALLCONV:
		return atomic_mutation_validate_callconv (anal, mutation, prepared);
	case R_ANAL_MUTATION_VAR_RENAME:
		return atomic_mutation_validate_rename (anal, mutation, prepared);
	default:
		return false;
	}
}

static bool atomic_mutation_prepare(RAnal *anal, RAnalPreparedAtomicMutation *prepared) {
	switch (prepared->kind) {
	case R_ANAL_MUTATION_CALLCONV:
		prepared->value.callconv.new_value = r_str_constpool_get (
			&anal->constpool, prepared->value.callconv.requested);
		return prepared->value.callconv.new_value != NULL;
	case R_ANAL_MUTATION_VAR_RENAME:
		prepared->value.rename.new_value = strdup (prepared->value.rename.requested);
		return prepared->value.rename.new_value != NULL;
	default:
		return false;
	}
}

static void atomic_mutation_plan_fini(RAnalPreparedAtomicMutation *prepared, size_t mutation_count) {
	size_t i;
	for (i = 0; i < mutation_count; i++) {
		if (prepared[i].kind == R_ANAL_MUTATION_VAR_RENAME) {
			free (prepared[i].value.rename.new_value);
		}
	}
	free (prepared);
}

static bool atomic_mutation_commit_one(RAnalPreparedAtomicMutation *prepared) {
	switch (prepared->kind) {
	case R_ANAL_MUTATION_CALLCONV:
		if (prepared->fcn->callconv != prepared->value.callconv.old_value) {
			return false;
		}
		if (prepared->changed) {
			prepared->fcn->callconv = prepared->value.callconv.new_value;
			prepared->applied = true;
		}
		return true;
	case R_ANAL_MUTATION_VAR_RENAME: {
		RAnalVar *var = prepared->value.rename.var;
		if (var->name != prepared->value.rename.old_value) {
			return false;
		}
		RAnalVar *existing = r_anal_function_get_var_byname (
			var->fcn, prepared->value.rename.new_value);
		if (existing && existing != var) {
			return false;
		}
		if (prepared->changed) {
			var->name = prepared->value.rename.new_value;
			prepared->applied = true;
		}
		return true;
	}
	default:
		return false;
	}
}

static void atomic_mutation_rollback_one(RAnalPreparedAtomicMutation *prepared) {
	if (!prepared->applied) {
		return;
	}
	switch (prepared->kind) {
	case R_ANAL_MUTATION_CALLCONV:
		prepared->fcn->callconv = prepared->value.callconv.old_value;
		break;
	case R_ANAL_MUTATION_VAR_RENAME:
		prepared->value.rename.var->name = prepared->value.rename.old_value;
		break;
	default:
		break;
	}
	prepared->applied = false;
}

static bool atomic_mutation_first_function_change(const RAnalPreparedAtomicMutation *prepared, size_t index) {
	size_t i;
	if (!prepared[index].changed) {
		return false;
	}
	for (i = 0; i < index; i++) {
		if (prepared[i].changed && prepared[i].fcn == prepared[index].fcn) {
			return false;
		}
	}
	return true;
}

static void atomic_mutation_publish(RAnal *anal, RAnalPreparedAtomicMutation *prepared, size_t mutation_count) {
	size_t i;
	bool changed = false;
	for (i = 0; i < mutation_count; i++) {
		if (atomic_mutation_first_function_change (prepared, i)) {
			r_anal_function_bump_dirty_epoch (prepared[i].fcn);
			changed = true;
		}
	}
	if (changed) {
		R_DIRTY_SET (anal);
	}
	for (i = 0; i < mutation_count; i++) {
		if (prepared[i].changed && prepared[i].kind == R_ANAL_MUTATION_VAR_RENAME) {
			REventVariable event = {
				.fcn = prepared[i].fcn,
				.var = prepared[i].value.rename.var,
				.name = prepared[i].value.rename.var->name,
			};
			r_event_send (anal->ev, R_EVENT_VARIABLE_NAME_CHANGED, &event);
		}
	}
}

static void atomic_mutation_finish_commit(RAnalPreparedAtomicMutation *prepared, size_t mutation_count) {
	size_t i;
	for (i = 0; i < mutation_count; i++) {
		if (prepared[i].changed && prepared[i].kind == R_ANAL_MUTATION_VAR_RENAME) {
			free (prepared[i].value.rename.old_value);
			prepared[i].value.rename.old_value = NULL;
			prepared[i].value.rename.new_value = NULL;
		}
	}
}

R_API RAnalMutationAtomicResult r_anal_apply_mutations_atomic(RAnal *anal, const RAnalMutation *mutations, size_t mutation_count) {
	RAnalMutationAtomicResult result = atomic_mutation_result (
		R_ANAL_MUTATION_ATOMIC_STATUS_OK, R_ANAL_MUTATION_ATOMIC_INDEX_NONE);
	if (!anal || (!mutations && mutation_count)) {
		result.status = R_ANAL_MUTATION_ATOMIC_STATUS_INVALID_ARGUMENT;
		result.failed_index = anal && mutation_count? 0: R_ANAL_MUTATION_ATOMIC_INDEX_NONE;
		return result;
	}
	if (!mutation_count) {
		return result;
	}
	r_th_lock_enter (anal->lock);
	size_t i;
	for (i = 0; i < mutation_count; i++) {
		if (!atomic_mutation_kind_supported (mutations[i].kind)) {
			result.status = R_ANAL_MUTATION_ATOMIC_STATUS_UNSUPPORTED;
			result.failed_index = i;
			r_th_lock_leave (anal->lock);
			return result;
		}
	}
	size_t allocation_size;
	if (r_mul_overflow_size_t (mutation_count, sizeof (RAnalPreparedAtomicMutation), &allocation_size)) {
		result.status = R_ANAL_MUTATION_ATOMIC_STATUS_PREPARATION_FAILED;
		r_th_lock_leave (anal->lock);
		return result;
	}
	RAnalPreparedAtomicMutation *prepared = calloc (1, allocation_size);
	if (!prepared) {
		result.status = R_ANAL_MUTATION_ATOMIC_STATUS_PREPARATION_FAILED;
		r_th_lock_leave (anal->lock);
		return result;
	}
	for (i = 0; i < mutation_count; i++) {
		if (!atomic_mutation_validate (anal, &mutations[i], &prepared[i])) {
			result.status = R_ANAL_MUTATION_ATOMIC_STATUS_VALIDATION_FAILED;
			result.failed_index = i;
			atomic_mutation_plan_fini (prepared, mutation_count);
			r_th_lock_leave (anal->lock);
			return result;
		}
		result.validated++;
	}
	for (i = 0; i < mutation_count; i++) {
		if (!atomic_mutation_prepare (anal, &prepared[i])) {
			result.status = R_ANAL_MUTATION_ATOMIC_STATUS_PREPARATION_FAILED;
			result.failed_index = i;
			atomic_mutation_plan_fini (prepared, mutation_count);
			r_th_lock_leave (anal->lock);
			return result;
		}
	}
	for (i = 0; i < mutation_count; i++) {
		if (!atomic_mutation_commit_one (&prepared[i])) {
			result.status = R_ANAL_MUTATION_ATOMIC_STATUS_COMMIT_FAILED;
			result.failed_index = i;
			while (i > 0) {
				i--;
				atomic_mutation_rollback_one (&prepared[i]);
			}
			result.committed = 0;
			atomic_mutation_plan_fini (prepared, mutation_count);
			r_th_lock_leave (anal->lock);
			return result;
		}
		result.committed++;
	}
	atomic_mutation_publish (anal, prepared, mutation_count);
	atomic_mutation_finish_commit (prepared, mutation_count);
	atomic_mutation_plan_fini (prepared, mutation_count);
	r_th_lock_leave (anal->lock);
	return result;
}

typedef enum {
	SNAPSHOT_STORAGE_INVALID = 0,
	SNAPSHOT_STORAGE_VALID,
	SNAPSHOT_STORAGE_NO_MEMORY,
} SnapshotStorageResult;

static SnapshotStorageResult snapshot_register_storage_collect(
	RAnal *anal, const char *name, RAnalSnapshotRegisterStorage *storage) {
	if (R_STR_ISEMPTY (name) || !anal->reg) {
		return SNAPSHOT_STORAGE_INVALID;
	}
	RRegItem *item = r_reg_get (anal->reg, name, -1);
	if (!item || item->offset < 0 || item->offset % 8
		|| item->size <= 0 || item->size % 8) {
		r_unref (item);
		return SNAPSHOT_STORAGE_INVALID;
	}
	storage->name = strdup (r_str_get (item->name));
	storage->offset = (ut64)(item->offset / 8);
	storage->size = (ut32)(item->size / 8);
	r_unref (item);
	return storage->name? SNAPSHOT_STORAGE_VALID: SNAPSHOT_STORAGE_NO_MEMORY;
}

static bool snapshot_function_address_size(const RAnalFunction *fcn, ut32 *size) {
	if (!fcn || fcn->bits <= 0 || fcn->bits % 8
		|| fcn->bits / 8 > UT32_MAX) {
		return false;
	}
	*size = (ut32)(fcn->bits / 8);
	return true;
}

static SnapshotStorageResult snapshot_return_address_storage_collect(
	RAnal *anal, const RAnalFunction *fcn, RAnalSnapshotRegisterStorage *storage) {
	ut32 address_size = 0;
	if (!anal->reg || !snapshot_function_address_size (fcn, &address_size)) {
		return SNAPSHOT_STORAGE_INVALID;
	}
	const RRegAlias aliases[] = {
		R_REG_ALIAS_LR,
		R_REG_ALIAS_RA,
		R_REG_ALIAS_PC,
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (aliases); i++) {
		RAnalSnapshotRegisterStorage candidate = {0};
		SnapshotStorageResult collected = snapshot_register_storage_collect (
			anal, r_reg_alias_getname (anal->reg, aliases[i]), &candidate);
		if (collected == SNAPSHOT_STORAGE_NO_MEMORY) {
			return collected;
		}
		if (collected == SNAPSHOT_STORAGE_VALID && candidate.size == address_size) {
			*storage = candidate;
			return SNAPSHOT_STORAGE_VALID;
		}
		snapshot_register_storage_fini (&candidate);
	}
	return SNAPSHOT_STORAGE_INVALID;
}

static SnapshotStorageResult snapshot_stack_pointer_storage_collect(
	RAnal *anal, const RAnalFunction *fcn, RAnalSnapshotRegisterStorage *storage) {
	ut32 address_size;
	if (!anal->reg || !snapshot_function_address_size (fcn, &address_size)) {
		return SNAPSHOT_STORAGE_INVALID;
	}
	SnapshotStorageResult collected = snapshot_register_storage_collect (
		anal, r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP), storage);
	if (collected == SNAPSHOT_STORAGE_VALID && storage->size != address_size) {
		snapshot_register_storage_fini (storage);
		return SNAPSHOT_STORAGE_INVALID;
	}
	return collected;
}

static bool snapshot_register_storage_resolve(RAnal *anal, const char *name, ut64 *offset, ut32 *size) {
	if (R_STR_ISEMPTY (name) || !anal->reg) {
		return false;
	}
	RRegItem *item = r_reg_get (anal->reg, name, -1);
	if (!item || item->offset < 0 || item->offset % 8
		|| item->size <= 0 || item->size % 8) {
		r_unref (item);
		return false;
	}
	*offset = (ut64)(item->offset / 8);
	*size = (ut32)(item->size / 8);
	r_unref (item);
	return true;
}

static bool snapshot_cc_argument_storage(RAnal *anal, const char *calling_convention, int index, int count, ut64 *offset, ut32 *size) {
	const char *place = r_anal_cc_argloc (anal, calling_convention, index, 0, count);
	RAnalCCArgSlot slot = {0};
	return R_STR_ISNOTEMPTY (place) && *place != '^' && *place != '{'
		&& r_anal_cc_argslot (anal, calling_convention, index, count, false, &slot)
		&& slot.reg && snapshot_register_storage_resolve (anal, slot.reg, offset, size);
}

static bool snapshot_cc_maps_register_interface(RAnal *anal, const RAnalFunctionSignature *signature, const char *calling_convention) {
	if (!signature || R_STR_ISEMPTY (calling_convention)
		|| !r_anal_cc_exist (anal, calling_convention)) {
		return false;
	}
	size_t parameter_count = (size_t)r_list_length (signature->params);
	if (parameter_count > INT_MAX) {
		return false;
	}
	size_t i;
	for (i = 0; i < parameter_count; i++) {
		ut64 offset;
		ut32 size;
		if (!snapshot_cc_argument_storage (anal, calling_convention, (int)i,
				(int)parameter_count, &offset, &size)) {
			return false;
		}
		ut64 end;
		if (r_add_overflow (offset, (ut64)size, &end)) {
			return false;
		}
		size_t j;
		for (j = 0; j < i; j++) {
			ut64 previous_offset;
			ut32 previous_size;
			ut64 previous_end;
			if (!snapshot_cc_argument_storage (anal, calling_convention, (int)j,
					(int)parameter_count, &previous_offset, &previous_size)
				|| r_add_overflow (previous_offset, (ut64)previous_size, &previous_end)
				|| (offset < previous_end && previous_offset < end)) {
				return false;
			}
		}
	}
	if (!strcmp (r_str_get (signature->ret_type), "void")) {
		return true;
	}
	if (R_STR_ISEMPTY (signature->ret_type)) {
		return false;
	}
	const char *return_name = r_anal_cc_ret (anal, calling_convention, 0);
	const char *second_return = r_anal_cc_ret (anal, calling_convention, 1);
	ut64 return_offset;
	ut32 return_size;
	return R_STR_ISNOTEMPTY (return_name) && *return_name != '{'
		&& *return_name != '^' && R_STR_ISEMPTY (second_return)
		&& snapshot_register_storage_resolve (
			anal, return_name, &return_offset, &return_size);
}

static bool snapshot_promote_exact_dwarf_stack_homes(
	RAnal *anal, RAnalFunction *fcn, RAnalFcnContext *ctx,
	RAnalFunctionInterfaceSnapshot *interface, const char *calling_convention) {
	if (!ctx->signature
		|| !r_anal_function_has_address_linked_signature_current (fcn)) {
		return true;
	}
	const size_t parameter_count = (size_t)r_list_length (ctx->signature->params);
	RListIter *iter;
	RAnalFcnSlot *slot;
	r_list_foreach (ctx->fcn_slots, iter, slot) {
		if (!slot || slot->role != R_ANAL_FCN_SLOT_ARG
			|| (slot->base != R_ANAL_FCN_BASE_BP
				&& slot->base != R_ANAL_FCN_BASE_SP)
			|| slot->arg_index < 0
			|| (size_t)slot->arg_index >= parameter_count
			|| (size_t)slot->arg_index >= interface->num_parameters) {
			continue;
		}
		const RAnalFunctionParam *signature_parameter =
			r_list_get_n (ctx->signature->params, slot->arg_index);
		if (!signature_parameter || R_STR_ISEMPTY (slot->type)
			|| R_STR_ISEMPTY (signature_parameter->type)
			|| strcmp (slot->type, signature_parameter->type)) {
			continue;
		}
		const char *place = r_anal_cc_argloc (anal, calling_convention,
			slot->arg_index, 0, (int)parameter_count);
		RAnalCCArgSlot abi_slot = {0};
		if (R_STR_ISEMPTY (place) || *place == '^' || *place == '{'
			|| !r_anal_cc_argslot (anal, calling_convention,
				slot->arg_index, (int)parameter_count, false, &abi_slot)
			|| !abi_slot.reg) {
			continue;
		}
		RAnalSnapshotRegisterStorage storage = {0};
		SnapshotStorageResult collected = snapshot_register_storage_collect (
			anal, abi_slot.reg, &storage);
		if (collected == SNAPSHOT_STORAGE_NO_MEMORY) {
			return false;
		}
		const RAnalSnapshotRegisterStorage *parameter_storage =
			&interface->parameters[slot->arg_index].storage;
		if (collected != SNAPSHOT_STORAGE_VALID
			|| R_STR_ISEMPTY (parameter_storage->name)
			|| strcmp (storage.name, parameter_storage->name)
			|| storage.offset != parameter_storage->offset
			|| storage.size != parameter_storage->size) {
			snapshot_register_storage_fini (&storage);
			continue;
		}
		slot->role = R_ANAL_FCN_SLOT_HOME;
		slot->home_reg = storage.name;
		slot->home_reg_offset = storage.offset;
		slot->home_reg_size = storage.size;
	}
	return true;
}

static bool snapshot_parameter_storages_overlap(
	const RAnalSnapshotParameter *parameters, size_t count) {
	size_t i, j;
	for (i = 0; i < count; i++) {
		ut64 left_end;
		if (r_add_overflow (parameters[i].storage.offset,
				(ut64)parameters[i].storage.size, &left_end)) {
			return true;
		}
		for (j = i + 1; j < count; j++) {
			ut64 right_end;
			if (r_add_overflow (parameters[j].storage.offset,
					(ut64)parameters[j].storage.size, &right_end)
				|| (parameters[i].storage.offset < right_end
					&& parameters[j].storage.offset < left_end)) {
				return true;
			}
		}
	}
	return false;
}

static bool snapshot_register_storages_overlap(
	const RAnalSnapshotRegisterStorage *left,
	const RAnalSnapshotRegisterStorage *right) {
	ut64 left_end;
	ut64 right_end;
	return !left->size || !right->size
		|| r_add_overflow (left->offset, (ut64)left->size, &left_end)
		|| r_add_overflow (right->offset, (ut64)right->size, &right_end)
		|| (left->offset < right_end && right->offset < left_end);
}

static bool snapshot_register_storages_equal(
	const RAnalSnapshotRegisterStorage *left,
	const RAnalSnapshotRegisterStorage *right) {
	return left->size && right->size
		&& left->offset == right->offset && left->size == right->size;
}

static bool snapshot_return_address_storage_overlaps_interface(
	const RAnalFunctionInterfaceSnapshot *interface, const RAnalFcnContext *ctx) {
	if (interface->stack_pointer_storage.name
		&& interface->stack_pointer_storage.size
		&& snapshot_register_storages_overlap (
			&interface->return_address_storage,
			&interface->stack_pointer_storage)) {
		return true;
	}
	size_t i;
	for (i = 0; i < interface->num_parameters; i++) {
		if (interface->parameters[i].storage.name
			&& interface->parameters[i].storage.size
			&& snapshot_register_storages_overlap (
				&interface->return_address_storage,
				&interface->parameters[i].storage)) {
			return true;
		}
	}
	if (interface->return_kind == R_ANAL_SNAPSHOT_RETURN_REGISTER
		&& snapshot_register_storages_overlap (
			&interface->return_address_storage, &interface->return_storage)) {
		return true;
	}
	RListIter *iter;
	RAnalFcnSlot *slot;
	r_list_foreach (ctx->fcn_slots, iter, slot) {
		if (!slot) {
			continue;
		}
		RAnalSnapshotRegisterStorage base_storage = {
			.offset = slot->base_offset,
			.size = slot->base_size,
		};
		if (slot->base_name && slot->base_size
			&& snapshot_register_storages_overlap (
				&interface->return_address_storage, &base_storage)) {
			return true;
		}
		RAnalSnapshotRegisterStorage home_storage = {
			.offset = slot->home_reg_offset,
			.size = slot->home_reg_size,
		};
		if (slot->home_reg && slot->home_reg_size
			&& snapshot_register_storages_overlap (
				&interface->return_address_storage, &home_storage)) {
			return true;
		}
	}
	return false;
}

static bool snapshot_stack_pointer_storage_conflicts_interface(
	const RAnalFunctionInterfaceSnapshot *interface, const RAnalFcnContext *ctx) {
	if (interface->return_address_storage.name
		&& interface->return_address_storage.size
		&& snapshot_register_storages_overlap (
			&interface->stack_pointer_storage,
			&interface->return_address_storage)) {
		return true;
	}
	size_t i;
	for (i = 0; i < interface->num_parameters; i++) {
		if (interface->parameters[i].storage.name
			&& interface->parameters[i].storage.size
			&& snapshot_register_storages_overlap (
				&interface->stack_pointer_storage,
				&interface->parameters[i].storage)) {
			return true;
		}
	}
	if (interface->return_kind == R_ANAL_SNAPSHOT_RETURN_REGISTER
		&& snapshot_register_storages_overlap (
			&interface->stack_pointer_storage, &interface->return_storage)) {
		return true;
	}
	RListIter *iter;
	RAnalFcnSlot *slot;
	r_list_foreach (ctx->fcn_slots, iter, slot) {
		if (!slot) {
			continue;
		}
		RAnalSnapshotRegisterStorage base_storage = {
			.offset = slot->base_offset,
			.size = slot->base_size,
		};
		if (slot->base == R_ANAL_FCN_BASE_SP) {
			if (R_STR_ISEMPTY (slot->base_name) || !snapshot_register_storages_equal (
					&interface->stack_pointer_storage, &base_storage)) {
				return true;
			}
		} else if (slot->base_size
			&& snapshot_register_storages_overlap (
				&interface->stack_pointer_storage, &base_storage)) {
			return true;
		}
		RAnalSnapshotRegisterStorage home_storage = {
			.offset = slot->home_reg_offset,
			.size = slot->home_reg_size,
		};
		if (slot->home_reg && slot->home_reg_size
			&& snapshot_register_storages_overlap (
				&interface->stack_pointer_storage, &home_storage)) {
			return true;
		}
	}
	return false;
}

static bool snapshot_stack_resources_complete(const RAnalFcnContext *ctx) {
	RListIter *left_iter;
	RAnalFcnSlot *left;
	r_list_foreach (ctx->fcn_slots, left_iter, left) {
		if (!left || (left->base != R_ANAL_FCN_BASE_BP
				&& left->base != R_ANAL_FCN_BASE_SP)
			|| R_STR_ISEMPTY (left->base_name) || !left->base_size
			|| left->base_offset > UT64_MAX - left->base_size
			|| !left->offset_valid || !left->size
			|| left->offset > ST64_MAX - (st64)left->size) {
			return false;
		}
		const st64 left_end = left->offset + (st64)left->size;
		RListIter *right_iter;
		for (right_iter = left_iter->n; right_iter; right_iter = right_iter->n) {
			RAnalFcnSlot *right = right_iter->data;
			if (!right || right->base != left->base) {
				continue;
			}
			if (!right->offset_valid || !right->size
				|| right->offset > ST64_MAX - (st64)right->size) {
				return false;
			}
			const st64 right_end = right->offset + (st64)right->size;
			if (left->offset < right_end && right->offset < left_end) {
				return false;
			}
		}
	}
	return true;
}

static bool snapshot_stack_slot_roles_complete(
	const RAnalFcnContext *ctx, const RAnalFunctionInterfaceSnapshot *interface) {
	RListIter *iter;
	RAnalFcnSlot *slot;
	r_list_foreach (ctx->fcn_slots, iter, slot) {
		if (!slot) {
			return false;
		}
		if (slot->role == R_ANAL_FCN_SLOT_LOCAL) {
			if (slot->arg_index != -1 || slot->home_reg_offset
				|| slot->home_reg_size) {
				return false;
			}
			continue;
		}
		if (slot->role != R_ANAL_FCN_SLOT_HOME || slot->arg_index < 0
			|| (size_t)slot->arg_index >= interface->num_parameters
			|| !slot->home_reg_size
			|| slot->home_reg_offset > UT64_MAX - slot->home_reg_size) {
			return false;
		}
		const RAnalSnapshotParameter *parameter =
			&interface->parameters[slot->arg_index];
		if (parameter->index != (ut32)slot->arg_index
			|| slot->home_reg_offset != parameter->storage.offset
			|| slot->home_reg_size != parameter->storage.size) {
			return false;
		}
		RListIter *previous_iter;
		RAnalFcnSlot *previous;
		r_list_foreach (ctx->fcn_slots, previous_iter, previous) {
			if (previous == slot) {
				break;
			}
			if (previous && previous->role == R_ANAL_FCN_SLOT_HOME
				&& previous->arg_index == slot->arg_index) {
				return false;
			}
		}
	}
	return true;
}

/* Record where the calling convention would place arguments and the result.
 *
 * These slots describe the convention, not the function: they are collected even
 * when no signature was recovered, and they say where a caller would leave a
 * value rather than that this function takes one. A consumer that recovers
 * parameters from the machine code needs the candidate list to intersect
 * against, and importing a guessed prototype instead would defeat the point. */
static bool snapshot_convention_slots_collect(
	RAnal *anal, RAnalFunction *fcn, RAnalFunctionInterfaceSnapshot *interface) {
	const char *convention = R_STR_ISNOTEMPTY (fcn->callconv)
		? fcn->callconv
		: r_anal_cc_default (anal);
	if (R_STR_ISEMPTY (convention) || !r_anal_cc_exist (anal, convention)) {
		return true;
	}
	/* Name the convention even when no signature was recovered: a consumer that
	 * recovers parameters from machine code needs to know which convention the
	 * candidate slots belong to. The signature path below replaces this when it
	 * resolves a more specific convention. */
	if (!interface->calling_convention) {
		interface->calling_convention = strdup (convention);
		if (!interface->calling_convention) {
			return false;
		}
	}
	RAnalSnapshotRegisterStorage slots[R_ANAL_CC_MAXARG] = {0};
	size_t count = 0;
	while (count < R_ANAL_CC_MAXARG) {
		RAnalCCArgSlot slot = {0};
		if (!r_anal_cc_argslot (anal, convention, (int)count, -1, false, &slot)
			|| R_STR_ISEMPTY (slot.reg)) {
			break;
		}
		if (snapshot_register_storage_collect (anal, slot.reg, &slots[count])
				!= SNAPSHOT_STORAGE_VALID) {
			break;
		}
		count++;
	}
	if (!count) {
		return true;
	}
	interface->convention_argument_slots = R_NEWS0 (RAnalSnapshotRegisterStorage, count);
	if (!interface->convention_argument_slots) {
		for (size_t i = 0; i < count; i++) {
			snapshot_register_storage_fini (&slots[i]);
		}
		return false;
	}
	for (size_t i = 0; i < count; i++) {
		interface->convention_argument_slots[i] = slots[i];
	}
	interface->num_convention_argument_slots = count;
	const char *result = r_anal_cc_ret (anal, convention, 0);
	if (R_STR_ISNOTEMPTY (result)
		&& snapshot_register_storage_collect (anal, result,
			&interface->convention_result_slot) == SNAPSHOT_STORAGE_NO_MEMORY) {
		return false;
	}
	interface->convention_slots_known = true;
	return true;
}

static bool function_interface_snapshot_collect(
	RAnal *anal, RAnalFunction *fcn, RAnalFcnContext *ctx,
	RAnalFunctionInterfaceSnapshot *interface,
	const RAnalFunctionSnapshotLimits *limits) {
	interface->return_type_id = R_ANAL_SNAPSHOT_TYPE_ID_INVALID;
	interface->variadic = fcn->is_variadic;
	interface->noreturn = fcn->is_noreturn;
	interface->stack_resources_complete = snapshot_stack_resources_complete (ctx);
	SnapshotStorageResult return_address_collected =
		snapshot_return_address_storage_collect (
			anal, fcn, &interface->return_address_storage);
	if (return_address_collected == SNAPSHOT_STORAGE_NO_MEMORY) {
		return false;
	}
	SnapshotStorageResult stack_pointer_collected =
		snapshot_stack_pointer_storage_collect (
			anal, fcn, &interface->stack_pointer_storage);
	if (stack_pointer_collected == SNAPSHOT_STORAGE_NO_MEMORY) {
		return false;
	}
	bool return_address_complete = return_address_collected == SNAPSHOT_STORAGE_VALID;
	bool stack_pointer_complete = stack_pointer_collected == SNAPSHOT_STORAGE_VALID;
	const bool return_address_conflict = return_address_complete
		&& snapshot_return_address_storage_overlaps_interface (interface, ctx);
	const bool stack_pointer_conflict = stack_pointer_complete
		&& snapshot_stack_pointer_storage_conflicts_interface (interface, ctx);
	if (return_address_conflict) {
		snapshot_register_storage_fini (&interface->return_address_storage);
		return_address_complete = false;
	}
	if (stack_pointer_conflict) {
		snapshot_register_storage_fini (&interface->stack_pointer_storage);
		stack_pointer_complete = false;
	}
	if (!snapshot_convention_slots_collect (anal, fcn, interface)) {
		return false;
	}
	if (!ctx->signature || !r_anal_function_has_address_linked_signature_current (fcn)) {
		return true;
	}
	const char *signature_calling_convention = ctx->signature->callconv;
	const char *live_calling_convention = fcn->callconv;
	const char *calling_convention = R_STR_ISNOTEMPTY (signature_calling_convention)
		? signature_calling_convention
		: live_calling_convention;
	if (R_STR_ISNOTEMPTY (signature_calling_convention)
		&& !snapshot_cc_maps_register_interface (
			anal, ctx->signature, signature_calling_convention)
		&& R_STR_ISNOTEMPTY (live_calling_convention)
		&& strcmp (signature_calling_convention, live_calling_convention)
		&& snapshot_cc_maps_register_interface (
			anal, ctx->signature, live_calling_convention)) {
		calling_convention = live_calling_convention;
	}
	if (R_STR_ISEMPTY (calling_convention) || !r_anal_cc_exist (anal, calling_convention)) {
		return true;
	}
	free (interface->calling_convention);
	interface->calling_convention = strdup (calling_convention);
	if (!interface->calling_convention) {
		return false;
	}
	size_t parameter_count = (size_t)r_list_length (ctx->signature->params);
	if (parameter_count > INT_MAX || parameter_count > UT32_MAX
		|| parameter_count > limits->max_interface_parameters) {
		return false;
	}
	size_t allocation_size;
	if (r_mul_overflow (parameter_count, sizeof (RAnalSnapshotParameter), &allocation_size)) {
		return false;
	}
	if (allocation_size) {
		interface->parameters = calloc (1, allocation_size);
		if (!interface->parameters) {
			return false;
		}
	}
	interface->num_parameters = parameter_count;
	bool parameters_complete = true;
	RListIter *iter;
	RAnalFunctionParam *parameter;
	size_t index = 0;
	r_list_foreach (ctx->signature->params, iter, parameter) {
		RAnalSnapshotParameter *snapshot_parameter = &interface->parameters[index];
		snapshot_parameter->index = (ut32)index;
		snapshot_parameter->logical_type_id = R_ANAL_SNAPSHOT_TYPE_ID_INVALID;
		if (parameter && R_STR_ISNOTEMPTY (parameter->name)) {
			snapshot_parameter->name = strdup (parameter->name);
			if (!snapshot_parameter->name) {
				return false;
			}
		}
		if (!parameter || R_STR_ISEMPTY (parameter->type)) {
			parameters_complete = false;
		}
		const char *place = r_anal_cc_argloc (
			anal, calling_convention, (int)index, 0, (int)parameter_count);
		RAnalCCArgSlot slot = {0};
		if (R_STR_ISEMPTY (place) || *place == '^' || *place == '{'
			|| !r_anal_cc_argslot (anal, calling_convention,
				(int)index, (int)parameter_count, false, &slot)
			|| !slot.reg) {
			parameters_complete = false;
			index++;
			continue;
		}
		SnapshotStorageResult collected = snapshot_register_storage_collect (
			anal, slot.reg, &snapshot_parameter->storage);
		if (collected == SNAPSHOT_STORAGE_NO_MEMORY) {
			return false;
		}
		if (collected != SNAPSHOT_STORAGE_VALID) {
			parameters_complete = false;
		}
		index++;
	}
	if (index != parameter_count
		|| snapshot_parameter_storages_overlap (interface->parameters, parameter_count)) {
		parameters_complete = false;
	}
	if (!snapshot_promote_exact_dwarf_stack_homes (
			anal, fcn, ctx, interface, calling_convention)) {
		return false;
	}
	bool return_complete = false;
	if (!strcmp (r_str_get (ctx->signature->ret_type), "void")) {
		interface->return_kind = R_ANAL_SNAPSHOT_RETURN_VOID;
		return_complete = true;
	} else if (R_STR_ISNOTEMPTY (ctx->signature->ret_type)) {
		const char *return_name = r_anal_cc_ret (anal, calling_convention, 0);
		const char *second_return = r_anal_cc_ret (anal, calling_convention, 1);
		if (R_STR_ISNOTEMPTY (return_name) && *return_name != '{'
			&& *return_name != '^' && R_STR_ISEMPTY (second_return)) {
			SnapshotStorageResult collected = snapshot_register_storage_collect (
				anal, return_name, &interface->return_storage);
			if (collected == SNAPSHOT_STORAGE_NO_MEMORY) {
				return false;
			}
			if (collected == SNAPSHOT_STORAGE_VALID) {
				interface->return_kind = R_ANAL_SNAPSHOT_RETURN_REGISTER;
				return_complete = true;
			}
		}
	}
	const bool final_return_address_conflict = return_address_complete
		&& snapshot_return_address_storage_overlaps_interface (interface, ctx);
	const bool final_stack_pointer_conflict = stack_pointer_complete
		&& snapshot_stack_pointer_storage_conflicts_interface (interface, ctx);
	if (final_return_address_conflict) {
		snapshot_register_storage_fini (&interface->return_address_storage);
		return_address_complete = false;
	}
	if (final_stack_pointer_conflict) {
		snapshot_register_storage_fini (&interface->stack_pointer_storage);
		stack_pointer_complete = false;
	}
	// noreturn says control does not come back, which is not a statement about
	// whether the parameter and return storage were recovered. Every field the
	// completeness of this interface rests on was resolved independently of it,
	// and the call-site path computes the same notion without consulting it, so
	// letting it disqualify an interface discards recovered storage for every
	// exit, abort and assert helper.
	// the frame extent is a separate claim, so it is not what makes an interface exact
	const bool physical_interface_complete = parameters_complete && return_complete
		&& return_address_complete && stack_pointer_complete
		&& !interface->variadic;
	// The convention names the carriers a callee restores, which is what lets a
	// consumer treat them as surviving a call instead of withholding every
	// entry-relative fact from any function that makes one.
	const char *sp_name = anal->reg
		? r_reg_alias_getname (anal->reg, R_REG_ALIAS_SP): NULL;
	const char *fp_name = anal->reg
		? r_reg_alias_getname (anal->reg, R_REG_ALIAS_BP): NULL;
	interface->stack_pointer_preserved_across_calls =
		r_anal_cc_preserves_reg (anal, interface->calling_convention, sp_name);
	interface->frame_pointer_preserved_across_calls =
		r_anal_cc_preserves_reg (anal, interface->calling_convention, fp_name);
	// roles carry the extent claim: unsized slots cannot prove they do not overlap
	interface->stack_slot_roles_complete = physical_interface_complete
		&& interface->stack_resources_complete
		&& snapshot_stack_slot_roles_complete (ctx, interface);
	interface->complete = physical_interface_complete;
	return true;
}

static void snapshot_return_mechanism_collect(RAnal *anal, const RAnalFunction *fcn,
		const RAnalFcnContext *ctx, const RAnalFunctionInterfaceSnapshot *interface,
		RAnalSnapshotReturnMechanismView *view) {
	*view = (RAnalSnapshotReturnMechanismView) {0};
	if (!interface->complete || R_STR_ISEMPTY (interface->calling_convention)) {
		return;
	}
	ut32 address_size;
	if (!snapshot_function_address_size (fcn, &address_size)
		|| R_STR_ISEMPTY (interface->return_address_storage.name)
		|| R_STR_ISEMPTY (interface->stack_pointer_storage.name)
		|| interface->return_address_storage.size != address_size
		|| interface->stack_pointer_storage.size != address_size) {
		return;
	}
	RAnalCCReturnMechanism mechanism = {0};
	if (!r_anal_cc_return_mechanism (
			anal, interface->calling_convention, &mechanism)
		|| mechanism.kind != R_ANAL_CC_RETURN_MECHANISM_STACK
		|| mechanism.entry_sp_offset != 0
		|| mechanism.slot_size != address_size
		|| mechanism.exit_sp_delta != (st64)mechanism.slot_size) {
		return;
	}
	RListIter *iter;
	RAnalFcnSlot *slot;
	r_list_foreach (ctx->fcn_slots, iter, slot) {
		if (!slot || slot->base != R_ANAL_FCN_BASE_SP
			|| R_STR_ISEMPTY (slot->base_name)
			|| strcmp (slot->base_name, interface->stack_pointer_storage.name)
			|| slot->base_offset != interface->stack_pointer_storage.offset
			|| slot->base_size != interface->stack_pointer_storage.size) {
			continue;
		}
		if (!slot->offset_valid || !slot->size
			|| slot->offset > ST64_MAX - (st64)slot->size) {
			return;
		}
		const st64 slot_end = slot->offset + (st64)slot->size;
		if (slot->offset < (st64)mechanism.slot_size && slot_end > 0) {
			return;
		}
	}
	*view = (RAnalSnapshotReturnMechanismView) {
		.kind = R_ANAL_SNAPSHOT_RETURN_MECHANISM_STACK,
		.entry_sp_offset = mechanism.entry_sp_offset,
		.slot_size = mechanism.slot_size,
		.exit_sp_delta = mechanism.exit_sp_delta,
	};
}

static bool snapshot_return_mechanism_equal(const RAnalSnapshotReturnMechanismView *a,
		const RAnalSnapshotReturnMechanismView *b) {
	return a->kind == b->kind
		&& a->entry_sp_offset == b->entry_sp_offset
		&& a->slot_size == b->slot_size
		&& a->exit_sp_delta == b->exit_sp_delta;
}

static void snapshot_stack_allocation_contract_collect(RAnal *anal,
		const RAnalFunctionInterfaceSnapshot *interface,
		RAnalSnapshotStackAllocationContractView *view) {
	*view = (RAnalSnapshotStackAllocationContractView) {0};
	if (!interface->complete || R_STR_ISEMPTY (interface->calling_convention)
		|| R_STR_ISEMPTY (interface->stack_pointer_storage.name)
		|| !interface->stack_pointer_storage.size) {
		return;
	}
	RAnalCCStackAllocationContract contract = {0};
	if (!r_anal_cc_stack_allocation_contract (
			anal, interface->calling_convention, &contract)) {
		return;
	}
	view->implicit_active_sp_bytes = contract.red_zone_bytes;
	switch (contract.growth) {
	case R_ANAL_CC_STACK_GROWTH_LOWER:
		view->growth = R_ANAL_SNAPSHOT_STACK_GROWTH_LOWER;
		break;
	case R_ANAL_CC_STACK_GROWTH_HIGHER:
		view->growth = R_ANAL_SNAPSHOT_STACK_GROWTH_HIGHER;
		break;
	case R_ANAL_CC_STACK_GROWTH_NONE:
	default:
		break;
	}
}

static bool snapshot_stack_allocation_contract_equal(
		const RAnalSnapshotStackAllocationContractView *a,
		const RAnalSnapshotStackAllocationContractView *b) {
	return a->growth == b->growth
		&& a->implicit_active_sp_bytes == b->implicit_active_sp_bytes;
}

static bool snapshot_frame_pointer_storage_conflicts_interface(
		const RAnalSnapshotRegisterStorage *storage,
		const RAnalFunctionInterfaceSnapshot *interface,
		const RAnalFcnContext *ctx) {
	if (snapshot_register_storages_overlap (
			storage, &interface->return_address_storage)
		|| snapshot_register_storages_overlap (
			storage, &interface->stack_pointer_storage)) {
		return true;
	}
	size_t i;
	for (i = 0; i < interface->num_parameters; i++) {
		if (snapshot_register_storages_overlap (
				storage, &interface->parameters[i].storage)) {
			return true;
		}
	}
	if (interface->return_kind == R_ANAL_SNAPSHOT_RETURN_REGISTER
		&& snapshot_register_storages_overlap (
			storage, &interface->return_storage)) {
		return true;
	}
	RListIter *iter;
	RAnalFcnSlot *slot;
	r_list_foreach (ctx->fcn_slots, iter, slot) {
		if (!slot) {
			return true;
		}
		RAnalSnapshotRegisterStorage home = {
			.offset = slot->home_reg_offset,
			.size = slot->home_reg_size,
		};
		if (slot->home_reg && slot->home_reg_size
			&& snapshot_register_storages_overlap (storage, &home)) {
			return true;
		}
		if (slot->base == R_ANAL_FCN_BASE_BP) {
			RAnalSnapshotRegisterStorage base = {
				.offset = slot->base_offset,
				.size = slot->base_size,
			};
			if (!snapshot_register_storages_equal (storage, &base)) {
				return true;
			}
		}
	}
	return false;
}

static bool snapshot_frame_pointer_storage_collect(RAnal *anal,
		const RAnalFunction *fcn, const RAnalFcnContext *ctx,
		const RAnalFunctionInterfaceSnapshot *interface,
		RAnalSnapshotRegisterStorage *storage) {
	if (!interface->complete
		|| !r_anal_function_has_address_linked_signature_current (
			(RAnalFunction *)fcn)) {
		return true;
	}
	RAnalDwarfFramePointerStorage proof = {0};
	if (!r_anal_dwarf_function_frame_pointer_get (
			anal, fcn->addr, &proof)) {
		return true;
	}
	ut32 address_size;
	RAnalSnapshotRegisterStorage candidate = {0};
	SnapshotStorageResult collected = snapshot_register_storage_collect (
		anal, proof.name, &candidate);
	if (collected == SNAPSHOT_STORAGE_NO_MEMORY) {
		r_anal_dwarf_frame_pointer_storage_fini (&proof);
		return false;
	}
	const bool exact = collected == SNAPSHOT_STORAGE_VALID
		&& snapshot_function_address_size (fcn, &address_size)
		&& candidate.size == address_size
		&& !strcmp (candidate.name, proof.name)
		&& candidate.offset == proof.offset
		&& candidate.size == proof.size
		&& !snapshot_frame_pointer_storage_conflicts_interface (
			&candidate, interface, ctx);
	r_anal_dwarf_frame_pointer_storage_fini (&proof);
	if (!exact) {
		snapshot_register_storage_fini (&candidate);
		return true;
	}
	*storage = candidate;
	return true;
}

static bool snapshot_frame_pointer_storage_equal(
		const RAnalSnapshotRegisterStorage *a,
		const RAnalSnapshotRegisterStorage *b) {
	return !strcmp (r_str_get (a->name), r_str_get (b->name))
		&& a->offset == b->offset && a->size == b->size;
}

typedef enum {
	SNAPSHOT_TYPE_GRAPH_UNSUPPORTED = 0,
	SNAPSHOT_TYPE_GRAPH_VALID,
	SNAPSHOT_TYPE_GRAPH_NO_MEMORY,
} SnapshotTypeGraphResult;

static int snapshot_base_type_compare(const void *left, const void *right) {
	const RAnalBaseType *a = left;
	const RAnalBaseType *b = right;
	const int name_cmp = strcmp (r_str_get (a? a->name: NULL),
		r_str_get (b? b->name: NULL));
	if (name_cmp || !a || !b || a->kind == b->kind) {
		return name_cmp;
	}
	return a->kind < b->kind? -1: 1;
}

static bool snapshot_nullable_string_equal(const char *left, const char *right) {
	return (!left && !right) || (left && right && !strcmp (left, right));
}

static bool snapshot_base_type_equal(const RAnalBaseType *left, const RAnalBaseType *right) {
	if (!left || !right) {
		return left == right;
	}
	if (left->kind != right->kind || left->size != right->size
		|| !snapshot_nullable_string_equal (left->name, right->name)
		|| !snapshot_nullable_string_equal (left->type, right->type)) {
		return false;
	}
	if (left->kind == R_ANAL_BASE_TYPE_KIND_STRUCT
		|| left->kind == R_ANAL_BASE_TYPE_KIND_UNION) {
		const RVecAnalTypeMember *left_members = r_anal_base_type_members (left);
		const RVecAnalTypeMember *right_members = r_anal_base_type_members (right);
		const size_t count = RVecAnalTypeMember_length (left_members);
		if (count != RVecAnalTypeMember_length (right_members)) {
			return false;
		}
		size_t i;
		for (i = 0; i < count; i++) {
			const RAnalTypeMember *a = RVecAnalTypeMember_at (left_members, i);
			const RAnalTypeMember *b = RVecAnalTypeMember_at (right_members, i);
			if (a->offset != b->offset || a->bitsize != b->bitsize
				|| a->count != b->count
				|| !snapshot_nullable_string_equal (a->name, b->name)
				|| !snapshot_nullable_string_equal (a->type, b->type)) {
				return false;
			}
		}
	} else if (left->kind == R_ANAL_BASE_TYPE_KIND_ENUM) {
		const size_t count = RVecAnalEnumCase_length (&left->enum_data.cases);
		if (count != RVecAnalEnumCase_length (&right->enum_data.cases)) {
			return false;
		}
		size_t i;
		for (i = 0; i < count; i++) {
			const RAnalEnumCase *a = RVecAnalEnumCase_at (&left->enum_data.cases, i);
			const RAnalEnumCase *b = RVecAnalEnumCase_at (&right->enum_data.cases, i);
			if (a->val != b->val
				|| !snapshot_nullable_string_equal (a->name, b->name)) {
				return false;
			}
		}
	}
	return true;
}

static bool snapshot_base_types_equal(const RList *left, const RList *right) {
	if (!left || !right || r_list_length (left) != r_list_length (right)) {
		return false;
	}
	RListIter *left_iter = r_list_iterator (left);
	RListIter *right_iter = r_list_iterator (right);
	while (left_iter && right_iter) {
		if (!snapshot_base_type_equal (left_iter->data, right_iter->data)) {
			return false;
		}
		left_iter = left_iter->n;
		right_iter = right_iter->n;
	}
	return !left_iter && !right_iter;
}

static bool snapshot_base_type_string_add(size_t *total, const char *string) {
	if (!string) {
		return true;
	}
	size_t bytes;
	return !r_add_overflow_size_t (strlen (string), 1, &bytes)
		&& !r_add_overflow_size_t (*total, bytes, total);
}

static bool snapshot_base_type_string_bytes(const RList *base_types, size_t *result) {
	size_t total = 0;
	RListIter *iter;
	RAnalBaseType *base;
	r_list_foreach (base_types, iter, base) {
		if (!base || !snapshot_base_type_string_add (&total, base->name)
			|| !snapshot_base_type_string_add (&total, base->type)) {
			return false;
		}
		switch (base->kind) {
		case R_ANAL_BASE_TYPE_KIND_STRUCT: {
			RAnalStructMember *member;
			R_VEC_FOREACH (&base->struct_data.members, member) {
				if (!snapshot_base_type_string_add (&total, member->name)
					|| !snapshot_base_type_string_add (&total, member->type)) {
					return false;
				}
			}
			break;
		}
		case R_ANAL_BASE_TYPE_KIND_UNION: {
			RAnalUnionMember *member;
			R_VEC_FOREACH (&base->union_data.members, member) {
				if (!snapshot_base_type_string_add (&total, member->name)
					|| !snapshot_base_type_string_add (&total, member->type)) {
					return false;
				}
			}
			break;
		}
		case R_ANAL_BASE_TYPE_KIND_ENUM: {
			RAnalEnumCase *cas;
			R_VEC_FOREACH (&base->enum_data.cases, cas) {
				if (!snapshot_base_type_string_add (&total, cas->name)) {
					return false;
				}
			}
			break;
		}
		default:
			break;
		}
	}
	*result = total;
	return true;
}

static void snapshot_type_resolver_select_current_roots(Sdb *type_db, RList *base_types) {
	RListIter *iter;
	RListIter *next;
	RAnalBaseType *base;
	r_list_foreach_safe (base_types, iter, next, base) {
		if (!base || R_STR_ISEMPTY (base->name)) {
			continue;
		}
		const char *current_kind = sdb_const_get (type_db, base->name, 0);
		const bool stale_atomic = base->kind == R_ANAL_BASE_TYPE_KIND_ATOMIC
			&& strcmp (r_str_get (current_kind), "type");
		const bool stale_typedef = base->kind == R_ANAL_BASE_TYPE_KIND_TYPEDEF
			&& strcmp (r_str_get (current_kind), "typedef");
		if (stale_atomic || stale_typedef) {
			r_list_delete (base_types, iter);
		}
	}
}

typedef struct {
	Sdb *type_db;
	RList *base_types;
	const RAnalFunctionSnapshotLimits *limits;
	size_t base_type_count;
	size_t string_bytes;
	bool valid;
} SnapshotTypeResolverCapture;

static bool snapshot_type_resolver_capture_cb(void *user, const char *name, const char *kind) {
	SnapshotTypeResolverCapture *capture = user;
	if (R_STR_ISEMPTY (name) || strcmp (r_str_get (kind), "type")
		|| strchr (name, '.')
		|| sdb_const_getf (capture->type_db, NULL, "type.%s", name)) {
		return true;
	}
	const ut64 bits = sdb_num_getf (capture->type_db, NULL, "type.%s.size", name);
	if (!bits) {
		return true;
	}
	RListIter *iter;
	RAnalBaseType *base;
	r_list_foreach (capture->base_types, iter, base) {
		if (base && base->kind == R_ANAL_BASE_TYPE_KIND_ATOMIC
			&& !strcmp (r_str_get (base->name), name)) {
			capture->valid = false;
			return false;
		}
	}
	size_t name_bytes;
	if (r_add_overflow_size_t (strlen (name), 1, &name_bytes)
		|| capture->base_type_count >= capture->limits->max_base_types
		|| name_bytes > capture->limits->max_base_type_string_bytes
			- capture->string_bytes) {
		capture->valid = false;
		return false;
	}
	base = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_ATOMIC);
	if (!base) {
		capture->valid = false;
		return false;
	}
	base->name = strdup (name);
	base->size = bits;
	if (!base->name || !r_list_append (capture->base_types, base)) {
		r_anal_base_type_free (base);
		capture->valid = false;
		return false;
	}
	capture->base_type_count++;
	capture->string_bytes += name_bytes;
	return true;
}

static RList *snapshot_type_resolver_capture(RAnal *anal, const RAnalFunctionSnapshotLimits *limits) {
	RList *base_types = r_anal_types_snapshot_with_limits (anal, limits);
	if (!base_types) {
		return NULL;
	}
	snapshot_type_resolver_select_current_roots (anal->sdb_types, base_types);
	SnapshotTypeResolverCapture capture = {
		.type_db = anal->sdb_types,
		.base_types = base_types,
		.limits = limits,
		.base_type_count = (size_t)r_list_length (base_types),
		.valid = true,
	};
	if (!snapshot_base_type_string_bytes (base_types, &capture.string_bytes)
		|| capture.base_type_count > limits->max_base_types
		|| capture.string_bytes > limits->max_base_type_string_bytes
		|| !sdb_foreach (anal->sdb_types, snapshot_type_resolver_capture_cb, &capture)
		|| !capture.valid) {
		r_list_free (base_types);
		return NULL;
	}
	r_list_sort (base_types, snapshot_base_type_compare);
	return base_types;
}

/* Signedness of plain `char` for one target.
 *
 * C leaves it implementation-defined and the ABIs disagree: x86 and MIPS make
 * it signed, while AArch64, ARM, PowerPC, RISC-V and s390 make it unsigned.
 * Returns false for a target whose choice is not recorded here, so callers can
 * decline instead of assuming one.
 */
static bool snapshot_arch_char_kind(const char *arch, RAnalSnapshotTypeKind *kind) {
	if (R_STR_ISEMPTY (arch)) {
		return false;
	}
	static const char *signed_arches[] = { "x86", "mips", "sparc", NULL };
	static const char *unsigned_arches[] = { "arm", "ppc", "riscv", "s390", NULL };
	size_t i;
	for (i = 0; signed_arches[i]; i++) {
		if (!strcmp (arch, signed_arches[i])) {
			*kind = R_ANAL_SNAPSHOT_TYPE_SIGNED_INTEGER;
			return true;
		}
	}
	for (i = 0; unsigned_arches[i]; i++) {
		if (!strcmp (arch, unsigned_arches[i])) {
			*kind = R_ANAL_SNAPSHOT_TYPE_UNSIGNED_INTEGER;
			return true;
		}
	}
	return false;
}

typedef struct {
	const RList *base_types;
	RAnalSnapshotTypeGraph *graph;
	const RAnalBaseType **aggregate_sources;
	size_t type_capacity;
	size_t aggregate_capacity;
	ut64 pointer_bits;
	// Plain char has no signedness in C: each target picks one. Absent when the
	// target's choice is not known here, so plain char stays unresolved rather
	// than being assigned a signedness it may not have.
	RAnalSnapshotTypeKind char_kind;
	bool char_kind_known;
} SnapshotTypeGraphBuilder;

static const RAnalBaseType *snapshot_type_find_unique_base(
	const RList *base_types, const char *name, RAnalBaseTypeKind kind,
	bool *ambiguous) {
	const RAnalBaseType *found = NULL;
	*ambiguous = false;
	RListIter *iter;
	RAnalBaseType *base;
	r_list_foreach (base_types, iter, base) {
		if (!base || base->kind != kind || strcmp (r_str_get (base->name), name)) {
			continue;
		}
		if (found) {
			*ambiguous = true;
			return NULL;
		}
		found = base;
	}
	return found;
}

static const RAnalBaseType *snapshot_type_find_bare_base(
	const SnapshotTypeGraphBuilder *builder, const char *name, bool *ambiguous) {
	static const RAnalBaseTypeKind preferred[] = {
		R_ANAL_BASE_TYPE_KIND_TYPEDEF,
		R_ANAL_BASE_TYPE_KIND_ATOMIC,
		R_ANAL_BASE_TYPE_KIND_ENUM,
		R_ANAL_BASE_TYPE_KIND_STRUCT,
	};
	const RAnalBaseType *bases[R_ARRAY_SIZE (preferred)] = {0};
	const RAnalBaseType *found = NULL;
	size_t i;
	*ambiguous = false;
	for (i = 0; i < R_ARRAY_SIZE (preferred); i++) {
		bases[i] = snapshot_type_find_unique_base (
			builder->base_types, name, preferred[i], ambiguous);
		if (*ambiguous) {
			return NULL;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (preferred); i++) {
		if (bases[i] && found) {
			*ambiguous = true;
			return NULL;
		}
		if (bases[i]) {
			found = bases[i];
		}
	}
	return found;
}

/* Remove cv-qualifier keywords from a type spec, in place.
 *
 * A qualifier changes none of what the type graph records: size, alignment,
 * signedness and storage are identical with or without it. Matching them as
 * substrings would also strike legitimate identifiers such as `atomic_t` or
 * `const_iterator`, so only whole words are removed.
 */
static void snapshot_type_strip_qualifiers(char *spec) {
	static const char *qualifiers[] = {
		"const", "volatile", "restrict", "__restrict", "_Atomic", NULL
	};
	size_t i;
	for (i = 0; qualifiers[i]; i++) {
		const size_t length = strlen (qualifiers[i]);
		char *cursor = spec;
		while ((cursor = strstr (cursor, qualifiers[i]))) {
			const bool starts_word = cursor == spec || !(isalnum ((unsigned char)cursor[-1])
				|| cursor[-1] == '_');
			char *after = cursor + length;
			const bool ends_word = !(isalnum ((unsigned char)*after) || *after == '_');
			if (!starts_word || !ends_word) {
				cursor = after;
				continue;
			}
			memmove (cursor, after, strlen (after) + 1);
		}
	}
	r_str_trim (spec);
	// Collapse the double blanks a removed qualifier leaves behind.
	char *read = spec;
	char *write = spec;
	bool blank = false;
	while (*read) {
		if (isspace ((unsigned char)*read)) {
			blank = true;
			read++;
			continue;
		}
		if (blank && write != spec) {
			*write++ = ' ';
		}
		blank = false;
		*write++ = *read++;
	}
	*write = '\0';
}

static bool snapshot_type_spec_rejected(const char *spec) {
	return R_STR_ISEMPTY (spec) || strchr (spec, '[') || strchr (spec, ']')
		|| strchr (spec, '(') || strchr (spec, ')')
		|| strstr (spec, "atomic");
}

static SnapshotTypeGraphResult snapshot_type_unalias(
	const SnapshotTypeGraphBuilder *builder, const char *type, char **result) {
	char *current = r_str_trim_dup (type);
	if (!current) {
		return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
	}
	snapshot_type_strip_qualifiers (current);
	size_t depth;
	const size_t maximum_depth = (size_t)r_list_length (builder->base_types) + 1;
	for (depth = 0; depth < maximum_depth; depth++) {
		if (snapshot_type_spec_rejected (current)) {
			free (current);
			return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
		}
		if (strchr (current, '*') || r_str_startswith (current, "struct ")
			|| r_str_startswith (current, "union ")) {
			*result = current;
			return SNAPSHOT_TYPE_GRAPH_VALID;
		}
		bool ambiguous;
		const RAnalBaseType *base = snapshot_type_find_bare_base (
			builder, current, &ambiguous);
		if (ambiguous) {
			free (current);
			return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
		}
		if (!base || base->kind != R_ANAL_BASE_TYPE_KIND_TYPEDEF) {
			*result = current;
			return SNAPSHOT_TYPE_GRAPH_VALID;
		}
		if (R_STR_ISEMPTY (base->type)) {
			free (current);
			return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
		}
		char *next = r_str_trim_dup (base->type);
		free (current);
		if (!next) {
			return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
		}
		current = next;
	}
	free (current);
	return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
}

typedef struct {
	bool valid;
	RAnalSnapshotTypeKind kind;
	ut64 required_bits;
} SnapshotIntegerSyntax;

static bool snapshot_type_integer_width_supported(ut64 bits) {
	return bits == 8 || bits == 16 || bits == 32 || bits == 64;
}

static SnapshotIntegerSyntax snapshot_type_integer_syntax(const char *spec) {
	SnapshotIntegerSyntax syntax = {0};
	const char *digits = NULL;
	if (r_str_startswith (spec, "uint")) {
		syntax.kind = R_ANAL_SNAPSHOT_TYPE_UNSIGNED_INTEGER;
		digits = spec + strlen ("uint");
	} else if (r_str_startswith (spec, "int")) {
		syntax.kind = R_ANAL_SNAPSHOT_TYPE_SIGNED_INTEGER;
		digits = spec + strlen ("int");
	}
	if (digits && *digits) {
		ut64 bits = 0;
		const char *cursor = digits;
		while (*cursor >= '0' && *cursor <= '9') {
			if (bits > (UT64_MAX - (ut64)(*cursor - '0')) / 10) {
				return syntax;
			}
			bits = bits * 10 + (ut64)(*cursor++ - '0');
		}
		if (!strcmp (cursor, "_t") && snapshot_type_integer_width_supported (bits)) {
			syntax.valid = true;
			syntax.required_bits = bits;
		}
		return syntax;
	}
	static const char *signed_specs[] = {
		"signed char", "short", "short int", "signed short",
		"signed short int", "int", "signed", "signed int", "long",
		"long int", "signed long", "signed long int", "long long",
		"long long int", "signed long long", "signed long long int",
	};
	static const char *unsigned_specs[] = {
		"unsigned char", "unsigned short", "unsigned short int", "unsigned",
		"unsigned int", "unsigned long", "unsigned long int",
		"unsigned long long", "unsigned long long int",
		// C fixes _Bool as unsigned, so unlike plain char this needs no
		// per-target choice. Both compilers spell it _Bool in debug info.
		"_Bool", "bool",
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (signed_specs); i++) {
		if (!strcmp (spec, signed_specs[i])) {
			syntax.valid = true;
			syntax.kind = R_ANAL_SNAPSHOT_TYPE_SIGNED_INTEGER;
			return syntax;
		}
	}
	for (i = 0; i < R_ARRAY_SIZE (unsigned_specs); i++) {
		if (!strcmp (spec, unsigned_specs[i])) {
			syntax.valid = true;
			syntax.kind = R_ANAL_SNAPSHOT_TYPE_UNSIGNED_INTEGER;
			return syntax;
		}
	}
	return syntax;
}

static SnapshotTypeGraphResult snapshot_type_integer_spec(
	const SnapshotTypeGraphBuilder *builder, const char *type,
	RAnalSnapshotTypeKind *kind, ut64 *bits) {
	char *current = r_str_trim_dup (type);
	if (!current) {
		return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
	}
	snapshot_type_strip_qualifiers (current);
	bool have_kind = false;
	ut64 required_bits = 0;
	size_t depth;
	const size_t maximum_depth = (size_t)r_list_length (builder->base_types) + 1;
	for (depth = 0; depth < maximum_depth; depth++) {
		if (snapshot_type_spec_rejected (current) || strchr (current, '*')
			|| r_str_startswith (current, "struct ")
			|| r_str_startswith (current, "union ")) {
			break;
		}
		SnapshotIntegerSyntax syntax = snapshot_type_integer_syntax (current);
		// Plain char is an integer type of its own, distinct from both signed
		// and unsigned char, so the syntax table cannot name its kind. Take it
		// from the target when the target's choice is known.
		if (!syntax.valid && !strcmp (current, "char") && builder->char_kind_known) {
			syntax.valid = true;
			syntax.kind = builder->char_kind;
		}
		if (syntax.valid) {
			if ((have_kind && *kind != syntax.kind)
				|| (required_bits && syntax.required_bits
					&& required_bits != syntax.required_bits)) {
				break;
			}
			*kind = syntax.kind;
			have_kind = true;
			if (syntax.required_bits) {
				required_bits = syntax.required_bits;
			}
		}
		char *base_name = r_str_sanitize_sdb_key (current);
		if (!base_name) {
			free (current);
			return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
		}
		bool ambiguous;
		const RAnalBaseType *base = snapshot_type_find_bare_base (
			builder, base_name, &ambiguous);
		free (base_name);
		if (ambiguous) {
			break;
		}
		if (!base) {
			break;
		}
		// An enumeration is an integer whose width the base type records. Its
		// signedness is not a target choice like plain char: it follows from the
		// values, since a negative enumerator can only be held by a signed type.
		if (base->kind == R_ANAL_BASE_TYPE_KIND_ENUM) {
			if (!snapshot_type_integer_width_supported (base->size)
				|| (required_bits && required_bits != base->size)) {
				break;
			}
			bool has_negative_case = false;
			RAnalEnumCase *enum_case;
			R_VEC_FOREACH (&base->enum_data.cases, enum_case) {
				if (enum_case && enum_case->val < 0) {
					has_negative_case = true;
					break;
				}
			}
			const RAnalSnapshotTypeKind enum_kind = has_negative_case
				? R_ANAL_SNAPSHOT_TYPE_SIGNED_INTEGER
				: R_ANAL_SNAPSHOT_TYPE_UNSIGNED_INTEGER;
			if (have_kind && *kind != enum_kind) {
				break;
			}
			*kind = enum_kind;
			*bits = base->size;
			free (current);
			return SNAPSHOT_TYPE_GRAPH_VALID;
		}
		if (base->kind == R_ANAL_BASE_TYPE_KIND_ATOMIC) {
			if (!have_kind || !snapshot_type_integer_width_supported (base->size)
				|| (required_bits && required_bits != base->size)) {
				break;
			}
			*bits = base->size;
			free (current);
			return SNAPSHOT_TYPE_GRAPH_VALID;
		}
		if (base->kind != R_ANAL_BASE_TYPE_KIND_TYPEDEF
			|| R_STR_ISEMPTY (base->type)) {
			break;
		}
		char *next = r_str_trim_dup (base->type);
		if (!next) {
			free (current);
			return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
		}
		free (current);
		current = next;
	}
	free (current);
	return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
}

static SnapshotTypeGraphResult snapshot_type_add_integer(
	SnapshotTypeGraphBuilder *builder, const char *type,
	RAnalSnapshotTypeId *result_id) {
	RAnalSnapshotTypeKind kind;
	ut64 bits;
	SnapshotTypeGraphResult result = snapshot_type_integer_spec (
		builder, type, &kind, &bits);
	// Integer width is bounded by what the graph can describe, not by pointer
	// width. An int64_t on a 32-bit target is wider than a pointer and entirely
	// ordinary, and snapshot_type_integer_width_supported already fixed the
	// real ceiling when the width was resolved.
	if (result != SNAPSHOT_TYPE_GRAPH_VALID) {
		return result;
	}
	size_t i;
	for (i = 0; i < builder->graph->num_types; i++) {
		RAnalSnapshotType *existing = &builder->graph->types[i];
		if (existing->kind == kind && existing->size_bits == bits
			&& existing->align_bits == bits) {
			*result_id = existing->id;
			return SNAPSHOT_TYPE_GRAPH_VALID;
		}
	}
	if (builder->graph->num_types >= builder->type_capacity
		|| builder->graph->num_types >= UT32_MAX) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	RAnalSnapshotType *snapshot_type =
		&builder->graph->types[builder->graph->num_types];
	snapshot_type->id = (RAnalSnapshotTypeId)builder->graph->num_types;
	snapshot_type->kind = kind;
	snapshot_type->size_bits = bits;
	snapshot_type->align_bits = bits;
	snapshot_type->target_type_id = R_ANAL_SNAPSHOT_TYPE_ID_INVALID;
	snapshot_type->aggregate_id = UT32_MAX;
	builder->graph->num_types++;
	*result_id = snapshot_type->id;
	return SNAPSHOT_TYPE_GRAPH_VALID;
}

static bool snapshot_type_align_up(ut64 value, ut64 alignment, ut64 *result) {
	if (!alignment || (alignment & (alignment - 1))) {
		return false;
	}
	ut64 remainder = value & (alignment - 1);
	ut64 padding = remainder? alignment - remainder: 0;
	return !r_add_overflow (value, padding, result);
}

static SnapshotTypeGraphResult snapshot_type_resolve_struct(
	const SnapshotTypeGraphBuilder *builder, const char *type,
	const RAnalBaseType **result_base) {
	char *spec = NULL;
	SnapshotTypeGraphResult result = snapshot_type_unalias (builder, type, &spec);
	if (result != SNAPSHOT_TYPE_GRAPH_VALID) {
		return result;
	}
	const char *name = spec;
	if (r_str_startswith (name, "struct ")) {
		name = r_str_trim_head_ro (name + strlen ("struct "));
	}
	if (R_STR_ISEMPTY (name) || strchr (name, '*')
		|| r_str_startswith (name, "union ")) {
		free (spec);
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	bool ambiguous;
	const RAnalBaseType *base = snapshot_type_find_unique_base (
		builder->base_types, name, R_ANAL_BASE_TYPE_KIND_STRUCT, &ambiguous);
	free (spec);
	if (ambiguous || !base) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	*result_base = base;
	return SNAPSHOT_TYPE_GRAPH_VALID;
}

static SnapshotTypeGraphResult snapshot_type_add_root(
	SnapshotTypeGraphBuilder *builder, const char *type,
	RAnalSnapshotTypeId *result_id);

static SnapshotTypeGraphResult snapshot_type_add_struct(
	SnapshotTypeGraphBuilder *builder, const char *type,
	RAnalSnapshotTypeId *result_id) {
	const RAnalBaseType *base = NULL;
	SnapshotTypeGraphResult result = snapshot_type_resolve_struct (
		builder, type, &base);
	if (result != SNAPSHOT_TYPE_GRAPH_VALID) {
		return result;
	}
	size_t i;
	for (i = 0; i < builder->graph->num_aggregates; i++) {
		if (builder->aggregate_sources[i] == base) {
			*result_id = builder->graph->aggregates[i].type_id;
			return SNAPSHOT_TYPE_GRAPH_VALID;
		}
	}
	if (builder->graph->num_types >= builder->type_capacity
		|| builder->graph->num_types >= UT32_MAX
		|| builder->graph->num_aggregates >= builder->aggregate_capacity
		|| builder->graph->num_aggregates >= UT32_MAX) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	const size_t type_index = builder->graph->num_types++;
	const size_t aggregate_index = builder->graph->num_aggregates++;
	RAnalSnapshotType *snapshot_type = &builder->graph->types[type_index];
	snapshot_type->id = (RAnalSnapshotTypeId)type_index;
	snapshot_type->kind = R_ANAL_SNAPSHOT_TYPE_STRUCT;
	snapshot_type->target_type_id = R_ANAL_SNAPSHOT_TYPE_ID_INVALID;
	snapshot_type->aggregate_id = (ut32)aggregate_index;
	RAnalSnapshotAggregateLayout *aggregate =
		&builder->graph->aggregates[aggregate_index];
	aggregate->id = (ut32)aggregate_index;
	aggregate->type_id = snapshot_type->id;
	const char *presentation_name = type;
	if (r_str_startswith (presentation_name, "struct ")) {
		presentation_name = r_str_trim_head_ro (
			presentation_name + strlen ("struct "));
	}
	if (R_STR_ISEMPTY (presentation_name) || strchr (presentation_name, '*')) {
		presentation_name = base->name;
	}
	aggregate->name = strdup (r_str_get (presentation_name));
	builder->aggregate_sources[aggregate_index] = base;
	if (!aggregate->name) {
		return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
	}
	RVecAnalTypeMember *base_members = r_anal_base_type_members (base);
	aggregate->num_members = RVecAnalTypeMember_length (base_members);
	if (!aggregate->num_members) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	size_t allocation_size;
	if (r_mul_overflow_size_t (aggregate->num_members,
			sizeof (RAnalSnapshotAggregateMember), &allocation_size)) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	aggregate->members = calloc (1, allocation_size);
	if (!aggregate->members) {
		return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
	}
	ut64 cursor = 0;
	ut64 maximum_alignment = 0;
	RAnalTypeMember *base_member;
	size_t member_index = 0;
	R_VEC_FOREACH (base_members, base_member) {
		if (member_index >= aggregate->num_members || !base_member
			|| R_STR_ISEMPTY (base_member->name)
			|| R_STR_ISEMPTY (base_member->type) || base_member->count) {
			return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
		}
		size_t prior;
		for (prior = 0; prior < member_index; prior++) {
			if (!strcmp (aggregate->members[prior].name, base_member->name)) {
				return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
			}
		}
		// A member is a type like any other. Resolving only integers made every
		// struct holding a pointer or a nested struct unrepresentable, which is
		// the shape of most non-trivial C structs.
		RAnalSnapshotTypeId member_type_id;
		result = snapshot_type_add_root (
			builder, base_member->type, &member_type_id);
		if (result != SNAPSHOT_TYPE_GRAPH_VALID) {
			return result;
		}
		const RAnalSnapshotType *member_type =
			&builder->graph->types[member_type_id];
		if (base_member->bitsize
			|| base_member->offset > UT64_MAX / 8) {
			return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
		}
		ut64 expected_offset;
		if (!snapshot_type_align_up (cursor, member_type->align_bits, &expected_offset)
			|| expected_offset != (ut64)base_member->offset * 8
			|| r_add_overflow (expected_offset, member_type->size_bits, &cursor)) {
			return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
		}
		RAnalSnapshotAggregateMember *member = &aggregate->members[member_index];
		member->member_id = (ut32)member_index;
		member->type_id = member_type_id;
		member->offset_bits = expected_offset;
		member->size_bits = member_type->size_bits;
		member->count = 1;
		member->name = strdup (base_member->name);
		if (!member->name) {
			return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
		}
		maximum_alignment = R_MAX (maximum_alignment, member_type->align_bits);
		member_index++;
	}
	ut64 size_bits;
	if (!snapshot_type_align_up (cursor, maximum_alignment, &size_bits)
		|| (base->size && base->size != size_bits)) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	aggregate->size_bits = size_bits;
	aggregate->align_bits = maximum_alignment;
	aggregate->complete = true;
	aggregate->c_layout_compatible = true;
	snapshot_type->size_bits = size_bits;
	snapshot_type->align_bits = maximum_alignment;
	*result_id = snapshot_type->id;
	return SNAPSHOT_TYPE_GRAPH_VALID;
}

static SnapshotTypeGraphResult snapshot_type_add_pointer(
	SnapshotTypeGraphBuilder *builder, const char *type,
	RAnalSnapshotTypeId *result_id) {
	char *spec = NULL;
	SnapshotTypeGraphResult result = snapshot_type_unalias (builder, type, &spec);
	if (result != SNAPSHOT_TYPE_GRAPH_VALID) {
		return result;
	}
	// Split at the last star so the pointee keeps any remaining ones: a
	// pointer to a pointer is described by describing what it points at, which
	// is another pointer this function can build. Refusing them left `char **`
	// unrepresentable, and with it the argv of every main.
	char *star = strrchr (spec, '*');
	if (!star || *r_str_trim_head_ro (star + 1)) {
		free (spec);
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	char *pointee = r_str_trim_ndup (spec, (size_t)(star - spec));
	free (spec);
	if (!pointee) {
		return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
	}
	RAnalSnapshotTypeId target_id;
	result = snapshot_type_add_integer (builder, pointee, &target_id);
	if (result == SNAPSHOT_TYPE_GRAPH_UNSUPPORTED) {
		result = strchr (pointee, '*')
			? snapshot_type_add_pointer (builder, pointee, &target_id)
			: snapshot_type_add_struct (builder, pointee, &target_id);
	}
	free (pointee);
	if (result != SNAPSHOT_TYPE_GRAPH_VALID) {
		return result;
	}
	size_t i;
	for (i = 0; i < builder->graph->num_types; i++) {
		RAnalSnapshotType *existing = &builder->graph->types[i];
		if (existing->kind == R_ANAL_SNAPSHOT_TYPE_POINTER
			&& existing->target_type_id == target_id
			&& existing->size_bits == builder->pointer_bits) {
			*result_id = existing->id;
			return SNAPSHOT_TYPE_GRAPH_VALID;
		}
	}
	if (builder->graph->num_types >= builder->type_capacity
		|| builder->graph->num_types >= UT32_MAX) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	RAnalSnapshotType *snapshot_type =
		&builder->graph->types[builder->graph->num_types];
	snapshot_type->id = (RAnalSnapshotTypeId)builder->graph->num_types;
	snapshot_type->kind = R_ANAL_SNAPSHOT_TYPE_POINTER;
	snapshot_type->size_bits = builder->pointer_bits;
	snapshot_type->align_bits = builder->pointer_bits;
	snapshot_type->target_type_id = target_id;
	snapshot_type->aggregate_id = UT32_MAX;
	builder->graph->num_types++;
	*result_id = snapshot_type->id;
	return SNAPSHOT_TYPE_GRAPH_VALID;
}

static SnapshotTypeGraphResult snapshot_type_add_root(
	SnapshotTypeGraphBuilder *builder, const char *type,
	RAnalSnapshotTypeId *result_id) {
	SnapshotTypeGraphResult result = snapshot_type_add_integer (
		builder, type, result_id);
	if (result != SNAPSHOT_TYPE_GRAPH_UNSUPPORTED) {
		return result;
	}
	char *spec = NULL;
	result = snapshot_type_unalias (builder, type, &spec);
	if (result != SNAPSHOT_TYPE_GRAPH_VALID) {
		return result;
	}
	const bool pointer = strchr (spec, '*') != NULL;
	free (spec);
	return pointer? snapshot_type_add_pointer (builder, type, result_id)
		: SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
}

static bool snapshot_type_carrier_project(
	const RAnalSnapshotTypeGraph *graph, RAnalSnapshotTypeId type_id,
	const RAnalSnapshotRegisterStorage *storage,
	RAnalSnapshotCarrierProjection *projection) {
	if (type_id >= graph->num_types || !storage->size) {
		return false;
	}
	const RAnalSnapshotType *type = &graph->types[type_id];
	const ut64 carrier_bits = (ut64)storage->size * 8;
	if (!type->size_bits || type->size_bits > carrier_bits
		|| (type->kind == R_ANAL_SNAPSHOT_TYPE_POINTER
			&& type->size_bits != carrier_bits)) {
		return false;
	}
	projection->kind = type->size_bits == carrier_bits
		? R_ANAL_SNAPSHOT_CARRIER_FULL
		: R_ANAL_SNAPSHOT_CARRIER_LOW_BITS;
	projection->size_bits = type->size_bits;
	return true;
}

static void function_logical_types_clear(RAnalFunctionInterfaceSnapshot *interface) {
	size_t i;
	for (i = 0; i < interface->num_parameters; i++) {
		interface->parameters[i].logical_type_id = R_ANAL_SNAPSHOT_TYPE_ID_INVALID;
		memset (&interface->parameters[i].carrier, 0,
			sizeof (interface->parameters[i].carrier));
	}
	interface->return_type_id = R_ANAL_SNAPSHOT_TYPE_ID_INVALID;
	memset (&interface->return_carrier, 0, sizeof (interface->return_carrier));
	interface->logical_types_complete = false;
}

static SnapshotTypeGraphResult function_type_graph_snapshot_collect(
	RAnal *anal, const RAnalFcnContext *ctx, RAnalFunctionSnapshot *snapshot,
	const RAnalFunctionSnapshotLimits *limits) {
	RAnalFunctionInterfaceSnapshot *interface = &snapshot->function_interface;
	function_logical_types_clear (interface);
	if (!interface->complete || !ctx->signature) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	// Pointer width is the only thing the builder takes from the target: it
	// sizes pointer types and bounds integer widths. Nothing in it is specific
	// to 64-bit, so a 32-bit target has no reason to lose its type graph.
	const ut64 pointer_bits = anal->config? (ut64)anal->config->bits: 0;
	if (pointer_bits != 32 && pointer_bits != 64) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	size_t base_count = (size_t)r_list_length (snapshot->base_types);
	size_t child_count = 0;
	RListIter *base_iter;
	RAnalBaseType *base;
	r_list_foreach (snapshot->base_types, base_iter, base) {
		if (base && (base->kind == R_ANAL_BASE_TYPE_KIND_STRUCT
				|| base->kind == R_ANAL_BASE_TYPE_KIND_UNION)
			&& r_add_overflow_size_t (child_count,
				RVecAnalTypeMember_length (r_anal_base_type_members (base)),
				&child_count)) {
			return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
		}
	}
	size_t root_capacity;
	if (r_add_overflow_size_t (interface->num_parameters, 1, &root_capacity)
		|| r_mul_overflow_size_t (root_capacity, 2, &root_capacity)) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	size_t type_capacity;
	if (r_add_overflow_size_t (root_capacity, base_count, &type_capacity)
		|| r_add_overflow_size_t (type_capacity, child_count, &type_capacity)
		|| type_capacity > UT32_MAX || base_count > UT32_MAX
		|| type_capacity > limits->max_type_graph_types
		|| base_count > limits->max_type_graph_aggregates
		|| child_count > limits->max_type_graph_members) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	RAnalSnapshotTypeGraph *graph = &snapshot->type_graph;
	size_t allocation_size;
	if (type_capacity && r_mul_overflow_size_t (
			type_capacity, sizeof (RAnalSnapshotType), &allocation_size)) {
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	graph->types = type_capacity? calloc (1, allocation_size): NULL;
	if (type_capacity && !graph->types) {
		return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
	}
	if (base_count && r_mul_overflow_size_t (
			base_count, sizeof (RAnalSnapshotAggregateLayout), &allocation_size)) {
		snapshot_type_graph_fini (graph);
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	graph->aggregates = base_count? calloc (1, allocation_size): NULL;
	if (base_count && !graph->aggregates) {
		snapshot_type_graph_fini (graph);
		return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
	}
	const RAnalBaseType **aggregate_sources = NULL;
	if (base_count && r_mul_overflow_size_t (
			base_count, sizeof (RAnalBaseType *), &allocation_size)) {
		snapshot_type_graph_fini (graph);
		return SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	if (base_count) {
		aggregate_sources = calloc (1, allocation_size);
		if (!aggregate_sources) {
			snapshot_type_graph_fini (graph);
			return SNAPSHOT_TYPE_GRAPH_NO_MEMORY;
		}
	}
	RAnalSnapshotTypeKind char_kind = R_ANAL_SNAPSHOT_TYPE_SIGNED_INTEGER;
	const bool char_kind_known = snapshot_arch_char_kind (
		anal->config? anal->config->arch: NULL, &char_kind);
	SnapshotTypeGraphBuilder builder = {
		.base_types = snapshot->base_types,
		.graph = graph,
		.aggregate_sources = aggregate_sources,
		.type_capacity = type_capacity,
		.aggregate_capacity = base_count,
		.pointer_bits = pointer_bits,
		.char_kind = char_kind,
		.char_kind_known = char_kind_known,
	};
	SnapshotTypeGraphResult result = SNAPSHOT_TYPE_GRAPH_VALID;
	RListIter *iter;
	RAnalFunctionParam *parameter;
	size_t index = 0;
	r_list_foreach (ctx->signature->params, iter, parameter) {
		if (!parameter || index >= interface->num_parameters) {
			result = SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
			break;
		}
		RAnalSnapshotParameter *snapshot_parameter = &interface->parameters[index];
		result = snapshot_type_add_root (
			&builder, parameter->type, &snapshot_parameter->logical_type_id);
		if (result != SNAPSHOT_TYPE_GRAPH_VALID
			|| !snapshot_type_carrier_project (graph,
				snapshot_parameter->logical_type_id, &snapshot_parameter->storage,
				&snapshot_parameter->carrier)) {
			if (result == SNAPSHOT_TYPE_GRAPH_VALID) {
				result = SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
			}
			break;
		}
		index++;
	}
	if (result == SNAPSHOT_TYPE_GRAPH_VALID && index != interface->num_parameters) {
		result = SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	if (result == SNAPSHOT_TYPE_GRAPH_VALID
		&& interface->return_kind == R_ANAL_SNAPSHOT_RETURN_REGISTER) {
		result = snapshot_type_add_root (
			&builder, ctx->signature->ret_type, &interface->return_type_id);
		if (result == SNAPSHOT_TYPE_GRAPH_VALID
			&& !snapshot_type_carrier_project (graph, interface->return_type_id,
				&interface->return_storage, &interface->return_carrier)) {
			result = SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
		}
	} else if (result == SNAPSHOT_TYPE_GRAPH_VALID
		&& interface->return_kind != R_ANAL_SNAPSHOT_RETURN_VOID) {
		result = SNAPSHOT_TYPE_GRAPH_UNSUPPORTED;
	}
	free (aggregate_sources);
	if (result != SNAPSHOT_TYPE_GRAPH_VALID) {
		snapshot_type_graph_fini (graph);
		function_logical_types_clear (interface);
		return result;
	}
	graph->complete = true;
	interface->logical_types_complete = true;
	return SNAPSHOT_TYPE_GRAPH_VALID;
}

static int call_site_interface_snapshot_compare(const void *left, const void *right) {
	const RAnalCallSiteInterfaceSnapshot *a = left;
	const RAnalCallSiteInterfaceSnapshot *b = right;
	if (a->instruction_addr < b->instruction_addr) {
		return -1;
	}
	if (a->instruction_addr > b->instruction_addr) {
		return 1;
	}
	if (a->target_addr < b->target_addr) {
		return -1;
	}
	return a->target_addr > b->target_addr? 1: 0;
}

static bool call_site_interface_snapshot_collect_one(
	RAnal *anal, const RAnalFcnCallee *callee,
	RAnalCallSiteInterfaceSnapshot *interface,
	const RAnalFunctionSnapshotLimits *limits) {
	interface->instruction_addr = callee->call_addr;
	interface->target_addr = callee->addr;
	RAnalFunction *target = r_anal_get_fcn_in (anal, callee->addr, R_ANAL_FCN_TYPE_ANY);
	const bool target_is_exact = target && target->addr == callee->addr;
	if (target_is_exact && R_STR_ISNOTEMPTY (target->name)) {
		interface->target_name = strdup (target->name);
		if (!interface->target_name) {
			return false;
		}
	}
	if (!callee->signature || !target_is_exact) {
		return true;
	}
	const char *calling_convention = callee->signature->callconv;
	if (R_STR_ISEMPTY (calling_convention)
		|| !r_anal_cc_exist (anal, calling_convention)) {
		return true;
	}
	interface->calling_convention = strdup (calling_convention);
	if (!interface->calling_convention) {
		return false;
	}
	/* A variadic signature carries the ellipsis as a trailing parameter with no
	 * type. It names no storage, so counting it as an argument leaves a slot the
	 * convention cannot fill and marks the whole call site incomplete. Record it
	 * as variadic and describe only the fixed arguments, the way argument
	 * recovery already does elsewhere. */
	size_t argument_count = (size_t)r_list_length (callee->signature->params);
	bool signature_variadic = false;
	if (argument_count > 0) {
		RAnalFunctionParam *last = r_list_get_n (callee->signature->params,
			(int)(argument_count - 1));
		if (last && R_STR_ISEMPTY (last->type) && !strcmp (r_str_get (last->name), "...")) {
			signature_variadic = true;
			argument_count--;
		}
	}
	if (argument_count > INT_MAX || argument_count > UT32_MAX
		|| argument_count > limits->max_call_site_parameters) {
		return false;
	}
	size_t allocation_size;
	if (r_mul_overflow (argument_count, sizeof (RAnalSnapshotParameter), &allocation_size)) {
		return false;
	}
	if (allocation_size) {
		interface->arguments = calloc (1, allocation_size);
		if (!interface->arguments) {
			return false;
		}
	}
	interface->num_arguments = argument_count;
	bool arguments_complete = true;
	RListIter *iter;
	RAnalFunctionParam *argument;
	size_t index = 0;
	r_list_foreach (callee->signature->params, iter, argument) {
		if (index >= argument_count) {
			break;
		}
		RAnalSnapshotParameter *snapshot_argument = &interface->arguments[index];
		snapshot_argument->index = (ut32)index;
		snapshot_argument->logical_type_id = R_ANAL_SNAPSHOT_TYPE_ID_INVALID;
		memset (&snapshot_argument->carrier, 0, sizeof (snapshot_argument->carrier));
		if (!argument || R_STR_ISEMPTY (argument->type)) {
			arguments_complete = false;
		}
		const char *place = r_anal_cc_argloc (
			anal, calling_convention, (int)index, 0, (int)argument_count);
		RAnalCCArgSlot slot = {0};
		if (R_STR_ISEMPTY (place) || *place == '^' || *place == '{'
			|| !r_anal_cc_argslot (anal, calling_convention,
				(int)index, (int)argument_count, false, &slot)
			|| !slot.reg) {
			arguments_complete = false;
			index++;
			continue;
		}
		SnapshotStorageResult collected = snapshot_register_storage_collect (
			anal, slot.reg, &snapshot_argument->storage);
		if (collected == SNAPSHOT_STORAGE_NO_MEMORY) {
			return false;
		}
		if (collected != SNAPSHOT_STORAGE_VALID) {
			arguments_complete = false;
		}
		index++;
	}
	if (index != argument_count
		|| snapshot_parameter_storages_overlap (interface->arguments, argument_count)) {
		arguments_complete = false;
	}
	interface->variadic = target->is_variadic || signature_variadic;
	interface->noreturn = callee->signature->noreturn || target->is_noreturn;
	bool result_complete = false;
	if (!strcmp (r_str_get (callee->signature->ret_type), "void")) {
		interface->result_kind = R_ANAL_SNAPSHOT_RETURN_VOID;
		result_complete = true;
	} else if (R_STR_ISNOTEMPTY (callee->signature->ret_type)) {
		const char *return_name = r_anal_cc_ret (anal, calling_convention, 0);
		const char *second_return = r_anal_cc_ret (anal, calling_convention, 1);
		if (R_STR_ISNOTEMPTY (return_name) && *return_name != '{'
			&& *return_name != '^' && R_STR_ISEMPTY (second_return)) {
			SnapshotStorageResult collected = snapshot_register_storage_collect (
				anal, return_name, &interface->result_storage);
			if (collected == SNAPSHOT_STORAGE_NO_MEMORY) {
				return false;
			}
			if (collected == SNAPSHOT_STORAGE_VALID) {
				interface->result_kind = R_ANAL_SNAPSHOT_RETURN_REGISTER;
				result_complete = true;
			}
		}
	}
	// Completeness describes the prototype, not the call instruction. Xrefs
	// establish which callee is reached, so the argument and result carriers
	// resolved above are exactly as good as the callee's own signature; which
	// lifted operation performs the call is a separate question, answered
	// downstream by matching this instruction and target address. Reporting
	// the prototype as incomplete because the identity is settled elsewhere
	// withholds what was recovered here.
	interface->complete = arguments_complete && result_complete;
	return true;
}

static bool call_site_interfaces_snapshot_collect(
	RAnal *anal, const RAnalFcnContext *ctx, RAnalFunctionSnapshot *snapshot,
	const RAnalFunctionSnapshotLimits *limits) {
	size_t count = (size_t)r_list_length (ctx->callees);
	if (!count) {
		return true;
	}
	if (count > limits->max_call_sites) {
		return false;
	}
	size_t total_arguments = 0;
	RListIter *preflight_iter;
	RAnalFcnCallee *preflight_callee;
	r_list_foreach (ctx->callees, preflight_iter, preflight_callee) {
		const int listed = preflight_callee && preflight_callee->signature
			&& preflight_callee->signature->params
			? r_list_length (preflight_callee->signature->params): 0;
		if (listed < 0 || (size_t)listed > limits->max_call_site_parameters
			|| r_add_overflow_size_t (
				total_arguments, (size_t)listed, &total_arguments)
			|| total_arguments > limits->max_total_call_site_parameters) {
			return false;
		}
	}
	size_t allocation_size;
	if (r_mul_overflow (count, sizeof (RAnalCallSiteInterfaceSnapshot), &allocation_size)) {
		return false;
	}
	snapshot->call_site_interfaces = calloc (1, allocation_size);
	if (!snapshot->call_site_interfaces) {
		return false;
	}
	snapshot->num_call_site_interfaces = count;
	RListIter *iter;
	RAnalFcnCallee *callee;
	size_t index = 0;
	r_list_foreach (ctx->callees, iter, callee) {
		if (!callee || index >= count
			|| !call_site_interface_snapshot_collect_one (
				anal, callee, &snapshot->call_site_interfaces[index], limits)) {
			return false;
		}
		index++;
	}
	if (index != count) {
		return false;
	}
	qsort (snapshot->call_site_interfaces, count,
		sizeof (RAnalCallSiteInterfaceSnapshot), call_site_interface_snapshot_compare);
	return true;
}

static bool snapshot_string_budget_add(const char *string, size_t limit, size_t *used) {
	if (!string) {
		return true;
	}
	size_t bytes;
	return !r_add_overflow_size_t (strlen (string), 1, &bytes)
		&& !r_add_overflow_size_t (*used, bytes, used) && *used <= limit;
}

static bool snapshot_signature_budget_add(const RAnalFunctionSignature *signature,
		const RAnalFunctionSnapshotLimits *limits, size_t *items, size_t *strings) {
	if (!signature) {
		return true;
	}
	const int listed = signature->params? r_list_length (signature->params): 0;
	if (listed < 0 || (size_t)listed > limits->max_interface_parameters
		|| !snapshot_string_budget_add (signature->signature,
			limits->max_context_string_bytes, strings)
		|| !snapshot_string_budget_add (signature->ret_type,
			limits->max_context_string_bytes, strings)
		|| !snapshot_string_budget_add (signature->callconv,
			limits->max_context_string_bytes, strings)) {
		return false;
	}
	RListIter *iter;
	RAnalFunctionParam *parameter;
	r_list_foreach (signature->params, iter, parameter) {
		if (!parameter || r_add_overflow_size_t (*items, 1, items)
			|| *items > limits->max_context_items
			|| !snapshot_string_budget_add (parameter->name,
				limits->max_context_string_bytes, strings)
			|| !snapshot_string_budget_add (parameter->type,
				limits->max_context_string_bytes, strings)) {
			return false;
		}
	}
	return true;
}

static bool snapshot_context_within_limits(const RAnalFunctionSnapshot *snapshot,
		const RAnalFunctionSnapshotLimits *limits) {
	size_t items = 0;
	size_t strings = 0;
	const RAnalFcnContext *ctx = &snapshot->context;
	if (!snapshot_string_budget_add (snapshot->arch_id,
			limits->max_context_string_bytes, &strings)
		|| !snapshot_string_budget_add (snapshot->cpu_id,
			limits->max_context_string_bytes, &strings)
		|| !snapshot_string_budget_add (snapshot->function_name,
			limits->max_context_string_bytes, &strings)
		|| !snapshot_string_budget_add (ctx->assumptions_json,
			limits->max_context_string_bytes, &strings)
		|| !snapshot_signature_budget_add (ctx->signature, limits, &items, &strings)) {
		return false;
	}
	RListIter *iter;
	RAnalFcnRegArg *arg;
	r_list_foreach (ctx->reg_args, iter, arg) {
		if (!arg || r_add_overflow_size_t (items, 1, &items)
			|| items > limits->max_context_items
			|| !snapshot_string_budget_add (arg->name,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (arg->type,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (arg->reg,
				limits->max_context_string_bytes, &strings)) {
			return false;
		}
	}
	RAnalFcnSlot *slot;
	r_list_foreach (ctx->fcn_slots, iter, slot) {
		if (!slot || r_add_overflow_size_t (items, 1, &items)
			|| items > limits->max_context_items
			|| !snapshot_string_budget_add (slot->name,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (slot->type,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (slot->base_name,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (slot->arg_name,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (slot->home_reg,
				limits->max_context_string_bytes, &strings)) {
			return false;
		}
	}
	RAnalFcnCallee *callee;
	r_list_foreach (ctx->callees, iter, callee) {
		if (!callee || r_add_overflow_size_t (items, 1, &items)
			|| items > limits->max_context_items
			|| !snapshot_string_budget_add (callee->name,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_signature_budget_add (
				callee->signature, limits, &items, &strings)) {
			return false;
		}
	}
	RAnalFunctionAssumption *assumption;
	r_list_foreach (ctx->assumptions, iter, assumption) {
		if (!assumption || r_add_overflow_size_t (items, 1, &items)
			|| items > limits->max_context_items
			|| !snapshot_string_budget_add (assumption->kind,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (assumption->target,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (assumption->scope,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (assumption->provenance,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (assumption->subject_json,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (assumption->value_json,
				limits->max_context_string_bytes, &strings)
			|| !snapshot_string_budget_add (assumption->payload_json,
				limits->max_context_string_bytes, &strings)) {
			return false;
		}
	}
	return true;
}

static bool snapshot_interface_within_limits(const RAnalFunctionSnapshot *snapshot,
		const RAnalFunctionSnapshotLimits *limits) {
	size_t strings = 0;
	const RAnalFunctionInterfaceSnapshot *interface = &snapshot->function_interface;
	if (interface->num_parameters > limits->max_interface_parameters
		|| !snapshot_string_budget_add (interface->calling_convention,
			limits->max_interface_string_bytes, &strings)
		|| !snapshot_string_budget_add (interface->return_storage.name,
			limits->max_interface_string_bytes, &strings)
		|| !snapshot_string_budget_add (interface->return_address_storage.name,
			limits->max_interface_string_bytes, &strings)
		|| !snapshot_string_budget_add (interface->stack_pointer_storage.name,
			limits->max_interface_string_bytes, &strings)
		|| !snapshot_string_budget_add (snapshot->frame_pointer_storage.name,
			limits->max_interface_string_bytes, &strings)) {
		return false;
	}
	size_t i;
	for (i = 0; i < interface->num_parameters; i++) {
		if (!snapshot_string_budget_add (interface->parameters[i].name,
				limits->max_interface_string_bytes, &strings)
			|| !snapshot_string_budget_add (interface->parameters[i].storage.name,
				limits->max_interface_string_bytes, &strings)) {
			return false;
		}
	}
	if (snapshot->num_call_site_interfaces > limits->max_call_sites) {
		return false;
	}
	for (i = 0; i < snapshot->num_call_site_interfaces; i++) {
		const RAnalCallSiteInterfaceSnapshot *call = &snapshot->call_site_interfaces[i];
		if (call->num_arguments > limits->max_call_site_parameters
			|| !snapshot_string_budget_add (call->calling_convention,
				limits->max_interface_string_bytes, &strings)
			|| !snapshot_string_budget_add (call->result_storage.name,
				limits->max_interface_string_bytes, &strings)) {
			return false;
		}
		size_t argument_index;
		for (argument_index = 0; argument_index < call->num_arguments; argument_index++) {
			if (!snapshot_string_budget_add (call->arguments[argument_index].storage.name,
					limits->max_interface_string_bytes, &strings)) {
				return false;
			}
		}
	}
	const RAnalSnapshotTypeGraph *graph = &snapshot->type_graph;
	if (graph->num_types > limits->max_type_graph_types
		|| graph->num_aggregates > limits->max_type_graph_aggregates) {
		return false;
	}
	size_t members = 0;
	for (i = 0; i < graph->num_aggregates; i++) {
		const RAnalSnapshotAggregateLayout *aggregate = &graph->aggregates[i];
		if (r_add_overflow_size_t (members, aggregate->num_members, &members)
			|| members > limits->max_type_graph_members
			|| !snapshot_string_budget_add (aggregate->name,
				limits->max_interface_string_bytes, &strings)) {
			return false;
		}
		size_t member_index;
		for (member_index = 0; member_index < aggregate->num_members; member_index++) {
			if (!snapshot_string_budget_add (aggregate->members[member_index].name,
					limits->max_interface_string_bytes, &strings)) {
				return false;
			}
		}
	}
	return true;
}

static bool snapshot_limits_valid(const RAnalFunctionSnapshotLimits *limits) {
	if (!limits || limits->struct_size != sizeof (*limits)) {
		return false;
	}
	const size_t values[] = {
		limits->max_base_types,
		limits->max_base_type_children,
		limits->max_base_type_string_bytes,
		limits->max_assumptions_json_bytes,
		limits->max_function_blocks,
		limits->max_block_source_bytes,
		limits->max_function_source_bytes,
		limits->max_function_successors,
		limits->max_context_items,
		limits->max_context_string_bytes,
		limits->max_interface_parameters,
		limits->max_call_sites,
		limits->max_call_site_parameters,
		limits->max_total_call_site_parameters,
		limits->max_interface_string_bytes,
		limits->max_type_graph_types,
		limits->max_type_graph_aggregates,
		limits->max_type_graph_members,
		limits->max_total_owned_bytes,
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (values); i++) {
		if (!values[i] || values[i] == SIZE_MAX) {
			return false;
		}
	}
	if (limits->max_block_source_bytes > limits->max_function_source_bytes) {
		return false;
	}
	size_t total = sizeof (RAnalFunctionSnapshot);
#define SNAPSHOT_LIMIT_ADD(value) \
	do { \
		if (r_add_overflow_size_t (total, (value), &total)) { \
			return false; \
		} \
	} while (0)
#define SNAPSHOT_LIMIT_MUL_ADD(count, size) \
	do { \
		size_t bytes; \
		if (r_mul_overflow_size_t ((count), (size), &bytes)) { \
			return false; \
		} \
		SNAPSHOT_LIMIT_ADD (bytes); \
	} while (0)
	SNAPSHOT_LIMIT_ADD (limits->max_function_source_bytes);
	SNAPSHOT_LIMIT_ADD (limits->max_base_type_string_bytes);
	SNAPSHOT_LIMIT_ADD (limits->max_assumptions_json_bytes);
	SNAPSHOT_LIMIT_ADD (limits->max_context_string_bytes);
	SNAPSHOT_LIMIT_ADD (limits->max_interface_string_bytes);
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_function_blocks, sizeof (RAnalSnapshotBlock));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_function_successors,
		sizeof (RAnalSnapshotSuccessor) + sizeof (ut64));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_base_types, sizeof (RAnalBaseType));
	const size_t base_type_child_size = R_MAX (sizeof (RAnalStructMember),
		R_MAX (sizeof (RAnalUnionMember), sizeof (RAnalEnumCase)));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_base_type_children, base_type_child_size);
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_context_items, sizeof (RAnalFcnSlot));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_interface_parameters,
		sizeof (RAnalSnapshotParameter));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_call_sites,
		sizeof (RAnalCallSiteInterfaceSnapshot));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_total_call_site_parameters,
		sizeof (RAnalSnapshotParameter));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_type_graph_types,
		sizeof (RAnalSnapshotType));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_type_graph_aggregates,
		sizeof (RAnalSnapshotAggregateLayout));
	SNAPSHOT_LIMIT_MUL_ADD (limits->max_type_graph_members,
		sizeof (RAnalSnapshotAggregateMember));
#undef SNAPSHOT_LIMIT_MUL_ADD
#undef SNAPSHOT_LIMIT_ADD
	return total <= limits->max_total_owned_bytes;
}

static const RArchConfig *function_snapshot_active_arch_config(const RAnal *anal) {
	if (anal && anal->arch && anal->arch->session && anal->arch->session->config) {
		return anal->arch->session->config;
	}
	return anal? anal->config: NULL;
}

static bool function_snapshot_machine_tuple_collect(RAnalFunctionSnapshot *snapshot, const RAnal *anal) {
	const RArchConfig *config = function_snapshot_active_arch_config (anal);
	if (!config) {
		return false;
	}
	snapshot->arch_id = strdup (r_str_get (config->arch));
	snapshot->cpu_id = strdup (r_str_get (config->cpu));
	snapshot->bits = config->bits;
	snapshot->endian = config->endian;
	return snapshot->arch_id && snapshot->cpu_id;
}

static bool function_snapshot_machine_tuple_is_current(const RAnalFunctionSnapshot *snapshot, const RAnal *anal) {
	const RArchConfig *config = function_snapshot_active_arch_config (anal);
	return config && snapshot->bits == config->bits && snapshot->endian == config->endian
		&& !strcmp (snapshot->arch_id, r_str_get (config->arch))
		&& !strcmp (snapshot->cpu_id, r_str_get (config->cpu));
}

// Refusals are reported through `reason` so a caller can say why a function
// could not be captured. Every refusal below names one cause.
#define SNAPSHOT_REFUSE(why) do { refusal = (why); goto fail; } while (0)

static RAnalFunctionSnapshot *function_snapshot_collect_with_limits_unlocked(RAnal *anal, RAnalFunction *fcn, const RAnalFunctionSnapshotLimits *limits, const char **reason) {
	RAnalFcnVarsCache cache = {0};
	RAnalFunctionSnapshot *snapshot = NULL;
	const char *refusal = "unspecified refusal";

	R_RETURN_VAL_IF_FAIL (anal && fcn && limits, NULL);
	if (!snapshot_limits_valid (limits)) {
		SNAPSHOT_REFUSE ("snapshot limits are not internally consistent");
	}
	ut64 function_dirty_epoch = r_anal_function_dirty_epoch (fcn);
	ut64 type_dirty_epoch = r_anal_types_dirty_epoch (anal);
	snapshot = R_NEW0 (RAnalFunctionSnapshot);
	if (!snapshot) {
		SNAPSHOT_REFUSE ("out of memory allocating the snapshot");
	}
	if (!function_image_snapshot_collect (
			anal, fcn, limits, &snapshot->image, &refusal)) {
		goto fail;
	}
	const char *assumptions_json = R_STR_ISNOTEMPTY (fcn->assumptions_json)
		? fcn->assumptions_json: "[]";
	size_t assumptions_json_bytes;
	if (r_add_overflow_size_t (strlen (assumptions_json), 1, &assumptions_json_bytes)
		|| assumptions_json_bytes > limits->max_assumptions_json_bytes) {
		SNAPSHOT_REFUSE ("the assumptions payload exceeds its limit");
	}
	RList *base_types = snapshot_type_resolver_capture (anal, limits);
	if (!base_types || type_dirty_epoch != r_anal_types_dirty_epoch (anal)) {
		r_anal_types_snapshot_free (base_types);
		SNAPSHOT_REFUSE ("the type database is unreadable or changed during capture");
	}

	snapshot->base_types = base_types;
	RAnalFcnContext *ctx = &snapshot->context;
	ctx->signature = fcn_context_collect_signature (fcn);
	ctx->reg_args = r_list_newf ((RListFree)fcn_context_reg_arg_free);
	ctx->fcn_slots = r_list_newf ((RListFree)fcn_context_slot_free);
	ctx->callees = fcn_context_collect_callees (anal, &snapshot->image);
	ctx->assumptions = r_anal_function_list_assumptions (anal, fcn);
	ctx->assumptions_json = strdup (assumptions_json);
	snapshot->schema_version = R_ANAL_FUNCTION_SNAPSHOT_SCHEMA_VERSION;
	snapshot->struct_size = sizeof (RAnalFunctionSnapshot);
	snapshot->function_addr = snapshot->image.entry_addr;
	const RAnalSnapshotBlock *first_block = &snapshot->image.blocks[0];
	const RAnalSnapshotBlock *last_block =
		&snapshot->image.blocks[snapshot->image.num_blocks - 1];
	snapshot->function_size = last_block->addr + last_block->size - first_block->addr;
	snapshot->maxstack = fcn->maxstack;
	snapshot->function_name = strdup (r_str_get (fcn->name));
	if (!function_snapshot_machine_tuple_collect (snapshot, anal)) {
		SNAPSHOT_REFUSE ("the active architecture tuple is unavailable");
	}
	ctx->function_dirty_epoch = function_dirty_epoch;
	ctx->type_dirty_epoch = type_dirty_epoch;
	snapshot->type_context_hash = r_anal_types_context_hash_from_snapshot (
		anal, snapshot->base_types, type_dirty_epoch);
	if (!ctx->reg_args || !ctx->fcn_slots || !ctx->callees
		|| !ctx->assumptions || !ctx->assumptions_json
		|| !snapshot->function_name || !snapshot->base_types) {
		SNAPSHOT_REFUSE ("out of memory collecting the function context");
	}

	r_anal_function_vars_cache_init_readonly (anal, &cache, fcn);
	RAnalVar **it;
	R_VEC_FOREACH (cache.rvars, it) {
		RAnalVar *var = *it;
		if (!var || !var->isarg || var->kind != R_ANAL_VAR_KIND_REG) {
			continue;
		}
		const int arg_index = fcn_context_register_arg_index (
			anal, fcn, cache.rvars, var);
		RAnalFcnRegArg *arg = fcn_context_collect_reg_arg (
			anal, ctx, var, arg_index);
		if (!arg || !r_list_append (ctx->reg_args, arg)) {
			fcn_context_reg_arg_free (arg);
			SNAPSHOT_REFUSE ("out of memory collecting function variables");
		}
	}
	r_list_sort (ctx->reg_args, fcn_context_reg_arg_compare);

	R_VEC_FOREACH (cache.bvars, it) {
		RAnalVar *var = *it;
		if (!var) {
			continue;
		}
		RAnalVar *home_source = fcn_context_find_register_home_source (cache.rvars, var);
		int exact_formal_ordinal = -1;
		const int arg_index = home_source
			? fcn_context_register_arg_index (anal, fcn, cache.rvars, home_source)
			: r_anal_var_exact_formal_get (anal, var, &exact_formal_ordinal)
				? exact_formal_ordinal: -1;
		RAnalFcnSlot *slot = fcn_context_collect_slot (
			anal, ctx, fcn, var, home_source, arg_index);
		if (!slot || !r_list_append (ctx->fcn_slots, slot)) {
			fcn_context_slot_free (slot);
			SNAPSHOT_REFUSE ("out of memory collecting function variables");
		}
	}
	R_VEC_FOREACH (cache.svars, it) {
		RAnalVar *var = *it;
		if (!var) {
			continue;
		}
		RAnalVar *home_source = fcn_context_find_register_home_source (cache.rvars, var);
		int exact_formal_ordinal = -1;
		const int arg_index = home_source
			? fcn_context_register_arg_index (anal, fcn, cache.rvars, home_source)
			: r_anal_var_exact_formal_get (anal, var, &exact_formal_ordinal)
				? exact_formal_ordinal: -1;
		RAnalFcnSlot *slot = fcn_context_collect_slot (
			anal, ctx, fcn, var, home_source, arg_index);
		if (!slot || !r_list_append (ctx->fcn_slots, slot)) {
			fcn_context_slot_free (slot);
			SNAPSHOT_REFUSE ("out of memory collecting function variables");
		}
	}
	r_anal_function_vars_cache_fini (&cache);
	if (!snapshot_context_within_limits (snapshot, limits)) {
		SNAPSHOT_REFUSE ("the function context exceeds its limits");
	}
	if (!function_interface_snapshot_collect (
			anal, fcn, ctx, &snapshot->function_interface, limits)) {
		SNAPSHOT_REFUSE ("the function interface could not be collected");
	}
	if (!snapshot_frame_pointer_storage_collect (anal, fcn, ctx,
			&snapshot->function_interface, &snapshot->frame_pointer_storage)) {
		SNAPSHOT_REFUSE ("the frame pointer storage could not be resolved");
	}
	snapshot_return_mechanism_collect (anal, fcn,
		ctx, &snapshot->function_interface, &snapshot->return_mechanism);
	snapshot_stack_allocation_contract_collect (anal,
		&snapshot->function_interface, &snapshot->stack_allocation_contract);
	SnapshotTypeGraphResult graph_result = function_type_graph_snapshot_collect (
		anal, ctx, snapshot, limits);
	if (graph_result == SNAPSHOT_TYPE_GRAPH_NO_MEMORY) {
		SNAPSHOT_REFUSE ("out of memory building the type graph");
	}
	if (!call_site_interfaces_snapshot_collect (anal, ctx, snapshot, limits)) {
		SNAPSHOT_REFUSE ("the call site interfaces could not be collected");
	}
	if (!snapshot_interface_within_limits (snapshot, limits)) {
		SNAPSHOT_REFUSE ("the function interface exceeds its limits");
	}
	RAnalFunctionImageSnapshot current_image = {0};
	const bool image_current = function_image_snapshot_collect (
		anal, fcn, limits, &current_image, NULL)
		&& function_image_snapshot_equal (&snapshot->image, &current_image);
	function_image_snapshot_fini (&current_image);
	RList *current_base_types = snapshot_type_resolver_capture (anal, limits);
	const bool base_types_current = snapshot_base_types_equal (
		snapshot->base_types, current_base_types);
	r_list_free (current_base_types);
	RAnalSnapshotReturnMechanismView current_return_mechanism = {0};
	snapshot_return_mechanism_collect (anal, fcn,
		ctx, &snapshot->function_interface, &current_return_mechanism);
	RAnalSnapshotStackAllocationContractView current_stack_allocation_contract = {0};
	snapshot_stack_allocation_contract_collect (anal,
		&snapshot->function_interface, &current_stack_allocation_contract);
	RAnalSnapshotRegisterStorage current_frame_pointer_storage = {0};
	const bool frame_pointer_current = snapshot_frame_pointer_storage_collect (
		anal, fcn, ctx, &snapshot->function_interface,
		&current_frame_pointer_storage)
		&& snapshot_frame_pointer_storage_equal (
			&snapshot->frame_pointer_storage, &current_frame_pointer_storage);
	snapshot_register_storage_fini (&current_frame_pointer_storage);
	if (function_dirty_epoch != r_anal_function_dirty_epoch (fcn)
		|| type_dirty_epoch != r_anal_types_dirty_epoch (anal)
		|| !function_snapshot_machine_tuple_is_current (snapshot, anal)
		|| !image_current || !base_types_current
		|| !snapshot_return_mechanism_equal (
			&snapshot->return_mechanism, &current_return_mechanism)
		|| !snapshot_stack_allocation_contract_equal (
			&snapshot->stack_allocation_contract,
			&current_stack_allocation_contract)
		|| !frame_pointer_current) {
		SNAPSHOT_REFUSE ("the function or type state changed during capture");
	}
	snapshot->capabilities = R_ANAL_FUNCTION_SNAPSHOT_CAP_REGISTER_ARGS
		| R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_SLOTS
		| R_ANAL_FUNCTION_SNAPSHOT_CAP_CALLEES
		| R_ANAL_FUNCTION_SNAPSHOT_CAP_TYPES
		| R_ANAL_FUNCTION_SNAPSHOT_CAP_ASSUMPTIONS
		| R_ANAL_FUNCTION_SNAPSHOT_CAP_REVISION
		| R_ANAL_FUNCTION_SNAPSHOT_CAP_OWNED_BOUNDED_FUNCTION_IMAGE;
	if (ctx->signature) {
		snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_SIGNATURE;
	}
	if (snapshot->function_interface.complete) {
		snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE;
	}
	if (snapshot->function_interface.return_address_storage.name
		&& snapshot->function_interface.return_address_storage.size) {
		snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE;
	}
	if (snapshot->function_interface.stack_pointer_storage.name
		&& snapshot->function_interface.stack_pointer_storage.size) {
		snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE;
	}
	if (snapshot->return_mechanism.kind != R_ANAL_SNAPSHOT_RETURN_MECHANISM_NONE
		&& (snapshot->capabilities & (
			R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE)) == (
			R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE)) {
		snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_RETURN_MECHANISM;
	}
	if (snapshot->frame_pointer_storage.name
		&& snapshot->frame_pointer_storage.size
		&& (snapshot->capabilities & (
			R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE)) == (
			R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_RETURN_ADDRESS_STORAGE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE)) {
		snapshot->capabilities |=
			R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FRAME_POINTER_STORAGE;
	}
	if (snapshot->stack_allocation_contract.growth
			!= R_ANAL_SNAPSHOT_STACK_GROWTH_NONE
		&& (snapshot->capabilities & (
			R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE)) == (
			R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_INTERFACE
			| R_ANAL_FUNCTION_SNAPSHOT_CAP_STACK_POINTER_STORAGE)) {
		snapshot->capabilities |=
			R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_ALLOCATION_CONTRACT;
	}
	if (snapshot->function_interface.stack_slot_roles_complete) {
		snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_STACK_SLOT_ROLES;
	}
	if (snapshot->type_graph.complete
		&& snapshot->function_interface.logical_types_complete) {
		snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_EXACT_FUNCTION_TYPES;
	}
	if (snapshot->num_call_site_interfaces) {
		snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_CALL_SITE_INTERFACES;
	}
	snapshot->revision_identity = function_snapshot_hash (snapshot);
	ctx->context_hash = snapshot->revision_identity;
	return snapshot;

fail:
	r_anal_function_vars_cache_fini (&cache);
	r_anal_function_snapshot_free (snapshot);
	if (reason) {
		*reason = refusal;
	}
	return NULL;
}

#undef SNAPSHOT_REFUSE

R_IPI void r_anal_function_snapshot_limits_default(RAnalFunctionSnapshotLimits *limits) {
	R_RETURN_IF_FAIL (limits);
	*limits = (RAnalFunctionSnapshotLimits) {
		.struct_size = sizeof (*limits),
		.max_base_types = 4096,
		.max_base_type_children = 65536,
		.max_base_type_string_bytes = 16 * 1024 * 1024,
		.max_assumptions_json_bytes = 1024 * 1024,
		.max_function_blocks = 65536,
		.max_block_source_bytes = 16 * 1024 * 1024,
		.max_function_source_bytes = 256 * 1024 * 1024,
		.max_function_successors = 262144,
		.max_context_items = 65536,
		.max_context_string_bytes = 16 * 1024 * 1024,
		.max_interface_parameters = 4096,
		.max_call_sites = 65536,
		.max_call_site_parameters = 4096,
		.max_total_call_site_parameters = 65536,
		.max_interface_string_bytes = 16 * 1024 * 1024,
		.max_type_graph_types = 131072,
		.max_type_graph_aggregates = 4096,
		.max_type_graph_members = 65536,
		.max_total_owned_bytes = 512 * 1024 * 1024,
	};
}

// A consumer that reasons across a call needs the callee's body. Four is the
// bound because the cost is a full capture each and the reach a caller actually
// uses is its direct calls, not its transitive closure; recursion is refused
// outright rather than unrolled.
#define SNAPSHOT_MAX_CALLEE_SNAPSHOTS 4

static void function_snapshot_collect_callees_unlocked(RAnal *anal, RAnalFunctionSnapshot *snapshot, const RAnalFunctionSnapshotLimits *limits) {
	if (!snapshot->context.callees) {
		return;
	}
	RAnalFunctionSnapshot **collected = R_NEWS0 (RAnalFunctionSnapshot *, SNAPSHOT_MAX_CALLEE_SNAPSHOTS);
	if (!collected) {
		return;
	}
	size_t count = 0;
	RListIter *iter;
	RAnalFcnCallee *callee;
	r_list_foreach (snapshot->context.callees, iter, callee) {
		if (count >= SNAPSHOT_MAX_CALLEE_SNAPSHOTS) {
			break;
		}
		// A callee that is the caller is the same body, and one already taken
		// is the same body too: a set with a repeat describes nothing extra and
		// costs a consumer a disjointness check it cannot satisfy.
		if (!callee || callee->addr == UT64_MAX || callee->addr == snapshot->function_addr) {
			continue;
		}
		size_t seen;
		bool duplicate = false;
		for (seen = 0; seen < count && !duplicate; seen++) {
			duplicate = collected[seen]->function_addr == callee->addr;
		}
		if (duplicate) {
			continue;
		}
		RAnalFunction *callee_fcn = r_anal_get_function_at (anal, callee->addr);
		if (!callee_fcn) {
			continue;
		}
		RAnalFunctionSnapshot *callee_snapshot = function_snapshot_collect_with_limits_unlocked (
			anal, callee_fcn, limits, NULL);
		if (!callee_snapshot) {
			continue;
		}
		// One level. A callee's own callees are its business, and collecting
		// them would make the cost of a capture depend on the shape of the
		// program rather than on the function asked for.
		size_t nested;
		for (nested = 0; nested < callee_snapshot->num_callee_snapshots; nested++) {
			r_anal_function_snapshot_free (callee_snapshot->callee_snapshots[nested]);
		}
		free (callee_snapshot->callee_snapshots);
		callee_snapshot->callee_snapshots = NULL;
		callee_snapshot->num_callee_snapshots = 0;
		callee_snapshot->capabilities &= ~R_ANAL_FUNCTION_SNAPSHOT_CAP_CALLEE_SNAPSHOTS;
		// The identity a set carries is the identity of the capture, not of one
		// function in it. A consumer reasoning across a call has to be able to
		// tell that these bodies were read together, and a per-function hash
		// says the opposite about every member.
		callee_snapshot->revision_identity = snapshot->revision_identity;
		collected[count++] = callee_snapshot;
	}
	if (!count) {
		free (collected);
		return;
	}
	snapshot->callee_snapshots = collected;
	snapshot->num_callee_snapshots = count;
	snapshot->capabilities |= R_ANAL_FUNCTION_SNAPSHOT_CAP_CALLEE_SNAPSHOTS;
}

R_IPI RAnalFunctionSnapshot *r_anal_function_snapshot_collect_with_limits(RAnal *anal, RAnalFunction *fcn, const RAnalFunctionSnapshotLimits *limits, const char **reason) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, NULL);
	r_th_lock_enter (anal->lock);
	RAnalFunctionSnapshot *snapshot = function_snapshot_collect_with_limits_unlocked (
		anal, fcn, limits, reason);
	if (snapshot) {
		function_snapshot_collect_callees_unlocked (anal, snapshot, limits);
	}
	r_th_lock_leave (anal->lock);
	return snapshot;
}

R_IPI RAnalFunctionSnapshot *r_anal_function_snapshot_collect_bounded(RAnal *anal, RAnalFunction *fcn, const char **reason) {
	RAnalFunctionSnapshotLimits limits;
	r_anal_function_snapshot_limits_default (&limits);
	return r_anal_function_snapshot_collect_with_limits (anal, fcn, &limits, reason);
}

R_API bool r_anal_function_snapshot_visit_bounded_advisory(RAnal *anal, ut64 function_addr, RAnalFunctionSnapshotCallback callback, void *user, const char **reason) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock && callback, false);
	if (reason) {
		*reason = NULL;
	}
	r_th_lock_enter (anal->lock);
	RAnalFunction *fcn = r_anal_get_function_at (anal, function_addr);
	if (!fcn) {
		if (reason) {
			*reason = "no function starts at that address";
		}
		r_th_lock_leave (anal->lock);
		return false;
	}
	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (
		anal, fcn, reason);
	if (!snapshot) {
		r_th_lock_leave (anal->lock);
		return false;
	}
	const bool result = callback (snapshot, user);
	r_anal_function_snapshot_free (snapshot);
	r_th_lock_leave (anal->lock);
	return result;
}

R_API RAnalFcnContext *r_anal_function_context_collect(RAnal *anal, RAnalFunction *fcn) {
	RAnalFunctionSnapshot *snapshot = r_anal_function_snapshot_collect_bounded (anal, fcn, NULL);
	if (!snapshot) {
		return NULL;
	}
	RAnalFcnContext *ctx = R_NEW0 (RAnalFcnContext);
	*ctx = snapshot->context;
	memset (&snapshot->context, 0, sizeof (snapshot->context));
	r_anal_function_snapshot_free (snapshot);
	return ctx;
}

typedef struct {
	RGraph *graph;
	HtUP *nodes;
	RGraphNode *from;
} EdgeCtx;

// a successor outside the function (tail jump, noreturn split) is not an edge
static bool add_edge_cb(ut64 addr, void *user) {
	EdgeCtx *ctx = user;
	RGraphNode *to = ht_up_find (ctx->nodes, addr, NULL);
	if (to) {
		r_graph_add_edge (ctx->graph, ctx->from, to);
	}
	return true;
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
	EdgeCtx ctx = { g, nodes, NULL };
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->jump == UT64_MAX && bb->fail == UT64_MAX && (!bb->switch_op || r_list_empty (bb->switch_op->cases))) {
			continue;
		}
		ctx.from = ht_up_find (nodes, bb->addr, NULL);
		r_anal_block_successor_addrs_foreach (bb, add_edge_cb, &ctx);
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
