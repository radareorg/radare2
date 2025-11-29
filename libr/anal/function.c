/* radare - LGPL - Copyright 2019-2025 - pancake, thestr4ng3r */

#include <r_anal.h>

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
		R_LOG_WARN ("Function already defined in 0x%08"PFMT64x, addr);
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
	// XXX this is slow use skiplist or vector instead
	if (r_list_contains (bb->fcns, fcn)) {
		return;
	}
	r_list_append (bb->fcns, fcn); // associate the given fcn with this bb
	r_anal_block_ref (bb);
	r_list_append (fcn->bbs, bb);

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
	r_anal_block_unref (bb);
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
