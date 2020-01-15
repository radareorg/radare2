/* radare - LGPL - Copyright 2019 - pancake, thestr4ng3r */

#include <r_anal.h>

#define D if (anal->verbose)
#define ADDR_FCN_CONTAINER(x) container_of ((RBNode*)(x), RAnalFunction, addr_rb)

static int _fcn_addr_tree_cmp(const void *a_, const RBNode *b_, void *user) {
	const RAnalFunction *a = (const RAnalFunction *)a_;
	const RAnalFunction *b = ADDR_FCN_CONTAINER (b_);
	ut64 from0 = a->addr, from1 = b->addr;
	if (from0 != from1) {
		return from0 < from1 ? -1 : 1;
	}
	return 0;
}

static bool _fcn_tree_delete(RAnal *anal, RAnalFunction *fcn) {
	r_return_val_if_fail (anal && fcn, false);
	return !!r_rbtree_delete (&anal->fcn_addr_tree, fcn, _fcn_addr_tree_cmp, NULL, NULL, NULL);
}

static void _fcn_tree_insert(RAnal *anal, RAnalFunction *fcn) {
	r_rbtree_insert (&anal->fcn_addr_tree, fcn, &(fcn->addr_rb), _fcn_addr_tree_cmp, NULL);
}

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
	RList *list = r_list_new ();
	if (!list) {
		return NULL;
	}
	r_anal_blocks_foreach_in (anal, addr, get_functions_block_cb, list);
	return list;
}

static bool __fcn_exists(RAnal *anal, const char *name, ut64 addr) {
	// check if name is already registered
	bool found = false;
	if (addr == UT64_MAX) {
		eprintf ("Invalid function address (-1) '%s'\n", name);
		return true;
	}
	if (!name) {
		eprintf ("TODO: Empty function name, we must auto generate one\n");
		return true;
	}
	RAnalFunction *f = ht_pp_find (anal->ht_name_fun, name, &found);
	if (f && found) {
		eprintf ("Invalid function name '%s' at 0x%08"PFMT64x"\n", name, addr);
		return true;
	}
	// check if there's a function already in the given address
	found = false;
	f = ht_up_find (anal->ht_addr_fun, addr, &found);
	if (f && found) {
		eprintf ("Function already defined in 0x%08"PFMT64x"\n", addr);
		return true;
	}
	return false;
}

R_API RAnalFunction *r_anal_function_new(RAnal *anal) {
	RAnalFunction *fcn = R_NEW0 (RAnalFunction);
	if (!fcn) {
		return NULL;
	}
	fcn->anal = anal;
	/* Function qualifier: static/volatile/inline/naked/virtual */
	fcn->fmod = R_ANAL_FQUALIFIER_NONE;
	/* Function calling convention: cdecl/stdcall/fastcall/etc */
	/* Function attributes: weak/noreturn/format/etc */
	fcn->addr = UT64_MAX;
	fcn->cc = r_str_constpool_get (&anal->constpool, r_anal_cc_default (anal));
	fcn->bits = anal->bits;
	fcn->bbs = r_list_new ();
	fcn->diff = r_anal_diff_new ();
	fcn->has_changed = true;
	fcn->bp_frame = true;
	fcn->is_noreturn = false;
	fcn->meta._min = UT64_MAX;
	return fcn;
}

R_API void r_anal_function_free(void *_fcn) {
	RAnalFunction *fcn = _fcn;
	if (!_fcn) {
		return;
	}

	RAnalBlock *block;
	RListIter *iter;
	r_list_foreach (fcn->bbs, iter, block) {
		r_list_delete_data (block->fcns, fcn);
		r_anal_block_unref (block);
	}
	r_list_free (fcn->bbs);

	RAnal *anal = fcn->anal;
	ht_up_delete (anal->ht_addr_fun, fcn->addr);
	ht_pp_delete (anal->ht_name_fun, fcn->name);
	_fcn_tree_delete (anal, fcn);

	free (fcn->name);
	free (fcn->attr);
	r_list_free (fcn->fcn_locs);
	fcn->bbs = NULL;
	free (fcn->fingerprint);
	r_anal_diff_free (fcn->diff);
	free (fcn->args);
	free (fcn);
}

R_API bool r_anal_add_function(RAnal *anal, RAnalFunction *fcn) {
	if (__fcn_exists (anal, fcn->name, fcn->addr)) {
		return false;
	}
	if (anal->cb.on_fcn_new) {
		anal->cb.on_fcn_new (anal, anal->user, fcn);
	}
	if (anal->flg_fcn_set) {
		anal->flg_fcn_set (anal->flb.f, fcn->name, fcn->addr, r_anal_function_size_from_entry (fcn));
	}
	_fcn_tree_insert (anal, fcn);
	r_list_append (anal->fcns, fcn);
	ht_pp_insert (anal->ht_name_fun, fcn->name, fcn);
	ht_up_insert (anal->ht_addr_fun, fcn->addr, fcn);
	return true;
}

R_API RAnalFunction *r_anal_create_function(RAnal *anal, const char *name, ut64 addr, int type, RAnalDiff *diff) {
	RAnalFunction *fcn = r_anal_function_new (anal);
	if (!fcn) {
		return NULL;
	}
	fcn->addr = addr;
	fcn->type = type;
	fcn->cc = r_str_constpool_get (&anal->constpool, r_anal_cc_default (anal));
	fcn->bits = anal->bits;
	if (name) {
		free (fcn->name);
		fcn->name = strdup (name);
	} else {
		const char *fcnprefix = anal->coreb.cfgGet ? anal->coreb.cfgGet (anal->coreb.core, "anal.fcnprefix") : NULL;
		if (!fcnprefix) {
			fcnprefix = "fcn";
		}
		fcn->name = r_str_newf ("%s.%08"PFMT64x, fcnprefix, fcn->addr);
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

R_API bool r_anal_function_delete(RAnalFunction *fcn) {
	return r_list_delete_data (fcn->anal->fcns, fcn);
}

R_API RAnalFunction *r_anal_get_function_at(RAnal *anal, ut64 addr) {
	bool found = false;
	RAnalFunction *f = ht_up_find (anal->ht_addr_fun, addr, &found);
	if (f && found) {
		return f;
	}
	return NULL;
}

R_API bool r_anal_function_relocate(RAnalFunction *fcn, ut64 addr) {
	if (fcn->addr == addr) {
		return true;
	}
	if (r_anal_get_function_at (fcn->anal, addr)) {
		return false;
	}
	_fcn_tree_delete (fcn->anal, fcn);
	fcn->addr = addr;
	_fcn_tree_insert (fcn->anal, fcn);
	return true;
}

R_API bool r_anal_function_rename(RAnalFunction *fcn, const char *name) {
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
	if (!newname) {
		return false;
	}
	bool in_tree = ht_pp_delete (anal->ht_name_fun, fcn->name);
	free (fcn->name);
	fcn->name = newname;
	if (in_tree) {
		// only re-insert if it really was in the tree before
		ht_pp_insert (anal->ht_name_fun, fcn->name, fcn);
	}
	return true;
}

R_API void r_anal_function_add_block(RAnalFunction *fcn, RAnalBlock *bb) {
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
	ensure_fcn_range (fcn);
	return fcn->meta._max - fcn->meta._min;
}

R_API ut64 r_anal_function_min_addr(RAnalFunction *fcn) {
	ensure_fcn_range (fcn);
	return fcn->meta._min;
}

R_API ut64 r_anal_function_max_addr(RAnalFunction *fcn) {
	ensure_fcn_range (fcn);
	return fcn->meta._max;
}

R_API ut64 r_anal_function_size_from_entry(RAnalFunction *fcn) {
	ensure_fcn_range (fcn);
	return fcn->meta._min == UT64_MAX ? 0 : fcn->meta._max - fcn->addr;
}

R_API ut64 r_anal_function_realsize(const RAnalFunction *fcn) {
	RListIter *iter, *fiter;
	RAnalBlock *bb;
	RAnalFunction *f;
	ut64 sz = 0;
	if (!sz) {
		r_list_foreach (fcn->bbs, iter, bb) {
			sz += bb->size;
		}
		r_list_foreach (fcn->fcn_locs, fiter, f) {
			r_list_foreach (f->bbs, iter, bb) {
				sz += bb->size;
			}
		}
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
	// fcn_in_cb breaks with false if it finds the fcn
	return !r_anal_blocks_foreach_in (fcn->anal, addr, fcn_in_cb, fcn);
}
