/* radare - LGPL - Copyright 2019 - pancake, thestr4ng3r */

#include <r_anal.h>

#define D if (anal->verbose)

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
	r_anal_block_get_in (anal, addr, get_functions_block_cb, list);
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
	r_anal_block_check_invariants (fcn->anal);
	r_list_foreach (fcn->bbs, iter, block) {
		r_list_delete_data (block->fcns, fcn);
		r_anal_block_unref (block);
	}
	r_list_free (fcn->bbs);
	r_anal_block_check_invariants (fcn->anal);

	RAnal *anal = fcn->anal;
	ht_up_delete (anal->ht_addr_fun, fcn->addr);
	ht_pp_delete (anal->ht_name_fun, fcn->name);
	r_anal_fcn_tree_delete (anal, fcn);

	free (fcn->name);
	free (fcn->attr);
	r_list_free (fcn->fcn_locs);
	fcn->bbs = NULL;
	free (fcn->fingerprint);
	r_anal_diff_free (fcn->diff);
	free (fcn->args);
	free (fcn);
}

R_API bool r_anal_function_add(RAnal *anal, RAnalFunction *fcn) {
	if (__fcn_exists (anal, fcn->name, fcn->addr)) {
		return false;
	}
	if (anal->cb.on_fcn_new) {
		anal->cb.on_fcn_new (anal, anal->user, fcn);
	}
	if (anal->flg_fcn_set) {
		anal->flg_fcn_set (anal->flb.f, fcn->name, fcn->addr, r_anal_fcn_size_from_entry (fcn));
	}
	r_anal_fcn_tree_insert (anal, fcn);
	r_list_append (anal->fcns, fcn);
	ht_pp_insert (anal->ht_name_fun, fcn->name, fcn);
	ht_up_insert (anal->ht_addr_fun, fcn->addr, fcn);
	return true;
}

R_API RAnalFunction *r_anal_function_create(RAnal *anal, const char *name, ut64 addr) {
	RAnalFunction *fcn = r_anal_function_new (anal);
	if (!fcn) {
		return NULL;
	}
	fcn->addr = addr;
	if (name) {
		free (fcn->name);
		fcn->name = strdup (name);
	}
	if (!r_anal_function_add (anal, fcn)) {
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

R_API void r_anal_function_block_add(RAnalFunction *fcn, RAnalBlock *bb) {
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

R_API void r_anal_function_block_remove(RAnalFunction *fcn, RAnalBlock *bb) {
	r_list_delete_data (bb->fcns, fcn);

	if (fcn->meta._min != UT64_MAX
		&& (fcn->meta._min == bb->addr || fcn->meta._max == bb->addr + bb->size)) {
		// If a block is removed at the beginning or end, updating min/max is not trivial anymore, just invalidate
		fcn->meta._min = UT64_MAX;
	}

	r_list_delete_data (fcn->bbs, bb);
	r_anal_block_unref (bb);
}
