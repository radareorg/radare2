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



















// A callee reached by jumping through a value loaded from a relocated slot.
// The relocation is what names it: nothing at the slot address is code, so
// the name, the linkage and the prototype all come from the relocation record
// rather than from a function at `addr`. A relocation with no name offers
// nothing, because a prototype cannot be looked up for it.



// How the instruction at transfer_addr, the last one of its block, leaves.
//
// The block itself cannot answer this. A tail jump records no successor at
// all: the function walk stops at a jump whose target is a named function or
// an import, and it stops before it stores the edge, so a return, a trap and
// a jump out of the function are indistinguishable from the block record.
// Only the instruction tells them apart, so it is decoded here.
//
// `target` receives the address a direct jump names. `memory_operand` receives
// the address a value jump reads its target from, when the instruction names
// one; a jump through a register names none and leaves it absent.


// A block that ends in a jump through a value may be a tail transfer to the
// function a relocated slot names. Every relocated slot the block refers to is
// offered: the jump's own memory operand where it has one, and the target of
// every data reference the block makes. Which of them the jump actually reads
// is machine evidence the consumer holds and this side does not, so this
// offers rather than decides, and an offer the machine cannot confirm is
// simply unmatched.

// The jumps that leave the function for another one. A jump whose target is
// exactly where a function starts is a tail transfer: the jump is the call,
// and the callee's return is this function's. The function map decides it,
// not the shape of the jump, so a jump into the middle of another function
// stays what it is. The transfer is recorded at the block's last instruction,
// which is the one that performs it.











// Returns one for an exact block start, zero outside the image, and -1 for
// an address inside a block which is not a valid basic-block destination.

#define IMAGE_REFUSE(why) do { refusal = (why); goto fail; } while (0)

/* String literals the function refers to, taken from the `Cs` metadata radare2
 * already keeps. A consumer holding only the snapshot can read the address a
 * constant carries but not what is stored there, so without this a call can be
 * named and still have to spell its argument as a number. */
// A word counts as a code pointer when a function starts there. Anything looser
// -- inside a function, or merely in an executable map -- admits alignment
// padding and offsets into the middle of instructions, and a table that carries
// those is worse than no table at all.

#define SNAPSHOT_MAX_CODE_POINTER_TABLES 16
#define SNAPSHOT_MAX_CODE_POINTER_TABLE_ENTRIES 256

// The table is read until it stops looking like one. A run of code pointers
// ends at the first word that does not begin a function, which is where the
// next datum starts; carrying past it would report neighbouring data as
// reachable code.



// The names radare2 already has for the data this function points at.
//
// Mirrors the string-literal collector exactly: walk every reference out of the
// function's own bytes, and where radare2 has a flag for the address, keep the
// name beside it. A consumer holding only the snapshot otherwise renders a
// global as its address, which is the difference between `progName` and
// `0x6000`.
//
// Only flags that name data. A reference to another function is already carried
// as a successor or a callee, and repeating it here would let a call render its
// target twice under two different authorities.


#undef IMAGE_REFUSE



























// The signature is only offered when the capability says it was recovered, so
// an absent one reads as absent rather than as an empty prototype.







// The prototype of the function a call site targets, which is where a spelling
// like `size_t` for an argument comes from.


























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














R_API char *r_anal_function_get_assumptions_json(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, NULL);
	return strdup (R_STR_ISNOTEMPTY (fcn->assumptions_json)? fcn->assumptions_json: "[]");
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
		if (child->type != R_JSON_OBJECT) {
			r_json_free (parsed);
			free (trimmed);
			return false;
		}
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

















/* Record where the calling convention would place arguments and the result.
 *
 * These slots describe the convention, not the function: they are collected even
 * when no signature was recovered, and they say where a caller would leave a
 * value rather than that this function takes one. A consumer that recovers
 * parameters from the machine code needs the candidate list to intersect
 * against, and importing a guessed prototype instead would defeat the point. */




















/* Signedness of plain `char` for one target.
 *
 * C leaves it implementation-defined and the ABIs disagree: x86 and MIPS make
 * it signed, while AArch64, ARM, PowerPC, RISC-V and s390 make it unsigned.
 * Returns false for a target whose choice is not recorded here, so callers can
 * decline instead of assuming one.
 */




/* Remove cv-qualifier keywords from a type spec, in place.
 *
 * A qualifier changes none of what the type graph records: size, alignment,
 * signedness and storage are identical with or without it. Matching them as
 * substrings would also strike legitimate identifiers such as `atomic_t` or
 * `const_iterator`, so only whole words are removed.
 */

// A member spec carries its own extent, as `int32_t[8]`, because that is how the
// type importer records an array; the count field beside it stays zero. Returns
// the element spec with the extent removed, and the extent through `count`.
// NULL when the spec has brackets that do not spell one plain extent.




























// Refusals are reported through `reason` so a caller can say why a function
// could not be captured. Every refusal below names one cause.




// A consumer that reasons across a call needs the callee's body. Four is the
// bound because the cost is a full capture each and the reach a caller actually
// uses is its direct calls, not its transitive closure; recursion is refused
// outright rather than unrolled.





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

/* Content hash of one function's analysis, for artifact staleness.
 *
 * This used to build a whole function snapshot and read its revision
 * identity back out, which meant radare2 depended on r2sleigh's capture to
 * answer a question about its own stored artifacts. It hashes radare2's state
 * directly instead. Every input the old hash folded in was derived from these
 * same facts, so a change that mattered still changes the hash; hashing the
 * inputs rather than the derivations is the more conservative direction.
 *
 * The value is not stable across versions. Bumping the salt below invalidates
 * every stored artifact revision once, which is the intended way to force a
 * recapture after the hashed inputs change. */
#define FUNCTION_CONTEXT_HASH_SALT 2ULL

static ut64 context_hash_mix(ut64 hash, ut64 value) {
	hash ^= value;
	return hash * 0x100000001b3ULL;
}

static ut64 context_hash_string(ut64 hash, const char *string) {
	if (!string) {
		return context_hash_mix (hash, 0xffffffffffffffffULL);
	}
	const unsigned char *p = (const unsigned char *)string;
	while (*p) {
		hash = context_hash_mix (hash, (ut64)*p++);
	}
	return context_hash_mix (hash, 0);
}

R_API ut64 r_anal_function_context_hash(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (anal && fcn, 0);
	ut64 hash = 0xcbf29ce484222325ULL;
	hash = context_hash_mix (hash, FUNCTION_CONTEXT_HASH_SALT);
	hash = context_hash_mix (hash, fcn->addr);
	hash = context_hash_mix (hash, (ut64)r_anal_function_linear_size (fcn));
	hash = context_hash_mix (hash, (ut64)fcn->maxstack);
	hash = context_hash_mix (hash, (ut64)fcn->bits);
	hash = context_hash_mix (hash, (ut64)fcn->type);
	hash = context_hash_string (hash, fcn->name);
	hash = context_hash_string (hash, fcn->callconv);
	if (anal->config) {
		hash = context_hash_string (hash, anal->config->arch);
		hash = context_hash_string (hash, anal->config->cpu);
		hash = context_hash_mix (hash, (ut64)anal->config->bits);
		hash = context_hash_mix (hash, anal->config->big_endian? 1: 0);
	}
	RListIter *iter;
	RAnalBlock *block;
	r_list_foreach (fcn->bbs, iter, block) {
		if (!block) {
			continue;
		}
		hash = context_hash_mix (hash, block->addr);
		hash = context_hash_mix (hash, (ut64)block->size);
		hash = context_hash_mix (hash, block->jump);
		hash = context_hash_mix (hash, block->fail);
		if (block->switch_op) {
			hash = context_hash_mix (hash, block->switch_op->addr);
			hash = context_hash_mix (hash, block->switch_op->def_val);
			RListIter *case_iter;
			RAnalCaseOp *case_op;
			r_list_foreach (block->switch_op->cases, case_iter, case_op) {
				if (case_op) {
					hash = context_hash_mix (hash, case_op->value);
					hash = context_hash_mix (hash, case_op->jump);
				}
			}
		}
	}
	RAnalFcnVarsCache cache = {0};
	r_anal_function_vars_cache_init_readonly (anal, &cache, fcn);
	RAnalVar **var_it;
	R_VEC_FOREACH (cache.rvars, var_it) {
		RAnalVar *var = *var_it;
		if (var) {
			hash = context_hash_string (hash, var->name);
			hash = context_hash_string (hash, var->type);
			hash = context_hash_mix (hash, (ut64)(st64)var->delta);
		}
	}
	R_VEC_FOREACH (cache.bvars, var_it) {
		RAnalVar *var = *var_it;
		if (var) {
			hash = context_hash_string (hash, var->name);
			hash = context_hash_string (hash, var->type);
			hash = context_hash_mix (hash, (ut64)(st64)var->delta);
		}
	}
	R_VEC_FOREACH (cache.svars, var_it) {
		RAnalVar *var = *var_it;
		if (var) {
			hash = context_hash_string (hash, var->name);
			hash = context_hash_string (hash, var->type);
			hash = context_hash_mix (hash, (ut64)(st64)var->delta);
		}
	}
	r_anal_function_vars_cache_fini (&cache);
	// Deliberately not the dirty epochs. This is a hash of what the analysis
	// *says*, not of how many times it has been touched: every caller that
	// stores it also stores the two epochs and checks them separately, so
	// folding them in here would make a revision differ from itself after any
	// mutation that left the content alone -- including the artifact publish
	// whose result the caller is about to verify.
	hash = context_hash_mix (hash, r_anal_types_context_hash (anal));
	return hash? hash: 1;
}
