/* radare - LGPL - Copyright 2009-2025 - pancake, nibble, defragger, ret2libc */

// R2R db/cmd/cmd_aflxj db/cmd/cmd_aflxv db/cmd/cmd_ax

#include <r_anal.h>
#include <r_core.h>
#include <r_cons.h>
#include <r_vec.h>
#include <sdb/cwisstable.h>

R_VEC_TYPE (RVecAnalRef, RAnalRef);

// xrefs are stored as an adjacency list (in both directions),
// as a hastable mapping at (from) to hashtables mapping addr (at) to a ref type.
CWISS_DECLARE_FLAT_HASHMAP_DEFAULT(Edges, ut64, RAnalRefType);
// TODO store Edges directly in other hashmap, but how to hash & compare the hashmap itself?
CWISS_DECLARE_FLAT_HASHMAP_DEFAULT(AdjacencyList, ut64, Edges*);

#define INITIAL_CAPACITY 0

#define R_HM_FOREACH(type, hm, entry) \
	type##_CIter iter; \
	for (iter = type##_citer ((hm)); (entry = type##_CIter_get (&iter)) != NULL; type##_CIter_next (&iter))

#define R_ADJACENCY_LIST_FOREACH(adj_list, entry) R_HM_FOREACH(AdjacencyList, adj_list, entry)
#define R_EDGES_FOREACH(edges, entry) R_HM_FOREACH(Edges, edges, entry)

// NOTE: this is heavy in memory usage, but needed due to performance reasons for large amounts of xrefs..
typedef struct r_ref_manager_t {
	R_ALIGNED(16) AdjacencyList refs;   // forward refs
	R_ALIGNED(16) AdjacencyList xrefs;  // backward refs
} RefManager;

static inline int compare_ref(const RAnalRef *a, const RAnalRef *b) {
	if (a->at < b->at) {
		return -1;
	}
	if (a->at > b->at) {
		return 1;
	}
	if (a->addr < b->addr) {
		return -1;
	}
	if (a->addr > b->addr) {
		return 1;
	}
	return 0;
}

static RefManager *ref_manager_new(void) {
	RefManager *rm = R_NEW0 (RefManager);
	rm->refs = AdjacencyList_new (INITIAL_CAPACITY);
	rm->xrefs = AdjacencyList_new (INITIAL_CAPACITY);
	return rm;
}

static inline void adjacency_list_fini(AdjacencyList *adj_list) {
	const AdjacencyList_Entry *entry;
	R_ADJACENCY_LIST_FOREACH (adj_list, entry) {
		Edges *edges = entry->val;
		Edges_destroy (edges);
		free (edges);
	}
	AdjacencyList_destroy (adj_list);
}

static void ref_manager_free(RefManager *rm) {
	if (R_LIKELY (rm)) {
		adjacency_list_fini (&rm->refs);
		adjacency_list_fini (&rm->xrefs);
	}
	free (rm);
}

static void _add_ref(AdjacencyList *adj_list, ut64 from, ut64 to, RAnalRefType type) {
	AdjacencyList_Iter iter = AdjacencyList_find (adj_list, &from);
	AdjacencyList_Entry *entry = AdjacencyList_Iter_get (&iter);
	Edges *edges = entry ? entry->val : NULL;
	if (!edges) {
		// optionally add a hashtable if missing
		edges = R_NEW0 (Edges);
		if (!edges) {
			R_LOG_WARN ("failed to allocate hashtable for xrefs");
			return;
		}

		*edges = Edges_new (INITIAL_CAPACITY);
		AdjacencyList_Entry new_entry = { .key = from, .val = edges };
		AdjacencyList_insert (adj_list, &new_entry); // adds the new (empty) hashtable
	}
	Edges_Entry edge_entry = { .key = to, .val = type };
	Edges_Insert result = Edges_insert (edges, &edge_entry); // and adds the ref
	if (!result.inserted) {
		Edges_Entry *existing_entry = Edges_Iter_get (&result.iter);
		existing_entry->val = type;
	}
}

static void ref_manager_add_entry(RefManager *rm, ut64 from, ut64 to, RAnalRefType type) {
	_add_ref (&rm->refs, from, to, type);
	_add_ref (&rm->xrefs, to, from, type);
}

static void _delete_ref(AdjacencyList *adj_list, ut64 from, ut64 to) {
	AdjacencyList_Iter iter = AdjacencyList_find (adj_list, &from);
	AdjacencyList_Entry *entry = AdjacencyList_Iter_get (&iter);
	Edges *edges = entry ? entry->val : NULL;
	if (edges) {
		if (Edges_size (edges) == 1) {
			AdjacencyList_erase_at (iter); // delete rest of hashtable
		} else {
			Edges_erase (edges, &to); // delete only a reference
		}
	}
}

// TODO add extra R_API call for deleting all refs, can be implemented in a more performant way
static void ref_manager_remove_entry(RefManager *rm, ut64 from, ut64 to) {
	_delete_ref (&rm->refs, from, to);
	_delete_ref (&rm->xrefs, to, from);
}

static ut64 ref_manager_count_xrefs(RefManager *rm) {
	R_RETURN_VAL_IF_FAIL (rm, 0);

	ut64 count = 0;

	const AdjacencyList_Entry *entry;
	R_ADJACENCY_LIST_FOREACH (&rm->xrefs, entry) {
		count += Edges_size (entry->val);
	}

	return count;
}

static ut64 ref_manager_count_xrefs_at(RefManager *rm, ut64 to) {
	R_RETURN_VAL_IF_FAIL (rm, 0);

	AdjacencyList_CIter iter = AdjacencyList_cfind (&rm->xrefs, &to);
	const AdjacencyList_Entry *entry = AdjacencyList_CIter_get (&iter);
	const Edges *edges = entry? entry->val: NULL;

	return edges? Edges_size (edges): 0;
}

static RVecAnalRef *_collect_all_refs(RefManager *rm, const AdjacencyList *adj_list) {
	RVecAnalRef *result = RVecAnalRef_new ();
	if (R_UNLIKELY (!result)) {
		return NULL;
	}

	const ut64 length = ref_manager_count_xrefs (rm);
	if (!RVecAnalRef_reserve (result, length)) {
		RVecAnalRef_free (result);
		return NULL;
	}

	const AdjacencyList_Entry *entry;
	R_ADJACENCY_LIST_FOREACH (adj_list, entry) {
		const Edges_Entry *edge_entry;
		R_EDGES_FOREACH (entry->val, edge_entry) {
			RAnalRef *ref = RVecAnalRef_emplace_back (result);
			if (R_UNLIKELY (!ref)) {
				RVecAnalRef_free (result);
				return false;
			}
			ref->at = entry->key;
			ref->addr = edge_entry->key;
			ref->type = edge_entry->val;
		}
	}

	return result;
}

static RVecAnalRef *_collect_refs_from(const AdjacencyList *adj_list, ut64 from) {
	// only finds entries with matching "from"
	const Edges *edges = NULL;
	{
		AdjacencyList_CIter iter = AdjacencyList_cfind (adj_list, &from);
		const AdjacencyList_Entry *entry = AdjacencyList_CIter_get (&iter);
		edges = entry ? entry->val : NULL;
	}
	if (!edges) {
		return NULL;
	}

	RVecAnalRef *result = RVecAnalRef_new ();
	if (R_UNLIKELY (!result)) {
		return NULL;
	}

	ut64 ref_count = Edges_size (edges);
	if (!RVecAnalRef_reserve (result, ref_count)) {
		RVecAnalRef_free (result);
		return NULL;
	}

	const Edges_Entry *entry;
	R_EDGES_FOREACH(edges, entry) {
		RAnalRef *ref = RVecAnalRef_emplace_back (result);
		if (R_UNLIKELY (!ref)) {
			RVecAnalRef_free (result);
			return NULL;
		}

		ref->at = from;
		ref->addr = entry->key;
		ref->type = entry->val;
	}

	return result;
}

static RVecAnalRef *_collect_refs(RefManager *rm, const AdjacencyList *adj_list, ut64 addr) {
	return addr == UT64_MAX
		? _collect_all_refs (rm, adj_list)
		: _collect_refs_from (adj_list, addr);
}

static inline RVecAnalRef *ref_manager_get_refs(RefManager *rm, ut64 from) {
	R_RETURN_VAL_IF_FAIL (rm, NULL);
	return _collect_refs (rm, &rm->refs, from);
}

static inline RVecAnalRef *ref_manager_get_xrefs(RefManager *rm, ut64 to) {
	R_RETURN_VAL_IF_FAIL (rm, NULL);
	return _collect_refs (rm, &rm->xrefs, to);
}

R_API bool r_anal_xrefs_init(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal, false);

	r_anal_xrefs_free (anal);
	anal->rm = ref_manager_new ();
	return !!anal->rm;
}

R_API void r_anal_xrefs_free(RAnal *anal) {
	R_RETURN_IF_FAIL (anal);
	ref_manager_free (anal->rm);
}

// set a reference from FROM to TO and a cross-reference(xref) from TO to FROM.
R_API bool r_anal_xrefs_set(RAnal *anal, ut64 from, ut64 to, const RAnalRefType _type) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, false);

	if (from == to || from == UT64_MAX || to == UT64_MAX) {
		return false;
	}
	if (anal->iob.is_valid_offset) {
		if (!anal->iob.is_valid_offset (anal->iob.io, from, 0)) {
			return false;
		}
		if (!anal->iob.is_valid_offset (anal->iob.io, to, 0)) {
			return false;
		}
	}

	RAnalRefType type = _type;
	if (!R_ANAL_REF_TYPE_PERM (type)) {
		// type |= R_ANAL_REF_TYPE_READ;
		switch (R_ANAL_REF_TYPE_MASK (type)) {
		case R_ANAL_REF_TYPE_CODE:
		case R_ANAL_REF_TYPE_CALL:
		case R_ANAL_REF_TYPE_JUMP:
			type |= R_ANAL_REF_TYPE_EXEC;
			break;
		default:
			type |= R_ANAL_REF_TYPE_READ;
			break;
		}
	}

	ref_manager_add_entry (anal->rm, from, to, type);
	R_DIRTY_SET (anal);

	// Invalidate function ref counts
	RAnalFunction *fcn_from = r_anal_get_function_at (anal, from);
	if (fcn_from) {
		fcn_from->meta.numcallrefs = -1;
	}
	RAnalFunction *fcn_to = r_anal_get_function_at (anal, to);
	if (fcn_to) {
		fcn_to->meta.numrefs = -1;
	}

	return true;
}

R_API bool r_anal_xref_del(RAnal *anal, ut64 from, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal, false);
	ref_manager_remove_entry (anal->rm, from, to);
	R_DIRTY_SET (anal);

	// Invalidate function ref counts
	RAnalFunction *fcn_from = r_anal_get_function_at (anal, from);
	if (fcn_from) {
		fcn_from->meta.numcallrefs = -1;
	}
	RAnalFunction *fcn_to = r_anal_get_function_at (anal, to);
	if (fcn_to) {
		fcn_to->meta.numrefs = -1;
	}

	return true;
}

R_API RVecAnalRef *r_anal_refs_get(RAnal *anal, ut64 from) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, NULL);

	RVecAnalRef *anal_refs = ref_manager_get_refs (anal->rm, from);
	if (!anal_refs || RVecAnalRef_empty (anal_refs)) {
		RVecAnalRef_free (anal_refs);
		return NULL;
	}

	RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?
	return anal_refs;
}

R_API RVecAnalRef *r_anal_xrefs_get(RAnal *anal, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, NULL);

	RVecAnalRef *anal_refs = ref_manager_get_xrefs (anal->rm, to);
	if (!anal_refs || RVecAnalRef_empty (anal_refs)) {
		RVecAnalRef_free (anal_refs);
		return NULL;
	}

	RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?
	return anal_refs;
}

R_API RVecAnalRef *r_anal_xrefs_get_from(RAnal *anal, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, NULL);

	RVecAnalRef *anal_refs = ref_manager_get_refs (anal->rm, to);
	if (!anal_refs || RVecAnalRef_empty (anal_refs)) {
		RVecAnalRef_free (anal_refs);
		return NULL;
	}

	RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?
	return anal_refs;
}

R_API bool r_anal_xrefs_has_xrefs_at(RAnal *anal, ut64 at) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, false);

	AdjacencyList_CIter iter = AdjacencyList_cfind (&anal->rm->xrefs, &at);
	const AdjacencyList_Entry *entry = AdjacencyList_CIter_get (&iter);
	return !!entry;
}

static void r_anal_xrefs_list_table(RAnal *anal, RVecAnalRef *anal_refs, const char *arg, RTable *table) {
	if (!table) {
		table = r_table_new ("xrefs");
	}
	r_table_set_columnsf (table, "dddssss", "from", "to", "size", "type", "perm", "fromname", "toname");

	RAnalRef *ref;
	R_VEC_FOREACH (anal_refs, ref) {
		int t = R_ANAL_REF_TYPE_MASK (ref->type);
		char *fromname = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
		char *toname = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
		r_table_add_rowf (table, "xxnssss",
				ref->at, ref->addr,
				r_anal_ref_size (ref),
				r_anal_ref_type_tostring (t),
				r_anal_ref_perm_tostring (ref),
				toname, fromname
		);
		free (fromname);
		free (toname);
	}

	bool show_table = true;
	if (R_STR_ISNOTEMPTY (arg)) {
		show_table = r_table_query (table, arg);
	}
	if (show_table) {
		char *s = r_table_tostring (table);
		RCore *core = anal->coreb.core;
		RCons *cons = core->cons;
		r_cons_print (cons, s);
		free (s);
	}
	r_table_free (table);
}

static void r_anal_xrefs_list_json(RAnal *anal, RVecAnalRef *anal_refs) {
	PJ *pj = anal->coreb.pjWithEncoding (anal->coreb.core);
	if (!pj) {
		return;
	}

	pj_a (pj);

	RAnalRef *ref;
	R_VEC_FOREACH (anal_refs, ref) {
		int t = R_ANAL_REF_TYPE_MASK (ref->type);
		if (!t) {
			t = ' ';
		}

		pj_o (pj);

		char *name = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
		if (name) {
			r_str_replace_ch (name, ' ', 0, true);
			pj_ks (pj, "name", name);
			free (name);
		}

		pj_kn (pj, "from", ref->at);
		pj_ks (pj, "type", r_anal_ref_type_tostring (t));
		pj_ks (pj, "perm", r_anal_ref_perm_tostring (ref));
		pj_kn (pj, "addr", ref->addr);

		name = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
		if (name) {
			r_str_replace_ch (name, ' ', 0, true);
			pj_ks (pj, "refname", name);
			free (name);
		}

		pj_end (pj);
	}

	pj_end (pj);

	anal->cb_printf ("%s\n", pj_string (pj));
	pj_free (pj);
}

static void r_anal_xrefs_list_hex(RAnal *anal, RVecAnalRef *anal_refs) {
	RAnalRef *ref;
	R_VEC_FOREACH (anal_refs, ref) {
		const int t = R_ANAL_REF_TYPE_MASK (ref->type);
		// TODO: export/import the read-write-exec information
		anal->cb_printf ("ax%c 0x%"PFMT64x" 0x%"PFMT64x"\n", t? t: ' ', ref->addr, ref->at);
	}
}

static void r_anal_xrefs_list_mapping(RAnal *anal, RVecAnalRef *anal_refs) {
	RAnalRef *ref;
	R_VEC_FOREACH (anal_refs, ref) {
		RAnalRefType t = R_ANAL_REF_TYPE_MASK (ref->type);
		anal->cb_printf ("0x%08"PFMT64x" -> 0x%08"PFMT64x"  %s:%s\n", ref->at, ref->addr,
			r_anal_ref_type_tostring (t), r_anal_ref_perm_tostring (ref));
	}
}

static void r_anal_xrefs_list_plaintext(RAnal *anal, RVecAnalRef *anal_refs) {
	RAnalRef *ref;
	R_VEC_FOREACH (anal_refs, ref) {
		int t = R_ANAL_REF_TYPE_MASK (ref->type);
		if (!t) {
			t = ' ';
		}

		char *name = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
		if (name) {
			r_str_replace_ch (name, ' ', 0, true);
			anal->cb_printf ("%40s", name);
			free (name);
		} else {
			anal->cb_printf ("%40s", "?");
		}

		anal->cb_printf (" 0x%"PFMT64x" > %4s:%s > 0x%"PFMT64x, ref->at,
			r_anal_ref_type_tostring (t), r_anal_ref_perm_tostring (ref), ref->addr);

		name = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
		if (name) {
			r_str_replace_ch (name, ' ', 0, true);
			anal->cb_printf (" %s\n", name);
			free (name);
		} else {
			anal->cb_printf ("\n");
		}
	}
}

R_API void r_anal_xrefs_list(RAnal *anal, int rad, const char *arg, RTable *t) {
	R_RETURN_IF_FAIL (anal && anal->rm);

	RVecAnalRef *anal_refs = ref_manager_get_refs (anal->rm, UT64_MAX);
	if (!anal_refs) {
		R_LOG_DEBUG ("Could not list xrefs");
		return;
	}

	RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?

	switch (rad) {
	case ',':
		r_anal_xrefs_list_table (anal, anal_refs, arg, t);
		break;
	case 'j':
		r_anal_xrefs_list_json (anal, anal_refs);
		break;
	case '*':
		r_anal_xrefs_list_hex (anal, anal_refs);
		break;
	case 'q':
		r_anal_xrefs_list_mapping (anal, anal_refs);
		break;
	case '\0':
		r_anal_xrefs_list_plaintext (anal, anal_refs);
		break;
	default:
		R_LOG_DEBUG ("Unsupported xrefs list format: %c", rad);
		break;
	}

	RVecAnalRef_free (anal_refs);
}

R_API ut64 r_anal_xrefs_count(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, 0);
	return ref_manager_count_xrefs (anal->rm);
}

R_API ut64 r_anal_xrefs_count_at(RAnal *anal, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, 0);
	return ref_manager_count_xrefs_at (anal->rm, to);
}

R_API RVecAnalRef *r_anal_function_get_xrefs(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);

	RefManager *rm = fcn->anal->rm;
	// XXX assume first basic block is the entrypoint
	RVecAnalRef *anal_refs = ref_manager_get_xrefs (rm, fcn->addr);
	if (anal_refs) {
		RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?
	}
	return anal_refs;
}

typedef RVecAnalRef *(*CollectFn)(RefManager *rm, ut64 addr);

static RVecAnalRef *fcn_get_all_refs(RAnalFunction *fcn, RefManager *rm, CollectFn collect_refs) {
	RVecAnalRef *anal_refs = RVecAnalRef_new ();
	if (R_LIKELY (anal_refs)) {
		RListIter *iter;
		RAnalBlock *bb;
		r_list_foreach (fcn->bbs, iter, bb) {
			// TODO : add an option to choose to iterate over bytes or ops
#if 1
			// iterate over instructions
			int i;
			for (i = 0; i < bb->ninstr; i++) {
				ut64 addr = bb->addr + r_anal_bb_offset_inst (bb, i);
#else
			// iterate on every byte -- slower but more "precise somehow?"
			ut64 addr;
			ut64 end = bb->addr + bb->size;
			for (addr = bb->addr; addr < end; addr++) {
#endif
				RVecAnalRef *refs = collect_refs (rm, addr);
				if (refs) {
					RVecAnalRef_append (anal_refs, refs, NULL);
					RVecAnalRef_free (refs);
				}
			}
		}
		RVecAnalRef_sort (anal_refs, compare_ref);

		// Remove duplicates after sorting
		if (!RVecAnalRef_empty (anal_refs)) {
			RAnalRef *write_ptr = anal_refs->_start;
			RAnalRef *read_ptr = anal_refs->_start + 1;
			RAnalRef *end_ptr = anal_refs->_end;

			while (read_ptr < end_ptr) {
				// Only keep if different from previous
				if (compare_ref (write_ptr, read_ptr) != 0) {
					write_ptr++;
					if (write_ptr != read_ptr) {
						*write_ptr = *read_ptr;
					}
				}
				read_ptr++;
			}

			// Truncate by adjusting end pointer
			anal_refs->_end = write_ptr + 1;
		}
	}

	return anal_refs;
}

// XXX rename to r_anal_function_get_all_refs?
R_API RVecAnalRef *r_anal_function_get_refs(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
	return fcn_get_all_refs (fcn, fcn->anal->rm, ref_manager_get_refs);
}

R_API RVecAnalRef *r_anal_function_get_all_xrefs(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn, NULL);
	return fcn_get_all_refs (fcn, fcn->anal->rm, ref_manager_get_xrefs);
}

// Helper function to count refs without allocating
typedef ut64 (*CountFn)(RefManager *rm, ut64 addr, RAnalRefType type_filter);

static inline bool ref_matches_type(const RAnalRef *ref, RAnalRefType type_filter) {
	return type_filter == R_ANAL_REF_TYPE_ANY || R_ANAL_REF_TYPE_MASK (ref->type) == type_filter;
}

static ut64 ref_manager_count_refs_filtered(RefManager *rm, ut64 addr, RAnalRefType type_filter) {
	RVecAnalRef *refs = ref_manager_get_refs (rm, addr);
	if (!refs) {
		return 0;
	}
	ut64 count = 0;
	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
		if (ref_matches_type (ref, type_filter)) {
			count++;
		}
	}
	RVecAnalRef_free (refs);
	return count;
}

static ut64 ref_manager_count_xrefs_filtered(RefManager *rm, ut64 addr, RAnalRefType type_filter) {
	RVecAnalRef *refs = ref_manager_get_xrefs (rm, addr);
	if (!refs) {
		return 0;
	}
	ut64 count = 0;
	RAnalRef *ref;
	R_VEC_FOREACH (refs, ref) {
		if (ref_matches_type (ref, type_filter)) {
			count++;
		}
	}
	RVecAnalRef_free (refs);
	return count;
}

static ut64 fcn_count_refs(RAnalFunction *fcn, RefManager *rm, CountFn count_refs, RAnalRefType type_filter) {
	ut64 total = 0;
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		int i;
		for (i = 0; i < bb->ninstr; i++) {
			ut64 addr = bb->addr + r_anal_bb_offset_inst (bb, i);
			total += count_refs (rm, addr, type_filter);
		}
	}
	return total;
}

// Count refs of a specific type from a function (use R_ANAL_REF_TYPE_ANY to count all)
R_API ut64 r_anal_function_count_refs(RAnalFunction *fcn, RAnalRefType type) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	if (type == R_ANAL_REF_TYPE_CALL && fcn->meta.numcallrefs != -1) {
		return fcn->meta.numcallrefs;
	}
	ut64 count = fcn_count_refs (fcn, fcn->anal->rm, ref_manager_count_refs_filtered, type);
	if (type == R_ANAL_REF_TYPE_CALL) {
		fcn->meta.numcallrefs = count;
	}
	return count;
}

// Count xrefs to a function (optionally filtered by type)
R_API ut64 r_anal_function_count_xrefs(RAnalFunction *fcn, RAnalRefType type) {
	R_RETURN_VAL_IF_FAIL (fcn, 0);
	if (type == R_ANAL_REF_TYPE_ANY && fcn->meta.numrefs != -1) {
		return fcn->meta.numrefs;
	}
	// For xrefs, we only need to check the function entry point
	ut64 count = ref_manager_count_xrefs_filtered (fcn->anal->rm, fcn->addr, type);
	if (type == R_ANAL_REF_TYPE_ANY) {
		fcn->meta.numrefs = count;
	}
	return count;
}

R_API char r_anal_ref_perm_tochar(RAnalRef *ref) {
	if (ref->type & R_ANAL_REF_TYPE_WRITE) {
		return 'w';
	}
	if (ref->type & R_ANAL_REF_TYPE_READ) {
		return 'r';
	}
	if (ref->type & R_ANAL_REF_TYPE_EXEC) {
		return 'x';
	}
	switch (R_ANAL_REF_TYPE_MASK (ref->type)) {
	case R_ANAL_REF_TYPE_STRN:
		return 'r';
	case R_ANAL_REF_TYPE_CODE:
	case R_ANAL_REF_TYPE_CALL:
	case R_ANAL_REF_TYPE_JUMP:
		return 'x';
	}
	return '-';
}

R_API const char *r_anal_ref_perm_tostring(RAnalRef *ref) {
	ut32 perm = R_ANAL_REF_TYPE_PERM (ref->type);
	if (!perm) {
		switch (R_ANAL_REF_TYPE_MASK (ref->type)) {
		case R_ANAL_REF_TYPE_CODE:
		case R_ANAL_REF_TYPE_CALL:
		case R_ANAL_REF_TYPE_JUMP:
			perm = R_ANAL_REF_TYPE_EXEC;
			break;
		}
	}
	return r_str_rwx_i (perm);
}

R_API int r_anal_ref_size(RAnalRef *ref) {
	int size = R_ANAL_REF_TYPE_SIZE (ref->type);
	if (size) {
		return size;
	}
	switch (R_ANAL_REF_TYPE_MASK (ref->type)) {
	case R_ANAL_REF_TYPE_ICOD:
		return 4; // or 8?
	case R_ANAL_REF_TYPE_DATA:
		return 4; // or 8?
	}
	return 0;
}

R_API const char *r_anal_ref_type_tostring(RAnalRefType type) {
	switch (R_ANAL_REF_TYPE_MASK (type)) {
	case R_ANAL_REF_TYPE_NULL:
		return "NULL";
	case R_ANAL_REF_TYPE_ICOD:
		return "ICOD";
	case R_ANAL_REF_TYPE_CODE:
		return "CODE";
	case R_ANAL_REF_TYPE_CALL:
		return "CALL";
	case R_ANAL_REF_TYPE_JUMP:
		return "JUMP";
	case R_ANAL_REF_TYPE_DATA:
		return "DATA";
	case R_ANAL_REF_TYPE_STRN:
		return "STRN";
	default:
		// R_LOG_ERROR ("Invalid unknown ref type %c", R_ANAL_REF_TYPE_MASK (type));
		return "UNKN";
	}
}

// UNUSED
R_API RAnalRefType r_anal_xrefs_type_from_string(const char *s) {
	RAnalRefType rt = R_ANAL_REF_TYPE_NULL;
	if (strchr (s, 'r')) {
		rt |= (R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_READ);
	}
	if (strchr (s, 'w')) {
		rt |= (R_ANAL_REF_TYPE_DATA | R_ANAL_REF_TYPE_WRITE);
	}
	if (strchr (s, 'x')) {
		rt |= R_ANAL_REF_TYPE_EXEC;
	}
	if (strchr (s, 'c')) {
		rt |= R_ANAL_REF_TYPE_CODE;
	}
	if (strchr (s, 'C')) {
		rt |= R_ANAL_REF_TYPE_CALL;
	}
	if (strchr (s, 'j')) {
		rt |= R_ANAL_REF_TYPE_JUMP;
	}
	if (strchr (s, 'd')) {
		rt |= R_ANAL_REF_TYPE_DATA;
	}
	if (strchr (s, 's')) {
		rt |= R_ANAL_REF_TYPE_STRN;
	}
	return rt;
}

R_API int r_anal_ref_typemask(int x) {
	const int maskedType = x & 0xff;
	switch (maskedType) {
	case R_ANAL_REF_TYPE_NULL:
	case R_ANAL_REF_TYPE_CODE | R_ANAL_REF_TYPE_DATA: // 'g' // XXX R2_590 - this is a conflictive type
	case R_ANAL_REF_TYPE_CODE: // 'c' // code ref
	case R_ANAL_REF_TYPE_CALL: // 'C' // code ref (call)
	case R_ANAL_REF_TYPE_JUMP: // 'j' // code ref (call)
	case R_ANAL_REF_TYPE_DATA: // 'd' // mem ref
	case R_ANAL_REF_TYPE_STRN: // 's' // string ref
	case R_ANAL_REF_TYPE_ICOD: // 'i' // indirect cod reference
		return maskedType;
	case ' ':
		return R_ANAL_REF_TYPE_NULL;
	}
	R_LOG_ERROR ("Invalid reftype mask '%c' (0x%02x)", x, x);
	// SHOULD NEVER HAPPEN MAYBE WARN HERE
	return 0;
}

// TODO: deprecate
R_API RAnalRefType r_anal_xrefs_type(char ch) {
	switch (ch) {
	case R_ANAL_REF_TYPE_CODE:
	case R_ANAL_REF_TYPE_CALL:
	case R_ANAL_REF_TYPE_DATA:
	case R_ANAL_REF_TYPE_STRN:
	case R_ANAL_REF_TYPE_ICOD:
	case R_ANAL_REF_TYPE_NULL:
		return (RAnalRefType)ch;
	default:
		return R_ANAL_REF_TYPE_NULL;
	}
}
