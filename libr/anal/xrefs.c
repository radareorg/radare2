/* radare - LGPL - Copyright 2009-2025 - pancake, nibble, defragger, ret2libc */

// R2R db/cmd/cmd_aflxj db/cmd/cmd_aflxv db/cmd/cmd_ax

#include <r_anal_priv.h>
#include <r_core.h>
#include <r_cons.h>
#include <r_vec.h>
#include <sdb/cwisstable.h>

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
typedef struct r_owned_xref_set_internal_t {
	char *producer_namespace;
	ut64 owner_addr;
	RAnalRef *refs;
	size_t ref_count;
	struct r_owned_xref_set_internal_t *next;
} OwnedXrefSetInternal;

typedef struct r_ref_manager_t {
	R_ALIGNED(16) AdjacencyList refs;   // forward refs
	R_ALIGNED(16) AdjacencyList xrefs;  // backward refs
	R_ALIGNED(16) AdjacencyList unowned_refs;
	OwnedXrefSetInternal *owned_sets;
} RefManager;

typedef struct r_affected_xref_address_t {
	ut64 addr;
	ut8 roles;
} AffectedXrefAddress;

struct r_anal_owned_xref_prepared_t {
	RAnal *source_anal;
	RefManager *rm;
	AffectedXrefAddress *affected;
	size_t affected_count;
	bool changed;
};

enum {
	AFFECTED_XREF_SOURCE = 1,
	AFFECTED_XREF_TARGET = 2,
};

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
	rm->unowned_refs = AdjacencyList_new (INITIAL_CAPACITY);
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
		adjacency_list_fini (&rm->unowned_refs);
		OwnedXrefSetInternal *set = rm->owned_sets;
		while (set) {
			OwnedXrefSetInternal *next = set->next;
			free (set->producer_namespace);
			free (set->refs);
			free (set);
			set = next;
		}
	}
	free (rm);
}

static bool _add_ref(AdjacencyList *adj_list, ut64 from, ut64 to, RAnalRefType type) {
	AdjacencyList_Iter iter = AdjacencyList_find (adj_list, &from);
	AdjacencyList_Entry *entry = AdjacencyList_Iter_get (&iter);
	Edges *edges = entry ? entry->val : NULL;
	if (!edges) {
		// optionally add a hashtable if missing
		edges = R_NEW0 (Edges);
		if (!edges) {
			R_LOG_WARN ("failed to allocate hashtable for xrefs");
			return false;
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
	return true;
}

static void _delete_ref(AdjacencyList *adj_list, ut64 from, ut64 to);

static bool ref_manager_add_entry(RefManager *rm, ut64 from, ut64 to, RAnalRefType type) {
	if (!_add_ref (&rm->refs, from, to, type)) {
		return false;
	}
	if (!_add_ref (&rm->xrefs, to, from, type)) {
		_delete_ref (&rm->refs, from, to);
		return false;
	}
	return true;
}

static void _delete_ref(AdjacencyList *adj_list, ut64 from, ut64 to) {
	AdjacencyList_Iter iter = AdjacencyList_find (adj_list, &from);
	AdjacencyList_Entry *entry = AdjacencyList_Iter_get (&iter);
	Edges *edges = entry ? entry->val : NULL;
	if (edges) {
		Edges_CIter edge_iter = Edges_cfind (edges, &to);
		if (!Edges_CIter_get (&edge_iter)) {
			return;
		}
		if (Edges_size (edges) == 1) {
			AdjacencyList_erase_at (iter); // delete rest of hashtable
			Edges_destroy (edges);
			free (edges);
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
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, false);
	RefManager *replacement = ref_manager_new ();
	r_th_lock_enter (anal->lock);
	RefManager *old = anal->rm;
	anal->rm = replacement;
	ref_manager_free (old);
	r_th_lock_leave (anal->lock);
	return true;
}

R_API void r_anal_xrefs_free(RAnal *anal) {
	R_RETURN_IF_FAIL (anal && anal->lock);
	r_th_lock_enter (anal->lock);
	RefManager *rm = anal->rm;
	anal->rm = NULL;
	ref_manager_free (rm);
	r_th_lock_leave (anal->lock);
}

static inline RAnalRefType xref_resolve_type(const RAnalRefType _type) {
	RAnalRefType type = _type;
	if (!R_ANAL_REF_TYPE_PERM (type)) {
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
	return type;
}

static bool ref_type_at(const AdjacencyList *adj_list, ut64 from, ut64 to, RAnalRefType *type) {
	AdjacencyList_CIter iter = AdjacencyList_cfind (adj_list, &from);
	const AdjacencyList_Entry *entry = AdjacencyList_CIter_get (&iter);
	if (!entry) {
		return false;
	}
	Edges_CIter edge_iter = Edges_cfind (entry->val, &to);
	const Edges_Entry *edge = Edges_CIter_get (&edge_iter);
	if (!edge) {
		return false;
	}
	if (type) {
		*type = edge->val;
	}
	return true;
}

static bool owned_ref_type_valid(RAnalRefType type) {
	if (type < 0) {
		return false;
	}
	const ut32 raw = (ut32)type;
	const ut32 allowed = R_ANAL_REF_TYPE_MASK | R_ANAL_REF_PERM_MASK | R_ANAL_REF_SIZE_MASK;
	if (raw & ~allowed) {
		return false;
	}
	switch (raw & R_ANAL_REF_TYPE_MASK) {
	case R_ANAL_REF_TYPE_CODE:
	case R_ANAL_REF_TYPE_CALL:
	case R_ANAL_REF_TYPE_JUMP:
	case R_ANAL_REF_TYPE_DATA:
	case R_ANAL_REF_TYPE_ICOD:
	case R_ANAL_REF_TYPE_STRN:
		break;
	default:
		return false;
	}
	const ut32 perms = raw & R_ANAL_REF_PERM_MASK;
	if (perms & ~(R_ANAL_REF_TYPE_READ | R_ANAL_REF_TYPE_WRITE | R_ANAL_REF_TYPE_EXEC)) {
		return false;
	}
	switch (R_ANAL_REF_TYPE_SIZE (raw)) {
	case 0:
	case 1:
	case 2:
	case 4:
	case 8:
		return true;
	default:
		return false;
	}
}

static int compare_owned_ref(const void *a, const void *b) {
	const RAnalRef *ra = a;
	const RAnalRef *rb = b;
	int cmp = compare_ref (ra, rb);
	if (cmp) {
		return cmp;
	}
	if (ra->type < rb->type) {
		return -1;
	}
	return ra->type > rb->type;
}

static bool owned_ref_endpoint_equal(const RAnalRef *a, const RAnalRef *b) {
	return a->at == b->at && a->addr == b->addr;
}

static void owned_xref_set_free(OwnedXrefSetInternal *set) {
	if (set) {
		free (set->producer_namespace);
		free (set->refs);
		free (set);
	}
}

static RAnalOwnedXrefStatus owned_xref_set_prepare(RAnal *anal, const RAnalOwnedXrefSet *input, OwnedXrefSetInternal **result) {
	*result = NULL;
	if (!input || !R_STR_ISNOTEMPTY (input->producer_namespace) || input->owner_addr == UT64_MAX) {
		return R_ANAL_OWNED_XREF_STATUS_INVALID;
	}
	if (r_str_nlen (input->producer_namespace, R_ANAL_OWNED_XREF_NAMESPACE_MAX + 1) > R_ANAL_OWNED_XREF_NAMESPACE_MAX) {
		return R_ANAL_OWNED_XREF_STATUS_INVALID;
	}
	if (input->ref_count && !input->refs) {
		return R_ANAL_OWNED_XREF_STATUS_INVALID;
	}
	OwnedXrefSetInternal *set = R_NEW0 (OwnedXrefSetInternal);
	set->producer_namespace = strdup (input->producer_namespace);
	if (!set->producer_namespace) {
		owned_xref_set_free (set);
		return R_ANAL_OWNED_XREF_STATUS_NOMEM;
	}
	set->owner_addr = input->owner_addr;
	if (!input->ref_count) {
		*result = set;
		return R_ANAL_OWNED_XREF_STATUS_OK;
	}
	size_t alloc_size;
	if (r_mul_overflow_size_t (input->ref_count, sizeof (RAnalRef), &alloc_size)) {
		owned_xref_set_free (set);
		return R_ANAL_OWNED_XREF_STATUS_INVALID;
	}
	set->refs = calloc (1, alloc_size);
	if (!set->refs) {
		owned_xref_set_free (set);
		return R_ANAL_OWNED_XREF_STATUS_NOMEM;
	}
	size_t i;
	for (i = 0; i < input->ref_count; i++) {
		const RAnalRef *ref = &input->refs[i];
		if (ref->at == ref->addr || ref->at == UT64_MAX || ref->addr == UT64_MAX
			|| !owned_ref_type_valid (ref->type)) {
			owned_xref_set_free (set);
			return R_ANAL_OWNED_XREF_STATUS_INVALID;
		}
		if (anal->iob.is_valid_offset
			&& (!anal->iob.is_valid_offset (anal->iob.io, ref->at, 0)
				|| !anal->iob.is_valid_offset (anal->iob.io, ref->addr, 0))) {
			owned_xref_set_free (set);
			return R_ANAL_OWNED_XREF_STATUS_INVALID;
		}
		set->refs[i].at = ref->at;
		set->refs[i].addr = ref->addr;
		set->refs[i].type = xref_resolve_type (ref->type);
	}
	qsort (set->refs, input->ref_count, sizeof (RAnalRef), compare_owned_ref);
	size_t write = 0;
	for (i = 0; i < input->ref_count; i++) {
		if (write && owned_ref_endpoint_equal (&set->refs[write - 1], &set->refs[i])) {
			if (set->refs[write - 1].type != set->refs[i].type) {
				owned_xref_set_free (set);
				return R_ANAL_OWNED_XREF_STATUS_INVALID;
			}
			continue;
		}
		set->refs[write++] = set->refs[i];
	}
	set->ref_count = write;
	*result = set;
	return R_ANAL_OWNED_XREF_STATUS_OK;
}

static OwnedXrefSetInternal *owned_xref_set_clone(const OwnedXrefSetInternal *source) {
	OwnedXrefSetInternal *set = R_NEW0 (OwnedXrefSetInternal);
	set->producer_namespace = strdup (source->producer_namespace);
	if (!set->producer_namespace) {
		owned_xref_set_free (set);
		return NULL;
	}
	set->owner_addr = source->owner_addr;
	if (source->ref_count) {
		size_t alloc_size;
		if (r_mul_overflow_size_t (source->ref_count, sizeof (RAnalRef), &alloc_size)) {
			owned_xref_set_free (set);
			return NULL;
		}
		set->refs = malloc (alloc_size);
		if (!set->refs) {
			owned_xref_set_free (set);
			return NULL;
		}
		memcpy (set->refs, source->refs, alloc_size);
		set->ref_count = source->ref_count;
	}
	return set;
}

static bool owned_xref_key_equal(const OwnedXrefSetInternal *set, const char *producer_namespace, ut64 owner_addr) {
	return set->owner_addr == owner_addr && !strcmp (set->producer_namespace, producer_namespace);
}

static OwnedXrefSetInternal *ref_manager_owned_set(RefManager *rm, const char *producer_namespace, ut64 owner_addr) {
	OwnedXrefSetInternal *set;
	for (set = rm->owned_sets; set; set = set->next) {
		if (owned_xref_key_equal (set, producer_namespace, owner_addr)) {
			return set;
		}
	}
	return NULL;
}

static bool owned_xref_set_equal(const OwnedXrefSetInternal *a, const OwnedXrefSetInternal *b) {
	if (!a) {
		return !b || !b->ref_count;
	}
	if (!b) {
		return !a->ref_count;
	}
	if (a->ref_count != b->ref_count) {
		return false;
	}
	size_t i;
	for (i = 0; i < a->ref_count; i++) {
		if (compare_owned_ref (&a->refs[i], &b->refs[i])) {
			return false;
		}
	}
	return true;
}

static void ref_manager_append_owned_set(RefManager *rm, OwnedXrefSetInternal *set) {
	OwnedXrefSetInternal **tail = &rm->owned_sets;
	while (*tail) {
		tail = &(*tail)->next;
	}
	*tail = set;
}

static bool ref_manager_project_owned_set(RefManager *rm, const OwnedXrefSetInternal *set) {
	size_t i;
	for (i = 0; i < set->ref_count; i++) {
		const RAnalRef *ref = &set->refs[i];
		RAnalRefType visible_type;
		RAnalRefType unowned_type;
		if (ref_type_at (&rm->unowned_refs, ref->at, ref->addr, &unowned_type)) {
			if (unowned_type != ref->type) {
				return false;
			}
			continue;
		}
		if (ref_type_at (&rm->refs, ref->at, ref->addr, &visible_type)) {
			if (visible_type != ref->type) {
				return false;
			}
			continue;
		}
		if (!ref_manager_add_entry (rm, ref->at, ref->addr, ref->type)) {
			return false;
		}
	}
	return true;
}

static bool ref_manager_owned_ref_type(const RefManager *rm, ut64 from, ut64 to, RAnalRefType *type) {
	const OwnedXrefSetInternal *set;
	for (set = rm->owned_sets; set; set = set->next) {
		size_t i;
		for (i = 0; i < set->ref_count; i++) {
			const RAnalRef *ref = &set->refs[i];
			if (ref->at == from && ref->addr == to) {
				*type = ref->type;
				return true;
			}
		}
	}
	return false;
}

static RAnalOwnedXrefStatus ref_manager_clone_unowned(RefManager *result, const RefManager *source) {
	const AdjacencyList_Entry *entry;
	R_ADJACENCY_LIST_FOREACH (&source->unowned_refs, entry) {
		const Edges_Entry *edge;
		R_EDGES_FOREACH (entry->val, edge) {
			if (!_add_ref (&result->unowned_refs, entry->key, edge->key, edge->val)
				|| !ref_manager_add_entry (result, entry->key, edge->key, edge->val)) {
				return R_ANAL_OWNED_XREF_STATUS_NOMEM;
			}
		}
	}
	return R_ANAL_OWNED_XREF_STATUS_OK;
}

static bool owned_xref_key_in_replacements(const OwnedXrefSetInternal *set, OwnedXrefSetInternal *const *replacements, size_t replacement_count) {
	size_t i;
	for (i = 0; i < replacement_count; i++) {
		if (owned_xref_key_equal (set, replacements[i]->producer_namespace, replacements[i]->owner_addr)) {
			return true;
		}
	}
	return false;
}

static RAnalOwnedXrefStatus ref_manager_clone_owned_except(RefManager *result, const RefManager *source, OwnedXrefSetInternal *const *replacements, size_t replacement_count) {
	const OwnedXrefSetInternal *source_set;
	for (source_set = source->owned_sets; source_set; source_set = source_set->next) {
		if (owned_xref_key_in_replacements (source_set, replacements, replacement_count)) {
			continue;
		}
		OwnedXrefSetInternal *clone = owned_xref_set_clone (source_set);
		if (!clone) {
			return R_ANAL_OWNED_XREF_STATUS_NOMEM;
		}
		if (!ref_manager_project_owned_set (result, clone)) {
			owned_xref_set_free (clone);
			return R_ANAL_OWNED_XREF_STATUS_INVALID;
		}
		ref_manager_append_owned_set (result, clone);
	}
	return R_ANAL_OWNED_XREF_STATUS_OK;
}

static int compare_affected_address(const void *a, const void *b) {
	const AffectedXrefAddress *aa = a;
	const AffectedXrefAddress *ab = b;
	if (aa->addr < ab->addr) {
		return -1;
	}
	return aa->addr > ab->addr;
}

static RAnalOwnedXrefStatus prepare_affected_addresses(OwnedXrefSetInternal *const *old_sets, OwnedXrefSetInternal *const *new_sets, const bool *changed, size_t set_count, RAnalOwnedXrefPrepared *prepared) {
	size_t ref_count = 0;
	size_t set_index;
	for (set_index = 0; set_index < set_count; set_index++) {
		if (!changed[set_index]) {
			continue;
		}
		const size_t old_count = old_sets[set_index] ? old_sets[set_index]->ref_count : 0;
		if (r_add_overflow_size_t (ref_count, old_count, &ref_count)
			|| r_add_overflow_size_t (ref_count, new_sets[set_index]->ref_count, &ref_count)) {
			return R_ANAL_OWNED_XREF_STATUS_INVALID;
		}
	}
	if (!ref_count) {
		return R_ANAL_OWNED_XREF_STATUS_OK;
	}
	size_t address_count;
	size_t alloc_size;
	if (r_mul_overflow_size_t (ref_count, 2, &address_count)
		|| r_mul_overflow_size_t (address_count, sizeof (AffectedXrefAddress), &alloc_size)) {
		return R_ANAL_OWNED_XREF_STATUS_INVALID;
	}
	AffectedXrefAddress *affected = calloc (1, alloc_size);
	if (!affected) {
		return R_ANAL_OWNED_XREF_STATUS_NOMEM;
	}
	size_t index = 0;
	for (set_index = 0; set_index < set_count; set_index++) {
		if (!changed[set_index]) {
			continue;
		}
		const OwnedXrefSetInternal *sets[] = { old_sets[set_index], new_sets[set_index] };
		size_t side;
		for (side = 0; side < R_ARRAY_SIZE (sets); side++) {
			const OwnedXrefSetInternal *set = sets[side];
			if (!set) {
				continue;
			}
			size_t i;
			for (i = 0; i < set->ref_count; i++) {
				affected[index++] = (AffectedXrefAddress) {
					.addr = set->refs[i].at,
					.roles = AFFECTED_XREF_SOURCE,
				};
				affected[index++] = (AffectedXrefAddress) {
					.addr = set->refs[i].addr,
					.roles = AFFECTED_XREF_TARGET,
				};
			}
		}
	}
	qsort (affected, index, sizeof (AffectedXrefAddress), compare_affected_address);
	size_t write = 0;
	size_t read;
	for (read = 0; read < index; read++) {
		if (write && affected[write - 1].addr == affected[read].addr) {
			affected[write - 1].roles |= affected[read].roles;
			continue;
		}
		affected[write++] = affected[read];
	}
	prepared->affected = affected;
	prepared->affected_count = write;
	return R_ANAL_OWNED_XREF_STATUS_OK;
}

R_API void r_anal_xrefs_owned_prepared_free(RAnalOwnedXrefPrepared *prepared) {
	if (prepared) {
		ref_manager_free (prepared->rm);
		free (prepared->affected);
		free (prepared);
	}
}

static void owned_xref_replacements_free(OwnedXrefSetInternal **replacements, size_t count) {
	if (replacements) {
		size_t i;
		for (i = 0; i < count; i++) {
			owned_xref_set_free (replacements[i]);
		}
	}
	free (replacements);
}

static RAnalOwnedXrefStatus xrefs_owned_prepare_many_locked(RAnal *anal, const RAnalOwnedXrefSet *sets, size_t set_count, RAnalOwnedXrefPrepared **prepared_out) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm && prepared_out, R_ANAL_OWNED_XREF_STATUS_INVALID);
	*prepared_out = NULL;
	if (set_count && !sets) {
		return R_ANAL_OWNED_XREF_STATUS_INVALID;
	}
	RAnalOwnedXrefPrepared *prepared = R_NEW0 (RAnalOwnedXrefPrepared);
	prepared->source_anal = anal;
	if (!set_count) {
		*prepared_out = prepared;
		return R_ANAL_OWNED_XREF_STATUS_OK;
	}
	size_t pointer_bytes;
	if (r_mul_overflow_size_t (set_count, sizeof (OwnedXrefSetInternal *), &pointer_bytes)) {
		r_anal_xrefs_owned_prepared_free (prepared);
		return R_ANAL_OWNED_XREF_STATUS_INVALID;
	}
	OwnedXrefSetInternal **replacements = calloc (1, pointer_bytes);
	OwnedXrefSetInternal **old_sets = calloc (1, pointer_bytes);
	bool *changed = calloc (set_count, sizeof (bool));
	if (!replacements || !old_sets || !changed) {
		owned_xref_replacements_free (replacements, set_count);
		free (old_sets);
		free (changed);
		r_anal_xrefs_owned_prepared_free (prepared);
		return R_ANAL_OWNED_XREF_STATUS_NOMEM;
	}
	RAnalOwnedXrefStatus status = R_ANAL_OWNED_XREF_STATUS_OK;
	bool any_changed = false;
	size_t i;
	for (i = 0; i < set_count; i++) {
		status = owned_xref_set_prepare (anal, &sets[i], &replacements[i]);
		if (status != R_ANAL_OWNED_XREF_STATUS_OK) {
			break;
		}
		size_t previous;
		for (previous = 0; previous < i; previous++) {
			if (owned_xref_key_equal (replacements[i], replacements[previous]->producer_namespace,
				replacements[previous]->owner_addr)) {
				status = R_ANAL_OWNED_XREF_STATUS_INVALID;
				break;
			}
		}
		if (status != R_ANAL_OWNED_XREF_STATUS_OK) {
			break;
		}
		old_sets[i] = ref_manager_owned_set (anal->rm, replacements[i]->producer_namespace,
			replacements[i]->owner_addr);
		changed[i] = !owned_xref_set_equal (old_sets[i], replacements[i]);
		any_changed |= changed[i];
	}
	if (status == R_ANAL_OWNED_XREF_STATUS_OK && any_changed) {
		status = prepare_affected_addresses (old_sets, replacements, changed, set_count, prepared);
	}
	if (status == R_ANAL_OWNED_XREF_STATUS_OK && any_changed) {
		prepared->rm = ref_manager_new ();
		status = ref_manager_clone_unowned (prepared->rm, anal->rm);
	}
	if (status == R_ANAL_OWNED_XREF_STATUS_OK && any_changed) {
		status = ref_manager_clone_owned_except (prepared->rm, anal->rm, replacements, set_count);
	}
	if (status == R_ANAL_OWNED_XREF_STATUS_OK && any_changed) {
		for (i = 0; i < set_count; i++) {
			if (!replacements[i]->ref_count) {
				continue;
			}
			if (!ref_manager_project_owned_set (prepared->rm, replacements[i])) {
				status = R_ANAL_OWNED_XREF_STATUS_INVALID;
				break;
			}
			ref_manager_append_owned_set (prepared->rm, replacements[i]);
			replacements[i] = NULL;
		}
	}
	owned_xref_replacements_free (replacements, set_count);
	free (old_sets);
	free (changed);
	if (status != R_ANAL_OWNED_XREF_STATUS_OK) {
		r_anal_xrefs_owned_prepared_free (prepared);
		return status;
	}
	prepared->changed = any_changed;
	*prepared_out = prepared;
	return R_ANAL_OWNED_XREF_STATUS_OK;
}

R_API RAnalOwnedXrefStatus r_anal_xrefs_owned_prepare_many(RAnal *anal, const RAnalOwnedXrefSet *sets, size_t set_count, RAnalOwnedXrefPrepared **prepared_out) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, R_ANAL_OWNED_XREF_STATUS_INVALID);
	return xrefs_owned_prepare_many_locked (anal, sets, set_count, prepared_out);
}

R_API bool r_anal_xrefs_owned_changed(const RAnalOwnedXrefPrepared *prepared) {
	return prepared && prepared->changed;
}

static void invalidate_affected_functions(RAnal *anal, const AffectedXrefAddress *affected_addresses, size_t affected_count) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_list_foreach (anal->fcns, iter, fcn) {
		ut8 roles = 0;
		size_t i;
		for (i = 0; i < affected_count; i++) {
			const AffectedXrefAddress *affected = &affected_addresses[i];
			if (fcn->addr == affected->addr || r_anal_function_contains (fcn, affected->addr)) {
				roles |= affected->roles;
				if (roles == (AFFECTED_XREF_SOURCE | AFFECTED_XREF_TARGET)) {
					break;
				}
			}
		}
		if (roles & AFFECTED_XREF_SOURCE) {
			fcn->meta.numcallrefs = -1;
		}
		if (roles & AFFECTED_XREF_TARGET) {
			fcn->meta.numrefs = -1;
		}
	}
}

static void xrefs_owned_swap_locked(RAnal *anal, RAnalOwnedXrefPrepared *prepared) {
	if (prepared->changed) {
		RefManager *rm = anal->rm;
		anal->rm = prepared->rm;
		prepared->rm = rm;
	}
}

static void xrefs_owned_publish_locked(RAnal *anal, const RAnalOwnedXrefPrepared *prepared) {
	if (!prepared->changed) {
		return;
	}
	invalidate_affected_functions (anal, prepared->affected, prepared->affected_count);
	R_DIRTY_SET (anal);
}

R_API void r_anal_xrefs_owned_swap(RAnal *anal, RAnalOwnedXrefPrepared *prepared) {
	R_RETURN_IF_FAIL (anal && anal->lock && prepared && prepared->source_anal == anal);
	xrefs_owned_swap_locked (anal, prepared);
}

R_API void r_anal_xrefs_owned_publish(RAnal *anal, const RAnalOwnedXrefPrepared *prepared) {
	R_RETURN_IF_FAIL (anal && anal->lock && prepared && prepared->source_anal == anal);
	xrefs_owned_publish_locked (anal, prepared);
}

R_API RAnalOwnedXrefStatus r_anal_xrefs_replace_owned(RAnal *anal, const RAnalOwnedXrefSet *set) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, R_ANAL_OWNED_XREF_STATUS_INVALID);
	r_th_lock_enter (anal->lock);
	RAnalOwnedXrefPrepared *prepared = NULL;
	RAnalOwnedXrefStatus status = xrefs_owned_prepare_many_locked (
		anal, set, 1, &prepared);
	if (status == R_ANAL_OWNED_XREF_STATUS_OK) {
		xrefs_owned_swap_locked (anal, prepared);
		xrefs_owned_publish_locked (anal, prepared);
	}
	r_th_lock_leave (anal->lock);
	r_anal_xrefs_owned_prepared_free (prepared);
	return status;
}

R_API RAnalOwnedXrefStatus r_anal_xrefs_owned_clear_all(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock && anal->rm,
		R_ANAL_OWNED_XREF_STATUS_INVALID);
	size_t set_count = 0;
	OwnedXrefSetInternal *owned;
	for (owned = anal->rm->owned_sets; owned; owned = owned->next) {
		set_count++;
	}
	if (!set_count) {
		return R_ANAL_OWNED_XREF_STATUS_OK;
	}
	size_t alloc_size;
	if (r_mul_overflow_size_t (set_count, sizeof (RAnalOwnedXrefSet), &alloc_size)) {
		return R_ANAL_OWNED_XREF_STATUS_INVALID;
	}
	RAnalOwnedXrefSet *sets = calloc (1, alloc_size);
	if (!sets) {
		return R_ANAL_OWNED_XREF_STATUS_NOMEM;
	}
	size_t index = 0;
	for (owned = anal->rm->owned_sets; owned; owned = owned->next) {
		sets[index++] = (RAnalOwnedXrefSet) {
			.producer_namespace = owned->producer_namespace,
			.owner_addr = owned->owner_addr,
		};
	}
	RAnalOwnedXrefPrepared *prepared = NULL;
	RAnalOwnedXrefStatus status = xrefs_owned_prepare_many_locked (
		anal, sets, set_count, &prepared);
	free (sets);
	if (status == R_ANAL_OWNED_XREF_STATUS_OK) {
		xrefs_owned_swap_locked (anal, prepared);
		xrefs_owned_publish_locked (anal, prepared);
	}
	r_anal_xrefs_owned_prepared_free (prepared);
	return status;
}

// set a reference from FROM to TO and a cross-reference(xref) from TO to FROM.
// when fcn is known (the function containing FROM), pass it to skip hash lookups.
static bool xrefs_setf_locked(RAnal *anal, RAnalFunction *fcn, ut64 from, ut64 to, const RAnalRefType _type) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, false);
	(void)fcn;

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

	const RAnalRefType type = xref_resolve_type (_type);
	RAnalRefType owned_type;
	if (ref_manager_owned_ref_type (anal->rm, from, to, &owned_type)
			&& owned_type != type) {
		return false;
	}
	if (!_add_ref (&anal->rm->unowned_refs, from, to, type)
		|| !ref_manager_add_entry (anal->rm, from, to, type)) {
		return false;
	}
	R_DIRTY_SET (anal);

	AffectedXrefAddress affected[] = {
		{ .addr = from, .roles = AFFECTED_XREF_SOURCE },
		{ .addr = to, .roles = AFFECTED_XREF_TARGET },
	};
	invalidate_affected_functions (anal, affected, R_ARRAY_SIZE (affected));

	return true;
}

R_API bool r_anal_xrefs_setf(RAnal *anal, RAnalFunction *fcn, ut64 from, ut64 to, const RAnalRefType type) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, false);
	r_th_lock_enter (anal->lock);
	bool result = xrefs_setf_locked (anal, fcn, from, to, type);
	r_th_lock_leave (anal->lock);
	return result;
}

R_API bool r_anal_xrefs_set(RAnal *anal, ut64 from, ut64 to, const RAnalRefType type) {
	return r_anal_xrefs_setf (anal, NULL, from, to, type);
}

static bool xref_del_locked(RAnal *anal, ut64 from, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal && anal->rm, false);
	_delete_ref (&anal->rm->unowned_refs, from, to);
	ref_manager_remove_entry (anal->rm, from, to);
	RAnalRefType type;
	if (ref_type_at (&anal->rm->unowned_refs, from, to, &type)
		|| ref_manager_owned_ref_type (anal->rm, from, to, &type)) {
		if (!ref_manager_add_entry (anal->rm, from, to, type)) {
			return false;
		}
	}
	R_DIRTY_SET (anal);

	AffectedXrefAddress affected[] = {
		{ .addr = from, .roles = AFFECTED_XREF_SOURCE },
		{ .addr = to, .roles = AFFECTED_XREF_TARGET },
	};
	invalidate_affected_functions (anal, affected, R_ARRAY_SIZE (affected));

	return true;
}

R_API bool r_anal_xref_del(RAnal *anal, ut64 from, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, false);
	r_th_lock_enter (anal->lock);
	bool result = xref_del_locked (anal, from, to);
	r_th_lock_leave (anal->lock);
	return result;
}

R_API RVecAnalRef *r_anal_refs_get(RAnal *anal, ut64 from) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, NULL);
	r_th_lock_enter (anal->lock);
	RVecAnalRef *anal_refs = ref_manager_get_refs (anal->rm, from);
	if (!anal_refs || RVecAnalRef_empty (anal_refs)) {
		RVecAnalRef_free (anal_refs);
		anal_refs = NULL;
	} else {
		RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?
	}
	r_th_lock_leave (anal->lock);
	return anal_refs;
}

R_API RVecAnalRef *r_anal_refs_get_unowned(RAnal *anal, ut64 from) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, NULL);
	r_th_lock_enter (anal->lock);
	RVecAnalRef *anal_refs = anal->rm
		? _collect_refs (anal->rm, &anal->rm->unowned_refs, from): NULL;
	if (!anal_refs || RVecAnalRef_empty (anal_refs)) {
		RVecAnalRef_free (anal_refs);
		anal_refs = NULL;
	} else {
		RVecAnalRef_sort (anal_refs, compare_ref);
	}
	r_th_lock_leave (anal->lock);
	return anal_refs;
}

R_API RVecAnalRef *r_anal_xrefs_get(RAnal *anal, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, NULL);
	r_th_lock_enter (anal->lock);
	RVecAnalRef *anal_refs = ref_manager_get_xrefs (anal->rm, to);
	if (!anal_refs || RVecAnalRef_empty (anal_refs)) {
		RVecAnalRef_free (anal_refs);
		anal_refs = NULL;
	} else {
		RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?
	}
	r_th_lock_leave (anal->lock);
	return anal_refs;
}

R_API RVecAnalRef *r_anal_xrefs_get_from(RAnal *anal, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, NULL);
	r_th_lock_enter (anal->lock);
	RVecAnalRef *anal_refs = ref_manager_get_refs (anal->rm, to);
	if (!anal_refs || RVecAnalRef_empty (anal_refs)) {
		RVecAnalRef_free (anal_refs);
		anal_refs = NULL;
	} else {
		RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?
	}
	r_th_lock_leave (anal->lock);
	return anal_refs;
}

R_API bool r_anal_xrefs_has_xrefs_at(RAnal *anal, ut64 at) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, false);
	r_th_lock_enter (anal->lock);
	if (!anal->rm) {
		r_th_lock_leave (anal->lock);
		return false;
	}
	AdjacencyList_CIter iter = AdjacencyList_cfind (&anal->rm->xrefs, &at);
	const AdjacencyList_Entry *entry = AdjacencyList_CIter_get (&iter);
	bool result = !!entry;
	r_th_lock_leave (anal->lock);
	return result;
}

static void r_anal_xrefs_list_table(RAnal *anal, RVecAnalRef *anal_refs, const char *arg, RTable *table) {
	if (!table) {
		table = r_table_new ("xrefs", NULL);
	}
	r_table_set_columnsf (table, "dddssss", "from", "to", "size", "type", "perm", "fromname", "toname");

	RAnalRef *ref;
	R_VEC_FOREACH (anal_refs, ref) {
		int t = R_ANAL_REF_TYPE_MASK (ref->type);
		char *fromname = anal->coreb.getNameDelta (anal->coreb.core, ref->addr);
		char *toname = anal->coreb.getNameDelta (anal->coreb.core, ref->at);
		r_table_add_rowf (table, "xxnssss",
				ref->at, ref->addr,
				(ut64)r_anal_ref_size (ref),
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
	R_RETURN_IF_FAIL (anal && anal->lock);
	r_th_lock_enter (anal->lock);
	RVecAnalRef *anal_refs = ref_manager_get_refs (anal->rm, UT64_MAX);
	r_th_lock_leave (anal->lock);
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
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, 0);
	r_th_lock_enter (anal->lock);
	ut64 count = ref_manager_count_xrefs (anal->rm);
	r_th_lock_leave (anal->lock);
	return count;
}

R_API ut64 r_anal_xrefs_count_at(RAnal *anal, ut64 to) {
	R_RETURN_VAL_IF_FAIL (anal && anal->lock, 0);
	r_th_lock_enter (anal->lock);
	ut64 count = ref_manager_count_xrefs_at (anal->rm, to);
	r_th_lock_leave (anal->lock);
	return count;
}

R_API RVecAnalRef *r_anal_function_get_xrefs(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn && fcn->anal && fcn->anal->lock, NULL);
	RAnal *anal = fcn->anal;
	r_th_lock_enter (anal->lock);
	// XXX assume first basic block is the entrypoint
	RVecAnalRef *anal_refs = ref_manager_get_xrefs (anal->rm, fcn->addr);
	if (anal_refs) {
		RVecAnalRef_sort (anal_refs, compare_ref); // XXX not needed?
	}
	r_th_lock_leave (anal->lock);
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
	R_RETURN_VAL_IF_FAIL (fcn && fcn->anal && fcn->anal->lock, NULL);
	RAnal *anal = fcn->anal;
	r_th_lock_enter (anal->lock);
	RVecAnalRef *refs = fcn_get_all_refs (fcn, anal->rm, ref_manager_get_refs);
	r_th_lock_leave (anal->lock);
	return refs;
}

R_API RVecAnalRef *r_anal_function_get_all_xrefs(RAnalFunction *fcn) {
	R_RETURN_VAL_IF_FAIL (fcn && fcn->anal && fcn->anal->lock, NULL);
	RAnal *anal = fcn->anal;
	r_th_lock_enter (anal->lock);
	RVecAnalRef *refs = fcn_get_all_refs (fcn, anal->rm, ref_manager_get_xrefs);
	r_th_lock_leave (anal->lock);
	return refs;
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
	R_RETURN_VAL_IF_FAIL (fcn && fcn->anal && fcn->anal->lock, 0);
	RAnal *anal = fcn->anal;
	r_th_lock_enter (anal->lock);
	if (type == R_ANAL_REF_TYPE_CALL && fcn->meta.numcallrefs != -1) {
		ut64 cached = fcn->meta.numcallrefs;
		r_th_lock_leave (anal->lock);
		return cached;
	}
	ut64 count = fcn_count_refs (fcn, anal->rm, ref_manager_count_refs_filtered, type);
	if (type == R_ANAL_REF_TYPE_CALL) {
		fcn->meta.numcallrefs = count;
	}
	r_th_lock_leave (anal->lock);
	return count;
}

// Count xrefs to a function (optionally filtered by type)
R_API ut64 r_anal_function_count_xrefs(RAnalFunction *fcn, RAnalRefType type) {
	R_RETURN_VAL_IF_FAIL (fcn && fcn->anal && fcn->anal->lock, 0);
	RAnal *anal = fcn->anal;
	r_th_lock_enter (anal->lock);
	if (type == R_ANAL_REF_TYPE_ANY && fcn->meta.numrefs != -1) {
		ut64 cached = fcn->meta.numrefs;
		r_th_lock_leave (anal->lock);
		return cached;
	}
	// For xrefs, we only need to check the function entry point
	ut64 count = ref_manager_count_xrefs_filtered (anal->rm, fcn->addr, type);
	if (type == R_ANAL_REF_TYPE_ANY) {
		fcn->meta.numrefs = count;
	}
	r_th_lock_leave (anal->lock);
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
