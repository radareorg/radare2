#ifndef R2_FREEZE_H
#define R2_FREEZE_H

#ifdef __cplusplus
extern "C" {
#endif

// Frozen view of an owner's pointer array, stable while the owner mutates or dies.
// Freezing borrows the owner's buffer without copying. The owner must call
// r_freeze_detach () before changing or freeing the array; only then the items
// are copied once and referenced, so readers keep iterating a consistent snapshot.
// No locks: the view is meant for re-entrant code and coroutines on one thread.

typedef struct r_freeze_t {
	void **items;
	size_t count;
	int refs;
	bool owned; // items is a private copy holding a reference on each element
	struct r_freeze_t **slot; // owner field pointing here while the buffer is borrowed
	RRefLayout layout; // how to reference items, R_REF_LAYOUT_NONE for plain pointers
} RFreeze;

R_API R_OWNED RFreeze *r_freeze_acquire(RFreeze **slot, void **items, size_t count, RRefLayout layout);
R_API void r_freeze_release(RFreeze * R_NULLABLE freeze);
R_API void r_freeze_unshare(RFreeze **slot);
// Owned snapshot of a list holding a reference on each element
R_API R_OWNED RFreeze *r_freeze_list(const RList *list, RRefLayout layout);

// Owner hook before mutating the array: a NULL check unless a freeze is active
static inline void r_freeze_detach(RFreeze **slot) {
	if (R_UNLIKELY (*slot)) {
		r_freeze_unshare (slot);
	}
}

// Freeze an RVec of pointers to objects embedding R_REF_TYPE
#define r_freeze_vec(slot, vec, type) r_freeze_acquire ((slot), (void **)R_VEC_START_ITER (vec), \
	(size_t)(R_VEC_END_ITER (vec) - R_VEC_START_ITER (vec)), R_REF_LAYOUT (type))
#define r_freeze_vec_raw(slot, vec) r_freeze_acquire ((slot), (void **)R_VEC_START_ITER (vec), \
	(size_t)(R_VEC_END_ITER (vec) - R_VEC_START_ITER (vec)), R_REF_LAYOUT_NONE)

#define r_freeze_foreach(freeze, idx, item) \
	for ((idx) = 0; (freeze) && (idx) < (freeze)->count && ((item) = (freeze)->items[(idx)], 1); (idx)++)

#ifdef __cplusplus
}
#endif

#endif
