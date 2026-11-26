/* radare - LGPL - Copyright 2026 - pancake */

#include <r_util.h>

R_API RFreeze *r_freeze_acquire(RFreeze **slot, void **items, size_t count, RRefLayout layout) {
	R_RETURN_VAL_IF_FAIL (slot, NULL);
	RFreeze *freeze = *slot;
	if (freeze) {
		freeze->refs++;
		return freeze;
	}
	freeze = R_NEW0 (RFreeze);
	freeze->items = items;
	freeze->count = items? count: 0;
	freeze->refs = 1;
	freeze->slot = slot;
	freeze->layout = layout;
	*slot = freeze;
	return freeze;
}

R_API void r_freeze_unshare(RFreeze **slot) {
	R_RETURN_IF_FAIL (slot);
	RFreeze *freeze = *slot;
	if (!freeze) {
		return;
	}
	*slot = NULL;
	freeze->slot = NULL;
	void **items = freeze->count? R_NEWS0 (void *, freeze->count): NULL;
	if (!items) {
		freeze->items = NULL;
		freeze->count = 0;
		return;
	}
	size_t i;
	for (i = 0; i < freeze->count; i++) {
		items[i] = r_ref_erased (freeze->items[i], freeze->layout);
	}
	freeze->items = items;
	freeze->owned = true;
}

R_API RFreeze *r_freeze_list(const RList *list, RRefLayout layout) {
	R_RETURN_VAL_IF_FAIL (list, NULL);
	const int count = r_list_length (list);
	void **items = count > 0? R_NEWS (void *, count): NULL;
	if (count > 0 && !items) {
		return NULL;
	}
	RFreeze *freeze = R_NEW0 (RFreeze);
	freeze->items = items;
	freeze->refs = 1;
	freeze->owned = true;
	freeze->layout = layout;
	RListIter *iter;
	void *item;
	r_list_foreach (list, iter, item) {
		freeze->items[freeze->count++] = r_ref_erased (item, layout);
	}
	return freeze;
}

R_API void r_freeze_release(RFreeze *freeze) {
	if (!freeze || --freeze->refs > 0) {
		return;
	}
	if (freeze->slot) {
		*freeze->slot = NULL;
	}
	if (freeze->owned) {
		size_t i;
		for (i = 0; i < freeze->count; i++) {
			r_unref_erased (freeze->items[i], freeze->layout);
		}
		free (freeze->items);
	}
	free (freeze);
}
