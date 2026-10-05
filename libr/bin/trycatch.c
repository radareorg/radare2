/* radare2 - LGPL - Copyright 2026 - pancake */

#include <r_bin.h>
#include <sdb/ht_uu.h>
#include "i/private.h"

typedef struct {
	ut64 prev;
	ut64 next;
} TrycatchLinks;

R_VEC_TYPE (RVecTrycatchLinks, TrycatchLinks);

typedef struct {
	RVecRBinTrycatch regions;
	RVecTrycatchLinks links;
	HtUU *tails;
} TrycatchStore;

R_IPI void r_bin_trycatch_free(void *data) {
	TrycatchStore *store = data;
	if (store) {
		RVecRBinTrycatch_fini (&store->regions);
		RVecTrycatchLinks_fini (&store->links);
		ht_uu_free (store->tails);
		free (store);
	}
}

static void trycatch_link(TrycatchStore *store, ut64 source, size_t index) {
	TrycatchLinks *links = R_VEC_START_ITER (&store->links);
	bool found;
	ut64 tail = ht_uu_find (store->tails, source, &found);
	if (found) {
		ut64 first = links[tail].next;
		links[index] = (TrycatchLinks) { tail, first };
		links[tail].next = index;
		links[first].prev = index;
	} else {
		links[index] = (TrycatchLinks) { index, index };
	}
	ht_uu_update (store->tails, source, index);
}

static TrycatchStore *trycatch_store(RBinFile *bf) {
	RBinObject *bo = bf->bo;
	if (bo->trycatch) {
		return bo->trycatch;
	}
	TrycatchStore *store = R_NEW0 (TrycatchStore);
	RVecRBinTrycatch *regions = bo->plugin && bo->plugin->trycatch? bo->plugin->trycatch (bf): NULL;
	size_t count = regions? RVecRBinTrycatch_length (regions): 0;
	if (count) {
		store->tails = ht_uu_new0 ();
		if (!store->tails) {
			free (store);
			return NULL;
		}
	}
	if (!RVecTrycatchLinks_reserve (&store->links, count)) {
		r_bin_trycatch_free (store);
		return NULL;
	}
	size_t i;
	for (i = 0; i < count; i++) {
		TrycatchLinks *link = RVecTrycatchLinks_emplace_back (&store->links);
		if (!link) {
			r_bin_trycatch_free (store);
			return NULL;
		}
		trycatch_link (store, RVecRBinTrycatch_at (regions, i)->source, i);
	}
	if (regions) {
		RVecRBinTrycatch_swap (&store->regions, regions);
	}
	bo->trycatch = store;
	return store;
}

R_API R_UNOWNED const RVecRBinTrycatch *r_bin_file_get_trycatch(RBinFile * R_NONNULL bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, NULL);
	TrycatchStore *store = trycatch_store (bf);
	return store? &store->regions: NULL;
}

R_API bool r_bin_trycatch_insert(RBinFile *bf, const RBinTrycatch *tc) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && tc, false);
	if (tc->from >= tc->to || tc->kind < R_BIN_TRYCATCH_UNSPECIFIED || tc->kind > R_BIN_TRYCATCH_FINALLY) {
		return false;
	}
	RBinTrycatch item = *tc;
	item.type = tc->type? strdup (tc->type): NULL;
	if (tc->type && !item.type) {
		return false;
	}
	TrycatchStore *store = trycatch_store (bf);
	if (!store) {
		free (item.type);
		return false;
	}
	if (!store->tails) {
		store->tails = ht_uu_new0 ();
		if (!store->tails) {
			free (item.type);
			return false;
		}
	}
	RBinTrycatch *region = RVecRBinTrycatch_emplace_back (&store->regions);
	if (!region) {
		free (item.type);
		return false;
	}
	TrycatchLinks *link = RVecTrycatchLinks_emplace_back (&store->links);
	if (!link) {
		RVecRBinTrycatch_pop_back (&store->regions);
		free (item.type);
		return false;
	}
	*region = item;
	trycatch_link (store, item.source, RVecRBinTrycatch_length (&store->regions) - 1);
	return true;
}

R_API bool r_bin_trycatch_delete(RBinFile *bf, size_t index) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, false);
	TrycatchStore *store = trycatch_store (bf);
	if (!store || index >= RVecRBinTrycatch_length (&store->regions)) {
		return false;
	}
	RBinTrycatch *regions = R_VEC_START_ITER (&store->regions);
	TrycatchLinks *links = R_VEC_START_ITER (&store->links);
	TrycatchLinks removed = links[index];
	ut64 source = regions[index].source;
	if (removed.next == index) {
		ht_uu_delete (store->tails, source);
	} else {
		links[removed.prev].next = removed.next;
		links[removed.next].prev = removed.prev;
		if (ht_uu_find (store->tails, source, NULL) == index) {
			ht_uu_update (store->tails, source, removed.prev);
		}
	}
	size_t last = RVecRBinTrycatch_length (&store->regions) - 1;
	if (index != last) {
		r_bin_trycatch_fini (&regions[index]);
		regions[index] = regions[last];
		memset (&regions[last], 0, sizeof (RBinTrycatch));
		links[index] = links[last];
		if (links[index].next == last) {
			links[index] = (TrycatchLinks) { index, index };
		} else {
			links[links[index].prev].next = index;
			links[links[index].next].prev = index;
		}
		source = regions[index].source;
		if (ht_uu_find (store->tails, source, NULL) == last) {
			ht_uu_update (store->tails, source, index);
		}
	}
	RVecRBinTrycatch_pop_back (&store->regions);
	RVecTrycatchLinks_pop_back (&store->links);
	return true;
}

R_API bool r_bin_trycatch_clear(RBinFile *bf) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo, false);
	TrycatchStore *store = trycatch_store (bf);
	if (!store) {
		return false;
	}
	ht_uu_free (store->tails);
	store->tails = NULL;
	RVecRBinTrycatch_fini (&store->regions);
	RVecTrycatchLinks_fini (&store->links);
	return true;
}

R_API bool r_bin_trycatch_foreach(RBinFile *bf, ut64 source, RBinTrycatchCb cb, void *user) {
	R_RETURN_VAL_IF_FAIL (bf && bf->bo && cb, false);
	TrycatchStore *store = trycatch_store (bf);
	if (!store) {
		return false;
	}
	if (!store->tails) {
		return true;
	}
	bool found;
	ut64 tail = ht_uu_find (store->tails, source, &found);
	if (!found) {
		return true;
	}
	const TrycatchLinks *links = R_VEC_START_ITER (&store->links);
	const RBinTrycatch *regions = R_VEC_START_ITER (&store->regions);
	ut64 first = links[tail].next;
	ut64 index = first;
	do {
		if (!cb (&regions[index], user)) {
			return false;
		}
		index = links[index].next;
	} while (index != first);
	return true;
}
