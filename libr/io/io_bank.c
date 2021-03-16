/* radare2 - LGPL - Copyright 2021 - condret */

#include <r_io.h>
#include <r_util.h>

R_API RIOBank *r_io_bank_new(void) {
	RIOBank *bank = R_NEW0 (RIOBank);
	if (!bank) {
		return NULL;
	}
	bank->submaps = r_rbtree_cont_newf (free);
	if (!bank->submaps) {
		free (bank);
		return NULL;
	}
	bank->maprefs = r_list_newf (free);
	if (!bank->maprefs) {
		r_rbtree_cont_free (bank->submaps);
		free (bank);
		return NULL;
	}
	bank->todo = r_queue_new (8);
	if (!bank->todo) {
		r_list_free (bank->maprefs);
		r_rbtree_cont_free (bank->submaps);
		free (bank);
		return NULL;
	}
	return bank;
}

R_API void r_io_bank_free(RIOBank *bank) {
	if (!bank) {
		return;
	}
	r_queue_free (bank->todo);
	r_list_free (bank->maprefs);
	r_rbtree_cont_free (bank->submaps);
	free (bank);
}

static bool _bank_free_cb(void *user, void *data, ut32 id) {
	r_io_bank_free ((RIOBank *)data);
	return true;
}

R_API void r_io_bank_init(RIO *io) {
	r_return_if_fail (io);
	r_io_bank_fini (io);
	io->banks = r_id_storage_new (0, UT32_MAX);
}

R_API void r_io_bank_fini(RIO *io) {
	r_return_if_fail (io);
	if (io->banks) {
		r_id_storage_foreach (io->banks, _bank_free_cb, NULL);
		r_id_storage_free (io->banks);
		io->banks = NULL;
	}
}

R_API RIOBank *r_io_bank_get(RIO *io, ut32 bankid) {
	r_return_val_if_fail (io && io->banks, NULL);
	return (RIOBank *)r_id_storage_get (io->banks, bankid);
}

static RIOMapRef *_mapref_from_map(RIOMap *map) {
	RIOMapRef *mapref = R_NEW (RIOMapRef);
	if (!mapref) {
		return NULL;
	}
	mapref->id = map->id;
	mapref->ts = map->ts;
	return mapref;
}

static int _find_sm_by_vaddr_cb(void *incoming, void *in, void *user) {
	RIOSubMap *bd = (RIOSubMap *)incoming, *sm = (RIOSubMap *)in;
	if (bd->itv.addr > sm->itv.addr) {
		return -1;
	}
	if (bd->itv.addr < sm->itv.addr) {
		return 1;
	}
	return 0;
}

static int _find_lowest_intersection_sm_cb(void *incoming, void *in, void *user) {
	RIOSubMap *bd = (RIOSubMap *)incoming, *sm = (RIOSubMap *)in;
	if (r_io_submap_overlap (bd, sm)) {
		return 0;
	}
	if (bd->itv.addr > sm->itv.addr) {
		return -1;
	}
	return 1;
}

// returns the node containing the submap with lowest itv.addr, that intersects with sm
static RContRBNode *_find_entry_submap_node(RIOBank *bank, RIOSubMap *sm) {
	RContRBNode *node = r_rbtree_cont_find_node (bank->submaps, sm, _find_lowest_intersection_sm_cb, NULL);
	if (!node) {
		return NULL;
	}
	RContRBNode *prev = r_rbtree_cont_node_prev (node);
	while (prev && r_io_submap_overlap (((RIOSubMap *)prev->data), sm)) {
		node = prev;
		prev = r_rbtree_cont_node_prev (node);
	}
	return node;
}

R_API bool r_io_bank_map_add_top(RIO *io, ut32 bankid, ut32 mapid) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	RIOMap *map = r_io_map_get (io, mapid);
	r_return_val_if_fail (io && bank && map, false);
	RIOMapRef *mapref = _mapref_from_map (map);
	if (!mapref) {
		return false;
	}
	RIOSubMap *sm = r_io_submap_new (io, mapref);
	if (!sm) {
		free (mapref);
		return false;
	}
	r_list_append (bank->maprefs, mapref);
	RContRBNode *entry = _find_entry_submap_node (bank, sm);
	if (!entry) {
		// no intersection with any submap, so just insert
		return r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL);
	}
	RIOSubMap *bd = (RIOSubMap *)entry->data;
	if (r_itv_eq (bd->itv, sm->itv)) {
		// this makes gb bankswitches way faster than skyline
		// instead of deleting and inserting, just replace the mapref
		sm->mapref = bd->mapref;
		free (sm);
		return true;
	}
	if (r_io_submap_from (bd) < r_io_submap_from (sm) &&
		r_io_submap_to (sm) < r_io_submap_to (bd)) {
		// split bd into 2 maps => bd and bdsm
		RIOSubMap *bdsm = R_NEW (RIOSubMap);
		if (!bdsm) {
			free (sm);
			return false;
		}
		bdsm->mapref = bd->mapref;
		bdsm->itv.addr = r_io_submap_to (sm) + 1;
		bdsm->itv.size = r_io_submap_to (bd) - bdsm->itv.addr + 1;
		bd->itv.size = r_io_submap_from (sm) - r_io_submap_from (bd);
		// TODO: insert and check return value, before adjusting sm size
		return r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL) &
			r_rbtree_cont_insert (bank->submaps, bdsm, _find_sm_by_vaddr_cb, NULL);
	}

	bd->itv.size = r_io_submap_from (sm) - r_io_submap_from (bd);
	entry = r_rbtree_cont_node_next (entry);
	while (entry && r_io_submap_to (((RIOSubMap *)entry->data)) <= r_io_submap_to (sm)) {
		//delete all submaps that are completly included in sm
		RContRBNode *next = r_rbtree_cont_node_next (entry);
		// this can be optimized, there is no need to do search here
		r_rbtree_cont_delete (bank->submaps, entry->data, _find_sm_by_vaddr_cb, NULL);
		entry = next;
	}
	if (entry && r_io_submap_from (((RIOSubMap *)entry->data)) <= r_io_submap_to (sm)) {
		bd = (RIOSubMap *)entry->data;
		bd->itv.size = r_io_submap_to (bd) - r_io_submap_to (sm);
		bd->itv.addr = r_io_submap_to (sm) + 1;
	}
	return r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL);
}


R_API bool r_io_bank_map_priorize (RIO *io, const ut32 bankid, const ut32 mapid) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	r_return_val_if_fail (io && bank, false);
	RListIter *iter;
	RIOMapRef *mapref;
	r_list_foreach (bank->maprefs, iter, mapref) {
		if (mapref->id == mapid) {
			goto found;
		}
	}
	return false;
found:
	if (iter == bank->maprefs->head) {
		return r_io_map_get_by_ref (io, mapref) ? true : false;
	}
	RIOSubMap *sm = r_io_submap_new (io, mapref);
	if (!sm) {
		return false;
	}
	RContRBNode *entry = _find_entry_submap_node (bank, sm);
	if (!entry) {
		// if this happens, something is really fucked up
		free (sm);
		return false;
	}
	RIOSubMap *bd = (RIOSubMap *)entry->data;
	if (r_itv_eq (bd->itv, sm->itv)) {
		bd->mapref = *mapref;
		free (sm);
		return true;
	}
	if (r_io_submap_from (bd) < r_io_submap_from (sm) &&
		r_io_submap_to (sm) < r_io_submap_to (bd)) {
		// split bd into 2 maps => bd and bdsm
		RIOSubMap *bdsm = R_NEW (RIOSubMap);
		if (!bdsm) {
			free (sm);
			return false;
		}
		bdsm->mapref = bd->mapref;
		bdsm->itv.addr = r_io_submap_to (sm) + 1;
		bdsm->itv.size = r_io_submap_to (bd) - bdsm->itv.addr + 1;
		bd->itv.size = sm->itv.addr - bd->itv.addr;
		// TODO: insert and check return value, before adjusting sm size
		return r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL) &
			r_rbtree_cont_insert (bank->submaps, bdsm, _find_sm_by_vaddr_cb, NULL);
	}

	bd->itv.size = r_io_submap_from (sm) - r_io_submap_from (bd);
	entry = r_rbtree_cont_node_next (entry);
	while (entry && r_io_submap_to (((RIOSubMap *)entry->data)) <= r_io_submap_to (sm)) {
		//delete all submaps that are completly included in sm
		RContRBNode *next = r_rbtree_cont_node_next (entry);
		// this can be optimized, there is no need to do search here
		r_rbtree_cont_delete (bank->submaps, entry->data, _find_sm_by_vaddr_cb, NULL);
		entry = next;
	}
	if (entry && r_io_submap_from (((RIOSubMap *)entry->data)) <= r_io_submap_to (sm)) {
		bd = (RIOSubMap *)entry->data;
		bd->itv.size = r_io_submap_to (bd) - r_io_submap_to (sm);
		bd->itv.addr = r_io_submap_to (sm) + 1;
	}
	return r_rbtree_cont_insert (bank->submaps, sm, _find_sm_by_vaddr_cb, NULL);
}

R_API bool r_io_bank_locate(RIO *io, ut32 bankid, const ut64 size, ut64 *addr) {
	RIOBank *bank = r_io_bank_get (io, bankid);
	r_return_val_if_fail (io && bank && bank->submaps && addr && size, false);
	RContRBNode *entry = r_rbtree_cont_first (bank->submaps);
	if (!entry) {
		// no submaps in this bank
		*addr = 0LL;
		return true;
	}
	ut64 next_location = 0LL;
	while (entry) {
		RIOSubMap *sm = (RIOSubMap *)entry->data;
		if (size <= r_io_submap_from (sm) - next_location) {
			*addr = next_location;
			return true;
		}
		next_location = r_io_submap_to (sm) + 1;
		entry = r_rbtree_cont_node_next (entry);
	}
	if (next_location == 0LL) {
		// overflow from last submap in the tree => no location
		return false;
	}
	if (UT64_MAX - size + 1 < next_location) {
		return false;
	}
	*addr = next_location;
	return true;
}
