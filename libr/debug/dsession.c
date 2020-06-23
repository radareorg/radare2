/* radare - LGPL - Copyright 2017 - rkx1209 */

#include <r_debug.h>

R_API void r_debug_session_free(RDebugSession *session) {
	if (session) {
		r_list_free (session->snaps);
		ht_up_free (session->registers);
		ht_up_free (session->memory);
		R_FREE (session);
	}
}

static void memory_ht_free(HtUPKv *kv) {
	r_vector_free (kv->value);
}

static void registers_ht_free(HtUPKv *kv) {
	r_vector_free (kv->value);
}

R_API RDebugSession *r_debug_session_new(RDebug *dbg) {
	RDebugSession *session = R_NEW0 (RDebugSession);
	if (!session) {
		return NULL;
	}

	session->registers = ht_up_new (NULL, registers_ht_free, NULL);
	if (!session->registers) {
		r_debug_session_free (session);
		return NULL;
	}
	session->memory = ht_up_new (NULL, memory_ht_free, NULL);
	if (!session->memory) {
		r_debug_session_free (session);
		return NULL;
	}

	size_t i;
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		session->reg[i] = r_list_tail (dbg->reg->regset[i].pool);
	}
	r_reg_arena_push (dbg->reg);

	session->snaps = r_list_newf ((RListFree)r_debug_snap_free);
	if (!session->snaps) {
		r_debug_session_free (session);
	}
	RListIter *iter;
	RDebugMap *map;
	r_debug_map_sync (dbg);
	r_list_foreach (dbg->maps, iter, map) {
		if ((map->perm & R_PERM_RW) == R_PERM_RW) {
			RDebugSnap *snap = r_debug_snap_map (dbg, map);
			if (snap) {
				r_list_append (session->snaps, snap);
			}
		}
	}

	return session;
}

/*
static ut8 get_initial_memory(RDebug *dbg, ut64 addr) {
	RListIter *iter;
	RDebugSnap *snap;
	r_list_foreach (dbg->session->snaps, iter, snap) {
		if (r_debug_snap_contains (snap, addr)) {
			return r_read_at_ble8 (snap->data, snap->addr - addr);
		}
	}
	eprintf ("Error: cannot find snapshot for memory at 0x%"PFMT64x"\n", addr);
	return 0;
}

R_API ut8 r_debug_session_get_byte(RDebug *dbg, ut32 cnum, ut64 addr) {
	size_t index;
	RVector *vmem = ht_up_find (dbg->session->memory, addr, NULL);
	if (!vmem) {
		return get_initial_memory (dbg, addr);
	}
	r_vector_upper_bound (vmem, cnum, index, CMP_CNUM_MEM);
	if (index == 0) {
		return get_initial_memory (dbg, addr);
	} else if (index <= vmem->len) {
		RDebugChangeMem *mem = r_vector_index_ptr (vmem, index - 1);
		return mem->data;
	}
	eprintf ("Error: cannot find memory at 0x%"PFMT64x" in cnum %u\n", addr, cnum);
	return 0;
}
*/

static void set_initial_registers(RDebug *dbg) {
	size_t i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RListIter *iter = dbg->session->reg[i];
		RRegArena *arena = iter->data;
		if (dbg->reg->regset[i].arena->bytes) {
			memcpy (dbg->reg->regset[i].arena->bytes, arena->bytes, arena->size);
		}
	}
}

static void set_register(RDebug *dbg, RRegItem *ri, ut32 cnum) {
	RVector *vreg = ht_up_find (dbg->session->registers, ri->offset | (ri->arena << 16), NULL);
	if (!vreg) {
		return;
	}
	size_t index;
	r_vector_upper_bound (vreg, cnum, index, CMP_CNUM_REG);
	if (index > 0 && index <= vreg->len) {
		RDebugChangeReg *reg = r_vector_index_ptr (vreg, index - 1);
		r_reg_set_value (dbg->reg, ri, reg->data);
	}
}

R_API void r_debug_session_restore_registers(RDebug *dbg, ut32 cnum) {
	RListIter *iter;
	RRegItem *ri;

	set_initial_registers (dbg);
	r_list_foreach (dbg->reg->allregs, iter, ri) {
		set_register (dbg, ri, cnum);
	}
}

static void set_initial_memory(RDebug *dbg) {
	RListIter *iter;
	RDebugSnap *snap;
	r_list_foreach (dbg->session->snaps, iter, snap) {
		dbg->iob.write_at (dbg->iob.io, snap->addr, snap->data, snap->size);
	}
}

static bool restore_memory_cb(void *user, const ut64 key, const void *value) {
	size_t index;
	RDebug *dbg = user;
	RVector *vmem = (RVector *)value;

	r_vector_upper_bound (vmem, dbg->cnum, index, CMP_CNUM_MEM);
	if (index > 0 && index <= vmem->len) {
		RDebugChangeMem *mem = r_vector_index_ptr (vmem, index - 1);
		dbg->iob.write_at (dbg->iob.io, key, &mem->data, 1);
	}
	return true;
}

R_API void r_debug_session_restore_memory(RDebug *dbg, ut32 cnum) {
	set_initial_memory (dbg);
	ht_up_foreach (dbg->session->memory, restore_memory_cb, dbg);
}

static RDebugSnap *get_snap_at(RDebugSession *session, ut64 addr) {
	RListIter *iter;
	RDebugSnap *snap;
	r_list_foreach (session->snaps, iter, snap) {
		if (r_debug_snap_contains (snap, addr)) {
			return snap;
		}
	}
	return NULL;
}

R_API void r_debug_session_list_memory(RDebug *dbg) {
	RListIter *iter;
	RDebugMap *map;
	r_debug_map_sync (dbg);
	r_list_foreach (dbg->maps, iter, map) {
		if ((map->perm & R_PERM_RW) == R_PERM_RW) {
			RDebugSnap *snap = r_debug_snap_map (dbg, map);
			if (!snap) {
				return;
			}

			ut8 *hash = r_debug_snap_get_hash (snap);
			if (!hash) {
				r_debug_snap_free (snap);
				return;
			}

			char *hexstr = r_hex_bin2strdup (hash, R_HASH_SIZE_SHA256);
			if (!hexstr) {
				free (hash);
				r_debug_snap_free (snap);
				return;
			}
			dbg->cb_printf ("%s: %s\n", snap->name, hexstr);

			free (hexstr);
			free (hash);
			r_debug_snap_free (snap);
		}
	}
}

R_API bool r_debug_session_verify_memory(RDebug *dbg) {
	RListIter *iter;
	RDebugMap *map;
	r_debug_map_sync (dbg);
	r_list_foreach (dbg->maps, iter, map) {
		if ((map->perm & R_PERM_RW) == R_PERM_RW) {
			RDebugSnap *snap = r_debug_snap_map (dbg, map);

			RDebugSnap *prev_snap = get_snap_at (dbg->session, snap->addr);
			if (!prev_snap) {
				r_debug_snap_free (snap);
				return false;
			}
			if (!r_debug_snap_is_equal (snap, prev_snap)) {
				r_debug_snap_free (snap);
				return false;
			}
		}
	}

	return true;
}
