/* radare - LGPL - Copyright 2017 - rkx1209 */

#include <r_debug.h>

R_API void r_debug_session_free(RDebugSession *session) {
	if (session) {
		r_vector_free (session->checkpoints);
		ht_up_free (session->registers);
		ht_up_free (session->memory);
		R_FREE (session);
	}
}

static void r_debug_checkpoint_fini(void *element, void *user) {
	RDebugCheckpoint *checkpoint = element;
	r_list_free (checkpoint->snaps);
}

static void htup_vector_free(HtUPKv *kv) {
	r_vector_free (kv->value);
}

R_API RDebugSession *r_debug_session_new(RDebug *dbg) {
	RDebugSession *session = R_NEW0 (RDebugSession);
	if (!session) {
		return NULL;
	}

	session->checkpoints = r_vector_new (sizeof (RDebugCheckpoint), r_debug_checkpoint_fini, NULL);
	if (!session->checkpoints) {
		r_debug_session_free (session);
		return NULL;
	}
	session->registers = ht_up_new (NULL, htup_vector_free, NULL);
	if (!session->registers) {
		r_debug_session_free (session);
		return NULL;
	}
	session->memory = ht_up_new (NULL, htup_vector_free, NULL);
	if (!session->memory) {
		r_debug_session_free (session);
		return NULL;
	}

	return session;
}

R_API bool r_debug_add_checkpoint(RDebug *dbg) {
	r_return_val_if_fail (dbg->session, false);
	size_t i;
	RDebugCheckpoint checkpoint = { 0 };

	// Save current registers arena iter
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		checkpoint.reg[i] = r_list_tail (dbg->reg->regset[i].pool);
	}
	r_reg_arena_push (dbg->reg);

	// Save current memory maps
	checkpoint.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	if (!checkpoint.snaps) {
		return false;
	}
	RListIter *iter;
	RDebugMap *map;
	r_debug_map_sync (dbg);
	r_list_foreach (dbg->maps, iter, map) {
		if ((map->perm & R_PERM_RW) == R_PERM_RW) {
			RDebugSnap *snap = r_debug_snap_map (dbg, map);
			if (snap) {
				r_list_append (checkpoint.snaps, snap);
			}
		}
	}

	checkpoint.cnum = dbg->session->cnum;
	r_vector_push (dbg->session->checkpoints, &checkpoint);

	// Add PC register change so we can check for breakpoints when continue [back]
	RRegItem *ripc = r_reg_get (dbg->reg, dbg->reg->name[R_REG_NAME_PC], R_REG_TYPE_GPR);
	ut64 data = r_reg_get_value (dbg->reg, ripc);
	r_debug_session_add_reg_change (dbg->session, ripc->arena, ripc->offset, data);

	return true;
}

static void _set_initial_registers(RDebug *dbg) {
	size_t i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RListIter *iter = dbg->session->cur_chkpt->reg[i];
		RRegArena *arena = iter->data;
		if (dbg->reg->regset[i].arena->bytes) {
			memcpy (dbg->reg->regset[i].arena->bytes, arena->bytes, arena->size);
		}
	}
}

static void _set_register(RDebug *dbg, RRegItem *ri, ut32 cnum) {
	RVector *vreg = ht_up_find (dbg->session->registers, ri->offset | (ri->arena << 16), NULL);
	if (!vreg) {
		return;
	}
	size_t index;
	r_vector_upper_bound (vreg, cnum, index, CMP_CNUM_REG);
	if (index > 0 && index <= vreg->len) {
		RDebugChangeReg *reg = r_vector_index_ptr (vreg, index - 1);
		if (reg->cnum > dbg->session->cur_chkpt->cnum) {
			r_reg_set_value (dbg->reg, ri, reg->data);
		}
	}
}

R_API void _restore_registers(RDebug *dbg, ut32 cnum) {
	RListIter *iter;
	RRegItem *ri;
	_set_initial_registers (dbg);
	r_list_foreach (dbg->reg->allregs, iter, ri) {
		_set_register (dbg, ri, cnum);
	}
}

static void _set_initial_memory(RDebug *dbg) {
	RListIter *iter;
	RDebugSnap *snap;
	r_list_foreach (dbg->session->cur_chkpt->snaps, iter, snap) {
		dbg->iob.write_at (dbg->iob.io, snap->addr, snap->data, snap->size);
	}
}

static bool _restore_memory_cb(void *user, const ut64 key, const void *value) {
	size_t index;
	RDebug *dbg = user;
	RVector *vmem = (RVector *)value;

	r_vector_upper_bound (vmem, dbg->session->cnum, index, CMP_CNUM_MEM);
	if (index > 0 && index <= vmem->len) {
		RDebugChangeMem *mem = r_vector_index_ptr (vmem, index - 1);
		if (mem->cnum > dbg->session->cur_chkpt->cnum) {
			dbg->iob.write_at (dbg->iob.io, key, &mem->data, 1);
		}
	}
	return true;
}

static void _restore_memory(RDebug *dbg, ut32 cnum) {
	_set_initial_memory (dbg);
	ht_up_foreach (dbg->session->memory, _restore_memory_cb, dbg);
}

static RDebugCheckpoint *_get_checkpoint_before(RDebugSession *session, ut32 cnum) {
	RDebugCheckpoint *checkpoint = NULL;
	size_t index;
	r_vector_upper_bound (session->checkpoints, cnum, index, CMP_CNUM_CHKPT);
	if (index > 0 && index <= session->checkpoints->len) {
		checkpoint = r_vector_index_ptr (session->checkpoints, index - 1);
	}
	return checkpoint;
}

R_API void r_debug_session_restore_reg_mem(RDebug *dbg, ut32 cnum) {
	// Set checkpoint for initial registers and memory
	dbg->session->cur_chkpt = _get_checkpoint_before (dbg->session, cnum);

	// Restore registers
	_restore_registers (dbg, cnum);
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, true);

	// Restore memory
	_restore_memory (dbg, cnum);
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

R_API bool r_debug_session_add_reg_change(RDebugSession *session, int arena, ut64 offset, ut64 data) {
	RVector *vreg = ht_up_find (session->registers, offset | (arena << 16), NULL);
	if (!vreg) {
		vreg = r_vector_new (sizeof (RDebugChangeReg), NULL, NULL);
		if (!vreg) {
			eprintf ("Error: creating a register vector.\n");
			return false;
		}
		ht_up_insert (session->registers, offset | (arena << 16), vreg);
	}
	RDebugChangeReg reg = { session->cnum, data };
	r_vector_push (vreg, &reg);
	return true;
}

R_API bool r_debug_session_add_mem_change(RDebugSession *session, ut64 addr, ut8 data) {
	RVector *vmem = ht_up_find (session->memory, addr, NULL);
	if (!vmem) {
		vmem = r_vector_new (sizeof (RDebugChangeMem), NULL, NULL);
		if (!vmem) {
			eprintf ("Error: creating a memory vector.\n");
			return false;
		}
		ht_up_insert (session->memory, addr, vmem);
	}
	RDebugChangeMem mem = { session->cnum, data };
	r_vector_push (vmem, &mem);
	return true;
}
