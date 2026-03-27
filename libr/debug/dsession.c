/* radare - LGPL - Copyright 2017-2023 - rkx1209 */

#include <r_debug.h>
#include <r_util/r_json.h>
#if R2__UNIX__
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#endif

static int cmp_cnum_reg(const RDebugChangeReg *a, const RDebugChangeReg *b) {
	return (a->cnum > b->cnum) - (a->cnum < b->cnum);
}

static int cmp_cnum_mem(const RDebugChangeMem *a, const RDebugChangeMem *b) {
	return (a->cnum > b->cnum) - (a->cnum < b->cnum);
}

static int cmp_cnum_chkpt(const RDebugCheckpoint *a, const RDebugCheckpoint *b) {
	int cmp = (a->cnum > b->cnum) - (a->cnum < b->cnum);
	if (cmp) {
		return cmp;
	}
	return (a->id > b->id) - (a->id < b->id);
}

static int cmp_int_fd(const void *a, const void *b) {
	const int ia = *(const int *)a;
	const int ib = *(const int *)b;
	return (ia > ib) - (ia < ib);
}

static size_t checkpoint_index_slot(const RDebugSession *session, ut64 checkpoint_id) {
	return (size_t)ht_up_find (session->checkpoint_index, checkpoint_id, NULL);
}

static void checkpoint_index_insert(RDebugSession *session, ut64 checkpoint_id, size_t index) {
	ht_up_insert (session->checkpoint_index, checkpoint_id, (void *)(index + 1));
}

static void checkpoint_index_rebuild(RDebugSession *session) {
	if (!session || !session->checkpoint_index || !session->checkpoints) {
		return;
	}
	ht_up_free (session->checkpoint_index);
	session->checkpoint_index = ht_up_new (NULL, NULL, NULL);
	if (!session->checkpoint_index) {
		return;
	}
	RDebugCheckpoint *chkpt;
	size_t index = 0;
	R_VEC_FOREACH (session->checkpoints, chkpt) {
		checkpoint_index_insert (session, chkpt->id, index++);
	}
}

static void htup_replay_stream_free(HtUPKv *kv) {
	r_debug_replay_stream_free ((RDebugReplayStream *)kv->value);
}

static RDebugReplayStream *replay_stream_new(int fd, const ut8 *buf, ut64 len, const char *label) {
	RDebugReplayStream *stream = R_NEW0 (RDebugReplayStream);
	if (!stream) {
		return NULL;
	}
	stream->fd = fd;
	stream->data = r_buf_new_with_bytes (buf, len);
	if (!stream->data) {
		r_debug_replay_stream_free (stream);
		return NULL;
	}
	if (R_STR_ISNOTEMPTY (label)) {
		stream->label = strdup (label);
	}
	return stream;
}

static RDebugReplayStream *replay_stream_clone(const RDebugReplayStream *stream) {
	R_RETURN_VAL_IF_FAIL (stream, NULL);
	ut64 size = r_buf_size (stream->data);
	ut8 *bytes = size? malloc (size): NULL;
	if (size && !bytes) {
		return NULL;
	}
	if (size && r_buf_read_at (stream->data, 0, bytes, size) < 0) {
		free (bytes);
		return NULL;
	}
	RDebugReplayStream *clone = replay_stream_new (stream->fd, bytes? bytes: (const ut8 *)"", size, stream->label);
	free (bytes);
	if (!clone) {
		return NULL;
	}
	clone->consumed = stream->consumed;
	return clone;
}

typedef struct replay_clone_ctx_t {
	HtUP *dst;
	bool ok;
} ReplayCloneCtx;

static bool replay_clone_cb(void *user, const ut64 key, const void *value) {
	ReplayCloneCtx *ctx = user;
	RDebugReplayStream *clone = replay_stream_clone ((const RDebugReplayStream *)value);
	if (!clone) {
		ctx->ok = false;
		return false;
	}
	ht_up_insert (ctx->dst, key, clone);
	return true;
}

static HtUP *replay_table_clone(HtUP *src) {
	HtUP *dst = ht_up_new (NULL, htup_replay_stream_free, NULL);
	if (!dst) {
		return NULL;
	}
	if (!src) {
		return dst;
	}
	ReplayCloneCtx ctx = {
		.dst = dst,
		.ok = true,
	};
	ht_up_foreach (src, replay_clone_cb, &ctx);
	if (!ctx.ok) {
		ht_up_free (dst);
		return NULL;
	}
	return dst;
}

static RDebugReplayStream *replay_stream_get(RDebugCheckpoint *chkpt, int fd) {
	R_RETURN_VAL_IF_FAIL (chkpt && chkpt->replay, NULL);
	return ht_up_find (chkpt->replay, (ut64)(ut32)fd, NULL);
}

static bool checkpoint_replay_count_cb(void *user, const ut64 key, const void *value) {
	size_t *count = user;
	(void)key;
	(void)value;
	(*count)++;
	return true;
}

typedef struct replay_collect_ctx_t {
	int *fds;
	size_t idx;
} ReplayCollectCtx;

static bool checkpoint_replay_collect_cb(void *user, const ut64 key, const void *value) {
	ReplayCollectCtx *ctx = user;
	(void)value;
	ctx->fds[ctx->idx++] = (int)(ut32)key;
	return true;
}

static int *checkpoint_replay_sorted_fds(RDebugCheckpoint *chkpt, size_t *count) {
	R_RETURN_VAL_IF_FAIL (count, NULL);
	*count = 0;
	if (!chkpt || !chkpt->replay) {
		return NULL;
	}
	ht_up_foreach (chkpt->replay, checkpoint_replay_count_cb, count);
	if (!*count) {
		return NULL;
	}
	int *fds = calloc (*count, sizeof (int));
	if (!fds) {
		*count = 0;
		return NULL;
	}
	ReplayCollectCtx ctx = {
		.fds = fds,
		.idx = 0,
	};
	ht_up_foreach (chkpt->replay, checkpoint_replay_collect_cb, &ctx);
	qsort (fds, *count, sizeof (int), cmp_int_fd);
	return fds;
}

static bool replay_stream_hex(const RDebugReplayStream *stream, char **hex, ut64 *size) {
	R_RETURN_VAL_IF_FAIL (stream && hex && size, false);
	*hex = NULL;
	*size = r_buf_size (stream->data);
	if (!*size) {
		*hex = strdup ("");
		return *hex != NULL;
	}
	if (*size > INT_MAX) {
		return false;
	}
	ut8 *bytes = malloc (*size);
	if (!bytes) {
		return false;
	}
	if (r_buf_read_at (stream->data, 0, bytes, *size) < 0) {
		free (bytes);
		return false;
	}
	*hex = r_hex_bin2strdup (bytes, (int)*size);
	free (bytes);
	return *hex != NULL;
}

static const char *replay_binding_kind_name(int kind) {
	switch (kind) {
	case R_DEBUG_REPLAY_BINDING_PTY:
		return "pty";
	default:
		return "none";
	}
}

static bool replay_binding_reset_pty(const RDebugReplayBinding *binding) {
#if R2__UNIX__
	R_RETURN_VAL_IF_FAIL (binding, false);
	if (R_STR_ISNOTEMPTY (binding->slave_name)) {
		int slave_fd = open (binding->slave_name, O_RDWR | O_NOCTTY);
		if (slave_fd >= 0) {
			bool ok = tcflush (slave_fd, TCIFLUSH) == 0;
			close (slave_fd);
			return ok;
		}
	}
	return tcflush (binding->host_fd, TCIFLUSH) == 0;
#else
	return false;
#endif
}

static bool replay_binding_write_all(const RDebugReplayBinding *binding, const ut8 *bytes, ut64 remaining) {
#if R2__UNIX__
	R_RETURN_VAL_IF_FAIL (binding && bytes, false);
	while (remaining > 0) {
		size_t chunk = remaining > INT_MAX? INT_MAX: (size_t)remaining;
		ssize_t written = write (binding->host_fd, bytes, chunk);
		if (written < 0) {
			r_sys_perror ("replay write");
			return false;
		}
		bytes += written;
		remaining -= (ut64)written;
	}
	return true;
#else
	return false;
#endif
}

R_API void r_debug_session_fini_runtime(RDebug *dbg) {
	r_debug_fasttime_reset (dbg);
}

static void reset_resume_state(RDebug *dbg) {
	R_RETURN_IF_FAIL (dbg);
	dbg->reason.type = R_DEBUG_REASON_NONE;
	dbg->reason.signum = -1;
	dbg->reason.bp_addr = 0;
	dbg->reason.addr = 0;
	dbg->reason.ptr = 0;
	dbg->reason.timestamp = 0;
	dbg->recoil_mode = R_DBG_RECOIL_NONE;
	dbg->pc_at_bp = false;
	dbg->pc_at_bp_set = false;
	dbg->trace_continue = false;
	if (dbg->session) {
		dbg->session->reasontype = R_DEBUG_REASON_NONE;
		dbg->session->bp = NULL;
	}
}

static void restore_checkpoint_snapshot(RDebug *dbg, const RDebugCheckpoint *chkpt) {
	size_t i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = chkpt->arena[i];
		RRegArena *b = dbg->reg->regset[i].arena;
		if (a && b && a->bytes && b->bytes) {
			memcpy (b->bytes, a->bytes, a->size);
		}
	}
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, true);

	RListIter *iter;
	RDebugSnap *snap;
	r_list_foreach (chkpt->snaps, iter, snap) {
		dbg->iob.write_at (dbg->iob.io, snap->addr, snap->data, snap->size);
	}
}

R_API void r_debug_session_free(RDebugSession *session) {
	if (session) {
		RVecDebugCheckpoint_free (session->checkpoints);
		ht_up_free (session->checkpoint_index);
		ht_up_free (session->registers);
		ht_up_free (session->memory);
		free (session);
	}
}

static void htup_vec_reg_free(HtUPKv *kv) {
	RVecDebugChangeReg_free ((RVecDebugChangeReg *)kv->value);
}

static void htup_vec_mem_free(HtUPKv *kv) {
	RVecDebugChangeMem_free ((RVecDebugChangeMem *)kv->value);
}

R_API RDebugSession *r_debug_session_new(void) {
	RDebugSession *session = R_NEW0 (RDebugSession);
	if (!session) {
		return NULL;
	}

	session->checkpoints = RVecDebugCheckpoint_new ();
	if (!session->checkpoints) {
		r_debug_session_free (session);
		return NULL;
	}
	session->checkpoint_index = ht_up_new (NULL, NULL, NULL);
	if (!session->checkpoint_index) {
		r_debug_session_free (session);
		return NULL;
	}
	session->registers = ht_up_new (NULL, htup_vec_reg_free, NULL);
	if (!session->registers) {
		r_debug_session_free (session);
		return NULL;
	}
	session->memory = ht_up_new (NULL, htup_vec_mem_free, NULL);
	if (!session->memory) {
		r_debug_session_free (session);
		return NULL;
	}
	session->current_checkpoint_id = UT64_MAX;
	session->next_checkpoint_id = 1;
	session->linear_history_valid = true;

	return session;
}

R_API ut64 r_debug_checkpoint_create(RDebug *dbg, ut64 parent_id, const char *label) {
	R_RETURN_VAL_IF_FAIL (dbg->session, false);
	size_t i;
	RDebugCheckpoint checkpoint = {0};
	RDebugSession *session = dbg->session;
	checkpoint.id = session->next_checkpoint_id++;
	checkpoint.parent_id = parent_id;
	checkpoint.cnum = session->cnum;
	checkpoint.label = R_STR_ISNOTEMPTY (label)? strdup (label): NULL;
	RDebugCheckpoint *parent = parent_id == UT64_MAX? NULL: r_debug_session_checkpoint_get (session, parent_id);
	checkpoint.replay = parent? replay_table_clone (parent->replay): ht_up_new (NULL, htup_replay_stream_free, NULL);
	if (!checkpoint.replay) {
		free (checkpoint.label);
		return false;
	}

	// Save current registers arena iter
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = dbg->reg->regset[i].arena;
		if (a && a->bytes) {
			RRegArena *b = r_reg_arena_new (a->size);
			if (!b) {
				continue;
			}
			memcpy (b->bytes, a->bytes, b->size);
			checkpoint.arena[i] = b;
		}
	}

	// Save current memory maps
	checkpoint.snaps = r_list_new ();
	if (!checkpoint.snaps) {
		ht_up_free (checkpoint.replay);
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

	RVecDebugCheckpoint_push_back (session->checkpoints, &checkpoint);
	checkpoint_index_insert (session, checkpoint.id, RVecDebugCheckpoint_length (session->checkpoints) - 1);
	session->current_checkpoint_id = checkpoint.id;

	// Add PC register change so we can check for breakpoints when continue [back]
	RRegItem *ripc = r_reg_get (dbg->reg, "PC", R_REG_TYPE_GPR);
	if (ripc) {
		ut64 data = r_reg_get_value (dbg->reg, ripc);
		r_debug_session_add_reg_change (session, ripc->arena, ripc->offset, data);
	}

	return checkpoint.id;
}

R_API bool r_debug_add_checkpoint(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->session, false);
	ut64 parent_id = dbg->session->current_checkpoint_id;
	return r_debug_checkpoint_create (dbg, parent_id, NULL) != 0;
}

static void _set_initial_registers(RDebug *dbg) {
	size_t i;
	if (!dbg->session->cur_chkpt) {
		return;
	}
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = dbg->session->cur_chkpt->arena[i];
		RRegArena *b = dbg->reg->regset[i].arena;
		if (a && b && a->bytes && b->bytes) {
			memcpy (b->bytes, a->bytes, a->size);
		}
	}
}

static void _set_register(RDebug *dbg, RRegItem *ri, ut32 cnum) {
	RVecDebugChangeReg *vreg = ht_up_find (dbg->session->registers, ri->offset | (ri->arena << 16), NULL);
	if (!vreg) {
		return;
	}
	ut64 index = RVecDebugChangeReg_upper_bound (vreg, &(RDebugChangeReg){ (int)cnum, 0 }, cmp_cnum_reg);
	if (index > 0 && index <= RVecDebugChangeReg_length (vreg)) {
		RDebugChangeReg *reg = RVecDebugChangeReg_at (vreg, index - 1);
		if (!dbg->session->cur_chkpt) {
			r_reg_set_value (dbg->reg, ri, reg->data);
		} else if (reg->cnum > dbg->session->cur_chkpt->cnum) {
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
	if (!dbg->session->cur_chkpt) {
		return;
	}
	r_list_foreach (dbg->session->cur_chkpt->snaps, iter, snap) {
		dbg->iob.write_at (dbg->iob.io, snap->addr, snap->data, snap->size);
	}
}

static bool _restore_memory_cb(void *user, const ut64 key, const void *value) {
	RDebug *dbg = user;
	RVecDebugChangeMem *vmem = (RVecDebugChangeMem *)value;

	ut64 index = RVecDebugChangeMem_upper_bound (vmem, &(RDebugChangeMem){ (int)dbg->session->cnum, 0 }, cmp_cnum_mem);
	if (index > 0 && index <= RVecDebugChangeMem_length (vmem)) {
		RDebugChangeMem *mem = RVecDebugChangeMem_at (vmem, index - 1);
		if (!dbg->session->cur_chkpt) {
			dbg->iob.write_at (dbg->iob.io, key, &mem->data, 1);
		} else if (mem->cnum > dbg->session->cur_chkpt->cnum) {
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
	ut64 index = RVecDebugCheckpoint_upper_bound (session->checkpoints, &(RDebugCheckpoint){ .cnum = (int)cnum, .id = UT64_MAX }, cmp_cnum_chkpt);
	if (index > 0 && index <= RVecDebugCheckpoint_length (session->checkpoints)) {
		checkpoint = RVecDebugCheckpoint_at (session->checkpoints, index - 1);
	}
	return checkpoint;
}

R_API RDebugCheckpoint *r_debug_session_checkpoint_get(RDebugSession *session, ut64 checkpoint_id) {
	R_RETURN_VAL_IF_FAIL (session && session->checkpoint_index, NULL);
	size_t slot = checkpoint_index_slot (session, checkpoint_id);
	if (!slot) {
		return NULL;
	}
	return RVecDebugCheckpoint_at (session->checkpoints, slot - 1);
}

R_API void r_debug_session_restore_reg_mem(RDebug *dbg, ut32 cnum) {
	r_debug_session_fini_runtime (dbg);
	reset_resume_state (dbg);
	// Set checkpoint for initial registers and memory
	dbg->session->cur_chkpt = _get_checkpoint_before (dbg->session, cnum);
	if (dbg->session->cur_chkpt) {
		dbg->session->current_checkpoint_id = dbg->session->cur_chkpt->id;
	}

	// Restore registers
	_restore_registers (dbg, cnum);
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, true);

	// Restore memory
	_restore_memory (dbg, cnum);
}

R_API bool r_debug_session_restore_checkpoint(RDebug *dbg, ut64 checkpoint_id) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->session, false);
	r_debug_session_fini_runtime (dbg);
	reset_resume_state (dbg);
	RDebugCheckpoint *chkpt = r_debug_session_checkpoint_get (dbg->session, checkpoint_id);
	if (!chkpt) {
		R_LOG_ERROR ("Unknown checkpoint id %"PFMT64u, checkpoint_id);
		return false;
	}
	dbg->session->cur_chkpt = chkpt;
	dbg->session->current_checkpoint_id = checkpoint_id;
	dbg->session->linear_history_valid = false;
	restore_checkpoint_snapshot (dbg, chkpt);
	return true;
}

R_API void r_debug_session_list_checkpoints(RDebug *dbg, int mode) {
	R_RETURN_IF_FAIL (dbg && dbg->session);
	RDebugSession *session = dbg->session;
	RDebugCheckpoint *chkpt;
	size_t index = 0;
	if (mode == 'j') {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
		R_VEC_FOREACH (session->checkpoints, chkpt) {
			pj_o (pj);
			pj_kn (pj, "id", chkpt->id);
			if (chkpt->parent_id != UT64_MAX) {
				pj_kn (pj, "parent", chkpt->parent_id);
			} else {
				pj_knull (pj, "parent");
			}
			pj_kn (pj, "cnum", chkpt->cnum);
			pj_ks (pj, "label", chkpt->label? chkpt->label: "");
			pj_kb (pj, "current", chkpt->id == session->current_checkpoint_id);
			pj_kn (pj, "index", index++);
			pj_end (pj);
		}
		pj_end (pj);
		dbg->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
		return;
	}
	R_VEC_FOREACH (session->checkpoints, chkpt) {
		if (chkpt->parent_id == UT64_MAX) {
			dbg->cb_printf ("%"PFMT64u" parent=- cnum=%d%s%s%s\n",
				chkpt->id,
				chkpt->cnum,
				chkpt->id == session->current_checkpoint_id? " current": "",
				chkpt->label? " label=": "",
				chkpt->label? chkpt->label: "");
		} else {
			dbg->cb_printf ("%"PFMT64u" parent=%"PFMT64u" cnum=%d%s%s%s\n",
				chkpt->id,
				chkpt->parent_id,
				chkpt->cnum,
				chkpt->id == session->current_checkpoint_id? " current": "",
				chkpt->label? " label=": "",
				chkpt->label? chkpt->label: "");
		}
	}
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
			int hashsz = 0;
			ut8 *hash = r_debug_snap_get_hash (dbg, snap, &hashsz);
			if (hash && hashsz > 0) {
				char *hexstr = r_hex_bin2strdup (hash, hashsz);
				if (hexstr) {
					dbg->cb_printf ("%s: %s\n", snap->name, hexstr);
					free (hexstr);
				}
				free (hash);
			}
		// 	r_debug_snap_free (snap);
		}
	}
}

R_API bool r_debug_session_add_reg_change(RDebugSession *session, int arena, ut64 offset, ut64 data) {
	RVecDebugChangeReg *vreg = ht_up_find (session->registers, offset | (arena << 16), NULL);
	if (!vreg) {
		vreg = RVecDebugChangeReg_new ();
		if (!vreg) {
			R_LOG_ERROR ("creating a register vector");
			return false;
		}
		ht_up_insert (session->registers, offset | (arena << 16), vreg);
	}
	RDebugChangeReg reg = { session->cnum, data };
	RVecDebugChangeReg_push_back (vreg, &reg);
	return true;
}

R_API bool r_debug_session_add_mem_change(RDebugSession *session, ut64 addr, ut8 data) {
	RVecDebugChangeMem *vmem = ht_up_find (session->memory, addr, NULL);
	if (!vmem) {
		vmem = RVecDebugChangeMem_new ();
		if (!vmem) {
			R_LOG_ERROR ("creating a memory vector");
			return false;
		}
		ht_up_insert (session->memory, addr, vmem);
	}
	RDebugChangeMem mem = { session->cnum, data };
	RVecDebugChangeMem_push_back (vmem, &mem);
	return true;
}

/* Save and Load Session */

// 0x<addr>=[<RDebugChangeReg>]
static bool serialize_register_cb(void *db, const ut64 k, const void *v) {
	RDebugChangeReg *reg;
	RVecDebugChangeReg *vreg = (RVecDebugChangeReg *)v;
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_a (j);

	R_VEC_FOREACH (vreg, reg) {
		pj_o (j);
		pj_kN (j, "cnum", reg->cnum);
		pj_kn (j, "data", reg->data);
		pj_end (j);
	}

	pj_end (j);
	r_strf_var (key, 32, "0x%"PFMT64x, k);
	sdb_set (db, key, pj_string (j), 0);
	pj_free (j);
	return true;
}

static void serialize_registers(Sdb *db, HtUP *registers) {
	ht_up_foreach (registers, serialize_register_cb, db);
}

// 0x<addr>={ "size":<size_t>, "a":[<RDebugChangeMem>]}},
static bool serialize_memory_cb(void *db, const ut64 k, const void *v) {
	RDebugChangeMem *mem;
	RVecDebugChangeMem *vmem = (RVecDebugChangeMem *)v;
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_a (j);

	R_VEC_FOREACH (vmem, mem) {
		pj_o (j);
		pj_kN (j, "cnum", mem->cnum);
		pj_kn (j, "data", mem->data);
		pj_end (j);
	}

	pj_end (j);
	r_strf_var (key, 32, "0x%"PFMT64x, k);
	sdb_set (db, key, pj_string (j), 0);
	pj_free (j);
	return true;
}

static void serialize_memory(Sdb *db, HtUP *memory) {
	ht_up_foreach (memory, serialize_memory_cb, db);
}

static void serialize_checkpoints(Sdb *db, RVecDebugCheckpoint *checkpoints) {
	size_t i;
	RDebugCheckpoint *chkpt;
	RDebugSnap *snap;
	RListIter *iter;

	R_VEC_FOREACH (checkpoints, chkpt) {
		// 0x<id>={
		//   registers:{ "<RRegisterType>":<RRegArena>, ...},
		//   snaps:{ "size":<size_t>, "a":[<RDebugSnap>]}
		// }
		PJ *j = pj_new ();
		if (!j) {
			return;
		}
		pj_o (j);
		pj_kn (j, "id", chkpt->id);
		pj_kn (j, "cnum", chkpt->cnum);
		if (chkpt->parent_id != UT64_MAX) {
			pj_kn (j, "parent", chkpt->parent_id);
		} else {
			pj_knull (j, "parent");
		}
		pj_ks (j, "label", chkpt->label? chkpt->label: "");

		// Serialize RRegArena to "registers"
		// { "size":<int>, "bytes":"<base64>" }
		pj_ka (j, "registers");
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			RRegArena *arena = chkpt->arena[i];
			if (arena && arena->bytes) {
				pj_o (j);
				pj_kn (j, "arena", i);
				char *ebytes = sdb_encode ((const void *)arena->bytes, arena->size);
				pj_ks (j, "bytes", ebytes);
				free (ebytes);
				pj_kn (j, "size", arena->size);
				pj_end (j);
			}
		}
		pj_end (j);

		// Serialize RDebugSnap to "snaps"
		// { "name":<str>, "addr":<ut64>, "addr_end":<ut64>, "size":<ut64>,
		//  "data":"<base64>", "perm":<int>, "user":<int>, "shared":<bool>}
		pj_ka (j, "snaps");
		r_list_foreach (chkpt->snaps, iter, snap) {
			pj_o (j);
			pj_ks (j, "name", snap->name);
			pj_kn (j, "addr", snap->addr);
			pj_kn (j, "addr_end", snap->addr_end);
			pj_kn (j, "size", snap->size);
			char *edata = sdb_encode ((const void *)snap->data, snap->size);
			if (!edata) {
				pj_free (j);
				return;
			}
			pj_ks (j, "data", edata);
			free (edata);
			pj_kn (j, "perm", snap->perm);
			pj_kn (j, "user", snap->user);
			pj_kb (j, "shared", snap->shared);
			pj_end (j);
		}
		pj_end (j);

		pj_ka (j, "replay");
		size_t replay_count = 0;
		int *fds = checkpoint_replay_sorted_fds (chkpt, &replay_count);
		for (i = 0; fds && i < replay_count; i++) {
			RDebugReplayStream *stream = replay_stream_get (chkpt, fds[i]);
			if (!stream) {
				continue;
			}
			char *hex = NULL;
			ut64 size = 0;
			if (!replay_stream_hex (stream, &hex, &size)) {
				continue;
			}
			pj_o (j);
			pj_kn (j, "fd", stream->fd);
			pj_kn (j, "consumed", stream->consumed);
			pj_ks (j, "label", stream->label? stream->label: "");
			pj_ks (j, "hex", hex);
			pj_kn (j, "size", size);
			pj_end (j);
			free (hex);
		}
		free (fds);
		pj_end (j);

		pj_end (j);
		r_strf_var (key, 32, "0x%"PFMT64x, chkpt->id);
		sdb_set (db, key, pj_string (j), 0);
		pj_free (j);
	}
}

/*
 * SDB Format:
 *
 * /
 *   maxcnum=<maxcnum>
 *
 *   /registers
 *     0x<addr>={ "size":<size_t>, "a":[<RDebugChangeReg>]}
 *
 *   /memory
 *     0x<addr>={ "size":<size_t>, "a":[<RDebugChangeMem>]}
 *
 *   /checkpoints
 *     0x<id>={
 *       id:<ut64>,
 *       cnum:<int>,
 *       registers:{ "<RRegisterType>":<RRegArena>, ...},
 *       snaps:{ "size":<size_t>, "a":[<RDebugSnap>]}
 *     }
 *
 * RDebugChangeReg JSON:
 * { "cnum":<int>, "data":<ut64>}
 *
 * RDebugChangeMem JSON:
 * { "cnum":<int>, "data":<ut8>}
 *
 * RRegArena JSON:
 * { "size":<int>, "bytes":"<base64>" }
 *
 * RDebugSnap JSON:
 * { "name":<str>, "addr":<ut64>, "addr_end":<ut64>, "size":<ut64>,
 *  "data":"<base64>", "perm":<int>, "user":<int>, "shared":<bool>}
 *
 * Notes:
 * - This mostly follows r2db-style serialization and uses sdb_json as the parser.
 */
R_API void r_debug_session_serialize(RDebugSession *session, Sdb *db) {
	sdb_num_set (db, "maxcnum", session->maxcnum, 0);
	sdb_num_set (db, "next_checkpoint_id", session->next_checkpoint_id, 0);
	if (session->current_checkpoint_id != UT64_MAX) {
		sdb_num_set (db, "current_checkpoint_id", session->current_checkpoint_id, 0);
	}
	sdb_bool_set (db, "linear_history_valid", session->linear_history_valid, 0);
	serialize_registers (sdb_ns (db, "registers", true), session->registers);
	serialize_memory (sdb_ns (db, "memory", true), session->memory);
	serialize_checkpoints (sdb_ns (db, "checkpoints", true), session->checkpoints);
}

static bool session_sdb_save(Sdb *db, const char *path) {
	char *filename;
	if (!r_file_is_directory (path)) {
		R_LOG_ERROR ("%s is not a directory", path);
		return false;
	}

	filename = r_str_newf ("%s%ssession.sdb", path, R_SYS_DIR);
	sdb_file (db, filename);
	if (!sdb_sync (db)) {
		R_LOG_ERROR ("Failed to sync session to %s", filename);
		free (filename);
		sdb_close (db);
		return false;
	}
	free (filename);
	sdb_close (db);

	SdbListIter *it;
	SdbNs *ns;
	ls_foreach (db->ns, it, ns) {
		char *filename = r_str_newf ("%s%s%s.sdb", path, R_SYS_DIR, ns->name);
		sdb_file (ns->sdb, filename);
		if (!sdb_sync (ns->sdb)) {
			R_LOG_ERROR ("Failed to sync %s to %s", ns->name, filename);
			free (filename);
			sdb_close (ns->sdb);
			return false;
		}
		free (filename);
		sdb_close (ns->sdb);
	}

	return true;
}

R_API bool r_debug_session_save(RDebugSession *session, const char *path) {
	Sdb *db = sdb_new0 ();
	if (!db) {
		return false;
	}
	r_debug_session_serialize (session, db);

	if (!session_sdb_save (db, path)) {
		sdb_free (db);
		return false;
	}
	sdb_free (db);
	return true;
}


#define CHECK_TYPE(v,t) \
	if (!v || v->type != t) \
		continue

static bool deserialize_memory_cb(void *user, const char *addr, const char *v) {
	RJson *child;
	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *reg_json = r_json_parse (json_str);
	if (!reg_json || reg_json->type != R_JSON_ARRAY) {
		free (json_str);
		return true;
	}

	HtUP *memory = user;
	// Insert a new vector into `memory` HtUP at `addr`
	RVecDebugChangeMem *vmem = RVecDebugChangeMem_new ();
	if (!vmem) {
		R_LOG_ERROR ("failed to allocate RVecDebugChangeMem vmem");
		free (json_str);
		r_json_free (reg_json);
		return false;
	}
	ht_up_insert (memory, sdb_atoi (addr), vmem);

	// Extract <RDebugChangeMem>'s into the new vector
	for (child = reg_json->children.first; child; child = child->next) {
		if (child->type != R_JSON_OBJECT) {
			continue;
		}
		const RJson *baby = r_json_get (child, "cnum");
		CHECK_TYPE (baby, R_JSON_INTEGER);
		int cnum = baby->num.s_value;

	baby = r_json_get (child, "data");
	CHECK_TYPE (baby, R_JSON_INTEGER);
	ut64 data = baby->num.u_value;

	RDebugChangeMem mem = { cnum, data };
	RVecDebugChangeMem_push_back (vmem, &mem);
}

	free (json_str);
	r_json_free (reg_json);
	return true;
}

static void deserialize_memory(Sdb *db, HtUP *memory) {
	sdb_foreach (db, deserialize_memory_cb, memory);
}

static bool deserialize_registers_cb(void *user, const char *addr, const char *v) {
	RJson *child;
	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *reg_json = r_json_parse (json_str);
	if (!reg_json || reg_json->type != R_JSON_ARRAY) {
		free (json_str);
		return true;
	}

	// Insert a new vector into `registers` HtUP at `addr`
	HtUP *registers = user;
	RVecDebugChangeReg *vreg = RVecDebugChangeReg_new ();
	if (!vreg) {
		R_LOG_ERROR ("failed to allocate RVecDebugChangeReg vreg");
		r_json_free (reg_json);
		free (json_str);
		return true;
	}
	ht_up_insert (registers, sdb_atoi (addr), vreg);

	// Extract <RDebugChangeReg>'s into the new vector
	for (child = reg_json->children.first; child; child = child->next) {
		if (child->type != R_JSON_OBJECT) {
			continue;
		}
		const RJson *baby = r_json_get (child, "cnum");
		CHECK_TYPE (baby, R_JSON_INTEGER);
		int cnum = baby->num.s_value;

	baby = r_json_get (child, "data");
	CHECK_TYPE (baby, R_JSON_INTEGER);
	ut64 data = baby->num.u_value;

	RDebugChangeReg reg = { cnum, data };
	RVecDebugChangeReg_push_back (vreg, &reg);
}

	r_json_free (reg_json);
	free (json_str);
	return true;
}

static void deserialize_registers(Sdb *db, HtUP *registers) {
	sdb_foreach (db, deserialize_registers_cb, registers);
}

static bool deserialize_checkpoints_cb(void *user, const char *id, const char *v) {
	const RJson *child;
	char *json_str = strdup (v);
	if (!json_str) {
		return true;
	}
	RJson *chkpt_json = r_json_parse (json_str);
	if (!chkpt_json || chkpt_json->type != R_JSON_OBJECT) {
		free (json_str);
		return true;
	}

	RVecDebugCheckpoint *checkpoints = user;
	RDebugCheckpoint checkpoint = {0};
	checkpoint.id = sdb_atoi (id);
	checkpoint.parent_id = UT64_MAX;

	// Extract RRegArena's from "registers"
	const RJson *id_json = r_json_get (chkpt_json, "id");
	if (!id_json || id_json->type != R_JSON_INTEGER || id_json->num.u_value != checkpoint.id) {
		free (json_str);
		r_json_free (chkpt_json);
		return true;
	}
	const RJson *cnum_json = r_json_get (chkpt_json, "cnum");
	if (!cnum_json || cnum_json->type != R_JSON_INTEGER) {
		free (json_str);
		r_json_free (chkpt_json);
		return true;
	}
	checkpoint.cnum = cnum_json->num.s_value;
	const RJson *parent_json = r_json_get (chkpt_json, "parent");
	if (parent_json) {
		if (parent_json->type == R_JSON_INTEGER) {
			checkpoint.parent_id = parent_json->num.u_value;
		} else if (parent_json->type == R_JSON_NULL) {
			checkpoint.parent_id = UT64_MAX;
		}
	}
	const RJson *label_json = r_json_get (chkpt_json, "label");
	if (label_json && label_json->type == R_JSON_STRING && R_STR_ISNOTEMPTY (label_json->str_value)) {
		checkpoint.label = strdup (label_json->str_value);
	}
	const RJson *regs_json = r_json_get (chkpt_json, "registers");
	if (!regs_json || regs_json->type != R_JSON_ARRAY) {
		free (json_str);
		return true;
	}
	for (child = regs_json->children.first; child; child = child->next) {
		const RJson *baby;
		baby = r_json_get (child, "arena");
		CHECK_TYPE (baby, R_JSON_INTEGER);
		int arena = baby->num.s_value;
		if (arena < 0 || arena >= R_REG_TYPE_LAST) {
			continue;
		}
		baby = r_json_get (child, "size");
		CHECK_TYPE (baby, R_JSON_INTEGER);
		int size = baby->num.s_value;
		if (size < 0) {
			continue;
		}
		baby = r_json_get (child, "bytes");
		CHECK_TYPE (baby, R_JSON_STRING);
		ut8 *bytes = sdb_decode (baby->str_value, NULL);

		RRegArena *a = r_reg_arena_new (size);
		if (!a) {
			free (bytes);
			continue;
		}
		memcpy (a->bytes, bytes, a->size);
		checkpoint.arena[arena] = a;
		free (bytes);
	}

	// Extract RDebugSnap's from "snaps"
	checkpoint.snaps = r_list_newf ((RListFree)r_debug_snap_free);
	checkpoint.replay = ht_up_new (NULL, htup_replay_stream_free, NULL);
	if (!checkpoint.replay) {
		free (json_str);
		r_json_free (chkpt_json);
		return true;
	}
	const RJson *snaps_json = r_json_get (chkpt_json, "snaps");
	if (!snaps_json || snaps_json->type != R_JSON_ARRAY) {
		goto replay;
	}
	for (child = snaps_json->children.first; child; child = child->next) {
		const RJson *namej = r_json_get (child, "name");
		CHECK_TYPE (namej, R_JSON_STRING);
		const RJson *dataj = r_json_get (child, "data");
		CHECK_TYPE (dataj, R_JSON_STRING);
		const RJson *sizej = r_json_get (child, "size");
		CHECK_TYPE (sizej, R_JSON_INTEGER);
		const RJson *addrj = r_json_get (child, "addr");
		CHECK_TYPE (addrj, R_JSON_INTEGER);
		const RJson *addr_endj = r_json_get (child, "addr_end");
		CHECK_TYPE (addr_endj, R_JSON_INTEGER);
		const RJson *permj = r_json_get (child, "perm");
		CHECK_TYPE (permj, R_JSON_INTEGER);
		const RJson *userj = r_json_get (child, "user");
		CHECK_TYPE (userj, R_JSON_INTEGER);
		const RJson *sharedj = r_json_get (child, "shared");
		CHECK_TYPE (sharedj, R_JSON_BOOLEAN);

		RDebugSnap *snap = R_NEW0 (RDebugSnap);
		if (!snap) {
			R_LOG_ERROR ("failed to allocate RDebugSnap snap");
			continue;
		}
		snap->name = strdup (namej->str_value);
		snap->addr = addrj->num.u_value;
		snap->addr_end = addr_endj->num.u_value;
		snap->size = sizej->num.u_value;
		snap->data = sdb_decode (dataj->str_value, NULL);
		snap->perm = permj->num.s_value;
		snap->user = userj->num.s_value;
		snap->shared = sharedj->num.u_value;

			r_list_append (checkpoint.snaps, snap);
		}
	{
		const RJson *replay_json;
replay:
		replay_json = r_json_get (chkpt_json, "replay");
		if (replay_json && replay_json->type == R_JSON_ARRAY) {
			for (child = replay_json->children.first; child; child = child->next) {
				const RJson *fdj = r_json_get (child, "fd");
				CHECK_TYPE (fdj, R_JSON_INTEGER);
			const RJson *consumedj = r_json_get (child, "consumed");
			CHECK_TYPE (consumedj, R_JSON_INTEGER);
			const RJson *hexj = r_json_get (child, "hex");
			CHECK_TYPE (hexj, R_JSON_STRING);
			const RJson *labelj = r_json_get (child, "label");
			const char *replay_label = (labelj && labelj->type == R_JSON_STRING)? labelj->str_value: NULL;
			size_t hexlen = 0;
			ut8 *bytes = r_hex_str2bin_dup (hexj->str_value, &hexlen);
			if (!bytes && *hexj->str_value) {
				continue;
			}
			RDebugReplayStream *stream = replay_stream_new (fdj->num.s_value, bytes? bytes: (const ut8 *)"", hexlen, replay_label);
			free (bytes);
			if (!stream) {
				continue;
			}
			stream->consumed = consumedj->num.u_value;
				ht_up_insert (checkpoint.replay, (ut64)(ut32)stream->fd, stream);
			}
		}
	}
	free (json_str);
	r_json_free (chkpt_json);
	RVecDebugCheckpoint_push_back (checkpoints, &checkpoint);
	return true;
}

static void deserialize_checkpoints(Sdb *db, RVecDebugCheckpoint *checkpoints) {
	sdb_foreach (db, deserialize_checkpoints_cb, checkpoints);
	RVecDebugCheckpoint_sort (checkpoints, cmp_cnum_chkpt);
}

static bool session_sdb_load_ns(Sdb *db, const char *nspath, const char *filename) {
	Sdb *tmpdb = sdb_new0 ();
	if (sdb_open (tmpdb, filename) == -1) {
		R_LOG_ERROR ("failed to load %s into sdb", filename);
		sdb_free (tmpdb);
		return false;
	}
	Sdb *ns = sdb_ns_path (db, nspath, true);
	sdb_copy (tmpdb, ns);
	sdb_free (tmpdb);
	return true;
}

static Sdb *session_sdb_load(const char *path) {
	char *filename;
	Sdb *db = sdb_new0 ();
	if (!db) {
		return NULL;
	}

#define SDB_LOAD(fn, ns) do { \
		filename = r_str_newf ("%s%s" fn ".sdb", path, R_SYS_DIR); \
		if (!session_sdb_load_ns (db, ns, filename)) { \
			free (filename); \
			goto error; \
		} \
		free (filename); \
	} while (0)

	SDB_LOAD ("session", "");
	SDB_LOAD ("registers", "registers");
	SDB_LOAD ("memory", "memory");
	SDB_LOAD ("checkpoints", "checkpoints");
	return db;
error:
	sdb_free (db);
	return NULL;
}

R_API void r_debug_session_deserialize(RDebugSession *session, Sdb *db) {
	Sdb *subdb;

	session->maxcnum = sdb_num_get (db, "maxcnum", NULL);
	session->next_checkpoint_id = sdb_const_get (db, "next_checkpoint_id", NULL)?
		sdb_num_get (db, "next_checkpoint_id", NULL): 1;
	session->current_checkpoint_id = sdb_const_get (db, "current_checkpoint_id", NULL)?
		sdb_num_get (db, "current_checkpoint_id", NULL): UT64_MAX;
	session->linear_history_valid = sdb_const_get (db, "linear_history_valid", NULL)?
		sdb_bool_get (db, "linear_history_valid", NULL): true;

#define DESERIALIZE(ns, func) do { \
		subdb = sdb_ns (db, ns, false); \
		if (!subdb) { \
			R_LOG_ERROR ("missing " ns " namespace"); \
			return; \
		} \
		func; \
	} while (0)

	DESERIALIZE ("memory", deserialize_memory (subdb, session->memory));
	DESERIALIZE ("registers", deserialize_registers (subdb, session->registers));
	DESERIALIZE ("checkpoints", deserialize_checkpoints (subdb, session->checkpoints));
	checkpoint_index_rebuild (session);
	if (!session->next_checkpoint_id) {
		RDebugCheckpoint *chkpt;
		ut64 max_checkpoint_id = 0;
		R_VEC_FOREACH (session->checkpoints, chkpt) {
			if (chkpt->id > max_checkpoint_id) {
				max_checkpoint_id = chkpt->id;
			}
		}
		session->next_checkpoint_id = max_checkpoint_id + 1;
	}
}

R_API bool r_debug_session_load(RDebug *dbg, const char *path) {
	RDebugSession *session;
	Sdb *db = session_sdb_load (path);
	if (!db) {
		return false;
	}
	session = r_debug_session_new ();
	if (!session) {
		sdb_free (db);
		return false;
	}
	r_debug_session_deserialize (session, db);
	r_debug_session_free (dbg->session);
	dbg->session = session;
	r_debug_session_restore_reg_mem (dbg, 0);
	sdb_free (db);
	return true;
}

R_API bool r_debug_session_checkpoint_replay_append(RDebugSession *session, ut64 checkpoint_id, int fd, const ut8 *buf, ut64 len, const char *label) {
	R_RETURN_VAL_IF_FAIL (session && buf, false);
	RDebugCheckpoint *chkpt = r_debug_session_checkpoint_get (session, checkpoint_id);
	if (!chkpt || !chkpt->replay) {
		return false;
	}
	RDebugReplayStream *stream = replay_stream_get (chkpt, fd);
	if (!stream) {
		stream = replay_stream_new (fd, buf, len, label);
		if (!stream) {
			return false;
		}
		ht_up_insert (chkpt->replay, (ut64)(ut32)fd, stream);
		return true;
	}
	if (!r_buf_append_bytes (stream->data, buf, len)) {
		return false;
	}
	if (R_STR_ISNOTEMPTY (label) && !stream->label) {
		stream->label = strdup (label);
	}
	return true;
}

R_API bool r_debug_session_checkpoint_replay_clear(RDebugSession *session, ut64 checkpoint_id, int fd) {
	R_RETURN_VAL_IF_FAIL (session, false);
	RDebugCheckpoint *chkpt = r_debug_session_checkpoint_get (session, checkpoint_id);
	if (!chkpt || !chkpt->replay) {
		return false;
	}
	if (fd < 0) {
		ht_up_free (chkpt->replay);
		chkpt->replay = ht_up_new (NULL, htup_replay_stream_free, NULL);
		return chkpt->replay != NULL;
	}
	RDebugReplayStream *stream = replay_stream_get (chkpt, fd);
	if (!stream) {
		return false;
	}
	ht_up_delete (chkpt->replay, (ut64)(ut32)fd);
	return true;
}

static bool replay_apply_stream(RDebug *dbg, RDebugReplayStream *stream) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->session && stream, false);
	RDebugReplayBinding *binding = r_debug_replay_binding_get (dbg, stream->fd);
	if (!binding || !binding->owned || !binding->writable || !binding->resettable) {
		R_LOG_ERROR ("Replay fd %d is not bound to a resettable debugger-owned channel", stream->fd);
		return false;
	}
	ut64 total = r_buf_size (stream->data);
	if (stream->consumed >= total) {
		return true;
	}
	ut64 remaining = total - stream->consumed;
	ut8 *bytes = malloc (remaining);
	if (!bytes) {
		return false;
	}
	if (r_buf_read_at (stream->data, stream->consumed, bytes, remaining) < 0) {
		free (bytes);
		return false;
	}
	bool ok = false;
	switch (binding->kind) {
	case R_DEBUG_REPLAY_BINDING_PTY:
		ok = replay_binding_reset_pty (binding) && replay_binding_write_all (binding, bytes, remaining);
		break;
	default:
		R_LOG_ERROR ("Unsupported replay binding backend");
		break;
	}
	free (bytes);
	if (!ok) {
		return false;
	}
	stream->consumed += remaining;
	return true;
}

R_API bool r_debug_session_checkpoint_replay_apply(RDebug *dbg, ut64 checkpoint_id, int fd) {
	R_RETURN_VAL_IF_FAIL (dbg && dbg->session, false);
	RDebugCheckpoint *chkpt = r_debug_session_checkpoint_get (dbg->session, checkpoint_id);
	if (!chkpt || !chkpt->replay) {
		return false;
	}
	if (fd >= 0) {
		RDebugReplayStream *stream = replay_stream_get (chkpt, fd);
		if (!stream) {
			R_LOG_ERROR ("No replay stream for checkpoint %"PFMT64u" fd %d", checkpoint_id, fd);
			return false;
		}
		return replay_apply_stream (dbg, stream);
	}
	size_t replay_count = 0;
	int *fds = checkpoint_replay_sorted_fds (chkpt, &replay_count);
	size_t i;
	bool ok = true;
	for (i = 0; fds && i < replay_count; i++) {
		RDebugReplayStream *stream = replay_stream_get (chkpt, fds[i]);
		if (stream && !replay_apply_stream (dbg, stream)) {
			ok = false;
			break;
		}
	}
	free (fds);
	return ok;
}

R_API void r_debug_session_list_checkpoint_replay(RDebug *dbg, int mode) {
	R_RETURN_IF_FAIL (dbg && dbg->session);
	RDebugSession *session = dbg->session;
	RDebugCheckpoint *chkpt;
	if (mode == 'j') {
		PJ *pj = pj_new ();
		if (!pj) {
			return;
		}
		pj_a (pj);
		R_VEC_FOREACH (session->checkpoints, chkpt) {
			pj_o (pj);
			pj_kn (pj, "id", chkpt->id);
			pj_ka (pj, "replay");
			size_t replay_count = 0;
			int *fds = checkpoint_replay_sorted_fds (chkpt, &replay_count);
			size_t i;
			for (i = 0; fds && i < replay_count; i++) {
				RDebugReplayStream *stream = replay_stream_get (chkpt, fds[i]);
				if (!stream) {
					continue;
				}
				char *hex = NULL;
				ut64 size = 0;
				if (!replay_stream_hex (stream, &hex, &size)) {
					continue;
				}
				pj_o (pj);
				pj_kn (pj, "fd", stream->fd);
				RDebugReplayBinding *binding = r_debug_replay_binding_get (dbg, stream->fd);
				pj_kn (pj, "size", size);
				pj_kn (pj, "consumed", stream->consumed);
				pj_kn (pj, "remaining", size > stream->consumed? size - stream->consumed: 0);
				pj_ks (pj, "label", stream->label? stream->label: "");
				pj_ks (pj, "backend", binding? replay_binding_kind_name (binding->kind): "none");
				pj_kb (pj, "owned", binding? binding->owned: false);
				pj_kb (pj, "resettable", binding? binding->resettable: false);
				pj_ks (pj, "hex", hex);
				pj_end (pj);
				free (hex);
			}
			free (fds);
			pj_end (pj);
			pj_end (pj);
		}
		pj_end (pj);
		dbg->cb_printf ("%s\n", pj_string (pj));
		pj_free (pj);
		return;
	}
	R_VEC_FOREACH (session->checkpoints, chkpt) {
		size_t replay_count = 0;
		int *fds = checkpoint_replay_sorted_fds (chkpt, &replay_count);
		size_t i;
		for (i = 0; fds && i < replay_count; i++) {
			RDebugReplayStream *stream = replay_stream_get (chkpt, fds[i]);
			if (!stream) {
				continue;
			}
			RDebugReplayBinding *binding = r_debug_replay_binding_get (dbg, stream->fd);
			ut64 size = r_buf_size (stream->data);
			dbg->cb_printf ("%"PFMT64u" fd=%d backend=%s owned=%s resettable=%s size=%"PFMT64u" consumed=%"PFMT64u" remaining=%"PFMT64u"%s%s\n",
				chkpt->id,
				stream->fd,
				binding? replay_binding_kind_name (binding->kind): "none",
				binding && binding->owned? "true": "false",
				binding && binding->resettable? "true": "false",
				size,
				stream->consumed,
				size > stream->consumed? size - stream->consumed: 0,
				stream->label? " label=": "",
				stream->label? stream->label: "");
		}
		free (fds);
	}
}

static ut64 state_json_addr_value(const RJson *value, bool *ok) {
	if (ok) {
		*ok = false;
	}
	if (!value) {
		return 0;
	}
	if (value->type == R_JSON_INTEGER) {
		if (ok) {
			*ok = true;
		}
		return value->num.u_value;
	}
	if (value->type == R_JSON_STRING && R_STR_ISNOTEMPTY (value->str_value)) {
		char *endptr = NULL;
		ut64 parsed = strtoull (value->str_value, &endptr, 0);
		if (endptr && *endptr == '\0') {
			if (ok) {
				*ok = true;
			}
			return parsed;
		}
	}
	return 0;
}

R_API RDebugStateRequest *r_debug_state_request_parse_json(const char *json) {
	R_RETURN_VAL_IF_FAIL (json, NULL);
	char *json_copy = strdup (json);
	if (!json_copy) {
		return NULL;
	}
	RJson *root = r_json_parse (json_copy);
	if (!root || root->type != R_JSON_OBJECT) {
		free (json_copy);
		r_json_free (root);
		return NULL;
	}
	RDebugStateRequest *request = R_NEW0 (RDebugStateRequest);
	if (!request) {
		free (json_copy);
		r_json_free (root);
		return NULL;
	}
	request->registers = r_list_newf ((RListFree)r_debug_state_reg_spec_free);
	request->memory = r_list_newf ((RListFree)r_debug_state_mem_spec_free);
	if (!request->registers || !request->memory) {
		r_debug_state_request_free (request);
		free (json_copy);
		r_json_free (root);
		return NULL;
	}

	const RJson *registers = r_json_get (root, "registers");
	if (registers && registers->type == R_JSON_ARRAY) {
		RJson *child;
		for (child = registers->children.first; child; child = child->next) {
			if (child->type != R_JSON_STRING || R_STR_ISEMPTY (child->str_value)) {
				continue;
			}
			RDebugStateRegSpec *spec = R_NEW0 (RDebugStateRegSpec);
			if (!spec) {
				continue;
			}
			spec->name = strdup (child->str_value);
			if (!spec->name) {
				r_debug_state_reg_spec_free (spec);
				continue;
			}
			r_list_append (request->registers, spec);
		}
	}

	const RJson *memory = r_json_get (root, "memory");
	if (memory && memory->type == R_JSON_ARRAY) {
		RJson *child;
		for (child = memory->children.first; child; child = child->next) {
			if (child->type != R_JSON_OBJECT) {
				continue;
			}
			bool ok = false;
			const RJson *addrj = r_json_get (child, "addr");
			ut64 addr = state_json_addr_value (addrj, &ok);
			if (!ok) {
				continue;
			}
			const RJson *sizej = r_json_get (child, "size");
			if (!sizej || sizej->type != R_JSON_INTEGER || sizej->num.u_value > UT32_MAX) {
				continue;
			}
			RDebugStateMemSpec *spec = R_NEW0 (RDebugStateMemSpec);
			if (!spec) {
				continue;
			}
			spec->addr = addr;
			spec->size = (ut32)sizej->num.u_value;
			const RJson *labelj = r_json_get (child, "label");
			if (labelj && labelj->type == R_JSON_STRING && R_STR_ISNOTEMPTY (labelj->str_value)) {
				spec->label = strdup (labelj->str_value);
			}
			r_list_append (request->memory, spec);
		}
	}

	const RJson *threadsj = r_json_get (root, "threads");
	if (threadsj && threadsj->type == R_JSON_BOOLEAN) {
		request->include_threads = threadsj->num.u_value != 0;
	}

	r_json_free (root);
	free (json_copy);
	return request;
}

R_API void r_debug_state_request_free(RDebugStateRequest *request) {
	if (!request) {
		return;
	}
	r_list_free (request->registers);
	r_list_free (request->memory);
	free (request);
}

R_API RDebugStateSnapshot *r_debug_state_snapshot_collect(RDebug *dbg, const RDebugStateRequest *request) {
	R_RETURN_VAL_IF_FAIL (dbg && request, NULL);
	RDebugStateSnapshot *snapshot = R_NEW0 (RDebugStateSnapshot);
	if (!snapshot) {
		return NULL;
	}
	snapshot->pid = dbg->pid;
	snapshot->tid = dbg->tid;
	snapshot->reason_type = dbg->reason.type;
	snapshot->registers = r_list_newf ((RListFree)r_debug_state_reg_value_free);
	snapshot->memory = r_list_newf ((RListFree)r_debug_state_mem_value_free);
	snapshot->threads = r_list_newf ((RListFree)r_debug_state_thread_free);
	if (!snapshot->registers || !snapshot->memory || !snapshot->threads) {
		r_debug_state_snapshot_free (snapshot);
		return NULL;
	}

	if (dbg->reg) {
		r_debug_reg_sync (dbg, R_REG_TYPE_GPR, false);
		snapshot->pc = r_debug_reg_get (dbg, "PC");
	}

	RListIter *iter;
	RDebugStateRegSpec *regspec;
	r_list_foreach (request->registers, iter, regspec) {
		RDebugStateRegValue *value = R_NEW0 (RDebugStateRegValue);
		if (!value) {
			continue;
		}
		value->name = regspec->name? strdup (regspec->name): NULL;
		bool err = false;
		value->value = r_debug_reg_get_err (dbg, regspec->name, &err, NULL);
		value->found = !err;
		r_list_append (snapshot->registers, value);
	}

	RDebugStateMemSpec *memspec;
	r_list_foreach (request->memory, iter, memspec) {
		RDebugStateMemValue *value = R_NEW0 (RDebugStateMemValue);
		if (!value) {
			continue;
		}
		value->addr = memspec->addr;
		value->size = memspec->size;
		value->label = memspec->label? strdup (memspec->label): NULL;
		if (memspec->size > 0) {
			value->bytes = calloc (1, memspec->size);
			if (!value->bytes) {
				r_debug_state_mem_value_free (value);
				continue;
			}
			value->ok = dbg->iob.read_at (dbg->iob.io, memspec->addr, value->bytes, memspec->size) == (int)memspec->size;
		} else {
			value->ok = true;
		}
		r_list_append (snapshot->memory, value);
	}

	if (request->include_threads && dbg->threads) {
		RDebugPid *th;
		r_list_foreach (dbg->threads, iter, th) {
			RDebugStateThread *thread = R_NEW0 (RDebugStateThread);
			if (!thread) {
				continue;
			}
			thread->pid = th->pid;
			thread->tid = th->pid;
			thread->status = th->status;
			r_list_append (snapshot->threads, thread);
		}
	}

	return snapshot;
}

R_API char *r_debug_state_snapshot_to_json(const RDebugStateSnapshot *snapshot) {
	R_RETURN_VAL_IF_FAIL (snapshot, NULL);
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}
	pj_o (pj);
	pj_kn (pj, "pc", snapshot->pc);
	pj_kn (pj, "pid", snapshot->pid);
	pj_kn (pj, "tid", snapshot->tid);
	pj_kn (pj, "reason_type", snapshot->reason_type);

	pj_ka (pj, "registers");
	RListIter *iter;
	RDebugStateRegValue *reg;
	r_list_foreach (snapshot->registers, iter, reg) {
		pj_o (pj);
		pj_ks (pj, "name", reg->name? reg->name: "");
		pj_kb (pj, "found", reg->found);
		if (reg->found) {
			pj_kn (pj, "value", reg->value);
		} else {
			pj_knull (pj, "value");
		}
		pj_end (pj);
	}
	pj_end (pj);

	pj_ka (pj, "memory");
	RDebugStateMemValue *mem;
	r_list_foreach (snapshot->memory, iter, mem) {
		char *hex = NULL;
		if (mem->ok && mem->size > 0 && mem->bytes) {
			hex = r_hex_bin2strdup (mem->bytes, mem->size);
		} else {
			hex = strdup ("");
		}
		pj_o (pj);
		pj_kn (pj, "addr", mem->addr);
		pj_kn (pj, "size", mem->size);
		pj_kb (pj, "ok", mem->ok);
		pj_ks (pj, "label", mem->label? mem->label: "");
		pj_ks (pj, "hex", hex? hex: "");
		pj_end (pj);
		free (hex);
	}
	pj_end (pj);

	pj_ka (pj, "threads");
	RDebugStateThread *thread;
	r_list_foreach (snapshot->threads, iter, thread) {
		pj_o (pj);
		pj_kn (pj, "pid", thread->pid);
		pj_kn (pj, "tid", thread->tid);
		char status[2] = { thread->status, 0 };
		pj_ks (pj, "status", status);
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	char *out = strdup (pj_string (pj));
	pj_free (pj);
	return out;
}
