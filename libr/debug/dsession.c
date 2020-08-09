/* radare - LGPL - Copyright 2017 - rkx1209 */

#include <r_debug.h>

#define CMP_CNUM_REG(x, y) ((x) >= ((RDebugChangeReg *)y)->cnum ? 1 : -1)
#define CMP_CNUM_MEM(x, y) ((x) >= ((RDebugChangeMem *)y)->cnum ? 1 : -1)
#define CMP_CNUM_CHKPT(x, y) ((x) >= ((RDebugCheckpoint *)y)->cnum ? 1 : -1)

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

// {"<addr>": {"size":<size_t>, "a":[<RDebugChangeReg>]}},
static bool save_register_cb(void *j, const ut64 k, const void *v) {
	RVector *vreg = (RVector *)v;
	RDebugChangeReg *reg;
	pj_ko (j, sdb_fmt ("0x%"PFMT64x, k));
	pj_kn (j, "size", vreg->len);
	pj_ka (j, "a");
	r_vector_foreach (vreg, reg) {
		pj_o (j);
		pj_kN (j, "cnum", reg->cnum);
		pj_kn (j, "data", reg->data);
		pj_end (j);
	}
	pj_end (j);
	pj_end (j);
	return true;
}

// reglist=<addr>,<addr>,...
static bool save_reglist(void *db, const ut64 k, const void *v) {
	sdb_array_add (db, "reglist", sdb_fmt ("0x%"PFMT64x, k), 0);
	return true;
}

static bool save_registers(Sdb *db, HtUP *registers) {
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_o (j);
	ht_up_foreach (registers, save_register_cb, j);
	pj_end (j);
	sdb_set (db, "registers", pj_string (j), 0);
	pj_free (j);

	ht_up_foreach (registers, save_reglist, db);
	return true;
}

// {"<addr>": {"size":<size_t>, "a":[<RDebugChangeMem>]}},
static bool save_memory_cb(void *j, const ut64 k, const void *v) {
	RVector *vmem = (RVector *)v;
	RDebugChangeMem *mem;
	pj_ko (j, sdb_fmt ("0x%"PFMT64x, k));
	pj_kn (j, "size", vmem->len);
	pj_ka (j, "a");
	r_vector_foreach (vmem, mem) {
		pj_o (j);
		pj_kN (j, "cnum", mem->cnum);
		pj_kn (j, "data", mem->data);
		pj_end (j);
	}
	pj_end (j);
	pj_end (j);
	return true;
}

// memorylist=<addr>,<addr>,...
static bool save_memorylist(void *db, const ut64 k, const void *v) {
	sdb_array_add (db, "memorylist", sdb_fmt ("0x%"PFMT64x, k), 0);
	return true;
}

static bool save_memory(Sdb *db, HtUP *memory) {
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_o (j);
	ht_up_foreach (memory, save_memory_cb, j);
	pj_end (j);
	sdb_set (db, "memory", pj_string (j), 0);
	pj_free (j);

	ht_up_foreach (memory, save_memorylist, db);
	return true;
}

static bool save_checkpoints(Sdb *db, RVector *checkpoints) {
	size_t i;
	RDebugCheckpoint *chkpt;
	RDebugSnap *snap;
	RListIter *iter;
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}

	pj_o (j);
	r_vector_foreach (checkpoints, chkpt) {
		// Append cnum to chkptlist sdb_array
		// chkptlist=<cnum>,<cnum>,...
		sdb_array_add (db, "chkptlist", sdb_fmt ("0x%"PFMT64x, chkpt->cnum), 0);

		pj_ko (j, sdb_fmt ("0x%"PFMT64x, chkpt->cnum));

		// Serialize RRegArena to json
		// registers: {"<RRegisterType>": <RRegArena>, ...}
		pj_ko (j, "registers");
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			iter = chkpt->reg[i];
			RRegArena *arena = iter->data;
			pj_ko (j, sdb_fmt ("%d", i));
			if (arena->bytes) {
				char *ebytes = sdb_encode ((const void *)arena->bytes, arena->size);
				pj_ks (j, "bytes", ebytes);
				free (ebytes);
				pj_kn (j, "size", arena->size);
			} else {
				pj_kn (j, "size", 0);
			}
			pj_end (j);
		}
		pj_end (j);

		// Serialize RDebugSnap to json
		// snaps: {"size":<size_t>, "a":[<RDebugSnap>]},
		pj_ko (j, "snaps");
		pj_kn (j, "size", r_list_length (chkpt->snaps));
		pj_ka (j, "a");
		r_list_foreach (chkpt->snaps, iter, snap) {
			pj_o (j);
			pj_ks (j, "name", snap->name);
			pj_kn (j, "addr", snap->addr);
			pj_kn (j, "addr_end", snap->addr_end);
			pj_kn (j, "size", snap->size);
			char *edata = sdb_encode ((const void *)snap->data, snap->size);
			pj_ks (j, "data", edata);
			free (edata);
			pj_kn (j, "perm", snap->perm);
			pj_kn (j, "user", snap->user);
			pj_kb (j, "shared", snap->shared);
			pj_end (j);
		}
		pj_end (j);
		pj_end (j);
		pj_end (j);
	}
	pj_end (j);
	sdb_set (db, "checkpoints", pj_string (j), 0);
	pj_free (j);
	return true;
}

/*
 * SDB Format:
 *
 * /
 *   maxcnum=<maxcnum>
 *
 *   reglist=<addr>,<addr>,...
 *   registers={"<addr>": {"size":<size_t>, "a":[<RDebugChangeReg>]}, ...}
 *
 *   memorylist=<addr>,<addr>,...
 *   memory={"<addr>": {"size":<size_t>, "a":[<RDebugChangeMem>]}, ...}
 *
 *   chkptlist=<cnum>,<cnum>,...
 *   checkpoints={
 *     "<cnum>": {
 *       registers: {"<RRegisterType>": <RRegArena>, ...},
 *       snaps: {"size":<size_t>, "a":[<RDebugSnap>]},
 *     },
 *     ...
 *   }
 *
 * RDebugChangeReg JSON:
 * {"cnum":<int>, "data":<ut64>}
 *
 * RDebugChangeMem JSON:
 * {"cnum":<int>, "data":<ut8>}
 *
 * RRegArena JSON:
 * {"size":<int>, "bytes":"<base64>"}
 *
 * RDebugSnap JSON:
 * {"name":<str>, "addr":<ut64>, "addr_end":<ut64>, "size":<ut64>,
 *  "data":"<base64>", "perm":<int>, "user":<int>, "shared":<bool>}
 *
 * Notes:
 * - This mostly follows r2db-style serialization and uses sdb_json as the parser.
 * - Use keys in reglist, memorylist, chkptlist to iterate over their corresponding dicts.
 */
R_API bool r_debug_session_save(RDebugSession *session, const char *file) {
	bool ret = false;
	Sdb *db = sdb_new0 ();
	if (!db) {
		return false;
	}

	sdb_num_set (db, "maxcnum", session->maxcnum, 0);
	if (!save_registers (db, session->registers)) {
		eprintf ("Error: failed to save registers to sdb\n");
		goto end;
	}
	if (!save_memory (db, session->memory)) {
		eprintf ("Error: failed to save memory to sdb\n");
		goto end;
	}
	if (!save_checkpoints (db, session->checkpoints)) {
		eprintf ("Error: failed to save checkpoints to sdb\n");
		goto end;
	}

	sdb_file (db, file);
	if (!sdb_sync (db)) {
		eprintf ("Failed to sync session to %s\n", file);
		goto end;
	}
	ret = true;
end:
	sdb_close (db);
	sdb_free (db);
	return ret;
}

#define CNUM(x) sdb_fmt ("%s.a[%u].cnum", addr, x)
#define DATA(x) sdb_fmt ("%s.a[%u].data", addr, x)

// Extract ut64 value from sdb_json str
static ut64 _json_num_get(Sdb *db, const char *k, const char *p, ut32 *cas) {
	char *vstr = sdb_json_get (db, k, p, cas);
	if (vstr) {
		ut64 v = sdb_atoi (vstr);
		free (vstr);
		return v;
	}
	return 0;
}

static bool load_memory(Sdb *db, HtUP *memory) {
	size_t i, size;
	char *addr;
	// Iterate over "memory" items
	char *a = sdb_get (db, "memorylist", 0);
	sdb_aforeach (addr, a) {
		// Insert a new vector into `memory` HtUP at `addr`
		RVector *vmem = r_vector_new (sizeof (RDebugChangeMem), NULL, NULL);
		if (!vmem) {
			eprintf ("Error: failed to allocate RVector vmem.\n");
			return false;
		}
		ht_up_insert (memory, sdb_atoi (addr), vmem);

		// Extract <RDebugChangeMem>'s into the new vector
		size = _json_num_get (db, "memory", sdb_fmt ("%s.size", addr, i), 0);
		for (i = 0; i < size; i++) {
			int cnum = _json_num_get (db, "memory", CNUM (i), 0);
			ut8 data = _json_num_get (db, "memory", DATA (i), 0);
			RDebugChangeMem mem = { cnum, data };
			r_vector_push (vmem, &mem);
		}
		sdb_aforeach_next (addr);
	}
	return true;
}

static bool load_registers(Sdb *db, HtUP *registers) {
	size_t i, size;
	char *addr;
	// Iterate over "registers" items
	char *a = sdb_get (db, "reglist", 0);
	sdb_aforeach (addr, a) {
		// Insert a new vector into `registers` HtUP at `addr`
		RVector *vreg = r_vector_new (sizeof (RDebugChangeReg), NULL, NULL);
		if (!vreg) {
			eprintf ("Error: failed to allocate RVector vreg.\n");
			return false;
		}
		ht_up_insert (registers, sdb_atoi (addr), vreg);

		// Extract <RDebugChangeReg>'s into the new vector
		size = _json_num_get (db, "registers", sdb_fmt ("%s.size", addr, i), 0);
		for (i = 0; i < size; i++) {
			int cnum = _json_num_get (db, "registers", CNUM (i), 0);
			ut64 data = _json_num_get (db, "registers", DATA (i), 0);
			RDebugChangeReg reg = { cnum, data };
			r_vector_push (vreg, &reg);
		}
		sdb_aforeach_next (addr);
	}
	return true;
}

#define SNAPATTR(ATTR) sdb_fmt ("%s.snaps.a[%u]." #ATTR, cnum, i)
#define REGATTR(ATTR) sdb_fmt ("%s.registers.%d." #ATTR, cnum, i)

static bool load_checkpoints(Sdb *db, RDebug *dbg, RVector *checkpoints) {
	size_t i, size;
	char *cnum;
	// Iterate over "checkpoints" items
	char *a = sdb_get (db, "chkptlist", 0);
	sdb_aforeach (cnum, a) {
		RDebugCheckpoint checkpoint = { 0 };
		checkpoint.cnum = (int)sdb_atoi (cnum);

		// Extract RRegArena's from "registers"
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			int size = _json_num_get (db, "checkpoints", REGATTR (size), 0);
			if (size == 0) {
				continue;
			}
			char *edata = sdb_json_get (db, "checkpoints", REGATTR (bytes), 0);
			ut8 *bytes = sdb_decode (edata, NULL);
			r_reg_set_bytes (dbg->reg, i, bytes, size);
			free (bytes);
			free (edata);
			checkpoint.reg[i] = r_list_tail (dbg->reg->regset[i].pool);
		}
		r_reg_arena_push (dbg->reg);

		// Extract RDebugSnap's from "snaps"
		checkpoint.snaps = r_list_newf ((RListFree)r_debug_snap_free);
		size = sdb_json_num_get (db, "checkpoints", sdb_fmt ("%s.snaps.size", cnum, i), 0);
		for (i = 0; i < size; i++) {
			RDebugSnap *snap = R_NEW0 (RDebugSnap);
			if (!snap) {
				eprintf ("Error: failed to allocate RDebugSnap snap");
				return false;
			}

			snap->name = sdb_json_get (db, "checkpoints", SNAPATTR (name), 0);
			snap->size = _json_num_get (db, "checkpoints", SNAPATTR (size), 0);
			snap->addr = _json_num_get (db, "checkpoints", SNAPATTR (addr), 0);
			snap->addr_end = _json_num_get (db, "checkpoints", SNAPATTR (addr_end), 0);
			snap->perm = _json_num_get (db, "checkpoints", SNAPATTR (perm), 0);
			snap->user = _json_num_get (db, "checkpoints", SNAPATTR (user), 0);
			char *sharedstr = sdb_json_get (db, "checkpoints", SNAPATTR (shared), 0);
			snap->shared = (strlen (sharedstr) == 4 && !strncmp (sharedstr, "true", 4));
			free (sharedstr);

			char *edata = sdb_json_get (db, "checkpoints", SNAPATTR (data), 0);
			snap->data = sdb_decode (edata, NULL);
			free (edata);
			r_list_append (checkpoint.snaps, snap);
		}

		r_vector_push (checkpoints, &checkpoint);
		sdb_aforeach_next (cnum);
	}
	return true;
}

R_API bool r_debug_session_load(RDebug *dbg, const char *file) {
	bool ret = false;
	Sdb *db = sdb_new (NULL, file, 0);
	if (!db) {
		return false;
	}

	dbg->session->maxcnum = sdb_num_get (db, "maxcnum", 0);
	if (!load_memory (db, dbg->session->memory)) {
		eprintf ("Error: failed to load memory from %s sdb\n", file);
		goto end;
	}
	if (!load_registers (db, dbg->session->registers)) {
		eprintf ("Error: failed to load registers from %s sdb\n", file);
		goto end;
	}
	if (!load_checkpoints (db, dbg, dbg->session->checkpoints)) {
		eprintf ("Error: failed to load checkpoints from %s sdb\n", file);
		goto end;
	}

	// Restore debugger to cnum 0
	r_debug_session_restore_reg_mem (dbg, 0);
	ret = true;
end:
	sdb_close (db);
	sdb_free (db);
	return ret;
}
