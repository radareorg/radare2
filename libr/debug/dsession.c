/* radare - LGPL - Copyright 2017-2023 - rkx1209 */

#include <r_debug.h>
#include <r_util/r_json.h>

static int cmp_cnum_reg(const RDebugChangeReg *a, const RDebugChangeReg *b) {
	return (a->cnum > b->cnum) - (a->cnum < b->cnum);
}

static int cmp_cnum_mem(const RDebugChangeMem *a, const RDebugChangeMem *b) {
	return (a->cnum > b->cnum) - (a->cnum < b->cnum);
}

static int cmp_cnum_chkpt(const RDebugCheckpoint *a, const RDebugCheckpoint *b) {
	return (a->cnum > b->cnum) - (a->cnum < b->cnum);
}

R_API void r_debug_session_free(RDebugSession *session) {
	if (session) {
		RVecDebugCheckpoint_free (session->checkpoints);
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

	return session;
}

R_API bool r_debug_add_checkpoint(RDebug *dbg) {
	R_RETURN_VAL_IF_FAIL (dbg->session, false);
	size_t i;
	RDebugCheckpoint checkpoint = {0};

	// Save current registers arena iter
	r_debug_reg_sync (dbg, R_REG_TYPE_ALL, 0);
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = dbg->reg->regset[i].arena;
		RRegArena *b = r_reg_arena_new (a->size);
		if (a && a->bytes) {
			memcpy (b->bytes, a->bytes, b->size);
			checkpoint.arena[i] = b;
		}
	}

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
	RVecDebugCheckpoint_push_back (dbg->session->checkpoints, &checkpoint);

	// Add PC register change so we can check for breakpoints when continue [back]
	RRegItem *ripc = r_reg_get (dbg->reg, "PC", R_REG_TYPE_GPR);
	if (ripc) {
		ut64 data = r_reg_get_value (dbg->reg, ripc);
		r_debug_session_add_reg_change (dbg->session, ripc->arena, ripc->offset, data);
	}

	return true;
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
	ut64 index = RVecDebugCheckpoint_upper_bound (session->checkpoints, &(RDebugCheckpoint){ (int)cnum, {0}, NULL }, cmp_cnum_chkpt);
	if (index > 0 && index <= RVecDebugCheckpoint_length (session->checkpoints)) {
		checkpoint = RVecDebugCheckpoint_at (session->checkpoints, index - 1);
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
			if (hash) {
				char *hexstr = r_hex_bin2strdup (hash, R_HASH_SIZE_SHA256);
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
		// 0x<cnum>={
		//   registers:{ "<RRegisterType>":<RRegArena>, ...},
		//   snaps:{ "size":<size_t>, "a":[<RDebugSnap>]}
		// }
		PJ *j = pj_new ();
		if (!j) {
			return;
		}
		pj_o (j);

		// Serialize RRegArena to "registers"
		// { "size":<int>, "bytes":"<base64>" }
		pj_ka (j, "registers");
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			RRegArena *arena = chkpt->arena[i];
			if (arena->bytes) {
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

		pj_end (j);
		r_strf_var (key, 32, "0x%x", chkpt->cnum);
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
 *     0x<cnum>={
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

static bool deserialize_checkpoints_cb(void *user, const char *cnum, const char *v) {
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
	checkpoint.cnum = (int)sdb_atoi (cnum);

	// Extract RRegArena's from "registers"
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
	const RJson *snaps_json = r_json_get (chkpt_json, "snaps");
	if (!snaps_json || snaps_json->type != R_JSON_ARRAY) {
		goto end;
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
end:
	free (json_str);
	r_json_free (chkpt_json);
	RVecDebugCheckpoint_push_back (checkpoints, &checkpoint);
	return true;
}

static void deserialize_checkpoints(Sdb *db, RVecDebugCheckpoint *checkpoints) {
	sdb_foreach (db, deserialize_checkpoints_cb, checkpoints);
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

	session->maxcnum = sdb_num_get (db, "maxcnum", 0);

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
}

R_API bool r_debug_session_load(RDebug *dbg, const char *path) {
	Sdb *db = session_sdb_load (path);
	if (!db) {
		return false;
	}
	r_debug_session_deserialize (dbg->session, db);
	// Restore debugger to the beginning of the session
	r_debug_session_restore_reg_mem (dbg, 0);
	sdb_free (db);
	return true;
}
