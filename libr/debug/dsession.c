/* radare - LGPL - Copyright 2017 - rkx1209 */

#include <r_debug.h>
#include <r_util/r_json.h>

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
	size_t i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_reg_arena_free (checkpoint->arena[i]);
	}
	r_list_free (checkpoint->snaps);
}

static void htup_vector_free(HtUPKv *kv) {
	r_vector_free (kv->value);
}

R_API RDebugSession *r_debug_session_new(void) {
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
		RRegArena *a = dbg->session->cur_chkpt->arena[i];
		RRegArena *b = dbg->reg->regset[i].arena;
		if (a && b && a->bytes && b->bytes) {
			memcpy (b->bytes, a->bytes, a->size);
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

/* Save and Load Session */

// 0x<addr>=[<RDebugChangeReg>]
static bool serialize_register_cb(void *db, const ut64 k, const void *v) {
	RDebugChangeReg *reg;
	RVector *vreg = (RVector *)v;
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_a (j);

	r_vector_foreach (vreg, reg) {
		pj_o (j);
		pj_kN (j, "cnum", reg->cnum);
		pj_kn (j, "data", reg->data);
		pj_end (j);
	}

	pj_end (j);
	sdb_set (db, sdb_fmt ("0x%"PFMT64x, k), pj_string (j), 0);
	pj_free (j);
	return true;
}

static void serialize_registers(Sdb *db, HtUP *registers) {
	ht_up_foreach (registers, serialize_register_cb, db);
}

// 0x<addr>={"size":<size_t>, "a":[<RDebugChangeMem>]}},
static bool serialize_memory_cb(void *db, const ut64 k, const void *v) {
	RDebugChangeMem *mem;
	RVector *vmem = (RVector *)v;
	PJ *j = pj_new ();
	if (!j) {
		return false;
	}
	pj_a (j);

	r_vector_foreach (vmem, mem) {
		pj_o (j);
		pj_kN (j, "cnum", mem->cnum);
		pj_kn (j, "data", mem->data);
		pj_end (j);
	}

	pj_end (j);
	sdb_set (db, sdb_fmt ("0x%"PFMT64x, k), pj_string (j), 0);
	pj_free (j);
	return true;
}

static void serialize_memory(Sdb *db, HtUP *memory) {
	ht_up_foreach (memory, serialize_memory_cb, db);
}

static void serialize_checkpoints(Sdb *db, RVector *checkpoints) {
	size_t i;
	RDebugCheckpoint *chkpt;
	RDebugSnap *snap;
	RListIter *iter;

	r_vector_foreach (checkpoints, chkpt) {
		// 0x<cnum>={
		//   registers:{"<RRegisterType>":<RRegArena>, ...},
		//   snaps:{"size":<size_t>, "a":[<RDebugSnap>]}
		// }
		PJ *j = pj_new ();
		if (!j) {
			return;
		}
		pj_o (j);

		// Serialize RRegArena to "registers"
		// {"size":<int>, "bytes":"<base64>"}
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
		// {"name":<str>, "addr":<ut64>, "addr_end":<ut64>, "size":<ut64>,
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
		sdb_set (db, sdb_fmt ("0x%x", chkpt->cnum), pj_string (j), 0);
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
 *     0x<addr>={"size":<size_t>, "a":[<RDebugChangeReg>]}
 *
 *   /memory
 *     0x<addr>={"size":<size_t>, "a":[<RDebugChangeMem>]}
 *
 *   /checkpoints
 *     0x<cnum>={
 *       registers:{"<RRegisterType>":<RRegArena>, ...},
 *       snaps:{"size":<size_t>, "a":[<RDebugSnap>]}
 *     }
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
		eprintf ("Error: %s is not a directory\n", path);
		return false;
	}

	filename = r_str_newf ("%s%ssession.sdb", path, R_SYS_DIR);
	sdb_file (db, filename);
	if (!sdb_sync (db)) {
		eprintf ("Failed to sync session to %s\n", filename);
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
			eprintf ("Failed to sync %s to %s\n", ns->name, filename);
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
	RVector *vmem = r_vector_new (sizeof (RDebugChangeMem), NULL, NULL);
	if (!vmem) {
		eprintf ("Error: failed to allocate RVector vmem.\n");
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
		r_vector_push (vmem, &mem);
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
	RVector *vreg = r_vector_new (sizeof (RDebugChangeReg), NULL, NULL);
	if (!vreg) {
		eprintf ("Error: failed to allocate RVector vreg.\n");
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
		r_vector_push (vreg, &reg);
	}

	r_json_free (reg_json);
	free (json_str);
	return true;
}

static void deserialize_registers(Sdb *db, HtUP *registers) {
	sdb_foreach (db, deserialize_registers_cb, registers);
}

#define SNAPATTR(ATTR) sdb_fmt ("snaps.a[%u]." ATTR, i)
#define REGATTR(ATTR) sdb_fmt ("registers.%d." ATTR, i)

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

	RVector *checkpoints = user;
	RDebugCheckpoint checkpoint = { 0 };
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
		if (arena < R_REG_TYPE_GPR || arena > R_REG_TYPE_SEG) {
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
			eprintf ("Error: failed to allocate RDebugSnap snap");
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
	r_vector_push (checkpoints, &checkpoint);
	return true;
}

static void deserialize_checkpoints(Sdb *db, RVector *checkpoints) {
	sdb_foreach (db, deserialize_checkpoints_cb, checkpoints);
}

static bool session_sdb_load_ns(Sdb *db, const char *nspath, const char *filename) {
	Sdb *tmpdb = sdb_new0 ();
	if (sdb_open (tmpdb, filename) == -1) {
		eprintf ("Error: failed to load %s into sdb\n", filename);
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
			eprintf ("Error: missing " ns " namespace\n"); \
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
