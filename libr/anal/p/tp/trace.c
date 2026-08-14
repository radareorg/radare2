/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type propagation: esil trace + voyeur recording, and the queries over a recorded trace */

#include "tp.h"

static void tt_regwrite_kv_free(HtPPKv *kv) {
	if (kv) {
		free (kv->key);
		VecWriteIdx_free (kv->value);
	}
}

static void update_trace_db_op(TypeTraceDB *db) {
	const ut32 trace_op_len = VecTraceOp_length (&db->ops);
	if (!trace_op_len) {
		return;
	}
	TypeTraceOp *last = VecTraceOp_at (&db->ops, trace_op_len - 1);
	if (!last) {
		return;
	}
	const ut32 vec_idx = VecAccess_length (&db->accesses);
	if (!vec_idx) {
		R_LOG_ERROR ("Invalid access database");
		return;
	}
	last->end = vec_idx; //  - 1;
}

void type_trace_voyeur_reg_read(void *user, const char *name, ut64 val) {
	R_RETURN_IF_FAIL (user && name);
	TypeTraceDB *db = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&db->accesses);
	access->reg.name = strdup (name);
	access->reg.value = val;
	access->is_reg = true;
	access->is_write = false;
	update_trace_db_op (db);
}

void type_trace_voyeur_reg_write(void *user, const char *name, ut64 old, ut64 val) {
	R_RETURN_IF_FAIL (user && name);
	TypeTrace *trace = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&trace->db.accesses);
	access->is_reg = true;
	access->reg.name = strdup (name);
	access->reg.value = val;
	access->is_write = true;
	if (trace->enable_rollback) {
		r_strbuf_prependf (&trace->rollback, "0x%" PFMT64x ",%s,:=,", old, name);
	}
	update_trace_db_op (&trace->db);
}

void type_trace_voyeur_mem_read(void *user, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (user && buf && (len > 0));
	TypeTraceDB *db = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&db->accesses);
	access->is_reg = false;
	access->mem.addr = addr;
	access->mem.size = len;
	access->is_write = false;
	update_trace_db_op (db);
}

void type_trace_voyeur_mem_write(void *user, ut64 addr, const ut8 *old, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (user && buf && (len > 0));
	TypeTrace *trace = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&trace->db.accesses);
	access->is_reg = false;
	access->mem.addr = addr;
	access->mem.size = len;
	const bool pow2 = len <= 8 && !(len & (len - 1));
	access->mem.value = pow2? r_read_ble (buf, trace->be, len * 8): 0;
	access->is_write = true;

	if (trace->enable_rollback && old) {
		int i;
		for (i = len - 1; i >= 0; i--) {
			r_strbuf_prependf (&trace->rollback,
				"0x%02x,0x%" PFMT64x ",=[1],", old[i], addr + i);
		}
	}
	update_trace_db_op (&trace->db);
}

static void trace_db_reset_index(TypeTraceDB *db) {
	ht_pp_free (db->regwrites);
	db->regwrites = ht_pp_new (NULL, tt_regwrite_kv_free, NULL);
	db->indexed_ops = 0;
}

static void trace_db_init(TypeTraceDB *db) {
	VecTraceOp_init (&db->ops);
	VecAccess_init (&db->accesses);
	db->loop_counts = ht_uu_new0 ();
	db->regwrites = NULL;
	trace_db_reset_index (db);
}

static void trace_db_fini(TypeTraceDB *db) {
	if (db) {
		VecTraceOp_fini (&db->ops);
		VecAccess_fini (&db->accesses);
		ht_uu_free (db->loop_counts);
		db->loop_counts = NULL;
		ht_pp_free (db->regwrites);
		db->regwrites = NULL;
		db->indexed_ops = 0;
	}
}

bool type_trace_init(TypeTrace *trace, REsil *esil, RReg *reg) {
	R_RETURN_VAL_IF_FAIL (trace && esil && reg, false);
	*trace = (const TypeTrace){ 0 };
	trace_db_init (&trace->db);
	r_strbuf_init (&trace->rollback);
	trace->enable_rollback = false; // Disabled by default for performance
	trace->voy[TP_VOYEUR_REG_READ] = r_esil_add_voyeur (esil, &trace->db,
		type_trace_voyeur_reg_read, R_ESIL_VOYEUR_REG_READ);
	if (R_UNLIKELY (trace->voy[TP_VOYEUR_REG_READ] == R_ESIL_VOYEUR_ERR)) {
		goto fail_regr_voy;
	}
	trace->voy[TP_VOYEUR_REG_WRITE] = r_esil_add_voyeur (esil, trace,
		type_trace_voyeur_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	if (R_UNLIKELY (trace->voy[TP_VOYEUR_REG_WRITE] == R_ESIL_VOYEUR_ERR)) {
		goto fail_regw_voy;
	}
	trace->voy[TP_VOYEUR_MEM_READ] = r_esil_add_voyeur (esil, &trace->db,
		type_trace_voyeur_mem_read, R_ESIL_VOYEUR_MEM_READ);
	if (R_UNLIKELY (trace->voy[TP_VOYEUR_MEM_READ] == R_ESIL_VOYEUR_ERR)) {
		goto fail_memr_voy;
	}
	trace->voy[TP_VOYEUR_MEM_WRITE] = r_esil_add_voyeur (esil, trace,
		type_trace_voyeur_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
	if (R_UNLIKELY (trace->voy[TP_VOYEUR_MEM_WRITE] == R_ESIL_VOYEUR_ERR)) {
		goto fail_memw_voy;
	}
	trace->reg = reg;
	return true;
fail_memw_voy:
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_MEM_READ]);
fail_memr_voy:
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_REG_WRITE]);
fail_regw_voy:
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_REG_READ]);
fail_regr_voy:
	trace_db_fini (&trace->db);
	return false;
}

ut64 type_trace_loopcount(TypeTrace *trace, ut64 addr) {
	bool found = false;
	const ut64 count = ht_uu_find (trace->db.loop_counts, addr, &found);
	return found? count: 0;
}

void type_trace_loopcount_increment(TypeTrace *trace, ut64 addr) {
	const ut64 count = type_trace_loopcount (trace, addr);
	ht_uu_update (trace->db.loop_counts, addr, count + 1);
}

// Execute rollback ESIL to restore state, then clear buffer
void type_trace_rollback(TypeTrace *trace, REsil *esil) {
	R_RETURN_IF_FAIL (trace && esil);
	if (r_strbuf_length (&trace->rollback) > 0) {
		// replaying appends restore writes to an op the index may already hold, so drop it
		trace_db_reset_index (&trace->db);
		const char *expr = r_strbuf_get (&trace->rollback);
		if (expr && *expr) {
			// Disable rollback recording during rollback execution
			// to prevent voyeur callbacks from adding to the buffer
			bool was_enabled = trace->enable_rollback;
			trace->enable_rollback = false;
			r_esil_parse (esil, expr);
			r_esil_stack_free (esil);
			trace->enable_rollback = was_enabled;
		}
		r_strbuf_fini (&trace->rollback);
		r_strbuf_init (&trace->rollback);
	}
}

// Clear rollback buffer without executing
void type_trace_rollback_clear(TypeTrace *trace) {
	R_RETURN_IF_FAIL (trace);
	r_strbuf_fini (&trace->rollback);
	r_strbuf_init (&trace->rollback);
}

void type_trace_fini(TypeTrace *trace, REsil *esil) {
	R_RETURN_IF_FAIL (trace && esil);
	trace_db_fini (&trace->db);
	r_strbuf_fini (&trace->rollback);
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_MEM_WRITE]);
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_MEM_READ]);
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_REG_WRITE]);
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_REG_READ]);
	r_reg_free (trace->reg);
	trace->reg = NULL;
	*trace = (const TypeTrace){ 0 };
}

bool type_trace_op(TypeTrace *trace, REsil *esil, RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (trace && esil && op, false);
	const char *expr = r_strbuf_get (&op->esil);
	if (R_STR_ISEMPTY (expr)) {
		// empty expressions are nops or unimplemented, we can move forward here
		return true;
	}

	TypeTraceOp *to = VecTraceOp_emplace_back (&trace->db.ops);
	ut32 vec_idx = VecAccess_length (&trace->db.accesses);
	to->start = vec_idx;
	to->end = vec_idx;
	to->addr = op->addr;
	const bool ret = r_esil_parse (esil, expr);
	r_esil_stack_free (esil);
	trace->idx++;
	return ret;
}

// TODO: type_trace_restore() for state rollback during backtracking
// was removed as dead code - can be re-implemented if needed for
// more accurate cross-basic-block type propagation

/// BEGIN /////////////////// esil trace helpers ///////////////////////

int etrace_index(TypeTrace *etrace) {
	int len = VecTraceOp_length (&etrace->db.ops);
	etrace->cur_idx = len; //  > 0? len -1: 0;
	return etrace->cur_idx; // VecTraceOp_length (&etrace->db.ops);
}

ut64 etrace_addrof(TypeTrace *etrace, ut32 idx) {
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	return op? op->addr: 0;
}

const TypeTraceAccess *etrace_find_access(TypeTrace *etrace, ut32 idx, AccessPredicate pred, void *user) {
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	if (!op || op->start == op->end) {
		return NULL;
	}
	const TypeTraceAccess *start = VecAccess_at (&etrace->db.accesses, op->start);
	const TypeTraceAccess *end = VecAccess_at (&etrace->db.accesses, op->end - 1);
	if (!start || !end || start > end) {
		return NULL;
	}
	while (start <= end) {
		if (pred (start, user)) {
			return start;
		}
		start++;
	}
	return NULL;
}

// folds the trace ops appended since the last call into the per-register write index
static void trace_db_index_regwrites(TypeTraceDB *db) {
	const ut32 nops = VecTraceOp_length (&db->ops);
	ut32 i;
	for (i = db->indexed_ops; i < nops; i++) {
		const TypeTraceOp *op = VecTraceOp_at (&db->ops, i);
		ut32 a;
		for (a = op->start; a < op->end; a++) {
			const TypeTraceAccess *access = VecAccess_at (&db->accesses, a);
			if (!access || !access->is_reg || !access->is_write || !access->reg.name) {
				continue;
			}
			VecWriteIdx *idxs = ht_pp_find (db->regwrites, access->reg.name, NULL);
			if (!idxs) {
				idxs = VecWriteIdx_new ();
				ht_pp_insert (db->regwrites, access->reg.name, idxs);
			}
			const ut32 *last = VecWriteIdx_last (idxs);
			// one op can write the same register twice, keep the list strictly ascending
			if (!last || *last != i) {
				VecWriteIdx_push_back (idxs, &i);
			}
		}
	}
	db->indexed_ops = nops;
}

static int writeidx_cmp(ut32 const *a, ut32 const *b) {
	return (*a > *b) - (*a < *b);
}

// most recent trace index at or before j whose op wrote rname, or -1
int etrace_last_regwrite(TypeTrace *etrace, const char *rname, int j) {
	if (!rname || j < 0) {
		return -1;
	}
	trace_db_index_regwrites (&etrace->db);
	VecWriteIdx *idxs = ht_pp_find (etrace->db.regwrites, rname, NULL);
	if (!idxs) {
		return -1;
	}
	ut32 needle = j;
	const size_t pos = VecWriteIdx_upper_bound (idxs, &needle, writeidx_cmp);
	return pos? (int)*VecWriteIdx_at (idxs, pos - 1): -1;
}

static bool etrace_is_memwrite(const TypeTraceAccess *access, void *user) {
	(void)user;
	return !access->is_reg && access->is_write;
}

bool etrace_is_memread(const TypeTraceAccess *access, void *user) {
	(void)user;
	return !access->is_reg && !access->is_write;
}

static bool etrace_is_regread(const TypeTraceAccess *access, void *user) {
	const char *rname = (const char *)user;
	return access->is_reg && !access->is_write && !strcmp (rname, access->reg.name);
}

static bool etrace_is_regwrite(const TypeTraceAccess *access, void *user) {
	(void)user;
	return access->is_reg && access->is_write;
}

bool etrace_is_regwrite_name(const TypeTraceAccess *access, void *user) {
	const char *rname = (const char *)user;
	return access->is_reg && access->is_write && !strcmp (rname, access->reg.name);
}

ut64 etrace_memwrite_addr(TypeTrace *etrace, ut32 idx) {
	const TypeTraceAccess *access = etrace_find_access (etrace, idx, etrace_is_memwrite, NULL);
	if (access) {
		return access->mem.addr;
	}
	return 0;
}

bool etrace_have_memread(TypeTrace *etrace, ut32 idx) {
	return etrace_find_access (etrace, idx, etrace_is_memread, NULL) != NULL;
}

ut64 etrace_regread_value(TypeTrace *etrace, ut32 idx, const char *rname) {
	const TypeTraceAccess *access = etrace_find_access (etrace, idx, etrace_is_regread, (void *)rname);
	if (access) {
		return access->reg.value;
	}
	return 0;
}

const char *etrace_regwrite(TypeTrace *etrace, ut32 idx) {
	const TypeTraceAccess *access = etrace_find_access (etrace, idx, etrace_is_regwrite, NULL);
	if (access) {
		return access->reg.name;
	}
	return NULL;
}

/// END ///////////////////// esil trace helpers ///////////////////////

bool etrace_regwrite_contains(TypeTrace *etrace, ut32 idx, const char *rname) {
	if (!etrace || !rname) {
		return false;
	}
	return etrace_find_access (etrace, idx, etrace_is_regwrite_name, (void *)rname) != NULL;
}

bool etrace_memread_first_addr(TypeTrace *etrace, ut32 idx, ut64 *addr) {
	const TypeTraceAccess *access = etrace_find_access (etrace, idx, etrace_is_memread, NULL);
	if (!access) {
		return false;
	}
	if (addr) {
		*addr = access->mem.addr;
	}
	return true;
}

// any write in the trace overlapping the field at [addr, addr + width)
bool etrace_memwrite_at(TypeTrace *tt, ut64 addr, int width) {
	const ut64 w = R_MAX (width, 1);
	const TypeTraceAccess *a;
	R_VEC_FOREACH (&tt->db.accesses, a) {
		if (!a->is_reg && a->is_write && a->mem.addr < addr + w && addr < a->mem.addr + a->mem.size) {
			return true;
		}
	}
	return false;
}
