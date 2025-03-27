#include <r_arch.h>
#include <r_anal.h>
#include <r_esil.h>
#include <r_reg.h>

static void update_trace_db_op(RAnalEsilTraceDB *db) {
	const ut32 trace_op_len = RVecAnalEsilTraceOp_length (&db->ops);
	if (!trace_op_len) {
		return;
	}
	RAnalEsilTraceOp *last = RVecAnalEsilTraceOp_at (&db->ops, trace_op_len - 1);
	if (!last) {
		return;
	}
	const ut32 vec_idx = RVecAnalEsilAccess_length (&db->accesses);
	if (!vec_idx) {
		R_LOG_ERROR ("Invalid access database");
		return;
	}
	last->end = vec_idx; //  - 1;
}

static void anal_esil_trace_voyeur_reg_read (void *user, const char *name, ut64 val) {
	R_RETURN_IF_FAIL (user && name);
	char *name_dup = strdup (name);
	if (!name_dup) {
		R_LOG_ERROR ("Failed to allocate(strdup) memory for storing access");
		return;
	}
	RAnalEsilTraceDB *db = user;
	RAnalEsilTraceAccess *access = RVecAnalEsilAccess_emplace_back (&db->accesses);
	if (!access) {
		free (name_dup);
		R_LOG_ERROR ("Failed to allocate memory for storing access");
		return;
	}
	access->reg.name = name_dup;
	access->reg.value = val;
	access->is_reg = true;
	access->is_write = false;
	update_trace_db_op (db);
}

static void add_reg_change(RAnalEsilTrace *trace, RRegItem *ri, ut64 data, ut64 odata) {
	R_RETURN_IF_FAIL (trace && ri);
	ut64 addr = ri->offset | (ri->arena << 16);
	RVector *vreg = ht_up_find (trace->registers, addr, NULL);
	if (R_UNLIKELY (!vreg)) {
		vreg = r_vector_new (sizeof (RAnalEsilTraceRegChange), NULL, NULL);
		if (R_UNLIKELY (!vreg)) {
			R_LOG_ERROR ("creating a register vector");
			return;
		}
		ht_up_insert (trace->registers, addr, vreg);
	}
	RAnalEsilTraceRegChange reg = {trace->cur_idx, trace->cc++,
		strdup (ri->name), data, odata};
	r_vector_push (vreg, &reg);
}

static void anal_esil_trace_voyeur_reg_write (void *user, const char *name, ut64 old, ut64 val) {
	R_RETURN_IF_FAIL (user && name);
	RAnalEsilTrace *trace = user;
	RRegItem *ri = r_reg_get (trace->reg, name, -1);
	if (!ri) {
		return;
	}
	char *name_dup = strdup (name);
	if (!name_dup) {
		R_LOG_ERROR ("Failed to allocate(strdup) memory for storing access");
		goto fail_name_dup;
	}
	RAnalEsilTraceAccess *access = RVecAnalEsilAccess_emplace_back (&trace->db.accesses);
	if (!access) {
		R_LOG_ERROR ("Failed to allocate memory for storing access");
		goto fail_emplace_back;
	}
	access->is_reg = true;
	access->reg.name = name_dup;
	access->reg.value = val;
	access->is_write = true;

	add_reg_change (trace, ri, val, old);
	update_trace_db_op (&trace->db);
	r_unref (ri);
	return;
fail_emplace_back:
	free (name_dup);
fail_name_dup:
	r_unref (ri);
}

static void anal_esil_trace_voyeur_mem_read (void *user, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (user && buf && (len > 0));
	char *hexbuf = r_hex_bin2strdup (buf, len);	//why?
	if (!hexbuf) {
		R_LOG_ERROR ("Failed to allocate(r_hex_bin2strdup) memory for storing access");
		return;
	}
	RAnalEsilTraceDB *db = user;
	RAnalEsilTraceAccess *access = RVecAnalEsilAccess_emplace_back (&db->accesses);
	if (!access) {
		free (hexbuf);
		R_LOG_ERROR ("Failed to allocate memory for storing access");
		return;
	}
	access->is_reg = false;
	access->mem.data = hexbuf;
	access->mem.addr = addr;
	access->is_write = false;
	update_trace_db_op (db);
}

static void anal_esil_trace_voyeur_mem_write (void *user, ut64 addr, const ut8 *old, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (user && buf && (len > 0));
	char *hexbuf = r_hex_bin2strdup (buf, len);	//why?
	if (!hexbuf) {
		R_LOG_ERROR ("Failed to allocate(r_hex_bin2strdup) memory for storing access");
		return;
	}
	RAnalEsilTrace *trace = user;
	RAnalEsilTraceAccess *access = RVecAnalEsilAccess_emplace_back (&trace->db.accesses);
	if (!access) {
		free (hexbuf);
		R_LOG_ERROR ("Failed to allocate memory for storing access");
		return;
	}
	access->is_reg = false;
	access->mem.data = hexbuf;
	access->mem.addr = addr;
	access->is_write = true;
	ut32 i;
	for (i = 0; i < len; i++) {
		//adding each byte one by one is utterly stupid, typical gsoc crap
		//ideally this would use a tree structure, that splits nodes when necessary
		RVector *vmem = ht_up_find (trace->memory, addr, NULL);
		if (!vmem) {
			vmem = r_vector_new (sizeof (RAnalEsilTraceMemChange), NULL, NULL);
			if (!vmem) {
				R_LOG_ERROR ("creating a memory vector");
				break;
			}
			ht_up_insert (trace->memory, addr, vmem);
		}
		RAnalEsilTraceMemChange mem = {trace->idx, trace->cc++, addr, buf[i], old[i]};
		r_vector_push (vmem, &mem);
	}
	update_trace_db_op (&trace->db);
}

static void htup_vector_free(HtUPKv *kv) {
	if (kv) {
		r_vector_free (kv->value);
	}
}

static void trace_db_init(RAnalEsilTraceDB *db) {
	RVecAnalEsilTraceOp_init (&db->ops);
	RVecAnalEsilAccess_init (&db->accesses);
	db->loop_counts = ht_uu_new0 ();
}

R_API bool r_anal_esil_trace_init(RAnalEsilTrace *trace, REsil *esil, RReg *reg,
	ut64 stack_addr, ut64 stack_size) {
	R_RETURN_VAL_IF_FAIL (trace && esil && reg && stack_size, false);
	*trace = (const RAnalEsilTrace){0};
	trace_db_init (&trace->db);
	trace->registers = ht_up_new (NULL, htup_vector_free, NULL);
	if (!trace->registers) {
		goto fail_registers_ht;
	}
	trace->memory = ht_up_new (NULL, htup_vector_free, NULL);
	if (!trace->memory) {
		goto fail_memory_ht;
	}
	trace->stack_data = malloc (stack_size);
	if (!trace->stack_data) {
		goto fail_malloc;
	}
	if (!r_esil_mem_read_silent (esil, stack_addr, trace->stack_data, stack_size)) {
		goto fail_read;
	}
	ut32 i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = reg->regset[i].arena;
		RRegArena *b = r_reg_arena_new (a->size);
		if (!b) {
			goto fail_regs_copy;
		}
		if (b->bytes && a->bytes && b->size > 0) {
			memcpy (b->bytes, a->bytes, b->size);
		}
		trace->arena[i] = b;
	}
	trace->reg = reg;
	trace->stack_addr = stack_addr;
	trace->stack_size = stack_size;
	return true;
fail_regs_copy:
	while (i) {
		i--;
		r_reg_arena_free (trace->arena[i]);
	}
fail_read:
	R_FREE (trace->stack_data);
fail_malloc:
	ht_up_free (trace->memory);
	trace->memory = NULL;
fail_memory_ht:
	ht_up_free (trace->registers);
	trace->registers = NULL;
fail_registers_ht:
	return false;
}

R_API void r_anal_esil_trace_fini(RAnalEsilTrace *trace) {
	R_RETURN_IF_FAIL (trace);
	RVecAnalEsilTraceOp_fini (&trace->db.ops);
	RVecAnalEsilAccess_fini (&trace->db.accesses);
	ht_uu_free (trace->db.loop_counts);
	ht_up_free (trace->registers);
	ht_up_free (trace->memory);
	free (trace->stack_data);
	ut32 i;
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		r_reg_arena_free (trace->arena[i]);
	}
	trace[0] = (const RAnalEsilTrace){0};
}

R_API void r_anal_esil_trace_op(RAnalEsilTrace *trace, REsil *esil, RAnalOp *op) {
	R_RETURN_IF_FAIL (trace && esil && op);
	const char *expr = r_strbuf_get (&op->esil);
	if (R_UNLIKELY (!expr || !strlen (expr))) {
		R_LOG_WARN ("expr is empty or null");
		return;
	}
	trace->cc = 0;
	ut32 voy[4];
	voy[R_ESIL_VOYEUR_REG_READ] = r_esil_add_voyeur (esil, &trace->db,
		anal_esil_trace_voyeur_reg_read, R_ESIL_VOYEUR_REG_READ);
	if (R_UNLIKELY (voy[R_ESIL_VOYEUR_REG_READ] == R_ESIL_VOYEUR_ERR)) {
		return;
	}
	voy[R_ESIL_VOYEUR_REG_WRITE] = r_esil_add_voyeur (esil, trace,
		anal_esil_trace_voyeur_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	if (R_UNLIKELY (voy[R_ESIL_VOYEUR_REG_WRITE] == R_ESIL_VOYEUR_ERR)) {
		goto fail_regw_voy;
	}
	voy[R_ESIL_VOYEUR_MEM_READ] = r_esil_add_voyeur (esil, &trace->db,
		anal_esil_trace_voyeur_mem_read, R_ESIL_VOYEUR_MEM_READ);
	if (R_UNLIKELY (voy[R_ESIL_VOYEUR_MEM_READ] == R_ESIL_VOYEUR_ERR)) {
		goto fail_memr_voy;
	}
	voy[R_ESIL_VOYEUR_MEM_WRITE] = r_esil_add_voyeur (esil, trace,
		anal_esil_trace_voyeur_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
	if (R_UNLIKELY (voy[R_ESIL_VOYEUR_MEM_WRITE] == R_ESIL_VOYEUR_ERR)) {
		goto fail_memw_voy;
	}
	
	RRegItem *ri = r_reg_get (esil->anal->reg, "PC", -1);
	if (ri) {
		const bool suc = r_esil_reg_write (esil, ri->name, op->addr);
		r_unref (ri);
		if (!suc) {
			goto fail_set_pc;
		}
	}

	RAnalEsilTraceOp *to = RVecAnalEsilTraceOp_emplace_back (&trace->db.ops);
	if (R_LIKELY (to)) {
		ut32 vec_idx = RVecAnalEsilAccess_length (&trace->db.accesses);
		to->start = vec_idx;
		to->end = vec_idx;
		to->addr = op->addr;
	} else {
		R_LOG_WARN ("Couldn't allocate(emplace_back) trace op");
		//anything to do here?
	}
	r_esil_parse (esil, expr);
	r_esil_stack_free (esil);
	trace->idx++;
	trace->end_idx++;	// should be vector length?
fail_set_pc:
	r_esil_del_voyeur (esil, voy[R_ESIL_VOYEUR_MEM_WRITE]);
fail_memw_voy:
	r_esil_del_voyeur (esil, voy[R_ESIL_VOYEUR_MEM_READ]);
fail_memr_voy:
	r_esil_del_voyeur (esil, voy[R_ESIL_VOYEUR_REG_WRITE]);
fail_regw_voy:
	r_esil_del_voyeur (esil, voy[R_ESIL_VOYEUR_REG_READ]);
}

static bool count_changes_above_idx_cb (void *user, const ut64 key, const void *val) {
	RVector *vec = val;
	if (R_UNLIKELY (r_vector_empty (vec))) {
		return true;
	}
	ut64 *v = user;
	const int idx = v[0] >> 32;
	ut32 count = v[0] & UT32_MAX;
	v[0] &= UT64_MAX ^ UT64_MAX;
	ut32 i = r_vector_length (vec) - 1;
	RAnalEsilTraceMemChange *change = r_vector_index_ptr (vec, i);
	//idx is guaranteed to be at struct offset 0 for MemChange and RegChange, so this hack is fine
	while (change->idx >= idx) {
		count++;
		if (!i) {
			break;
		}
		i--;
		change = r_vector_index_ptr (vec, i);
	}
	v[0] |= count;
	return true;
}

typedef struct {
	int idx;
	union {
		RAnalEsilTraceRegChange *rc_ptr;
		RAnalEsilTraceMemChange *mc_ptr;
		void *data;
	};
} ChangeCollector;

static bool collect_reg_changes_cb (void *user, const ut64 key, const void *val) {
	RVector *vec = val;
	if (R_UNLIKELY (r_vector_empty (vec))) {
		return true;
	}
	ChangeCollector *cc = user;
	ut32 i = r_vector_length (vec) - 1;
	RAnalEsilTraceRegChange *rc = r_vector_index_ptr (vec, i);
	while (rc->idx >= cc->idx) {
		r_vector_remove_at (vec, i, cc->rc_ptr);
		cc->rc_ptr++;
		if (!i) {
			return true;
		}
		i--;
	}
	return true;
}

static bool collect_mem_changes_cb (void *user, const ut64 key, const void *val) {
	RVector *vec = val;
	if (R_UNLIKELY (r_vector_empty (vec))) {
		return true;
	}
	ChangeCollector *cc = user;
	ut32 i = r_vector_length (vec) - 1;
	RAnalEsilTraceMemChange *rc = r_vector_index_ptr (vec, i);
	while (rc->idx >= cc->idx) {
		r_vector_remove_at (vec, i, cc->mc_ptr);
		cc->mc_ptr++;
		if (!i) {
			return true;
		}
		i--;
	}
	return true;
}

static int sort_reg_changes_cb (const void *v0, const void *v1) {
	const RAnalEsilTraceRegChange *a = v0;
	const RAnalEsilTraceRegChange *b = v1;
	if (a->idx == b->idx) {
		return (int)b->cc - (int)a->cc;
	}
	return b->idx - a->idx;
}

static int sort_mem_changes_cb (const void *v0, const void *v1) {
	const RAnalEsilTraceMemChange *a = v0;
	const RAnalEsilTraceMemChange *b = v1;
	if (a->idx == b->idx) {
		return (int)b->cc - (int)a->cc;
	}
	return b->idx - a->idx;
}

R_API void r_anal_esil_trace_restore(RAnalEsilTrace *trace, REsil *esil, int idx) {
	R_RETURN_IF_FAIL (trace && esil && (idx < trace->idx));
	ut64 v = ((ut64)idx) << 32;
	ht_up_foreach (trace->registers, count_changes_above_idx_cb, &v);
	ut32 c_num = v & UT32_MAX;
	void *data = NULL;
	if (c_num) {
		data = R_NEWS (RAnalEsilTraceRegChange, c_num);
		ChangeCollector collector = {.idx = idx, .data = data};
		ht_up_foreach (trace->registers, collect_reg_changes_cb, &collector);
		//sort collected reg changes so that the newest come first
		qsort (data, c_num, sizeof (RAnalEsilTraceRegChange), sort_reg_changes_cb);
		collector.data = data;
		ut32 i = 0;
		for (; i < c_num; i++) {
			r_esil_reg_write_silent (esil, collector.rc_ptr[i].name, collector.rc_ptr[i].odata);
			R_FREE (collector.rc_ptr[i].name);
		}
	}
	v &= UT64_MAX ^ UT32_MAX;
	ht_up_foreach (trace->memory, count_changes_above_idx_cb, &v);
	if (data && (((v & UT32_MAX) * sizeof (RAnalEsilTraceMemChange)) >
		(c_num * sizeof (RAnalEsilTraceRegChange)))) {
		c_num = v & UT32_MAX;
		void *new_data = realloc (data, sizeof (RAnalEsilTraceMemChange) * c_num);
		if (!new_data) {
			free (data);
			return;
		}
		data = new_data;
	} else {
		c_num = v & UT32_MAX;
	}
	if (!c_num) {
		free (data);
		return;
	}
	if (R_UNLIKELY (!data)) {
		data = R_NEWS (RAnalEsilTraceMemChange, c_num);
		if (!data) {
			return;
		}
	}
	ChangeCollector collector = {.idx = idx, .data = data};
	ht_up_foreach (trace->memory, collect_mem_changes_cb, &collector);
	//sort collected mem changes so that the newest come first
	qsort (data, c_num, sizeof (RAnalEsilTraceMemChange), sort_mem_changes_cb);
	collector.data = data;
	ut32 i = 0;
	for (;i < c_num; i++) {
		r_esil_mem_write_silent (esil, collector.mc_ptr[i].addr, &collector.rc_ptr[i].odata, 1);
	}
	
}
