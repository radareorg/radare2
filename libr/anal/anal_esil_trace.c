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

static void add_reg_change(RAnalEsilTrace *trace, RRegItem *ri, ut64 data) {
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
	RAnalEsilTraceRegChange reg = {trace->cur_idx, data}; // imho cur_idx is not necessary, we keep track of this in the other vector
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

	add_reg_change (trace, ri, val);
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
		RAnalEsilTraceMemChange mem = {trace->cur_idx, buf[i]};
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
