/* radare - LGPL - Copyright 2015-2023 - pancake, rkx1209 */

#include <r_anal.h>
#define CMP_REG_CHANGE(x, y) ((x) - ((REsilRegChange *)y)->idx)
#define CMP_MEM_CHANGE(x, y) ((x) - ((REsilMemChange *)y)->idx)

static void htup_vector_free(HtUPKv *kv) {
	if (kv) {
		r_vector_free (kv->value);
	}
}

static void trace_db_init(REsilTraceDB *db) {
	RVecTraceOp_init (&db->ops);
	RVecAccess_init (&db->accesses);
	db->loop_counts = ht_uu_new0 ();
}

R_API REsilTrace *r_esil_trace_new(REsil *esil) {
	r_return_val_if_fail (esil, NULL);
	if (!esil->stack_addr || !esil->stack_size) {
		// R_LOG_ERROR ("Run `aeim` to initialize a stack for the ESIL vm");
		return NULL;
	}
	size_t i;
	REsilTrace *trace = R_NEW0 (REsilTrace);
	if (!trace) {
		return NULL;
	}
	trace_db_init (&trace->db);
	trace->registers = ht_up_new (NULL, htup_vector_free, NULL);
	if (!trace->registers) {
		goto error;
	}
	trace->memory = ht_up_new (NULL, htup_vector_free, NULL);
	if (!trace->memory) {
		goto error;
	}
	// Save initial ESIL stack memory
	trace->stack_addr = esil->stack_addr;
	trace->stack_size = esil->stack_size;
	trace->stack_data = malloc (esil->stack_size);
	if (!trace->stack_data) {
		goto error;
	}
	esil->anal->iob.read_at (esil->anal->iob.io, trace->stack_addr,
		trace->stack_data, trace->stack_size);
	// Save initial registers arenas
	for (i = 0; i < R_REG_TYPE_LAST; i++) {
		RRegArena *a = esil->anal->reg->regset[i].arena;
		RRegArena *b = r_reg_arena_new (a->size);
		if (!b) {
			goto error;
		}
		if (b->bytes && a->bytes && b->size > 0) {
			memcpy (b->bytes, a->bytes, b->size);
		}
		trace->arena[i] = b;
	}
	return trace;
error:
	R_LOG_ERROR ("trace initialization failed");
	r_esil_trace_free (trace);
	return NULL;
}

static void trace_db_fini(REsilTraceDB *db) {
	if (db) {
		RVecAccess_fini (&db->accesses);
		RVecTraceOp_fini (&db->ops);
		ht_uu_free (db->loop_counts);
	}
}

R_API ut64 r_esil_trace_loopcount(REsilTrace *etrace, ut64 addr) {
	bool found = false;
	const ut64 count = ht_uu_find (etrace->db.loop_counts, addr, &found);
	return found ? count : 0;
}

R_API void r_esil_trace_loopcount_increment(REsilTrace *etrace, ut64 addr) {
	const ut64 count = r_esil_trace_loopcount (etrace, addr);
	ht_uu_update (etrace->db.loop_counts, addr, count + 1);
}

R_API void r_esil_trace_free(REsilTrace *trace) {
	size_t i;
	if (trace) {
		ht_up_free (trace->registers);
		ht_up_free (trace->memory);
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			r_reg_arena_free (trace->arena[i]);
		}
		free (trace->stack_data);
		trace_db_fini (&trace->db);
		R_FREE (trace);
	}
}

static void add_reg_change(REsilTrace *trace, int idx, RRegItem *ri, ut64 data) {
	r_return_if_fail (trace && ri);
	ut64 addr = ri->offset | (ri->arena << 16);
	RVector *vreg = ht_up_find (trace->registers, addr, NULL);
	if (!vreg) {
		vreg = r_vector_new (sizeof (REsilRegChange), NULL, NULL);
		if (!vreg) {
			R_LOG_ERROR ("creating a register vector");
			return;
		}
		ht_up_insert (trace->registers, addr, vreg);
	}
	REsilRegChange reg = { idx, data };
	r_vector_push (vreg, &reg);
}

static void add_mem_change(REsilTrace *trace, int idx, ut64 addr, ut8 data) {
	r_return_if_fail (trace);
	RVector *vmem = ht_up_find (trace->memory, addr, NULL);
	if (!vmem) {
		vmem = r_vector_new (sizeof (REsilMemChange), NULL, NULL);
		if (!vmem) {
			R_LOG_ERROR ("creating a memory vector");
			return;
		}
		ht_up_insert (trace->memory, addr, vmem);
	}
	REsilMemChange mem = { idx, data };
	r_vector_push (vmem, &mem);
}

// TODO better name
static void update_last_trace_op(REsil *esil) {
	ut32 trace_op_length = RVecTraceOp_length (&esil->trace->db.ops);
	if (trace_op_length > 0) {
		REsilTraceOp *last = RVecTraceOp_at (&esil->trace->db.ops, trace_op_length - 1);
		if (last) {
			ut32 vec_idx = RVecAccess_length (&esil->trace->db.accesses);
			last->end = vec_idx + 1;
		}
	}
}

static bool trace_hook_reg_read(REsil *esil, const char *name, ut64 *res, int *size) {
	r_return_val_if_fail (esil && name && res, -1);
	bool ret = false;
	if (*name == '0') {
		// eprintf ("Register not found in profile\n");
		return false;
	}
	if (esil->ocb.hook_reg_read) {
		REsilCallbacks cbs = esil->cb;
		esil->cb = esil->ocb;
		ret = esil->ocb.hook_reg_read (esil, name, res, size);
		esil->cb = cbs;
	}
	if (!ret && esil->cb.reg_read) {
		ret = esil->cb.reg_read (esil, name, res, size);
	}
	if (ret) {
		REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
		if (!access) {
			R_LOG_ERROR ("Failed to allocate memory for storing access");
			return false;
		}

		access->is_reg = true;
		// eprintf ("[ESIL] REG READ %s 0x%08"PFMT64x"\n", name, val);
		access->reg.reg = name;
		access->reg.value = *res;
		// TODO size
		access->is_write = false;
		// eprintf ("select it %p%c", DB, 10);
		update_last_trace_op (esil);
	}
	return ret;
}

static bool trace_hook_reg_write(REsil *esil, const char *name, ut64 *val) {
	bool ret = false;
	// eprintf ("[ESIL] REG WRITE %s 0x%08"PFMT64x"\n", name, *val);
	RRegItem *ri = r_reg_get (esil->anal->reg, name, -1);
	if (ri) {
		REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
		if (!access) {
			R_LOG_ERROR ("Failed to allocate memory for storing access");
			return false;
		}
		access->is_reg = true;
		access->reg.reg = name;
		access->reg.value = *val;
		// TODO size
		access->is_write = true;
		update_last_trace_op (esil);

		add_reg_change (esil->trace, esil->trace->idx + 1, ri, *val);
		if (esil->ocb.hook_reg_write) {
			REsilCallbacks cbs = esil->cb;
			esil->cb = esil->ocb;
			ret = esil->ocb.hook_reg_write (esil, name, val);
			esil->cb = cbs;
		}
		r_unref (ri);
	}
	return ret;
}

static bool trace_hook_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	int ret = 0;
	if (esil->cb.mem_read) {
		ret = esil->cb.mem_read (esil, addr, buf, len);
	}

	char *hexbuf = calloc ((1 + len), 4);
	if (!hexbuf) {
		return false;
	}

	r_hex_bin2str (buf, len, hexbuf);
	//eprintf ("[ESIL] MEM READ 0x%08"PFMT64x" %s\n", addr, hexbuf);

	REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
	if (!access) {
		free (hexbuf);
		return false;
	}

	access->is_reg = false;
	access->mem.data = hexbuf;
	access->mem.addr = addr;
	access->is_write = false;
	update_last_trace_op (esil);

	if (esil->ocb.hook_mem_read) {
		REsilCallbacks cbs = esil->cb;
		esil->cb = esil->ocb;
		ret = esil->ocb.hook_mem_read (esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret;
}

static bool trace_hook_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	size_t i;
	int ret = 0;
	char *hexbuf = r_hex_bin2strdup (buf, len);
	if (!hexbuf) {
		return false;
	}

	//eprintf ("[ESIL] MEM WRITE 0x%08"PFMT64x" %s\n", addr, hexbuf);
	REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
	if (!access) {
		free (hexbuf);
		return false;
	}
	access->is_reg = false;
	access->mem.data = hexbuf;
	access->mem.addr = addr;
	access->is_write = true;
	update_last_trace_op (esil);

	for (i = 0; i < len; i++) {
		add_mem_change (esil->trace, esil->trace->idx + 1, addr + i, buf[i]);
	}

	if (esil->ocb.hook_mem_write) {
		REsilCallbacks cbs = esil->cb;
		esil->cb = esil->ocb;
		ret = esil->ocb.hook_mem_write (esil, addr, buf, len);
		esil->cb = cbs;
	}
	return ret != 0;
}

R_API void r_esil_trace_op(REsil *esil, RAnalOp *op) {
	r_return_if_fail (esil && op);
	const char *expr = r_strbuf_get (&op->esil);
	if (!esil->trace) {
		esil->trace = r_esil_trace_new (esil);
		if (!esil->trace) {
			R_LOG_ERROR ("Cannot initialize the esil trace class");
			return;
		}
	}
	if (R_STR_ISEMPTY (expr)) {
		// do nothing
		return;
	}
	// XXX condition should not happen?
	/* restore from trace when `idx` is not at the end */
	if (esil->trace->idx != esil->trace->end_idx) {
		// eprintf ("j %d\n", esil->trace->idx);
		r_esil_trace_restore (esil, esil->trace->idx + 1);
		return;
	}
	/* save old callbacks */
	if (esil->ocb_set) {
		R_LOG_WARN ("r_esil_trace_op: Cannot call recursively");
	}
	esil->ocb = esil->cb;
	esil->ocb_set = true;

	REsilTraceOp *to = RVecTraceOp_emplace_back (&esil->trace->db.ops);
	if (!to) {
		R_LOG_ERROR ("r_esil_trace_op: Failed to allocate memory");
		return;
	}
	ut32 vec_idx = RVecAccess_length (&esil->trace->db.accesses);
	to->start = vec_idx;
	to->end = vec_idx;
	to->addr = op->addr;
	//sdb_set (DB, KEY ("opcode"), op->mnemonic, 0);
	//sdb_set (DB, KEY ("addr"), expr, 0);
	//eprintf ("[ESIL] ADDR 0x%08"PFMT64x"\n", op->addr);
	//eprintf ("[ESIL] OPCODE %s\n", op->mnemonic);
	//eprintf ("[ESIL] EXPR = %s\n", expr);

	RRegItem *pc_ri = r_reg_get (esil->anal->reg, "PC", -1);
	add_reg_change (esil->trace, esil->trace->idx, pc_ri, op->addr);
	/* set hooks */
	esil->cb.hook_reg_read = trace_hook_reg_read;
	esil->cb.hook_reg_write = trace_hook_reg_write;
	esil->cb.hook_mem_read = trace_hook_mem_read;
	esil->cb.hook_mem_write = trace_hook_mem_write;
	/* evaluate esil expression */
	const int esil_verbose = esil->verbose;
	esil->verbose = 0; // disable verbose logs when tracing
	r_esil_parse (esil, expr);
	r_esil_stack_free (esil);
	esil->verbose = esil_verbose;
	/* restore hooks */
	esil->cb = esil->ocb;
	esil->ocb_set = false;
	/* increment idx */
	esil->trace->idx++;
	esil->trace->end_idx++;
}

static bool restore_memory_cb(void *user, const ut64 key, const void *value) {
	size_t index;
	REsil *esil = user;
	RVector *vmem = (RVector *)value;

	r_vector_upper_bound (vmem, esil->trace->idx, index, CMP_MEM_CHANGE);
	if (index > 0 && index <= vmem->len) {
		REsilMemChange *c = r_vector_index_ptr (vmem, index - 1);
		esil->anal->iob.write_at (esil->anal->iob.io, key, &c->data, 1);
	}
	return true;
}

static bool restore_register(REsil *esil, RRegItem *ri, int idx) {
	size_t index;
	RVector *vreg = ht_up_find (esil->trace->registers, ri->offset | (ri->arena << 16), NULL);
	if (vreg) {
		r_vector_upper_bound (vreg, idx, index, CMP_REG_CHANGE);
		if (index > 0 && index <= vreg->len) {
			REsilRegChange *c = r_vector_index_ptr (vreg, index - 1);
			if (c) {
				r_reg_set_value (esil->anal->reg, ri, c->data);
			}
		}
	}
	return true;
}

R_API void r_esil_trace_restore(REsil *esil, int idx) {
	size_t i;
	REsilTrace *trace = esil->trace;
	// Restore initial state when going backward
	if (idx < esil->trace->idx) {
		// Restore initial registers value
		for (i = 0; i < R_REG_TYPE_LAST; i++) {
			RRegArena *a = esil->anal->reg->regset[i].arena;
			RRegArena *b = trace->arena[i];
			if (a && b) {
				memcpy (a->bytes, b->bytes, a->size);
			}
		}
		// Restore initial stack memory
		esil->anal->iob.write_at (esil->anal->iob.io, trace->stack_addr,
			trace->stack_data, trace->stack_size);
	}
	// Apply latest changes to registers and memory
	esil->trace->idx = idx;
	RListIter *iter;
	RRegItem *ri;
	r_list_foreach (esil->anal->reg->allregs, iter, ri) {
		restore_register (esil, ri, idx);
	}
	ht_up_foreach (trace->memory, restore_memory_cb, esil);
}

static void print_access(PrintfCallback p, int idx, REsilTraceAccess *a, int format) {
	const char *direction = a->is_write ? "write" : "read";

	switch (format) {
	case '*':
		if (a->is_reg) {
			p ("ar %s = %"PFMT64u"\n", a->reg.reg, a->reg.value);
		} else {
			p ("wx %s @ %"PFMT64u"\n", a->mem.data, a->mem.addr);
		}
		break;
	default:
		if (a->is_reg) {
			p ("%d.reg.%s=0x%"PFMT64x, idx, direction, a->reg.value);
		} else {
			p ("%d.mem.%s.data=0x%"PFMT64x, idx, direction, a->mem.data);
		}
		break;
	}
}

R_API void r_esil_trace_list(REsil *esil, int format) {
	r_return_if_fail (esil && esil->anal);
	if (esil->trace) {
		int idx = 0;
		REsilTraceOp *op;
		R_VEC_FOREACH (&esil->trace->db.ops, op) {
			r_esil_trace_show (esil, idx, format);
			idx++;
		}
	}
}

static ut64 lookup_pc(REsilTraceDB *db, int idx) {
	REsilTraceOp *to = RVecTraceOp_at (&db->ops, idx);
	return to ? to->addr : UT64_MAX;
}

R_API void r_esil_trace_show(REsil *esil, int idx, int format) {
	PrintfCallback p = esil->anal->cb_printf;
	if (!esil->trace) {
		return;
	}
	int trace_idx = esil->trace->idx;
	esil->trace->idx = idx;

	const ut64 pc = lookup_pc (&esil->trace->db, esil->trace->idx);
	if (pc == UT64_MAX) {
		return;
	}

	REsilTraceOp *op = RVecTraceOp_at (&esil->trace->db.ops, idx);
	switch (format) {
	case '*': // radare
		p ("ar PC = %"PFMT64u"\n", pc);
		break;
	default: // sdb
		p ("%d.addr=0x"PFMT64x, idx, op->addr);
		const ut32 start_idx = op->start;
		const ut32 end_idx = op->end;

		REsilTraceAccess *start = RVecAccess_at (&esil->trace->db.accesses, start_idx);
		REsilTraceAccess *end = RVecAccess_at (&esil->trace->db.accesses, end_idx);
		while (start != end) {
			print_access (p, idx, start, format);
			start++;
		}
		break;
	}

	esil->trace->idx = trace_idx;
}
