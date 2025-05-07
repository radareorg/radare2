/* radare - LGPL - Copyright 2015-2025 - pancake, rkx1209 */

#include <r_esil.h>
#include <r_anal.h>
#include <r_arch.h>

#define CMP_REG_CHANGE(x, y) ((x) - ((REsilRegChange *)y)->idx)
#define CMP_MEM_CHANGE(x, y) ((x) - ((REsilMemChange *)y)->idx)

#define D if (false)

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
	R_RETURN_VAL_IF_FAIL (esil, NULL);
	if (!esil->stack_addr || !esil->stack_size) {
		// R_LOG_ERROR ("Run `aeim` to initialize a stack for the ESIL vm");
		return NULL;
	}
	size_t i;
	REsilTrace *trace = R_NEW0 (REsilTrace);
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
	int res = esil->anal->iob.read_at (esil->anal->iob.io, trace->stack_addr, trace->stack_data, trace->stack_size);
	if (res < 1) {
		goto error;
	}

	// AFAIK this is not used
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

static void add_reg_change(REsilTrace *trace, RRegItem *ri, ut64 data) {
	R_RETURN_IF_FAIL (trace && ri);
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
	REsilRegChange reg = { trace->cur_idx, data }; // imho cur_idx is not necessary, we keep track of this in the other vector
	r_vector_push (vreg, &reg);
}

static void add_mem_change(REsilTrace *trace, ut64 addr, ut8 data) {
	R_RETURN_IF_FAIL (trace);
	RVector *vmem = ht_up_find (trace->memory, addr, NULL);
	if (!vmem) {
		vmem = r_vector_new (sizeof (REsilMemChange), NULL, NULL);
		if (!vmem) {
			R_LOG_ERROR ("creating a memory vector");
			return;
		}
		ht_up_insert (trace->memory, addr, vmem);
	}
	REsilMemChange mem = { trace->cur_idx, data };
	r_vector_push (vmem, &mem);
}

// TODO find a better name
static void update_last_trace_op(REsil *esil) {
	// updates last traced op 'end' field to point to the end of the accesses
	ut32 trace_op_length = RVecTraceOp_length (&esil->trace->db.ops);
	if (trace_op_length > 0) {
		REsilTraceOp *last = RVecTraceOp_at (&esil->trace->db.ops, trace_op_length - 1);
		if (last) {
			ut32 vec_idx = RVecAccess_length (&esil->trace->db.accesses);
			if (vec_idx < 1) {
				R_LOG_ERROR ("Invalid access database");
			}
			// eprintf ("update %d %d %d\n", esil->trace->cur_idx, last->end, vec_idx - 1);
			last->end = vec_idx; //  - 1;
		}
	}
}

static bool trace_hook_reg_read(REsil *esil, const char *name, ut64 *res, int *size) {
	R_RETURN_VAL_IF_FAIL (esil && name && res, -1);
	D eprintf ("%d RR %s\n", esil->trace->cur_idx, name);
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
	if (true) {
		REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
		if (!access) {
			R_LOG_ERROR ("Failed to allocate memory for storing access");
			return false;
		}
		access->is_reg = true;
		D eprintf ("emplaced a new access\n");
		// eprintf ("[ESIL] REG READ %s 0x%08"PFMT64x"\n", name, val);
		access->reg.name = strdup (name); // XXX leaks. and regnames should be constant not heap allocated
		access->reg.value = *res;
		// TODO size
		access->is_write = false;
		// eprintf ("select it %p%c", DB, 10);
	} else  {
		R_LOG_ERROR ("cannot read");
	}
	update_last_trace_op (esil);
	return ret;
}

static bool trace_hook_reg_write(REsil *esil, const char *name, ut64 *val) {
	bool ret = false;
	// eprintf ("[ESIL] REG WRITE %s 0x%08"PFMT64x"\n", name, *val);
	D eprintf ("%d RW %s\n", esil->trace->cur_idx, name);
	RRegItem *ri = r_reg_get (esil->anal->reg, name, -1);
	if (ri) {
		REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
		if (!access) {
			R_LOG_ERROR ("Failed to allocate memory for storing access");
			return false;
		}
		access->is_reg = true;
		access->reg.name = strdup (name); // TODO: LEAK reg.name instead of .reg!
		access->reg.value = *val;
		access->is_write = true;
		// TODO size

		add_reg_change (esil->trace, ri, *val);
		if (esil->ocb.hook_reg_write) {
			REsilCallbacks cbs = esil->cb;
			esil->cb = esil->ocb;
			ret = esil->ocb.hook_reg_write (esil, name, val);
			esil->cb = cbs;
		}
		r_unref (ri);
	}
	update_last_trace_op (esil);
	return ret;
}

static bool trace_hook_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	int ret = 0;
	D eprintf ("%d MR 0x%"PFMT64x" %d\n", esil->trace->cur_idx, addr, len);
	if (esil->cb.mem_read) {
		ret = esil->cb.mem_read (esil, addr, buf, len);
	}

	char *hexbuf = calloc ((1 + len), 4);
	if (!hexbuf) {
		return false;
	}

	r_hex_bin2str (buf, len, hexbuf);
	// eprintf ("[ESIL] MEM READ 0x%08"PFMT64x" %s\n", addr, hexbuf);

	REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
	if (!access) {
		free (hexbuf);
		return false;
	}

	access->is_reg = false;
	access->mem.data = hexbuf;
	access->mem.addr = addr;
	access->is_write = false;

	if (esil->ocb.hook_mem_read) {
		REsilCallbacks cbs = esil->cb;
		esil->cb = esil->ocb;
		ret = esil->ocb.hook_mem_read (esil, addr, buf, len);
		esil->cb = cbs;
	}
	update_last_trace_op (esil);
	return ret;
}

static bool trace_hook_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	size_t i;
	int ret = 0;
	D eprintf ("%d MW 0x%"PFMT64x" %d\n", esil->trace->cur_idx, addr, len);
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

	for (i = 0; i < len; i++) {
		add_mem_change (esil->trace, addr + i, buf[i]);
	}

	if (esil->ocb.hook_mem_write) {
		REsilCallbacks cbs = esil->cb;
		esil->cb = esil->ocb;
		ret = esil->ocb.hook_mem_write (esil, addr, buf, len);
		esil->cb = cbs;
	}
	update_last_trace_op (esil);
	return ret != 0;
}

R_API void r_esil_trace_op(REsil *esil, struct r_anal_op_t *op) {
	R_RETURN_IF_FAIL (esil && op);
	const char *expr = r_strbuf_tostring (&op->esil);
	if (!esil->trace) {
		esil->trace = r_esil_trace_new (esil);
		if (!esil->trace) {
			R_LOG_ERROR ("Cannot initialize the esil trace class");
			return;
		}
	}
	D eprintf ("trace op\n");
	if (R_STR_ISEMPTY (expr)) {
		// do nothing
		return;
	}
#if 0
	// XXX condition that should not happen?
	if (esil->trace->cur_idx != esil->trace->end_idx) {
		// eprintf ("j %d\n", esil->trace->idx);
		eprintf ("RESTORE\n");
		r_esil_trace_restore (esil, esil->trace->cur_idx); //  + 1);
		return;
	}
#endif
	/* save old callbacks */
	if (esil->ocb_set) {
		R_LOG_WARN ("r_esil_trace_op: prevented recursive call");
	}
	esil->ocb = esil->cb;
	esil->ocb_set = true;

	REsilTraceOp *to = RVecTraceOp_emplace_back (&esil->trace->db.ops);
	if (to) {
		ut32 vec_idx = RVecAccess_length (&esil->trace->db.accesses);
		D eprintf ("emplaced op with xs %d\n", vec_idx);
		to->start = vec_idx;
		to->end = vec_idx;
		to->addr = op->addr;
	}

	RRegItem *pc_ri = r_reg_get (esil->anal->reg, "PC", -1);
	if (pc_ri) {
		add_reg_change (esil->trace, pc_ri, op->addr);
	}
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
	// update_last_trace_op (esil);
	/* increment idx */
	esil->trace->idx++;
	esil->trace->end_idx++; // should be vector length
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
			REsilRegChange *c = r_vector_index_ptr (vreg, index - 2);
			if (c) {
				// printf ("set value %s 0x%"PFMT64x"\n", ri->name, c->data);
				r_reg_set_value (esil->anal->reg, ri, c->data);
			}
		}
	}
	return true;
}

R_API void r_esil_trace_restore(REsil *esil, int idx) {
	size_t i;
	D printf ("RESTORE 2\n");
	REsilTrace *trace = esil->trace;
	if (!trace) {
		return;
	}
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
	esil->trace->cur_idx = idx;
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
			p ("ar %s = %"PFMT64u"\n", a->reg.name, a->reg.value);
		} else {
			p ("wx %s @ %"PFMT64u"\n", a->mem.data, a->mem.addr);
		}
		break;
	default:
		if (a->is_reg) {
			p ("%d.reg.%s.%s=0x%"PFMT64x"\n", idx, direction, a->reg.name, a->reg.value);
		} else {
			p ("%d.mem.%s.0x%"PFMT64x"=%s\n", idx, direction, a->mem.addr, a->mem.data);
		}
		break;
	}
}

R_API void r_esil_trace_list(REsil *esil, int format) {
	R_RETURN_IF_FAIL (esil && esil->anal);
	D {
		ut32 vec_idx = RVecAccess_length (&esil->trace->db.accesses);
		int i;
		for (i = 0; i < vec_idx; i++) {
			REsilTraceAccess *xs= RVecAccess_at (&esil->trace->db.accesses, i);
			eprintf ("%d XS %c%c %s\n", i, xs->is_reg?'r':'m', xs->is_write?'w':'r', xs->is_reg?xs->reg.name: "");
		}
	}
	if (esil->trace) {
		// PrintfCallback p = esil->anal->cb_printf;
		int idx = 0;
		REsilTraceOp *op;
		R_VEC_FOREACH (&esil->trace->db.ops, op) {
			D eprintf ("---> %d | 0x%08"PFMT64x" | %d %d\n", idx, op->addr, op->start, op->end);
			// p ("---> %d | 0x%08"PFMT64x" | %d %d\n", idx, op->addr, op->start, op->end);
			// p ("%d-----\n", idx);
			r_esil_trace_show (esil, idx, format);
			idx++;
		}
	}
}

static inline ut64 lookup_pc(REsilTraceDB *db, int idx) {
	REsilTraceOp *to = RVecTraceOp_at (&db->ops, idx);
	return to ? to->addr : UT64_MAX;
}

R_API void r_esil_trace_show(REsil *esil, int idx, int format) {
	PrintfCallback p = esil->anal->cb_printf;
	if (!esil->trace) {
		return;
	}

	const ut64 pc = lookup_pc (&esil->trace->db, idx);
	if (pc == UT64_MAX) {
		return;
	}

	REsilTraceOp *op = RVecTraceOp_at (&esil->trace->db.ops, idx);
	switch (format) {
	case '*': // radare
		p ("ar PC=0x%"PFMT64x"\n", pc);
		break;
	default: // sdb
		p ("%d.addr=0x%08"PFMT64x"\n", idx, op->addr);
		if (op->start != op->end) {
			REsilTraceAccess *start = RVecAccess_at (&esil->trace->db.accesses, op->start);
			REsilTraceAccess *end = RVecAccess_at (&esil->trace->db.accesses, op->end - 1);
			while (start <= end) {
				print_access (p, idx, start, format);
				start++;
			}
		} else {
			ut32 last = RVecAccess_length (&esil->trace->db.accesses);
			R_LOG_WARN ("DETECTED CORRUPTED ACCESS %d %d", op->end, last);
		}
		break;
	}
}
