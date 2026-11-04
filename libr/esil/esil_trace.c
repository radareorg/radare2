/* radare - LGPL - Copyright 2015-2026 - pancake, rkx1209 */

#include <r_esil.h>
#include <r_anal.h>
#include <r_arch.h>

static void trace_db_init(REsilTraceDB *db) {
	RVecTraceOp_init (&db->ops);
	RVecAccess_init (&db->accesses);
}

R_API REsilTrace *r_esil_trace_new(REsil *esil) {
	R_RETURN_VAL_IF_FAIL (esil, NULL);
	if (!esil->stack_addr || !esil->stack_size) {
		// R_LOG_ERROR ("Run `aeim` to initialize a stack for the ESIL vm");
		return NULL;
	}
	REsilTrace *trace = R_NEW0 (REsilTrace);
	if (!trace) {
		return NULL;
	}
	trace_db_init (&trace->db);
	return trace;
}

static void trace_db_fini(REsilTraceDB *db) {
	if (db) {
		RVecAccess_fini (&db->accesses);
		RVecTraceOp_fini (&db->ops);
	}
}

R_API void r_esil_trace_free(REsilTrace *trace) {
	if (trace) {
		trace_db_fini (&trace->db);
		R_FREE (trace);
	}
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
			last->end = vec_idx; //  - 1;
		}
	}
}

static bool trace_hook_reg_read(REsil *esil, const char *name, ut64 *res, int *size) {
	R_RETURN_VAL_IF_FAIL (esil && name && res, -1);
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
		access->is_reg = true;
		// eprintf ("[ESIL] REG READ %s 0x%08"PFMT64x"\n", name, val);
		access->reg.name = strdup (name); // XXX leaks. and regnames should be constant not heap allocated
		access->reg.value = *res;
		// TODO size
		access->is_write = false;
		// eprintf ("select it %p%c", DB, 10);
	} else {
		R_LOG_ERROR ("cannot read");
	}
	update_last_trace_op (esil);
	return ret;
}

static bool trace_hook_reg_write(REsil *esil, const char *name, ut64 *val) {
	bool ret = false;
	// eprintf ("[ESIL] REG WRITE %s 0x%08"PFMT64x"\n", name, *val);
	RRegItem *ri = r_reg_get (esil->anal->reg, name, -1);
	if (ri) {
		REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
		access->is_reg = true;
		access->reg.name = strdup (name); // TODO: LEAK reg.name instead of .reg!
		access->reg.value = *val;
		access->is_write = true;
		// TODO size
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
	int ret = 0;
	char *hexbuf = r_hex_bin2strdup (buf, len);
	if (!hexbuf) {
		return false;
	}

	// eprintf ("[ESIL] MEM WRITE 0x%08"PFMT64x" %s\n", addr, hexbuf);
	REsilTraceAccess *access = RVecAccess_emplace_back (&esil->trace->db.accesses);
	access->is_reg = false;
	access->mem.data = hexbuf;
	access->mem.addr = addr;
	access->is_write = true;

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
	/* save old callbacks */
	if (esil->ocb_set) {
		R_LOG_WARN ("r_esil_trace_op: prevented recursive call");
	}
	esil->ocb = esil->cb;
	esil->ocb_set = true;

	REsilTraceOp *to = RVecTraceOp_emplace_back (&esil->trace->db.ops);
	ut32 vec_idx = RVecAccess_length (&esil->trace->db.accesses);
	to->start = vec_idx;
	to->end = vec_idx;
	to->addr = op->addr;

	/* set hooks */
	esil->cb.hook_reg_read = trace_hook_reg_read;
	esil->cb.hook_reg_write = trace_hook_reg_write;
	esil->cb.hook_mem_read = trace_hook_mem_read;
	esil->cb.hook_mem_write = trace_hook_mem_write;
	/* evaluate esil expression */
	r_esil_parse (esil, expr);
	r_esil_stack_free (esil);
	/* restore hooks */
	esil->cb = esil->ocb;
	esil->ocb_set = false;
}

static void print_access(RStrBuf *sb, int idx, REsilTraceAccess *a, int format) {
	const char *direction = a->is_write? "write": "read";
	switch (format) {
	case '*':
		if (a->is_reg) {
			r_strbuf_appendf (sb, "ar %s = %" PFMT64u "\n", a->reg.name, a->reg.value);
		} else {
			r_strbuf_appendf (sb, "wx %s @ %" PFMT64u "\n", a->mem.data, a->mem.addr);
		}
		break;
	default:
		if (a->is_reg) {
			r_strbuf_appendf (sb, "%d.reg.%s.%s=0x%" PFMT64x "\n", idx, direction, a->reg.name, a->reg.value);
		} else {
			r_strbuf_appendf (sb, "%d.mem.%s.0x%" PFMT64x "=%s\n", idx, direction, a->mem.addr, a->mem.data);
		}
		break;
	}
}

static inline ut64 lookup_pc(REsilTraceDB *db, int idx) {
	REsilTraceOp *to = RVecTraceOp_at (&db->ops, idx);
	return to? to->addr: UT64_MAX;
}

static void trace_show(REsil *esil, RStrBuf *sb, int idx, int format) {
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
		r_strbuf_appendf (sb, "ar PC=0x%" PFMT64x "\n", pc);
		break;
	default: // sdb
		r_strbuf_appendf (sb, "%d.addr=0x%08" PFMT64x "\n", idx, op->addr);
		if (op->start != op->end) {
			REsilTraceAccess *start = RVecAccess_at (&esil->trace->db.accesses, op->start);
			REsilTraceAccess *end = RVecAccess_at (&esil->trace->db.accesses, op->end - 1);
			while (start <= end) {
				print_access (sb, idx, start, format);
				start++;
			}
		} else {
			ut32 last = RVecAccess_length (&esil->trace->db.accesses);
			R_LOG_WARN ("Corrupted access detected %d %d", op->end, last);
		}
		break;
	}
}

R_API char *r_esil_trace_list(REsil *esil, int format) {
	R_RETURN_VAL_IF_FAIL (esil, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	if (esil->trace) {
		int idx = 0;
		REsilTraceOp *op;
		R_VEC_FOREACH (&esil->trace->db.ops, op) {
			// eprintf ("---> %d | 0x%08" PFMT64x " | %d %d\n", idx, op->addr, op->start, op->end);
			trace_show (esil, sb, idx, format);
			idx++;
		}
	}
	return r_strbuf_drain (sb);
}
