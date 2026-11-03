/* radare - LGPL - Copyright 2015-2026 - pancake, rkx1209, condret */

#include <r_esil.h>
#include <r_anal.h>

static void update_last_trace_op(REsilTrace *trace) {
	// point the end of the last traced op at the current access count
	const ut32 op_length = RVecTraceOp_length (&trace->ops);
	if (!op_length) {
		return;
	}
	REsilTraceOp *last = RVecTraceOp_at (&trace->ops, op_length - 1);
	if (last) {
		last->end = RVecAccess_length (&trace->accesses);
	}
}

static void trace_voyeur_reg_read(void *user, const char *name, ut64 val) {
	REsilTrace *trace = user;
	REsilTraceAccess *access = RVecAccess_emplace_back (&trace->accesses);
	access->is_reg = true;
	access->reg.name = strdup (name);
	access->reg.value = val;
	access->is_write = false;
}

static void trace_voyeur_reg_write(void *user, const char *name, ut64 old, ut64 val) {
	(void)old;
	REsilTrace *trace = user;
	REsilTraceAccess *access = RVecAccess_emplace_back (&trace->accesses);
	access->is_reg = true;
	access->reg.name = strdup (name);
	access->reg.value = val;
	access->is_write = true;
}

static void trace_voyeur_mem_read(void *user, ut64 addr, const ut8 *buf, int len) {
	REsilTrace *trace = user;
	char *data = r_hex_bin2strdup (buf, len);
	if (R_UNLIKELY (!data)) {
		return;
	}
	REsilTraceAccess *access = RVecAccess_emplace_back (&trace->accesses);
	access->is_reg = false;
	access->mem.data = data;
	access->mem.addr = addr;
	access->is_write = false;
}

static void trace_voyeur_mem_write(void *user, ut64 addr, const ut8 *oldbuf, const ut8 *buf, int len) {
	(void)oldbuf;
	REsilTrace *trace = user;
	char *data = r_hex_bin2strdup (buf, len);
	if (R_UNLIKELY (!data)) {
		return;
	}
	REsilTraceAccess *access = RVecAccess_emplace_back (&trace->accesses);
	access->is_reg = false;
	access->mem.data = data;
	access->mem.addr = addr;
	access->is_write = true;
}

R_API bool r_esil_trace_start(REsilTrace *trace, REsil *esil) {
	R_RETURN_VAL_IF_FAIL (trace && esil, false);
	if (R_UNLIKELY (trace->vid_reg_write != R_ESIL_VOYEUR_ERR)) {
		return false; // already attached
	}
	trace->vid_reg_read = r_esil_add_voyeur (esil, trace, trace_voyeur_reg_read, R_ESIL_VOYEUR_REG_READ);
	if (R_UNLIKELY (trace->vid_reg_read == R_ESIL_VOYEUR_ERR)) {
		return false;
	}
	trace->vid_reg_write = r_esil_add_voyeur (esil, trace, trace_voyeur_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	if (R_UNLIKELY (trace->vid_reg_write == R_ESIL_VOYEUR_ERR)) {
		goto delete_reg_read;
	}
	trace->vid_mem_read = r_esil_add_voyeur (esil, trace, trace_voyeur_mem_read, R_ESIL_VOYEUR_MEM_READ);
	if (R_UNLIKELY (trace->vid_mem_read == R_ESIL_VOYEUR_ERR)) {
		goto delete_reg_write;
	}
	trace->vid_mem_write = r_esil_add_voyeur (esil, trace, trace_voyeur_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
	if (R_UNLIKELY (trace->vid_mem_write == R_ESIL_VOYEUR_ERR)) {
		goto delete_mem_read;
	}
	return true;
delete_mem_read:
	r_esil_del_voyeur (esil, trace->vid_mem_read);
delete_reg_write:
	r_esil_del_voyeur (esil, trace->vid_reg_write);
delete_reg_read:
	trace->vid_reg_read = R_ESIL_VOYEUR_ERR;
	return false;
}

R_API void r_esil_trace_stop(REsilTrace *trace, REsil *esil) {
	R_RETURN_IF_FAIL (trace && esil);
	if (R_UNLIKELY (trace->vid_reg_read == R_ESIL_VOYEUR_ERR)) {
		return; // not attached
	}
	r_esil_del_voyeur (esil, trace->vid_reg_read);
	r_esil_del_voyeur (esil, trace->vid_reg_write);
	r_esil_del_voyeur (esil, trace->vid_mem_read);
	r_esil_del_voyeur (esil, trace->vid_mem_write);
	trace->vid_reg_read = R_ESIL_VOYEUR_ERR;
	trace->vid_reg_write = R_ESIL_VOYEUR_ERR;
	trace->vid_mem_read = R_ESIL_VOYEUR_ERR;
	trace->vid_mem_write = R_ESIL_VOYEUR_ERR;
}

R_API void r_esil_trace_reset(REsilTrace *trace) {
	// drop the recorded data, the session stays attached
	R_RETURN_IF_FAIL (trace);
	RVecAccess_fini (&trace->accesses);
	RVecAccess_init (&trace->accesses);
	RVecTraceOp_fini (&trace->ops);
	RVecTraceOp_init (&trace->ops);
	trace->idx = 0;
}

R_API void r_esil_trace_finit(REsilTrace *trace) {
	R_RETURN_IF_FAIL (trace);
	r_esil_trace_reset (trace);
	trace->vid_reg_read = R_ESIL_VOYEUR_ERR;
	trace->vid_reg_write = R_ESIL_VOYEUR_ERR;
	trace->vid_mem_read = R_ESIL_VOYEUR_ERR;
	trace->vid_mem_write = R_ESIL_VOYEUR_ERR;
}

R_API void r_esil_trace_op_begin(REsilTrace *trace, ut64 addr) {
	R_RETURN_IF_FAIL (trace);
	if (R_UNLIKELY (trace->vid_reg_read == R_ESIL_VOYEUR_ERR)) {
		return; // not recording
	}
	REsilTraceOp *op = RVecTraceOp_emplace_back (&trace->ops);
	if (R_UNLIKELY (!op)) {
		return;
	}
	op->start = RVecAccess_length (&trace->accesses);
	op->end = op->start;
	op->addr = addr;
}

R_API void r_esil_trace_op_end(REsilTrace *trace) {
	R_RETURN_IF_FAIL (trace);
	if (R_UNLIKELY (trace->vid_reg_read == R_ESIL_VOYEUR_ERR)) {
		return; // not recording
	}
	trace->idx++;
	update_last_trace_op (trace);
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

static void trace_show(REsilTrace *trace, RStrBuf *sb, int idx, int format) {
	REsilTraceOp *op = RVecTraceOp_at (&trace->ops, idx);
	if (!op) {
		return;
	}
	switch (format) {
	case '*': // radare
		r_strbuf_appendf (sb, "ar PC=0x%" PFMT64x "\n", op->addr);
		break;
	default: // sdb
		r_strbuf_appendf (sb, "%d.addr=0x%08" PFMT64x "\n", idx, op->addr);
		if (op->start != op->end) {
			REsilTraceAccess *start = RVecAccess_at (&trace->accesses, op->start);
			REsilTraceAccess *end = RVecAccess_at (&trace->accesses, op->end - 1);
			while (start <= end) {
				print_access (sb, idx, start, format);
				start++;
			}
		} else {
			const ut32 last = RVecAccess_length (&trace->accesses);
			R_LOG_WARN ("Corrupted access detected %d %d", op->end, last);
		}
		break;
	}
}

R_API char *r_esil_trace_list(REsilTrace *trace, int format) {
	R_RETURN_VAL_IF_FAIL (trace, NULL);
	RStrBuf *sb = r_strbuf_new ("");
	int idx = 0;
	REsilTraceOp *op;
	R_VEC_FOREACH (&trace->ops, op) {
		trace_show (trace, sb, idx, format);
		idx++;
	}
	return r_strbuf_drain (sb);
}

// kept until the REsil.trace member is excised
R_API void r_esil_trace_free(REsilTrace *trace) {
	if (trace) {
		RVecAccess_fini (&trace->accesses);
		RVecTraceOp_fini (&trace->ops);
		R_FREE (trace);
	}
}