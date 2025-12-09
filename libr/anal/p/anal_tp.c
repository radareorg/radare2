/* radare - LGPL - Copyright 2016-2025 - oddcoder, sivaramaaa, pancake */
/* type matching - type propagation */

#include <r_anal.h>
#define LOOP_MAX 10
#define TYPE_MATCH_MAX_BACKTRACE 512

typedef struct type_trace_change_reg_t {
	int idx;
	ut32 cc;
	char *name;
	ut64 data;
	ut64 odata;
} TypeTraceRegChange;

static void type_trace_reg_change_fini(void *data, void *user) {
	if (data) {
		TypeTraceRegChange *change = data;
		free (change->name);
	}
}

typedef struct type_trace_change_mem_t {
	int idx;
	ut32 cc;
	ut64 addr;
	ut8 data;
	ut8 odata;
} TypeTraceMemChange;

typedef struct {
	char *name;
	ut64 value;
	// TODO: size
} TypeTraceRegAccess;

typedef struct {
	char *data;
	ut64 addr;
	// TODO: size
} TypeTraceMemoryAccess;

typedef struct {
	union {
		TypeTraceRegAccess reg;
		TypeTraceMemoryAccess mem;
	};
	bool is_write;
	bool is_reg;
} TypeTraceAccess;

typedef struct {
	ut64 addr;
	ut32 start;
	ut32 end; // 1 past the end of the op for this index
} TypeTraceOp;

static inline void tt_fini_access(TypeTraceAccess *access) {
	if (access->is_reg) {
		free (access->reg.name);
		return;
	}
	free (access->mem.data);
}

R_VEC_TYPE(VecTraceOp, TypeTraceOp);
R_VEC_TYPE_WITH_FINI(VecAccess, TypeTraceAccess, tt_fini_access);

typedef struct {
	VecTraceOp ops;
	VecAccess accesses;
	HtUU *loop_counts;
} TypeTraceDB;

typedef struct type_trace_t {
	TypeTraceDB db;
	int idx;
	ut32 cc;
	int end_idx;
	int cur_idx;
	RReg *reg;
	HtUP *registers;
	HtUP *memory;
	ut32 voy[4];
	RStrBuf rollback;  // ESIL string to rollback state (inspired by PR #24428)
	bool enable_rollback;
	// TODO: Add REsil instance here
} TypeTrace;

#define CMP_REG_CHANGE(x, y) ((x) - ((TypeTraceRegChange *)y)->idx)
#define CMP_MEM_CHANGE(x, y) ((x) - ((TypeTraceMemChange *)y)->idx)

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

static void type_trace_voyeur_reg_read(void *user, const char *name, ut64 val) {
	R_RETURN_IF_FAIL (user && name);
	char *name_dup = strdup (name);
	if (!name_dup) {
		R_LOG_ERROR ("Failed to allocate(strdup) memory for storing access");
		return;
	}
	TypeTraceDB *db = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&db->accesses);
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

static void add_reg_change(TypeTrace *trace, RRegItem *ri, ut64 data, ut64 odata) {
	R_RETURN_IF_FAIL (trace && ri);
	ut64 addr = ri->offset | (ri->arena << 16);
	RVector *vreg = ht_up_find (trace->registers, addr, NULL);
	if (R_UNLIKELY (!vreg)) {
		// TODO: Do not use RVector!
		vreg = r_vector_new (sizeof (TypeTraceRegChange), type_trace_reg_change_fini, NULL);
		if (R_UNLIKELY (!vreg)) {
			R_LOG_ERROR ("creating a register vector");
			return;
		}
		ht_up_insert (trace->registers, addr, vreg);
	}
	char *name = strdup (ri->name);
	TypeTraceRegChange reg = { trace->cur_idx, trace->cc++, name, data, odata };
	r_vector_push (vreg, &reg);
}

static void type_trace_voyeur_reg_write(void *user, const char *name, ut64 old, ut64 val) {
	R_RETURN_IF_FAIL (user && name);
	TypeTrace *trace = user;
	RRegItem *ri = r_reg_get (trace->reg, name, -1);
	if (!ri) {
		return;
	}
	char *name_dup = strdup (name);
	TypeTraceAccess *access = VecAccess_emplace_back (&trace->db.accesses);
	access->is_reg = true;
	access->reg.name = name_dup;
	access->reg.value = val;
	access->is_write = true;

	if (trace->enable_rollback) {
		r_strbuf_prependf (&trace->rollback, "0x%" PFMT64x ",%s,:=,", old, name);
	}
	add_reg_change (trace, ri, val, old);
	update_trace_db_op (&trace->db);
	r_unref (ri);
}

static void type_trace_voyeur_mem_read(void *user, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (user && buf && (len > 0));
	char *hexbuf = r_hex_bin2strdup (buf, len); // why?
	if (!hexbuf) {
		R_LOG_ERROR ("Failed to allocate(r_hex_bin2strdup) memory for storing access");
		return;
	}
	TypeTraceDB *db = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&db->accesses);
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

static void type_trace_voyeur_mem_write(void *user, ut64 addr, const ut8 *old, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (user && buf && (len > 0));
	char *hexbuf = r_hex_bin2strdup (buf, len); // why?
	if (!hexbuf) {
		R_LOG_ERROR ("Failed to allocate(r_hex_bin2strdup) memory for storing access");
		return;
	}
	TypeTrace *trace = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&trace->db.accesses);
	if (!access) {
		free (hexbuf);
		R_LOG_ERROR ("Failed to allocate memory for storing access");
		return;
	}
	access->is_reg = false;
	access->mem.data = hexbuf;
	access->mem.addr = addr;
	access->is_write = true;

	if (trace->enable_rollback && old) {
		int i;
		for (i = len - 1; i >= 0; i--) {
			r_strbuf_prependf (&trace->rollback,
				"0x%02x,0x%" PFMT64x ",=[1],", old[i], addr + i);
		}
	}

	ut32 j;
	for (j = 0; j < len; j++) {
		ut64 cur_addr = addr + j;
		// adding each byte one by one is utterly stupid, typical gsoc crap
		// ideally this would use a tree structure, that splits nodes when necessary
		RVector *vmem = ht_up_find (trace->memory, cur_addr, NULL);
		if (!vmem) {
			vmem = r_vector_new (sizeof (TypeTraceMemChange), NULL, NULL);
			if (!vmem) {
				R_LOG_ERROR ("creating a memory vector");
				break;
			}
			ht_up_insert (trace->memory, cur_addr, vmem);
		}
		TypeTraceMemChange mem = { trace->idx, trace->cc++, cur_addr, buf[j], old[j] };
		r_vector_push (vmem, &mem);
	}
	update_trace_db_op (&trace->db);
}

static void htup_vector_free(HtUPKv *kv) {
	if (kv) {
		r_vector_free (kv->value);
	}
}

static void trace_db_init(TypeTraceDB *db) {
	VecTraceOp_init (&db->ops);
	VecAccess_init (&db->accesses);
	db->loop_counts = ht_uu_new0 ();
}

static void trace_db_fini(TypeTraceDB *db) {
	if (db) {
		VecTraceOp_fini (&db->ops);
		VecAccess_fini (&db->accesses);
		ht_uu_free (db->loop_counts);
		db->loop_counts = NULL;
	}
}

static bool type_trace_init(TypeTrace *trace, REsil *esil, RReg *reg) {
	R_RETURN_VAL_IF_FAIL (trace && esil && reg, false);
	*trace = (const TypeTrace){ 0 };
	trace_db_init (&trace->db);
	r_strbuf_init (&trace->rollback);
	trace->enable_rollback = false; // Disabled by default for performance
	trace->registers = ht_up_new (NULL, htup_vector_free, NULL);
	if (!trace->registers) {
		goto fail_registers_ht;
	}
	trace->memory = ht_up_new (NULL, htup_vector_free, NULL);
	if (!trace->memory) {
		goto fail_memory_ht;
	}
	trace->voy[R_ESIL_VOYEUR_REG_READ] = r_esil_add_voyeur (esil, &trace->db,
		type_trace_voyeur_reg_read, R_ESIL_VOYEUR_REG_READ);
	if (R_UNLIKELY (trace->voy[R_ESIL_VOYEUR_REG_READ] == R_ESIL_VOYEUR_ERR)) {
		goto fail_regr_voy;
	}
	trace->voy[R_ESIL_VOYEUR_REG_WRITE] = r_esil_add_voyeur (esil, trace,
		type_trace_voyeur_reg_write, R_ESIL_VOYEUR_REG_WRITE);
	if (R_UNLIKELY (trace->voy[R_ESIL_VOYEUR_REG_WRITE] == R_ESIL_VOYEUR_ERR)) {
		goto fail_regw_voy;
	}
	trace->voy[R_ESIL_VOYEUR_MEM_READ] = r_esil_add_voyeur (esil, &trace->db,
		type_trace_voyeur_mem_read, R_ESIL_VOYEUR_MEM_READ);
	if (R_UNLIKELY (trace->voy[R_ESIL_VOYEUR_MEM_READ] == R_ESIL_VOYEUR_ERR)) {
		goto fail_memr_voy;
	}
	trace->voy[R_ESIL_VOYEUR_MEM_WRITE] = r_esil_add_voyeur (esil, trace,
		type_trace_voyeur_mem_write, R_ESIL_VOYEUR_MEM_WRITE);
	if (R_UNLIKELY (trace->voy[R_ESIL_VOYEUR_MEM_WRITE] == R_ESIL_VOYEUR_ERR)) {
		goto fail_memw_voy;
	}
	trace->reg = reg;
	return true;
fail_memw_voy:
	r_esil_del_voyeur (esil, trace->voy[R_ESIL_VOYEUR_MEM_READ]);
fail_memr_voy:
	r_esil_del_voyeur (esil, trace->voy[R_ESIL_VOYEUR_REG_WRITE]);
fail_regw_voy:
	r_esil_del_voyeur (esil, trace->voy[R_ESIL_VOYEUR_REG_READ]);
fail_regr_voy:
	ht_up_free (trace->memory);
	trace->memory = NULL;
fail_memory_ht:
	ht_up_free (trace->registers);
	trace->registers = NULL;
fail_registers_ht:
	trace_db_fini (&trace->db);
	return false;
}

static ut64 type_trace_loopcount(TypeTrace *trace, ut64 addr) {
	bool found = false;
	const ut64 count = ht_uu_find (trace->db.loop_counts, addr, &found);
	return found? count: 0;
}

static void type_trace_loopcount_increment(TypeTrace *trace, ut64 addr) {
	const ut64 count = type_trace_loopcount (trace, addr);
	ht_uu_update (trace->db.loop_counts, addr, count + 1);
}

// Execute rollback ESIL to restore state, then clear buffer
static void type_trace_rollback(TypeTrace *trace, REsil *esil) {
	R_RETURN_IF_FAIL (trace && esil);
	if (r_strbuf_length (&trace->rollback) > 0) {
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
static void type_trace_rollback_clear(TypeTrace *trace) {
	R_RETURN_IF_FAIL (trace);
	r_strbuf_fini (&trace->rollback);
	r_strbuf_init (&trace->rollback);
}

static void type_trace_fini(TypeTrace *trace, REsil *esil) {
	R_RETURN_IF_FAIL (trace && esil);
	trace_db_fini (&trace->db);
	r_strbuf_fini (&trace->rollback);
	ht_up_free (trace->registers);
	trace->registers = NULL;
	ht_up_free (trace->memory);
	trace->memory = NULL;
	r_esil_del_voyeur (esil, trace->voy[R_ESIL_VOYEUR_MEM_WRITE]);
	r_esil_del_voyeur (esil, trace->voy[R_ESIL_VOYEUR_MEM_READ]);
	r_esil_del_voyeur (esil, trace->voy[R_ESIL_VOYEUR_REG_WRITE]);
	r_esil_del_voyeur (esil, trace->voy[R_ESIL_VOYEUR_REG_READ]);
	r_reg_free (trace->reg);
	trace->reg = NULL;
	*trace = (const TypeTrace){ 0 };
}

static bool type_trace_op(TypeTrace *trace, REsil *esil, RAnalOp *op) {
	R_RETURN_VAL_IF_FAIL (trace && esil && op, false);
	const char *expr = r_strbuf_get (&op->esil);
	if (R_UNLIKELY (!expr || !strlen (expr))) {
		R_LOG_WARN ("expr is empty or null at 0x%08" PFMT64x " type=%d", op->addr, op->type);
		return false;
	}
	trace->cc = 0;
	RRegItem *ri = r_reg_get (trace->reg, "PC", -1);
	if (ri) {
		const bool suc = r_esil_reg_write_silent (esil, ri->name, op->addr + op->size);
		r_unref (ri);
		if (!suc) {
			return false;
		}
	}

	TypeTraceOp *to = VecTraceOp_emplace_back (&trace->db.ops);
	if (R_UNLIKELY (!to)) {
		R_LOG_ERROR ("Failed to allocate trace op at 0x%08" PFMT64x, op->addr);
		return false;
	}
	ut32 vec_idx = VecAccess_length (&trace->db.accesses);
	to->start = vec_idx;
	to->end = vec_idx;
	to->addr = op->addr;
	const bool ret = r_esil_parse (esil, expr);
	r_esil_stack_free (esil);
	trace->idx++;
	trace->end_idx++;
	return ret;
}

// TODO: type_trace_restore() for state rollback during backtracking
// was removed as dead code - can be re-implemented if needed for
// more accurate cross-basic-block type propagation

R_VEC_TYPE(RVecUT64, ut64);
R_VEC_TYPE(RVecBuf, ut8);

// TPState - Isolated ESIL environment for type propagation
// Design inspired by RCoreEsil from PR #24428:
// - Centralized ESIL state (esil, reg_if, mem_if)
// - Tracing with rollback capability (tt)
// - Hook callbacks for extensibility
typedef struct tp_state_t {
	// ESIL engine and interfaces
	REsil esil;
	REsilRegInterface reg_if;
	REsilMemInterface mem_if;
	TypeTrace tt;
	ut64 stack_base;
	int stack_fd;
	ut32 stack_map;
	RAnal *anal;
	// RConfigHold *hc;
	char *cfg_spec;
	bool cfg_breakoninvalid;
	bool cfg_chk_constraint;
	bool cfg_rollback;
	bool old_follow;
	void (*on_call)(struct tp_state_t *tps, ut64 addr, const char *name);
	void *hook_user;
} TPState;

/// BEGIN /////////////////// esil trace helpers ///////////////////////

static int etrace_index(TypeTrace *etrace) {
	int len = VecTraceOp_length (&etrace->db.ops);
	etrace->cur_idx = len; //  > 0? len -1: 0;
	return etrace->cur_idx; // VecTraceOp_length (&etrace->db.ops);
}

static ut64 etrace_addrof(TypeTrace *etrace, ut32 idx) {
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	return op? op->addr: 0;
}

static ut64 etrace_memwrite_addr(TypeTrace *etrace, ut32 idx) {
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	R_LOG_DEBUG ("memwrite %d %d", etrace->idx, idx);
	if (op && op->start != op->end) {
		TypeTraceAccess *start = VecAccess_at (&etrace->db.accesses, op->start);
		TypeTraceAccess *end = VecAccess_at (&etrace->db.accesses, op->end - 1);
		while (start <= end) {
			if (!start->is_reg && start->is_write) {
				return start->mem.addr;
			}
			start++;
		}
	}
	return 0;
}

static bool etrace_have_memread(TypeTrace *etrace, ut32 idx) {
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	R_LOG_DEBUG ("memread %d %d", etrace->idx, idx);
	if (op && op->start != op->end) {
		TypeTraceAccess *start = VecAccess_at (&etrace->db.accesses, op->start);
		TypeTraceAccess *end = VecAccess_at (&etrace->db.accesses, op->end - 1);
		while (start <= end) {
			if (!start->is_reg && !start->is_write) {
				return true;
			}
			start++;
		}
	}
	return false;
}

static ut64 etrace_regread_value(TypeTrace *etrace, ut32 idx, const char *rname) {
	R_LOG_DEBUG ("regread %d %d", etrace->idx, idx);
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	if (op && op->start != op->end) {
		TypeTraceAccess *start = VecAccess_at (&etrace->db.accesses, op->start);
		TypeTraceAccess *end = VecAccess_at (&etrace->db.accesses, op->end - 1);
		while (start <= end) {
			if (start->is_reg && !start->is_write) {
				if (!strcmp (rname, start->reg.name)) {
					return start->reg.value;
				}
			}
			start++;
		}
	}
	return 0;
}

static const char *etrace_regwrite(TypeTrace *etrace, ut32 idx) {
	R_LOG_DEBUG ("regwrite %d %d", etrace->idx, idx);
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	if (op && op->start != op->end) {
		TypeTraceAccess *start = VecAccess_at (&etrace->db.accesses, op->start);
		TypeTraceAccess *end = VecAccess_at (&etrace->db.accesses, op->end - 1);
		while (start <= end) {
			if (start->is_reg && start->is_write) {
				return start->reg.name;
			}
			start++;
		}
	}
	return NULL;
}

/// END ///////////////////// esil trace helpers ///////////////////////

static bool etrace_regwrite_contains(TypeTrace *etrace, ut32 idx, const char *rname) {
	R_LOG_DEBUG ("regwrite contains %d %s", idx, rname);
	R_RETURN_VAL_IF_FAIL (etrace && rname, false);
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx); // AAA + 1);
	if (op && op->start != op->end) {
		TypeTraceAccess *start = VecAccess_at (&etrace->db.accesses, op->start);
		TypeTraceAccess *end = VecAccess_at (&etrace->db.accesses, op->end - 1);
		while (start <= end) {
			if (start->is_reg && start->is_write) {
				if (!strcmp (rname, start->reg.name)) {
					return true;
				}
			}
			start++;
		}
	}
	return false;
}

static bool type_pos_hit(TPState *tps, bool in_stack, int idx, int size, const char *place) {
	R_LOG_DEBUG ("Type pos hit %d %d %d %s", in_stack, idx, size, place);
	if (in_stack) {
		ut64 sp = r_reg_getv (tps->tt.reg, "SP"); // XXX this is slow too and we can cache
		const ut64 write_addr = etrace_memwrite_addr (&tps->tt, idx); // AAA -1
		return (write_addr == sp + size);
	}
	return place && etrace_regwrite_contains (&tps->tt, idx, place);
}

static void var_rename(RAnal *anal, RAnalVar *v, const char *name, ut64 addr) {
	if (!name || !v) {
		return;
	}
	if (!*name || !strcmp (name, "...")) {
		return;
	}
	bool is_default = (r_str_startswith (v->name, VARPREFIX) || r_str_startswith (v->name, ARGPREFIX));
	if (*name == '*') {
		name++;
	}
	// longer name tends to be meaningful like "src" instead of "s1"
	if (!is_default && (strlen (v->name) > strlen (name))) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
	if (fcn) {
		r_anal_var_rename (anal, v, name);
	}
}

static void var_retype(RAnal *anal, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
	R_LOG_DEBUG ("Var retype %s %s", var->name, type);
	R_RETURN_IF_FAIL (anal && var && type);
	// XXX types should be passed without spaces to trim
	type = r_str_trim_head_ro (type);
	// default type if none is provided
	if (!*type) {
		type = "int";
	}
	bool is_ptr = (vname && *vname == '*');
	// removing this return makes 64bit vars become 32bit
	if (r_str_startswith (type, "int") || (!is_ptr && !strcmp (type, "void"))) {
		// default or void type
		R_LOG_DEBUG ("DEFAULT NOT DOING THIS");
		return;
	}
	const char *expand = var->type;
	if (!strcmp (var->type, "int32_t")) {
		expand = "int";
	} else if (!strcmp (var->type, "uint32_t")) {
		expand = "unsigned int";
	} else if (!strcmp (var->type, "uint64_t")) {
		expand = "unsigned long long";
	}
	const char *tmp = strstr (expand, "int");
	bool is_default = tmp;
	if (!is_default && !r_str_startswith (var->type, "void")) {
		// return since type is already propagated
		// except for "void *", since "void *" => "char *" is possible
		R_LOG_DEBUG ("not default NOT DOING A SHIT HERE");
		return;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (pfx) {
		if (is_default && !r_str_startswith (var->type, "signed")) {
			r_strbuf_setf (sb, "%s %s", type, tmp);
		} else {
			r_strbuf_free (sb);
			R_LOG_DEBUG ("THIS IS RETURN NOT DOING A SHIT HERE");
			return;
		}
	} else {
		r_strbuf_set (sb, type);
	}
	if (r_str_startswith (r_strbuf_get (sb), "const ")) {
		// Dropping const from type
		// TODO: Inferring const type
		r_strbuf_setf (sb, "%s", type + 6);
	}
	if (is_ptr) {
		// type *ptr => type *
		r_strbuf_append (sb, " *");
	}
	while (ref > 0) {
		if (r_str_endswith (r_strbuf_get (sb), "*")) { // type * => type **
			r_strbuf_append (sb, "*");
		} else { //  type => type *
			r_strbuf_append (sb, " *");
		}
		ref--;
	}
	while (ref < 0) {
		char *s = r_strbuf_get (sb);
		if (!s) {
			break;
		}
		r_str_trim (s);
		if (r_str_endswith (s, "*")) {
			r_strbuf_slice (sb, 0, r_strbuf_length (sb) - 1);
		}
		ref++;
	}

	char *tmp1 = r_strbuf_get (sb);
	if (r_str_startswith (tmp1, "unsigned long long")) {
		r_strbuf_set (sb, "uint64_t");
	} else if (r_str_startswith (tmp1, "unsigned")) {
		r_strbuf_set (sb, "uint32_t");
	} else if (r_str_startswith (tmp1, "int")) {
		r_strbuf_set (sb, "int32_t");
	}
	r_anal_var_set_type (anal, var, r_strbuf_get (sb));
	r_strbuf_free (sb);
}

static RAnalOp *tp_anal_op(RAnal *anal, ut64 addr, int mask);

static void get_src_regname(RAnal *anal, ut64 addr, char *regname, int size) {
	R_RETURN_IF_FAIL (anal && regname && size > 0);
	regname[0] = 0;
	RAnalOp *op = tp_anal_op (anal, addr, R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL);
	if (!op || r_strbuf_is_empty (&op->esil)) {
		r_anal_op_free (op);
		return;
	}
	char *op_esil = r_strbuf_get (&op->esil);
	char *tmp = strchr (op_esil, ',');
	if (tmp) {
		*tmp = '\0';
	}
	RRegItem *ri = r_reg_get (anal->reg, op_esil, -1);
	if (ri) {
		const char *s = op_esil;
		if ((anal->config->bits == 64) && (ri->size == 32)) {
			const char *reg = r_reg_32_to_64 (anal->reg, op_esil);
			if (reg) {
				s = reg;
			}
		}
		if (s) {
			r_str_ncpy (regname, s, size);
		}
		R_LOG_DEBUG ("===================regitem %s", regname);
		r_unref (ri);
	} else {
		R_LOG_DEBUG ("no regitem %s at 0x%" PFMT64x, op_esil, addr);
	}
	r_anal_op_free (op);
}

static ut64 get_addr(TypeTrace *et, const char *regname, int idx) {
	if (R_STR_ISEMPTY (regname)) {
		return 0;
	}
	/// r_strf_var (query, 64, "%d.reg.read.%s", idx, regname);
	// return r_num_math (NULL, sdb_const_get (trace, query, 0));
	return etrace_regread_value (et, idx, regname);
}

static RAnalCondType cond_invert(RAnal *anal, RAnalCondType cond) {
	switch (cond) {
	case R_ANAL_CONDTYPE_LE:
		return R_ANAL_CONDTYPE_GT;
	case R_ANAL_CONDTYPE_LT:
		return R_ANAL_CONDTYPE_GE;
	case R_ANAL_CONDTYPE_GE:
		return R_ANAL_CONDTYPE_LT;
	case R_ANAL_CONDTYPE_GT:
		return R_ANAL_CONDTYPE_LE;
	case R_ANAL_CONDTYPE_AL:
		return R_ANAL_CONDTYPE_NV;
	case R_ANAL_CONDTYPE_NV:
		return R_ANAL_CONDTYPE_AL;
	case R_ANAL_CONDTYPE_EQ:
		return R_ANAL_CONDTYPE_NE;
	case R_ANAL_CONDTYPE_NE:
		return R_ANAL_CONDTYPE_EQ;
	default:
		R_LOG_WARN ("unhandled condition for swapping %d", cond);
		break;
	}
	return 0; // 0 is COND_ALways...
	/* I haven't looked into it but I suspect that this might be confusing:
	the opposite of any condition not in the list above is "always"? */
}

typedef const char *String;
R_VEC_TYPE(RVecString, String); // no fini, these are owned by SDB

static RAnalOp *tp_anal_op(RAnal *anal, ut64 addr, int mask);

static bool parse_format(TPState *tps, const char *fmt, RVecString *vec) {
	if (R_STR_ISEMPTY (fmt)) {
		return false;
	}

	Sdb *s = tps->anal->sdb_fmts;
	char arr[32] = { 0 };
	const char *ptr = strchr (fmt, '%');
	while (ptr) {
		ptr++;
		// strip [width] specifier
		while (isdigit (*ptr)) {
			ptr++;
		}
		r_str_ncpy (arr, ptr, sizeof (arr) - 1);
		char *tmp = arr;
		while (isalpha (*tmp)) {
			tmp++;
		}
		*tmp = '\0';
		r_strf_var (query, 128, "spec.%s.%s", tps->cfg_spec, arr);
		const char *type = sdb_const_get (s, query, 0); // maybe better to return an owned pointer here?
		if (type) {
			RVecString_push_back (vec, &type);
		}
		// ptr = strchr (ptr + (tmp-arr), '%');
		ptr = strchr (ptr, '%');
	}

	return true;
}

static void retype_callee_arg(RAnal *anal, const char *callee_name, bool in_stack, const char *place, int size, const char *type) {
	R_LOG_DEBUG (">>> CALLE ARG");
	RAnalFunction *fcn = r_anal_get_function_byname (anal, callee_name);
	if (!fcn) {
		return;
	}
	if (in_stack) {
		RAnalVar *var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_BPV, size - fcn->bp_off + 8);
		if (!var) {
			return;
		}
		var_retype (anal, var, NULL, type, false, false);
	} else {
		RRegItem *item = r_reg_get (anal->reg, place, -1);
		if (!item) {
			return;
		}
		RAnalVar *rvar = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, item->index);
		if (!rvar) {
			r_unref (item);
			return;
		}
		char *t = strdup (type);
		var_retype (anal, rvar, NULL, type, false, false);
		RAnalVar *lvar = r_anal_var_get_dst_var (rvar);
		if (lvar) {
			var_retype (anal, lvar, NULL, t, false, false);
		}
		free (t);
		r_unref (item);
	}
}

static bool etrace_memread_contains_addr(TypeTrace *etrace, ut32 idx, ut64 addr) {
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	if (op && op->start != op->end) {
		TypeTraceAccess *start = VecAccess_at (&etrace->db.accesses, op->start);
		TypeTraceAccess *end = VecAccess_at (&etrace->db.accesses, op->end - 1);
		while (start <= end) {
			if (!start->is_reg && !start->is_write && start->mem.addr == addr) {
				return true;
			}
			start++;
		}
	}
	return false;
}

static bool etrace_memread_first_addr(TypeTrace *etrace, ut32 idx, ut64 *addr) {
	TypeTraceOp *op = VecTraceOp_at (&etrace->db.ops, idx);
	if (!op || op->start == op->end) {
		return false;
	}
	TypeTraceAccess *start = VecAccess_at (&etrace->db.accesses, op->start);
	TypeTraceAccess *end = VecAccess_at (&etrace->db.accesses, op->end - 1);
	while (start <= end) {
		if (!start->is_reg && !start->is_write) {
			if (addr) {
				*addr = start->mem.addr;
			}
			return true;
		}
		start++;
	}
	return false;
}

#define DEFAULT_MAX 3
#define REGNAME_SIZE 10
#define MAX_INSTR 5

/**
 * type match at a call instruction inside another function
 *
 * \param fcn_name name of the callee
 * \param addr addr of the call instruction
 * \param baddr addr of the caller function
 * \param cc cc of the callee
 * \param prev_idx index in the esil trace
 * \param userfnc whether the callee is a user function (affects propagation direction)
 * \param caddr addr of the callee
 */
static void type_match(TPState *tps, char *fcn_name, ut64 addr, ut64 baddr, const char *cc,
	int prev_idx, bool userfnc, ut64 caddr) {
	RAnal *anal = tps->anal;
	TypeTrace *tt = &tps->tt;
	Sdb *TDB = anal->sdb_types;
	const int idx = etrace_index (tt) - 1;
	const bool verbose = anal->coreb.cfgGetB? anal->coreb.cfgGetB (anal->coreb.core, "anal.types.verbose"): false;
	bool stack_rev = false, in_stack = false, format = false;
	R_LOG_DEBUG ("type_match %s %" PFMT64x " %" PFMT64x " %s %d", fcn_name, addr, baddr, cc, prev_idx);

	if (!fcn_name || !cc) {
		return;
	}
	int i, j, pos = 0, size = 0, max = r_type_func_args_count (TDB, fcn_name);
	int lastarg = ST32_MAX;
	const char *place = r_anal_cc_arg (anal, cc, lastarg, -1);
	r_cons_break_push (r_cons_singleton (), NULL, NULL);

	if (place && !strcmp (place, "stack_rev")) {
		stack_rev = true;
	}
	place = r_anal_cc_arg (anal, cc, 0, -1);
	if (place && r_str_startswith (place, "stack")) {
		in_stack = true;
	}
	if (verbose && r_str_startswith (fcn_name, "sym.imp.")) {
		R_LOG_WARN ("Missing function definition for '%s'", fcn_name + 8);
	}
	if (!max) {
		max = in_stack? DEFAULT_MAX: r_anal_cc_max_arg (anal, cc);
	}
	// TODO: if function takes more than 7 args is usually bad analysis
	if (max > 7) {
		max = DEFAULT_MAX;
	}

	RVecString types;
	RVecString_init (&types);
	const int bytes = anal->config->bits / 8;
	const ut32 opmask = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL;
	for (i = 0; i < max; i++) {
		int arg_num = stack_rev? (max - 1 - i): i;
		char *type = NULL;
		const char *name = NULL;
		R_LOG_DEBUG ("ARG NUM %d %d %d", i, arg_num, format);
		if (format) {
			if (RVecString_empty (&types)) {
				break;
			}
			const String *type_ = RVecString_at (&types, pos++);
			type = type_? strdup (*type_): NULL;
			R_LOG_DEBUG ("TYPE (%s)", type);
		} else {
			type = r_type_func_args_type (TDB, fcn_name, arg_num);
			name = r_type_func_args_name (TDB, fcn_name, arg_num);
		}
		if (!type && !userfnc) {
			R_LOG_DEBUG ("NO TYPE AND NO USER FUNK");
			continue;
		}
		if (!in_stack) {
			// XXX: param arg_num must be fixed to support floating point register
			// before this change place could be null
			R_LOG_DEBUG ("not in stack");
			const char *p = r_anal_cc_arg (anal, cc, arg_num, -1);
			if (p && r_str_startswith (p, "stack")) {
				in_stack = true;
				place = p;
			}
			place = p;
		}
		char regname[REGNAME_SIZE] = { 0 };
		ut64 xaddr = UT64_MAX;
		int memref = 0;
		bool cmt_set = false;
		bool res = false;
		bool memref_addr_valid = false;
		ut64 memref_addr = UT64_MAX;
		// Backtrace instruction from source sink to prev source sink
		// Limit iterations to avoid quadratic blowup on large traces
		const int bt_limit = R_MIN (idx - prev_idx + 1, TYPE_MATCH_MAX_BACKTRACE);
		int bt_count = 0;
		for (j = idx; j >= prev_idx && bt_count < bt_limit; j--, bt_count++) {
			// r_strf_var (k, 32, "%d.addr", j);
			// ut64 instr_addr = sdb_num_get (trace, k, 0);
			ut64 instr_addr = etrace_addrof (tt, j);
			R_LOG_DEBUG ("0x%08" PFMT64x " back traceing %d", instr_addr, j);
			if (instr_addr < baddr) {
				break;
			}
			RAnalOp *op = tp_anal_op (anal, instr_addr, opmask);
			if (!op) {
				break;
			}
			RAnalOp *next_op = tp_anal_op (anal, instr_addr + op->size, opmask);
			if (!next_op || (j != idx && (next_op->type == R_ANAL_OP_TYPE_CALL || next_op->type == R_ANAL_OP_TYPE_JMP))) {
				r_anal_op_free (op);
				r_anal_op_free (next_op);
				break;
			}
			RAnalVar *var = r_anal_get_used_function_var (anal, op->addr);
			bool related = false;
			const char *esil_str = r_strbuf_get (&op->esil);
			if (esil_str) {
				if (regname[0]) {
					if (strstr (esil_str, regname)) {
						related = true;
					}
				} else {
					if (place && strstr (esil_str, place)) {
						related = true;
					}
					if (!related && in_stack) {
						ut64 sp = r_reg_getv (tps->tt.reg, "SP");
						if (etrace_memread_contains_addr (tt, j, sp + size)) {
							related = true;
						}
					}
				}
			}

			// Match type from function param to instr
			if (type_pos_hit (tps, in_stack, j, size, place)) {
				R_LOG_DEBUG ("InHit");
				if (!cmt_set && type && name) {
					char *ms = r_str_newf ("%s%s%s", type, r_str_endswith (type, "*")? "": " ", name);
					r_meta_set_string (anal, R_META_TYPE_VARTYPE, instr_addr, ms);
					free (ms);
					cmt_set = true;
					if ((op->ptr && op->ptr != UT64_MAX) && !strcmp (name, "format")) {
						RFlagItem *f = anal->flb.f? r_flag_get_by_spaces (anal->flb.f, false, op->ptr, "strings", NULL): NULL;
						if (f && f->size > 0) {
							char formatstr[0x200];
							int len = R_MIN (sizeof (formatstr) - 1, f->size);
							bool ok = anal->iob.read_at? anal->iob.read_at (anal->iob.io, f->addr, (ut8 *)formatstr, len): false;
							if (ok) {
								formatstr[len] = '\0';
								RVecString_clear (&types);
								if (parse_format (tps, formatstr, &types)) {
									max += RVecString_length (&types);
								}
								format = true;
							}
						}
					}
				}
				if (var) {
					R_LOG_DEBUG ("retype var %s", name);
					int var_memref = var->isarg? 0: memref;
					if (op->type == R_ANAL_OP_TYPE_LEA) {
						var_memref--;
					}
					if (!userfnc) {
						// not a userfunction, propagate the callee's arg types into our function's vars
						var_retype (anal, var, name, type, var_memref, false);
						var_rename (anal, var, name, addr);
					} else {
						// callee is a userfunction, propagate our variable's type into the callee's args
						retype_callee_arg (anal, fcn_name, in_stack, place, size, var->type);
					}
					res = true;
				} else {
					char src_reg[REGNAME_SIZE] = { 0 };
					get_src_regname (anal, instr_addr, src_reg, sizeof (src_reg));
					if (src_reg[0]) {
						r_str_ncpy (regname, src_reg, sizeof (regname));
					}
					xaddr = get_addr (tt, regname, j);
				}
			}

			// Type propagate by following source reg
			if (!res && *regname && etrace_regwrite_contains (tt, j, regname)) {
				if (op->type == R_ANAL_OP_TYPE_MOV && etrace_have_memread (tt, j)) {
					if (!var || var->kind == R_ANAL_VAR_KIND_REG) {
						ut64 addr_read = UT64_MAX;
						bool has_addr = etrace_memread_first_addr (tt, j, &addr_read);
						if (!has_addr || !memref_addr_valid || addr_read != memref_addr) {
							memref++;
							if (has_addr) {
								memref_addr = addr_read;
								memref_addr_valid = true;
							}
						}
					}
				}
				if (var) {
					int var_memref = var->isarg? 0: memref;
					if (!userfnc) {
						// not a userfunction, propagate the callee's arg types into our function's vars
						var_retype (anal, var, name, type, var_memref, false);
						var_rename (anal, var, name, addr);
					} else {
						// callee is a userfunction, propagate our variable's type into the callee's args
						retype_callee_arg (anal, fcn_name, in_stack, place, size, var->type);
					}
					res = true;
				} else {
					switch (op->type) {
					case R_ANAL_OP_TYPE_MOV:
					case R_ANAL_OP_TYPE_PUSH:
						get_src_regname (anal, instr_addr, regname, sizeof (regname));
						break;
					case R_ANAL_OP_TYPE_LEA:
					case R_ANAL_OP_TYPE_LOAD:
					case R_ANAL_OP_TYPE_STORE:
						res = true;
						break;
					}
				}
			} else if (var && res && (xaddr && xaddr != UT64_MAX)) { // Type progation using value
				char tmp[REGNAME_SIZE] = { 0 };
				get_src_regname (anal, instr_addr, tmp, sizeof (tmp));
				ut64 ptr = get_addr (tt, tmp, j);
				if (ptr == xaddr) {
					int var_memref = var->isarg? 0: memref;
					var_retype (anal, var, name, r_str_get_fail (type, "int"), var_memref, false);
				}
			}
			r_anal_op_free (op);
			r_anal_op_free (next_op);
		}
		size += bytes;
		free (type);
	}
	RVecString_fini (&types);
	r_cons_break_pop (r_cons_singleton ());
}

static int bb_cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return a->addr > b->addr? 1: (a->addr < b->addr? -1: 0);
}

static void tps_fini(TPState *tps) {
	R_RETURN_IF_FAIL (tps);
	type_trace_fini (&tps->tt, &tps->esil);
	r_esil_fini (&tps->esil);
	if (tps->anal->iob.fd_close) {
		tps->anal->iob.fd_close (tps->anal->iob.io, tps->stack_fd);
	}
	free (tps->cfg_spec);
	if (tps->anal->coreb.cmd) {
		if (tps->old_follow) {
			tps->anal->coreb.cmd (tps->anal->coreb.core, "e dbg.follow=true");
		} else {
			tps->anal->coreb.cmd (tps->anal->coreb.core, "e dbg.follow=false");
		}
	}
	// r_config_hold_restore (tps->hc);
	// r_config_hold_free (tps->hc);
	free (tps);
}

static bool tt_is_reg(void *reg, const char *name) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return false;
	}
	r_unref (ri);
	return true;
}

static bool tt_reg_read(void *reg, const char *name, ut64 *val) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return false;
	}
	if (val) {
		*val = r_reg_get_value ((RReg *)reg, ri);
	}
	r_unref (ri);
	return true;
}

static ut32 tt_reg_size(void *reg, const char *name) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return 0;
	}
	ut32 size = ri->size;
	r_unref (ri);
	return size;
}

static bool tt_mem_read(void *mem, ut64 addr, ut8 *buf, int len) {
	TPState *tps = (TPState *)mem;
	if (tps->anal->iob.read_at) {
		return tps->anal->iob.read_at (tps->anal->iob.io, addr, buf, len);
	}
	return false;
}

// ensures type trace esil engine only writes to it's designated stack map.
// writes outside of that itv will be assumed as valid and return true.
// this function assumes, that stack map has highest priority,
// or does not overlap with any other map.
static bool tt_mem_write(void *mem, ut64 addr, const ut8 *buf, int len) {
	TPState *tps = (TPState *)mem;
	RIOMap *map = tps->anal->iob.map_get? tps->anal->iob.map_get (tps->anal->iob.io, tps->stack_map): NULL;
	if (!map) {
		R_LOG_WARN ("stack map unavailable for type propagation writes");
		return false;
	}
	RInterval itv = { addr, len };
	if (!r_itv_overlap (map->itv, itv)) {
		return true;
	}
	itv = r_itv_intersect (map->itv, itv);
	if (tps->anal->iob.write_at) {
		return tps->anal->iob.write_at (tps->anal->iob.io, itv.addr, &buf[itv.addr - addr], (int)itv.size);
	}
	return false;
}

static bool tt_esil_reg_write(REsil *esil, const char *name, ut64 val) {
	TPState *tps = esil->user;
	if (!tps || !tps->reg_if.reg_read || !tps->reg_if.reg_write) {
		return false;
	}
	ut64 old = 0;
	if (!tps->reg_if.reg_read (tps->reg_if.reg, name, &old)) {
		return false;
	}
	if (!tps->reg_if.reg_write (tps->reg_if.reg, name, val)) {
		return false;
	}
	type_trace_voyeur_reg_write (&tps->tt, name, old, val);
	return true;
}

static bool tt_esil_reg_read(REsil *esil, const char *name, ut64 *val, int *size) {
	TPState *tps = esil->user;
	if (!tps || !tps->reg_if.reg_read) {
		return false;
	}
	ut64 tmp = 0;
	ut64 *out = val? val: &tmp;
	if (!tps->reg_if.reg_read (tps->reg_if.reg, name, out)) {
		return false;
	}
	if (size) {
		ut32 rsz = tps->reg_if.reg_size
			? tps->reg_if.reg_size (tps->reg_if.reg, name)
			: 0;
		*size = rsz? (int)rsz: 64;
	}
	type_trace_voyeur_reg_read (&tps->tt, name, *out);
	return true;
}

static bool tt_esil_mem_read(REsil *esil, ut64 addr, ut8 *buf, int len) {
	TPState *tps = esil->user;
	if (!tps || !tps->mem_if.mem_read) {
		return false;
	}
	if (!tps->mem_if.mem_read (tps->mem_if.mem, addr, buf, len)) {
		return false;
	}
	type_trace_voyeur_mem_read (&tps->tt, addr, buf, len);
	return true;
}

static bool tt_esil_mem_write(REsil *esil, ut64 addr, const ut8 *buf, int len) {
	TPState *tps = esil->user;
	if (!tps || !tps->mem_if.mem_read || !tps->mem_if.mem_write) {
		return false;
	}
	ut8 *old = malloc (len);
	if (!old) {
		return false;
	}
	if (!tps->mem_if.mem_read (tps->mem_if.mem, addr, old, len)) {
		memset (old, 0xff, len);
	}
	bool ret = tps->mem_if.mem_write (tps->mem_if.mem, addr, buf, len);
	if (ret) {
		type_trace_voyeur_mem_write (&tps->tt, addr, old, buf, len);
	}
	free (old);
	return ret;
}

static TPState *tps_init(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal && anal->iob.io && anal->esil, NULL);
	RIO *io = anal->iob.io;
	TPState *tps = R_NEW0 (TPState);
	tps->anal = anal;
	int align = r_arch_info (anal->arch, R_ARCH_INFO_DATA_ALIGN);
	align = R_MAX (r_arch_info (anal->arch, R_ARCH_INFO_CODE_ALIGN), align);
	align = R_MAX (align, 1);
	tps->stack_base = anal->coreb.cfgGetI? anal->coreb.cfgGetI (anal->coreb.core, "esil.stack.addr"): 0x100000;
	ut64 stack_size = anal->coreb.cfgGetI? anal->coreb.cfgGetI (anal->coreb.core, "esil.stack.size"): 0xf0000;
	// ideally this all would happen in a dedicated temporal io bank
	if (anal->iob.map_locate && !anal->iob.map_locate (io, &tps->stack_base, stack_size, align)) {
		free (tps);
		return NULL;
	}
	char *uri = r_str_newf ("malloc://0x%" PFMT64x, stack_size);
	if (!uri) {
		free (tps);
		return NULL;
	}
	tps->stack_fd = anal->iob.fd_open? anal->iob.fd_open (io, uri, R_PERM_RW, 0): -1;
	free (uri);
	if (tps->stack_fd < 0) {
		free (tps);
		return NULL;
	}
	RIOMap *map = anal->iob.map_add? anal->iob.map_add (io, tps->stack_fd, R_PERM_RW, 0, tps->stack_base, stack_size): NULL;
	if (!map) {
		if (anal->iob.fd_close) {
			anal->iob.fd_close (io, tps->stack_fd);
		}
		free (tps);
		return NULL;
	}
	// XXX: r_reg_clone should be invoked in type_trace_init
	RReg *reg = r_reg_clone (anal->reg);
	if (!reg) {
		if (anal->iob.fd_close) {
			anal->iob.fd_close (io, tps->stack_fd);
		}
		free (tps);
		return NULL;
	}
	tps->stack_map = map->id;
	tps->reg_if.reg = reg;
	tps->reg_if.is_reg = tt_is_reg;
	tps->reg_if.reg_read = tt_reg_read;
	tps->reg_if.reg_write = (REsilRegWrite)r_reg_setv;
	tps->reg_if.reg_size = tt_reg_size;
	tps->mem_if.mem = tps;
	tps->mem_if.mem_read = tt_mem_read;
	tps->mem_if.mem_write = tt_mem_write;
	ut64 sp = tps->stack_base + stack_size - (stack_size % align) - align * 8;
	// todo: this probably needs some boundary checks
	r_reg_setv (reg, "SP", sp);
	r_reg_setv (reg, "BP", sp);
	if (!r_esil_init (&tps->esil, 4096, false, anal->config->bits, &tps->reg_if, &tps->mem_if)) {
		r_reg_free (reg);
		if (anal->iob.fd_close) {
			anal->iob.fd_close (io, tps->stack_fd);
		}
		free (tps);
		return NULL;
	}
	tps->esil.user = tps;
	tps->esil.cb.reg_read = tt_esil_reg_read;
	tps->esil.cb.reg_write = tt_esil_reg_write;
	tps->esil.cb.mem_read = tt_esil_mem_read;
	tps->esil.cb.mem_write = tt_esil_mem_write;

	if (!type_trace_init (&tps->tt, &tps->esil, reg)) {
		r_esil_fini (&tps->esil);
		r_reg_free (reg);
		if (anal->iob.fd_close) {
			anal->iob.fd_close (io, tps->stack_fd);
		}
		free (tps);
		return NULL;
	}
	tps->esil.anal = anal;
	// Config hold requires RConfig which we get through coreb.core
	void *core = anal->coreb.core;
	if (core && anal->coreb.cfgGet && anal->coreb.cfgGetB) {
		const char *spec = anal->coreb.cfgGet (core, "anal.types.spec");
		tps->cfg_spec = strdup (spec? spec: "gcc");
		tps->cfg_breakoninvalid = anal->coreb.cfgGetB (core, "esil.breakoninvalid");
		tps->cfg_chk_constraint = anal->coreb.cfgGetB (core, "anal.types.constraint");
		tps->cfg_rollback = anal->coreb.cfgGetB (core, "anal.types.rollback");
		if (anal->coreb.cfgGetI && anal->coreb.cmd) {
			tps->old_follow = anal->coreb.cfgGetI (core, "dbg.follow");
			anal->coreb.cmd (core, "e dbg.follow=0");
		}
	} else {
		tps->cfg_spec = strdup ("gcc");
		tps->cfg_breakoninvalid = false;
		tps->cfg_chk_constraint = false;
		tps->cfg_rollback = false;
	}
	tps->tt.enable_rollback = tps->cfg_rollback;
	return tps;
}

R_API void r_anal_type_match(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (anal && fcn);

	// const int op_tions = R_ARCH_OP_MASK_BASIC ;//| R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT;
	const int op_tions = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_ESIL;
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = { 0 };
	bool resolved = false;
	Sdb *TDB = anal->sdb_types;
	int ret;
	const int mininstrsz = r_anal_archinfo (anal, R_ARCH_INFO_MINOP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	int cur_idx, prev_idx = 0;
	TPState *tps = tps_init (anal);
	if (!tps) {
		return;
	}

	tps->tt.cur_idx = 0;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config);
	char *fcn_name = NULL;
	char *ret_type = NULL;
	bool str_flag = false;
	bool prop = false;
	bool prev_var = false;
	char prev_type[256] = { 0 };
	const char *prev_dest = NULL;
	char *ret_reg = NULL;
	r_cons_break_push (r_cons_singleton (), NULL, NULL);
	RVecBuf buf;
	RVecBuf_init (&buf);
	RVecUT64 bblist;
	RVecUT64_init (&bblist);
	RAnalOp *next_op = R_NEW0 (RAnalOp);
	r_list_sort (fcn->bbs, bb_cmpaddr); // TODO: The algorithm can be more accurate if blocks are followed by their jmp/fail, not just by address
	int retries = 2;
repeat:
	if (retries < 0) {
		R_FREE (next_op);
		tps_fini (tps);
		return;
	}
	if (tps->cfg_rollback && retries < 2) {
		type_trace_rollback (&tps->tt, &tps->esil);
	}
	RVecUT64_clear (&bblist);
	size_t bblist_size = r_list_length (fcn->bbs); // TODO: Use ut64
	RVecUT64_reserve (&bblist, bblist_size);
	// TODO: add a dependency graph out of it, maybe just saving the depth index is enough so we save and restore the state on each level
	r_list_foreach (fcn->bbs, it, bb) {
		RVecUT64_push_back (&bblist, &bb->addr);
	}
	int i, j;
	TypeTrace *etrace = &tps->tt;
	RIO *io = anal->iob.io;
	for (j = 0; j < bblist_size; j++) {
		const ut64 bbat = *RVecUT64_at (&bblist, j);
		bb = r_anal_get_block_at (anal, bbat);
		if (!bb) {
			R_LOG_WARN ("basic block at 0x%08" PFMT64x " was removed during analysis", bbat);
			retries--;
			goto repeat;
		}
		ut64 bb_addr = bb->addr;
		ut64 bb_size = bb->size;
		const ut64 buf_size = bb->size + 32;
		if (!RVecBuf_reserve (&buf, buf_size)) {
			break;
		}
		ut8 *buf_ptr = R_VEC_START_ITER (&buf);
		if (!anal->iob.read_at || anal->iob.read_at (io, bb_addr, buf_ptr, bb_size) < 1) {
			break;
		}
		ut64 addr = bb_addr;
		bool have_cached_op = false;
		for (i = 0; i < bb_size;) {
			if (r_cons_is_breaked (r_cons_singleton ())) {
				goto out_function;
			}
			r_reg_setv (etrace->reg, "PC", addr);
			ut64 bb_left = bb_size - i;
			if ((addr >= bb_addr + bb_size) || (addr < bb_addr)) {
				// stop emulating this bb if pc is outside the basic block boundaries
				break;
			}
			if (have_cached_op) {
				// Reuse next_op from previous iteration instead of re-parsing
				aop = *next_op;
				memset (next_op, 0, sizeof (RAnalOp));
				ret = aop.size;
				have_cached_op = false;
			} else {
				ret = r_anal_op (anal, &aop, addr, buf_ptr + i, bb_left, op_tions);
				if (ret <= 0) {
					i += minopcode;
					addr += minopcode;
					r_reg_setv (etrace->reg, "PC", addr);
					r_anal_op_fini (&aop);
					continue;
				}
			}
			const int loop_count = type_trace_loopcount (etrace, addr);
#if 1
			if (loop_count > LOOP_MAX || aop.type == R_ANAL_OP_TYPE_RET) {
				r_anal_op_fini (&aop);
				break;
			}
#endif
			type_trace_loopcount_increment (etrace, addr);
			r_reg_setv (etrace->reg, "PC", addr + aop.size);
			if (!r_anal_op_nonlinear (aop.type)) { // skip jmp/cjmp/trap/ret/call ops
				// this shit probably needs further refactoring. i hate this code
				if (aop.type == R_ANAL_OP_TYPE_ILL || aop.type == R_ANAL_OP_TYPE_UNK) {
					if (tps->cfg_breakoninvalid) {
						R_LOG_ERROR ("step failed at 0x%08" PFMT64x, addr);
						r_anal_op_fini (&aop);
						retries = -1;
						goto repeat;
					}
					goto skip_trace;
				}
				if (!type_trace_op (etrace, &tps->esil, &aop) && tps->cfg_breakoninvalid) {
					R_LOG_ERROR ("step failed at 0x%08" PFMT64x, addr);
					retries--;
					goto repeat;
				}
			}
		skip_trace:
#if 1
			// XXX this code looks wrong and slow maybe is not needed
			// maybe the basic block is gone after the step
			if (i < bblist_size) {
				bb = r_anal_get_block_at (anal, bb_addr);
				if (!bb) {
					R_LOG_WARN ("basic block at 0x%08" PFMT64x " was removed during analysis", *RVecUT64_at (&bblist, i));
					retries--;
					goto repeat;
				}
			}
#endif
			bool userfnc = false;
			cur_idx = etrace_index (etrace) - 1;
			if (cur_idx < 0) {
				cur_idx = 0;
			}
			tps->tt.cur_idx = etrace_index (etrace);
			RAnalVar *var = r_anal_get_used_function_var (anal, aop.addr);

			// Parse next_op with full options so it can be reused as aop next iteration
			if (i + aop.size < bb_size) {
				int left = bb_left - ret;
				if (left < 1) {
					r_anal_op_fini (&aop);
					break;
				}
				int ret2 = r_anal_op (anal, next_op, addr + ret, buf_ptr + i + ret, left, op_tions);
				if (ret2 < 1) {
					r_anal_op_fini (&aop);
					break;
				}
				have_cached_op = true;
			}

			ut32 type = aop.type & R_ANAL_OP_TYPE_MASK;
			if (type == R_ANAL_OP_TYPE_CALL || type & R_ANAL_OP_TYPE_UCALL) {
				char *full_name = NULL;
				RAnalFunction *fcn_call = NULL;
				ut64 callee_addr = UT64_MAX;
				if (type == R_ANAL_OP_TYPE_CALL) {
					fcn_call = r_anal_get_fcn_in (anal, aop.jump, -1);
					if (fcn_call) {
						full_name = fcn_call->name;
						callee_addr = fcn_call->addr;
					}
				} else if (aop.ptr != UT64_MAX) {
					RFlagItem *flag = anal->flb.f? r_flag_get_by_spaces (anal->flb.f, false, aop.ptr, "imports", NULL): NULL;
					if (flag && flag->realname) {
						full_name = flag->realname;
						callee_addr = aop.ptr;
					}
				}
				if (full_name) {
					if (r_type_func_exist (TDB, full_name)) {
						fcn_name = strdup (full_name);
					} else {
						fcn_name = r_type_func_guess (TDB, full_name);
					}
					if (!fcn_name) {
						fcn_name = strdup (full_name);
						userfnc = true;
					}
					const char *Cc = NULL;
					if (fcn_call && fcn_call->callconv) {
						Cc = fcn_call->callconv;
					}
					if (!Cc) {
						Cc = r_anal_cc_func (anal, fcn_name);
					}
					R_LOG_DEBUG ("CC can %s %s", Cc, fcn_name);
					if (Cc && r_anal_cc_exist (anal, Cc)) {
						char *cc = strdup (Cc);
						if (tps->on_call) {
							tps->on_call (tps, callee_addr, fcn_name);
						}
						type_match (tps, fcn_name, addr, bb->addr, cc, prev_idx, userfnc, callee_addr);
						// prev_idx = tps->tt.cur_idx;
						prev_idx = etrace->cur_idx;
						R_FREE (ret_type);
						const char *rt = r_type_func_ret (TDB, fcn_name);
						if (rt) {
							ret_type = strdup (rt);
						}
						R_FREE (ret_reg);
						const char *rr = r_anal_cc_ret (anal, cc);
						if (rr) {
							ret_reg = strdup (rr);
						}
						resolved = false;
						free (cc);
					}
					if (!strcmp (fcn_name, "__stack_chk_fail")) {
						// r_strf_var (query, 32, "%d.addr", cur_idx - 1);
						// ut64 mov_addr = sdb_num_get (trace, query, 0);
						// cur_idx = tps->tt.cur_idx - 2;
						cur_idx = etrace->cur_idx - 2;
						// eprintf (Color_GREEN"ADDROF %d\n"Color_RESET, cur_idx);
						ut64 mov_addr = etrace_addrof (etrace, cur_idx);
						RAnalOp *mop = tp_anal_op (anal, mov_addr, R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_BASIC);
						if (mop) {
							RAnalVar *mopvar = r_anal_get_used_function_var (anal, mop->addr);
							ut32 vt = mop->type & R_ANAL_OP_TYPE_MASK;
							if (vt == R_ANAL_OP_TYPE_MOV) {
								var_rename (anal, mopvar, "canary", addr);
							}
						}
						r_anal_op_free (mop);
					}
					free (fcn_name);
				}
			} else if (!resolved && ret_type && ret_reg) {
				// Forward propgation of function return type
				char src[REGNAME_SIZE] = { 0 };
				// r_strf_var (query, 32, "%d.reg.write", cur_idx);
				// const char *cur_dest = sdb_const_get (trace, query, 0);
				// sdb_const_get (trace, query, 0);
				// cur_idx = tps->tt.cur_idx - 1;
				cur_idx = etrace->cur_idx - 1;
				const char *cur_dest = etrace_regwrite (etrace, cur_idx);
				get_src_regname (anal, aop.addr, src, sizeof (src));
				if (ret_reg && *src && strstr (ret_reg, src)) {
					if (var && aop.direction == R_ANAL_OP_DIR_WRITE) {
						var_retype (anal, var, NULL, ret_type, false, false);
						resolved = true;
					} else if (type == R_ANAL_OP_TYPE_MOV) {
						R_FREE (ret_reg);
						if (cur_dest) {
							ret_reg = strdup (cur_dest);
						}
					}
				} else if (cur_dest) {
					char *foo = strdup (cur_dest);
					char *tmp = strchr (foo, ',');
					if (tmp) {
						*tmp++ = '\0';
					}
					if (ret_reg && (strstr (ret_reg, foo) || (tmp && strstr (ret_reg, tmp)))) {
						resolved = true;
					} else if (type == R_ANAL_OP_TYPE_MOV && (next_op && next_op->type == R_ANAL_OP_TYPE_MOV)) {
						// Progate return type passed using pointer
						// int *ret; *ret = strlen (s);
						// TODO: memref check , dest and next src match
						char nsrc[REGNAME_SIZE] = { 0 };
						get_src_regname (anal, next_op->addr, nsrc, sizeof (nsrc));
						if (ret_reg && *nsrc && strstr (ret_reg, nsrc) && var && aop.direction == R_ANAL_OP_DIR_READ) {
							var_retype (anal, var, NULL, ret_type, true, false);
						}
					}
					free (foo);
				}
			}
			// Type propagation using instruction access pattern
			if (var) {
				bool sign = false;
				if ((type == R_ANAL_OP_TYPE_CMP) && next_op) {
					if (next_op->sign) {
						sign = true;
					} else {
						// cmp [local_ch], rax ; jb
						var_retype (anal, var, NULL, "unsigned", false, true);
					}
				}
				// cmp [local_ch], rax ; jge
				if (sign || aop.sign) {
					var_retype (anal, var, NULL, "signed", false, true);
				}
				// lea rax , str.hello  ; mov [local_ch], rax;
				// mov rdx , [local_4h] ; mov [local_8h], rdx;
				if (prev_dest && (type == R_ANAL_OP_TYPE_MOV || type == R_ANAL_OP_TYPE_STORE)) {
					char reg[REGNAME_SIZE] = { 0 };
					get_src_regname (anal, addr, reg, sizeof (reg));
					bool match = strstr (prev_dest, reg);
					if (str_flag && match) {
						var_retype (anal, var, NULL, "const char *", false, false);
					}
					if (prop && match && prev_var) {
						var_retype (anal, var, NULL, prev_type, false, false);
					}
				}
				if (tps->cfg_chk_constraint && var && (type == R_ANAL_OP_TYPE_CMP && aop.disp != UT64_MAX) && next_op && next_op->type == R_ANAL_OP_TYPE_CJMP) {
					bool jmp = false;
					RAnalOp *jmp_op = { 0 };
					ut64 jmp_addr = next_op->jump;
					RAnalBlock *jmpbb = r_anal_function_bbget_in (anal, fcn, jmp_addr);
					RAnalBlock jbb = { 0 };
					if (jmpbb) {
						// the bb can be invalidated in the loop below, causing
						// a crash, so we copy that into a stack ghosty struct
						jbb.addr = jmpbb->addr;
						jbb.size = jmpbb->size;
					}

					// Check exit status of jmp branch
					for (i = 0; i < MAX_INSTR; i++) {
						jmp_op = tp_anal_op (anal, jmp_addr, R_ARCH_OP_MASK_BASIC);
						if (!jmp_op) {
							r_anal_op_free (jmp_op);
							r_anal_op_fini (&aop);
							break;
						}
						if ((jmp_op->type == R_ANAL_OP_TYPE_RET && r_anal_block_contains (&jbb, jmp_addr)) || jmp_op->type == R_ANAL_OP_TYPE_CJMP) {
							jmp = true;
							r_anal_op_free (jmp_op);
							r_anal_op_fini (&aop);
							break;
						}
						jmp_addr += jmp_op->size;
						r_anal_op_free (jmp_op);
					}
					RAnalVarConstraint constr = {
						.cond = jmp? cond_invert (anal, next_op->cond): next_op->cond,
						.val = aop.val
					};
					r_anal_var_add_constraint (var, &constr);
				}
			}
			prev_var = (var && aop.direction == R_ANAL_OP_DIR_READ);
			str_flag = false;
			prop = false;
			prev_dest = NULL;
			switch (type) {
			case R_ANAL_OP_TYPE_MOV:
			case R_ANAL_OP_TYPE_LEA:
			case R_ANAL_OP_TYPE_LOAD:
				if (aop.ptr && aop.refptr && aop.ptr != UT64_MAX) {
					if (type == R_ANAL_OP_TYPE_LOAD) {
						ut8 sbuf[256] = { 0 };
						if (anal->iob.read_at) {
							anal->iob.read_at (io, aop.ptr, sbuf, sizeof (sbuf) - 1);
						}
						ut64 ptr = r_read_ble (sbuf, be, aop.refptr * 8);
						if (ptr && ptr != UT64_MAX) {
							RFlagItem *f = anal->flb.f? r_flag_get_by_spaces (anal->flb.f, false, ptr, "strings", NULL): NULL;
							if (f) {
								str_flag = true;
							}
						}
					} else if (anal->flb.f && r_flag_exist_at (anal->flb.f, "str", 3, aop.ptr)) {
						str_flag = true;
					}
				}
				// mov dword [local_4h], str.hello;
				if (var && str_flag) {
					var_retype (anal, var, NULL, "const char *", false, false);
				}
				prev_dest = etrace_regwrite (etrace, cur_idx);
				if (var) {
					r_str_ncpy (prev_type, var->type, sizeof (prev_type) - 1);
					prop = true;
				}
			}
			i += ret;
			addr += ret;
			r_anal_op_fini (&aop);
		}
		// Clean up any cached op that wasn't used (e.g., at end of BB)
		if (have_cached_op) {
			r_anal_op_fini (next_op);
		}
		if (tps->cfg_rollback) {
			type_trace_rollback_clear (etrace);
		}
	}

	// Type propagation for register based args
	RList *list = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_REG);
	RAnalVar *rvar;
	RListIter *iter;
	r_list_foreach (list, iter, rvar) {
		RAnalVar *lvar = r_anal_var_get_dst_var (rvar);
		RRegItem *i = r_reg_index_get (anal->reg, rvar->delta);
		if (i && lvar) {
			// Propagate local var type = to => register-based var
			var_retype (anal, rvar, NULL, lvar->type, false, false);
			// Propagate local var type <= from = register-based var
			var_retype (anal, lvar, NULL, rvar->type, false, false);
		}
	}
	r_list_free (list);
out_function:
	R_FREE (next_op);
	R_FREE (ret_reg);
	R_FREE (ret_type);
	r_anal_op_fini (&aop);
	r_cons_break_pop (r_cons_singleton ());
	RVecBuf_fini (&buf);
	RVecUT64_fini (&bblist);
	tps_fini (tps);
}
// TODO: infer const qualifier from usage patterns
// TODO: struct/union field type propagation

static bool tp_requirements_met(RAnal *anal, bool noisy) {
	if (!anal) {
		if (noisy) {
			R_LOG_WARN ("analysis context not ready");
		}
		return false;
	}
	if (!anal->iob.io) {
		if (noisy) {
			R_LOG_WARN ("IO not ready");
		}
		return false;
	}
	if (!anal->esil) {
		if (noisy) {
			R_LOG_WARN ("Run 'aei' to initialize ESIL");
		}
		return false;
	}
	bool is_debug = anal->coreb.cfgGetB? anal->coreb.cfgGetB (anal->coreb.core, "cfg.debug"): false;
	if (is_debug) {
		if (noisy) {
			R_LOG_WARN ("Type propagation is disabled in debugger mode");
		}
		return false;
	}
	return true;
}

static RAnalOp *tp_anal_op(RAnal *anal, ut64 addr, int mask) {
	R_RETURN_VAL_IF_FAIL (anal, NULL);
	int maxopsz = r_anal_archinfo (anal, R_ARCH_INFO_MAXOP_SIZE);
	if (maxopsz <= 0) {
		maxopsz = 32;
	}
	ut8 stack_buf[64];
	ut8 *buf = stack_buf;
	if (maxopsz > (int)sizeof (stack_buf)) {
		buf = malloc (maxopsz);
		if (!buf) {
			return NULL;
		}
	}
	RAnalOp *op = NULL;
	if (!anal->iob.read_at || anal->iob.read_at (anal->iob.io, addr, buf, maxopsz) < 1) {
		goto beach;
	}
	op = R_NEW0 (RAnalOp);
	if (!op) {
		goto beach;
	}
	if (r_anal_op (anal, op, addr, buf, maxopsz, mask) < 1) {
		r_anal_op_free (op);
		op = NULL;
		goto beach;
	}
beach:
	if (buf != stack_buf) {
		free (buf);
	}
	return op;
}

static RCoreHelpMessage help_msg_tp = {
	"Usage:", "a:tp", "propagate types for current function",
	"a:tp", "all", "propagate types for every function (aaft)",
	"a:tp", "?", "show this help",
	NULL
};

static bool tp_cmd(RAnal *anal, const char *input) {
	R_RETURN_VAL_IF_FAIL (anal && input, false);
	if (!r_str_startswith (input, "tp")) {
		return false;
	}
	const char *args = r_str_trim_head_ro (input + 2);
	void *core = anal->coreb.core;
	if (*args == '?') {
		if (anal->coreb.help && core) {
			anal->coreb.help (core, help_msg_tp);
		}
		return true;
	}
	if (!core) {
		return true;
	}
	if (!tp_requirements_met (anal, true)) {
		return true;
	}
	if (!*args) {
		ut64 cur_addr = anal->coreb.numGet? anal->coreb.numGet (core, "$$"): 0;
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, cur_addr, -1);
		if (!fcn) {
			R_LOG_WARN ("Cannot find function at current offset");
			return true;
		}
		r_cons_break_push (r_cons_singleton (), NULL, NULL);
		r_esil_set_pc (anal->esil, fcn->addr);
		r_anal_type_match (anal, fcn);
		r_cons_break_pop (r_cons_singleton ());
		return true;
	}
	if (!strcmp (args, "all")) {
		if (anal->coreb.cmd) {
			anal->coreb.cmd (core, "aaft");
		} else {
			R_LOG_WARN ("Cannot run 'aaft' because core bindings are missing");
		}
		return true;
	}
	if (anal->coreb.help && core) {
		anal->coreb.help (core, help_msg_tp);
	}
	return true;
}

static bool tp_plugin_eligible(RAnal *anal) {
	return tp_requirements_met (anal, false);
}

RAnalPlugin r_anal_plugin_tp = {
	.meta = {
		.name = "tp",
		.desc = "Type propagation analysis",
		.author = "radare2",
		.license = "LGPL3",
	},
	.depends = "esil",
	.cmd = tp_cmd,
	.eligible = tp_plugin_eligible,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_tp,
	.version = R2_VERSION
};
#endif
