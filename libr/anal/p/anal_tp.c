/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type matching - type propagation */

#include <r_anal.h>
#define LOOP_MAX 10
#define TYPE_MATCH_MAX_BACKTRACE 512

enum {
	TP_VOYEUR_REG_READ = 0,
	TP_VOYEUR_REG_WRITE,
	TP_VOYEUR_MEM_READ,
	TP_VOYEUR_MEM_WRITE,
	TP_VOYEUR_NMAX
};

typedef struct {
	char *name;
	ut64 value;
	// TODO: size
} TypeTraceRegAccess;

typedef struct {
	ut64 addr;
	int size;
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
	}
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
	int cur_idx;
	RReg *reg;
	ut32 voy[TP_VOYEUR_NMAX];
	RStrBuf rollback;  // ESIL string to rollback state (inspired by PR #24428)
	bool enable_rollback;
	// TODO: Add REsil instance here
} TypeTrace;

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
	TypeTraceDB *db = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&db->accesses);
	access->reg.name = strdup (name);
	access->reg.value = val;
	access->is_reg = true;
	access->is_write = false;
	update_trace_db_op (db);
}

static void type_trace_voyeur_reg_write(void *user, const char *name, ut64 old, ut64 val) {
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

static void type_trace_voyeur_mem_read(void *user, ut64 addr, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (user && buf && (len > 0));
	TypeTraceDB *db = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&db->accesses);
	access->is_reg = false;
	access->mem.addr = addr;
	access->mem.size = len;
	access->is_write = false;
	update_trace_db_op (db);
}

static void type_trace_voyeur_mem_write(void *user, ut64 addr, const ut8 *old, const ut8 *buf, int len) {
	R_RETURN_IF_FAIL (user && buf && (len > 0));
	TypeTrace *trace = user;
	TypeTraceAccess *access = VecAccess_emplace_back (&trace->db.accesses);
	access->is_reg = false;
	access->mem.addr = addr;
	access->mem.size = len;
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
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_MEM_WRITE]);
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_MEM_READ]);
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_REG_WRITE]);
	r_esil_del_voyeur (esil, trace->voy[TP_VOYEUR_REG_READ]);
	r_reg_free (trace->reg);
	trace->reg = NULL;
	*trace = (const TypeTrace){ 0 };
}

static bool type_trace_op(TypeTrace *trace, REsil *esil, RAnalOp *op) {
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

R_VEC_TYPE(RVecUT64, ut64);
R_VEC_TYPE(RVecBuf, ut8);

#define TP_CHAIN_MAX 4

// bounded deref-offset sequence, outermost hop first: up to TP_CHAIN_MAX
// backtraced hops plus one disp taken from the call/store instruction itself
typedef struct {
	ut64 off[TP_CHAIN_MAX + 1];
	int len;
} TPHopSeq;

// a const member retype kept on call-site evidence, revisited once the whole function is traced
typedef struct {
	char *ptr_type;
	char *type; // already stripped of the const qualifier
	TPHopSeq seq;
	ut64 slot;
	int width;
} TPPendingConst;

static void tp_pending_const_fini(TPPendingConst *pc) {
	free (pc->ptr_type);
	free (pc->type);
}
R_VEC_TYPE_WITH_FINI(RVecTPPendingConst, TPPendingConst, tp_pending_const_fini);

// a var type applied during this pass, with the basic block that evidenced it
typedef struct {
	char *type;
	ut64 bb_addr;
	int rank;
	bool met; // once facts from parallel paths met, only further meets may apply
} TPVarFact;

static void tp_var_fact_kv_free(HtUPKv *kv) {
	TPVarFact *fact = kv->value;
	if (fact) {
		free (fact->type);
		free (fact);
	}
}

static void tp_reach_kv_free(HtUPKv *kv) {
	set_u_free (kv->value);
}

// a function whose call sites state an object size (memset, allocators, ...)
typedef struct {
	char *name;
	int ptr_arg; // arg index whose pointee is constrained, -1 = return value
	int size_arg; // arg index carrying the byte count
	int mul_arg; // second factor (calloc), -1 = none
} TPSizeFn;

static void tp_sizefn_fini(TPSizeFn *f) {
	free (f->name);
}
R_VEC_TYPE_WITH_FINI (RVecTPSizeFn, TPSizeFn, tp_sizefn_fini);

// return-value allocators (malloc, calloc, operator new) join once the ret-side harvest lands
#define TP_SIZEFN_BUILTINS "memset/0/2,bzero/0/1,memcpy/0/2,memcpy/1/2,memmove/0/2,memmove/1/2"

// one function may constrain several pointer operands (memcpy dst and src), so entries key on name + ptr_arg
static void tp_sizefn_set(RVecTPSizeFn *v, const char *name, int ptr_arg, int size_arg, int mul_arg) {
	TPSizeFn *f;
	R_VEC_FOREACH (v, f) {
		if (f->ptr_arg == ptr_arg && !strcmp (f->name, name)) {
			f->size_arg = size_arg;
			f->mul_arg = mul_arg;
			return;
		}
	}
	f = RVecTPSizeFn_emplace_back (v);
	if (f) {
		f->name = strdup (name);
		f->ptr_arg = ptr_arg;
		f->size_arg = size_arg;
		f->mul_arg = mul_arg;
	}
}

static void tp_sizefn_remove(RVecTPSizeFn *v, const char *name) {
	size_t i = RVecTPSizeFn_length (v);
	while (i > 0) {
		i--;
		if (!strcmp (RVecTPSizeFn_at (v, i)->name, name)) {
			RVecTPSizeFn_remove (v, i);
		}
	}
}

static bool tp_sizefn_num(const char *s, int *out) {
	if (!isdigit ((ut8)*s)) {
		return false;
	}
	char *end = NULL;
	const long v = strtol (s, &end, 10);
	if (!end || *end || v < 0 || v > 15) {
		return false;
	}
	*out = (int)v;
	return true;
}

// entries look like name/ptrarg/sizearg[*mularg]; name/- drops a builtin
static void tp_sizefns_init(RVecTPSizeFn *v, const char *extra) {
	char *s = R_STR_ISEMPTY (extra)? strdup (TP_SIZEFN_BUILTINS)
		: r_str_newf (TP_SIZEFN_BUILTINS ",%s", extra);
	RList *entries = r_str_split_list (s, ",", 0);
	RListIter *it;
	char *tok;
	r_list_foreach (entries, it, tok) {
		r_str_trim (tok);
		if (R_STR_ISEMPTY (tok)) {
			continue;
		}
		char *p1 = strchr (tok, '/');
		if (!p1 || tok == p1) {
			R_LOG_WARN ("Ignoring invalid types.sizefns entry for '%s'", tok);
			continue;
		}
		*p1++ = 0;
		if (!strcmp (p1, "-")) {
			tp_sizefn_remove (v, tok);
			continue;
		}
		char *p2 = strchr (p1, '/');
		if (p2) {
			*p2++ = 0;
		}
		int ptr_arg = 0, size_arg = 0, mul_arg = -1;
		char *mul = p2? strchr (p2, '*'): NULL;
		if (mul) {
			*mul++ = 0;
		}
		// return-value entries are rejected until the ret-side harvest exists
		if (!p2 || !tp_sizefn_num (p1, &ptr_arg) || !tp_sizefn_num (p2, &size_arg)
				|| (mul && !tp_sizefn_num (mul, &mul_arg))) {
			R_LOG_WARN ("Ignoring invalid types.sizefns entry for '%s'", tok);
			continue;
		}
		tp_sizefn_set (v, tok, ptr_arg, size_arg, mul_arg);
	}
	r_list_free (entries);
	free (s);
}

static bool tp_sizefn_name_match(const TPSizeFn *f, const char *name) {
	if (R_STR_ISEMPTY (name)) {
		return false;
	}
	const char *dot = r_str_rchr (name, NULL, '.');
	const char *base = dot? dot + 1: name;
	if (!strcmp (f->name, base) || !strcmp (f->name, name)) {
		return true;
	}
	// darwin-style leading underscore
	return *base == '_' && !strcmp (f->name, base + 1);
}

static const TPSizeFn *tp_sizefn_for_arg(const RVecTPSizeFn *v, const char *name, int arg_num) {
	const TPSizeFn *f;
	R_VEC_FOREACH (v, f) {
		if (f->ptr_arg == arg_num && tp_sizefn_name_match (f, name)) {
			return f;
		}
	}
	return NULL;
}

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
	ut64 stack_size;
	int stack_fd;
	ut32 stack_map;
	RAnal *anal;
	// RConfigHold *hc;
	const char *cfg_spec;
	bool cfg_breakoninvalid;
	bool cfg_chk_constraint;
	bool cfg_fields;
	bool cfg_rollback;
	bool old_follow;
	RVecTPSizeFn sizefns; // empty unless types.sizes is set
	RList *clobber; // caller-saved regs to poison across skipped calls (synth only)
	RVecTPPendingConst pending_const;
	HtUP *var_facts; // RAnalVar * => TPVarFact *
	HtUP *reach_cache; // block addr => SetU of reachable block addrs
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

typedef bool (*AccessPredicate)(const TypeTraceAccess *access, void *user);

static const TypeTraceAccess *etrace_find_access(TypeTrace *etrace, ut32 idx, AccessPredicate pred, void *user) {
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

static bool etrace_is_memwrite(const TypeTraceAccess *access, void *user) {
	(void)user;
	return !access->is_reg && access->is_write;
}

static bool etrace_is_memread(const TypeTraceAccess *access, void *user) {
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

static bool etrace_is_regwrite_name(const TypeTraceAccess *access, void *user) {
	const char *rname = (const char *)user;
	return access->is_reg && access->is_write && !strcmp (rname, access->reg.name);
}

static ut64 etrace_memwrite_addr(TypeTrace *etrace, ut32 idx) {
	const TypeTraceAccess *access = etrace_find_access (etrace, idx, etrace_is_memwrite, NULL);
	if (access) {
		return access->mem.addr;
	}
	return 0;
}

static bool etrace_have_memread(TypeTrace *etrace, ut32 idx) {
	return etrace_find_access (etrace, idx, etrace_is_memread, NULL) != NULL;
}

static ut64 etrace_regread_value(TypeTrace *etrace, ut32 idx, const char *rname) {
	const TypeTraceAccess *access = etrace_find_access (etrace, idx, etrace_is_regread, (void *)rname);
	if (access) {
		return access->reg.value;
	}
	return 0;
}

static const char *etrace_regwrite(TypeTrace *etrace, ut32 idx) {
	const TypeTraceAccess *access = etrace_find_access (etrace, idx, etrace_is_regwrite, NULL);
	if (access) {
		return access->reg.name;
	}
	return NULL;
}

/// END ///////////////////// esil trace helpers ///////////////////////

static bool etrace_regwrite_contains(TypeTrace *etrace, ut32 idx, const char *rname) {
	if (!etrace || !rname) {
		return false;
	}
	return etrace_find_access (etrace, idx, etrace_is_regwrite_name, (void *)rname) != NULL;
}

static bool type_pos_hit(TypeTrace *tt, bool in_stack, ut64 sp, int idx, int size, const char *place) {
	if (in_stack) {
		const ut64 write_addr = etrace_memwrite_addr (tt, idx); // AAA -1
		return (write_addr == sp + size);
	}
	return place && etrace_regwrite_contains (tt, idx, place);
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

static bool tp_prim_scalar(const char *t);

// specificity lattice shared by var facts (var=true) and struct member types (var=false)
// vars: 0 default < 1 sign hint < 2 non-pointer < 3 scalar/void pointer < 4 char *, typed pointer or named type
// members: 0 default < 1 prim scalar < 2 void pointer < 3 prim pointer (char * ties) < 4 named type
static int tp_rank(const char *t, bool var) {
	if (R_STR_ISEMPTY (t)) {
		return 0;
	}
	t = r_str_skip_prefix (r_str_trim_head_ro (t), "const ");
	if (R_STR_ISEMPTY (t) || r_str_startswith (t, "undefined")) {
		return 0;
	}
	if (!strchr (t, '*')) {
		if (!strcmp (t, "void")) {
			return 0;
		}
		// member named types outrank prototype scalars; var facts keep a single non-pointer tier
		return var? 2: (tp_prim_scalar (t)? 1: 4);
	}
	if (r_str_startswith (t, "void")) {
		return var? 3: 2;
	}
	// char * is string evidence for a var, so it tops that lattice; for members it ties with the prim pointers
	if (var && r_str_startswith (t, "char")) {
		return 4;
	}
	return tp_prim_scalar (t)? 3: 4;
}

static bool tp_is_float_type(const char *t) {
	return !strcmp (t, "float") || !strcmp (t, "double") || !strcmp (t, "long double");
}

// the meet of facts proven on parallel paths is the weaker side: their common knowledge
static char *tp_type_meet(RAnal *anal, const char *a, int rank_a, const char *b, int rank_b) {
	a = r_str_skip_prefix (a, "const ");
	b = r_str_skip_prefix (b, "const ");
	if (!strcmp (a, b)) {
		return strdup (a);
	}
	// different pointees agree only on being a pointer; ranking one side would make the meet order-dependent
	if (strchr (a, '*') && strchr (b, '*')) {
		return strdup ("void *");
	}
	if (rank_a != rank_b) {
		return strdup (rank_a < rank_b? a: b);
	}
	if (tp_is_float_type (a) && tp_is_float_type (b)) {
		// unequal float spellings always include a 64-bit-or-wider side
		return strdup ("double");
	}
	// equal-rank scalar conflict: the order-independent common knowledge is the wider side's default int
	const ut64 w = R_MAX (r_type_get_bitsize (anal->sdb_types, a), r_type_get_bitsize (anal->sdb_types, b));
	switch (w) {
	case 64: return strdup ("int64_t");
	case 16: return strdup ("int16_t");
	case 8: return strdup ("int8_t");
	default: return strdup ("int32_t");
	}
}

static bool tp_reach_fill_cb(RAnalBlock *bb, void *user) {
	set_u_add ((SetU *)user, bb->addr);
	return true;
}

static bool tp_block_reaches(TPState *tps, ut64 from, ut64 to) {
	RAnalBlock *bb = r_anal_get_block_at (tps->anal, from);
	if (!bb) {
		// unknown topology counts as sequential, keeping the pre-lattice behavior
		return true;
	}
	bool found = false;
	SetU *reach = ht_up_find (tps->reach_cache, from, &found);
	if (!found) {
		reach = set_u_new ();
		if (!reach) {
			return true;
		}
		r_anal_block_recurse (bb, tp_reach_fill_cb, reach);
		ht_up_insert (tps->reach_cache, from, reach);
	}
	return set_u_contains (reach, to);
}

static bool tp_facts_parallel(TPState *tps, ut64 a, ut64 b) {
	if (a == b || a == UT64_MAX || b == UT64_MAX) {
		return false;
	}
	return !tp_block_reaches (tps, a, b) && !tp_block_reaches (tps, b, a);
}

// the canonical int spelling behind the sized aliases, as the legacy default test expects it
static const char *tp_expand_int(const char *t) {
	if (!strcmp (t, "int32_t")) {
		return "int";
	}
	if (!strcmp (t, "uint32_t")) {
		return "unsigned int";
	}
	if (!strcmp (t, "uint64_t")) {
		return "unsigned long long";
	}
	return t;
}

// canonical spelling as the retype applies it; NULL when a prefix form cannot attach to the var's current type
static char *tp_built_type(RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
	bool is_ptr = (vname && *vname == '*');
	const char *tmp = strstr (tp_expand_int (var->type), "int");
	RStrBuf sb;
	r_strbuf_init (&sb);
	if (pfx) {
		if (tmp && !r_str_startswith (var->type, "signed")) {
			r_strbuf_setf (&sb, "%s %s", type, tmp);
		} else {
			r_strbuf_fini (&sb);
			return NULL;
		}
	} else {
		r_strbuf_set (&sb, type);
	}
	if (r_str_startswith (r_strbuf_get (&sb), "const ")) {
		// Dropping const from type
		// TODO: Inferring const type
		r_strbuf_setf (&sb, "%s", type + 6);
	}
	if (is_ptr) {
		// type *ptr => type *
		r_strbuf_append (&sb, " *");
	}
	while (ref > 0) {
		if (r_str_endswith (r_strbuf_get (&sb), "*")) { // type * => type **
			r_strbuf_append (&sb, "*");
		} else { //  type => type *
			r_strbuf_append (&sb, " *");
		}
		ref--;
	}
	while (ref < 0) {
		char *s = r_strbuf_get (&sb);
		if (!s) {
			break;
		}
		r_str_trim (s);
		if (r_str_endswith (s, "*")) {
			r_strbuf_slice (&sb, 0, r_strbuf_length (&sb) - 1);
		}
		ref++;
	}

	char *tmp1 = r_strbuf_get (&sb);
	if (r_str_startswith (tmp1, "unsigned long long")) {
		r_strbuf_set (&sb, "uint64_t");
	} else if (r_str_startswith (tmp1, "unsigned")) {
		r_strbuf_set (&sb, "uint32_t");
	} else if (r_str_startswith (tmp1, "int")) {
		r_strbuf_set (&sb, "int32_t");
	}
	return r_strbuf_drain_nofree (&sb);
}

// applies newtype to the var and takes ownership of it as the recorded fact
static void tp_fact_apply(RAnal *anal, TPVarFact *fact, RAnalVar *var, char *newtype, int rank, ut64 baddr) {
	r_anal_var_set_type (anal, var, newtype);
	free (fact->type);
	fact->type = newtype;
	fact->rank = rank;
	fact->bb_addr = baddr;
}

// a fact for this var is already on record, so the lattice decides instead of the legacy default checks
static void tp_fact_retype(TPState *tps, ut64 baddr, TPVarFact *fact, RAnalVar *var,
		const char *vname, const char *type, int ref, bool pfx) {
	RAnal *anal = tps->anal;
	char *cand = tp_built_type (var, vname, type, ref, pfx);
	if (!cand) {
		// a prefix that cannot attach to the current spelling keeps the incumbent, like before the lattice
		return;
	}
	const int rank = pfx? 1: tp_rank (cand, true);
	if (!strcmp (cand, fact->type)) {
		free (cand);
		return;
	}
	if (fact->rank == 1 && rank == 1) {
		// legacy sign semantics: unsigned upgrades to signed, width kept from the current spelling
		tp_fact_apply (anal, fact, var, cand, 1, baddr);
		return;
	}
	if (rank == 1) {
		// sign hints come from weak compare heuristics and never weaken stronger facts
		free (cand);
		return;
	}
	if (fact->rank == 1) {
		// any real fact beats a sign hint, on any path
		tp_fact_apply (anal, fact, var, cand, rank, baddr);
		return;
	}
	if (fact->met || tp_facts_parallel (tps, fact->bb_addr, baddr)) {
		char *met = tp_type_meet (anal, fact->type, fact->rank, cand, rank);
		free (cand);
		fact->met = true;
		if (!met || !strcmp (met, fact->type)) {
			free (met);
			return;
		}
		tp_fact_apply (anal, fact, var, met, tp_rank (met, true), baddr);
	} else if (rank > fact->rank) {
		tp_fact_apply (anal, fact, var, cand, rank, baddr);
	} else {
		free (cand);
	}
}

// concrete argloc value at the current emulated call site; stack slots read from the ESIL map
static bool tp_argloc_val(TPState *tps, const char *cc, int argno, int wordsz, ut64 *val) {
	RAnal *anal = tps->anal;
	const char *place = r_anal_cc_argloc (anal, cc, argno, 0, -1);
	if (R_STR_ISEMPTY (place)) {
		return false;
	}
	if (*place != '^') {
		*val = r_reg_getv (tps->tt.reg, place);
		return true;
	}
	if (place[1] == '-') {
		return false; // reversed stack conventions are not resolved here
	}
	ut64 off;
	if (isdigit ((ut8)place[1])) {
		off = (ut64)atoi (place + 1);
	} else {
		// bare ^ slots count from the convention's first stack argument
		int first = argno, i;
		for (i = 0; i < argno; i++) {
			const char *p = r_anal_cc_argloc (anal, cc, i, 0, -1);
			if (p && *p == '^') {
				first = i;
				break;
			}
		}
		off = (ut64)(argno - first) * wordsz;
	}
	ut8 buf[8] = {0};
	const ut64 addr = r_reg_getv (tps->tt.reg, "SP") + off;
	if (wordsz > (int)sizeof (buf) || !anal->iob.read_at
			|| !anal->iob.read_at (anal->iob.io, addr, buf, wordsz)) {
		return false;
	}
	*val = r_read_ble (buf, R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config), wordsz * 8);
	return true;
}

#define TP_SIZEFN_MAXSZ 0x100000 // sizes past 1 MiB are dynamic or stale register values

// pointer and computed size operands of a size-fn call, false when unresolvable or zero
static bool tp_sizefn_read(TPState *tps, const char *cc, const TPSizeFn *sf, int wordsz, ut64 *pv, ut64 *n) {
	if (!tp_argloc_val (tps, cc, sf->ptr_arg, wordsz, pv)
			|| !tp_argloc_val (tps, cc, sf->size_arg, wordsz, n)) {
		return false;
	}
	if (sf->mul_arg >= 0) {
		ut64 m = 0;
		if (!tp_argloc_val (tps, cc, sf->mul_arg, wordsz, &m) || !m || *n > UT64_MAX / m) {
			return false;
		}
		*n *= m;
	}
	return *n > 0;
}

// exact stack-object size stated for this argument by a size-fn entry, 0 when absent
static ut64 tp_sizefn_arg_stacksize(TPState *tps, const char *cc, const char *fcn_name, int arg_num, int wordsz, ut64 *pv_out) {
	const TPSizeFn *sf = tp_sizefn_for_arg (&tps->sizefns, fcn_name, arg_num);
	ut64 pv = 0, n = 0;
	if (!sf || !tp_sizefn_read (tps, cc, sf, wordsz, &pv, &n) || n >= TP_SIZEFN_MAXSZ) {
		return 0;
	}
	// only a pointer into the emulated stack maps back to a stack variable
	if (pv < tps->stack_base || pv >= tps->stack_base + tps->stack_size) {
		return 0;
	}
	*pv_out = pv;
	return n;
}

// the op at idx must have materialized exactly the pointer value the size-fn call received
static bool tp_selfsize_hit(TPState *tps, ut32 idx, RAnalVar *var, const char *rname, ut64 pv) {
	if (!var || var->isarg || (var->kind != R_ANAL_VAR_KIND_BPV && var->kind != R_ANAL_VAR_KIND_SPV)) {
		return false;
	}
	if (R_STR_ISEMPTY (rname) || etrace_have_memread (&tps->tt, idx)) {
		return false;
	}
	const TypeTraceAccess *a = etrace_find_access (&tps->tt, idx, etrace_is_regwrite_name, (void *)rname);
	return a && a->reg.value == pv;
}

// a memset-style call on a stack var's address states the object's exact size
static void tp_selfsize_var(TPState *tps, ut64 baddr, RAnalVar *var, ut64 n) {
	RAnal *anal = tps->anal;
	TPVarFact *fact = ht_up_find (tps->var_facts, (ut64)(size_t)var, NULL);
	const char *cur = fact? fact->type: var->type;
	if (r_str_startswith (cur, "uint8_t [")) {
		// clears on parallel paths merge to the larger stated size, independent of sweep order
		if (n <= strtoull (cur + strlen ("uint8_t ["), NULL, 10)) {
			return;
		}
	} else {
		if (fact && fact->rank > 2) {
			return; // pointer facts are stronger evidence than a size
		}
		if (!tp_prim_scalar (cur)) {
			return; // named and debug-provided types stay
		}
		if (n * 8 < r_type_get_bitsize (anal->sdb_types, cur)) {
			return; // a partial copy or clear cannot shrink the var below its own width
		}
	}
	char *nt = r_str_newf ("uint8_t [%" PFMT64u "]", n);
	if (!nt) {
		return;
	}
	if (fact) {
		// byte-array evidence sits on the pointer tier: above plain scalars, below typed pointers
		tp_fact_apply (anal, fact, var, nt, 3, baddr);
		return;
	}
	r_anal_var_set_type (anal, var, nt);
	TPVarFact *nf = R_NEW0 (TPVarFact);
	nf->type = nt;
	nf->rank = 3;
	nf->bb_addr = baddr;
	ht_up_insert (tps->var_facts, (ut64)(size_t)var, nf);
}

static void var_retype_impl(RAnal *anal, TPState *tps, ut64 baddr, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
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
		// default or void type carries no fact
		return;
	}
	TPVarFact *fact = tps? ht_up_find (tps->var_facts, (ut64)(size_t)var, NULL): NULL;
	if (fact) {
		tp_fact_retype (tps, baddr, fact, var, vname, type, ref, pfx);
		return;
	}
	bool is_default = strstr (tp_expand_int (var->type), "int") != NULL;
	if (!is_default && !r_str_startswith (var->type, "void")) {
		// type is already propagated; only "void *" => "char *" stays possible
		return;
	}
	char *nt = tp_built_type (var, vname, type, ref, pfx);
	if (!nt) {
		return;
	}
	r_anal_var_set_type (anal, var, nt);
	if (tps) {
		TPVarFact *nf = R_NEW0 (TPVarFact);
		nf->type = nt;
		nf->rank = pfx? 1: tp_rank (nt, true);
		nf->bb_addr = baddr;
		ht_up_insert (tps->var_facts, (ut64)(size_t)var, nf);
	} else {
		free (nt);
	}
}

// lattice-exempt path for callee-side retypes that carry no per-block fact
static void var_retype(RAnal *anal, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
	var_retype_impl (anal, NULL, UT64_MAX, var, vname, type, ref, pfx);
}

static void tp_var_retype(TPState *tps, ut64 baddr, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx) {
	var_retype_impl (tps->anal, tps, baddr, var, vname, type, ref, pfx);
}

static RAnalOp *tp_anal_op(RAnal *anal, ut64 addr, int mask);

static void get_src_regname_from_esil(RAnal *anal, const char *op_esil, ut64 addr, char *regname, int size) {
	if (!anal || !op_esil || !regname || size < 1) {
		return;
	}
	regname[0] = 0;
	if (!*op_esil) {
		return;
	}
	char src[64];
	const char *comma = strchr (op_esil, ',');
	size_t src_len = comma? (size_t)(comma - op_esil): strlen (op_esil);
	if (src_len >= sizeof (src)) {
		return;
	}
	memcpy (src, op_esil, src_len);
	src[src_len] = 0;
	RRegItem *ri = r_reg_get (anal->reg, src, -1);
	if (ri) {
		const char *s = src;
		if ((anal->config->bits == 64) && (ri->size == 32)) {
			const char *reg = r_reg_32_to_64 (anal->reg, src);
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
		R_LOG_DEBUG ("no regitem %s at 0x%" PFMT64x, src, addr);
	}
}

static ut64 get_addr(TypeTrace *et, const char *regname, int idx) {
	if (R_STR_ISEMPTY (regname)) {
		return 0;
	}
	/// r_strf_var (query, 64, "%d.reg.read.%s", idx, regname);
	// return r_num_math (NULL, sdb_const_get (trace, query, 0));
	return etrace_regread_value (et, idx, regname);
}

static bool is_reg_token_char(char ch) {
	return ch == '_' || isalnum ((ut8)ch);
}

static bool reg_token_contains_len(const char *regs, const char *reg, size_t reg_len) {
	if (R_STR_ISEMPTY (regs) || !reg || !reg_len) {
		return false;
	}
	const char *end = regs + strlen (regs);
	const char *ptr = regs;
	for (; *ptr; ptr++) {
		if (ptr + reg_len > end) {
			break;
		}
		if ((ptr == regs || !is_reg_token_char (ptr[-1])) && !strncmp (ptr, reg, reg_len) && !is_reg_token_char (ptr[reg_len])) {
			return true;
		}
	}
	return false;
}

static bool reg_token_contains(const char *regs, const char *reg) {
	return R_STR_ISNOTEMPTY (reg)? reg_token_contains_len (regs, reg, strlen (reg)): false;
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
		ptr = r_str_trim_head_digits (ptr);
		r_str_ncpy (arr, ptr, sizeof (arr) - 1);
		char *tmp = arr;
		while (isalpha (*tmp)) {
			tmp++;
		}
		*tmp = '\0';
		const char *type = sdb_const_getf (s, NULL, "spec.%s.%s", tps->cfg_spec, arr);
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
	if (!type) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_function_byname (anal, callee_name);
	if (!fcn) {
		return;
	}
	if (in_stack) {
		RAnalVar *var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_BPV, size - fcn->bp_off + 8);
		if (!var) {
			return;
		}
		// callee vars belong to another function, so their facts stay out of this pass's lattice
		var_retype (anal, var, NULL, type, false, false);
	} else {
		if (R_STR_ISEMPTY (place)) {
			return;
		}
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

static void propagate_arg_type(TPState *tps, ut64 baddr, RAnalVar *var, const char *name, const char *type,
		int var_memref, const char *fcn_name, bool in_stack, const char *place,
		int size, ut64 addr, bool userfnc) {
	RAnal *anal = tps->anal;
	if (userfnc) {
		retype_callee_arg (anal, fcn_name, in_stack, place, size, var->type);
	} else {
		tp_var_retype (tps, baddr, var, name, type, var_memref, false);
		var_rename (anal, var, name, addr);
	}
}

// the prefix must end at a word boundary so named types like printer_t do not rank as scalars
static bool tp_prim_scalar(const char *t) {
	static const char * const prims[] = {
		"int", "uint", "char", "short", "long", "signed", "unsigned",
		"size_t", "ssize_t", "bool", "float", "double", NULL
	};
	size_t i;
	for (i = 0; prims[i]; i++) {
		if (r_str_startswith (t, prims[i])) {
			const char c = t[strlen (prims[i])];
			if (!c || c == ' ' || isdigit ((ut8)c)) {
				return true;
			}
		}
	}
	return false;
}

#define TP_TYPEDEF_MAX 4

static const char *tp_skip_kind_prefix(const char *t) {
	t = r_str_skip_prefix (t, "struct ");
	return r_str_skip_prefix (t, "union ");
}

// follow typedef aliases to the underlying type name; the bound keeps cycles from hanging
static char *tp_unwrap_typedef(RAnal *anal, const char *name) {
	char *cur = strdup (name);
	int depth;
	for (depth = 0; cur && depth < TP_TYPEDEF_MAX; depth++) {
		const char *tgt = sdb_const_getf (anal->sdb_types, NULL, "typedef.%s", cur);
		if (!tgt) {
			break;
		}
		char *next = strdup (tp_skip_kind_prefix (tgt));
		free (cur);
		cur = next;
	}
	return cur;
}

// r_type_get_bitsize returns 32 for any non-char* pointer and 0 for typedefs, so handle both here
static ut64 tp_type_bits(RAnal *anal, const char *t) {
	if (R_STR_ISEMPTY (t)) {
		return 0;
	}
	char *name = tp_unwrap_typedef (anal, t);
	if (!name) {
		return 0;
	}
	const ut64 bits = strchr (name, '*')
		? anal->config->bits: r_type_get_bitsize (anal->sdb_types, name);
	free (name);
	return bits;
}

// reject retypes that would overlap the next member; growing the last member is fine
static bool tp_member_fits(RAnal *anal, RAnalBaseType *bt, const RAnalTypeMember *m, const char *type) {
	const ut64 bits = tp_type_bits (anal, type);
	if (!bits) {
		return false;
	}
	ut64 next = UT64_MAX;
	RAnalTypeMember *it;
	R_VEC_FOREACH (r_anal_base_type_members (bt), it) {
		if (it->offset > m->offset && it->offset < next) {
			next = it->offset;
		}
	}
	return next == UT64_MAX || m->offset + (bits / 8) <= next;
}

// resolve "struct Foo *" / "Foo *" (typedef chains allowed) to the struct base type behind it
static RAnalBaseType *tp_resolve_ptr_base(RAnal *anal, const char *ptr_type) {
	if (R_STR_ISEMPTY (ptr_type)) {
		return NULL;
	}
	char *t = strdup (ptr_type);
	if (!t) {
		return NULL;
	}
	r_str_trim (t);
	char *star = strrchr (t, '*');
	if (!star || star[1]) {   // must be a single-level pointer "... *"
		free (t);
		return NULL;
	}
	*star = 0;
	r_str_trim (t);
	char *name = tp_unwrap_typedef (anal, tp_skip_kind_prefix (t));
	free (t);
	if (!name) {
		return NULL;
	}
	RAnalBaseType *bt = r_anal_get_base_type (anal, name);
	free (name);
	if (bt && bt->kind != R_ANAL_BASE_TYPE_KIND_STRUCT && bt->kind != R_ANAL_BASE_TYPE_KIND_UNION) {
		r_anal_base_type_free (bt);
		return NULL;
	}
	return bt;
}

// the single member at off; a nonzero width disambiguates union members sharing their offset
static RAnalTypeMember *tp_pick_member(RAnal *anal, RAnalBaseType *bt, ut64 off, int width) {
	RAnalTypeMember *m, *cand = NULL;
	R_VEC_FOREACH (r_anal_base_type_members (bt), m) {
		if (m->offset != off) {
			continue;
		}
		if (width && tp_type_bits (anal, m->type) != (ut64)width * 8) {
			continue;
		}
		if (cand) {
			return NULL;
		}
		cand = m;
	}
	// an array member is a deliberate type, neither retype nor follow it
	return (cand && !cand->count)? cand: NULL;
}

// walk deref hops through nested struct pointers and retype the member behind the last one
static bool tp_retype_field_chain(RAnal *anal, const char *ptr_type, const TPHopSeq *seq, const char *type, int width, bool store_dir) {
	if (seq->len < 1 || R_STR_ISEMPTY (type)) {
		return false;
	}
	char *pt = strdup (ptr_type);
	if (!pt) {
		return false;
	}
	bool changed = false;
	int i;
	for (i = 0; i < seq->len; i++) {
		RAnalBaseType *bt = tp_resolve_ptr_base (anal, pt);
		if (!bt) {
			break;
		}
		const bool last = i == seq->len - 1;
		const bool is_union = bt->kind == R_ANAL_BASE_TYPE_KIND_UNION;
		RAnalTypeMember *m = tp_pick_member (anal, bt, seq->off[i], (is_union && last)? width: 0);
		if (!m) {
			r_anal_base_type_free (bt);
			break;
		}
		if (last) {
			// a store into the member disproves an inferred const qualifier
			if (store_dir && r_str_startswith (m->type, "const ")) {
				char *demoted = strdup (r_str_skip_prefix (m->type, "const "));
				if (demoted) {
					free (m->type);
					m->type = demoted;
					changed = true;
				}
			}
			// overlap only matters for structs; union members all start at their shared offset
			const bool fits = is_union || tp_member_fits (anal, bt, m, type);
			if (fits && tp_rank (type, false) > tp_rank (m->type, false)) {
				char *nt = strdup (type);
				if (nt) {
					free (m->type);
					m->type = nt;
					changed = true;
				}
			}
			if (changed) {
				r_anal_save_base_type (anal, bt);
			}
		} else {
			free (pt);
			pt = strdup (m->type);
		}
		r_anal_base_type_free (bt);
		if (!pt) {
			break;
		}
	}
	free (pt);
	return changed;
}

#define REGNAME_SIZE 10

// small positive displacements are plausible field offsets; indexed addressing is array access
static bool tp_field_disp_ok(const RAnalOp *op) {
	return op->disp != UT64_MAX && op->disp < 0x10000 && !op->ireg;
}

// deref displacements seen while backtracing an arg, latest instruction first
typedef struct {
	ut64 hops[TP_CHAIN_MAX];
	ut64 slot_addr; // memread addr of the final field load, for const write evidence
	int width; // access width of the final field load, disambiguates union members
	int len;
	bool ok;
} TPFieldChain;

// hops were collected walking backwards, so append them outermost-first
static void tp_seq_from_chain(TPHopSeq *seq, const TPFieldChain *chain) {
	// the seq must hold a full chain plus the one hop call sites push themselves
	R_STATIC_ASSERT (R_ARRAY_SIZE (((TPHopSeq *)0)->off) >= R_ARRAY_SIZE (((TPFieldChain *)0)->hops) + 1);
	int i;
	for (i = chain->len - 1; i >= 0; i--) {
		seq->off[seq->len++] = chain->hops[i];
	}
}

static bool etrace_memread_first_addr(TypeTrace *etrace, ut32 idx, ut64 *addr) {
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
static bool etrace_memwrite_at(TypeTrace *tt, ut64 addr, int width) {
	const ut64 w = R_MAX (width, 1);
	const TypeTraceAccess *a;
	R_VEC_FOREACH (&tt->db.accesses, a) {
		if (!a->is_reg && a->is_write && a->mem.addr < addr + w && addr < a->mem.addr + a->mem.size) {
			return true;
		}
	}
	return false;
}

// follow the base register of a plain base+disp load and record the disp as a deref hop
static bool tp_chain_collect(TypeTrace *tt, int idx, RAnalOp *op, TPFieldChain *chain, char *regname, int size) {
	if (!chain->ok || !etrace_have_memread (tt, idx)) {
		return false;
	}
	const ut32 ot = op->type & R_ANAL_OP_TYPE_MASK;
	if (ot != R_ANAL_OP_TYPE_MOV && ot != R_ANAL_OP_TYPE_LOAD && ot != R_ANAL_OP_TYPE_PUSH) {
		chain->ok = false;
		return false;
	}
	const RArchValue *v = RVecRArchValue_at (&op->srcs, 0);
	if (!v || !v->reg || !v->memref || v->regdelta) {
		chain->ok = false;
		return false;
	}
	// a stack pointer base is a stack slot, not a field deref
	const char *sp = r_reg_alias_getname (tt->reg, R_REG_ALIAS_SP);
	const char *bp = r_reg_alias_getname (tt->reg, R_REG_ALIAS_BP);
	if ((sp && !strcmp (v->reg, sp)) || (bp && !strcmp (v->reg, bp))) {
		chain->ok = false;
		return false;
	}
	if (!tp_field_disp_ok (op)) {
		chain->ok = false;
		return false;
	}
	if (!chain->len) {
		etrace_memread_first_addr (tt, idx, &chain->slot_addr);
		chain->width = v->memref;
	}
	// a chain deeper than the budget is abandoned, truncating would mistype
	if (chain->len >= (int)R_ARRAY_SIZE (chain->hops)) {
		chain->ok = false;
		return false;
	}
	chain->hops[chain->len++] = op->disp;
	r_str_ncpy (regname, v->reg, size);
	return true;
}

// when a call arg was loaded through struct-pointer derefs, retype the member it came from
static void tp_field_from_arg(TPState *tps, int idx, RAnalVar *var, RAnalOp *op, TPFieldChain *chain, const char *type, bool userfnc) {
	RAnal *anal = tps->anal;
	TypeTrace *tt = &tps->tt;
	if (userfnc || !var || R_STR_ISEMPTY (var->type) || R_STR_ISEMPTY (type)) {
		return;
	}
	if (!chain->ok) {
		return;
	}
	TPHopSeq seq = { .len = 0 };
	ut64 lea_off = 0;
	const ut32 ot = op->type & R_ANAL_OP_TYPE_MASK;
	const bool reg_kind = var->kind == R_ANAL_VAR_KIND_REG;
	const bool memread = etrace_have_memread (tt, idx);
	ut64 slot = chain->len? chain->slot_addr: UT64_MAX;
	if (reg_kind && ot == R_ANAL_OP_TYPE_LEA) {
		if (!tp_field_disp_ok (op)) {
			return;
		}
		if (!chain->len) {
			// out-param: &ctx->field passed to a callee taking T** means the field is a T*
			const char *star = strrchr (type, '*');
			char *deref = star? r_str_ndup (type, star - type): NULL;
			if (deref) {
				r_str_trim (deref);
				const TPHopSeq hop = { .off = { op->disp }, .len = 1 };
				tp_retype_field_chain (anal, var->type, &hop, deref, 0, false);
				free (deref);
			}
			return;
		}
		// lea base+d1 followed by [reg+d2] is a single deref at d1+d2
		lea_off = op->disp;
	} else if (memread) {
		if (ot != R_ANAL_OP_TYPE_LOAD && ot != R_ANAL_OP_TYPE_MOV) {
			return;
		}
		if (reg_kind) {
			// indexed addressing is array access, not a field deref
			if (!tp_field_disp_ok (op)) {
				return;
			}
			if (!chain->len) {
				etrace_memread_first_addr (tt, idx, &slot);
			}
			seq.off[seq.len++] = op->disp;
		}
	} else if (!reg_kind || ot != R_ANAL_OP_TYPE_MOV) {
		return;
	}
	tp_seq_from_chain (&seq, chain);
	if (!seq.len) {
		return;
	}
	if (lea_off) {
		// a lea can only start the chain, so the folded disp lands on the first hop
		seq.off[0] += lea_off;
	}
	const int width = chain->len? chain->width: op->refptr;
	if (r_str_startswith (type, "const ")) {
		const char *unconst = r_str_skip_prefix (type, "const ");
		if (slot == UT64_MAX) {
			// no slot to gather write evidence for, so the qualifier cannot be kept
			tp_retype_field_chain (anal, var->type, &seq, unconst, width, false);
			return;
		}
		// the trace only reaches the call site here, so retype once the whole function ran
		TPPendingConst pc = {
			.ptr_type = strdup (var->type),
			.type = strdup (unconst),
			.seq = seq,
			.slot = slot,
			.width = width
		};
		if (pc.ptr_type && pc.type) {
			RVecTPPendingConst_push_back (&tps->pending_const, &pc);
		} else {
			tp_pending_const_fini (&pc);
		}
		return;
	}
	tp_retype_field_chain (anal, var->type, &seq, type, width, false);
}

// with a deref chain the var holds the base pointer, so only its member is typed
static void tp_apply_arg_type(TPState *tps, ut64 baddr, int j, RAnalVar *var, RAnalOp *op, TPFieldChain *chain,
		const char *name, const char *type, int memref, bool lea_adjust,
		const char *fcn_name, bool in_stack, const char *place, int size, ut64 addr, bool userfnc) {
	if (!tps->cfg_fields || !chain->len) {
		int var_memref = var->isarg? 0: memref;
		if (lea_adjust && op->type == R_ANAL_OP_TYPE_LEA) {
			var_memref--;
		}
		propagate_arg_type (tps, baddr, var, name, type, var_memref,
			fcn_name, in_stack, place, size, addr, userfnc);
	}
	if (tps->cfg_fields) {
		tp_field_from_arg (tps, j, var, op, chain, type, userfnc);
	}
}

// keep a prototype const qualifier only when the field slot shows no write in the whole trace
static void tp_flush_pending_const(TPState *tps) {
	TPPendingConst *pc;
	R_VEC_FOREACH (&tps->pending_const, pc) {
		const bool written = etrace_memwrite_at (&tps->tt, pc->slot, pc->width);
		char *t = written? strdup (pc->type): r_str_newf ("const %s", pc->type);
		if (t) {
			tp_retype_field_chain (tps->anal, pc->ptr_type, &pc->seq, t, pc->width, written);
			free (t);
		}
	}
	RVecTPPendingConst_clear (&tps->pending_const);
}

#define TP_REGCOPY_MAX 4

// resolve a register to the type of the reg arg it was copied from, following copies and deref hops
static char *tp_reg_var_type(TPState *tps, RAnalFunction *fcn, const char *reg, TPFieldChain *chain) {
	RAnal *anal = tps->anal;
	TypeTrace *tt = &tps->tt;
	char cur[REGNAME_SIZE] = { 0 };
	r_str_ncpy (cur, reg, sizeof (cur));
	int j = tt->cur_idx - 1;
	int steps = 0;
	int depth;
	for (depth = 0; depth < TP_REGCOPY_MAX; depth++) {
		bool found = false;
		for (; j >= 0 && steps < TYPE_MATCH_MAX_BACKTRACE; j--, steps++) {
			if (etrace_regwrite_contains (tt, j, cur)) {
				found = true;
				break;
			}
		}
		if (!found) {
			if (j >= 0) {
				// budget exhausted before proving the register untouched
				return NULL;
			}
			// no write since entry, so the reg arg's declared type still holds
			RRegItem *item = r_reg_get (anal->reg, cur, -1);
			if (item) {
				RAnalVar *var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, item->index);
				r_unref (item);
				if (var && R_STR_ISNOTEMPTY (var->type)) {
					return strdup (var->type);
				}
			}
			return NULL;
		}
		RAnalOp *op = tp_anal_op (anal, etrace_addrof (tt, j), R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL);
		if (!op) {
			return NULL;
		}
		const bool copy = (op->type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_MOV && !etrace_have_memread (tt, j);
		char src[REGNAME_SIZE] = { 0 };
		if (copy) {
			get_src_regname_from_esil (anal, r_strbuf_get (&op->esil), op->addr, src, sizeof (src));
		} else {
			// a base+disp load is a deref hop, keep following the base pointer
			tp_chain_collect (tt, j, op, chain, src, sizeof (src));
		}
		r_anal_op_free (op);
		if (!src[0]) {
			return NULL;
		}
		r_str_ncpy (cur, src, sizeof (cur));
		j--;
	}
	return NULL;
}

// a callee return value stored into *(struct-ptr + disp) types the member behind it
static bool tp_field_from_ret(TPState *tps, RAnalFunction *fcn, RAnalOp *op, const char *ret_type) {
	RAnal *anal = tps->anal;
	if (!tps->cfg_fields || R_STR_ISEMPTY (ret_type) || op->direction != R_ANAL_OP_DIR_WRITE) {
		return false;
	}
	RAnalOp *vop = tp_anal_op (anal, op->addr, R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_BASIC);
	if (!vop) {
		return false;
	}
	const RArchValue *dv = RVecRArchValue_at (&vop->dsts, 0);
	char base[REGNAME_SIZE] = { 0 };
	ut64 disp = UT64_MAX;
	// arch plugins may fold zero or large displacements out of op->disp, the dst value keeps them
	if (dv && dv->reg && dv->memref && !dv->regdelta && dv->delta >= 0 && dv->delta < 0x10000) {
		r_str_ncpy (base, dv->reg, sizeof (base));
		disp = dv->delta;
	}
	r_anal_op_free (vop);
	if (!base[0]) {
		return false;
	}
	TPFieldChain chain = { .slot_addr = UT64_MAX, .ok = true };
	char *ptr_type = tp_reg_var_type (tps, fcn, base, &chain);
	if (!ptr_type) {
		return false;
	}
	// the assignment itself disproves const on the member
	ret_type = r_str_skip_prefix (ret_type, "const ");
	TPHopSeq seq = { .len = 0 };
	tp_seq_from_chain (&seq, &chain);
	seq.off[seq.len++] = disp;
	const bool changed = tp_retype_field_chain (anal, ptr_type, &seq, ret_type, op->refptr, true);
	free (ptr_type);
	return changed;
}

#define DEFAULT_MAX 3
#define MAX_INSTR 5

/**
 * type match at a call instruction inside another function
 *
 * \param fcn_name name of the callee
 * \param addr addr of the call instruction
 * \param baddr addr of the basic block containing the call
 * \param cc cc of the callee
 * \param prev_idx index in the esil trace
 * \param userfnc whether the callee is a user function (affects propagation direction)
 */
static void type_match(TPState *tps, char *fcn_name, ut64 addr, ut64 baddr, const char *cc,
	int prev_idx, bool userfnc) {
	RAnal *anal = tps->anal;
	TypeTrace *tt = &tps->tt;
	Sdb *TDB = anal->sdb_types;
	const int idx = etrace_index (tt) - 1;
	const bool verbose = anal->coreb.cfgGetB? anal->coreb.cfgGetB (anal->coreb.core, "types.verbose"): false;
	bool stack_rev = false, in_stack = false, format = false;
	R_LOG_DEBUG ("type_match %s %" PFMT64x " %" PFMT64x " %s %d", fcn_name, addr, baddr, cc, prev_idx);

	if (!fcn_name || !cc) {
		return;
	}
	int i, j, pos = 0, size = 0, max = r_type_func_args_count (TDB, fcn_name);
	int lastarg = ST32_MAX;
	const char *place = r_anal_cc_argloc (anal, cc, lastarg, 0, -1);
	r_cons_break_push (r_cons_singleton (), NULL, NULL);

	if (place && !strcmp (place, "^-")) {
		stack_rev = true;
	}
	place = r_anal_cc_argloc (anal, cc, 0, 0, -1);
	if (place && *place == '^') {
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
		ut64 selfptr = 0;
		const ut64 selfsize = tp_sizefn_arg_stacksize (tps, cc, fcn_name, arg_num, bytes, &selfptr);
		char *owned_type = NULL;
		const char *type = NULL;
		const char *name = NULL;
		R_LOG_DEBUG ("ARG NUM %d %d %d", i, arg_num, format);
		if (format) {
			if (RVecString_empty (&types)) {
				break;
			}
			const String *type_ = RVecString_at (&types, pos++);
			type = type_? *type_: NULL;
			R_LOG_DEBUG ("TYPE (%s)", type);
		} else {
			owned_type = r_type_func_args_type (TDB, fcn_name, arg_num);
			type = owned_type;
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
			const char *p = r_anal_cc_argloc (anal, cc, arg_num, 0, -1);
			if (p && *p == '^') {
				in_stack = true;
				place = p;
			}
			place = p;
		}
		const ut64 sp = in_stack? r_reg_getv (tt->reg, "SP"): 0;
		char regname[REGNAME_SIZE] = { 0 };
		ut64 xaddr = UT64_MAX;
		int memref = 0;
		bool cmt_set = false;
		bool res = false;
		TPFieldChain chain = { .slot_addr = UT64_MAX, .ok = true };
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
			RAnalOp *next_op = tp_anal_op (anal, instr_addr + op->size, R_ARCH_OP_MASK_BASIC);
			if (!next_op || (j != idx && (next_op->type == R_ANAL_OP_TYPE_CALL || next_op->type == R_ANAL_OP_TYPE_JMP))) {
				r_anal_op_free (op);
				r_anal_op_free (next_op);
				break;
			}
			RAnalVar *var = r_anal_get_used_function_var (anal, op->addr);

			bool pos_hit = type_pos_hit (tt, in_stack, sp, j, size, place);
			// once the arg is traced through a deref, earlier dead writes to the arg location are stale
			if (pos_hit && tps->cfg_fields && chain.len > 0 && !etrace_regwrite_contains (tt, j, regname)) {
				pos_hit = false;
			}
			// Match type from function param to instr
			if (pos_hit) {
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
					if (selfsize && tp_selfsize_hit (tps, j, var, place, selfptr)) {
						// the callee clears this stack object, so its stated size types the var
						tp_selfsize_var (tps, baddr, var, selfsize);
					} else {
						R_LOG_DEBUG ("retype var %s", name);
						tp_apply_arg_type (tps, baddr, j, var, op, &chain, name, type, memref, true,
							fcn_name, in_stack, place, size, addr, userfnc);
					}
					res = true;
				} else {
					// a memread is a deref, not a copy, even with a zero displacement
					const bool hop = tps->cfg_fields
						&& tp_chain_collect (tt, j, op, &chain, regname, sizeof (regname));
					if (!hop) {
						char src_reg[REGNAME_SIZE] = { 0 };
						get_src_regname_from_esil (anal, r_strbuf_get (&op->esil), instr_addr, src_reg, sizeof (src_reg));
						if (src_reg[0]) {
							r_str_ncpy (regname, src_reg, sizeof (regname));
						}
						// past a deref the base pointer's value is not the arg value
						xaddr = get_addr (tt, regname, j);
					}
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
					// on stack-argument conventions the var is only reached through the copy chain
					if (selfsize && tp_selfsize_hit (tps, j, var, regname, selfptr)) {
						tp_selfsize_var (tps, baddr, var, selfsize);
					} else {
						tp_apply_arg_type (tps, baddr, j, var, op, &chain, name, type, memref, false,
							fcn_name, in_stack, place, size, addr, userfnc);
					}
					res = true;
				} else {
					switch (op->type) {
					case R_ANAL_OP_TYPE_MOV:
					case R_ANAL_OP_TYPE_PUSH:
						// a memread mov is a deref, not a copy, even with a zero displacement
						if (tps->cfg_fields && op->type == R_ANAL_OP_TYPE_MOV
								&& tp_chain_collect (tt, j, op, &chain, regname, sizeof (regname))) {
							break;
						}
						get_src_regname_from_esil (anal, r_strbuf_get (&op->esil), instr_addr, regname, sizeof (regname));
						break;
					case R_ANAL_OP_TYPE_LEA:
					case R_ANAL_OP_TYPE_LOAD:
					case R_ANAL_OP_TYPE_STORE:
						res = true;
						break;
					default:
						// non-copy op redefined the followed reg; the deref chain is no longer pure
						chain.ok = false;
						break;
					}
				}
			} else if (var && res && (xaddr && xaddr != UT64_MAX)) { // Type progation using value
				char tmp[REGNAME_SIZE] = { 0 };
				get_src_regname_from_esil (anal, r_strbuf_get (&op->esil), instr_addr, tmp, sizeof (tmp));
				ut64 ptr = get_addr (tt, tmp, j);
				if (ptr == xaddr) {
					int var_memref = var->isarg? 0: memref;
					tp_var_retype (tps, baddr, var, name, r_str_get_fail (type, "int"), var_memref, false);
				}
			}
			r_anal_op_free (op);
			r_anal_op_free (next_op);
		}
		size += bytes;
		free (owned_type);
	}
	RVecString_fini (&types);
	r_cons_break_pop (r_cons_singleton ());
}

static int bb_cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return a->addr > b->addr? 1: (a->addr < b->addr? -1: 0);
}

typedef struct {
	HtUP *blocks;
	HtUU *seen;
	RVecUT64 postorder;
} RpoCtx;

static bool rpo_visit(RAnalBlock *bb, void *user) {
	return true;
}

static bool rpo_collect(RAnalBlock *bb, void *user) {
	RpoCtx *ctx = user;
	if (ht_up_find (ctx->blocks, bb->addr, NULL)) {
		ht_uu_update (ctx->seen, bb->addr, 1);
		RVecUT64_push_back (&ctx->postorder, &bb->addr);
	}
	return true;
}

// reverse post-order via r_anal_block_recurse_depth_first's on_exit callback
static bool bblist_from_cfg(RAnalFunction *fcn, RVecUT64 *bblist) {
	RAnalBlock *bb;
	RAnalBlock *entry = NULL;
	RListIter *it;
	RpoCtx ctx = { ht_up_new0 (), ht_uu_new0 () };
	RVecUT64_init (&ctx.postorder);
	if (!ctx.blocks || !ctx.seen) {
		ht_up_free (ctx.blocks);
		ht_uu_free (ctx.seen);
		return false;
	}
	r_list_foreach (fcn->bbs, it, bb) {
		ht_up_insert (ctx.blocks, bb->addr, bb);
		if (!entry && r_anal_block_contains (bb, fcn->addr)) {
			entry = bb;
		}
	}
	if (!entry) {
		ht_up_free (ctx.blocks);
		ht_uu_free (ctx.seen);
		return false;
	}
	r_anal_block_recurse_depth_first (entry, rpo_visit, rpo_collect, &ctx);
	ht_up_free (ctx.blocks);
	ut64 *pa;
	R_VEC_FOREACH_PREV (&ctx.postorder, pa) {
		RVecUT64_push_back (bblist, pa);
	}
	RVecUT64_fini (&ctx.postorder);
	// blocks unreachable from the entry still get emulated, in address order
	r_list_foreach (fcn->bbs, it, bb) {
		bool found = false;
		ht_uu_find (ctx.seen, bb->addr, &found);
		if (!found) {
			RVecUT64_push_back (bblist, &bb->addr);
		}
	}
	ht_uu_free (ctx.seen);
	if (RVecUT64_length (bblist) != r_list_length (fcn->bbs)) {
		RVecUT64_clear (bblist);
		return false;
	}
	return true;
}

static void tps_fini(TPState *tps) {
	R_RETURN_IF_FAIL (tps);
	r_list_free (tps->clobber);
	RVecTPSizeFn_fini (&tps->sizefns);
	ht_up_free (tps->var_facts);
	ht_up_free (tps->reach_cache);
	tp_flush_pending_const (tps);
	RVecTPPendingConst_fini (&tps->pending_const);
	type_trace_fini (&tps->tt, &tps->esil);
	r_esil_fini (&tps->esil);
	if (tps->anal->iob.fd_close) {
		tps->anal->iob.fd_close (tps->anal->iob.io, tps->stack_fd);
	}
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

static ut32 tt_reg_packed_size(void *reg, const char *name) {
	RRegItem *ri = r_reg_get ((RReg *)reg, name, -1);
	if (!ri) {
		return 0;
	}
	const ut32 psize = ri->packed_size > 0 ? (ut32)ri->packed_size : 0;
	r_unref (ri);
	return psize;
}

static bool tt_reg_alias(void *reg, int alias, const char *name) {
	return r_reg_alias_setname ((RReg *)reg, alias, name);
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
	ut8 *old = NULL;
	if (tps->tt.enable_rollback) {
		old = malloc (len);
		if (!old) {
			return false;
		}
		if (!tps->mem_if.mem_read (tps->mem_if.mem, addr, old, len)) {
			memset (old, 0xff, len);
		}
	}
	bool ret = tps->mem_if.mem_write (tps->mem_if.mem, addr, buf, len);
	if (ret) {
		type_trace_voyeur_mem_write (&tps->tt, addr, old, buf, len);
	}
	free (old);
	return ret;
}

// back a located address range with an anonymous malloc:// map; returns the fd or -1
static int tp_map_anon(RAnal *anal, ut64 size, int align, ut64 *base, ut32 *map_id) {
	RIOBind *iob = &anal->iob;
	RIO *io = iob->io;
	if (iob->map_locate && !iob->map_locate (io, base, size, align)) {
		return -1;
	}
	char *uri = r_str_newf ("malloc://0x%" PFMT64x, size);
	const int fd = (uri && iob->fd_open)? iob->fd_open (io, uri, R_PERM_RW, 0): -1;
	free (uri);
	if (fd < 0) {
		return -1;
	}
	RIOMap *map = iob->map_add? iob->map_add (io, fd, R_PERM_RW, 0, *base, size): NULL;
	if (!map) {
		if (iob->fd_close) {
			iob->fd_close (io, fd);
		}
		return -1;
	}
	if (map_id) {
		*map_id = map->id;
	}
	return fd;
}

static TPState *tps_init(RAnal *anal) {
	R_RETURN_VAL_IF_FAIL (anal && anal->iob.io && anal->esil, NULL);
	RIO *io = anal->iob.io;
	TPState *tps = R_NEW0 (TPState);
	tps->anal = anal;
	RVecTPPendingConst_init (&tps->pending_const);
	RVecTPSizeFn_init (&tps->sizefns);
	tps->var_facts = ht_up_new (NULL, tp_var_fact_kv_free, NULL);
	tps->reach_cache = ht_up_new (NULL, tp_reach_kv_free, NULL);
	int align = r_arch_info (anal->arch, R_ARCH_INFO_DATA_ALIGN);
	align = R_MAX (r_arch_info (anal->arch, R_ARCH_INFO_CODE_ALIGN), align);
	align = R_MAX (align, 1);
	tps->stack_base = anal->coreb.cfgGetI? anal->coreb.cfgGetI (anal->coreb.core, "esil.stack.addr"): 0x100000;
	ut64 stack_size = anal->coreb.cfgGetI? anal->coreb.cfgGetI (anal->coreb.core, "esil.stack.size"): 0xf0000;
	tps->stack_size = stack_size;
	// ideally this all would happen in a dedicated temporal io bank
	tps->stack_fd = tp_map_anon (anal, stack_size, align, &tps->stack_base, &tps->stack_map);
	if (tps->stack_fd < 0) {
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
	tps->reg_if.reg = reg;
	tps->reg_if.is_reg = tt_is_reg;
	tps->reg_if.reg_read = tt_reg_read;
	tps->reg_if.reg_write = (REsilRegWrite)r_reg_setv;
	tps->reg_if.reg_alias = tt_reg_alias;
	tps->reg_if.reg_size = tt_reg_size;
	tps->reg_if.reg_packed_size = tt_reg_packed_size;
	tps->mem_if.mem = tps;
	tps->mem_if.mem_read = tt_mem_read;
	tps->mem_if.mem_write = tt_mem_write;
	ut64 sp = tps->stack_base + stack_size - (stack_size % align) - align * 8;
	// todo: this probably needs some boundary checks
	r_reg_setv (reg, "SP", sp);
	r_reg_setv (reg, "BP", sp);
	REsilOptions esil_opt = r_esil_options (NULL, NULL);
	// VM address width, not the decode width (config->bits is 16 on thumb); SP-reg width is the library-mode fallback
	ut64 aw = 64;
	if (anal->coreb.cfgGetI) {
		aw = anal->coreb.cfgGetI (anal->coreb.core, "esil.addr.size");
	} else {
		RRegItem *spri = r_reg_get (reg, "SP", -1);
		if (spri) {
			aw = spri->size? spri->size: aw;
			r_unref (spri);
		}
	}
	esil_opt.addrsize = aw;
	esil_opt.ifaces.reg = tps->reg_if;
	esil_opt.ifaces.mem = tps->mem_if;
	if (!r_esil_init (&tps->esil, &esil_opt)) {
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
		const char *spec = anal->coreb.cfgGet (core, "types.spec");
		tps->cfg_spec = spec? spec: "gcc";
		tps->cfg_breakoninvalid = anal->coreb.cfgGetB (core, "esil.breakoninvalid");
		tps->cfg_chk_constraint = anal->coreb.cfgGetB (core, "types.constraint");
		tps->cfg_fields = anal->coreb.cfgGetB (core, "types.fields");
		tps->cfg_rollback = anal->coreb.cfgGetB (core, "types.rollback");
		if (anal->coreb.cfgGetB (core, "types.sizes")) {
			tp_sizefns_init (&tps->sizefns, anal->coreb.cfgGet (core, "types.sizefns"));
		}
		if (anal->coreb.cfgGetI && anal->coreb.cmd) {
			tps->old_follow = anal->coreb.cfgGetI (core, "dbg.follow");
			anal->coreb.cmd (core, "e dbg.follow=0");
		}
	} else {
		tps->cfg_spec = "gcc";
		tps->cfg_breakoninvalid = false;
		tps->cfg_chk_constraint = false;
		tps->cfg_fields = false;
		tps->cfg_rollback = false;
	}
	tps->tt.enable_rollback = tps->cfg_rollback;
	return tps;
}

typedef struct type_prop_state_t {
	char *ret_type;
	char *ret_reg;
	bool resolved;
	bool userfnc;
	const char *prev_dest;
	RAnalVar *prev_var;
	bool str_flag;
	bool prop;
	char *prev_type;
} TypePropState;

static inline void tp_state_reset(TypePropState *state) {
	state->str_flag = false;
	state->prop = false;
	state->prev_dest = NULL;
}

static inline void tp_state_fini(TypePropState *state) {
	R_FREE (state->ret_type);
	R_FREE (state->ret_reg);
	R_FREE (state->prev_type);
}

typedef enum {
	TP_EMU_DONE = 0,
	TP_EMU_BREAK, // interrupted by the user
	TP_EMU_RETRY, // a block vanished or an esil step failed, the caller may re-run
	TP_EMU_FAIL, // invalid instruction with esil.breakoninvalid set
	TP_EMU_BUDGET, // the max_ops emulation budget was hit; the trace is partial
} TPEmuResult;

// next_op is zeroed when no lookahead op was decoded
typedef void (*TPEmulateOpCb)(void *user, RAnalOp *aop, RAnalOp *next_op, ut64 addr, ut64 bb_addr);

// step the type-trace esil over the linear ops of every block; op_cb also enables the one-op lookahead
static TPEmuResult tp_emulate_linear(TPState *tps, RAnalFunction *fcn, int max_ops, TPEmulateOpCb op_cb, void *user, bool lookahead) {
	RAnal *anal = tps->anal;
	const int op_tions = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_HINT | R_ARCH_OP_MASK_ESIL;
	const int minopcode = R_MAX (1, r_arch_info (anal->arch, R_ARCH_INFO_MINOP_SIZE));
	RAnalOp aop = { 0 };
	int ret, total = 0;
	TPEmuResult res = TP_EMU_DONE;
	RAnalOp *next_op = R_NEW0 (RAnalOp);
	RCons *cons = r_cons_singleton ();
	r_cons_break_push (cons, NULL, NULL);
	RVecBuf buf;
	RVecBuf_init (&buf);
	RVecUT64 bblist;
	RVecUT64_init (&bblist);
	r_list_sort (fcn->bbs, bb_cmpaddr);
	size_t bblist_size = r_list_length (fcn->bbs); // TODO: Use ut64
	RVecUT64_reserve (&bblist, bblist_size);
	RAnalBlock *bb;
	RListIter *it;
	if (!bblist_from_cfg (fcn, &bblist)) {
		R_LOG_DEBUG ("cannot compute cfg order at 0x%08" PFMT64x ", using address order", fcn->addr);
		r_list_foreach (fcn->bbs, it, bb) {
			RVecUT64_push_back (&bblist, &bb->addr);
		}
	}
	int i, j;
	TypeTrace *etrace = &tps->tt;
	RIO *io = anal->iob.io;
	// blocks swept in CFG order still inherit register state across non-adjacent boundaries: a coverage/accuracy tradeoff
	for (j = 0; j < bblist_size; j++) {
		const ut64 bbat = *RVecUT64_at (&bblist, j);
		bb = r_anal_get_block_at (anal, bbat);
		if (!bb) {
			R_LOG_WARN ("basic block at 0x%08" PFMT64x " was removed during analysis", bbat);
			res = TP_EMU_RETRY;
			goto beach;
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
			if (r_cons_is_breaked (cons)) {
				res = TP_EMU_BREAK;
				goto beach;
			}
			if (max_ops && ++total > max_ops) {
				res = TP_EMU_BUDGET;
				goto beach;
			}
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
					r_anal_op_fini (&aop);
					continue;
				}
			}
			if (type_trace_loopcount (etrace, addr) > LOOP_MAX || aop.type == R_ANAL_OP_TYPE_RET) {
				r_anal_op_fini (&aop);
				break;
			}
			type_trace_loopcount_increment (etrace, addr);
			r_reg_setv (etrace->reg, "PC", addr + aop.size);
			if (!r_anal_op_nonlinear (aop.type)) { // skip jmp/cjmp/trap/ret/call ops
				if (aop.type == R_ANAL_OP_TYPE_ILL || aop.type == R_ANAL_OP_TYPE_UNK) {
					if (tps->cfg_breakoninvalid) {
						R_LOG_ERROR ("step failed at 0x%08" PFMT64x, addr);
						r_anal_op_fini (&aop);
						res = TP_EMU_FAIL;
						goto beach;
					}
					goto skip_trace;
				}
				if (!type_trace_op (etrace, &tps->esil, &aop) && tps->cfg_breakoninvalid) {
					R_LOG_ERROR ("step failed at 0x%08" PFMT64x, addr);
					r_anal_op_fini (&aop);
					res = TP_EMU_RETRY;
					goto beach;
				}
			}
		skip_trace:
			if (op_cb) {
				// Parse next_op with full options so it can be reused as aop next iteration
				if (lookahead && i + aop.size < bb_size) {
					int left = bb_left - ret;
					if (left < 1) {
						r_anal_op_fini (&aop);
						break;
					}
					if (r_anal_op (anal, next_op, addr + ret, buf_ptr + i + ret, left, op_tions) < 1) {
						r_anal_op_fini (&aop);
						r_anal_op_fini (next_op);
						break;
					}
					have_cached_op = true;
				}
				op_cb (user, &aop, lookahead? next_op: NULL, addr, bb_addr);
			}
			if (tps->clobber) {
				// UCALL is the base value 4, not a flag, so match on the base type
				const int base = aop.type & 0xff;
				if (base == R_ANAL_OP_TYPE_CALL || base == R_ANAL_OP_TYPE_UCALL) {
					// drop caller-saved sentinels after op_cb so a size-fn harvest still sees the live arg regs
					RListIter *cit;
					const char *rn;
					r_list_foreach (tps->clobber, cit, rn) {
						r_reg_setv (etrace->reg, rn, 0);
					}
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
beach:
	r_anal_op_fini (&aop);
	r_anal_op_free (next_op); // a cached lookahead op may still be live on a break/budget exit
	r_cons_break_pop (cons);
	RVecBuf_fini (&buf);
	RVecUT64_fini (&bblist);
	return res;
}

typedef struct {
	RAnal *anal;
	RAnalFunction *fcn;
	TPState *tps;
	TypePropState tp;
	int prev_idx;
	bool be;
} TypeMatchCtx;

// the called function/import name for a call op, plus its RAnalFunction when direct
static const char *tp_call_target_name(RAnal *anal, RAnalOp *aop, ut32 type, RAnalFunction **fcn_call) {
	*fcn_call = NULL;
	if (type == R_ANAL_OP_TYPE_CALL) {
		*fcn_call = r_anal_get_fcn_in (anal, aop->jump, -1);
		return *fcn_call? (*fcn_call)->name: NULL;
	}
	if (aop->ptr != UT64_MAX && anal->flb.f) {
		RFlagItem *flag = r_flag_get_by_spaces (anal->flb.f, false, aop->ptr, "imports", NULL);
		if (flag) {
			return flag->realname;
		}
	}
	return NULL;
}

// the callee's calling convention: its own when known, else derived from the name
static const char *tp_call_cc(RAnal *anal, RAnalFunction *fcn_call, const char *name) {
	const char *cc = fcn_call? r_anal_function_cc (fcn_call): NULL;
	return cc? cc: r_anal_cc_func (anal, name);
}

// per-op type propagation body run by tp_emulate_linear for r_anal_type_match
static void type_match_op_cb(void *user, RAnalOp *aop, RAnalOp *next_op, ut64 addr, ut64 bb_addr) {
	TypeMatchCtx *c = user;
	RAnal *anal = c->anal;
	TPState *tps = c->tps;
	TypeTrace *etrace = &tps->tt;
	Sdb *TDB = anal->sdb_types;
	char *fcn_name = NULL;
	c->tp.userfnc = false;
	tps->tt.cur_idx = etrace_index (etrace);
	int cur_idx = tps->tt.cur_idx - 1;
	if (cur_idx < 0) {
		cur_idx = 0;
	}
	RAnalVar *var = r_anal_get_used_function_var (anal, aop->addr);
	ut32 type = aop->type & R_ANAL_OP_TYPE_MASK;
	// UCALL is the base value 4, not a flag: type & UCALL also matches STORE and swallows the return-value consumer below
	if (type == R_ANAL_OP_TYPE_CALL || type == R_ANAL_OP_TYPE_UCALL || type == R_ANAL_OP_TYPE_UCCALL) {
		RAnalFunction *fcn_call = NULL;
		const char *full_name = tp_call_target_name (anal, aop, type, &fcn_call);
		if (full_name) {
			if (r_type_func_exist (TDB, full_name)) {
				fcn_name = strdup (full_name);
			} else {
				fcn_name = r_type_func_guess (TDB, full_name);
			}
			if (!fcn_name) {
				fcn_name = strdup (full_name);
				c->tp.userfnc = true;
			}
			const char *Cc = tp_call_cc (anal, fcn_call, fcn_name);
			R_LOG_DEBUG ("CC can %s %s", Cc, fcn_name);
			if (Cc && r_anal_cc_exist (anal, Cc)) {
				type_match (tps, fcn_name, addr, bb_addr, Cc, c->prev_idx, c->tp.userfnc);
				c->prev_idx = etrace->cur_idx;
				R_FREE (c->tp.ret_type);
				const char *rt = r_type_func_ret (TDB, fcn_name);
				if (rt) {
					c->tp.ret_type = strdup (rt);
				}
				R_FREE (c->tp.ret_reg);
				const char *rr = r_anal_cc_ret (anal, Cc, 0);
				if (rr) {
					c->tp.ret_reg = strdup (rr);
				}
				c->tp.resolved = false;
			}
			if (r_str_endswith (fcn_name, "stack_chk_fail")) {
				cur_idx = etrace->cur_idx - 2;
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
	} else if (!c->tp.resolved && c->tp.ret_type && c->tp.ret_reg) {
		// Forward propgation of function return type
		char src[REGNAME_SIZE] = { 0 };
		cur_idx = etrace->cur_idx - 1;
		const char *cur_dest = etrace_regwrite (etrace, cur_idx);
		get_src_regname_from_esil (anal, r_strbuf_get (&aop->esil), aop->addr, src, sizeof (src));
		if (reg_token_contains (c->tp.ret_reg, src)) {
			if (var && aop->direction == R_ANAL_OP_DIR_WRITE) {
				tp_var_retype (tps, bb_addr, var, NULL, c->tp.ret_type, false, false);
				c->tp.resolved = true;
			} else {
				// typing the member must not consume the tracking a later var store relies on
				if (type == R_ANAL_OP_TYPE_MOV || type == R_ANAL_OP_TYPE_STORE) {
					tp_field_from_ret (tps, c->fcn, aop, c->tp.ret_type);
				}
				if (type == R_ANAL_OP_TYPE_MOV) {
					R_FREE (c->tp.ret_reg);
					if (cur_dest) {
						c->tp.ret_reg = strdup (cur_dest);
					}
				}
			}
		} else if (cur_dest) {
			const char *tmp = strchr (cur_dest, ',');
			if (reg_token_contains_len (c->tp.ret_reg, cur_dest, tmp? (size_t)(tmp - cur_dest): strlen (cur_dest))
				|| reg_token_contains (c->tp.ret_reg, tmp? tmp + 1: NULL)) {
				c->tp.resolved = true;
			} else if (type == R_ANAL_OP_TYPE_MOV && (next_op && next_op->type == R_ANAL_OP_TYPE_MOV)) {
				// Progate return type passed using pointer
				// int *ret; *ret = strlen (s);
				// TODO: memref check , dest and next src match
				char nsrc[REGNAME_SIZE] = { 0 };
				get_src_regname_from_esil (anal, r_strbuf_get (&next_op->esil), next_op->addr, nsrc, sizeof (nsrc));
				if (reg_token_contains (c->tp.ret_reg, nsrc) && var && aop->direction == R_ANAL_OP_DIR_READ) {
					tp_var_retype (tps, bb_addr, var, NULL, c->tp.ret_type, true, false);
				}
			}
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
				tp_var_retype (tps, bb_addr, var, NULL, "unsigned", false, true);
			}
		}
		// cmp [local_ch], rax ; jge
		if (sign || aop->sign) {
			tp_var_retype (tps, bb_addr, var, NULL, "signed", false, true);
		}
		// lea rax , str.hello  ; mov [local_ch], rax;
		// mov rdx , [local_4h] ; mov [local_8h], rdx;
		if (c->tp.prev_dest && (type == R_ANAL_OP_TYPE_MOV || type == R_ANAL_OP_TYPE_STORE)) {
			char reg[REGNAME_SIZE] = { 0 };
			get_src_regname_from_esil (anal, r_strbuf_get (&aop->esil), addr, reg, sizeof (reg));
			bool match = reg_token_contains (c->tp.prev_dest, reg);
			if (c->tp.str_flag && match) {
				tp_var_retype (tps, bb_addr, var, NULL, "const char *", false, false);
			}
			if (c->tp.prop && match && c->tp.prev_var) {
				tp_var_retype (tps, bb_addr, var, NULL, c->tp.prev_type, false, false);
			}
		}
		if (tps->cfg_chk_constraint && var && (type == R_ANAL_OP_TYPE_CMP && aop->disp != UT64_MAX) && next_op && next_op->type == R_ANAL_OP_TYPE_CJMP) {
			bool jmp = false;
			RAnalOp *jmp_op = NULL;
			ut64 jmp_addr = next_op->jump;
			RAnalBlock *jmpbb = r_anal_function_bbget_in (anal, c->fcn, jmp_addr);
			RAnalBlock jbb = { 0 };
			if (jmpbb) {
				// Copy only fields needed for r_anal_block_contains check.
				// The bb can be invalidated in the loop below, so avoid
				// shallow-copying pointer members from jmpbb.
				jbb.addr = jmpbb->addr;
				jbb.size = jmpbb->size;
			}

			// Check exit status of jmp branch
			int k;
			for (k = 0; k < MAX_INSTR; k++) {
				jmp_op = tp_anal_op (anal, jmp_addr, R_ARCH_OP_MASK_BASIC);
				if (!jmp_op) {
					break;
				}
				if ((jmp_op->type == R_ANAL_OP_TYPE_RET && r_anal_block_contains (&jbb, jmp_addr)) || jmp_op->type == R_ANAL_OP_TYPE_CJMP) {
					jmp = true;
					r_anal_op_free (jmp_op);
					break;
				}
				jmp_addr += jmp_op->size;
				r_anal_op_free (jmp_op);
			}
			RAnalVarConstraint constr = {
				.cond = jmp? cond_invert (anal, next_op->cond): next_op->cond,
				.val = aop->val
			};
			r_anal_var_add_constraint (var, &constr);
		}
	}
	c->tp.prev_var = (var && aop->direction == R_ANAL_OP_DIR_READ)? var: NULL;
	tp_state_reset (&c->tp);
	switch (type) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_LOAD:
		if (aop->ptr && aop->refptr && aop->ptr != UT64_MAX) {
			if (type == R_ANAL_OP_TYPE_LOAD) {
				ut8 sbuf[256] = { 0 };
				if (anal->iob.read_at) {
					anal->iob.read_at (anal->iob.io, aop->ptr, sbuf, sizeof (sbuf) - 1);
				}
				ut64 ptr = r_read_ble (sbuf, c->be, aop->refptr * 8);
				if (ptr && ptr != UT64_MAX) {
					RFlagItem *f = anal->flb.f? r_flag_get_by_spaces (anal->flb.f, false, ptr, "strings", NULL): NULL;
					if (f) {
						c->tp.str_flag = true;
					}
				}
			} else if (anal->flb.f && r_flag_exist_at (anal->flb.f, "str", 3, aop->ptr)) {
				c->tp.str_flag = true;
			}
		}
		// mov dword [local_4h], str.hello;
		if (var && c->tp.str_flag) {
			tp_var_retype (tps, bb_addr, var, NULL, "const char *", false, false);
		}
		c->tp.prev_dest = etrace_regwrite (etrace, cur_idx);
		if (var) {
			free (c->tp.prev_type);
			c->tp.prev_type = strdup (r_str_get (var->type));
			c->tp.prop = true;
		}
	}
}

R_API void r_anal_type_match(RAnal *anal, RAnalFunction *fcn) {
	R_RETURN_IF_FAIL (anal && fcn);
	TPState *tps = tps_init (anal);
	if (!tps) {
		return;
	}
	tps->tt.cur_idx = 0;
	TypeMatchCtx ctx = {
		.anal = anal,
		.fcn = fcn,
		.tps = tps,
		.be = R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config),
	};
	int retries = 2;
	for (;;) {
		const TPEmuResult res = tp_emulate_linear (tps, fcn, 0, type_match_op_cb, &ctx, true);
		if (res == TP_EMU_DONE || res == TP_EMU_BUDGET) {
			break;
		}
		if (res != TP_EMU_RETRY || retries < 1) {
			goto beach;
		}
		retries--;
		if (tps->cfg_rollback) {
			type_trace_rollback (&tps->tt, &tps->esil);
		}
	}

	// Type propagation for register based args
	RAnalVar **rvarp;
	R_VEC_FOREACH (&fcn->vars, rvarp) {
		RAnalVar *rvar = *rvarp;
		if (rvar->kind != R_ANAL_VAR_KIND_REG) {
			continue;
		}
		RAnalVar *lvar = r_anal_var_get_dst_var (rvar);
		RRegItem *i = r_reg_index_get (anal->reg, rvar->delta);
		if (i && lvar && rvar->type) {
			char *rvar_type = strdup (rvar->type);
			if (rvar_type) {
				// Propagate local var type = to => register-based var
				var_retype (anal, rvar, NULL, lvar->type, false, false);
				// Propagate local var type <= from = register-based var
				var_retype (anal, lvar, NULL, rvar_type, false, false);
				free (rvar_type);
			}
		}
	}
beach:
	tp_state_fini (&ctx.tp);
	tps_fini (tps);
}

static const char *synth_type_for_size(int sz) {
	switch (sz) {
	case 1: return "uint8_t";
	case 2: return "uint16_t";
	case 4: return "uint32_t";
	}
	return "uint64_t";
}

// malloc:// maps are demand-zero, so resident cost tracks the written SYNTH_DETW*MAXARGS, not the full region
#define SYNTH_WINDOW 0x40000ULL // per-arg sentinel window (field offsets capped at WINDOW/2)
#define SYNTH_MAXARGS 8 // args past this are not seeded (not recovered)
#define SYNTH_REGION (SYNTH_WINDOW * SYNTH_MAXARGS) // whole sentinel region
// per-arg span scanned for pointer fields; a pointer field past this is not nested
#define SYNTH_DETW 0x1000ULL
// child-window size per pointer slot; a deref offset past this aliases the next slot and is lost
#define SYNTH_PSTRIDE 0x400ULL
#define SYNTH_SLOTS(psz) (SYNTH_DETW / (psz)) // detectable pointer slots per arg
#define SYNTH_PSIZE(psz) (SYNTH_SLOTS (psz) * SYNTH_MAXARGS * SYNTH_PSTRIDE) // whole poison region
#define SYNTH_MIN_FIELDS 2 // smallest field count worth emitting as a struct
#define SYNTH_ARR_MIN 4 // shortest constant-stride run collapsed into an array member
#define SYNTH_SPROOM 0x80ULL // stack-map room above SP for stack-arg sentinels (SYNTH_MAXARGS * 8 + slack)
#define SYNTH_MAXOPS 200000 // emulation budget, the recorded trace is partial beyond it

typedef struct {
	ut64 off;
	ut64 child; // for poison hits: offset accessed through the pointer (nested field)
	ut64 iaddr; // address of the accessing instruction
	int arg;
	int size;
	bool is_ptr;
} SynthField;

// one access site contributing a field, for disasm hints and command emission
typedef struct {
	ut64 off;
	ut64 iaddr;
} SynthSite;

R_VEC_TYPE (RVecSynthSite, SynthSite);

// a collapsed constant-stride run: an array member at off with count elements of elsize bytes
typedef struct {
	ut64 off;
	int elsize;
	int count;
} SynthArr;

R_VEC_TYPE (RVecSynthArr, SynthArr);

// one synthesized struct: a per-arg parent, or a nested child hanging off a parent pointer field
typedef struct {
	ut64 off; // parent field offset holding the pointer (child structs only)
	char *var; // arg var the parent type was applied to
	RAnalBaseType *bt;
	RVecSynthSite sites;
	RVecSynthArr arrs;
	int arg;
	bool child;
} SynthRec;

static int synth_key_cmp(const SynthField *x, const SynthField *y) {
	if (x->arg != y->arg) {
		return x->arg - y->arg;
	}
	if (x->off != y->off) {
		return (x->off < y->off)? -1: 1;
	}
	return 0;
}

static int synth_field_cmp(const SynthField *a, const SynthField *b) {
	const int d = synth_key_cmp (a, b);
	return d? d: b->size - a->size; // larger width first
}

// sort poison hits so all children of one pointer field are adjacent
static int synth_child_cmp(const SynthField *x, const SynthField *y) {
	int d = synth_key_cmp (x, y);
	if (!d && x->child != y->child) {
		d = (x->child < y->child)? -1: 1;
	}
	return d? d: y->size - x->size;
}

static void synth_rec_fini(SynthRec *r) {
	free (r->var);
	r_anal_base_type_free (r->bt);
	RVecSynthSite_fini (&r->sites);
	RVecSynthArr_fini (&r->arrs);
}

R_VEC_TYPE (RVecSynthField, SynthField);
R_VEC_TYPE_WITH_FINI (RVecSynthRec, SynthRec, synth_rec_fini);

// the array member covering off, or NULL for a scalar access
static SynthArr *synth_arr_at(SynthRec *rec, ut64 off) {
	SynthArr *a;
	R_VEC_FOREACH (&rec->arrs, a) {
		if (off >= a->off && off < a->off + (ut64)a->elsize * a->count) {
			return a;
		}
	}
	return NULL;
}

static SynthRec *synth_rec_find(RVecSynthRec *recs, int arg, bool child, ut64 off) {
	SynthRec *r;
	R_VEC_FOREACH (recs, r) {
		if (r->child == child && r->arg == arg && (!child || r->off == off)) {
			return r;
		}
	}
	return NULL;
}

// remember each access site in its struct's rec, for hints and command emission
static void synth_collect_sites(RVecSynthRec *recs, RVecSynthField *fields, bool child) {
	SynthField *f;
	R_VEC_FOREACH (fields, f) {
		SynthRec *rc = synth_rec_find (recs, f->arg, child, child? f->off: 0);
		if (rc) {
			SynthSite *st = RVecSynthSite_emplace_back (&rc->sites);
			if (st) {
				*st = (SynthSite){ .off = child? f->child: f->off, .iaddr = f->iaddr };
			}
		}
	}
}

// make disasm render the member name at the accessing instruction
static void synth_hint(RAnal *anal, SynthRec *rec, ut64 off, ut64 iaddr) {
	const char *sname = rec->bt->name;
	char *memb = r_type_get_struct_memb (anal->sdb_types, sname, (int)off);
	if (!memb) {
		// interior of an atomic array member doesn't resolve; snap to its base
		SynthArr *a = synth_arr_at (rec, off);
		if (a) {
			memb = r_type_get_struct_memb (anal->sdb_types, sname, (int)a->off);
		}
	}
	if (off > 0) {
		if (memb) {
			r_anal_hint_set_offset (anal, iaddr, memb);
		}
	} else {
		// off 0 with no resolved member is a whole-struct access ([reg]); label it with the type
		r_meta_set_string (anal, R_META_TYPE_VARTYPE, iaddr, memb? memb: sname);
	}
	free (memb);
}

// takes ownership of type; returns the new end offset
static ut64 synth_add_member(RAnalBaseType *bt, const char *pfx, ut64 off, int size, int count, char *type) {
	RAnalTypeMember *m = RVecAnalTypeMember_emplace_back (&bt->struct_data.members);
	if (!m) {
		free (type);
		return off;
	}
	m->name = r_str_newf ("%s_0x%" PFMT64x, pfx, off);
	m->type = type;
	m->offset = off;
	m->bitsize = (size_t)size * 8;
	m->count = count;
	return off + (ut64)size;
}

// a size-fn call stated the exact object size: pad the unobserved tail out to it
static ut64 synth_pad_tail(RAnalBaseType *bt, RVecSynthArr *arrs, ut64 cur, ut64 want) {
	if (want <= cur) {
		return cur;
	}
	const int padlen = (int)(want - cur);
	SynthArr *pa = RVecSynthArr_emplace_back (arrs);
	if (pa) {
		*pa = (SynthArr){ .off = cur, .elsize = 1, .count = padlen };
	}
	synth_add_member (bt, "pad", cur, 1, padlen, strdup ("uint8_t"));
	return want;
}

static const char *synth_fcn_cc(RAnal *anal, RAnalFunction *fcn) {
	const char *cc = r_anal_function_cc (fcn);
	return cc? cc: r_anal_cc_default (anal);
}

// the cc's caller-saved register names, poisoned across skipped calls
static RList *synth_clobber_regs(RAnal *anal, const char *cc) {
	RList *list = NULL;
	RListIter *iter;
	RRegItem *item;
	r_list_foreach (anal->reg->regset[R_REG_TYPE_GPR].regs, iter, item) {
		if (r_anal_cc_isclobber (anal, cc, item->name)) {
			if (!list) {
				list = r_list_newf (free);
			}
			r_list_append (list, strdup (item->name));
		}
	}
	return list;
}

static RAnalVar *synth_arg_var(RAnal *anal, RAnalFunction *fcn, const char *cc, int argi) {
	const char *place = cc? r_anal_cc_argloc (anal, cc, argi, 0, -1): NULL;
	if (R_STR_ISEMPTY (place)) {
		return NULL;
	}
	if (*place != '^') {
		RRegItem *ri = r_reg_get (anal->reg, place, -1);
		if (!ri) {
			return NULL;
		}
		const int index = ri->index;
		r_unref (ri);
		return r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, index);
	}
	// the n-th stack argloc maps to the n-th arg-kind stack var in delta order
	int nth = 0;
	int i;
	for (i = 0; i < argi; i++) {
		const char *p = r_anal_cc_argloc (anal, cc, i, 0, -1);
		if (p && *p == '^') {
			nth++;
		}
	}
	RAnalVar *pick = NULL;
	int lastd = INT_MIN;
	int n;
	for (n = 0; n <= nth; n++) {
		pick = NULL;
		int bestd = INT_MAX;
		RAnalVar **vp;
		R_VEC_FOREACH (&fcn->vars, vp) {
			RAnalVar *v = *vp;
			if (v->kind == R_ANAL_VAR_KIND_REG || !v->isarg) {
				continue;
			}
			// BPV and SPV deltas use different bases, so normalize before ordering
			const int off = v->kind == R_ANAL_VAR_KIND_BPV? v->delta + fcn->bp_off: v->delta;
			if (off > lastd && off < bestd) {
				bestd = off;
				pick = v;
			}
		}
		if (!pick) {
			return NULL;
		}
		lastd = bestd;
	}
	return pick;
}

// each pointer slot holds a strided poison pointer into its own child window (a deref decodes back to the parent offset); one level deep, child windows hold no further poison
static int synth_poison_map(RAnal *anal, ut64 sbase, int align, int psz, ut64 *pbase) {
	RIOBind *iob = &anal->iob;
	RIO *io = iob->io;
	const int fd = tp_map_anon (anal, SYNTH_PSIZE (psz), align, pbase, NULL);
	if (fd < 0) {
		return -1;
	}
	ut8 *win = malloc (SYNTH_DETW);
	if (!win) {
		iob->fd_close (io, fd);
		return -1;
	}
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config);
	int ai;
	for (ai = 0; ai < SYNTH_MAXARGS; ai++) {
		ut64 o;
		for (o = 0; o < SYNTH_DETW; o += psz) {
			const ut64 slot = ((ut64)ai * SYNTH_SLOTS (psz)) + (o / psz);
			r_write_ble (win + o, *pbase + slot * SYNTH_PSTRIDE, be, psz * 8);
		}
		iob->write_at (io, sbase + (ut64)ai * SYNTH_WINDOW, win, (int)SYNTH_DETW);
	}
	free (win);
	return fd;
}

// seed each arg reg with a sentinel base and turn observed base+offset accesses into struct fields
// recs may be NULL when the caller only wants the apply side effects
typedef struct {
	TPState *tps;
	ut64 sbase;
	ut64 pbase;
	ut64 want[SYNTH_MAXARGS]; // exact object size stated by a size-fn call, per arg window
	RVecSynthField childwant; // same, for dereferenced-field children keyed by (arg, off)
	int psz;
} SynthSizeCtx;

static ut64 synth_child_want(RVecSynthField *cw, int arg, ut64 off) {
	ut64 best = 0;
	SynthField *f;
	R_VEC_FOREACH (cw, f) {
		if (f->arg == arg && f->off == off && (ut64)f->size > best) {
			best = (ut64)f->size;
		}
	}
	return best;
}

static void synth_size_entry(SynthSizeCtx *c, const char *cc, const TPSizeFn *sf) {
	ut64 pv = 0, n = 0;
	if (!tp_sizefn_read (c->tps, cc, sf, c->psz, &pv, &n)) {
		return;
	}
	if (pv >= c->sbase && pv < c->sbase + SYNTH_REGION) {
		// interior pointers still bound the object: off + n bytes from the window base
		const ut64 off = (pv - c->sbase) % SYNTH_WINDOW;
		if (off + n >= SYNTH_WINDOW / 2) {
			return; // stale sentinel values and oversized objects fail this bound
		}
		const int argi = (int)((pv - c->sbase) / SYNTH_WINDOW);
		c->want[argi] = R_MAX (c->want[argi], off + n);
		return;
	}
	// a dereferenced pointer field carries a poison value decoding to its parent (arg, offset)
	if (c->pbase && pv >= c->pbase && pv < c->pbase + SYNTH_PSIZE (c->psz)) {
		const ut64 slot = (pv - c->pbase) / SYNTH_PSTRIDE;
		const ut64 coff = (pv - c->pbase) % SYNTH_PSTRIDE;
		if (coff + n >= SYNTH_PSTRIDE) {
			return; // beyond the child stride these are stale values
		}
		SynthField *cw = RVecSynthField_emplace_back (&c->childwant);
		if (cw) {
			*cw = (SynthField){
				.arg = (int)(slot / SYNTH_SLOTS (c->psz)),
				.off = (slot % SYNTH_SLOTS (c->psz)) * c->psz,
				.size = (int)(coff + n),
			};
		}
	}
}

// harvest object sizes at calls to size functions while the sentinel emulation runs
static void synth_size_cb(void *user, RAnalOp *aop, RAnalOp *next_op, ut64 addr, ut64 bb_addr) {
	SynthSizeCtx *c = user;
	RAnal *anal = c->tps->anal;
	// UCALL is the base value 4, not a flag, so match on the base type (conditional calls resolve alike)
	const int base = aop->type & 0xff;
	if (base != R_ANAL_OP_TYPE_CALL && base != R_ANAL_OP_TYPE_UCALL) {
		return;
	}
	RAnalFunction *fcn_call = NULL;
	const char *name = tp_call_target_name (anal, aop, base, &fcn_call);
	if (R_STR_ISEMPTY (name)) {
		return;
	}
	const char *cc = tp_call_cc (anal, fcn_call, name);
	if (!cc) {
		cc = r_anal_cc_default (anal);
	}
	if (!cc) {
		return;
	}
	const TPSizeFn *sf;
	R_VEC_FOREACH (&c->tps->sizefns, sf) {
		// return-value entries carry no arg-window evidence
		if (sf->ptr_arg >= 0 && tp_sizefn_name_match (sf, name)) {
			synth_size_entry (c, cc, sf);
		}
	}
}

static void type_synth(RAnal *anal, RAnalFunction *fcn, bool apply, RVecSynthRec *recs) {
	R_RETURN_IF_FAIL (anal && fcn);
	RVecSynthRec local;
	const bool own_recs = !recs;
	if (own_recs) {
		RVecSynthRec_init (&local);
		recs = &local;
	}
	TPState *tps = tps_init (anal);
	if (!tps) {
		if (own_recs) {
			RVecSynthRec_fini (recs);
		}
		return;
	}
	RIOBind *iob = &anal->iob;
	RIO *io = iob->io;
	const int align = R_MAX (1, r_arch_info (anal->arch, R_ARCH_INFO_DATA_ALIGN));
	ut64 sbase = 0;
	const int sfd = tp_map_anon (anal, SYNTH_REGION, align, &sbase, NULL);
	if (sfd < 0) {
		tps_fini (tps);
		return;
	}
	const char *cc = synth_fcn_cc (anal, fcn);
	tps->clobber = synth_clobber_regs (anal, cc);
	// pointer width comes from the arg registers, not config->bits (16 on arm thumb)
	int psz = anal->config->bits > 32? 8: 4;
	int i;
	for (i = 0; i < SYNTH_MAXARGS; i++) {
		const char *place = cc? r_anal_cc_argloc (anal, cc, i, 0, -1): NULL;
		if (place && *place && *place != '^') {
			RRegItem *ri = r_reg_get (tps->tt.reg, place, -1);
			if (ri) {
				if (ri->size >= 32) {
					psz = ri->size / 8;
				}
				r_unref (ri);
			}
			break;
		}
	}
	psz = R_MIN (psz, 8); // the poison slots and the sbuf[8] stack write assume <= 8 bytes
	ut64 pbase = 0;
	const int pfd = synth_poison_map (anal, sbase, align, psz, &pbase);
	// on link-register archs the first stack arg is [SP]; on x86 it follows the return address slot
	const bool ra_reg = r_reg_alias_getname (tps->tt.reg, R_REG_ALIAS_LR)
		|| r_reg_alias_getname (tps->tt.reg, R_REG_ALIAS_RA);
	const bool sbe = R_ARCH_CONFIG_IS_BIG_ENDIAN (anal->config);
	// tps_init leaves only align * 8 bytes of map above SP
	const ut64 spv = r_reg_getv (tps->tt.reg, "SP") - SYNTH_SPROOM;
	r_reg_setv (tps->tt.reg, "SP", spv);
	r_reg_setv (tps->tt.reg, "BP", spv);
	ut64 soff = ra_reg? 0: (ut64)psz;
	for (i = 0; i < SYNTH_MAXARGS; i++) {
		const char *place = cc? r_anal_cc_argloc (anal, cc, i, 0, -1): NULL;
		if (R_STR_ISEMPTY (place)) {
			continue;
		}
		const ut64 sval = sbase + (ut64)i * SYNTH_WINDOW;
		if (*place == '^') {
			ut8 sbuf[8] = {0};
			r_write_ble (sbuf, sval, sbe, psz * 8);
			iob->write_at (io, spv + soff, sbuf, psz);
			soff += psz;
		} else {
			r_reg_setv (tps->tt.reg, place, sval);
		}
	}
	// emulate the function linearly, letting the mem voyeurs record base+offset accesses
	SynthSizeCtx szctx = { .tps = tps, .sbase = sbase, .pbase = pfd >= 0? pbase: 0, .psz = psz };
	RVecSynthField_init (&szctx.childwant);
	const bool harvest = !RVecTPSizeFn_empty (&tps->sizefns);
	r_reg_setv (tps->tt.reg, "PC", fcn->addr);
	if (tp_emulate_linear (tps, fcn, SYNTH_MAXOPS, harvest? synth_size_cb: NULL, harvest? &szctx: NULL, false) == TP_EMU_BUDGET) {
		R_LOG_WARN ("Struct synthesis hit the %d-op budget at 0x%08" PFMT64x "; result is partial", SYNTH_MAXOPS, fcn->addr);
	}

	// collect accesses in the arg windows (fields) and the poison region (deref evidence)
	RVecSynthField vfields;
	RVecSynthField vporig;
	RVecSynthField_init (&vfields);
	RVecSynthField_init (&vporig);
	const ut32 nacc = VecAccess_length (&tps->tt.db.accesses);
	const ut32 nops = VecTraceOp_length (&tps->tt.db.ops);
	bool oom = false;
	ut32 oi;
	for (oi = 0; oi < nops && !oom; oi++) {
		TypeTraceOp *top = VecTraceOp_at (&tps->tt.db.ops, oi);
		const ut32 kend = R_MIN (top->end, nacc);
		ut32 k;
		for (k = top->start; k < kend; k++) {
			TypeTraceAccess *a = VecAccess_at (&tps->tt.db.accesses, k);
			if (!a || a->is_reg) {
				continue;
			}
			const ut64 ma = a->mem.addr;
			const int asz = a->mem.size > 0? a->mem.size: 1;
			if (pfd >= 0 && ma >= pbase && ma < pbase + SYNTH_PSIZE (psz)) {
				// decode the poison slot back to the exact (arg, parent field offset)
				const ut64 slot = (ma - pbase) / SYNTH_PSTRIDE;
				SynthField *sf = RVecSynthField_emplace_back (&vporig);
				if (!sf) {
					oom = true;
					break;
				}
				*sf = (SynthField){
					.arg = (int)(slot / SYNTH_SLOTS (psz)),
					.off = (slot % SYNTH_SLOTS (psz)) * psz,
					.child = (ma - pbase) % SYNTH_PSTRIDE,
					.size = asz,
					.iaddr = top->addr,
				};
				continue;
			}
			if (ma < sbase || ma >= sbase + SYNTH_REGION) {
				continue;
			}
			const ut64 woff = (ma - sbase) % SYNTH_WINDOW;
			if (woff >= SYNTH_WINDOW / 2) {
				continue; // negative offsets off a neighboring arg land in the window tail
			}
			SynthField *sf = RVecSynthField_emplace_back (&vfields);
			if (!sf) {
				oom = true;
				break;
			}
			*sf = (SynthField){
				.arg = (int)((ma - sbase) / SYNTH_WINDOW),
				.off = woff,
				.size = asz,
				.iaddr = top->addr,
			};
		}
	}
	RVecSynthField_sort (&vfields, synth_field_cmp);
	RVecSynthField_sort (&vporig, synth_child_cmp);
	const size_t nfields = RVecSynthField_length (&vfields);
	const size_t nporig = RVecSynthField_length (&vporig);
	SynthField *fields = R_VEC_START_ITER (&vfields);
	SynthField *porig = R_VEC_START_ITER (&vporig);
	// a field whose loaded value was dereferenced is a pointer; both arrays sort by (arg, off)
	size_t pi = 0, fi = 0;
	while (pi < nporig && fi < nfields) {
		const int d = synth_key_cmp (&porig[pi], &fields[fi]);
		if (d > 0) {
			fi++;
		} else if (d < 0) {
			pi++;
		} else {
			fields[fi++].is_ptr = true;
		}
	}
	// pointer fields with enough distinct child accesses get a nested child struct
	char *fname = r_str_sanitize_sdb_key (fcn->name);
	size_t ci = 0;
	while (ci < nporig) {
		const int carg = porig[ci].arg;
		const ut64 coff = porig[ci].off;
		RAnalBaseType *cbt = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
		ut64 ccur = 0;
		int ccount = 0;
		size_t cj = ci;
		while (cj < nporig && porig[cj].arg == carg && porig[cj].off == coff) {
			const ut64 choff = porig[cj].child;
			const int csize = porig[cj].size;
			do {
				cj++;
			} while (cj < nporig && porig[cj].arg == carg && porig[cj].off == coff
				&& porig[cj].child == choff);
			if (choff < ccur) {
				continue; // overlaps the previous member (widest-wins, like the parent)
			}
			ccur = synth_add_member (cbt, "field", choff, csize, 0, strdup (synth_type_for_size (csize)));
			ccount++;
		}
		const ut64 cwant = synth_child_want (&szctx.childwant, carg, coff);
		if (ccount >= SYNTH_MIN_FIELDS || (ccount > 0 && cwant > ccur)) {
			RVecSynthArr carrs;
			RVecSynthArr_init (&carrs);
			ccur = synth_pad_tail (cbt, &carrs, ccur, cwant);
			cbt->name = r_str_newf ("%s_arg%d_0x%" PFMT64x, fname, carg, coff);
			cbt->size = ccur;
			SynthRec *rec = RVecSynthRec_emplace_back (recs);
			if (rec) {
				*rec = (SynthRec){ .arg = carg, .child = true, .off = coff, .bt = cbt };
				RVecSynthSite_init (&rec->sites);
				rec->arrs = carrs;
				cbt = NULL;
			} else {
				RVecSynthArr_fini (&carrs);
			}
		}
		if (cbt) {
			r_anal_base_type_free (cbt);
		}
		ci = cj;
	}

	// one struct per argument that accumulated enough non-overlapping fields
	size_t p = 0;
	while (p < nfields) {
		const int arg = fields[p].arg;
		RAnalBaseType *bt = r_anal_base_type_new (R_ANAL_BASE_TYPE_KIND_STRUCT);
		ut64 cur = 0;
		int count = 0;
		size_t q = p;
		// unique members, widest access per offset wins; a narrower overlapping access is dropped (no union-ish layouts)
		RVecSynthField uniq;
		RVecSynthField_init (&uniq);
		while (q < nfields && fields[q].arg == arg) {
			const ut64 foff = fields[q].off;
			const int fsize = fields[q].size;
			const bool fptr = fields[q].is_ptr;
			do {
				q++; // skip duplicate offsets (largest width sorts first)
			} while (q < nfields && fields[q].arg == arg && fields[q].off == foff);
			if (foff < cur) {
				continue; // overlaps the previous member
			}
			cur = foff + fsize;
			SynthField *u = RVecSynthField_emplace_back (&uniq);
			if (u) {
				*u = (SynthField){ .arg = arg, .off = foff, .size = fsize, .is_ptr = fptr };
			}
		}
		// emit members, collapsing constant-stride non-pointer runs into arrays
		RVecSynthArr arrs;
		RVecSynthArr_init (&arrs);
		const size_t un = RVecSynthField_length (&uniq);
		cur = 0;
		size_t u = 0;
		while (u < un) {
			SynthField *m = RVecSynthField_at (&uniq, u);
			size_t run = 1;
			if (!m->is_ptr) {
				while (u + run < un) {
					SynthField *nx = RVecSynthField_at (&uniq, u + run);
					if (nx->is_ptr || nx->size != m->size
						|| nx->off != m->off + (ut64)m->size * run) {
						break;
					}
					run++;
				}
			}
			if (run >= SYNTH_ARR_MIN) {
				SynthArr *a = RVecSynthArr_emplace_back (&arrs);
				if (a) {
					*a = (SynthArr){ .off = m->off, .elsize = m->size, .count = (int)run };
				}
				synth_add_member (bt, "field", m->off, m->size, (int)run, strdup (synth_type_for_size (m->size)));
				cur = m->off + (ut64)m->size * run;
				count++;
				u += run;
			} else {
				const char *cty = NULL;
				if (m->is_ptr) {
					SynthRec *rc = synth_rec_find (recs, arg, true, m->off);
					if (rc) {
						cty = rc->bt->name;
					}
				}
				char *ty = cty? r_str_newf ("struct %s *", cty)
					: strdup (m->is_ptr? "void *": synth_type_for_size (m->size));
				cur = synth_add_member (bt, "field", m->off, m->size, 0, ty);
				count++;
				u++;
			}
		}
		RVecSynthField_fini (&uniq);
		// a single big array is still a meaningful struct; a size-fn stated size upgrades even one field
		SynthRec *rec = NULL;
		const bool emit = count >= SYNTH_MIN_FIELDS || !RVecSynthArr_empty (&arrs)
			|| (count > 0 && szctx.want[arg] > cur);
		if (emit) {
			cur = synth_pad_tail (bt, &arrs, cur, szctx.want[arg]);
			bt->name = r_str_newf ("%s_arg%d", fname, arg);
			bt->size = cur;
			rec = RVecSynthRec_emplace_back (recs);
		}
		if (rec) {
			*rec = (SynthRec){ .arg = arg, .bt = bt };
			RVecSynthSite_init (&rec->sites);
			rec->arrs = arrs;
		} else {
			RVecSynthArr_fini (&arrs);
			r_anal_base_type_free (bt);
		}
		p = q;
	}
	// remember the access sites per struct, for hints and command emission
	synth_collect_sites (recs, &vfields, false);
	synth_collect_sites (recs, &vporig, true);
	if (apply) {
		// bookkeeping lives in the root sdb to keep it out of the type namespace
		Sdb *bookdb = anal->sdb;
		char *key = r_str_newf ("synth.%08" PFMT64x, fcn->addr);
		// re-runs and function renames would leave stale types behind otherwise
		char *stale = sdb_get (bookdb, key, 0);
		if (stale) {
			char *sp;
			sdb_aforeach (sp, stale) {
				r_anal_remove_parsed_type (anal, sp);
				sdb_aforeach_next (sp);
			}
			free (stale);
			sdb_unset (bookdb, key, 0);
		}
		if (!RVecSynthRec_empty (recs)) {
			RStrBuf sb;
			r_strbuf_init (&sb);
			SynthRec *rec;
			R_VEC_FOREACH (recs, rec) {
				r_anal_save_base_type (anal, rec->bt);
				r_strbuf_appendf (&sb, "%s%s", r_strbuf_length (&sb)? ",": "", rec->bt->name);
				if (!rec->child) {
					RAnalVar *av = synth_arg_var (anal, fcn, cc, rec->arg);
					if (av) {
						char *ty = r_str_newf ("struct %s *", rec->bt->name);
						if (ty) {
							r_anal_var_set_type (anal, av, ty);
							free (ty);
						}
						rec->var = strdup (av->name);
					}
				}
			}
			sdb_set (bookdb, key, r_strbuf_get (&sb), 0);
			r_strbuf_fini (&sb);
			// annotate the accessing instructions so disasm renders member names
			R_VEC_FOREACH (recs, rec) {
				SynthSite *st;
				R_VEC_FOREACH (&rec->sites, st) {
					synth_hint (anal, rec, st->off, st->iaddr);
				}
			}
		}
		free (key);
	}
	free (fname);
	RVecSynthField_fini (&szctx.childwant);
	RVecSynthField_fini (&vfields);
	RVecSynthField_fini (&vporig);
	iob->fd_close (io, sfd);
	if (pfd >= 0) {
		iob->fd_close (io, pfd);
	}
	tps_fini (tps);
	if (own_recs) {
		RVecSynthRec_fini (recs);
	}
}

static char *synth_json(RVecSynthRec *recs) {
	PJ *pj = pj_new ();
	if (!pj) {
		return NULL;
	}
	pj_a (pj);
	SynthRec *rec;
	R_VEC_FOREACH (recs, rec) {
		pj_o (pj);
		pj_ks (pj, "name", rec->bt->name);
		pj_ki (pj, "arg", rec->arg);
		pj_kb (pj, "child", rec->child);
		if (rec->child) {
			pj_kn (pj, "offset", rec->off);
		}
		if (rec->var) {
			pj_ks (pj, "var", rec->var);
		}
		pj_kn (pj, "size", rec->bt->size);
		pj_ka (pj, "members");
		RAnalTypeMember *m;
		R_VEC_FOREACH (&rec->bt->struct_data.members, m) {
			pj_o (pj);
			pj_ks (pj, "name", m->name);
			pj_ks (pj, "type", m->type);
			pj_kn (pj, "offset", m->offset);
			pj_kn (pj, "size", (ut64)m->bitsize / 8);
			SynthArr *a = synth_arr_at (rec, m->offset);
			if (a) {
				pj_ki (pj, "count", a->count);
			}
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
	}
	pj_end (pj);
	return pj_drain (pj);
}

// the same synthesis serialized as r2 commands instead of being applied
static char *synth_commands(RAnal *anal, RAnalFunction *fcn, RVecSynthRec *recs) {
	const char *cc = synth_fcn_cc (anal, fcn);
	RStrBuf *sb = r_strbuf_new ("");
	SynthRec *rec;
	R_VEC_FOREACH (recs, rec) {
		r_strbuf_appendf (sb, "'td struct %s {", rec->bt->name);
		ut64 cur = 0;
		RAnalTypeMember *m;
		R_VEC_FOREACH (&rec->bt->struct_data.members, m) {
			if (m->offset > cur) {
				// pad the gaps so the C layout keeps the observed offsets
				r_strbuf_appendf (sb, "uint8_t pad_0x%" PFMT64x "[%" PFMT64u "];", cur, m->offset - cur);
			}
			SynthArr *a = synth_arr_at (rec, m->offset);
			if (a) {
				r_strbuf_appendf (sb, "%s %s[%d];", m->type, m->name, a->count);
				cur = m->offset + (ut64)a->elsize * a->count;
			} else {
				r_strbuf_appendf (sb, "%s %s;", m->type, m->name);
				cur = m->offset + m->bitsize / 8;
			}
		}
		r_strbuf_append (sb, "};\n");
	}
	R_VEC_FOREACH (recs, rec) {
		if (rec->child) {
			continue;
		}
		RAnalVar *av = synth_arg_var (anal, fcn, cc, rec->arg);
		if (!av) {
			continue;
		}
		if (av->kind == R_ANAL_VAR_KIND_REG) {
			RRegItem *ri = r_reg_index_get (anal->reg, av->delta);
			if (ri) {
				r_strbuf_appendf (sb, "'afvr %s %s struct %s *\n", ri->name, av->name, rec->bt->name);
			}
		} else {
			const int delta = av->kind == R_ANAL_VAR_KIND_BPV? av->delta + fcn->bp_off: av->delta;
			r_strbuf_appendf (sb, "'afv%c %d %s struct %s *\n", av->kind, delta, av->name, rec->bt->name);
		}
	}
	R_VEC_FOREACH (recs, rec) {
		SynthSite *st;
		R_VEC_FOREACH (&rec->sites, st) {
			// aht cannot address inside an atomic array, so only the base element is emitted (the applied path hints all)
			SynthArr *a = synth_arr_at (rec, st->off);
			if (a && st->off != a->off) {
				continue;
			}
			if (st->off > 0) {
				r_strbuf_appendf (sb, "'@0x%08" PFMT64x "'aht %s.field_0x%" PFMT64x "\n",
					st->iaddr, rec->bt->name, st->off);
			} else {
				r_strbuf_appendf (sb, "'@0x%08" PFMT64x "'Ct %s.field_0x0\n", st->iaddr, rec->bt->name);
			}
		}
	}
	char *res = r_strbuf_drain (sb);
	r_str_trim_tail (res);
	return res;
}

// true when type matching left an argument with a plain non-pointer type
static bool synth_args_untyped(RAnalFunction *fcn) {
	RAnalVar **vp;
	R_VEC_FOREACH (&fcn->vars, vp) {
		RAnalVar *v = *vp;
		if (v->isarg && v->type && !strchr (v->type, '*') && !r_str_startswith (v->type, "struct")) {
			return true;
		}
	}
	return false;
}

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
	int maxopsz = r_arch_info (anal->arch, R_ARCH_INFO_MAXOP_SIZE);
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
	"a:tp", "synth", "synthesize struct types from pointer-argument accesses (afts)",
	"a:tp", "synth*", "show the synthesis as r2 commands without applying (afts*)",
	"a:tp", "synthj", "apply the synthesis and report it in json (aftsj)",
	"a:tp", "?", "show this help",
	NULL
};

// afts / afts* / aftsj: synthesize struct types at the current function; suffix selects the mode
static char *tp_synth_cmd(RAnal *anal, void *core, const char *suffix) {
	const char mode = *suffix;
	if (mode && !((mode == '*' || mode == 'j') && !suffix[1])) {
		if (anal->coreb.help) {
			anal->coreb.help (core, help_msg_tp);
		}
		return strdup ("");
	}
	const ut64 cur_addr = anal->coreb.numGet? anal->coreb.numGet (core, "$$"): 0;
	RAnalFunction *fcn = r_anal_get_fcn_in (anal, cur_addr, -1);
	if (!fcn) {
		R_LOG_WARN ("Cannot find function at current offset");
		return strdup ("");
	}
	RVecSynthRec recs;
	RVecSynthRec_init (&recs);
	type_synth (anal, fcn, mode != '*', &recs);
	char *res = NULL;
	if (mode == 'j') {
		res = synth_json (&recs);
	} else if (mode == '*') {
		res = synth_commands (anal, fcn, &recs);
	} else {
		SynthRec *rec;
		R_VEC_FOREACH (&recs, rec) {
			if (anal->coreb.cmdf) {
				anal->coreb.cmdf (core, "tsc %s", rec->bt->name);
			}
		}
		if (RVecSynthRec_empty (&recs)) {
			R_LOG_INFO ("no pointer-argument struct recovered here");
		}
	}
	RVecSynthRec_fini (&recs);
	return res? res: strdup ("");
}

static char *tp_cmd(RAnal *anal, const char *input) {
	R_RETURN_VAL_IF_FAIL (anal && input, NULL);
	if (!r_str_startswith (input, "tp")) {
		return NULL;
	}
	const char *args = r_str_trim_head_ro (input + 2);
	void *core = anal->coreb.core;
	if (*args == '?') {
		if (anal->coreb.help && core) {
			anal->coreb.help (core, help_msg_tp);
		}
		return strdup ("");
	}
	if (!core) {
		return strdup ("");
	}
	if (!tp_requirements_met (anal, true)) {
		return strdup ("");
	}
	if (!*args) {
		ut64 cur_addr = anal->coreb.numGet? anal->coreb.numGet (core, "$$"): 0;
		RAnalFunction *fcn = r_anal_get_fcn_in (anal, cur_addr, -1);
		if (!fcn) {
			R_LOG_WARN ("Cannot find function at current offset");
			return strdup ("");
		}
		r_cons_break_push (r_cons_singleton (), NULL, NULL);
		r_esil_set_pc (anal->esil, fcn->addr);
		r_anal_type_match (anal, fcn);
		r_cons_break_pop (r_cons_singleton ());
		if (anal->coreb.cfgGetB && anal->coreb.cfgGetB (core, "types.synth") && synth_args_untyped (fcn)) {
			type_synth (anal, fcn, true, NULL);
		}
		return strdup ("");
	}
	if (!strcmp (args, "all")) {
		if (anal->coreb.cmd) {
			anal->coreb.cmd (core, "aaft");
		} else {
			R_LOG_WARN ("Cannot run 'aaft' because core bindings are missing");
		}
		return strdup ("");
	}
	if (r_str_startswith (args, "synth")) {
		return tp_synth_cmd (anal, core, args + 5);
	}
	if (anal->coreb.help && core) {
		anal->coreb.help (core, help_msg_tp);
	}
	return strdup ("");
}

static int tp_plugin_eligible(RAnal *anal) {
	return tp_requirements_met (anal, false) ? 0 : -1;
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
