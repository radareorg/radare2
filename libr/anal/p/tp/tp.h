/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type matching - type propagation */

#ifndef R2_ANAL_TP_H
#define R2_ANAL_TP_H

#include <r_anal.h>
#include <r_anal_priv.h>
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
	ut64 value; // written value when the store is a power-of-two width up to 8 bytes (write records only)
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
R_VEC_TYPE(VecWriteIdx, ut32);

typedef struct {
	VecTraceOp ops;
	VecAccess accesses;
	HtUU *loop_counts;
	HtPP *regwrites; // register name => ascending trace indexes of the ops writing it
	ut32 indexed_ops; // ops already folded into regwrites
} TypeTraceDB;

typedef struct type_trace_t {
	TypeTraceDB db;
	int idx;
	int cur_idx;
	RReg *reg;
	ut32 voy[TP_VOYEUR_NMAX];
	RStrBuf rollback;  // ESIL string to rollback state (inspired by PR #24428)
	bool enable_rollback;
	bool be; // decode recorded store values with the target's endianness
	// TODO: Add REsil instance here
} TypeTrace;

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

// a function whose call sites state an object size (memset, allocators, ...)
typedef struct {
	char *name;
	int ptr_arg; // arg index whose pointee is constrained, -1 = return value
	int alias_arg; // return-value entries only: arg the return aliases (realloc), -1 = fresh object
	int size_arg; // arg index carrying the byte count
	int mul_arg; // second factor (calloc), -1 = none
} TPSizeFn;

static void tp_sizefn_fini(TPSizeFn *f) {
	free (f->name);
}
R_VEC_TYPE_WITH_FINI (RVecTPSizeFn, TPSizeFn, tp_sizefn_fini);

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
	bool cfg_bbstate;
	bool old_follow;
	bool lineage_reset; // set when a block's machine state was restored from a real predecessor
	RVecTPSizeFn sizefns; // empty unless types.sizes is set
	RList *clobber; // caller-saved regs to poison across skipped calls (synth only)
	char *seed_reg; // ret reg to seed after the current call's clobber (allocator harvest)
	ut64 seed_val;
	RVecTPPendingConst pending_const;
	HtUP *var_facts; // RAnalVar * => TPVarFact *
	HtUP *reach_cache; // block addr => SetU of reachable block addrs
	HtUP *mem_types; // emulated address => pointer type written by a call
} TPState;

typedef bool (*AccessPredicate)(const TypeTraceAccess *access, void *user);

RAnalOp *tp_anal_op(RAnal *anal, ut64 addr, int mask);

typedef const char *String;
R_VEC_TYPE(RVecString, String); // no fini, these are owned by SDB

#define REGNAME_SIZE 10

// deref displacements seen while backtracing an arg, latest instruction first
typedef struct {
	ut64 hops[TP_CHAIN_MAX];
	ut64 slot_addr; // memread addr of the final field load, for const write evidence
	int width; // access width of the final field load, disambiguates union members
	int len;
	bool ok;
} TPFieldChain;

#define DEFAULT_MAX 3
#define MAX_INSTR 5

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

// UCALL is the base value 4, not a flag, so match on the base type (conditional calls resolve alike)
static inline ut32 tp_op_call_base(ut32 optype) {
	const ut32 base = optype & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_TYPE_COND;
	return (base == R_ANAL_OP_TYPE_CALL || base == R_ANAL_OP_TYPE_UCALL)? base: 0;
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

typedef struct {
	ut64 off;
	ut64 child; // for poison hits: offset accessed through the pointer (nested field)
	ut64 iaddr; // address of the accessing instruction (or size-fn call site for size hints)
	const char *fn; // size-fn that stated a child size, borrowed from the flag/function; NULL otherwise
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
	ut64 hint_size; // size a size-fn stated for this object, 0 when the extent came from accesses alone
	ut64 hint_site; // call site of that size-fn
	char *hint_fn; // that size-fn's name (owned)
	int arg; // sentinel window this object came from
	int argno; // arg number to report, which a reverse-stack cc numbers the other way round
	bool child;
} SynthRec;

static void synth_rec_fini(SynthRec *r) {
	free (r->var);
	free (r->hint_fn);
	r_anal_base_type_free (r->bt);
	RVecSynthSite_fini (&r->sites);
	RVecSynthArr_fini (&r->arrs);
}

R_VEC_TYPE (RVecSynthField, SynthField);
R_VEC_TYPE_WITH_FINI (RVecSynthRec, SynthRec, synth_rec_fini);

bool tp_argloc_val(TPState *tps, const char *cc, int argno, int argc, ut64 *val);

ut64 etrace_addrof(TypeTrace *etrace, ut32 idx);
const TypeTraceAccess *etrace_find_access(TypeTrace *etrace, ut32 idx, AccessPredicate pred, void *user);
bool etrace_have_memread(TypeTrace *etrace, ut32 idx);
bool etrace_is_regwrite_name(const TypeTraceAccess *access, void *user);
int etrace_last_regwrite(TypeTrace *etrace, const char *rname, int j);
bool etrace_memread_first_addr(TypeTrace *etrace, ut32 idx, ut64 *addr);
ut64 etrace_memwrite_addr(TypeTrace *etrace, ut32 idx);
bool etrace_memwrite_at(TypeTrace *tt, ut64 addr, int width);
ut64 etrace_regread_value(TypeTrace *etrace, ut32 idx, const char *rname);
bool etrace_regwrite_contains(TypeTrace *etrace, ut32 idx, const char *rname);

void tp_flush_pending_const(TPState *tps);
void tp_sizefns_init(RVecTPSizeFn *v, const char *extra);
void type_trace_fini(TypeTrace *trace, REsil *esil);
bool type_trace_init(TypeTrace *trace, REsil *esil, RReg *reg);
ut64 type_trace_loopcount(TypeTrace *trace, ut64 addr);
void type_trace_loopcount_increment(TypeTrace *trace, ut64 addr);
bool type_trace_op(TypeTrace *trace, REsil *esil, RAnalOp *op);
void type_trace_rollback_clear(TypeTrace *trace);
void type_trace_voyeur_mem_read(void *user, ut64 addr, const ut8 *buf, int len);
void type_trace_voyeur_mem_write(void *user, ut64 addr, const ut8 *old, const ut8 *buf, int len);
void type_trace_voyeur_reg_read(void *user, const char *name, ut64 val);
void type_trace_voyeur_reg_write(void *user, const char *name, ut64 old, ut64 val);

RAnalCondType cond_invert(RAnal *anal, RAnalCondType cond);
int etrace_index(TypeTrace *etrace);
bool etrace_is_memread(const TypeTraceAccess *access, void *user);
const char *etrace_regwrite(TypeTrace *etrace, ut32 idx);
ut64 get_addr(TypeTrace *et, const char *regname, int idx);
void get_src_regname_from_esil(RAnal *anal, const char *op_esil, ut64 addr, char *regname, int size);
bool parse_format(TPState *tps, const char *fmt, RVecString *vec);
bool reg_token_contains(const char *regs, const char *reg);
bool reg_token_contains_len(const char *regs, const char *reg, size_t reg_len);
void tp_apply_arg_type(TPState *tps, ut64 baddr, int j, RAnalVar *var, RAnalOp *op, TPFieldChain *chain, const char *name, const char *type, int memref, bool lea_adjust, const char *fcn_name, bool in_stack, const char *place, int soff, ut64 addr, bool userfnc);
bool tp_chain_collect(TypeTrace *tt, int idx, RAnalOp *op, TPFieldChain *chain, char *regname, int size);
TPEmuResult tp_emulate_linear(TPState *tps, RAnalFunction *fcn, int max_ops, TPEmulateOpCb op_cb, void *user, bool lookahead, bool restore_state);
bool tp_field_from_ret(TPState *tps, RAnalFunction *fcn, RAnalOp *op, const char *ret_type);
char *tp_indirect_call_type(TPState *tps, RAnalFunction *fcn, const char *reg, ut64 *load_addr);
const char *tp_mem_type_at(TPState *tps, ut64 addr);
void tp_mem_type_set(TPState *tps, ut64 addr, const char *type);
bool tp_op_loads_value(TypeTrace *tt, RAnalOp *op, ut32 j);
bool tp_selfsize_hit(TPState *tps, ut32 idx, RAnalVar *var, const char *rname, ut64 pv);
void tp_selfsize_var(TPState *tps, ut64 baddr, RAnalVar *var, ut64 n);
ut64 tp_sizefn_arg_stacksize(TPState *tps, const char *cc, const char *fcn_name, int arg_num, int argc, ut64 *pv_out);
void tp_var_retype(TPState *tps, ut64 baddr, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx);
void tps_fini(TPState *tps);
TPState *tps_init(RAnal *anal);
bool type_pos_hit(TypeTrace *tt, bool in_stack, ut64 sp, int idx, st64 off, const char *place);
void type_trace_rollback(TypeTrace *trace, REsil *esil);
void var_rename(RAnal *anal, RAnalVar *v, const char *name, ut64 addr);
void var_retype(RAnal *anal, RAnalVar *var, const char *vname, const char *type, int ref, bool pfx);

const char *tp_call_cc(RAnal *anal, RAnalFunction *fcn_call, const char *name);
const char *tp_call_target_name(RAnal *anal, RAnalOp *aop, ut32 type, RAnalFunction **fcn_call);
int tp_callee_argc(RAnal *anal, const char *name);
int tp_map_anon(RAnal *anal, ut64 size, int align, ut64 *base, ut32 *map_id);
bool tp_sizefn_name_match(const TPSizeFn *f, const char *name);
bool tp_sizefn_read(TPState *tps, const char *cc, const TPSizeFn *sf, int argc, ut64 *pv, ut64 *n);
bool tp_sizefns_have_rets(const RVecTPSizeFn *v);

bool synth_args_untyped(RAnalFunction *fcn);
char *synth_commands(RAnal *anal, RAnalFunction *fcn, RVecSynthRec *recs);
char *synth_json(RVecSynthRec *recs);
void type_synth(RAnal *anal, RAnalFunction *fcn, bool apply, RVecSynthRec *recs);

#endif
