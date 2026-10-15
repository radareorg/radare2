/* radare - LGPL - Copyright 2026 - pancake */

#ifndef R2_ANAL_PRIV_H
#define R2_ANAL_PRIV_H

#include "r_anal.h"

#ifdef __cplusplus
extern "C" {
#endif

// Argument locations are a property of the convention, not of the function
#define R_ANAL_ARGSEQ_SLOTS (R_ANAL_CC_MAXARG * 2)

typedef struct {
	RBitmap *writes;
	RVecAnalRef calls;
	ut64 addr;
	ut64 size;
	ut32 hash;
	int last_type;
	bool unknown;
} RAnalRegUsage;

typedef struct r_anal_argseq_t {
	const char *cc; // fcn->callconv, interned in anal->constpool, so the pointer names the convention
	ut64 generation; // cc_generation when loc and max_arg were read
	const char *loc[R_ANAL_ARGSEQ_SLOTS]; // interned too: a cc db write can make them stale, never dangle
	int max_arg;
} RAnalArgSeq;

typedef struct r_anal_priv_t {
	bool types_dirty;
	char *types_libraries;
	Sdb *types_index;
	char *types_subsystem;
	int types_loaded_bits;
	char *dir_prefix;
	// moves on every change to sdb_cc: the sdb hook set in r_anal_new sees
	// each key write, and r_anal_cc_reset covers sdb_reset, which calls no hook
	ut64 cc_generation;
	RAnalArgSeq argseq; // single-threaded, like the rest of the analysis state
	HtPP *cc_cache; // convention name -> RAnalCCInfo, dropped on every write to the cc sdb
	struct r_anal_cc_info_t *cc_last;
	HtUP *reg_usage; // block pointer -> writes collected by existing instruction walks
	const char *reg_usage_profile;
} RAnalPriv;

// Recorded adrp/add (or lea) target for a register. Populated by the
// function recurser as it walks a basic block and consumed by the jmptbl
// dispatcher resolver.
typedef struct r_leaddr_pair_t {
	ut64 op_addr;
	ut64 leaddr;
	char *reg;
} RLeaddrPair;

#define R_ANAL_PRIV(x) ((RAnalPriv*)(x)->priv)
#define R_ANAL_CC_STACK_POP_UNKNOWN (-1)

static inline void reg_usage_free(HtUPKv *kv) {
	RAnalRegUsage *usage = kv->value;
	r_bitmap_free (usage->writes);
	RVecAnalRef_fini (&usage->calls);
	free (usage);
}

static inline void r_anal_reg_usage_check_profile(RAnal *anal) {
	RAnalPriv *priv = R_ANAL_PRIV (anal);
	const char *profile = r_str_constpool_get (&anal->constpool, anal->reg->reg_profile_str);
	if (!profile || priv->reg_usage_profile != profile) {
		ht_up_free (priv->reg_usage);
		priv->reg_usage = NULL;
		priv->reg_usage_profile = profile;
	}
}

// Record decoded operands; a NULL operation only looks up the block summary.
static inline RAnalRegUsage *r_anal_block_reg_usage(RAnalBlock *bb, RAnalOp *op) {
	RAnalPriv *priv = R_ANAL_PRIV (bb->anal);
	if (!priv->reg_usage && op) {
		priv->reg_usage = ht_up_new (NULL, reg_usage_free, NULL);
	}
	const ut64 key = (ut64)(size_t)bb;
	RAnalRegUsage *usage = priv->reg_usage? ht_up_find (priv->reg_usage, key, NULL): NULL;
	if (!op || !priv->reg_usage) {
		return usage;
	}
	if (!usage) {
		if (!op->access || op->addr != bb->addr) {
			return NULL;
		}
		usage = R_NEW0 (RAnalRegUsage);
		usage->writes = r_bitmap_new (r_list_length (bb->anal->reg->allregs));
		if (!usage->writes || !usage->writes->bitmap || !ht_up_insert (priv->reg_usage, key, usage)) {
			r_bitmap_free (usage->writes);
			free (usage);
			return NULL;
		}
	}
	if (op->addr == bb->addr) {
		memset (usage->writes->bitmap, 0, (usage->writes->length + 7) / 8);
		RVecAnalRef_clear (&usage->calls);
		usage->addr = bb->addr;
		usage->size = 0;
		usage->unknown = false;
	}
	const int type = op->type & R_ANAL_OP_TYPE_MASK & ~R_ANAL_OP_TYPE_COND;
	usage->unknown |= op->addr - bb->addr != usage->size || !op->access
		|| type == R_ANAL_OP_TYPE_UNK || type == R_ANAL_OP_TYPE_ILL
		|| type == R_ANAL_OP_TYPE_UCALL || type == R_ANAL_OP_TYPE_UJMP
		|| type == R_ANAL_OP_TYPE_SWI || type == R_ANAL_OP_TYPE_TRAP;
	usage->size += op->size;
	usage->last_type = type;
	if (usage->unknown) {
		return usage;
	}
	if (type == R_ANAL_OP_TYPE_CALL || type == R_ANAL_OP_TYPE_JMP) {
		RAnalRef *ref = RVecAnalRef_emplace_back (&usage->calls);
		usage->unknown = !ref;
		if (ref) {
			ref->addr = op->jump;
			ref->type = type == R_ANAL_OP_TYPE_CALL? R_ANAL_REF_TYPE_CALL: R_ANAL_REF_TYPE_CODE;
		}
	}
	RListIter *iter;
	RAnalValue *value;
	r_list_foreach (op->access, iter, value) {
		if (value->type == R_ANAL_VAL_REG && (value->access & R_PERM_W)) {
			RRegItem *reg = value->reg? r_reg_get (bb->anal->reg, value->reg, -1): NULL;
			if (reg && reg->index >= 0 && reg->index < usage->writes->length) {
			r_bitmap_set (usage->writes, reg->index);
			} else {
				usage->unknown = true;
			}
			r_unref (reg);
		}
	}
	return usage;
}

/* Store a function's calling convention, resolving a bare dyncc marker. */
R_IPI bool r_anal_var_is_default_argname(const char *name);
R_IPI bool r_anal_reg_same(RAnal *anal, const char *a, const char *b);
/* Adopt the block a switch case targets. False when no block covers it, in
 * which case the case needs scanning; the walker decides where. */
R_IPI bool r_anal_function_materialize_switch_case(RAnal *anal, RAnalFunction *fcn, ut64 case_addr, int stack);
/* Scan a switch case outside a walk and adopt the block it produced. */
R_IPI void r_anal_function_scan_switch_case(RAnal *anal, RAnalFunction *fcn, ut64 case_addr);
typedef struct r_anal_switch_cursor_t RAnalSwitchCursor;
/* Apply cases until one needs scanning: true with `*target` set. False once the
 * table is finished, after which only r_anal_switch_cursor_finish may follow. */
R_IPI bool r_anal_switch_cursor_step(RAnalSwitchCursor *c, ut64 *target);
/* Record the switch the cases applied so far describe, and free the cursor. */
R_IPI void r_anal_switch_cursor_finish(RAnalSwitchCursor *c);
R_IPI void r_anal_cc_cache_reset(RAnal *anal);
R_IPI int r_anal_cc_stack_pop(RAnal *anal, const char *convention);
R_IPI int r_anal_cc_shadow(RAnal *anal, const char *convention);
R_IPI bool r_anal_cc_stack_rev(RAnal *anal, const char *cc);
R_IPI int r_anal_cc_raslot(RAnal *anal, int word);
R_IPI const char *r_anal_cc_rolelabel(char tag, char label[2], int *slot);
R_IPI const char *r_anal_cc_regset(RAnal *anal, const char *convention, bool preserve);
R_IPI bool r_anal_cc_location_in_regset(RAnal *anal, const char *loc, const char *regset, bool all);
R_IPI const char *r_anal_call_type_at(RAnal *anal, ut64 addr);
R_IPI void r_anal_call_type_set(RAnal *anal, ut64 addr, const char *type);

// Bump the recorded leaddr of the most recent entry that matches `reg` by
// `delta`. Used on arm64 to finalise `adrp Rd, page; add Rd, Rd, #imm`
// sequences where multiple adrp's can interleave before their matching adds.
R_IPI void r_anal_jmptbl_leaddrs_bump(RList *leaddrs, const char *reg, ut64 delta);

// Detect and walk an arm64 jmptbl dispatcher at the indirect branch `op`.
// Scans the preceding add/load pair, resolves the base/table lea pairs
// via the recorded `leaddrs`, reads the table and registers each case.
// Returns true when a jmptbl was successfully resolved and applied.
R_IPI bool r_anal_jmptbl_arm64_from_br(RAnal *anal, RAnalFunction *fcn, RAnalBlock *bb, RAnalOp *op, int loadsize, const RAnalScanSink *sink);

#ifdef __cplusplus
}
#endif

#endif
