/* radare - LGPL - Copyright 2016-2026 - oddcoder, sivaramaaa, pancake */
/* type propagation: the type matcher and canary naming */

#include "tp.h"

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
	bool format = false;
	R_LOG_DEBUG ("type_match %s %" PFMT64x " %" PFMT64x " %s %d", fcn_name, addr, baddr, cc, prev_idx);

	if (!fcn_name || !cc) {
		return;
	}
	int i, j, pos = 0, max = r_type_func_args_count (TDB, fcn_name);
	const bool stack_rev = r_anal_cc_stack_rev (anal, cc);
	r_cons_break_push (r_cons_singleton (), NULL, NULL);

	// asked of the convention, not of an argument, so the arg count is not known yet
	const char *first = r_anal_cc_argloc (anal, cc, 0, 0, -1);
	const bool stack_cc = first && *first == '^';
	if (verbose && r_str_startswith (fcn_name, "sym.imp.")) {
		R_LOG_WARN ("Missing function definition for '%s'", fcn_name + 8);
	}
	if (!max) {
		max = stack_cc? DEFAULT_MAX: r_anal_cc_max_arg (anal, cc);
	}
	// TODO: if function takes more than 7 args is usually bad analysis
	if (max > 7) {
		max = DEFAULT_MAX;
	}

	RVecString types;
	RVecString_init (&types);
	const ut32 opmask = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL;
	for (i = 0; i < max; i++) {
		int arg_num = stack_rev? (max - 1 - i): i;
		// one lookup answers both where the arg lives and its slot offset, so the two cannot disagree
		RAnalCCArgSlot slot;
		const bool resolved = r_anal_cc_argslot (anal, cc, arg_num, max, false, &slot);
		const bool in_stack = resolved && !slot.reg;
		const st64 soff = in_stack? slot.off: -1; // a register-homed arg occupies no stack slot
		const char *place = resolved? slot.reg: NULL;
		ut64 selfptr = 0;
		const ut64 selfsize = tp_sizefn_arg_stacksize (tps, cc, fcn_name, arg_num, max, &selfptr);
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

			bool pos_hit = type_pos_hit (tt, in_stack, sp, j, soff, place);
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
							bool ok = anal->iob.read_at
								&& anal->iob.read_at (anal->iob.io, f->addr, (ut8 *)formatstr, len) == len;
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
							fcn_name, in_stack, place, soff, addr, userfnc);
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
				if (tp_op_loads_value (tt, op, j)) {
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
							fcn_name, in_stack, place, soff, addr, userfnc);
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
					case R_ANAL_OP_TYPE_STORE:
						res = true;
						break;
					case R_ANAL_OP_TYPE_LOAD:
						// A load through a copied struct pointer is another deref hop.
						// Keep the old stop behavior when it is not a plain field load.
						if (tps->cfg_fields
								&& tp_chain_collect (tt, j, op, &chain, regname, sizeof (regname))) {
							break;
						}
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
		free (owned_type);
	}
	RVecString_fini (&types);
	r_cons_break_pop (r_cons_singleton ());
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
const char *tp_call_target_name(RAnal *anal, RAnalOp *aop, ut32 type, RAnalFunction **fcn_call) {
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
	return r_anal_call_type_at (anal, aop->addr);
}

// the callee's calling convention: its own when known, else derived from the name
const char *tp_call_cc(RAnal *anal, RAnalFunction *fcn_call, const char *name) {
	const char *cc = fcn_call? r_anal_function_cc (fcn_call): NULL;
	return cc? cc: r_anal_cc_func (anal, name);
}

static void tp_call_effect(TPState *tps, const char *name, const char *cc) {
	if (strcmp (name, "JNIInvokeInterface.GetEnv")
			&& strcmp (name, "JNIInvokeInterface.AttachCurrentThread")
			&& strcmp (name,
				"JNIInvokeInterface.AttachCurrentThreadAsDaemon")) {
		return;
	}
	const int argc = r_type_func_args_count (
		tps->anal->sdb_types, name);
	const char *loc = r_anal_cc_argloc (
		tps->anal, cc, 1, 0, argc);
	RRegItem *item = loc? r_reg_get (tps->tt.reg, loc, -1): NULL;
	if (!item) {
		return;
	}
	r_unref (item);
	const ut64 addr = r_reg_getv (tps->tt.reg, loc);
	if (addr && addr != UT64_MAX) {
		tp_mem_type_set (tps, addr, "JNIEnv *");
	}
}

// per-op type propagation body run by tp_emulate_linear for r_anal_type_match
#define TP_CANARY_MAX_INSN 64
#define TP_CANARY_MAX_HOPS 16

// one operand of a guard compare: a register to chase, or a slot the compare reads itself
typedef struct {
	char reg[REGNAME_SIZE];
	int memref; // access width when the operand is a memory reference
} TPCanaryOp;

static void tp_canary_op(TPCanaryOp *co, RVecRArchValue *vals) {
	const RArchValue *v = RVecRArchValue_at (vals, 0);
	*co = (const TPCanaryOp){ 0 };
	if (v && v->memref) {
		co->memref = v->memref;
	} else if (v && v->reg) {
		r_str_ncpy (co->reg, v->reg, REGNAME_SIZE);
	}
}

// the last compare style op of the guard block, and the operands it tests
static ut64 tp_canary_cmp(RAnal *anal, RAnalBlock *bb, TPCanaryOp ops[2]) {
	const ut64 end = bb->addr + bb->size;
	ut64 at = bb->addr;
	ut64 found = UT64_MAX;
	int n;
	// the compare sits at the end of the guard block, so bound the scan from the tail
	if (bb->ninstr > TP_CANARY_MAX_INSN) {
		const ut64 tail = r_anal_bb_opaddr_i (bb, bb->ninstr - TP_CANARY_MAX_INSN);
		if (tail != UT64_MAX && tail >= at && tail < end) {
			at = tail;
		}
	}
	for (n = 0; n < TP_CANARY_MAX_INSN && at < end; n++) {
		RAnalOp *op = tp_anal_op (anal, at, R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL);
		if (!op) {
			break;
		}
		const ut32 t = op->type & R_ANAL_OP_TYPE_MASK;
		if (t == R_ANAL_OP_TYPE_CMP || t == R_ANAL_OP_TYPE_ACMP
				|| t == R_ANAL_OP_TYPE_XOR || t == R_ANAL_OP_TYPE_SUB) {
			found = op->addr;
			tp_canary_op (&ops[0], &op->dsts);
			tp_canary_op (&ops[1], &op->srcs);
		}
		at += R_MAX (op->size, 1);
		r_anal_op_free (op);
	}
	return found;
}

static bool tp_canary_name_var(RAnal *anal, ut64 at, ut64 addr) {
	RAnalVar *var = r_anal_get_used_function_var (anal, at);
	// a register argument occupies no stack slot, so it can never hold the canary
	if (!var || var->kind == R_ANAL_VAR_KIND_REG) {
		return false;
	}
	var_rename (anal, var, "canary", addr);
	return true;
}

// names the slot the compare loaded, found through the register's last writer, at any distance
static bool tp_canary_rename_reg(TPState *tps, RAnalBlock *guard, const char *rname, ut64 cmp_addr, ut64 addr) {
	RAnal *anal = tps->anal;
	TypeTrace *tt = &tps->tt;
	if (R_STR_ISEMPTY (rname)) {
		return false;
	}
	const ut64 end = guard->addr + guard->size;
	int w = etrace_last_regwrite (tt, rname, tt->cur_idx - 1);
	int hops;
	// blocks emulated between the guard and the failure call clobber the register, and the
	// compare writes it too on xor and sub forms, so walk back to the load that fed it
	for (hops = 0; w >= 0 && hops < TP_CANARY_MAX_HOPS; hops++) {
		const ut64 wa = etrace_addrof (tt, w);
		if (wa >= guard->addr && wa < end && wa != cmp_addr) {
			break;
		}
		w = etrace_last_regwrite (tt, rname, w - 1);
	}
	if (w < 0 || hops >= TP_CANARY_MAX_HOPS) {
		return false;
	}
	const ut64 load_addr = etrace_addrof (tt, w);
	const TypeTraceAccess *rd = etrace_find_access (tt, w, etrace_is_memread, NULL);
	const int word = anal->config->bits / 8;
	// a canary fills one aligned pointer sized slot, a narrower or skewed load is something else
	if (!rd || word < 1 || rd->mem.size != word || (rd->mem.addr % word)) {
		return false;
	}
	RAnalOp *op = tp_anal_op (anal, load_addr, R_ARCH_OP_MASK_BASIC);
	if (!op) {
		return false;
	}
	const bool mov = (op->type & R_ANAL_OP_TYPE_MASK) == R_ANAL_OP_TYPE_MOV;
	r_anal_op_free (op);
	return mov? tp_canary_name_var (anal, load_addr, addr): false;
}

static bool tp_canary_from_guard(TPState *tps, RAnalBlock *guard, ut64 addr) {
	RAnal *anal = tps->anal;
	TPCanaryOp ops[2] = {{{ 0 }}};
	const ut64 cmp_addr = tp_canary_cmp (anal, guard, ops);
	if (cmp_addr == UT64_MAX) {
		return false;
	}
	const int word = anal->config->bits / 8;
	int i;
	for (i = 0; i < 2; i++) {
		// a compare reading the slot in place never loads it into a register first
		if (ops[i].memref == word && tp_canary_name_var (anal, cmp_addr, addr)) {
			return true;
		}
		if (tp_canary_rename_reg (tps, guard, ops[i].reg, cmp_addr, addr)) {
			return true;
		}
	}
	return false;
}

// every conditional predecessor is a candidate: one failure block can guard several checks
static void tp_canary_rename(TPState *tps, RAnalFunction *fcn, ut64 bb_addr, ut64 addr) {
	RListIter *iter;
	RAnalBlock *bb;
	r_list_foreach (fcn->bbs, iter, bb) {
		if (bb->addr != bb_addr && (bb->jump == bb_addr || bb->fail == bb_addr)) {
			if (tp_canary_from_guard (tps, bb, addr)) {
				return;
			}
		}
	}
}

static void type_match_op_cb(void *user, RAnalOp *aop, RAnalOp *next_op, ut64 addr, ut64 bb_addr) {
	TypeMatchCtx *c = user;
	RAnal *anal = c->anal;
	TPState *tps = c->tps;
	TypeTrace *etrace = &tps->tt;
	Sdb *TDB = anal->sdb_types;
	char *fcn_name = NULL;
	c->tp.userfnc = false;
	if (tps->lineage_reset) {
		// state came from another predecessor: call-return and one-op adjacency tracking are stale
		tp_state_fini (&c->tp);
		tp_state_reset (&c->tp);
		c->tp.resolved = false;
		c->tp.prev_var = NULL;
		tps->lineage_reset = false;
	}
	tps->tt.cur_idx = etrace_index (etrace);
	int cur_idx = tps->tt.cur_idx - 1;
	if (cur_idx < 0) {
		cur_idx = 0;
	}
	RAnalVar *var = r_anal_get_used_function_var (anal, aop->addr);
	ut32 type = aop->type & R_ANAL_OP_TYPE_MASK;
	if ((type == R_ANAL_OP_TYPE_UCALL || type == R_ANAL_OP_TYPE_UCCALL)
			&& R_STR_ISNOTEMPTY (aop->reg)) {
		r_anal_call_type_set (anal, addr, NULL);
		ut64 load_addr = UT64_MAX;
		char *call_type = tp_indirect_call_type (tps,
			c->fcn, aop->reg, &load_addr);
		if (call_type) {
			r_anal_call_type_set (anal, addr, call_type);
			if (load_addr != UT64_MAX) {
				r_anal_hint_set_offset (anal,
					load_addr, call_type);
			}
			free (call_type);
		}
	}
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
				tp_call_effect (tps, fcn_name, Cc);
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
				tp_canary_rename (tps, c->fcn, bb_addr, addr);
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
				int nread = anal->iob.read_at
					? anal->iob.read_at (anal->iob.io, aop->ptr, sbuf, sizeof (sbuf) - 1)
					: -1;
				ut64 ptr = nread >= aop->refptr
					? r_read_ble (sbuf, c->be, aop->refptr * 8)
					: 0;
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
		const TPEmuResult res = tp_emulate_linear (tps, fcn, 0, type_match_op_cb, &ctx, true, true);
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
