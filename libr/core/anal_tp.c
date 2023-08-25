/* radare - LGPL - Copyright 2016-2023 - oddcoder, sivaramaaa, pancake */
/* type matching - type propagation */

#include <r_core.h>
#define LOOP_MAX 10

#define D if (false)
#define DD if (false)

R_VEC_TYPE (RVecUT64, ut64);
R_VEC_TYPE (RVecBuf, ut8);

/// BEGIN /////////////////// esil trace helpers ///////////////////////

static int etrace_index(REsilTrace *etrace) {
	int len = RVecTraceOp_length (&etrace->db.ops);
	etrace->cur_idx = len; //  > 0? len -1: 0;
	return etrace->cur_idx; // RVecTraceOp_length (&etrace->db.ops);
}

static ut64 etrace_addrof(REsilTrace *etrace, ut32 idx) {
	REsilTraceOp *op = RVecTraceOp_at (&etrace->db.ops, idx);
	return op? op->addr: 0;
}

static ut64 etrace_memwrite_addr(REsilTrace *etrace, ut32 idx) {
	REsilTraceOp *op = RVecTraceOp_at (&etrace->db.ops, idx);
	D eprintf ("memwrite %d %d\n", etrace->idx, idx);
	if (op && op->start != op->end) {
		REsilTraceAccess *start = RVecAccess_at (&etrace->db.accesses, op->start);
		REsilTraceAccess *end = RVecAccess_at (&etrace->db.accesses, op->end - 1);
		while (start <= end) {
			if (!start->is_reg && start->is_write) {
				return start->mem.addr;
			}
			start++;
		}
	}
	return 0;
}

static bool etrace_have_memread(REsilTrace *etrace, ut32 idx) {
	REsilTraceOp *op = RVecTraceOp_at (&etrace->db.ops, idx);
	D eprintf ("memread %d %d\n", etrace->idx, idx);
	if (op && op->start != op->end) {
		REsilTraceAccess *start = RVecAccess_at (&etrace->db.accesses, op->start);
		REsilTraceAccess *end = RVecAccess_at (&etrace->db.accesses, op->end - 1);
		while (start <= end) {
			if (!start->is_reg && !start->is_write) {
				return true;
			}
			start++;
		}
	}
	return false;
}

static ut64 etrace_regread_value(REsilTrace *etrace, ut32 idx, const char *rname) {
	D eprintf ("regread %d %d\n", etrace->idx, idx);
	REsilTraceOp *op = RVecTraceOp_at (&etrace->db.ops, idx);
	if (op && op->start != op->end) {
		REsilTraceAccess *start = RVecAccess_at (&etrace->db.accesses, op->start);
		REsilTraceAccess *end = RVecAccess_at (&etrace->db.accesses, op->end - 1);
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

static const char *etrace_regwrite(REsilTrace *etrace, ut32 idx) {
	DD eprintf ("regwrite %d %d\n", etrace->idx, idx);
	REsilTraceOp *op = RVecTraceOp_at (&etrace->db.ops, idx);
	if (op && op->start != op->end) {
		REsilTraceAccess *start = RVecAccess_at (&etrace->db.accesses, op->start);
		REsilTraceAccess *end = RVecAccess_at (&etrace->db.accesses, op->end - 1);
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

static bool anal_emul_init(RCore *core, RConfigHold *hc, RDebugTrace **dt, REsilTrace **et) {
	r_return_val_if_fail (core && core->anal && core->anal->esil, false);
	*dt = core->dbg->trace;
	*et = core->anal->esil->trace;
	core->dbg->trace = r_debug_trace_new ();
	core->anal->esil->trace = r_esil_trace_new (core->anal->esil);
	r_config_hold (hc, "esil.romem", "dbg.trace", "esil.nonull", "dbg.follow", NULL);
	r_config_set_b (core->config, "esil.romem", true);
	r_config_set_b (core->config, "dbg.trace", true);
	r_config_set_b (core->config, "esil.nonull", true);
	r_config_set_i (core->config, "dbg.follow", 0);
	const char *bp = r_reg_get_name (core->anal->reg, R_REG_NAME_BP);
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	if ((bp && !r_reg_getv (core->anal->reg, bp)) && (sp && !r_reg_getv (core->anal->reg, sp))) {
		R_LOG_WARN ("The virtual stack is not yet available. Run aeim or aei and try again");
		return false;
	}
	return true;
}

static void anal_emul_restore(RCore *core, RConfigHold *hc, RDebugTrace *dt, REsilTrace *et) {
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	r_debug_trace_free (core->dbg->trace);
	r_esil_trace_free (core->anal->esil->trace);
	core->anal->esil->trace = et;
	core->dbg->trace = dt;
}

static bool etrace_regwrite_contains(REsilTrace *etrace, ut32 idx, const char *rname) {
	DD eprintf ("regwrite contains %d %s\n", idx, rname);
	r_return_val_if_fail (etrace && rname, false);
	REsilTraceOp *op = RVecTraceOp_at (&etrace->db.ops, idx); // AAA + 1);
	if (op && op->start != op->end) {
		REsilTraceAccess *start = RVecAccess_at (&etrace->db.accesses, op->start);
		REsilTraceAccess *end = RVecAccess_at (&etrace->db.accesses, op->end - 1);
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

static bool type_pos_hit(RAnal *anal, bool in_stack, int idx, int size, const char *place) {
	DD eprintf ("TYpe pos hit %d %d %d %s\n", in_stack, idx, size, place);
	REsilTrace *etrace = anal->esil->trace;
	if (in_stack) {
		const char *sp_name = r_reg_get_name (anal->reg, R_REG_NAME_SP); // XXX this is slow and we can cache
		ut64 sp = r_reg_getv (anal->reg, sp_name); // XXX this is slow too and we can cache
		const ut64 write_addr = etrace_memwrite_addr (etrace, idx); // AAA -1
		return (write_addr == sp + size);
	}
	return place && etrace_regwrite_contains (etrace, idx, place);
}

static void var_rename(RAnal *anal, RAnalVar *v, const char *name, ut64 addr) {
	if (!name || !v) {
		return;
	}
	if (!*name || !strcmp (name , "...")) {
		return;
	}
	bool is_default = (r_str_startswith (v->name, VARPREFIX)
			|| r_str_startswith (v->name, ARGPREFIX));
	if (*name == '*') {
		name++;
	}
	// longer name tends to be meaningful like "src" instead of "s1"
	if (!is_default && (strlen (v->name) > strlen (name))) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
	if (!fcn) {
		return;
	}
	r_anal_var_rename (v, name, false);
}

static void var_retype(RAnal *anal, RAnalVar *var, const char *vname, const char *type, bool ref, bool pfx) {
	DD eprintf ("Var retype %s %s\n", var->name, type);
	r_return_if_fail (anal && var && type);
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
		DD eprintf ("DEFAULT NOT DOING THIS\n");
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
		DD eprintf ("not default NOT DOING A SHIT HERE\n");
		return;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (pfx) {
		if (is_default && !r_str_startswith (var->type, "signed")) {
			r_strbuf_setf (sb, "%s %s", type, tmp);
		} else {
			r_strbuf_free (sb);
			DD eprintf ("THIS IS RETURN NOT DOING A SHIT HERE\n");
			return;
		}
	} else {
		r_strbuf_set (sb, type);
	}
	if (r_str_startswith (r_strbuf_get (sb), "const ")) {
		// Dropping const from type
		//TODO: Inferring const type
		r_strbuf_setf (sb, "%s", type + 6);
	}
	if (is_ptr) {
		//type *ptr => type *
		r_strbuf_append (sb, " *");
	}
	if (ref) {
		if (r_str_endswith (r_strbuf_get (sb), "*")) { // type * => type **
			r_strbuf_append (sb, "*");
		} else {   //  type => type *
			r_strbuf_append (sb, " *");
		}
	}

	char* tmp1 = r_strbuf_get (sb);
	if (r_str_startswith (tmp1, "unsigned long long")) {
		r_strbuf_set (sb, "uint64_t");
	} else if (r_str_startswith (tmp1, "unsigned")) {
		r_strbuf_set (sb, "uint32_t");
	} else if (r_str_startswith (tmp1, "int")) {
		r_strbuf_set (sb, "int32_t");
	}
	r_anal_var_set_type (var, r_strbuf_get (sb));
	r_strbuf_free (sb);
}

static void get_src_regname(RCore *core, ut64 addr, char *regname, int size) {
	DD eprintf ("getsrcregname 0x%"PFMT64x" %s %d\n", addr, regname, size);
	r_return_if_fail (core && regname && size > 0);
	RAnal *anal = core->anal;
	regname[0] = 0;
	RAnalOp *op = r_core_anal_op (core, addr, R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL);
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
		DD R_LOG_WARN ("===================regitem %s", regname);
		r_unref (ri);
	} else {
		DD R_LOG_WARN ("no regitem %s at 0x%"PFMT64x, op_esil, addr);
	}
	r_anal_op_free (op);
}

static ut64 get_addr(REsilTrace *etrace, const char *regname, int idx) {
	if (R_STR_ISEMPTY (regname)) {
		return 0;
	}
	/// r_strf_var (query, 64, "%d.reg.read.%s", idx, regname);
	// return r_num_math (NULL, sdb_const_get (trace, query, 0));
	return etrace_regread_value (etrace, idx, regname);
}

static _RAnalCond cond_invert(RAnal *anal, _RAnalCond cond) {
	switch (cond) {
	case R_ANAL_COND_LE:
		return R_ANAL_COND_GT;
	case R_ANAL_COND_LT:
		return R_ANAL_COND_GE;
	case R_ANAL_COND_GE:
		return R_ANAL_COND_LT;
	case R_ANAL_COND_GT:
		return R_ANAL_COND_LE;
	case R_ANAL_COND_AL:
		return R_ANAL_COND_NV;
	case R_ANAL_COND_NV:
		return R_ANAL_COND_AL;
	case R_ANAL_COND_EQ:
		return R_ANAL_COND_NE;
	case R_ANAL_COND_NE:
		return R_ANAL_COND_EQ;
	default:
		R_LOG_WARN ("unhandled condition for swapping %d", cond);
		break;
	}
	return 0; // 0 is COND_ALways...
	/* I haven't looked into it but I suspect that this might be confusing:
	the opposite of any condition not in the list above is "always"? */
}

typedef const char* String;
R_VEC_TYPE (RVecString, String);  // no fini, these are owned by SDB

static bool parse_format(RCore *core, const char *fmt, RVecString *vec) {
	if (R_STR_ISEMPTY (fmt)) {
		return false;
	}

	Sdb *s = core->anal->sdb_fmts;
	const char *spec = r_config_get (core->config, "anal.types.spec");
	char arr[32] = {0};
	const char *ptr = strchr (fmt, '%');
	while (ptr) {
		ptr++;
		// strip [width] specifier
		while (IS_DIGIT (*ptr)) {
			ptr++;
		}
		r_str_ncpy (arr, ptr, sizeof (arr) - 1);
		char *tmp = arr;
		while (isalpha (*tmp)) {
			tmp++;
		}
		*tmp = '\0';
		r_strf_var (query, 128, "spec.%s.%s", spec, arr);
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
	DD eprintf (">>> CALLE ARG\n");
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
			return;
		}
		char *t = strdup (type);
		var_retype (anal, rvar, NULL, type, false, false);
		RAnalVar *lvar = r_anal_var_get_dst_var (rvar);
		if (lvar) {
			var_retype (anal, lvar, NULL, t, false, false);
		}
		free (t);
	}
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
static void type_match(RCore *core, char *fcn_name, ut64 addr, ut64 baddr, const char* cc,
		int prev_idx, bool userfnc, ut64 caddr) {
	r_return_if_fail (core && core->anal->esil && core->anal->esil->trace && fcn_name);
	RAnal *anal = core->anal;
	REsilTrace *etrace = anal->esil->trace;
	Sdb *TDB = anal->sdb_types;
	const int idx = etrace_index (etrace) -1;
	const bool verbose = r_config_get_b (core->config, "anal.types.verbose"); // XXX
	bool stack_rev = false, in_stack = false, format = false;
	DD eprintf ("type_match %s %"PFMT64x" %"PFMT64x" %s %d\n", fcn_name, addr, baddr, cc, prev_idx);

	if (!fcn_name || !cc) {
		return;
	}
	int i, j, pos = 0, size = 0, max = r_type_func_args_count (TDB, fcn_name);
	int lastarg = ST32_MAX;
	const char *place = r_anal_cc_arg (anal, cc, lastarg, -1);
	r_cons_break_push (NULL, NULL);

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
		if (in_stack) {
			max = DEFAULT_MAX;
		} else {
			max = r_anal_cc_max_arg (anal, cc);
		}
	}
	// TODO: if function takes more than 7 args is usually bad analysis
	if (max > 7) {
		max = DEFAULT_MAX;
	}

	RVecString types;
	RVecString_init (&types);
	const int bytes = anal->config->bits / 8;
	const ut32 opmask = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL;
	for (i = 0; i < max; i++) {
		int arg_num = stack_rev ? (max - 1 - i) : i;
		char *type = NULL;
		const char *name = NULL;
		DD eprintf ("ARG NUM %d %d %d\n", i, arg_num, format);
		if (format) {
			if (RVecString_empty (&types)) {
				break;
			}
			const String *type_ = RVecString_at (&types, pos++);
			type = type_ ? r_str_new (*type_) : NULL;
			DD R_LOG_INFO ("TYPE (%s)", type);
		} else {
			type = r_type_func_args_type (TDB, fcn_name, arg_num);
			name = r_type_func_args_name (TDB, fcn_name, arg_num);
		}
		if (!type && !userfnc) {
			DD eprintf ("NO TYPE AND NO USER FUNK\n");
			continue;
		}
		if (!in_stack) {
			// XXX: param arg_num must be fixed to support floating point register
			// before this change place could be null
			DD eprintf ("not in stack\n");
			const char *p = r_anal_cc_arg (anal, cc, arg_num, -1);
			if (p && r_str_startswith (p, "stack")) {
				in_stack = true;
				place = p;
			}
			place = p;
		}
		char regname[REGNAME_SIZE] = {0};
		ut64 xaddr = UT64_MAX;
		bool memref = false;
		bool cmt_set = false;
		bool res = false;
		// Backtrace instruction from source sink to prev source sink
		for (j = idx; j >= prev_idx; j--) {
			// r_strf_var (k, 32, "%d.addr", j);
			// ut64 instr_addr = sdb_num_get (trace, k, 0);
			ut64 instr_addr = etrace_addrof (etrace, j);
			DD eprintf ("0x%08"PFMT64x" back traceing %d\n", instr_addr, j);
			if (instr_addr < baddr) {
				break;
			}
			RAnalOp *op = r_core_anal_op (core, instr_addr, opmask);
			if (!op) {
				r_anal_op_free (op);
				break;
			}
			RAnalOp *next_op = r_core_anal_op (core, instr_addr + op->size, opmask);
			if (!next_op || (j != idx && (next_op->type == R_ANAL_OP_TYPE_CALL || next_op->type == R_ANAL_OP_TYPE_JMP))) {
				r_anal_op_free (op);
				r_anal_op_free (next_op);
				break;
			}
			RAnalVar *var = r_anal_get_used_function_var (anal, op->addr);
			if (op->type == R_ANAL_OP_TYPE_MOV && etrace_have_memread (etrace, j)) {
				memref = ! (!memref && var && (var->kind != R_ANAL_VAR_KIND_REG));
			}
			// Match type from function param to instr
			if (type_pos_hit (anal, in_stack, j, size, place)) {
				DD eprintf ("InHit\n");
				if (!cmt_set && type && name) {
					char *ms = r_str_newf ("%s%s%s", type, r_str_endswith (type, "*") ? "" : " ", name);
					r_meta_set_string (anal, R_META_TYPE_VARTYPE, instr_addr, ms);
					free (ms);
					cmt_set = true;
					if ((op->ptr && op->ptr != UT64_MAX) && !strcmp (name, "format")) {
						RFlagItem *f = r_flag_get_by_spaces (core->flags, op->ptr, R_FLAGS_FS_STRINGS, NULL);
						if (f) {
							char formatstr[0x200];
							int read = r_io_nread_at (core->io, f->offset, (ut8 *)formatstr, R_MIN (sizeof (formatstr) - 1, f->size));
							if (read > 0) {
								formatstr[read] = '\0';
								RVecString_clear (&types);
								if (parse_format (core, formatstr, &types)) {
									max += RVecString_length (&types);
								}
								format = true;
							}
						}
					}
				}
				if (var) {
					DD eprintf ("retype var %s\n", name);
					if (!userfnc) {
						// not a userfunction, propagate the callee's arg types into our function's vars
						var_retype (anal, var, name, type, memref, false);
						var_rename (anal, var, name, addr);
					} else {
						// callee is a userfunction, propagate our variable's type into the callee's args
						retype_callee_arg (anal, fcn_name, in_stack, place, size, var->type);
					}
					res = true;
				} else {
					DD eprintf ("re-typed 0x%"PFMT64x"\n", instr_addr);
					get_src_regname (core, instr_addr, regname, sizeof (regname));
					DD eprintf ("get src regname 0x%"PFMT64x" = %s\n", instr_addr, regname);
					xaddr = get_addr (etrace, regname, j);
				}
			} else {
				DD eprintf ("NoHit\n");
			}
			DD eprintf ("RES REGNAME %d %d %s\n", res, j, regname);
			// Type propagate by following source reg
			if (!res && *regname && etrace_regwrite_contains (etrace, j, regname)) {
				if (var) {
					DD eprintf ("----- retyps (%s) (%s)\n", var->name, type);
					if (!userfnc) {
						// not a userfunction, propagate the callee's arg types into our function's vars
						var_retype (anal, var, name, type, memref, false);
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
						get_src_regname (core, instr_addr, regname, sizeof (regname));
						break;
					case R_ANAL_OP_TYPE_LEA:
					case R_ANAL_OP_TYPE_LOAD:
					case R_ANAL_OP_TYPE_STORE:
						res = true;
						break;
					}
				}
			} else if (var && res && (xaddr && xaddr != UT64_MAX)) { // Type progation using value
				char tmp[REGNAME_SIZE] = {0};
				get_src_regname (core, instr_addr, tmp, sizeof (tmp));
				ut64 ptr = get_addr (etrace, tmp, j);
				if (ptr == xaddr) {
					var_retype (anal, var, name, r_str_get_fail (type, "int"), memref, false);
				}
			}
			r_anal_op_free (op);
			r_anal_op_free (next_op);
		}
		size += bytes;
		free (type);
	}
	RVecString_fini (&types);
	r_cons_break_pop ();
}

static int bb_cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return a->addr > b->addr ? 1 : (a->addr < b->addr ? -1 : 0);
}

R_API void r_core_anal_type_match(RCore *core, RAnalFunction *fcn) {
	r_return_if_fail (core && core->anal && fcn);

	const int op_tions = R_ARCH_OP_MASK_BASIC | R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_ESIL | R_ARCH_OP_MASK_HINT;
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = {0};
	bool resolved = false;
	RAnal *anal = core->anal;
	Sdb *TDB = anal->sdb_types;
	int ret;
	const bool chk_constraint = r_config_get_b (core->config, "anal.types.constraint");
	const int mininstrsz = r_anal_archinfo (anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	int cur_idx, prev_idx = 0;
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return;
	}
	RDebugTrace *dt = NULL;
	REsilTrace *et = NULL;
	if (!anal_emul_init (core, hc, &dt, &et) || !fcn) {
		anal_emul_restore (core, hc, dt, et);
		return;
	}
	RDebugTrace *dtrace = core->dbg->trace;
	HtPPOptions opt = dtrace->ht->opt;
	ht_pp_free (dtrace->ht);
	dtrace->ht = ht_pp_new_size (fcn->ninstr, opt.dupvalue, opt.freefn, opt.calcsizeV);
	dtrace->ht->opt = opt;

	anal->esil->trace->cur_idx = 0;
	const bool be = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
	char *fcn_name = NULL;
	char *ret_type = NULL;
	bool str_flag = false;
	bool prop = false;
	bool prev_var = false;
	char prev_type[256] = {0};
	const char *prev_dest = NULL;
	char *ret_reg = NULL;
	const char *_pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	if (!_pc) {
		anal_emul_restore (core, hc, dt, et);
		return;
	}
	char *pc = strdup (_pc);
	r_cons_break_push (NULL, NULL);
	RVecBuf buf;
	RVecBuf_init (&buf);
	RVecUT64 bblist;
	RVecUT64_init (&bblist);
	r_list_sort (fcn->bbs, bb_cmpaddr); // TODO: The algorithm can be more accurate if blocks are followed by their jmp/fail, not just by address
	int retries = 2;
repeat:
	if (retries < 0) {
		anal_emul_restore (core, hc, dt, et);
		free (pc);
		return;
	}
	RVecUT64_clear (&bblist);
	size_t bblist_size = r_list_length (fcn->bbs); // TODO: Use ut64
	RVecUT64_reserve (&bblist, bblist_size);
	// TODO: add a dependency graph out of it, maybe just saving the depth index is enough so we save and restore the state on each level
	r_list_foreach (fcn->bbs, it, bb) {
		RVecUT64_push_back (&bblist, &bb->addr);
	}
	int j;
	for (j = 0; j < bblist_size; j++) {
		REsilTrace *etrace = core->anal->esil->trace;
		{
			const ut64 addr = *RVecUT64_at (&bblist, j);
			DD eprintf ("BB 0x%"PFMT64x"\n", addr);
			bb = r_anal_get_block_at (core->anal, addr);
			if (!bb) {
				R_LOG_WARN ("basic block at 0x%08"PFMT64x" was removed during analysis", addr);
				retries--;
				goto repeat;
			}
		}
		ut64 bb_addr = bb->addr;
		ut64 bb_size = bb->size;
		ut64 addr = bb->addr;
		const ut64 buf_size = bb->size + 32;
		if (!RVecBuf_reserve (&buf, buf_size)) {
			break;
		}
		ut8 *buf_ptr = R_VEC_START_ITER (&buf);
		if (r_io_read_at (core->io, addr, buf_ptr, bb_size) < 1) {
			break;
		}
		int i = 0;
		r_reg_setv (core->dbg->reg, pc, addr);
		for (i = 0; i < bb_size;) {
			if (r_cons_is_breaked ()) {
				goto out_function;
			}
			if (i >= bb_size) {
				break;
			}
			ut64 pcval = r_reg_getv (anal->reg, pc);
			D eprintf ("---> 0x%"PFMT64x"\n", addr);
			if ((addr >= bb_addr + bb_size) || (addr < bb_addr) || pcval != addr) {
				// stop emulating this bb if pc is outside the basic block boundaries
				break;
			}
			DD eprintf ("op 0x%"PFMT64x"\n", addr);
			ret = r_anal_op (anal, &aop, addr, buf_ptr + i, bb_size - i, op_tions);
			if (ret <= 0) {
				DD eprintf ("FAIL\n");
				i += minopcode;
				addr += minopcode;
				r_reg_setv (core->dbg->reg, pc, addr);
				r_anal_op_fini (&aop);
				continue;
			}
			const int loop_count = r_esil_trace_loopcount (etrace, addr);
#if 1
			if (loop_count > LOOP_MAX || aop.type == R_ANAL_OP_TYPE_RET) {
				DD eprintf ("0x%"PFMT64x" LOOP FAIL %d\n", aop.addr, loop_count);
				r_anal_op_fini (&aop);
				break;
			}
#endif
			r_esil_trace_loopcount_increment (etrace, addr);
			if (r_anal_op_nonlinear (aop.type)) { // skip jmp/cjmp/trap/ret/call ops
				r_reg_setv (core->dbg->reg, pc, addr + aop.size); // + ret
			} else {
				// eprintf ("STEP 0x%"PFMT64x"\n", addr);
				r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
			}
#if 1
			// XXX this code looks wrong and slow maybe is not needed
			// maybe the basic block is gone after the step
			if (i < bblist_size) {
				bb = r_anal_get_block_at (core->anal, bb_addr);
				if (!bb) {
					R_LOG_WARN ("basic block at 0x%08"PFMT64x" was removed during analysis", *RVecUT64_at (&bblist, i));
					retries--;
					goto repeat;
				}
			}
#endif

			bool userfnc = false;
			cur_idx = etrace_index (etrace) - 1;
			if (cur_idx < 0) cur_idx = 0;
			anal->esil->trace->cur_idx = etrace_index (etrace);
			RAnalVar *var = r_anal_get_used_function_var (anal, aop.addr);
			DD eprintf ("CUR IDX %d %s\n", cur_idx, var?var->name:"");

			// XXX this is analyzing the same op twice wtf this is so wrong
			RAnalOp *next_op = r_core_anal_op (core, addr + ret, R_ARCH_OP_MASK_BASIC); // | _VAL ?

			ut32 type = aop.type & R_ANAL_OP_TYPE_MASK;
			if (aop.type == R_ANAL_OP_TYPE_CALL || aop.type & R_ANAL_OP_TYPE_UCALL) {
				char *full_name = NULL;
				ut64 callee_addr = UT64_MAX;
				if (aop.type == R_ANAL_OP_TYPE_CALL) {
					RAnalFunction *fcn_call = r_anal_get_fcn_in (anal, aop.jump, -1);
					if (fcn_call) {
						full_name = fcn_call->name;
						callee_addr = fcn_call->addr;
					}
				} else if (aop.ptr != UT64_MAX) {
					RFlagItem *flag = r_flag_get_by_spaces (core->flags, aop.ptr, R_FLAGS_FS_IMPORTS, NULL);
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
					const char* Cc = r_anal_cc_func (anal, fcn_name);
					DD eprintf ("CC can %s %s\n", Cc, fcn_name);
					if (Cc && r_anal_cc_exist (anal, Cc)) {
						char *cc = strdup (Cc);
						type_match (core, fcn_name, addr, bb->addr, cc, prev_idx, userfnc, callee_addr);
						prev_idx = anal->esil->trace->cur_idx;
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
						cur_idx = anal->esil->trace->cur_idx - 2;
						// eprintf (Color_GREEN"ADDROF %d\n"Color_RESET, cur_idx);
						ut64 mov_addr = etrace_addrof (etrace, cur_idx);
						RAnalOp *mop = r_core_anal_op (core, mov_addr, R_ARCH_OP_MASK_VAL | R_ARCH_OP_MASK_BASIC);
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
				char src[REGNAME_SIZE] = {0};
				// r_strf_var (query, 32, "%d.reg.write", cur_idx);
				// const char *cur_dest = sdb_const_get (trace, query, 0);
				// sdb_const_get (trace, query, 0);
				cur_idx = anal->esil->trace->cur_idx - 1;
				const char *cur_dest = etrace_regwrite (etrace, cur_idx);
				DD eprintf ("regwrite2 %d\n", cur_idx);
				get_src_regname (core, aop.addr, src, sizeof (src));
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
						// int *ret; *ret = strlen(s);
						// TODO: memref check , dest and next src match
						char nsrc[REGNAME_SIZE] = {0};
						get_src_regname (core, next_op->addr, nsrc, sizeof (nsrc));
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
				DD eprintf ("PREV DEST %s\n", prev_dest);
				// lea rax , str.hello  ; mov [local_ch], rax;
				// mov rdx , [local_4h] ; mov [local_8h], rdx;
				if (prev_dest && (type == R_ANAL_OP_TYPE_MOV || type == R_ANAL_OP_TYPE_STORE)) {
					char reg[REGNAME_SIZE] = {0};
					DD eprintf ("rmove-typed %s\n", prev_type);
					get_src_regname (core, addr, reg, sizeof (reg));
					bool match = strstr (prev_dest, reg);
					if (str_flag && match) {
						var_retype (anal, var, NULL, "const char *", false, false);
					}
					if (prop && match && prev_var) {
						var_retype (anal, var, NULL, prev_type, false, false);
					}
				}
				if (chk_constraint && var && (type == R_ANAL_OP_TYPE_CMP && aop.disp != UT64_MAX)
						&& next_op && next_op->type == R_ANAL_OP_TYPE_CJMP) {
					bool jmp = false;
					RAnalOp *jmp_op = {0};
					ut64 jmp_addr = next_op->jump;
					RAnalBlock *jmpbb = r_anal_function_bbget_in (anal, fcn, jmp_addr);
					RAnalBlock jbb = {0};
					if (jmpbb) {
						// the bb can be invalidated in the loop below, causing
					        // a crash, so we copy that into a stack ghosty struct
						jbb.addr = jmpbb->addr;
						jbb.size = jmpbb->size;
					}

					// Check exit status of jmp branch
					for (i = 0; i < MAX_INSTR; i++) {
						jmp_op = r_core_anal_op (core, jmp_addr, R_ARCH_OP_MASK_BASIC);
						if (!jmp_op) {
							r_anal_op_free (jmp_op);
							r_anal_op_fini (&aop);
							break;
						}
						if ((jmp_op->type == R_ANAL_OP_TYPE_RET && r_anal_block_contains (&jbb, jmp_addr))
								|| jmp_op->type == R_ANAL_OP_TYPE_CJMP) {
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
						ut8 sbuf[256] = {0};
						r_io_read_at (core->io, aop.ptr, sbuf, sizeof (sbuf) - 1);
						ut64 ptr = r_read_ble (sbuf, be, aop.refptr * 8);
						if (ptr && ptr != UT64_MAX) {
							RFlagItem *f = r_flag_get_by_spaces (core->flags, ptr, R_FLAGS_FS_STRINGS, NULL);
							if (f) {
								str_flag = true;
							}
						}
					} else if (r_flag_exist_at (core->flags, "str", 3, aop.ptr)) {
						str_flag = true;
					}
				}
				// mov dword [local_4h], str.hello;
				if (var && str_flag) {
					var_retype (anal, var, NULL, "const char *", false, false);
				}
				prev_dest = etrace_regwrite (etrace, cur_idx);
				DD eprintf (":= regwrite prevdest %d %s\n", cur_idx, prev_dest);
				if (var) {
					r_str_ncpy (prev_type, var->type, sizeof (prev_type) - 1);
					prop = true;
				}
			}
			i += ret;
			addr += ret;
			// XXX its slow to analyze 2 instructions for every instruction :facepalm: we can reuse
			r_anal_op_free (next_op);
			r_anal_op_fini (&aop);
		}
	}
	RVecBuf_fini (&buf);
	RVecUT64_fini (&bblist);

	// Type propagation for register based args
	RList *list = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_REG);
	RAnalVar *rvar;
	RListIter *iter;
	r_list_foreach (list, iter, rvar) {
		RAnalVar *lvar = r_anal_var_get_dst_var (rvar);
		RRegItem *i = r_reg_index_get (anal->reg, rvar->delta);
		if (!i) {
			continue;
		}
		if (lvar) {
			// Propagate local var type = to => register-based var
			var_retype (anal, rvar, NULL, lvar->type, false, false);
			// Propagate local var type <= from = register-based var
			var_retype (anal, lvar, NULL, rvar->type, false, false);
		}
	}
	r_list_free (list);
out_function:
	// r_core_cmd0 (core, "dte"); // useful for debugging
	R_FREE (ret_reg);
	R_FREE (ret_type);
	r_anal_op_fini (&aop);
	r_cons_break_pop ();
	RVecBuf_fini (&buf);
	RVecUT64_fini (&bblist);
	anal_emul_restore (core, hc, dt, et);
	free (pc);
}
