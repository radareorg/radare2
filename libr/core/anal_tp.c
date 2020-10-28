/* radare - LGPL - Copyright 2016-2020 - oddcoder, sivaramaaa */
/* type matching - type propagation */

#include <r_anal.h>
#include <r_util.h>
#include <r_core.h>
#define LOOP_MAX 10

static bool anal_emul_init(RCore *core, RConfigHold *hc, RDebugTrace **dt, RAnalEsilTrace **et) {
	if (!core->anal->esil) {
		return false;
	}
	*dt = core->dbg->trace;
	*et = core->anal->esil->trace;
	core->dbg->trace = r_debug_trace_new ();
	core->anal->esil->trace = r_anal_esil_trace_new (core->anal->esil);
	r_config_hold_i (hc, "esil.romem", "dbg.trace",
			"esil.nonull", "dbg.follow", NULL);
	r_config_set (core->config, "esil.romem", "true");
	r_config_set (core->config, "dbg.trace", "true");
	r_config_set (core->config, "esil.nonull", "true");
	r_config_set_i (core->config, "dbg.follow", false);
	const char *bp = r_reg_get_name (core->anal->reg, R_REG_NAME_BP);
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	if ((bp && !r_reg_getv (core->anal->reg, bp)) && (sp && !r_reg_getv (core->anal->reg, sp))) {
		eprintf ("Stack isn't initialized.\n");
		eprintf ("Try running aei and aeim commands before aft for default stack initialization\n");
		return false;
	}
	return (core->dbg->trace && core->anal->esil->trace);
}

static void anal_emul_restore(RCore *core, RConfigHold *hc, RDebugTrace *dt, RAnalEsilTrace *et) {
	r_config_hold_restore (hc);
	r_config_hold_free (hc);
	r_debug_trace_free (core->dbg->trace);
	r_anal_esil_trace_free (core->anal->esil->trace);
	core->anal->esil->trace = et;
	core->dbg->trace = dt;
}

#define SDB_CONTAINS(i,s) sdb_array_contains (trace, sdb_fmt ("%d.reg.write", i), s, 0)

static bool type_pos_hit(RAnal *anal, Sdb *trace, bool in_stack, int idx, int size, const char *place) {
	if (in_stack) {
		const char *sp_name = r_reg_get_name (anal->reg, R_REG_NAME_SP);
		ut64 sp = r_reg_getv (anal->reg, sp_name);
		ut64 write_addr = sdb_num_get (trace, sdb_fmt ("%d.mem.write", idx), 0);
		return (write_addr == sp + size);
	}
	return SDB_CONTAINS (idx, place);
}

static void __var_rename(RAnal *anal, RAnalVar *v, const char *name, ut64 addr) {
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

static void __var_retype(RAnal *anal, RAnalVar *var, const char *vname, const char *type, bool ref, bool pfx) {
	r_return_if_fail (anal && var && type);
	// XXX types should be passed without spaces to trim
	type = r_str_trim_head_ro (type);
	// default type if none is provided
	if (!*type) {
		type = "int";
	}
	bool is_ptr = (vname && *vname == '*');
	// removing this return makes 64bit vars become 32bit
	if (!strncmp (type, "int", 3) || (!is_ptr && !strcmp (type, "void"))) {
		// default or void type
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
	bool is_default = tmp != NULL;
	if (!is_default && strncmp (var->type, "void", 4)) {
		// return since type is already propagated
		// except for "void *", since "void *" => "char *" is possible
		return;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (pfx) {
		if (is_default && strncmp (var->type, "signed", 6)) {
			r_strbuf_setf (sb, "%s %s", type, tmp);
		} else {
			r_strbuf_free (sb);
			return;
		}
	} else {
		r_strbuf_set (sb, type);
	}
	if (!strncmp (r_strbuf_get (sb), "const ", 6)) {
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
	RAnal *anal = core->anal;
	RAnalOp *op = r_core_anal_op (core, addr, R_ANAL_OP_MASK_VAL | R_ANAL_OP_MASK_ESIL);
	if (!op || r_strbuf_is_empty (&op->esil)) {
		r_anal_op_free (op);
		return;
	}
	char *op_esil = strdup (r_strbuf_get (&op->esil));
	char *tmp = strchr (op_esil, ',');
	if (tmp) {
		*tmp = '\0';
	}
	memset (regname, 0, size);
	RRegItem *ri = r_reg_get (anal->reg, op_esil, -1);
	if (ri) {
		if ((anal->bits == 64) && (ri->size == 32)) {
			const char *reg = r_reg_32_to_64 (anal->reg, op_esil);
			if (reg) {
				free (op_esil);
				op_esil = strdup (reg);
			}
		}
		strncpy (regname, op_esil, size - 1);
	}
	free (op_esil);
	r_anal_op_free (op);
}

static ut64 get_addr(Sdb *trace, const char *regname, int idx) {
	if (!regname || !*regname) {
		return UT64_MAX;
	}
	const char *query = sdb_fmt ("%d.reg.read.%s", idx, regname);
	return r_num_math (NULL, sdb_const_get (trace, query, 0));
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
	default:
		if (anal->verbose) {
			eprintf ("Unhandled conditional swap\n");
		}
		break;
	}
	return 0; // 0 is COND_ALways...
	/* I haven't looked into it but I suspect that this might be confusing:
	the opposite of any condition not in the list above is "always"? */
}

static RList *parse_format(RCore *core, char *fmt) {
	if (!fmt || !*fmt) {
		return NULL;
	}
	RList *ret = r_list_new ();
	if (!ret) {
		return NULL;
	}
	Sdb *s = core->anal->sdb_fmts;
	const char *spec = r_config_get (core->config, "anal.types.spec");
	char arr[10] = {0};
	char *ptr = strchr (fmt, '%');
	fmt[strlen (fmt) - 1] = '\0';
	while (ptr) {
		ptr++;
		// strip [width] specifier
		while (IS_DIGIT (*ptr)) {
			ptr++;
		}
		r_str_ncpy (arr, ptr, sizeof (arr) - 1);
		char *tmp = arr;
		while (tmp && (IS_LOWER (*tmp) || IS_UPPER (*tmp))) {
			tmp++;
		}
		*tmp = '\0';
		const char *query = sdb_fmt ("spec.%s.%s", spec, arr);
		char *type = (char *) sdb_const_get (s, query, 0);
		if (type) {
			r_list_append (ret, type);
		}
		ptr = strchr (ptr, '%');
	}
	return ret;
}

static void retype_callee_arg(RAnal *anal, const char *callee_name, bool in_stack, const char *place, int size, const char *type) {
	RAnalFunction *fcn = r_anal_get_function_byname (anal, callee_name);
	if (!fcn) {
		return;
	}
	if (in_stack) {
		RAnalVar *var = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_BPV, size - fcn->bp_off + 8);
		if (!var) {
			return;
		}
		__var_retype (anal, var, NULL, type, false, false);
	} else {
		RRegItem *item = r_reg_get (anal->reg, place, -1);
		if (!item) {
			return;
		}
		RAnalVar *rvar = r_anal_function_get_var (fcn, R_ANAL_VAR_KIND_REG, item->index);
		if (!rvar) {
			return;
		}
		__var_retype (anal, rvar, NULL, type, false, false);
		RAnalVar *lvar = r_anal_var_get_dst_var (rvar);
		if (lvar) {
			__var_retype (anal, lvar, NULL, type, false, false);
		}
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
	Sdb *trace = core->anal->esil->trace->db;
	Sdb *TDB = core->anal->sdb_types;
	RAnal *anal = core->anal;
	RList *types = NULL;
	int idx = sdb_num_get (trace, "idx", 0);
	bool verbose = r_config_get_i (core->config, "anal.types.verbose");
	bool stack_rev = false, in_stack = false, format = false;

	if (!fcn_name || !cc) {
		return;
	}
	int i, j, pos = 0, size = 0, max = r_type_func_args_count (TDB, fcn_name);
	const char *place = r_anal_cc_arg (anal, cc, ST32_MAX);
	r_cons_break_push (NULL, NULL);

	if (place && !strcmp (place, "stack_rev")) {
		stack_rev = true;
	}
	place = r_anal_cc_arg (anal, cc, 0);
	if (place && r_str_startswith ("stack", place)) {
		in_stack = true;
	}
	if (verbose && !strncmp (fcn_name, "sym.imp.", 8)) {
		eprintf ("%s missing function definition\n", fcn_name + 8);
	}
	if (!max) {
		if (!in_stack) {
			max = r_anal_cc_max_arg (anal, cc);
		} else {
			max = DEFAULT_MAX;
		}
	}
	for (i = 0; i < max; i++) {
		int arg_num = stack_rev ? (max - 1 - i) : i;
		char *type = NULL;
		const char *name = NULL;
		if (format) {
			if (r_list_empty (types)) {
				break;
			}
			type = r_str_new (r_list_get_n (types, pos++));
		} else {
			type = r_type_func_args_type (TDB, fcn_name, arg_num);
			name = r_type_func_args_name (TDB, fcn_name, arg_num);
		}
		if (!type && !userfnc) {
			continue;
		}
		if (!in_stack) {
			//XXX: param arg_num must be fixed to support floating point register
			place = r_anal_cc_arg (anal, cc, arg_num);
			if (place && r_str_startswith ("stack", place)) {
				in_stack = true;
			}
		}
		char regname[REGNAME_SIZE] = {0};
		ut64 xaddr = UT64_MAX;
		bool memref = false;
		bool cmt_set = false;
		bool res = false;
		// Backtrace instruction from source sink to prev source sink
		for (j = idx; j >= prev_idx; j--) {
			ut64 instr_addr = sdb_num_get (trace, sdb_fmt ("%d.addr", j), 0);
			if (instr_addr < baddr) {
				break;
			}
			RAnalOp *op = r_core_anal_op (core, instr_addr, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_VAL);
			if (!op) {
				r_anal_op_free (op);
				break;
			}
			RAnalOp *next_op = r_core_anal_op (core, instr_addr + op->size, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_VAL);
			if (!next_op || (j != idx && (next_op->type == R_ANAL_OP_TYPE_CALL
							|| next_op->type == R_ANAL_OP_TYPE_JMP))) {
				r_anal_op_free (op);
				r_anal_op_free (next_op);
				break;
			}
			RAnalVar *var = r_anal_get_used_function_var (anal, op->addr);
			const char *query = sdb_fmt ("%d.mem.read", j);
			if (op->type == R_ANAL_OP_TYPE_MOV && sdb_const_get (trace, query, 0)) {
				memref = ! (!memref && var && (var->kind != R_ANAL_VAR_KIND_REG));
			}
			// Match type from function param to instr
			if (type_pos_hit (anal, trace, in_stack, j, size, place)) {
				if (!cmt_set && type && name) {
					r_meta_set_string (anal, R_META_TYPE_VARTYPE, instr_addr,
							sdb_fmt ("%s%s%s", type, r_str_endswith (type, "*") ? "" : " ", name));
					cmt_set = true;
					if ((op->ptr && op->ptr != UT64_MAX) && !strcmp (name, "format")) {
						RFlagItem *f = r_flag_get_by_spaces (core->flags, op->ptr, R_FLAGS_FS_STRINGS, NULL);
						if (f) {
							char formatstr[0x200];
							int read = r_io_nread_at (core->io, f->offset, (ut8 *)formatstr, R_MIN (sizeof (formatstr) - 1, f->size));
							if (read > 0) {
								formatstr[read] = '\0';
								if ((types = parse_format (core, formatstr))) {
									max += r_list_length (types);
								}
								format = true;
							}
						}
					}
				}
				if (var) {
					if (!userfnc) {
						// not a userfunction, propagate the callee's arg types into our function's vars
						__var_retype (anal, var, name, type, memref, false);
						__var_rename (anal, var, name, addr);
					} else {
						// callee is a userfunction, propagate our variable's type into the callee's args
						retype_callee_arg (anal, fcn_name, in_stack, place, size, var->type);
					}
					res = true;
				} else {
					get_src_regname (core, instr_addr, regname, sizeof (regname));
					xaddr = get_addr (trace, regname, j);
				}
			}
			// Type propagate by following source reg
			if (!res && *regname && SDB_CONTAINS (j, regname)) {
				if (var) {
					if (!userfnc) {
						// not a userfunction, propagate the callee's arg types into our function's vars
						__var_retype (anal, var, name, type, memref, false);
						__var_rename (anal, var, name, addr);
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
			} else if (var && res && xaddr && (xaddr != UT64_MAX)) { // Type progation using value
				char tmp[REGNAME_SIZE] = {0};
				get_src_regname (core, instr_addr, tmp, sizeof (tmp));
				ut64 ptr = get_addr (trace, tmp, j);
				if (ptr == xaddr) {
					__var_retype (anal, var, name, type? type: "int", memref, false);
				}
			}
			r_anal_op_free (op);
			r_anal_op_free (next_op);
		}
		size += anal->bits / 8;
		free (type);
	}
	r_list_free (types);
	r_cons_break_pop ();
}

static int bb_cmpaddr(const void *_a, const void *_b) {
	const RAnalBlock *a = _a, *b = _b;
	return a->addr > b->addr ? 1 : (a->addr < b->addr ? -1 : 0);
}

R_API void r_core_anal_type_match(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = {0};
	bool resolved = false;

	r_return_if_fail (core && core->anal && fcn);

	if (!core->anal->esil) {
		eprintf ("Please run aeim\n");
		return;
	}

	RAnal *anal = core->anal;
	Sdb *TDB = anal->sdb_types;
	bool chk_constraint = r_config_get_i (core->config, "anal.types.constraint");
	int ret, bsize = R_MAX (64, core->blocksize);
	const int mininstrsz = r_anal_archinfo (anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	int cur_idx , prev_idx = 0;
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return;
	}
	RDebugTrace *dt = NULL;
	RAnalEsilTrace *et = NULL;
	if (!anal_emul_init (core, hc, &dt, &et) || !fcn) {
		anal_emul_restore (core, hc, dt, et);
		return;
	}
	ut8 *buf = malloc (bsize);
	if (!buf) {
		anal_emul_restore (core, hc, dt, et);
		return;
	}

	// Reserve bigger ht to avoid rehashing
	Sdb *etracedb = core->anal->esil->trace->db;
	HtPPOptions opt = etracedb->ht->opt;
	ht_pp_free (etracedb->ht);
	etracedb->ht = ht_pp_new_size (fcn->ninstr * 0xf, opt.dupvalue, opt.freefn, opt.calcsizeV);
	etracedb->ht->opt = opt;
	RDebugTrace *dtrace = core->dbg->trace;
	opt = dtrace->ht->opt;
	ht_pp_free (dtrace->ht);
	dtrace->ht = ht_pp_new_size (fcn->ninstr, opt.dupvalue, opt.freefn, opt.calcsizeV);
	dtrace->ht->opt = opt;

	char *fcn_name = NULL;
	char *ret_type = NULL;
	bool str_flag = false;
	bool prop = false;
	bool prev_var = false;
	char prev_type[256] = {0};
	const char *prev_dest = NULL;
	char *ret_reg = NULL;
	const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	if (!pc) {
		return;
	}
	RRegItem *r = r_reg_get (core->dbg->reg, pc, -1);
	if (!r) {
		return;
	}
	r_cons_break_push (NULL, NULL);
	r_list_sort (fcn->bbs, bb_cmpaddr); // TODO: The algorithm can be more accurate if blocks are followed by their jmp/fail, not just by address
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 addr = bb->addr;
		int i = 0;
		r_reg_set_value (core->dbg->reg, r, addr);
		while (1) {
			if (r_cons_is_breaked ()) {
				goto out_function;
			}
			if (i >= (bsize - 32)) {
				i = 0;
			}
			ut64 pcval = r_reg_getv (anal->reg, pc);
			if ((addr >= bb->addr + bb->size) || (addr < bb->addr) || pcval != addr) {
				break;
			}
			if (!i) {
				r_io_read_at (core->io, addr, buf, bsize);
			}
			ret = r_anal_op (anal, &aop, addr, buf + i, bsize - i, R_ANAL_OP_MASK_BASIC | R_ANAL_OP_MASK_VAL);
			if (ret <= 0) {
				i += minopcode;
				addr += minopcode;
				r_anal_op_fini (&aop);
				continue;
			}
			int loop_count = sdb_num_get (anal->esil->trace->db, sdb_fmt ("0x%"PFMT64x".count", addr), 0);
			if (loop_count > LOOP_MAX || aop.type == R_ANAL_OP_TYPE_RET) {
				r_anal_op_fini (&aop);
				break;
			}
			sdb_num_set (anal->esil->trace->db, sdb_fmt ("0x%"PFMT64x".count", addr), loop_count + 1, 0);
			if (r_anal_op_nonlinear (aop.type)) {   // skip the instr
				r_reg_set_value (core->dbg->reg, r, addr + ret);
			} else {
				r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
			}
			bool userfnc = false;
			Sdb *trace = anal->esil->trace->db;
			cur_idx = sdb_num_get (trace, "idx", 0);
			RAnalVar *var = r_anal_get_used_function_var (anal, aop.addr);
			RAnalOp *next_op = r_core_anal_op (core, addr + ret, R_ANAL_OP_MASK_BASIC); // | _VAL ?
			ut32 type = aop.type & R_ANAL_OP_TYPE_MASK;
			if (aop.type == R_ANAL_OP_TYPE_CALL || aop.type & R_ANAL_OP_TYPE_UCALL) {
				char *full_name = NULL;
				ut64 callee_addr;
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
					if (Cc && r_anal_cc_exist (anal, Cc)) {
						char *cc = strdup (Cc);
						type_match (core, fcn_name, addr, bb->addr, cc, prev_idx, userfnc, callee_addr);
						prev_idx = cur_idx;
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
						const char *query = sdb_fmt ("%d.addr", cur_idx - 1);
						ut64 mov_addr = sdb_num_get (trace, query, 0);
						RAnalOp *mop = r_core_anal_op (core, mov_addr, R_ANAL_OP_MASK_VAL | R_ANAL_OP_MASK_BASIC);
						if (mop) {
							RAnalVar *mopvar = r_anal_get_used_function_var (anal, mop->addr);
							ut32 type = mop->type & R_ANAL_OP_TYPE_MASK;
							if (type == R_ANAL_OP_TYPE_MOV) {
								__var_rename (anal, mopvar, "canary", addr);
							}
						}
						r_anal_op_free (mop);
					}
					free (fcn_name);
				}
			} else if (!resolved && ret_type && ret_reg) {
				// Forward propgation of function return type
				char src[REGNAME_SIZE] = {0};
				const char *query = sdb_fmt ("%d.reg.write", cur_idx);
				const char *cur_dest = sdb_const_get (trace, query, 0);
				get_src_regname (core, aop.addr, src, sizeof (src));
				if (ret_reg && *src && strstr (ret_reg, src)) {
					if (var && aop.direction == R_ANAL_OP_DIR_WRITE) {
						__var_retype (anal, var, NULL, ret_type, false, false);
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
					} else if (type == R_ANAL_OP_TYPE_MOV &&
							(next_op && next_op->type == R_ANAL_OP_TYPE_MOV)){
						// Progate return type passed using pointer
						// int *ret; *ret = strlen(s);
						// TODO: memref check , dest and next src match
						char nsrc[REGNAME_SIZE] = {0};
						get_src_regname (core, next_op->addr, nsrc, sizeof (nsrc));
						if (ret_reg && *nsrc && strstr (ret_reg, nsrc) && var &&
								aop.direction == R_ANAL_OP_DIR_READ) {
							__var_retype (anal, var, NULL, ret_type, true, false);
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
						__var_retype (anal, var, NULL, "unsigned", false, true);
					}
				}
				// cmp [local_ch], rax ; jge
				if (sign || aop.sign) {
					__var_retype (anal, var, NULL, "signed", false, true);
				}
				// lea rax , str.hello  ; mov [local_ch], rax;
				// mov rdx , [local_4h] ; mov [local_8h], rdx;
				if (prev_dest && (type == R_ANAL_OP_TYPE_MOV || type == R_ANAL_OP_TYPE_STORE)) {
					char reg[REGNAME_SIZE] = {0};
					get_src_regname (core, addr, reg, sizeof (reg));
					bool match = strstr (prev_dest, reg) != NULL;
					if (str_flag && match) {
						__var_retype (anal, var, NULL, "const char *", false, false);
					}
					if (prop && match && prev_var) {
						__var_retype (anal, var, NULL, prev_type, false, false);
					}
				}
				if (chk_constraint && var && (type == R_ANAL_OP_TYPE_CMP && aop.disp != UT64_MAX)
						&& next_op && next_op->type == R_ANAL_OP_TYPE_CJMP) {
					bool jmp = false;
					RAnalOp *jmp_op = {0};
					ut64 jmp_addr = next_op->jump;
					RAnalBlock *jmpbb = r_anal_fcn_bbget_in (anal, fcn, jmp_addr);

					// Check exit status of jmp branch
					for (i = 0; i < MAX_INSTR ; i++) {
						jmp_op = r_core_anal_op (core, jmp_addr, R_ANAL_OP_MASK_BASIC);
						if (!jmp_op) {
							break;
						}
						if ((jmp_op->type == R_ANAL_OP_TYPE_RET && r_anal_block_contains (jmpbb, jmp_addr))
								|| jmp_op->type == R_ANAL_OP_TYPE_CJMP) {
							jmp = true;
							r_anal_op_free (jmp_op);
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
						ut8 buf[256] = {0};
						r_io_read_at (core->io, aop.ptr, buf, sizeof (buf) - 1);
						ut64 ptr = r_read_ble (buf, core->print->big_endian, aop.refptr * 8);
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
					__var_retype (anal, var, NULL, "const char *", false, false);
				}
				const char *query = sdb_fmt ("%d.reg.write", cur_idx);
				prev_dest = sdb_const_get (trace, query, 0);
				if (var) {
					strncpy (prev_type, var->type, sizeof (prev_type) - 1);
					prop = true;
				}
			}
			i += ret;
			addr += ret;
			r_anal_op_free (next_op);
			r_anal_op_fini (&aop);

		}
	}
	// Type propgation for register based args
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
			__var_retype (anal, rvar, NULL, lvar->type, false, false);
			// Propagate local var type <= from = register-based var
			__var_retype (anal, lvar, NULL, rvar->type, false, false);
		}
	}
	r_list_free (list);
out_function:
	R_FREE (ret_reg);
	R_FREE (ret_type);
	free (buf);
	r_cons_break_pop();
	anal_emul_restore (core, hc, dt, et);
}
