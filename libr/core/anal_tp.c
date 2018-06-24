/* radare - LGPL - Copyright 2016-2018 - oddcoder, sivaramaaa */
/* type matching - type propagation */

#include <r_anal.h>
#include <r_util.h>
#include <r_core.h>
#define LOOP_MAX 10
#define SUMARRAY(arr, size, res) do (res) += (arr)[--(size)]; while ((size))
#define MAXINSTR 20

enum {
	ROMEM = 0,
	ASM_TRACE,
	ANAL_TRACE,
	DBG_TRACE,
	NONULL,
	STATES_SIZE
};

static bool r_anal_emul_init(RCore *core, RConfigHold *hc) {
	r_config_save_num (hc, "esil.romem", "asm.trace", "dbg.trace",
			"esil.nonull", NULL);
	r_config_set (core->config, "esil.romem", "true");
	r_config_set (core->config, "asm.trace", "true");
	r_config_set (core->config, "dbg.trace", "true");
	r_config_set (core->config, "esil.nonull", "true");
	const char *bp = r_reg_get_name (core->anal->reg, R_REG_NAME_BP);
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	if ((bp && !r_reg_getv (core->anal->reg, bp)) && (sp && !r_reg_getv (core->anal->reg, sp))) {
		eprintf ("Stack isn't initiatized.\n");
		eprintf ("Try running aei and aeim commands before aftm for default stack initialization\n");
		return false;
	}
	return (core->anal->esil != NULL);
}

static void r_anal_emul_restore(RCore *core, RConfigHold *hc) {
	r_config_restore (hc);
	r_config_hold_free (hc);
}

#define SDB_CONTAINS(i,s) sdb_array_contains (trace, sdb_fmt ("%d.reg.write", i), s, 0)

static bool type_pos_hit(RAnal *anal, Sdb *trace, bool in_stack, int idx, int size, const char *place) {
	if (in_stack) {
		const char *sp_name = r_reg_get_name (anal->reg, R_REG_NAME_SP);
		ut64 sp = r_reg_getv (anal->reg, sp_name);
		ut64 write_addr = sdb_num_get (trace, sdb_fmt ("%d.mem.write", idx), 0);
		return (write_addr == sp + size);
	} else {
		return SDB_CONTAINS (idx, place);
	}
}

static void var_rename (RAnal *anal, RAnalVar *v, const char *name, ut64 addr) {
	if (!name || !v) {
		return;
	}
	if (!*name || !strcmp (name , "...")) {
		return;
	}
	bool is_default = (!strncmp (v->name, "local_", 6)
			|| !strncmp (v->name, "arg_", 4))? true: false;
	if (*name == '*') {
		name++;
	}
	// longer name tends to be meaningful like "src" instead of "s1"
	if (!is_default && (strlen (v->name) > strlen (name))) {
		return;
	}
	RAnalFunction *fcn = r_anal_get_fcn_in (anal, addr, 0);
	RAnalVar *v1 = r_anal_var_get_byname (anal, fcn, name);
	if (v1) {
		r_anal_var_free (v1);
		return;
	}
	r_anal_var_rename (anal, fcn->addr, 1, v->kind, v->name, name);
}

static void var_retype (RAnal *anal, RAnalVar *var, const char *vname, char *type, ut64 addr) {
	if (!type || !var) {
		return;
	}
	if (!*type) {
		return;
	}
	if (!strncmp (type, "int", 3)) {
		return;
	}
	if (strncmp (var->type, "void", 4) && strncmp (var->type, "int", 3)) {
		return;
	}
	char *vtype = NULL;
	char *ntype = type;
	if (!strncmp (type, "const ", 6)) {
		// Droping const from type
		//TODO: Infering const type
		ntype = type + 6;
	}
	if (vname && *vname == '*') {
		//type *ptr => type *
		vtype = r_str_newf ("%s %c", ntype, '*');
	}
	if (vtype && *vtype) {
		ntype = vtype;
	}
	r_anal_var_retype (anal, addr, 1, -1, var->kind, ntype, -1, var->isarg, var->name);
	free (vtype);
}

static const char *get_regname (RAnal *anal, Sdb *trace, int idx) {
	const char *query = sdb_fmt ("%d.reg.read", idx);
	const char *res = sdb_const_get (trace, query, 0);
	if (!res) {
		return NULL;
	}
	char *tmp = strchr (res, ',');
	if (tmp) {
		res = tmp + 1;
	}
	RRegItem *ri = r_reg_get (anal->reg, res, -1);
	if (ri && (ri->size == 32) && (anal->bits == 64)) {
		res = r_reg_32_to_64 (anal->reg, res);
	}
	return res;
}

static ut64 get_addr (Sdb *trace, const char *regname, int idx) {
	if (!regname) {
		return UT64_MAX;
	}
	const char *query = sdb_fmt ("%d.reg.read.%s", idx, regname);
	return r_num_math (NULL, sdb_const_get (trace, query, 0));
}

static void type_match(RCore *core, ut64 addr, char *fcn_name, const char* cc, int prev_idx) {
	Sdb *trace = core->anal->esil->db_trace;
	Sdb *TDB = core->anal->sdb_types;
	RAnal *anal = core->anal;
	int idx = sdb_num_get (trace, "idx", 0);
	bool stack_rev = false, in_stack = false;

	if (!fcn_name || !cc) {
		return;
	}
	int i, j, size = 0, max = r_type_func_args_count (TDB, fcn_name);
	const char *place = r_anal_cc_arg (anal, cc, 1);
	r_cons_break_push (NULL, NULL);

	if (!strcmp (place, "stack_rev")) {
		stack_rev = true;
	}
	if (!strncmp (place, "stack", 5)) {
		in_stack = true;
	}
	for (i = 0; i < max; i++) {
		int arg_num = stack_rev ? (max - 1 - i) : i;
		char *type = r_type_func_args_type (TDB, fcn_name, arg_num);
		const char *name = r_type_func_args_name (TDB, fcn_name, arg_num);
		if (!in_stack) {
			place = r_anal_cc_arg (anal, cc, arg_num + 1);
		}
		const char *regname = NULL;
		ut64 xaddr = UT64_MAX;
		bool cmt_set = false;
		bool res = false;
		// Backtrace instruction from source sink to prev source sink
		for (j = idx; j >= prev_idx; j--) {
			ut64 instr_addr = sdb_num_get (trace, sdb_fmt ("%d.addr", j), 0);
			RAnalOp *op = r_core_anal_op (core, instr_addr, R_ANAL_OP_MASK_BASIC);
			if (op && op->type == R_ANAL_OP_TYPE_CALL) {
				r_anal_op_fini (op);
				break;
			}
			RAnalVar *var = op ? op->var: NULL;
			// Match type from function param to instr
			if (type_pos_hit (anal, trace, in_stack, j, size, place)) {
				if (!cmt_set) {
					r_meta_set_string (anal, R_META_TYPE_COMMENT, instr_addr,
							sdb_fmt ("%s%s%s", type, r_str_endswith (type, "*") ? "" : " ", name));
					cmt_set = true;
				}
				if (var) {
					var_retype (anal, var, name, type, addr);
					var_rename (anal, var, name, addr);
					res = true;
				} else {
					regname = get_regname (anal, trace, j);
					xaddr = get_addr (trace, regname, j);
				}
			}
			// Type propagate by following source reg
			if (!res && regname && SDB_CONTAINS (j, regname)) {
				if (var) {
					var_retype (anal, var, name, type, addr);
					var_rename (anal, var, name, addr);
					res = true;
				} else {
					if (op && op->type == R_ANAL_OP_TYPE_MOV) {
						regname = get_regname (anal, trace, j);
					}
				}
			} else if (var && res && (xaddr != UT64_MAX)) { // Type progation using value
				const char *reg = get_regname (anal, trace, j);
				ut64 ptr = get_addr (trace, reg, j);
				if (ptr == xaddr) {
					var_retype (anal, var, name, type, addr);
				}
			}
			r_anal_op_free (op);
		}
		size += anal->bits / 8;
		free (type);
	}
	r_cons_break_pop ();
}

R_API void r_core_anal_type_match(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = {0};
	RAnal *anal = core->anal;
	Sdb *TDB = anal->sdb_types;
	bool resolved = false;

	if (!core|| !fcn) {
		return;
	}
	if (!core->anal->esil) {
		return;
	}
	int ret, bsize = R_MAX (64, core->blocksize);
	const int mininstrsz = r_anal_archinfo (anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	int cur_idx , prev_idx = anal->esil->trace_idx;
	RConfigHold *hc = r_config_hold_new (core->config);
	if (!hc) {
		return;
	}
	if (!r_anal_emul_init (core, hc) || !fcn) {
		r_anal_emul_restore (core, hc);
		return;
	}
	ut8 *buf = malloc (bsize);
	if (!buf) {
		free (buf);
		return;
	}
	char *fcn_name = NULL;
	char *ret_type = NULL;
	const char *ret_reg = NULL;
	const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	RRegItem *r = r_reg_get (core->dbg->reg, pc, -1);
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 addr = bb->addr;
		int i = 0;
		r_reg_set_value (core->dbg->reg, r, addr);
		r_cons_break_push (NULL, NULL);
		while (1) {
			if (r_cons_is_breaked ()) {
				goto out_function;
			}
			if (i >= (bsize - 32)) {
				i = 0;
			}
			if (!i) {
				r_io_read_at (core->io, addr, buf, bsize);
			}
			ret = r_anal_op (anal, &aop, addr, buf + i, bsize - i, R_ANAL_OP_MASK_BASIC);
			if (ret <= 0) {
				i += minopcode;
				addr += minopcode;
				r_anal_op_fini (&aop);
				continue;
			}
			int loop_count = sdb_num_get (anal->esil->db_trace, sdb_fmt ("0x%"PFMT64x".count", addr), 0);
			if (loop_count > LOOP_MAX || aop.type == R_ANAL_OP_TYPE_RET
					|| addr >= bb->addr + bb->size || addr < bb->addr) {
				r_anal_op_fini (&aop);
				break;
			}
			sdb_num_set (anal->esil->db_trace, sdb_fmt ("0x%"PFMT64x".count", addr), loop_count + 1, 0);
			if (r_anal_op_nonlinear (aop.type)) {   // skip the instr
				r_reg_set_value (core->dbg->reg, r, addr + ret);
			} else {
				r_core_esil_step (core, UT64_MAX, NULL, NULL);
			}
			Sdb *trace = anal->esil->db_trace;
			cur_idx = sdb_num_get (trace, "idx", 0);
			if (aop.type == R_ANAL_OP_TYPE_CALL) {
				RAnalFunction *fcn_call = r_anal_get_fcn_in (anal, aop.jump, -1);
				if (fcn_call) {
					if (r_type_func_exist (TDB, fcn_call->name)) {
						fcn_name = strdup (fcn_call->name);
					} else if (!(fcn_name = r_type_func_guess (TDB, fcn_call->name))) {
						goto beach;
					}
					const char* cc = r_anal_cc_func (anal, fcn_name);
					if (cc && r_anal_cc_exist (anal, cc)) {
						type_match (core, addr, fcn_name, cc, prev_idx);
						prev_idx = cur_idx;
						ret_type = (char *) r_type_func_ret (TDB, fcn_name);
						ret_reg = r_anal_cc_ret (anal, cc);
						resolved = false;
					}
					free (fcn_name);
				}
			}
			// Forward propgation of function return type
			if (!resolved && ret_type && ret_reg) {
				const char *reg = get_regname (anal, trace, cur_idx);
				if (reg && !strcmp (reg, ret_reg) && aop.var) {
					var_retype (anal, aop.var, aop.var->name, ret_type, addr);
					resolved = true;
				}
				if (SDB_CONTAINS (cur_idx, ret_reg)) {
					resolved = true;
				}
			}
beach:
			i += ret;
			addr += ret;
			r_anal_op_fini (&aop);

		}
	}
out_function:
	free (buf);
	r_cons_break_pop();
	r_anal_emul_restore (core, hc);
	sdb_reset (anal->esil->db_trace);
}
