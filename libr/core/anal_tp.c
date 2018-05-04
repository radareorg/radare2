/* radare - LGPL - Copyright 2016 - oddcoder */
/* type matching - type propagation */

#include <r_anal.h>
#include <r_util.h>
#include <r_core.h>
#define LOOP_MAX 10

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

static void type_match_var(RAnal *anal , Sdb *trace, ut64 addr,const char *type, int idx) {
	RAnalVar *v;
	const char *sp_name = r_reg_get_name (anal->reg, R_REG_NAME_SP);
	const char *bp_name = r_reg_get_name (anal->reg, R_REG_NAME_BP);
	ut64 sp = r_reg_getv (anal->reg, sp_name);
	ut64 bp = r_reg_getv (anal->reg, bp_name);
	char *key = sdb_fmt ("%d.mem.read", idx);
	int i, array_size = sdb_array_size (trace, key);

	for (i = 0; i < array_size; i++) {
		if (bp_name) {
			int bp_idx = sdb_array_get_num (trace, key, i, 0) - bp;
			if ((v = r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_BPV, 1, bp_idx))) {
				r_anal_var_retype (anal, addr, 1, bp_idx, R_ANAL_VAR_KIND_BPV, type, -1, v->name);
				r_anal_var_free (v);
			}
		}
		int sp_idx = sdb_array_get_num (trace, key, i, 0) - sp;
		if ((v = r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_SPV, 1, sp_idx))) {
			r_anal_var_retype (anal, addr, 1, sp_idx, R_ANAL_VAR_KIND_SPV, type, -1, v->name);
			r_anal_var_free (v);
		}
	}
}

static bool type_pos_hit(RAnal *anal, Sdb *trace, bool in_stack, int idx, int size, const char *place) {
	if (in_stack) {
		const char *sp_name = r_reg_get_name (anal->reg, R_REG_NAME_SP);
		ut64 sp = r_reg_getv (anal->reg, sp_name);
		ut64 write_addr = sdb_num_get (trace, sdb_fmt ("%d.mem.write", idx), 0);
		return (write_addr == sp + size);
	} else {
		return sdb_array_contains (trace, sdb_fmt ("%d.reg.write", idx), place, 0);
	}
}

static void type_match(RCore *core, ut64 addr, char *name) {
	Sdb *trace = core->anal->esil->db_trace;
	RAnal *anal = core->anal;
	char *fcn_name;
	bool stack_rev = false, in_stack = false;

	if (r_anal_type_func_exist (anal, name)) {
		fcn_name = strdup (name);
	} else if (!(fcn_name = r_anal_type_func_guess (anal, name))) {
		//eprintf ("can't find function prototype for %s\n", name);
		return;
	}
	const char* cc = r_anal_type_func_cc (anal, fcn_name);
	if (!cc || !r_anal_cc_exist (anal, cc)) {
		//eprintf ("can't find %s calling convention %s\n", fcn_name, cc);
		return;
	}
	int i, j, size = 0, max = r_anal_type_func_args_count (anal, fcn_name);
	int idx = sdb_num_get (trace, "idx", 0);
	const char *place = r_anal_cc_arg (anal, cc, 1);
	r_cons_break_push (NULL, NULL);

	if (!strcmp (place, "stack_rev")) {
		stack_rev = true;
	}
	if (!strncmp (place, "stack", 5)) {
		// type_match_reg
		in_stack = true;
	}
	for (i = 0; i < max; i++) {
		int arg_num = stack_rev ? (max - 1 - i) : i;
		char *type = r_anal_type_func_args_type (anal, fcn_name, arg_num);
		const char *name = r_anal_type_func_args_name (anal, fcn_name, arg_num);
		if (!in_stack) {
			place = r_anal_cc_arg (anal, cc, arg_num + 1);
		}
		for (j = idx; j >= 0; j--) {
			if (type_pos_hit (anal, trace, in_stack, j, size, place)) {
				ut64 instr_addr = sdb_num_get (trace, sdb_fmt ("%d.addr", j), 0);
				r_meta_set_string (anal, R_META_TYPE_COMMENT, instr_addr,
						sdb_fmt ("%s%s%s", type, r_str_endswith (type, "*") ? "" : " ", name));
				type_match_var (anal, trace, addr, type , j);
				break;
			}
		}
		size += r_anal_type_get_size (anal, type) / 8;
	}
	r_cons_break_pop ();
	free (fcn_name);
}

static int stack_clean (RCore *core, ut64 addr, RAnalFunction *fcn) {
	int offset, ret;
	char *tmp, *str, *sig;
	RAnalOp *op = r_core_anal_op (core, addr);
	if (!op) {
		return 0;
	}
	str = strdup (r_strbuf_get (&op->esil));
	if (!str) {
		return 0;
	}
	tmp = strchr (str, ',');
	if (!tmp) {
		free (str);
		return 0;
	}
	*tmp++ = 0;

	offset = r_num_math (core->num, str);
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	sig = sdb_fmt ("%s,+=", sp);
	ret = 0;
	if (!strncmp (tmp, sig, strlen (sig))) {
		const char *esil = sdb_fmt ("%d,%s,-=", offset, sp);
		r_anal_esil_parse (core->anal->esil, esil);
		r_anal_esil_stack_free (core->anal->esil);
		r_core_esil_step (core, UT64_MAX, NULL, NULL);
		ret = op->size;
	}
	r_anal_op_free (op);
	free (str);
	return ret;
}

R_API void r_core_anal_type_match(RCore *core, RAnalFunction *fcn) {
	RConfigHold *hc = NULL;
	RAnalBlock *bb;
	RListIter *it;

	if (!core|| !fcn) {
		return;
	}
	hc = r_config_hold_new (core->config);
	if (!hc) {
		return;
	}
	if (!r_anal_emul_init (core, hc) || !fcn) {
		r_anal_emul_restore (core, hc);
		return;
	}
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 addr = bb->addr;
		r_reg_setv (core->dbg->reg, pc, bb->addr);
		r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
		r_cons_break_push (NULL, NULL);
		while (1) {
			if (r_cons_is_breaked ()) {
				goto out_function;
			}
			RAnalOp *op = r_core_anal_op (core, addr);
			int loop_count = sdb_num_get (core->anal->esil->db_trace, sdb_fmt ("0x%"PFMT64x".count", addr), 0);
			if (loop_count > LOOP_MAX || !op || op->type == R_ANAL_OP_TYPE_RET || addr >= bb->addr + bb->size || addr < bb->addr) {
				r_anal_op_free (op);
				break;
			}
			sdb_num_set (core->anal->esil->db_trace, sdb_fmt ("0x%"PFMT64x".count", addr), loop_count + 1, 0);
			switch (op->type) {
			case R_ANAL_OP_TYPE_CALL:
				{
					RAnalFunction *fcn_call = r_anal_get_fcn_in (core->anal, op->jump, -1);
					if (fcn_call) {
						type_match (core, addr, fcn_call->name);
					}
					addr += op->size;
					r_anal_op_free (op);
					r_reg_setv (core->dbg->reg, pc, addr);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
					r_anal_esil_set_pc (core->anal->esil, addr);
					addr += stack_clean (core, addr, fcn);
					r_reg_setv (core->dbg->reg, pc, addr);
					r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
					r_anal_esil_set_pc (core->anal->esil, addr);
					break;
				}
				break;
			default:
				{
				   r_core_esil_step (core, UT64_MAX, NULL, NULL);
				   r_anal_op_free (op);
				   r_core_cmd0 (core, ".ar*");
				   addr = r_reg_getv (core->anal->reg, pc);
				}
				break;
			}
		}
		r_cons_break_pop();
	}
out_function:
	r_cons_break_pop ();
	r_anal_emul_restore (core, hc);
	sdb_reset (core->anal->esil->db_trace);
}
