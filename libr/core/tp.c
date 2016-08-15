/* radare - LGPL - Copyright 2016 - oddcoder */
/*type matching - type propagation*/
#include <r_anal.h>
#include <r_util.h>
#include <r_core.h>

static bool r_anal_emul_init (RCore *core) {
	r_config_set (core->config, "esil.romem", "true");
	r_config_set (core->config, "asm.trace", "true");
	r_config_set (core->config, "anal.trace", "true");
	r_config_set (core->config, "dbg.trace", "true");
	r_config_set (core->config, "esil.nonull", "true");
	if (!core->anal->esil) {
		return false;
	}
	return true;
}

static void type_match (RCore *core, ut64 addr, char *name) {
	Sdb *trace = core->anal->esil->db_trace;
	RAnal *anal = core->anal;
	RAnalVar *v;
	char *fcn_name;
	if (r_anal_type_func_exist (anal, name)) {
		fcn_name = strdup (name);
	} else if (!(fcn_name = r_anal_type_func_guess (anal, name))) {
		eprintf ("can't find function prototype for %s\n", name);
		return;
	}
	const char* cc = r_anal_type_func_cc (anal, fcn_name);
	if (!cc || !r_anal_cc_exist (anal, cc)) {
		eprintf("cant find %s calling covnention %s\n", fcn_name, cc);
	}
	int i, j, max = r_anal_type_func_args_count (anal, fcn_name);
	int size = 0, idx = sdb_num_get (trace, "idx", 0);
	const char *sp_name = r_reg_get_name (anal->reg, R_REG_NAME_SP);
	const char *bp_name = r_reg_get_name (anal->reg, R_REG_NAME_BP);
	RRegItem *r = r_reg_get (anal->reg, sp_name, -1);
	ut64 bp, sp = r_reg_get_value (anal->reg, r);
	if (bp_name) {
		r = r_reg_get (anal->reg, bp_name, -1);
		bp = r_reg_get_value (anal->reg, r);
	}
	for (i = 0; i < max; i++) {
		char *type = r_anal_type_func_args_type (anal, fcn_name, i);
		const char *name =r_anal_type_func_args_name (anal, fcn_name, i);
		const char *place = r_anal_cc_arg (anal, cc, i + 1);
		if (!strcmp (place, "stack")) {
			for (j = idx; j >= 0; j--) {
				ut64 write_addr = sdb_num_get (trace, sdb_fmt (-1, "%d.mem.write", j), 0);
				if (write_addr == sp + size) {
					ut64 instr_addr = sdb_num_get (trace, sdb_fmt (-1, "%d.addr", j), 0);
					r_meta_set_string (core->anal, R_META_TYPE_COMMENT, instr_addr,
						sdb_fmt (-1, "%s %s", type, name));
					char *tmp = sdb_fmt (-1, "%d.mem.read", j);
					int i2, array_size = sdb_array_size (trace, tmp);
					for (i2 = 0; i2 < array_size; i2++) {
						if (bp_name) {
							int bp_idx = sdb_array_get_num (trace, tmp, i2, 0) - bp;
							if ((v =r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_BPV, 1, bp_idx))) {
								r_anal_var_retype (anal, addr, 1, bp_idx, R_ANAL_VAR_KIND_BPV, type, -1, v->name);
								r_anal_var_free (v);
							}
						}
						int sp_idx = sdb_array_get_num (trace, tmp, i2, 0) - sp;
						if ((v =r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_SPV, 1, sp_idx))) {
							r_anal_var_retype (anal, addr, 1, sp_idx, R_ANAL_VAR_KIND_SPV, type, -1, v->name);
							r_anal_var_free (v);
						}
					}
					break;
				}
			}
			size += r_anal_type_get_size (anal, type) / 8;
		} else if (!strcmp (place , "stack_rev")) {
			free (type);
			int k;
			for ( k = max -1; k >=i; k--) {
				type = r_anal_type_func_args_type (anal, fcn_name, k);
				name =r_anal_type_func_args_name (anal, fcn_name, k);
				place = r_anal_cc_arg (anal, cc, k + 1);
				if (strcmp (place ,"stack_rev")) {
					break;
				}
				for (j = idx; j >= 0; j--) {
					ut64 write_addr = sdb_num_get (trace, sdb_fmt (-1, "%d.mem.write", j), 0);
					if (write_addr == sp + size) {
						ut64 instr_addr = sdb_num_get (trace, sdb_fmt (-1, "%d.addr", j), 0);
						r_meta_set_string (core->anal, R_META_TYPE_COMMENT, instr_addr,
							sdb_fmt (-1, "%s %s", type, name));
						char *tmp = sdb_fmt (-1, "%d.mem.read", j);
						int i2, array_size = sdb_array_size (trace, tmp);
						for (i2 = 0; i2 < array_size; i2++) {
							if (bp_name) {
								int bp_idx = sdb_array_get_num (trace, tmp, i2, 0) - bp;
								if ((v =r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_BPV, 1, bp_idx))) {
									r_anal_var_retype (anal, addr, 1, bp_idx, R_ANAL_VAR_KIND_BPV, type, -1, v->name);
									r_anal_var_free (v);
								}
							}
							int sp_idx = sdb_array_get_num (trace, tmp, i2, 0) - sp;
							if ((v =r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_SPV, 1, sp_idx))) {
								r_anal_var_retype (anal, addr, 1, sp_idx, R_ANAL_VAR_KIND_SPV, type, -1, v->name);
								r_anal_var_free (v);
							}
						}
						break;
					}

				}
				size +=r_anal_type_get_size (anal, type) / 8;
			}
			break;
		} else {
			for (j = idx; j >= 0; j--) {
				if (sdb_array_contains (trace, sdb_fmt (-1, "%d.reg.write", j), place, 0)) {
					ut64 instr_addr = sdb_num_get (trace, sdb_fmt (-1, "%d.addr", j), 0);
					r_meta_set_string (core->anal, R_META_TYPE_COMMENT, instr_addr,
						sdb_fmt (-1, "%s %s", type, name));
					char *tmp = sdb_fmt (-1, "%d.mem.read", j);
					int i2, array_size = sdb_array_size (trace, tmp);
					for (i2 = 0; i2 < array_size; i2++) {
						if (bp_name) {
							int bp_idx = sdb_array_get_num (trace, tmp, i2, 0) - bp;
							if ((v =r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_BPV, 1, bp_idx))) {
								r_anal_var_retype (anal, addr, 1, bp_idx, R_ANAL_VAR_KIND_BPV, type, -1, v->name);
								r_anal_var_free (v);
							}
						}
						int sp_idx = sdb_array_get_num (trace, tmp, i2, 0) - sp;
						if ((v =r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_SPV, 1, sp_idx))) {
							r_anal_var_retype (anal, addr, 1, sp_idx, R_ANAL_VAR_KIND_SPV, type, -1, v->name);
							r_anal_var_free (v);
						}
					}
					break;
				}
			}
		}
		free (type);
	}
	free (fcn_name);
}

static int stack_clean (RCore *core, ut64 addr, RAnalFunction *fcn) {
	RAnalOp *op = r_core_anal_op (core, addr);
	char *str = strdup (r_strbuf_get (&op->esil));
	char *tmp = strchr (str, ',');
	if (!tmp) {
		free (str);
		return 0;
	}
	*tmp++ = 0;
	int offset = r_num_math (core->num, str);
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	char *sig = sdb_fmt (-1, "%s,+=", sp);
	int ret = 0;
	if (!strncmp (tmp, sig, strlen (sig))) {
		char *esil = sdb_fmt (-1, "%d,%s,-=", offset, sp);
		r_anal_esil_parse (core->anal->esil, esil);
		r_anal_esil_dumpstack (core->anal->esil);
		r_anal_esil_stack_free (core->anal->esil);
		r_core_esil_step (core, UT64_MAX, NULL);
		ret = op->size;
	}
	r_anal_op_free (op);
	free (str);
	return ret;
}
R_API void r_anal_type_match(RCore *core, RAnalFunction *fcn) {
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	ut64 addr = fcn->addr;
	if (!core || !r_anal_emul_init (core) || !fcn ) {
		return;
	}
	RRegItem *pc_reg = r_reg_get (core->anal->reg, pc, -1);
	r_reg_set_value (core->dbg->reg, pc_reg, fcn->addr);
	r_debug_reg_sync (core->dbg, -1, true);
	while (1) {
		RAnalOp *op = r_core_anal_op (core, addr);
		if (op->type == R_ANAL_OP_TYPE_RET) {
			return;
		}
		if (op->type == R_ANAL_OP_TYPE_CALL) {
			RAnalFunction *fcn_call = r_anal_get_fcn_in (core->anal, op->jump, -1);
			//eprintf ("in the middle of %s\n", fcn_call->name);
			type_match (core, addr, fcn_call->name);
			addr += op->size;
			r_anal_op_free (op);
			r_reg_set_value (core->dbg->reg, pc_reg, addr);
			r_debug_reg_sync (core->dbg, -1, true);
			r_anal_esil_set_pc (core->anal->esil, addr);
			addr += stack_clean (core, addr, fcn);
			r_reg_set_value (core->dbg->reg, pc_reg, addr);
			r_debug_reg_sync (core->dbg, -1, true);
			r_anal_esil_set_pc (core->anal->esil, addr);
			continue;
			//eprintf ("call\n");
		} else {
			r_core_esil_step (core, UT64_MAX, NULL);
			r_anal_op_free (op);
		}
		r_core_cmd0 (core, ".ar*");
		addr = r_num_get (core->num, pc);
	}
}
