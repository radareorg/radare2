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
				r_anal_var_retype (anal, addr, 1, bp_idx, R_ANAL_VAR_KIND_BPV, type, -1, v->isarg, v->name);
				r_anal_var_free (v);
			}
		}
		int sp_idx = sdb_array_get_num (trace, key, i, 0) - sp;
		if ((v = r_anal_var_get (anal, addr, R_ANAL_VAR_KIND_SPV, 1, sp_idx))) {
			r_anal_var_retype (anal, addr, 1, sp_idx, R_ANAL_VAR_KIND_SPV, type, -1, v->isarg, v->name);
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

static void type_match(RCore *core, ut64 addr, char *name, int prev_idx) {
	Sdb *trace = core->anal->esil->db_trace;
	Sdb *TDB = core->anal->sdb_types;
	RAnal *anal = core->anal;
	char *fcn_name;
	int idx = sdb_num_get (trace, "idx", 0);
	bool stack_rev = false, in_stack = false;

	if (r_type_func_exist (TDB, name)) {
		fcn_name = strdup (name);
	} else if (!(fcn_name = r_type_func_guess (TDB, name))) {
		//eprintf ("can't find function prototype for %s\n", name);
		return;
	}
	const char* cc = r_anal_cc_func (anal, fcn_name);
	if (!cc || !r_anal_cc_exist (anal, cc)) {
		//eprintf ("can't find %s calling convention %s\n", fcn_name, cc);
		return;
	}
	int i, j, size = 0, max = r_type_func_args_count (TDB, fcn_name);
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
		char *type = r_type_func_args_type (TDB, fcn_name, arg_num);
		const char *name = r_type_func_args_name (TDB, fcn_name, arg_num);
		if (!in_stack) {
			place = r_anal_cc_arg (anal, cc, arg_num + 1);
		}
		for (j = idx; j >= prev_idx; j--) {
			if (type_pos_hit (anal, trace, in_stack, j, size, place)) {
				ut64 instr_addr = sdb_num_get (trace, sdb_fmt ("%d.addr", j), 0);
				r_meta_set_string (anal, R_META_TYPE_COMMENT, instr_addr,
						sdb_fmt ("%s%s%s", type, r_str_endswith (type, "*") ? "" : " ", name));
				if (strncmp (type, "int", 3)) {
					// change type only if not int
					type_match_var (anal, trace, addr, type , j);
				}
				break;
			}
		}
		size += r_type_get_bitsize (TDB, type) / 8;
	}
	r_cons_break_pop ();
	free (fcn_name);
}

// Emulates previous N instr
static void emulate_prev_N_instr(RCore *core, ut64 at, ut64 curpc) {
	int i, inslen, bsize = R_MIN (64, core->blocksize);
	RAnalOp aop;
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	RRegItem *r = r_reg_get (core->dbg->reg, pc, -1);

	ut8 *arr = malloc (bsize);
	if (!arr) {
		eprintf ("Cannot allocate %d byte(s)\n", bsize);
		free (arr);
		return;
	}
	r_reg_set_value (core->dbg->reg, r, curpc);
	for (i = 0; curpc < at; curpc++, i++) {
		if (i >= (bsize - 32)) {
			i = 0;
		}
		if (!i) {
			r_io_read_at (core->io, curpc, arr, bsize);
		}
		inslen = r_anal_op (core->anal, &aop, curpc, arr + i, bsize - i, R_ANAL_OP_MASK_BASIC);
		int incr = inslen - 1;
		if (incr < 0) {
			incr = minopcode;
		}
		i += incr;
		curpc += incr;
		if ((inslen > 0) || (inslen < 50)) {
			if (r_anal_op_nonlinear (aop.type)) {   // skip the instr
				r_reg_set_value (core->dbg->reg, r, curpc + 1);
			} else {                       // step instr
				r_core_esil_step (core, UT64_MAX, NULL, NULL);
			}
		}
		r_anal_op_fini (&aop);

	}
	free (arr);
}

R_API void r_core_anal_type_match(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = {0};
	ut64 prevpc;

	if (!core|| !fcn) {
		return;
	}
	if (!core->anal->esil) {
		return;
	}
	int ret, bsize = R_MAX (64, core->blocksize);
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	int cur_idx , prev_idx = core->anal->esil->trace_idx;
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
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 addr = bb->addr;
		int i = 0, curpos, idx = 0;
		int *previnstr = calloc (MAXINSTR + 1, sizeof (int));
		if (!previnstr) {
			eprintf ("Cannot allocate %d byte(s)\n", MAXINSTR + 1);
			free (buf);
			return;
		}
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
			ret = r_anal_op (core->anal, &aop, addr, buf + i, bsize - i, R_ANAL_OP_MASK_BASIC);
			if (ret <= 0) {
				i += minopcode;
				addr += minopcode;
				r_anal_op_fini (&aop);
				continue;
			}
			int loop_count = sdb_num_get (core->anal->esil->db_trace, sdb_fmt ("0x%"PFMT64x".count", addr), 0);
			if (loop_count > LOOP_MAX || aop.type == R_ANAL_OP_TYPE_RET
					|| addr >= bb->addr + bb->size || addr < bb->addr) {
				break;
			}
			sdb_num_set (core->anal->esil->db_trace, sdb_fmt ("0x%"PFMT64x".count", addr), loop_count + 1, 0);
			curpos = idx++ % (MAXINSTR + 1);
			previnstr[curpos] = ret; // This array holds prev n instr size + cur instr size
			if (aop.type == R_ANAL_OP_TYPE_CALL) {
				int nbytes = 0;
				int nb_opcodes = MAXINSTR;
				SUMARRAY (previnstr, nb_opcodes, nbytes);
				prevpc = addr - (nbytes - previnstr[curpos]);
				emulate_prev_N_instr (core, addr, prevpc);
				RAnalFunction *fcn_call = r_anal_get_fcn_in (core->anal, aop.jump, -1);
				if (fcn_call) {
					cur_idx = sdb_num_get (core->anal->esil->db_trace, "idx", 0);
					type_match (core, addr, fcn_call->name, prev_idx);
					prev_idx = cur_idx;
				}
				memset (previnstr, 0, sizeof (previnstr) * sizeof (*previnstr)); // clearing the buffer
			}
			i += ret;
			addr += ret;
			r_anal_op_fini (&aop);

		}
		r_cons_break_pop();
	}
out_function:
	free (buf);
	r_cons_break_pop();
	r_anal_emul_restore (core, hc);
	sdb_reset (core->anal->esil->db_trace);
}
