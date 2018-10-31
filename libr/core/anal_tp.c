/* radare - LGPL - Copyright 2016-2018 - oddcoder, sivaramaaa */
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
		eprintf ("Stack isn't initialized.\n");
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

static void var_rename(RAnal *anal, RAnalVar *v, const char *name, ut64 addr) {
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
	if (!fcn) {
		return;
	}
	r_anal_var_rename (anal, fcn->addr, 1, v->kind, v->name, name, false);
}

static void var_retype(RAnal *anal, RAnalVar *var, const char *vname, char *type, ut64 addr, bool ref, bool pfx) {
	if (!type || !var) {
		return;
	}
	char *trim = r_str_trim (type);
	if (!*trim) {
		return;
	}
	bool is_ptr = (vname && *vname == '*')? true: false;
	if (!strncmp (trim, "int", 3) || (!is_ptr && !strcmp (trim, "void"))) {
		// default or void type
		return;
	}
	const char *tmp = strstr (var->type, "int");
	bool is_default = tmp? true: false;
	if (!is_default && strncmp (var->type, "void", 4)) {
		// return since type is already propgated
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
		r_strbuf_set (sb, trim);
	}
	if (!strncmp (r_strbuf_get (sb), "const ", 6)) {
		// Droping const from type
		//TODO: Infering const type
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
	r_anal_var_retype (anal, addr, 1, var->delta, var->kind, r_strbuf_get (sb), var->size, var->isarg, var->name);
	r_strbuf_free (sb);
}

static void get_src_regname(RCore *core, ut64 addr, char *regname, int size) {
	RAnal *anal = core->anal;
	RAnalOp *op = r_core_anal_op (core, addr, R_ANAL_OP_MASK_ESIL);
	if (!op) {
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

static int cond_invert (int cond) {
	int res = 0;
	switch (cond) {
	case R_ANAL_COND_LE:
		res = R_ANAL_COND_GT;
		break;
	case R_ANAL_COND_LT:
		res = R_ANAL_COND_GE;
		break;
	case R_ANAL_COND_GE:
		res = R_ANAL_COND_LT;
		break;
	case R_ANAL_COND_GT:
		res = R_ANAL_COND_LE;
		break;
	}
	return res;
}

#define RKEY(a,k,d) sdb_fmt ("var.range.0x%"PFMT64x ".%c.%d", a, k, d)
#define ADB a->sdb_fcns

static void var_add_range (RAnal *a, RAnalVar *var, int cond, ut64 val) {
	const char *key = RKEY (var->addr, var->kind, var->delta);
	sdb_array_append_num (ADB, key, cond, 0);
	sdb_array_append_num (ADB, key, val, 0);
}

R_API RStrBuf *var_get_constraint (RAnal *a, RAnalVar *var) {
	const char *key = RKEY (var->addr, var->kind, var->delta);
	int i, n = sdb_array_length (ADB, key);

	if (n < 2) {
		return NULL;
	}

	bool low = false, high = false;
	RStrBuf *sb = r_strbuf_new ("");

	for (i = 0; i < n; i += 2) {
		ut64 cond = sdb_array_get_num (ADB, key, i, 0);
		ut64 val = sdb_array_get_num (ADB, key, i + 1, 0);
		switch (cond) {
		case R_ANAL_COND_LE:
			if (high) {
				r_strbuf_append (sb, " && ");
			}
			r_strbuf_append (sb, sdb_fmt ("<= 0x%"PFMT64x "", val));
			low = true;
			break;
		case R_ANAL_COND_LT:
			if (high) {
				r_strbuf_append (sb, " && ");
			}
			r_strbuf_append (sb, sdb_fmt ("< 0x%"PFMT64x "", val));
			low = true;
			break;
		case R_ANAL_COND_GE:
			r_strbuf_append (sb, sdb_fmt (">= 0x%"PFMT64x "", val));
			high = true;
			break;
		case R_ANAL_COND_GT:
			r_strbuf_append (sb, sdb_fmt ("> 0x%"PFMT64x "", val));
			high = true;
			break;
		}
		if (low && high && i != n-2) {
			r_strbuf_append (sb, " || ");
			low = false;
			high = false;
		}
	}
	return sb;
}

static RList *parse_format(RCore *core, char *fmt) {
	RList *ret = r_list_new ();
	Sdb *s = core->anal->sdb_fmts;
	const char *spec = r_config_get (core->config, "anal.types.spec");
	char arr[10] = {0};
	char *ptr = strchr (fmt, '%');
	fmt[strlen(fmt) - 1] = '\0';
	while (ptr) {
		ptr += 1;
		// strip [width] specifier
		while (IS_DIGIT (*ptr)) { ptr++; }
		r_str_ncpy (arr, ptr, sizeof (arr) - 1);
		char *tmp = arr;
		while (tmp && (IS_LOWER (*tmp) || IS_UPPER (*tmp))) { tmp++; }
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

#define DEFAULT_MAX 3
#define REG_SZ 10
#define MAX_INSTR 5

static void type_match(RCore *core, ut64 addr, char *fcn_name, ut64 baddr, const char* cc,
		int prev_idx, bool userfnc, ut64 caddr) {
	Sdb *trace = core->anal->esil->db_trace;
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
	const char *place = r_anal_cc_arg (anal, cc, 1);
	r_cons_break_push (NULL, NULL);

	if (!strcmp (place, "stack_rev")) {
		stack_rev = true;
	}
	if (!strncmp (place, "stack", 5)) {
		in_stack = true;
	}
	if (verbose && !strncmp (fcn_name, "sym.imp.", 8)) {
		eprintf ("%s missing function definition\n", fcn_name + 8);
	}
	if (!max) {
		if (!in_stack) {
			max = r_anal_cc_max_arg(anal, cc);
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
			place = r_anal_cc_arg (anal, cc, arg_num + 1);
		}
		char regname[REG_SZ] = {0};
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
			RAnalOp *op = r_core_anal_op (core, instr_addr, R_ANAL_OP_MASK_BASIC);
			if (!op) {
				r_anal_op_free (op);
				break;
			}
			RAnalOp *next_op = r_core_anal_op (core, instr_addr + op->size, R_ANAL_OP_MASK_BASIC);
			if (!next_op || (j != idx && (next_op->type == R_ANAL_OP_TYPE_CALL
							|| next_op->type == R_ANAL_OP_TYPE_JMP))) {
				r_anal_op_free (op);
				r_anal_op_free (next_op);
				break;
			}
			char *key = NULL;
			RAnalVar *var = op->var;
			if (!in_stack) {
				key = sdb_fmt ("fcn.0x%08"PFMT64x".arg.%s", caddr, place);
			} else {
				key = sdb_fmt ("fcn.0x%08"PFMT64x".arg.%d", caddr, size);
			}
			const char *query = sdb_fmt ("%d.mem.read", j);
			if (op->type == R_ANAL_OP_TYPE_MOV && sdb_const_get (trace, query, 0)) {
				memref = (!memref && var && (var->kind != R_ANAL_VAR_KIND_REG))? false: true;
			}
			// Match type from function param to instr
			if (type_pos_hit (anal, trace, in_stack, j, size, place)) {
				if (!cmt_set && type && name) {
					r_meta_set_string (anal, R_META_TYPE_VARTYPE, instr_addr,
							sdb_fmt ("%s%s%s", type, r_str_endswith (type, "*") ? "" : " ", name));
					cmt_set = true;
					if ((op->ptr && op->ptr != UT64_MAX) && !strcmp (name, "format")) {
						RFlagItem *f = r_flag_get_i (core->flags, op->ptr);
						if (f && !strncmp (f->name, "str", 3)) {
							types = parse_format (core, f->realname);
							max += r_list_length (types);
							format = true;
						}
					}
				}
				if (var) {
					if (!userfnc) {
						var_retype (anal, var, name, type, addr, memref, false);
						var_rename (anal, var, name, addr);
					} else {
						// Set callee argument info
						sdb_set (anal->sdb_fcns, key, var->type, 0);
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
						var_retype (anal, var, name, type, addr, memref, false);
						var_rename (anal, var, name, addr);
					} else {
						sdb_set (anal->sdb_fcns, key, var->type, 0);
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
				char tmp[REG_SZ] = {0};
				get_src_regname (core, instr_addr, tmp, sizeof (tmp));
				ut64 ptr = get_addr (trace, tmp, j);
				if (ptr == xaddr) {
					var_retype (anal, var, name, type, addr, memref, false);
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
	bool chk_constraint = r_config_get_i (core->config, "anal.types.constraint");
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
		r_anal_emul_restore (core, hc);
		return;
	}
	char *fcn_name = NULL;
	char *ret_type = NULL;
	bool str_flag = false;
	bool prop = false;
	bool prev_var = false;
	char prev_type[256] = {0};
	const char *prev_dest = NULL;
	const char *ret_reg = NULL;
	const char *pc = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	RRegItem *r = r_reg_get (core->dbg->reg, pc, -1);
	r_cons_break_push (NULL, NULL);
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
			ut64 pcval = r_reg_getv (core->anal->reg, pc);
			if ((addr >= bb->addr + bb->size) || (addr < bb->addr) || pcval != addr) {
				break;
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
			if (loop_count > LOOP_MAX || aop.type == R_ANAL_OP_TYPE_RET) {
				r_anal_op_fini (&aop);
				break;
			}
			sdb_num_set (anal->esil->db_trace, sdb_fmt ("0x%"PFMT64x".count", addr), loop_count + 1, 0);
			if (r_anal_op_nonlinear (aop.type)) {   // skip the instr
				r_reg_set_value (core->dbg->reg, r, addr + ret);
			} else {
				r_core_esil_step (core, UT64_MAX, NULL, NULL);
			}
			bool userfnc = false;
			Sdb *trace = anal->esil->db_trace;
			cur_idx = sdb_num_get (trace, "idx", 0);
			RAnalVar *var = aop.var;
			RAnalOp *next_op = r_core_anal_op (core, addr + ret, R_ANAL_OP_MASK_BASIC);
			ut32 type = aop.type & R_ANAL_OP_TYPE_MASK;
			if (aop.type == R_ANAL_OP_TYPE_CALL) {
				RAnalFunction *fcn_call = r_anal_get_fcn_in (anal, aop.jump, -1);
				if (fcn_call) {
					if (r_type_func_exist (TDB, fcn_call->name)) {
						fcn_name = strdup (fcn_call->name);
					} else {
						fcn_name = r_type_func_guess (TDB, fcn_call->name);
					}
					if (!fcn_name) {
						fcn_name = strdup (fcn_call->name);
						userfnc = true;
					}
					const char* cc = r_anal_cc_func (anal, fcn_name);
					if (cc && r_anal_cc_exist (anal, cc)) {
						type_match (core, addr, fcn_name, bb->addr, cc, prev_idx,
								userfnc, fcn_call->addr);
						prev_idx = cur_idx;
						ret_type = (char *) r_type_func_ret (TDB, fcn_name);
						ret_reg = r_anal_cc_ret (anal, cc);
						resolved = false;
					}
					if (!strcmp (fcn_name, "__stack_chk_fail")) {
						const char *query = sdb_fmt ("%d.addr", cur_idx - 1);
						ut64 mov_addr = sdb_num_get (trace, query, 0);
						RAnalOp *mop = r_core_anal_op (core, mov_addr, R_ANAL_OP_MASK_BASIC);
						if (mop && mop->var) {
							ut32 type = mop->type & R_ANAL_OP_TYPE_MASK;
							if (type == R_ANAL_OP_TYPE_MOV) {
								var_rename (anal, mop->var, "canary", addr);
							}
						}
						r_anal_op_free (mop);
					}
					free (fcn_name);
				}
			} else if (!resolved && ret_type && ret_reg) {
				// Forward propgation of function return type
				char src[REG_SZ] = {0};
				const char *query = sdb_fmt ("%d.reg.write", cur_idx);
				const char *cur_dest = sdb_const_get (trace, query, 0);
				get_src_regname (core, aop.addr, src, sizeof (src));
				if (ret_reg && *src && strstr (ret_reg, src)) {
					if (var && aop.direction == R_ANAL_OP_DIR_WRITE) {
						var_retype (anal, var, NULL, ret_type, addr, false, false);
						resolved = true;
					} else if (type == R_ANAL_OP_TYPE_MOV) {
						ret_reg = cur_dest;
					}
				} else if (cur_dest) {
					char *foo = r_str_new (cur_dest);
					char *tmp = strchr (foo, ',');
					if (tmp) {
						*tmp = '\0';
					}
					if (strstr (ret_reg, foo) || (tmp && strstr (ret_reg, tmp + 1))) {
						resolved = true;
					} else if (type == R_ANAL_OP_TYPE_MOV &&
							(next_op && next_op->type == R_ANAL_OP_TYPE_MOV)){
						// Progate return type passed using pointer
						// int *ret; *ret = strlen(s);
						// TODO: memref check , dest and next src match
						char nsrc[REG_SZ] = {0};
						get_src_regname (core, next_op->addr, nsrc, sizeof (nsrc));
						if (ret_reg && *nsrc && strstr (ret_reg, nsrc) && var &&
								aop.direction == R_ANAL_OP_DIR_READ) {
							var_retype (anal, var, NULL, ret_type, addr, true, false);
						}
					}
					free (foo);
				}
			}
			// Type Propgation using intruction access pattern
			if (var) {
				bool sign = false;
				if ((type == R_ANAL_OP_TYPE_CMP) && next_op) {
					if (next_op->sign) {
						sign = true;
					} else {
						// cmp [local_ch], rax ; jb
						var_retype (anal, var, NULL, "unsigned", addr, false, true);
					}
				}
				// cmp [local_ch], rax ; jge
				if (sign || aop.sign) {
					var_retype (anal, var, NULL, "signed", addr, false, true);
				}
				// lea rax , str.hello  ; mov [local_ch], rax;
				// mov rdx , [local_4h] ; mov [local_8h], rdx;
				if (prev_dest && (type == R_ANAL_OP_TYPE_MOV || type == R_ANAL_OP_TYPE_STORE)) {
					char reg[REG_SZ] = {0};
					get_src_regname (core, addr, reg, sizeof (reg));
					bool match = strstr (prev_dest, reg)? true: false;
					if (str_flag && match) {
						var_retype (anal, var, NULL, "const char *", addr, false, false);
					}
					if (prop && match && prev_var) {
						var_retype (anal, var, NULL, prev_type, addr, false, false);
					}
				}
				if (chk_constraint && var && (type == R_ANAL_OP_TYPE_CMP && aop.ptr != UT64_MAX)
						&& next_op && next_op->type == R_ANAL_OP_TYPE_CJMP) {
					bool jmp = false;
					RAnalOp *jmp_op = {0};
					ut64 jmp_addr = next_op->jump;
					RAnalBlock *jmpbb = r_anal_fcn_bbget_in (fcn, jmp_addr);

					// Check exit status of jmp branch
					for (i = 0; i < MAX_INSTR ; i++) {
						jmp_op = r_core_anal_op (core, jmp_addr, R_ANAL_OP_MASK_BASIC);
						if ((jmp_op->type == R_ANAL_OP_TYPE_RET && r_anal_bb_is_in_offset (jmpbb, jmp_addr))
								|| jmp_op->type == R_ANAL_OP_TYPE_CJMP) {
							jmp = true;
							r_anal_op_free (jmp_op);
							break;
						}
						jmp_addr += jmp_op->size;
						r_anal_op_free (jmp_op);
					}
					int cond = jmp? cond_invert (next_op->cond): next_op->cond;
					var_add_range (anal, var, cond, aop.val);
				}
			}
			prev_var = (var && aop.direction == R_ANAL_OP_DIR_READ)? true: false;
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
							RFlagItem *f = r_flag_get_i (core->flags, ptr);
							if (f && !strncmp (f->name, "str", 3)) {
								str_flag = true;
							}
						}
					} else if (r_flag_exist_at (core->flags, "str", 3, aop.ptr)) {
						str_flag = true;
					}
				}
				// mov dword [local_4h], str.hello;
				if (var && str_flag) {
					var_retype (anal, var, NULL, "const char *", addr, false, false);
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
	const char *place = r_anal_cc_arg (anal, fcn->cc, 1);
	// Type propgation for register based args
	RList *list = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_REG);
	RAnalVar *rvar, *bp_var;
	RListIter *iter , *iter2;
	r_list_foreach (list, iter, rvar) {
		RAnalVar *lvar = get_link_var (anal, fcn->addr, rvar);
		RRegItem *i = r_reg_index_get (anal->reg, rvar->delta);
		if (!i) {
			continue;
		}
		bool res = true;
		char *type = NULL;
		const char *query = sdb_fmt ("fcn.0x%08"PFMT64x".arg.%s", fcn->addr, i->name);
		const char *qres = sdb_const_get (anal->sdb_fcns, query, NULL);
		if (qres) {
			type = strdup (qres);
		}
		if (lvar) {
			// Propagate local var type = to => register-based var
			var_retype (anal, rvar, NULL, lvar->type, fcn->addr, false, false);
			// Propagate local var type <= from = register-based var
			var_retype (anal, lvar, NULL, rvar->type, fcn->addr, false, false);
			if (!strstr (lvar->type, "int")) {
				res = false;
			}
		}
		if (type && res) {
			// Propgate type to local var and register based var passed
			// from caller function
			var_retype (anal, rvar, NULL, type, fcn->addr, false, false);
			if (lvar) {
				var_retype (anal, lvar, NULL, type, fcn->addr, false, false);
			}
		}
		free (type);
		r_anal_var_free (lvar);
	}
	// Type propgation from caller to callee function for stack based arguments
	if (place && !strncmp (place, "stack", 5)) {
		RList *list2 = r_anal_var_list (anal, fcn, R_ANAL_VAR_KIND_BPV);
		r_list_foreach (list2, iter2, bp_var) {
			if (bp_var->isarg) {
				const char *query = sdb_fmt ("fcn.0x%08"PFMT64x".arg.%d", fcn->addr, (bp_var->delta - 8));
				char *type = (char *) sdb_const_get (anal->sdb_fcns, query, NULL);
				if (type) {
					var_retype (anal, bp_var, NULL, type, fcn->addr, false, false);
				}
			}
		}
		r_list_free (list2);
	}
	r_list_free (list);
out_function:
	free (buf);
	r_cons_break_pop();
	r_anal_emul_restore (core, hc);
	sdb_reset (anal->esil->db_trace);
}
