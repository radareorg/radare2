/* radare - LGPL - Copyright 2009-2018 - pancake */

#include <r_core.h>

#define MAXSTRLEN 50

static void set_fcn_args_info(RAnalFuncArg *arg, RAnal *anal, const char *fcn_name, const char *cc, int arg_num) {
	if (!fcn_name || !arg || !anal) {
		return;
	}
	arg->name = r_anal_type_func_args_name (anal, fcn_name, arg_num);
	arg->orig_c_type = r_anal_type_func_args_type (anal, fcn_name, arg_num);
	if (!strncmp ("const ", arg->orig_c_type, 6)) {
		arg->c_type = arg->orig_c_type + 6;
	} else {
		arg->c_type = arg->orig_c_type;
	}
	const char *query = sdb_fmt (-1, "type.%s", arg->c_type);
	arg->fmt = sdb_const_get (anal->sdb_types, query, 0);
	const char *t_query = sdb_fmt (-1, "type.%s.size", arg->c_type);
	arg->size = sdb_num_get (anal->sdb_types, t_query, 0) / 8;
	arg->cc_source = r_anal_cc_arg (anal, cc, arg_num + 1);
}

static char *resolve_fcn_name(RAnal *anal, const char *func_name) {
	const char *str = func_name;
	const char *name = func_name;
	if (r_anal_type_func_exist (anal, func_name)) {
		return strdup (func_name);
	}
	while ((str = strchr (str, '.'))) {
		name = str + 1;
		str++;
	}
	if (r_anal_type_func_exist (anal, name)) {
		return strdup (name);
	}
	return r_anal_type_func_guess (anal, (char*)func_name);
}

static ut64 get_buf_val(ut8 *buf, int endian, int width) {
	return (width == 8)? r_read_ble64 (buf, endian) : (ut64) r_read_ble32 (buf,endian);
}

static void print_arg_str(int argcnt, const char *name, bool color) {
	if (color) {
		r_cons_printf (Color_BYELLOW" arg [%d]"Color_RESET" -"Color_BCYAN" %s"Color_RESET" : ",
				argcnt, name);
	} else {
		r_cons_printf (" arg [%d] -  %s : ", argcnt, name);
	}
}

static void print_format_values(RCore *core, const char *fmt, bool onstack, ut64 src, bool color) {
	char opt;
	ut64 bval = src;
	int i;
	int endian = core->print->big_endian;
	int width = (core->anal->bits == 64)? 8: 4;
	int bsize = R_MIN (64, core->blocksize);

	ut8 *buf = malloc (bsize);
	if (!buf) {
		eprintf ("Cannot allocate %d byte(s)\n", bsize);
		free (buf);
		return;
	}
	if (fmt) {
		opt = *fmt;
	} else {
		opt = 'p'; // void *ptr
	}
	if (onstack || ((opt != 'd' && opt != 'x') && !onstack)) {
		if (color) {
			r_cons_printf (Color_BGREEN"0x%08"PFMT64x Color_RESET" --> ", bval);
		} else {
			r_cons_printf ("0x%08"PFMT64x" --> ", bval);
		}
        	r_core_read_at (core, bval, buf, bsize);
	}
	if (onstack) { // Fetch value from stack
		bval = get_buf_val (buf, endian, width);
		if (opt != 'd' && opt != 'x') {
			r_core_read_at (core, bval, buf, bsize); // update buf with val from stack
		}
	}
	r_cons_print (color? Color_BGREEN: "");
	switch (opt) {
	case 'z' : // Null terminated string
		r_cons_print (color ?Color_RESET Color_BWHITE:"");
		r_cons_print ("\"");
		for (i = 0; i < MAXSTRLEN; i++) {
			if (buf[i] == '\0') {
				break;
			}
			ut8 b = buf[i];
			if (IS_PRINTABLE (b)) {
				r_cons_printf ("%c", b);
			} else {
				r_cons_printf ("\\x%02x", b);
			}
			if (i == MAXSTRLEN - 1) {
				 r_cons_print ("..."); // To show string is truncated
			}
		}
		r_cons_print ("\"");
		r_cons_newline ();
		break;
	case 'd' : // integer
	case 'x' :
		r_cons_printf ("0x%08" PFMT64x, bval);
		r_cons_newline ();
		break;
	case 'c' : // char
		r_cons_print ("\'");
		ut8 ch = buf[0];
		if (IS_PRINTABLE (ch)) {
			r_cons_printf ("%c", ch);
		} else {
			r_cons_printf ("\\x%02x", ch);
		}
		r_cons_print ("\'");
		r_cons_newline ();
		break;
	case 'p' : // pointer
		{
		// Try to deref the pointer once again
		r_cons_printf ("0x%08"PFMT64x, get_buf_val (buf, endian, width));
		r_cons_newline ();
		break;
		}
	default:
		//TODO: support types like structs and unions
		r_cons_println ("unk_format");
	}
	r_cons_print (Color_RESET);
	free (buf);
}

/* This functon display list of arg with some colors */

R_API void r_core_print_func_args(RCore *core) {
	RListIter *iter;
	bool color = r_config_get_i (core->config, "scr.color");
	if (!core->anal) {
		return;
	}
	if (!core->anal->reg) {
		return;
	}
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	ut64 cur_addr = r_reg_getv (core->anal->reg, pc);
	RAnalOp *op = r_core_anal_op (core, cur_addr);
	if (!op) {
		return;
	}
	if (op->type == R_ANAL_OP_TYPE_CALL) {
		RAnalFunction *fcn;
		RAnalFuncArg *arg;
		int i;
		int nargs = 0;
		bool onstack = false;
		const char *fcn_name = NULL;
		ut64 pcv = op->jump;
		if (pcv == UT64_MAX) {
			pcv = op->ptr;
		}
		fcn = r_anal_get_fcn_at (core->anal, pcv, 0);
		if (fcn) {
			fcn_name = fcn->name;
		} else {
			if (core->flags) {
				RFlagItem *item = r_flag_get_i (core->flags, pcv);
				if (item) {
					fcn_name = item->name;
				}
			}
		}
		RList *list = r_core_get_func_args (core, fcn_name);
		if (!r_list_empty (list)) {
			int argcnt = 0;
			r_list_foreach (list, iter, arg) {
				if (arg->cc_source && !strncmp (arg->cc_source, "stack", 5)) {
					onstack = true;
				}
				print_arg_str (argcnt, arg->name, color);
				print_format_values (core, arg->fmt, onstack, arg->src, color);
				argcnt++;
			}
		} else {
			if (fcn) {
				nargs = fcn->nargs;
			}
			if (nargs > 0) {
				for (i = 0; i < nargs; i++) {
					ut64 v = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_STDCALL, i);
					print_arg_str (i, "", color);
					r_cons_printf ("0x%08" PFMT64x, v);
					r_cons_newline ();
				}
			} else {
				print_arg_str (0, "void", color);
			}
		}
	}
	r_anal_op_fini (op);
}

/* Returns a list of RAnalFuncArg */
R_API RList *r_core_get_func_args(RCore *core, const char *fcn_name) {
	if (!fcn_name || !core->anal) {
		return NULL;
	}
	RList *list = r_list_new ();
	char *key = resolve_fcn_name (core->anal, fcn_name);
	if (!key) {
		return NULL;
	}
	const char *sp = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	int nargs = r_anal_type_func_args_count (core->anal, key);
	const char *cc = r_anal_type_func_cc (core->anal, key);
	const char *src = r_anal_cc_arg (core->anal, cc, 1); // src of first argument
	if (!cc) {
		// unsupported calling convention
		return NULL;
	}
	int i;
	ut64 spv = r_reg_getv (core->anal->reg, sp);
	ut64 s_width = (core->anal->bits == 64)? 8: 4;
	if (src && !strcmp (src, "stack_rev")) {
		for (i = nargs - 1; i >= 0; i--) {
			RAnalFuncArg *arg = R_NEW0 (RAnalFuncArg);
			set_fcn_args_info (arg, core->anal, key, cc, i);
			arg->src = spv;
			spv += arg->size? arg->size : s_width;
			r_list_append (list, arg);
		}
	} else {
		for (i = 0; i < nargs; i++) {
			RAnalFuncArg *arg = R_NEW0 (RAnalFuncArg);
			if (!arg) {
				return NULL;
			}
			set_fcn_args_info (arg, core->anal, key, cc, i);
			if (src && !strncmp (src, "stack", 5)) {
				arg->src = spv;
				if (!arg->size) {
					arg->size = s_width;
				}
				spv += arg->size;
			} else {
				arg->src = r_reg_getv (core->anal->reg, arg->cc_source);
			}
			r_list_append (list, arg);
		}
	}
	return list;
}
