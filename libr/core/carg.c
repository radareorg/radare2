/* radare - LGPL - Copyright 2009-2024 - pancake */

#include <r_core.h>

#define MAXSTRLEN 50

static const char *cc_source_first(RAnal *anal, const char *loc) {
	return loc? r_anal_cc_location_first (anal, loc): NULL;
}

static bool cc_source_on_stack(RAnal *anal, const char *loc) {
	const char *first = cc_source_first (anal, loc);
	return first && *first == '^';
}

static void set_fcn_args_info(RAnalFuncArg *arg, RAnal *anal, const char *fcn_name, const char *cc, int arg_num) {
	if (!fcn_name || !arg || !anal) {
		return;
	}
	Sdb *TDB = anal->sdb_types;
	arg->name = r_type_func_args_name (TDB, fcn_name, arg_num);
	arg->orig_c_type = r_type_func_args_type (TDB, fcn_name, arg_num);
	if (!arg->name || !arg->orig_c_type) {
		R_LOG_WARN ("Missing type for function argument to set (%s)", fcn_name);
		return;
	}
	arg->c_type = arg->orig_c_type;
	if (r_str_startswith (arg->c_type, "const ")) {
		arg->c_type += 6;
	}
	arg->fmt = sdb_const_getf (TDB, NULL, "type.%s", arg->c_type);
	arg->size = sdb_num_getf (TDB, NULL, "type.%s.size", arg->c_type) / 8;
	arg->cc_source = r_anal_cc_argloc (anal, cc, arg_num, 0, -1);
}

static ut64 get_buf_val(ut8 *buf, int endian, int width) {
	return (width == 8)? r_read_ble64 (buf, endian) : (ut64) r_read_ble32 (buf,endian);
}

static void print_arg_str(RCore *core, int argcnt, const char *name, bool color) {
	if (color) {
		r_cons_printf (core->cons, Color_BYELLOW" arg [%d]"Color_RESET" -"Color_BCYAN" %s"Color_RESET" : ", argcnt, name);
	} else {
		r_cons_printf (core->cons, " arg [%d] -  %s : ", argcnt, name);
	}
}

static void print_format_values(RCore *core, const char *fmt, bool onstack, ut64 src, bool color) {
	char opt;
	ut64 bval = src;
	int i;
	const int endian = R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config);
	int width = (core->anal->config->bits == 64)? 8: 4;
	int bsize = R_MIN (64, core->blocksize);

	ut8 *buf = malloc (bsize);
	if (!buf) {
		R_LOG_ERROR ("Cannot allocate %d byte(s)", bsize);
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
			r_cons_printf (core->cons, Color_BGREEN"0x%08"PFMT64x Color_RESET" --> ", bval);
		} else {
			r_cons_printf (core->cons, "0x%08"PFMT64x" --> ", bval);
		}
		r_io_read_at (core->io, bval, buf, bsize);
	}
	if (onstack) { // Fetch value from stack
		bval = get_buf_val (buf, endian, width);
		if (opt != 'd' && opt != 'x') {
			r_io_read_at (core->io, bval, buf, bsize); // update buf with val from stack
		}
	}
	r_cons_print (core->cons, color? Color_BGREEN: "");
	switch (opt) {
	case 'z' : // Null terminated string
		r_cons_print (core->cons, color ?Color_RESET Color_BWHITE:"");
		r_cons_print (core->cons, "\"");
		const char *ellipsis = r_print_ellipsis (core->print, NULL, NULL);
		for (i = 0; i < MAXSTRLEN; i++) {
			if (buf[i] == '\0') {
				break;
			}
			ut8 b = buf[i];
			if (IS_PRINTABLE (b)) {
				r_cons_printf (core->cons, "%c", b);
			} else {
				r_cons_printf (core->cons, "\\x%02x", b);
			}
			if (i == MAXSTRLEN - 1) {
				r_cons_print (core->cons, ellipsis); // To show string is truncated
			}
		}
		r_cons_print (core->cons, "\"");
		r_cons_newline (core->cons);
		break;
	case 'd' : // integer
	case 'x' :
		r_cons_printf (core->cons, "0x%08" PFMT64x, bval);
		r_cons_newline (core->cons);
		break;
	case 'c' : // char
		r_cons_print (core->cons, "\'");
		ut8 ch = buf[0];
		if (IS_PRINTABLE (ch)) {
			r_cons_printf (core->cons, "%c", ch);
		} else {
			r_cons_printf (core->cons, "\\x%02x", ch);
		}
		r_cons_print (core->cons, "\'");
		r_cons_newline (core->cons);
		break;
	case 'p' : // pointer
		{
		// Try to deref the pointer once again
		r_cons_printf (core->cons, "0x%08"PFMT64x, get_buf_val (buf, endian, width));
		r_cons_newline (core->cons);
		break;
		}
	default:
		//TODO: support types like structs and unions
		r_cons_println (core->cons, "unk_format");
	}
	r_cons_print (core->cons, Color_RESET);
	free (buf);
}

/* This function display list of arg with some colors */

R_API void r_core_print_func_args(RCore *core) {
	R_RETURN_IF_FAIL (core && core->anal && core->anal->reg);
	bool color = r_config_get_i (core->config, "scr.color");
	ut64 cur_addr = r_reg_getv (core->anal->reg, "PC");
	RListIter *iter;
	RAnalOp *op = r_core_anal_op (core, cur_addr, R_ARCH_OP_MASK_BASIC);
	if (!op) {
		return;
	}
	if (op->type == R_ANAL_OP_TYPE_CALL) {
		RAnalFunction *fcn;
		RAnalFuncArg *arg;
		const char *fcn_name = NULL;
		ut64 pcv = op->jump;
		if (pcv == UT64_MAX) {
			pcv = op->ptr;
		}
		fcn = r_anal_get_function_at (core->anal, pcv);
		if (fcn) {
			fcn_name = fcn->name;
		} else {
			if (core->flags) {
				RFlagItem *item = r_flag_get_in (core->flags, pcv);
				if (item) {
					fcn_name = item->name;
				}
			}
		}
		RList *list = r_core_get_func_args (core, fcn_name);
		if (!r_list_empty (list)) {
			int argcnt = 0;
			r_list_foreach (list, iter, arg) {
				bool onstack = cc_source_on_stack (core->anal, arg->cc_source);
				print_arg_str (core, argcnt, arg->name, color);
				print_format_values (core, arg->fmt, onstack, arg->src, color);
				argcnt++;
			}
		} else {
			int nargs = 4; // TODO: use a correct value here when available
			int i;
			const char *cc = r_anal_cc_default (core->anal); // or use "reg" ?
			for (i = 0; i < nargs; i++) {
				ut64 v = r_debug_arg_get (core->dbg, cc, i);
				print_arg_str (core, i, "", color);
				r_cons_printf (core->cons, "0x%08" PFMT64x, v);
				r_cons_newline (core->cons);
			}
		}
	}
	r_anal_op_fini (op);
}

static void r_anal_function_arg_free(RAnalFuncArg *arg) {
	if (arg) {
		free (arg->orig_c_type);
		free (arg);
	}
}

// printf-family formatters whose vararg list is described by the fixed arg right before "..."
static bool is_format_function(const char *name) {
	const char *base = r_str_rchr (name, NULL, '.');
	base = base? base + 1: name;
	static const char *const fns[] = {
		"printf", "fprintf", "dprintf", "sprintf", "snprintf", "asprintf",
		"syslog", "err", "errx", "warn", "warnx",
		"wprintf", "fwprintf", "swprintf",
		"__printf_chk", "__fprintf_chk", "__sprintf_chk", "__snprintf_chk", NULL
	};
	int i;
	for (i = 0; fns[i]; i++) {
		if (!strcmp (base, fns[i])) {
			return true;
		}
	}
	return false;
}

static char *read_format_string(RCore *core, ut64 ptr) {
	if (!ptr || ptr == UT64_MAX) {
		return NULL;
	}
	ut8 buf[256];
	if (!r_io_read_at (core->io, ptr, buf, sizeof (buf) - 1)) {
		return NULL;
	}
	buf[sizeof (buf) - 1] = 0;
	if (!buf[0] || !IS_PRINTABLE (buf[0])) {
		return NULL;
	}
	return strdup ((const char *)buf);
}

// exact-width read: rejects unreadable maps and slots whose tail would be io fill bytes
R_IPI bool core_slot_read(RCore *core, ut64 addr, int width, ut64 *out) {
	ut8 buf[8] = {0};
	if (!addr || addr == UT64_MAX || width < 1 || width > 8) {
		return false;
	}
	if (r_io_nread_at (core->io, addr, buf, width) != width) {
		return false;
	}
	*out = r_read_ble (buf, R_ARCH_CONFIG_IS_BIG_ENDIAN (core->rasm->config), width * 8);
	return true;
}

// argument address from the cc layout (shadow space, slot width, reverse order); 0 when unresolvable
static void arg_set_src(RCore *core, RAnalFuncArg *arg, const char *cc, int argno, int argc, ut64 spbase) {
	RAnalCCArgSlot slot;
	if (!r_anal_cc_argslot (core->anal, cc, argno, argc, false, &slot)) {
		return;
	}
	if (slot.reg) {
		arg->src = r_reg_getv (core->anal->reg, slot.reg);
	} else {
		arg->src = spbase + slot.off;
	}
}

// value width of a promoted printf vararg; the C type set r_str_printfmt emits is closed
static int vararg_size(const char *ctype, int word) {
	if (strchr (ctype, '*')) {
		return word;
	}
	if (strstr (ctype, "long long") || strstr (ctype, "double")) {
		return 8;
	}
	return strstr (ctype, "long")? word: 4;
}

static RAnalFuncArg *make_vararg(RCore *core, const char *cc, int slot, const char *ctype, ut64 spbase, int word) {
	RAnalFuncArg *arg = R_NEW0 (RAnalFuncArg);
	arg->orig_c_type = strdup (ctype);
	arg->c_type = arg->orig_c_type;
	arg->name = "";
	arg->size = vararg_size (ctype, word);
	// "z" makes print_fcn_arg/print_format_values render the string; scalars print their raw value
	arg->fmt = !strcmp (ctype, "char *")? "z": NULL;
	arg->cc_source = r_anal_cc_argloc (core->anal, cc, slot, 0, -1);
	arg_set_src (core, arg, cc, slot, -1, spbase);
	return arg;
}

// false leaves the "..." placeholder in place: the format arg isn't a resolvable literal
static bool append_format_varargs(RCore *core, RList *list, const char *cc, int nargs, ut64 spbase, int word) {
	const RAnalFuncArg *fmtarg = r_list_last (list); // the fixed arg right before "..."
	if (!fmtarg) {
		return false;
	}
	ut64 fptr = fmtarg->src;
	if (cc_source_on_stack (core->anal, fmtarg->cc_source)
		&& !core_slot_read (core, fptr, word, &fptr)) {
		return false;
	}
	char *fmt = read_format_string (core, fptr);
	if (!fmt) {
		return false;
	}
	char *types = r_str_printfmt (fmt, core->anal->config->bits, 0);
	free (fmt);
	if (!types) {
		return false;
	}
	int slotidx = nargs - 1; // the first vararg takes the "..." slot
	int i, ntypes = r_str_split (types, ',');
	const char *t = types;
	for (i = 0; i < ntypes; i++, t += strlen (t) + 1) {
		RAnalFuncArg *arg = make_vararg (core, cc, slotidx, t, spbase, word);
		r_list_append (list, arg);
		slotidx += R_MAX (1, (arg->size + word - 1) / word); // wide values span slots (%lld on 32-bit)
	}
	free (types);
	return true;
}

/* Returns a list of RAnalFuncArg */
R_API RList *r_core_get_func_args(RCore *core, const char *fcn_name) {
	if (!fcn_name || !core->anal) {
		return NULL;
	}
	Sdb *TDB = core->anal->sdb_types;
	char *key = r_type_func_name (core->anal->sdb_types, fcn_name);
	if (!key) {
		return NULL;
	}
	int nargs = r_type_func_args_count (TDB, key);
	const char *cc = r_anal_cc_func (core->anal, key);
	if (!cc) {
		free (key);
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_anal_function_arg_free);
	int i;
	const ut64 spbase = r_reg_getv (core->anal->reg, "SP");
	const int word = (core->anal->config->bits == 64)? 8: 4;
	bool variadic = nargs > 1 && is_format_function (key) && r_type_func_is_variadic (TDB, key);
	for (i = 0; i < nargs; i++) {
		if (variadic && i == nargs - 1
			&& append_format_varargs (core, list, cc, nargs, spbase, word)) {
			continue;
		}
		RAnalFuncArg *arg = R_NEW0 (RAnalFuncArg);
		set_fcn_args_info (arg, core->anal, key, cc, i);
		if (!arg->size) {
			arg->size = word;
		}
		arg_set_src (core, arg, cc, i, nargs, spbase);
		r_list_append (list, arg);
	}
	free (key);
	return list;
}
