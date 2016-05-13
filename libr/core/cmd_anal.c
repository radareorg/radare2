/* radare - LGPL - Copyright 2009-2016 - pancake, maijin */

#include "r_util.h"
#include "r_core.h"

static void find_refs(RCore *core, const char *glob) {
	char cmd[128];
	ut64 curseek = core->offset;
	while (*glob == ' ') glob++;
	if (!*glob)
		glob = "str.";
	if (*glob == '?') {
		eprintf ("Usage: arf [flag-str-filter]\n");
		return;
	}
	eprintf ("Finding references of flags matching '%s'...\n", glob);
	snprintf (cmd, sizeof (cmd) - 1, ".(findstref) @@= `f~%s[0]`", glob);
	r_core_cmd0 (core, "(findstref,f here=$$,s entry0,/r here,f-here)");
	r_core_cmd0 (core, cmd);
	r_core_cmd0 (core, "(-findstref)");
	r_core_seek (core, curseek, 1);
}

/* set flags for every function */
static void flag_every_function(RCore *core) {
	RListIter *iter;
	RAnalFunction *fcn;
	r_flag_space_push (core->flags, "functions");
	r_list_foreach (core->anal->fcns, iter, fcn) {
		r_flag_set (core->flags, fcn->name,
			fcn->addr, r_anal_fcn_size (fcn));
	}
	r_flag_space_pop (core->flags);
}

static void var_help(RCore *core, char ch) {
	const char *help_sp[] = {
		"Usage:", "afe", " [idx] [type] [name]",
		"afe", "", "list stack based arguments and variables",
		"afe*", "", "same as afe but in r2 commands",
		"afe", " [idx] [name] [type]", "define stack based arguments,variables",
		"afen", " [old_name] [new_name]", "rename stack based argument or variable",
		"afet", " [name] [new_type]", "change type for given argument or variable",
		"afej", "", "return list of stack based arguments and variables in JSON format",
		"afe-", " [name]", "delete stack based argument or variables with the given name",
		"afeg", " [idx] [addr]", "define var get reference",
		"afes", " [idx] [addr]", "define var set reference",
		NULL
	};
	const char *help_bp[] = {
		"Usage:", "afa", " [idx] [type] [name]",
		"afa", "", "list base pointer based arguments, variables",
		"afa*", "", "same as afa but in r2 commands",
		"afa", " [idx] [name] ([type])", "define base pointer based argument, variable",
		"afan", " [old_name] [new_name]", "rename base pointer based argument or variable",
		"afat", " [name] [new_type]", "change type for given base pointer based argument or variable",
		"afaj", "", "return list of base pointer based arguments, variables in JSON format",
		"afa-", " [name]", "delete argument/ variables at the given name",
		"afag", " [idx] [addr]", "define var get reference",
		"afas", " [idx] [addr]", "define var set reference",
		NULL
	};
	const char *help_reg[] = {
		"Usage:", "afv", " [reg] [type] [name]",
		"afv", "", "list register based arguments",
		"afv*", "", "same as afv but in r2 commands",
		"afv", " [reg] [name] ([type])", "define register arguments",
		"afvn", " [old_name] [new_name]", "rename argument",
		"afvt", " [name] [new_type]", "change type for given argument",
		"afvj", "", "return list of register arguments in JSON format",
		"afv-", " [name]", "delete register arguments at the given index",
		"afvg", " [reg] [addr]", "define var get reference",
		"afvs", " [reg] [addr]", "define var set reference",
		NULL
	};
	switch (ch) {
	case 'a':
		r_core_cmd_help (core, help_bp);
		break;
	case 'e':
		r_core_cmd_help (core, help_sp);
		break;
	case 'v':
		r_core_cmd_help (core, help_reg);
		break;
	default:
		eprintf ("See afv?, afe? and afa?\n");
	}
}

static int var_cmd(RCore *core, const char *str) {
	char *p, *ostr;
	int delta, type = *str, res = true;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);

	ostr = p = strdup (str);
	str = (const char *)ostr;

	switch (type) {
	case '?':
		var_help (core, 0);
		break;
	case 'v': // registers
	case 'a': // base pointer vars/args
	case 'e': // stack pointer vars/args
		// XXX nested dup
		if (str[1] == '?') {
			var_help (core, *str);
			break;
		}
		if (!fcn && str[1] != 'j' && str[1] != '*') {
			eprintf ("Cannot find function here\n");
			break;
		}

		/* Variable access CFvs = set fun var */
		switch (str[1]) {
		case '\0':
		case '*':
		case 'j':
			r_anal_var_list_show (core->anal, fcn, type, str[1]);
			break;
		case '.':
			r_anal_var_list_show (core->anal, fcn, core->offset, 0);
			break;
		case '-': // "afaAev-"
			if (str[2] == '*') {
				r_anal_var_delete_all (core->anal, fcn->addr, type);
			} else {
				if (IS_NUMBER (str[2])) {
					r_anal_var_delete (core->anal, fcn->addr,
							type, 1, (int)r_num_math (core->num, str + 1));
				} else {
					char *name = r_str_chop ( strdup (str + 2));
					r_anal_var_delete_byname (core->anal, fcn, type, name);
					free (name);
				}
			}
			break;
		case 'n': {
			RAnalVar *v1;
			str++;
			for (str++; *str == ' ';) str++;
			char *new_name = strchr (str, ' ');
			if (!new_name) {
				var_help (core, type);
				break;
			}
			*new_name++ = 0;
			char *old_name = strdup (str);
			r_str_split (old_name, ' ');
			v1 = r_anal_var_get_byname (core->anal, fcn, 'a', new_name);
			if (!v1) {
				v1 = r_anal_var_get_byname (core->anal, fcn, 'e', new_name);
			}
			if (!v1) {
				v1 = r_anal_var_get_byname (core->anal, fcn, 'v', new_name);
			}
			if(v1) {
				free (v1);
				eprintf("variable or arg with name `%s` already exist\n", new_name);
				break;
			}
			r_anal_var_rename (core->anal, fcn->addr,
					R_ANAL_VAR_SCOPE_LOCAL, (char)type,
					old_name, new_name);
			free (old_name);
		} break;
		case 't': {
			//should we read types from t
			const char *name = str + 1;
			for (name++; *name == ' ';) name++;
			char *new_type = strchr (name, ' ');
			if (!new_type) {
				var_help (core, type);
				break;
			}
			*new_type++ = 0;
			r_anal_var_retype (core->anal, fcn->addr,
					R_ANAL_VAR_SCOPE_LOCAL, -1, (char)str[0],
					new_type, -1, name);
		} break;
		case 's':
		case 'g':
			if (str[2] != '\0') {
				int rw = 0; // 0 = read, 1 = write
				RAnalVar *var = r_anal_var_get (core->anal, fcn->addr,
								(char)type, atoi (str + 2), R_ANAL_VAR_SCOPE_LOCAL);
				if (!var) {
					eprintf ("Cannot find variable in: '%s'\n", str);
					res = false;
					break;
				}
				if (var != NULL) {
					int scope = (str[1] == 'g')? 0: 1;
					r_anal_var_access (core->anal, fcn->addr, (char)type,
							scope, atoi (str + 2), rw, core->offset);
					r_anal_var_free (var);
					break;
				}
			} else eprintf ("Missing argument\n");
			break;
		case ' ': {
			const char *name;
			char *vartype;
			int size = 4;
			int scope = 1;

			for (str++; *str == ' ';) str++;
			p = strchr (str, ' ');
			if (!p) {
				var_help (core, type);
				break;
			}
			*p++ = 0;
			if (type == 'v') { //registers
				RRegItem *i = r_reg_get (core->anal->reg, str, -1);
				if (!i) {
					eprintf ("Register not found");
					break;
				}
				delta = i->index;
			} else {
				delta = r_num_math (core->num, str);
			}
			name = p;
			vartype = strchr (name, ' ');
			if (vartype) {
				*vartype++ = 0;
				r_anal_var_add (core->anal, fcn->addr,
						scope, delta, type,
						vartype, size, name);
			} else eprintf ("Missing name\n");
			break;
		}
		default:
			var_help (core, *str);
			break;
		}
		break;
	}

	free (ostr);
	return res;
}

static void print_trampolines(RCore *core, ut64 a, ut64 b, size_t element_size) {
	int i;
	for (i = 0; i < core->blocksize; i += element_size) {
		ut32 n;
		memcpy (&n, core->block + i, sizeof (ut32));
		if (n >= a && n <= b) {
			if (element_size == 4)
				r_cons_printf ("f trampoline.%x @ 0x%" PFMT64x "\n", n, core->offset + i);
			else r_cons_printf ("f trampoline.%" PFMT64x " @ 0x%" PFMT64x "\n", n, core->offset + i);

			r_cons_printf ("Cd %u @ 0x%" PFMT64x ":%u\n", element_size, core->offset + i, element_size);
			// TODO: add data xrefs
		}
	}
}

static void cmd_anal_trampoline(RCore *core, const char *input) {
	int bits = r_config_get_i (core->config, "asm.bits");
	char *p, *inp = strdup (input);
	p = strchr (inp, ' ');
	if (p) *p = 0;
	ut64 a = r_num_math (core->num, inp);
	ut64 b = p? r_num_math (core->num, p + 1): 0;
	free (inp);

	switch (bits) {
	case 32:
		print_trampolines (core, a, b, 4);
		break;
	case 64:
		print_trampolines (core, a, b, 8);
		break;
	}
}

R_API char *cmd_syscall_dostr(RCore *core, int n) {
	char *res = NULL;
	int i;
	char str[64];
	if (n == -1) {
		n = (int)r_debug_reg_get (core->dbg, "oeax");
		if (n == 0 || n == -1) {
			const char *a0 = r_reg_get_name (core->anal->reg, R_REG_NAME_A0);
			n = (int)r_debug_reg_get (core->dbg, a0);
		}
	}
	RSyscallItem *item = r_syscall_get (core->anal->syscall, n, -1);
	if (item == NULL) {
		res = r_str_concatf (res, "%d = unknown ()", n);
		return res;
	}
	res = r_str_concatf (res, "%d = %s (", item->num, item->name);
	// TODO: move this to r_syscall
	for (i = 0; i < item->args; i++) {
		ut64 arg = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_FASTCALL, i + 1);
		//r_cons_printf ("(%d:0x%"PFMT64x")\n", i, arg);
		if (item->sargs) {
			switch (item->sargs[i]) {
			case 'p': // pointer
				res = r_str_concatf (res, "0x%08" PFMT64x "", arg);
				break;
			case 'i':
				res = r_str_concatf (res, "%" PFMT64d "", arg);
				break;
			case 'z':
				r_io_read_at (core->io, arg, (ut8 *)str, sizeof (str));
				// TODO: filter zero terminated string
				str[63] = '\0';
				r_str_filter (str, strlen (str));
				res = r_str_concatf (res, "\"%s\"", str);
				break;
			case 'Z': {
				ut64 len = r_debug_arg_get (core->dbg, R_ANAL_CC_TYPE_FASTCALL, i + 2);
				len = R_MIN (len + 1, sizeof (str) - 1);
				if (len == 0) len = 16; // override default
				(void)r_io_read_at (core->io, arg, (ut8 *)str, len);
				str[len] = 0;
				r_str_filter (str, -1);
				res = r_str_concatf (res, "\"%s\"", str);
			} break;
			default:
				res = r_str_concatf (res, "0x%08" PFMT64x "", arg);
				break;
			}
		} else {
			res = r_str_concatf (res, "0x%08" PFMT64x "", arg);
		}
		if (i + 1 < item->args)
			res = r_str_concatf (res, ", ");
	}
	res = r_str_concatf (res, ")");
	return res;
}

static void cmd_syscall_do(RCore *core, int n) {
	char *msg = cmd_syscall_dostr (core, n);
	if (msg) {
		r_cons_printf ("%s\n", msg);
		free (msg);
	}
}

static void core_anal_bytes(RCore *core, const ut8 *buf, int len, int nops, int fmt) {
	int stacksize = r_config_get_i (core->config, "esil.stacksize");
	bool iotrap = r_config_get_i (core->config, "esil.iotrap");
	bool romem = r_config_get_i (core->config, "esil.romem");
	bool stats = r_config_get_i (core->config, "esil.stats");
	bool use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	int ret, i, j, idx, size;
	const char *color = "";
	const char *esilstr;
	RAnalHint *hint;
	RAnalEsil *esil;
	RAsmOp asmop;
	RAnalOp op;
	ut64 addr;

	// Variables required for setting up ESIL to REIL conversion
	if (use_color) {
		color = core->cons->pal.label;
	}
	switch (fmt) {
	case 'j':
		r_cons_printf ("[");
		break;
	case 'r':
		// Setup for ESIL to REIL conversion
		esil = r_anal_esil_new (stacksize, iotrap);
		if (!esil) {
			return;
		}
		r_anal_esil_to_reil_setup (esil, core->anal, romem, stats);
		r_anal_esil_set_pc (esil, core->offset);
		break;
	}
	for (i = idx = ret = 0; idx < len && (!nops || (nops && i < nops)); i++, idx += ret) {
		addr = core->offset + idx;
		// TODO: use more anal hints
		hint = r_anal_hint_get (core->anal, addr);
		r_asm_set_pc (core->assembler, addr);
		ret = r_asm_disassemble (core->assembler, &asmop, buf + idx, len - idx);
		ret = r_anal_op (core->anal, &op, core->offset + idx, buf + idx, len - idx);
		esilstr = R_STRBUF_SAFEGET (&op.esil);
		if (ret < 1 && fmt != 'd') {
			eprintf ("Oops at 0x%08" PFMT64x " (", core->offset + idx);
			for (i = idx, j = 0; i < core->blocksize && j < 3; ++i, ++j) {
				eprintf ("%02x ", buf[i]);
			}
			eprintf ("...)\n");
			break;
		}
		size = (hint && hint->size)? hint->size: op.size;
		if (fmt == 'd') {
			char *opname = strdup (asmop.buf_asm);
			r_str_split (opname, ' ');
			char *d = r_asm_describe (core->assembler, opname);
			if (d && *d) {
				r_cons_printf ("%s: %s\n", opname, d);
				free (d);
			} else r_cons_printf ("Unknown opcode\n");
			free (opname);
		} else if (fmt == 'e') {
			if (*esilstr) {
				if (use_color) {
					r_cons_printf ("%s0x%" PFMT64x Color_RESET " %s\n", color, core->offset + idx, esilstr);
				} else {
					r_cons_printf ("0x%" PFMT64x " %s\n", core->offset + idx, esilstr);
				}
			}
		} else if (fmt == 'r') {
			if (*esilstr) {
				if (use_color) {
					r_cons_printf ("%s0x%" PFMT64x Color_RESET "\n", color, core->offset + idx);
				} else {
					r_cons_printf ("0x%" PFMT64x "\n", core->offset + idx);
				}
				r_anal_esil_parse (esil, esilstr);
				r_anal_esil_dumpstack (esil);
				r_anal_esil_stack_free (esil);
			}
		} else if (fmt == 'j') {
			r_cons_printf ("{\"opcode\": \"%s\",", asmop.buf_asm);
			if (hint && hint->opcode)
				r_cons_printf ("\"ophint\": \"%s\",", hint->opcode);
			r_cons_printf ("\"prefix\": %" PFMT64d ",", op.prefix);
			r_cons_printf ("\"addr\": %" PFMT64d ",", core->offset + idx);
			r_cons_printf ("\"bytes\": \"");
			for (j = 0; j < size; j++)
				r_cons_printf ("%02x", buf[j]);
			r_cons_printf ("\",");
			if (op.val != UT64_MAX)
				r_cons_printf ("\"val\": %" PFMT64d ",", op.val);
			if (op.ptr != UT64_MAX)
				r_cons_printf ("\"ptr\": %" PFMT64d ",", op.ptr);
			r_cons_printf ("\"size\": %d,", size);
			r_cons_printf ("\"type\": \"%s\",",
				r_anal_optype_to_string (op.type));
			if (op.reg) {
				r_cons_printf ("\"reg\": \"%s\",", op.reg);
			}
			if (*esilstr) {
				r_cons_printf ("\"esil\": \"%s\",",
					esilstr);
			}
			if (hint && hint->jump != UT64_MAX)
				op.jump = hint->jump;
			if (op.jump != UT64_MAX)
				r_cons_printf ("\"jump\":%" PFMT64d ",", op.jump);
			if (hint && hint->fail != UT64_MAX)
				op.fail = hint->fail;
			if (op.refptr != -1)
				r_cons_printf ("\"refptr\":%d,", op.refptr);
			if (op.fail != UT64_MAX)
				r_cons_printf ("\"fail\":%" PFMT64d ",", op.fail);

			r_cons_printf ("\"cycles\":%d,", op.cycles);
			if (op.failcycles)
				r_cons_printf ("\"failcycles\":%d,", op.failcycles);
			r_cons_printf ("\"delay\":%d,", op.delay);
			{
				const char *p = r_anal_stackop_tostring (op.stackop);
				if (p && *p && strcmp (p, "null"))
					r_cons_printf ("\"stack\":\"%s\",", p);
			}
			{
				const char *arg = (op.type & R_ANAL_OP_TYPE_COND)?
					r_anal_cond_tostring (op.cond): NULL;
				if (arg) {
					r_cons_printf ("\"cond\":\"%s\",", arg);
				}
			}
			r_cons_printf ("\"family\":\"%s\"}", r_anal_op_family_to_string (op.family));
		} else {
#define printline(k, fmt, arg)\
	{ \
		if (use_color)\
			r_cons_printf ("%s%s: " Color_RESET, color, k);\
		else\
			r_cons_printf ("%s: ", k);\
		if (fmt) r_cons_printf (fmt, arg);\
	}
			printline ("address", "0x%" PFMT64x "\n", core->offset + idx);
			printline ("opcode", "%s\n", asmop.buf_asm);
			if (hint) {
				if (hint->opcode)
					printline ("ophint", "%s\n", hint->opcode);
				printline ("addr", "0x%08" PFMT64x "\n", (hint->addr + idx));
			}
			printline ("prefix", "%" PFMT64d "\n", op.prefix);
			printline ("bytes", NULL, 0);
			for (j = 0; j < size; j++)
				r_cons_printf ("%02x", buf[j]);
			r_cons_newline ();
			if (op.val != UT64_MAX)
				printline ("val", "0x%08" PFMT64x "\n", op.val);
			if (op.ptr != UT64_MAX)
				printline ("ptr", "0x%08" PFMT64x "\n", op.ptr);
			if (op.refptr != -1)
				printline ("refptr", "%d\n", op.refptr);
			printline ("size", "%d\n", size);
			printline ("type", "%s\n", r_anal_optype_to_string (op.type));
			{
				const char *t2 = r_anal_optype_to_string (op.type2);
				if (t2 && strcmp (t2, "null")) {
					printline ("type2", "%s\n", t2);
				}
			}
			if (op.reg)
				printline ("reg", "%s\n", op.reg);
			if (*esilstr)
				printline ("esil", "%s\n", esilstr);
			if (hint && hint->jump != UT64_MAX)
				op.jump = hint->jump;
			if (op.jump != UT64_MAX)
				printline ("jump", "0x%08" PFMT64x "\n", op.jump);

			if (hint && hint->fail != UT64_MAX)
				op.fail = hint->fail;
			if (op.fail != UT64_MAX)
				printline ("fail", "0x%08" PFMT64x "\n", op.fail);
			if (op.delay)
				printline ("delay", "%d\n", op.delay);

			printline ("stack", "%s\n", r_anal_stackop_tostring (op.stackop));
			{
				const char *arg = (op.type & R_ANAL_OP_TYPE_COND)?  r_anal_cond_tostring (op.cond): NULL;
				if (arg) {
					printline ("cond", "%s\n", arg);
				}
			}
			printline ("family", "%s\n", r_anal_op_family_to_string (op.family));
		}
		//r_cons_printf ("false: 0x%08"PFMT64x"\n", core->offset+idx);
		//free (hint);
		r_anal_hint_free (hint);
		if (((idx + ret) < len) && (!nops || (i + 1) < nops) && fmt != 'e' && fmt != 'r')
			r_cons_printf (",");
	}

	if (fmt == 'j') {
		r_cons_printf ("]");
		r_cons_newline ();
	} else if (fmt == 'r') {
		r_anal_esil_free (esil);
	}
}

static int bb_cmp(const void *a, const void *b) {
	const RAnalBlock *ba = a;
	const RAnalBlock *bb = b;
	return ba->addr - bb->addr;
}

static int anal_fcn_list_bb(RCore *core, const char *input) {
	RDebugTracepoint *tp = NULL;
	RAnalFunction *fcn;
	RListIter *iter;
	RAnalBlock *b;
	int mode = 0;
	ut64 addr;

	if (*input) {
		mode = *input;
		input++;
	}
	const char *space = strchr (input, ' ');
	if (space) {
		addr = r_num_math (core->num, space + 1);
	} else {
		addr = core->offset;
	}
	fcn = r_anal_get_fcn_in (core->anal, addr, 0);
	if (!fcn)
		return false;
	switch (mode) {
	case 'j':
		r_cons_printf ("[");
		break;
	case '*':
		r_cons_printf ("fs blocks\n");
		break;
	}
	r_list_sort (fcn->bbs, bb_cmp);
	r_list_foreach (fcn->bbs, iter, b) {
		switch (mode) {
		case 'r':
			if (b->jump == UT64_MAX) {
				ut64 retaddr = b->addr;
				if (b->op_pos) {
					retaddr += b->op_pos[b->ninstr - 2];
				}
				if (!strcmp (input, "*")) {
					r_cons_printf ("db 0x%08"PFMT64x"\n", retaddr);
				} else if (!strcmp (input, "-*")) {
					r_cons_printf ("db-0x%08"PFMT64x"\n", retaddr);
				} else {
					r_cons_printf ("0x%08"PFMT64x"\n", retaddr);
				}
			}
			break;
		case '*':
			r_cons_printf ("f bb.%05" PFMT64x " = 0x%08" PFMT64x "\n",
				b->addr & 0xFFFFF, b->addr);
			break;
		case 'q':
			r_cons_printf ("0x%08" PFMT64x "\n", b->addr);
			break;
		case 'j':
			r_cons_printf ("%" PFMT64d "%s", b->addr, iter->n? ",": "");
			break;
		default:
			tp = r_debug_trace_get (core->dbg, b->addr);
			r_cons_printf ("0x%08" PFMT64x " 0x%08" PFMT64x " %02X:%04X %d",
				b->addr, b->addr + b->size,
				tp? tp->times: 0, tp? tp->count: 0,
				b->size);
			if (b->jump != UT64_MAX) {
				r_cons_printf (" j 0x%08" PFMT64x, b->jump);
			}
			if (b->fail != UT64_MAX) {
				r_cons_printf (" f 0x%08" PFMT64x, b->fail);
			}
			r_cons_newline ();
			break;
		}
	}
	if (mode == 'j') {
		r_cons_printf ("]\n");
	}
	return true;
}

static bool anal_fcn_del_bb(RCore *core, const char *input) {
	ut64 addr = r_num_math (core->num, input);
	if (!addr) addr = core->offset;
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
	if (fcn) {
		if (!strcmp (input, "*")) {
			r_list_free (fcn->bbs);
			fcn->bbs = NULL;
		} else {
			RAnalBlock *b;
			RListIter *iter;
			r_list_foreach (fcn->bbs, iter, b) {
				if (b->addr == addr) {
					r_list_delete (fcn->bbs, iter);
					return true;
				}
			}
			eprintf ("Cannot find basic block\n");
		}
	} else {
		eprintf ("Cannot find function\n");
	}
	return false;
}

static int anal_fcn_add_bb(RCore *core, const char *input) {
	// fcn_addr bb_addr bb_size [jump] [fail]
	char *ptr;
	const char *ptr2 = NULL;
	ut64 fcnaddr = -1LL, addr = -1LL;
	ut64 size = 0LL;
	ut64 jump = UT64_MAX;
	ut64 fail = UT64_MAX;
	int type = R_ANAL_BB_TYPE_NULL;
	RAnalFunction *fcn = NULL;
	RAnalDiff *diff = NULL;

	while (*input == ' ') input++;
	ptr = strdup (input);

	switch (r_str_word_set0 (ptr)) {
	case 7:
		ptr2 = r_str_word_get0 (ptr, 6);
		if (!(diff = r_anal_diff_new ())) {
			eprintf ("error: Cannot init RAnalDiff\n");
			free (ptr);
			return false;
		}
		if (ptr2[0] == 'm')
			diff->type = R_ANAL_DIFF_TYPE_MATCH;
		else if (ptr2[0] == 'u')
			diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
	case 6:
		ptr2 = r_str_word_get0 (ptr, 5);
		if (strchr (ptr2, 'h'))
			type |= R_ANAL_BB_TYPE_HEAD;
		if (strchr (ptr2, 'b'))
			type |= R_ANAL_BB_TYPE_BODY;
		if (strchr (ptr2, 'l'))
			type |= R_ANAL_BB_TYPE_LAST;
		if (strchr (ptr2, 'f'))
			type |= R_ANAL_BB_TYPE_FOOT;
	case 5: // get fail
		fail = r_num_math (core->num, r_str_word_get0 (ptr, 4));
	case 4: // get jump
		jump = r_num_math (core->num, r_str_word_get0 (ptr, 3));
	case 3: // get size
		size = r_num_math (core->num, r_str_word_get0 (ptr, 2));
	case 2: // get addr
		addr = r_num_math (core->num, r_str_word_get0 (ptr, 1));
	case 1: // get fcnaddr
		fcnaddr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
	}
	fcn = r_anal_get_fcn_in (core->anal, fcnaddr, 0);
	if (fcn) {
		int ret = r_anal_fcn_add_bb (core->anal, fcn, addr,
					size, jump, fail, type, diff);
		if (!ret) {
			eprintf ("Cannot add basic block\n");
		}
	} else {
		eprintf ("Cannot find function at 0x%" PFMT64x "\n", fcnaddr);
	}
	r_anal_diff_free (diff);
	free (ptr);
	return true;
}

static void r_core_anal_nofunclist  (RCore *core, const char *input) {
	int minlen = (int)(input[0]==' ') ? r_num_math (core->num, input + 1): 16;
	ut64 code_size = r_num_get (core->num, "$SS");
	ut64 base_addr = r_num_get (core->num, "$S");
	ut64 chunk_size, chunk_offset, i;
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	RAnalBlock *b;
	char* bitmap;
	int counter;

	if (minlen < 1) minlen=1;
	if (code_size < 1) return;
	bitmap = calloc (1, code_size+64);
	if (!bitmap) return;

	// for each function
	r_list_foreach (core->anal->fcns, iter, fcn) {
		// for each basic block in the function
		r_list_foreach (fcn->bbs, iter2, b) {
			// if it is not withing range, continue
			if ((fcn->addr < base_addr) || (fcn->addr >= base_addr+code_size))
				continue;
			// otherwise mark each byte in the BB in the bitmap
			for (counter = 0; counter < b->size; counter++) {
				bitmap[b->addr+counter-base_addr] = '=';
			}
			// finally, add a special marker to show the beginning of a
			// function
			bitmap[fcn->addr-base_addr] = 'F';
		}
	}

	// Now we print the list of memory regions that are not assigned to a function
	chunk_size = 0;
	chunk_offset = 0;
	for (i = 0; i < code_size; i++) {
		if (bitmap[i]){
			// We only print a region is its size is bigger than 15 bytes
			if (chunk_size >= minlen){
				fcn = r_anal_get_fcn_in (core->anal, base_addr+chunk_offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
				if (fcn) {
					r_cons_printf ("0x%08"PFMT64x"  %6d   %s\n", base_addr+chunk_offset, chunk_size, fcn->name);
				} else {
					r_cons_printf ("0x%08"PFMT64x"  %6d\n", base_addr+chunk_offset, chunk_size);
				}
			}
			chunk_size = 0;
			chunk_offset = i+1;
			continue;
		}
		chunk_size+=1;
	}
	if (chunk_size >= 16) {
		fcn = r_anal_get_fcn_in (core->anal, base_addr+chunk_offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (fcn) {
			r_cons_printf ("0x%08"PFMT64x"  %6d   %s\n", base_addr+chunk_offset, chunk_size, fcn->name);
		} else {
			r_cons_printf ("0x%08"PFMT64x"  %6d\n", base_addr+chunk_offset, chunk_size);
		}
	}
	free(bitmap);
}

static void r_core_anal_fmap  (RCore *core, const char *input) {
	int show_color = r_config_get_i (core->config, "scr.color");
	int cols = r_config_get_i (core->config, "hex.cols") * 4;
	ut64 code_size = r_num_get (core->num, "$SS");
	ut64 base_addr = r_num_get (core->num, "$S");
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	RAnalBlock *b;
	char* bitmap;
	int assigned;
	ut64 i;

	if (code_size < 1) return;
	bitmap = calloc (1, code_size+64);
	if (!bitmap) return;

	// for each function
	r_list_foreach (core->anal->fcns, iter, fcn) {
		// for each basic block in the function
		r_list_foreach (fcn->bbs, iter2, b) {
			// if it is not within range, continue
			if ((fcn->addr < base_addr) || (fcn->addr >= base_addr+code_size))
				continue;
			// otherwise mark each byte in the BB in the bitmap
			int counter = 1;
			for (counter = 0; counter < b->size; counter++) {
				bitmap[b->addr+counter-base_addr] = '=';
			}
			bitmap[fcn->addr-base_addr] = 'F';
		}
	}
	// print the bitmap
	assigned = 0;
	for (i = 0; i < code_size; i += 1) {
		if (!(i % cols)) {
			r_cons_printf ("\n0x%08"PFMT64x"  ", base_addr+i);
		}
		if (bitmap[i]) assigned++;
		if (show_color) {
			if (bitmap[i])
				r_cons_printf ("%s%c\x1b[0m", Color_GREEN, bitmap[i]);
			else
				r_cons_printf (".");
		} else
			r_cons_printf ("%c", bitmap[i] ? bitmap[i] : '.' );
	}
	r_cons_printf ("\n%d / %d (%.2lf%%) bytes assigned to a function\n", assigned, code_size, 100.0*( (float) assigned) / code_size);
	free(bitmap);
}

static bool fcnNeedsPrefix(const char *name) {
	if (!strncmp (name, "entry", 5))
		return false;
	if (!strncmp (name, "main", 4))
		return false;
	return (!strchr (name, '.'));
}

/* TODO: move into r_anal_fcn_rename(); */
static bool setFunctionName(RCore *core, ut64 off, const char *name, bool prefix) {
	char *oname, *nname = NULL;
	RAnalFunction *fcn;
	if (!core || !name) {
		return false;
	}
	if (r_reg_get (core->anal->reg, name, -1)) {
		name = r_str_newf ("fcn.%s", name);
	}

	fcn = r_anal_get_fcn_in (core->anal, off,
				R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM | R_ANAL_FCN_TYPE_LOC);
	if (!fcn) return false;
	if (prefix && fcnNeedsPrefix (name)) {
		nname = r_str_newf ("fcn.%s", name);
	} else {
		nname = strdup (name);
	}
	oname = fcn->name;
	r_flag_rename (core->flags, r_flag_get (core->flags, fcn->name), nname);
	fcn->name = strdup (nname);
	if (core->anal->cb.on_fcn_rename) {
		core->anal->cb.on_fcn_rename (core->anal,
					core->anal->user, fcn, nname);
	}
	free (oname);
	free (nname);
	return true;
}

static int cmd_anal_fcn(RCore *core, const char *input) {
	switch (input[1]) {
	case 'f':
		r_anal_fcn_fit_overlaps (core->anal, NULL);
		break;
	case '-': // "af-"
		if (!input[2] || !strcmp (input + 2, "*")) {
			r_anal_fcn_del_locs (core->anal, UT64_MAX);
			r_anal_fcn_del (core->anal, UT64_MAX);
		} else {
			ut64 addr = input[2] ?
					r_num_math (core->num, input + 2) :
					core->offset;
			r_anal_fcn_del_locs (core->anal, addr);
			r_anal_fcn_del (core->anal, addr);
		}
		break;
	case 'u':
		{
		ut64 addr = core->offset;
		ut64 addr_end = r_num_math (core->num, input + 2);
		if (addr_end < addr) {
			eprintf ("Invalid address ranges\n");
		} else {
			int depth = 1;
			ut64 a, b;
			const char *c;
			a = r_config_get_i (core->config, "anal.from");
			b = r_config_get_i (core->config, "anal.to");
			c = r_config_get (core->config, "anal.limits");
			r_config_set_i (core->config, "anal.from", addr);
			r_config_set_i (core->config, "anal.to", addr_end);
			r_config_set (core->config, "anal.limits", "true");

			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) r_anal_fcn_resize (fcn, addr_end - addr);
			r_core_anal_fcn (core, addr, UT64_MAX,
					R_ANAL_REF_TYPE_NULL, depth);
			fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) r_anal_fcn_resize (fcn, addr_end - addr);

			r_config_set_i (core->config, "anal.from", a);
			r_config_set_i (core->config, "anal.to", b);
			r_config_set (core->config, "anal.limits", c? c: "");
		}
		}
		break;
	case '+':
		{
		char *ptr = strdup (input + 3);
		const char *ptr2;
		int n = r_str_word_set0 (ptr);
		const char *name = NULL;
		ut64 addr = -1LL;
		ut64 size = 0LL;
		RAnalDiff *diff = NULL;
		int type = R_ANAL_FCN_TYPE_FCN;
		if (n > 2) {
			switch (n) {
			case 5:
				ptr2 = r_str_word_get0 (ptr, 4);
				if (!(diff = r_anal_diff_new ())) {
					eprintf ("error: Cannot init RAnalDiff\n");
					free (ptr);
					return false;
				}
				if (ptr2[0] == 'm')
					diff->type = R_ANAL_DIFF_TYPE_MATCH;
				else if (ptr2[0] == 'u')
					diff->type = R_ANAL_DIFF_TYPE_UNMATCH;
			case 4:
				ptr2 = r_str_word_get0 (ptr, 3);
				if (strchr (ptr2, 'l'))
					type = R_ANAL_FCN_TYPE_LOC;
				else if (strchr (ptr2, 'i'))
					type = R_ANAL_FCN_TYPE_IMP;
				else if (strchr (ptr2, 's'))
					type = R_ANAL_FCN_TYPE_SYM;
				else type = R_ANAL_FCN_TYPE_FCN;
			case 3:
				name = r_str_word_get0 (ptr, 2);
			case 2:
				size = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			case 1:
				addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			}
			if (!r_anal_fcn_add (core->anal, addr, size, name, type, diff))
				eprintf ("Cannot add function (duplicated)\n");
		}
		r_anal_diff_free (diff);
		free (ptr);
		}
		break;
	case 'o': // "afo"
		{
		RAnalFunction *fcn;
		ut64 addr = core->offset;
		if (input[2] == ' ')
			addr = r_num_math (core->num, input + 3);
		if (addr == 0LL) {
			fcn = r_anal_fcn_find_name (core->anal, input + 3);
		} else {
			fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
		}
		if (fcn) r_cons_printf ("0x%08" PFMT64x "\n", fcn->addr);
		}
		break;
	case 'i': // "afi"
		switch (input[2]) {
		case '?':
        	eprintf ("Usage: afi[jl*] <addr>\n"); break;
        	eprintf ("afij - function info in json format\n");
			eprintf ("afil - verbose function info\n");
        	eprintf ("afi* - function, variables and arguments\n");
		case 'j':   // "afij"
        case 'l':   // "afil"
        case '*':   // "afi*"
        	r_core_anal_fcn_list (core, input + 3, input[2]);
        	break;
		default:
        	r_core_anal_fcn_list (core, input + 2, 1);
        	break;
		}
		break;
	case 'l': // "afl"
		switch (input[2]) {
		case '?':
			eprintf ("Usage: afl[jlqs*]\n");
			eprintf ("List all functions in quiet, commands or json format\n");
			eprintf ("afl  - list functions\n");
			eprintf ("aflj - list functions in json format\n");
			eprintf ("afll - list functions in verbose mode\n");
			eprintf ("aflq - list functions in 'quiet' mode\n");
			eprintf ("afls - print sum of sizes of all functions\n");
			break;
		case 'j':
		case 'l':
		case 'q':
		case 's':
		case '*':
			r_core_anal_fcn_list (core, NULL, input[2]);
			break;
		default:
			r_core_anal_fcn_list (core, NULL, 'o');
			break;
		}
		break;
	case 's':
		{ // "afs"
		ut64 addr;
		RAnalFunction *f;
		const char *arg = input + 3;
		if (input[2] && (addr = r_num_math (core->num, arg))) {
			arg = strchr (arg, ' ');
			if (arg) arg++;
		} else addr = core->offset;
		if ((f = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL))) {
			if (arg && *arg) {
				r_anal_str_to_fcn (core->anal, f, arg);
			} else {
				char *str = r_anal_fcn_to_string (core->anal, f);
				r_cons_printf ("%s\n", str);
				free (str);
			}
		} else {
			eprintf ("No function defined at 0x%08" PFMT64x "\n", addr);
		}
		}
		break;
	case 'm': // "afm" - merge two functions
		r_core_anal_fcn_merge (core, core->offset, r_num_math (core->num, input + 2));
		break;
	case 'M': // "afM" - print functions map
		r_core_anal_fmap (core, input + 1);
		break;
	case 'a': // "afa"
	case 'v': // "afv"
	case 'e': // "afe"
		var_cmd (core, input + 1);
		break;
	case 'c': // "afc"
		{
		RAnalFunction *fcn;
		if ((fcn = r_anal_get_fcn_in (core->anal, core->offset, 0)) != NULL) {
			r_cons_printf ("%i\n", r_anal_fcn_cc (fcn));
		} else  {
			eprintf ("Error: Cannot find function at 0x08%" PFMT64x "\n", core->offset);
		}
		}
		break;
	case 'C':{ // "afC"
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
		if (!fcn && !(input[2] == '?'|| input[2] == 'l')) {
			eprintf ("Cant find function here\n");
			break;
		}
		const char *help_afC[] = {
			"Usage:", "afC[agl?]", "",
			"afC", " convention", "Manually set calling convention for current function",
			"afC", "", "Show Calling convention for the Current function",
			"afCa", "", "Analyse function argument for the current calling convention",
			"afCl", "", "List all available calling conventions",
			"afCg", "", "Guess calling convention of function at current offset",
			NULL };
		switch (input[2]) {
		case'?': {
			r_core_cmd_help (core, help_afC);
			} break;
		case 'l':{ //afCl list all function Calling conventions.
			r_cons_printf ("%s\n", r_anal_cc_type2str (R_ANAL_CC_TYPE_CDECL));
			r_cons_printf ("%s\n", r_anal_cc_type2str (R_ANAL_CC_TYPE_STDCALL));
			r_cons_printf ("%s\n", r_anal_cc_type2str (R_ANAL_CC_TYPE_FASTCALL));
			//THOSE are the only implemented ones
			//should I test for null ... no ;)
			} break;
		case 'g': {
			//TODO guess calling conventions
			eprintf ("TODO\n") ;
			} break;
		case 'a': {
			r_anal_var_delete_all (core->anal, fcn->addr, 'e');
			r_anal_var_delete_all (core->anal, fcn->addr, 'a');
			r_anal_var_delete_all (core->anal, fcn->addr, 'v');
			fcn_callconv (core, fcn);
			} break;
		case ' ': {
			int type = r_anal_cc_str2type (input + 3);
			if (type == -1) {
				eprintf ("Unknown calling convention '%s'\n"
					"See afCl for available types\n", input + 3);
			} else {
				fcn->call = type;
			}
			}break;
		case 0:{
			const char *str = r_anal_cc_type2str (fcn->call);
			r_cons_printf ("%s\n", str);
		       }break;
		default:
			eprintf("See afC?\n");
		}
		}break;
	case 'B': // "afB" // set function bits
		if (input[2] == ' ') {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset,
								R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
			if (fcn)
				fcn->bits = atoi (input + 3);
			else eprintf ("Cannot find function to set bits\n");
		} else {
			eprintf ("Usage: afB [bits]\n");
		}
		break;
	case 'b': // "afb"
		switch (input[2]) {
		case '-':
			anal_fcn_del_bb (core, input +3);
			break;
		case 0:
		case ' ':
		case 'q':
		case 'r':
		case '*':
		case 'j':
			anal_fcn_list_bb (core, input + 2);
			break;
		case '+': // "afb+"
			anal_fcn_add_bb (core, input + 3);
			break;
		default:
		case '?':
			/* TODO: use r_core_help */
			eprintf ("Usage: afb+ or afbb or afb\n"
				/* TODO: move afbr into afr? */
				" afbr        - show addresses of instructions which leave the function\n"
				" .afbr*      - set breakpoint on every return address of the fcn\n"
				" .afbr-*     - undo the above operation\n"
				" afbj        - show basic blocks information in JSON\n"
				" afB [bits]  - define asm.bits for given function\n"
				" afb [addr]  - list basic blocks of function (see afbq, afbj, afb*)\n"
				" afb+ fcn_at bbat bbsz [jump] [fail] ([type] ([diff]))  add bb to function @ fcnaddr\n");
			break;
		}
		break;
	case 'n': // "afn"
		switch (input[2]) {
		case '?':
			eprintf ("Usage: afn[sa] - analyze function names\n");
			eprintf (" afna       - construct a function name for the current offset\n");
			eprintf (" afns       - list all strings associated with the current function\n");
			eprintf (" afn [name] - rename function\n");
			break;
		case 's':
			free (r_core_anal_fcn_autoname (core, core->offset, 1));
			break;
		case 'a':
			{
			char *name = r_core_anal_fcn_autoname (core, core->offset, 0);
			if (name) {
				r_cons_printf ("afn %s 0x%08" PFMT64x "\n", name, core->offset);
				free (name);
			}
			}
			break;
		default:
			{
			ut64 off = core->offset;
			char *p, *name = strdup (input + 3);
			if ((p = strchr (name, ' '))) {
				*p++ = 0;
				off = r_num_math (core->num, p);
			}
			if (*name) {
				if (!setFunctionName (core, off, name, false)) {
					eprintf ("Cannot find function '%s' at 0x%08" PFMT64x "\n", name, off);
				}
				free (name);
			} else {
				eprintf ("Usage: afn newname [off]   # set new name to given function\n");
				free (name);
			}
			}
			break;
		}
		break;
#if 0
	/* this is undocumented and probably have no uses. plz discuss */
	case 'e': // "afe"
		{
		RAnalFunction *fcn;
		ut64 off = core->offset;
		char *p, *name = strdup ((input[2]&&input[3])? input + 3: "");
		if ((p = strchr (name, ' '))) {
			*p = 0;
			off = r_num_math (core->num, p + 1);
		}
		fcn = r_anal_get_fcn_in (core->anal, off, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (fcn) {
			RAnalBlock *b;
			RListIter *iter;
			RAnalRef *r;
			r_list_foreach (fcn->refs, iter, r) {
				r_cons_printf ("0x%08" PFMT64x " -%c 0x%08" PFMT64x "\n", r->at, r->type, r->addr);
			}
			r_list_foreach (fcn->bbs, iter, b) {
				int ok = 0;
				if (b->type == R_ANAL_BB_TYPE_LAST) ok = 1;
				if (b->type == R_ANAL_BB_TYPE_FOOT) ok = 1;
				if (b->jump == UT64_MAX && b->fail == UT64_MAX) ok = 1;
				if (ok) {
					r_cons_printf ("0x%08" PFMT64x " -r\n", b->addr);
					// TODO: check if destination is outside the function boundaries
				}
			}
		} else eprintf ("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
		free (name);
		}
		break;
#endif
	case 'x':
		switch (input[2]) {
		case '\0':
		case ' ':
#if FCN_OLD
			// TODO: sdbize!
			// list xrefs from current address
			{
				ut64 addr = input[2]? r_num_math (core->num, input + 2): core->offset;
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, R_ANAL_FCN_TYPE_NULL);
				if (fcn) {
					RAnalRef *ref;
					RListIter *iter;
					r_list_foreach (fcn->refs, iter, ref) {
						r_cons_printf ("%c 0x%08" PFMT64x " -> 0x%08" PFMT64x "\n",
							ref->type, ref->at, ref->addr);
					}
				} else eprintf ("Cannot find function\n");
			}
#else
#warning TODO_ FCNOLD sdbize xrefs here
			eprintf ("TODO\n");
#endif
			break;
		case 'c': // add meta xref
		case 'd':
		case 's':
		case 'C':
			{
			char *p;
			ut64 a, b;
			RAnalFunction *fcn;
			char *mi = strdup (input);
			if (mi && mi[3] == ' ' && (p = strchr (mi + 4, ' '))) {
				*p = 0;
				a = r_num_math (core->num, mi + 3);
				b = r_num_math (core->num, p + 1);
				fcn = r_anal_get_fcn_in (core->anal, a, R_ANAL_FCN_TYPE_ROOT);
				if (fcn) {
					r_anal_fcn_xref_add (core->anal, fcn, a, b, input[2]);
				} else eprintf ("Cannot add reference to non-function\n");
			} else eprintf ("Usage: afx[cCd?] [src] [dst]\n");
			free (mi);
			}
			break;
		case '-':
			{
			char *p;
			ut64 a, b;
			RAnalFunction *fcn;
			char *mi = strdup (input + 2);
			if (mi && *mi == ' ' && (p = strchr (mi + 1, ' '))) {
				*p = 0;
				a = r_num_math (core->num, mi);
				b = r_num_math (core->num, p + 1);
				fcn = r_anal_get_fcn_in (core->anal, a, R_ANAL_FCN_TYPE_ROOT);
				if (fcn) {
					r_anal_fcn_xref_del (core->anal, fcn, a, b, -1);
				} else eprintf ("Cannot del reference to non-function\n");
			} else {
				eprintf ("Usage: afx- [src] [dst]\n");
			}
			free (mi);
			}
			break;
		default:
		case '?':
			{
			const char *help_msg[] = {
				"Usage:", "afx[-cCd?] [src] [dst]", "# manage function references (see also ar?)",
				"afxc", " sym.main+0x38 sym.printf", "add code ref",
				"afxC", " sym.main sym.puts", "add call ref",
				"afxd", " sym.main str.helloworld", "add data ref",
				"afx-", " sym.main str.helloworld", "remove reference",
				NULL };
			r_core_cmd_help (core, help_msg);
			}
			break;
		}
		break;
	case 'g': // "afg" - non-interactive VV
		r_core_visual_graph (core, NULL, NULL, false);
		break;
	case 'F': // "afF"
		{
		RAnalFunction *fcn;
		int val = input[2] && r_num_math (core->num, input + 2);
		fcn = r_anal_get_fcn_in (core->anal, core->offset, R_ANAL_FCN_TYPE_NULL);
		if (fcn) {
			fcn->folded = input[2]? val: !fcn->folded;
		}
		}
		break;
	case '?':
		{ // "af?"
		const char *help_msg[] = {
			"Usage:", "af", "",
			"af", " ([name]) ([addr])", "analyze functions (start at addr or $$)",
			"afr", " ([name]) ([addr])", "analyze functions recursively",
			"af+", " addr size name [type] [diff]", "hand craft a function (requires afb+)",
			"af-", " [addr]", "clean all function analysis data (or function at addr)",
			"af[aev]", "?", "manipulate args, registers and variables in function",
			"afb+", " fa a sz [j] [f] ([t]( [d]))", "add bb to function @ fcnaddr",
			"afb", " [addr]", "List basic blocks of given function",
			"afB", " 16", "set current function as thumb (change asm.bits)",
			"afc", "@[addr]", "calculate the Cyclomatic Complexity (starting at addr)",
			"afC[?]", " type @[addr]", "set calling convention for function",
			"aff", "", "re-adjust function boundaries to fit",
			"afF", "[1|0|]", "fold/unfold/toggle",
			"afg", "", "non-interactive ascii-art basic-block graph (See VV)",
			"afi", " [addr|fcn.name]", "show function(s) information (verbose afl)",
			"afl", "[l*] [fcn name]", "list functions (addr, size, bbs, name) (see afll)",
			"afo", " [fcn.name]", "show address for the function named like this",
			"afn", " name [addr]", "rename name for function at address (change flag too)",
			"afna", "", "suggest automatic name for current offset",
			"afs", " [addr] [fcnsign]", "get/set function signature at current address",
			"afx", "[cCd-] src dst", "add/remove code/Call/data/string reference",
			NULL };
		r_core_cmd_help (core, help_msg);
		}
		break;
	case 'r': // "afr" // analyze function recursively
	default: {
		char *uaddr = NULL, *name = NULL;
		int mybits = core->assembler->bits;
		int depth = r_config_get_i (core->config, "anal.depth");
		bool analyze_recursively = r_config_get_i (core->config, "anal.calls");
		RAnalFunction *fcn;
		ut64 addr = core->offset;
		if (input[1] == 'r') {
			input++;
			analyze_recursively = true;
		}

		// first undefine
		if (input[0] && input[1] == ' ') {
			name = strdup (input + 2);
			uaddr = strchr (name, ' ');
			if (uaddr) {
				*uaddr++ = 0;
				addr = r_num_math (core->num, uaddr);
			}
			// depth = 1; // or 1?
			// disable hasnext
		}

		bool swapbits = false;
		{
			if (mybits == 32) {
				const char *asmarch = r_config_get (core->config, "asm.arch");
				if (strstr (asmarch, "arm")) {
					RFlagItem *item = r_flag_get_i (core->flags, addr + 1);
					if (item) {
						r_config_set_i (core->config, "asm.bits", 16);
						swapbits = true;
					}
				}
			}
		}

		//r_core_anal_undefine (core, core->offset);
		r_core_anal_fcn (core, addr, UT64_MAX, R_ANAL_REF_TYPE_NULL, depth);
		if (swapbits) {
			fcn = r_anal_get_fcn_in (core->anal, addr, 0);
			if (fcn) {
				fcn->bits = core->assembler->bits;
			}
		}
		if (analyze_recursively) {
			fcn = r_anal_get_fcn_in (core->anal, addr, 0); /// XXX wrong in case of nopskip
			if (fcn) {
				RAnalRef *ref;
				RListIter *iter;
				RIOSection *sect = r_io_section_vget (core->io, fcn->addr);
				ut64 text_addr = 0x1000; // XXX use file baddr
				if (sect) {
					text_addr = sect->vaddr;
				}
				r_list_foreach (fcn->refs, iter, ref) {
					if (ref->addr == UT64_MAX || ref->addr < text_addr) {
						eprintf ("Warning: ignore call 0x%08"PFMT64x"\n", ref->addr);
						continue;
					}
					r_core_anal_fcn (core, ref->addr, fcn->addr, R_ANAL_REF_TYPE_CALL, depth);
					RAnalFunction *f = r_anal_get_fcn_at (core->anal, fcn->addr, 0);
					if (!f) {
						f = r_anal_get_fcn_in (core->anal, fcn->addr, 0);
						if (f) {
							/* cut function */
							r_anal_fcn_resize (f, addr - fcn->addr);
							r_core_anal_fcn (core, ref->addr, fcn->addr,
									R_ANAL_REF_TYPE_CALL, depth);
							f = r_anal_get_fcn_at (core->anal, fcn->addr, 0);
						}
						if (!f) {
							eprintf ("Cannot find function at 0x%08" PFMT64x "\n", fcn->addr);
						}
					}
				}
			}
		}

		if (mybits != core->assembler->bits) {
			r_config_set_i (core->config, "asm.bits", mybits);
		}
		if (name) {
			if (*name && !setFunctionName (core, addr, name, true))
				eprintf ("Cannot find function '%s' at 0x%08" PFMT64x "\n", name, addr);
			free (name);
		}
		flag_every_function (core);
	}
	}
	return true;
}

static void __anal_reg_list(RCore *core, int type, int size, char mode) {
	RReg *hack = core->dbg->reg;
	int bits = (size > 0)? size: core->anal->bits;
	;
	const char *use_color;
	int use_colors = r_config_get_i (core->config, "scr.color");
	if (use_colors) {
#undef ConsP
#define ConsP(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
		use_color = ConsP (creg)
		: Color_BWHITE;
	} else {
		use_color = NULL;
	}
	core->dbg->reg = core->anal->reg;

	/* workaround for thumb */
	if (core->anal->cur->arch && !strcmp (core->anal->cur->arch, "arm") && bits == 16) {
		bits = 32;
	}
	/* workaround for 6502 */
	if (core->anal->cur->arch && !strcmp (core->anal->cur->arch, "6502") && bits == 8) {
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, 16, mode, use_color); // XXX detect which one is current usage
	}
	if (mode == '=') {
		int pcbits = 0;
		const char *pcname = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
		RRegItem *reg = r_reg_get (core->anal->reg, pcname, 0);
		if (bits != reg->size) {
			pcbits = reg->size;
		}
		if (pcbits) {
			r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, pcbits, 2, use_color); // XXX detect which one is current usage
		}
	}
	r_debug_reg_list (core->dbg, type, bits, mode, use_color);
	core->dbg->reg = hack;
}

static void ar_show_help(RCore *core) {
	const char *help_message[] = {
		"Usage: ar", "", "# Analysis Registers",
		"ar", "", "Show 'gpr' registers",
		"ar0", "", "Reset register arenas to 0",
		"ara", "", "Manage register arenas",
		"ar", " 16", "Show 16 bit registers",
		"ar", " 32", "Show 32 bit registers",
		"ar", " all", "Show all bit registers",
		"ar", " <type>", "Show all registers of given type",
		"arC", "", "Display register profile comments",
		"arr", "", "Show register references (telescoping)",
		"ar=", "", "Show register values in columns",
		"ar?", " <reg>", "Show register value",
		"arb", " <type>", "Display hexdump of the given arena",
		"arc", " <name>", "Conditional flag registers",
		"ard", " <name>", "Show only different registers",
		"arn", " <regalias>", "Get regname for pc,sp,bp,a0-3,zf,cf,of,sg",
		"aro", "", "Show old (previous) register values",
		"arp", " <file>", "Load register profile from file",
		"ars", "", "Stack register state",
		"art", "", "List all register types",
		"arw", " <hexnum>", "Set contents of the register arena",
		".ar*", "", "Import register values as flags",
		".ar-", "", "Unflag all registers",
		NULL };
	r_core_cmd_help (core, help_message);
}

static void cmd_ara_help(RCore *core) {
	const char *help_msg[] = {
		"Usage:", "ara[+-s]", "Register Arena Push/Pop/Swap",
		"ara", "", "show all register arenas allocated",
		"ara", "+", "push a new register arena for each type",
		"ara", "-", "pop last register arena",
		"aras", "", "swap last two register arenas",
		NULL };
	r_core_cmd_help (core, help_msg);
}

static void cmd_arw_help (RCore *core) {
	const char *help_msg[] = {
		"Usage:", " arw ", "# Set contents of the register arena",
		"arw", " <hexnum>", "Set contents of the register arena",
		NULL };
	r_core_cmd_help (core, help_msg);
}

// XXX dup from drp :OOO
void cmd_anal_reg (RCore *core, const char *str) {
	int size = 0, i, type = R_REG_TYPE_GPR;
	int bits = (core->anal->bits & R_SYS_BITS_64)? 64: 32;
	int use_colors = r_config_get_i (core->config, "scr.color");
	struct r_reg_item_t *r;
	const char *use_color;
	const char *name;
	char *arg;

	if (use_colors) {
#define ConsP(x) (core->cons && core->cons->pal.x)? core->cons->pal.x
		use_color = ConsP (creg)
		: Color_BWHITE;
	} else {
		use_color = NULL;
	}
	switch (str[0]) {
	case 'l': // "arl"
	{
		RRegSet *rs = r_reg_regset_get (core->anal->reg, R_REG_TYPE_GPR);
		if (rs) {
			RRegItem *r;
			RListIter *iter;
			r_list_foreach (rs->regs, iter, r) {
				r_cons_printf ("%s\n", r->name);
			}
		}
	} break;
	case '0': // "ar0"
		r_reg_arena_zero (core->anal->reg);
		break;
	case 'C': // "arC"
		if (core->anal->reg->reg_profile_cmt) {
			r_cons_printf ("%s\n", core->anal->reg->reg_profile_cmt);
		}
		break;
	case 'w':
		switch (str[1]) {
		case '?': {
			cmd_arw_help (core);
			break;
		}
		case ' ':
			r_reg_arena_set_bytes (core->anal->reg, str + 1);
			break;
		default:
			cmd_arw_help (core);
			break;
		}
                break;
	case 'a': // "ara"
		switch (str[1]) {
		case '?':
			cmd_ara_help (core);
			break;
		case 's':
			r_reg_arena_swap (core->anal->reg, false);
			break;
		case '+':
			r_reg_arena_push (core->anal->reg);
			break;
		case '-':
			r_reg_arena_pop (core->anal->reg);
			break;
		default: {
			int i, j;
			RRegArena *a;
			RListIter *iter;
			for (i = 0; i < R_REG_TYPE_LAST; i++) {
				RRegSet *rs = &core->anal->reg->regset[i];
				j = 0;
				r_list_foreach (rs->pool, iter, a) {
					r_cons_printf ("%s %p %d %d %s %d\n",
						(a == rs->arena)? "*": ".", a,
						i, j, r_reg_get_type (i), a->size);
					j++;
				}
			}
		} break;
		}
		break;
	case '?':
		if (str[1]) {
			ut64 off = r_reg_getv (core->anal->reg, str + 1);
			r_cons_printf ("0x%08" PFMT64x "\n", off);
		} else ar_show_help (core);
		break;
	case 'r':
		r_core_debug_rr (core, core->anal->reg);
		break;
	case 'S': {
		int sz;
		ut8 *buf = r_reg_get_bytes (
			core->anal->reg, R_REG_TYPE_GPR, &sz);
		r_cons_printf ("%d\n", sz);
		free (buf);
	} break;
	case 'b': { // WORK IN PROGRESS // DEBUG COMMAND
		int len;
		ut8 *buf = r_reg_get_bytes (core->dbg->reg, R_REG_TYPE_GPR, &len);
		//r_print_hexdump (core->print, 0LL, buf, len, 16, 16);
		r_print_hexdump (core->print, 0LL, buf, len, 32, 4);
		free (buf);
	} break;
	case 'c':
		// TODO: set flag values with drc zf=1
		{
			RRegItem *r;
			const char *name = str + 1;
			while (*name == ' ') name++;
			if (*name && name[1]) {
				r = r_reg_cond_get (core->dbg->reg, name);
				if (r) {
					r_cons_printf ("%s\n", r->name);
				} else {
					int id = r_reg_cond_from_string (name);
					RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
					if (rf) {
						int o = r_reg_cond_bits (core->dbg->reg, id, rf);
						core->num->value = o;
						// ORLY?
						r_cons_printf ("%d\n", o);
						free (rf);
					} else eprintf ("unknown conditional or flag register\n");
				}
			} else {
				RRegFlags *rf = r_reg_cond_retrieve (core->dbg->reg, NULL);
				if (rf) {
					r_cons_printf ("| s:%d z:%d c:%d o:%d p:%d\n",
						rf->s, rf->z, rf->c, rf->o, rf->p);
					if (*name == '=') {
						for (i = 0; i < R_REG_COND_LAST; i++) {
							r_cons_printf ("%s:%d ",
								r_reg_cond_to_string (i),
								r_reg_cond_bits (core->dbg->reg, i, rf));
						}
						r_cons_newline ();
					} else {
						for (i = 0; i < R_REG_COND_LAST; i++) {
							r_cons_printf ("%d %s\n",
								r_reg_cond_bits (core->dbg->reg, i, rf),
								r_reg_cond_to_string (i));
						}
					}
					free (rf);
				}
			}
		}
		break;
	case 's': // "drs"
		switch (str[1]) {
		case '-':
			r_reg_arena_pop (core->dbg->reg);
			// restore debug registers if in debugger mode
			r_debug_reg_sync (core->dbg, 0, 1);
			break;
		case '+':
			r_reg_arena_push (core->dbg->reg);
			break;
		case '?': {
			const char *help_msg[] = {
				"Usage:", "drs", " # Register states commands",
				"drs", "", "List register stack",
				"drs+", "", "Push register state",
				"drs-", "", "Pop register state",
				NULL };
			r_core_cmd_help (core, help_msg);
		} break;
		default:
			r_cons_printf ("%d\n", r_list_length (
						core->dbg->reg->regset[0].pool));
			break;
		}
		break;
	case 'p': // arp
		// XXX we have to break out .h for these cmd_xxx files.
		cmd_reg_profile (core, 'a', str);
		break;
	case 't': // "drt"
		for (i = 0; (name = r_reg_get_type (i)); i++)
			r_cons_printf ("%s\n", name);
		break;
	case 'n': // "drn" // "arn"
		if (*(str + 1) == '\0') {
			eprintf ("Oops. try drn [PC|SP|BP|A0|A1|A2|A3|A4|R0|R1|ZF|SF|NF|OF]\n");
			break;
		}
		name = r_reg_get_name (core->dbg->reg, r_reg_get_name_idx (str + 2));
		if (name && *name)
			r_cons_printf ("%s\n", name);
		else eprintf ("Oops. try drn [PC|SP|BP|A0|A1|A2|A3|A4|R0|R1|ZF|SF|NF|OF]\n");
		break;
	case 'd':								// "drd"
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 3, use_color); // XXX detect which one is current usage
		break;
	case 'o': // "dro"
		r_reg_arena_swap (core->dbg->reg, false);
		r_debug_reg_list (core->dbg, R_REG_TYPE_GPR, bits, 0, use_color); // XXX detect which one is current usage
		r_reg_arena_swap (core->dbg->reg, false);
		break;
	case '=': // "dr="
		__anal_reg_list (core, type, size, 2);
		break;
	case '-':
	case '*':
	case 'j':
	case '\0':
		__anal_reg_list (core, type, size, str[0]);
		break;
	case ' ':
		arg = strchr (str + 1, '=');
		if (arg) {
			char *ostr, *regname;
			*arg = 0;
			ostr = r_str_chop (strdup (str + 1));
			regname = r_str_clean (ostr);
			r = r_reg_get (core->dbg->reg, regname, -1);
			if (!r) {
				int type = r_reg_get_name_idx (regname);
				if (type != -1) {
					const char *alias = r_reg_get_name (core->dbg->reg, type);
					r = r_reg_get (core->dbg->reg, alias, -1);
				}
			}
			if (r) {
				//eprintf ("%s 0x%08"PFMT64x" -> ", str,
				//	r_reg_get_value (core->dbg->reg, r));
				r_reg_set_value (core->dbg->reg, r,
						r_num_math (core->num, arg + 1));
				r_debug_reg_sync (core->dbg, -1, true);
				//eprintf ("0x%08"PFMT64x"\n",
				//	r_reg_get_value (core->dbg->reg, r));
			} else {
				eprintf ("ar: Unknown register '%s'\n", regname);
			}
			free (ostr);
			return;
		}
		size = atoi (str + 1);
		if (size == 0) {
			r = r_reg_get (core->dbg->reg, str + 1, -1);
			if (r) {
				r_cons_printf ("0x%08" PFMT64x "\n",
					r_reg_get_value (core->dbg->reg, r));
				return;
			}
			arg = strchr (str + 1, ' ');
			if (arg && size == 0) {
				*arg = '\0';
				size = atoi (arg);
			} else size = bits;
			type = r_reg_type_by_name (str + 1);
		}
		if (type != R_REG_TYPE_LAST) {
			__anal_reg_list (core, type, size, str[0]);
		} else eprintf ("cmd_debug_reg: Unknown type\n");
	}
}

static int esil_step(RCore *core, ut64 until_addr, const char *until_expr) {
	// Stepping
	int ret;
	ut8 code[256];
	RAnalOp op;
	RAnalEsil *esil = core->anal->esil;
	const char *name = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	ut64 addr = r_reg_getv (core->anal->reg, name);
repeat:
	if (r_cons_singleton ()->breaked) {
		eprintf ("[+] ESIL emulation interrupted at 0x%08" PFMT64x "\n", addr);
		return 0;
	}
	if (!esil) {
		int romem = r_config_get_i (core->config, "esil.romem");
		int stats = r_config_get_i (core->config, "esil.stats");
		int iotrap = r_config_get_i (core->config, "esil.iotrap");
		int exectrap = r_config_get_i (core->config, "esil.exectrap");
		int stacksize = r_config_get_i (core->config, "esil.stacksize");
		if (!(core->anal->esil = r_anal_esil_new (stacksize, iotrap)))
			return 0;
		esil = core->anal->esil;
		r_anal_esil_setup (esil, core->anal, romem, stats); // setup io
		esil->exectrap = exectrap;
		RList *entries = r_bin_get_entries (core->bin);
		RBinAddr *entry = NULL;
		RBinInfo *info = NULL;
		if (entries && !r_list_empty (entries)) {
			entry = (RBinAddr *)r_list_pop (entries);
			info = r_bin_get_info (core->bin);
			addr = info->has_va? entry->vaddr: entry->paddr;
			r_list_push (entries, entry);
		} else {
			addr = core->offset;
		}
		r_reg_setv (core->anal->reg, name, addr);
		// set memory read only
	} else {
		esil->trap = 0;
		addr = r_reg_getv (core->anal->reg, name);
		//eprintf ("PC=0x%"PFMT64x"\n", (ut64)addr);
	}
	if (r_anal_pin_call (core->anal, addr)) {
		eprintf ("esil pin called\n");
		return 1;
	}
	if (esil->exectrap) {
		if (!(r_io_section_get_rwx (core->io, addr) & R_IO_EXEC)) {
			esil->trap = R_ANAL_TRAP_EXEC_ERR;
			esil->trap_code = addr;
			eprintf ("[ESIL] Trap, trying to execute on non-executable memory\n");
			return 1;
		}
	}
	r_io_read_at (core->io, addr, code, sizeof (code));
	r_asm_set_pc (core->assembler, addr);
	ret = r_anal_op (core->anal, &op, addr, code, sizeof (code));
	if (op.size < 1) op.size = 1; // avoid inverted stepping
	r_reg_setv (core->anal->reg, name, addr + op.size);
	if (ret) {
		ut64 delay_slot = 0;
		r_anal_esil_reg_read (esil, "$ds", &delay_slot, NULL);
		if (delay_slot > 0) {
			if (op.type >= R_ANAL_OP_TYPE_JMP &&
			op.type <= R_ANAL_OP_TYPE_CRET) {
				// branches are illegal in a delay slot
				esil->trap = R_ANAL_TRAP_EXEC_ERR;
				esil->trap_code = addr;
				eprintf ("[ESIL] Trap, trying to execute a branch in a delay slot\n");
				return 1;
			}
		}

		r_anal_esil_set_pc (esil, addr);
		r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op.esil));
		if (core->anal->cur && core->anal->cur->esil_post_loop)
			core->anal->cur->esil_post_loop (esil, &op);
		r_anal_esil_dumpstack (esil);
		r_anal_esil_stack_free (esil);

		delay_slot--;

		if (((st64)delay_slot) <= 0) {
			// no delay slot, or just consumed
			ut64 jump_target_set = 0;
			r_anal_esil_reg_read (esil, "$js", &jump_target_set, NULL);
			if (jump_target_set) {
				// perform the branch
				ut64 jump_target = 0;
				r_anal_esil_reg_read (esil, "$jt", &jump_target, NULL);
				r_anal_esil_reg_write (esil, "$js", 0);
				r_reg_setv (core->anal->reg, name, jump_target);
			}
		}

		if (((st64)delay_slot) >= 0) {
			// save decreased delay slot counter
			r_anal_esil_reg_write (esil, "$ds", delay_slot);
			if (!esil->trap) {
				// emulate the instruction and its delay slots in the same 'aes' step
				goto repeat;
			}
		}
	}

	st64 follow = (st64)r_config_get_i (core->config, "dbg.follow");
	ut64 pc = r_debug_reg_get (core->dbg, "PC");
	if (follow > 0) {
		if ((pc < core->offset) || (pc > (core->offset + follow)))
			r_core_cmd0 (core, "sr PC");
	}

	if (core->dbg->trace->enabled) {
		RReg *reg = core->dbg->reg;
		core->dbg->reg = core->anal->reg;
		r_debug_trace_pc (core->dbg, pc);
		core->dbg->reg = reg;
	}
	// check addr
	if (until_addr != UT64_MAX) {
		if (r_reg_getv (core->anal->reg, name) == until_addr) {
			eprintf ("ADDR BREAK\n");
			return 0;
		} else goto repeat;
	}
	// check esil
	if (esil->trap) {
		eprintf ("TRAP\n");
		return 0;
	}
	if (until_expr) {
		if (r_anal_esil_condition (core->anal->esil, until_expr)) {
			eprintf ("ESIL BREAK!\n");
			return 0;
		} else goto repeat;
	}
	return 1;
}

static void cmd_address_info(RCore *core, const char *addrstr, int fmt) {
	ut64 addr, type;
	if (!addrstr || !*addrstr) {
		addr = core->offset;
	} else {
		addr = r_num_math (core->num, addrstr);
	}
	type = r_core_anal_address (core, addr);
	int isp = 0;
	switch (fmt) {
	case 'j':
#define COMMA isp++? ",": ""
		r_cons_printf ("{");
		if (type & R_ANAL_ADDR_TYPE_PROGRAM)
			r_cons_printf ("%s\"program\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_LIBRARY)
			r_cons_printf ("%s\"library\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_EXEC)
			r_cons_printf ("%s\"exec\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_READ)
			r_cons_printf ("%s\"read\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_WRITE)
			r_cons_printf ("%s\"write\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_FLAG)
			r_cons_printf ("%s\"flag\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_FUNC)
			r_cons_printf ("%s\"func\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_STACK)
			r_cons_printf ("%s\"stack\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_HEAP)
			r_cons_printf ("%s\"heap\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_REG)
			r_cons_printf ("%s\"reg\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_ASCII)
			r_cons_printf ("%s\"ascii\":true", COMMA);
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
			r_cons_printf ("%s\"sequence\":true", COMMA);
		r_cons_printf ("}");
		break;
	default:
		if (type & R_ANAL_ADDR_TYPE_PROGRAM)
			r_cons_printf ("program\n");
		if (type & R_ANAL_ADDR_TYPE_LIBRARY)
			r_cons_printf ("library\n");
		if (type & R_ANAL_ADDR_TYPE_EXEC)
			r_cons_printf ("exec\n");
		if (type & R_ANAL_ADDR_TYPE_READ)
			r_cons_printf ("read\n");
		if (type & R_ANAL_ADDR_TYPE_WRITE)
			r_cons_printf ("write\n");
		if (type & R_ANAL_ADDR_TYPE_FLAG)
			r_cons_printf ("flag\n");
		if (type & R_ANAL_ADDR_TYPE_FUNC)
			r_cons_printf ("func\n");
		if (type & R_ANAL_ADDR_TYPE_STACK)
			r_cons_printf ("stack\n");
		if (type & R_ANAL_ADDR_TYPE_HEAP)
			r_cons_printf ("heap\n");
		if (type & R_ANAL_ADDR_TYPE_REG)
			r_cons_printf ("reg\n");
		if (type & R_ANAL_ADDR_TYPE_ASCII)
			r_cons_printf ("ascii\n");
		if (type & R_ANAL_ADDR_TYPE_SEQUENCE)
			r_cons_printf ("sequence\n");
	}
}

static void cmd_anal_info(RCore *core, const char *input) {
	switch (input[0]) {
	case '?':
		eprintf ("Usage: ai @ rsp\n");
		break;
	case ' ':
		cmd_address_info (core, input, 0);
		break;
	case 'j': // "aij"
		cmd_address_info (core, input + 1, 'j');
		break;
	default:
		cmd_address_info (core, NULL, 0);
		break;
	}
}

static void cmd_esil_mem(RCore *core, const char *input) {
	ut64 curoff = core->offset;
	ut64 addr = 0x100000;
	ut32 size = 0xf0000;
	char name[128];
	RCoreFile *cf;
	RFlagItem *fi;
	const char *sp;
	char uri[32];
	char nomalloc[256];
	char *p;
	if (*input == '?') {
		eprintf ("Usage: [addr] [size] [name]\n");
		eprintf ("Default: 0x100000 0xf0000\n");
		return;
	}

	p = strncpy (nomalloc, input, 255);
	if ((p = strchr (p, ' '))) {
		while (*p == ' ') p++;
		addr = r_num_math (core->num, p);
		if ((p = strchr (p, ' '))) {
			while (*p == ' ') p++;
			size = (ut32)r_num_math (core->num, p);
			if (size < 1)
				size = 0xf0000;
			if ((p = strchr (p, ' '))) {
				while (*p == ' ') p++;
				snprintf (name, 128, "mem.%s", p);
			} else snprintf (name, 128, "mem.0x%" PFMT64x "_0x%x", addr, size);
		} else snprintf (name, 128, "mem.0x%" PFMT64x "_0x%x", addr, size);
	} else snprintf (name, 128, "mem.0x%" PFMT64x "_0x%x", addr, size);

	fi = r_flag_get (core->flags, name);
	if (fi) {
		if (*input == '-') {
			cf = r_core_file_get_by_fd (core, fi->offset);
			r_core_file_close (core, cf);
			r_flag_unset_name (core->flags, name);
			eprintf ("Deinitialized %s\n", name);
			return;
		}
		eprintf ("Cannot create mem here, mem allready lives here");
		return;
	}
	if (*input == '-') {
		eprintf ("Cannot deinitialize %s\n", name);
		return;
	}
	snprintf (uri, sizeof (uri), "malloc://%d", (int)size);
	cf = r_core_file_open (core, uri, R_IO_RW, addr);
	if (cf) r_flag_set (core->flags, name, addr, size);
	//r_core_cmdf (core, "f stack_fd=`on malloc://%d 0x%08"
	//	PFMT64x"`", stack_size, stack_addr);
	//r_core_cmdf (core, "f stack=0x%08"PFMT64x, stack_addr);
	//r_core_cmdf (core, "dr %s=0x%08"PFMT64x, sp, stack_ptr);
	// SP
	sp = r_reg_get_name (core->dbg->reg, R_REG_NAME_SP);
	r_debug_reg_set (core->dbg, sp, addr + (size / 2));
	// BP
	sp = r_reg_get_name (core->dbg->reg, R_REG_NAME_BP);
	r_debug_reg_set (core->dbg, sp, addr + (size / 2));
	//r_core_cmdf (core, "ar %s=0x%08"PFMT64x, sp, stack_ptr);
	//r_core_cmdf (core, "f %s=%s", sp, sp);
	if (!r_io_section_get_name (core->io, "esil_stack")) {
		r_core_cmdf (core, "S 0x%"PFMT64x" 0x%"PFMT64x" %d %d esil_stack", addr, addr, size, size);
	}
	r_core_seek (core, curoff, 0);
}

static ut64 opc = UT64_MAX;
static ut8 *regstate = NULL;

static void esil_init (RCore *core) {
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	opc = r_reg_getv (core->anal->reg, pc);
	if (!opc || opc==UT64_MAX) opc = core->offset;
	if (!core->anal->esil) {
		int iotrap = r_config_get_i (core->config, "esil.iotrap");
		int stacksize = r_config_get_i (core->config, "esil.stacksize");
		if (!(core->anal->esil = r_anal_esil_new (stacksize, iotrap))) {
			R_FREE (regstate);
			return;
		}
		r_anal_esil_setup (core->anal->esil, core->anal, 0, 0);
	}
	free (regstate);
	regstate = r_reg_arena_peek (core->anal->reg);
}

static void esil_fini(RCore *core) {
	const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	r_reg_arena_poke (core->anal->reg, regstate);
	r_reg_setv (core->anal->reg, pc, opc);
	R_FREE (regstate);
}

typedef struct {
	RList *regs;
	RList *regread;
	RList *regwrite;
} AeaStats;

static void aea_stats_init (AeaStats *stats) {
	stats->regs = r_list_newf (free);
	stats->regread = r_list_newf (free);
	stats->regwrite = r_list_newf (free);
}

static void aea_stats_fini (AeaStats *stats) {
	R_FREE (stats->regs);
	R_FREE (stats->regread);
	R_FREE (stats->regwrite);
}

static bool contains(RList *list, const char *name) {
	RListIter *iter;
	const char *n;
	r_list_foreach (list, iter, n) {
		if (!strcmp (name, n))
			return true;
	}
	return false;
}

static char *oldregread = NULL;

static int myregwrite(RAnalEsil *esil, const char *name, ut64 val) {
	AeaStats *stats = esil->user;
	if (oldregread && !strcmp (name, oldregread)) {
		r_list_pop (stats->regread);
		R_FREE (oldregread)
	}
	if (!IS_NUMBER (*name)) {
		if (!contains (stats->regs, name)) {
			r_list_push (stats->regs, strdup (name));
		}
		if (!contains (stats->regwrite, name)) {
			r_list_push (stats->regwrite, strdup (name));
		}
	}
	return 0;
}

static int myregread(RAnalEsil *esil, const char *name, ut64 *val, int *len) {
	AeaStats *stats = esil->user;
	if (!IS_NUMBER (*name)) {
		if (!contains (stats->regs, name)) {
			r_list_push (stats->regs, strdup (name));
		}
		if (!contains (stats->regread, name)) {
			r_list_push (stats->regread, strdup (name));
		}
	}
	return 0;
}

static void showregs (RList *list) {
	if (!r_list_empty (list)) {
		char *reg;
		RListIter *iter;
		r_list_foreach (list, iter, reg) {
			r_cons_printf ("%s", reg);
			if (iter->n) r_cons_printf (" ");
		}
		r_cons_newline();
	}
}

static bool cmd_aea(RCore* core, int mode, ut64 addr, int length) {
	RAnalEsil *esil;
	int ptr, ops, ops_end = 0, len, buf_sz, maxopsize;
	ut64 addr_end;
	AeaStats stats;
	const char *esilstr;
	RAnalOp aop = {0};
	ut8 *buf;
	if (!core)
		return false;
	maxopsize = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MAX_OP_SIZE);
	if (maxopsize < 1) {
		maxopsize = 16;
	}
	if (mode & 1) {
		// number of bytes / length
		buf_sz = length;
	} else {
		// number of instructions / opcodes
		ops_end = length;
		if (ops_end < 1) ops_end = 1;
		buf_sz = ops_end * maxopsize;
	}
	if (buf_sz < 1) {
		buf_sz = maxopsize;
	}
	addr_end = addr + buf_sz;
	buf = malloc (buf_sz);
	if (!buf) {
		return false;
	}
	(void)r_io_read_at (core->io, addr, (ut8 *)buf, buf_sz);
	aea_stats_init (&stats);

	esil_init (core);
	esil = core->anal->esil;
#	define hasNext(x) (x&1) ? (addr<addr_end) : (ops<ops_end)
	esil->user = &stats;
	esil->cb.hook_reg_write = myregwrite;
	esil->cb.hook_reg_read = myregread;
	esil->nowrite = true;
	for (ops = ptr = 0; ptr < buf_sz && hasNext (mode); ops++, ptr += len) {
		len = r_anal_op (core->anal, &aop, addr + ptr, buf + ptr, buf_sz - ptr);
		esilstr = R_STRBUF_SAFEGET (&aop.esil);
		if (len < 1) {
			eprintf ("Invalid 0x%08"PFMT64x" instruction %02x %02x\n",
				addr + ptr, buf[ptr], buf[ptr + 1]);
			break;
		}
		r_anal_esil_parse (esil, esilstr);
		r_anal_esil_stack_free (esil);
	}
	esil->nowrite = false;
	esil->cb.hook_reg_write = NULL;
	esil->cb.hook_reg_read = NULL;
	esil_fini (core);

	/* show registers used */
	if ((mode >> 1) & 1) {
		showregs (stats.regread);
	} else if ((mode >> 2) & 1) {
		showregs (stats.regwrite);
	} else if ((mode >> 3) & 1) {
		RListIter *iter;
		char *reg;
		r_list_foreach (stats.regs, iter, reg) {
			if (!contains (stats.regwrite, reg)) {
				r_cons_printf ("%s", reg);
				if (iter->n) r_cons_printf (" ");
			}
		}
		r_cons_newline();
	} else {
		r_cons_printf ("A: ");
		showregs (stats.regs);
		r_cons_printf ("R: ");
		showregs (stats.regread);
		r_cons_printf ("W: ");
		showregs (stats.regwrite);
		r_cons_printf ("N: ");
		{
			RListIter *iter;
			char *reg;
			r_list_foreach (stats.regs, iter, reg) {
				if (!contains (stats.regwrite, reg)) {
					r_cons_printf ("%s", reg);
					if (iter->n) r_cons_printf (" ");
				}
			}
			r_cons_newline();
		}
	}
	aea_stats_fini (&stats);
	free (buf);
	return true;
}

static void aea_help(RCore *core) {
	const char *help_msg[] = {
		"Examples:", "aea", " show regs used in a range",
		"aea", " [ops]", "Show regs used in N instructions",
		"aeaf", "", "Show regs used in current function",
		"aear", " [ops]", "Show regs read in N instructions",
		"aeaw", " [ops]", "Show regs written in N instructions",
		"aean", " [ops]", "Show regs not written in N instructions",
		"aeA", " [len]", "Show regs used in N bytes (subcommands are the same)",
		NULL };
	r_core_cmd_help (core, help_msg);
}

static void cmd_anal_esil(RCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "aep[-c] ", " [...]",
		"aepc", " [addr]", "change program counter for esil",
		"aep", "-[addr]", "remove pin",
		"aep", " [name] @ [addr]", "set pin",
		"aep", "", "list pins",
		NULL };
	RAnalEsil *esil = core->anal->esil;
	ut64 addr = core->offset;
	int stacksize = r_config_get_i (core->config, "esil.stacksize");
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	int romem = r_config_get_i (core->config, "esil.romem");
	int stats = r_config_get_i (core->config, "esil.stats");
	ut64 until_addr = UT64_MAX;
	const char *until_expr = NULL;
	RAnalOp *op;

	switch (input[0]) {
	case 'p': // "aep"
		switch (input[1]) {
		case 'c':
			if (input[2] == ' ') {
				// seek to this address
				r_core_cmd0 (core, "aei");  // init vm
				r_core_cmd0 (core, "aeim"); // init stack
				r_core_cmdf (core, "ar PC=%s", input + 3);
				r_core_cmd0 (core, ".ar*");
			} else {
				eprintf ("Missing argument\n");
			}
			break;
		case 0:
			r_anal_pin_list (core->anal);
			break;
		case '-':
			if (input[2])
				addr = r_num_math (core->num, input + 2);
			r_anal_pin_unset (core->anal, addr);
			break;
		case ' ':
			r_anal_pin (core->anal, addr, input + 2);
			break;
		default:
			r_core_cmd_help (core, help_msg);
			break;
		}
		break;
	case 'r':
		// 'aer' is an alias for 'ar'
		cmd_anal_reg (core, input + 1);
		break;
	case '*':
		// XXX: this is wip, not working atm
		if (core->anal->esil) {
			r_cons_printf ("trap: %d\n", core->anal->esil->trap);
			r_cons_printf ("trap-code: %d\n", core->anal->esil->trap_code);
		} else {
			eprintf ("esil vm not initialized. run `aei`\n");
		}
		break;
	case ' ':
		//r_anal_esil_eval (core->anal, input+1);
		if (!esil) {
			if (!(core->anal->esil = esil = r_anal_esil_new (stacksize, iotrap)))
				return;
		}
		r_anal_esil_setup (esil, core->anal, romem, stats); // setup io
		r_anal_esil_set_pc (esil, core->offset);
		r_anal_esil_parse (esil, input + 1);
		r_anal_esil_dumpstack (esil);
		r_anal_esil_stack_free (esil);
		break;
	case 's':
		// "aes" "aeso" "aesu" "aesue"
		// aes -> single step
		// aeso -> single step over
		// aesu -> until address
		// aesue -> until esil expression
		switch (input[1]) {
		case '?':
			eprintf ("See: ae?~aes\n");
			break;
		case 'l': // "aesl"
		{
			ut64 pc = r_debug_reg_get (core->dbg, "PC");
			RAnalOp *op = r_core_anal_op (core, pc);
			if (!op) break;
			esil_step (core, UT64_MAX, NULL);
			r_debug_reg_set (core->dbg, "PC", pc + op->size);
			r_anal_esil_set_pc (esil, pc + op->size);
			r_core_cmd0 (core, ".ar*");
		} break;
		case 'u': // "aesu"
			if (input[2] == 'e') {
				until_expr = input + 3;
			} else {
				until_addr = r_num_math (core->num, input + 2);
			}
			esil_step (core, until_addr, until_expr);
			r_core_cmd0 (core, ".ar*");
			break;
		case 'o': // "aeso"
			// step over
			op = r_core_anal_op (core, addr);
			if (op && op->type == R_ANAL_OP_TYPE_CALL) {
				until_addr = addr + op->size;
			}
			esil_step (core, until_addr, until_expr);
			r_anal_op_free (op);
			r_core_cmd0 (core, ".ar*");
			break;
		default:
			esil_step (core, until_addr, until_expr);
			r_core_cmd0 (core, ".ar*");
			break;
		}
		break;
	case 'c':
		if (input[1] == '?') { // "aec?"
			eprintf ("aecs         - continue until syscall\n");
			eprintf ("aec          - continue until exception\n");
			eprintf ("aecu [addr]  - continue until address\n");
			eprintf ("aecue [expr] - continue until esil expression\n");
		} else if (input[1] == 's') { // "aecs"
			const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
			ut64 newaddr;
			int ret;
			for (;;) {
				op = r_core_anal_op (core, addr);
				if (!op) break;
				if (op->type == R_ANAL_OP_TYPE_SWI) {
					eprintf ("syscall at 0x%08" PFMT64x "\n", addr);
					break;
				}
				if (op->type == R_ANAL_OP_TYPE_TRAP) {
					eprintf ("trap at 0x%08" PFMT64x "\n", addr);
					break;
				}
				ret = esil_step (core, UT64_MAX, NULL);
				r_anal_op_free (op);
				if (core->anal->esil->trap || core->anal->esil->trap_code) {
					break;
				}
				if (!ret)
					break;
				r_core_cmd0 (core, ".ar*");
				newaddr = r_num_get (core->num, pc);
				if (addr == newaddr) {
					addr++;
					break;
				} else {
					addr = newaddr;
				}
			}
		} else {
			// "aec"  -> continue until ^C
			// "aecu" -> until address
			// "aecue" -> until esil expression
			if (input[1] == 'u' && input[2] == 'e')
				until_expr = input + 3;
			else if (input[1] == 'u')
				until_addr = r_num_math (core->num, input + 2);
			else until_expr = "0";
			esil_step (core, until_addr, until_expr);
		}
		break;
	case 'i': // "aei"
		switch (input[1]) {
		case 's':
		case 'm': // "aeim"
			cmd_esil_mem (core, input + 2);
			break;
		case 'p': // initialize pc = $$
			r_core_cmd0 (core, "ar PC=$$");
			break;
		case '?':
			cmd_esil_mem (core, "?");
			break;
		case '-':
			if (esil) {
				sdb_reset (esil->stats);
			}
			r_anal_esil_free (esil);
			core->anal->esil = NULL;
			break;
		case 0:
			r_anal_esil_free (esil);
			// reinitialize
			{
				const char *pc = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
				if (r_reg_getv (core->anal->reg, pc) == 0LL) {
					r_core_cmd0 (core, "ar PC=$$");
				}
			}
			if (!(esil = core->anal->esil = r_anal_esil_new (stacksize, iotrap)))
				return;
			r_anal_esil_setup (esil, core->anal, romem, stats); // setup io
			esil->debug = (int)r_config_get_i (core->config, "esil.debug");
			/* restore user settings for interrupt handling */
			{
				const char *s = r_config_get (core->config, "cmd.esil.intr");
				if (s) {
					char *my = strdup (s);
					if (my)
						r_config_set (core->config, "cmd.esil.intr", my);
					free (my);
				}
			}
			break;
		}
		break;
	case 'k':
		switch (input[1]) {
		case '\0':
			input = "123*";
			/* fall through */
		case ' ':
			if (esil && esil->stats) {
				char *out = sdb_querys (esil->stats, NULL, 0, input + 2);
				if (out) {
					r_cons_printf ("%s\n", out);
					free (out);
				}
			} else eprintf ("esil.stats is empty. Run 'aei'\n");
			break;
		}
		break;
	case 'f': // "aef"
	{
		RListIter *iter;
		RAnalBlock *bb;
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal,
							core->offset, R_ANAL_FCN_TYPE_FCN | R_ANAL_FCN_TYPE_SYM);
		if (fcn) {
			// emulate every instruction in the function recursively across all the basic blocks
			r_list_foreach (fcn->bbs, iter, bb) {
				ut64 pc = bb->addr;
				ut64 end = bb->addr + bb->size;
				RAnalOp op;
				ut8 *buf;
				int ret, bbs = end - pc;
				if (bbs < 1 || bbs > 0xfffff) {
					eprintf ("Invalid block size\n");
				}
				eprintf ("Emulate basic block 0x%08" PFMT64x " - 0x%08" PFMT64x "\n", pc, end);
				buf = malloc (bbs + 1);
				r_io_read_at (core->io, pc, buf, bbs);
				int left;
				while (pc < end) {
					left = R_MIN (end - pc, 32);
					r_asm_set_pc (core->assembler, pc);
					ret = r_anal_op (core->anal, &op, addr, buf, left); // read overflow
					if (ret) {
						r_reg_setv (core->anal->reg, "PC", pc);
						r_anal_esil_parse (esil, R_STRBUF_SAFEGET (&op.esil));
						r_anal_esil_dumpstack (esil);
						r_anal_esil_stack_free (esil);
						pc += op.size;
					} else {
						pc += 4; // XXX
					}
				}
			}
		} else eprintf ("Cannot find function at 0x%08" PFMT64x "\n", core->offset);
	} break;
	case 't': // "aet"
		switch (input[1]) {
		case 'r': // "aetr"
		{
			// anal ESIL to REIL.
			RAnalEsil *esil = r_anal_esil_new (stacksize, iotrap);
			if (!esil)
				return;
			r_anal_esil_to_reil_setup (esil, core->anal, romem, stats);
			r_anal_esil_set_pc (esil, core->offset);
			r_anal_esil_parse (esil, input + 2);
			r_anal_esil_dumpstack (esil);
			r_anal_esil_free (esil);
			break;
		}
		default:
			eprintf ("Unknown command. Use `aetr`.\n");
			break;
		}
		break;
	case 'A': // "aeA"
		if (input[1] == '?') {
			aea_help (core);
		} else if (input[1] == 'r') {
			cmd_aea (core, 1 + (1<<1), core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'w') {
			cmd_aea (core, 1 + (1<<2), core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'n') {
			cmd_aea (core, 1 + (1<<3), core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'f') {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
			if (fcn) cmd_aea (core, 1, fcn->addr, r_anal_fcn_size (fcn));
		} else {
			cmd_aea (core, 1, core->offset, (int)r_num_math (core->num, input+2));
		}
		break;
	case 'a': // "aea"
		if (input[1] == '?') {
			aea_help (core);
		} else if (input[1] == 'r') {
			cmd_aea (core, 1<<1, core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'w') {
			cmd_aea (core, 1<<2, core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'n') {
			cmd_aea (core, 1<<3, core->offset, r_num_math (core->num, input+2));
		} else if (input[1] == 'f') {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
			if (fcn) cmd_aea (core, 1, fcn->addr, r_anal_fcn_size (fcn));
		} else {
			cmd_aea (core, 0, core->offset, r_num_math (core->num, input+2));
		}
		break;
	case 'x': { // "aex"
		ut32 new_bits = -1;
		int segoff, old_bits, pos = 0;
		char *new_arch = NULL, *old_arch = NULL, *hex = NULL;
		old_arch = strdup (r_config_get (core->config, "asm.arch"));
		old_bits = r_config_get_i (core->config, "asm.bits");
		segoff = r_config_get_i (core->config, "asm.segoff");

		if (input[0]) {
			for (pos = 1; pos < R_BIN_SIZEOF_STRINGS && input[pos]; pos++)
				if (input[pos] == ' ') break;
		}

		if (!r_core_process_input_pade (core, input+pos, &hex, &new_arch, &new_bits)) {
			// XXX - print help message
			//return false;
		}

		if (!new_arch) new_arch = strdup (old_arch);
		if (new_bits == -1) new_bits = old_bits;

		if (strcmp (new_arch, old_arch) || new_bits != old_bits) {
			r_core_set_asm_configs (core, new_arch, new_bits, segoff);
		}
		int ret, bufsz;
		RAnalOp aop = {0};
		bufsz = r_hex_str2bin (hex, (ut8*)hex);
		ret = r_anal_op (core->anal, &aop, core->offset,
			(const ut8*)hex, bufsz);
		if (ret>0) {
			const char *str = R_STRBUF_SAFEGET (&aop.esil);
			char *str2 = r_str_newf (" %s", str);
			cmd_anal_esil (core, str2);
			free (str2);
		}
		r_anal_op_fini (&aop);
		free (old_arch);
		}
		break;
	case '?':
		if (input[1] == '?') {
			const char *help_msg[] = {
				"Examples:", "ESIL", " examples and documentation",
				"+", "=", "A+=B => B,A,+=",
				"+", "", "A=A+B => B,A,+,A,=",
				"*", "=", "A*=B => B,A,*=",
				"/", "=", "A/=B => B,A,/=",
				"&", "=", "and ax, bx => bx,ax,&=",
				"|", "", "or r0, r1, r2 => r2,r1,|,r0,=",
				"^", "=", "xor ax, bx => bx,ax,^=",
				">>", "=", "shr ax, bx => bx,ax,>>=  # shift right",
				"<<", "=", "shr ax, bx => bx,ax,<<=  # shift left",
				"", "[]", "mov eax,[eax] => eax,[],eax,=",
				"=", "[]", "mov [eax+3], 1 => 1,3,eax,+,=[]",
				"=", "[1]", "mov byte[eax],1 => 1,eax,=[1]",
				"=", "[8]", "mov [rax],1 => 1,rax,=[8]",
				"$", "", "int 0x80 => 0x80,$",
				"$$", "", "simulate a hardware trap",
				"==", "", "pops twice, compare and update esil flags",
				"<", "", "compare for smaller",
				"<", "=", "compare for smaller or equal",
				">", "", "compare for bigger",
				">", "=", "compare bigger for or equal",
				"?{", "", "if popped value != 0 run the block until }",
				"POP", "", "drops last element in the esil stack",
				"TODO", "", "the instruction is not yet esilized",
				"STACK", "", "show contents of stack",
				"CLEAR", "", "clears the esil stack",
				"BREAK", "", "terminates the string parsing",
				"GOTO", "", "jump to the Nth word popped from the stack",
				NULL };
			r_core_cmd_help (core, help_msg);
			break;
		}
	/* fall through */
	default: {
		const char *help_msg[] = {
			"Usage:", "ae[idesr?] [arg]", "ESIL code emulation",
			"ae?", "", "show this help",
			"ae??", "", "show ESIL help",
			"aei", "", "initialize ESIL VM state (aei- to deinitialize)",
			"aeim", "", "initialize ESIL VM stack (aeim- remove)",
			"aeip", "", "initialize ESIL program counter to curseek",
			"ae", " [expr]", "evaluate ESIL expression",
			"aex", " [hex]", "evaluate opcode expression",
			"ae[aA]", "[f] [count]", "analyse esil accesses (regs, mem..)",
			"aep", " [addr]", "change esil PC to this address",
			"aef", " [addr]", "emulate function",
			"aek", " [query]", "perform sdb query on ESIL.info",
			"aek-", "", "resets the ESIL.info sdb instance",
			"aec", "", "continue until ^C",
			"aecs", " [sn]", "continue until syscall number",
			"aecu", " [addr]", "continue until address",
			"aecue", " [esil]", "continue until esil expression match",
			"aetr", "[esil]", "Convert an ESIL Expression to REIL",
			"aes", "", "perform emulated debugger step",
			"aeso", " ", "step over",
			"aesu", " [addr]", "step until given address",
			"aesue", " [esil]", "step until esil expression match",
			"aer", " [..]", "handle ESIL registers like 'ar' or 'dr' does",
			NULL };
		r_core_cmd_help (core, help_msg);
	} break;
	}
}

static void cmd_anal_noreturn(RCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "an [-][0xaddr|symname]", " manage no-return marks",
		"an[a]", " 0x3000", "stop function analysis if call/jmp to this address",
		"an[n]", " sym.imp.exit", "same as above but for flag/fcn names",
		"an", "-*", "remove all no-return references",
		"an", "", "list them all",
		NULL };
	switch (input[0]) {
	case '-':
		r_anal_noreturn_drop (core->anal, input + 1);
		break;
	case ' ':
		if (input[1] == '0' && input[2] == 'x') {
			r_anal_noreturn_add (core->anal, NULL,
					r_num_math (core->num, input + 1));
		} else {
			r_anal_noreturn_add (core->anal, input + 1,
					r_num_math (core->num, input + 1));
		}
		break;
	case 'a':
		if (input[1] == ' ') {
			r_anal_noreturn_add (core->anal, NULL,
					r_num_math (core->num, input + 1));
		} else r_core_cmd_help (core, help_msg);
		break;
	case 'n':
		if (input[1] == ' ') {
		} else r_core_cmd_help (core, help_msg);
		break;
	case '*':
	case 'r':
		r_anal_noreturn_list (core->anal, 1);
		break;
	case 0:
		r_anal_noreturn_list (core->anal, 0);
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	}
}

static void cmd_anal_opcode(RCore *core, const char *input) {
	int l, len = core->blocksize;
	ut32 tbs = core->blocksize;

	switch (input[0]) {
	case '?': {
		const char *help_msg[] = {
			"Usage:", "ao[e?] [len]", "Analyze Opcodes",
			"aoj", " N", "display opcode analysis information in JSON for N opcodes",
			"aoe", " N", "display esil form for N opcodes",
			"aor", " N", "display reil form for N opcodes",
			"aos", " [esil]", "show sdb representation of esil expression (TODO)",
			"ao", " 5", "display opcode analysis of 5 opcodes",
			"ao*", "", "display opcode in r commands",
			NULL };
		r_core_cmd_help (core, help_msg);
	} break;
	case 'j':
	case 'e':
	case 'r': {
		int count = 1;
		if (input[1] && input[2]) {
			l = (int)r_num_get (core->num, input + 1);
			if (l > 0) count = l;
			if (l > tbs) {
				r_core_block_size (core, l * 4);
				//len = l;
			}
		} else {
			len = l = core->blocksize;
			count = 1;
		}
		core_anal_bytes (core, core->block, len, count, input[0]);
	} break;
	case '*':
		r_core_anal_hint_list (core->anal, input[0]);
		break;
	default: {
		int count = 0;
		if (input[0]) {
			l = (int)r_num_get (core->num, input + 1);
			if (l > 0) count = l;
			if (l > tbs) {
				r_core_block_size (core, l * 4);
				//len = l;
			}
		} else {
			len = l = core->blocksize;
			count = 1;
		}
		core_anal_bytes (core, core->block, len, count, 0);
	}
	}
}

static void cmd_anal_jumps(RCore *core, const char *input) {
	r_core_cmdf (core, "af @@= `ax~ref.code.jmp[1]`");
}

static void cmd_anal_calls(RCore *core, const char *input) {
	int bufi, minop = 1; // 4
	ut8 *buf;
	RBinFile *binfile;
	RAnalOp op;
	ut64 addr, addr_end;
	int depth = r_config_get_i (core->config, "anal.depth");
	ut64 len = r_num_math (core->num, input);
	if (len > 0xffffff) {
		eprintf ("Too big\n");
		return;
	}
	binfile = r_core_bin_cur (core);
	if (!binfile) {
		eprintf ("cur binfile null\n");
		return;
	}
	addr = core->offset;
	if (!len) {
		// ignore search.in to avoid problems. analysis != search
		RIOSection *s = r_io_section_vget (core->io, addr);
		if (s && s->rwx & 1) {
			// search in current section
			if (s->size > binfile->size) {
				addr = s->vaddr;
				len = binfile->size - s->offset;
			} else {
				addr = s->vaddr;
				len = s->size;
			}
		} else {
			// search in full file
			ut64 o = r_io_section_vaddr_to_maddr (core->io, core->offset);
			if (o != UT64_MAX && binfile->size > o) {
				len = binfile->size - o;
			} else {
				if (binfile->size > core->offset) {
					len = binfile->size - core->offset;
				} else {
					eprintf ("Oops invalid range\n");
					len = 0;
				}
			}
		}
	}
	/*
		if (core->offset + len > binfile->size) {
			len = binfile->size - core->offset;
		}
		*/
	addr_end = addr + len;
	r_cons_break (NULL, NULL);
	buf = malloc (4096);
	if (!buf) return;
	bufi = 0;
	while (addr < addr_end) {
		if (core->cons->breaked)
			break;
		// TODO: too many ioreads here
		if (bufi > 4000) bufi = 0;
		if (!bufi) {
			r_io_read_at (core->io, addr, buf, 4096);
		}
		if (r_anal_op (core->anal, &op, addr, buf + bufi, 4096 - bufi)) {
			if (op.size < 1) op.size = minop; // XXX must be +4 on arm/mips/.. like we do in disasm.c
			if (op.type == R_ANAL_OP_TYPE_CALL) {
				r_core_anal_fcn (core, op.jump, addr,
						R_ANAL_REF_TYPE_NULL, depth);
			}
		} else {
			op.size = minop;
		}
		addr += (op.size > 0)? op.size: 1;
		bufi += (op.size > 0)? op.size: 1;
	}
	free (buf);
}

static void cmd_asf(RCore *core, const char *input) {
	char *ret;
	if (input[0] == ' ') {
		ret = sdb_querys (core->anal->sdb_fcnsign, NULL, 0, input + 1);
	} else {
		ret = sdb_querys (core->anal->sdb_fcnsign, NULL, 0, "*");
	}
	if (ret && *ret)
		r_cons_printf ("%s\n", ret);
	free (ret);
}

static void cmd_anal_syscall(RCore *core, const char *input) {
	RSyscallItem *si;
	RListIter *iter;
	RList *list;
	char *out;
	int n;
	const char *help_msg[] = {
		"Usage: as[ljk?]", "", "syscall name <-> number utility",
		"as", "", "show current syscall and arguments",
		"as", " 4", "show syscall 4 based on asm.os and current regs/mem",
		"asf", " [k[=[v]]]", "list/set/unset pf function signatures (see fcnsign)",
		"asj", "", "list of syscalls in JSON",
		"asl", "", "list of syscalls by asm.os and asm.arch",
		"asl", " close", "returns the syscall number for close",
		"asl", " 4", "returns the name of the syscall number 4",
		"ask", " [query]", "perform syscall/ queries",
		NULL };

	switch (input[0]) {
	case 'f': // "asf"
		cmd_asf (core, input + 1);
		break;
	case 'l': // "asl"
		if (input[1] == ' ') {
			if ((n = atoi (input + 2)) > 0) {
				si = r_syscall_get (core->anal->syscall, n, -1);
				if (si)
					r_cons_printf ("%s\n", si->name);
				else eprintf ("Unknown syscall number\n");
			} else {
				n = r_syscall_get_num (core->anal->syscall, input + 2);
				if (n != -1)
					r_cons_printf ("%d\n", n);
				else eprintf ("Unknown syscall name\n");
			}
		} else {
			list = r_syscall_list (core->anal->syscall);
			r_list_foreach (list, iter, si) {
				r_cons_printf ("%s = 0x%02x.%d\n",
					si->name, si->swi, si->num);
			}
			r_list_free (list);
		}
		break;
	case 'j': // "asj"
		list = r_syscall_list (core->anal->syscall);
		r_cons_printf ("[");
		r_list_foreach (list, iter, si) {
			r_cons_printf ("{\"name\":\"%s\","
				"\"swi\":\"%d\",\"num\":\"%d\"}",
				si->name, si->swi, si->num);
			if (iter->n) r_cons_printf (",");
		}
		r_cons_printf ("]\n");
		r_list_free (list);
		// JSON support
		break;
	case '\0':
		cmd_syscall_do (core, -1); //n);
		break;
	case ' ':
		cmd_syscall_do (core, (int)r_num_get (core->num, input + 1));
		break;
	case 'k': // "ask"
		if (input[1] == ' ') {
			out = sdb_querys (core->anal->syscall->db, NULL, 0, input + 2);
			if (out) {
				r_cons_printf ("%s\n", out);
				free (out);
			}
		} else eprintf ("|ERROR| Usage: ask [query]\n");
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	}
}

static void anal_axg (RCore *core, const char *input, int level, Sdb *db) {
	char arg[32], pre[128];
	RList *xrefs;
	RListIter *iter;
	RAnalRef *ref;
	ut64 addr = core->offset;
	if (input && *input) {
		addr = r_num_math (core->num, input);
	}
	int spaces = (level+1) * 2;
	if (spaces > sizeof (pre)-4) {
		spaces = sizeof(pre)-4;
	}
	memset (pre, ' ', sizeof(pre));
	strcpy (pre+spaces, "- ");

	xrefs = r_anal_xrefs_get (core->anal, addr);
	if (!r_list_empty (xrefs)) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, addr, -1);
		if (fcn) {
			//if (sdb_add (db, fcn->name, "1", 0)) {
				r_cons_printf ("%s0x%08"PFMT64x" fcn 0x%08"PFMT64x" %s\n",
					pre+2, addr, fcn->addr, fcn->name);
			//}
		} else {
			//snprintf (arg, sizeof (arg), "0x%08"PFMT64x, addr);
			//if (sdb_add (db, arg, "1", 0)) {
				r_cons_printf ("%s0x%08"PFMT64x"\n", pre+2, addr);
			//}
		}
	}
	r_list_foreach (xrefs, iter, ref) {
		RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, ref->addr, -1);
		//assert (ref->at == addr);
		if (fcn) {
			r_cons_printf ("%s0x%08"PFMT64x" fcn 0x%08"PFMT64x" %s\n", pre, ref->addr, fcn->addr, fcn->name);
			if (sdb_add (db, fcn->name, "1", 0)) {
				snprintf (arg, sizeof (arg), "0x%08"PFMT64x, fcn->addr);
				anal_axg (core, arg, level+1, db);
			}
		} else {
			r_cons_printf ("%s0x%08"PFMT64x" ???\n", pre, ref->addr);
			snprintf (arg, sizeof (arg), "0x%08"PFMT64x, ref->addr);
			if (sdb_add (db, arg, "1", 0)) {
				anal_axg (core, arg, level +1, db);
			}
		}
	}
}

static bool cmd_anal_refs(RCore *core, const char *input) {
	ut64 addr = core->offset;
	const char *help_msg[] = {
		"Usage:", "ax[?d-l*]", " # see also 'afx?'",
		"ax", " addr [at]", "add code ref pointing to addr (from curseek)",
		"axc", " addr [at]", "add code jmp ref // unused?",
		"axC", " addr [at]", "add code call ref",
		"axg", " addr", "show xrefs graph to reach current function",
		"axd", " addr [at]", "add data ref",
		"axj", "", "list refs in json format",
		"axF", " [flg-glob]", "find data/code references of flags",
		"axt", " [addr]", "find data/code references to this address",
		"axf", " [addr]", "find data/code references from this address",
		"ax-", " [at]", "clean all refs (or refs from addr)",
		"ax", "", "list refs",
		"axk", " [query]", "perform sdb query",
		"ax*", "", "output radare commands",
		NULL };
	switch (input[0]) {
	case '-': { // "ax-"
		const char *inp;
		ut64 a, b;
		for (inp = input + 1; *inp && IS_WHITESPACE (*inp); inp++)
			;
		if (!strcmp (inp, "*")) {
			r_anal_xrefs_init (core->anal);
		} else {
			char *p = strdup (inp);
			char *q = strchr (p, ' ');
			a = r_num_math (core->num, p);
			if (q) {
				*q++ = 0;
				b = r_num_math (core->num, q);
			} else {
				//b = UT64_MAX;
				b = core->offset;
			}
			r_anal_ref_del (core->anal, b, a);
			free (p);
		}
	} break;
	case 'g': // "axg"
		{
			Sdb *db = sdb_new0();
			anal_axg (core, input+2, 0, db);
			sdb_free (db);
		}
		break;
	case 'k': // "axk"
		if (input[1] == ' ') {
			sdb_query (core->anal->sdb_xrefs, input + 2);
		} else eprintf ("|ERROR| Usage: axk [query]\n");
		break;
	case '\0':
	case 'j': // "axj"
	case '*': // "ax*"
		r_core_anal_ref_list (core, input[0]);
		break;
	case 't': { // "axt"
		const int size = 12;
		RList *list;
		RAnalRef *ref;
		RListIter *iter;
		ut8 buf[12];
		RAsmOp asmop;
		char *buf_asm = NULL;
		char *space = strchr (input, ' ');

		if (space) {
			addr = r_num_math (core->num, space + 1);
		} else {
			addr = core->offset;
		}
		list = r_anal_xrefs_get (core->anal, addr);
		if (list) {
			if (input[1] == 'q') { // "axtq"
				r_list_foreach (list, iter, ref)
					r_cons_printf ("0x%" PFMT64x "\n", ref->addr);
			} else if (input[1] == 'j') { // "axtj"
				r_cons_printf ("[");
				r_list_foreach (list, iter, ref) {
					r_core_read_at (core, ref->addr, buf, size);
					r_asm_set_pc (core->assembler, ref->addr);
					r_asm_disassemble (core->assembler, &asmop, buf, size);
					char str[512];
					r_parse_filter (core->parser, core->flags,
							asmop.buf_asm, str, sizeof (str), core->print->big_endian);
					r_cons_printf ("{\"from\":%" PFMT64u ",\"type\":\"%c\",\"opcode\":\"%s\"}%s",
						ref->addr, ref->type, str, iter->n? ",": "");
				}
				r_cons_printf ("]");
				r_cons_newline ();
			} else if (input[1] == '*') { // axt*
				// TODO: implement multi-line comments
				r_list_foreach (list, iter, ref)
					r_cons_printf ("CCa 0x%" PFMT64x " \"XREF type %d at 0x%" PFMT64x"%s\n",
						ref->addr, ref->type, addr, iter->n? ",": "");
			} else { // axt
				int has_color = core->print->flags & R_PRINT_FLAGS_COLOR;
				char str[512];
				RAnalFunction *fcn;
				char *buf_fcn;
				char *comment;
				r_list_foreach (list, iter, ref) {
					r_core_read_at (core, ref->addr, buf, size);
					r_asm_set_pc (core->assembler, ref->addr);
					r_asm_disassemble (core->assembler, &asmop, buf, size);
					r_parse_filter (core->parser, core->flags,
							asmop.buf_asm, str, sizeof (str), core->print->big_endian);
					fcn = r_anal_get_fcn_in (core->anal, ref->addr, 0);
					if (has_color) {
						buf_asm = r_print_colorize_opcode (str, core->cons->pal.reg,
										core->cons->pal.num);
					} else {
						buf_asm = r_str_new (str);
					}
					comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, ref->addr);
					if (comment) {
						buf_fcn = r_str_newf ("%s; %s", fcn ?
								     fcn->name : "unknown function",
								     strtok (comment, "\n"));
					} else {
						buf_fcn = r_str_newf ("%s", fcn ? fcn->name : "unknown function");
					}
					r_cons_printf ("%s 0x%" PFMT64x " %s in %s\n",
						r_anal_ref_to_string (core->anal, ref->type),
						ref->addr, buf_asm, buf_fcn);
					free (buf_asm);
					free (buf_fcn);
				}
			}
			r_list_free (list);
		}
	} break;
	case 'f': {
		ut8 buf[12];
		RAsmOp asmop;
		char *buf_asm = NULL;
		RList *list;
		RAnalRef *ref;
		RListIter *iter;
		char *space = strchr (input, ' ');

		if (space) {
			addr = r_num_math (core->num, space + 1);
		} else {
			addr = core->offset;
		}
		list = r_anal_xrefs_get_from (core->anal, addr);
		if (list) {
			if (input[1] == 'q') { // axfq
				r_list_foreach (list, iter, ref)
					r_cons_printf ("0x%" PFMT64x "\n", ref->at);
			} else if (input[1] == 'j') { // axfj
				r_cons_printf ("[");
				r_list_foreach (list, iter, ref) {
					r_core_read_at (core, ref->at, buf, 12);
					r_asm_set_pc (core->assembler, ref->at);
					r_asm_disassemble (core->assembler, &asmop, buf, 12);
					r_cons_printf ("{\"from\":0x%" PFMT64x ",\"type\":\"%c\",\"opcode\":\"%s\"}%s",
						ref->at, ref->type, asmop.buf_asm, iter->n? ",": "");
				}
				r_cons_printf ("]\n");
			} else if (input[1] == '*') { // axf*
				// TODO: implement multi-line comments
				r_list_foreach (list, iter, ref)
					r_cons_printf ("CCa 0x%" PFMT64x " \"XREF from 0x%" PFMT64x "\n",
						ref->at, ref->type, asmop.buf_asm, iter->n? ",": "");
			} else { // axf
				char str[512];
				r_list_foreach (list, iter, ref) {
					r_core_read_at (core, ref->at, buf, 12);
					r_asm_set_pc (core->assembler, ref->at);
					r_asm_disassemble (core->assembler, &asmop, buf, 12);
					r_parse_filter (core->parser, core->flags,
							asmop.buf_asm, str, sizeof (str), core->print->big_endian);
					buf_asm = r_print_colorize_opcode (str, core->cons->pal.reg,
									core->cons->pal.num);
					r_cons_printf ("%c 0x%" PFMT64x " %s\n",
						ref->type, ref->at, buf_asm);
					free (buf_asm);
				}
			}
			r_list_free (list);
		}
	} break;
	case 'F':
		find_refs (core, input + 1);
		break;
	case 'C': // "axC"
	case 'c': // "axc"
	case 'd': // "axd"
	case ' ': {
		char *ptr = strdup (r_str_trim_head ((char *)input + 1));
		int n = r_str_word_set0 (ptr);
		ut64 at = core->offset;
		ut64 addr = UT64_MAX;
		switch (n) {
		case 2: // get at
			at = r_num_math (core->num, r_str_word_get0 (ptr, 1));
			/* fall through */
		case 1: // get addr
			addr = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			break;
		default:
			free (ptr);
			return false;
		}
		r_anal_ref_add (core->anal, addr, at, input[0]);
		free (ptr);
	} break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	}

	return true;
}
/*
	in core/disasm we call
	R_API int r_core_hint(RCore *core, ut64 addr) {
		static int hint_bits = 0;
		RAnalHint *hint = r_anal_hint_get (core->anal, addr);
		if (hint->bits) {
			if (!hint_bits)
			hint_bits = core->assembler->bits;
			r_config_set_i (core->config, "asm.bits", hint->bits);
		} else if (hint_bits) {
			r_config_set_i (core->config, "asm.bits", hint_bits);
			hint_bits = 0;
		}
		if (hint->arch)
			r_config_set (core->config, "asm.arch", hint->arch);
		if (hint->length)
			force_instruction_length = hint->length;
		r_anal_hint_free (hint);
	}
	*/

static void cmd_anal_hint(RCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "ah[lba-]", "Analysis Hints",
		"ah?", "", "show this help",
		"ah?", " offset", "show hint of given offset",
		"ah", "", "list hints in human-readable format",
		"ah.", "", "list hints in human-readable format from current offset",
		"ah-", "", "remove all hints",
		"ah-", " offset [size]", "remove hints at given offset",
		"ah*", " offset", "list hints in radare commands format",
		"aha", " ppc 51", "set arch for a range of N bytes",
		"ahb", " 16 @ $$", "force 16bit for current instruction",
		"ahc", " 0x804804", "override call/jump address",
		"ahf", " 0x804840", "override fallback address for call",
		"ahi", " 10", "define numeric base for immediates (1, 8, 10, 16, s)",
		"ahs", " 4", "set opcode size=4",
		"ahS", " jz", "set asm.syntax=jz for this opcode",
		"aho", " foo a0,33", "replace opcode string",
		"ahe", " eax+=3", "set vm analysis string",
		NULL };
	switch (input[0]) {
	case '?':
		if (input[1]) {
			ut64 addr = r_num_math (core->num, input+1);
			r_core_anal_hint_print (core->anal, addr);
		} else r_core_cmd_help (core, help_msg);
		break;
	case '.': // ah.
		r_core_anal_hint_print(core->anal, core->offset);
		break;
	case 'a': // set arch
		if (input[1]) {
			int i;
			char *ptr = strdup (input + 2);
			i = r_str_word_set0 (ptr);
			if (i == 2)
				r_num_math (core->num, r_str_word_get0 (ptr, 1));
			r_anal_hint_set_arch (core->anal, core->offset,
					r_str_word_get0 (ptr, 0));
			free (ptr);
		} else eprintf ("Missing argument\n");
		break;
	case 'b': // set bits
		if (input[1]) {
			char *ptr = strdup (input + 2);
			int bits;
			int i = r_str_word_set0 (ptr);
			if (i == 2)
				r_num_math (core->num, r_str_word_get0 (ptr, 1));
			bits = r_num_math (core->num, r_str_word_get0 (ptr, 0));
			r_anal_hint_set_bits (core->anal, core->offset, bits);
			free (ptr);
		} else eprintf ("Missing argument\n");
		break;
	case 'i': // "ahi"
		if (input[1] == '?') {
			const char* help_msg[] = {
				"Usage", "ahi [sbodh] [@ offset]", " Define numeric base",
				"ahi", " [base]", "set numeric base (1, 2, 8, 10, 16)",
				"ahi", " b", "set base to binary (1)",
				"ahi", " d", "set base to decimal (10)",
				"ahi", " h", "set base to hexadecimal (16)",
				"ahi", " o", "set base to octal (8)",
				"ahi", " i", "set base to IP address (32)",
				"ahi", " S", "set base to syscall (80)",
				"ahi", " s", "set base to string (2)",
				NULL };
			r_core_cmd_help (core, help_msg);
		} else if (input[1] == ' ') {
		// You can either specify immbase with letters, or numbers
			const int base =
				(input[2] == 'b') ? 1 :
				(input[2] == 's') ? 2 :
				(input[2] == 'o') ? 8 :
				(input[2] == 'd') ? 10 :
				(input[2] == 'h') ? 16 :
				(input[2] == 'i') ? 32 : // ip address
				(input[2] == 'S') ? 80 : // syscall
				(int) r_num_math (core->num, input + 1);
			r_anal_hint_set_immbase (core->anal, core->offset, base);
		} else eprintf ("|ERROR| Usage: ahi [base]\n");
		break;
	case 'c':
		r_anal_hint_set_jump (core->anal, core->offset,
				r_num_math (core->num, input + 1));
		break;
	case 'f':
		r_anal_hint_set_fail (core->anal, core->offset,
				r_num_math (core->num, input + 1));
		break;
	case 's': // set size (opcode length)
		if (input[1]) {
			r_anal_hint_set_size (core->anal, core->offset, atoi (input + 1));
		} else eprintf ("Usage: ahs 16\n");
		break;
	case 'S': // set size (opcode length)
		if (input[1] == ' ') {
			r_anal_hint_set_syntax (core->anal, core->offset, input + 2);
		} else eprintf ("Usage: ahS att\n");
		break;
	case 'o': // set opcode string
		if (input[1] == ' ') {
			r_anal_hint_set_opcode (core->anal, core->offset, input + 2);
		} else eprintf ("Usage: aho popall\n");
		break;
	case 'e': // set ESIL string
		if (input[1] == ' ') {
			r_anal_hint_set_esil (core->anal, core->offset, input + 2);
		} else eprintf ("Usage: ahe r0,pc,=\n");
		break;
#if TODO
	case 'e': // set endian
		r_anal_hint_set_opcode (core->anal, core->offset, atoi (input + 1));
		break;
#endif
	case 'p':
		r_anal_hint_set_pointer (core->anal, core->offset, r_num_math (core->num, input + 1));
		break;
	case '*':
	case 'j':
	case '\0':
		r_core_anal_hint_list (core->anal, input[0]);
		break;
	case '-': // "ah-"
		if (input[1]) {
			if (input[1] == '*') {
				r_anal_hint_clear (core->anal);
			} else {
				char *ptr = strdup (input + 1);
				ut64 addr;
				int size = 1;
				int i = r_str_word_set0 (ptr);
				if (i == 2) {
					size = r_num_math (core->num, r_str_word_get0 (ptr, 1));
				}
				const char *a0 = r_str_word_get0 (ptr, 0);
				if (a0 && *a0) {
					addr = r_num_math (core->num, a0);
				} else {
					addr = core->offset;
				}
				r_anal_hint_del (core->anal, addr, size);
				free (ptr);
			}
		} else {
			r_anal_hint_clear (core->anal);
		}
		break;
	}
}

static void agraph_print_node_dot(RANode *n, void *user) {
	char *label = strdup (n->body);
	label = r_str_replace (label, "\n", "\\l", 1);
	if (!label || !*label) {
		free (label);
		label = strdup (n->title);
	}
	r_cons_printf ("\"%s\" [URL=\"%s\", color=\"lightgray\", label=\"%s\"]\n",
		n->title, n->title, label);
	free (label);
}

static void agraph_print_node(RANode *n, void *user) {
	char *encbody, *cmd;
	int len = strlen (n->body);

	if (n->body[len - 1] == '\n') len--;
	encbody = r_base64_encode_dyn (n->body, len);
	cmd = r_str_newf ("agn \"%s\" base64:%s\n", n->title, encbody);
	r_cons_printf (cmd);
	free (cmd);
	free (encbody);
}

static void agraph_print_edge_dot(RANode *from, RANode *to, void *user) {
	r_cons_printf ("\"%s\" -> \"%s\"\n", from->title, to->title);
}

static void agraph_print_edge(RANode *from, RANode *to, void *user) {
	r_cons_printf ("age \"%s\" \"%s\"\n", from->title, to->title);
}

static void cmd_agraph_node(RCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "agn [title] [body]", "",
		"Examples:", "", "",
		"agn", " title1 body1", "Add a node with title \"title1\" and body \"body1\"",
		"agn", " \"title with space\" \"body with space\"", "Add a node with spaces in the title and in the body",
		"agn", " title1 base64:Ym9keTE=", "Add a node with the body specified as base64",
		"agn-", " title1", "Remove a node with title \"title1\"",
		"agn?", "", "Show this help",
		NULL };

	switch (*input) {
	case ' ': {
		char *newbody = NULL;
		char **args, *body;
		int n_args, B_LEN = strlen ("base64:");

		input++;
		args = r_str_argv (input, &n_args);
		if (n_args < 1 || n_args > 2) {
			r_cons_printf ("Wrong arguments\n");
			r_str_argv_free (args);
			break;
		}
		//strdup cause there is double free in r_str_argv_free due to a realloc call
		if (n_args > 1) {
			body = strdup (args[1]);
			if (strncmp (body, "base64:", B_LEN) == 0) {
				body = r_str_replace (body, "\\n", "", true);
				newbody = (char *)r_base64_decode_dyn (body + B_LEN, -1);
				free (body);
				if (!newbody) {
					eprintf ("Not enough space to allocate %s at %d\n", __FILE__, __LINE__);
					r_str_argv_free (args);
					break;
				}
				body = newbody;
			}
			body = r_str_concat (body, "\n");
		} else {
			body = strdup ("");
		}
		r_agraph_add_node (core->graph, args[0], body);
		r_str_argv_free (args);
		free (body);
		//free newbody it's not necessary since r_str_concat reallocate the space
		break;
	}
	case '-': {
		char **args;
		int n_args;

		input++;
		args = r_str_argv (input, &n_args);
		if (n_args != 1) {
			r_cons_printf ("Wrong arguments\n");
			r_str_argv_free (args);
			break;
		}
		r_agraph_del_node (core->graph, args[0]);
		r_str_argv_free (args);
		break;
	}
	case '?':
	default:
		r_core_cmd_help (core, help_msg);
		break;
	}
}

static void cmd_agraph_edge(RCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "age [title1] [title2]", "",
		"Examples:", "", "",
		"age", " title1 title2", "Add an edge from the node with \"title1\" as title to the one with title \"title2\"",
		"age", " \"title1 with spaces\" title2", "Add an edge from node \"title1 with spaces\" to node \"title2\"",
		"age-", " title1 title2", "Remove an edge from the node with \"title1\" as title to the one with title \"title2\"",
		"age?", "", "Show this help",
		NULL };

	switch (*input) {
	case ' ':
	case '-': {
		RANode *u, *v;
		char **args;
		int n_args;

		args = r_str_argv (input + 1, &n_args);
		if (n_args != 2) {
			r_cons_printf ("Wrong arguments\n");
			r_str_argv_free (args);
			break;
		}

		u = r_agraph_get_node (core->graph, args[0]);
		v = r_agraph_get_node (core->graph, args[1]);
		if (!u || !v) {
			r_cons_printf ("Nodes not found!\n");
			r_str_argv_free (args);
			break;
		}
		if (*input == ' ') {
			r_agraph_add_edge (core->graph, u, v);
		} else {
			r_agraph_del_edge (core->graph, u, v);
		}
		r_str_argv_free (args);
		break;
	}
	case '?':
	default:
		r_core_cmd_help (core, help_msg);
		break;
	}
}

static void cmd_agraph_print(RCore *core, const char *input) {
	const char *help_msg[] = {
		"Usage:", "agg[kid?*]", "print graph",
		"agg", "", "show current graph in ascii art",
		"aggk", "", "show graph in key=value form",
		"aggd", "", "print the current graph in GRAPHVIZ dot format",
		"aggi", "", "enter interactive mode for the current graph",
		"aggd", "", "print the current graph in GRAPHVIZ dot format",
		"agg*", "", "in r2 commands, to save in projects, etc",
		NULL };
	switch (*input) {
	case 'k': // "aggk"
	{
		Sdb *db = r_agraph_get_sdb (core->graph);
		char *o = sdb_querys (db, "NULL", 0, "*");
		r_cons_printf ("%s", o);
		free (o);
		break;
	}
	case 'i': // "aggi" - open current core->graph in interactive mode
	{
		RANode *ran = r_agraph_get_first_node (core->graph);
		r_agraph_set_title (core->graph, r_config_get (core->config, "graph.title"));
		r_agraph_set_curnode (core->graph, ran);
		core->graph->force_update_seek = true;
		core->graph->need_set_layout = true;
		int ov = r_config_get_i (core->config, "scr.interactive");
		core->graph->need_update_dim = true;
		r_core_visual_graph (core, core->graph, NULL, true);
		r_config_set_i (core->config, "scr.interactive", ov);
		r_cons_show_cursor (true);
		break;
	}
	case 'd': // "aggd" - dot format
		r_cons_printf ("digraph code {\ngraph [bgcolor=white];\n"
			"node [color=lightgray, style=filled shape=box "
			"fontname=\"Courier\" fontsize=\"8\"];\n");
		r_agraph_foreach (core->graph, agraph_print_node_dot, NULL);
		r_agraph_foreach_edge (core->graph, agraph_print_edge_dot, NULL);
		r_cons_printf ("}\n");
		break;
	case '*': // "agg*" -
		r_agraph_foreach (core->graph, agraph_print_node, NULL);
		r_agraph_foreach_edge (core->graph, agraph_print_edge, NULL);
		break;
	case '?':
		r_core_cmd_help (core, help_msg);
		break;
	default:
		core->graph->can->linemode = 1;
		core->graph->can->color = r_config_get_i (core->config, "scr.color");
		r_agraph_set_title (core->graph,
			r_config_get (core->config, "graph.title"));
		r_agraph_print (core->graph);
		break;
	}
}

static void cmd_anal_graph(RCore *core, const char *input) {
	RList *list;
	const char *arg;
	const char *help_msg[] = {
		"Usage:", "ag[?f]", "Graphviz/graph code",
		"ag", " [addr]", "output graphviz code (bb at addr and children)",
		"ag-", "", "Reset the current ASCII art graph (see agn, age, agg?)",
		"aga", " [addr]", "idem, but only addresses",
		"agc", " [addr]", "output graphviz call graph of function",
		"agd", " [fcn name]", "output graphviz code of diffed function",
		"age", "[?] title1 title2", "Add an edge to the current graph",
		"agf", " [addr]", "Show ASCII art graph of given function",
		"agg", "[kdi*]", "Print graph in ASCII-Art, graphviz, k=v, r2 or visual",
		"agj", " [addr]", "idem, but in JSON format",
		"agk", " [addr]", "idem, but in SDB key-value format",
		"agl", " [fcn name]", "output graphviz code using meta-data",
		"agn", "[?] title body", "Add a node to the current graph",
		"ags", " [addr]", "output simple graphviz call graph of function (only bb offset)",
		"agt", " [addr]", "find paths from current offset to given address",
		"agv", "[acdltfl] [a]", "view function using graphviz",
		NULL };

	switch (input[0]) {
	case 'f':			// "agf"
		r_core_cmd0 (core, "afg"); // afg should be deprecated imho
		break;
	case '-':
		r_agraph_reset (core->graph);
		break;
	case 'n': // "agn"
		cmd_agraph_node (core, input + 1);
		break;
	case 'e': // "age"
		cmd_agraph_edge (core, input + 1);
		break;
	case 'g': // "agg"
		cmd_agraph_print (core, input + 1);
		break;
	case 's': // "ags"
		r_core_anal_graph (core, r_num_math (core->num, input + 1), 0);
		break;
	case 't':
		list = r_core_anal_graph_to (core, r_num_math (core->num, input + 1), 0);
		if (list) {
			RListIter *iter, *iter2;
			RList *list2;
			RAnalBlock *bb;
			r_list_foreach (list, iter, list2) {
				r_list_foreach (list2, iter2, bb) {
					r_cons_printf ("-> 0x%08" PFMT64x "\n", bb->addr);
				}
			}
			r_list_purge (list);
			free (list);
		}
		break;
	case 'c': // "agc"
		if (input[1] == '*') {
			ut64 addr = input[2]? r_num_math (core->num, input + 2): UT64_MAX;
			r_core_anal_coderefs (core, addr, '*');
		} else if (input[1] == ' ') {
			ut64 addr = input[2]? r_num_math (core->num, input + 1): UT64_MAX;
			r_core_anal_coderefs (core, addr, input[1] == 'j'? 2: 1);
		} else eprintf ("|ERROR| Usage: agc [addr]\n");
		break;
	case 'j': // "agj"
		r_core_anal_graph (core, r_num_math (core->num, input + 1), R_CORE_ANAL_JSON);
		break;
	case 'k': // "agk"
		r_core_anal_graph (core, r_num_math (core->num, input + 1), R_CORE_ANAL_KEYVALUE);
		break;
	case 'l': // "agl"
		r_core_anal_graph (core, r_num_math (core->num, input + 1), R_CORE_ANAL_GRAPHLINES);
		break;
	case 'a': // "aga"
		r_core_anal_graph (core, r_num_math (core->num, input + 1), 0);
		break;
	case 'd': // "agd"
		r_core_anal_graph (core, r_num_math (core->num, input + 1),
				R_CORE_ANAL_GRAPHBODY | R_CORE_ANAL_GRAPHDIFF);
		break;
	case 'v': // "agv"
		r_core_cmd0 (core, "=H /graph/");
		break;
	case '?': // "ag?"
		r_core_cmd_help (core, help_msg);
		break;
	case ' ': // "ag"
		arg = strchr (input, ' ');
		if (arg) arg++;
		r_core_anal_graph (core, r_num_math (core->num, arg),
				R_CORE_ANAL_GRAPHBODY);
		break;
	case 0:
		eprintf ("|ERROR| Usage: ag [addr]\n");
		break;
	default:
		eprintf ("See ag?\n");
		break;
	}
}

static void cmd_anal_trace(RCore *core, const char *input) {
	RDebugTracepoint *t;
	const char *ptr;
	ut64 addr = core->offset;
	const char *help_msg[] = {
		"Usage:", "at", "[*] [addr]",
		"at", "", "list all traced opcode ranges",
		"at-", "", "reset the tracing information",
		"at*", "", "list all traced opcode offsets",
		"at+", " [addr] [times]", "add trace for address N times",
		"at", " [addr]", "show trace info at address",
		"ate", "", "show esil trace logs (anal.trace)",
		"ate", " [idx]", "show commands to restore to this trace index",
		"ate", "-", "clear esil trace logs",
		"att", " [tag]", "select trace tag (no arg unsets)",
		"at%", "", "TODO",
		"ata", " 0x804020 ...", "only trace given addresses",
		"atr", "", "show traces as range commands (ar+)",
		"atd", "", "show disassembly trace (use .atd)",
		"atl", "", "list all traced addresses (useful for @@= `atl`)",
		"atD", "", "show dwarf trace (at*|rsc dwarf-traces $FILE)",
		NULL };

	switch (input[0]) {
	case 'r':
		eprintf ("TODO\n");
		//trace_show(-1, trace_tag_get());
		break;
	case 'e': // "ate"
		if (!core->anal->esil) {
			int stacksize = r_config_get_i (core->config, "esil.stacksize");
			int romem = r_config_get_i (core->config, "esil.romem");
			int stats = r_config_get_i (core->config, "esil.stats");
			int iotrap = r_config_get_i (core->config, "esil.iotrap");
			if (!(core->anal->esil = r_anal_esil_new (stacksize, iotrap)))
				return;
			r_anal_esil_setup (core->anal->esil,
					core->anal, romem, stats);
		}
		switch (input[1]) {
		case 0:
			r_anal_esil_trace_list (core->anal->esil);
			break;
		case 'i': {
			RAnalOp *op;
			ut64 addr = r_num_math (core->num, input + 2);
			if (!addr)
				addr = core->offset;
			op = r_core_anal_op (core, addr);
			if (op)
				r_anal_esil_trace (core->anal->esil, op);
			r_anal_op_free (op);
		} break;
		case '-':
			if (!strcmp (input + 2, "*")) {
				if (core->anal->esil) {
					sdb_free (core->anal->esil->db_trace);
					core->anal->esil->db_trace = sdb_new0 ();
				}
			} else {
				eprintf ("TODO: ate- cannot delete specific logs. Use ate-*\n");
			}
			break;
		case ' ': {
			int idx = atoi (input + 2);
			r_anal_esil_trace_show (
				core->anal->esil, idx);
		} break;
		case 'k':
			if (input[2] == ' ') {
				char *s = sdb_querys (core->anal->esil->db_trace,
						NULL, 0, input + 3);
				r_cons_printf ("%s\n", s);
				free (s);
			} else {
				eprintf ("Usage: atek [query]\n");
			}
			break;
		default:
			eprintf ("|Usage: ate[ilk] [-arg]\n"
				"| ate           esil trace log single instruction\n"
				"| ate idx       show commands for that index log\n"
				"| ate-*         delete all esil traces\n"
				"| atei          esil trace log single instruction\n"
				"| atek  [sdbq]  esil trace log single instruction\n");
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg);
		eprintf ("Current Tag: %d\n", core->dbg->trace->tag);
		break;
	case 'a':
		eprintf ("NOTE: Ensure given addresses are in 0x%%08" PFMT64x " format\n");
		r_debug_trace_at (core->dbg, input + 1);
		break;
	case 't':
		r_debug_trace_tag (core->dbg, atoi (input + 1));
		break;
	case 'l':
		r_debug_trace_list (core->dbg, 'l');
		r_cons_newline ();
		break;
	case 'd':
		r_debug_trace_list (core->dbg, 'd');
		break;
	case 'D':
		// XXX: not yet tested..and rsc dwarf-traces comes from r1
		r_core_cmd (core, "at*|rsc dwarf-traces $FILE", 0);
		break;
	case '+':
		ptr = input + 2;
		addr = r_num_math (core->num, ptr);
		ptr = strchr (ptr, ' ');
		if (ptr != NULL) {
			RAnalOp *op = r_core_op_anal (core, addr);
			if (op != NULL) {
				RDebugTracepoint *tp = r_debug_trace_add (core->dbg, addr, op->size);
				tp->count = atoi (ptr + 1);
				r_anal_trace_bb (core->anal, addr);
				r_anal_op_free (op);
			} else eprintf ("Cannot analyze opcode at 0x%" PFMT64x "\n", addr);
		}
		break;
	case '-':
		r_debug_trace_free (core->dbg->trace);
		core->dbg->trace = r_debug_trace_new ();
		break;
	case ' ':
		if ((t = r_debug_trace_get (core->dbg,
					r_num_math (core->num, input)))) {
			r_cons_printf ("offset = 0x%" PFMT64x "\n", t->addr);
			r_cons_printf ("opsize = %d\n", t->size);
			r_cons_printf ("times = %d\n", t->times);
			r_cons_printf ("count = %d\n", t->count);
			//TODO cons_printf("time = %d\n", t->tm);
		}
		break;
	case '*':
		r_debug_trace_list (core->dbg, 1);
		break;
	default:
		r_debug_trace_list (core->dbg, 0);
	}
}

R_API int r_core_anal_refs(RCore *core, const char *input) {
	int cfg_debug = r_config_get_i (core->config, "cfg.debug");
	ut64 from, to;
	char *ptr;
	int rad, n;
	const char *help_msg_aar[] = {
		"Usage:", "aar", "[j*] [sz] # search and analyze xrefs",
		"aar", " [sz]", "analyze xrefs in current section or sz bytes of code",
		"aarj", " [sz]", "list found xrefs in JSON format",
		"aar*", " [sz]", "list found xrefs in radare commands format",
		NULL };
	if (*input == '?') {
		r_core_cmd_help (core, help_msg_aar);
		return 0;
	}

	if (*input == 'j' || *input == '*') {
		rad = *input;
		input++;
	} else {
		rad = 0;
	}

	from = to = 0;
	ptr = r_str_trim_head (strdup (input));
	n = r_str_word_set0 (ptr);
	if (n == 0) {
		int rwx = R_IO_EXEC;
		// get boundaries of current memory map, section or io map
		if (cfg_debug) {
			RDebugMap *map = r_debug_map_get (core->dbg, core->offset);
			if (map) {
				from = map->addr;
				to = map->addr_end;
				rwx = map->perm;
			}
		} else if (core->io->va) {
			RIOSection *section = r_io_section_vget (core->io, core->offset);
			if (section) {
				from = section->vaddr;
				to = section->vaddr + section->vsize;
				rwx = section->rwx;
			}
		} else {
			RIOMap *map = r_io_map_get (core->io, core->offset);
			from = core->offset;
			to = r_io_size (core->io) + (map? map->to: 0);
		}
		if (from == 0 && to == 0) {
			eprintf ("Cannot determine xref search boundaries\n");
		} else if (!(rwx & R_IO_EXEC)) {
			eprintf ("Warning: Searching xrefs in non-executable region\n");
		}
	} else if (n == 1) {
		from = core->offset;
		to = core->offset + r_num_math (core->num, r_str_word_get0 (ptr, 0));
	} else {
		eprintf ("Invalid number of arguments\n");
	}
	free (ptr);

	if (from == UT64_MAX && to == UT64_MAX) return false;
	if (from == 0 && to == 0) return false;
	if (to - from > r_io_size (core->io)) return false;

	return r_core_anal_search_xrefs (core, from, to, rad);
}

static const char *oldstr = NULL;

static void rowlog(RCore *core, const char *str) {
	int use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	bool verbose = r_config_get_i (core->config, "scr.prompt");
	oldstr = str;
	if (!verbose) {
		return;
	}
	if (use_color) {
		eprintf ("[ ] "Color_YELLOW"%s\r["Color_RESET, str);
	} else {
		eprintf ("[ ] %s\r[", str);
	}
}

static void rowlog_done(RCore *core) {
	int use_color = core->print->flags & R_PRINT_FLAGS_COLOR;
	bool verbose = r_config_get_i (core->config, "scr.prompt");
	if (verbose) {
		if (use_color)
			eprintf ("\r"Color_GREEN"[x]"Color_RESET" %s\n", oldstr);
		else eprintf ("\r[x] %s\n", oldstr);
	}
}

static int compute_coverage(RCore *core) {
	RListIter *iter;
	RAnalFunction *fcn;
	int cov = 0;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		cov += r_anal_fcn_realsize (fcn);
	}
	return cov;
}

static int compute_calls(RCore *core) {
	RListIter *iter;
	RAnalFunction *fcn;
	int cov = 0;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		cov += r_list_length (fcn->xrefs);
	}
	return cov;
}

static void r_core_anal_info (RCore *core, const char *input) {
	int fcns = r_list_length (core->anal->fcns);
	int strs = r_flag_count (core->flags, "str.*");
	int syms = r_flag_count (core->flags, "sym.*");
	int imps = r_flag_count (core->flags, "sym.imp.*");
	int code = r_num_get (core->num, "$SS");
	int covr = compute_coverage (core);
	int call = compute_calls (core);
	int xrfs = r_anal_xrefs_count (core->anal);
	int cvpc = (code>0)? (covr * 100 / code): 0;
	if (*input == 'j') {
		r_cons_printf ("{\"fcns\":%d", fcns);
		r_cons_printf (",\"xrefs\":%d", xrfs);
		r_cons_printf (",\"calls\":%d", call);
		r_cons_printf (",\"strings\":%d", strs);
		r_cons_printf (",\"symbols\":%d", syms);
		r_cons_printf (",\"imports\":%d", imps);
		r_cons_printf (",\"covrage\":%d", covr);
		r_cons_printf (",\"codesz\":%d", code);
		r_cons_printf (",\"percent\":%d}\n", cvpc);
	} else {
		r_cons_printf ("fcns    %d\n", fcns);
		r_cons_printf ("xrefs   %d\n", xrfs);
		r_cons_printf ("calls   %d\n", call);
		r_cons_printf ("strings %d\n", strs);
		r_cons_printf ("symbols %d\n", syms);
		r_cons_printf ("imports %d\n", imps);
		r_cons_printf ("covrage %d\n", covr);
		r_cons_printf ("codesz  %d\n", code);
		r_cons_printf ("percent %d%%\n", cvpc);
	}
}

extern int cmd_search_value_in_range(RCore *core, ut64 from, ut64 to, ut64 vmin, ut64 vmax, int vsize);

static void cmd_anal_aav(RCore *core, const char *input) {
#define set(x,y) r_config_set(core->config, x, y);
#define seti(x,y) r_config_set_i(core->config, x, y);
#define geti(x) r_config_get_i(core->config, x);
	RIOSection *s;
	ut64 o_align = geti ("search.align");
	ut64 from, to, ptr;
	ut64 vmin, vmax;
	bool asterisk = strchr (input, '*');;
	bool is_debug = r_config_get_i (core->config, "cfg.debug");

	if (is_debug) {
		r_list_free (r_core_get_boundaries_prot (core, 0, "dbg.map", &from, &to));
	} else {
		s = r_io_section_vget (core->io, core->offset);
		if (s) {
			from = s->vaddr;
			to = s->vaddr + s->size;
		} else {
			eprintf ("aav: Cannot find section at this address\n");
			// TODO: look in debug maps
			return;
		}
	}
	seti ("search.align", 4);

	char *arg = strchr (input, ' ');
	if (arg) {
		ptr = r_num_math (core->num, arg + 1);
		s = r_io_section_vget (core->io, ptr);
	}
	{
		RList *ret;
		if (is_debug) {
			ret = r_core_get_boundaries_prot (core, 0, "dbg.map", &vmin, &vmax);
		} else {
			from = r_config_get_i (core->config, "bin.baddr");
			to = from + ((core->file)? r_io_desc_size (core->io, core->file->desc): 0);
			if (!s) {
				eprintf ("aav: Cannot find section at 0x%"PFMT64d"\n", ptr);
				return; // WTF!
			}
			ret = r_core_get_boundaries_prot (core, 0, "io.sections", &vmin, &vmax);
		}
		r_list_free (ret);
	}
	eprintf ("aav: using from to 0x%"PFMT64x" 0x%"PFMT64x"\n", from, to);
	eprintf ("Using vmin 0x%"PFMT64x" and vmax 0x%"PFMT64x"\n", vmin, vmax);
	int vsize = 4; // 32bit dword
	if (core->assembler->bits == 64) {
		vsize = 8;
	}
	(void)cmd_search_value_in_range (core, from, to, vmin, vmax, vsize);
	// TODO: for each hit . must set flag, xref and metadata Cd 4
	if (asterisk) {
		r_cons_printf ("f-hit*\n");
	} else {
		r_core_cmd0 (core, "f-hit*");
	}
	seti ("search.align", o_align);
}

static int cmd_anal_all(RCore *core, const char *input) {
	const char *help_msg_aa[] = {
		"Usage:", "aa[0*?]", " # see also 'af' and 'afna'",
		"aa", " ", "alias for 'af@@ sym.*;af@entry0'", //;.afna @@ fcn.*'",
		"aa*", "", "analyze all flags starting with sym. (af @@ sym.*)",
		"aaa", "", "autoname functions after aa (see afna)",
		"aac", " [len]", "analyze function calls (af @@ `pi len~call[1]`)",
		"aae", " [len] ([addr])", "analyze references with ESIL (optionally to address)",
		"aai", "[j]", "show info of all analysis parameters",
		"aar", " [len]", "analyze len bytes of instructions for references",
		"aan", "", "autoname functions that either start with fcn.* or sym.func.*",
		"aas", " [len]", "analyze symbols (af @@= `isq~[0]`)",
		"aat", " [len]", "analyze all consecutive functions in section",
		"aap", "", "find and analyze function preludes",
		"aav", " [sat]", "find values referencing a specific section or map",
		"aau", " [len]", "list mem areas (larger than len bytes) not covered by functions",
		NULL };

	switch (*input) {
	case '?': r_core_cmd_help (core, help_msg_aa); break;
	case 'c': cmd_anal_calls (core, input + 1); break; // "aac"
	case 'j': cmd_anal_jumps (core, input + 1); break; // "aaj"
	case '*':
		r_core_cmd0 (core, "af @@ sym.*");
		r_core_cmd0 (core, "af @ entry0");
		break;
	case 'v': // "aav"
		cmd_anal_aav (core, input);
		break;
	case 'u': // "aau" - print areas not covered by functions
		r_core_anal_nofunclist (core, input + 1);
		break;
	case 'i': // "aai"
		r_core_anal_info (core, input + 1);
		break;
	case 's':
		r_core_cmd0 (core, "af @@= `isq~[0]`");
		r_core_cmd0 (core, "af @ entry0");
		break;
	case 'n': r_core_anal_autoname_all_fcns (core); break; //aan
	case 'p': // "aap"
		if (*input == '?') {
			// TODO: accept parameters for ranges
			eprintf ("Usage: /aap   ; find in memory for function preludes");
		} else {
			r_core_search_preludes (core);
		}
		break;
	case '\0': // "aa"
	case 'a':
		if (input[0] && (input[1] == '?' || (input[1] && input[2] == '?'))) {
			eprintf ("Usage: See aa? for more help\n");
		} else {
			bool done_aav = false;
			r_cons_break (NULL, NULL);
			ut64 curseek = core->offset;
			rowlog (core, "Analyze all flags starting with sym. and entry0 (aa)");
			if (strstr (r_config_get (core->config, "asm.arch"), "arm")) {
				rowlog (core, "Analyze value pointers (aav)");
				done_aav = true;
				r_core_cmd0 (core, "aav");
				r_core_cmd0 (core, "aav $S+$SS+1");
			}
			r_core_anal_all (core);
			rowlog_done (core);
			if (core->cons->breaked)
				goto jacuzzi;
			r_cons_clear_line (1);
			r_cons_break_end ();
			if (*input == 'a') { // "aaa"
				int c = r_config_get_i (core->config, "anal.calls");
				r_config_set_i (core->config, "anal.calls", 1);
				r_core_cmd0 (core, "s $S");
				rowlog (core, "Analyze len bytes of instructions for references (aar)");
				(void)r_core_anal_refs (core, input + 1); // "aar"
				rowlog_done(core);
				if (core->cons->breaked)
					goto jacuzzi;
				rowlog (core, "Analyze function calls (aac)");
				r_core_seek (core, curseek, 1);
				(void)cmd_anal_calls (core, ""); // "aac"
				rowlog_done(core);
				if (core->cons->breaked)
					goto jacuzzi;
				if (input[1] == 'a') { // "aaaa"
					rowlog (core, "Emulate code to find computed references (aae)");
					r_core_cmd0 (core, "aae $SS @ $S");
					rowlog_done (core);
					rowlog (core, "Analyze consecutive function (aat)");
					r_core_cmd0 (core, "aat");
					rowlog_done (core);
					if (!done_aav) {
						rowlog (core, "Analyze value pointers (aav)");
						r_core_cmd0 (core, "aav");
						r_core_cmd0 (core, "aav $S+$SS+1");
						rowlog_done (core);
					}
				} else {
					rowlog (core, "[*] Use -AA or aaaa to perform additional experimental analysis.\n");
				}
				r_config_set_i (core->config, "anal.calls", c);
				rowlog (core, "Constructing a function name for fcn.* and sym.func.* functions (aan)");
				if (r_config_get_i (core->config, "anal.autoname")) {
					r_core_anal_autoname_all_fcns (core);
				}
				rowlog_done (core);
				if (core->cons->breaked)
					goto jacuzzi;
				r_core_cmd0 (core, "s-");
			}
		jacuzzi:
			flag_every_function (core);
		//	r_core_cmd0 (core, "aai");
		}
		break;
	case 't': {
		ut64 cur = core->offset;
		RIOSection *s = r_io_section_vget (core->io, cur);
		if (s) {
			int hasnext = r_config_get_i (core->config, "anal.hasnext");
			r_core_seek (core, s->vaddr, 1);
			r_config_set_i (core->config, "anal.hasnext", 1);
			(void)cmd_anal_fcn (core, "af"); //af oob read if we pass ""
			r_config_set_i (core->config, "anal.hasnext", hasnext);
		} else {
			// TODO: honor search.in? support dbg.maps?
			eprintf ("Cannot find section boundaries in here\n");
		}
		r_core_seek (core, cur, 1);
		break;
	}
	case 'e': // "aae"
		if (input[1] == ' ') {
			char *len = strdup (input + 2);
			if (len) {
				char *addr = strchr (len, ' ');
				if (addr) {
					*addr++ = 0;
				}
				r_core_anal_esil (core, len, addr);
				free (len);
			}
		} else {
			ut64 at = core->offset;
			ut64 from = r_num_get (core->num, "$S");
			r_core_seek (core, from, 1);
			r_core_anal_esil (core, "$SS", NULL);
			r_core_seek (core, at, 1);
		}
		break;
	case 'r':
		(void)r_core_anal_refs (core, input + 1);
		break;
	default:
		r_core_cmd_help (core, help_msg_aa);
		break;
	}

	return true;
}

static bool anal_fcn_data (RCore *core, const char *input) {
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
	ut32 fcn_size = r_anal_fcn_size (fcn);
	if (fcn) {
		int i;
		bool gap = false;
		ut64 gap_addr = UT64_MAX;
		char *bitmap = calloc (1, fcn_size);
		if (bitmap) {
			RAnalBlock *b;
			RListIter *iter;
			r_list_foreach (fcn->bbs, iter, b) {
				int f = b->addr - fcn->addr;
				int t = R_MIN (f + b->size, fcn_size);
				if (f>=0) {
					while (f < t) {
						bitmap[f++] = 1;
					}
				}
			}
		}
		for (i = 0; i < fcn_size; i++) {
			ut64 here = fcn->addr + i;
			if (bitmap && bitmap[i]) {
				if (gap) {
					r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", here - gap_addr, gap_addr);
					gap = false;
				}
				gap_addr = UT64_MAX;
			} else {
				if (!gap) {
					gap = true;
					gap_addr = here;
				}
			}
		}
		if (gap) {
			r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", fcn->addr + fcn_size - gap_addr, gap_addr);
			gap = false;
		}
		free (bitmap);
		return true;
	}
	return false;
}

static int cmpaddr (const void *_a, const void *_b) {
        const RAnalFunction *a = _a, *b = _b;
        return (a->addr > b->addr);
}

static bool anal_fcn_data_gaps (RCore *core, const char *input) {
	ut64 end = UT64_MAX;
	RAnalFunction *fcn;
	RListIter *iter;
	int i, wordsize = (core->assembler->bits == 64)? 8: 4;
	r_list_sort (core->anal->fcns, cmpaddr);
	r_list_foreach (core->anal->fcns, iter, fcn) {
		if (end != UT64_MAX) {
			int range = fcn->addr - end;
			if (range > 0) {
				for (i = 0; i + wordsize < range; i+= wordsize) {
					r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", wordsize, end + i);
				}
				r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", range - i, end + i);
				//r_cons_printf ("Cd %d @ 0x%08"PFMT64x"\n", range, end);
			}
		}
		end = fcn->addr + r_anal_fcn_size (fcn);
	}
	return true;
}

static int cmd_anal(void *data, const char *input) {
	const char *r;
	RCore *core = (RCore *)data;
	ut32 tbs = core->blocksize;
	const char *help_msg_ad[] = {
		"Usage:", "ad", "[kt] [...]",
		"ad", " [N] [D]", "analyze N data words at D depth",
		"adf", "", "analyze data in function (use like .adf @@=`afl~[0]`",
		"adfg", "", "analyze data in function gaps",
		"adt", "", "analyze data trampolines (wip)",
		"adk", "", "analyze data kind (code, text, data, invalid, ...)",
		NULL };
	const char *help_msg[] = {
		"Usage:", "a", "[abdefFghoprxstc] [...]",
		"ab", " [hexpairs]", "analyze bytes",
		"aa", "", "analyze all (fcns + bbs) (aa0 to avoid sub renaming)",
		"ac", " [cycles]", "analyze which op could be executed in [cycles]",
		"ad", "", "analyze data trampoline (wip)",
		"ad", " [from] [to]", "analyze data pointers to (from-to)",
		"ae", " [expr]", "analyze opcode eval expression (see ao)",
		"af", "[rnbcsl?+-*]", "analyze Functions",
		"aF", "", "same as above, but using anal.depth=1",
		"ag", "[?acgdlf]", "output Graphviz code",
		"ah", "[?lba-]", "analysis hints (force opcode size, ...)",
		"ai", " [addr]", "address information (show perms, stack, heap, ...)",
		"ao", "[e?] [len]", "analyze Opcodes (or emulate it)",
		"an", "[an-] [...]", "manage no-return addresses/symbols/functions",
		"ar", "", "like 'dr' but for the esil vm. (registers)",
		"ap", "", "find prelude for current offset",
		"ax", "[?ld-*]", "manage refs/xrefs (see also afx?)",
		"as", " [num]", "analyze syscall using dbg.reg",
		"at", "[trd+-%*?] [.]", "analyze execution traces",
		//"ax", " [-cCd] [f] [t]", "manage code/call/data xrefs",
		NULL };

	r_cons_break (NULL, NULL);

	switch (input[0]) {
	case 'p': // "ap"
		{
			const ut8 *prelude = (const ut8*)"\xe9\x2d"; //:fffff000";
			const int prelude_sz = 2;
			const int bufsz = 4096;
			ut8 *buf = calloc (1, bufsz);
			ut64 off = core->offset;
			if (input[1] == ' ') {
				off = r_num_math (core->num, input+1);
				r_io_read_at (core->io, off - bufsz + prelude_sz, buf, bufsz);
			} else {
				r_io_read_at (core->io, off - bufsz + prelude_sz, buf, bufsz);
			}
			//const char *prelude = "\x2d\xe9\xf0\x47"; //:fffff000";
			r_mem_reverse (buf, bufsz);
			//r_print_hexdump (NULL, off, buf, bufsz, 16, -16);
			const ut8 *pos = r_mem_mem (buf, bufsz, prelude, prelude_sz);
			if (pos) {
				int delta = (size_t)(pos - buf);
				eprintf ("POS = %d\n", delta);
				eprintf ("HIT = 0x%"PFMT64x"\n", off - delta);
				r_cons_printf ("0x%08"PFMT64x"\n", off - delta);
			} else {
				eprintf ("Cannot find prelude\n");
			}
			free (buf);
		}
		break;
	case 'b':
		if (input[1] == ' ' || input[1] == 'j') {
			ut8 *buf = malloc (strlen (input) + 1);
			int len = r_hex_str2bin (input + 2, buf);
			if (len > 0)
				core_anal_bytes (core, buf, len, 0, input[1]);
			free (buf);
		} else eprintf ("Usage: ab [hexpair-bytes]\n abj [hexpair-bytes] (json)");
		break;
	case 'i': cmd_anal_info (core, input + 1); break; // "ai"
	case 'r': cmd_anal_reg (core, input + 1); break;  // "ar"
	case 'e': cmd_anal_esil (core, input + 1); break; // "ae"
	case 'o': cmd_anal_opcode (core, input + 1); break; // "ao"
	case 'n': cmd_anal_noreturn (core, input + 1); break; // "an"
	case 'F':
		r_core_anal_fcn (core, core->offset, UT64_MAX, R_ANAL_REF_TYPE_NULL, 1);
		break;
	case 'f': // "af"
		if (!cmd_anal_fcn (core, input)) {
			r_cons_break_end ();
			return false;
		}
		break;
	case 'g':
		cmd_anal_graph (core, input + 1);
		break;
	case 't':
		cmd_anal_trace (core, input + 1);
		break;
	case 's': // "as"
		cmd_anal_syscall (core, input + 1);
		break;
	case 'x':
		if (!cmd_anal_refs (core, input + 1)) {
			r_cons_break_end ();
			return false;
		}
		break;
	case 'a':
		if (!cmd_anal_all (core, input + 1))
			return false;
		break;
	case 'c':
		if (input[1] == '?') {
			eprintf ("Usage: ac [cycles]   # analyze instructions that fit in N cycles\n");
		} else {
			RList *hooks;
			RListIter *iter;
			RAnalCycleHook *hook;
			char *instr_tmp = NULL;
			int ccl = input[1]? r_num_math (core->num, &input[2]): 0; //get cycles to look for
			int cr = r_config_get_i (core->config, "asm.cmtright");
			int fun = r_config_get_i (core->config, "asm.functions");
			int li = r_config_get_i (core->config, "asm.lines");
			int xr = r_config_get_i (core->config, "asm.xrefs");

			r_config_set_i (core->config, "asm.cmtright", true);
			r_config_set_i (core->config, "asm.functions", false);
			r_config_set_i (core->config, "asm.lines", false);
			r_config_set_i (core->config, "asm.xrefs", false);

			r_cons_break (NULL, NULL);
			hooks = r_core_anal_cycles (core, ccl); //analyse
			r_cons_break_end ();
			r_cons_clear_line (1);
			r_list_foreach (hooks, iter, hook) {
				instr_tmp = r_core_disassemble_instr (core, hook->addr, 1);
				r_cons_printf ("After %4i cycles:\t%s", (ccl - hook->cycles), instr_tmp);
				r_cons_flush ();
				free (instr_tmp);
			}
			r_list_free (hooks);

			r_config_set_i (core->config, "asm.cmtright", cr); //reset settings
			r_config_set_i (core->config, "asm.functions", fun);
			r_config_set_i (core->config, "asm.lines", li);
			r_config_set_i (core->config, "asm.xrefs", xr);
		}
		break;
	case 'd':
		switch (input[1]) {
		case 'f':
			if (input[2] == 'g') {
				anal_fcn_data_gaps (core, input + 1);
			} else {
				anal_fcn_data (core, input + 1);
			}
			break;
		case 't':
			cmd_anal_trampoline (core, input + 2);
			break;
		case ' ': {
			const int default_depth = 1;
			const char *p;
			int a, b;
			a = r_num_math (core->num, input + 2);
			p = strchr (input + 2, ' ');
			b = p? r_num_math (core->num, p + 1): default_depth;
			if (a < 1) a = 1;
			if (b < 1) b = 1;
			r_core_anal_data (core, core->offset, a, b);
		} break;
		case 'k':
			r = r_anal_data_kind (core->anal,
					core->offset, core->block, core->blocksize);
			r_cons_printf ("%s\n", r);
			break;
		case '\0':
			r_core_anal_data (core, core->offset, 2 + (core->blocksize / 4), 1);
			break;
		default:
			r_core_cmd_help (core, help_msg_ad);
			break;
		}
		break;
	case 'h':
		cmd_anal_hint (core, input + 1);
		break;
	case '!':
		if (core->anal && core->anal->cur && core->anal->cur->cmd_ext)
			return core->anal->cur->cmd_ext (core->anal, input + 1);
		else r_cons_printf ("No plugins for this analysis plugin\n");
		break;
	default:
		r_core_cmd_help (core, help_msg);
		r_cons_printf ("Examples:\n"
			" f ts @ `S*~text:0[3]`; f t @ section..text\n"
			" f ds @ `S*~data:0[3]`; f d @ section..data\n"
			" .ad t t+ts @ d:ds\n",
			NULL);
		break;
	}
	if (tbs != core->blocksize)
		r_core_block_size (core, tbs);
	if (core->cons->breaked) {
		r_cons_clear_line (1);
		eprintf ("Interrupted\n");
	}
	r_cons_break_end ();
	return 0;
}
