/* radare - LGPL - Copyright 2009-2018 - pancake, oddcoder, Anton Kochkov, Jody Frankowski */

#include <string.h>
#include "r_anal.h"
#include "r_cons.h"
#include "r_core.h"
#include "sdb/sdb.h"

static const char *help_msg_t[] = {
	"Usage: t", "", "# cparse types commands",
	"t", "", "List all loaded types",
	"tj", "", "List all loaded types as json",
	"t", " <type>", "Show type in 'pf' syntax",
	"t*", "", "List types info in r2 commands",
	"t-", " <name>", "Delete types by its name",
	"t-*", "", "Remove all types",
	"ta", " <type>", "Mark immediate as a type offset",
	"tc", " ([cctype])", "calling conventions listing and manipulations",
	"te", "[?]", "List all loaded enums",
	"td", "[?] <string>", "Load types from string",
	"tf", "", "List all loaded functions signatures",
	"tk", " <sdb-query>", "Perform sdb query",
	"tl", "[?]", "Show/Link type to an address",
	"tn", "[?] [-][addr]", "manage noreturn function attributes and marks",
	"to", " -", "Open cfg.editor to load types",
	"to", " <path>", "Load types from C header file",
	"tos", " <path>", "Load types from parsed Sdb database",
	"tp", "  <type> [addr|varname]", "cast data at <address> to <type> and print it",
	"tpx", " <type> <hexpairs>", "Show value for type with specified byte sequence",
	"ts", "[?]", "print loaded struct types",
	"tu", "[?]", "print loaded union types",
	"tt", "[?]", "List all loaded typedefs",
	NULL
};

static const char *help_msg_t_minus[] = {
	"Usage: t-", " <type>", "Delete type by its name",
	NULL
};

static const char *help_msg_ta[] = {
	"Usage: ta[...]", "", "",
	"tas", " <offset>", "List all matching structure offsets",
	"ta", " <struct member>", "Change immediate to structure offset",
	"taa", " [fcn]", "Analyze all/given function to convert immediate to linked structure offsets (see tl?)",
	"ta?", "", "show this help",
	NULL
};

static const char *help_msg_tf[] = {
	"Usage: tf[...]", "", "",
	"tf", "", "List all function definitions loaded",
	"tf", " <name>", "Show function signature",
	"tfj", "", "List all function definitions in json",
	"tfj", " <name>", "Show function signature in json",
	NULL
};

static const char *help_msg_to[] = {
	"Usage: to[...]", "", "",
	"to", " -", "Open cfg.editor to load types",
	"to", " <path>", "Load types from C header file",
	"tos", " <path>", "Load types from parsed Sdb database",
	NULL
};

static const char *help_msg_tc[] = {
	"Usage: tc[...]", " [cctype]", "",
	"tc", "", "List all loaded calling convention",
	"tc", " [cctype]", "Show convention rules for this type",
	"tc=", "([cctype])", "Select (or show) default calling convention",
	"tc-", "[cctype]", "TODO: remove given calling convention",
	"tc+", "[cctype] ...", "TODO: define new calling convention",
	"tcl", "", "List all the calling conventions",
	"tcr", "", "Register telescoping using the calling conventions order",
	"tcj", "", "json output (TODO)",
	"tc?", "", "show this help",
	NULL
};

static const char *help_msg_td[] = {
	"Usage:", "\"td [...]\"", "",
	"td", "[string]", "Load types from string",
	NULL
};

static const char *help_msg_te[] = {
	"Usage: te[...]", "", "",
	"te", "", "List all loaded enums",
	"te", " <enum>", "Print all values of enum for given name",
	"tej", "", "List all loaded enums in json",
	"tej", " <enum>", "Show enum in json",
	"te", " <enum> <value>", "Show name for given enum number",
	"teb", " <enum> <name>", "Show matching enum bitfield for given name",
	"te?", "", "show this help",
	NULL
};

static const char *help_msg_tt[] = {
	"Usage: tt[...]", "", "",
	"tt", "", "List all loaded typedefs",
	"tt", " <typename>", "Show name for given type alias",
	"tt?", "", "show this help",
	NULL
};

static const char *help_msg_tl[] = {
	"Usage:", "", "",
	"tl", "", "list all links in readable format",
	"tl", "[typename]", "link a type to current address.",
	"tl", "[typename] = [address]", "link type to given address.",
	"tls", "[address]", "show link at given address",
	"tl-*", "", "delete all links.",
	"tl-", "[address]", "delete link at given address.",
	"tl*", "", "list all links in radare2 command format",
	"tl?", "", "print this help.",
	NULL
};

static const char *help_msg_tn[] = {
	"Usage:", "tn [-][0xaddr|symname]", " manage no-return marks",
	"tn[a]", " 0x3000", "stop function analysis if call/jmp to this address",
	"tn[n]", " sym.imp.exit", "same as above but for flag/fcn names",
	"tn", "-*", "remove all no-return references",
	"tn", "", "list them all",
	NULL
};

static const char *help_msg_ts[] = {
	"Usage: ts[...]", " [type]", "",
	"ts", "", "List all loaded structs",
	"ts", " [type]", "Show pf format string for given struct",
	"tsj", "", "List all loaded structs in json",
	"tsj", " [type]", "Show pf format string for given struct in json",
	"ts*", " [type]", "Show pf.<name> format string for given struct",
	"tss", " [type]", "Display size of struct",
	"ts?", "", "show this help",
	NULL
};

static const char *help_msg_tu[] = {
	"Usage: tu[...]", "", "",
	"tu", "", "List all loaded unions",
	"tu", " [type]", "Show pf format string for given union",
	"tuj", "", "List all loaded unions in json",
	"tuj", " [type]", "Show pf format string for given union in json",
	"tu*", " [type]", "Show pf.<name> format string for given union",
	"tu?", "", "show this help",
	NULL
};

static void cmd_type_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, t);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, t-, t_minus);
	DEFINE_CMD_DESCRIPTOR (core, ta);
	DEFINE_CMD_DESCRIPTOR (core, tc);
	DEFINE_CMD_DESCRIPTOR (core, td);
	DEFINE_CMD_DESCRIPTOR (core, te);
	DEFINE_CMD_DESCRIPTOR (core, tl);
	DEFINE_CMD_DESCRIPTOR (core, tn);
	DEFINE_CMD_DESCRIPTOR (core, ts);
	DEFINE_CMD_DESCRIPTOR (core, tu);
	DEFINE_CMD_DESCRIPTOR (core, tt);
}

static void show_help(RCore *core) {
	r_core_cmd_help (core, help_msg_t);
}

static void showFormat(RCore *core, const char *name, int mode) {
	const char *isenum = sdb_const_get (core->anal->sdb_types, name, 0);
	if (isenum && !strcmp (isenum, "enum")) {
		eprintf ("IS ENUM\n");
	} else {
		char *fmt = r_type_format (core->anal->sdb_types, name);
		if (fmt) {
			r_str_trim (fmt);
			if (mode == 'j') {
				r_cons_printf ("{\"name\":\"%s\",\"format\":\"%s\"}", name, fmt);
			} else {
				if (mode) {
					r_cons_printf ("pf.%s %s\n", name, fmt);
				} else {
					r_cons_printf ("pf %s\n", fmt);
				}
			}
			free (fmt);
		} else {
			eprintf ("Cannot find '%s' type\n", name);
		}
	}
}

static void cmd_type_noreturn(RCore *core, const char *input) {
	switch (input[0]) {
	case '-': // "tn-"
		r_anal_noreturn_drop (core->anal, input + 1);
		break;
	case ' ': // "tn"
		if (input[1] == '0' && input[2] == 'x') {
			r_anal_noreturn_add (core->anal, NULL,
					r_num_math (core->num, input + 1));
		} else {
			r_anal_noreturn_add (core->anal, input + 1,
					r_num_math (core->num, input + 1));
		}
		break;
	case 'a': // "tna"
		if (input[1] == ' ') {
			r_anal_noreturn_add (core->anal, NULL,
					r_num_math (core->num, input + 1));
		} else {
			r_core_cmd_help (core, help_msg_tn);
		}
		break;
	case 'n': // "tnn"
		if (input[1] == ' ') {
			/* do nothing? */
		} else {
			r_core_cmd_help (core, help_msg_tn);
		}
		break;
	case '*':
	case 'r': // "tn*"
		r_anal_noreturn_list (core->anal, 1);
		break;
	case 0: // "tn"
		r_anal_noreturn_list (core->anal, 0);
		break;
	default:
	case '?':
		r_core_cmd_help (core, help_msg_tn);
		break;
	}
}

static void save_parsed_type(RCore *core, const char *parsed) {
	if (!core || !core->anal || !parsed) {
		return;
	}
	// First, if this exists, let's remove it.
	char *type = strdup (parsed);
	if (type) {
		char *name = NULL;
		if ((name = strstr (type, "=type")) || (name = strstr (type, "=struct")) || (name = strstr (type, "=union")) ||
			(name = strstr (type, "=enum")) || (name = strstr (type, "=typedef")) ||(name = strstr (type, "=func"))) {
			*name = 0;
			while (name - 1 >= type && *(name - 1) != '\n') {
				name--;
			}

		}
		if (name) {
			r_core_cmdf (core, "\"t- %s\"", name);
			// Now add the type to sdb.
			sdb_query_lines (core->anal->sdb_types, parsed);
		}
		free (type);
	}
}

static int stdifstruct(void *user, const char *k, const char *v) {
	return !strncmp (v, "struct", strlen ("struct") + 1);
}

static int printkey_cb(void *user, const char *k, const char *v) {
	r_cons_println (k);
	return 1;
}

static int printkey_json_cb(void *user, const char *k, const char *v) {
	r_cons_printf ("\"%s\"", k);
	return 1;
}

static void printFunctionType(RCore *core, const char *input) {
	Sdb *TDB = core->anal->sdb_types;
	char *res = sdb_querys (TDB, NULL, -1, sdb_fmt ("func.%s.args", input));
	const char *name = r_str_trim_ro (input);
	int i, args = sdb_num_get (TDB, sdb_fmt ("func.%s.args", name), 0);
	r_cons_printf ("{\"name\":\"%s\",\"args\":[", name);
	for (i = 0; i< args; i++) {
		char *type = sdb_get (TDB, sdb_fmt ("func.%s.arg.%d", name, i), 0);
		char *name = strchr (type, ',');
		if (name) {
			*name++ = 0;
		}
		r_cons_printf ("{\"type\":\"%s\",\"name\":\"%s\"}%s", type, name, i+1==args? "": ",");
	}
	r_cons_printf ("]}");
	free (res);
}

static int printfunc_json_cb(void *user, const char *k, const char *v) {
	printFunctionType ((RCore *)user, k);
	return 1;
}

static int stdiffunc(void *p, const char *k, const char *v) {
	return !strncmp (v, "func", strlen ("func") + 1);
}

static int stdifunion(void *p, const char *k, const char *v) {
	return !strncmp (v, "union", strlen ("union") + 1);
}

static int sdbdeletelink(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	if (!strncmp (k, "link.", strlen ("link."))) {
		r_type_del (core->anal->sdb_types, k);
	}
	return 1;
}

static int stdiflink(void *p, const char *k, const char *v) {
	return !strncmp (k, "link.", strlen ("link."));
}

static int print_link_cb(void *p, const char *k, const char *v) {
	r_cons_printf ("tl %s = 0x%s\n", v, k + strlen ("link."));
	return 1;
}

static int print_link_readable_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	char *fmt = r_type_format (core->anal->sdb_types, v);
	if (!fmt) {
		eprintf ("Cant fint type %s", v);
		return 1;
	}
	r_cons_printf ("(%s)\n", v);
	r_core_cmdf (core, "pf %s @ 0x%s\n", fmt, k + strlen ("link."));
	return 1;
}

static int stdiftype(void *p, const char *k, const char *v) {
	return !strncmp (v, "type", strlen ("type") + 1);
}

static int print_typelist_r_cb(void *p, const char *k, const char *v) {
	r_cons_printf ("tk %s=%s\n", k, v);
	return 1;
}

static int print_typelist_json_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	Sdb *sdb = core->anal->sdb_types;
	char *sizecmd = r_str_newf ("type.%s.size", k);
	char *size_s = sdb_querys (sdb, NULL, -1, sizecmd);
	char *formatcmd = r_str_newf ("type.%s", k);
	char *format_s = r_str_trim (sdb_querys (sdb, NULL, -1, formatcmd));
	r_cons_printf ("{\"type\":\"%s\",\"size\":%d,\"format\":\"%s\"}", k,
			size_s ? atoi (size_s) : -1,
			format_s);
	free (size_s);
	free (format_s);
	free (sizecmd);
	free (formatcmd);
	return 1;
}

static void print_keys(Sdb *TDB, RCore *core, SdbForeachCallback filter, SdbForeachCallback printfn_cb, bool json) {
	SdbList *l = sdb_foreach_list_filter (TDB, filter, true);
	SdbListIter *it;
	SdbKv *kv;
	const char *comma = "";

	if (json) {
		r_cons_printf ("[");
	}
	ls_foreach (l, it, kv) {
		const char *k = sdbkv_key (kv);
		if (!k || !*k) {
			continue;
		}
		if (json) {
			r_cons_printf ("%s", comma);
			comma = ",";
		}
		printfn_cb (core, sdbkv_key (kv), sdbkv_value (kv));
	}
	if (json) {
		r_cons_printf ("]\n");
	}
	ls_free (l);
}

static void typesList(RCore *core, int mode) {
	switch (mode) {
	case 1:
	case '*':
		print_keys (core->anal->sdb_types, core, NULL, print_typelist_r_cb, false);
		break;
	case 'j':
		print_keys (core->anal->sdb_types, core, stdiftype, print_typelist_json_cb, true);
		break;
	default:
		print_keys (core->anal->sdb_types, core, stdiftype, printkey_cb, false);
		break;
	}
}

static void set_offset_hint(RCore *core, RAnalOp op, const char *type, ut64 laddr, ut64 at, int offimm) {
	char *res = r_type_get_struct_memb (core->anal->sdb_types, type, offimm);
	const char *cmt = ((offimm == 0) && res)? res: type;
	if (offimm > 0) {
		// set hint only if link is present
		char* query = sdb_fmt ("link.%08"PFMT64x, laddr);
		if (res && sdb_const_get (core->anal->sdb_types, query, 0)) {
			r_anal_hint_set_offset (core->anal, at, res);
		}
	} else if (cmt && r_anal_op_ismemref (op.type)) {
			r_meta_set_string (core->anal, R_META_TYPE_VARTYPE, at, cmt);
	}
}

R_API int r_core_get_stacksz (RCore *core, ut64 from, ut64 to) {
	int stack = 0, maxstack = 0;
	ut64 at = from;

	if (from >= to) {
		return 0;
	}
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	while (at < to) {
		RAnalOp *op = r_core_anal_op (core, at, R_ANAL_OP_MASK_BASIC);
		if (!op || op->size <= 0) {
			at += minopcode;
			continue;
		}
		if ((op->stackop == R_ANAL_STACK_INC) && R_ABS (op->stackptr) < 8096) {
			stack += op->stackptr;
			if (stack > maxstack) {
				maxstack = stack;
			}
		}
		at += op->size;
		r_anal_op_free (op);
	}
	return maxstack;
}

static void set_retval (RCore *core, ut64 at) {
	RAnal *anal = core->anal;
	RAnalHint *hint = r_anal_hint_get (anal, at);
	RAnalFunction *fcn = r_anal_get_fcn_in (anal, at, 0);

	if (!hint || !fcn || !fcn->name) {
		goto beach;
	}
	if (hint->ret == UT64_MAX) {
		goto beach;
	}
	const char *cc = r_anal_cc_func (core->anal, fcn->name);
	const char *regname = r_anal_cc_ret (anal, cc);
	if (regname) {
		RRegItem *reg = r_reg_get (anal->reg, regname, -1);
		if (reg) {
			r_reg_set_value (anal->reg, reg, hint->ret);
		}
	}
beach:
	r_anal_hint_free (hint);
	return;
}

static void link_struct_offset(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = {0};
	bool ioCache = r_config_get_i (core->config, "io.cache");
	bool stack_set = false;
	bool resolved = false;
	const char *varpfx;
	int dbg_follow = r_config_get_i (core->config, "dbg.follow");
	Sdb *TDB = core->anal->sdb_types;
	RAnalEsil *esil = core->anal->esil;
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	const char *pc_name = r_reg_get_name (core->anal->reg, R_REG_NAME_PC);
	const char *sp_name = r_reg_get_name (core->anal->reg, R_REG_NAME_SP);
	RRegItem *pc = r_reg_get (core->anal->reg, pc_name, -1);

	if (!fcn) {
		return;
	}
	if (!(esil = r_anal_esil_new (stacksize, iotrap, addrsize))) {
		return;
	}
	r_anal_esil_setup (esil, core->anal, 0, 0, 0);
	int i, ret, bsize = R_MAX (64, core->blocksize);
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	ut8 *buf = malloc (bsize);
	if (!buf) {
		free (buf);
		r_anal_esil_free (esil);
		return;
	}
	r_reg_arena_push (core->anal->reg);
	r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
	ut64 spval = r_reg_getv (esil->anal->reg, sp_name);
	if (spval) {
		// reset stack pointer to intial value
		RRegItem *sp = r_reg_get (esil->anal->reg, sp_name, -1);
		ut64 curpc = r_reg_getv (esil->anal->reg, pc_name);
		int stacksz = r_core_get_stacksz (core, fcn->addr, curpc);
		if (stacksz > 0) {
			r_reg_arena_zero (esil->anal->reg); // clear prev reg values
			r_reg_set_value (esil->anal->reg, sp, spval + stacksz);
		}
	} else {
		// intialize stack
		r_core_cmd0 (core, "aeim");
		stack_set = true;
	}
	r_config_set_i (core->config, "io.cache", 1);
	r_config_set_i (core->config, "dbg.follow", 0);
	ut64 oldoff = core->offset;
	r_cons_break_push (NULL, NULL);
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 at = bb->addr;
		ut64 to = bb->addr + bb->size;
		r_reg_set_value (esil->anal->reg, pc, at);
		for (i = 0; at < to; i++) {
			if (r_cons_is_breaked ()) {
				goto beach;
			}
			if (at < bb->addr) {
				break;
			}
			if (i >= (bsize - 32)) {
				i = 0;
			}
			if (!i) {
				r_io_read_at (core->io, at, buf, bsize);
			}
			ret = r_anal_op (core->anal, &aop, at, buf + i, bsize - i, R_ANAL_OP_MASK_VAL);
			if (ret <= 0) {
				i += minopcode;
				at += minopcode;
				r_anal_op_fini (&aop);
				continue;
			}
			i += ret - 1;
			at += ret;
			int index = 0;
			if (aop.ireg) {
				index = r_reg_getv (esil->anal->reg, aop.ireg) * aop.scale;
			}
			int j, src_imm = -1, dst_imm = -1;
			ut64 src_addr = UT64_MAX;
			ut64 dst_addr = UT64_MAX;
			for (j = 0; j < 3; j++) {
				if (aop.src[j] && aop.src[j]->reg && aop.src[j]->reg->name) {
					src_addr = r_reg_getv (esil->anal->reg, aop.src[j]->reg->name) + index;
					src_imm = aop.src[j]->delta;
				}
			}
			if (aop.dst && aop.dst->reg && aop.dst->reg->name) {
				dst_addr = r_reg_getv (esil->anal->reg, aop.dst->reg->name) + index;
				dst_imm = aop.dst->delta;
			}
			RAnalVar *var = aop.var;
			char *slink = r_type_link_at (TDB, src_addr);
			char *vlink = r_type_link_at (TDB, src_addr + src_imm);
			char *dlink = r_type_link_at (TDB, dst_addr);
			//TODO: Handle register based arg for struct offset propgation
			if (vlink && var && var->kind != 'r') {
				if (r_type_kind (TDB, vlink) == R_TYPE_UNION) {
					varpfx = "union";
				} else {
					varpfx = "struct";
				}
				// if a var addr matches with struct , change it's type and name
				// var int local_e0h --> var struct foo
				if (strcmp (var->name , vlink) && !resolved) {
					resolved = true;
					r_anal_var_retype (core->anal, fcn->addr, R_ANAL_VAR_SCOPE_LOCAL,
							-1, var->kind, varpfx, -1, var->isarg, var->name);
					r_anal_var_rename (core->anal, fcn->addr, R_ANAL_VAR_SCOPE_LOCAL,
							var->kind, var->name, vlink, false);
				}
			} else if (slink) {
				set_offset_hint (core, aop, slink, src_addr, at - ret, src_imm);
			} else if (dlink) {
				set_offset_hint (core, aop, dlink, dst_addr, at - ret, dst_imm);
			}
			if (r_anal_op_nonlinear (aop.type)) {
				r_reg_set_value (esil->anal->reg, pc, at);
				set_retval (core, at - ret);
			} else {
				r_core_esil_step (core, UT64_MAX, NULL, NULL);
			}
			free (dlink);
			free (vlink);
			free (slink);
			r_anal_op_fini (&aop);
		}
	}
beach:
	r_core_cmd0 (core, "wc-*"); // drop cache writes
	r_config_set_i (core->config, "io.cache", ioCache);
	r_config_set_i (core->config, "dbg.follow", dbg_follow);
	if (stack_set) {
		r_core_cmd0 (core, "aeim-");
	}
	r_core_seek (core, oldoff, 1);
	r_anal_esil_free (esil);
	r_reg_arena_pop (core->anal->reg);
	r_core_cmd0 (core, ".ar*");
	r_cons_break_pop ();
	free (buf);
}

static int cmd_type(void *data, const char *input) {
	RCore *core = (RCore *)data;
	Sdb *TDB = core->anal->sdb_types;
	char *res;

	switch (input[0]) {
	case 'n': // "tn"
		cmd_type_noreturn (core, input + 1);
		break;
	// t [typename] - show given type in C syntax
	case 'u': { // "tu"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_tu);
			break;
		case '*':
			if (input[2] == ' ') {
				showFormat (core, r_str_trim_ro (input + 2), 1);
			}
			break;
		case 'j':
			if (input[2]) {
				showFormat (core, r_str_trim_ro (input + 2), 'j');
			} else {
				print_keys (TDB, core, stdifunion, printkey_json_cb, true);
			}
			break;
		case ' ':
			showFormat (core, r_str_trim_ro (input + 1), 0);
			break;
		case 0:
			print_keys (TDB, core, stdifunion, printkey_cb, false);
			break;
		}
	} break;
	case 'k': // "tk"
		res = (input[1] == ' ')
			? sdb_querys (TDB, NULL, -1, input + 2)
			: sdb_querys (TDB, NULL, -1, "*");
		if (res) {
			r_cons_print (res);
			free (res);
		}
		break;
	case 'c': // "tc"
		switch (input[1]) {
		case ' ':
			r_core_cmdf (core, "k anal/cc/*~cc.%s.", input + 2);
			break;
		case '=':
			if (input[2]) {
				r_core_cmdf (core, "k anal/cc/default.cc=%s", input + 2);
			} else {
				r_core_cmd0 (core, "k anal/cc/default.cc");
			}
			break;
		case 'r':
			{ /* very slow, but im tired of waiting for having this, so this is the quickest implementation */
				int i;
				char *cc = r_str_trim (r_core_cmd_str (core, "k anal/cc/default.cc"));
				for (i = 0; i < 8; i++) {
					char *res = r_core_cmd_strf (core, "k anal/cc/cc.%s.arg%d", cc, i);
					r_str_trim_nc (res);
					if (*res) {
						char *row = r_str_trim (r_core_cmd_strf (core, "drr~%s 0x", res));
						r_cons_printf ("arg[%d] %s\n", i, row);
						free (row);
					}
					free (res);
				}
				free (cc);
			}
			break;
		case 'j':
			// TODO: json output here
			break;
		case 'l':
		case 'k':
			r_core_cmd0 (core, "k anal/cc/*");
			break;
		case 0:
			r_core_cmd0 (core, "k anal/cc/*~=cc[0]");
			break;
		default:
			r_core_cmd_help (core, help_msg_tc);
			break;
		}
		break;
	case 's': { // "ts"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_ts);
			break;
		case '*':
			if (input[2] == ' ') {
				showFormat (core, r_str_trim_ro (input + 2), 1);
			}
			break;
		case ' ':
			showFormat (core, r_str_trim_ro (input + 1), 0);
			break;
		case 's':
			if (input[2] == ' ') {
				r_cons_printf ("%d\n", (r_type_get_bitsize (TDB, input + 3) / 8));
			} else {
				r_core_cmd_help (core, help_msg_ts);
			}
			break;
		case 0:
			print_keys (TDB, core, stdifstruct, printkey_cb, false);
			break;
		case 'j': // "tsj"
			// TODO: current output is a bit poor, will be good to improve
			if (input[2]) {
				showFormat (core, r_str_trim_ro (input + 2), 'j');
				r_cons_newline ();
			} else {
				print_keys (TDB, core, stdifstruct, printkey_json_cb, true);
			}
			break;
		}
	} break;
	case 'e': { // "te"
		char *res = NULL, *temp = strchr(input, ' ');
		Sdb *TDB = core->anal->sdb_types;
		char *name = temp ? strdup (temp + 1): NULL;
		char *member_name = name ? strchr (name, ' '): NULL;

		if (member_name) {
			*member_name++ = 0;
		}
		if (name && (r_type_kind (TDB, name) != R_TYPE_ENUM)) {
			eprintf ("%s is not an enum\n", name);
			break;
		}
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_te);
			break;
		case 'j': // "tej"
			if (input[2] == 0) { // "tej"
				char *name = NULL;
				SdbKv *kv;
				SdbListIter *iter;
				SdbList *l = sdb_foreach_list (TDB, true);
				const char *comma = "";
				r_cons_printf ("{");
				ls_foreach (l, iter, kv) {
					if (!strcmp (sdbkv_value (kv), "enum")) {
						if (!name || strcmp (sdbkv_value (kv), name)) {
							free (name);
							name = strdup (sdbkv_key (kv));
							r_cons_printf ("%s\"%s\":", comma, name);
							//r_cons_printf ("%s\"%s\"", comma, name);
							{
								RList *list = r_type_get_enum (TDB, name);
								if (list && !r_list_empty (list)) {
									r_cons_printf ("{");
									RListIter *iter;
									RTypeEnum *member;
									const char *comma = "";
									r_list_foreach (list, iter, member) {
										r_cons_printf ("%s\"%s\":%d", comma, member->name, r_num_math (NULL, member->val));
										comma = ",";
									}
									r_cons_printf ("}");
								}
								r_list_free (list);
							}
							comma = ",";
						}
					}
				}
				r_cons_printf ("}\n");
				ls_free (l);
			} else { // "tej ENUM"
				RListIter *iter;
				RTypeEnum *member = R_NEW0 (RTypeEnum);
				if (member_name) {
					res = r_type_enum_member (TDB, name, NULL, r_num_math (core->num, member_name));
					// NEVER REACHED
				} else {
					RList *list = r_type_get_enum (TDB, name);
					if (list && !r_list_empty (list)) {
						r_cons_printf ("{\"name\":\"%s\",\"values\":{", name);
						const char *comma = "";
						r_list_foreach (list, iter, member) {
							r_cons_printf ("%s\"%s\":%d", comma, member->name, r_num_math (NULL, member->val));
							comma = ",";
						}
						r_cons_printf ("}}\n");
					}
					r_list_free (list);
				}
			}
			break;
		case 'b': // "teb"
			res = r_type_enum_member (TDB, name, member_name, 0);
			break;
		case ' ' :
			if (member_name) {
				res = r_type_enum_member (TDB, name, NULL, r_num_math (core->num, member_name));
			} else {
				RList *list = r_type_get_enum (TDB, name);
				RListIter *iter;
				RTypeEnum *member;
				r_list_foreach (list, iter, member) {
					r_cons_printf ("%s = %s\n", member->name, member->val);
				}
			}
			break;
		case '\0' : {
			char *name = NULL;
			SdbKv *kv;
			SdbListIter *iter;
			SdbList *l = sdb_foreach_list (TDB, true);
			ls_foreach (l, iter, kv) {
				if (!strcmp (sdbkv_value (kv), "enum")) {
					if (!name || strcmp (sdbkv_value (kv), name)) {
						free (name);
						name = strdup (sdbkv_key (kv));
						r_cons_println (name);
					}
				}
			}
			ls_free (l);
		} break;
		}
		free (name);
		if (res) {
			r_cons_println (res);
		} else if (member_name) {
			eprintf ("Invalid enum member\n");
		}
	} break;
	case ' ':
		showFormat (core, input + 1, 0);
		break;
	// t* - list all types in 'pf' syntax
	case 'j': // "tj"
	case '*': // "t*"
	case 0: // "t"
		typesList (core, input[0]);
		break;
	case 'o': // "to"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_to);
		} else if (!r_sandbox_enable (0)) {
			if (input[1] == ' ') {
				const char *filename = input + 2;
				char *homefile = NULL;
				if (*filename == '~') {
					if (filename[1] && filename[2]) {
						homefile = r_str_home (filename + 2);
						filename = homefile;
					}
				}
				if (!strcmp (filename, "-")) {
					char *tmp = r_core_editor (core, "*.h", "");
					if (tmp) {
						char *out = r_parse_c_string (core->anal, tmp);
						if (out) {
							//		r_cons_strcat (out);
							save_parsed_type (core, out);
							free (out);
						}
						free (tmp);
					}
				} else {
					char *out = r_parse_c_file (core->anal, filename);
					if (out) {
						//r_cons_strcat (out);
						save_parsed_type (core, out);
						free (out);
					}
				}
				free (homefile);
			} else if (input[1] == 's') {
				const char *dbpath = input + 3;
				if (r_file_exists (dbpath)) {
					Sdb *db_tmp = sdb_new (0, dbpath, 0);
					sdb_merge (TDB, db_tmp);
					sdb_close (db_tmp);
					sdb_free (db_tmp);
				}
			}
		} else {
			eprintf ("Sandbox: system call disabled\n");
		}
		break;
	// td - parse string with cparse engine and load types from it
	case 'd': // "td"
		if (input[1] == '?') {
			// TODO #7967 help refactor: move to detail
			r_core_cmd_help (core, help_msg_td);
			r_cons_printf ("Note: The td command should be put between double quotes\n"
				"Example: \"td struct foo {int bar;int cow;};\""
				"\nt");

		} else if (input[1] == ' ') {
			char tmp[8192];
			snprintf (tmp, sizeof (tmp) - 1, "%s;", input + 2);
			char *out = r_parse_c_string (core->anal, tmp);
			if (out) {
				save_parsed_type (core, out);
				free (out);
			}
		} else {
			eprintf ("Invalid use of td. See td? for help\n");
		}
		break;
	// ta - link immediate type offset to an address
	case 'a': // "ta"
		switch (input[1]) {
		case 's': { // "tas"
			char *off = strdup (input + 2);
			r_str_trim (off);
			int toff = r_num_math (NULL, off);
			if (toff) {
				RList *typeoffs = r_type_get_by_offset (TDB, toff);
				RListIter *iter;
				char *ty;
				r_list_foreach (typeoffs, iter, ty) {
					r_cons_printf ("%s\n", ty);
				}
				r_list_free (typeoffs);
			}
			free (off);
			break;
		}
		case 'a': { // "taa"
			char *off = r_str_trim (strdup (input + 2));
			RAnalFunction *fcn;
			RListIter *it;
			if (off && *off) {
				ut64 addr = r_num_math (NULL, off);
				fcn = r_anal_get_fcn_at (core->anal, core->offset, 0);
				if (fcn) {
					link_struct_offset (core, fcn);
				} else {
					eprintf ("cannot find function at %08"PFMT64x"\n", addr);
				}
			} else {
				if (r_list_length (core->anal->fcns) == 0) {
					eprintf ("couldn't find any functions\n");
					break;
				}
				r_list_foreach (core->anal->fcns, it, fcn) {
					if (r_cons_is_breaked ()) {
						break;
					}
					link_struct_offset (core, fcn);
				}
			}
			free (off);
		} break;
		case ' ': {
			char *type = strdup (input + 2);
			char *ptr = strchr (type, '=');
			ut64 offimm = 0;
			int i = 0;
			ut64 addr;

			if (ptr) {
				*ptr++ = 0;
				r_str_trim (ptr);
				if (ptr && *ptr) {
					addr = r_num_math (core->num, ptr);
				} else {
					eprintf ("address is unvalid\n");
					free (type);
					break;
				}
			} else {
				addr = core->offset;
			}
			r_str_trim (type);
			RAsmOp asmop;
			RAnalOp op = {0};
			ut8 code[128] = {0};
			(void)r_io_read_at (core->io, core->offset, code, sizeof (code));
			r_asm_set_pc (core->assembler, addr);
			int ret = r_asm_disassemble (core->assembler, &asmop, code, core->blocksize);
			ret = r_anal_op (core->anal, &op, core->offset, code, core->blocksize, R_ANAL_OP_MASK_VAL);
			if (ret >= 0) {
				// HACK: Just convert only the first imm seen
				for (i = 0; i < 3; i++) {
					if (op.src[i]) {
						if (op.src[i]->imm) {
							offimm = op.src[i]->imm;
						} else if (op.src[i]->delta) {
							offimm = op.src[i]->delta;
						}
					}
				}
				if (!offimm && op.dst) {
					if (op.dst->imm) {
						offimm = op.dst->imm;
					} else if (op.dst->delta) {
						offimm = op.dst->delta;
					}
				}
				if (offimm != 0) {
					// TODO: Allow to select from multiple choices
					RList* otypes = r_type_get_by_offset (TDB, offimm);
					RListIter *iter;
					char *otype = NULL;
					r_list_foreach (otypes, iter, otype) {
						if (!strcmp(type, otype)) {
							//eprintf ("Adding type offset %s\n", type);
							r_type_link_offset (TDB, type, addr);
							r_anal_hint_set_offset (core->anal, addr, otype);
							break;
						}
					}
					if (!otype) {
						eprintf ("wrong type for opcode offset\n");
					}
					r_list_free (otypes);
				}
			}
			r_anal_op_fini (&op);
			free (type);
		}
		break;
		case '?':
			r_core_cmd_help (core, help_msg_ta);
			break;
		}
		break;
	// tl - link a type to an address
	case 'l': // "tl"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_tl);
			break;
		case ' ': {
			char *type = strdup (input + 2);
			char *ptr = strchr (type, '=');
			ut64 addr;

			if (ptr) {
				*ptr++ = 0;
				r_str_trim (ptr);
				if (ptr && *ptr) {
					addr = r_num_math (core->num, ptr);
				} else {
					eprintf ("address is unvalid\n");
					free (type);
					break;
				}
			} else {
				addr = core->offset;
			}
			r_str_trim (type);
			char *tmp = sdb_get (TDB, type, 0);
			if (tmp && *tmp) {
				r_type_set_link (TDB, type, addr);
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
				if (fcn) {
					link_struct_offset (core, fcn);
				}
				free (tmp);
			} else {
				eprintf ("unknown type %s\n", type);
			}
			free (type);
			break;
		}
		case 's': {
			char *ptr = r_str_trim (strdup (input + 2));
			ut64 addr = r_num_math (NULL, ptr);
			const char *query = sdb_fmt ("link.%08" PFMT64x, addr);
			const char *link = sdb_const_get (TDB, query, 0);
			if (link) {
				print_link_readable_cb (core, query, link);
			}
			free (ptr);
			break;
		}
		case '-':
			switch (input[2]) {
			case '*':
				sdb_foreach (TDB, sdbdeletelink, core);
				break;
			case ' ': {
				const char *ptr = input + 3;
				ut64 addr = r_num_math (core->num, ptr);
				r_type_unlink (TDB, addr);
				break;
			}
			}
			break;
		case '*':
			print_keys (TDB, core, stdiflink, print_link_cb, false);
			break;
		case '\0':
			print_keys (TDB, core, stdiflink, print_link_readable_cb, false);
			break;
		}
		break;
	case 'p': { // "tp"
		char *tmp = strdup (input);
		char *ptr = r_str_trim (strchr (tmp , ' '));
		if (!ptr) {
			break;
		}
		int nargs = r_str_word_set0 (ptr);
		if (nargs > 0) {
			const char *type = r_str_word_get0 (ptr, 0);
			const char *arg = nargs > 1? r_str_word_get0 (ptr, 1): NULL;
			char *fmt = r_type_format (TDB, type);
			if (!fmt) {
				eprintf ("Cannot find '%s' type\n", type);
				break;
			}
			if (input[1] == 'x' && arg) {
				r_core_cmdf (core, "pf %s @x: %s", fmt, arg);
			} else {
				ut64 addr = arg ? r_num_math (core->num, arg): core->offset;
				if (!addr && arg) {
					RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, -1);
					addr = r_anal_var_addr (core->anal, fcn, arg);
				}
				if (addr != UT64_MAX) {
					r_core_cmdf (core, "pf %s @ 0x%08" PFMT64x "\n", fmt, addr);
				}
			}
			free (fmt);
		} else {
			eprintf ("see t?\n");
			break;
		}
		free (tmp);
	} break;
	case '-':
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_t_minus);
		} else if (input[1] == '*') {
			sdb_reset (TDB);
		} else {
			const char *name = input + 1;
			while (IS_WHITESPACE (*name)) name++;
			if (*name) {
				SdbKv *kv;
				SdbListIter *iter;
				const char *type = sdb_const_get (TDB, name, 0);
				if (!type)
					break;
				int tmp_len = strlen (name) + strlen (type);
				char *tmp = malloc (tmp_len + 1);
				r_type_del (TDB, name);
				if (tmp) {
					snprintf (tmp, tmp_len + 1, "%s.%s.", type, name);
					SdbList *l = sdb_foreach_list (TDB, true);
					ls_foreach (l, iter, kv) {
						if (!strncmp (sdbkv_key (kv), tmp, tmp_len)) {
							r_type_del (TDB, sdbkv_key (kv));
						}
					}
					ls_free (l);
					free (tmp);
				}
			} else eprintf ("Invalid use of t- . See t-? for help.\n");
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f': // "tf"
		switch (input[1]) {
		case 0:
			print_keys (TDB, core, stdiffunc, printkey_cb, false);
			break;
		case 'j':
			if (input[2] == ' ') {
				printFunctionType (core, input + 2);
				r_cons_printf ("\n");
			} else {
				print_keys (TDB, core, stdiffunc, printfunc_json_cb, true);
			}
			break;
		case ' ': {
			char *res = sdb_querys (TDB, NULL, -1, sdb_fmt ("~~func.%s", input + 2));
			if (res) {
				r_cons_printf ("%s", res);
				free (res);
			}
			break;
		}
		default:
			r_core_cmd_help (core, help_msg_tf);
			break;
		}
		break;
	case 't': {
		if (!input[1]) {
			char *name = NULL;
			SdbKv *kv;
			SdbListIter *iter;
			SdbList *l = sdb_foreach_list (TDB, true);
			ls_foreach (l, iter, kv) {
				if (!strcmp (sdbkv_value (kv), "typedef")) {
					if (!name || strcmp (sdbkv_value (kv), name)) {
						free (name);
						name = strdup (sdbkv_key (kv));
						r_cons_println (name);
					}
				}
			}
			free (name);
			ls_free (l);
			break;
		}
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_tt);
			break;
		}
		char *s = strdup (input + 2);
		const char *istypedef;
		istypedef = sdb_const_get (TDB, s, 0);
		if (istypedef && !strncmp (istypedef, "typedef", 7)) {
			const char *q = sdb_fmt ("typedef.%s", s);
			const char *res = sdb_const_get (TDB, q, 0);
			if (res)
				r_cons_println (res);
		} else {
			eprintf ("This is not an typedef\n");
		}
		free (s);
	} break;
	case '?':
		show_help (core);
		break;
	}
	return true;
}
