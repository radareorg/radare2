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
	"tp", "  <type> [addr]", "cast data at <address> to <type> and print it",
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
	"ts*", " [type]", "Show pf.<name> format string for given struct",
	"tss", " [type]", "Display size of struct",
	"ts?", "", "show this help",
	NULL
};

static const char *help_msg_tu[] = {
	"Usage: tu[...]", "", "",
	"tu", "", "List all loaded unions",
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
			if (mode) {
				r_cons_printf ("pf.%s %s\n", name, fmt);
			} else {
				r_cons_printf ("pf %s\n", fmt);
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

//TODO
//look at the next couple of functions
//can be optimized into one right ... you see it you do it :P
static int stdprintifstruct (void *p, const char *k, const char *v) {
	if (!strncmp (v, "struct", strlen ("struct") + 1)) {
		r_cons_println (k);
	}
	return 1;
}
static int stdprintiffunc (void *p, const char *k, const char *v) {
	if (!strncmp (v, "func", strlen ("func") + 1)) {
		r_cons_println (k);
	}
	return 1;
}
static int stdprintifunion (void *p, const char *k, const char *v) {
	if (!strncmp (v, "union", strlen ("union") + 1)) {
		r_cons_println (k);
	}
	return 1;
}

static int sdbdeletelink (void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	if (!strncmp (k, "link.", strlen ("link."))) {
		r_type_del (core->anal->sdb_types, k);
	}
	return 1;
}

static int linklist (void *p, const char *k, const char *v) {
	if (!strncmp (k, "link.", strlen ("link."))) {
		r_cons_printf ("tl %s = 0x%s\n", v, k + strlen ("link."));
	}
	return 1;
}
static int linklist_readable (void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	if (!strncmp (k, "link.", strlen ("link."))) {
		char *fmt = r_type_format (core->anal->sdb_types, v);
		if (!fmt) {
			eprintf("Cant fint type %s", v);
			return 1;
		}
		r_cons_printf ("(%s)\n", v);
		r_core_cmdf (core, "pf %s @ 0x%s\n", fmt, k + strlen ("link."));
	}
	return 1;

}
static int typelist_cb(void *p, const char *k, const char *v) {
	r_cons_printf ("tk %s=%s\n", k, v);
	return 1;
}

static int sdbforcb_default (void *p, const char *k, const char *v) {
	r_cons_println (k);
	return 1;
}

static int sdbforcb_json (void *p, const char *k, const char *v) {
	Sdb *sdb = (Sdb *)p;
	char *sizecmd = r_str_newf ("type.%s.size", k);
	char *size_s = sdb_querys (sdb, NULL, -1, sizecmd);
	char *formatcmd = r_str_newf ("type.%s", k);
	r_cons_printf ("{\"type\":\"%s\",\"size\":%d,\"format\":\"%s\"}", k,
			size_s ? atoi (size_s) : -1,
			r_str_trim (sdb_querys (sdb, NULL, -1, formatcmd)));
	free (sizecmd);
	free (formatcmd);
	return 1;
}

static void typesList(RCore *core, int mode) {
	switch (mode) {
	case 1:
	case '*':
		sdb_foreach (core->anal->sdb_types, typelist_cb, core);
		break;
	case 'j':
	default:
		{
		SdbList *ls = sdb_foreach_list (core->anal->sdb_types, true);
		SdbList *filtls = ls_new ();
		SdbListIter *it;
		SdbKv *kv;
		ls_foreach (ls, it, kv) {
			if (!strncmp (kv->value, "type", strlen ("type") + 1)) {
				ls_append (filtls, kv);
			}
		}
		if (mode == 'j') {
			r_cons_print ("[");
			ls_foreach (filtls, it, kv) {
				sdbforcb_json ((void *)core->anal->sdb_types, kv->key, kv->value);
				if (it->n) { r_cons_print (","); }
			}
			r_cons_println ("]");
		} else {
			ls_foreach (filtls, it, kv) {
				sdbforcb_default ((void *)core->anal->sdb_types, kv->key, kv->value);
			}
		}
		ls_free (ls);
		ls_free (filtls);
		}
		break;
	}
}

static void set_offset_hint (RCore *core, const char *type, ut64 addr, int offimm) {
	if (offimm > 0) {
		char *res = r_type_get_struct_memb (core->anal->sdb_types, type, offimm);
		if (res) {
			r_anal_hint_set_offset (core->anal, addr, res);
		}
	}
}

static void link_struct_offset (RCore *core, RAnalFunction *fcn, const char *type, ut64 taddr) {
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = {0};
	RAnalEsil *esil = core->anal->esil;
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	const char *pc_name = r_reg_get_name (core->dbg->reg, R_REG_NAME_PC);
	RRegItem *pc = r_reg_get (core->dbg->reg, pc_name, -1);

	if (!fcn) {
		return;
	}
	r_reg_arena_push (core->anal->reg);
	if (!(esil = r_anal_esil_new (stacksize, iotrap, addrsize))) {
		return;
	}
	int i, ret, bsize = R_MAX (64, core->blocksize);
	const int mininstrsz = r_anal_archinfo (core->anal, R_ANAL_ARCHINFO_MIN_OP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	ut8 *buf = malloc (bsize);
	if (!buf) {
		free (buf);
		r_anal_esil_free (esil);
		return;
	}
	ut64 oldoff = core->offset;
	r_cons_break_push (NULL, NULL);
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 at = bb->addr;
		ut64 to = bb->addr + bb->size;
		r_reg_set_value (core->dbg->reg, pc, at);
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
			if (r_anal_op_nonlinear (aop.type)) {
				r_reg_set_value (core->dbg->reg, pc, at);
			} else {
				r_core_esil_step (core, UT64_MAX, NULL, NULL);
			}
			int j, src_imm = -1, dst_imm = -1;
			ut64 src_addr, dst_addr;
			for (j = 0; j < 3; j++) {
				if (aop.src[j] && aop.src[j]->reg && aop.src[j]->reg->name) {
					src_addr = r_debug_reg_get (core->dbg, aop.src[j]->reg->name);
					src_imm = aop.src[j]->delta;
				}
			}
			if (aop.dst && aop.dst->reg && aop.dst->reg->name) {
				dst_addr = r_debug_reg_get (core->dbg, aop.dst->reg->name);
				dst_imm = aop.dst->delta;
			}
			if (type) {
				if (src_addr == taddr) {
					set_offset_hint (core, type, at - ret, src_imm);
				} else if (dst_addr == taddr) {
					set_offset_hint (core, type, at - ret, dst_imm);
				}
			} else {
				char *slink = r_type_link_at (core->anal->sdb_types, src_addr);
				char *dlink = r_type_link_at (core->anal->sdb_types, dst_addr);
				if (slink) {
					set_offset_hint (core, slink, at - ret, src_imm);
				} else if (dlink) {
					set_offset_hint (core, dlink, at - ret, dst_imm);
				}
				free (slink);
				free (dlink);
			}
			r_anal_op_fini (&aop);
		}
	}
beach:
	r_core_seek (core, oldoff, 1);
	r_anal_esil_free (esil);
	r_reg_arena_pop (core->anal->reg);
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
	case 'u': // "tu"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_tu);
			break;
		case 0:
			sdb_foreach (TDB, stdprintifunion, core);
			break;
		}
		break;
	case 'k': // "tk"
		res = (input[1] == ' ')
			? sdb_querys (TDB, NULL, -1, input + 2)
			: sdb_querys (TDB, NULL, -1, "*");
		if (res) {
			r_cons_print (res);
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
		char *name = strchr (input, ' ');
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_ts);
			break;
		case '*':
			showFormat (core, name + 1, 1);
			break;
		case ' ':
			showFormat (core, name + 1, 0);
			break;
		case 's':
			if (input[2] == ' ') {
				r_cons_printf ("%d\n", (r_type_get_bitsize (TDB, input + 3) / 8));
			} else {
				r_core_cmd_help (core, help_msg_ts);
			}
			break;
		case 0:
			sdb_foreach (TDB, stdprintifstruct, core);
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
		if (name && !r_type_isenum (TDB, name)) {
			eprintf ("%s is not an enum\n", name);
			break;
		}
		switch (input[1]) {
		case '?' :
			r_core_cmd_help (core, help_msg_te);
			break;
		case 'b' :
			res = r_type_enum_member (TDB, name, member_name, 0);
			break;
		case ' ' : {
			RListIter *iter;
			RTypeEnum *member = R_NEW0 (RTypeEnum);
			if (member_name) {
				res = r_type_enum_member (TDB, name, NULL, r_num_math (core->num, member_name));
			} else {
				RList *list = r_type_get_enum (TDB, name);
				r_list_foreach (list, iter, member) {
					r_cons_printf ("%s = %s\n", member->name, member->val);
				}
			}
		} break;
		case '\0' : {
			char *name = NULL;
			SdbKv *kv;
			SdbListIter *iter;
			SdbList *l = sdb_foreach_list (TDB, true);
			ls_foreach (l, iter, kv) {
				if (!strcmp (kv->value, "enum")) {
					if (!name || strcmp (kv->value, name)) {
						free (name);
						name = strdup (kv->key);
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
					char *out, *tmp;
					tmp = r_core_editor (core, NULL, "");
					if (tmp) {
						out = r_parse_c_string (core->anal, tmp);
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
				"Example: \" td struct foo {int bar;int cow};\""
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
					link_struct_offset (core, fcn, NULL, -1);
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
					link_struct_offset (core, fcn, NULL, -1);
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
				RAnalFunction *fcn = r_anal_get_fcn_at (core->anal, core->offset, 0);
				if (fcn) {
					link_struct_offset (core, fcn, type, addr);
				}
				free (tmp);
			} else {
				eprintf ("unknown type %s\n", type);
			}
			free (type);
			}
			break;
		case 's': {
			char *ptr = r_str_trim (strdup (input + 2));
			ut64 addr = r_num_math (NULL, ptr);
			const char* query = sdb_fmt ("link.%08"PFMT64x, addr);
			const char *link = sdb_const_get (TDB, query, 0);
			if (link) {
				linklist_readable (core, query, link);
			}
			free (ptr);
			}
			break;
		case '-':
			switch (input[2]) {
			case '*':
				sdb_foreach (TDB, sdbdeletelink, core);
				break;
			case ' ': {
				const char *ptr = input + 3;
				ut64 addr = r_num_math (core->num, ptr);
				r_type_unlink (TDB, addr);
				}
				break;
			}
			break;
		case '*':
			sdb_foreach (TDB, linklist, core);
			break;
		case '\0':
			sdb_foreach (TDB, linklist_readable, core);
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
				r_core_cmdf (core, "pf %s @ 0x%08" PFMT64x "\n", fmt, addr);
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
						if (!strncmp (kv->key, tmp, tmp_len)) {
							r_type_del (TDB, kv->key);
						}
					}
					ls_free (l);
					free (tmp);
				}
			} else eprintf ("Invalid use of t- . See t-? for help.\n");
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f':
		switch (input[1]) {
		case 0:
			sdb_foreach (TDB, stdprintiffunc, core);
			break;
		case ' ':
			r_core_cmdf (core, "tk~func.%s.", input + 2);
			break;
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
				if (!strcmp (kv->value, "typedef")) {
					if (!name || strcmp (kv->value, name)) {
						free (name);
						name = strdup (kv->key);
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
