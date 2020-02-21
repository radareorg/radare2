/* radare - LGPL - Copyright 2009-2019 - pancake, oddcoder, Anton Kochkov, Jody Frankowski */

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
	"tail", " [filename]", "Output the last part of files",
	"tc", "[type.name]", "List all/given types in C output format",
	"te", "[?]", "List all loaded enums",
	"td", "[?] <string>", "Load types from string",
	"tf", "", "List all loaded functions signatures",
	"tk", " <sdb-query>", "Perform sdb query",
	"tl", "[?]", "Show/Link type to an address",
	"tn", "[?] [-][addr]", "manage noreturn function attributes and marks",
	"to", " -", "Open cfg.editor to load types",
	"to", " <path>", "Load types from C header file",
	"toe", "[type.name]", "Open cfg.editor to edit types",
	"tos", " <path>", "Load types from parsed Sdb database",
	"tp", "  <type> [addr|varname]", "cast data at <address> to <type> and print it",
	"tpx", " <type> <hexpairs>", "Show value for type with specified byte sequence",
	"ts", "[?]", "Print loaded struct types",
	"tu", "[?]", "Print loaded union types",
	"tx", "[f?]", "Type xrefs",
	"tt", "[?]", "List all loaded typedefs",
	NULL
};

static const char *help_msg_tcc[] = {
	"Usage: tfc", "[-name]", "# type function calling conventions",
	"tcc", "", "List all calling convcentions",
	"tcc", " r0 pascal(r0,r1,r2)", "Show signature for the 'pascal' calling convention",
	"tcc", "-pascal", "Remove the pascal cc",
	"tcck", "", "List calling conventions in k=v",
	"tccl", "", "List the cc signatures",
	"tccj", "", "List them in JSON",
	"tcc*", "", "List them as r2 commands",
	NULL
};

static const char *help_msg_t_minus[] = {
	"Usage: t-", " <type>", "Delete type by its name",
	NULL
};

static const char *help_msg_tf[] = {
	"Usage: tf[...]", "", "",
	"tf", "", "List all function definitions loaded",
	"tf", " <name>", "Show function signature",
	"tfc", " <name>", "Show function signature in C syntax",
	"tfcj", " <name>", "Same as above but in JSON",
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
	"tc", "[type.name]", "List all/given loaded types in C output format with newlines",
	"tcd", "", "List all loaded types in C output format without newlines",
	"tcc", "?", "Manage calling conventions types",
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
	"tec", "<name>", "List all/given loaded enums in C output format with newlines",
	"ted", "", "List all loaded enums in C output format without newlines",
	"te?", "", "show this help",
	NULL
};

static const char *help_msg_tt[] = {
	"Usage: tt[...]", "", "",
	"tt", "", "List all loaded typedefs",
	"tt", " <typename>", "Show name for given type alias",
	"ttj", "", "Show typename and type alias in json",
	"ttc", "<name>", "Show typename and type alias in C output format",
	"tt?", "", "show this help",
	NULL
};

static const char *help_msg_tl[] = {
	"Usage: tl[...]", "[typename] [[=] address]", "# Type link commands",
	"tl", "", "list all links.",
	"tll", "", "list all links in readable format.",
	"tllj", "", "list all links in readable JSON format.",
	"tl", " [typename]", "link a type to current address.",
	"tl", " [typename] = [address]", "link type to given address.",
	"tls", " [address]", "show link at given address.",
	"tl-*", "", "delete all links.",
	"tl-", " [address]", "delete link at given address.",
	"tl*", "", "list all links in radare2 command format.",
	"tlj", "", "list all links in JSON format.",
	NULL
};

static const char *help_msg_tn[] = {
	"Usage:", "tn [-][0xaddr|symname]", " manage no-return marks",
	"tn[a]", " 0x3000", "stop function analysis if call/jmp to this address",
	"tn[n]", " sym.imp.exit", "same as above but for flag/fcn names",
	"tn-", " 0x3000 sym.imp.exit ...", "remove some no-return references",
	"tn-*", "", "remove all no-return references",
	"tn", "", "list them all",
	NULL
};

static const char *help_msg_ts[] = {
	"Usage: ts[...]", " [type]", "",
	"ts", "", "List all loaded structs",
	"ts", " [type]", "Show pf format string for given struct",
	"tsj", "", "List all loaded structs in json",
	"tsj", " [type]", "Show pf format string for given struct in json",
	"ts*", "", "Show pf.<name> format string for all loaded structs",
	"ts*", " [type]", "Show pf.<name> format string for given struct",
	"tsc", "<name>", "List all/given loaded structs in C output format with newlines",
	"tsd", "", "List all loaded structs in C output format without newlines", 
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
	"tu*", "", "Show pf.<name> format string for all loaded unions",
	"tu*", " [type]", "Show pf.<name> format string for given union",
	"tuc", "<name>", "List all/given loaded unions in C output format with newlines",
	"tud", "", "List all loaded unions in C output format without newlines",
	"tu?", "", "show this help",
	NULL
};

static void cmd_type_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, t);
	DEFINE_CMD_DESCRIPTOR_SPECIAL (core, t-, t_minus);
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

static void __core_cmd_tcc(RCore *core, const char *input) {
	switch (*input) {
	case '?':
		r_core_cmd_help (core, help_msg_tcc);
		break;
	case '-':
		r_anal_cc_del (core->anal, r_str_trim_head_ro (input + 1));
		break;
	case 0:
		r_core_cmd0 (core, "afcl");
		break;
	case 'j':
		{
			char *ccs = r_core_cmd_strf (core, "afcl");
			r_str_trim_head_tail (ccs);
			RList *list = r_str_split_list (ccs, "\n", 0);
			RListIter *iter;
			const char *cc;
			PJ *pj = pj_new ();
			pj_a (pj);
			r_list_foreach (list, iter, cc) {
				char *ccexpr = r_anal_cc_get (core->anal, cc);
				// TODO: expose this as an object, not just an array of strings
				pj_s (pj, ccexpr);
				free (ccexpr);
			}
			pj_end (pj);
			r_cons_printf ("%s\n", pj_string (pj));
			pj_free (pj);
			r_list_free (list);
			free (ccs);
		}
		break;
	case 'l':
		{
			char *ccs = r_core_cmd_strf (core, "afcl");
			r_str_trim_head_tail (ccs);
			RList *list = r_str_split_list (ccs, "\n", 0);
			RListIter *iter;
			const char *cc;
			r_list_foreach (list, iter, cc) {
				char *ccexpr = r_anal_cc_get (core->anal, cc);
				r_cons_printf ("%s\n", ccexpr);
				free (ccexpr);
			}
			r_list_free (list);
			free (ccs);
		}
		break;
	case '*':
		{
			char *ccs = r_core_cmd_strf (core, "afcl");
			r_str_trim_head_tail (ccs);
			RList *list = r_str_split_list (ccs, "\n", 0);
			RListIter *iter;
			const char *cc;
			r_list_foreach (list, iter, cc) {
				char *ccexpr = r_anal_cc_get (core->anal, cc);
				r_cons_printf ("tfc %s\n", ccexpr);
				free (ccexpr);
			}
			r_list_free (list);
			free (ccs);
		}
		break;
	case 'k':
		r_core_cmd0 (core, "afck");
		break;
	case ' ':
		if (strchr (input, '(')) {
			r_anal_cc_set (core->anal, input + 1);
		} else {
			char *cc = r_anal_cc_get (core->anal, input + 1);
			if (cc) {
				r_cons_printf ("%s\n", cc);
				free (cc);
			}
		}
		break;
	}
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
				PJ *pj = pj_new ();
				if (!pj) {
					return;
				}
				pj_o (pj);
				pj_ks (pj, "name", name);
				pj_ks (pj, "format", fmt);
				pj_end (pj);
				r_cons_printf ("%s", pj_string (pj));
				pj_free (pj);
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

static int cmd_tail(void *data, const char *_input) { // "tail"
	char *input = strdup (_input);
	RCore *core = (RCore *)data;
	int lines = 5;
	char *arg = strchr (input, ' ');
	char *tmp, *count;
	if (arg) {
		arg = (char *)r_str_trim_head_ro (arg + 1); 	// contains "count filename"
		count = strchr (arg, ' ');
		if (count) {
			*count = 0;	// split the count and file name
			tmp = (char *)r_str_trim_head_ro (count + 1);
			lines = atoi (arg);
			arg = tmp;
		}
	}
	switch (*input) {
	case '?': // "tail?"
		eprintf ("Usage: tail [file] # to list last n lines in file\n");
		break;
	default: // "tail"
		if (!arg) {
			arg = "";
		}
		if (r_fs_check (core->fs, arg)) {
			r_core_cmdf (core, "md %s", arg);
		} else {
			char *res = r_syscmd_tail (arg, lines);
			if (res) {
				r_cons_print (res);
				free (res);
			}
		}
		break;
	}
	free (input);
	return 0;
}

static void cmd_type_noreturn(RCore *core, const char *input) {
	switch (input[0]) {
	case '-': // "tn-"
		if (input[1] == '*') {
			r_core_cmd0 (core, "tn-`tn`");
		} else {
			char *s = strdup (r_str_trim_head_ro (input + 1));
			RListIter *iter;
			char *k;
			RList *list = r_str_split_list (s, " ", 0);
			r_list_foreach (list, iter, k) {
				r_anal_noreturn_drop (core->anal, k);
			}
			r_list_free (list);
			free (s);
		}
		break;
	case ' ': // "tn"
		{
			const char *arg = r_str_trim_head_ro (input + 1);
			ut64 n = r_num_math (core->num, arg);
			if (n) {
				r_anal_noreturn_add (core->anal, arg, n);
			} else {
				r_anal_noreturn_add (core->anal, arg, UT64_MAX);
			}
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
			r_anal_noreturn_add (core->anal, r_str_trim_head_ro (input + 2), UT64_MAX);
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

static Sdb *TDB_ = NULL; // HACK

static int stdifstruct(void *user, const char *k, const char *v) {
	r_return_val_if_fail (TDB_, false);
	if (!strcmp (v, "struct")) {
		return true;
	}
	if (!strcmp (v, "typedef")) {
		const char *typedef_key = sdb_fmt ("typedef.%s", k);
		const char *type = sdb_const_get (TDB_, typedef_key, NULL);
		if (type && r_str_startswith (type, "struct ")) {
			return true;
		}
	}
	return false;
}

/*!
 * \brief print the data types details in JSON format
 * \param TDB pointer to the sdb for types
 * \param filter a callback function for the filtering
 * \return 1 if success, 0 if failure
 */
static int print_struct_union_list_json(Sdb *TDB, SdbForeachCallback filter) {
	PJ *pj = pj_new ();
	if (!pj) {
		return 0;
	}
	SdbList *l = sdb_foreach_list_filter (TDB, filter, true);
	SdbListIter *it;
	SdbKv *kv;

	pj_a (pj); // [
	ls_foreach (l, it, kv) {
		const char *k = sdbkv_key (kv);
		if (!k || !*k) {
			continue;
		}

		pj_o (pj); // {
		char *sizecmd = r_str_newf ("%s.%s.!size", sdbkv_value (kv), k);
		if (!sizecmd) {
			break;
		}
		char *size_s = sdb_querys (TDB, NULL, -1, sizecmd);
		pj_ks (pj, "type", k); // key value pair of string and string
		pj_ki (pj, "size", size_s ? atoi (size_s) : 0); // key value pair of string and int
		pj_end (pj); // }

		free (sizecmd);
		free (size_s);
	}
	pj_end (pj); // ]

	r_cons_println (pj_string (pj));
	pj_free (pj);
	ls_free (l);
	return 1;
}

static void print_struct_union_in_c_format(Sdb *TDB, SdbForeachCallback filter, const char *arg, bool multiline) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list_filter (TDB, filter, true);
	const char *space = "";
	bool match = false;

	ls_foreach (l, iter, kv) {
		if (name && !strcmp (sdbkv_value (kv), name)) {
			continue;
		}
		free (name);
		int n;
		name = strdup (sdbkv_key (kv));
		if (name && (arg && *arg)) {
			if (!strcmp (arg, name)) {
				match = true;
			} else {
				continue;
			}
		}
		r_cons_printf ("%s %s {%s", sdbkv_value (kv), name, multiline? "\n": "");
		char *p, *var = r_str_newf ("%s.%s", sdbkv_value (kv), name);
		for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
			char *var2 = r_str_newf ("%s.%s", var, p);
			if (var2) {
				char *val = sdb_array_get (TDB, var2, 0, NULL);
				if (val) {
					if (multiline) {
						r_cons_printf ("\t%s", val);
						if (p && p[0] != '\0') {
							r_cons_printf ("%s%s", strstr (val, " *")? "": " ", p);
						}
					} else {
						r_cons_printf ("%s%s %s;", space, val, p);
						space = " ";
					}
				}
				if (multiline) {
					r_cons_println (";");
				}
				free (val);
			}
			free (var2);
			free (p);
		}
		free (var);
		r_cons_println ("};");
		space = "";
		if (match) {
			break;
		}
	}
	free (name);
	ls_free (l);
}

static void print_enum_in_c_format(Sdb *TDB, const char *arg, bool multiline) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list (TDB, true);
	const char *separator = "";
	bool match = false;
	ls_foreach (l, iter, kv) {
		if (!strcmp (sdbkv_value (kv), "enum")) {
			if (!name || strcmp (sdbkv_value (kv), name)) {
				free (name);
				name = strdup (sdbkv_key (kv));
				if (name && (arg && *arg)) {
					if (!strcmp (arg, name)) {
						match = true;
					} else {
						continue;
					}
				}
				r_cons_printf ("%s %s {%s", sdbkv_value (kv), name, multiline? "\n": "");
				{
					RList *list = r_type_get_enum (TDB, name);
					if (list && !r_list_empty (list)) {
						RListIter *iter;
						RTypeEnum *member;
						separator = multiline? "\t": "";
						r_list_foreach (list, iter, member) {
							r_cons_printf ("%s%s = %d", separator, member->name, r_num_math (NULL, member->val));
							separator = multiline? ",\n\t": ", ";
						}
					}
					r_list_free (list);
				}
				r_cons_println (multiline? "\n};": "};");
				if (match) {
					break;
				}
			}
		}
	}
	free (name);
	ls_free (l);
}

static int printkey_cb(void *user, const char *k, const char *v) {
	r_cons_println (k);
	return 1;
}

// maybe dupe?. should return char *instead of print for reusability
static void printFunctionTypeC(RCore *core, const char *input) {
	Sdb *TDB = core->anal->sdb_types;
	char *res = sdb_querys (TDB, NULL, -1, sdb_fmt ("func.%s.args", input));
	const char *name = r_str_trim_head_ro (input);
	int i, args = sdb_num_get (TDB, sdb_fmt ("func.%s.args", name), 0);
	const char *ret = sdb_const_get (TDB, sdb_fmt ("func.%s.ret", name), 0);
	if (!ret || !name) {
		// missing function name specified
		return;
	}

	r_cons_printf ("%s %s (", ret, name);
	for (i = 0; i < args; i++) {
		char *type = sdb_get (TDB, sdb_fmt ("func.%s.arg.%d", name, i), 0);
		char *name = strchr (type, ',');
		if (name) {
			*name++ = 0;
		}
		r_cons_printf ("%s%s %s", i==0? "": ", ", type, name);
	}
	r_cons_printf (");\n");
	free (res);
}

static void printFunctionType(RCore *core, const char *input) {
	Sdb *TDB = core->anal->sdb_types;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	char *res = sdb_querys (TDB, NULL, -1, sdb_fmt ("func.%s.args", input));
	const char *name = r_str_trim_head_ro (input);
	int i, args = sdb_num_get (TDB, sdb_fmt ("func.%s.args", name), 0);
	pj_ks (pj, "name", name);
	pj_ks (pj, "ret", sdb_const_get (TDB, sdb_fmt ("func.%s.ret", name), 0));
	pj_k (pj, "args");
	pj_a (pj);
	for (i = 0; i < args; i++) {
		char *type = sdb_get (TDB, sdb_fmt ("func.%s.arg.%d", name, i), 0);
		if (!type) {
			continue;
		}
		char *name = strchr (type, ',');
		if (name) {
			*name++ = 0;
		}
		pj_o (pj);
		pj_ks (pj, "type", type);
		if (name) {
			pj_ks (pj, "name", name);
		} else {
			pj_ks (pj, "name", "(null)");
		}
		pj_end (pj);
	}
	pj_end (pj);
	pj_end (pj);
	r_cons_printf ("%s", pj_string (pj));
	pj_free (pj);
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
	r_cons_printf ("0x%s = %s\n", k + strlen ("link."), v);
	return 1;
}

static int print_link_json_cb(void *p, const char *k, const char *v) {
	r_cons_printf ("{\"0x%s\":\"%s\"}", k + strlen ("link."), v);
	return 1;
}

static int print_link_r_cb(void *p, const char *k, const char *v) {
	r_cons_printf ("tl %s = 0x%s\n", v, k + strlen ("link."));
	return 1;
}

static int print_link_readable_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	char *fmt = r_type_format (core->anal->sdb_types, v);
	if (!fmt) {
		eprintf ("Can't fint type %s", v);
		return 1;
	}
	r_cons_printf ("(%s)\n", v);
	r_core_cmdf (core, "pf %s @ 0x%s\n", fmt, k + strlen ("link."));
	return 1;
}

static int print_link_readable_json_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	char *fmt = r_type_format (core->anal->sdb_types, v);
	if (!fmt) {
		eprintf ("Can't fint type %s", v);
		return 1;
	}
	r_cons_printf ("{\"%s\":", v);
	r_core_cmdf (core, "pfj %s @ 0x%s\n", fmt, k + strlen ("link."));
	r_cons_printf ("}");
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
	PJ *pj = pj_new ();
	pj_o (pj);
	Sdb *sdb = core->anal->sdb_types;
	char *sizecmd = r_str_newf ("type.%s.size", k);
	char *size_s = sdb_querys (sdb, NULL, -1, sizecmd);
	char *formatcmd = r_str_newf ("type.%s", k);
	char *format_s = sdb_querys (sdb, NULL, -1, formatcmd);
	r_str_trim (format_s);
	pj_ks (pj, "type", k);
	pj_ki (pj, "size", size_s ? atoi (size_s) : -1);
	pj_ks (pj, "format", format_s);
	pj_end (pj);
	r_cons_printf ("%s", pj_string (pj));
	pj_free (pj);
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

static void set_offset_hint(RCore *core, RAnalOp *op, const char *type, ut64 laddr, ut64 at, int offimm) {
	char *res = r_type_get_struct_memb (core->anal->sdb_types, type, offimm);
	const char *cmt = ((offimm == 0) && res)? res: type;
	if (offimm > 0) {
		// set hint only if link is present
		char* query = sdb_fmt ("link.%08"PFMT64x, laddr);
		if (res && sdb_const_get (core->anal->sdb_types, query, 0)) {
			r_anal_hint_set_offset (core->anal, at, res);
		}
	} else if (cmt && r_anal_op_ismemref (op->type)) {
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

R_API void r_core_link_stroff(RCore *core, RAnalFunction *fcn) {
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = {0};
	bool ioCache = r_config_get_i (core->config, "io.cache");
	bool stack_set = false;
	bool resolved = false;
	const char *varpfx;
	int dbg_follow = r_config_get_i (core->config, "dbg.follow");
	Sdb *TDB = core->anal->sdb_types;
	RAnalEsil *esil;
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
		// reset stack pointer to initial value
		RRegItem *sp = r_reg_get (esil->anal->reg, sp_name, -1);
		ut64 curpc = r_reg_getv (esil->anal->reg, pc_name);
		int stacksz = r_core_get_stacksz (core, fcn->addr, curpc);
		if (stacksz > 0) {
			r_reg_arena_zero (esil->anal->reg); // clear prev reg values
			r_reg_set_value (esil->anal->reg, sp, spval + stacksz);
		}
	} else {
		// initialize stack
		r_core_cmd0 (core, "aeim");
		stack_set = true;
	}
	r_config_set_i (core->config, "io.cache", 1);
	r_config_set_i (core->config, "dbg.follow", 0);
	ut64 oldoff = core->offset;
	r_cons_break_push (NULL, NULL);
	r_list_sort (fcn->bbs, bb_cmpaddr); // TODO: The algorithm can be more accurate if blocks are followed by their jmp/fail, not just by address
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
				set_offset_hint (core, &aop, slink, src_addr, at - ret, src_imm);
			} else if (dlink) {
				set_offset_hint (core, &aop, dlink, dst_addr, at - ret, dst_imm);
			}
			if (r_anal_op_nonlinear (aop.type)) {
				r_reg_set_value (esil->anal->reg, pc, at);
				set_retval (core, at - ret);
			} else {
				r_core_esil_step (core, UT64_MAX, NULL, NULL, false);
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
	TDB_ = TDB; // HACK

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
				showFormat (core, r_str_trim_head_ro (input + 2), 1);
			} else {
				SdbList *l = sdb_foreach_list_filter (TDB, stdifunion, true);
				SdbListIter *it;
				SdbKv *kv;
				ls_foreach (l, it, kv) {
					showFormat (core, sdbkv_key (kv), 1);
				}
				ls_free (l);
			}
			break;
		case 'j': // "tuj"
			if (input[2]) {
				showFormat (core, r_str_trim_head_ro (input + 2), 'j');
				r_cons_newline ();
			} else {
				print_struct_union_list_json (TDB, stdifunion);
			}
			break;
		case 'c':
			print_struct_union_in_c_format (TDB, stdifunion, r_str_trim_head_ro (input + 2), true);
			break;
		case 'd':
			print_struct_union_in_c_format (TDB, stdifunion, r_str_trim_head_ro (input + 2), false);
			break;	
		case ' ':
			showFormat (core, r_str_trim_head_ro (input + 1), 0);
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
		case 'c': // "tcc" -- calling conventions
			__core_cmd_tcc (core, input + 2);
			break;
		case '?': //"tc?"
			r_core_cmd_help (core, help_msg_tc);
			break;
		case ' ': {
			const char *type = r_str_trim_head_ro (input + 1);
			const char *name = type ? strchr (type, '.') + 1: NULL;
			if (name && type) {
				if (r_str_startswith (type, "struct")) {
					r_core_cmdf (core, "tsc %s", name);
				} else if (r_str_startswith (type, "union")) {
					r_core_cmdf (core, "tuc %s", name);
				} else if (r_str_startswith (type, "enum")) {
					r_core_cmdf (core, "tec %s", name);
				} else if (r_str_startswith (type, "typedef")) {
					r_core_cmdf (core, "ttc %s", name);
				} else if (r_str_startswith (type, "func")) {
					r_core_cmdf (core, "tfc %s", name);
				}
			}
			break;
		}
		case 0:
			r_core_cmd0 (core, "tfc;tuc;tsc;ttc;tec");
			break;
		case 'd':
			r_core_cmd0 (core, "tud;tsd;ttc;ted");
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
				showFormat (core, r_str_trim_head_ro (input + 2), 1);
			} else {
				SdbList *l = sdb_foreach_list_filter (TDB, stdifstruct, true);
				SdbListIter *it;
				SdbKv *kv;

				ls_foreach (l, it, kv) {
					showFormat (core, sdbkv_key (kv), 1);
				}
				ls_free (l);
			}
			break;
		case ' ':
			showFormat (core, r_str_trim_head_ro (input + 1), 0);
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
		case 'c':
			print_struct_union_in_c_format (TDB, stdifstruct, r_str_trim_head_ro (input + 2), true);
			break;
		case 'd':
			print_struct_union_in_c_format (TDB, stdifstruct, r_str_trim_head_ro (input + 2), false);
			break;
		case 'j': // "tsj"
			// TODO: current output is a bit poor, will be good to improve
			if (input[2]) {
				showFormat (core, r_str_trim_head_ro (input + 2), 'j');
				r_cons_newline ();
			} else {
				print_struct_union_list_json (TDB, stdifstruct);
			}
			break;
		}
	} break;
	case 'e': { // "te"
		char *res = NULL, *temp = strchr (input, ' ');
		Sdb *TDB = core->anal->sdb_types;
		char *name = temp ? strdup (temp + 1): NULL;
		char *member_name = name ? strchr (name, ' '): NULL;

		if (member_name) {
			*member_name++ = 0;
		}
		if (name && (r_type_kind (TDB, name) != R_TYPE_ENUM)) {
			eprintf ("%s is not an enum\n", name);
			free (name);
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
				PJ *pj = pj_new ();
				pj_o (pj);
				ls_foreach (l, iter, kv) {
					if (!strcmp (sdbkv_value (kv), "enum")) {
						if (!name || strcmp (sdbkv_value (kv), name)) {
							free (name);
							name = strdup (sdbkv_key (kv));
							pj_k (pj, name);
							{
								RList *list = r_type_get_enum (TDB, name);
								if (list && !r_list_empty (list)) {
									pj_o (pj);
									RListIter *iter;
									RTypeEnum *member;
									r_list_foreach (list, iter, member) {
										pj_kn (pj, member->name, r_num_math (NULL, member->val));
									}
									pj_end (pj);
								}
								r_list_free (list);
							}
						}
					}
				}
				pj_end (pj);
				r_cons_printf ("%s\n", pj_string (pj));
				pj_free (pj);
				free (name);
				ls_free (l);
			} else { // "tej ENUM"
				RListIter *iter;
				PJ *pj = pj_new ();
				RTypeEnum *member;
				pj_o (pj);
				if (member_name) {
					res = r_type_enum_member (TDB, name, NULL, r_num_math (core->num, member_name));
					// NEVER REACHED
				} else {
					RList *list = r_type_get_enum (TDB, name);
					if (list && !r_list_empty (list)) {
						pj_ks (pj, "name", name);
						pj_k (pj, "values");
						pj_o (pj);
						r_list_foreach (list, iter, member) {
							pj_kn (pj, member->name, r_num_math (NULL, member->val));
						}
						pj_end (pj);
						pj_end (pj);
					}
					r_cons_printf ("%s\n", pj_string (pj));
					pj_free (pj);
					r_list_free (list);
				}
			}
			break;
		case 'b': // "teb"
			res = r_type_enum_member (TDB, name, member_name, 0);
			break;
		case 'c': // "tec"
			print_enum_in_c_format(TDB, r_str_trim_head_ro (input + 2), true);
			break;
		case 'd':
			print_enum_in_c_format(TDB, r_str_trim_head_ro (input + 2), false);
			break;
		case ' ':
			if (member_name) {
				res = r_type_enum_member (TDB, name, NULL, r_num_math (core->num, member_name));
			} else {
				RList *list = r_type_get_enum (TDB, name);
				RListIter *iter;
				RTypeEnum *member;
				r_list_foreach (list, iter, member) {
					r_cons_printf ("%s = %s\n", member->name, member->val);
				}
				r_list_free (list);
			}
			break;
		case '\0': {
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
			free (name);
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
				const char *dir = r_config_get (core->config, "dir.types");
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
						char *error_msg = NULL;
						char *out = r_parse_c_string (core->anal, tmp, &error_msg);
						if (out) {
							//		r_cons_strcat (out);
							r_anal_save_parsed_type (core->anal, out);
							free (out);
						}
						if (error_msg) {
							fprintf (stderr, "%s", error_msg);
							free (error_msg);
						}
						free (tmp);
					}
				} else {
					char *error_msg = NULL;
					char *out = r_parse_c_file (core->anal, filename, dir, &error_msg);
					if (out) {
						//r_cons_strcat (out);
						r_anal_save_parsed_type (core->anal, out);
						free (out);
					}
					if (error_msg) {
						fprintf (stderr, "%s", error_msg);
						free (error_msg);
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
			}  else if (input[1] == 'e') { // "toe"
				char *str = r_core_cmd_strf (core , "tc %s", input + 2);
				char *tmp = r_core_editor (core, "*.h", str);
				if (tmp) {
					char *error_msg = NULL;
					char *out = r_parse_c_string (core->anal, tmp, &error_msg);
					if (out) {
						// remove previous types and save new edited types
						sdb_reset (TDB);
						r_parse_c_reset (core->parser);
						r_anal_save_parsed_type (core->anal, out);
						free (out);
					}
					if (error_msg) {
						eprintf ("%s\n", error_msg);
						free (error_msg);
					}
					free (tmp);
				}
				free (str);
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
			char *tmp = r_str_newf ("%s;", input + 2);
			if (!tmp) {
				break;
			}
			char *error_msg = NULL;
			char *out = r_parse_c_string (core->anal, tmp, &error_msg);
			free (tmp);
			if (out) {
				r_anal_save_parsed_type (core->anal, out);
				free (out);
			}
			if (error_msg) {
				fprintf (stderr, "%s", error_msg);
				free (error_msg);
			}
		} else {
			eprintf ("Invalid use of td. See td? for help\n");
		}
		break;
	case 'x': {
		  char *type, *type2;
		RListIter *iter, *iter2;
		  RAnalFunction *fcn;
		switch (input[1]) {
		case '.': // "tx." type xrefs 
		case 'f': // "txf" type xrefs 
			fcn  = r_anal_get_function_at (core->anal, core->offset);
			if (fcn) {
				RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
				r_list_foreach (uniq , iter , type) {
					r_cons_println (type);
				}
				r_list_free (uniq);
			} else {
				eprintf ("cannot find function at 0x%08"PFMT64x"\n", core->offset);
			}
			break;
		case 0: // "tx"
			r_list_foreach (core->anal->fcns, iter, fcn) {
				RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
				if (r_list_length (uniq)) {
					r_cons_printf ("%s: ", fcn->name);
				}
				r_list_foreach (uniq , iter2, type) {
					r_cons_printf ("%s%s", type, iter2->n ? ",":"\n");
				}
			}
			break;
		case 'g': // "txg"
			{
				r_list_foreach (core->anal->fcns, iter, fcn) {
					RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
					if (r_list_length (uniq)) {
						r_cons_printf ("agn %s\n", fcn->name);
					}
					r_list_foreach (uniq , iter2, type) {
						char *myType = strdup (type);
						r_str_replace_ch (myType, ' ', '_', true);
						r_cons_printf ("agn %s\n", myType);
						r_cons_printf ("age %s %s\n", myType, fcn->name);
						free (myType);
					}
				}
			}
			break;
		case 'l': // "txl"
			{
				RList *uniqList = r_list_newf (free);
				r_list_foreach (core->anal->fcns, iter, fcn) {
					RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
					r_list_foreach (uniq , iter2, type) {
						if (!r_list_find (uniqList, type, (RListComparator)strcmp)) {
							r_list_push (uniqList, strdup (type));
						}
					}
				}
				r_list_sort (uniqList, (RListComparator)strcmp);
				r_list_foreach (uniqList, iter, type) {
					r_cons_printf ("%s\n", type);
				}
				r_list_free (uniqList);
			}
			break;
		case ' ': // "tx " -- show which function use given type
			type = (char *)r_str_trim_head_ro (input + 2);
			r_list_foreach (core->anal->fcns, iter, fcn) {
				RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
				r_list_foreach (uniq , iter2, type2) {
					if (!strcmp (type2, type)) {
						r_cons_printf ("%s\n", fcn->name);
						break;
					}
				}
			}
			break;
		default:
			eprintf ("Usage: tx[flg] [...]\n");
			eprintf (" txf | tx.      list all types used in this function\n");
			eprintf (" txl            list all types used by any function\n");
			eprintf (" txg            render the type xrefs graph\n");
			eprintf (" tx  int32_t    list functions names using this type\n");
			eprintf (" tx             list functions and the types they use\n");
			break;
		}
	} break;
	// ta: moved to anal hints (aht)- just for tail, at the moment
	case 'a': // "ta"
		switch (input[1]) {
		case 'i': { // "tai"
			if (input[2] == 'l') {
				cmd_tail (core, input);
			} else {
				eprintf ("Usage: tail [number] [file]\n");
			}
		} break;
		default:
			eprintf ("[WARNING] \"ta\" is deprecated. Use \"aht\" instead.\n");
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
					r_core_link_stroff (core, fcn);
				}
				free (tmp);
			} else {
				eprintf ("unknown type %s\n", type);
			}
			free (type);
			break;
		}
		case 's': {
			char *ptr = r_str_trim_dup (input + 2);
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
			print_keys (TDB, core, stdiflink, print_link_r_cb, false);
			break;
		case 'l':
			switch (input[2]) {
			case 'j':
				print_keys (TDB, core, stdiflink, print_link_readable_json_cb, true);
				break;
			default:
				print_keys (TDB, core, stdiflink, print_link_readable_cb, false);
				break;
			}
			break;
		case 'j':
			print_keys (TDB, core, stdiflink, print_link_json_cb, true);
			break;
		case '\0':
			print_keys (TDB, core, stdiflink, print_link_cb, false);
			break;
		}
		break;
	case 'p':  // "tp"
		if (input[1] == '?') { // "tp?"
			r_core_cmd0 (core, "t?~tp\n");
		} else { // "tp"
			char *tmp = strdup (input);
			char *ptr = strchr (tmp, ' ');
			if (!ptr) {
				break;
			}
			r_str_trim (ptr);
			int nargs = r_str_word_set0 (ptr);
			if (nargs > 0) {
				const char *type = r_str_word_get0 (ptr, 0);
				const char *arg = (nargs > 1)? r_str_word_get0 (ptr, 1): NULL;
				char *fmt = r_type_format (TDB, type);
				if (!fmt) {
					eprintf ("Cannot find '%s' type\n", type);
					break;
				}
				if (input[1] == 'x' && arg) { // "tpx"
					r_core_cmdf (core, "pf %s @x:%s", fmt, arg);
					eprintf ("pf %s @x:%s", fmt, arg);
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
		}
		break;
	case '-': // "t-"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_t_minus);
		} else if (input[1] == '*') {
			sdb_reset (TDB);
			r_parse_c_reset (core->parser);
		} else {
			const char *name = input + 1;
			while (IS_WHITESPACE (*name)) name++;
			if (*name) {
				r_anal_remove_parsed_type (core->anal, name);
			} else {
				eprintf ("Invalid use of t- . See t-? for help.\n");
			}
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f': // "tf"
		switch (input[1]) {
		case 0:
			print_keys (TDB, core, stdiffunc, printkey_cb, false);
			break;
		case 'c': // "tfc"
			printFunctionTypeC (core, input + 2);
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
		if (!input[1] || input[1] == 'j') {
			PJ *pj = NULL;
			if (input[1] == 'j') {
				pj = pj_new ();
				pj_o (pj);
			}
			char *name = NULL;
			SdbKv *kv;
			SdbListIter *iter;
			SdbList *l = sdb_foreach_list (TDB, true);
			ls_foreach (l, iter, kv) {
				if (!strcmp (sdbkv_value (kv), "typedef")) {
					if (!name || strcmp (sdbkv_value (kv), name)) {
						free (name);
						name = strdup (sdbkv_key (kv));
						if (!input[1]) {
							r_cons_println (name);
						} else {
							const char *q = sdb_fmt ("typedef.%s", name);
							const char *res = sdb_const_get (TDB, q, 0);
							pj_ks (pj, name, res);
						}
					}
				}
			}
			if (input[1] == 'j') {
				pj_end (pj);
			}
			if (pj) {
				r_cons_printf ("%s\n", pj_string (pj));
				pj_free (pj);
			}
			free (name);
			ls_free (l);
			break;
		}
		if (input[1] == 'c') {
			char *name = NULL;
			SdbKv *kv;
			SdbListIter *iter;
			SdbList *l = sdb_foreach_list (TDB, true);
			const char *arg = r_str_trim_head_ro (input + 2);
			bool match = false;
			ls_foreach (l, iter, kv) {
				if (!strcmp (sdbkv_value (kv), "typedef")) {
					if (!name || strcmp (sdbkv_value (kv), name)) {
						free (name);
						name = strdup (sdbkv_key (kv));
						if (name && (arg && *arg)) {
							if (!strcmp (arg, name)) {
								match = true;
							} else {
								continue;
							}
						}
						const char *q = sdb_fmt ("typedef.%s", name);
						const char *res = sdb_const_get (TDB, q, 0);
						if (res) {
							r_cons_printf ("%s %s %s;\n", sdbkv_value (kv), res, name);
						}
						if (match) {
							break;
						}
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
