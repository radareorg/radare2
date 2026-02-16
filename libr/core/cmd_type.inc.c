/* radare - LGPL - Copyright 2009-2026 - pancake, oddcoder, Anton Kochkov, Jody Frankowski */

#if R_INCLUDE_BEGIN

// clang-format off

static RCoreHelpMessage help_msg_t = {
	"Usage: t", "", "Parse, manage, and print C types",
	"t", "", "list all loaded types",
	"tj", "", "list all loaded types as json",
	"t", " <type>", "show type in 'pf' syntax",
	"t*", "", "list types info in r2 commands",
	"t-", " <name> [name2..]", "delete type(s) by name (supports glob with *)",
	"t-*", "", "remove all types",
	"tail", "([n]) [file]", "output the last n lines of a file (default n=5)",
	"tac", " [file]", "the infamous reverse cat command",
	"tc", "[?] [type.name]", "list all/given types in C output format",
	"td", " <string>", "load types from string (quote the whole command: \"td ...\")",
	"te", "[?]", "list all loaded enums",
	"tf", "[?]", "list all loaded functions signatures",
	"tk", " <sdb-query>", "perform sdb query",
	"tl", "[?]", "show/Link type to an address",
	"tn", "[?] [-][addr]", "manage noreturn function attributes and marks",
	"to", "[?] <path>", "load types from C header file",
	"tp", "[?]  <type> [addr|varname]", "cast data at <address> to <type> and print it (XXX: type can contain spaces)",
	"ts", "[?]", "print loaded struct types",
	"tt", "[?]", "list all loaded typedefs",
	"tu", "[?]", "print loaded union types",
	"tv", "[?]", "view types with offsets and xrefs",
	"tx", "[?]", "type xrefs",
	NULL
};

static RCoreHelpMessage help_msg_tv = {
	"Usage: tv[...]", " [type]", "View types with offsets and xrefs",
	"tv", "", "list all types with offsets (structs, unions, enums, types)",
	"tv", " [type]", "show specific type with offsets and xrefs",
	NULL
};

static RCoreHelpMessage help_msg_tx = {
	"Usage: tx[.tflg]", "[...]", "Function types",
	"tx", "", "list functions and the types they use",
	"tx.", "", "same as txf",
	"tx", " int32_t", "list functions names using this type",
	"txt", " int32_t", "same as 'tx type'",
	"txf", " ([addr])", "list all types used in the current or given function (same as tx.)",
	"txl", "", "list all types used by any function",
	"txg", "", "render the type xrefs graph (usage .txg;aggv)",
	NULL
};

static RCoreHelpMessage help_msg_tcc = {
	"Usage: tcc", "[-name]", "Type function calling conventions (see also afc? and arcc)",
	"tcc", "", "list all calling conventions",
	"tcc*", "", "list calling conventions as r2 commands",
	"tcck", "", "list calling conventions in k=v format",
	"tccl", "", "list cc signatures (return ccname (arg0, arg1, ..) err;)",
	"tccj", "", "list them in JSON",
	"tcc ", "<ret> ([args]) ([err])", "define function cc",
	"tcc ", "r0 pascal(r0,r1,r2)", "define signature for pascal cc (see also arcc)",
	"tcc-", "<name>", "unregister calling convention by name",
	"tcc-*", "", "unregister all calling conventions",
	NULL
};

static RCoreHelpMessage help_msg_tf = {
	"Usage: tf[...]", "", "",
	"tf", "", "list all function definitions loaded",
	"tf", " <name>", "show function signature",
	"tfc", " [name]", "list all/given function signatures in C output format with newlines",
	"tfcj", " <name>", "same as above but in JSON",
	"tfe", " <name>", "edit function signature with cfg.editor",
	"tfj", "", "list all function definitions in JSON",
	"tfj", " <name>", "show function signature in JSON",
	NULL
};

static RCoreHelpMessage help_msg_to = {
	"Usage: to[...]", "", "",
	"to", " -", "open cfg.editor to load types",
	"to", " <path>", "load types from C header file",
	"tos", " <path>", "load types from parsed Sdb database",
	"toe", " [type.name]", "open cfg.editor to edit types",
	"tos", " <path>", "load types from parsed Sdb database",
	"touch", " <file>", "create or update timestamp in file",
	NULL
};

static RCoreHelpMessage help_msg_tp = {
	"Usage: tp[vx]", " <type> [...]", "Print type",
	"tp", "  <type> [addr|varname]", "cast data at <address> to <type> and print it (XXX: type can contain spaces)",
	"tpv", " <type> [@addr]", "show offset formatted for given type",
	"tpx", " <type> <hexpairs>", "show value for type with specified byte sequence (XXX: type can contain spaces)",
	NULL
};

static RCoreHelpMessage help_msg_tc = {
	"Usage: tc[...]", " [type]", "Print loaded types",
	"tc", "", "list all loaded types in C output format with newlines",
	"tc", " [type.name]", "list given loaded type in C output format with newlines",
	"tcd", "", "list all loaded types in C output format without newlines",
	"tcc", "[?]", "manage calling convention types",
	NULL
};

static RCoreHelpMessage help_msg_te = {
	"Usage: te[...]", "", "Type enum commands",
	"te", "", "list all loaded enums",
	"te", " <enum>", "print all values of enum for given name",
	"te", " <enum> <value>", "show name for given enum number",
	"te-", " <enum> [name2..]", "delete enum type(s) (supports glob with *)",
	"teb", " <enum> <name>", "show matching enum bitfield for given name",
	"tec", "", "list all loaded enums in C output format with newlines",
	"tec", " <name>", "list given loaded enums in C output format with newlines",
	"ted", "", "list all loaded enums in C output format without newlines",
	"tee", " <name>", "edit enum with cfg.editor",
	"tej", "", "list all loaded enums in json",
	"tej", " <enum>", "show enum in json",
	"test", " [-x,f,d] [path]", "test if executable, file or directory exists",
	"tev", " [name]", "view all/given enums in C format with member values",
	NULL
};

static RCoreHelpMessage help_msg_tt = {
	"Usage: tt[...]", "", "Type typedef commands",
	"tt", "", "list all loaded typedefs",
	"tt", " <typename>", "show name for given type alias",
	"tte", " <name>", "edit typedef with cfg.editor",
	"ttj", "", "show typename and type alias in json",
	"ttc", "<name>", "show typename and type alias in C output format",
	NULL
};

static RCoreHelpMessage help_msg_tl = {
	"Usage: tl[...]", "[typename] [[=] address]", "Type link commands",
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

static RCoreHelpMessage help_msg_tn = {
	"Usage:", "tn [-][0xaddr|symname]", " manage no-return marks",
	"tn[a]", " [addr]", "stop function analysis if call/jmp to 'addr'",
	"tn[n]", " sym.imp.exit", "same as above but for flag/fcn names",
	"tnf", "", "same as `afl,noret/eq/1`",
	"tn-", " 0x3000 sym.imp.exit ...", "remove some no-return references",
	"tn-*", "", "remove all no-return references",
	"tn", "", "list them all",
	NULL
};

static RCoreHelpMessage help_msg_ts = {
	"Usage: ts[...]", " [type]", "",
	"ts", "", "list all loaded structs",
	"ts", " [type]", "show pf format string for given struct",
	"tu.", "[type]", "show struct contents mapped in current offset (same as .ts)",
	"ts-", " <type> [name2..]", "delete struct type(s) (supports glob with *)",
	"tse", " <name>", "edit struct with cfg.editor",
	"tsj", "", "list all loaded structs in json",
	"tsj", " [type]", "show pf format string for given struct in json",
	"ts*", "", "show pf.<name> format string for all loaded structs",
	"ts*", " [type]", "show pf.<name> format string for given struct",
	"tsc", "<name>", "list all/given loaded structs in C output format with newlines",
	"tsd", "", "list all loaded structs in C output format without newlines",
	"tss", " [type]", "display size of struct",
	"tsv", " [name]", "view all/given structs in C format with field offsets",
	NULL
};

static RCoreHelpMessage help_msg_tu = {
	"Usage: tu[...]", "", "",
	"tu", "", "list all loaded unions",
	"tu", " [type]", "show pf format string for given union",
	"tu.", "[type]", "show union contents mapped in current offset (same as .tu)",
	"tu-", " <type> [name2..]", "delete union type(s) (supports glob with *)",
	"tue", " <name>", "edit union with cfg.editor",
	"tuj", "", "list all loaded unions in json",
	"tuj", " [type]", "show pf format string for given union in json",
	"tu*", "", "show pf.<name> format string for all loaded unions",
	"tu*", " [type]", "show pf.<name> format string for given union",
	"tuc", "<name>", "list all/given loaded unions in C output format with newlines",
	"tud", "", "list all loaded unions in C output format without newlines",
	"tuv", " [name]", "view all/given unions in C format with field offsets",
	NULL
};

// clang-format on

static bool cc_cb(void *p, const char *k, const char *v) {
	if (!strcmp (v, "cc")) {
		RList *list = (RList*)p;
		r_list_append (list, (void*)k);
	}
	return true;
}

static void cmd_afcl(RCore *core, const char *input) {
	int mode = 0;
	PJ *pj = NULL;
	if (input) {
		mode = *input;
		if (*input == 'j') {
			pj = r_core_pj_new (core);
			pj_o (pj);
		}
	}
	RList *list = r_list_newf (NULL);
	sdb_foreach (core->anal->sdb_cc, cc_cb, list);
	char *cc;
	RListIter *iter;
	r_list_sort (list, (RListComparator)strcmp);
	r_list_foreach (list, iter, cc) {
		if (pj) {
			pj_ko (pj, cc);
			r_anal_cc_get_json (core->anal, pj, cc);
			pj_end (pj);
		} else if (mode == 'l') {
			char *sig = r_anal_cc_get (core->anal, cc);
			r_cons_println (core->cons, sig);
			free (sig);
		} else if (mode == '*') {
			char *ccexpr = r_anal_cc_get (core->anal, cc);
			r_cons_printf (core->cons, "tcc %s\n", ccexpr);
			free (ccexpr);
		} else {
			r_cons_println (core->cons, cc);
		}
	}
	r_list_free (list);
	if (pj) {
		pj_end (pj);
		char *j = pj_drain (pj);
		r_cons_println (core->cons, j);
		free (j);
	}
}

static void cmd_afck(RCore *core, const char *c) {
	const char *s = "anal/cc/*";
	char *out = sdb_querys (core->sdb, NULL, 0, s);
	if (out) {
		r_cons_print (core->cons, out);
	}
	free (out);
}

static void cmd_tcc(RCore *core, const char *input) {
	switch (*input) {
	case '?':
		r_core_cmd_help (core, help_msg_tcc);
		break;
	case '-':
		if (input[1] == '*') {
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_tcc, "tcc-*");
			} else {
				sdb_reset (core->anal->sdb_cc);
			}
		} else if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_tcc, "tcc-");
		} else {
			r_anal_cc_del (core->anal, r_str_trim_head_ro (input + 1));
		}
		break;
	case '\0':
	case 'l':
	case 'j':
	case '*':
		if (*input && input[1] == '?') {
			r_core_cmd_help_match_spec (core, help_msg_tcc, "tcc", *input);
		} else {
			cmd_afcl (core, input);
		}
		break;
	case 'k':
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_tcc, "tcck");
		} else {
			cmd_afck (core, NULL);
		}
		break;
	case ' ':
		if (strchr (input, '(')) {
			if (!r_anal_cc_set (core->anal, input + 1)) {
				R_LOG_ERROR ("Invalid syntax in cc signature");
			}
		} else {
			const char *ccname = r_str_trim_head_ro (input + 1);
			char *cc = r_anal_cc_get (core->anal, ccname);
			if (cc) {
				r_cons_println (core->cons, cc);
				free (cc);
			}
		}
		break;
	}
}

static void add_type_fields_to_json(RCore *core, PJ *pj, const char *struct_name, const char *type_name) {
	const bool is_union = !strcmp (type_name, "union");
	// Get struct members list
	char *members_query = r_str_newf ("%s.%s", type_name, struct_name);
	char *members = sdb_get (core->anal->sdb_types, members_query, 0);
	free (members_query);
	if (!members) {
		return;
	}

	pj_k (pj, "fields");
	pj_a (pj);

	ut32 current_offset = 0;
	int i, nargs = r_str_split (members, ',');
	for (i = 0; i < nargs; i++) {
		const char *member_name = r_str_word_get0 (members, i);
		if (!member_name || R_STR_ISEMPTY (member_name)) {
			continue;
		}
		char *member_query = r_str_newf ("%s.%s.%s", type_name, struct_name, member_name);
		char *member_details = sdb_get (core->anal->sdb_types, member_query, 0);
		free (member_query);
		if (!member_details) {
			continue;
		}
		int details_len = r_str_split (member_details, ',');
		if (details_len >= 3) {
			const char *type = r_str_word_get0 (member_details, 0);
			const char *arr_size_str = r_str_word_get0 (member_details, 2);
			ut32 arr_size = r_num_get (NULL, arr_size_str);
			arr_size = arr_size ? arr_size : 1;
			ut32 type_size;
			if (strchr (type, '*')) {
				type_size = core->anal->config->bits / 8;
			} else {
				ut64 type_bits = r_type_get_bitsize (core->anal->sdb_types, type);
				type_size = type_bits / 8;
				if (type_size == 0) {
					type_size = 1;
				}
			}
			ut32 size = type_size * arr_size;
			pj_o (pj);
			pj_ks (pj, "name", member_name);
			pj_ks (pj, "type", type);
			pj_ki (pj, "offset", current_offset);
			pj_ki (pj, "size", size);
			if (!is_union) {
				current_offset += size;
			}
			if (arr_size > 1) {
				pj_ki (pj, "array_size", arr_size);
			}
			pj_end (pj);
		}
		free (member_details);
	}
	pj_end (pj);
	free (members);
}

static void showFormat(RCore *core, const char *name, int mode) {
	const char *isenum = sdb_const_get (core->anal->sdb_types, name, 0);
	if (isenum && !strcmp (isenum, "enum")) {
		R_LOG_INFO ("Type is an enum");
	} else {
		char *fmt = r_type_format (core->anal->sdb_types, name);
		if (fmt) {
			r_str_trim (fmt);
			if (mode == 'j') {
				PJ *pj = r_core_pj_new (core);
				pj_o (pj);
				pj_ks (pj, "name", name);
				pj_ks (pj, "format", fmt);

				const char *typeinfo = sdb_const_get (core->anal->sdb_types, name, 0);
				if (typeinfo && (!strcmp (typeinfo, "struct") || !strcmp (typeinfo, "union"))) {
					add_type_fields_to_json (core, pj, name, typeinfo);
				}

				pj_end (pj);
				r_cons_printf (core->cons, "%s", pj_string (pj));
				pj_free (pj);
			} else {
				if (R_STR_ISNOTEMPTY (fmt)) {
					if (mode) {
						r_cons_printf (core->cons, "pf.%s %s\n", name, fmt);
					} else {
						r_cons_printf (core->cons, "pf %s\n", fmt);
					}
				} else {
					// This happens when the type hasnt been fully removed
					R_LOG_DEBUG ("Type wasnt properly deleted");
				}
			}
			free (fmt);
		} else {
			R_LOG_ERROR ("Cannot find '%s' type", name);
		}
	}
}

R_API char *r_core_slurp(RCore *core, const char *path, size_t *len) {
	if (*path == '$') {
		if (!path[1]) {
			R_LOG_ERROR ("No alias name given");
			return NULL;
		}
		RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, path + 1);
		if (!v) {
			R_LOG_ERROR ("No such alias \"$%s\"", path + 1);
			return NULL;
		}
		char *r = r_cmd_alias_val_strdup (v);
		if (len) {
			*len = strlen (r);
		}
		return r;
	}
	return r_file_slurp (path, len);
}

static int cmd_tac(void *data, const char *_input) { // "tac"
	RCore *core = (RCore *) data;
	char *input = strdup (_input);
	char *arg = strchr (input, ' ');
	if (arg) {
		arg = (char *)r_str_trim_head_ro (arg + 1);
	}
	switch (*input) {
	case '?': // "tac?"
		r_core_cmd_help_match (core, help_msg_t, "tac");
		break;
	default: // "tac"
		if (R_STR_ISNOTEMPTY (arg)) {
			char *filedata = r_core_slurp (core, arg, NULL);
			if (filedata) {
				RList *lines = r_str_split_list (filedata, "\n", 0);
				RListIter *iter;
				char *line;
				r_list_foreach_prev (lines, iter, line) {
					r_cons_printf (core->cons, "%s\n", line);
				}
				r_list_free (lines);
				free (filedata);
			} else {
				R_LOG_ERROR ("File not found");
			}
		} else {
			r_core_cmd_help_match (core, help_msg_t, "tac");
		}
		break;
	}
	free (input);
	return 0;
}

static int cmd_tail(void *data, const char *_input) { // "tail"
	char *tmp, *arg;
	char *input = strdup (_input);
	RCore *core = (RCore *)data;
	int lines = 5;
	if (r_str_startswith (input, "ail")) {
		arg = input + 3;
	} else {
		arg = strchr (input, ' ');
	}
	if (arg) {
		arg = (char *)r_str_trim_head_ro (arg);
		char *count = strchr (arg, ' ');
		if (count) {
			*count = 0; // split the count and file name
			tmp = (char *)r_str_trim_head_ro (count + 1);
			lines = r_num_math (core->num, arg);
			arg = tmp;
		}
	}
	switch (*input) {
	case '?': // "tail?"
		r_core_cmd_help_match (core, help_msg_t, "tail");
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
				r_cons_print (core->cons, res);
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
			r_core_cmd0 (core, "tn- `tn`");
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
	case 'f': // "tnf"
		r_core_cmd_call (core, "afl,noret/eq/1");
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

static void cmd_type_edit(RCore *core, const char *typename, const char *c_cmd) {
	if (R_STR_ISEMPTY (typename)) {
		R_LOG_ERROR ("Type name required");
		return;
	}
	char *str = r_core_cmd_strf (core, "%s %s", c_cmd, typename);
	if (R_STR_ISEMPTY (str)) {
		R_LOG_ERROR ("Type '%s' not found", typename);
		free (str);
		return;
	}
	char *tmp = r_core_editor (core, "*.h", str);
	if (tmp) {
		r_str_trim (tmp);
		char *str_trimmed = strdup (str);
		r_str_trim (str_trimmed);
		if (strcmp (tmp, str_trimmed)) {
			r_core_cmdf (core, "t- %s", typename);
			char *errmsg = NULL;
			char *out = r_anal_cparse (core->anal, tmp, &errmsg);
			if (out) {
				r_anal_save_parsed_type (core->anal, out);
				free (out);
			}
			if (errmsg) {
				R_LOG_ERROR ("%s", errmsg);
				free (errmsg);
			}
		}
		free (str_trimmed);
		free (tmp);
	}
	free (str);
}

static bool stdifstruct(void *user, const char *k, const char *v) {
	Sdb *TDB = (Sdb *)user;
	if (!strcmp (v, "struct") && !r_str_startswith (k, "typedef")) {
		return true;
	}
	if (!strcmp (v, "typedef")) {
		char *typedef_key = r_str_newf ("typedef.%s", k);
		const char *type = sdb_const_get (TDB, typedef_key, NULL);
		free (typedef_key);
		if (type && r_str_startswith (type, "struct")) {
			return true;
		}
	}
	return false;
}

static bool stdifunion(void *p, const char *k, const char *v) {
	return !strcmp (v, "union");
}

static bool stdifenum(void *p, const char *k, const char *v) {
	return !strcmp (v, "enum");
}

static bool stdifany(void *p, const char *k, const char *v) {
	return !strcmp (v, "struct") || !strcmp (v, "union") || !strcmp (v, "enum") || !strcmp (v, "type") || !strcmp (v, "typedef");
}

static void types_remove_glob(RCore *core, SdbForeachCallback filter, const char *arg) {
	Sdb *TDB = core->anal->sdb_types;
	RList *names = r_list_newf (free);
	SdbList *l = sdb_foreach_list_filter (TDB, filter, true);
	SdbListIter *it;
	SdbKv *kv;
	char *args = strdup (arg);
	RList *patterns = r_str_split_list (args, " ", 0);
	RListIter *pit;
	char *pattern;
	ls_foreach (l, it, kv) {
		const char *name = sdbkv_key (kv);
		r_list_foreach (patterns, pit, pattern) {
			if (strchr (pattern, '*')) {
				if (r_str_glob (name, pattern)) {
					r_list_append (names, strdup (name));
					break;
				}
			} else if (!strcmp (name, pattern)) {
				r_list_append (names, strdup (name));
				break;
			}
		}
	}
	ls_free (l);
	r_list_free (patterns);
	free (args);
	char *name;
	RListIter *iter;
	r_list_foreach (names, iter, name) {
		r_anal_remove_parsed_type (core->anal, name);
	}
	r_list_free (names);
}

/*!
* \brief print the data types details in JSON format
* \param TDB pointer to the sdb for types
* \param filter a callback function for the filtering
* \return 1 if success, 0 if failure
*/
static int print_struct_union_list_json(RCore *core, Sdb *TDB, SdbForeachCallback filter) {
	PJ *pj = r_core_pj_new (core);
	if (!pj) {
		return 0;
	}
	SdbList *l = sdb_foreach_list_filter (TDB, filter, true);
	SdbListIter *it;
	SdbKv *kv;
	pj_a (pj);
	ls_foreach (l, it, kv) {
		const char *k = sdbkv_key (kv);
		if (R_STR_ISEMPTY (k)) {
			continue;
		}
		pj_o (pj);
		pj_ks (pj, "name", k);
		char *fmt = r_type_format (TDB, k);
		if (fmt) {
			r_str_trim (fmt);
			pj_ks (pj, "format", fmt);
			const char *typeinfo = sdb_const_get (TDB, k, 0);
			if (typeinfo && (!strcmp (typeinfo, "struct") || !strcmp (typeinfo, "union"))) {
				add_type_fields_to_json (core, pj, k, typeinfo);
			}
			free (fmt);
		}
		pj_end (pj);
	}
	pj_end (pj);

	r_cons_println (core->cons, pj_string (pj));
	pj_free (pj);
	ls_free (l);
	return 1;
}

// Rename to char *RAnal.type_to_c() {}
static void print_struct_union_in_c_format(RCore *core, Sdb *TDB, SdbForeachCallback filter, const char *arg, bool multiline) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list_filter (TDB, filter, true);
	const char *space = "";
	bool match = false;

	RStrBuf *sb = r_strbuf_new ("");

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
		r_strbuf_appendf (sb, "%s %s {%s", sdbkv_value (kv), name, multiline? "\n": "");
		char *p, *var = r_str_newf ("%s.%s", sdbkv_value (kv), name);
		for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
			char *var2 = r_str_newf ("%s.%s", var, p);
			if (var2) {
				char *val = sdb_array_get (TDB, var2, 0, NULL);
				if (val) {
					char *arr = sdb_array_get (TDB, var2, 2, NULL);
					int arrnum = arr? atoi (arr): 0;
					free (arr);
					// Check for metadata attributes for this field
					RStrBuf *attrs_sb = r_strbuf_new ("");
					SdbList *all_keys = sdb_foreach_list (TDB, true);
					SdbListIter *attr_iter;
					SdbKv *attr_kv;
					char *attr_prefix = r_str_newf ("%s.@.", var2);
					ls_foreach (all_keys, attr_iter, attr_kv) {
						const char *attr_key = sdbkv_key (attr_kv);
						if (r_str_startswith (attr_key, attr_prefix)) {
							const char *attr_name = attr_key + strlen (attr_prefix);
							const char *attr_val = sdbkv_value (attr_kv);
							if (!strcmp (attr_val, "true")) {
								r_strbuf_appendf (attrs_sb, " /// @%s", attr_name);
							} else {
								r_strbuf_appendf (attrs_sb, " /// @%s(%s)", attr_name, attr_val);
							}
						}
					}
					free (attr_prefix);
					ls_free (all_keys);
					char *attrs_str = r_strbuf_drain (attrs_sb);
					if (multiline) {
						r_strbuf_appendf (sb, "  %s", val);
						if (p && p[0] != '\0') {
							r_strbuf_appendf (sb, "%s%s", strstr (val, " *")? "": " ", p);
							if (arrnum) {
								r_strbuf_appendf (sb, "[%d]", arrnum);
							}
						}
						r_strbuf_appendf (sb, ";%s\n", attrs_str? attrs_str: "");
					} else {
						r_strbuf_appendf (sb, "%s%s %s", space, val, p);
						if (arrnum) {
							r_strbuf_appendf (sb, "[%d]", arrnum);
						}
						r_strbuf_appendf (sb, ";%s", attrs_str? attrs_str: "");
						space = " ";
					}
					free (attrs_str);
					free (val);
				}
				free (var2);
			}
			free (p);
		}
		free (var);
		r_strbuf_append (sb, "};\n");
		space = "";
		if (match) {
			break;
		}
	}
	char *s = r_strbuf_drain (sb);
	r_cons_print (core->cons, s);
	free (s);
	free (name);
	ls_free (l);
}

typedef struct type_xref_t {
	ut64 addr;
	char *fcn_name;
	char *field_name;
	int access_type; // R_PERM_R, R_PERM_W, or both
} TypeXref;

static void type_xref_free(void *x) {
	TypeXref *xref = (TypeXref *)x;
	if (xref) {
		free (xref->fcn_name);
		free (xref->field_name);
		free (xref);
	}
}

static RList *collect_type_xrefs(RCore *core, const char *type_name) {
	RList *xrefs = r_list_newf (type_xref_free);
	if (!xrefs) {
		return NULL;
	}
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		RList *vars = r_anal_var_all_list (core->anal, fcn);
		RAnalVar *var;
		r_list_foreach (vars, iter2, var) {
			if (!var->type) {
				continue;
			}
			char *var_type = strdup (var->type);
			r_str_trim (var_type);
			char *sp = strchr (var_type, ' ');
			if (sp) {
				*sp = 0;
			}
			char *base_type = var_type;
			if (r_str_startswith (var_type, "struct ")) {
				base_type = var_type + 7;
			} else if (r_str_startswith (var_type, "union ")) {
				base_type = var_type + 6;
			}
			bool type_match = !strcmp (base_type, type_name);
			if (!type_match && sp) {
				*sp = ' ';
				type_match = !strcmp (var_type, type_name);
			}
			if (type_match) {
				RAnalVarAccess *acc;
				R_VEC_FOREACH (&var->accesses, acc) {
					TypeXref *xref = R_NEW0 (TypeXref);
					if (xref) {
						xref->addr = fcn->addr + acc->offset;
						xref->fcn_name = strdup (fcn->name);
						xref->field_name = NULL;
						xref->access_type = acc->type;
						r_list_append (xrefs, xref);
					}
				}
			}
			free (var_type);
		}
		r_list_free (vars);
	}
	return xrefs;
}

static RList *collect_field_xrefs(RCore *core, const char *type_name, const char *field_name, ut32 field_offset) {
	RList *xrefs = r_list_newf (type_xref_free);
	if (!xrefs) {
		return NULL;
	}
	RListIter *iter, *iter2;
	RAnalFunction *fcn;
	r_list_foreach (core->anal->fcns, iter, fcn) {
		RList *vars = r_anal_var_all_list (core->anal, fcn);
		RAnalVar *var;
		r_list_foreach (vars, iter2, var) {
			if (!var->type) {
				continue;
			}
			char *var_type = strdup (var->type);
			r_str_trim (var_type);
			char *sp = strchr (var_type, ' ');
			if (sp) {
				*sp = 0;
			}
			char *base_type = var_type;
			if (r_str_startswith (var_type, "struct ")) {
				base_type = var_type + 7;
			} else if (r_str_startswith (var_type, "union ")) {
				base_type = var_type + 6;
			}
			bool type_match = !strcmp (base_type, type_name);
			if (!type_match && sp) {
				*sp = ' ';
				type_match = !strcmp (var_type, type_name);
			}
			if (type_match) {
				RAnalVarAccess *acc;
				R_VEC_FOREACH (&var->accesses, acc) {
					if (acc->stackptr == (st64)field_offset) {
						TypeXref *xref = R_NEW0 (TypeXref);
						if (xref) {
							xref->addr = fcn->addr + acc->offset;
							xref->fcn_name = strdup (fcn->name);
							xref->field_name = strdup (field_name);
							xref->access_type = acc->type;
							r_list_append (xrefs, xref);
						}
					}
				}
			}
			free (var_type);
		}
		r_list_free (vars);
	}
	return xrefs;
}

static void append_xrefs_to_strbuf(RCore *core, RStrBuf *sb, RList *xrefs, bool use_color) {
	if (!xrefs || r_list_empty (xrefs)) {
		return;
	}
	const char *color_addr = "";
	const char *color_fname = "";
	const char *color_comment = "";
	const char *color_read = "";
	const char *color_write = "";
	const char *color_reset = "";
	if (use_color) {
		RConsPrintablePalette *pal = &core->cons->context->pal;
		color_addr = pal->addr ? pal->addr : Color_GREEN;
		color_fname = pal->fname ? pal->fname : Color_RED;
		color_comment = pal->comment ? pal->comment : Color_CYAN;
		color_read = pal->ai_read ? pal->ai_read : Color_GREEN;
		color_write = pal->ai_write ? pal->ai_write : Color_RED;
		color_reset = Color_RESET;
	}
	RListIter *iter;
	TypeXref *xref;
	r_list_foreach (xrefs, iter, xref) {
		r_strbuf_appendf (sb, "             %s; XREF[", color_comment);
		if (xref->access_type & R_PERM_R) {
			r_strbuf_appendf (sb, "%sr%s", color_read, color_reset);
		}
		if (xref->access_type & R_PERM_W) {
			r_strbuf_appendf (sb, "%sw%s", color_write, color_reset);
		}
		r_strbuf_appendf (sb, "%s] %s0x%08"PFMT64x" %s%s%s\n",
			color_comment, color_addr, xref->addr, color_fname, xref->fcn_name, color_reset);
	}
}

static void print_struct_union_with_offsets(RCore *core, Sdb *TDB, SdbForeachCallback filter, const char *arg, bool is_union) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list_filter (TDB, filter, true);
	bool match = false;
	bool use_color = r_config_get_i (core->config, "scr.color") > 0;

	const char *color_addr = "";
	const char *color_type = "";
	const char *color_name = "";
	const char *color_reset = "";
	if (use_color) {
		RConsPrintablePalette *pal = &core->cons->context->pal;
		color_addr = pal->addr ? pal->addr : Color_GREEN;
		color_type = pal->var_type ? pal->var_type : Color_CYAN;
		color_name = pal->var_name ? pal->var_name : Color_YELLOW;
		color_reset = Color_RESET;
	}

	RStrBuf *sb = r_strbuf_new ("");

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
		RList *type_xrefs = collect_type_xrefs (core, name);
		append_xrefs_to_strbuf (core, sb, type_xrefs, use_color);
		r_list_free (type_xrefs);
		r_strbuf_appendf (sb, "%s0x%08x%s %s %s%s%s {\n", color_addr, 0, color_reset, sdbkv_value (kv), color_name, name, color_reset);
		char *p, *var = r_str_newf ("%s.%s", sdbkv_value (kv), name);
		ut32 current_offset = 0;
		for (n = 0; (p = sdb_array_get (TDB, var, n, NULL)); n++) {
			char *var2 = r_str_newf ("%s.%s", var, p);
			if (var2) {
				char *val = sdb_array_get (TDB, var2, 0, NULL);
				if (val) {
					char *arr = sdb_array_get (TDB, var2, 2, NULL);
					int arrnum = arr? atoi (arr): 0;
					free (arr);
					ut32 type_size;
					if (strchr (val, '*')) {
						type_size = core->anal->config->bits / 8;
					} else {
						ut64 type_bits = r_type_get_bitsize (TDB, val);
						type_size = type_bits / 8;
						if (type_size == 0) {
							type_size = 1;
						}
					}
					ut32 arr_size = arrnum ? arrnum : 1;
					ut32 size = type_size * arr_size;
					r_strbuf_appendf (sb, "%s0x%08x%s   %s%s%s", color_addr, current_offset, color_reset, color_type, val, color_reset);
					if (p && p[0] != '\0') {
						r_strbuf_appendf (sb, "%s%s%s%s", strstr (val, " *")? "": " ", color_name, p, color_reset);
						if (arrnum) {
							r_strbuf_appendf (sb, "[%d]", arrnum);
						}
					}
					RList *field_xrefs = collect_field_xrefs (core, name, p, current_offset);
					append_xrefs_to_strbuf (core, sb, field_xrefs, use_color);
					r_list_free (field_xrefs);
					r_strbuf_append (sb, ";\n");
					if (!is_union) {
						current_offset += size;
					}
					free (val);
				}
				free (var2);
			}
			free (p);
		}
		free (var);
		r_strbuf_appendf (sb, "%s0x%08x%s };\n", color_addr, current_offset, color_reset);
		if (match) {
			break;
		}
	}
	char *s = r_strbuf_drain (sb);
	r_cons_print (core->cons, s);
	free (s);
	free (name);
	ls_free (l);
}

static void print_enum_with_offsets(RCore *core, Sdb *TDB, const char *arg) {
	char *name = NULL;
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list (TDB, true);
	bool match = false;
	bool use_color = r_config_get_i (core->config, "scr.color") > 0;

	const char *color_addr = "";
	const char *color_name = "";
	const char *color_num = "";
	const char *color_reset = "";
	if (use_color) {
		RConsPrintablePalette *pal = &core->cons->context->pal;
		color_addr = pal->addr ? pal->addr : Color_GREEN;
		color_name = pal->var_name ? pal->var_name : Color_YELLOW;
		color_num = pal->num ? pal->num : Color_CYAN;
		color_reset = Color_RESET;
	}

	RStrBuf *sb = r_strbuf_new ("");
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
				RList *type_xrefs = collect_type_xrefs (core, name);
				append_xrefs_to_strbuf (core, sb, type_xrefs, use_color);
				r_list_free (type_xrefs);
				r_strbuf_appendf (sb, "%s0x%08x%s enum %s%s%s {\n", color_addr, 0, color_reset, color_name, name, color_reset);
				RList *list = r_type_get_enum (TDB, name);
				if (list && !r_list_empty (list)) {
					RListIter *liter;
					RTypeEnum *member;
					r_list_foreach (list, liter, member) {
						r_strbuf_appendf (sb, "%s0x%08x%s   %s%s%s = %s%s%s;\n",
							color_addr, (ut32)r_num_math (NULL, member->val), color_reset,
							color_name, member->name, color_reset,
							color_num, member->val, color_reset);
					}
				}
				r_list_free (list);
				r_strbuf_appendf (sb, "%s0x00000000%s };\n", color_addr, color_reset);
				if (match) {
					break;
				}
			}
		}
	}
	char *s = r_strbuf_drain (sb);
	r_cons_print (core->cons, s);
	free (s);
	free (name);
	ls_free (l);
}

static bool stdifbasictype(void *p, const char *k, const char *v) {
	return !strcmp (v, "type");
}

static void print_basic_type_with_offsets(RCore *core, Sdb *TDB, const char *arg) {
	SdbKv *kv;
	SdbListIter *iter;
	SdbList *l = sdb_foreach_list_filter (TDB, stdifbasictype, true);
	bool match = false;
	bool use_color = r_config_get_i (core->config, "scr.color") > 0;

	const char *color_addr = "";
	const char *color_name = "";
	const char *color_comment = "";
	const char *color_reset = "";
	if (use_color) {
		RConsPrintablePalette *pal = &core->cons->context->pal;
		color_addr = pal->addr ? pal->addr : Color_GREEN;
		color_name = pal->var_name ? pal->var_name : Color_YELLOW;
		color_comment = pal->comment ? pal->comment : Color_CYAN;
		color_reset = Color_RESET;
	}

	RStrBuf *sb = r_strbuf_new ("");

	ls_foreach (l, iter, kv) {
		const char *name = sdbkv_key (kv);
		if (arg && *arg) {
			if (!strcmp (arg, name)) {
				match = true;
			} else {
				continue;
			}
		}
		char *size_key = r_str_newf ("type.%s.size", name);
		const char *size_str = sdb_const_get (TDB, size_key, NULL);
		free (size_key);
		ut32 size = size_str ? (ut32)(atoi (size_str) / 8) : 0;
		RList *type_xrefs = collect_type_xrefs (core, name);
		append_xrefs_to_strbuf (core, sb, type_xrefs, use_color);
		r_list_free (type_xrefs);
		r_strbuf_appendf (sb, "%s0x%08x%s type %s%s%s; %s// size=%d%s\n",
			color_addr, 0, color_reset, color_name, name, color_reset,
			color_comment, size, color_reset);
		r_strbuf_appendf (sb, "%s0x%08x%s\n", color_addr, size, color_reset);
		if (match) {
			break;
		}
	}
	char *s = r_strbuf_drain (sb);
	r_cons_print (core->cons, s);
	free (s);
	ls_free (l);
}

static void print_type_view(RCore *core, const char *arg) {
	Sdb *TDB = core->anal->sdb_types;
	if (arg && *arg) {
		const char *type_kind = sdb_const_get (TDB, arg, 0);
		if (type_kind) {
			if (!strcmp (type_kind, "struct")) {
				print_struct_union_with_offsets (core, TDB, stdifstruct, arg, false);
			} else if (!strcmp (type_kind, "union")) {
				print_struct_union_with_offsets (core, TDB, stdifunion, arg, true);
			} else if (!strcmp (type_kind, "enum")) {
				print_enum_with_offsets (core, TDB, arg);
			} else if (!strcmp (type_kind, "type")) {
				print_basic_type_with_offsets (core, TDB, arg);
			} else if (!strcmp (type_kind, "typedef")) {
				char *typedef_key = r_str_newf ("typedef.%s", arg);
				const char *real_type = sdb_const_get (TDB, typedef_key, NULL);
				free (typedef_key);
				if (real_type) {
					print_type_view (core, real_type);
				}
			} else {
				R_LOG_ERROR ("Unknown type kind: %s", type_kind);
			}
		} else {
			R_LOG_ERROR ("Type not found: %s", arg);
		}
	} else {
		print_struct_union_with_offsets (core, TDB, stdifstruct, NULL, false);
		print_struct_union_with_offsets (core, TDB, stdifunion, NULL, true);
		print_enum_with_offsets (core, TDB, NULL);
		print_basic_type_with_offsets (core, TDB, NULL);
	}
}

static void print_enum_in_c_format(RCore *core, Sdb *TDB, const char *arg, bool multiline) {
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
				r_cons_printf (core->cons, "%s %s {%s", sdbkv_value (kv), name, multiline? "\n": "");
				{
					RList *list = r_type_get_enum (TDB, name);
					if (list && !r_list_empty (list)) {
						RListIter *iter;
						RTypeEnum *member;
						separator = multiline? "\t": "";
						r_list_foreach (list, iter, member) {
							r_cons_printf (core->cons, "%s%s = %" PFMT64u, separator, member->name, r_num_math (NULL, member->val));
							separator = multiline? ",\n\t": ", ";
						}
					}
					r_list_free (list);
				}
				r_cons_println (core->cons, multiline? "\n};": "};");
				if (match) {
					break;
				}
			}
		}
	}
	free (name);
	ls_free (l);
}

static bool printkey_cb(void *user, const char *k, const char *v) {
	RCore *core = (RCore *)user;
	r_cons_println (core->cons, k);
	return true;
}

// maybe dupe?. should return char *instead of print for reusability
static void printFunctionTypeC(RCore *core, const char *input) {
	Sdb *TDB = core->anal->sdb_types;
	r_strf_buffer (256);
	char *res = sdb_querys (TDB, NULL, -1, r_strf ("func.%s.args", input));
	const char *name = r_str_trim_head_ro (input);
	int i, args = sdb_num_get (TDB, r_strf ("func.%s.args", name), 0);
	const char *ret = sdb_const_get (TDB, r_strf ("func.%s.ret", name), 0);
	if (!ret) {
		ret = "void";
	}
	if (!ret || !name) {
		// missing function name specified
		return;
	}

	r_cons_printf (core->cons, "%s %s (", ret, name);
	for (i = 0; i < args; i++) {
		char *type = sdb_get (TDB, r_strf ("func.%s.arg.%d", name, i), 0);
		if (!type) {
			continue;
		}
		char *argname = strchr (type, ',');
		if (argname) {
			*argname++ = 0;
		}
		if (!strcmp (type, "...")) {
			r_cons_printf (core->cons, "%s%s", (i == 0)? "": ", ", type);
		} else {
			r_cons_printf (core->cons, "%s%s %s", (i == 0)? "": ", ", type, argname);
		}
		free (type);
	}
	r_cons_printf (core->cons, ");\n");
	free (res);
}

typedef struct {
	RCore *core;
	PJ *pj;
} TypePrintCtx;

static void printFunctionTypeJson(TypePrintCtx *ctx, const char *input) {
	Sdb *tdb = ctx->core->anal->sdb_types;
	PJ *pj = ctx->pj;
	r_strf_buffer (256);
	const char *name = r_str_trim_head_ro (input);
	int i, args = sdb_num_get (tdb, r_strf ("func.%s.args", name), 0);
	pj_o (pj);
	pj_ks (pj, "name", name);
	pj_ks (pj, "ret", r_str_get_fail (sdb_const_get (tdb, r_strf ("func.%s.ret", name), 0), "void"));
	pj_ka (pj, "args");
	for (i = 0; i < args; i++) {
		char *type = sdb_get (tdb, r_strf ("func.%s.arg.%d", name, i), 0);
		if (type) {
			char *argname = strchr (type, ',');
			if (argname) {
				*argname++ = 0;
			}
			pj_o (pj);
			pj_ks (pj, "type", type);
			if (strcmp (type, "...")) {
				pj_ks (pj, "name", argname? argname: "(null)");
			}
			pj_end (pj);
			free (type);
		}
	}
	pj_end (pj);
	pj_end (pj);
}

static void printFunctionType(RCore *core, const char *input) {
	PJ *pj = r_core_pj_new (core);
	TypePrintCtx ctx = { .core = core, .pj = pj };
	printFunctionTypeJson (&ctx, input);
	char *s = pj_drain (pj);
	if (s) {
		r_cons_printf (core->cons, "%s", s);
		free (s);
	}
}

static bool printfunc_json_cb(void *user, const char *k, const char *v) {
	printFunctionTypeJson ((TypePrintCtx *)user, k);
	return true;
}

static bool stdiffunc(void *p, const char *k, const char *v) {
	return !strcmp (v, "func");
}

static bool sdbdeletelink(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	if (r_str_startswith (k, "link.")) {
		r_type_del (core->anal->sdb_types, k);
	}
	return true;
}

static bool stdiflink(void *p, const char *k, const char *v) {
	return r_str_startswith (k, "link.");
}

static bool print_link_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	r_cons_printf (core->cons, "0x%s = %s\n", k + strlen ("link."), v);
	return true;
}

static bool print_link_json_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	r_cons_printf (core->cons, "{\"0x%s\":\"%s\"}", k + strlen ("link."), v);
	return true;
}

static bool print_link_r_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	r_cons_printf (core->cons, "tl %s = 0x%s\n", v, k + strlen ("link."));
	return true;
}

static bool print_link_readable_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	char *fmt = r_type_format (core->anal->sdb_types, v);
	if (!fmt) {
		R_LOG_ERROR ("Can't find type %s", v);
		return 1;
	}
	r_cons_printf (core->cons, "(%s)\n", v);
	r_core_cmdf (core, "pf %s @ 0x%s", fmt, k + strlen ("link."));
	return true;
}

static bool print_link_readable_json_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	char *fmt = r_type_format (core->anal->sdb_types, v);
	if (!fmt) {
		R_LOG_ERROR ("Can't find type %s", v);
		return true;
	}
	r_cons_printf (core->cons, "{\"%s\":", v);
	r_core_cmdf (core, "pfj %s @ 0x%s", fmt, k + strlen ("link."));
	r_cons_printf (core->cons, "}");
	return true;
}

static bool stdiftype(void *p, const char *k, const char *v) {
	return !strcmp (v, "type");
}

static bool print_typelist_r_cb(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	r_cons_printf (core->cons, "'tk %s=%s\n", k, v);
	return true;
}

static bool print_typelist_json_cb(void *p, const char *k, const char *v) {
	R_RETURN_VAL_IF_FAIL (p && k, false);
	TypePrintCtx *ctx = (TypePrintCtx *)p;
	RCore *core = ctx->core;
	PJ *pj = ctx->pj;
	if (!v) {
		v = "";
	}
	pj_o (pj);
	Sdb *sdb = core->anal->sdb_types;
	char *sizecmd = r_str_newf ("type.%s.size", k);
	char *size_s = sdb_get (sdb, sizecmd, NULL);
	char *formatcmd = r_str_newf ("type.%s", k);
	pj_ks (pj, "type", k);
	pj_ki (pj, "size", size_s ? atoi (size_s) : -1);
	char *format_s = sdb_get (sdb, formatcmd, NULL);
	if (format_s) {
		r_str_trim (format_s);
		pj_ks (pj, "format", format_s);
		free (format_s);
	}
	pj_end (pj);
	free (size_s);
	free (sizecmd);
	free (formatcmd);
	return true;
}

static void print_keys(RCore *core, SdbForeachCallback filter, SdbForeachCallback printfn_cb, bool json) {
	Sdb *tdb = core->anal->sdb_types;
	SdbList *l = sdb_foreach_list_filter (tdb, filter, true);
	SdbListIter *it;
	SdbKv *kv;

	PJ *pj = NULL;
	TypePrintCtx ctx = { .core = core, .pj = NULL };
	if (json) {
		pj = r_core_pj_new (core);
		pj_o (pj);
		pj_ka (pj, "types");
		ctx.pj = pj;
	}
	ls_foreach (l, it, kv) {
		const char *k = sdbkv_key (kv);
		const char *v = sdbkv_value (kv);
		if (R_STR_ISEMPTY (k)) {
			continue;
		}
		if (v) {
			if (json) {
				printfn_cb (&ctx, k, v);
			} else {
				printfn_cb (core, k, v);
			}
		}
	}
	if (pj) {
		pj_end (pj);
		pj_end (pj);
		char *s = pj_drain (pj);
		r_cons_println (core->cons, s);
		free (s);
	}
	ls_free (l);
}

static void typesList(RCore *core, int mode) {
	switch (mode) {
	case 1:
	case '*':
		print_keys (core, NULL, print_typelist_r_cb, false);
		break;
	case 'j':
		print_keys (core, stdiftype, print_typelist_json_cb, true);
		break;
	default:
		print_keys (core, stdiftype, printkey_cb, false);
		break;
	}
}

static void set_offset_hint(RCore *core, RAnalOp *op, const char *type, ut64 laddr, ut64 at, int offimm) {
	char *res = r_type_get_struct_memb (core->anal->sdb_types, type, offimm);
	const char *cmt = ((offimm == 0) && res)? res: type;
	if (offimm > 0) {
		// set hint only if link is present
		char* query = r_str_newf ("link.%08"PFMT64x, laddr);
		if (res && sdb_const_get (core->anal->sdb_types, query, 0)) {
			r_anal_hint_set_offset (core->anal, at, res);
		}
		free (query);
	} else if (cmt && r_anal_op_ismemref (op->type)) {
		r_meta_set_string (core->anal, R_META_TYPE_VARTYPE, at, cmt);
	}
}

R_API int r_core_get_stacksz(RCore *core, ut64 from, ut64 to) {
	int stack = 0, maxstack = 0;
	ut64 at = from;

	if (from >= to) {
		return 0;
	}
	const int mininstrsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	while (at < to) {
		RAnalOp *op = r_core_anal_op (core, at, R_ARCH_OP_MASK_BASIC);
		if (!op || op->size <= 0) {
			at += minopcode;
			r_anal_op_free (op);
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

static void set_retval(RCore *core, ut64 at) {
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
	if (!fcn) {
		return;
	}
	RAnalBlock *bb;
	RListIter *it;
	RAnalOp aop = {0};
	bool ioCache = r_config_get_b (core->config, "io.cache");
	bool stack_set = false;
	bool resolved = false;
	const char *varpfx;
	int dbg_follow = r_config_get_i (core->config, "dbg.follow");
	Sdb *TDB = core->anal->sdb_types;
	REsil *esil;
	int iotrap = r_config_get_i (core->config, "esil.iotrap");
	int stacksize = r_config_get_i (core->config, "esil.stack.depth");
	unsigned int addrsize = r_config_get_i (core->config, "esil.addr.size");
	RRegItem *pc = r_reg_get (core->anal->reg, "PC", -1);

	if (!(esil = r_esil_new (stacksize, iotrap, addrsize))) {
		return;
	}
	r_esil_setup (esil, core->anal, 0, 0, 0);
	int i, ret, bsize = R_MAX (64, core->blocksize);
	const int mininstrsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
	const int maxinstrsz = r_anal_archinfo (core->anal, R_ARCH_INFO_MAXOP_SIZE);
	const int minopcode = R_MAX (1, mininstrsz);
	ut8 *buf = malloc (bsize);
	if (!buf) {
		free (buf);
		r_esil_free (esil);
		return;
	}
	r_reg_arena_push (core->anal->reg);
	r_debug_reg_sync (core->dbg, R_REG_TYPE_ALL, true);
	ut64 spval = r_reg_getv (esil->anal->reg, "SP");
	if (spval) {
		// reset stack pointer to initial value
		RRegItem *sp = r_reg_get (esil->anal->reg, "SP", -1);
		ut64 curpc = r_reg_getv (esil->anal->reg, "PC");
		int stacksz = r_core_get_stacksz (core, fcn->addr, curpc);
		if (stacksz > 0) {
			r_reg_arena_zero (esil->anal->reg); // clear prev reg values
			r_reg_set_value (esil->anal->reg, sp, spval + stacksz);
		}
	} else {
		// initialize stack
		r_core_cmd_call (core, "aeim");
		stack_set = true;
	}
	r_config_set_b (core->config, "io.cache", true);
	r_config_set_i (core->config, "dbg.follow", 0);
	ut64 oldoff = core->addr;
	r_cons_break_push (core->cons, NULL, NULL);
	// TODO: The algorithm can be more accurate if blocks are followed by their jmp/fail, not just by address
	r_list_sort (fcn->bbs, bb_cmpaddr);
	r_list_foreach (fcn->bbs, it, bb) {
		ut64 at = bb->addr;
		ut64 to = bb->addr + bb->size;
		r_reg_set_value (esil->anal->reg, pc, at);
		for (i = 0; at < to; i++) {
			if (r_cons_is_breaked (core->cons)) {
				goto beach;
			}
			if (at < bb->addr) {
				break;
			}
			if (i >= (bsize - maxinstrsz)) {
				i = 0;
			}
			if (!i) {
				r_io_read_at (core->io, at, buf, bsize);
			}
			ret = r_anal_op (core->anal, &aop, at, buf + i, bsize - i, R_ARCH_OP_MASK_VAL);
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
			int src_imm = -1, dst_imm = -1;
			ut64 src_addr = UT64_MAX;
			ut64 dst_addr = UT64_MAX;
			RAnalValue *src = NULL;
			R_VEC_FOREACH (&aop.srcs, src) {
				if (src && src->reg) {
					src_addr = r_reg_getv (esil->anal->reg, src->reg) + index;
					src_imm = src->delta;
				}
			}
			RAnalValue *dst = RVecRArchValue_at (&aop.dsts, 0);
			if (dst && dst->reg) {
				dst_addr = r_reg_getv (esil->anal->reg, dst->reg) + index;
				dst_imm = dst->delta;
			}
			RAnalVar *var = r_anal_get_used_function_var (core->anal, aop.addr);
			if (false) { // src_addr != UT64_MAX || dst_addr != UT64_MAX) {
			//  if (src_addr == UT64_MAX && dst_addr == UT64_MAX) {
				r_anal_op_fini (&aop);
				continue;
			}
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
					r_anal_var_set_type (core->anal, var, varpfx);
					r_anal_var_rename (core->anal, var, vlink);
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
	r_core_cmd_call (core, "wc-*"); // drop cache writes
	r_config_set_b (core->config, "io.cache", ioCache);
	r_config_set_i (core->config, "dbg.follow", dbg_follow);
	if (stack_set) {
		r_core_cmd_call (core, "aeim-");
	}
	r_core_seek (core, oldoff, true);
	r_esil_free (esil);
	r_reg_arena_pop (core->anal->reg);
	r_core_cmd0 (core, ".ar*");
	r_cons_break_pop (core->cons);
	free (buf);
}

static void test_flag(RCore *core, bool res, bool verbose) {
	r_core_return_value (core, res? 0: 1);
	if (verbose) {
		r_cons_println (core->cons, res? "found": "not found");
	}
}

static int cmd_test(RCore *core, const char *input) {
	bool verbose = false;
	int type = 'f';
	if (*input == '-') {
		if (input[1] == 'v') {
			input++;
			verbose = true;
		}
		type = input[1];
	}
	const char *arg = strchr (input, ' ');
	if (arg) {
		arg = r_str_trim_head_ro (arg + 1);
	} else {
		R_LOG_ERROR ("Missing file argument. Use 'test -[v]fdx [file]'");
		return 1;
	}
	char *filePath = r_file_abspath_rel (NULL, arg);
	switch (type) {
	case 'f': // "test -f"
		test_flag (core, r_file_exists (filePath), verbose);
		break;
	case 'x': // "test -x"
		test_flag (core, r_file_is_executable (filePath), verbose);
		break;
	case 's': // "test -s"
		test_flag (core, r_file_size (filePath) > 0, verbose);
		break;
	case 'd': // "test -d"
		test_flag (core, r_file_is_directory (filePath), verbose);
		break;
	default:
		R_LOG_ERROR ("Unknown flag for test. Use -f, -x or -d");
		free (filePath);
		return 1;
	}
	free (filePath);
	return 0;
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
		case '-': { // "tu-"
			const char *arg = r_str_trim_head_ro (input + 2);
			if (strchr (arg, '*') || strchr (arg, ' ')) {
				types_remove_glob (core, stdifunion, arg);
			} else {
				r_core_cmd_callf (core, "t-%s", arg);
			}
			break;
		}
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
		case '.': // "tu."
			if (input[2]) {
				const char *typename = r_str_trim_head_ro (input + 2);
				r_core_cmdf (core, ".tu %s", typename);
			}
			break;
		case 'j': // "tuj"
			if (input[2]) {
				showFormat (core, r_str_trim_head_ro (input + 2), 'j');
				r_cons_newline (core->cons);
			} else {
				print_struct_union_list_json (core, TDB, stdifunion);
			}
			break;
		case 'c':
			print_struct_union_in_c_format (core, TDB, stdifunion, r_str_trim_head_ro (input + 2), true);
			break;
		case 'd':
			print_struct_union_in_c_format (core, TDB, stdifunion, r_str_trim_head_ro (input + 2), false);
			break;
		case 'e': // "tue"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_tu, "tue");
			} else {
				cmd_type_edit (core, r_str_trim_head_ro (input + 2), "tuc");
			}
			break;
		case 'v': // "tuv"
			print_struct_union_with_offsets (core, TDB, stdifunion, r_str_trim_head_ro (input + 2), true);
			break;
		case ' ':
			showFormat (core, r_str_trim_head_ro (input + 1), 0);
			break;
		case 0:
			print_keys (core, stdifunion, printkey_cb, false);
			break;
		default:
			r_core_return_invalid_command (core, "tu", input[1]);
			break;
		}
		break;
	}
	case 'i': // "ti"
		if (r_str_startswith (input, "ime")) {
			if (input[3] == ' ') {
				r_core_cmdf (core, "?t %s", r_str_trim_head_ro (input + 4));
			} else {
				R_LOG_INFO ("Usage: time [command] # alias for the `?t` command");
			}
		} else {
			r_core_return_invalid_command (core, "ti", input[1]);
		}
		break;
	case 'k': // "tk"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_t, "tk");
		} else {
			res = (input[1] == ' ')
				? sdb_querys (TDB, NULL, -1, input + 2)
				: sdb_querys (TDB, NULL, -1, "*");
			if (res) {
				r_cons_print (core->cons, res);
				free (res);
			}
		}
		break;
	case 'c': // "tc"
		switch (input[1]) {
		case 'c': // "tcc" -- calling conventions
			cmd_tcc (core, input + 2);
			break;
		case '?': //"tc?"
			r_core_cmd_help (core, help_msg_tc);
			break;
		case ' ': { // "tcc "
			const char *type = r_str_trim_head_ro (input + 1);
			const char *name = type ? strchr (type, '.') : NULL;
			if (name && type) {
				name++; // skip the '.'
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
				} else {
					R_LOG_ERROR ("unk");
				}
			}
			break;
		}
		case '*': // "tc*"
			r_core_cmd_call (core, "ts*");
			break;
		case 0: // "tc"
			r_core_cmd0 (core, "tfc;tuc;tsc;ttc;tec");
			break;
		case 'd': // "tcd"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_tc, "tcd");
			} else {
				r_core_cmd0 (core, "tud;tsd;ttc;ted");
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_tc);
			break;
		}
		break;
	case 's': { // "ts"
		switch (input[1]) {
		case 0: // "ts"
			print_keys (core, stdifstruct, printkey_cb, false);
			break;
		case '*': // "ts*"
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
		case '.': // "ts."
			if (input[2]) {
				const char *typename = r_str_trim_head_ro (input + 2);
				r_core_cmdf (core, ".ts %s", typename);
			}
			break;
		case '-': { // "ts-"
			const char *arg = r_str_trim_head_ro (input + 2);
			if (strchr (arg, '*') || strchr (arg, ' ')) {
				types_remove_glob (core, stdifstruct, arg);
			} else {
				r_core_cmd_callf (core, "t-%s", arg);
			}
			break;
		}
		case ' ':
			showFormat (core, r_str_trim_head_ro (input + 1), 0);
			break;
		case 's': // "tss"
			if (input[2] == ' ') {
				r_cons_printf (core->cons, "%" PFMT64u "\n", (r_type_get_bitsize (TDB, input + 3) / 8));
			} else {
				r_core_cmd_help (core, help_msg_ts);
			}
			break;
		case 'c': // "tsc"
			print_struct_union_in_c_format (core, TDB, stdifstruct, r_str_trim_head_ro (input + 2), true);
			break;
		case 'd': // "tsd"
			print_struct_union_in_c_format (core, TDB, stdifstruct, r_str_trim_head_ro (input + 2), false);
			break;
		case 'e': // "tse"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_ts, "tse");
			} else {
				cmd_type_edit (core, r_str_trim_head_ro (input + 2), "tsc");
			}
			break;
		case 'j': // "tsj"
			if (input[2]) {
				showFormat (core, r_str_trim_head_ro (input + 2), 'j');
				r_cons_newline (core->cons);
			} else {
				print_struct_union_list_json (core, TDB, stdifstruct);
			}
			break;
		case 'v': // "tsv"
			print_struct_union_with_offsets (core, TDB, stdifstruct, r_str_trim_head_ro (input + 2), false);
			break;
		case '?': // "ts?"
			r_core_cmd_help (core, help_msg_ts);
			break;
		default:
			r_core_return_invalid_command (core, "ts", input[1]);
			break;
		} // end of switch (input[1])
		break;
	}
	case 'e': { // "te"
		if (r_str_startswith (input, "est")) {
			return cmd_test (core, r_str_trim_head_ro (input + 3));
		}
		char *res = NULL, *temp = strchr (input, ' ');
		Sdb *TDB = core->anal->sdb_types;
		char *name = temp ? strdup (temp + 1): NULL;
		char *member_name = name ? strchr (name, ' '): NULL;

		if (member_name) {
			*member_name++ = 0;
		}
		if (input[1] == '-') { // "te-"
			const char *arg = r_str_trim_head_ro (input + 2);
			if (strchr (arg, '*') || strchr (arg, ' ')) {
				types_remove_glob (core, stdifenum, arg);
			} else {
				r_core_cmd_callf (core, "t-%s", arg);
			}
			free (name);
			break;
		}
		if (R_STR_ISNOTEMPTY (name) && (r_type_kind (TDB, name) != R_TYPE_ENUM)) {
			R_LOG_ERROR ("%s is not an enum", name);
			free (name);
			break;
		}
		switch (input[1]) {
		case '-': // "te-" (handled above)
			break;
		case 'j': // "tej"
			if (input[2] == '\0') { // "tej"
				char *name = NULL;
				SdbKv *kv;
				SdbListIter *iter;
				SdbList *l = sdb_foreach_list (TDB, true);
				PJ *pj = r_core_pj_new (core);
				pj_o (pj);
				ls_foreach (l, iter, kv) {
					if (!strcmp (sdbkv_value (kv), "enum")
							&& (!name || strcmp (sdbkv_value (kv), name))) {
						RList *list;
						free (name);
						name = strdup (sdbkv_key (kv));
						pj_k (pj, name);
						list = r_type_get_enum (TDB, name);
						if (!r_list_empty (list)) {
							RListIter *iter;
							RTypeEnum *member;
							pj_o (pj);
							r_list_foreach (list, iter, member) {
								pj_kn (pj, member->name,
										r_num_math (NULL, member->val));
							}
							pj_end (pj);
						}
						r_list_free (list);
					}
				}
				pj_end (pj);
				r_cons_printf (core->cons, "%s\n", pj_string (pj));
				pj_free (pj);
				free (name);
				ls_free (l);
			} else if (input[2] == '?') {
				r_core_cmd_help_contains (core, help_msg_te, "tej");
			} else { // "tej ENUM"
				RListIter *iter;
				PJ *pj = r_core_pj_new (core);
				RTypeEnum *member;
				pj_o (pj);
				if (member_name) {
					res = r_type_enum_member (TDB, name, NULL, r_num_math (core->num, member_name));
					// NEVER REACHED
				} else {
					RList *list = r_type_get_enum (TDB, name);
					if (!r_list_empty (list)) {
						pj_ks (pj, "name", name);
						pj_k (pj, "values");
						pj_o (pj);
						r_list_foreach (list, iter, member) {
							pj_kn (pj, member->name, r_num_math (NULL, member->val));
						}
						pj_end (pj);
						pj_end (pj);
					}
					r_cons_printf (core->cons, "%s\n", pj_string (pj));
					pj_free (pj);
					r_list_free (list);
				}
			}
			break;
		case 'b': // "teb"
			if (R_STR_ISEMPTY (name) || input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_te, "teb");
			} else {
				res = r_type_enum_member (TDB, name, member_name, 0);
			}
			break;
		case 'c': // "tec"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_te, "tec");
			} else {
				print_enum_in_c_format (core, TDB, r_str_trim_head_ro (input + 2), true);
			}
			break;
		case 'd': // "ted"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_te, "ted");
			} else {
				print_enum_in_c_format (core, TDB, r_str_trim_head_ro (input + 2), false);
			}
			break;
		case 'e': // "tee"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_te, "tee");
			} else {
				cmd_type_edit (core, r_str_trim_head_ro (input + 2), "tec");
			}
			break;
		case 'v': // "tev"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_te, "tev");
			} else {
				print_enum_with_offsets (core, TDB, r_str_trim_head_ro (input + 2));
			}
			break;
		case ' ': // "te "
			if (member_name) {
				res = r_type_enum_member (TDB, name, NULL, r_num_math (core->num, member_name));
			} else {
				RList *list = r_type_get_enum (TDB, name);
				RListIter *iter;
				RTypeEnum *member;
				r_list_foreach (list, iter, member) {
					r_cons_printf (core->cons, "%s = %s\n", member->name, member->val);
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
						r_cons_println (core->cons, name);
					}
				}
			}
			free (name);
			ls_free (l);
			break;
		}
		case '?':
			r_core_cmd_help (core, help_msg_te);
			break;
		default:
			r_core_return_invalid_command (core, "te", *input);
			break;
		} // end of switch (input[1])
		free (name);
		if (res) {
			r_cons_println (core->cons, res);
		} else if (member_name) {
			R_LOG_ERROR ("Invalid enum member");
		}
		break;
	}
	case ' ': // "t "
		  {
			  const char *token = r_str_trim_head_ro (input + 1);
			  const char *typdef = sdb_const_get (core->anal->sdb_types, token, 0);
			  // Resolve typedef if any
			  if (typdef && !strcmp (typdef, "typedef")) {
				  r_strf_var (a, 128, "typedef.%s", token);
				  const char *tokendef = sdb_const_get (core->anal->sdb_types, a, 0);
				  if (tokendef) {
					  token = tokendef;
				  }
			  }
			  showFormat (core, token, 0);
		  }
		break;
	// t* - list all types in 'pf' syntax
	case 'j': // "tj"
	case '*': // "t*"
	case '\0': // "t"
		if (input[0] && input[1] == '?') {
			r_core_cmd_help_match_spec (core, help_msg_t, "t", input[0]);
		} else {
			typesList (core, input[0]);
		}
		break;
	case 'o': // "to"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_to);
		} else if (!r_sandbox_enable (0)) {
			if (input[1] == ' ') {
				const char *dir = r_config_get (core->config, "dir.types");
				const char *filename = r_str_trim_head_ro (input + 2);
				char *homefile = NULL;
				if (*filename == '~') {
					if (filename[1] && filename[2]) {
						homefile = r_file_home (filename + 2);
						filename = homefile;
					}
				}
				if (!strcmp (filename, "-")) {
					char *tmp = r_core_editor (core, "*.h", "");
					if (tmp) {
						char *errmsg = NULL;
						char *out = r_anal_cparse (core->anal, tmp, &errmsg);
						if (out) {
							// r_cons_print (core->cons, out);
							r_anal_save_parsed_type (core->anal, out);
							free (out);
						}
						if (errmsg) {
							R_LOG_ERROR ("%s", errmsg);
							free (errmsg);
						}
						free (tmp);
					}
				} else {
					char *errmsg = NULL;
					char *out = r_anal_cparse_file (core->anal, filename, dir, &errmsg);
					if (out) {
						// r_cons_print (core->cons, out);
						r_anal_save_parsed_type (core->anal, out);
						free (out);
					}
					if (errmsg) {
						R_LOG_ERROR ("%s", errmsg);
						free (errmsg);
					}
				}
				free (homefile);
			} else if (input[1] == 'u') {
				// "tou" "touch"
				char *arg = strchr (input, ' ');
				if (arg) {
					r_file_touch (arg + 1);
				} else {
					r_core_cmd_help_match (core, help_msg_to, "touch");
				}
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
					char *errmsg = NULL;
					char *out = r_anal_cparse (core->anal, tmp, &errmsg);
					if (out) {
						// remove previous types and save new edited types
						sdb_reset (TDB);
						r_anal_save_parsed_type (core->anal, out);
						free (out);
					}
					if (errmsg) {
						R_LOG_ERROR ("%s", errmsg);
						free (errmsg);
					}
					free (tmp);
				}
				free (str);
			}
		} else {
			R_LOG_ERROR ("Sandbox: system call disabled");
		}
		break;
	// td - parse string with cparse engine and load types from it
	case 'd': // "td"
		if (input[1] == '?') {
			// TODO #7967 help refactor: move to detail
			r_core_cmd_help_match (core, help_msg_t, "td");
		} else if (input[1] == ' ') {
			char *tmp = r_str_newf ("%s;", input + 2);
			if (!tmp) {
				break;
			}
			char *errmsg = NULL;
			char *out = r_anal_cparse (core->anal, tmp, &errmsg);
			free (tmp);
			if (out) {
				r_anal_save_parsed_type (core->anal, out);
				free (out);
			}
			if (errmsg) {
				R_LOG_ERROR ("%s", errmsg);
				free (errmsg);
			}
		} else {
			R_LOG_ERROR ("Invalid use of td. See td? for help");
		}
		break;
	case 'v': // "tv"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_tv);
			break;
		case ' ':
			print_type_view (core, r_str_trim_head_ro (input + 2));
			break;
		case 0:
			print_type_view (core, NULL);
			break;
		default:
			r_core_return_invalid_command (core, "tv", input[1]);
			break;
		}
		break;
	case 'x': {
		  char *type, *type2;
		RListIter *iter, *iter2;
		RAnalFunction *fcn;
		switch (input[1]) {
		case '.': // "tx." type xrefs
		case 'f': // "txf" type xrefs
			{
			ut64 addr = core->addr;
			if (input[2] == ' ') {
				addr = r_num_math (core->num, input + 2);
			}
			fcn = r_anal_get_function_at (core->anal, addr);
			if (fcn) {
				RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
				r_list_foreach (uniq , iter , type) {
					r_cons_println (core->cons, type);
				}
				r_list_free (uniq);
			} else {
				R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, addr);
			}
			}
			break;
		case 0: // "tx"
			r_list_foreach (core->anal->fcns, iter, fcn) {
				RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
				if (r_list_length (uniq)) {
					r_cons_printf (core->cons, "%s: ", fcn->name);
				}
				r_list_foreach (uniq , iter2, type) {
					r_cons_printf (core->cons, "%s%s", type, iter2->n ? ",":"\n");
				}
			}
			break;
		case 'g': // "txg"
			{
				r_list_foreach (core->anal->fcns, iter, fcn) {
					RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
					if (r_list_length (uniq)) {
						r_cons_printf (core->cons, "agn %s\n", fcn->name);
					}
					r_list_foreach (uniq , iter2, type) {
						char *myType = strdup (type);
						r_str_replace_ch (myType, ' ', '_', true);
						r_cons_printf (core->cons, "agn %s\n", myType);
						r_cons_printf (core->cons, "age %s %s\n", myType, fcn->name);
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
					r_cons_printf (core->cons, "%s\n", type);
				}
				r_list_free (uniqList);
			}
			break;
		case 't': // "txt"
		case ' ': // "tx " -- show which function use given type
			type = (char *)r_str_trim_head_ro (input + 2);
			r_list_foreach (core->anal->fcns, iter, fcn) {
				RList *uniq = r_anal_types_from_fcn (core->anal, fcn);
				r_list_foreach (uniq , iter2, type2) {
					if (!strcmp (type2, type)) {
						r_cons_printf (core->cons, "%s\n", fcn->name);
						break;
					}
				}
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_tx);
			break;
		}
		break;
	}
	// ta: moved to anal hints (aht)- just for tail, at the moment
	case 'a': // "ta"
		switch (input[1]) {
		case 'c': // "tac"
			cmd_tac (core, input);
			break;
		case 'i': // "tai"
			if (input[2] == 'l') {
				cmd_tail (core, input);
			} else {
				r_core_cmd_help_match (core, help_msg_t, "tail");
			}
			break;
		default:
			r_core_cmd_help_contains (core, help_msg_t, "ta");
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
			ut64 addr = core->addr;

			if (ptr) {
				*ptr++ = 0;
				r_str_trim (ptr);
				if (ptr && *ptr) {
					addr = r_num_math (core->num, ptr);
				} else {
					R_LOG_ERROR ("tl: Address is invalid");
					free (type);
					break;
				}
			}
			r_str_trim (type);
			char *tmp = sdb_get (TDB, type, 0);
			if (R_STR_ISNOTEMPTY (tmp)) {
				r_type_set_link (TDB, type, addr);
				RList *fcns = r_anal_get_functions_in (core->anal, core->addr);
				if (r_list_length (fcns) > 1) {
					R_LOG_ERROR ("Multiple functions found in here");
				} else if (r_list_length (fcns) == 1) {
					RAnalFunction *fcn = r_list_first (fcns);
					r_core_link_stroff (core, fcn);
				} else {
					R_LOG_ERROR ("Cannot find any function here");
				}
				r_list_free (fcns);
				free (tmp);
			} else {
				R_LOG_ERROR ("unknown type %s", type);
			}
			free (type);
			break;
		}
		case 's': {
			char *ptr = r_str_trim_dup (input + 2);
			ut64 addr = r_num_math (NULL, ptr);
			char *query = r_str_newf ("link.%08" PFMT64x, addr);
			const char *link = sdb_const_get (TDB, query, 0);
			if (link) {
				print_link_readable_cb (core, query, link);
			}
			free (ptr);
			free (query);
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
			print_keys (core, stdiflink, print_link_r_cb, false);
			break;
		case 'l':
			switch (input[2]) {
			case 'j':
				print_keys (core, stdiflink, print_link_readable_json_cb, true);
				break;
			default:
				print_keys (core, stdiflink, print_link_readable_cb, false);
				break;
			}
			break;
		case 'j':
			print_keys (core, stdiflink, print_link_json_cb, true);
			break;
		case '\0':
			print_keys (core, stdiflink, print_link_cb, false);
			break;
		}
		break;
	case 'p':  // "tp"
		if (input[1] == '?') { // "tp?"
			r_core_cmd_help (core, help_msg_tp);
		} else if (input[1] == 'v') { // "tpv"
			const char *type_name = r_str_trim_head_ro (input + 2);
			char *fmt = r_type_format (TDB, type_name);
			if (fmt && *fmt) {
				ut64 val = core->addr;
				r_core_cmdf (core, "pf %s @v:0x%08" PFMT64x, fmt, val);
			} else {
				r_core_cmd_help_match (core, help_msg_tp, "tpv");
			}
		} else if (input[1] == ' ' || input[1] == 'x' || !input[1]) {
			char *tmp = strdup (input);
			char *type_begin = strchr (tmp, ' ');
			if (type_begin) {
				r_str_trim (type_begin);
				const char *type_end = r_str_rchr (type_begin, NULL, ' ');
				int type_len = (type_end)
					? (int)(type_end - type_begin)
					: strlen (type_begin);
				char *type = strdup (type_begin);
				if (!type) {
					free (tmp);
					break;
				}
				snprintf (type, type_len + 1, "%s", type_begin);
				const char *arg = (type_end) ? type_end + 1 : NULL;
				char *fmt = r_type_format (TDB, type);
				if (!fmt) {
					R_LOG_ERROR ("Cannot find '%s' type", type);
					free (tmp);
					free (type);
					break;
				}
				if (input[1] == 'x' && arg) { // "tpx"
					r_core_cmdf (core, "pf %s @x:%s", fmt, arg);
				} else {
					ut64 addr = arg ? r_num_math (core->num, arg): core->addr;
					ut64 original_addr = addr;
					if (!addr && arg) {
						RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, -1);
						if (fcn) {
							RAnalVar *var = r_anal_function_get_var_byname (fcn, arg);
							if (var) {
								addr = r_anal_var_addr (var);
							}
						}
					}
					int type_size = r_type_get_bitsize (core->anal->sdb_types, type) / 8;
					int obs = core->blocksize;
					if (type_size > obs) {
						r_core_block_size (core, type_size);
					}
					if (addr != UT64_MAX) {
						r_core_cmdf (core, "pf %s @ 0x%08"PFMT64x, fmt, addr);
					} else if (original_addr == 0) {
						r_core_cmdf (core, "pf %s @ 0x%08"PFMT64x, fmt, original_addr);
					}
					if (type_size > obs) {
						r_core_block_size (core, obs);
					}
				}
				free (fmt);
				free (type);
			} else {
				r_core_cmd_help (core, help_msg_tp);
			}
			free (tmp);
		} else { // "tp"
			r_core_cmd_help (core, help_msg_tp);
		}
		break;
	case '-': // "t-"
		if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_t, "t-");
		} else if (input[1] == '*') {
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_t, "t-*");
			} else {
				sdb_reset (TDB);
			}
		} else {
			const char *arg = r_str_trim_head_ro (input + 1);
			if (*arg) {
				if (strchr (arg, '*') || strchr (arg, ' ')) {
					types_remove_glob (core, stdifany, arg);
				} else {
					r_anal_remove_parsed_type (core->anal, arg);
				}
			} else {
				R_LOG_ERROR ("Invalid use of t-. See t-? for help");
			}
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f': // "tf"
		switch (input[1]) {
		case 0: // "tf"
			print_keys (core, stdiffunc, printkey_cb, false);
			break;
		case 'c': // "tfc"
			if (input[2] == ' ') {
				printFunctionTypeC (core, input + 3);
			} else {
				// No argument: print all function signatures in C syntax
				SdbList *l = sdb_foreach_list_filter (TDB, stdiffunc, true);
				SdbListIter *it;
				SdbKv *kv;
				ls_foreach (l, it, kv) {
					const char *fname = sdbkv_key (kv);
					if (R_STR_ISNOTEMPTY (fname)) {
						printFunctionTypeC (core, fname);
					}
				}
				ls_free (l);
			}
			break;
		case 'e': // "tfe"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_tf, "tfe");
			} else {
				cmd_type_edit (core, r_str_trim_head_ro (input + 2), "tfc");
			}
			break;
		case 'j': // "tfj"
			if (input[2] == ' ') {
				printFunctionType (core, input + 2);
				r_cons_newline (core->cons);
			} else {
				print_keys (core, stdiffunc, printfunc_json_cb, true);
			}
			break;
		case ' ': {
			char *k = r_str_newf ("~~func.%s", input + 2);
			char *res = sdb_querys (TDB, NULL, -1, k);
			free (k);
			if (res) {
				r_cons_printf (core->cons, "%s", res);
				free (res);
			}
			break;
		}
		default:
			r_core_cmd_help (core, help_msg_tf);
			break;
		}
		break;
	case 't': { // "tt"
		if (!input[1] || input[1] == 'j') {
			PJ *pj = NULL;
			if (input[1] == 'j') {
				pj = r_core_pj_new (core);
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
							r_cons_println (core->cons, name);
						} else {
							char *q = r_str_newf ("typedef.%s", name);
							const char *res = sdb_const_get (TDB, q, 0);
							if (!res) {
								res = "";
							}
							pj_ks (pj, name, res);
							free (q);
						}
					}
				}
			}
			if (input[1] == 'j') {
				pj_end (pj);
			}
			if (pj) {
				r_cons_printf (core->cons, "%s\n", pj_string (pj));
				pj_free (pj);
			}
			free (name);
			ls_free (l);
			break;
		}
		if (input[1] == 'c') { // "ttc"
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
						char *q = r_str_newf ("typedef.%s", name);
						const char *res = sdb_const_get (TDB, q, 0);
						free (q);
						if (res) {
							r_cons_printf (core->cons, "%s %s %s;\n", sdbkv_value (kv), res, name);
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
		if (input[1] == 'e') { // "tte"
			if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_tt, "tte");
			} else {
				cmd_type_edit (core, r_str_trim_head_ro (input + 2), "ttc");
			}
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
			char *q = r_str_newf ("typedef.%s", s);
			const char *res = sdb_const_get (TDB, q, 0);
			if (res) {
				r_cons_println (core->cons, res);
			}
			free (q);
		} else {
			R_LOG_ERROR ("This is not a typedef");
		}
		free (s);
		break;
	}
	case '?':
		r_core_cmd_help (core, help_msg_t);
		break;
	default:
		r_core_return_invalid_command (core, "t", *input);
		break;
	}
	return true;
}

#endif
