/* radare - LGPL - Copyright 2009-2016 - pancake, oddcoder, Anton Kochkov, Jody Frankowski */

static void show_help(RCore *core) {
	const char *help_message[] = {
		"Usage: t", "", "# cparse types commands",
		"t", "", "List all loaded types",
		"t", " <type>", "Show type in 'pf' syntax",
		"t*", "", "List types info in r2 commands",
		"t-", " <name>", "Delete types by its name",
		"t-*", "", "Remove all types",
		//"t-!", "",          "Use to open $EDITOR",
		"tb", " <enum> <value>", "Show matching enum bitfield for given number",
		"te", " <enum> <value>", "Show name for given enum number",
		"td", " <string>", "Load types from string",
		"td-", "<name>", "Undefine type by name",
		"tf", " <addr>", "View linked type at given address",
		"tl", "[?]", "Show/Link type to an address",
		//"to",  "",         "List opened files",
		"to", " -", "Open cfg.editor to load types",
		"to", " <path>", "Load types from C header file",
		"tk", " <sdb-query>", "Perform sdb query",
		"ts", " <k>=<v>", "Set fields at curseek linked type",
		//"| ts k=v k=v @ link.addr set fields at given linked type\n"
		NULL };
	r_core_cmd_help (core, help_message);
}

static int sdbforcb(void *p, const char *k, const char *v) {
	r_cons_printf ("%s=%s\n", k, v);
	return 1;
}
static int sdbdelete(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	r_anal_type_del (core->anal, k);
	return 1;
}
static int typelist(void *p, const char *k, const char *v) {
#define DB core->anal->sdb_types
	RCore *core = (RCore *)p;
	int i;
	if (!strcmp (v, "func")) {
		const char *rv = sdb_const_get (DB,
						sdb_fmt (0, "func.%s.ret", k), 0);
		r_cons_printf ("# %s %s(", rv, k);
		for (i = 0; i < 16; i++) {
			char *av = sdb_get (DB,
					sdb_fmt (0, "func.%s.arg.%d", k, i), 0);
			if (!av) break;
			r_str_replace_char (av, ',', ' ');
			r_cons_printf ("%s%s", i? ", ": "", av);
			free (av);
		}
		r_cons_printf (");\n");
		// signature in pf for asf
		r_cons_printf ("asf %s=", k);
		// formats
		for (i = 0; i < 16; i++) {
			const char *fmt;
			char *comma, *av = sdb_get (DB,
						sdb_fmt (0, "func.%s.arg.%d", k, i), 0);
			if (!av) break;
			comma = strchr (av, ',');
			if (comma) *comma = 0;
			fmt = sdb_const_get (DB, sdb_fmt (0, "type.%s", av), 0);
			r_cons_printf ("%s", fmt);
			if (comma) *comma = ',';
			free (av);
		}
		// names
		for (i = 0; i < 16; i++) {
			char *comma, *av = sdb_get (DB,
						sdb_fmt (0, "func.%s.arg.%d", k, i), 0);
			if (!av) break;
			comma = strchr (av, ',');
			if (comma) *comma++ = 0;
			r_cons_printf (" %s", comma);
			free (av);
		}
		r_cons_newline ();
	}
	return 1;
}

static int cmd_type(void *data, const char *input) {
	RCore *core = (RCore *)data;

	switch (input[0]) {
	// t [typename] - show given type in C syntax
	case 'k':
		if (input[1] == ' ') {
			sdb_query (core->anal->sdb_types, input + 2);
		} else sdb_query (core->anal->sdb_types, "*");
		break;
	case 's': {
		char *q, *p, *o, *e;
		p = o = strdup (input + 1);
		for (;;) {
			if (*p == '\0') {
				eprintf ("Usage: ts <k>=<v> Set fields at curseek linked type\n");
				break;
			}
			q = strchr (p, ' ');
			if (q) *q = 0;
			if (!*p) {
				p++;
				continue;
			}
			e = strchr (p, '=');
			if (e) {
				*e = 0;
				r_anal_type_set (core->anal, core->offset,
						p, r_num_math (core->num, e + 1));
			} else eprintf ("TODO: implement get\n");
			if (!q) break;
			p = q + 1;
		}
		free (o);
	} break;
	case 'b': {
		char *p, *s = (strlen (input) > 1)? strdup (input + 2): NULL;
		const char *isenum;
		p = s? strchr (s, ' '): NULL;
		if (p) {
			*p++ = 0;
			// dupp in core.c (see getbitfield())
			isenum = sdb_const_get (core->anal->sdb_types, s, 0);
			if (isenum && !strcmp (isenum, "enum")) {
				*--p = '.';
				const char *res = sdb_const_get (core->anal->sdb_types, s, 0);
				if (res)
					r_cons_printf ("%s\n", res);
				else eprintf ("Invalid enum member\n");
			} else {
				eprintf ("This is not an enum\n");
			}
		} else {
			eprintf ("Missing value\n");
		}
		free (s);
	} break;
	case 'e': {
		if (!input[1]) {
			char *name = NULL;
			SdbKv *kv;
			SdbListIter *iter;
			SdbList *l = sdb_foreach_list (core->anal->sdb_types);
			ls_foreach (l, iter, kv) {
				if (!strcmp (kv->value, "enum")) {
					if (!name || strcmp (kv->value, name)) {
						free (name);
						name = strdup (kv->key);
						r_cons_printf ("%s\n", name);
					}
				}
			}
			free (name);
			ls_free (l);
			break;
		}
		char *p, *s = strdup (input + 2);
		const char *isenum;
		p = strchr (s, ' ');
		if (p) {
			*p++ = 0;
			isenum = sdb_const_get (core->anal->sdb_types, s, 0);
			if (isenum && !strcmp (isenum, "enum")) {
				const char *q = sdb_fmt (0, "%s.0x%x", s, (ut32)r_num_math (core->num, p));
				const char *res = sdb_const_get (core->anal->sdb_types, q, 0);
				if (res)
					r_cons_printf ("%s\n", res);
			} else {
				eprintf ("This is not an enum\n");
			}
		} else {
			//eprintf ("Missing value\n");
			r_core_cmdf (core, "t~&%s,=0x", s);
		}
		free (s);
	} break;
	case ' ': {
		const char *isenum = sdb_const_get (core->anal->sdb_types, input + 1, 0);
		if (isenum && !strcmp (isenum, "enum")) {
			eprintf ("IS ENUM! \n");
		} else {
			char *fmt = r_anal_type_format (core->anal, input + 1);
			if (fmt) {
				r_cons_printf ("pf %s\n", fmt);
				free (fmt);
			} else eprintf ("Cannot find '%s' type\n", input + 1);
		}
	} break;
	// t* - list all types in 'pf' syntax
	case '*':
		sdb_foreach (core->anal->sdb_types, typelist, core);
		break;
	case 0:
		sdb_foreach (core->anal->sdb_types, sdbforcb, core);
		break;
	case 'o':
		if (!r_sandbox_enable (0)) {
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
						out = r_parse_c_string (tmp);
						if (out) {
							//		r_cons_strcat (out);
							sdb_query_lines (core->anal->sdb_types, out);
							free (out);
						}
						free (tmp);
					}
				} else {
					char *out = r_parse_c_file (filename);
					if (out) {
						//r_cons_strcat (out);
						sdb_query_lines (core->anal->sdb_types, out);
						free (out);
					}
					//r_anal_type_loadfile (core->anal, filename);
				}
				free (homefile);
			}
		} else {
			eprintf ("Sandbox: system call disabled\n");
		}
		break;
	// td - parse string with cparse engine and load types from it
	case 'd':
		if (input[1] == '?') {
			const char *help_message[] = {
				"Usage:", "td[...]", "",
				"td", "[string]", "Load types from string",
				NULL };
			r_core_cmd_help (core, help_message);
		} else if (input[1] == '-') {
			const char *arg = strchr (input + 1, ' ');
			if (arg)
				arg++;
			else arg = input + 2;
			r_anal_type_del (core->anal, arg);
		} else if (input[1] == ' ') {
			char tmp[8192];
			snprintf (tmp, sizeof (tmp) - 1, "%s;", input + 2);
			//const char *string = input + 2;
			//r_anal_str_to_type (core->anal, string);
			char *out = r_parse_c_string (tmp);
			if (out) {
				//r_cons_strcat (out);
				sdb_query_lines (core->anal->sdb_types, out);
				free (out);
			}
		} else {
			eprintf ("Invalid use of td. See td? for help\n");
		}
		break;
	// tl - link a type to an address
	case 'l':
		if (input[1] == '?') {
			const char *help_message[] = {
				"Usage: tl", " [typename|addr] ([addr])@[addr|function]", "",
				NULL };

			r_core_cmd_help (core, help_message);
		} else if (input[1]) {
			ut64 addr = r_num_math (core->num, input + 2);
			char *ptr = strchr (input + 2, ' ');
			if (ptr) {
				addr = r_num_math (core->num, ptr + 1);
				*ptr = '\0';
			} else addr = core->offset;
			r_anal_type_link (core->anal, input + 2, addr);
		} else {
			r_core_cmd0 (core, "t~^link");
		}
		break;
	case '-':
		if (input[1] == '?') {
			const char *help_message[] = {
				"Usage: t-", " <type>", "Delete type by its name",
				NULL };

			r_core_cmd_help (core, help_message);
		} else if (input[1] == '*') {
			sdb_foreach (core->anal->sdb_types, sdbdelete, core);
		} else {
			const char *name = input + 1;
			if (*name == ' ') name++;
			if (*name) {
				SdbKv *kv;
				SdbListIter *iter;
				int tmp_len = strlen (name);
				char *tmp = malloc (tmp_len + 2);
				r_anal_type_del (core->anal, name);
				if (tmp) {
					snprintf (tmp, tmp_len + 1, "%s.", name);
					SdbList *l = sdb_foreach_list (core->anal->sdb_types);
					ls_foreach (l, iter, kv) {
						if (!strncmp (kv->key, tmp, tmp_len - 1))
							r_anal_type_del (core->anal, kv->key);
					}
					free (tmp);
				}
			} else eprintf ("Invalid use of t- . See t-? for help.\n");
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f': {
		ut64 addr;
		char *fmt, key[128];
		const char *type;
		if (input[1]) {
			addr = r_num_math (core->num, input + 1);
		} else addr = core->offset;
		snprintf (key, sizeof (key), "link.%08" PFMT64x, addr);
		type = sdb_const_get (core->anal->sdb_types, key, 0);
		if (type) {
			fmt = r_anal_type_format (core->anal, type);
			r_cons_printf ("struct %s {\n", type);
			if (fmt) {
				r_core_cmdf (core, "pf %s @ 0x%08" PFMT64x "\n", fmt, addr);
				free (fmt);
			} // else eprintf ("Cannot find '%s' type\n", input+1);
			r_cons_printf ("}\n");
		} //else eprintf ("Cannot find type at 0x%llx\n", addr);
	} break;
	case '?':
		show_help (core);
		break;
	}
	return true;
}
