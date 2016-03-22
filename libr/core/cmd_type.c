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
		"te", "", "List all loaded enums",
		"te", " <enum> <value>", "Show name for given enum number",
		"td", " <string>", "Load types from string",
		"tf", "", "List all loaded functions signitures",
		"tk", " <sdb-query>", "Perform sdb query",
		"tl", "[?]", "Show/Link type to an address",
		//"to",  "",         "List opened files",
		"to", " -", "Open cfg.editor to load types",
		"to", " <path>", "Load types from C header file",
		"ts", "", "print loaded struct types",
		"tu", "", "print loaded union types",
		//"| ts k=v k=v @ link.addr set fields at given linked type\n"
		NULL };
	r_core_cmd_help (core, help_message);
}
//TODO
//look at the next couple of functions
//can be optimized into one right ... you see it you do it :P
static int sdbforcb(void *p, const char *k, const char *v) {
	if (!strncmp (v, "type", strlen ("type") + 1))
		r_cons_printf ("%s\n", k);
	return 1;
}
static int stdprintifstruct(void *p, const char *k, const char *v) {
	if (!strncmp (v, "struct", strlen ("struct") + 1))
		r_cons_printf ("%s\n", k);
	return 1;
}
static int stdprintiffunc(void *p, const char *k, const char *v) {
	if (!strncmp (v, "func", strlen ("func") + 1))
		r_cons_printf ("%s\n", k);
	return 1;
}
static int stdprintifunion(void *p, const char *k, const char *v) {
	if (!strncmp (v, "union", strlen ("union") + 1))
		r_cons_printf ("%s\n", k);
	return 1;
}
static int sdbdelete(void *p, const char *k, const char *v) {
	RCore *core = (RCore *)p;
	r_anal_type_del (core->anal, k);
	return 1;
}
static int typelist(void *p, const char *k, const char *v) {
	r_cons_printf ("tk %s = %s \n", k, v);
	return 1;
}

static int cmd_type(void *data, const char *input) {
	RCore *core = (RCore *)data;

	switch (input[0]) {
	// t [typename] - show given type in C syntax
	case 'u':
		switch (input[1]) {
		case '?': {
			const char *help_message[] = {
				"USAGE tu[...]", "", "",
				"tu", "", "List all loaded unions",
				"tu?", "", "show this help",
				NULL };
			r_core_cmd_help (core, help_message);
		} break;
		case 0:
			sdb_foreach (core->anal->sdb_types, stdprintifunion, core);
			break;
		}break;

	case 'k':
		if (input[1] == ' ') {
			sdb_query (core->anal->sdb_types, input + 2);
		} else sdb_query (core->anal->sdb_types, "*");
		break;
	case 's':
		switch (input[1]) {
		case '?': {
			const char *help_message[] = {
				"USAGE ts[...]", "", "",
				"ts", "", "List all loaded structs",
				"ts?", "", "show this help",
				NULL };
			r_core_cmd_help (core, help_message);
		} break;
		case 0:
			sdb_foreach (core->anal->sdb_types, stdprintifstruct, core);
			break;
		}break;
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
		if (input[1] == '?') {
			const char *help_message[] = {
				"USAGE te[...]", "", "",
				"te", "", "List all loaded enums",
				"te", " <enum> <value>", "Show name for given enum number",
				"te?", "", "show this help",
				NULL };
			r_core_cmd_help (core, help_message);
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
				"Usage:", "\"td [...]\"", "",
				"td", "[string]", "Load types from string",
				NULL };
			r_core_cmd_help (core, help_message);
			r_cons_printf ("Note: The td command should be put between double quotes\n"
				"Example: \" td struct foo {int bar;int cow};\""
				"\nt");

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
			while (IS_WHITESPACE (*name)) name++;
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
	case 'f':
		sdb_foreach (core->anal->sdb_types, stdprintiffunc, core);
		break;

	case '?':
		show_help (core);
		break;
	}
	return true;
}
