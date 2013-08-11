/* radare - LGPL - Copyright 2009-2013 - pancake, Anton Kochkov */


static void cmd_type_init(RCore *core) {
	Sdb *D = core->anal->sdb_types;
	sdb_set (D, "type.unsigned int", "i", 0);
	sdb_set (D, "type.int", "d", 0);
	sdb_set (D, "type.long", "x", 0);
	sdb_set (D, "type.char", "x", 0);
	sdb_set (D, "type.char*", "*z", 0);
	sdb_set (D, "type.const char*", "*z", 0);
}

static int cmd_type(void *data, const char *input) {
	RCore *core = (RCore*)data;
	RAnalType *t = NULL;

	switch (input[0]) {
	// t [typename] - show given type in C syntax
#if 0
	case ' ':
	{
		const char *tname = input + 1;
		t = r_anal_type_find (core->anal, tname);
		if (t == NULL) eprintf ("Type %s not found!\n", tname);
		else r_anal_type_to_str (core->anal, t, "; ");
	}
		break;
	// t* - list all types in 'pf' syntax
	case '*':
		r_anal_type_list (core->anal, R_ANAL_TYPE_ANY, 1);
		break;
#endif
	case 0:
		sdb_list (core->anal->sdb_types);
		break;
	case 'f':
		if (input[1] == ' ') {
			const char *filename = input + 2;
			if (!strcmp (filename, "-")) {
#if 0
				char *out, *ctype = "";
				out = r_core_editor (core, ctype);
				t = r_anal_str_to_type (core->anal, out);
				if (t != NULL)
					r_anal_type_add (core->anal, t);
				free (out);
				free (ctype);
#endif
			} else {
				char *out = r_parse_c_file (filename);
				if (out) {
					r_cons_strcat (out);
					sdb_query_lines (core->anal->sdb_types, out);
					free (out);
				}
				//r_anal_type_loadfile (core->anal, filename);
			}
		}
		break;
	// td - parse string with cparse engine and load types from it
	case 'd':
		if (input[1] == ' ') {
			const char *string = input + 2;
			//r_anal_str_to_type (core->anal, string);
			char *out = r_parse_c_string (string);
			if (out) {
				r_cons_strcat (out);
				sdb_query_lines (core->anal->sdb_types, out);
				free (out);
			}
		} else {
			eprintf ("Usage: td[...]\n"
				" td [string]    : load types from string\n");
		}
		break;
	// tl - link a type to an address
	case 'l':
	{
		char var[128], *ptr = NULL;
		ut64 addr = core->offset;
		ptr = strchr (input + 2, ' ');
		if (ptr) {
			*ptr = '\0';
			addr = r_num_math (core->num, ptr + 1);
			if (addr > 0) {
				if (sdb_getc (core->anal->sdb_types, input+2,0)) {
				sprintf (var, "link.%08"PFMT64x, addr);
				sdb_set (core->anal->sdb_types, var, input+2, 0);
				} else eprintf ("Cannot find type\n");
			} else eprintf ("Wrong address to link!\n");
		} else
			eprintf("Usage: tl[...]\n"
				" tl [typename] ([addr])@[addr|function]\n");
	}
		break;
#if 0
	// tv - get/set type value linked to a given address
	case 'v':
		break;
	case 'h':
		switch (input[1]) {
		case ' ':
			break;
		/* Convert type into format string */
		case '*':
			break;
		default:
			eprintf ("Usage: th[..]\n"
				"th [path] [name] : show definition of type\n");
			break;
		}
		break;
	case '-':
		if (input[1]!='*') {
			ut64 n = r_num_math (core->num, input + ((input[1] == ' ') ? 2 : 1));
			eprintf ("val 0x%"PFMT64x"\n", n);
			//TODO r_anal_type_del (core->anal->types, R_ANAL_TYPE_ANY, core->offset, i, "");
		} else {
			const char *ntr, *name = input + 2;
			ntr = strchr(name, ' ');
			if (ntr && !ntr[1]) {
				r_anal_type_del (core->anal, name);
			} else
				eprintf ("Usage: t- name\n"
					"t- name : delete type by its name\n");
		}
		break;
	// t - list all types in C syntax
	case '\0':
	{
		RListIter *k;
		RAnalType *t;
		r_list_foreach (core->anal->types, k, t) {
			const char *str = r_anal_type_to_str (core->anal, t, "; ");
			r_cons_printf ("%s\n", str);
		}
	}
		break;
#endif
	case '?':
		if (input[1]) {
			sdb_query (core->anal->sdb_types, input+1);
		} else
		eprintf (
		"Usage: t[-LCvsdfm?] [...]\n"
		" t                      # list all loaded types\n"
		" t*                     # list types info in r2 commands\n"
		" t- [name]              # delete type by its name. Use t-* to remove all types. Use t-! to open $EDITOR\n"
		" t [type]               # show given type in C syntax\n"
		" tf [path]              # load types from C header file\n"
		" tf -                   # open cfg.editor to load types\n"
		" td int foo(int a);     # parse oneliner type definition\n"
		" tl [type] [addr]       # link type to a given address\n");
		break;
	}
	return R_TRUE;
}
