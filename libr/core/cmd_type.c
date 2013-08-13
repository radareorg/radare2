/* radare - LGPL - Copyright 2009-2013 - pancake, Anton Kochkov */

static void show_help() {
	eprintf ("Usage: t[-LCvsdfm?] [...]\n"
	" t                      list all loaded types\n"
	" t*                     list types info in r2 commands\n"
	" t- [name]              delete type by its name.\n"
	" t-*                    remove all types\n"
	//". Use t-! to open $EDITOR\n"
	" t [type]               show given type in 'pf' syntax\n"
	" tf [path]              load types from C header file\n"
	" tf -                   open cfg.editor to load types\n"
	" td int foo(int a)      parse oneliner type definition\n"
	" tv addr                view linked type at given address\n"
	" tl [type] [addr]       link type to a given address\n");
}

static int cmd_type(void *data, const char *input) {
	RCore *core = (RCore*)data;
	char pcmd[512];
	RAnalType *t = NULL;

	switch (input[0]) {
	// t [typename] - show given type in C syntax
	case ' ':
	{
		char *fmt = r_anal_type_format (core->anal, input +1);
		if (fmt) {
			r_cons_printf ("pf %s\n", fmt);
			free (fmt);
		} else eprintf ("Cannot find '%s' type\n", input+1);
	}
		break;
#if 0
	// t* - list all types in 'pf' syntax
	case '*':
		r_anal_type_list (core->anal, R_ANAL_TYPE_ANY, 1);
		break;
#endif
	case 0:
		// TODO: use r_cons here
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
			char tmp[256];
			snprintf (tmp, sizeof (tmp), "%s;", input+2);
			//const char *string = input + 2;
			//r_anal_str_to_type (core->anal, string);
			char *out = r_parse_c_string (tmp);
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
		ut64 addr = r_num_math (core->num, input+2);
		char *ptr = strchr (input + 2, ' ');
		if (ptr) {
			addr = r_num_math (core->num, ptr + 1);
			*ptr = '\0';
			if (addr > 0) {
				r_anal_type_link (core->anal, input+2, addr);
			} else eprintf ("Wrong address to link!\n");
		} else
			eprintf("Usage: tl[...]\n"
				" tl [typename|addr] ([addr])@[addr|function]\n");
	}
		break;
	case '-':
		if (input[1]=='*') {
			eprintf ("TODO\n");
		} else {
			const char *ntr, *name = input + 1;
			if (*name==' ') name++;
			ntr = strchr (name, ' ');
			if (*name) {
				r_anal_type_del (core->anal, name);
			} else eprintf ("Usage: t- name\n"
				"t- name : delete type by its name\n");
		}
		break;
	// tv - get/set type value linked to a given address
	case 'v':
		snprintf (pcmd, sizeof (pcmd), "pf `t %s`", input+2);
		r_core_cmd0 (core, pcmd);
		break;
	case '?':
		if (input[1]) {
			sdb_query (core->anal->sdb_types, input+1);
		} else show_help();

		break;
	}
	return R_TRUE;
}
