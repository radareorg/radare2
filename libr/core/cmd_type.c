/* radare - LGPL - Copyright 2009-2013 - pancake, Anton Kochkov */

static void show_help() {
	eprintf ("|Usage: t[-LCvsdfm?] [...]\n"
	"| t                      list all loaded types\n"
	"| t*                     list types info in r2 commands\n"
	"| t- [name]              delete type by its name.\n"
	"| t-*                    remove all types\n"
	//"|. Use t-! to open $EDITOR\n"
	"| t [type]               show given type in 'pf' syntax\n"
	//"| to                     list of opened files\n"
	"| to [path]              load types from C header file\n"
	"| to -                   open cfg.editor to load types\n"
	"| td int foo(int a)      parse oneliner type definition\n"
	"| td-foo                 undefine type 'foo'\n"
	"| tf addr                view linked type at given address\n"
	"| ts k=v k=v @ link.addr set fields at given linked type\n"
	"| tl [type] ([addr])     show show / link type to a address\n");
}

static int sdbforcb (void *p, const char *k, const char *v) {
	r_cons_printf ("%s=%s\n", k, v);
	return 1;
}

static int cmd_type(void *data, const char *input) {
	RCore *core = (RCore*)data;

	switch (input[0]) {
	// t [typename] - show given type in C syntax
	case 's':
	{
		char *q, *p, *o, *e;
		p = o = strdup (input+1);
		for (;;) {
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
					p, r_num_math (core->num, e+1));
			} else eprintf ("TODO: implement get\n");
			if (!q) break;
			p = q+1;
		}
		free (o);
	}
		break;
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
		//sdb_list (core->anal->sdb_types);
		sdb_foreach (core->anal->sdb_types, sdbforcb, core);
		break;
	case 'o':
		if (input[1] == ' ') {
			const char *filename = input + 2;
			if (!strcmp (filename, "-")) {
				char *out, *tmp;
				tmp = r_core_editor (core, "");
				if (tmp) {
					out = r_parse_c_string (tmp);
					if (out) {
						r_cons_strcat (out);
						sdb_query_lines (core->anal->sdb_types, out);
						free (out);
					}
					free (tmp);
				}
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
		if (input[1] == '-') {
			const char *arg = strchr (input+1, ' ');
			if (arg) arg++; else arg = input+2;
			r_anal_type_del (core->anal, arg);
		} else
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
		if (input[1]=='?') {
			eprintf("Usage: tl[...]\n"
				" tl [typename|addr] ([addr])@[addr|function]\n");
		} else if (input[1]) {
			ut64 addr = r_num_math (core->num, input+2);
			char *ptr = strchr (input + 2, ' ');
			if (ptr) {
				addr = r_num_math (core->num, ptr + 1);
				*ptr = '\0';
			} else addr = core->offset;
			r_anal_type_link (core->anal, input+2, addr);
		} else {
			r_core_cmd0 (core, "t~^link");
		}
		break;
	case '-':
		if (input[1]=='*') {
			eprintf ("TODO\n");
		} else {
			const char *name = input + 1;
			if (*name==' ') name++;
			if (*name) {
				r_anal_type_del (core->anal, name);
			} else eprintf ("Usage: t- name\n"
				"t- name : delete type by its name\n");
		}
		break;
	// tv - get/set type value linked to a given address
	case 'f':
		 {
			ut64 addr;
			char *fmt, key[128];
			const char *type;
			if (input[1]) {
				addr = r_num_math (core->num, input+1);
			} else addr = core->offset;
			snprintf (key, sizeof (key), "link.%"PFMT64x, addr);
			type = sdb_const_get (core->anal->sdb_types, key, 0);
			fmt = r_anal_type_format (core->anal, type);
			if (fmt) {
				r_core_cmdf (core, "pf %s @ 0x%08"PFMT64x"\n", fmt, addr);
				free (fmt);
			}// else eprintf ("Cannot find '%s' type\n", input+1);
		 }
		break;
	case '?':
		if (input[1]) {
			sdb_query (core->anal->sdb_types, input+1);
		} else show_help();

		break;
	}
	return R_TRUE;
}
