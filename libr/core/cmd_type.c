/* radare - LGPL - Copyright 2009-2012 - Anton Kochkov */

static int cmd_type(void *data, const char *input) {
	RCore *core = (RCore*)data;
	RAnalType *t = NULL;

	switch (input[0]) {
	// t [typename] - show given type in C syntax
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
	case 'f':
		if (input[1] == ' ') {
			const char *filename = input + 2;
			if (!strcmp (filename, "-")) {
				char *out, *ctype = "";
				out = r_core_editor (core, ctype);
				t = r_anal_str_to_type (core->anal, out);
				if (t != NULL)
					r_anal_type_add (core->anal, t);
				free (out);
				free (ctype);
			} else {
				r_anal_type_loadfile (core->anal, filename);
			}
		}
		break;
	// td - parse string with cparse engine and load types from it
	case 'd':
		if (input[1] == ' ') {
			const char *string = input + 2;
			r_anal_str_to_type (core->anal, string);
		} else {
			eprintf ("Usage: td[...]\n"
				" td [string]    : load types from string\n");
		}
		break;
	// tl - link a type to an address
	case 'l':
	{
		char *ptr = NULL;
		ut64 addr = core->offset;
		ptr = strchr (input + 2, ' ');
		if (ptr) {
			*ptr = '\0';
			addr = r_num_math (core->num, ptr + 1);
			//do linking
			// TODO
			if (addr <= 0) {
				eprintf("Wrong address to link!\n");
			}
			eprintf ("TODO: not implemented\n");
		} else
			eprintf("Usage: tl[...]\n"
				" tl [typename] ([addr])@[addr|function]\n");
	}
		break;
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
	case '?':
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
