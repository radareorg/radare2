/* radare - LGPL - Copyright 2009-2012 // pancake<nopcode.org> */
static int cmd_macro(void *data, const char *input) {
	char *buf = NULL;
	char *p, *ptr = (char *)input;
	RCore *core = (RCore*)data;
	switch (*input) {
	case ')':
		r_cmd_macro_break (&core->cmd->macro, input+1);
		break;
	case '-':
		r_cmd_macro_rm (&core->cmd->macro, input+1);
		break;
	case '*':
	case '\0':
		r_cmd_macro_list (&core->cmd->macro);
		break;
	case '?':
		eprintf (
		"Usage: (foo\\n..cmds..\\n)\n"
		" Record macros grouping commands\n"
		" (foo args\\n ..)     ; define a macro\n"
		" (-foo)              ; remove a macro\n"
		" .(foo)              ; to call it\n"
		" ()                  ; break inside macro\n"
		" (*                  ; list all defined macros\n"
		"Argument support:\n"
		" (foo x y\\n$1 @ $2)  ; define fun with args\n"
		" .(foo 128 0x804800) ; call it with args\n"
		"Iterations:\n"
		" .(foo\\n() $@)       ; define iterator returning iter index\n"
		" x @@ .(foo)         ; iterate over them\n"
		);
		break;
	default:
		if (input[strlen (input)-1] != ')') {
			buf = malloc (4096); // XXX: possible heap overflow here
			strcpy (buf, input);
			do {
				ptr = buf + strlen (buf);
				strcpy (ptr, ",");
				ptr++;
				fgets (ptr, 1024, stdin); // XXX: possible overflow // TODO: use r_cons here
				p = strchr (ptr, '#');
				if (p) *p = 0;
				else ptr[strlen (ptr)-1] = 0; // chop \n
				if (feof (stdin))
					break;
			} while (ptr[strlen (ptr)-1] != ')');
			ptr = buf;
		} else {
			buf = strdup (input);
			buf[strlen (input)-1] = 0;
		}
		r_cmd_macro_add (&core->cmd->macro, buf);
		free (buf);
		break;
	}
	return 0;
}

