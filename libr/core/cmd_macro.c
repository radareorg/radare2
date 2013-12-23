/* radare - LGPL - Copyright 2009-2013 - pancake */

static int cmd_macro(void *data, const char *input) {
	char *buf = NULL;
	RCore *core = (RCore*)data;

	switch (*input) {
	case ')': r_cmd_macro_break (&core->rcmd->macro, input+1); break;
	case '-': r_cmd_macro_rm (&core->rcmd->macro, input+1); break;
	case '*':
	case '\0': r_cmd_macro_list (&core->rcmd->macro); break;
	case '(':
	case '?':
		eprintf (
		"|Usage: (foo args,cmd1,cmd2,..)\n"
		"| (foo args,..,..)    ; define a macro\n"
		"| (foo args,..,..)()  ; define and call a macro\n"
		"| (-foo)              ; remove a macro\n"
		"| .(foo)              ; to call it\n"
		"| ()                  ; break inside macro\n"
		"| (*                  ; list all defined macros\n"
		"|Argument support:\n"
		"| (foo x y\\n$0 @ $1)  ; define fun with args\n"
		"| .(foo 128 0x804800) ; call it with args\n"
		"|Iterations:\n"
		"| .(foo\\n() $@)       ; define iterator returning iter index\n"
		"| x @@ .(foo)         ; iterate over them\n"
		);
		break;
	default: {
		// XXX: stop at first ')'. if next is '(' and last
		//int lastiscp = input[strlen (input)-1] == ')';
		int mustcall =0;
		int i, j = 0;
		buf = strdup (input);

		for (i=0; buf[i]; i++) {
			switch (buf[i]) {
			case '(': j++; break;
			case ')': j--; 
				if (buf[i+1] =='(') {
					buf[i+1] = 0;
					mustcall = i+2;
				} break;
			}
		}
		buf[strlen(buf)-1]=0;
		r_cmd_macro_add (&core->rcmd->macro, buf);
		if (mustcall) {
			char *comma = strchr (buf, ' ');
			if (!comma)
				comma = strchr (buf, ',');
			if (comma) {
				*comma = ' ';
				strcpy (comma+1, buf+mustcall);
				r_cmd_macro_call (&core->rcmd->macro, buf);
			} else eprintf ("Invalid syntax for macro\n");
		}
		free (buf);
		} break;
	}
	return 0;
}
