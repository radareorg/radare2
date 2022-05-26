/* radare - LGPL - Copyright 2009-2022 - pancake */

#include "r_cmd.h"
#include "r_core.h"

static const char *help_msg_lparen[] = {
	"Usage:", "(foo args;cmd1;cmd2;..)", "Aliases",
	"(foo args;..;..)", "", "define a macro",
	"(foo args;..;..)()", "", "define and call a macro",
	"(-foo)", "", "remove a macro",
	".(foo)", "", "to call it",
	"()", "", "break inside macro",
	"(*", "", "list all defined macros",
	"", "Argument support:", "",
	"(foo x y; $0 @ $1)", "", "define fun with args (x - $0; y - $1)",
	".(foo 128 0x804800)", "", "call it with args",
	NULL
};

static int cmd_macro(void *data, const char *_input) {
	char *buf = NULL;
	RCore *core = (RCore*)data;
	char *input = strdup (_input);
#if !SHELLFILTER
	r_str_trim_args (input);
#endif

	switch (*input) {
	case ')':
		r_cmd_macro_break (&core->rcmd->macro, input + 1);
		break;
	case '-':
		r_cmd_macro_rm (&core->rcmd->macro, input + 1);
		break;
	case '*':
	case 'j':
	case '\0':
		r_cmd_macro_list (&core->rcmd->macro, *input);
		break;
	case '(':
	case '?':
		r_core_cmd_help (core, help_msg_lparen);
		break;
	default: {
		// XXX: stop at first ')'. if next is '(' and last
		//int lastiscp = input[strlen (input)-1] == ')';
		int mustcall = 0;
		int i, j = 0;
		buf = strdup (input);

		for (i = 0; buf[i]; i++) {
			switch (buf[i]) {
			case '(':
				j++;
				break;
			case ')':
				j--;
				if (buf[i + 1] == '(') {
					buf[i + 1] = 0;
					mustcall = i + 2;
				}
				break;
			}
		}
		buf[strlen (buf) - 1] = 0;
		r_cmd_macro_add (&core->rcmd->macro, buf);
		if (mustcall) {
			char *comma = strchr (buf, ' ');
			if (!comma) {
				comma = strchr (buf, ';');
			}
			if (comma) {
				*comma = ' ';
				memmove (comma + 1, buf + mustcall, strlen (buf + mustcall) + 1);
				r_cmd_macro_call (&core->rcmd->macro, buf);
			} else {
				eprintf ("Invalid syntax for macro\n");
				r_core_return_value (core, R_CMD_RC_FAILURE);
			}
		}
		free (buf);
		} break;
	}
	r_core_return_value (core, R_CMD_RC_SUCCESS);
	free (input);
	return R_CMD_RC_SUCCESS;
}
