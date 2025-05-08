/* radare - LGPL - Copyright 2009-2024 - pancake */

#if R_INCLUDE_BEGIN

// R2R db/cmd/write
// R2R db/cmd/cmd_macros

static RCoreHelpMessage help_msg_lparen = {
	"Usage:", "(foo args;cmd1;cmd2;..)", "Command macros",
	"(foo args;..;..)", "", "define a macro",
	"(foo args;..;..)()", "", "define and call a macro",
	"(-foo)", "", "remove a macro",
	".(foo)", "", "to call it",
	"()", "", "break inside macro",
	"(*)", "", "list all defined macros",
	"(j)", "", "list macros in json format",
	"", "Argument support:", "",
	"(foo x y; $0 @ $1)", "", "define fun with args (x - $0; y - $1)",
	".(foo 128 0x804800)", "", "call it with args",
	NULL
};

static int cmd_macro(void *data, const char *_input) {
	char *buf = NULL;
	RCore *core = (RCore*)data;
	char *input = strdup (_input);
	if (r_config_get_b (core->config, "scr.interactive")) {
		if (strlen (_input) > 2 && *_input != '-' && (r_str_endswith (_input, ";") || !r_str_endswith (_input, ")"))) {
			free (input);
			RStrBuf *sb = r_strbuf_new (_input);
			if (!strchr (_input, ';')) {
				r_strbuf_append (sb, ";");
			}
			r_line_set_prompt (core->cons, "> ");
			bool closepar = true;
			while (true) {
				const char *ptr = r_line_readline (core->cons);
				if (R_STR_ISEMPTY (ptr)) {
					break;
				}
				if (!strcmp (ptr, ")")) {
					r_strbuf_append (sb, ptr);
					closepar = false;
				} else {
					r_strbuf_append (sb, ptr);
					r_strbuf_append (sb, ";");
				}
			}
			if (closepar) {
				r_strbuf_append (sb, ")");
			}
			input = r_strbuf_drain (sb);
		}
	}

#if !SHELLFILTER
	r_str_trim_args (input);
#endif
	if (input[0] == 'j' || input[0] == '*') {
		const char ch = input[1];
		if (!ch || ch == ')') {
			r_cmd_macro_list (&core->rcmd->macro, *input);
			free (input);
			return R_CMD_RC_SUCCESS;
		}
	}

	switch (*input) {
	case ')':
		r_cmd_macro_break (&core->rcmd->macro, input + 1);
		break;
	case '-':
		r_cmd_macro_rm (&core->rcmd->macro, input + 1);
		break;
	case '\0':
		r_cmd_macro_list (&core->rcmd->macro, *input);
		break;
	case '(':
	case '?':
		r_core_cmd_help (core, help_msg_lparen);
		break;
	default: {
		int i, mustcall = 0;
		buf = strdup (input);

		for (i = 0; buf[i]; i++) {
			switch (buf[i]) {
			case '(':
				break;
			case ')':
				if (buf[i + 1] == '(') {
					buf[i + 1] = 0;
					mustcall = i + 2;
				}
				break;
			}
		}
		buf[strlen (buf) - 1] = 0;
		char *comma = strchr (buf, ' '); // haveargs
		if (!comma) {
			comma = strchr (buf, ';');
		}
		if (comma) {
			r_cmd_macro_add (&core->rcmd->macro, buf);
		}
		if (mustcall) {
			if (comma) {
				*comma = ' ';
				memmove (comma + 1, buf + mustcall, strlen (buf + mustcall) + 1);
				r_cmd_macro_call (&core->rcmd->macro, buf);
			} else {
				char *s = r_str_newf ("%s)()", buf);
				r_cmd_macro_call (&core->rcmd->macro, s);
				free (s);
			}
		} else {
			r_cmd_macro_add (&core->rcmd->macro, buf);
		}
		free (buf);
		} break;
	}
	r_core_return_value (core, R_CMD_RC_SUCCESS);
	free (input);
	return R_CMD_RC_SUCCESS;
}
#endif
