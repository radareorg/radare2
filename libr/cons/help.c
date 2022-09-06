/* radare2 - LGPL - Copyright 2008-2022 - pancake */

#include <r_cons.h>

R_API void r_cons_cmd_help_json(const char *help[]) {
	int i, max_length = 0;
	const char *usage_str = "Usage:";
	const char *help_cmd = NULL, *help_args = NULL, *help_desc = NULL;

	// calculate padding for description text in advance
	for (i = 0; help[i]; i += 3) {
		help_cmd  = help[i + 0];
		help_args = help[i + 1];

		int len_cmd = strlen (help_cmd);
		int len_args = strlen (help_args);
		if (i) {
			max_length = R_MAX (max_length, len_cmd + len_args);
		}
	}

	PJ *pj = pj_new ();
	pj_o (pj);
	for (i = 0; help[i]; i += 3) {
		help_cmd  = help[i + 0];
		help_args = help[i + 1];
		help_desc = help[i + 2];


		if (r_str_startswith (help_cmd, usage_str)) {
			pj_ks (pj, "root", help_cmd);
			pj_ks (pj, "args", help_args);
			pj_ks (pj, "usage", usage_str);
			pj_ka (pj, "commands");
		} else if (!help_args[0] && !help_desc[0]) {
			/* Section header, no need to indent it */
		//	r_cons_printf ("%s%s%s\n", pal_help_color, help_cmd, pal_reset);
		} else {
			/* Body of help text, indented */
			pj_o (pj);
			pj_ks (pj, "cmd", help_cmd);
			pj_ks (pj, "args", help_args);
			pj_ks (pj, "desc", help_desc);
			pj_end (pj);
		}
	}
	pj_end (pj);
	pj_end (pj);
	char *s = pj_drain (pj);
	r_cons_printf ("%s\n", s);
	free (s);
}

/* Print a coloured help message */
R_API void r_cons_cmd_help(const char *help[], bool use_color) {
	RCons *cons = r_cons_singleton ();
	const char *pal_input_color = use_color ? cons->context->pal.input : "";
	const char *pal_args_color = use_color ? cons->context->pal.args : "";
	const char *pal_help_color = use_color ? cons->context->pal.help : "";
	const char *pal_reset = use_color ? cons->context->pal.reset : "";
	int i, max_length = 0, padding = 0;
	const char *usage_str = "Usage:";
	const char *help_cmd = NULL, *help_args = NULL, *help_desc = NULL;

	// calculate padding for description text in advance
	for (i = 0; help[i]; i += 3) {
		help_cmd  = help[i + 0];
		help_args = help[i + 1];

		int len_cmd = strlen (help_cmd);
		int len_args = strlen (help_args);
		if (i) {
			max_length = R_MAX (max_length, len_cmd + len_args);
		}
	}

	for (i = 0; help[i]; i += 3) {
		help_cmd  = help[i + 0];
		help_args = help[i + 1];
		help_desc = help[i + 2];

		if (r_str_startswith (help_cmd, usage_str)) {
			/* Usage header */
			const char *afterusage = help_cmd + strlen (usage_str);
			r_cons_printf ("Usage:%s%s", pal_args_color, afterusage);
			if (help_args[0]) {
				r_cons_printf (" %s", help_args);
			}
			if (help_desc[0]) {
				r_cons_printf ("  %s", help_desc);
			}
			r_cons_printf ("%s\n", pal_reset);
		} else if (!help_args[0] && !help_desc[0]) {
			/* Section header, no need to indent it */
			r_cons_printf ("%s%s%s\n", pal_help_color, help_cmd, pal_reset);
		} else {
			/* Body of help text, indented */
			int str_length = strlen (help_cmd) + strlen (help_args);
			padding = R_MAX ((max_length - str_length), 0);
			r_cons_printf ("| %s%s%s%s%*s  %s%s%s\n",
				pal_input_color, help_cmd,
				pal_args_color, help_args,
				padding, "",
				pal_help_color, help_desc, pal_reset);
		}
	}
}

static void print_match(const char **match, bool use_color) {
	const char *match_help_text[4];
	size_t i;

	/* Manually construct help array. No need to strdup, just borrow. */
	match_help_text[3] = NULL;
	for (i = 0; i < 3; i++) {
		match_help_text[i] = match[i];
	}
	r_cons_cmd_help (match_help_text, use_color);
}

/* See r_cons_cmd_help().
 * This version will only print help for a specific command.
 * Will append spec to cmd before looking for a match, if spec != 0.
 *
 * If exact is false, will match any command that contains the search text.
 * For example, ("pd", 'r', false) matches both `pdr` and `pdr.`.
 */
R_API void r_cons_cmd_help_match(const char *help[], bool use_color, R_BORROW R_NONNULL char *cmd, char spec, bool exact) {
	size_t i;

	if (spec) {
		/* We now own cmd */
		cmd = r_str_newf ("%s%c", cmd, spec);
	}

	for (i = 0; help[i]; i += 3) {
		if (exact) {
			if (!strcmp (help[i], cmd)) {
				print_match (&help[i], use_color);
				break;
			}
		} else {
			if (strstr (help[i], cmd)) {
				print_match (&help[i], use_color);
				/* Don't break - can have multiple results */
			}
		}
	}

	if (spec) {
		free (cmd);
	}
}
