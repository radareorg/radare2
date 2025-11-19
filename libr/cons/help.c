/* radare2 - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>

// TODO: deprecate
R_API void r_cons_cmd_help_json(RCons *cons, RCoreHelpMessage help) {
	int i, max_length = 0;
	const char usage_str[] = "Usage:";
	const char *help_cmd = NULL;
	const char *help_args = NULL;
	const char *help_desc = NULL;

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
		//	r_cons_printf (cons, "%s%s%s\n", pal_help_color, help_cmd, pal_reset);
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
	if (s) {
		r_cons_printf (cons, "%s\n", s);
		free (s);
	}
}

/* Print a coloured help message */
R_API void r_cons_cmd_help(RCons *cons, RCoreHelpMessage help, bool use_color) {
	const char *pal_input_color = use_color ? cons->context->pal.input : "";
	const char *pal_args_color = use_color ? cons->context->pal.args : "";
	const char *pal_help_color = use_color ? cons->context->pal.help : "";
	const char *pal_reset = use_color ? cons->context->pal.reset : "";
	int i, max_length = 0, padding = 0;
	const char *usage_str = "Usage:";
	const char *help_cmd = NULL, *help_args = NULL, *help_desc = NULL;
	if (!pal_input_color) {
		pal_input_color = "";
	}
	if (!pal_args_color) {
		pal_args_color = "";
	}
	if (!pal_help_color) {
		pal_help_color = "";
	}
	if (!pal_reset) {
		pal_reset = Color_RESET;
	}

	// calculate padding for description text in advance
	for (i = 0; help[i]; i += 3) {
		help_cmd = help[i + 0];
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
			r_cons_printf (cons, "Usage:%s%s", pal_args_color, afterusage);
			if (help_args[0]) {
				r_cons_printf (cons, " %s", help_args);
			}
			if (help_desc[0]) {
				r_cons_printf (cons, "  %s", help_desc);
			}
			r_cons_printf (cons, "%s\n", pal_reset);
		} else if (!help_args[0] && !help_desc[0]) {
			/* Section header, no need to indent it */
			r_cons_printf (cons, "%s%s%s\n", pal_help_color, help_cmd, pal_reset);
		} else {
			/* Body of help text, indented */
			int str_length = strlen (help_cmd) + strlen (help_args);
			padding = R_MAX ((max_length - str_length), 0);
			r_cons_printf (cons, "| %s%s%s%s%*s  %s%s%s\n",
				pal_input_color, help_cmd,
				pal_args_color, help_args,
				padding, "",
				pal_help_color, help_desc, pal_reset);
		}
	}
}

/* See r_cons_cmd_help().
 * This version will only print help for a specific command.
 * Will append spec to cmd before looking for a match, if spec != 0.
 *
 * If exact is false, will match any command that contains the search text.
 * For example, ("pd", 'r', false) matches both `pdr` and `pdr.`.
 */
R_API int r_cons_cmd_help_match(RCons *cons, RCoreHelpMessage help, bool use_color, const char * R_NONNULL cmd, char spec, bool exact) {
	RVector/*<int>*/ *match_indices = r_vector_new (sizeof (int), NULL, NULL);
	int *current_index_ptr;
	size_t matches_copied;
	size_t i;
	char *search_cmd = spec? r_str_newf ("%s%c", cmd, spec): strdup (cmd);

	/* Collect matching indices */
	for (i = 0; help[i]; i += 3) {
		if (exact? (bool)!strcmp (help[i], search_cmd): (bool)strstr (help[i], search_cmd)) {
			r_vector_push (match_indices, &i);
		}
	}

	/* Leave if no matches */
	size_t num_matches = r_vector_length (match_indices);
	char **matches = NULL;
	if (num_matches > 0) {
		matches = R_NEWS (char *, (3 * num_matches) + 1);
		matches_copied = 0;
		r_vector_foreach (match_indices, current_index_ptr) {
			int current_index = *current_index_ptr;
			for (i = 0; i < 3; i++) {
				matches[matches_copied++] = (char *)help[current_index++];
			}
		}
		matches[matches_copied] = NULL;
		r_cons_cmd_help (cons, (const char * const *)matches, use_color);
	}
	free (matches);
	r_vector_free (match_indices);
	free (search_cmd);
	return num_matches;
}
