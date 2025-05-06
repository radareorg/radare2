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
	if (s) {
		r_cons_printf ("%s\n", s);
		free (s);
	}
}

/* Print a coloured help message */
R_API void r_cons_cmd_help(RCoreHelpMessage help, bool use_color) {
	RCons *cons = r_cons_singleton ();
	r_kons_cmd_help (cons, help, use_color);
}

/* See r_cons_cmd_help().
 * This version will only print help for a specific command.
 * Will append spec to cmd before looking for a match, if spec != 0.
 *
 * If exact is false, will match any command that contains the search text.
 * For example, ("pd", 'r', false) matches both `pdr` and `pdr.`.
 */
R_API void r_cons_cmd_help_match(RCoreHelpMessage help, bool use_color, R_BORROW char * R_NONNULL cmd, char spec, bool exact) {
	RVector/*<int>*/ *match_indices = r_vector_new (sizeof (int), NULL, NULL);
	char **matches = NULL;
	size_t num_matches;
	int *current_index_ptr;
	size_t matches_copied;
	size_t i;

	if (spec) {
		/* We now own cmd */
		cmd = r_str_newf ("%s%c", cmd, spec);
	}

	/* Collect matching indices */
	for (i = 0; help[i]; i += 3) {
		if (exact? (bool)!strcmp (help[i], cmd): (bool)strstr (help[i], cmd)) {
			r_vector_push (match_indices, &i);
		}
	}

	/* Leave if no matches */
	num_matches = r_vector_length (match_indices);
	if (num_matches == 0) {
		goto out;
	}

	matches = R_NEWS (char *, (3 * num_matches) + 1);

	matches_copied = 0;
	r_vector_foreach (match_indices, current_index_ptr) {
		int current_index = *current_index_ptr;
		for (i = 0; i < 3; i++) {
			matches[matches_copied++] = (char *)help[current_index++];
		}
	}
	matches[matches_copied] = NULL;
	r_cons_cmd_help ((const char * const *)matches, use_color);

out:
	free (matches);
	r_vector_free (match_indices);
	if (spec) {
		free (cmd);
	}
}
