/* radare - LGPLv3 - Copyright 2014 Jody Frankowski */
/* This file holds help messages relative functions */

#include <r_core.h>

/* Prints a coloured help message.
 * help should be an array of the following form:
 * {"command", "args", "description",
 * "command2", "args2", "description"}; */
R_API void r_core_cmd_help(RCore *core, const char * help[]) {
	char padding[256];
	int i, max_length, padding_length, use_colors;
	char const * args_color_start;
	char const * help_color_start;
	char const * reset_colors;
	RCons *cons;

	cons = r_cons_singleton();

	use_colors = core->print->flags & R_PRINT_FLAGS_COLOR;

	args_color_start = use_colors? cons->pal.pop: "";
	help_color_start = use_colors? cons->pal.comment: "";
	reset_colors     = use_colors? cons->pal.reset: "";

	max_length = 0;
	for (i = 0; help[i]; i += 3) {
		int len0 = strlen (help[i]);
		int len1 = strlen (help[i+1]);
		max_length = R_MAX (len0+len1, max_length);
	}

	for (i = 0; help[i]; i += 3) {
		padding_length = max_length - \
			(strlen(help[i]) + strlen(help[i+1]));
		memset(padding, ' ', padding_length);
		padding[padding_length] = '\0';

		if (i) {
		r_cons_printf("|%s%s%s%s%s%s  %s%s%s\n", i?" ":"",help[i],
			args_color_start, help[i+1], reset_colors, padding,
			help_color_start, help[i+2], reset_colors);
		} else {
			// no need to indent the first line
			r_cons_printf ("|%s%s %s%s%s\n",
				help_color_start,
				help[i],help[i+1],help[i+2],
				reset_colors);
		}
	}
}
