/* radare - LGPL - Copyright 2009-2014 - pancake */

static int cmd_quit(void *data, const char *input) {
	RCore *core = (RCore *)data;
	if (input)
	switch (*input) {
	case '?':
		r_cons_printf (
		"|Usage: q[!] [retvalue]\n"
		"| q      quit program\n"
		"| q!     force quit (no questions)\n"
		"| q 1    quit with return value 1\n"
		"| q a-b  quit with return value a-b\n");
		break;
	case ' ':
	case '!':
		input++;
	case '\0':
		// TODO
	default:
		r_line_hist_save (R2_HOMEDIR"/history");
		if (*input)
			r_num_math (core->num, input);
		else core->num->value = 0LL;
		//exit (*input?r_num_math (core->num, input+1):0);
		//if (core->http_up) return R_FALSE; // cancel quit when http is running
		return -2;
	}
	return R_FALSE;
}
