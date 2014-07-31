/* radare - LGPL - Copyright 2009-2014 - pancake */

static int cmd_log(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *input2 = input + 1;
	char *arg = strchr (input2, ' ');
	int n = atoi (input2);
	int n2 = arg? atoi (arg+1): 0;

	switch (*input) {
	case 'e': // shell: less
		{
		char *p = strchr (input, ' ');
		if (p) {
			char *b = r_file_slurp (p+1, NULL);
			if (b) {
				r_cons_less_str (b);
				free (b);
			} else eprintf ("File not found\n");
		} else eprintf ("Usage: less [filename]\n");
		}
		break;
	case 'l':
		r_cons_printf ("%d\n", core->log->last-1);
		break;
	case '-':
		r_core_log_del (core, n);
		break;
	case '?':{
			const char* help_msg[] = {
			"Usage:", "l","[-][ num|msg]",
			"l", "", "List all log messages",
			"l", " new comment", "0x80480",
			"l", " 123", "List log from 123",
			"l", " 10 3", "List 3 log messages starting from 10",
			"l*", "", "List in radare commands",
			"l-", "", "Delete all logs",
			"l-", " 123", "Delete logs before 123",
			"ll", "", "Get last log message id",
			"lj", "", "List in json format",
			"lm", " [idx]", "Display log messages without index",
			"ls", "", "List files in current directory (see pwd, cd)",
			"lp", "[-plug]", "list, load, unload plugins",
			NULL};
		r_core_cmd_help(core, help_msg);
		}
		break;
	case 'p':
		switch (input[1]) {
		case 0:
			r_lib_list (core->lib);
			break;
		case '-':
			r_lib_close (core->lib, input+2);
			break;
		case ' ':
			r_lib_open (core->lib, input+2);
			break;
		case '?': {
			const char* help_msg[] = {
			"Usage:", "lp", "[-name][ file]",
			"lp", "", "List all plugins loaded by RCore.lib",
			"lp-", "duk", "Unload plugin matching in filename",
			"lp", " blah."R_LIB_EXT, "Load plugin file",
			NULL};
			r_core_cmd_help(core, help_msg);
			}
			break;
		}
		break;
	case ' ':
		if (n>0) {
			r_core_log_list (core, n, n2, *input);
		} else {
			r_core_log_add (core, input+1);
		}
		break;
	case 'm':
		if (n>0) {
			r_core_log_list (core, n, 1, 't');
		} else {
			r_core_log_list (core, n, 0, 't');
		}
		break;
	case 's':
		r_core_syscmd_ls (input);
		break;
	case 'j':
	case '*':
	case '\0':
		r_core_log_list (core, n, n2, *input);
		break;
	}
	return 0;
}
