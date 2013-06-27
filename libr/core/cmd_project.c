/* radare - LGPL - Copyright 2009-2012 // pancake<nopcode.org> */
static int cmd_project(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *arg = input+1;
	char *str = strdup (r_config_get (core->config, "file.project"));
	if (*arg==' ') arg++;
	switch (input[0]) {
	case 'o': r_core_project_open (core, input[1]?arg:str); break;
	case 's': r_core_project_save (core, input[1]?arg:str); break;
	case 'i': free (r_core_project_info (core, input[1]?arg:str)); break;
	default:
		r_cons_printf (
		"Usage: P[?osi] [file]\n"
		" Po [file]  open project\n"
		" Ps [file]  save project\n"
		" Pi [file]  info\n"
		"NOTE: project files are stored in ~/.config/radare2/rdb\n");
		break;
	}
	free (str);
	return R_TRUE;
}
