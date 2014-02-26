/* radare - LGPL - Copyright 2009-2013 - pancake */

static int cmd_project(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *file, *arg = input+1;
	char *str = strdup (r_config_get (core->config, "file.project"));
	if (*arg==' ') arg++;
	file = input[1]?arg:str;
	switch (input[0]) {
	case 'o':
	//	if (r_file_is_regular (file))
		r_core_project_open (core, file);
		break;
	case 's':
		r_core_project_save (core, file);
		r_config_set (core->config, "file.project", file);
		break;
	case 'i':
//		if (r_file_is_regular (file))
		free (r_core_project_info (core, file));
		break;
	default:
		r_cons_printf (
		"|Usage: P[?osi] [file]\n"
		"| Po [file]  open project\n"
		"| Ps [file]  save project\n"
		"| Pi [file]  show project information\n"
		"|NOTE: See 'e file.project'\n"
		"|NOTE: project files are stored in ~/.config/radare2/projects\n");
		break;
	}
	free (str);
	return R_TRUE;
}
