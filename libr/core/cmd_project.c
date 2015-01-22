/* radare - LGPL - Copyright 2009-2015 - pancake */

static int cmd_project(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *file, *arg = input+1;
	char *str = strdup (r_config_get (core->config, "file.project"));
	if (*arg==' ') arg++;
	file = input[1]?arg:str;
	switch (input[0]) {
	case 'c':
		if (!input[1]) {
			eprintf ("TODO: Show project saving script to console\n");
		} else if (input[1]==' ') {
			r_core_project_cat (core, input+2);
		} else eprintf ("Usage: Pc [prjname]\n");
		break;
	case 'o':
	//	if (r_file_is_regular (file))
		if (input[1]) {
			r_core_project_open (core, file);
		} else {
			if (file && *file)
				r_cons_printf ("%s\n", file);
		}
		break;
	case 'l':
		r_core_project_list (core, input[1]);
		break;
	case 'd':
		r_core_project_delete (core, file);
		break;
	case 's':
		if (r_core_project_save (core, file)) {
			r_config_set (core->config, "file.project", file);
			r_cons_printf ("%s\n", file);
		}
		break;
	case 'i':
//		if (r_file_is_regular (file))
		free (r_core_project_info (core, file));
		break;
	default: {
		const char* help_msg[] = {
		"Usage:", "P[?osi] [file]", "Project management",
		"Po", " [file]", "open project",
		"Ps", " [file]", "save project",
		"Pd", " [file]", "delete project",
		"Pi", " [file]", "show project information",
		"Pc", " [file]", "show project script to console",
		"Pc", "", "show what will be saved in the project script",
		"Pl", "", "list all projects",
		"NOTE:", "", "See 'e file.project'",
		"NOTE:", "", "project files are stored in ~/.config/radare2/projects",
		NULL};
		r_core_cmd_help (core, help_msg);
		}
		break;
	}
	free (str);
	return R_TRUE;
}
