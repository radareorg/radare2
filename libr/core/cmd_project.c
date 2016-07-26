/* radare - LGPL - Copyright 2009-2015 - pancake */
#include "r_config.h"
#include "r_core.h"
#include "r_print.h"

static int cmd_project(void *data, const char *input) {
	RCore *core = (RCore *)data;
	const char *file, *arg = (input && *input)? input+1: NULL;
	const char *fileproject = r_config_get (core->config, "file.project");
	char *str = NULL;

	if (!input)
		return false;

	str = strdup (fileproject);
	if (arg && *arg==' ') arg++;
	file = (input[0] && input[1])? arg: str;
	switch (input[0]) {
	case 'c':
		if (input[1]==' ') {
			r_core_project_cat (core, input+2);
		} else {
			r_core_cmd_help (core, help_msg_Pc);
		}
		break;
	case 'o':
	//	if (r_file_is_regular (file))
		if (input[1]) {
			r_core_project_open (core, file);
		} else {
			if (file && *file)
				r_cons_println (file);
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
			r_cons_println (file);
		}
		break;
	case 'S':
		if (input[1] == ' ') {
			r_core_project_save_rdb (core, input+2, R_CORE_PRJ_ALL);
		} else {
			r_core_cmd_help (core, help_msg_PS);
		}
		break;
	case 'n':
		if (!fileproject || !*fileproject) {
			eprintf ("No project\n");
		} else
		switch (input[1]) {
		case '-':
			/* remove lines containing specific words */
			{
			FILE *fd = r_sandbox_fopen (str, "w");
			if (!fd) {
				eprintf ("Cannot open %s\n", str);
			} else {
				char *str = r_core_project_notes_file (core, fileproject);
				char *data = r_file_slurp (str, NULL);
				int del = 0;
				if (data) {
					char *ptr, *nl;
					for (ptr = data; ptr; ptr = nl)  {
						nl = strchr (ptr, '\n');
						if (nl) {
							*nl++ = 0;
							if (strstr (ptr, input+2))
								del++;
							else
								fprintf (fd, "%s\n", ptr);
						}
					}
					free (data);
				}
				if (del>0) {
					eprintf ("Deleted %d lines\n", del);
				}
				free (str);
				fclose (fd);
			}
			}
			break;
		case ' ':
			if (input[2]=='-') {
				char *str = r_core_project_notes_file (core, fileproject);
				// edit with cfg.editor
				const char *editor = r_config_get (core->config, "cfg.editor");
				if (str && *str && editor && *editor)
					r_sys_cmdf ("%s %s", editor, str);
				else eprintf ("No cfg.editor configured\n");
				free (str);
			} else {
				//char *str = r_core_project_notes_file (core, fileproject);
				// append line to project notes
				char *str = r_core_project_notes_file (core, fileproject);
				char *data = r_file_slurp (str, NULL);
				FILE *fd = r_sandbox_fopen (str, "a");
				if (fd) {
					fprintf (fd, "%s\n", input+2);
					fclose (fd);
				}
				free (str);
				free (data);
			}
			break;
		case 'j':
			if (!input[2]) {
				int len = 0;
				/* get base64 string */
				char *str = r_core_project_notes_file (core, fileproject);
				if (str) {
					char *data = r_file_slurp (str, &len);
					char *res = r_base64_encode_dyn (data, len);
					if (res) {
						r_cons_println (res);
						free (res);
					}
					free (data);
					free (str);
				}
			} else if (input[2] == ' ') {
				/* set base64 string */
				ut8 *data = r_base64_decode_dyn (input+3, -1);
				if (data) {
					char *str = r_core_project_notes_file (core, fileproject);
					if (str) {
						r_file_dump (str, data, strlen ((const char*)data), 0);
						free (str);
					}
					free (data);
				}
			} else {
				r_core_cmd_help (core, help_msg_Pnj);
			}
			break;
		case 0:
			{
			char *str = r_core_project_notes_file (core, fileproject);
			char *data = r_file_slurp (str, NULL);
			if (data) {
				r_cons_println (data);
				free (data);
			}
			free (str);
			}
			break;
		case '?':
			{
				r_core_cmd_help (core, help_msg_Pn);
			}
			break;
		}
		break;
	case 'i':
//		if (r_file_is_regular (file))
		free (r_core_project_info (core, file));
		break;
	default: {
		r_core_cmd_help (core, help_msg_P);
		}
		break;
	}
	free (str);
	return true;
}
