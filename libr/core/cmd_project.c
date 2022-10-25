/* radare - LGPL - Copyright 2009-2022 - pancake */

#include <r_core.h>

static RCoreHelpMessage help_msg_P = {
	"Usage:", "P[?.+-*cdilnsS] [file]", "Project management",
	"P", " [file]", "open project (formerly Po)",
	"P.", "", "show current loaded project (see prj.name)",
	"P+", " [name]", "save project (same as Ps, but doesnt checks for changes)",
	"P-", " [name]", "delete project",
	"P*", "", "save project (same as Ps, but doesnt checks for changes)",
	"P!", "([cmd])", "open a shell in the project directory",
	"Pc", " [file]", "show project script to console (R2_580 -> PS*)",
	"Pd", " [N]", "diff Nth commit",
	"Pi", " [file]", "show project information",
	"Pl", "", "list all projects",
	"Pn", " -", "edit current loaded project notes using cfg.editor",
	"Pn", "[j]", "manage notes associated with the project",
	"Ps", " [file]", "save project (see dir.projects)",
	"PS", " [file]", "save script file",
	"PS*", "", "print the project script file (Like PS /dev/stdout)",
	"Px", "-", "close the opened project (R2_580 -> Pc)",
	"NOTE:", "", "the 'e prj.name' evar can save/open/rename/list projects.",
	"NOTE:", "", "see the other 'e??prj.' evars for more options.",
	"NOTE:", "", "project are stored in dir.projects",
	NULL
};

static RCoreHelpMessage help_msg_Pn = {
	"Usage:", "Pn[j-?] [...]", "Project Notes",
	"Pn", "", "show project notes",
	"Pn", " -", "edit notes with cfg.editor",
	"Pn", " [base64]", "set notes text",
	"Pn-", "", "delete notes",
	"Pn-", "str", "delete lines matching /str/ in notes",
	"Pn+", "str", "append one line to the notes",
	"Pnj", "", "show notes in base64",
	"Pnj", " [base64]", "set notes in base64",
	"Pnx", "", "run project note commands",
	NULL
};

static int cmd_project(void *data, const char *input) {
	RCore *core = (RCore *) data;
	const char *file;
	const char *fileproject = r_config_get (core->config, "prj.name");

	if (!input) {
		return false;
	}
	char *str = strdup (fileproject);
	const char *arg = strchr (input, ' ');
	if (arg) {
		arg++;
	} else {
		if (*input) {
			arg = input + 1;
			if (*arg == '&') {
				arg++;
			}
		}
	}
	file = arg;
	switch (input[0]) {
	case 'c': // "Pc"
		// R2_580 - old Px code moves here..
		if (input[1] == '?') {
			eprintf ("Usage: Pc [prjname]\n");
		} else if (input[1] == '\0' && fileproject) {
			r_core_project_cat (core, fileproject);
		} else if (input[1] == ' ') {
			r_core_project_cat (core, input + 2);
		} else {
			eprintf ("Usage: Pc [prjname]\n");
		}
		break;
	case 'o': // "Po" DEPRECATED
		R_LOG_WARN ("Po is deprecated, use 'P [prjname]' instead");
		// fallthru
	case ' ': // "P [prj]"
		if (input[1] == '&') { // "Po&"
			r_core_cmdf (core, "& Po %s", file);
		} else if (input[1]) { // "Po"
			r_core_project_open (core, file);
		} else {
			if (R_STR_ISNOTEMPTY (str)) {
				r_cons_println (str);
			}
		}
		break;
	case 'd': // "Pd"
		{
			char *pdir = r_file_new (
				r_config_get (core->config, "dir.projects"),
				r_config_get (core->config, "prj.name"), NULL);
			if (r_syscmd_pushd (pdir)) {
				if (r_file_is_directory (".git")) {
					// TODO: Use ravc2 api
					r_sys_cmdf ("git diff @~%d", atoi (input + 1));
				} else {
					R_LOG_TODO ("Not a git project. Diffing projects is WIP for now");
				}
				r_syscmd_popd ();
			}
			free (pdir);
		}
		break;
	case '-': // "P-"
		if (!strcmp (input + 1, "-")) {
			//r_project_close (core->prj);
			r_config_set (core->config, "prj.name", "");
		} else if (input[1]) {
			if (R_STR_ISNOTEMPTY (file)) {
				r_core_project_delete (core, file);
			} else {
			//	r_project_close (core->prj);
				r_config_set (core->config, "prj.name", "");
			}
		} else {
			// r_project_close (core->prj);
			r_config_set (core->config, "prj.name", "");
		}
		break;
	case '+': // "P+"
		// xxx
	case 's': // "Ps"
		if (R_STR_ISEMPTY (file)) {
			file = str;
		}
		if (!R_STR_ISEMPTY (file)) {
			if (!r_core_project_save (core, file)) {
				r_cons_eprintf ("Cannot save project.\n");
			}
		} else {
			r_cons_eprintf ("Use: Ps [projectname]\n");
		}
		break;
	case '!': // "P!"
		if (input [1] == '?') {
			eprintf ("Usage: P!([cmd]) - run shell or command in project directory\n");
		} else if (r_config_get_b (core->config, "scr.interactive")) {
			char *pdir = r_file_new (
				r_config_get (core->config, "dir.projects"),
				r_config_get (core->config, "prj.name"), NULL);
			r_syscmd_pushd (pdir);
			free (pdir);
			if (R_STR_ISNOTEMPTY (r_str_trim_head_ro (input + 1))) {
				r_sys_cmdf ("%s", input + 1);
			} else {
#if __WINDOWS__
				r_sys_cmdf ("cmd");
#else
				r_sys_cmdf ("sh");
#endif
			}
			r_syscmd_popd ();
		} else {
			R_LOG_ERROR ("P! requires scr.interactive to open a shell");
		}
		break;
	case '*': // "P*"
		r_core_project_save_script (core, "/dev/stdout", R_CORE_PRJ_ALL);
		break;
	case 'S': // "PS"
		if (input[1] == ' ') {
			r_core_project_save_script (core, r_str_trim_head_ro (input + 2), R_CORE_PRJ_ALL);
		} else if (input[1] == '*') {
			r_core_project_save_script (core, "/dev/stdout", R_CORE_PRJ_ALL);
		} else {
			r_cons_eprintf ("Usage: PS[*] [projectname]\n");
		}
		break;
	case 'n': // "Pn"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_Pn);
		} else if (R_STR_ISEMPTY (fileproject)) {
			R_LOG_ERROR ("No project");
		} else {
			switch (input[1]) {
			case '-': // "Pn-"
				/* remove lines containing specific words */
			{
				FILE *fd = r_sandbox_fopen (str, "w");
				if (!fd) {
					R_LOG_ERROR ("Cannot open %s", str);
				} else {
					char *str = r_core_project_notes_file (core, fileproject);
					char *data = r_file_slurp (str, NULL);
					int del = 0;
					if (data) {
						char *ptr, *nl;
						for (ptr = data; ptr; ptr = nl) {
							nl = strchr (ptr, '\n');
							if (nl) {
								*nl++ = 0;
								if (strstr (ptr, input + 2)) {
									del++;
								} else {
									fprintf (fd, "%s\n", ptr);
								}
							}
						}
						free (data);
					}
					if (del > 0) {
						R_LOG_ERROR ("Deleted %d lines", del);
					}
					free (str);
					fclose (fd);
				}
			}
			break;
			case ' ': // "Pn "
				if (input[2] == '-') {
					char *str = r_core_project_notes_file (core, fileproject);
					// edit with cfg.editor
					const char *editor = r_config_get (core->config, "cfg.editor");
					if (str && *str && editor && *editor) {
						r_sys_cmdf ("%s %s", editor, str);
					} else {
						R_LOG_ERROR ("No cfg.editor configured");
					}
					free (str);
				} else {
					// char *str = r_core_project_notes_file (core, fileproject);
					// append line to project notes
					char *str = r_core_project_notes_file (core, fileproject);
					char *data = r_file_slurp (str, NULL);
					FILE *fd = r_sandbox_fopen (str, "a");
					if (fd) {
						fprintf (fd, "%s\n", input + 2);
						fclose (fd);
					}
					free (str);
					free (data);
				}
				break;
			case '+': // "Pn+"
				{
					char *str = r_core_project_notes_file (core, fileproject);
					char *data = r_file_slurp (str, NULL);
					data = r_str_append (data, input + 2);
					data = r_str_append (data, "\n");
					r_file_dump (str, (const ut8*)data, strlen (data), false);
					free (data);
					free (str);
				}
				break;
			case 'j': // "Pnj"
				if (!input[2]) {
					size_t len = 0;
					/* get base64 string */
					char *str = r_core_project_notes_file (core, fileproject);
					if (str) {
						char *data = r_file_slurp (str, &len);
						char *res = r_base64_encode_dyn (data, (int)len);
						if (res) {
							r_cons_println (res);
							free (res);
						}
						free (data);
						free (str);
					}
				} else if (input[2] == ' ') {
					/* set base64 string */
					ut8 *data = r_base64_decode_dyn (input + 3, -1);
					if (data) {
						char *str = r_core_project_notes_file (core, fileproject);
						if (str) {
							r_file_dump (str, data, strlen ((const char *) data), 0);
							free (str);
						}
						free (data);
					}
				} else {
					eprintf ("Usage: `Pnj` or `Pnj ...`\n");
				}
				break;
			case 'x': // "Pnx"
				r_core_project_execute_cmds (core, fileproject);
				break;
			case 0: // "Pn"
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
			}
		}
		break;
	case 'i': // "Pi" DEPRECATE
		if (file && *file) {
			char *prj_name = r_core_project_name (core, file);
			if (!R_STR_ISEMPTY (prj_name)) {
				r_cons_println (prj_name);
				free (prj_name);
			}
		} else if (r_project_is_loaded (core->prj)) {
			if (R_STR_ISNOTEMPTY (core->prj->name)) {
				r_cons_println (core->prj->name);
			}
			if (R_STR_ISNOTEMPTY (core->prj->path)) {
				r_cons_println (core->prj->path);
			}
		}
		break;
	case '.': // "P."
		r_cons_printf ("%s\n", fileproject);
		break;
	case 'x':
		r_project_close (core->prj);
		r_config_set (core->config, "prj.name", "");
		break;
	case 0: // "P"
	case 'P':
	case 'l':
	case 'j': // "Pj"
		r_core_project_list (core, input[0]);
		break;
	default:
		r_core_cmd_help (core, help_msg_P);
		break;
	}
	free (str);
	return 0;
}
