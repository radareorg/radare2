/* radare - LGPL - Copyright 2009-2020 - pancake */

#include "r_config.h"
#include "r_core.h"
#include "r_util.h"

static const char *help_msg_P[] = {
	"Usage:", "P[?osi] [file]", "Project management",
	"P", "", "list all projects",
	"Pc", " [file]", "show project script to console",
	"Pd", " [file]", "delete project",
	"Pi", " [file]", "show project information",
	"Pn", "[j]", "show project notes (Pnj for json)",
	"Pn", " [base64]", "set notes text",
	"Pn", " -", "edit notes with cfg.editor",
	"Po", " [file]", "open project",
	"Ps", " [file]", "save project",
	"PS", " [file]", "save script file",
	"P-", " [file]", "delete project (alias for Pd)",
	"NOTE:", "", "The 'e prj.name' evar can save/open/rename/list projects.",
	"NOTE:", "", "See the other 'e??prj.' evars for more options.",
	"NOTE:", "", "project are stored in " R_JOIN_2_PATHS ("~", R2_HOME_PROJECTS),
	NULL
};

static const char *help_msg_Pn[] = {
	"Usage:", "Pn[j-?] [...]", "Project Notes",
	"Pn", "", "show project notes",
	"Pn", " -", "edit notes with cfg.editor",
	"Pn-", "", "delete notes",
	"Pn-", "str", "delete lines matching /str/ in notes",
	"Pn+", "str", "append one line to the notes",
	"Pnj", "", "show notes in base64",
	"Pnj", " [base64]", "set notes in base64",
	"Pnx", "", "run project note commands",
	NULL
};

static void cmd_project_init(RCore *core, RCmdDesc *parent) {
	DEFINE_CMD_DESCRIPTOR (core, P);
	DEFINE_CMD_DESCRIPTOR (core, Pn);
}

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
		if (input[1] == ' ') {
			r_core_project_cat (core, input + 2);
		} else {
			eprintf ("Usage: Pc [prjname]\n");
		}
		break;
	case 'o': // "Po"
		if (input[1] == '&') { // "Po&"
			r_core_cmdf (core, "& Po %s", file);
		} else if (input[1]) { // "Po"
			r_core_project_open (core, file);
		} else {
			if (str && *str) {
				r_cons_println (file);
			}
		}
		break;
	case 'd': // "Pd"
	case '-': // "P-"
		r_core_project_delete (core, file);
		break;
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
	case 'S': // "PS"
		if (input[1] == ' ') {
			r_core_project_save_script (core, input + 2, R_CORE_PRJ_ALL);
		} else {
			r_cons_eprintf ("Usage: PS [file]\n");
		}
		break;
	case 'n': // "Pn"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_Pn);
		} else if (!fileproject || !*fileproject) {
			r_cons_eprintf ("No project\n");
		} else {
			switch (input[1]) {
			case '-': // "Pn-"
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
						eprintf ("Deleted %d lines\n", del);
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
						eprintf ("No cfg.editor configured\n");
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
	case 'i': // "Pi"
		if (file && *file) {
			char *prj_name = r_core_project_name (core, file);
			if (!R_STR_ISEMPTY (prj_name)) {
				r_cons_println (prj_name);
				free (prj_name);
			}
		} else if (r_project_is_loaded (core->prj)) {
			r_cons_println (core->prj->name);
			r_cons_println (core->prj->path);
		}
		break;
	case 'l':
	case 0:
	case 'j': // "Pj"
		r_core_project_list (core, input[0]);
		break;
	default:
		r_core_cmd_help (core, help_msg_P);
		break;
	}
	free (str);
	return true;
}
