/* radare2 - LGPL - Copyright 2009-2020 - pancake */

#include <stddef.h>
#include <stdbool.h>
#include "r_core.h"

static const char *help_msg_e[] = {
	"Usage:", "e [var[=value]]", "Evaluable vars",
	"e","?asm.bytes", "show description",
	"e", "??", "list config vars with description",
	"e", " a", "get value of var 'a'",
	"e", " a=b", "set var 'a' the 'b' value",
	"e var=?", "", "print all valid values of var",
	"e var=??", "", "print all valid values of var with description",
	"e.", "a=b", "same as 'e a=b' but without using a space",
	"e,", "k=v,k=v,k=v", "comma separated k[=v]",
	"e-", "", "reset config vars",
	"e*", "", "dump config vars in r commands",
	"e!", "a", "invert the boolean value of 'a' var",
	"ec", " [k] [color]", "set color for given key (prompt, offset, ...)",
	"ee", "var", "open editor to change the value of var",
	"ed", "", "open editor to change the ~/.radare2rc",
	"ej", "", "list config vars in JSON",
	"env", " [k[=v]]", "get/set environment variable",
	"er", " [key]", "set config key as readonly. no way back",
	"es", " [space]", "list all eval spaces [or keys]",
	"et", " [key]", "show type of given config variable",
	"ev", " [key]", "list config vars in verbose format",
	"evj", " [key]", "list config vars in verbose format in JSON",
	NULL
};

static const char *help_msg_ec[] = {
	"Usage ec[s?] [key][[=| ]fg] [bg]", "", "",
	"ec", " [key]", "list all/key color keys",
	"ec*", "", "same as above, but using r2 commands",
	"ecd", "", "set default palette",
	"ecr", "", "set random palette (see also scr.randpal)",
	"ecs", "", "show a colorful palette",
	"ecj", "", "show palette in JSON",
	"ecc", " [prefix]", "show palette in CSS",
	"eco", " [theme]", "load theme if provided (list available themes if not)",
	"ecp", "", "load previous color theme",
	"ecn", "", "load next color theme",
	"ecH", " [?]", "highlight word or instruction",
	"ec", " prompt red", "change color of prompt",
	"ec", " prompt red blue", "change color and background of prompt",
	"Vars:", "", "",
	"colors:", "", "rgb:000, red, green, blue, #ff0000, ...",
	"e scr.color", "=0", "use more colors (0: no color 1: ansi 16, 2: 256, 3: 16M)",
	"$DATADIR/radare2/cons", "", R_JOIN_2_PATHS ("~", R2_HOME_THEMES) " ./",
	NULL
};

static const char *help_msg_eco[] = {
	"Usage: eco[jc] [theme]", "", "load theme (cf. Path and dir.prefix)",
	"eco", "", "list available themes",
	"eco.", "", "display current theme name",
	"ecoo", "", "reload current theme",
	"ecoq", "", "list available themes without showing the current one",
	"ecoj", "", "list available themes in JSON",
	"Path:", "", "",
	"$DATADIR/radare2/cons", "", R_JOIN_2_PATHS ("~", R2_HOME_THEMES) " ./",
	NULL
};

static bool getNext = false;

static void cmd_eval_init(RCore *core, RCmdDesc *parent) {
	DEFINE_CMD_DESCRIPTOR (core, e);
	DEFINE_CMD_DESCRIPTOR (core, ec);
}

static bool load_theme(RCore *core, const char *path) {
	if (!r_file_exists (path)) {
		return false;
	}
	core->cmdfilter = "ec ";
	bool res = r_core_cmd_file (core, path);
	if (res) {
		r_cons_pal_update_event ();
	}
	core->cmdfilter = NULL;
	return res;
}

static bool nextpal_item(RCore *core, PJ *pj, int mode, const char *file) {
	const char *fn = r_str_lchr (file, '/');
	if (!fn) fn = file;
	switch (mode) {
	case 'j': // json
		pj_s (pj, fn);
		break;
	case 'l': // list
		r_cons_println (fn);
		break;
	case 'p': // previous
		// TODO: move logic here
		break;
	case 'n': // next
		if (core->theme && !strcmp (core->theme, "default")) {
			core->theme = r_str_dup (core->theme, fn);
			getNext = false;
		}
		if (getNext) {
			core->theme = r_str_dup (core->theme, fn);
			getNext = false;
			return false;
		} else if (core->theme) {
			if (!strcmp (core->theme, fn)) {
				getNext = true;
			}
		} else {
			core->theme = r_str_dup (core->theme, fn);
			return false;
		}
		break;
	}
	return true;
}

static bool cmd_load_theme(RCore *core, const char *_arg) {
	bool failed = false;
	char *path;
	if (!_arg || !*_arg) {
		return false;
	}
	if (!r_str_cmp (_arg, "default", strlen (_arg))) {
		core->theme = r_str_dup (core->theme, _arg);
		r_cons_pal_init (core->cons->context);
		return true;
	}
	char *arg = strdup (_arg);

	char *tmp = r_str_newf (R_JOIN_2_PATHS (R2_HOME_THEMES, "%s"), arg);
	char *home = tmp ? r_str_home (tmp) : NULL;
	free (tmp);

	tmp = r_str_newf (R_JOIN_2_PATHS (R2_THEMES, "%s"), arg);
	path = tmp ? r_str_r2_prefix (tmp) : NULL;
	free (tmp);

	if (!load_theme (core, home)) {
		if (load_theme (core, path)) {
			core->theme = r_str_dup (core->theme, arg);
		} else {
			if (load_theme (core, arg)) {
				core->theme = r_str_dup (core->theme, arg);
			} else {
				char *absfile = r_file_abspath (arg);
				eprintf ("eco: cannot open colorscheme profile (%s)\n", absfile);
				free (absfile);
				failed = true;
			}
		}
	}
	free (home);
	free (path);
	free (arg);
	return !failed;
}

static void list_themes_in_path(RList *list, const char *path) {
	RListIter *iter;
	const char *fn;
	RList *files = r_sys_dir (path);
	r_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			r_list_append (list, strdup (fn));
		}
	}
	r_list_free (files);
}

R_API char *r_core_get_theme (RCore *core) {
	return core->theme;
}

R_API RList *r_core_list_themes(RCore *core) {
	RList *list = r_list_newf (free);
	getNext = false;
	char *tmp = strdup ("default");
	r_list_append (list, tmp);
	char *path = r_str_home (R2_HOME_THEMES R_SYS_DIR);
	if (path) {
		list_themes_in_path (list, path);
		R_FREE (path);
	}

	path = r_str_r2_prefix (R2_THEMES R_SYS_DIR);
	if (path) {
		list_themes_in_path (list, path);
		R_FREE (path);
	}

	return list;
}

static void nextpal(RCore *core, int mode) {
// TODO: use r_core_list_themes() here instead of rewalking all the time
	RList *files = NULL;
	RListIter *iter;
	const char *fn;
	char *path = NULL;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return;
		}
		pj_a (pj);
	}
	char *home = r_str_home (R2_HOME_THEMES R_SYS_DIR);

	getNext = false;
	// spaguetti!
	if (home) {
		files = r_sys_dir (home);
		if (files) {
			r_list_sort (files, (RListComparator)strcmp);
			r_list_foreach (files, iter, fn) {
				if (*fn && *fn != '.') {
					if (mode == 'p') {
						const char *nfn = iter->n? iter->n->data: NULL;
						if (!core->theme) {
							free (home);
							r_list_free (files);
							return;
						}
						eprintf ("%s %s %s\n",
							r_str_get (nfn),
							r_str_get (core->theme),
							r_str_get (fn));
						if (nfn && !strcmp (nfn, core->theme)) {
							r_list_free (files);
							files = NULL;
							free (core->theme);
							core->theme = strdup (fn);
							R_FREE (home);
							goto done;
						}
					} else {
						if (!nextpal_item (core, pj, mode, fn)) {
							r_list_free (files);
							files = NULL;
							R_FREE (home);
							goto done;
						}
					}
				}
			}
		}
		r_list_free (files);
		files = NULL;
		R_FREE (home);
	}

	path = r_str_r2_prefix (R2_THEMES R_SYS_DIR);
	if (path) {
		files = r_sys_dir (path);
		if (files) {
			r_list_sort (files, (RListComparator)strcmp);
			r_list_foreach (files, iter, fn) {
				if (*fn && *fn != '.') {
					if (mode == 'p') {
						const char *nfn = iter->n? iter->n->data: NULL;
						if (!core->theme) {
							free (home);
							r_list_free (files);
							return;
						}
						eprintf ("%s %s %s\n",
							r_str_get (nfn),
							r_str_get (core->theme),
							r_str_get (fn));
						if (nfn && !strcmp (nfn, core->theme)) {
							free (core->theme);
							core->theme = strdup (fn);
							goto done;
						}
					} else { // next
						if (!nextpal_item (core, pj, mode, fn)) {
							goto done;
						}
					}
				}
			}
		}
	}

done:
	free (path);
	if (getNext) {
		R_FREE (core->theme);
		nextpal (core, mode);
		return;
	}
	if (mode == 'l' && !core->theme && !r_list_empty (files)) {
		//nextpal (core, mode);
	} else if (mode == 'n' || mode == 'p') {
		if (core->theme) {
			r_core_cmdf (core, "eco %s", core->theme);
		}
	}
	r_list_free (files);
	files = NULL;
	if (mode == 'j') {
		pj_end (pj);
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
}

R_API void r_core_echo(RCore *core, const char *input) {
	if (!strncmp (input, "64 ", 3)) {
		char *buf = strdup (input);
		r_base64_decode ((ut8*)buf, input + 3, -1);
		if (*buf) {
			r_cons_echo (buf);
		}
		free (buf);
	} else {
		char *p = strchr (input, ' ');
		if (p) {
			r_cons_strcat (p + 1);
			r_cons_newline ();
		}
	}
}

static int cmd_eval(void *data, const char *input) {
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '\0': // "e"
		r_config_list (core->config, NULL, 0);
		break;
	case '?': // "e?"
	default:
		switch (input[1]) {
		case '\0': r_core_cmd_help (core, help_msg_e); break;
		case '?': r_config_list (core->config, input + 2, 2); break;
		default: r_config_list (core->config, input + 1, 2); break;
		}
		break;
	case 't': // "et"
		if (input[1] == 'a') {
			r_cons_printf ("%s\n", (r_num_rand (10) % 2)? "wen": "son");
		} else if (input[1]==' ' && input[2]) {
			RConfigNode *node = r_config_node_get (core->config, input+2);
			if (node) {
				const char *type = r_config_node_type (node);
				if (type && *type) {
					r_cons_println (type);
				}
			}
		} else {
			eprintf ("Usage: et [varname]  ; show type of eval var\n");
		}
		break;
	case 'n': // "en"
		if (!strchr (input, '=')) {
			char *var, *p;
			var = strchr (input, ' ');
			if (var) while (*var==' ') var++;
			p = r_sys_getenv (var);
			if (p) {
				r_cons_println (p);
				free (p);
			} else {
				char **e = r_sys_get_environ ();
				while (e && *e) {
					r_cons_println (*e);
					e++;
				}
			}
		} else if (strlen (input) > 3) {
			char *v, *k = strdup (input + 3);
			if (!k) break;
			v = strchr (k, '=');
			if (v) {
				*v++ = 0;
				r_str_trim (k);
				r_str_trim (v);
				r_sys_setenv (k, v);
			}
			free (k);
		}
		return true;
	case 'x': // "ex"
		// XXX we need headers for the cmd_xxx files.
		return cmd_quit (data, "");
	case 'j': // "ej"
		r_config_list (core->config, NULL, 'j');
		break;
	case 'v': // verbose
		r_config_list (core->config, input + 1, 'v');
		break;
	case 'q': // quiet list of eval keys
		r_config_list (core->config, NULL, 'q');
		break;
	case 'c': // "ec"
		switch (input[1]) {
		case 'd': // "ecd"
			r_cons_pal_init (core->cons->context);
			break;
		case '?':
			r_core_cmd_help (core, help_msg_ec);
			break;
		case 'o': // "eco"
			if (input[2] == 'j') {
				nextpal (core, 'j');
			} else if (input[2] == ' ') {
				cmd_load_theme (core, input + 3);
			} else if (input[2] == 'o') {
				cmd_load_theme (core, core->theme);
			} else if (input[2] == 'c' || input[2] == '.') {
				r_cons_printf ("%s\n", core->theme);
			} else if (input[2] == '?') {
				r_core_cmd_help (core, help_msg_eco);
			} else {
				RList *themes_list = r_core_list_themes (core);
				RListIter *th_iter;
				const char *th;
				r_list_foreach (themes_list, th_iter, th) {
					if (input[2] == 'q') {
						r_cons_printf ("%s\n", th);
					} else if (core->theme && !strcmp (core->theme, th)) {
						r_cons_printf ("- %s\n", th);
					} else {
						r_cons_printf ("  %s\n", th);
					}
				}
				r_list_free (themes_list);
			}
			break;
		case 's': r_cons_pal_show (); break; // "ecs"
		case '*': r_cons_pal_list (1, NULL); break; // "ec*"
		case 'h': // echo
			if (input[2] == 'o') {
				r_core_echo (core, input + 3);
			} else {
				r_cons_pal_list ('h', NULL);
			}
			break;
		case 'j': // "ecj"
			r_cons_pal_list ('j', NULL);
			break;
		case 'c': // "ecc"
			r_cons_pal_list ('c', input + 2);
			break;
		case '\0': // "ec"
			r_cons_pal_list (0, NULL);
			break;
		case 'r': // "ecr"
			r_cons_pal_random ();
			break;
		case 'n': // "ecn"
			nextpal (core, 'n');
			break;
		case 'p': // "ecp"
			nextpal (core, 'p');
			break;
		case 'H': { // "ecH"
			char *color_code = NULL;
			char *word = NULL;
			int argc = 0;
			int delta = (input[2])? 3: 2;
			char** argv = r_str_argv (r_str_trim_head_ro (input + delta), &argc);
			switch (input[2]) {
			case '?': {
				const char *helpmsg[] = {
					"Usage ecH[iw-?]","","",
					"ecHi","[color]","highlight current instruction with 'color' background",
					"ecHw","[word] [color]","highlight 'word ' in current instruction with 'color' background",
					"ecH","","list all the highlight rules",
					"ecH.","","show highlight rule in current offset",
					"ecH-","*","remove all the highlight hints",
					"ecH-","","remove all highlights on current instruction",
					NULL
				};
				r_core_cmd_help (core, helpmsg);
				}
				r_str_argv_free (argv);
				return false;
			case '-': // ecH-
				if (input[3] == '*') {
					r_meta_del (core->anal, R_META_TYPE_HIGHLIGHT, 0, UT64_MAX);
				} else {
					r_meta_del (core->anal, R_META_TYPE_HIGHLIGHT, core->offset, 1);
					// r_meta_set_string (core->anal, R_META_TYPE_HIGHLIGHT, core->offset, "");
				}
				r_str_argv_free (argv);
				return false;
			case '.':
				r_meta_print_list_in_function (core->anal, R_META_TYPE_HIGHLIGHT, 0, core->offset, NULL);
				r_str_argv_free (argv);
				return false;
			case '\0':
				r_meta_print_list_all (core->anal, R_META_TYPE_HIGHLIGHT, 0, NULL);
				r_str_argv_free (argv);
				return false;
			case 'j':
				r_meta_print_list_all (core->anal, R_META_TYPE_HIGHLIGHT, 'j', NULL);
				r_str_argv_free (argv);
				return false;
			case '*':
				r_meta_print_list_all (core->anal, R_META_TYPE_HIGHLIGHT, '*', NULL);
				r_str_argv_free (argv);
				return false;
			case ' ':
			case 'i': // "ecHi"
				if (argc) {
					char *dup = r_str_newf ("bgonly %s", argv[0]);
					color_code = r_cons_pal_parse (dup, NULL);
					R_FREE (dup);
					if (!color_code) {
						eprintf ("Unknown color %s\n", argv[0]);
						r_str_argv_free (argv);
						return true;
					}
				}
				break;
			case 'w': // "ecHw"
				if (!argc) {
					eprintf ("Usage: ecHw word [color]\n");
					r_str_argv_free (argv);
					return true;
				}
				word = strdup (argv[0]);
				if (argc > 1) {
					char *dup = r_str_newf ("bgonly %s", argv[1]);
					color_code = r_cons_pal_parse (dup, NULL);
					R_FREE (dup);
					if (!color_code) {
						eprintf ("Unknown color %s\n", argv[1]);
						r_str_argv_free (argv);
						free (word);
						return true;
					}
				}
				break;
			default:
				eprintf ("See ecH?\n");
				r_str_argv_free (argv);
				return true;
			}
			r_meta_set_string (core->anal, R_META_TYPE_HIGHLIGHT, core->offset, "");
			const char *str = r_meta_get_string (core->anal, R_META_TYPE_HIGHLIGHT, core->offset);
			char *dup = r_str_newf ("%s \"%s%s\"", r_str_get (str), r_str_get (word),
				color_code ? color_code : r_cons_singleton ()->context->pal.wordhl);
			r_meta_set_string (core->anal, R_META_TYPE_HIGHLIGHT, core->offset, dup);
			r_str_argv_free (argv);
			R_FREE (word);
			R_FREE (dup);
			break;
			  }
		default: {
				 char *p = strdup (input + 2);
				 char *q = strchr (p, '=');
				 if (!q) {
					 q = strchr (p, ' ');
				 }
				 if (q) {
					 // Set color
					 *q++ = 0;
					 if (r_cons_pal_set (p, q)) {
						 r_cons_pal_update_event ();
					 }
				 } else {
					 char color[32];
					 RColor rcolor = r_cons_pal_get (p);
					 r_cons_rgb_str (color, sizeof (color), &rcolor);
					 eprintf ("(%s)(%sCOLOR"Color_RESET")\n", p, color);
				 }
				 free (p);
			 }
		}
		break;
	case 'd': // "ed"
		if (input[1] == '?') {
			eprintf ("Usage: ed[-][?] - edit ~/.radare2rc with cfg.editor\n");
			eprintf ("NOTE: ~ is HOME and this can be changed with %%HOME=/tmp\n");
			eprintf ("  ed    : ${cfg.editor} ~/.radare2rc\n");
			eprintf ("  ed-   : rm ~/.radare2rc\n");
		} else if (input[1] == '-') {
			char *file = r_str_home (".radare2rc");
			r_cons_printf ("rm %s\n", file);
			// r_file_rm (file);
			free (file);
		} else {
			char *file = r_str_home (".radare2rc");
			if (r_cons_is_interactive ()) {
				r_file_touch (file);
				char * res = r_cons_editor (file, NULL);
				if (res) {
					if (r_cons_yesno ('y', "Reload? (Y/n)")) {
						r_core_run_script (core, file);
					}
				}
			} else {
				r_core_run_script (core, file);
			}
			free (file);
		}
		break;
	case 'e': // "ee"
		if (input[1] == ' ') {
			char *p;
			const char *input2 = strchr (input + 2, ' ');
			input2 = (input2) ? input2 + 1 : input + 2;
			const char *val = r_config_get (core->config, input2);
			p = r_core_editor (core, NULL, val);
			if (p) {
				r_str_replace_char (p, '\n', ';');
				r_config_set (core->config, input2, p);
			}
		} else {
			eprintf ("Usage: ee varname # use $EDITOR to edit this config value\n");
		}
		break;
	case '!': // "e!"
		input = r_str_trim_head_ro (input + 1);
		if (!r_config_toggle (core->config, input)) {
			eprintf ("r_config: '%s' is not a boolean variable.\n", input);
		}
		break;
	case 's': // "es"
		r_config_list (core->config, (input[1])? input + 1: NULL, 's');
		break;
	case '-': // "e-"
		r_core_config_init (core);
		//eprintf ("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case '*': // "e*"
		r_config_list (core->config, NULL, 1);
		break;
	case 'r': // "er"
		if (input[1]) {
			const char *key = input + ((input[1] == ' ')? 2: 1);
			if (!r_config_readonly (core->config, key)) {
				eprintf ("cannot find key '%s'\n", key);
			}
		} else {
			eprintf ("Usage: er [key]  # make an eval key PERMANENTLY read only\n");
		}
		break;
	case ',': // "e."
		r_config_eval (core->config, input + 1, true);
		break;
	case '.': // "e "
	case ' ': // "e "
		if (r_str_endswith (input, ".")) {
			r_config_list (core->config, input + 1, 0);
		} else {
			// XXX we cant do "e cmd.gprompt=dr=", because the '=' is a token, and quotes dont affect him
			r_config_eval (core->config, input + 1, false);
		}
		break;
	}
	return 0;
}
