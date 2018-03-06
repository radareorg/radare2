/* radare2 - LGPL - Copyright 2009-2017 - pancake */

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
	"ec", "", "list all color keys",
	"ec*", "", "same as above, but using r2 commands",
	"ecd", "", "set default palette",
	"ecr", "", "set random palette (see also scr.randpal)",
	"ecs", "", "show a colorful palette",
	"ecj", "", "show palette in JSON",
	"ecc", " [prefix]", "show palette in CSS",
	"eco", " dark|white", "load white color scheme template",
	"ecp", "", "load previous color theme",
	"ecn", "", "load next color theme",
	"ecH", "[?]", "highlight word or instruction",
	"ec", " prompt red", "change color of prompt",
	"ec", " prompt red blue", "change color and background of prompt",
	"", " ", "",
	"colors:", "", "rgb:000, red, green, blue, #ff0000, ...",
	"e scr.color", "=0", "use more colors (0: no color 1: ansi 16, 2: 256, 3: 16M)",
	"$DATADIR/radare2/cons", "", "~/.config/radare2/cons ./",
	NULL
};

static char *curtheme = NULL;
static bool getNext = false;

static void cmd_eval_init(RCore *core) {
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

static bool nextpal_item(RCore *core, int mode, const char *file, int ctr) {
	const char *fn = r_str_lchr (file, '/');
	if (!fn) fn = file;
	switch (mode) {
	case 'j': // json
		r_cons_printf ("%s\"%s\"", ctr?",":"", fn);
		break;
	case 'l': // list
		r_cons_println (fn);
		break;
	case 'p': // previous
		// TODO: move logic here
		break;
	case 'n': // next
		if (getNext) {
			curtheme = r_str_dup (curtheme, fn);
			getNext = false;
			return false;
		} else if (curtheme) {
			if (!strcmp (curtheme, fn)) {
				getNext = true;
			}
		} else {
			curtheme = r_str_dup (curtheme, fn);
			return false;
		}
		break;
	}
	return true;
}

R_API RList *r_core_list_themes(RCore *core) {
	RList *files = NULL;
	RListIter *iter;
	const char *fn;
	char *home = r_str_home (".config/radare2/cons/");

	RList *list = r_list_new ();
	getNext = false;
	if (home) {
		files = r_sys_dir (home);
		r_list_foreach (files, iter, fn) {
			if (*fn && *fn != '.') {
				r_list_append (list, strdup (fn));
			}
		}
		r_list_free (files);
		R_FREE (home);
	}
	files = r_sys_dir (R2_DATDIR"/radare2/"R2_VERSION"/cons/");
	r_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			r_list_append (list, strdup (fn));
		}
	}
	r_list_free (files);
	files = NULL;
	return list;
}

static void nextpal(RCore *core, int mode) {
// TODO: use r_core_list_themes() here instead of rewalking all the time
	RList *files = NULL;
	RListIter *iter;
	const char *fn;
	int ctr = 0;
	char *home = r_str_home (".config/radare2/cons/");

	getNext = false;
	if (mode == 'j') {
		r_cons_printf ("[");
	}
	if (home) {
		files = r_sys_dir (home);
		r_list_foreach (files, iter, fn) {
			if (*fn && *fn != '.') {
				if (mode == 'p') {
					const char *nfn = iter->n? iter->n->data: NULL;
					if (!curtheme) {
						free (home);
						r_list_free (files);
						return;
					}
					eprintf ("%s %s %s\n", nfn, curtheme, fn);
					if (nfn && !strcmp (nfn, curtheme)) {
						r_list_free (files);
						files = NULL;
						free (curtheme);
						curtheme = strdup (fn);
						R_FREE (home);
						goto done;
					}
				} else {
					if (!nextpal_item (core, mode, fn, ctr++)) {
						r_list_free (files);
						files = NULL;
						R_FREE (home);
						goto done;
					}
				}
			}
		}
		r_list_free (files);
		R_FREE (home);
	}
	files = r_sys_dir (R2_DATDIR"/radare2/"R2_VERSION"/cons/");
	r_list_foreach (files, iter, fn) {
		if (*fn && *fn != '.') {
			if (mode == 'p') {
				const char *nfn = iter->n? iter->n->data: NULL;
				if (!curtheme) {
					free (home);
					r_list_free (files);
					return;
				}
				eprintf ("%s %s %s\n", nfn, curtheme, fn);
				if (nfn && !strcmp (nfn, curtheme)) {
					free (curtheme);
					curtheme = strdup (fn);
					goto done;
				}
			} else {
				if (!nextpal_item (core, mode, fn, ctr++)) {
					goto done;
				}
			}
		}
	}
done:
	if (getNext) {
		R_FREE (curtheme);
		nextpal (core, mode);
		return;
	}
	if (mode == 'l' && !curtheme && !r_list_empty (files)) {
		//nextpal (core, mode);
	} else if (mode != 'j') {
		if (curtheme) {
			r_core_cmdf (core, "eco %s", curtheme);
		}
	}
	r_list_free (files);
	files = NULL;
	if (mode == 'j') {
		r_cons_printf ("]\n");
	}
}

static int cmd_eval(void *data, const char *input) {
	char *p;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case '\0': // "e"
		r_config_list (core->config, NULL, 0);
		break;
	case '?': // "e?"
	default:
		switch (input[1]) {
		case '\0': r_core_cmd_help (core, help_msg_e); break;
		case '?': r_config_list (core->config, input+2, 2); break;
		default: r_config_list (core->config, input+1, 2); break;
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
		} else if (strlen (input)>3) {
			char *v, *k = strdup (input+3);
			if (!k) break;
			v = strchr (k, '=');
			if (v) {
				*v++ = 0;
				r_sys_setenv (k, v);
			}
			free (k);
		}
		return true;
	case 'x': // exit
		// XXX we need headers for the cmd_xxx files.
		return cmd_quit (data, "");
	case 'j': // json
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
			r_cons_pal_init ();
			break;
		case '?':
			r_core_cmd_help (core, help_msg_ec);
			break;
		case 'o': // "eco"
			if (input[2] == 'j') {
				nextpal (core, 'j');
			} else if (input[2] == ' ') {
				bool failed = false;
				char *home, path[512];
				snprintf (path, sizeof (path), ".config/radare2/cons/%s", input + 3);
				home = r_str_home (path);
				snprintf (path, sizeof (path), R2_DATDIR"/radare2/"
					R2_VERSION"/cons/%s", input + 3);
				if (!load_theme (core, home)) {
					if (load_theme (core, path)) {
						//curtheme = r_str_dup (curtheme, path);
						curtheme = r_str_dup (curtheme, input + 3);
					} else {
						if (load_theme (core, input + 3)) {
							curtheme = r_str_dup (curtheme, input + 3);
						} else {
							char *absfile = r_file_abspath (input + 3);
							eprintf ("eco: cannot open colorscheme profile (%s)\n", absfile);
							free (absfile);
							failed = true;
						}
					}
				}
				free (home);
				if (failed) {
					eprintf ("Something went wrong\n");
				}
			} else if (input[2] == '?') {
				eprintf ("Usage: eco [themename]  ;load theme from "R2_DATDIR"/radare2/"R2_VERSION"/cons/\n");

			} else {
				nextpal (core, 'l');
			}
			break;
		case 's': r_cons_pal_show (); break; // "ecs"
		case '*': r_cons_pal_list (1, NULL); break; // "ec*"
		case 'h': // echo
			if (( p = strchr (input, ' ') )) {
				r_cons_strcat (p+1);
				r_cons_newline ();
			} else {
				// "ech"
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
			char** argv = r_str_argv (input + 4, &argc);
			switch (input[2]) {
			case '?': {
				const char *helpmsg[] = {
					"Usage ecH[iw-?]","","",
					"ecHi","[color]","highlight current instruction with 'color' background",
					"ecHw","[word] [color]","highlight 'word ' in current instruction with 'color' background",
					"ecH-","","remove all highlights on current instruction",
					NULL
				};
				r_core_cmd_help (core, helpmsg);
				}
				break;
			case '-':
				r_meta_set_string (core->anal, R_META_TYPE_HIGHLIGHT, core->offset, "");
				return false;
			case '\0':
			case 'i': // "ecHi"
				if (argc) {
					char *dup = r_str_newf ("bgonly %s", argv[0]);
					color_code = r_cons_pal_parse (dup, NULL);
					R_FREE (dup);
				}
				break;
			case 'w': // "ecHw"
				if (!argc) {
					eprintf ("Usage: echw word [color]\n");
					r_str_argv_free (argv);
					return true;
				}
				word = strdup (argv[0]);
				if (argc > 1) {
					char *dup = r_str_newf ("bgonly %s", argv[1]);
					color_code = r_cons_pal_parse (dup, NULL);
					if (!color_code) {
						eprintf ("Unknown color %s\n", argv[1]);
						r_str_argv_free (argv);
						free (dup);
						free (word);
						return true;
					}
					R_FREE (dup);
				}
				break;
			default:
				eprintf ("See ecH?\n");
				r_str_argv_free (argv);
				return true;
			}
			char *str = r_meta_get_string (core->anal, R_META_TYPE_HIGHLIGHT, core->offset);
			char *dup = r_str_newf ("%s \"%s%s\"", str?str:"", word?word:"", color_code?color_code:r_cons_singleton ()->pal.highlight);
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
				r_cons_rgb_str (color, &rcolor);
				eprintf ("(%s)(%sCOLOR"Color_RESET")\n", p, color);
			}
			free (p);
		}
		}
		break;
	case 'd': // "ed"
		{
			if (r_config_get_i (core->config, "scr.interactive")) {
				char *file = r_str_home(".radare2rc");
				char * res = r_cons_editor (file, NULL);
				if (res) {
					if (r_cons_yesno ('y', "Reload? (Y/n)")) {
						r_core_run_script (core, file);
					}
				}
				free (file);
			}
		}
		break;
	case 'e': // "ee"
		if (input[1] == ' ') {
			char *p;
			const char *val, *input2 = strchr (input+2, ' ');
			if (input2) input2++; else input2 = input+2;
			val = r_config_get (core->config, input2);
			p = r_core_editor (core, NULL, val);
			if (p) {
				r_str_replace_char (p, '\n', ';');
				r_config_set (core->config, input2, p);
			}
		} else {
			eprintf ("Usage: ee varname\n");
		}
		break;
	case '!': // "e!"
		input = r_str_trim_ro (input+1);
		if (!r_config_toggle (core->config, input))
			eprintf ("r_config: '%s' is not a boolean variable.\n", input);
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
			const char *key = input+((input[1]==' ')?2:1);
			if (!r_config_readonly (core->config, key)) {
				eprintf ("cannot find key '%s'\n", key);
			}
		} else {
			eprintf ("Usage: er [key]\n");
		}
		break;
	case ' ': r_config_eval (core->config, input+1); break;
	}
	return 0;
}
