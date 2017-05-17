/* radare2 - LGPL - Copyright 2009-2017 - pancake */

#include <stddef.h>
#include <stdbool.h>
#include "r_core.h"

static char *curtheme = NULL;
static bool getNext = false;

static bool load_theme(RCore *core, const char *path) {
	core->cmdfilter = "ec ";
	bool res = r_core_cmd_file (core, path);
	r_cons_pal_update_event ();
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
	} else {
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
	case 't': // env
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
	case 'n': // env
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
	case '\0': // "e"
		r_config_list (core->config, NULL, 0);
		break;
	case 'c': // "ec"
		switch (input[1]) {
		case 'd':
			r_cons_pal_init (NULL);
			break;
		case '?': {
			const char *helpmsg[] = {
			"Usage ec[s?] [key][[=| ]fg] [bg]","","",
			"ec","","list all color keys",
			"ec*","","same as above, but using r2 commands",
			"ecd","","set default palette",
			"ecr","","set random palette",
			"ecs","","show a colorful palette",
			"ecj","","show palette in JSON",
			"ecc"," [prefix]","show palette in CSS",
			"eco"," dark|white","load white color scheme template",
			"ecp","","load previous color theme",
			"ecn","","load next color theme",
			"ec"," prompt red","change color of prompt",
			"ec"," prompt red blue","change color and background of prompt",
			""," ","",
			"colors:","","rgb:000, red, green, blue, ...",
			"e scr.rgbcolor","=1|0","for 256 color cube (boolean)",
			"e scr.truecolor","=1|0","for 256*256*256 colors (boolean)",
			"$DATADIR/radare2/cons","","~/.config/radare2/cons ./",
			NULL};
			r_core_cmd_help (core, helpmsg);
			}
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
							eprintf ("eco: cannot open colorscheme profile (%s)\n", path);
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
		default: {
			char *p = strdup (input + 2);
			char *q = strchr (p, '=');
			if (!q) q = strchr (p, ' ');
			if (q) {
				// set
				*q++ = 0;
				r_cons_pal_set (p, q);
			} else {
				const char *k = r_cons_pal_get (p);
				if (k)
					eprintf ("(%s)(%sCOLOR"Color_RESET")\n", p, k);
			}
			free (p);
		}
		}
		break;
	case 'e':
		if (input[1]==' ') {
			char *p;
			const char *val, *input2 = strchr (input+2, ' ');
			if (input2) input2++; else input2 = input+2;
			val = r_config_get (core->config, input2);
			p = r_core_editor (core, NULL, val);
			if (p) {
				r_str_replace_char (p, '\n', ';');
				r_config_set (core->config, input2, p);
			}
		} else eprintf ("Usage: ee varname\n");
		break;
	case '!':
		input = r_str_chop_ro (input+1);
		if (!r_config_toggle (core->config, input))
			eprintf ("r_config: '%s' is not a boolean variable.\n", input);
		break;
	case '-':
		r_core_config_init (core);
		//eprintf ("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case '*': r_config_list (core->config, NULL, 1); break;
	case '?':
		switch (input[1]) {
		case '?': r_config_list (core->config, input+2, 2); break;
		default: r_config_list (core->config, input+1, 2); break;
		case 0:{
			const char* help_msg[] = {
			"Usage:", "e [var[=value]]", "Evaluable vars",
			"e","?asm.bytes", "show description",
			"e", "??", "list config vars with description",
			"ej", "", "list config vars in JSON",
			"e-", "", "reset config vars",
			"e*", "", "dump config vars in r commands",
			"e!", "a", "invert the boolean value of 'a' var",
			"ee", "var", "open editor to change the value of var",
			"er", " [key]", "set config key as readonly. no way back",
			"ec", " [k] [color]", "set color for given key (prompt, offset, ...)",
			"et", " [key]", "show type of given config variable",
			"ev", " [key]", "list config vars in verbose format",
			"evj", " [key]", "list config vars in verbose format in JSON",
			"e", " a", "get value of var 'a'",
			"e", " a=b", "set var 'a' the 'b' value",
			"e var=?", "", "print all valid values of var",
			"env", " [k[=v]]", "get/set environment variable",
			NULL};
			r_core_cmd_help (core, help_msg);
			}
		}
		break;
	case 'r':
		if (input[1]) {
			const char *key = input+((input[1]==' ')?2:1);
			if (!r_config_readonly (core->config, key))
				eprintf ("cannot find key '%s'\n", key);
		} else eprintf ("Usage: er [key]\n");
		break;
	case ' ': r_config_eval (core->config, input+1); break;
	default: r_config_eval (core->config, input); break;
	}
	return 0;
}
