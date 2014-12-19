/* radare - LGPL - Copyright 2009-2014 - pancake */

static int cmd_eval(void *data, const char *input) {
	char *p;
	RCore *core = (RCore *)data;
	switch (input[0]) {
	case 'n': // env
		if (!strchr (input, '=')) {
			char *var, *p;
			var = strchr (input, ' ');
			if (var) while (*var==' ') var++;
			p = r_sys_getenv (var);
			if (p) {
				r_cons_printf ("%s\n", p);
				free (p);
			} else {
				char **e = r_sys_get_environ ();
				while (e && *e) {
					r_cons_printf ("%s\n", *e);
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
		return R_TRUE;
	case 'x': // exit
		return cmd_quit (data, "");
	case 'j':
		r_config_list (core->config, NULL, 'j');
		break;
	case '\0':
		r_config_list (core->config, NULL, 0);
		break;
	case 'c':
		switch (input[1]) {
		case 'h': // echo
			if (( p = strchr (input, ' ') )) {
				r_cons_strcat (p+1);
				r_cons_newline ();
			}
			break;
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
			"eco"," dark|white","load white color scheme template",
			"ec"," prompt red","change color of prompt",
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
			if (input[2] == ' ') {
				char *home, path[512];
				snprintf (path, sizeof (path), ".config/radare2/cons/%s", input+3);
				home = r_str_home (path);
				snprintf (path, sizeof (path), R2_DATDIR"/radare2/"
					R2_VERSION"/cons/%s", input+3);
				if (!r_core_cmd_file (core, home))
					if (!r_core_cmd_file (core, path))
						if (!r_core_cmd_file (core, input+3))
							eprintf ("eco: cannot open colorscheme profile (%s)\n", path);
				free (home);
			} else {
				RList *files;
				RListIter *iter;
				const char *fn;
				char *home = r_str_home (".config/radare2/cons/");
				if (home) {
					files = r_sys_dir (home);
					r_list_foreach (files, iter, fn) {
						if (*fn && *fn != '.')
							r_cons_printf ("%s\n", fn);
					}
					r_list_free (files);
					free (home);
				}
				files = r_sys_dir (R2_DATDIR"/radare2/"R2_VERSION"/cons/");
				r_list_foreach (files, iter, fn) {
					if (*fn && *fn != '.')
						r_cons_printf ("%s\n", fn);
				}
				r_list_free (files);
			}
			break;
		case 's': r_cons_pal_show (); break;
		case '*': r_cons_pal_list (1); break;
		case 'j': r_cons_pal_list ('j'); break;
		case '\0': r_cons_pal_list (0); break;
		case 'r': r_cons_pal_random (); break;
		default: {
			char *p = strdup (input+2);
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
		if (!r_config_swap (core->config, input))
			eprintf ("r_config: '%s' is not a boolean variable.\n", input);
		break;
	case '-':
		r_core_config_init (core);
		eprintf ("BUG: 'e-' command locks the eval hashtable. patches are welcome :)\n");
		break;
	case 'v': eprintf ("Invalid command '%s'. Use 'e?'\n", input); break;
	case '*': r_config_list (core->config, NULL, 1); break;
	case '?':
		switch (input[1]) {
		case '?': r_config_list (core->config, input+2, 2); break;
		default: r_config_list (core->config, input+1, 2); break;
		case 0:{
			const char* help_msg[] = {
			"Usage:", "e[?] [var[=value]]", "Evaluable vars",
			"e","?asm.bytes", "show description",
			"e", "??", "list config vars with description",
			"e", "", "list config vars",
			"e-", "", "reset config vars",
			"e*", "", "dump config vars in r commands",
			"e!", "a", "invert the boolean value of 'a' var",
			"er", " [key]", "set config key as readonly. no way back",
			"ec", " [k] [color]", "set color for given key (prompt, offset, ...)",
			"e", " a", "get value of var 'a'",
			"e", " a=b", "set var 'a' the 'b' value",
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
