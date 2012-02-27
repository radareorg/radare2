/* radare - LGPL - Copyright 2009-2012 // pancake<nopcode.org> */

static int cmd_flag(void *data, const char *input) {
	RCore *core = (RCore *)data;
	char *str = NULL;
	ut64 off = core->offset;

	if (*input)
		str = strdup (input+1);
	switch (*input) {
	case '+':
	case ' ': {
		char *s = NULL, *s2 = NULL;
		ut32 bsze = core->blocksize;
		s = strchr (str, ' ');
		if (s) {
			*s = '\0';
			s2 = strchr (s+1, ' ');
			if (s2) {
				*s2 = '\0';
				if (s2[1]&&s2[2])
					off = r_num_math (core->num, s2+1);
			}
			bsze = r_num_math (core->num, s+1);
		}
		r_flag_set (core->flags, str, off, bsze, (*input=='+'));
		}
		break;
	case '-':
		if (input[1]) {
			if (strchr (input+1, '*'))
				r_flag_unset_glob (core->flags, input+1);
			else r_flag_unset (core->flags, input+1, NULL);
		} else r_flag_unset_i (core->flags, off, NULL);
		break;
	case 'l':
		if (input[1] == ' ') {
			RFlagItem *item = r_flag_get_i (core->flags,
				r_num_math (core->num, input+2));
			if (item) {
				r_cons_printf ("0x%08"PFMT64x"\n", item->offset);
			}
		} else eprintf ("Missing arguments\n");
		break;
	case 'S':
		r_flag_sort (core->flags, (input[1]=='n'));
		break;
	case 's':
		if (input[1]==' ') r_flag_space_set (core->flags, input+2);
		else r_flag_space_list (core->flags);
		break;
	case 'o':
		{ // TODO: use file.fortunes
			char *file = R2_PREFIX"/share/doc/radare2/fortunes";
			char *line = r_file_slurp_random_line (file);
			if (line) {
				r_cons_printf (" -- %s\n", line);
				free (line);
			}
		}
		break;
	case 'r':
		{
			char *old, *new;
			RFlagItem *item;
			old = str+1;
			new = strchr (old, ' ');
			if (new) {
				*new = 0;
				new++;
				item = r_flag_get (core->flags, old);
			} else {
				new = old;
				item = r_flag_get_i (core->flags, core->offset);
			}
			if (item) r_flag_rename (core->flags, item, new);
			else eprintf ("Cannot find flag\n");
		}
		break;
	case '*':
		r_flag_list (core->flags, 1);
		break;
	case '\0':
		r_flag_list (core->flags, 0);
		break;
	case 'd':
		{
			ut64 addr = 0;
			RFlagItem *f = NULL;
			switch (input[1]) {
			case '?':
				eprintf ("Usage: fd [off]\n");
				return R_FALSE;
			case '\0':
				addr = core->offset;
				break;
			default:
				addr = r_num_math (core->num, input+2);
				break;
			}
			f = r_flag_get_at (core->flags, addr);
			if (f) {
				if (f->offset != addr) {
					r_cons_printf ("%s+%d\n", f->name, (int)(addr-f->offset));
				} else r_cons_printf ("%s\n", f->name);
			}
		}
		break;
	case '?':
		r_cons_printf (
		"Usage: f[?] [flagname]\n"
		" f name 12 @ 33   ; set flag 'name' with length 12 at offset 33\n"
		" f name 12 33     ; same as above\n"
		" f+name 12 @ 33   ; like above but creates new one if doesnt exist\n"
		" f-name           ; remove flag 'name'\n"
		" f-@addr          ; remove flag at address expression\n"
		" fd addr          ; return flag+delta\n"
		" f                ; list flags\n"
		" f*               ; list flags in r commands\n"
		" fr [old] [new]   ; rename flag\n"
		" fs functions     ; set flagspace\n"
		" fs *             ; set no flagspace\n"
		" fs               ; display flagspaces\n"
		" fl [flagname]    ; show flag length (size)\n"
		" fS[on]           ; sort flags by offset or name\n"
		" fo               ; show fortunes\n");
		break;
	}
	if (str)
		free (str);
	return 0;
}

