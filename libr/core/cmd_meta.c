/* radare - LGPL - Copyright 2009-2013 - pancake */

// XXX this command is broken. output of _list is not compatible with input
static int cmd_meta(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int n = 0, type = input[0];
	ut64 addr = core->offset;
	char *t, *p, name[256];
	int i, ret, line = 0;
	ut64 addr_end = 0LL;
	RAnalFunction *f;
	char file[1024];

	switch (*input) {
	case 'j':
	case '*':
		r_meta_list (core->anal, R_META_TYPE_ANY, *input);
		break;
	case 'l':
		// XXX: this should be moved to CL?
		if (input[2]=='a') {
			ut64 offset;
			input++;
			if (input[1]=='?') {
				eprintf ("Usage: cla [addr]\n");
			} else {
				char *sl;
				if (input[1]==' ')
					offset = r_num_math (core->num, input+2);
				else offset = core->offset;
				sl = r_bin_addr2text (core->bin, offset);
				if (sl) {
					r_cons_printf ("%s\n", sl);
					free (sl);
				}
			}
		} else {
			int num;
			char *f, *p, *line, buf[4096];
			f = strdup (input +2);
			p = strchr (f, ':');
			if (p) {
				*p = 0;
				num = atoi (p+1);
				line = r_file_slurp_line (f, num, 0);
				if (!line) {
					const char *dirsrc = r_config_get (core->config, "dir.source");
					if (dirsrc && *dirsrc) {
						f = r_str_concat (strdup (dirsrc), f);
						line = r_file_slurp_line (f, num, 0);
					}
					if (!line) {
						eprintf ("Cannot slurp file '%s'\n", f);
						return R_FALSE;
					}
				}
// filter_line
char *a;
for (a=line; *a; a++) {
	switch (*a) {
	case '%':
	case '(':
	case ')':
	case '~':
	case '|':
	case '#':
	case ';':
	case '"':
		*a = '_';
		break;
	}
}
				p = strchr (p+1, ' ');
				if (p) {
					snprintf (buf, sizeof (buf), "CC %s:%d %s @ %s",
						f, num, line, p+1);
				} else {
					snprintf (buf, sizeof (buf), "\"CC %s:%d %s\"",
						f, num, line);
				}
eprintf ("-- %s\n", buf);
				r_core_cmd0 (core, buf);
				free (line);
				free (f);
			} else eprintf ("Usage: Cl [file:line] [address]\n");
		}
		break;
	case 'L': // debug information of current offset
		ret = r_bin_addr2line (core->bin, core->offset, file,
			sizeof (file)-1, &line);
		if (ret) {
			r_cons_printf ("file %s\nline %d\n", file, line);
			ret = (line<5)? 5-line: 5;
			line -= 2;
			for (i = 0; i<ret; i++) {
				char *row = r_file_slurp_line (file, line+i, 0);
				r_cons_printf ("%c %.3x  %s\n", (i==2)?'>':' ', line+i, row);
				free (row);
			}
		} else eprintf ("Cannot find meta information at 0x%08"
			PFMT64x"\n", core->offset);
		break;
	// XXX: use R_META_TYPE_XXX here
	case 'z': /* string */
		{
			r_core_read_at (core, addr, (ut8*)name, sizeof (name));
			name[sizeof (name)-1] = 0;
			n = strlen (name);
			eprintf ("%d\n", n);
		}
	case 'C': /* comment */
		if (input[1] == '+') {
			char *text, *newcomment = input+2;
			while (*newcomment==' ') newcomment++;
			char *comment = r_meta_get_string (
				core->anal, R_META_TYPE_COMMENT, addr);
			if (comment) {
				text = malloc (strlen (comment)+strlen (newcomment)+2);
				strcpy (text, comment);
				strcat (text, "\n");
				strcat (text, newcomment);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT,
					addr, text);
				free (text);
			} else {
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT,
					addr, newcomment);
			}
			return R_TRUE;
		} else
		if (input[1] == 'a') {
			char *s, *p;
			s = strchr (input, ' ');
			if (s) {
				s = strdup (s+1);
			} else {
				eprintf ("Usage\n");
				return R_FALSE;
			}
			p = strchr (s, ' ');
			if (p) *p++ = 0;
			ut64 addr;
			if (input[2]=='-') {
				if (input[3]) {
					addr = r_num_math (core->num, input+3);
					r_meta_del (core->anal,
						R_META_TYPE_COMMENT,
						addr, 1, NULL);
				} else eprintf ("Usage: CCa-[address]\n");
				free (s);
				return R_TRUE;
			}
			addr = r_num_math (core->num, s);
			// Comment at
			if (p) {
				if (input[2]=='+') {
					char *text = p;
					char *comment = r_meta_get_string (
						core->anal, R_META_TYPE_COMMENT,
					     addr);
					if (comment) {
						text = malloc (strlen (comment) + strlen (p)+2);
						strcpy (text, comment);
						strcat (text, "\n");
						strcat (text, p);
						r_meta_add (core->anal,
							R_META_TYPE_COMMENT,
							   addr, addr+1, text);
						free (text);
					} else {
						r_meta_add (core->anal,
							R_META_TYPE_COMMENT,
							addr, addr+1, p);
					}
				} else {
					r_meta_add (core->anal,
						R_META_TYPE_COMMENT,
						addr, addr+1, p);
				}
			} else eprintf ("Usage: CCa [address] [comment]\n");
			free (s);
			return R_TRUE;
		}
	case 'h': /* comment */
	case 's': /* string */
	case 'd': /* data */
	case 'm': /* magic */
	case 'f': /* formatted */
		switch (input[1]) {
		case '?':
			eprintf ("See C?\n");
			break;
		case '-':
			switch (input[2]) {
			case '*':
				core->num->value = r_meta_del (core->anal,
					input[0], 0, UT64_MAX, NULL);
				break;
			case ' ':
				addr = r_num_math (core->num, input+3);
			default:
				core->num->value = r_meta_del (core->anal,
					input[0], addr, 1, NULL);
				break;
			}
			break;
		case '*':
			r_meta_list (core->anal, input[0], 1);
			break;
		case '!':
			{
				char *out, *comment = r_meta_get_string (
					core->anal, R_META_TYPE_COMMENT, addr);
				out = r_core_editor (core, comment);
				if (out) {
					//r_meta_add (core->anal->meta, R_META_TYPE_COMMENT, addr, 0, out);
					r_core_cmdf (core, "CC-@0x%08"PFMT64x, addr);
					//r_meta_del (core->anal->meta, input[0], addr, addr+1, NULL);
					r_meta_set_string (core->anal,
						R_META_TYPE_COMMENT, addr, out);
					free (out);
				}
				free (comment);
			}
			break;
		case ' ':
		case '\0':
			if (type!='z' && !input[1]) {
				r_meta_list (core->anal, input[0], 0);
				break;
			}
			t = strdup (input+2);
			p = NULL;
			n = 0;
			strncpy (name, t, sizeof (name)-1);
			if (*input != 'C') {
				n = r_num_math (core->num, t);
				if (!*t || n>0) {
					RFlagItem *fi;
					p = strchr (t, ' ');
					if (p) {
						*p = '\0';
						strncpy (name, p+1, sizeof (name)-1);
					} else
					switch (type) {
					case 'z':
						type='s';
					case 's':
						// TODO: filter \n and so on :)
						strncpy (name, t, sizeof (name)-1);
						r_core_read_at (core, addr, (ut8*)name, sizeof (name));
						break;
					default:
						fi = r_flag_get_i (core->flags, addr);
						if (fi) strncpy (name, fi->name, sizeof (name)-1);
					}
				} else if (n<1) {
					eprintf ("Invalid length %d\n", n);
					return R_FALSE;
				}
			}
			if (!n) n++;
			addr_end = addr + n;
			if (!r_meta_add (core->anal, type, addr, addr_end, name))
				free (t);
			//r_meta_cleanup (core->anal->meta, 0LL, UT64_MAX);
			break;
		default:
			eprintf ("Missing space after CC\n");
			break;
		}
		break;
	case 'v':
#if USE_VARSUBS
		switch (input[1]) {
		case '?':
			r_cons_printf ("Usage: Cv[-*][ off reg name] \n");
			break;
		case '-':
			{
			ut64 offset;
			if (input[2]==' ') {
				offset = r_num_math (core->num, input+3);
				if ((f = r_anal_fcn_find (core->anal, offset,
						R_ANAL_FCN_TYPE_NULL)) != NULL)
					memset (f->varsubs, 0, sizeof (f->varsubs));
			} else if (input[2]=='*') {
				r_list_foreach (core->anal->fcns, iter, f)
					memset (f->varsubs, 0, sizeof (f->varsubs));
			}
			}
			break;
		case '*':
			r_list_foreach (core->anal->fcns, iter, f) {
				for (i = 0; i < R_ANAL_VARSUBS; i++) {
					if (f->varsubs[i].pat[0] != '\0')
						r_cons_printf ("Cv 0x%08"PFMT64x" %s %s\n", f->addr, f->varsubs[i].pat, f->varsubs[i].sub);
					else break;
				}
			}
			break;
		default:
			{
			char *ptr = strdup (input+2);
			const char *varsub = NULL;
			const char *pattern = NULL;
			ut64 offset = -1LL;
			n = r_str_word_set0 (ptr);
			if (n > 2) {
				switch(n) {
				case 3: varsub = r_str_word_get0 (ptr, 2);
				case 2: pattern = r_str_word_get0 (ptr, 1);
				case 1: offset = r_num_math (core->num, r_str_word_get0 (ptr, 0));
				}
				if ((f = r_anal_fcn_find (core->anal, offset, R_ANAL_FCN_TYPE_NULL)) != NULL) {
					if (pattern && varsub)
					for (i = 0; i < R_ANAL_VARSUBS; i++)
						if (f->varsubs[i].pat[0] == '\0' || !strcmp (f->varsubs[i].pat, pattern)) {
							strncpy (f->varsubs[i].pat, pattern, sizeof (f->varsubs[i].pat)-1);
							strncpy (f->varsubs[i].sub, varsub, sizeof (f->varsubs[i].sub)-1);
							break;
						}
				} else eprintf ("Error: Function not found\n");
			}
			free (ptr);
			}
		break;
		}
#else
		eprintf ("TODO: varsubs has been disabled because it needs to be sdbized\n");
#endif
	case '-':
		if (input[1]!='*') {
			i = r_num_math (core->num, input+((input[1]==' ')?2:1));
			r_meta_del (core->anal, R_META_TYPE_ANY, core->offset, i, "");
		} else r_meta_cleanup (core->anal, 0LL, UT64_MAX);
		break;
	case '\0':
	case '?':
		r_cons_strcat (
		"|Usage: C[-LCvsdfm?] [...]\n"
		"| C*                              List meta info in r2 commands\n"
		"| C- [len] [@][ addr]             delete metadata at given address range\n"
		"| CL[-] [addr|file:line [addr] ]  show 'code line' information (bininfo)\n"
		"| Cl  file:line [addr]            add comment with line information\n"
		"| CC[-] [comment-text]    add/remove comment. Use CC! to edit with $EDITOR\n"
		"| CCa[-at]|[at] [text]    add/remove comment at given address\n"
		"| Cv[-] offset reg name   add var substitution\n"
		"| Cs[-] [size] [[addr]]   add string\n"
		"| Ch[-] [size] [@addr]    hide data\n"
		"| Cd[-] [size]            hexdump data\n"
		"| Cf[-] [sz] [fmt..]      format memory (see pf?)\n"
		"| Cm[-] [sz] [fmt..]      magic parse (see pm?)\n");
		break;
	case 'F':
		f = r_anal_fcn_find (core->anal, core->offset,
				R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) r_anal_str_to_fcn (core->anal, f, input+2);
		else eprintf ("Cannot find function here\n");
		break;
	}
	return R_TRUE;
}
