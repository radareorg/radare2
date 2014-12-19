/* radare - LGPL - Copyright 2009-2014 - pancake */
#if 0
static void filter_line(char *line) {
	char *a;

	if (!line)
		return;

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
}
#endif

static int remove_meta_offset(RCore *core, ut64 offset) {
	int ret;
	char aoffset[64], *aoffsetptr;

	aoffsetptr = sdb_itoa (offset, aoffset, 16);

	if (!aoffsetptr) {
		eprintf ("Failed to convert %"PFMT64x" to a key", offset);
		return -1;
	}
	ret = sdb_unset (core->bin->cur->sdb_addrinfo, aoffsetptr, 0);
	return ret;
}

static int print_meta_offset(RCore *core, ut64 offset) {
	int ret, line, line_old, i;
	char file[1024];

	ret = r_bin_addr2line (core->bin, offset, file, sizeof (file)-1, &line);

	if (ret) {
		r_cons_printf ("file %s\nline %d\n", file, line);
		line_old = line;
		if (line >= 2)
			line -= 2;
		if (r_file_exists (file)) {
			for (i = 0; i<5; i++) {
				char *row = r_file_slurp_line (file, line+i, 0);
				if (row) {
					r_cons_printf ("%c %.3x  %s\n", line+i == line_old ? '>' : ' ', line+i, row);
					free (row);
				}
			}
		} else {
			eprintf ("Cannot open '%s'\n", file);
		}
	} else {
		eprintf ("Cannot find meta information at 0x%08"
			PFMT64x"\n", offset);
	}

	return 0;
}

static int remove_meta_fileline(RCore *core, const char *file_line) {
	int ret;

	ret = sdb_unset (core->bin->cur->sdb_addrinfo, file_line, 0);

	return ret;
}

static int print_meta_fileline(RCore *core, const char *file_line) {
	char *meta_info;

	meta_info = sdb_get (core->bin->cur->sdb_addrinfo, file_line, 0);

	if (meta_info) {
		printf ("Meta info %s\n", meta_info);
	} else {
		printf ("No meta info for %s found\n", file_line);
	}

	return 0;
}

static int print_addrinfo (void *user, const char *k, const char *v) {
	ut64 offset;
	char *colonpos, *subst;

	offset = sdb_atoi (v);
	if (!offset)
		return R_TRUE;

	subst = strdup (k);
	colonpos = strchr (subst, '|');

	if (colonpos)
		*colonpos = ':';

	r_cons_printf ("CL %s %s\n", subst, v);

	free (subst);

	return R_TRUE;
}

static int cmd_meta_add_fileline(Sdb *s, char *fileline, ut64 offset) {
	char aoffset[64], *aoffsetptr;

	aoffsetptr = sdb_itoa (offset, aoffset, 16);

	if (!aoffsetptr)
		return -1;

	if (!sdb_add (s, aoffsetptr, fileline, 0)) {
		sdb_set (s, aoffsetptr, fileline, 0);
	}

	if (!sdb_add (s, fileline, aoffsetptr, 0)) {
		sdb_set (s, fileline, aoffsetptr, 0);
	}

	return 0;
}

static int cmd_meta_lineinfo(RCore *core, const char *input) {
	int ret;
	ut64 offset = UT64_MAX; // use this as error value
	int remove = R_FALSE;
	int all = R_FALSE;
	const char *p = input;
	char *colon, *space, *file_line = 0;

	if (*p == '?') {
		eprintf ("Usage: CL[-][*] [file:line] [addr]");
		return 0;
	}

	if (*p == '-') {
		p++;
		remove = R_TRUE;
	}

	if (*p == '*') {
		p++;
		all = R_TRUE;
	}

	if (all) {
		if (remove) {
			sdb_reset (core->bin->cur->sdb_addrinfo);
		} else {
			sdb_foreach (core->bin->cur->sdb_addrinfo, print_addrinfo, NULL);
		}
		return 0;
	}

	while (*p == ' ') {
		p++;
	}

	if (*p) {
		offset = r_num_math (core->num, p);
		if (!offset)
			offset = core->offset;
	} else offset = core->offset;
	colon = strchr (p, ':');
	if (colon) {
		space = strchr (p, ' ');
		if (!space) {
			file_line = strdup (p);
		} else if (space > colon) {
			file_line = r_str_ndup (p, space - p);
		} else {
			goto error;
		}

		colon = strchr (file_line, ':');
		if (!colon)
			goto error;
		*colon = '|';

		while (*p != ' ')
			p++;

		while (*p == ' ')
			p++;

		if (*p != '\0') {
			ret = sscanf (p, "0x%"PFMT64x, &offset);

			if (ret != 1) {
				eprintf ("Failed to parse addr at %s\n", p);
				goto error;
			}

			ret = cmd_meta_add_fileline (core->bin->cur->sdb_addrinfo,
					file_line, offset);

			goto error;
		}

		if (!file_line)
			return -1;

		if (remove) {
			remove_meta_fileline (core, file_line);
		} else {
			print_meta_fileline (core, file_line);
		}

		free (file_line);
		return 0;
	}
	offset = core->offset;

	if (offset != UT64_MAX) {
		if (remove) {
			remove_meta_offset (core, offset);
		} else {
			print_meta_offset (core, offset);
		}
	} else {
		goto error;
	}
	return 0;

error:
	free (file_line);
	return -1;
}

static int cmd_meta_comment(RCore *core, const char *input) {
	ut64 addr = core->offset;
	switch (input[1]) {
	case '!':
		{
			char *out, *comment = r_meta_get_string (
					core->anal, R_META_TYPE_COMMENT, addr);
			out = r_core_editor (core, NULL, comment);
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
	case '+':
	case ' ':
		{
		const char* newcomment = input+2;
		char *text;
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
		}
		break;
	case '*':
		r_meta_list (core->anal, R_META_TYPE_COMMENT, 1);
		break;
	case '-':
		r_meta_del (core->anal, R_META_TYPE_COMMENT, core->offset, 1, NULL);
		break;
	case 'u':
		//
		{
		const char* newcomment = input+2;
		while (*newcomment==' ') newcomment++;
		char *comment = r_meta_get_string (
				core->anal, R_META_TYPE_COMMENT, addr);
		if (!comment || (comment && !strstr (comment, newcomment))) {
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT,
					addr, newcomment);
		}
		free (comment);
		}
		break;
	case 'a':
		{
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
	}

	return R_TRUE;
}

static int cmd_meta_hsdmf (RCore *core, const char *input) {
	int n, type = input[0];
	char *t = 0, *p, name[256];
	ut64 addr_end = 0LL, addr = core->offset;

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
			out = r_core_editor (core, NULL, comment);
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
			r_meta_list (core->anal, type, 0);
			break;
		}
		t = strdup (input+2);
		p = NULL;
		n = 0;
		strncpy (name, t, sizeof (name)-1);
		if (*input != 'C') {
			n = r_num_math (core->num, t);
			if (type == 'f') {
				p = strchr (t, ' ');
				if (p)
					n = r_print_format (core->print, addr, core->block,
							core->blocksize, p+1, -1, NULL, NULL);
			}
			if (type == 's') {
				/* This is kept for compatibility with old projects.
				 * Somewhat broken, but project will get corrected on
				 * save and reload.
				 */
				p = strchr (t, ' ');
				if (p)
					addr = r_num_math (core->num, p+1);
			}
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
							r_core_read_at (core, addr, (ut8*)name, sizeof (name)-1);
							if (n < sizeof(name))
								name[n] = '\0';
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

	return R_TRUE;
}

static int cmd_meta(void *data, const char *input) {
	RCore *core = (RCore*)data;
	int i;
	RAnalFunction *f;

	switch (*input) {
	case 'j':
	case '*':
		r_meta_list (core->anal, R_META_TYPE_ANY, *input);
		break;
	case 'L':
		cmd_meta_lineinfo (core, input + 1);
		break;
	case 'C':
		cmd_meta_comment (core, input);
		break;
	case 'h': /* comment */
	case 's': /* string */
	case 'd': /* data */
	case 'm': /* magic */
	case 'f': /* formatted */
		cmd_meta_hsdmf (core, input);
		break;
	case '-':
		if (input[1]!='*') {
			i = r_num_math (core->num, input+((input[1]==' ')?2:1));
			r_meta_del (core->anal, R_META_TYPE_ANY, core->offset, i, "");
		} else r_meta_cleanup (core->anal, 0LL, UT64_MAX);
		break;
	case '\0':
	case '?':{
			const char* help_msg[] = {
				"Usage:", "C[-LCvsdfm?] [...]", " # Metadata management",
				"C*", "", "list meta info in r2 commands",
				"C-", " [len] [[@]addr]", "delete metadata at given address range",
				"CL", "[-][*] [file:line] [addr]", "show or add 'code line' information (bininfo)",
				"CC", "[-] [comment-text] [@addr]", "add/remove comment",
				"CC!", " [@addr]", "edit comment with $EDITOR",
				"CCa", "[-at]|[at] [text] [@addr]", "add/remove comment at given address",
				"CCu", " [comment-text] [@addr]", "add unique comment",
				"Cs", "[-] [size] [@addr]", "add string",
				"Ch", "[-] [size] [@addr]", "hide data",
				"Cd", "[-] [size] [@addr]", "hexdump data",
				"Cf", "[-] [sz] [fmt..] [@addr]", "format memory (see pf?)",
				"Cm", "[-] [sz] [fmt..] [@addr]", "magic parse (see pm?)",
				NULL};
			r_core_cmd_help (core, help_msg);
			}
		break;
	case 'F':
		f = r_anal_get_fcn_in (core->anal, core->offset,
			R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) r_anal_str_to_fcn (core->anal, f, input+2);
		else eprintf ("Cannot find function here\n");
		break;
	}
	return R_TRUE;
}
