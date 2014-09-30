/* radare - LGPL - Copyright 2009-2013 - pancake */

static int cmd_zign(void *data, const char *input) {
	RCore *core = (RCore *)data;
	RAnalFunction *fcni;
	RListIter *iter;
	RSignItem *item;
	int i, fd = -1, len;
	char *ptr, *name;

	switch (*input) {
	case 'g':
		if (input[1]==' ' && input[2]) {
			int fdold = r_cons_singleton ()->fdout;
			ptr = strchr (input+2, ' ');
			if (ptr) {
				*ptr = '\0';
				fd = open (ptr+1, O_RDWR|O_CREAT|O_TRUNC, 0644);
				if (fd == -1) {
					eprintf ("Cannot open %s in read-write\n", ptr+1);
					return R_FALSE;
				}
				r_cons_singleton ()->fdout = fd;
				r_cons_strcat ("# Signatures\n");
			}
			r_cons_printf ("zn %s\n", input+2);
			r_list_foreach (core->anal->fcns, iter, fcni) {
				ut8 buf[128];
				if (r_io_read_at (core->io, fcni->addr, buf,
						sizeof (buf)) == sizeof (buf)) {
					RFlagItem *flag = r_flag_get_i (
						core->flags, fcni->addr);
					if (flag) {
						name = flag->name;
						r_cons_printf ("zb %s ", name);
						len = (fcni->size > sizeof (buf))?
							sizeof (buf): fcni->size;
						for (i=0; i<len; i++)
							r_cons_printf ("%02x", buf[i]);
						r_cons_newline ();
					} else eprintf ("Unnamed function at 0x%08"PFMT64x"\n", fcni->addr);
				} else eprintf ("Cannot read at 0x%08"PFMT64x"\n", fcni->addr);
			}
			r_cons_strcat ("zn-\n");
			if (ptr) {
				r_cons_flush ();
				r_cons_singleton ()->fdout = fdold;
				close (fd);
			}
		} else eprintf ("Usage: zg libc [libc.sig]\n");
		break;
	case 'n':
		if (!input[1])
			r_cons_printf ("%s\n", core->sign->ns);
		else if (!strcmp ("-", input+1))
			r_sign_ns (core->sign, "");
		else r_sign_ns (core->sign, input+2);
		break;
	case 'a':
	case 'b':
	case 'h':
	case 'f':
		ptr = strchr (input+3, ' ');
		if (ptr) {
			*ptr = 0;
			r_sign_add (core->sign, core->anal, (int)*input, input+2, ptr+1);
		} else eprintf ("Usage: z%c [name] [arg]\n", *input);
		break;
	case 'c':
		item = r_sign_check (core->sign, core->block, core->blocksize);
		if (item)
			r_cons_printf ("f sign.%s @ 0x%08"PFMT64x"\n", item->name, core->offset);
		break;
	case '-':
		if (input[1] == '*')
			r_sign_reset (core->sign);
		else {
			int i = r_sign_remove_ns(core->sign, input+1);
			r_cons_printf ("%d zignatures removed\n", i);
		}
		break;
	case '/':
		{
			// TODO: parse arg0 and arg1
			ut8 *buf;
			int len, idx;
			ut64 ini, fin;
			RSignItem *si;
			RIOSection *s;
			if (input[1]) {
				char *ptr = strchr (input+2, ' ');
				if (ptr) {
					*ptr = '\0';
					ini = r_num_math (core->num, input+2);
					fin = r_num_math (core->num, ptr+1);
				} else {
					ini = core->offset;
					fin = ini+r_num_math (core->num, input+2);
				}
			} else {
				s = r_io_section_vget (core->io, core->io->off);
				if (s) {
					ini = core->io->va?s->vaddr:s->offset;
					fin = ini + (core->io->va?s->vsize:s->size);
				} else {
					eprintf ("No section identified, please provide range.\n");
					return R_FALSE;
				}
			}
			if (ini>=fin) {
				eprintf ("Invalid range (0x%"PFMT64x"-0x%"PFMT64x").\n", ini, fin);
				return R_FALSE;
			}
			len = fin-ini;
			buf = malloc (len);
			if (buf != NULL) {
				int count = 0;
				eprintf ("Ranges are: 0x%08"PFMT64x" 0x%08"PFMT64x"\n", ini, fin);
				r_cons_printf ("fs sign\n");
				r_cons_break (NULL, NULL);
				if (r_io_read_at (core->io, ini, buf, len) == len) {
					for (idx=0; idx<len; idx++) {
						if (r_cons_singleton ()->breaked)
							break;
						si = r_sign_check (core->sign, buf+idx, len-idx);
						if (si) {
							count++;
							if (si->type == 'f')
								r_cons_printf ("f sign.fun_%s_%d @ 0x%08"PFMT64x"\n",
									si->name, idx, ini+idx); //core->offset);
							else r_cons_printf ("f sign.%s @ 0x%08"PFMT64x"\n",
								si->name, ini+idx); //core->offset+idx);
							eprintf ("- Found %d matching function signatures\r", count);
						}
					}
				} else eprintf ("Cannot read %d bytes at 0x%08"PFMT64x"\n", len, ini);
				r_cons_break_end ();
				free (buf);
			} else eprintf ("Cannot alloc %d bytes\n", len);
		}
		break;
	case '\0':
	case '*':
		r_sign_list (core->sign, (*input=='*'));
		break;
	case 'F': {
		if (input[1] == 'd') {
			if(input[2] != ' ') {
				eprintf("Usage: zFd <file>\n");
				return R_FALSE;
			}
			r_sign_flirt_dump (core->anal, input + 3);
		} else {
			if(input[1] != ' ') {
				eprintf("Usage: zF <file>\n");
				return R_FALSE;
			}
			r_sign_flirt_scan (core->anal, input + 2);
		}
	}
		break;
	default:
	case '?':{
		const char* help_msg[] = {
			"Usage:", "z[abcp/*-] [arg]", "Zignatures",
			"z", "", "show status of zignatures",
			"z*", "", "display all zignatures",
			"z-", "namespace", "Unload zignatures in namespace",
			"z-*", "", "unload all zignatures",
			"z/", "[ini] [end]", "search zignatures between these regions",
			"za", " ...", "define new zignature for analysis",
			"zb", " name bytes", "define zignature for bytes",
			"zc", " @ fcn.foo", "flag signature if matching (.zc@@fcn)",
			"zf", " name fmt", "define function zignature (fast/slow, args, types)",
			"zF", " file", "Open a flirt signature file and scan opened file",
			"zFd", " file", "Dump a flirt signature",
			"zg", " namespace [file]", "Generate zignatures for current file",
			"zh", " name bytes", "define function header zignature",
			"zn", " namespace", "Define namespace for following zignatures (until zn-)",
			"zn", "", "Display current namespace",
			"zn-", "", "Unset namespace",
			"NOTE:", "", "bytes can contain '.' (dots) to specify a binary mask",
			NULL};
			r_core_cmd_help (core, help_msg);
			 }
		break;
	}
	return 0;
}
