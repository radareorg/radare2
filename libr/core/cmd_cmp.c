/* radare - LGPL - Copyright 2009-2014 - pancake */

R_API void r_core_cmpwatch_free (RCoreCmpWatcher *w) {
	free (w->ndata);
	free (w->odata);
	free (w);
}

R_API RCoreCmpWatcher* r_core_cmpwatch_get(RCore *core, ut64 addr) {
	RListIter *iter;
	RCoreCmpWatcher *w;
	r_list_foreach (core->watchers, iter, w) {
		if (addr == w->addr)
			return w;
	}
	return NULL;
}

R_API int r_core_cmpwatch_add (RCore *core, ut64 addr, int size, const char *cmd) {
	RCoreCmpWatcher *cmpw;
	if (size<1) return R_FALSE;
	cmpw = r_core_cmpwatch_get (core, addr);
	if (!cmpw) {
		cmpw = R_NEW (RCoreCmpWatcher);
		cmpw->addr = addr;
	}
	cmpw->size = size;
	snprintf (cmpw->cmd, sizeof (cmpw->cmd), "%s", cmd);
	cmpw->odata = NULL;
	cmpw->ndata = malloc (size);
	r_io_read_at (core->io, addr, cmpw->ndata, size);
	r_list_append (core->watchers, cmpw);
	return R_TRUE;
}

R_API int r_core_cmpwatch_del (RCore *core, ut64 addr) {
	int ret = R_FALSE;
	RCoreCmpWatcher *w;
	RListIter *iter, *iter2;
	r_list_foreach_safe (core->watchers, iter, iter2, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			r_list_delete (core->watchers, iter);
			ret = R_TRUE;
		}
	}
	return ret;
}

R_API int r_core_cmpwatch_show (RCore *core, ut64 addr, int mode) {
	char cmd[128];
	RListIter *iter;
	RCoreCmpWatcher *w;
	r_list_foreach (core->watchers, iter, w) {
		int is_diff = w->odata? memcmp (w->odata, w->ndata, w->size): 0;
		switch (mode) {
		case '*':
			r_cons_printf ("cw 0x%08"PFMT64x" %d %s%s\n",
				w->addr, w->size, w->cmd, is_diff? " # differs":"");
			break;
		case 'd': // diff
			if (is_diff)
				r_cons_printf ("0x%08"PFMT64x" has changed\n", w->addr);
		case 'o': // old contents
			// use tmpblocksize
		default:
			r_cons_printf ("0x%08"PFMT64x"%s\n", w->addr, is_diff? " modified":"");
			snprintf (cmd, sizeof (cmd), "%s@%"PFMT64d"!%d",
				w->cmd, w->addr, w->size);
			r_core_cmd0 (core, cmd);
			break;
		}
	}
	return R_FALSE;
}

R_API int r_core_cmpwatch_update (RCore *core, ut64 addr) {
	RCoreCmpWatcher *w;
	RListIter *iter;
	r_list_foreach (core->watchers, iter, w) {
		free (w->odata);
		w->odata = w->ndata;
		w->ndata = malloc (w->size);
		r_io_read_at (core->io, w->addr, w->ndata, w->size);
	}
	return !r_list_empty (core->watchers);
}

R_API int r_core_cmpwatch_revert (RCore *core, ut64 addr) {
	RCoreCmpWatcher *w;
	int ret = R_FALSE;
	RListIter *iter;
	r_list_foreach (core->watchers, iter, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			if (w->odata) {
				free (w->ndata);
				w->ndata = w->odata;
				w->odata = NULL;
				ret = R_TRUE;
			}
		}
	}
	return ret;
}

static int radare_compare_unified(RCore *core, ut64 of, ut64 od, int len) {
	int i, min, inc = 16;
	ut8 *f, *d;
	if (len<1)
		return R_FALSE;
	f = malloc (len);
	d = malloc (len);
	r_io_read_at (core->io, of, f, len);
	r_io_read_at (core->io, od, d, len);
	int headers = B_IS_SET (core->print->flags, R_PRINT_FLAGS_HEADER);
	if (headers)
		B_UNSET (core->print->flags, R_PRINT_FLAGS_HEADER);
	for (i=0; i<len; i+=inc) {
		min = R_MIN (16, (len-i));
		if (!memcmp (f+i, d+i, min)) {
			r_cons_printf ("  ");
			r_print_hexdiff (core->print, of+i, f+i, of+i, f+i, min, 0);
		} else {
			r_cons_printf ("- ");
			r_print_hexdiff (core->print, of+i, f+i, od+i, d+i, min, 0);
			r_cons_printf ("+ ");
			r_print_hexdiff (core->print, od+i, d+i, of+i, f+i, min, 0);
		}
	}
	if (headers)
		B_SET (core->print->flags, R_PRINT_FLAGS_HEADER);
	return R_TRUE;
}

static int radare_compare(RCore *core, const ut8 *f, const ut8 *d, int len) {
	int i, eq = 0;
	for (i=0; i<len; i++) {
		if (f[i]==d[i]) {
			eq++;
			continue;
		}
		r_cons_printf ("0x%08"PFMT64x" (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n",
			core->offset+i, i+1,
			f[i], (IS_PRINTABLE(f[i]))?f[i]:' ',
			d[i], (IS_PRINTABLE(d[i]))?d[i]:' ');
	}
	eprintf ("Compare %d/%d equal bytes (%d%%)\n", eq, len, (eq/len)*100);
	return len-eq;
}

static void cmd_cmp_watcher (RCore *core, const char *input) {
	char *p, *q, *r = NULL;
	int size = 0;
	ut64 addr = 0;
	switch (*input) {
	case ' ':
		p = strdup (input+1);
		q = strchr (p, ' ');
		if (q) {
			*q++ = 0;
			addr = r_num_math (core->num, p);
			r = strchr (q, ' ');
			if (r) {
				*r++ = 0;
				size = atoi (q);
			}
			r_core_cmpwatch_add (core, addr, size, r);
			//eprintf ("ADD (%llx) %d (%s)\n", addr, size, r);
		} else eprintf ("Missing parameters\n");
		free (p);
		break;
	case 'r':
		addr = input[1]? r_num_math (core->num, input+1): UT64_MAX;
		r_core_cmpwatch_revert (core, addr);
		break;
	case 'u':
		addr = input[1]? r_num_math (core->num, input+1): UT64_MAX;
		r_core_cmpwatch_update (core, addr);
		break;
	case '*':
		r_core_cmpwatch_show (core, UT64_MAX, '*');
		break;
	case '\0':
		r_core_cmpwatch_show (core, UT64_MAX, 0);
		break;
	case '?':
		r_cons_printf (
			"Usage: cw[?] [...]\n"
			"  cw              list all compare watchers\n"
			"  cw*             list compare watchers in r2 cmds\n"
			"  cw addr         list all compare watchers\n"
			"  cw addr sz cmd  add a memory watcher\n"
			//"  cws [addr]      show watchers\n"
			"  cwu [addr]      update watchers\n"
			"  cwr [addr]      reset/revert watchers\n"
			);
		break;
	}
}

static int cmd_cmp(void *data, const char *input) {
	RCore *core = data;
	FILE *fd;
	ut8 *buf;
	int ret;
	ut16 v16;
	ut32 v32;
	ut64 v64;
	ut64 val = UT64_MAX;

	switch (*input) {
	case 'a':
		{
			int sz;
			char *p = strchr (input+1, ' ');
			if (p) {
				char *data = r_file_slurp (p+1, &sz);
				if (data) {
					r_cons_memcat (data, sz);
					free (data);
				} else eprintf ("No such file or directory\n");
			} else eprintf ("Usage: cat [file]\n");
		}
		break;
		break;
	case 'w':
		cmd_cmp_watcher (core, input+1);
		break;
	case ' ':
		val = radare_compare (core, core->block, (ut8*)input+1, strlen (input+1)+1);
		break;
	case 'x':
		if (input[1]!=' ') {
			eprintf ("Usage: cx 001122'\n");
			return 0;
		}
		buf = (ut8*)malloc (strlen (input+2)+1);
		ret = r_hex_str2bin (input+2, buf);
		if (ret<1) eprintf ("Cannot parse hexpair\n");
		else val = radare_compare (core, core->block, buf, ret);
		free (buf);
		break;
	case 'X':
		buf = malloc (core->blocksize);
		ret = r_io_read_at (core->io, r_num_math (core->num, input+1),
			buf, core->blocksize);
		val = radare_compare (core, core->block, buf, ret);
		free (buf);
		break;
	case 'f':
		if (input[1]!=' ') {
			eprintf ("Please. use 'cf [file]'\n");
			return 0;
		}
		fd = r_sandbox_fopen (input+2, "rb");
		if (fd == NULL) {
			eprintf ("Cannot open file '%s'\n", input+2);
			return 0;
		}
		buf = (ut8 *)malloc (core->blocksize);
		fread (buf, 1, core->blocksize, fd);
		fclose (fd);
		val = radare_compare (core, core->block, buf, core->blocksize);
		free (buf);
		break;
	case 'd':
		while (input[1]==' ') input++;
		if (r_sandbox_chdir (input+1)==-1)
			eprintf ("Cannot chdir\n");
		break;
	case '2':
		v16 = (ut16) r_num_math (core->num, input+1);
		val = radare_compare (core, core->block, (ut8*)&v16, sizeof (v16));
		break;
	case '4':
		v32 = (ut32) r_num_math (core->num, input+1);
		val = radare_compare (core, core->block, (ut8*)&v32, sizeof (v32));
		break;
	case '8':
		v64 = (ut64) r_num_math (core->num, input+1);
		val = radare_compare (core, core->block, (ut8*)&v64, sizeof (v64));
		break;
#if 0
	case 'c':
		radare_compare_code (
			r_num_math (core->num, input+1),
			core->block, core->blocksize);
		break;
	case 'D':
		{ // XXX ugly hack
		char cmd[1024];
		sprintf (cmd, "radiff -b %s %s", ".curblock", input+2);
		r_file_dump (".curblock", config.block, config.block_size);
		radare_system(cmd);
		unlink(".curblock");
		}
		break;
#endif
	case 'c':
		{
		int col = core->cons->columns>123;
		ut8 *b = malloc (core->blocksize);
		ut64 addr = r_num_math (core->num, input+2);
		if (!b) return 0;
		memset (b, 0xff, core->blocksize);
		r_core_read_at (core, addr, b, core->blocksize);
		r_print_hexdiff (core->print, core->offset, core->block,
			addr, b, core->blocksize, col);
		free (b);
		}
		break;
	case 'g':
		{ // XXX: this is broken
			int diffops = 0;
		RCore *core2;
		char *file2 = NULL;
		if (input[1]=='o') {
			file2 = (char*)r_str_chop_ro (input+2);
			r_anal_diff_setup (core->anal, R_TRUE, -1, -1);
		} else
		if (input[1]==' ') {
			file2 = (char*)r_str_chop_ro (input+2);
			r_anal_diff_setup (core->anal, R_FALSE, -1, -1);
		} else {
			eprintf ("Usage: cg[o] [file]\n");
			eprintf (" cg  - byte-per-byte code graph diff\n");
			eprintf (" cgo - opcode-bytes code graph diff\n");
			return R_FALSE;
		}

		if (!(core2 = r_core_new ())) {
			eprintf ("Cannot init diff core\n");
			return R_FALSE;
		}
		r_core_loadlibs (core2, R_CORE_LOADLIBS_ALL, NULL);
		core2->io->va = core->io->va;
		core2->anal->split = core->anal->split;
		if (!r_core_file_open (core2, file2, 0, 0LL)) {
			eprintf ("Cannot open diff file '%s'\n", file2);
			r_core_free (core2);
			return R_FALSE;
		}
		// TODO: must replicate on core1 too
		r_config_set_i (core2->config, "io.va", R_TRUE);
		r_config_set_i (core2->config, "anal.split", R_TRUE);
                r_anal_diff_setup (core->anal, diffops, -1, -1);
                r_anal_diff_setup (core2->anal, diffops, -1, -1);

		r_core_bin_load (core2, file2,
			r_config_get_i (core->config, "bin.baddr"));
		r_core_gdiff (core, core2);
		r_core_diff_show (core, core2);
		r_core_free (core2);
		}
		break;
	case 'u':
		if (input[1] == ' ') {
			ut64 off = r_num_math (core->num, input+1);
			radare_compare_unified (core, core->offset, off,
				core->blocksize);
		} else {
			r_cons_strcat (
			"|Usage: cu [offset]  # creates a unified hex patch\n"
			"|  cu $$+1 > p       # compare current seek and +1\n"
			"|  wu p              # apply unified hex patch\n");
		}
		break;
	case '?':
		r_cons_strcat (
		"|Usage: c[?dfx] [argument]\n"
		"| c  [string]    Compares a plain with escaped chars string\n"
		"| cc [at] [(at)] Compares in two hexdump columns of block size\n"
		//"| cc [offset]   Code bindiff current block against offset\n"
		"| c4 [value]     Compare a doubleword from a math expression\n"
		//"| cD [file]     Like above, but using radiff -b\n");
		"| c8 [value]     Compare a quadword from a math expression\n"
		"| cx [hexpair]   Compare hexpair string\n"
		"| cX [addr]      Like 'cc' but using hexdiff output\n"
		"| cf [file]      Compare contents of file at current seek\n"
		"| cg[o] [file]   Graphdiff current file and [file]\n"
		"| cu [addr] @at  Compare memory hexdumps of $$ and dst in unified diff\n"
		"| cw[us?] [...]  Compare memory watchers\n"
		"| cat  [file]    Show contents of file (see pwd, ls)\n"
		"| cl|cls|clear   Clear screen, (clear0 to goto 0, 0 only)\n");
		break;
	case 'l':
		if (strchr (input, 'f')) {
			r_cons_flush();
		} else
		if (!strchr (input, '0')) {
			r_cons_clear ();
#if 0
write (1, "\x1b[2J", 4);
write (1, "\x1b[0;0H", 6);
write (1, "\x1b[0m", 4);
#endif
//r_cons_clear();
		}
		r_cons_gotoxy (0, 0);
//		r_cons_flush ();
		break;
	default:
		eprintf ("|Usage: c[?48cdDxfw] [argument]\n");
	}
	if (val != UT64_MAX)
		core->num->value = val;
	return 0;
}

