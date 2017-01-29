/* radare - LGPL - Copyright 2009-2015 - pancake */

#include "r_core.h"

static void showhelp(RCore *core) {
	const char* help_msg[] = {
		"Usage:", "c[?dfx] [argument]", " # Compare",
		"c", " [string]", "Compare a plain with escaped chars string",
		"c*", " [string]", "Compare a plain with escaped chars string (output r2 commands)",
		"c4", " [value]", "Compare a doubleword from a math expression",
		"c8", " [value]", "Compare a quadword from a math expression",
		"cat", " [file]", "Show contents of file (see pwd, ls)",
		"cc", " [at] [(at)]", "Compares in two hexdump columns of block size",
		"ccc", " [at] [(at)]", "Same as above, but only showing different lines",
		"ccd", " [at] [(at)]", "Compares in two disasm columns of block size",
		//"cc", " [offset]", "code bindiff current block against offset"
		//"cD", " [file]", "like above, but using radiff -b",
		"cf", " [file]", "Compare contents of file at current seek",
		"cg", "[?] [o] [file]","Graphdiff current file and [file]",
		"cl|cls|clear", "", "Clear screen, (clear0 to goto 0, 0 only)",
		"cu", "[?] [addr] @at", "Compare memory hexdumps of $$ and dst in unified diff",
		"cud", " [addr] @at", "Unified diff disasm from $$ and given address",
		"cv", "[1248] [addr] @at", "Compare 1,2,4,8-byte value",
		"cw", "[?] [us?] [...]", "Compare memory watchers",
		"cx", " [hexpair]", "Compare hexpair string (use '.' as nibble wildcard)",
		"cx*", " [hexpair]", "Compare hexpair string (output r2 commands)",
		"cX", " [addr]", "Like 'cc' but using hexdiff output",
		NULL
	};
	r_core_cmd_help (core, help_msg);
}
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
	if (size<1) return false;
	cmpw = r_core_cmpwatch_get (core, addr);
	if (!cmpw) {
		cmpw = R_NEW (RCoreCmpWatcher);
		if (!cmpw)
			return false;
		cmpw->addr = addr;
	}
	cmpw->size = size;
	snprintf (cmpw->cmd, sizeof (cmpw->cmd), "%s", cmd);
	cmpw->odata = NULL;
	cmpw->ndata = malloc (size);
	if (!cmpw->ndata) {
		free (cmpw);
		return false;
	}
	r_io_read_at (core->io, addr, cmpw->ndata, size);
	r_list_append (core->watchers, cmpw);
	return true;
}

R_API int r_core_cmpwatch_del (RCore *core, ut64 addr) {
	int ret = false;
	RCoreCmpWatcher *w;
	RListIter *iter, *iter2;
	r_list_foreach_safe (core->watchers, iter, iter2, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			r_list_delete (core->watchers, iter);
			ret = true;
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
	return false;
}

R_API int r_core_cmpwatch_update (RCore *core, ut64 addr) {
	RCoreCmpWatcher *w;
	RListIter *iter;
	r_list_foreach (core->watchers, iter, w) {
		free (w->odata);
		w->odata = w->ndata;
		w->ndata = malloc (w->size);
		if (!w->ndata)
			return false;
		r_io_read_at (core->io, w->addr, w->ndata, w->size);
	}
	return !r_list_empty (core->watchers);
}

R_API int r_core_cmpwatch_revert (RCore *core, ut64 addr) {
	RCoreCmpWatcher *w;
	int ret = false;
	RListIter *iter;
	r_list_foreach (core->watchers, iter, w) {
		if (w->addr == addr || addr == UT64_MAX) {
			if (w->odata) {
				free (w->ndata);
				w->ndata = w->odata;
				w->odata = NULL;
				ret = true;
			}
		}
	}
	return ret;
}

static int radare_compare_unified(RCore *core, ut64 of, ut64 od, int len) {
	int i, min, inc = 16;
	ut8 *f, *d;
	if (len<1)
		return false;
	f = malloc (len);
	if (!f)
		return false;
	d = malloc (len);
	if (!d) {
		free (f);
		return false;
	}
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
	return true;
}

static int radare_compare(RCore *core, const ut8 *f, const ut8 *d, int len, int mode) {
	int i, eq = 0;
	if (len < 1)
		return 0;
	for (i=0; i<len; i++) {
		if (f[i]==d[i]) {
			eq++;
			continue;
		}
		switch (mode)
		{
			case 0:
				r_cons_printf ("0x%08"PFMT64x" (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n",
						core->offset+i, i+1,
						f[i], (IS_PRINTABLE(f[i]))?f[i]:' ',
						d[i], (IS_PRINTABLE(d[i]))?d[i]:' ');
				break;
			case '*':
				r_cons_printf ("wx %02x @ 0x%08"PFMT64x"\n",
						d[i],
						core->offset+i);
				break;

		}
	}
	if (mode == 0)
		eprintf ("Compare %d/%d equal bytes (%d%%)\n", eq, len, (eq / len) * 100);
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
	case '?': {
			const char * help_message[] = {
				"Usage: cw", "", "Watcher commands",
				"cw", "", "List all compare watchers",
				"cw", " addr", "List all compare watchers",
				"cw", " addr sz cmd", "Add a memory watcher",
				//"cws", " [addr]", "Show watchers",
				"cw", "*", "List compare watchers in r2 cmds",
				"cwr", " [addr]", "Reset/revert watchers",
				"cwu", " [addr]", "Update watchers",
				NULL
			};
			r_core_cmd_help(core, help_message);
		}
		break;
	}
}

static int cmd_cmp_disasm(RCore *core, const char *input, int mode) {
	RAsmOp op, op2;
	int i, j, iseq;
	char colpad[80];
	int hascolor = r_config_get_i (core->config, "scr.color");
	int cols = r_config_get_i (core->config, "hex.cols") * 2;
	ut64 off = r_num_math (core->num, input);
	ut8 *buf = calloc (core->blocksize+32, 1);
	if (!buf) return false;
	r_core_read_at (core, off, buf, core->blocksize+32);
	switch (mode) {
	case 'c': // columns
		for (i=j=0; i<core->blocksize && j<core->blocksize; ) {
			// dis A
			r_asm_set_pc (core->assembler, core->offset+i);
			(void)r_asm_disassemble (core->assembler, &op,
				core->block+i, core->blocksize-i);

			// dis B
			r_asm_set_pc (core->assembler, off+i);
			(void)r_asm_disassemble (core->assembler, &op2,
				buf+j, core->blocksize-j);

			// show output
			iseq = (!strcmp (op.buf_asm, op2.buf_asm));
			memset (colpad, ' ', sizeof(colpad));
			{
			int pos = strlen (op.buf_asm);
			pos = (pos>cols)? 0: cols-pos;
			colpad[pos] = 0;
			}
			if (hascolor) {
				r_cons_printf (iseq?Color_GREEN:Color_RED);
			}
			r_cons_printf (" 0x%08"PFMT64x"  %s %s",
				core->offset +i, op.buf_asm, colpad);
			r_cons_printf ("%c 0x%08"PFMT64x"  %s\n",
				iseq?'=':'!', off+j, op2.buf_asm);
			if (hascolor) {
				r_cons_printf (Color_RESET);
			}
			if (op.size<1) op.size =1;
			i+= op.size;
			if (op2.size<1) op2.size =1;
			j+= op2.size;
		}
		break;
	case 'u': // unified
		for (i=j=0; i< core->blocksize && j<core->blocksize; ) {
			// dis A
			r_asm_set_pc (core->assembler, core->offset+i);
			(void)r_asm_disassemble (core->assembler, &op,
				core->block+i, core->blocksize-i);

			// dis B
			r_asm_set_pc (core->assembler, off+i);
			(void)r_asm_disassemble (core->assembler, &op2,
				buf+j, core->blocksize-j);

			// show output
			iseq = (!strcmp (op.buf_asm, op2.buf_asm));
			if (iseq) {
				r_cons_printf (" 0x%08"PFMT64x"  %s\n",
					core->offset +i, op.buf_asm);
			} else {
				if (hascolor)
					r_cons_printf (Color_RED);
				r_cons_printf ("-0x%08"PFMT64x"  %s\n",
					core->offset +i, op.buf_asm);
				if (hascolor)
					r_cons_printf (Color_GREEN);
				r_cons_printf ("+0x%08"PFMT64x"  %s\n",
					off+j, op2.buf_asm);
				if (hascolor)
					r_cons_printf (Color_RESET);
			}
			if (op.size < 1) {
				op.size = 1;
			}
			i += op.size;
			if (op2.size < 1) {
				op2.size = 1;
			}
			j += op2.size;
		}
		break;
	}
	return 0;
}

static int cmd_cp(void *data, const char *input) {
	char *src, *dst;
	if (strlen (input) < 3) {
		eprintf ("Usage: cp src dst\n");
		return false;
	}
	src = strdup (input + 2);
	dst = strchr (src, ' ');
	if (dst) {
		*dst++ = 0;
		bool rc = r_file_copy (src, dst);
		free (src);
		return rc;
	}
	eprintf ("Usage: cp src dst\n");
	free (src);
	return false;
}

static int cmd_cmp(void *data, const char *input) {
	static char *oldcwd = NULL;
	int ret, i, mode = 0;
	RCore *core = data;
	ut64 val = UT64_MAX;
	char * filled;
	ut8 *buf;
	ut16 v16;
	ut32 v32;
	ut64 v64;
	FILE *fd;

	switch (*input) {
	case 'p':
		return cmd_cp (data, input);
		break;
	case 'a':
		if (input[1] == 't') {
			char *res = r_syscmd_cat (input + 1);
			if (res) {
				r_cons_print (res);
				free (res);
			}
		}
		break;
	case 'w': cmd_cmp_watcher (core, input+1); break;
	case '*':
		if (!input[2]) {
			eprintf ("Usage: cx* 00..22'\n");
			return 0;
		}

		val = radare_compare (core, core->block, (ut8*)input + 2,
			strlen (input + 2) + 1, '*');
		break;
	case ' ':
		{
			char *str = strdup (input + 1);
			int len = r_str_unescape (str);
			val = radare_compare (core, core->block, (ut8*)str, len, 0);
			free (str);
		}
		break;
	case 'x':
		switch (input[1]) {
		case ' ':
			mode = 0;
			input += 2;
			break;
		case '*':
			if (input[2] != ' ') {
				eprintf ("Usage: cx* 00..22'\n");
				return 0;
			}
			mode = '*';
			input += 3;
			break;
		default:
			eprintf ("Usage: cx 00..22'\n");
			return 0;
		}
		if (!(filled = (char*) malloc (strlen (input) + 1))) {
			return false;
		}
		memcpy (filled, input, strlen (input) + 1);
		if (!(buf = (ut8*)malloc (strlen (input) + 1))) {
			free (filled);
			return false;
		}
		ret = r_hex_bin2str (core->block, strlen (input) / 2, (char *)buf);
		for (i = 0; i < ret * 2; i++) {
			if (filled[i] == '.') {
				filled[i] = buf[i];
			}
		}

		ret = r_hex_str2bin (filled, buf);
		if (ret < 1) {
			eprintf ("Cannot parse hexpair\n");
		} else {
			val = radare_compare (core, core->block, buf, ret, mode);
		}
		free (buf);
		free (filled);
		break;
	case 'X':
		buf = malloc (core->blocksize);
		if (buf) {
			if (!r_io_read_at (core->io, r_num_math (core->num,
				input+1), buf, core->blocksize))
					eprintf ("Cannot read hexdump\n");
			val = radare_compare (core, core->block, buf, ret, 0);
			free (buf);
		} return false;
		break;
	case 'f':
		if (input[1]!=' ') {
			eprintf ("Please. use 'cf [file]'\n");
			return 0;
		}
		fd = r_sandbox_fopen (input+2, "rb");
		if (!fd) {
			eprintf ("Cannot open file '%s'\n", input+2);
			return 0;
		}
		buf = (ut8 *)malloc (core->blocksize);
		if (buf) {
			if (fread (buf, 1, core->blocksize, fd) <1) {
				eprintf ("Cannot read file %s\n", input + 2);
			} else val = radare_compare (core, core->block,
				buf, core->blocksize, 0);
			fclose (fd);
			free (buf);
		} else {
			fclose (fd);
			return false;
		}
		break;
	case 'd':
		while (input[1]==' ') input++;
		if (input[1]) {
			if (!strcmp (input+1, "-")) {
				if (oldcwd) {
					char *newdir = oldcwd;
					oldcwd = r_sys_getdir ();
					if (r_sandbox_chdir (newdir)==-1) {
						eprintf ("Cannot chdir to %s\n", newdir);
						free (oldcwd);
						oldcwd = newdir;
					} else {
						free (newdir);
					}
				} else {
					// nothing to do here
				}
			} else if (input[1]=='~' && input[2]=='/') {
				char *homepath = r_str_home (input+3);
				if (homepath) {
					if (*homepath) {
						free (oldcwd);
						oldcwd = r_sys_getdir ();
						if (r_sandbox_chdir (homepath)==-1)
							eprintf ("Cannot chdir to %s\n", homepath);
					}
					free (homepath);
				} else eprintf ("Cannot find home\n");
			} else {
				free (oldcwd);
				oldcwd = r_sys_getdir ();
				if (r_sandbox_chdir (input+1)==-1) {
					eprintf ("Cannot chdir to %s\n", input+1);
				}
			}
		} else {
			char* home = r_sys_getenv (R_SYS_HOME);
			if (!home || r_sandbox_chdir (home) == -1) {
				eprintf ("Cannot find home.\n");
			}
			free (home);
		}
		break;
	case '2':
		v16 = (ut16) r_num_math (core->num, input+1);
		val = radare_compare (core, core->block, (ut8*)&v16, sizeof (v16), 0);
		break;
	case '4':
		v32 = (ut32) r_num_math (core->num, input+1);
		val = radare_compare (core, core->block, (ut8*)&v32, sizeof (v32), 0);
		break;
	case '8':
		v64 = (ut64) r_num_math (core->num, input+1);
		val = radare_compare (core, core->block, (ut8*)&v64, sizeof (v64), 0);
		break;
	case 'c': // "cc"
		if (input[1] == 'd') {
			cmd_cmp_disasm (core, input+2, 'c');
		} else {
			ut32 oflags = core->print->flags;
			ut64 addr = 0; // TOTHINK: Not sure what default address should be
			if (input[1]=='c') { // "ccc"
				core->print->flags |= R_PRINT_FLAGS_DIFFOUT;
				addr = r_num_math (core->num, input+2);
			} else {
				if (*input && input[1])
					addr = r_num_math (core->num, input+2);
			}
			int col = core->cons->columns>123;
			ut8 *b = malloc (core->blocksize);
			if (b != NULL) {
				memset (b, 0xff, core->blocksize);
				r_core_read_at (core, addr, b, core->blocksize);
				r_print_hexdiff (core->print, core->offset, core->block,
						addr, b, core->blocksize, col);
				free (b);
			}
			core->print->flags = oflags;
		}
		break;
	case 'g': // "cg"
		 { // XXX: this is broken
			int diffops = 0;
			RCore *core2;
			char *file2 = NULL;
			switch (input[1]) {
			case 'o': // "cgo"
				file2 = (char*)r_str_chop_ro (input+2);
				r_anal_diff_setup (core->anal, true, -1, -1);
				break;
			case 'f': // "cgf"
				eprintf ("TODO: agf is experimental\n");
				r_anal_diff_setup (core->anal, true, -1, -1);
				r_core_gdiff_fcn (core, core->offset,
					r_num_math (core->num, input +2));
				return false;
			case ' ':
				file2 = (char*)r_str_chop_ro (input+2);
				r_anal_diff_setup (core->anal, false, -1, -1);
				break;
			default: {
				const char * help_message[] = {
				"Usage: cg", "", "Graph code commands",
				"cg",  "", "diff ratio among functions (columns: off-A, match-ratio, off-B)",
				"cgf", "[fcn]", "Compare functions (curseek vs fcn)",
				"cgo", "", "Opcode-bytes code graph diff",
				NULL
				};
				r_core_cmd_help(core, help_message);
				return false;
				}
			}

			if (r_file_size (file2) <= 0) {
				eprintf ("Cannot compare with file %s\n", file2);
				return false;
			}

			if (!(core2 = r_core_new ())) {
				eprintf ("Cannot init diff core\n");
				return false;
			}
			r_core_loadlibs (core2, R_CORE_LOADLIBS_ALL, NULL);
			core2->io->va = core->io->va;
			core2->anal->split = core->anal->split;
			if (!r_core_file_open (core2, file2, 0, 0LL)) {
				eprintf ("Cannot open diff file '%s'\n", file2);
				r_core_free (core2);
				return false;
			}
			// TODO: must replicate on core1 too
			r_config_set_i (core2->config, "io.va", true);
			r_config_set_i (core2->config, "anal.split", true);
			r_anal_diff_setup (core->anal, diffops, -1, -1);
			r_anal_diff_setup (core2->anal, diffops, -1, -1);

			r_core_bin_load (core2, file2,
				r_config_get_i (core->config, "bin.baddr"));
			r_core_gdiff (core, core2);
			r_core_diff_show (core, core2);
			/* exchange a segfault with a memleak */
			core2->config = NULL;
			r_core_free (core2);
		 }
		break;
	case 'u':
		switch (input[1]) {
		case ' ':
			radare_compare_unified (core, core->offset,
				r_num_math (core->num, input+1),
				core->blocksize);
			break;
		case 'd':
			cmd_cmp_disasm (core, input+2, 'u');
			break;
		default: {
			const char* help_msg[] = {
			"Usage: cu",  " [offset]", "# Creates a unified hex patch",
			"cu", " $$+1 > p", "Compare current seek and +1",
			"cud", " $$+1 > p", "Compare disasm current seek and +1",
			"wu", " p", "Apply unified hex patch",
			NULL};
			r_core_cmd_help (core, help_msg); }
		}
		break;
	case '?':
		showhelp (core);
		break;
	case 'v': // "cv"
		{
		int sz = input[1];
		if (sz== ' ') {
			switch (r_config_get_i (core->config, "asm.bits")) {
			case 8: sz = '1'; break;
			case 16: sz = '2'; break;
			case 32: sz = '4'; break;
			case 64: sz = '8'; break;
			default: sz = '4'; break; // default
			}
		}
		// TODO: honor endian
		switch (sz) {
		case '1':
			{ ut8 n = (ut8)r_num_math (core->num, input+2);
			if (core->block[0] == n) r_cons_printf ("0x%08"PFMT64x"\n", core->offset); }
			break;
		case '2':
			{ ut16 *b = (ut16*)core->block, n = (ut16)r_num_math (core->num, input+2);
			if (*b == n) r_cons_printf ("0x%08"PFMT64x"\n", core->offset); }
			break;
		case '4':
			{ ut32 *b = (ut32*)core->block, n = (ut32)r_num_math (core->num, input+2);
			if (*b == n) r_cons_printf ("0x%08"PFMT64x"\n", core->offset); }
			break;
		case '8':
			{ ut64 *b = (ut64*)core->block, n = (ut64)r_num_math (core->num, input+2);
			if (*b == n) r_cons_printf ("0x%08"PFMT64x"\n", core->offset); }
			break;
		default:
		case '?':
			eprintf ("Usage: cv[1248] [num]\n"
			"Show offset if current value equals to the one specified\n"
			" /v 18312   # serch for a known value\n"
			" dc\n"
			" cv4 18312 @@ hit*\n"
			" dc\n");
			break;
		}
		}
		break;
	case 'l':
		if (strchr (input, 'f')) {
			r_cons_flush();
		} else if (!strchr (input, '0')) {
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
		showhelp (core);
	}
	if (val != UT64_MAX)
		core->num->value = val;
	return 0;
}

