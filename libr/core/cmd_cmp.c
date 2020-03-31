/* radare - LGPL - Copyright 2009-2019 - pancake */

#include "r_core.h"

static const char *help_msg_c[] = {
	"Usage:", "c[?dfx] [argument]", " # Compare",
	"c", " [string]", "Compare a plain with escaped chars string",
	"c*", " [string]", "Same as above, but printing r2 commands instead",
	"c1", " [addr]", "Compare 8 bits from current offset",
	"c2", " [value]", "Compare a word from a math expression",
	"c4", " [value]", "Compare a doubleword from a math expression",
	"c8", " [value]", "Compare a quadword from a math expression",
	"cat", " [file]", "Show contents of file (see pwd, ls)",
	"cc", " [at]", "Compares in two hexdump columns of block size",
	"ccc", " [at]", "Same as above, but only showing different lines",
	"ccd", " [at]", "Compares in two disasm columns of block size",
	"ccdd", " [at]", "Compares decompiler output (e cmd.pdc=pdg|pdd)",
	// "cc", " [offset]", "code bindiff current block against offset"
	// "cD", " [file]", "like above, but using radiff -b",
	"cf", " [file]", "Compare contents of file at current seek",
	"cg", "[?] [o] [file]", "Graphdiff current file and [file]",
	"cu", "[?] [addr] @at", "Compare memory hexdumps of $$ and dst in unified diff",
	"cud", " [addr] @at", "Unified diff disasm from $$ and given address",
	"cv", "[1248] [hexpairs] @at", "Compare 1,2,4,8-byte (silent return in $?)",
	"cV", "[1248] [addr] @at", "Compare 1,2,4,8-byte address contents (silent, return in $?)",
	"cw", "[?] [us?] [...]", "Compare memory watchers",
	"cx", " [hexpair]", "Compare hexpair string (use '.' as nibble wildcard)",
	"cx*", " [hexpair]", "Compare hexpair string (output r2 commands)",
	"cX", " [addr]", "Like 'cc' but using hexdiff output",
	"", "", "",
	"cd", " [dir]", "chdir",
	"cl|cls|clear", "", "Clear screen, (clear0 to goto 0, 0 only)",
	NULL
};

static void cmd_cmp_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, c);
}

R_API void r_core_cmpwatch_free(RCoreCmpWatcher *w) {
	free (w->ndata);
	free (w->odata);
	free (w);
}

R_API RCoreCmpWatcher *r_core_cmpwatch_get(RCore *core, ut64 addr) {
	RListIter *iter;
	RCoreCmpWatcher *w;
	r_list_foreach (core->watchers, iter, w) {
		if (addr == w->addr) {
			return w;
		}
	}
	return NULL;
}

R_API int r_core_cmpwatch_add(RCore *core, ut64 addr, int size, const char *cmd) {
	RCoreCmpWatcher *cmpw;
	if (size < 1) {
		return false;
	}
	cmpw = r_core_cmpwatch_get (core, addr);
	if (!cmpw) {
		cmpw = R_NEW (RCoreCmpWatcher);
		if (!cmpw) {
			return false;
		}
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

R_API int r_core_cmpwatch_del(RCore *core, ut64 addr) {
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

R_API int r_core_cmpwatch_show(RCore *core, ut64 addr, int mode) {
	char cmd[128];
	RListIter *iter;
	RCoreCmpWatcher *w;
	r_list_foreach (core->watchers, iter, w) {
		int is_diff = w->odata? memcmp (w->odata, w->ndata, w->size): 0;
		switch (mode) {
		case '*':
			r_cons_printf ("cw 0x%08"PFMT64x " %d %s%s\n",
				w->addr, w->size, w->cmd, is_diff? " # differs": "");
			break;
		case 'd': // diff
			if (is_diff) {
				r_cons_printf ("0x%08"PFMT64x " has changed\n", w->addr);
			}
		case 'o': // old contents
		// use tmpblocksize
		default:
			r_cons_printf ("0x%08"PFMT64x "%s\n", w->addr, is_diff? " modified": "");
			snprintf (cmd, sizeof (cmd), "%s@%"PFMT64d "!%d",
				w->cmd, w->addr, w->size);
			r_core_cmd0 (core, cmd);
			break;
		}
	}
	return false;
}

R_API int r_core_cmpwatch_update(RCore *core, ut64 addr) {
	RCoreCmpWatcher *w;
	RListIter *iter;
	r_list_foreach (core->watchers, iter, w) {
		free (w->odata);
		w->odata = w->ndata;
		w->ndata = malloc (w->size);
		if (!w->ndata) {
			return false;
		}
		r_io_read_at (core->io, w->addr, w->ndata, w->size);
	}
	return !r_list_empty (core->watchers);
}

R_API int r_core_cmpwatch_revert(RCore *core, ut64 addr) {
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

static int radare_compare_words(RCore *core, ut64 of, ut64 od, int len, int ws) {
	int i;
	bool useColor = r_config_get_i (core->config, "scr.color") != 0;
	utAny v0, v1;
	RConsPrintablePalette *pal = &r_cons_singleton ()->context->pal;
	for (i = 0; i < len; i+=ws) {
		memset (&v0, 0, sizeof (v0));
		memset (&v1, 0, sizeof (v1));
		r_io_read_at (core->io, of + i, (ut8*)&v0, ws);
		r_io_read_at (core->io, od + i, (ut8*)&v1, ws);
		char ch = (v0.v64 == v1.v64)? '=': '!';
		const char *color = useColor? ch == '='? "": pal->graph_false: "";
		const char *colorEnd = useColor? Color_RESET: "";

		if (useColor) {
			r_cons_printf ("%s0x%08" PFMT64x"  "Color_RESET, pal->offset, of + i);
		} else {
			r_cons_printf ("0x%08" PFMT64x"  ", of + i);
		}
		switch (ws) {
		case 1:
			r_cons_printf ("%s0x%02x %c 0x%02x%s\n", color,
				(ut32)(v0.v8 & 0xff), ch, (ut32)(v1.v8 & 0xff), colorEnd);
			break;
		case 2:
			r_cons_printf ("%s0x%04hx %c 0x%04hx%s\n", color,
				v0.v16, ch, v1.v16, colorEnd);
			break;
		case 4:
			r_cons_printf ("%s0x%08"PFMT32x" %c 0x%08"PFMT32x"%s\n", color,
				v0.v32, ch, v1.v32, colorEnd);
			//r_core_cmdf (core, "fd@0x%"PFMT64x, v0.v32);
			if (v0.v32 != v1.v32) {
			//	r_core_cmdf (core, "fd@0x%"PFMT64x, v1.v32);
			}
			break;
		case 8:
			r_cons_printf ("%s0x%016"PFMT64x" %c 0x%016"PFMT64x"%s\n",
				color, v0.v64, ch, v1.v64, colorEnd);
			//r_core_cmdf (core, "fd@0x%"PFMT64x, v0.v64);
			if (v0.v64 != v1.v64) {
			//	r_core_cmdf (core, "fd@0x%"PFMT64x, v1.v64);
			}
			break;
		}
	}
	return 0;
}

static int radare_compare_unified(RCore *core, ut64 of, ut64 od, int len) {
	int i, min, inc = 16;
	ut8 *f, *d;
	if (len < 1) {
		return false;
	}
	f = malloc (len);
	if (!f) {
		return false;
	}
	d = malloc (len);
	if (!d) {
		free (f);
		return false;
	}
	r_io_read_at (core->io, of, f, len);
	r_io_read_at (core->io, od, d, len);
	int headers = B_IS_SET (core->print->flags, R_PRINT_FLAGS_HEADER);
	if (headers) {
		B_UNSET (core->print->flags, R_PRINT_FLAGS_HEADER);
	}
	for (i = 0; i < len; i += inc) {
		min = R_MIN (16, (len - i));
		if (!memcmp (f + i, d + i, min)) {
			r_cons_printf ("  ");
			r_print_hexdiff (core->print, of + i, f + i, of + i, f + i, min, 0);
		} else {
			r_cons_printf ("- ");
			r_print_hexdiff (core->print, of + i, f + i, od + i, d + i, min, 0);
			r_cons_printf ("+ ");
			r_print_hexdiff (core->print, od + i, d + i, of + i, f + i, min, 0);
		}
	}
	if (headers) {
		B_SET (core->print->flags, R_PRINT_FLAGS_HEADER);
	}
	return true;
}

static int radare_compare(RCore *core, const ut8 *f, const ut8 *d, int len, int mode) {
	int i, eq = 0;
	PJ *pj = NULL;
	if (len < 1) {
		return 0;
	}
	if (mode == 'j') {
		pj = pj_new ();
		if (!pj) {
			return -1;
		}
		pj_o (pj);
		pj_k (pj, "diff_bytes");
		pj_a (pj);
	}
	for (i = 0; i < len; i++) {
		if (f[i] == d[i]) {
			eq++;
			continue;
		}
		switch (mode)
		{
		case 0:
			r_cons_printf ("0x%08"PFMT64x " (byte=%.2d)   %02x '%c'  ->  %02x '%c'\n",
				core->offset + i, i + 1,
				f[i], (IS_PRINTABLE (f[i]))? f[i]: ' ',
				d[i], (IS_PRINTABLE (d[i]))? d[i]: ' ');
			break;
		case '*':
			r_cons_printf ("wx %02x @ 0x%08"PFMT64x "\n",
				d[i],
				core->offset + i);
			break;
		case 'j':
			pj_o (pj);
			pj_kn (pj, "offset", core->offset + i);
			pj_ki (pj, "rel_offset", i);
			pj_ki (pj, "value", (int)f[i]);
			pj_ki (pj, "cmp_value", (int)d[i]);
			pj_end (pj);
			break;

		}
	}
	if (mode == 0) {
		eprintf ("Compare %d/%d equal bytes (%d%%)\n", eq, len, (eq / len) * 100);
	} else if (mode == 'j') {
		pj_end (pj);
		pj_ki (pj, "equal_bytes", eq);
		pj_ki (pj, "total_bytes", len);
		pj_end (pj); // End array
		pj_end (pj); // End object
		r_cons_println (pj_string (pj));
	}
	return len - eq;
}

static void cmd_cmp_watcher(RCore *core, const char *input) {
	char *p, *q, *r = NULL;
	int size = 0;
	ut64 addr = 0;
	switch (*input) {
	case ' ':
		p = strdup (input + 1);
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
			// eprintf ("ADD (%llx) %d (%s)\n", addr, size, r);
		} else {
			eprintf ("Missing parameters\n");
		}
		free (p);
		break;
	case 'r':
		addr = input[1]? r_num_math (core->num, input + 1): UT64_MAX;
		r_core_cmpwatch_revert (core, addr);
		break;
	case 'u':
		addr = input[1]? r_num_math (core->num, input + 1): UT64_MAX;
		r_core_cmpwatch_update (core, addr);
		break;
	case '*':
		r_core_cmpwatch_show (core, UT64_MAX, '*');
		break;
	case '\0':
		r_core_cmpwatch_show (core, UT64_MAX, 0);
		break;
	case '?': {
		const char *help_message[] = {
			"Usage: cw", "", "Watcher commands",
			"cw", "", "List all compare watchers",
			"cw", " addr", "List all compare watchers",
			"cw", " addr sz cmd", "Add a memory watcher",
			// "cws", " [addr]", "Show watchers",
			"cw", "*", "List compare watchers in r2 cmds",
			"cwr", " [addr]", "Reset/revert watchers",
			"cwu", " [addr]", "Update watchers",
			NULL
		};
		r_core_cmd_help (core, help_message);
	}
		  break;
	}
}

static int cmd_cmp_disasm(RCore *core, const char *input, int mode) {
	RAsmOp op, op2;
	int i, j;
	char colpad[80];
	int hascolor = r_config_get_i (core->config, "scr.color");
	int cols = r_config_get_i (core->config, "hex.cols") * 2;
	ut64 off = r_num_math (core->num, input);
	ut8 *buf = calloc (core->blocksize + 32, 1);
	RConsPrintablePalette *pal = &r_cons_singleton ()->context->pal;
	if (!buf) {
		return false;
	}
	r_io_read_at (core->io, off, buf, core->blocksize + 32);
	switch (mode) {
	case 'd': // decompiler
		{
#if 0
		char *a = r_core_cmd_strf (core, "pdc @ 0x%"PFMT64x, off);
		char *b = r_core_cmd_strf (core, "pdc @ 0x%"PFMT64x, core->offset);
		RDiff *d = r_diff_new ();
		char *s = r_diff_buffers_unified (d, a, strlen(a), b, strlen(b));
		r_cons_printf ("%s\n", s);
		free (a);
		free (b);
		free (s);
		r_diff_free (d);
#else
		r_core_cmdf (core, "pdc @ 0x%"PFMT64x">$a", off);
		r_core_cmdf (core, "pdc @ 0x%"PFMT64x">$b", core->offset);
		r_core_cmd0 (core, "diff $a $b;rm $a;rm $b");
#endif
		}
		break;
	case 'c': // columns
		for (i = j = 0; i < core->blocksize && j < core->blocksize;) {
			// dis A
			r_asm_set_pc (core->assembler, core->offset + i);
			(void) r_asm_disassemble (core->assembler, &op,
				core->block + i, core->blocksize - i);

			// dis B
			r_asm_set_pc (core->assembler, off + i);
			(void) r_asm_disassemble (core->assembler, &op2,
				buf + j, core->blocksize - j);

			// show output
			bool iseq = r_strbuf_equals (&op.buf_asm, &op2.buf_asm);
			memset (colpad, ' ', sizeof (colpad));
			{
				int pos = strlen (r_strbuf_get (&op.buf_asm));
				pos = (pos > cols)? 0: cols - pos;
				colpad[pos] = 0;
			}
			if (hascolor) {
				r_cons_printf (iseq? pal->graph_true: pal->graph_false);
			}
			r_cons_printf (" 0x%08"PFMT64x "  %s %s",
				core->offset + i, r_strbuf_get (&op.buf_asm), colpad);
			r_cons_printf ("%c 0x%08"PFMT64x "  %s\n",
				iseq? '=': '!', off + j, r_strbuf_get (&op2.buf_asm));
			if (hascolor) {
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
	case 'u': // unified
		for (i = j = 0; i < core->blocksize && j < core->blocksize;) {
			// dis A
			r_asm_set_pc (core->assembler, core->offset + i);
			(void) r_asm_disassemble (core->assembler, &op,
				core->block + i, core->blocksize - i);

			// dis B
			r_asm_set_pc (core->assembler, off + i);
			(void) r_asm_disassemble (core->assembler, &op2,
				buf + j, core->blocksize - j);

			// show output
			bool iseq = r_strbuf_equals (&op.buf_asm, &op2.buf_asm); // (!strcmp (op.buf_asm, op2.buf_asm));
			if (iseq) {
				r_cons_printf (" 0x%08"PFMT64x "  %s\n",
					core->offset + i, r_strbuf_get (&op.buf_asm));
			} else {
				if (hascolor) {
					r_cons_printf (pal->graph_false);
				}
				r_cons_printf ("-0x%08"PFMT64x "  %s\n",
					core->offset + i, r_strbuf_get (&op.buf_asm));
				if (hascolor) {
					r_cons_printf (pal->graph_true);
				}
				r_cons_printf ("+0x%08"PFMT64x "  %s\n",
					off + j, r_strbuf_get (&op2.buf_asm));
				if (hascolor) {
					r_cons_printf (Color_RESET);
				}
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
	RCore *core = (RCore *)data;
	if (input[1] == '.') {
		char *file = r_core_cmd_strf (core, "ij~{core.file}");
		r_str_trim (file);
		char *newfile = r_str_newf ("%s.%s", file, input + 2);
		r_file_copy (file, newfile);
		free (file);
		free (newfile);
		return true;
	}
	if (strlen (input) < 3) {
		eprintf ("Usage: cp src dst\n");
		eprintf ("Usage: cp.orig  # cp $file $file.orig\n");
		return false;
	}
	char *cmd = strdup (input + 2);
	if (cmd) {
		char **files = r_str_argv (cmd, NULL);
		if (files[0] && files[1]) {
			bool rc = r_file_copy (files[0], files[1]);
			free (cmd);
			r_str_argv_free (files);
			return rc;
		}
		r_str_argv_free (files);
	}
	eprintf ("Usage: cp src dst\n");
	return false;
}

static void __core_cmp_bits (RCore *core, ut64 addr) {
	const bool scr_color = r_config_get_i (core->config, "scr.color");
	int i;
	ut8 a, b;
	r_io_read_at (core->io, core->offset, &a, 1);
	r_io_read_at (core->io, addr, &b, 1);
	RConsPrintablePalette *pal = &r_cons_singleton ()->context->pal;
	const char *color = scr_color? pal->offset: "";
	const char *color_end = scr_color? Color_RESET: "";
	if (r_config_get_i (core->config, "hex.header")) {
		char *n = r_str_newf ("0x%08"PFMT64x, core->offset);
		const char *extra = r_str_pad (' ', strlen (n) - 10);
		free (n);
		r_cons_printf ("%s- offset -%s  7 6 5 4 3 2 1 0%s\n", color, extra, color_end);
	}
	color = scr_color? pal->graph_false: "";
	color_end = scr_color? Color_RESET: "";

	r_cons_printf ("%s0x%08"PFMT64x"%s  ", color, core->offset, color_end);
	for (i = 7; i >= 0; i--) {
		bool b0 = (a & 1<<i)? 1: 0;
		bool b1 = (b & 1<<i)? 1: 0;
		color = scr_color? (b0 == b1)? "": b0? pal->graph_true:pal->graph_false: "";
		color_end = scr_color ? Color_RESET: "";
		r_cons_printf ("%s%d%s ", color, b0, color_end);
	}
	color = scr_color? pal->graph_true: "";
	color_end = scr_color? Color_RESET: "";
	r_cons_printf ("\n%s0x%08"PFMT64x"%s  ", color, addr, color_end);
	for (i = 7; i >= 0; i--) {
		bool b0 = (a & 1<<i)? 1: 0;
		bool b1 = (b & 1<<i)? 1: 0;
		color = scr_color? (b0 == b1)? "": b1? pal->graph_true: pal->graph_false: "";
		color_end = scr_color ? Color_RESET: "";
		r_cons_printf ("%s%d%s ", color, b1, color_end);
	}
	r_cons_newline ();
}

static int cmd_cmp(void *data, const char *input) {
	static char *oldcwd = NULL;
	int ret = 0, i, mode = 0;
	RCore *core = (RCore *)data;
	ut64 val = UT64_MAX;
	char *filled;
	ut8 *buf;
	ut16 v16;
	ut32 v32;
	ut64 v64;
	FILE *fd;
	const ut8* block = core->block;

	switch (*input) {
	case 'p':
		return cmd_cp (data, input);
		break;
	case 'a': // "cat"
		if (input[1] == 't') {
			const char *path = r_str_trim_head_ro (input + 2);
			if (*path == '$') {
				const char *oldText = r_cmd_alias_get (core->rcmd, path, 1);
				if (oldText) {
					r_cons_printf ("%s\n", oldText + 1);
				}
			} else {
				if (r_fs_check (core->fs, path)) {
					r_core_cmdf (core, "mg %s", path);
				} else {
					char *res = r_syscmd_cat (path);
					if (res) {
						r_cons_print (res);
						free (res);
					}
				}
			}
		}
		break;
	case 'w':
		cmd_cmp_watcher (core, input + 1);
		break;
	case '*':
		if (!input[2]) {
			eprintf ("Usage: cx* 00..22'\n");
			return 0;
		}

		val = radare_compare (core, block, (ut8 *) input + 2,
			strlen (input + 2) + 1, '*');
		break;
	case ' ':
	{
		char *str = strdup (input + 1);
		int len = r_str_unescape (str);
		val = radare_compare (core, block, (ut8 *) str, len, 0);
		free (str);
	}
	break;
	case 'j':
	{
		if (input[1] != ' ') {
			eprintf ("Usage: cj [string]\n");
		} else {
			char *str = strdup (input + 2);
			int len = r_str_unescape (str);
			val = radare_compare (core, block, (ut8 *) str, len, 'j');
			free (str);
		}
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
		if (!(filled = (char *) malloc (strlen (input) + 1))) {
			return false;
		}
		memcpy (filled, input, strlen (input) + 1);
		if (!(buf = (ut8 *) malloc (strlen (input) + 1))) {
			free (filled);
			return false;
		}
		ret = r_hex_bin2str (block, strlen (input) / 2, (char *) buf);
		for (i = 0; i < ret * 2; i++) {
			if (filled[i] == '.') {
				filled[i] = buf[i];
			}
		}

		ret = r_hex_str2bin (filled, buf);
		if (ret < 1) {
			eprintf ("Cannot parse hexpair\n");
		} else {
			val = radare_compare (core, block, buf, ret, mode);
		}
		free (buf);
		free (filled);
		break;
	case 'X':
		buf = malloc (core->blocksize);
		if (buf) {
			if (!r_io_read_at (core->io, r_num_math (core->num,
					    input + 1), buf, core->blocksize)) {
				eprintf ("Cannot read hexdump\n");
			} else {
				val = radare_compare (core, block, buf, ret, mode);
			}
			free (buf);
		}
		return false;
		break;
	case 'f':
		if (input[1] != ' ') {
			eprintf ("Please. use 'cf [file]'\n");
			return false;
		}
		fd = r_sandbox_fopen (input + 2, "rb");
		if (!fd) {
			eprintf ("Cannot open file '%s'\n", input + 2);
			return false;
		}
		buf = (ut8 *) malloc (core->blocksize);
		if (buf) {
			if (fread (buf, 1, core->blocksize, fd) < 1) {
				eprintf ("Cannot read file %s\n", input + 2);
			} else {
				val = radare_compare (core, block, buf, core->blocksize, 0);
			}
			fclose (fd);
			free (buf);
		} else {
			fclose (fd);
			return false;
		}
		break;
	case 'd': // "cd"
		while (input[1] == ' ') input++;
		if (input[1]) {
			if (!strcmp (input + 1, "-")) {
				if (oldcwd) {
					char *newdir = oldcwd;
					oldcwd = r_sys_getdir ();
					if (r_sandbox_chdir (newdir) == -1) {
						eprintf ("Cannot chdir to %s\n", newdir);
						free (oldcwd);
						oldcwd = newdir;
					} else {
						free (newdir);
					}
				} else {
					// nothing to do here
				}
			} else if (input[1] == '~' && input[2] == '/') {
				char *homepath = r_str_home (input + 3);
				if (homepath) {
					if (*homepath) {
						free (oldcwd);
						oldcwd = r_sys_getdir ();
						if (r_sandbox_chdir (homepath) == -1) {
							eprintf ("Cannot chdir to %s\n", homepath);
						}
					}
					free (homepath);
				} else {
					eprintf ("Cannot find home\n");
				}
			} else {
				free (oldcwd);
				oldcwd = r_sys_getdir ();
				if (r_sandbox_chdir (input + 1) == -1) {
					eprintf ("Cannot chdir to %s\n", input + 1);
				}
			}
		} else {
			char *home = r_sys_getenv (R_SYS_HOME);
			if (!home || r_sandbox_chdir (home) == -1) {
				eprintf ("Cannot find home.\n");
			}
			free (home);
		}
		break;
	case '1': // "c1"
		__core_cmp_bits (core, r_num_math (core->num, input + 1));
		break;
	case '2': // "c2"
		v16 = (ut16) r_num_math (core->num, input + 1);
		val = radare_compare (core, block, (ut8 *) &v16, sizeof (v16), 0);
		break;
	case '4': // "c4"
		v32 = (ut32) r_num_math (core->num, input + 1);
		val = radare_compare (core, block, (ut8 *) &v32, sizeof (v32), 0);
		break;
	case '8': // "c8"
		v64 = (ut64) r_num_math (core->num, input + 1);
		val = radare_compare (core, block, (ut8 *) &v64, sizeof (v64), 0);
		break;
	case 'c': // "cc"
		if (input[1] == '?') { // "cc?"
			r_core_cmd0 (core, "c?~cc");
		} else if (input[1] == 'd') { // "ccd"
			if (input[2] == 'd') { // "ccdd"
				cmd_cmp_disasm (core, input + 3, 'd');
			} else {
				cmd_cmp_disasm (core, input + 2, 'c');
			}
		} else {
			ut32 oflags = core->print->flags;
			ut64 addr = 0; // TOTHINK: Not sure what default address should be
			if (input[1] == 'c') { // "ccc"
				core->print->flags |= R_PRINT_FLAGS_DIFFOUT;
				addr = r_num_math (core->num, input + 2);
			} else {
				if (*input && input[1]) {
					addr = r_num_math (core->num, input + 2);
				}
			}
			int col = core->cons->columns > 123;
			ut8 *b = malloc (core->blocksize);
			if (b != NULL) {
				memset (b, 0xff, core->blocksize);
				r_io_read_at (core->io, addr, b, core->blocksize);
				r_print_hexdiff (core->print, core->offset, block,
					addr, b, core->blocksize, col);
				free (b);
			}
			core->print->flags = oflags;
		}
		break;
	case 'g': // "cg"
	{          // XXX: this is broken
		int diffops = 0;
		RCore *core2;
		char *file2 = NULL;
		switch (input[1]) {
		case 'o':         // "cgo"
			file2 = (char *) r_str_trim_head_ro (input + 2);
			r_anal_diff_setup (core->anal, true, -1, -1);
			break;
		case 'f':         // "cgf"
			eprintf ("TODO: agf is experimental\n");
			r_anal_diff_setup (core->anal, true, -1, -1);
			r_core_gdiff_fcn (core, core->offset,
				r_num_math (core->num, input + 2));
			return false;
		case ' ':
			file2 = (char *) r_str_trim_head_ro (input + 2);
			r_anal_diff_setup (core->anal, false, -1, -1);
			break;
		default: {
			const char *help_message[] = {
				"Usage: cg", "", "Graph code commands",
				"cg", "", "diff ratio among functions (columns: off-A, match-ratio, off-B)",
				"cgf", "[fcn]", "Compare functions (curseek vs fcn)",
				"cgo", "", "Opcode-bytes code graph diff",
				NULL
			};
			r_core_cmd_help (core, help_message);
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
		if (!r_core_file_open (core2, file2, 0, 0LL)) {
			eprintf ("Cannot open diff file '%s'\n", file2);
			r_core_free (core2);
			r_core_bind_cons (core);
			return false;
		}
		// TODO: must replicate on core1 too
		r_config_set_i (core2->config, "io.va", true);
		r_anal_diff_setup (core->anal, diffops, -1, -1);
		r_anal_diff_setup (core2->anal, diffops, -1, -1);

		r_core_bin_load (core2, file2,
			r_config_get_i (core->config, "bin.baddr"));
		r_core_gdiff (core, core2);
		r_core_diff_show (core, core2);
		/* exchange a segfault with a memleak */
		core2->config = NULL;
		r_core_free (core2);
		r_core_bind_cons (core);
	}
	break;
	case 'u': // "cu"
		switch (input[1]) {
		case '.':
		case ' ':
			radare_compare_unified (core, core->offset,
				r_num_math (core->num, input + 2),
				core->blocksize);
			break;
		case '1':
		case '2':
		case '4':
		case '8':
			radare_compare_words (core, core->offset,
				r_num_math (core->num, input + 2),
				core->blocksize, input[1] - '0');
			break;
		case 'd':
			cmd_cmp_disasm (core, input + 2, 'u');
			break;
		default: {
			const char *help_msg[] = {
				"Usage: cu", " [offset]", "# Prints unified comparison to make hexpatches",
				"cu", " $$+1 > p", "Compare hexpairs from  current seek and +1",
				"cu1", " $$+1 > p", "Compare bytes from current seek and +1",
				"cu2", " $$+1 > p", "Compare words (half, 16bit) from current seek and +1",
				"cu4", " $$+1 > p", "Compare dwords from current seek and +1",
				"cu8", " $$+1 > p", "Compare qwords from current seek and +1",
				"cud", " $$+1 > p", "Compare disasm current seek and +1",
				"wu", " p", "Apply unified hex patch (see output of cu)",
				NULL
			};
			r_core_cmd_help (core, help_msg);
		}
		}
		break;
	case '?':
		r_core_cmd_help (core, help_msg_c);
		break;
	case 'v': { // "cv"
		int sz = input[1];
		if (sz == ' ') {
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
		case '1': { // "cv1"
			ut8 n = (ut8) r_num_math (core->num, input + 2);
			core->num->value = 1;
			if (block[0] == n) {
				r_cons_printf ("0x%08"PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
			break;
		}
		case '2': { // "cv2"
			ut16 n = (ut16) r_num_math (core->num, input + 2);
			core->num->value = 1;
			if (core->blocksize >= 2 && *(ut16*)block == n) {
				r_cons_printf ("0x%08"PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
			break;
		}
		case '4': { // "cv4"
			ut32 n = (ut32) r_num_math (core->num, input + 2);
			core->num->value = 1;
			if (core->blocksize >= 4 && *(ut32*)block == n) {
				r_cons_printf ("0x%08"PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
			break;
		}
		case '8': { // "cv8"
			ut64 n = (ut64) r_num_math (core->num, input + 2);
			core->num->value = 1;
			if (core->blocksize >= 8 && *(ut64*)block == n) {
				r_cons_printf ("0x%08"PFMT64x "\n", core->offset);
				core->num->value = 0;
			}
			break;
		}
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
	case 'V': { // "cV"
		int sz = input[1];
		if (sz == ' ') {
			switch (r_config_get_i (core->config, "asm.bits")) {
			case 8: sz = '1'; break;
			case 16: sz = '2'; break;
			case 32: sz = '4'; break;
			case 64: sz = '8'; break;
			default: sz = '4'; break; // default
			}
		} else if (sz == '?') {
			eprintf ("Usage: cV[1248] [addr] @ addr2\n"
				"Compare n bytes from one address to current one and return in $? 0 or 1\n");
		}
		sz -= '0';
		if (sz > 0) {
			ut64 at = r_num_math (core->num, input + 2);
			ut8 buf[8] = {0};
			r_io_read_at (core->io, at, buf, sizeof (buf));
			core->num->value = memcmp (buf, core->block, sz)? 1: 0;
		}
		break;
	}
	case 'l': // "cl"
		if (strchr (input, 'f')) {
			r_cons_flush ();
		} else if (input[1] == 0) {
			r_cons_fill_line ();
			// r_cons_clear_line (0);
		} else if (!strchr (input, '0')) {
			r_cons_clear00 ();
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_c);
	}
	if (val != UT64_MAX) {
		core->num->value = val;
	}
	return 0;
}
