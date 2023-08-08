/* radare - LGPL - Copyright 2009-2022 - pancake */

#include "r_core.h"

static RCoreHelpMessage help_message_ci = {
	"Usage: ci", "[sil] ([obid])", "Compare two bin objects",
	"cis", " 0", "compare symbols with current `ob 1` with given obid (0)",
	"cii", " 0", "compare imports",
	"cil", " 0", "compare libraries",
	NULL
};

static RCoreHelpMessage help_msg_cmp = {
	"Usage: cmp", " [file] [file]", "Compare two ($alias) files, and change $? value",
	"cmp", " ls ls.old", "compare contents of given files",
	"cmp", " $a $b", "same as above but using alias files",
	NULL
};

static RCoreHelpMessage help_msg_c = {
	"Usage:", "c[?dfx] [argument]", " # Compare",
	"c", " [string]", "compare a plain with escaped chars string",
	"c*", " [string]", "same as c, but printing r2 commands instead",
	"cj", " [string]", "same as c, with JSON output",
	"c1", " [addr]", "compare byte at addr with current offset",
	"c2", "[*] [value]", "compare word at offset with given value",
	"c4", "[*] [value]", "compare doubleword at offset with given value",
	"c8", "[*] [value]", "compare quadword at offset with given value",
	"cat", " [file]", "show contents of file (see pwd, ls)",
	"cc", " [at]", "compares in two hexdump columns of block size",
	"ccc", " [at]", "same as above, but only showing different lines",
	"ccd", " [at]", "compares in two disasm columns of block size",
	"ccdd", " [at]", "compares decompiler output (e cmd.pdc=pdg|pdd)",
	"cd", " [dir]", "chdir",
	// "cc", " [offset]", "code bindiff current block against offset"
	// "cD", " [file]", "like above, but using radiff -b",
	"cf", " [file]", "compare contents of file at current seek",
	"cg", "[?][afo] [file]", "compare graphdiff current file and find similar functions",
	"ci", "[?] [obid] ([obid2])", "compare two bin-objects (symbols, imports, ...)",
	"cl|cls|clear", "", "clear screen, (clear0 to goto 0, 0 only)",
	"cmp", " [file] [file]", "compare two files",
	"cu", "[?] [addr] @at", "compare memory hexdumps of $$ and dst in unified diff",
	"cud", " [addr] @at", "unified diff disasm from $$ and given address",
	"cv", "[1248] [hexpairs] @at", "compare 1,2,4,8-byte (silent return in $?)",
	"cV", "[1248] [addr] @at", "compare 1,2,4,8-byte address contents (silent, return in $?)",
	"cw", "[?][*dqjru] [addr]", "compare memory watchers",
	"cx", " [hexpair]", "compare hexpair string (use '.' as nibble wildcard)",
	"cx*", " [hexpair]", "compare hexpair string (output r2 commands)",
	"cX", " [addr]", "Like 'cc' but using hexdiff output",
	NULL
};

static RCoreHelpMessage help_msg_cu = {
	"Usage: cu", " [offset]", "# Prints unified comparison to make hexpatches",
	"cu", " $$+1 > p", "compare hexpairs from current seek and +1",
	"cu1", " $$+1 > p", "compare bytes from current seek and +1",
	"cu2", " $$+1 > p", "compare words (half, 16bit) from current seek and +1",
	"cu4", " $$+1 > p", "compare dwords from current seek and +1",
	"cu8", " $$+1 > p", "compare qwords from current seek and +1",
	"cud", " $$+1 > p", "compare disasm current seek and +1",
	"wu", " p", "apply unified hex patch (see output of cu)",
	"curl", " [http-url]", "",
	NULL
};

static RCoreHelpMessage help_msg_cg = {
	"Usage: cg", "", "Graph compare",
	"cg", " [file]", "diff ratio among functions (columns: off-A, match-ratio, off-B)",
	"cgf", " [fcn]", "compare functions (curseek vs fcn)",
	"cgfa", "", "list all functions similar to the current one",
	"cgo", "", "opcode-bytes code graph diff",
	NULL
};

R_API void r_core_cmpwatch_free(RCoreCmpWatcher *w) {
	if (w) {
		free (w->ndata);
		free (w->odata);
		free (w->cmd);
		free (w);
	}
}

R_API R_BORROW RCoreCmpWatcher *r_core_cmpwatch_get(RCore *core, ut64 addr) {
	RCoreCmpWatcher *w;
	RListIter *iter;
	r_list_foreach (core->watchers, iter, w) {
		if (addr == w->addr) {
			return w;
		}
	}
	return NULL;
}

R_API bool r_core_cmpwatch_add(RCore *core, ut64 addr, int size, const char *cmd) {
	RCoreCmpWatcher *cmpw;
	bool found = false;
	r_return_val_if_fail (core && cmd && size > 0, false);

	cmpw = r_core_cmpwatch_get (core, addr);
	if (!cmpw) {
		cmpw = R_NEW0 (RCoreCmpWatcher);
		if (!cmpw) {
			return false;
		}
		cmpw->addr = addr;
	} else {
		free (cmpw->odata);
		free (cmpw->ndata);
		free (cmpw->cmd);
		found = true;
	}
	cmpw->size = size;
	cmpw->cmd = r_str_new (cmd);
	if (!cmpw->cmd) {
		free (cmpw);
		return false;
	}

	cmpw->odata = NULL;
	cmpw->ndata = malloc (size);
	if (!cmpw->ndata) {
		r_core_cmpwatch_free (cmpw);
		return false;
	}

	if (r_io_nread_at (core->io, addr, cmpw->ndata, size) != size) {
		r_core_cmpwatch_free (cmpw);
		return false;
	}

	// Don't append a duplicate
	if (!found) {
		r_list_append (core->watchers, cmpw);
	}
	return true;
}

R_API bool r_core_cmpwatch_del(RCore *core, ut64 addr) {
	bool ret = false;
	RCoreCmpWatcher *w;
	RListIter *iter, *iter2;

	if (addr == UT64_MAX) { // match all
		r_list_foreach_safe (core->watchers, iter, iter2, w) {
			r_list_delete (core->watchers, iter);
			ret = true;
		}
		return ret;
	}

	// Can't use r_core_cmpwatch_get() here since we need the iter
	r_list_foreach_safe (core->watchers, iter, iter2, w) {
		if (w->addr == addr) {
			/* Only one watcher per address - we can leave early */
			r_list_delete (core->watchers, iter);
			ret = true;
			break;
		}
	}
	return ret;
}

R_API bool r_core_cmpwatch_show(RCore *core, ut64 addr, int mode) {
	RListIter *iter;
	RCoreCmpWatcher *w;
	PJ *pj = NULL;
	bool ret = false;

	if (mode == 'j') {
		pj = r_core_pj_new (core);
		if (!pj) {
			return false;
		}
		pj_a (pj);
	}

	r_list_foreach (core->watchers, iter, w) {
		bool changed = w->odata? memcmp (w->odata, w->ndata, w->size): false;
		if (addr != UT64_MAX && addr != w->addr) {
			continue;
		}
		switch (mode) {
		case '*': // print watchers as r2 commands
			r_cons_printf ("cw 0x%08" PFMT64x " %d %s%s\n",
					w->addr, w->size, w->cmd,
					changed? " # differs": "");
			break;
		case 'q': // quiet
			if (changed) {
				r_cons_printf ("0x%08" PFMT64x " has changed\n", w->addr);
			}
			break;
		case 'j': // "cw"
			{
			char *cmd_output = r_core_cmd_strf (core, "%s %d @%" PFMT64d,
					w->cmd, w->size, w->addr);
			pj_o (pj);
			pj_kn (pj, "addr", w->addr);
			pj_kb (pj, "changed", changed);
			pj_ks (pj, "cmd", w->cmd);
			pj_ks (pj, "cmd_out", r_str_get (cmd_output));
			pj_end (pj);
			free (cmd_output);
			}
			break;
		default:
			r_cons_printf ("0x%08" PFMT64x "%s\n", w->addr, changed? " modified": "");
			r_core_cmdf (core, "%s %d @%" PFMT64d, w->cmd, w->size, w->addr);
			break;
		}

		ret = true;
	}

	if (pj) {
		char *out;
		pj_end (pj);
		out = pj_drain (pj);
		r_cons_println (out);
		free (out);
	}

	return ret;
}

static bool update_watcher(RIO *io, RCoreCmpWatcher *w) {
	r_return_val_if_fail (io && w, false);

	free (w->odata);
	w->odata = w->ndata;
	w->ndata = malloc (w->size);
	if (!w->ndata) {
		return false;
	}
	r_io_read_at (io, w->addr, w->ndata, w->size);
	return true;
}

/* Replace old data with current new data, then read IO into new data */
R_API bool r_core_cmpwatch_update(RCore *core, ut64 addr) {
	RCoreCmpWatcher *w;
	RListIter *iter;
	bool ret = false;

	if (addr != UT64_MAX) {
		w = r_core_cmpwatch_get (core, addr);
		if (w) {
			return update_watcher (core->io, w);
		}
		return false;
	}

	r_list_foreach (core->watchers, iter, w) {
		if (update_watcher (core->io, w)) {
			ret = true;
		}
	}

	return ret;
}

static bool revert_watcher(RCoreCmpWatcher *w) {
	r_return_val_if_fail (w, false);
	if (w->odata) {
		free (w->ndata);
		w->ndata = w->odata;
		w->odata = NULL;
	}

	return true;
}

/* Mark the current old state as new, discarding the original new state */
R_API bool r_core_cmpwatch_revert(RCore *core, ut64 addr) {
	RCoreCmpWatcher *w;
	RListIter *iter;
	bool ret = false;

	if (addr != UT64_MAX) {
		w = r_core_cmpwatch_get (core, addr);
		if (w) {
			return revert_watcher (w);
		}

		return false;
	}


	r_list_foreach (core->watchers, iter, w) {
		if (revert_watcher (w)) {
			ret = true;
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
		switch (mode) {
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
		default:
			R_LOG_ERROR ("Unknown mode");
			break;
		}
	}
	if (mode == 0) {
		R_LOG_INFO ("Compare %d/%d equal bytes (%d%%)", eq, len, (eq / len) * 100);
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

static void nowatchers(ut64 addr) {
	if (addr == UT64_MAX) {
		R_LOG_ERROR ("No watchers exist");
	} else {
		R_LOG_ERROR ("No watcher exists at address %" PFMT64x, addr);
	}
}

/* Returns 0 if operation succeeded, 1 otherwise */
static int cmd_cmp_watcher(RCore *core, const char *input) {
	static RCoreHelpMessage help_msg_cw = {
		"Usage: cw", "[args]", "Manage compare watchers; See if and how memory changes",
		"cw??", "", "Show more info about watchers",
		"cw ", "addr sz cmd", "Add a compare watcher",
		"cw", "[*qj] [addr]", "Show compare watchers (*=r2 commands, q=quiet, j=json)",
		"cwd", " [addr]", "Delete watcher",
		"cwr", " [addr]", "Revert watcher",
		"cwu", " [addr]", "Update watcher",
		NULL
	};
	static const char *verbose_help_cw =
		"Watchers are used to record memory at 2 different points in time, then\n"
		"report if and how it changed. First, create one with `cw addr sz cmd`. This\n"
		"will record sz bytes at addr. To record the second state, use `cwu`. Now, when\n"
		"you run `cw`, the watcher will report if the bytes changed and run the command given\n"
		"at creation with the size and address. You may overwrite any watcher by creating\n"
		"another at the same address. This will discard the existing watcher completely.\n"
		"\n"
		"When you create a watcher, the data read from memory is marked as \"new\". Updating\n"
		"the watcher with `cwu` will mark this data as \"old\", and then read the \"new\" data.\n"
		"`cwr` will mark the current \"old\" state as being \"new\", letting you reuse it as\n"
		"your new base state when updating with `cwu`. Any existing \"new\" state from running\n"
		"`cwu` previously is lost in this process. Watched memory areas may overlap with no ill\n"
		"effects, but may have unexpected results if you update some but not others.\n"
		"\n"
		"Showing a watcher without updating will still run the command, but it will not report\n"
		"changes.\n"
		"\n"
		"When an address is an optional argument, the command will apply to all watchers if\n"
		"you don't pass one.\n"
		"\n"
		"For more details and examples, see section 4.10 of the radare2 book.\n";

	ut64 addr = UT64_MAX;
	int ret = 0;

	switch (*input) {
	case ' ': { // "cw "
		int argc;
		char **argv = r_str_argv (input + 1, &argc);
		if (!argv) {
			return 1;
		}
		if (argc == 1) { // "cw [addr]"
			addr = r_num_math (core->num, argv[0]);
			r_core_cmpwatch_show (core, addr, 0);
		} else if (argc == 3) { // "cw addr sz cmd"
			addr = r_num_math (core->num, argv[0]);
			ut64 size = r_num_math (core->num, argv[1]);

			if (size < 1) {
				ret = 1;
				R_LOG_ERROR ("Can't create a watcher with size less than 1");
				goto out_free_argv;
			}
			if (size > INT_MAX) {
				ret = 1;
				R_LOG_ERROR ("Can't create a watcher with size larger than an int");
				goto out_free_argv;
			}

			if (!r_core_cmpwatch_add (core, addr, (int)size, argv[2])) {
				ret = 1;
				R_LOG_ERROR ("Failed to add watcher");
			}
		} else {
			r_core_cmd_help_match (core, help_msg_cw, "cw ", true);
		}
out_free_argv:
		r_str_argv_free (argv);
		break;
	}
	case 'd': // "cwd"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_cw, "cwd", true);
			return 0;
		}
		if (input[1]) {
			addr = r_num_math (core->num, input + 2);
		}
		if (addr == UT64_MAX && !r_cons_yesno ('n', "Delete all watchers? (y/N)")) {
			return 1;
		}
		if (!r_core_cmpwatch_del (core, addr) && addr) {
			ret = 1;
			nowatchers (addr);
		}
		break;
	case 'r': // "cwr"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_cw, "cwr", true);
			return 0;
		}

		if (input[1]) {
			addr = r_num_math (core->num, input + 2);
		}

		if (addr == UT64_MAX &&
				!r_cons_yesno ('n', "Revert all watchers? (y/N)")) {
			return 1;
		}

		if (!r_core_cmpwatch_revert (core, addr)) {
			ret = 0;
			nowatchers (addr);
		}
		break;
	case 'u': // "cwu"
		if (input[1] == '?') {
			r_core_cmd_help_match (core, help_msg_cw, "cwu", true);
			return 0;
		}
		if (input[1]) {
			addr = r_num_math (core->num, input + 2);
		}
		if (!r_core_cmpwatch_update (core, addr)) {
			ret = 1;
			nowatchers (addr);
		}
		break;
	case '*': // "cw*"
	case 'q': // "cwq"
	case 'j': // "cwj"
	case '\0': { // "cw"
		int mode = *input;
		if (*input && input[1]) {
			addr = r_num_math (core->num, input + 2);
		}
		if (!r_core_cmpwatch_show (core, addr, mode)) {
			ret = 1;
			/* Skip error message for json, it will still show [] */
			if (mode == 'j') {
				break;
			}
			nowatchers (addr);
		}
		break;
	}
	case '?': // "cw?"
	default:
		if (input[1] == '?') {
			// this command really needs explaining
			// so it's strongly signposted
			r_cons_printf ("%s", verbose_help_cw);
		} else {
			r_core_cmd_help (core, help_msg_cw);
		}
		break;
	}

	return ret;
}

static int cmd_cmp_disasm(RCore *core, const char *input, int mode) {
	RAnalOp op, op2;
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
			r_asm_set_pc (core->rasm, core->offset + i);
			(void) r_asm_disassemble (core->rasm, &op,
				core->block + i, core->blocksize - i);

			// dis B
			r_asm_set_pc (core->rasm, off + i);
			(void) r_asm_disassemble (core->rasm, &op2,
				buf + j, core->blocksize - j);

			// show output
			bool iseq = !strcmp (op.mnemonic, op2.mnemonic);
			memset (colpad, ' ', sizeof (colpad));
			{
				int pos = strlen (op.mnemonic);
				pos = (pos > cols)? 0: cols - pos;
				colpad[pos] = 0;
			}
			if (hascolor) {
				r_cons_print (iseq? pal->graph_true: pal->graph_false);
			}
			r_cons_printf (" 0x%08"PFMT64x "  %s %s", core->offset + i, op.mnemonic, colpad);
			r_cons_printf ("%c 0x%08"PFMT64x "  %s\n", iseq? '=': '!', off + j, op2.mnemonic);
			if (hascolor) {
				r_cons_print (Color_RESET);
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
			r_asm_set_pc (core->rasm, core->offset + i);
			(void) r_asm_disassemble (core->rasm, &op,
				core->block + i, core->blocksize - i);

			// dis B
			r_asm_set_pc (core->rasm, off + i);
			(void) r_asm_disassemble (core->rasm, &op2,
				buf + j, core->blocksize - j);

			// show output
			bool iseq = !strcmp (op.mnemonic, op2.mnemonic);
			if (iseq) {
				r_cons_printf (" 0x%08"PFMT64x "  %s\n",
					core->offset + i, op.mnemonic);
			} else {
				if (hascolor) {
					r_cons_print (pal->graph_false);
				}
				r_cons_printf ("-0x%08"PFMT64x "  %s\n", core->offset + i, op.mnemonic);
				if (hascolor) {
					r_cons_print (pal->graph_true);
				}
				r_cons_printf ("+0x%08"PFMT64x "  %s\n", off + j, op2.mnemonic);
				if (hascolor) {
					r_cons_print (Color_RESET);
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
	bool use_corefile;
	RCoreHelpMessage help_msg_cp = {
		"cp", " src dst", "Standard file copy",
		"cp", ".[ext]", "Copy current file <name> to <name>.ext",
		NULL
	};

	if (*input == '?' || !*input) {
		r_core_cmd_help (core, help_msg_cp);
		return false;
	}

	use_corefile = (*input == '.');
	input++;

	if (!*input) {
		r_core_cmd_help (core, help_msg_cp);
		return false;
	}

	if (use_corefile) {
		char *file = r_core_cmd_str (core, "ij~{core.file}");
		bool ret;

		if (!file) {
			return false;
		}
		r_str_trim (file);

		if (!r_file_exists (file)) {
			R_LOG_ERROR ("%s is not a file on the disk. Can't copy, see `wt?`", file);
			free (file);
			return false;
		}

		char *newfile = r_str_newf ("%s.%s", file, input);
		if (!newfile) {
			free (file);
			return false;
		}

		ret = r_file_copy (file, newfile);
		free (file);
		free (newfile);
		return ret;
	}

	char **files = r_str_argv (input, NULL);
	if (files) {
		bool ret = false;
		if (files[0] && files[1]) {
			ret = r_file_copy (files[0], files[1]);
		} else {
			r_core_cmd_help (core, help_msg_cp);
		}
		r_str_argv_free (files);
		return ret;
	}

	return false;
}

/* Show the bits for the bytes at addr and offset.
 * If scr.color is enabled, when bytes differ 1 is colored graph_true and 0 is
 * colored graph_false.
 */
static int cmp_bits(RCore *core, ut64 addr) {
	RConsPrintablePalette *pal = &r_cons_singleton ()->context->pal;
	const bool use_color = r_config_get_b (core->config, "scr.color");
	const char *color_end = use_color? Color_RESET: "";
	int i;
	ut8 a, b;
	bool a_bits[8], b_bits[8];
	const char *a_colors[8], *b_colors[8];

	r_io_nread_at (core->io, core->offset, &a, 1);
	r_io_nread_at (core->io, addr, &b, 1);

	/* Print offset header if enabled */
	if (r_config_get_i (core->config, "hex.header")) {
		const char *color = use_color? pal->offset: "";
		char *n = r_str_newf ("0x%08" PFMT64x, core->offset);
		const char *padding = r_str_pad (' ', strlen (n) - 10);
		free (n);
		r_cons_printf ("%s- offset -%s  7 6 5 4 3 2 1 0%s\n", color, padding, color_end);
	}

	/* Set up bits and colors */
	for (i = 7; i >= 0; i--) {
		a_bits[i] = a & (1 << i);
		b_bits[i] = b & (1 << i);

		if (use_color && a_bits[i] != b_bits[i]) {
			a_colors[i] = a_bits[i]? pal->graph_true: pal->graph_false;
			b_colors[i] = b_bits[i]? pal->graph_true: pal->graph_false;
		} else {
			a_colors[i] = "";
			b_colors[i] = "";
		}
	}

	r_cons_printf ("%s0x%08" PFMT64x "%s  ", use_color? pal->graph_false: "", core->offset, color_end);
	for (i = 7; i >= 0; i--) {
		r_cons_printf ("%s%d%s%s", a_colors[i], a_bits[i], color_end, i? " ": "");
	}

	r_cons_printf ("\n%s0x%08" PFMT64x "%s  ", use_color? pal->graph_true: "", addr, color_end);
	for (i = 7; i >= 0; i--) {
		r_cons_printf ("%s%d%s%s", b_colors[i], b_bits[i], color_end, i? " ": "");
	}
	r_cons_newline ();

	// 0 if equal, 1 if not equal
	// same return pattern as ?==
	return a != b;
}

static const RList *symbols_of(RCore *core, int id0) {
	RBinFile *bf = r_bin_file_find_by_id (core->bin, id0);
	RBinFile *old_bf = core->bin->cur;
	r_bin_file_set_cur_binfile (core->bin, bf);
	const RList *list = bf? r_bin_get_symbols (core->bin): NULL;
	r_bin_file_set_cur_binfile (core->bin, old_bf);
	return list;
}

static const RList *imports_of(RCore *core, int id0) {
	RBinFile *bf = r_bin_file_find_by_id (core->bin, id0);
	RBinFile *old_bf = core->bin->cur;
	r_bin_file_set_cur_binfile (core->bin, bf);
	const RList *list = bf? r_bin_get_imports (core->bin): NULL;
	r_bin_file_set_cur_binfile (core->bin, old_bf);
	return list;
}

static const RList *libs_of(RCore *core, int id0) {
	RBinFile *bf = r_bin_file_find_by_id (core->bin, id0);
	RBinFile *old_bf = core->bin->cur;
	r_bin_file_set_cur_binfile (core->bin, bf);
	const RList *list = bf? r_bin_get_libs (core->bin): NULL;
	r_bin_file_set_cur_binfile (core->bin, old_bf);
	return list;
}

static void _core_cmp_info_libs(RCore *core, int id0, int id1) {
	const RList *s0 = libs_of (core, id0);
	const RList *s1 = libs_of (core, id1);
	if (!s0 || !s1) {
		R_LOG_ERROR ("Missing bin object");
		return;
	}
	RListIter *iter, *iter2;
	char *s, *s2;
	if (id0 == id1) {
		eprintf ("%d == %d\n", id0, id1);
		return;
	}
	r_list_foreach (s0, iter, s) {
		bool found = false;
		r_list_foreach (s1, iter2, s2) {
			if (!strcmp (s, s2)) {
				found = true;
			}
		}
		r_cons_printf ("%s%s\n", found? " ": "-", s);
	}
	r_list_foreach (s1, iter, s) {
		bool found = false;
		r_list_foreach (s0, iter2, s2) {
			if (!strcmp (s, s2)) {
				found = true;
			}
		}
		if (!found) {
			r_cons_printf ("+%s\n", s);
		}
	}
	// r_list_free (s0);
	// r_list_free (s1);
}

static void _core_cmp_info_imports(RCore *core, int id0, int id1) {
	const RList *s0 = imports_of (core, id0);
	const RList *s1 = imports_of (core, id1);
	if (!s0 || !s1) {
		R_LOG_ERROR ("Missing bin object");
		return;
	}
	RListIter *iter, *iter2;
	RBinImport *s, *s2;
	if (id0 == id1) {
		eprintf ("%d == %d\n", id0, id1);
		return;
	}
	r_list_foreach (s0, iter, s) {
		bool found = false;
		r_list_foreach (s1, iter2, s2) {
			if (!strcmp (s->name, s2->name)) {
				found = true;
			}
		}
		r_cons_printf ("%s%s\n", found? " ": "-", s->name);
	}
	r_list_foreach (s1, iter, s) {
		bool found = false;
		r_list_foreach (s0, iter2, s2) {
			if (!strcmp (s->name, s2->name)) {
				found = true;
			}
		}
		if (!found) {
			r_cons_printf ("+%s\n", s->name);
		}
	}
	// r_list_free (s0);
	// r_list_free (s1);
}

static void _core_cmp_info_symbols(RCore *core, int id0, int id1) {
	const RList *s0 = symbols_of (core, id0);
	const RList *s1 = symbols_of (core, id1);
	if (!s0 || !s1) {
		R_LOG_ERROR ("Missing bin object");
		return;
	}
	RListIter *iter, *iter2;
	RBinSymbol *s, *s2;
	if (id0 == id1) {
		eprintf ("%d == %d\n", id0, id1);
		return;
	}
	r_list_foreach (s0, iter, s) {
		bool found = false;
		r_list_foreach (s1, iter2, s2) {
			if (!strcmp (s->name, s2->name)) {
				found = true;
			}
		}
		r_cons_printf ("%s%s\n", found? " ": "-", s->name);
	}
	r_list_foreach (s1, iter, s) {
		bool found = false;
		r_list_foreach (s0, iter2, s2) {
			if (!strcmp (s->name, s2->name)) {
				found = true;
			}
		}
		if (!found) {
			r_cons_printf ("+%s\n", s->name);
		}
	}
}

static void _core_cmp_info(RCore *core, const char *input) {
	RBinFile *cur = core->bin->cur;
	int id0 = (cur && cur->bo) ? cur->id: 0;
	int id1 = atoi (input + 1);
	// do the magic
	switch (input[0]) {
	case 's':
		_core_cmp_info_symbols (core, id0, id1);
		break;
	case 'l':
		_core_cmp_info_libs (core, id0, id1);
		break;
	case 'i':
		_core_cmp_info_imports (core, id0, id1);
		break;
	default:
		r_core_cmd_help (core, help_message_ci);
		break;
	}
}

static void cmd_curl(RCore *core, const char *arg) {
	if (r_sys_getenv_asbool ("R2_CURL")) {
		r_sys_cmdf ("curl %s", arg);
	} else {
		if (r_str_startswith (arg, "http://") || r_str_startswith (arg, "https://")) {
			int len;
			char *s = r_socket_http_get (arg, NULL, &len);
			if (s) {
				r_cons_write (s, len);
				free (s);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_cu, "curl", true);
		}
	}
}

static char *myslurp(RCore *core, const char *a, ut64 *sz) {
	if (*a == '$') {
		RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, a + 1);
		if (v) {
			char *v_str = r_cmd_alias_val_strdup (v);
			*sz = strlen (v_str);
			return v_str;
		}
	} else {
		size_t ssz;
		char *rc = r_file_slurp (a, &ssz);
		*sz = ssz;
		return rc;
	}
	*sz = 0;
	return NULL;
}

static int cmd_cmp_posix(RCore *core, const char *a, const char *b) {
	ut64 sa, sb;
	char *ba = myslurp (core, a, &sa);
	char *bb = myslurp (core, b, &sb);
	int res = 0;
	if (!ba || !bb) {
		R_LOG_ERROR ("One or more files can't be read");
		res = 1;
	} else {
		if (sa == sb) {
			res = memcmp (ba, bb, sa)? 1: 0;
		} else {
			res = 1;
		}
	}
	free (ba);
	free (bb);
	// return 0 if both files are the same
	return res;
}

static int cmd_cmp(void *data, const char *input) {
	static R_TH_LOCAL char *oldcwd = NULL;
	int ret = 0, i, mode = 0;
	RCore *core = (RCore *)data;
	ut64 val = UT64_MAX;
	char *filled;
	ut8 *buf;
	utAny wordcmp;
	FILE *fd;
	const ut8* block = core->block;

	switch (*input) {
	case 'p': // "cp"
		return cmd_cp (data, input + 1);
		break;
	case 'a': // "ca"
		if (input[1] == 't') { // "cat"
			const char *path = r_str_trim_head_ro (input + 2);
			if (*path == '$' && !path[1]) {
				R_LOG_ERROR ("No alias name given");
			} else if (*path == '$') {
				RCmdAliasVal *v = r_cmd_alias_get (core->rcmd, path + 1);
				if (v) {
					char *v_str = r_cmd_alias_val_strdup (v);
					r_cons_println (v_str);
					free (v_str);
				} else {
					R_LOG_ERROR ("No such alias \"$%s\"", path + 1);
				}
			} else if (*path) {
				if (r_fs_check (core->fs, path)) {
					r_core_cmdf (core, "mg %s", path);
				} else {
					char *res = r_syscmd_cat (path);
					if (res) {
						r_cons_print (res);
						free (res);
					}
				}
			} else {
				r_core_cmd_help_match (core, help_msg_c, "cat", true);
			}
		} else { // "ca"
			r_core_cmd_help_match (core, help_msg_c, "cat", true);
		}
		break;
	case 'w':
		return cmd_cmp_watcher (core, input + 1);
		break;
	case '*': // "c*"
		if (!input[2]) {
			r_core_cmd_help_match (core, help_msg_c, "c*", true);
			return 0;
		}

		val = radare_compare (core, block, (ut8 *) input + 2,
			strlen (input + 2) + 1, '*');
		break;
	case ' ': { // "c"
		char *str = strdup (input + 1);
		int len = r_str_unescape (str);
		val = radare_compare (core, block, (ut8 *) str, len, 0);
		free (str);
		break;
	}
	case 'j': // "cj"
		if (input[1] != ' ') {
			r_core_cmd_help_match (core, help_msg_c, "cj", true);
		} else {
			char *str = strdup (input + 2);
			int len = r_str_unescape (str);
			val = radare_compare (core, block, (ut8 *) str, len, 'j');
			free (str);
		}
		break;
	case 'x': // "cx"
		switch (input[1]) {
		case ' ':
			mode = 0;
			input += 2;
			break;
		case '*':
			if (input[2] != ' ') {
				r_core_cmd_help_match (core, help_msg_c, "cx*", true);
				return 0;
			}
			mode = '*';
			input += 3;
			break;
		default:
			r_core_cmd_help_match (core, help_msg_c, "cx", true);
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
			R_LOG_ERROR ("Cannot parse hexpair");
		} else {
			val = radare_compare (core, block, buf, ret, mode);
		}
		free (buf);
		free (filled);
		break;
	case 'X': // "cX"
		buf = malloc (core->blocksize);
		if (buf) {
			if (!r_io_read_at (core->io, r_num_math (core->num,
					    input + 1), buf, core->blocksize)) {
				R_LOG_ERROR ("Cannot read hexdump");
			} else {
				val = radare_compare (core, block, buf, core->blocksize, mode);
			}
			free (buf);
		}
		break;
	case 'f': // "cf"
		if (input[1] != ' ') {
			R_LOG_INFO ("Please. use 'cf [file]'");
			return false;
		}
		fd = r_sandbox_fopen (input + 2, "rb");
		if (!fd) {
			R_LOG_ERROR ("Cannot open file '%s'", input + 2);
			return false;
		}
		buf = (ut8 *) malloc (core->blocksize);
		if (buf) {
			if (fread (buf, 1, core->blocksize, fd) < 1) {
				R_LOG_ERROR ("Cannot read file %s", input + 2);
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
						R_LOG_ERROR ("Cannot chdir to %s", newdir);
						free (oldcwd);
						oldcwd = newdir;
					} else {
						free (newdir);
					}
				} else {
					// nothing to do here
				}
			} else if (input[1] == '~' && input[2] == '/') {
				char *homepath = r_file_home (input + 3);
				if (homepath) {
					if (*homepath) {
						free (oldcwd);
						oldcwd = r_sys_getdir ();
						if (r_sandbox_chdir (homepath) == -1) {
							R_LOG_ERROR ("Cannot chdir to %s", homepath);
						}
					}
					free (homepath);
				} else {
					R_LOG_ERROR ("Cannot find home");
				}
			} else {
				free (oldcwd);
				oldcwd = r_sys_getdir ();
				if (r_sandbox_chdir (input + 1) == -1) {
					R_LOG_ERROR ("Cannot chdir to %s", input + 1);
				}
			}
		} else {
			char *home = r_sys_getenv (R_SYS_HOME);
			if (!home || r_sandbox_chdir (home) == -1) {
				R_LOG_ERROR ("Cannot find home");
			}
			free (home);
		}
		break;
	case '1':
	case '2':
	case '4':
	case '8': {
		const char width = *input++;
		const char mode = *input == '*'? '*': 0;
		const char *arg;
		utAny cmp_val;

		arg = *input? r_str_trim_head_ro (input + 1): NULL;

		if (input[0] == '?' || R_STR_ISEMPTY (arg)) {
			r_core_cmd_help_match_spec (core, help_msg_c, "c", width, true);
			break;
		}

		if (width == '1') {
			if (mode == '*') {
				R_LOG_ERROR ("c1 does not support * mode");
				r_core_cmd_help_match (core, help_msg_c, "c1", true);
			} else {
				val = cmp_bits (core, r_num_math (core->num, arg));
			}
		} else if (width == '2') {
			cmp_val.v16 = (ut16) r_num_math (core->num, arg);
			val = radare_compare (core, block, (ut8 *) &cmp_val.v16, sizeof (wordcmp.v16), mode);
		} else if (width == '4') {
			cmp_val.v32 = (ut32) r_num_math (core->num, arg);
			val = radare_compare (core, block, (ut8 *) &cmp_val.v32, sizeof (wordcmp.v32), mode);
		} else if (width == '8') {
			cmp_val.v64 = r_num_math (core->num, arg);
			val = radare_compare (core, block, (ut8 *) &cmp_val.v64, sizeof (wordcmp.v64), mode);
		}
		break;
	}
	case 'c': // "cc"
		if (input[1] == '?') { // "cc?"
			r_core_cmd_help_match (core, help_msg_c, "cc", false);
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
			if (b) {
				memset (b, 0xff, core->blocksize);
				r_io_read_at (core->io, addr, b, core->blocksize);
				r_print_hexdiff (core->print, core->offset, block,
					addr, b, core->blocksize, col);
				free (b);
			}
			core->print->flags = oflags;
		}
		break;
	case 'i': // "ci"
		_core_cmp_info (core, input + 1);
		break;
	case 'g': // "cg"
	{          // XXX: this is broken
		int diffops = 0;
		RCore *core2;
		char *file2 = NULL;
		switch (input[1]) {
		case 'o': // "cgo"
			file2 = (char *) r_str_trim_head_ro (input + 2);
			if (*file2) {
				r_anal_diff_setup (core->anal, true, -1, -1);
			} else {
				r_core_cmd_help_match (core, help_msg_cg, "cgo", true);
				return false;
			}
			break;
		case 'f': // "cgf"
			R_LOG_TODO ("agf is experimental");
			if (input[2] == 'a') {
				r_anal_diff_setup (core->anal, true, -1, -1);
				RListIter *iter;
				RAnalFunction *fcn;
				r_list_foreach (core->anal->fcns, iter, fcn) {
					// R_LOG_INFO ("compare %s", fcn->name);
					r_core_gdiff_fcn (core, core->offset, fcn->addr);
				}
			} else {
				r_anal_diff_setup (core->anal, true, -1, -1);
				r_core_gdiff_fcn (core, core->offset,
					r_num_math (core->num, input + 2));
			}
			return false;
		case ' ': // "cg "
			file2 = (char *) r_str_trim_head_ro (input + 2);
			r_anal_diff_setup (core->anal, false, -1, -1);
			break;
		default:
			r_core_cmd_help (core, help_msg_cg);
			return false;
		}

		if (r_file_size (file2) <= 0) {
			R_LOG_ERROR ("Cannot compare with file %s", file2);
			return false;
		}

		if (!(core2 = r_core_new ())) {
			R_LOG_ERROR ("Cannot init diff core");
			return false;
		}
		r_core_loadlibs (core2, R_CORE_LOADLIBS_ALL, NULL);
		core2->io->va = core->io->va;
		if (!r_core_file_open (core2, file2, 0, 0LL)) {
			R_LOG_ERROR ("Cannot open diff file '%s'", file2);
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
		if (r_str_startswith (input, "url")) {
			const char *arg = r_str_trim_head_ro (input + 3);
			cmd_curl (core, arg);
			break;
		}
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
			r_core_cmd_help (core, help_msg_cu);
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
			if (block[0] == n) {
				r_cons_printf ("0x%08"PFMT64x "\n", core->offset);
				r_core_return_value (core, 0);
			} else {
				r_core_return_value (core, 1);
			}
			break;
		}
		case '2': { // "cv2"
			ut16 n = (ut16) r_num_math (core->num, input + 2);
			if (core->blocksize >= 2 && *(ut16*)block == n) {
				r_cons_printf ("0x%08"PFMT64x "\n", core->offset);
				r_core_return_value (core, 0);
			} else {
				r_core_return_value (core, 1);
			}
			break;
		}
		case '4': { // "cv4"
			ut32 n = (ut32) r_num_math (core->num, input + 2);
			if (core->blocksize >= 4 && *(ut32*)block == n) {
				r_cons_printf ("0x%08"PFMT64x "\n", core->offset);
				r_core_return_value (core, 0);
			} else {
				r_core_return_value (core, 1);
			}
			break;
		}
		case '8': { // "cv8"
			ut64 n = (ut64) r_num_math (core->num, input + 2);
			if (core->blocksize >= 8 && *(ut64*)block == n) {
				r_cons_printf ("0x%08"PFMT64x "\n", core->offset);
				r_core_return_value (core, 0);
			} else {
				r_core_return_value (core, 1);
			}
			break;
		}
		default:
			r_core_return_value (core, 1);
			// fallthrough
		case '?':
			r_core_cmd_help_match (core, help_msg_c, "cv", true);
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
			r_core_cmd_help_match (core, help_msg_c, "cV", true);
		}
		sz -= '0';
		if (sz > 0) {
			ut64 at = r_num_math (core->num, input + 2);
			ut8 buf[8] = {0};
			if (r_io_read_at (core->io, at, buf, sizeof (buf)) < 1) {
				r_core_return_value (core, -1);
				break;
			}
			int val = memcmp (buf, core->block, R_MIN (core->blocksize, sz))? 1: 0;
			r_core_return_value (core, val);
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
	case 'm': // "cmp"
		if (input[1] != 'p' || strchr (input, '?')) {
			r_core_cmd_help (core, help_msg_cmp);
		} else {
			int argc;
			char **argv = r_str_argv (r_str_trim_head_ro (input + 2), &argc);
			if (argc == 2) {
				int res = cmd_cmp_posix (core, argv[0], argv[1]);
				r_core_return_value (core, res);
			} else {
				r_core_cmd_help (core, help_msg_cmp);
			}
			free (argv);
		}
		break;
	default:
		r_core_cmd_help (core, help_msg_c);
		break;
	}
	if (val != UT64_MAX) {
		r_core_return_value (core, val);
	}
	return 0;
}
