/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

static void __core_cmd_search_backward_prelude(RCore *core, bool doseek, bool forward);

static RCoreHelpMessage help_msg_s = {
	"Usage: s", "", " # Help for the seek commands. See ?$? to see all variables",
	"s", "", "print current address",
	"s", " addr", "seek to address",
	"s.", "[?]hexoff", "seek honoring a base from core->addr",
	"s:", "pad", "print current address with N padded zeros (defaults to 8)",
	"s-", "", "undo seek",
	"s-*", "", "reset undo seek history",
	"s-", " n", "seek n bytes backward",
	"s--", "[n]", "seek blocksize bytes backward (/=n)",
	"s+", "", "redo seek",
	"s+", " n", "seek n bytes forward",
	"s++", "[n]", "seek blocksize bytes forward (/=n)",
	"s[j*=!]", "", "list undo seek history (JSON, =list, *r2, !=names, s==)",
	"s/", " DATA", "search for next occurrence of 'DATA' (see /?)",
	"s/x", " 9091", "search for next occurrence of \\x90\\x91",
	"sa", " ([+-]addr)", "seek to block-size aligned address (addr=$$ if not specified)",
	"sb", " ([addr])", "seek to the beginning of the basic block",
	"sC", "[?] string", "seek to comment matching given string",
	"sd", " ([addr])", "show delta seek compared to all possible reference bases",
	"sf", "", "seek to next function (f->addr+f->size)",
	"sf", " function", "seek to address of specified function",
	"sf.", "", "seek to the beginning of current function",
	"sfp", "", "seek to the function prelude checking back blocksize bytes",
	"sff", "", "seek to the nearest flag backwards (uses fd and ignored the delta)",
	"sg/sG", "", "seek begin (sg) or end (sG) of section or file",
	"sh", "", "open a basic shell (aims to support basic posix syntax)",
	"sl", "[?] [+-]line", "seek to line",
	"sn/sp", " ([nkey])", "seek to next/prev location, as specified by scr.nkey",
	"snp", "", "seek to next function prelude",
	"spp", "", "seek to prev function prelude",
	"so", " ([[-]N])", "seek to N opcode(s) forward (or backward when N is negative), N=1 by default",
	"sr", " PC", "seek to register (or register alias) value",
	"ss", "[?]", "seek silently (without adding an entry to the seek history)",
	// "sp [page]  seek page N (page = block)",
	"sort", " [file]", "sort the contents of the file",
	NULL
};

static RCoreHelpMessage help_msg_sdot = {
	"Usage:", "s.", "Seek here or there (near seeks)",
	"s.", "", "seek here, same as 's $$'",
	"s..", "32a8", "seek to the same address but replacing the lower nibbles",
	NULL
};

static RCoreHelpMessage help_msg_sh = {
	"Usage:", "sh", "r2's posix shell compatible subset",
	"sh", "", "enters a posix shell subset repl (requires scr.interactive)",
	"sh", " [cmd]", "run the given line and update $?",
	NULL
};

static RCoreHelpMessage help_msg_sC = {
	"Usage:", "sC", "Comment grep",
	"sC", "*", "list all comments",
	"sC", " str", "seek to the first comment matching 'str'",
	NULL
};

static RCoreHelpMessage help_msg_sn = {
	"Usage:", "sn[p]", "",
	"sn", " [line]", "seek to next address",
	"snp", "", "seek to next prelude",
	NULL
};

static RCoreHelpMessage help_msg_sp = {
	"Usage:", "sp[p]", "",
	"sp", " [line]", "seek to previous address",
	"spp", "", "seek to previous prelude",
	NULL
};

static RCoreHelpMessage help_msg_sl = {
	"Usage:", "sl+ or sl- or slc", "",
	"sl", " [line]", "seek to absolute line",
	"sl", "[+-][line]", "seek to relative line",
	"slc", "", "clear line cache",
	"sll", "", "show total number of lines",
	"sleep", " [seconds]", "sleep for an specific amount of time (support decimal values)",
	NULL
};

static RCoreHelpMessage help_msg_ss = {
	"Usage: ss", "", " # Seek silently (not recorded in the seek history)",
	"s?", "", "works with all s subcommands, for example ssr = silent 'sr'",
	NULL
};

static void __init_seek_line(RCore *core) {
	r_config_bump (core->config, "lines.to");
	ut64 from = r_config_get_i (core->config, "lines.from");
	const char *to_str = r_config_get (core->config, "lines.to");
	ut64 to = r_num_math (core->num, (to_str && *to_str) ? to_str : "$s");
	if (r_core_lines_initcache (core, from, to) == -1) {
		R_LOG_ERROR ("lines.from and lines.to are not defined");
	}
}

static void printPadded(RCore *core, int pad) {
	if (pad < 1) {
		pad = 8;
	}
	char *fmt = r_str_newf ("0x%%0%d" PFMT64x, pad);
	char *off = r_str_newf (fmt, core->addr);
	r_kons_printf (core->cons, "%s\n", off);
	free (off);
	free (fmt);
}

static void __get_current_line(RCore *core) {
	if (core->print->lines_cache_sz > 0) {
		int curr = r_util_lines_getline (core->print->lines_cache, core->print->lines_cache_sz, core->addr);
		r_kons_printf (core->cons, "%d\n", curr);
	}
}

static void __seek_line_absolute(RCore *core, int numline) {
	if (numline < 1 || numline > core->print->lines_cache_sz - 1) {
		R_LOG_ERROR ("Line must be between 1 and %d", core->print->lines_cache_sz - 1);
	} else {
		r_core_seek (core, core->print->lines_cache[numline - 1], true);
	}
}

static void __seek_line_relative(RCore *core, int numlines) {
	int curr = r_util_lines_getline (core->print->lines_cache, core->print->lines_cache_sz, core->addr);
	if (numlines > 0 && curr + numlines >= core->print->lines_cache_sz - 1) {
		R_LOG_ERROR ("Line must be < %d", core->print->lines_cache_sz - 1);
	} else if (numlines < 0 && curr + numlines < 1) {
		R_LOG_ERROR ("Line must be > 1");
	} else {
		r_core_seek (core, core->print->lines_cache[curr + numlines - 1], true);
	}
}

static void __clean_lines_cache(RCore *core) {
	core->print->lines_cache_sz = -1;
	R_FREE (core->print->lines_cache);
}

R_API int r_core_lines_currline(RCore *core) {  // make priv8 again
	int imin = 0;
	int imax = core->print->lines_cache_sz;
	int imid = 0;

	while (imin <= imax) {
		imid = imin + ((imax - imin) / 2);
		if (core->print->lines_cache[imid] == core->addr) {
			return imid;
		} else if (core->print->lines_cache[imid] < core->addr) {
			imin = imid + 1;
		} else {
			imax = imid - 1;
		}
	}
	return imin;
}

R_API int r_core_lines_initcache(RCore *core, ut64 start_addr, ut64 end_addr) {
	int i, bsz = core->blocksize;
	ut64 off = start_addr;
	if (start_addr == UT64_MAX || end_addr == UT64_MAX) {
		return -1;
	}

	ut64 *lines_cache = R_NEWS0 (ut64, bsz);
	if (!lines_cache) {
		return -1;
	}
	free (core->print->lines_cache);
	core->print->lines_cache = lines_cache;

	ut64 baddr = r_config_get_i (core->config, "bin.baddr");

	int line_count = start_addr? 0: 1;
	core->print->lines_cache[0] = start_addr? 0: baddr;
	char *buf = malloc (bsz);
	if (!buf) {
		return -1;
	}
	r_cons_break_push (NULL, NULL);
	while (off < end_addr) {
		if (r_kons_is_breaked (core->cons)) {
			break;
		}
		r_io_read_at (core->io, off, (ut8 *) buf, bsz);
		for (i = 0; i < bsz; i++) {
			if (buf[i] != '\n') {
				continue;
			}
			if ((line_count + 1) >= bsz) {
				break;
			}
			core->print->lines_cache[line_count] = start_addr? off + i + 1: off + i + 1 + baddr;
			line_count++;
			if (line_count % bsz == 0) {
				ut64 *tmp = realloc (core->print->lines_cache,
					(line_count + bsz) * sizeof (ut64));
				if (tmp) {
					core->print->lines_cache = tmp;
				} else {
					R_FREE (core->print->lines_cache);
					line_count = -1;
					break;
				}
			}
		}
		off += bsz;
	}
	free (buf);
	r_cons_break_pop ();
	return line_count;
}

static void seek_to_register(RCore *core, const char *input, bool is_silent) {
	if (r_config_get_b (core->config, "cfg.debug")) {
		ut64 off = r_debug_reg_get (core->dbg, input);
		if (!is_silent) {
			r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
		}
		r_core_seek (core, off, true);
	} else {
		RReg *orig = core->dbg->reg;
		core->dbg->reg = core->anal->reg;
		ut64 off = r_debug_reg_get (core->dbg, input);
		core->dbg->reg = orig;
		if (!is_silent) {
			r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
		}
		r_core_seek (core, off, true);
	}
}

static int cmd_sort(void *data, const char *input) { // "sort"
	RCore *core = (RCore *)data;
	const char *arg = strchr (input, ' ');
	if (arg) {
		arg = r_str_trim_head_ro (arg + 1);
	}
	switch (*input) {
	case '?': // "sort?"
		r_core_cmd_help_match (core, help_msg_s, "sort");
		break;
	default: // "ls"
		if (!arg) {
			arg = "";
		}
		if (r_fs_check (core->fs, arg)) {
			r_core_cmdf (core, "md %s", arg);
		} else {
			char *res = r_syscmd_sort (arg);
			if (res) {
				r_kons_print (core->cons, res);
				free (res);
			}
		}
		break;
	}
	return 0;
}

static int cmd_seek_opcode_backward(RCore *core, int numinstr) {
	int i, val = 0;
	// N previous instructions
	ut64 addr = core->addr;
	int ret = 0;
	if (r_core_prevop_addr (core, core->addr, numinstr, &addr)) {
		ret = core->addr - addr;
	} else {
#if 0
		// core_asm_bwdis_len is buggy as hell we should kill it. seems like prevop_addr
		// works as expected, because is the one used from visual
		ret = r_core_asm_bwdis_len (core, &instr_len, &addr, numinstr);
#endif
		addr = core->addr;
		const int mininstrsize = r_anal_archinfo (core->anal, R_ARCH_INFO_MINOP_SIZE);
		for (i = 0; i < numinstr; i++) {
			ut64 prev_addr = r_core_prevop_addr_force (core, addr, 1);
			if (prev_addr == UT64_MAX) {
				prev_addr = addr - mininstrsize;
			}
			if (prev_addr == UT64_MAX || prev_addr >= core->addr) {
				break;
			}
			RAnalOp op = {0};
			r_core_seek (core, prev_addr, true);
			r_asm_disassemble (core->rasm, &op, core->block, 32);
			if (op.size < mininstrsize) {
				op.size = mininstrsize;
			}
			val += op.size;
			addr = prev_addr;
			r_asm_op_fini (&op);
		}
	}
	r_core_seek (core, addr, true);
	val += ret;
	return val;
}

static int cmd_seek_opcode_forward(RCore *core, int n) {
	// N forward instructions
	int i, ret, val = 0;
	for (val = i = 0; i < n; i++) {
		RAnalOp op;
		ret = r_anal_op (core->anal, &op, core->addr, core->block,
			core->blocksize, R_ARCH_OP_MASK_BASIC);
		if (ret < 1) {
			ret = 1;
		}
		r_core_seek_delta (core, ret);
		r_anal_op_fini (&op);
		val += ret;
	}
	return val;
}

static void cmd_seek_opcode(RCore *core, const char *input) {
	if (!strcmp (input, "-")) {
		input = "-1";
	}
	int n = r_num_math (core->num, input);
	if (n == 0) {
		n = 1;
	}
	int val = (n < 0)
		? cmd_seek_opcode_backward (core, -n)
		: cmd_seek_opcode_forward (core, n);
	r_core_return_value (core, val);
}

static int cmd_seek(void *data, const char *input) {
	RCore *core = (RCore *) data;
	char *cmd, *p;
	ut64 off = core->addr;

	if (!*input) {
		r_kons_printf (core->cons, "0x%"PFMT64x "\n", core->addr);
		return 0;
	}
	char *ptr;
	if ((ptr = strstr (input, "+."))) {
		char *dup = strdup (input);
		dup[ptr - input] = '\x00';
		off = r_num_math (core->num, dup + 1);
		core->addr = off;
		free (dup);
	}
	const char *inputnum = strchr (input, ' ');
	if (!r_str_startswith (input, "ort")) { // hack to handle Invalid Argument for sort
		const char *u_num = inputnum? inputnum + 1: input + 1;
		off = r_num_math (core->num, u_num);
		if (*u_num == '-') {
			off = -(st64)off;
		}
	}
#if 1
//	int sign = 1;
	if (input[0] == ' ') {
		switch (input[1]) {
		case '-':
//			sign = -1;
			/* pass thru */
		case '+':
			input++;
			break;
		}
	}
#endif
	// this makes adds all the subcommands of s under ss which breaks some logics
	bool silent = false;
	if (*input == 's') {
		silent = true;
		input++;
		switch (*input) {
		case '?':
		case 0:
			r_core_cmd_help (core, help_msg_ss);
			return 0;
		}
	}

	switch (*input) {
	case 'r': // "sr"
		if (input[1] && input[2]) {
			seek_to_register (core, input + 2, silent);
		} else {
			r_core_cmd_help_contains (core, help_msg_s, "sr");
		}
		break;
	case 'd': // "sd"
		{
			st64 delta;
			ut64 at = core->addr;
			char *ro = r_core_get_reloff (core, RELOFF_TO_FLAG, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "flag %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
			ro = r_core_get_reloff (core, RELOFF_TO_FUNC, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "func %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
			ro = r_core_get_reloff (core, RELOFF_TO_MAPS, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "maps %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
			ro = r_core_get_reloff (core, RELOFF_TO_FILE, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "file %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
			ro = r_core_get_reloff (core, RELOFF_TO_FMAP, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "fmap %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
			ro = r_core_get_reloff (core, RELOFF_TO_LIBS, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "libs %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
			ro = r_core_get_reloff (core, RELOFF_TO_SYMB, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "symb %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
			ro = r_core_get_reloff (core, RELOFF_TO_SECT, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "sect %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
			ro = r_core_get_reloff (core, RELOFF_TO_DMAP, at, &delta);
			if (ro) {
				r_kons_printf (core->cons, "dmap %s+0x%"PFMT64x"\n", ro, delta);
				free (ro);
			}
		}
		break;
	case 'C': // "sC"
		if (input[1] == '*') { // "sC*"
			r_core_cmd0 (core, "C*~^\"CC");
		} else if (input[1] == ' ') {
			RIntervalTreeIter it;
			RAnalMetaItem *meta;
			bool seeked = false;
			r_interval_tree_foreach (&core->anal->meta, it, meta) {
				if (meta->type == R_META_TYPE_COMMENT && !strcmp (meta->str, input + 2)) {
					if (!silent) {
						r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
					}
					r_core_seek (core, off, true);
					r_core_block_read (core);
					seeked = true;
					break;
				}
			}
			if (!seeked) {
				R_LOG_ERROR ("No matching comment");
			}
		} else {
			r_core_cmd_help (core, help_msg_sC);
		}
		break;
	case '0': // "s0"
	case '1': // "s1"
	case '2': // "s2"
	case '3': // "s3"
	case '4': // "s4"
	case '5': // "s5"
	case '6': // "s6"
	case '7': // "s7"
	case '8': // "s8"
	case '9': // "s9"
	case ' ': // "s "
	{
		const char *trimin = r_str_trim_head_ro (input);
		ut64 addr = r_num_math (core->num, trimin);
		if (core->num->nc.errors) { // TODO expose an api for this char *r_num_failed();
			if (core->cons->context->is_interactive) {
				R_LOG_ERROR ("Cannot seek to unknown address '%s'", trimin);
			}
			break;
		}
		if (!silent) {
			r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
		}
		r_core_seek (core, addr, true);
		r_core_block_read (core);
	}
	break;
	case '/': // "s/"
	{
		const char *pfx = r_config_get (core->config, "search.prefix");
		const ut64 saved_from = r_config_get_i (core->config, "search.from");
		const ut64 saved_maxhits = r_config_get_i (core->config, "search.maxhits");
// kwidx cfg var is ignored
		int kwidx = core->search->n_kws; // (int)r_config_get_i (core->config, "search.kwidx")-1;
		if (kwidx < 0) {
			kwidx = 0;
		}
		switch (input[1]) {
		case ' ':
		case 'v':
		case 'V':
		case 'w':
		case 'W':
		case 'z':
		case 'm':
		case 'c':
		case 'A':
		case 'e':
		case 'E':
		case 'i':
		case 'R':
		case 'r':
		case '/':
		case 'x':
			r_config_set_i (core->config, "search.from", core->addr + 1);
			r_config_set_i (core->config, "search.maxhits", 1);
			r_core_cmdf (core, "s+1; %s; s-1; s %s%d_0; f-%s%d_0",
				input, pfx, kwidx, pfx, kwidx);
			r_config_set_i (core->config, "search.from", saved_from);
			r_config_set_i (core->config, "search.maxhits", saved_maxhits);
			break;
		case '?':
			r_core_cmd_help_contains (core, help_msg_s, "s/");
			break;
		default:
			R_LOG_ERROR ("unknown search subcommand");
			break;
		}
	}
	break;
	case '.': // "s." "s.."
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_sdot);
		} else if (input[1]) {
			for (input++; *input == '.'; input++) {
				;
			}
			r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
			r_core_seek_base (core, input);
		} else {
			// just re-read the current block
			r_core_seek (core, core->addr, true);
			r_core_block_read (core);
		}
		break;
	case 'j':  // "sj"
		{
			RList /*<ut64 *>*/ *addrs = r_list_newf (free);
			RList /*<char *>*/ *names = r_list_newf (free);
			RList *list = r_io_sundo_list (core->io, '!');
			ut64 lsz = 0;
			ut64 i;
			RListIter *iter;
			RIOUndos *undo;
			if (list) {
				r_list_foreach (list, iter, undo) {
					char *name = NULL;

					RFlagItem *f = r_flag_get_at (core->flags, undo->off, true);
					if (f) {
						if (f->addr != undo->off) {
							name = r_str_newf ("%s+%d", f->name,
									(int)(undo->off - f->addr));
						} else {
							name = strdup (f->name);
						}
					}
					if (!name) {
						name = strdup ("");
					}
					ut64 *val = malloc (sizeof (ut64));
					if (!val) {
						free (name);
						break;
					}
					*val = undo->off;
					r_list_append (addrs, val);
					r_list_append (names, strdup (name));
					lsz++;
					free (name);
				}
				r_list_free (list);
			}
			PJ *pj = r_core_pj_new (core);
			pj_a (pj);
			for (i = 0; i < lsz; i++) {
				ut64 *addr = r_list_get_n (addrs, i);
				const char *name = r_list_get_n (names, i);
				pj_o (pj);
				pj_kn (pj, "offset", *addr);
				if (name && *name) {
					pj_ks (pj, "name", name);
				}
				if (core->io->undo.undos == i) {
					pj_kb (pj, "current", true);
				}
				pj_end (pj);
			}
			pj_end (pj);
			char *s = pj_drain (pj);
			r_kons_printf (core->cons, "%s\n", s);
			free (s);
			r_list_free (addrs);
			r_list_free (names);
		}
		break;
	case '*': // "s*"
	case '=': // "s="
	case '!': // "s!"
		{
			char mode = input[0];
			if (input[1] == '=') {
				mode = 0;
			} else if (input[1] == '*') {
				mode = 'r';
			}
			RList *list = r_io_sundo_list (core->io, mode);
			if (list) {
				RListIter *iter;
				RIOUndos *undo;
				r_list_foreach (list, iter, undo) {
					char *name = NULL;

					RFlagItem *f = r_flag_get_at (core->flags, undo->off, true);
					if (f) {
						if (f->addr != undo->off) {
							name = r_str_newf ("%s + %d\n", f->name,
									(int)(undo->off - f->addr));
						} else {
							name = strdup (f->name);
						}
					}
					if (mode) {
						r_kons_printf (core->cons, "0x%"PFMT64x" %s\n", undo->off, r_str_get (name));
					} else {
						if (!name) {
							name = r_str_newf ("0x%"PFMT64x, undo->off);
						}
						r_kons_printf (core->cons, "%s%s", name, iter->n? " > ":"");
					}
					free (name);
				}
				r_list_free (list);
				if (!mode) {
					r_cons_newline (core->cons);
				}
			}
		}
		break;
	case '+': // "s+"
		if (input[1] != '\0') {
			st64 delta = off;
			if (input[1] == '+') {
				delta = core->blocksize;
				st64 mult = r_num_math (core->num, input + 2);
				if (mult > 0) {
					delta /= mult;
				}
			}
			// int delta = (input[1] == '+')? core->blocksize: off;
			if (!silent) {
				r_io_sundo_push (core->io, core->addr,
					r_print_get_cursor (core->print));
			}
			r_core_seek_delta (core, delta);
			r_core_block_read (core);
		} else {
			RIOUndos *undo = r_io_sundo_redo (core->io);
			if (undo) {
				r_core_seek (core, undo->off, false);
				r_core_block_read (core);
			}
		}
		break;
	case '-': // "s-"
		switch (input[1]) {
		case '*': // "s-*"
			r_io_sundo_reset (core->io);
			break;
		case 0: // "s-"
			{
				RIOUndos *undo = r_io_sundo (core->io, core->addr);
				if (undo) {
					r_core_seek (core, undo->off, false);
					r_core_block_read (core);
				}
			}
			break;
		case '-': // "s--"
		default:
			{
				st64 delta = -(st64)off;
				if (input[1] == '-') {
					delta = -(st64)core->blocksize;
					int mult = r_num_math (core->num, input + 2);
					if (mult > 0) {
						delta /= mult;
					}
				}
				if (!silent) {
					r_io_sundo_push (core->io, core->addr,
							r_print_get_cursor (core->print));
				}
				r_core_seek_delta (core, delta);
				r_core_block_read (core);
			}
		break;
		}
		break;
	case 'n': // "sn"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_sn);
		} else if (input[1] == 'p') { // "snp" - seek next prelude
			__core_cmd_search_backward_prelude (core, true, true);
		} else {
			if (!silent) {
				r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
			}
			const char *nkey = (input[1] == ' ')
				? input + 2
				: r_config_get (core->config, "scr.nkey");
			r_core_seek_next (core, nkey);
		}
		break;
	case 'p': // "sp"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_sp);
		} else if (input[1] == 'p') { // "spp" - seek previous prelude
			__core_cmd_search_backward_prelude (core, true, false);
		} else {
			if (!silent) {
				r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
			}
			const char *nkey = (input[1] == ' ')
				? input + 2
				: r_config_get (core->config, "scr.nkey");
			r_core_seek_previous (core, nkey);
		}
		break;
	case 'a': // "sa"
		if (input[1] == 0 || input[1] == ' ') {
			off = core->blocksize;
			if (input[1] && input[2]) {
				cmd = strdup (input);
				p = strchr (cmd + 2, ' ');
				if (p) {
					off = r_num_math (core->num, p + 1);
					*p = '\0';
				}
				cmd[0] = 's';
				// perform real seek if provided
				r_cmd_call (core->rcmd, cmd);
				free (cmd);
			}
			if (!silent) {
				r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
			}
			r_core_seek_align (core, off, 0);
		} else {
			r_core_cmd_help_contains (core, help_msg_s, "sa");
		}
		break;
	case 'b': // "sb"
		if (input[1] == 0 || input[1] == ' ') {
			if (off == 0) {
				off = core->addr;
			}
			if (!silent) {
				r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
			}
			r_core_anal_bb_seek (core, off);
		} else {
			r_core_cmd_help_contains (core, help_msg_s, "sb");
		}
		break;
	case 'f': { // "sf"
		RAnalFunction *fcn;
		switch (input[1]) {
		case '\0': // "sf"
			fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
			if (fcn) {
				r_core_seek (core, r_anal_function_max_addr (fcn), true);
			}
			break;
		case ' ': // "sf "
			fcn = r_anal_get_function_byname (core->anal, input + 2);
			if (fcn) {
				r_core_seek (core, fcn->addr, true);
			}
			break;
		case '.': // "sf."
			fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
			if (fcn) {
				r_core_seek (core, fcn->addr, true);
			}
			break;
		case 'p': // "sfp"
			// find function prelude backwards
			r_core_cmd0 (core, "s `ap`");
			break;
		case 'f': // "sff"
			// find function prelude backwards
			r_core_cmd0 (core, "s `fd~[0]`");
			break;
		default:
			r_core_cmd_help_contains (core, help_msg_s, "sf");
			break;
		}
		break;
	}
	case 'o': // "so"
		switch (input[1]) {
		case 'r':
			if (input[2] == 't') {
				cmd_sort (core, input);
			} else if (input[2] == '?') {
				r_core_cmd_help_match (core, help_msg_s, "sort");
			} else {
				return -1;
			}
			break;
		case '?':
			r_core_cmd_help_contains (core, help_msg_s, "so");
		case ' ':
		case '\0':
		case '+':
		case '-':
			cmd_seek_opcode (core, input + 1);
			break;
		default:
			return -1; // invalid command
		}
		break;
	case 'g': // "sg"
		if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_s, "sg");
		} else {
			RIOMap *map  = r_io_map_get_at (core->io, core->addr);
			if (map) {
				r_core_seek (core, r_io_map_begin (map), true);
			} else {
				r_core_seek (core, 0, true);
			}
		}
		break;
	case 'G': // "sG"
		if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_s, "sG");
		} else {
			if (!core->io->desc) {
				break;
			}
			RIOMap *map = r_io_map_get_at (core->io, core->addr);
			// XXX: this +2 is a hack. must fix gap between sections
			if (map) {
				r_core_seek (core, r_io_map_end (map) + 2, true);
			} else {
				r_core_seek (core, r_io_fd_size (core->io, core->io->desc->fd), true);
			}
		}
		break;
	case 'h': // "sh"
		if (input[1] == '?') {
			r_core_cmd_help (core, help_msg_sh);
		} else {
			char *arg = r_str_trim_dup (input + 1);
			if (R_STR_ISNOTEMPTY (arg)) {
				int rc = r_sys_tem (arg);
				r_core_return_value (core, (rc > 0)? rc: 1);
			} else {
				if (r_config_get_b (core->config, "scr.interactive")) {
					// open shell
					r_line_set_prompt (core->cons->line, "sh> ");
					for (;;) {
						const char *line = r_line_readline (core->cons);
						if (!line || !strcmp (line, "exit")) {
							break;
						}
						int rc = r_sys_tem (line);
						r_core_return_value (core, (rc > 0)? rc: 1);
					}
				} else {
					R_LOG_WARN ("enable scr.interactive to use this new shell prompt");
				}
			}
			free (arg);
		}
		break;
	case 'l': // "sl"
	{
		int sl_arg = r_num_math (core->num, input + 1);
		switch (input[1]) {
		case 'e': // "sleep"
			{
				const char *arg = strchr (input, ' ');
				if (arg) {
					arg++;
					void *bed = r_cons_sleep_begin ();
					if (strchr (arg, '.')) {
						double d = 0;
						sscanf (arg, "%lf", &d);
						r_sys_usleep ((int)(d * 1000000));
					} else {
						r_sys_sleep (atoi (arg));
					}
					r_cons_sleep_end (bed);
				} else {
					r_core_cmd_help_match (core, help_msg_sl, "sleep");
				}
			}
			break;
		case '\0': // "sl"
			if (!core->print->lines_cache) {
				__init_seek_line (core);
			}
			__get_current_line (core);
			break;
		case ' ': // "sl "
			if (!core->print->lines_cache) {
				__init_seek_line (core);
			}
			__seek_line_absolute (core, sl_arg);
			break;
		case '+': // "sl+"
		case '-': // "sl-"
			if (!core->print->lines_cache) {
				__init_seek_line (core);
			}
			__seek_line_relative (core, sl_arg);
			break;
		case 'c': // "slc"
			__clean_lines_cache (core);
			break;
		case 'l': // "sll"
			if (!core->print->lines_cache) {
				__init_seek_line (core);
			}
			r_kons_printf (core->cons, "%d\n", core->print->lines_cache_sz - 1);
			break;
		case '?': // "sl?"
			r_core_cmd_help (core, help_msg_sl);
			break;
		}
	}
	break;
	case ':': // "s:"
		printPadded (core, atoi (input + 1));
		break;
	case '?': // "s?"
		r_core_cmd_help (core, help_msg_s);
		break;
	default:
		if (input[0] && input[1]) {
			ut64 n = r_num_math (core->num, input);
			if (n) {
				if (!silent) {
					r_io_sundo_push (core->io, core->addr, r_print_get_cursor (core->print));
				}
				r_core_seek (core, n, true);
				r_core_block_read (core);
			}
		} else {
			R_LOG_ERROR ("Invalid s subcommand");
		}
		break;
	}
	return 0;
}

#endif
