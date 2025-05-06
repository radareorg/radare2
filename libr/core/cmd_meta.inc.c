/* radare2 - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

// R2R db/cmd/cmd_meta

char *getcommapath(RCore *core);

typedef struct {
	ut64 filter_offset;
	int filter_format;
	size_t filter_count;
	PJ *pj;
	Sdb *fscache;
} FilterStruct;

static RCoreHelpMessage help_msg_C = {
	"Usage:", "C[-LCvsdfm*?][*?] [...]", " # Metadata management",
	"C", "", "list meta info in human friendly form",
	"C*", "", "list meta info in r2 commands",
	"C*.", "", "list meta info of current offset in r2 commands",
	"C-", " [len] [[@]addr]", "delete metadata at given address range",
	"C.", "", "list meta info of current offset in human friendly form",
	"CC!", " [@addr]", "edit comment with $EDITOR",
	"CC", "[?] [-] [comment-text] [@addr]", "add/remove comment",
	"CC.", "[addr]", "show comment in current address",
	"CCa", "[+-] [addr] [text]", "add/remove comment at given address",
	"CCu", " [comment-text] [@addr]", "add unique comment",
	"CF", "[sz] [fcn-sign..] [@addr]", "function signature",
	"CL", "[-][*] [file:line] [addr]", "show or add 'code line' information (bininfo)",
	"CS", "[-][space]", "manage meta-spaces to filter comments, etc..",
	"C[Cthsdmf]", "", "list comments/types/hidden/strings/data/magic/formatted in human friendly form",
	"C[Cthsdmf]*", "", "list comments/types/hidden/strings/data/magic/formatted in r2 commands",
	"Cd", "[-] [size] [repeat] [@addr]", "hexdump data array (Cd 4 10 == dword [10])",
	"Cd.", " [@addr]", "show size of data at current address",
	"Cf", "[?][-] [sz] [0|cnt][fmt] [a0 a1...] [@addr]", "format memory (see pf?)",
	"Cb", "[?][-] [addr] [@addr]", "bind both addresses for reflines purposes",
	"Cr", "[?][-] [sz] [r2cmd] [@addr]", "run the given command to replace SZ bytes in the disasm",
	"Ch", "[-] [size] [@addr]", "hide data",
	"Cm", "[-] [sz] [fmt..] [@addr]", "magic parse (see pm?)",
	"Cs", "[?] [-] [size] [@addr]", "add string",
	"Ct", "[?] [-] [comment-text] [@addr]", "add/remove type analysis comment",
	"Ct.", "[@addr]", "show comment at current or specified address",
	"Cv", "[?][bsr]", "add comments to args",
	"Cz", "[@addr]", "add string (see Cs?)",
	NULL
};

static RCoreHelpMessage help_msg_CC = {
	"Usage:", "CC[-+!*au] [base64:..|str] @ addr", "",
	"CC!", "", "edit comment using cfg.editor (vim, ..)",
	"CC", " [text]", "append comment at current address",
	"CC", "", "list all comments in human friendly form",
	"CC*", "", "list all comments in r2 commands",
	"CC+", " [text]", "append comment at current address",
	"CC,", " [table-query]", "list comments in table format",
	"CCF", " [file]", "show or set comment file",
	"CC-", " @ cmt_addr", "remove comment at given address",
	"CC.", "", "show comment at current offset",
	"CCf", "", "list comments in function",
	"CCf-", "", "delete all comments in current function",
	"CCu", " base64:AA== @ addr", "add comment in base64",
	"CCu", " good boy @ addr", "add good boy comment at given address",
	NULL
};

// IMHO 'code-line' should be universal concept, instead of dbginfo/dwarf/...
static RCoreHelpMessage help_msg_CL = {
	"Usage: CL", ".j-", "@addr - manage code-line references (loaded via bin.dbginfo and shown when asm.dwarf)",
	"CL", "", "list all code line information (virtual address <-> source file:line)",
	"CLf", " [addr]", "show filename for current or given offset",
	"CLj", "", "same as above but in JSON format (See dir.source to change the path to find the referenced lines)",
	"CL*", "", "same as above but in r2 commands format",
	"CL.", "", "show list all code line information (virtual address <-> source file:line)",
	"CL-", "*", "remove all the cached codeline information",
	"CLL", "[f]", "show source code line associated to current offset",
	"CLLf", "", "show source lines covered by the current function (see CLL@@i or list)",
	"CL+", "file:line @ addr", "register new file:line source details, r2 will slurp the line",
	"CL", " addr file:line", "register new file:line source details, r2 will slurp the line",
	"CL", " addr base64:text", "register new source details for given address using base64",
	NULL
};

static RCoreHelpMessage help_msg_Ct = {
	"Usage: Ct", "[.|-] [@ addr]", " # Manage comments for variable types",
	"Ct", "", "list all variable type comments",
	"Ct", " comment-text [@ addr]", "place comment at current or specified address",
	"Ct.", " [@ addr]", "show comment at current or specified address",
	"Ct-", " [@ addr]", "remove comment at current or specified address",
	NULL
};

static RCoreHelpMessage help_msg_CS = {
	"Usage: CS", "[*] [+-][metaspace|addr]", " # Manage metaspaces",
	"CS", "", "display metaspaces",
	"CS", " *", "select all metaspaces",
	"CS", " metaspace", "select metaspace or create if it doesn't exist",
	"CS", "-metaspace", "remove metaspace",
	"CS", "-*", "remove all metaspaces",
	"CS", "+foo", "push previous metaspace and set",
	"CS", "-", "pop to the previous metaspace",
	//	"CSm", " [addr]", "move metas at given address to the current metaspace",
	"CSr", " newname", "rename selected metaspace",
	NULL
};

static RCoreHelpMessage help_msg_Cs = {
	"Usage:", "Cs[ga-*.] ([size]) [@addr]", "",
	"Cs", " [size] @addr", "add string (guess latin1/utf16le)",
	"Cs", "", "list all strings in human friendly form",
	"Cs*", "", "list all strings in r2 commands",
	"Cs-", " [@addr]", "remove string",
	"Cs.", "", "show string at current address",
	"Cs..", "", "show string + info about it at current address",
	"Cs.j", "", "show string at current address in JSON",
	"Cs8", " [size] ([@addr])", "add utf8 string",
	"Csa", " [size] ([@addr])", "add ascii/latin1 string",
	"Csg", " [size] ([@addr])", "as above but addr not needed",
	"Csw", " [size] ([@addr])", "add wide string (utf16)",
	"Csz", " [size] ([@addr])", "define zero terminated strings (with size as maxlen)",
	"Css", " ([range]) ([@addr])", "define all strings found in given range or section",
	"Cz", " [size] [@addr]", "Alias for Csz",
	NULL
};

static RCoreHelpMessage help_msg_Cvb = {
	"Usage:", "Cvb", "[name] [comment]",
	"Cvb?", "", "show this help",
	"Cvb", "", "list all base pointer args/vars comments in human friendly format",
	"Cvb*", "", "list all base pointer args/vars comments in r2 format",
	"Cvb-", "[name]", "delete comments for var/arg at current offset for base pointer",
	"Cvb", " [name]", "show comments for var/arg at current offset for base pointer",
	"Cvb", " [name] [comment]", "add/append comment for the variable with the current name",
	"Cvb!", "[name]", "edit comment using cfg editor",
	NULL
};

static RCoreHelpMessage help_msg_Cvr = {
	"Usage:", "Cvr", "[name] [comment]",
	"Cvr?", "", "show this help",
	"Cvr", "", "list all register based args comments in human friendly format",
	"Cvr*", "", "list all register based args comments in r2 format",
	"Cvr-", "[name]", "delete comments for register based arg for that name",
	"Cvr", "[name]", "show comments for register based arg for that name",
	"Cvr", "[name] [comment]", "add/append comment for the variable",
	"Cvr!", "[name]", "edit comment using cfg editor",
	NULL
};

static RCoreHelpMessage help_msg_Cvs = {
	"Usage:", "Cvs", "[name] [comment]",
	"Cvs!", "[name]", "edit comment using cfg editor",
	"Cvs", "", "list all stack based args/vars comments in human friendly format",
	"Cvs", "[name] [comment]", "add/append comment for the variable",
	"Cvs", "[name]", "show comments for stack pointer var/arg with that name",
	"Cvs*", "", "list all stack based args/vars comments in r2 format",
	"Cvs-", "[name]", "delete comments for stack pointer var/arg with that name",
	"Cvs?", "", "show this help",
	NULL
};

static bool print_meta_offset(RCore *core, ut64 addr, PJ *pj) {
	RBinAddrline *al = r_bin_addrline_get (core->bin, addr);
	if (!al) {
		return false;
	}
	if (pj) {
		pj_o (pj);
		pj_ks (pj, "file", al->file);
		pj_kn (pj, "line", al->line);
		pj_kn (pj, "colu", al->column);
		pj_kn (pj, "addr", addr);
		if (r_file_exists (al->file)) {
			char *row = r_file_slurp_line (al->file, al->line, 0);
			pj_ks (pj, "text", row);
			free (row);
		} else {
			// R_LOG_ERROR ("Cannot open '%s'", file);
		}
		pj_end (pj);
		return true;
	}
	int line = al->line;

	r_cons_printf ("file: %s\nline: %d\ncolu: %d\naddr: 0x%08"PFMT64x"\n", al->file, line, al->column, addr);
	int line_old = line;
	if (line >= 2) {
		line -= 2;
	}
	if (r_file_exists (al->file)) {
		int i;
		for (i = 0; i < 5; i++) {
			char *row = r_file_slurp_line (al->file, line + i, 0);
			if (row) {
				r_cons_printf ("%c %.3x  %s\n", al->line + i == line_old ? '>' : ' ', line + i, row);
				free (row);
			}
		}
	} else {
		R_LOG_ERROR ("Cannot open '%s'", al->file);
	}
	return true;
}

static bool print_addrinfo_json(void *user, const char *k, const char *v) {
	FilterStruct *fs = (FilterStruct *)user;
	ut64 offset = sdb_atoi (k);
	if (!offset || offset == UT64_MAX) {
		return true;
	}
	char *subst = strdup (v);
	char *colonpos = strchr (subst, '|'); // XXX keep only : for simplicity?
	if (!colonpos) {
		colonpos = strchr (subst, ':');
	}
	if (!colonpos) {
		r_cons_printf ("%s\n", subst);
	}
	if (colonpos && (fs->filter_offset == UT64_MAX || fs->filter_offset == offset)) {
		if (fs->filter_format) {
			*colonpos = ':';
	//		r_cons_printf ("CL %s %s\n", k, subst);
		} else {
			*colonpos = 0;
	//		r_cons_printf ("file: %s\nline: %s\naddr: 0x%08"PFMT64x"\n", subst, colonpos + 1, offset);
		}
		fs->filter_count++;
	}
	const char *file = subst;
	int line = atoi (colonpos + 1);
	ut64 addr = offset;
	PJ *pj = fs->pj;
	if (pj) {
		pj_o (pj);
		pj_ks (pj, "file", file);
		pj_kn (pj, "line", line);
		pj_kn (pj, "addr", addr);
		const char *cached_existance = sdb_const_get (fs->fscache, file, NULL);
		bool file_exists = false;
		if (cached_existance) {
			file_exists = !strcmp (cached_existance, "1");
		} else {
			if (r_file_exists (file)) {
				sdb_set (fs->fscache, file, "1", 0);
			} else {
				sdb_set (fs->fscache, file, "0", 0);
			}
		}
		if (file_exists) {
			char *row = r_file_slurp_line (file, line, 0);
			pj_ks (pj, "text", file);
			free (row);
		}
		pj_end (pj);
	}
	free (subst);
	return true;
}

static bool print_addrinfo2_json(void *user, RBinAddrline *item) {
	FilterStruct *fs = (FilterStruct *)user;
	ut64 offset = item->addr;
	if (!offset || offset == UT64_MAX) {
		return true;
	}
#if 0
	if (colonpos && (fs->filter_offset == UT64_MAX || fs->filter_offset == offset)) {
		if (fs->filter_format) {
			*colonpos = ':';
	//		r_cons_printf ("CL %s %s\n", k, subst);
		} else {
			*colonpos = 0;
	//		r_cons_printf ("file: %s\nline: %s\naddr: 0x%08"PFMT64x"\n", subst, colonpos + 1, offset);
		}
		fs->filter_count++;
	}
#endif
	const char *file = item->file;
	int line = item->line;
	PJ *pj = fs->pj;
	if (pj) {
		pj_o (pj);
		pj_ks (pj, "file", item->file);
		pj_kn (pj, "line", item->line);
		if (item->column > 0) {
			pj_kn (pj, "column", item->column);
		}
		pj_kn (pj, "addr", item->addr);
		const char *cached_existance = sdb_const_get (fs->fscache, file, NULL);
		bool file_exists = false;
		if (cached_existance) {
			file_exists = !strcmp (cached_existance, "1");
		} else {
			if (r_file_exists (file)) {
				sdb_set (fs->fscache, file, "1", 0);
			} else {
				sdb_set (fs->fscache, file, "0", 0);
			}
		}
		if (file_exists) {
			char *row = r_file_slurp_line (file, line, 0);
			pj_ks (pj, "text", file);
			free (row);
		}
		pj_end (pj);
	}
	return true;
}

static bool print_addrinfo2(void *user, RBinAddrline *item) {
	FilterStruct *fs = (FilterStruct*)user;
	ut64 offset = item->addr;
	if (!offset || offset == UT64_MAX) {
		return true;
	}
	if (fs->filter_offset == UT64_MAX || fs->filter_offset == offset) {
		if (fs->filter_format) {
			// TODO add column if defined
			r_cons_printf ("'CL 0x%08"PFMT64x" %s:%d\n", item->addr, item->file, item->line);
		} else {
			r_cons_printf ("file: %s\nline: %d\ncolu: %d\naddr: 0x%08"PFMT64x"\n",
				item->file, item->line, item->column, item->addr);
		}
		fs->filter_count++;
	}
	// TODO: return false if filter_offset is found ?

	return true;
}

// R2_600 - DEPRECATE
static bool print_addrinfo(void *user, const char *k, const char *v) {
	FilterStruct *fs = (FilterStruct*)user;
	ut64 offset = sdb_atoi (k);
	if (!offset || offset == UT64_MAX) {
		return true;
	}
	char *subst = strdup (v);
	char *colonpos = strchr (subst, '|');
	if (!colonpos) {
		colonpos = strchr (subst, ':'); // : for shell and | for db.. imho : everywhere
	}
	if (!colonpos) {
		r_cons_printf ("%s\n", subst);
	} else if (fs->filter_offset == UT64_MAX || fs->filter_offset == offset) {
		if (fs->filter_format) {
			*colonpos = ':';
			r_cons_printf ("'CL %s %s\n", k, subst);
		} else {
			*colonpos++ = 0;
			int line = atoi (colonpos);
			int colu = 0;
			char *columnpos = strchr (colonpos, '|');
			if (columnpos) {
				*columnpos ++ = 0;
				colu = atoi (columnpos);
			}
			r_cons_printf ("file: %s\nline: %d\ncolu: %d\naddr: 0x%08"PFMT64x"\n",
				subst, line, colu, offset);
		}
		fs->filter_count++;
	}
	free (subst);

	return true;
}

static int cmd_meta_add_fileline(RBinFile *bf, const char *fileline, ut64 offset) {
#if 1
	char *file = strdup (fileline);
	char *line = strchr (file, ':');
	if (line) {
		*line++ = 0;
	}
	RBinAddrline item = {
		.addr = offset,
		.file = file,
		.line = line? atoi (line): 0,
	};
	bf->addrline.al_add (&bf->addrline, item);
	free (file);
#else
	Sdb *s = bf->sdb_addrinfo;
	char aoffset[SDB_NUM_BUFSZ];
	char *aoffsetptr = sdb_itoa (offset, 16, aoffset, sizeof (aoffset));
	if (!aoffsetptr) {
		return -1;
	}
	if (!sdb_add (s, aoffsetptr, fileline, 0)) {
		sdb_set (s, aoffsetptr, fileline, 0);
	}
	if (!sdb_add (s, fileline, aoffsetptr, 0)) {
		sdb_set (s, fileline, aoffsetptr, 0);
	}
#endif
	return 0;
}

static int cmd_meta_lineinfo(RCore *core, const char *input) {
	int ret;
	ut64 offset = UT64_MAX; // use this as error value
	bool remove = false;
	bool use_json = false;
	int all = false;
	const char *p = input;
	char *file_line = NULL;

	FilterStruct fs = { UT64_MAX, 0, 0, NULL };

	if (*p == '?') {
		r_core_cmd_help (core, help_msg_CL);
		return 0;
	}
	if (*p == 'L') { // "CLL"
		if (p[1] == 'f') { // "CLLf"
			r_core_cmd0 (core, "CLL@@i");
			// same as CLL@@i = r_core_cmd0 (core, "list");
			return 0;
		}
		ut64 at = core->addr;
		if (p[1] == ' ') {
			at = r_num_get (core->num, p + 2);
		}
		char *text = r_bin_addrline_tostring (core->bin, at, 0);
		if (R_STR_ISNOTEMPTY (text)) {
			r_cons_printf ("0x%08"PFMT64x"  %s\n", at, text);
		}
		free (text);
		return 0;
	}
	if (*p == 'f') { // "CLf"
		int retries = 5;
		ut64 addr = core->addr;
		if (p[1] == ' ') {
			addr = r_num_math (core->num, p + 1);
		}
retry:
		;
		char *s = r_bin_addrline_tostring (core->bin, addr, 3);
		if (!s) {
			RAnalOp *op = r_core_anal_op (core, addr, 0);
			if (op) {
				addr += op->size;
				r_anal_op_free (op);
				if (retries-- > 0) {
					goto retry;
				}
			}
		}
		if (s) {
			r_str_after (s, ':');
			r_cons_println (s);
			free (s);
			r_core_return_code (core, 0);
		} else {
			r_core_return_code (core, 1);
		}
		return 0;
	}
	if (*p == '-') { // "CL-"
		p++;
		remove = true;
	}
	if (*p == 'j') { // "CLj"
		p++;
		use_json = true;
	}
	if (*p == '.') { // "CL."
		p++;
		offset = core->addr;
	}
	if (*p == '+') { // "CL+"
		offset = core->addr;
		p = r_str_trim_head_ro (p + 1);
		RBinFile *bf = r_bin_cur (core->bin);
		if (bf) {
			ret = cmd_meta_add_fileline (bf, p, offset);
		}
		return 0;
	}
	if (*p == ' ') { // "CL "
		p = r_str_trim_head_ro (p + 1);
		char *arg = strchr (p, ' ');
		if (!arg) {
			offset = r_num_math (core->num, p);
			p = "";
		}
	} else if (*p == '*') {
		p++;
		all = true;
		fs.filter_format = '*';
	} else {
		fs.filter_format = 0;
	}
	if (all && core->bin->cur) {
		if (remove) {
			r_bin_addrline_reset (core->bin);
		} else {
			if (core->bin->cur && core->bin->cur->addrline.used) {
				r_bin_addrline_foreach (core->bin, print_addrinfo2, &fs);
			} else {
				sdb_foreach (core->bin->cur->sdb_addrinfo, print_addrinfo, &fs);
			}
		}
		return 0;
	}

	p = r_str_trim_head_ro (p);
	char *myp = strdup (p);
	char *sp = strchr (myp, ' ');
	if (sp) {
		*sp = 0;
		sp++;
		if (offset == UT64_MAX) {
			offset = r_num_math (core->num, myp);
		}

		char *pheap = NULL;
		if (r_str_startswith (sp, "base64:")) {
			int len = 0;
			ut8 *o = sdb_decode (sp + 7, &len);
			if (!o) {
				R_LOG_ERROR ("Invalid base64");
				return 0;
			}
			sp = pheap = (char *)o;
		}
		RBinFile *bf = r_bin_cur (core->bin);
		if (bf) {
			// R_LOG_ERROR ("deprecated way to add addrinfo metadata");
			ret = cmd_meta_add_fileline (bf, sp, offset);
		} else {
			R_LOG_TODO ("Support global SdbAddrinfo or dummy rbinfile to handle this case");
			ret = 0;
		}
		free (file_line);
		free (myp);
		free (pheap);
		return ret;
	}
	free (myp);
	if (remove) {
		r_bin_addrline_reset_at (core->bin, offset);
	} else {
		// taken from r2 // TODO: we should move this addrinfo sdb logic into RBin.. use HT
		fs.filter_offset = offset;
		fs.filter_count = 0;
		fs.fscache = sdb_new0 ();
		PJ *pj = NULL;
		RBinFile *bf = r_bin_cur (core->bin);
		if (use_json) {
			pj = r_core_pj_new (core);
			fs.pj = pj;
			pj_a (pj);
			if (!r_bin_addrline_foreach (core->bin, print_addrinfo2_json, &fs)) {
				if (bf && bf->sdb_addrinfo) {
					sdb_foreach (bf->sdb_addrinfo, print_addrinfo_json, &fs);
				}
			}
		} else {
			if (!r_bin_addrline_foreach (core->bin, print_addrinfo2, &fs)) {
				if (bf && bf->sdb_addrinfo) {
					sdb_foreach (bf->sdb_addrinfo, print_addrinfo, &fs);
				}
			}
		}
		if (fs.filter_count == 0) {
			print_meta_offset (core, offset, pj);
		}
		if (use_json) {
			pj_end (pj);
			char *s = pj_drain (pj);
			if (s) {
				r_cons_printf ("%s\n", s);
				free (s);
			}
		}
		sdb_free (fs.fscache);
	}
	return 0;
}

static int cmd_meta_comment(RCore *core, const char *input) {
	ut64 addr = core->addr;
	switch (input[1]) {
	case '?':
		r_core_cmd_help (core, help_msg_CC);
		break;
	case ',': // "CC,"
		{
			RTable *t = r_core_table_new (core, "meta");
			r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, ',', input + 2, t);
		}
		break;
	case 'F': // "CC,"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_CC, "CCF");
		} else if (input[2] == ' ') {
			const char *fn = input + 2;
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			fn = r_str_trim_head_ro (fn);
			if (R_STR_ISNOTEMPTY (comment)) {
				// append filename in current comment
				char *nc = r_str_newf ("%s ,(%s)", comment, fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, nc);
				free (nc);
			} else {
				char *newcomment = r_str_newf (",(%s)", fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, newcomment);
				free (newcomment);
			}
		} else {
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			if (R_STR_ISNOTEMPTY (comment)) {
				char *cmtfile = r_str_between (comment, ",(", ")");
				if (R_STR_ISNOTEMPTY (cmtfile)) {
					char *cwd = getcommapath (core);
					r_cons_printf ("%s"R_SYS_DIR"%s\n", cwd, cmtfile);
					free (cwd);
				}
				free (cmtfile);
			}
		}
		break;
	case '.': // "CC."
		{
			ut64 at = input[2]? r_num_math (core->num, input + 2): addr;
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, at);
			if (R_STR_ISNOTEMPTY (comment)) {
				r_cons_println (comment);
			}
		}
		break;
	case 0: // "CC"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 0, NULL, NULL);
		break;
	case 'f': // "CCf"
		switch (input[2]) {
		case '-': // "CCf-"
			{
				ut64 arg = r_num_math (core->num, input + 2);
				if (!arg) {
					arg = core->addr;
				}
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, arg, 0);
				if (fcn) {
					RAnalBlock *bb;
					RListIter *iter;
					r_list_foreach (fcn->bbs, iter, bb) {
						int i;
						for (i = 0; i < bb->size; i++) {
							ut64 addr = bb->addr + i;
							r_meta_del (core->anal, R_META_TYPE_COMMENT, addr, 1);
						}
					}
				}
			}
			break;
		case ',': // "CCf,"
			{
				RTable *t = r_core_table_new (core, "comments");
				r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, ',', core->addr, input + 3, t);
			}
			break;
		case 'j': // "CCfj"
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 'j', core->addr, NULL, NULL);
			break;
		case '*': // "CCf*"
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 1, core->addr, NULL, NULL);
			break;
		default:
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 0, core->addr, NULL, NULL);
			break;
		}
		break;
	case 'j': // "CCj"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 'j', input + 2, NULL);
		break;
	case '!': // "CC!"
		{
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			char *out = r_core_editor (core, NULL, comment);
			if (out) {
				r_str_ansi_strip (out);
				//r_meta_set (core->anal->meta, R_META_TYPE_COMMENT, addr, 0, out);
				r_core_cmd_call_at (core, addr, "CC-");
				//r_meta_del (core->anal->meta, input[0], addr, addr+1);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, out);
				free (out);
			}
		}
		break;
	case '+':
	case ' ':
		{
		const char *arg = r_str_trim_head_ro (input + 2);
		const char *newcomment = arg;
		if (r_str_startswith (arg, "base64:")) {
			char *s = (char *)sdb_decode (arg + 7, NULL);
			if (s) {
				newcomment = s;
			} else {
				R_LOG_ERROR ("Invalid base64 string");
				break;
			}
		}
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
		char *nc = strdup (newcomment);
		r_str_unescape (nc);
		r_str_ansi_strip (nc);
		if (comment) {
			char *text = r_str_newf ("%s %s", comment, nc);
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, text);
			free (text);
		} else {
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, nc);
			if (r_config_get_b (core->config, "cmd.undo")) {
				char *a = r_str_newf ("'CC-0x%08"PFMT64x, addr);
				char *b = r_str_newf ("'@0x%08"PFMT64x"'CC %s", addr, nc);
				RCoreUndo *uc = r_core_undo_new (core->addr, b, a);
				r_core_undo_push (core, uc);
				free (a);
				free (b);
			}
		}
		free (nc);
		}
		break;
	case '*': // "CC*"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 1, NULL, NULL);
		break;
	case '-': // "CC-"
		if (input[2] == '*') { // "CC-*"
			r_meta_del (core->anal, R_META_TYPE_COMMENT, UT64_MAX, UT64_MAX);
		} else if (input[2]) { // "CC-$$+32"
			ut64 arg = r_num_math (core->num, input + 2);
			r_meta_del (core->anal, R_META_TYPE_COMMENT, arg, 1);
		} else { // "CC-"
			r_meta_del (core->anal, R_META_TYPE_COMMENT, core->addr, 1);
		}
		break;
	case 'u': // "CCu"
		{
		const char *arg = input + 2;
		while (*arg && *arg == ' ') {
			arg++;
		}
		char *newcomment = r_str_startswith (arg, "base64:")
			? (char *)sdb_decode (arg + 7, NULL): strdup (arg);
		if (newcomment) {
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			if (!comment || (comment && !strstr (comment, newcomment))) {
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, newcomment);
			}
			free (newcomment);
		}
		}
		break;
	case 'a': // "CCa"
		{
		char *s = strchr (input, ' ');
		if (s) {
			s = strdup (s + 1);
		} else {
			r_core_cmd_help_match (core, help_msg_CC, "CCa");
			return false;
		}
		char *p = strchr (s, ' ');
		if (p) {
			*p++ = 0;
		}
		ut64 addr;
		if (input[2] == '-') {
			if (input[3]) {
				addr = r_num_math (core->num, input+3);
				r_meta_del (core->anal,
						R_META_TYPE_COMMENT,
						addr, 1);
			} else {
				r_core_cmd_help_match (core, help_msg_CC, "CCa");
			}
			free (s);
			return true;
		}
		addr = r_num_math (core->num, s);
		// Comment at
		if (p) {
			if (input[2] == '+') {
				const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
				if (comment) {
					char *text = r_str_newf ("%s\n%s", comment, p);
					r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, 1, text);
					free (text);
				} else {
					r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, 1, p);
				}
			} else {
				r_meta_set (core->anal, R_META_TYPE_COMMENT, addr, 1, p);
			}
		} else {
			r_core_cmd_help_match (core, help_msg_CC, "CCa");
		}
		free (s);
		return true;
		}
	}
	return true;
}

static int cmd_meta_vartype_comment(RCore *core, const char *input) {
	ut64 addr = core->addr;
	switch (input[1]) {
	case '?': // "Ct?"
		r_core_cmd_help (core, help_msg_Ct);
		break;
	case 0: // "Ct"
		r_meta_print_list_all (core->anal, R_META_TYPE_VARTYPE, 0, NULL, NULL);
		break;
	case ' ': // "Ct <vartype comment> @ addr"
		{
		const char* newcomment = r_str_trim_head_ro (input + 2);
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, addr);
		char *nc = strdup (newcomment);
		r_str_unescape (nc);
		if (comment) {
			char *text = r_str_newf ("%s %s", comment, nc);
			if (R_LIKELY (text)) {
				r_meta_set_string (core->anal, R_META_TYPE_VARTYPE, addr, text);
				free (text);
			}
		} else {
			r_meta_set_string (core->anal, R_META_TYPE_VARTYPE, addr, nc);
		}
		free (nc);
		}
		break;
	case '.': // "Ct. @ addr"
		{
		ut64 at = input[2]? r_num_math (core->num, input + 2): addr;
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, at);
		if (R_STR_ISNOTEMPTY (comment)) {
			r_cons_println (comment);
		}
		}
		break;
	case '-': // "Ct-"
		r_meta_del (core->anal, R_META_TYPE_VARTYPE, core->addr, 1);
		break;
	default:
		r_core_cmd_help (core, help_msg_Ct);
		break;
	}
	return true;
}

typedef struct {
	RCore *core;
	ut64 addr;
	ut8 *buf;
	int bufsz;
} StringSearchOptions;

static int cb_strhit(RSearchKeyword * R_NULLABLE kw, void *user, ut64 where) {
	StringSearchOptions *sso = (StringSearchOptions*)user;
	if (where - sso->addr >= sso->bufsz) {
		r_core_cmd_call_at (sso->core, where, "Cz");
	} else {
		const char *name = (const char *)(sso->buf + (where - sso->addr));
		const size_t maxlen = sso->bufsz - (where - sso->addr);
		char *hname = r_str_ndup (name, maxlen);
		const size_t n = strlen (hname) + 1;
		r_meta_set (sso->core->anal, R_META_TYPE_STRING, where, n, hname);
		free (hname);
	}
	return true;
}

static int cmd_meta_others(RCore *core, const char *input) {
	char *t = 0, *p, *p2, name[256] = {0};
	int n, repeat = 1;
	ut64 addr = core->addr;

	int type = input[0];
	if (!type) {
		return 0;
	}
	int subtype = input[1];
	if (type == 's' && subtype == 'z') {
		subtype = 0;
	}

	switch (subtype) {
	case '?':
		switch (input[0]) {
		case 'f': // "Cf?"
			r_core_cmd_help_match (core, help_msg_C, "Cf");
			r_cons_println (
				"'sz' indicates the byte size taken up by struct.\n"
				"'fmt' is a 'pf?' style format string. It controls only the display format.\n\n"
				"You may wish to have 'sz' != sizeof (fmt) when you have a large struct\n"
				"but have only identified specific fields in it. In that case, use 'fmt'\n"
				"to show the fields you know about (perhaps using 'skip' fields), and 'sz'\n"
				"to match the total struct size in mem.\n");
			break;
		case 's': // "Cs?"
			r_core_cmd_help (core, help_msg_Cs);
			break;
		default:
			r_cons_println ("See C?");
			break;
		}
		break;
	case '-': // "Cf-", "Cd-", ...
		switch (input[2]) {
		case '*': // "Cf-*", "Cd-*", ...
			r_meta_del (core->anal, input[0], 0, UT64_MAX);
			break;
		case ' ':
			p2 = strchr (input + 3, ' ');
			if (p2) {
				ut64 i;
				ut64 size = r_num_math (core->num, input + 3);
				ut64 rep = r_num_math (core->num, p2 + 1);
				ut64 cur_addr = addr;
				if (!size) {
					break;
				}
				for (i = 0; i < rep && UT64_MAX - cur_addr > size; i++, cur_addr += size) {
					r_meta_del (core->anal, input[0], cur_addr, size);
				}
				break;
			} else {
				addr = r_num_math (core->num, input + 3);
				/* fallthrough */
			}
		default:
			r_meta_del (core->anal, input[0], addr, 1);
			break;
		}
		break;
	case '*': // "Cf*", "Cd*", ...
		r_meta_print_list_all (core->anal, input[0], 1, NULL, NULL);
		break;
	case 'j': // "Cfj", "Cdj", ...
		r_meta_print_list_all (core->anal, input[0], 'j', NULL, NULL);
		break;
	case '!': // "Cf!", "Cd!", ...
		{
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			char *out = r_core_editor (core, NULL, comment);
			if (out) {
				r_str_ansi_strip (out);
				//r_meta_set (core->anal->meta, R_META_TYPE_COMMENT, addr, 0, out);
				r_core_cmd_call_at (core, addr, "CC-");
				//r_meta_del (core->anal->meta, input[0], addr, addr+1);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, out);
				free (out);
			}
		}
		break;
	case '.': // "Cf.", "Cd.", ...
		if (input[2] == '.') { // "Cs.."
			ut64 size;
			RAnalMetaItem *mi = r_meta_get_at (core->anal, addr, type, &size);
			if (mi) {
				r_meta_print (core->anal, mi, addr, size, input[3], NULL, NULL, false);
			}
			break;
		} else if (input[2] == 'j') { // "Cs.j"
			ut64 size;
			RAnalMetaItem *mi = r_meta_get_at (core->anal, addr, type, &size);
			if (mi) {
				r_meta_print (core->anal, mi, addr, size, input[2], NULL, NULL, false);
				r_cons_newline ();
			}
			break;
		}
		ut64 size;
		RAnalMetaItem *mi = r_meta_get_at (core->anal, addr, type, &size);
		if (!mi) {
			break;
		}
		if (type == 's') {
			char *esc_str;
			bool esc_bslash = core->print->esc_bslash;
			switch (mi->subtype) {
			case R_STRING_ENC_UTF8:
				esc_str = r_str_escape_utf8 (mi->str, false, esc_bslash);
				break;
			case 0: // temporary legacy workaround
				esc_bslash = false;
				// falltrhru
			default:
				esc_str = r_str_escape_latin1 (mi->str, false, esc_bslash, false);
				break;
			}
			if (esc_str) {
				r_cons_printf ("\"%s\"\n", esc_str);
				free (esc_str);
			} else {
				r_cons_println ("<oom>");
			}
		} else if (type == 'd') {
			r_cons_printf ("%"PFMT64u"\n", size);
		} else {
			r_cons_println (mi->str);
		}
		break;
	case 's': // "Css"
		{
			ut64 range = UT64_MAX;
			if (input[0] && input[1] && input[2]) {
				range = r_num_math (core->num, input + 3);
			}
			if (range == UT64_MAX || range == 0) {
				// get cursection size
				RBinSection *s = r_bin_get_section_at (r_bin_cur_object (core->bin), core->addr, true);
				if (s) {
					range = s->vaddr + s->vsize - core->addr;
				}
				// TODO use debug maps if cfg.debug=true?
			}
			if (range == UT64_MAX || range == 0) {
				R_LOG_ERROR ("Invalid memory range passed to Css");
			} else if (range > 32 * 1024 * 1024) {
				R_LOG_ERROR ("Range is too large");
			} else {
				ut8 *buf = malloc (range + 1);
				if (buf) {
					buf[range] = 0;
					const ut64 addr = core->addr;
					const int minstr = r_config_get_i (core->config, "bin.str.min");
					const int maxstr = r_config_get_i (core->config, "bin.str.max");
					r_core_cmdf (core, "Cz@0x%08"PFMT64x, addr);
					// maps are not yet set
					free (r_core_cmd_str (core, "o;om")); // wtf?
					if (!r_io_read_at (core->io, addr, buf, range)) {
						R_LOG_ERROR ("Cannot read %d", range);
					}
					RSearch *ss = r_search_new (R_SEARCH_STRING);
					r_search_set_string_limits (ss, minstr, maxstr);
					StringSearchOptions sso = {
						.addr = addr,
						.core = core,
						.buf = buf,
						.bufsz = range
					};
					// r_print_hexdump (core->print, addr, buf, range, 8,1,1);
					r_search_set_callback (ss, cb_strhit, &sso);
					r_search_begin (ss);
					r_search_update (ss, addr, buf, range);
					r_search_free (ss);
					free (buf);
				} else {
					R_LOG_ERROR ("Cannot allocate");
				}
#if 0
				r_core_cmdf (core, "/z 8 100@0x%08"PFMT64x"@e:search.in=range@e:search.from=0x%"PFMT64x"@e:search.to=0x%"PFMT64x,
						core->addr, core->addr, core->addr + range);
				r_core_cmd0 (core, "Csz @@ hit*;f-hit*");
#else
#endif
			}
		}
		break;
	case ' ': // "Cf", "Cd", ...
	case '\0':
	case 'g':
	case 'a':
	case '1':
	case 'w':
	case 'p':
	case 'b':
	case 'r':
	case '2':
	case '4':
	case '8': // "Cd8"
		if (type == 'd') {  // "Cd4"
			switch (input[1]) {
			case '1':
			case '2':
			case '4':
			case '8':
				input--;
				break;
			}
		}
		if (type == 'z') {
			type = 's';
		} else {
			if (!input[1] && !core->tmpseek) {
				r_meta_print_list_all (core->anal, type, 0, NULL, NULL);
				break;
			}
		}
		int len = (!input[1] || input[1] == ' ') ? 2 : 3;
		if (strlen (input) > len) {
			char *rep = strchr (input + len, '[');
			if (!rep) {
				rep = strchr (input + len, ' ');
			}
			if (*input == 'd') {
				if (rep) {
					repeat = r_num_math (core->num, rep + 1);
				}
			}
		}
		int repcnt = 0;
		if (repeat < 1) {
			repeat = 1;
		}
		while (repcnt < repeat) {
			int off = (!input[1] || input[1] == ' ') ? 1 : 2;
			t = strdup (r_str_trim_head_ro (input + off));
			p = NULL;
			n = 0;
			r_str_ncpy (name, t, sizeof (name));
			if (type != 'C') {
				n = r_num_math (core->num, t);
				if (type == 'f') { // "Cf"
					p = strchr (t, ' ');
					if (p) {
						p = (char *)r_str_trim_head_ro (p);
						if (*p == '.') {
							const char *realformat = r_print_format_byname (core->print, p + 1);
							if (realformat) {
								p = (char *)realformat;
							} else {
								R_LOG_WARN ("Cannot resolve format '%s'", p + 1);
								break;
							}
						}
						if (n < 1) {
							n = r_print_format_struct_size (core->print, p, 0, 0);
							if (n < 1) {
								R_LOG_WARN ("Cannot resolve struct size for '%s'", p);
								n = 32; //
							}
						}
						// make sure we do not overflow on r_print_format
						if (n > core->blocksize) {
							n = core->blocksize;
						}
						int r = r_print_format (core->print, addr, core->block,
							n, p, 0, NULL, NULL);
						if (r < 0) {
							n  = -1;
						}
					} else {
						r_core_cmd_help_match (core, help_msg_C, "Cf");
						break;
					}
				} else if (type == 's') { // "Cs"
					int name_len = 0;
					// TODO 256 is the limit. and that shouldnt be a hard limit
					if (input[1] == 'w' || input[1] == 'g') { // "Csw" "Csg"
						int i, j;
						char tmp[256] = {0};
						(void)r_io_read_at (core->io, addr, (ut8*)tmp, sizeof (tmp) - 3);
						name_len = r_str_nlen_w (tmp, sizeof (tmp) - 3);
						// handle wide strings
						for (i = 0, j = 0; i < sizeof (name); i++, j++) {
							name[i] = tmp[j];
							if (!tmp[j]) {
								break;
							}
							if (!tmp[j + 1]) {
								if (j + 3 < sizeof (tmp)) {
									if (tmp[j + 3]) {
										break;
									}
								}
								j++;
							}
						}
						name[sizeof (name) - 1] = '\0';
					} else if (input[1] == 'p') { // "Csp" // pascal string
						// TODO: add support for wide pascal strings
						ut8 fourbuf[4];
						(void)r_io_read_at (core->io, addr, (ut8*)fourbuf, sizeof (fourbuf));
						name_len = 0;
						if (n == 0 || n > 4) {
							// autoguess
							if (!fourbuf[0] && !fourbuf[1]) {
								n = 4;
							} else if (!fourbuf[1]) {
								n = 2;
							} else {
								n = 1;
							}
						}
						switch (n) {
						case 4:
							name_len = r_read_le32 (fourbuf);
							break;
						case 2:
							name_len = r_read_le16 (fourbuf);
							break;
						case 1:
							name_len = fourbuf[0];
							break;
						case -4:
							name_len = r_read_be32 (fourbuf);
							break;
						case -2:
							name_len = r_read_be16 (fourbuf);
							break;
						case -1:
							name_len = fourbuf[0];
							break;
						default:
							R_LOG_ERROR ("Invalid pascal length field size. Must be -4, -2, -1, 1, 2, 4");
							return false;
						}
						if (name_len >= 0 && name_len < 256) {
							char tmp[256] = {0};
							const size_t delta = R_ABS (n);
							(void)r_io_read_at (core->io, addr + delta, (ut8*)tmp, sizeof (tmp) - 3);
							r_str_ncpy (name, tmp, name_len);
							// TODO: use api instead: r_meta_set (core->anal, 'd', addr, delta, name);
							r_core_cmdf (core, "Cd%d@0x%08"PFMT64x, (int)delta, addr);
							{
								char *tmp = r_name_filter_dup (name);
								r_core_cmdf (core, "f str.pascal.%s@0x%08"PFMT64x, tmp, addr);
								free (tmp);
							}
							addr += delta;
							n = name_len;
						} else {
							R_LOG_ERROR ("Invalid pascal string value length (%d)", name_len);
							return false;
						}
					} else if (input[1] == 'a' || input[1] == '8') {
						// "Cs8" "Csa" // utf8 and ascii strings handling
						(void)r_io_read_at (core->io, addr, (ut8*)name, sizeof (name) - 1);
						name[sizeof (name) - 1] = '\0';
						name_len = strlen (name);
					} else if (input[1] == 0 || input[1] == ' ') {
						// same as Cs8 or Csa
						(void)r_io_read_at (core->io, addr, (ut8*)name, sizeof (name) - 1);
						name[sizeof (name) - 1] = '\0';
						name_len = strlen (name);
					} else {
						R_LOG_WARN ("Unknown Cs subcommand %c", input[1]);
						(void)r_io_read_at (core->io, addr, (ut8*)name, sizeof (name) - 1);
						name[sizeof (name) - 1] = '\0';
						name_len = strlen (name);
					}
					if (n == 0) {
						n = name_len + 1;
					} else {
						if (n > 0 && n < name_len) {
							name[n] = 0;
						}
					}
				}
				if (n < 1) {
					/* invalid length, do not insert into db */
					return false;
				}
				if (!*t || n > 0) {
					p = strchr (t, ' ');
					if (p) {
						*p++ = '\0';
						p = (char *)r_str_trim_head_ro (p);
						r_str_ncpy (name, p, sizeof (name));
					} else {
						if (type != 'b' && type != 's') {
							RFlagItem *fi = r_flag_get_in (core->flags, addr);
							if (fi) {
								r_str_ncpy (name, fi->name, sizeof (name));
							}
						}
					}
				}
			}
			if (!n) {
				n++;
			}
			if (type == 's') {
				switch (input[1]) {
				case 'a':
				case '8':
				case 'w':
					subtype = input[1];
					break;
				default:
					subtype = R_STRING_ENC_GUESS;
				}
				r_meta_set_with_subtype (core->anal, type, subtype, addr, n, name);
			} else {
				r_meta_set (core->anal, type, addr, n, name);
			}
			free (t);
			repcnt ++;
			addr += n;
		}
		// r_meta_cleanup (core->anal->meta, 0LL, UT64_MAX);
		break;
	default:
		R_LOG_ERROR ("Missing space after CC");
		break;
	}

	return true;
}

static void comment_var_help(RCore *core, char type) {
	switch (type) {
	case 'b':
		r_core_cmd_help (core, help_msg_Cvb);
		break;
	case 's':
		r_core_cmd_help (core, help_msg_Cvs);
		break;
	case 'r':
		r_core_cmd_help (core, help_msg_Cvr);
		break;
	case '?':
		r_cons_printf ("See Cvb?, Cvs? and Cvr?\n");
	}
}

static void cmd_Cv(RCore *core, const char *input) {
	// TODO enable base64 and make it the default for C*
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->addr, 0);
	char *oname = NULL, *name = NULL;

	if (!input[0] || input[1] == '?' || (input[0] != 'b' && input[0] != 'r' && input[0] != 's')) {
		comment_var_help (core, input[0]);
		return;
	}
	if (!fcn) {
		R_LOG_ERROR ("Can't find function here");
		return;
	}
	oname = name = r_str_trim_dup (input + 1);
	switch (input[1]) {
	case '*': // "Cv*"
	case '\0': { // "Cv"
		void **it;
		char kind = input[0];
		r_pvector_foreach (&fcn->vars, it) {
			RAnalVar *var = *it;
			if (var->kind != kind || !var->comment) {
				continue;
			}
			if (input[1]) {
				char *b64 = sdb_encode ((const ut8 *)var->comment, strlen (var->comment));
				if (!b64) {
					continue;
				}
				r_cons_printf ("'@0x%08"PFMT64x"'Cv%c %s base64:%s\n", fcn->addr, kind, var->name, b64);
				free (b64);
			} else {
				r_cons_printf ("%s : %s\n", var->name, var->comment);
			}
		}
		}
		break;
	case ' ': { // "Cv "
		char *comment = strchr (name, ' ');
		char *heap_comment = NULL;
		if (comment) { // new comment given
			if (*comment) {
				*comment++ = 0;
			}
			if (!strncmp (comment, "base64:", 7)) {
				heap_comment = (char *)sdb_decode (comment + 7, NULL);
				comment = heap_comment;
			}
		}
		RAnalVar *var = r_anal_function_get_var_byname (fcn, name);
		if (!var) {
			const int idx = (int)strtol (name, NULL, 0);
			var = r_anal_function_get_var (fcn, input[0], idx);
		}
		if (var) {
			if (var->comment) {
				if (R_STR_ISNOTEMPTY (comment)) {
					char *text = r_str_newf ("%s\n%s", var->comment, comment);
					free (var->comment);
					var->comment = text;
				} else {
					r_cons_println (var->comment);
				}
			} else if (R_STR_ISNOTEMPTY (comment)) {
				var->comment = strdup (comment);
			}
		} else {
			R_LOG_ERROR ("can't find variable at given offset");
		}
		free (heap_comment);
		}
		break;
	case '-': { // "Cv-"
		name++;
		r_str_trim (name);
		RAnalVar *var = r_anal_function_get_var_byname (fcn, name);
		if (!var) {
			int idx = (int)strtol (name, NULL, 0);
			var = r_anal_function_get_var (fcn, input[0], idx);
		}
		if (!var) {
			R_LOG_ERROR ("can't find variable at given offset");
			break;
		}
		free (var->comment);
		var->comment = NULL;
		break;
	}
	case '!': { // "Cv!"
		char *comment;
		name++;
		r_str_trim (name);
		RAnalVar *var = r_anal_function_get_var_byname (fcn, name);
		if (!var) {
			R_LOG_ERROR ("can't find variable named `%s`", name);
			break;
		}
		comment = r_core_editor (core, NULL, var->comment);
		if (comment) {
			free (var->comment);
			var->comment = comment;
		}
		}
		break;
	}
	free (oname);
}

static int cmd_meta(void *data, const char *input) {
	RCore *core = (RCore*)data;
	RAnalFunction *f;
	RSpaces *ms;
	int i;

	switch (*input) {
	case 'v': // "Cv"
		cmd_Cv (core, input + 1);
		break;
	case '\0': // "C"
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, 0, NULL, NULL);
		break;
	case ',': // "C,"
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, *input, input + 1, NULL);
		break;
	case 'j': // "Cj"
	case '*': { // "C*"
		if (input[1] == '.') {
			r_meta_print_list_at (core->anal, core->addr, *input, input + 2, NULL);
		} else if (input[1]) {
			r_meta_print_list_at (core->anal, core->addr, *input, input + 2, NULL);
		} else {
			r_meta_print_list_all (core->anal, R_META_TYPE_ANY, *input, input + 1, NULL);
		}
		break;
	}
	case '.': { // "C."
		r_meta_print_list_at (core->anal, core->addr, 0, NULL, NULL);
		break;
	}
	case 'L': // "CL"
		cmd_meta_lineinfo (core, input + 1);
		break;
	case 'C': // "CC"
		cmd_meta_comment (core, input);
		break;
	case 't': // "Ct" type analysis commnets
		cmd_meta_vartype_comment (core, input);
		break;
	case 'b': // "Cb" bind addresses
	case 'r': // "Cr" run command
	case 'h': // "Ch" comment
	case 's': // "Cs" string
	case 'z': // "Cz" zero-terminated string
	case 'd': // "Cd" data
	case 'm': // "Cm" magic
	case 'f': // "Cf" formatted
		cmd_meta_others (core, input);
		break;
	case '-': // "C-"
		if (input[1] != '*') {
			i = input[1] ? r_num_math (core->num, input + (input[1] == ' ' ? 2 : 1)) : 1;
			r_meta_del (core->anal, R_META_TYPE_ANY, core->addr, i);
		} else {
			r_meta_del (core->anal, R_META_TYPE_ANY, 0, UT64_MAX);
		}
		break;
	case '?': // "C?"
		r_core_cmd_help (core, help_msg_C);
		break;
	case 'F': // "CF"
		f = r_anal_get_fcn_in (core->anal, core->addr,
			R_ANAL_FCN_TYPE_FCN|R_ANAL_FCN_TYPE_SYM);
		if (f) {
			r_anal_str_to_fcn (core->anal, f, input + 2);
		} else {
			R_LOG_ERROR ("Cannot find function here");
		}
		break;
	case 'S': // "CS"
		ms = &core->anal->meta_spaces;
		/** copypasta from `fs`.. this must be refactorized to be shared */
		switch (input[1]) {
		case '?': // "CS?"
			r_core_cmd_help (core, help_msg_CS);
			break;
		case '+': // "CS+"
			r_spaces_push (ms, input + 2);
			break;
		case 'r': // "CSr"
			if (input[2] == ' ') {
				r_spaces_rename (ms, NULL, input + 2);
			} else {
				r_core_cmd_help_match (core, help_msg_CS, "CSr");
			}
			break;
		case '-': // "CS-"
			if (input[2]) {
				if (input[2] == '*') {
					r_spaces_unset (ms, NULL);
				} else {
					r_spaces_unset (ms, input + 2);
				}
			} else {
				r_spaces_pop (ms);
			}
			break;
		case 'j': // "CSj"
		case '\0': // "CS"
		case '*': // "CS*"
			spaces_list (core, ms, input[1]);
			break;
		case ' ': // "CS "
			r_spaces_set (ms, input + 2);
			break;
		default:
			spaces_list (core, ms, 0);
			break;
		}
		break;
	default:
		r_core_return_invalid_command (core, "C", *input);
		break;
	}
	return true;
}
#endif
