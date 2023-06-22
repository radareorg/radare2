/* radare2 - LGPL - Copyright 2009-2023 - pancake */

#include <r_core.h>
#include <sdb/sdb.h>

// R2R db/cmd/cmd_meta

char *getcommapath(RCore *core);

static R_TH_LOCAL ut64 filter_offset = UT64_MAX;
static R_TH_LOCAL int filter_format = 0;
static R_TH_LOCAL size_t filter_count = 0;
static R_TH_LOCAL Sdb *fscache = NULL;

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
	"CLj", "", "same as above but in JSON format (See dir.source to change the path to find the referenced lines)",
	"CL*", "", "same as above but in r2 commands format",
	"CL.", "", "show list all code line information (virtual address <-> source file:line)",
	"CL-", "*", "remove all the cached codeline information",
	"CLL", "[f]", "show source code line associated to current offset",
	"CLLf", "", "show source lines covered by the current function (see CLL@@i or list)",
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
	"Usage: CS","[*] [+-][metaspace|addr]", " # Manage metaspaces",
	"CS","","display metaspaces",
	"CS"," *","select all metaspaces",
	"CS"," metaspace","select metaspace or create if it doesn't exist",
	"CS","-metaspace","remove metaspace",
	"CS","-*","remove all metaspaces",
	"CS","+foo","push previous metaspace and set",
	"CS","-","pop to the previous metaspace",
	//	"CSm"," [addr]","move metas at given address to the current metaspace",
	"CSr"," newname","rename selected metaspace",
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

static int remove_meta_offset(RCore *core, ut64 offset) {
	char aoffset[SDB_NUM_BUFSZ];
	char *aoffsetptr = sdb_itoa (offset, 16, aoffset, sizeof (aoffset));
	if (!aoffsetptr) {
		R_LOG_ERROR ("Failed to convert %"PFMT64x" to a key", offset);
		return -1;
	}
	return sdb_unset (core->bin->cur->sdb_addrinfo, aoffsetptr, 0);
}

static bool print_meta_offset(RCore *core, ut64 addr, PJ *pj) {
	int line, line_old, i;
	char file[1024];
	int colu = 0; /// addr2line function cant retrieve column info
	int ret = r_bin_addr2line (core->bin, addr, file, sizeof (file) - 1, &line, &colu);
	if (ret) {
		if (pj) {
			pj_o (pj);
			pj_ks (pj, "file", file);
			pj_kn (pj, "line", line);
			pj_kn (pj, "colu", colu);
			pj_kn (pj, "addr", addr);
			if (r_file_exists (file)) {
				char *row = r_file_slurp_line (file, line, 0);
				pj_ks (pj, "text", file);
				free (row);
			} else {
				// R_LOG_ERROR ("Cannot open '%s'", file);
			}
			pj_end (pj);
			return ret;
		}

		r_cons_printf ("file: %s\nline: %d\ncolu: %d\naddr: 0x%08"PFMT64x"\n", file, line, colu, addr);
		line_old = line;
		if (line >= 2) {
			line -= 2;
		}
		if (r_file_exists (file)) {
			for (i = 0; i < 5; i++) {
				char *row = r_file_slurp_line (file, line + i, 0);
				if (row) {
					r_cons_printf ("%c %.3x  %s\n", line+i == line_old ? '>' : ' ', line+i, row);
					free (row);
				}
			}
		} else {
			R_LOG_ERROR ("Cannot open '%s'", file);
		}
	}
	return ret;
}

#if 0
static int remove_meta_fileline(RCore *core, const char *file_line) {
	return sdb_unset (core->bin->cur->sdb_addrinfo, file_line, 0);
}

static int print_meta_fileline(RCore *core, const char *file_line) {
	char *meta_info = sdb_get (core->bin->cur->sdb_addrinfo, file_line, 0);
	if (meta_info) {
		r_cons_printf ("Meta info %s\n", meta_info);
	} else {
		r_cons_printf ("No meta info for %s found\n", file_line);
	}
	return 0;
}
#endif

static bool print_addrinfo_json(void *user, const char *k, const char *v) {
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
	if (colonpos && (filter_offset == UT64_MAX || filter_offset == offset)) {
		if (filter_format) {
			*colonpos = ':';
	//		r_cons_printf ("CL %s %s\n", k, subst);
		} else {
			*colonpos = 0;
	//		r_cons_printf ("file: %s\nline: %s\naddr: 0x%08"PFMT64x"\n", subst, colonpos + 1, offset);
		}
		filter_count++;
	}
	const char *file = subst;
	int line = atoi (colonpos + 1);
	ut64 addr = offset;
	PJ *pj = (PJ*)user;
	if (pj) {
		pj_o (pj);
		pj_ks (pj, "file", file);
		pj_kn (pj, "line", line);
		pj_kn (pj, "addr", addr);
		const char *cached_existance = sdb_const_get (fscache, file, NULL);
		bool file_exists = false;
		if (cached_existance) {
			file_exists = !strcmp (cached_existance, "1");
		} else {
			if (r_file_exists (file)) {
				sdb_set (fscache, file, "1", 0);
			} else {
				sdb_set (fscache, file, "0", 0);
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

static bool print_addrinfo(void *user, const char *k, const char *v) {
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
	} else if (filter_offset == UT64_MAX || filter_offset == offset) {
		if (filter_format) {
			*colonpos = ':';
			r_cons_printf ("\"\"CL %s %s\n", k, subst);
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
		filter_count++;
	}
	free (subst);

	return true;
}

static int cmd_meta_add_fileline(Sdb *s, char *fileline, ut64 offset) {
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
		ut64 at = core->offset;
		if (p[1] == ' ') {
			at = r_num_get (core->num, p + 2);
		}
		char *text = r_bin_addr2text (core->bin, at, 0);
		if (R_STR_ISNOTEMPTY (text)) {
			r_cons_printf ("0x%08"PFMT64x"  %s\n", at, text);
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
		offset = core->offset;
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
		filter_format = '*';
	} else {
		filter_format = 0;
	}

	if (all) {
		if (remove) {
			sdb_reset (core->bin->cur->sdb_addrinfo);
		} else {
			sdb_foreach (core->bin->cur->sdb_addrinfo, print_addrinfo, NULL);
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
		if (!strncmp (sp, "base64:", 7)) {
			int len = 0;
			ut8 *o = sdb_decode (sp + 7, &len);
			if (!o) {
				R_LOG_ERROR ("Invalid base64");
				return 0;
			}
			sp = pheap = (char *)o;
		}
		RBinFile *bf = r_bin_cur (core->bin);
		ret = 0;
		if (bf && bf->sdb_addrinfo) {
			ret = cmd_meta_add_fileline (bf->sdb_addrinfo, sp, offset);
		} else {
			R_LOG_TODO ("Support global SdbAddrinfo or dummy rbinfile to handlee this case");
		}
		free (file_line);
		free (myp);
		free (pheap);
		return ret;
	}
	free (myp);
	if (remove) {
		remove_meta_offset (core, offset);
	} else {
		// taken from r2 // TODO: we should move this addrinfo sdb logic into RBin.. use HT
		filter_offset = offset;
		filter_count = 0;
		fscache = sdb_new0 ();
		PJ *pj = NULL;
		RBinFile *bf = r_bin_cur (core->bin);
		if (use_json) {
			pj = r_core_pj_new (core);
			pj_a (pj);
			if (bf && bf->sdb_addrinfo) {
				sdb_foreach (bf->sdb_addrinfo, print_addrinfo_json, pj);
			}
		} else {
			if (bf && bf->sdb_addrinfo) {
				sdb_foreach (bf->sdb_addrinfo, print_addrinfo, NULL);
			}
		}
		if (filter_count == 0) {
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
		sdb_free (fscache);
	}
	return 0;
}

static int cmd_meta_comment(RCore *core, const char *input) {
	ut64 addr = core->offset;
	switch (input[1]) {
	case '?':
		r_core_cmd_help (core, help_msg_CC);
		break;
	case ',': // "CC,"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, ',', input + 2);
		break;
	case 'F': // "CC,"
		if (input[2] == '?') {
			r_core_cmd_help_match (core, help_msg_CC, "CCF", true);
		} else if (input[2] == ' ') {
			const char *fn = input + 2;
			const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			fn = r_str_trim_head_ro (fn);
			if (comment && *comment) {
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
			if (comment && *comment) {
				char *cmtfile = r_str_between (comment, ",(", ")");
				if (cmtfile && *cmtfile) {
					char *cwd = getcommapath (core);
					r_cons_printf ("%s"R_SYS_DIR"%s\n", cwd, cmtfile);
					free (cwd);
				}
				free (cmtfile);
			}
		}
		break;
	case '.':
		  {
			  ut64 at = input[2]? r_num_math (core->num, input + 2): addr;
			  const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, at);
			  if (comment) {
				  r_cons_println (comment);
			  }
		  }
		break;
	case 0: // "CC"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 0, NULL);
		break;
	case 'f': // "CCf"
		switch (input[2]) {
		case '-': // "CCf-"
			{
				ut64 arg = r_num_math (core->num, input + 2);
				if (!arg) {
					arg = core->offset;
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
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, ',', core->offset, input + 3);
			break;
		case 'j': // "CCfj"
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 'j', core->offset, NULL);
			break;
		case '*': // "CCf*"
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 1, core->offset, NULL);
			break;
		default:
			r_meta_print_list_in_function (core->anal, R_META_TYPE_COMMENT, 0, core->offset, NULL);
			break;
		}
		break;
	case 'j': // "CCj"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 'j', input + 2);
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
		const char *newcomment = r_str_trim_head_ro (input + 2);
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
		char *text;
		char *nc = strdup (newcomment);
		r_str_unescape (nc);
		r_str_ansi_strip (nc);
		if (comment) {
			text = malloc (strlen (comment) + strlen (newcomment) + 2);
			if (text) {
				strcpy (text, comment);
				strcat (text, " ");
				strcat (text, nc);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, text);
				free (text);
			} else {
				r_sys_perror ("malloc");
			}
		} else {
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, nc);
			if (r_config_get_b (core->config, "cmd.undo")) {
				char *a = r_str_newf ("CC-0x%08"PFMT64x, addr);
				char *b = r_str_newf ("CC %s@0x%08"PFMT64x, nc, addr);
				RCoreUndo *uc = r_core_undo_new (core->offset, b, a);
				r_core_undo_push (core, uc);
				free (a);
				free (b);
			}
		}
		free (nc);
		}
		break;
	case '*': // "CC*"
		r_meta_print_list_all (core->anal, R_META_TYPE_COMMENT, 1, NULL);
		break;
	case '-': // "CC-"
		if (input[2] == '*') { // "CC-*"
			r_meta_del (core->anal, R_META_TYPE_COMMENT, UT64_MAX, UT64_MAX);
		} else if (input[2]) { // "CC-$$+32"
			ut64 arg = r_num_math (core->num, input + 2);
			r_meta_del (core->anal, R_META_TYPE_COMMENT, arg, 1);
		} else { // "CC-"
			r_meta_del (core->anal, R_META_TYPE_COMMENT, core->offset, 1);
		}
		break;
	case 'u': // "CCu"
		//
		{
		char *newcomment;
		const char *arg = input + 2;
		while (*arg && *arg == ' ') arg++;
		if (!strncmp (arg, "base64:", 7)) {
			char *s = (char *)sdb_decode (arg + 7, NULL);
			if (s) {
				newcomment = s;
			} else {
				newcomment = NULL;
			}
		} else {
			newcomment = strdup (arg);
		}
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
		char *s, *p;
		s = strchr (input, ' ');
		if (s) {
			s = strdup (s + 1);
		} else {
			r_core_cmd_help_match (core, help_msg_CC, "CCa", true);
			return false;
		}
		p = strchr (s, ' ');
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
				r_core_cmd_help_match (core, help_msg_CC, "CCa", true);
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
			r_core_cmd_help_match (core, help_msg_CC, "CCa", true);
		}
		free (s);
		return true;
		}
	}
	return true;
}

static int cmd_meta_vartype_comment(RCore *core, const char *input) {
	ut64 addr = core->offset;
	switch (input[1]) {
	case '?': // "Ct?"
		r_core_cmd_help (core, help_msg_Ct);
		break;
	case 0: // "Ct"
		r_meta_print_list_all (core->anal, R_META_TYPE_VARTYPE, 0, NULL);
		break;
	case ' ': // "Ct <vartype comment> @ addr"
		{
		const char* newcomment = r_str_trim_head_ro (input + 2);
		const char *comment = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, addr);
		char *nc = strdup (newcomment);
		r_str_unescape (nc);
		if (comment) {
			char *text = r_str_newf ("%s %s", comment, nc);
			if (text) {
				r_meta_set_string (core->anal, R_META_TYPE_VARTYPE, addr, text);
				free (text);
			} else {
				r_sys_perror ("malloc");
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
		if (comment) {
			r_cons_println (comment);
		}
		}
		break;
	case '-': // "Ct-"
		r_meta_del (core->anal, R_META_TYPE_VARTYPE, core->offset, 1);
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

static int cb_strhit(R_NULLABLE RSearchKeyword *kw, void *user, ut64 where) {
	StringSearchOptions *sso = (StringSearchOptions*)user;
	if (where - sso->addr >= sso->bufsz) {
		r_core_cmdf (sso->core, "Cz@0x%08"PFMT64x, where);
	} else {
		const char *name = (const char *)(sso->buf + (where - sso->addr));
		size_t maxlen = sso->bufsz - (where - sso->addr);
		char *hname = r_str_ndup (name, maxlen);
		size_t n = strlen (hname) + 1;
		r_meta_set (sso->core->anal, R_META_TYPE_STRING, where, n, hname);
		free (hname);
	}
	return true;
}

static int cmd_meta_others(RCore *core, const char *input) {
	char *t = 0, *p, *p2, name[256] = {0};
	int n, repeat = 1;
	ut64 addr = core->offset;

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
			r_core_cmd_help_match (core, help_msg_C, "Cf", true);
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
		r_meta_print_list_all (core->anal, input[0], 1, NULL);
		break;
	case 'j': // "Cfj", "Cdj", ...
		r_meta_print_list_all (core->anal, input[0], 'j', NULL);
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
				r_meta_print (core->anal, mi, addr, size, input[3], NULL, false);
			}
			break;
		} else if (input[2] == 'j') { // "Cs.j"
			ut64 size;
			RAnalMetaItem *mi = r_meta_get_at (core->anal, addr, type, &size);
			if (mi) {
				r_meta_print (core->anal, mi, addr, size, input[2], NULL, false);
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
			case 0:  /* temporary legacy workaround */
				esc_bslash = false;
			default:
				esc_str = r_str_escape_latin1 (mi->str, false, esc_bslash, false);
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
				RBinSection *s = r_bin_get_section_at (r_bin_cur_object (core->bin), core->offset, true);
				if (s) {
					range = s->vaddr + s->vsize - core->offset;
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
					const ut64 addr = core->offset;
					int minstr = 3;
					int maxstr = r_config_get_i (core->config, "bin.str.max");
					if (maxstr < 1) {
						maxstr = 128;
					}
					r_core_cmdf (core, "Cz@0x%08"PFMT64x, addr);
					// maps are not yet set
					char *s = r_core_cmd_str (core, "o;om");
					free (s);
					if (!r_io_read_at (core->io, addr, buf, range)) {
						R_LOG_ERROR ("cannot read %d", range);
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
				} else {
					R_LOG_ERROR ("Cannot allocate");
				}

#if 0
				r_core_cmdf (core, "/z 8 100@0x%08"PFMT64x"@e:search.in=range@e:search.from=0x%"PFMT64x"@e:search.to=0x%"PFMT64x,
						core->offset, core->offset, core->offset + range);
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
	case 'r':
	case '2':
	case '4':
	case '8':
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
				r_meta_print_list_all (core->anal, type, 0, NULL);
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
			strncpy (name, t, sizeof (name) - 1);
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
						r_core_cmd_help_match (core, help_msg_C, "Cf", true);
						break;
					}
				} else if (type == 's') { // "Cs"
					char tmp[256] = {0};
					int i, j, name_len = 0;
					if (input[1] == 'a' || input[1] == '8') {
						(void)r_io_read_at (core->io, addr, (ut8*)name, sizeof (name) - 1);
						name[sizeof (name) - 1] = '\0';
						name_len = strlen (name);
					} else {
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
						strncpy (name, p, sizeof (name)-1);
					} else {
						if (type != 's') {
							RFlagItem *fi = r_flag_get_i (core->flags, addr);
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

void r_comment_var_help(RCore *core, char type) {
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
		r_cons_printf("See Cvb?, Cvs? and Cvr?\n");
	}
}

void r_comment_vars(RCore *core, const char *input) {
	//TODO enable base64 and make it the default for C*
	RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, core->offset, 0);
	char *oname = NULL, *name = NULL;

	if (!input[0] || input[1] == '?' || (input[0] != 'b' && input[0] != 'r' && input[0] != 's')) {
		r_comment_var_help (core, input[0]);
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
			if (!input[1]) {
				r_cons_printf ("%s : %s\n", var->name, var->comment);
			} else {
				char *b64 = sdb_encode ((const ut8 *)var->comment, strlen (var->comment));
				if (!b64) {
					continue;
				}
				r_cons_printf ("\"Cv%c %s base64:%s @ 0x%08"PFMT64x"\"\n", kind, var->name, b64, fcn->addr);
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
			int idx = (int)strtol (name, NULL, 0);
			var = r_anal_function_get_var (fcn, input[0], idx);
		}
		if (!var) {
			R_LOG_ERROR ("can't find variable at given offset");
		} else {
			if (var->comment) {
				if (comment && *comment) {
					char *text = r_str_newf ("%s\n%s", var->comment, comment);
					free (var->comment);
					var->comment = text;
				} else {
					r_cons_println (var->comment);
				}
			} else {
				var->comment = strdup (comment);
			}
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
		r_comment_vars (core, input + 1);
		break;
	case '\0': // "C"
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, 0, NULL);
		break;
	case ',': // "C,"
		r_meta_print_list_all (core->anal, R_META_TYPE_ANY, *input, input + 1);
		break;
	case 'j': // "Cj"
	case '*': { // "C*"
		if (input[1] == '.') {
			r_meta_print_list_at (core->anal, core->offset, *input, input + 2);
		} else if (input[1]) {
			r_meta_print_list_at (core->anal, core->offset, *input, input + 2);
		} else {
			r_meta_print_list_all (core->anal, R_META_TYPE_ANY, *input, input + 1);
		}
		break;
	}
	case '.': { // "C."
		r_meta_print_list_at (core->anal, core->offset, 0, NULL);
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
			r_meta_del (core->anal, R_META_TYPE_ANY, core->offset, i);
		} else {
			r_meta_del (core->anal, R_META_TYPE_ANY, 0, UT64_MAX);
		}
		break;
	case '?': // "C?"
		r_core_cmd_help (core, help_msg_C);
		break;
	case 'F': // "CF"
		f = r_anal_get_fcn_in (core->anal, core->offset,
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
				r_core_cmd_help_match (core, help_msg_CS, "CSr", true);
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
			spaces_list (ms, input[1]);
			break;
		case ' ': // "CS "
			r_spaces_set (ms, input + 2);
			break;
		default:
			spaces_list (ms, 0);
			break;
		}
		break;
	}
	return true;
}
