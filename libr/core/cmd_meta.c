/* radare2 - LGPL - Copyright 2009-2020 - pancake */

#include "r_anal.h"
#include "r_bin.h"
#include "r_cons.h"
#include "r_core.h"
#include "r_util.h"
#include "r_types.h"
#include "sdb/sdb.h"

static const char *help_msg_C[] = {
	"Usage:", "C[-LCvsdfm*?][*?] [...]", " # Metadata management",
	"C", "", "list meta info in human friendly form",
	"C*", "", "list meta info in r2 commands",
	"C*.", "", "list meta info of current offset in r2 commands",
	"C-", " [len] [[@]addr]", "delete metadata at given address range",
	"C.", "", "list meta info of current offset in human friendly form",
	"CC!", " [@addr]", "edit comment with $EDITOR",
	"CC", "[?] [-] [comment-text] [@addr]", "add/remove comment",
	"CC.", "[addr]", "show comment in current address",
	"CCa", "[-at]|[at] [text] [@addr]", "add/remove comment at given address",
	"CCu", " [comment-text] [@addr]", "add unique comment",
	"CF", "[sz] [fcn-sign..] [@addr]", "function signature",
	"CL", "[-][*] [file:line] [addr]", "show or add 'code line' information (bininfo)",
	"CS", "[-][space]", "manage meta-spaces to filter comments, etc..",
	"C[Cthsdmf]", "", "list comments/types/hidden/strings/data/magic/formatted in human friendly form",
	"C[Cthsdmf]*", "", "list comments/types/hidden/strings/data/magic/formatted in r2 commands",
	"Cd", "[-] [size] [repeat] [@addr]", "hexdump data array (Cd 4 10 == dword [10])",
	"Cd.", " [@addr]", "show size of data at current address",
	"Cf", "[?][-] [sz] [0|cnt][fmt] [a0 a1...] [@addr]", "format memory (see pf?)",
	"Ch", "[-] [size] [@addr]", "hide data",
	"Cm", "[-] [sz] [fmt..] [@addr]", "magic parse (see pm?)",
	"Cs", "[?] [-] [size] [@addr]", "add string",
	"Ct", "[?] [-] [comment-text] [@addr]", "add/remove type analysis comment",
	"Ct.", "[@addr]", "show comment at current or specified address",
	"Cv", "[bsr][?]", "add comments to args",
	"Cz", "[@addr]", "add string (see Cs?)",
	NULL
};

static const char *help_msg_CC[] = {
	"Usage:", "CC[-+!*au] [base64:..|str] @ addr", "",
	"CC!", "", "edit comment using cfg.editor (vim, ..)",
	"CC", " [text]", "append comment at current address",
	"CC", "", "list all comments in human friendly form",
	"CC*", "", "list all comments in r2 commands",
	"CC+", " [text]", "append comment at current address",
	"CC,", " [file]", "show or set comment file",
	"CC-", " @ cmt_addr", "remove comment at given address",
	"CC.", "", "show comment at current offset",
	"CCf", "", "list comments in function",
	"CCf-", "", "delete all comments in current function",
	"CCu", " base64:AA== @ addr", "add comment in base64",
	"CCu", " good boy @ addr", "add good boy comment at given address",
	NULL
};

static const char *help_msg_Ct[] = {
	"Usage: Ct", "[.|-] [@ addr]", " # Manage comments for variable types",
	"Ct", "", "list all variable type comments",
	"Ct", " comment-text [@ addr]", "place comment at current or specified address",
	"Ct.", " [@ addr]", "show comment at current or specified address",
	"Ct-", " [@ addr]", "remove comment at current or specified address",
	NULL
};

static const char *help_msg_CS[] = {
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

static const char *help_msg_Cs[] = {
	"Usage:", "Cs[ga-*.] [size] [@addr]", "",
	"NOTE:", " size", "1 unit in bytes == width in bytes of smallest possible char in encoding,",
	"", "", "  so ascii/latin1/utf8 = 1, utf16le = 2",
	" Cz", " [size] [@addr]", "ditto",
	"Cs", " [size] @addr", "add string (guess latin1/utf16le)",
	"Cs", "", "list all strings in human friendly form",
	"Cs*", "", "list all strings in r2 commands",
	"Cs-", " [@addr]", "remove string",
	"Cs.", "", "show string at current address",
	"Cs..", "", "show string + info about it at current address",
	"Cs.j", "", "show string at current address in JSON",
	"Cs8", " [size] [@addr]", "add utf8 string",
	"Csa", " [size] [@addr]", "add ascii/latin1 string",
	"Csg", " [size] [@addr]", "as above but addr not needed",
	NULL
};

static const char *help_msg_Cvb[] = {
	"Usage:", "Cvb", "[name] [comment]",
	"Cvb?", "", "show this help",
	"Cvb", "", "list all base pointer args/vars comments in human friendly format",
	"Cvb*", "", "list all base pointer args/vars comments in r2 format",
	"Cvb-", "[name]", "delete comments for var/arg at current offset for base pointer",
	"Cvb", " [name]", "Show comments for var/arg at current offset for base pointer",
	"Cvb", " [name] [comment]", "add/append comment for the variable with the current name",
	"Cvb!", "[name]", "edit comment using cfg editor",
	NULL
};

static const char *help_msg_Cvr[] = {
	"Usage:", "Cvr", "[name] [comment]",
	"Cvr?", "", "show this help",
	"Cvr", "", "list all register based args comments in human friendly format",
	"Cvr*", "", "list all register based args comments in r2 format",
	"Cvr-", "[name]", "delete comments for register based arg for that name",
	"Cvr", "[name]", "Show comments for register based arg for that name",
	"Cvr", "[name] [comment]", "add/append comment for the variable",
	"Cvr!", "[name]", "edit comment using cfg editor",
	NULL
};

static const char *help_msg_Cvs[] = {
	"Usage:", "Cvs", "[name] [comment]",
	"Cvs!", "[name]", "edit comment using cfg editor",
	"Cvs", "", "list all stack based args/vars comments in human friendly format",
	"Cvs", "[name] [comment]", "add/append comment for the variable",
	"Cvs", "[name]", "Show comments for stack pointer var/arg with that name",
	"Cvs*", "", "list all stack based args/vars comments in r2 format",
	"Cvs-", "[name]", "delete comments for stack pointer var/arg with that name",
	"Cvs?", "", "show this help",
	NULL
};

static void cmd_meta_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, C);
	DEFINE_CMD_DESCRIPTOR (core, CC);
	DEFINE_CMD_DESCRIPTOR (core, CS);
	DEFINE_CMD_DESCRIPTOR (core, Cs);
	DEFINE_CMD_DESCRIPTOR (core, Cvb);
	DEFINE_CMD_DESCRIPTOR (core, Cvr);
	DEFINE_CMD_DESCRIPTOR (core, Cvs);
}

static int remove_meta_offset(RCore *core, ut64 offset) {
	char aoffset[64];
	char *aoffsetptr = sdb_itoa (offset, aoffset, 16);
	if (!aoffsetptr) {
		eprintf ("Failed to convert %"PFMT64x" to a key", offset);
		return -1;
	}
	return sdb_unset (core->bin->cur->sdb_addrinfo, aoffsetptr, 0);
}

static bool print_meta_offset(RCore *core, ut64 addr) {
	int line, line_old, i;
	char file[1024];

	int ret = r_bin_addr2line (core->bin, addr, file, sizeof (file) - 1, &line);
	if (ret) {
		r_cons_printf ("file: %s\nline: %d\n", file, line);
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
			eprintf ("Cannot open '%s'\n", file);
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

static ut64 filter_offset = UT64_MAX;
static int filter_format = 0;
static size_t filter_count = 0;

static int print_addrinfo (void *user, const char *k, const char *v) {
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
			r_cons_printf ("CL %s %s\n", k, subst);
		} else {
			*colonpos = 0;
			r_cons_printf ("file: %s\nline: %s\n", subst, colonpos + 1);
		}
		filter_count++;
	}
	free (subst);

	return true;
}

static int cmd_meta_add_fileline(Sdb *s, char *fileline, ut64 offset) {
	char aoffset[64];
	char *aoffsetptr = sdb_itoa (offset, aoffset, 16);

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
	int all = false;
	const char *p = input;
	char *file_line = NULL;
	char *pheap = NULL;

	if (*p == '?') {
		eprintf ("Usage: CL[.-*?] [addr] [file:line]\n");
		eprintf ("or: CL [addr] base64:[string]\n");
		free (pheap);
		return 0;
	}
	if (*p == '-') {
		p++;
		remove = true;
	}
	if (*p == '.') {
		p++;
		offset = core->offset;
	}
	if (*p == ' ') {
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
		free (pheap);
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

		if (!strncmp (sp, "base64:", 7)) {
			int len = 0;
			ut8 *o = sdb_decode (sp + 7, &len);
			if (!o) {
				eprintf ("Invalid base64\n");
				return 0;
			}
			sp = pheap = (char *)o;
		}
		RBinFile *bf = r_bin_cur (core->bin);
		ret = 0;
		if (bf && bf->sdb_addrinfo) {
			ret = cmd_meta_add_fileline (bf->sdb_addrinfo, sp, offset);
		} else {
			eprintf ("TODO: Support global SdbAddrinfo or dummy rbinfile to handlee this case\n");
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
		sdb_foreach (core->bin->cur->sdb_addrinfo, print_addrinfo, NULL);
		if (filter_count == 0) {
			print_meta_offset (core, offset);
		}
	}
	free (pheap);
	return 0;
}

static int cmd_meta_comment(RCore *core, const char *input) {
	ut64 addr = core->offset;
	switch (input[1]) {
	case '?':
		r_core_cmd_help (core, help_msg_CC);
		break;
	case ',': // "CC,"
		if (input[2]=='?') {
			eprintf ("Usage: CC, [file]\n");
		} else if (input[2] == ' ') {
			const char *fn = input+2;
			char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			while (*fn== ' ')fn++;
			if (comment && *comment) {
				// append filename in current comment
				char *nc = r_str_newf ("%s ,(%s)", comment, fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, nc);
				free (nc);
			} else {
				char *comment = r_str_newf (",(%s)", fn);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, comment);
				free (comment);
			}
		} else {
			char *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
			if (comment && *comment) {
				char *cmtfile = r_str_between (comment, ",(", ")");
				if (cmtfile && *cmtfile) {
					char *getcommapath(RCore *core);
					char *cwd = getcommapath (core);
					r_cons_printf ("%s"R_SYS_DIR"%s\n", cwd, cmtfile);
					free (cwd);
				}
				free (cmtfile);
			}
			free (comment);
		}
		break;
	case '.':
		  {
			  ut64 at = input[2]? r_num_math (core->num, input + 2): addr;
			  char *comment = r_meta_get_string (
					  core->anal, R_META_TYPE_COMMENT, at);
			  if (comment) {
				  r_cons_println (comment);
				  free (comment);
			  }
		  }
		break;
	case 0: // "CC"
		r_meta_list (core->anal, R_META_TYPE_COMMENT, 0);
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
		case 'j': // "CCfj"
			r_meta_list_at (core->anal, R_META_TYPE_COMMENT, 'j', core->offset);
			break;
		case '*': // "CCf*"
			r_meta_list_at (core->anal, R_META_TYPE_COMMENT, 1, core->offset);
			break;
		default:
			r_meta_list_at (core->anal, R_META_TYPE_COMMENT, 0, core->offset);
			break;
		}
		break;
	case 'j': // "CCj"
		r_meta_list (core->anal, R_META_TYPE_COMMENT, 'j');
		break;
	case '!':
		{
			char *out, *comment = r_meta_get_string (
					core->anal, R_META_TYPE_COMMENT, addr);
			out = r_core_editor (core, NULL, comment);
			if (out) {
				//r_meta_add (core->anal->meta, R_META_TYPE_COMMENT, addr, 0, out);
				r_core_cmdf (core, "CC-@0x%08"PFMT64x, addr);
				//r_meta_del (core->anal->meta, input[0], addr, addr+1);
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
		const char* newcomment = r_str_trim_head_ro (input + 2);
		char *text, *comment = r_meta_get_string (core->anal, R_META_TYPE_COMMENT, addr);
		char *nc = strdup (newcomment);
		r_str_unescape (nc);
		if (comment) {
			text = malloc (strlen (comment)+ strlen (newcomment)+2);
			if (text) {
				strcpy (text, comment);
				strcat (text, " ");
				strcat (text, nc);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, text);
				free (comment);
				free (text);
			} else {
				r_sys_perror ("malloc");
			}
		} else {
			r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, nc);
		}
		free (nc);
		}
		break;
	case '*': // "CC*"
		r_meta_list (core->anal, R_META_TYPE_COMMENT, 1);
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
			char *comment = r_meta_get_string (
					core->anal, R_META_TYPE_COMMENT, addr);
			if (!comment || (comment && !strstr (comment, newcomment))) {
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT,
						addr, newcomment);
			}
			free (comment);
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
			eprintf ("Usage\n");
			return false;
		}
		p = strchr (s, ' ');
		if (p) {
			*p++ = 0;
		}
		ut64 addr;
		if (input[2]=='-') {
			if (input[3]) {
				addr = r_num_math (core->num, input+3);
				r_meta_del (core->anal,
						R_META_TYPE_COMMENT,
						addr, 1);
			} else eprintf ("Usage: CCa-[address]\n");
			free (s);
			return true;
		}
		addr = r_num_math (core->num, s);
		// Comment at
		if (p) {
			if (input[2]=='+') {
				char *comment = r_meta_get_string (
						core->anal, R_META_TYPE_COMMENT,
						addr);
				if (comment) {
					char* text = r_str_newf ("%s\n%s", comment, p);
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
						addr, addr + 1, p);
			}
		} else {
			eprintf ("Usage: CCa [address] [comment]\n");
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
		r_meta_list (core->anal, R_META_TYPE_VARTYPE, 0);
		break;
	case ' ': // "Ct <vartype comment> @ addr"
		{
		const char* newcomment = r_str_trim_head_ro (input + 2);
		char *text, *comment = r_meta_get_string (core->anal, R_META_TYPE_VARTYPE, addr);
		char *nc = strdup (newcomment);
		r_str_unescape (nc);
		if (comment) {
			text = malloc (strlen (comment)+ strlen (newcomment)+2);
			if (text) {
				strcpy (text, comment);
				strcat (text, " ");
				strcat (text, nc);
				r_meta_set_string (core->anal, R_META_TYPE_VARTYPE, addr, text);
				free (comment);
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
		char *comment = r_meta_get_string (
				core->anal, R_META_TYPE_VARTYPE, at);
		if (comment) {
			r_cons_println (comment);
			free (comment);
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

static int cmd_meta_others(RCore *core, const char *input) {
	int n, type = input[0], subtype;
	char *t = 0, *p, *p2, name[256];
	int repeat = 1;
	ut64 addr_end = 0LL, addr = core->offset;

	switch (input[1]) {
	case '?':
		switch (input[0]) {
		case 'f':
			r_cons_println(
				"Usage: Cf[-] [sz] [fmt..] [@addr]\n\n"
				"'sz' indicates the byte size taken up by struct.\n"
				"'fmt' is a 'pf?' style format string. It controls only the display format.\n\n"
				"You may wish to have 'sz' != sizeof(fmt) when you have a large struct\n"
				"but have only identified specific fields in it. In that case, use 'fmt'\n"
				"to show the fields you know about (perhaps using 'skip' fields), and 'sz'\n"
				"to match the total struct size in mem.\n");
			break;
		case 's':
			r_core_cmd_help (core, help_msg_Cs);
			break;
		default:
			r_cons_println ("See C?");
			break;
		}
		break;
	case '-':
		switch (input[2]) {
		case '*':
			core->num->value = r_meta_del (core->anal,
					input[0], 0, UT64_MAX);
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
					core->num->value = r_meta_del (core->anal, input[0], cur_addr, size);
				}
				break;
			} else {
				addr = r_num_math (core->num, input + 3);
				/* fallthrough */
			}
		default:
			core->num->value = r_meta_del (core->anal,
					input[0], addr, 1);
			break;
		}
		break;
	case '*':
		r_meta_list (core->anal, input[0], 1);
		break;
	case 'j':
		r_meta_list (core->anal, input[0], 'j');
		break;
	case '!':
		{
			char *out, *comment = r_meta_get_string (
					core->anal, R_META_TYPE_COMMENT, addr);
			out = r_core_editor (core, NULL, comment);
			if (out) {
				//r_meta_add (core->anal->meta, R_META_TYPE_COMMENT, addr, 0, out);
				r_core_cmdf (core, "CC-@0x%08"PFMT64x, addr);
				//r_meta_del (core->anal->meta, input[0], addr, addr+1);
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, out);
				free (out);
			}
			free (comment);
		}
		break;
	case '.':
		if (input[2] == '.') { // "Cs.."
			RAnalMetaItem *mi = r_meta_find (core->anal, addr, type, R_META_WHERE_HERE);
			if (mi) {
				r_meta_print (core->anal, mi, input[3], NULL, false);
				r_meta_item_free (mi);
			}
			break;
		} else if (input[2] == 'j') { // "Cs.j"
			RAnalMetaItem *mi = r_meta_find (core->anal, addr, type, R_META_WHERE_HERE);
			if (mi) {
				r_meta_print (core->anal, mi, input[2], NULL, false);
				r_cons_newline ();
				r_meta_item_free (mi);
			}
			break;
		}
		char key[100];
		const char *val;
		RAnalMetaItem mi;
		Sdb *s = core->anal->sdb_meta;
		bool esc_bslash = core->print->esc_bslash;
		snprintf (key, sizeof (key), "meta.%c.0x%" PFMT64x, type, addr);
		val = sdb_const_get (s, key, 0);
		if (!val) {
			break;
		}
		if (!r_meta_deserialize_val (core->anal, &mi, type, addr, val)) {
			break;
		}
		if (!mi.str) {
			break;
		}
		if (type == 's') {
			char *esc_str;
			switch (mi.subtype) {
			case R_STRING_ENC_UTF8:
				esc_str = r_str_escape_utf8 (mi.str, false, esc_bslash);
				break;
			case 0:  /* temporary legacy workaround */
				esc_bslash = false;
			default:
				esc_str = r_str_escape_latin1 (mi.str, false, esc_bslash, false);
			}
			if (esc_str) {
				r_cons_printf ("\"%s\"\n", esc_str);
				free (esc_str);
			} else {
				r_cons_println ("<oom>");
			}
		} else if (type == 'd') {
			r_cons_printf ("%"PFMT64u"\n", mi.size);
		} else {
			r_cons_println (mi.str);
		}
		free (mi.str);
		break;
	case ' ':
	case '\0':
	case 'g':
	case 'a':
	case '8':
		if (type != 'z' && !input[1] && !core->tmpseek) {
			r_meta_list (core->anal, type, 0);
			break;
		}
		if (type == 'z') {
			type = 's';
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
								eprintf ("Cannot resolve format '%s'\n", p + 1);
								break;
							}
						}
						if (n < 1) {
							n = r_print_format_struct_size (core->print, p, 0, 0);
							if (n < 1) {
								eprintf ("Warning: Cannot resolve struct size for '%s'\n", p);
								n = 32; //
							}
						}
						//make sure we do not overflow on r_print_format
						if (n > core->blocksize) {
							n = core->blocksize;
						}
						int r = r_print_format (core->print, addr, core->block,
							n, p, 0, NULL, NULL);
						if (r < 0) {
							n  = -1;
						}
					} else {
						eprintf ("Usage: Cf [size] [pf-format-string]\n");
						break;
					}
				} else if (type == 's') { //Cs
					char tmp[256] = R_EMPTY;
					int i, j, name_len = 0;
					if (input[1] == 'a' || input[1] == '8') {
						(void)r_io_read_at (core->io, addr, (ut8*)name, sizeof (name) - 1);
						name[sizeof (name) - 1] = '\0';
						name_len = strlen (name);
					} else {
						(void)r_io_read_at (core->io, addr, (ut8*)tmp, sizeof (tmp) - 3);
						name_len = r_str_nlen_w (tmp, sizeof (tmp) - 3);
						//handle wide strings
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
					RFlagItem *fi;
					p = strchr (t, ' ');
					if (p) {
						*p++ = '\0';
						p = (char *)r_str_trim_head_ro (p);
						strncpy (name, p, sizeof (name)-1);
					} else {
						if (type != 's') {
							fi = r_flag_get_i (core->flags, addr);
							if (fi) {
								strncpy (name, fi->name, sizeof (name)-1);
							}
						}
					}
				}
			}
			if (!n) {
				n++;
			}
			addr_end = addr + n;
			if (type == 's') {
				switch (input[1]) {
				case 'a':
				case '8':
					subtype = input[1];
					break;
				default:
					subtype = R_STRING_ENC_GUESS;
				}
				r_meta_add_with_subtype (core->anal, type, subtype, addr, addr_end, name);
			} else {
				r_meta_add (core->anal, type, addr, addr_end, name);
			}
			free (t);
			repcnt ++;
			addr = addr_end;
		}
		//r_meta_cleanup (core->anal->meta, 0LL, UT64_MAX);
		break;
	default:
		eprintf ("Missing space after CC\n");
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
	int idx;
	char *oname = NULL, *name = NULL;
	char *oldcomment = NULL;
	char *heap_comment = NULL;
	RAnalVar *var;

	if (input[1] == '?' || (input[0] != 'b' && input[0] != 'r' && input[0] != 's') ) {
		r_comment_var_help (core, input[0]);
		return;
	}
	if (!fcn) {
		eprintf ("Can't find function here\n");
		return;
	}
	oname = name = strdup (input + 2);
	while (*name == ' ') {
		name++;
	}
	switch (input[1]) {
	case '*': // "Cv*"
	case '\0': { // "Cv"
		RList *var_list;
		RListIter *iter;
		var_list = r_anal_var_list (core->anal, fcn, input[0]);
		r_list_foreach (var_list, iter, var) {
			oldcomment = r_meta_get_var_comment (core->anal, input[0], var->delta, fcn->addr);
			if (!oldcomment) {
				continue;
			}
			if (!input[1]) {
				r_cons_printf ("%s : %s\n", var->name, oldcomment);
			} else {
				r_cons_printf ("\"Cv%c %s base64:%s @ 0x%08"PFMT64x"\"\n", input[0], var->name,
					sdb_encode ((const ut8 *) oldcomment, strlen(oldcomment)), fcn->addr);
			}
		}
		}
		break;
	case ' ': { // "Cv "
		// TODO check that idx exist
		char *comment = strchr (name, ' ');
		if (comment) { // new comment given
			if (*comment) {
				*comment++ = 0;
			}
			if (!strncmp (comment, "base64:", 7)) {
				heap_comment = (char *)sdb_decode (comment + 7, NULL);
				comment = heap_comment;
			}
		}
		var = r_anal_var_get_byname (core->anal, fcn->addr, name);
		if (var) {
			idx = var->delta;
		} else if (!strncmp (name, "0x", 2))  {
			idx = (int) r_num_get (NULL, name);
		} else if (!strncmp (name, "-0x", 3)) {
			idx = -(int) r_num_get (NULL, name+1);
		} else {
			eprintf ("can't find variable named `%s`\n",name);
			free (heap_comment);
			break;
		}
		r_anal_var_free (var);
		if (!r_anal_var_get (core->anal, fcn->addr, input[0], 1, idx)) {
			eprintf ("can't find variable at given offset\n");
		} else {
			oldcomment = r_meta_get_var_comment (core->anal, input[0], idx, fcn->addr);
			if (oldcomment) {
				if (comment && *comment) {
					char *text = r_str_newf ("%s\n%s", oldcomment, comment);
					r_meta_set_var_comment (core->anal, input[0], idx, fcn->addr, text);
					free (text);
				} else {
					r_cons_println (oldcomment);
				}
			} else {
				r_meta_set_var_comment (core->anal, input[0], idx, fcn->addr, comment);
			}
		}
		free (heap_comment);
		}
		break;
	case '-': // "Cv-"
		var = r_anal_var_get_byname (core->anal, fcn->addr, name);
		if (var) {
			idx = var->delta;
		} else if (!strncmp (name, "0x", 2)) {
			idx = (int) r_num_get (NULL, name);
		} else if (!strncmp (name, "-0x", 3)) {
			idx = -(int) r_num_get (NULL, name+1);
		 }else {
			eprintf ("can't find variable named `%s`\n",name);
			break;
		}
		r_anal_var_free (var);
		//XXX TODO here we leak a var
		if (!r_anal_var_get (core->anal, fcn->addr, input[0],1,idx)) {
			eprintf ("can't find variable at given offset\n");
			break;
		}
		r_meta_var_comment_del (core->anal, input[0], idx, fcn->addr);
		break;
	case '!': { // "Cv!"
		char *comment;
		var = r_anal_var_get_byname (core->anal, fcn->addr, name);
		if (!var) {
			eprintf ("can't find variable named `%s`\n",name);
			break;
		}
		oldcomment = r_meta_get_var_comment (core->anal, input[0], var->delta, fcn->addr);
		comment = r_core_editor (core, NULL, oldcomment);
		if (comment) {
			r_meta_var_comment_del (core->anal, input[0], var->delta, fcn->addr);
			r_meta_set_var_comment (core->anal, input[0], var->delta, fcn->addr, comment);
			free (comment);
		}
		r_anal_var_free (var);
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
		r_meta_list (core->anal, R_META_TYPE_ANY, 0);
		break;
	case 'j': // "Cj"
	case '*': { // "C*"
		if (!input[0] || input[1] == '.') {
			r_meta_list_offset (core->anal, core->offset, *input);
		} else {
			r_meta_list (core->anal, R_META_TYPE_ANY, *input);
		}
		break;
	}
	case '.': { // "C."
		r_meta_list_offset (core->anal, core->offset, 0);
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
		} else r_meta_cleanup (core->anal, 0LL, UT64_MAX);
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
			eprintf ("Cannot find function here\n");
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
				r_spaces_rename (ms, NULL, input+2);
			} else {
				eprintf ("Usage: CSr [newname]\n");
			}
			break;
		case '-': // "CS-"
			if (input[2]) {
				if (input[2]=='*') {
					r_spaces_unset (ms, NULL);
				} else {
					r_spaces_unset (ms, input+2);
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
