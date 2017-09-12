/* radare2 - LGPL - Copyright 2009-2017 - pancake */

#include "r_anal.h"
#include "r_bin.h"
#include "r_cons.h"
#include "r_core.h"
#include "r_print.h"
#include "r_types.h"
#include "sdb/sdb.h"

static const char *help_msg_C[] = {
	"Usage:", "C[-LCvsdfm*?][*?] [...]", " # Metadata management",
	"C", "", "list meta info in human friendly form",
	"C*", "", "list meta info in r2 commands",
	"C[Chsdmf]", "", "list comments/hidden/strings/data/magic/formatted in human friendly form",
	"C[Chsdmf]*", "", "list comments/hidden/strings/data/magic/formatted in r2 commands",
	"C-", " [len] [[@]addr]", "delete metadata at given address range",
	"CL", "[-][*] [file:line] [addr]", "show or add 'code line' information (bininfo)",
	"CS", "[-][space]", "manage meta-spaces to filter comments, etc..",
	"CC", "[?] [-] [comment-text] [@addr]", "add/remove comment",
	"CC.", "[addr]", "show comment in current address",
	"CC!", " [@addr]", "edit comment with $EDITOR",
	"CCa", "[-at]|[at] [text] [@addr]", "add/remove comment at given address",
	"CCu", " [comment-text] [@addr]", "add unique comment",
	"Cv", "[bsr][?]", "add comments to args",
	"Cs", "[?] [-] [size] [@addr]", "add string",
	"Cz", "[@addr]", "add zero-terminated string",
	"Ch", "[-] [size] [@addr]", "hide data",
	"Cd", "[-] [size] [repeat] [@addr]", "hexdump data array (Cd 4 10 == dword [10])",
	"Cf", "[?][-] [sz] [0|cnt][fmt] [a0 a1...] [@addr]", "format memory (see pf?)",
	"CF", "[sz] [fcn-sign..] [@addr]", "function signature",
	"Cm", "[-] [sz] [fmt..] [@addr]", "magic parse (see pm?)",
	NULL
};

static const char *help_msg_CC[] = {
	"Usage:", "CC[-+!*au] [base64:..|str] @ addr", "",
	"CC", "", "list all comments in human friendly form",
	"CC*", "", "list all comments in r2 commands",
	"CC.", "", "show comment at current offset",
	"CC,", " [file]", "show or set comment file",
	"CC", " [text]", "append comment at current address",
	"CCf", "", "list comments in function",
	"CC+", " [text]", "append comment at current address",
	"CC!", "", "edit comment using cfg.editor (vim, ..)",
	"CC-", " @ cmt_addr", "remove comment at given address",
	"CCu", " good boy @ addr", "add good boy comment at given address",
	"CCu", " base64:AA== @ addr", "add comment in base64",
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
	"Cvs?", "", "show this help",
	"Cvs", "", "list all stack based args/vars comments in human friendly format",
	"Cvs*", "", "list all stack based args/vars comments in r2 format",
	"Cvs-", "[name]", "delete comments for stack pointer var/arg with that name",
	"Cvs", "[name]", "Show comments for stack pointer var/arg with that name",
	"Cvs", "[name] [comment]", "add/append comment for the variable",
	"Cvs!", "[name]", "edit comment using cfg editor",
	NULL
};

static void cmd_meta_init(RCore *core) {
	DEFINE_CMD_DESCRIPTOR (core, C);
	DEFINE_CMD_DESCRIPTOR (core, CC);
	DEFINE_CMD_DESCRIPTOR (core, CS);
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

static void print_meta_offset(RCore *core, ut64 offset) {
	int ret, line, line_old, i;
	char file[1024];

	ret = r_bin_addr2line (core->bin, offset, file, sizeof (file)-1, &line);
	if (ret) {
		r_cons_printf ("file %s\nline %d\n", file, line);
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
	} else {
		eprintf ("Cannot find meta information at 0x%08"
			PFMT64x"\n", offset);
	}
}

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

static int print_addrinfo (void *user, const char *k, const char *v) {
	char *colonpos, *subst;

	ut64 offset = sdb_atoi (k);
	if (!offset) {
		return true;
	}
	subst = strdup (v);
	colonpos = strchr (subst, '|');

	if (colonpos) {
		*colonpos = ':';
	}
	r_cons_printf ("CL %s %s\n", subst, k);
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
	int remove = false;
	int all = false;
	const char *p = input;
	char *colon, *space, *file_line = 0;

	if (*p == '?') {
		eprintf ("Usage: CL[-][*] [file:line] [addr]");
		return 0;
	}

	if (*p == '-') {
		p++;
		remove = true;
	}

	if (*p == '*') {
		p++;
		all = true;
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
	} else {
		offset = core->offset;
	}
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
		if (!file_line) {
			return -1;
		}
		colon = strchr (file_line, ':');
		if (!colon) {
			goto error;
		}
		*colon = '|';
		while (*p && *p != ' ') {
			p++;
		}
		while (*p == ' ') {
			p++;
		}
		if (*p != '\0') {
			// TODO: use r_num_math here or something less rusty than sscanf
			ret = sscanf (p, "0x%"PFMT64x, &offset);
			if (ret != 1) {
				remove = 0;
				eprintf ("Failed to parse addr at %s\n", p);
				// goto error;
			} else {
				ret = cmd_meta_add_fileline (core->bin->cur->sdb_addrinfo,
						file_line, offset);
				goto error;
			}
		}
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
		case 'j': // "CCfj"
			r_meta_list_at (core->anal, R_META_TYPE_COMMENT, 'j', core->offset);
			break;
		default:
			r_meta_list_at (core->anal, R_META_TYPE_COMMENT, 'f', core->offset);
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
		const char* newcomment = r_str_chop_ro (input + 2);
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
	case '*':
		r_meta_list (core->anal, R_META_TYPE_COMMENT, 1);
		break;
	case '-': // "CC-"
		r_meta_del (core->anal, R_META_TYPE_COMMENT, core->offset, 1, NULL);
		break;
	case 'u':
		//
		{
		char *newcomment;
		const char *arg = input + 2;
		while (*arg && *arg == ' ') arg++;
		if (!strncmp (arg, "base64:", 7)) {
			char *s = (char *)sdb_decode (arg+7, NULL);
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
	case 'a':
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
						addr, 1, NULL);
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

static int cmd_meta_hsdmf(RCore *core, const char *input) {
	int n, type = input[0];
	char *t = 0, *p, name[256];
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
		default:
			r_cons_println ("See C?");
			break;
		}
		break;
	case '-':
		switch (input[2]) {
		case '*':
			core->num->value = r_meta_del (core->anal,
					input[0], 0, UT64_MAX, NULL);
			break;
		case ' ':
			addr = r_num_math (core->num, input+3);
			/* fallthrough */
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
				r_meta_set_string (core->anal, R_META_TYPE_COMMENT, addr, out);
				free (out);
			}
			free (comment);
		}
		break;
	case ' ':
	case '\0':
		if (type != 'z' && !input[1] && !core->tmpseek) {
			r_meta_list (core->anal, type, 0);
			break;
		}
		if (type == 'z') {
			type = 's';
		}
		if (strlen (input) > 2) {
			char *rep = strchr (input + 2, '[');
			if (!rep) rep = strchr (input + 2, ' ');
			if (rep) {
				repeat = r_num_get (core->num, rep + 1);
			}
		}
		int repcnt = 0;
		if (repeat < 1) {
			repeat = 1;
		}
		while (repcnt < repeat) {
			t = strdup (r_str_chop_ro (input + 1));
			p = NULL;
			n = 0;
			strncpy (name, t, sizeof (name) - 1);
			if (type != 'C') {
				n = r_num_math (core->num, t);
				if (type == 'f') { // "Cf"
					p = strchr (t, ' ');
					if (p) {
						if (n < 1) {
							n = r_print_format_struct_size (p + 1, core->print, 0);
							if (n < 1) {
								eprintf ("Cannot resolve struct size\n");
								n = 32; //
							}
						}
						//make sure we do not overflow on r_print_format
						if (n > core->blocksize) {
							n = core->blocksize;
						}
						int r = r_print_format (core->print, addr, core->block,
							n, p + 1, 0, NULL, NULL);
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
					(void)r_core_read_at (core, addr, (ut8*)tmp, sizeof (tmp) - 3);
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
						*p = '\0';
						strncpy (name, p + 1, sizeof (name)-1);
					} else {
						if (type != 's') {
							fi = r_flag_get_i (core->flags, addr);
							if (fi) strncpy (name, fi->name, sizeof (name)-1);
						}
					}
				}
			}
			if (!n) {
				n++;
			}
			addr_end = addr + n;
			r_meta_add (core->anal, type, addr, addr_end, name);
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
		eprintf ("Cant find function here\n");
		return;
	}
	oname = name = strdup (input + 2);
	while (*name == ' ') {
		name++;
	}
	switch (input[1]) {
	case '*':
	case '\0': {
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
	case ' ': {
		// TODO check that idx exist
		char *comment = strstr (name, " ");
		if (comment) { // new comment given
			if (*comment) {
				*comment++ = 0;
			}
			if (!strncmp (comment, "base64:", 7)) {
				heap_comment = (char *)sdb_decode (comment + 7, NULL);
				comment = heap_comment;
			}
		}
		var = r_anal_var_get_byname (core->anal, fcn, name);
		if (var) {
			idx = var->delta;
		} else if (!strncmp (name, "0x", 2))  {
			idx = (int) r_num_get (NULL, name);
		} else if (!strncmp (name, "-0x", 3)) {
			idx = -(int) r_num_get (NULL, name+1);
		} else {
			eprintf ("cant find variable named `%s`\n",name);
			free (heap_comment);
			break;
		}
		r_anal_var_free (var);
		if (!r_anal_var_get (core->anal, fcn->addr, input[0], 1, idx)) {
			eprintf ("cant find variable at given offset\n");
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
	case '-':
		var = r_anal_var_get_byname (core->anal,fcn, name);
		if (var) {
			idx = var->delta;
		} else if (!strncmp (name, "0x", 2)) {
			idx = (int) r_num_get (NULL, name);
		} else if (!strncmp (name, "-0x", 3)) {
			idx = -(int) r_num_get (NULL, name+1);
		 }else {
			eprintf ("cant find variable named `%s`\n",name);
			break;
		}
		r_anal_var_free (var);
		//XXX TODO here we leak a var
		if (!r_anal_var_get (core->anal, fcn->addr, input[0],1,idx)) {
			eprintf ("cant find variable at given offset\n");
			break;
		}
		r_meta_var_comment_del (core->anal, input[0], idx, fcn->addr);
		break;
	case '!': {
		char *comment;
		var = r_anal_var_get_byname (core->anal,fcn, name);
		if (!var) {
			eprintf ("cant find variable named `%s`\n",name);
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
	case 'v': // Cr
		r_comment_vars (core, input + 1);
		break;
	case '\0':
	case 'j':
	case '*':
		r_meta_list (core->anal, R_META_TYPE_ANY, *input);
		break;
	case 'L': // "CL"
		cmd_meta_lineinfo (core, input + 1);
		break;
	case 'C': // "CC"
		cmd_meta_comment (core, input);
		break;
	case 'r': /* Cr run command*/
	case 'h': /* Ch comment */
	case 's': /* Cs string */
	case 'z': /* Cz zero-terminated string */
	case 'd': /* Cd data */
	case 'm': /* Cm magic */
	case 'f': /* Cf formatted */
		cmd_meta_hsdmf (core, input);
		break;
	case '-':
		if (input[1]!='*') {
			i = r_num_math (core->num, input+((input[1]==' ')?2:1));
			r_meta_del (core->anal, R_META_TYPE_ANY, core->offset, i, "");
		} else r_meta_cleanup (core->anal, 0LL, UT64_MAX);
		break;
	case '?':
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
		case '?':
			r_core_cmd_help (core, help_msg_CS);
			break;
		case '+':
			r_space_push (ms, input + 2);
			break;
		case 'r':
			if (input[2] == ' ') {
				r_space_rename (ms, NULL, input+2);
			} else {
				eprintf ("Usage: CSr [newname]\n");
			}
			break;
		case '-':
			if (input[2]) {
				if (input[2]=='*') {
					r_space_unset (ms, NULL);
				} else {
					r_space_unset (ms, input+2);
				}
			} else {
				r_space_pop (ms);
			}
			break;
		case 'j':
		case '\0':
		case '*':
			r_space_list (ms, input[1]);
			break;
		case ' ':
			r_space_set (ms, input + 2);
			break;
#if 0
		case 'm':
			{ RFlagItem *f;
				ut64 off = core->offset;
				if (input[2] == ' ')
					off = r_num_math (core->num, input+2);
				f = r_flag_get_i (core->flags, off);
				if (f) {
					f->space = core->flags->space_idx;
				} else eprintf ("Cannot find any flag at 0x%"PFMT64x".\n", off);
			}
			break;
#endif
		default: {
				 int i, j = 0;
				 for (i = 0; i < R_FLAG_SPACES_MAX; i++) {
					 if (!ms->spaces[i]) continue;
					 r_cons_printf ("%02d %c %s\n", j++,
						 (i == ms->space_idx)?'*':' ',
						 ms->spaces[i]);
				 }
			 } break;
		}
		break;
	}
	return true;
}
