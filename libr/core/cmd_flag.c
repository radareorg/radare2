/* radare - LGPL - Copyright 2009-2020 - pancake */

#include <stddef.h>
#include "r_cons.h"
#include "r_core.h"

static const char *help_msg_f[] = {
	"Usage: f","[?] [flagname]", " # Manage offset-name flags",
	"f","","list flags (will only list flags from selected flagspaces)",
	"f?","flagname","check if flag exists or not, See ?? and ?!",
	"f."," [*[*]]","list local per-function flags (*) as r2 commands",
	"f.","blah=$$+12","set local function label named 'blah'",
	"f."," fname","list all local labels for the given function",
	"f,","","table output for flags",
	"f*","","list flags in r commands",
	"f"," name 12 @ 33","set flag 'name' with length 12 at offset 33",
	"f"," name = 33","alias for 'f name @ 33' or 'f name 1 33'",
	"f"," name 12 33 [cmt]","same as above + optional comment",
	"f-",".blah@fcn.foo","delete local label from function at current seek (also f.-)",
	"f--","","delete all flags and flagspaces (deinit)",
	"f+","name 12 @ 33","like above but creates new one if doesnt exist",
	"f-","name","remove flag 'name'",
	"f-","@addr","remove flag at address expression",
	"f="," [glob]","list range bars graphics with flag offsets and sizes",
	"fa"," [name] [alias]","alias a flag to evaluate an expression",
	"fb"," [addr]","set base address for new flags",
	"fb"," [addr] [flag*]","move flags matching 'flag' to relative addr",
	"fc","[?][name] [color]","set color for given flag",
	"fC"," [name] [cmt]","set comment for given flag",
	"fd","[?] addr","return flag+delta",
	"fe-","","resets the enumerator counter",
	"fe"," [name]","create flag name.#num# enumerated flag. See fe?",
	"ff"," ([glob])","distance in bytes to reach the next flag (see sn/sp)",
	"fi"," [size] | [from] [to]","show flags in current block or range",
	"fg","[*] ([prefix])","construct a graph with the flag names",
	"fj","","list flags in JSON format",
	"fl"," (@[flag]) [size]","show or set flag length (size)",
	"fla"," [glob]","automatically compute the size of all flags matching glob",
	"fm"," addr","move flag at current offset to new address",
	"fn","","list flags displaying the real name (demangled)",
	"fnj","","list flags displaying the real name (demangled) in JSON format",
	"fN","","show real name of flag at current address",
	"fN"," [[name]] [realname]","set flag real name (if no flag name current seek one is used)",
	"fo","","show fortunes",
	"fO", " [glob]", "flag as ordinals (sym.* func.* method.*)",
	//" fc [name] [cmt]  ; set execution command for a specific flag"
	"fr"," [[old]] [new]","rename flag (if no new flag current seek one is used)",
	"fR","[?] [f] [t] [m]","relocate all flags matching f&~m 'f'rom, 't'o, 'm'ask",
	"fs","[?]+-*","manage flagspaces",
	"ft","[?]*","flag tags, useful to find all flags matching some words",
	"fV","[*-] [nkey] [offset]","dump/restore visual marks (mK/'K)",
	"fx","[d]","show hexdump (or disasm) of flag:flagsize",
	"fq","","list flags in quiet mode",
	"fz","[?][name]","add named flag zone -name to delete. see fz?[name]",
	NULL
};

static const char *help_msg_fc[] = {
	"Usage: fc", "<flagname> [color]", " # List colors with 'ecs'",
	"fc", " flagname", "Get current color for given flagname",
	"fc", " flagname color", "Set color to a flag",
	NULL
};
static const char *help_msg_fd[] = {
	"Usage: fd[d]", " [offset|flag|expression]", " # Describe flags",
	"fd", " $$" , "# describe flag + delta for given offset",
 	"fd.", " $$", "# check flags in current address (no delta)",
	"fdd", " $$", "# describe flag without space restrictions",
	"fdw", " [string]", "# filter closest flag by string for current offset",
	NULL
};

static const char *help_msg_fs[] = {
	"Usage: fs","[*] [+-][flagspace|addr]", " # Manage flagspaces",
	"fs","","display flagspaces",
	"fs*","","display flagspaces as r2 commands",
	"fsj","","display flagspaces in JSON",
	"fs"," *","select all flagspaces",
	"fs"," flagspace","select flagspace or create if it doesn't exist",
	"fs","-flagspace","remove flagspace",
	"fs","-*","remove all flagspaces",
	"fs","+foo","push previous flagspace and set",
	"fs","-","pop to the previous flagspace",
	"fs","-.","remove the current flagspace",
	"fsq","", "list flagspaces in quiet mode",
	"fsm"," [addr]","move flags at given address to the current flagspace",
	"fss","","display flagspaces stack",
	"fss*","","display flagspaces stack in r2 commands",
	"fssj","","display flagspaces stack in JSON",
	"fsr"," newname","rename selected flagspace",
	NULL
};

static const char *help_msg_fz[] = {
	"Usage: f", "[?|-name| name] [@addr]", " # Manage flagzones",
	" fz", " math", "add new flagzone named 'math'",
	" fz-", "math", "remove the math flagzone",
	" fz-", "*", "remove all flagzones",
	" fz.", "", "show around flagzone context",
	" fz:", "", "show what's in scr.flagzone for visual",
	" fz*", "", "dump into r2 commands, for projects",
	NULL
};

static void cmd_flag_init(RCore *core, RCmdDesc *parent) {
	DEFINE_CMD_DESCRIPTOR (core, f);
	DEFINE_CMD_DESCRIPTOR (core, fc);
	DEFINE_CMD_DESCRIPTOR (core, fd);
	DEFINE_CMD_DESCRIPTOR (core, fs);
	DEFINE_CMD_DESCRIPTOR (core, fz);
}

static bool listFlag(RFlagItem *flag, void *user) {
	r_list_append (user, flag);
	return true;
}

static size_t countMatching (const char *a, const char *b) {
	size_t matches = 0;
	for (; *a && *b; a++, b++) {
		if (*a != *b) {
			break;
		}
		matches++;
	}
	return matches;
}

static const char *__isOnlySon(RCore *core, RList *flags, const char *kw) {
        RListIter *iter;
        RFlagItem *f;

        size_t count = 0;
        char *fname = NULL;
        r_list_foreach (flags, iter, f) {
                if (!strncmp (f->name, kw, strlen (kw))) {
                        count++;
                        if (count > 1) {
                                return NULL;
                        }
                        fname = f->name;
                }
        }
        return fname;
}

static RList *__childrenFlagsOf(RCore *core, RList *flags, const char *prefix) {
	RList *list = r_list_newf (free);
	RListIter *iter, *iter2;
	RFlagItem *f, *f2;
	char *fn;

	const size_t prefix_len = strlen (prefix);
	r_list_foreach (flags, iter, f) {
		if (prefix_len > 0 && strncmp (f->name, prefix, prefix_len)) {
			continue;
		}
		if (prefix_len > strlen (f->name)) {
			continue;
		}
		if (r_cons_is_breaked ()) {
			break;
		}
		const char *name = f->name;
		int name_len = strlen (name);
		r_list_foreach (flags, iter2, f2) {
			if (prefix_len > strlen (f2->name)) {
				continue;
			}
			if (prefix_len > 0 && strncmp (f2->name, prefix, prefix_len)) {
				continue;
			}
			int matching = countMatching (name, f2->name);
			if (matching < prefix_len || matching == name_len) {
				continue;
			}
			if (matching > name_len) {
				break;
			}
			if (matching < name_len) {
				name_len = matching;
			}
		}
		char *kw = r_str_ndup (name, name_len + 1);
		const int kw_len = strlen (kw);
		const char *only = __isOnlySon (core, flags, kw);
		if (only) {
			free (kw);
			kw = strdup (only);
		} else {
			const char *fname = NULL;
			size_t fname_len = 0;
			r_list_foreach (flags, iter2, f2) {
				if (strncmp (f2->name, kw, kw_len)) {
					continue;
				}
				if (fname) {
					int matching = countMatching (fname, f2->name);
					if (fname_len) {
						if (matching < fname_len) {
							fname_len = matching;
						}
					} else {
						fname_len = matching;
					}
				} else {
					fname = f2->name;
				}
			}
			if (fname_len > 0) {
				free (kw);
				kw = r_str_ndup (fname, fname_len);
			}
		}
		
		bool found = false;
		r_list_foreach (list, iter2, fn) {
			if (!strcmp (fn, kw)) {
				found = true;
				break;
			}
		}
		if (found) {
			free (kw);
		} else {
			if (strcmp (prefix, kw)) {
				r_list_append (list, kw);
			} else {
				free (kw);
			}
		}
	}
	return list;
}

static void __printRecursive (RCore *core, RList *list, const char *prefix, int mode, int depth);

static void __printRecursive (RCore *core, RList *flags, const char *prefix, int mode, int depth) {
	char *fn;
	RListIter *iter;
	const int prefix_len = strlen (prefix);
	// eprintf ("# fg %s\n", prefix);
	if (mode == '*' && !*prefix) {
		r_cons_printf ("agn root\n");
	}
	if (r_flag_get (core->flags, prefix)) {
		return;
	}
	RList *children = __childrenFlagsOf (core, flags, prefix);
	r_list_foreach (children, iter, fn) {
		if (!strcmp (fn, prefix)) {
			continue;
		}
		if (mode == '*') {
			r_cons_printf ("agn %s %s\n", fn, fn + prefix_len);
			r_cons_printf ("age %s %s\n", *prefix? prefix: "root", fn);
		} else {
			r_cons_printf ("%s %s\n", r_str_pad (' ', prefix_len), fn + prefix_len);
		}
		//r_cons_printf (".fg %s\n", fn);
		__printRecursive (core, flags, fn, mode, depth+1);
	}
	r_list_free (children);
}

static void __flag_graph (RCore *core, const char *input, int mode) {
	RList *flags = r_list_newf (NULL);
	r_flag_foreach_space (core->flags, r_flag_space_cur (core->flags), listFlag, flags);
	__printRecursive (core, flags, input, mode, 0);
	r_list_free (flags);
}

static void spaces_list(RSpaces *sp, int mode) {
	RSpaceIter it;
	RSpace *s;
	const RSpace *cur = r_spaces_current (sp);
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new ();
		pj_a (pj);
	}
	r_spaces_foreach (sp, it, s) {
		int count = r_spaces_count (sp, s->name);
		if (mode == 'j') {
			pj_o (pj);
			pj_ks (pj, "name", s->name);
			pj_ki (pj, "count", count);
			pj_kb (pj, "selected", cur == s);
			pj_end (pj);
		} else if (mode == 'q') {
			r_cons_printf ("%s\n", s->name);
		} else if (mode == '*') {
			r_cons_printf ("%s %s\n", sp->name, s->name);
		} else {
			r_cons_printf ("%5d %c %s\n", count, (!cur || cur == s)? '*': '.',
				s->name);
		}
	}
	if (mode == '*' && r_spaces_current (sp)) {
		r_cons_printf ("%s %s # current\n", sp->name, r_spaces_current_name (sp));
	}
	if (mode == 'j') {
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
}

static void cmd_fz(RCore *core, const char *input) {
	switch (*input) {
	case '?': // "fz?"
		r_core_cmd_help (core, help_msg_fz);
		break;
	case '.': // "fz."
		{
			const char *a = NULL, *b = NULL;
			r_flag_zone_around (core->flags, core->offset, &a, &b);
			r_cons_printf ("%s %s\n", a?a:"~", b?b:"~");
		}
		break;
	case ':': // "fz:"
		{
			const char *a, *b;
			int a_len = 0;
			int w = r_cons_get_size (NULL);
			r_flag_zone_around (core->flags, core->offset, &a, &b);
			if (a) {
				r_cons_printf ("[<< %s]", a);
				a_len = strlen (a) + 4;
			}
			int padsize = (w / 2)  - a_len;
			int title_size = 12;
			if (a || b) {
				char *title = r_str_newf ("[ 0x%08"PFMT64x" ]", core->offset);
				title_size = strlen (title);
				padsize -= strlen (title) / 2;
				const char *halfpad = r_str_pad (' ', padsize);
				r_cons_printf ("%s%s", halfpad, title);
				free (title);
			}
			if (b) {
				padsize = (w / 2) - title_size - strlen (b) - 4;
				const char *halfpad = padsize > 1? r_str_pad (' ', padsize): "";
				r_cons_printf ("%s[%s >>]", halfpad, b);
			}
			if (a || b) {
				r_cons_newline();
			}
		}
		break;
	case ' ':
		r_flag_zone_add (core->flags, r_str_trim_head_ro (input + 1), core->offset);
		break;
	case '-':
		if (input[1] == '*') {
			r_flag_zone_reset (core->flags);
		} else {
			r_flag_zone_del (core->flags, input + 1);
		}
		break;
	case '*':
		r_flag_zone_list (core->flags, '*');
		break;
	case 0:
		r_flag_zone_list (core->flags, 0);
		break;
	}
}

struct flagbar_t {
	RCore *core;
	int cols;
};

static bool flagbar_foreach(RFlagItem *fi, void *user) {
	struct flagbar_t *u = (struct flagbar_t *)user;
	ut64 min = 0, max = r_io_size (u->core->io);
	RIOMap *m = r_io_map_get (u->core->io, fi->offset);
	if (m) {
		min = m->itv.addr;
		max = m->itv.addr + m->itv.size;
	}
	r_cons_printf ("0x%08"PFMT64x" ", fi->offset);
	r_print_rangebar (u->core->print, fi->offset, fi->offset + fi->size, min, max, u->cols);
	r_cons_printf ("  %s\n", fi->name);
	return true;
}

static void flagbars(RCore *core, const char *glob) {
	int cols = r_cons_get_size (NULL);
	cols -= 80;
	if (cols < 0) {
		cols += 80;
	}

	struct flagbar_t u = { .core = core, .cols = cols };
	r_flag_foreach_space_glob (core->flags, glob, r_flag_space_cur (core->flags), flagbar_foreach, &u);
}

struct flag_to_flag_t {
	ut64 next;
	ut64 offset;
};

static bool flag_to_flag_foreach(RFlagItem *fi, void *user) {
	struct flag_to_flag_t *u = (struct flag_to_flag_t *)user;
	if (fi->offset < u->next && fi->offset > u->offset) {
		u->next = fi->offset;
	}
	return true;
}

static int flag_to_flag(RCore *core, const char *glob) {
	r_return_val_if_fail (glob, 0);
	glob = r_str_trim_head_ro (glob);
	struct flag_to_flag_t u = { .next = UT64_MAX, .offset = core->offset };
	r_flag_foreach_glob (core->flags, glob, flag_to_flag_foreach, &u);
	if (u.next != UT64_MAX && u.next > core->offset) {
		return u.next - core->offset;
	}
	return 0;
}

typedef struct {
	RTable *t;
} FlagTableData;

static bool __tableItemCallback(RFlagItem *flag, void *user) {
	FlagTableData *ftd = user;
	if (!R_STR_ISEMPTY (flag->name)) {
		RTable *t = ftd->t;
		const char *spaceName = (flag->space && flag->space->name)? flag->space->name: "";
		const char *addr = sdb_fmt ("0x%08"PFMT64x, flag->offset);
		r_table_add_row (t, addr, sdb_fmt ("%d", flag->size), spaceName, flag->name, NULL);
	}
	return true;
}

static void cmd_flag_table(RCore *core, const char *input) {
	const char fmt = *input++;
	const char *q = input;
	FlagTableData ftd = {0};
	RTable *t = r_core_table (core);
	ftd.t = t;
	RTableColumnType *typeString = r_table_type ("string");
	RTableColumnType *typeNumber = r_table_type ("number");
	r_table_add_column (t, typeNumber, "addr", 0);
	r_table_add_column (t, typeNumber, "size", 0);
	r_table_add_column (t, typeString, "space", 0);
	r_table_add_column (t, typeString, "name", 0);

	RSpace *curSpace = r_flag_space_cur (core->flags);
	r_flag_foreach_space (core->flags, curSpace, __tableItemCallback, &ftd);
	if (r_table_query (t, q)) {
		char *s = (fmt == 'j')
			? r_table_tojson (t)
			: r_table_tostring (t);
		r_cons_printf ("%s\n", s);
		free (s);
	}
	r_table_free (t);
}

static void cmd_flag_tags(RCore *core, const char *input) {
	char mode = input[1];
	for (; *input && !IS_WHITESPACE (*input); input++) {}
	char *inp = strdup (input);
	char *arg = inp;
	r_str_trim (arg);
	if (!*arg && !mode) {
		const char *tag;
		RListIter *iter;
		RList *list = r_flag_tags_list (core->flags, NULL);
		r_list_foreach (list, iter, tag) {
			r_cons_printf ("%s\n", tag);
		}
		r_list_free (list);
		free (inp);
		return;
	}
	if (mode == '?') {
		eprintf ("Usage: ft[?ln] [k] [v ...]\n");
		eprintf (" ft tag strcpy strlen ... # set words for the 'string' tag\n");
		eprintf (" ft tag                   # get offsets of all matching flags\n");
		eprintf (" ft                       # list all tags\n");
		eprintf (" ftn tag                  # get matching flagnames fot given tag\n");
		eprintf (" ftw                      # flag tags within this file\n");
		eprintf (" ftj                      # list all flagtags in JSON format\n");
		eprintf (" ft*                      # list all flagtags in r2 commands\n");
		free (inp);
		return;
	}
	if (mode == 'w') { // "ftw"
		const char *tag;
		RListIter *iter;
		RList *list = r_flag_tags_list (core->flags, NULL);
		r_list_foreach (list, iter, tag) {
			r_cons_printf ("%s:\n", tag);
			r_core_cmdf (core, "ftn %s", tag);
		}
		r_list_free (list);
		free (inp);
		return;
	}
	if (mode == '*') {
		RListIter *iter;
		const char *tag;
		RList *list = r_flag_tags_list (core->flags, NULL);
		r_list_foreach (list, iter, tag) {
			const char *flags = sdb_get (core->flags->tags, sdb_fmt ("tag.%s", tag), NULL);
			r_cons_printf ("ft %s %s\n", tag, flags);
		}
		r_list_free (list);
		free (inp);
		return;
	}
	if (mode == 'j') { // "ftj"
		RListIter *iter, *iter2;
		const char *tag, *flg;
		PJ *pj = pj_new ();
		pj_o (pj);
		RList *list = r_flag_tags_list (core->flags, NULL);
		r_list_foreach (list, iter, tag) {
			pj_k (pj, tag);
			pj_a (pj);
			RList *flags = r_flag_tags_list (core->flags, tag);
			r_list_foreach (flags, iter2, flg) {
				pj_s (pj, flg);
			}
			pj_end (pj);
			r_list_free (flags);
		}
		pj_end (pj);
		r_list_free (list);
		free (inp);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
		return;
	}
	char *arg1 = strchr (arg, ' ');
	if (arg1) {
		*arg1 = 0;
		const char *a1 = r_str_trim_head_ro (arg1 + 1);
		r_flag_tags_set (core->flags, arg, a1);
	} else {
		RListIter *iter;
		RFlagItem *flag;
		RList *flags = r_flag_tags_get (core->flags, arg);
		switch (mode) {
		case 'n':
			r_list_foreach (flags, iter, flag) {
				// r_cons_printf ("0x%08"PFMT64x"\n", flag->offset);
				r_cons_printf ("0x%08"PFMT64x"  %s\n", flag->offset, flag->name);
			}
			break;
		default:
			r_list_foreach (flags, iter, flag) {
				r_cons_printf ("0x%08"PFMT64x"\n", flag->offset);
			}
			break;
		}
	}
	free (inp);
}

struct rename_flag_t {
	RCore *core;
	const char *pfx;
	int count;
};

static bool rename_flag_ordinal(RFlagItem *fi, void *user) {
	struct rename_flag_t *u = (struct rename_flag_t *)user;
	char *newName = r_str_newf ("%s%d", u->pfx, u->count++);
	if (!newName) {
		return false;
	}
	r_flag_rename (u->core->flags, fi, newName);
	free (newName);
	return true;
}

static void flag_ordinals(RCore *core, const char *str) {
	const char *glob = r_str_trim_head_ro (str);
	char *pfx = strdup (glob);
	char *p = strchr (pfx, '*');
	if (p) {
		*p = 0;
	}

	struct rename_flag_t u = { .core = core, .pfx = pfx, .count = 0 };
	r_flag_foreach_glob (core->flags, glob, rename_flag_ordinal, &u);
	free (pfx);
}

static int cmpflag(const void *_a, const void *_b) {
	const RFlagItem *flag1 = _a , *flag2 = _b;
	return (flag1->offset - flag2->offset);
}

struct find_flag_t {
	RFlagItem *win;
	ut64 at;
};

static bool find_flag_after(RFlagItem *flag, void *user) {
	struct find_flag_t *u = (struct find_flag_t *)user;
	if (flag->offset > u->at && (!u->win || flag->offset < u->win->offset)) {
		u->win = flag;
	}
	return true;
}

static bool find_flag_after_foreach(RFlagItem *flag, void *user) {
	if (flag->size != 0) {
		return true;
	}

	RFlag *flags = (RFlag *)user;
	struct find_flag_t u = { .win = NULL, .at = flag->offset };
	r_flag_foreach (flags, find_flag_after, &u);
	if (u.win) {
		flag->size = u.win->offset - flag->offset;
	}
	return true;
}

static bool adjust_offset(RFlagItem *flag, void *user) {
	st64 base = *(st64 *)user;
	flag->offset += base;
	return true;
}

static void print_space_stack(RFlag *f, int ordinal, const char *name, bool selected, PJ *pj, int mode) {
	bool first = ordinal == 0;
	switch (mode) {
	case 'j': {
		char *ename = r_str_escape (name);
		if (!ename) {
			return;
		}

		pj_o (pj);
		pj_ki (pj, "ordinal", ordinal);
		pj_ks (pj, "name", ename);
		pj_kb (pj, "selected", selected);
		pj_end (pj);
		free (ename);
		break;
	}
	case '*': {
		const char *fmt = first? "fs %s\n": "fs+%s\n";
		r_cons_printf (fmt, name);
		break;
	}
	default:
		r_cons_printf ("%-2d %s%s\n", ordinal, name, selected? " (selected)": "");
		break;
	}
}

static int flag_space_stack_list(RFlag *f, int mode) {
	RListIter *iter;
	char *space;
	int i = 0;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = pj_new ();
		pj_a (pj);
	}
	r_list_foreach (f->spaces.spacestack, iter, space) {
		print_space_stack (f, i++, space, false, pj, mode);
	}
	const char *cur_name = r_flag_space_cur_name (f);
	print_space_stack (f, i++, cur_name, true, pj, mode);
	if (mode == 'j') {
		pj_end (pj);
		r_cons_printf ("%s\n", pj_string (pj));
		pj_free (pj);
	}
	return i;
}

typedef struct {
	int rad;
	PJ *pj;
	RAnalFunction *fcn;
} PrintFcnLabelsCtx;

static bool print_function_labels_cb(void *user, const ut64 addr, const void *v) {
	const PrintFcnLabelsCtx *ctx = user;
	const char *name = v;
	switch (ctx->rad) {
	case '*':
	case 1:
		r_cons_printf ("f.%s@0x%08"PFMT64x"\n", name, addr);
		break;
	case 'j':
		pj_kn (ctx->pj, name, addr);
		break;
	default:
		r_cons_printf ("0x%08"PFMT64x" %s   [%s + %"PFMT64d"]\n",
			addr,
			name, ctx->fcn->name,
			addr - ctx->fcn->addr);
	}
	return true;
}


static void print_function_labels_for(RAnalFunction *fcn, int rad, PJ *pj) {
	r_return_if_fail (fcn && (rad != 'j' || pj));
	bool json = rad == 'j';
	if (json) {
		pj_o (pj);
	}
	PrintFcnLabelsCtx ctx = { rad, pj, fcn };
	ht_up_foreach (fcn->labels, print_function_labels_cb, &ctx);
	if (json) {
		pj_end (pj);
	}
}

static void print_function_labels(RAnal *anal, RAnalFunction *fcn, int rad) {
	r_return_if_fail (anal || fcn);
	PJ *pj = NULL;
	bool json = rad == 'j';
	if (json) {
		pj = pj_new ();
	}
	if (fcn) {
		print_function_labels_for (fcn, rad, pj);
	} else {
		if (json) {
			pj_o (pj);
		}
		RAnalFunction *f;
		RListIter *iter;
		r_list_foreach (anal->fcns, iter, f) {
			if (!f->labels->count) {
				continue;
			}
			if (json) {
				pj_k (pj, f->name);
			}
			print_function_labels_for (f, rad, pj);
		}
		if (json) {
			pj_end (pj);
		}
	}
	if (json) {
		r_cons_println (pj_string (pj));
		pj_free (pj);
	}
}

static int cmd_flag(void *data, const char *input) {
	static int flagenum = 0;
	RCore *core = (RCore *)data;
	ut64 off = core->offset;
	char *ptr, *str = NULL;
	RFlagItem *item;
	char *name = NULL;
	st64 base;

	// TODO: off+=cursor
	if (*input) {
		str = strdup (input + 1);
	}
rep:
	switch (*input) {
	case 'f': // "ff"
		if (input[1] == 's') { // "ffs"
			int delta = flag_to_flag (core, input + 2);
			if (delta > 0) {
				r_cons_printf ("0x%08"PFMT64x"\n", core->offset + delta);
			}
		} else {
			r_cons_printf ("%d\n", flag_to_flag (core, input + 1));
		}
		break;
	case 'e': // "fe"
		switch (input[1]) {
		case ' ':
			ptr = r_str_newf ("%s.%d", input + 2, flagenum);
			(void)r_flag_set (core->flags, ptr, core->offset, 1);
			flagenum++;
			free (ptr);
			break;
		case '-':
			flagenum = 0;
			break;
		default:
			eprintf ("|Usage: fe[-| name] @@= 1 2 3 4\n");
			break;
		}
		break;
	case '=': // "f="
		switch (input[1]) {
		case ' ':
			flagbars (core, input + 2);
			break;
		case 0:
			flagbars (core, NULL);
			break;
		default:
		case '?':
			eprintf ("Usage: f= [glob] to grep for matching flag names\n");
			break;
		}
		break;
	case 'a':
		if (input[1] == ' '){
			RFlagItem *fi;
			R_FREE (str);
			str = strdup (input+2);
			ptr = strchr (str, '=');
			if (!ptr)
				ptr = strchr (str, ' ');
			if (ptr) *ptr++ = 0;
			name = (char *)r_str_trim_head_ro (str);
			ptr = (char *)r_str_trim_head_ro (ptr);
			fi = r_flag_get (core->flags, name);
			if (!fi)
				fi = r_flag_set (core->flags, name,
					core->offset, 1);
			if (fi) {
				r_flag_item_set_alias (fi, ptr);
			} else {
				eprintf ("Cannot find flag '%s'\n", name);
			}
		} else {
			eprintf ("Usage: fa flagname flagalias\n");
		}
		break;
	case 'V': // visual marks
		switch (input[1]) {
		case '-':
			r_core_visual_mark_reset (core);
			break;
		case ' ':
			{
				int n = atoi (input + 1);
				if (n + ASCII_MAX + 1 < UT8_MAX) {
					const char *arg = strchr (input + 2, ' ');
					ut64 addr = arg? r_num_math (core->num, arg): core->offset;
					r_core_visual_mark_set (core, n + ASCII_MAX + 1, addr);
				}
			}
			break;
		case '?':
			eprintf ("Usage: fV[*-] [nkey] [offset]\n");
			eprintf ("Dump/Restore visual marks (mK/'K)\n");
			break;
		default:
			r_core_visual_mark_dump (core);
			break;
		}
		break;
	case 'm': // "fm"
		r_flag_move (core->flags, core->offset, r_num_math (core->num, input+1));
		break;
	case 'R': // "fR"
		switch(*str) {
		case '\0':
			eprintf ("Usage: fR [from] [to] ([mask])\n");
			eprintf ("Example to relocate PIE flags on debugger:\n"
				" > fR entry0 `dm~:1[1]`\n");
			break;
		case '?':
			r_cons_println ("Usage: fR [from] [to] ([mask])");
			r_cons_println ("Example to relocate PIE flags on debugger:\n"
				" > fR entry0 `dm~:1[1]`");
			break;
		default:
            {
				char *p = strchr (str+1, ' ');
				ut64 from, to, mask = 0xffff;
				int ret;
				if (p) {
					char *q = strchr (p + 1, ' ');
					*p = 0;
					if (q) {
						*q = 0;
						mask = r_num_math (core->num, q+1);
					}
					from = r_num_math (core->num, str+1);
					to = r_num_math (core->num, p+1);
					ret = r_flag_relocate (core->flags, from, mask, to);
					eprintf ("Relocated %d flags\n", ret);
				} else {
					eprintf ("Usage: fR [from] [to] ([mask])\n");
					eprintf ("Example to relocate PIE flags on debugger:\n"
						" > fR entry0 `dm~:1[1]`\n");
				}
			}
		}
		break;
	case 'b': // "fb"
		switch (input[1]) {
		case ' ':
			free (str);
			str = strdup (input + 2);
			ptr = strchr (str, ' ');
			if (ptr) {
				RFlag *f = core->flags;
				*ptr = 0;
				base = r_num_math (core->num, str);
				r_flag_foreach_glob (f, ptr + 1, adjust_offset, &base);
			} else {
				core->flags->base = r_num_math (core->num, input+1);
			}
			R_FREE (str);
			break;
		case '\0':
			r_cons_printf ("%"PFMT64d" 0x%"PFMT64x"\n",
				core->flags->base,
				core->flags->base);
			break;
		default:
			eprintf ("Usage: fb [addr] [[flags*]]\n");
			break;
		}
		break;
	case '+': // "f+'
	case ' ': {
		const char *cstr = r_str_trim_head_ro (str);
		char* eq = strchr (cstr, '=');
		char* b64 = strstr (cstr, "base64:");
		char* s = strchr (cstr, ' ');
		char* s2 = NULL, *s3 = NULL;
		char* comment = NULL;
		bool comment_needs_free = false;
		ut32 bsze = 1; //core->blocksize;
		int eqdir = 0;

		if (eq && eq > cstr) {
			char *prech = eq - 1;
			if (*prech == '+') {
				eqdir = 1;
				*prech = 0;
			} else if (*prech == '-') {
				eqdir = -1;
				*prech = 0;
			}
		}

		// Get outta here as fast as we can so we can make sure that the comment
		// buffer used on later code can be freed properly if necessary.
		if (*cstr == '.') {
			input++;
			goto rep;
		}
		// Check base64 padding
		if (eq && !(b64 && eq > b64 && (eq[1] == '\0' || (eq[1] == '=' && eq[2] == '\0')))) {
			*eq = 0;
			ut64 arg = r_num_math (core->num, eq + 1);
			RFlagItem *item = r_flag_get (core->flags, cstr);
			if (eqdir && item) {
				off = item->offset + (arg * eqdir);
			} else {
				off = arg;
			}
		}
		if (s) {
			*s = '\0';
			s2 = strchr (s + 1, ' ');
			if (s2) {
				*s2 = '\0';
				if (s2[1] && s2[2]) {
					off = r_num_math (core->num, s2 + 1);
				}
				s3 = strchr (s2 + 1, ' ');
				if (s3) {
					*s3 = '\0';
					if (!strncmp (s3 + 1, "base64:", 7)) {
						comment = (char *) r_base64_decode_dyn (s3 + 8, -1);
						comment_needs_free = true;
					} else if (s3[1]) {
						comment = s3 + 1;
					}
				}
			}
			bsze = (s[1] == '=') ? 1 : r_num_math (core->num, s + 1);
		}

		bool addFlag = true;
		if (input[0] == '+') {
			if ((item = r_flag_get_at (core->flags, off, false))) {
				addFlag = false;
			}
		}
		if (addFlag) {
			item = r_flag_set (core->flags, cstr, off, bsze);
		}
		if (item && comment) {
			r_flag_item_set_comment (item, comment);
			if (comment_needs_free) {
				free (comment);
			}
		}
		}
		break;
	case '-':
		if (input[1] == '-') {
			r_flag_unset_all (core->flags);
		} else if (input[1]) {
			const char *flagname = r_str_trim_head_ro (input + 1);
			while (*flagname==' ') {
				flagname++;
			}
			if (*flagname == '.') {
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
				if (fcn) {
					r_anal_function_delete_label_at (fcn, off);
				} else {
					eprintf ("Cannot find function at 0x%08"PFMT64x"\n", off);
				}
			} else {
				if (strchr (flagname, '*')) {
					r_flag_unset_glob (core->flags, flagname);
				} else {
					r_flag_unset_name (core->flags, flagname);
				}
			}
		} else {
			r_flag_unset_off (core->flags, off);
		}
		break;
	case '.': // "f."
		input = r_str_trim_head_ro (input + 1) - 1;
		if (input[1]) {
			if (input[1] == '*' || input[1] == 'j') {
				if (input[2] == '*') {
					print_function_labels (core->anal, NULL, input[1]);
				} else {
					RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
					if (fcn) {
						print_function_labels (core->anal, fcn, input[1]);
					} else {
						eprintf ("Cannot find function at 0x%08"PFMT64x"\n", off);
					}
				}
			} else {
				char *name = strdup (input + ((input[2] == ' ')? 2: 1));
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
				if (name) {
					char *eq = strchr (name, '=');
					if (eq) {
						*eq = 0;
						off = r_num_math (core->num, eq + 1);
					}
					r_str_trim (name);
					if (fcn) {
						if (*name=='-') {
							r_anal_function_delete_label (fcn, name + 1);
						} else {
							r_anal_function_set_label (fcn, name, off);
						}
					} else {
						eprintf ("Cannot find function at 0x%08"PFMT64x"\n", off);
					}
					free (name);
				}
			}
		} else {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
			if (fcn) {
				print_function_labels (core->anal, fcn, 0);
			} else {
				eprintf ("Local flags require a function to work.");
			}
		}
		break;
	case 'l': // "fl"
		if (input[1] == '?') { // "fl?"
			eprintf ("Usage: fl[a] [flagname] [flagsize]\n");
		} else if (input[1] == 'a') { // "fla"
			// TODO: we can optimize this if core->flags->flags is sorted by flagitem->offset
			char *glob = strchr (input, ' ');
			if (glob) {
				glob++;
			}
			r_flag_foreach_glob (core->flags, glob, find_flag_after_foreach, core->flags);
		} else if (input[1] == ' ') { // "fl ..."
			char *p, *arg = strdup (input + 2);
			r_str_trim (arg);
			p = strchr (arg, ' ');
			if (p) {
				*p++ = 0;
				item = r_flag_get_i (core->flags,
					r_num_math (core->num, arg));
				if (item)
					item->size = r_num_math (core->num, p);
			} else {
				if (*arg) {
					item = r_flag_get_i (core->flags, core->offset);
					if (item) {
						item->size = r_num_math (core->num, arg);
					}
				} else {
					item = r_flag_get_i (core->flags, r_num_math (core->num, arg));
					if (item) {
						r_cons_printf ("0x%08"PFMT64x"\n", item->size);
					}
				}
			}
			free (arg);
		} else { // "fl"
			item = r_flag_get_i (core->flags, core->offset);
			if (item)
				r_cons_printf ("0x%08"PFMT64x"\n", item->size);
		}
		break;
#if 0
	case 'd':
		if (input[1] == ' ') {
			char cmd[128];
			RFlagItem *item = r_flag_get_i (core->flags,
				r_num_math (core->num, input+2));
			if (item) {
				r_cons_printf ("0x%08"PFMT64x"\n", item->offset);
				snprintf (cmd, sizeof (cmd), "pD@%"PFMT64d":%"PFMT64d,
					 item->offset, item->size);
				r_core_cmd0 (core, cmd);
			}
		} else eprintf ("Missing arguments\n");
		break;
#endif
	case 'z': // "fz"
		cmd_fz (core, input + 1);
		break;
	case 'x':
		if (input[1] == ' ') {
			char cmd[128];
			RFlagItem *item = r_flag_get_i (core->flags,
				r_num_math (core->num, input+2));
			if (item) {
				r_cons_printf ("0x%08"PFMT64x"\n", item->offset);
				snprintf (cmd, sizeof (cmd), "px@%"PFMT64d":%"PFMT64d,
					 item->offset, item->size);
				r_core_cmd0 (core, cmd);
			}
		} else {
			eprintf ("Missing arguments\n");
		}
		break;
	case ',': // "f,"
		cmd_flag_table (core, input);
		break;
	case 't': // "ft"
		cmd_flag_tags (core, input);
		break;
	case 's': // "fs"
		switch (input[1]) {
		case '?':
			r_core_cmd_help (core, help_msg_fs);
			break;
		case '+':
			r_flag_space_push (core->flags, input+2);
			break;
		case 'r':
			if (input[2] ==' ') {
				char *newname = strdup (input + 3);
				r_str_trim (newname);
				r_flag_space_rename (core->flags, NULL, newname);
				free (newname);
			} else {
				eprintf ("Usage: fsr [newname]\n");
			}
			break;
		case 's':
			flag_space_stack_list (core->flags, input[2]);
			break;
		case '-':
			switch (input[2]) {
			case '*':
				r_flag_space_unset (core->flags, NULL);
				break;
			case '.': {
				const RSpace *sp = r_flag_space_cur (core->flags);
				if (sp) {
					r_flag_space_unset (core->flags, sp->name);
				}
				break;
			}
			case 0:
				r_flag_space_pop (core->flags);
				break;
			default:
				r_flag_space_unset (core->flags, input+2);
				break;
			}
			break;
		case ' ':
		{
			char *name = strdup (input + 2);
			r_str_trim (name);
			r_flag_space_set (core->flags, name);
			free (name);
			break;
		}
		case 'm':
			{ RFlagItem *f;
			ut64 off = core->offset;
			if (input[2] == ' ') {
				off = r_num_math (core->num, input+2);
			}
			f = r_flag_get_i (core->flags, off);
			if (f) {
				f->space = r_flag_space_cur (core->flags);
			} else {
				eprintf ("Cannot find any flag at 0x%"PFMT64x".\n", off);
			}
			}
			break;
		case 'j':
		case '\0':
		case '*':
		case 'q':
			spaces_list (&core->flags->spaces, input[1]);
			break;
		default:
			spaces_list (&core->flags->spaces, 0);
			break;
		}
		break;
	case 'g': // "fg"
		switch (input[1]) {
		case '*':
			__flag_graph (core, r_str_trim_head_ro (input + 2), '*');
			break;
		case ' ':
			__flag_graph (core, r_str_trim_head_ro (input + 2), ' ');
			break;
		case 0:
			__flag_graph (core, r_str_trim_head_ro (input + 1), 0);
			break;
		default:
			eprintf ("Usage: fg[*] ([prefix])\n");
			break;
		}
		break;
	case 'c': // "fc"
		if (input[1]=='?' || input[1] != ' ') {
			r_core_cmd_help (core, help_msg_fc);
		} else {
			RFlagItem *fi;
			const char *ret;
			char *arg = r_str_trim_dup (input + 2);
			char *color = strchr (arg, ' ');
			if (color && color[1]) {
				*color++ = 0;
			}
			fi = r_flag_get (core->flags, arg);
			if (fi) {
				ret = r_flag_item_set_color (fi, color);
				if (!color && ret)
					r_cons_println (ret);
			} else {
				eprintf ("Unknown flag '%s'\n", arg);
			}
			free (arg);
		}
		break;
	case 'C': // "fC"
		if (input[1] == ' ') {
			RFlagItem *item;
			char *q, *p = strdup (input + 2), *dec = NULL;
			q = strchr (p, ' ');
			if (q) {
				*q = 0;
				item = r_flag_get (core->flags, p);
				if (item) {
					if (!strncmp (q + 1, "base64:", 7)) {
						dec = (char *) r_base64_decode_dyn (q + 8, -1);
						if (dec) {
							r_flag_item_set_comment (item, dec);
							free (dec);
						} else {
							eprintf ("Failed to decode base64-encoded string\n");
						}
					} else {
						r_flag_item_set_comment (item, q + 1);
					}
				} else {
					eprintf ("Cannot find flag with name '%s'\n", p);
				}
			} else {
				item = r_flag_get_i (core->flags, r_num_math (core->num, p));
				if (item && item->comment) {
					r_cons_println (item->comment);
				} else {
					eprintf ("Cannot find item\n");
				}
			}
			free (p);
		} else eprintf ("Usage: fC [name] [comment]\n");
		break;
	case 'o': // "fo"
		r_core_fortune_print_random (core);
		break;
	case 'O': // "fO"
		flag_ordinals (core, input + 1);
		break;
	case 'r':
		if (input[1] == ' ' && input[2]) {
			RFlagItem *item;
			char *old = str + 1;
			char *new = strchr (old, ' ');
			if (new) {
				*new = 0;
				new++;
				item = r_flag_get (core->flags, old);
				if (!item && !strncmp (old, "fcn.", 4)) {
					item = r_flag_get (core->flags, old+4);
				}
			} else {
				new = old;
				item = r_flag_get_i (core->flags, core->offset);
			}
			if (item) {
				if (!r_flag_rename (core->flags, item, new)) {
					eprintf ("Invalid name\n");
				}
			} else {
				eprintf ("Usage: fr [[old]] [new]\n");
			}
		}
		break;
	case 'N':
		if (!input[1]) {
			RFlagItem *item = r_flag_get_i (core->flags, core->offset);
			if (item) {
				r_cons_printf ("%s\n", item->realname);
			}
			break;
		} else if (input[1] == ' ' && input[2]) {
			RFlagItem *item;
			char *name = str + 1;
			char *realname = strchr (name, ' ');
			if (realname) {
				*realname = 0;
				realname++;
				item = r_flag_get (core->flags, name);
				if (!item && !strncmp (name, "fcn.", 4)) {
					item = r_flag_get (core->flags, name+4);
				}
			} else {
				realname = name;
				item = r_flag_get_i (core->flags, core->offset);
			}
			if (item) {
				r_flag_item_set_realname (item, realname);
			}
			break;
		}
		eprintf ("Usage: fN [[name]] [[realname]]\n");
		break;
	case '\0':
	case 'n': // "fn" "fnj"
	case '*': // "f*"
	case 'j': // "fj"
	case 'q': // "fq"
		if (input[0]) {
			switch (input[1]) {
			case 'j':
			case 'q':
			case 'n':
			case '*':
				input++;
				break;
			}
		}
		if (input[0] && input[1] == '.') {
			const int mode = input[2];
			const RList *list = r_flag_get_list (core->flags, core->offset);
			PJ *pj = NULL;
			if (mode == 'j') {
				pj = pj_new ();
				pj_a (pj);
			}
			RListIter *iter;
			RFlagItem *item;
			r_list_foreach (list, iter, item) {
				switch (mode) {
				case '*':
					r_cons_printf ("f %s = 0x%08"PFMT64x"\n", item->name, item->offset);
					break;
				case 'j':
					{
						pj_o (pj);
						pj_ks (pj, "name", item->name);
						pj_ks (pj, "realname", item->realname);
						pj_kn (pj, "offset", item->offset);
						pj_kn (pj, "size", item->size);
						pj_end (pj);
					}
					break;
				default:
					r_cons_printf ("%s\n", item->name);
					break;
				}
			}
			if (mode == 'j') {
				pj_end (pj);
				char *s = pj_drain (pj);
				r_cons_printf ("%s\n", s);
				free (s);
			}
		} else {
			r_flag_list (core->flags, *input, input[0]? input + 1: "");
		}
		break;
	case 'i': // "fi"
		if (input[1] == ' ' || (input[1] && input[2] == ' ')) {
			char *arg = strdup (r_str_trim_head_ro (input + 2));
			if (*arg) {
				arg = strdup (r_str_trim_head_ro (input + 2));
				char *sp = strchr (arg, ' ');
				if (!sp) {
					char *newarg = r_str_newf ("%c0x%"PFMT64x" %s+0x%"PFMT64x,
						input[1], core->offset, arg, core->offset);
					free (arg);
					arg = newarg;
				} else {
					char *newarg = r_str_newf ("%c%s", input[1], arg);
					free (arg);
					arg = newarg;
				}
			} else {
				free (arg);
				arg = r_str_newf (" 0x%"PFMT64x" 0x%"PFMT64x,
					core->offset, core->offset + core->blocksize);
			}
			r_flag_list (core->flags, 'i', arg);
			free (arg);
		} else {
			// XXX dupe for prev case
			char *arg = r_str_newf (" 0x%"PFMT64x" 0x%"PFMT64x,
				core->offset, core->offset + core->blocksize);
			r_flag_list (core->flags, 'i', arg);
			free (arg);
		}
		break;
	case 'd': // "fd"
		{
			ut64 addr = core->offset;
			char *arg = NULL;
			RFlagItem *f = NULL;
			bool strict_offset = false;
			switch (input[1]) {
			case '?':
				r_core_cmd_help (core, help_msg_fd);
				if (str) {
					free (str);
				}
				return false;
			case '\0':
				addr = core->offset;
				break;
			case 'd':
				arg = strchr (input, ' ');
				if (arg) {
					addr = r_num_math (core->num, arg + 1);
				}
				break;
			case '.': // "fd." list all flags at given offset
				{
				RFlagItem *flag;
				RListIter *iter;
				bool isJson = false;
				const RList *flaglist;
				arg = strchr (input, ' ');
				if (arg) {
					addr = r_num_math (core->num, arg + 1);
				}
				flaglist = r_flag_get_list (core->flags, addr);
				isJson = strchr (input, 'j');
				PJ *pj = pj_new (); 
				if (isJson) {
					pj_a (pj);
				}

				// Sometime an address has multiple flags assigned to, show them all
				r_list_foreach (flaglist, iter, flag) {
					if (flag) {
						if (isJson) {
							pj_o (pj);
							pj_ks (pj, "name", flag->name);
							if (flag->realname) {
								pj_ks (pj, "realname", flag->realname);
							}
							pj_end (pj);
							
						} else {
							// Print realname if exists and asm.flags.real is enabled
							if (core->flags->realnames && flag->realname) {
								r_cons_println (flag->realname);
							} else {
								r_cons_println (flag->name);
							}	
						}
					}
				}

				if (isJson) {
					pj_end (pj);
					r_cons_println (pj_string (pj));
				}

				if (pj) {
					pj_free (pj);
				}

				return 0;
				}
			case 'w': {
				arg = strchr (input, ' ');
				if (!arg) {
					return 0;
				}
				arg++;
				if (!*arg) {
					return 0;
				}

				RFlag *f = core->flags;
				RList *temp = r_flag_all_list (f, true);
				ut64 loff = 0;
				ut64 uoff = 0;
				ut64 curseek = core->offset;
				char *lmatch = NULL , *umatch = NULL;
				RFlagItem *flag;
				RListIter *iter;
				r_list_sort (temp, &cmpflag);
				r_list_foreach (temp, iter, flag) {
					if (strstr (flag->name , arg) != NULL) {
						if (flag->offset < core->offset) {
							loff = flag->offset;
							lmatch = flag->name;
							continue;
						}
						uoff = flag->offset;
						umatch = flag->name;
						break;
					}
				}
				char *match = (curseek - loff) < (uoff - curseek) ? lmatch : umatch ;
				if (match) {
					if (*match) {
						r_cons_println (match);
					}
				}
				r_list_free (temp);
				return 0;
			}
			default:
				arg = strchr (input, ' ');
				if (arg) {
					addr = r_num_math (core->num, arg + 1);
				}
				break;
			}
			f = r_flag_get_at (core->flags, addr, !strict_offset);
			if (f) {
				if (f->offset != addr) {
					// if input contains 'j' print json
					if (strchr (input, 'j')) {
						PJ *pj = pj_new (); 
						pj_o (pj);
						pj_kn (pj, "offset", f->offset);
						pj_ks (pj, "name", f->name);
						// Print flag's real name if defined
						if (f->realname) {
							pj_ks (pj, "realname", f->realname);
						}
						pj_end (pj);
						r_cons_println (pj_string (pj));
						if (pj) {
							pj_free (pj);
						}
					} else {
						// Print realname if exists and asm.flags.real is enabled
						if (core->flags->realnames && f->realname) {
							r_cons_printf ("%s + %d\n", f->realname,
									   (int)(addr - f->offset));
						} else {
							r_cons_printf ("%s + %d\n", f->name,
									   (int)(addr - f->offset));
						}
					}
				} else {
					if (strchr (input, 'j')) {
						PJ *pj = pj_new ();
						pj_o (pj);
						pj_ks (pj, "name", f->name);
						// Print flag's real name if defined
						if (f->realname) {
							pj_ks (pj, "realname", f->realname);
						}
						pj_end (pj);
						r_cons_println (pj_string (pj));
						pj_free (pj);
					} else {
						// Print realname if exists and asm.flags.real is enabled
						if (core->flags->realnames && f->realname) {
							r_cons_println (f->realname);
						} else {
							r_cons_println (f->name);
						}
					}
				}
			}
		}
		break;
	case '?':
	default:
		if (input[1]) {
			core->num->value = r_flag_get (core->flags, input + 1)? 1: 0;
		} else {
			r_core_cmd_help (core, help_msg_f);
			break;
		}
	}
	free (str);
	return 0;
}
