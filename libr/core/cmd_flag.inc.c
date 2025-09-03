/* radare - LGPL - Copyright 2009-2025 - pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_fR = {
	"Usage: fR", " [from] [to] ([mask])", " # Relocate flags matching a mask asuming old and new base addresses",
	"fR", " entry0 `dm~:1[1]`", "rebase entrypoint",
	NULL
};

static RCoreHelpMessage help_msg_fV = {
	"Usage: fV", "[*-] [nkey] [offset]", " # dump/restore visual marks (mK/'K)",
	"fV", " a 33", "set visual mark 'a' to the offset 33",
	"fV", "-", "delete all visual marks",
	"fV", "*", "dump visual marks as r2 commands",
	"fV", "", "list visual marks",
	NULL
};

static RCoreHelpMessage help_msg_f = {
	"Usage: f", "[?] [flagname]", " # Manage offset-name flags",
	"f", "", "list flags (will only list flags from selected flagspaces)",
	"f", " name 12 @ 33", "set flag 'name' with length 12 at offset 33",
	"f", " name = 33", "alias for 'f name @ 33' or 'f name 1 33'",
	"f", " name 12 33 [cmt]", "same as above + optional comment",
	"f?", "flagname", "check if flag exists or not, See ?? and ?!",
	"f.", " [*[*]]", "list local per-function flags (*) as r2 commands",
	"f.", "blah=$$+12", "set local function label named 'blah' (f.blah@$$+12)",
	"f.", "-blah", "delete local function label named 'blah'",
	"f.", " fname", "list all local labels for the given function",
	"f,", "", "table output for flags",
	"f*", "", "list flags in r commands",
	"f-", ".blah@fcn.foo", "delete local label from function at current seek (also f.-)",
	"f-", "name", "remove flag 'name'",
	"f-", "@addr", "remove flag at address expression (same as f-$$ or f-0x..)",
	"f--", "", "delete all flags and flagspaces (deinit)",
	"f+", "name 12 @ 33", "like above but creates new one if doesnt exist",
	"f=", " [glob]", "list range bars graphics with flag offsets and sizes",
	"fa", "[- ][name] [alias]", "set or unset(-) an alias expression for a flag",
	"fb", " [addr]", "set base address for new flags",
	"fb", " [addr] [flag*]", "move flags matching 'flag' to relative addr",
	"fc", "[?][name] [color]", "set color for given flag",
	"fC", " [name] [cmt]", "set comment for given flag",
	"fd", "[?] addr", "return flag+delta",
	"fD", "[?] rawname", "(de)mangle flag or set a new flag",
	"fe", " [name]", "create flag name.#num# enumerated flag. (f.ex: fe foo @@= 1 2 3 4)",
	"fe-", "", "resets the enumerator counter",
	"ff", " ([glob])", "distance in bytes to reach the next flag (see sn/sp)",
	"fi", " [size] | [from] [to]", "show flags in current block or range",
	"fg", "", "bring coretasks jobs to the foreground (see '&' command)",
	"fh", "[*] ([prefix])", "construct a graph hirearchy with the flag names",
	"fj", "", "list flags in JSON format",
	"fq", "", "list flags in quiet mode",
	"fl", " (@[flag]) [size]", "show or set flag length (size)",
	"fla", " [glob]", "automatically compute the size of all flags matching glob",
	"fm", " addr", "move flag at current offset to new address",
	"fn", "", "list flags displaying the real name (demangled)",
	"fnj", "", "list flags displaying the real name (demangled) in JSON format",
	"fN", "", "show real name of flag at current address",
	"fN", " [[name]] [realname]", "set flag real name (if no flag name current seek one is used)",
	"fo", "", "show fortunes",
	"fO", " [glob]", "flag as ordinals (sym.* func.* method.*)",
	//" fc [name] [cmt]  ; set execution command for a specific flag"
	"fr", " [[old]] [new]", "rename flag (if no new flag current seek one is used)",
	"fR", "[?] [from] [to] [mask]", "relocate all flags matching from&~m",
	"fs", "[?]+-*", "manage flagspaces",
	"ft", "[?]*", "flag tags, useful to find all flags matching some words",
	"fV", "[*-] [nkey] [offset]", "dump/restore visual marks (mK/'K)",
	"fx", "[d]", "show hexdump (or disasm) of flag:flagsize",
	"fz", "[?][name]", "add named flag zone -name to delete. see fz?[name]",
	NULL
};

static RCoreHelpMessage help_msg_fc = {
	"Usage: fc", "<flagname> [color]", " # List colors with 'ecs'",
	"fc", "", "same as fc.",
	"fc", " color", "set color to all flags in current offset",
	"fc", " flag=color", "set color to given flag. Same as 'fc color@flag'",
	"fc.", "", "get color of all flags in current offset",
	"fc-", "", "remove color from current offset",
	"fc-", "flagname", "remove color from given flag",
	"fc-*", "", "reset all color flags",
	"fc*", "", "list all flags colors in r2 commands",
	"fc.*", "", "set color to all flags in current offset",
	NULL
};

static RCoreHelpMessage help_msg_feq = {
	"Usage: f=", " [glob]", " # Grep flag names using glob expression",
	"f=", " str*", "filter all flags starting with str",
	NULL
};

static RCoreHelpMessage help_msg_ft = {
	"Usage: ft", "[?ln] ([k] [v ...])", "# Grep flag names using glob expression",
	"ft", " tag strcpy strlen ...", "set words for the 'string' tag",
	"ft", " tag", "get offsets of all matching flags",
	"ft", "", "list all tags",
	"ftn", " tag", "get matching flagnames fot given tag",
	"ftw", "", "flag tags within this file",
	"ftj", "", "list all flagtags in JSON format",
	"ft*", "", "list all flagtags in r2 commands",
	NULL
};

static RCoreHelpMessage help_msg_fD = {
	"Usage: fD[*.j]", " [rawname]", " # filter/mangle raw symbol name to be valid flag name",
	"fD", " rawname" , "print the mangled flag name using the raw name, see the ' command prefix",
 	"fD.", " rawname", "set a flag using the orig raw name in the current offset",
	"fDj", " rawname", "same as fD but output is in json",
	"fD*", " rawname", "filter raw name to be a valid flag and output in r2 commands",
	NULL
};

static RCoreHelpMessage help_msg_fd = {
	"Usage: fd[d]", " [offset|flag|expression]", " # Describe flags",
	"fd", " $$" , "describe flag + delta for given offset",
 	"fd.", " $$", "check flags in current address (no delta)",
	"fdj", " $$", "describe current flag in json",
	"fdd", " $$", "describe flag without space restrictions",
	"fdw", " [string]", "filter closest flag by string for current offset",
	NULL
};

static RCoreHelpMessage help_msg_fs = {
	"Usage: fs", "[*] [+-][flagspace|addr]", " # Manage flagspaces",
	"fs", "", "display flagspaces",
	"fs*", "", "display flagspaces as r2 commands",
	"fsj", "", "display flagspaces in JSON",
	"fs", " *", "select all flagspaces",
	"fs", " flagspace", "select flagspace or create if it doesn't exist",
	"fs", "-flagspace", "remove flagspace",
	"fs", "-*", "remove all flagspaces",
	"fs", "+foo", "push previous flagspace and set",
	"fs", "-", "pop to the previous flagspace",
	"fs", "-.", "remove the current flagspace",
	"fsq", "", "list flagspaces in quiet mode",
	"fsm", " [addr]", "move flags at given address to the current flagspace",
	"fss", "", "display flagspaces stack",
	"fss*", "", "display flagspaces stack in r2 commands",
	"fssj", "", "display flagspaces stack in JSON",
	"fsr", " newname", "rename selected flagspace",
	NULL
};

static RCoreHelpMessage help_msg_fz = {
	"Usage: f", "[?|-name| name] [@addr]", " # Manage flagzones",
	"fz", " math", "add new flagzone named 'math'",
	"fz-", "math", "remove the math flagzone",
	"fz-", "*", "remove all flagzones",
	"fz.", "", "show around flagzone context",
	"fz:", "", "show what's in scr.flagzone for visual",
	"fz*", "", "dump into r2 commands, for projects",
	NULL
};

static bool listFlag(RFlagItem *flag, void *user) {
	r_list_append (user, flag);
	return true;
}

static int strcmp_cb(const void *a, const void *b) {
	const RFlagItem *fa = *(const RFlagItem **)a;
	const RFlagItem *fb = *(const RFlagItem **)b;
	return strcmp (fa->name, fb->name);
}

static size_t common_prefix_len(const char *a, const char *b, size_t start) {
	size_t k = start;
	while (a[k] && b[k] && a[k] == b[k]) {
		k++;
	}
	return k;
}

static void __printRecursive(RCore *core, RList *flags, const char *prefix, int mode) {
	/* Context structure for iterative traversal */
	typedef struct {
		char *prefix;
		size_t prefix_len;
		size_t start;
		size_t end;
		size_t index;
		HtPP *processed;
	} FlagContext;

	size_t prefix_len = strlen (prefix);
	if (mode == '*' && !*prefix) {
		r_cons_printf (core->cons, "agn root\n");
	}
	/* If prefix is an actual flag name, do nothing (leaf) */
	if (r_flag_get (core->flags, prefix)) {
		return;
	}

	/* Build and sort array of flag items (cache all flags under the given prefix) */
	size_t total = r_list_length (flags);
	if (total == 0) {
		return;
	}
	RFlagItem **flag_array = malloc (total * sizeof (RFlagItem *));
	if (!flag_array) {
		return;
	}
	size_t count = 0;
	RListIter *it;
	RFlagItem *f;
	r_list_foreach (flags, it, f) {
		if (r_cons_is_breaked (core->cons)) {
			free (flag_array);
			return;
		}
		const char *name = f->name;
		size_t len = strlen (name);
		if (prefix_len > 0) {
			if (len <= prefix_len || strncmp (name, prefix, prefix_len) != 0) {
				continue;
			}
		}
		/* Exclude the prefix itself if present (already handled above by r_flag_get) */
		flag_array[count++] = f;
	}
	if (count == 0) {
		free (flag_array);
		return;
	}
	qsort (flag_array, count, sizeof (RFlagItem *), strcmp_cb);

	/* Stack for DFS traversal of flag hierarchy */
	RList *stack = r_list_newf (NULL);
	if (!stack) {
		free (flag_array);
		return;
	}
	/* Initialize root context */
	FlagContext *root_ctx = R_NEW0 (FlagContext);
	if (!root_ctx) {
		r_list_free (stack);
		free (flag_array);
		return;
	}
	root_ctx->prefix = strdup (prefix);
	root_ctx->prefix_len = prefix_len;
	root_ctx->start = 0;
	root_ctx->end = count;
	root_ctx->index = 0;
	root_ctx->processed = ht_pp_new0 ();
	if (!root_ctx->processed) {
		free (root_ctx->prefix);
		free (root_ctx);
		r_list_free (stack);
		free (flag_array);
		return;
	}
	r_list_append (stack, root_ctx);

	bool aborted = false;
	/* Depth-first traversal using stack */
	while (!r_list_empty (stack) && !aborted) {
		FlagContext *ctx = r_list_pop (stack);  /* get current context (LIFO) */
		if (!ctx) {
			continue;
		}
		size_t i = ctx->index;
		const char *parent_prefix = ctx->prefix;
		size_t parent_len = ctx->prefix_len;
		bool resume = false;
		/* Iterate over children in this context */
		while (i < ctx->end && !r_cons_is_breaked (core->cons)) {
			const char *name = flag_array[i]->name;
			/* Skip printing if the child name equals the parent prefix */
			if (!strcmp (name, parent_prefix)) {
				i++;
				continue;
			}
			/* Case 1: current name is prefix of next name -> output current and skip grouping */
			if (i + 1 < ctx->end && strncmp (flag_array[i+1]->name, name, strlen (name)) == 0) {
				if (!ht_pp_find (ctx->processed, name, NULL) && strcmp (name, parent_prefix) != 0) {
					ht_pp_insert (ctx->processed, name, (void *)1);
					if (mode == '*') {
						r_cons_printf (core->cons, "agn %s %s\n", name, name + parent_len);
						r_cons_printf (core->cons, "age %s %s\n", *parent_prefix ? parent_prefix : "root", name);
					} else {
						r_cons_printf (core->cons, "%s %s\n", r_str_pad(' ', parent_len), name + parent_len);
					}
				}
				/* No recursive push for actual flag (leaf) */
				i++;
				continue;
			}
			/* Case 2: last element or no shared prefix beyond parent -> output current as leaf */
			if (i + 1 >= ctx->end) {
				if (!ht_pp_find (ctx->processed, name, NULL) && strcmp (name, parent_prefix) != 0) {
					ht_pp_insert (ctx->processed, name, (void *)1);
					if (mode == '*') {
						r_cons_printf (core->cons, "agn %s %s\n", name, name + parent_len);
						r_cons_printf (core->cons, "age %s %s\n", *parent_prefix ? parent_prefix : "root", name);
					} else {
						r_cons_printf (core->cons, "%s %s\n", r_str_pad(' ', parent_len), name + parent_len);
					}
				}
				i++;
				continue;
			}
			/* Case 3: there is a common prefix with the next name beyond parent_prefix */
			const char *next_name = flag_array[i + 1]->name;
			size_t common_len = common_prefix_len (name, next_name, parent_len);
			if (common_len <= parent_len) {
				/* No additional common prefix beyond parent -> current is a standalone leaf */
				if (!ht_pp_find (ctx->processed, name, NULL) && strcmp (name, parent_prefix) != 0) {
					ht_pp_insert (ctx->processed, name, (void *)1);
					if (mode == '*') {
						r_cons_printf (core->cons, "agn %s %s\n", name, name + parent_len);
						r_cons_printf (core->cons, "age %s %s\n", *parent_prefix ? parent_prefix : "root", name);
					} else {
						r_cons_printf (core->cons, "%s %s\n", r_str_pad (' ', parent_len), name + parent_len);
					}
				}
				i++;
				continue;
			}
			/* Determine the cluster of names sharing the common prefix */
			size_t j = i + 2;
			size_t cluster_prefix_len = common_len;
			while (j < ctx->end && strncmp (flag_array[j]->name, name, cluster_prefix_len) == 0) {
				size_t new_common = common_prefix_len(name, flag_array[j]->name, parent_len);
				if (new_common < cluster_prefix_len) {
					cluster_prefix_len = new_common;
				}
				j++;
			}
			bool skip_group = (cluster_prefix_len == strlen(name));
			if (j - i < 2) {
				skip_group = true;  /* only one element in cluster */
			}
			if (!skip_group) {
				/* Create a group prefix for this cluster */
				char *group = r_str_ndup(name, cluster_prefix_len);
				if (!group) {
					aborted = true;
					break;
				}
				if (!ht_pp_find (ctx->processed, group, NULL) && strcmp (group, parent_prefix) != 0) {
					ht_pp_insert (ctx->processed, group, (void *)1);
					/* Print the group prefix */
					if (mode == '*') {
						r_cons_printf (core->cons, "agn %s %s\n", group, group + parent_len);
						r_cons_printf (core->cons, "age %s %s\n", *parent_prefix ? parent_prefix : "root", group);
					} else {
						r_cons_printf (core->cons, "%s %s\n", r_str_pad (' ', parent_len), group + parent_len);
					}
					/* Prepare new context for this group */
					FlagContext *child_ctx = R_NEW0 (FlagContext);
					if (!child_ctx) {
						free (group);
						aborted = true;
						break;
					}
					child_ctx->prefix = group;
					child_ctx->prefix_len = cluster_prefix_len;
					child_ctx->start = i;
					child_ctx->end = j;
					child_ctx->index = i;
					child_ctx->processed = ht_pp_new0();
					if (!child_ctx->processed) {
						free (child_ctx->prefix);
						free (child_ctx);
						aborted = true;
						break;
					}
					/* Update current context to resume after this cluster */
					ctx->index = j;
					/* Push current context back and push the new child context */
					r_list_append (stack, ctx);
					r_list_append (stack, child_ctx);
					resume = true;
					break;  /* dive into child context next */
				} else {
					/* Group prefix already processed or equals parent prefix, skip grouping */
					free (group);
					/* Just skip this cluster since it's already handled */
					i = j;
					continue;
				}
			} else {
				/* No grouping: output each element in the cluster individually */
				size_t k;
				for (k = i; k < j && !r_cons_is_breaked (core->cons); k++) {
					const char *fname = flag_array[k]->name;
					if (!ht_pp_find (ctx->processed, fname, NULL) && strcmp (fname, parent_prefix) != 0) {
						ht_pp_insert (ctx->processed, fname, (void *)1);
						if (mode == '*') {
							r_cons_printf (core->cons, "agn %s %s\n", fname, fname + parent_len);
							r_cons_printf (core->cons, "age %s %s\n", *parent_prefix ? parent_prefix : "root", fname);
						} else {
							r_cons_printf (core->cons, "%s %s\n", r_str_pad(' ', parent_len), fname + parent_len);
						}
					}
				}
				if (r_cons_is_breaked (core->cons)) {
					break;
				}
				/* Advance index past this cluster */
				i = j;
				continue;
			}
		} /* end while over children */

		if (r_cons_is_breaked (core->cons)) {
			aborted = true;
		}
		if (!resume) {
			/* Context finished processing all children (or aborted), free it */
			ht_pp_free (ctx->processed);
			free (ctx->prefix);
			free (ctx);
		} else {
			/* If we broke out early to dive, the context was pushed back on stack */
			/* Do NOT free ctx here, it remains on stack for later processing */
		}
	}

	/* If aborted, clear any remaining stack entries without processing */
	if (aborted) {
		RListIter *iter;
		FlagContext *ctx;
		r_list_foreach (stack, iter, ctx) {
			if (!ctx) continue;
			if (ctx->processed) {
				ht_pp_free (ctx->processed);
			}
			free (ctx->prefix);
			free (ctx);
		}
	}
	r_list_free (stack);
	free (flag_array);
}

static void __flag_graph(RCore *core, const char *input, int mode) {
	RList *flags = r_list_newf (NULL);
	r_flag_foreach_space (core->flags, r_flag_space_cur (core->flags), listFlag, flags);
	r_cons_break_push (core->cons, NULL, NULL);
	__printRecursive (core, flags, input, mode);
	r_cons_break_pop (core->cons);
	r_list_free (flags);
}

static void spaces_list(RCore *core, RSpaces *sp, int mode) {
	RSpaceIter *it;
	RSpace *s;
	const RSpace *cur = r_spaces_current (sp);
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
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
			r_cons_printf (core->cons, "%s\n", s->name);
		} else if (mode == '*') {
			r_cons_printf (core->cons, "%s %s\n", sp->name, s->name);
		} else {
			r_cons_printf (core->cons, "%5d %c %s\n", count, (!cur || cur == s)? '*': '.',
				s->name);
		}
	}
	if (mode == '*' && r_spaces_current (sp)) {
		r_cons_printf (core->cons, "%s %s # current\n", sp->name, r_spaces_current_name (sp));
	}
	if (mode == 'j') {
		pj_end (pj);
		r_cons_printf (core->cons, "%s\n", pj_string (pj));
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
			r_flag_zone_around (core->flags, core->addr, &a, &b);
			r_cons_printf (core->cons, "%s %s\n", r_str_get_fail (a, "~"), r_str_get_fail (b, "~"));
		}
		break;
	case ':': // "fz:"
		{
			const char *a, *b;
			int a_len = 0;
			int w = r_cons_get_size (core->cons, NULL);
			r_flag_zone_around (core->flags, core->addr, &a, &b);
			if (a) {
				r_cons_printf (core->cons, "[<< %s]", a);
				a_len = strlen (a) + 4;
			}
			int padsize = (w / 2)  - a_len;
			int title_size = 12;
			if (a || b) {
				char *title = r_str_newf ("[ 0x%08"PFMT64x" ]", core->addr);
				title_size = strlen (title);
				padsize -= strlen (title) / 2;
				const char *halfpad = r_str_pad (' ', padsize);
				r_cons_printf (core->cons, "%s%s", halfpad, title);
				free (title);
			}
			if (b) {
				padsize = (w / 2) - title_size - strlen (b) - 4;
				const char *halfpad = padsize > 1? r_str_pad (' ', padsize): "";
				r_cons_printf (core->cons, "%s[%s >>]", halfpad, b);
			}
			if (a || b) {
				r_cons_newline (core->cons);
			}
		}
		break;
	case ' ':
		r_flag_zone_add (core->flags, r_str_trim_head_ro (input + 1), core->addr);
		break;
	case '-':
		if (input[1] == '*') {
			r_flag_zone_reset (core->flags);
		} else {
			r_flag_zone_del (core->flags, input + 1);
		}
		break;
	case '*':
	case 0:
		{
			char *s = r_flag_zone_list (core->flags, *input);
			r_cons_print (core->cons, s);
			free (s);
		}
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
	RIOMap *m = r_io_map_get_at (u->core->io, fi->addr);
	if (m) {
		min = m->itv.addr;
		max = m->itv.addr + m->itv.size;
	}
	r_cons_printf (u->core->cons, "0x%08"PFMT64x" ", fi->addr);
	r_print_rangebar (u->core->print, fi->addr, fi->addr + fi->size, min, max, u->cols);
	r_cons_printf (u->core->cons, "  %s\n", fi->name);
	return true;
}

static void flagbars(RCore *core, const char *glob) {
	int cols = r_cons_get_size (core->cons, NULL);
	cols -= 80;
	if (cols < 0) {
		cols += 80;
	}

	struct flagbar_t u = { .core = core, .cols = cols };
	r_flag_foreach_space_glob (core->flags, glob, r_flag_space_cur (core->flags), flagbar_foreach, &u);
}

struct flag_to_flag_t {
	ut64 next;
	ut64 addr;
};

static bool flag_to_flag_foreach(RFlagItem *fi, void *user) {
	struct flag_to_flag_t *u = (struct flag_to_flag_t *)user;
	if (fi->addr < u->next && fi->addr > u->addr) {
		u->next = fi->addr;
	}
	return true;
}

static int flag_to_flag(RCore *core, const char *glob) {
	R_RETURN_VAL_IF_FAIL (glob, 0);
	glob = r_str_trim_head_ro (glob);
	struct flag_to_flag_t u = { .next = UT64_MAX, .addr = core->addr };
	r_flag_foreach_glob (core->flags, glob, flag_to_flag_foreach, &u);
	if (u.next != UT64_MAX && u.next > core->addr) {
		return u.next - core->addr;
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
		r_strf_var (addr, 32, "0x%08"PFMT64x, flag->addr);
		r_strf_var (size, 32, "%"PFMT64d, flag->size);
		r_table_add_row (t, addr, size, spaceName, flag->name, NULL);
	}
	return true;
}

static void cmd_flag_table(RCore *core, const char *input) {
	const char fmt = *input++;
	const char *q = input;
	FlagTableData ftd = {0};
	RTable *t = r_core_table_new (core, "flags");
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
		r_cons_printf (core->cons, "%s\n", s);
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
			r_cons_printf (core->cons, "%s\n", tag);
		}
		r_list_free (list);
		free (inp);
		return;
	}
	if (mode == '?') {
		r_core_cmd_help (core, help_msg_ft);
		free (inp);
		return;
	}
	if (mode == 'w') { // "ftw"
		const char *tag;
		RListIter *iter;
		RList *list = r_flag_tags_list (core->flags, NULL);
		r_list_foreach (list, iter, tag) {
		//	r_cons_printf (core->cons, "%s:\n", tag);
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
			r_strf_var (key, 128, "tag.%s", tag);
			const char *flags = sdb_get (core->flags->tags, key, NULL);
			r_cons_printf (core->cons, "ft %s %s\n", tag, flags);
		}
		r_list_free (list);
		free (inp);
		return;
	}
	if (mode == 'j') { // "ftj"
		RListIter *iter, *iter2;
		const char *tag, *flg;
		PJ *pj = r_core_pj_new (core);
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
		r_cons_printf (core->cons, "%s\n", pj_string (pj));
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
		case 'n': // "ftn"
			  // TODO : implement ftnj
			  // TODO : implement ftn, -> using table api
			r_list_foreach (flags, iter, flag) {
				// r_cons_printf (core->cons, "0x%08"PFMT64x"\n", flag->addr);
				r_cons_printf (core->cons, "0x%08"PFMT64x"  %s  %s\n",
						flag->addr, arg, flag->name);
			}
			break;
		default:
			r_list_foreach (flags, iter, flag) {
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", flag->addr);
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
	return (flag1->addr - flag2->addr);
}

struct find_flag_t {
	RFlagItem *win;
	ut64 at;
};

static bool find_flag_after(RFlagItem *flag, void *user) {
	struct find_flag_t *u = (struct find_flag_t *)user;
	if (flag->addr > u->at && (!u->win || flag->addr < u->win->addr)) {
		u->win = flag;
	}
	return true;
}

static bool find_flag_after_foreach(RFlagItem *flag, void *user) {
	if (flag->size != 0) {
		return true;
	}

	RFlag *flags = (RFlag *)user;
	struct find_flag_t u = { .win = NULL, .at = flag->addr };
	r_flag_foreach (flags, find_flag_after, &u);
	if (u.win) {
		flag->size = u.win->addr - flag->addr;
	}
	return true;
}

static bool adjust_offset(RFlagItem *flag, void *user) {
	st64 base = *(st64 *)user;
	flag->addr += base;
	return true;
}

static void print_space_stack(RCore *core, int ordinal, const char *name, bool selected, PJ *pj, int mode) {
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
		r_cons_printf (core->cons, fmt, name);
		break;
	}
	default:
		r_cons_printf (core->cons, "%-2d %s%s\n", ordinal, name, selected? " (selected)": "");
		break;
	}
}

static int flag_space_stack_list(RCore *core, int mode) {
	RListIter *iter;
	char *space;
	int i = 0;
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	r_list_foreach (core->flags->spaces.spacestack, iter, space) {
		print_space_stack (core, i++, space, false, pj, mode);
	}
	const char *cur_name = r_flag_space_cur_name (core->flags);
	print_space_stack (core, i++, cur_name, true, pj, mode);
	if (mode == 'j') {
		pj_end (pj);
		r_cons_printf (core->cons, "%s\n", pj_string (pj));
		pj_free (pj);
	}
	return i;
}

typedef struct {
	RCore *core;
	int rad;
	PJ *pj;
	RAnalFunction *fcn;
} PrintFcnLabelsCtx;

static bool print_function_labels_cb(void *user, const ut64 addr, const void *v) {
	const PrintFcnLabelsCtx *ctx = user;
	RCons *cons = ctx->core->cons;
	const char *name = v;
	switch (ctx->rad) {
	case '*':
	case 1:
		r_cons_printf (cons, "f.%s@0x%08"PFMT64x"\n", name, addr);
		break;
	case 'j':
		pj_kn (ctx->pj, name, addr);
		break;
	default:
		r_cons_printf (cons, "0x%08"PFMT64x" %s   [%s + %"PFMT64d"]\n",
			addr,
			name, ctx->fcn->name,
			addr - ctx->fcn->addr);
	}
	return true;
}

static void cmd_fd_dot(RCore *core, const char *input) {
	RFlagItem *flag;
	RListIter *iter;
	bool isJson = false;
	const RList *flaglist;
	const char *arg = strchr (input, ' ');
	ut64 addr = core->addr;
	if (arg) {
		addr = r_num_math (core->num, arg + 1);
	}
	flaglist = r_flag_get_list (core->flags, addr);
	isJson = strchr (input, 'j');
	PJ *pj = r_core_pj_new (core);
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
					r_cons_println (core->cons, flag->realname);
				} else {
					r_cons_println (core->cons, flag->name);
				}
			}
		}
	}

	if (isJson) {
		pj_end (pj);
		r_cons_println (core->cons, pj_string (pj));
	}

	if (pj) {
		pj_free (pj);
	}
}

static void print_function_labels_for(RCore *core, RAnalFunction *fcn, int rad, PJ *pj) {
	R_RETURN_IF_FAIL (fcn && (rad != 'j' || pj));
	bool json = rad == 'j';
	if (json) {
		pj_o (pj);
	}
	PrintFcnLabelsCtx ctx = { core, rad, pj, fcn };
	ht_up_foreach (fcn->labels, print_function_labels_cb, &ctx);
	if (json) {
		pj_end (pj);
	}
}

static void print_function_labels(RCore *core, RAnalFunction *fcn, int rad) {
	R_RETURN_IF_FAIL (core || fcn);
	RAnal *anal = core->anal;
	PJ *pj = NULL;
	bool json = rad == 'j';
	if (json) {
		pj = r_core_pj_new (core);
	}
	if (fcn) {
		print_function_labels_for (core, fcn, rad, pj);
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
			print_function_labels_for (core, f, rad, pj);
		}
		if (json) {
			pj_end (pj);
		}
	}
	if (json) {
		r_cons_println (core->cons, pj_string (pj));
		pj_free (pj);
	}
}

static void cmd_fd(RCore *core, const char *input) {
	ut64 addr = core->addr;
	char *arg = NULL;
	RFlagItem *f = NULL;
	bool strict_offset = false;
	switch (input[1]) {
	case '?':
		r_core_cmd_help (core, help_msg_fd);
		return;
	case '\0':
		addr = core->addr;
		break;
	case 'd':
		arg = strchr (input, ' ');
		if (arg) {
			addr = r_num_math (core->num, arg + 1);
		}
		break;
	case '.': // "fd." list all flags at given offset
		cmd_fd_dot (core, input);
		return;
	case 'w': {
			  arg = strchr (input, ' ');
			  if (!arg) {
				  return;
			  }
			  arg++;
			  if (!*arg) {
				  return;
			  }

			  RList *temp = r_flag_all_list (core->flags, true);
			  ut64 loff = 0;
			  ut64 uoff = 0;
			  ut64 curseek = core->addr;
			  char *lmatch = NULL , *umatch = NULL;
			  RFlagItem *flag;
			  RListIter *iter;
			  r_list_sort (temp, &cmpflag);
			  r_list_foreach (temp, iter, flag) {
				  if (strstr (flag->name , arg)) {
					  if (flag->addr < core->addr) {
						  loff = flag->addr;
						  lmatch = flag->name;
						  continue;
					  }
					  uoff = flag->addr;
					  umatch = flag->name;
					  break;
				  }
			  }
			  char *match = (curseek - loff) < (uoff - curseek) ? lmatch : umatch ;
			  if (match) {
				  if (*match) {
					  r_cons_println (core->cons, match);
				  }
			  }
			  r_list_free (temp);
			  return;
		  }
		  break;
	default:
		  arg = strchr (input, ' ');
		  if (arg) {
			  addr = r_num_math (core->num, arg + 1);
		  }
		  break;
	}
	f = r_flag_get_at (core->flags, addr, !strict_offset);
	if (f) {
		if (f->addr != addr) {
			// if input contains 'j' print json
			if (strchr (input, 'j')) {
				PJ *pj = r_core_pj_new (core);
				pj_o (pj);
				pj_kn (pj, "addr", f->addr);
				pj_ks (pj, "name", f->name);
				// Print flag's real name if defined
				if (f->realname) {
					pj_ks (pj, "realname", f->realname);
				}
				pj_end (pj);
				r_cons_println (core->cons, pj_string (pj));
				pj_free (pj);
			} else {
				// Print realname if exists and asm.flags.real is enabled
				const char *name = (core->flags->realnames && f->realname)
					? f->realname: f->name;
				r_cons_printf (core->cons, "%s + %d\n", name, (int)(addr - f->addr));
			}
		} else {
			if (strchr (input, 'j')) {
				PJ *pj = r_core_pj_new (core);
				pj_o (pj);
				pj_ks (pj, "name", f->name);
				// Print flag's real name if defined
				if (f->realname) {
					pj_ks (pj, "realname", f->realname);
				}
				pj_end (pj);
				r_cons_println (core->cons, pj_string (pj));
				pj_free (pj);
			} else {
				// Print realname if exists and asm.flags.real is enabled
				if (core->flags->realnames && f->realname) {
					r_cons_println (core->cons, f->realname);
				} else {
					r_cons_println (core->cons, f->name);
				}
			}
		}
	} else if (input[1] == 'j') {
		r_cons_println (core->cons, "{}");
	}
}

static int cmd_flag(void *data, const char *input);

static bool cmd_flag_add(RCore * R_NONNULL core, const char *str, bool addsign) {
	const char *cstr = r_str_trim_head_ro (str);
	char* eq = strchr (cstr, '=');
	char* b64 = strstr (cstr, "base64:");
	char* s = strchr (cstr, ' ');
	char* s2 = NULL, *s3 = NULL;
	char* comment = NULL;
	bool comment_needs_free = false;
	RFlagItem *item;
	ut32 bsze = 1; // core->blocksize;
#if 0
	int eqdir = 0;
	if (eq && eq > cstr) {
		if (sign > 0) {
			eqdir = 1;
		} else if (sign < 0) {
			eqdir = -1;
		}
	}
#endif
	// Get outta here as fast as we can so we can make sure that the comment
	// buffer used on later code can be freed properly if necessary.
	if (*cstr == '.') {
		return cmd_flag (core, str);
	}
	ut64 off = core->addr;
	// Check base64 padding
	if (eq && !(b64 && eq > b64 && (eq[1] == '\0' || (eq[1] == '=' && eq[2] == '\0')))) {
		*eq = 0;
		ut64 arg = r_num_math (core->num, eq + 1);
		if (core->num->nc.errors) {
			R_LOG_ERROR ("Invalid eq number (%s)", eq + 1);
			return 0;
		}
		off = arg;
#if 0
		RFlagItem *item = r_flag_get (core->flags, cstr);
		if (sign && item) {
			off = item->offset + (arg * eqdir);
		} else {
			off = arg;
		}
#endif
	}
	if (s) {
		*s = '\0';
		s2 = strchr (s + 1, ' ');
		if (s2) {
			*s2 = '\0';
			if (s2[1] && s2[2]) {
				const char *arg = r_str_trim_head_ro (s2 + 1);
				off = r_num_math (core->num, arg);
				if (core->num->nc.errors) {
					R_LOG_ERROR ("Invalid s2 number (%s)", arg);
					return false;
				}
			}
			s3 = strchr (s2 + 1, ' ');
			if (s3) {
				*s3 = '\0';
				if (r_str_startswith (s3 + 1, "base64:")) {
					comment = (char *) r_base64_decode_dyn (s3 + 8, -1, NULL);
					comment_needs_free = true;
				} else if (s3[1]) {
					comment = s3 + 1;
				}
			}
		}
		if (s[1] == '=') {
			bsze = 1;
		} else {
			bsze = r_num_math (core->num, s + 1);
			if (core->num->nc.errors) {
				R_LOG_ERROR ("Invalid number (%s)", s + 1);
				return false;
			}
		}
	}

	bool addFlag = true;
	if (addsign) {
		if ((item = r_flag_get_at (core->flags, off, false))) {
			addFlag = false;
		}
	}
	if (addFlag) {
		if (!r_name_check (cstr)) {
			R_LOG_ERROR ("Invalid flag name '%s'", cstr);
			return false;
		}
		item = r_flag_set (core->flags, cstr, off, bsze);
	}
	if (item && comment) {
		r_flag_item_set_comment (core->flags, item, comment);
		if (comment_needs_free) {
			free (comment);
		}
	}
	return true;
}

static void cmd_fR(RCore *core, const char *str) {
	switch (*str) {
	case '\0':
		r_core_cmd_help_match (core, help_msg_f, "fR");
		R_LOG_INFO ("Relocate PIE flags in debugger with f.ex: fR entry0 `dm~:1[1]`");
		break;
	case '?':
		r_core_cmd_help (core, help_msg_fR);
		break;
	case ' ':
		{
			char *p = strchr (str + 1, ' ');
			ut64 from, to, mask = 0xffff;
			int ret;
			if (p) {
				char *q = strchr (p + 1, ' ');
				*p = 0;
				if (q) {
					*q++ = 0;
					mask = r_num_math (core->num, q);
				}
				from = r_num_math (core->num, str + 1);
				to = r_num_math (core->num, p + 1);
				ret = r_flag_relocate (core->flags, from, mask, to);
				R_LOG_INFO ("Relocated %d flags", ret);
			} else {
				r_core_cmd_help_match (core, help_msg_f, "fR");
				R_LOG_INFO ("Relocate PIE flags in debugger with f.ex: fR entry0 `dm~:1[1]`");
			}
		}
		break;
	default:
		r_core_return_invalid_command (core, "fR", *str);
		break;
	}
}

static int cmd_flag(void *data, const char *input) {
	static R_TH_LOCAL int flagenum = 0;
	RCore *core = (RCore *)data;
	ut64 off = core->addr;
	char *ptr;
	RFlagItem *item;
	char *name = NULL;
	st64 base;

	char *str = (*input)? strdup (input + 1): NULL;
	switch (*input) {
	case 'f': // "ff"
		if (input[1] == '?') { // "ff?"
			r_core_cmd_help_contains (core, help_msg_f, "ff");
		} else if (input[1] == 's') { // "ffs"
			const int delta = flag_to_flag (core, input + 2);
			if (delta > 0) {
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", core->addr + delta);
			}
		} else {
			r_cons_printf (core->cons, "%d\n", flag_to_flag (core, input + 1));
		}
		break;
	case 'e': // "fe"
		switch (input[1]) {
		case ' ':
			ptr = r_str_newf ("%s.%d", input + 2, flagenum);
			(void)r_flag_set (core->flags, ptr, core->addr, 1);
			flagenum++;
			free (ptr);
			break;
		case '-':
			flagenum = 0;
			break;
		case '?':
			r_core_cmd_help_contains (core, help_msg_f, "fe");
			break;
		default:
			r_core_return_invalid_command (core, "fe", input[1]);
			break;
		}
		break;
	case '=': // "f="
		switch (input[1]) {
		case 0:
			flagbars (core, NULL);
			break;
		case ' ':
			flagbars (core, input + 2);
			break;
		case '?':
			r_core_cmd_help (core, help_msg_feq);
			break;
		default:
			r_core_return_invalid_command (core, "f=", input[1]);
			break;
		}
		break;
	case 'a': // "fa"
		switch (input[1]) {
		case 0:
		case '.':
			{
				RFlagItem *fi = r_flag_get_at (core->flags, core->addr, false);
				if (fi) {
					const char *alias = r_flag_item_set_alias (core->flags, fi, NULL);
					if (alias) {
						r_cons_println (core->cons, alias);
					} else {
						R_LOG_ERROR ("No alias set for this flag");
					}
				} else {
					R_LOG_ERROR ("Cannot find flag '%s'", name);
				}
			}
			break;
		case '-':
			{
				const char *name = (char *)r_str_trim_head_ro (input + 2);
				if (*name) {
					if (*name == '*') {
						R_LOG_ERROR ("Not implemented");
						break;
					}
					RFlagItem *fi;
					if (*name == '.') {
						fi = r_flag_get_at (core->flags, core->addr, false);
					} else {
						fi = r_flag_get (core->flags, name);
					}
					if (fi) {
						r_flag_item_set_alias (core->flags, fi, "");
					} else {
						R_LOG_ERROR ("Cannot find flag '%s'", name);
					}
				} else {
					R_LOG_ERROR ("Missing flag name to remove its alias");
				}
			}
			break;
		case ' ':
			R_FREE (str);
			str = strdup (input + 2);
			ptr = strchr (str, '=');
			if (!ptr) {
				ptr = strchr (str, ' ');
			}
			if (ptr) {
				*ptr++ = 0;
			}
			name = (char *)r_str_trim_head_ro (str);
			ptr = (char *)r_str_trim_head_ro (ptr);
			RFlagItem *fi = r_flag_get (core->flags, name);
			if (!fi) {
				fi = r_flag_set (core->flags, name, core->addr, 1);
			}
			if (fi) {
				r_flag_item_set_alias (core->flags, fi, ptr);
			} else {
				R_LOG_ERROR ("Cannot find flag '%s'", name);
			}
			break;
		case '?':
			r_core_cmd_help_match (core, help_msg_f, "fa");
			break;
		default:
			r_core_return_invalid_command (core, "fa", input[1]);
			break;
		}
		break;
	case 'V': // "fV" visual marks
		switch (input[1]) {
		case '*':
			r_core_vmark_dump (core, '*');
			break;
		case '-': // "fV-"
			if (input[2] == '*') {
				r_core_vmark_reset (core);
			} else if (input[2]) {
				r_core_vmark_del (core, input[2]);
			} else {
				R_LOG_ERROR ("Give me a name or delete them all with fV-*");
			}
			break;
		case ' ': // "fV "
			if (input[2] && input[3]) {
				const char *arg = r_str_trim_head_ro (input + 1);
				if (isdigit (*arg)) {
					int n = atoi (arg);
					if (n > 0 && n < UT8_MAX) {
						while (*arg && *arg != ' ') {
							arg++;
						}
						arg = r_str_trim_head_ro (arg);
						ut64 addr = arg? r_num_math (core->num, arg): core->addr;
						r_core_vmark_set (core, n, addr, 0, 0);
					} else {
						R_LOG_ERROR ("invalid argument for fV");
					}
				} else {
					const char *arg = r_str_trim_head_ro (input + 3);
					ut64 addr = arg? r_num_math (core->num, arg): core->addr;
					r_core_vmark_set (core, input[2], addr, 0, 0);
				}
			} else {
				// uh
			}
			break;
		case '?':
			r_core_cmd_help (core, help_msg_fV);
			break;
		default:
			r_core_vmark_dump (core, 0);
			break;
		}
		break;
	case 'm': // "fm"
		r_flag_move (core->flags, core->addr, r_num_math (core->num, input+1));
		break;
	case 'R': // "fR"
		cmd_fR (core, str);
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
			r_cons_printf (core->cons, "%"PFMT64d" 0x%"PFMT64x"\n",
				core->flags->base, core->flags->base);
			break;
		default:
			r_core_cmd_help_match (core, help_msg_f, "fb");
			break;
		}
		break;
	case '+': // "f+'
		cmd_flag_add (core, str, 1);
		break;
	case ' ': // "f "
		cmd_flag_add (core, str, 0);
		break;
	case '-': // "f-"
		if (input[1] == '-') {
			r_flag_unset_all (core->flags);
		} else if (input[1]) {
			const char *flagname = r_str_trim_head_ro (input + 1);
			while (*flagname == ' ') {
				flagname++;
			}
			if (*flagname == '?') {
				r_core_cmd_help_contains (core, help_msg_f, "f-");
			} else if (isdigit (*flagname)) {
				ut64 addr = r_num_math (core->num, flagname);
				r_flag_unset_addr (core->flags, addr);
			} else if (!strcmp (flagname, "$$")) {
				r_flag_unset_addr (core->flags, core->addr);
			} else if (*flagname == '.') {
				RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
				if (fcn) {
					r_anal_function_delete_label_at (fcn, off);
				} else {
					R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, off);
				}
			} else {
				if (strchr (flagname, '*')) {
					r_flag_unset_glob (core->flags, flagname);
				} else {
					r_flag_unset_name (core->flags, flagname);
				}
			}
		} else {
			r_flag_unset_addr (core->flags, off);
		}
		break;
	case '.': // "f."
		input = r_str_trim_head_ro (input + 1) - 1;
		if (input[1]) {
			if (input[1] == '?') {
				r_core_cmd_help_contains (core, help_msg_f, "f.");
			} else if (input[1] == '*' || input[1] == 'j') {
				if (input[2] == '*') {
					print_function_labels (core, NULL, input[1]);
				} else {
					RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
					if (fcn) {
						print_function_labels (core, fcn, input[1]);
					} else {
						R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, off);
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
						if (*name == '-') {
							r_anal_function_delete_label (fcn, name + 1);
						} else {
							r_anal_function_set_label (fcn, name, off);
						}
					} else {
						R_LOG_ERROR ("Cannot find function at 0x%08"PFMT64x, off);
					}
					free (name);
				}
			}
		} else {
			RAnalFunction *fcn = r_anal_get_fcn_in (core->anal, off, 0);
			if (fcn) {
				print_function_labels (core, fcn, 0);
			} else {
				R_LOG_ERROR ("Local flags require a function to work");
			}
		}
		break;
	case 'l': // "fl"
		if (input[1] == '?') { // "fl?"
			r_core_cmd_help_contains (core, help_msg_f, "fl");
		} else if (input[1] == 'a') { // "fla"
			// TODO: we can optimize this if core->flags->flags is sorted by flagitem->offset
			char *glob;
			if (input[2] == '?') { // "fla?"
				r_core_cmd_help_match (core, help_msg_f, "fla");
			}
			glob = strchr (input, ' ');
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
				item = r_flag_get_in (core->flags,
					r_num_math (core->num, arg));
				if (item)
					item->size = r_num_math (core->num, p);
			} else {
				if (*arg) {
					item = r_flag_get_in (core->flags, core->addr);
					if (item) {
						item->size = r_num_math (core->num, arg);
					}
				} else {
					item = r_flag_get_in (core->flags, r_num_math (core->num, arg));
					if (item) {
						r_cons_printf (core->cons, "0x%08"PFMT64x"\n", item->size);
					}
				}
			}
			free (arg);
		} else { // "fl"
			item = r_flag_get_in (core->flags, core->addr);
			if (item) {
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", item->size);
			}
		}
		break;
#if 0
	case 'd':
		if (input[1] == ' ') {
			char cmd[128];
			RFlagItem *item = r_flag_get_in (core->flags,
				r_num_math (core->num, input+2));
			if (item) {
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", item->offset);
				snprintf (cmd, sizeof (cmd), "pD@%"PFMT64d":%"PFMT64d,
					 item->offset, item->size);
				r_core_cmd0 (core, cmd);
			}
		} else {
			R_LOG_ERROR ("add help here");
		}
		break;
#endif
	case 'z': // "fz"
		cmd_fz (core, input + 1);
		break;
	case 'x':
		if (input[1] == ' ') {
			RFlagItem *item = r_flag_get_in (core->flags,
				r_num_math (core->num, input+2));
			if (item) {
				r_cons_printf (core->cons, "0x%08"PFMT64x"\n", item->addr);
				r_core_cmdf (core, "px@%"PFMT64d":%"PFMT64d, item->addr, item->size);
			}
		} else {
			R_LOG_ERROR ("Missing arguments");
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
		case '?': // "fs?"
			r_core_cmd_help (core, help_msg_fs);
			break;
		case '+': // "fs+"
			r_flag_space_push (core->flags, r_str_trim_head_ro (input + 2));
			break;
		case 'r': // "fsr"
			if (input[2] == ' ') {
				char *newname = r_str_trim_dup (input + 3);
				r_str_trim (newname);
				r_flag_space_rename (core->flags, NULL, newname);
				free (newname);
			} else {
				r_core_cmd_help_match (core, help_msg_fs, "fsr");
			}
			break;
		case 's': // "fss"
			flag_space_stack_list (core, input[2]);
			break;
		case '-': // "fs-"
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
				r_flag_space_unset (core->flags, r_str_trim_head_ro (input + 2));
				break;
			}
			break;
		case ' ':
			{
				char *name = r_str_trim_dup (input + 2);
				r_str_trim (name);
				r_flag_space_set (core->flags, name);
				free (name);
				break;
			}
		case 'm': // "fsm"
			{
				ut64 off = core->addr;
				if (input[2] == ' ') {
					off = r_num_math (core->num, input+2);
				}
				RFlagItem *f = r_flag_get_in (core->flags, off);
				if (f) {
					f->space = r_flag_space_cur (core->flags);
				} else {
					R_LOG_ERROR ("Cannot find any flag at 0x%"PFMT64x, off);
				}
				break;
			}
		case 'j':
		case '\0':
		case '*':
		case 'q':
			spaces_list (core, &core->flags->spaces, input[1]);
			break;
		default:
			spaces_list (core, &core->flags->spaces, 0);
			break;
		}
		break;
	case 'g': // "fg"
		if (input[1]) {
			if (input[1] == ' ') {
				r_core_cmdf (core, "&& %d", atoi (input + 2));
			} else {
				R_LOG_ERROR ("fg: wait for all backaground jobs to finish");
			}
		} else {
			r_core_cmd0 (core, "&&");
		}
		break;
	case 'h': // "fh"
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
			r_core_cmd_help_contains (core, help_msg_f, "fh");
			break;
		}
		break;
	case 'c': // "fc"
		if (input[1] == 0 || input[1] == '.') {
			RList *list_to_free = input[1]? NULL: r_flag_all_list (core->flags, false);
			const RList *list = input[1]? r_flag_get_list (core->flags, core->addr): list_to_free;
			RListIter *iter;
			RFlagItem *fi;
			r_list_foreach (list, iter, fi) {
				RFlagItemMeta *fim = r_flag_get_meta (core->flags, fi->id);
				if (fim && fim->color) {
					if (input[1] && input[2] == '*') {
						r_cons_printf (core->cons, "fc %s=%s\n", fi->name, fim->color);
					} else {
						const char *pad = r_str_pad (' ', 10- strlen (fi->name));
						r_cons_printf (core->cons, "0x%08"PFMT64x"  %s%s%s\n", fi->addr, fi->name, pad, fim->color);
					}
				}
			}
			r_list_free (list_to_free);
		} else if (input[1] == '-') {
			RListIter *iter;
			RFlagItem *fi;
			ut64 addr = (input[1] && input[2] != '*' && input[2]) ? r_num_math (core->num, input + 2): core->addr;
			RList *list_to_free = (input[1] && input[2] == '*')? r_flag_all_list (core->flags, false): NULL;
			const RList *list = (input[1] && input[2] == '*')?
				list_to_free
				: r_flag_get_list (core->flags, addr);
			r_list_foreach (list, iter, fi) {
				r_flag_item_set_color (core->flags, fi, "");
			}
			r_list_free (list_to_free);
		} else if (input[1] == '*') {
			RListIter *iter;
			RFlagItem *fi;
			RList *list = r_flag_all_list (core->flags, false);
			r_list_foreach (list, iter, fi) {
				RFlagItemMeta *fim = r_flag_get_meta (core->flags, fi->id);
				if (fim && fim->color) {
					r_cons_printf (core->cons, "fc %s=%s\n", fi->name, fim->color);
				}
			}
			r_list_free (list);
		} else if (input[1] == ' ') {
			const char *ret;
			char *arg = r_str_trim_dup (input + 2);
			char *color = strchr (arg, '=');
			if (color) {
				*color++ = 0;
				RFlagItem *fi = r_flag_get (core->flags, arg);
				if (fi) {
					if (*color) {
						ret = r_flag_item_set_color (core->flags, fi, color);
						if (ret) {
							r_cons_println (core->cons, ret);
						}
					} else {
						r_flag_item_set_color (core->flags, fi, NULL);
					}
				} else {
					R_LOG_ERROR ("Unknown flag '%s'", arg);
				}
			} else {
				const RList *list = r_flag_get_list (core->flags, core->addr);
				char *color = r_str_trim_dup (input + 2);
				RListIter *iter;
				RFlagItem *fi;
				r_list_foreach (list, iter, fi) {
					r_flag_item_set_color (core->flags, fi, color);
				}
				free (color);
			}
			free (arg);
		} else {
			r_core_cmd_help (core, help_msg_fc);
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
						dec = (char *) r_base64_decode_dyn (q + 8, -1, NULL);
						if (dec) {
							r_flag_item_set_comment (core->flags, item, dec);
							free (dec);
						} else {
							R_LOG_ERROR ("Failed to decode base64-encoded string");
						}
					} else {
						r_flag_item_set_comment (core->flags, item, q + 1);
					}
				} else {
					R_LOG_ERROR ("Cannot find flag with name '%s'", p);
				}
			} else {
				item = r_flag_get_in (core->flags, r_num_math (core->num, p));
				if (item) {
					const char *cmt = r_flag_item_set_comment (core->flags, item, NULL);
					if (cmt) {
						r_cons_println (core->cons, cmt);
					}
				} else {
					R_LOG_ERROR ("Cannot find item");
				}
			}
			free (p);
		} else {
			r_core_cmd_help_match (core, help_msg_f, "fC");
		}
		break;
	case 'o': // "fo"
		r_core_fortune_print_random (core);
		break;
	case 'O': // "fO"
		flag_ordinals (core, input + 1);
		break;
	case 'r': // "fr"
		if (input[1] == '?') {
			r_core_cmd_help_contains (core, help_msg_f, "fr");
		} else if (input[1] == ' ' && input[2]) {
			RFlagItem *item = NULL;
			char *old = str + 1;
			char *new = strchr (old, ' ');
			if (new) {
				*new++ = 0;
				item = r_flag_get (core->flags, old);
				if (!item && r_str_startswith (old, "fcn.")) {
					item = r_flag_get (core->flags, old + 4);
				}
			} else {
				new = old;
				item = r_flag_get_in (core->flags, core->addr);
			}
			if (item) {
				if (!r_flag_rename (core->flags, item, new)) {
					R_LOG_ERROR ("Invalid name");
				}
			} else {
				R_LOG_ERROR ("Cannot find flag with given name");
				// r_core_cmd_help_contains (core, help_msg_f, "fr");
			}
		}
		break;
	case 'N':
		if (!input[1]) {
			RFlagItem *item = r_flag_get_in (core->flags, core->addr);
			if (item) {
				r_cons_printf (core->cons, "%s\n", item->realname);
			}
			break;
		} else if (input[1] == ' ' && input[2]) {
			RFlagItem *item;
			char *name = str + 1;
			char *realname = strchr (name, ' ');
			if (realname) {
				*realname++ = 0;
				item = r_flag_get (core->flags, name);
				if (!item && r_str_startswith (name, "fcn.")) {
					item = r_flag_get (core->flags, name + 4);
				}
			} else {
				realname = name;
				item = r_flag_get_in (core->flags, core->addr);
			}
			if (item) {
				r_flag_item_set_realname (core->flags, item, realname);
			}
			break;
		}
		r_core_cmd_help_contains (core, help_msg_f, "fN");
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
		if (input[0] && input[1] == '?') {
			char cmd[3] = "fn";
			cmd[1] = input[0];
			r_core_cmd_help_contains (core, help_msg_f, cmd);
			break;
		}
		if (input[0] && input[1] == '.') {
			const int mode = input[2];
			const RList *list = r_flag_get_list (core->flags, core->addr);
			PJ *pj = NULL;
			if (mode == 'j') {
				pj = r_core_pj_new (core);
				pj_a (pj);
			}
			RListIter *iter;
			RFlagItem *item;
			r_list_foreach (list, iter, item) {
				switch (mode) {
				case '*':
					r_cons_printf (core->cons, "f %s = 0x%08"PFMT64x"\n", item->name, item->addr);
					break;
				case 'j':
					{
						pj_o (pj);
						pj_ks (pj, "name", item->name);
						pj_ks (pj, "realname", item->realname);
						pj_kn (pj, "addr", item->addr);
						pj_kn (pj, "size", item->size);
						pj_end (pj);
					}
					break;
				default:
					r_cons_printf (core->cons, "%s\n", item->name);
					break;
				}
			}
			if (mode == 'j') {
				pj_end (pj);
				char *s = pj_drain (pj);
				r_cons_printf (core->cons, "%s\n", s);
				free (s);
			}
		} else {
			char *s = r_flag_list (core->flags, *input, input[0]? input + 1: "");
			if (*input == 'j') {
				r_cons_println (core->cons, s);
			} else {
				r_cons_print (core->cons, s);
			}
			free (s);
		}
		break;
	case 'i': // "fi"
		if (input[1] == ' ' || (input[1] && input[2] == ' ')) {
			char *arg = strdup (r_str_trim_head_ro (input + 2));
			if (*arg) {
				char *sp = strchr (arg, ' ');
				if (!sp) {
					char *newarg = r_str_newf ("%c0x%"PFMT64x" %s+0x%"PFMT64x,
						input[1], core->addr, arg, core->addr);
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
					core->addr, core->addr + core->blocksize);
			}
			char *s = r_flag_list (core->flags, 'i', arg);
			r_cons_print (core->cons, s);
			free (s);
			free (arg);
		} else {
			// XXX dupe for prev case
			char *arg = r_str_newf (" 0x%"PFMT64x" 0x%"PFMT64x,
				core->addr, core->addr + core->blocksize);
			char *s = r_flag_list (core->flags, 'i', arg);
			r_cons_print (core->cons, s);
			free (s);
			free (arg);
		}
		break;
	case 'D': // "fD"
		switch (input[1]) {
		case ' ':
			{
				char *orig = r_str_trim_dup (input + 2);
				char *nfn = r_name_filter_dup (orig);
				r_cons_printf (core->cons, "%s\n", nfn);
				free (nfn);
				free (orig);
			}
			break;
		case '*':
			if (input[2] == ' ') {
				char *orig = r_str_trim_dup (input + 3);
				char *nfn = r_name_filter_dup (orig);
				r_cons_printf (core->cons, "f %s\n", nfn);
				free (nfn);
				free (orig);
			} else {
				r_core_cmd_help (core, help_msg_fD);
			}
			break;
		case '.':
			if (input[2] == ' ') {
				char *orig = r_str_trim_dup (input + 3);
				char *nfn = r_name_filter_dup (orig);
				r_flag_set (core->flags, nfn, core->addr, 1);
				free (nfn);
				free (orig);
			} else {
				r_core_cmd_help (core, help_msg_fD);
			}
			break;
		case 'j':
			if (input[2] == ' ') {
				char *orig = r_str_trim_dup (input + 2);
				char *nfn = r_name_filter_dup (orig);
				PJ *pj = r_core_pj_new (core);
				pj_o (pj);
				pj_ks (pj, "orig", orig);
				pj_ks (pj, "filtered", nfn);
				pj_end (pj);
				free (nfn);
				free (orig);
			} else {
				r_core_cmd_help (core, help_msg_fD);
			}
			break;
		default:
			r_core_cmd_help (core, help_msg_fD);
			break;
		}
		break;
	case 'd': // "fd"
		cmd_fd (core, input);
		break;
	case '?':
		if (input[1]) {
			const char *arg = r_str_trim_head_ro (input + 1);
			RFlagItem *fi = r_flag_get (core->flags, arg);
			r_core_return_value (core, fi? 1:0);
		} else {
			r_core_cmd_help (core, help_msg_f);
		}
		break;
	default:
		r_core_return_invalid_command (core, "f", *input);
		break;
	}
	free (str);
	return 0;
}
#endif
