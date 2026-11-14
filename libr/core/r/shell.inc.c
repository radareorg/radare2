/* radare - LGPL - Copyright 2009-2026 // pancake */

#if R_INCLUDE_BEGIN

static RCoreHelpMessage help_msg_mkdir = {
	"Usage:", "mkdir [-p] [directory]", "Create a directory on the host filesystem",
	"mkdir", " [directory]", "create a directory",
	"mkdir -p", " [directory]", "create a directory and its parents",
	NULL
};

// R2R test/db/cmd/posixshell
static bool mkdir_run(RCmdContext *ctx) {
	const char *args[2];
	r_cmdctx_args (ctx, args, R_ARRAY_SIZE (args));
	const bool parents = !strcmp (args[0], "-p");
	const char *path = args[parents? 1: 0];
	bool ok = false;
	if (R_STR_ISNOTEMPTY (path) && (parents || !args[1])) {
		ok = r_sys_mkdirp (path) && r_file_is_directory (path);
		if (!ok) {
			R_LOG_ERROR ("Cannot create '%s'", path);
		}
	} else {
		R_LOG_INFO ("Usage: mkdir [-p] [directory]");
	}
	return ok;
}

static RCoreHelpMessage help_msg_mktemp = {
	"Usage:", "mktemp [-d] [file|directory]", "Create a temporary file or directory and print its path",
	"mktemp", " [prefix]", "create a temporary file",
	"mktemp -d", " [prefix]", "create a temporary directory",
	NULL
};

// R2R test/db/cmd/cmd_mount
static bool mktemp_run(RCmdContext *ctx) {
	const char *args[2];
	r_cmdctx_args (ctx, args, R_ARRAY_SIZE (args));
	const bool dir = !strcmp (args[0], "-d");
	const char *path = args[dir? 1: 0];
	if (R_STR_ISEMPTY (path) || (!dir && args[1])) {
		R_LOG_INFO ("Usage: mktemp [-d] [file|directory]");
		return false;
	}
	char *name = NULL;
	int fd = r_file_mkstemp (path, &name);
	bool ok = fd != -1;
	if (ok) {
		close (fd);
		if (dir) {
			ok = r_file_rm (name) && r_sys_mkdir (name);
		}
	}
	if (ok) {
		r_cons_println (ctx->cons, name);
	} else {
		R_LOG_ERROR ("Cannot create '%s'", path);
	}
	free (name);
	return ok;
}

static RCoreHelpMessage help_msg_man = {
	"Usage:", "man [page]", "Read documentation",
	"mal", "", "list available r2 docs",
	"man", " [page]", "man=manpage reading (see mal)",
	NULL
};

static char *man_read(RCmdContext *ctx, const char *page) {
	RCore *core = ctx->user;
	const char *docdir = R2_DATDIR "/doc/radare2/";
	if (!strcmp (page, "?")) {
		RList *files = r_sys_dir (docdir);
		RListIter *iter;
		const char *name;
		r_list_foreach (files, iter, name) {
			if (*name != '.' && (r_str_endswith (name, ".md") || r_str_endswith (name, ".txt"))) {
				r_cons_println (ctx->cons, name);
			}
		}
		r_list_free (files);
		return NULL;
	}
	if (r_file_exists (page)) {
		return r_file_slurp (page, NULL);
	}
	char *n = r_str_newf (R2_DATDIR "/doc/radare2/%s", page);
	if (r_file_exists (n)) {
		if (r_str_endswith (page, ".r2.md")) {
			r_core_callf (core, ". %s", n);
			free (n);
			return NULL;
		}
		if (r_str_endswith (page, ".md")) {
			char *md = r_file_slurp (n, NULL);
			char *data = r_core_md2txt (core, md, false);
			free (md);
			free (n);
			return data;
		}
		char *data = r_file_slurp (n, NULL);
		free (n);
		return data;
	}
	free (n);
	const char *dirs[] = { R2_DATDIR, "/usr/share" };
	char *res = NULL;
	int cat;
	size_t i;
	for (cat = 1; cat <= 3 && !res; cat += 2) {
		for (i = 0; i < R_ARRAY_SIZE (dirs) && !res; i++) {
			char *p = r_str_newf ("%s/man/man%d/%s.%d", dirs[i], cat, page, cat);
			res = r_file_slurp (p, NULL);
			free (p);
		}
	}
	if (res) {
		// Process man page macros to markdown
		RStrBuf *sb = r_strbuf_new ("");
		char *lines = res;
		char *line = lines;
		bool in_code_block = false;
		bool in_list = false;

		while (line && *line) {
			char *next_line = strchr (line, '\n');
			if (next_line) {
				*next_line = '\0';
				next_line++;
			}

			// Skip empty lines at the beginning
			if (!*line) {
				line = next_line;
				continue;
			}

			// Check if this is a man macro line
			if (*line == '.') {
				char *macro = line + 1;
				char *args_str = strchr (macro, ' ');
				const char *args_trimmed = NULL;
				if (args_str) {
					*args_str = '\0';
					args_trimmed = r_str_trim_head_ro (args_str + 1);
				}

				if (!strcmp (macro, "Sh")) {
					// Section header
					r_strbuf_appendf (sb, "%s## %s\n\n", r_strbuf_is_empty (sb)? "": "\n\n", args_trimmed? args_trimmed: "");
					in_list = false;
				} else if (!strcmp (macro, "Ss")) {
					// Subsection header
					r_strbuf_appendf (sb, "%s### %s\n\n", r_strbuf_is_empty (sb)? "": "\n\n", args_trimmed? args_trimmed: "");
					in_list = false;
				} else if (!strcmp (macro, "Pp")) {
					// Paragraph break
					r_strbuf_append (sb, "\n\n");
				} else if (!strcmp (macro, "Bl")) {
					// Begin list
					in_list = true;
				} else if (!strcmp (macro, "El")) {
					// End list
					in_list = false;
					r_strbuf_append (sb, "\n");
				} else if (!strcmp (macro, "It")) {
					// List item
					if (in_list) {
						if (args_trimmed) {
							// Handle tagged list items
							if (!strcmp (args_trimmed, "Fl")) {
								r_strbuf_append (sb, "\n- `-`: ");
							} else if (r_str_startswith (args_trimmed, "Fl ")) {
								const char *flag = args_trimmed + 3; // Skip "Fl "
								r_strbuf_appendf (sb, "\n- `-%s`: ", flag);
							} else if (!strcmp (args_trimmed, "Ar")) {
								r_strbuf_append (sb, "\n- `<arg>`: ");
							} else {
								r_strbuf_appendf (sb, "\n- `%s`: ", args_trimmed);
							}
						} else {
							r_strbuf_append (sb, "\n- ");
						}
					} else {
						r_strbuf_appendf (sb, "\n   * %s", args_trimmed? args_trimmed: "");
					}
				} else if (!strcmp (macro, "Nm")) {
					// Name
					r_strbuf_appendf (sb, "%s", args_trimmed? args_trimmed: "");
				} else if (!strcmp (macro, "Nd")) {
					// Description
					r_strbuf_appendf (sb, " - %s", args_trimmed? args_trimmed: "");
				} else if (!strcmp (macro, "Xr") && R_STR_ISNOTEMPTY (args_trimmed)) {
					size_t name_len = strcspn (args_trimmed, " \t");
					const char *tail = r_str_trim_head_ro (args_trimmed + name_len);
					r_strbuf_append (sb, "`");
					r_strbuf_append_n (sb, args_trimmed, name_len);
					if (*tail && !strchr (".,;:!?)]", *tail)) {
						size_t section_len = strcspn (tail, " \t");
						r_strbuf_appendf (sb, "(%.*s)", (int)section_len, tail);
						tail = r_str_trim_head_ro (tail + section_len);
					}
					r_strbuf_appendf (sb, "`%s\n", tail);
				} else if (!strcmp (macro, "Ft")) {
					// Function type
					r_strbuf_appendf (sb, "\n**%s** ", args_trimmed? args_trimmed: "");
				} else if (!strcmp (macro, "Fn")) {
					// Function name
					r_strbuf_appendf (sb, "`%s`", args_trimmed? args_trimmed: "");
				} else if (!strcmp (macro, "Fl")) {
					// Flag option
					r_strbuf_appendf (sb, "`-%s`", args_trimmed? args_trimmed: "");
				} else if (!strcmp (macro, "Ar")) {
					// Argument
					r_strbuf_appendf (sb, "`%s`", args_trimmed? args_trimmed: "");
				} else if (!strcmp (macro, "Op")) {
					// Optional argument - ignore for now
				} else if (!strcmp (macro, "In")) {
					// Include file
					r_strbuf_appendf (sb, "\n`%s`", args_trimmed? args_trimmed: "");
				} else if (!strcmp (macro, "Dl")) {
					// Display literal
					r_strbuf_appendf (sb, "\n```\n%s\n```\n", args_trimmed? args_trimmed: "");
				} else if (!strcmp (macro, "Bd")) {
					// Begin display
					r_strbuf_append (sb, "\n```\n");
					in_code_block = true;
				} else if (!strcmp (macro, "Ed")) {
					// End display
					r_strbuf_append (sb, "\n```\n");
					in_code_block = false;
				}
			} else {
				// Regular text line
				if (in_code_block) {
					r_strbuf_appendf (sb, "%s\n", line);
				} else {
					// Clean up extra spaces and format text
					char *trimmed = r_str_trim_dup (line);
					if (*trimmed) {
						r_strbuf_appendf (sb, "%s\n", trimmed);
					}
					free (trimmed);
				}
			}

			line = next_line;
		}

		free (res);
		res = r_strbuf_drain (sb);

		// Clean up extra whitespace
		res = r_str_replace_all (res, "\n\n\n", "\n\n");
		res = r_str_replace_all (res, "\\-", "-");
		char *rendered = r_core_md2txt (core, res, false);
		free (res);
		res = rendered;
	}
	return res;
}

// R2R test/db/cmd/posixshell
static bool man_run(RCmdContext *ctx) {
	const RCmdRow *row = ctx->handler_user;
	if (!strcmp (row->name, "mal")) {
		man_read (ctx, "?");
		return true;
	}
	char *text = man_read (ctx, r_cmdctx_arg (ctx, 0).a);
	if (text) {
		r_cons_less_str (ctx->cons, text, NULL);
		free (text);
	} else {
		R_LOG_ERROR ("Cannot find manpage");
	}
	return true;
}

static bool man_group_help(RCmdContext *ctx) {
	r_cons_cmd_help_match (ctx->cons, help_msg_man, "ma", 0, false);
	return true;
}

static RCoreHelpMessage help_msg_make = {
	"Usage:", "make [arguments]", "Run the host make command",
	"make", " [arguments]", "pass arguments to make using shell syntax",
	NULL
};

static bool make_run(RCmdContext *ctx) {
	// Pass shell syntax through to make.
	const int rc = r_sys_cmdf ("make%s", ctx->subcmd.b);
	r_core_return_value ((RCore *)ctx->user, rc);
	return !rc;
}

static RCoreHelpMessage help_msg_mv = {
	"Usage:", "mv [src] [dst]", "Move a file on the host filesystem",
	"mv", " [src] [dst]", "move or rename a file",
	NULL
};

// R2R test/db/cmd/cmd_mount
static bool mv_run(RCmdContext *ctx) {
	bool ok = r_file_move (r_cmdctx_arg (ctx, 0).a, r_cmdctx_arg (ctx, 1).a);
	if (!ok) {
		R_LOG_ERROR ("Cannot move file");
	}
	return ok;
}

static bool r_core_cmd_shell_init(RCmd *cmd) {
	static const RCmdRow rows[] = {
		{ "ma?", man_group_help, "", NULL, 0, 0 },
		{ "make", make_run, " [arguments]", help_msg_make, 0, 0, R_CMD_ARGS_VERBATIM | R_CMD_ROW_SETS_VALUE },
		{ "mal", man_run, "", NULL, 0, 0 },
		{ "man", man_run, " [page]", NULL, 1, 1 },
		{ "mkdir", mkdir_run, " [-p] [directory]", help_msg_mkdir, 1, 2 },
		{ "mktemp", mktemp_run, " [-d] [file|directory]", help_msg_mktemp, 1, 2 },
		{ "mv", mv_run, " [src] [dst]", help_msg_mv, 2, 2 },
	};
	static const RCmdTable table = { help_msg_man, rows, R_ARRAY_SIZE (rows) };
	return r_cmd_register_table (cmd, "mk", &table)
		&& r_cmd_register_table (cmd, "ma", &table)
		&& r_cmd_register_table (cmd, "mv", &table);
}

#endif
