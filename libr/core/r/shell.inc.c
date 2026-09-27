/* radare - LGPL - Copyright 2009-2026 // pancake */

#if R_INCLUDE_BEGIN

typedef struct {
	const char *name;
	int (*run)(RCmdContext *ctx);
	const char *const *help;
	RCmdArgFlags flags;
} ShellCommand;

static RCoreHelpMessage help_msg_mkdir = {
	"Usage:", "mkdir [-p] [directory]", "Create a directory on the host filesystem",
	"mkdir", " [directory]", "create a directory",
	"mkdir -p", " [directory]", "create a directory and its parents",
	NULL
};

// R2R test/db/cmd/posixshell
static int mkdir_run(RCmdContext *ctx) {
	const char *args[2];
	r_cmdctx_args (ctx, args, R_ARRAY_SIZE (args));
	const size_t argc = r_cmdctx_argc (ctx);
	if (argc < 1 || argc > 2 || !*args[0]) {
		R_LOG_ERROR ("Usage: mkdir [-p] [directory]");
		return 1;
	}
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
	return ok? 0: 1;
}

static RCoreHelpMessage help_msg_mktemp = {
	"Usage:", "mktemp [-d] [file|directory]", "Create a temporary file or directory and print its path",
	"mktemp", " [prefix]", "create a temporary file",
	"mktemp -d", " [prefix]", "create a temporary directory",
	NULL
};

// R2R test/db/cmd/cmd_mount
static int mktemp_run(RCmdContext *ctx) {
	const char *args[2];
	r_cmdctx_args (ctx, args, R_ARRAY_SIZE (args));
	const size_t argc = r_cmdctx_argc (ctx);
	if (argc < 1 || argc > 2 || !*args[0]) {
		R_LOG_ERROR ("Usage: mktemp [-d] [file|directory]");
		return 1;
	}
	const bool dir = !strcmp (args[0], "-d");
	const char *path = args[dir? 1: 0];
	if (R_STR_ISEMPTY (path) || (!dir && args[1])) {
		R_LOG_INFO ("Usage: mktemp [-d] [file|directory]");
		return 1;
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
	return ok? 0: 1;
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
					r_strbuf_appendf (sb, "\n## %s\n\n", args_trimmed? args_trimmed: "");
					in_list = false;
				} else if (!strcmp (macro, "Ss")) {
					// Subsection header
					r_strbuf_appendf (sb, "\n### %s\n\n", args_trimmed? args_trimmed: "");
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
	}
	return res;
}

static int man_run(RCmdContext *ctx) {
	const ShellCommand *spec = ctx->handler_user;
	const char *command = spec->name;
	const bool list = !strcmp (command, "mal");
	const size_t argc = r_cmdctx_argc (ctx);
	RStrs arg = r_cmdctx_arg (ctx, 0);
	if (argc != (list? 0: 1) || (!list && !r_strs_at (arg, 0))) {
		R_LOG_ERROR ("Usage: %s%s", command, list? "": " [page]");
		return 1;
	}
	if (list) {
		man_read (ctx, "?");
		return 0;
	}
	char *text = man_read (ctx, arg.a);
	if (text) {
		r_cons_less_str (ctx->cons, text, NULL);
		free (text);
	} else {
		R_LOG_ERROR ("Cannot find manpage");
	}
	return 0;
}

static RCoreHelpMessage help_msg_make = {
	"Usage:", "make [arguments]", "Run the host make command",
	"make", " [arguments]", "pass arguments to make using shell syntax",
	NULL
};

static int make_run(RCmdContext *ctx) {
	// Pass shell syntax through to make.
	return r_sys_cmdf ("make%s", ctx->subcmd.b);
}

static RCoreHelpMessage help_msg_mv = {
	"Usage:", "mv [src] [dst]", "Move a file on the host filesystem",
	"mv", " [src] [dst]", "move or rename a file",
	NULL
};

// R2R test/db/cmd/cmd_mount
static int mv_run(RCmdContext *ctx) {
	if (r_cmdctx_argc (ctx) != 2 || !*r_cmdctx_arg (ctx, 0).a) {
		R_LOG_ERROR ("Usage: mv [src] [dst]");
		return 1;
	}
	bool ok = r_file_move (r_cmdctx_arg (ctx, 0).a, r_cmdctx_arg (ctx, 1).a);
	if (!ok) {
		R_LOG_ERROR ("Cannot move file");
	}
	return ok? 0: 1;
}

static RCmdResult shell_callback(RCmdContext *ctx) {
	const ShellCommand *command = ctx->handler_user;
	int rc = 0;
	if (r_strs_equals_str (ctx->subcmd, "?") || !strcmp (command->name, "ma?")) {
		if (command->help == help_msg_man) {
			bool group = !strcmp (command->name, "ma?");
			r_cons_cmd_help_match (ctx->cons, command->help, group? "ma": command->name, 0, !group);
		} else {
			r_cons_cmd_help (ctx->cons, command->help);
		}
	} else if (!r_strs_empty (ctx->subcmd)) {
		r_core_return_invalid_command (ctx->user, command->name, r_strs_at (ctx->subcmd, 0));
		rc = 1;
	} else {
		rc = command->run (ctx);
	}
	RCore *core = ctx->user;
	r_core_return_value (core, rc);
	return (RCmdResult) { .status = rc };
}

static bool r_core_cmd_shell_init(RCmd *cmd) {
	static const ShellCommand commands[] = {
		{ "mkdir", mkdir_run, help_msg_mkdir, 0 },
		{ "mktemp", mktemp_run, help_msg_mktemp, 0 },
		{ "man", man_run, help_msg_man, 0 },
		{ "mal", man_run, help_msg_man, 0 },
		{ "ma?", man_run, help_msg_man, 0 },
		{ "make", make_run, help_msg_make, R_CMD_ARGS_VERBATIM },
		{ "mv", mv_run, help_msg_mv, 0 },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (commands); i++) {
		const ShellCommand *command = &commands[i];
		if (!r_cmd_register_args (cmd, command->name, shell_callback, (void *)command, command->flags)) {
			while (i > 0) {
				r_cmd_unregister (cmd, commands[--i].name);
			}
			return false;
		}
	}
	return true;
}

#endif
