/* radare - LGPL - Copyright 2009-2026 // pancake */

#if R_INCLUDE_BEGIN

#include "../cmd_mmc.inc.c"

static RCoreHelpMessage help_msg_m = {
	"Usage:", "m[-?*dgy] [...] ", "Mountpoints management",
	"m", " /mnt ext2 0", "mount ext2 fs at /mnt with delta 0 on IO",
	"m", " /mnt 9fs tcp:127.0.0.1:9999", "mount fs with plugin options",
	"m", " /mnt", "mount fs at /mnt with autodetect fs and current offset",
	"m", "", "list all mountpoints in human readable format",
	"m*", "", "same as above, but in r2 commands",
	"m-", " /", "umount given path (also m-/)",
	"mL", "[Lj]", "list filesystem plugins (Same as Lm), mLL shows only fs plugin names",
	"mc", " [file]", "cat: Show the contents of the given file",
	"md", " /", "list files and directory on the virtual r2's fs",
	"mdd", " /", "show file size like `ls -l` in ms",
	"mdx", " /", "list deleted files (FAT)",
	"mdq", " /", "show just the file name (quiet)",
	"mf", "[?] [o|n]", "search files for given filename or for offset",
	"mg", " /foo [offset [size]]", "dump to disk; size 0 reads to EOF (supports base64:)",
	"mi", " /foo/bar", "get offset and size of given file",
	"mi", " 0x1234", "find filename by offset in current fs",
	"mix", " 0x1234", "find deleted filename by offset (FAT)",
	"mis", " /foo/bar", "get offset and size of file and seek to it",
	"mj", "", "list mounted filesystems in JSON",
	"mmc", "[left_path] [right_path]", "Mountpoint Miknight Commander (dual-panel file manager)",
	"mn", " [mountpoint]", "show filesystem information details",
	"mo", " /foo/bar", "open given file into a malloc://",
	"mp", " msdos 0", "show partitions in msdos format at offset 0",
	"mp", "", "list all supported partition types",
	"ms", " /mnt", "open filesystem shell at /mnt (or fs.cwd if not defined)",
	"md+", " /dir", "create directory inside mounted filesystem",
	"mw", " [file] [data]", "write data into file (quote filenames and data containing spaces)",
	"mwf", " [diskfile] [r2filepath]", "write contents of local diskfile into r2fs mounted path",
	"my", "", "yank contents of file into clipboard",
	"mal", "", "list available r2 docs",
	"man", " [page]", "man=manpage reading (see mal)",
	//"TODO: support multiple mountpoints and RFile IO's (need io+core refactorn",
	NULL
};

static RCoreHelpMessage help_msg_mcolon = {
	"Usage:", "m:", "[plugin-command]",
	"m:", "", "list the fs plugins",
	"m:", "posix", "run the command associated with the 'posix' fs plugin",
	NULL
};

static RCoreHelpMessage help_msg_mf = {
	"Usage:", "mf[no] [...]", "search files matching name or offset",
	"mfn", " /foo *.c", "search files by name in /foo path",
	"mfo", " /foo 0x5e91", "search files by offset in /foo path",
	NULL
};

static const char *mount_file_type(const char ch) {
	switch (ch) {
	case 'f': return "file";
	case 'd': return "directory";
	case 'm': return "mountpoint";
	}
	return "unknown";
}

static RList *mount_find_off(RCore *core, const char *cwd, ut64 off) {
	RList *list = NULL;
	if (R_STR_ISEMPTY (cwd) || !strcmp (cwd, "/")) {
		list = r_list_newf (free);
		RListIter *iter;
		RFSRoot *root;
		r_list_foreach (core->fs->roots, iter, root) {
			if (!root || !root->path) {
				continue;
			}
			RList *found = r_fs_find_off (core->fs, root->path, off);
			if (found) {
				r_list_join (list, found);
				r_list_free (found);
			}
		}
	} else {
		list = r_fs_find_off (core->fs, cwd, off);
	}
	if (list && r_list_empty (list)) {
		r_list_free (list);
		list = NULL;
	}
	return list;
}

static char *mount_escape_name(const char *name) {
	char *escaped = r_str_escape_utf8_keep_printable (name, false, true);
	return escaped? escaped: strdup (name);
}

static int mount_ls(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	const bool isJSON = r_cmd_ctx_mode (ctx, "j") == 'j';
	const bool minus_ele = r_strs_at (ctx->subcmd, 1) == 'd';
	const bool deleted_only = r_strs_findc (ctx->subcmd, 'x') != NULL;
	const bool minus_quiet = r_cmd_ctx_mode (ctx, "q") == 'q';
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	const char *input = argv[0]? argv[0]: "";
	char *decoded = NULL;
	if (r_str_startswith (input, "base64:")) {
		decoded = (char *)sdb_decode (input + 7, NULL);
		if (decoded) {
			input = decoded;
		}
	}
	int old_view = core->fs->view;
	if (deleted_only) {
		r_fs_view (core->fs, R_FS_VIEW_DELETED);
	}
	RList *list = r_fs_dir (core->fs, input);
	if (deleted_only) {
		r_fs_view (core->fs, old_view);
	}
	PJ *pj = NULL;
	if (isJSON) {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	if (list) {
		r_list_foreach (list, iter, file) {
			bool is_deleted = false;
			if (deleted_only) {
				is_deleted = file->name && (ut8)file->name[0] == 0xe5;
				if (!is_deleted) {
					continue;
				}
			}
			if (isJSON) {
				pj_o (pj);
				pj_ks (pj, "type", is_deleted? "deleted": mount_file_type (file->type));
				pj_kn (pj, "size", file->size);
				pj_ks (pj, "name", file->name);
				pj_end (pj);
			} else {
				char ftype = is_deleted? R_FS_FILE_TYPE_DELETED: file->type;
				char *dname = NULL;
				const char *name = file->name;
				if (is_deleted && file->name) {
					dname = mount_escape_name (file->name);
					if (dname) {
						name = dname;
					}
				}
				if (minus_quiet) {
					if (ftype == 'd') {
						r_cons_printf (ctx->cons, "%s/\n", name);
					} else {
						r_cons_printf (ctx->cons, "%s\n", name);
					}
				} else if (minus_ele) {
					r_cons_printf (ctx->cons, "%c %10u %s\n", ftype, file->size, name);
				} else {
					r_cons_printf (ctx->cons, "%c %s\n", ftype, name);
				}
				free (dname);
			}
		}
		r_list_free (list);
	} else {
		if (strlen (input) > 1) {
			R_LOG_ERROR ("Invalid path");
		}
	}
	const char *path = *input? input: "/";
	r_list_foreach (core->fs->roots, iter, root) {
		// TODO: adjust contents between //
		if (!strncmp (path, root->path, strlen (path))) {
			char *base = strdup (root->path);
			char *ls = (char *)r_str_lchr (base, '/');
			if (ls) {
				ls++;
				*ls = 0;
			}
			// TODO: adjust contents between //
			if (!strcmp (path, base)) {
				if (isJSON) {
					pj_o (pj);
					pj_ks (pj, "path", root->path);
					pj_kn (pj, "delta", root->delta);
					pj_ks (pj, "type", root->p->meta.name);
					pj_end (pj);
				} else {
					r_cons_printf (ctx->cons, "m %s\n", root->path); // (root->path && root->path[0])? root->path + 1: "");
				}
			}
			free (base);
		}
	}
	if (isJSON) {
		pj_end (pj);
		r_cons_printf (ctx->cons, "%s\n", pj_string (pj));
		pj_free (pj);
	}
	free (decoded);
	return 0;
}

// R2R test/db/cmd/cmd_mount
static R_OWNED RFSFile *mount_read_file(RCore *core, const char *filename) {
	RFSFile *file = r_fs_open (core->fs, filename, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open %s", filename);
		return NULL;
	}
	int nread = file->size > INT_MAX? -1: file->size;
	if (nread > 0 && !file->data) {
		nread = r_fs_read (core->fs, file, 0, nread);
	}
	if (nread >= 0 && nread == file->size && (!nread || file->data)) {
		return file;
	}
	R_LOG_ERROR ("Cannot read %s", filename);
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return NULL;
}

static int mount_cat(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	RFSFile *file = mount_read_file (core, argv[0]);
	if (!file) {
		return 1;
	}
	if (file->size) {
		r_cons_write (ctx->cons, (const char *)file->data, file->size);
	}
	r_cons_newline (ctx->cons);
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return 0;
}

static int mount_get(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	const size_t argc = RVecRStrs_length (&ctx->args);
	ut64 range[2] = { 0, 0 };
	char *decoded = NULL;
	bool ok = false;
	size_t i;
	for (i = 1; i < argc; i++) {
		const char *err = NULL;
		range[i - 1] = r_num_math_err (core->num, argv[i], &err);
		if (err || core->num->dbz || (st64)range[i - 1] < 0) {
			R_LOG_ERROR ("Invalid offset or size");
			goto beach;
		}
	}
	const char *filename = argv[0];
	if (r_str_startswith (filename, "base64:")) {
		decoded = (char *)sdb_decode (filename + 7, NULL);
		if (R_STR_ISEMPTY (decoded)) {
			R_LOG_ERROR ("Invalid base64 filename");
			goto beach;
		}
		filename = decoded;
	}
	RFSFile *file = r_fs_open (core->fs, filename, false);
	if (file) {
		ut64 offset = range[0];
		ut64 size = range[1]? range[1]: file->size;
		const char *localfile = r_file_basename (filename);
		ok = offset <= file->size && r_file_dump (localfile, NULL, 0, false);
		size = offset <= file->size? R_MIN (size, file->size - offset): 0;
		bool cached = file->data != NULL;
		while (ok && size > 0) {
			int len = R_MIN (size, ctx->blocksize);
			int nread = cached? len: r_fs_read (core->fs, file, offset, len);
			ok = nread > 0 && nread <= len && file->data
				&& r_file_dump (localfile, file->data + (cached? offset: 0), nread, true);
			if (ok) {
				offset += nread;
				size -= nread;
			}
		}
		r_fs_close (core->fs, file);
		r_fs_file_free (file);
	} else if (argc == 1) {
		ok = r_fs_dir_dump (core->fs, filename, "./");
	}
	if (!ok) {
		R_LOG_ERROR ("Cannot dump %s", filename);
	}
beach:
	free (decoded);
	return ok? 0: 1;
}

static bool mount_arg_is_offset(const char *arg) {
	if (!*arg || strchr (arg, '=')) {
		return false;
	}
	if (*arg == '-' || *arg == '+') {
		arg++;
	}
	return isdigit ((ut8)*arg) || *arg == '$';
}

static int mount_add(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	const char *path = argv[0];
	const char *type = argv[1];
	ut64 off = 0;
	const char *options = argv[2];
	if (options && mount_arg_is_offset (options)) {
		off = r_num_math (core->num, options);
		options = argv[3];
	} else if (argv[3]) {
		R_LOG_ERROR ("Usage: m [mountpoint] [fstype] [offset] [options]");
		return 1;
	}
	if (type && *path != '/') {
		path = argv[1];
		type = argv[0];
	}
	if (*path != '/') {
		R_LOG_ERROR ("Invalid mountpoint");
		return 1;
	}
	char *detected = NULL;
	if (!type) {
		type = detected = r_fs_name (core->fs, core->addr);
		off = core->addr;
		if (!type) {
			R_LOG_ERROR ("Unknown filesystem type");
			return 1;
		}
	}
	bool ok = r_fs_mount_with_options (core->fs, type, path, off, options);
	if (!ok) {
		R_LOG_ERROR ("Cannot mount %s", path);
	}
	free (detected);
	return ok? 0: 1;
}

static int mount_list(RCmdContext *ctx, const char **argv) {
	if (argv[0]) {
		return mount_add (ctx, argv);
	}
	RCore *core = ctx->user;
	RListIter *iter;
	RFSRoot *root;
	const char mode = r_cmd_ctx_mode (ctx, "j*");
	PJ *pj = NULL;
	if (mode == 'j') {
		pj = r_core_pj_new (core);
		pj_o (pj);
		pj_ka (pj, "mountpoints");
	}
	r_list_foreach (core->fs->roots, iter, root) {
		if (pj) {
			pj_o (pj);
			pj_ks (pj, "path", root->path);
			pj_ks (pj, "plugin", root->p->meta.name);
			pj_kn (pj, "offset", root->delta);
			if (root->options) {
				pj_ks (pj, "options", root->options);
			}
			pj_end (pj);
		} else if (mode == '*') {
			char *path = r_str_arg_escape (root->path);
			char *options = root->options? r_str_arg_escape (root->options): NULL;
			r_cons_printf (ctx->cons, "m %s %s 0x%" PFMT64x "%s%s\n",
				path, root->p->meta.name, root->delta,
				options? " ": "", options? options: "");
			free (path);
			free (options);
		} else {
			r_cons_printf (ctx->cons, "%s\t0x%" PFMT64x "\t%s%s%s\n",
				root->p->meta.name, root->delta, root->path,
				root->options? "\t": "", root->options? root->options: "");
		}
	}
	if (pj) {
		RFSPlugin *plug;
		pj_end (pj);
		pj_ka (pj, "plugins");
		r_list_foreach (core->fs->libstore->plugins, iter, plug) {
			pj_o (pj);
			pj_ks (pj, "name", plug->meta.name);
			pj_ks (pj, "description", plug->meta.desc);
			pj_end (pj);
		}
		pj_end (pj);
		pj_end (pj);
		r_cons_println (ctx->cons, pj_string (pj));
		pj_free (pj);
	}
	return 0;
}

static int mount_plugins(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	const char mode = r_cmd_ctx_mode (ctx, "jL");
	const bool names = r_strs_equals_str (ctx->subcmd, "LL") || *ctx->subcmd.a == ':';
	PJ *pj = mode == 'j'? r_core_pj_new (core): NULL;
	if (pj) {
		pj_a (pj);
	}
	RListIter *iter;
	RFSPlugin *plug;
	r_list_foreach (core->fs->libstore->plugins, iter, plug) {
		if (pj) {
			pj_o (pj);
			r_lib_meta_pj (pj, &plug->meta);
			pj_end (pj);
		} else if (names) {
			r_cons_println (ctx->cons, plug->meta.name);
		} else {
			r_cons_printf (ctx->cons, "%10s  %s\n", plug->meta.name, plug->meta.desc);
		}
	}
	if (pj) {
		pj_end (pj);
		r_cons_println (ctx->cons, pj_string (pj));
		pj_free (pj);
	}
	return 0;
}

static int mount_umount(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	if (!r_fs_umount (core->fs, argv[0])) {
		R_LOG_ERROR ("Nothing to unmount");
		return 1;
	}
	return 0;
}

static int mount_details(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	RFSRoot *root = NULL;
	if (argv[0]) {
		RFSRoot *candidate;
		RListIter *iter;
		r_list_foreach (core->fs->roots, iter, candidate) {
			if (!strcmp (candidate->path, argv[0])) {
				root = candidate;
				break;
			}
		}
		if (!root) {
			R_LOG_ERROR ("Mountpoint '%s' not found", argv[0]);
			return 1;
		}
	} else {
		root = r_list_first (core->fs->roots);
		if (!root) {
			R_LOG_ERROR ("No filesystems mounted");
			return 1;
		}
	}
	if (!root->p->details) {
		R_LOG_ERROR ("Filesystem does not provide details information");
		return 1;
	}
	RStrBuf *sb = r_strbuf_new ("");
	root->p->details (root, sb);
	r_cons_print (ctx->cons, r_strbuf_get (sb));
	r_strbuf_free (sb);
	return 0;
}

static int mount_mkdir(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	char *path = *argv[0] == '/'? strdup (argv[0])
		: r_str_newf ("%s/%s", r_config_get (core->config, "fs.cwd"), argv[0]);
	if (!path) {
		return 1;
	}
	r_str_trim_path (path);
	bool ok = r_fs_mkdir (core->fs, *path? path: "/");
	free (path);
	if (!ok) {
		R_LOG_ERROR ("Cannot create directory");
	}
	return ok? 0: 1;
}

static int mount_partitions(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	if (!argv[0]) {
		int i;
		for (i = 0;; i++) {
			const char *name = r_fs_partition_type_get (i);
			if (!name) {
				break;
			}
			r_cons_println (ctx->cons, name);
		}
		return 0;
	}
	ut64 off = argv[1]? r_num_math (core->num, argv[1]): 0;
	RList *list = r_fs_partitions (core->fs, argv[0], off);
	if (!list) {
		R_LOG_ERROR ("Cannot read partition");
		return 1;
	}
	RListIter *iter;
	RFSPartition *part;
	r_list_foreach (list, iter, part) {
		r_cons_printf (ctx->cons, "%d %02x 0x%010" PFMT64x " 0x%010" PFMT64x "\n",
			part->number, part->type, part->start, part->start + part->length);
	}
	r_list_free (list);
	return 0;
}

static void mount_print_paths_and_free(RCmdContext *ctx, RList *R_OWNED list, bool escape) {
	RListIter *iter;
	char *path;
	r_list_foreach (list, iter, path) {
		char *escaped = escape? mount_escape_name (path): NULL;
		char *name = escaped? escaped: path;
		r_str_trim_path (name);
		r_cons_println (ctx->cons, name);
		free (escaped);
	}
	r_list_free (list);
}

static int mount_info(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	const char *path = argv[0];
	const char mode = r_cmd_ctx_mode (ctx, "sx");
	if (mode == 'x' || (!mode && (r_str_isnumber (path) || r_str_startswith (path, "0x")))) {
		ut64 off = r_num_math (core->num, path);
		const char *cwd = r_config_get (core->config, "fs.cwd");
		int old_view = core->fs->view;
		if (mode == 'x') {
			r_fs_view (core->fs, R_FS_VIEW_DELETED);
		}
		RList *list = mount_find_off (core, cwd, off);
		r_fs_view (core->fs, old_view);
		mount_print_paths_and_free (ctx, list, mode == 'x');
		return 0;
	}
	RFSFile *file = r_fs_open (core->fs, path, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open file");
		return 1;
	}
	if (mode == 's') {
		r_core_seek (core, file->off, true);
	}
	r_cons_printf (ctx->cons, "'f file %u 0x%08" PFMT64x "\n", file->size, file->off);
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return 0;
}

static int mount_find(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	RList *list = r_cmd_ctx_mode (ctx, "no") == 'n'
		? r_fs_find_name (core->fs, argv[0], argv[1])
		: r_fs_find_off (core->fs, argv[0], r_num_math (core->num, argv[1]));
	mount_print_paths_and_free (ctx, list, false);
	return 0;
}

static int mount_open(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	RFSFile *file = mount_read_file (core, argv[0]);
	if (!file) {
		return 1;
	}
	int rc = 1;
	if (file->size) {
		char *uri = r_str_newf ("malloc://%u", file->size);
		RIODesc *fd = r_io_open (core->io, uri, R_PERM_RW, 0);
		free (uri);
		if (fd) {
			if (r_io_desc_write (fd, file->data, file->size) == file->size) {
				// Load and raise the new binfile so its config and seek become active.
				r_core_cmdf (core, "oba 0;obo %d", fd->fd);
				rc = 0;
			} else {
				r_io_desc_close (fd);
			}
		}
	}
	if (rc) {
		R_LOG_ERROR ("Cannot open %s into malloc://", argv[0]);
	}
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return rc;
}

static int mount_write(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	const bool from_file = r_strs_equals_str (ctx->subcmd, "wf");
	const char *path = argv[from_file? 1: 0];
	char *buffer = NULL;
	const char *data = argv[1]? argv[1]: "";
	RStrs *arg = RVecRStrs_at (&ctx->args, 1);
	size_t size = arg? r_strs_len (*arg): 0;
	if (from_file) {
		data = buffer = r_file_slurp (argv[0], &size);
		if (!buffer) {
			R_LOG_ERROR ("Cannot read %s", argv[0]);
			return 1;
		}
	}
	bool ok = false;
	if (size <= INT_MAX) {
		RFSFile *file = r_fs_open (core->fs, path, true);
		if (file) {
			ok = r_fs_write (core->fs, file, 0, (const ut8 *)data, size) == size;
			r_fs_close (core->fs, file);
			r_fs_file_free (file);
		}
	}
	free (buffer);
	if (!ok) {
		R_LOG_ERROR ("Cannot write");
	}
	return ok? 0: 1;
}

static int mount_yank(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	RFSFile *file = mount_read_file (core, argv[0]);
	if (!file) {
		return 1;
	}
	bool ok = r_core_yank_set (core, 0, file->data, file->size);
	if (!ok) {
		R_LOG_ERROR ("Cannot yank %s", argv[0]);
	}
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return ok? 0: 1;
}

static int mount_shell(RCmdContext *ctx, const char **argv) {
	RCore *core = ctx->user;
	if (!r_config_get_b (core->config, "scr.interactive")) {
		R_LOG_ERROR ("mount shell requires scr.interactive");
		return 1;
	}
	if (core->http_up) {
		return 0;
	}
	r_cons_set_raw (ctx->cons, false);
	free (core->rfs->cwd);
	core->rfs->cons = ctx->cons;
	core->rfs->cwd = strdup (r_config_get (core->config, "fs.cwd"));
	core->rfs->set_prompt = r_line_set_prompt;
	core->rfs->readline = r_line_readline;
	core->rfs->hist_add = r_line_hist_add;
	core->autocomplete_type = AUTOCOMPLETE_MS;
	r_core_autocomplete_reload (core);
	r_fs_shell (core->rfs, core->fs, argv[0]? argv[0]: "");
	core->autocomplete_type = AUTOCOMPLETE_DEFAULT;
	r_core_autocomplete_reload (core);
	r_config_set (core->config, "fs.cwd", core->rfs->cwd);
	return 0;
}

static int mount_host_mkdir(RCmdContext *ctx, const char **argv) {
	const bool parents = !strcmp (argv[0], "-p");
	const char *path = argv[parents? 1: 0];
	bool ok = false;
	if (path && *path && (parents || !argv[1])) {
		ok = r_sys_mkdirp (path) && r_file_is_directory (path);
		if (!ok) {
			R_LOG_ERROR ("Cannot create '%s'", path);
		}
	} else {
		R_LOG_INFO ("Usage: mkdir [-p] [directory]");
	}
	return ok? 0: 1;
}

static int mount_host_mktemp(RCmdContext *ctx, const char **argv) {
	const bool dir = !strcmp (argv[0], "-d");
	const char *path = argv[dir? 1: 0];
	if (R_STR_ISEMPTY (path) || (!dir && argv[1])) {
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

static int mount_host_mv(RCmdContext *ctx, const char **argv) {
	bool ok = r_file_move (argv[0], argv[1]);
	if (!ok) {
		R_LOG_ERROR ("Cannot move file");
	}
	return ok? 0: 1;
}

static int mount_help(RCmdContext *ctx) {
	RStrs sub = ctx->subcmd;
	if (r_strs_lastch (sub) == '?') {
		sub.b--;
	}
	if (r_strs_equals_str (sub, "mc")) {
		return cmd_mmc (ctx, NULL);
	}
	if (r_strs_equals_str (sub, "f")) {
		r_cons_cmd_help (ctx->cons, help_msg_mf);
	} else if (r_strs_equals_str (sub, ":")) {
		r_cons_cmd_help (ctx->cons, help_msg_mcolon);
	} else if (r_strs_empty (sub)) {
		r_cons_cmd_help (ctx->cons, help_msg_m);
	} else {
		char *name = r_str_newf ("m%.*s", (int)r_strs_len (sub), sub.a);
		bool exact = !r_strs_equals_str (sub, "d") && !r_strs_equals_str (sub, "w");
		if (!r_cons_cmd_help_match (ctx->cons, help_msg_m, name, 0, exact)) {
			r_cons_cmd_help (ctx->cons, help_msg_m);
		}
		free (name);
	}
	return 0;
}

static int mount_dispatch(RCmdContext *ctx) {
	const size_t argc = RVecRStrs_length (&ctx->args);
	const RStrs sub = ctx->subcmd;
	RCore *core = ctx->user;
	if (r_strs_startswith (sub, ":") && !r_strs_equals_str (sub, ":?")) {
		if (!argc && (r_strs_equals_str (sub, ":") || r_strs_equals_str (sub, ":l"))) {
			return mount_plugins (ctx, NULL);
		}
		// Filesystem plugins interpret their own command language.
		r_fs_cmd (core->fs, r_str_trim_head_ro (sub.a + 1));
		return 0;
	}
	if (r_cmd_ctx_help (ctx)) {
		return mount_help (ctx);
	}
	if (r_strs_equals_str (sub, "ake")) {
		// Pass shell syntax through to make.
		return r_sys_cmdf ("make%s", sub.b);
	}
	if (r_strs_startswith (sub, "-/") && !argc) {
		const char *argv[] = { sub.a + 1 };
		return mount_umount (ctx, argv);
	}
	static const struct {
		const char *name;
		int (*callback)(RCmdContext *ctx, const char **argv);
		size_t min_args;
		size_t max_args;
		const char *usage;
	} commands[] = {
		{ "", mount_list, 0, 4, "m [mountpoint] [fstype] [offset] [options]" },
		{ "*", mount_list, 0, 0, "m*" },
		{ "j", mount_list, 0, 0, "mj" },
		{ "-", mount_umount, 1, 1, "m- [mountpoint]" },
		{ "L", mount_plugins, 0, 0, "mL" },
		{ "LL", mount_plugins, 0, 0, "mLL" },
		{ "Lj", mount_plugins, 0, 0, "mLj" },
		{ "c", mount_cat, 1, 1, "mc [filename]" },
		{ "g", mount_get, 1, 3, "mg [filename] [offset [size]]" },
		{ "n", mount_details, 0, 1, "mn [mountpoint]" },
		{ "d", mount_ls, 0, 1, "md [path]" },
		{ "dj", mount_ls, 0, 1, "mdj [path]" },
		{ "dd", mount_ls, 0, 1, "mdd [path]" },
		{ "dq", mount_ls, 0, 1, "mdq [path]" },
		{ "dx", mount_ls, 0, 1, "mdx [path]" },
		{ "ddx", mount_ls, 0, 1, "mddx [path]" },
		{ "ddq", mount_ls, 0, 1, "mddq [path]" },
		{ "dxq", mount_ls, 0, 1, "mdxq [path]" },
		{ "ddxq", mount_ls, 0, 1, "mddxq [path]" },
		{ "d+", mount_mkdir, 1, 1, "md+ /path" },
		{ "p", mount_partitions, 0, 2, "mp [type] [offset]" },
		{ "i", mount_info, 1, 1, "mi [path|offset]" },
		{ "is", mount_info, 1, 1, "mis [path]" },
		{ "ix", mount_info, 1, 1, "mix 0xOFFSET" },
		{ "fn", mount_find, 2, 2, "mfn [path] [pattern]" },
		{ "fo", mount_find, 2, 2, "mfo [path] [offset]" },
		{ "o", mount_open, 1, 1, "mo [path]" },
		{ "w", mount_write, 1, 2, "mw [file] [data]" },
		{ "wf", mount_write, 2, 2, "mwf [diskfile] [r2filepath]" },
		{ "y", mount_yank, 1, 1, "my [file]" },
		{ "s", mount_shell, 0, 1, "ms [path]" },
		{ "mc", cmd_mmc, 0, 2, "mmc [left_path] [right_path]" },
		{ "kdir", mount_host_mkdir, 1, 2, "mkdir [-p] [directory]" },
		{ "ktemp", mount_host_mktemp, 1, 2, "mktemp [-d] [file|directory]" },
		{ "v", mount_host_mv, 2, 2, "mv [src] [dst]" },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (commands); i++) {
		if (!r_strs_equals_str (sub, commands[i].name)) {
			continue;
		}
		if (argc < commands[i].min_args || argc > commands[i].max_args) {
			R_LOG_ERROR ("Usage: %s", commands[i].usage);
			return 1;
		}
		// FS APIs take C strings; context arguments are length-delimited slices.
		const char *argv[5] = { 0 };
		size_t j;
		int rc = 1;
		for (j = 0; j < argc; j++) {
			argv[j] = r_strs_tostring (*RVecRStrs_at (&ctx->args, j));
			if (!argv[j]) {
				break;
			}
		}
		if (j == argc) {
			if (argc && !*argv[0]) {
				R_LOG_ERROR ("Usage: %s", commands[i].usage);
			} else {
				rc = commands[i].callback (ctx, argv);
			}
		}
		for (j = 0; j < argc; j++) {
			free ((char *)argv[j]);
		}
		return rc;
	}
	if (r_strs_at (sub, 0) == 'c' || r_strs_at (sub, 0) == 'g') {
		R_LOG_ERROR ("Usage: %s", r_strs_at (sub, 0) == 'c'
			? "mc [filename]": "mg [filename] [offset [size]]");
	} else {
		r_core_return_invalid_command (core, "m", r_strs_at (sub, 0));
	}
	return 1;
}

static RCmdResult mount_callback(RCmdContext *ctx) {
	RCore *core = ctx->user;
	int rc = mount_dispatch (ctx);
	char sub = r_strs_at (ctx->subcmd, 0);
	if (sub == 'c' || sub == 'g' || sub == '-'
			|| sub == 'o' || sub == 'y'
			|| r_strs_equals_str (ctx->subcmd, "d+")
			|| r_strs_equals_str (ctx->subcmd, "kdir")
			|| r_strs_equals_str (ctx->subcmd, "ktemp")
			|| r_strs_equals_str (ctx->subcmd, "v")) {
		r_core_return_value (core, rc);
	}
	return (RCmdResult) { .status = rc };
}

static bool r_core_cmd_mount_init(RCmd *cmd) {
	return r_cmd_register (cmd, "m", mount_callback, NULL);
}

#endif
