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

static bool mount_ls(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const bool isJSON = r_cmdctx_mode (ctx, "j") == 'j';
	const bool minus_ele = r_strs_at (ctx->subcmd, 1) == 'd';
	const bool deleted_only = r_strs_findc (ctx->subcmd, 'x') != NULL;
	const bool minus_quiet = r_cmdctx_mode (ctx, "q") == 'q';
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	const char *input = r_cmdctx_arg (ctx, 0).a;
	input = input? input: "";
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
	bool ok = list || strlen (input) <= 1;
	r_list_foreach (list, iter, file) {
		bool is_deleted = deleted_only && file->name && (ut8)file->name[0] == 0xe5;
		if (deleted_only && !is_deleted) {
			continue;
		}
		if (isJSON) {
			pj_o (pj);
			pj_ks (pj, "type", is_deleted? "deleted": mount_file_type (file->type));
			pj_kn (pj, "size", file->size);
			pj_ks (pj, "name", file->name);
			pj_end (pj);
		} else {
			char ftype = is_deleted? R_FS_FILE_TYPE_DELETED: file->type;
			char *escaped = is_deleted? mount_escape_name (file->name): NULL;
			const char *name = escaped? escaped: file->name;
			if (minus_quiet) {
				r_cons_printf (ctx->cons, "%s%s\n", name, ftype == 'd'? "/": "");
			} else if (minus_ele) {
				r_cons_printf (ctx->cons, "%c %10u %s\n", ftype, file->size, name);
			} else {
				r_cons_printf (ctx->cons, "%c %s\n", ftype, name);
			}
			free (escaped);
		}
	}
	r_list_free (list);
	const char *path = *input? input: "/";
	r_list_foreach (core->fs->roots, iter, root) {
		const char *slash = r_str_lchr (root->path, '/');
		if (!slash || !r_strs_equals_str (r_strs_new (root->path, slash + 1), path)) {
			continue;
		}
		ok = true;
		if (isJSON) {
			pj_o (pj);
			pj_ks (pj, "path", root->path);
			pj_kn (pj, "delta", root->delta);
			pj_ks (pj, "type", root->p->meta.name);
			pj_end (pj);
		} else {
			r_cons_printf (ctx->cons, "m %s\n", root->path);
		}
	}
	if (!ok) {
		R_LOG_ERROR ("Invalid path");
	}
	if (isJSON) {
		pj_end (pj);
		r_cons_printf (ctx->cons, "%s\n", pj_string (pj));
		pj_free (pj);
	}
	free (decoded);
	return ok;
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

static bool mount_cat(RCmdContext *ctx) {
	RCore *core = ctx->user;
	RFSFile *file = mount_read_file (core, r_cmdctx_arg (ctx, 0).a);
	if (!file) {
		return false;
	}
	if (file->size) {
		r_cons_write (ctx->cons, (const char *)file->data, file->size);
	}
	r_cons_newline (ctx->cons);
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return true;
}

static bool mount_get(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const size_t argc = r_cmdctx_argc (ctx);
	ut64 range[2] = { 0, 0 };
	char *decoded = NULL;
	bool ok = false;
	size_t i;
	for (i = 1; i < argc; i++) {
		const char *err = NULL;
		range[i - 1] = r_num_math_err (core->num, r_cmdctx_arg (ctx, i).a, &err);
		if (err || core->num->dbz || (st64)range[i - 1] < 0) {
			R_LOG_ERROR ("Invalid offset or size");
			goto beach;
		}
	}
	const char *filename = r_cmdctx_arg (ctx, 0).a;
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
	return ok;
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

static bool mount_add(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *path = r_cmdctx_arg (ctx, 0).a;
	const char *type = r_cmdctx_arg (ctx, 1).a;
	ut64 off = 0;
	const char *options = r_cmdctx_arg (ctx, 2).a;
	if (options && mount_arg_is_offset (options)) {
		const char *err = NULL;
		off = r_num_math_err (core->num, options, &err);
		if (err || core->num->dbz || (st64)off < 0) {
			R_LOG_ERROR ("Invalid mount offset");
			return false;
		}
		options = r_cmdctx_arg (ctx, 3).a;
	} else if (r_cmdctx_arg (ctx, 3).a) {
		R_LOG_ERROR ("Usage: m [mountpoint] [fstype] [offset] [options]");
		return false;
	}
	if (type && *path != '/') {
		path = r_cmdctx_arg (ctx, 1).a;
		type = r_cmdctx_arg (ctx, 0).a;
	}
	if (*path != '/') {
		R_LOG_ERROR ("Invalid mountpoint");
		return false;
	}
	char *detected = NULL;
	if (!type) {
		type = detected = r_fs_name (core->fs, core->addr);
		off = core->addr;
		if (!type) {
			R_LOG_ERROR ("Unknown filesystem type");
			return false;
		}
	}
	bool ok = r_fs_mount_with_options (core->fs, type, path, off, options);
	if (!ok) {
		R_LOG_ERROR ("Cannot mount %s at %s (offset 0x%"PFMT64x")", type, path, off);
	}
	free (detected);
	return ok;
}

static bool mount_list(RCmdContext *ctx) {
	if (r_cmdctx_arg (ctx, 0).a) {
		return mount_add (ctx);
	}
	RCore *core = ctx->user;
	RListIter *iter;
	RFSRoot *root;
	const char mode = r_cmdctx_mode (ctx, "j*");
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
	return true;
}

static bool mount_plugins(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char mode = r_cmdctx_mode (ctx, "jL");
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
	return true;
}

static bool mount_umount(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *path = r_strs_startswith (ctx->subcmd, "-/")? ctx->subcmd.a + 1: r_cmdctx_arg (ctx, 0).a;
	if (!r_fs_umount (core->fs, path)) {
		R_LOG_ERROR ("Nothing to unmount");
		return false;
	}
	return true;
}

static bool mount_details(RCmdContext *ctx) {
	RCore *core = ctx->user;
	RFSRoot *root = NULL;
	if (r_cmdctx_arg (ctx, 0).a) {
		RFSRoot *candidate;
		RListIter *iter;
		r_list_foreach (core->fs->roots, iter, candidate) {
			if (!strcmp (candidate->path, r_cmdctx_arg (ctx, 0).a)) {
				root = candidate;
				break;
			}
		}
		if (!root) {
			R_LOG_ERROR ("Mountpoint '%s' not found", r_cmdctx_arg (ctx, 0).a);
			return false;
		}
	} else {
		root = r_list_first (core->fs->roots);
		if (!root) {
			R_LOG_ERROR ("No filesystems mounted");
			return false;
		}
	}
	if (!root->p->details) {
		R_LOG_ERROR ("Filesystem does not provide details information");
		return false;
	}
	RStrBuf *sb = r_strbuf_new ("");
	root->p->details (root, sb);
	r_cons_print (ctx->cons, r_strbuf_get (sb));
	r_strbuf_free (sb);
	return true;
}

static bool mount_mkdir(RCmdContext *ctx) {
	RCore *core = ctx->user;
	char *path = *r_cmdctx_arg (ctx, 0).a == '/'? strdup (r_cmdctx_arg (ctx, 0).a)
		: r_str_newf ("%s/%s", r_config_get (core->config, "fs.cwd"), r_cmdctx_arg (ctx, 0).a);
	if (!path) {
		return false;
	}
	r_str_trim_path (path);
	bool ok = r_fs_mkdir (core->fs, *path? path: "/");
	free (path);
	if (!ok) {
		R_LOG_ERROR ("Cannot create directory");
	}
	return ok;
}

static bool mount_partitions(RCmdContext *ctx) {
	RCore *core = ctx->user;
	if (!r_cmdctx_arg (ctx, 0).a) {
		int i;
		for (i = 0;; i++) {
			const char *name = r_fs_partition_type_get (i);
			if (!name) {
				break;
			}
			r_cons_println (ctx->cons, name);
		}
		return true;
	}
	ut64 off = r_cmdctx_arg (ctx, 1).a? r_num_math (core->num, r_cmdctx_arg (ctx, 1).a): 0;
	RList *list = r_fs_partitions (core->fs, r_cmdctx_arg (ctx, 0).a, off);
	if (!list) {
		R_LOG_ERROR ("Cannot read partition");
		return false;
	}
	RListIter *iter;
	RFSPartition *part;
	r_list_foreach (list, iter, part) {
		r_cons_printf (ctx->cons, "%d %02x 0x%010" PFMT64x " 0x%010" PFMT64x "\n",
			part->number, part->type, part->start, part->start + part->length);
	}
	r_list_free (list);
	return true;
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

static bool mount_info(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *path = r_cmdctx_arg (ctx, 0).a;
	const char mode = r_cmdctx_mode (ctx, "sx");
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
		return true;
	}
	RFSFile *file = r_fs_open (core->fs, path, false);
	if (!file) {
		R_LOG_ERROR ("Cannot open file");
		return false;
	}
	if (mode == 's') {
		r_core_seek (core, file->off, true);
	}
	r_cons_printf (ctx->cons, "'f file %u 0x%08" PFMT64x "\n", file->size, file->off);
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return true;
}

static bool mount_find(RCmdContext *ctx) {
	RCore *core = ctx->user;
	RList *list = r_cmdctx_mode (ctx, "no") == 'n'
		? r_fs_find_name (core->fs, r_cmdctx_arg (ctx, 0).a, r_cmdctx_arg (ctx, 1).a)
		: r_fs_find_off (core->fs, r_cmdctx_arg (ctx, 0).a, r_num_math (core->num, r_cmdctx_arg (ctx, 1).a));
	mount_print_paths_and_free (ctx, list, false);
	return true;
}

static bool mount_open(RCmdContext *ctx) {
	RCore *core = ctx->user;
	RFSFile *file = mount_read_file (core, r_cmdctx_arg (ctx, 0).a);
	if (!file) {
		return false;
	}
	bool ok = false;
	if (file->size) {
		char *uri = r_str_newf ("malloc://%u", file->size);
		RIODesc *fd = r_io_open (core->io, uri, R_PERM_RW, 0);
		free (uri);
		if (fd) {
			if (r_io_desc_write (fd, file->data, file->size) == file->size) {
				// Load and raise the new binfile so its config and seek become active.
				r_core_cmdf (core, "oba 0;obo %d", fd->fd);
				ok = true;
			} else {
				r_io_desc_close (fd);
			}
		}
	}
	if (!ok) {
		R_LOG_ERROR ("Cannot open %s into malloc://", r_cmdctx_arg (ctx, 0).a);
	}
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return ok;
}

static bool mount_write(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const bool from_file = r_strs_equals_str (ctx->subcmd, "wf");
	const char *path = r_cmdctx_arg (ctx, from_file? 1: 0).a;
	char *buffer = NULL;
	RStrs arg = r_cmdctx_arg (ctx, 1);
	const char *data = arg.a? arg.a: "";
	size_t size = arg.a? r_strs_len (arg): 0;
	if (from_file) {
		data = buffer = r_file_slurp (r_cmdctx_arg (ctx, 0).a, &size);
		if (!buffer) {
			R_LOG_ERROR ("Cannot read %s", r_cmdctx_arg (ctx, 0).a);
			return false;
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
	return ok;
}

static bool mount_yank(RCmdContext *ctx) {
	RCore *core = ctx->user;
	RFSFile *file = mount_read_file (core, r_cmdctx_arg (ctx, 0).a);
	if (!file) {
		return false;
	}
	bool ok = r_core_yank_set (core, 0, file->data, file->size);
	if (!ok) {
		R_LOG_ERROR ("Cannot yank %s", r_cmdctx_arg (ctx, 0).a);
	}
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return ok;
}

static bool mount_shell(RCmdContext *ctx) {
	RCore *core = ctx->user;
	if (!r_config_get_b (core->config, "scr.interactive")) {
		R_LOG_ERROR ("mount shell requires scr.interactive");
		return false;
	}
	if (core->http_up) {
		return true;
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
	const char *path = r_cmdctx_arg (ctx, 0).a;
	r_fs_shell (core->rfs, core->fs, path? path: "");
	core->autocomplete_type = AUTOCOMPLETE_DEFAULT;
	r_core_autocomplete_reload (core);
	r_config_set (core->config, "fs.cwd", core->rfs->cwd);
	return true;
}

static bool mount_mmc(RCmdContext *ctx) {
	return cmd_mmc (ctx) == 0;
}

static bool mount_help(RCmdContext *ctx) {
	RStrs sub = ctx->subcmd;
	if (r_strs_lastch (sub) == '?') {
		sub.b--;
	}
	if (r_strs_equals_str (sub, "mc")) {
		return cmd_mmc (ctx) == 0;
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
	return true;
}

static int mount_dispatch(RCmdContext *ctx) {
	const size_t argc = r_cmdctx_argc (ctx);
	const RStrs sub = ctx->subcmd;
	RCore *core = ctx->user;
	if (r_strs_startswith (sub, ":") && !r_strs_equals_str (sub, ":?")) {
		if (!argc && (r_strs_equals_str (sub, ":") || r_strs_equals_str (sub, ":l"))) {
			return mount_plugins (ctx)? 0: 1;
		}
		// Filesystem plugins interpret their own command language.
		return r_fs_cmd (core->fs, r_str_trim_head_ro (sub.a + 1))? 0: 1;
	}
	if (r_cmdctx_help (ctx)) {
		return mount_help (ctx)? 0: 1;
	}
	if (r_strs_startswith (sub, "-/") && !argc) {
		return mount_umount (ctx)? 0: 1;
	}
	static const struct {
		const char *name;
		bool (*callback)(RCmdContext *ctx);
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
		{ "mc", mount_mmc, 0, 2, "mmc [left_path] [right_path]" },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (commands); i++) {
		if (!r_strs_equals_str (sub, commands[i].name)) {
			continue;
		}
		if (argc < commands[i].min_args || argc > commands[i].max_args
				|| (argc && !*r_cmdctx_arg (ctx, 0).a)) {
			R_LOG_ERROR ("Usage: %s", commands[i].usage);
			return 1;
		}
		return commands[i].callback (ctx)? 0: 1;
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
	r_core_return_value (core, rc);
	return (RCmdResult) { .status = rc };
}

static bool r_core_cmd_mount_init(RCmd *cmd) {
	return r_cmd_register (cmd, "m", mount_callback, NULL);
}

#endif
