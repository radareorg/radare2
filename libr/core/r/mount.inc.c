/* radare - LGPL - Copyright 2009-2026 - pancake */

#if R_INCLUDE_BEGIN

#include "../cmd_mmc.inc.c"

static RCoreHelpMessage help_msg_m = {
	"Usage:", "m[-?*dgy] [...] ", "Mountpoints management",
	"m", " /mnt ext2 0", "mount ext2 fs at /mnt with delta 0 on IO",
	"m", " /mnt tmp 0 options", "use an explicit offset before arbitrary plugin options",
	"m", " /mnt 9fs tcp:127.0.0.1:9999", "mount fs with plugin options",
	"m", " /mnt", "mount fs at /mnt with autodetect fs and current offset",
	"m", "", "list all mountpoints in human readable format",
	"m*", "", "same as above, but in r2 commands",
	"m-", " /", "umount given path (also m-/)",
	"mL", "[Lj]", "list filesystem plugins (Same as Lm), mLL shows only fs plugin names",
	"mc", " [file]", "cat: Show the contents of the given file",
	"md", " /", "list files and directory on the virtual r2's fs",
	"mdt", " [path] [depth]", "show a directory tree (scr.utf8; default depth: 64)",
	"mdd", " /", "show file size like `ls -l` in ms",
	"mdx", " /", "list deleted files (FAT)",
	"mdq", " /", "show just the file name (quiet)",
	"mf", "[?] [o|n]", "search files for given filename or for offset",
	"mg", " /foo [offset [size]]", "dump file to disk; size 0 reads to EOF (supports base64:)",
	"mg", " /directory", "recursively dump a directory into the current directory",
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

typedef struct {
	const char *name;
	bool (*run)(RCmdContext *ctx);
	const char *usage;
	size_t min_args;
	size_t max_args;
	RCmdArgFlags flags;
} MountCommand;

static char *mount_path(RCmdContext *ctx) {
	const char *path = r_cmdctx_arg (ctx, 0).a;
	if (!path || !r_str_startswith (path, "base64:")) {
		return strdup (path? path: "");
	}
	int length = 0;
	char *decoded = (char *)sdb_decode (path + 7, &length);
	if (!decoded || length < 1 || memchr (decoded, 0, length)) {
		R_LOG_ERROR ("Invalid base64 filename");
		free (decoded);
		return NULL;
	}
	return decoded;
}

static bool mount_ls(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const MountCommand *command = ctx->handler_user;
	const char *modes = command->name + 2;
	const bool is_json = strchr (modes, 'j');
	const bool long_format = strchr (modes, 'd');
	const bool deleted_only = strchr (modes, 'x');
	const bool quiet = strchr (modes, 'q');
	RListIter *iter;
	RFSFile *file;
	RFSRoot *root;
	char *input = mount_path (ctx);
	if (!input) {
		return false;
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
	if (is_json) {
		pj = r_core_pj_new (core);
		pj_a (pj);
	}
	bool ok = list || strlen (input) <= 1;
	r_list_foreach (list, iter, file) {
		bool is_deleted = deleted_only && (ut8)file->name[0] == 0xe5;
		if (deleted_only && !is_deleted) {
			continue;
		}
		if (pj) {
			pj_o (pj);
			pj_ks (pj, "type", is_deleted? "deleted": mount_file_type (file->type));
			pj_kn (pj, "size", file->size);
			pj_ks (pj, "name", file->name);
			pj_end (pj);
		} else {
			char ftype = is_deleted? R_FS_FILE_TYPE_DELETED: file->type;
			char *escaped = is_deleted? r_str_escape_utf8_keep_printable (file->name, false, true): NULL;
			const char *name = escaped? escaped: file->name;
			if (quiet) {
				r_cons_printf (ctx->cons, "%s%s\n", name, ftype == 'd'? "/": "");
			} else if (long_format) {
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
		if (pj) {
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
	if (pj) {
		pj_end (pj);
		r_cons_printf (ctx->cons, "%s\n", pj_string (pj));
		pj_free (pj);
	}
	free (input);
	return ok;
}

static int mount_tree_file_cmp(const void *a, const void *b) {
	const RFSFile *fa = a;
	const RFSFile *fb = b;
	return strcmp (fa->name, fb->name);
}

static RList *mount_tree_dir(RCore *core, RFSRoot *root, const char *path) {
	RList *list = root? root->p->dir (root, path, core->fs->view): r_fs_dir (core->fs, path);
	if (!root && !strcmp (path, "/")) {
		if (!list) {
			list = r_list_newf ((RListFree)r_fs_file_free);
		}
		RListIter *iter;
		RFSRoot *mount;
		r_list_foreach (core->fs->roots, iter, mount) {
			if (!strcmp (mount->path, "/")) {
				continue;
			}
			RFSFile *file = r_fs_file_new (NULL, mount->path + 1);
			file->type = R_FS_FILE_TYPE_MOUNTPOINT;
			r_list_append (list, file);
		}
	}
	if (!list) {
		return NULL;
	}
	RListIter *iter, *next;
	RFSFile *file;
	r_list_foreach_safe (list, iter, next, file) {
		if (R_STR_ISEMPTY (file->name) || !strcmp (file->name, ".") || !strcmp (file->name, "..")
			|| strchr (file->name, '/') || strchr (file->name, '\\')) {
			r_list_delete (list, iter);
		}
	}
	r_list_sort (list, mount_tree_file_cmp);
	return list;
}

static bool mount_tree_collect(RCore *core, RFSRoot *root, const char *path, int depth, RList *list, RTreeNode *parent) {
	bool ok = true;
	RListIter *iter;
	RFSFile *file;
	r_list_foreach (list, iter, file) {
		if (r_cons_is_breaked (core->cons)) {
			return false;
		}
		bool directory = file->type == R_FS_FILE_TYPE_DIRECTORY || file->type == R_FS_FILE_TYPE_MOUNTPOINT;
		char *escaped = r_str_escape_utf8_keep_printable (file->name, false, true);
		char *name = escaped? r_str_newf ("%s%s", escaped, directory? "/": ""): NULL;
		free (escaped);
		if (!name) {
			return false;
		}
		RTreeNode *node = r_tree_add_node (parent->tree, parent, name);
		if (!node) {
			free (name);
			return false;
		}
		node->free = free;
		if (!directory || depth <= 1) {
			continue;
		}
		char *child = r_str_newf ("%s/%s", !strcmp (path, "/")? "": path, file->name);
		if (!child) {
			return false;
		}
		RList *children = mount_tree_dir (core, root, child);
		if (children) {
			ok &= mount_tree_collect (core, root, child, depth - 1, children, node);
		} else {
			ok = false;
		}
		r_list_free (children);
		free (child);
	}
	return ok;
}

static bool core_fs_tree(RCore *core, RFSRoot *root, const char *path, int depth) {
	RList *list = mount_tree_dir (core, root, path);
	if (!list) {
		R_LOG_ERROR ("Invalid path");
		return false;
	}
	char *escaped = r_str_escape_utf8_keep_printable (path, false, true);
	if (!escaped) {
		r_list_free (list);
		return false;
	}
	RTree *tree = r_tree_new ();
	RTreeNode *node = r_tree_add_node (tree, NULL, escaped);
	node->free = free;
	r_cons_break_push (core->cons, NULL, NULL);
	bool ok = mount_tree_collect (core, root, path, depth, list, node);
	r_cons_break_pop (core->cons);
	char *text = r_tree_to_string (tree, NULL, NULL, r_config_get_b (core->config, "scr.utf8"));
	if (text) {
		r_cons_print (core->cons, text);
	} else {
		ok = false;
	}
	free (text);
	r_tree_free (tree);
	r_list_free (list);
	return ok;
}

static bool mount_tree(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 depth = 64;
	if (!r_cmdctx_num (ctx, 1, core->num, &depth) || depth < 1 || depth > 64) {
		R_LOG_ERROR ("Tree depth must be between 1 and 64");
		return false;
	}
	char *path = mount_path (ctx);
	if (!path) {
		return false;
	}
	r_str_trim_path (path);
	bool ok = core_fs_tree (core, NULL, *path? path: "/", depth);
	free (path);
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
	if (file->size > 0) {
		r_cons_write (ctx->cons, (const char *)file->data, file->size);
		r_cons_newline (ctx->cons);
	}
	r_fs_close (core->fs, file);
	r_fs_file_free (file);
	return true;
}

static bool mount_get(RCmdContext *ctx) {
	RCore *core = ctx->user;
	ut64 offset = 0, size = 0;
	if (!r_cmdctx_num (ctx, 1, core->num, &offset) || !r_cmdctx_num (ctx, 2, core->num, &size)
			|| offset > ST64_MAX || size > ST64_MAX) {
		R_LOG_ERROR ("Invalid offset or size");
		return false;
	}
	char *filename = mount_path (ctx);
	if (!filename) {
		return false;
	}
	bool ok = false;
	RFSFile *file = r_fs_open (core->fs, filename, false);
	if (!file) {
		// With only a directory path, dump its contents recursively into the current directory.
		ok = r_cmdctx_argc (ctx) == 1 && r_fs_dir_dump (core->fs, filename, "./");
	} else if (offset <= file->size) {
		const char *localfile = r_file_basename (filename);
		size = R_MIN (size? size: file->size, file->size - offset);
		const int chunk = R_CLAMP (ctx->blocksize, 1, INT_MAX);
		const bool cached = file->data != NULL;
		ok = r_file_dump (localfile, NULL, 0, false);
		while (ok && size > 0) {
			int len = R_MIN (size, chunk);
			int nread = cached? len: r_fs_read (core->fs, file, offset, len);
			ok = nread > 0 && nread <= len && file->data;
			if (ok) {
				const ut8 *data = file->data + (cached? offset: 0);
				ok = r_file_dump (localfile, data, nread, true);
				offset += nread;
				size -= nread;
			}
		}
	}
	if (file) {
		r_fs_close (core->fs, file);
		r_fs_file_free (file);
	}
	if (!ok) {
		R_LOG_ERROR ("Cannot dump %s", filename);
	}
	free (filename);
	return ok;
}

static bool mount_add(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *args[4];
	r_cmdctx_args (ctx, args, R_ARRAY_SIZE (args));
	const bool reversed = args[1] && *args[0] != '/';
	const char *path = args[reversed? 1: 0];
	const char *type = args[reversed? 0: 1];
	ut64 offset = type? 0: core->addr;
	const char *options = args[3];
	if (args[2]) {
		// Three-argument mounts may omit the offset when passing plugin options.
		const char *error = NULL;
		ut64 value = r_num_math_err (core->num, args[2], &error);
		if (!error && !core->num->dbz) {
			if (value > ST64_MAX) {
				R_LOG_ERROR ("Invalid mount offset");
				return false;
			}
			offset = value;
		} else if (!options && (strchr (args[2], '=') || strchr (args[2], ':'))) {
			options = args[2];
		} else {
			R_LOG_ERROR ("Invalid mount offset; use an explicit offset before plugin options");
			return false;
		}
	}
	return r_fs_mount_with_options (core->fs, type, path, offset, options) != NULL;
}

static bool mount_list(RCmdContext *ctx) {
	if (r_cmdctx_arg (ctx, 0).a) {
		return mount_add (ctx);
	}
	RCore *core = ctx->user;
	RListIter *iter;
	RFSRoot *root;
	const MountCommand *command = ctx->handler_user;
	const char mode = command->name[1];
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
	const MountCommand *command = ctx->handler_user;
	const char mode = command->name[strlen (command->name) - 1];
	const bool names = !strcmp (command->name, "mLL") || mode == ':';
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
	const char *path = r_cmdctx_arg (ctx, 0).a;
	if (!r_fs_umount (core->fs, path)) {
		R_LOG_ERROR ("Nothing to unmount");
		return false;
	}
	return true;
}

static bool mount_details(RCmdContext *ctx) {
	RCore *core = ctx->user;
	RFSRoot *root = NULL;
	const char *path = r_cmdctx_arg (ctx, 0).a;
	if (path) {
		RFSRoot *candidate;
		RListIter *iter;
		r_list_foreach (core->fs->roots, iter, candidate) {
			if (!strcmp (candidate->path, path)) {
				root = candidate;
				break;
			}
		}
		if (!root) {
			R_LOG_ERROR ("Mountpoint '%s' not found", path);
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
	const char *arg = r_cmdctx_arg (ctx, 0).a;
	char *path = *arg == '/'? strdup (arg): r_str_newf ("%s/%s", r_config_get (core->config, "fs.cwd"), arg);
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
	ut64 off = 0;
	if (!r_cmdctx_num (ctx, 1, core->num, &off)) {
		return false;
	}
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

static void mount_print_paths(RCmdContext *ctx, RList *R_OWNED list, bool escape) {
	RListIter *iter;
	char *path;
	r_list_foreach (list, iter, path) {
		char *escaped = escape? r_str_escape_utf8_keep_printable (path, false, true): NULL;
		r_cons_println (ctx->cons, escaped? escaped: path);
		free (escaped);
	}
	r_list_free (list);
}

static bool mount_info(RCmdContext *ctx) {
	RCore *core = ctx->user;
	const char *path = r_cmdctx_arg (ctx, 0).a;
	const MountCommand *command = ctx->handler_user;
	const char mode = command->name[2];
	if (mode == 'x' || (!mode && (r_str_isnumber (path) || r_str_startswith (path, "0x")))) {
		ut64 off = 0;
		if (!r_cmdctx_num (ctx, 0, core->num, &off)) {
			return false;
		}
		const char *cwd = r_config_get (core->config, "fs.cwd");
		int old_view = core->fs->view;
		if (mode == 'x') {
			r_fs_view (core->fs, R_FS_VIEW_DELETED);
		}
		RList *list = r_fs_find_off (core->fs, cwd, off);
		r_fs_view (core->fs, old_view);
		mount_print_paths (ctx, list, mode == 'x');
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
	const MountCommand *command = ctx->handler_user;
	const char *args[2];
	r_cmdctx_args (ctx, args, R_ARRAY_SIZE (args));
	ut64 offset = 0;
	const bool by_name = command->name[2] == 'n';
	if (!by_name && !r_cmdctx_num (ctx, 1, core->num, &offset)) {
		return false;
	}
	RList *list = by_name? r_fs_find_name (core->fs, args[0], args[1])
		: r_fs_find_off (core->fs, args[0], offset);
	mount_print_paths (ctx, list, false);
	return true;
}

static bool mount_open(RCmdContext *ctx) {
	RCore *core = ctx->user;
	RFSFile *file = mount_read_file (core, r_cmdctx_arg (ctx, 0).a);
	if (!file) {
		return false;
	}
	bool ok = false;
	if (file->size > 0) {
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
	const MountCommand *command = ctx->handler_user;
	const bool from_file = !strcmp (command->name, "mwf");
	const char *path = r_cmdctx_arg (ctx, from_file? 1: 0).a;
	char *buffer = NULL;
	RStrs arg = r_cmdctx_arg (ctx, 1);
	const char *data = arg.a? arg.a: "";
	size_t size = r_strs_len (arg);
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

static bool mount_command(RCmdContext *ctx) {
	RCore *core = ctx->user;
	RStrs input = r_strs_from (ctx->subcmd.b);
	r_strs_trim (&input);
	if (r_strs_empty (input) || r_strs_equals_str (input, "l")) {
		return mount_plugins (ctx);
	}
	return r_fs_cmd (core->fs, input.a);
}

static bool mount_help(RCmdContext *ctx) {
	const MountCommand *command = ctx->handler_user;
	if (!strcmp (command->name, "mmc")) {
		return cmd_mmc (ctx);
	}
	if (!strcmp (command->name, "mf")) {
		r_cons_cmd_help (ctx->cons, help_msg_mf);
	} else if (!strcmp (command->name, "m:")) {
		r_cons_cmd_help (ctx->cons, help_msg_mcolon);
	} else if (!strcmp (command->name, "m")) {
		r_cons_cmd_help (ctx->cons, help_msg_m);
	} else {
		bool exact = strcmp (command->name, "md") && strcmp (command->name, "mw");
		if (!r_cons_cmd_help_match (ctx->cons, help_msg_m, command->name, 0, exact)) {
			r_cons_cmd_help (ctx->cons, help_msg_m);
		}
	}
	return true;
}

static RCmdResult mount_callback(RCmdContext *ctx) {
	const MountCommand *command = ctx->handler_user;
	const size_t argc = r_cmdctx_argc (ctx);
	bool ok = false;
	if (r_cmdctx_help (ctx)) {
		ok = mount_help (ctx);
	} else if (!r_strs_empty (ctx->subcmd) || argc < command->min_args || argc > command->max_args
			|| (argc && !*r_cmdctx_arg (ctx, 0).a)) {
		R_LOG_ERROR ("Usage: %s", command->usage);
	} else {
		ok = command->run (ctx);
	}
	int rc = ok? 0: 1;
	RCore *core = ctx->user;
	r_core_return_value (core, rc);
	return (RCmdResult) { .status = rc };
}

static bool r_core_cmd_mount_init(RCmd *cmd) {
	static const MountCommand commands[] = {
		{ "m", mount_list, "m [mountpoint] [fstype] [offset] [options]", 0, 4, 0 },
		{ "m*", mount_list, "m*", 0, 0, 0 },
		{ "mj", mount_list, "mj", 0, 0, 0 },
		{ "m-", mount_umount, "m- [mountpoint]", 1, 1, R_CMD_ARGS_ATTACHED },
		{ "mL", mount_plugins, "mL", 0, 0, 0 },
		{ "mLL", mount_plugins, "mLL", 0, 0, 0 },
		{ "mLj", mount_plugins, "mLj", 0, 0, 0 },
		{ "mc", mount_cat, "mc [filename]", 1, 1, 0 },
		{ "mg", mount_get, "mg [filename] [offset [size]]", 1, 3, 0 },
		{ "mn", mount_details, "mn [mountpoint]", 0, 1, 0 },
		{ "md", mount_ls, "md [path]", 0, 1, 0 },
		{ "mdt", mount_tree, "mdt [path] [depth]", 0, 2, 0 },
		{ "mdj", mount_ls, "mdj [path]", 0, 1, 0 },
		{ "mdd", mount_ls, "mdd [path]", 0, 1, 0 },
		{ "mdq", mount_ls, "mdq [path]", 0, 1, 0 },
		{ "mdx", mount_ls, "mdx [path]", 0, 1, 0 },
		{ "mddx", mount_ls, "mddx [path]", 0, 1, 0 },
		{ "mddq", mount_ls, "mddq [path]", 0, 1, 0 },
		{ "mdxq", mount_ls, "mdxq [path]", 0, 1, 0 },
		{ "mddxq", mount_ls, "mddxq [path]", 0, 1, 0 },
		{ "md+", mount_mkdir, "md+ /path", 1, 1, 0 },
		{ "mp", mount_partitions, "mp [type] [offset]", 0, 2, 0 },
		{ "mi", mount_info, "mi [path|offset]", 1, 1, 0 },
		{ "mis", mount_info, "mis [path]", 1, 1, 0 },
		{ "mix", mount_info, "mix 0xOFFSET", 1, 1, 0 },
		{ "mfn", mount_find, "mfn [path] [pattern]", 2, 2, 0 },
		{ "mfo", mount_find, "mfo [path] [offset]", 2, 2, 0 },
		{ "mo", mount_open, "mo [path]", 1, 1, 0 },
		{ "mw", mount_write, "mw [file] [data]", 1, 2, 0 },
		{ "mwf", mount_write, "mwf [diskfile] [r2filepath]", 2, 2, 0 },
		{ "my", mount_yank, "my [file]", 1, 1, 0 },
		{ "ms", mount_shell, "ms [path]", 0, 1, 0 },
		{ "mmc", cmd_mmc, "mmc [left_path] [right_path]", 0, 2, 0 },
		{ "mf", mount_help, "mf[no] [path] [name|offset]", 0, 0, 0 },
		{ "m:", mount_command, "m:[plugin-command]", 0, 0, R_CMD_ARGS_ATTACHED | R_CMD_ARGS_VERBATIM },
	};
	size_t i;
	for (i = 0; i < R_ARRAY_SIZE (commands); i++) {
		const MountCommand *command = &commands[i];
		if (!r_cmd_register_args (cmd, command->name, mount_callback, (void *)command, command->flags)) {
			while (i > 0) {
				r_cmd_unregister (cmd, commands[--i].name);
			}
			return false;
		}
	}
	return true;
}

#endif
