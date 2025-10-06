/* radare2 - LGPL - Copyright 2018-2025 - pancake */

#define R_LOG_ORIGIN "fs.shell"

#include <r_fs.h>

static bool handlePipes(RFS *fs, char *msg, const ut8 *data, const char *cwd) {
	char *red = strchr (msg, '>');
	if (!red) {
		return false;
	}
	*red++ = 0;
	r_str_trim (msg);
	red = r_str_trim_dup (red);
	if (*red != '/') {
		char *blu = r_str_newf ("%s/%s", cwd, red);
		free (red);
		red = blu;
	}
	RFSFile *f = r_fs_open (fs, red, true);
	if (!f) {
		R_LOG_ERROR ("Cannot open %s for writing", red);
		free (red);
		return true;
	}
	r_fs_write (fs, f, 0, data? data: (ut8*)msg, strlen (data? (char*)data: msg));
	free (red);
	r_fs_close (fs, f);
	r_fs_file_free (f);
	return true;
}

static char *fs_abspath(RFSShell *shell, const char *input) {
	char *path = strdup (shell->cwd);
	if (path == NULL) {
		return NULL;
	}
	if (!strcmp (input, "..")) {
		char *p = (char*) r_str_lchr (path, '/');
		if (p) {
			p[(p == path)? 1: 0] = 0;
		}
	} else if (*input == '/') {
		// absolute path
		free (path);
		path = strdup (input);
	} else {
		char *npath = r_str_newf ("%s/%s", path, input);
		free (path);
		path = npath;
	}
	while (strstr (path, "//")) {
		path = r_str_replace (path, "//", "/", true);
	}
	return path;
}

static bool r_fs_shell_command(RFSShell *shell, RFS *fs, const char *buf) {
	RFSFile *file;
	RListIter *iter;
	RConsPrintfCallback cb_printf = fs->csb.cb_printf;
	RCons *cons = fs->csb.cons;
	if (*buf == ':') {
		char *msg = fs->cob.cmdStr (fs->cob.core, buf + 1);
		printf ("%s", msg);
		free (msg);
	} else if (*buf == '!') {
		r_sandbox_system (buf + 1, 1);
	} else if (r_str_startswith (buf, "echo")) {
		char *msg = r_str_trim_dup (buf + 4);
		if (!handlePipes (fs, msg, NULL, shell->cwd)) {
			cb_printf (cons, "%s\n", msg);
		}
		free (msg);
	} else if (r_str_startswith (buf, "getall")) {
		RList *list = r_fs_dir (fs, shell->cwd);
		r_list_foreach (list, iter, file) {
			if (file->type == 'f') {
				R_LOG_INFO ("Downloading: %s", file->name);
				char *cmd = r_str_newf ("get %s", file->name);
				r_fs_shell_command (shell, fs, cmd);
				free (cmd);
			} else {
				R_LOG_INFO ("Not a file: %s", file->name);
			}
		}
		r_list_free (list);
	} else if (r_str_startswith (buf, "ls")) {
		char *cwd = NULL;
		bool minus_ele = r_str_startswith (buf, "ls -l");
		if (minus_ele) {
			buf += 3;
		}
		if (buf[2] == ' ') {
			if (buf[3] == '/') {
				cwd = strdup (buf + 3);
			} else {
				cwd = r_str_newf ("%s/%s", shell->cwd, buf + 3);
			}
		} else {
			cwd = strdup (shell->cwd);
		}
		RList *list = r_fs_dir (fs, cwd);
		if (list) {
			r_list_foreach (list, iter, file) {
				if (minus_ele) {
					cb_printf (cons, "%c %8d %s\n", file->type, file->size, file->name);
				} else {
					cb_printf (cons, "%c %s\n", file->type, file->name);
				}
			}
		} else {
			if (strlen (cwd) > 1) {
				R_LOG_ERROR ("Invalid path");
			}
		}
		r_list_free (list);
		// mountpoints if any
		RFSRoot *r;
		r_list_foreach (fs->roots, iter, r) {
			char *base = strdup (r->path);
			char *ls = (char *)r_str_lchr (base, '/');
			if (ls) {
				ls++;
				*ls = 0;
			}
			if (r_str_startswith (base, shell->cwd)) {
				cb_printf (cons, "m %s\n", (r->path && r->path[0]) ? r->path + 1: "");
			}
			free (base);
		}
		free (cwd);
	} else if (r_str_startswith (buf, "pwd")) {
		cb_printf (cons, "%s\n", shell->cwd);
	} else if (r_str_startswith (buf, "cd ")) {
		const char *input = r_str_trim_head_ro (buf + 3);
		char *abspath = fs_abspath (shell, input);
		free (shell->cwd);
		shell->cwd = abspath;
#if 0
		RList *list = r_fs_dir (fs, path);
		if (r_list_empty (list)) {
			RFSRoot *r;
			RListIter *iter;
			r_list_foreach (fs->roots, iter, r) {
				if (!strcmp (path, r->path)) {
					r_list_append (list, r->path);
				}
			}
		}
		r_list_free (list);
#endif
	} else if (r_str_startswith (buf, "mount ")) {
		char *arg = r_str_trim_dup (buf + 6);
		char *path = strchr (arg, ' ');
		if (path) {
			*path++ = 0;
			path = (char *)r_str_trim_head_ro (path);
			char *off = strchr (path, ' ');
			ut64 n = 0;
			if (off) {
				*off++ = 0;
				off = (char *)r_str_trim_head_ro (off);
				n = r_num_math (NULL, off);
			}
			bool res = r_fs_mount (fs, arg, path, n);
			if (!res) {
				R_LOG_ERROR ("cannot mount");
			}
		} else {
			RFSPlugin *plug;
			eprintf ("Usage: mount [fstype] [path]\nfstypes:");
			r_list_foreach (fs->plugins, iter, plug) {
				eprintf (" %s", plug->meta.name);
			}
			eprintf ("\n");
		}
		free (arg);
	} else if (r_str_startswith (buf, "mount")) {
		RFSRoot* r;
		r_list_foreach (fs->roots, iter, r) {
			cb_printf (cons, "%s %s\n", r->path, r->p->meta.name);
		}
	} else if (r_str_startswith (buf, "cat ")) {
		const char *input = r_str_trim_head_ro (buf + 3);
		char *abspath = fs_abspath (shell, input);
		char *p = strchr (abspath, '>');
		if (p) {
			*p = 0;
			r_str_trim (abspath);
		}
		file = r_fs_open (fs, abspath, false);
		if (file) {
			r_fs_read (fs, file, 0, file->size);
			char *fname = (char *)r_str_lchr (abspath, '/');
			if (fname) {
				fname++;
			}
			if (file->data && !handlePipes (fs, abspath, file->data, fname)) {
				char *s = r_str_ndup ((const char *)file->data, file->size);
				cb_printf (cons, "%s\n", s);
				free (s);
			}
			r_fs_close (fs, file);
		} else {
			R_LOG_ERROR ("Cannot open file");
		}
		free (abspath);
	} else if (r_str_startswith (buf, "cat")) {
		eprintf ("Usage: cat [filename] ([> localfile])\n");
	} else if (r_str_startswith (buf, "get64 ")) {
		const char *input = r_str_trim_head_ro (buf + 6);
		char *abspath = fs_abspath (shell, input);
		file = r_fs_open (fs, abspath, false);
		if (file) {
			r_fs_read (fs, file, 0, file->size);
			if (file->data) {
				char *b64 = r_base64_encode_dyn ((const ut8 *)file->data, file->size);
				if (b64) {
					cb_printf (cons, "%s\n", b64);
					free (b64);
				}
			}
			r_fs_close (fs, file);
		} else {
			R_LOG_ERROR ("Cannot open file");
		}
		free (abspath);
	} else if (r_str_startswith (buf, "get ")) {
		const char *input = r_str_trim_head_ro (buf + 3);
		char *abspath = fs_abspath (shell, input);
		const char *fname = r_str_lchr (abspath, '/');
		if (fname) {
			fname++;
		}
		file = r_fs_open (fs, abspath, false);
		if (file) {
			r_fs_read (fs, file, 0, file->size);
			r_file_dump (fname, file->data, file->size, 0);
			r_fs_close (fs, file);
		} else {
			char *f = r_str_newf ("./%s", fname);
			if (!r_fs_dir_dump (fs, abspath, f)) {
				R_LOG_ERROR ("Cannot open file");
			}
			free (f);
		}
		free (abspath);
	} else if (r_str_startswith (buf, "mkdir ")) {
		const char *input = r_str_trim_head_ro (buf + 5);
		if (R_STR_ISEMPTY (input)) {
			R_LOG_ERROR ("Usage: mkdir [path]");
			return true;
		}
		char *abspath = fs_abspath (shell, input);
		if (!abspath) {
			R_LOG_ERROR ("Cannot resolve path");
			return true;
		}
		r_str_trim_path (abspath);
		if (!*abspath) {
			free (abspath);
			abspath = strdup ("/");
			if (!abspath) {
				R_LOG_ERROR ("Cannot resolve path");
				return true;
			}
		}
		if (!r_fs_mkdir (fs, abspath)) {
			R_LOG_ERROR ("Cannot create directory");
		}
		free (abspath);
	} else if (r_str_startswith (buf, "set64 ")) {
		char *data = strdup (buf + 6);
		if (!data) {
			return true;
		}
		char *space = strchr (data, ' ');
		if (!space) {
			R_LOG_ERROR ("Usage: set64 <file> <base64>");
			free (data);
			return true;
		}
		*space++ = 0;
		char *abspath = fs_abspath (shell, data);
		if (!abspath) {
			R_LOG_ERROR ("Cannot resolve path");
			free (data);
			return true;
		}
		r_str_trim_path (abspath);
		if (!*abspath) {
			free (abspath);
			abspath = strdup ("/");
			if (!abspath) {
				free (data);
				return true;
			}
		}
		int outlen = 0;
		ut8 *decoded = (ut8 *)sdb_decode (space, &outlen);
		if (!decoded && *space) {
			R_LOG_ERROR ("Invalid base64");
			free (abspath);
			free (data);
			return true;
		}
		RFSFile *f = r_fs_open (fs, abspath, true);
		if (f) {
			r_fs_write (fs, f, 0, decoded? decoded: (const ut8 *)"", decoded? (size_t)outlen: 0);
			r_fs_close (fs, f);
			r_fs_file_free (f);
		} else {
			R_LOG_ERROR ("Cannot open file for writing");
		}
		free (decoded);
		free (abspath);
		free (data);
	} else if (r_str_startswith (buf, "set ")) {
		char *data = strdup (buf + 4);
		if (!data) {
			return true;
		}
		char *space = strchr (data, ' ');
		if (!space) {
			R_LOG_ERROR ("Usage: set <file> <contents>");
			free (data);
			return true;
		}
		*space++ = 0;
		char *abspath = fs_abspath (shell, data);
		if (!abspath) {
			R_LOG_ERROR ("Cannot resolve path");
			free (data);
			return true;
		}
		r_str_trim_path (abspath);
		if (!*abspath) {
			free (abspath);
			abspath = strdup ("/");
			if (!abspath) {
				free (data);
				return true;
			}
		}
		RFSFile *f = r_fs_open (fs, abspath, true);
		if (f) {
			r_fs_write (fs, f, 0, (const ut8 *)space, strlen (space));
			r_fs_close (fs, f);
			r_fs_file_free (f);
		} else {
			R_LOG_ERROR ("Cannot open file for writing");
		}
		free (abspath);
		free (data);
	} else if (r_str_startswith (buf, "o ") || r_str_startswith (buf, "open ")) {
		char *data = strdup (buf);
		const char *input = r_str_nextword (data, ' ');
		input = (char *)r_str_trim_head_ro (input);
		file = r_fs_open (fs, input, false);
		if (file) {
			r_fs_read (fs, file, 0, file->size);
			char *uri = r_str_newf ("malloc://%d", file->size);
			RIODesc *fd = fs->iob.open_at (fs->iob.io, uri, R_PERM_RW, 0, 0);
			free (uri);
			if (fd) {
				fs->iob.fd_write (fs->iob.io, fd->fd, file->data, file->size);
				return true;
			}
		} else {
			R_LOG_ERROR ("Cannot open file");
		}
		free (data);
	} else if (r_str_startswith (buf, "help") || r_str_startswith (buf, "?")) {
		cb_printf (cons,
			"Usage: [command (arguments)]([~grep-expression])\n"
			" !cmd        ; escape to system\n"
			" :cmd        ; escape to the r2 repl\n"
			" ls [path]   ; list current directory\n"
			" cd path     ; change current directory\n"
			" cat file    ; print contents of file\n"
			" get file    ; dump file to local disk\n"
			" get64 file  ; print base64 contents\n"
			" mkdir dir   ; create directory\n"
			" set file txt; write text into file\n"
			" set64 file b; write base64 contents\n"
			" getall      ; fetch all files in current rfs directory to local cwd\n"
			" o/open file ; open file with r2\n"
			" mount       ; show mount points\n"
			" q/exit      ; leave prompt mode\n"
			" ?/help      ; show this help\n");
	} else {
		if (*buf) {
			R_LOG_ERROR ("Unknown command %s", buf);
		}
	}
	return true;
}

#define PROMPT_PATH_BUFSIZE 1024

R_API bool r_fs_shell(RFSShell* shell, RFS* fs, const char* root) {
	R_RETURN_VAL_IF_FAIL (shell && fs, false);
	if (R_STR_ISNOTEMPTY (root)) {
		free (shell->cwd);
		shell->cwd = strdup (root);
	}
	char buf[PROMPT_PATH_BUFSIZE];
	char prompt[PROMPT_PATH_BUFSIZE];
	for (;;) {
		snprintf (prompt, sizeof (prompt), "[%.*s]> ", (int)sizeof (prompt) - 5, shell->cwd);
		if (shell) {
			if (shell->set_prompt) {
				shell->set_prompt (shell->cons->line, prompt);
			}
			if (shell->readline) {
				const char* ptr = shell->readline (shell->cons);
				if (!ptr) {
					break;
				}
				r_str_ncpy (buf, ptr, sizeof (buf) - 1);
			}
		}
		if (!shell || !shell->readline) {
			printf ("%s", prompt);
			if (!fgets (buf, sizeof (buf), stdin)) {
				break;
			}
			if (feof (stdin)) {
				break;
			}
		}
		r_str_trim (buf);

		if (shell && shell->hist_add) {
			shell->hist_add (shell->cons->line, buf);
		}

		char *wave = strchr (buf, '~');
		if (wave) {
			*wave++ = 0;
		}
		if (buf[0] == '#') {
			// comment
			continue;
		}
		if (r_str_startswith (buf, "q") || r_str_startswith (buf, "exit")) {
			return true;
		}
		if (!r_fs_shell_command (shell, fs, buf)) {
			break;
		}
		if (wave) {
			fs->csb.cb_grep (fs->csb.cons, wave);
		}
		fs->csb.cb_flush (fs->csb.cons);
	}
	clearerr (stdin);
	return true;
}
