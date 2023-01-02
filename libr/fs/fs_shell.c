/* radare2 - LGPL - Copyright 2018-2022 - pancake */

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
	if (!strcmp (input, "..")) {
		char* p = (char*) r_str_lchr (path, '/');
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
	PrintfCallback cb_printf = fs->csb.cb_printf;
	if (*buf == ':') {
		char *msg = fs->cob.cmdstr (fs->cob.core, buf + 1);
		printf ("%s", msg);
		free (msg);
	} else if (*buf == '!') {
		r_sandbox_system (buf + 1, 1);
	} else if (r_str_startswith (buf, "echo")) {
		char *msg = r_str_trim_dup (buf + 4);
		if (!handlePipes (fs, msg, NULL, shell->cwd)) {
			cb_printf ("%s\n", msg);
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
					cb_printf ("%c %8d %s\n", file->type, file->size, file->name);
				} else {
					cb_printf ("%c %s\n", file->type, file->name);
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
				cb_printf ("m %s\n", (r->path && r->path[0]) ? r->path + 1: "");
			}
			free (base);
		}
		free (cwd);
	} else if (r_str_startswith (buf, "pwd")) {
		cb_printf ("%s\n", shell->cwd);
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
				eprintf (" %s", plug->name);
			}
			eprintf ("\n");
		}
		free (arg);
	} else if (r_str_startswith (buf, "mount")) {
		RFSRoot* r;
		r_list_foreach (fs->roots, iter, r) {
			cb_printf ("%s %s\n", r->path, r->p->name);
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
				cb_printf ("%s", s);
				free (s);
			}
			r_fs_close (fs, file);
		} else {
			R_LOG_ERROR ("Cannot open file");
		}
		free (abspath);
	} else if (r_str_startswith (buf, "cat")) {
		eprintf ("Usage: cat [filename] ([> localfile])\n");
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
		cb_printf (
			"Usage: [command (arguments)]([~grep-expression])\n"
			" !cmd        ; escape to system\n"
			" :cmd        ; escape to the r2 repl\n"
			" ls [path]   ; list current directory\n"
			" cd path     ; change current directory\n"
			" cat file    ; print contents of file\n"
			" get file    ; dump file to local disk\n"
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
	r_return_val_if_fail (shell && fs, false);
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
				shell->set_prompt (prompt);
			}
			if (shell->readline) {
				const char* ptr = shell->readline ();
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
			shell->hist_add (buf);
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
			fs->csb.cb_grep (wave);
		}
		fs->csb.cb_flush ();
	}
	clearerr (stdin);
	return true;
}
