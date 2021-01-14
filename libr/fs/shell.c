/* radare2 - LGPL - Copyright 2018-2020 - pancake */

#include <r_fs.h>

#define PROMPT_PATH_BUFSIZE 1024

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
		eprintf ("Cannot open %s for writing\n", red);
		free (red);
		return true;
	}
	r_fs_write (fs, f, 0, data ? data : (ut8*)msg, strlen (data ? (char*)data : msg));
	free (red);
	r_fs_close (fs, f);
	r_fs_file_free (f);
	return true;
}

R_API int r_fs_shell_prompt(RFSShell* shell, RFS* fs, const char* root) {
	char buf[PROMPT_PATH_BUFSIZE];
	char path[PROMPT_PATH_BUFSIZE];
	char prompt[PROMPT_PATH_BUFSIZE];
	char str[2048];
	char* input;
	const char* ptr;
	RList* list = NULL;
	RListIter* iter;
	RFSFile* file = NULL;

	if (root && *root) {
		strncpy (buf, root, sizeof (buf) - 1);
		r_str_trim_path (buf);
		list = r_fs_root (fs, buf);
		if (r_list_empty (list)) {
			printf ("Unknown root\n");
			r_list_free (list);
			return false;
		}
		r_str_ncpy (path, buf, sizeof (path) - 1);
	} else {
		strcpy (path, "/");
	}

	PrintfCallback cb_printf = fs->csb.cb_printf;
	for (;;) {
		snprintf (prompt, sizeof (prompt), "[%.*s]> ", (int)sizeof (prompt) - 5, path);
		if (shell) {
			*shell->cwd = strdup (path);
			if (shell->set_prompt) {
				shell->set_prompt (prompt);
			}
			if (shell->readline) {
				ptr = shell->readline ();
			} else {
				if (!fgets (buf, sizeof (buf), stdin)) {
					break;
				}
				if (feof (stdin)) {
					break;
				}
				r_str_trim_tail (buf);
				ptr = buf;
			}
			if (!ptr) {
				break;
			}
			r_str_trim ((char *)ptr); // XXX abadidea
			if (shell->hist_add) {
				shell->hist_add (ptr);
			}
			if (ptr != buf) {
				r_str_ncpy (buf, ptr, sizeof (buf) - 1);
			}
		} else {
			printf ("%s", prompt);
			if (!fgets (buf, sizeof (buf), stdin)) {
				break;
			}
			if (feof (stdin)) {
				break;
			}
			r_str_trim_tail (buf);
		}
		char *wave = strchr (buf, '~');
		if (wave) {
			*wave++ = 0;
		}

		if (!strcmp (buf, "q") || !strcmp (buf, "exit")) {
			r_list_free (list);
			return true;
		}
		if (buf[0] == '#') {
			// comment
			continue;
		} else if (buf[0] == ':') {
			char *msg = fs->cob.cmdstr (fs->cob.core, buf + 1);
			printf ("%s\n", msg);
			free (msg);
		} else if (buf[0] == '!') {
			r_sandbox_system (buf + 1, 1);
		} else if (!strncmp (buf, "echo", 4)) {
			char *msg = r_str_trim_dup (buf + 4);
			if (!handlePipes (fs, msg, NULL, path)) {
				cb_printf ("%s\n", msg);
			}
			free (msg);
		} else if (!strncmp (buf, "ls", 2)) {
			char *ptr = str;
			r_list_free (list);
			if (buf[2] == ' ') {
				if (buf[3] != '/') {
					snprintf (str, sizeof (str), "%s/%s", path, buf + 3);
					list = r_fs_dir (fs, str);
				} else {
					list = r_fs_dir (fs, buf + 3);
					ptr = buf + 3;
				}
			} else {
				ptr = path;
				list = r_fs_dir (fs, path);
			}
			if (list) {
				r_list_foreach (list, iter, file) {
					cb_printf ("%c %s\n", file->type, file->name);
				}
			}
			// mountpoints if any
			RFSRoot *r;
			char *me = strdup (ptr);
			r_list_foreach (fs->roots, iter, r) {
				char *base = strdup (r->path);
				char *ls = (char *)r_str_lchr (base, '/');
				if (ls) {
					ls++;
					*ls = 0;
				}
				// TODO: adjust contents between //
				if (!strcmp (me, base)) {
					cb_printf ("m %s\n", (r->path && r->path[0]) ? r->path + 1: "");
				}
				free (base);
			}
			free (me);
		} else if (!strncmp (buf, "pwd", 3)) {
			eprintf ("%s\n", path);
		} else if (!memcmp (buf, "cd ", 3)) {
			char opath[PROMPT_PATH_BUFSIZE];
			r_str_ncpy (opath, path, sizeof (opath));
			input = buf + 3;
			while (*input == ' ') {
				input++;
			}
			if (!strcmp (input, "..")) {
				char* p = (char*) r_str_lchr (path, '/');
				if (p) {
					p[(p == path)? 1: 0] = 0;
				}
			} else {
				strcat (path, "/");
				if (*input == '/') {
					strncpy (path, input, sizeof (opath) - 1);
				} else {
					if ((strlen (path) + strlen (input)) >= sizeof (path)) {
						// overflow
						path[0] = 0;
					} else {
						strcat (path, input);
					}
				}
				path[sizeof (path) - 1] = 0;
			}
			r_str_trim_path (path);
			r_list_free (list);
			list = r_fs_dir (fs, path);
			if (r_list_empty (list)) {
				RFSRoot *r;
				RListIter *iter;
				r_list_foreach (fs->roots, iter, r) {
					if (!strcmp (path, r->path)) {
						r_list_append (list, r->path);
					}
				}
			}
		} else if (!memcmp (buf, "cat ", 4)) {
			input = buf + 3;
			while (input[0] == ' ') {
				input++;
			}
			if (input[0] == '/') {
				if (root) {
					strncpy (str, root, sizeof (str) - 1);
				} else {
					str[0] = 0;
				}
			} else {
				strncpy (str, path, sizeof (str) - 1);
			}
			size_t n = strlen (str);
			snprintf (str + n, sizeof (str) - n, "/%s", input);
			char *p = strchr (str, '>');
			if (p) {
				*p = 0;
			}
			file = r_fs_open (fs, str, false);
			if (file) {
				if (p) {
					*p = '>';
				}
				r_fs_read (fs, file, 0, file->size);
				if (!handlePipes (fs, str, file->data, path)) {
					char *s = r_str_ndup ((const char *)file->data, file->size);
					cb_printf ("%s\n", s);
					free (s);
				}
				cb_printf ("\n");
				r_fs_close (fs, file);
			} else {
				eprintf ("Cannot open file\n");
			}
		} else if (!memcmp (buf, "mount", 5)) {
			RFSRoot* r;
			r_list_foreach (fs->roots, iter, r) {
				cb_printf ("%s %s\n", r->path, r->p->name);
			}
		} else if (!memcmp (buf, "get ", 4)) {
			char* s = 0;
			input = buf + 3;
			while (input[0] == ' ') {
				input++;
			}
			if (input[0] == '/') {
				if (root) {
					s = malloc (strlen (root) + strlen (input) + 2);
					if (!s) {
						goto beach;
					}
					strcpy (s, root);
				}
			} else {
				s = malloc (strlen (path) + strlen (input) + 2);
				if (!s) {
					goto beach;
				}
				strcpy (s, path);
			}
			if (!s) {
				s = calloc (strlen (input) + 32, 1);
				if (!s) {
					goto beach;
				}
			}
			strcat (s, "/");
			strcat (s, input);
			file = r_fs_open (fs, s, false);
			if (file) {
				r_fs_read (fs, file, 0, file->size);
				r_file_dump (input, file->data, file->size, 0);
				r_fs_close (fs, file);
			} else {
				char *f = r_str_newf ("./%s", input);
				if (!r_fs_dir_dump (fs, s, f)) {
					eprintf ("Cannot open file\n");
				}
				free (f);
			}
			free (s);
		} else if (!memcmp (buf, "help", 4) || !strcmp (buf, "?")) {
			cb_printf (
				"Usage: [command (arguments)]([~grep-expression])\n"
				" !cmd        ; escape to system\n"
				" :cmd        ; escape to the r2 repl\n"
				" ls [path]   ; list current directory\n"
				" cd path     ; change current directory\n"
				" cat file    ; print contents of file\n"
				" get file    ; dump file to disk\n"
				" mount       ; list mount points\n"
				" q/exit      ; leave prompt mode\n"
				" ?/help      ; show this help\n");
		} else {
			if (*buf) {
				eprintf ("Unknown command %s\n", buf);
			}
		}
		if (wave) {
			fs->csb.cb_grep (wave);
		}
		fs->csb.cb_flush ();
	}
beach:
	clearerr (stdin);
	printf ("\n");
	r_list_free (list);
	return true;
}

