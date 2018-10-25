/* radare2 - LGPL - Copyright 2018 - pancake */

#include <r_fs.h>

#define PROMPT_PATH_BUFSIZE 1024

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
		strncpy (path, buf, sizeof (path) - 1);
	} else {
		strcpy (path, "/");
	}

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
				fgets (buf, sizeof (buf) - 1, stdin);
				if (feof (stdin)) {
					break;
				}
				buf[strlen (buf) - 1] = '\0';
				ptr = buf;
			}
			if (!ptr) {
				break;
			}
			ptr = r_str_trim ((char *)ptr);
			if (shell->hist_add) {
				shell->hist_add (ptr);
			}
			if (ptr != buf) {
				r_str_ncpy (buf, ptr, sizeof (buf) - 1);
			}
		} else {
			printf ("%s", prompt);
			fgets (buf, sizeof (buf) - 1, stdin);
			if (feof (stdin)) {
				break;
			}
			buf[strlen (buf) - 1] = '\0';
		}

		if (!strcmp (buf, "q") || !strcmp (buf, "exit")) {
			r_list_free (list);
			return true;
		}
		if (buf[0] == '!') {
			r_sandbox_system (buf + 1, 1);
		} else if (!strncmp (buf, "ls", 2)) {
			char *ptr = str;
			r_list_free (list);
			if (buf[2] == ' ') {
				if (buf[3] != '/') {
					strncpy (str, path, sizeof (str) - 1);
					strcat (str, "/");
					strncat (str, buf + 3, sizeof (buf) - 1);
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
					printf ("%c %s\n", file->type, file->name);
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
					printf ("m %s\n", (r->path && r->path[0]) ? r->path + 1: "");
				}
				free (base);
			}
			free (me);
		} else if (!strncmp (buf, "pwd", 3)) {
			eprintf ("%s\n", path);
		} else if (!memcmp (buf, "cd ", 3)) {
			char opath[PROMPT_PATH_BUFSIZE];
			strncpy (opath, path, sizeof (opath) - 1);
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
				RFSRoot *root;
				bool found = false;
				RListIter *iter;
				r_list_foreach (fs->roots, iter, root) {
					if (!strcmp (path, root->path)) {
						r_list_append (list, root->path);
						found = true;
					}
				}
				if (!found) {
					strcpy (path, opath);
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
			strncat (str, "/",   sizeof (str) - strlen (str) - 1);
			strncat (str, input, sizeof (str) - strlen (str) - 1);
			file = r_fs_open (fs, str);
			if (file) {
				r_fs_read (fs, file, 0, file->size);
				write (1, file->data, file->size);
				free (file->data);
				r_fs_close (fs, file);
			} else {
				eprintf ("Cannot open file\n");
			}
		} else if (!memcmp (buf, "mount", 5)) {
			RFSRoot* r;
			r_list_foreach (fs->roots, iter, r) {
				eprintf ("%s %s\n", r->path, r->p->name);
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
			file = r_fs_open (fs, s);
			if (file) {
				r_fs_read (fs, file, 0, file->size);
				r_file_dump (input, file->data, file->size, 0);
				free (file->data);
				r_fs_close (fs, file);
			} else {
				input -= 2; //OMFG!!!! O_O
				memcpy (input, "./", 2);
				if (!r_fs_dir_dump (fs, s, input)) {
					printf ("Cannot open file\n");
				}
			}
			free (s);
		} else if (!memcmp (buf, "help", 4) || !strcmp (buf, "?")) {
			eprintf (
				"Commands:\n"
				" !cmd        ; escape to system\n"
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
	}
beach:
	clearerr (stdin);
	printf ("\n");
	r_list_free (list);
	return true;
}

