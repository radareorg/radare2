/* radare - LGPL - Copyright 2013-2018 - pancake */

#include <r_core.h>
#include <errno.h>

#define FMT_NONE 0
#define FMT_RAW  1
#define FMT_JSON 2

static int needs_newline = 0;

static char *showfile(char *res, const int nth, const char *fpath, const char *name, int printfmt) {
#if __UNIX__
	struct stat sb;
#endif
	const char *n = fpath;
	char *nn, *u_rwx = NULL;
	int sz = r_file_size (n);
	int perm, uid = 0, gid = 0;
	int fch = '-';
	if (!strncmp (fpath, "./", 2)) {
		fpath = fpath + 2;
	}
	const bool isdir = r_file_is_directory (n);
	if (isdir) {
		nn = r_str_append (strdup (fpath), "/");
	} else {
		nn = strdup (fpath);
	}
	if (!*nn) {
		free (nn);
		return res;
	}
	perm = isdir? 0755: 0644;
	if (!printfmt) {
		needs_newline = ((nth + 1) % 4)? 1: 0;
		res = r_str_appendf (res, "%18s%s", nn, needs_newline? "  ": "\n");
		free (nn);
		return res;
	}
	// TODO: escape non-printable chars in filenames
	// TODO: Implement more real info in ls -l
	// TODO: handle suid
#if __UNIX__
	if (lstat (n, &sb) != -1) {
		ut32 ifmt = sb.st_mode & S_IFMT;
		uid = sb.st_uid;
		gid = sb.st_gid;
		perm = sb.st_mode & 0777;
		if (!(u_rwx = strdup (r_str_rwx_i (perm >> 6)))) {
			free (nn);
			return res;
		}
		if (sb.st_mode & S_ISUID) {
			u_rwx[2] = (sb.st_mode & S_IXUSR) ? 's' : 'S';
		}
		if (isdir) {
			fch = 'd';
		} else {
			switch (ifmt) {
			case S_IFCHR: fch = 'c'; break;
			case S_IFBLK: fch = 'b'; break;
			case S_IFLNK: fch = 'l'; break;
			case S_IFIFO: fch = 'p'; break;
#ifdef S_IFSOCK
			case S_IFSOCK: fch = 's'; break;
#endif
			}
		}
	}
#else
	u_rwx = strdup ("-");
	fch = isdir? 'd': '-';
#endif
	if (printfmt == 'q') {
		res = r_str_appendf (res, "%s\n", nn);
	} else if (printfmt == 'e') {
		const char *eDIR = "📁";
		const char *eLNK = "📎";
		const char *eIMG = "🌅";
		const char *eUID = "🔼";
		const char *eHID = "👀";
		const char *eANY = "  ";
		// --
		const char *icon = eANY;
		if (isdir) {
			icon = eDIR;
#if __UNIX__
		} else if ((sb.st_mode & S_IFMT) == S_IFLNK) {
			icon = eLNK;
		} else if (sb.st_mode & S_ISUID) {
			icon = eUID;
#endif
		} else if (r_str_casestr (nn, ".jpg") || r_str_casestr (nn, ".png") || r_str_casestr (nn, ".gif")) {
			icon = eIMG;
		} else if (*nn == '.') {
			icon = eHID;
		}
		res = r_str_appendf (res, "%s %s\n", icon, nn);
	} else if (printfmt == FMT_RAW) {
		res = r_str_appendf (res, "%c%s%s%s  1 %4d:%-4d  %-10d  %s\n",
			isdir?'d': fch,
			u_rwx? u_rwx: "-",
			r_str_rwx_i ((perm >> 3) & 7),
			r_str_rwx_i (perm & 7),
			uid, gid, sz, nn);
	} else if (printfmt == FMT_JSON) {
		if (nth > 0) {
			res = r_str_append (res, ",");
		}
		res = r_str_appendf (res, "{\"name\":\"%s\",\"size\":%d,\"uid\":%d,"
			"\"gid\":%d,\"perm\":%d,\"isdir\":%s}",
			name, sz, uid, gid, perm, isdir? "true": "false");
	}
	free (nn);
	free (u_rwx);
	return res;
}

// TODO: Move into r_util .. r_print maybe? r_cons dep is annoying
R_API char *r_syscmd_ls(const char *input) {
	char *res = NULL;
	const char *path = ".";
	char *d = NULL;
	char *p = NULL;
	char *homepath = NULL;
	char *pattern = NULL;
	int printfmt = 0;
	RListIter *iter;
	RList *files;
	char *name;
	char *dir;
	int off;
	if (!input) {
		input = "";
		path = ".";
	}
	if (*input == 'q') {
		printfmt = 'q';
		input++;
	}
	if (r_sandbox_enable (0)) {
		eprintf ("Sandbox forbids listing directories\n");
		return NULL;
	}
	if (*input && input[0] == ' ') {
		input++;
	}
	if (*input) {
		if ((!strncmp (input, "-h", 2))) {
			eprintf ("Usage: ls ([-e,-l,-j,-q]) ([path]) # long, json, quiet\n");
		} else if ((!strncmp (input, "-e", 2))) {
			printfmt = 'e';
			path = r_str_trim_head_ro (path + 1);
		} else if ((!strncmp (input, "-q", 2))) {
			printfmt = 'q';
			path = r_str_trim_head_ro (path + 1);
		} else if ((!strncmp (input, "-l", 2)) || (!strncmp (input, "-j", 2))) {
			// mode = 'l';
			if (input[2]) {
				printfmt = (input[2] == 'j') ? FMT_JSON : FMT_RAW;
				path = r_str_trim_head_ro (input + 2);
				if (!*path) {
					path = ".";
				}
			} else {
				printfmt = FMT_RAW;
			}
		} else {
			path = input;
		}
	}
	if (!path || !*path) {
		path = ".";
	} else if (!strncmp (path, "~/", 2)) {
		homepath = r_str_home (path + 2);
		if (homepath) {
			path = (const char *)homepath;
		}
	} else if (*path == '$') {
		if (!strncmp (path + 1, "home", 4) || !strncmp (path + 1, "HOME", 4)) {
			homepath = r_str_home ((strlen (path) > 5)? path + 6: NULL);
			if (homepath) {
				path = (const char *)homepath;
			}
		}
	}
	if (!r_file_is_directory (path)) {
		p = strrchr (path, '/');
		if (p) {
			off = p - path;
			d = (char *) calloc (1, off + 1);
			if (!d) {
				free (homepath);
				return NULL;
			}
			memcpy (d, path, off);
			path = (const char *)d;
			pattern = strdup (p + 1);
		} else {
			pattern = strdup (path);
			path = ".";
		}
	} else {
		pattern = strdup ("*");
	}
	if (r_file_is_regular (path)) {
		res = showfile (res, 0, path, path, printfmt);
		free (homepath);
		free (pattern);
		free (d);
		return res;
	}
	files = r_sys_dir (path);

	if (path[strlen (path) - 1] == '/') {
		dir = strdup (path);
	} else {
		dir = r_str_append (strdup (path), "/");
	}
	int nth = 0;
	if (printfmt == FMT_JSON) {
		res = strdup ("[");
	}
	needs_newline = 0;
	r_list_foreach (files, iter, name) {
		char *n = r_str_append (strdup (dir), name);
		if (!n) {
			break;
		}
		if (r_str_glob (name, pattern)) {
			if (*n) {
				res = showfile (res, nth, n, name, printfmt);
			}
			nth++;
		}
		free (n);
	}
	if (printfmt == FMT_JSON) {
		res = r_str_append (res, "]");
	}
	if (needs_newline) {
		res = r_str_append (res, "\n");
	}
	free (dir);
	free (d);
	free (homepath);
	free (pattern);
	r_list_free (files);
	return res;
}

static int cmpstr (const void *_a, const void *_b) {
	const char *a = _a, *b = _b;
	return (int)strcmp (a, b);
}

R_API char *r_syscmd_sort(const char *file) {
	int sz;
	const char *p = NULL;
	RList *list = NULL;
	if (file) {
		if ((p = strchr (file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup (p);
		r_str_trim (filename);
		char *data = r_file_slurp (filename, &sz);
		if (!data) {
			eprintf ("No such file or directory\n");
		} else {
			list = r_str_split_list (data, "\n", 0);
			r_list_sort (list, cmpstr);
			data = r_list_to_str (list, '\n');
			r_list_free (list);
		}
		free (filename);
		return data;
	} else {
		eprintf ("Usage: sort [file]\n");
	}
	return NULL;
}

R_API char *r_syscmd_head(const char *file, int count) {
	const char *p = NULL;
	if (file) {
		if ((p = strchr (file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	} 
	if (p && *p) {
		char *filename = strdup (p);
		r_str_trim (filename);
		char *data = r_file_slurp_lines (filename, 1, count);
		if (!data) {
			eprintf ("No such file or directory\n");
		}
		free (filename);
		return data;
	} else {
		eprintf ("Usage: head 7 [file]\n");
	}
	return NULL;
}

R_API char *r_syscmd_tail(const char *file, int count) {
	const char *p = NULL;
	if (file) {
		if ((p = strchr (file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup (p);
		r_str_trim (filename);
		char *data = r_file_slurp_lines_from_bottom (filename, count);
		if (!data) {
			eprintf ("No such file or directory\n");
		}
		free (filename);
		return data;
	} else {
		eprintf ("Usage: tail 7 [file]\n");
	}
	return NULL;
}

R_API char *r_syscmd_uniq(const char *file) {
	int sz;
	const char *p = NULL;
	RList *list = NULL;
	if (file) {
		if ((p = strchr (file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup (p);
		r_str_trim (filename);
		char *data = r_file_slurp (filename, &sz);
		if (!data) {
			eprintf ("No such file or directory\n");
		} else {
			list = r_str_split_list (data, "\n", 0);
			RList *uniq_list = r_list_uniq (list, cmpstr);
			data = r_list_to_str (uniq_list, '\n');
			r_list_free (uniq_list);
			r_list_free (list);
		}
		free (filename);
		return data;
	} else {
		eprintf ("Usage: uniq [file]\n");
	}
	return NULL;
}

R_API char *r_syscmd_join(const char *file1, const char *file2) {
	int sz1, sz2;
	const char *p1 = NULL, *p2 = NULL;
	RList *list1, *list2, *list = r_list_newf (NULL);
	if (!list) {
		return NULL;
	}
	if (file1) {
		if ((p1 = strchr (file1, ' '))) {
			p1 = p1 + 1;
		} else {
			p1 = file1;
		}
	}
	if (file2) {
		if ((p2 = strchr (file2, ' '))) {
			p2 = p2 + 1;
		} else {
			p2 = file2;
		}
	}
	if (p1 && *p1 && p2 && *p2 ) {
		char *filename1 = strdup (p1);
		char *filename2 = strdup (p2);
		r_str_trim (filename1);
		r_str_trim (filename2);
		char *data1 = r_file_slurp (filename1, &sz1);
		char *data2 = r_file_slurp (filename2, &sz2);
		char *data = NULL;
		RListIter *iter1, *iter2;
		if (!data1 && !data2) {
			eprintf ("No such files or directory\n");
		} else {
			list1 = r_str_split_list (data1, "\n",  0);
			list2 = r_str_split_list (data2, "\n", 0);

			char *str1, *str2;
			r_list_foreach (list1, iter1, str1) {
				char *field = strdup (str1);			// extract comman field
				char *end = strchr (field, ' ');
				if (end) {
					*end = '\0';
				} else {
					free (field);
					continue;
				}
				r_list_foreach (list2, iter2, str2) {
					if (r_str_startswith (str2, field)) {
						char *out = r_str_new (field);
						char *first = strchr (str1, ' ');
						char *second = strchr (str2, ' ');
						r_str_append (out, first ? first : " ");
						r_str_append (out, second ? second : " ");
						r_list_append (list, out);
					}
				}
				free (field);
			}
			data = r_list_to_str (list, '\n');
			r_list_free (list);
			r_list_free (list1);
			r_list_free (list2);
		}
		free (filename1);
		free (filename2);
		return data;
	} else {
		eprintf ("Usage: join file1 file2\n");
	}
	return NULL;
}

R_API char *r_syscmd_cat(const char *file) {
	int sz;
	const char *p = NULL;
	if (file) {
		if ((p = strchr (file, ' '))) {
			p = p + 1;
		} else {
			p = file;
		}
	}
	if (p && *p) {
		char *filename = strdup (p);
		r_str_trim (filename);
		char *data = r_file_slurp (filename, &sz);
		if (!data) {
			eprintf ("No such file or directory\n");
		}
		free (filename);
		return data;
	} else {
		eprintf ("Usage: cat [file]\n");
	}
	return NULL;
}

R_API char *r_syscmd_mkdir(const char *dir) {
	const char *suffix = r_str_trim_head_ro (strchr (dir, ' '));
	if (!suffix || !strncmp (suffix, "-p", 3)) {
		return r_str_dup (NULL, "Usage: mkdir [-p] [directory]\n");
	}
	int ret;
	char *dirname = (!strncmp (suffix, "-p ", 3))
		? strdup (suffix + 3): strdup (suffix);
	r_str_trim (dirname);
	ret = r_sys_mkdirp (dirname);
	if (!ret) {
		if (r_sys_mkdir_failed ()) {
			char *res = r_str_newf ("Cannot create \"%s\"\n", dirname);
			free (dirname);
			return res;
		}
	}
	free (dirname);
	return NULL;
}

R_API bool r_syscmd_mv(const char *input) {
	if (strlen (input) < 3) {
		eprintf ("Usage: mv src dst\n");
		return false;
	}
	input = input + 2;
	if (!r_sandbox_enable (0)) {
#if __WINDOWS__
		r_sys_cmdf ("move %s", input);
#else
		r_sys_cmdf ("mv %s", input);
#endif
	}
	return false;
}
