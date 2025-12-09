/* radare - LGPL - Copyright 2013-2024 - pancake */

#include <r_core.h>
#include <errno.h>

#define FMT_NONE 0
#define FMT_RAW  1
#define FMT_JSON 'j'
#define FMT_QUIET 'q'
#define FMT_EMOJI 'e'

static R_TH_LOCAL RList *dirstack = NULL;

static char *showfile(char *res, const int nth, const char *fpath, const char *name, int printfmt, bool needs_newline, int column_width) {
#if R2__UNIX__
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
		res = r_str_appendf (res, "%-*s%s", column_width, nn, needs_newline? "\n": "  ");
		free (nn);
		return res;
	}
	// TODO: escape non-printable chars in filenames
	// TODO: Implement more real info in ls -l
	// TODO: handle suid
#if R2__UNIX__
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
#ifndef __wasi__
#ifdef S_IFSOCK
			case S_IFSOCK: fch = 's'; break;
#endif
#endif
			}
		}
	}
#else
	u_rwx = strdup ("-");
	fch = isdir? 'd': '-';
#endif
	if (printfmt == FMT_QUIET) {
		res = r_str_appendf (res, "%s\n", nn);
	} else if (printfmt == FMT_EMOJI) {
		const char *eDIR = "📁";
		const char *eIMG = "🌅";
		const char *eHID = "👀";
		const char *eANY = "  ";
		const char *eZIP = "🤐";
		const char *eMOV = "📺";
		const char *eEXE = "🏃";
		const char *eLIB = "📚";
		const char *eCOD = "📖";
		// --
		const char *icon = eANY;
		if (isdir) {
			icon = eDIR;
		} else if (r_str_casestr (nn, ".mov") || r_str_casestr (nn, ".mp4") || r_str_casestr (nn, ".mpg")) {
			icon = eMOV;
		} else if (r_str_endswith (nn, ".py")) {
			icon = "🐍";
		} else if (r_str_endswith (nn, ".c")) {
			icon = eCOD;
		} else if (r_str_endswith (nn, ".o")) {
			icon = "📕";
		} else if (r_str_casestr (nn, ".exe")) {
			icon = eEXE;
		} else if (r_str_casestr (nn, ".apk") || r_str_casestr (nn, ".dmg")) {
			icon = "📦";
		} else if (r_str_casestr (nn, ".so") || r_str_casestr (nn, ".dll") || r_str_casestr (nn, ".dylib")) {
			icon = eLIB;
		} else if (r_str_casestr (nn, ".csv") || r_str_casestr (nn, ".txt") || r_str_casestr (nn, ".xml") || r_str_casestr (nn, ".json") || r_str_casestr (nn, ".pdf")) {
			icon = "📄";
		} else if (r_str_casestr (nn, ".zip") || r_str_casestr (nn, ".gz") || r_str_casestr (nn, ".xz") || r_str_casestr (nn, ".bz2") || r_str_casestr (nn, "jar")) {
			icon = eZIP;
		} else if (r_str_casestr (nn, ".jpg") || r_str_casestr (nn, ".png") || r_str_casestr (nn, ".gif") || r_str_casestr (nn, ".jpeg") || r_str_casestr (nn, ".svg")) {
			icon = eIMG;
#if R2__UNIX__
		} else if ((sb.st_mode & S_IFMT) == S_IFLNK) {
			const char *eLNK = "📎";
			icon = eLNK;
		} else if (sb.st_mode & S_ISUID) {
			const char *eUID = "🔼";
			icon = eUID;
		} else if (perm & 1) {
			icon = eEXE;
#endif
		} else if (*nn == '.') {
			icon = eHID;
		}
		res = r_str_appendf (res, "%s %s\n", icon, nn);
	} else if (printfmt == FMT_RAW) {
		res = r_str_appendf (res, "%c%s%s%s  1 %4d:%-4d  %-10d  %s\n",
			isdir? 'd': fch,
			r_str_get_fail (u_rwx, "-"),
			r_str_rwx_i ((perm >> 3) & 7),
			r_str_rwx_i (perm & 7),
			uid, gid, sz, nn);
	} else if (printfmt == FMT_JSON) {
		if (nth > 0) {
			res = r_str_append (res, ",");
		}
		PJ *pj = pj_new ();
		pj_o (pj);
		pj_ks (pj, "name", name);
		pj_kn (pj, "size", sz);
		pj_kn (pj, "uid", uid);
		pj_kn (pj, "gid", gid);
		pj_kn (pj, "perm", perm);
		pj_ks (pj, "perm_root", r_str_rwx_i ((perm >> 6)&7));
		pj_ks (pj, "perm_group", r_str_rwx_i ((perm >> 3)&7));
		pj_ks (pj, "perm_other", r_str_rwx_i (perm & 7));
		pj_kb (pj, "isdir", isdir);
		pj_end (pj);
		char *js = pj_drain (pj);
		res = r_str_append (res, js);
		free (js);
	} else {
		R_LOG_ERROR ("unknown format");
	}
	free (nn);
	free (u_rwx);
	return res;
}

// TODO: Move into r_util .. r_print maybe? r_cons dep is annoying
R_API char *r_syscmd_ls(const char *input, int cons_width) {
	char *res = NULL;
	const char *path = ".";
	char *d = NULL;
	char *p = NULL;
	char *homepath = NULL;
	char *pattern = NULL;
	int printfmt = 0;
	RListIter *iter;
	char *name;
	char *dir;
	int off;
	if (!input) {
		input = "";
		path = ".";
	}
	if (*input == '?') {
		input = "-h";
	} else if (*input == 'e') {
		printfmt = FMT_EMOJI;
		input++;
	} else if (*input == 'j') {
		printfmt = FMT_JSON;
		input++;
	} else if (*input == 'q') {
		printfmt = FMT_QUIET;
		input++;
	}
	if (r_sandbox_enable (0)) {
		R_LOG_ERROR ("Sandbox forbids listing directories");
		return NULL;
	}
	input = r_str_trim_head_ro (input);
	if (*input) {
		if (r_str_startswith (input, "-h") || *input == '?') {
			eprintf ("Usage: ls [-e,-l,-j,-q] [path] # long, json, quiet\n");
			return NULL;
		}
		if (r_str_startswith (input, "-e")) {
			printfmt = FMT_EMOJI;
			path = r_str_trim_head_ro (input + 2);
		} else if (r_str_startswith (input, "-q")) {
			printfmt = FMT_QUIET;
			path = r_str_trim_head_ro (input + 2);
		} else if (r_str_startswith (input, "-l") || r_str_startswith (input, "-j")) {
			printfmt = (input[1] == 'j') ? FMT_JSON : FMT_RAW;
			path = r_str_trim_head_ro (input + 2);
			if (!*path) {
				path = ".";
			}
		} else {
			path = input;
		}
	}
	if (R_STR_ISEMPTY (path)) {
		path = ".";
	} else if (!strncmp (path, "~/", 2)) {
		homepath = r_file_home (path + 2);
		if (homepath) {
			path = (const char *)homepath;
		}
	} else if (*path == '$') {
		if (!strncmp (path + 1, "home", 4) || !strncmp (path + 1, "HOME", 4)) {
			homepath = r_file_home ((strlen (path) > 5)? path + 6: NULL);
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
		res = showfile (res, 0, path, path, printfmt, false, 18);
		free (homepath);
		free (pattern);
		free (d);
		return res;
	}
	RList *files = r_sys_dir (path);
	if (!files) {
		free (homepath);
		free (pattern);
		free (d);
		return NULL;
	}
	r_list_sort (files, (RListComparator)strcmp);

	int max_name_len = 0;
	r_list_foreach (files, iter, name) {
		int len = strlen (name);
		if (len > max_name_len) max_name_len = len;
	}

	if (path[strlen (path) - 1] == '/') {
		dir = strdup (path);
	} else {
		dir = r_str_append (strdup (path), "/");
	}
	int max_len = strlen (dir) + max_name_len + 1;
	int column_width = max_len + 2;
	if (column_width > cons_width / 2) {
		column_width = cons_width / 2;
	}
	if (column_width < 12) column_width = 12;
	int nth = 0;
	if (printfmt == FMT_JSON) {
		res = strdup ("[");
	}
	bool needs_newline = false;
	int linelen = 0;
	r_list_foreach (files, iter, name) {
		char *n = r_str_append (strdup (dir), name);
		if (!n) {
			break;
		}
		if (r_str_glob (name, pattern)) {
			if (*n) {
				bool isdir = r_file_is_directory (n);
				char *nn = isdir ? r_str_append (strdup (n), "/") : strdup (n);
				int display_len = strlen (nn);
				linelen += R_MAX (column_width, display_len) + 2;
				if (linelen > cons_width) {
					needs_newline = true;
				}
				res = showfile (res, nth, n, name, printfmt, needs_newline, column_width);
				if (needs_newline) {
					needs_newline = false;
					linelen = 0;
				}
				free (nn);
			}
			nth++;
		}
		free (n);
	}
	if (printfmt == FMT_JSON) {
		res = r_str_append (res, "]");
	} else {
		if (res) {
			char * last = res + strlen (res) - 1;
			if (*last != '\n') {
				res = r_str_append (res, "\n");
			}
		}
	}
	free (dir);
	free (d);
	free (homepath);
	free (pattern);
	r_list_free (files);
	return res;
}

static ut64 valstr(const void *_a) {
	const char *a = _a;
	return r_str_hash64 (a);
}

static int cmpstr(const void *_a, const void *_b) {
	const char *a = _a, *b = _b;
	return (int)strcmp (a, b);
}

R_API char *r_syscmd_sort(const char *file) {
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
		char *data = r_file_slurp (filename, NULL);
		if (!data) {
			R_LOG_ERROR ("No such file or directory");
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
			R_LOG_ERROR ("No such file or directory");
		}
		free (filename);
		return data;
	}
	R_LOG_INFO ("Usage: head 7 [file]");
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
	if (R_STR_ISNOTEMPTY (p)) {
		char *filename = strdup (p);
		r_str_trim (filename);
		char *data = r_file_slurp_lines_from_bottom (filename, count);
		if (!data) {
			R_LOG_ERROR ("No such file or directory");
		}
		free (filename);
		return data;
	}
	R_LOG_INFO ("Usage: tail 7 [file]");
	return NULL;
}

R_API char *r_syscmd_uniq(const char *file) {
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
		char *data = r_file_slurp (filename, NULL);
		if (!data) {
			R_LOG_ERROR ("No such file or directory");
		} else {
			list = r_str_split_list (data, "\n", 0);
			RList *uniq_list = r_list_uniq (list, valstr);
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
	const char *p1 = NULL, *p2 = NULL;
	if (file1) {
		if ((p1 = strchr (file1, ' '))) {
			p1++;
		} else {
			p1 = file1;
		}
	}
	if (file2) {
		if ((p2 = strchr (file2, ' '))) {
			p2++;
		} else {
			p2 = file2;
		}
	}
	if (R_STR_ISEMPTY (p1) || R_STR_ISEMPTY (p2)) {
		R_LOG_INFO ("Usage: join file1 file2");
		return NULL;
	}

	RList *list = r_list_newf (free);
	if (!list) {
		return NULL;
	}
	char *filename1 = strdup (p1);
	char *filename2 = strdup (p2);
	r_str_trim (filename1);
	r_str_trim (filename2);
	char *data1 = r_file_slurp (filename1, NULL);
	char *data2 = r_file_slurp (filename2, NULL);
	char *data = NULL;
	RListIter *iter1, *iter2;
	if (!data1 || !data2) {
		R_LOG_ERROR ("No such files or directory");
	} else {
		RList *list1 = r_str_split_list (data1, "\n",  0);
		RList *list2 = r_str_split_list (data2, "\n", 0);

		char *str1, *str2;
		r_list_foreach (list1, iter1, str1) {
			char *field = strdup (str1); // extract command field
			char *end = strchr (field, ' ');
			if (end) {
				*end = '\0';
			} else {
				free (field);
				continue;
			}
			r_list_foreach (list2, iter2, str2) {
				if (r_str_startswith (str2, field)) {
					char *out = strdup (field);
					char *first = strchr (str1, ' ');
					char *second = strchr (str2, ' ');
					out = r_str_append (out, r_str_get_fail (first, " "));
					out = r_str_append (out, r_str_get_fail (second, " "));
					r_list_append (list, out);
				}
			}
			free (field);
		}
		data = r_list_to_str (list, '\n');
		r_list_free (list1);
		r_list_free (list2);
	}
	r_list_free (list);
	free (filename1);
	free (filename2);
	free (data1);
	free (data2);
	return data;
}

R_API char *r_syscmd_cat(const char *file) {
	const char *p = r_str_trim_head_ro (file);
	if (R_STR_ISNOTEMPTY (p)) {
		char *filename = r_file_abspath (p);
		r_str_trim (filename);
		char *data = r_file_slurp (filename, NULL);
		if (!data) {
			R_LOG_ERROR ("No such file or directory");
		}
		free (filename);
		return data;
	}
	R_LOG_INFO ("Usage: cat [file]");
	return NULL;
}

R_API char *r_syscmd_mktemp(const char *dir) {
	const char *space = strchr (dir, ' ');
	const char *suffix = space? r_str_trim_head_ro (space): "";
	if (!*suffix || (!strncmp (suffix, "-d ", 3) && strstr (suffix, " -"))) {
		eprintf ("Usage: mktemp [-d] [file|directory]\n");
		return NULL;
	}
	bool dodir = (bool) strstr (suffix, "-d");
	int ret;
	char *dirname = (!strncmp (suffix, "-d ", 3))
		? strdup (suffix + 3): strdup (suffix);
	r_str_trim (dirname);
	char *arg = NULL;
	if (!*dirname || *dirname == '-') {
		eprintf ("Usage: mktemp [-d] [file|directory]\n");
		free (dirname);
		return NULL;
	}
	int fd = r_file_mkstemp (dirname, &arg);
	if (fd != -1) {
		ret = 1;
		close (fd);
	} else {
		ret = 0;
	}
	if (ret && dodir) {
		r_file_rm (arg);
		ret = r_sys_mkdirp (arg);
	}
	if (!ret) {
		R_LOG_ERROR ("Cannot create '%s'", dirname);
		free (dirname);
		return NULL;
	}
	return dirname;
}

R_API bool r_syscmd_mkdir(const char *dir) {
	const char *space = strchr (dir, ' ');
	const char *suffix = space? r_str_trim_head_ro (space): "";
	if (!*suffix || (!strncmp (suffix, "-p ", 3) && strstr (suffix, " -"))) {
		eprintf ("Usage: mkdir [-p] [directory]\n");
		return false;
	}
	char *dirname = (!strncmp (suffix, "-p ", 3))
		? strdup (suffix + 3): strdup (suffix);
	r_str_trim (dirname);
	if (!*dirname || *dirname == '-') {
		eprintf ("Usage: mkdir [-p] [directory]\n");
		free (dirname);
		return false;
	}
	if (!r_sys_mkdirp (dirname)) {
		if (r_sys_mkdir_failed ()) {
			R_LOG_ERROR ("Cannot create '%s'", dirname);
			free (dirname);
			return false;
		}
	}
	free (dirname);
	return true;
}

R_API bool r_syscmd_pushd(const char *input) {
	if (!dirstack) {
		dirstack = r_list_newf (free);
	}
	char *cwd = r_sys_getdir ();
	if (!cwd) {
		R_LOG_ERROR ("Where am I?");
		return false;
	}
	bool suc = r_sys_chdir (input);
	if (suc) {
		r_list_push (dirstack, cwd);
	} else {
		R_LOG_ERROR ("Cannot chdir");
	}
	return suc;
}

R_API bool r_syscmd_popd(void) {
	if (!dirstack) {
		return false;
	}
	char *d = r_list_pop (dirstack);
	if (d) {
		r_sys_chdir (d);
		eprintf ("%s\n", d);
		free (d);
	}
	if (r_list_empty (dirstack)) {
		r_list_free (dirstack);
		dirstack = NULL;
	}
	return true;
}

R_API bool r_syscmd_popalld(void) {
	if (!dirstack || r_list_empty (dirstack)) {
		return false;
	}
	while (r_syscmd_popd ()) {
		// wait for it
	}
	return true;
}

R_API bool r_syscmd_mv(const char *input) {
	if (strlen (input) < 3) {
		eprintf ("Usage: mv src dst\n");
		return false;
	}
	char *inp = r_str_trim_dup (input + 2);
	char *arg = strchr (inp, ' ');
	bool rc = false;
	if (arg) {
		*arg++ = 0;
		if (!(rc = r_file_move (inp, arg))) {
			R_LOG_ERROR ("Cannot move file");
		}
	} else {
		eprintf ("Usage: mv src dst\n");
	}
	free (inp);
	return rc;
}
