/* radare - LGPL - Copyright 2013-2025 - pancake */

#include <r_core.h>
#include <errno.h>

#define FMT_NONE 0
#define FMT_RAW 1
#define FMT_JSON 'j'
#define FMT_QUIET 'q'
#define FMT_EMOJI 'e'

static R_TH_LOCAL RList *dirstack = NULL;

static void showfile(RStrBuf *sb, PJ *pj, const int nth, const char *fpath, const char *name, int printfmt, bool needs_newline, int column_width) {
#if R2__UNIX__
	struct stat st;
#endif
	const char *n = fpath;
	char *u_rwx = NULL;
	int sz = r_file_size (n);
	int uid = 0, gid = 0;
	int fch = '-';
	if (r_str_startswith (fpath, "./")) {
		fpath = fpath + 2;
	}
	const bool isdir = r_file_is_directory (n);
	char *nn = r_str_newf ("%s%s", fpath, isdir? "/": "");
	int perm = isdir? 0755: 0644;
	if (!printfmt) {
		if (needs_newline) {
			r_strbuf_appendf (sb, "%s\n", nn);
		} else {
			r_strbuf_appendf (sb, "%-*s%s", column_width, nn, "  ");
		}
		free (nn);
		return;
	}
	// TODO: escape non-printable chars in filenames
	// TODO: Implement more real info in ls -l
	// TODO: handle suid
#if R2__UNIX__
	if (lstat (n, &st) != -1) {
		ut32 ifmt = st.st_mode & S_IFMT;
		uid = st.st_uid;
		gid = st.st_gid;
		perm = st.st_mode & 0777;
		if (! (u_rwx = strdup (r_str_rwx_i (perm >> 6)))) {
			free (nn);
			return;
		}
		if (st.st_mode & S_ISUID) {
			u_rwx[2] = (st.st_mode & S_IXUSR)? 's': 'S';
		}
		if (isdir) {
			fch = 'd';
		} else {
			switch (ifmt) {
			case S_IFCHR: fch = 'c'; break;
			case S_IFBLK: fch = 'b'; break;
			case S_IFLNK: fch = 'l'; break;
			case S_IFIFO: fch = 'p'; break;
#if !defined(__wasi__) && defined(S_IFSOCK)
			case S_IFSOCK: fch = 's'; break;
#endif
			}
		}
	}
#else
	u_rwx = strdup ("-");
	fch = isdir? 'd': '-';
#endif
	if (printfmt == FMT_QUIET) {
		r_strbuf_appendf (sb, "%s\n", nn);
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
		} else if ((st.st_mode & S_IFMT) == S_IFLNK) {
			icon = "📎";
		} else if (st.st_mode & S_ISUID) {
			icon = "🔼";
		} else if (perm & 1) {
			icon = eEXE;
#endif
		} else if (*nn == '.') {
			icon = eHID;
		}
		r_strbuf_appendf (sb, "%s %s\n", icon, nn);
	} else if (printfmt == FMT_RAW) {
		r_strbuf_appendf (sb, "%c%s%s%s  1 %4d:%-4d  %-10d  %s\n",
			isdir? 'd': fch,
			r_str_get_fail (u_rwx, "-"),
			r_str_rwx_i ((perm >> 3) & 7),
			r_str_rwx_i (perm & 7),
			uid, gid, sz, nn);
	} else if (printfmt == FMT_JSON) {
		pj_o (pj);
		pj_ks (pj, "name", name);
		pj_kn (pj, "size", sz);
		pj_kn (pj, "uid", uid);
		pj_kn (pj, "gid", gid);
		pj_kn (pj, "perm", perm);
		pj_ks (pj, "perm_root", r_str_rwx_i ((perm >> 6) & 7));
		pj_ks (pj, "perm_group", r_str_rwx_i ((perm >> 3) & 7));
		pj_ks (pj, "perm_other", r_str_rwx_i (perm & 7));
		pj_kb (pj, "isdir", isdir);
		pj_end (pj);
	} else {
		R_LOG_ERROR ("unknown format");
	}
	free (nn);
	free (u_rwx);
}

typedef struct {
	char *path;
	char *pattern;
	char *homepath;
	char *d;
	int printfmt;
} PathInfo;

static PathInfo *resolve_path_info(const char *input) {
	PathInfo *pi = R_NEW0 (PathInfo);
	if (!pi) {
		return NULL;
	}
	const char *path = ".";
	char *homepath = NULL;
	char *d = NULL;
	char *pattern = NULL;
	int printfmt = 0;
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
		free (pi);
		return NULL;
	}
	input = r_str_trim_head_ro (input);
	if (*input) {
		if (r_str_startswith (input, "-h") || *input == '?') {
			eprintf ("Usage: ls [-e,-l,-j,-q] [path] # long, json, quiet\n");
			free (pi);
			return NULL;
		}
		if (*input == '-') {
			switch (input[1]) {
			case 'e':
				printfmt = FMT_EMOJI;
				path = r_str_trim_head_ro (input + 2);
				break;
			case 'q':
				printfmt = FMT_QUIET;
				path = r_str_trim_head_ro (input + 2);
				break;
			case 'l':
			case 'j':
				printfmt = (input[1] == 'j')? FMT_JSON: FMT_RAW;
				path = r_str_trim_head_ro (input + 2);
				if (!*path) {
					path = ".";
				}
				break;
			default:
				R_LOG_ERROR ("Unknown flag %s", input);
				break;
			}
		} else {
			path = input;
		}
	}
	if (R_STR_ISEMPTY (path)) {
		path = ".";
	} else if (r_str_startswith (path, "~/")) {
		homepath = r_file_home (path + 2);
		if (homepath) {
			path = (const char *)homepath;
		}
	} else if (*path == '$') {
		if (r_str_startswith (path + 1, "HOME")) {
			homepath = r_file_home ((strlen (path) > 5)? path + 6: NULL);
			if (homepath) {
				path = (const char *)homepath;
			}
		}
	}
	if (r_file_is_directory (path)) {
		pattern = strdup ("*");
	} else {
		char *p = strrchr (path, '/');
		if (p) {
			size_t off = p - path;
			d = (char *)calloc (1, off + 1);
			if (!d) {
				free (homepath);
				free (pi);
				return NULL;
			}
			memcpy (d, path, off);
			path = (const char *)d;
			pattern = strdup (p + 1);
		} else {
			pattern = strdup (path);
			path = ".";
		}
	}
	pi->path = (char *)path;
	pi->pattern = pattern;
	pi->homepath = homepath;
	pi->d = d;
	pi->printfmt = printfmt;
	return pi;
}

static void free_path_info(PathInfo *pi) {
	if (pi) {
		free (pi->homepath);
		free (pi->pattern);
		free (pi->d);
		free (pi);
	}
}

R_API char *r_syscmd_ls(const char *input, int cons_width) {
	PJ *pj = NULL;
	PathInfo *pi = resolve_path_info (input);
	if (!pi) {
		return NULL;
	}
	RStrBuf *sb = r_strbuf_new ("");
	if (pi->printfmt == FMT_JSON) {
		pj = pj_new ();
		pj_a (pj);
	}
	if (r_file_is_regular (pi->path)) {
		showfile (sb, pj, 0, pi->path, pi->path, pi->printfmt, false, 18);
		char *res;
		if (pj) {
			pj_end (pj);
			res = pj_drain (pj);
		} else {
			res = r_strbuf_drain (sb);
		}
		free_path_info (pi);
		return res;
	}
	RList *files = r_sys_dir (pi->path);
	if (!files) {
		free_path_info (pi);
		r_strbuf_free (sb);
		if (pj) {
			pj_free (pj);
		}
		return NULL;
	}
	r_list_sort (files, (RListComparator)strcmp);

	RListIter *iter;
	char *name;
	int max_name_len = 0;
	r_list_foreach (files, iter, name) {
		int len = strlen (name);
		if (len > max_name_len) {
			max_name_len = len;
		}
	}

	char *dir = r_str_newf ("%s%s", pi->path, pi->path[strlen(pi->path) - 1] == '/' ? "" : "/");
	const char *display_dir = r_str_startswith (dir, "./")? dir + 2: dir;
	int max_len = strlen (display_dir) + max_name_len + 1;
	int column_width = max_len + 2;
	if (column_width > cons_width / 2) {
		column_width = cons_width / 2;
	}
	if (column_width < 12) {
		column_width = 12;
	}
	int nth = 0;
	int linelen = 0;
	r_list_foreach (files, iter, name) {
		char *n = r_str_newf ("%s%s", dir, name);
		if (r_str_glob (name, pi->pattern)) {
			if (*n) {
				bool isdir = r_file_is_directory (n);
				const char *display_path = r_str_startswith (n, "./")? n + 2: n;
				int display_len = strlen (display_path) + (isdir? 1: 0);
				int add = R_MAX (column_width, display_len) + 2;
				bool needs_newline = (linelen + add > cons_width);
				showfile (sb, pj, nth, n, name, pi->printfmt, needs_newline, column_width);
				if (needs_newline) {
					linelen = 0;
				} else {
					linelen += add;
				}
			}
			nth++;
		}
		free (n);
	}
	char *res;
	if (pj) {
		pj_end (pj);
		res = pj_drain (pj);
	} else {
		/// AITODO this is awful
		if (r_strbuf_length (sb) > 0 && r_strbuf_get (sb)[r_strbuf_length (sb) - 1] != '\n') {
			r_strbuf_append (sb, "\n");
		}
		res = r_strbuf_drain (sb);
	}
	free (dir);
	r_list_free (files);
	free_path_info (pi);
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
		RList *list1 = r_str_split_list (data1, "\n", 0);
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
	bool dodir = (bool)strstr (suffix, "-d");
	int ret;
	char *dirname = (!strncmp (suffix, "-d ", 3))
		? strdup (suffix + 3)
		: strdup (suffix);
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
		? strdup (suffix + 3)
		: strdup (suffix);
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
		if (! (rc = r_file_move (inp, arg))) {
			R_LOG_ERROR ("Cannot move file");
		}
	} else {
		eprintf ("Usage: mv src dst\n");
	}
	free (inp);
	return rc;
}
