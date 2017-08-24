/* radare - LGPL - Copyright 2013-2017 - pancake */

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
	if (printfmt == FMT_RAW) {
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
			name, sz, uid, gid, perm, isdir?"true":"false");
	}
	free (nn);
	free (u_rwx);
	return res;
}

// TODO: Move into r_util .. r_print maybe? r_cons dep is anoying
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
	if (r_sandbox_enable (0)) {
		eprintf ("Sandbox forbids listing directories\n");
		return NULL;
	}
	if (*input && input[0] == ' ') {
		input++;
	}
	if (*input) {
		if ((!strncmp (input, "-l", 2)) || (!strncmp (input, "-j", 2))) {
			// mode = 'l';
			if (input[2]) {
				printfmt = (input[2] == 'j') ? FMT_JSON : FMT_RAW;
				path = input + 2;
				while (*path == ' ') {
					path++;
				}
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
	} else if (*path == '~') {
		homepath = r_str_home (path + 2);
		if (homepath) {
			path = (const char *)homepath;
		}
	} else if (*path == '$') {
		if (!strncmp (path + 1, "home", 4) || !strncmp (path + 1, "HOME", 4)){
			homepath = r_str_home ((strlen (path)>5)? path + 6: NULL);
			if (homepath) {
				path = (const char *)homepath;
			}
		}
	}
	if (!r_file_is_directory (path)) {
		p = strrchr (path, '/');
		if (p){
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
		filename = r_str_chop (filename);
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
	bool show_help = true;
	const char *p = strchr (dir, ' ');
	if (p) {
		int ret;
		char *dirname;
		if (!strncmp (p + 1, "-p ", 3)) {
			dirname = r_str_chop (strdup (p + 3));
			ret = r_sys_mkdirp (dirname);
		} else {
			dirname = r_str_chop (strdup (p + 1));
			ret = r_sys_mkdir (dirname);
		}
		if (!ret) {
			if (r_sys_mkdir_failed ()) {
				eprintf ("Cannot create \"%s\"\n", dirname);
			}
		}
		free (dirname);
		show_help = false;
	}
	if (show_help) {
		eprintf ("Usage: mkdir [-p] [directory]\n");
	}
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
