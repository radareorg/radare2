/* radare - LGPL - Copyright 2013-2014 - pancake */

#include <r_core.h>

#define FMT_RAW  1
#define FMT_JSON 2


static void showfile(const int nth, const char *fpath, const char *name, int printfmt) {
	struct stat sb;
	const char *n = fpath;
	char *nn, *u_rwx = "";
	int sz = r_file_size (n);
	int perm, isdir, uid = 0, gid = 0;
	int fch = '-';
	if (!strncmp (fpath, "./", 2))
		fpath = fpath+2;
	if (r_file_is_directory (n)) {
		nn = r_str_concat (strdup (fpath), "/");
		isdir = 1;
	} else {
		nn = strdup (fpath);
		isdir = 0;
	}
	if (!*nn) {
		free (nn);
		return;
	}
	perm = isdir? 0755: 0644;
	if (!printfmt) {
		r_cons_printf ("%18s%s", nn, (nth%4)?"  ":"\n");
		free (nn);
		return;
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
		if (!(u_rwx = strdup(r_str_rwx_i(perm>>6)))) {
			free(nn);
			return;
		}
		if (sb.st_mode & S_ISUID)
			u_rwx[2] = (sb.st_mode & S_IXUSR) ? 's' : 'S';
		if (isdir) fch = 'd';
		else
			switch (ifmt) {
			case S_IFCHR: fch = 'c'; break;
			case S_IFBLK: fch = 'b'; break;
			case S_IFLNK: fch = 'l'; break;
			case S_IFIFO: fch = 'p'; break;
			case S_IFSOCK: fch = 's'; break;
			}
	}
#else
	fch = isdir? 'd': '-';
#endif
	if (printfmt == FMT_RAW) {
		r_cons_printf ("%c%s%s%s  1 %4d:%-4d  %-8d  %s\n",
		isdir?'d':fch,
		      u_rwx,
		      r_str_rwx_i ((perm>>3)&7),
		      r_str_rwx_i (perm&7),
		      uid, gid, sz, nn);
	} else if (printfmt == FMT_JSON) {
		if (nth > 0) r_cons_printf(",");
		r_cons_printf("{\"name\":\"%s\",\"size\":%d,\"uid\":%d,"
			"\"gid\":%d,\"perm\":%d,\"isdir\":%s}",
			name, sz, uid, gid, perm, isdir?"true":"false");
	}
	free (nn);
	free(u_rwx);
}

// TODO: Move into r_util .. r_print maybe? r_cons dep is anoying
R_API void r_core_syscmd_ls(const char *input) {
	const char *path = ".";
	int printfmt = 0;
	RListIter *iter;
	RList *files;
	char *name;
	char *dir;
	if (r_sandbox_enable (0)) {
		eprintf ("Sandbox forbids listing directories\n");
		return;
	}
	if (input[1]==' ') {
		if ((!strncmp (input+2, "-l", 2)) || (!strncmp (input+2, "-j", 2))) {
			if (input[3]) {
				printfmt = (input[3] == 'j') ? FMT_JSON : FMT_RAW;
				path = input+4;
				while (*path==' ') path++;
				if (!*path) path = ".";
			}
		} else path = input+2;
	}
	if (r_file_is_regular (path)) {
		showfile (0, path, path, printfmt);
		return;
	}
	files = r_sys_dir (path);

	if (path[strlen(path)-1] == '/')
		dir = strdup (path);
	else
		dir = r_str_concat (strdup (path), "/");
	int nth = 0;
	if (printfmt == FMT_JSON) r_cons_printf("[");
	r_list_foreach (files, iter, name) {
		char *n = r_str_concat (strdup (dir), name);
		if (!n) break;
		if (*n) showfile (nth, n, name, printfmt);
		free (n);
		nth++;
	}
	if (printfmt == FMT_JSON) r_cons_printf("]");
	free (dir);
	r_list_free (files);
}

R_API void r_core_syscmd_cat(const char *file) {
	int sz;
	const char *p = strchr (file, ' ');
	if (p) {
		char *data, *filename = strdup (p+1);
		filename = r_str_chop (filename);
		data = r_file_slurp (filename, &sz);
		if (data) {
			r_cons_memcat (data, sz);
			free (data);
		} else eprintf ("No such file or directory\n");
		free (filename);
	} else eprintf ("Usage: cat [file]\n");
}
