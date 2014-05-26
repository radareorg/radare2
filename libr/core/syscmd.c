/* radare - LGPL - Copyright 2013-2014 - pancake */

#include <r_core.h>

static void showfile(const int nth, const char *name, int minusl) {
	struct stat sb;
	const char *n = name;
	char *nn;
	int sz = r_file_size (n);
	int perm, isdir, uid = 0, gid = 0;
	int fch = '-';
	if (!strncmp (name, "./", 2))
		name = name+2;
	if (r_file_is_directory (n)) {
		nn = r_str_concat (strdup (name), "/");
		isdir = 1;
	} else {
		nn = strdup (name);
		isdir = 0;
	}
	if (!*nn) {
		free (nn);
		return;
	}
	perm = isdir? 0755: 0644;
	if (!minusl) {
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
	r_cons_printf ("%c%s%s%s  1 %4d:%-4d  %-8d  %s\n",
		isdir?'d':fch,
		      r_str_rwx_i (perm>>6),
		      r_str_rwx_i ((perm>>3)&7),
		      r_str_rwx_i (perm&7),
		      uid, gid, sz, nn);
	free (nn);
}

// TODO: Move into r_util .. r_print maybe? r_cons dep is anoying
R_API void r_core_syscmd_ls(const char *input) {
	const char *path = ".";
	int minusl = 0;
	RListIter *iter;
	RList *files;
	char *name;
	char *dir;
	if (input[1]==' ') {
		if (!strncmp (input+2, "-l", 2)) {
			if (input[3]) {
				minusl = 1;
				path = input+4;
				while (*path==' ') path++;
				if (!*path) path = ".";
			}
		} else path = input+2;
	}
	if (r_file_is_regular (path)) {
		showfile (0, path, minusl);
		return;
	}
	files = r_sys_dir (path);

	dir = r_str_concat (strdup (path), "/");
	int nth = 0;
	r_list_foreach (files, iter, name) {
		char *n = r_str_concat (strdup (dir), name);
		if (!n) break;
		if (*n) showfile (nth, n, minusl);
		free (n);
		nth++;
	}
	free (dir);
	r_list_free (files);
}
