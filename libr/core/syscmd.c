/* radare - LGPL - Copyright 2013-2014 - pancake */
#include <r_core.h>

// TODO: Move into r_util .. r_print maybe? r_cons dep is anoying
R_API void r_core_syscmd_ls(const char *input) {
	const char *path = ".";
	char *name;
	int isdir, i = 5, minusl = 0;
	RListIter *iter;
	RList *files;
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
	files = r_sys_dir (path);

	dir = r_str_concat (strdup (path), "/");
	r_list_foreach (files, iter, name) {
		char *n = r_str_concat (strdup (dir), name);
		if (!n) break;
		if (*n) {
			char *nn;
			if (r_file_is_directory (n)) {
				nn = r_str_concat (strdup (name), "/");
				isdir = 1;
			} else {
				nn = strdup (name);
				isdir = 0;
			}
			if (*nn) {
				if (minusl) {
					// TODO: escape non-printable chars in filenames
					// TODO: Implement more real info in ls -l
					// TODO: handle suid
					struct stat sb;
					int sz = r_file_size (n);
					int uid = 0;
					int gid = 0;
					int perm = isdir? 0755: 0644;
					int fch = '-';
					if (lstat (n, &sb) != -1) {
						ut32 ifmt = sb.st_mode & S_IFMT;
						uid = sb.st_uid;
						gid = sb.st_gid;
						perm = sb.st_mode & 0777;
						if (isdir) fch = 'd'; else
						switch (ifmt) {
						case S_IFCHR: fch = 'c'; break;
						case S_IFBLK: fch = 'b'; break;
						case S_IFLNK: fch = 'l'; break;
						case S_IFIFO: fch = 'p'; break;
						case S_IFSOCK: fch = 's'; break;
						}
					}
					r_cons_printf ("%c%s%s%s  1 %4d:%-4d  %-8d  %s\n", 
						isdir?'d':fch,
						r_str_rwx_i (perm>>6),
						r_str_rwx_i ((perm>>3)&7),
						r_str_rwx_i (perm&7),
						uid, gid, sz, nn);
				} else {
					r_cons_printf ("%18s%s", nn, ((i++)%4)?"  ":"\n");
				}
			}
			free (nn);
		}
		free (n);
	}
	free (dir);
	r_list_free (files);
}
