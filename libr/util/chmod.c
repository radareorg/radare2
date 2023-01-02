/* radare - LGPL - Copyright 2011-2022 - pancake */

#include <r_util.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#if R2__UNIX__
static bool chmodr(const char *, int recursive);
static bool parsemode(const char *);
static void recurse(const char *path, int rec, bool(*fn)(const char *,int));

static char oper = '=';
static mode_t mode = 0;
#endif

R_API bool r_file_chmod(const char *file, const char *mod, int recursive) {
#if R2__UNIX__
	oper = '=';
	mode = 0;
	if (!parsemode (mod)) {
		return false;
	}
	return chmodr (file, recursive);
#else
	return false;
#endif
}

#if R2__UNIX__
/* copied from sbase/chmod.c (suckless.org) */
static bool chmodr(const char *path, int rflag) {
	struct stat st;
	int fd = open (path, O_RDONLY);
	if (fd == -1) {
		return false;
	}
	if (fstat (fd, &st) == -1) {
		close (fd);
		return false;
	}
	switch (oper) {
	case '+':
		st.st_mode |= mode;
		break;
	case '-':
		st.st_mode &= ~mode;
		break;
	case '=':
		st.st_mode = mode;
		break;
	}
#if !__wasi__
	if (fchmod (fd, st.st_mode) == -1) {
		R_LOG_ERROR ("chmod %s", path);
		close (fd);
		return false;
	}
#endif
	if (rflag) {
		recurse (path, rflag, chmodr);
	}
	close (fd);
	return true;
}

static bool parsemode(const char *str) {
	char *end;
	const char *p;
	int octal;
	mode_t mask = 0;

	octal = strtol(str, &end, 8);
	if (*end == '\0') {
		if (octal & 04000) {
			mode |= S_ISUID;
		}
		if (octal & 02000) {
			mode |= S_ISGID;
		}
		if (octal & 00400) {
			mode |= S_IRUSR;
		}
		if (octal & 00200) {
			mode |= S_IWUSR;
		}
		if (octal & 00100) {
			mode |= S_IXUSR;
		}
		if (octal & 00040) {
			mode |= S_IRGRP;
		}
		if (octal & 00020) {
			mode |= S_IWGRP;
		}
		if (octal & 00010) {
			mode |= S_IXGRP;
		}
		if (octal & 00004) {
			mode |= S_IROTH;
		}
		if (octal & 00002) {
			mode |= S_IWOTH;
		}
		if (octal & 00001) {
			mode |= S_IXOTH;
		}
		return true;
	}
	for (p = str; *p; p++) {
		switch(*p) {
		/* masks */
		case 'u':
			mask |= S_IRWXU;
			break;
		case 'g':
			mask |= S_IRWXG;
			break;
		case 'o':
			mask |= S_IRWXO;
			break;
		case 'a':
			mask |= S_IRWXU|S_IRWXG|S_IRWXO;
			break;
		/* opers */
		case '+':
		case '-':
		case '=':
			oper = *p;
			break;
		/* modes */
		case 'r':
			mode |= S_IRUSR|S_IRGRP|S_IROTH;
			break;
		case 'w':
			mode |= S_IWUSR|S_IWGRP|S_IWOTH;
			break;
		case 'x':
			mode |= S_IXUSR|S_IXGRP|S_IXOTH;
			break;
		case 's':
			mode |= S_ISUID|S_ISGID;
			break;
		/* error */
		default:
			R_LOG_ERROR ("%s: invalid mode", str);
			return false;
		}
	}
	if (mask) {
		mode &= mask;
	}
	return true;
}

static char *agetcwd(void) {
	char *buf = malloc (4096);
	if (!buf) {
		return NULL;
	}
	if (!getcwd (buf, 4096)) {
		R_LOG_ERROR ("getcwd");
	}
	return buf;
}

static void recurse(const char *path, int rec, bool(*fn)(const char *,int)) {
	char *cwd;
	struct dirent *d;
	struct stat st;
	DIR *dp;

	if (lstat (path, &st) == -1 || !S_ISDIR (st.st_mode)) {
		return;
	}
	if (!(dp = opendir (path))) {
		R_LOG_ERROR ("opendir %s", path);
		return;
	}
	cwd = agetcwd ();
	if (chdir (path) == -1) {
		R_LOG_ERROR ("chdir %s", path);
		closedir (dp);
		free (cwd);
		return;
	}
	while ((d = readdir (dp))) {
		if (strcmp (d->d_name, ".") && strcmp (d->d_name, "..")) {
			fn (d->d_name, 1);
		}
	}

	closedir (dp);
	if (chdir (cwd) == -1) {
		R_LOG_ERROR ("chdir %s", cwd);
	}
	free (cwd);
}
#endif
