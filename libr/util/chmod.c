/* radare - LGPL - Copyright 2011-2012 - pancake */

#include <r_util.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int chmodr(const char *, int recursive);
static int parsemode(const char *);
static void recurse(const char *path, int rec, int (*fn)(const char *,int));

static char oper = '=';
static mode_t mode = 0;

R_API int r_file_chmod (const char *file, const char *mod, int recursive) {
#if __UNIX__
	oper = '=';
	mode = 0;
	if (!parsemode (mod))
		return R_FALSE;
	return chmodr (file, recursive);
#else
	return -1;
#endif
}

#if __UNIX__
/* copied from sbase/chmod.c (suckless.org) */
int chmodr(const char *path, int rflag) {
	struct stat st;

	if (stat (path, &st) == -1)
		return 0;

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
	if (chmod (path, st.st_mode) == -1) {
		eprintf ("chmod %s:", path);
		return R_FALSE;
	}
	if (rflag)
		recurse (path, rflag, chmodr);
	return R_TRUE;
}

int parsemode(const char *str) {
	char *end;
	const char *p;
	int octal;
	mode_t mask = 0;

	octal = strtol(str, &end, 8);
	if (*end == '\0') {
		if (octal & 04000) mode |= S_ISUID;
		if (octal & 02000) mode |= S_ISGID;
		if (octal & 00400) mode |= S_IRUSR;
		if (octal & 00200) mode |= S_IWUSR;
		if (octal & 00100) mode |= S_IXUSR;
		if (octal & 00040) mode |= S_IRGRP;
		if (octal & 00020) mode |= S_IWGRP;
		if (octal & 00010) mode |= S_IXGRP;
		if (octal & 00004) mode |= S_IROTH;
		if (octal & 00002) mode |= S_IWOTH;
		if (octal & 00001) mode |= S_IXOTH;
		return R_TRUE;
	}
	for(p = str; *p; p++)
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
			eprintf ("%s: invalid mode\n", str);
			return R_FALSE;
		}
	if (mask)
		mode &= mask;
	return R_TRUE;
}

char * agetcwd(void) {
        char *buf = malloc (4096);
        if(!getcwd(buf, 4096))
                eprintf("getcwd:");
        return buf;
}

static void recurse(const char *path, int rec, int (*fn)(const char *,int)) {
        char *cwd;
        struct dirent *d;
        struct stat st;
        DIR *dp;

        if (lstat (path, &st) == -1 || !S_ISDIR (st.st_mode))
                return;
        else if (!(dp = opendir (path))) {
                eprintf ("opendir %s:", path);
		return;
	}
        cwd = agetcwd();
        if (chdir (path) == -1) {
                eprintf ("chdir %s:", path);
		closedir (dp);
		free (cwd);
		return;
	}
        while ((d = readdir (dp)))
                if (strcmp (d->d_name, ".") && strcmp (d->d_name, ".."))
                        fn (d->d_name, 1);

        closedir (dp);
        if (chdir (cwd) == -1)
                eprintf ("chdir %s:", cwd);
        free (cwd);
}
#endif
