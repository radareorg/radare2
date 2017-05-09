/* sdb - MIT - Copyright 2013-2016 - pancake */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "sdb.h"

#if __SDB_WINDOWS__
#define r_sys_mkdir(x) (CreateDirectoryA(x,NULL)!=0)
#ifndef ERROR_ALREADY_EXISTS
#define ERROR_ALREADY_EXISTS 183
#endif
#define r_sys_mkdir_failed() (GetLastError () != 183)
#else
#define r_sys_mkdir(x) (mkdir(x,0755)!=-1)
#define r_sys_mkdir_failed() (errno != EEXIST)
#endif

static inline int r_sys_mkdirp(char *dir) {
	int ret = 1;
	const char slash = DIRSEP;
	char *path = dir;
	char *ptr = path;
	if (*ptr == slash) {
		ptr++;
	}
#if __WINDOWS__
	char *p = strstr (ptr, ":\\");
	if (p) {
		ptr = p + 2;
	}
#endif
	while ((ptr = strchr (ptr, slash))) {
		*ptr = 0;
		if (!r_sys_mkdir (path) && r_sys_mkdir_failed ()) {
			eprintf ("r_sys_mkdirp: fail '%s' of '%s'\n", path, dir);
			*ptr = slash;
			return 0;
		}
		*ptr = slash;
		ptr++;
	}
	return ret;
}

SDB_API bool sdb_disk_create(Sdb* s) {
	int nlen;
	char *str;
	const char *dir;
	if (!s || s->fdump >= 0) {
		return false; // cannot re-create
	}
	if (!s->dir && s->name) {
		s->dir = strdup (s->name);
	}
	dir = s->dir ? s->dir : "./";
	R_FREE (s->ndump);
	nlen = strlen (dir);
	str = malloc (nlen + 5);
	if (!str) {
		return false;
	}
	memcpy (str, dir, nlen + 1);
	r_sys_mkdirp (str);
	memcpy (str + nlen, ".tmp", 5);
	if (s->fdump != -1) {
		close (s->fdump);
	}
	s->fdump = open (str, O_BINARY | O_RDWR | O_CREAT | O_TRUNC, SDB_MODE);
	if (s->fdump == -1) {
		eprintf ("sdb: Cannot open '%s' for writing.\n", str);
		free (str);
		return false;
	}
	cdb_make_start (&s->m, s->fdump);
	s->ndump = str;
	return true;
}

SDB_API int sdb_disk_insert(Sdb* s, const char *key, const char *val) {
	struct cdb_make *c = &s->m;
	if (!key || !val) {
		return 0;
	}
	//if (!*val) return 0; //undefine variable if no value
	return cdb_make_add (c, key, strlen (key), val, strlen (val));
}

#define IFRET(x) if (x) ret = 0
SDB_API bool sdb_disk_finish (Sdb* s) {
	bool reopen = false, ret = true;
	IFRET (!cdb_make_finish (&s->m));
#if USE_MMAN
	IFRET (fsync (s->fdump));
#endif
	IFRET (close (s->fdump));
	s->fdump = -1;
	// close current fd to avoid sharing violations
	if (s->fd != -1) {
		close (s->fd);
		s->fd = -1;
		reopen = true;
	}
#if __SDB_WINDOWS__
	if (MoveFileExA (s->ndump, s->dir, MOVEFILE_REPLACE_EXISTING)) {
		//eprintf ("Error 0x%02x\n", GetLastError ());
	}
#else
	if (s->ndump && s->dir) {
		IFRET (rename (s->ndump, s->dir));
	}
#endif
	free (s->ndump);
	s->ndump = NULL;
	// reopen if was open before
	reopen = true; // always reopen if possible
	if (reopen) {
		int rr = sdb_open (s, s->dir);
		if (ret && rr < 0) {
			ret = false;
		}
		cdb_init (&s->db, s->fd);
	}
	return ret;
}

SDB_API bool sdb_disk_unlink (Sdb *s) {
	return (s->dir && *(s->dir) && unlink (s->dir) != -1);
}
