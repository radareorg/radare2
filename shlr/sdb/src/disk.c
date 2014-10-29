/* sdb - LGPLv3 - Copyright 2013-2014 - pancake */

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include "sdb.h"

#if __WINDOWS__
#define r_sys_mkdir(x) (CreateDirectory(x,NULL)!=0)
#ifndef ERROR_ALREADY_EXISTS
#define ERROR_ALREADY_EXISTS 183
#endif
#define r_sys_mkdir_failed() (GetLastError () != 183)
#else
#define r_sys_mkdir(x) (mkdir(x,0755)!=-1)
#define r_sys_mkdir_failed() (errno != EEXIST)
#endif

// TODO: move into util.c ?
static inline int r_sys_rmkdir(char *dir) {
        char *ptr = dir;
        if (*ptr==DIRSEP) ptr++;
        while ((ptr = strchr (ptr, DIRSEP))) {
                *ptr = 0;
                if (!r_sys_mkdir (dir) && r_sys_mkdir_failed ()) {
                        eprintf ("r_sys_rmkdir: fail %s\n", dir);
			*ptr = DIRSEP;
                        return 0;
                }
                *ptr = DIRSEP;
                ptr++;
        }
        return 1;
}

SDB_API int sdb_disk_create (Sdb* s) {
	int nlen;
	char *str;
	if (!s || !s->dir || s->fdump != -1)
		return 0; // cannot re-create
	free (s->ndump);
	s->ndump = NULL;
	nlen = strlen (s->dir);
	str = malloc (nlen+5);
	if (!str) return 0;
	memcpy (str, s->dir, nlen+1);
	r_sys_rmkdir (str);
	memcpy (str+nlen, ".tmp", 5);
	s->fdump = open (str, O_BINARY|O_RDWR|O_CREAT|O_TRUNC, SDB_MODE);
	if (s->fdump == -1) {
		eprintf ("sdb: Cannot open '%s' for writing.\n", str);
		free (str);
		return 0;
	}
	cdb_make_start (&s->m, s->fdump);
	s->ndump = str;
	return 1;
}

SDB_API int sdb_disk_insert(Sdb* s, const char *key, const char *val) {
	struct cdb_make *c = &s->m;
	if (!key || !val) return 0;
	//if (!*val) return 0; //undefine variable if no value
	return cdb_make_add (c, key, strlen (key)+1, val, strlen (val)+1);
}

#define IFRET(x) if(x)ret=0
SDB_API int sdb_disk_finish (Sdb* s) {
	int ret = 1;
	IFRET (!cdb_make_finish (&s->m));
#if USE_MMAN
	IFRET (fsync (s->fdump));
#endif
	IFRET (close (s->fdump));
	s->fdump = -1;
	IFRET (rename (s->ndump, s->dir));
	free (s->ndump);
	s->ndump = NULL;
	return ret;
}

SDB_API int sdb_disk_unlink (Sdb *s) {
	if (s->dir && *(s->dir))
		if (unlink (s->dir) != -1)
			return 1;
	return 0;
}
