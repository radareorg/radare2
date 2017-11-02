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

#if UNICODE
static wchar_t* r_str_mb_to_wc_l(const char *buf, int len) {
	wchar_t *res_buf = NULL;
	size_t sz;
	bool fail = true;

	if (!buf || len <= 0) {
		return NULL;
	}
	sz = mbstowcs (NULL, buf, len);
	if (sz == (size_t)-1) {
		goto err_r_str_mb_to_wc;
	}
	res_buf = (wchar_t *)calloc (1, (sz + 1) * sizeof (wchar_t));  
    	if (!res_buf) {
		goto err_r_str_mb_to_wc;
	}
	sz = mbstowcs (res_buf, buf, sz + 1);
	if (sz == (size_t)-1) {
		goto err_r_str_mb_to_wc;
	}
	fail = false;
err_r_str_mb_to_wc:
	if (fail) {
		free (res_buf);
		res_buf = NULL;
	}
	return res_buf;
}

static wchar_t* r_str_mb_to_wc(const char *buf) {
	if (!buf) {
		return NULL;
	}
	return r_str_mb_to_wc_l (buf, strlen (buf));
}

#define r_sys_conv_utf8_to_utf16(buf) r_str_mb_to_wc (buf)

static bool r_sys_mkdir(char *path) {
	LPTSTR path_ = r_sys_conv_utf8_to_utf16 (path);
	bool ret = CreateDirectory (path_, NULL);

	free (path);
	return ret;
}
#else
#define r_sys_conv_utf8_to_utf16(buf) strdup (buf) 
#define r_sys_mkdir(x) CreateDirectory (x, NULL)
#endif
#ifndef ERROR_ALREADY_EXISTS
#define ERROR_ALREADY_EXISTS 183
#endif
#define r_sys_mkdir_failed() (GetLastError () != 183)
#else
#define r_sys_mkdir(x) (mkdir (x,0755)!=-1)
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
	LPTSTR ndump_ = r_sys_conv_utf8_to_utf16 (s->ndump);
	LPTSTR dir_ = r_sys_conv_utf8_to_utf16 (s->dir);

	if (MoveFileEx (ndump_, dir_, MOVEFILE_REPLACE_EXISTING)) {
		//eprintf ("Error 0x%02x\n", GetLastError ());
	}
	free (ndump_);
	free (dir_);
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
