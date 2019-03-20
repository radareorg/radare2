/* radare - LGPL - Copyright 2013-2019 - pancake */

#include "spp.h"
#include "r_api.h"

SStrBuf *r_strbuf_new(const char *str) {
	SStrBuf *s = R_NEW0 (SStrBuf);
	if (str) r_strbuf_set (s, str);
	return s;
}

void r_strbuf_init(SStrBuf *sb) {
	memset (sb, 0, sizeof (SStrBuf));
}

bool r_strbuf_set(SStrBuf *sb, const char *s) {
	int l;
	if (!sb) return false;
	if (!s) {
		r_strbuf_init (sb);
		return true;
	}
	l = strlen (s);
	if (l >= sizeof (sb->buf)) {
		char *ptr = sb->ptr;
		if (!ptr || l+1 > sb->ptrlen) {
			ptr = malloc (l + 1);
			if (!ptr) return false;
			sb->ptrlen = l + 1;
			sb->ptr = ptr;
		}
		memcpy (ptr, s, l+1);
	} else {
		sb->ptr = NULL;
		memcpy (sb->buf, s, l+1);
	}
	sb->len = l;
	return true;
}

int r_strbuf_append(SStrBuf *sb, const char *s) {
	int l = strlen (s);
	if (l < 1) {
		return false;
	}
	if ((sb->len + l + 1) < sizeof (sb->buf)) {
		memcpy (sb->buf + sb->len, s, l + 1);
		R_FREE (sb->ptr);
	} else {
		int newlen = sb->len + l + 128;
		char *p = sb->ptr;
		bool allocated = true;
		if (!sb->ptr) {
			p = malloc (newlen);
			if (p && sb->len > 0) {
				memcpy (p, sb->buf, sb->len);
			}
		} else if (sb->len + l + 1 > sb->ptrlen) {
			p = realloc (sb->ptr, newlen);
		} else {
			allocated = false;
		}
		if (allocated) {
			if (!p) return false;
			sb->ptr = p;
			sb->ptrlen = newlen;
		}
		memcpy (p + sb->len, s, l + 1);
	}
	sb->len += l;
	return true;
}

char *r_strbuf_get(SStrBuf *sb) {
	return sb? (sb->ptr? sb->ptr: sb->buf) : NULL;
}

void r_strbuf_free(SStrBuf *sb) {
	r_strbuf_fini (sb);
	free (sb);
}

void r_strbuf_fini(SStrBuf *sb) {
	if (sb && sb->ptr)
		R_FREE (sb->ptr);
}

/* --------- */
int r_sys_setenv(const char *key, const char *value) {
#if __UNIX__ || __CYGWIN__ && !defined(MINGW32)
	if (!key) {
		return 0;
	}
	if (!value) {
		unsetenv (key);
		return 0;
	}
	return setenv (key, value, 1);
#elif __WINDOWS__
	SetEnvironmentVariable (key, (LPSTR)value);
	return 0; // TODO. get ret
#else
#warning s_sys_setenv : unimplemented for this platform
	return 0;
#endif
}
