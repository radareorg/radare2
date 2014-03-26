/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"
#include <sys/time.h>

// XXX deprecate or wtf? who uses this??
SDB_API int sdb_check_value(const char *s) {
	if (!s || *s=='$')
		return 0;
#if 0
	for (; *s; s++) {
		switch (*s) {
		case ';':
			return 0;
		}
	}
#endif
	return 1;
}

SDB_API int sdb_check_key(const char *s) {
	const char *special_chars = "\"+-=[]:$;";
	if (!s || !*s)
		return 0;
	for (; *s; s++)
		if (strchr (special_chars, *s))
			return 0;
	return 1;
}

// assert sdb_hash("hi", 2) == sdb_hash("hi", 0)
SDB_API ut32 sdb_hash(const char *s, int len) {
	ut32 h = CDB_HASHSTART;
	if (len<1) {
		while (*s)
			h = (h+(h<<5))^*s++;
	} else {
		while (len--)
			h = (h+(h<<5))^*s++;
	}
	return h;
}

// assert (sizeof (s)>64)
SDB_API char *sdb_itoa(ut64 n, char *s, int base) {
	static const char* lookup = "0123456789abcdef";
	int i = 62;
	if (!s) {
		s = malloc (64);
		if (!s) return NULL;
		memset (s, 0, 64);
	}
	s[63] = '\0';
	if (base==16) {
		for (; n && i>0; n/=16)
			s[i--] = lookup[(n % 16)];
		s[i--] = 'x';
		s[i--] = '0';
	} else {
		for (; n && i>0; n/=10)
			s[i--] = (n % 10) + '0';
	}
	return s+i+1;
}

SDB_API ut64 sdb_atoi(const char *s) {
	char *p;
	ut64 ret;
	if (!s || *s=='-')
		return 0LL;
	ret = !strncmp (s, "0x", 2)?
		strtoull (s+2, &p, 16):
		strtoull (s, &p, 10);
	if (!p) return 0LL;
	return ret;
}

// NOTE: Reuses memory. probably not bindings friendly..
SDB_API char *sdb_array_compact(char *p) {
	char *e;
	// remove empty elements
	while (*p) {
		if (!strncmp (p, ",,", 2)) {
			p++;
			for (e=p+1; *e==','; e++) {};
			memmove (p, e, strlen (e)+1);
		} else p++;
	}
	return p;
}

// NOTE: Reuses memory. probably not bindings friendly..
SDB_API char *sdb_aslice(char *out, int from, int to) {
	int len, idx = 0;
	char *str = NULL;
	char *end = NULL;
	char *p = out;
	if (from>=to)
		return NULL;
	while (*p) {
		if (idx == from)
			if (!str) str = p;
		if (idx == to) {
			end = p;
			break;
		}
		if (*p == ',')
			idx++;
		p++;
	}
	if (str) {
		if (!end)
			end = str + strlen (str);
		len = (size_t)(end-str);
		memcpy (out, str, len);
		out[len] = 0;
		return out;
	}
	return NULL;
}

// TODO: find better name for it
SDB_API int sdb_alen(const char *str) {
	int len = 1;
	const char *n, *p = str;
	if (!p|| !*p) return 0;
	for (len=0; ; len++) {
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n+1;
	}
	if (*p) len++;
	return len;
}

SDB_API char *sdb_anext(char *str, char **next) {
	char *nxt, *p = strchr (str, SDB_RS);
	if (p) { *p = 0; nxt = p+1; } else nxt = NULL;
	if (next) *next = nxt;
	return str;
}

SDB_API ut64 sdb_now () {
	struct timeval now;
	if (!gettimeofday (&now, NULL))
		return now.tv_sec;
	return 0LL;
}

SDB_API ut64 sdb_unow () {
	ut64 x;
        struct timeval now;
        if (!gettimeofday (&now, NULL)) {
		x = now.tv_sec;
		x <<= 32;
		x += now.tv_usec;
	} else x = 0LL;
	return x;
}

SDB_API int sdb_isnum (const char *s) {
	if (*s=='-') // || *s=='+')
		return 1;
	if (*s>='0' && *s<='9')
		return 1;
	return 0;
}

SDB_API int sdb_num_base (const char *s) {
	if (!s) return SDB_NUM_BASE;
	if (!strncmp (s, "0x", 2))
		return 16;
	if (*s=='0' && s[1]) return 8;
	return 10;
}
