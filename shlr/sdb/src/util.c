/* sdb - MIT - Copyright 2011-2015 - pancake */

#include "sdb.h"

#if USE_MONOTONIC_CLOCK
#include <time.h>
#else
#include <sys/time.h>
#endif

// XXX deprecate or wtf? who uses this??
SDB_API int sdb_check_value(const char *s) {
	if (!s || *s == '$')
		return 0;
	// TODO: check value length
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

SDB_API bool sdb_check_key(const char *s) {
	if (!s || !*s) {
		return false;
	}
	const char *last = s + SDB_KSZ - 1;
	for (; *s; s++) {
		char c = *s;
		if (!c) {
			return true;
		}
		if (s == last) {
			return false;
		}
		switch (c) {
		case '"':
		case '+':
		case '-':
		case '=':
		case '[':
		case ']':
		case ':':
		case '$':
		case ';':
			return false;
		}
	}
	return true;
}

SDB_API ut32 sdb_hash(const char *s) {
	ut32 h = CDB_HASHSTART;
	if (s)
		while (*s)
			h = (h + (h << 5)) ^* s++;
	return h;
}

SDB_API ut32 sdb_hash_len(const char *s, ut32 *len) {
	ut32 h = CDB_HASHSTART;
	ut32 count = 0;
	if (s) {
		while (*s) {
			h = (h + (h << 5)) ^* s++;
			count++;
		}
	}
	if (len) {
		*len = count;
	}
	return h;
}

// assert (sizeof (s)>64)
// if s is null, the returned pointer must be freed!!
SDB_API char *sdb_itoa(ut64 n, char *s, int base) {
	static const char* lookup = "0123456789abcdef";
	char tmpbuf[64], *os = NULL;
	const int imax = 62;
	int i = imax, copy_string = 1;
	if (s) {
		*s = 0;
	} else {
		os = s = tmpbuf;
	}
	if (base < 0) {
		copy_string = 0;
		base = -base;
	}
	if ((base > 16) || (base < 1))
		return NULL;
	if (!n) {
		if (os) s = strdup ("0");
		else strcpy (s, "0");
		return s;
	}
	s[imax+1] = '\0';
	if (base <= 10) {
		for (; n && i>0; n /= base)
			s[i--] = (n % base) + '0';
	} else {
		for (; n && i > 0; n /= base)
			s[i--] = lookup[(n % base)];
		if (i!=imax)
			s[i--] = 'x';
		s[i--] = '0';
	}
	if (os) {
		return strdup (s+i+1);
	}
	if (copy_string) {
		// unnecessary memmove in case we use the return value
		// return s + i + 1;
		memmove (s, s + i + 1, strlen (s + i + 1) + 1);
		return s;
	}
	return s + i + 1;
}

SDB_API ut64 sdb_atoi(const char *s) {
	char *p;
	ut64 ret;
	if (!s || *s == '-')
		return 0LL;
	ret = strtoull (s, &p, 0);
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
			for (e = p + 1; *e == ','; e++) {};
			memmove (p, e, strlen (e) + 1);
		} else {
			p++;
		}
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
// TODO: optimize, because this is the main bottleneck for sdb_array_set()
SDB_API int sdb_alen(const char *str) {
	int len = 1;
	const char *n, *p = str;
	if (!p|| !*p) return 0;
	for (len = 0; ; len++) {
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n+1;
	}
	return ++len;
}

SDB_API int sdb_alen_ignore_empty(const char *str) {
	int len = 1;
	const char *n, *p = str;
	if (!p || !*p) return 0;
	while (*p == SDB_RS) p++;
	for (len = 0; ; ) {
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n+1;
		if (*(p) == SDB_RS) continue;
		len++;
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

SDB_API const char *sdb_const_anext(const char *str, const char **next) {
	if (next) {
		const char *p = strchr (str, SDB_RS);
		*next = p? p+1: NULL;
	}
	return str;
}

SDB_API ut64 sdb_now () {
#if USE_MONOTINIC_CLOCK
	struct timespec ts;
	if (!clock_gettime (CLOCK_MONOTONIC, &ts))
		return ts.tv_sec;
#else
	struct timeval now;
	if (!gettimeofday (&now, NULL))
		return now.tv_sec;
#endif
	return 0LL;
}

SDB_API ut64 sdb_unow () {
	ut64 x = 0LL;
#if USE_MONOTONIC_CLOCK
	struct timespec ts;
	if (!clock_gettime (CLOCK_MONOTONIC, &ts)) {
		x = ts.tv_sec;
		x <<= 32;
		x += ts.tv_nsec/1000;
	}
#else
        struct timeval now;
        if (!gettimeofday (&now, NULL)) {
		x = now.tv_sec;
		x <<= 32;
		x += now.tv_usec;
	}
#endif
	return x;
}

SDB_API int sdb_isnum (const char *s) {
	const char vs = *s;
	return ((vs=='-' || vs=='+') || (vs>='0' && vs<='9'));
}

SDB_API int sdb_num_base (const char *s) {
	if (!s) return SDB_NUM_BASE;
	if (!strncmp (s, "0x", 2))
		return 16;
	if (*s=='0' && s[1]) return 8;
	return 10;
}

SDB_API const char *sdb_type(const char *k) {
	if (!k || !*k)
		return "undefined";
	if (sdb_isnum (k))
		return "number";
	if (sdb_isjson (k))
		return "json";
	if (strchr (k, ','))
		return "array";
	if (!strcmp (k, "true") || !strcmp (k, "false"))
		return "boolean";
	return "string";
}

// TODO: check if open and closed bracket/parenthesis matches
// TODO: check all the values
SDB_API int sdb_isjson (const char *k) {
	int level = 0;
	int quotes = 0;
	if (!k || (*k!='{' && *k != '['))
		return 0;
	for (; *k; k++) {
		if (quotes) {
			if (*k == '"')
				quotes = 0;
			continue;
		}
		switch (*k) {
		case '"':
			quotes = 1;
			break;
		case '[':
		case '{':
			level++;
			break;
		case ']':
		case '}':
			level--;
			break;
		}
	}
	if (quotes || level)
		return 0;
	return 1;
}
