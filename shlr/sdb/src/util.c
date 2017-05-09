/* sdb - MIT - Copyright 2011-2017 - pancake */

#include "sdb.h"

#define FORCE_COLLISION 0

#if USE_MONOTONIC_CLOCK
#include <time.h>
#else
#ifdef _MSC_VER
#pragma message ("gettimeofday: Windows support is ugly here")
#include <windows.h>
int gettimeofday (struct timeval* p, void* tz) {
	ULARGE_INTEGER ul; // As specified on MSDN.
	FILETIME ft;

	// Returns a 64-bit value representing the number of
	// 100-nanosecond intervals since January 1, 1601 (UTC).
	GetSystemTimeAsFileTime (&ft);

	// Fill ULARGE_INTEGER low and high parts.
	ul.LowPart = ft.dwLowDateTime;
	ul.HighPart = ft.dwHighDateTime;
	// Convert to microseconds.
	ul.QuadPart /= 10ULL;
	// Remove Windows to UNIX Epoch delta.
	ul.QuadPart -= 11644473600000000ULL;
	// Modulo to retrieve the microseconds.
	p->tv_usec = (long)(ul.QuadPart % 1000000LL);
	// Divide to retrieve the seconds.
	p->tv_sec = (long)(ul.QuadPart / 1000000LL);

	return 0;
}

#else
#include <sys/time.h>
#endif
#endif

SDB_API ut32 sdb_hash_len(const char *s, ut32 *len) {
	ut32 h = CDB_HASHSTART;
#if FORCE_COLLISION
	h = 0;
	while (*s) {
		h += *s;
		s++;
	}
#else
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
#endif
	return h;
}

SDB_API ut32 sdb_hash(const char *s) {
	return sdb_hash_len (s, NULL);
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
	if ((base > 16) || (base < 1)) {
		return NULL;
	}
	if (!n) {
		if (os) {
			return strdup ("0");
		}
		strcpy (s, "0");
		return s;
	}
	s[imax + 1] = '\0';
	if (base <= 10) {
		for (; n && i>0; n /= base) {
			s[i--] = (n % base) + '0';
		}
	} else {
		for (; n && i > 0; n /= base) {
			s[i--] = lookup[(n % base)];
		}
		if (i != imax) {
			s[i--] = 'x';
		}
		s[i--] = '0';
	}
	if (os) {
		return strdup (s + i + 1);
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
	if (!s || *s == '-') {
		return 0LL;
	}
	ret = strtoull (s, &p, 0);
	return p ? ret: 0LL;
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
	if (from >= to) {
		return NULL;
	}
	while (*p) {
		if (!str && idx == from) {
			str = p;
		}
		if (idx == to) {
			end = p;
			break;
		}
		if (*p == ',') {
			idx++;
		}
		p++;
	}
	if (str) {
		if (!end) {
			end = str + strlen (str);
		}
		len = (size_t)(end - str);
		memmove (out, str, len);
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
	if (!p|| !*p) {
		return 0;
	}
	for (len = 0; ; len++) {
		n = strchr (p, SDB_RS);
		if (!n) {
			break;
		}
		p = n + 1;
	}
	return ++len;
}

SDB_API int sdb_alen_ignore_empty(const char *str) {
	int len = 1;
	const char *n, *p = str;
	if (!p || !*p) {
		return 0;
	}
	while (*p == SDB_RS) {
		p++;
	}
	for (len = 0; ; ) {
		n = strchr (p, SDB_RS);
		if (!n) {
			break;
		}
		p = n + 1;
		if (*(p) == SDB_RS) {
			continue;
		}
		len++;
	}
	if (*p) len++;
	return len;
}

SDB_API char *sdb_anext(char *str, char **next) {
	char *nxt, *p = strchr (str, SDB_RS);
	if (p) {
		*p = 0;
		nxt = p + 1;
	} else {
		nxt = NULL;
	}
	if (next) {
		*next = nxt;
	}
	return str;
}

SDB_API const char *sdb_const_anext(const char *str, const char **next) {
	if (next) {
		const char *p = strchr (str, SDB_RS);
		*next = p? p + 1: NULL;
	}
	return str;
}

SDB_API ut64 sdb_now () {
#if USE_MONOTONIC_CLOCK
	struct timespec ts;
	if (!clock_gettime (CLOCK_MONOTONIC, &ts)) {
		return ts.tv_sec;
	}
#else
	struct timeval now;
	if (!gettimeofday (&now, NULL)) {
		return now.tv_sec;
	}
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
		x += ts.tv_nsec / 1000;
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

SDB_API int sdb_isnum(const char *s) {
	const char vs = *s;
	return ((vs == '-' || vs == '+') || (vs >= '0' && vs <= '9'));
}

SDB_API int sdb_num_base(const char *s) {
	if (!s) {
		return SDB_NUM_BASE;
	}
	if (!strncmp (s, "0x", 2)) {
		return 16;
	}
	return (*s=='0' && s[1]) ? 8: 10;
}

SDB_API const char *sdb_type(const char *k) {
	if (!k || !*k) {
		return "undefined";
	}
	if (sdb_isnum (k)) {
		return "number";
	}
	if (sdb_isjson (k)) {
		return "json";
	}
	if (strchr (k, ',')) {
		return "array";
	}
	if (!strcmp (k, "true") || !strcmp (k, "false")) {
		return "boolean";
	}
	return "string";
}

// TODO: check all the values
SDB_API bool sdb_isjson (const char *k) {
	int level = 0;
	bool quotes = false;
	if (!k || (*k != '{' && *k != '[')) {
		return false;
	}
	for (; *k; k++) {
		if (quotes) {
			if (*k == '"') {
				quotes = false;
			}
			continue;
		}
		switch (*k) {
		case '"':
			quotes = true;
			break;
		case '[':
		case '{':
			level++;
			break;
		case ']':
		case '}':
			level--;
			if (level < 0) {
				/* invalid json */
				return false;
			}
			break;
		}
	}
	return (!quotes && !level);
}
