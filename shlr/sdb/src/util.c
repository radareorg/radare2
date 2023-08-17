/* sdb - MIT - Copyright 2011-2022 - pancake */

#include "sdb/sdb.h"

#define FORCE_COLLISION 0

#if USE_MONOTONIC_CLOCK
#include <time.h>
#else

#ifdef _MSC_VER
#pragma message ("gettimeofday: Windows support is ugly here")
#include <windows.h>
#include <time.h>

struct timezone {
	int tz_minuteswest; /* minutes W of Greenwich */
	int tz_dsttime;     /* type of dst correction */
};

SDB_API int gettimeofday(struct timeval* p, struct timezone * tz) {
	//ULARGE_INTEGER ul; // As specified on MSDN.
	ut64 ul = 0;
	static bool tzflag = false;
	FILETIME ft;
	if (p) {
		// Returns a 64-bit value representing the number of
		// 100-nanosecond intervals since January 1, 1601 (UTC).
		GetSystemTimeAsFileTime (&ft);
		// Fill ULARGE_INTEGER low and high parts.
		//ul.LowPart = ft.dwLowDateTime;
		//ul.HighPart = ft.dwHighDateTime;
		ul |= ft.dwHighDateTime;
		ul <<= 32;
		ul |= ft.dwLowDateTime;
		// Convert to microseconds.
		//ul.QuadPart /= 10ULL;
		ul /= 10;
		// Remove Windows to UNIX Epoch delta.
		//ul.QuadPart -= 11644473600000000ULL;
		ul -= 11644473600000000ULL;
		// Modulo to retrieve the microseconds.
		//p->tv_usec = (long)(ul.QuadPart % 1000000LL);
		// Divide to retrieve the seconds.
		//p->tv_sec = (long)(ul.QuadPart / 1000000LL);
		p->tv_sec = (long)(ul / 1000000LL);
		p->tv_usec = (long)(ul % 1000000LL);
	}
	if (tz) {
		if (!tzflag) {
			_tzset ();
			tzflag = true;
		}
		tz->tz_minuteswest = _timezone / 60;
		tz->tz_dsttime = _daylight;
	}
	return 0;
}

#else
#include <sys/time.h>
#endif
#endif

#if !SDB_INLINE_HASH
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
			SDB_HASH_ONELINER;
			// h = (h + (h << 5)) ^ *s++; // 2.22s
			// h = (h ^ (h << 1)) + *s++; // 2.15s
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
#endif

SDB_API ut8 sdb_hash_byte(const char *s) {
	const ut32 hash = sdb_hash_len (s, NULL);
	const ut8 *h = (const ut8*)&hash;
	return h[0] ^ h[1] ^ h[2] ^ h[3];
}

SDB_API char *sdb_itoa(ut64 n, int base, char *os, int oslen) {
	if (base == 0) {
		base = SDB_NUM_BASE;
	}
	static const char *const lookup = "0123456789abcdef";
	char tmpbuf[64], *s = NULL;
	int sl, copy_string = 1;
	if (os) {
		*os = 0;
		s = os;
		sl = oslen;
	} else {
		s = tmpbuf;
		sl = sizeof (tmpbuf);
	}
	const int imax = sl - 2;
	int i = imax;
	if (base < 0) {
		copy_string = 0;
		base = -base;
	}
	if (base > 16) {
		return NULL;
	}
	if (!n) {
		if (!os) {
			return sdb_strdup ("0");
		}
		if (sl > 1) {
			memcpy (os, "0", 2);
		} else {
			*os = 0;
		}
		return os;
	}
	s[imax + 1] = '\0';
	if (base <= 10) {
		for (; n && i > 0; n /= base) {
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
	if (!os) {
		return sdb_strdup (s + i + 1);
	}
	if (copy_string) {
		// unnecessary memmove in case we use the return value
		// return s + i + 1;
		int a = strlen (s + i + 1) + 1;
		int len = R_MIN (a, sl);
		memmove (os, s + i + 1, len);
		return os;
	}
	return os + i + 1;
}

SDB_API char *sdb_itoas(ut64 n, int base) {
	return sdb_itoa (n, base, NULL, 0);
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
	if (*p) {
		len++;
	}
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

SDB_API const char *sdb_const_anext(const char *str) {
	const char *p = strchr (str, SDB_RS);
	return p ? p + 1 : NULL;
}

SDB_API ut64 sdb_now (void) {
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

SDB_API ut64 sdb_unow (void) {
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
