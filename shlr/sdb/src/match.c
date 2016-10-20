/* sdb - MIT - Copyright 2015-2016 - pancake */

#include "sdb.h"
#include <ctype.h>

static inline int haveSuffix(const char *glob, int glob_len, const char *sfx) {
	const int sfx_len = strlen (sfx);
	return (glob_len>sfx_len && !strcmp (glob+glob_len-sfx_len, sfx));
}

static inline int havePrefix(const char *glob, int glob_len, const char *pfx) {
	const int pfx_len = strlen (pfx);
	return (pfx_len<glob_len && !strncmp (glob, pfx, pfx_len));
}

enum MatchFlag {
	SDB_LIKE_NONE = 0,
	SDB_LIKE_ICASE = 1, // ?i
	SDB_LIKE_START = 2, // ^
	SDB_LIKE_END = 4,   // $
	SDB_LIKE_BASE64 = 8 // %
};

static inline int mycmp(const char *a, const char *b, int n, int any) {
	int i, j;
	for (i = j = 0; a[i] && b[j] && j < n; i++) {
		if (tolower ((const ut8)a[i]) == tolower ((const ut8)b[j])) {
			j++;
		} else {
			if (!any) {
				return 0;
			}
			j = 0;
		}
	}
	return any? j != n: 1;
}

static inline int strstr2(const char *a, const char *b, int n) {
	int i, j;
	for (i = j = 0; a[i] && b[j] && j < n; i++) {
		if (a[i] == b[j]) {
			j++;
		} else {
			j = 0;
		}
	}
	return j == n;
}

static inline bool compareString(const char *a, const char *b, int blen, int flags) {
	const int start = flags & SDB_LIKE_START;
	const int end = flags & SDB_LIKE_END;
	char *aa = NULL;
	int alen;
	bool ret = false;
	if (!a || !b || blen < 0) {
		return 0;
	}
	if (flags & SDB_LIKE_BASE64) {
		aa = (char*)sdb_decode (a, &alen);
		if (!aa) {
			return 0;
		}
		a = (const char *)aa;
	} else {
		alen = strlen (a);
	}
	if (blen <= alen) {
		if (flags & SDB_LIKE_ICASE) {
			if (start && end) ret = (alen==blen && !mycmp (a, b, blen, 0));
			else if (start) ret = !mycmp (a, b, blen, 0);
			else if (end) ret = !mycmp (a+(alen-blen), b, blen, 0);
			else ret = !mycmp (a, b, blen, 1);
		} else {
			if (start && end) ret = (alen==blen && !strncmp (a, b, blen));
			else if (start) ret = !strncmp (a, b, blen);
			else if (end) ret = !strncmp (a+(alen-blen), b, blen);
			else ret = strstr2 (a, b, blen);
		}
	}
	free (aa);
	return ret;
}

SDB_API bool sdb_match (const char *str, const char *glob) {
	int glob_len, flags = SDB_LIKE_NONE;
	if (!str || !glob) {
		return false;
	}
	glob_len = strlen (glob);
	if (haveSuffix (glob, glob_len, "?i")) {
		glob_len -= 2;
		flags |= SDB_LIKE_ICASE;
	}
	if (havePrefix (glob, glob_len, "%")) {
		glob++;
		glob_len--;
		flags |= SDB_LIKE_BASE64;
	}
	if (havePrefix (glob, glob_len, "^")) {
		glob++;
		glob_len--;
		flags |= SDB_LIKE_START;
	}
	if (haveSuffix (glob, glob_len, "$")) {
		glob_len--;
		flags |= SDB_LIKE_END;
	}
	return compareString (str, glob, glob_len, flags);
}
