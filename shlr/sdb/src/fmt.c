/* sdb - MIT - Copyright 2014-2022 - pancake */

#include "sdb/sdb.h"

// TODO: convert into a function
// TODO: Add 'a' format for array of pointers null terminated??
// XXX SLOW CONCAT
#define concat(x) if (x) { \
	int size = 2 + strlen (x? x: "")+(out? strlen (out) + 4: 0); \
	if (out) { \
		char *o = (char *)sdb_gh_realloc (out, size); \
		if (o) { \
			strcat (o, ","); \
			strcat (o, x); \
			out = o; \
		} \
	} else { \
		out = sdb_strdup (x); \
	} \
}

SDB_API char *sdb_fmt_tostr(void *p, const char *fmt) {
	char buf[SDB_NUM_BUFSZ], *e_str, *out = NULL;
	int n, len = 0;
	if (!p || !fmt) {
		return NULL;
	}
	for (; *fmt; fmt++) {
		n = 4;
		const ut8 *nbuf = ((ut8*)p) + len;
		switch (*fmt) {
		case 'b':
			concat (sdb_itoa ((ut64)*(nbuf), 10, buf, sizeof (buf)));
			break;
		case 'h':
			concat (sdb_itoa ((ut64)*((short*)nbuf), 10, buf, sizeof (buf)));
			break;
		case 'd':
			concat (sdb_itoa ((ut64)*((int*)nbuf), 10, buf, sizeof (buf)));
			break;
		case 'q':
			concat (sdb_itoa (*((ut64*)nbuf), 10, buf, sizeof (buf)));
			n = 8;
			break;
		case 'z':
			concat ((char*)p + len);
			break;
		case 's':
			e_str = sdb_encode ((const ut8*)*((char**)nbuf), -1);
			concat (e_str);
			sdb_gh_free (e_str);
			break;
		case 'p':
			concat (sdb_itoa ((ut64)*((size_t*)(nbuf)), 16, buf, sizeof (buf)));
			n = sizeof (size_t);
			break;
		}
		len += R_MAX ((long)sizeof (void*), n); // align
	}
	return out;
}

// TODO: return false if array length != fmt length
SDB_API int sdb_fmt_tobin(const char *_str, const char *fmt, void *stru) {
	int n, idx = 0, items = 0;
	char *stru8 = (char*)stru;
	char *next, *str, *ptr, *word, *e_str;
	if (!_str || !*_str || !fmt) {
		return 0;
	}
	str = ptr = sdb_strdup (_str);
	for (; *fmt; fmt++) {
		word = sdb_anext (ptr, &next);
		if (!word || !*word) {
			break;
		}
		items++;
		n = 4; // ALIGN
		switch (*fmt) {
		case 'b': *((ut8*)(stru8 + idx)) = (ut8)sdb_atoi (word); break;
		case 'd': *((int*)(stru8 + idx)) = (int)sdb_atoi (word); break;
		case 'q': *((ut64*)(stru8 + idx)) = sdb_atoi (word); n = 8; break;
		case 'h': *((short*)(stru8 + idx)) = (short)sdb_atoi (word); break;
		case 's':
			e_str = (char*)sdb_decode (word, 0);
			*((char**)(stru8 + idx)) = e_str? e_str: sdb_strdup (word);
			break;
		case 'z':
			*((char**)(stru8 + idx)) = (char*)sdb_strdup (word);
			break;
		case 'p':
			*((void**)(stru8 + idx)) = (void*)(size_t)sdb_atoi (word);
			break;
		}
		idx += R_MAX ((long)sizeof (void*), n); // align
		if (!next) {
			break;
		}
		ptr = next;
	}
	free (str);
	return items;
}

SDB_API void sdb_fmt_free (void *stru, const char *fmt) {
	int n, len = 0;
	for (; *fmt; fmt++) {
		n = 4;
		switch (*fmt) {
		case 'p': // TODO: leak or wat
		case 'b':
		case 'h':
		case 'd':
			/* do nothing */
			break;
		case 'q':
			n = 8;
			break;
		case 'z':
		case 's':
			sdb_gh_free ((void*)*((char**)((ut8*)stru + len)));
			break;
		}
		len += R_MAX ((long)sizeof (void*), n); // align
	}
}

SDB_API int sdb_fmt_init (void *p, const char *fmt) {
	int len = 0;
	for (; *fmt; fmt++) {
		switch (*fmt) {
		case 'b': len += sizeof (ut8); break;   // 1
		case 'h': len += sizeof (short); break; // 2
		case 'd': len += sizeof (ut32); break;  // 4
		case 'q': len += sizeof (ut64); break;  // 8
		case 'z': len += sizeof (char*); break; // void*
		case 's': len += sizeof (char*); break; // void*
		case 'p': len += sizeof (char*); break; // void *
		}
	}
	if (p) {
		memset (p, 0, len);
	}
	return len;
}

static const char *sdb_anext2(const char *str, const char **next) {
	const char *p = strchr (str, SDB_RS);
	const char *nxt = (p) ?  p + 1: NULL;
	if (next) {
		*next = nxt;
	}
	return str;
}

// TODO: move this into fmt?
SDB_API ut64* sdb_fmt_array_num(const char *list) {
	ut64 *retp, *ret = NULL;
	ut32 size;
	const char *next, *ptr = list;
	if (list && *list) {
		ut32 len = (ut32) sdb_alen (list);
		size = sizeof (ut64) * (len + 1);
		if (size < len) {
			return NULL;
		}
		retp = ret = (ut64*) sdb_gh_malloc (size);
		if (!ret) {
			return NULL;
		}
		*retp++ = len;
		do {
			const char *str = sdb_anext2 (ptr, &next);
			ut64 n = sdb_atoi (str);
			*retp++ = n;
			ptr = next;
		} while (next);
	}
	return ret;
}

SDB_API char** sdb_fmt_array(const char *list) {
	char *_s, **retp, **ret = NULL;
	const char *next, *ptr = list;
	if (list && *list) {
		int len = sdb_alen (list);
		retp = ret = (char**) sdb_gh_malloc (2 * strlen (list) +
			((len + 1) * sizeof (char *)) + 1);
		_s = (char *)ret + ((len + 1) * sizeof (char *));
		if (!ret) {
			return NULL;
		}
		do {
			const char *str = sdb_anext2 (ptr, &next);
			int slen = next? (next - str) - 1:
				(int)strlen (str) + 1;
			memcpy (_s, str, slen);
			_s[slen] = 0;
			*retp++ = _s;
			_s += slen + 1;
			ptr = next;
		} while (next);
		*retp = NULL;
	}
	return ret;
}
