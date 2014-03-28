/* sdb - LGPLv3 - Copyright 2014 - pancake */

#include "sdb.h"

// TODO: Add 'a' format for array of pointers null terminated??
// XXX SLOW CONCAT
#define concat(x) if (x) { \
	int size = 2+strlen(x)+(out?strlen(out)+4:0); \
	if (out) { char *o = realloc (out, size); \
		if (o) { strcat (o, ","); strcat (o, x); out = o; } \
	} else out = strdup (x); \
}

SDB_API char *sdb_fmt_tostr(void *p, const char *fmt) {
	char buf[128], *e_str, *out = NULL;
	int n, len = 0;

	for (; *fmt; fmt++) {
		n = 4;
		switch (*fmt) {
		case 'b':
			concat (sdb_itoa ((ut64)*((ut8*)(p+len)), buf, 10));
			break;
		case 'h':
			concat (sdb_itoa ((ut64)*((short*)(p+len)), buf, 10));
			break;
		case 'd':
			concat (sdb_itoa ((ut64)*((int*)(p+len)), buf, 10));
			break;
		case 'q':
			concat (sdb_itoa (*((ut64*)(p+len)), buf, 10));
			n = 8;
			break;
		case 's':
			e_str = sdb_encode ((const ut8*)*((char**)(p+len)), -1);
			concat (e_str);
			free (e_str);
			break;
		case 'p':
			concat (sdb_itoa ((ut64)*((size_t*)(p+len)), buf, 16));
			n = sizeof (size_t);
			break;
		}
		len += R_MAX (sizeof (void*), n); // align
	}
	return out;
}

// TODO: return false if array length != fmt length
SDB_API int sdb_fmt_tobin(const char *_str, const char *fmt, void *stru) {
	int n, idx = 0;
	char *next, *str, *ptr, *word, *e_str;
	str = ptr = strdup (_str);
	for (; *fmt; fmt++) {
		word = sdb_anext (ptr, &next);
		if (!word || !*word)
			break;
		n = 4; // ALIGN
		switch (*fmt) {
		case 'b': *((ut8*)(stru + idx)) = (ut8)sdb_atoi (word); break;
		case 'd': *((int*)(stru + idx)) = (int)sdb_atoi (word); break;
		case 'q': *((ut64*)(stru + idx)) = sdb_atoi (word); n=8; break;
		case 'h': *((short*)(stru + idx)) = (short)sdb_atoi (word); break;
		case 's':
			e_str = (char*)sdb_decode (word, 0);
			*((char**)(stru + idx)) = (char*)strdup (e_str?e_str:word);
			free (e_str);
			break;
		case 'p': *((void**)(stru + idx)) = (void*)(size_t)sdb_atoi (word);
			break;
		}
		idx += R_MAX(sizeof (void*), n); // align
		if (!next)
			break;
		ptr = next;
	}
	free (str);
	return 1;
}

SDB_API void sdb_fmt_free (void *stru, const char *fmt) {
	int n, len = 0;
	for (; *fmt; fmt++) {
		n = 4;
		switch (*fmt) {
		case 'p': // TODO: leak or wat
		case 'b':
		case 'h':
		case 'd': break;
		case 'q': n = 8; break;
		case 's': free ((void*)*((char**)(stru+len))); break;
		}
		len += R_MAX (sizeof (void*), n); // align
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
		case 's': len += sizeof (char*); break; // void*
		case 'p': len += sizeof (char*); break; // void *
		}
	}
	if (p) memset (p, 0, len);
	return len;
}
