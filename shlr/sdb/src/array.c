/* sdb - MIT - Copyright 2011-2022 - pancake */

#include "sdb/sdb.h"
#include <limits.h>

// TODO: Push should always prepend. do not make this configurable
#define PUSH_PREPENDS 1

// TODO: missing num_{inc/dec} functions

static const char *Aindexof(const char *str, int idx) {
	int len = 0;
	const char *n, *p = str;
	for (len = 0; ; len++) {
		if (len == idx) {
			return p;
		}
		if (!(n = strchr (p, SDB_RS))) {
			break;
		}
		p = n + 1;
	}
	return NULL;
}

static int astrcmp(const char *a, const char *b) {
	char va = *a;
	char vb = *b;
	for (;;) {
		if (va == '\0' || va == SDB_RS) {
			if (vb == '\0' || vb == SDB_RS) {
				return 0;
			}
			return -1;
		}
		if (vb == '\0' || vb == SDB_RS) {
			return 1;
		}
		if (va != vb) {
			return (va > vb) ? 1 : -1;
		}
		va = *(++a);
		vb = *(++b);
	}
}

static inline int cstring_cmp(const void *a, const void *b) { 
	const char **va = (const char **)a;
	const char **vb = (const char **)b;
	return astrcmp (*va, *vb);
}

static inline int int_cmp(const void *a, const void *b) { 
	const ut64 va = *(const ut64 *)a;
	const ut64 vb = *(const ut64 *)b;
	if (va > vb) {
		return 1;
	}
	if (va < vb) {
		return -1;
	}
	return 0;
} 

SDB_API ut64 sdb_array_get_num(Sdb *s, const char *key, int idx, ut32 *cas) {
	int i;
	const char *n, *str = sdb_const_get (s, key, cas);
	if (!str || !*str) {
		return 0LL;
	}
	if (idx) {
		for (i = 0; i < idx; i++) {
			n = strchr (str, SDB_RS);
			if (!n) {
				return 0LL;
			}
			str = n + 1;
		}
	}
	return sdb_atoi (str);
}

SDB_API char *sdb_array_get(Sdb *s, const char *key, int idx, ut32 *cas) {
	const char *str = sdb_const_get (s, key, cas);
	const char *p = str;
	char *o, *n;
	int i, len;
	if (!str || !*str) {
		return NULL;
	}
	if (idx < 0) {
		int alen = sdb_alen (str);
		if (-idx > alen) {
			return NULL;
		}
		idx += alen;
	}
	if (!idx) {
		n = strchr ((char *)str, SDB_RS);
		if (!n) {
			return sdb_strdup (str);
		}
		len = n - str;
		o = (char *)sdb_gh_malloc (len + 1);
		if (!o) {
			return NULL;
		}
		memcpy (o, str, len);
		o[len] = 0;
		return o;
	}
	for (i = 0; i < idx; i++) {
		n = strchr ((char *)p, SDB_RS);
		if (!n) return NULL;
		p = n + 1;
	}
	n = strchr ((char *)p, SDB_RS);
	if (!n) {
		return sdb_strdup (p);
	}
	len = n - p;
	o = (char *)sdb_gh_malloc (len + 1);
	if (o) {
		memcpy (o, p, len);
		o[len] = 0;
		return o;
	}
	return NULL;
}

SDB_API int sdb_array_insert_num(Sdb *s, const char *key, int idx, ut64 val, ut32 cas) {
	char valstr[SDB_NUM_BUFSZ];
	sdb_itoa (val, 0, valstr, sizeof (valstr));
	return sdb_array_insert (s, key, idx, valstr, cas);
}

// TODO: done, but there's room for improvement
SDB_API int sdb_array_insert(Sdb *s, const char *key, int idx, const char *val, ut32 cas) {
	int lnstr, lstr;
	size_t lval;
	char *x, *ptr;
	const char *str = sdb_const_get_len (s, key, &lstr, 0);
	if (!str || !*str) {
		return sdb_set (s, key, val, cas);
	}
	lval = strlen (val);
	lstr--;
	// XXX: lstr is wrongly computed in sdb_const_get_with an off-by-one
	// we can optimize this by caching value len in memory . add
	// sdb_const_get_size()
	lstr = strlen (str); 

	// When removing strlen this conversion should be checked
	size_t lstr_tmp = lstr;
	if (SZT_ADD_OVFCHK (lval, lstr_tmp) || SZT_ADD_OVFCHK (lval + lstr_tmp, 2)) {
		return false;
	}
	x = (char *)sdb_gh_malloc (lval + lstr_tmp + 2);
	if (!x) {
		return false;
	}

	if (idx == -1) {
		memcpy (x, str, lstr);
		x[lstr] = SDB_RS;
		memcpy (x + lstr + 1, val, lval + 1);
	} else if (!idx) {
		memcpy (x, val, lval);
		x[lval] = SDB_RS;
		memcpy (x + lval + 1, str, lstr + 1);
	} else {
		char *nstr = (char *)sdb_gh_malloc (lstr + 1);
		if (!nstr) {
			sdb_gh_free (x);
			return false;
		}
		memcpy (nstr, str, lstr + 1);
		ptr = (char *)Aindexof (nstr, idx);
		if (ptr) {
			int lptr = (nstr + lstr + 1) - ptr;
			char *p_1 = ptr > nstr? ptr - 1: ptr;
			*p_1 = 0;
			lnstr = ptr - nstr - 1;
			memcpy (x, nstr, lnstr);
			x[lnstr] = SDB_RS;
			memcpy (x + lnstr + 1, val, lval);
			x[lnstr + lval + 1] = SDB_RS;
			// TODO: this strlen hurts performance
			memcpy (x + lval + 2 + lnstr, ptr, lptr); //strlen (ptr)+1);
			sdb_gh_free (nstr);
		} else {
			// this is not efficient
			sdb_gh_free (nstr);
			sdb_gh_free (x);
			// fallback for empty buckets
			return sdb_array_set (s, key, idx, val, cas);
		}
	}
	return sdb_set_owned (s, key, x, cas);
}

SDB_API int sdb_array_set_num(Sdb *s, const char *key, int idx, ut64 val, ut32 cas) {
	char valstr[SDB_NUM_BUFSZ];
	sdb_itoa (val, 0, valstr, sizeof (valstr));
	return sdb_array_set (s, key, idx, valstr, cas);
}

SDB_API int sdb_array_add_num(Sdb *s, const char *key, ut64 val, ut32 cas) {
	char buf[SDB_NUM_BUFSZ];
	char *v = sdb_itoa (val, 0, buf, sizeof (buf));
	if (!sdb_array_contains (s, key, v, NULL)) {
		if (val < 256) {
			v = sdb_itoa (val, 10, buf, sizeof (buf));
		}
	}
	return sdb_array_add (s, key, v, cas);
}

// XXX: index should be supressed here? if its a set we shouldnt change the index
SDB_API int sdb_array_add(Sdb *s, const char *key, const char *val, ut32 cas) {
	if (sdb_array_contains (s, key, val, NULL)) {
		return 0;
	}
	return sdb_array_insert (s, key, -1, val, cas);
}

SDB_API int sdb_array_add_sorted(Sdb *s, const char *key, const char *val, ut32 cas) {
	int lstr, lval, i, j;
	const char *str_e, *str_lp, *str_p, *str = sdb_const_get_len (s, key, &lstr, 0);
	char *nstr, *nstr_p, **vals;
	const char null = '\0';
	if (!str || !*str) {
		str = &null;
		lstr = 0;
	}
	str_e = str + lstr;
	str_lp = str_p = str;
	if (!val || !*val) {
		return 1;
	}
	lval = strlen (val);
	vals = sdb_fmt_array (val);
	for (i = 0; vals[i]; i++) {
		/* empty */
	}
	if (i > 1) {
		qsort (vals, i, sizeof (ut64*), cstring_cmp);
	}
	nstr_p = nstr = (char *)sdb_gh_malloc (lstr + lval + 3);
	if (!nstr) {
		return 1;
	}
	for (i = 0; vals[i]; i++) {
		while (str_p < str_e) {
			if (astrcmp (vals[i], str_p) < 0) {
				break;
			}
			str_p = sdb_const_anext (str_p);
			if (!str_p) {
				str_p = str_e;
			}
		}
		memcpy (nstr_p, str_lp, str_p - str_lp);
		nstr_p += str_p - str_lp;
		if (str_p == str_e && str_lp != str_e) {
			*(nstr_p++) = SDB_RS;
		}
		str_lp = str_p;
		j = strlen (vals[i]);
		memcpy (nstr_p, vals[i], j);
		nstr_p += j;
		*(nstr_p++) = SDB_RS;
	}
	if (str_lp < str_e) {
		memcpy (nstr_p, str_lp, str_e - str_lp);
		nstr_p += str_e - str_lp;
		*(nstr_p) = '\0';
	} else {
		*(--nstr_p) = '\0';
	}
	sdb_set_owned (s, key, nstr, cas);
	sdb_gh_free (vals);
	return 0;
}

SDB_API int sdb_array_add_sorted_num(Sdb *s, const char *key, ut64 val, ut32 cas) {
	int i;
	char valstr[SDB_NUM_BUFSZ];
	const char *str = sdb_const_get (s, key, 0);
	const char *n = str;
	if (!str || !*str) {
		return sdb_set (s, key, sdb_itoa (val, 0, valstr, sizeof (valstr)), cas);
	}
	for (i = 0; n; i++) {
		if (val <= sdb_atoi (n)) {
			break;
		}
		n = sdb_const_anext (n);
	}
	return sdb_array_insert_num (s, key, n? i: -1, val, cas);
}

SDB_API int sdb_array_unset(Sdb *s, const char *key, int idx, ut32 cas) {
	return sdb_array_set (s, key, idx, "", cas);
}

SDB_API bool sdb_array_append(Sdb *s, const char *key, const char *val,
			       ut32 cas) {
#if SLOW
	return sdb_array_set (s, key, -1, val, cas);
#else
	int str_len = 0;
	ut32 kas = cas;
	const char *str = sdb_const_get_len (s, key, &str_len, &kas);
	if (!val || (cas && cas != kas)) {
		return false;
	}
	cas = kas;
	if (str && *str && str_len > 0) {
		int val_len = strlen (val);
		char *newval = (char *)sdb_gh_malloc (str_len + val_len + 2);
		if (!newval) {
			return false;
		}
		memcpy (newval, str, str_len);
		newval[str_len] = SDB_RS;
		memcpy (newval+str_len+1, val, val_len);
		newval[str_len+val_len+1] = 0;
		sdb_set_owned (s, key, newval, cas);
	} else {
		sdb_set (s, key, val, cas);
	}
	return true;
#endif
}

SDB_API bool sdb_array_append_num(Sdb *s, const char *key, ut64 val, ut32 cas) {
	return sdb_array_set_num (s, key, -1, val, cas);
}

SDB_API int sdb_array_set(Sdb *s, const char *key, int idx, const char *val,
			   ut32 cas) {
	int lstr, lval, len;
	const char *usr, *str = sdb_const_get_len (s, key, &lstr, 0);
	char *ptr;

	if (!str || !*str) {
		return sdb_set (s, key, val, cas);
	}
	// XXX: should we cache sdb_alen value inside kv?
	len = sdb_alen (str);
	lstr--;
	if (idx < 0 || idx == len) { // append
		return sdb_array_insert (s, key, -1, val, cas);
	}
	lval = strlen (val);
	if (idx > len) {
		int ret, i, ilen = idx-len;
		char *newkey = (char *)sdb_gh_malloc (ilen + lval + 1);
		if (!newkey) {
			return 0;
		}
		for (i = 0; i < ilen; i++) {
			newkey [i] = SDB_RS;
		}
		memcpy (newkey + i, val, lval + 1);
		ret = sdb_array_insert (s, key, -1, newkey, cas);
		sdb_gh_free (newkey);
		return ret;
	}
	//lstr = strlen (str);
	ptr = (char*)Aindexof (str, idx);
	if (ptr) {
		int diff = ptr - str;
		char *nstr = (char *)sdb_gh_malloc (lstr + lval + 2);
		if (!nstr) {
			return false;
		}
		ptr = nstr + diff;
		//memcpy (nstr, str, lstr+1);
		memcpy (nstr, str, diff);
		memcpy (ptr, val, lval + 1);
		usr = Aindexof (str, idx + 1);
		if (usr) {
			ptr[lval] = SDB_RS;
			strcpy (ptr + lval + 1, usr);
		}
		int ret = sdb_set (s, key, nstr, cas);
		sdb_gh_free (nstr);
		return ret;
	}
	return 0;
}

SDB_API int sdb_array_remove_num(Sdb *s, const char *key, ut64 val, ut32 cas) {
	const char *n, *p, *str = sdb_const_get (s, key, 0);
	int idx = 0;
	ut64 num;
	if (str) {
		for (p = str; ; idx++) {
			num = sdb_atoi (p);
			if (num == val) {
				return sdb_array_delete (s, key, idx, cas);
			}
			n = strchr (p, SDB_RS);
			if (!n) {
				break;
			}
			p = n + 1;
		}
	}
	return 0;
}

/* get array index of given value */
SDB_API int sdb_array_indexof(Sdb *s, const char *key, const char *val,
			       ut32 cas) {
	const char *str = sdb_const_get (s, key, 0);
	const char *n, *p = str;
	int i;
	for (i = 0; ; i++) {
		if (!p) {
			break;
		}
		if (!astrcmp (p, val)) {
			return i;
		}
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n + 1;
	}
	return -1;
}

// previously named del_str... pair with _add
SDB_API int sdb_array_remove (Sdb *s, const char *key, const char *val,
			      ut32 cas) {
	const char *str = sdb_const_get (s, key, 0);
	const char *n, *p = str;
	int idx;
	if (p) {
		for (idx = 0; ; idx++) {
			if (!astrcmp (p, val)) {
				return sdb_array_delete (s, key, idx, cas);
			}
			n = strchr (p, SDB_RS);
			if (!n) {
				break;
			}
			p = n + 1;
		}
	}
	return 0;
}

SDB_API int sdb_array_delete(Sdb *s, const char *key, int idx, ut32 cas) {
	int i;
	char *p, *n, *str = sdb_get (s, key, 0);
	p = str;
	if (!str || !*str) {
		sdb_gh_free (str);
		return 0;
	}
	if (idx < 0) {
		idx = sdb_alen (str);
		if (idx) idx--;
	}
	for (i = 0; i < idx; i++) {
		if ( (n = strchr (p, SDB_RS)) ) {
			p = n + 1;
		} else {
			sdb_gh_free (str);
			return 0;
		}
	}
	n = strchr (p, SDB_RS);
	if (n) {
		memmove (p, n + 1, strlen (n));
	} else {
		if (p != str) {
			p--; // remove tailing SDB_RS
		}
		*p = 0;
		p[1] = 0;
	}
	sdb_set_owned (s, key, str, cas);
	return 1;
}

// XXX Doesnt work if numbers are stored in different base
SDB_API bool sdb_array_contains_num(Sdb *s, const char *key, ut64 num, ut32 *cas) {
	char val[SDB_NUM_BUFSZ];
	char *nval = sdb_itoa (num, 0, val, sizeof (val));
	return sdb_array_contains (s, key, nval, cas);
}

SDB_API bool sdb_array_contains(Sdb *s, const char *key, const char *val, ut32 *cas) {
	if (!s || !key || !val) {
		return false;
	}
	const char *next, *ptr = sdb_const_get (s, key, cas);
	if (ptr && *ptr) {
		size_t vlen = strlen (val);
		while (1) {
			next = strchr (ptr, SDB_RS);
			size_t len = next ? (size_t)(next - ptr) : strlen (ptr);
			if (len == vlen && !memcmp (ptr, val, len)) {
				return true;
			}
			if (!next) {
				break;
			}
			ptr = next + 1;
		}
	}
	return false;
}

SDB_API int sdb_array_size(Sdb *s, const char *key) {
	return sdb_alen (sdb_const_get (s, key, 0));
}

// NOTE: ignore empty buckets
SDB_API int sdb_array_length(Sdb *s, const char *key) {
	return sdb_alen_ignore_empty (sdb_const_get (s, key, 0));
}

SDB_API int sdb_array_push_num(Sdb *s, const char *key, ut64 num, ut32 cas) {
	char buf[SDB_NUM_BUFSZ];
	char *n = sdb_itoa (num, 0, buf, sizeof (buf));
	return sdb_array_push (s, key, n, cas);
}

SDB_API bool sdb_array_push(Sdb *s, const char *key, const char *val, ut32 cas) {
#if PUSH_PREPENDS
	return sdb_array_prepend (s, key, val, cas);
#else
	return sdb_array_append (s, key, val, cas);
#endif
}

SDB_API bool sdb_array_prepend_num(Sdb *s, const char *key, ut64 num, ut32 cas) {
	char buf[SDB_NUM_BUFSZ];
	char *n = sdb_itoa (num, 0, buf, sizeof (buf));
	return sdb_array_push (s, key, n, cas);
}

SDB_API bool sdb_array_prepend (Sdb *s, const char *key, const char *val, ut32 cas) {
	if (!s || !key || !val) {
		return false;
	}
	int str_len = 0;
	ut32 kas = cas;
	const char *str = sdb_const_get_len (s, key, &str_len, &kas);
	if (!val || (cas && cas != kas)) {
		return false;
	}
	cas = kas;
	if (str && *str) {
		int val_len = strlen (val);
		char *newval = (char *)sdb_gh_malloc (str_len + val_len + 2);
		if (!newval) {
			return false;
		}
		memcpy (newval, val, val_len);
		newval[val_len] = SDB_RS;
		memcpy (newval + val_len + 1, str, str_len);
		newval[str_len + val_len + 1] = 0;
		// TODO: optimize this because we already have allocated and strlened everything
		sdb_set_owned (s, key, newval, cas);
	} else {
		sdb_set (s, key, val, cas);
	}
	return true;
}

SDB_API ut64 sdb_array_pop_num(Sdb *s, const char *key, ut32 *cas) {
	ut64 ret;
	char *a = sdb_array_pop (s, key, cas);
	if (!a) {
		if (cas) {
			*cas = UT32_MAX; // invalid
		}
		return UT64_MAX;
	}
	if (cas) {
		*cas = 0;
	}
	ret = sdb_atoi (a);
	sdb_gh_free (a);
	return ret;
}

SDB_API char *sdb_array_pop(Sdb *s, const char *key, ut32 *cas) {
#if PUSH_PREPENDS
	return sdb_array_pop_head (s, key, cas);
#else
	return sdb_array_pop_tail (s, key, cas);
#endif
}

SDB_API char *sdb_array_pop_head(Sdb *s, const char *key, ut32 *cas) {
	// remove last element in 
	ut32 kas;
	char *end, *str = sdb_get (s, key, &kas);
	if (!str || !*str) {
		sdb_gh_free (str);
		return NULL;
	}
	if (cas && *cas != kas) {
		*cas = kas;
	}
	end = strchr (str, SDB_RS);
	if (end) {
		*end = 0;
		sdb_set (s, key, end + 1, 0);
	} else {
		sdb_unset (s, key, 0);
	}
	return str;
}

SDB_API char *sdb_array_pop_tail(Sdb *s, const char *key, ut32 *cas) {
	ut32 kas;
	char *end, *str = sdb_get (s, key, &kas);
	if (!str || !*str) {
		sdb_gh_free (str);
		return NULL;
	}
	if (cas && *cas != kas) {
		*cas = kas;
	}
	for (end = str + strlen (str) - 1; end > str && *end != SDB_RS; end--) {
		//nothing to see here
	}
	if (*end == SDB_RS) {
		*end++ = 0;
	}
	sdb_set_owned (s, key, str, 0);
	// XXX: probably wrong
	return sdb_strdup (end);
}

SDB_API void sdb_array_sort(Sdb *s, const char *key, ut32 cas) {
	char *nstr, *str, **strs;
	int lstr, j, i;
	str = sdb_get_len (s, key, &lstr, 0);
	if (!str) {
		return;
	}
	if (!*str) {
		sdb_gh_free (str);
		return;
	}
	strs = sdb_fmt_array (str);
	for (i = 0; strs[i]; i++) {
		//nothing to see here
	}
	qsort (strs, i, sizeof (char*), cstring_cmp);
	nstr = str;
	for (i = 0; strs[i]; i++) {
		j = strlen (strs[i]);
		memcpy (nstr, strs[i], j);
		nstr += j;
		*(nstr++) = SDB_RS;
	}
	if (nstr > str) {
		*(--nstr) = '\0';
	} else {
		*nstr = '\0';
	}
	sdb_set_owned (s, key, str, cas);
	sdb_gh_free (strs);
}

SDB_API void sdb_array_sort_num(Sdb *s, const char *key, ut32 cas) {
	char *ret, *nstr;

	char *str = sdb_get (s, key, 0);
	if (!str) {
		return;
	}
	if (!*str) {
		sdb_gh_free (str);
		return;
	}
	ut64 *nums = sdb_fmt_array_num (str);
	sdb_gh_free (str);
	if (!nums) {
		return;
	}

	qsort (nums + 1, (int)*nums, sizeof (ut64), int_cmp);

	nstr = (char *)sdb_gh_malloc (*nums + 1);
	if (!nstr) {
		sdb_gh_free (nums);
		return;
	}
	memset (nstr, 'q', *nums);
	nstr[*nums] = '\0';

	ret = sdb_fmt_tostr (nums + 1, nstr);
	sdb_set_owned (s, key, ret, cas);

	sdb_gh_free (nstr);
	sdb_gh_free (nums);
	return;
}
