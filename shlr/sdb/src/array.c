/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"

#define PUSH_PREPENDS 1
// TODO: missing num_{inc/dec} functions

static const char *Aindexof(const char *str, int idx) {
	int len = 0;
	const char *n, *p = str;
	for (len=0; ; len++) {
		if (len == idx)
			return p;
		n = strchr (p, SDB_RS);
		if (n) p = n+1;
		else break;
	}
	return NULL;
}

static const char *Aconst_index(const char *str, int idx) {
	int len = 0;
	const char *n, *p = str;
	for (len=0; ; len++) {
		if (len == idx)
			return p;
		n = strchr (p, SDB_RS);
		if (n) p = n+1;
		else break;
	}
	return NULL;
}

static int astrcmp (const char *a, const char *b) {
	for (;;) {
		if (*a == '\0' || *a == SDB_RS) {
			if (*b == '\0' || *b == SDB_RS)
				return 0;
			return 1;
		}
		if (*b == '\0' || *b == SDB_RS)
			return 1;
		if (*a != *b) return 1;
		a++;
		b++;
	}
	return 1;
}

SDB_API ut64 sdb_array_get_num(Sdb *s, const char *key, int idx, ut32 *cas) {
	const char *str, *n, *p;
	int i;
	p = str = sdb_const_get (s, key, cas);
	if (!str || !*str)
		return 0LL;
	if (idx==0)
		return sdb_atoi (str);
	for (i=0; i<idx; i++) {
		n = strchr (p, SDB_RS);
		if (!n) return 0LL;
		p = n+1;
	}
	return sdb_atoi (p);
}

SDB_API char *sdb_array_get(Sdb *s, const char *key, int idx, ut32 *cas) {
	const char *str = sdb_const_get (s, key, cas);
	const char *p = str;
	char *o, *n;
	int i, len;
	if (!str || !*str) return NULL;
	if (idx<0) {
		int len = sdb_alen (str);
		idx = -idx;
		if (idx>len)
			return NULL;
		idx = (len-idx);
	}
	if (idx==0) {
		n = strchr (str, SDB_RS);
		if (!n) return strdup (str);
		len = n-str;
		o = malloc (len+1);
		memcpy (o, str, len);
		o[len] = 0;
		return o;
	}
	for (i=0; i<idx; i++) {
		n = strchr (p, SDB_RS);
		if (!n) return NULL;
		p = n+1;
	}
	n = strchr (p, SDB_RS);
	if (!n) return strdup (p);
	len = n-p;
	o = malloc (len+1);
	memcpy (o, p, len);
	o[len] = 0;
	return o;
}

SDB_API int sdb_array_insert_num(Sdb *s, const char *key, int idx, ut64 val, ut32 cas) {
	char valstr[64];
	return sdb_array_insert (s, key, idx,
		sdb_itoa (val, valstr, SDB_NUM_BASE), cas);
}

// TODO: done, but there's room for improvement
SDB_API int sdb_array_insert(Sdb *s, const char *key, int idx, const char *val, ut32 cas) {
	int lnstr, lstr, lval;
	const char *str = sdb_const_get_len (s, key, &lstr, 0);
	char *x, *ptr;
	if (!str || !*str)
		return sdb_set (s, key, val, cas);
	lval = strlen (val);
	lstr--;
	//lstr = strlen (str); // we can optimize this by caching value len in memory . add sdb_const_get_size()
	x = malloc (lval + lstr + 2);
	if (idx==-1) {
		memcpy (x, str, lstr);
		x[lstr] = SDB_RS;
		memcpy (x+lstr+1, val, lval+1);
	} else if (idx == 0) {
		memcpy (x, val, lval);
		x[lval] = SDB_RS;
		memcpy (x+lval+1, str, lstr+1);
	} else {
		char *nstr = malloc (lstr+1);
		memcpy (nstr, str, lstr+1);
		ptr = (char *)Aindexof (nstr, idx);
		if (ptr) {
			int lptr = (nstr+lstr+1)-ptr;
			*(ptr-1) = 0;
			lnstr = ptr-nstr-1;
			memcpy (x, nstr, lnstr);
			x[lnstr] = SDB_RS;
			memcpy (x+lnstr+1, val, lval);
			x[lnstr+lval+1] = SDB_RS;
			// TODO: this strlen hurts performance
			memcpy (x+lval+2+lnstr, ptr, lptr); //strlen (ptr)+1);
			free (nstr);
		} else {
			// this is not efficient
			free (nstr);
			free (x);
			// fallback for empty buckets
			return sdb_array_set (s, key, idx, val, cas);
		}
	}
	return sdb_set_owned (s, key, x, cas);
}

SDB_API int sdb_array_set_num(Sdb *s, const char *key, int idx, ut64 val, ut32 cas) {
	char valstr[64];
	return sdb_array_set (s, key, idx,
		sdb_itoa (val, valstr, SDB_NUM_BASE), cas);
}

SDB_API int sdb_array_add_num(Sdb *s, const char *key, ut64 val, ut32 cas) {
	char valstr10[64], valstr16[64];
	char *v10 = sdb_itoa (val, valstr10, 10);
	char *v16 = sdb_itoa (val, valstr16, 16);
	// TODO: optimize
	// TODO: check cas vs mycas
	if (sdb_array_contains (s, key, v10, NULL))
		return 0;
	return sdb_array_add (s, key, v16, cas); // TODO: v10 or v16
}

// XXX: index should be supressed here? if its a set we shouldnt change the index
SDB_API int sdb_array_add(Sdb *s, const char *key, const char *val, ut32 cas) {
	if (sdb_array_contains (s, key, val, NULL))
		return 0;
	return sdb_array_set (s, key, -1, val, cas);
}

SDB_API int sdb_array_unset(Sdb *s, const char *key, int idx, ut32 cas) {
	return sdb_array_set (s, key, idx, "", cas);
}

SDB_API int sdb_array_set(Sdb *s, const char *key, int idx, const char *val, ut32 cas) {
	char *ptr;
	int lstr, lval, len;
	const char *usr, *str = sdb_const_get_len (s, key, &lstr, 0);
	if (!str || !*str)
		return sdb_set (s, key, val, cas);
	// XXX: should we cache sdb_alen value inside kv?
	len = sdb_alen (str);
	lstr--;
	if (idx<0 || idx==len) // append
		return sdb_array_insert (s, key, -1, val, cas);
	lval = strlen (val);
	if (idx>len) {
		int ret, i, ilen = idx-len;
		char *newkey = malloc (ilen+lval+1);
		if (!newkey)
			return 0;
		for (i=0; i<ilen; i++)
			newkey [i] = SDB_RS;
		memcpy (newkey+i, val, lval+1);
		ret = sdb_array_insert (s, key, -1, newkey, cas);
		free (newkey);
		return ret;
	}
	//lstr = strlen (str);
	ptr = (char*)Aindexof (str, idx);
	if (ptr) {
		int diff = ptr-str;
		char *nstr = malloc (lstr+lval+2);
		ptr = nstr+diff;
		//memcpy (nstr, str, lstr+1);
		memcpy (nstr, str, diff);
		memcpy (ptr, val, lval+1);
		usr = Aconst_index (str, idx+1);
		if (usr) {
			ptr[lval] = SDB_RS;
			strcpy (ptr+lval+1, usr);
		}
		return sdb_set_owned (s, key, nstr, 0);
	}
	return 0;
}

SDB_API int sdb_array_remove_num(Sdb *s, const char *key, ut64 val, ut32 cas) {
	const char *n, *p, *str = sdb_const_get (s, key, 0);
	int idx = 0;
	ut64 num;
	if (!str) return 0;
	for (p=str; ; idx++) {
		num = sdb_atoi (p);
		if (num == val)
			return sdb_array_delete (s, key, idx, cas);
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n+1;
	}
	return 0;
}

/* get array index of given value */
SDB_API int sdb_array_indexof(Sdb *s, const char *key, const char *val, ut32 cas) {
	const char *str = sdb_const_get (s, key, 0);
	const char *n, *p = str;
	int idx;
	for (idx=0; ; idx++) {
		if (!p) break;
		if (!astrcmp (p, val))
			return idx;
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n+1;
	}
	return -1;
}

// previously named del_str... pair with _add
SDB_API int sdb_array_remove(Sdb *s, const char *key, const char *val, ut32 cas) {
	const char *str = sdb_const_get (s, key, 0);
	const char *n, *p = str;
	int idx;
	if (p)
	for (idx=0; ; idx++) {
		if (!astrcmp (p, val))
			return sdb_array_delete (s, key, idx, cas);
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n+1;
	}
	return 0;
}

SDB_API int sdb_array_delete(Sdb *s, const char *key, int idx, ut32 cas) {
	int i;
	char *p, *n, *str = sdb_get (s, key, 0);
	p = str;
	if (!str || !*str) {
		free (str);
		return 0;
	}
	if (idx<0) {
		idx = sdb_alen (str);
		if (idx) idx--;
	}
	for (i = 0; i<idx; i++) {
		if ( (n = strchr (p, SDB_RS)) ) {
			p = n+1;
		} else {
			free (str);
			return 0;
		}
	}
	n = strchr (p, SDB_RS);
	if (n) {
		memmove (p, n+1, strlen (n));
	} else {
		if (p != str)
			p--; // remove tailing SDB_RS
		*p = 0;
		p[1] = 0;
	}
	sdb_set_owned (s, key, str, cas);
	return 1;
}

// XXX Doesnt works if numbers are stored in different base
SDB_API int sdb_array_contains_num(Sdb *s, const char *key, ut64 num, ut32 *cas) {
	char val[64];
	char *nval = sdb_itoa (num, val, SDB_NUM_BASE);
	return sdb_array_contains (s, key, nval, cas);
}

SDB_API int sdb_array_contains(Sdb *s, const char *key, const char *val, ut32 *cas) {
	const char *list = sdb_const_get (s, key, cas);
	const char *next, *ptr = list;
	const int vlen = strlen (val);
	if (list && *list) {
		do {
			const char *str = sdb_const_anext (ptr, &next);
			int len = next? (int)(size_t)(next-str)-1 : strlen (str);
			if (len == vlen) {
				if (!memcmp (str, val, len)) {
					return 1;
				}
			}
			ptr = next;
		} while (next);
	}
	return 0;
}

SDB_API int sdb_array_size(Sdb *s, const char *key) {
	return sdb_alen (sdb_const_get (s, key, 0));
}

// NOTE: ignore empty buckets
SDB_API int sdb_array_length(Sdb *s, const char *key) {
	int ret = 0;
	char *val = sdb_get (s, key, 0);
	if (val && *val) {
		// TOO SLOW
		sdb_array_compact (val);
		ret = sdb_alen (val);
	}
	free (val);
	return ret;
}

SDB_API int sdb_array_push_num(Sdb *s, const char *key, ut64 num, ut32 cas) {
	char buf[128];
	char *n = sdb_itoa (num, buf, SDB_NUM_BASE);
	return sdb_array_push (s, key, n, cas);
}

SDB_API int sdb_array_push(Sdb *s, const char *key, const char *val, ut32 cas) {
	int str_len = 0;
	ut32 kas = cas;
	const char *str = sdb_const_get_len (s, key, &str_len, &kas);
	if (cas && cas != kas)
		return 0;
	cas = kas;
	if (str && *str) {
		int val_len = strlen (val);
		char *newval = malloc (str_len + val_len + 2);
#if PUSH_PREPENDS
		memcpy (newval, val, val_len);
		newval[val_len] = SDB_RS;
		memcpy (newval+val_len+1, str, str_len);
		newval[str_len+val_len+1] = 0;
		// TODO: optimize this because we already have allocated and strlened everything
#else
		memcpy (newval, str, str_len);
		newval[str_len] = SDB_RS;
		memcpy (newval+str_len+1, val, val_len);
		newval[str_len+val_len+1] = 0;
#endif
		sdb_set_owned (s, key, newval, cas);
	} else {
		sdb_set (s, key, val, cas);
	}
	return 1;
}

SDB_API ut64 sdb_array_pop_num(Sdb *s, const char *key, ut32 *cas) {
	ut64 ret;
	char *a = sdb_array_pop (s, key, cas);
	if (!a) {
		if (cas) *cas = UT32_MAX; // invalid
		return UT64_MAX;
	}
	if (cas)
		*cas = 0;
	ret = sdb_atoi (a);
	free (a);
	return ret;
}

SDB_API char *sdb_array_pop(Sdb *s, const char *key, ut32 *cas) {
	ut32 kas;
	char *end, *str = sdb_get (s, key, &kas);
	if (!str || !*str) {
		free (str);
		return NULL;
	}
	if (cas && *cas != kas)
		*cas = kas;
#if PUSH_PREPENDS
	end = strchr (str, SDB_RS);
	if (end) {
		*end = 0;
		sdb_set (s, key, end+1, 0);
	} else {
		sdb_unset (s, key, 0);
	}
	return str;
#else
	for (end = str+strlen (str)-1;
		end>str && *end!=SDB_RS; end--);
	if (*end==SDB_RS) *end++ = 0;
	sdb_set_owned (s, key, str, 0);
	// XXX: probably wrong
	return strdup (end);
#endif
}

