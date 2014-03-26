/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"

#define PUSH_PREPENDS 1
// TODO: missing num_{inc/dec} functions

static char *Aindexof(char *str, int idx) {
	int len = 0;
	char *n, *p = str;
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
	const char *str = sdb_const_get (s, key, 0);
	int lnstr, lstr, lval, ret;
	char *x, *ptr;
	if (!str || !*str)
		return sdb_set (s, key, val, cas);
	lval = strlen (val);
	lstr = strlen (str);
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
		char *nstr = strdup (str);
		ptr = Aindexof (nstr, idx);
		if (ptr) {
			*(ptr-1) = 0;
			lnstr = strlen (nstr);
			memcpy (x, nstr, lnstr);
			x[lnstr] = SDB_RS;
			memcpy (x+lnstr+1, val, lval);
			x[lnstr+lval+1] = SDB_RS;
			memcpy (x+lval+2+lnstr, ptr, strlen (ptr)+1);
			ret = 1;
		} else {
			free (nstr);
			free (x);
			// fallback for empty buckets
			return sdb_array_set (s, key, idx, val, cas);
		}
		free (nstr);
	}
	ret = sdb_set (s, key, x, cas);
	free (x);
	return ret;
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
	if (sdb_array_contains (s, key, v10))
		return 0;
	if (sdb_array_contains (s, key, v16))
		return 0;
	return sdb_array_add (s, key, v16, cas); // TODO: v10 or v16
}

// XXX: index should be supressed here? if its a set we shouldnt change the index
SDB_API int sdb_array_add(Sdb *s, const char *key, const char *val, ut32 cas) {
	if (sdb_array_contains (s, key, val))
		return 0;
	return sdb_array_set (s, key, -1, val, cas);
}

SDB_API int sdb_array_unset(Sdb *s, const char *key, int idx, ut32 cas) {
	return sdb_array_set (s, key, idx, "", cas);
}

SDB_API int sdb_array_set(Sdb *s, const char *key, int idx, const char *val, ut32 cas) {
	char *nstr, *ptr;
	const char *usr, *str = sdb_const_get (s, key, 0);
	int lval, len, ret = 0;
	if (!str || !*str)
		return sdb_set (s, key, val, cas);
	len = sdb_alen (str);
	if (idx<0 || idx==len) // append
		return sdb_array_insert (s, key, -1, val, cas);
	if (idx>len) {
		int i, ilen = idx-len;
		char *newkey = malloc (ilen+strlen (val)+1);
		if (!newkey)
			return 0;
		for (i=0; i<ilen; i++)
			newkey [i]=',';
		strcpy (newkey+i, val);
		return sdb_array_insert (s, key, -1, newkey, cas);
	}
	nstr = malloc (strlen (str)+strlen (val)+2);
	strcpy (nstr, str);
	ptr = Aindexof (nstr, idx);
	if (ptr) {
		lval = strlen (val);
		memcpy (ptr, val, lval+1);
		usr = Aconst_index (str, idx+1);
		if (usr) {
			ptr[lval] = SDB_RS;
			strcpy (ptr+lval+1, usr);
		}
		ret = sdb_set (s, key, nstr, 0);
	}
	free (nstr);
	return ret;
}

SDB_API int sdb_array_delete_num(Sdb *s, const char *key, ut64 val, ut32 cas) {
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
	for (idx=0; ; idx++) {
		if (!p) break;
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
		memmove (p, n+1, strlen (n+1)+1);
	} else {
		if (p != str)
			p--; // remove tailing SDB_RS
		*p = 0;
		p[1] = 0;
	}
	sdb_set (s, key, str, cas);
	free (str);
	return 1;
}

// XXX Doesnt works if numbers are stored in different base
SDB_API int sdb_array_contains_num(Sdb *s, const char *key, ut64 num) {
	char val[64];
	char *nval = sdb_itoa (num, val, SDB_NUM_BASE);
	return sdb_array_contains (s, key, nval);
}

SDB_API int sdb_array_contains(Sdb *s, const char *key, const char *val) {
	int found = 0;
	char *list = sdb_get (s, key, 0);
	char *next, *ptr = list;
	if (list && *list) {
		do {
			char *str = sdb_anext (ptr, &next);
			if (!strcmp (str, val)) {
				found = 1;
				break;
			}
			ptr = next;
		} while (next);
	}
	free (list);
	return found;
}

SDB_API int sdb_array_size(Sdb *s, const char *key) {
	return sdb_alen (sdb_const_get (s, key, 0));
}

// NOTE: ignore empty buckets
SDB_API int sdb_array_length(Sdb *s, const char *key) {
	int ret = 0;
	char *val = sdb_get (s, key, 0);
	if (val && *val) {
		sdb_array_compact (val);
		ret = sdb_alen (val);
	}
	free (val);
	return ret;
}

SDB_API int sdb_array_push(Sdb *s, const char *key, const char *val, ut32 cas) {
	ut32 kas = cas;
	const char *str = sdb_const_get (s, key, &kas);
	if (cas && cas != kas)
		return 0;
	cas = kas;
	if (str && *str) {
#if PUSH_PREPENDS
		int str_len = strlen (str);
		int val_len = strlen (val);
		char *newval = malloc (str_len + val_len + 2);
		memcpy (newval, val, val_len);
		newval[val_len] = SDB_RS;
		memcpy (newval+val_len+1, str, str_len);
		newval[str_len+val_len+1] = 0;
		sdb_set (s, key, newval, cas);
		free (newval);
#else
		int str_len = strlen (str);
		int val_len = strlen (val);
		char *newval = malloc (str_len + val_len + 2);
		memcpy (newval, str, str_len);
		newval[str_len] = SDB_RS;
		memcpy (newval+str_len+1, val, val_len);
		newval[str_len+val_len+1] = 0;
		sdb_set (s, key, newval, cas);
		free (newval);
#endif
	} else {
		sdb_set (s, key, val, cas);
	}
	return 1;
}

SDB_API char *sdb_array_pop(Sdb *s, const char *key, ut32 *cas) {
	ut32 kas;
	char *ret, *end, *str = sdb_get (s, key, &kas);
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
		ret = strdup (str);
		sdb_set (s, key, end+1, 0);
	} else {
		ret = strdup (str);
		sdb_unset (s, key, 0);
	}
#else
	for (end = str+strlen(str)-1;
		end>str && *end!=SDB_RS; end--);
	if (*end==SDB_RS) *end++ = 0;
	ret = strdup (end);
	sdb_set (s, key, str, 0);
#endif
	free (str);
	return ret;
}
