/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"

static char *sdb_array_index_nc(char *str, int idx) {
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

SDB_API const char *sdb_array_next(const char *str) {
	return str+strlen (str)+1;
}

SDB_API char *sdb_array_string(char *str, int *hasnext) {
	int nxt = 0;
	char *p = strchr (str, SDB_RS);
	if (p) { *p = 0; nxt = 1; }
	if (hasnext) *hasnext = nxt;
	return str;
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
	if (!p) return NULL;
	n = strchr (p, SDB_RS);
	if (!n) return strdup (p);
	len = n-p;
	o = malloc (len+1);
	memcpy (o, p, len);
	o[len] = 0;
	return o;
}

SDB_API int sdb_array_ins_num(Sdb *s, const char *key, int idx, ut64 val, ut32 cas) {
	char valstr[64];
	return sdb_array_ins (s, key, idx, sdb_itoa (val, valstr, 10), cas);
}

// TODO: done, but there's room for improvement
SDB_API int sdb_array_ins(Sdb *s, const char *key, int idx, const char *val, ut32 cas) {
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
		ptr = sdb_array_index_nc (nstr, idx);
		if (ptr) {
			*(ptr-1) = 0;
			lnstr = strlen (nstr);
			memcpy (x, nstr, lnstr);
			x[lnstr] = SDB_RS;
			memcpy (x+lnstr+1, val, lval);
			x[lnstr+lval+1] = SDB_RS;
			memcpy (x+lval+2+lnstr, ptr, strlen (ptr)+1);
			ret = 1;
		} else ret = 0;
		free (nstr);
		free (x);
		return ret;
	}
	ret = sdb_set (s, key, x, cas);
	free (x);
	return ret;
}

SDB_API int sdb_array_set_num(Sdb *s, const char *key, int idx, ut64 val, ut32 cas) {
	char valstr[64];
	return sdb_array_set (s, key, idx, sdb_itoa (val, valstr, 10), cas);
}

SDB_API int sdb_array_add_num(Sdb *s, const char *key, int idx, ut64 val, ut32 cas) {
	char valstr[64], *vs = sdb_itoa (val, valstr, 10);
	if (sdb_array_exists (s, key, vs))
		return 0;
	return sdb_array_add (s, key, idx, vs, cas);
}

SDB_API int sdb_array_add(Sdb *s, const char *key, int idx, const char *val, ut32 cas) {
	if (sdb_array_exists (s, key, val))
		return 0;
	return sdb_array_set (s, key, idx, val, cas);
}

SDB_API int sdb_array_set(Sdb *s, const char *key, int idx, const char *val, ut32 cas) {
	char *nstr, *ptr;
	const char *usr, *str = sdb_const_get (s, key, 0);
	int lval, len, ret = 0;
	if (!str || !*str)
		return sdb_set (s, key, val, cas);
	len = sdb_alen (str);
	if (idx<0 || idx>len) // append
		return sdb_array_ins (s, key, -1, val, cas);
	nstr = malloc (strlen (str)+strlen (val)+2);
	strcpy (nstr, str);
	ptr = sdb_array_index_nc (nstr, idx);
	if (ptr) {
		lval = strlen (val);
		memcpy (ptr, val, lval+1);
		usr = sdb_array_index (str, idx+1);
		if (usr) {
			ptr[lval] = SDB_RS;
			strcpy (ptr+lval+1, usr);
		}
		ret = sdb_set (s, key, nstr, 0);
	}
	free (nstr);
	return ret;
}

SDB_API int sdb_array_del_num(Sdb *s, const char *key, ut64 val, ut32 cas) {
	const char *n, *p, *str = sdb_const_get (s, key, 0);
	int idx = 0;
	ut64 num;
	if (!str) return 0;
	for (p=str; ; idx++) {
		num = sdb_atoi (p);
		if (num == val)
			return sdb_array_del (s, key, idx, cas);
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n+1;
	}
	return 0;
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

/* get array index of given value */
SDB_API int sdb_array_get_idx(Sdb *s, const char *key, const char *val, ut32 cas) {
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

SDB_API int sdb_array_del_str(Sdb *s, const char *key, const char *val, ut32 cas) {
	const char *str = sdb_const_get (s, key, 0);
	const char *n, *p = str;
	int idx;
	for (idx=0; ; idx++) {
		if (!p) break;
		if (!astrcmp (p, val))
			return sdb_array_del (s, key, idx, cas);
		n = strchr (p, SDB_RS);
		if (!n) break;
		p = n+1;
	}
	return 0;
}

SDB_API int sdb_array_del(Sdb *s, const char *key, int idx, ut32 cas) {
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
		n = strchr (p, SDB_RS);
		if (n) p = n+1;
		else {
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

SDB_API const char *sdb_array_index(const char *str, int idx) {
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

SDB_API int sdb_array_exists(Sdb *s, const char *key, const char *val) {
	int found = 0, hasnext = 1;
	char *list = sdb_get (s, key, 0);
	char *ptr = list;
	hasnext = list && *list;
	while (hasnext) {
		char *str = sdb_array_string (ptr, &hasnext);
		if (!strcmp (str, val)) {
			found = 1;
			break;
		}
		ptr = (char *)sdb_array_next (str);
	}
	free (list);
	return found;
}

SDB_API int sdb_array_len(Sdb *s, const char *key) {
	const char *str = sdb_const_get (s, key, 0);
	return sdb_alen (str);
}

SDB_API int sdb_array_push(Sdb *s, const char *key, const char *val, ut32 cas) {
	ut32 kas = cas;
	const char *str = sdb_const_get (s, key, &kas);
	if (cas && cas != kas)
		return 0;
	cas = kas;
	if (str && *str) {
		int str_len = strlen (str);
		int val_len = strlen (val);
		char *newval = malloc (str_len + val_len + 2);
		memcpy (newval, str, str_len);
		newval[str_len] = SDB_RS;
		memcpy (newval+str_len+1, val, val_len);
		newval[str_len+val_len+1] = 0;
		sdb_set (s, key, newval, cas);
		free (newval);
	} else {
		sdb_set (s, key, val, cas);
	}
	return 1;
}

SDB_API char *sdb_array_pop(Sdb *s, const char *key, ut32 *cas) {
	ut32 kas;
	char *ret;
	const char *str = sdb_const_get (s, key, &kas);
	int n = sdb_alen (str);
	if (n<1) return NULL;
	if (cas  && *cas != kas)
		*cas = kas;
	ret = strdup (str);
	sdb_array_del (s, key, n-1, kas);
	return ret;
}

#if 0
// XXX: totally unefficient. do not use, replace SDB_RS for '\n' may be enought
SDB_API int sdb_alist(Sdb *s, const char *key) {
	int len = 0, hasnext = 1;
	char *list = sdb_get (s, key, 0);
	char *ptr = list;
	hasnext = list && *list;
	while (hasnext) {
		char *str = sdb_astring (ptr, &hasnext);
		// TODO: use callback instead of printf
		printf ("%s\n", str);
		ptr = (char *)sdb_array_next (str);
		len++;
	}
	free (list);
	return len;
}
#endif
