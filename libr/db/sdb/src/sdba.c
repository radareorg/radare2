/* Copyleft 2011-2013 - sdb - pancake */

#include "sdb.h"

#if 0
list=foo,bar,cow
list[0]

int hasnext;
char *ptr, *list = sdb_get (db, "list");
ptr = list;
do {
	char *str = sdb_astring (ptr, &hasnext);
	printf ("--> %s\n", str);
	ptr = str_anext (ptr);
} while (hasnext);
free (list);
#endif

const char *sdb_anext(const char *str) {
	return str+strlen(str)+1;
}

char *sdb_astring(char *str, int *hasnext) {
	char *p = strchr (str, SDB_RS);
	if (!p) {
		if (hasnext) *hasnext = 0;
		return str;
	}
	*p = 0;
	if (hasnext) *hasnext = 1;
	return str;
}

char *sdb_aget(Sdb *s, const char *key, int idx) {
	int i, len;
	const char *str = sdb_getc (s, key, 0);
	char *o, *n, *p = (char*)str;
	if (!str || !*str) return NULL;
	if (idx==0) {
		n = strchr (str, SDB_RS);
		if (!n) return strdup (str);
		len = n-str+1;
		o = malloc (len);
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
	len = n-p+1;
	o = malloc (len);
	memcpy (o, p, len);
	o[len] = 0;
	return o;
}

int sdb_aset(Sdb *s, const char *key, int idx, const char *val) {
	const char *str = sdb_getc (s, key, 0);
	int lstr, lval, ret = 0;
	if (!str || !*str)
		return sdb_set (s, key, val, 0);
	lval = strlen (val);
	lstr = strlen (str);
	if (idx==-1) {
		char *x = malloc (lval + lstr + 2);
		memcpy (x, str, lstr);
		x[lstr] = SDB_RS;
		memcpy (x+lstr+1, val, lval+1);
		ret = sdb_set (s, key, x, 0);
		free (x);
	} else if (idx == 0) {
		char *x = malloc (lval + lstr + 2);
		memcpy (x, val, lval);
		x[lval] = SDB_RS;
		memcpy (x+lval+1, str, lstr+1);
		ret = sdb_set (s, key, x, 0);
		free (x);
	} else {
		fprintf (stderr, "TODO: sdb_aset (idx>0)\n");
	}
	return ret;
}

int sdb_adel(Sdb *s, const char *key, int idx) {
	int i;
	char *p, *n, *str = sdb_get (s, key, 0);
	p = str;
	if (!str || !*str) return 0;
	if (idx<0) idx = sdb_alen (str);
	for (i = 0; i<idx; i++) {
		n = strchr (p, SDB_RS);
		if (n) p = n+1;
		else return 0;;
	}
	n = strchr (p, SDB_RS);
	if (n) strcpy (p, n+1);
	else *p = 0;
	sdb_set (s, key, str, 0);
	free (str);
	return 1;
}

int sdb_alen(const char *str) {
	int len = 0;
	const char *n, *p = str;
	for (len=0; ; len++) {
		n = strchr (p, SDB_RS);
		if (n) p = n+1;
		else break;
	}
	return len;
}
