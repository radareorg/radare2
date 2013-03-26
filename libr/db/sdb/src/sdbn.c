/* Copyleft 2011-2013 - sdb - pancake */

#include "sdb.h"
#include "types.h"

int sdb_nexists (Sdb *s, const char *key) {
	char c;
	const char *o = sdb_getc (s, key, NULL);
	if (!o) return 0;
	c = *o;
	return c>='0' && c<='9';
}

static void __strrev(char *s, int len) {
	int i, j = len -1;
	for (i=0; i<j; i++, j--) {
		char c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

static void __ulltoa(ut64 n, char *s) {
	int i = 0;
	do s[i++] = n % 10 + '0';
	while ((n /= 10) > 0);
	s[i] = '\0';
	__strrev (s, i);
}

ut64 sdb_getn(Sdb *s, const char *key, ut32 *cas) {
	ut64 n;
	char *p;
	const char *v = sdb_getc (s, key, cas);
	if (!v) return 0LL;
	n = strtoull (v, &p, 10);
	if (!p) return 0LL;
	//XXX sdb_setn (s, key, n);
	return n;
}

int sdb_setn(Sdb *s, const char *key, ut64 v, ut32 cas) {
	char b[128];
	__ulltoa (v, b);
	return sdb_set (s, key, b, cas);
}

ut64 sdb_inc(Sdb *s, const char *key, ut64 n2, ut32 cas) {
	ut32 c;
	ut64 n = sdb_getn (s, key, &c);
	if (cas && c != cas) return 0LL;
	if (-n2<n) return 0LL;
	n += n2;
	sdb_setn (s, key, n, cas);
	return n;
}

ut64 sdb_dec(Sdb *s, const char *key, ut64 n2, ut32 cas) {
	ut32 c;
	ut64 n = sdb_getn (s, key, &c);
	if (cas && c != cas)
		return 0LL;
	if (n2>n) {
		sdb_set (s, key, "0", cas);
		return 0LL; // XXX must be -1?
	}
	n -= n2;
	sdb_setn (s, key, n, cas);
	return n;
}
