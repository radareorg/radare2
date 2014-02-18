/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"
#include "types.h"

SDB_API int sdb_nexists (Sdb *s, const char *key) {
	char c;
	const char *o = sdb_getc (s, key, NULL);
	if (!o) return 0;
	c = *o;
	return c>='0' && c<='9';
}

SDB_API ut64 sdb_getn(Sdb *s, const char *key, ut32 *cas) {
	ut64 n;
	char *p;
	const char *v = sdb_getc (s, key, cas);
	if (!v || *v=='-') return 0LL;
	n = (!strncmp (v, "0x", 2))?
		strtoull (v+2, &p, 16):
		strtoull (v, &p, 10);
	if (!p) return 0LL;
	return n;
}

SDB_API int sdb_setn(Sdb *s, const char *key, ut64 v, ut32 cas) {
	char *val, b[128];
	int numbase = sdb_numbase (sdb_getc (s, key, NULL));
	val = sdb_itoa (v, b, numbase);
	return sdb_set (s, key, val, cas);
}

SDB_API ut64 sdb_inc(Sdb *s, const char *key, ut64 n2, ut32 cas) {
	ut32 c;
	ut64 n = sdb_getn (s, key, &c);
	if (cas && c != cas) return 0LL;
	if (-n2<n) return 0LL;
	n += n2;
	sdb_setn (s, key, n, cas);
	return n;
}

SDB_API ut64 sdb_dec(Sdb *s, const char *key, ut64 n2, ut32 cas) {
	ut32 c;
	ut64 n = sdb_getn (s, key, &c);
	if (cas && c != cas)
		return 0LL;
	if (n2>n) {
		sdb_set (s, key, "0", cas);
		return 0LL; // XXX must be -1LL?
	}
	n -= n2;
	sdb_setn (s, key, n, cas);
	return n;
}
