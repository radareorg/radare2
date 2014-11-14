/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"
#include "types.h"

// check if key exists and if it's a number.. rename?
SDB_API int sdb_num_exists (Sdb *s, const char *key) {
	const char *o = sdb_const_get (s, key, NULL);
	return o? (*o>='0' && *o<='9'): 0;
}

SDB_API ut64 sdb_num_get(Sdb *s, const char *key, ut32 *cas) {
	const char *v = sdb_const_get (s, key, cas);
	if (!v || *v=='-') return 0LL;
	return sdb_atoi (v);
}

SDB_API int sdb_num_add(Sdb *s, const char *key, ut64 v, ut32 cas) {
	char *val, b[128];
	int numbase = sdb_num_base (sdb_const_get (s, key, NULL));
	val = sdb_itoa (v, b, numbase);
	return sdb_add (s, key, val, cas);
}

SDB_API int sdb_num_set(Sdb *s, const char *key, ut64 v, ut32 cas) {
	char *val, b[128];
	int numbase = sdb_num_base (sdb_const_get (s, key, NULL));
	val = sdb_itoa (v, b, numbase);
	return sdb_set (s, key, val, cas);
}

SDB_API ut64 sdb_num_inc(Sdb *s, const char *key, ut64 n2, ut32 cas) {
	ut32 c;
	ut64 n = sdb_num_get (s, key, &c);
	if (cas && c != cas) return 0LL;
	if (-n2<n) return 0LL;
	n += n2;
	sdb_num_set (s, key, n, cas);
	return n;
}

SDB_API ut64 sdb_num_dec(Sdb *s, const char *key, ut64 n2, ut32 cas) {
	ut32 c;
	ut64 n = sdb_num_get (s, key, &c);
	if (cas && c != cas)
		return 0LL;
	if (n2>n) {
		sdb_set (s, key, "0", cas);
		return 0LL; // XXX must be -1LL?
	}
	n -= n2;
	sdb_num_set (s, key, n, cas);
	return n;
}

SDB_API int sdb_bool_set(Sdb *db, const char *str, int v, ut32 cas) {
	return sdb_set (db, str, v?"true":"false", cas);
}

SDB_API int sdb_bool_get(Sdb *db, const char *str, ut32 *cas) {
	const char *b = sdb_const_get (db, str, cas);
	return (!strcmp (b, "1") || !strcmp (b, "true"))? 1: 0;
}

SDB_API int sdb_num_min(Sdb *db, const char*k, ut64 n, ut32 cas) {
	const char* a = sdb_const_get (db, k, NULL);
	if (!a || n<sdb_atoi (a))
		return sdb_num_set (db, k, n, cas);
	return 0;
}

SDB_API int sdb_num_max(Sdb *db, const char*k, ut64 n, ut32 cas) {
	const char* a = sdb_const_get (db, k, NULL);
	if (!a || n>sdb_atoi (a))
		return sdb_num_set (db, k, n, cas);
	return 0;
}
