/* sdb - LGPLv3 - Copyright 2011-2013 - pancake */

#include "sdb.h"

// XXX: must be sdb_str_hash
SDB_VISIBLE ut32 sdb_hash(const char *s, int len) {
	ut32 h = CDB_HASHSTART;
	if (len<1) len = strlen (s)+1; // XXX slow
	while (len--) {
		h += (h<<5);
		h ^= *s++;
	}
	return h;
}
