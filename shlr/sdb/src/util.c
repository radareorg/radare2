/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include "sdb.h"

// assert sdb_hash("hi", 2) == sdb_hash("hi", 0)
SDB_API ut32 sdb_hash(const char *s, int len) {
	ut32 h = CDB_HASHSTART;
	if (len<1) {
		while (*s) {
			h += (h<<5);
			h ^= *s++;
		}
	} else {
		while (len--) {
			h += (h<<5);
			h ^= *s++;
		}
	}
	return h;
}

/* TODO: find algorithm without strrev */
/* TODO: try to avoid the use of heap */
static void __strrev(char *s, int len) {
	int i, j = len -1;
	for (i=0; i<j; i++, j--) {
		char c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

SDB_API char *sdb_itoa(ut64 n, char *s) {
	int i = 0;
	if (!s) s = malloc (64);
	do s[i++] = n % 10 + '0';
	while ((n /= 10) > 0);
	s[i] = '\0';
	__strrev (s, i);
	return s;
}

SDB_API ut64 sdb_atoi(const char *s) {
	char *p;
	if (!strncmp (s, "0x", 2))
		return strtoull (s+2, &p, 16);
	return strtoull (s, &p, 10);
}
