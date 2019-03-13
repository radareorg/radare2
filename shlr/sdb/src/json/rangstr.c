/* Copyleft 2012-2017 - sdb (aka SimpleDB) - pancake<nopcode.org> */

#ifndef RANGSTR_C
#define RANGSTR_C

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rangstr.h"

#if 0
SDB_IPI void rangstr_print (Rangstr *s) {
	if (s && s->p) {
		(void) fwrite (s->p+s->f,
			s->t-s->f, 1, stdout);
	}
}
#endif

SDB_IPI Rangstr rangstr_null(void) {
	Rangstr rs = {0, 0, 0, 0, 0};
	return rs;
}

SDB_IPI Rangstr rangstr_new (const char *s) {
	Rangstr rs;
	if (!s) {
		return rangstr_null ();
	}
	rs.f = 0;
	rs.next = 1;
	rs.t = strlen (s);
	rs.p = s;
	rs.type = 0;
	return rs;
}

SDB_IPI int rangstr_length (Rangstr* rs) {
	if (rs->t > rs->f) {
		return rs->t - rs->f;
	}
	return 0;
}

SDB_IPI int rangstr_int (Rangstr *s) {
	if (!s || !s->p) {
		return 0;
	}

	const int base = 10;
	int mul = 1;
	int ch, n = 0;
	size_t i = 0;
	if (s->p[s->f]=='[') {
		i++;
	}
	if (s->p[s->f]=='-') {
		mul = -1;
		i += s->f + 1;
	} else {
		i += s->f;
	}
	for (; i < s->t; i++) {
		ch = s->p[i];
		if (ch < '0' || ch > '9') {
			break;
		}
		n = n * base + (ch - '0');
	}
	return n * mul;
}

SDB_IPI char *rangstr_dup (Rangstr *rs) {
	if (!rs->p) {
		return NULL;
	}
	int len = rangstr_length (rs);
	char *p = malloc (len + 1);
	if (p) {
		memcpy (p, rs->p + rs->f, len);
		p[len] = 0;
	}
	return p;
}

SDB_IPI Rangstr rangstr_news (const char *s, RangstrType *res, int i) {
	Rangstr rs;
	rs.next = 1;
	rs.f = res[i];
	rs.t = res[i]+res[i+1];
	rs.p = s;
	rs.type = 0;
	return rs;
}

SDB_IPI int rangstr_cmp (Rangstr *a, Rangstr *b) {
	int la = a->t - a->f;
	int lb = b->t - b->f;
	int lbz = strlen (b->p + b->f);
	if (lbz < lb) {
		lb = lbz;
	}
	if (la != lb) {
		return 1;
	}
	return memcmp (a->p + a->f, b->p + b->f, la);
}

SDB_IPI int rangstr_find (Rangstr* a, char ch) {
	size_t i = a->f;
	while (i < a->t && a->p[i] && a->p[i] != ch) i++;
	return (i < a->t && a->p[i]) ? (int) i: -1;
}

SDB_IPI  const char *rangstr_str (Rangstr* rs) {
	return rs->p + rs->f;
}

#endif
