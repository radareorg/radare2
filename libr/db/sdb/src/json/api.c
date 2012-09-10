/* Copyleft 2012 - sdb (aka SimpleDB) - pancake<nopcode.org> */
// XXX: this is deprecated coz its dupper for ../json.c

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "rangstr.h"
#include "json.h"

/* public sdb api */
char *api_json_get (const char *s, const char *p) {
	Rangstr rs = json_get (s, p);
	return rangstr_dup (&rs);
}

char *api_json_set (const char *s, const char *k, const char *v) {
	const char *beg[3];
	const char *end[3];
	int idx, len[3];
	char *str = NULL;
	Rangstr rs = json_get (s, k);
	if (!rs.p) return NULL;
#define WLEN(x) (int)(size_t)(end[x]-beg[x])

	beg[0] = s;
	end[0] = rs.p + rs.f;
	len[0] = WLEN (0);

	beg[1] = v;
	end[1] = v + strlen (v);
	len[1] = WLEN (1);

	beg[2] = rs.p + rs.t;
	end[2] = s + strlen (s);
	len[2] = WLEN (2);

	str = malloc (len[0]+len[1]+len[2]+1);
	idx = len[0];
	memcpy (str, beg[0], idx);
	memcpy (str+idx, beg[1], len[1]);
	idx += len[1];
	memcpy (str+idx, beg[2], len[2]);
	str[idx+len[2]] = 0;
	return str;
}

char *api_json_seti (const char *s, const char *k, int a) {
	char str[64];
	sprintf (str, "%d", a);
	return api_json_set (s, k, str);
}
