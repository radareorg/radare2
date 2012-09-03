/* Copyleft 2012 - sdb (aka SimpleDB) - pancake<nopcode.org> */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rangstr.h"
#include "json.h"

void json_path_first(Rangstr *s) {
	char *p;
	if (!s->p) return;
	p = strchr (s->p, '.');
	s->f = 0;
	s->t = p? p-s->p: strlen (s->p);
}

int json_path_next(Rangstr *s) {
	int stop = '.';
	if (!s||!s->p||!s->p[s->t])
		return 0;
	if (!s->next) return 0;
	if (s->p[s->t] == '"')
		s->t++;
rep:
	if (s->p[s->t] == '[') {
		s->type = '[';
		stop = ']';
	} else s->type = 0;
	s->f = ++s->t;
	if (s->p[s->t] == stop)
		s->f = ++s->t;
		if (!s->p[s->t])
			return 0;
	while (s->p[s->t] != stop) {
		if (!s->p[s->t]) {
			s->next = 0;
			return 1;
		}
		if (s->p[s->t] == '[')
			break;
		s->t++;
	}
	if (s->f == s->t)
		goto rep;
	if (s->p[s->f] == '"') {
		s->f++;
		s->t--;
	}
	return 1;
}

int json_walk (const char *s) {
	int i, len, ret;
	unsigned short *res;
	len = strlen (s);
	res = malloc (len);
	ret = js0n ((unsigned char *)s, len, res);
	if (!ret) return 0;
	if (*s=='[') {
		for (i=0; res[i]; i+=2) {
			printf ("%d %.*s\n", i, res[i+1], s+res[i]);
		}
	} else {
		for (i=0; res[i]; i+=4) {
			printf ("%.*s = ", res[i+1], s+res[i]);
			printf ("%.*s\n", res[i+3], s+res[i+2]);
		}
	}
	return 1;
}

Rangstr json_find (const char *s, Rangstr *rs) {
	unsigned short resfix[512];
	unsigned short *res = NULL;
	int i, j, n, len, ret;
	Rangstr rs2;

	if (!s) return rangstr_null ();
	len = strlen (s);
	if (len<512)
		res = resfix;
	else res = malloc (len);
	ret = js0n ((unsigned char *)s, len, res);
	if (ret>0) return rangstr_null ();
#define PFREE(x) if (x&&x!=resfix) free (x)
	if (*s=='[') {
		n = rangstr_int (rs);
		n++;
		if (n<0) goto beach;
		for (i=j=0; res[i] && j<n; i+=2, j++);
		if (j<n) goto beach;
		rs2 = rangstr_news (s, res, i-2);
		PFREE (res);
		return rs2;
	} else {
		for (i=0; res[i]; i+=4) {
			Rangstr rs2 = rangstr_news (s, res, i);
			if (!rangstr_cmp (rs, &rs2)) {
				rs2 = rangstr_news (s, res, i+2);
				PFREE (res);
				return rs2;
			}
		}
	}
beach:
	PFREE (res);
	return rangstr_null ();
}

Rangstr json_get (const char *js, const char *p) {
	Rangstr rj = rangstr_new (js);
	Rangstr rs = rangstr_new (p);
	json_path_first (&rs);
	//len = rs.t;
	do { 
		rj = json_find (rangstr_str (&rj), &rs);
		//if (!rs.p || !rs.p[rs.t]) // HACK to fix path_next()
		//	break;
	} while (json_path_next (&rs));
	return rj;
}

char *json_set (const char *s, const char *k, const char *v) {
	return NULL;
}

