/* sdb - LGPLv3 - Copyright 2012-2013 - pancake */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rangstr.h"
#include "json.h"
#include "../types.h"

void json_path_first(Rangstr *s) {
	char *p;
	if (!s->p) return;
	p = strchr (s->p, '.');
	s->f = 0;
	s->t = p? (size_t)(p-s->p): strlen (s->p);
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

#if 0
typedef int (*JSONCallback)();

int json_foreach(const char *s, JSONCallback cb UNUSED) {
	int i, len, ret;
	unsigned short *res = NULL;
	len = strlen (s);
	res = malloc (len);
	ret = js0n ((const unsigned char *)s, len, res);
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
#endif

int json_walk (const char *s) {
	unsigned short *res;
	int i, ret, len = strlen (s);
	res = malloc (len+1);
	ret = js0n ((const unsigned char *)s, len, res);
	if (!ret) {
		free (res);
		return 0;
	}
	if (*s=='[' || *s=='{') {
		for (i=0; res[i]; i+=2) {
			printf ("%d %.*s\n", i, res[i+1], s+res[i]);
		}
	} else {
		for (i=0; res[i]; i+=4) {
			printf ("%.*s = ", res[i+1], s+res[i]);
			printf ("%.*s\n", res[i+3], s+res[i+2]);
		}
	}
	free (res);
	return 1;
}

Rangstr json_find (const char *s, Rangstr *rs) {
#define RESFIXSZ 512
	unsigned short resfix[RESFIXSZ];
	unsigned short *res = NULL;
	int i, j, n, len, ret;
	Rangstr rsn;

	if (!s) return rangstr_null ();
	len = strlen (s);
	res = (len<RESFIXSZ)? resfix: malloc (len+1);
	ret = js0n ((const unsigned char *)s, len, res);
#define PFREE(x) if (x&&x!=resfix) free (x)
	if (ret>0) {
		PFREE (res);
		return rangstr_null ();
	}
	if (*s=='[') {
		n = rangstr_int (rs);
		n++;
		if (n<0) goto beach;
		for (i=j=0; res[i] && j<n; i+=2, j++);
		if (j<n) goto beach;
		rsn = rangstr_news (s, res, i-2);
		PFREE (res);
		return rsn;
	} else {
		for (i=0; res[i]; i+=4) {
			Rangstr rsn = rangstr_news (s, res, i);
			if (!rangstr_cmp (rs, &rsn)) {
				rsn = rangstr_news (s, res, i+2);
				PFREE (res);
				return rsn;
			}
		}
	}
beach:
	PFREE (res);
	return rangstr_null ();
}

Rangstr json_get (const char *js, const char *p) {
	int x, n = 0;
	size_t rst;
	Rangstr rj2, rj = rangstr_new (js);
	Rangstr rs = rangstr_new (p);
	json_path_first (&rs);
	do {
		rst = rs.t;
		rs.f++;
		x = rangstr_find (&rs, '[');
		rs.f--;
		if (x != -1)
			rs.t = x;
#if 0
printf ("x = %d f = %d t = %d\n", x, rs.f, rs.t);
fprintf (stderr, "source (%s)\n", rangstr_dup (&rs));
fprintf (stderr, "onjson (%s)\n", rangstr_dup (&rj));
#endif
		if (rst == rs.t && n && rj.p)  // last key
			break;
		if (!rj.p) break;
		do {
			rj2 = json_find (rangstr_str (&rj), &rs);
//fprintf (stderr, "++ (%s)(%d vs %d)\n", rangstr_dup (&rs), x, rs.t);
//if (rj.p[rj.f]=='[') { break; }
//fprintf (stderr, "ee %c\n", rj.p[rj.f]);
			if (!rj2.p) {
				if (!rj.p[rj.t]) return rj2;
				break;
			}
			rj = rj2;
#if 0
fprintf (stderr, "--  (%s)\n", rangstr_dup (&rj));
#endif
		} while (json_path_next (&rs));
//if (!rj.p) return rj;
#if 0
printf ("x = %d\n", x); printf ("rsf = %d\n", rs.f);
fprintf (stderr, "xxx (%s)\n", rangstr_dup (&rj));
return rj;
#endif
		if ((rst == rs.t && n && rj.p))  // last key
			break;
		rs.t = rst;
		rs.f = x;
		n++;
	} while (x != -1);
	return rj;
}

#if 0
char *json_set (const char *s UNUSED, const char *k UNUSED, const char *v UNUSED) {
	return NULL;
}
#endif
