/* sdb - LGPLv3 - Copyright 2012-2014 - pancake */

#include <stdarg.h>
#include "sdb.h"
#include "json/api.c"
#include "json/js0n.c"
#include "json/path.c"
#include "json/rangstr.c"
#include "json/indent.c"

SDB_API char *sdb_json_get (Sdb *s, const char *k, const char *p, ut32 *cas) {
	Rangstr rs;
	char *u, *v = sdb_get (s, k, cas);
	if (!v) return NULL;
	rs = json_get (v, p);
	u = rangstr_dup (&rs);
	free (v);
	return u;
}

SDB_API int sdb_json_num_inc(Sdb *s, const char *k, const char *p, int n, ut32 cas) {
	ut32 c;
	int cur = sdb_json_num_get (s, k, p, &c);
	if (cas && c != cas)
		return 0;
	sdb_json_num_set (s, k, p, cur+n, cas);
	return cur+n;
}

SDB_API int sdb_json_num_dec(Sdb *s, const char *k, const char *p, int n, ut32 cas) {
	ut32 c;
	int cur = sdb_json_num_get (s, k, p, &c);
	if (cas && c != cas)
		return 0;
	sdb_json_num_set (s, k, p, cur-n, cas);
	return cur-n;
}

SDB_API int sdb_json_num_get (Sdb *s, const char *k, const char *p, ut32 *cas) {
	char *v = sdb_get (s, k, cas);
	if (v) {
		Rangstr rs = json_get (v, p);
		return rangstr_int (&rs);
	}
	return 0;
}

static int findkey(Rangstr *rs) {
	int i;
	for (i = rs->f ; i>0; i--) {
		if (rs->p[i] == '"') {
			for (--i;i>0; i--) {
				if (rs->p[i] == '"')
					return i;
			}
		}
	}
	return -1;
}

static int isstring(const char *s) {
	if (!strcmp (s, "true"))
		return 0;
	if (!strcmp (s, "false"))
		return 0;
	for (;*s;s++) {
		if (*s<'0' || *s>'9')
			return 1;
	}
	return 0;
}

// JSON only supports base16 numbers
SDB_API int sdb_json_num_set (Sdb *s, const char *k, const char *p, int v, ut32 cas) {
	char *_str, str[64];
	_str = sdb_itoa (v, str, 10);
	return sdb_json_set (s, k, p, _str, cas);
}

SDB_API int sdb_json_unset (Sdb *s, const char *k, const char *p, ut32 cas) {
	return sdb_json_set (s, k, p, NULL, cas);
}

SDB_API int sdb_json_set (Sdb *s, const char *k, const char *p, const char *v, ut32 cas) {
	const char *beg[3];
	const char *end[3];
	int l, idx, len[3];
	char *b, *js, *str = NULL;
	Rangstr rs;
	ut32 c;

	if (!s || !k)
		return 0; 
	js = sdb_get (s, k, &c);
	if (!js) {
		b = malloc (strlen (p)+strlen (v)+8);
		if (b) {
			int is_str = isstring (v);
			const char *q = is_str?"\"":"";
			sprintf (b, "{\"%s\":%s%s%s}", p, q, v, q);
#if 0
			/* disabled because it memleaks */
			sdb_set_owned (s, k, b, cas);
#else
			sdb_set (s, k, b, cas);
			free (b);
#endif
			return 1;
		}
		return 0;
	}
	if (cas && c != cas) {
		free (js);
		return 0;
	}
	rs = json_get (js, p);
	if (!rs.p) {
		char *b = malloc (strlen (js)+strlen(k)+strlen (v)+32);
		if (b) {
			int curlen, is_str = isstring (v);
			const char *q = is_str?"\"":"";
			const char *e = ""; // XX: or comma
			if (js[0] && js[1] != '}')
				e = ",";
			curlen = sprintf (b, "{\"%s\":%s%s%s%s",
				p, q, v, q, e);
			strcpy (b+curlen, js+1);
			// transfer ownership
			sdb_set_owned (s, k, b, cas);
			free (js);
			return 1;
		}
		// invalid json?
		free (js);
		return 0;
	} 
#define WLEN(x) (int)(size_t)(end[x]-beg[x])

	beg[0] = js;
	end[0] = rs.p + rs.f;
	len[0] = WLEN (0);

	if (*v) {
		beg[1] = v;
		end[1] = v + strlen (v);
		len[1] = WLEN (1);
	}

	beg[2] = rs.p + rs.t;
	end[2] = js + strlen (js);
	len[2] = WLEN (2);

	// TODO: accelerate with small buffer in stack for small jsons
	if (*v) {
		int is_str = isstring (v);
		int msz = len[0]+len[1]+len[2]+strlen (v);
		if (msz<1)
			return 0;
		str = malloc (msz);
		idx = len[0];
		memcpy (str, beg[0], idx);
		if (is_str) {
			if (beg[2][0]!='"') {
				str[idx]='"';
				idx++;
			}
		} else {
			if (beg[2][0]=='"') {
				idx--;
			}
		}
		l = len[1];
		memcpy (str+idx, beg[1], l);
		idx += len[1];
		if (is_str) {
			// TODO: add quotes
			if (beg[2][0]!='"') {
				str[idx]='"';
				idx++;
			}
		} else {
			if (beg[2][0]=='"') {
				beg[2]++;
			}
		}
		l = len[2];
		memcpy (str+idx, beg[2], l);
		str[idx+l] = 0;
	} else {
		int kidx;
		// DELETE KEY
		rs.f -= 2;
		kidx = findkey (&rs);
		len[0] = R_MAX (1, kidx-1);
		if (kidx==1){
			if (beg[2][0]=='"')
				beg[2]++;
			beg[2]++;
		}
		str = malloc (len[0]+len[2]+1);
		if (!str)
			return 0;
		memcpy (str, beg[0], len[0]);
		if (!*beg[2])
			beg[2]--;
		memcpy (str+len[0], beg[2], len[2]);
		str[len[0]+len[2]] = 0;
	}
	sdb_set_owned (s, k, str, cas);
	free (js);
	return 1;
}

SDB_API const char *sdb_json_format(SdbJsonString* s, const char *fmt, ...) {
	char *arg_s, *x, tmp[128];
	unsigned long long arg_l;
	int i, arg_i;
	float arg_f;
	va_list ap;

#define JSONSTR_ALLOCATE(y) \
	if (s->len+y>s->blen) {\
		s->blen *= 2;\
		x = realloc (s->buf, s->blen);\
		if (!x) { \
			va_end (ap); \
			return NULL;\
		}\
		s->buf = x;\
	}
	if (!s) return NULL;
	if (!s->buf) {
		s->blen = 1024;
		s->buf = malloc (s->blen);
		if (!s->buf)
			return NULL;
		*s->buf = 0;
	}
	if (!fmt || !*fmt) return s->buf;
	va_start (ap, fmt);
	for (; *fmt; fmt++) {
		if (*fmt == '%') {
			fmt++;
			switch (*fmt) {
			case 'b':
				JSONSTR_ALLOCATE (32);
				arg_i = va_arg (ap, int);
				arg_i = arg_i? 4: 5;
				memcpy (s->buf+s->len, arg_i==4?"true":"false", 5);
				s->len += arg_i;
				break;
			case 'f':
				JSONSTR_ALLOCATE (32);
				arg_f = va_arg (ap, int);
				snprintf (tmp, sizeof (tmp), "%f", arg_f);
				memcpy (s->buf+s->len, tmp, strlen (tmp));
				s->len += strlen (tmp);
				break;
			case 'l':
				JSONSTR_ALLOCATE (32);
				arg_l = va_arg (ap, unsigned long long);
				snprintf (tmp, sizeof (tmp), "0x%"ULLFMT"x", arg_l);
				memcpy (s->buf+s->len, tmp, strlen (tmp));
				s->len += strlen (tmp);
				break;
			case 'd':
			case 'i':
				JSONSTR_ALLOCATE (32);
				arg_i = va_arg (ap, int);
				snprintf (tmp, sizeof (tmp), "%d", arg_i);
				memcpy (s->buf+s->len, tmp, strlen (tmp));
				s->len += strlen (tmp);
				break;
			case 's':
				arg_s = va_arg (ap, char *);
				JSONSTR_ALLOCATE (strlen (arg_s)+3);
				s->buf[s->len++] = '"';
				for (i=0; arg_s[i]; i++) {
					if (arg_s[i]=='"')
						s->buf[s->len++] = '\\';
					s->buf[s->len++] = arg_s[i];
				}
				s->buf[s->len++] = '"';
				break;
			}
		} else {
			JSONSTR_ALLOCATE (10);
			s->buf[s->len++] = *fmt;
		}
		s->buf[s->len] = 0;
	}
	va_end (ap);
	return s->buf;
}

#if 0
int main () {
	SdbJsonString s = {0};
	sdb_json_format (&s, "[{%s:%d},%b]", "Hello \"world\"", 1024, 3);
	printf ("%s\n", sdb_json_format (&s, 0));
	sdb_json_format_free (&s);
	return 0;
}
#endif
