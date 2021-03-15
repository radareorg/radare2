/* sdb - MIT - Copyright 2012-2021 - pancake */

#include <stdarg.h>
#include "sdb.h"
#include "json/rangstr.c"
#include "json/js0n.c"
#include "json/path.c"
#include "json/api.c"
#include "json/indent.c"

SDB_API char *sdb_json_get_str (const char *json, const char *path) {
	Rangstr rs = json_get (json, path);
	return rangstr_dup (&rs);
}

SDB_API bool sdb_json_get_bool(const char *json, const char *path) {
	Rangstr rs = json_get (json, path);
	const char *p = rs.p + rs.f;
	return (rangstr_length (&rs) == 4 && !strncmp (p, "true", 4));
}

SDB_API char *sdb_json_get(Sdb *s, const char *k, const char *p, ut32 *cas) {
	Rangstr rs;
	char *u, *v = sdb_get (s, k, cas);
	if (!v) {
		return NULL;
	}
	rs = json_get (v, p);
	u = rangstr_dup (&rs);
	free (v);
	return u;
}

SDB_API int sdb_json_num_inc(Sdb *s, const char *k, const char *p, int n, ut32 cas) {
	ut32 c;
	int cur = sdb_json_num_get (s, k, p, &c);
	if (cas && c != cas) {
		return 0;
	}
	sdb_json_num_set (s, k, p, cur + n, cas);
	return cur + n;
}

SDB_API int sdb_json_num_dec(Sdb *s, const char *k, const char *p, int n, ut32 cas) {
	ut32 c;
	int cur = sdb_json_num_get (s, k, p, &c);
	if (cas && c != cas) {
		return 0;
	}
	sdb_json_num_set (s, k, p, cur - n, cas);
	return cur - n;
}

SDB_API int sdb_json_num_get(Sdb *s, const char *k, const char *p, ut32 *cas) {
	char *v = sdb_get (s, k, cas);
	if (v) {
		Rangstr rs = json_get (v, p);
		int ret = rangstr_int (&rs);
		free (v);
		return ret;
	}
	return 0;
}

static int findkey(Rangstr *rs) {
	int i;
	for (i = rs->f; i > 0; i--) {
		// Find the quote after the key
		if (rs->p[i] == '"') {
			for (--i; i > 0; i--) {
				// Find the quote before the key
				if (rs->p[i] == '"') {
					return i;
				}
			}
		}
	}
	return -1;
}

static bool isstring(const char *s) {
	if (!strcmp (s, "true")) {
		return false;
	}
	if (!strcmp (s, "false")) {
		return false;
	}
	for (; *s; s++) {
		if (*s < '0' || *s > '9') {
			return true;
		}
	}
	return false;
}

// JSON only supports base16 numbers
SDB_API int sdb_json_num_set(Sdb *s, const char *k, const char *p, int v, ut32 cas) {
	char *_str, str[64];
	_str = sdb_itoa (v, str, 10);
	return sdb_json_set (s, k, p, _str, cas);
}

SDB_API int sdb_json_unset(Sdb *s, const char *k, const char *p, ut32 cas) {
	return sdb_json_set (s, k, p, NULL, cas);
}

SDB_API bool sdb_json_set(Sdb *s, const char *k, const char *p, const char *v, ut32 cas) {
	int l, idx, len[3], jslen = 0;
	char *b, *str = NULL;
	const char *beg[3];
	const char *end[3];
	const char *js;
	Rangstr rs;
	ut32 c;

	if (!s || !k || !v) {
		return false;
	}
	js = sdb_const_get_len (s, k, &jslen, &c);
	if (!js) {
		const int v_len = strlen (v);
		const int p_len = strlen (p);
		b = malloc (p_len + v_len + 8);
		if (b) {
			int is_str = isstring (v);
			const char *q = is_str? "\"": "";
			sprintf (b, "{\"%s\":%s%s%s}", p, q, v, q);
#if 0
			/* disabled because it memleaks */
			sdb_set_owned (s, k, b, cas);
#else
			sdb_set (s, k, b, cas);
			free (b);
#endif
			return true;
		}
		return false;
	}
	jslen++;
	if (cas && c != cas) {
		return false;
	}
	rs = json_get (js, p);
	if (!rs.p) {
		// jslen already comprehends the NULL-terminator and is
		// ensured to be positive by sdb_const_get_len
		// 7 corresponds to the length of '{"":"",'
		size_t buf_len = jslen + strlen (p) + strlen (v) + 7;
		char *buf = malloc (buf_len);
		if (buf) {
			int curlen, is_str = isstring (v);
			const char *quote = is_str ? "\"" : "";
			const char *end = ""; // XX: or comma
			if (js[0] && js[1] != '}') {
				end = ",";
			}
			curlen = sprintf (buf, "{\"%s\":%s%s%s%s",
				p, quote, v, quote, end);
			strcpy (buf + curlen, js + 1);
			// transfer ownership
			sdb_set_owned (s, k, buf, cas);
			return true;
		}
		// invalid json?
		return false;
	}

	// rs.p and js point to the same memory location
	beg[0] = js;
	end[0] = rs.p + rs.f;
	len[0] = WLEN (0);

	if (*v) {
		beg[1] = v;
		end[1] = v + strlen (v);
		len[1] = WLEN (1);
	}

	beg[2] = rs.p + rs.t;
	end[2] = js + jslen;
	len[2] = WLEN (2);

	// TODO: accelerate with small buffer in stack for small jsons
	if (*v) {
		int is_str = isstring (v);
		// 2 is the maximum amount of quotes that can be inserted
		int msz = len[0] + len[1] + len[2] + strlen (v) + 2;
		if (msz < 1) {
			return false;
		}
		str = malloc (msz);
		if (!str) {
			return false;
		}
		idx = len[0];
		memcpy (str, beg[0], idx);
		if (is_str) {
			if (beg[2][0] != '"') {
				str[idx] = '"';
				idx++;
			}
		} else {
			if (beg[2][0] == '"') {
				beg[2]++;
				len[2]--;
			}
		}
		l = len[1];
		memcpy (str + idx, beg[1], l);
		idx += len[1];
		if (is_str) {
			// TODO: add quotes
			if (beg[2][0] != '"') {
				str[idx] = '"';
				idx++;
			}
		} else {
			if (beg[2][0] == '"') {
				beg[2]++;
				len[2]--;
			}
		}
		l = len[2];
		memcpy (str + idx, beg[2], l);
		str[idx + l] = 0;
	} else {
		int kidx;
		// DELETE KEY
		rs.f -= 2;
		kidx = findkey (&rs);
		len[0] = R_MAX (1, kidx - 1);

		// Delete quote if deleted value was a string
		if (beg[2][0] == '"') {
			beg[2]++;
			len[2]--;
		}

		// If not the last key, delete comma
		if (len[2] != 2) {
			beg[2]++;
			len[2]--;
		}

		str = malloc (len[0] + len[2] + 1);
		if (!str) {
			return false;
		}

		memcpy (str, beg[0], len[0]);
		memcpy (str + len[0], beg[2], len[2]);
		str[len[0] + len[2]] = 0;
	}
	sdb_set_owned (s, k, str, cas);
	return true;
}

SDB_API const char *sdb_json_format(SdbJsonString *s, const char *fmt, ...) {
	char *arg_s, *x, tmp[128];
	ut64 arg_l;
	int i, arg_i;
	double arg_f;
	va_list ap;
#define JSONSTR_ALLOCATE(y)\
	if (s->len + y > s->blen) {\
		s->blen *= 2;\
		x = realloc (s->buf, s->blen);\
		if (!x) {\
			va_end (ap);\
			return NULL;\
		}\
		s->buf = x;\
	}
	if (!s) {
		return NULL;
	}
	if (!s->buf) {
		s->blen = 1024;
		s->buf = malloc (s->blen);
		if (!s->buf) {
			return NULL;
		}
		*s->buf = 0;
	}
	if (!fmt || !*fmt) {
		return s->buf;
	}
	va_start (ap, fmt);
	for (; *fmt; fmt++) {
		if (*fmt == '%') {
			fmt++;
			switch (*fmt) {
			case 'b':
				JSONSTR_ALLOCATE (32);
				arg_i = va_arg (ap, int);
				arg_i = arg_i? 4: 5;
				memcpy (s->buf + s->len, (arg_i == 4)? "true": "false", 5);
				s->len += arg_i;
				break;
			case 'f':
				JSONSTR_ALLOCATE (32);
				arg_f = va_arg (ap, double);
				snprintf (tmp, sizeof (tmp), "%f", arg_f);
				memcpy (s->buf + s->len, tmp, strlen (tmp));
				s->len += strlen (tmp);
				break;
			case 'l':
				JSONSTR_ALLOCATE (32);
				arg_l = va_arg (ap, ut64);
				snprintf (tmp, sizeof (tmp), "0x%"ULLFMT "x", arg_l);
				memcpy (s->buf + s->len, tmp, strlen (tmp));
				s->len += strlen (tmp);
				break;
			case 'd':
			case 'i':
				JSONSTR_ALLOCATE (32);
				arg_i = va_arg (ap, int);
				snprintf (tmp, sizeof (tmp), "%d", arg_i);
				memcpy (s->buf + s->len, tmp, strlen (tmp));
				s->len += strlen (tmp);
				break;
			case 's':
				arg_s = va_arg (ap, char *);
				JSONSTR_ALLOCATE (strlen (arg_s) + 3);
				s->buf[s->len++] = '"';
				for (i = 0; arg_s[i]; i++) {
					if (arg_s[i] == '"') {
						s->buf[s->len++] = '\\';
					}
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
	SdbJsonString s = {
		0
	};
	sdb_json_format (&s, "[{%s:%d},%b]", "Hello \"world\"", 1024, 3);
	printf ("%s\n", sdb_json_format (&s, 0));
	sdb_json_format_free (&s);
	return 0;
}
#endif
