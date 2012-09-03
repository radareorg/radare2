/* Copyleft 2012 - sdb (aka SimpleDB) - pancake<nopcode.org> */

#include "sdb.h"
#include "json/json.h"

static int itoa(int value, char *string) {
	int i, sign, count;
	char buf[64];
	char *temp = buf;
	char *ptr = string;

	count = 0;
	temp[0] = 0;
	string[0] = 0;

	if ((sign = value) < 0) {
		value = -value;
		count++;
	}
	do {
		*temp++ = value % 10 + '0';
		count++;
	} while ((value /= 10)>0);
	if (sign < 0)
		*temp++ = '-';
	*temp-- = '\0';
	/* reverse string */
	for (i = 0; i < count; i++, temp--, ptr++)
		*ptr = *temp;
	*ptr = 0;
	return 1;
}

char *sdb_json_get (Sdb *s, const char *k, const char *p, ut32 *cas) {
	char *u, *v = sdb_get (s, k, cas);
	if (!v) return NULL;
	Rangstr rs = json_get (v, p);
	u = rangstr_dup (&rs);
	free (v);
	return u;
}

int sdb_json_inc(Sdb *s, const char *k, const char *p, int n, ut32 cas) {
	int cur = sdb_json_geti (s, k, p);
	sdb_json_seti (s, k, p, cur+n, cas);
	return cur;
}

int sdb_json_dec(Sdb *s, const char *k, const char *p, int n, ut32 cas) {
	int cur = sdb_json_geti (s, k, p);
	sdb_json_seti (s, k, p, cur-n, cas);
	return cur;
}

int sdb_json_geti (Sdb *s, const char *k, const char *p) {
	char *v = sdb_get (s, k, 0); // XXX cas
	if (v) {
		Rangstr rs = json_get (v, p);
		return rangstr_int (&rs);
	}
	return 0;
}

int sdb_json_seti (Sdb *s, const char *k, const char *p, int v, ut32 cas) {
	char str[64];
	str[0] = 0;
	itoa (v, str);
	return sdb_json_set (s, k, p, str, cas);
}

int sdb_json_set (Sdb *s, const char *k, const char *p, const char *v, ut32 cas) {
	const char *beg[3];
	const char *end[3];
	int l, idx, len[3];
	char *str = NULL;
	Rangstr rs;
	ut32 c;
	char *js = sdb_get (s, k, &c);
	if (cas && c != cas) {
		free (js);
		return 0;
	}

	if (!js) return 0;
	rs = json_get (js, p);
	if (!rs.p) {
		free (js);
		return 0;
	}
#define WLEN(x) (int)(size_t)(end[x]-beg[x])

	beg[0] = js;
	end[0] = rs.p + rs.f;
	len[0] = WLEN (0);

	beg[1] = v;
	end[1] = v + strlen (v);
	len[1] = WLEN (1);

	beg[2] = rs.p + rs.t;
	end[2] = js + strlen (js);
	len[2] = WLEN (2);

	// TODO: accelerate with small buffer in stack for small jsons
	str = malloc (len[0]+len[1]+len[2]+1);
	idx = len[0];
	memcpy (str, beg[0], idx);
	l = len[1];
	memcpy (str+idx, beg[1], l);
	idx += len[1];
	l = len[2];
	memcpy (str+idx, beg[2], l);
	str[idx+l] = 0;

	sdb_set (s, k, str, cas);
	free (str);
	free (js);
	return 1;
}

char *sdb_json_indent(const char *s) {
	int indent = 0;
	int i, instr = 0;
	char *o, *O = malloc (strlen (s)*2);
	for (o=O; *s; s++) {
		if (instr) {
			if (s[0] == '"') {
				instr = 0;
			} else {
				if (s[0] == '\\' && s[1] == '"')
					*o++ = *s;
			}
			*o++ = *s;
			continue;
		} else {
			if (s[0] == '"')
				instr = 1;
		}
		if (*s == '\n'|| *s == '\r' || *s == '\t' || *s == ' ')
			continue;
		#define INDENT(x) indent+=x; for (i=0;i<indent;i++) *o++ = '\t'
		switch (*s) {
                case ':':
                        *o++ = *s;
                        *o++ = ' ';
                        break;
                case ',':
                        *o++ = *s;
                        *o++ = '\n';
                        INDENT(0);
                        break;
                case '{':
                case '[':
                        if (indent!=-1 ) {
                                *o++ = *s;
                                *o++ = '\n';
                        } else {
                                *o++ = *s;
                                *o++ = ' ';
                        }
                        INDENT (1);
                        break;
                case '}':
                case ']':
                        *o++ = '\n';
                        INDENT (-1);
                        *o++ = *s;
                        break;
		default:
			*o++ = *s;
		}
	}
	*o = 0;
	return O;
}

char *sdb_json_unindent(const char *s) {
	int instr = 0;
	int len = strlen (s);
	char *o, *O = malloc (len);
	if (!O) return NULL;
	memset (O, 0, len);
	for (o=O; *s; s++) {
		if (instr) {
			if (s[0] == '"') {
				instr = 0;
			} else {
				if (s[0] == '\\' && s[1] == '"')
					*o++ = *s;
			}
			*o++ = *s;
			continue;
		} else {
			if (s[0] == '"')
				instr = 1;
		}
		if (*s == '\n'|| *s == '\r' || *s == '\t' || *s == ' ')
			continue;
		*o++ = *s;
	}
	*o = 0;
	return O;
}
