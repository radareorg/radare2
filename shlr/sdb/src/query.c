/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "sdb.h"

SDB_VISIBLE int sdb_queryf (Sdb *s, const char *fmt, ...) {
        char string[4096];
        int ret;
        va_list ap;
        va_start (ap, fmt);
        vsnprintf (string, sizeof (string), fmt, ap);
        ret = sdb_query (s, string);
        va_end (ap);
        return ret;
}

SDB_VISIBLE char *sdb_querysf (Sdb *s, char *buf, size_t buflen, const char *fmt, ...) {
        char string[4096];
        char *ret;
        va_list ap;
        va_start (ap, fmt);
        vsnprintf (string, sizeof (string), fmt, ap);
        ret = sdb_querys (s, buf, buflen, string);
        va_end (ap);
        return ret;
}

// XXX: cmd is reused
SDB_VISIBLE char *sdb_querys (Sdb *s, char *buf, size_t len, const char *cmd) {
	const char *p, *q, *val = NULL;
	char *eq, *ask;
	int i, d, ok, w, alength;
	ut64 n;
	if (!s) return NULL;
	if (cmd == NULL) {
		cmd = buf;
		buf = NULL;
	}
	if (!len || !buf) buf = malloc ((len=64));
	ask = strchr (cmd, '?');
	if (*cmd == '(') {
		char *tp = strchr (cmd, ')');
		if (!tp) {
			fprintf (stderr, "Missing ')'.\n");
			return NULL;
		}
		*tp++ = 0;
		p = (const char *)tp;
	} else p = cmd;
	eq = strchr (p, '=');
	if (eq) {
		*eq++ = 0;
		if (*eq=='$')
			val = sdb_getc (s, eq+1, 0);
	}
	if (!val) val = eq;
	if (*cmd=='$')
		cmd = sdb_getc (s, cmd+1, 0);
	// cmd = val
	// cmd is key and val is value

	if (*cmd == '.') {
		sdb_query_file (s, cmd+1);
	} else
	if (*cmd == '+' || *cmd == '-') {
		d = 1;
		*buf = 0;
		if (val) {
			d = sdb_atoi (val);
			if (d) {
				if (*cmd=='+')
					sdb_inc (s, cmd+1, d, 0);
				else
					sdb_dec (s, cmd+1, d, 0);
			} else {
				sdb_concat (s, cmd+1, val, 0);
			}
		} else {
			if (ask) {
				*ask = 0;
				if (*cmd=='+') n = sdb_json_inc (s, cmd+1, ask+1, d, 0);
				else n = sdb_json_dec (s, cmd+1, ask+1, d, 0);
				*ask = '?';
			} else {
				if (*cmd=='+') n = sdb_inc (s, cmd+1, d, 0);
				else n = sdb_dec (s, cmd+1, d, 0);
			}
			w = snprintf (buf, len-1, "%"ULLFMT"d", n);
			if (w<0 || (size_t)w>len) {
				buf = malloc (0xff);
				snprintf (buf, 0xff, "%"ULLFMT"d", n);
			}
			return buf;
		}
	} else if (*cmd == '(') {
		if (cmd[1]=='?') {
			// if (!eq) { ...
			alength = sdb_alength (s, p);
			w = snprintf (buf, len, "%d", alength);
			if (w<0 || (size_t)w>len) {
				buf = malloc (32);
				snprintf (buf, 31, "%d", alength);
			}
			return buf;
		}
		if (cmd[1]=='+'||cmd[1]=='-') {
			/* (+)foo=bla (-)foo=bla */
			if (!cmd[2] || cmd[2] ==')') {
				// insert
				if (eq) {
					if (cmd[1]=='+') {
						if (sdb_agetv (s, p, val, 0)== -1)
							sdb_aset (s, p, -1, val, 0);
					} else sdb_adels (s, p, val, 0);
					return NULL;
				} else {
					char *ret;
					if (cmd[1]=='+') {
// XXX: this is a little strange syntax to remove an item
						ret = sdb_aget (s, p, 0, 0);
						// (+)foo :: remove first element
						sdb_adel (s, p, 0, 0);
					} else {
						ret = sdb_aget (s, p, -1, 0);
						// (-)foo :: remove last element
						sdb_adel (s, p, -1, 0);
					}
					return ret;
				}
			} else {
				// get/set specific element in array
				/* (+3)foo=bla */
				i = atoi (cmd+1);
				if (eq) {
					ok = cmd[1]? (
							(cmd[1]=='+')?
							sdb_ains (s, p, i, val, 0):
							sdb_aset (s, p, i, val, 0)
						    ): sdb_adel (s, p, i, 0);
					if (ok) *buf = 0; else buf = NULL;
					return buf;
				}
				return sdb_aget (s, p, i, NULL);
			}
		} else {
			if (eq) {
				/* (3)foo=bla */
				char *q, *out = strdup (val);
				// TODO: define new printable separator character
				for (q=out; *q; q++) if (*q==',') *q = SDB_RS;
				if (cmd[1]) {
					int idx = atoi (cmd+1);
					ok = sdb_aset (s, p, idx, val, 0);
// TODO: handle when idx > sdb_alen
				} else {
					ok = sdb_set (s, p, out, 0);
				}
				free (out);
				if (ok) {
					*buf = 0;
					return buf;
				}
			} else {
				/* (3)foo */
				const char *out = sdb_getc (s, p, 0);
				size_t wl;
				if (cmd[1]) {
					i = atoi (cmd+1);
					return sdb_aget (s, p, i, NULL);
				}
				if (!out) return NULL;
				wl = strlen (out);
				if (wl>len) buf = malloc (wl+2);
				for (i=0; out[i]; i++) {
					if (out[i+1])
					buf[i] = out[i]==SDB_RS? '\n': out[i];
					else buf[i] = out[i];
				}
				buf[i] = 0;
				return buf;
			}
		}
	} else {
		if (eq) {
			// 1 0 kvpath=value
			// 1 1 kvpath?jspath=value
			if (ask>eq) ask = NULL;
			if (ask) {
				*ask++ = 0;
				ok = sdb_json_set (s, cmd, ask, val, 0);
			} else ok = sdb_set (s, cmd, val, 0);
			if (!ok) return NULL;
			*buf = 0;
			return buf;
		} else {
			// 0 1 kvpath?jspath
			// 0 0 kvpath
			if (ask) {
				*ask++ = 0;
				// TODO: not optimized to reuse 'buf'
				if ((p = sdb_json_get (s, cmd, ask, 0)))
					return strdup (p);
			} else {
				// sdbget
				if (!(q = sdb_getc (s, cmd, 0)))
					return NULL;
				if (strlen (q)> len) return strdup (q);
				strcpy (buf, q);
				return buf;
			}
		}
	}
	return NULL;
}

SDB_VISIBLE int sdb_query (Sdb *s, const char *cmd) {
	char buf[1024], *out = sdb_querys (s, buf, sizeof (buf), cmd);
	if (!out) return 0;
	if (*out) puts (out);
	if (out != buf) free (out);
	return 1;
}

SDB_VISIBLE int sdb_query_lines (Sdb *s, const char *cmd) {
	char *o, *p, *op = strdup (cmd);
	if (!s || !op) return 0;
	p = op;
	do {
		o = strchr (p, '\n');
		if (o) *o = 0;
		sdb_query (s, p);
		if (o) p = o+1;
	} while (o);
	free (op);
	return 1;
}

static char *slurp(const char *file) {
	int ret, fd = open (file, O_RDONLY);
	char *text;
	long sz;
	if (fd == -1)
		return NULL;
	sz = lseek (fd, 0, SEEK_END);
	if (sz<0)
		return NULL;
	lseek (fd, 0, SEEK_SET);
	text = malloc (sz+1);
	if (!text) {
		close (fd);
		return NULL;
	}
	ret = read (fd, text, sz);
	if (ret != sz) {
		free (text);
		text = NULL;
	} else text[sz] = 0;
	close (fd);
	return text;
}

SDB_VISIBLE int sdb_query_file(Sdb *s, const char* file) {
	char *txt = slurp (file);
	int ret = sdb_query_lines (s, txt);
	free (txt);
	return ret;
}
