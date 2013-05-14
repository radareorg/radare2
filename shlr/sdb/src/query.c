/* sdb - LGPLv3 - Copyright 2011-2013 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
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

SDB_VISIBLE char *sdb_querys (Sdb *s, char *buf, size_t len, const char *cmd) {
	const char *q;
	char *p, *eq, *ask;
	int i, ok, w, alength;
	ut64 n;
	if (cmd == NULL) {
		cmd = buf;
		buf = NULL;
	}
	if (!len || !buf) buf = malloc ((len=32));

	ask = strchr (cmd, '?');
	if (*cmd == '+' || *cmd == '-') {
		*buf = 0;
		if (ask) {
			*ask = 0;
			if (*cmd=='+') n = sdb_json_inc (s, cmd+1, ask+1, 1, 0);
			else n = sdb_json_dec (s, cmd+1, ask+1, 1, 0);
			*ask = '?';
		} else {
			if (*cmd=='+') n = sdb_inc (s, cmd+1, 1, 0);
			else n = sdb_dec (s, cmd+1, 1, 0);
		}
		w = snprintf (buf, len-1, "%"ULLFMT"d", n);
		if (w<0 || (size_t)w>len) {
			buf = malloc (0xff);
			snprintf (buf, 0xff, "%"ULLFMT"d", n);
		}
		return buf;
	} else if (*cmd == '(') {
		p = strchr (cmd, ')');
		if (!p) {
			fprintf (stderr, "Missing ')'.\n");
			return NULL;
		}
		*p = 0;
		eq = strchr (p+1, '=');
		if (cmd[1]=='?') {
			// if (!eq) { ...
			alength = sdb_alength (s, p+1);
			w = snprintf (buf, len, "%d", alength);
			if (w<0 || (size_t)w>len) {
				buf = malloc (32);
				snprintf (buf, 32, "%d", alength);
			}
			return buf;
		}
		if (cmd[1]) {
			i = atoi (cmd+1);
			if (eq) {
				*eq = 0;
				ok = eq[1]? (
					(cmd[1]=='+')?
						sdb_ains (s, p+1, i, eq+1, 0):
						sdb_aset (s, p+1, i, eq+1, 0)
					): sdb_adel (s, p+1, i, 0);
				if (ok) *buf = 0; else buf = NULL;
				return buf;
			}
			return sdb_aget (s, p+1, i, NULL);
		} else {
			if (eq) {
				char *q, *out = strdup (eq+1);
				*eq = 0;
				// TODO: define new printable separator character
				for (q=out; *q; q++) if (*q==',') *q = SDB_RS;
				ok = sdb_set (s, p+1, out, 0);
				free (out);
				if (ok) {
					*buf = 0;
					return buf;
				}
			} else {
				const char *out = sdb_getc (s, p+1, 0);
				size_t wl;
				if (!out) return NULL;
				wl = strlen (out);
				if (wl>len) buf = malloc (wl+2);
				for (i=0; out[i]; i++)
					buf[i] = out[i]==SDB_RS? '\n': out[i];
				buf[i] = 0;
				return buf;
			}
		}
	} else {
		eq = strchr (cmd, '=');
		if (eq) {
			// 1 0 kvpath=value
			// 1 1 kvpath?jspath=value
			if (ask>eq) ask = NULL;
			*eq++ = 0;
			if (ask) {
				*ask++ = 0;
				ok = sdb_json_set (s, cmd, ask, eq, 0);
			} else ok = sdb_set (s, cmd, eq, 0);
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
					return p;
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
