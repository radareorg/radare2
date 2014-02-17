/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "sdb.h"

SDB_API int sdb_queryf (Sdb *s, const char *fmt, ...) {
        char string[4096];
        int ret;
        va_list ap;
        va_start (ap, fmt);
        vsnprintf (string, sizeof (string), fmt, ap);
        ret = sdb_query (s, string);
        va_end (ap);
        return ret;
}

SDB_API char *sdb_querysf (Sdb *s, char *buf, size_t buflen, const char *fmt, ...) {
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
#define out_concat(x) if (x) { char *o =(void*)realloc((void*)out, 2+strlen(x)+(out?strlen(out):0)); if (o) { if (out) strcat (out, "\n"); else *o=0; out=o; strcat (out, x); } }

SDB_API char *sdb_querys (Sdb *s, char *buf, size_t len, const char *cmd) {
	int i, d, ok, w, alength, bufset = 0;
	const char *p, *q, *val = NULL;
	char *eq, *tmp, *json, *next, *out = NULL;
	ut64 n;
	if (!s) return NULL;
	if (!len || !buf) {
		bufset = 1;
		buf = malloc ((len=64));
	}
	if (cmd == NULL) {
		cmd = buf;
		buf = NULL;
	}
repeat:
	next = strchr (cmd, ';');
	if (next) *next = 0;
	json = strchr (cmd, ':');
	if (*cmd == '[') {
		char *tp = strchr (cmd, ']');
		if (!tp) {
			fprintf (stderr, "Missing ']'.\n");
			goto failure;
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
		if (!sdb_query_file (s, cmd+1)) {
			fprintf (stderr, "sdb: Cannot open '%s'\n", cmd+1);
			goto failure;
		}
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
			if (json) {
				*json = 0;
				if (*cmd=='+') n = sdb_json_inc (s, cmd+1, json+1, d, 0);
				else n = sdb_json_dec (s, cmd+1, json+1, d, 0);
				*json = ':';
			} else {
				if (*cmd=='+') n = sdb_inc (s, cmd+1, d, 0);
				else n = sdb_dec (s, cmd+1, d, 0);
			}
			w = snprintf (buf, len-1, "%"ULLFMT"d", n);
			if (w<0 || (size_t)w>len) {
				buf = malloc (0xff);
				snprintf (buf, 0xff, "%"ULLFMT"d", n);
			}
		}
		return buf;
	} else if (*cmd == '[') {
		// [?] - count elements of array
		if (cmd[1]=='?') {
			// if (!eq) { ...
			alength = sdb_alength (s, p);
			w = snprintf (buf, len, "%d", alength);
			if (w<0 || (size_t)w>len) {
				buf = malloc (32);
				snprintf (buf, 31, "%d", alength);
				bufset = 1;
			}
			out_concat (buf);
		} else
		if (cmd[1]=='+'||cmd[1]=='-') {
			// [+]foo        remove first element */
			// [+]foo=bar    PUSH */
			// [-]foo        POP */
			// [-]foo=xx     POP  (=xx ignored) */
			if (!cmd[2] || cmd[2] ==']') {
				// insert
				if (eq) {
					if (cmd[1]=='+') {
						// [+]K=1
						if (sdb_agetv (s, p, val, 0)==-1)
							sdb_aset (s, p, -1, val, 0);
					} else {
						// [-]K= = remove first element
						sdb_adels (s, p, val, 0);
					}
					//return NULL;
				} else {
					char *ret;
					if (cmd[1]=='+') {
						// [+]K = remove first element
						// XXX: this is a little strange syntax to remove an item
						ret = sdb_aget (s, p, 0, 0);
						out_concat (ret);
						// (+)foo :: remove first element
						sdb_adel (s, p, 0, 0);
					} else {
						// [-]K = remove last element
						ret = sdb_aget (s, p, -1, 0);
						out_concat (ret);
						// (-)foo :: remove last element
						sdb_adel (s, p, -1, 0);
					}
					free (ret);
				}
			} else {
				// get/set specific element in array
				i = atoi (cmd+1);
				if (eq) {
					/* [+3]foo=bla */
					if (i<0) {
						char *tmp = sdb_aget (s, p, -i, NULL);
						ok = 0;
						out_concat (tmp);
						sdb_adel (s, p, -i, 0);
						free (tmp);
					} else {
						ok = cmd[1]? (
							(cmd[1]=='+')?
						sdb_ains (s, p, i, val, 0):
						sdb_aset (s, p, i, val, 0)
						): sdb_adel (s, p, i, 0);
					}
					if (ok) *buf = 0;
					else buf = NULL;
				} else {
					if (i==0) {
						/* [-b]foo */
						if (cmd[1]=='-') {
							sdb_adels (s, p, cmd+2, 0);
						} else {
fprintf (stderr, "TODO: [b]foo -> get index of b key inside foo array\n");
						//	sdb_adels (s, p, cmd+1, 0);
						}
					} else
					if (i<0) {
						/* [-3]foo */
						char *tmp = sdb_aget (s, p, -i, NULL);
						out_concat (tmp);
						free (tmp);
						sdb_adel (s, p, -i, 0);
					} else {
						/* [+3]foo */
						char *tmp = sdb_aget (s, p, i, NULL);
						out_concat (tmp);
						free (tmp);
					}
				}
			}
		} else {
			if (eq) {
				/* [3]foo=bla */
				char *q, *sval = strdup (val);
				// TODO: define new printable separator character
				for (q=sval; *q; q++) if (*q==',') *q = SDB_RS;
				if (cmd[1]) {
					int idx = atoi (cmd+1);
					ok = sdb_aset (s, p, idx, val, 0);
// TODO: handle when idx > sdb_alen
				} else {
					ok = sdb_set (s, p, sval, 0);
				}
				free (sval);
				if (ok) {
					*buf = 0;
					return buf;
				}
			} else {
				/* [3]foo */
				const char *sval = sdb_getc (s, p, 0);
				size_t wl;
				if (cmd[1]) {
					i = atoi (cmd+1);
					tmp = sdb_aget (s, p, i, NULL);
					out_concat (tmp);
					free (tmp);
				} else {
					if (!sval) return NULL;
					wl = strlen (sval);
					if (wl>len) {
						buf = malloc (wl+2);
						bufset = 1;
					}
					for (i=0; sval[i]; i++) {
						if (sval[i+1])
						buf[i] = sval[i]==SDB_RS? '\n': sval[i];
						else buf[i] = sval[i];
					}
					buf[i] = 0;
					out_concat (buf);
				}
			}
		}
	} else {
		if (eq) {
			// 1 0 kvpath=value
			// 1 1 kvpath:jspath=value
			if (json>eq) json = NULL;
			if (json) {
				*json++ = 0;
				ok = sdb_json_set (s, cmd, json, val, 0);
			} else ok = sdb_set (s, cmd, val, 0);
			if (!ok)
				goto failure;
		} else {
			// 0 1 kvpath?jspath
			// 0 0 kvpath
			if (json) {
				*json++ = 0;
				// TODO: not optimized to reuse 'buf'
				if ((tmp = sdb_json_get (s, cmd, json, 0))) {
					out_concat (tmp);
					free (tmp);
				}
			} else {
				// sdbget
				if ((q = sdb_getc (s, cmd, 0))) {
					out_concat (q);
				}
			}
		}
	}
	if (next) {
		if (bufset) {
			free (buf);
			buf = NULL;
			bufset = 0;
		}
		cmd = next+1;
		goto repeat;
	}
failure:
	if (bufset)
		free (buf);
	return out;
}

SDB_API int sdb_query (Sdb *s, const char *cmd) {
	char buf[1024], *out = sdb_querys (s, buf, sizeof (buf), cmd);
	if (!out) return 0;
	if (*out) puts (out);
	if (out != buf) free (out);
	return 1;
}

SDB_API int sdb_query_lines (Sdb *s, const char *cmd) {
	char *o, *p, *op;
	if (!s||!cmd)
		return 0;
	op = strdup (cmd);
	if (!op) return 0;
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
	if (sz<0){
         close (fd);
		return NULL;
    }
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

SDB_API int sdb_query_file(Sdb *s, const char* file) {
	char *txt = slurp (file);
	int ret = sdb_query_lines (s, txt);
	free (txt);
	return ret;
}
