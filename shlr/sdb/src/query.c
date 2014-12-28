/* sdb - LGPLv3 - Copyright 2011-2014 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "sdb.h"

typedef struct {
	char *buf;
	int len;
	int size;
} StrBuf;

static StrBuf* strbuf_new() {
	return calloc (sizeof (StrBuf), 1);
}

#define NEWLINE_AFTER_QUERY 1

static StrBuf* strbuf_append(StrBuf *sb, const char *str, const int nl) {
	int len = strlen (str);
	if ((sb->len + len+2)>=sb->size) {
		int newsize = sb->size+len+256;
		char *b = realloc (sb->buf, newsize);
		/// TODO perform free and force all callers to update the ref?
		if (!b) return NULL;
		sb->buf = b;
		sb->size = newsize;
	}
	memcpy (sb->buf+sb->len, str, len);
	sb->len += len;
#if NEWLINE_AFTER_QUERY
	if (nl) {
		sb->buf[sb->len++] = '\n';
		len++;
	}
#endif
	sb->buf[sb->len] = 0;
	return sb;
}

static StrBuf *strbuf_free(StrBuf *sb) {
	free (sb->buf);
	free (sb);
	return NULL;
}

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

// TODO: Reimplement as a function with optimized concat
#define out_concat(x) if (x&&*x) { \
	strbuf_append (out, x, 1); \
}

typedef struct {
	StrBuf *out;
	int encode;
	char *root;
} ForeachListUser;

static int foreach_list_cb(void *user, const char *k, const char *v) {
	ForeachListUser *rlu = user;
	char *line, *root;
	int rlen, klen, vlen;
	ut8 *v2 = NULL;
	if (!rlu) return 0;
	root = rlu->root;
	klen = strlen (k);
	if (rlu->encode) {
		v2 = sdb_decode (v, NULL);
		if (v2) v = (const char *)v2;
	}
	vlen = strlen (v);
	if (root) {
		rlen = strlen (root);
		line = malloc (klen + vlen + rlen + 3);
		memcpy (line, root, rlen);
		line[rlen]='/'; /*append the '/' at the end of the namespace */
		memcpy (line+rlen+1, k, klen);
		line[rlen+klen+1] = '=';
		memcpy (line+rlen+klen+2, v, vlen+1);
	} else {
		line = malloc (klen + vlen +2);
		memcpy (line, k, klen);
		line[klen] = '=';
		memcpy (line+klen+1,v,vlen+1);
	}
	strbuf_append (rlu->out, line, 1);
	free (v2);
	free (line);
	return 1;
}

static void walk_namespace (StrBuf *sb, char *root, int left, char *p, SdbNs *ns, int encode) {
	int len;
	SdbListIter *it;
	char *_out, *out = sb->buf;
	SdbNs *n;
	ForeachListUser user = { sb, encode, root };
	char *roote = root + strlen (root);
	if (!ns->sdb)
		return;

	/*Pick all key=value in the local ns*/
	sdb_foreach (ns->sdb, foreach_list_cb, &user);

	/*Pick "sub"-ns*/
	ls_foreach (ns->sdb->ns, it, n) {
		len = strlen (n->name);
		p[0] = '/';
		if (len+2<left) {
			memcpy (p+1, n->name, len+1);
			left -= len+2;
		}

		_out = out;
		walk_namespace (sb, root, left,
			roote+len+1, n, encode);
		out = _out;
	}
}

SDB_API char *sdb_querys (Sdb *r, char *buf, size_t len, const char *_cmd) {
	int i, d, ok, w, alength, bufset = 0, is_ref = 0, encode = 0;
	char *eq, *tmp, *json, *next, *quot, *arroba, *res, *cmd, *newcmd = NULL, *oldcmd = NULL;
	const char *p, *q, *val = NULL;
	StrBuf *out;
	Sdb *s = r;
	ut64 n;
	if (!s || (!_cmd && !buf)) return NULL;
	out = strbuf_new ();
	if (_cmd) {
		cmd = newcmd = strdup (_cmd);
		if (!cmd) {
			free (out);
			return NULL;
		}
	} else {
		if (len<1 || !buf) {
			bufset = 1;
			buf = malloc ((len=64));
		}
		cmd = buf;
	}
	// if cmd is null, we take buf as cmd
	next = NULL;
repeat:
	s = r;
	p = cmd;
	eq = NULL;
	encode = 0;
	is_ref = 0;
	quot = NULL;
	json = NULL;
	if (next) *next = ';';
	if (*p=='%') {
		encode = 1;
		cmd++;
		p++;
	}
	eq = strchr (p, '=');
	if (eq) {
		d = 1;
		*eq++ = 0;
		if (*eq=='$') {
			next = strchr (eq+1, ';');
			if (next) *next = 0;
			val = sdb_const_get (s, eq+1, 0);
			if (next) *next = ';';
			is_ref = 1; // protect readonly buffer from being processed
		} else val = eq;
	} else {
		val = NULL;
		d = 0;
	}
	if (!is_ref) {
		next = strchr (val?val:cmd, ';'); //val?val:cmd, ';');
	}
	//if (!val) val = eq;
	if (!is_ref && val && *val == '"') {
		val++;
		// TODO: escape \" too
		quot = (char*)val;
next_quote:
		quot = strchr (quot, '"');
		if (quot) {
			quot--;
			if (*quot=='\\') {
				memmove (quot, quot+1, strlen (quot));
				quot += 2;
				goto next_quote;
			}
			quot++;
			*quot++ = 0; // crash on read only mem!!
		} else {
			eprintf ("Missing quote\n");
			*eq++ = 0;
			out = strbuf_free (out);
			goto fail;
		}
		next = strchr (quot, ';');
	} else {
		quot = NULL;
	}
	if (next) *next = 0;
	arroba = strchr (cmd, '/');
	if (arroba) {
	next_arroba:
		*arroba = 0;
		s = sdb_ns (s, cmd, eq?1:0);
		if (!s) {
			eprintf ("Cant find namespace %s\n", cmd);
			out = strbuf_free (out);
			goto fail;
		}
		cmd = arroba+1;
		arroba = strchr (cmd, '/');
		if (arroba)
			goto next_arroba;
	}
	if (*cmd=='?') {
		const char *val = sdb_const_get (s, cmd+1, 0);
		const char *type = sdb_type (val);
		out_concat (type);
	} else
	if (*cmd=='*') {
		if (!strcmp (cmd, "***")) {
			char root[1024]; // limit namespace length?
			SdbListIter *it;
			SdbNs *ns;
			ls_foreach (s->ns, it, ns) {
				int len = strlen (ns->name);
				if (len<sizeof (root)) {
					memcpy (root, ns->name, len+1);
					walk_namespace (out, root,
						sizeof (root)-len,
						root+len, ns, encode);
				} else eprintf ("TODO: Namespace too long\n");
			}
			goto fail;
		} else
		if (!strcmp (cmd, "**")) {
			SdbListIter *it;
			SdbNs *ns;
			ls_foreach (s->ns, it, ns) {
				out_concat (ns->name);
			}
			goto fail;
		} else
		if (!strcmp (cmd, "*")) {
			ForeachListUser user = { out, encode };
			sdb_foreach (s, foreach_list_cb, &user);
			goto fail;
		}
	}
	json = strchr (cmd, ':');
	if (*cmd == '[') {
		char *tp = strchr (cmd, ']');
		if (!tp) {
			eprintf ("Missing ']'.\n");
			goto fail;
		}
		*tp++ = 0;
		p = (const char *)tp;
	} else p = cmd;

	if (*cmd=='$') {
		char *nc = sdb_get (s, cmd+1, 0);
		if (nc) {
			free (oldcmd);
			oldcmd = newcmd;
			cmd = newcmd = nc;
		} else {
			cmd = newcmd = strdup ("");
		}
	}
	// cmd = val
	// cmd is key and val is value
	if (*cmd == '.') {
		if (s->options & SDB_OPTION_FS) {
			if (!sdb_query_file (s, cmd+1)) {
				eprintf ("sdb: cannot open '%s'\n", cmd+1);
				goto fail;
			}
		} else {
			eprintf ("sdb: filesystem access disabled in config\n");
		}
	} else
	if (*cmd == '~') {
		d = 1;
		sdb_unset_matching (s, cmd+1);
	} else
	if (*cmd == '+' || *cmd == '-') {
		d = 1;
		if (!buf)
			buf = strdup ("");
		*buf = 0;
		if (val) {
			if (sdb_isnum (val)) {
				int op = *cmd;
				if (*val=='-') {
					if (*cmd == '-') {
						op = '+';
					} else {
						op = '-';
					}
					d = sdb_atoi (val+1);
				} else d = sdb_atoi (val);
				if (op=='+')
					sdb_num_inc (s, cmd+1, d, 0);
				else sdb_num_dec (s, cmd+1, d, 0);
			} else {
				if (*cmd=='+') {
					sdb_concat (s, cmd+1, val, 0);
				} else {
					sdb_uncat (s, cmd+1, val, 0);
				}
			}
		} else {
			int base = sdb_num_base (sdb_const_get (s, cmd+1, 0));
			if (json) {
				base = 10; // NOTE: json is base10 only
				*json = 0;
				if (*cmd=='+') n = sdb_json_num_inc (s, cmd+1, json+1, d, 0);
				else n = sdb_json_num_dec (s, cmd+1, json+1, d, 0);
				*json = ':';
			} else {
				if (*cmd=='+') n = sdb_num_inc (s, cmd+1, d, 0);
				else n = sdb_num_dec (s, cmd+1, d, 0);
			}
			// keep base
			if (base==16) {
				w = snprintf (buf, len-1, "0x%"ULLFMT"x", n);
				if (w<0 || (size_t)w>len) {
					if (bufset && len<0xff) {
						free (buf);
						buf = malloc (0xff);
					}
					bufset = 1;
					snprintf (buf, 0xff, "0x%"ULLFMT"x", n);
				}
			} else {
				w = snprintf (buf, len-1, "%"ULLFMT"d", n);
				if (w<0 || (size_t)w>len) {
					if (bufset && len<0xff) {
						free (buf);
						buf = malloc (0xff);
					}
					bufset = 1;
					snprintf (buf, 0xff, "%"ULLFMT"d", n);
				}
			}
		}
		out_concat (buf);
	} else if (*cmd == '[') {
		// [?] - count elements of array
		if (cmd[1]=='?') {
			// if (!eq) ...
			alength = sdb_array_length (s, p);
			if (!buf) {
				buf = malloc (len+1);
				bufset = 1;
			}
			w = snprintf (buf, len, "%d", alength);
			if (w<0 || (size_t)w>len) {
				if (bufset)
					free (buf);
				buf = malloc (64);
				bufset = 1;
				snprintf (buf, 63, "%d", alength);
			}
			out_concat (buf);
		} else
		if (cmd[1]=='+'||cmd[1]=='-') {
			if (cmd[1] == cmd[2]) {
				// stack
#if 0
				[++]foo=33 # push
				[++]foo    # <invalid>
				[--]foo    # pop
				[--]foo=b  # <invalid>
#endif
				if (eq) {
					sdb_array_push (s, p, val, 0);
				} else {
					char *ret = sdb_array_pop (s, p, 0);
					out_concat (ret);
					free (ret);
				}
			} else
			// [+]foo        remove first element */
			// [+]foo=bar    ADD */
			// [-]foo        POP */
			// [-]foo=xx     REMOVE (=xx ignored) */
			if (!cmd[2] || cmd[2] ==']') {
				// insert
				if (eq) {
					if (cmd[1]=='+') {
						// [+]K=1
						sdb_array_add (s, p, val, 0);
					} else {
						// [-]K= = remove first element
						sdb_array_remove (s, p, val, 0);
					}
					//return NULL;
				} else {
					char *ret;
					if (cmd[1]=='+') {
						// [+]K = remove first element
						// XXX: this is a little strange syntax to remove an item
						ret = sdb_array_get (s, p, 0, 0);
						if (ret && *ret)
							out_concat (ret);
						// (+)foo :: remove first element
						sdb_array_delete (s, p, 0, 0);
					} else {
						// [-]K = remove last element
						ret = sdb_array_get (s, p, -1, 0);
						if (ret && *ret)
							out_concat (ret);
						// (-)foo :: remove last element
						sdb_array_delete (s, p, -1, 0);
					}
					free (ret);
				}
			} else {
				// get/set specific element in array
				i = atoi (cmd+1);
				if (eq) {
					/* [+3]foo=bla */
					if (i<0) {
						char *tmp = sdb_array_get (s, p, -i, NULL);
						if (tmp) {
							if (encode) {
								char *newtmp = (void*)sdb_decode (tmp, NULL);
								if (!newtmp)
									goto fail;
								free (tmp);
								tmp = newtmp;
							}
							ok = 0;
							out_concat (tmp);
							sdb_array_delete (s, p, -i, 0);
							free (tmp);
						} else goto fail;
					} else {
						if (encode)
							val = sdb_encode ((const ut8*)val, -1);
						ok = cmd[1]? ((cmd[1]=='+')?
							sdb_array_insert (s, p, i, val, 0):
							sdb_array_set (s, p, i, val, 0)
							): sdb_array_delete (s, p, i, 0);
						if (encode) {
							free ((void*)val);
							val = NULL;
						}
					}
					if (ok) *buf = 0;
					else buf = NULL;
				} else {
					if (i==0) {
						/* [-b]foo */
						if (cmd[1]=='-') {
							sdb_array_remove (s, p, cmd+2, 0);
						} else {
							eprintf ("TODO: [b]foo -> get index of b key inside foo array\n");
						//	sdb_array_dels (s, p, cmd+1, 0);
						}
					} else
					if (i<0) {
						/* [-3]foo */
						char *tmp = sdb_array_get (s, p, -i, NULL);
						if (tmp && *tmp) {
							out_concat (tmp);
							sdb_array_delete (s, p, -i, 0);
						}
						free (tmp);
					} else {
						/* [+3]foo */
						char *tmp = sdb_array_get (s, p, i, NULL);
						if (tmp && *tmp) {
							out_concat (tmp);
						}
						free (tmp);
					}
				}
			}
		} else {
			if (eq) {
				/* [3]foo=bla */
				char *sval = (char*)val;
				if (encode) {
					sval = sdb_encode ((const ut8*)val, -1);
				}
				if (cmd[1]) {
					int idx = atoi (cmd+1);
					ok = sdb_array_set (s, p, idx, sval, 0);
// TODO: handle when idx > sdb_alen
					if (encode)
						free (sval);
				} else {
					if (encode) ok = sdb_set_owned (s, p, sval, 0);
					else ok = sdb_set (s, p, sval, 0);
				}
				if (ok) *buf = 0;
			} else {
				/* [3]foo */
				const char *sval = sdb_const_get (s, p, 0);
				size_t wl;
				if (cmd[1]) {
					i = atoi (cmd+1);
					buf = sdb_array_get (s, p, i, NULL);
					bufset = 1;
					if (encode) {
						char *newbuf = (void*)sdb_decode (buf, NULL);
						if (newbuf) {
							free (buf);
							buf = newbuf;
						}
					}
					out_concat (buf);
				} else {
					if (!sval) goto fail;
					wl = strlen (sval);
					if (!buf || wl>len) {
						buf = malloc (wl+2);
						if (!buf) {
							free (out->buf);
							out->buf = NULL;
							goto fail;
						}
						bufset = 1;
					}
					for (i=0; sval[i]; i++) {
						if (sval[i+1])
						buf[i] = sval[i]==SDB_RS? '\n': sval[i];
						else buf[i] = sval[i];
					}
					buf[i] = 0;
					if (encode) {
						char *newbuf = (void*)sdb_decode (buf, NULL);
						if (newbuf) {
							free (buf);
							buf = newbuf;
						}
					}
					out_concat (buf);
				}
			}
		}
	} else {
		if (eq) {
			// 1 0 kvpath=value
			// 1 1 kvpath:jspath=value
			if (encode)
				val = sdb_encode ((const ut8*)val, -1);
			if (json>eq) json = NULL;
			if (json) {
				*json++ = 0;
				ok = sdb_json_set (s, cmd, json, val, 0);
			} else ok = sdb_set (s, cmd, val, 0);
			if (encode) {
				free ((void*)val);
				val = NULL;
			}
			if (ok && buf) *buf = 0;
		} else {
			// 0 1 kvpath:jspath
			// 0 0 kvpath
			if (json) {
				*json++ = 0;
				if (*json) {
					// TODO: not optimized to reuse 'buf'
					if ((tmp = sdb_json_get (s, cmd, json, 0))) {
						if (encode) {
							char *newtmp = (void*)sdb_decode (tmp, NULL);
							if (!newtmp)
								goto fail;
							free (tmp);
							tmp = newtmp;
						}
						out_concat (tmp);
						free (tmp);
					}
				} else {
					// kvpath:  -> show indented json
					char *o = sdb_json_indent (sdb_const_get (s, cmd, 0));
					out_concat (o);
					free (o);
				}
			} else {
				// sdbget
				if ((q = sdb_const_get (s, cmd, 0))) {
					if (encode)
						q = (void*)sdb_decode (q, NULL);
					out_concat (q);
					if (encode)
						free ((void*)q);
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
		encode = 0;
		goto repeat;
	}
	if (eq) *--eq = '=';
fail:
	if (bufset)
		free (buf);
	if (out) {
		res = out->buf;
		free (out);
	} else {
		res = NULL;
	}
	free (newcmd);
	free (oldcmd);
	return res;
}

SDB_API int sdb_query (Sdb *s, const char *cmd) {
	char buf[1024], *out;
	int must_save = ((*cmd=='~') || strchr (cmd, '='));
	out = sdb_querys (s, buf, sizeof (buf), cmd);
	if (out) {
		if (*out) puts (out);
		if (out != buf)
			free (out);
	}
	return must_save;
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
