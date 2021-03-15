/* sdb - MIT - Copyright 2011-2020 - pancake */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <ctype.h>
#include "sdb.h"

typedef struct {
	char *buf;
	int len;
	int size;
} StrBuf;

static StrBuf* strbuf_new(void) {
	return calloc (sizeof (StrBuf), 1);
}

#define NEWLINE_AFTER_QUERY 1

static StrBuf* strbuf_append(StrBuf *sb, const char *str, const int nl) {
	if (!sb || !str || nl < 0) {
		return sb;
	}
	int len = strlen (str);
	if ((sb->len + len + 2) >= sb->size) {
		int newsize = sb->size + len + 256;
		char *b = realloc (sb->buf, newsize);
		/// TODO perform free and force all callers to update the ref?
		if (!b) {
			return NULL;
		}
		sb->buf = b;
		sb->size = newsize;
	}
	if (sb->buf && str) {
		memcpy (sb->buf + sb->len, str, len);
		sb->len += len;
	}
#if NEWLINE_AFTER_QUERY
	if (sb->buf && nl) {
		sb->buf[sb->len++] = '\n';
		len++;
	}
#endif
	if (sb->buf) {
		sb->buf[sb->len] = 0;
	}
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

SDB_API char *sdb_querysf(Sdb *s, char *buf, size_t buflen, const char *fmt, ...) {
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

static bool foreach_list_cb(void *user, const char *k, const char *v) {
	ForeachListUser *rlu = user;
	char *line, *root;
	int rlen, klen, vlen;
	ut8 *v2 = NULL;
	if (!rlu) {
		return false;
	}
	root = rlu->root;
	klen = strlen (k);
	if (rlu->encode) {
		v2 = sdb_decode (v, NULL);
		if (v2) {
			v = (const char *)v2;
		}
	}
	vlen = strlen (v);
	if (root) {
		rlen = strlen (root);
		line = malloc (klen + vlen + rlen + 3);
		if (!line) {
			free (v2);
			return false;
		}
		memcpy (line, root, rlen);
		line[rlen]='/'; /*append the '/' at the end of the namespace */
		memcpy (line + rlen + 1, k, klen);
		line[rlen + klen + 1] = '=';
		memcpy (line + rlen + klen + 2, v, vlen + 1);
	} else {
		line = malloc (klen + vlen + 2);
		if (!line) {
			free (v2);
			return false;
		}
		memcpy (line, k, klen);
		line[klen] = '=';
		memcpy (line + klen + 1, v, vlen + 1);
	}
	strbuf_append (rlu->out, line, 1);
	free (v2);
	free (line);
	return true;
}

static void walk_namespace (StrBuf *sb, char *root, int left, char *p, SdbNs *ns, int encode) {
	int len;
	SdbListIter *it;
	char *_out, *out = sb->buf;
	SdbNs *n;
	ForeachListUser user = { sb, encode, root };
	char *roote = root + strlen (root);
	if (!ns->sdb) {
		return;
	}
	/*Pick all key=value in the local ns*/
	sdb_foreach (ns->sdb, foreach_list_cb, &user);

	/*Pick "sub"-ns*/
	ls_foreach (ns->sdb->ns, it, n) {
		len = strlen (n->name);
		p[0] = '/';
		if (len + 2 < left) {
			memcpy (p + 1, n->name, len + 1);
			left -= len + 2;
		}
		_out = out;
		walk_namespace (sb, root, left,
			roote + len + 1, n, encode);
		out = _out;
	}
}

SDB_API char *sdb_querys (Sdb *r, char *buf, size_t len, const char *_cmd) {
	int i, d, ok, w, alength, bufset = 0, is_ref = 0, encode = 0;
	const char *p, *q, *val = NULL;
	char *eq, *tmp, *json, *next, *quot, *slash, *res,
		*cmd, *newcmd = NULL, *original_cmd = NULL;
	StrBuf *out;
	Sdb *s = r;
	ut64 n;
	if (!s || (!_cmd && !buf)) {
		return NULL;
	}
	out = strbuf_new ();
	if ((int)len < 1 || !buf) {
		bufset = 1;
		buf = malloc ((len = 64));
		if (!buf) {
			strbuf_free (out);
			return NULL;
		}
	}
	if (_cmd) {
		cmd = original_cmd = strdup (_cmd);
		if (!cmd) {
			free (out);
			if (bufset) {
				free (buf);
			}
			return NULL;
		}
	} else {
		cmd = buf;
	}
	// if cmd is null, we take buf as cmd
	next = NULL;
repeat:
	/* skip spaces */
	while (*cmd && (*cmd == ' ' || *cmd == '\t')) {
		cmd++;
	}
	s = r;
	p = cmd;
	eq = NULL;
	encode = 0;
	is_ref = 0;
	quot = NULL;
	json = NULL;
	if (*p == '#') {
		p++;
		next = strchr (p, ';');
		if (next) {
			*next = 0;
		}
		out_concat (sdb_fmt ("0x%08x\n", sdb_hash (p)));
		if (next) {
			*next = ';';
		}
		goto runNext;
	} else
	if (*p == '%') {
		encode = 1;
		cmd++;
		p++;
	}
	if (next) *next = ';';
	eq = strchr (p, '=');
	if (eq) {
		d = 1;
		*eq++ = 0;
		if (*eq == '$') {
			next = strchr (eq + 1, ';');
			if (next) *next = 0;
			val = sdb_const_get (s, eq + 1, 0);
			if (!val) {
				eprintf ("No value for '%s'\n", eq + 1);
				goto fail;
			}
			if (next) *next = ';';
			is_ref = 1; // protect readonly buffer from being processed
		} else {
			val = eq;
		}
	} else {
		val = NULL;
		d = 0;
	}
	if (!is_ref) {
		next = strchr (val? val: cmd, ';');
	}
	//if (!val) val = eq;
	if (!is_ref && val && *val == '"') {
		val++;
		// TODO: escape \" too
		quot = (char*)val;
next_quote:
		quot = strchr (quot, '"');
		if (quot) {
			if (*(quot - 1) == '\\') {
				memmove (quot - 1, quot, strlen (quot) + 1);
				goto next_quote;
			}
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
	if (next) {
		*next = 0;
	}
	slash = strchr (cmd, '/');
	while (slash) {
		*slash = 0;
		s = sdb_ns (s, cmd, eq? 1: 0);
		if (!s) {
			eprintf ("Cant find namespace %s\n", cmd);
			out = strbuf_free (out);
			goto fail;
		}
		cmd = slash + 1;
		slash = strchr (cmd, '/');
	}
	if (*cmd=='?') {
		const char *val = sdb_const_get (s, cmd+1, 0);
		const char *type = sdb_type (val);
		out_concat (type);
	} else
	if (*cmd == '*') {
		if (!strcmp (cmd, "***")) {
			char root[1024]; // limit namespace length?
			SdbListIter *it;
			SdbNs *ns;
			ls_foreach (s->ns, it, ns) {
				int name_len = strlen (ns->name);
				if (name_len < (long)sizeof (root)) {
					memcpy (root, ns->name, name_len + 1);
					walk_namespace (out, root,
						sizeof (root) - name_len,
						root + name_len, ns, encode);
				} else {
					eprintf ("TODO: Namespace too long\n");
				}
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
			ForeachListUser user = { out, encode, NULL };
			SdbList *list = sdb_foreach_list (s, true);
			SdbListIter *iter;
			SdbKv *kv;
			ls_foreach (list, iter, kv) {
				foreach_list_cb (&user, sdbkv_key (kv), sdbkv_value (kv));
			}
			ls_free (list);
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
	} else {
		p = cmd;
	}
	if (*cmd == '$') {
		free (newcmd);
		char *nc = sdb_get (s, cmd + 1, 0);
		cmd = newcmd = (nc) ? nc : strdup ("");
	}
	// cmd = val
	// cmd is key and val is value
	if (*cmd == '.') {
		if (s->options & SDB_OPTION_FS) {
			if (!sdb_query_file (s, cmd + 1)) {
				eprintf ("sdb: cannot open '%s'\n", cmd+1);
				goto fail;
			}
		} else {
			eprintf ("sdb: filesystem access disabled in config\n");
		}
	} else if (*cmd == '~') { // delete
		if (cmd[1] == '~') { // grep
			SdbKv *kv;
			SdbListIter *li;
			SdbList *l = sdb_foreach_match (s, cmd + 2, false);
			ls_foreach (l, li, kv) {
				strbuf_append (out, sdbkv_key (kv), 0);
				strbuf_append (out, "=", 0);
				strbuf_append (out, sdbkv_value (kv), 1);
			}
			fflush (stdout);
			ls_free (l);
		} else {
			d = 1;
			sdb_unset_like (s, cmd + 1);
		}
	} else if (*cmd == '+' || *cmd == '-') {
		d = 1;
		if (!buf) {
			buf = calloc (1, len);
			if (!buf) {
				goto fail;
			}
			bufset = 1;
		}
		*buf = 0;
		if (cmd[1]=='[') {
			const char *eb = strchr (cmd, ']');
			if (!eb) {
				eprintf ("Missing ']'.\n");
				goto fail;
			}
			int idx = sdb_atoi (cmd + 2);
			/* +[idx]key=n */
			/* -[idx]key=n */
			ut64 curnum = sdb_array_get_num (s,
				eb + 1, idx, 0);
			if (eq) {
				/* +[idx]key=n  -->  key[idx] += n */
				/* -[idx]key=n  -->  key[idx] -= n */
				st64 n = sdb_atoi (eq);
				if (*cmd=='+') {
					curnum += n;
				} else if (*cmd=='-') {
					curnum -= n;
				} else {
					// never happens
				}
				sdb_array_set_num (s, eb+1, idx, curnum, 0);
			} else {
				/* +[idx]key    -->  key[idx] + 1 */
				/* -[idx]key    -->  key[idx] - 1 */
				char *nstr, numstr[128];
				if (*cmd=='+') {
					curnum ++;
				} else if (*cmd=='-') {
					curnum --;
				} else {
					// never happens
				}
				nstr = sdb_itoa (curnum, numstr, 10);
				strbuf_append (out, nstr, 1);
			}
		} else if (val) {
			if (sdb_isnum (val)) {
				int op = *cmd;
				if (*val == '-') {
					if (*cmd == '-') {
						op = '+';
					} else {
						op = '-';
					}
					d = sdb_atoi (val + 1);
				} else {
					d = sdb_atoi (val);
				}
				if (op=='+') {
					sdb_num_inc (s, cmd+1, d, 0);
				} else {
					sdb_num_dec (s, cmd+1, d, 0);
				}
			} else {
				if (*cmd == '+') {
					sdb_concat (s, cmd + 1, val, 0);
				} else {
					sdb_uncat (s, cmd + 1, val, 0);
				}
			}
		} else {
			int base = sdb_num_base (sdb_const_get (s, cmd+1, 0));
			if (json) {
				base = 10; // NOTE: json is base10 only
				*json = 0;
				if (*cmd=='+') {
					n = sdb_json_num_inc (s, cmd + 1, json + 1, d, 0);
				} else {
					n = sdb_json_num_dec (s, cmd + 1, json + 1, d, 0);
				}
				*json = ':';
			} else {
				if (*cmd=='+') {
					n = sdb_num_inc (s, cmd + 1, d, 0);
				} else {
					n = sdb_num_dec (s, cmd + 1, d, 0);
				}
			}
			// keep base
			if (base == 16) {
				w = snprintf (buf, len - 1, "0x%"ULLFMT"x", n);
				if (w < 0 || (size_t)w > len) {
					if (bufset && len < 0xff) {
						free (buf);
						buf = malloc (len = 0xff);
						if (!buf) {
							goto fail;
						}
					}
					bufset = 1;
					snprintf (buf, 0xff, "0x%"ULLFMT"x", n);
				}
			} else {
				w = snprintf (buf, len-1, "%"ULLFMT"d", n);
				if (w < 0 || (size_t)w > len) {
					if (bufset && len < 0xff) {
						free (buf);
						buf = malloc (len = 0xff);
						if (!buf) {
							goto fail;
						}
					}
					bufset = 1;
					snprintf (buf, 0xff, "%"ULLFMT"d", n);
				}
			}
		}
		out_concat (buf);
	} else if (*cmd == '[') {
		// [?] - count elements of array
		if (cmd[1] == '?') {
			// if (!eq) ...
			alength = sdb_array_length (s, p);
			if (!buf) {
				buf = malloc (++len);
				if (!buf) {
					goto fail;
				}
				bufset = 1;
			}
			w = snprintf (buf, len, "%d", alength);
			if (w < 0 || (size_t)w > len) {
				if (bufset) {
					free (buf);
				}
				buf = malloc (len = 32);
				bufset = 1;
				snprintf (buf, 31, "%d", alength);
			}
			out_concat (buf);
		} else if (cmd[1]=='!') {
			if (cmd[2]=='+') {
				// [!+]key=aa	# add_sorted
				sdb_array_add_sorted (s, p, val, 0);
			} else {
				// [!]key		# sort
				sdb_array_sort (s, p, 0);
			}
		} else if (cmd[1]=='#') {
				// [#+]key=num	# add_sorted_num
			if (cmd[2]=='+') {
				// [#]key		# sort_num
				sdb_array_add_sorted_num (s, p, sdb_atoi (val), 0);
			} else {
				sdb_array_sort_num (s, p, 0);
			}
		} else if (cmd[1] == '+' || cmd[1] == '-') {
			if (cmd[1] == cmd[2]) {
				// stack
#if 0
				[++]foo=33 # push
				[++]foo    # <invalid>
				[--]foo    # pop
				[--]foo=b  # <invalid>
#endif
				if (cmd[1] == '-' && eq) {
					/* invalid syntax */
				} else if (cmd[1] == '+' && !eq) {
					/* invalid syntax */
				} else {
					if (eq) {
						sdb_array_push (s, p, val, 0);
					} else {
						char *ret = sdb_array_pop (s, p, 0);
						out_concat (ret);
						free (ret);
					}
				}
			} else
			// [+]foo        remove first element */
			// [+]foo=bar    ADD */
			// [-]foo        POP */
			// [-]foo=xx     REMOVE (=xx ignored) */
			if (!cmd[2] || cmd[2] == ']') {
				// insert
				if (eq) {
					if (cmd[1] == '+') {
						// [+]K=1
						sdb_array_add (s, p, val, 0);
					} else {
						// [-]K= = remove first element
						sdb_array_remove (s, p, val, 0);
					}
					//return NULL;
				} else {
					char *ret;
					if (cmd[1] == '+') {
						// [+]K = remove first element
						// XXX: this is a little strange syntax to remove an item
						ret = sdb_array_get (s, p, 0, 0);
						if (ret && *ret) {
							out_concat (ret);
						}
						// (+)foo :: remove first element
						sdb_array_delete (s, p, 0, 0);
					} else {
						// [-]K = remove last element
						ret = sdb_array_get (s, p, -1, 0);
						if (ret && *ret) {
							out_concat (ret);
						}
						// (-)foo :: remove last element
						sdb_array_delete (s, p, -1, 0);
					}
					free (ret);
				}
			} else {
				// get/set specific element in array
				i = atoi (cmd + 1);
				if (eq) {
					/* [+3]foo=bla */
					if (i < 0) {
						char *tmp = sdb_array_get (s, p, -i, NULL);
						if (tmp) {
							if (encode) {
								char *newtmp = (void*)sdb_decode (tmp, NULL);
								if (!newtmp) {
									goto fail;
								}
								free (tmp);
								tmp = newtmp;
							}
							ok = 0;
							out_concat (tmp);
							sdb_array_delete (s, p, -i, 0);
							free (tmp);
						} else goto fail;
					} else {
						if (encode) {
							val = sdb_encode ((const ut8*)val, -1);
						}
						ok = cmd[1]? ((cmd[1]=='+')?
							sdb_array_insert (s, p, i, val, 0):
							sdb_array_set (s, p, i, val, 0)
							): sdb_array_delete (s, p, i, 0);
						if (encode) {
							free ((void*)val);
							val = NULL;
						}
					}
					if (ok && buf) *buf = 0;
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
					} else if (i<0) {
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
					if (encode) {
						ok = sdb_set_owned (s, p, sval, 0);
					} else {
						ok = sdb_set (s, p, sval, 0);
					}
				}
				if (ok && buf) {
					*buf = 0;
				}
			} else {
				/* [3]foo */
				const char *sval = sdb_const_get (s, p, 0);
				size_t wl;
				if (cmd[1]) {
					i = atoi (cmd + 1);
					buf = sdb_array_get (s, p, i, NULL);
					if (buf) {
						bufset = 1;
						len = strlen(buf) + 1;
					}
					if (encode) {
						char *newbuf = (void*)sdb_decode (buf, NULL);
						if (newbuf) {
							free (buf);
							buf = newbuf;
							len = strlen(buf) + 1;
						}
					}
					out_concat (buf);
				} else {
					if (!sval) {
						goto fail;
					}
					wl = strlen (sval);
					if (!buf || wl >= len) {
						buf = malloc (wl + 2);
						if (!buf) {
							free (out->buf);
							out->buf = NULL;
							goto fail;
						}
						bufset = 1;
						len = wl + 2;
					}
					for (i = 0; sval[i]; i++) {
						if (sval[i + 1]) {
							buf[i] = (sval[i] == SDB_RS)
								? '\n': sval[i];
						} else {
							buf[i] = sval[i];
						}
					}
					buf[i] = 0;
					if (encode) {
						char *newbuf = (void*)sdb_decode (buf, NULL);
						if (newbuf) {
							if (bufset) {
								free (buf);
							}
							buf = newbuf;
							len = strlen (buf) + 1;
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
			if (encode) {
				val = sdb_encode ((const ut8*)val, -1);
			}
			if (json > eq) {
				json = NULL;
			}

			if (json) {
				*json++ = 0;
				ok = sdb_json_set (s, cmd, json, val, 0);
			} else {
				while (*val && isspace (*val)) {
					val++;
				}
				int i = strlen (cmd) - 1;
				while (i >= 0 && isspace (cmd[i])) {
					cmd[i] = '\0';
					i--;
				}
				ok = sdb_set (s, cmd, val, 0);
			}
			if (encode) {
				free ((void*)val);
				val = NULL;
			}
			if (ok && buf) {
				*buf = 0;
			}
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
					char *o = sdb_json_indent (sdb_const_get (s, cmd, 0), "  ");
					out_concat (o);
					free (o);
				}
			} else {
				// sdbget
				if ((q = sdb_const_get (s, cmd, 0))) {
					if (encode) {
						q = (void*)sdb_decode (q, NULL);
					}
					out_concat (q);
					if (encode) {
						free ((void*)q);
					}
				}
			}
		}
	}
runNext:
	if (next) {
		if (bufset) {
			free (buf);
			buf = NULL;
			bufset = 0;
		}
		cmd = next + 1;
		encode = 0;
		goto repeat;
	}
	if (eq) {
		*--eq = '=';
	}
fail:
	if (bufset) {
		free (buf);
	}
	if (out) {
		res = out->buf;
		free (out);
	} else {
		res = NULL;
	}
	free (original_cmd);
	free (newcmd);
	return res;
}

SDB_API int sdb_query (Sdb *s, const char *cmd) {
	char buf[1024], *out;
	int must_save = ((*cmd=='~') || strchr (cmd, '='));
	out = sdb_querys (s, buf, sizeof (buf) - 1, cmd);
	if (out) {
		if (*out) {
			puts (out);
		}
		if (out != buf) {
			free (out);
		}
	}
	return must_save;
}

SDB_API int sdb_query_lines (Sdb *s, const char *cmd) {
	char *o, *p, *op;
	if (!s || !cmd) {
		return 0;
	}
	op = strdup (cmd);
	if (!op) {
		return 0;
	}
	p = op;
	do {
		o = strchr (p, '\n');
		if (o) {
			*o = 0;
		}
		(void)sdb_query (s, p);
		if (o) {
			p = o + 1;
		}
	} while (o);
	free (op);
	return 1;
}

static char *slurp(const char *file) {
	int ret, fd;
	char *text;
	long sz;
	if (!file || !*file)
		return NULL;
	fd = open (file, O_RDONLY);
	if (fd == -1) {
		return NULL;
	}
	sz = lseek (fd, 0, SEEK_END);
	if (sz < 0){
		close (fd);
		return NULL;
	}
	lseek (fd, 0, SEEK_SET);
	text = malloc (sz + 1);
	if (!text) {
		close (fd);
		return NULL;
	}
	ret = read (fd, text, sz);
	if (ret != sz) {
		free (text);
		text = NULL;
	} else {
		text[sz] = 0;
	}
	close (fd);
	return text;
}

SDB_API int sdb_query_file(Sdb *s, const char* file) {
	int ret = 0;
	char *txt = slurp (file);
	if (txt) {
		ret = sdb_query_lines (s, txt);
		free (txt);
	}
	return ret;
}
