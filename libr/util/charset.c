/* radare - LGPL - Copyright 2020-2022 - gogo, pancake */

#include <r_util.h>
#include <config.h>

#define USE_RUNES 0

#if HAVE_GPERF
extern SdbGperf gperf_ascii;
extern SdbGperf gperf_ebcdic37;
extern SdbGperf gperf_hiragana;
extern SdbGperf gperf_iso8859_1;
extern SdbGperf gperf_katakana;
extern SdbGperf gperf_pokered;

static const SdbGperf * const gperfs[] = {
	&gperf_ascii,
	&gperf_ebcdic37,
	&gperf_hiragana,
	&gperf_iso8859_1,
	&gperf_katakana,
	&gperf_pokered,
	NULL
};

R_API SdbGperf *r_charset_get_gperf(const char *k) {
	SdbGperf **gp = (SdbGperf**)gperfs;
	while (*gp) {
		SdbGperf *g = *gp;
		if (!strcmp (k, g->name)) {
			return *gp;
		}
		gp++;
	}
	return NULL;
}
#else
R_API SdbGperf *r_charset_get_gperf(const char *k) {
	return NULL;
}
#endif

R_API RList *r_charset_list(RCharset *ch) {
	RList *list = r_list_newf (free);
#if HAVE_GPERF
	SdbGperf **gp = (SdbGperf**)gperfs;
	while (*gp) {
		SdbGperf *g = *gp;
		r_list_append (list, strdup (g->name));
		gp++;
	}
#endif
	// iterate in disk
	const char *cs = R2_PREFIX R_SYS_DIR R2_SDB R_SYS_DIR "charsets" R_SYS_DIR;
	RList *files = r_sys_dir (cs);
	RListIter *iter;
	char *file;
	r_list_foreach (files, iter, file) {
		char *dot = strstr (file, ".sdb");
		if (dot) {
			*dot = 0;
			r_list_append (list, strdup (file));
		}
	}
	r_list_free (files);
	return list;
}

R_API RCharset *r_charset_new(void) {
	RCharset *ch = R_NEW0 (RCharset);
	if (ch) {
		ch->db = sdb_new0 ();
		ch->db_char_to_hex = sdb_new0 ();
	}
	return ch;
}

R_API void r_charset_free(RCharset *c) {
	if (c) {
		sdb_free (c->db);
		sdb_free (c->db_char_to_hex);
		free (c);
	}
}

R_API void r_charset_close(RCharset *c) {
	r_return_if_fail (c);
	c->loaded = false;
}

R_API bool r_charset_use(RCharset *c, const char *cf) {
	r_return_val_if_fail (c && cf, false);
	bool rc = false;
	SdbGperf *gp = r_charset_get_gperf (cf);
	if (gp) {
		sdb_free (c->db);
		c->db = sdb_new0 ();
		if (sdb_open_gperf (c->db, gp) != -1) {
			rc = r_charset_open (c, NULL);
			r_sys_setenv ("RABIN2_CHARSET", cf);
			rc = true;
		}
	} else {
		const char *cs = R2_PREFIX R_SYS_DIR R2_SDB R_SYS_DIR "charsets" R_SYS_DIR;
		char *syscs = r_str_newf ("%s%s.sdb", cs, cf);
		if (r_file_exists (syscs)) {
			rc = r_charset_open (c, syscs);
			r_sys_setenv ("RABIN2_CHARSET", cf);
		} else {
			if (r_file_exists (cf)) {
				rc = r_charset_open (c, cf);
				r_sys_setenv ("RABIN2_CHARSET", cf);
			}
		}
		free (syscs);
	}
	return rc;
}

R_API bool r_charset_open(RCharset *c, const char *cs) {
	r_return_val_if_fail (c, false);
	if (cs) {
		sdb_reset (c->db);
		sdb_open (c->db, cs);

		sdb_free (c->db_char_to_hex);
		c->db_char_to_hex = sdb_new0 ();
	}

	SdbListIter *iter;
	SdbKv *kv;
	SdbList *sdbls = sdb_foreach_list (c->db, true);

	c->loaded = false;
	ls_foreach (sdbls, iter, kv) {
		const char *new_key = kv->base.value;
		const char *new_value = kv->base.key;
		const size_t key_len = strlen (new_key);
		const size_t val_len = strlen (new_value);
		if (key_len > c->encode_maxkeylen) {
			c->encode_maxkeylen = key_len;
		}
		if (val_len > c->decode_maxkeylen) {
			c->decode_maxkeylen = val_len;
		}
		sdb_add (c->db_char_to_hex, new_key, new_value, 0);
		c->loaded = true;
	}
	ls_free (sdbls);

	return true;
}

// rune
R_API RCharsetRune *r_charset_rune_new(const ut8 *ch, const ut8 *hx) {
	r_return_val_if_fail (ch && hx, NULL);
	RCharsetRune* c = R_NEW0 (RCharsetRune);
	if (!c) {
		return NULL;
	}
	c->ch = (ut8 *) strdup ((char *) ch);
	c->hx = (ut8 *) strdup ((char *) hx);
	c->left = NULL;
	c->right = NULL;
	return c;
}

R_API void r_charset_rune_free(RCharsetRune *c) {
	if (c) {
		free (c->ch);
		free (c->hx);
		free (c);
	}
}

#if 0
R_API RCharsetRune *add_rune(RCharsetRune *r, const ut8 *ch, const ut8 *hx) {
	if (!r) {
		r = r_charset_rune_new (ch, hx);
	}
	int cmp = strcmp ((char *)hx, (char *)r->hx);
	if (cmp < 0) {
		r->left = add_rune (r->left, ch, hx);
	} else if (cmp > 0) {
		r->right = add_rune (r->right, ch, hx);
	} else {
		int cmp = strcmp ((char *)ch, (char *)r->ch);
		if (cmp > 0) {
			r->left = add_rune (r->left, ch, hx);
		} else if (cmp < 0) {
			r->right = add_rune (r->right, ch, hx);
		}
	}
	return r;
}

R_API RCharsetRune *search_from_hex(RCharsetRune *r, const ut8 *hx) {
	if (!r) {
		return NULL;
	}
	if (!strcmp ((char *)r->hx, (char *)hx)) {
		return r;
	}
	RCharsetRune *left = search_from_hex (r->left, hx);
	return left? left: search_from_hex (r->right, hx);
}
#endif

R_API size_t r_charset_encode_str(RCharset *rc, ut8 *out, size_t out_len, const ut8 *in, size_t in_len) {
	if (!rc->loaded) {
		return in_len;
	}
	char k[32];
	char *o = (char*)out;
	size_t i, oi;
	char *o_end = o + out_len;
	bool fine = false;
	for (i = oi = 0; i < in_len && o < o_end; i++) {
		ut8 ch_in = in[i];
		snprintf (k, sizeof (k), "0x%02x", ch_in);
		const char *v = sdb_const_get (rc->db, k, 0);
		const char *ret = r_str_get_fail (v, "?");
		char *res = strdup (ret);
		if (res) {
			size_t reslen = strlen (res);
			if (reslen >= o_end - o) {
				break;
			}
			fine = true;
			r_str_unescape (res);
		//	memcpy (o, res, out_len - i);
			r_str_ncpy (o, res, out_len - oi);
			free (res);
		}
		size_t di = strlen (o);
		oi += di;
		o += di;
	}
	if (!fine) {
		return 0;
	}
	return o - (char*)out;
}

// assumes out is as big as in_len
R_API size_t r_charset_decode_str(RCharset *rc, ut8 *out, size_t out_len, const ut8 *in, size_t in_len) {
	if (!rc->loaded) {
		return in_len;
	}
	char *o = (char*)out;

	size_t maxkeylen = rc->encode_maxkeylen;
	size_t cur, j;
	for (cur = 0; cur < in_len; cur++) {
		size_t left = in_len - cur;
		size_t toread = R_MIN (left + 1, maxkeylen);
		char *str = calloc (toread + 128, 1);
		if (!str) {
			break;
		}
		memcpy (str, in + cur, toread);
		bool found = false;
		for (j = toread; cur < in_len && j > 0; j--) {
			left = in_len - cur + 1;
			toread = R_MIN (left, maxkeylen);
			str[j] = 0;
			const char *v = sdb_const_get (rc->db_char_to_hex, (char *) str, 0);
			if (v) {
				int repeat = !strncmp (v, "0x", 2)? strlen (v + 2) / 2: 1;
				ut64 nv = r_num_get (NULL, v);
				if (!nv) {
					int i;
					// write 0x00 N times (
					for (i = 0; i < repeat; i++) {
						// write null byte
						memcpy (o, "\x00", 2);
						o++;
					}
					o--;
					found = true;
					break;
				}
				//convert to ascii
				char *str_hx = malloc (1 + maxkeylen);
				if (!str_hx) {
					break;
				}
				if (nv > 0xff) {
					ut64 d  = 0;
					r_mem_swapendian ((ut8*)&d, (const ut8*)&nv, 8);
					nv = d;
				}
				int i;
				bool skip = true;
				int chcount = 0;
				for (i = 0; i < 8; i++) {
					ut8 bv = nv & 0xff;
					// skip until we found one byet
					if (bv & 0xff) {
						skip = false;
					}
					if (skip) {
						nv >>= 8;
						continue;
					} else if (!bv) {
						break;
					}
					// eprintf ("-> 0x%02x\n", nv & 0xff);
					//in the future handle multiple chars output
					str_hx[0] = bv;
					str_hx[1] = 0;
					const char *ret = r_str_get_fail (str_hx, "?");

					// concatenate
					const size_t ll = R_MIN (left, strlen (ret) + 1);
					if (ll > 0) {
						memcpy (o, ret, ll);
						o[ll] = 0;
						o += ll - 1;
						chcount++;
					}
					found = true;
					nv >>= 8;
				}
				cur += (chcount>1)?chcount - 2:j-1;
				free (str_hx);
				break;
			}
		}
		if (!found) {
			o[0] = '?';
			o[1] = 0;
			o++;
		}
		free (str);
	}
	return o - (char*)out;
}
