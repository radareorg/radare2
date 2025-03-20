/* radare - LGPL - Copyright 2010-2022 - pancake */

#include <r_search.h>

static int ignoreMask(const ut8 *bm, int len) {
	int i;
	for (i = 0; i < len; i++) {
		if (bm[i] != 0xff) {
			return 0;
		}
	}
	return 1;
}

R_API RSearchKeyword* r_search_keyword_new_hexstr(const char *xs, const char *data) {
	char *s = strdup (xs);
	char *m = strchr (s, ' ');
	int mlen = 0;
	if (m) {
		*m++ = 0;
		mlen = r_hex_str2bin (m, (ut8*)m);
	}
	int slen = r_hex_str2bin (s, (ut8*)s);
	RSearchKeyword *k = r_search_keyword_new ((const ut8*)s, slen, (const ut8*)m, mlen, data);
	free (s);
	return k;
}

R_API RSearchKeyword* r_search_keyword_new(const ut8 *kwbuf, int kwlen, const ut8 *bmbuf, int bmlen, const char *data) {
	RSearchKeyword *kw;
	if (kwlen < 1 || bmlen < 0) {
		return NULL;
	}
	kw = R_NEW0 (RSearchKeyword);
	kw->type = R_SEARCH_KEYWORD_TYPE_BINARY;
	kw->data = (void *) data;
	kw->keyword_length = kwlen;
	kw->bin_keyword = malloc (kwlen);
	if (!kw->bin_keyword) {
		r_search_keyword_free (kw);
		return NULL;
	}
	memcpy (kw->bin_keyword, kwbuf, kwlen);
	if (bmbuf && bmlen > 0 && !ignoreMask (bmbuf, bmlen)) {
		kw->bin_binmask = malloc (bmlen);
		if (!kw->bin_binmask) {
			r_search_keyword_free (kw);
			return NULL;
		}
		memcpy (kw->bin_binmask, bmbuf, bmlen);
		kw->binmask_length = bmlen;
	} else {
		kw->bin_binmask = NULL;
		kw->binmask_length = 0;
	}
	return kw;
}

R_API void r_search_keyword_free(RSearchKeyword *kw) {
	if (R_LIKELY (kw)) {
		free (kw->bin_binmask);
		free (kw->bin_keyword);
		free (kw);
	}
}

R_API RSearchKeyword* r_search_keyword_new_str(const char *kwbuf, const char *bmstr, const char *data, bool ignore_case) {
	R_RETURN_VAL_IF_FAIL (kwbuf, NULL);
	ut8 *bmbuf = NULL;
	int bmlen = 0;

	if (bmstr) {
		bmbuf = malloc (strlen (bmstr) + 1);
		if (!bmbuf) {
			return NULL;
		}
		int bmlen = r_hex_str2bin (bmstr, bmbuf);
		if (bmlen < 1) {
			R_FREE (bmbuf);
		}
	}
	RSearchKeyword *kw = r_search_keyword_new ((ut8 *)kwbuf, strlen (kwbuf), bmbuf, bmlen, data);
	if (kw) {
		kw->icase = ignore_case;
		kw->type = R_SEARCH_KEYWORD_TYPE_STRING;
	}
	free (bmbuf);
	return kw;
}

R_API RSearchKeyword* r_search_keyword_new_wide(const char *kwbuf, const char *bmstr, const char *data, bool ignore_case, bool be) {
	RSearchKeyword *kw;
	int len;
	const char *p2;
	char *p, *str;
	ut8 *bmbuf = NULL;
	int bmlen = 0;

	if (bmstr) {
		bmbuf = malloc (strlen (bmstr) + 1);
		if (!bmbuf) {
			return NULL;
		}
		bmlen = r_hex_str2bin (bmstr, bmbuf);
		if (bmlen < 1) {
			R_FREE (bmbuf);
		}
	}

	len = strlen (kwbuf);
	str = malloc ((len + 1) * 2);
	for (p2 = kwbuf, p = str; *p2; ) {
		RRune ch;
		const int num_utf8_bytes = r_utf8_decode ((const ut8 *)p2, kwbuf + len - p2, &ch);
		if (num_utf8_bytes < 1) {
			R_LOG_WARN ("Malformed UTF8 at pos %d", (int)(p2 - kwbuf));
			p[0] = *p2;
			p[1] = 0;
			p2++;
			p += 2;
			continue;
		}
		if (ignore_case && ch <= 0xff) {
			ch = tolower (ch);
		}
		const int num_wide_bytes = be
			? r_utf16be_encode ((ut8 *)p, ch)
			: r_utf16le_encode ((ut8 *)p, ch);
		R_WARN_IF_FAIL (num_wide_bytes != 0);
		p2 += num_utf8_bytes;
		p += num_wide_bytes;
	}

	kw = r_search_keyword_new ((ut8 *)str, p - str, bmbuf, bmlen, data);
	free (str);
	if (kw) {
		kw->icase = ignore_case;
	}
	free (bmbuf);
	return kw;
}

R_API RSearchKeyword* r_search_keyword_new_hex(const char *kwstr, const char *bmstr, const char *data) {
	RSearchKeyword *kw;
	ut8 *kwbuf, *bmbuf;
	int kwlen, bmlen = 0;

	if (!kwstr) {
		return NULL;
	}

	kwbuf = malloc (strlen (kwstr) + 1);
	if (!kwbuf) {
		return NULL;
	}

	kwlen = r_hex_str2bin (kwstr, kwbuf);
	if (kwlen < 1) {
		free (kwbuf);
		return NULL;
	}

	bmbuf = NULL;
	if (bmstr && *bmstr) {
		bmbuf = malloc (strlen (bmstr)+1);
		if (!bmbuf) {
			free (kwbuf);
			return NULL;
		}
		bmlen = r_hex_str2bin (bmstr, bmbuf);
		if (bmlen < 1) {
			free (bmbuf);
			free (kwbuf);
			return NULL;
		}
	}

	kw = r_search_keyword_new (kwbuf, kwlen, bmbuf, bmlen, data);
	free (kwbuf);
	free (bmbuf);
	return kw;
}

R_API RSearchKeyword* r_search_keyword_new_hexmask(const char *kwstr, const char *data) {
	RSearchKeyword *ks = NULL;
	ut8 *kw, *bm;
	if (kwstr) {
		int len = strlen (kwstr);
		kw = malloc (len + 4);
		bm = malloc (len + 4);
		if (kw && bm) {
			len = r_hex_str2binmask (kwstr, (ut8*)kw, (ut8*)bm);
			if (len < 0) {
				len = -len - 1;
			}
			if (len > 0) {
				ks = r_search_keyword_new (kw, len, bm, len, data);
			}
		}
		free (kw);
		free (bm);
	}
	return ks;
}

/* Validate a regexp in the canonical format /<regexp>/<options> */
R_API RSearchKeyword *r_search_keyword_new_regexp(const char *str, const char *data) {
	int i = 0, start, length;

	// TODO: use r_str_trim_head_ro (str);
	while (isspace ((const unsigned char)str[i])) {
		i++;
	}

	if (str[i++] != '/') {
		return NULL;
	}

	/* Find the fist non backslash-escaped slash */
	int specials = 0;
	for (start = i; str[i]; i++) {
		if (str[i] == '/' && str[i - 1] != '\\') {
			break;
		} else if (str[i - 1] == '\\' && isalpha (str[i] & 0xff)) {
			specials++;
		}
	}

	if (str[i++] != '/') {
		return NULL;
	}

	length = i - start - 1;
	if ((length > 128) || (length < 1)) {
		return NULL;
	}

	RSearchKeyword *kw = R_NEW0 (RSearchKeyword);
	if (!kw) {
		return NULL;
	}
	kw->bin_keyword = malloc (length+1);
	if (!kw->bin_keyword) {
		r_search_keyword_free (kw);
		return NULL;
	}
	kw->bin_keyword[length] = 0;
	memcpy (kw->bin_keyword, str + start, length);
	kw->keyword_length = length - specials;
	kw->type = R_SEARCH_KEYWORD_TYPE_STRING;
	kw->data = (void *) data;

	/* Parse the options */
	for (; str[i]; i++) {
		switch (str[i]) {
			case 'i':
				kw->icase = true;
				break;
			default:
				r_search_keyword_free (kw);
				return NULL;
		}
	}

	return kw;
}
