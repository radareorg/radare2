/* radare - LGPL - Copyright 2010-2014 - pancake */

#include <r_search.h>

R_API RSearchKeyword* r_search_keyword_new(const ut8 *kwbuf, int kwlen, const ut8 *bmbuf, int bmlen, const char *data) {
	RSearchKeyword *kw;
	if (kwlen < 1 || bmlen < 0)
		return NULL;
	kw = R_NEW0 (RSearchKeyword);
	if (!kw) return NULL;
	kw->type = R_SEARCH_KEYWORD_TYPE_BINARY;
	kw->keyword_length = kwlen;
	kw->bin_keyword = malloc (kwlen);
	memcpy (kw->bin_keyword, kwbuf, kwlen);
	if (bmbuf && bmlen > 0) {
		kw->bin_binmask = malloc (bmlen);
		memcpy (kw->bin_binmask, bmbuf, bmlen);
		kw->binmask_length = bmlen;
	} else {
		kw->bin_binmask = NULL;
		kw->binmask_length = 0;
	}
	return kw;
}

R_API void r_search_keyword_free (RSearchKeyword *kw) {
	free (kw->bin_binmask);
	free (kw->bin_keyword);
	free (kw);
}

R_API RSearchKeyword* r_search_keyword_new_str(const char *kwbuf, const char *bmstr, const char *data, int ignore_case) {
	RSearchKeyword *kw;
	ut8 *bmbuf = NULL;
	int bmlen = 0;

	if (bmstr) {
		bmbuf = malloc (strlen (bmstr)+1);
		if (!bmbuf) return NULL;
		bmlen = r_hex_str2bin (bmstr, bmbuf);
		if (bmlen < 1) {
			free (bmbuf);
			bmbuf = NULL;
		}
	}
	kw = r_search_keyword_new ((ut8 *)kwbuf, strlen (kwbuf),
		bmbuf, bmlen, data);
	if (kw) {
		kw->icase = ignore_case;
		kw->type = R_SEARCH_KEYWORD_TYPE_STRING;
	}
	free (bmbuf);
	return kw;
}

R_API RSearchKeyword* r_search_keyword_new_hex(const char *kwstr, const char *bmstr, const char *data) {
	RSearchKeyword *kw;
	ut8 *kwbuf, *bmbuf;
	int kwlen, bmlen = 0;

	if (!kwstr)
		return NULL;

	kwbuf = malloc (strlen (kwstr)+1);
	if (!kwbuf)
		return NULL;

	kwlen = r_hex_str2bin (kwstr, kwbuf);
	if (kwlen < 1) {
		free (kwbuf);
		return NULL;
	}

	bmbuf = NULL;
	if (bmstr) {
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
	if (kwstr != NULL) {
		int len = strlen (kwstr);
		kw = malloc (len+4);
		bm = malloc (len+4);
		if (kw != NULL && bm != NULL) {
			len = r_hex_str2binmask (kwstr, (ut8*)kw, (ut8*)bm);
			if (len<0)
				len = -len+1;
			if (len>0)
				ks = r_search_keyword_new (kw, R_ABS (len), bm, len, data);
		}
		free (kw);
		free (bm);
	}
	return ks;
}

/* Validate a regexp in the canonical format /<regexp>/<options> */
R_API RSearchKeyword *r_search_keyword_new_regexp (const char *str, const char *data) {
	RSearchKeyword *kw;
	int i = 0, start, length;

	while (isspace((const unsigned char)str[i]))
		i++;

	if (str[i++] != '/')
		return NULL;

	/* Find the fist non backslash-escaped slash */
	for (start = i; str[i]; i++) {
		if (str[i] == '/' && str[i-1] != '\\') 
			break;
	}

	if (str[i++] != '/')
		return NULL;

	length = i - start - 1;
	if ((length > 128) || (length < 1))
		return NULL;

	kw = R_NEW0(RSearchKeyword); 
	if (!kw)
		return NULL;

	kw->bin_keyword = malloc (length+1);
	if (!kw->bin_keyword)
		return NULL;

	kw->bin_keyword[length]=0;
	memcpy(kw->bin_keyword, str + start, length);
	kw->keyword_length = length;
	kw->type = R_SEARCH_KEYWORD_TYPE_STRING;
	kw->data = data;

	/* Parse the options */
	for (; str[i]; i++) {
		switch (str[i]) {
			case 'i':
				kw->icase = R_TRUE;
				break;
			default:
				free(kw);
				return NULL;
		}
	}

	return kw;
}
