/* radare - LGPL - Copyright 2010-2012 pancake<nopcode.org> */

#include <r_search.h>

R_API RSearchKeyword* r_search_keyword_new(const ut8 *kwbuf, int kwlen, const ut8 *bmbuf, int bmlen, const char *data) {
	RSearchKeyword *kw;
	if (kwlen < 1 || bmlen < 0)
		return NULL;
	kw = R_NEW0 (RSearchKeyword);
	if (!kw) return NULL;
	kw->type = R_SEARCH_KEYWORD_TYPE_BINARY;
	kw->keyword_length = kwlen;
	memcpy (kw->bin_keyword, kwbuf, kwlen);
	if (bmbuf && bmlen > 0) {
		memcpy (kw->bin_binmask, bmbuf, bmlen);
		kw->binmask_length = bmlen;
	} 
	return kw;
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
