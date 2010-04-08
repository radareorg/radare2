/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_search.h>

R_API RSearchKeyword* r_search_keyword_new(const ut8 *kw, int kwlen, const ut8 *bm, int bmlen, const char *data) {
	RSearchKeyword *k = NULL;
	if (bm == NULL)
		bm = (const ut8*) "";
	if (kwlen>0 && bmlen>=0 && (kwlen < sizeof (k->keyword))
			&& (bmlen < sizeof (k->binmask))) {
		k = R_NEW (RSearchKeyword);
		if (k != NULL) {
			memcpy (k->keyword, kw, kwlen);
			k->keyword_length = kwlen;
			memcpy (k->bin_keyword, kw, kwlen);
			if (bm && bmlen>0) {
				//memcpy (k->binmask, bm, bmlen);
				// XXX Fix this conversion.. r_hex_str.. ?
				snprintf (k->binmask, sizeof (k->binmask),
					"%02x%02x%02x..", bm[0], bm[1], bm[2]);
				memcpy (k->bin_binmask, bm, bmlen);
				k->binmask_length = bmlen;
			} else k->binmask[0] = k->binmask_length = 0;
		}
	}
	return k;
}

R_API RSearchKeyword* r_search_keyword_new_str(const char *kw, const char *bmhex, const char *data) {
	RSearchKeyword *ks = NULL;
	int bmlen = 0;
	ut8 *bm = NULL;
	if (bmhex != NULL) {
		bm = malloc (strlen (bmhex));
		if (bm != NULL) {
			bmlen = r_hex_str2bin (bmhex, (ut8*)bm);
			if (bmlen<1) {
				free (bm);
				bm = NULL;
			}
		}
	}
	ks = r_search_keyword_new ((ut8 *)kw, strlen (kw), bm, bmlen, data);
	free (bm);
	return ks;
}

R_API RSearchKeyword* r_search_keyword_new_hex(const char *kwstr, const char *bmstr, const char *data) {
	RSearchKeyword *ks = NULL;
	ut8 *kw, *bm;
	int bmlen, kwlen;
	if (kwstr != NULL) {
		kw = malloc (strlen (kwstr));
		bm = malloc (strlen (bmstr));
		if (kw != NULL && bm != NULL) {
			bmlen = r_hex_str2bin (bmstr, (ut8*)bm);
			kwlen = r_hex_str2bin (kwstr, (ut8*)kw);
			if (bmlen>=0 && kwlen>0)
				ks = r_search_keyword_new (kw, kwlen, bm, bmlen, data);
		}
		free (kw);
		free (bm);
	}
	return ks;
}
