/* radare - LGPL - Copyright 2010 pancake<nopcode.org> */

#include <r_search.h>

// WIP

R_API RSearchKeyword* r_search_keyword_new(RSearch *s, const char *kw, int kwlen, const char *bm, int bmlen, const char *data) {
	return NULL;
}

R_API RSearchKeyword* r_search_keyword_new_hex(RSearch *s, const char *kw, const char *bm, const char *data) {
	RSearchKeyword *k = R_NEW (RSearchKeyword);
	int kwlen = strlen (kw)+1;
	if (k == NULL)
		return NULL;
	if (bm == NULL) bm = "";
	memcpy (k->keyword, kw, kwlen);
	memcpy (k->bin_keyword, kw, kwlen);
	k->keyword_length = strlen (kw);
	if (k->binmask_length == -1)
		k->binmask_length = strlen (bm);
	if (bm) {
		memcpy (k->binmask, bm, k->binmask_length);
		k->binmask_length = r_hex_str2bin (bm, k->bin_binmask);
	} else k->binmask[0] = k->binmask_length = 0;
	list_add (&(k->list), &(s->kws));
	k->kwidx = s->n_kws++;
	return k;
}
