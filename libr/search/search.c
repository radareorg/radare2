/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include <r_search.h>

R_API int r_search_init(RSearch *s, int mode) {
	memset (s,'\0', sizeof (RSearch));
	if (!r_search_set_mode (s, mode))
		return R_FALSE;
	s->mode = mode;
	s->user = NULL;
	s->callback = NULL;
	s->pattern_size = 0;
	s->string_max = 255;
	s->string_min = 3;
	s->hits = r_list_new ();
	// TODO: review those mempool sizes. ensure never gets NULL
	s->pool = r_mem_pool_new (sizeof (RSearchHit), 1024, 10);
	INIT_LIST_HEAD (&(s->kws));
	return R_TRUE;
}

R_API RSearch *r_search_new(int mode) {
	RSearch *s = R_NEW (RSearch);
	if (!r_search_init (s, mode)) {
		r_search_free (s);
		s = NULL;
	}
	return s;
}

R_API RSearch *r_search_free(RSearch *s) {
	// TODO: it leaks
	r_mem_pool_free (s->pool);
	r_list_destroy (s->hits);
	free (s);
	return NULL;
}

R_API int r_search_set_string_limits(RSearch *s, ut32 min, ut32 max) {
	if (max < min)
		return R_FALSE;
	s->string_min = min;
	s->string_max = max;
	return R_TRUE;
}

R_API int r_search_set_mode(RSearch *s, int mode) {
	int ret = R_FALSE;
	switch (mode) {
	case R_SEARCH_KEYWORD:
	case R_SEARCH_REGEXP:
	case R_SEARCH_PATTERN:
	case R_SEARCH_STRING:
	case R_SEARCH_XREFS:
	case R_SEARCH_AES:
		s->mode = mode;
		ret = R_TRUE;
	}
	return ret;
}

/* control */
R_API int r_search_begin(RSearch *s) {
	struct list_head *pos;
	list_for_each_prev (pos, &s->kws) {
		RSearchKeyword *kw = list_entry (pos, RSearchKeyword, list);
		kw->count = 0;
		kw->idx = 0;
	}
#if 0
	/* TODO: compile regexpes */
	switch(s->mode) {
	case R_SEARCH_REGEXP:
		break;
	}
#endif
	return 1;
}

R_API int r_search_hit_new(RSearch *s, RSearchKeyword *kw, ut64 addr) {
	RSearchHit* hit;
	if (s->callback)
		return s->callback (kw, s->user, addr);
	hit = r_mem_pool_alloc (s->pool);
	if (!hit)
		return R_FALSE;
	hit->kw = kw;
	hit->addr = addr;
	r_list_append (s->hits, hit);
	return R_TRUE;
}

// TODO: move into a plugin */
R_API int r_search_mybinparse_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	struct list_head *pos;
	int i, count = 0;

	for (i=0; i<len; i++) {
		list_for_each_prev (pos, &s->kws) {
			RSearchKeyword *kw = list_entry(pos, RSearchKeyword, list);
			ut8 ch = kw->bin_keyword[kw->idx];
			ut8 ch2 = buf[i];
			if (kw->binmask_length != 0 && kw->idx < kw->binmask_length) {
				ch &= kw->bin_binmask[kw->idx];
				ch2 &= kw->bin_binmask[kw->idx];
			}
			if (ch == ch2) {
				kw->idx++;
				if (kw->idx == kw->keyword_length) {
					r_search_hit_new (s, kw, (ut64)
						from+i-kw->keyword_length+1);
					kw->idx = 0;
					kw->count++;
				}
			} else kw->idx = 0;
			count++;
		}
		count = 0;
	}
	return count;
}

R_API int r_search_set_pattern_size(RSearch *s, int size) {
	s->pattern_size = size;
	return 0;
}

R_API void r_search_set_callback(RSearch *s, RSearchCallback(callback), void *user) {
	s->callback = callback;
	s->user = user;
}

/* TODO: initialize update callback in _init */
R_API int r_search_update(RSearch *s, ut64 *from, const ut8 *buf, long len) {
	int ret = 0;
	switch (s->mode) {
	case R_SEARCH_KEYWORD:
		ret += r_search_mybinparse_update (s, *from, buf, len);
		break;
	case R_SEARCH_XREFS:
		r_search_xrefs_update (s, *from, buf, len);
		break;
	case R_SEARCH_REGEXP:
		ret += r_search_regexp_update (s, *from, buf, len);
		break;
	case R_SEARCH_AES:
		ret += r_search_aes_update (s, *from, buf, len);
		*from -= R_SEARCH_AES_BOX_SIZE;
		break;
	case R_SEARCH_STRING:
		ret += r_search_strings_update (s, *from, (const char *)buf, len, 0);
		break;
	case R_SEARCH_PATTERN:
		//ret += r_search_pattern_update(buf, s->pattern_size
		break;
	}
	return ret;
}

R_API int r_search_update_i(RSearch *s, ut64 from, const ut8 *buf, long len) {
	return r_search_update (s, &from, buf, len);
}

/* --- keywords --- */
/* string */
R_API int r_search_kw_add(RSearch *s, const char *kw, const char *bm) {
	RSearchKeyword *k = R_NEW (RSearchKeyword);
	int kwlen = strlen (kw)+1;
	if (k == NULL)
		return R_FALSE;
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
	return R_TRUE;
}

/* hexpair string */
R_API int r_search_kw_add_hex(RSearch *s, const char *kw, const char *bm) {
	RSearchKeyword *k = R_NEW (RSearchKeyword);
	if (k == NULL) // is necessary to assert everywhere??
		return R_FALSE;
	strncpy (k->keyword, kw, sizeof (k->keyword));
	k->keyword_length = r_hex_str2bin (kw, k->bin_keyword);
	if (bm) {
		strncpy(k->binmask, bm, sizeof (k->binmask));
		k->binmask_length = r_hex_str2bin (bm, k->bin_binmask);
	} else k->binmask[0] = k->binmask_length = 0;
	list_add (&(k->list), &(s->kws));
	k->kwidx = s->n_kws++;
	return R_TRUE;
}

/* raw bin */
R_API int r_search_kw_add_bin(RSearch *s, const ut8 *kw, int kw_len, const ut8 *bm, int bm_len) {
	RSearchKeyword *k = R_NEW (RSearchKeyword);
	if (kw == NULL)
		return R_FALSE;
	memcpy (k->bin_keyword, kw, kw_len);
	k->keyword_length = kw_len;
	r_hex_bin2str (kw, kw_len, k->keyword);
	if (bm) memcpy (k->bin_binmask, bm, bm_len);
	if (bm) r_hex_bin2str (bm, bm_len, k->binmask);
	else k->binmask_length = 0;
	list_add (&(k->list), &(s->kws));
	k->kwidx = s->n_kws++;
	return R_TRUE;
}

/* // MUST DEPRECATE // show keywords */
R_API RSearchKeyword *r_search_kw_list(RSearch *s) {
	struct list_head *pos;
	list_for_each_prev (pos, &s->kws) {
		RSearchKeyword *kw = list_entry (pos, RSearchKeyword, list);
		printf ("%s %s\n", kw->keyword, kw->binmask);
	}
	return NULL;
}

R_API void r_search_reset(RSearch *s) {
	r_list_destroy (s->hits);
	s->hits = r_list_new ();
	s->hits->free = free;
	r_search_kw_reset (s);
}

R_API void r_search_kw_reset(RSearch *s) {
}
