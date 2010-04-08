/* radare - LGPL - Copyright 2008-2010 pancake<nopcode.org> */

#include <r_search.h>

R_API int r_search_init(RSearch *s, int mode) {
	memset (s,'\0', sizeof (RSearch));
	if (!r_search_set_mode (s, mode)) {
		eprintf ("Cannot init search for mode %d\n", mode);
		return R_FALSE;
	}
	s->mode = mode;
	s->user = NULL;
	s->callback = NULL;
	s->distance = 0;
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
	int ret;
	s->update = NULL;
	switch (mode) {
	case R_SEARCH_KEYWORD:
		s->update = r_search_mybinparse_update;
		break;
	case R_SEARCH_XREFS:
		s->update = r_search_xrefs_update;
		break;
	case R_SEARCH_REGEXP:
		s->update = r_search_regexp_update;
		break;
	case R_SEARCH_AES:
		s->update = r_search_aes_update;
		break;
	case R_SEARCH_STRING:
		s->update = r_search_strings_update;
		break;
	case R_SEARCH_PATTERN:
		//ret += r_search_pattern_update(buf, s->pattern_size
		break;
	}
	if (s->update) {
		s->mode = mode;
		ret = R_TRUE;
	} else ret = R_FALSE;
	return ret;
}

R_API int r_search_begin(RSearch *s) {
	struct list_head *pos;
	list_for_each_prev (pos, &s->kws) {
		RSearchKeyword *kw = list_entry (pos, RSearchKeyword, list);
		kw->count = 0;
		kw->idx[0] = 0;
		kw->distance = 0;//s->distance;
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
// TODO: This algorithm can be simplified by just using a non-distance search
// ... split this algorithm in two for performance
R_API int r_search_mybinparse_update(void *_s, ut64 from, const ut8 *buf, int len) {
	struct list_head *pos;
	int i, j, hit, count = 0;
	RSearch *s = (RSearch*)_s;

	for (i=0; i<len; i++) {
		list_for_each_prev (pos, &s->kws) {
			RSearchKeyword *kw = list_entry (pos, RSearchKeyword, list);
			for (j=0;j<=kw->distance;j++) {
				ut8 ch = kw->bin_keyword[kw->idx[j]];
				ut8 ch2 = buf[i];
				if (kw->binmask_length != 0 && kw->idx[j]<kw->binmask_length) {
					ch &= kw->bin_binmask[kw->idx[j]];
					ch2 &= kw->bin_binmask[kw->idx[j]];
				}
				if (ch != ch2) {
					if (kw->distance<s->distance) {
						kw->idx[kw->distance+1] = kw->idx[kw->distance];
						kw->distance++;
						hit = R_TRUE;
					} else {
						kw->idx[0] = 0;
						kw->distance = 0;
						hit = R_FALSE;
					}
				} else hit = R_TRUE;
				if (hit) {
					kw->idx[j]++;
					if (kw->idx[j] == kw->keyword_length) {
						r_search_hit_new (s, kw, (ut64)
							from+i-kw->keyword_length+1);
						kw->idx[0] = 0;
						kw->distance = 0;
						kw->count++;
						count++;
					}
				}
			}
		}
		count = 0;
	}
	return count;
}

R_API void r_search_set_distance(RSearch *s, int dist) {
	if (dist>=R_SEARCH_DISTANCE_MAX) {
		eprintf ("Invalid distance\n");
		s->distance = 0;
	} else s->distance = (dist>0)?dist:0;
}

R_API void r_search_set_pattern_size(RSearch *s, int size) {
	s->pattern_size = size;
}

R_API void r_search_set_callback(RSearch *s, RSearchCallback(callback), void *user) {
	s->callback = callback;
	s->user = user;
}

/* TODO: initialize update callback in _init or begin... */
R_API int r_search_update(RSearch *s, ut64 *from, const ut8 *buf, long len) {
	int ret = -1;
	if (s->update != NULL) {
		ret = s->update (s, *from, buf, len);
		if (s->mode == R_SEARCH_AES) {
			int l = R_SEARCH_AES_BOX_SIZE;
			//*from -= R_SEARCH_AES_BOX_SIZE;
			if (len<l) l = len;
			return l;
		}
	} else eprintf ("r_search_update: No search method defined\n");
	return ret;
}

R_API int r_search_update_i(RSearch *s, ut64 from, const ut8 *buf, long len) {
	return r_search_update (s, &from, buf, len);
}

/* --- keywords --- */
R_API int r_search_kw_add(RSearch *s, RSearchKeyword *kw) {
	int ret = R_FALSE;
	if (kw) {
		list_add (&(kw->list), &(s->kws));
		kw->kwidx = s->n_kws++;
		ret = R_TRUE;
	}
	return ret;
}

R_API void r_search_kw_reset(RSearch *s) {
	// leaks
	struct list_head *pos, *n;
	list_for_each_safe (pos, n, &s->kws) {
		RSearchKeyword *kw = list_entry (pos, RSearchKeyword, list);
		free (kw);
	}
	INIT_LIST_HEAD (&(s->kws));
}

/* // MUST DEPRECATE // show keywords */
R_API void r_search_kw_list(RSearch *s) {
	struct list_head *pos, *n;
	list_for_each_safe (pos, n, &s->kws) {
		RSearchKeyword *kw = list_entry (pos, RSearchKeyword, list);
		free (kw);
	}
}

R_API void r_search_reset(RSearch *s) {
	r_list_destroy (s->hits);
	s->hits = r_list_new ();
	s->hits->free = free;
	r_search_kw_reset (s);
}
