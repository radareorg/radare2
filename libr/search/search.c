/* radare - LGPL - Copyright 2008-2014 pancake */

#include <r_search.h>
#include <r_list.h>
#include <ctype.h>

// Experimental search engine (fails, because stops at first hit of every block read 
#define USE_BMH 0

R_LIB_VERSION (r_search);

R_API RSearch *r_search_new(int mode) {
	RSearch *s = R_NEW0 (RSearch);
	if (!s) return NULL;
	if (!r_search_set_mode (s, mode)) {
		free (s);
		eprintf ("Cannot init search for mode %d\n", mode);
		return R_FALSE;
	}
	s->inverse = R_FALSE;
	s->user = NULL;
	s->callback = NULL;
	s->align = 0;
	s->distance = 0;
	s->contiguous = 0;
	s->pattern_size = 0;
	s->string_max = 255;
	s->string_min = 3;
	s->hits = r_list_new ();
	// TODO: review those mempool sizes. ensure never gets NULL
	s->pool = r_mem_pool_new (sizeof (RSearchHit), 1024, 10);
	s->kws = r_list_new ();
	s->kws->free = (RListFree) r_search_keyword_free;
	return s;
}

R_API RSearch *r_search_free(RSearch *s) {
	if (!s) return NULL;
	// TODO: it leaks
	r_mem_pool_free (s->pool);
	r_list_free (s->hits);
	r_list_free (s->kws);
	//r_io_free(s->iob.io); this is suposed to be a weak reference
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
	s->update = NULL;
	switch (mode) {
	case R_SEARCH_KEYWORD: s->update = r_search_mybinparse_update; break;
	case R_SEARCH_XREFS: s->update = r_search_xrefs_update; break;
	case R_SEARCH_REGEXP: s->update = r_search_regexp_update; break;
	case R_SEARCH_AES: s->update = r_search_aes_update; break;
	case R_SEARCH_STRING: s->update = r_search_strings_update; break;
	case R_SEARCH_DELTAKEY: s->update = r_search_deltakey_update; break;
	}
	if (s->update || mode == R_SEARCH_PATTERN) {
		s->mode = mode;
		return R_TRUE;
	}
	return R_FALSE;
}

R_API int r_search_begin(RSearch *s) {
	RListIter *iter;
	RSearchKeyword *kw;
	r_list_foreach (s->kws, iter, kw) {
		kw->count = 0;
		kw->idx[0] = 0;
		kw->distance = 0; //s->distance;
		kw->last = 0;
	}
#if 0
	/* TODO: compile regexpes */
	switch(s->mode) {
	case R_SEARCH_REGEXP:
		break;
	}
#endif
	return R_TRUE;
}

R_API int r_search_hit_new(RSearch *s, RSearchKeyword *kw, ut64 addr) {
	RSearchHit* hit;
	if (s->align && (addr%s->align)) {
		eprintf ("0x%08"PFMT64x" unaligned\n", addr);
		return R_FALSE;
	}
	if (!s->contiguous) {
		if (kw->last && addr == kw->last) {
			kw->count--;
			kw->last = addr + kw->keyword_length;
			eprintf ("0x%08"PFMT64x" Sequencial hit ignored.\n", addr);
			return R_TRUE;
		}
		kw->last = addr + kw->keyword_length;
	}
	if (s->callback)
		return s->callback (kw, s->user, addr);
	if (!(hit = r_mem_pool_alloc (s->pool)))
		return R_FALSE;
	hit->kw = kw;
	hit->addr = addr;
	r_list_append (s->hits, hit);
	return R_TRUE;
}

R_API int r_search_deltakey_update(void *_s, ut64 from, const ut8 *buf, int len) {
	RListIter *iter;
	unsigned char pch = 0;
	int i, j, count = 0;
	RSearch *s = (RSearch*)_s;

	for (i=0; i<len; i++) {
		RSearchKeyword *kw;
		r_list_foreach (s->kws, iter, kw) {
			for (j=0; j<=kw->distance; j++) {
				char ch = kw->bin_keyword[kw->idx[j]]; // signed char
				ut8 ch2 = buf[i];
				/* no icase in delta keys */
				/* no binmask in delta keys */
				/* no inverse support for delta keys */
				if (pch+ch == ch2) {
					kw->idx[j]++;
					if (kw->idx[j] == kw->keyword_length) {
						if (!r_search_hit_new (s, kw, (ut64)
							from+i-kw->keyword_length+1))
							return -1;
						kw->idx[j] = 0;
						//kw->idx[0] = 0;
						kw->distance = 0;
						kw->count++;
						count++;
						//s->nhits++;
					}
				}
				pch = ch2;
			}
		}
		count = 0;
	}
	return count;
}

/* Boyer-Moore-Horspool pattern matching */
#if USE_BMH
R_API int r_search_bmh (const RSearchKeyword *kw, const ut64 from, const ut8 *buf, const int len, ut64 *out) {
	ut64 bad_char_shift[UT8_MAX + 1];
	ut64 pos = from;
	int i, kw_len;
	ut8 ch;

	kw_len = kw->keyword_length - 1;

	if (kw_len < 0)
		return R_FALSE;

	for (i = 0; i < 256; i++)
		bad_char_shift[i] = kw->keyword_length;

	for (i = 0; i < kw_len; i++) {
		ch = kw->bin_keyword[i];
		bad_char_shift[kw->icase?tolower(ch):ch] = kw_len - i;
	}

	while (pos < len) {
		for (i = kw_len; ; i--) {
			ut8 ch1 = buf[pos + i];
			ut8 ch2 = kw->bin_keyword[i];
			if (kw->icase) {
				ch1 = tolower(ch1);
				ch2 = tolower(ch2);
			}
			if (kw->binmask_length && i < kw->binmask_length) {
				ch1 &= kw->bin_binmask[i];
				ch2 &= kw->bin_binmask[i];
			}
			if (ch1 != ch2)
				break;
			if (i == 0) {
				if (out) 
					*out = pos;
				return R_TRUE;
			}
		}
		ch = buf[pos + kw_len];
		pos += bad_char_shift[kw->icase?tolower(ch):ch];
	}

	return R_FALSE;
}
#endif

R_API int r_search_mybinparse_update(void *_s, ut64 from, const ut8 *buf, int len) {
	RSearch *s = (RSearch*)_s;
	RListIter *iter;
	//ut64 offset;
	int count = 0;

#if USE_BMH
	ut64 match_pos;
	RSearchKeyword *kw;
	r_list_foreach (s->kws, iter, kw) {
		offset = 0;
		while (offset < len && r_search_bmh(kw, offset, buf, len, &match_pos)) {
			if (!r_search_hit_new (s, kw, from + match_pos)) {
				eprintf ("Something very bad has happened...\n");
				return -1;
			}
			offset += match_pos + kw->keyword_length;
			kw->count++;
			count++;
			/* Stop at the first occurrence */
			if (s->inverse)
				return -1;
		}
	}
#else
	int i, j, hit;
	for (i=0; i<len; i++) {
		RSearchKeyword *kw;
		r_list_foreach (s->kws, iter, kw) {
			if (s->inverse && s->nhits>0) {
				//eprintf ("nhits = %d\n", s->nhits);
				return -1;
			}
			for (j=0; j<=kw->distance; j++) {
				ut8 ch = kw->bin_keyword[kw->idx[j]];
				ut8 ch2 = buf[i];
				if (kw->icase) {
					ch = tolower (ch);
					ch2 = tolower (ch2);
				}
				if (kw->binmask_length != 0 && kw->idx[j]<kw->binmask_length) {
					ch &= kw->bin_binmask[kw->idx[j]];
					ch2 &= kw->bin_binmask[kw->idx[j]];
				}
				if (ch != ch2) {
					if (s->inverse) {
						if (!r_search_hit_new (s, kw, (ut64)
								from+i-kw->keyword_length+1))
							return -1;
						kw->idx[j] = 0;
						//kw->idx[0] = 0;
						kw->distance = 0;
						//eprintf ("HIT FOUND !!! %x %x 0x%llx %d\n", ch, ch2, from+i, i);
						kw->count++;
						s->nhits++;
						return 1; // only return 1 keyword if inverse mode
					}
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
						if (s->inverse) {
							kw->idx[j] = 0;
							continue;
						}
						if (!r_search_hit_new (s, kw, (ut64)
								from+i-kw->keyword_length+1))
							return -1;
						kw->idx[j] = 0;
						//kw->idx[0] = 0;
						kw->distance = 0;
						kw->count++;
						count++;
						//s->nhits++;
					}
				}
			}
		}
		count = 0;
	}
#endif

	return count;
}

R_API void r_search_set_distance(RSearch *s, int dist) {
	if (dist>=R_SEARCH_DISTANCE_MAX) {
		eprintf ("Invalid distance\n");
		s->distance = 0;
	} else s->distance = (dist>0)?dist:0;
}

// deprecate? or standarize with ->align ??
R_API void r_search_pattern_size(RSearch *s, int size) {
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

static int listcb(RSearchKeyword *k, void *user, ut64 addr) {
	RSearchHit *hit = R_NEW (RSearchHit);
	hit->kw = k;
	hit->addr = addr;
	r_list_append (user, hit);
	return R_TRUE;
}

R_API RList *r_search_find(RSearch *s, ut64 addr, const ut8 *buf, int len) {
	RList *ret = r_list_new ();
	r_search_set_callback (s, listcb, ret);
	r_search_update (s, &addr, buf, len);
	return ret;
}

/* --- keywords --- */
R_API int r_search_kw_add(RSearch *s, RSearchKeyword *kw) {
	if (!kw) return R_FALSE;
	r_list_append (s->kws, kw);
	kw->kwidx = s->n_kws++;
	return R_TRUE;
}

R_API void r_search_kw_reset(RSearch *s) {
	r_list_free (s->kws);
	s->kws = r_list_new ();
}

R_API void r_search_reset(RSearch *s, int mode) {
	r_list_purge (s->hits);
	s->nhits = 0;
	s->hits = r_list_new ();
	s->hits->free = free;
	r_search_kw_reset (s);
	if (!r_search_set_mode (s, mode))
		eprintf ("Cannot init search for mode %d\n", mode);
}
