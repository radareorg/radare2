/* radare - LGPL - Copyright 2008-2016 pancake */

#include <r_search.h>
#include <r_list.h>
#include <ctype.h>

// Experimental search engine (fails, because stops at first hit of every block read
#define USE_BMH 0

R_LIB_VERSION (r_search);

typedef struct {
	ut64 end;
	int len;
	ut8 data[];
} RSearchLeftover;

R_API RSearch *r_search_new(int mode) {
	RSearch *s = R_NEW0 (RSearch);
	if (!s) {
		return NULL;
	}
	if (!r_search_set_mode (s, mode)) {
		free (s);
		eprintf ("Cannot init search for mode %d\n", mode);
		return false;
	}
	s->inverse = false;
	s->data = NULL;
	s->user = NULL;
	s->callback = NULL;
	s->align = 0;
	s->distance = 0;
	s->contiguous = 0;
	s->overlap = false;
	s->pattern_size = 0;
	s->string_max = 255;
	s->string_min = 3;
	s->hits = r_list_newf (free);
	s->maxhits = 0;
	// TODO: review those mempool sizes. ensure never gets NULL
	s->kws = r_list_newf (free);
	if (!s->kws) {
		r_search_free (s);
		return NULL;
	}
	s->kws->free = (RListFree) r_search_keyword_free;
	return s;
}

R_API RSearch *r_search_free(RSearch *s) {
	if (!s) {
		return NULL;
	}
	r_list_free (s->hits);
	r_list_free (s->kws);
	//r_io_free(s->iob.io); this is supposed to be a weak reference
	free (s->data);
	free (s);
	return NULL;
}

R_API int r_search_set_string_limits(RSearch *s, ut32 min, ut32 max) {
	if (max < min) {
		return false;
	}
	s->string_min = min;
	s->string_max = max;
	return true;
}

R_API int r_search_magic_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	eprintf ("TODO: import libr/core/cmd_search.c /m implementation into rsearch\n");
	return false;
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
	case R_SEARCH_MAGIC: s->update = r_search_magic_update; break;
	}
	if (s->update || mode == R_SEARCH_PATTERN) {
		s->mode = mode;
		return true;
	}
	return false;
}

R_API int r_search_begin(RSearch *s) {
	RListIter *iter;
	RSearchKeyword *kw;
	r_list_foreach (s->kws, iter, kw) {
		kw->count = 0;
		kw->last = 0;
	}
	return true;
}

// Returns 2 if search.maxhits is reached, 0 on error, otherwise 1
R_API int r_search_hit_new(RSearch *s, RSearchKeyword *kw, ut64 addr) {
	if (s->align && (addr%s->align)) {
		eprintf ("0x%08"PFMT64x" unaligned\n", addr);
		return 1;
	}
	if (!s->contiguous) {
		if (kw->last && addr == kw->last) {
			kw->count--;
			kw->last = s->bckwrds ? addr : addr + kw->keyword_length;
			eprintf ("0x%08"PFMT64x" Sequential hit ignored.\n", addr);
			return 1;
		}
	}
	// kw->last is used by string search, the right endpoint of last matcch (forward search), to honor search.overlap
	kw->last = s->bckwrds ? addr : addr + kw->keyword_length;
	if (s->callback) {
		int ret = s->callback (kw, s->user, addr);
		kw->count++;
		s->nhits++;
		// If callback returns 0 or larger than 1, forwards it; otherwise returns 2 if search.maxhits is reached
		return !ret || ret > 1 ? ret : s->maxhits && s->nhits >= s->maxhits ? 2 : 1;
	}
	kw->count++;
	s->nhits++;
	RSearchHit* hit = R_NEW0 (RSearchHit);
	if (hit) {
		hit->kw = kw;
		hit->addr = addr;
		r_list_append (s->hits, hit);
	}
	return s->maxhits && s->nhits >= s->maxhits ? 2 : 1;
}

// TODO support search across block boundaries
// Supported search variants: backward, overlap
R_API int r_search_deltakey_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	RListIter *iter;
	int longest = 0, i, j;
	RSearchKeyword *kw;
	RSearchLeftover *left;
	const int old_nhits = s->nhits;
	r_list_foreach (s->kws, iter, kw) {
		longest = R_MAX (longest, kw->keyword_length + 1);
	}
	if (!longest) {
		return 0;
	}
	if (s->data) {
		left = s->data;
		if (left->end != from) {
			left->len = 0;
		}
	} else {
		left = malloc (sizeof(RSearchLeftover) + (size_t)2 * (longest - 1));
		if (!left) {
			return -1;
		}
		s->data = left;
		left->len = 0;
		if (s->bckwrds) {
			r_list_foreach (s->kws, iter, kw) {
				ut8 *i = kw->bin_keyword, *j = kw->bin_keyword + kw->keyword_length;
				for (; i < j; i++) {
					*i = -*i;
				}
			}
		}
	}
	if (s->bckwrds) {
		// XXX Change function signature from const ut8 * to ut8 *
		ut8 *i = (ut8 *)buf, *j = i + len;
		while (i < j) {
			ut8 t = *i;
			*i++ = *--j;
			*j = t;
		}
	}

	ut64 len1 = left->len + R_MIN (longest - 1, len);
	memcpy (left->data + left->len, buf, len1 - left->len);
	r_list_foreach (s->kws, iter, kw) {
		ut8 *a = kw->bin_keyword;
		i = s->overlap || !kw->count ? 0 :
				s->bckwrds
				? kw->last - from < left->len ? from + left->len - kw->last : 0
				: from - kw->last < left->len ? kw->last + left->len - from : 0;
		for (; i + kw->keyword_length < len1 && i < left->len; i++) {
			if ((ut8)(left->data[i+1] - left->data[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(left->data[i+j+1] - left->data[i+j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = r_search_hit_new (s, kw, s->bckwrds ? from - kw->keyword_length - 1 - i + left->len : from + i - left->len);
					kw->last += s->bckwrds ? 0 : 1;
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					if (!s->overlap) {
						i += kw->keyword_length;
					}
				}
			}
		}
		i = s->overlap || !kw->count ? 0 :
				s->bckwrds
				? from > kw->last ? from - kw->last : 0
				: from < kw->last ? kw->last - from : 0;
		for (; i + kw->keyword_length < len; i++) {
			if ((ut8)(buf[i+1] - buf[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(buf[i+j+1] - buf[i+j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = r_search_hit_new (s, kw, s->bckwrds ? from - kw->keyword_length - 1 - i : from + i);
					kw->last += s->bckwrds ? 0 : 1;
					if (!t) {
						return -1;
					}
					if (t > 1) {
						return s->nhits - old_nhits;
					}
					if (!s->overlap) {
						i += kw->keyword_length;
					}
				}
			}
		}
	}
	if (len < longest - 1) {
		if (len1 < longest) {
			left->len = len1;
		} else {
			left->len = longest - 1;
			memmove (left->data, left->data + len1 - longest + 1, longest - 1);
		}
	} else {
		left->len = longest - 1;
		memcpy (left->data, buf + len - longest + 1, longest - 1);
	}
	left->end = s->bckwrds ? from - len : from + len;

	return s->nhits - old_nhits;
}

#if 0
// Boyer-Moore-Horspool pattern matching
// Supported search variants: icase, overlap
static int r_search_horspool(RSearch *s, RSearchKeyword *kw, ut64 from, const ut8 *buf, int len) {
	ut64 bad_char_shift[UT8_MAX + 1];
	int i, j, m = kw->keyword_length - 1, count = 0;
	ut8 ch;

	for (i = 0; i < R_ARRAY_SIZE (bad_char_shift); i++) {
		bad_char_shift[i] = kw->keyword_length;
	}
	for (i = 0; i < m; i++) {
		ch = kw->bin_keyword[i];
		bad_char_shift[kw->icase ? tolower (ch) : ch] = m - i;
	}

	for (i = 0; i + m < len; ) {
	next:
		for (j = m; ; j--) {
			ut8 a = buf[i + j], b = kw->bin_keyword[j];
			if (kw->icase) {
				a = tolower (a);
				b = tolower (b);
			}
			if (a != b) break;
			if (i == 0) {
				if (!r_search_hit_new (s, kw, from + i)) {
					return -1;
				}
				kw->count++;
				count++;
				if (!s->overlap) {
					i += kw->keyword_length;
					goto next;
				}
			}
		}
		ch = buf[i + m];
		i += bad_char_shift[kw->icase ? tolower (ch) : ch];
	}

	return false;
}
#endif

static bool brute_force_match(RSearch *s, RSearchKeyword *kw, const ut8 *buf, int i) {
	int j = 0;
	if (s->distance) { // slow path, more work in the loop
		int dist = 0;
		if (kw->binmask_length > 0) {
			for (; j < kw->keyword_length; j++) {
				int k = j % kw->binmask_length;
				ut8 a = buf[i + j], b = kw->bin_keyword[j];
				if (kw->icase) {
					a = tolower (a);
					b = tolower (b);
				}
				if ((a & kw->bin_binmask[k]) != (b & kw->bin_binmask[k])) {
					dist++;
				}
			}
		} else if (kw->icase) {
			for (; j < kw->keyword_length; j++) {
				if (tolower (buf[i + j]) != tolower (kw->bin_keyword[j])) {
					dist++;
				}
			}
		} else {
			for (; j < kw->keyword_length; j++) {
				if (buf[i + j] != kw->bin_keyword[j]) {
					dist++;
				}
			}
		}
		return dist <= s->distance;
	}

	if (kw->binmask_length > 0) {
		for (; j < kw->keyword_length; j++) {
			int k = j % kw->binmask_length;
			ut8 a = buf[i + j], b = kw->bin_keyword[j];
			if (kw->icase) {
				a = tolower (a);
				b = tolower (b);
			}
			if ((a & kw->bin_binmask[k]) != (b & kw->bin_binmask[k])) {
				break;
			}
		}
	} else if (kw->icase) {
		while (j < kw->keyword_length &&
			tolower (buf[i + j]) == tolower (kw->bin_keyword[j])) {
			j++;
		}
	} else {
		while (j < kw->keyword_length && buf[i + j] == kw->bin_keyword[j]) {
			j++;
		}
	}
	return j == kw->keyword_length;
}

// Supported search variants: backward, binmask, icase, inverse, overlap
R_API int r_search_mybinparse_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	RSearchKeyword *kw;
	RListIter *iter;
	RSearchLeftover *left;
	int longest = 0, i;
	const int old_nhits = s->nhits;

	r_list_foreach (s->kws, iter, kw) {
		longest = R_MAX (longest, kw->keyword_length);
	}
	if (!longest) {
		return 0;
	}
	if (s->data) {
		left = s->data;
		if (left->end != from) {
			left->len = 0;
		}
	} else {
		left = malloc (sizeof(RSearchLeftover) + (size_t)2 * (longest - 1));
		if (!left) {
			return -1;
		}
		s->data = left;
		left->len = 0;
	}
	if (s->bckwrds) {
		// XXX Change function signature from const ut8 * to ut8 *
		ut8 *i = (ut8 *)buf, *j = i + len;
		while (i < j) {
			ut8 t = *i;
			*i++ = *--j;
			*j = t;
		}
	}

	ut64 len1 = left->len + R_MIN (longest - 1, len);
	memcpy (left->data + left->len, buf, len1 - left->len);
	r_list_foreach (s->kws, iter, kw) {
		i = s->overlap || !kw->count ? 0 :
				s->bckwrds
				? kw->last - from < left->len ? from + left->len - kw->last : 0
				: from - kw->last < left->len ? kw->last + left->len - from : 0;
		for (; i + kw->keyword_length <= len1 && i < left->len; i++) {
			if (brute_force_match (s, kw, left->data, i) != s->inverse) {
				int t = r_search_hit_new (s, kw, s->bckwrds ? from - kw->keyword_length - i + left->len : from + i - left->len);
				if (!t) {
					return -1;
				}
				if (t > 1) {
					return s->nhits - old_nhits;
				}
				if (!s->overlap) {
					i += kw->keyword_length - 1;
				}
			}
		}
		i = s->overlap || !kw->count ? 0 :
				s->bckwrds
				? from > kw->last ? from - kw->last : 0
				: from < kw->last ? kw->last - from : 0;
		for (; i + kw->keyword_length <= len; i++) {
			if (brute_force_match (s, kw, buf, i) != s->inverse) {
				int t = r_search_hit_new (s, kw, s->bckwrds ? from - kw->keyword_length - i : from + i);
				if (!t) {
					return -1;
				}
				if (t > 1) {
					return s->nhits - old_nhits;
				}
				if (!s->overlap) {
					i += kw->keyword_length - 1;
				}
			}
		}
	}
	if (len < longest - 1) {
		if (len1 < longest) {
			left->len = len1;
		} else {
			left->len = longest - 1;
			memmove (left->data, left->data + len1 - longest + 1, longest - 1);
		}
	} else {
		left->len = longest - 1;
		memcpy (left->data, buf + len - longest + 1, longest - 1);
	}
	left->end = s->bckwrds ? from - len : from + len;

	return s->nhits - old_nhits;
}

R_API void r_search_set_distance(RSearch *s, int dist) {
	if (dist>=R_SEARCH_DISTANCE_MAX) {
		eprintf ("Invalid distance\n");
		s->distance = 0;
	} else {
		s->distance = (dist>0)?dist:0;
	}
}

// deprecate? or standarize with ->align ??
R_API void r_search_pattern_size(RSearch *s, int size) {
	s->pattern_size = size;
}

R_API void r_search_set_callback(RSearch *s, RSearchCallback(callback), void *user) {
	s->callback = callback;
	s->user = user;
}

// backward search: from points to the right endpoint
// forward search: from points to the left endpoint
R_API int r_search_update(RSearch *s, ut64 from, const ut8 *buf, long len) {
	int ret = -1;
	if (s->update) {
		if (s->maxhits && s->nhits >= s->maxhits) {
			return 0;
		}
		ret = s->update (s, from, buf, len);
		if (s->mode == R_SEARCH_AES) {
			ret = R_MIN (R_SEARCH_AES_BOX_SIZE, len);
		}
	} else {
		eprintf ("r_search_update: No search method defined\n");
	}
	return ret;
}

R_API int r_search_update_i(RSearch *s, ut64 from, const ut8 *buf, long len) {
	return r_search_update (s, from, buf, len);
}

static int listcb(RSearchKeyword *k, void *user, ut64 addr) {
	RSearchHit *hit = R_NEW0 (RSearchHit);
	if (!hit) {
		return 0;
	}
	hit->kw = k;
	hit->addr = addr;
	r_list_append (user, hit);
	return 1;
}

R_API RList *r_search_find(RSearch *s, ut64 addr, const ut8 *buf, int len) {
	RList *ret = r_list_new ();
	r_search_set_callback (s, listcb, ret);
	r_search_update (s, addr, buf, len);
	return ret;
}

/* --- keywords --- */
R_API int r_search_kw_add(RSearch *s, RSearchKeyword *kw) {
	if (!kw || !kw->keyword_length) {
		return false;
	}
	kw->kwidx = s->n_kws++;
	r_list_append (s->kws, kw);
	return true;
}

// Reverse bin_keyword & bin_binmask for backward search
R_API void r_search_string_prepare_backward(RSearch *s) {
	RListIter *iter;
	RSearchKeyword *kw;
	// Precondition: !kw->binmask_length || kw->keyword_length % kw->binmask_length == 0
	r_list_foreach (s->kws, iter, kw) {
		ut8 *i = kw->bin_keyword, *j = kw->bin_keyword + kw->keyword_length;
		while (i < j) {
			ut8 t = *i;
			*i++ = *--j;
			*j = t;
		}
		i = kw->bin_binmask;
		j = kw->bin_binmask + kw->binmask_length;
		while (i < j) {
			ut8 t = *i;
			*i++ = *--j;
			*j = t;
		}
	}
}

R_API void r_search_reset(RSearch *s, int mode) {
	s->nhits = 0;
	if (!r_search_set_mode (s, mode)) {
		eprintf ("Cannot init search for mode %d\n", mode);
	}
}

R_API void r_search_kw_reset(RSearch *s) {
	r_list_purge (s->kws);
	r_list_purge (s->hits);
	R_FREE (s->data);
}
