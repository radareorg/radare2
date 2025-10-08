/* radare - LGPL - Copyright 2008-2024 pancake */

#define R_LOG_ORIGIN "search"

#include <r_search.h>
#include "search.h"

R_LIB_VERSION (r_search);

typedef struct {
	ut64 end;
	int len;
	ut8 data[];
} RSearchLeftover;

R_API RSearch *r_search_new(int mode) {
	RSearch *s = R_NEW0 (RSearch);
	if (!r_search_set_mode (s, mode)) {
		free (s);
		R_LOG_ERROR ("Cannot init search for mode %d", mode);
		return false;
	}
	s->inverse = false;
	s->data = NULL;
	s->datafree = free;
	s->user = NULL;
	s->callback = NULL;
	s->r_callback = NULL;
	s->align = 0;
	s->distance = 0;
	s->contiguous = 0;
	s->overlap = false;
	s->pattern_size = 0;
	s->longest = -1;
	s->string_max = 1024;
	s->string_min = 3;
	s->hits = r_list_newf (free);
	s->maxhits = 0;
	s->kws = r_list_newf (free);
	if (!s->kws) {
		r_search_free (s);
		return NULL;
	}
	s->kws->free = (RListFree) r_search_keyword_free;
	return s;
}

R_API void r_search_free(RSearch *s) {
	if (s) {
		r_list_free (s->hits);
		r_list_free (s->kws);
		if (s->datafree) {
			s->datafree (s->data);
		}
		free (s);
	}
}

R_API bool r_search_set_string_limits(RSearch *s, ut32 min, ut32 max) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (max > 0 && max < min) {
		return false;
	}
	if (min > 0) {
		s->string_min = min;
	}
	if (max > 0) {
		s->string_max = max;
	}
	return true;
}

static int search_magic_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	R_LOG_TODO ("import libr/core/cmd_search.c /m implementation into rsearch");
	return false;
}

R_API int r_search_set_mode(RSearch *s, int mode) {
	s->update = NULL;
	bool ok = true;
	switch (mode) {
	case R_SEARCH_KEYWORD: s->update = search_kw_update; break;
	case R_SEARCH_REGEXP: s->update = search_regexp_update; break;
	case R_SEARCH_AES: s->update = search_aes_update; break;
	case R_SEARCH_SM4: s->update = search_sm4_update; break;
	case R_SEARCH_ASN1_PRIV_KEY: s->update = search_asn1_privkey_update; break;
	case R_SEARCH_RAW_PRIV_KEY: s->update = search_raw_privkey_update; break;
	case R_SEARCH_STRING: s->update = search_strings_update; break;
	case R_SEARCH_DELTAKEY: s->update = search_deltakey_update; break;
	case R_SEARCH_MAGIC: s->update = search_magic_update; break;

	// no r_search_update for these
	case R_SEARCH_RABIN_KARP:
	case R_SEARCH_TIRE:
	case R_SEARCH_PATTERN:
		break;
	default:
		ok = false;
		break;
	}
	if (ok) {
		s->mode = mode;
		return true;
	}
	return false;
}

R_API void r_search_begin(RSearch *s) {
	R_RETURN_IF_FAIL (s);
	RListIter *iter;
	RSearchKeyword *kw;
	r_list_foreach (s->kws, iter, kw) {
		kw->count = 0;
		kw->last = 0;
	}
}

// use when the size of the hit does not match the size of the keyword (ie: /a{30}/)
R_IPI int r_search_hit_sz(RSearch *s, RSearchKeyword *kw, ut64 addr, ut32 sz) {
	if (s->align && (addr % s->align)) {
		R_LOG_DEBUG ("0x%08"PFMT64x" unaligned", addr);
		return 1;
	}
	if (kw->align && (addr % kw->align)) {
		R_LOG_DEBUG ("0x%08"PFMT64x" unaligned", addr);
		return 1;
	}
	if (!s->contiguous) {
		if (kw->last && addr == kw->last) {
			kw->count--;
			kw->last = s->bckwrds? addr: addr + sz;
			R_LOG_WARN ("0x%08"PFMT64x" Sequential hit ignored", addr);
			return 1;
		}
	}
	// kw->last is used by string search, the right endpoint of last match (forward search), to honor search.overlap
	kw->last = s->bckwrds? addr: addr + sz;

	bool callback = false;
	int ret;
	if (s->callback) {
		callback = true;
		ret = s->callback (kw, s->user, addr);
	} else if (s->r_callback) {
		callback = true;
		ret = s->r_callback (kw, sz, s->user, addr);
	}
	kw->count++;
	s->nhits++;
	if (callback) {
		// If callback returns 0 or larger than 1, forwards it; otherwise returns 2 if search.maxhits is reached
		if (!ret || ret > 1) {
			return ret;
		}
		if (s->maxhits && s->nhits >= s->maxhits) {
			return 2;
		}
		return 1;
	}
	RSearchHit* hit = R_NEW0 (RSearchHit);
	if (hit) {
		hit->kw = kw;
		hit->addr = addr;
		r_list_append (s->hits, hit);
	}
	return s->maxhits && s->nhits >= s->maxhits? 2: 1;
}

// Returns 2 if search.maxhits is reached, 0 on error, otherwise 1
R_API int r_search_hit_new(RSearch *s, RSearchKeyword *kw, ut64 addr) {
	R_RETURN_VAL_IF_FAIL (s && kw, 0);
	return r_search_hit_sz (s, kw, addr, kw->keyword_length);
}

static inline int get_longest(RSearch *s) {
	if (s->longest > 0) {
		return s->longest;
	}
	RListIter *iter;
	RSearchKeyword *kw;
	r_list_foreach (s->kws, iter, kw) {
		s->longest = R_MAX (s->longest, (int)kw->keyword_length);
	}
	return s->longest;
}

// TODO support search across block boundaries
// Supported search variants: backward, overlap
R_IPI int search_deltakey_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	RListIter *iter;
	int i, j;
	RSearchKeyword *kw;
	RSearchLeftover *left;
	const int old_nhits = s->nhits;

	const int longest = get_longest (s) + 1;
	if (!longest) {
		return 0;
	}
	if (s->data) {
		left = s->data;
		if (left->end != from) {
			left->len = 0;
		}
	} else {
		left = calloc (sizeof (RSearchLeftover) + (size_t)2, (longest - 1));
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
	ut8 *bwbuf = NULL;
	if (s->bckwrds) {
		bwbuf = malloc (len);
		int j = len - 1;
		for (i = 0; i < len; i++, j--) {
			bwbuf[i] = buf[j];
		}
		buf = bwbuf;
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
			if ((ut8)(left->data[i + 1] - left->data[i]) == a[0]) {
				j = 1;
				while (j < kw->keyword_length && (ut8)(left->data[i + j + 1] - left->data[i+j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = r_search_hit_new (s, kw, s->bckwrds ? from - kw->keyword_length - 1 - i + left->len : from + i - left->len);
					kw->last += s->bckwrds ? 0 : 1;
					if (!t) {
						goto error;
					}
					if (t > 1) {
						goto complete;
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
				while (j < kw->keyword_length && (ut8)(buf[i + j + 1] - buf[i + j]) == a[j]) {
					j++;
				}
				if (j == kw->keyword_length) {
					int t = r_search_hit_new (s, kw, s->bckwrds ? from - kw->keyword_length - 1 - i : from + i);
					kw->last += s->bckwrds ? 0 : 1;
					if (!t) {
						goto error;
					}
					if (t > 1) {
						goto complete;
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
complete:
	free (bwbuf);
	return s->nhits - old_nhits;
error:
	free (bwbuf);
	return -1;
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
R_IPI int search_kw_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	RSearchKeyword *kw;
	RListIter *iter;
	RSearchLeftover *left;
	int i;
	const int old_nhits = s->nhits;

	int longest = get_longest (s);
	if (longest <= 0) {
		return 0;
	}
	if (s->data) {
		left = s->data;
		if (left->end != from) {
			left->len = 0;
		}
	} else {
		left = malloc (sizeof (RSearchLeftover) + (size_t)2 * (longest - 1));
		if (!left) {
			return -1;
		}
		s->data = left;
		left->len = 0;
	}
	ut8 *bwbuf = NULL;
	if (s->bckwrds) {
		bwbuf = malloc (len);
		int j = len - 1;
		for (i = 0; i < len; i++, j--) {
			bwbuf[i] = buf[j];
		}
		buf = bwbuf;
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
					goto error;
				}
				if (t > 1) {
					goto complete;
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
					goto error;
				}
				if (t > 1) {
					goto complete;
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
complete:
	free (bwbuf);
	return s->nhits - old_nhits;
error:
	free (bwbuf);
	return -1;
}

R_API void r_search_set_distance(RSearch *s, int dist) {
	if (dist >= R_SEARCH_DISTANCE_MAX) {
		R_LOG_ERROR ("Invalid distance");
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
	s->r_callback = NULL; // prevent user from being passed to wrong function
	s->callback = callback;
	s->user = user;
}

R_API void r_search_set_read_cb(RSearch *s, RSearchRCb cb, void *user) {
	s->callback = NULL; // prevent user from being passed to wrong function
	s->r_callback = cb;
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
	} else {
		R_LOG_ERROR ("Missing r_search_update callback");
	}
	return ret;
}

// like r_search_update but uses s->iob, does not need to loop as much
R_API int r_search_update_read(RSearch *s, ut64 from, ut64 to) {
	R_RETURN_VAL_IF_FAIL (s && s->iob.read_at && s->consb.is_breaked, -1);
	switch (s->mode) {
	case R_SEARCH_PATTERN:
		return search_pattern (s, from, to);
	case R_SEARCH_REGEXP:
		return search_regex_read (s, from, to);
	case R_SEARCH_RABIN_KARP:
		return search_rk (s, from, to);
	case R_SEARCH_TIRE:
		return search_tire (s, from, to);
	case R_SEARCH_STRING:
		R_LOG_TODO ("Not implemented");
		return 0;
	default:
		R_LOG_WARN ("Unsupported search mode");
		return -1;
	}
}

// TODO: show progress
R_API int r_search_maps(RSearch *s, RList *maps) {
	R_RETURN_VAL_IF_FAIL (s && s->consb.is_breaked && maps, -1);
	RListIter *iter;
	RIOMap *m;
	ut64 prevto = UT64_MAX;
	ut64 prevfrom = UT64_MAX;
	int ret = 0;

	r_list_foreach_prev (maps, iter, m) {
		if (s->consb.is_breaked (s->consb.cons)) {
			break;
		}
		ut64 from = r_io_map_begin (m);
		ut64 to = r_io_map_end (m);

		if (prevto == from) { // absorb new search area into previous
			prevto = to;
			continue;
		}
		if (prevto != UT64_MAX && prevfrom != UT64_MAX) {
			// do last search
			int tmp = r_search_update_read (s, prevfrom, prevto);
			if (tmp < 0) {
				return tmp;
			}
			ret += tmp;
		}
		prevto = to;
		prevfrom = from;
	}
	if (prevto != UT64_MAX && prevfrom != UT64_MAX) {
		int tmp = r_search_update_read (s, prevfrom, prevto);
		if (tmp < 0) {
			return tmp;
		}
		ret += tmp;
	}
	return ret;
}

static int listcb(RSearchKeyword *k, void *user, ut64 addr) {
	RSearchHit *hit = R_NEW0 (RSearchHit);
	if (R_LIKELY (hit)) {
		hit->kw = k;
		hit->addr = addr;
		r_list_append (user, hit);
		return 1;
	}
	return 0;
}

R_API RList *r_search_find(RSearch *s, ut64 addr, const ut8 *buf, int len) {
	RList *ret = r_list_new ();
	r_search_set_callback (s, listcb, ret);
	r_search_update (s, addr, buf, len);
	return ret;
}

/* --- keywords --- */
R_API bool r_search_kw_add(RSearch *s, RSearchKeyword *kw) {
	R_RETURN_VAL_IF_FAIL (s && kw, false);
	if (kw->keyword_length < 1) {
		return false;
	}
	s->longest = R_MAX ((int)kw->keyword_length, s->longest);
	kw->kwidx = s->n_kws++;
	r_list_append (s->kws, kw);
	return true;
}

// Reverse bin_keyword & bin_binmask for backward search
R_API void r_search_string_prepare_backward(RSearch *s) {
	R_RETURN_IF_FAIL (s);
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
	R_RETURN_IF_FAIL (s);
	s->nhits = 0;
	if (!r_search_set_mode (s, mode)) {
		R_LOG_ERROR ("Cannot init search for mode %d", mode);
	}
}

R_API void r_search_kw_reset(RSearch *s) {
	R_RETURN_IF_FAIL (s);
	s->longest = -1;
	r_list_purge (s->kws);
	r_list_purge (s->hits);
	if (s->datafree) {
		s->datafree (s->data);
		s->datafree = free;
		s->data = NULL;
	}
}
