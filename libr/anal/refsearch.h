#ifndef R2_REFSEARCH_H
#define R2_REFSEARCH_H

#include <sdb/ht_uu.h>

typedef struct {
	ut64 from;
	ut64 to;
} RefSearchRange;

R_VEC_TYPE (RVecRefSearchRange, RefSearchRange);
R_VEC_TYPE (RVecRefSearchAddr, ut64);

typedef struct {
	PJ *json;
	RStrBuf *text;
	RVecRefSearchRange ranges;
	RVecRefSearchAddr destinations;
	HtUU *seen;
	ut64 hits;
	ut64 maxhits;
	bool failed;
} RefSearch;

static inline bool refsearch_parse_range(RNum *num, char *arg, RefSearchRange *range) {
	char *dots = strstr (arg, "..");
	const char *err = NULL;
	if (dots) {
		*dots = 0;
	}
	range->from = r_num_math_err (num, arg, &err);
	const bool valid = *r_str_trim_head_ro (arg) && !err;
	range->to = range->from;
	if (dots) {
		*dots = '.';
		if (!valid || !*r_str_trim_head_ro (dots + 2)) {
			return false;
		}
		range->to = r_num_math_err (num, dots + 2, &err);
	}
	return valid && !err && range->from <= range->to;
}

static inline bool refsearch_stopped(const RefSearch *search) {
	return search->failed || (search->maxhits && search->hits >= search->maxhits);
}

static inline bool refsearch_add_range(RVecRefSearchRange *ranges, const RefSearchRange range) {
	RefSearchRange *slot = RVecRefSearchRange_emplace_back (ranges);
	if (!slot) {
		return false;
	}
	*slot = range;
	return true;
}

static inline int refsearch_range_cmp(const RefSearchRange *a, const RefSearchRange *b) {
	return (a->from > b->from) - (a->from < b->from);
}

static inline void refsearch_ranges_sort(RVecRefSearchRange *ranges) {
	if (RVecRefSearchRange_empty (ranges)) {
		return;
	}
	RVecRefSearchRange_sort (ranges, refsearch_range_cmp);
	RefSearchRange *last = R_VEC_START_ITER (ranges);
	RefSearchRange *cur;
	R_VEC_FOREACH (ranges, cur) {
		if (cur->from <= last->to) {
			last->to = R_MAX (last->to, cur->to);
		} else {
			last++;
			*last = *cur;
		}
	}
	RVecRefSearchRange_erase_back (ranges, last + 1);
}

static inline int refsearch_target_cmp(const void *key, const void *item) {
	const ut64 addr = *(const ut64 *)key;
	const RefSearchRange *range = item;
	return addr < range->from? -1: addr > range->to;
}

static inline bool refsearch_matches(const RefSearch *search, ut64 addr) {
	const RVecRefSearchRange *ranges = &search->ranges;
	const size_t count = RVecRefSearchRange_length (ranges);
	return addr != UT64_MAX && (!count
		|| bsearch (&addr, R_VEC_START_ITER (ranges), count, sizeof (RefSearchRange), refsearch_target_cmp));
}

static inline int refsearch_addr_cmp(const ut64 *a, const ut64 *b) {
	return (*a > *b) - (*a < *b);
}

static inline bool refsearch_emit(RefSearch *search, ut64 from, ut64 to, RAnalRefType type) {
	if (refsearch_stopped (search) || !refsearch_matches (search, to)) {
		return false;
	}
	if (search->seen) {
		if (ht_uu_find (search->seen, to, NULL)) {
			return false;
		}
		if (!ht_uu_insert (search->seen, to, 1)) {
			search->failed = true;
			return false;
		}
		ut64 *slot = RVecRefSearchAddr_emplace_back (&search->destinations);
		if (!slot) {
			search->failed = true;
			return false;
		}
		*slot = to;
	} else if (search->json) {
		pj_o (search->json);
		pj_kn (search->json, "from", from);
		pj_kn (search->json, "target", to);
		pj_ks (search->json, "type", r_anal_ref_type_tostring (type));
		pj_end (search->json);
	} else {
		r_strbuf_appendf (search->text, "0x%"PFMT64x" -> 0x%"PFMT64x" %s\n",
			from, to, r_anal_ref_type_tostring (type));
	}
	search->hits++;
	return true;
}

static inline void refsearch_finish(RefSearch *search) {
	RVecRefSearchAddr_sort (&search->destinations, refsearch_addr_cmp);
	ut64 *addr;
	R_VEC_FOREACH (&search->destinations, addr) {
		if (search->json) {
			pj_n (search->json, *addr);
		} else {
			r_strbuf_appendf (search->text, "0x%"PFMT64x"\n", *addr);
		}
	}
	if (search->json) {
		pj_end (search->json);
	}
	ht_uu_free (search->seen);
	RVecRefSearchAddr_fini (&search->destinations);
	RVecRefSearchRange_fini (&search->ranges);
}

#endif
