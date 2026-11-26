/* radare - LGPL - Copyright 2008-2025 - pancake */

#include <r_util.h>

// TODO: use r_list instead of list.h
// TODO: redesign this api.. why? :)
// TODO: add tags to ranges

//void (*ranges_new_callback)(struct range_t *r) = NULL;

R_API RRange *r_range_new(void) {
	RRange *r = R_NEW0 (RRange);
	r->count = r->changed = 0;
	r->ranges = r_list_new ();
	if (!r->ranges) {
		r_range_free (r);
		return NULL;
	}
	r->ranges->free = free;
	r->ranges->sorted = true;
	return r;
}

R_API RRange *r_range_free(RRange *r) {
	r_list_purge (r->ranges);
	free (r);
	return NULL;
}

// TODO: optimize by just returning the pointers to the internal foo?
R_API int r_range_get_data(RRange *rgs, ut64 addr, ut8 *buf, int len) {
	RRangeItem *r = r_range_item_get (rgs, addr);
	if (!r) {
		return 0;
	}
	if (r->datalen < len) {
		len = r->datalen;
	}
	memcpy (buf, r->data, len);
	return len;
}

R_API int r_range_set_data(RRange *rgs, ut64 addr, const ut8 *buf, int len) {
	RRangeItem *r = r_range_item_get (rgs, addr);
	if (!r) {
		return 0;
	}
	r->data = (ut8*)malloc (len);
	if (!r->data) {
		return 0;
	}
	r->datalen = len;
	memcpy (r->data, buf, len);
	return 1;
}

RRangeItem *r_range_item_get(RRange *rgs, ut64 addr) {
	RRangeItem *r;
	RListIter *iter;
	r_list_foreach (rgs->ranges, iter, r) {
		if (addr >= r->fr && addr < r->to) {
			return r;
		}
	}
	return NULL;
}

/* returns the sum of all the ranges contained */
// XXX: can be caught while adding/removing elements
R_API ut64 r_range_size(RRange *rgs) {
	ut64 sum = 0;
	RListIter *iter;
	RRangeItem *r;
	r_list_foreach (rgs->ranges, iter, r) {
		sum += r->to - r->fr;
	}
	return sum;
}

R_API RRange *r_range_new_from_string(const char *string) {
	RRange *rgs = r_range_new ();
	r_range_add_from_string (rgs, string);
	return rgs;
}

R_API char *r_range_tostring(RRange *rgs) {
	RStrBuf *sb = r_strbuf_new ("");
	// squash and then walk the thingk
	RListIter *iter;
	RRangeItem *r;
	bool second = false;
	r_list_foreach_prev (rgs->ranges, iter, r) {
		if (second) {
			r_strbuf_append (sb, ",");
		}
		r_strbuf_appendf (sb, "0x%08"PFMT64x"-0x%08"PFMT64x, r->fr, r->to);
		second = true;
	}
	return r_strbuf_drain (sb);
}

typedef bool (*RangeItemCallback)(void *user, ut64 from, ut64 to);

static bool parse_number(char *s, ut64 *n) {
	r_str_trim (s);
	if (!*s) {
		return false;
	}
	const char *err = NULL;
	*n = r_num_math_err (NULL, s, &err);
	return !err;
}

// parse "N,A..B,..." calling cb with inclusive bounds until it returns false
static bool range_parse(const char *str, RangeItemCallback cb, void *user) {
	if (!*str) {
		return true;
	}
	char *s = strdup (str);
	if (!s) {
		return false;
	}
	char *item = s;
	bool ok = true;
	while (ok && item) {
		char *next = strchr (item, ',');
		if (next) {
			*next++ = 0;
		}
		ut64 from, to;
		char *dots = strstr (item, "..");
		if (dots) {
			*dots = 0;
			ok = parse_number (item, &from) && parse_number (dots + 2, &to) && from <= to;
		} else {
			ok = parse_number (item, &from);
			to = from;
		}
		if (ok && !cb (user, from, to)) {
			break;
		}
		item = next;
	}
	free (s);
	return ok;
}

static bool range_add_cb(void *user, ut64 from, ut64 to) {
	r_range_add ((RRange *)user, from, (to == UT64_MAX)? to: to + 1, 1);
	return true;
}

R_API int r_range_add_from_string(RRange *rgs, const char *string) {
	R_RETURN_VAL_IF_FAIL (rgs && string, 0);
	if (!range_parse (string, range_add_cb, rgs)) {
		R_LOG_ERROR ("Invalid range");
	}
	return rgs->changed;
}

typedef struct {
	ut64 addr;
	bool found;
} RangeInContext;

static bool range_in_cb(void *user, ut64 from, ut64 to) {
	RangeInContext *ctx = user;
	ctx->found = ctx->addr >= from && ctx->addr <= to;
	return !ctx->found;
}

R_API bool r_str_range_in(const char *r, ut64 addr) {
	if (!r) {
		return false;
	}
	RangeInContext ctx = { .addr = addr };
	if (!range_parse (r, range_in_cb, &ctx)) {
		R_LOG_ERROR ("Invalid range");
	}
	return ctx.found;
}

typedef struct {
	RStrRangeCallback cb;
	void *user;
} RangeForeachContext;

static bool range_foreach_cb(void *user, ut64 from, ut64 to) {
	RangeForeachContext *ctx = user;
	ut64 i = from;
	do {
		ctx->cb (ctx->user, (int)i);
	} while (i++ < to);
	return true;
}

R_API void r_str_range_foreach(const char *r, RStrRangeCallback cb, void *u) {
	R_RETURN_IF_FAIL (r && cb);
	RangeForeachContext ctx = { cb, u };
	if (!range_parse (r, range_foreach_cb, &ctx)) {
		R_LOG_ERROR ("Invalid range");
	}
}

#if 0
	    update to      new one     update fr   update fr/to  ignore

	   |______|        |___|           |_____|      |____|      |_______|  range_t
	+     |______|   +      |__|   + |___|      + |_________|  +  |__|     fr/to
	  ------------   -----------   -----------  -------------  -----------
	=  |_________|   = |___||__|   = |_______|  = |_________|   |_______|  result
#endif

RRangeItem *r_range_add(RRange *rgs, ut64 fr, ut64 to, int rw) {
	RListIter *iter;
	RRangeItem *r, *ret = NULL;
	int add = 1;

	r_num_minmax_swap (&fr, &to);
	// while ranges arrive in ascending order the list stays sorted and disjoint, so only the tail matters
	RRangeItem *last = r_list_last (rgs->ranges);
	const bool ascending = rgs->ranges->sorted && (!last || fr >= last->to);
	if (ascending && last && fr == last->to) {
		last->to = to;
		return last;
	}
	if (!ascending) {
		rgs->ranges->sorted = false;
		r_list_foreach (rgs->ranges, iter, r) {
			if (r->fr == fr && r->to == to) {
				add = 0;
			} else if (r->fr <= fr && r->fr <= to && r->to >= fr && r->to <= to) {
				r->to = to;
				ret = r;
				add = 0;
			} else if (r->fr >= fr && r->fr <= to && r->to >= fr && r->to >= to) {
				r->fr = fr;
				ret = r;
				add = 0;
			} else if (r->fr <= fr && r->fr <= to && r->to >= fr && r->to >= to) {
				/* ignore */
				add = 0;
			} else if (r->fr >= fr && r->fr <= to && r->to >= fr && r->to <= to) {
				r->fr = fr;
				r->to = to;
				ret = r;
				add = 0;
			}
		}
	}

	if (rw && add) {
		ret = R_NEW (RRangeItem);
		ret->fr = fr;
		ret->to = to;
		ret->datalen = 0;
		ret->data = NULL;
		r_list_append (rgs->ranges, ret);
		rgs->ranges->sorted = ascending;
		rgs->changed = 1;
	}

	return ret;
}

#if 0
	    update to      ignore      update fr      delete        split

	   |______|        |___|           |_____|      |____|       |________|  range_t
	-     |______|   -      |__|   - |___|      - |_________|  -    |__|     fr/to
	  ------------   -----------   -----------  -------------  ------------
	=  |__|          =             =     |___|  =                |__|  |__|   result
#endif

R_API int r_range_sub(RRange *rgs, ut64 fr, ut64 to) {
	RRangeItem *r;
	RListIter *iter;

	r_num_minmax_swap (&fr, &to);

	__reloop:
	r_list_foreach (rgs->ranges, iter, r) {
		/* update to */
		if (r->fr < fr && r->fr < to && r->to > fr && r->to < to) {
			r->to = fr;
		} else if (r->fr > fr && r->fr < to && r->to > fr && r->to > to) {
			/* update fr */
			r->fr = to;
		}
		/* delete */
		if (r->fr > fr && r->fr < to && r->to > fr && r->to < to) {
			/* delete */
			r_list_delete (rgs->ranges, iter);
			rgs->changed = 1;
			goto __reloop;
		}
		/* split */
		if (r->fr < fr && r->fr < to && r->to > fr && r->to > to) {
			r->to = fr;
			r_range_add (rgs, to, r->to, 1);
			//ranges_add(rang, to, r->to, 1);
			goto __reloop;
		}
	}
	return 0;
}

#if 0
/* TODO: should remove some of them right? */
R_API void r_range_merge(RRange *rgs, RRange *r) {
	RListIter *iter;
	RRangeItem *r;
	r_list_foreach (rgs->ranges, iter, r)
		r_range_add (rgs, r->fr, r->to, 0);
}
#endif

//int ranges_is_used(ut64 addr)
R_API int r_range_contains(RRange *rgs, ut64 addr) {
	RRangeItem *r;
	RListIter *iter;
	r_list_foreach (rgs->ranges, iter, r) {
		if (addr >= r->fr && addr <= r->to) {
			return true;
		}
	}
	return false;
}

static int cmp_ranges(void *a, void *b) {
	RRangeItem *first = (RRangeItem *)a;
	RRangeItem *second = (RRangeItem *)b;
	return (first->fr > second->fr) - (first->fr < second->fr);
}

R_API int r_range_sort(RRange *rgs) {
	bool ch = rgs->ranges->sorted;
	if (!rgs->changed) {
		return false;
	}
	rgs->changed = false;
	r_list_sort (rgs->ranges, (RListComparator)cmp_ranges);
	if (ch != rgs->ranges->sorted) {
		rgs->changed = true;
	}
	return rgs->changed;
}

R_API void r_range_percent(RRange *rgs) {
	RListIter *iter;
	RRangeItem *r;
	int w, i;
	ut64 seek, step;
	ut64 dif, fr = -1, to = -1;

	r_list_foreach (rgs->ranges, iter, r) {
		if (fr == -1) {
			/* init */
			fr = r->fr;
			to = r->to;
		} else {
			if (fr > r->fr) {
				fr = r->fr;
			}
			if (to < r->to) {
				to = r->to;
			}
		}
	}
	w = 65 ; // columns
	if (fr != -1) {
		dif = to - fr;
		if (dif < w) {
			step = 1; // XXX
		} else {
			step = dif / w;
		}
	} else {
		step = fr = to = 0;
	}
	seek = 0;
	// XXX do not use printf here!
	printf ("0x%08"PFMT64x" [", fr);
	for (i = 0; i < w; i++) {
		if (r_range_contains (rgs, seek)) {
			printf ("#");
		} else {
			printf (".");
		}
		seek += step;
	}
	printf ("] 0x%08"PFMT64x"\n", to);
}

// TODO: total can be cached in rgs!!
int r_range_list(RRange *rgs, int rad) {
	ut64 total = 0;
	RRangeItem *r;
	RListIter *iter;
	r_range_sort (rgs);
	r_list_foreach (rgs->ranges, iter, r) {
		if (rad) {
			printf ("ar+ 0x%08"PFMT64x" 0x%08"PFMT64x"\n", r->fr, r->to);
		} else {
			printf ("0x%08"PFMT64x" 0x%08"PFMT64x" ; %"PFMT64d"\n", r->fr, r->to, r->to - r->fr);
		}
		total += (r->to - r->fr);
	}
	eprintf ("Total bytes: %"PFMT64d"\n", total);
	return 0;
}

int r_range_get_n(RRange *rgs, int n, ut64 *fr, ut64 *to) {
	int count = 0;
	RRangeItem *r;
	RListIter *iter;
	r_range_sort (rgs);
	r_list_foreach (rgs->ranges, iter, r) {
		if  (count == n) {
			*fr = r->fr;
			*to = r->to;
			return 1;
		}
		count++;
	}
	return 0;
}

#if 0
	 .....|______________________|...
	  |_____|  |____|  |_______|
	---------------------------------
		|__|    |__|       |_|
#endif
RRange *r_range_inverse(RRange *rgs, ut64 fr, ut64 to, int flags) {
	// ut64 total = 0;
	RListIter *iter;
	RRangeItem *r = NULL;
	RRange *newrgs = r_range_new();

	r_range_sort(rgs);

	r_list_foreach (rgs->ranges, iter, r) {
		if (r->fr > fr && r->fr < to) {
			r_range_add (newrgs, fr, r->fr, 1);
			//eprintf("0x%08"PFMT64x" .. 0x%08"PFMT64x"\n", fr, r->fr);
	//		total += (r->fr - fr);
			fr = r->to;
		}
	}
	if (fr < to) {
		//eprintf("0x%08"PFMT64x" .. 0x%08"PFMT64x"\n", fr, to);
		r_range_add (newrgs, fr, to, 1);
//		total += (to - fr);
	}
	// eprintf("Total bytes: %"PFMT64d"\n", total);
	return newrgs;
}

/*
	return true if overlap
	in *d
*/
// TODO: move to num.c ?
R_API int r_range_overlap(ut64 a0, ut64 a1, ut64 b0, ut64 b1, int *d) {
	// does not overlap
	// a  |__|           |__|
	// b      |__|   |__|
	//
	// a     |____|   |_____|  |____|     |_____|
	// b  |____|        |_|       |____| |_______|
	//      b needs    a needs   a needs   b needs
	// delta required
	return *d = (b0 - a0), R_INBETWEEN (a0, a1, b0, b1);
}
