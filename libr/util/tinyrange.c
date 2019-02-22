/* radare2 - LGPL - Copyright 2016 - alvarofe */

#include <r_util.h>

R_API RRangeTiny *r_tinyrange_new() {
	RRangeTiny *res = R_NEW (RRangeTiny);
	r_tinyrange_init (res);
	return res;
}

R_API void r_tinyrange_init(RRangeTiny *bbr) {
	bbr->count = 0;
	bbr->pairs = 0;
	bbr->ranges = NULL;
	bbr->min_value = UT64_MAX;
	bbr->max_value = 0;
}

R_API void r_tinyrange_fini(RRangeTiny *bbr) {
	bbr->count = 0;
	bbr->pairs = 0;
	R_FREE (bbr->ranges);
}

R_API void r_tinyrange_free(RRangeTiny *bbr) {
	r_tinyrange_fini (bbr);
	free (bbr);
}

//bool value if true return bb->addr otherwise a boolean to notify was found
R_API bool r_tinyrange_in(RRangeTiny *bbr, ut64 at) {
	if (bbr->pairs > 0) {
		int idx, lastIndex = ((bbr->pairs - 1) * 2);
		if (at < bbr->ranges[0]) {
			return false;
		}
		if (at > bbr->ranges[lastIndex + 1]) {
			return false;
		}
		idx = lastIndex / 2;
		if (idx % 2) {
			idx--;
		}
		while (idx <= lastIndex + 1 && idx >= 0) {
			if (at >= bbr->ranges[idx] && at < bbr->ranges[idx + 1]) {
				return true;
			} 
			if (idx >= lastIndex) {
				return false;
			}
			if (at < bbr->ranges[idx]) {
				lastIndex = idx;
				idx -= (idx / 2);
				if (idx % 2) {
					idx--;
				}
			} else {
				idx += ((lastIndex - idx) / 2);
				if (idx % 2) {
					idx++;
				}
			}
		}
	}
	return false;
}

/* must be always called in a sorted way */
R_API bool r_tinyrange_add(RRangeTiny *bbr, ut64 from, ut64 to) {
	if (from >= to) {
		return false;
	}
	if (bbr->pairs > 0) {
		int idx = (bbr->pairs - 1) * 2;
		if (from == bbr->ranges[idx + 1]) {
			bbr->ranges[idx + 1] = to;
		} else {
			bbr->pairs++;
			idx += 2;
			void *ranges = realloc (bbr->ranges, sizeof (ut64) * bbr->pairs * 2);
			if (!ranges) {
				bbr->pairs--;
				return false;
			}
			bbr->ranges = ranges;
			bbr->ranges[idx] = from;
			bbr->ranges[idx + 1] = to;
		}
	} else {
		bbr->pairs = 1;
		bbr->ranges = calloc (sizeof (ut64), 2);
		bbr->ranges[0] = from;
		bbr->ranges[1] = to;
	}
	bbr->count++;
	if (bbr->min_value > from) {
		bbr->min_value = from;
	}
	if (bbr->max_value < to) {
		bbr->max_value = to;
	}
	return true;
}
