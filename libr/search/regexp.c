/* radare - LGPL - Copyright 2008-2020 - pancake, TheLemonMan */

#include "r_search.h"
#include <r_regex.h>

R_API int r_search_regexp_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
	RSearchKeyword *kw;
	RListIter *iter;
	RRegexMatch match;
	RRegex rx = {0};
	const int old_nhits = s->nhits;
	int ret = 0;

	r_list_foreach (s->kws, iter, kw) {
		int reflags = R_REGEX_EXTENDED;

		if (kw->icase) {
			reflags |= R_REGEX_ICASE;
		}

		if (r_regex_init (&rx, (char *)kw->bin_keyword, reflags)) {
			eprintf ("Cannot compile '%s' regexp\n", kw->bin_keyword);
			return -1;
		}

		match.rm_so = 0;
		match.rm_eo = len;

		while (!r_regex_exec (&rx, (char *)buf, 1, &match, R_REGEX_STARTEND)) {
			int t = r_search_hit_new (s, kw, from + match.rm_so);
			if (!t) {
				ret = -1;
				goto beach;
			}
			if (t > 1) {
				goto beach;
			}
			/* Setup the boundaries for R_REGEX_STARTEND */
			match.rm_so = match.rm_eo;
			match.rm_eo = len;
		}
	}

beach:
	r_regex_fini (&rx);
	if (!ret) {
		ret = s->nhits - old_nhits;
	}
	return ret;
}
