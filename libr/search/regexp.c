/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> */

#include "r_search.h"
#include <r_regex.h>

R_API int r_search_regexp_update(void *_s, ut64 from, const ut8 *buf, int len) {
	RSearch *s = (RSearch*)_s;
	RSearchKeyword *kw;
	RListIter *iter;
	int count = 0, pos;
	RRegexMatch match;
	RRegex compiled;

	r_list_foreach (s->kws, iter, kw) {
		int reflags = R_REGEX_EXTENDED;

		if (kw->icase)
			reflags |= R_REGEX_ICASE;

		if (r_regex_comp (&compiled, (char *)kw->bin_keyword, reflags)) {
			eprintf ("Cannot compile '%s' regexp\n", kw->bin_keyword);
			return -1;
		}

		match.rm_so = 0;
		match.rm_eo = len;

		pos = 0;
		while (!r_regex_exec (&compiled, (char *)buf+pos, 1, &match, R_REGEX_STARTEND)) {
			r_search_hit_new (s, kw, (ut64)(from+pos+match.rm_so));
			pos += (match.rm_eo - match.rm_so);
			count++;
			kw->count++;
		} 
	}

	return count;
}
