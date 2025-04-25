/* radare - LGPL - Copyright 2008-2020 - pancake, TheLemonMan */

#include "r_search.h"
#include "search.h"
#include <r_regex.h>

R_IPI int search_regex_read(RSearch *s, ut64 from, ut64 to) {
	RSearchKeyword *kw;
	RListIter *iter;
	RRegexMatch match;
	RRegex rx = {0};
	const int old_nhits = s->nhits;
	int ret = 0;

	ut64 buflen = 0x1000;
	ut8 *buf = malloc (buflen);
	if (!buf) {
		return -1;
	}

	r_list_foreach (s->kws, iter, kw) {
		ut64 addr = from;
		int reflags = R_REGEX_EXTENDED;

		if (kw->icase) {
			reflags |= R_REGEX_ICASE;
		}

		if (r_regex_init (&rx, (char *)kw->bin_keyword, reflags)) {
			R_LOG_ERROR ("Cannot compile '%s' regexp", kw->bin_keyword);
			ret = -1;
			goto beach;
		}

		// TODO: allow user to configure according to the maximum expected
		// match length to prevent FN on matches that span boundaries.
		while (addr < to) { // get buffer
			if (s->consb.is_breaked (s->consb.cons)) {
				goto beach;
			}

			int len = R_MIN (to - addr, buflen);
			if (!s->iob.read_at (s->iob.io, addr, buf, len)) {
				ret = -1; // failed to read
				goto beach;
			}

			match.rm_so = 0;
			match.rm_eo = len;
			int m = r_regex_exec (&rx, (char *)buf, 1, &match, R_REGEX_STARTEND);
			if (!m) { // match
				ut32 mtch_len = match.rm_eo - match.rm_so;
				if (match.rm_eo < match.rm_so || !mtch_len) {
					// <= zero length match (ie /a*/ matches everything)
					ret = -1;
					goto beach;
				}

				// match extends to end of this buffer, but maybe even further?, so try again at match start
				if (match.rm_eo == len && !match.rm_so && mtch_len < len) {
					addr += match.rm_so;
					continue;
				}
				int t = r_search_hit_sz (s, kw, addr + match.rm_so, mtch_len);
				if (!t) {
					ret = -1;
					goto beach;
				}
				if (t > 1) { // max matches reached
					goto beach;
				}
				// adjust where buffer starts next loop
				if (s->overlap) {
					addr += match.rm_so + 1;
				} else {
					addr += match.rm_eo;
				}
			} else if (m == R_REGEX_NOMATCH) {
				// if a match exists accross buffer boundary, this will still
				// find it, unless start of match is withen first 7/8th of buffer
				addr += buflen - (buflen / 8);
			} else { // regex error
				ret = -1;
				goto beach;
			}
		}
	}

beach:
	r_regex_fini (&rx);
	free (buf);
	if (!ret) {
		ret = s->nhits - old_nhits;
	}
	return ret;
}

R_IPI int search_regexp_update(RSearch *s, ut64 from, const ut8 *buf, int len) {
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
			R_LOG_ERROR ("Cannot compile '%s' regexp", kw->bin_keyword);
			return -1;
		}

		match.rm_so = 0;
		match.rm_eo = len;

		while (!r_regex_exec (&rx, (char *)buf, 1, &match, R_REGEX_STARTEND)) {
			if (match.rm_eo <= match.rm_so) {
				// empty match
				match.rm_so++;
				match.rm_eo = len;
				continue;
			}
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
