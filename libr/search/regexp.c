/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> */

#include "r_search.h"
#include <r_regex.h>

R_API int r_search_regexp_update(void *_s, ut64 from, const ut8 *buf, size_t len) {
	RSearch *s = (RSearch*)_s;
	RListIter *iter;
	char *buffer = malloc (len+1);
	unsigned int count = 0;

	memcpy (buffer, buf, len);
	buffer[len]='\0';

	RSearchKeyword *kw;
	r_list_foreach (s->kws, iter, kw) {
        char *skipz, *end;
		int reflags = R_REGEX_EXTENDED;
		int ret, delta = 0;
		RRegexMatch matches[10];
		RRegex compiled;

		if (strchr (kw->binmask, 'i'))
			reflags |= R_REGEX_ICASE;

		if (r_regex_comp (&compiled, kw->keyword, reflags)) {
			eprintf ("Cannot compile '%s' regexp\n",kw->keyword);
            free(buffer);
			return -1;
		}
		foo:
		ret = r_regex_exec (&compiled, buffer+delta, 1, matches, 0);
		if (ret){
            free(buffer);
            return 0;
        }
		do {
			r_search_hit_new (s, kw, (ut64)(from+matches[0].rm_so+delta));
			delta += matches[0].rm_so+1;
			kw->count++;
			count++;
		} while (!r_regex_exec (&compiled, buffer+delta, 1, matches, 0));
		if (delta == 0){
            free(buffer);
			return 0;
        }

		/* TODO: check if skip 0 works */
		skipz = strchr (buffer, '\0');
		end = buffer+len;
		if (skipz && skipz+1 < end) {
			for (; !*skipz && end; skipz++);
			delta = skipz - buffer;
			if (kw->count > 0)
				goto foo;
		}
	}
    free(buffer);
	return count;
}
