/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include "r_search.h"
#include <regex.h>

R_API int r_search_regexp_update(struct r_search_t *s, ut64 from, const ut8 *buf, int len)
{
	struct list_head *pos;
	char *buffer = malloc(len+1);
	char *skipz, *end;
	int count = 0;

	memcpy(buffer, buf, len);
	buffer[len]='\0';

	list_for_each_prev(pos, &s->kws) {
		struct r_search_kw_t *kw = list_entry(pos, struct r_search_kw_t, list);
		int reflags = REG_EXTENDED;
		int ret, delta = 0;
		regmatch_t matches[10];
		regex_t compiled;

		if (strchr(kw->binmask, 'i'))
			reflags |= REG_ICASE;

		if (regcomp(&compiled, kw->keyword, reflags)) {
			fprintf(stderr, "Cannot compile '%s' regexp\n",kw->keyword);
			return -1;
		}
		foo:
		ret = regexec(&compiled, buffer+delta, 1, matches, 0);
		if (ret) {
			return 0;
		} else
		do {
			if (s->callback)
				s->callback(kw, s->user, (ut64)from+matches[0].rm_so+delta);
			else printf("hit%d_%d 0x%08llx ; %s\n",
				count, kw->count, (ut64)(from+matches[0].rm_so),
				buf+matches[0].rm_so+delta);
			delta += matches[0].rm_so+1;
			kw->count++;
			count++;
		} while(!regexec(&compiled, buffer+delta, 1, matches, 0));
		if (delta == 0)
			return 0;

		/* TODO: check if skip 0 works */
		skipz = strchr(buffer, '\0');
		end = buffer+len;
		if (skipz && skipz+1 < end) {
			for(;!*skipz&&end;skipz=skipz+1);
			delta = skipz-buffer;
			if (kw->count>0)
				goto foo;
		}
	}
	return count;
}
