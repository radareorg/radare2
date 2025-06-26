#ifndef R_CONS_PRIVATE_H
#define R_CONS_PRIVATE_H

#include <r_util.h>

R_IPI void pager_color_line(RCons *cons, const char *line, RStrpool *p, RList *ml);
R_IPI void pager_printpage(RCons *cons, const char *line, int *index, RList **mla, int from, int to, int w);
R_IPI int pager_next_match(int from, RList **mla, int lcount);
R_IPI int pager_prev_match(int from, RList **mla);
R_IPI bool pager_all_matches(const char *s, RRegex *rx, RList **mla, int *lines, int lcount);
R_IPI int *pager_splitlines(char *s, int *lines_count);
R_IPI void pal_clone(RConsContext *ctx);

static inline void __cons_write_ll(RCons *cons, const char *buf, int len) {
#if R2__WINDOWS__
	if (cons->vtmode) {
		(void) write (cons->fdout, buf, len);
	} else {
		if (cons->fdout == 1) {
			r_cons_win_print (cons, buf, len, false);
		} else {
			R_IGNORE_RETURN (write (cons->fdout, buf, len));
		}
	}
#else
	if (cons->fdout < 1) {
		cons->fdout = 1;
	}
	R_IGNORE_RETURN (write (cons->fdout, buf, len));
#endif
}

static inline void __cons_write(RCons *cons, const char *obuf, int olen) {
	const size_t bucket = 64 * 1024;
	size_t i;
	if (olen < 0) {
		olen = strlen (obuf);
	}
	for (i = 0; (i + bucket) < olen; i += bucket) {
		__cons_write_ll (cons, obuf + i, bucket);
	}
	if (i < olen) {
		__cons_write_ll (cons, obuf + i, olen - i);
	}
}

#endif
