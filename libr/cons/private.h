#ifndef R_CONS_PRIVATE_H
#define R_CONS_PRIVATE_H

#include <r_util.h>

R_IPI void pager_color_line(RCons *cons, const char *line, RStrBuf *p, RList *ml);
R_IPI void pager_printpage(RCons *cons, const char *line, int *index, RList **mla, int from, int to, int w);
R_IPI int pager_next_match(int from, RList **mla, int lcount);
R_IPI int pager_prev_match(int from, RList **mla);
R_IPI bool pager_all_matches(const char *s, RRegex *rx, RList **mla, int *lines, int lcount);
R_IPI int *pager_splitlines(char *s, int *lines_count);
R_IPI void pal_clone(RConsContext *ctx);

typedef struct r_cons_canvas_attrs_t RConsCanvasAttrs;
R_IPI RConsCanvasAttrs *canvas_attrs_new(void);
R_IPI void canvas_attrs_free(RConsCanvasAttrs *a);
R_IPI void canvas_attrs_clear(RConsCanvasAttrs *a, bool release);
R_IPI void canvas_attrs_set(RConsCanvasAttrs *a, ut64 loc, const char *style);
R_IPI const char *canvas_attrs_get(const RConsCanvasAttrs *a, ut64 loc);
R_IPI ut64 canvas_attrs_size(const RConsCanvasAttrs *a);

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

static inline void __cons_write(RCons *cons, const char *obuf, size_t olen) {
	const size_t bucket = 64 * 1024;
	size_t i;
	for (i = 0; olen - i > bucket; i += bucket) {
		__cons_write_ll (cons, obuf + i, (int)bucket);
	}
	if (i < olen) {
		__cons_write_ll (cons, obuf + i, (int)(olen - i));
	}
}

#endif
