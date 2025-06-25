/* radare2 - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>
#include <r_util/r_time.h>
#include "private.h"

static int real_strlen(const char *ptr, int len) {
	int utf8len = r_str_len_utf8 (ptr);
	int ansilen = r_str_ansi_len (ptr);
	int diff = len - utf8len;
	if (diff > 0) {
		diff--;
	}
	return ansilen - diff;
}

static void print_fps(RCons *cons, int col) {
	int fps = 0, w = r_cons_get_size (NULL);
	fps = 0;
	if (cons->prev) {
		ut64 now = r_time_now_mono ();
		st64 diff = (st64)(now - cons->prev);
		if (diff <= 0) {
			fps = 0;
		} else {
			fps = (diff < 1000000)? (int)(1000000.0 / diff): 0;
		}
		cons->prev = now;
	} else {
		cons->prev = r_time_now_mono ();
	}
	if (col < 1) {
		col = 12;
	}
#ifdef R2__WINDOWS__
	if (cons->vtmode) {
		eprintf ("\x1b[0;%dH[%d FPS] \n", w - col, fps);
	} else {
		r_cons_win_gotoxy (cons, 2, w - col, 0);
		eprintf (" [%d FPS] \n", fps);
	}
#else
	eprintf ("\x1b[0;%dH[%d FPS] \n", w - col, fps);
#endif
}

R_API void r_cons_visual_write(RCons *cons, char *buffer) {
	char white[1024];
	int cols = cons->columns;
	int alen, plen, lines = cons->rows;
	bool break_lines = cons->break_lines;
	const char *endptr;
	char *nl, *ptr = buffer, *pptr;

	if (cons->null) {
		return;
	}
	memset (&white, ' ', sizeof (white));
	while ((nl = strchr (ptr, '\n'))) {
		int len = ((int)(size_t)(nl - ptr)) + 1;
		int lines_needed = 0;

		*nl = 0;
		alen = real_strlen (ptr, len);
		*nl = '\n';
		pptr = ptr > buffer ? ptr - 1 : ptr;
		plen = ptr > buffer ? len : len - 1;

		if (break_lines) {
			lines_needed = alen / cols + (alen % cols == 0 ? 0 : 1);
		}
		if ((break_lines && lines < lines_needed && lines > 0)
		    || (!break_lines && alen > cols)) {
			int olen = len;
			endptr = r_str_ansi_chrn (ptr, (break_lines ? cols * lines : cols) + 1);
			endptr++;
			len = endptr - ptr;
			plen = ptr > buffer ? len : len - 1;
			if (lines > 0) {
				__cons_write (cons, pptr, plen);
				if (len != olen) {
					__cons_write (cons, R_CONS_CLEAR_FROM_CURSOR_TO_END, -1);
					__cons_write (cons, Color_RESET, strlen (Color_RESET));
				}
			}
		} else {
			if (lines > 0) {
				int w = cols - (alen % cols == 0 ? cols : alen % cols);
				__cons_write (cons, pptr, plen);
				if (cons->blankline && w > 0) {
					__cons_write (cons, white, R_MIN (w, sizeof (white)));
				}
			}
			// TRICK to empty columns.. maybe buggy in w32
			if (r_mem_mem ((const ut8*)ptr, len, (const ut8*)"\x1b[0;0H", 6)) {
				lines = cons->rows;
				__cons_write (cons, pptr, plen);
			}
		}
		if (break_lines) {
			lines -= lines_needed;
		} else {
			lines--; // do not use last line
		}
		ptr = nl + 1;
	}
	/* fill the rest of screen */
	if (lines > 0) {
		while (--lines >= 0) {
			__cons_write (cons, white, R_MIN (cols, sizeof (white)));
		}
	}
}

R_API void r_cons_visual_flush(RCons *cons) {
	RConsContext *ctx = cons->context;
	if (ctx->noflush) {
		return;
	}
	r_kons_highlight (cons, cons->highlight);
	if (!cons->null) {
/* TODO: this ifdef must go in the function body */
#if R2__WINDOWS__
		if (cons->vtmode) {
			r_kons_visual_write (cons, ctx->buffer);
		} else {
			r_cons_win_print (cons, ctx->buffer, ctx->buffer_len, true);
		}
#else
		r_cons_visual_write (cons, ctx->buffer);
#endif
	}
	r_kons_reset (cons);
	if (cons->fps) {
		print_fps (cons, 0);
	}
}

