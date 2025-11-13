/* radare2 - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>
#include <r_util/r_time.h>
#include "private.h"

static void print_fps(RCons *cons, int col) {
	int fps = 0, w = r_cons_get_size (cons, NULL);
	ut64 now = r_time_now_mono ();
	if (cons->prev) {
		st64 diff = (st64)(now - cons->prev);
		if (diff <= 0) {
			fps = 0;
		} else {
			fps = (diff < 1000000)? (int)(1000000.0 / diff): 0;
		}
	}
	cons->prev = now;
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
	int cols = cons->columns;
	int alen, plen, lines = cons->rows;
	bool break_lines = cons->break_lines;
	const char *endptr;
	char *nl, *ptr = buffer, *pptr;
	char *white = NULL;
	int white_len = 0;

	if (cons->null) {
		return;
	}
	if (cols > 0) {
		white = r_str_pad2 (NULL, 0, ' ', cols);
		if (white) {
			white_len = cols;
		}
	}
	while ((nl = strchr (ptr, '\n'))) {
		int len = ((int)(size_t)(nl - ptr)) + 1;
		int lines_needed = 0;
		bool line_wraps = false;

		*nl = 0;
		alen = r_str_display_width (ptr);
		*nl = '\n';
		pptr = ptr > buffer ? ptr - 1 : ptr;
		plen = ptr > buffer ? len : len - 1;

		if (break_lines) {
			lines_needed = alen / cols + (alen % cols == 0 ? 0 : 1);
			line_wraps = lines_needed > 1;
		} else {
			line_wraps = alen > cols;
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
					__cons_write (cons, R_CONS_CLEAR_FROM_CURSOR_TO_END Color_RESET, -1);
				}
			}
		} else {
			if (lines > 0 && cols > 0) {
				int w = cols - (alen % cols == 0 ? cols : alen % cols);
				__cons_write (cons, pptr, plen);
				if (!line_wraps && cons->blankline && w > 0 && white) {
					__cons_write (cons, white, R_MIN (w, white_len));
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
	if (white && lines > 0) {
		while (--lines >= 0) {
			__cons_write (cons, white, R_MIN (cols, white_len));
		}
	}
	free (white);
}

R_API void r_cons_visual_flush(RCons *cons) {
	RConsContext *ctx = cons->context;
	if (ctx->noflush) {
		return;
	}
	r_cons_highlight (cons, cons->highlight);
	if (!cons->null) {
/* TODO: this ifdef must go in the function body */
#if R2__WINDOWS__
		if (cons->vtmode) {
			r_cons_visual_write (cons, ctx->buffer);
		} else {
			r_cons_win_print (cons, ctx->buffer, ctx->buffer_len, true);
		}
#else
		r_cons_visual_write (cons, ctx->buffer);
#endif
	}
	r_cons_reset (cons);
	if (cons->fps) {
		print_fps (cons, 0);
	}
}
