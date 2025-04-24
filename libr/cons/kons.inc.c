/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_cons.h>

static int kons_chop(RCons *cons, int len) {
	RConsContext *ctx = cons->context;
	if (ctx->buffer_limit > 0) {
		if (ctx->buffer_len + len >= ctx->buffer_limit) {
			if (ctx->buffer_len >= ctx->buffer_limit) {
				ctx->breaked = true;
				return 0;
			}
			return ctx->buffer_limit - ctx->buffer_len;
		}
	}
	return len;
}

#define MOAR (4096 * 8)
static bool kons_palloc(RCons *cons, size_t moar) {
	RConsContext *C = cons->context;
	if (moar == 0 || moar > INT_MAX) {
		return false;
	}
	if (!C->buffer) {
		if (moar > SIZE_MAX - MOAR) {
			return false;
		}
		size_t new_sz = moar + MOAR;
		void *temp = calloc (1, new_sz);
		if (temp) {
			C->buffer_sz = new_sz; // Maintain int for C->buffer_sz
			C->buffer = temp;
			C->buffer[0] = '\0';
		} else {
			return false;
		}
	} else if (moar + C->buffer_len > C->buffer_sz) {
		size_t old_buffer_sz = C->buffer_sz;
		size_t new_sz = old_buffer_sz * 2; // Exponential growth
		if (new_sz < old_buffer_sz || new_sz < moar + C->buffer_len) {
			new_sz = moar + C->buffer_len + MOAR; // Ensure enough space
		}
		if (new_sz < old_buffer_sz) { // Check for overflow
			return false;
		}
		void *new_buffer = realloc (C->buffer, new_sz);
		if (new_buffer) {
			C->buffer = new_buffer;
			C->buffer_sz = (int)new_sz; // Maintain int for C->buffer_sz
		} else {
			C->buffer_sz = (int)old_buffer_sz; // Restore on failure
			return false;
		}
	}
	return true;
}

R_API void r_kons_println(RCons *cons, const char* str) {
	r_kons_print (cons, str);
	r_kons_newline (cons);
}

R_API void r_kons_print(RCons *cons, const char *str) {
	R_RETURN_IF_FAIL (str);
	if (!cons || cons->null) {
		return;
	}
	size_t len = strlen (str);
	if (len > 0) {
		r_kons_write (cons, str, len);
	}
}

R_API void r_kons_newline(RCons *cons) {
	if (!cons->null) {
		r_kons_print (cons, "\n");
	}
#if 0
This place is wrong to manage the color reset, can interfire with r2pipe output sending resetchars
and break json output appending extra chars.
this code now is managed into output.c:118 at function r_cons_w32_print
now the console color is reset with each \n (same stuff do it here but in correct place ... i think)

#if R2__WINDOWS__
	r_cons_reset_colors();
#else
	r_cons_print (Color_RESET_ALL"\n");
#endif
	if (cons->is_html) r_cons_print ("<br />\n");
#endif
}

R_API int r_kons_write(RCons *cons, const char *str, int len) {
	R_RETURN_VAL_IF_FAIL (str && len >= 0, -1);
	RConsContext *ctx = cons->context;
	if (len < 1 || ctx->breaked) {
		return 0;
	}

	if (cons->echo) {
		// Here to silent pedantic meson flags ...
		int rlen = write (2, str, len);
		if (rlen != len) {
			return rlen;
		}
	}
	if (str && len > 0 && !cons->null) {
		R_CRITICAL_ENTER (cons);
		if (kons_palloc (cons, len + 1)) {
			if ((len = kons_chop (cons, len)) < 1) {
				R_CRITICAL_LEAVE (cons);
				return 0;
			}
			memcpy (ctx->buffer + ctx->buffer_len, str, len);
			ctx->buffer_len += len;
			ctx->buffer[ctx->buffer_len] = 0;
		}
		R_CRITICAL_LEAVE (cons);
	}
	if (ctx->flush) {
		r_cons_flush ();
	}
	if (cons->break_word && str && len > 0) {
		if (r_mem_mem ((const ut8*)str, len, (const ut8*)cons->break_word, cons->break_word_len)) {
			ctx->breaked = true;
		}
	}
	return len;
}

R_API void r_kons_memset(RCons *cons, char ch, int len) {
	RConsContext *C = cons->context;
	if (C->breaked) {
		return;
	}
	if (!cons->null && len > 0) {
		if ((len = kons_chop (cons, len)) < 1) {
			return;
		}
		if (kons_palloc (cons, len + 1)) {
			memset (C->buffer + C->buffer_len, ch, len);
			C->buffer_len += len;
			C->buffer[C->buffer_len] = 0;
		}
	}
}

// XXX: if this function returns <0 in rows or cols expect MAYHEM
R_API int r_kons_get_size(RCons *cons, int *rows) {
#if R2__WINDOWS__
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	bool ret = GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &csbi);
	if (ret) {
		cons->columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		cons->rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
	} else {
		if (cons->term_xterm) {
			ret = __xterm_get_size ();
		}
		if (!ret || (cons->columns == -1 && cons->rows == 0)) {
			// Stdout is probably redirected so we set default values
			cons->columns = 80;
			cons->rows = 23;
		}
	}
#elif EMSCRIPTEN || __wasi__
	cons->columns = 80;
	cons->rows = 23;
#elif R2__UNIX__
	struct winsize win = {0};
	if (isatty (0) && !ioctl (0, TIOCGWINSZ, &win)) {
		if ((!win.ws_col) || (!win.ws_row)) {
			char ttybuf[64];
			const char *tty = NULL;
			if (isatty (1)) {
				if (!ttyname_r (1, ttybuf, sizeof (ttybuf))) {
					tty = ttybuf;
				}
			}
			int fd = open (r_str_get_fail (tty, "/dev/tty"), O_RDONLY);
			if (fd != -1) {
				int ret = ioctl (fd, TIOCGWINSZ, &win);
				if (ret || !win.ws_col || !win.ws_row) {
					win.ws_col = 80;
					win.ws_row = 23;
				}
				close (fd);
			}
		}
		cons->columns = win.ws_col;
		cons->rows = win.ws_row;
	} else {
		cons->columns = 80;
		cons->rows = 23;
	}
#else
	char *str = r_sys_getenv ("COLUMNS");
	if (str) {
		cons->columns = atoi (str);
		cons->rows = 23; // XXX. windows must get console size
		free (str);
	} else {
		cons->columns = 80;
		cons->rows = 23;
	}
#endif
#if SIMULATE_ADB_SHELL
	cons->rows = 0;
	cons->columns = 0;
#endif
#if SIMULATE_MAYHEM
	// expect tons of crashes
	cons->rows = -1;
	cons->columns = -1;
#endif
	if (cons->rows < 0) {
		cons->rows = 0;
	}
	if (cons->columns < 0) {
		cons->columns = 0;
	}
	if (cons->force_columns) {
		cons->columns = cons->force_columns;
	}
	if (cons->force_rows) {
		cons->rows = cons->force_rows;
	}
	if (cons->fix_columns) {
		cons->columns += cons->fix_columns;
	}
	if (cons->fix_rows) {
		cons->rows += cons->fix_rows;
	}
	if (rows) {
		*rows = cons->rows;
	}
	cons->rows = R_MAX (0, cons->rows);
	return R_MAX (0, cons->columns);
}

R_API void r_kons_printf_list(RCons *cons, const char *format, va_list ap) {
	va_list ap2, ap3;

	va_copy (ap2, ap);
	va_copy (ap3, ap);
	if (cons->null || !format) {
		va_end (ap2);
		va_end (ap3);
		return;
	}
	if (strchr (format, '%')) {
		RConsContext *ctx = cons->context;
		if (kons_palloc (cons, MOAR + strlen (format) * 20)) {
			bool need_retry = true;
			while (need_retry) {
				need_retry = false;
				size_t left = ctx->buffer_sz - ctx->buffer_len;
				size_t written = vsnprintf (ctx->buffer + ctx->buffer_len, left, format, ap3);
				if (written >= left) {
					if (kons_palloc (cons, written + 1)) {
						va_end (ap3);
						va_copy (ap3, ap2);
						need_retry = true; // Retry with larger buffer
					} else {
						// Allocation failed, use available space
						size_t added = (left > 0) ? left - 1 : 0;
						ctx->buffer_len += added;
						ctx->breaked = true; // Indicate truncation
					}
				} else {
					ctx->buffer_len += written;
				}
			}
		} else {
			ctx->breaked = true; // Initial allocation failed
		}
	} else {
		r_kons_print (cons, format);
	}
	va_end (ap2);
	va_end (ap3);
}

R_API int r_kons_printf(RCons *cons, const char *format, ...) {
	va_list ap;
	if (R_STR_ISEMPTY (format)) {
		return -1;
	}
	va_start (ap, format);
	r_kons_printf_list (cons, format, ap);
	va_end (ap);
	return 0;
}

R_API void r_kons_gotoxy(RCons *cons, int x, int y) {
#if R2__WINDOWS__
	r_cons_w32_gotoxy (1, x, y);
#else
	r_kons_printf (cons, "\x1b[%d;%dH", y, x);
#endif
}

R_API void r_kons_set_interactive(RCons *cons, bool x) {
	RConsContext *ctx = cons->context;
	cons->lasti = ctx->is_interactive;
	ctx->is_interactive = x;
}

R_API void r_kons_set_last_interactive(RCons *cons) {
	cons->context->is_interactive = cons->lasti;
}
