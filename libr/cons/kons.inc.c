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
		r_kons_flush (cons);
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

#if R2__WINDOWS__
static bool w32_xterm_get_size(RCons *cons) {
	if (write (cons->fdout, R_CONS_CURSOR_SAVE, sizeof (R_CONS_CURSOR_SAVE)) < 1) {
		return false;
	}
	int rows, columns;
	const char nainnain[] = "\x1b[999;999H";
	if (write (cons->fdout, nainnain, sizeof (nainnain)) != sizeof (nainnain)) {
		return false;
	}
	rows = __xterm_get_cur_pos (&columns);
	if (rows) {
		cons->rows = rows;
		cons->columns = columns;
	} // otherwise reuse previous values
	if (write (cons->fdout, R_CONS_CURSOR_RESTORE, sizeof (R_CONS_CURSOR_RESTORE) != sizeof (R_CONS_CURSOR_RESTORE))) {
		return false;
	}
	return true;
}
#endif

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
			ret = w32_xterm_get_size (cons);
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

static inline void __cons_write_ll(RCons *cons, const char *buf, int len) {
#if R2__WINDOWS__
	if (cons->vtmode) {
		(void) write (cons->fdout, buf, len);
	} else {
		if (cons->fdout == 1) {
			r_cons_w32_print (buf, len, false);
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

static bool lastMatters(RConsContext *C) {
	if (!C->lastMode) {
		return false;
	}
	return (C->buffer_len > 0 &&
		(C->lastEnabled && !C->filter && r_list_empty (C->grep.strings)) \
		&& !C->grep.tokens_used && !C->grep.less \
		&& !C->grep.json && !C->is_html);
}

R_API void r_kons_flush(RCons *cons) {
	RConsContext *ctx = cons->context;
	const char *tee = cons->teefile;
	if (ctx->noflush) {
		return;
	}
	if (cons->null) {
		r_cons_reset ();
		return;
	}
	if (!r_list_empty (ctx->marks)) {
		r_list_free (ctx->marks);
		ctx->marks = r_list_newf ((RListFree)r_cons_mark_free);
	}
	if (lastMatters (ctx)) {
		// snapshot of the output
		if (ctx->buffer_len > ctx->lastLength) {
			free (ctx->lastOutput);
			ctx->lastOutput = malloc (ctx->buffer_len + 1);
		}
		ctx->lastLength = ctx->buffer_len;
		memcpy (ctx->lastOutput, ctx->buffer, ctx->buffer_len);
	} else {
		ctx->lastMode = false;
	}
#if 0
	if (cons->optimize > 0) {
		// compress output (45 / 250 KB)
		optimize (ctx);
		if (I->optimize > 1) {
			optimize (C);
		}
	}
#endif
	r_cons_filter ();
	if (!ctx->buffer || ctx->buffer_len < 1) {
		r_cons_reset ();
		return;
	}
	if (r_cons_is_interactive () && cons->fdout == 1) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (ctx->pageable && R_STR_ISNOTEMPTY (cons->pager) && ctx->buffer_len > 0 && r_str_char_count (ctx->buffer, '\n') >= cons->rows) {
			ctx->buffer[ctx->buffer_len - 1] = 0;
			if (!strcmp (cons->pager, "..")) {
				char *str = r_str_ndup (ctx->buffer, ctx->buffer_len);
				ctx->pageable = false;
				r_cons_less_str (str, NULL);
				r_cons_reset ();
				free (str);
				return;
			}
			r_sys_cmd_str_full (cons->pager, ctx->buffer, -1, NULL, NULL, NULL);
			r_cons_reset ();
		} else if (cons->maxpage > 0 && ctx->buffer_len > cons->maxpage) {
#if COUNT_LINES
			char *buffer = ctx->buffer;
			int lines = 0;
			int i;
			for (i = 0; buffer[i]; i++) {
				if (buffer[i] == '\n') {
					lines ++;
				}
			}
			if (lines > 0 && !r_cons_yesno ('n',"Do you want to print %d lines? (y/N)", lines)) {
				r_cons_reset ();
				return;
			}
#else
			char buf[8];
			r_num_units (buf, sizeof (buf), ctx->buffer_len);
			if (!r_cons_yesno ('n', "Do you want to print %s chars? (y/N)", buf)) {
				r_cons_reset ();
				return;
			}
#endif
			// fix | more | less problem
			r_cons_set_raw (true);
		}
	}
	if (R_STR_ISNOTEMPTY (tee)) {
		FILE *d = r_sandbox_fopen (tee, "a+");
		if (d) {
			if (ctx->buffer_len != fwrite (ctx->buffer, 1, ctx->buffer_len, d)) {
				R_LOG_ERROR ("r_cons_flush: fwrite: error (%s)", tee);
			}
			fclose (d);
		} else {
			R_LOG_ERROR ("Cannot write on '%s'", tee);
		}
	}
	r_cons_highlight (cons->highlight);

	if (r_cons_is_interactive () && !r_sandbox_enable (false)) {
		if (cons->linesleep > 0 && cons->linesleep < 1000) {
			int i = 0;
			int pagesize = R_MAX (1, cons->pagesize);
			char *ptr = ctx->buffer;
			char *nl = strchr (ptr, '\n');
			int len = ctx->buffer_len;
			ctx->buffer[ctx->buffer_len] = 0;
			r_cons_break_push (NULL, NULL);
			while (nl && !r_cons_is_breaked ()) {
				__cons_write (cons, ptr, nl - ptr + 1);
				if (cons->linesleep && !(i % pagesize)) {
					r_sys_usleep (cons->linesleep * 1000);
				}
				ptr = nl + 1;
				nl = strchr (ptr, '\n');
				i++;
			}
			__cons_write (cons, ptr, ctx->buffer + len - ptr);
			r_cons_break_pop ();
		} else {
			__cons_write (cons, ctx->buffer, ctx->buffer_len);
		}
	} else {
		__cons_write (cons, ctx->buffer, ctx->buffer_len);
	}

	r_cons_reset ();
	if (cons->newline) {
		eprintf ("\n");
		cons->newline = false;
	}
	if (ctx->tmp_html) {
		ctx->is_html = ctx->was_html;
		ctx->tmp_html = false;
		ctx->was_html = false;
	}
}
