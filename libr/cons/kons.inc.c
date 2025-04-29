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

#if R2__WINDOWS__
static int win_xterm_get_cur_pos(RCons *cons, int *xpos) {
	int ypos = 0;
	const char *get_pos = R_CONS_GET_CURSOR_POSITION;
	if (write (cons->fdout, get_pos, sizeof (get_pos)) < 1) {
		return 0;
	}
	int ch;
	char pos[16];
	size_t i;
	bool is_reply;
	do {
		is_reply = true;
		ch = r_cons_readchar ();
		if (ch != 0x1b) {
			while ((ch = r_cons_readchar_timeout (25))) {
				if (ch < 1) {
					return 0;
				}
				if (ch == 0x1b) {
					break;
				}
			}
		}
		(void)r_cons_readchar ();
		for (i = 0; i < R_ARRAY_SIZE (pos) - 1; i++) {
			ch = r_cons_readchar ();
			if ((!i && !isdigit (ch)) || // dumps arrow keys etc.
			    (i == 1 && ch == '~')) {  // dumps PgUp, PgDn etc.
				is_reply = false;
				break;
			}
			if (ch == ';') {
				pos[i] = 0;
				break;
			}
			pos[i] = ch;
		}
	} while (!is_reply);
	pos[R_ARRAY_SIZE (pos) - 1] = 0;
	ypos = atoi (pos);
	for (i = 0; i < R_ARRAY_SIZE (pos) - 1; i++) {
		if ((ch = r_cons_readchar ()) == 'R') {
			pos[i] = 0;
			break;
		}
		pos[i] = ch;
	}
	pos[R_ARRAY_SIZE (pos) - 1] = 0;
	*xpos = atoi (pos);

	return ypos;
}

#endif
#define MOAR (4096 * 8)
static bool kons_palloc(RCons *cons, size_t moar) {
	RConsContext *C = cons->context;
	if (moar == 0 || moar > ST32_MAX) {
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
		size_t new_sz = moar + (C->buffer_sz * 2); // Exponential growth
		if (new_sz < C->buffer_sz || new_sz < moar + C->buffer_len) {
			new_sz = moar + C->buffer_sz + MOAR; // Ensure enough space
		}
		if (new_sz < C->buffer_sz) { // Check for overflow
			return false;
		}
		void *new_buffer = realloc (C->buffer, new_sz);
		if (!new_buffer) {
			return false;
		}
		C->buffer = new_buffer;
		C->buffer_sz = new_sz;
	}
	return true;
}

R_API void r_kons_println(RCons *cons, const char* str) {
	r_kons_print (cons, str);
	r_kons_newline (cons);
}

R_API void r_kons_print(RCons *cons, const char *str) {
	R_RETURN_IF_FAIL (str);
	if (cons->null) {
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
this code now is managed into output.c:118 at function r_cons_win_print
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
			int choplen = kons_chop (cons, len);
			if (choplen > len || choplen < 1) {
				// R_LOG_ERROR ("CHOP ISSUE");
				R_CRITICAL_LEAVE (cons);
				return 0;
			}
			len = choplen;
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
	rows = win_xterm_get_cur_pos (cons, &columns);
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
R_API int r_kons_get_size(RCons *cons, R_NULLABLE int *rows) {
	R_RETURN_VAL_IF_FAIL (cons, 0);
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
		if (kons_palloc (cons, MOAR + strlen (format) * 20)) {
			bool need_retry = true;
			while (need_retry) {
				need_retry = false;
				size_t left = cons->context->buffer_sz - cons->context->buffer_len;
				size_t written = vsnprintf (cons->context->buffer + cons->context->buffer_len, left, format, ap3);
				if (written >= left) {
					if (kons_palloc (cons, written + 1)) {
						va_end (ap3);
						va_copy (ap3, ap2);
						need_retry = true; // Retry with larger buffer
					} else {
						// Allocation failed, use available space
						size_t added = (left > 0) ? left - 1 : 0;
						cons->context->buffer_len += added;
						cons->context->breaked = true; // Indicate truncation
					}
				} else {
					cons->context->buffer_len += written;
				}
			}
		} else {
			cons->context->breaked = true; // Initial allocation failed
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
	r_cons_win_gotoxy (cons, 1, x, y);
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

static bool lastMatters(RConsContext *C) {
	if (!C->lastEnabled) {
		return false;
	}
	return (C->buffer_len > 0 &&
		(C->lastEnabled && !C->filter && r_list_empty (C->grep.strings)) \
		&& !C->grep.tokens_used && !C->grep.less \
		&& !C->grep.json && !C->is_html);
}

R_API bool r_kons_is_interactive(RCons *cons) {
	return cons->context->is_interactive;
}

R_API void r_kons_break_push(RCons *cons, RConsBreak cb, void *user) {
	RConsContext *ctx = cons->context;
	if (ctx->break_stack && r_stack_size (ctx->break_stack) > 0) {
		r_cons_break_timeout (cons->otimeout);
	}
	r_cons_context_break_push (ctx, cb, user, true);
}

R_API void r_kons_break_pop(RCons *cons) {
	cons->timeout = 0;
	r_cons_context_break_pop (cons->context, true);
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
	r_kons_filter (cons);
	if (!ctx->buffer || ctx->buffer_len < 1) {
		r_cons_reset ();
		return;
	}
	if (r_kons_is_interactive (cons) && cons->fdout == 1) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (ctx->pageable && R_STR_ISNOTEMPTY (cons->pager) && ctx->buffer_len > 0 && r_str_char_count (ctx->buffer, '\n') >= cons->rows) {
			ctx->buffer[ctx->buffer_len - 1] = 0;
			if (!strcmp (cons->pager, "..")) {
				char *str = r_str_ndup (ctx->buffer, ctx->buffer_len);
				ctx->pageable = false;
				r_cons_less_str (str, NULL);
				r_kons_reset (cons);
				free (str);
				return;
			}
			r_sys_cmd_str_full (cons->pager, ctx->buffer, -1, NULL, NULL, NULL);
			r_kons_reset (cons);
		} else if (cons->maxpage > 0 && ctx->buffer_len > cons->maxpage) {
#if COUNT_LINES
			char *buffer = ctx->buffer;
			int i, lines = 0;
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
			r_kons_set_raw (cons, true);
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
	r_kons_highlight (cons, cons->highlight);

	if (r_kons_is_interactive (cons) && !r_sandbox_enable (false)) {
		if (cons->linesleep > 0 && cons->linesleep < 1000) {
			int i = 0;
			int pagesize = R_MAX (1, cons->pagesize);
			char *ptr = ctx->buffer;
			char *nl = strchr (ptr, '\n');
			int len = ctx->buffer_len;
			ctx->buffer[ctx->buffer_len] = 0;
			r_cons_break_push (NULL, NULL);
			while (nl && !r_kons_is_breaked (cons)) {
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

R_API void r_kons_last(RCons *cons) {
	RConsContext *ctx = cons->context;
	if (!ctx->lastEnabled) {
		return;
	}
	ctx->lastMode = true;
	if (ctx->lastLength > 0) {
		r_cons_write (ctx->lastOutput, ctx->lastLength);
	}
}


typedef struct {
	char *buf;
	int buf_len;
	int buf_size;
	RConsGrep *grep;
} RConsStack;

typedef struct {
	bool breaked;
	RConsEvent event_interrupt;
	void *event_interrupt_data;
} RConsBreakStack;

static void break_stack_free(void *ptr) {
	RConsBreakStack *b = (RConsBreakStack*)ptr;
	free (b);
}

static void grep_word_free(RConsGrepWord *gw) {
	if (gw) {
		free (gw->str);
		free (gw);
	}
}

static void cons_grep_reset(RConsGrep *grep) {
	if (grep) {
		R_FREE (grep->str);
		ZERO_FILL (*grep);
		r_list_free (grep->strings);
		grep->strings = r_list_newf ((RListFree)grep_word_free);
		grep->line = -1;
		grep->sort = -1;
		grep->sort_invert = false;
	}
}

#if 0
static void cons_stack_free(void *ptr) {
	RConsStack *s = (RConsStack *)ptr;
	R_FREE (s->buf);
	cons_grep_reset (s->grep);
	R_FREE (s->grep);
	free (s);
#if 0
	// XXX
	C->grep.str = NULL;
	cons_grep_reset (&C->grep);
#endif
}
#endif

#if 0
static RConsStack *cons_stack_dump(RCons *cons, bool recreate) {
	RConsContext *ctx = cons->context;
	RConsStack *data = R_NEW0 (RConsStack);
	if (ctx->buffer) {
		data->buf = ctx->buffer;
		data->buf_len = ctx->buffer_len;
		data->buf_size = ctx->buffer_sz;
	}
	data->grep = r_mem_dup (&ctx->grep, sizeof (RConsGrep));
	if (ctx->grep.str) {
		data->grep->str = strdup (ctx->grep.str);
	}
	if (recreate && ctx->buffer_sz > 0) {
		ctx->buffer = malloc (ctx->buffer_sz);
		if (R_UNLIKELY (!ctx->buffer)) {
			ctx->buffer = data->buf;
			free (data);
			return NULL;
		}
	} else {
		ctx->buffer = NULL;
	}
	return data;
}

static void cons_stack_load(RConsContext *C, RConsStack *data, bool free_current) {
	return;
	R_RETURN_IF_FAIL (data);
	if (free_current) {
		// double free
		free (C->buffer);
	}
	C->buffer = data->buf;
	data->buf = NULL;
	C->buffer_len = data->buf_len;
	C->buffer_sz = data->buf_size;
	if (data->grep) {
		free (C->grep.str);
		memcpy (&C->grep, data->grep, sizeof (RConsGrep));
	}
}
#endif

#if 0
static void cons_context_deinit(RConsContext *ctx) {
	return;
	// r_stack_free (ctx->cons_stack);
	r_list_free (ctx->marks);
	ctx->cons_stack = NULL;
	r_stack_free (ctx->break_stack);
	ctx->break_stack = NULL;
	r_cons_pal_free (ctx);
}
#endif

static void init_cons_context(RConsContext *context, R_NULLABLE RConsContext *parent) {
	context->marks = r_list_newf ((RListFree)r_cons_mark_free);
	context->breaked = false;
	// context->cmd_depth = R_CONS_CMD_DEPTH + 1;
	context->buffer_sz = 0;
	context->lastEnabled = true;
	context->buffer_len = 0;
	context->is_interactive = false;
	// context->cons_stack = r_stack_newf (6, cons_stack_free);
	context->break_stack = r_stack_newf (6, break_stack_free);
	context->event_interrupt = NULL;
	context->event_interrupt_data = NULL;
	context->pageable = true;
	context->log_callback = NULL;
	context->cmd_str_depth = 0;
	context->noflush = false;

	if (parent) {
		context->color_mode = parent->color_mode;
		r_cons_pal_copy (context, parent);
	} else {
		context->color_mode = COLOR_MODE_DISABLED;
		r_cons_pal_init (context);
	}
	cons_grep_reset (&context->grep);
}
#if R2__WINDOWS__
static HANDLE h;
static BOOL __w32_control(DWORD type) {
	if (type == CTRL_C_EVENT) {
		__break_signal (2); // SIGINT
		eprintf ("{ctrl+c} pressed.\n");
		return true;
	}
	return false;
}
#elif R2__UNIX__ && !__wasi__
volatile sig_atomic_t sigwinchFlag;
static void resize(int sig) {
	sigwinchFlag = 1;
}
#endif

static inline void init_cons_input(InputState *state) {
	state->readbuffer = NULL;
	state->readbuffer_length = 0;
	state->bufactive = true;
}

R_API RCons *r_kons_new(void) {
	RCons *cons = R_NEW0 (RCons);
	cons->refcnt++;
#if 0
	if (cons->refcnt != 1) {
		return cons;
	}
	if (cons->lock) {
		r_th_lock_wait (cons->lock);
	} else {
		cons->lock = r_th_lock_new (false);
	}
	R_CRITICAL_ENTER (I);
#endif
	// r_cons_context_reset (cons->context);
	cons->context = R_NEW0 (RConsContext);
	cons->ctx_stack = r_list_newf ((RListFree)r_cons_context_free);
	init_cons_context (cons->context, NULL);
	// eprintf ("CTX %p %p\n", cons, cons->context);
	init_cons_input (&cons->input_state);
	cons->lock = r_th_lock_new (false);
	cons->use_utf8 = r_cons_is_utf8 ();
	cons->rgbstr = r_cons_rgb_str_off;
	cons->line = r_line_new ();
	cons->enable_highlight = true;
	cons->highlight = NULL;
	cons->is_wine = -1;
	cons->fps = 0;
	cons->blankline = true;
	cons->teefile = NULL;
	cons->fix_columns = 0;
	cons->fix_rows = 0;
	RVecFdPairs_init (&cons->fds);
	cons->mouse_event = 0;
	cons->force_rows = 0;
	cons->force_columns = 0;
	cons->event_resize = NULL;
	cons->event_data = NULL;
	cons->linesleep = 0;
	cons->fdin = stdin;
	cons->fdout = 1;
	cons->break_lines = false;
	cons->lines = 0;
	cons->maxpage = 102400;

	r_kons_get_size (cons, &cons->pagesize);
	cons->num = NULL;
	cons->null = 0;
#if R2__WINDOWS__
	cons->old_cp = GetConsoleOutputCP ();
	cons->vtmode = win_is_vtcompat ();
#else
	cons->vtmode = 2;
#endif
#if EMSCRIPTEN || __wasi__
	/* do nothing here :? */
#elif R2__UNIX__
	tcgetattr (0, &cons->term_buf);
	memcpy (&cons->term_raw, &cons->term_buf, sizeof (cons->term_raw));
	cons->term_raw.c_iflag &= ~(BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	cons->term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	cons->term_raw.c_cflag &= ~(CSIZE|PARENB);
	cons->term_raw.c_cflag |= CS8;
	cons->term_raw.c_cc[VMIN] = 1; // Solaris stuff hehe
	r_sys_signal (SIGWINCH, resize);
#elif R2__WINDOWS__
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &cons->term_buf);
	cons->term_raw = 0;
	if (!SetConsoleCtrlHandler ((PHANDLER_ROUTINE)__w32_control, TRUE)) {
		R_LOG_ERROR ("Cannot set control console handler");
	}
#endif
	cons->pager = NULL; /* no pager by default */
	cons->mouse = 0;
	cons->show_vals = false;
	r_kons_reset (cons);
	r_kons_rgb_init (cons);
	r_print_set_is_interrupted_cb (r_cons_is_breaked);
	return cons;
}

R_API void r_kons_free(R_NULLABLE RCons *cons) {
	if (!cons) {
		return;
	}
#if R2__WINDOWS__
	r_cons_enable_mouse (false);
	if (cons->old_cp) {
		(void)SetConsoleOutputCP (cons->old_cp);
		// chcp doesn't pick up the code page switch for some reason
		(void)r_sys_cmdf ("chcp %u > NUL", cons->old_cp);
	}
#endif
#if 0
	cons->refcnt--;
	if (cons->refcnt != 0) {
		return;
	}
#endif
	if (cons->line) {
		r_line_free ();
		cons->line = NULL;
	}
	while (r_kons_pop (cons)) {
		// do not stop
	}
	r_cons_context_free (cons->context);
#if 0
	RConsContext *ctx = cons->context;
	R_FREE (ctx->buffer);
	R_FREE (cons->break_word);
	cons_context_deinit (ctx);
	R_FREE (ctx->lastOutput);
	ctx->lastLength = 0;
#endif
	R_FREE (cons->pager);
	RVecFdPairs_fini (&cons->fds);
}

R_API void r_kons_print_clear(RCons *cons) {
	r_kons_print (cons, "\x1b[0;0H\x1b[0m");
}

R_API void r_kons_fill_line(RCons *cons) {
	char white[1024];
	int cols = cons->columns - 1;
	if (cols < 1) {
		return;
	}
	char *p = (cols >= sizeof (white))? malloc (cols + 1): white;
	if (p) {
		memset (p, ' ', cols);
		p[cols] = 0;
		r_kons_print (cons, p);
		if (white != p) {
			free (p);
		}
	}
}

R_API void r_kons_clear_line(RCons *cons, int std_err) {
#if R2__WINDOWS__
	if (cons->vtmode) {
		fprintf (std_err? stderr: stdout,"%s", R_CONS_CLEAR_LINE);
	} else {
		char white[1024];
		memset (&white, ' ', sizeof (white));
		if (cons->columns > 0 && cons->columns < sizeof (white)) {
			white[cons->columns - 1] = 0;
		} else if (cons->columns == 0) {
			white[0] = 0;
		} else {
			white[sizeof (white) - 1] = 0; // HACK
		}
		fprintf (std_err? stderr: stdout, "\r%s\r", white);
	}
#else
	fprintf (std_err? stderr: stdout,"%s", R_CONS_CLEAR_LINE);
#endif
	fflush (std_err? stderr: stdout);
}

R_API void r_kons_reset_colors(RCons *cons) {
	r_kons_print (cons, Color_RESET_BG Color_RESET);
}

R_API void r_kons_clear(RCons *cons) {
	cons->lines = 0;
#if R2__WINDOWS__
	r_cons_win_clear (cons);
#else
	r_kons_print (cons, Color_RESET R_CONS_CLEAR_SCREEN);
#endif
}

R_API void r_kons_clear00(RCons *cons) {
	r_kons_clear (cons);
	r_kons_gotoxy (cons, 0, 0);
}

R_API void r_kons_reset(RCons *cons) {
	RConsContext *c = cons->context;
	if (c->buffer) {
		c->buffer[0] = '\0';
	}
	c->buffer_len = 0;
	cons->lines = 0;
	cons->lastline = c->buffer;
	cons_grep_reset (&c->grep);
	c->pageable = true;
}

R_API const char *r_kons_get_buffer(RCons *cons, size_t *buffer_len) {
	RConsContext *ctx = cons->context;
	if (buffer_len) {
		*buffer_len = ctx->buffer_len;
	}
	// check len otherwise it will return trash
	return (ctx->buffer_len > 0)? ctx->buffer : NULL;
}

R_API void r_kons_filter(RCons *cons) {
	RConsContext *ctx = cons->context;
	/* grep */
	if (ctx->filter || ctx->grep.tokens_used \
			|| (ctx->grep.strings && r_list_length (ctx->grep.strings) > 0) \
			|| ctx->grep.less || ctx->grep.json) {
		(void)r_kons_grepbuf (cons);
		ctx->filter = false;
	}
	/* html */
	if (ctx->is_html) {
		int newlen = 0;
		char *input = r_str_ndup (ctx->buffer, ctx->buffer_len);
		char *res = r_cons_html_filter (input, &newlen);
		if (res) {
			free (ctx->buffer);
			ctx->buffer = res;
			ctx->buffer_len = newlen;
			ctx->buffer_sz = newlen;
		}
		free (input);
	}
	if (ctx->tmp_html) {
		ctx->is_html = ctx->was_html;
		ctx->tmp_html = false;
		ctx->was_html = false;
	}
}

R_API void r_cons_context_free(R_NULLABLE RConsContext *ctx) {
	if (ctx) {
		// TODO: free more stuff
#if 0
	// r_stack_free (ctx->cons_stack);
	r_list_free (ctx->marks);
	ctx->cons_stack = NULL;
	r_stack_free (ctx->break_stack);
	ctx->break_stack = NULL;
	r_cons_pal_free (ctx);
#endif
		free (ctx);
	}
}

R_API RConsContext *r_cons_context_clone(RConsContext *ctx) {
	RConsContext *c = r_mem_dup (ctx, sizeof (RConsContext));
	if (ctx->buffer) {
		c->buffer = r_mem_dup (ctx->buffer, ctx->buffer_sz);
	}
	if (ctx->break_stack) {
		c->break_stack = r_stack_newf (3, break_stack_free);
	}
	if (ctx->lastOutput) {
		c->lastOutput = r_mem_dup (ctx->lastOutput, ctx->lastLength);
	}
	if (ctx->sorted_lines) {
		c->sorted_lines = r_list_clone (ctx->sorted_lines, (RListClone)strdup);
	}
	if (ctx->unsorted_lines) {
		c->unsorted_lines = r_list_clone (ctx->unsorted_lines, (RListClone)strdup);
	}
	c->marks = r_list_clone (ctx->marks, (RListClone)strdup);
	return c;
}

R_API void r_kons_push(RCons *cons) {
	r_list_push (cons->ctx_stack, cons->context);
	RConsContext *nc = r_cons_context_clone (cons->context);
#if 1
	nc->buffer = NULL;
	nc->buffer_sz = 0;
	nc->buffer_len = 0;
#endif
	cons->context = nc;
	// global hacks
	r_cons_singleton ()->context = nc;
	// r_cons_context_reset (cons->context);
#if 0
	// memcpy (&tc, cons->context, sizeof (tc));
	if (!ctx->cons_stack) {
		return;
	}
	RConsStack *data = cons_stack_dump (cons, true);
	if (data) {
		r_stack_push (ctx->cons_stack, data);
		ctx->buffer_len = 0;
		if (ctx->buffer) {
			memset (ctx->buffer, 0, ctx->buffer_sz);
		}
	}
#endif
}

R_API bool r_kons_pop(RCons *cons) {
	RConsContext *ctx = r_list_pop (cons->ctx_stack);
	if (ctx) {
		r_cons_context_free (cons->context);
		cons->context = ctx;
		// global hacks
		r_cons_singleton ()->context = ctx;
		return true;
	}
	// R_LOG_INFO ("Nothing to pop");
	return false;
#if 0
	if (ctx->cons_stack) {
		RConsStack *data = (RConsStack *)r_stack_pop (ctx->cons_stack);
		if (data) {
			cons_stack_load (ctx, data, true);
			cons_stack_free ((void *)data);
		}
	}
	memcpy (cons->context, &tc, sizeof (tc));
#endif
}

R_API bool r_kons_context_is_main(RCons *cons) {
	if (r_list_length (cons->ctx_stack) == 0) {
		return true;
	}
	RConsContext *first_context = r_list_get_n (cons->ctx_stack, 0);
	return cons->context == first_context;
}

R_API void r_kons_echo(RCons *cons, const char *msg) {
	if (msg) {
		if (cons->echodata) {
			r_strbuf_append (cons->echodata, msg);
			r_strbuf_append_n (cons->echodata, "\n", 1);
		} else {
			cons->echodata = r_strbuf_new (msg);
		}
	} else {
		if (cons->echodata) {
			char *data = r_strbuf_drain (cons->echodata);
			r_cons_print (data);
			r_cons_newline ();
			cons->echodata = NULL;
			free (data);
		}
	}
}

R_API char *r_kons_drain(RCons *cons) {
	size_t buf_size;
	const char *buf = r_kons_get_buffer (cons, &buf_size);
	char *s = r_str_ndup (buf, buf_size);
	r_kons_reset (cons);
	return s;
}

R_API void r_kons_print_fps(RCons *cons, int col) {
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

static int real_strlen(const char *ptr, int len) {
	int utf8len = r_str_len_utf8 (ptr);
	int ansilen = r_str_ansi_len (ptr);
	int diff = len - utf8len;
	if (diff > 0) {
		diff--;
	}
	return ansilen - diff;
}

R_API void r_kons_visual_write(RCons *cons, char *buffer) {
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

R_API void r_kons_visual_flush(RCons *cons) {
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
		r_kons_visual_write (cons, ctx->buffer);
#endif
	}
	r_cons_reset ();
	if (cons->fps) {
		r_kons_print_fps (cons, 0);
	}
}

R_API int r_kons_get_column(RCons *cons) {
	RConsContext *C = cons->context;
	char *line = strrchr (C->buffer, '\n');
	if (!line) {
		line = C->buffer;
	}
	C->buffer[C->buffer_len] = 0;
	return r_str_ansi_len (line);
}

/* return the aproximated x,y of cursor before flushing */
// XXX this function is a huge bottleneck
R_API int r_kons_get_cursor(RCons *cons, int *rows) {
	// This implementation is very slow
	if (rows) {
		*rows = 0;
	}
	return 0;
#if 0
	// TODO: this is too slow and not really useful
	RConsContext *c = C;
	int i, col = 0;
	int row = 0;
	// TODO: we need to handle GOTOXY and CLRSCR ansi escape code too
	for (i = 0; i < c->buffer_len; i++) {
		// ignore ansi chars, copypasta from r_str_ansi_len
		if (c->buffer[i] == 0x1b) {
			char ch2 = c->buffer[i + 1];
			char *str = c->buffer;
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp (str + 2 + 5, "rgb:", 4)) {
					i += 18;
				}
			} else if (ch2 == '[') {
				for (i++; str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H'; i++) {
					;
				}
			}
		} else if (c->buffer[i] == '\n') {
			row++;
			col = 0;
		} else {
			col++;
		}
	}
	if (rows) {
		*rows = row;
	}
	return col;
#endif
}

#if R2__WINDOWS__
R_IPI int r_kons_is_vtcompat(RCons *cons) {
	DWORD major;
	DWORD minor;
	DWORD release = 0;
	char *cmd_session = r_sys_getenv ("SESSIONNAME");
	if (cmd_session) {
		free (cmd_session);
		return 2;
	}
	// Windows Terminal
	char *wt_session = r_sys_getenv ("WT_SESSION");
	if (wt_session) {
		free (wt_session);
		return 2;
	}
	char *alacritty = r_sys_getenv ("ALACRITTY_LOG");
	if (alacritty) {
		free (alacritty);
		return 1;
	}
	char *term = r_sys_getenv ("TERM");
	if (term) {
		if (strstr (term, "xterm")) {
			cons->term_xterm = true;
			free (term);
			return 2;
		}
		cons->term_xterm = false;
		free (term);
	}
	char *ansicon = r_sys_getenv ("ANSICON");
	if (ansicon) {
		free (ansicon);
		return 1;
	}
	bool win_support = 0;
	RSysInfo *info = r_sys_info ();
	if (info && info->version) {
		char *save_ptr = NULL;
		char *dot = r_str_tok_r (info->version, ".", &save_ptr);
		major = atoi (dot);
		dot = r_str_tok_r (NULL, ".", &save_ptr);
		minor = atoi (dot);
		if (info->release) {
			release = atoi (info->release);
		}
		if (major > 10
			|| (major == 10 && minor > 0)
			|| (major == 10 && minor == 0 && release >= 1703)) {
			win_support = 1;
		}
	}
	r_sys_info_free (info);
	return win_support;
}
#endif

R_API void r_kons_show_cursor(RCons *I, int cursor) {
	RConsContext *C = I->context;
#if R2__WINDOWS__
	if (I->vtmode) {
#endif
		if (write (1, cursor ? "\x1b[?25h" : "\x1b[?25l", 6) != 6) {
			C->breaked = true;
		}
#if R2__WINDOWS__
	} else {
		static R_TH_LOCAL HANDLE hStdout = NULL;
		static R_TH_LOCAL DWORD size = -1;
		CONSOLE_CURSOR_INFO cursor_info;
		if (!hStdout) {
			hStdout = GetStdHandle (STD_OUTPUT_HANDLE);
		}
		if (size == -1) {
			GetConsoleCursorInfo (hStdout, &cursor_info);
			size = cursor_info.dwSize;
		}
		cursor_info.dwSize = size;
		cursor_info.bVisible = cursor ? TRUE : FALSE;
		SetConsoleCursorInfo (hStdout, &cursor_info);
	}
#endif
}

R_API void r_kons_set_raw(RCons *I, bool is_raw) {
	if (I->oldraw != 0) {
		if (is_raw == I->oldraw - 1) {
			return;
		}
	}
#if EMSCRIPTEN || __wasi__
	/* do nothing here */
#elif R2__UNIX__
	struct termios *term_mode;
	if (is_raw) {
		I->term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
		term_mode = &I->term_raw;
	} else {
		term_mode = &I->term_buf;
	}
	if (tcsetattr (0, TCSANOW, term_mode) == -1) {
		return;
	}
#elif R2__WINDOWS__
	if (I->term_xterm) {
		char *stty = r_file_path ("stty");
		if (!stty || *stty == 's') {
			I->term_xterm = false;
		}
		free (stty);
	}
	if (I->term_xterm) {
		const char *cmd = is_raw
			? "stty raw -echo"
			: "stty raw echo";
		r_sandbox_system (cmd, 1);
	} else {
		if (!SetConsoleMode (h, is_raw? I->term_raw: I->term_buf)) {
			return;
		}
	}
#else
#warning No raw console supported for this platform
#endif
	I->oldraw = is_raw + 1;
}

R_API void r_kons_set_utf8(RCons *cons, bool b) {
	cons->use_utf8 = b;
#if R2__WINDOWS__
	if (b) {
		if (IsValidCodePage (CP_UTF8)) {
			if (!SetConsoleOutputCP (CP_UTF8)) {
				r_sys_perror ("r_cons_set_utf8");
			}
#if UNICODE
			UINT inCP = CP_UTF8;
#else
			UINT inCP = GetACP ();
#endif
			if (!SetConsoleCP (inCP)) {
				r_sys_perror ("r_cons_set_utf8");
			}
		} else {
			R_LOG_WARN ("UTF-8 Codepage not installed");
		}
	} else {
		UINT acp = GetACP ();
		if (!SetConsoleCP (acp) || !SetConsoleOutputCP (acp)) {
			r_sys_perror ("r_cons_set_utf8");
		}
	}
#endif
}

R_API void r_kons_invert(RCons *cons, int set, int color) {
	r_kons_print (cons, R_CONS_INVERT (set, color));
}

R_API void r_kons_column(RCons *cons, int c) {
	RConsContext *ctx = cons->context;
	char *b = malloc (ctx->buffer_len + 1);
	if (!b) {
		return;
	}
	memcpy (b, ctx->buffer, ctx->buffer_len);
	b[ctx->buffer_len] = 0;
	r_kons_reset (cons);
	// align current buffer N chars right
	r_cons_print_justify (b, c, 0);
	free (b);
	r_kons_gotoxy (cons, 0, 0);
}

R_API void r_kons_set_title(RCons *cons, const char *str) {
#if R2__WINDOWS__
#  if defined(_UNICODE)
	wchar_t* wstr = r_utf8_to_utf16_l (str, strlen (str));
	if (wstr) {
		SetConsoleTitleW (wstr);
		R_FREE (wstr);
	}
#  else // defined(_UNICODE)
	SetConsoleTitle (str);
#  endif // defined(_UNICODE)
#else
	r_kons_printf (cons, "\x1b]0;%s\007", str);
#endif
}

R_API void r_kons_zero(RCons *cons) {
	if (cons->line) {
		cons->line->zerosep = true;
	}
	if (write (1, "", 1) != 1) {
		cons->context->breaked = true;
	}
}

R_API void r_kons_highlight(RCons *cons, const char *word) {
	int l, *cpos = NULL;
	char *rword = NULL, *res, *clean = NULL;
	char *inv[2] = {
		R_CONS_INVERT (true, true),
		R_CONS_INVERT (false, true)
	};
	const int linv[2] = {
		strlen (inv[0]),
		strlen (inv[1])
	};

	if (!cons->enable_highlight) {
		r_cons_enable_highlight (true);
		return;
	}
	RConsContext *C = cons->context;
	if (R_STR_ISNOTEMPTY (word) && C->buffer) {
		int word_len = strlen (word);
		char *orig;
		clean = r_str_ndup (C->buffer, C->buffer_len);
		l = r_str_ansi_filter (clean, &orig, &cpos, -1);
		free (C->buffer);
		C->buffer = orig;
		if (cons->highlight) {
			if (strcmp (word, cons->highlight)) {
				free (cons->highlight);
				cons->highlight = strdup (word);
			}
		} else {
			cons->highlight = strdup (word);
		}
		rword = malloc (word_len + linv[0] + linv[1] + 1);
		if (!rword) {
			free (cpos);
			free (clean);
			return;
		}
		strcpy (rword, inv[0]);
		strcpy (rword + linv[0], word);
		strcpy (rword + linv[0] + word_len, inv[1]);
		res = r_str_replace_thunked (C->buffer, clean, cpos,
					l, word, rword, 1);
		if (res) {
			C->buffer = res;
			C->buffer_len = C->buffer_sz = strlen (res);
		}
		free (rword);
		free (clean);
		free (cpos);
	} else {
		R_FREE (cons->highlight);
	}
}

R_API char *r_kons_lastline(RCons *cons, int *len) {
	RConsContext *c = cons->context;
	char *start = c->buffer;
	char *b = start + c->buffer_len;
	while (b > start) {
		b--;
		if (*b == '\n') {
			b++;
			break;
		}
	}
	if (len) {
		int delta = b - start;
		*len = c->buffer_len - delta;
	}
	return b;
}
// same as r_cons_lastline(), but len will be the number of
// utf-8 characters excluding ansi escape sequences as opposed to just bytes
R_API char *r_kons_lastline_utf8_ansi_len(RCons *cons, int *len) {
	RConsContext *c = cons->context;
	if (!len) {
		return r_kons_lastline (cons, 0);
	}

	char *start = c->buffer;
	char *b = start + c->buffer_len;
	int l = 0;
	int last_possible_ansi_end = 0;
	char ch = '\0';
	char ch2;
	while (b > start) {
		ch2 = ch;
		ch = *b;

		if (ch == '\n') {
			b++;
			l--;
			break;
		}

		// utf-8
		if ((ch & 0xc0) != 0x80) {
			l++;
		}

		// ansi
		if (ch == 'J' || ch == 'm' || ch == 'H') {
			last_possible_ansi_end = l - 1;
		} else if (ch == '\x1b' && ch2 == '[') {
			l = last_possible_ansi_end;
		}

		b--;
	}

	*len = l;
	return b;
}

R_API bool r_kons_drop(RCons *cons, int n) {
	RConsContext *c = cons->context;
	if (n > c->buffer_len) {
		c->buffer_len = 0;
		return false;
	}
	c->buffer_len -= n;
	return true;
}

R_API void r_kons_trim(RCons *cons) {
	RConsContext *c = cons->context;
	while (c->buffer_len > 0) {
		char ch = c->buffer[c->buffer_len - 1];
		if (ch != '\n' && !IS_WHITESPACE (ch)) {
			break;
		}
		c->buffer_len--;
	}
}

R_API void r_kons_breakword(RCons *cons, R_NULLABLE const char *s) {
	free (cons->break_word);
	if (s) {
		cons->break_word = strdup (s);
		cons->break_word_len = strlen (s);
	} else {
		cons->break_word = NULL;
		cons->break_word_len = 0;
	}
}

R_API void r_kons_clear_buffer(RCons *cons) {
	if (cons->vtmode) {
		if (write (1, "\x1b" "c\x1b[3J", 6) != 6) {
			cons->context->breaked = true;
		}
	}
}

R_API void r_cons_mark_free(RConsMark *m) {
	if (m) {
		free (m->name);
		free (m);
	}
}

R_API void r_kons_mark(RCons *cons, ut64 addr, const char *name) {
	RConsMark *mark = R_NEW0 (RConsMark);
	RConsContext *ctx = cons->context;
	mark->addr = addr;
	int row = 0, col = r_cons_get_cursor (&row);
	mark->name = strdup (name); // TODO. use a const pool
	mark->pos = ctx->buffer_len;
	mark->col = col;
	mark->row = row;
	r_list_append (ctx->marks, mark);
}

R_API void r_kons_mark_flush(RCons *cons) {
	r_list_free (cons->context->marks);
}

R_API RConsMark *r_kons_mark_at(RCons *cons, ut64 addr, const char *name) {
	RConsContext *C = cons->context;
	RListIter *iter;
	RConsMark *mark;
	r_list_foreach (C->marks, iter, mark) {
		if (R_STR_ISNOTEMPTY (name)) {
			if (strcmp (mark->name, name)) {
				continue;
			}
			return mark;
		}
		if (addr != UT64_MAX && mark->addr == addr) {
			return mark;
		}
	}
	return NULL;
}

R_API bool r_kons_is_breaked(RCons *cons) {
#if WANT_DEBUGSTUFF
	RConsContext *C = cons->context;
	if (R_UNLIKELY (cons->cb_break)) {
		cons->cb_break (cons->user);
	}
	if (R_UNLIKELY (cons->timeout)) {
		if (r_stack_size (C->break_stack) > 0) {
			if (r_time_now_mono () > cons->timeout) {
				C->breaked = true;
				C->was_breaked = true;
				r_cons_break_timeout (cons->otimeout);
			}
		}
	}
	if (R_UNLIKELY (!C->was_breaked)) {
		C->was_breaked = C->breaked;
	}
	return R_UNLIKELY (C && C->breaked);
#else
	return false;
#endif
}

R_API void r_kons_break_end(RCons *cons) {
	RConsContext *C = cons->context;
	C->breaked = false;
	cons->timeout = 0;
#if R2__UNIX__ && !__wasi__
	if (!C->unbreakable) {
		r_sys_signal (SIGINT, SIG_IGN);
	}
#endif
	if (!r_stack_is_empty (C->break_stack)) {
		// free all the stack
		r_stack_free (C->break_stack);
		// create another one
		C->break_stack = r_stack_newf (6, break_stack_free);
		C->event_interrupt_data = NULL;
		C->event_interrupt = NULL;
	}
}

R_API void *r_kons_sleep_begin(RCons *cons) {
	R_CRITICAL_ENTER (cons);
	if (cons->cb_sleep_begin) {
		return cons->cb_sleep_begin (cons->user);
	}
	return NULL;
}

R_API void r_kons_sleep_end(RCons *cons, void *user) {
	if (cons->cb_sleep_end) {
		cons->cb_sleep_end (cons->user, user);
	}
	R_CRITICAL_LEAVE (cons);
}

R_API void r_kons_break_clear(RCons *cons) {
	RConsContext *ctx = cons->context;
	ctx->was_breaked = false;
	ctx->breaked = false;
}

R_API void r_kons_cmd_help(RCons *cons, RCoreHelpMessage help, bool use_color) {
	const char *pal_input_color = use_color ? cons->context->pal.input : "";
	const char *pal_args_color = use_color ? cons->context->pal.args : "";
	const char *pal_help_color = use_color ? cons->context->pal.help : "";
	const char *pal_reset = use_color ? cons->context->pal.reset : "";
	int i, max_length = 0, padding = 0;
	const char *usage_str = "Usage:";
	const char *help_cmd = NULL, *help_args = NULL, *help_desc = NULL;
	if (!pal_input_color) {
		pal_input_color = "";
	}
	if (!pal_args_color) {
		pal_args_color = "";
	}
	if (!pal_help_color) {
		pal_help_color = "";
	}
	if (!pal_reset) {
		pal_reset = Color_RESET;
	}

	// calculate padding for description text in advance
	for (i = 0; help[i]; i += 3) {
		help_cmd = help[i + 0];
		help_args = help[i + 1];

		int len_cmd = strlen (help_cmd);
		int len_args = strlen (help_args);
		if (i) {
			max_length = R_MAX (max_length, len_cmd + len_args);
		}
	}

	for (i = 0; help[i]; i += 3) {
		help_cmd  = help[i + 0];
		help_args = help[i + 1];
		help_desc = help[i + 2];

		if (r_str_startswith (help_cmd, usage_str)) {
			/* Usage header */
			const char *afterusage = help_cmd + strlen (usage_str);
			r_cons_printf ("Usage:%s%s", pal_args_color, afterusage);
			if (help_args[0]) {
				r_cons_printf (" %s", help_args);
			}
			if (help_desc[0]) {
				r_cons_printf ("  %s", help_desc);
			}
			r_cons_printf ("%s\n", pal_reset);
		} else if (!help_args[0] && !help_desc[0]) {
			/* Section header, no need to indent it */
			r_cons_printf ("%s%s%s\n", pal_help_color, help_cmd, pal_reset);
		} else {
			/* Body of help text, indented */
			int str_length = strlen (help_cmd) + strlen (help_args);
			padding = R_MAX ((max_length - str_length), 0);
			r_cons_printf ("| %s%s%s%s%*s  %s%s%s\n",
				pal_input_color, help_cmd,
				pal_args_color, help_args,
				padding, "",
				pal_help_color, help_desc, pal_reset);
		}
	}
}

R_API void r_kons_grep_help(RCons *cons) {
	r_cons_cmd_help (help_detail_tilde, true);
}
