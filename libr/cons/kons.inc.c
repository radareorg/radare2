/* radare2 - LGPL - Copyright 2025 - pancake */

#include <r_cons.h>
#include "private.h"

R_API void r_kons_print(RCons *cons, const char *str) {
	R_RETURN_IF_FAIL (str);
	if (cons->null) {
		return;
	}
	size_t len = strlen (str);
	if (len > 0) {
		r_cons_write (cons, str, len);
	}
}

R_API int r_kons_printf(RCons *cons, const char *format, ...) {
	va_list ap;
	if (R_STR_ISEMPTY (format)) {
		return -1;
	}
	va_start (ap, format);
	r_cons_printf_list (cons, format, ap);
	va_end (ap);
	return 0;
}

R_API void r_kons_set_interactive(RCons *cons, bool x) {
	RConsContext *ctx = cons->context;
	cons->lasti = ctx->is_interactive;
	ctx->is_interactive = x;
}

R_API void r_kons_set_last_interactive(RCons *cons) {
	cons->context->is_interactive = cons->lasti;
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

R_API void r_kons_last(RCons *cons) {
	RConsContext *ctx = cons->context;
	if (!ctx->lastEnabled) {
		return;
	}
	ctx->lastMode = true;
	if (ctx->lastLength > 0) {
		r_cons_write (cons, ctx->lastOutput, ctx->lastLength);
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
		free (grep->str);
		grep->str = NULL;
		if (grep->strings) {
			r_list_free (grep->strings);
			grep->strings = r_list_newf ((RListFree)grep_word_free);
		}
		ZERO_FILL (*grep);
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

static void mark_free(RConsMark *m) {
	free (m->name);
	free (m);
}

static void init_cons_context(RCons *cons, RConsContext * R_NULLABLE parent) {
	RConsContext *ctx = cons->context;
	ctx->marks = r_list_newf ((RListFree)mark_free);
	ctx->breaked = false;
	// ctx->cmd_depth = R_CONS_CMD_DEPTH + 1;
	ctx->buffer_sz = 0;
	ctx->lastEnabled = true;
	ctx->buffer_len = 0;
	ctx->is_interactive = false;
	// ctx->cons_stack = r_stack_newf (6, cons_stack_free);
	ctx->break_stack = r_stack_newf (6, break_stack_free);
	ctx->event_interrupt = NULL;
	ctx->event_interrupt_data = NULL;
	ctx->pageable = true;
	ctx->log_callback = NULL;
	ctx->cmd_str_depth = 0;
	ctx->noflush = false;

	if (parent) {
		ctx->color_mode = parent->color_mode;
		r_cons_pal_copy (cons, parent);
	} else {
		ctx->color_mode = COLOR_MODE_DISABLED;
		r_cons_pal_init (cons);
	}
	cons_grep_reset (&ctx->grep);
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
	init_cons_context (cons, NULL);
	// eprintf ("CTX %p %p\n", cons, cons->context);
	init_cons_input (&cons->input_state);
	cons->lock = r_th_lock_new (false);
	cons->use_utf8 = r_cons_is_utf8 ();
	cons->rgbstr = r_cons_rgb_str_off; // XXX maybe we can kill that
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

	r_cons_get_size (cons, &cons->pagesize);
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
	r_cons_reset (cons);
	cons->line = r_line_new (cons);
	return cons;
}

R_API void r_kons_free(RCons * R_NULLABLE cons) {
	if (!cons) {
		return;
	}
#if R2__WINDOWS__
	r_cons_enable_mouse (cons, false);
	if (cons->old_cp) {
		(void)SetConsoleOutputCP (cons->old_cp);
		// chcp doesn't pick up the code page switch for some reason
		(void)r_sys_cmdf ("chcp %u > NUL", cons->old_cp);
	}
#endif
	if (cons->line) {
		r_line_free (cons->line);
		cons->line = NULL;
	}
	while (!r_list_empty (cons->ctx_stack)) {
		r_kons_pop (cons);
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
	r_cons_gotoxy (cons, 0, 0);
}

R_API const char *r_kons_get_buffer(RCons *cons, size_t *buffer_len) {
	RConsContext *ctx = cons->context;
	if (buffer_len) {
		*buffer_len = ctx->buffer_len;
	}
	// check len otherwise it will return trash
	return (ctx->buffer_len > 0)? ctx->buffer : NULL;
}

R_API void r_kons_push(RCons *cons) {
	r_list_push (cons->ctx_stack, cons->context);
	RConsContext *nc = r_cons_context_clone (cons->context);
#if 1
	// maybe this is done by kons_reset too
	nc->buffer = NULL;
	nc->buffer_sz = 0;
	nc->buffer_len = 0;
#endif
	cons->context = nc;
	// global hacks
	RCons *Gcons = r_cons_singleton ();
	if (cons == Gcons) {
		Gcons->context = nc;
	}
	r_cons_reset (cons);
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
	if (r_list_empty (cons->ctx_stack)) {
		R_LOG_INFO ("Nothing to pop");
		return false;
	}
	RConsContext *ctx = r_list_pop (cons->ctx_stack);
	r_cons_context_free (cons->context);
	cons->context = ctx;
	// global hacks
	RCons *Gcons = r_cons_singleton ();
	if (cons == Gcons) {
		Gcons->context = ctx;
	}
	return true;
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
	return r_cons_context_is_main (cons, cons->context);
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
			r_kons_print (cons, data);
			r_cons_newline (cons);
			cons->echodata = NULL;
			free (data);
		}
	}
}

R_API char *r_kons_drain(RCons *cons) {
	size_t buf_size;
	const char *buf = r_kons_get_buffer (cons, &buf_size);
	char *s = r_str_ndup (buf, buf_size);
	r_cons_reset (cons);
	return s;
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

R_API void r_cons_show_cursor(RCons *I, int cursor) {
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
		r_cons_enable_highlight (cons, true);
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
