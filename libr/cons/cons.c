/* radare2 - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>
#include <r_util/r_print.h>

#define COUNT_LINES 1

static R_TH_LOCAL RCons *I = NULL;

R_LIB_VERSION (r_cons);

static RCons s_cons_global = {0};

static void __break_signal(int sig);

#define MOAR (4096 * 8)

static bool cons_palloc(RCons *cons, size_t moar) {
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
			free (C->buffer);
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


#include "thread.inc.c"
#include "private.h"

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
		r_list_free (grep->strings);
		grep->strings = r_list_newf ((RListFree)grep_word_free);
		ZERO_FILL (*grep);
		grep->line = -1;
		grep->sort = -1;
		grep->sort_invert = false;
	}
}

#if 0
typedef struct {
	char *buf;
	int buf_len;
	int buf_size;
	RConsGrep *grep;
} RConsStack;

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

static void cons_context_deinit(RConsContext *ctx) {
	if (!ctx) {
		return;
	}
	// r_stack_free (ctx->cons_stack);
	r_list_free (ctx->marks);
	ctx->marks = NULL;
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

R_API RCons *r_cons_new2(void) {
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

R_API void r_cons_free2(RCons * R_NULLABLE cons) {
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
	r_line_free (cons->line);
	while (!r_list_empty (cons->ctx_stack)) {
		r_cons_pop (cons);
	}
	r_cons_context_free (cons->context);
	r_list_free (cons->ctx_stack);
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

static void __break_signal(int sig) {
	r_cons_context_break (I->context); // &r_cons_context_default);
}

#if 0
static inline void init_cons_instance(void) {
	return;
	if (R_LIKELY (I)) {
		if (!I->context) {
			I->context = &r_cons_context_default;
		}
	} else {
		I = &s_cons_global;
		I->context = &r_cons_context_default;
		init_cons_input (&I->input_state);
	}
}
#endif

R_API bool r_cons_is_initialized(void) {
	return I != NULL;
}

R_API RColor r_cons_color_random(RCons *cons, ut8 alpha) {
	RColor rcolor = {0};
	RConsContext *ctx = cons->context;
	if (ctx->color_mode > COLOR_MODE_16) {
		rcolor.r = r_num_rand (0xff);
		rcolor.g = r_num_rand (0xff);
		rcolor.b = r_num_rand (0xff);
		rcolor.a = alpha;
		return rcolor;
	}
	int r = r_num_rand (16);
	switch (r) {
	case 0: case 1: rcolor = (RColor) RColor_RED; break;
	case 2: case 3: rcolor = (RColor) RColor_WHITE; break;
	case 4: case 5: rcolor = (RColor) RColor_GREEN; break;
	case 6: case 7: rcolor = (RColor) RColor_MAGENTA; break;
	case 8: case 9: rcolor = (RColor) RColor_YELLOW; break;
	case 10: case 11: rcolor = (RColor) RColor_CYAN; break;
	case 12: case 13: rcolor = (RColor) RColor_BLUE; break;
	case 14: case 15: rcolor = (RColor) RColor_GRAY; break;
	}
	if (r & 1) {
		rcolor.attr = R_CONS_ATTR_BOLD;
	}
	return rcolor;
}

R_API void r_cons_print_justify(RCons *cons, const char *str, int j, char c) {
	int i, o, len;
	for (o = i = len = 0; str[i]; i++, len++) {
		if (str[i] == '\n') {
			r_cons_memset (cons, ' ', j);
			if (c) {
				r_cons_memset (cons, c, 1);
				r_cons_memset (cons, ' ', 1);
			}
			r_cons_write (cons, str + o, len);
			if (str[o + len] == '\n') {
				r_cons_newline (cons);
			}
			o = i + 1;
			len = 0;
		}
	}
	if (len > 1) {
		r_cons_write (cons, str + o, len);
	}
}

R_API void r_cons_print_at(RCons *cons, const char *_str, int x, char y, int w, int h) {
	int i, o, len;
	int cols = 0;
	int rows = 0;
	if (x < 0 || y < 0) {
		int H, W = r_cons_get_size (cons, &H);
		if (x < 0) {
			x += W;
		}
		if (y < 0) {
			y += H;
		}
	}
	// TODO: what happens if w == 0 || h == 0 ?
	char *str = r_str_ansi_crop (_str, 0, 0, w + 1, h);
	r_cons_print (cons, R_CONS_CURSOR_SAVE);
	for (o = i = len = 0; str[i]; i++, len++) {
		if (w < 0 || rows > w) {
			break;
		}
		if (str[i] == '\n') {
			r_cons_gotoxy (cons, x, y + rows);
			size_t ansilen = r_str_ansi_len (str + o);
			cols = R_MIN (w, ansilen);
			const char *end = r_str_ansi_chrn (str + o, cols);
			cols = end - str + o;
			r_cons_write (cons, str + o, R_MIN (len, cols));
			o = i + 1;
			len = 0;
			rows++;
		}
	}
	if (len > 1) {
		r_cons_gotoxy (cons, x, y + rows);
		r_cons_write (cons, str + o, len);
	}
	r_cons_print (cons, Color_RESET);
	r_cons_print (cons, R_CONS_CURSOR_RESTORE);
	free (str);
}

#if 0
R_API RConsContext *r_cons_context(void) {
	return C;
}
#endif

R_API RCons *r_cons_global(RCons *c) {
	if (c) {
		I = c;
	}
	return I;
}

R_API RCons *r_cons_singleton(void) {
	if (!I) {
		r_cons_new ();
	}
	// eprintf ("INIT CONS\n");
	return I;
}

R_API void r_cons_break_clear(RCons *cons) {
	RConsContext *ctx = cons->context;
	ctx->was_breaked = false;
	ctx->breaked = false;
}

R_API void r_cons_context_break_push(RCons* cons, RConsContext *context, RConsBreak cb, void *user, bool sig) {
	// eprintf ("Brk.push\n");
#if WANT_DEBUGSTUFF
	if (!context || !context->break_stack) {
		return;
	}
	// if we don't have any element in the stack start the signal
	RConsBreakStack *b = R_NEW0 (RConsBreakStack);
	if (r_stack_is_empty (context->break_stack)) {
#if R2__UNIX__
		if (!context->unbreakable) {
			if (sig && r_cons_context_is_main (cons, context)) {
				r_sys_signal (SIGINT, __break_signal);
			}
		}
#endif
		context->breaked = false;
	}
	// save the actual state
	b->event_interrupt = context->event_interrupt;
	b->event_interrupt_data = context->event_interrupt_data;
	r_stack_push (context->break_stack, b);
	// configure break
	context->event_interrupt = cb;
	context->event_interrupt_data = user;
#endif
}

R_API void r_cons_context_break_pop(RCons *cons, RConsContext *context, bool sig) {
	// eprintf ("Brk.pop\n");
#if WANT_DEBUGSTUFF
	if (!context || !context->break_stack) {
		return;
	}
	//restore old state
	RConsBreakStack *b = NULL;
	b = r_stack_pop (context->break_stack);
	if (b) {
		context->event_interrupt = b->event_interrupt;
		context->event_interrupt_data = b->event_interrupt_data;
		break_stack_free (b);
	} else {
		//there is not more elements in the stack
#if R2__UNIX__ && !__wasi__
		if (sig && r_cons_context_is_main (cons, context)) {
			if (!context->unbreakable) {
				r_sys_signal (SIGINT, SIG_IGN);
			}
		}
#endif
		context->was_breaked = context->breaked;
		context->breaked = false;
	}
#endif
}

R_API bool r_cons_is_interactive(RCons *cons) {
	return cons->context->is_interactive;
}

#if 0
R_API bool r_cons_default_context_is_interactive(void) {
	// XXX this is pure evil
	return I->context->is_interactive;
}
#endif

R_API bool r_cons_was_breaked(RCons *cons) {
#if WANT_DEBUGSTUFF
	const bool res = r_cons_is_breaked (cons) || cons->context->was_breaked;
	cons->context->breaked = false;
	cons->context->was_breaked = false;
	return res;
#else
	return false;
#endif
}

R_API bool r_cons_is_breaked(RCons *cons) {
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
				r_cons_break_timeout (cons, cons->otimeout);
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

// UNUSED
R_API void r_cons_line(RCons *cons, int x, int y, int x2, int y2, int ch) {
	char chstr[2] = {ch, 0};
	int X, Y;
	for (X = x; X < x2; X++) {
		for (Y = y; Y < y2; Y++) {
			r_cons_gotoxy (cons, X, Y);
			r_cons_print (cons, chstr);
		}
	}
}

#if 0
R_API void r_cons_color(RCons *cons, int fg, int r, int g, int b) {
	int k;
	r = R_DIM (r, 0, 255);
	g = R_DIM (g, 0, 255);
	b = R_DIM (b, 0, 255);
	if (r == g && g == b) { // b&w
		k = 232 + (int)(((r+g+b)/3)/10.3);
	} else {
		r = (int)(r / 42.6);
		g = (int)(g / 42.6);
		b = (int)(b / 42.6);
		k = 16 + (r * 36) + (g * 6) + b;
	}
	r_cons_printf (cons, "\x1b[%d;5;%dm", fg? 48: 38, k);
}

#endif

R_API int r_cons_get_cur_line(void) {
	int curline = 0;
#if R2__WINDOWS__
	CONSOLE_SCREEN_BUFFER_INFO info;
	if (!GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &info)) {
		return 0;
	}
	curline = info.dwCursorPosition.Y - info.srWindow.Top;
#endif

#ifdef __sun
static inline void cfmakeraw(struct termios *tm) {
	tm->c_cflag &= ~(CSIZE | PARENB);
	tm->c_cflag |= CS8;
	tm->c_iflag &= ~(IMAXBEL | IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	tm->c_oflag &= ~OPOST;
	tm->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
}
#endif

#if R2__UNIX__ && !__wasi__
	char buf[8];
	struct termios save,raw;
	// flush the Arrow keys escape keys which was messing up the output
	fflush (stdout);
	(void) tcgetattr (0, &save);
	cfmakeraw (&raw);
	(void) tcsetattr (0, TCSANOW, &raw);
	if (isatty (fileno (stdin))) {
		if (write (1, R_CONS_GET_CURSOR_POSITION, sizeof (R_CONS_GET_CURSOR_POSITION)) != -1) {
			if (read (0, buf, sizeof (buf)) != sizeof (buf)) {
				if (isdigit ((ut8)buf[2])) {
					curline = (buf[2] - '0');
				} if (isdigit ((ut8)buf[3])) {
					curline = curline * 10 + (buf[3] - '0');
				}
			}
		}
	}
	(void) tcsetattr (0, TCSANOW, &save);
#endif
	return curline;
}

R_API void r_cons_break_timeout(RCons *cons, int timeout) {
	if (timeout > 0) {
		cons->timeout = r_time_now_mono () + (timeout * 1000);
		cons->otimeout = timeout;
	} else {
		cons->otimeout = 0;
		cons->timeout = 0;
	}
#if 0
	I->timeout = (timeout && !I->timeout)
		? r_time_now_mono () + ((ut64) timeout << 20) : 0;
#endif
}

R_API void r_cons_set_click(RCons * R_NONNULL cons, int x, int y) {
	R_RETURN_IF_FAIL (cons);
	cons->click_x = x;
	cons->click_y = y;
	cons->click_set = true;
	cons->mouse_event = 1;
}

R_API bool r_cons_get_click(RCons * R_NONNULL cons, int *x, int *y) {
	R_RETURN_VAL_IF_FAIL (cons, false);
	if (x) {
		*x = cons->click_x;
	}
	if (y) {
		*y = cons->click_y;
	}
	bool set = cons->click_set;
	cons->click_set = false;
	return set;
}

R_API void r_cons_enable_highlight(RCons *cons, const bool enable) {
	cons->enable_highlight = enable;
}

R_API bool r_cons_enable_mouse(RCons *cons, const bool enable) {
	bool enabled = cons->mouse;
#if R2__WINDOWS__
	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);
	DWORD mode = 0;
	GetConsoleMode (h, &mode);
	mode |= ENABLE_EXTENDED_FLAGS;
	mode |= enable
		? (mode | ENABLE_MOUSE_INPUT) & ~ENABLE_QUICK_EDIT_MODE
		: (mode & ~ENABLE_MOUSE_INPUT) | ENABLE_QUICK_EDIT_MODE;
	if (SetConsoleMode (h, mode)) {
		cons->mouse = enable;
	}
#else
	if (cons->vtmode == 2) {
		const char *click = enable
			? "\x1b[?1000;1006;1015h"
			: "\x1b[?1000;1006;1015l";
		const size_t click_len = strlen (click);
		if (write (2, click, click_len) != click_len) {
			enabled = false;
		} else {
			cons->mouse = enable;
		}
	}
#endif
	return enabled;
}

R_API RCons *r_cons_new(void) {
	RCons *cons = r_cons_new2 ();
	if (I) {
		R_LOG_INFO ("Second cons!");
		I = cons;
	} else {
		I = cons;
	}
	return cons;
}

R_API void r_cons_free(RCons *cons) {
	r_cons_free2 (cons);
	if (cons == I) {
		I = NULL; // hack for globals
	}
	free (cons);
}

R_API void r_cons_fill_line(RCons *cons) {
	char white[1024];
	int cols = cons->columns - 1;
	if (cols < 1) {
		return;
	}
	char *p = (cols >= sizeof (white))? malloc (cols + 1): white;
	if (p) {
		memset (p, ' ', cols);
		p[cols] = 0;
		r_cons_print (cons, p);
		if (white != p) {
			free (p);
		}
	}
}

R_API void r_cons_filter(RCons *cons) {
	RConsContext *ctx = cons->context;
	/* grep */
	if (ctx->filter || ctx->grep.tokens_used \
			|| (ctx->grep.strings && r_list_length (ctx->grep.strings) > 0) \
			|| ctx->grep.less || ctx->grep.json) {
		(void)r_cons_grepbuf (cons);
		ctx->filter = false;
	}
	/* html */
	if (ctx->is_html) {
		int newlen = 0;
		char *input = r_str_ndup (ctx->buffer, ctx->buffer_len);
		char *res = r_str_html_strip (input, &newlen);
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

R_API void r_cons_context_load(RConsContext *context) {
	if (!I) {
		I = &s_cons_global;
	}
	I->context = context;
}

R_API void r_cons_context_reset(RConsContext *context) {
	// XXX does nothing
#if 0
	while (r_cons_pop (I)) {
		// you cant stop
	}
#endif
}

R_API void r_cons_context_break(RConsContext *context) {
	// eprintf ("ctx.brk\n");
	if (R_LIKELY (context)) {
		context->breaked = true;
		if (context->event_interrupt) {
			context->event_interrupt (context->event_interrupt_data);
		}
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

R_API void r_cons_flush(RCons *cons) {
	RConsContext *ctx = cons->context;
	const char *tee = cons->teefile;
	if (ctx->noflush) {
		return;
	}
	if (cons->null) {
		r_cons_reset (cons);
		return;
	}
#if 0
	if (!r_list_empty (ctx->marks)) {
		r_list_free (ctx->marks);
		ctx->marks = r_list_newf ((RListFree)r_cons_mark_free);
	}
#endif
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
	r_cons_filter (cons);
	if (!ctx->buffer || ctx->buffer_len < 1) {
		r_cons_reset (cons);
		return;
	}
	if (r_cons_is_interactive (cons) && cons->fdout == 1) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (ctx->pageable && R_STR_ISNOTEMPTY (cons->pager) && ctx->buffer_len > 0 && r_str_char_count (ctx->buffer, '\n') >= cons->rows) {
			ctx->buffer[ctx->buffer_len - 1] = 0;
			if (!strcmp (cons->pager, "..")) {
				char *str = r_str_ndup (ctx->buffer, ctx->buffer_len);
				ctx->pageable = false;
				r_cons_less_str (cons, str, NULL);
				r_cons_reset (cons);
				free (str);
				return;
			}
			r_sys_cmd_str_full (cons->pager, ctx->buffer, -1, NULL, NULL, NULL);
			r_cons_reset (cons);
		} else if (cons->maxpage > 0 && ctx->buffer_len > cons->maxpage) {
#if COUNT_LINES
			char *buffer = ctx->buffer;
			int i, lines = 0;
			for (i = 0; buffer[i]; i++) {
				if (buffer[i] == '\n') {
					lines ++;
				}
			}
			if (lines > 0 && !r_cons_yesno (cons, 'n',"Do you want to print %d lines? (y/N)", lines)) {
				r_cons_reset (cons);
				return;
			}
#else
			char buf[8];
			r_num_units (buf, sizeof (buf), ctx->buffer_len);
			if (!r_cons_yesno (cons, 'n', "Do you want to print %s chars? (y/N)", buf)) {
				r_cons_reset (cons);
				return;
			}
#endif
			// fix | more | less problem
			r_cons_set_raw (cons, true);
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
	r_cons_highlight (cons, cons->highlight);

	if (r_cons_is_interactive (cons) && !r_sandbox_enable (false)) {
		if (cons->linesleep > 0 && cons->linesleep < 1000) {
			int i = 0;
			int pagesize = R_MAX (1, cons->pagesize);
			char *ptr = ctx->buffer;
			char *nl = strchr (ptr, '\n');
			int len = ctx->buffer_len;
			ctx->buffer[ctx->buffer_len] = 0;
			r_cons_break_push (cons, NULL, NULL);
			while (nl && !r_cons_is_breaked (cons)) {
				__cons_write (cons, ptr, nl - ptr + 1);
				if (cons->linesleep && !(i % pagesize)) {
					r_sys_usleep (cons->linesleep * 1000);
				}
				ptr = nl + 1;
				nl = strchr (ptr, '\n');
				i++;
			}
			__cons_write (cons, ptr, ctx->buffer + len - ptr);
			r_cons_break_pop (cons);
		} else {
			__cons_write (cons, ctx->buffer, ctx->buffer_len);
		}
	} else {
		__cons_write (cons, ctx->buffer, ctx->buffer_len);
	}

	r_cons_reset (cons);
	if (ctx->tmp_html) {
		ctx->is_html = ctx->was_html;
		ctx->tmp_html = false;
		ctx->was_html = false;
	}
}


#if 0
// UNUSED
R_API int r_cons_get_column(RCons *cons) {
	RConsContext *C = cons->context;
	char *line = strrchr (C->buffer, '\n');
	if (!line) {
		line = C->buffer;
	}
	C->buffer[C->buffer_len] = 0;
	return r_str_ansi_len (line);
}
#endif

R_API bool r_cons_is_windows(void) {
#if R2__WINDOWS__
	return true;
#else
	char *e = r_sys_getenv ("WSL_INTEROP");
	bool res = R_STR_ISNOTEMPTY (e);
	free (e);
	return res;
#endif
}

R_API bool r_cons_is_tty(void) {
#if EMSCRIPTEN || __wasi__
	return false;
#elif R2__UNIX__
	struct winsize win = {0};
	struct stat sb = {0};

	if (!isatty (1)) {
		return false;
	}
	if (ioctl (1, TIOCGWINSZ, &win)) {
		return false;
	}
	if (!win.ws_col || !win.ws_row) {
		return false;
	}
	char ttybuf[64];
	if (ttyname_r (1, ttybuf, sizeof (ttybuf))) {
		return false;
	}
	const char *tty = ttybuf;
	if (stat (tty, &sb) || !S_ISCHR (sb.st_mode)) {
		return false;
	}
	return true;
#elif R2__WINDOWS__
	HANDLE hOut = GetStdHandle (STD_OUTPUT_HANDLE);
	if (GetFileType (hOut) == FILE_TYPE_CHAR) {
		DWORD unused;
		return GetConsoleMode (hOut, &unused);
	}
	return false;
#else
	/* non-UNIX do not have ttys */
	return false;
#endif
}

R_API void r_cons_invert(RCons *cons, int set, int color) {
	r_cons_print (cons, R_CONS_INVERT (set, color));
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
		ch = r_cons_readchar (cons);
		if (ch != 0x1b) {
			while ((ch = r_cons_readchar_timeout (cons, 25))) {
				if (ch < 1) {
					return 0;
				}
				if (ch == 0x1b) {
					break;
				}
			}
		}
		(void)r_cons_readchar (cons);
		for (i = 0; i < R_ARRAY_SIZE (pos) - 1; i++) {
			ch = r_cons_readchar (cons);
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
		if ((ch = r_cons_readchar (cons)) == 'R') {
			pos[i] = 0;
			break;
		}
		pos[i] = ch;
	}
	pos[R_ARRAY_SIZE (pos) - 1] = 0;
	*xpos = atoi (pos);

	return ypos;
}

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

// This function will never return rows or cols lower than 0
R_API int r_cons_get_size(RCons *cons, int * R_NULLABLE rows) {
	R_RETURN_VAL_IF_FAIL (cons, 0);
	bool pick_defaults = false;
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
			pick_defaults = true;
		}
	}
#elif R2__UNIX__ && !__wasi__
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
					pick_defaults = true;
				}
				close (fd);
			}
		}
		if (!pick_defaults) {
			cons->columns = win.ws_col;
			cons->rows = win.ws_row;
		}
	} else {
		pick_defaults = true;
	}
#endif
	if (pick_defaults || cons->columns < 1 || cons->rows < 1) {
		char *cols = r_sys_getenv ("COLUMNS");
		cons->columns = cols? atoi (cols): 80;
		free (cols);
		char *rows = r_sys_getenv ("ROWS");
		cons->rows = rows? atoi (rows): 23;
		free (rows);
	}
#if SIMULATE_ADB_SHELL
	cons->rows = 0;
	cons->columns = 0;
#else
	if (cons->rows < 0) {
		cons->rows = 0;
	}
	if (cons->columns < 0) {
		cons->columns = 0;
	}
#endif
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
	if (cons->rows < 0) {
		cons->rows = 0;
	}
	if (rows) {
		*rows = cons->rows;
	}
	cons->rows = R_MAX (0, cons->rows);
	return R_MAX (0, cons->columns);
}

#if 0
Enable/Disable scrolling in terminal:
FMI: cd libr/cons/t ; make ti ; ./ti
smcup: disable terminal scrolling (fullscreen mode)
rmcup: enable terminal scrolling (normal mode)
#endif
R_API bool r_cons_set_cup(bool enable) {
#if R2__UNIX__
	const char *code = enable
		? "\x1b[?1049h" "\x1b" "7\x1b[?47h"
		: "\x1b[?1049l" "\x1b[?47l" "\x1b" "8";
	const size_t code_len = strlen (code);
	if (write (2, code, code_len) != code_len) {
		return false;
	}
	fflush (stdout);
#elif R2__WINDOWS__
	if (I->vtmode) {
		if (enable) {
			const char *code = enable // xterm + xterm-color
			? "\x1b[?1049h\x1b" "7\x1b[?47h"
			: "\x1b[?1049l\x1b[?47l""\x1b""8";
			const size_t code_len = strlen (code);
			if (write (2, code, code_len) != code_len) {
				return false;
			}
		}
		fflush (stdout);
	}
#endif
	return true;
}

/* swap color from foreground to background, returned value must be freed */
R_API char *r_cons_swap_ground(const char *col) {
	if (!col) {
		return NULL;
	}
	if (r_str_startswith (col, "\x1b[48;5;")) {
		/* rgb background */
		return r_str_newf ("\x1b[38;5;%s", col + 7);
	}
	if (r_str_startswith (col, "\x1b[38;5;")) {
		/* rgb foreground */
		return r_str_newf ("\x1b[48;5;%s", col + 7);
	}
	if (r_str_startswith (col, "\x1b[4")) {
		/* is background */
		return r_str_newf ("\x1b[3%s", col + 3);
	}
	if (r_str_startswith (col, "\x1b[3")) {
		/* is foreground */
		return r_str_newf ("\x1b[4%s", col + 3);
	}
	return strdup (col);
}

static void mygrep(RCons *cons, const char *grep) {
	r_cons_grep_expression (cons, grep);
	r_cons_grepbuf (cons);
}

R_API void r_cons_bind(RCons *cons, RConsBind *bind) {
	R_RETURN_IF_FAIL (cons && bind);
	bind->cons = cons;
	bind->get_size = r_cons_get_size;
	bind->get_cursor = r_cons_get_cursor;
	bind->cb_printf = r_cons_printf;
	bind->cb_write = r_cons_write;
	bind->cb_flush = r_cons_flush;
	bind->cb_grep = mygrep;
	bind->is_breaked = r_cons_is_breaked;
}

#if WITH_STATIC_THEMES
#include "d_themes.inc.c"

R_API const RConsTheme* r_cons_themes(void) {
	return (const RConsTheme *)d_themes;
}

#else
R_API const RConsTheme* r_cons_themes(void) {
	return NULL;
}
#endif

// TODO: deprecate
R_API int r_cons_gprintf(const char *format, ...) {
	va_list ap;
	if (R_STR_ISEMPTY (format)) {
		return -1;
	}
	va_start (ap, format);
	r_cons_printf_list (I, format, ap);
	va_end (ap);
	return 0;
}

R_API void r_cons_set_utf8(RCons *cons, bool b) {
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

R_API void r_cons_memset(RCons *cons, char ch, int len) {
	RConsContext *C = cons->context;
	if (C->breaked) {
		return;
	}
	if (!cons->null && len > 0) {
		if ((len = kons_chop (cons, len)) < 1) {
			return;
		}
		if (cons_palloc (cons, len + 1)) {
			memset (C->buffer + C->buffer_len, ch, len);
			C->buffer_len += len;
			C->buffer[C->buffer_len] = 0;
		}
	}
}

R_API int r_cons_write(RCons *cons, const void *data, int len) {
	R_RETURN_VAL_IF_FAIL (data && len >= 0, -1);
	const char *str = data;
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
		if (cons_palloc (cons, len + 1)) {
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
		r_cons_flush (cons);
	}
	if (cons->break_word && str && len > 0) {
		if (r_mem_mem ((const ut8*)str, len, (const ut8*)cons->break_word, cons->break_word_len)) {
			ctx->breaked = true;
		}
	}
	return len;
}

R_API void r_cons_mark(RCons *cons, ut64 addr, const char *name) {
	RConsMark *mark = R_NEW0 (RConsMark);
	RConsContext *ctx = cons->context;
	mark->addr = addr;
	int row = 0, col = r_cons_get_cursor (cons, &row);
	mark->name = strdup (name); // TODO. use a const pool instead
	mark->pos = ctx->buffer_len;
	mark->col = col;
	mark->row = row;
	r_list_append (ctx->marks, mark);
}

R_API RConsMark *r_cons_mark_at(RCons *cons, ut64 addr, const char *name) {
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

R_API void r_cons_breakword(RCons *cons, const char * R_NULLABLE s) {
	free (cons->break_word);
	if (s) {
		cons->break_word = strdup (s);
		cons->break_word_len = strlen (s);
	} else {
		cons->break_word = NULL;
		cons->break_word_len = 0;
	}
}

R_API void r_cons_clear_buffer(RCons *cons) {
	if (cons->vtmode) {
		// not implemented or ignored by most terminals out there...
		if (write (1, "\x1b" "c\x1b[3J", 6) != 6) {
			cons->context->breaked = true;
		}
	}
}

R_API void r_cons_set_raw(RCons *cons, bool is_raw) {
	if (cons->oldraw != 0) {
		if (is_raw == cons->oldraw - 1) {
			return;
		}
	}
#if EMSCRIPTEN || __wasi__
	/* do nothing here */
#elif R2__UNIX__
	struct termios *term_mode;
	if (is_raw) {
		cons->term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
		term_mode = &cons->term_raw;
	} else {
		term_mode = &cons->term_buf;
	}
	if (tcsetattr (0, TCSANOW, term_mode) == -1) {
		return;
	}
#elif R2__WINDOWS__
	if (cons->term_xterm) {
		char *stty = r_file_path ("stty");
		if (!stty || *stty == 's') {
			cons->term_xterm = false;
		}
		free (stty);
	}
	if (cons->term_xterm) {
		const char *cmd = is_raw
			? "stty raw -echo"
			: "stty raw echo";
		r_sandbox_system (cmd, 1);
	} else {
		if (!SetConsoleMode (h, is_raw? cons->term_raw: cons->term_buf)) {
			return;
		}
	}
#else
#warning No raw console supported for this platform
#endif
	cons->oldraw = is_raw + 1;
}

R_API void r_cons_newline(RCons *cons) {
	if (!cons->null) {
		r_cons_print (cons, "\n");
	}
#if 0
This place is wrong to manage the color reset, can interfire with r2pipe output sending resetchars
and break json output appending extra chars.
this code now is managed into output.c:118 at function r_cons_win_print
now the console color is reset with each \n (same stuff do it here but in correct place ... i think)

#if R2__WINDOWS__
	r_cons_reset_colors();
#else
	r_cons_print (cons, Color_RESET_ALL"\n");
#endif
	if (cons->is_html) r_cons_print (cons, "<br />\n");
#endif
}

R_API void r_cons_printf_list(RCons *cons, const char *format, va_list ap) {
	va_list ap2, ap3;

	va_copy (ap2, ap);
	va_copy (ap3, ap);
	if (cons->null || !format) {
		va_end (ap2);
		va_end (ap3);
		return;
	}
	if (strchr (format, '%')) {
		if (cons_palloc (cons, MOAR + strlen (format) * 20)) {
			bool need_retry = true;
			while (need_retry) {
				need_retry = false;
				size_t left = cons->context->buffer_sz - cons->context->buffer_len;
				size_t written = vsnprintf (cons->context->buffer + cons->context->buffer_len, left, format, ap3);
				if (written >= left) {
					if (cons_palloc (cons, written + 1)) {
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
		r_cons_print (cons, format);
	}
	va_end (ap2);
	va_end (ap3);
}

R_API void r_cons_println(RCons *cons, const char* str) {
	r_cons_print (cons, str);
	r_cons_newline (cons);
}

R_API void r_cons_column(RCons *cons, int c) {
	RConsContext *ctx = cons->context;
	char *b = malloc (ctx->buffer_len + 1);
	if (!b) {
		return;
	}
	memcpy (b, ctx->buffer, ctx->buffer_len);
	b[ctx->buffer_len] = 0;
	r_cons_reset (cons);
	// align current buffer N chars right
	r_cons_print_justify (cons, b, c, 0);
	free (b);
	r_cons_gotoxy (cons, 0, 0);
}

R_API void r_cons_gotoxy(RCons *cons, int x, int y) {
#if R2__WINDOWS__
	r_cons_win_gotoxy (cons, 1, x, y);
#else
	r_cons_printf (cons, "\x1b[%d;%dH", y, x);
#endif
}

R_API void r_cons_reset(RCons *cons) {
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

R_API void r_cons_reset_colors(RCons *cons) {
	r_cons_print (cons, Color_RESET_BG Color_RESET);
}

R_API void r_cons_context_free(RConsContext * R_NULLABLE ctx) {
	if (ctx) {
		r_cons_context_pal_free (ctx);
		r_stack_free (ctx->break_stack);

		// Free the marks list
		r_list_free (ctx->marks);

		// Free the grep strings list
		r_list_free (ctx->grep.strings);

		// Free sorted and unsorted lines
		r_list_free (ctx->sorted_lines);
		r_list_free (ctx->unsorted_lines);

		// Free the buffer and lastOutput
		free (ctx->buffer);
		free (ctx->lastOutput);
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
	// Don't clone marks to avoid double free issues
	c->marks = r_list_newf ((RListFree)mark_free);
	if (ctx->sorted_lines) {
		c->sorted_lines = r_list_clone (ctx->sorted_lines, (RListClone)strdup);
	}
	if (ctx->unsorted_lines) {
		c->unsorted_lines = r_list_clone (ctx->unsorted_lines, (RListClone)strdup);
	}
	c->pal.rainbow = NULL;
	pal_clone (c);
	// rainbow_clone (c);
	memset (&c->grep, 0, sizeof (c->grep));
	c->grep.strings = r_list_newf ((RListFree)grep_word_free);
	c->grep.line = -1;
	c->grep.sort = -1;
	c->grep.sort_invert = false;
	return c;
}

R_API bool r_cons_context_is_main(RCons *cons, RConsContext *ctx) {
	if (r_list_length (cons->ctx_stack) == 0) {
		return true;
	}
	RConsContext *first_context = r_list_get_n (cons->ctx_stack, 0);
	return ctx == first_context;
}

R_API void r_cons_break_end(RCons *cons) {
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

R_API void r_cons_break_push(RCons *cons, RConsBreak cb, void *user) {
	RConsContext *ctx = cons->context;
	if (ctx->break_stack && r_stack_size (ctx->break_stack) > 0) {
		r_cons_break_timeout (cons, cons->otimeout);
	}
	r_cons_context_break_push (cons, ctx, cb, user, true);
}

R_API void r_cons_break_pop(RCons *cons) {
	cons->timeout = 0;
	r_cons_context_break_pop (cons, cons->context, true);
}

R_API void *r_cons_sleep_begin(RCons *cons) {
	R_CRITICAL_ENTER (cons);
	if (cons->cb_sleep_begin) {
		return cons->cb_sleep_begin (cons->user);
	}
	return NULL;
}

R_API void r_cons_sleep_end(RCons *cons, void *user) {
	if (cons->cb_sleep_end) {
		cons->cb_sleep_end (cons->user, user);
	}
	R_CRITICAL_LEAVE (cons);
}

R_API void r_cons_trim(RCons *cons) {
	RConsContext *c = cons->context;
	while (c->buffer_len > 0) {
		char ch = c->buffer[c->buffer_len - 1];
		if (ch != '\n' && !IS_WHITESPACE (ch)) {
			break;
		}
		c->buffer_len--;
	}
}

R_API bool r_cons_drop(RCons *cons, int n) {
	RConsContext *c = cons->context;
	if (n > c->buffer_len) {
		c->buffer_len = 0;
		return false;
	}
	c->buffer_len -= n;
	return true;
}

R_API void r_cons_push(RCons *cons) {
	r_list_push (cons->ctx_stack, cons->context);
	RConsContext *nc = r_cons_context_clone (cons->context);
	// Free the buffer in the cloned context since we're going to reset it anyway
	free (nc->buffer);
	nc->buffer = NULL;
	nc->buffer_sz = 0;
	nc->buffer_len = 0;
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

R_API bool r_cons_pop(RCons *cons) {
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

R_API void r_cons_echo(RCons *cons, const char *msg) {
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
			r_cons_print (cons, data);
			r_cons_newline (cons);
			cons->echodata = NULL;
			free (data);
		}
	}
}

R_API void r_cons_show_cursor(RCons *cons, int cursor) {
	RConsContext *C = cons->context;
#if R2__WINDOWS__
	if (cons->vtmode) {
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

R_API void r_cons_print_clear(RCons *cons) {
	r_cons_print (cons, "\x1b[0;0H\x1b[0m");
}

R_API char *r_cons_lastline(RCons *cons, int *len) {
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
#if 0
// same as r_cons_lastline(), but len will be the number of
// utf-8 characters excluding ansi escape sequences as opposed to just bytes
R_API char *r_cons_lastline_utf8_ansi_len(RCons *cons, int *len) {
	RConsContext *c = cons->context;
	if (!len) {
		return r_cons_lastline (cons, 0);
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
#endif

R_API void r_cons_highlight(RCons *cons, const char *word) {
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

R_API void r_cons_set_interactive(RCons *cons, bool x) {
	RConsContext *ctx = cons->context;
	cons->lasti = ctx->is_interactive;
	ctx->is_interactive = x;
}

R_API void r_cons_set_last_interactive(RCons *cons) {
	cons->context->is_interactive = cons->lasti;
}

R_API void r_cons_last(RCons *cons) {
	RConsContext *ctx = cons->context;
	if (!ctx->lastEnabled) {
		return;
	}
	ctx->lastMode = true;
	if (ctx->lastLength > 0) {
		r_cons_write (cons, ctx->lastOutput, ctx->lastLength);
	}
}

R_API void r_cons_clear_line(RCons *cons, int std_err) {
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

R_API void r_cons_clear(RCons *cons) {
	cons->lines = 0;
#if R2__WINDOWS__
	r_cons_win_clear (cons);
#else
	r_cons_print (cons, Color_RESET R_CONS_CLEAR_SCREEN);
#endif
}

R_API void r_cons_clear00(RCons *cons) {
	r_cons_clear (cons);
	r_cons_gotoxy (cons, 0, 0);
}

R_API char *r_cons_drain(RCons *cons) {
	size_t buf_size;
	const char *buf = r_cons_get_buffer (cons, &buf_size);
	char *s = r_str_ndup (buf, buf_size);
	r_cons_reset (cons);
	return s;
}
/* return the aproximated x,y of cursor before flushing */
// XXX this function is a huge bottleneck
R_API int r_cons_get_cursor(RCons *cons, int *rows) {
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

R_API const char *r_cons_get_buffer(RCons *cons, size_t *buffer_len) {
	RConsContext *ctx = cons->context;
	if (buffer_len) {
		*buffer_len = ctx->buffer_len;
	}
	// check len otherwise it will return trash
	return (ctx->buffer_len > 0)? ctx->buffer : NULL;
}

#if 0
#if R2__WINDOWS__
R_IPI int r_cons_is_vtcompat(RCons *cons) {
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
#endif

R_API void r_cons_set_title(RCons *cons, const char *str) {
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
	r_cons_printf (cons, "\x1b]0;%s\007", str);
#endif
}

R_API void r_cons_zero(RCons *cons) {
	if (cons->line) {
		cons->line->zerosep = true;
	}
	if (write (1, "", 1) != 1) {
		cons->context->breaked = true;
	}
}

R_API void r_cons_print(RCons *cons, const char *str) {
	R_RETURN_IF_FAIL (str);
	if (cons->null) {
		return;
	}
	size_t len = strlen (str);
	if (len > 0) {
		r_cons_write (cons, str, len);
	}
}

R_API int r_cons_printf(RCons *cons, const char *format, ...) {
	va_list ap;
	if (R_STR_ISEMPTY (format)) {
		return -1;
	}
	va_start (ap, format);
	r_cons_printf_list (cons, format, ap);
	va_end (ap);
	return 0;
}

#if R2_USE_NEW_ABI
R_API void r_cons_break(RCons *cons) {
	if (!cons) {
		if (!I) {
			return;
		}
		cons = I;
	}
	r_cons_context_break (cons->context);
#if R2__UNIX__ && !__wasi__
	/* Trigger a SIGINT so threads or blocking syscalls can be interrupted. */
	raise (SIGINT);
#endif
}
#endif
