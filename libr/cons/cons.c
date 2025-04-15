/* radare2 - LGPL - Copyright 2008-2025 - pancake, Jody Frankowski */

#include <r_cons.h>
#include <r_util.h>
#include <r_util/r_print.h>

#define COUNT_LINES 1

R_LIB_VERSION (r_cons);

static R_TH_LOCAL int oldraw = -1;
static R_TH_LOCAL RConsContext r_cons_context_default = {0};
static RCons g_cons_instance = {0};
static R_TH_LOCAL RCons g_cons_instance_tls = {0};
static R_TH_LOCAL RCons *r_cons_instance = NULL;
static R_TH_LOCAL ut64 prev = 0LL; //r_time_now_mono ();
static R_TH_LOCAL RStrBuf *echodata = NULL; // TODO: move into RConsInstance? maybe nope
#define I (r_cons_instance)
#define C (getctx ())

static inline void init_cons_input(InputState *state) {
	state->readbuffer = NULL;
	state->readbuffer_length = 0;
	state->bufactive = true;
}

static inline void init_cons_instance(void) {
	if (R_UNLIKELY (!r_cons_instance)) {
		r_cons_instance = &g_cons_instance;
		r_cons_instance->context = &r_cons_context_default;
		init_cons_input (&r_cons_instance->input_state);
	}
}

static RConsContext *getctx(void) {
	init_cons_instance ();
	return r_cons_instance->context;
}

R_API InputState *r_cons_input_state(void) {
	init_cons_instance ();
	return &r_cons_instance->input_state;
}

R_API bool r_cons_is_initialized(void) {
	return r_cons_instance != NULL;
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

static void r_cons_grep_word_free(RConsGrepWord *gw) {
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
		grep->strings = r_list_newf ((RListFree)r_cons_grep_word_free);
		grep->line = -1;
		grep->sort = -1;
		grep->sort_invert = false;
	}
}

static void break_stack_free(void *ptr) {
	RConsBreakStack *b = (RConsBreakStack*)ptr;
	free (b);
}

static void cons_stack_free(void *ptr) {
	RConsStack *s = (RConsStack *)ptr;
	R_FREE (s->buf);
	cons_grep_reset (s->grep);
	R_FREE (s->grep);
	free (s);
	C->grep.str = NULL;
	cons_grep_reset (&C->grep);
}

static RConsStack *cons_stack_dump(bool recreate) {
	RConsStack *data = R_NEW0 (RConsStack);
	if (data) {
		if (C->buffer) {
			data->buf = C->buffer;
			data->buf_len = C->buffer_len;
			data->buf_size = C->buffer_sz;
		}
		data->grep = R_NEW0 (RConsGrep);
		if (data->grep) {
			memcpy (data->grep, &C->grep, sizeof (RConsGrep));
			if (C->grep.str) {
				data->grep->str = strdup (C->grep.str);
			}
		}
		if (recreate && C->buffer_sz > 0) {
			C->buffer = malloc (C->buffer_sz);
			if (R_UNLIKELY (!C->buffer)) {
				C->buffer = data->buf;
				free (data);
				return NULL;
			}
		} else {
			C->buffer = NULL;
		}
	}
	return data;
}

static void cons_stack_load(RConsStack *data, bool free_current) {
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

static void init_cons_context(RConsContext *context, R_NULLABLE RConsContext *parent) {
	context->marks = r_list_newf ((RListFree)r_cons_mark_free);
	context->breaked = false;
	// context->cmd_depth = R_CONS_CMD_DEPTH + 1;
	context->buffer_sz = 0;
	context->lastEnabled = true;
	context->buffer_len = 0;
	context->is_interactive = false;
	context->cons_stack = r_stack_newf (6, cons_stack_free);
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

static void cons_context_deinit(RConsContext *context) {
	r_stack_free (context->cons_stack);
	r_list_free (context->marks);
	context->cons_stack = NULL;
	r_stack_free (context->break_stack);
	context->break_stack = NULL;
	r_cons_pal_free (context);
}

static void __break_signal(int sig) {
	r_cons_context_break (&r_cons_context_default);
}

static inline void __cons_write_ll(const char *buf, int len) {
#if R2__WINDOWS__
	if (I->vtmode) {
		(void) write (I->fdout, buf, len);
	} else {
		if (I->fdout == 1) {
			r_cons_w32_print (buf, len, false);
		} else {
			R_IGNORE_RETURN (write (I->fdout, buf, len));
		}
	}
#else
	if (I->fdout < 1) {
		I->fdout = 1;
	}
	R_IGNORE_RETURN (write (I->fdout, buf, len));
#endif
}

static inline void __cons_write(const char *obuf, int olen) {
	const size_t bucket = 64 * 1024;
	size_t i;
	if (olen < 0) {
		olen = strlen (obuf);
	}
	for (i = 0; (i + bucket) < olen; i += bucket) {
		__cons_write_ll (obuf + i, bucket);
	}
	if (i < olen) {
		__cons_write_ll (obuf + i, olen - i);
	}
}

R_API RColor r_cons_color_random(ut8 alpha) {
	RColor rcolor = {0};
	if (C->color_mode > COLOR_MODE_16) {
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

R_API void r_cons_color(int fg, int r, int g, int b) {
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
	r_cons_printf ("\x1b[%d;5;%dm", fg? 48: 38, k);
}

R_API void r_cons_println(const char* str) {
	r_cons_print (str);
	r_cons_newline ();
}

R_API void r_cons_printat(const char *str, int x, char y) {
	int i, o, len;
	int h, w = r_cons_get_size (&h);
	int lines = 0;
	for (o = i = len = 0; str[i]; i++, len++) {
		if (str[i] == '\n') {
			r_cons_gotoxy (x, y + lines);
			int wlen = R_MIN (len, w);
			r_cons_write (str + o, wlen);
			o = i + 1;
			len = 0;
			lines++;
		}
	}
	if (len > 0) {
		r_cons_gotoxy (x, y + lines);
		r_cons_write (str + o, len);
	}
}

R_API void r_cons_print_justify(const char *str, int j, char c) {
	int i, o, len;
	for (o = i = len = 0; str[i]; i++, len++) {
		if (str[i] == '\n') {
			r_cons_memset (' ', j);
			if (c) {
				r_cons_memset (c, 1);
				r_cons_memset (' ', 1);
			}
			r_cons_write (str + o, len);
			if (str[o + len] == '\n') {
				r_cons_newline ();
			}
			o = i + 1;
			len = 0;
		}
	}
	if (len > 1) {
		r_cons_write (str + o, len);
	}
}

R_API void r_cons_print_at(const char *_str, int x, char y, int w, int h) {
	int i, o, len;
	int cols = 0;
	int rows = 0;
	if (x < 0 || y < 0) {
		int H, W = r_cons_get_size (&H);
		if (x < 0) {
			x += W;
		}
		if (y < 0) {
			y += H;
		}
	}
	char *str = r_str_ansi_crop (_str, 0, 0, w + 1, h);
	r_cons_print (R_CONS_CURSOR_SAVE);
	for (o = i = len = 0; str[i]; i++, len++) {
		if (w < 0 || rows > w) {
			break;
		}
		if (str[i] == '\n') {
			r_cons_gotoxy (x, y + rows);
			int ansilen = r_str_ansi_len (str + o);
			cols = R_MIN (w, ansilen);
			const char *end = r_str_ansi_chrn (str + o, cols);
			cols = end - str + o;
			r_cons_write (str + o, R_MIN (len, cols));
			o = i + 1;
			len = 0;
			rows++;
		}
	}
	if (len > 1) {
		r_cons_gotoxy (x, y + rows);
		r_cons_write (str + o, len);
	}
	r_cons_print (Color_RESET);
	r_cons_print (R_CONS_CURSOR_RESTORE);
	free (str);
}

R_API RConsContext *r_cons_context(void) {
	return C;
}

R_API RCons *r_cons_singleton(void) {
	if (!I) {
		r_cons_new ();
	}
	return I;
}

R_API void r_cons_break_clear(void) {
	C->was_breaked = false;
	C->breaked = false;
}

R_API void r_cons_context_break_push(RConsContext *context, RConsBreak cb, void *user, bool sig) {
#if WANT_DEBUGSTUFF
	if (!context || !context->break_stack) {
		return;
	}
	// if we don't have any element in the stack start the signal
	RConsBreakStack *b = R_NEW0 (RConsBreakStack);
	if (!b) {
		return;
	}
	if (r_stack_is_empty (context->break_stack)) {
#if R2__UNIX__
		if (!C->unbreakable) {
			if (sig && r_cons_context_is_main ()) {
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

R_API void r_cons_context_break_pop(RConsContext *context, bool sig) {
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
		if (sig && r_cons_context_is_main ()) {
			if (!C->unbreakable) {
				r_sys_signal (SIGINT, SIG_IGN);
			}
		}
#endif
		C->was_breaked = C->breaked;
		context->breaked = false;
	}
#endif
}

R_API void r_cons_break_push(RConsBreak cb, void *user) {
	if (r_stack_size (C->break_stack) > 0) {
		r_cons_break_timeout (I->otimeout);
	}
	r_cons_context_break_push (C, cb, user, true);
}

R_API void r_cons_break_pop(void) {
	I->timeout = 0;
	r_cons_context_break_pop (C, true);
}

R_API bool r_cons_is_interactive(void) {
	return C->is_interactive;
}

R_API bool r_cons_default_context_is_interactive(void) {
	return r_cons_context_default.is_interactive;
}

R_API bool r_cons_was_breaked(void) {
#if WANT_DEBUGSTUFF
	const bool res = r_cons_is_breaked () || C->was_breaked;
	C->breaked = false;
	C->was_breaked = false;
	return res;
#else
	return false;
#endif
}

R_API bool r_cons_is_breaked(void) {
#if WANT_DEBUGSTUFF
	if (R_UNLIKELY (I->cb_break)) {
		I->cb_break (I->user);
	}
	if (R_UNLIKELY (I->timeout)) {
		if (r_stack_size (C->break_stack) > 0) {
			if (r_time_now_mono () > I->timeout) {
				C->breaked = true;
				C->was_breaked = true;
				r_cons_break_timeout (I->otimeout);
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

R_API void r_cons_line(int x, int y, int x2, int y2, int ch) {
	char chstr[2] = {ch, 0};
	int X, Y;
	for (X = x; X < x2; X++) {
		for (Y = y; Y < y2; Y++) {
			r_cons_gotoxy (X, Y);
			r_cons_print (chstr);
		}
	}
}

R_API int r_cons_get_cur_line(void) {
	int curline = 0;
#if R2__WINDOWS__
	CONSOLE_SCREEN_BUFFER_INFO info;
	if (!GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &info)) {
		return 0;
	}
	curline = info.dwCursorPosition.Y - info.srWindow.Top;
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

R_API void r_cons_break_timeout(int timeout) {
	if (timeout > 0) {
		I->timeout = r_time_now_mono () + (timeout * 1000);
		I->otimeout = timeout;
	} else {
		I->otimeout = 0;
		I->timeout = 0;
	}
#if 0
	I->timeout = (timeout && !I->timeout)
		? r_time_now_mono () + ((ut64) timeout << 20) : 0;
#endif
}

R_API void r_cons_break_end(void) {
	C->breaked = false;
	I->timeout = 0;
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

R_API void *r_cons_sleep_begin(void) {
	R_CRITICAL_ENTER (I);
	if (!r_cons_instance) {
		r_cons_thready ();
	}
	if (!I->cb_sleep_begin) {
		return NULL;
	}
	return I->cb_sleep_begin (I->user);
}

R_API void r_cons_sleep_end(void *user) {
	if (!r_cons_instance) {
		r_cons_thready ();
	}
	if (I->cb_sleep_end) {
		I->cb_sleep_end (I->user, user);
	}
	R_CRITICAL_LEAVE (I);
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
void resizeWin(void) {
	if (I->event_resize) {
		I->event_resize (I->event_data);
	}
}

R_API void r_cons_set_click(int x, int y) {
	I->click_x = x;
	I->click_y = y;
	I->click_set = true;
	I->mouse_event = 1;
}

R_API bool r_cons_get_click(int *x, int *y) {
	if (x) {
		*x = I->click_x;
	}
	if (y) {
		*y = I->click_y;
	}
	bool set = I->click_set;
	I->click_set = false;
	return set;
}

R_API void r_cons_enable_highlight(const bool enable) {
	I->enable_highlight = enable;
}

R_API bool r_cons_enable_mouse(const bool enable) {
	bool enabled = I->mouse;
#if R2__WINDOWS__
	HANDLE h = GetStdHandle (STD_INPUT_HANDLE);
	DWORD mode = 0;
	GetConsoleMode (h, &mode);
	mode |= ENABLE_EXTENDED_FLAGS;
	mode |= enable
		? (mode | ENABLE_MOUSE_INPUT) & ~ENABLE_QUICK_EDIT_MODE
		: (mode & ~ENABLE_MOUSE_INPUT) | ENABLE_QUICK_EDIT_MODE;
	if (SetConsoleMode (h, mode)) {
		I->mouse = enable;
	}
#else
	if (I->vtmode == 2) {
		const char *click = enable
			? "\x1b[?1000;1006;1015h"
			: "\x1b[?1000;1006;1015l";
		const size_t click_len = strlen (click);
		if (write (2, click, click_len) != click_len) {
			enabled = false;
		} else {
			I->mouse = enable;
		}
	}
#endif
	return enabled;
}

R_API RCons *r_cons_new(void) {
	if (!r_cons_instance) {
		r_cons_instance = &g_cons_instance;
	}
	I->refcnt++;
	if (I->refcnt != 1) {
		return I;
	}
	if (I->lock) {
		r_th_lock_wait (I->lock);
	} else {
		I->lock = r_th_lock_new (false);
	}
	R_CRITICAL_ENTER (I);
	I->use_utf8 = r_cons_is_utf8 ();
	I->rgbstr = r_cons_rgb_str_off;
	I->line = r_line_new ();
	I->enable_highlight = true;
	I->highlight = NULL;
	I->is_wine = -1;
	I->fps = 0;
	I->blankline = true;
	I->teefile = NULL;
	I->fix_columns = 0;
	I->fix_rows = 0;
	RVecFdPairs_init (&I->fds);
	I->mouse_event = 0;
	I->force_rows = 0;
	I->force_columns = 0;
	I->event_resize = NULL;
	I->event_data = NULL;
	I->linesleep = 0;
	I->fdin = stdin;
	I->fdout = 1;
	I->break_lines = false;
	I->lines = 0;
	I->maxpage = 102400;

	r_cons_context_reset ();
	init_cons_context (C, NULL);
	init_cons_input (&I->input_state);

	r_cons_get_size (&I->pagesize);
	I->num = NULL;
	I->null = 0;
#if R2__WINDOWS__
	I->old_cp = GetConsoleOutputCP ();
	I->vtmode = r_cons_is_vtcompat ();
#else
	I->vtmode = 2;
#endif
#if EMSCRIPTEN || __wasi__
	/* do nothing here :? */
#elif R2__UNIX__
	tcgetattr (0, &I->term_buf);
	memcpy (&I->term_raw, &I->term_buf, sizeof (I->term_raw));
	I->term_raw.c_iflag &= ~(BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	I->term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	I->term_raw.c_cflag &= ~(CSIZE|PARENB);
	I->term_raw.c_cflag |= CS8;
	I->term_raw.c_cc[VMIN] = 1; // Solaris stuff hehe
	r_sys_signal (SIGWINCH, resize);
#elif R2__WINDOWS__
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &I->term_buf);
	I->term_raw = 0;
	if (!SetConsoleCtrlHandler ((PHANDLER_ROUTINE)__w32_control, TRUE)) {
		R_LOG_ERROR ("Cannot set control console handler");
	}
#endif
	I->pager = NULL; /* no pager by default */
	I->mouse = 0;
	I->show_vals = false;
	r_cons_reset ();
	r_cons_rgb_init ();
	r_print_set_is_interrupted_cb (r_cons_is_breaked);
	R_CRITICAL_LEAVE (I);
	return I;
}

R_API RCons *r_cons_free(void) {
#if R2__WINDOWS__
	r_cons_enable_mouse (false);
	if (I->old_cp) {
		(void)SetConsoleOutputCP (I->old_cp);
		// chcp doesn't pick up the code page switch for some reason
		(void)r_sys_cmdf ("chcp %u > NUL", I->old_cp);
	}
#endif
	I->refcnt--;
	if (I->refcnt != 0) {
		return NULL;
	}
	if (I->line) {
		r_line_free ();
		I->line = NULL;
	}
	R_FREE (C->buffer);
	R_FREE (I->break_word);
	cons_context_deinit (C);
	R_FREE (C->lastOutput);
	C->lastLength = 0;
	R_FREE (I->pager);
	RVecFdPairs_fini (&I->fds);
	return NULL;
}

#define MOAR (4096 * 8)
static bool palloc(size_t moar) {
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

R_API int r_cons_eof(void) {
	return feof (I->fdin);
}

R_API void r_cons_gotoxy(int x, int y) {
#if R2__WINDOWS__
	r_cons_w32_gotoxy (1, x, y);
#else
	r_cons_printf ("\x1b[%d;%dH", y, x);
#endif
}

R_API void r_cons_print_clear(void) {
	r_cons_print ("\x1b[0;0H\x1b[0m");
}

R_API void r_cons_fill_line(void) {
	char white[1024];
	int cols = I->columns - 1;
	if (cols < 1) {
		return;
	}
	char *p = (cols >= sizeof (white))?  malloc (cols + 1): white;
	if (p) {
		memset (p, ' ', cols);
		p[cols] = 0;
		r_cons_print (p);
		if (white != p) {
			free (p);
		}
	}
}

R_API void r_cons_clear_line(int std_err) {
#if R2__WINDOWS__
	if (I->vtmode) {
		fprintf (std_err? stderr: stdout,"%s", R_CONS_CLEAR_LINE);
	} else {
		char white[1024];
		memset (&white, ' ', sizeof (white));
		if (I->columns > 0 && I->columns < sizeof (white)) {
			white[I->columns - 1] = 0;
		} else if (I->columns == 0) {
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

R_API void r_cons_clear00(void) {
	r_cons_clear ();
	r_cons_gotoxy (0, 0);
}

R_API void r_cons_reset_colors(void) {
	r_cons_print (Color_RESET_BG Color_RESET);
}

R_API void r_cons_clear(void) {
	I->lines = 0;
#if R2__WINDOWS__
	r_cons_w32_clear ();
#else
	r_cons_print (Color_RESET R_CONS_CLEAR_SCREEN);
#endif
}

R_API void r_cons_reset(void) {
	RConsContext *c = C;
	if (c->buffer) {
		c->buffer[0] = '\0';
	}
	c->buffer_len = 0;
	I->lines = 0;
	I->lastline = c->buffer;
	cons_grep_reset (&c->grep);
	c->pageable = true;
}

R_API const char *r_cons_get_buffer(void) {
	// check len otherwise it will return trash
	return C->buffer_len? C->buffer : NULL;
}

R_API int r_cons_get_buffer_len(void) {
	return C->buffer_len;
}

R_API void r_cons_filter(void) {
	/* grep */
	if (C->filter || C->grep.tokens_used \
			|| (C->grep.strings && r_list_length (C->grep.strings) > 0) \
			|| C->grep.less || C->grep.json) {
		(void)r_cons_grepbuf ();
		C->filter = false;
	}
	/* html */
	if (C->is_html) {
		int newlen = 0;
		char *input = r_str_ndup (C->buffer, C->buffer_len);
		char *res = r_cons_html_filter (input, &newlen);
		if (res) {
			free (C->buffer);
			C->buffer = res;
			C->buffer_len = newlen;
			C->buffer_sz = newlen;
		}
		free (input);
	}
	if (C->tmp_html) {
		C->is_html = C->was_html;
		C->tmp_html = false;
		C->was_html = false;
	}
}

R_API void r_cons_push(void) {
	if (!C->cons_stack) {
		return;
	}
	RConsStack *data = cons_stack_dump (true);
	if (!data) {
		return;
	}
	r_stack_push (C->cons_stack, data);
	C->buffer_len = 0;
	if (C->buffer) {
		memset (C->buffer, 0, C->buffer_sz);
	}
}

R_API void r_cons_pop(void) {
	if (!C->cons_stack) {
		return;
	}
	RConsStack *data = (RConsStack *)r_stack_pop (C->cons_stack);
	if (!data) {
		return;
	}
	cons_stack_load (data, true);
	cons_stack_free ((void *)data);
}

R_API RConsContext *r_cons_context_new(R_NULLABLE RConsContext *parent) {
	RConsContext *context = R_NEW0 (RConsContext);
	if (!context) {
		return NULL;
	}
	init_cons_context (context, parent);
	return context;
}

R_API void r_cons_context_free(RConsContext *context) {
	if (R_LIKELY (context)) {
		cons_context_deinit (context);
		free (context);
	}
}

R_API void r_cons_context_load(RConsContext *context) {
	if (!r_cons_instance) {
		r_cons_instance = &g_cons_instance;
	}
	r_cons_instance->context = context;
}

R_API void r_cons_context_reset(void) {
	if (!r_cons_instance) {
		r_cons_instance = &g_cons_instance;
	}
	r_cons_instance->context = &r_cons_context_default;
	C->sorted_column = -1;
}

R_API bool r_cons_context_is_main(void) {
	return C == &r_cons_context_default;
}

R_API void r_cons_context_break(RConsContext *context) {
	if (R_LIKELY (context)) {
		context->breaked = true;
		if (context->event_interrupt) {
			context->event_interrupt (context->event_interrupt_data);
		}
	}
}

R_API void r_cons_last(void) {
	if (!C->lastEnabled) {
		return;
	}
	C->lastMode = true;
	if (C->lastLength > 0) {
		r_cons_write (C->lastOutput, C->lastLength);
	}
}

static bool lastMatters(void) {
	return (C->buffer_len > 0 &&
		(C->lastEnabled && !C->filter && r_list_empty (C->grep.strings)) \
		&& !C->grep.tokens_used && !C->grep.less \
		&& !C->grep.json && !C->is_html);
}

R_API void r_cons_echo(const char *msg) {
	if (msg) {
		if (echodata) {
			r_strbuf_append (echodata, msg);
			r_strbuf_append (echodata, "\n");
		} else {
			echodata = r_strbuf_new (msg);
		}
	} else {
		if (echodata) {
			char *data = r_strbuf_drain (echodata);
			r_cons_print (data);
			r_cons_newline ();
			echodata = NULL;
			free (data);
		}
	}
}

static void optimize(RConsContext *ctx) {
	char *buf = ctx->buffer;
	int len = ctx->buffer_len;
	if (len < 1) {
		return;
	}

	int i = 0;
	int j = 0;
	const int buf_sz = ctx->buffer_sz;

	while (i < len) {
		if (buf[i] == 0x1b && i + 1 < len && buf[i+1] == '[') {
			char escape_seq[32];
			int k = 0;

			// Copy ESC and [
			if (j + 2 > buf_sz) {
				goto overflow;
			}
			escape_seq[k++] = buf[i++]; // ESC
			escape_seq[k++] = buf[i++]; // [

			while (i < len && k < sizeof (escape_seq) - 1) {
				char c = buf[i++];
				if (j + k > buf_sz) {
					goto overflow;
				}
				escape_seq[k++] = c;
				if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
					break;
				}
			}
			escape_seq[k] = '\0';

			// TODO: Implement logic here to determine if escape_seq should be kept,
			// modified, or discarded based on context or previous sequences.
			// For now, we assume it should always be kept.
			bool keep_sequence = true;
			if (keep_sequence) {
				if (j + k <= buf_sz) {
					memcpy (buf + j, escape_seq, k);
					j += k;
				} else {
					goto overflow;
				}
			}
		} else {
			if (j < buf_sz) {
				buf[j++] = buf[i++];
			} else {
				goto overflow;
			}
		}
	}

	if (j < ctx->buffer_len) {
		ctx->buffer_len = j;
		if (j < buf_sz) {
			buf[j] = '\0';
		}
	}
	return;

overflow:
	R_LOG_WARN ("Buffer overflow during ANSI optimization, output truncated");
	if (j <= buf_sz) {
		ctx->buffer_len = j;
		if (j < buf_sz) {
			buf[j] = '\0';
		}
	} else {
		ctx->buffer_len = buf_sz > 0 ? buf_sz - 1 : 0;
		if (buf_sz > 0) {
			buf[ctx->buffer_len] = '\0';
		}
	}
}

R_API char *r_cons_drain(void) {
	const char *buf = r_cons_get_buffer ();
	size_t buf_size = r_cons_get_buffer_len ();
	char *s = r_str_ndup (buf, buf_size);
	r_cons_reset ();
	return s;
}

R_API void r_cons_flush(void) {
	RConsContext *ctx = getctx ();
	if (!ctx) {
		r_cons_context_reset ();
		ctx = getctx ();
	}
	if (!r_cons_instance) {
		r_cons_instance = &g_cons_instance;
	}
	const char *tee = I->teefile;
	if (C->noflush) {
		return;
	}
	if (I->null) {
		r_cons_reset ();
		return;
	}
	if (!r_list_empty (ctx->marks)) {
		r_list_free (ctx->marks);
		ctx->marks = r_list_newf ((RListFree)r_cons_mark_free);
	}
	if (lastMatters () && !ctx->lastMode) {
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
	if (I->optimize > 0) {
		// compress output (45 / 250 KB)
		optimize (C);
		if (I->optimize > 1) {
			optimize (C);
		}
	}

	r_cons_filter ();
	if (!ctx->buffer || ctx->buffer_len < 1) {
		r_cons_reset ();
		return;
	}
	if (r_cons_is_interactive () && I->fdout == 1) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (ctx->pageable && I->pager && *I->pager && ctx->buffer_len > 0 && r_str_char_count (ctx->buffer, '\n') >= I->rows) {
			ctx->buffer[ctx->buffer_len - 1] = 0;
			if (!strcmp (I->pager, "..")) {
				char *str = r_str_ndup (ctx->buffer, ctx->buffer_len);
				ctx->pageable = false;
				r_cons_less_str (str, NULL);
				r_cons_reset ();
				free (str);
				return;
			} else {
				r_sys_cmd_str_full (I->pager, ctx->buffer, -1, NULL, NULL, NULL);
				r_cons_reset ();
			}
		} else if (I->maxpage > 0 && ctx->buffer_len > I->maxpage) {
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
	r_cons_highlight (I->highlight);

	if (r_cons_is_interactive () && !r_sandbox_enable (false)) {
		if (I->linesleep > 0 && I->linesleep < 1000) {
			int i = 0;
			int pagesize = R_MAX (1, I->pagesize);
			char *ptr = ctx->buffer;
			char *nl = strchr (ptr, '\n');
			int len = ctx->buffer_len;
			ctx->buffer[ctx->buffer_len] = 0;
			r_cons_break_push (NULL, NULL);
			while (nl && !r_cons_is_breaked ()) {
				__cons_write (ptr, nl - ptr + 1);
				if (I->linesleep && !(i % pagesize)) {
					r_sys_usleep (I->linesleep * 1000);
				}
				ptr = nl + 1;
				nl = strchr (ptr, '\n');
				i++;
			}
			__cons_write (ptr, ctx->buffer + len - ptr);
			r_cons_break_pop ();
		} else {
			__cons_write (ctx->buffer, ctx->buffer_len);
		}
	} else {
		__cons_write (ctx->buffer, ctx->buffer_len);
	}

	r_cons_reset ();
	if (I->newline) {
		eprintf ("\n");
		I->newline = false;
	}
	if (ctx->tmp_html) {
		ctx->is_html = ctx->was_html;
		ctx->tmp_html = false;
		ctx->was_html = false;
	}
}

R_API void r_cons_visual_flush(void) {
	if (C->noflush) {
		return;
	}
	r_cons_highlight (I->highlight);
	if (!I->null) {
/* TODO: this ifdef must go in the function body */
#if R2__WINDOWS__
		if (I->vtmode) {
			r_cons_visual_write (C->buffer);
		} else {
			r_cons_w32_print (C->buffer, C->buffer_len, true);
		}
#else
		r_cons_visual_write (C->buffer);
#endif
	}
	r_cons_reset ();
	if (I->fps) {
		r_cons_print_fps (0);
	}
}

R_API void r_cons_print_fps(int col) {
	int fps = 0, w = r_cons_get_size (NULL);
	fps = 0;
	if (prev) {
		ut64 now = r_time_now_mono ();
		st64 diff = (st64)(now - prev);
		if (diff <= 0) {
			fps = 0;
		} else {
			fps = (diff < 1000000)? (int)(1000000.0 / diff): 0;
		}
		prev = now;
	} else {
		prev = r_time_now_mono ();
	}
	if (col < 1) {
		col = 12;
	}
#ifdef R2__WINDOWS__
	if (I->vtmode) {
		eprintf ("\x1b[0;%dH[%d FPS] \n", w - col, fps);
	} else {
		r_cons_w32_gotoxy (2, w - col, 0);
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

static int chop(int len) {
	RConsContext *ctx = getctx ();
	if (ctx->buffer_limit > 0) {
		if (ctx->buffer_len + len >= ctx->buffer_limit) {
			if (ctx->buffer_len >= ctx->buffer_limit) {
				C->breaked = true;
				return 0;
			}
			return ctx->buffer_limit - ctx->buffer_len;
		}
	}
	return len;
}

R_API void r_cons_visual_write(char *buffer) {
	char white[1024];
	int cols = I->columns;
	int alen, plen, lines = I->rows;
	bool break_lines = I->break_lines;
	const char *endptr;
	char *nl, *ptr = buffer, *pptr;

	if (I->null) {
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
				__cons_write (pptr, plen);
				if (len != olen) {
					__cons_write (R_CONS_CLEAR_FROM_CURSOR_TO_END, -1);
					__cons_write (Color_RESET, strlen (Color_RESET));
				}
			}
		} else {
			if (lines > 0) {
				int w = cols - (alen % cols == 0 ? cols : alen % cols);
				__cons_write (pptr, plen);
				if (I->blankline && w > 0) {
					__cons_write (white, R_MIN (w, sizeof (white)));
				}
			}
			// TRICK to empty columns.. maybe buggy in w32
			if (r_mem_mem ((const ut8*)ptr, len, (const ut8*)"\x1b[0;0H", 6)) {
				lines = I->rows;
				__cons_write (pptr, plen);
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
			__cons_write (white, R_MIN (cols, sizeof (white)));
		}
	}
}

R_API void r_cons_printf_list(const char *format, va_list ap) {
	va_list ap2, ap3;

	va_copy (ap2, ap);
	va_copy (ap3, ap);
	if (I->null || !format) {
		va_end (ap2);
		va_end (ap3);
		return;
	}
	if (strchr (format, '%')) {
		if (palloc (MOAR + strlen (format) * 20)) {
			RConsContext *ctx = getctx ();
			bool need_retry = true;
			while (need_retry) {
				need_retry = false;
				size_t left = ctx->buffer_sz - ctx->buffer_len;
				size_t written = vsnprintf (ctx->buffer + ctx->buffer_len, left, format, ap3);
				if (written >= left) {
					if (palloc (written + 1)) {
						va_end (ap3);
						va_copy (ap3, ap2);
						need_retry = true; // Retry with larger buffer
					} else {
						// Allocation failed, use available space
						size_t added = (left > 0) ? left - 1 : 0;
						ctx->buffer_len += added;
						C->breaked = true; // Indicate truncation
					}
				} else {
					ctx->buffer_len += written;
				}
			}
		} else {
			C->breaked = true; // Initial allocation failed
		}
	} else {
		r_cons_print (format);
	}
	va_end (ap2);
	va_end (ap3);
}

R_API int r_cons_printf(const char *format, ...) {
	va_list ap;
	if (R_STR_ISEMPTY (format)) {
		return -1;
	}
	va_start (ap, format);
	r_cons_printf_list (format, ap);
	va_end (ap);

	return 0;
}

R_API int r_cons_get_column(void) {
	char *line = strrchr (C->buffer, '\n');
	if (!line) {
		line = C->buffer;
	}
	C->buffer[C->buffer_len] = 0;
	return r_str_ansi_len (line);
}

/* final entrypoint for adding stuff in the buffer screen */
R_API int r_cons_write(const char *str, int len) {
	R_RETURN_VAL_IF_FAIL (str && len >= 0, -1);
	if (len < 1 || C->breaked) {
		return 0;
	}

	if (I->echo) {
		// Here to silent pedantic meson flags ...
		int rlen;
		if ((rlen = write (2, str, len)) != len) {
			return rlen;
		}
	}
	if (str && len > 0 && !I->null) {
		R_CRITICAL_ENTER (I);
		if (palloc (len + 1)) {
			if ((len = chop (len)) < 1) {
				R_CRITICAL_LEAVE (I);
				return 0;
			}
			memcpy (C->buffer + C->buffer_len, str, len);
			C->buffer_len += len;
			C->buffer[C->buffer_len] = 0;
		}
		R_CRITICAL_LEAVE (I);
	}
	if (C->flush) {
		r_cons_flush ();
	}
	if (I->break_word && str && len > 0) {
		if (r_mem_mem ((const ut8*)str, len, (const ut8*)I->break_word, I->break_word_len)) {
			C->breaked = true;
		}
	}
	return len;
}

R_API void r_cons_memset(char ch, int len) {
	if (C->breaked) {
		return;
	}
	if (!I->null && len > 0) {
		if ((len = chop (len)) < 1) {
			return;
		}
		if (palloc (len + 1)) {
			memset (C->buffer + C->buffer_len, ch, len);
			C->buffer_len += len;
			C->buffer[C->buffer_len] = 0;
		}
	}
}

R_API void r_cons_print(const char *str) {
	R_RETURN_IF_FAIL (str);
	if (!I || I->null) {
		return;
	}
	size_t len = strlen (str);
	if (len > 0) {
		r_cons_write (str, len);
	}
}

R_API void r_cons_newline(void) {
	if (!I->null) {
		r_cons_print ("\n");
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
	if (I->is_html) r_cons_print ("<br />\n");
#endif
}

/* return the aproximated x,y of cursor before flushing */
// XXX this function is a huge bottleneck
R_API int r_cons_get_cursor(int *rows) {
	// This implementation is very slow
	if (rows) {
		*rows = 0;
	}
	return 0;
#if 0
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

#if R2__WINDOWS__
static int __xterm_get_cur_pos(int *xpos) {
	int ypos = 0;
	const char *get_pos = R_CONS_GET_CURSOR_POSITION;
	if (write (I->fdout, get_pos, sizeof (get_pos)) < 1) {
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

static bool __xterm_get_size(void) {
	if (write (I->fdout, R_CONS_CURSOR_SAVE, sizeof (R_CONS_CURSOR_SAVE)) < 1) {
		return false;
	}
	int rows, columns;
	const char nainnain[] = "\x1b[999;999H";
	if (write (I->fdout, nainnain, sizeof (nainnain)) != sizeof (nainnain)) {
		return false;
	}
	rows = __xterm_get_cur_pos (&columns);
	if (rows) {
		I->rows = rows;
		I->columns = columns;
	} // otherwise reuse previous values
	if (write (I->fdout, R_CONS_CURSOR_RESTORE, sizeof (R_CONS_CURSOR_RESTORE) != sizeof (R_CONS_CURSOR_RESTORE))) {
		return false;
	}
	return true;
}

#endif

// XXX: if this function returns <0 in rows or cols expect MAYHEM
R_API int r_cons_get_size(int *rows) {
#if R2__WINDOWS__
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	bool ret = GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &csbi);
	if (ret) {
		I->columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		I->rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
	} else {
		if (I->term_xterm) {
			ret = __xterm_get_size ();
		}
		if (!ret || (I->columns == -1 && I->rows == 0)) {
			// Stdout is probably redirected so we set default values
			I->columns = 80;
			I->rows = 23;
		}
	}
#elif EMSCRIPTEN || __wasi__
	I->columns = 80;
	I->rows = 23;
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
		I->columns = win.ws_col;
		I->rows = win.ws_row;
	} else {
		I->columns = 80;
		I->rows = 23;
	}
#else
	char *str = r_sys_getenv ("COLUMNS");
	if (str) {
		I->columns = atoi (str);
		I->rows = 23; // XXX. windows must get console size
		free (str);
	} else {
		I->columns = 80;
		I->rows = 23;
	}
#endif
#if SIMULATE_ADB_SHELL
	I->rows = 0;
	I->columns = 0;
#endif
#if SIMULATE_MAYHEM
	// expect tons of crashes
	I->rows = -1;
	I->columns = -1;
#endif
	if (I->rows < 0) {
		I->rows = 0;
	}
	if (I->columns < 0) {
		I->columns = 0;
	}
	if (I->force_columns) {
		I->columns = I->force_columns;
	}
	if (I->force_rows) {
		I->rows = I->force_rows;
	}
	if (I->fix_columns) {
		I->columns += I->fix_columns;
	}
	if (I->fix_rows) {
		I->rows += I->fix_rows;
	}
	if (rows) {
		*rows = I->rows;
	}
	I->rows = R_MAX (0, I->rows);
	return R_MAX (0, I->columns);
}

#if R2__WINDOWS__
R_API int r_cons_is_vtcompat(void) {
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
			I->term_xterm = true;
			free (term);
			return 2;
		}
		I->term_xterm = false;
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

R_API void r_cons_show_cursor(int cursor) {
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

/**
 * void r_cons_set_raw( [0,1] )
 *
 *   Change canonicality of the terminal
 *
 * For optimization reasons, there's no initialization flag, so you need to
 * ensure that the make the first call to r_cons_set_raw() with '1' and
 * the next calls ^= 1, so: 1, 0, 1, 0, 1, ...
 *
 * If you doesn't use this order you'll probably loss your terminal properties.
 *
 */
R_API void r_cons_set_raw(bool is_raw) {
	if (oldraw != -1) {
		if (is_raw == oldraw) {
			return;
		}
	}
#if EMSCRIPTEN || __wasi__
	/* do nothing here */
#elif R2__UNIX__
	// enforce echo off
	if (is_raw) {
		I->term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
		tcsetattr (0, TCSANOW, &I->term_raw);
	} else {
		tcsetattr (0, TCSANOW, &I->term_buf);
	}
#elif R2__WINDOWS__
	if (I->term_xterm) {
		char *stty = r_file_path ("stty");
		if (!stty || *stty == 's') {
			I->term_xterm = false;
		}
		free (stty);
	}
	if (is_raw) {
		if (I->term_xterm) {
			r_sandbox_system ("stty raw -echo", 1);
		} else {
			SetConsoleMode (h, I->term_raw);
		}
	} else {
		if (I->term_xterm) {
			r_sandbox_system ("stty -raw echo", 1);
		} else {
			SetConsoleMode (h, I->term_buf);
		}
	}
#else
#warning No raw console supported for this platform
#endif
	fflush (stdout);
	oldraw = is_raw;
}

R_API void r_cons_set_utf8(bool b) {
	I->use_utf8 = b;
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

R_API void r_cons_invert(int set, int color) {
	r_cons_print (R_CONS_INVERT (set, color));
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

R_API void r_cons_column(int c) {
	char *b = malloc (C->buffer_len + 1);
	if (!b) {
		return;
	}
	memcpy (b, C->buffer, C->buffer_len);
	b[C->buffer_len] = 0;
	r_cons_reset ();
	// align current buffer N chars right
	r_cons_print_justify (b, c, 0);
	r_cons_gotoxy (0, 0);
	free (b);
}

//  XXX deprecate must be push/pop context state
static bool lasti = false; /* last interactive mode */

R_API void r_cons_set_interactive(bool x) {
	lasti = r_cons_context ()->is_interactive;
	r_cons_context ()->is_interactive = x;
}

R_API void r_cons_set_last_interactive(void) {
	r_cons_context ()->is_interactive = lasti;
}

R_API void r_cons_set_title(const char *str) {
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
	r_cons_printf ("\x1b]0;%s\007", str);
#endif
}

R_API void r_cons_zero(void) {
	if (I->line) {
		I->line->zerosep = true;
	}
	if (write (1, "", 1) != 1) {
		C->breaked = true;
	}
}

R_API void r_cons_highlight(const char *word) {
	int l, *cpos = NULL;
	char *rword = NULL, *res, *clean = NULL;
	char *inv[2] = {
		R_CONS_INVERT (true, true),
		R_CONS_INVERT (false, true)
	};
	int linv[2] = {
		strlen (inv[0]),
		strlen (inv[1])
	};

	if (!I->enable_highlight) {
		r_cons_enable_highlight (true);
		return;
	}
	if (word && *word && C->buffer) {
		int word_len = strlen (word);
		char *orig;
		clean = r_str_ndup (C->buffer, C->buffer_len);
		l = r_str_ansi_filter (clean, &orig, &cpos, -1);
		free (C->buffer);
		C->buffer = orig;
		if (I->highlight) {
			if (strcmp (word, I->highlight)) {
				free (I->highlight);
				I->highlight = strdup (word);
			}
		} else {
			I->highlight = strdup (word);
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
		/* don't free orig - it's assigned
		 * to C->buffer and possibly realloc'd */
	} else {
		R_FREE (I->highlight);
	}
}

R_API char *r_cons_lastline(int *len) {
	RConsContext *c = C;
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
R_API char *r_cons_lastline_utf8_ansi_len(int *len) {
	RConsContext *c = C;
	if (!len) {
		return r_cons_lastline (0);
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

/* swap color from foreground to background, returned value must be freed */
R_API char *r_cons_swap_ground(const char *col) {
	if (!col) {
		return NULL;
	}
	if (!strncmp (col, "\x1b[48;5;", 7)) {
		/* rgb background */
		return r_str_newf ("\x1b[38;5;%s", col+7);
	} else if (!strncmp (col, "\x1b[38;5;", 7)) {
		/* rgb foreground */
		return r_str_newf ("\x1b[48;5;%s", col+7);
	} else if (!strncmp (col, "\x1b[4", 3)) {
		/* is background */
		return r_str_newf ("\x1b[3%s", col+3);
	} else if (!strncmp (col, "\x1b[3", 3)) {
		/* is foreground */
		return r_str_newf ("\x1b[4%s", col+3);
	}
	return strdup (col);
}

R_API bool r_cons_drop(int n) {
	RConsContext *c = C;
	if (n > c->buffer_len) {
		c->buffer_len = 0;
		return false;
	}
	c->buffer_len -= n;
	return true;
}

R_API void r_cons_trim(void) {
	RConsContext *c = C;
	while (c->buffer_len > 0) {
		char ch = c->buffer[c->buffer_len - 1];
		if (ch != '\n' && !IS_WHITESPACE (ch)) {
			break;
		}
		c->buffer_len--;
	}
}

R_API void r_cons_bind(RConsBind *bind) {
	if (!bind) {
		return;
	}
	bind->get_size = r_cons_get_size;
	bind->get_cursor = r_cons_get_cursor;
	bind->cb_printf = r_cons_printf;
	bind->cb_flush = r_cons_flush;
	bind->cb_grep = r_cons_grep;
	bind->is_breaked = r_cons_is_breaked;
}

R_API const char* r_cons_get_rune(const ut8 ch) {
	switch (ch) {
	case RUNECODE_LINE_HORIZ: return RUNE_LINE_HORIZ;
	case RUNECODE_LINE_VERT:  return RUNE_LINE_VERT;
	case RUNECODE_LINE_CROSS: return RUNE_LINE_CROSS;
	case RUNECODE_CORNER_TL:  return RUNE_CORNER_TL;
	case RUNECODE_CORNER_TR:  return RUNE_CORNER_TR;
	case RUNECODE_CORNER_BR:  return RUNE_CORNER_BR;
	case RUNECODE_CORNER_BL:  return RUNE_CORNER_BL;
	case RUNECODE_CURVE_CORNER_TL:  return RUNE_CURVE_CORNER_TL;
	case RUNECODE_CURVE_CORNER_TR:  return RUNE_CURVE_CORNER_TR;
	case RUNECODE_CURVE_CORNER_BR:  return RUNE_CURVE_CORNER_BR;
	case RUNECODE_CURVE_CORNER_BL:  return RUNE_CURVE_CORNER_BL;
	}
	return NULL;
}

R_API void r_cons_breakword(R_NULLABLE const char *s) {
	free (I->break_word);
	if (s) {
		I->break_word = strdup (s);
		I->break_word_len = strlen (s);
	} else {
		I->break_word = NULL;
		I->break_word_len = 0;
	}
}

R_API void r_cons_clear_buffer(void) {
	if (I->vtmode) {
		if (write (1, "\x1b" "c\x1b[3J", 6) != 6) {
			C->breaked = true;
		}
	}
}

R_API void r_cons_thready(void) {
	// use tls instance
	r_cons_instance = &g_cons_instance_tls;
	if (r_cons_instance) {
		R_CRITICAL_ENTER (I);
	}
	C->unbreakable = true;
	r_sys_signable (false); // disable signal handling
	if (!r_cons_instance) {
		r_cons_new ();
	}
	if (r_cons_instance) {
		R_CRITICAL_LEAVE (I);
	}
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

R_API void r_cons_mark_free(RConsMark *m) {
	if (m) {
		free (m->name);
		free (m);
	}
}

R_API void r_cons_mark(ut64 addr, const char *name) {
	RConsMark *mark = R_NEW0 (RConsMark);
	if (mark) {
		RConsContext *ctx = getctx ();
		mark->addr = addr;
		int row = 0, col = r_cons_get_cursor (&row);
		mark->name = strdup (name); // TODO. use a const pool
		mark->pos = ctx->buffer_len;
		mark->col = col;
		mark->row = row;
		r_list_append (ctx->marks, mark);
	}
};

// must be called before
R_API void r_cons_mark_flush(void) {
	r_list_free (C->marks);
}

R_API RConsMark *r_cons_mark_at(ut64 addr, const char *name) {
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
