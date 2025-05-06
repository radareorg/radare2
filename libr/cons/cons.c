/* radare2 - LGPL - Copyright 2008-2025 - pancake */

#include <r_cons.h>
#include <r_util/r_print.h>

#define COUNT_LINES 1

R_LIB_VERSION (r_cons);

// static R_TH_LOCAL RConsContext r_cons_context_default = {0};

static RCons s_cons_global = {0};
static R_TH_LOCAL RCons s_cons_thread = {0};

static void __break_signal(int sig);

#include "kons.inc.c"
static R_TH_LOCAL RCons *I = NULL; // &s_cons_global; // NULL;

static void __break_signal(int sig) {
	r_cons_context_break (I->context); // &r_cons_context_default);
}
#define C (getctx ())

static inline void init_cons_instance(void) {
	return;
#if 0
	if (R_LIKELY (I)) {
		if (!I->context) {
			I->context = &r_cons_context_default;
		}
	} else {
		I = &s_cons_global;
		I->context = &r_cons_context_default;
		init_cons_input (&I->input_state);
	}
#endif
}

static RConsContext *getctx(void) {
	init_cons_instance ();
	return I->context;
}

R_API InputState *r_cons_input_state(void) {
	init_cons_instance ();
	return &I->input_state;
}

R_API bool r_cons_is_initialized(void) {
	return I != NULL;
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
	r_kons_println (I, str);
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

R_API void r_cons_print_justify(RCons *cons, const char *str, int j, char c) {
	int i, o, len;
	for (o = i = len = 0; str[i]; i++, len++) {
		if (str[i] == '\n') {
			r_kons_memset (cons, ' ', j);
			if (c) {
				r_kons_memset (cons, c, 1);
				r_kons_memset (cons, ' ', 1);
			}
			r_cons_write (str + o, len);
			if (str[o + len] == '\n') {
				r_kons_newline (cons);
			}
			o = i + 1;
			len = 0;
		}
	}
	if (len > 1) {
		r_kons_write (cons, str + o, len);
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

R_API void r_cons_break_clear(void) {
	r_kons_break_clear (I);
}

R_API void r_cons_context_break_push(RConsContext *context, RConsBreak cb, void *user, bool sig) {
	// eprintf ("Brk.push\n");
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
	r_kons_break_push (I, cb, user);
}

R_API void r_cons_break_pop(void) {
	r_kons_break_pop (I);
}

R_API bool r_cons_is_interactive(void) {
	return r_kons_is_interactive (I);
}

R_API bool r_cons_default_context_is_interactive(void) {
	// XXX this is pure evil
	return I->context->is_interactive;
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
	return r_kons_is_breaked (r_cons_singleton ());
}

#if 0
// UNUSED
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
	r_kons_break_end (I);
}

R_API void *r_cons_sleep_begin(void) {
	return r_kons_sleep_begin (I);
}

R_API void r_cons_sleep_end(void *user) {
	r_kons_sleep_end (I, user);
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
	RCons *cons = r_kons_new ();
	if (I) {
		R_LOG_INFO ("Second cons!");
		I = cons;
	} else {
		I = cons;
	}
	return cons;
}

R_API void r_cons_free(RCons *cons) {
	r_kons_free (cons);
	if (cons == I) {
		I = NULL; // hack for globals
	}
}

R_API void r_cons_gotoxy(int x, int y) {
	r_kons_gotoxy (I, x, y);
}

R_API void r_cons_print_clear(void) {
	r_kons_print_clear (I);
}

R_API void r_cons_fill_line(void) {
	r_kons_fill_line (I);
}

R_API void r_cons_clear_line(int std_err) {
	r_kons_clear_line (I, std_err);
}

R_API void r_cons_clear00(void) {
	RCons *cons = r_cons_singleton ();
	r_kons_clear (cons);
	r_kons_gotoxy (cons, 0, 0);
}

R_API void r_cons_reset_colors(void) {
	r_kons_reset_colors (I);
}

R_API void r_cons_clear(void) {
	r_kons_clear (I);
}

R_API void r_cons_reset(void) {
	r_kons_reset (I);
}

// TODO. merge these two functions into one!! return len with parameter
R_API const char *r_cons_get_buffer(void) {
	return r_kons_get_buffer (I, NULL);
}

// TODO. merge these two functions into one!! return len with parameter
R_API int r_cons_get_buffer_len(void) {
	size_t len;
	r_kons_get_buffer (I, &len);
	return (int)len;
}

R_API void r_cons_filter(void) {
	r_kons_filter (r_cons_singleton ());
}

R_API void r_cons_push(void) {
	r_kons_push (I);
}

R_API void r_cons_pop(void) {
	r_kons_pop (I);
}

R_API void r_cons_context_load(RConsContext *context) {
	// eprintf ("ctx.loa\n");
	if (!I) {
		I = &s_cons_global;
	}
	I->context = context;
}

R_API void r_cons_context_reset(void) {
#if 0
	while (r_kons_pop (I)) {
		// you cant stop
	}
#endif
}

R_API bool r_cons_context_is_main(void) {
	return r_kons_context_is_main (I);
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

R_API void r_cons_echo(const char *msg) {
	r_kons_echo (I, msg);
}

#if 0
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
#endif

R_API char *r_cons_drain(void) {
	return r_kons_drain (I);
}

R_API void r_cons_flush(void) {
	r_kons_flush (I);
}

R_API void r_cons_visual_flush(void) {
	r_kons_visual_flush (I);
}

R_API void r_cons_print_fps(int col) {
	r_kons_print_fps (I, col);
}

R_API void r_cons_visual_write(char *buffer) {
	r_kons_visual_write (I, buffer);
}

R_API int r_cons_get_column(void) {
	return r_kons_get_column (I);
}

/* final entrypoint for adding stuff in the buffer screen */
R_API int r_cons_write(const char *str, int len) {
	return r_kons_write (I, str, len);
}

R_API void r_cons_memset(char ch, int len) {
	r_kons_memset (I, ch, len);
}

R_API void r_cons_print(const char *str) {
	r_kons_print (I, str);
}

R_API void r_cons_newline(void) {
	r_kons_newline (I);
}

R_API int r_cons_get_cursor(int *rows) {
	return r_kons_get_cursor (I, rows);
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

R_API int r_cons_get_size(int *rows) {
	return r_kons_get_size (I, rows);
}


R_API void r_cons_invert(int set, int color) {
	r_kons_invert (I, set, color);
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
	r_kons_column (I, c);
}

R_API void r_cons_set_interactive(bool x) {
	r_kons_set_interactive (I, x);
}

R_API void r_cons_set_last_interactive(void) {
	r_kons_set_last_interactive (I);
}

R_API void r_cons_set_title(const char *str) {
	r_kons_set_title (I, str);
}

R_API void r_cons_zero(void) {
	r_kons_zero (I);
}

R_API void r_cons_highlight(const char *word) {
	r_kons_highlight (I, word);
}

R_API char *r_cons_lastline(int *len) {
	return r_kons_lastline (I, len);
}

// same as r_cons_lastline(), but len will be the number of
// utf-8 characters excluding ansi escape sequences as opposed to just bytes
R_API char *r_cons_lastline_utf8_ansi_len(int *len) {
	return r_kons_lastline_utf8_ansi_len (I, len);
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

R_API bool r_cons_drop(int n) {
	return r_kons_drop (I, n);
}

R_API void r_cons_trim(void) {
	r_kons_trim (I);
}

R_API void r_cons_bind(RCons *cons, RConsBind *bind) {
	R_RETURN_IF_FAIL (cons && bind);
	bind->cons = cons;
	bind->get_size = r_kons_get_size;
	bind->get_cursor = r_kons_get_cursor;
	bind->cb_printf = r_kons_printf;
	bind->cb_flush = r_kons_flush;
	bind->cb_grep = r_kons_grep;
	bind->is_breaked = r_kons_is_breaked;
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
	r_kons_breakword (I, s);
}

R_API void r_cons_clear_buffer(void) {
	r_kons_clear_buffer (I);
}

// conceptually wrong, needs redesign
R_API void r_cons_thready(void) {
	I = &s_cons_thread;
	if (I->refcnt > 0) {
		R_CRITICAL_ENTER (I);
	}
	RConsContext *ctx = getctx ();
	if (ctx) {
		C->unbreakable = true;
	}
	r_sys_signable (false); // disable signal handling
	if (I->refcnt == 0) {
		r_cons_new ();
	}
	if (I->refcnt > 0) {
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

R_API void r_cons_mark(ut64 addr, const char *name) {
	r_kons_mark (I, addr, name);
}

// must be called before
R_API void r_cons_mark_flush(void) {
	r_kons_mark_flush (I);
}

R_API RConsMark *r_cons_mark_at(ut64 addr, const char *name) {
	return r_kons_mark_at (I, addr, name);
}

R_API void r_cons_printf_list(const char *format, va_list ap) {
	r_kons_printf_list (I, format, ap);
}

R_API int r_cons_printf(const char *format, ...) {
	va_list ap;
	if (R_STR_ISEMPTY (format)) {
		return -1;
	}
	va_start (ap, format);
	r_kons_printf_list (I, format, ap);
	va_end (ap);
	return 0;
}

R_API void r_cons_show_cursor(int cursor) {
	r_kons_show_cursor (I, cursor);
}

R_API void r_cons_set_raw(bool is_raw) {
	r_kons_set_raw (I, is_raw);
}

R_API void r_cons_set_utf8(bool b) {
	r_kons_set_utf8 (I, b);
}
