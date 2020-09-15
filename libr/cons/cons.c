/* radare2 - LGPL - Copyright 2008-2020 - pancake, Jody Frankowski */

#include <r_cons.h>
#include <r_util.h>
#include <r_util/r_print.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>

#define COUNT_LINES 1
#define CTX(x) I.context->x

R_LIB_VERSION (r_cons);

static RConsContext r_cons_context_default = {{{{0}}}};
static RCons r_cons_instance = {0};
#define I r_cons_instance

//this structure goes into cons_stack when r_cons_push/pop
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

static void cons_grep_reset(RConsGrep *grep);

static void break_stack_free(void *ptr) {
	RConsBreakStack *b = (RConsBreakStack*)ptr;
	free (b);
}

static void cons_stack_free(void *ptr) {
	RConsStack *s = (RConsStack *)ptr;
	free (s->buf);
	if (s->grep) {
		R_FREE (s->grep->str);
		CTX (grep.str) = NULL;
	}
	free (s->grep);
	free (s);
}

static RConsStack *cons_stack_dump(bool recreate) {
	RConsStack *data = R_NEW0 (RConsStack);
	if (data) {
		if (CTX (buffer)) {
			data->buf = CTX (buffer);
			data->buf_len = CTX (buffer_len);
			data->buf_size = CTX (buffer_sz);
		}
		data->grep = R_NEW0 (RConsGrep);
		if (data->grep) {
			memcpy (data->grep, &I.context->grep, sizeof (RConsGrep));
			if (I.context->grep.str) {
				data->grep->str = strdup (I.context->grep.str);
			}
		}
		if (recreate && I.context->buffer_sz > 0) {
			I.context->buffer = malloc (I.context->buffer_sz);
			if (!I.context->buffer) {
				I.context->buffer = data->buf;
				free (data);
				return NULL;
			}
		} else {
			I.context->buffer = NULL;
		}
	}
	return data;
}

static void cons_stack_load(RConsStack *data, bool free_current) {
	r_return_if_fail (data);
	if (free_current) {
		free (I.context->buffer);
	}
	I.context->buffer = data->buf;
	data->buf = NULL;
	I.context->buffer_len = data->buf_len;
	I.context->buffer_sz = data->buf_size;
	if (data->grep) {
		free (I.context->grep.str);
		memcpy (&I.context->grep, data->grep, sizeof (RConsGrep));
	}
}

static void cons_context_init(RConsContext *context, R_NULLABLE RConsContext *parent) {
	context->breaked = false;
	context->cmd_depth = R_CONS_CMD_DEPTH + 1;
	context->buffer = NULL;
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
	context->cons_stack = NULL;
	r_stack_free (context->break_stack);
	context->break_stack = NULL;
	r_cons_pal_free (context);
}

static void __break_signal(int sig) {
	r_cons_context_break (&r_cons_context_default);
}

static inline void __cons_write_ll(const char *buf, int len) {
#if __WINDOWS__
	if (I.vtmode) {
		(void) write (I.fdout, buf, len);
	} else {
		if (I.fdout == 1) {
			r_cons_w32_print (buf, len, false);
		} else {
			(void) write (I.fdout, buf, len);
		}
	}
#else
	if (I.fdout < 1) {
		I.fdout = 1;
	}
	(void) write (I.fdout, buf, len);
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
	if (I.context->color_mode > COLOR_MODE_16) {
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

R_API void r_cons_strcat_justify(const char *str, int j, char c) {
	int i, o, len;
	for (o = i = len = 0; str[i]; i++, len++) {
		if (str[i] == '\n') {
			r_cons_memset (' ', j);
			if (c) {
				r_cons_memset (c, 1);
				r_cons_memset (' ', 1);
			}
			r_cons_memcat (str + o, len);
			if (str[o + len] == '\n') {
				r_cons_newline ();
			}
			o = i + 1;
			len = 0;
		}
	}
	if (len > 1) {
		r_cons_memcat (str + o, len);
	}
}

R_API void r_cons_strcat_at(const char *_str, int x, char y, int w, int h) {
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
	r_cons_strcat (R_CONS_CURSOR_SAVE);
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
			r_cons_memcat (str + o, R_MIN (len, cols));
			o = i + 1;
			len = 0;
			rows++;
		}
	}
	if (len > 1) {
		r_cons_gotoxy (x, y + rows);
		r_cons_memcat (str + o, len);
	}
	r_cons_strcat (Color_RESET);
	r_cons_strcat (R_CONS_CURSOR_RESTORE);
	free (str);
}

R_API RCons *r_cons_singleton(void) {
	return &I;
}

R_API void r_cons_break_clear(void) {
	I.context->breaked = false;
}

R_API void r_cons_context_break_push(RConsContext *context, RConsBreak cb, void *user, bool sig) {
	if (!context->break_stack) {
		return;
	}

	//if we don't have any element in the stack start the signal
	RConsBreakStack *b = R_NEW0 (RConsBreakStack);
	if (!b) {
		return;
	}
	if (r_stack_is_empty (context->break_stack)) {
#if __UNIX__
		if (sig && r_cons_context_is_main ()) {
			r_sys_signal (SIGINT, __break_signal);
		}
#endif
		context->breaked = false;
	}
	//save the actual state
	b->event_interrupt = context->event_interrupt;
	b->event_interrupt_data = context->event_interrupt_data;
	r_stack_push (context->break_stack, b);
	//configure break
	context->event_interrupt = cb;
	context->event_interrupt_data = user;
}

R_API void r_cons_context_break_pop(RConsContext *context, bool sig) {
	if (!context->break_stack) {
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
#if __UNIX__
		if (sig && r_cons_context_is_main ()) {
			r_sys_signal (SIGINT, SIG_IGN);
		}
#endif
		context->breaked = false;
	}
}

R_API void r_cons_break_push(RConsBreak cb, void *user) {
	r_cons_context_break_push (I.context, cb, user, true);
}

R_API void r_cons_break_pop(void) {
	r_cons_context_break_pop (I.context, true);
}

R_API bool r_cons_is_interactive(void) {
	return I.context->is_interactive;
}

R_API bool r_cons_default_context_is_interactive(void) {
	return r_cons_context_default.is_interactive;
}

R_API bool r_cons_is_breaked(void) {
	if (I.cb_break) {
		I.cb_break (I.user);
	}
	if (I.timeout) {
		if (r_time_now_mono () > I.timeout) {
			I.context->breaked = true;
			eprintf ("\nTimeout!\n");
			I.timeout = 0;
		}
	}
	return I.context->breaked;
}

R_API int r_cons_get_cur_line(void) {
	int curline = 0;
#if __WINDOWS__
	POINT point;
	if (GetCursorPos (&point)) {
		curline = point.y;
	}
#endif
#if __UNIX__
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
				if (isdigit (buf[2])) {
					curline = (buf[2] - '0');
				} if (isdigit (buf[3])) {
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
	I.timeout = (timeout && !I.timeout) 
		? r_time_now_mono () + ((ut64) timeout << 20) : 0;
}

R_API void r_cons_break_end(void) {
	I.context->breaked = false;
	I.timeout = 0;
#if __UNIX__
	r_sys_signal (SIGINT, SIG_IGN);
#endif
	if (!r_stack_is_empty (I.context->break_stack)) {
		// free all the stack
		r_stack_free (I.context->break_stack);
		// create another one
		I.context->break_stack = r_stack_newf (6, break_stack_free);
		I.context->event_interrupt_data = NULL;
		I.context->event_interrupt = NULL;
	}
}

R_API void *r_cons_sleep_begin(void) {
	if (!I.cb_sleep_begin) {
		return NULL;
	}
	return I.cb_sleep_begin (I.user);
}

R_API void r_cons_sleep_end(void *user) {
	if (I.cb_sleep_end) {
		I.cb_sleep_end (I.user, user);
	}
}

#if __WINDOWS__
static HANDLE h;
static BOOL __w32_control(DWORD type) {
	if (type == CTRL_C_EVENT) {
		__break_signal (2); // SIGINT
		eprintf ("{ctrl+c} pressed.\n");
		return true;
	}
	return false;
}
#elif __UNIX__
volatile sig_atomic_t sigwinchFlag;
static void resize(int sig) {
	sigwinchFlag = 1;
}
#endif
void resizeWin(void) {
	if (I.event_resize) {
		I.event_resize (I.event_data);
	}
}

R_API void r_cons_set_click(int x, int y) {
	I.click_x = x;
	I.click_y = y;
	I.click_set = true;
	I.mouse_event = 1;
}

R_API bool r_cons_get_click(int *x, int *y) {
	if (x) {
		*x = I.click_x;
	}
	if (y) {
		*y = I.click_y;
	}
	bool set = I.click_set;
	I.click_set = false;
	return set;
}

R_API void r_cons_enable_highlight(const bool enable) {
        I.enable_highlight = enable;
}

R_API bool r_cons_enable_mouse(const bool enable) {
	if ((I.mouse && enable)
	    || (!I.mouse && !enable)) {
		return I.mouse;
	}
#if __WINDOWS__
	if (I.vtmode == 2) {
#endif
		const char *click = enable
			? "\x1b[?1000;1006;1015h"
			: "\x1b[?1001r"
			  "\x1b[?1000l";
		// : "\x1b[?1000;1006;1015l";
		// const char *old = enable ? "\x1b[?1001s" "\x1b[?1000h" : "\x1b[?1001r" "\x1b[?1000l";
		bool enabled = I.mouse;
		const size_t click_len = strlen (click);
		if (write (2, click, click_len) != click_len) {
			return false;
		}
		I.mouse = enable;
		return enabled;
#if __WINDOWS__
	}
	DWORD mode;
	HANDLE h;
	bool enabled = I.mouse;
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &mode);
	mode |= ENABLE_EXTENDED_FLAGS;
	mode = enable 
		? (mode | ENABLE_MOUSE_INPUT) & ~ENABLE_QUICK_EDIT_MODE
		: (mode & ~ENABLE_MOUSE_INPUT) | ENABLE_QUICK_EDIT_MODE;
	if (SetConsoleMode (h, mode)) {
		I.mouse = enable;
	}
	return enabled;
#else
	return false;
#endif
}

// Stub function that cb_main_output gets pointed to in util/log.c by r_cons_new
// This allows Cutter to set per-task logging redirection
R_API RCons *r_cons_new(void) {
	I.refcnt++;
	if (I.refcnt != 1) {
		return &I;
	}
	I.rgbstr = r_cons_rgb_str_off;
	I.line = r_line_new ();
	I.enable_highlight = true;
	I.highlight = NULL;
	I.is_wine = -1;
	I.fps = 0;
	I.blankline = true;
	I.teefile = NULL;
	I.fix_columns = 0;
	I.fix_rows = 0;
	I.mouse_event = 0;
	I.force_rows = 0;
	I.force_columns = 0;
	I.event_resize = NULL;
	I.event_data = NULL;
	I.noflush = false;
	I.linesleep = 0;
	I.fdin = stdin;
	I.fdout = 1;
	I.break_lines = false;
	I.lines = 0;

	I.context = &r_cons_context_default;
	cons_context_init (I.context, NULL);

	r_cons_get_size (&I.pagesize);
	I.num = NULL;
	I.null = 0;
#if __WINDOWS__
	I.old_cp = GetConsoleOutputCP ();
	I.vtmode = r_cons_is_vtcompat ();
#else
	I.vtmode = 2;
#endif
#if EMSCRIPTEN
	/* do nothing here :? */
#elif __UNIX__
	tcgetattr (0, &I.term_buf);
	memcpy (&I.term_raw, &I.term_buf, sizeof (I.term_raw));
	I.term_raw.c_iflag &= ~(BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	I.term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	I.term_raw.c_cflag &= ~(CSIZE|PARENB);
	I.term_raw.c_cflag |= CS8;
	I.term_raw.c_cc[VMIN] = 1; // Solaris stuff hehe
	r_sys_signal (SIGWINCH, resize);
#elif __WINDOWS__
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, &I.term_buf);
	I.term_raw = 0;
	if (!SetConsoleCtrlHandler ((PHANDLER_ROUTINE)__w32_control, TRUE)) {
		eprintf ("r_cons: Cannot set control console handler\n");
	}
#endif
	I.pager = NULL; /* no pager by default */
	I.mouse = 0;
	I.show_vals = false;
	r_cons_reset ();
	r_cons_rgb_init ();

	r_print_set_is_interrupted_cb (r_cons_is_breaked);

	return &I;
}

R_API RCons *r_cons_free(void) {
#if __WINDOWS__
	r_cons_enable_mouse (false);
	if (I.old_cp) {
		(void)SetConsoleOutputCP (I.old_cp);
		// chcp doesn't pick up the code page switch for some reason
		(void)r_sys_cmdf ("chcp %u > NUL", I.old_cp);
	}
#endif
	I.refcnt--;
	if (I.refcnt != 0) {
		return NULL;
	}
	if (I.line) {
		r_line_free ();
		I.line = NULL;
	}
	R_FREE (I.context->buffer);
	R_FREE (I.break_word);
	cons_context_deinit (I.context);
	R_FREE (I.context->lastOutput);
	I.context->lastLength = 0;
	R_FREE (I.pager);
	return NULL;
}

#define MOAR (4096 * 8)
static bool palloc(int moar) {
	void *temp;
	if (moar <= 0) {
		return false;
	}
	if (!I.context->buffer) {
		int new_sz;
		if ((INT_MAX - MOAR) < moar) {
			return false;
		}
		new_sz = moar + MOAR;
		temp = calloc (1, new_sz);
		if (temp) {
			I.context->buffer_sz = new_sz;
			I.context->buffer = temp;
			I.context->buffer[0] = '\0';
		}
	} else if (moar + I.context->buffer_len > I.context->buffer_sz) {
		char *new_buffer;
		int old_buffer_sz = I.context->buffer_sz;
		if ((INT_MAX - MOAR - moar) < I.context->buffer_sz) {
			return false;
		}
		I.context->buffer_sz += moar + MOAR;
		new_buffer = realloc (I.context->buffer, I.context->buffer_sz);
		if (new_buffer) {
			I.context->buffer = new_buffer;
		} else {
			I.context->buffer_sz = old_buffer_sz;
			return false;
		}
	}
	return true;
}

R_API int r_cons_eof(void) {
	return feof (I.fdin);
}

R_API void r_cons_gotoxy(int x, int y) {
#if __WINDOWS__
	r_cons_w32_gotoxy (1, x, y);
#else
	r_cons_printf ("\x1b[%d;%dH", y, x);
#endif
}

R_API void r_cons_print_clear(void) {
	r_cons_strcat ("\x1b[0;0H\x1b[0m");
}

R_API void r_cons_fill_line(void) {
	char *p, white[1024];
	int cols = I.columns - 1;
	if (cols < 1) {
		return;
	}
	p = (cols >= sizeof (white))
		?  malloc (cols + 1): white;
	if (p) {
		memset (p, ' ', cols);
		p[cols] = 0;
		r_cons_strcat (p);
		if (white != p) {
			free (p);
		}
	}
}

R_API void r_cons_clear_line(int std_err) {
#if __WINDOWS__
	if (I.vtmode) {
		fprintf (std_err? stderr: stdout,"%s", R_CONS_CLEAR_LINE);
	} else {
		char white[1024];
		memset (&white, ' ', sizeof (white));
		if (I.columns > 0 && I.columns < sizeof (white)) {
			white[I.columns - 1] = 0;
		} else if (I.columns == 0) {
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
	r_cons_strcat (Color_RESET_BG Color_RESET);
}

R_API void r_cons_clear(void) {
	I.lines = 0;
#if __WINDOWS__
	r_cons_w32_clear ();
#else
	r_cons_strcat (Color_RESET R_CONS_CLEAR_SCREEN);
#endif
}

static void cons_grep_reset(RConsGrep *grep) {
	R_FREE (grep->str);
	ZERO_FILL (*grep);
	grep->line = -1;
	grep->sort = -1;
	grep->sort_invert = false;
}

R_API void r_cons_reset(void) {
	if (I.context->buffer) {
		I.context->buffer[0] = '\0';
	}
	I.context->buffer_len = 0;
	I.lines = 0;
	I.lastline = I.context->buffer;
	cons_grep_reset (&I.context->grep);
	CTX (pageable) = true;
}

R_API const char *r_cons_get_buffer(void) {
	//check len otherwise it will return trash
	return I.context->buffer_len? I.context->buffer : NULL;
}

R_API int r_cons_get_buffer_len(void) {
	return I.context->buffer_len;
}

R_API void r_cons_filter(void) {
	/* grep */
	if (I.filter || I.context->grep.nstrings > 0 || I.context->grep.tokens_used || I.context->grep.less || I.context->grep.json) {
		(void)r_cons_grepbuf ();
		I.filter = false;
	}
	/* html */
	if (I.is_html) {
		int newlen = 0;
		char *input = r_str_ndup (I.context->buffer, I.context->buffer_len);
		char *res = r_cons_html_filter (input, &newlen);
		free (I.context->buffer);
		I.context->buffer = res;
		I.context->buffer_len = newlen;
		I.context->buffer_sz = newlen;
		free (input);
	}
	if (I.was_html) {
		I.is_html = true;
		I.was_html = false;
	}
}

R_API void r_cons_push(void) {
	if (!I.context->cons_stack) {
		return;
	}
	RConsStack *data = cons_stack_dump (true);
	if (!data) {
		return;
	}
	r_stack_push (I.context->cons_stack, data);
	I.context->buffer_len = 0;
	if (I.context->buffer) {
		memset (I.context->buffer, 0, I.context->buffer_sz);
	}
}

R_API void r_cons_pop(void) {
	if (!I.context->cons_stack) {
		return;
	}
	RConsStack *data = (RConsStack *)r_stack_pop (I.context->cons_stack);
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
	cons_context_init (context, parent);
	return context;
}

R_API void r_cons_context_free(RConsContext *context) {
	if (!context) {
		return;
	}
	cons_context_deinit (context);
	free (context);
}

R_API void r_cons_context_load(RConsContext *context) {
	I.context = context;
}

R_API void r_cons_context_reset(void) {
	I.context = &r_cons_context_default;
}

R_API bool r_cons_context_is_main(void) {
	return I.context == &r_cons_context_default;
}

R_API void r_cons_context_break(RConsContext *context) {
	if (!context) {
		return;
	}
	context->breaked = true;
	if (context->event_interrupt) {
		context->event_interrupt (context->event_interrupt_data);
	}
}

R_API void r_cons_last(void) {
	if (!CTX (lastEnabled)) {
		return;
	}
	CTX (lastMode) = true;
	r_cons_memcat (CTX (lastOutput), CTX (lastLength));
}

static bool lastMatters(void) {
	return (I.context->buffer_len > 0) \
		&& (CTX (lastEnabled) && !I.filter && I.context->grep.nstrings < 1 && \
		!I.context->grep.tokens_used && !I.context->grep.less && \
		!I.context->grep.json && !I.is_html);
}

R_API void r_cons_echo(const char *msg) {
	static RStrBuf *echodata = NULL; // TODO: move into RConsInstance? maybe nope
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
			r_cons_strcat (data);
			r_cons_newline ();
			echodata = NULL;
			free (data);
		}
	}
}

R_API void r_cons_flush(void) {
	const char *tee = I.teefile;
	if (I.noflush) {
		return;
	}
	if (I.null) {
		r_cons_reset ();
		return;
	}
	if (lastMatters () && !CTX (lastMode)) {
		// snapshot of the output
		if (CTX (buffer_len) > CTX (lastLength)) {
			free (CTX (lastOutput));
			CTX (lastOutput) = malloc (CTX (buffer_len) + 1);
		}
		CTX (lastLength) = CTX (buffer_len);
		memcpy (CTX (lastOutput), CTX (buffer), CTX (buffer_len));
	} else {
		CTX (lastMode) = false;
	}
	r_cons_filter ();
	if (r_cons_is_interactive () && I.fdout == 1) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (CTX (pageable) && CTX (buffer) && I.pager && *I.pager && CTX (buffer_len) > 0 && r_str_char_count (CTX (buffer), '\n') >= I.rows) {
			I.context->buffer[I.context->buffer_len - 1] = 0;
			if (!strcmp (I.pager, "..")) {
				char *str = r_str_ndup (CTX (buffer), CTX (buffer_len));
				CTX (pageable) = false;
				r_cons_less_str (str, NULL);
				r_cons_reset ();
				free (str);
				return;
			} else {
				r_sys_cmd_str_full (I.pager, CTX (buffer), NULL, NULL, NULL);
				r_cons_reset ();
			}
		} else if (I.context->buffer_len > CONS_MAX_USER) {
#if COUNT_LINES
			int i, lines = 0;
			for (i = 0; I.context->buffer[i]; i++) {
				if (I.context->buffer[i] == '\n') {
					lines ++;
				}
			}
			if (lines > 0 && !r_cons_yesno ('n',"Do you want to print %d lines? (y/N)", lines)) {
				r_cons_reset ();
				return;
			}
#else
			char buf[8];
			r_num_units (buf, sizeof (buf), I.context->buffer_len);
			if (!r_cons_yesno ('n', "Do you want to print %s chars? (y/N)", buf)) {
				r_cons_reset ();
				return;
			}
#endif
			// fix | more | less problem
			r_cons_set_raw (true);
		}
	}
	if (tee && *tee) {
		FILE *d = r_sandbox_fopen (tee, "a+");
		if (d) {
			if (I.context->buffer_len != fwrite (I.context->buffer, 1, I.context->buffer_len, d)) {
				eprintf ("r_cons_flush: fwrite: error (%s)\n", tee);
			}
			fclose (d);
		} else {
			eprintf ("Cannot write on '%s'\n", tee);
		}
	}
	r_cons_highlight (I.highlight);

	// is_html must be a filter, not a write endpoint
	if (r_cons_is_interactive () && !r_sandbox_enable (false)) {
		if (I.linesleep > 0 && I.linesleep < 1000) {
			int i = 0;
			int pagesize = R_MAX (1, I.pagesize);
			char *ptr = I.context->buffer;
			char *nl = strchr (ptr, '\n');
			int len = I.context->buffer_len;
			I.context->buffer[I.context->buffer_len] = 0;
			r_cons_break_push (NULL, NULL);
			while (nl && !r_cons_is_breaked ()) {
				__cons_write (ptr, nl - ptr + 1);
				if (I.linesleep && !(i % pagesize)) {
					r_sys_usleep (I.linesleep * 1000);
				}
				ptr = nl + 1;
				nl = strchr (ptr, '\n');
				i++;
			}
			__cons_write (ptr, I.context->buffer + len - ptr);
			r_cons_break_pop ();
		} else {
			__cons_write (I.context->buffer, I.context->buffer_len);
		}
	} else {
		__cons_write (I.context->buffer, I.context->buffer_len);
	}

	r_cons_reset ();
	if (I.newline) {
		eprintf ("\n");
		I.newline = false;
	}
}

R_API void r_cons_visual_flush(void) {
	if (I.noflush) {
		return;
	}
	r_cons_highlight (I.highlight);
	if (!I.null) {
/* TODO: this ifdef must go in the function body */
#if __WINDOWS__
		if (I.vtmode) {
			r_cons_visual_write (I.context->buffer);
		} else {
			r_cons_w32_print (I.context->buffer, I.context->buffer_len, true);
		}
#else
		r_cons_visual_write (I.context->buffer);
#endif
	}
	r_cons_reset ();
	if (I.fps) {
		r_cons_print_fps (0);
	}
}

R_API void r_cons_print_fps (int col) {
	int fps = 0, w = r_cons_get_size (NULL);
	static ut64 prev = 0LL; //r_time_now_mono ();
	fps = 0;
	if (prev) {
		ut64 now = r_time_now_mono ();
		st64 diff = (st64)(now - prev);
		if (diff < 0) {
			fps = 0;
		} else {
			fps = (diff < 1000000)? (1000000.0 / diff): 0;
		}
		prev = now;
	} else {
		prev = r_time_now_mono ();
	}
	if (col < 1) {
		col = 12;
	}
#ifdef __WINDOWS__
	if (I.vtmode) {
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

R_API void r_cons_visual_write(char *buffer) {
	char white[1024];
	int cols = I.columns;
	int alen, plen, lines = I.rows;
	bool break_lines = I.break_lines;
	const char *endptr;
	char *nl, *ptr = buffer, *pptr;

	if (I.null) {
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
				if (I.blankline && w > 0) {
					if (w > sizeof (white) - 1) {
						w = sizeof (white) - 1;
					}
					__cons_write (white, w);
				}
			}
			// TRICK to empty columns.. maybe buggy in w32
			if (r_mem_mem ((const ut8*)ptr, len, (const ut8*)"\x1b[0;0H", 6)) {
				lines = I.rows;
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
		if (cols > sizeof (white)) {
			cols = sizeof (white);
		}
		while (--lines >= 0) {
			__cons_write (white, cols);
		}
	}
}

R_API void r_cons_printf_list(const char *format, va_list ap) {
	size_t size, written;
	va_list ap2, ap3;

	va_copy (ap2, ap);
	va_copy (ap3, ap);
	if (I.null || !format) {
		va_end (ap2);
		va_end (ap3);
		return;
	}
	if (strchr (format, '%')) {
		if (palloc (MOAR + strlen (format) * 20)) {
club:
			size = I.context->buffer_sz - I.context->buffer_len - 1; /* remaining space in I.context->buffer */
			written = vsnprintf (I.context->buffer + I.context->buffer_len, size, format, ap3);
			if (written >= size) { /* not all bytes were written */
				if (palloc (written)) {
					va_end (ap3);
					va_copy (ap3, ap2);
					goto club;
				}
			}
			I.context->buffer_len += written;
			I.context->buffer[I.context->buffer_len] = 0;
		}
	} else {
		r_cons_strcat (format);
	}
	va_end (ap2);
	va_end (ap3);
}

R_API int r_cons_printf(const char *format, ...) {
	va_list ap;
	if (!format || !*format) {
		return -1;
	}
	va_start (ap, format);
	r_cons_printf_list (format, ap);
	va_end (ap);

	return 0;
}

R_API int r_cons_get_column(void) {
	char *line = strrchr (I.context->buffer, '\n');
	if (!line) {
		line = I.context->buffer;
	}
	I.context->buffer[I.context->buffer_len] = 0;
	return r_str_ansi_len (line);
}

/* final entrypoint for adding stuff in the buffer screen */
R_API int r_cons_memcat(const char *str, int len) {
	if (len < 0) {
		return -1;
	}
	if (I.echo) {
		// Here to silent pedantic meson flags ...
		int rlen;
		if ((rlen = write (2, str, len)) != len) {
			return rlen;
		}
	}
	if (str && len > 0 && !I.null) {
		if (palloc (len + 1)) {
			memcpy (I.context->buffer + I.context->buffer_len, str, len);
			I.context->buffer_len += len;
			I.context->buffer[I.context->buffer_len] = 0;
		}
	}
	if (I.flush) {
		r_cons_flush ();
	}
	if (I.break_word && str && len > 0) {
		if (r_mem_mem ((const ut8*)str, len, (const ut8*)I.break_word, I.break_word_len)) {
			I.context->breaked = true;
		}
	}
	return len;
}

R_API void r_cons_memset(char ch, int len) {
	if (!I.null && len > 0) {
		if (palloc (len + 1)) {
			memset (I.context->buffer + I.context->buffer_len, ch, len);
			I.context->buffer_len += len;
			I.context->buffer[I.context->buffer_len] = 0;
		}
	}
}

R_API void r_cons_strcat(const char *str) {
	int len;
	if (!str || I.null) {
		return;
	}
	len = strlen (str);
	if (len > 0) {
		r_cons_memcat (str, len);
	}
}

R_API void r_cons_newline(void) {
	if (!I.null) {
		r_cons_strcat ("\n");
	}
#if 0
This place is wrong to manage the color reset, can interfire with r2pipe output sending resetchars
and break json output appending extra chars.
this code now is managed into output.c:118 at function r_cons_w32_print
now the console color is reset with each \n (same stuff do it here but in correct place ... i think)

#if __WINDOWS__
	r_cons_reset_colors();
#else
	r_cons_strcat (Color_RESET_ALL"\n");
#endif
	if (I.is_html) r_cons_strcat ("<br />\n");
#endif
}

/* return the aproximated x,y of cursor before flushing */
// XXX this function is a huge bottleneck
R_API int r_cons_get_cursor(int *rows) {
	int i, col = 0;
	int row = 0;
	// TODO: we need to handle GOTOXY and CLRSCR ansi escape code too
	for (i = 0; i < I.context->buffer_len; i++) {
		// ignore ansi chars, copypasta from r_str_ansi_len
		if (I.context->buffer[i] == 0x1b) {
			char ch2 = I.context->buffer[i + 1];
			char *str = I.context->buffer;
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp (str + 2 + 5, "rgb:", 4)) {
					i += 18;
				}
			} else if (ch2 == '[') {
				for (++i; str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H'; i++) {
					;
				}
			}
		} else if (I.context->buffer[i] == '\n') {
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
}

R_API bool r_cons_isatty(void) {
#if __UNIX__
	struct winsize win = { 0 };
	const char *tty;
	struct stat sb;

	if (!isatty (1)) {
		return false;
	}
	if (ioctl (1, TIOCGWINSZ, &win)) {
		return false;
	}
	if (!win.ws_col || !win.ws_row) {
		return false;
	}
	tty = ttyname (1);
	if (!tty) {
		return false;
	}
	if (stat (tty, &sb) || !S_ISCHR (sb.st_mode)) {
		return false;
	}
	return true;
#endif
	/* non-UNIX do not have ttys */
	return false;
}

#if __WINDOWS__
static int __xterm_get_cur_pos(int *xpos) {
	int ypos = 0;
	const char *get_pos = R_CONS_GET_CURSOR_POSITION;
	if (write (I.fdout, get_pos, sizeof (get_pos)) < 1) {
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
			while (ch = r_cons_readchar_timeout (25)) {
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
			if ((!i && !IS_DIGIT (ch)) || // dumps arrow keys etc.
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
	if (write (I.fdout, R_CONS_CURSOR_SAVE, sizeof (R_CONS_CURSOR_SAVE)) < 1) {
		return false;
	}
	int rows, columns;
	(void)write (I.fdout, "\x1b[999;999H", sizeof ("\x1b[999;999H"));
	rows = __xterm_get_cur_pos (&columns);
	if (rows) {
		I.rows = rows;
		I.columns = columns;
	} // otherwise reuse previous values
	(void)write (I.fdout, R_CONS_CURSOR_RESTORE, sizeof (R_CONS_CURSOR_RESTORE));
	return true;
}

#endif

// XXX: if this function returns <0 in rows or cols expect MAYHEM
R_API int r_cons_get_size(int *rows) {
#if __WINDOWS__
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	bool ret = GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &csbi);
	if (ret) {
		I.columns = csbi.srWindow.Right - csbi.srWindow.Left + 1;
		I.rows = csbi.srWindow.Bottom - csbi.srWindow.Top + 1;
	} else {
		if (I.term_xterm) {
			ret = __xterm_get_size ();
		}
		if (!ret || (I.columns == -1 && I.rows == 0)) {
			// Stdout is probably redirected so we set default values
			I.columns = 80;
			I.rows = 23;
		}
	}
#elif EMSCRIPTEN
	I.columns = 80;
	I.rows = 23;
#elif __UNIX__
	struct winsize win = { 0 };
	if (isatty (0) && !ioctl (0, TIOCGWINSZ, &win)) {
		if ((!win.ws_col) || (!win.ws_row)) {
			const char *tty = isatty (1)? ttyname (1): NULL;
			int fd = open (tty? tty: "/dev/tty", O_RDONLY);
			if (fd != -1) {
				int ret = ioctl (fd, TIOCGWINSZ, &win);
				if (ret || !win.ws_col || !win.ws_row) {
					win.ws_col = 80;
					win.ws_row = 23;
				}
				close (fd);
			}
		}
		I.columns = win.ws_col;
		I.rows = win.ws_row;
	} else {
		I.columns = 80;
		I.rows = 23;
	}
#else
	char *str = r_sys_getenv ("COLUMNS");
	if (str) {
		I.columns = atoi (str);
		I.rows = 23; // XXX. windows must get console size
		free (str);
	} else {
		I.columns = 80;
		I.rows = 23;
	}
#endif
#if SIMULATE_ADB_SHELL
	I.rows = 0;
	I.columns = 0;
#endif
#if SIMULATE_MAYHEM
	// expect tons of crashes
	I.rows = -1;
	I.columns = -1;
#endif
	if (I.rows < 0) {
		I.rows = 0;
	}
	if (I.columns < 0) {
		I.columns = 0;
	}
	if (I.force_columns) {
		I.columns = I.force_columns;
	}
	if (I.force_rows) {
		I.rows = I.force_rows;
	}
	if (I.fix_columns) {
		I.columns += I.fix_columns;
	}
	if (I.fix_rows) {
		I.rows += I.fix_rows;
	}
	if (rows) {
		*rows = I.rows;
	}
	I.rows = R_MAX (0, I.rows);
	return R_MAX (0, I.columns);
}

#if __WINDOWS__
R_API int r_cons_is_vtcompat(void) {
	DWORD major;
	DWORD minor;
	DWORD release = 0;
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
			I.term_xterm = 1;
			free (term);
			return 2;
		}
		I.term_xterm = 0;
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
		char *dot = strtok (info->version, ".");
		major = atoi (dot);
		dot = strtok (NULL, ".");
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
#if __WINDOWS__
	if (I.vtmode) {
#endif
		(void) write (1, cursor ? "\x1b[?25h" : "\x1b[?25l", 6);
#if __WINDOWS__
	} else {
		static HANDLE hStdout = NULL;
		static DWORD size = -1;
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
 * the next calls ^=1, so: 1, 0, 1, 0, 1, ...
 *
 * If you doesn't use this order you'll probably loss your terminal properties.
 *
 */
R_API void r_cons_set_raw(bool is_raw) {
	static int oldraw = -1;
	if (oldraw != -1) {
		if (is_raw == oldraw) {
			return;
		}
	}
#if EMSCRIPTEN
	/* do nothing here */
#elif __UNIX__
	// enforce echo off
	if (is_raw) {
		I.term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
		tcsetattr (0, TCSANOW, &I.term_raw);
	} else {
		tcsetattr (0, TCSANOW, &I.term_buf);
	}
#elif __WINDOWS__
	if (is_raw) {
		if (I.term_xterm) {
			r_sandbox_system ("stty raw -echo", 1);
		} else {
			SetConsoleMode (h, I.term_raw);
		}
	} else {
		if (I.term_xterm) {
			r_sandbox_system ("stty -raw echo", 1);
		} else {
			SetConsoleMode (h, I.term_buf);
		}
	}
#else
#warning No raw console supported for this platform
#endif
	fflush (stdout);
	oldraw = is_raw;
}

R_API void r_cons_set_utf8(bool b) {
	I.use_utf8 = b;
#if __WINDOWS__
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
			R_LOG_WARN ("UTF-8 Codepage not installed.\n");
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
	r_cons_strcat (R_CONS_INVERT (set, color));
}

/*
  Enable/Disable scrolling in terminal:
    FMI: cd libr/cons/t ; make ti ; ./ti
  smcup: disable terminal scrolling (fullscreen mode)
  rmcup: enable terminal scrolling (normal mode)
*/
R_API bool r_cons_set_cup(bool enable) {
#if __UNIX__
	const char *code = enable
		? "\x1b[?1049h" "\x1b" "7\x1b[?47h"
		: "\x1b[?1049l" "\x1b[?47l" "\x1b" "8";
	const size_t code_len = strlen (code);
	if (write (2, code, code_len) != code_len) {
		return false;
	}
	fflush (stdout);
#elif __WINDOWS__
	if (I.vtmode) {
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
	char *b = malloc (I.context->buffer_len + 1);
	if (!b) {
		return;
	}
	memcpy (b, I.context->buffer, I.context->buffer_len);
	b[I.context->buffer_len] = 0;
	r_cons_reset ();
	// align current buffer N chars right
	r_cons_strcat_justify (b, c, 0);
	r_cons_gotoxy (0, 0);
	free (b);
}

//  XXX deprecate must be push/pop context state
static bool lasti = false; /* last interactive mode */

R_API void r_cons_set_interactive(bool x) {
	lasti = r_cons_singleton ()->context->is_interactive;
	r_cons_singleton ()->context->is_interactive = x;
}

R_API void r_cons_set_last_interactive(void) {
	r_cons_singleton ()->context->is_interactive = lasti;
}

R_API void r_cons_set_title(const char *str) {
#if __WINDOWS__
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
	if (I.line) {
		I.line->zerosep = true;
	}
	(void)write (1, "", 1);
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

	if (!I.enable_highlight) {
		r_cons_enable_highlight (true);
		return;
	}
	if (word && *word && I.context->buffer) {
		int word_len = strlen (word);
		char *orig;
		clean = r_str_ndup (I.context->buffer, I.context->buffer_len);
		l = r_str_ansi_filter (clean, &orig, &cpos, -1);
		free (I.context->buffer);
		I.context->buffer = orig;
		if (I.highlight) {
			if (strcmp (word, I.highlight)) {
				free (I.highlight);
				I.highlight = strdup (word);
			}
		} else {
			I.highlight = strdup (word);
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
		res = r_str_replace_thunked (I.context->buffer, clean, cpos,
					l, word, rword, 1);
		if (res) {
			I.context->buffer = res;
			I.context->buffer_len = I.context->buffer_sz = strlen (res);
		}
		free (rword);
		free (clean);
		free (cpos);
		/* don't free orig - it's assigned
		 * to I.context->buffer and possibly realloc'd */
	} else {
		R_FREE (I.highlight);
	}
}

R_API char *r_cons_lastline(int *len) {
	char *b = I.context->buffer + I.context->buffer_len;
	while (b > I.context->buffer) {
		if (*b == '\n') {
			b++;
			break;
		}
		b--;
	}
	if (len) {
		int delta = b - I.context->buffer;
		*len = I.context->buffer_len - delta;
	}
	return b;
}

// same as r_cons_lastline(), but len will be the number of
// utf-8 characters excluding ansi escape sequences as opposed to just bytes
R_API char *r_cons_lastline_utf8_ansi_len(int *len) {
	if (!len) {
		return r_cons_lastline (0);
	}

	char *b = I.context->buffer + I.context->buffer_len;
	int l = 0;
	int last_possible_ansi_end = 0;
	char ch = '\0';
	char ch2;
	while (b > I.context->buffer) {
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
	if (n > I.context->buffer_len) {
		I.context->buffer_len = 0;
		return false;
	}
	I.context->buffer_len -= n;
	return true;
}

R_API void r_cons_chop(void) {
	while (I.context->buffer_len > 0) {
		char ch = I.context->buffer[I.context->buffer_len - 1];
		if (ch != '\n' && !IS_WHITESPACE (ch)) {
			break;
		}
		I.context->buffer_len--;
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
	free (I.break_word);
	if (s) {
		I.break_word = strdup (s);
		I.break_word_len = strlen (s);
	} else {
		I.break_word = NULL;
		I.break_word_len = 0;
	}
}

/* Prints a coloured help message.
 * help should be an array of the following form:
 * {"command", "args", "description",
 * "command2", "args2", "description"}; */
R_API void r_cons_cmd_help(const char *help[], bool use_color) {
	RCons *cons = r_cons_singleton ();
	const char *pal_args_color = use_color ? cons->context->pal.args : "",
		   *pal_help_color = use_color ? cons->context->pal.help : "",
		   *pal_input_color = use_color ? cons->context->pal.input : "",
		   *pal_reset = use_color ? cons->context->pal.reset : "";
	int i, max_length = 0;
	const char *usage_str = "Usage:";

	for (i = 0; help[i]; i += 3) {
		int len0 = strlen (help[i]);
		int len1 = strlen (help[i + 1]);
		if (i) {
			max_length = R_MAX (max_length, len0 + len1);
		}
	}

	for (i = 0; help[i]; i += 3) {
		if (!strncmp (help[i], usage_str, strlen (usage_str))) {
			// Lines matching Usage: should always be the first in inline doc
			r_cons_printf ("%s%s %s  %s%s\n", pal_args_color,
				help[i], help[i + 1], help[i + 2], pal_reset);
			continue;
		}
		if (!help[i + 1][0] && !help[i + 2][0]) {
			// no need to indent the sections lines
			r_cons_printf ("%s%s%s\n", pal_help_color, help[i], pal_reset);
		} else {
			// these are the normal lines
			int str_length = strlen (help[i]) + strlen (help[i + 1]);
			int padding = (str_length < max_length)? (max_length - str_length): 0;
			r_cons_printf ("| %s%s%s%s%*s  %s%s%s\n",
				pal_input_color, help[i], pal_args_color, help[i + 1],
				padding, "", pal_help_color, help[i + 2], pal_reset);
		}
	}
}

R_API void r_cons_clear_buffer(void) {
	if (I.vtmode) {
		(void)write (1, "\x1b" "c\x1b[3J", 6);
	}
}
