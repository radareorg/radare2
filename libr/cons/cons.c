/* radare2 - LGPL - Copyright 2008-2016 - pancake */

#include <r_cons.h>
#include <r_print.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#if __UNIX__ || __CYGWIN__
#include <signal.h>
#endif

#define COUNT_LINES 1

R_LIB_VERSION (r_cons);

static RCons r_cons_instance;
#define I r_cons_instance

//this structure goes into cons_stack when r_cons_push/pop
typedef struct {
	char *buf;
	int buf_len;	
	int buf_size;
} RConsStack;


static void cons_stack_free(void *ptr) {
	RConsStack *s = (RConsStack *)ptr;
	free (s->buf);
	free (s);
}

static void break_signal(int sig) {
	I.breaked = true;
	r_print_set_interrupted (I.breaked);
	if (I.event_interrupt) {
		I.event_interrupt (I.data);
	}
}

static inline void r_cons_write(const char *buf, int len) {
#if __WINDOWS__ && !__CYGWIN__
	if (I.ansicon) {
		(void) write (I.fdout, buf, len);
	} else {
		if (I.fdout == 1) {
			r_cons_w32_print ((const ut8*)buf, len, 0);
		} else {
			(void) write (I.fdout, buf, len);
		}
	}
#else
	(void) write (I.fdout, buf, len);
#endif
}

R_API char *r_cons_color_random_string(int bg) {
	int r, g, b;
	if (I.truecolor > 0) {
		char out[32];
		r = r_num_rand (0xff);
		g = r_num_rand (0xff);
		b = r_num_rand (0xff);
		r_cons_rgb_str (out, r, g, b, bg);
		return strdup (out);
	}
	// random ansi
	const char *color = "white";
	r = r_num_rand (8);
	switch (r) {
	case 0: color = "red"; break;
	case 1: color = "white"; break;
	case 2: color = "green"; break;
	case 3: color = "magenta"; break;
	case 4: color = "yellow"; break;
	case 5: color = "cyan"; break;
	case 6: color = "blue"; break;
	case 7: color = "gray"; break;
	}
	return strdup (color);
}

R_API char *r_cons_color_random(int bg) {
	int r, g, b;
	if (I.truecolor > 0) {
		char out[32];
		r = r_num_rand (0xff);
		g = r_num_rand (0xff);
		b = r_num_rand (0xff);
		r_cons_rgb_str (out, r, g, b, bg);
		return strdup (out);
	}
	const char *color = Color_RESET;
	// random ansi
	r = r_num_rand (16);
	switch (r) {
	case 0: color = Color_RED; break;
	case 1: color = Color_BRED; break;
	case 2: color = Color_WHITE; break;
	case 3: color = Color_BWHITE; break;
	case 4: color = Color_GREEN; break;
	case 5: color = Color_BGREEN; break;
	case 6: color = Color_MAGENTA; break;
	case 7: color = Color_BMAGENTA; break;
	case 8: color = Color_YELLOW; break;
	case 9: color = Color_BYELLOW; break;
	case 10: color = Color_CYAN; break;
	case 11: color = Color_BCYAN; break;
	case 12: color = Color_BLUE; break;
	case 13: color = Color_BBLUE; break;
	case 14: color = Color_GRAY; break;
	case 15: color = Color_BGRAY; break;
	}
	return strdup (color);
}

R_API void r_cons_color (int fg, int r, int g, int b) {
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

R_API void r_cons_strcat_justify (const char *str, int j, char c) {
	int i, o, len;
	for (o = i = len = 0; str[i]; i++, len++) {
		if (str[i]=='\n') {
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
		r_cons_memcat (str+o, len);
	}
}

R_API RCons *r_cons_singleton () {
	return &I;
}

R_API void r_cons_break(void (*cb)(void *u), void *user) {
	I.breaked = false;
	I.event_interrupt = cb;
	I.data = user;
#if __UNIX__ || __CYGWIN__
	signal (SIGINT, break_signal);
#endif
}

R_API bool r_cons_is_breaked() {
	return I.breaked;
}

R_API void r_cons_break_end() {
	I.breaked = false;
	r_print_set_interrupted (I.breaked);
#if __UNIX__ || __CYGWIN__
	signal (SIGINT, SIG_IGN);
#endif
}

#if __WINDOWS__ && !__CYGWIN__
static HANDLE h;
static BOOL __w32_control(DWORD type) {
	if (type == CTRL_C_EVENT) {
		break_signal (2); // SIGINT
		eprintf("{ctrl+c} pressed.\n");
		return true;
	}
	return false;
}
#elif __UNIX__ || __CYGWIN__
static void resize (int sig) {
	if (I.event_resize) {
		I.event_resize (I.event_data);
	}
}
#endif

R_API bool r_cons_enable_mouse(const bool enable) {
#if __UNIX__ || __CYGWIN__
	const char *code = enable
		? "\x1b[?1001s" "\x1b[?1000h"
		: "\x1b[?1001r" "\x1b[?1000l";
	bool enabled = I.mouse;
	I.mouse = enable;
	write (2, code, 16);
	return enabled;
#else
	return false;
#endif
}

static void r_cons_pal_null() {
	int i;
	RCons *cons = r_cons_singleton ();
	for (i = 0; i < R_CONS_PALETTE_LIST_SIZE; i++){
		cons->pal.list[i] = NULL;	
	}
}

R_API RCons *r_cons_new() {
	I.refcnt++;
	if (I.refcnt != 1) {
		return &I;
	}
	I.line = r_line_new ();
	I.highlight = NULL;
	I.event_interrupt = NULL;
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
	I.data = NULL;
	I.event_data = NULL;
	I.is_interactive = true;
	I.noflush = false;
	I.linesleep = 0;
	I.fdin = stdin;
	I.fdout = 1;
	I.breaked = false;
	//I.lines = 0;
	I.buffer = NULL;
	I.buffer_sz = 0;
	I.buffer_len = 0;
	r_cons_get_size (&I.pagesize);
	I.num = NULL;
	I.null = 0;
#if __WINDOWS__ && !__CYGWIN__
	I.ansicon = r_sys_getenv ("ANSICON");
#endif
#if EMSCRIPTEN
	/* do nothing here :? */
#elif __UNIX__ || __CYGWIN__
	tcgetattr (0, &I.term_buf);
	memcpy (&I.term_raw, &I.term_buf, sizeof (I.term_raw));
	I.term_raw.c_iflag &= ~(BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
	I.term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	I.term_raw.c_cflag &= ~(CSIZE|PARENB);
	I.term_raw.c_cflag |= CS8;
	I.term_raw.c_cc[VMIN] = 1; // Solaris stuff hehe
	signal (SIGWINCH, resize);
#elif __WINDOWS__
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, (PDWORD) &I.term_buf);
	I.term_raw = 0;
	if (!SetConsoleCtrlHandler ((PHANDLER_ROUTINE)__w32_control, TRUE)) {
		eprintf ("r_cons: Cannot set control console handler\n");
	}
#endif
	I.pager = NULL; /* no pager by default */
	I.truecolor = 0;
	I.mouse = 0;
	I.cons_stack = r_stack_newf (6, cons_stack_free);
	r_cons_pal_null ();
	r_cons_pal_init (NULL);
	r_cons_rgb_init ();
	r_cons_reset ();
	return &I;
}

R_API RCons *r_cons_free() {
	I.refcnt--;
	if (I.refcnt != 0) {
		return NULL;
	}
	r_cons_pal_free ();
	if (I.line) {
		r_line_free ();
		I.line = NULL;
	}
	if (I.buffer) {
		free (I.buffer);
		I.buffer = NULL;
	}
	r_stack_free (I.cons_stack);	
	return NULL;
}

#define MOAR (4096 * 8)
static bool palloc(int moar) {
	void *temp;
	if (moar <= 0) {
		return false;
	}
	if (!I.buffer) {
		int new_sz;
		if ((INT_MAX - MOAR) < moar) {
			return false;
		}
		new_sz = moar + MOAR;
		temp = calloc (1, new_sz);
		if (temp) {
			I.buffer_sz = new_sz;
			I.buffer = temp;
			I.buffer[0] = '\0';
		}
	} else if (moar + I.buffer_len > I.buffer_sz) {
		char *new_buffer;
		int old_buffer_sz = I.buffer_sz;
		if ((INT_MAX - MOAR - moar) < I.buffer_sz) {
			return false;
		}
		I.buffer_sz += moar + MOAR;
		new_buffer = realloc (I.buffer, I.buffer_sz);
		if (new_buffer) {
			I.buffer = new_buffer;
		} else {
			I.buffer_sz = old_buffer_sz;
			return false;
		}
	}
	return true;
}

R_API int r_cons_eof() {
	return feof (I.fdin);
}

R_API void r_cons_gotoxy(int x, int y) {
	r_cons_printf ("\x1b[%d;%dH", y, x);
}

R_API void r_cons_print_clear() {
	r_cons_strcat ("\x1b[0;0H\x1b[0m");
}

R_API void r_cons_fill_line() {
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
	if (I.ansicon) {
		fprintf (std_err? stderr: stdout,"\x1b[0K\r");
	} else {
		char white[1024];
		memset (&white, ' ', sizeof (white));
		if (I.columns < sizeof (white)) {
			white[I.columns - 1] = 0;
		} else {
			white[sizeof (white) - 1] = 0; // HACK
		}
		fprintf (std_err? stderr: stdout, "\r%s\r", white);
	}
#else
	fprintf (std_err? stderr: stdout,"\x1b[0K\r");
#endif
	fflush (std_err? stderr: stdout);
}

R_API void r_cons_clear00() {
	r_cons_clear ();
	r_cons_gotoxy (0, 0);
}

R_API void r_cons_reset_colors() {
	r_cons_strcat (Color_RESET);
}

R_API void r_cons_clear() {
	r_cons_strcat (Color_RESET"\x1b[2J");
	I.lines = 0;
}

R_API void r_cons_reset() {
	if (I.buffer) {
		I.buffer[0] = '\0';
	}
	I.buffer_len = 0;
	I.lines = 0;
	I.lastline = I.buffer;
	I.grep.strings[0][0] = '\0';
	I.grep.nstrings = 0; // XXX
	I.grep.line = -1;
	I.grep.sort = -1;
	I.grep.sort_invert = false;
	I.grep.str = NULL;
	memset (I.grep.tokens, 0, R_CONS_GREP_TOKENS);
	I.grep.tokens_used = 0;
}

R_API const char *r_cons_get_buffer() {
	return I.buffer;
}

R_API void r_cons_filter() {
	/* grep*/
	if (I.grep.nstrings > 0 || I.grep.tokens_used || I.grep.less || I.grep.json) {
		r_cons_grepbuf (I.buffer, I.buffer_len);
	}
	/* html */
	/* TODO */
}


R_API void r_cons_push() {
	if (I.cons_stack) {
		RConsStack *data = R_NEW0 (RConsStack);
		data->buf = malloc (I.buffer_len);
		if (!data->buf) {
			free (data);
			return;
		}
		memcpy (data->buf, I.buffer, I.buffer_len);
		data->buf_len = I.buffer_len;
		data->buf_size = I.buffer_sz;
		r_stack_push (I.cons_stack, data);
		I.buffer_len = 0;
		memset (I.buffer, 0, I.buffer_sz);
	}
}

R_API void r_cons_pop() {
	if (I.cons_stack) {
		RConsStack *data = (RConsStack *)r_stack_pop (I.cons_stack);
		char *tmp;
		if (!data) {
			return;
		}
		if (!data->buf) {
			free (data);
			return;
		} 
		tmp = malloc (data->buf_size);
		if (!tmp) {
			cons_stack_free ((void *)data);
			return;
		}
		free (I.buffer);
		I.buffer = tmp;
		memcpy (I.buffer, data->buf, data->buf_len);
		I.buffer_len = data->buf_len;
		I.buffer_sz = data->buf_size;
		cons_stack_free ((void *)data);
	}
}

R_API void r_cons_flush() {
	const char *tee = I.teefile;
	if (I.noflush) {
		return;
	}
	if (I.null) {
		r_cons_reset ();
		return;
	}
	r_cons_filter ();
	if (I.is_interactive && I.fdout == 1) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (I.pager && *I.pager && I.buffer_len > 0
				&& r_str_char_count (I.buffer, '\n') >= I.rows) {
			I.buffer[I.buffer_len-1] = 0;
			r_sys_cmd_str_full (I.pager, I.buffer, NULL, NULL, NULL);
			r_cons_reset ();

		} else if (I.buffer_len > CONS_MAX_USER) {
#if COUNT_LINES
			int i, lines = 0;
			for (i = 0; I.buffer[i]; i++) {
				if (I.buffer[i]=='\n') {
					lines ++;
				}
			}
			if (lines > 0 && !r_cons_yesno ('n',"Do you want to print %d lines? (y/N)", lines)) {
				r_cons_reset ();
				return;
			}
#else
			char buf[64];
			char *buflen = r_num_units (buf, I.buffer_len);
			if (buflen && !r_cons_yesno ('n',"Do you want to print %s chars? (y/N)", buflen)) {
				r_cons_reset ();
				return;
			}
#endif
			// fix | more | less problem
			r_cons_set_raw (1);
		}
	}
	if (tee && *tee) {
		FILE *d = r_sandbox_fopen (tee, "a+");
		if (d) {
			if (I.buffer_len != fwrite (I.buffer, 1, I.buffer_len, d)) {
				eprintf ("r_cons_flush: fwrite: error (%s)\n", tee);
			}
			fclose (d);
		} else {
			eprintf ("Cannot write on '%s'\n", tee);
		}
	}
	r_cons_highlight (I.highlight);
	// is_html must be a filter, not a write endpoint
	if (I.is_html) {
		r_cons_html_print (I.buffer);
	} else {
		if (I.linesleep > 0 && I.linesleep < 1000) {
			int i = 0;
			int pagesize = R_MAX (1, I.pagesize);
			char *ptr = I.buffer;
			char *nl = strchr (ptr, '\n');
			int len = I.buffer_len;
			I.buffer[I.buffer_len] = 0;
			r_cons_break (NULL, NULL);
			while (nl && !r_cons_is_breaked ()) {
				r_cons_write (ptr, nl - ptr + 1);
				if (!(i % pagesize)) {
					r_sys_usleep (I.linesleep * 1000);
				}
				ptr = nl + 1;
				nl = strchr (ptr, '\n');
				i++;
			}
			r_cons_write (ptr, I.buffer + len - ptr);
			r_cons_break_end ();
		} else {
			r_cons_write (I.buffer, I.buffer_len);
		}
	}

	r_cons_reset ();
	if (I.newline) {
		eprintf ("\n");
		I.newline = false;
	}
}

R_API void r_cons_visual_flush() {
	if (I.noflush) {
		return;
	}
	r_cons_highlight (I.highlight);
	if (!I.null) {
/* TODO: this ifdef must go in the function body */
#if __WINDOWS__ && !__CYGWIN__
		if (I.ansicon) {
			r_cons_visual_write (I.buffer);
		} else {
			r_cons_w32_print ((const ut8*)I.buffer, I.buffer_len, 1);
		}
#else
		r_cons_visual_write (I.buffer);
#endif
	}
	r_cons_reset ();
	if (I.fps) {
		int fps = 0, w = r_cons_get_size (NULL);
		static ut64 prev = 0LL; //r_sys_now ();
		fps = 0;
		if (prev) {
			ut64 now = r_sys_now ();
			ut64 diff = now-prev;
			fps = (diff<1000000)? (1000000/diff): 0;
			prev = now;
		} else {
			prev = r_sys_now ();
		}
		eprintf ("\x1b[0;%dH[%d FPS] \n", w-10, fps);
	}
}

static int real_strlen(const char *ptr, int len) {
	int utf8len = r_str_len_utf8 (ptr);
	int ansilen = r_str_ansi_len (ptr);
	int diff = len - utf8len;
	if (diff) {
		diff--;
	}
	return ansilen - diff;
}

R_API void r_cons_visual_write (char *buffer) {
	char white[1024];
	int cols = I.columns;
	int alen, plen, lines = I.rows;
	const char *endptr;
	char *nl, *ptr = buffer, *pptr;

	if (I.null) {
		return;
	}
	memset (&white, ' ', sizeof (white));
	while ((nl = strchr (ptr, '\n'))) {
		int len = ((int)(size_t)(nl-ptr))+1;

		*nl = 0;
		alen = real_strlen (ptr, len);
		*nl = '\n';
		pptr = ptr > buffer ? ptr - 1 : ptr;
		plen = ptr > buffer ? len : len - 1;

		if (alen > cols) {
			int olen = len;
			endptr = r_str_ansi_chrn (ptr, cols);
			endptr++;
			len = endptr - ptr;
			plen = ptr > buffer ? len : len - 1;
			if (lines > 0) {
				r_cons_write (pptr, plen);
				if (len != olen) {
					r_cons_write (Color_RESET, strlen (Color_RESET));
				}
			}
		} else {
			if (lines > 0) {
				int w = cols - alen;
				r_cons_write (pptr, plen);
				if (I.blankline && w > 0) {
					if (w > sizeof (white) - 1) {
						w = sizeof (white) - 1;
					}
					r_cons_write (white, w);
				}
			}
			// TRICK to empty columns.. maybe buggy in w32
			if (r_mem_mem ((const ut8*)ptr, len, (const ut8*)"\x1b[0;0H", 6)) {
				lines = I.rows;
				r_cons_write (pptr, plen);
			}
		}
		lines--; // do not use last line
		ptr = nl + 1;
	}
	/* fill the rest of screen */
	if (lines > 0) {
		if (cols > sizeof (white)) {
			cols = sizeof (white);
		}
		while (--lines >= 0) {
			r_cons_write (white, cols);
		}
	}
}

R_API void r_cons_printf(const char *format, ...) {
	size_t size, written;
	va_list ap;

	if (I.null || !format) {
		return;
	}
	if (strchr (format, '%')) {
		palloc (MOAR + strlen (format) * 20);
		size = I.buffer_sz - I.buffer_len - 1; /* remaining space in I.buffer */
		va_start (ap, format);
		written = vsnprintf (I.buffer+I.buffer_len, size, format, ap);
		va_end (ap);
		if (written>=size) { /* not all bytes were written */
			palloc (written);
			va_start (ap, format);
			written = vsnprintf (I.buffer+I.buffer_len, written, format, ap);
			va_end (ap);
		}
		I.buffer_len += written;
	} else {
		r_cons_strcat (format);
	}
}

R_API int r_cons_get_column() {
	char *line = strrchr (I.buffer, '\n');
	if (!line) {
		line = I.buffer;
	}
	I.buffer[I.buffer_len] = 0;
	return r_str_ansi_len (line);
}

/* final entrypoint for adding stuff in the buffer screen */
R_API void r_cons_memcat(const char *str, int len) {
	if (len < 0 || (I.buffer_len + len) < 0) {
		return;
	}
	if (I.echo) {
		write (2, str, len);
	}
	if (str && len > 0 && !I.null) {
		if (palloc (len + 1)) {
			memcpy (I.buffer + I.buffer_len, str, len);
			I.buffer_len += len;
			I.buffer[I.buffer_len] = 0;
		}
	}
	if (I.flush) {
		r_cons_flush ();
	}
}

R_API void r_cons_memset(char ch, int len) {
	if (!I.null && len > 0) {
		palloc (len + 1);
		memset (I.buffer + I.buffer_len, ch, len + 1);
		I.buffer_len += len;
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

R_API void r_cons_newline() {
	if (!I.null) {
		r_cons_strcat ("\n");
	}
	//if (I.is_html) r_cons_strcat ("<br />\n");
}

/* return the aproximated x,y of cursor before flushing */
R_API int r_cons_get_cursor(int *rows) {
	int i, col = 0;
	int row = 0;
	// TODO: we need to handle GOTOXY and CLRSCR ansi escape code too
	for (i = 0; i < I.buffer_len; i++) {
		// ignore ansi chars, copypasta from r_str_ansi_len
		if (I.buffer[i] == 0x1b) {
			char ch2 = I.buffer[i+1];
			char *str = I.buffer;
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp (str + 2 + 5, "rgb:", 4))
					i += 18;
			} else if (ch2 == '[') {
				for (++i; str[i] && str[i] != 'J' && str[i] != 'm' && str[i] != 'H'; i++);
			}
		} else if (I.buffer[i] == '\n') {
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

R_API bool r_cons_isatty() {
#if __UNIX__ || __CYGWIN__
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

// XXX: if this function returns <0 in rows or cols expect MAYHEM
R_API int r_cons_get_size(int *rows) {
#if __WINDOWS__ && !__CYGWIN__
	char buffer[1024];
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	GetConsoleScreenBufferInfo (GetStdHandle (STD_OUTPUT_HANDLE), &csbi);
	I.columns = (csbi.srWindow.Right - csbi.srWindow.Left) - 1;
	I.rows = csbi.srWindow.Bottom - csbi.srWindow.Top; // last row empty
#elif EMSCRIPTEN
	I.columns = 80;
	I.rows = 23;
#elif __UNIX__ || __CYGWIN__
	struct winsize win = { 0 };
	if (isatty (0) && !ioctl (0, TIOCGWINSZ, &win)) {
		if ((!win.ws_col) || (!win.ws_row)) {
			const char *tty = ttyname (1);
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

R_API void r_cons_show_cursor (int cursor) {
#if __WINDOWS__ && !__CYGWIN__
	// TODO
#else
	if (cursor) {
		write (1, "\x1b[?25h", 6);
	} else {
		write (1, "\x1b[?25l", 6);
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
static int oldraw = -1;
R_API void r_cons_set_raw(int is_raw) {
	if (oldraw != -1) {
		if (is_raw == oldraw) {
			return;
		}
	}
#if EMSCRIPTEN
	/* do nothing here */
#elif __UNIX__ || __CYGWIN__
	// enforce echo off
	I.term_raw.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
	if (is_raw) {
		tcsetattr (0, TCSANOW, &I.term_raw);
	} else {
		tcsetattr (0, TCSANOW, &I.term_buf);
	}
#elif __WINDOWS__
	if (is_raw) {
		SetConsoleMode (h, (DWORD)I.term_raw);
	} else {
		SetConsoleMode (h, (DWORD)I.term_buf);
	}
#else
#warning No raw console supported for this platform
#endif
	fflush (stdout);
	oldraw = is_raw;
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
R_API void r_cons_set_cup(int enable) {
#if __UNIX__ || __CYGWIN__
	if (enable) {
		const char *code =
			"\x1b[?1049h" // xterm
			"\x1b" "7\x1b[?47h"; // xterm-color
		write (2, code, strlen (code));
	} else {
		const char *code =
			"\x1b[?1049l" // xterm
			"\x1b[?47l""\x1b""8"; // xterm-color
		write (2, code, strlen (code));
	}
	fflush (stdout);
#elif __WINDOWS__ && !__CYGWIN__
	if (I.ansicon) {
		if (enable) {
			const char *code =
				"\x1b[?1049h" // xterm
				"\x1b" "7\x1b[?47h"; // xterm-color
			write (2, code, strlen (code));
		} else {
			const char *code =
				"\x1b[?1049l" // xterm
				"\x1b[?47l""\x1b""8"; // xterm-color
			write (2, code, strlen (code));
		}
		fflush (stdout);
	}
#endif
	/* not supported ? */
}

R_API void r_cons_column(int c) {
	char *b = malloc (I.buffer_len+1);
	if (!b) {
		return;
	}
	memcpy (b, I.buffer, I.buffer_len);
	b[I.buffer_len] = 0;
	r_cons_reset ();
	// align current buffer N chars right
	r_cons_strcat_justify (b, c, 0);
	r_cons_gotoxy (0, 0);
	free(b);
}

static int lasti = 0; /* last interactive mode */

R_API void r_cons_set_interactive(int x) {
	lasti = r_cons_singleton ()->is_interactive;
	r_cons_singleton ()->is_interactive = x;
}

R_API void r_cons_set_last_interactive() {
	r_cons_singleton ()->is_interactive = lasti;
}

R_API void r_cons_set_title(const char *str) {
	r_cons_printf ("\x1b]0;%s\007", str);
}

R_API void r_cons_zero() {
	if (I.line) {
		I.line->zerosep = true;
	}
	write (1, "", 1);
}

R_API void r_cons_highlight (const char *word) {
	int l, *cpos;
	char *rword, *res, *clean;
	char *inv[2] = {
		R_CONS_INVERT (true, true),
		R_CONS_INVERT (false, true)
	};
	int linv[2] = {
		strlen (inv[0]),
		strlen (inv[1])
	};

	if (word && *word && I.buffer) {
		int word_len = strlen (word);
		char *orig;
		clean = I.buffer;
		l = r_str_ansi_filter (clean, &orig, &cpos, 0);
		I.buffer = orig;
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
			return;
		}
		strcpy (rword, inv[0]);
		strcpy (rword + linv[0], word);
		strcpy (rword + linv[0] + word_len, inv[1]);
		res = r_str_replace_thunked (I.buffer, clean, cpos,
					     l, word, rword, 1);
		if (res) {
			I.buffer = res;
			I.buffer_len = I.buffer_sz = strlen (res);
		}
		free (rword);
		free (clean);
		free (cpos);
		/* don't free orig - it's assigned
		 * to I.buffer and possibly realloc'd */
	} else {
		free (I.highlight);
		I.highlight = NULL;
	}
}

R_API char *r_cons_lastline () {
	char *b = I.buffer+I.buffer_len;
	while (b >I.buffer) {
		if (*b == '\n') {
			b++;
			break;
		}
		b--;
	}
	return b;
}

/* swap color from foreground to background, returned value must be freed */
R_API char *r_cons_swap_ground(const char *col) {
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

R_API bool r_cons_drop (int n) {
	if (n > I.buffer_len) {
		I.buffer_len = 0;
		return false;
	}
	I.buffer_len -= n;
	return true;
}

R_API void r_cons_chop () {
	while (I.buffer_len > 0) {
		char ch = I.buffer[I.buffer_len - 1];
		if (ch != '\n' && !IS_WHITESPACE (ch)) {
			break;
		}
		I.buffer_len--;
	}
}

R_API void r_cons_bind(RConsBind *bind) {
	if (!bind) {
		return;
	}
	bind->get_size = r_cons_get_size;
	bind->get_cursor = r_cons_get_cursor;
}

R_API const char* r_cons_get_rune(const ut8 ch) {
	if (ch >= RUNECODE_MIN && ch < RUNECODE_MAX) {
		switch (ch) {
		case RUNECODE_LINE_HORIZ: return RUNE_LINE_HORIZ;
		case RUNECODE_LINE_VERT:  return RUNE_LINE_VERT;
		case RUNECODE_LINE_CROSS: return RUNE_LINE_CROSS;
		case RUNECODE_CORNER_TL:  return RUNE_CORNER_TL;
		case RUNECODE_CORNER_TR:  return RUNE_CORNER_TR;
		case RUNECODE_CORNER_BR:  return RUNE_CORNER_BR;
		case RUNECODE_CORNER_BL:  return RUNE_CORNER_BL;
		}
	}
	return NULL;
}

