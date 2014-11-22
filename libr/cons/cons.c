/* radare - LGPL - Copyright 2008-2014 - pancake */

#include <r_cons.h>
#include <r_print.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#if __UNIX__
#include <signal.h>
#endif

R_LIB_VERSION (r_cons);

static RCons r_cons_instance;
#define I r_cons_instance

static void break_signal(int sig) {
	I.breaked = R_TRUE;
	r_print_set_interrupted (I.breaked);
	if (I.event_interrupt)
		I.event_interrupt (I.data);
}

static inline void r_cons_write (const char *buf, int len) {
#if __WINDOWS__
	r_cons_w32_print ((unsigned char *)buf, 0);
#else
	if (write (I.fdout, buf, len) == -1) {
		//eprintf ("r_cons_write: write error\n");
		//exit (1);
	}
#endif
}

R_API char *r_cons_color_random(int bg) {
	int r, g, b;
	if (I.truecolor>0) {
		char out[32];
		r = r_num_rand (0xff);
		g = r_num_rand (0xff);
		b = r_num_rand (0xff);
		r_cons_rgb_str (out, r, g, b, bg);
		return strdup (out);
	}
	// random ansi
	r = r_num_rand (16);
	switch (r) {
	case 0: return strdup (Color_RED);
	case 1: return strdup (Color_BRED);
	case 2: return strdup (Color_WHITE);
	case 3: return strdup (Color_BWHITE);
	case 4: return strdup (Color_GREEN);
	case 5: return strdup (Color_BGREEN);
	case 6: return strdup (Color_MAGENTA);
	case 7: return strdup (Color_BMAGENTA);
	case 8: return strdup (Color_YELLOW);
	case 9: return strdup (Color_BYELLOW);
	case 10: return strdup (Color_CYAN);
	case 11: return strdup (Color_BCYAN);
	case 12: return strdup (Color_BLUE);
	case 13: return strdup (Color_BBLUE);
	case 14: return strdup (Color_GRAY);
	case 15: return strdup (Color_BGRAY);
	}
	return Color_RESET;
}

R_API void r_cons_color (int fg, int r, int g, int b) {
	int k;
	r = R_DIM (r, 0, 255);
	g = R_DIM (g, 0, 255);
	b = R_DIM (b, 0, 255);
	if (r == g && g == b) { // b&w
		k = 232 + (int)(((r+g+b)/3)/10.3);
	} else {
		r = (int)(r/42.6);
		g = (int)(g/42.6);
		b = (int)(b/42.6);
		k = 16 + (r*36) + (g*6) + b;
	}
	r_cons_printf ("\x1b[%d;5;%dm", fg? 48: 38, k);
}

R_API void r_cons_strcat_justify (const char *str, int j, char c) {
	int i, o, len;
	for (o=i=len=0; str[i]; i++, len++) {
		if (str[i]=='\n') {
			r_cons_memset (' ', j);
			if (c) {
				r_cons_memset (c, 1);
				r_cons_memset (' ', 1);
			}
			r_cons_memcat (str+o, len);
			if (str[o+len] == '\n')
				r_cons_newline ();
			o = i+1;
			len = 0;
		}
	}
	if (len>1)
		r_cons_memcat (str+o, len);
}

R_API RCons *r_cons_singleton () {
	return &I;
}

R_API void r_cons_break(void (*cb)(void *u), void *user) {
	I.breaked = R_FALSE;
	I.event_interrupt = cb;
	I.data = user;
#if __UNIX__
	signal (SIGINT, break_signal);
#endif
// TODO: add support for w32 ^C
}

R_API void r_cons_break_end() {
	I.breaked = R_FALSE;
	r_print_set_interrupted (I.breaked);
#if __UNIX__
	signal (SIGINT, SIG_IGN);
#endif
}

#if __WINDOWS__
static HANDLE h;
static BOOL __w32_control(DWORD type) {
	if (type == CTRL_C_EVENT) {
		break_signal (2); // SIGINT
		return R_TRUE;
	}
	return R_FALSE;
}
#elif __UNIX__
static void resize (int sig) {
	if (I.event_resize)
		I.event_resize (I.event_data);
}
#endif

// http://invisible-island.net/xterm/ctlseqs/ctlseqs.txt
R_API int r_cons_enable_mouse (const int enable) {
#if __UNIX__
// TODO: this sequence must be flushed, so maybe we should not use the rcons buffer api
	int enabled = I.mouse;
	if ((I.mouse = enable)) {
	//	r_cons_memcat ("\x1b[?1001s", 8);
		const char *code = "\x1b[?1001s" "\x1b[?1000h";
		write (2, code, strlen (code));
	} else {
		//r_cons_memcat ("\x1b[?1001r", 8);
		const char *code = "\x1b[?1001r" "\x1b[?1000l";
		write (2, code, strlen (code));
	}
	return enabled;
#else
	return R_FALSE;
#endif
}

R_API RCons *r_cons_new () {
	I.line = r_line_new ();
	I.highlight = NULL;
	I.event_interrupt = NULL;
	I.fps = 0;
	I.blankline = R_TRUE;
	I.teefile = NULL;
	I.fix_columns = 0;
	I.fix_rows = 0;
	I.force_rows = 0;
	I.force_columns = 0;
	I.event_resize = NULL;
	I.data = NULL;
	I.event_data = NULL;
	I.is_interactive = R_TRUE;
	I.noflush = R_FALSE;
	I.fdin = stdin;
	I.fdout = 1;
	I.breaked = R_FALSE;
	//I.lines = 0;
	I.buffer = NULL;
	I.buffer_sz = 0;
	I.buffer_len = 0;
	r_cons_get_size (NULL);
	I.num = NULL;
	I.null = 0;
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
	signal (SIGWINCH, resize);
#elif __WINDOWS__
	h = GetStdHandle (STD_INPUT_HANDLE);
	GetConsoleMode (h, (PDWORD) &I.term_buf);
	I.term_raw = 0;
	if (!SetConsoleCtrlHandler ((PHANDLER_ROUTINE)__w32_control, TRUE))
		eprintf ("r_cons: Cannot set control console handler\n");
#endif
	I.pager = NULL; /* no pager by default */
	I.truecolor = 0;
	I.mouse = 0;
	r_cons_pal_init (NULL);
	r_cons_rgb_init ();
	r_cons_reset ();
	return &I;
}

R_API RCons *r_cons_free () {
	if (I.line) {
		r_line_free (I.line);
		I.line = NULL;
	}
	if (I.buffer) {
		free (I.buffer);
		I.buffer = NULL;
	}
	return NULL;
}

#define MOAR 4096*4
static void palloc(int moar) {
	if (I.buffer == NULL) {
		I.buffer_sz = moar+MOAR;
		I.buffer = (char *)malloc (I.buffer_sz);
		I.buffer[0] = '\0';
	} else if (moar + I.buffer_len >= I.buffer_sz) {
		char *new_buffer;
		int old_buffer_sz = I.buffer_sz;
		I.buffer_sz += moar+MOAR;
		new_buffer = (char *)realloc (I.buffer, I.buffer_sz);
		if (new_buffer)
			I.buffer = new_buffer;
		else I.buffer_sz = old_buffer_sz;
	}
}

R_API int r_cons_eof() {
	return feof (I.fdin);
}

R_API void r_cons_gotoxy(int x, int y) {
#if 0
#if __WINDOWS__
        static HANDLE hStdout = NULL;
        COORD coord;
        coord.X = x;
        coord.Y = y;
        if (!hStdout)
                hStdout = GetStdHandle (STD_OUTPUT_HANDLE);
        SetConsoleCursorPosition (hStdout, coord);
#else
	r_cons_printf ("\x1b[%d;%dH", y, x);
#endif
#endif
	r_cons_printf ("\x1b[%d;%dH", y, x);
}

R_API void r_cons_print_clear() {
	// xlr8!
	r_cons_write ("\x1b[0;0H", 6);
	r_cons_write ("\x1b[0m", 4);
	//r_cons_memcat ("\x1b[2J", 4);
}

R_API void r_cons_fill_line() {
	char *p, white[1024];
	int cols = I.columns-1;
	if (cols<1) return;
	p = (cols>=sizeof (white))?
		malloc (cols+1): white;
	memset (p, ' ', cols);
	p[cols] = 0;
	r_cons_strcat (p);
	if (white != p) free (p);
}

R_API void r_cons_clear_line(int std_err) {
#if __WINDOWS__
	char white[1024];
	memset (&white, ' ', sizeof (white));
	if (I.columns<sizeof (white))
		white[I.columns-1] = 0;
	else white[sizeof (white)-1] = 0; // HACK
	fprintf (std_err? stderr:stdout, "\r%s\r", white);
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
	//r_cons_gotoxy (0, 0);
//	r_cons_flush ();
	I.lines = 0;
}

R_API void r_cons_reset() {
	if (I.buffer)
		I.buffer[0] = '\0';
	I.buffer_len = 0;
	I.lines = 0;
	I.lastline = I.buffer;
	I.grep.strings[0][0] = '\0';
	I.grep.nstrings = 0; // XXX
	I.grep.line = -1;
	I.grep.str = NULL;
	I.grep.tokenfrom = 0;
	I.grep.tokento = ST32_MAX;
}

R_API const char *r_cons_get_buffer() {
	return I.buffer;
}

R_API void r_cons_filter() {
	/* grep*/
	if (I.grep.nstrings>0||I.grep.tokenfrom!=0||I.grep.tokento!=ST32_MAX||I.grep.line!=-1 || I.grep.less || I.grep.json)
		r_cons_grepbuf (I.buffer, I.buffer_len);
	/* html */
	/* TODO */
}

R_API void r_cons_flush() {
	const char *tee = I.teefile;
	if (I.noflush)
		return;
	if (I.null) {
		r_cons_reset ();
		return;
	}
	r_cons_filter ();
	if (I.is_interactive) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (I.pager && *(I.pager)
				&& I.buffer_len > 0
				&& r_str_char_count (I.buffer, '\n') >= I.rows) {
			I.buffer[I.buffer_len-1] = 0;
			r_sys_cmd_str_full (I.pager, I.buffer, NULL, NULL, NULL);
			r_cons_reset ();

		} else if (I.buffer_len > CONS_MAX_USER) {
			char buf[64];
			char *buflen = r_num_units (buf, I.buffer_len);
			if (!r_cons_yesno ('n',"Do you want to print %s chars? (y/N)",
					buflen)) {
				r_cons_reset ();
				return;
			}
			// fix | more | less problem
			r_cons_set_raw (1);
		}
	}
	if (tee&&*tee) {
		FILE *d = r_sandbox_fopen (tee, "a+");
		if (d != NULL) {
			if (I.buffer_len != fwrite (I.buffer, 1, I.buffer_len, d))
				eprintf ("r_cons_flush: fwrite: error (%s)\n", tee);
			fclose (d);
		} else eprintf ("Cannot write on '%s'\n", tee);
	}
	r_cons_highlight (I.highlight);
	// is_html must be a filter, not a write endpoint
	if (I.is_html) r_cons_html_print (I.buffer);
	else r_cons_write (I.buffer, I.buffer_len);
	// add newline if there's no one in buffer. this fixes the problem of printing
	// stuff without newline to the console and the prompt hides it.
	if (I.buffer_len>0)
		if (I.buffer[I.buffer_len-1]!= '\n')
			write (2, "\n", 1);
	r_cons_reset ();
}

R_API void r_cons_visual_flush() {
	if (I.noflush)
		return;
	r_cons_highlight (I.highlight);
	if (!I.null) {
/* TODO: this ifdef must go in the function body */
#if __WINDOWS__
		r_cons_w32_print ((ut8*)I.buffer, 1);
#else
		r_cons_visual_write (I.buffer);
#endif
	}
	r_cons_reset ();
	if (I.fps) {
		int w = r_cons_get_size (NULL);
		int fps = 0;
		static ut64 prev = 0LL; //r_sys_now ();
		fps = 0;
		if (prev) {
			ut64 now = r_sys_now ();
			ut64 diff = now-prev;
			fps = (diff<1000000)? (1000000/diff): 0;
			prev = now;
		} else prev = r_sys_now ();
		eprintf ("\x1b[0;%dH[%d FPS] \n", w-10, fps);
	}
	return;
}

R_API void r_cons_visual_write (char *buffer) {
	char white[1024];
	int cols = I.columns;
	int alen, lines = I.rows;
	const char *endptr;
	char *nl, *ptr = buffer;

	if (I.null)
		return;
	memset (&white, ' ', sizeof (white));

	while ((nl = strchr (ptr, '\n'))) {
		int len = ((int)(size_t)(nl-ptr))+1;

		*nl = 0;
		//alen = r_str_ansi_len (ptr);
// handle ansi chars
		 {
			int utf8len = r_str_len_utf8 (ptr);
			int ansilen = r_str_ansi_len (ptr);
			int diff = len-utf8len;
			if (diff) diff--;
			alen = ansilen - diff;
		 }
		*nl = '\n';

		if (alen>cols) {
			endptr = r_str_ansi_chrn (ptr, cols);
			endptr++;
			len = (endptr-ptr);
			if (lines>0) {
				r_cons_write (ptr, len);
			}
		} else {
			if (lines>0) {
				int w = cols-alen;
				if (ptr>buffer) r_cons_write (ptr-1, len);
				else r_cons_write (ptr, len-1);
				if (I.blankline && w>0) { 
					if (w>sizeof (white)-1)
						w = sizeof (white)-1;
					r_cons_write (white, w);
				}
			}
#if 1
			// TRICK to empty columns.. maybe buggy in w32
			if (r_mem_mem ((const ut8*)ptr, len, (const ut8*)"\x1b[0;0H", 6)) {
				lines = I.rows;
				r_cons_write (ptr, len);
			}
#endif
		}
//r_cons_write ("\r\n", 2);
		lines--; // do not use last line
		ptr = nl+1;
	}
	/* fill the rest of screen */
	if (lines>0) {
		if (cols>sizeof (white))
			cols = sizeof (white);
		while (lines-->0)
			r_cons_write (white, cols);
	}
}

R_API void r_cons_printf(const char *format, ...) {
	size_t size, written;
	va_list ap;

	if (I.null) return;
	if (strchr (format, '%')) {
		palloc (MOAR);
		size = I.buffer_sz-I.buffer_len-1; /* remaining space in I.buffer */
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
	} else r_cons_strcat (format);
}

R_API int r_cons_get_column() {
	char *line = strrchr (I.buffer, '\n');
	if (!line) line = I.buffer;
	I.buffer[I.buffer_len] = 0;
	return r_str_ansi_len (line);
}

/* final entrypoint for adding stuff in the buffer screen */
R_API void r_cons_memcat(const char *str, int len) {
	if (I.echo) {
		write (2, str, len);
	}
	if (str && len>0 && !I.null) {
		palloc (len+1);
		memcpy (I.buffer+I.buffer_len, str, len);
		I.buffer_len += len;
		I.buffer[I.buffer_len] = 0;
	}
}

R_API void r_cons_memset(char ch, int len) {
	if (I.null) return;
	if (len>0) {
		palloc (len+1);
		memset (I.buffer+I.buffer_len, ch, len+1);
		I.buffer_len += len;
	}
}

R_API void r_cons_strcat(const char *str) {
	int len;
	if (!str||I.null) return;
	len = strlen (str);
	if (len>0)
		r_cons_memcat (str, len);
}

R_API void r_cons_newline() {
	if (!I.null)
		r_cons_strcat ("\n");
	//if (I.is_html) r_cons_strcat ("<br />\n");
	//else r_cons_strcat ("\n");
}

/* return the aproximated x,y of cursor before flushing */
R_API int r_cons_get_cursor(int *rows) {
	int i, col = 0;
	int row = 0;
	// TODO: we need to handle GOTOXY and CLRSCR ansi escape code too
	for (i=0; i<I.buffer_len; i++) {
		// ignore ansi chars, copypasta from r_str_ansi_len
		if (I.buffer[i] == 0x1b) {
			char ch2 = I.buffer[i+1];
			char *str = I.buffer;
			if (ch2 == '\\') {
				i++;
			} else if (ch2 == ']') {
				if (!strncmp (str+2+5, "rgb:", 4))
					i += 18;
			} else if (ch2 == '[') {
				for (++i; str[i]&&str[i]!='J'&& str[i]!='m'&&str[i]!='H';i++);
			}
		} else
		if (I.buffer[i] == '\n') {
			row++;
			col = 0;
		} else col++;
	}
	if (rows)
		*rows = row;
	return col;
}

// XXX: if this function returns <0 in rows or cols expect MAYHEM
R_API int r_cons_get_size(int *rows) {
#if EMSCRIPTEN
	I.columns = 80;
	I.rows = 23;
#elif __UNIX__
	struct winsize win;
	// use stdin as reference?
	//if (isatty (1) && ioctl (1, TIOCGWINSZ, &win) == 0) {
	if (isatty (0) && ioctl (0, TIOCGWINSZ, &win) == 0) {
		if (win.ws_col==0) {
			// TODO: use ttyname() ?
			int fd = open ("/dev/tty", O_RDONLY);
			if (fd != -1) {
				if (ioctl (fd, TIOCGWINSZ, &win) != 0) {
					I.columns = 80;
					I.rows = 23;
				}
				close (fd);
			}
		}
		I.columns = win.ws_col;
		I.rows = win.ws_row-1;
	} else {
		I.columns = 80;
		I.rows = 23;
	}
#else
	char *str = r_sys_getenv ("COLUMNS");
	if (str != NULL) {
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
	if (I.rows<0)
		I.rows = 0;
	if (I.columns<0)
		I.columns = 0;
	if (I.force_columns) I.columns = I.force_columns;
	if (I.force_rows) I.rows = I.force_rows;
	if (I.fix_columns) I.columns += I.fix_columns;
	if (I.fix_rows) I.rows += I.fix_rows;
	if (rows)
		*rows = I.rows;
	I.rows = R_MAX (0, I.rows);
	return R_MAX (0, I.columns);
}

R_API void r_cons_show_cursor (int cursor) {
#if __WINDOWS__
	// TODO
#else
	if (cursor) write (1, "\x1b[?25h", 6);
	else write (1, "\x1b[?25l", 6);
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
	if (oldraw != -1)
		if (is_raw == oldraw)
			return;
#if EMSCRIPTEN
	/* do nothing here */
#elif __UNIX__
	if (is_raw) tcsetattr (0, TCSANOW, &I.term_raw);
	else tcsetattr (0, TCSANOW, &I.term_buf);
#elif __WINDOWS__
	if (is_raw) SetConsoleMode (h, (DWORD)I.term_raw);
	else SetConsoleMode (h, (DWORD)I.term_buf);
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
#if __UNIX__
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
#else
	/* not supported ? */
#endif
}

R_API void r_cons_column(int c) {
	char *b = malloc (I.buffer_len+1);
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
	write (1, "", 1);
}

R_API void r_cons_highlight (const char *word) {
	char *rword, *res;
// that word str should ignore ansi scapes
	if (word && *word) {
		if (I.highlight) {
			if (strcmp (word, I.highlight)) {
				free (I.highlight);
				I.highlight = strdup (word);
			}
		} else {
			I.highlight = strdup (word);
		}
		rword = malloc (strlen (word)+32);
		strcpy (rword, "\x1b[0m\x1b[7m");
		strcpy (rword+8, word);
		strcpy (rword+8+strlen (word), "\x1b[0m");
		res = r_str_replace (I.buffer, word, rword, 1);
		if (res) {
			I.buffer = res;
			I.buffer_len = I.buffer_sz = strlen (res);
		}
	} else {
		free (I.highlight);
		I.highlight = NULL;
	}
}

R_API char *r_cons_lastline () {
	char *b = I.buffer+I.buffer_len;
	while (b >I.buffer) {
		if (*b=='\n') {
			b++;
			break;
		}
		b--;
	}
	return b;
}
