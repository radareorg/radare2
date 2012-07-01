/* radare - LGPL - Copyright 2008-2012 pancake<nopcode.org> */

#include <r_cons.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#if __UNIX__
#include <signal.h>
#endif

static RCons r_cons_instance;
#define I r_cons_instance

static void break_signal(int sig) {
	I.breaked = R_TRUE;
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
#endif

#if __UNIX__
static void resize (int sig) {
	if (I.event_resize)
		I.event_resize (I.data);
}
#endif

R_API RCons *r_cons_new () {
	I.event_interrupt = NULL;
	I.event_resize = NULL;
	I.data = NULL;
	I.is_interactive = R_TRUE;
	I.noflush = R_FALSE;
	I.fdin = stdin;
	I.fdout = 1;
	I.breaked = R_FALSE;
	I.lines = 0;
	I.buffer = NULL;
	I.buffer_sz = 0;
	I.buffer_len = 0;
	r_cons_get_size (NULL);
	I.num = NULL;
#if __UNIX__
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
	//r_cons_palette_init(NULL);
	r_cons_reset ();
	return &I;
}

R_API RCons *r_cons_free () {
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
	} else if (moar + I.buffer_len > I.buffer_sz) {
		I.buffer_sz += moar+MOAR;
		I.buffer = (char *)realloc (I.buffer, I.buffer_sz);
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

R_API void r_cons_clear_line() {
#if __WINDOWS__
	char white[1024];
	memset (&white, ' ', sizeof (white));
	if (I.columns<sizeof (white))
		white[I.columns-1] = 0;
	else white[sizeof (white)-1] = 0; // HACK
	printf ("\r%s\r", white);
#else
	printf ("\x1b[0K\r");
#endif
	fflush (stdout);
}

R_API void r_cons_clear00() {
	r_cons_clear ();
	r_cons_gotoxy (0, 0);
}

R_API void r_cons_clear() {
	r_cons_strcat (Color_RESET"\x1b[2J");
	r_cons_gotoxy (0, 0);
	r_cons_flush ();
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
	if (I.grep.nstrings>0||I.grep.tokenfrom!=0||I.grep.tokento!=ST32_MAX||I.grep.line!=-1)
		r_cons_grepbuf (I.buffer, I.buffer_len);
	/* html */
	/* TODO */
}

R_API void r_cons_flush() {
	const char *tee = I.teefile;
	if (I.noflush)
		return;
	r_cons_filter ();
	if (I.is_interactive) {
		/* Use a pager if the output doesn't fit on the terminal window. */
		if (I.pager && *(I.pager)
				&& I.buffer_len > 0
				&& r_str_char_count (I.buffer, '\n') >= I.rows) {
			I.buffer[I.buffer_len-1] = 0;
			r_sys_cmd_str_full(I.pager, I.buffer, NULL, NULL, NULL);
			r_cons_reset ();

		} else if (I.buffer_len > CONS_MAX_USER) {
			if (!r_cons_yesno ('n',"Do you want to print %d bytes? (y/N)",
					I.buffer_len)) {
				r_cons_reset ();
				return;
			}
		}
	}
	if (tee&&*tee) {
		FILE *d = fopen (tee, "a+");
		if (d != NULL) {
			if (I.buffer_len != fwrite (I.buffer, 1, I.buffer_len, d))
				eprintf ("r_cons_flush: fwrite: error (%s)\n", tee);
			fclose (d);
		}
	}
	// is_html must be a filter, not a write endpoint
	if (I.is_html) r_cons_html_print (I.buffer);
	else r_cons_write (I.buffer, I.buffer_len);
	r_cons_reset ();
}

R_API void r_cons_visual_flush() {
	if (I.noflush)
		return;
/* TODO: this ifdef must go in the function body */
#if __WINDOWS__
	r_cons_w32_print ((ut8*)I.buffer, 1);
#else
	r_cons_visual_write (I.buffer);
#endif
	r_cons_reset ();
	return;
}

R_API void r_cons_visual_write (char *buffer) {
	const char white[1024];
	int cols = I.columns;
	int alen, lines = I.rows;
	const char *endptr;
	char *nl, *ptr = buffer;

	memset (&white, ' ', sizeof (white));

	while ((nl = strchr (ptr, '\n'))) {
		int len = ((int)(size_t)(nl-ptr))+1;

		*nl = 0;
		alen = r_str_ansi_len (ptr);
		*nl = '\n';

		if (alen>cols) {
			endptr = r_str_ansi_chrn (ptr, cols);
			endptr++;
			len = (endptr-ptr);
			if (lines>0) {
				r_cons_write (ptr, len);
				//r_cons_write (newline, strlen (newline));
			}
		} else {
			if (lines>0) {
				int w = cols-alen;
				if (ptr>buffer) r_cons_write (ptr-1, len);
				else r_cons_write (ptr, len-1);
				if (w>0) { 
					if (w>sizeof (white)-1)
						w = sizeof (white)-1;
					r_cons_write (white, w);
				}
			}
			// TRICK to empty columns.. maybe buggy in w32
			if (r_mem_mem ((const ut8*)ptr, len, (const ut8*)"\x1b[0;0H", 6)) {
				lines = I.rows;
				r_cons_write (ptr, len);
			}
		}
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

	if (strchr (format, '%')) {
		palloc (MOAR);
		size = I.buffer_sz-I.buffer_len; /* remaining space in I.buffer */

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
	if (str && len>0) {
		palloc (len+1);
		memcpy (I.buffer+I.buffer_len, str, len+1);
		I.buffer_len += len;
	}
}

R_API void r_cons_memset(char ch, int len) {
	if (len>0) {
		palloc (len+1);
		memset (I.buffer+I.buffer_len, ch, len+1);
		I.buffer_len += len;
	}
}

R_API void r_cons_strcat(const char *str) {
	int len = strlen (str);
	if (len>0)
		r_cons_memcat (str, len);
}

R_API void r_cons_newline() {
	if (I.is_html) r_cons_strcat ("<br />\n");
	else r_cons_strcat ("\n");
}

R_API int r_cons_get_size(int *rows) {
#if __UNIX__
	struct winsize win;
	if (ioctl (1, TIOCGWINSZ, &win) == 0) {
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
	if (rows)
		*rows = I.rows;
	return I.columns;
}

R_API void r_cons_show_cursor (int cursor) {
#if __WINDOWS__
	// TODO
#else
	if (cursor) write (1, "\x1b[?25h", 6);
	else write(1, "\x1b[?25l", 6);
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
#if __UNIX__
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
	if (color) r_cons_strcat (set?  Color_INVERT: Color_INVERT_RESET);
	else r_cons_strcat (set? "[": "]");
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
		printf ("\x1b[?1049h"); // xterm
		printf ("\x1b" "7\x1b[?47h"); // xterm-color
	} else {
		printf ("\x1b[?1049l"); // xterm
		printf ("\x1b[?47l""\x1b""8"); // xterm-color
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
}

static int lasti = 0; /* last interactive mode */

R_API void r_cons_set_interactive(int x) {
	lasti = r_cons_singleton ()->is_interactive;
	r_cons_singleton ()->is_interactive = x;
}

R_API void r_cons_set_last_interactive() {
	r_cons_singleton ()->is_interactive = lasti;
}
