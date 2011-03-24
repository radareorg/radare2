/* radare - LGPL - Copyright 2008-2011 pancake<nopcode.org> */

#include <r_cons.h>
#include <r_types.h>
#include <r_util.h>
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

static inline void r_cons_write (char *buf, int len) {
#if __WINDOWS__
	r_cons_w32_print ((unsigned char *)buf);
#else
	if (write (I.fdout, buf, len) == -1) {
		eprintf ("r_cons_write: write error\n");
		exit (1);
	}
#endif
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
	//r_cons_palette_init(NULL);
	r_cons_reset ();
	return &I;
}

R_API RCons *r_cons_free () {
	if (I.buffer)
		free (I.buffer);
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
}

R_API void r_cons_clear00() {
	r_cons_clear ();
	r_cons_gotoxy (0, 0);
}

R_API void r_cons_clear() {
#if __WINDOWS__
	static HANDLE hStdout = NULL;
	static CONSOLE_SCREEN_BUFFER_INFO csbi;
	const COORD startCoords = { 0, 0 };
	DWORD dummy;
	
	if (!hStdout) {
		hStdout = GetStdHandle (STD_OUTPUT_HANDLE);
		GetConsoleScreenBufferInfo (hStdout,&csbi);
	}
	
	FillConsoleOutputCharacter (hStdout, ' ',
		csbi.dwSize.X * csbi.dwSize.Y, startCoords, &dummy);
#else
	r_cons_strcat (Color_RESET"\x1b[2J");
#endif
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
		if (I.buffer_len > CONS_MAX_USER) {
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
			if (I.buffer_len != fwrite (I.buffer, 1, I.buffer_len, d)) {
				eprintf ("r_cons_flush: fwrite: error (%s)\n", tee);
			}
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
	r_cons_w32_print (I.buffer);
#else
	r_cons_visual_write (I.buffer);
#endif
	r_cons_reset ();
	return;
}

R_API void r_cons_visual_write (char *buffer) {
	int cols = I.columns;
	int lines = I.rows-1;
	const char *endptr;
	char *nl, *ptr = buffer;
	while (lines && (nl = strchr (ptr, '\n'))) {
		int clen, len = ((int)(size_t)(nl-ptr))+1;
#if 1
		*nl = 0;
		endptr = r_str_ansi_chrn (ptr, cols);
		clen = (int)(size_t)(endptr-ptr)-1;
		*nl = '\n';
		if (clen>cols) {
			ptr[clen-1]='\0';
			len = clen;
		}
		ptr-=2;
#endif
		r_cons_write (ptr, len); //nl-ptr+1);
		lines--;
		ptr = nl+1;
	}
}

R_API void r_cons_printf(const char *format, ...) {
	int len;
	char buf[CONS_BUFSZ];
	va_list ap;

	if (strchr (format, '%')) {
		va_start (ap, format);
		len = vsnprintf (buf, CONS_BUFSZ-1, format, ap);
		if (len>0)
			r_cons_memcat (buf, len);
		va_end (ap);
	} else r_cons_strcat (format);
}

/* final entrypoint for adding stuff in the buffer screen */
R_API void r_cons_memcat(const char *str, int len) {
	if (len>0) {
		palloc (len+1);
		memcpy (I.buffer+I.buffer_len, str, len+1);
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
		I.rows = win.ws_row;
	} else {
		I.columns = 80;
		I.rows = 23;
	}
#else
	const char *str = r_sys_getenv ("COLUMNS");
	if (str != NULL) {
		I.columns = atoi (str);
		I.rows = 23; // XXX. windows must get console size
	} else {
		I.columns = 80;
		I.rows = 23;
	}
#endif
	if (rows)
		*rows = I.rows;
	return I.columns;
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
R_API void r_cons_set_raw(int is_raw) {
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
}
