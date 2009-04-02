/* radare - LGPL - Copyright 2008-2009 pancake<nopcode.org> */

#include <r_cons.h>

#include "r_types.h"
#include "r_line.h"

#if HAVE_DIETLINE
#include "r_line.h"
#include "r_util.h"
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#if __UNIX__
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#endif
#if __WINDOWS__
#include <windows.h>
#endif

#define MOAR_VALUE 4096*4

// WTF //
char *strsub (char *string, char *pat, char *rep, int global);
int r_cons_stdout_fd = 1;
FILE *r_cons_stdin_fd = NULL; // TODO use int fd here too!

static int r_cons_buffer_sz = 0;
static int r_cons_buffer_len = 0;
static char *r_cons_buffer = NULL;
static char *r_cons_lastline = NULL;
char *r_cons_filterline = NULL;
char *r_cons_teefile = NULL;
int r_cons_is_html = 0;
int r_cons_interactive = 1;
int r_cons_lines = 0;
int r_cons_noflush = 0;

static int grepline = -1, greptoken = -1, grepcounter = 0, grepneg = 0;
static char *grepstr = NULL;
static char grepstrings[10][64] = { "", };
static int grepstrings_n = 0;

int r_cons_breaked = 0;

static void (*r_cons_break_cb)(void *user);
static void *r_cons_break_user;

static void break_signal(int sig)
{
	r_cons_breaked = 1;
	if (r_cons_break_cb)
		r_cons_break_cb(r_cons_break_user);
}

void r_cons_break(void (*cb)(void *u), void *user)
{
	r_cons_breaked = 0;
	r_cons_break_user = user;
	r_cons_break_cb = cb;
#if __UNIX__
	signal(SIGINT, break_signal);
#endif
}

void r_cons_break_end()
{
	r_cons_breaked = 0;
#if __UNIX__
	signal(SIGINT, SIG_IGN);
#endif
}

int r_cons_init()
{
	r_cons_stdin_fd = stdin;
#if HAVE_DIETLINE
	r_line_init();
#endif
	//r_cons_palette_init(NULL);
	return 0;
}

static void palloc(int moar)
{
	if (r_cons_buffer == NULL) {
		r_cons_buffer_sz = moar+MOAR_VALUE;
		r_cons_buffer = (char *)malloc(r_cons_buffer_sz);
		r_cons_buffer[0]='\0';
	} else
	if (moar + r_cons_buffer_len > r_cons_buffer_sz) {
		r_cons_buffer_sz += moar+MOAR_VALUE;
		r_cons_buffer = (char *)realloc(r_cons_buffer, r_cons_buffer_sz);
	}
}

int r_cons_eof()
{
	return feof(r_cons_stdin_fd);
}

static void r_cons_print_real(const char *buf)
{
#if __WINDOWS__
	if (r_cons_stdout_fd == 1)
		r_cons_w32_print(buf);
	else
#endif
	if (r_cons_is_html)
		r_cons_html_print(buf);
	else write(r_cons_stdout_fd, buf, r_cons_buffer_len);
}


#if __WINDOWS__
void r_cons_gotoxy(int x, int y)
{
        static HANDLE hStdout = NULL;
        COORD coord;

        coord.X = x;
        coord.Y = y;

        if(!hStdout)
                hStdout = GetStdHandle(STD_OUTPUT_HANDLE);

        SetConsoleCursorPosition(hStdout,coord);
}
#else
void r_cons_gotoxy(int x, int y)
{
	r_cons_strcat("\x1b[0;0H");
}
#endif

void r_cons_clear00()
{
	r_cons_clear();
	r_cons_gotoxy(0, 0);
}

void r_cons_clear()
{
#if __WINDOWS__
        static HANDLE hStdout = NULL;
        static CONSOLE_SCREEN_BUFFER_INFO csbi;
        const COORD startCoords = {0,0};
        DWORD dummy;

        if(!hStdout) {
                hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
                GetConsoleScreenBufferInfo(hStdout,&csbi);
        }

        FillConsoleOutputCharacter(hStdout, ' ', csbi.dwSize.X * csbi.dwSize.Y, startCoords, &dummy);
        r_cons_gotoxy(0,0);
#else
	r_cons_strcat("\x1b[2J");
#endif
r_cons_flush();
	r_cons_lines = 0;
}

void r_cons_reset()
{
	if (r_cons_buffer)
		r_cons_buffer[0] = '\0';
	r_cons_buffer_len = 0;
	r_cons_lines = 0;
	r_cons_lastline = r_cons_buffer;
	grepstrings_n = 0; // XXX
	grepline = -1;
	grepstr = NULL;
	greptoken = -1;
}

const char *r_cons_get_buffer()
{
	return r_cons_buffer;
}

void r_cons_grep(const char *str)
{
	char *optr, *tptr;
	char *ptr, *ptr2, *ptr3;
	grepcounter=0;
	/* set grep string */
	if (str != NULL && *str) {
		if (*str == '!') {
			grepneg = 1;
			str = str + 1;
		} else grepneg = 0;
		if (*str == '?') {
			grepcounter = 1;
			str = str + 1;
		}
		ptr = alloca(strlen(str)+2);
		strcpy(ptr, str);

		ptr3 = strchr(ptr, '[');
		ptr2 = strchr(ptr, '#');

		if (ptr3) {
			ptr3[0]='\0';
			greptoken = atoi(ptr3+1);
			if (greptoken<0)
				greptoken--;
		}
		if (ptr2) {
			ptr2[0]='\0';
			grepline = atoi(ptr2+1);
		}

		grepstrings_n = 0;
		if (*ptr) {
			free(grepstr);
			grepstr = (char *)strdup(ptr);
		/* set the rest of words to grep */
			grepstrings_n = 0;
			// TODO: refactor this ugly loop
			optr = grepstr;
			tptr = strchr(optr, '!');
			while(tptr) {
				tptr[0] = '\0';
				// TODO: check if keyword > 64
				strncpy(grepstrings[grepstrings_n], optr, 63);
				grepstrings_n++;
				optr = tptr+1;
				tptr = strchr(optr, '!');
			}
			strncpy(grepstrings[grepstrings_n], optr, 63);
			grepstrings_n++;
			ptr = optr;
		}
	} else {
		greptoken = -1;
		grepline = -1;
		grepstr = NULL;
		grepstrings_n = 0;
	}
}

void r_cons_flush()
{
	char *tee = r_cons_teefile;

	if (r_cons_noflush)
		return;

	if (r_cons_interactive) {
		if (r_cons_buffer_len > CONS_MAX_USER) {
			if (r_cons_yesno('n', "Do you want to print %d bytes? (y/N)", r_cons_buffer_len)== 0) {
				r_cons_reset();
				return;
			}
		}
	}

	if (tee&&tee[0]) {
		FILE *d = fopen(tee, "a+");
		if (d != NULL) {
			fwrite(r_cons_buffer, strlen(r_cons_buffer), 1, d);
			fclose(d);
		}
	// TODO: make this 'write' portable
	} else write(1, r_cons_buffer, r_cons_buffer_len);
	r_cons_reset();
}

void r_cons_printf(const char *format, ...)
{
	int len;
	char buf[CONS_BUFSZ];
	va_list ap;

	if (strchr(format,'%')==NULL) {
		r_cons_strcat(format);
		return;
	}

	va_start(ap, format);

	len = vsnprintf(buf, CONS_BUFSZ-1, format, ap);
	if (len>0)
		r_cons_memcat(buf, len);

	va_end(ap);
}

int r_cons_grepbuf(const char *buf, int len)
{
	int donotline = 0;
	int i, j, hit = 0;
	char delims[6][2] = {"|", "/", "\\", ",", ";", "\t"};
	char *n = memchr(buf, '\n', len);

	if (grepstrings_n==0) {
		if (n) r_cons_lines++;
		return len;
	}

	if (r_cons_lastline==NULL)
		r_cons_lastline = r_cons_buffer;

	if (!n) return len;

	for(i=0;i<grepstrings_n;i++) {
		grepstr = grepstrings[i];
		if ( (!grepneg && strstr(buf, grepstr))
		|| (grepneg && !strstr(buf, grepstr))) {
			hit = 1;
			break;
		}
	}

	if (hit) {
		if (grepline != -1) {
			if (grepline==r_cons_lines) {
				r_cons_lastline = buf+len;
				//r_cons_lines++;
			} else {
				donotline = 1;
				r_cons_lines++;
			}
		}
	} else donotline = 1;

	if (donotline) {
		r_cons_buffer_len -= strlen(r_cons_lastline)-len;
		r_cons_lastline[0]='\0';
		len = 0;
	} else {
		if (greptoken != -1) {
			//ptr = alloca(strlen(r_cons_lastline));
			char *tok = NULL;
			char *ptr = alloca(1024); // XXX
			strcpy(ptr, r_cons_lastline);
			for (i=0; i<len; i++) for (j=0;j<6;j++)
				if (ptr[i] == delims[j][0])
					ptr[i] = ' ';
			tok = ptr;
			for (i=0;tok != NULL && i<=greptoken;i++) {
				if (i==0) tok = (char *)strtok(ptr, " ");
				else tok = (char *)strtok(NULL, " ");
			}
			if (tok) {
				// XXX remove strlen here!
				r_cons_buffer_len -= strlen(r_cons_lastline)-len;
				len = strlen(tok);
				memcpy(r_cons_lastline, tok, len);
				if (r_cons_lastline[len-1]!='\n')
					memcpy(r_cons_lastline+len, "\n", 2);
				len++;
				r_cons_lastline +=len;
			}
		} else r_cons_lastline = buf+len;
		r_cons_lines++;
	}
	return len;
}

/* final entrypoint for adding stuff in the buffer screen */
void r_cons_memcat(const char *str, int len)
{
	palloc(len);
	memcpy(r_cons_buffer+r_cons_buffer_len, str, len+1); // XXX +1??
	r_cons_buffer_len += r_cons_grepbuf(r_cons_buffer+r_cons_buffer_len, len);
}

void r_cons_strcat(const char *str)
{
	int len = strlen(str);
	if (len>0)
		r_cons_memcat(str, len);
}

void r_cons_newline()
{
	if (r_cons_is_html)
		r_cons_strcat("<br />\n");
	else r_cons_strcat("\n");
}

int r_cons_get_columns()
{
	int columns_i = r_cons_get_real_columns();
	char buf[64];

	if (columns_i<2)
		columns_i = 78;

	sprintf(buf, "%d", columns_i);
	setenv("COLUMNS", buf, 0);

	return columns_i;
}

int r_cons_get_real_columns()
{
#if __UNIX__
        struct winsize win;

        if (ioctl(1, TIOCGWINSZ, &win)) {
		/* default values */
		win.ws_col = 80;
		win.ws_row = 23;
	}
#ifdef RADARE_CORE
	config.width = win.ws_col;
	config.height = win.ws_row;
#endif
        return win.ws_col;
#else
	return 80;
#endif
}

int r_cons_yesno(int def, const char *fmt, ...)
{
	va_list ap;
	int key = def;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fflush(stderr);
	r_cons_set_raw(1);
	read(0, &key, 1); write(2, "\n", 1);
	r_cons_set_raw(0);
	if (key=='\n'||key=='\r')
		key = def;
	else key = 'y';

	return key=='y';
}

/**
 *
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
#if __UNIX__
static struct termios tio_old, tio_new;
#endif
static int termios_init = 0;

void r_cons_set_raw(int b)
{
#if __UNIX__
	if (b) {
		if (termios_init == 0) {
			tcgetattr(0, &tio_old);
			memcpy (&tio_new,&tio_old,sizeof(struct termios));
			tio_new.c_iflag &= ~(BRKINT|PARMRK|ISTRIP|INLCR|IGNCR|ICRNL|IXON);
			tio_new.c_lflag &= ~(ECHO|ECHONL|ICANON|ISIG|IEXTEN);
			tio_new.c_cflag &= ~(CSIZE|PARENB);
			tio_new.c_cflag |= CS8;
			tio_new.c_cc[VMIN]=1; // Solaris stuff hehe
			termios_init = 1;
		}
		tcsetattr(0, TCSANOW, &tio_new);
	} else
		tcsetattr(0, TCSANOW, &tio_old);
#else
	/* TODO : W32 */
#endif
	fflush(stdout);
}

#if 1
// XXX: major refactorize : get_arrow
//int r_cons_0x1b_to_hjkl(int ch)
int r_cons_get_arrow(int ch)
{
	if (ch==0x1b) {
		ch = r_cons_readchar();
		if (ch==0x5b) {
			// TODO: must also work in interactive visual write ascii mode
			ch = r_cons_readchar();
			switch(ch) {
			case 0x35: ch='K'; break; // re.pag
			case 0x36: ch='J'; break; // av.pag
			case 0x41: ch='k'; break; // up
			case 0x42: ch='j'; break; // down
			case 0x43: ch='l'; break; // right
			case 0x44: ch='h'; break; // left
			case 0x3b:
				   break;
			default:
				   ch = 0;
			}
		}
	}
	return ch;
}
#endif

/* TODO: handle screen width */
void r_cons_progressbar(int pc)
{
        int tmp, cols = 78;
        (pc<0)?pc=0:(pc>100)?pc=100:0;
        fprintf(stderr, "\x1b[K  %3d%% [", pc);
        cols-=15;
        for(tmp=cols*pc/100;tmp;tmp--) fprintf(stderr,"#");
        for(tmp=cols-(cols*pc/100);tmp;tmp--) fprintf(stderr,"-");
        fprintf(stderr, "]\r");
        fflush(stderr);
}
