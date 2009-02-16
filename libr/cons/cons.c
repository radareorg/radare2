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

// WTF //
char *strsub (char *string, char *pat, char *rep, int global);
int r_cons_stdout_fd = 1;
FILE *r_cons_stdin_fd = NULL; // TODO use int fd here too!

static int r_cons_buffer_sz = 0;
static int r_cons_buffer_len = 0;
static char *r_cons_buffer = NULL;
char *r_cons_filterline = NULL;
char *r_cons_teefile = NULL;
int r_cons_is_html = 0;
int r_cons_lines = 0;
int r_cons_noflush = 0;

static int grepline = -1, greptoken = -1, grepcounter = 0, grepneg = 0;
static char *grepstr = NULL;

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
		r_cons_buffer_sz = moar+4096;
		r_cons_buffer = (char *)malloc(r_cons_buffer_sz);
		r_cons_buffer[0]='\0';
	} else
	if (moar + r_cons_buffer_len > r_cons_buffer_sz) {
		r_cons_buffer_sz += moar+4096;
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
	r_cons_lines = 0;
}


void r_cons_reset()
{
	if (r_cons_buffer)
		r_cons_buffer[0] = '\0';
	r_cons_buffer_len = 0;
	r_cons_lines = 0;
}

const char *r_cons_get_buffer()
{
	return r_cons_buffer;
}

void r_cons_grep(const char *str)
{
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

		if (*ptr) {
			free(grepstr);
			grepstr = (char *)strdup(ptr);
		}
	} else {
		greptoken = -1;
		grepline = -1;
		free(grepstr);
		grepstr = NULL;
	}
}

/* TODO: refactorize */
void r_cons_flush()
{
	FILE *fd;
	char buf[1024];
	int i,j;
	int lines_counter = 0;

	if (r_cons_noflush)
		return;

	if (!STR_IS_NULL(r_cons_buffer)) {
		char *file = r_cons_filterline;
		char *tee = r_cons_teefile;
		if (!STR_IS_NULL(file)) {
			fd = fopen(file, "r");
			if (fd) {
				while(!feof(fd)) {
					buf[0]='\0';
					fgets(buf, 1020, fd);
					if (buf[0]) {
						buf[strlen(buf)-1]='\0';
						char *ptr = strchr(buf, '\t');;
						if (ptr) {
							ptr[0]='\0'; ptr = ptr +1;
							r_cons_buffer = (char *)r_str_sub(r_cons_buffer, buf, ptr, 1);
							r_cons_buffer_len = strlen(r_cons_buffer);
						}
					}
				}
				fclose(fd);
			}
		}
		
		if (tee&&tee[0]) {
			FILE *d = fopen(tee, "a+");
			if (d != NULL) {
				fwrite(r_cons_buffer, strlen(r_cons_buffer),1, d);
				fclose(d);
			}
		}

		// XXX merge grepstr with r_cons_lines loop //
		r_cons_lines += r_str_nchr(buf, '\n');

		// XXX major cleanup here!
		if (grepstr != NULL) {
			int line, len;
			char *one = r_cons_buffer;
			char *two;
			char *ptr, *tok;
			char delims[6][2] = {"|", "/", "\\", ",", ";", "\t"};

			for(line=0;;) {
				two = strchr(one, '\n');
				if (two) {
					two[0] = '\0';
					len = two-one;
				//	len = strlen(one);
//					if (strstr(one, grepstr)) {
					if ( (!grepneg && strstr(one, grepstr))
					|| (grepneg && !strstr(one, grepstr))) {
						if (grepline ==-1 || grepline==line) {
							if (greptoken != -1) {
								ptr = alloca(len+1);
								strcpy(ptr, one);
								for (i=0; i<len; i++)
									for (j=0;j<6;j++)
										if (ptr[i] == delims[j][0])
											ptr[i] = ' ';
								tok = ptr;
								if (greptoken<0) {
									int i, idx = greptoken+1;
									for(i = 0;ptr[i]; i++) {
										if (ptr[i]==' ')
											idx++;
										if (idx == 0) {
											ptr = ptr +i;
											r_cons_buffer_len = strlen(ptr);
											break;
										}
									}
								} else {
									for (i=0;tok != NULL && i<=greptoken;i++) {
										if (i==0)
											tok = (char *)strtok(ptr, " ");
										else tok = (char *)strtok(NULL, " ");
									}
								}

								if (tok) {
									ptr = tok;
									r_cons_buffer_len=strlen(tok);
								}
							} else {
								ptr = one;
								r_cons_buffer_len=len;
							}
							if (grepcounter==0) {
								r_cons_print_real(ptr);
								r_cons_buffer_len=1;
								r_cons_print_real("\n");
							} else lines_counter++;
						}
						line++;
					}
					two[0] = '\n';
					one = two + 1;
				} else break;
			}
		} else {
			if (grepline != -1 || grepcounter || greptoken != -1) {
				int len, line;
				char *one = r_cons_buffer;
				char *two;
				char *ptr, *tok;
				char delims[6][2] = {"|", "/", "\\", ",", ";", "\t"};
				for(line=0;;line++) {
					two = strchr(one, '\n');
					if (two) {
						two[0] = '\0';
						len=two-one;
						if (grepline ==-1 || grepline==line) {
							if (greptoken != -1) {
								ptr = alloca(len+1);
								strcpy(ptr, one);

								for (i=0; i<len; i++)
									for (j=0;j<6;j++)
										if (ptr[i] == delims[j][0])
											ptr[i] = ' ';

								tok = ptr;
								if (greptoken<0) {
									int i, idx = greptoken+1;
									for(i = 0;ptr[i]; i++) {
										if (ptr[i]==' ')
											idx++;
										if (idx == 0) {
											ptr = ptr +i;
											r_cons_buffer_len = strlen(ptr);
											break;
										}
									}
								} else {
									for (i=0;tok != NULL && i<=greptoken;i++) {
										if (i==0)
											tok = (char *)strtok(ptr, " ");
										else tok = (char *)strtok(NULL," ");
									}
								}

								if (tok) {
									ptr = tok;
									r_cons_buffer_len=strlen(tok);
								}
							} else {
								ptr = one;
								r_cons_buffer_len=len;
							}
							if (grepcounter==0) {
								r_cons_print_real(ptr);
								r_cons_buffer_len=1;
								r_cons_print_real("\n");
							} else lines_counter++;
						}
						two[0] = '\n';
						one = two + 1;
					} else break;
				}
			} else r_cons_print_real(r_cons_buffer);
		}

		r_cons_buffer[0] = '\0';
	}

	if (grepcounter) {
		char buf[32];
		sprintf(buf, "%d\n", lines_counter);
		r_cons_buffer_len = strlen(buf);
		r_cons_print_real(buf);
	}
	//r_cons_buffer_sz=0;
	r_cons_buffer_len=0;
}

/* stream is ignored */
void r_cons_fprintf(FILE *stream, const char *format, ...)
{
	/* dupped */
	int len;
	char buf[CONS_BUFSZ];
	va_list ap;

	va_start(ap, format);

	len = vsnprintf(buf, CONS_BUFSZ-1, format, ap);
	if (len>0) {
		len = strlen(buf);
		palloc(len);
		memcpy(r_cons_buffer+r_cons_buffer_len, buf, len+1);
		r_cons_buffer_len += len;
	}

	va_end(ap);
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
	if (len>0) {
		palloc(len);
	//	r_cons_lines += r_cons_lines_count(buf);
		memcpy(r_cons_buffer+r_cons_buffer_len, buf, len+1);
		r_cons_buffer_len += len;
	}

	va_end(ap);
}

void r_cons_memcat(const char *str, int len)
{
	palloc(len);
	memcpy(r_cons_buffer+r_cons_buffer_len, str, len+1);
	r_cons_buffer_len += len;
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

#ifdef RADARE_CORE
int yesno(int def, const char *fmt, ...)
{
	va_list ap;
	int key = def;

	if (config.visual)
		key='y';
	else D {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
		fflush(stderr);
		r_cons_set_raw(1);
		read(0, &key, 1); write(2, "\n", 1);
		r_cons_set_raw(0);
		if (key=='\n'||key=='\r')
			key = def;
	} else
		key = 'y';

	return key=='y';
}
#endif

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

#if 0
// get_arrow
int r_cons_0x1b_to_hjkl(int ch)
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
