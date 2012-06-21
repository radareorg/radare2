#ifndef _INCLUDE_CONS_R_
#define _INCLUDE_CONS_R_

#define HAVE_DIETLINE 0

#include <r_types.h>
#include <r_util.h>

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if __UNIX__
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#endif
#if __WINDOWS__
#include <windows.h>
#include <wincon.h>
#endif

/* constants */
#define CONS_MAX_USER 102400
#define CONS_BUFSZ 0x4f00
#define STR_IS_NULL(x) (!x || !x[0])

/* palette */
#define CONS_PALETTE_SIZE 22
#define CONS_COLORS_SIZE 21

typedef struct r_cons_grep_t {
	char strings[10][64];
	int nstrings;
	char *str;
	int counter;
	int line;
	int tokenfrom;
	int tokento;
	int neg;
	int begin;
	int end;
} RConsGrep;

typedef void (*RConsEvent)(void *);

typedef struct r_cons_t {
	RConsGrep grep;
	char *buffer;
	int line;
	int buffer_len;
	int buffer_sz;
	char *lastline;
	int is_html;
	int is_interactive;
	int lines;
	int rows;
	int columns;
	int breaked;
	int noflush;
	FILE *fdin; // FILE? and then int ??
	int fdout; // only used in pipe.c :?? remove?
	const char *teefile;
	int (*user_fgets)(char *buf, int len);
	RConsEvent event_interrupt;
	RConsEvent event_resize;
	void *data;
#if __UNIX__
	struct termios term_raw, term_buf;
#elif __WINDOWS__
	LPDWORD term_raw, term_buf;
#endif
	RNum *num;
	/* Pager (like more or less) to use if the output doesn't fit on the
	 * current window. If NULL or "" no pager is used. */
	char *pager;
} RCons;

// XXX THIS MUST BE A SINGLETON AND WRAPPED INTO RCons */
/* XXX : global variables? or a struct with a singleton? */
//extern FILE *stdin_fd;
//extern FILE *r_cons_stdin_fd;
//extern int r_cons_stdout_fd;
//extern int r_cons_stdout_file;
//extern char *r_cons_filterline;
//extern char *r_cons_teefile;
// not needed anymoar
//extern int (*r_cons_user_fgets)(char *buf, int len);

#define R_CONS_KEY_F1 0xf1
#define R_CONS_KEY_F2 0xf2
#define R_CONS_KEY_F3 0xf3
#define R_CONS_KEY_F4 0xf4
#define R_CONS_KEY_F5 0xf5
#define R_CONS_KEY_F6 0xf6
#define R_CONS_KEY_F7 0xf7
#define R_CONS_KEY_F8 0xf8
#define R_CONS_KEY_F9 0xf9
#define R_CONS_KEY_F10 0xfa
#define R_CONS_KEY_F11 0xfb
#define R_CONS_KEY_F12 0xfc

#define R_CONS_KEY_ESC 0x1b

#define Color_BLINK        "\x1b[5m"
#define Color_INVERT       "\x1b[7m"
#define Color_INVERT_RESET "\x1b[27m"
/* plain colors */
#define Color_BLACK    "\x1b[30m"
#define Color_BGBLACK  "\x1b[40m"
#define Color_RED      "\x1b[31m"
#define Color_BGRED    "\x1b[41m"
#define Color_WHITE    "\x1b[37m"
#define Color_RESET    "\x1b[0m"
#define Color_GREEN    "\x1b[32m"
#define Color_MAGENTA  "\x1b[35m"
#define Color_YELLOW   "\x1b[33m"
#define Color_TURQOISE "\x1b[36m"
#define Color_BLUE     "\x1b[34m"
#define Color_GRAY     "\x1b[38m"
/* bold colors */
#define Color_BBLACK    "\x1b[1;30m"
#define Color_BRED      "\x1b[1;31m"
#define Color_BBGRED    "\x1b[1;41m"
#define Color_BWHITE    "\x1b[1;37m"
#define Color_BGREEN    "\x1b[1;32m"
#define Color_BMAGENTA  "\x1b[1;35m"
#define Color_BYELLOW   "\x1b[1;33m"
#define Color_BTURQOISE "\x1b[1;36m"
#define Color_BBLUE     "\x1b[1;34m"
#define Color_BGRAY     "\x1b[1;38m"

enum {
	PAL_PROMPT = 0,
	PAL_ADDRESS,
	PAL_DEFAULT,
	PAL_CHANGED,
	PAL_JUMP,
	PAL_CALL,
	PAL_PUSH,
	PAL_TRAP,
	PAL_CMP,
	PAL_RET,
	PAL_NOP,
	PAL_METADATA,
	PAL_HEADER,
	PAL_PRINTABLE,
	PAL_LINES0,
	PAL_LINES1,
	PAL_LINES2,
	PAL_00,
	PAL_7F,
	PAL_FF
};

/* default byte colors */
#if 0
#define COLOR_00 C_TURQOISE
#define COLOR_FF C_RED
#define COLOR_7F C_MAGENTA
#define COLOR_PR C_YELLOW
#define COLOR_HD C_GREEN
// addresses
#define COLOR_AD C_GREEN
#endif

#ifdef R_API
R_API RCons *r_cons_new ();
R_API RCons *r_cons_singleton ();
R_API RCons *r_cons_free ();

R_API void r_cons_break(void (*cb)(void *u), void *user);
R_API void r_cons_break_end();

/* pipe */
R_API int r_cons_pipe_open(const char *file, int append);
R_API void r_cons_pipe_close(int fd);

#if __WINDOWS__
R_API int r_cons_w32_print(ut8 *ptr, int empty);
#endif

/* control */
R_API void r_cons_reset();
R_API void r_cons_clear();
R_API void r_cons_clear00();
R_API void r_cons_clear_line();
R_API void r_cons_stdout_open(const char *file, int append);
R_API int  r_cons_stdout_set_fd(int fd);
R_API void r_cons_gotoxy(int x, int y);
R_API void r_cons_show_cursor (int cursor);
R_API void r_cons_set_raw(int b);
R_API void r_cons_set_interactive(int b);
R_API void r_cons_set_last_interactive();

/* output */
R_API void r_cons_printf(const char *format, ...);
R_API void r_cons_strcat(const char *str);
#define r_cons_puts(x) r_cons_strcat(x)
R_API void r_cons_strcat_justify (const char *str, int j, char c);
R_API void r_cons_memcat(const char *str, int len);
R_API void r_cons_newline();
R_API void r_cons_filter();
R_API void r_cons_flush();
R_API void r_cons_memset(char ch, int len);
R_API void r_cons_visual_flush();
R_API void r_cons_visual_write (char *buffer);

/* input */
//R_API int  r_cons_fgets(char *buf, int len, int argc, const char **argv);
R_API int  r_cons_readchar();
R_API void r_cons_any_key();
R_API int  r_cons_eof();

R_API int r_cons_palette_init(const unsigned char *pal);
R_API int r_cons_get_size(int *rows);
R_API int r_cons_arrow_to_hjkl(int ch);
R_API int r_cons_html_print(const char *ptr);

// TODO: use gets() .. MUST BE DEPRECATED
R_API int r_cons_fgets(char *buf, int len, int argc, const char **argv);
R_API char *r_cons_hud(RList *list, const char *prompt);
R_API char *r_cons_hud_path(const char *path, int dir);
R_API char *r_cons_hud_string(const char *s);
R_API char *r_cons_hud_file(const char *f);

R_API const char *r_cons_get_buffer();
R_API void r_cons_grep(const char *str);
R_API int r_cons_grep_line(char *buf, int len); // must be static
R_API int r_cons_grepbuf(char *buf, int len);

R_API void r_cons_invert(int set, int color);
R_API int r_cons_yesno(int def, const char *fmt, ...);
R_API void r_cons_set_cup(int enable);
R_API void r_cons_column(int c);
R_API int r_cons_get_column();
R_API char *r_cons_message(const char *msg);
#endif

#endif
