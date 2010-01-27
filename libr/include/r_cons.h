#ifndef _INCLUDE_CONS_R_
#define _INCLUDE_CONS_R_

#define HAVE_DIETLINE 0

#include "r_types.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define CONS_MAX_USER 102400
#define CONS_BUFSZ 0x4f00
#define STR_IS_NULL(x) (!x || !x[0])

typedef struct r_cons_t {
	int is_html;
	int rows;
	int columns;
	/* TODO: moar */
} RCons;

extern RCons r_cons_instance;

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

/* palette */
#define CONS_PALETTE_SIZE 22
#define CONS_COLORS_SIZE 21
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

// XXX THIS MUST BE A SINGLETON AND WRAPPED INTO RCons */
/* XXX : global variables? or a struct with a singleton? */
//extern FILE *stdin_fd;
extern FILE *r_cons_stdin_fd;
//extern int r_cons_stdout_fd;
//extern int r_cons_stdout_file;
extern int r_cons_breaked;
extern const char *r_cons_palette_default;
const char *r_cons_colors[CONS_COLORS_SIZE+1];
extern char r_cons_palette[CONS_PALETTE_SIZE][8];
//extern const char *dl_prompt;
extern int r_cons_columns;
extern int r_cons_rows;
extern int r_cons_lines; // private or public?
extern int r_cons_is_html;
extern int r_cons_noflush;
extern char *r_cons_filterline;
extern char *r_cons_teefile;
extern int (*r_cons_user_fgets)(char *buf, int len);

#ifdef R_API

R_API void r_cons_break(void (*cb)(void *u), void *user);
R_API void r_cons_break_end();

/* pipe */
R_API int r_cons_pipe_open(const char *file, int append);
R_API void r_cons_pipe_close(int fd);

/* constructor */
R_API int  r_cons_init();

/* control */
R_API void r_cons_reset();
R_API void r_cons_clear();
R_API void r_cons_clear00();
R_API void r_cons_stdout_open(const char *file, int append);
R_API int  r_cons_stdout_set_fd(int fd);
R_API void r_cons_gotoxy(int x, int y);
R_API void r_cons_set_raw(int b);

/* output */
R_API void r_cons_printf(const char *format, ...);
R_API void r_cons_strcat(const char *str);
R_API void r_cons_memcat(const char *str, int len);
R_API void r_cons_newline();
R_API void r_cons_flush();

/* input */
R_API int  r_cons_fgets(char *buf, int len, int argc, const char **argv);
R_API int  r_cons_readchar();
R_API void r_cons_any_key();
R_API int  r_cons_eof();

R_API int r_cons_palette_init(const unsigned char *pal);
R_API int r_cons_get_size(int *rows);
R_API int r_cons_get_arrow(int ch);
R_API int r_cons_html_print(const char *ptr);

R_API const char *r_cons_get_buffer();
R_API void r_cons_grep(const char *str);
R_API int r_cons_grepbuf(char *buf, int len);

R_API void r_cons_invert(int set, int color);
R_API int r_cons_yesno(int def, const char *fmt, ...);
#endif

#endif
