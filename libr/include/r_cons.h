#ifndef _INCLUDE_CONS_R_
#define _INCLUDE_CONS_R_

#define HAVE_DIETLINE 1

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define CONS_BUFSZ 0x4f00
#define STR_IS_NULL(x) (!x || !x[0])
#define IS_PRINTABLE(x) (x>=' '&&x<='~')

/* XXX */
extern FILE *stdin_fd;
extern FILE *r_cons_stdin_fd;
extern int r_cons_stdout_fd;
extern int r_cons_stdout_file;

/* pipe */
int r_cons_pipe_open(const char *file, int append);
void r_cons_pipe_close(int fd);

/* plain colors */
#define C_BLACK    "\x1b[30m"
#define C_BGBLACK  "\x1b[40m"
#define C_RED      "\x1b[31m"
#define C_BGRED    "\x1b[41m"
#define C_WHITE    "\x1b[37m"
#define C_RESET    "\x1b[0m"
#define C_GREEN    "\x1b[32m"
#define C_MAGENTA  "\x1b[35m"
#define C_YELLOW   "\x1b[33m"
#define C_TURQOISE "\x1b[36m"
#define C_BLUE     "\x1b[34m"
#define C_GRAY     "\x1b[38m"
/* bold colors */
#define C_BBLACK    "\x1b[1;30m"
#define C_BRED      "\x1b[1;31m"
#define C_BBGRED    "\x1b[1;41m"
#define C_BWHITE    "\x1b[1;37m"
#define C_BGREEN    "\x1b[1;32m"
#define C_BMAGENTA  "\x1b[1;35m"
#define C_BYELLOW   "\x1b[1;33m"
#define C_BTURQOISE "\x1b[1;36m"
#define C_BBLUE     "\x1b[1;34m"
#define C_BGRAY     "\x1b[1;38m"

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

/* constructor */
int  r_cons_init();

/* control */
void r_cons_reset();
void r_cons_clear();
void r_cons_clear00();
void r_cons_stdout_open(const char *file, int append);
int  r_cons_stdout_set_fd(int fd);
void r_cons_gotoxy(int x, int y);
void r_cons_set_raw(int b);

/* output */
void r_cons_printf(const char *format, ...);
void r_cons_strcat(const char *str);
void r_cons_memcat(const char *str, int len);
void r_cons_newline();
void r_cons_flush();

/* input */
int  r_cons_fgets(char *buf, int len, int argc, const char **argv);
int  r_cons_readchar();
void r_cons_any_key();
int  r_cons_eof();

/* colors */
int r_cons_palette_init(const unsigned char *pal);

int r_cons_get_real_columns();
int r_cons_get_columns();
extern const char *dl_prompt;
int r_cons_get_arrow(int ch);
int r_cons_html_print(const char *ptr);

extern int r_cons_lines;
extern int r_cons_is_html;
extern int r_cons_noflush;
extern char *r_cons_filterline;
extern char *r_cons_teefile;

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

extern const char *r_cons_palette_default;
const char *r_cons_colors[CONS_COLORS_SIZE+1];
extern char r_cons_palette[CONS_PALETTE_SIZE][8];
const char *r_cons_get_buffer();
void r_cons_grep(const char *str);

void r_cons_invert(int set, int color);


#endif
