#ifndef R2_CONS_H
#define R2_CONS_H

#define HAVE_DIETLINE 1

#ifdef __cplusplus
extern "C" {
#endif

#include <r_types.h>
#include <r_util.h>
#include <sdb.h>

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

#define R_CONS_GREP_WORDS 10
#define R_CONS_GREP_WORD_SIZE 64

R_LIB_VERSION_HEADER(r_cons);

typedef struct r_cons_grep_t {
	char strings[R_CONS_GREP_WORDS][R_CONS_GREP_WORD_SIZE];
	int nstrings;
	char *str;
	int counter;
	int less;
	int json;
	int line;
	int tokenfrom;
	int tokento;
	int amp;
	int neg;
	int begin;
	int end;
} RConsGrep;

typedef struct r_cons_palette_t {
	char *b0x00;
	char *b0x7f;
	char *b0xff;
	char *args;
	char *bin;
	char *btext;
	char *call;
	char *cjmp;
	char *cmp;
	char *comment;
	char *creg;
	char *flag;
	char *fline;
	char *floc;
	char *flow;
	char *fname;
	char *help;
	char *input;
	char *invalid;
	char *jmp;
	char *label;
	char *math;
	char *mov;
	char *nop;
	char *num;
	char *offset;
	char *other;
	char *pop;
	char *prompt;
	char *push;
	char *reg;
	char *reset;
	char *ret;
	char *swi;
	char *trap;
	char *ai_read;
	char *ai_write;
	char *ai_exec;
	char *ai_seq;
	char *ai_ascii;
	char *gui_cflow;
	char *gui_dataoffset;
	char *gui_background;
	char *gui_alt_background;
	char *gui_border;
#define R_CONS_PALETTE_LIST_SIZE 8
	char *list[R_CONS_PALETTE_LIST_SIZE];
} RConsPalette;

typedef void (*RConsEvent)(void *);

typedef struct r_cons_canvas_t {
	int w;
	int h;
	int x;
	int y;
	char *b;
	int blen;
	int sx; // scrollx
	int sy; // scrolly
} RConsCanvas;

typedef char *(*RConsEditorCallback)(void *core, const char *file, const char *str);

typedef struct r_cons_t {
	RConsGrep grep;
	char *buffer;
	//int line;
	int buffer_len;
	int buffer_sz;
	char *lastline;
	int is_html;
	int is_interactive;
	int lines;
	int rows;
	int echo; // dump to stdout in realtime
	int fps;
	int columns;
	int force_rows;
	int force_columns;
	int fix_rows;
	int fix_columns;
	int breaked;
	int noflush;
	FILE *fdin; // FILE? and then int ??
	int fdout; // only used in pipe.c :?? remove?
	const char *teefile;
	int (*user_fgets)(char *buf, int len);
	RConsEvent event_interrupt;
	RConsEvent event_resize;
	void *data;
	void *event_data;

	RConsEditorCallback editor;
	void *user; // Used by <RCore*>
#if __UNIX__
	struct termios term_raw, term_buf;
#elif __WINDOWS__
	LPDWORD term_raw, term_buf;
#endif
	RNum *num;
	/* Pager (like more or less) to use if the output doesn't fit on the
	 * current window. If NULL or "" no pager is used. */
	char *pager;
	int blankline;
	int truecolor; // 0 = ansi, 1 = rgb 256), 2 = truecolor (16M)
	char *highlight;
	int null; // if set, does not show anything
	int mouse;
	RConsPalette pal;
	struct r_line_t *line;
	const char **vline;
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
#define Color_RESET      "\x1b[0m"
#define Color_BLACK      "\x1b[30m"
#define Color_BGBLACK    "\x1b[40m"
#define Color_RED        "\x1b[31m"
#define Color_BGRED      "\x1b[41m"
#define Color_WHITE      "\x1b[37m"
#define Color_BGWHITE    "\x1b[47m"
#define Color_GREEN      "\x1b[32m"
#define Color_BGGREEN    "\x1b[42m"
#define Color_MAGENTA    "\x1b[35m"
#define Color_BGMAGENTA  "\x1b[45m"
#define Color_YELLOW     "\x1b[33m"
#define Color_BGYELLOW   "\x1b[43m"
#define Color_CYAN       "\x1b[36m"
#define Color_BGCYAN     "\x1b[46m"
#define Color_BLUE       "\x1b[34m"
#define Color_BGBLUE     "\x1b[44m"
#define Color_GRAY       "\x1b[38m"
#define Color_BGGRAY     "\x1b[48m"
/* bold colors */
#define Color_BBLACK    "\x1b[1;30m"
#define Color_BRED      "\x1b[1;31m"
#define Color_BBGRED    "\x1b[1;41m"
#define Color_BWHITE    "\x1b[1;37m"
#define Color_BGREEN    "\x1b[1;32m"
#define Color_BMAGENTA  "\x1b[1;35m"
#define Color_BYELLOW   "\x1b[1;33m"
#define Color_BCYAN     "\x1b[1;36m"
#define Color_BBLUE     "\x1b[1;34m"
#define Color_BGRAY     "\x1b[1;38m"

#define Colors_PLAIN { \
	Color_BLACK, Color_RED, Color_WHITE, \
	Color_GREEN, Color_MAGENTA, Color_YELLOW, \
	Color_CYAN, Color_BLUE, Color_GRAY}

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

// UTF-8 symbols indexes

#define LINE_VERT 0
#define LINE_CROSS 1
#define RUP_CORNER 2
#define RDWN_CORNER 3
#define ARROW_RIGHT 4
#define ARROW_LEFT 5
#define LINE_HORIZ 6
#define LUP_CORNER 7
#define LDWN_CORNER 8
#define LINE_UP 9


#ifdef R_API
R_API RConsCanvas* r_cons_canvas_new (int w, int h);
R_API void r_cons_canvas_free (RConsCanvas *c);
R_API void r_cons_canvas_clear (RConsCanvas *c);
R_API void r_cons_canvas_print(RConsCanvas *c);
R_API char *r_cons_canvas_to_string(RConsCanvas *c);
R_API void r_cons_canvas_write(RConsCanvas *c, const char *_s);
R_API int r_cons_canvas_gotoxy(RConsCanvas *c, int x, int y);
R_API void r_cons_canvas_box(RConsCanvas *c, int x, int y, int w, int h);
R_API void r_cons_canvas_line (RConsCanvas *c, int x, int y, int x2, int y2, int style);
R_API int r_cons_canvas_resize(RConsCanvas *c, int w, int h);
R_API void r_cons_canvas_fill(RConsCanvas *c, int x, int y, int w, int h, char ch, int replace);

R_API RCons *r_cons_new ();
R_API RCons *r_cons_singleton ();
R_API RCons *r_cons_free ();
R_API char *r_cons_lastline ();

typedef void (*RConsBreak)(void *);
R_API void r_cons_break(RConsBreak cb, void *user);
R_API void r_cons_break_end();

/* pipe */
R_API int r_cons_pipe_open(const char *file, int fdn, int append);
R_API void r_cons_pipe_close(int fd);

#if __WINDOWS__
R_API int r_cons_w32_print(ut8 *ptr, int empty);
#endif

/* control */
R_API char *r_cons_editor (const char *file, const char *str);
R_API void r_cons_reset();
R_API void r_cons_reset_colors();
R_API void r_cons_print_clear();
R_API void r_cons_zero();
R_API void r_cons_highlight (const char *word);
R_API void r_cons_clear();
R_API void r_cons_clear00();
R_API void r_cons_clear_line(int err);
R_API void r_cons_fill_line();
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
R_API void r_cons_less_str(const char *str);
R_API void r_cons_less();
R_API void r_cons_2048();
R_API void r_cons_memset(char ch, int len);
R_API void r_cons_visual_flush();
R_API void r_cons_visual_write (char *buffer);
R_API int r_cons_is_utf8();

/* input */
//R_API int  r_cons_fgets(char *buf, int len, int argc, const char **argv);
R_API int r_cons_controlz(int ch);
R_API int  r_cons_readchar();
R_API void r_cons_any_key();
R_API int  r_cons_eof();

R_API int r_cons_palette_init(const unsigned char *pal);
R_API int r_cons_pal_set (const char *key, const char *val);
R_API void r_cons_pal_init(const char *foo);
R_API char *r_cons_pal_parse(const char *str);
R_API void r_cons_pal_random();
R_API const char *r_cons_pal_get (const char *key);
R_API const char *r_cons_pal_get_i (int n);
R_API const char *r_cons_pal_get_color(int n);
R_API int r_cons_rgb_parse (const char *p, ut8 *r, ut8 *g, ut8 *b, int *is_bg);
R_API void r_cons_pal_list (int rad);
R_API void r_cons_pal_show ();
R_API int r_cons_get_size(int *rows);
R_API int r_cons_get_cursor(int *rows);
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

R_API void r_cons_rgb (ut8 r, ut8 g, ut8 b, int is_bg);
R_API void r_cons_rgb_fgbg (ut8 r, ut8 g, ut8 b, ut8 R, ut8 G, ut8 B);
R_API void r_cons_rgb_init (void);
R_API char *r_cons_rgb_str (char *outstr, ut8 r, ut8 g, ut8 b, int is_bg);
R_API void r_cons_color (int fg, int r, int g, int b);
R_API char *r_cons_color_random(int bg);
R_API void r_cons_invert(int set, int color);
R_API int r_cons_yesno(int def, const char *fmt, ...);
R_API void r_cons_set_cup(int enable);
R_API void r_cons_column(int c);
R_API int r_cons_get_column (void);
R_API char *r_cons_message(const char *msg);
R_API void r_cons_set_title(const char *str);
R_API int r_cons_enable_mouse(const int enable);
#endif

/* r_line */
#define R_LINE_BUFSIZE 4096
#define R_LINE_HISTSIZE 256

typedef struct r_line_hist_t {
	char **data;
	int size;
	int index;
	int top;
	int autosave;
} RLineHistory;

typedef struct r_line_buffer_t {
	char data[R_LINE_BUFSIZE];
	int index;
	int length;
} RLineBuffer;

typedef struct r_line_t RLine; // forward declaration

typedef int (*RLineCallback)(RLine *line);

typedef struct r_line_comp_t {
	int argc;
	const char **argv;
	RLineCallback run;
} RLineCompletion;

typedef char* (*RLineEditorCb)(void *core, const char *str);

struct r_line_t {
	RLineCompletion completion;
	RLineHistory history;
	RLineBuffer buffer;
	RLineEditorCb editor_cb;
	int echo;
	int has_echo;
	char *prompt;
	char *clipboard;
	int disable;
	void *user;
	int (*hist_up)(void *user);
	int (*hist_down)(void *user);
	char *contents;
}; /* RLine */

#ifdef R_API

R_API RLine *r_line_new();
R_API RLine *r_line_singleton();
R_API void r_line_free();
R_API char *r_line_get_prompt ();
R_API void r_line_set_prompt(const char *prompt);

typedef int (RLineReadCallback) (void *user, const char *line);
R_API char *r_line_readline();
R_API char *r_line_readline_cb(RLineReadCallback cb, void *user);

R_API int r_line_hist_load(const char *file);
R_API int r_line_hist_add(const char *line);
R_API int r_line_hist_save(const char *file);
R_API int r_line_hist_label(const char *label, void (*cb)(const char*));
R_API void r_line_label_show();
R_API int r_line_hist_list();
R_API const char *r_line_hist_get(int n);

#define R_CONS_INVERT(x,y) (y? (x?Color_INVERT: Color_INVERT_RESET): (x?"[":"]"))

#endif

#ifdef __cplusplus
}
#endif

#endif
