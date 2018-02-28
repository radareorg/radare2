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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#if __UNIX__ || __CYGWIN__ && !defined(MINGW32)
#include <termios.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/socket.h>
#endif
#if __WINDOWS__ && !defined(__CYGWIN__)
#include <windows.h>
#include <wincon.h>
#endif
#include <unistd.h>

/* constants */
#define CONS_MAX_USER 102400
#define CONS_BUFSZ 0x4f00
#define STR_IS_NULL(x) (!x || !x[0])

/* palette */
#define CONS_PALETTE_SIZE 22
#define CONS_COLORS_SIZE 21

#define R_CONS_GREP_WORDS 10
#define R_CONS_GREP_WORD_SIZE 64
#define R_CONS_GREP_TOKENS 64

R_LIB_VERSION_HEADER(r_cons);

typedef int (*RConsGetSize)(int *rows);
typedef int (*RConsGetCursor)(int *rows);

typedef struct r_cons_bind_t {
	RConsGetSize get_size;
	RConsGetCursor get_cursor;
} RConsBind;

typedef struct r_cons_grep_t {
	char strings[R_CONS_GREP_WORDS][R_CONS_GREP_WORD_SIZE];
	int nstrings;
	char *str;
	int counter;
	bool charCounter;
	int less;
	int json;
	char *json_path;
	int range_line;
	int line;
	int sort;
	int sort_row;
	bool sort_invert;
	int f_line; //first line
	int l_line; //last line
	int tokens[R_CONS_GREP_TOKENS];
	int tokens_used;
	int amp;
	int neg;
	int begin;
	int end;
	int icase;
} RConsGrep;

#if 0
// TODO Might be better than using r_cons_pal_get_i
// And have smaller RConsPrintablePalette and RConsPalette
enum {
	R_CONS_PAL_0x00 = 0,
	R_CONS_PAL_0x7f,
	R_CONS_PAL_0xff,
	R_CONS_PAL_ARGS,
	R_CONS_PAL_BIN,
	R_CONS_PAL_BTEXT,
	R_CONS_PAL_CALL,
	R_CONS_PAL_CJMP,
	R_CONS_PAL_CMP,
	R_CONS_PAL_COMMENT,
	R_CONS_PAL_CREG,
	R_CONS_PAL_FLAG,
	R_CONS_PAL_FLINE,
	R_CONS_PAL_FLOC,
	R_CONS_PAL_FLOW,
	R_CONS_PAL_FLOW2,
	R_CONS_PAL_FNAME,
	R_CONS_PAL_HELP,
	R_CONS_PAL_INPUT,
	R_CONS_PAL_INVALID,
	R_CONS_PAL_JMP,
	R_CONS_PAL_LABEL,
	R_CONS_PAL_MATH,
	R_CONS_PAL_MOV,
	R_CONS_PAL_NOP,
	R_CONS_PAL_NUM,
	R_CONS_PAL_OFFSET,
	R_CONS_PAL_OTHER,
	R_CONS_PAL_POP,
	R_CONS_PAL_PROMPT,
	R_CONS_PAL_PUSH,
	R_CONS_PAL_CRYPTO,
	R_CONS_PAL_REG,
	R_CONS_PAL_RESET,
	R_CONS_PAL_RET,
	R_CONS_PAL_SWI,
	R_CONS_PAL_TRAP,
	R_CONS_PAL_AI_READ,
	R_CONS_PAL_AI_WRITE,
	R_CONS_PAL_AI_EXEC,
	R_CONS_PAL_AI_SEQ,
	R_CONS_PAL_AI_ASCII,
	R_CONS_PAL_AI_UNMAP,
	R_CONS_PAL_GUI_CFLOW,
	R_CONS_PAL_GUI_DATAOFFSET,
	R_CONS_PAL_GUI_BACKGROUND,
	R_CONS_PAL_GUI_ALT_BACKGROUND,
	R_CONS_PAL_GUI_BORDER,
	R_CONS_PAL_GRAPH_BOX,
	R_CONS_PAL_GRAPH_BOX2,
	R_CONS_PAL_GRAPH_BOX3,
	R_CONS_PAL_GRAPH_BOX4,
	R_CONS_PAL_GRAPH_TRUE,
	R_CONS_PAL_GRAPH_FALSE,
	R_CONS_PAL_GRAPH_TRUFAE,
	R_CONS_PAL_GRAPH_TRACED,
	R_CONS_PAL_GRAPH_CURRENT,
	R_CONS_PAL_LAST
};
#endif

enum { COLOR_MODE_DISABLED = 0, COLOR_MODE_16, COLOR_MODE_256, COLOR_MODE_16M };

enum { ALPHA_RESET = 0x00, ALPHA_FG = 0x01, ALPHA_BG = 0x02, ALPHA_FGBG = 0x03, ALPHA_BOLD = 0x04 };

typedef struct rcolor_t {
	ut8 a;
	ut8 r;
	ut8 g;
	ut8 b;
	ut8 r2; // Background color
	ut8 g2; // Only used when a &= ALPHA_FGBG
	ut8 b2;
} RColor;

typedef struct r_cons_palette_t {
	RColor b0x00;
	RColor b0x7f;
	RColor b0xff;
	RColor args;
	RColor bin;
	RColor btext;
	RColor call;
	RColor cjmp;
	RColor cmp;
	RColor comment;
	RColor usercomment;
	RColor creg;
	RColor flag;
	RColor fline;
	RColor floc;
	RColor flow;
	RColor flow2;
	RColor fname;
	RColor help;
	RColor input;
	RColor invalid;
	RColor jmp;
	RColor label;
	RColor math;
	RColor mov;
	RColor nop;
	RColor num;
	RColor offset;
	RColor other;
	RColor pop;
	RColor prompt;
	RColor push;
	RColor crypto;
	RColor reg;
	RColor reset;
	RColor ret;
	RColor swi;
	RColor trap;
	RColor ai_read;
	RColor ai_write;
	RColor ai_exec;
	RColor ai_seq;
	RColor ai_ascii;
	RColor gui_cflow;
	RColor gui_dataoffset;
	RColor gui_background;
	RColor gui_alt_background;
	RColor gui_border;
	RColor highlight;

	/* Graph colors */
	RColor graph_box;
	RColor graph_box2;
	RColor graph_box3;
	RColor graph_box4;
	RColor graph_true;
	RColor graph_false;
	RColor graph_trufae;
	RColor graph_traced;
	RColor graph_current;
} RConsPalette;

typedef struct r_cons_printable_palette_t {
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
	char *usercomment;
	char *creg;
	char *flag;
	char *fline;
	char *floc;
	char *flow;
	char *flow2;
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
	char *crypto;
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
	char *ai_unmap;
	char *gui_cflow;
	char *gui_dataoffset;
	char *gui_background;
	char *gui_alt_background;
	char *gui_border;
	char *highlight;

	/* graph colors */
	char *graph_box;
	char *graph_box2;
	char *graph_box3;
	char *graph_box4;
	char *graph_true;
	char *graph_false;
	char *graph_trufae;
	char *graph_traced;
	char *graph_current;
	char **rainbow; // rainbow
	int rainbow_sz; // size of rainbow
} RConsPrintablePalette;

R_API char *r_cons_rainbow_get(int idx, int last, bool bg);
R_API void r_cons_rainbow_free(void);
R_API void r_cons_rainbow_new(int sz);

typedef void (*RConsEvent)(void *);

#define CONS_MAX_ATTR_SZ 15
typedef struct r_cons_canvas_attr_t {
	//TODO add support for 256 colors.
	int loc;
	const char * a;
} RConsCanvasAttr;

typedef struct r_cons_canvas_t {
	int w;
	int h;
	int x;
	int y;
	char *b;
	int blen;
	const char * attr;//The current attr (inserted on each write)
	RConsCanvasAttr * attrs;// all the different attributes
	int attrslen;
	int sx; // scrollx
	int sy; // scrolly
	int color;
	int linemode; // 0 = diagonal , 1 = square
} RConsCanvas;

#define RUNECODE_MIN 0xc8 // 200
#define RUNECODE_LINE_VERT 0xc8
#define RUNECODE_LINE_CROSS 0xc9
#define RUNECODE_CORNER_BR 0xca
#define RUNECODE_CORNER_BL 0xcb
#define RUNECODE_ARROW_RIGHT 0xcc
#define RUNECODE_ARROW_LEFT 0xcd
#define RUNECODE_LINE_HORIZ 0xce
#define RUNECODE_CORNER_TL 0xcf
#define RUNECODE_CORNER_TR 0xd0
#define RUNECODE_LINE_UP 0xd1
#define RUNECODE_CURVE_CORNER_TL 0xd2
#define RUNECODE_CURVE_CORNER_TR 0xd3
#define RUNECODE_CURVE_CORNER_BR 0xd4
#define RUNECODE_CURVE_CORNER_BL 0xd5
#define RUNECODE_MAX 0xd6

#define RUNECODESTR_MIN 0xc8 // 200
#define RUNECODESTR_LINE_VERT "\xc8"
#define RUNECODESTR_LINE_CROSS "\xc9"
#define RUNECODESTR_CORNER_BR "\xca"
#define RUNECODESTR_CORNER_BL "\xcb"
#define RUNECODESTR_ARROW_RIGHT "\xcc"
#define RUNECODESTR_ARROW_LEFT "\xcd"
#define RUNECODESTR_LINE_HORIZ "\xce"
#define RUNECODESTR_CORNER_TL "\xcf"
#define RUNECODESTR_CORNER_TR "\xd0"
#define RUNECODESTR_LINE_UP "\xd1"
#define RUNECODESTR_CURVE_CORNER_TL "\xd2"
#define RUNECODESTR_CURVE_CORNER_TR "\xd3"
#define RUNECODESTR_CURVE_CORNER_BR "\xd4"
#define RUNECODESTR_CURVE_CORNER_BL "\xd5"
#define RUNECODESTR_MAX 0xd5

#define RUNE_LINE_VERT "│"
#define RUNE_LINE_CROSS "┼" /* ├ */
#define RUNE_LINE_HORIZ "─"
#define RUNE_LINE_UP "↑"
#define RUNE_CORNER_BR "┘"
#define RUNE_CORNER_BL "└"
#define RUNE_CORNER_TL "┌"
#define RUNE_CORNER_TR "┐"
#define RUNE_ARROW_RIGHT ">"
#define RUNE_ARROW_LEFT "<"
#define RUNE_CURVE_CORNER_TL "╭"
#define RUNE_CURVE_CORNER_TR "╮"
#define RUNE_CURVE_CORNER_BR "╯"
#define RUNE_CURVE_CORNER_BL "╰"

typedef char *(*RConsEditorCallback)(void *core, const char *file, const char *str);
typedef int (*RConsClickCallback)(void *core, int x, int y);

typedef struct r_cons_t {
	RConsGrep grep;
	RStack *cons_stack;
	RStack *break_stack;
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
	bool breaked;
	bool break_lines;
	int noflush;
	FILE *fdin; // FILE? and then int ??
	int fdout; // only used in pipe.c :?? remove?
	const char *teefile;
	int (*user_fgets)(char *buf, int len);
	RConsEvent event_interrupt;
	RConsEvent event_resize;
	void *data;
	void *event_data;
	int mouse_event;

	RConsEditorCallback editor;
	void *user; // Used by <RCore*>
#if __UNIX__ || __CYGWIN__ && !defined(MINGW32)
	struct termios term_raw, term_buf;
#elif __WINDOWS__
	DWORD term_raw, term_buf;
#endif
	RNum *num;
	/* Pager (like more or less) to use if the output doesn't fit on the
	 * current window. If NULL or "" no pager is used. */
	char *pager;
	int blankline;
	int color; // 0 = none, 1 = ansi (16), 2 = palette (256), 3 = truecolor (16M)
	char *highlight;
	int null; // if set, does not show anything
	int mouse;
	int is_wine;
	RConsPalette cpal;
	RConsPrintablePalette pal;
	struct r_line_t *line;
	const char **vline;
	int refcnt;
	RConsClickCallback onclick;
	bool newline;
#if __WINDOWS__ && !__CYGWIN__
	bool ansicon;
#endif
	bool flush;
	bool use_utf8; // use utf8 features
	bool use_utf8_curvy; // use utf8 curved corners
	int linesleep;
	int pagesize;
	char *break_word;
	int break_word_len;
	ut64 timeout;
	bool grep_color;
	bool use_tts;
	bool filter;
	char* (*rgbstr)(char *str, ut64 addr);
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
#define Color_NOBGRESET  "\x1b[22;24;25;27;28;39m"
#define Color_BGRESET    "\x1b[49m"
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
#define Color_BGBYELLOW  "\x1b[1;43m"
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

#ifdef _MSC_VER
#define RCOLOR(a, r, g, b, bgr, bgg, bgb) {a, r, g, b, bgr, bgg, bgb}
#else
#define RCOLOR(a, r, g, b, bgr, bgg, bgb) (RColor) {a, r, g, b, bgr, bgg, bgb}
#endif
#define RColor_NULL      RCOLOR(0x00,         0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
#define RColor_BLACK     RCOLOR(ALPHA_FG,     0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
#define RColor_BGBLACK   RCOLOR(ALPHA_BG,     0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
#define RColor_RED       RCOLOR(ALPHA_FG,     0xff, 0x00, 0x00, 0x00, 0x00, 0x00)
#define RColor_BGRED     RCOLOR(ALPHA_BG,     0xff, 0x00, 0x00, 0x00, 0x00, 0x00)
#define RColor_WHITE     RCOLOR(ALPHA_FG,     0xff, 0xff, 0xff, 0x00, 0x00, 0x00)
#define RColor_BGWHITE   RCOLOR(ALPHA_BG,     0xff, 0xff, 0xff, 0x00, 0x00, 0x00)
#define RColor_GREEN     RCOLOR(ALPHA_FG,     0x00, 0xff, 0x00, 0x00, 0x00, 0x00)
#define RColor_BGGREEN   RCOLOR(ALPHA_BG,     0x00, 0xff, 0x00, 0x00, 0x00, 0x00)
#define RColor_MAGENTA   RCOLOR(ALPHA_FG,     0xff, 0x00, 0xff, 0x00, 0x00, 0x00)
#define RColor_BGMAGENTA RCOLOR(ALPHA_BG,     0xff, 0x00, 0xff, 0x00, 0x00, 0x00)
#define RColor_YELLOW    RCOLOR(ALPHA_FG,     0xff, 0xff, 0x00, 0x00, 0x00, 0x00)
#define RColor_BGYELLOW  RCOLOR(ALPHA_BG,     0xff, 0xff, 0x00, 0x00, 0x00, 0x00)
#define RColor_CYAN      RCOLOR(ALPHA_FG,     0x00, 0xff, 0xff, 0x00, 0x00, 0x00)
#define RColor_BGCYAN    RCOLOR(ALPHA_BG,     0x00, 0xff, 0xff, 0x00, 0x00, 0x00)
#define RColor_BLUE      RCOLOR(ALPHA_FG,     0x00, 0x00, 0xff, 0x00, 0x00, 0x00)
#define RColor_BGBLUE    RCOLOR(ALPHA_BG,     0x00, 0x00, 0xff, 0x00, 0x00, 0x00)
#define RColor_GRAY      RCOLOR(ALPHA_FG,     0x7f, 0x7f, 0x7f, 0x00, 0x00, 0x00)
#define RColor_BGGRAY    RCOLOR(ALPHA_BG,     0x7f, 0x7f, 0x7f, 0x00, 0x00, 0x00)
#define RColor_BBLACK    RCOLOR(ALPHA_BOLD,   0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
#define RColor_BRED      RCOLOR(ALPHA_BOLD,   0xff, 0x00, 0x00, 0x00, 0x00, 0x00)
#define RColor_BGBYELLOW RCOLOR(ALPHA_BG,     0xff, 0xff, 0x00, 0x00, 0x00, 0x00)
#define RColor_BWHITE    RCOLOR(ALPHA_BOLD,   0xff, 0xff, 0xff, 0x00, 0x00, 0x00)
#define RColor_BGREEN    RCOLOR(ALPHA_BOLD,   0x00, 0xff, 0x00, 0x00, 0x00, 0x00)
#define RColor_BMAGENTA  RCOLOR(ALPHA_BOLD,   0xff, 0x00, 0xff, 0x00, 0x00, 0x00)
#define RColor_BYELLOW   RCOLOR(ALPHA_BOLD,   0xff, 0xff, 0x00, 0x00, 0x00, 0x00)
#define RColor_BCYAN     RCOLOR(ALPHA_BOLD,   0x00, 0xff, 0xff, 0x00, 0x00, 0x00)
#define RColor_BBLUE     RCOLOR(ALPHA_BOLD,   0x00, 0x00, 0xff, 0x00, 0x00, 0x00)
#define RColor_BGRAY     RCOLOR(ALPHA_BOLD,   0x7f, 0x7f, 0x7f, 0x00, 0x00, 0x00)

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

/* canvas line colors */
enum {
	LINE_NONE = 0,
	LINE_TRUE,
	LINE_FALSE,
	LINE_UNCJMP,
	LINE_NOSYM_VERT,
	LINE_NOSYM_HORIZ
};

typedef struct r_cons_canvas_line_style_t {
	int color;
	int symbol;
} RCanvasLineStyle;

// UTF-8 symbols indexes
// XXX. merge with RUNE/RUNECODE/RUNECODESTR
#if 0
#define LINE_VERT 0
#define LINE_CROSS 1
#define LINE_HORIZ 2
#define LINE_UP 3
#define CORNER_BR 4
#define CORNER_BL 5
#define CORNER_TL 6
#define CORNER_TR 7
#define ARROW_RIGHT 8
#define ARROW_LEFT 9
#else
#define LINE_VERT 0
#define LINE_CROSS 1
#define LINE_HORIZ 2
#define LINE_UP 3
#define CORNER_TL 6
#define CORNER_BR 4
#define CORNER_BL 5
#define CORNER_TR 6
#define ARROW_RIGHT 8
#define ARROW_LEFT 9
#endif


#ifdef R_API
R_API RConsCanvas* r_cons_canvas_new(int w, int h);
R_API void r_cons_canvas_free(RConsCanvas *c);
R_API void r_cons_canvas_clear(RConsCanvas *c);
R_API void r_cons_canvas_print(RConsCanvas *c);
R_API void r_cons_canvas_print_region(RConsCanvas *c);
R_API char *r_cons_canvas_to_string(RConsCanvas *c);
R_API void r_cons_canvas_attr(RConsCanvas *c,const char * attr);
R_API void r_cons_canvas_write(RConsCanvas *c, const char *_s);
R_API bool r_cons_canvas_gotoxy(RConsCanvas *c, int x, int y);
R_API void r_cons_canvas_goto_write(RConsCanvas *c,int x,int y, const char * s);
R_API void r_cons_canvas_box(RConsCanvas *c, int x, int y, int w, int h, const char *color);
R_API void r_cons_canvas_line(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style);
R_API void r_cons_canvas_line_diagonal(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style);
R_API void r_cons_canvas_line_square(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style);
R_API int r_cons_canvas_resize(RConsCanvas *c, int w, int h);
R_API void r_cons_canvas_fill(RConsCanvas *c, int x, int y, int w, int h, char ch, int replace);
R_API void r_cons_canvas_line_square_defined (RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style, int bendpoint, int isvert);
R_API void r_cons_canvas_line_back_edge (RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style, int ybendpoint1, int xbendpoint, int ybendpoint2, int isvert);

R_API RCons *r_cons_new(void);
R_API RCons *r_cons_singleton(void);
R_API RCons *r_cons_free(void);
R_API char *r_cons_lastline(int *size);

typedef void (*RConsBreak)(void *);
R_API void r_cons_break_end(void);
R_API bool r_cons_is_breaked(void);
R_API void r_cons_break_timeout(int timeout);
R_API void r_cons_breakword(const char *s);

/* pipe */
R_API int r_cons_pipe_open(const char *file, int fdn, int append);
R_API void r_cons_pipe_close(int fd);

#if __WINDOWS__
R_API int r_cons_w32_print(const ut8 *ptr, int len, int empty);
#endif

R_API void r_cons_push(void);
R_API void r_cons_pop(void);
R_API void r_cons_break_pop(void);
R_API void r_cons_break_push(RConsBreak cb, void*user);
R_API void r_cons_break_clear(void);

/* control */
R_API char *r_cons_editor(const char *file, const char *str);
R_API void r_cons_reset(void);
R_API void r_cons_reset_colors(void);
R_API void r_cons_print_clear(void);
R_API void r_cons_zero(void);
R_API void r_cons_highlight(const char *word);
R_API void r_cons_clear(void);
R_API void r_cons_clear00(void);
R_API void r_cons_clear_line(int err);
R_API void r_cons_fill_line(void);
R_API void r_cons_stdout_open(const char *file, int append);
R_API int  r_cons_stdout_set_fd(int fd);
R_API void r_cons_gotoxy(int x, int y);
R_API void r_cons_show_cursor(int cursor);
R_API char *r_cons_swap_ground(const char *col);
R_API bool r_cons_drop(int n);
R_API void r_cons_chop(void);
R_API void r_cons_set_raw(bool b);
R_API void r_cons_set_interactive(bool b);
R_API void r_cons_set_last_interactive(void);

/* output */
R_API void r_cons_printf(const char *format, ...);
R_API void r_cons_printf_list(const char *format, va_list ap);
R_API void r_cons_strcat(const char *str);
#define r_cons_print(x) r_cons_strcat (x)
R_API void r_cons_println(const char* str);
R_API void r_cons_strcat_justify(const char *str, int j, char c);
R_API int r_cons_memcat(const char *str, int len);
R_API void r_cons_newline(void);
R_API void r_cons_filter(void);
R_API void r_cons_flush(void);
R_API int r_cons_less_str(const char *str, const char *exitkeys);
R_API void r_cons_less(void);
R_API void r_cons_2048(bool color);
R_API void r_cons_memset(char ch, int len);
R_API void r_cons_visual_flush(void);
R_API void r_cons_visual_write(char *buffer);
R_API int r_cons_is_utf8(void);
R_API void r_cons_cmd_help(const char * help[], bool use_color);

/* input */
//R_API int  r_cons_fgets(char *buf, int len, int argc, const char **argv);
R_API int r_cons_controlz(int ch);
R_API int r_cons_readchar(void);
R_API bool r_cons_readpush(const char *str, int len);
R_API void r_cons_readflush();
R_API int r_cons_readchar_timeout(ut32 usec);
R_API int r_cons_any_key(const char *msg);
R_API int r_cons_eof(void);

R_API int r_cons_palette_init(const unsigned char *pal);
R_API int r_cons_pal_set(const char *key, const char *val);
R_API void r_cons_pal_update_event(void);
R_API void r_cons_pal_free(void);
R_API void r_cons_pal_init();
R_API char *r_cons_pal_parse(const char *str, RColor *outcol);
R_API void r_cons_pal_random(void);
R_API RColor r_cons_pal_get(const char *key);
R_API RColor r_cons_pal_get_i(int index);
R_API const char *r_cons_pal_get_name(int index);
R_API int r_cons_rgb_parse(const char *p, ut8 *r, ut8 *g, ut8 *b, ut8 *a);
R_API char *r_cons_rgb_tostring(ut8 r, ut8 g, ut8 b);
R_API void r_cons_pal_list(int rad, const char *arg);
R_API void r_cons_pal_show(void);
R_API int r_cons_get_size(int *rows);
R_API bool r_cons_isatty(void);
R_API int r_cons_get_cursor(int *rows);
R_API int r_cons_arrow_to_hjkl(int ch);
R_API char *r_cons_html_filter(const char *ptr, int *newlen);

// TODO: use gets() .. MUST BE DEPRECATED
R_API int r_cons_fgets(char *buf, int len, int argc, const char **argv);
R_API char *r_cons_hud(RList *list, const char *prompt);
R_API char *r_cons_hud_path(const char *path, int dir);
R_API char *r_cons_hud_string(const char *s);
R_API char *r_cons_hud_file(const char *f);

R_API const char *r_cons_get_buffer(void);
R_API void r_cons_grep_help(void);
R_API void r_cons_grep_parsecmd(char *cmd, const char *quotestr);
R_API char * r_cons_grep_strip(char *cmd, const char *quotestr);
R_API void r_cons_grep_process(char * grep);
R_API int r_cons_grep_line(char *buf, int len); // must be static
R_API int r_cons_grepbuf(char *buf, int len);

R_API void r_cons_rgb(ut8 r, ut8 g, ut8 b, ut8 a);
R_API void r_cons_rgb_fgbg(ut8 r, ut8 g, ut8 b, ut8 R, ut8 G, ut8 B);
R_API void r_cons_rgb_init(void);
R_API char *r_cons_rgb_str(char *outstr, RColor *rcolor);
R_API char *r_cons_rgb_str_off(char *outstr, ut64 off);
R_API void r_cons_color(int fg, int r, int g, int b);
R_API RColor r_cons_color_random(ut8 alpha);
R_API void r_cons_invert(int set, int color);
R_API int r_cons_yesno(int def, const char *fmt, ...);
R_API char *r_cons_input(const char *msg);
R_API void r_cons_set_cup(int enable);
R_API void r_cons_column(int c);
R_API int r_cons_get_column(void);
R_API char *r_cons_message(const char *msg);
R_API void r_cons_set_title(const char *str);
R_API bool r_cons_enable_mouse(const bool enable);
R_API void r_cons_bind(RConsBind *bind);
R_API const char* r_cons_get_rune(const ut8 ch);
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
	bool zerosep;
}; /* RLine */

#ifdef R_API

R_API RLine *r_line_new(void);
R_API RLine *r_line_singleton(void);
R_API void r_line_free(void);
R_API char *r_line_get_prompt(void);
R_API void r_line_set_prompt(const char *prompt);
R_API int r_line_dietline_init(void);
R_API void r_line_hist_free(void);

typedef int (RLineReadCallback)(void *user, const char *line);
R_API const char *r_line_readline(void);
R_API const char *r_line_readline_cb(RLineReadCallback cb, void *user);

R_API int r_line_hist_load(const char *file);
R_API int r_line_hist_add(const char *line);
R_API int r_line_hist_save(const char *file);
R_API int r_line_hist_label(const char *label, void (*cb)(const char*));
R_API void r_line_label_show(void);
R_API int r_line_hist_list(void);
R_API const char *r_line_hist_get(int n);

#define R_CONS_INVERT(x,y) (y? (x?Color_INVERT: Color_INVERT_RESET): (x?"[":"]"))

#endif

/* r_agraph */

typedef struct r_ascii_node_t {
	RGraphNode *gnode;
	char *title;
	char *body;

	int x;
	int y;
	int w;
	int h;

	int layer;
	int layer_height;
	int layer_width;
	int pos_in_layer;
	int is_dummy;
	int is_reversed;
	int klass;
	bool is_mini;
} RANode;

#define R_AGRAPH_MODE_NORMAL 0
#define R_AGRAPH_MODE_OFFSET 1
#define R_AGRAPH_MODE_MINI 2
#define R_AGRAPH_MODE_TINY 3
#define R_AGRAPH_MODE_SUMMARY 4
#define R_AGRAPH_MODE_MAX 5

typedef void (*RANodeCallback)(RANode *n, void *user);
typedef void (*RAEdgeCallback)(RANode *from, RANode *to, void *user);

typedef struct r_ascii_graph_t {
	RConsCanvas *can;
	RGraph *graph;
	const RGraphNode *curnode;
	char *title;
	Sdb *db;
	Sdb *nodes; // Sdb with title(key)=RANode*(value)

	int layout;
	int is_instep;
	bool is_tiny;
	bool is_dis;
	int edgemode;
	int mode;
	bool is_callgraph;
	int zoom;
	int movspeed;

	RANode *update_seek_on;
	bool need_reload_nodes;
	bool need_set_layout;
	int need_update_dim;
	int force_update_seek;

	/* events */
	RANodeCallback on_curnode_change;
	void *on_curnode_change_data;

	int x, y;
	int w, h;

	/* layout algorithm info */
	RList *back_edges;
	RList *long_edges;
	struct layer_t *layers;
	int n_layers;
	RList *dists; /* RList<struct dist_t> */
	RList *edges; /* RList<AEdge> */

	/* colors */
	const char *color_box;
	const char *color_box2;
	const char *color_box3;
	const char *color_true;
	const char *color_false;
} RAGraph;

#ifdef R_API
R_API RAGraph *r_agraph_new(RConsCanvas *can);
R_API void r_agraph_free(RAGraph *g);
R_API void r_agraph_reset(RAGraph *g);
R_API void r_agraph_set_title(RAGraph *g, const char *title);
R_API RANode *r_agraph_get_first_node(const RAGraph *g);
R_API RANode *r_agraph_get_node(const RAGraph *g, const char *title);
R_API RANode *r_agraph_add_node(const RAGraph *g, const char *title, const char *body);
R_API bool r_agraph_del_node(const RAGraph *g, const char *title);
R_API void r_agraph_add_edge(const RAGraph *g, RANode *a, RANode *b);
R_API void r_agraph_add_edge_at(const RAGraph *g, RANode *a, RANode *b, int nth);
R_API void r_agraph_del_edge(const RAGraph *g, RANode *a, RANode *b);
R_API void r_agraph_print(RAGraph *g);
R_API Sdb *r_agraph_get_sdb(RAGraph *g);
R_API void r_agraph_foreach(RAGraph *g, RANodeCallback cb, void *user);
R_API void r_agraph_foreach_edge(RAGraph *g, RAEdgeCallback cb, void *user);
R_API void r_agraph_set_curnode(RAGraph *g, RANode *node);
#endif

#ifdef __cplusplus
}
#endif

#endif
