#ifndef R2_CONS_H
#define R2_CONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <r_types.h>
#include <r_util/pj.h>
#include <r_util/r_graph.h>
#include <r_util/r_hex.h>
#include <r_util/r_log.h>
#include <r_util/r_num.h>
#include <r_util/r_panels.h>
#include <r_util/r_sandbox.h>
#include <r_util/r_signal.h>
#include <r_util/r_stack.h>
#include <r_util/r_str.h>
#include <r_util/r_str_constpool.h>
#include <r_util/r_sys.h>
#include <r_util/r_file.h>
#include <r_vector.h>
#include <sdb.h>
#include <ht_up.h>

#include <stdio.h>
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
#include <winuser.h>
# ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
# define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
# endif
# ifndef ENABLE_VIRTUAL_TERMINAL_INPUT
# define ENABLE_VIRTUAL_TERMINAL_INPUT 0x0200
# endif
#else
#include <unistd.h>
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
#define R_CONS_GREP_TOKENS 64

R_LIB_VERSION_HEADER(r_cons);

#define R_CONS_CMD_DEPTH 100

typedef int (*RConsGetSize)(int *rows);
typedef int (*RConsGetCursor)(int *rows);
typedef bool (*RConsIsBreaked)(void);
typedef void (*RConsFlush)(void);
typedef void (*RConsGrepCallback)(const char *grep);

typedef struct r_cons_bind_t {
	RConsGetSize get_size;
	RConsGetCursor get_cursor;
	PrintfCallback cb_printf;
	RConsIsBreaked is_breaked;
	RConsFlush cb_flush;
	RConsGrepCallback cb_grep;
} RConsBind;

typedef struct r_cons_grep_t {
	char strings[R_CONS_GREP_WORDS][R_CONS_GREP_WORD_SIZE];
	int nstrings;
	char *str;
	int counter;
	bool charCounter;
	int less;
	bool hud;
	bool human;
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
	int zoom;
	int zoomy; // if set then its scaled unproportionally
	int neg;
	int begin;
	int end;
	int icase;
} RConsGrep;

enum { ALPHA_RESET = 0x00, ALPHA_FG = 0x01, ALPHA_BG = 0x02, ALPHA_FGBG = 0x03 };
enum { R_CONS_ATTR_BOLD = 1u << 1,
       R_CONS_ATTR_DIM = 1u << 2,
       R_CONS_ATTR_ITALIC = 1u << 3,
       R_CONS_ATTR_UNDERLINE = 1u << 4,
       R_CONS_ATTR_BLINK = 1u << 5
};

typedef struct rcolor_t {
	// bold, italic, underline, ...
	ut8 attr;
	ut8 a;
	ut8 r;
	ut8 g;
	ut8 b;
	ut8 r2; // Background color
	ut8 g2; // Only used when a &= ALPHA_FGBG
	ut8 b2;
	st8 id16; // Mapping to 16-color table
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
	RColor ucall;
	RColor ujmp;
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
	RColor wordhl;
	RColor linehl;
	RColor func_var;
	RColor func_var_type;
	RColor func_var_addr;
	RColor widget_bg;
	RColor widget_sel;

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
        RColor graph_diff_match;
        RColor graph_diff_unmatch;
        RColor graph_diff_unknown;
        RColor graph_diff_new;
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
	char *ucall;
	char *ujmp;
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
	char *wordhl;
	char *linehl;
	char *func_var;
	char *func_var_type;
	char *func_var_addr;
	char *widget_bg;
	char *widget_sel;

	/* graph colors */
	char *graph_box;
	char *graph_box2;
	char *graph_box3;
	char *graph_box4;
	char *graph_diff_match;
	char *graph_diff_unmatch;
	char *graph_diff_unknown;
	char *graph_diff_new;
	char *graph_true;
	char *graph_false;
	char *graph_trufae;
	char *graph_traced;
	char *graph_current;
	char **rainbow; // rainbow
	int rainbow_sz; // size of rainbow
} RConsPrintablePalette;

typedef void (*RConsEvent)(void *);

#define CONS_MAX_ATTR_SZ 16

typedef struct r_cons_canvas_t {
	int w;
	int h;
	int x;
	int y;
	char **b;
	int *blen;
	int *bsize;
	const char *attr; //The current attr (inserted on each write)
	HtUP *attrs; // all the different attributes <key: unsigned int loc, const char *attr>
	RStrConstPool constpool; // Pool for non-compile-time attrs
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
#define RUNE_LONG_LINE_HORIZ "―"
#define R_UTF8_CIRCLE "\u25EF"
#define R_UTF8_BLOCK "\u2588"

// Emoji
#define R_UTF8_POLICE_CARS_REVOLVING_LIGHT "🚨"
#define R_UTF8_WHITE_HEAVY_CHECK_MARK "✅"
#define R_UTF8_SEE_NO_EVIL_MONKEY "🙈"
#define R_UTF8_SKULL_AND_CROSSBONES "☠"
#define R_UTF8_KEYBOARD "⌨"
#define R_UTF8_LEFT_POINTING_MAGNIFYING_GLASS "🔍"
#define R_UTF8_DOOR "🚪"

// Variation Selectors
#define R_UTF8_VS16 "\xef\xb8\x8f"

typedef char *(*RConsEditorCallback)(void *core, const char *file, const char *str);
typedef int (*RConsClickCallback)(void *core, int x, int y);
typedef void (*RConsBreakCallback)(void *core);
typedef void *(*RConsSleepBeginCallback)(void *core);
typedef void (*RConsSleepEndCallback)(void *core, void *user);
typedef void (*RConsQueueTaskOneshot)(void *core, void *task, void *user);
typedef void (*RConsFunctionKey)(void *core, int fkey);

typedef enum { COLOR_MODE_DISABLED = 0, COLOR_MODE_16, COLOR_MODE_256, COLOR_MODE_16M } RConsColorMode;

typedef struct r_cons_context_t {
	RConsGrep grep;
	RStack *cons_stack;
	char *buffer; // TODO: replace with RStrBuf
	size_t buffer_len;
	size_t buffer_sz;
	RStrBuf *error; // r_cons_eprintf / r_cons_errstr / r_cons_errmode
	int errmode;
	bool breaked;
	RStack *break_stack;
	RConsEvent event_interrupt;
	void *event_interrupt_data;
	int cmd_depth;

	// Used for per-task logging redirection
	RLogCallback log_callback; // TODO: RList of callbacks

	char *lastOutput;
	int lastLength;
	bool lastMode;
	bool lastEnabled;
	bool is_interactive;
	bool pageable;

	int color_mode;
	RConsPalette cpal;
	RConsPrintablePalette pal;
} RConsContext;

#define HUD_BUF_SIZE 512

typedef struct {
	int x;
	int y;
} RConsCursorPos;

typedef struct r_cons_t {
	RConsContext *context;
	char *lastline;
	bool is_html;
	bool was_html;
	int lines;
	int rows;
	int echo; // dump to stdout in realtime
	int fps;
	int columns;
	int force_rows;
	int force_columns;
	int fix_rows;
	int fix_columns;
	bool break_lines;
	int noflush;
	bool show_autocomplete_widget;
	FILE *fdin; // FILE? and then int ??
	int fdout; // only used in pipe.c :?? remove?
	const char *teefile;
	int (*user_fgets)(char *buf, int len);
	RConsEvent event_resize;
	void *event_data;
	int mouse_event;

	RConsEditorCallback cb_editor;
	RConsBreakCallback cb_break;
	RConsSleepBeginCallback cb_sleep_begin;
	RConsSleepEndCallback cb_sleep_end;
	RConsClickCallback cb_click;
	RConsQueueTaskOneshot cb_task_oneshot;
	RConsFunctionKey cb_fkey;

	void *user; // Used by <RCore*>
#if __UNIX__
	struct termios term_raw, term_buf;
#elif __WINDOWS__
	DWORD term_raw, term_buf, term_xterm;
	UINT old_cp;
#endif
	RNum *num;
	/* Pager (like more or less) to use if the output doesn't fit on the
	 * current window. If NULL or "" no pager is used. */
	char *pager;
	int blankline;
	char *highlight;
	bool enable_highlight;
	int null; // if set, does not show anything
	int mouse;
	int is_wine;
	struct r_line_t *line;
	const char **vline;
	int refcnt;
	R_DEPRECATE bool newline;
	int vtmode;
	bool flush;
	bool use_utf8; // use utf8 features
	bool use_utf8_curvy; // use utf8 curved corners
	bool dotted_lines;
	int linesleep;
	int pagesize;
	char *break_word;
	int break_word_len;
	ut64 timeout; // must come from r_time_now_mono()
	bool grep_color;
	bool grep_highlight;
	bool use_tts;
	bool filter;
	char* (*rgbstr)(char *str, size_t sz, ut64 addr);
	bool click_set;
	int click_x;
	int click_y;
	bool show_vals;		// show which section in Vv
	// TODO: move into instance? + avoid unnecessary copies
	RConsCursorPos cpos;
} RCons;

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

#define R_CONS_CLEAR_LINE "\x1b[2K\r"
#define R_CONS_CLEAR_SCREEN "\x1b[2J\r"
#define R_CONS_CLEAR_FROM_CURSOR_TO_END "\x1b[0J\r"

#define R_CONS_CURSOR_SAVE "\x1b[s"
#define R_CONS_CURSOR_RESTORE "\x1b[u"
#define R_CONS_GET_CURSOR_POSITION "\x1b[6n"
#define R_CONS_CURSOR_UP "\x1b[A"
#define R_CONS_CURSOR_DOWN "\x1b[B"
#define R_CONS_CURSOR_RIGHT "\x1b[C"
#define R_CONS_CURSOR_LEFT "\x1b[D"

#define Color_BLINK        "\x1b[5m"
#define Color_INVERT       "\x1b[7m"
#define Color_INVERT_RESET "\x1b[27m"
     /* See 'man 4 console_codes' for details:
      * "ESC c"        -- Reset
      * "ESC ( K"      -- Select user mapping
      * "ESC [ 0 m"    -- Reset all display attributes
      * "ESC [ J"      -- Erase to the end of screen
      * "ESC [ ? 25 h" -- Make cursor visible
      */
#define Color_RESET_TERMINAL  "\x1b" "c\x1b(K\x1b[0m\x1b[J\x1b[?25h"
#define Color_RESET      "\x1b[0m" /* reset all */
#define Color_RESET_NOBG "\x1b[27;22;24;25;28;39m"  /* Reset everything except background (order is important) */
#define Color_RESET_BG   "\x1b[49m"
#define Color_RESET_ALL  "\x1b[0m\x1b[49m"
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
#define Color_GRAY       "\x1b[90m"
#define Color_BGGRAY     "\x1b[100m"
/* bright colors */
#define Color_BBLACK     Color_GRAY
#define Color_BBGBLACK   Color_BGGRAY
#define Color_BRED       "\x1b[91m"
#define Color_BBGRED     "\x1b[101m"
#define Color_BWHITE     "\x1b[97m"
#define Color_BBGWHITE   "\x1b[107m"
#define Color_BGREEN     "\x1b[92m"
#define Color_BBGGREEN   "\x1b[102m"
#define Color_BMAGENTA   "\x1b[95m"
#define Color_BBGMAGENTA "\x1b[105m"
#define Color_BYELLOW    "\x1b[93m"
#define Color_BBGYELLOW  "\x1b[103m"
#define Color_BCYAN      "\x1b[96m"
#define Color_BBGCYAN    "\x1b[106m"
#define Color_BBLUE      "\x1b[94m"
#define Color_BBGBLUE    "\x1b[104m"

#ifdef _MSC_VER
#define RCOLOR(a, r, g, b, bgr, bgg, bgb, id16) {0, a, r, g, b, bgr, bgg, bgb, id16}
#else
#define RCOLOR(a, r, g, b, bgr, bgg, bgb, id16) (RColor) {0, a, r, g, b, bgr, bgg, bgb, id16}
#endif
#define RColor_NULL       RCOLOR(0x00,     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -1)
#if __WINDOWS__
#define RColor_BLACK      RCOLOR(ALPHA_FG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0)
#define RColor_BGBLACK    RCOLOR(ALPHA_BG, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  0)
#define RColor_RED        RCOLOR(ALPHA_FG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,  1)
#define RColor_BGRED      RCOLOR(ALPHA_BG, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00,  1)
#define RColor_WHITE      RCOLOR(ALPHA_FG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00,  7)
#define RColor_BGWHITE    RCOLOR(ALPHA_BG, 0xc0, 0xc0, 0xc0, 0x00, 0x00, 0x00,  7)
#define RColor_GREEN      RCOLOR(ALPHA_FG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,  2)
#define RColor_BGGREEN    RCOLOR(ALPHA_BG, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,  2)
#define RColor_MAGENTA    RCOLOR(ALPHA_FG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00,  5)
#define RColor_BGMAGENTA  RCOLOR(ALPHA_BG, 0x80, 0x00, 0x80, 0x00, 0x00, 0x00,  5)
#define RColor_YELLOW     RCOLOR(ALPHA_FG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00,  3)
#define RColor_BGYELLOW   RCOLOR(ALPHA_BG, 0x80, 0x80, 0x00, 0x00, 0x00, 0x00,  3)
#define RColor_CYAN       RCOLOR(ALPHA_FG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00,  6)
#define RColor_BGCYAN     RCOLOR(ALPHA_BG, 0x00, 0x80, 0x80, 0x00, 0x00, 0x00,  6)
#define RColor_BLUE       RCOLOR(ALPHA_FG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,  4)
#define RColor_BGBLUE     RCOLOR(ALPHA_BG, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00,  4)
#define RColor_BBLACK     RCOLOR(ALPHA_FG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00,  8)
#define RColor_BBGBLACK   RCOLOR(ALPHA_BG, 0x80, 0x80, 0x80, 0x00, 0x00, 0x00,  8)
#define RColor_BRED       RCOLOR(ALPHA_FG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,  9)
#define RColor_BBGRED     RCOLOR(ALPHA_BG, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00,  9)
#define RColor_BWHITE     RCOLOR(ALPHA_FG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RColor_BBGWHITE   RCOLOR(ALPHA_BG, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 15)
#define RColor_BGREEN     RCOLOR(ALPHA_FG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RColor_BBGGREEN   RCOLOR(ALPHA_BG, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 10)
#define RColor_BMAGENTA   RCOLOR(ALPHA_FG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RColor_BBGMAGENTA RCOLOR(ALPHA_BG, 0xff, 0x00, 0xff, 0x00, 0x00, 0x00, 13)
#define RColor_BYELLOW    RCOLOR(ALPHA_FG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RColor_BBGYELLOW  RCOLOR(ALPHA_BG, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 11)
#define RColor_BCYAN      RCOLOR(ALPHA_FG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RColor_BBGCYAN    RCOLOR(ALPHA_BG, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 14)
#define RColor_BBLUE      RCOLOR(ALPHA_FG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#define RColor_BBGBLUE    RCOLOR(ALPHA_BG, 0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 12)
#else
// Campbell (https://devblogs.microsoft.com/commandline/updating-the-windows-console-colors/).
// Not used on Windows since cmd.exe doesn't support bold (needed for easier
// differentiation between normal and bright color text for some colors).
#define RColor_BLACK      RCOLOR(ALPHA_FG,  12,  12,  12, 0x00, 0x00, 0x00,  0)
#define RColor_BGBLACK    RCOLOR(ALPHA_BG,  12,  12,  12, 0x00, 0x00, 0x00,  0)
#define RColor_RED        RCOLOR(ALPHA_FG, 197,  15,  31, 0x00, 0x00, 0x00,  1)
#define RColor_BGRED      RCOLOR(ALPHA_BG, 197,  15,  31, 0x00, 0x00, 0x00,  1)
#define RColor_WHITE      RCOLOR(ALPHA_FG, 204, 204, 204, 0x00, 0x00, 0x00,  7)
#define RColor_BGWHITE    RCOLOR(ALPHA_BG, 204, 204, 204, 0x00, 0x00, 0x00,  7)
#define RColor_GREEN      RCOLOR(ALPHA_FG,  19, 161,  14, 0x00, 0x00, 0x00,  2)
#define RColor_BGGREEN    RCOLOR(ALPHA_BG,  19, 161,  14, 0x00, 0x00, 0x00,  2)
#define RColor_MAGENTA    RCOLOR(ALPHA_FG, 136,  23, 152, 0x00, 0x00, 0x00,  5)
#define RColor_BGMAGENTA  RCOLOR(ALPHA_BG, 136,  23, 152, 0x00, 0x00, 0x00,  5)
#define RColor_YELLOW     RCOLOR(ALPHA_FG, 193, 156,   0, 0x00, 0x00, 0x00,  3)
#define RColor_BGYELLOW   RCOLOR(ALPHA_BG, 193, 156,   0, 0x00, 0x00, 0x00,  3)
#define RColor_CYAN       RCOLOR(ALPHA_FG,  58, 150, 221, 0x00, 0x00, 0x00,  6)
#define RColor_BGCYAN     RCOLOR(ALPHA_BG,  58, 150, 221, 0x00, 0x00, 0x00,  6)
#define RColor_BLUE       RCOLOR(ALPHA_FG,   0,  55, 218, 0x00, 0x00, 0x00,  4)
#define RColor_BGBLUE     RCOLOR(ALPHA_BG,   0,  55, 218, 0x00, 0x00, 0x00,  4)
#define RColor_BBLACK     RCOLOR(ALPHA_FG, 118, 118, 118, 0x00, 0x00, 0x00,  8)
#define RColor_BBGBLACK   RCOLOR(ALPHA_BG, 118, 118, 118, 0x00, 0x00, 0x00,  8)
#define RColor_BRED       RCOLOR(ALPHA_FG, 231,  72,  86, 0x00, 0x00, 0x00,  9)
#define RColor_BBGRED     RCOLOR(ALPHA_BG, 231,  72,  86, 0x00, 0x00, 0x00,  9)
#define RColor_BWHITE     RCOLOR(ALPHA_FG, 242, 242, 242, 0x00, 0x00, 0x00, 15)
#define RColor_BBGWHITE   RCOLOR(ALPHA_BG, 242, 242, 242, 0x00, 0x00, 0x00, 15)
#define RColor_BGREEN     RCOLOR(ALPHA_FG,  22, 198,  12, 0x00, 0x00, 0x00, 10)
#define RColor_BBGGREEN   RCOLOR(ALPHA_BG,  22, 198,  12, 0x00, 0x00, 0x00, 10)
#define RColor_BMAGENTA   RCOLOR(ALPHA_FG, 180,   0, 158, 0x00, 0x00, 0x00, 13)
#define RColor_BBGMAGENTA RCOLOR(ALPHA_BG, 180,   0, 158, 0x00, 0x00, 0x00, 13)
#define RColor_BYELLOW    RCOLOR(ALPHA_FG, 249, 241, 165, 0x00, 0x00, 0x00, 11)
#define RColor_BBGYELLOW  RCOLOR(ALPHA_BG, 249, 241, 165, 0x00, 0x00, 0x00, 11)
#define RColor_BCYAN      RCOLOR(ALPHA_FG,  97, 214, 214, 0x00, 0x00, 0x00, 14)
#define RColor_BBGCYAN    RCOLOR(ALPHA_BG,  97, 214, 214, 0x00, 0x00, 0x00, 14)
#define RColor_BBLUE      RCOLOR(ALPHA_FG,  59, 120, 255, 0x00, 0x00, 0x00, 12)
#define RColor_BBGBLUE    RCOLOR(ALPHA_BG,  59, 120, 255, 0x00, 0x00, 0x00, 12)
#endif
#define RColor_GRAY       RColor_BBLACK
#define RColor_BGGRAY     RColor_BBGBLACK

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

typedef enum {
	INSERT_MODE = 'i',
	CONTROL_MODE = 'c'
} RViMode;

#define DOT_STYLE_NORMAL 0
#define DOT_STYLE_CONDITIONAL 1
#define DOT_STYLE_BACKEDGE 2

typedef struct r_cons_canvas_line_style_t {
	int color;
	int symbol;
	int dot_style;
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
R_API void r_cons_image(const ut8 *buf, int bufsz, int width, int mode);
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
R_API void r_cons_canvas_circle(RConsCanvas *c, int x, int y, int w, int h, const char *color);
R_API void r_cons_canvas_line(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style);
R_API void r_cons_canvas_line_diagonal(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style);
R_API void r_cons_canvas_line_square(RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style);
R_API int r_cons_canvas_resize(RConsCanvas *c, int w, int h);
R_API void r_cons_canvas_fill(RConsCanvas *c, int x, int y, int w, int h, char ch);
R_API void r_cons_canvas_line_square_defined (RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style, int bendpoint, int isvert);
R_API void r_cons_canvas_line_back_edge (RConsCanvas *c, int x, int y, int x2, int y2, RCanvasLineStyle *style, int ybendpoint1, int xbendpoint, int ybendpoint2, int isvert);
R_API RCons *r_cons_new(void);
R_API RCons *r_cons_singleton(void);
R_API RCons *r_cons_free(void);
R_API char *r_cons_lastline(int *size);
R_API char *r_cons_lastline_utf8_ansi_len(int *len);
R_API void r_cons_set_click(int x, int y);
R_API bool r_cons_get_click(int *x, int *y);

typedef void (*RConsBreak)(void *);
R_API bool r_cons_is_breaked(void);
R_API bool r_cons_is_interactive(void);
R_API bool r_cons_default_context_is_interactive(void);
R_API void *r_cons_sleep_begin(void);
R_API void r_cons_sleep_end(void *user);

/* ^C */
R_API void r_cons_break_push(RConsBreak cb, void *user);
R_API void r_cons_break_pop(void);
R_API void r_cons_break_clear(void);
R_API void r_cons_breakword(const char *s);
R_API void r_cons_break_end(void);
R_API void r_cons_break_timeout(int timeout);

/* pipe */
R_API int r_cons_pipe_open(const char *file, int fdn, int append);
R_API void r_cons_pipe_close(int fd);

#if __WINDOWS__
R_API int r_cons_is_vtcompat(void);
R_API void r_cons_w32_clear(void);
R_API void r_cons_w32_gotoxy(int fd, int x, int y);
R_API int r_cons_w32_print(const char *ptr, int len, bool vmode);
R_API int r_cons_win_printf(bool vmode, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
R_API int r_cons_win_eprintf(bool vmode, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
R_API int r_cons_win_vhprintf(DWORD hdl, bool vmode, const char *fmt, va_list ap);
#endif

#if 0

Flush Print Buffer
  0     0     0     null
  0     0     1     quiet
  0     1     0     echo
  0     1     1     buffer
  1     0     1     flush

#endif

enum {
	R_CONS_ERRMODE_NULL,   // no buffer no print = null
	R_CONS_ERRMODE_QUIET,  // buffer no print = quiet
	R_CONS_ERRMODE_ECHO,   // no buffer, print = like eprintf()
	R_CONS_ERRMODE_BUFFER, // no buffer, print = like eprintf()
	R_CONS_ERRMODE_FLUSH,  // no buffer, print = like eprintf + log
};

R_API void r_cons_push(void);
R_API void r_cons_pop(void);
R_API RConsContext *r_cons_context_new(R_NULLABLE RConsContext *parent);
R_API void r_cons_context_free(RConsContext *context);
R_API void r_cons_context_load(RConsContext *context);
R_API void r_cons_context_reset(void);
R_API bool r_cons_context_is_main(void);
R_API void r_cons_context_break(RConsContext *context);
R_API void r_cons_context_break_push(RConsContext *context, RConsBreak cb, void *user, bool sig);
R_API void r_cons_context_break_pop(RConsContext *context, bool sig);

/* control */
R_API char *r_cons_editor(const char *file, const char *str);
R_API void r_cons_reset(void);
R_API void r_cons_reset_colors(void);
R_API char *r_cons_errstr(void);
R_API void r_cons_errmode(int mode);
R_API void r_cons_errmodes(const char *mode);
R_API int r_cons_eprintf(const char *format, ...);
R_API void r_cons_eflush(void);
R_API void r_cons_print_clear(void);
R_API void r_cons_echo(const char *msg);
R_API void r_cons_zero(void);
R_API void r_cons_highlight(const char *word);
R_API void r_cons_clear(void);
R_API void r_cons_clear_buffer(void);
R_API void r_cons_clear00(void);
R_API void r_cons_clear_line(int err);
R_API void r_cons_fill_line(void);
R_API void r_cons_stdout_open(const char *file, int append);
R_API int  r_cons_stdout_set_fd(int fd);
R_API void r_cons_gotoxy(int x, int y);
R_API int r_cons_get_cur_line(void);
R_API void r_cons_line(int x, int y, int x2, int y2, int ch);
R_API void r_cons_show_cursor(int cursor);
R_API char *r_cons_swap_ground(const char *col);
R_API bool r_cons_drop(int n);
R_API void r_cons_chop(void);
R_API void r_cons_set_raw(bool b);
R_API void r_cons_set_interactive(bool b);
R_API void r_cons_set_last_interactive(void);
R_API void r_cons_set_utf8(bool b);
R_API void r_cons_grep(const char *grep);

/* output */
R_API int r_cons_printf(const char *format, ...) R_PRINTF_CHECK(1, 2);
R_API void r_cons_printf_list(const char *format, va_list ap);
R_API void r_cons_strcat(const char *str);
R_API void r_cons_strcat_at(const char *str, int x, char y, int w, int h);
#define r_cons_print(x) r_cons_strcat (x)
R_API void r_cons_println(const char* str);

R_API void r_cons_strcat_justify(const char *str, int j, char c);
R_API void r_cons_printat(const char *str, int x, char y);
R_API int r_cons_memcat(const char *str, int len);
R_API void r_cons_newline(void);
R_API void r_cons_filter(void);
R_API void r_cons_flush(void);
R_API void r_cons_print_fps (int col);
R_API void r_cons_last(void);
R_API int r_cons_less_str(const char *str, const char *exitkeys);
R_API void r_cons_less(void);
R_API void r_cons_2048(bool color);
R_API void r_cons_memset(char ch, int len);
R_API void r_cons_visual_flush(void);
R_API void r_cons_visual_write(char *buffer);
R_API bool r_cons_is_utf8(void);
R_API void r_cons_cmd_help(const char * help[], bool use_color);
R_API void r_cons_log_stub(const char *output, const char *funcname, const char *filename,
 unsigned int lineno, unsigned int level, const char *tag, const char *fmtstr, ...) R_PRINTF_CHECK(7, 8);


/* input */
R_API int r_cons_controlz(int ch);
R_API int r_cons_readchar(void);
R_API bool r_cons_readpush(const char *str, int len);
R_API void r_cons_readflush(void);
R_API void r_cons_switchbuf(bool active);
R_API int r_cons_readchar_timeout(ut32 usec);
R_API int r_cons_any_key(const char *msg);
R_API int r_cons_eof(void);

R_API int r_cons_palette_init(const unsigned char *pal);
R_API int r_cons_pal_set(const char *key, const char *val);
R_API void r_cons_pal_update_event(void);
R_API void r_cons_pal_free(RConsContext *ctx);
R_API void r_cons_pal_init(RConsContext *ctx);
R_API void r_cons_pal_copy(RConsContext *dst, RConsContext *src);
R_API char *r_cons_pal_parse(const char *str, RColor *outcol);
R_API void r_cons_pal_random(void);
R_API RColor r_cons_pal_get(const char *key);
R_API RColor r_cons_pal_get_i(int index);
R_API const char *r_cons_pal_get_name(int index);
R_API int r_cons_pal_len(void);
R_API int r_cons_rgb_parse(const char *p, ut8 *r, ut8 *g, ut8 *b, ut8 *a);
R_API char *r_cons_rgb_tostring(ut8 r, ut8 g, ut8 b);
R_API void r_cons_pal_list(int rad, const char *arg);
R_API void r_cons_pal_show(void);
R_API int r_cons_get_size(int *rows);
R_API bool r_cons_isatty(void);
R_API int r_cons_get_cursor(int *rows);
R_API int r_cons_arrow_to_hjkl(int ch);
R_API char *r_cons_html_filter(const char *ptr, int *newlen);
R_API char *r_cons_rainbow_get(int idx, int last, bool bg);
R_API void r_cons_rainbow_free(RConsContext *ctx);
R_API void r_cons_rainbow_new(RConsContext *ctx, int sz);

R_API int r_cons_fgets(char *buf, int len, int argc, const char **argv);
R_API char *r_cons_hud(RList *list, const char *prompt);
R_API char *r_cons_hud_path(const char *path, int dir);
R_API char *r_cons_hud_string(const char *s);
R_API char *r_cons_hud_file(const char *f);

R_API const char *r_cons_get_buffer(void);
R_API int r_cons_get_buffer_len(void);
R_API void r_cons_grep_help(void);
R_API void r_cons_grep_parsecmd(char *cmd, const char *quotestr);
R_API char * r_cons_grep_strip(char *cmd, const char *quotestr);
R_API void r_cons_grep_process(char * grep);
R_API int r_cons_grep_line(char *buf, int len); // must be static
R_API void r_cons_grepbuf(void);

R_API void r_cons_rgb(ut8 r, ut8 g, ut8 b, ut8 a);
R_API void r_cons_rgb_fgbg(ut8 r, ut8 g, ut8 b, ut8 R, ut8 G, ut8 B);
R_API void r_cons_rgb_init(void);
R_API char *r_cons_rgb_str_mode(RConsColorMode mode, char *outstr, size_t sz, RColor *rcolor);
R_API char *r_cons_rgb_str(char *outstr, size_t sz, RColor *rcolor);
R_API char *r_cons_rgb_str_off(char *outstr, size_t sz, ut64 off);
R_API void r_cons_color(int fg, int r, int g, int b);

R_API RColor r_cons_color_random(ut8 alpha);
R_API void r_cons_invert(int set, int color);
R_API bool r_cons_yesno(int def, const char *fmt, ...) R_PRINTF_CHECK(2, 3);
R_API char *r_cons_input(const char *msg);
R_API char *r_cons_password(const char *msg);
R_API bool r_cons_set_cup(bool enable);
R_API void r_cons_column(int c);
R_API int r_cons_get_column(void);
R_API char *r_cons_message(const char *msg);
R_API void r_cons_set_title(const char *str);
R_API bool r_cons_enable_mouse(const bool enable);
R_API void r_cons_enable_highlight(const bool enable);
R_API void r_cons_bind(RConsBind *bind);
R_API const char* r_cons_get_rune(const ut8 ch);
#endif

/* r_line */
#define R_LINE_BUFSIZE 4096
#define R_LINE_HISTSIZE 256

#define R_EDGES_X_INC 4

#define R_SELWIDGET_MAXH 15
#define R_SELWIDGET_MAXW 30
#define R_SELWIDGET_DIR_UP 0
#define R_SELWIDGET_DIR_DOWN 1

typedef struct r_selection_widget_t {
	const char **options;
	int options_len;
	int selection;
	int w, h;
	int scroll;
	bool complete_common;
	bool direction;
} RSelWidget;

typedef struct r_line_hist_t {
	char **data;
	char *match;
	int size;
	int index;
	int top;
	int autosave;
	bool do_setup_match;
} RLineHistory;

typedef struct r_line_buffer_t {
	char data[R_LINE_BUFSIZE];
	int index;
	int length;
} RLineBuffer;

typedef struct r_hud_t {
	int current_entry_n;
	int top_entry_n;
	char activate;
	int vi;
} RLineHud;

typedef struct r_line_t RLine; // forward declaration
typedef struct r_line_comp_t RLineCompletion;

typedef enum { R_LINE_PROMPT_DEFAULT, R_LINE_PROMPT_OFFSET, R_LINE_PROMPT_FILE } RLinePromptType;

typedef int (*RLineCompletionCb)(RLineCompletion *completion, RLineBuffer *buf, RLinePromptType prompt_type, void *user);

struct r_line_comp_t {
	bool opt;
	size_t args_limit;
	bool quit;
	RPVector args; /* <char *> */
	RLineCompletionCb run;
	void *run_user;
};

typedef char* (*RLineEditorCb)(void *core, const char *str);
typedef int (*RLineHistoryUpCb)(RLine* line);
typedef int (*RLineHistoryDownCb)(RLine* line);

struct r_line_t {
	RLineCompletion completion;
	RLineBuffer buffer;
	RLineHistory history;
	RSelWidget *sel_widget;
	/* callbacks */
	RLineHistoryUpCb cb_history_up;
	RLineHistoryDownCb cb_history_down;
	RLineEditorCb cb_editor;
	// RLineFunctionKeyCb cb_fkey;
	RConsFunctionKey cb_fkey;
	/* state , TODO: use more bool */
	int echo;
	int has_echo;
	char *prompt;
	RList/*<str>*/ *kill_ring;
	int kill_ring_ptr;
	char *clipboard;
	int disable;
	void *user;
	int (*hist_up)(void *user);
	int (*hist_down)(void *user);
	char *contents;
	bool zerosep;
	bool enable_vi_mode;
	int vi_mode;
	bool prompt_mode;
	RLinePromptType prompt_type;
	int offset_hist_index;
	int file_hist_index;
	RLineHud *hud;
	RList *sdbshell_hist;
	RListIter *sdbshell_hist_iter;
	int vtmode;
}; /* RLine */

#ifdef R_API

R_API RLine *r_line_new(void);
R_API RLine *r_line_singleton(void);
R_API void r_line_free(void);
R_API char *r_line_get_prompt(void);
R_API void r_line_set_prompt(const char *prompt);
R_API int r_line_dietline_init(void);
R_API void r_line_clipboard_push (const char *str);
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

R_API int r_line_set_hist_callback(RLine *line, RLineHistoryUpCb cb_up, RLineHistoryDownCb cb_down);
R_API int r_line_hist_cmd_up(RLine *line);
R_API int r_line_hist_cmd_down(RLine *line);

R_API void r_line_completion_init(RLineCompletion *completion, size_t args_limit);
R_API void r_line_completion_fini(RLineCompletion *completion);
R_API void r_line_completion_push(RLineCompletion *completion, const char *str);
R_API void r_line_completion_set(RLineCompletion *completion, int argc, const char **argv);
R_API void r_line_completion_clear(RLineCompletion *completion);

#define R_CONS_INVERT(x,y) (y? (x?Color_INVERT: Color_INVERT_RESET): (x?"[":"]"))

#endif

typedef int (*RPanelsMenuCallback)(void *user);
typedef struct r_panels_menu_item {
	int n_sub, selectedIndex;
	char *name;
	struct r_panels_menu_item **sub;
	RPanelsMenuCallback cb;
	RPanel *p;
} RPanelsMenuItem;

typedef struct r_panels_menu_t {
	RPanelsMenuItem *root;
	RPanelsMenuItem **history;
	int depth;
	int n_refresh;
	RPanel **refreshPanels;
} RPanelsMenu;

typedef enum {
	PANEL_MODE_DEFAULT,
	PANEL_MODE_MENU,
	PANEL_MODE_ZOOM,
	PANEL_MODE_WINDOW,
	PANEL_MODE_HELP
} RPanelsMode;

typedef enum {
	PANEL_FUN_SNOW,
	PANEL_FUN_SAKURA,
	PANEL_FUN_NOFUN
} RPanelsFun;

typedef enum {
	PANEL_LAYOUT_DEFAULT_STATIC = 0,
	PANEL_LAYOUT_DEFAULT_DYNAMIC = 1
} RPanelsLayout;

typedef struct {
	int x;
	int y;
} RPanelsSnow;

typedef struct {
	RStrBuf *data;
	RPanelPos pos;
	int idx;
	int offset;
} RModal;

typedef struct r_panels_t {
	RConsCanvas *can;
	RPanel **panel;
	int n_panels;
	int columnWidth;
	int curnode;
	int mouse_orig_x;
	int mouse_orig_y;
	bool autoUpdate;
	bool mouse_on_edge_x;
	bool mouse_on_edge_y;
	RPanelsMenu *panels_menu;
	Sdb *db;
	Sdb *rotate_db;
	Sdb *modal_db;
	HtPP *mht;
	RPanelsMode mode;
	RPanelsFun fun;
	RPanelsMode prevMode;
	RPanelsLayout layout;
	RList *snows;
	char *name;
} RPanels;

typedef enum {
	DEFAULT,
	ROTATE,
	DEL,
	QUIT,
} RPanelsRootState;

typedef struct r_panels_root_t {
	int n_panels;
	int cur_panels;
	Sdb *pdc_caches;
	Sdb *cur_pdc_cache;
	RPanels **panels;
	RPanelsRootState root_state;
} RPanelsRoot;


#ifdef __sun
static inline void cfmakeraw(struct termios *tm) {
	tm->c_cflag &= ~(CSIZE | PARENB);
	tm->c_cflag |= CS8;
	tm->c_iflag &= ~(IMAXBEL | IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
	tm->c_oflag &= ~OPOST;
	tm->c_lflag &= ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
}
#endif

#ifdef __cplusplus
}
#endif
#endif
