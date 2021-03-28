#ifndef R2_PRINT_H
#define R2_PRINT_H

#include "r_types.h"
#include "r_cons.h"
#include "r_bind.h"
#include "r_io.h"
#include "r_reg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define R_PRINT_FLAGS_COLOR    0x00000001
#define R_PRINT_FLAGS_ADDRMOD  0x00000002
#define R_PRINT_FLAGS_CURSOR   0x00000004
#define R_PRINT_FLAGS_HEADER   0x00000008
#define R_PRINT_FLAGS_SPARSE   0x00000010
#define R_PRINT_FLAGS_SEGOFF   0x00000020
#define R_PRINT_FLAGS_OFFSET   0x00000040
#define R_PRINT_FLAGS_REFS     0x00000080
#define R_PRINT_FLAGS_DIFFOUT  0x00000100 /* only show different rows in `cc` hexdiffing */
#define R_PRINT_FLAGS_ADDRDEC  0x00000200
#define R_PRINT_FLAGS_COMMENT  0x00000400
#define R_PRINT_FLAGS_COMPACT  0x00000800
#define R_PRINT_FLAGS_NONHEX   0x00001000
#define R_PRINT_FLAGS_SECSUB   0x00002000
#define R_PRINT_FLAGS_RAINBOW  0x00004000
#define R_PRINT_FLAGS_HDROFF   0x00008000
#define R_PRINT_FLAGS_STYLE    0x00010000
#define R_PRINT_FLAGS_NONASCII 0x00020000
#define R_PRINT_FLAGS_ALIGN    0x00040000
#define R_PRINT_FLAGS_UNALLOC  0x00080000
#define R_PRINT_FLAGS_BGFILL   0x00100000
#define R_PRINT_FLAGS_SECTION  0x00200000

/*

 1 2   1  8   x  xx  xx  x   xx   x  xx  xx  xx
 3 4   2 16   x   x   x  xx  x   x    x  xx  xx
 5 6   4 32   x  x    x   x   x  xx  x   xx   x
 7 8  1< 2<   x  xx  xx   x  x   xx  x   xx  x

*/

#define $00 1
#define $01 8
#define $10 2
#define $11 16
#define $20 4
#define $21 32
#define $30 (1 << 8)
#define $31 (2 << 8)
#define BRAILE_ONE $00+$01+$11+$21+$31
#define BRAILE_TWO $00+$01+$11+$20+$30+$31
#define BRAILE_TRI $00+$01+$11+$21+$30+$31
#define BRAILE_FUR $00+$10+$11+$21+$31
#define BRAILE_FIV $00+$01+$10+$21+$30
#define BRAILE_SIX $01+$10+$20+$21+$30+$31
#define BRAILE_SEV $00+$01+$11+$20+$30
#define BRAILE_EIG $00+$01+$10+$11+$20+$21+$30+$31
#define BRAILE_NIN $00+$01+$10+$11+$21+$30

typedef struct {
	char str[4];
} RBraile;

R_API RBraile r_print_braile(int u);

typedef int (*RPrintZoomCallback)(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size);
typedef const char *(*RPrintNameCallback)(void *user, ut64 addr);
typedef int (*RPrintSizeCallback)(void *user, ut64 addr);
typedef char *(*RPrintCommentCallback)(void *user, ut64 addr);
typedef const char *(*RPrintSectionGet)(void *user, ut64 addr);
typedef const char *(*RPrintColorFor)(void *user, ut64 addr, bool verbose);
typedef char *(*RPrintHasRefs)(void *user, ut64 addr, int mode);

typedef struct r_print_zoom_t {
	ut8 *buf;
	ut64 from;
	ut64 to;
	int size;
	int mode;
} RPrintZoom;

typedef struct r_print_t {
	void *user;
	RIOBind iob;
	bool pava;
	RCoreBind coreb;
	const char *cfmt;
	char datefmt[32];
	int datezone;
	int (*write)(const unsigned char *buf, int len);
	PrintfCallback cb_printf;
	PrintfCallback cb_eprintf;
	char *(*cb_color)(int idx, int last, bool bg);
	bool scr_prompt;
	int (*disasm)(void *p, ut64 addr);
	PrintfCallback oprintf;
	int big_endian;
	int width;
	int limit;
	int bits;
	bool histblock;
	// true if the cursor is enabled, false otherwise
	bool cur_enabled;
	// offset of the selected byte from the first displayed one
	int cur;
	// offset of the selected byte from the first displayed one, when a
	// range of bytes is selected. -1 is used if no bytes are selected.
	int ocur;
	int cols;
	int flags;
	int seggrn;
	bool use_comments;
	int addrmod;
	int col;
	int stride;
	int bytespace;
	int pairs;
	bool resetbg;
	RPrintZoom *zoom;
	RPrintNameCallback offname;
	RPrintSizeCallback offsize;
	RPrintColorFor colorfor;
	RPrintHasRefs hasrefs;
	RPrintCommentCallback get_comments;
	RPrintSectionGet get_section_name;
	Sdb *formats;
	Sdb *sdb_types;
	RCons *cons;
	RConsBind consbind;
	RNum *num;
	RReg *reg;
	RRegItem* (*get_register)(RReg *reg, const char *name, int type);
	ut64 (*get_register_value)(RReg *reg, RRegItem *item);
	bool (*exists_var)(struct r_print_t *print, ut64 func_addr, char *str);
	ut64* lines_cache;
	int lines_cache_sz;
	int lines_abs;
	bool esc_bslash;
	bool wide_offsets;
	const char *strconv_mode;
	RList *vars;
	char io_unalloc_ch;
	bool show_offset;

	// when true it uses row_offsets
	bool calc_row_offsets;
	// offset of the first byte of each printed row.
	// Last elements is marked with a UT32_MAX.
	ut32 *row_offsets;
	// size of row_offsets
	int row_offsets_sz;
	// when true it makes visual mode flush the buffer to screen
	bool vflush;
	// represents the first not-visible offset on the screen
	// (only when in visual disasm mode)
	ut64 screen_bounds;
	// HACK: Used to temporarily disable the progress bar when it doesn't make sense to have it,
	// eg. when setting the default flag tags on startup. Does not override scr.progressbar.
	bool enable_progressbar;
	RCharset *charset;
} RPrint;

#ifdef R_API

/* RConsBreak handlers */
typedef bool (*RPrintIsInterruptedCallback)();

R_API bool r_print_is_interrupted(void);
R_API void r_print_set_is_interrupted_cb(RPrintIsInterruptedCallback cb);

/* ... */
R_API char *r_print_hexpair(RPrint *p, const char *str, int idx);
R_API void r_print_hex_from_bin(RPrint *p, char *bin_str);
R_API RPrint *r_print_new(void);
R_API RPrint *r_print_free(RPrint *p);
R_API bool r_print_mute(RPrint *p, int x);
R_API void r_print_set_flags(RPrint *p, int _flags);
R_API void r_print_unset_flags(RPrint *p, int flags);
R_API void r_print_addr(RPrint *p, ut64 addr);
R_API void r_print_section(RPrint *p, ut64 at);
R_API void r_print_columns(RPrint *p, const ut8 *buf, int len, int height);
R_API void r_print_hexii(RPrint *p, ut64 addr, const ut8 *buf, int len, int step);
R_API void r_print_hexdump(RPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step, size_t zoomsz);
R_API void r_print_hexdump_simple(const ut8 *buf, int len);
R_API int r_print_jsondump(RPrint *p, const ut8 *buf, int len, int wordsize);
R_API void r_print_hexpairs(RPrint *p, ut64 addr, const ut8 *buf, int len);
R_API void r_print_hexdiff(RPrint *p, ut64 aa, const ut8* a, ut64 ba, const ut8 *b, int len, int scndcol);
R_API void r_print_bytes(RPrint *p, const ut8* buf, int len, const char *fmt);
R_API void r_print_fill(RPrint *p, const ut8 *arr, int size, ut64 addr, int step);
R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch);
R_API const char *r_print_byte_color(RPrint *p, int ch);
R_API void r_print_c(RPrint *p, const ut8 *str, int len);
R_API void r_print_raw(RPrint *p, ut64 addr, const ut8* buf, int len, int offlines);
R_API bool r_print_have_cursor(RPrint *p, int cur, int len);
R_API bool r_print_cursor_pointer(RPrint *p, int cur, int len);
R_API void r_print_cursor(RPrint *p, int cur, int len, int set);
R_API void r_print_cursor_range(RPrint *p, int cur, int to, int set);
R_API int r_print_get_cursor(RPrint *p);
R_API void r_print_set_cursor(RPrint *p, int curset, int ocursor, int cursor);
R_API void r_print_code(RPrint *p, ut64 addr, const ut8 *buf, int len, char lang);
#define SEEFLAG -2
#define JSONOUTPUT -3

/* mode values for r_print_format_* API */
#define R_PRINT_MUSTSEE   (1)      // enable printing of data in specified fmt
#define R_PRINT_ISFIELD   (1 << 1)
#define R_PRINT_SEEFLAGS  (1 << 2)
#define R_PRINT_JSON      (1 << 3)
#define R_PRINT_MUSTSET   (1 << 4)
#define R_PRINT_UNIONMODE (1 << 5)
#define R_PRINT_VALUE     (1 << 6)
#define R_PRINT_DOT       (1 << 7)
#define R_PRINT_QUIET     (1 << 8)
#define R_PRINT_STRUCT    (1 << 9)
R_API int r_print_format_struct_size(RPrint *p, const char *format, int mode, int n);
R_API int r_print_format(RPrint *p, ut64 seek, const ut8* buf, const int len, const char *fmt, int elem, const char *setval, char *field);
R_API const char *r_print_format_byname(RPrint *p, const char *name);
R_API void r_print_offset(RPrint *p, ut64 off, int invert, int opt, int dec, int delta, const char *label);
R_API void r_print_offset_sg(RPrint *p, ut64 off, int invert, int offseg, int seggrn, int offdec, int delta, const char *label);
#define R_PRINT_STRING_WIDE 1
#define R_PRINT_STRING_ZEROEND 2
#define R_PRINT_STRING_URLENCODE 4
#define R_PRINT_STRING_WRAP 8
#define R_PRINT_STRING_WIDE32 16
#define R_PRINT_STRING_ESC_NL 32
R_API int r_print_string(RPrint *p, ut64 seek, const ut8 *str, int len, int options);
R_API int r_print_date_dos(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_hfs(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_w32(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_unix(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_get_now(RPrint *p, char *str);
R_API void r_print_zoom(RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen);
R_API void r_print_zoom_buf(RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen);
R_API void r_print_progressbar(RPrint *pr, int pc, int _cols);
R_API void r_print_progressbar_with_count(RPrint *pr, unsigned int pc, unsigned int total, int _cols, bool reset_line);
R_API void r_print_portionbar(RPrint *p, const ut64 *portions, int n_portions);
R_API void r_print_rangebar(RPrint *p, ut64 startA, ut64 endA, ut64 min, ut64 max, int cols);
R_API char * r_print_randomart(const ut8 *dgst_raw, ut32 dgst_raw_len, ut64 addr);
R_API void r_print_2bpp_row(RPrint *p, ut8 *buf, const char **colors);
R_API void r_print_2bpp_tiles(RPrint *p, ut8 *buf, size_t buflen, ut32 tiles, const char **colors);
R_API char * r_print_colorize_opcode(RPrint *print, char *p, const char *reg, const char *num, bool partial_reset, ut64 func_addr);
R_API const char * r_print_color_op_type(RPrint *p, ut32 anal_type);
R_API void r_print_set_interrupted(int i);
R_API void r_print_init_rowoffsets(RPrint *p);
R_API ut32 r_print_rowoff(RPrint *p, int i);
R_API void r_print_set_rowoff(RPrint *p, int i, ut32 offset, bool overwrite);
R_API int r_print_row_at_off(RPrint *p, ut32 offset);
R_API int r_print_pie(RPrint *p, ut64 *values, int nvalues, int size);

R_API const char* r_print_rowlog(RPrint *print, const char *str);
R_API void r_print_rowlog_done(RPrint *print, const char *str);
R_API void r_print_graphline(RPrint *print, const ut8 *buf, size_t len);

// WIP
R_API int r_print_unpack7bit(const char *src, char *dest);
R_API int r_print_pack7bit(const char *src, char *dest);
R_API char *r_print_stereogram_bytes(const ut8 *buf, int len);
R_API char *r_print_stereogram(const char *bump, int w, int h);
R_API void r_print_stereogram_print(RPrint *p, const char *buf);
R_API void r_print_set_screenbounds(RPrint *p, ut64 addr);
R_API int r_util_lines_getline(ut64 *lines_cache, int lines_cache_sz, ut64 off);
R_API char* r_print_json_indent(const char* s, bool color, const char *tab, const char **colors);
R_API char* r_print_json_human(const char* s);
R_API char* r_print_json_path(const char* s, int pos);

#endif

#ifdef __cplusplus
}
#endif

#endif
