#ifndef R2_PRINT_H
#define R2_PRINT_H

#include "r_types.h"
#include "r_util.h"
#include "r_cons.h"
#include "r_io.h"
#include "r_reg.h"

#ifdef __cplusplus
extern "C" {
#endif

#define R_PRINT_FLAGS_COLOR   0x00000001
#define R_PRINT_FLAGS_ADDRMOD 0x00000002
#define R_PRINT_FLAGS_CURSOR  0x00000004
#define R_PRINT_FLAGS_HEADER  0x00000008
#define R_PRINT_FLAGS_SPARSE  0x00000010
#define R_PRINT_FLAGS_SEGOFF  0x00000020
#define R_PRINT_FLAGS_OFFSET  0x00000040
#define R_PRINT_FLAGS_REFS    0x00000080
#define R_PRINT_FLAGS_DIFFOUT 0x00000100 /* only show different rows in `cc` hexdiffing */
#define R_PRINT_FLAGS_ADDRDEC 0x00000200
#define R_PRINT_FLAGS_COMMENT 0x00000400
#define R_PRINT_FLAGS_COMPACT 0x00000800
#define R_PRINT_FLAGS_NONHEX  0x00001000
#define R_PRINT_FLAGS_SECSUB  0x00002000
#define R_PRINT_FLAGS_RAINBOW 0x00004000

typedef int (*RPrintZoomCallback)(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size);
typedef const char *(*RPrintNameCallback)(void *user, ut64 addr);
typedef char *(*RPrintCommentCallback)(void *user, ut64 addr);
typedef const char *(*RPrintColorFor)(void *user, ut64 addr, bool verbose);

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
	char datefmt[32];
	int datezone;
	int (*write)(const unsigned char *buf, int len);
	void (*cb_printf)(const char *str, ...);
	char *(*cb_color)(int idx, int last, bool bg);
	int (*disasm)(void *p, ut64 addr);
	void (*oprintf)(const char *str, ...);
	char* (*get_bitfield)(void *user, const char *name, ut64 value);
	char* (*get_enumname)(void *user, const char *name, ut64 value);
	int interrupt;
	int big_endian;
	int width;
	int limit;
	int bits;
	// true if the cursor is enabled, false otherwise
	bool cur_enabled;
	// offset of the selected byte from the first displayed one
	int cur;
	// offset of the selected byte from the first displayed one, when a
	// range of bytes is selected. -1 is used if no bytes are selected.
	int ocur;
	int cols;
	int flags;
	bool use_comments;
	int addrmod;
	int col;
	int stride;
	int bytespace;
	int pairs;
	RPrintZoom *zoom;
	RPrintNameCallback offname;
	RPrintColorFor colorfor;
	RPrintColorFor hasrefs;
	RPrintCommentCallback get_comments;
	Sdb *formats;
	RCons *cons;
	RConsBind consbind;
	RNum *num;
	RReg *reg;
	RRegItem* (*get_register)(RReg *reg, const char *name, int type);
	ut64 (*get_register_value)(RReg *reg, RRegItem *item);
	ut64* lines_cache;
	int lines_cache_sz;
	int lines_abs;
	bool esc_bslash;
	const char *strconv_mode;

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
} RPrint;

#ifdef R_API
/* RConsBreak handlers */
R_API int r_print_is_interrupted(void);
R_API void r_print_set_interrupt(int i);

/* ... */
R_API char *r_print_hexpair(RPrint *p, const char *str, int idx);
R_API void r_print_hex_from_bin (RPrint *p, char *bin_str);
R_API RPrint *r_print_new(void);
R_API RPrint *r_print_free(RPrint *p);
R_API bool r_print_mute(RPrint *p, int x);
R_API void r_print_set_flags(RPrint *p, int _flags);
R_API void r_print_unset_flags(RPrint *p, int flags);
R_API void r_print_addr(RPrint *p, ut64 addr);
R_API void r_print_columns (RPrint *p, const ut8 *buf, int len, int height);
R_API void r_print_hexii(RPrint *p, ut64 addr, const ut8 *buf, int len, int step);
R_API void r_print_hexdump(RPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step, int zoomsz);
R_API int r_print_jsondump(RPrint *p, const ut8 *buf, int len, int wordsize);
R_API void r_print_hexpairs(RPrint *p, ut64 addr, const ut8 *buf, int len);
R_API void r_print_hexdiff(RPrint *p, ut64 aa, const ut8* a, ut64 ba, const ut8 *b, int len, int scndcol);
R_API void r_print_bytes(RPrint *p, const ut8* buf, int len, const char *fmt);
R_API void r_print_fill(RPrint *p, const ut8 *arr, int size, ut64 addr, int step);
R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch);
R_API void r_print_c(RPrint *p, const ut8 *str, int len);
R_API void r_print_raw(RPrint *p, ut64 addr, const ut8* buf, int len, int offlines);
R_API void r_print_cursor(RPrint *p, int cur, int set);
R_API void r_print_cursor_range(RPrint *p, int cur, int to, int set);
R_API int r_print_get_cursor(RPrint *p);
R_API void r_print_set_cursor(RPrint *p, int curset, int ocursor, int cursor);
R_API void r_print_code(RPrint *p, ut64 addr, ut8 *buf, int len, char lang);
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
R_API int r_print_format_struct_size(const char *format, RPrint *p, int mode, int n);
R_API int r_print_format(RPrint *p, ut64 seek, const ut8* buf, const int len, const char *fmt, int elem, const char *setval, char *field);
R_API int r_print_format_length(const char *fmt);
R_API void r_print_offset(RPrint *p, ut64 off, int invert, int opt, int dec, int delta, const char *label);
#define R_PRINT_STRING_WIDE 1
#define R_PRINT_STRING_ZEROEND 2
#define R_PRINT_STRING_URLENCODE 4
#define R_PRINT_STRING_WRAP 8
#define R_PRINT_STRING_WIDE32 16
R_API int r_print_string(RPrint *p, ut64 seek, const ut8 *str, int len, int options);
R_API int r_print_date_dos(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_hfs(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_w32(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_unix(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_get_now(RPrint *p, char *str);
R_API void r_print_zoom(RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen);
R_API void r_print_progressbar(RPrint *pr, int pc, int _cols);
R_API void r_print_portionbar(RPrint *p, const ut64 *portions, int n_portions);
R_API void r_print_rangebar(RPrint *p, ut64 startA, ut64 endA, ut64 min, ut64 max, int cols);
R_API char * r_print_randomart(const ut8 *dgst_raw, ut32 dgst_raw_len, ut64 addr);
R_API void r_print_2bpp_row(RPrint *p, ut8 *buf);
R_API void r_print_2bpp_tiles(RPrint *p, ut8 *buf, ut32 tiles);
R_API char * r_print_colorize_opcode(RPrint *print, char *p, const char *reg, const char *num, bool partial_reset);
R_API const char * r_print_color_op_type(RPrint *p, ut64 anal_type);
R_API void r_print_set_interrupted(int i);
R_API void r_print_init_rowoffsets(RPrint *p);
R_API ut32 r_print_rowoff(RPrint *p, int i);
R_API void r_print_set_rowoff(RPrint *p, int i, ut32 offset, bool overwrite);
R_API int r_print_row_at_off(RPrint *p, ut32 offset);
// WIP
R_API int r_print_unpack7bit(const char *src, char *dest);
R_API int r_print_pack7bit(const char *src, char *dest);
R_API char *r_print_stereogram_bytes(const ut8 *buf, int len);
R_API char *r_print_stereogram(const char *bump, int w, int h);
R_API void r_print_stereogram_print(RPrint *p, const char *buf);
R_API void r_print_set_screenbounds(RPrint *p, ut64 addr);
R_API int r_util_lines_getline(ut64 *lines_cache, int lines_cache_sz, ut64 off);
R_API char* r_print_json_indent(const char* s, bool color, const char *tab, const char **colors);
R_API char* r_print_json_path(const char* s, int pos);

#endif

#ifdef __cplusplus
}
#endif

#endif
