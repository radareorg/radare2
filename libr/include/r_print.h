#ifndef R2_PRINT_H
#define R2_PRINT_H

#include "r_types.h"
#include "r_util.h"
#include "r_cons.h"
#include "r_io.h"

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

typedef int (*RPrintZoomCallback)(void *user, int mode, ut64 addr, ut8 *bufz, ut64 size);
typedef const char *(*RPrintNameCallback)(void *user, ut64 addr);
typedef const char *(*RPrintColorFor)(void *user, ut64 addr);

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
	int (*write)(const unsigned char *buf, int len);
	int (*printf)(const char *str, ...);
	int (*disasm)(void *p, ut64 addr);
	int (*oprintf)(const char *str, ...);
	char* (*get_bitfield)(void *user, const char *name, ut64 value);
	char* (*get_enumname)(void *user, const char *name, ut64 value);
	int interrupt;
	int big_endian;
	int width;
	int limit;
	int bits;
	int cur_enabled;
	int cur;
	int cols;
	int ocur;
	int flags;
	int addrmod;
	int col;
	int stride;
	int bytespace;
	int pairs;
	RPrintZoom *zoom;
	RPrintNameCallback offname;
	RPrintColorFor colorfor;
	RPrintColorFor hasrefs;
	RStrHT *formats;
	RCons *cons;
} RPrint;

#ifdef R_API
/* RConsBreak handlers */
R_API int r_print_is_interrupted();
R_API void r_print_set_interrupt(int i);

/* ... */
R_API char *r_print_hexpair(RPrint *p, const char *str, int idx);
R_API RPrint *r_print_new();
R_API RPrint *r_print_free(RPrint *p);
R_API int r_print_mute(RPrint *p, int x);
R_API void r_print_set_flags(RPrint *p, int _flags);
R_API void r_print_unset_flags(RPrint *p, int flags);
R_API void r_print_addr(RPrint *p, ut64 addr);
R_API void r_print_hexdump(RPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step);
R_API void r_print_hexpairs(RPrint *p, ut64 addr, const ut8 *buf, int len);
R_API void r_print_hexdiff(RPrint *p, ut64 aa, const ut8* a, ut64 ba, const ut8 *b, int len, int scndcol);
R_API void r_print_bytes(RPrint *p, const ut8* buf, int len, const char *fmt);
R_API void r_print_fill(RPrint *p, const ut8 *arr, int size);
R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch);
R_API void r_print_c(RPrint *p, const ut8 *str, int len);
R_API void r_print_raw(RPrint *p, const ut8* buf, int len, int offlines);
R_API void r_print_cursor(RPrint *p, int cur, int set);
R_API void r_print_cursor_range(RPrint *p, int cur, int to, int set);
R_API void r_print_set_cursor(RPrint *p, int curset, int ocursor, int cursor);
R_API void r_print_code(RPrint *p, ut64 addr, ut8 *buf, int len, char lang);
#define SEEFLAG -2
#define JSONOUTPUT -3
R_API int r_print_format_struct_size(const char *format, RPrint *p);
R_API int r_print_format(RPrint *p, ut64 seek, const ut8* buf, const int len, const char *fmt, int elem, const char *setval, char *field);
R_API int r_print_format_length (const char *fmt);
R_API void r_print_offset(RPrint *p, ut64 off, int invert, int opt);
#define R_PRINT_STRING_WIDE 1
#define R_PRINT_STRING_ZEROEND 2
#define R_PRINT_STRING_URLENCODE 4
R_API int r_print_string(RPrint *p, ut64 seek, const ut8 *str, int len, int options);
R_API int r_print_date_dos(RPrint *p, ut8 *buf, int len);
R_API int r_print_date_w32(RPrint *p, const ut8 *buf, int len);
R_API int r_print_date_unix(RPrint *p, const ut8 *buf, int len);
R_API void r_print_zoom(RPrint *p, void *user, RPrintZoomCallback cb, ut64 from, ut64 to, int len, int maxlen);
R_API void r_print_progressbar(RPrint *pr, int pc, int _cols);
R_API char * r_print_randomart(const ut8 *dgst_raw, ut32 dgst_raw_len, ut64 addr);
R_API void r_print_2bpp_row(RPrint *p, ut8 *buf);
R_API void r_print_2bpp_tiles(RPrint *p, ut8 *buf, ut32 tiles);
R_API char * r_print_colorize_opcode (char *p, const char *reg, const char *num);
R_API const char * r_print_color_op_type ( RPrint *p, ut64 anal_type);
R_API void r_print_set_interrupted(int i);
// WIP
R_API int r_print_unpack7bit(const char *src, char *dest);
R_API int r_print_pack7bit(const char *src, char *dest);
#endif

#ifdef __cplusplus
}
#endif

#endif
