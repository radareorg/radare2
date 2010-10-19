#ifndef _INCLUDE_PRINT_R_
#define _INCLUDE_PRINT_R_

#include "r_types.h"
#include "r_util.h"

#define R_PRINT_FLAGS_COLOR   0x00000001
#define R_PRINT_FLAGS_ADDRMOD 0x00000002
#define R_PRINT_FLAGS_CURSOR  0x00000004
#define R_PRINT_FLAGS_HEADER  0x00000008

typedef struct r_print_t {
	void *user;
	int (*read_at)(ut64 addr, ut8 *buf, int len, void *user);
	char datefmt[32];
	int (*printf)(const char *str, ...);
	/* TODO: add printf callback */
	int interrupt;
	int bigendian;
	int width;
	int limit;
	int cur_enabled;
	int cur;
	int cols;
	int ocur;
	int flags;
	int addrmod;
} RPrint;

#ifdef R_API
R_API char *r_print_hexpair(RPrint *p, const char *str, int idx);
R_API RPrint *r_print_new();
R_API RPrint *r_print_free(RPrint *p);
R_API void r_print_set_flags(RPrint *p, int _flags);
void r_print_unset_flags(RPrint *p, int flags);
R_API void r_print_set_width(RPrint *p, int width);
R_API void r_print_addr(RPrint *p, ut64 addr);
R_API void r_print_hexdump(RPrint *p, ut64 addr, const ut8 *buf, int len, int base, int step);
R_API void r_print_hexpairs(RPrint *p, ut64 addr, const ut8 *buf, int len);
R_API void r_print_bytes(RPrint *p, const ut8* buf, int len, const char *fmt);
R_API void r_print_byte(RPrint *p, const char *fmt, int idx, ut8 ch);
R_API void r_print_c(RPrint *p, const char *str, int len);
R_API void r_print_raw(RPrint *p, const ut8* buf, int len);
R_API void r_print_cursor(RPrint *p, int cur, int set);
R_API void r_print_set_cursor(RPrint *p, int curset, int ocursor, int cursor);
R_API void r_print_code(RPrint *p, ut64 addr, ut8 *buf, int len);
R_API void r_print_format(RPrint *p, ut64 seek, const ut8* buf, int len, const char *fmt);
// XXX . change wide, zeroend, urlencode for option flags
R_API int r_print_string(RPrint *p, ut64 seek, const ut8 *str, int len, int wide, int zeroend, int urlencode);
R_API int r_print_date_dos(struct r_print_t *p, ut8 *buf, int len);
R_API int r_print_date_w32(struct r_print_t *p, const ut8 *buf, int len);
R_API int r_print_date_unix(struct r_print_t *p, const ut8 *buf, int len);
#endif

#endif
