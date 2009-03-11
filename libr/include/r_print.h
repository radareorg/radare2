#ifndef _INCLUDE_PRINT_R_
#define _INCLUDE_PRINT_R_

#include "r_types.h"

#define R_PRINT_FLAGS_COLOR   0x00000001
#define R_PRINT_FLAGS_ADDRMOD 0x00000002
#define R_PRINT_FLAGS_CURSOR  0x00000004
#define R_PRINT_FLAGS_HEADER  0x00000008

struct r_print_t {
	void *user;
	int (*read_at)(u64 addr, u8 *buf, int len, void *user);
	/* TODO: add printf callback */
	int width;
	int cur_enabled;
	int cur;
	int ocur;
	int flags;
	int addrmod;
};

struct r_print_t *r_print_new();
struct r_print_t *r_print_free(struct r_print_t *p);
void r_print_set_flags(struct r_print_t *p, int _flags);
void r_print_set_width(struct r_print_t *p, int width);
void r_print_addr(struct r_print_t *p, u64 addr);
void r_print_hexdump(struct r_print_t *p, u64 addr, u8 *buf, int len, int step);
void r_print_bytes(struct r_print_t *p, const u8* buf, int len, const char *fmt);
void r_print_raw(struct r_print_t *p, const u8* buf, int len);
void r_print_cursor(struct r_print_t *p, int cur, int set);
void r_print_set_cursor(struct r_print_t *p, int curset, int ocursor, int cursor);
void r_print_code(struct r_print_t *p, u64 addr, u8 *buf, int len);
void r_print_string(struct r_print_t *p, u64 addr, u8 *buf, int len);
void r_print_format(struct r_print_t *p, u64 seek, const u8* buf, int len, const char *fmt);

#endif
