#ifndef _INCLUDE_PRINT_R_
#define _INCLUDE_PRINT_R_

#include "r_types.h"

#define R_PRINT_FLAGS_COLOR   0x00000001
#define R_PRINT_FLAGS_ADDRMOD 0x00000002
#define R_PRINT_FLAGS_CURSOR  0x00000003

void r_print_set_flags(int flags);
void r_print_addr(u64 addr);
void r_print_hexdump(u64 addr, u8 *buf, int len, int step, int columns, int header);
void r_print_bytes(const u8* buf, int len, const char *fmt);
void r_print_raw(const u8* buf, int len);
void r_print_cursor(int cur, int set);
void r_print_set_cursor(int curset, int ocursor, int cursor);
void r_print_code(u64 addr, u8 *buf, int len, int step, int columns, int header);
void r_print_string(u64 addr, u8 *buf, int len, int step, int columns, int header);

#endif
