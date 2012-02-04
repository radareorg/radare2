#ifndef _INCLUDE_Z80_H_
#define _INCLUDE_Z80_H_

#include <r_util.h>

int z80asm (unsigned char *outbuf, const char *str);
int z80dis (int addr, const unsigned char *buf, int len, char *out);

#endif
