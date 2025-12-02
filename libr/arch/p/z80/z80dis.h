/* radare - GPL - Copyright 2002-2025 - pancake, condret, unlogic */

#ifndef Z80DIS_H
#define Z80DIS_H

#include <r_types.h>

/* Disassembler functions */
char *z80dis(const ut8 *buf, int len);
void z80_op_size(const ut8 *data, int len, int *size, int *size_prefix);

#endif
