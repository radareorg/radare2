#ifndef C55PLUS_H
#define C55PLUS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <r_types.h>
#include <r_lib.h>

int c55plus_disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len);

#endif
