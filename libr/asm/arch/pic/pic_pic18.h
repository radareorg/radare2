/* radare2 - LGPL - Copyright 2015-2018 - oddcoder, thestr4ng3r */

#ifndef PIC_PIC18_H
#define PIC_PIC18_H

#include <r_asm.h>

int pic_pic18_disassemble(RAsmOp *op, char *opbuf, const ut8 *b, int l);

#endif //PIC_PIC18_H
