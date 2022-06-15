#ifndef _8051_ASS_H
#define _8051_ASS_H

#include<r_asm.h>
int assemble_8051(RAnal *a, ut64 pc, char const *user_asm, ut8 *outbuf, int outlen);

#endif
