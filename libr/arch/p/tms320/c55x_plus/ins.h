#ifndef INS_H
#define INS_H

#include <r_types.h>
#include "utils.h"

// instruction length
ut32 get_ins_len(ut8 opcode);

// gets instruction bytes from a position
ut32 get_ins_part(ut32 pos, ut32 len);

#endif
