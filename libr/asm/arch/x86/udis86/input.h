/* -----------------------------------------------------------------------------
 * input.h
 *
 * Copyright (c) 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */
#ifndef UD_INPUT_H
#define UD_INPUT_H

#include "types.h"

uint8_t inp_next(struct ud*);
uint8_t inp_peek(struct ud*);
uint8_t inp_uint8(struct ud*);
uint16_t inp_uint16(struct ud*);
uint32_t inp_uint32(struct ud*);
uint64_t inp_uint64(struct ud*);
void inp_move(struct ud*, size_t);
void inp_back(struct ud*);

/* inp_init() - Initializes the input system. */
#define inp_init(u) \
do { \
  u->inp_curr = 0; \
  u->inp_fill = 0; \
  u->inp_ctr  = 0; \
  u->inp_end  = 0; \
} while (0)

/* inp_start() - Should be called before each de-code operation. */
#define inp_start(u) u->inp_ctr = 0

/* inp_back() - Resets the current pointer to its position before the current
 * instruction disassembly was started.
 */
#define inp_reset(u) \
do { \
  u->inp_curr -= u->inp_ctr; \
  u->inp_ctr = 0; \
} while (0)

/* inp_sess() - Returns the pointer to current session. */
#define inp_sess(u) (u->inp_sess)

/* inp_cur() - Returns the current input byte. */
#define inp_curr(u) ((u)->inp_cache[(u)->inp_curr])

#endif
