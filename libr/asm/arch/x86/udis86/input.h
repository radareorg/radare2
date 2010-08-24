/* udis86 - libudis86/input.h
 *
 * Copyright (c) 2002-2009 Vivek Thampi
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without modification, 
 * are permitted provided that the following conditions are met:
 * 
 *     * Redistributions of source code must retain the above copyright notice, 
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, 
 *       this list of conditions and the following disclaimer in the documentation 
 *       and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND 
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED 
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR 
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES 
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; 
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON 
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
