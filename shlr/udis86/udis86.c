/* udis86 - libudis86/udis86.c
 *
 * Copyright (c) 2002-2013 Vivek Thampi
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

#include "input.h"
#include "extern.h"
#include "decode.h"

#if !defined(__UD_STANDALONE__)
# if HAVE_STRING_H
#  include <string.h>
# endif
#endif /* !__UD_STANDALONE__ */

/* =============================================================================
 * ud_init() - Initializes ud_t object.
 * =============================================================================
 */
extern void 
ud_init(struct ud* u)
{
  memset((void*)u, 0, sizeof(struct ud));
  ud_set_mode(u, 16);
  u->mnemonic = UD_Iinvalid;
  ud_set_pc(u, 0);
#ifndef __UD_STANDALONE__
  ud_set_input_file(u, stdin);
#endif /* __UD_STANDALONE__ */

  ud_set_asm_buffer(u, u->asm_buf_int, sizeof(u->asm_buf_int));
}

/* =============================================================================
 * ud_disassemble() - disassembles one instruction and returns the number of 
 * bytes disassembled. A zero means end of disassembly.
 * =============================================================================
 */
extern unsigned int
ud_disassemble(struct ud* u)
{
  if (ud_input_end(u))
  return 0;

  u->asm_buf[0] = 0;
 
  if (ud_decode(u) == 0)
  return 0;
  if (u->translator)
  u->translator(u);
  return ud_insn_len(u);
}

/* =============================================================================
 * ud_set_mode() - Set Disassemly Mode.
 * =============================================================================
 */
extern void 
ud_set_mode(struct ud* u, uint8_t m)
{
  switch(m) {
  case 16:
  case 32:
  case 64: u->dis_mode = m ; return;
  default: u->dis_mode = 16; return;
  }
}

/* =============================================================================
 * ud_set_vendor() - Set vendor.
 * =============================================================================
 */
extern void 
ud_set_vendor(struct ud* u, unsigned v)
{
  switch(v) {
  case UD_VENDOR_INTEL:
    u->vendor = v;
    break;
  case UD_VENDOR_ANY:
    u->vendor = v;
    break;
  default:
    u->vendor = UD_VENDOR_AMD;
  }
}

/* =============================================================================
 * ud_set_pc() - Sets code origin. 
 * =============================================================================
 */
extern void 
ud_set_pc(struct ud* u, uint64_t o)
{
  u->pc = o;
}

/* =============================================================================
 * ud_set_syntax() - Sets the output syntax.
 * =============================================================================
 */
extern void 
ud_set_syntax(struct ud* u, void (*t)(struct ud*))
{
  u->translator = t;
}

/* =============================================================================
 * ud_insn() - returns the disassembled instruction
 * =============================================================================
 */
const char* 
ud_insn_asm(const struct ud* u) 
{
  return u->asm_buf;
}

/* =============================================================================
 * ud_insn_offset() - Returns the offset.
 * =============================================================================
 */
uint64_t
ud_insn_off(const struct ud* u) 
{
  return u->insn_offset;
}


/* =============================================================================
 * ud_insn_hex() - Returns hex form of disassembled instruction.
 * =============================================================================
 */
const char* 
ud_insn_hex(struct ud* u) 
{
  u->insn_hexcode[0] = 0;
  if (!u->error) {
    unsigned int i;
    unsigned char *src_ptr = inp_sess(u);
    char* src_hex;
    src_hex = (char*) u->insn_hexcode;
    /* for each byte used to decode instruction */
    for (i = 0; i < u->inp_ctr && i < sizeof(u->insn_hexcode) / 2;
         ++i, ++src_ptr) {
      sprintf(src_hex, "%02x", *src_ptr & 0xFF);
      src_hex += 2;
    }
  }
  return u->insn_hexcode;
}


/* =============================================================================
 * ud_insn_ptr() - Returns code disassembled.
 * =============================================================================
 */
extern const uint8_t* 
ud_insn_ptr(const struct ud* u) 
{
  return u->inp_sess;
}

/* =============================================================================
 * ud_insn_len() - Returns the count of bytes disassembled.
 * =============================================================================
 */
extern unsigned int 
ud_insn_len(const struct ud* u) 
{
  return u->inp_ctr;
}


/* =============================================================================
 * ud_insn_get_opr
 *    Return the operand struct representing the nth operand of
 *    the currently disassembled instruction. Returns NULL if
 *    there's no such operand.
 * =============================================================================
 */
const struct ud_operand*
ud_insn_opr(const struct ud *u, unsigned int n)
{
  if (n > 2 || u->operand[n].type == UD_NONE) {
    return NULL; 
  } else {
    return &u->operand[n];
  }
}


/* =============================================================================
 * ud_opr_is_sreg
 *    Returns non-zero if the given operand is of a segment register type.
 * =============================================================================
 */
int
ud_opr_is_sreg(const struct ud_operand *opr)
{
  return opr->type == UD_OP_REG && 
         opr->base >= UD_R_ES   &&
         opr->base <= UD_R_GS;
}


/* =============================================================================
 * ud_opr_is_sreg
 *    Returns non-zero if the given operand is of a general purpose
 *    register type.
 * =============================================================================
 */
int
ud_opr_is_gpr(const struct ud_operand *opr)
{
  return opr->type == UD_OP_REG && 
         opr->base >= UD_R_AL   &&
         opr->base <= UD_R_R15;
}


/* =============================================================================
 * ud_set_user_opaque_data
 * ud_get_user_opaque_data
 *    Get/set user opaqute data pointer
 * =============================================================================
 */
void
ud_set_user_opaque_data(struct ud * u, void* opaque)
{
  u->user_opaque_data = opaque;
}

void*
ud_get_user_opaque_data(const struct ud *u)
{
  return u->user_opaque_data;
}


/* =============================================================================
 * ud_set_asm_buffer
 *    Allow the user to set an assembler output buffer. If `buf` is NULL,
 *    we switch back to the internal buffer.
 * =============================================================================
 */
void
ud_set_asm_buffer(struct ud *u, char *buf, size_t size)
{
  if (buf == NULL) {
    ud_set_asm_buffer(u, u->asm_buf_int, sizeof(u->asm_buf_int));
  } else {
    u->asm_buf = buf;
    u->asm_buf_size = size;
  }
}


/* =============================================================================
 * ud_set_sym_resolver
 *    Set symbol resolver for relative targets used in the translation
 *    phase.
 *
 *    The resolver is a function that takes a uint64_t address and returns a
 *    symbolic name for the that address. The function also takes a second
 *    argument pointing to an integer that the client can optionally set to a
 *    non-zero value for offsetted targets. (symbol+offset) The function may
 *    also return NULL, in which case the translator only prints the target
 *    address.
 *
 *    The function pointer maybe NULL which resets symbol resolution.
 * =============================================================================
 */
void
ud_set_sym_resolver(struct ud *u, const char* (*resolver)(struct ud*, 
                                                          uint64_t addr,
                                                          int64_t *offset))
{
  u->sym_resolver = resolver;
}

/*
vim:set ts=2 sw=2 expandtab
*/
