/* -----------------------------------------------------------------------------
 * udis86.c
 *
 * Copyright (c) 2004, 2005, 2006, Vivek Mohan <vivek@sig9.com>
 * All rights reserved. See LICENSE
 * -----------------------------------------------------------------------------
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "input.h"
#include "extern.h"

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

 
  u->insn_buffer[0] = u->insn_hexcode[0] = 0;

 
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
extern char* 
ud_insn_asm(struct ud* u) 
{
  return u->insn_buffer;
}

/* =============================================================================
 * ud_insn_offset() - Returns the offset.
 * =============================================================================
 */
extern uint64_t
ud_insn_off(struct ud* u) 
{
  return u->insn_offset;
}


/* =============================================================================
 * ud_insn_hex() - Returns hex form of disassembled instruction.
 * =============================================================================
 */
extern char* 
ud_insn_hex(struct ud* u) 
{
  return u->insn_hexcode;
}

/* =============================================================================
 * ud_insn_ptr() - Returns code disassembled.
 * =============================================================================
 */
extern uint8_t* 
ud_insn_ptr(struct ud* u) 
{
  return u->inp_sess;
}

/* =============================================================================
 * ud_insn_len() - Returns the count of bytes disassembled.
 * =============================================================================
 */
extern unsigned int 
ud_insn_len(struct ud* u) 
{
  return u->inp_ctr;
}
