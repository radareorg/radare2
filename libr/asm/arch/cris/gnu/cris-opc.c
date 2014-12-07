/* cris-opc.c -- Table of opcodes for the CRIS processor.
   Copyright 2000, 2001, 2004, 2007 Free Software Foundation, Inc.
   Contributed by Axis Communications AB, Lund, Sweden.
   Originally written for GAS 1.38.1 by Mikael Asker.
   Reorganized by Hans-Peter Nilsson.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "opcode/cris.h"

#ifndef NULL
#define NULL (0)
#endif

/* This table isn't used for CRISv32 and the size of immediate operands.  */
const struct cris_spec_reg
cris_spec_regs[] =
{
  {"bz",  0,  1, cris_ver_v32p,	   NULL},
  {"p0",  0,  1, 0,		   NULL},
  {"vr",  1,  1, 0,		   NULL},
  {"p1",  1,  1, 0,		   NULL},
  {"pid", 2,  1, cris_ver_v32p,    NULL},
  {"p2",  2,  1, cris_ver_v32p,	   NULL},
  {"p2",  2,  1, cris_ver_warning, NULL},
  {"srs", 3,  1, cris_ver_v32p,    NULL},
  {"p3",  3,  1, cris_ver_v32p,	   NULL},
  {"p3",  3,  1, cris_ver_warning, NULL},
  {"wz",  4,  2, cris_ver_v32p,	   NULL},
  {"p4",  4,  2, 0,		   NULL},
  {"ccr", 5,  2, cris_ver_v0_10,   NULL},
  {"exs", 5,  4, cris_ver_v32p,	   NULL},
  {"p5",  5,  2, cris_ver_v0_10,   NULL},
  {"p5",  5,  4, cris_ver_v32p,	   NULL},
  {"dcr0",6,  2, cris_ver_v0_3,	   NULL},
  {"eda", 6,  4, cris_ver_v32p,	   NULL},
  {"p6",  6,  2, cris_ver_v0_3,	   NULL},
  {"p6",  6,  4, cris_ver_v32p,	   NULL},
  {"dcr1/mof", 7, 4, cris_ver_v10p,
   "Register `dcr1/mof' with ambiguous size specified.  Guessing 4 bytes"},
  {"dcr1/mof", 7, 2, cris_ver_v0_3,
   "Register `dcr1/mof' with ambiguous size specified.  Guessing 2 bytes"},
  {"mof", 7,  4, cris_ver_v10p,	   NULL},
  {"dcr1",7,  2, cris_ver_v0_3,	   NULL},
  {"p7",  7,  4, cris_ver_v10p,	   NULL},
  {"p7",  7,  2, cris_ver_v0_3,	   NULL},
  {"dz",  8,  4, cris_ver_v32p,	   NULL},
  {"p8",  8,  4, 0,		   NULL},
  {"ibr", 9,  4, cris_ver_v0_10,   NULL},
  {"ebp", 9,  4, cris_ver_v32p,	   NULL},
  {"p9",  9,  4, 0,		   NULL},
  {"irp", 10, 4, cris_ver_v0_10,   NULL},
  {"erp", 10, 4, cris_ver_v32p,	   NULL},
  {"p10", 10, 4, 0,		   NULL},
  {"srp", 11, 4, 0,		   NULL},
  {"p11", 11, 4, 0,		   NULL},
  /* For disassembly use only.  Accept at assembly with a warning.  */
  {"bar/dtp0", 12, 4, cris_ver_warning,
   "Ambiguous register `bar/dtp0' specified"},
  {"nrp", 12, 4, cris_ver_v32p,	   NULL},
  {"bar", 12, 4, cris_ver_v8_10,   NULL},
  {"dtp0",12, 4, cris_ver_v0_3,	   NULL},
  {"p12", 12, 4, 0,		   NULL},
  /* For disassembly use only.  Accept at assembly with a warning.  */
  {"dccr/dtp1",13, 4, cris_ver_warning,
   "Ambiguous register `dccr/dtp1' specified"},
  {"ccs", 13, 4, cris_ver_v32p,	   NULL},
  {"dccr",13, 4, cris_ver_v8_10,   NULL},
  {"dtp1",13, 4, cris_ver_v0_3,	   NULL},
  {"p13", 13, 4, 0,		   NULL},
  {"brp", 14, 4, cris_ver_v3_10,   NULL},
  {"usp", 14, 4, cris_ver_v32p,	   NULL},
  {"p14", 14, 4, cris_ver_v3p,	   NULL},
  {"usp", 15, 4, cris_ver_v10,	   NULL},
  {"spc", 15, 4, cris_ver_v32p,	   NULL},
  {"p15", 15, 4, cris_ver_v10p,	   NULL},
  {NULL, 0, 0, cris_ver_version_all, NULL}
};

/* Add version specifiers to this table when necessary.
   The (now) regular coding of register names suggests a simpler
   implementation.  */
const struct cris_support_reg cris_support_regs[] =
{
  {"s0", 0},
  {"s1", 1},
  {"s2", 2},
  {"s3", 3},
  {"s4", 4},
  {"s5", 5},
  {"s6", 6},
  {"s7", 7},
  {"s8", 8},
  {"s9", 9},
  {"s10", 10},
  {"s11", 11},
  {"s12", 12},
  {"s13", 13},
  {"s14", 14},
  {"s15", 15},
  {NULL, 0}
};

/* All CRIS opcodes are 16 bits.

   - The match component is a mask saying which bits must match a
     particular opcode in order for an instruction to be an instance
     of that opcode.

   - The args component is a string containing characters symbolically
     matching the operands of an instruction.  Used for both assembly
     and disassembly.

     Operand-matching characters:
     [ ] , space
        Verbatim.
     A	The string "ACR" (case-insensitive).
     B	Not really an operand.  It causes a "BDAP -size,SP" prefix to be
	output for the PUSH alias-instructions and recognizes a push-
	prefix at disassembly.  This letter isn't recognized for v32.
	Must be followed by a R or P letter.
     !	Non-match pattern, will not match if there's a prefix insn.
     b	Non-matching operand, used for branches with 16-bit
	displacement. Only recognized by the disassembler.
     c	5-bit unsigned immediate in bits <4:0>.
     C	4-bit unsigned immediate in bits <3:0>.
     d  At assembly, optionally (as in put other cases before this one)
	".d" or ".D" at the start of the operands, followed by one space
	character.  At disassembly, nothing.
     D	General register in bits <15:12> and <3:0>.
     f	List of flags in bits <15:12> and <3:0>.
     i	6-bit signed immediate in bits <5:0>.
     I	6-bit unsigned immediate in bits <5:0>.
     M	Size modifier (B, W or D) for CLEAR instructions.
     m	Size modifier (B, W or D) in bits <5:4>
     N  A 32-bit dword, like in the difference between s and y.
        This has no effect on bits in the opcode.  Can also be expressed
	as "[pc+]" in input.
     n  As N, but PC-relative (to the start of the instruction).
     o	[-128..127] word offset in bits <7:1> and <0>.  Used by 8-bit
	branch instructions.
     O	[-128..127] offset in bits <7:0>.  Also matches a comma and a
	general register after the expression, in bits <15:12>.  Used
	only for the BDAP prefix insn (in v32 the ADDOQ insn; same opcode).
     P	Special register in bits <15:12>.
     p	Indicates that the insn is a prefix insn.  Must be first
	character.
     Q  As O, but don't relax; force an 8-bit offset.
     R	General register in bits <15:12>.
     r	General register in bits <3:0>.
     S	Source operand in bit <10> and a prefix; a 3-operand prefix
	without side-effect.
     s	Source operand in bits <10> and <3:0>, optionally with a
	side-effect prefix, except [pc] (the name, not R15 as in ACR)
	isn't allowed for v32 and higher.
     T  Support register in bits <15:12>.
     u  4-bit (PC-relative) unsigned immediate word offset in bits <3:0>.
     U  Relaxes to either u or n, instruction is assumed LAPCQ or LAPC.
	Not recognized at disassembly.
     x	Register-dot-modifier, for example "r5.w" in bits <15:12> and <5:4>.
     y	Like 's' but do not allow an integer at assembly.
     Y	The difference s-y; only an integer is allowed.
     z	Size modifier (B or W) in bit <4>.  */


/* Please note the order of the opcodes in this table is significant.
   The assembler requires that all instances of the same mnemonic must
   be consecutive.  If they aren't, the assembler might not recognize
   them, or may indicate an internal error.

   The disassembler should not normally care about the order of the
   opcodes, but will prefer an earlier alternative if the "match-score"
   (see cris-dis.c) is computed as equal.

   It should not be significant for proper execution that this table is
   in alphabetical order, but please follow that convention for an easy
   overview.  */

const struct cris_opcode
cris_opcodes[] =
{
  {"abs",     0x06B0, 0x0940,		  "r,R",     0, SIZE_NONE,     0,
   cris_abs_op},

  {"add",     0x0600, 0x09c0,		  "m r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  {"add",     0x0A00, 0x01c0,		  "m s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"add",     0x0A00, 0x01c0,		  "m S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"add",     0x0a00, 0x05c0,		  "m S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_add_sub_cmp_and_or_op},

  {"add",     0x0A00, 0x01c0,		  "m s,R",   0, SIZE_FIELD,
   cris_ver_v32p,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"addc",    0x0570, 0x0A80,		  "r,R",     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"addc",    0x09A0, 0x0250,		  "s,R",     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"addi",    0x0540, 0x0A80,		  "x,r,A",   0, SIZE_NONE,
   cris_ver_v32p,
   cris_addi_op},

  {"addi",    0x0500, 0x0Ac0,		  "x,r",     0, SIZE_NONE,     0,
   cris_addi_op},

  /* This collates after "addo", but we want to disassemble as "addoq",
     not "addo".  */
  {"addoq",   0x0100, 0x0E00,		  "Q,A",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"addo",    0x0940, 0x0280,		  "m s,R,A", 0, SIZE_FIELD_SIGNED,
   cris_ver_v32p,
   cris_not_implemented_op},

  /* This must be located after the insn above, lest we misinterpret
     "addo.b -1,r0,acr" as "addo .b-1,r0,acr".  FIXME: Sounds like a
     parser bug.  */
  {"addo",   0x0100, 0x0E00,		  "O,A",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"addq",    0x0200, 0x0Dc0,		  "I,R",     0, SIZE_NONE,     0,
   cris_quick_mode_add_sub_op},

  {"adds",    0x0420, 0x0Bc0,		  "z r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  /* FIXME: SIZE_FIELD_SIGNED and all necessary changes.  */
  {"adds",    0x0820, 0x03c0,		  "z s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"adds",    0x0820, 0x03c0,		  "z S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"adds",    0x0820, 0x07c0,		  "z S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_add_sub_cmp_and_or_op},

  {"addu",    0x0400, 0x0be0,		  "z r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  /* FIXME: SIZE_FIELD_UNSIGNED and all necessary changes.  */
  {"addu",    0x0800, 0x03e0,		  "z s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"addu",    0x0800, 0x03e0,		  "z S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"addu",    0x0800, 0x07e0,		  "z S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_add_sub_cmp_and_or_op},

  {"and",     0x0700, 0x08C0,		  "m r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  {"and",     0x0B00, 0x00C0,		  "m s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"and",     0x0B00, 0x00C0,		  "m S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"and",     0x0B00, 0x04C0,		  "m S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_add_sub_cmp_and_or_op},

  {"andq",    0x0300, 0x0CC0,		  "i,R",     0, SIZE_NONE,     0,
   cris_quick_mode_and_cmp_move_or_op},

  {"asr",     0x0780, 0x0840,		  "m r,R",   0, SIZE_NONE,     0,
   cris_asr_op},

  {"asrq",    0x03a0, 0x0c40,		  "c,R",     0, SIZE_NONE,     0,
   cris_asrq_op},

  {"ax",      0x15B0, 0xEA4F,		  "",	     0, SIZE_NONE,     0,
   cris_ax_ei_setf_op},

  /* FIXME: Should use branch #defines.  */
  {"b",	      0x0dff, 0x0200,		  "b",	     1, SIZE_NONE,     0,
   cris_sixteen_bit_offset_branch_op},

  {"ba",
   BA_QUICK_OPCODE,
   0x0F00+(0xF-CC_A)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  /* Needs to come after the usual "ba o", which might be relaxed to
     this one.  */
  {"ba",     BA_DWORD_OPCODE,
   0xffff & (~BA_DWORD_OPCODE),		  "n",	     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_none_reg_mode_jump_op},

  {"bas",     0x0EBF, 0x0140,		  "n,P",     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_none_reg_mode_jump_op},

  {"basc",     0x0EFF, 0x0100,		  "n,P",     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_none_reg_mode_jump_op},

  {"bcc",
   BRANCH_QUICK_OPCODE+CC_CC*0x1000,
   0x0f00+(0xF-CC_CC)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bcs",
   BRANCH_QUICK_OPCODE+CC_CS*0x1000,
   0x0f00+(0xF-CC_CS)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bdap",
   BDAP_INDIR_OPCODE, BDAP_INDIR_Z_BITS,  "pm s,R",  0, SIZE_FIELD_SIGNED,
   cris_ver_v0_10,
   cris_bdap_prefix},

  {"bdap",
   BDAP_QUICK_OPCODE, BDAP_QUICK_Z_BITS,  "pO",	     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_quick_mode_bdap_prefix},

  {"beq",
   BRANCH_QUICK_OPCODE+CC_EQ*0x1000,
   0x0f00+(0xF-CC_EQ)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  /* This is deliberately put before "bext" to trump it, even though not
     in alphabetical order, since we don't do excluding version checks
     for v0..v10.  */
  {"bwf",
   BRANCH_QUICK_OPCODE+CC_EXT*0x1000,
   0x0f00+(0xF-CC_EXT)*0x1000,		  "o",	     1, SIZE_NONE,
   cris_ver_v10,
   cris_eight_bit_offset_branch_op},

  {"bext",
   BRANCH_QUICK_OPCODE+CC_EXT*0x1000,
   0x0f00+(0xF-CC_EXT)*0x1000,		  "o",	     1, SIZE_NONE,
   cris_ver_v0_3,
   cris_eight_bit_offset_branch_op},

  {"bge",
   BRANCH_QUICK_OPCODE+CC_GE*0x1000,
   0x0f00+(0xF-CC_GE)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bgt",
   BRANCH_QUICK_OPCODE+CC_GT*0x1000,
   0x0f00+(0xF-CC_GT)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bhi",
   BRANCH_QUICK_OPCODE+CC_HI*0x1000,
   0x0f00+(0xF-CC_HI)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bhs",
   BRANCH_QUICK_OPCODE+CC_HS*0x1000,
   0x0f00+(0xF-CC_HS)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"biap", BIAP_OPCODE, BIAP_Z_BITS,	  "pm r,R",  0, SIZE_NONE,
   cris_ver_v0_10,
   cris_biap_prefix},

  {"ble",
   BRANCH_QUICK_OPCODE+CC_LE*0x1000,
   0x0f00+(0xF-CC_LE)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"blo",
   BRANCH_QUICK_OPCODE+CC_LO*0x1000,
   0x0f00+(0xF-CC_LO)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bls",
   BRANCH_QUICK_OPCODE+CC_LS*0x1000,
   0x0f00+(0xF-CC_LS)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"blt",
   BRANCH_QUICK_OPCODE+CC_LT*0x1000,
   0x0f00+(0xF-CC_LT)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bmi",
   BRANCH_QUICK_OPCODE+CC_MI*0x1000,
   0x0f00+(0xF-CC_MI)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bmod",    0x0ab0, 0x0140,		  "s,R",     0, SIZE_FIX_32,
   cris_ver_sim_v0_10,
   cris_not_implemented_op},

  {"bmod",    0x0ab0, 0x0140,		  "S,D",     0, SIZE_NONE,
   cris_ver_sim_v0_10,
   cris_not_implemented_op},

  {"bmod",    0x0ab0, 0x0540,		  "S,R,r",   0, SIZE_NONE,
   cris_ver_sim_v0_10,
   cris_not_implemented_op},

  {"bne",
   BRANCH_QUICK_OPCODE+CC_NE*0x1000,
   0x0f00+(0xF-CC_NE)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bound",   0x05c0, 0x0A00,		  "m r,R",   0, SIZE_NONE,     0,
   cris_two_operand_bound_op},
  /* FIXME: SIZE_FIELD_UNSIGNED and all necessary changes.  */
  {"bound",   0x09c0, 0x0200,		  "m s,R",   0, SIZE_FIELD,
   cris_ver_v0_10,
   cris_two_operand_bound_op},
  /* FIXME: SIZE_FIELD_UNSIGNED and all necessary changes.  */
  {"bound",   0x0dcf, 0x0200,		  "m Y,R",   0, SIZE_FIELD,    0,
   cris_two_operand_bound_op},
  {"bound",   0x09c0, 0x0200,		  "m S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_two_operand_bound_op},
  {"bound",   0x09c0, 0x0600,		  "m S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_bound_op},

  {"bpl",
   BRANCH_QUICK_OPCODE+CC_PL*0x1000,
   0x0f00+(0xF-CC_PL)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"break",   0xe930, 0x16c0,		  "C",	     0, SIZE_NONE,
   cris_ver_v3p,
   cris_break_op},

  {"bsb",
   BRANCH_QUICK_OPCODE+CC_EXT*0x1000,
   0x0f00+(0xF-CC_EXT)*0x1000,		  "o",	     1, SIZE_NONE,
   cris_ver_v32p,
   cris_eight_bit_offset_branch_op},

  {"bsr",     0xBEBF, 0x4140,		  "n",	     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_none_reg_mode_jump_op},

  {"bsrc",     0xBEFF, 0x4100,		  "n",	     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_none_reg_mode_jump_op},

  {"bstore",  0x0af0, 0x0100,		  "s,R",     0, SIZE_FIX_32,
   cris_ver_warning,
   cris_not_implemented_op},

  {"bstore",  0x0af0, 0x0100,		  "S,D",     0, SIZE_NONE,
   cris_ver_warning,
   cris_not_implemented_op},

  {"bstore",  0x0af0, 0x0500,		  "S,R,r",   0, SIZE_NONE,
   cris_ver_warning,
   cris_not_implemented_op},

  {"btst",    0x04F0, 0x0B00,		  "r,R",     0, SIZE_NONE,     0,
   cris_btst_nop_op},
  {"btstq",   0x0380, 0x0C60,		  "c,R",     0, SIZE_NONE,     0,
   cris_btst_nop_op},

  {"bvc",
   BRANCH_QUICK_OPCODE+CC_VC*0x1000,
   0x0f00+(0xF-CC_VC)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"bvs",
   BRANCH_QUICK_OPCODE+CC_VS*0x1000,
   0x0f00+(0xF-CC_VS)*0x1000,		  "o",	     1, SIZE_NONE,     0,
   cris_eight_bit_offset_branch_op},

  {"clear",   0x0670, 0x3980,		  "M r",     0, SIZE_NONE,     0,
   cris_reg_mode_clear_op},

  {"clear",   0x0A70, 0x3180,		  "M y",     0, SIZE_NONE,     0,
   cris_none_reg_mode_clear_test_op},

  {"clear",   0x0A70, 0x3180,		  "M S",     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_clear_test_op},

  {"clearf",  0x05F0, 0x0A00,		  "f",	     0, SIZE_NONE,     0,
   cris_clearf_di_op},

  {"cmp",     0x06C0, 0x0900,		  "m r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  {"cmp",     0x0Ac0, 0x0100,		  "m s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"cmp",     0x0Ac0, 0x0100,		  "m S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"cmpq",    0x02C0, 0x0D00,		  "i,R",     0, SIZE_NONE,     0,
   cris_quick_mode_and_cmp_move_or_op},

  /* FIXME: SIZE_FIELD_SIGNED and all necessary changes.  */
  {"cmps",    0x08e0, 0x0300,		  "z s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"cmps",    0x08e0, 0x0300,		  "z S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  /* FIXME: SIZE_FIELD_UNSIGNED and all necessary changes.  */
  {"cmpu",    0x08c0, 0x0320,		  "z s,R" ,  0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"cmpu",    0x08c0, 0x0320,		  "z S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"di",      0x25F0, 0xDA0F,		  "",	     0, SIZE_NONE,     0,
   cris_clearf_di_op},

  {"dip",     DIP_OPCODE, DIP_Z_BITS,	  "ps",	     0, SIZE_FIX_32,
   cris_ver_v0_10,
   cris_dip_prefix},

  {"div",     0x0980, 0x0640,		  "m R,r",   0, SIZE_FIELD,    0,
   cris_not_implemented_op},

  {"dstep",   0x06f0, 0x0900,		  "r,R",     0, SIZE_NONE,     0,
   cris_dstep_logshift_mstep_neg_not_op},

  {"ei",      0x25B0, 0xDA4F,		  "",	     0, SIZE_NONE,     0,
   cris_ax_ei_setf_op},

  {"fidxd",    0x0ab0, 0xf540,		  "[r]",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"fidxi",    0x0d30, 0xF2C0,		  "[r]",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"ftagd",    0x1AB0, 0xE540,		  "[r]",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"ftagi",    0x1D30, 0xE2C0,		  "[r]",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"halt",    0xF930, 0x06CF,		  "",	     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"jas",    0x09B0, 0x0640,		  "r,P",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_reg_mode_jump_op},

  {"jas",    0x0DBF, 0x0240,		  "N,P",     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_reg_mode_jump_op},

  {"jasc",    0x0B30, 0x04C0,		  "r,P",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_reg_mode_jump_op},

  {"jasc",    0x0F3F, 0x00C0,		  "N,P",     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_reg_mode_jump_op},

  {"jbrc",    0x69b0, 0x9640,		  "r",	     0, SIZE_NONE,
   cris_ver_v8_10,
   cris_reg_mode_jump_op},

  {"jbrc",    0x6930, 0x92c0,		  "s",	     0, SIZE_FIX_32,
   cris_ver_v8_10,
   cris_none_reg_mode_jump_op},

  {"jbrc",    0x6930, 0x92c0,		  "S",	     0, SIZE_NONE,
   cris_ver_v8_10,
   cris_none_reg_mode_jump_op},

  {"jir",     0xA9b0, 0x5640,		  "r",	     0, SIZE_NONE,
   cris_ver_v8_10,
   cris_reg_mode_jump_op},

  {"jir",     0xA930, 0x52c0,		  "s",	     0, SIZE_FIX_32,
   cris_ver_v8_10,
   cris_none_reg_mode_jump_op},

  {"jir",     0xA930, 0x52c0,		  "S",	     0, SIZE_NONE,
   cris_ver_v8_10,
   cris_none_reg_mode_jump_op},

  {"jirc",    0x29b0, 0xd640,		  "r",	     0, SIZE_NONE,
   cris_ver_v8_10,
   cris_reg_mode_jump_op},

  {"jirc",    0x2930, 0xd2c0,		  "s",	     0, SIZE_FIX_32,
   cris_ver_v8_10,
   cris_none_reg_mode_jump_op},

  {"jirc",    0x2930, 0xd2c0,		  "S",	     0, SIZE_NONE,
   cris_ver_v8_10,
   cris_none_reg_mode_jump_op},

  {"jsr",     0xB9b0, 0x4640,		  "r",	     0, SIZE_NONE,     0,
   cris_reg_mode_jump_op},

  {"jsr",     0xB930, 0x42c0,		  "s",	     0, SIZE_FIX_32,
   cris_ver_v0_10,
   cris_none_reg_mode_jump_op},

  {"jsr",     0xBDBF, 0x4240,		  "N",	     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_none_reg_mode_jump_op},

  {"jsr",     0xB930, 0x42c0,		  "S",	     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_jump_op},

  {"jsrc",    0x39b0, 0xc640,		  "r",	     0, SIZE_NONE,
   cris_ver_v8_10,
   cris_reg_mode_jump_op},

  {"jsrc",    0x3930, 0xc2c0,		  "s",	     0, SIZE_FIX_32,
   cris_ver_v8_10,
   cris_none_reg_mode_jump_op},

  {"jsrc",    0x3930, 0xc2c0,		  "S",	     0, SIZE_NONE,
   cris_ver_v8_10,
   cris_none_reg_mode_jump_op},

  {"jsrc",    0xBB30, 0x44C0,		  "r",       0, SIZE_NONE,
   cris_ver_v32p,
   cris_reg_mode_jump_op},

  {"jsrc",    0xBF3F, 0x40C0,		  "N",	     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_reg_mode_jump_op},

  {"jump",    0x09b0, 0xF640,		  "r",	     0, SIZE_NONE,     0,
   cris_reg_mode_jump_op},

  {"jump",
   JUMP_INDIR_OPCODE, JUMP_INDIR_Z_BITS,  "s",	     0, SIZE_FIX_32,
   cris_ver_v0_10,
   cris_none_reg_mode_jump_op},

  {"jump",
   JUMP_INDIR_OPCODE, JUMP_INDIR_Z_BITS,  "S",	     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_jump_op},

  {"jump",    0x09F0, 0x060F,		  "P",	     0, SIZE_NONE,
   cris_ver_v32p,
   cris_none_reg_mode_jump_op},

  {"jump",
   JUMP_PC_INCR_OPCODE_V32,
   (0xffff & ~JUMP_PC_INCR_OPCODE_V32),	  "N",	     0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_none_reg_mode_jump_op},

  {"jmpu",    0x8930, 0x72c0,		  "s",	     0, SIZE_FIX_32,
   cris_ver_v10,
   cris_none_reg_mode_jump_op},

  {"jmpu",    0x8930, 0x72c0,		   "S",	     0, SIZE_NONE,
   cris_ver_v10,
   cris_none_reg_mode_jump_op},

  {"lapc",    0x0970, 0x0680,		  "U,R",    0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"lapc",    0x0D7F, 0x0280,		  "dn,R",    0, SIZE_FIX_32,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"lapcq",   0x0970, 0x0680,		  "u,R",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_addi_op},

  {"lsl",     0x04C0, 0x0B00,		  "m r,R",   0, SIZE_NONE,     0,
   cris_dstep_logshift_mstep_neg_not_op},

  {"lslq",    0x03c0, 0x0C20,		  "c,R",     0, SIZE_NONE,     0,
   cris_dstep_logshift_mstep_neg_not_op},

  {"lsr",     0x07C0, 0x0800,		  "m r,R",   0, SIZE_NONE,     0,
   cris_dstep_logshift_mstep_neg_not_op},

  {"lsrq",    0x03e0, 0x0C00,		  "c,R",     0, SIZE_NONE,     0,
   cris_dstep_logshift_mstep_neg_not_op},

  {"lz",      0x0730, 0x08C0,		  "r,R",     0, SIZE_NONE,
   cris_ver_v3p,
   cris_not_implemented_op},

  {"mcp",      0x07f0, 0x0800,		  "P,r",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"move",    0x0640, 0x0980,		  "m r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  {"move",    0x0A40, 0x0180,		  "m s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"move",    0x0A40, 0x0180,		  "m S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"move",    0x0630, 0x09c0,		  "r,P",     0, SIZE_NONE,     0,
   cris_move_to_preg_op},

  {"move",    0x0670, 0x0980,		  "P,r",     0, SIZE_NONE,     0,
   cris_reg_mode_move_from_preg_op},

  {"move",    0x0BC0, 0x0000,		  "m R,y",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"move",    0x0BC0, 0x0000,		  "m D,S",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"move",
   MOVE_M_TO_PREG_OPCODE, MOVE_M_TO_PREG_ZBITS,
   "s,P",   0, SIZE_SPEC_REG, 0,
   cris_move_to_preg_op},

  {"move",    0x0A30, 0x01c0,		  "S,P",     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_move_to_preg_op},

  {"move",    0x0A70, 0x0180,		  "P,y",     0, SIZE_SPEC_REG, 0,
   cris_none_reg_mode_move_from_preg_op},

  {"move",    0x0A70, 0x0180,		  "P,S",     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_move_from_preg_op},

  {"move",    0x0B70, 0x0480,		  "r,T",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"move",    0x0F70, 0x0080,		  "T,r",     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"movem",   0x0BF0, 0x0000,		  "R,y",     0, SIZE_FIX_32,   0,
   cris_move_reg_to_mem_movem_op},

  {"movem",   0x0BF0, 0x0000,		  "D,S",     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_move_reg_to_mem_movem_op},

  {"movem",   0x0BB0, 0x0040,		  "s,R",     0, SIZE_FIX_32,   0,
   cris_move_mem_to_reg_movem_op},

  {"movem",   0x0BB0, 0x0040,		  "S,D",     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_move_mem_to_reg_movem_op},

  {"moveq",   0x0240, 0x0D80,		  "i,R",     0, SIZE_NONE,     0,
   cris_quick_mode_and_cmp_move_or_op},

  {"movs",    0x0460, 0x0B80,		  "z r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  /* FIXME: SIZE_FIELD_SIGNED and all necessary changes.  */
  {"movs",    0x0860, 0x0380,		  "z s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"movs",    0x0860, 0x0380,		  "z S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"movu",    0x0440, 0x0Ba0,		  "z r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  /* FIXME: SIZE_FIELD_UNSIGNED and all necessary changes.  */
  {"movu",    0x0840, 0x03a0,		  "z s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"movu",    0x0840, 0x03a0,		  "z S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"mstep",   0x07f0, 0x0800,		  "r,R",     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_dstep_logshift_mstep_neg_not_op},

  {"muls",    0x0d00, 0x02c0,		  "m r,R",   0, SIZE_NONE,
   cris_ver_v10p,
   cris_muls_op},

  {"mulu",    0x0900, 0x06c0,		  "m r,R",   0, SIZE_NONE,
   cris_ver_v10p,
   cris_mulu_op},

  {"neg",     0x0580, 0x0A40,		  "m r,R",   0, SIZE_NONE,     0,
   cris_dstep_logshift_mstep_neg_not_op},

  {"nop",     NOP_OPCODE, NOP_Z_BITS,	  "",	     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_btst_nop_op},

  {"nop",     NOP_OPCODE_V32, NOP_Z_BITS_V32, "",    0, SIZE_NONE,
   cris_ver_v32p,
   cris_btst_nop_op},

  {"not",     0x8770, 0x7880,		  "r",	     0, SIZE_NONE,     0,
   cris_dstep_logshift_mstep_neg_not_op},

  {"or",      0x0740, 0x0880,		  "m r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  {"or",      0x0B40, 0x0080,		  "m s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"or",      0x0B40, 0x0080,		  "m S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"or",      0x0B40, 0x0480,		  "m S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_add_sub_cmp_and_or_op},

  {"orq",     0x0340, 0x0C80,		  "i,R",     0, SIZE_NONE,     0,
   cris_quick_mode_and_cmp_move_or_op},

  {"pop",     0x0E6E, 0x0191,		  "!R",	     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"pop",     0x0e3e, 0x01c1,		  "!P",	     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_move_from_preg_op},

  {"push",    0x0FEE, 0x0011,		  "BR",	     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"push",    0x0E7E, 0x0181,		  "BP",	     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_move_to_preg_op},

  {"rbf",     0x3b30, 0xc0c0,		  "y",	     0, SIZE_NONE,
   cris_ver_v10,
   cris_not_implemented_op},

  {"rbf",     0x3b30, 0xc0c0,		  "S",	     0, SIZE_NONE,
   cris_ver_v10,
   cris_not_implemented_op},

  {"rfe",     0x2930, 0xD6CF,		  "",	     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"rfg",     0x4930, 0xB6CF,		  "",	     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"rfn",     0x5930, 0xA6CF,		  "",	     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  {"ret",     0xB67F, 0x4980,		  "",	     1, SIZE_NONE,
   cris_ver_v0_10,
   cris_reg_mode_move_from_preg_op},

  {"ret",     0xB9F0, 0x460F,		  "",	     1, SIZE_NONE,
   cris_ver_v32p,
   cris_reg_mode_move_from_preg_op},

  {"retb",    0xe67f, 0x1980,		  "",	     1, SIZE_NONE,
   cris_ver_v0_10,
   cris_reg_mode_move_from_preg_op},

  {"rete",     0xA9F0, 0x560F,		  "",	     1, SIZE_NONE,
   cris_ver_v32p,
   cris_reg_mode_move_from_preg_op},

  {"reti",    0xA67F, 0x5980,		  "",	     1, SIZE_NONE,
   cris_ver_v0_10,
   cris_reg_mode_move_from_preg_op},

  {"retn",     0xC9F0, 0x360F,		  "",	     1, SIZE_NONE,
   cris_ver_v32p,
   cris_reg_mode_move_from_preg_op},

  {"sbfs",    0x3b70, 0xc080,		  "y",	     0, SIZE_NONE,
   cris_ver_v10,
   cris_not_implemented_op},

  {"sbfs",    0x3b70, 0xc080,		  "S",	     0, SIZE_NONE,
   cris_ver_v10,
   cris_not_implemented_op},

  {"sa",
   0x0530+CC_A*0x1000,
   0x0AC0+(0xf-CC_A)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"ssb",
   0x0530+CC_EXT*0x1000,
   0x0AC0+(0xf-CC_EXT)*0x1000,		  "r",	     0, SIZE_NONE,
   cris_ver_v32p,
   cris_scc_op},

  {"scc",
   0x0530+CC_CC*0x1000,
   0x0AC0+(0xf-CC_CC)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"scs",
   0x0530+CC_CS*0x1000,
   0x0AC0+(0xf-CC_CS)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"seq",
   0x0530+CC_EQ*0x1000,
   0x0AC0+(0xf-CC_EQ)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"setf",    0x05b0, 0x0A40,		  "f",	     0, SIZE_NONE,     0,
   cris_ax_ei_setf_op},

  {"sfe",    0x3930, 0xC6CF,		  "",	     0, SIZE_NONE,
   cris_ver_v32p,
   cris_not_implemented_op},

  /* Need to have "swf" in front of "sext" so it is the one displayed in
     disassembly.  */
  {"swf",
   0x0530+CC_EXT*0x1000,
   0x0AC0+(0xf-CC_EXT)*0x1000,		  "r",	     0, SIZE_NONE,
   cris_ver_v10,
   cris_scc_op},

  {"sext",
   0x0530+CC_EXT*0x1000,
   0x0AC0+(0xf-CC_EXT)*0x1000,		  "r",	     0, SIZE_NONE,
   cris_ver_v0_3,
   cris_scc_op},

  {"sge",
   0x0530+CC_GE*0x1000,
   0x0AC0+(0xf-CC_GE)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"sgt",
   0x0530+CC_GT*0x1000,
   0x0AC0+(0xf-CC_GT)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"shi",
   0x0530+CC_HI*0x1000,
   0x0AC0+(0xf-CC_HI)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"shs",
   0x0530+CC_HS*0x1000,
   0x0AC0+(0xf-CC_HS)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"sle",
   0x0530+CC_LE*0x1000,
   0x0AC0+(0xf-CC_LE)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"slo",
   0x0530+CC_LO*0x1000,
   0x0AC0+(0xf-CC_LO)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"sls",
   0x0530+CC_LS*0x1000,
   0x0AC0+(0xf-CC_LS)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"slt",
   0x0530+CC_LT*0x1000,
   0x0AC0+(0xf-CC_LT)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"smi",
   0x0530+CC_MI*0x1000,
   0x0AC0+(0xf-CC_MI)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"sne",
   0x0530+CC_NE*0x1000,
   0x0AC0+(0xf-CC_NE)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"spl",
   0x0530+CC_PL*0x1000,
   0x0AC0+(0xf-CC_PL)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"sub",     0x0680, 0x0940,		  "m r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  {"sub",     0x0a80, 0x0140,		  "m s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"sub",     0x0a80, 0x0140,		  "m S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"sub",     0x0a80, 0x0540,		  "m S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_add_sub_cmp_and_or_op},

  {"subq",    0x0280, 0x0d40,		  "I,R",     0, SIZE_NONE,     0,
   cris_quick_mode_add_sub_op},

  {"subs",    0x04a0, 0x0b40,		  "z r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  /* FIXME: SIZE_FIELD_SIGNED and all necessary changes.  */
  {"subs",    0x08a0, 0x0340,		  "z s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"subs",    0x08a0, 0x0340,		  "z S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"subs",    0x08a0, 0x0740,		  "z S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_add_sub_cmp_and_or_op},

  {"subu",    0x0480, 0x0b60,		  "z r,R",   0, SIZE_NONE,     0,
   cris_reg_mode_add_sub_cmp_and_or_move_op},

  /* FIXME: SIZE_FIELD_UNSIGNED and all necessary changes.  */
  {"subu",    0x0880, 0x0360,		  "z s,R",   0, SIZE_FIELD,    0,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"subu",    0x0880, 0x0360,		  "z S,D",   0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_add_sub_cmp_and_or_move_op},

  {"subu",    0x0880, 0x0760,		  "z S,R,r", 0, SIZE_NONE,
   cris_ver_v0_10,
   cris_three_operand_add_sub_cmp_and_or_op},

  {"svc",
   0x0530+CC_VC*0x1000,
   0x0AC0+(0xf-CC_VC)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  {"svs",
   0x0530+CC_VS*0x1000,
   0x0AC0+(0xf-CC_VS)*0x1000,		  "r",	     0, SIZE_NONE,     0,
   cris_scc_op},

  /* The insn "swapn" is the same as "not" and will be disassembled as
     such, but the swap* family of mnmonics are generally v8-and-higher
     only, so count it in.  */
  {"swapn",   0x8770, 0x7880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapw",   0x4770, 0xb880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapnw",  0xc770, 0x3880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapb",   0x2770, 0xd880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapnb",  0xA770, 0x5880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapwb",  0x6770, 0x9880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapnwb", 0xE770, 0x1880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapr",   0x1770, 0xe880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapnr",  0x9770, 0x6880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapwr",  0x5770, 0xa880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapnwr", 0xd770, 0x2880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapbr",  0x3770, 0xc880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapnbr", 0xb770, 0x4880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapwbr", 0x7770, 0x8880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"swapnwbr", 0xf770, 0x0880,		  "r",	     0, SIZE_NONE,
   cris_ver_v8p,
   cris_not_implemented_op},

  {"test",    0x0640, 0x0980,		  "m D",     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_reg_mode_test_op},

  {"test",    0x0b80, 0xf040,		  "m y",     0, SIZE_FIELD,    0,
   cris_none_reg_mode_clear_test_op},

  {"test",    0x0b80, 0xf040,		  "m S",     0, SIZE_NONE,
   cris_ver_v0_10,
   cris_none_reg_mode_clear_test_op},

  {"xor",     0x07B0, 0x0840,		  "r,R",     0, SIZE_NONE,     0,
   cris_xor_op},

  {NULL, 0, 0, NULL, 0, 0, 0, cris_not_implemented_op}
};

/* Condition-names, indexed by the CC_* numbers as found in cris.h. */
const char * const
cris_cc_strings[] =
{
  "hs",
  "lo",
  "ne",
  "eq",
  "vc",
  "vs",
  "pl",
  "mi",
  "ls",
  "hi",
  "ge",
  "lt",
  "gt",
  "le",
  "a",
  /* This is a placeholder.  In v0, this would be "ext".  In v32, this
     is "sb".  See cris_conds15.  */
  "wf"
};

/* Different names and semantics for condition 1111 (0xf).  */
const struct cris_cond15 cris_cond15s[] =
{
  /* FIXME: In what version did condition "ext" disappear?  */
  {"ext", cris_ver_v0_3},
  {"wf", cris_ver_v10},
  {"sb", cris_ver_v32p},
  {NULL, 0}
};


/*
 * Local variables:
 * eval: (c-set-style "gnu")
 * indent-tabs-mode: t
 * End:
 */
