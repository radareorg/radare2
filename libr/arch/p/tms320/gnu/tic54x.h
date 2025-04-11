/* tic54x.h -- Header file for TI TMS320C54X opcode table
   Copyright (C) 1999-2025 Free Software Foundation, Inc.
   Written by Timothy Wall (twall@cygnus.com)

   This file is part of GDB, GAS, and the GNU binutils.

   GDB, GAS, and the GNU binutils are free software; you can redistribute
   them and/or modify them under the terms of the GNU General Public
   License as published by the Free Software Foundation; either version 3,
   or (at your option) any later version.

   GDB, GAS, and the GNU binutils are distributed in the hope that they
   will be useful, but WITHOUT ANY WARRANTY; without even the implied
   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
   the GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this file; see the file COPYING3.  If not, write to the Free
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef _opcode_tic54x_h_
#define _opcode_tic54x_h_

typedef struct _symbol
{
  const char *name;
  unsigned short value;
} tic54x_symbol;

enum optype {
  OPT = 0x8000,
  OP_None = 0x0,

  OP_Xmem, /* AR3 or AR4, indirect */
  OP_Ymem, /* AR3 or AR4, indirect */
  OP_pmad, /* PROG mem, direct */
  OP_dmad, /* DATA mem, direct */
  OP_Smem,
  OP_Lmem, /* 32-bit single-addressed (direct/indirect) */
  OP_MMR,
  OP_PA,
  OP_Sind,
  OP_xpmad,
  OP_xpmad_ms7,
  OP_MMRX,
  OP_MMRY,

  OP_SRC1, /* src accumulator in bit 8 */
  OP_SRC, /* src accumulator in bit 9 */
  OP_RND, /* rounded result dst accumulator, opposite of bit 8 */
  OP_DST, /* dst accumulator in bit 8 */
  OP_ARX, /* arX in bits 0-3 */
  OP_SHIFT, /* -16 to 15 (SHIFT), bits 0-4 */
  OP_SHFT, /*   0 to 15 (SHIFT1 in summary), bits 0-3 */
  OP_B, /* ACC B only */
  OP_A, /* ACC A only */

  OP_lk, /* 16-bit immediate, '#' optional */
  OP_TS,
  OP_k8, /* -128 <= k <= 128 */
  OP_16, /* literal "16" */
  OP_BITC, /* 0 to 16 */
  OP_CC, /* condition code */
  OP_CC2, /* 4-bit condition code */
  OP_CC3, /* 2-bit condition code */
  OP_123, /* 1, 2, or 3 */
  OP_031, /* 0-31, numeric */
  OP_k5, /* 0 to 31 */
  OP_k8u, /* 0 to 255 */
  OP_ASM, /* "ASM" */
  OP_T, /* "T" */
  OP_DP, /* "DP" */
  OP_ARP, /* "ARP" */
  OP_k3, /* 0-7 */
  OP_lku, /* 0 to 65535 */
  OP_N, /* 0/1 or ST0/ST1 */
  OP_SBIT, /* status bit or 0-15 */
  OP_12, /* one or two */
  OP_k9, /* 9 bits of data page (DP) address */
  OP_TRN, /* "TRN" */

};

typedef struct _template
{
  /* The opcode mnemonic */
  const char *name;
  unsigned int words; /* insn size in words */
  int minops, maxops; /* min/max operand count */
  /* The significant bits in the opcode.  Other bits are zero. 
     Instructions with more than 16 bits of opcode store the rest in the upper
     16 bits.
   */
  unsigned short opcode;
#define INDIRECT(OP)    ((OP)&0x80)
#define MOD(OP)         (((OP)>>3)&0xF)
#define ARF(OP)         ((OP)&0x7)
#define IS_LKADDR(OP)   (INDIRECT(OP) && MOD(OP)>=12)
#define SRC(OP)         ((OP)&0x200)
#define DST(OP)         ((OP)&0x100)
#define SRC1(OP)        ((OP)&0x100)
#define SHIFT(OP)       (((OP)&0x10)?(((OP)&0x1F)-32):((OP)&0x1F))
#define SHFT(OP)        ((OP)&0xF)
#define ARX(OP)         ((OP)&0x7)
#define XMEM(OP)        (((OP)&0x00F0)>>4)
#define YMEM(OP)        ((OP)&0x000F)
#define XMOD(C)        (((C)&0xC)>>2)
#define XARX(C)        (((C)&0x3)+2)
#define CC3(OP)         (((OP)>>8)&0x3)
#define SBIT(OP)        ((OP)&0xF)
#define MMR(OP)         ((OP)&0x7F)
#define MMRX(OP)        ((((OP)>>4)&0xF)+16)
#define MMRY(OP)        (((OP)&0xF)+16)

#define OPTYPE(X)       ((X)&~OPT)

  /* Ones in this mask indicate which bits must match the opcode field.
     Zeroes indicate don't care bits (operands and/or opcode options) */
  unsigned short mask;

  /* An array of operand codes (at most 4 operands) */
#define MAX_OPERANDS 4
  enum optype operand_types[MAX_OPERANDS];

  /* Special purpose flags (e.g. branch type, parallel, delay, etc) 
   */
  unsigned short flags;
#define B_NEXT      0 /* normal execution, next insn is next address */
#define B_BRANCH    1 /* next insn is in opcode */
#define B_RET       2 /* next insn is on stack */
#define B_BACC      3 /* next insn is in acc */
#define B_REPEAT    4 /* next insn repeats */
#define FL_BMASK    0x07

#define FL_DELAY    0x10 /* instruction uses delay slots */
#define FL_EXT      0x20 /* instruction takes two words */   
#define FL_FAR      0x40 /* far mode addressing */
#define FL_LP       0x80 /* LP-only instruction */
#define FL_NR       0x100 /* no repeat allowed */
#define FL_SMR      0x200 /* Smem read (for flagging write-only *+ARx */

#define FL_PAR      0x400 /* Parallel instruction. */

  unsigned short opcode2, mask2;   /* some insns have an extended opcode */

  const char* parname;
  enum optype paroperand_types[MAX_OPERANDS];

} insn_template;

extern const insn_template tic54x_unknown_opcode;
extern const insn_template tic54x_optab[];
extern const insn_template tic54x_paroptab[];
extern const tic54x_symbol tic54x_mmregs[], tic54x_regs[];
extern const tic54x_symbol tic54x_condition_codes[], tic54x_cc2_codes[];
extern const tic54x_symbol tic54x_status_bits[], tic54x_cc3_codes[];
extern const char *tic54x_misc_symbols[];
struct disassemble_info;
extern const insn_template* tic54x_get_insn (struct disassemble_info *, 
                                        bfd_vma, unsigned short, int *);

#endif /* _opcode_tic54x_h_ */
