/* s390-opc.c -- S390 opcode list
   Copyright (C) 2000-2021 Free Software Foundation, Inc.
   Contributed by Martin Schwidefsky (schwidefsky@de.ibm.com).

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
   along with this file; see the file COPYING.  If not, write to the
   Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include <stdio.h>
#include "ansidecl.h"
#include "opcode/s390.h"

/* This file holds the S390 opcode table.  The opcode table
   includes almost all of the extended instruction mnemonics.  This
   permits the disassembler to use them, and simplifies the assembler
   logic, at the cost of increasing the table size.  The table is
   strictly constant data, so the compiler should be able to put it in
   the .text section.

   This file also holds the operand table.  All knowledge about
   inserting operands into instructions and vice-versa is kept in this
   file.  */

/* The operands table.
   The fields are bits, shift, insert, extract, flags.  */

const struct s390_operand s390_operands[] =
{
#define UNUSED 0
  { 0, 0, 0 },                    /* Indicates the end of the operand list */

/* General purpose register operands.  */

#define R_8         1             /* GPR starting at position 8 */
  { 4, 8, S390_OPERAND_GPR },
#define R_12        2             /* GPR starting at position 12 */
  { 4, 12, S390_OPERAND_GPR },
#define R_16        3             /* GPR starting at position 16 */
  { 4, 16, S390_OPERAND_GPR },
#define R_20        4             /* GPR starting at position 20 */
  { 4, 20, S390_OPERAND_GPR },
#define R_24        5             /* GPR starting at position 24 */
  { 4, 24, S390_OPERAND_GPR },
#define R_28        6             /* GPR starting at position 28 */
  { 4, 28, S390_OPERAND_GPR },
#define R_32        7             /* GPR starting at position 32 */
  { 4, 32, S390_OPERAND_GPR },

/* General purpose register pair operands.  */

#define RE_8        8             /* GPR starting at position 8 */
  { 4, 8, S390_OPERAND_GPR | S390_OPERAND_REG_PAIR },
#define RE_12       9             /* GPR starting at position 12 */
  { 4, 12, S390_OPERAND_GPR | S390_OPERAND_REG_PAIR },
#define RE_16       10            /* GPR starting at position 16 */
  { 4, 16, S390_OPERAND_GPR | S390_OPERAND_REG_PAIR },
#define RE_20       11            /* GPR starting at position 20 */
  { 4, 20, S390_OPERAND_GPR | S390_OPERAND_REG_PAIR },
#define RE_24       12            /* GPR starting at position 24 */
  { 4, 24, S390_OPERAND_GPR | S390_OPERAND_REG_PAIR },
#define RE_28       13            /* GPR starting at position 28 */
  { 4, 28, S390_OPERAND_GPR | S390_OPERAND_REG_PAIR },
#define RE_32       14            /* GPR starting at position 32 */
  { 4, 32, S390_OPERAND_GPR | S390_OPERAND_REG_PAIR },

/* Floating point register operands.  */

#define F_8         15            /* FPR starting at position 8 */
  { 4, 8, S390_OPERAND_FPR },
#define F_12        16            /* FPR starting at position 12 */
  { 4, 12, S390_OPERAND_FPR },
#define F_16        17            /* FPR starting at position 16 */
  { 4, 16, S390_OPERAND_FPR },
#define F_24        18            /* FPR starting at position 24 */
  { 4, 24, S390_OPERAND_FPR },
#define F_28        19            /* FPR starting at position 28 */
  { 4, 28, S390_OPERAND_FPR },
#define F_32        20            /* FPR starting at position 32 */
  { 4, 32, S390_OPERAND_FPR },

/* Floating point register pair operands.  */

#define FE_8        21            /* FPR starting at position 8 */
  { 4, 8, S390_OPERAND_FPR | S390_OPERAND_REG_PAIR },
#define FE_12       22            /* FPR starting at position 12 */
  { 4, 12, S390_OPERAND_FPR | S390_OPERAND_REG_PAIR },
#define FE_16       23            /* FPR starting at position 16 */
  { 4, 16, S390_OPERAND_FPR | S390_OPERAND_REG_PAIR },
#define FE_24       24            /* FPR starting at position 24 */
  { 4, 24, S390_OPERAND_FPR | S390_OPERAND_REG_PAIR },
#define FE_28       25            /* FPR starting at position 28 */
  { 4, 28, S390_OPERAND_FPR | S390_OPERAND_REG_PAIR },
#define FE_32       26            /* FPR starting at position 32 */
  { 4, 32, S390_OPERAND_FPR | S390_OPERAND_REG_PAIR },

/* Vector register operands.  */

/* For each of these operands and additional bit in the RXB operand is
   needed.  */

#define V_8         27            /* Vector reg. starting at position 8 */
  { 4, 8, S390_OPERAND_VR },
#define V_12        28            /* Vector reg. starting at position 12 */
  { 4, 12, S390_OPERAND_VR },
#define V_CP16_12   29            /* Vector reg. starting at position 12 */
  { 4, 12, S390_OPERAND_VR | S390_OPERAND_CP16 }, /* with a copy at pos 16 */
#define V_16        30            /* Vector reg. starting at position 16 */
  { 4, 16, S390_OPERAND_VR },
#define V_32        31            /* Vector reg. starting at position 32 */
  { 4, 32, S390_OPERAND_VR },

/* Access register operands.  */

#define A_8         32            /* Access reg. starting at position 8 */
  { 4, 8, S390_OPERAND_AR },
#define A_12        33            /* Access reg. starting at position 12 */
  { 4, 12, S390_OPERAND_AR },
#define A_24        34            /* Access reg. starting at position 24 */
  { 4, 24, S390_OPERAND_AR },
#define A_28        35            /* Access reg. starting at position 28 */
  { 4, 28, S390_OPERAND_AR },

/* Control register operands.  */

#define C_8         36            /* Control reg. starting at position 8 */
  { 4, 8, S390_OPERAND_CR },
#define C_12        37            /* Control reg. starting at position 12 */
  { 4, 12, S390_OPERAND_CR },

/* Base register operands.  */

#define B_16        38            /* Base register starting at position 16 */
  { 4, 16, S390_OPERAND_BASE | S390_OPERAND_GPR },
#define B_32        39            /* Base register starting at position 32 */
  { 4, 32, S390_OPERAND_BASE | S390_OPERAND_GPR },

#define X_12        40            /* Index register starting at position 12 */
  { 4, 12, S390_OPERAND_INDEX | S390_OPERAND_GPR },

#define VX_12       41     /* Vector index register starting at position 12 */
  { 4, 12, S390_OPERAND_INDEX | S390_OPERAND_VR },

/* Address displacement operands.  */

#define D_20        42            /* Displacement starting at position 20 */
  { 12, 20, S390_OPERAND_DISP },
#define D_36        43            /* Displacement starting at position 36 */
  { 12, 36, S390_OPERAND_DISP },
#define D20_20      44		  /* 20 bit displacement starting at 20 */
  { 20, 20, S390_OPERAND_DISP | S390_OPERAND_SIGNED },

/* Length operands.  */

#define L4_8        45            /* 4 bit length starting at position 8 */
  { 4, 8, S390_OPERAND_LENGTH },
#define L4_12       46            /* 4 bit length starting at position 12 */
  { 4, 12, S390_OPERAND_LENGTH },
#define L8_8        47            /* 8 bit length starting at position 8 */
  { 8, 8, S390_OPERAND_LENGTH },

/* Signed immediate operands.  */

#define I8_8        48		  /* 8 bit signed value starting at 8 */
  { 8, 8, S390_OPERAND_SIGNED },
#define I8_32       49		  /* 8 bit signed value starting at 32 */
  { 8, 32, S390_OPERAND_SIGNED },
#define I12_12      50		  /* 12 bit signed value starting at 12 */
  { 12, 12, S390_OPERAND_SIGNED },
#define I16_16      51            /* 16 bit signed value starting at 16 */
  { 16, 16, S390_OPERAND_SIGNED },
#define I16_32      52            /* 16 bit signed value starting at 32 */
  { 16, 32, S390_OPERAND_SIGNED },
#define I24_24      53		  /* 24 bit signed value starting at 24 */
  { 24, 24, S390_OPERAND_SIGNED },
#define I32_16      54		  /* 32 bit signed value starting at 16 */
  { 32, 16, S390_OPERAND_SIGNED },

/* Unsigned immediate operands.  */

#define U4_8        55            /* 4 bit unsigned value starting at 8 */
  { 4, 8, 0 },
#define U4_12       56            /* 4 bit unsigned value starting at 12 */
  { 4, 12, 0 },
#define U4_16       57            /* 4 bit unsigned value starting at 16 */
  { 4, 16, 0 },
#define U4_20       58            /* 4 bit unsigned value starting at 20 */
  { 4, 20, 0 },
#define U4_24       59            /* 4 bit unsigned value starting at 24 */
  { 4, 24, 0 },
#define U4_OR1_24   60            /* 4 bit unsigned value ORed with 1 */
  { 4, 24, S390_OPERAND_OR1 },	  /* starting at 24 */
#define U4_OR2_24   61            /* 4 bit unsigned value ORed with 2 */
  { 4, 24, S390_OPERAND_OR2 },    /* starting at 24 */
#define U4_OR3_24   62            /* 4 bit unsigned value ORed with 3 */
  { 4, 24, S390_OPERAND_OR1 | S390_OPERAND_OR2 }, /* starting at 24 */
#define U4_28       63            /* 4 bit unsigned value starting at 28 */
  { 4, 28, 0 },
#define U4_OR8_28   64            /* 4 bit unsigned value ORed with 8 */
  { 4, 28, S390_OPERAND_OR8 },    /* starting at 28 */
#define U4_32       65            /* 4 bit unsigned value starting at 32 */
  { 4, 32, 0 },
#define U4_36       66            /* 4 bit unsigned value starting at 36 */
  { 4, 36, 0 },
#define U8_8        67            /* 8 bit unsigned value starting at 8 */
  { 8, 8, 0 },
#define U8_16       68            /* 8 bit unsigned value starting at 16 */
  { 8, 16, 0 },
#define U6_26       69            /* 6 bit unsigned value starting at 26 */
  { 6, 26, 0 },
#define U8_24       70            /* 8 bit unsigned value starting at 24 */
  { 8, 24, 0 },
#define U8_28       71            /* 8 bit unsigned value starting at 28 */
  { 8, 28, 0 },
#define U8_32       72            /* 8 bit unsigned value starting at 32 */
  { 8, 32, 0 },
#define U12_16      73            /* 12 bit unsigned value starting at 16 */
  { 12, 16, 0 },
#define U16_16      74            /* 16 bit unsigned value starting at 16 */
  { 16, 16, 0 },
#define U16_32      75		  /* 16 bit unsigned value starting at 32 */
  { 16, 32, 0 },
#define U32_16      76		  /* 32 bit unsigned value starting at 16 */
  { 32, 16, 0 },

/* PC-relative address operands.  */

#define J12_12      77            /* 12 bit PC relative offset at 12 */
  { 12, 12, S390_OPERAND_PCREL },
#define J16_16      78            /* 16 bit PC relative offset at 16 */
  { 16, 16, S390_OPERAND_PCREL },
#define J16_32      79            /* 16 bit PC relative offset at 32 */
  { 16, 32, S390_OPERAND_PCREL },
#define J24_24      80            /* 24 bit PC relative offset at 24 */
  { 24, 24, S390_OPERAND_PCREL },
#define J32_16      81            /* 32 bit PC relative offset at 16 */
  { 32, 16, S390_OPERAND_PCREL },

};


/* Macros used to form opcodes.  */

/* 8/16/48 bit opcodes.  */
#define OP8(x) { x, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define OP16(x) { x >> 8, x & 255, 0x00, 0x00, 0x00, 0x00 }
#define OP32(x) { x >> 24, (x >> 16) & 255, (x >> 8) & 255, x & 255,	\
		  0x00, 0x00 }
#define OP48(x) { x >> 40, (x >> 32) & 255, (x >> 24) & 255, \
		  (x >> 16) & 255, (x >> 8) & 255, x & 255}

/* The new format of the INSTR_x_y and MASK_x_y defines is based
   on the following rules:
   1) the middle part of the definition (x in INSTR_x_y) is the official
      names of the instruction format that you can find in the principals
      of operation.
   2) the last part of the definition (y in INSTR_x_y) gives you an idea
      which operands the binary represenation of the instruction has.
      The meanings of the letters in y are:
      a - access register
      c - control register
      d - displacement, 12 bit
      f - floating pointer register
      fe - fpr extended operand, a valid floating pointer register pair
      i - signed integer, 4, 8, 16 or 32 bit
      l - length, 4 or 8 bit
      p - pc relative
      r - general purpose register
      re - gpr extended operand, a valid general purpose register pair
      u - unsigned integer, 4, 8, 16 or 32 bit
      m - mode field, 4 bit
      0 - operand skipped.
      The order of the letters reflects the layout of the format in
      storage and not the order of the paramaters of the instructions.
      The use of the letters is not a 100% match with the PoP but it is
      quite close.

      For example the instruction "mvo" is defined in the PoP as follows:

      MVO  D1(L1,B1),D2(L2,B2)   [SS]

      --------------------------------------
      | 'F1' | L1 | L2 | B1 | D1 | B2 | D2 |
      --------------------------------------
       0      8    12   16   20   32   36

      The instruction format is: INSTR_SS_LLRDRD / MASK_SS_LLRDRD.  */

#define INSTR_E            2, { 0,0,0,0,0,0 }                    /* e.g. pr    */
#define INSTR_IE_UU        4, { U4_24,U4_28,0,0,0,0 }            /* e.g. niai  */
#define INSTR_MII_UPP      6, { U4_8,J12_12,J24_24 }             /* e.g. bprp  */
#define INSTR_RIE_RRP      6, { R_8,R_12,J16_16,0,0,0 }          /* e.g. brxhg */
#define INSTR_RIE_RRPU     6, { R_8,R_12,U4_32,J16_16,0,0 }      /* e.g. crj   */
#define INSTR_RIE_RRP0     6, { R_8,R_12,J16_16,0,0,0 }          /* e.g. cgrjne */
#define INSTR_RIE_RRI0     6, { R_8,R_12,I16_16,0,0,0 }          /* e.g. ahik  */
#define INSTR_RIE_RUPI     6, { R_8,I8_32,U4_12,J16_16,0,0 }     /* e.g. cij   */
#define INSTR_RIE_R0PI     6, { R_8,I8_32,J16_16,0,0,0 }         /* e.g. cijne */
#define INSTR_RIE_RUPU     6, { R_8,U8_32,U4_12,J16_16,0,0 }     /* e.g. clij  */
#define INSTR_RIE_R0PU     6, { R_8,U8_32,J16_16,0,0,0 }         /* e.g. clijne */
#define INSTR_RIE_R0IU     6, { R_8,I16_16,U4_32,0,0,0 }         /* e.g. cit   */
#define INSTR_RIE_R0I0     6, { R_8,I16_16,0,0,0,0 }             /* e.g. citne */
#define INSTR_RIE_R0UU     6, { R_8,U16_16,U4_32,0,0,0 }         /* e.g. clfit */
#define INSTR_RIE_R0U0     6, { R_8,U16_16,0,0,0,0 }             /* e.g. clfitne */
#define INSTR_RIE_RUI0     6, { R_8,I16_16,U4_12,0,0,0 }         /* e.g. lochi */
#define INSTR_RIE_RRUUU    6, { R_8,R_12,U8_16,U8_24,U8_32,0 }   /* e.g. rnsbg */
#define INSTR_RIE_RRUUU2   6, { R_8,R_12,U8_16,U6_26,U8_32,0 }   /* e.g. rnsbg */
#define INSTR_RIL_0P       6, { J32_16,0,0,0,0 }                 /* e.g. jg    */
#define INSTR_RIL_RP       6, { R_8,J32_16,0,0,0,0 }             /* e.g. brasl */
#define INSTR_RIL_UP       6, { U4_8,J32_16,0,0,0,0 }            /* e.g. brcl  */
#define INSTR_RIL_RI       6, { R_8,I32_16,0,0,0,0 }             /* e.g. afi   */
#define INSTR_RIL_RU       6, { R_8,U32_16,0,0,0,0 }             /* e.g. alfi  */
#define INSTR_RI_0P        4, { J16_16,0,0,0,0,0 }               /* e.g. j     */
#define INSTR_RI_RI        4, { R_8,I16_16,0,0,0,0 }             /* e.g. ahi   */
#define INSTR_RI_RP        4, { R_8,J16_16,0,0,0,0 }             /* e.g. brct  */
#define INSTR_RI_RU        4, { R_8,U16_16,0,0,0,0 }             /* e.g. tml   */
#define INSTR_RI_UP        4, { U4_8,J16_16,0,0,0,0 }            /* e.g. brc   */
#define INSTR_RIS_RURDI    6, { R_8,I8_32,U4_12,D_20,B_16,0 }    /* e.g. cib   */
#define INSTR_RIS_R0RDI    6, { R_8,I8_32,D_20,B_16,0,0 }        /* e.g. cibne */
#define INSTR_RIS_RURDU    6, { R_8,U8_32,U4_12,D_20,B_16,0 }    /* e.g. clib  */
#define INSTR_RIS_R0RDU    6, { R_8,U8_32,D_20,B_16,0,0 }        /* e.g. clibne*/
#define INSTR_RRE_00       4, { 0,0,0,0,0,0 }                    /* e.g. palb  */
#define INSTR_RRE_0R       4, { R_28,0,0,0,0,0 }                 /* e.g. tb    */
#define INSTR_RRE_AA       4, { A_24,A_28,0,0,0,0 }              /* e.g. cpya  */
#define INSTR_RRE_AR       4, { A_24,R_28,0,0,0,0 }              /* e.g. sar   */
#define INSTR_RRE_F0       4, { F_24,0,0,0,0,0 }                 /* e.g. lzer  */
#define INSTR_RRE_FE0      4, { FE_24,0,0,0,0,0 }                /* e.g. lzxr  */
#define INSTR_RRE_FF       4, { F_24,F_28,0,0,0,0 }              /* e.g. debr  */
#define INSTR_RRE_FEF      4, { FE_24,F_28,0,0,0,0 }             /* e.g. lxdbr */
#define INSTR_RRE_FFE      4, { F_24,FE_28,0,0,0,0 }             /* e.g. lexr  */
#define INSTR_RRE_FEFE     4, { FE_24,FE_28,0,0,0,0 }            /* e.g. dxr   */
#define INSTR_RRE_R0       4, { R_24,0,0,0,0,0 }                 /* e.g. ipm   */
#define INSTR_RRE_RA       4, { R_24,A_28,0,0,0,0 }              /* e.g. ear   */
#define INSTR_RRE_RF       4, { R_24,F_28,0,0,0,0 }              /* e.g. lgdr  */
#define INSTR_RRE_RFE      4, { R_24,FE_28,0,0,0,0 }             /* e.g. csxtr */
#define INSTR_RRE_RR       4, { R_24,R_28,0,0,0,0 }              /* e.g. lura  */
#define INSTR_RRE_RER      4, { RE_24,R_28,0,0,0,0 }             /* e.g. tre   */
#define INSTR_RRE_RERE     4, { RE_24,RE_28,0,0,0,0 }            /* e.g. cuse  */
#define INSTR_RRE_FR       4, { F_24,R_28,0,0,0,0 }              /* e.g. ldgr  */
#define INSTR_RRE_FER      4, { FE_24,R_28,0,0,0,0 }             /* e.g. cxfbr */
#define INSTR_RRF_F0FF     4, { F_16,F_24,F_28,0,0,0 }           /* e.g. madbr */
#define INSTR_RRF_FE0FF    4, { F_16,F_24,F_28,0,0,0 }           /* e.g. myr   */
#define INSTR_RRF_F0FF2    4, { F_24,F_16,F_28,0,0,0 }           /* e.g. cpsdr */
#define INSTR_RRF_F0FR     4, { F_24,F_16,R_28,0,0,0 }           /* e.g. iedtr */
#define INSTR_RRF_FE0FER   4, { FE_24,FE_16,R_28,0,0,0 }         /* e.g. iextr */
#define INSTR_RRF_FUFF     4, { F_24,F_16,F_28,U4_20,0,0 }       /* e.g. didbr */
#define INSTR_RRF_FEUFEFE  4, { FE_24,FE_16,FE_28,U4_20,0,0 }    /* e.g. qaxtr */
#define INSTR_RRF_FUFF2    4, { F_24,F_28,F_16,U4_20,0,0 }       /* e.g. adtra */
#define INSTR_RRF_FEUFEFE2 4, { FE_24,FE_28,FE_16,U4_20,0,0 }    /* e.g. axtra */
#define INSTR_RRF_RURR     4, { R_24,R_28,R_16,U4_20,0,0 }       /* e.g. ipte  */
#define INSTR_RRF_RURR2    4, { R_24,R_16,R_28,U4_20,0,0 }       /* e.g. lptea */
#define INSTR_RRF_R0RR     4, { R_24,R_16,R_28,0,0,0 }           /* e.g. idte  */
#define INSTR_RRF_R0RR2    4, { R_24,R_28,R_16,0,0,0 }           /* e.g. ark   */
#define INSTR_RRF_R0RR3    4, { R_24,R_28,R_16,0,0,0 }           /* e.g. selrz */
#define INSTR_RRF_U0FF     4, { F_24,U4_16,F_28,0,0,0 }          /* e.g. fidbr */
#define INSTR_RRF_U0FEFE   4, { FE_24,U4_16,FE_28,0,0,0 }        /* e.g. fixbr */
#define INSTR_RRF_U0RF     4, { R_24,U4_16,F_28,0,0,0 }          /* e.g. cfebr */
#define INSTR_RRF_U0RFE    4, { R_24,U4_16,FE_28,0,0,0 }         /* e.g. cfxbr */
#define INSTR_RRF_UUFF     4, { F_24,U4_16,F_28,U4_20,0,0 }      /* e.g. fidtr */
#define INSTR_RRF_UUFFE    4, { F_24,U4_16,FE_28,U4_20,0,0 }     /* e.g. ldxtr */
#define INSTR_RRF_UUFEFE   4, { FE_24,U4_16,FE_28,U4_20,0,0 }    /* e.g. fixtr */
#define INSTR_RRF_0UFF     4, { F_24,F_28,U4_20,0,0,0 }          /* e.g. ldetr */
#define INSTR_RRF_0UFEF    4, { FE_24,F_28,U4_20,0,0,0 }         /* e.g. lxdtr */
#define INSTR_RRF_FFRU     4, { F_24,F_16,R_28,U4_20,0,0 }       /* e.g. rrdtr */
#define INSTR_RRF_FEFERU   4, { FE_24,FE_16,R_28,U4_20,0,0 }     /* e.g. rrxtr */
#define INSTR_RRF_U0RR     4, { R_24,R_28,U4_16,0,0,0 }          /* e.g. sske  */
#define INSTR_RRF_U0RER    4, { RE_24,R_28,U4_16,0,0,0 }         /* e.g. trte  */
#define INSTR_RRF_U0RERE   4, { RE_24,RE_28,U4_16,0,0,0 }        /* e.g. cu24  */
#define INSTR_RRF_00RR     4, { R_24,R_28,0,0,0,0 }              /* e.g. clrtne */
#define INSTR_RRF_0URF     4, { R_24,F_28,U4_20,0,0,0 }          /* e.g. csdtr  */
#define INSTR_RRF_0UREFE   4, { RE_24,FE_28,U4_20,0,0,0 }        /* e.g. csxtr  */
#define INSTR_RRF_UUFR     4, { F_24,U4_16,R_28,U4_20,0,0 }      /* e.g. cdgtra */
#define INSTR_RRF_UUFER    4, { FE_24,U4_16,R_28,U4_20,0,0 }     /* e.g. cxfbra */
#define INSTR_RRF_UURF     4, { R_24,U4_16,F_28,U4_20,0,0 }      /* e.g. cgdtra */
#define INSTR_RRF_UURFE    4, { R_24,U4_16,FE_28,U4_20,0,0 }     /* e.g. cfxbra */
#define INSTR_RR_0R        2, { R_12, 0,0,0,0,0 }                /* e.g. br    */
#define INSTR_RR_FF        2, { F_8,F_12,0,0,0,0 }               /* e.g. adr   */
#define INSTR_RR_FEF       2, { FE_8,F_12,0,0,0,0 }              /* e.g. mxdr  */
#define INSTR_RR_FFE       2, { F_8,FE_12,0,0,0,0 }              /* e.g. ldxr  */
#define INSTR_RR_FEFE      2, { FE_8,FE_12,0,0,0,0 }             /* e.g. axr   */
#define INSTR_RR_R0        2, { R_8, 0,0,0,0,0 }                 /* e.g. spm   */
#define INSTR_RR_RR        2, { R_8,R_12,0,0,0,0 }               /* e.g. lr    */
#define INSTR_RR_RER       2, { RE_8,R_12,0,0,0,0 }              /* e.g. dr    */
#define INSTR_RR_U0        2, { U8_8, 0,0,0,0,0 }                /* e.g. svc   */
#define INSTR_RR_UR        2, { U4_8,R_12,0,0,0,0 }              /* e.g. bcr   */
#define INSTR_RRR_F0FF     4, { F_24,F_28,F_16,0,0,0 }           /* e.g. ddtr  */
#define INSTR_RRR_FE0FEFE  4, { FE_24,FE_28,FE_16,0,0,0 }        /* e.g. axtr  */
#define INSTR_RRS_RRRDU    6, { R_8,R_12,U4_32,D_20,B_16 }       /* e.g. crb   */
#define INSTR_RRS_RRRD0    6, { R_8,R_12,D_20,B_16,0 }           /* e.g. crbne */
#define INSTR_RSE_RRRD     6, { R_8,R_12,D_20,B_16,0,0 }         /* e.g. lmh   */
#define INSTR_RSE_RERERD   6, { RE_8,RE_12,D_20,B_16,0,0 }       /* e.g. mvclu */
#define INSTR_RSE_CCRD     6, { C_8,C_12,D_20,B_16,0,0 }         /* e.g. stctg */
#define INSTR_RSE_RURD     6, { R_8,U4_12,D_20,B_16,0,0 }        /* e.g. icmh  */
#define INSTR_RSL_R0RD     6, { D_20,L4_8,B_16,0,0,0 }           /* e.g. tp    */
#define INSTR_RSL_LRDFU    6, { F_32,D_20,L8_8,B_16,U4_36,0 }    /* e.g. cdzt  */
#define INSTR_RSL_LRDFEU   6, { FE_32,D_20,L8_8,B_16,U4_36,0 }   /* e.g. cxzt  */
#define INSTR_RSI_RRP      4, { R_8,R_12,J16_16,0,0,0 }          /* e.g. brxh  */
#define INSTR_RSY_RRRD     6, { R_8,R_12,D20_20,B_16,0,0 }       /* e.g. stmy  */
#define INSTR_RSY_RERERD   6, { RE_8,RE_12,D20_20,B_16,0,0 }     /* e.g. cdsy  */
#define INSTR_RSY_RURD     6, { R_8,U4_12,D20_20,B_16,0,0 }      /* e.g. icmh  */
#define INSTR_RSY_RURD2    6, { R_8,D20_20,B_16,U4_12,0,0 }      /* e.g. loc   */
#define INSTR_RSY_R0RD     6, { R_8,D20_20,B_16,0,0,0 }          /* e.g. locne */
#define INSTR_RSY_AARD     6, { A_8,A_12,D20_20,B_16,0,0 }       /* e.g. lamy  */
#define INSTR_RSY_CCRD     6, { C_8,C_12,D20_20,B_16,0,0 }       /* e.g. stctg */
#define INSTR_RS_AARD      4, { A_8,A_12,D_20,B_16,0,0 }         /* e.g. lam   */
#define INSTR_RS_CCRD      4, { C_8,C_12,D_20,B_16,0,0 }         /* e.g. lctl  */
#define INSTR_RS_R0RD      4, { R_8,D_20,B_16,0,0,0 }            /* e.g. sll   */
#define INSTR_RS_RE0RD     4, { RE_8,D_20,B_16,0,0,0 }           /* e.g. slda  */
#define INSTR_RS_RRRD      4, { R_8,R_12,D_20,B_16,0,0 }         /* e.g. cs    */
#define INSTR_RS_RERERD    4, { RE_8,RE_12,D_20,B_16,0,0 }       /* e.g. cds   */
#define INSTR_RS_RURD      4, { R_8,U4_12,D_20,B_16,0,0 }        /* e.g. icm   */
#define INSTR_RXE_FRRD     6, { F_8,D_20,X_12,B_16,0,0 }         /* e.g. adb   */
#define INSTR_RXE_FERRD    6, { FE_8,D_20,X_12,B_16,0,0 }        /* e.g. lxdb  */
#define INSTR_RXE_RRRD     6, { R_8,D_20,X_12,B_16,0,0 }         /* e.g. lg    */
#define INSTR_RXE_RRRDU    6, { R_8,D_20,X_12,B_16,U4_32,0 }     /* e.g. lcbb  */
#define INSTR_RXE_RERRD    6, { RE_8,D_20,X_12,B_16,0,0 }        /* e.g. dsg   */
#define INSTR_RXF_FRRDF    6, { F_32,F_8,D_20,X_12,B_16,0 }      /* e.g. madb  */
#define INSTR_RXF_FRRDFE   6, { FE_32,F_8,D_20,X_12,B_16,0 }     /* e.g. my    */
#define INSTR_RXF_FERRDFE  6, { FE_32,FE_8,D_20,X_12,B_16,0 }    /* e.g. slxt  */
#define INSTR_RXF_RRRDR    6, { R_32,R_8,D_20,X_12,B_16,0 }      /* e.g. .insn */
#define INSTR_RXY_RRRD     6, { R_8,D20_20,X_12,B_16,0,0 }       /* e.g. ly    */
#define INSTR_RXY_RERRD    6, { RE_8,D20_20,X_12,B_16,0,0 }      /* e.g. dsg   */
#define INSTR_RXY_FRRD     6, { F_8,D20_20,X_12,B_16,0,0 }       /* e.g. ley   */
#define INSTR_RXY_URRD     6, { U4_8,D20_20,X_12,B_16,0,0 }      /* e.g. pfd   */
#define INSTR_RXY_0RRD     6, { D20_20,X_12,B_16,0,0 }           /* e.g. bic   */
#define INSTR_RX_0RRD      4, { D_20,X_12,B_16,0,0,0 }           /* e.g. be    */
#define INSTR_RX_FRRD      4, { F_8,D_20,X_12,B_16,0,0 }         /* e.g. ae    */
#define INSTR_RX_FERRD     4, { FE_8,D_20,X_12,B_16,0,0 }        /* e.g. mxd   */
#define INSTR_RX_RRRD      4, { R_8,D_20,X_12,B_16,0,0 }         /* e.g. l     */
#define INSTR_RX_RERRD     4, { RE_8,D_20,X_12,B_16,0,0 }        /* e.g. d     */
#define INSTR_RX_URRD      4, { U4_8,D_20,X_12,B_16,0,0 }        /* e.g. bc    */
#define INSTR_SI_RD        4, { D_20,B_16,0,0,0,0 }              /* e.g. lpsw  */
#define INSTR_SI_URD       4, { D_20,B_16,U8_8,0,0,0 }           /* e.g. cli   */
#define INSTR_SIY_URD      6, { D20_20,B_16,U8_8,0,0,0 }         /* e.g. tmy   */
#define INSTR_SIY_IRD      6, { D20_20,B_16,I8_8,0,0,0 }         /* e.g. asi   */
#define INSTR_SIL_RDI      6, { D_20,B_16,I16_32,0,0,0 }         /* e.g. chhsi */
#define INSTR_SIL_RDU      6, { D_20,B_16,U16_32,0,0,0 }         /* e.g. clfhsi */
#define INSTR_SMI_U0RDP    6, { U4_8,J16_32,D_20,B_16,0,0 }      /* e.g. bpp   */
#define INSTR_SSE_RDRD     6, { D_20,B_16,D_36,B_32,0,0 }        /* e.g. mvcdk */
#define INSTR_SS_L0RDRD    6, { D_20,L8_8,B_16,D_36,B_32,0     } /* e.g. mvc   */
#define INSTR_SS_L2RDRD    6, { D_20,B_16,D_36,L8_8,B_32,0     } /* e.g. pka   */
#define INSTR_SS_LIRDRD    6, { D_20,L4_8,B_16,D_36,B_32,U4_12 } /* e.g. srp   */
#define INSTR_SS_LLRDRD    6, { D_20,L4_8,B_16,D_36,L4_12,B_32 } /* e.g. pack  */
#define INSTR_SS_RRRDRD    6, { D_20,R_8,B_16,D_36,B_32,R_12 }   /* e.g. mvck  */
#define INSTR_SS_RRRDRD2   6, { R_8,D_20,B_16,R_12,D_36,B_32 }   /* e.g. plo   */
#define INSTR_SS_RRRDRD3   6, { R_8,R_12,D_20,B_16,D_36,B_32 }   /* e.g. lmd   */
#define INSTR_SSF_RRDRD    6, { D_20,B_16,D_36,B_32,R_8,0 }      /* e.g. mvcos */
#define INSTR_SSF_RERDRD2  6, { RE_8,D_20,B_16,D_36,B_32,0 }     /* e.g. lpd   */
#define INSTR_S_00         4, { 0,0,0,0,0,0 }                    /* e.g. hsch  */
#define INSTR_S_RD         4, { D_20,B_16,0,0,0,0 }              /* e.g. stck  */
#define INSTR_VRV_VVXRDU   6, { V_8,D_20,VX_12,B_16,U4_32,0 }    /* e.g. vgef  */
#define INSTR_VRI_V0U      6, { V_8,U16_16,0,0,0,0 }             /* e.g. vgbm  */
#define INSTR_VRI_V        6, { V_8,0,0,0,0,0 }                  /* e.g. vzero */
#define INSTR_VRI_V0UUU    6, { V_8,U8_16,U8_24,U4_32,0,0 }      /* e.g. vgm   */
#define INSTR_VRI_V0UU     6, { V_8,U8_16,U8_24,0,0,0 }          /* e.g. vgmb  */
#define INSTR_VRI_V0UU2    6, { V_8,U16_16,U4_32,0,0,0 }         /* e.g. vlip  */
#define INSTR_VRI_VVUU     6, { V_8,V_12,U16_16,U4_32,0,0 }      /* e.g. vrep  */
#define INSTR_VRI_VVU      6, { V_8,V_12,U16_16,0,0,0 }          /* e.g. vrepb */
#define INSTR_VRI_VVU2     6, { V_8,V_12,U12_16,0,0,0 }          /* e.g. vftcidb */
#define INSTR_VRI_V0IU     6, { V_8,I16_16,U4_32,0,0,0 }         /* e.g. vrepi */
#define INSTR_VRI_V0I      6, { V_8,I16_16,0,0,0,0 }             /* e.g. vrepib */
#define INSTR_VRI_VVV0UU   6, { V_8,V_12,V_16,U8_24,U4_32,0 }    /* e.g. verim */
#define INSTR_VRI_VVV0UU2  6, { V_8,V_12,V_16,U8_28,U4_24,0 }    /* e.g. vap   */
#define INSTR_VRI_VVV0U    6, { V_8,V_12,V_16,U8_24,0,0 }        /* e.g. verimb*/
#define INSTR_VRI_VVUUU    6, { V_8,V_12,U12_16,U4_32,U4_28,0 }  /* e.g. vftci */
#define INSTR_VRI_VVUUU2   6, { V_8,V_12,U8_28,U8_16,U4_24,0 }   /* e.g. vpsop */
#define INSTR_VRI_VR0UU    6, { V_8,R_12,U8_28,U4_24,0,0 }       /* e.g. vcvd  */
#define INSTR_VRX_VRRD     6, { V_8,D_20,X_12,B_16,0,0 }         /* e.g. vl    */
#define INSTR_VRX_VV       6, { V_8,V_12,0,0,0,0 }               /* e.g. vlr   */
#define INSTR_VRX_VRRDU    6, { V_8,D_20,X_12,B_16,U4_32,0 }     /* e.g. vlrep */
#define INSTR_VRS_RVRDU    6, { R_8,V_12,D_20,B_16,U4_32,0 }     /* e.g. vlgv  */
#define INSTR_VRS_RVRD     6, { R_8,V_12,D_20,B_16,0,0 }         /* e.g. vlgvb */
#define INSTR_VRS_VVRDU    6, { V_8,V_12,D_20,B_16,U4_32,0 }     /* e.g. verll */
#define INSTR_VRS_VVRD     6, { V_8,V_12,D_20,B_16,0,0 }         /* e.g. vlm   */
#define INSTR_VRS_VRRDU    6, { V_8,R_12,D_20,B_16,U4_32,0 }     /* e.g. vlvg  */
#define INSTR_VRS_VRRD     6, { V_8,R_12,D_20,B_16,0,0 }         /* e.g. vlvgb */
#define INSTR_VRS_RRDV     6, { V_32,R_12,D_20,B_16,0,0 }        /* e.g. vlrlr */
#define INSTR_VRR_0V       6, { V_12,0,0,0,0,0 }                 /* e.g. vtp   */
#define INSTR_VRR_VRR      6, { V_8,R_12,R_16,0,0,0 }            /* e.g. vlvgp */
#define INSTR_VRR_VVV0U    6, { V_8,V_12,V_16,U4_32,0,0 }        /* e.g. vmrh  */
#define INSTR_VRR_VVV0U0   6, { V_8,V_12,V_16,U4_24,0,0 }        /* e.g. vfaeb */
#define INSTR_VRR_VVV0U1   6, { V_8,V_12,V_16,U4_OR1_24,0,0 }    /* e.g. vfaebs*/
#define INSTR_VRR_VVV0U2   6, { V_8,V_12,V_16,U4_OR2_24,0,0 }    /* e.g. vfaezb*/
#define INSTR_VRR_VVV0U3   6, { V_8,V_12,V_16,U4_OR3_24,0,0 }    /* e.g. vfaezbs*/
#define INSTR_VRR_VVV      6, { V_8,V_12,V_16,0,0,0 }            /* e.g. vmrhb */
#define INSTR_VRR_VVV2     6, { V_8,V_CP16_12,0,0,0,0 }          /* e.g. vnot  */
#define INSTR_VRR_VV0U     6, { V_8,V_12,U4_32,0,0,0 }           /* e.g. vseg  */
#define INSTR_VRR_VV0U2    6, { V_8,V_12,U4_24,0,0,0 }           /* e.g. vistrb*/
#define INSTR_VRR_VV0UU    6, { V_8,V_12,U4_28,U4_24,0,0 }       /* e.g. vcdgb */
#define INSTR_VRR_VV0UU2   6, { V_8,V_12,U4_32,U4_28,0,0 }       /* e.g. wfc */
#define INSTR_VRR_VV0UU8   6, { V_8,V_12,U4_OR8_28,U4_24,0,0 }   /* e.g. wcdgb */
#define INSTR_VRR_VV       6, { V_8,V_12,0,0,0,0 }               /* e.g. vsegb */
#define INSTR_VRR_VVVUU0V  6, { V_8,V_12,V_16,V_32,U4_20,U4_24 } /* e.g. vstrc */
#define INSTR_VRR_VVVU0V   6, { V_8,V_12,V_16,V_32,U4_20,0 }     /* e.g. vac   */
#define INSTR_VRR_VVVU0VB  6, { V_8,V_12,V_16,V_32,U4_24,0 }     /* e.g. vstrcb*/
#define INSTR_VRR_VVVU0VB1 6, { V_8,V_12,V_16,V_32,U4_OR1_24,0 } /* e.g. vstrcbs*/
#define INSTR_VRR_VVVU0VB2 6, { V_8,V_12,V_16,V_32,U4_OR2_24,0 } /* e.g. vstrczb*/
#define INSTR_VRR_VVVU0VB3 6, { V_8,V_12,V_16,V_32,U4_OR3_24,0 } /* e.g. vstrczbs*/
#define INSTR_VRR_VVV0V    6, { V_8,V_12,V_16,V_32,0,0 }         /* e.g. vacq  */
#define INSTR_VRR_VVV0U0U  6, { V_8,V_12,V_16,U4_32,U4_24,0 }    /* e.g. vfae  */
#define INSTR_VRR_VVVV     6, { V_8,V_12,V_16,V_32,0,0 }         /* e.g. vfmadb*/
#define INSTR_VRR_VVV0UUU  6, { V_8,V_12,V_16,U4_32,U4_28,U4_24 }/* e.g. vfch  */
#define INSTR_VRR_VVV0UU   6, { V_8,V_12,V_16,U4_32,U4_28,0 }    /* e.g. vfa   */
#define INSTR_VRR_VV0UUU   6, { V_8,V_12,U4_32,U4_28,U4_24,0 }   /* e.g. vcdg  */
#define INSTR_VRR_VVVU0UV  6, { V_8,V_12,V_16,V_32,U4_28,U4_20 } /* e.g. vfma  */
#define INSTR_VRR_VV0U0U   6, { V_8,V_12,U4_32,U4_24,0,0 }       /* e.g. vistr */
#define INSTR_VRR_0VV0U    6, { V_12,V_16,U4_24,0,0,0 }          /* e.g. vcp   */
#define INSTR_VRR_RV0U     6, { R_8,V_12,U4_24,0,0,0 }           /* e.g. vcvb  */
#define INSTR_VRR_RV0UU    6, { R_8,V_12,U4_24,U4_28,0,0 }       /* e.g. vcvb  */
#define INSTR_VSI_URDV     6, { V_32,D_20,B_16,U8_8,0,0 }        /* e.g. vlrl  */

#define MASK_E            { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_IE_UU        { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_MII_UPP      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RIE_RRP      { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIE_RRPU     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIE_RRP0     { 0xff, 0x00, 0x00, 0x00, 0xf0, 0xff }
#define MASK_RIE_RRI0     { 0xff, 0x00, 0x00, 0x00, 0xf0, 0xff }
#define MASK_RIE_RUPI     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIE_R0PI     { 0xff, 0x0f, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIE_RUPU     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIE_R0PU     { 0xff, 0x0f, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIE_R0IU     { 0xff, 0x0f, 0x00, 0x00, 0x0f, 0xff }
#define MASK_RIE_R0I0     { 0xff, 0x0f, 0x00, 0x00, 0xff, 0xff }
#define MASK_RIE_R0UU     { 0xff, 0x0f, 0x00, 0x00, 0x0f, 0xff }
#define MASK_RIE_R0U0     { 0xff, 0x0f, 0x00, 0x00, 0xff, 0xff }
#define MASK_RIE_RUI0     { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RIE_RRUUU    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIE_RRUUU2   { 0xff, 0x00, 0x00, 0xc0, 0x00, 0xff }
#define MASK_RIL_0P       { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RIL_RP       { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RIL_UP       { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RIL_RI       { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RIL_RU       { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RI_0P        { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RI_RI        { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RI_RP        { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RI_RU        { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RI_UP        { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RIS_RURDI    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIS_R0RDI    { 0xff, 0x0f, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIS_RURDU    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RIS_R0RDU    { 0xff, 0x0f, 0x00, 0x00, 0x00, 0xff }
#define MASK_RRE_00       { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 }
#define MASK_RRE_0R       { 0xff, 0xff, 0xff, 0xf0, 0x00, 0x00 }
#define MASK_RRE_AA       { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_AR       { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_F0       { 0xff, 0xff, 0xff, 0x0f, 0x00, 0x00 }
#define MASK_RRE_FE0      { 0xff, 0xff, 0xff, 0x0f, 0x00, 0x00 }
#define MASK_RRE_FF       { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_FEF      { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_FFE      { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_FEFE     { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_R0       { 0xff, 0xff, 0xff, 0x0f, 0x00, 0x00 }
#define MASK_RRE_RA       { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_RF       { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_RFE      { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_RR       { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_RER      { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_RERE     { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_FR       { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRE_FER      { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRF_F0FF     { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_FE0FF    { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_F0FF2    { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_F0FR     { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_FE0FER   { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_FUFF     { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_FEUFEFE  { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_FUFF2    { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_FEUFEFE2 { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_RURR     { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_RURR2    { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_R0RR     { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_R0RR2    { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_R0RR3    { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_U0FF     { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_U0FEFE   { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_U0RF     { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_U0RFE    { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_UUFF     { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_UUFFE    { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_UUFEFE   { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_0UFF     { 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00 }
#define MASK_RRF_0UFEF    { 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00 }
#define MASK_RRF_FFRU     { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_FEFERU   { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_U0RR     { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_U0RER    { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_U0RERE   { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRF_00RR     { 0xff, 0xff, 0xff, 0x00, 0x00, 0x00 }
#define MASK_RRF_0URF     { 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00 }
#define MASK_RRF_0UREFE   { 0xff, 0xff, 0xf0, 0x00, 0x00, 0x00 }
#define MASK_RRF_UUFR     { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_UUFER    { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_UURF     { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRF_UURFE    { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_0R        { 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_FF        { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_FEF       { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_FFE       { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_FEFE      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_R0        { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_RR        { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_RER       { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_U0        { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RR_UR        { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RRR_F0FF     { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRR_FE0FEFE  { 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00 }
#define MASK_RRS_RRRDU    { 0xff, 0x00, 0x00, 0x00, 0x0f, 0xff }
#define MASK_RRS_RRRD0    { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RSE_RRRD     { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RSE_RERERD   { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RSE_CCRD     { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RSE_RURD     { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RSL_R0RD     { 0xff, 0x0f, 0x00, 0x00, 0xff, 0xff }
#define MASK_RSL_LRDFU    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RSL_LRDFEU   { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RSI_RRP      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RS_AARD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RS_CCRD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RS_R0RD      { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RS_RE0RD     { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RS_RRRD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RS_RERERD    { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RS_RURD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RSY_RRRD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RSY_RERERD   { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RSY_RURD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RSY_RURD2    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RSY_R0RD     { 0xff, 0x0f, 0x00, 0x00, 0x00, 0xff }
#define MASK_RSY_AARD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RSY_CCRD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RXE_FRRD     { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RXE_FERRD    { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RXE_RRRD     { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RXE_RRRDU    { 0xff, 0x00, 0x00, 0x00, 0x0f, 0xff }
#define MASK_RXE_RERRD    { 0xff, 0x00, 0x00, 0x00, 0xff, 0xff }
#define MASK_RXF_FRRDF    { 0xff, 0x00, 0x00, 0x00, 0x0f, 0xff }
#define MASK_RXF_FRRDFE   { 0xff, 0x00, 0x00, 0x00, 0x0f, 0xff }
#define MASK_RXF_FERRDFE  { 0xff, 0x00, 0x00, 0x00, 0x0f, 0xff }
#define MASK_RXF_RRRDR    { 0xff, 0x00, 0x00, 0x00, 0x0f, 0xff }
#define MASK_RXY_RRRD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RXY_RERRD    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RXY_FRRD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RXY_URRD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_RXY_0RRD     { 0xff, 0xf0, 0x00, 0x00, 0x00, 0xff }
#define MASK_RX_0RRD      { 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RX_FRRD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RX_FERRD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RX_RRRD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RX_RERRD     { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_RX_URRD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SI_RD        { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SI_URD       { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SIY_URD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_SIY_IRD      { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_SIL_RDI      { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SIL_RDU      { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SMI_U0RDP    { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SSE_RDRD     { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SS_L0RDRD    { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SS_L2RDRD    { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SS_LIRDRD    { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SS_LLRDRD    { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SS_RRRDRD    { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SS_RRRDRD2   { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SS_RRRDRD3   { 0xff, 0x00, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SSF_RRDRD    { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_SSF_RERDRD2  { 0xff, 0x0f, 0x00, 0x00, 0x00, 0x00 }
#define MASK_S_00         { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 }
#define MASK_S_RD         { 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }
#define MASK_VRV_VVXRDU   { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRI_V0U      { 0xff, 0x0f, 0x00, 0x00, 0xf0, 0xff }
#define MASK_VRI_V        { 0xff, 0x0f, 0xff, 0xff, 0xf0, 0xff }
#define MASK_VRI_V0UUU    { 0xff, 0x0f, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRI_V0UU     { 0xff, 0x0f, 0x00, 0x00, 0xf0, 0xff }
#define MASK_VRI_V0UU2    { 0xff, 0x0f, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRI_VVUU     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRI_VVU      { 0xff, 0x00, 0x00, 0x00, 0xf0, 0xff }
#define MASK_VRI_VVU2     { 0xff, 0x00, 0x00, 0x0f, 0xf0, 0xff }
#define MASK_VRI_V0IU     { 0xff, 0x0f, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRI_V0I      { 0xff, 0x0f, 0x00, 0x00, 0xf0, 0xff }
#define MASK_VRI_VVV0UU   { 0xff, 0x00, 0x0f, 0x00, 0x00, 0xff }
#define MASK_VRI_VVV0UU2  { 0xff, 0x00, 0x0f, 0x00, 0x00, 0xff }
#define MASK_VRI_VVV0U    { 0xff, 0x00, 0x0f, 0x00, 0xf0, 0xff }
#define MASK_VRI_VVUUU    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRI_VVUUU2   { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRI_VR0UU    { 0xff, 0x00, 0xff, 0x00, 0x00, 0xff }
#define MASK_VRX_VRRD     { 0xff, 0x00, 0x00, 0x00, 0xf0, 0xff }
#define MASK_VRX_VV       { 0xff, 0x00, 0xff, 0xff, 0xf0, 0xff }
#define MASK_VRX_VRRDU    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRS_RVRDU    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRS_RVRD     { 0xff, 0x00, 0x00, 0x00, 0xf0, 0xff }
#define MASK_VRS_VVRDU    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRS_VVRD     { 0xff, 0x00, 0x00, 0x00, 0xf0, 0xff }
#define MASK_VRS_VRRDU    { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRS_VRRD     { 0xff, 0x00, 0x00, 0x00, 0xf0, 0xff }
#define MASK_VRS_RRDV     { 0xff, 0xf0, 0x00, 0x00, 0x00, 0xff }
#define MASK_VRR_0V       { 0xff, 0xf0, 0xff, 0xff, 0xf0, 0xff }
#define MASK_VRR_VRR      { 0xff, 0x00, 0x0f, 0xff, 0xf0, 0xff }
#define MASK_VRR_VVV0U    { 0xff, 0x00, 0x0f, 0xff, 0x00, 0xff }
#define MASK_VRR_VVV0U0   { 0xff, 0x00, 0x0f, 0x0f, 0xf0, 0xff }
#define MASK_VRR_VVV0U1   { 0xff, 0x00, 0x0f, 0x1f, 0xf0, 0xff }
#define MASK_VRR_VVV0U2   { 0xff, 0x00, 0x0f, 0x2f, 0xf0, 0xff }
#define MASK_VRR_VVV0U3   { 0xff, 0x00, 0x0f, 0x3f, 0xf0, 0xff }
#define MASK_VRR_VVV      { 0xff, 0x00, 0x0f, 0xff, 0xf0, 0xff }
#define MASK_VRR_VVV2     { 0xff, 0x00, 0x0f, 0xff, 0xf0, 0xff }
#define MASK_VRR_VVV0V    { 0xff, 0x00, 0x0f, 0xff, 0x00, 0xff }
#define MASK_VRR_VV0U     { 0xff, 0x00, 0xff, 0xff, 0x00, 0xff }
#define MASK_VRR_VV0U2    { 0xff, 0x00, 0xff, 0x0f, 0xf0, 0xff }
#define MASK_VRR_VV0UU    { 0xff, 0x00, 0xff, 0x00, 0xf0, 0xff }
#define MASK_VRR_VV0UU2   { 0xff, 0x00, 0xff, 0xf0, 0x00, 0xff }
#define MASK_VRR_VV0UU8   { 0xff, 0x00, 0xff, 0x08, 0xf0, 0xff }
#define MASK_VRR_VV       { 0xff, 0x00, 0xff, 0xff, 0xf0, 0xff }
#define MASK_VRR_VVVUU0V  { 0xff, 0x00, 0x00, 0x0f, 0x00, 0xff }
#define MASK_VRR_VVVU0V   { 0xff, 0x00, 0x00, 0xff, 0x00, 0xff }
#define MASK_VRR_VVVU0VB  { 0xff, 0x00, 0x0f, 0x0f, 0x00, 0xff }
#define MASK_VRR_VVVU0VB1 { 0xff, 0x00, 0x0f, 0x1f, 0x00, 0xff }
#define MASK_VRR_VVVU0VB2 { 0xff, 0x00, 0x0f, 0x2f, 0x00, 0xff }
#define MASK_VRR_VVVU0VB3 { 0xff, 0x00, 0x0f, 0x3f, 0x00, 0xff }
#define MASK_VRR_VVV0U0U  { 0xff, 0x00, 0x0f, 0x0f, 0x00, 0xff }
#define MASK_VRR_VVVV     { 0xff, 0x00, 0x0f, 0xff, 0x00, 0xff }
#define MASK_VRR_VVV0UUU  { 0xff, 0x00, 0x0f, 0x00, 0x00, 0xff }
#define MASK_VRR_VVV0UU   { 0xff, 0x00, 0x0f, 0xf0, 0x00, 0xff }
#define MASK_VRR_VV0UUU   { 0xff, 0x00, 0xff, 0x00, 0x00, 0xff }
#define MASK_VRR_VVVU0UV  { 0xff, 0x00, 0x00, 0xf0, 0x00, 0xff }
#define MASK_VRR_VV0U0U   { 0xff, 0x00, 0xff, 0x0f, 0x00, 0xff }
#define MASK_VRR_0VV0U    { 0xff, 0xf0, 0x0f, 0x0f, 0xf0, 0xff }
#define MASK_VRR_RV0U     { 0xff, 0x00, 0xff, 0x0f, 0xf0, 0xff }
#define MASK_VRR_RV0UU    { 0xff, 0x00, 0xff, 0x00, 0xf0, 0xff }
#define MASK_VSI_URDV     { 0xff, 0x00, 0x00, 0x00, 0x00, 0xff }


/* The opcode formats table (blueprints for .insn pseudo mnemonic).  */

const struct s390_opcode s390_opformats[] =
  {
  { "e",    OP8(0x00LL), MASK_E,	   INSTR_E,	      3,  0 ,0 },
  { "ri",   OP8(0x00LL), MASK_RI_RI,	   INSTR_RI_RI,	      3,  0 ,0 },
  { "rie",  OP8(0x00LL), MASK_RIE_RRP,	   INSTR_RIE_RRP,     3,  0 ,0 },
  { "ril",  OP8(0x00LL), MASK_RIL_RP,	   INSTR_RIL_RP,      3,  0 ,0 },
  { "rilu", OP8(0x00LL), MASK_RIL_RU,	   INSTR_RIL_RU,      3,  0 ,0 },
  { "ris",  OP8(0x00LL), MASK_RIS_RURDI,   INSTR_RIS_RURDI,   3,  6 ,0 },
  { "rr",   OP8(0x00LL), MASK_RR_RR,	   INSTR_RR_RR,       3,  0 ,0 },
  { "rre",  OP8(0x00LL), MASK_RRE_RR,	   INSTR_RRE_RR,      3,  0 ,0 },
  { "rrf",  OP8(0x00LL), MASK_RRF_RURR,	   INSTR_RRF_RURR,    3,  0 ,0 },
  { "rrs",  OP8(0x00LL), MASK_RRS_RRRDU,   INSTR_RRS_RRRDU,   3,  6 ,0 },
  { "rs",   OP8(0x00LL), MASK_RS_RRRD,	   INSTR_RS_RRRD,     3,  0 ,0 },
  { "rse",  OP8(0x00LL), MASK_RSE_RRRD,	   INSTR_RSE_RRRD,    3,  0 ,0 },
  { "rsi",  OP8(0x00LL), MASK_RSI_RRP,	   INSTR_RSI_RRP,     3,  0 ,0 },
  { "rsy",  OP8(0x00LL), MASK_RSY_RRRD,	   INSTR_RSY_RRRD,    3,  3 ,0 },
  { "rx",   OP8(0x00LL), MASK_RX_RRRD,	   INSTR_RX_RRRD,     3,  0 ,0 },
  { "rxe",  OP8(0x00LL), MASK_RXE_RRRD,	   INSTR_RXE_RRRD,    3,  0 ,0 },
  { "rxf",  OP8(0x00LL), MASK_RXF_RRRDR,   INSTR_RXF_RRRDR,   3,  0 ,0 },
  { "rxy",  OP8(0x00LL), MASK_RXY_RRRD,	   INSTR_RXY_RRRD,    3,  3 ,0 },
  { "s",    OP8(0x00LL), MASK_S_RD,	   INSTR_S_RD,	      3,  0 ,0 },
  { "si",   OP8(0x00LL), MASK_SI_URD,	   INSTR_SI_URD,      3,  0 ,0 },
  { "siy",  OP8(0x00LL), MASK_SIY_URD,	   INSTR_SIY_URD,     3,  3 ,0 },
  { "sil",  OP8(0x00LL), MASK_SIL_RDI,     INSTR_SIL_RDI,     3,  6 ,0 },
  { "ss",   OP8(0x00LL), MASK_SS_RRRDRD,   INSTR_SS_RRRDRD,   3,  0 ,0 },
  { "sse",  OP8(0x00LL), MASK_SSE_RDRD,	   INSTR_SSE_RDRD,    3,  0 ,0 },
  { "ssf",  OP8(0x00LL), MASK_SSF_RRDRD,   INSTR_SSF_RRDRD,   3,  0 ,0 },
  { "vrv",  OP8(0x00LL), MASK_VRV_VVXRDU,  INSTR_VRV_VVXRDU,  3,  9 ,0 },
  { "vri",  OP8(0x00LL), MASK_VRI_VVUUU,   INSTR_VRI_VVUUU,   3,  9 ,0 },
  { "vrx",  OP8(0x00LL), MASK_VRX_VRRDU,   INSTR_VRX_VRRDU,   3,  9 ,0 },
  { "vrs",  OP8(0x00LL), MASK_VRS_RVRDU,   INSTR_VRS_RVRDU,   3,  9 ,0 },
  { "vrr",  OP8(0x00LL), MASK_VRR_VVV0UUU, INSTR_VRR_VVV0UUU, 3,  9 ,0 },
  { "vsi",  OP8(0x00LL), MASK_VSI_URDV,	   INSTR_VSI_URDV,    3, 10 ,0 },
};

const int s390_num_opformats =
  sizeof (s390_opformats) / sizeof (s390_opformats[0]);

#include "s390-opc.tab"
