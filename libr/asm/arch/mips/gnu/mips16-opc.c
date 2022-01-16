/*
  Based on commits 250d07de5cf6efc81ed934c25292beb63c7e3129 from master branch
  of binutils-gdb.
*/
/* mips16-opc.c.  Mips16 opcode table.
   Copyright (C) 1996-2021 Free Software Foundation, Inc.
   Contributed by Ian Lance Taylor, Cygnus Support

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

#include "sysdep.h"
#include <stdio.h>
#include "opcode/mips.h"
#include "mips-formats.h"

static unsigned char reg_0_map[] = { 0 };
static unsigned char reg_29_map[] = { 29 };
static unsigned char reg_31_map[] = { 31 };
static unsigned char reg_m16_map[] = { 16, 17, 2, 3, 4, 5, 6, 7 };
static unsigned char reg32r_map[] = {
  0, 8, 16, 24,
  1, 9, 17, 25,
  2, 10, 18, 26,
  3, 11, 19, 27,
  4, 12, 20, 28,
  5, 13, 21, 29,
  6, 14, 22, 30,
  7, 15, 23, 31
};

/* Return the meaning of operand character TYPE, or null if it isn't
   recognized.  If the operand is affected by the EXTEND instruction,
   EXTENDED_P selects between the extended and unextended forms.
   The extended forms all have an lsb of 0.  */

const struct mips_operand *
decode_mips16_operand (char type, bfd_boolean extended_p)
{
  switch (type)
    {
    case '.': MAPPED_REG (0, 0, GP, reg_0_map);
    case '>': HINT (5, 22);

    case '0': HINT (5, 0);
    case '1': HINT (3, 5);
    case '2': HINT (3, 8);
    case '3': HINT (5, 16);
    case '4': HINT (3, 21);
    case '6': HINT (6, 5);
    case '9': SINT (9, 0);

    case 'G': SPECIAL (0, 0, REG28);
    case 'L': SPECIAL (6, 5, ENTRY_EXIT_LIST);
    case 'N': REG (5, 0, COPRO);
    case 'O': UINT (3, 21);
    case 'Q': REG (5, 16, HW);
    case 'P': SPECIAL (0, 0, PC);
    case 'R': MAPPED_REG (0, 0, GP, reg_31_map);
    case 'S': MAPPED_REG (0, 0, GP, reg_29_map);
    case 'T': HINT (5, 16);
    case 'X': REG (5, 0, GP);
    case 'Y': MAPPED_REG (5, 3, GP, reg32r_map);
    case 'Z': MAPPED_REG (3, 0, GP, reg_m16_map);

    case 'a': JUMP (26, 0, 2);
    case 'b': BIT (5, 22, 0);			/* (0 .. 31) */
    case 'c': MSB (5, 16, 1, TRUE, 32);		/* (1 .. 32) */
    case 'd': MSB (5, 16, 1, FALSE, 32);	/* (1 .. 32) */
    case 'e': HINT (11, 0);
    case 'i': JALX (26, 0, 2);
    case 'l': SPECIAL (6, 5, ENTRY_EXIT_LIST);
    case 'm': SPECIAL (7, 0, SAVE_RESTORE_LIST);
    case 'n': INT_BIAS (2, 0, 3, 1, 0, FALSE);	/* (1 .. 4) */
    case 'o': INT_ADJ (5, 16, 31, 4, FALSE);	/* (0 .. 31) << 4 */
    case 'r': MAPPED_REG (3, 16, GP, reg_m16_map);
    case 's': HINT (3, 24);
    case 'u': HINT (16, 0);
    case 'v': OPTIONAL_MAPPED_REG (3, 8, GP, reg_m16_map);
    case 'w': OPTIONAL_MAPPED_REG (3, 5, GP, reg_m16_map);
    case 'x': MAPPED_REG (3, 8, GP, reg_m16_map);
    case 'y': MAPPED_REG (3, 5, GP, reg_m16_map);
    case 'z': MAPPED_REG (3, 2, GP, reg_m16_map);
    }

  if (extended_p)
    switch (type)
      {
      case '<': UINT (5, 22);
      case '[': UINT (6, 0);
      case ']': UINT (6, 0);

      case '5': SINT (16, 0);
      case '8': SINT (16, 0);

      case 'A': PCREL (16, 0, TRUE, 0, 2, FALSE, FALSE);
      case 'B': PCREL (16, 0, TRUE, 0, 3, FALSE, FALSE);
      case 'C': SINT (16, 0);
      case 'D': SINT (16, 0);
      case 'E': PCREL (16, 0, TRUE, 0, 2, FALSE, FALSE);
      case 'F': SINT (15, 0);
      case 'H': SINT (16, 0);
      case 'K': SINT (16, 0);
      case 'U': UINT (16, 0);
      case 'V': SINT (16, 0);
      case 'W': SINT (16, 0);

      case 'j': SINT (16, 0);
      case 'k': SINT (16, 0);
      case 'p': BRANCH (16, 0, 1);
      case 'q': BRANCH (16, 0, 1);
      }
  else
    switch (type)
      {
      case '<': INT_ADJ (3, 2, 8, 0, FALSE);
      case '[': INT_ADJ (3, 2, 8, 0, FALSE);
      case ']': INT_ADJ (3, 8, 8, 0, FALSE);

      case '5': UINT (5, 0);
      case '8': UINT (8, 0);

      case 'A': PCREL (8, 0, FALSE, 2, 2, FALSE, FALSE);
      case 'B': PCREL (5, 0, FALSE, 3, 3, FALSE, FALSE);
      case 'C': INT_ADJ (8, 0, 255, 3, FALSE);	/* (0 .. 255) << 3 */
      case 'D': INT_ADJ (5, 0, 31, 3, FALSE);	/* (0 .. 31) << 3 */
      case 'E': PCREL (5, 0, FALSE, 2, 2, FALSE, FALSE);
      case 'F': SINT (4, 0);
      case 'H': INT_ADJ (5, 0, 31, 1, FALSE);	/* (0 .. 31) << 1 */
      case 'K': INT_ADJ (8, 0, 127, 3, FALSE);	/* (-128 .. 127) << 3 */
      case 'U': UINT (8, 0);
      case 'V': INT_ADJ (8, 0, 255, 2, FALSE);	/* (0 .. 255) << 2 */
      case 'W': INT_ADJ (5, 0, 31, 2, FALSE);	/* (0 .. 31) << 2 */

      case 'j': SINT (5, 0);
      case 'k': SINT (8, 0);
      case 'p': BRANCH (8, 0, 1);
      case 'q': BRANCH (11, 0, 1);
      }
  return 0;
}

/* This is the opcodes table for the mips16 processor.  The format of
   this table is intentionally identical to the one in mips-opc.c.
   However, the special letters that appear in the argument string are
   different, and the table uses some different flags.  */

/* Use some short hand macros to keep down the length of the lines in
   the opcodes table.  */

#define AL	INSN2_ALIAS

#define UBD     INSN_UNCOND_BRANCH_DELAY

#define WR_1	INSN_WRITE_1
#define WR_2	INSN_WRITE_2
#define RD_1	INSN_READ_1
#define RD_2	INSN_READ_2
#define RD_3	INSN_READ_3
#define RD_4	INSN_READ_4
#define MOD_1	(WR_1|RD_1)
#define MOD_2	(WR_2|RD_2)

#define RD_T	INSN_READ_GPR_24
#define WR_T	INSN_WRITE_GPR_24
#define WR_31	INSN_WRITE_GPR_31

#define RD_C0	INSN_COP
#define WR_C0	INSN_COP

#define WR_HI	INSN_WRITE_HI
#define WR_LO	INSN_WRITE_LO
#define RD_HI	INSN_READ_HI
#define RD_LO	INSN_READ_LO

#define NODS	INSN_NO_DELAY_SLOT
#define TRAP	INSN_NO_DELAY_SLOT

#define RD_16	INSN2_READ_GPR_16
#define RD_SP	INSN2_READ_SP
#define WR_SP	INSN2_WRITE_SP
#define MOD_SP	(RD_SP|WR_SP)
#define RD_31	INSN2_READ_GPR_31
#define RD_PC	INSN2_READ_PC
#define UBR	INSN2_UNCOND_BRANCH
#define CBR	INSN2_COND_BRANCH

#define SH	INSN2_SHORT_ONLY

#define I1	INSN_ISA1
#define I3	INSN_ISA3
#define I32	INSN_ISA32
#define I64	INSN_ISA64
#define T3	INSN_3900
#define IAMR2	INSN_INTERAPTIV_MR2

#define E2	ASE_MIPS16E2
#define E2MT	ASE_MIPS16E2_MT

const struct mips_opcode mips16_opcodes[] =
{
/* name,    args,	match,	mask,		pinfo,			pinfo2, membership,	ase,	exclusions */
{"nop",	    "",		0x6500, 0xffff,		0,			SH|RD_16|AL,	I1,	0,	0 }, /* move $0,$Z */
{"la",	    "x,A",	0x0800, 0xf800,		WR_1,			RD_PC|AL,	I1,	0,	0 },
{"abs",	    "x,w",	0, (int) M_ABS,		INSN_MACRO,		0,		I1,	0,	0 },
{"addiu",   "y,x,F",	0x4000, 0xf810,		WR_1|RD_2,		0,		I1,	0,	0 },
{"addiu",   "x,k",	0x4800, 0xf800,		MOD_1,			0,		I1,	0,	0 },
{"addiu",   "S,K",	0x6300, 0xff00,		0,			MOD_SP,		I1,	0,	0 },
{"addiu",   "S,S,K",	0x6300, 0xff00,		0,			MOD_SP,		I1,	0,	0 },
{"addiu",   "x,P,V",	0x0800, 0xf800,		WR_1,			RD_PC,		I1,	0,	0 },
{"addiu",   "x,S,V",	0x0000, 0xf800,		WR_1,			SH|RD_SP,	0,	E2,	0 },
{"addiu",   "x,S,V",	0x0000, 0xf800,		WR_1,			RD_SP,		I1,	0,	0 },
{"addiu",   "x,S,V",	0xf0000000, 0xf800f8e0,	WR_1,			RD_SP,		0,	E2,	0 },
{"addiu",   "x,G,V",	0xf0000020, 0xf800f8e0,	WR_1|RD_2,		0,		0,	E2,	0 },
{"addu",    "z,v,y",	0xe001, 0xf803,		WR_1|RD_2|RD_3,		SH,		I1,	0,	0 },
{"addu",    "y,x,F",	0x4000, 0xf810,		WR_1|RD_2,		0,		I1,	0,	0 },
{"addu",    "x,k",	0x4800, 0xf800,		MOD_1,			0,		I1,	0,	0 },
{"addu",    "S,K",	0x6300, 0xff00,		0,			MOD_SP,		I1,	0,	0 },
{"addu",    "S,S,K",	0x6300, 0xff00,		0,			MOD_SP,		I1,	0,	0 },
{"addu",    "x,P,V",	0x0800, 0xf800,		WR_1,			RD_PC,		I1,	0,	0 },
{"addu",    "x,S,V",	0x0000, 0xf800,		WR_1,			SH|RD_SP,	0,	E2,	0 },
{"addu",    "x,S,V",	0x0000, 0xf800,		WR_1,			RD_SP,		I1,	0,	0 },
{"addu",    "x,S,V",	0xf0000000, 0xf800f8e0,	WR_1,			RD_SP,		0,	E2,	0 },
{"addu",    "x,G,V",	0xf0000020, 0xf800f8e0,	WR_1|RD_2,		0,		0,	E2,	0 },
{"and",	    "x,y",	0xe80c, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"andi",    "x,u",	0xf0006860, 0xf800f8e0,	WR_1,			0,		0,	E2,	0 },
{"b",	    "q",	0x1000, 0xf800,		0,			UBR,		I1,	0,	0 },
{"beq",	    "x,y,p",	0, (int) M_BEQ,		INSN_MACRO,		0,		I1,	0,	0 },
{"beq",     "x,I,p",	0, (int) M_BEQ_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"beqz",    "x,p",	0x2000, 0xf800,		RD_1,			CBR,		I1,	0,	0 },
{"bge",	    "x,y,p",	0, (int) M_BGE,		INSN_MACRO,		0,		I1,	0,	0 },
{"bge",     "x,I,p",	0, (int) M_BGE_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"bgeu",    "x,y,p",	0, (int) M_BGEU,	INSN_MACRO,		0,		I1,	0,	0 },
{"bgeu",    "x,I,p",	0, (int) M_BGEU_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"bgt",	    "x,y,p",	0, (int) M_BGT,		INSN_MACRO,		0,		I1,	0,	0 },
{"bgt",     "x,I,p",	0, (int) M_BGT_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"bgtu",    "x,y,p",	0, (int) M_BGTU,	INSN_MACRO,		0,		I1,	0,	0 },
{"bgtu",    "x,I,p",	0, (int) M_BGTU_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"ble",	    "x,y,p",	0, (int) M_BLE,		INSN_MACRO,		0,		I1,	0,	0 },
{"ble",     "x,I,p",	0, (int) M_BLE_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"bleu",    "x,y,p",	0, (int) M_BLEU,	INSN_MACRO,		0,		I1,	0,	0 },
{"bleu",    "x,I,p",	0, (int) M_BLEU_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"blt",	    "x,y,p",	0, (int) M_BLT,		INSN_MACRO,		0,		I1,	0,	0 },
{"blt",     "x,I,p",	0, (int) M_BLT_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"bltu",    "x,y,p",	0, (int) M_BLTU,	INSN_MACRO,		0,		I1,	0,	0 },
{"bltu",    "x,I,p",	0, (int) M_BLTU_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"bne",	    "x,y,p",	0, (int) M_BNE,		INSN_MACRO,		0,		I1,	0,	0 },
{"bne",     "x,I,p",	0, (int) M_BNE_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"bnez",    "x,p",	0x2800, 0xf800,		RD_1,			CBR,		I1,	0,	0 },
{"break",   "",		0xe805, 0xffff,		TRAP,			SH,		I1,	0,	0 },
{"break",   "6",	0xe805, 0xf81f,		TRAP,			SH,		I1,	0,	0 },
{"bteqz",   "p",	0x6000, 0xff00,		RD_T,			CBR,		I1,	0,	0 },
{"btnez",   "p",	0x6100, 0xff00,		RD_T,			CBR,		I1,	0,	0 },
{"cache",   "T,9(x)",	0xf000d0a0, 0xfe00f8e0,	RD_3,			0,		0,	E2,	0 },
{"cmpi",    "x,U",	0x7000, 0xf800,		RD_1|WR_T,		0,		I1,	0,	0 },
{"cmp",	    "x,y",	0xe80a, 0xf81f,		RD_1|RD_2|WR_T,		SH,		I1,	0,	0 },
{"cmp",     "x,U",	0x7000, 0xf800,		RD_1|WR_T,		0,		I1,	0,	0 },
{"dla",	    "y,E",	0xfe00, 0xff00,		WR_1, 			RD_PC|AL,	I3,	0,	0 },
{"daddiu",  "y,x,F",	0x4010, 0xf810,		WR_1|RD_2, 		0,		I3,	0,	0 },
{"daddiu",  "y,j",	0xfd00, 0xff00,		MOD_1,			0,		I3,	0,	0 },
{"daddiu",  "S,K",	0xfb00, 0xff00,		0,	 		MOD_SP,		I3,	0,	0 },
{"daddiu",  "S,S,K",	0xfb00, 0xff00,		0,	 		MOD_SP,		I3,	0,	0 },
{"daddiu",  "y,P,W",	0xfe00, 0xff00,		WR_1,	 		RD_PC,		I3,	0,	0 },
{"daddiu",  "y,S,W",	0xff00, 0xff00,		WR_1,			RD_SP,		I3,	0,	0 },
{"daddu",   "z,v,y",	0xe000, 0xf803,		WR_1|RD_2|RD_3,		SH,		I3,	0,	0 },
{"daddu",   "y,x,F",	0x4010, 0xf810,		WR_1|RD_2, 		0,		I3,	0,	0 },
{"daddu",   "y,j",	0xfd00, 0xff00,		MOD_1,			0,		I3,	0,	0 },
{"daddu",   "S,K",	0xfb00, 0xff00,		0,	 		MOD_SP,		I3,	0,	0 },
{"daddu",   "S,S,K",	0xfb00, 0xff00,		0,	 		MOD_SP,		I3,	0,	0 },
{"daddu",   "y,P,W",	0xfe00, 0xff00,		WR_1,	 		RD_PC,		I3,	0,	0 },
{"daddu",   "y,S,W",	0xff00, 0xff00,		WR_1,			RD_SP,		I3,	0,	0 },
{"ddiv",    ".,x,y",	0xe81e, 0xf81f,		RD_2|RD_3|WR_HI|WR_LO,	SH,		I3,	0,	0 },
{"ddiv",    "z,v,y",	0, (int) M_DDIV_3,	INSN_MACRO,		0,		I3,	0,	0 },
{"ddivu",   ".,x,y",	0xe81f, 0xf81f,		RD_2|RD_3|WR_HI|WR_LO,	SH,		I3,	0,	0 },
{"ddivu",   "z,v,y",	0, (int) M_DDIVU_3,	INSN_MACRO,		0,		I3,	0,	0 },
{"di",	    "",		0xf006670c, 0xffffffff,	WR_C0,			0,		0,	E2,	0 },
{"di",	    ".",	0xf006670c, 0xffffffff,	WR_C0,			0,		0,	E2,	0 },
{"di",	    "y",	0xf002670c, 0xffffff1f,	WR_1|WR_C0,		0,		0,	E2,	0 },
{"div",	    ".,x,y",	0xe81a, 0xf81f,		RD_2|RD_3|WR_HI|WR_LO,	SH,		I1,	0,	0 },
{"div",     "z,v,y",	0, (int) M_DIV_3,	INSN_MACRO,		0,		I1,	0,	0 },
{"divu",    ".,x,y",	0xe81b, 0xf81f,		RD_2|RD_3|WR_HI|WR_LO,	SH,		I1,	0,	0 },
{"divu",    "z,v,y",	0, (int) M_DIVU_3,	INSN_MACRO,		0,		I1,	0,	0 },
{"dmul",    "z,v,y",	0, (int) M_DMUL,	INSN_MACRO, 		0,		I3,	0,	0 },
{"dmult",   "x,y",	0xe81c, 0xf81f,		RD_1|RD_2|WR_HI|WR_LO,	SH,		I3,	0,	0 },
{"dmultu",  "x,y",	0xe81d, 0xf81f,		RD_1|RD_2|WR_HI|WR_LO,	SH,		I3,	0,	0 },
{"drem",    ".,x,y",	0xe81e, 0xf81f,		RD_2|RD_3|WR_HI|WR_LO,	SH,		I3,	0,	0 },
{"drem",    "z,v,y",	0, (int) M_DREM_3,	INSN_MACRO,		0,		I3,	0,	0 },
{"dremu",   ".,x,y",	0xe81f, 0xf81f,		RD_2|RD_3|WR_HI|WR_LO,	SH,		I3,	0,	0 },
{"dremu",   "z,v,y",	0, (int) M_DREMU_3,	INSN_MACRO,		0,		I3,	0,	0 },
{"dsllv",   "y,x",	0xe814, 0xf81f,		MOD_1|RD_2,		SH,		I3,	0,	0 },
{"dsll",    "x,w,[",	0x3001, 0xf803,		WR_1|RD_2, 		0,		I3,	0,	0 },
{"dsll",    "y,x",	0xe814, 0xf81f,		MOD_1|RD_2,		SH,		I3,	0,	0 },
{"dsrav",   "y,x",	0xe817, 0xf81f,		MOD_1|RD_2,		SH,		I3,	0,	0 },
{"dsra",    "y,]",	0xe813, 0xf81f,		MOD_1,			0,		I3,	0,	0 },
{"dsra",    "y,x",	0xe817, 0xf81f,		MOD_1|RD_2,		SH,		I3,	0,	0 },
{"dsrlv",   "y,x",	0xe816, 0xf81f,		MOD_1|RD_2,		SH,		I3,	0,	0 },
{"dsrl",    "y,]",	0xe808, 0xf81f,		MOD_1,			0,		I3,	0,	0 },
{"dsrl",    "y,x",	0xe816, 0xf81f,		MOD_1|RD_2,		SH,		I3,	0,	0 },
{"dsubu",   "z,v,y",	0xe002, 0xf803,		WR_1|RD_2|RD_3,		SH,		I3,	0,	0 },
{"dsubu",   "y,x,I",	0, (int) M_DSUBU_I,	INSN_MACRO,		0,		I3,	0,	0 },
{"dsubu",   "y,I",	0, (int) M_DSUBU_I_2,	INSN_MACRO, 		0,		I3,	0,	0 },
{"ehb",	    "",		0xf0c03010, 0xffffffff,	0,			0,		0,	E2,	0 },
{"ei",	    "",		0xf007670c, 0xffffffff,	WR_C0,			0,		0,	E2,	0 },
{"ei",	    ".",	0xf007670c, 0xffffffff,	WR_C0,			0,		0,	E2,	0 },
{"ei",	    "y",	0xf003670c, 0xffffff1f,	WR_1|WR_C0,		0,		0,	E2,	0 },
{"exit",    "L",	0xed09, 0xff1f,		TRAP,			SH,		I1,	0,	0 },
{"exit",    "L",	0xee09, 0xff1f,		TRAP,			SH,		I1,	0,	0 },
{"exit",    "",		0xef09, 0xffff,		TRAP,			SH,		I1,	0,	0 },
{"exit",    "L",	0xef09, 0xff1f,		TRAP,			SH,		I1,	0,	0 },
{"entry",   "",		0xe809, 0xffff,		TRAP,			SH,		I1,	0,	0 },
{"entry",   "l",	0xe809, 0xf81f,		TRAP,			SH,		I1,	0,	0 },
{"ext",	    "y,x,b,d",	0xf0203008, 0xf820f81f,	WR_1|RD_2,		0,		0,	E2,	0 },
{"ins",	    "y,.,b,c",	0xf0003004, 0xf820ff1f,	WR_1,			0,		0,	E2,	0 },
{"ins",	    "y,x,b,c",	0xf0203004, 0xf820f81f,	WR_1|RD_2,		0,		0,	E2,	0 },
{"jalr",    "x",	0xe840, 0xf8ff,		RD_1|WR_31|UBD,		SH,		I1,	0,	0 },
{"jalr",    "R,x",	0xe840, 0xf8ff,		RD_2|WR_31|UBD,		SH,		I1,	0,	0 },
{"jal",	    "x",	0xe840, 0xf8ff,		RD_1|WR_31|UBD,		SH,		I1,	0,	0 },
{"jal",	    "R,x",	0xe840, 0xf8ff,		RD_2|WR_31|UBD,		SH,		I1,	0,	0 },
{"jal",	    "a",	0x18000000, 0xfc000000,	WR_31|UBD,		0,		I1,	0,	0 },
{"jalx",    "i",	0x1c000000, 0xfc000000,	WR_31|UBD,		0,		I1,	0,	0 },
{"jr",	    "x",	0xe800, 0xf8ff,		RD_1|UBD,		SH,		I1,	0,	0 },
{"jr",	    "R",	0xe820, 0xffff,		UBD,			SH|RD_31,	I1,	0,	0 },
{"j",	    "x",	0xe800, 0xf8ff,		RD_1|UBD,		SH,		I1,	0,	0 },
{"j",	    "R",	0xe820, 0xffff,		UBD,			SH|RD_31,	I1,	0,	0 },
/* MIPS16e compact jumps.  We keep them near the ordinary jumps
   so that we easily find them when converting a normal jump
   to a compact one.  */
{"jalrc",   "x",	0xe8c0, 0xf8ff,		RD_1|WR_31|NODS,	SH|UBR,		I32,	0,	0 },
{"jalrc",   "R,x",	0xe8c0, 0xf8ff,		RD_2|WR_31|NODS,	SH|UBR,		I32,	0,	0 },
{"jrc",	    "x",	0xe880, 0xf8ff,		RD_1|NODS,		SH|UBR,		I32,	0,	0 },
{"jrc",	    "R",	0xe8a0, 0xffff,		NODS,			SH|RD_31|UBR,	I32,	0,	0 },
{"lb",	    "y,5(x)",	0x8000, 0xf800,		WR_1|RD_3,		0,		I1,	0,	0 },
{"lb",	    "x,V(G)",	0xf0009060, 0xf800f8e0,	WR_1|RD_3,		0,		0,	E2,	0 },
{"lbu",	    "y,5(x)",	0xa000, 0xf800,		WR_1|RD_3,		0,		I1,	0,	0 },
{"lbu",	    "x,V(G)",	0xf00090a0, 0xf800f8e0,	WR_1|RD_3,		0,		0,	E2,	0 },
{"ld",	    "y,D(x)",	0x3800, 0xf800,		WR_1|RD_3, 		0,		I3,	0,	0 },
{"ld",	    "y,B",	0xfc00, 0xff00,		WR_1,	 		RD_PC|AL,	I3,	0,	0 },
{"ld",	    "y,D(P)",	0xfc00, 0xff00,		WR_1,	 		RD_PC,		I3,	0,	0 },
{"ld",	    "y,D(S)",	0xf800, 0xff00,		WR_1,			RD_SP,		I3,	0,	0 },
{"lh",	    "y,H(x)",	0x8800, 0xf800,		WR_1|RD_3,		0,		I1,	0,	0 },
{"lh",	    "x,V(G)",	0xf0009040, 0xf800f8e0,	WR_1|RD_3,		0,		0,	E2,	0 },
{"lhu",	    "y,H(x)",	0xa800, 0xf800,		WR_1|RD_3,		0,		I1,	0,	0 },
{"lhu",	    "x,V(G)",	0xf0009080, 0xf800f8e0,	WR_1|RD_3,		0,		0,	E2,	0 },
{"li",	    "x,U",	0x6800, 0xf800,		WR_1,			SH,		0,	E2,	0 },
{"li",	    "x,U",	0x6800, 0xf800,		WR_1,			0,		I1,	0,	0 },
{"li",	    "x,U",	0xf0006800, 0xf800f8e0,	WR_1,			0,		0,	E2,	0 },
{"ll",	    "x,9(r)",	0xf00090c0, 0xfe18f8e0,	WR_1|RD_3,		0,		0,	E2,	0 },
{"lui",	    "x,u",	0xf0006820, 0xf800f8e0,	WR_1,			0,		0,	E2,	0 },
{"lw",	    "y,W(x)",	0x9800, 0xf800,		WR_1|RD_3,		0,		I1,	0,	0 },
{"lw",	    "x,A",	0xb000, 0xf800,		WR_1,			RD_PC|AL,	I1,	0,	0 },
{"lw",	    "x,V(P)",	0xb000, 0xf800,		WR_1,			RD_PC,		I1,	0,	0 },
{"lw",	    "x,V(S)",	0x9000, 0xf800,		WR_1,			SH|RD_SP,	0,	E2,	0 },
{"lw",	    "x,V(S)",	0x9000, 0xf800,		WR_1,			RD_SP,		I1,	0,	0 },
{"lw",	    "x,V(S)",	0xf0009000, 0xf800f8e0,	WR_1,			RD_SP,		0,	E2,	0 },
{"lw",	    "x,V(G)",	0xf0009020, 0xf800f8e0,	WR_1|RD_3,		0,		0,	E2,	0 },
{"lwl",	    "x,9(r)",	0xf00090e0, 0xfe18f8e0,	WR_1|RD_3,		0,		0,	E2,	0 },
{"lwr",	    "x,9(r)",	0xf01090e0, 0xfe18f8e0,	WR_1|RD_3,		0,		0,	E2,	0 },
{"lwu",     "y,W(x)",	0xb800, 0xf800,		WR_1|RD_3, 		0,		I3,	0,	0 },
{"mfc0",    "y,N",	0xf0006700, 0xffffff00,	WR_1|RD_C0,		0,		0,	E2,	0 },
{"mfc0",    "y,N,O",	0xf0006700, 0xff1fff00,	WR_1|RD_C0,		0,		0,	E2,	0 },
{"mfhi",    "x",	0xe810, 0xf8ff,		WR_1|RD_HI,		SH,		I1,	0,	0 },
{"mflo",    "x",	0xe812, 0xf8ff,		WR_1|RD_LO,		SH,		I1,	0,	0 },
{"move",    "y,X",	0x6700, 0xff00,		WR_1|RD_2,		SH,		I1,	0,	0 },
{"move",    "Y,Z",	0x6500, 0xff00,		WR_1|RD_2,		SH,		I1,	0,	0 },
{"movn",    "x,.,w",	0xf000300a, 0xfffff81f,	WR_1|RD_2|RD_3,		0,		0,	E2,	0 },
{"movn",    "x,r,w",	0xf020300a, 0xfff8f81f,	WR_1|RD_2|RD_3,		0,		0,	E2,	0 },
{"movtn",   "x,.",	0xf000301a, 0xfffff8ff,	WR_1|RD_2|RD_T,		0,		0,	E2,	0 },
{"movtn",   "x,r",	0xf020301a, 0xfff8f8ff,	WR_1|RD_2|RD_T,		0,		0,	E2,	0 },
{"movtz",   "x,.",	0xf0003016, 0xfffff8ff,	WR_1|RD_2|RD_T,		0,		0,	E2,	0 },
{"movtz",   "x,r",	0xf0203016, 0xfff8f8ff,	WR_1|RD_2|RD_T,		0,		0,	E2,	0 },
{"movz",    "x,.,w",	0xf0003006, 0xfffff81f,	WR_1|RD_2|RD_3,		0,		0,	E2,	0 },
{"movz",    "x,r,w",	0xf0203006, 0xfff8f81f,	WR_1|RD_2|RD_3,		0,		0,	E2,	0 },
{"mtc0",    "y,N",	0xf0016700, 0xffffff00,	RD_1|WR_C0,		0,		0,	E2,	0 },
{"mtc0",    "y,N,O",	0xf0016700, 0xff1fff00,	RD_1|WR_C0,		0,		0,	E2,	0 },
{"mul",     "z,v,y",	0, (int) M_MUL, 	INSN_MACRO,		0,		I1,	0,	0 },
{"mult",    "x,y",	0xe818, 0xf81f,		RD_1|RD_2|WR_HI|WR_LO,	SH,		I1,	0,	0 },
{"multu",   "x,y",	0xe819, 0xf81f,		RD_1|RD_2|WR_HI|WR_LO,	SH,		I1,	0,	0 },
{"neg",	    "x,w",	0xe80b, 0xf81f,		WR_1|RD_2,		SH,		I1,	0,	0 },
{"not",	    "x,w",	0xe80f, 0xf81f,		WR_1|RD_2,		SH,		I1,	0,	0 },
{"or",	    "x,y",	0xe80d, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"ori",	    "x,u",	0xf0006840, 0xf800f8e0,	WR_1,			0,		0,	E2,	0 },
{"pause",   "",		0xf1403018, 0xffffffff,	0,			0,		0,	E2,	0 },
{"pref",    "T,9(x)",	0xf000d080, 0xfe00f8e0,	RD_3,			0,		0,	E2,	0 },
{"rdhwr",   "y,Q",	0xf000300c, 0xffe0ff1f,	WR_1,			0,		0,	E2,	0 },
{"rem",	    ".,x,y",	0xe81a, 0xf81f,		RD_2|RD_3|WR_HI|WR_LO,	SH,		I1,	0,	0 },
{"rem",     "z,v,y",	0, (int) M_REM_3,	INSN_MACRO,		0,		I1,	0,	0 },
{"remu",    ".,x,y",	0xe81b, 0xf81f,		RD_2|RD_3|WR_HI|WR_LO,	SH,		I1,	0,	0 },
{"remu",    "z,v,y",	0, (int) M_REMU_3,	INSN_MACRO,		0,		I1,	0,	0 },
{"sb",	    "y,5(x)",	0xc000, 0xf800,		RD_1|RD_3,		0,		I1,	0,	0 },
{"sb",	    "x,V(G)",	0xf000d060, 0xf800f8e0,	RD_1|RD_3,		0,		0,	E2,	0 },
{"sc",	    "x,9(r)",	0xf000d0c0, 0xfe18f8e0,	RD_1|RD_3,		0,		0,	E2,	0 },
{"sd",	    "y,D(x)",	0x7800, 0xf800,		RD_1|RD_3, 		0,		I3,	0,	0 },
{"sd",	    "y,D(S)",	0xf900, 0xff00,		RD_1, 			RD_SP,		I3,	0,	0 },
{"sd",	    "R,C(S)",	0xfa00, 0xff00,		0,			RD_31|RD_SP,	I3,	0,	0 },
{"sh",	    "y,H(x)",	0xc800, 0xf800,		RD_1|RD_3,		0,		I1,	0,	0 },
{"sh",	    "x,V(G)",	0xf000d040, 0xf800f8e0,	RD_1|RD_3,		0,		0,	E2,	0 },
{"sllv",    "y,x",	0xe804, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"sll",	    "x,w,<",	0x3000, 0xf803,		WR_1|RD_2,		SH,		0,	E2,	0 },
{"sll",	    "x,w,<",	0x3000, 0xf803,		WR_1|RD_2,		0,		I1,	0,	0 },
{"sll",	    "x,w,<",	0xf0003000, 0xf83ff81f,	WR_1|RD_2,		0,		0,	E2,	0 },
{"sll",	    "y,x",	0xe804, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"slti",    "x,8",	0x5000, 0xf800,		RD_1|WR_T,		0,		I1,	0,	0 },
{"slt",	    "x,y",	0xe802, 0xf81f,		RD_1|RD_2|WR_T,		SH,		I1,	0,	0 },
{"slt",     "x,8",	0x5000, 0xf800,		RD_1|WR_T,		0,		I1,	0,	0 },
{"sltiu",   "x,8",	0x5800, 0xf800,		RD_1|WR_T,		0,		I1,	0,	0 },
{"sltu",    "x,y",	0xe803, 0xf81f,		RD_1|RD_2|WR_T,		SH,		I1,	0,	0 },
{"sltu",    "x,8",	0x5800, 0xf800,		RD_1|WR_T,		0,		I1,	0,	0 },
{"srav",    "y,x",	0xe807, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"sra",	    "x,w,<",	0x3003, 0xf803,		WR_1|RD_2,		0,		I1,	0,	0 },
{"sra",	    "y,x",	0xe807, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"srlv",    "y,x",	0xe806, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"srl",	    "x,w,<",	0x3002, 0xf803,		WR_1|RD_2,		SH,		0,	E2,	0 },
{"srl",	    "x,w,<",	0x3002, 0xf803,		WR_1|RD_2,		0,		I1,	0,	0 },
{"srl",	    "x,w,<",	0xf0003002, 0xf83ff81f,	WR_1|RD_2,		0,		0,	E2,	0 },
{"srl",	    "y,x",	0xe806, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"subu",    "z,v,y",	0xe003, 0xf803,		WR_1|RD_2|RD_3,		SH,		I1,	0,	0 },
{"subu",    "y,x,I",	0, (int) M_SUBU_I,	INSN_MACRO,		0,		I1,	0,	0 },
{"subu",    "x,I",	0, (int) M_SUBU_I_2,	INSN_MACRO,		0,		I1,	0,	0 },
{"sw",	    "y,W(x)",	0xd800, 0xf800,		RD_1|RD_3,		0,		I1,	0,	0 },
{"sw",	    "x,V(S)",	0xd000, 0xf800,		RD_1,			SH|RD_SP,	0,	E2,	0 },
{"sw",	    "x,V(S)",	0xd000, 0xf800,		RD_1,			RD_SP,		I1,	0,	0 },
{"sw",	    "x,V(S)",	0xf000d000, 0xf800f8e0,	RD_1,			RD_SP,		0,	E2,	0 },
{"sw",	    "R,V(S)",	0x6200, 0xff00,		0,			RD_31|RD_SP,	I1,	0,	0 },
{"sw",	    "x,V(G)",	0xf000d020, 0xf800f8e0,	RD_1|RD_3,		0,		0,	E2,	0 },
{"swl",	    "x,9(r)",	0xf000d0e0, 0xfe18f8e0,	RD_1|RD_3,		0,		0,	E2,	0 },
{"swr",	    "x,9(r)",	0xf010d0e0, 0xfe18f8e0,	RD_1|RD_3,		0,		0,	E2,	0 },
{"sync_acquire", "",	0xf4403014, 0xffffffff,	0,			AL,		0,	E2,	0 },
{"sync_mb", "",		0xf4003014, 0xffffffff,	0,			AL,		0,	E2,	0 },
{"sync_release", "",	0xf4803014, 0xffffffff,	0,			AL,		0,	E2,	0 },
{"sync_rmb", "",	0xf4c03014, 0xffffffff,	0,			AL,		0,	E2,	0 },
{"sync_wmb", "",	0xf1003014, 0xffffffff,	0,			AL,		0,	E2,	0 },
{"sync",    "",		0xf0003014, 0xffffffff,	0,			0,		0,	E2,	0 },
{"sync",    ">",	0xf0003014, 0xf83fffff,	0,			0,		0,	E2,	0 },
{"xor",	    "x,y",	0xe80e, 0xf81f,		MOD_1|RD_2,		SH,		I1,	0,	0 },
{"xori",    "x,u",	0xf0006880, 0xf800f8e0,	WR_1,			0,		0,	E2,	0 },
  /* MIPS16e additions; see above for compact jumps.  */
{"restore", "m",	0x6400, 0xff80,		WR_31|NODS,		MOD_SP,		I32,	0,	0 },
{"save",    "m",	0x6480, 0xff80,		NODS,			RD_31|MOD_SP,	I32,	0,	0 },
{"sdbbp",   "",		0xe801, 0xffff,		TRAP,			SH,		I32,	0,	0 },
{"sdbbp",   "6",	0xe801, 0xf81f,		TRAP,			SH,		I32,	0,	0 },
{"seb",	    "x",	0xe891, 0xf8ff,		MOD_1,			SH,		I32,	0,	0 },
{"seh",	    "x",	0xe8b1, 0xf8ff,		MOD_1,			SH,		I32,	0,	0 },
{"sew",	    "x",	0xe8d1, 0xf8ff,		MOD_1,			SH,		I64,	0,	0 },
{"zeb",	    "x",	0xe811, 0xf8ff,		MOD_1,			SH,		I32,	0,	0 },
{"zeh",	    "x",	0xe831, 0xf8ff,		MOD_1,			SH,		I32,	0,	0 },
{"zew",	    "x",	0xe851, 0xf8ff,		MOD_1,			SH,		I64,	0,	0 },
  /* MIPS16e2 MT ASE instructions.  */
{"dmt",	    "",		0xf0266701, 0xffffffff,	WR_C0,			0,		0,	E2MT,	0 },
{"dmt",	    ".",	0xf0266701, 0xffffffff,	WR_C0,			0,		0,	E2MT,	0 },
{"dmt",	    "y",	0xf0226701, 0xffffff1f,	WR_1|WR_C0,		0,		0,	E2MT,	0 },
{"dvpe",    "",		0xf0266700, 0xffffffff,	WR_C0,			0,		0,	E2MT,	0 },
{"dvpe",    ".",	0xf0266700, 0xffffffff,	WR_C0,			0,		0,	E2MT,	0 },
{"dvpe",    "y",	0xf0226700, 0xffffff1f,	WR_1|WR_C0,		0,		0,	E2MT,	0 },
{"emt",	    "",		0xf0276701, 0xffffffff,	WR_C0,			0,		0,	E2MT,	0 },
{"emt",	    ".",	0xf0276701, 0xffffffff,	WR_C0,			0,		0,	E2MT,	0 },
{"emt",	    "y",	0xf0236701, 0xffffff1f,	WR_1|WR_C0,		0,		0,	E2MT,	0 },
{"evpe",    "",		0xf0276700, 0xffffffff,	WR_C0,			0,		0,	E2MT,	0 },
{"evpe",    ".",	0xf0276700, 0xffffffff,	WR_C0,			0,		0,	E2MT,	0 },
{"evpe",    "y",	0xf0236700, 0xffffff1f,	WR_1|WR_C0,		0,		0,	E2MT,	0 },
  /* interAptiv MR2 instruction extensions.  */
{"copyw",   "x,y,o,n",	0xf020e000, 0xffe0f81c,	RD_1|RD_2|NODS,		0,		IAMR2,	0,	0 },
{"ucopyw",  "x,y,o,n",	0xf000e000, 0xffe0f81c,	RD_1|RD_2|NODS,		0,		IAMR2,	0,	0 },
  /* Place asmacro at the bottom so that it catches any implementation
     specific macros that didn't match anything.  */
{"asmacro", "s,0,1,2,3,4", 0xf000e000, 0xf800f800, 0,			0,		I32,	0,	0 },
  /* Place EXTEND last so that it catches any prefix that didn't match
     anything.  */
{"extend",  "e",	0xf000, 0xf800,		NODS,			SH,		I1,	0,	0 },
};

const int bfd_mips16_num_opcodes =
  ((sizeof mips16_opcodes) / (sizeof (mips16_opcodes[0])));
