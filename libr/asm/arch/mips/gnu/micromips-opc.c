/*
  Based on commits 250d07de5cf6efc81ed934c25292beb63c7e3129 from master branch
  of binutils-gdb.
*/
/* micromips-opc.c.  microMIPS opcode table.
   Copyright (C) 2008-2021 Free Software Foundation, Inc.
   Contributed by Chao-ying Fu, MIPS Technologies, Inc.

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
#include "opcode/mips.h"
#include "mips-formats.h"

static unsigned char reg_0_map[] = {0};
static unsigned char reg_28_map[] = { 28 };
static unsigned char reg_29_map[] = { 29 };
static unsigned char reg_31_map[] = { 31 };
static unsigned char reg_m16_map[] = { 16, 17, 2, 3, 4, 5, 6, 7 };
static unsigned char reg_mn_map[] = { 0, 17, 2, 3, 16, 18, 19, 20 };
static unsigned char reg_q_map[] = { 0, 17, 2, 3, 4, 5, 6, 7 };

static unsigned char reg_h_map1[] = { 5, 5, 6, 4, 4, 4, 4, 4 };
static unsigned char reg_h_map2[] = { 6, 7, 7, 21, 22, 5, 6, 7 };

static int int_b_map[] = {
  1, 4, 8, 12, 16, 20, 24, -1
};
static int int_c_map[] = {
  128, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 255, 32768, 65535
};

/* Return the mips_operand structure for the operand at the beginning of P.  */

const struct mips_operand *
decode_micromips_operand (const char *p)
{
  switch (p[0])
    {
    case 'm':
      switch (p[1])
	{
	case 'a': MAPPED_REG (0, 0, GP, reg_28_map);
	case 'b': MAPPED_REG (3, 23, GP, reg_m16_map);
	case 'c': OPTIONAL_MAPPED_REG (3, 4, GP, reg_m16_map);
	case 'd': MAPPED_REG (3, 7, GP, reg_m16_map);
	case 'e': OPTIONAL_MAPPED_REG (3, 1, GP, reg_m16_map);
	case 'f': MAPPED_REG (3, 3, GP, reg_m16_map);
	case 'g': MAPPED_REG (3, 0, GP, reg_m16_map);
	case 'h': REG_PAIR (3, 7, GP, reg_h_map);
	case 'j': REG (5, 0, GP);
	case 'l': MAPPED_REG (3, 4, GP, reg_m16_map);
	case 'm': MAPPED_REG (3, 1, GP, reg_mn_map);
	case 'n': MAPPED_REG (3, 4, GP, reg_mn_map);
	case 'p': REG (5, 5, GP);
	case 'q': MAPPED_REG (3, 7, GP, reg_q_map);
	case 'r': SPECIAL (0, 0, PC);
	case 's': MAPPED_REG (0, 0, GP, reg_29_map);
	case 't': SPECIAL (0, 0, REPEAT_PREV_REG);
	case 'x': SPECIAL (0, 0, REPEAT_DEST_REG);
	case 'y': MAPPED_REG (0, 0, GP, reg_31_map);
	case 'z': MAPPED_REG (0, 0, GP, reg_0_map);

	case 'A': INT_ADJ (7, 0, 63, 2, FALSE);	 /* (-64 .. 63) << 2 */
	case 'B': MAPPED_INT (3, 1, int_b_map, FALSE);
	case 'C': MAPPED_INT (4, 0, int_c_map, TRUE);
	case 'D': BRANCH (10, 0, 1);
	case 'E': BRANCH (7, 0, 1);
	case 'F': HINT (4, 0);
	case 'G': INT_ADJ (4, 0, 14, 0, FALSE);	 /* (-1 .. 14) */
	case 'H': INT_ADJ (4, 0, 15, 1, FALSE);	 /* (0 .. 15) << 1 */
	case 'I': INT_ADJ (7, 0, 126, 0, FALSE); /* (-1 .. 126) */
	case 'J': INT_ADJ (4, 0, 15, 2, FALSE);	 /* (0 .. 15) << 2 */
	case 'L': INT_ADJ (4, 0, 15, 0, FALSE);	 /* (0 .. 15) */
	case 'M': INT_ADJ (3, 1, 8, 0, FALSE);   /* (1 .. 8) */
	case 'N': SPECIAL (2, 4, LWM_SWM_LIST);
	case 'O': HINT (4, 0);
	case 'P': INT_ADJ (5, 0, 31, 2, FALSE);	 /* (0 .. 31) << 2 */
	case 'Q': INT_ADJ (23, 0, 4194303, 2, FALSE);
	  					 /* (-4194304 .. 4194303) */
	case 'U': INT_ADJ (5, 0, 31, 2, FALSE);	 /* (0 .. 31) << 2 */
	case 'W': INT_ADJ (6, 1, 63, 2, FALSE);	 /* (0 .. 63) << 2 */
	case 'X': SINT (4, 1);
	case 'Y': SPECIAL (9, 1, ADDIUSP_INT);
	case 'Z': UINT (0, 0);			 /* 0 only */
	}
      break;

    case '+':
      switch (p[1])
	{
	case 'A': BIT (5, 6, 0);		 /* (0 .. 31) */
	case 'B': MSB (5, 11, 1, TRUE, 32);	 /* (1 .. 32), 32-bit op */
	case 'C': MSB (5, 11, 1, FALSE, 32);	 /* (1 .. 32), 32-bit op */
	case 'E': BIT (5, 6, 32);		 /* (32 .. 63) */
	case 'F': MSB (5, 11, 33, TRUE, 64);	 /* (33 .. 64), 64-bit op */
	case 'G': MSB (5, 11, 33, FALSE, 64);	 /* (33 .. 64), 64-bit op */
	case 'H': MSB (5, 11, 1, FALSE, 64);	 /* (1 .. 32), 64-bit op */
	case 'J': HINT (10, 16);
	case 'T': INT_ADJ (10, 16, 511, 0, FALSE);	/* (-512 .. 511) << 0 */
	case 'U': INT_ADJ (10, 16, 511, 1, FALSE);	/* (-512 .. 511) << 1 */
	case 'V': INT_ADJ (10, 16, 511, 2, FALSE);	/* (-512 .. 511) << 2 */
	case 'W': INT_ADJ (10, 16, 511, 3, FALSE);	/* (-512 .. 511) << 3 */

	case 'd': REG (5, 6, MSA);
	case 'e': REG (5, 11, MSA);
	case 'h': REG (5, 16, MSA);
	case 'i': JALX (26, 0, 2);
	case 'j': SINT (9, 0);
	case 'k': REG (5, 6, GP);
	case 'l': REG (5, 6, MSA_CTRL);
	case 'n': REG (5, 11, MSA_CTRL);
	case 'o': SPECIAL (4, 16, IMM_INDEX);
	case 'u': SPECIAL (3, 16, IMM_INDEX);
	case 'v': SPECIAL (2, 16, IMM_INDEX);
	case 'w': SPECIAL (1, 16, IMM_INDEX);
	case 'x': BIT (5, 16, 0);		/* (0 .. 31) */

	case '~': BIT (2, 6, 1);		/* (1 .. 4) */
	case '!': BIT (3, 16, 0);		/* (0 .. 7) */
	case '@': BIT (4, 16, 0);		/* (0 .. 15) */
	case '#': BIT (6, 16, 0);		/* (0 .. 63) */
	case '$': UINT (5, 16);			/* (0 .. 31) */
	case '%': SINT (5, 16);			/* (-16 .. 15) */
	case '^': SINT (10, 11);		/* (-512 .. 511) */
	case '&': SPECIAL (0, 0, IMM_INDEX);
	case '*': SPECIAL (5, 16, REG_INDEX);
	case '|': BIT (8, 16, 0);		/* (0 .. 255) */
	}
      break;

    case '.': SINT (10, 6);
    case '<': BIT (5, 11, 0);			 /* (0 .. 31) */
    case '>': BIT (5, 11, 32);			 /* (32 .. 63) */
    case '\\': BIT (3, 21, 0);			 /* (0 .. 7) */
    case '|': HINT (4, 12);
    case '~': SINT (12, 0);
    case '@': SINT (10, 16);
    case '^': HINT (5, 11);

    case '0': SINT (6, 16);
    case '1': HINT (5, 16);
    case '2': HINT (2, 14);
    case '3': HINT (3, 13);
    case '4': HINT (4, 12);
    case '5': HINT (8, 13);
    case '6': HINT (5, 16);
    case '7': REG (2, 14, ACC);
    case '8': HINT (6, 14);

    case 'C': HINT (23, 3);
    case 'D': REG (5, 11, FP);
    case 'E': REG (5, 21, COPRO);
    case 'G': REG (5, 16, COPRO);
    case 'K': REG (5, 16, HW);
    case 'H': UINT (3, 11);
    case 'M': REG (3, 13, CCC);
    case 'N': REG (3, 18, CCC);
    case 'R': REG (5, 6, FP);
    case 'S': REG (5, 16, FP);
    case 'T': REG (5, 21, FP);
    case 'V': OPTIONAL_REG (5, 16, FP);

    case 'a': JUMP (26, 0, 1);
    case 'b': REG (5, 16, GP);
    case 'c': HINT (10, 16);
    case 'd': REG (5, 11, GP);
    case 'h': HINT (5, 11);
    case 'i': HINT (16, 0);
    case 'j': SINT (16, 0);
    case 'k': HINT (5, 21);
    case 'n': SPECIAL (5, 21, LWM_SWM_LIST);
    case 'o': SINT (16, 0);
    case 'p': BRANCH (16, 0, 1);
    case 'q': HINT (10, 6);
    case 'r': OPTIONAL_REG (5, 16, GP);
    case 's': REG (5, 16, GP);
    case 't': REG (5, 21, GP);
    case 'u': HINT (16, 0);
    case 'v': OPTIONAL_REG (5, 16, GP);
    case 'w': OPTIONAL_REG (5, 21, GP);
    case 'y': REG (5, 6, GP);
    case 'z': MAPPED_REG (0, 0, GP, reg_0_map);
    }
  return 0;
}

#define UBD	INSN_UNCOND_BRANCH_DELAY
#define CBD	INSN_COND_BRANCH_DELAY
#define NODS	INSN_NO_DELAY_SLOT
#define TRAP	INSN_NO_DELAY_SLOT
#define LM	INSN_LOAD_MEMORY
#define SM	INSN_STORE_MEMORY
#define CM	INSN_COPROC_MOVE
#define LC	INSN_LOAD_COPROC
#define BD16	INSN2_BRANCH_DELAY_16BIT	/* Used in pinfo2.  */
#define BD32	INSN2_BRANCH_DELAY_32BIT	/* Used in pinfo2.  */

#define WR_1	INSN_WRITE_1
#define WR_2	INSN_WRITE_2
#define RD_1	INSN_READ_1
#define RD_2	INSN_READ_2
#define RD_3	INSN_READ_3
#define RD_4	INSN_READ_4
#define MOD_1	(WR_1|RD_1)
#define MOD_2	(WR_2|RD_2)

/* For 16-bit/32-bit microMIPS instructions.  They are used in pinfo2.  */
#define UBR	INSN2_UNCOND_BRANCH
#define CBR	INSN2_COND_BRANCH
#define RD_sp	INSN2_READ_SP
#define WR_sp	INSN2_WRITE_SP
#define RD_31	INSN2_READ_GPR_31
#define RD_pc	INSN2_READ_PC

/* For 32-bit microMIPS instructions.  */
#define WR_31	INSN_WRITE_GPR_31
#define WR_CC	INSN_WRITE_COND_CODE

#define RD_CC	INSN_READ_COND_CODE
#define RD_C0	INSN_COP
#define RD_C1	INSN_COP
#define RD_C2	INSN_COP
#define WR_C0	INSN_COP
#define WR_C1	INSN_COP
#define WR_C2	INSN_COP
#define CP	INSN_COP

#define WR_HI	INSN_WRITE_HI
#define RD_HI	INSN_READ_HI

#define WR_LO	INSN_WRITE_LO
#define RD_LO	INSN_READ_LO

#define WR_HILO	WR_HI|WR_LO
#define RD_HILO	RD_HI|RD_LO
#define MOD_HILO WR_HILO|RD_HILO

/* Reuse INSN_ISA1 for 32-bit microMIPS ISA.  All instructions in I1
   are accepted as 32-bit microMIPS ISA.
   Reuse INSN_ISA3 for 64-bit microMIPS ISA.  All instructions in I3
   are accepted as 64-bit microMIPS ISA.  */
#define I1	INSN_ISA1
#define I3	INSN_ISA3
#define I36	INSN_ISA32R5

/* MIPS DSP ASE support.  */
#define WR_a	WR_HILO		/* Write DSP accumulators (reuse WR_HILO).  */
#define RD_a	RD_HILO		/* Read DSP accumulators (reuse RD_HILO).  */
#define MOD_a	WR_a|RD_a
#define DSP_VOLA INSN_NO_DELAY_SLOT
#define D32	ASE_DSP
#define D33	ASE_DSPR2

/* MIPS MCU (MicroController) ASE support.  */
#define MC	ASE_MCU

/* MIPS Enhanced VA Scheme.  */
#define EVA	ASE_EVA

/* TLB invalidate instruction support.  */
#define TLBINV	ASE_EVA

/* MIPS Virtualization ASE.  */
#define IVIRT	ASE_VIRT
#define IVIRT64	ASE_VIRT64

/* MSA support.  */
#define MSA     ASE_MSA
#define MSA64   ASE_MSA64

/* eXtended Physical Address (XPA) support.  */
#define XPA	ASE_XPA
#define XPAVZ	ASE_XPA_VIRT

const struct mips_opcode micromips_opcodes[] =
{
/* These instructions appear first so that the disassembler will find
   them first.  The assemblers uses a hash table based on the
   instruction name anyhow.  */
/* name,		args,		match,      mask,	pinfo,			pinfo2,		membership,	ase,	exclusions */
{"pref",		"k,~(b)",	0x60002000, 0xfc00f000,	RD_3|LM,		0,		I1,		0,	0 },
{"pref",		"k,A(b)",	0,    (int) M_PREF_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"prefx",		"h,t(b)",	0x540001a0, 0xfc0007ff,	RD_2|RD_3|FP_S|LM,	0,		I1,		0,	0 },
{"nop",			"",		    0x0c00,     0xffff,	0,			INSN2_ALIAS,	I1,		0,	0 },
{"nop",			"",		0x00000000, 0xffffffff,	0,			INSN2_ALIAS,	I1,		0,	0 }, /* sll */
{"ssnop",		"",		0x00000800, 0xffffffff,	0,			INSN2_ALIAS,	I1,		0,	0 }, /* sll */
{"ehb",			"",		0x00001800, 0xffffffff,	0,			INSN2_ALIAS,	I1,		0,	0 }, /* sll */
{"pause",		"",		0x00002800, 0xffffffff,	0,			INSN2_ALIAS,	I1,		0,	0 }, /* sll */
{"li",			"md,mI",	    0xec00,     0xfc00,	WR_1,			0,		I1,		0,	0 },
{"li",			"t,j",		0x30000000, 0xfc1f0000,	WR_1,			INSN2_ALIAS,	I1,		0,	0 }, /* addiu */
{"li",			"t,i",		0x50000000, 0xfc1f0000,	WR_1,			INSN2_ALIAS,	I1,		0,	0 }, /* ori */
{"li",			"t,I",		0,    (int) M_LI,	INSN_MACRO,		0,		I1,		0,	0 },
{"move",		"d,s",		0,    (int) M_MOVE,	INSN_MACRO,		0,		I1,		0,	0 },
{"move",		"mp,mj",	    0x0c00,     0xfc00,	WR_1|RD_2,		0,		I1,		0,	0 },
{"move",		"d,s",		0x00000290, 0xffe007ff,	WR_1|RD_2,		INSN2_ALIAS,	I1,		0,	0 }, /* or */
{"move",		"d,s",		0x58000150, 0xffe007ff,	WR_1|RD_2,		INSN2_ALIAS,	I3,		0,	0 }, /* daddu */
{"move",		"d,s",		0x00000150, 0xffe007ff,	WR_1|RD_2,		INSN2_ALIAS,	I1,		0,	0 }, /* addu */
{"b",			"mD",		    0xcc00,     0xfc00,	UBD,			0,		I1,		0,	0 },
{"b",			"p",		0x94000000, 0xffff0000,	UBD,			INSN2_ALIAS,	I1,		0,	0 }, /* beq 0, 0 */
{"b",			"p",		0x40400000, 0xffff0000,	UBD,			INSN2_ALIAS,	I1,		0,	0 }, /* bgez 0 */
/* BC is next to B so that we easily find it when converting a normal
   branch to a compact one.  */
{"bc",			"p",		0x40e00000, 0xffff0000,	NODS,			INSN2_ALIAS|UBR,  I1,		0,	0 }, /* beqzc 0 */
{"bal",			"p",		0x40600000, 0xffff0000,	WR_31|UBD,		INSN2_ALIAS|BD32, I1,		0,	0 }, /* bgezal 0 */
{"bals",		"p",		0x42600000, 0xffff0000,	WR_31|UBD,		INSN2_ALIAS|BD16, I1,		0,	0 }, /* bgezals 0 */
{"abs",			"d,v",		0,    (int) M_ABS,	INSN_MACRO,		0,		I1,		0,	0 },
{"abs.d",		"T,V",		0x5400237b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"abs.s",		"T,V",		0x5400037b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"abs.ps",		"T,V",		0x5400437b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"aclr",		"\\,~(b)",	0x2000b000, 0xff00f000,	RD_3|LM|SM|NODS,	0,		0,		MC,	0 },
{"aclr",		"\\,A(b)",	0,    (int) M_ACLR_AB,	INSN_MACRO,		0,		0,		MC,	0 },
{"add",			"d,v,t",	0x00000110, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"add",			"t,r,I",	0,    (int) M_ADD_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"add.d",		"D,V,T",	0x54000130, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"add.s",		"D,V,T",	0x54000030, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_S,	0,		I1,		0,	0 },
{"add.ps",		"D,V,T",	0x54000230, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"addi",		"t,r,j",	0x10000000, 0xfc000000,	WR_1|RD_2,		0,		I1,		0,	0 },
{"addiu",		"mp,mj,mZ",	    0x0c00,     0xfc00,	WR_1|RD_2,		0,		I1,		0,	0 }, /* move */
{"addiu",		"md,ms,mW",	    0x6c01,     0xfc01,	WR_1|RD_2,		0,		I1,		0,	0 }, /* addiur1sp */
{"addiu",		"md,mc,mB",	    0x6c00,     0xfc01,	WR_1|RD_2,		0,		I1,		0,	0 }, /* addiur2 */
{"addiu",		"ms,mt,mY",	    0x4c01,     0xfc01,	MOD_1,			0,		I1,		0,	0 }, /* addiusp */
{"addiu",		"mp,mt,mX",	    0x4c00,     0xfc01,	MOD_1,			0,		I1,		0,	0 }, /* addius5 */
{"addiu",		"mb,mr,mQ",	0x78000000, 0xfc000000,	WR_1,			RD_pc,		I1,		0,	0 }, /* addiupc */
{"addiu",		"t,r,j",	0x30000000, 0xfc000000,	WR_1|RD_2,		0,		I1,		0,	0 },
{"addiupc",		"mb,mQ",	0x78000000, 0xfc000000,	WR_1,			RD_pc,		I1,		0,	0 },
{"addiur1sp",		"md,mW",	    0x6c01,     0xfc01,	WR_1,			RD_sp,		I1,		0,	0 },
{"addiur2",		"md,mc,mB",	    0x6c00,     0xfc01,	WR_1|RD_2,		0,		I1,		0,	0 },
{"addiusp",		"mY",		    0x4c01,     0xfc01,	0,			WR_sp|RD_sp,	I1,		0,	0 },
{"addius5",		"mp,mX",	    0x4c00,     0xfc01,	MOD_1,			0,		I1,		0,	0 },
{"addu",		"mp,mj,mz",	    0x0c00,     0xfc00,	WR_1|RD_2,		0,		I1,		0,	0 }, /* move */
{"addu",		"mp,mz,mj",	    0x0c00,     0xfc00,	WR_1|RD_3,		0,		I1,		0,	0 }, /* move */
{"addu",		"md,me,ml",	    0x0400,     0xfc01,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"addu",		"d,v,t",	0x00000150, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"addu",		"t,r,I",	0,    (int) M_ADDU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"alnv.ps",		"D,V,T,y",	0x54000019, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
{"and",			"mf,mt,mg",	    0x4480,     0xffc0,	MOD_1|RD_3,		0,		I1,		0,	0 },
{"and",			"mf,mg,mx",	    0x4480,     0xffc0,	MOD_1|RD_2,		0,		I1,		0,	0 },
{"and",			"d,v,t",	0x00000250, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"and",			"t,r,I",	0,    (int) M_AND_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"andi",		"md,mc,mC",	    0x2c00,     0xfc00,	WR_1|RD_2,		0,		I1,		0,	0 },
{"andi",		"t,r,i",	0xd0000000, 0xfc000000,	WR_1|RD_2,		0,		I1,		0,	0 },
{"aset",		"\\,~(b)",	0x20003000, 0xff00f000,	RD_3|LM|SM|NODS,	0,		0,		MC,	0 },
{"aset",		"\\,A(b)",	0,    (int) M_ASET_AB,	INSN_MACRO,		0,		0,		MC,	0 },
/* b is at the top of the table.  */
/* bal is at the top of the table.  */
{"bc1f",		"p",		0x43800000, 0xffff0000,	RD_CC|CBD|FP_S,		0,		I1,		0,	0 },
{"bc1f",		"N,p",		0x43800000, 0xffe30000,	RD_CC|CBD|FP_S,		0,		I1,		0,	0 },
{"bc1fl",		"p",		0,    (int) M_BC1FL,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"bc1fl",		"N,p",		0,    (int) M_BC1FL,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"bc2f",		"p",		0x42800000, 0xffff0000,	RD_CC|CBD,		0,		I1,		0,	0 },
{"bc2f",		"N,p",		0x42800000, 0xffe30000,	RD_CC|CBD,		0,		I1,		0,	0 },
{"bc2fl",		"p",		0,    (int) M_BC2FL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bc2fl",		"N,p",		0,    (int) M_BC2FL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bc1t",		"p",		0x43a00000, 0xffff0000,	RD_CC|CBD|FP_S,		0,		I1,		0,	0 },
{"bc1t",		"N,p",		0x43a00000, 0xffe30000,	RD_CC|CBD|FP_S,		0,		I1,		0,	0 },
{"bc1tl",		"p",		0,    (int) M_BC1TL,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"bc1tl",		"N,p",		0,    (int) M_BC1TL,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"bc2t",		"p",		0x42a00000, 0xffff0000,	RD_CC|CBD,		0,		I1,		0,	0 },
{"bc2t",		"N,p",		0x42a00000, 0xffe30000,	RD_CC|CBD,		0,		I1,		0,	0 },
{"bc2tl",		"p",		0,    (int) M_BC2TL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bc2tl",		"N,p",		0,    (int) M_BC2TL,	INSN_MACRO,		0,		I1,		0,	0 },
{"beqz",		"md,mE",	    0x8c00,     0xfc00,	RD_1|CBD,		0,		I1,		0,	0 },
{"beqz",		"s,p",		0x94000000, 0xffe00000,	RD_1|CBD,		0,		I1,		0,	0 },
{"beqzl",		"s,p",		0,    (int) M_BEQL,	INSN_MACRO,		0,		I1,		0,	0 },
{"beq",			"md,mz,mE",	    0x8c00,     0xfc00,	RD_1|CBD,		0,		I1,		0,	0 }, /* beqz */
{"beq",			"mz,md,mE",	    0x8c00,     0xfc00,	RD_2|CBD,		0,		I1,		0,	0 }, /* beqz */
{"beq",			"s,t,p",	0x94000000, 0xfc000000,	RD_1|RD_2|CBD,		0,		I1,		0,	0 },
{"beq",			"s,I,p",	0,    (int) M_BEQ_I,	INSN_MACRO,		0,		I1,		0,	0 },
/* BEQZC is next to BEQ so that we easily find it when converting a normal
   branch to a compact one.  */
{"beqzc",		"s,p",		0x40e00000, 0xffe00000,	RD_1|NODS,		CBR,		I1,		0,	0 },
{"beql",		"s,t,p",	0,    (int) M_BEQL,	INSN_MACRO,		0,		I1,		0,	0 },
{"beql",		"s,I,p",	0,    (int) M_BEQL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bge",			"s,t,p",	0,    (int) M_BGE,	INSN_MACRO,		0,		I1,		0,	0 },
{"bge",			"s,I,p",	0,    (int) M_BGE_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgel",		"s,t,p",	0,    (int) M_BGEL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgel",		"s,I,p",	0,    (int) M_BGEL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgeu",		"s,t,p",	0,    (int) M_BGEU,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgeu",		"s,I,p",	0,    (int) M_BGEU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgeul",		"s,t,p",	0,    (int) M_BGEUL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgeul",		"s,I,p",	0,    (int) M_BGEUL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgez",		"s,p",		0x40400000, 0xffe00000,	RD_1|CBD,		0,		I1,		0,	0 },
{"bgezl",		"s,p",		0,    (int) M_BGEZL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgezal",		"s,p",		0x40600000, 0xffe00000,	RD_1|WR_31|CBD,		BD32,		I1,		0,	0 },
{"bgezals",		"s,p",		0x42600000, 0xffe00000,	RD_1|WR_31|CBD,		BD16,		I1,		0,	0 },
{"bgezall",		"s,p",		0,    (int) M_BGEZALL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgt",			"s,t,p",	0,    (int) M_BGT,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgt",			"s,I,p",	0,    (int) M_BGT_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgtl",		"s,t,p",	0,    (int) M_BGTL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgtl",		"s,I,p",	0,    (int) M_BGTL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgtu",		"s,t,p",	0,    (int) M_BGTU,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgtu",		"s,I,p",	0,    (int) M_BGTU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgtul",		"s,t,p",	0,    (int) M_BGTUL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgtul",		"s,I,p",	0,    (int) M_BGTUL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bgtz",		"s,p",		0x40c00000, 0xffe00000,	RD_1|CBD,		0,		I1,		0,	0 },
{"bgtzl",		"s,p",		0,    (int) M_BGTZL,	INSN_MACRO,		0,		I1,		0,	0 },
{"ble",			"s,t,p",	0,    (int) M_BLE,	INSN_MACRO,		0,		I1,		0,	0 },
{"ble",			"s,I,p",	0,    (int) M_BLE_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"blel",		"s,t,p",	0,    (int) M_BLEL,	INSN_MACRO,		0,		I1,		0,	0 },
{"blel",		"s,I,p",	0,    (int) M_BLEL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bleu",		"s,t,p",	0,    (int) M_BLEU,	INSN_MACRO,		0,		I1,		0,	0 },
{"bleu",		"s,I,p",	0,    (int) M_BLEU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bleul",		"s,t,p",	0,    (int) M_BLEUL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bleul",		"s,I,p",	0,    (int) M_BLEUL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"blez",		"s,p",		0x40800000, 0xffe00000,	RD_1|CBD,		0,		I1,		0,	0 },
{"blezl",		"s,p",		0,    (int) M_BLEZL,	INSN_MACRO,		0,		I1,		0,	0 },
{"blt",			"s,t,p",	0,    (int) M_BLT,	INSN_MACRO,		0,		I1,		0,	0 },
{"blt",			"s,I,p",	0,    (int) M_BLT_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bltl",		"s,t,p",	0,    (int) M_BLTL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bltl",		"s,I,p",	0,    (int) M_BLTL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bltu",		"s,t,p",	0,    (int) M_BLTU,	INSN_MACRO,		0,		I1,		0,	0 },
{"bltu",		"s,I,p",	0,    (int) M_BLTU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bltul",		"s,t,p",	0,    (int) M_BLTUL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bltul",		"s,I,p",	0,    (int) M_BLTUL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"bltz",		"s,p",		0x40000000, 0xffe00000,	RD_1|CBD,		0,		I1,		0,	0 },
{"bltzl",		"s,p",		0,    (int) M_BLTZL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bltzal",		"s,p",		0x40200000, 0xffe00000,	RD_1|WR_31|CBD,		BD32,		I1,		0,	0 },
{"bltzals",		"s,p",		0x42200000, 0xffe00000,	RD_1|WR_31|CBD,		BD16,		I1,		0,	0 },
{"bltzall",		"s,p",		0,    (int) M_BLTZALL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bnez",		"md,mE",	    0xac00,     0xfc00,	RD_1|CBD,		0,		I1,		0,	0 },
{"bnez",		"s,p",		0xb4000000, 0xffe00000,	RD_1|CBD,		0,		I1,		0,	0 },
{"bnezl",		"s,p",		0,    (int) M_BNEL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bne",			"md,mz,mE",	    0xac00,     0xfc00,	RD_1|CBD,		0,		I1,		0,	0 }, /* bnez */
{"bne",			"mz,md,mE",	    0xac00,     0xfc00,	RD_2|CBD,		0,		I1,		0,	0 }, /* bnez */
{"bne",			"s,t,p",	0xb4000000, 0xfc000000,	RD_1|RD_2|CBD,		0,		I1,		0,	0 },
{"bne",			"s,I,p",	0,    (int) M_BNE_I,	INSN_MACRO,		0,		I1,		0,	0 },
/* BNEZC is next to BNE so that we easily find it when converting a normal
   branch to a compact one.  */
{"bnezc",		"s,p",		0x40a00000, 0xffe00000,	RD_1|NODS,		CBR,		I1,		0,	0 },
{"bnel",		"s,t,p",	0,    (int) M_BNEL,	INSN_MACRO,		0,		I1,		0,	0 },
{"bnel",		"s,I,p",	0,    (int) M_BNEL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"break",		"",		    0x4680,     0xffff,	TRAP,			0,		I1,		0,	0 },
{"break",		"",		0x00000007, 0xffffffff,	TRAP,			0,		I1,		0,	0 },
{"break",		"mF",		    0x4680,     0xfff0,	TRAP,			0,		I1,		0,	0 },
{"break",		"c",		0x00000007, 0xfc00ffff,	TRAP,			0,		I1,		0,	0 },
{"break",		"c,q",		0x00000007, 0xfc00003f,	TRAP,			0,		I1,		0,	0 },
{"c.f.d",		"S,T",		0x5400043c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.f.d",		"M,S,T",	0x5400043c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.f.s",		"S,T",		0x5400003c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.f.s",		"M,S,T",	0x5400003c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.f.ps",		"S,T",		0x5400083c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.f.ps",		"M,S,T",	0x5400083c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.un.d",		"S,T",		0x5400047c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.un.d",		"M,S,T",	0x5400047c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.un.s",		"S,T",		0x5400007c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.un.s",		"M,S,T",	0x5400007c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.un.ps",		"S,T",		0x5400087c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.un.ps",		"M,S,T",	0x5400087c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.eq.d",		"S,T",		0x540004bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.eq.d",		"M,S,T",	0x540004bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.eq.s",		"S,T",		0x540000bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.eq.s",		"M,S,T",	0x540000bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.eq.ps",		"S,T",		0x540008bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.eq.ps",		"M,S,T",	0x540008bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ueq.d",		"S,T",		0x540004fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ueq.d",		"M,S,T",	0x540004fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ueq.s",		"S,T",		0x540000fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ueq.s",		"M,S,T",	0x540000fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ueq.ps",		"S,T",		0x540008fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ueq.ps",		"M,S,T",	0x540008fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.olt.d",		"S,T",		0x5400053c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.olt.d",		"M,S,T",	0x5400053c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.olt.s",		"S,T",		0x5400013c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.olt.s",		"M,S,T",	0x5400013c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.olt.ps",		"S,T",		0x5400093c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.olt.ps",		"M,S,T",	0x5400093c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ult.d",		"S,T",		0x5400057c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ult.d",		"M,S,T",	0x5400057c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ult.s",		"S,T",		0x5400017c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ult.s",		"M,S,T",	0x5400017c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ult.ps",		"S,T",		0x5400097c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ult.ps",		"M,S,T",	0x5400097c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ole.d",		"S,T",		0x540005bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ole.d",		"M,S,T",	0x540005bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ole.s",		"S,T",		0x540001bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ole.s",		"M,S,T",	0x540001bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ole.ps",		"S,T",		0x540009bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ole.ps",		"M,S,T",	0x540009bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ule.d",		"S,T",		0x540005fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ule.d",		"M,S,T",	0x540005fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ule.s",		"S,T",		0x540001fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ule.s",		"M,S,T",	0x540001fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ule.ps",		"S,T",		0x540009fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ule.ps",		"M,S,T",	0x540009fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.sf.d",		"S,T",		0x5400063c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.sf.d",		"M,S,T",	0x5400063c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.sf.s",		"S,T",		0x5400023c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.sf.s",		"M,S,T",	0x5400023c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.sf.ps",		"S,T",		0x54000a3c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.sf.ps",		"M,S,T",	0x54000a3c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngle.d",		"S,T",		0x5400067c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngle.d",		"M,S,T",	0x5400067c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngle.s",		"S,T",		0x5400027c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ngle.s",		"M,S,T",	0x5400027c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ngle.ps",		"S,T",		0x54000a7c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngle.ps",		"M,S,T",	0x54000a7c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.seq.d",		"S,T",		0x540006bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.seq.d",		"M,S,T",	0x540006bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.seq.s",		"S,T",		0x540002bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.seq.s",		"M,S,T",	0x540002bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.seq.ps",		"S,T",		0x54000abc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.seq.ps",		"M,S,T",	0x54000abc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngl.d",		"S,T",		0x540006fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngl.d",		"M,S,T",	0x540006fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngl.s",		"S,T",		0x540002fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ngl.s",		"M,S,T",	0x540002fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ngl.ps",		"S,T",		0x54000afc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngl.ps",		"M,S,T",	0x54000afc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.lt.d",		"S,T",		0x5400073c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.lt.d",		"M,S,T",	0x5400073c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.lt.s",		"S,T",		0x5400033c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.lt.s",		"M,S,T",	0x5400033c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.lt.ps",		"S,T",		0x54000b3c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.lt.ps",		"M,S,T",	0x54000b3c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.nge.d",		"S,T",		0x5400077c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.nge.d",		"M,S,T",	0x5400077c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.nge.s",		"S,T",		0x5400037c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.nge.s",		"M,S,T",	0x5400037c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.nge.ps",		"S,T",		0x54000b7c, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.nge.ps",		"M,S,T",	0x54000b7c, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.le.d",		"S,T",		0x540007bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.le.d",		"M,S,T",	0x540007bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.le.s",		"S,T",		0x540003bc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.le.s",		"M,S,T",	0x540003bc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.le.ps",		"S,T",		0x54000bbc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.le.ps",		"M,S,T",	0x54000bbc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngt.d",		"S,T",		0x540007fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngt.d",		"M,S,T",	0x540007fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngt.s",		"S,T",		0x540003fc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ngt.s",		"M,S,T",	0x540003fc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_S,	0,		I1,		0,	0 },
{"c.ngt.ps",		"S,T",		0x54000bfc, 0xfc00ffff,	RD_1|RD_2|WR_CC|FP_D,	0,		I1,		0,	0 },
{"c.ngt.ps",		"M,S,T",	0x54000bfc, 0xfc001fff,	RD_2|RD_3|WR_CC|FP_D,	0,		I1,		0,	0 },
{"cache",		"k,~(b)",	0x20006000, 0xfc00f000,	RD_3,			0,		I1,		0,	0 },
{"cache",		"k,A(b)",	0,    (int) M_CACHE_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"ceil.l.d",		"T,S",		0x5400533b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"ceil.l.s",		"T,S",		0x5400133b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"ceil.w.d",		"T,S",		0x54005b3b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"ceil.w.s",		"T,S",		0x54001b3b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"cfc1",		"t,G",		0x5400103b, 0xfc00ffff,	WR_1|RD_C1,		0,		I1,		0,	0 },
{"cfc1",		"t,S",		0x5400103b, 0xfc00ffff,	WR_1|RD_C1,		0,		I1,		0,	0 },
{"cfc2",		"t,G",		0x0000cd3c, 0xfc00ffff,	WR_1|RD_C2,		0,		I1,		0,	0 },
{"clo",			"t,s",		0x00004b3c, 0xfc00ffff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"clz",			"t,s",		0x00005b3c, 0xfc00ffff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"cop2",		"C",		0x00000002, 0xfc000007,	CP,			0,		I1,		0,	0 },
{"ctc1",		"t,G",		0x5400183b, 0xfc00ffff,	RD_1|WR_CC,		0,		I1,		0,	0 },
{"ctc1",		"t,S",		0x5400183b, 0xfc00ffff,	RD_1|WR_CC,		0,		I1,		0,	0 },
{"ctc2",		"t,G",		0x0000dd3c, 0xfc00ffff,	RD_1|WR_C2|WR_CC,	0,		I1,		0,	0 },
{"cvt.d.l",		"T,S",		0x5400537b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"cvt.d.s",		"T,S",		0x5400137b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"cvt.d.w",		"T,S",		0x5400337b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"cvt.l.d",		"T,S",		0x5400413b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"cvt.l.s",		"T,S",		0x5400013b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"cvt.s.l",		"T,S",		0x54005b7b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"cvt.s.d",		"T,S",		0x54001b7b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"cvt.s.w",		"T,S",		0x54003b7b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"cvt.s.pl",		"T,S",		0x5400213b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"cvt.s.pu",		"T,S",		0x5400293b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"cvt.w.d",		"T,S",		0x5400493b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"cvt.w.s",		"T,S",		0x5400093b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"cvt.ps.s",		"D,V,T",	0x54000180, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_S|FP_D, 0,		I1,		0,	0 },
{"dabs",		"d,v",		0,    (int) M_DABS,	INSN_MACRO,		0,		I3,		0,	0 },
{"dadd",		"d,v,t",	0x58000110, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"dadd",		"t,r,I",	0,    (int) M_DADD_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"daddi",		"t,r,.",	0x5800001c, 0xfc00003f,	WR_1|RD_2,		0,		I3,		0,	0 },
{"daddi",		"t,r,I",	0,    (int) M_DADD_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"daddiu",		"t,r,j",	0x5c000000, 0xfc000000,	WR_1|RD_2,		0,		I3,		0,	0 },
{"daddu",		"d,v,t",	0x58000150, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"daddu",		"t,r,I",	0,    (int) M_DADDU_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"dclo",		"t,s",		0x58004b3c, 0xfc00ffff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dclz",		"t,s",		0x58005b3c, 0xfc00ffff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"deret",		"",		0x0000e37c, 0xffffffff,	NODS,			0,		I1,		0,	0 },
{"dext",		"t,r,+A,+H",	0x5800002c, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 },
{"dext",		"t,r,+A,+G",	0x58000024, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 }, /* dextm */
{"dext",		"t,r,+E,+H",	0x58000014, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 }, /* dextu */
{"dextm",		"t,r,+A,+G",	0x58000024, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 },
{"dextu",		"t,r,+E,+H",	0x58000014, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 },
/* For ddiv, see the comments about div.  */
{"ddiv",		"z,s,t",	0x5800ab3c, 0xfc00ffff,	RD_2|RD_3|WR_HILO,	0,		I3,		0,	0 },
{"ddiv",		"z,t",		0x5800ab3c, 0xfc1fffff,	RD_2|WR_HILO,		0,		I3,		0,	0 },
{"ddiv",		"d,v,t",	0,    (int) M_DDIV_3,	INSN_MACRO,		0,		I3,		0,	0 },
{"ddiv",		"d,v,I",	0,    (int) M_DDIV_3I,	INSN_MACRO,		0,		I3,		0,	0 },
/* For ddivu, see the comments about div.  */
{"ddivu",		"z,s,t",	0x5800bb3c, 0xfc00ffff,	RD_2|RD_3|WR_HILO,	0,		I3,		0,	0 },
{"ddivu",		"z,t",		0x5800bb3c, 0xfc1fffff,	RD_2|WR_HILO,		0,		I3,		0,	0 },
{"ddivu",		"d,v,t",	0,    (int) M_DDIVU_3,	INSN_MACRO,		0,		I3,		0,	0 },
{"ddivu",		"d,v,I",	0,    (int) M_DDIVU_3I,	INSN_MACRO,		0,		I3,		0,	0 },
{"di",			"",		0x0000477c, 0xffffffff,	RD_C0,			0,		I1,		0,	0 },
{"di",			"s",		0x0000477c, 0xffe0ffff,	WR_1|RD_C0,		0,		I1,		0,	0 },
{"dins",		"t,r,+A,+B",	0x5800000c, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 },
{"dins",		"t,r,+A,+F",	0x58000004, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 }, /* dinsm */
{"dins",		"t,r,+E,+F",	0x58000034, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 }, /* dinsu */
{"dinsm",		"t,r,+A,+F",	0x58000004, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 },
{"dinsu",		"t,r,+E,+F",	0x58000034, 0xfc00003f, WR_1|RD_2,		0,		I3,		0,	0 },
/* The MIPS assembler treats the div opcode with two operands as
   though the first operand appeared twice (the first operand is both
   a source and a destination).  To get the div machine instruction,
   you must use an explicit destination of $0.  */
{"div",			"z,s,t",	0x0000ab3c, 0xfc00ffff,	RD_2|RD_3|WR_HILO,	0,		I1,		0,	0 },
{"div",			"z,t",		0x0000ab3c, 0xfc1fffff,	RD_2|WR_HILO,		0,		I1,		0,	0 },
{"div",			"d,v,t",	0,    (int) M_DIV_3,	INSN_MACRO,		0,		I1,		0,	0 },
{"div",			"d,v,I",	0,    (int) M_DIV_3I,	INSN_MACRO,		0,		I1,		0,	0 },
{"div.d",		"D,V,T",	0x540001f0, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"div.s",		"D,V,T",	0x540000f0, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_S,	0,		I1,		0,	0 },
/* For divu, see the comments about div.  */
{"divu",		"z,s,t",	0x0000bb3c, 0xfc00ffff,	RD_2|RD_3|WR_HILO,	0,		I1,		0,	0 },
{"divu",		"z,t",		0x0000bb3c, 0xfc1fffff,	RD_2|WR_HILO,		0,		I1,		0,	0 },
{"divu",		"d,v,t",	0,    (int) M_DIVU_3,	INSN_MACRO,		0,		I1,		0,	0 },
{"divu",		"d,v,I",	0,    (int) M_DIVU_3I,	INSN_MACRO,		0,		I1,		0,	0 },
{"dla",			"t,A(b)",	0,    (int) M_DLA_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"dlca",		"t,A(b)",	0,    (int) M_DLCA_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"dli",			"t,j",		0x30000000, 0xfc1f0000,	WR_1,			0,		I3,		0,	0 }, /* addiu */
{"dli",			"t,i",		0x50000000, 0xfc1f0000,	WR_1,			0,		I3,		0,	0 }, /* ori */
{"dli",			"t,I",		0,    (int) M_DLI,	INSN_MACRO,		0,		I3,		0,	0 },
{"dmfc0",		"t,G",		0x580000fc, 0xfc00ffff,	WR_1|RD_C0,		0,		I3,		0,	0 },
{"dmfc0",		"t,G,H",	0x580000fc, 0xfc00c7ff,	WR_1|RD_C0,		0,		I3,		0,	0 },
{"dmfgc0",		"t,G",		0x580004fc, 0xfc00ffff,	WR_1|RD_C0,		0,		0,		IVIRT64, 0 },
{"dmfgc0",		"t,G,H",	0x580004fc, 0xfc00c7ff,	WR_1|RD_C0,		0,		0,		IVIRT64, 0 },
{"dmtc0",		"t,G",		0x580002fc, 0xfc00ffff,	RD_1|WR_C0|WR_CC,	0,		I3,		0,	0 },
{"dmtc0",		"t,G,H",	0x580002fc, 0xfc00c7ff,	RD_1|WR_C0|WR_CC,	0,		I3,		0,	0 },
{"dmtgc0",		"t,G",		0x580006fc, 0xfc00ffff,	RD_1|WR_C0|WR_CC,	0,		0,		IVIRT64, 0 },
{"dmtgc0",		"t,G,H",	0x580006fc, 0xfc00c7ff,	RD_1|WR_C0|WR_CC,	0,		0,		IVIRT64, 0 },
{"dmfc1",		"t,S",		0x5400243b, 0xfc00ffff,	WR_1|RD_2|FP_S|LC,	0,		I3,		0,	0 },
{"dmfc1",		"t,G",		0x5400243b, 0xfc00ffff,	WR_1|RD_2|FP_S|LC,	0,		I3,		0,	0 },
{"dmtc1",		"t,G",		0x54002c3b, 0xfc00ffff,	RD_1|WR_2|FP_S|CM,	0,		I3,		0,	0 },
{"dmtc1",		"t,S",		0x54002c3b, 0xfc00ffff,	RD_1|WR_2|FP_S|CM,	0,		I3,		0,	0 },
{"dmfc2",		"t,G",		0x00006d3c, 0xfc00ffff,	WR_1|RD_C2,		0,		I3,		0,	0 },
/*{"dmfc2",		"t,G,H",	0x58000283, 0xfc001fff,	WR_1|RD_C2,		0,		I3,		0,	0 },*/
{"dmtc2",		"t,G",		0x00007d3c, 0xfc00ffff,	RD_1|WR_C2|WR_CC,	0,		I3,		0,	0 },
/*{"dmtc2",		"t,G,H",	0x58000683, 0xfc001fff,	RD_1|WR_C2|WR_CC,	0,		I3,		0,	0 },*/
{"dmul",		"d,v,t",	0,    (int) M_DMUL,	INSN_MACRO,		0,		I3,		0,	0 },
{"dmul",		"d,v,I",	0,    (int) M_DMUL_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"dmulo",		"d,v,t",	0,    (int) M_DMULO,	INSN_MACRO,		0,		I3,		0,	0 },
{"dmulo",		"d,v,I",	0,    (int) M_DMULO_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"dmulou",		"d,v,t",	0,    (int) M_DMULOU,	INSN_MACRO,		0,		I3,		0,	0 },
{"dmulou",		"d,v,I",	0,    (int) M_DMULOU_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"dmult",		"s,t",		0x58008b3c, 0xfc00ffff,	RD_1|RD_2|WR_HILO,	0,		I3,		0,	0 },
{"dmultu",		"s,t",		0x58009b3c, 0xfc00ffff,	RD_1|RD_2|WR_HILO,	0,		I3,		0,	0 },
{"dneg",		"d,w",		0x58000190, 0xfc1f07ff,	WR_1|RD_2,		0,		I3,		0,	0 }, /* dsub 0 */
{"dnegu",		"d,w",		0x580001d0, 0xfc1f07ff,	WR_1|RD_2,		0,		I3,		0,	0 }, /* dsubu 0 */
{"drem",		"z,s,t",	0x5800ab3c, 0xfc00ffff,	RD_2|RD_3|WR_HILO,	0,		I3,		0,	0 },
{"drem",		"d,v,t",	0,    (int) M_DREM_3,	INSN_MACRO,		0,		I3,		0,	0 },
{"drem",		"d,v,I",	0,    (int) M_DREM_3I,	INSN_MACRO,		0,		I3,		0,	0 },
{"dremu",		"z,s,t",	0x5800bb3c, 0xfc00ffff,	RD_2|RD_3|WR_HILO,	0,		I3,		0,	0 },
{"dremu",		"d,v,t",	0,    (int) M_DREMU_3,	INSN_MACRO,		0,		I3,		0,	0 },
{"dremu",		"d,v,I",	0,    (int) M_DREMU_3I,	INSN_MACRO,		0,		I3,		0,	0 },
{"drol",		"d,v,t",	0,    (int) M_DROL,	INSN_MACRO,		0,		I3,		0,	0 },
{"drol",		"d,v,I",	0,    (int) M_DROL_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"dror",		"d,v,t",	0,    (int) M_DROR,	INSN_MACRO,		0,		I3,		0,	0 },
{"dror",		"d,v,I",	0,    (int) M_DROR_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"dror",		"t,r,<",	0x580000c0, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"drorv",		"d,t,s",	0x580000d0, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"dror32",		"t,r,<",	0x580000c8, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"drotl",		"d,v,t",	0,    (int) M_DROL,	INSN_MACRO,		0,		I3,		0,	0 },
{"drotl",		"d,v,I",	0,    (int) M_DROL_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"drotr",		"d,v,t",	0,    (int) M_DROR,	INSN_MACRO,		0,		I3,		0,	0 },
{"drotr",		"d,v,I",	0,    (int) M_DROR_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"drotrv",		"d,t,s",	0x580000d0, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"drotr32",		"t,r,<",	0x580000c8, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dsbh",		"t,r",		0x58007b3c, 0xfc00ffff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dshd",		"t,r",		0x5800fb3c, 0xfc00ffff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dsllv",		"d,t,s",	0x58000010, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"dsll32",		"t,r,<",	0x58000008, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dsll",		"d,t,s",	0x58000010, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 }, /* dsllv */
{"dsll",		"t,r,>",	0x58000008, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 }, /* dsll32 */
{"dsll",		"t,r,<",	0x58000000, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dsrav",		"d,t,s",	0x58000090, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"dsra32",		"t,r,<",	0x58000088, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dsra",		"d,t,s",	0x58000090, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 }, /* dsrav */
{"dsra",		"t,r,>",	0x58000088, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 }, /* dsra32 */
{"dsra",		"t,r,<",	0x58000080, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dsrlv",		"d,t,s",	0x58000050, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"dsrl32",		"t,r,<",	0x58000048, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dsrl",		"d,t,s",	0x58000050, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 }, /* dsrlv */
{"dsrl",		"t,r,>",	0x58000048, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 }, /* dsrl32 */
{"dsrl",		"t,r,<",	0x58000040, 0xfc0007ff,	WR_1|RD_2,		0,		I3,		0,	0 },
{"dsub",		"d,v,t",	0x58000190, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"dsub",		"d,v,I",	0,    (int) M_DSUB_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"dsubu",		"d,v,t",	0x580001d0, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I3,		0,	0 },
{"dsubu",		"d,v,I",	0,    (int) M_DSUBU_I,	INSN_MACRO,		0,		I3,		0,	0 },
{"ei",			"",		0x0000577c, 0xffffffff,	WR_C0,			0,		I1,		0,	0 },
{"ei",			"s",		0x0000577c, 0xffe0ffff,	WR_1|WR_C0,		0,		I1,		0,	0 },
{"eret",		"",		0x0000f37c, 0xffffffff,	NODS,			0,		I1,		0,	0 },
{"eretnc",		"",		0x0001f37c, 0xffffffff,	NODS,			0,		I36,		0,	0 },
{"ext",			"t,r,+A,+C",	0x0000002c, 0xfc00003f, WR_1|RD_2,		0,		I1,		0,	0 },
{"floor.l.d",		"T,V",		0x5400433b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"floor.l.s",		"T,V",		0x5400033b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"floor.w.d",		"T,V",		0x54004b3b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"floor.w.s",		"T,V",		0x54000b3b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"hypcall",		"",		0x0000c37c, 0xffffffff,	TRAP,			0,		0,		IVIRT,	0 },
{"hypcall",		"+J",		0x0000c37c, 0xfc00ffff,	TRAP,			0,		0,		IVIRT,	0 },
{"ins",			"t,r,+A,+B",	0x0000000c, 0xfc00003f, WR_1|RD_2,		0,		I1,		0,	0 },
{"iret",		"",		0x0000d37c, 0xffffffff,	NODS,			0,		0,		MC,	0 },
{"jr",			"mj",		    0x4580,     0xffe0,	RD_1|UBD,		0,		I1,		0,	0 },
{"jr",			"s",		0x00000f3c, 0xffe0ffff,	RD_1|UBD,		BD32,		I1,		0,	0 }, /* jalr */
{"jrs",			"s",		0x00004f3c, 0xffe0ffff,	RD_1|UBD,		BD16,		I1,		0,	0 }, /* jalrs */
{"jraddiusp",		"mP",		    0x4700,     0xffe0,	NODS,			WR_sp|RD_31|RD_sp|UBR, I1,	0,	0 },
/* This macro is after the real instruction so that it only matches with
   -minsn32.  */
{"jraddiusp",		"mP",		0,   (int) M_JRADDIUSP,	INSN_MACRO,		0,		I1,		0,	0 },
{"jr.hb",		"s",		0x00001f3c, 0xffe0ffff,	RD_1|UBD,		BD32,		I1,		0,	0 }, /* jalr.hb */
{"jrs.hb",		"s",		0x00005f3c, 0xffe0ffff,	RD_1|UBD,		BD16,		I1,		0,	0 }, /* jalrs.hb */
{"j",			"mj",		    0x4580,     0xffe0,	RD_1|UBD,		0,		I1,		0,	0 }, /* jr */
{"j",			"s",		0x00000f3c, 0xffe0ffff,	RD_1|UBD,		BD32,		I1,		0,	0 }, /* jr */
/* SVR4 PIC code requires special handling for j, so it must be a
   macro.  */
{"j",			"a",		0,    (int) M_J_A,	INSN_MACRO,		0,		I1,		0,	0 },
/* This form of j is used by the disassembler and internally by the
   assembler, but will never match user input (because the line above
   will match first).  */
{"j",			"a",		0xd4000000, 0xfc000000,	UBD,			0,		I1,		0,	0 },
/* JRC is close to JR and J so that we easily find it when converting
   a normal jump to a compact one.  */
{"jrc",			"mj",		    0x45a0,     0xffe0,	RD_1|NODS,		UBR,		I1,		0,	0 },
/* This macro is after the real instruction so that it only matches with
   -minsn32.  */
{"jrc",			"s",		0,    (int) M_JRC,	INSN_MACRO,		0,		I1,		0,	0 },
{"jalr",		"mj",		    0x45c0,     0xffe0,	RD_1|WR_31|UBD,		BD32,		I1,		0,	0 },
{"jalr",		"my,mj",	    0x45c0,     0xffe0,	RD_2|WR_31|UBD,		BD32,		I1,		0,	0 },
{"jalr",		"s",		0x03e00f3c, 0xffe0ffff,	RD_1|WR_31|UBD,		BD32,		I1,		0,	0 },
{"jalr",		"t,s",		0x00000f3c, 0xfc00ffff,	WR_1|RD_2|UBD,		BD32,		I1,		0,	0 },
{"jalr.hb",		"s",		0x03e01f3c, 0xffe0ffff,	RD_1|WR_31|UBD,		BD32,		I1,		0,	0 },
{"jalr.hb",		"t,s",		0x00001f3c, 0xfc00ffff,	WR_1|RD_2|UBD,		BD32,		I1,		0,	0 },
{"jalrs",		"mj",		    0x45e0,     0xffe0,	RD_1|WR_31|UBD,		BD16,		I1,		0,	0 },
{"jalrs",		"my,mj",	    0x45e0,     0xffe0,	RD_2|WR_31|UBD,		BD16,		I1,		0,	0 },
{"jalrs",		"s",		0x03e04f3c, 0xffe0ffff,	RD_1|WR_31|UBD,		BD16,		I1,		0,	0 },
{"jalrs",		"t,s",		0x00004f3c, 0xfc00ffff,	WR_1|RD_2|UBD,		BD16,		I1,		0,	0 },
{"jalrs.hb",		"s",		0x03e05f3c, 0xffe0ffff,	RD_1|WR_31|UBD,		BD16,		I1,		0,	0 },
{"jalrs.hb",		"t,s",		0x00005f3c, 0xfc00ffff,	WR_1|RD_2|UBD,		BD16,		I1,		0,	0 },
/* SVR4 PIC code requires special handling for jal, so it must be a
   macro.  */
{"jal",			"d,s",		0,    (int) M_JAL_2,	INSN_MACRO,		0,		I1,		0,	0 },
{"jal",			"s",		0,    (int) M_JAL_1,	INSN_MACRO,		0,		I1,		0,	0 },
{"jal",			"a",		0,    (int) M_JAL_A,	INSN_MACRO,		0,		I1,		0,	0 },
/* This form of jal is used by the disassembler and internally by the
   assembler, but will never match user input (because the line above
   will match first).  */
{"jal",			"a",		0xf4000000, 0xfc000000,	WR_31|UBD,		BD32,		I1,		0,	0 },
{"jals",		"d,s",		0,    (int) M_JALS_2,	INSN_MACRO,		0,		I1,		0,	0 },
{"jals",		"s",		0,    (int) M_JALS_1,	INSN_MACRO,		0,		I1,		0,	0 },
{"jals",		"a",		0,    (int) M_JALS_A,	INSN_MACRO,		0,		I1,		0,	0 },
{"jals",		"a",		0x74000000, 0xfc000000,	WR_31|UBD,		BD16,		I1,		0,	0 },
{"jalx",		"+i",		0xf0000000, 0xfc000000,	WR_31|UBD,		BD32,		I1,		0,	0 },
{"la",			"t,A(b)",	0,    (int) M_LA_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lb",			"t,o(b)",	0x1c000000, 0xfc000000,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lb",			"t,A(b)",	0,    (int) M_LB_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lbu",			"md,mG(ml)",        0x0800,     0xfc00,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lbu",			"t,o(b)",	0x14000000, 0xfc000000,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lbu",			"t,A(b)",	0,    (int) M_LBU_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lca",			"t,A(b)",	0,    (int) M_LCA_AB,	INSN_MACRO,		0,		I1,		0,	0 },
/* The macro has to be first to handle o32 correctly.  */
{"ld",			"t,A(b)",	0,    (int) M_LD_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"ld",			"t,o(b)",	0xdc000000, 0xfc000000,	WR_1|RD_3|LM,		0,		I3,		0,	0 },
{"ldc1",		"T,o(b)",	0xbc000000, 0xfc000000,	WR_1|RD_3|FP_D|LM,	0,		I1,		0,	0 },
{"ldc1",		"E,o(b)",	0xbc000000, 0xfc000000,	WR_1|RD_3|FP_D|LM,	0,		I1,		0,	0 },
{"ldc1",		"T,A(b)",	0,    (int) M_LDC1_AB,	INSN_MACRO,		INSN2_M_FP_D,	I1,		0,	0 },
{"ldc1",		"E,A(b)",	0,    (int) M_LDC1_AB,	INSN_MACRO,		INSN2_M_FP_D,	I1,		0,	0 },
{"ldc2",		"E,~(b)",	0x20002000, 0xfc00f000,	RD_3|WR_CC|LM,		0,		I1,		0,	0 },
{"ldc2",		"E,A(b)",	0,    (int) M_LDC2_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"l.d",			"T,o(b)",	0xbc000000, 0xfc000000,	WR_1|RD_3|FP_D|LM,	0,		I1,		0,	0 }, /* ldc1 */
{"l.d",			"T,A(b)",	0,    (int) M_LDC1_AB,	INSN_MACRO,		INSN2_M_FP_D,	I1,		0,	0 },
{"ldl",			"t,~(b)",	0x60004000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I3,		0,	0 },
{"ldl",			"t,A(b)",	0,    (int) M_LDL_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"ldm",			"n,~(b)",	0x20007000, 0xfc00f000,	RD_3|LM,		0,		I3,		0,	0 },
{"ldm",			"n,A(b)",	0,    (int) M_LDM_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"ldp",			"t,~(b)",	0x20004000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I3,		0,	0 },
{"ldp",			"t,A(b)",	0,    (int) M_LDP_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"ldr",			"t,~(b)",	0x60005000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I3,		0,	0 },
{"ldr",			"t,A(b)",	0,    (int) M_LDR_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"ldxc1",		"D,t(b)",	0x540000c8, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D|LM, 0,		I1,		0,	0 },
{"lh",			"t,o(b)",	0x3c000000, 0xfc000000,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lh",			"t,A(b)",	0,    (int) M_LH_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lhu",			"md,mH(ml)",        0x2800,     0xfc00,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lhu",			"t,o(b)",	0x34000000, 0xfc000000,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lhu",			"t,A(b)",	0,    (int) M_LHU_AB,	INSN_MACRO,		0,		I1,		0,	0 },
/* li is at the start of the table.  */
{"li.d",		"t,F",		0,    (int) M_LI_D,	INSN_MACRO,		INSN2_M_FP_D,	I1,		0,	0 },
{"li.d",		"T,L",		0,    (int) M_LI_DD,	INSN_MACRO,		INSN2_M_FP_D,	I1,		0,	0 },
{"li.s",		"t,f",		0,    (int) M_LI_S,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"li.s",		"T,l",		0,    (int) M_LI_SS,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"ll",			"t,~(b)",	0x60003000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"ll",			"t,A(b)",	0,    (int) M_LL_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lld",			"t,~(b)",	0x60007000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I3,		0,	0 },
{"lld",			"t,A(b)",	0,    (int) M_LLD_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"lui",			"s,u",		0x41a00000, 0xffe00000,	WR_1,			0,		I1,		0,	0 },
{"luxc1",		"D,t(b)",	0x54000148, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D|LM, 0,		I1,		0,	0 },
{"lw",			"md,mJ(ml)",        0x6800,     0xfc00,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lw",			"mp,mU(ms)",        0x4800,     0xfc00,	WR_1|RD_3|LM,		0,		I1,		0,	0 }, /* lwsp */
{"lw",			"md,mA(ma)",        0x6400,     0xfc00,	WR_1|RD_3|LM,		0,		I1,		0,	0 }, /* lwgp */
{"lw",			"t,o(b)",	0xfc000000, 0xfc000000,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lw",			"t,A(b)",	0,    (int) M_LW_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lwc1",		"T,o(b)",	0x9c000000, 0xfc000000,	WR_1|RD_3|FP_S|LM,	0,		I1,		0,	0 },
{"lwc1",		"E,o(b)",	0x9c000000, 0xfc000000,	WR_1|RD_3|FP_S|LM,	0,		I1,		0,	0 },
{"lwc1",		"T,A(b)",	0,    (int) M_LWC1_AB,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"lwc1",		"E,A(b)",	0,    (int) M_LWC1_AB,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"lwc2",		"E,~(b)",	0x20000000, 0xfc00f000,	RD_3|WR_CC|LM,		0,		I1,		0,	0 },
{"lwc2",		"E,A(b)",	0,    (int) M_LWC2_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"l.s",			"T,o(b)",	0x9c000000, 0xfc000000,	WR_1|RD_3|FP_S|LM,	0,		I1,		0,	0 }, /* lwc1 */
{"l.s",			"T,A(b)",	0,    (int) M_LWC1_AB,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"lwl",			"t,~(b)",	0x60000000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lwl",			"t,A(b)",	0,    (int) M_LWL_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lcache",		"t,~(b)",	0x60000000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I1,		0,	0 }, /* same */
{"lcache",		"t,A(b)",	0,    (int) M_LWL_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lwm",			"mN,mJ(ms)",	    0x4500,     0xffc0,	RD_3|NODS|LM,		0,		I1,		0,	0 },
{"lwm",			"n,~(b)",	0x20005000, 0xfc00f000,	RD_3|NODS|LM,		0,		I1,		0,	0 },
{"lwm",			"n,A(b)",	0,    (int) M_LWM_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lwp",			"t,~(b)",	0x20001000, 0xfc00f000,	WR_1|RD_3|NODS|LM,	0,		I1,		0,	0 },
{"lwp",			"t,A(b)",	0,    (int) M_LWP_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lwr",			"t,~(b)",	0x60001000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I1,		0,	0 },
{"lwr",			"t,A(b)",	0,    (int) M_LWR_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lwu",			"t,~(b)",	0x6000e000, 0xfc00f000,	WR_1|RD_3|LM,		0,		I3,		0,	0 },
{"lwu",			"t,A(b)",	0,    (int) M_LWU_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"lwxc1",		"D,t(b)",	0x54000048, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_S|LM, 0,		I1,		0,	0 },
{"flush",		"t,~(b)",	0x60001000, 0xfc00f000,	WR_1|RD_3,		0,		I1,		0,	0 }, /* same */
{"flush",		"t,A(b)",	0,    (int) M_LWR_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"lwxs",		"d,t(b)",	0x00000118, 0xfc0007ff,	WR_1|RD_2|RD_3|LM,	0,		I1,		0,	0 },
{"madd",		"s,t",		0x0000cb3c, 0xfc00ffff,	RD_1|RD_2|MOD_HILO,	0,		I1,		0,	0 },
{"madd",		"7,s,t",	0x00000abc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"madd.d",		"D,R,S,T",	0x54000009, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
{"madd.s",		"D,R,S,T",	0x54000001, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_S, 0,		I1,		0,	0 },
{"madd.ps",		"D,R,S,T",	0x54000011, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
{"maddu",		"s,t",		0x0000db3c, 0xfc00ffff,	RD_1|RD_2|MOD_HILO,	0,		I1,		0,	0 },
{"maddu",		"7,s,t",	0x00001abc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"mfc0",		"t,G",		0x000000fc, 0xfc00ffff,	WR_1|RD_C0,		0,		I1,		0,	0 },
{"mfc0",		"t,G,H",	0x000000fc, 0xfc00c7ff,	WR_1|RD_C0,		0,		I1,		0,	0 },
{"mfc1",		"t,S",		0x5400203b, 0xfc00ffff,	WR_1|RD_2|FP_S|LC,	0,		I1,		0,	0 },
{"mfc1",		"t,G",		0x5400203b, 0xfc00ffff,	WR_1|RD_2|FP_S|LC,	0,		I1,		0,	0 },
{"mfc2",		"t,G",		0x00004d3c, 0xfc00ffff,	WR_1|RD_C2,		0,		I1,		0,	0 },
{"mfgc0",		"t,G",		0x000004fc, 0xfc00ffff,	WR_1|RD_C0,		0,		0,		IVIRT,	0 },
{"mfgc0",		"t,G,H",	0x000004fc, 0xfc00c7ff,	WR_1|RD_C0,		0,		0,		IVIRT,	0 },
{"mfhc0",		"t,G",		0x000000f4, 0xfc00ffff,	WR_1|RD_C0,		0,		0,		XPA,	0 },
{"mfhc0",		"t,G,H",	0x000000f4, 0xfc00c7ff,	WR_1|RD_C0,		0,		0,		XPA,	0 },
{"mfhgc0",		"t,G",		0x000004f4, 0xfc00ffff,	WR_1|RD_C0,		0,		0,		XPAVZ,	0 },
{"mfhgc0",		"t,G,H",	0x000004f4, 0xfc00c7ff,	WR_1|RD_C0,		0,		0,		XPAVZ,	0 },
{"mfhc1",		"t,S",		0x5400303b, 0xfc00ffff,	WR_1|RD_2|FP_D|LC,	0,		I1,		0,	0 },
{"mfhc1",		"t,G",		0x5400303b, 0xfc00ffff,	WR_1|RD_2|FP_D|LC,	0,		I1,		0,	0 },
{"mfhc2",		"t,G",		0x00008d3c, 0xfc00ffff,	WR_1|RD_C2,		0,		I1,		0,	0 },
{"mfhi",		"mj",		    0x4600,     0xffe0,	WR_1|RD_HI,		0,		I1,		0,	0 },
{"mfhi",		"s",		0x00000d7c, 0xffe0ffff,	WR_1|RD_HI,		0,		I1,		0,	0 },
{"mfhi",		"s,7",		0x0000007c, 0xffe03fff,	WR_1|RD_HI,		0,		0,		D32,	0 },
{"mflo",		"mj",		    0x4640,     0xffe0,	WR_1|RD_LO,		0,		I1,		0,	0 },
{"mflo",		"s",		0x00001d7c, 0xffe0ffff,	WR_1|RD_LO,		0,		I1,		0,	0 },
{"mflo",		"s,7",		0x0000107c, 0xffe03fff,	WR_1|RD_LO,		0,		0,		D32,	0 },
{"mov.d",		"T,S",		0x5400207b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"mov.s",		"T,S",		0x5400007b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"mov.ps",		"T,S",		0x5400407b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"movep",		"mh,mm,mn",     0x8400,     0xfc01,	WR_1|RD_2|RD_3|NODS,	0,		I1,		0,	0 },
/* This macro is after the real instruction so that it only matches with
   -minsn32.  */
{"movep",		"mh,mm,mn",	0,    (int) M_MOVEP,	INSN_MACRO,		0,		I1,		0,	0 },
{"movf",		"t,s,M",	0x5400017b, 0xfc001fff,	WR_1|RD_2|RD_CC|FP_S|FP_D, 0,		I1,		0,	0 },
{"movf.d",		"T,S,M",	0x54000220, 0xfc001fff,	WR_1|RD_2|RD_CC|FP_D,	0,		I1,		0,	0 },
{"movf.s",		"T,S,M",	0x54000020, 0xfc001fff,	WR_1|RD_2|RD_CC|FP_S,	0,		I1,		0,	0 },
{"movf.ps",		"T,S,M",	0x54000420, 0xfc001fff,	WR_1|RD_2|RD_CC|FP_D,	0,		I1,		0,	0 },
{"movn",		"d,v,t",	0x00000018, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"movn.d",		"D,S,t",	0x54000138, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"movn.s",		"D,S,t",	0x54000038, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_S,	0,		I1,		0,	0 },
{"movn.ps",		"D,S,t",	0x54000238, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"movt",		"t,s,M",	0x5400097b, 0xfc001fff,	WR_1|RD_2|RD_CC|FP_S|FP_D, 0,		I1,		0,	0 },
{"movt.d",		"T,S,M",	0x54000260, 0xfc001fff,	WR_1|RD_2|RD_CC|FP_D,	0,		I1,		0,	0 },
{"movt.s",		"T,S,M",	0x54000060, 0xfc001fff,	WR_1|RD_2|RD_CC|FP_S,	0,		I1,		0,	0 },
{"movt.ps",		"T,S,M",	0x54000460, 0xfc001fff,	WR_1|RD_2|RD_CC|FP_D,	0,		I1,		0,	0 },
{"movz",		"d,v,t",	0x00000058, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"movz.d",		"D,S,t",	0x54000178, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"movz.s",		"D,S,t",	0x54000078, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_S,	0,		I1,		0,	0 },
{"movz.ps",		"D,S,t",	0x54000278, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"msub",		"s,t",		0x0000eb3c, 0xfc00ffff,	RD_1|RD_2|MOD_HILO,	0,		I1,		0,	0 },
{"msub",		"7,s,t",	0x00002abc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"msub.d",		"D,R,S,T",	0x54000029, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
{"msub.s",		"D,R,S,T",	0x54000021, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_S, 0,		I1,		0,	0 },
{"msub.ps",		"D,R,S,T",	0x54000031, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
{"msubu",		"s,t",		0x0000fb3c, 0xfc00ffff,	RD_1|RD_2|MOD_HILO,	0,		I1,		0,	0 },
{"msubu",		"7,s,t",	0x00003abc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"mtc0",		"t,G",		0x000002fc, 0xfc00ffff,	RD_1|WR_C0|WR_CC,	0,		I1,		0,	0 },
{"mtc0",		"t,G,H",	0x000002fc, 0xfc00c7ff,	RD_1|WR_C0|WR_CC,	0,		I1,		0,	0 },
{"mtc1",		"t,S",		0x5400283b, 0xfc00ffff,	RD_1|WR_2|FP_S|CM,	0,		I1,		0,	0 },
{"mtc1",		"t,G",		0x5400283b, 0xfc00ffff,	RD_1|WR_2|FP_S|CM,	0,		I1,		0,	0 },
{"mtc2",		"t,G",		0x00005d3c, 0xfc00ffff,	RD_1|WR_C2|WR_CC,	0,		I1,		0,	0 },
{"mtgc0",		"t,G",		0x000006fc, 0xfc00ffff,	RD_1|WR_C0|WR_CC,	0,		0,		IVIRT,	0 },
{"mtgc0",		"t,G,H",	0x000006fc, 0xfc00c7ff,	RD_1|WR_C0|WR_CC,	0,		0,		IVIRT,	0 },
{"mthc0",		"t,G",		0x000002f4, 0xfc00ffff,	RD_1|WR_C0|WR_CC,	0,		0,		XPA,	0 },
{"mthc0",		"t,G,H",	0x000002f4, 0xfc00c7ff,	RD_1|WR_C0|WR_CC,	0,		0,		XPA,	0 },
{"mthgc0",		"t,G",		0x000006f4, 0xfc00ffff,	RD_1|WR_C0|WR_CC,	0,		0,		XPAVZ,	0 },
{"mthgc0",		"t,G,H",	0x000006f4, 0xfc00c7ff,	RD_1|WR_C0|WR_CC,	0,		0,		XPAVZ,	0 },
{"mthc1",		"t,S",		0x5400383b, 0xfc00ffff,	RD_1|WR_2|FP_D|CM,	0,		I1,		0,	0 },
{"mthc1",		"t,G",		0x5400383b, 0xfc00ffff,	RD_1|WR_2|FP_D|CM,	0,		I1,		0,	0 },
{"mthc2",		"t,G",		0x00009d3c, 0xfc00ffff,	RD_1|WR_C2|WR_CC,	0,		I1,		0,	0 },
{"mthi",		"s",		0x00002d7c, 0xffe0ffff,	RD_1|WR_HI,		0,		I1,		0,	0 },
{"mthi",		"s,7",		0x0000207c, 0xffe03fff,	RD_1|WR_HI,		0,		0,		D32,	0 },
{"mtlo",		"s",		0x00003d7c, 0xffe0ffff,	RD_1|WR_LO,		0,		I1,		0,	0 },
{"mtlo",		"s,7",		0x0000307c, 0xffe03fff,	RD_1|WR_LO,		0,		0,		D32,	0 },
{"mul",			"d,v,t",	0x00000210, 0xfc0007ff,	WR_1|RD_2|RD_3|WR_HILO,	0,		I1,		0,	0 },
{"mul",			"d,v,I",	0,    (int) M_MUL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"mul.d",		"D,V,T",	0x540001b0, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"mul.s",		"D,V,T",	0x540000b0, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_S,	0,		I1,		0,	0 },
{"mul.ps",		"D,V,T",	0x540002b0, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"mulo",		"d,v,t",	0,    (int) M_MULO,	INSN_MACRO,		0,		I1,		0,	0 },
{"mulo",		"d,v,I",	0,    (int) M_MULO_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"mulou",		"d,v,t",	0,    (int) M_MULOU,	INSN_MACRO,		0,		I1,		0,	0 },
{"mulou",		"d,v,I",	0,    (int) M_MULOU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"mult",		"s,t",		0x00008b3c, 0xfc00ffff,	RD_1|RD_2|WR_HILO,	0,		I1,		0,	0 },
{"mult",		"7,s,t",	0x00000cbc, 0xfc003fff,	RD_2|RD_3|WR_a,		0,		0,		D32,	0 },
{"multu",		"s,t",		0x00009b3c, 0xfc00ffff,	RD_1|RD_2|WR_HILO,	0,		I1,		0,	0 },
{"multu",		"7,s,t",	0x00001cbc, 0xfc003fff,	RD_2|RD_3|WR_a,		0,		0,		D32,	0 },
{"neg",			"d,w",		0x00000190, 0xfc1f07ff,	WR_1|RD_2,		0,		I1,		0,	0 }, /* sub 0 */
{"negu",		"d,w",		0x000001d0, 0xfc1f07ff,	WR_1|RD_2,		0,		I1,		0,	0 }, /* subu 0 */
{"neg.d",		"T,V",		0x54002b7b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"neg.s",		"T,V",		0x54000b7b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"neg.ps",		"T,V",		0x54004b7b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"nmadd.d",		"D,R,S,T",	0x5400000a, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
{"nmadd.s",		"D,R,S,T",	0x54000002, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_S, 0,		I1,		0,	0 },
{"nmadd.ps",		"D,R,S,T",	0x54000012, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
{"nmsub.d",		"D,R,S,T",	0x5400002a, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
{"nmsub.s",		"D,R,S,T",	0x54000022, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_S, 0,		I1,		0,	0 },
{"nmsub.ps",		"D,R,S,T",	0x54000032, 0xfc00003f,	WR_1|RD_2|RD_3|RD_4|FP_D, 0,		I1,		0,	0 },
/* nop is at the start of the table.  */
{"not",			"mf,mg",	    0x4400,     0xffc0,	WR_1|RD_2,		0,		I1,		0,	0 }, /* put not before nor */
{"not",			"d,v",		0x000002d0, 0xffe007ff,	WR_1|RD_2,		0,		I1,		0,	0 }, /* nor d,s,0 */
{"nor",			"mf,mz,mg",	    0x4400,     0xffc0,	WR_1|RD_3,		0,		I1,		0,	0 }, /* not */
{"nor",			"mf,mg,mz",	    0x4400,     0xffc0,	WR_1|RD_2,		0,		I1,		0,	0 }, /* not */
{"nor",			"d,v,t",	0x000002d0, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"nor",			"t,r,I",	0,    (int) M_NOR_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"or",			"mp,mj,mz",	    0x0c00,     0xfc00,	WR_1|RD_2,		0,		I1,		0,	0 }, /* move */
{"or",			"mp,mz,mj",	    0x0c00,     0xfc00,	WR_1|RD_3,		0,		I1,		0,	0 }, /* move */
{"or",			"mf,mt,mg",	    0x44c0,     0xffc0,	MOD_1|RD_3,		0,		I1,		0,	0 },
{"or",			"mf,mg,mx",	    0x44c0,     0xffc0,	MOD_1|RD_2,		0,		I1,		0,	0 },
{"or",			"d,v,t",	0x00000290, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"or",			"t,r,I",	0,    (int) M_OR_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"ori",			"mp,mj,mZ",	    0x0c00,     0xfc00,	WR_1|RD_2,		0,		I1,		0,	0 }, /* move */
{"ori",			"t,r,i",	0x50000000, 0xfc000000,	WR_1|RD_2,		0,		I1,		0,	0 },
{"pll.ps",		"D,V,T",	0x54000080, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"plu.ps",		"D,V,T",	0x540000c0, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"pul.ps",		"D,V,T",	0x54000100, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"puu.ps",		"D,V,T",	0x54000140, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
/* pref is at the start of the table.  */
{"recip.d",		"T,S",		0x5400523b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"recip.s",		"T,S",		0x5400123b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"rem",			"z,s,t",	0x0000ab3c, 0xfc00ffff,	RD_2|RD_3|WR_HILO,	0,		I1,		0,	0 },
{"rem",			"d,v,t",	0,    (int) M_REM_3,	INSN_MACRO,		0,		I1,		0,	0 },
{"rem",			"d,v,I",	0,    (int) M_REM_3I,	INSN_MACRO,		0,		I1,		0,	0 },
{"remu",		"z,s,t",	0x0000bb3c, 0xfc00ffff,	RD_2|RD_3|WR_HILO,	0,		I1,		0,	0 },
{"remu",		"d,v,t",	0,    (int) M_REMU_3,	INSN_MACRO,		0,		I1,		0,	0 },
{"remu",		"d,v,I",	0,    (int) M_REMU_3I,	INSN_MACRO,		0,		I1,		0,	0 },
{"rdhwr",		"t,K",		0x00006b3c, 0xfc00ffff,	WR_1,			0,		I1,		0,	0 },
{"rdpgpr",		"t,r",		0x0000e17c, 0xfc00ffff,	WR_1,			0,		I1,		0,	0 },
{"rol",			"d,v,t",	0,    (int) M_ROL,	INSN_MACRO,		0,		I1,		0,	0 },
{"rol",			"d,v,I",	0,    (int) M_ROL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"ror",			"d,v,t",	0,    (int) M_ROR,	INSN_MACRO,		0,		I1,		0,	0 },
{"ror",			"d,v,I",	0,    (int) M_ROR_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"ror",			"t,r,<",	0x000000c0, 0xfc0007ff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"rorv",		"d,t,s",	0x000000d0, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"rotl",		"d,v,t",	0,    (int) M_ROL,	INSN_MACRO,		0,		I1,		0,	0 },
{"rotl",		"d,v,I",	0,    (int) M_ROL_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"rotr",		"d,v,t",	0,    (int) M_ROR,	INSN_MACRO,		0,		I1,		0,	0 },
{"rotr",		"t,r,<",	0x000000c0, 0xfc0007ff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"rotrv",		"d,t,s",	0x000000d0, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"round.l.d",		"T,S",		0x5400733b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"round.l.s",		"T,S",		0x5400333b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"round.w.d",		"T,S",		0x54007b3b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"round.w.s",		"T,S",		0x54003b3b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"rsqrt.d",		"T,S",		0x5400423b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"rsqrt.s",		"T,S",		0x5400023b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"sb",			"mq,mL(ml)",        0x8800,     0xfc00,	RD_1|RD_3|SM,		0,		I1,		0,	0 },
{"sb",			"t,o(b)",	0x18000000, 0xfc000000,	RD_1|RD_3|SM,		0,		I1,		0,	0 },
{"sb",			"t,A(b)",	0,    (int) M_SB_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"sc",			"t,~(b)",	0x6000b000, 0xfc00f000,	MOD_1|RD_3|SM,		0,		I1,		0,	0 },
{"sc",			"t,A(b)",	0,    (int) M_SC_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"scd",			"t,~(b)",	0x6000f000, 0xfc00f000,	MOD_1|RD_3|SM,		0,		I3,		0,	0 },
{"scd",			"t,A(b)",	0,    (int) M_SCD_AB,	INSN_MACRO,		0,		I3,		0,	0 },
/* The macro has to be first to handle o32 correctly.  */
{"sd",			"t,A(b)",	0,    (int) M_SD_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"sd",			"t,o(b)",	0xd8000000, 0xfc000000,	RD_1|RD_3|SM,		0,		I3,		0,	0 },
{"sdbbp",		"",		    0x46c0,     0xffff,	TRAP,			0,		I1,		0,	0 },
{"sdbbp",		"",		0x0000db7c, 0xffffffff,	TRAP,			0,		I1,		0,	0 },
{"sdbbp",		"mO",		    0x46c0,     0xfff0,	TRAP,			0,		I1,		0,	0 },
{"sdbbp",		"+J",		0x0000db7c, 0xfc00ffff,	TRAP,			0,		I1,		0,	0 },
{"sdc1",		"T,o(b)",	0xb8000000, 0xfc000000,	RD_1|RD_3|SM|FP_D,	0,		I1,		0,	0 },
{"sdc1",		"E,o(b)",	0xb8000000, 0xfc000000,	RD_1|RD_3|SM|FP_D,	0,		I1,		0,	0 },
{"sdc1",		"T,A(b)",	0,    (int) M_SDC1_AB,	INSN_MACRO,		INSN2_M_FP_D,	I1,		0,	0 },
{"sdc1",		"E,A(b)",	0,    (int) M_SDC1_AB,	INSN_MACRO,		INSN2_M_FP_D,	I1,		0,	0 },
{"sdc2",		"E,~(b)",	0x2000a000, 0xfc00f000,	RD_3|RD_C2|SM,		0,		I1,		0,	0 },
{"sdc2",		"E,A(b)",	0,    (int) M_SDC2_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"s.d",			"T,o(b)",	0xb8000000, 0xfc000000,	RD_1|RD_3|SM|FP_D,	0,		I1,		0,	0 }, /* sdc1 */
{"s.d",			"T,A(b)",	0,    (int) M_SDC1_AB,	INSN_MACRO,		INSN2_M_FP_D,	I1,		0,	0 },
{"sdl",			"t,~(b)",	0x6000c000, 0xfc00f000,	RD_1|RD_3|SM,		0,		I3,		0,	0 },
{"sdl",			"t,A(b)",	0,    (int) M_SDL_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"sdm",			"n,~(b)",	0x2000f000, 0xfc00f000,	RD_3|SM,		0,		I3,		0,	0 },
{"sdm",			"n,A(b)",	0,    (int) M_SDM_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"sdp",			"t,~(b)",	0x2000c000, 0xfc00f000,	RD_1|RD_3|SM,		0,		I3,		0,	0 },
{"sdp",			"t,A(b)",	0,    (int) M_SDP_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"sdr",			"t,~(b)",	0x6000d000, 0xfc00f000,	RD_1|RD_3|SM,		0,		I3,		0,	0 },
{"sdr",			"t,A(b)",	0,    (int) M_SDR_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"sdxc1",		"D,t(b)",	0x54000108, 0xfc0007ff,	RD_1|RD_2|RD_3|SM|FP_D,	0,		I1,		0,	0 },
{"seb",			"t,r",		0x00002b3c, 0xfc00ffff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"seh",			"t,r",		0x00003b3c, 0xfc00ffff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"seq",			"d,v,t",	0,    (int) M_SEQ,	INSN_MACRO,		0,		I1,		0,	0 },
{"seq",			"d,v,I",	0,    (int) M_SEQ_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sge",			"d,v,t",	0,    (int) M_SGE,	INSN_MACRO,		0,		I1,		0,	0 },
{"sge",			"d,v,I",	0,    (int) M_SGE_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sgeu",		"d,v,t",	0,    (int) M_SGEU,	INSN_MACRO,		0,		I1,		0,	0 },
{"sgeu",		"d,v,I",	0,    (int) M_SGEU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sgt",			"d,v,t",	0,    (int) M_SGT,	INSN_MACRO,		0,		I1,		0,	0 },
{"sgt",			"d,v,I",	0,    (int) M_SGT_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sgtu",		"d,v,t",	0,    (int) M_SGTU,	INSN_MACRO,		0,		I1,		0,	0 },
{"sgtu",		"d,v,I",	0,    (int) M_SGTU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sh",			"mq,mH(ml)",	    0xa800,     0xfc00,	RD_1|RD_3|SM,		0,		I1,		0,	0 },
{"sh",			"t,o(b)",	0x38000000, 0xfc000000,	RD_1|RD_3|SM,		0,		I1,		0,	0 },
{"sh",			"t,A(b)",	0,    (int) M_SH_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"sle",			"d,v,t",	0,    (int) M_SLE,	INSN_MACRO,		0,		I1,		0,	0 },
{"sle",			"d,v,I",	0,    (int) M_SLE_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sleu",		"d,v,t",	0,    (int) M_SLEU,	INSN_MACRO,		0,		I1,		0,	0 },
{"sleu",		"d,v,I",	0,    (int) M_SLEU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sllv",		"d,t,s",	0x00000010, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"sll",			"md,mc,mM",	    0x2400,     0xfc01,	WR_1|RD_2,		0,		I1,		0,	0 },
{"sll",			"d,w,s",	0x00000010, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 }, /* sllv */
{"sll",			"t,r,<",	0x00000000, 0xfc0007ff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"slt",			"d,v,t",	0x00000350, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"slt",			"d,v,I",	0,    (int) M_SLT_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"slti",		"t,r,j",	0x90000000, 0xfc000000,	WR_1|RD_2,		0,		I1,		0,	0 },
{"sltiu",		"t,r,j",	0xb0000000, 0xfc000000,	WR_1|RD_2,		0,		I1,		0,	0 },
{"sltu",		"d,v,t",	0x00000390, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"sltu",		"d,v,I",	0,    (int) M_SLTU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sne",			"d,v,t",	0,    (int) M_SNE,	INSN_MACRO,		0,		I1,		0,	0 },
{"sne",			"d,v,I",	0,    (int) M_SNE_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sqrt.d",		"T,S",		0x54004a3b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"sqrt.s",		"T,S",		0x54000a3b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"srav",		"d,t,s",	0x00000090, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"sra",			"d,w,s",	0x00000090, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 }, /* srav */
{"sra",			"t,r,<",	0x00000080, 0xfc0007ff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"srlv",		"d,t,s",	0x00000050, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"srl",			"md,mc,mM",	    0x2401,     0xfc01,	WR_1|RD_2,		0,		I1,		0,	0 },
{"srl",			"d,w,s",	0x00000050, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 }, /* srlv */
{"srl",			"t,r,<",	0x00000040, 0xfc0007ff,	WR_1|RD_2,		0,		I1,		0,	0 },
/* ssnop is at the start of the table.  */
{"sub",			"d,v,t",	0x00000190, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"sub",			"d,v,I",	0,    (int) M_SUB_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"sub.d",		"D,V,T",	0x54000170, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"sub.s",		"D,V,T",	0x54000070, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_S,	0,		I1,		0,	0 },
{"sub.ps",		"D,V,T",	0x54000270, 0xfc0007ff,	WR_1|RD_2|RD_3|FP_D,	0,		I1,		0,	0 },
{"subu",		"md,me,ml",	    0x0401,     0xfc01,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"subu",		"d,v,t",	0x000001d0, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"subu",		"d,v,I",	0,    (int) M_SUBU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"suxc1",		"D,t(b)",	0x54000188, 0xfc0007ff,	RD_1|RD_2|RD_3|SM|FP_D,	0,		I1,		0,	0 },
{"sw",			"mq,mJ(ml)",	    0xe800,     0xfc00,	RD_1|RD_3|SM,		0,		I1,		0,	0 },
{"sw",			"mp,mU(ms)",	    0xc800,     0xfc00,	RD_1|RD_3|SM,		0,		I1,		0,	0 }, /* swsp */
{"sw",			"t,o(b)",	0xf8000000, 0xfc000000,	RD_1|RD_3|SM,		0,		I1,		0,	0 },
{"sw",			"t,A(b)",	0,    (int) M_SW_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"swc1",		"T,o(b)",	0x98000000, 0xfc000000,	RD_1|RD_3|SM|FP_S,	0,		I1,		0,	0 },
{"swc1",		"E,o(b)",	0x98000000, 0xfc000000,	RD_1|RD_3|SM|FP_S,	0,		I1,		0,	0 },
{"swc1",		"T,A(b)",	0,    (int) M_SWC1_AB,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"swc1",		"E,A(b)",	0,    (int) M_SWC1_AB,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"swc2",		"E,~(b)",	0x20008000, 0xfc00f000,	RD_3|RD_C2|SM,		0,		I1,		0,	0 },
{"swc2",		"E,A(b)",	0,    (int) M_SWC2_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"s.s",			"T,o(b)",	0x98000000, 0xfc000000,	RD_1|RD_3|SM|FP_S,	0,		I1,		0,	0 }, /* swc1 */
{"s.s",			"T,A(b)",	0,    (int) M_SWC1_AB,	INSN_MACRO,		INSN2_M_FP_S,	I1,		0,	0 },
{"swl",			"t,~(b)",	0x60008000, 0xfc00f000,	RD_1|RD_3|SM,		0,		I1,		0,	0 },
{"swl",			"t,A(b)",	0,    (int) M_SWL_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"scache",		"t,~(b)",	0x60008000, 0xfc00f000,	RD_1|RD_3|SM,		0,		I1,		0,	0 }, /* same */
{"scache",		"t,A(b)",	0,    (int) M_SWL_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"swm",			"mN,mJ(ms)",    0x4540,     0xffc0,	RD_3|NODS,		0,		I1,		0,	0 },
{"swm",			"n,~(b)",	0x2000d000, 0xfc00f000,	RD_3|SM|NODS,		0,		I1,		0,	0 },
{"swm",			"n,A(b)",	0,    (int) M_SWM_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"swp",			"t,~(b)",	0x20009000, 0xfc00f000,	RD_1|RD_3|SM|NODS,	0,		I1,		0,	0 },
{"swp",			"t,A(b)",	0,    (int) M_SWP_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"swr",			"t,~(b)",	0x60009000, 0xfc00f000,	RD_1|RD_3|SM,		0,		I1,		0,	0 },
{"swr",			"t,A(b)",	0,    (int) M_SWR_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"invalidate",		"t,~(b)",	0x60009000, 0xfc00f000,	RD_1|RD_3|SM,		0,		I1,		0,	0 }, /* same */
{"invalidate",		"t,A(b)",	0,    (int) M_SWR_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"swxc1",		"D,t(b)",	0x54000088, 0xfc0007ff,	RD_1|RD_2|RD_3|SM|FP_S,	0,		I1,		0,	0 },
{"sync_acquire",	"",		0x00116b7c, 0xffffffff,	NODS,			INSN2_ALIAS,	I1,		0,	0 },
{"sync_mb",		"",		0x00106b7c, 0xffffffff,	NODS,			INSN2_ALIAS,	I1,		0,	0 },
{"sync_release",	"",		0x00126b7c, 0xffffffff,	NODS,			INSN2_ALIAS,	I1,		0,	0 },
{"sync_rmb",		"",		0x00136b7c, 0xffffffff,	NODS,			INSN2_ALIAS,	I1,		0,	0 },
{"sync_wmb",		"",		0x00046b7c, 0xffffffff,	NODS,			INSN2_ALIAS,	I1,		0,	0 },
{"sync",		"",		0x00006b7c, 0xffffffff,	NODS,			0,		I1,		0,	0 },
{"sync",		"1",		0x00006b7c, 0xffe0ffff,	NODS,			0,		I1,		0,	0 },
{"synci",		"o(b)",		0x42000000, 0xffe00000,	RD_2|SM,		0,		I1,		0,	0 },
{"syscall",		"",		0x00008b7c, 0xffffffff,	TRAP,			0,		I1,		0,	0 },
{"syscall",		"+J",		0x00008b7c, 0xfc00ffff,	TRAP,			0,		I1,		0,	0 },
{"teqi",		"s,j",		0x41c00000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 },
{"teq",			"s,t",		0x0000003c, 0xfc00ffff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"teq",			"s,t,|",	0x0000003c, 0xfc000fff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"teq",			"s,j",		0x41c00000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 }, /* teqi */
{"teq",			"s,I",		0,    (int) M_TEQ_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"tgei",		"s,j",		0x41200000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 },
{"tge",			"s,t",		0x0000023c, 0xfc00ffff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tge",			"s,t,|",	0x0000023c, 0xfc000fff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tge",			"s,j",		0x41200000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 }, /* tgei */
{"tge",			"s,I",		0,    (int) M_TGE_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"tgeiu",		"s,j",		0x41600000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 },
{"tgeu",		"s,t",		0x0000043c, 0xfc00ffff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tgeu",		"s,t,|",	0x0000043c, 0xfc000fff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tgeu",		"s,j",		0x41600000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 }, /* tgeiu */
{"tgeu",		"s,I",		0,    (int) M_TGEU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"tlbinv",		"",		0x0000437c, 0xffffffff,	INSN_TLB,		0,		0,		TLBINV,	0 },
{"tlbinvf",		"",		0x0000537c, 0xffffffff,	INSN_TLB,		0,		0,		TLBINV,	0 },
{"tlbginv",		"",		0x0000417c, 0xffffffff,	INSN_TLB,		0,		0,		IVIRT,	0 },
{"tlbginvf",		"",		0x0000517c, 0xffffffff,	INSN_TLB,		0,		0,		IVIRT,	0 },
{"tlbgp",		"",		0x0000017c, 0xffffffff,	INSN_TLB,		0,		0,		IVIRT,	0 },
{"tlbgr",		"",		0x0000117c, 0xffffffff,	INSN_TLB,		0,		0,		IVIRT,	0 },
{"tlbgwi",		"",		0x0000217c, 0xffffffff,	INSN_TLB,		0,		0,		IVIRT,	0 },
{"tlbgwr",		"",		0x0000317c, 0xffffffff,	INSN_TLB,		0,		0,		IVIRT,	0 },
{"tlbp",		"",		0x0000037c, 0xffffffff,	INSN_TLB,		0,		I1,		0,	0 },
{"tlbr",		"",		0x0000137c, 0xffffffff,	INSN_TLB,		0,		I1,		0,	0 },
{"tlbwi",		"",		0x0000237c, 0xffffffff,	INSN_TLB,		0,		I1,		0,	0 },
{"tlbwr",		"",		0x0000337c, 0xffffffff,	INSN_TLB,		0,		I1,		0,	0 },
{"tlti",		"s,j",		0x41000000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 },
{"tlt",			"s,t",		0x0000083c, 0xfc00ffff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tlt",			"s,t,|",	0x0000083c, 0xfc000fff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tlt",			"s,j",		0x41000000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 }, /* tlti */
{"tlt",			"s,I",		0,    (int) M_TLT_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"tltiu",		"s,j",		0x41400000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 },
{"tltu",		"s,t",		0x00000a3c, 0xfc00ffff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tltu",		"s,t,|",	0x00000a3c, 0xfc000fff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tltu",		"s,j",		0x41400000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 }, /* tltiu */
{"tltu",		"s,I",		0,    (int) M_TLTU_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"tnei",		"s,j",		0x41800000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 },
{"tne",			"s,t",		0x00000c3c, 0xfc00ffff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tne",			"s,t,|",	0x00000c3c, 0xfc000fff,	RD_1|RD_2|TRAP,		0,		I1,		0,	0 },
{"tne",			"s,j",		0x41800000, 0xffe00000,	RD_1|TRAP,		0,		I1,		0,	0 }, /* tnei */
{"tne",			"s,I",		0,    (int) M_TNE_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"trunc.l.d",		"T,S",		0x5400633b, 0xfc00ffff,	WR_1|RD_2|FP_D,		0,		I1,		0,	0 },
{"trunc.l.s",		"T,S",		0x5400233b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"trunc.w.d",		"T,S",		0x54006b3b, 0xfc00ffff,	WR_1|RD_2|FP_S|FP_D,	0,		I1,		0,	0 },
{"trunc.w.s",		"T,S",		0x54002b3b, 0xfc00ffff,	WR_1|RD_2|FP_S,		0,		I1,		0,	0 },
{"uld",			"t,A(b)",	0,    (int) M_ULD_AB,	INSN_MACRO,		0,		I3,		0,	0 },
{"ulh",			"t,A(b)",	0,    (int) M_ULH_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"ulhu",		"t,A(b)",	0,    (int) M_ULHU_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"ulw",			"t,A(b)",	0,    (int) M_ULW_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"usd",			"t,A(b)",	0,    (int) M_USD_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"ush",			"t,A(b)",	0,    (int) M_USH_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"usw",			"t,A(b)",	0,    (int) M_USW_AB,	INSN_MACRO,		0,		I1,		0,	0 },
{"wait",		"",		0x0000937c, 0xffffffff,	NODS,			0,		I1,		0,	0 },
{"wait",		"+J",		0x0000937c, 0xfc00ffff,	NODS,			0,		I1,		0,	0 },
{"wrpgpr",		"t,r",		0x0000f17c, 0xfc00ffff,	RD_2,			0,		I1,		0,	0 },
{"wsbh",		"t,r",		0x00007b3c, 0xfc00ffff,	WR_1|RD_2,		0,		I1,		0,	0 },
{"xor",			"mf,mt,mg",	    0x4440,     0xffc0,	MOD_1|RD_3,		0,		I1,		0,	0 },
{"xor",			"mf,mg,mx",	    0x4440,     0xffc0,	MOD_1|RD_2,		0,		I1,		0,	0 },
{"xor",			"d,v,t",	0x00000310, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		I1,		0,	0 },
{"xor",			"t,r,I",	0,    (int) M_XOR_I,	INSN_MACRO,		0,		I1,		0,	0 },
{"xori",		"t,r,i",	0x70000000, 0xfc000000,	WR_1|RD_2,		0,		I1,		0,	0 },
/* microMIPS Enhanced VA Scheme */
{"lbue",		"t,+j(b)",	0x60006000, 0xfc00fe00, WR_1|RD_3|LM,		0,		0,		EVA,	0 },
{"lbue",		"t,A(b)",	0,    (int) M_LBUE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"lhue",		"t,+j(b)",	0x60006200, 0xfc00fe00, WR_1|RD_3|LM,		0,		0,		EVA,	0 },
{"lhue",		"t,A(b)",	0,    (int) M_LHUE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"lbe",			"t,+j(b)",	0x60006800, 0xfc00fe00, WR_1|RD_3|LM,		0,		0,		EVA,	0 },
{"lbe",			"t,A(b)",	0,    (int) M_LBE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"lhe",			"t,+j(b)",	0x60006a00, 0xfc00fe00, WR_1|RD_3|LM,		0,		0,		EVA,	0 },
{"lhe",			"t,A(b)",	0,    (int) M_LHE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"lle",			"t,+j(b)",	0x60006c00, 0xfc00fe00, WR_1|RD_3|LM,		0,		0,		EVA,	0 },
{"lle",			"t,A(b)",	0,    (int) M_LLE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"lwe",			"t,+j(b)",	0x60006e00, 0xfc00fe00, WR_1|RD_3|LM,		0,		0,		EVA,	0 },
{"lwe",			"t,A(b)",	0,    (int) M_LWE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"lwle",		"t,+j(b)",	0x60006400, 0xfc00fe00, WR_1|RD_3|LM,		0,		0,		EVA,	0 },
{"lwle",		"t,A(b)",	0,    (int) M_LWLE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"lwre",		"t,+j(b)",	0x60006600, 0xfc00fe00, WR_1|RD_3|LM,		0,		0,		EVA,	0 },
{"lwre",		"t,A(b)",	0,    (int) M_LWRE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"sbe",			"t,+j(b)",	0x6000a800, 0xfc00fe00, WR_1|RD_3|SM,		0,		0,		EVA,	0 },
{"sbe",			"t,A(b)",	0,    (int) M_SBE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"sce",			"t,+j(b)",	0x6000ac00, 0xfc00fe00, MOD_1|RD_3|SM,		0,		0,		EVA,	0 },
{"sce",			"t,A(b)",	0,    (int) M_SCE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"she",			"t,+j(b)",	0x6000aa00, 0xfc00fe00, WR_1|RD_3|SM,		0,		0,		EVA,	0 },
{"she",			"t,A(b)",	0,    (int) M_SHE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"swe",			"t,+j(b)",	0x6000ae00, 0xfc00fe00, WR_1|RD_3|SM,		0,		0,		EVA,	0 },
{"swe",			"t,A(b)",	0,    (int) M_SWE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"swle",		"t,+j(b)",	0x6000a000, 0xfc00fe00, WR_1|RD_3|SM,		0,		0,		EVA,	0 },
{"swle",		"t,A(b)",	0,    (int) M_SWLE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"swre",		"t,+j(b)",	0x6000a200, 0xfc00fe00, WR_1|RD_3|SM,		0,		0,		EVA,	0 },
{"swre",		"t,A(b)",	0,    (int) M_SWRE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
{"cachee",		"k,+j(b)",	0x6000a600, 0xfc00fe00, RD_3,			0,		0,		EVA,	0 },
{"cachee",		"k,A(b)",	0,    (int) M_CACHEE_AB,INSN_MACRO,		0,		0,		EVA,	0 },
{"prefe",		"k,+j(b)",	0x6000a400, 0xfc00fe00, RD_3|LM,		0,		0,		EVA,	0 },
{"prefe",		"k,A(b)",	0,    (int) M_PREFE_AB,	INSN_MACRO,		0,		0,		EVA,	0 },
/* MIPS DSP ASE.  */
{"absq_s.ph",		"t,s",		0x0000113c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"absq_s.w",		"t,s",		0x0000213c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"addq.ph",		"d,s,t",	0x0000000d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"addq_s.ph",		"d,s,t",	0x0000040d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"addq_s.w",		"d,s,t",	0x00000305, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"addsc",		"d,s,t",	0x00000385, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"addu.qb",		"d,s,t",	0x000000cd, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"addu_s.qb",		"d,s,t",	0x000004cd, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"addwc",		"d,s,t",	0x000003c5, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"bitrev",		"t,s",		0x0000313c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"bposge32",		"p",		0x43600000, 0xffff0000,	CBD,			0,		0,		D32,	0 },
{"cmp.eq.ph",		"s,t",		0x00000005, 0xfc00ffff,	RD_1|RD_2,		0,		0,		D32,	0 },
{"cmpgu.eq.qb",		"d,s,t",	0x000000c5, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"cmp.le.ph",		"s,t",		0x00000085, 0xfc00ffff,	RD_1|RD_2,		0,		0,		D32,	0 },
{"cmpgu.le.qb",		"d,s,t",	0x00000145, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"cmp.lt.ph",		"s,t",		0x00000045, 0xfc00ffff,	RD_1|RD_2,		0,		0,		D32,	0 },
{"cmpgu.lt.qb",		"d,s,t",	0x00000105, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"cmpu.eq.qb",		"s,t",		0x00000245, 0xfc00ffff,	RD_1|RD_2,		0,		0,		D32,	0 },
{"cmpu.le.qb",		"s,t",		0x000002c5, 0xfc00ffff,	RD_1|RD_2,		0,		0,		D32,	0 },
{"cmpu.lt.qb",		"s,t",		0x00000285, 0xfc00ffff,	RD_1|RD_2,		0,		0,		D32,	0 },
{"dpaq_sa.l.w",		"7,s,t",	0x000012bc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"dpaq_s.w.ph",		"7,s,t",	0x000002bc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"dpau.h.qbl",		"7,s,t",	0x000020bc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"dpau.h.qbr",		"7,s,t",	0x000030bc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"dpsq_sa.l.w",		"7,s,t",	0x000016bc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"dpsq_s.w.ph",		"7,s,t",	0x000006bc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"dpsu.h.qbl",		"7,s,t",	0x000024bc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"dpsu.h.qbr",		"7,s,t",	0x000034bc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"extpdp",		"t,7,6",	0x0000367c, 0xfc003fff,	WR_1|RD_a|DSP_VOLA,	0,		0,		D32,	0 },
{"extpdpv",		"t,7,s",	0x000038bc, 0xfc003fff,	WR_1|RD_3|RD_a|DSP_VOLA, 0,		0,		D32,	0 },
{"extp",		"t,7,6",	0x0000267c, 0xfc003fff,	WR_1|RD_a,		0,		0,		D32,	0 },
{"extpv",		"t,7,s",	0x000028bc, 0xfc003fff,	WR_1|RD_3|RD_a,		0,		0,		D32,	0 },
{"extr_rs.w",		"t,7,6",	0x00002e7c, 0xfc003fff,	WR_1|RD_a,		0,		0,		D32,	0 },
{"extr_r.w",		"t,7,6",	0x00001e7c, 0xfc003fff,	WR_1|RD_a,		0,		0,		D32,	0 },
{"extr_s.h",		"t,7,6",	0x00003e7c, 0xfc003fff,	WR_1|RD_a,		0,		0,		D32,	0 },
{"extrv_rs.w",		"t,7,s",	0x00002ebc, 0xfc003fff,	WR_1|RD_3|RD_a,		0,		0,		D32,	0 },
{"extrv_r.w",		"t,7,s",	0x00001ebc, 0xfc003fff,	WR_1|RD_3|RD_a,		0,		0,		D32,	0 },
{"extrv_s.h",		"t,7,s",	0x00003ebc, 0xfc003fff,	WR_1|RD_3|RD_a,		0,		0,		D32,	0 },
{"extrv.w",		"t,7,s",	0x00000ebc, 0xfc003fff,	WR_1|RD_3|RD_a,		0,		0,		D32,	0 },
{"extr.w",		"t,7,6",	0x00000e7c, 0xfc003fff,	WR_1|RD_a,		0,		0,		D32,	0 },
{"insv",		"t,s",		0x0000413c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"lbux",		"d,t(b)",	0x00000225, 0xfc0007ff,	WR_1|RD_2|RD_3|LM,	0,		0,		D32,	0 },
{"lhx",			"d,t(b)",	0x00000165, 0xfc0007ff,	WR_1|RD_2|RD_3|LM,	0,		0,		D32,	0 },
{"lwx",			"d,t(b)",	0x000001a5, 0xfc0007ff,	WR_1|RD_2|RD_3|LM,	0,		0,		D32,	0 },
{"maq_sa.w.phl",	"7,s,t",	0x00003a7c, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"maq_sa.w.phr",	"7,s,t",	0x00002a7c, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"maq_s.w.phl",		"7,s,t",	0x00001a7c, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"maq_s.w.phr",		"7,s,t",	0x00000a7c, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"modsub",		"d,s,t",	0x00000295, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"mthlip",		"s,7",		0x0000027c, 0xffe03fff,	RD_1|MOD_a|DSP_VOLA,	0,		0,		D32,	0 },
{"muleq_s.w.phl",	"d,s,t",	0x00000025, 0xfc0007ff, WR_1|RD_2|RD_3|WR_HILO, 0,		0,		D32,	0 },
{"muleq_s.w.phr",	"d,s,t",	0x00000065, 0xfc0007ff, WR_1|RD_2|RD_3|WR_HILO, 0,		0,		D32,	0 },
{"muleu_s.ph.qbl",	"d,s,t",	0x00000095, 0xfc0007ff, WR_1|RD_2|RD_3|WR_HILO, 0,		0,		D32,	0 },
{"muleu_s.ph.qbr",	"d,s,t",	0x000000d5, 0xfc0007ff, WR_1|RD_2|RD_3|WR_HILO, 0,		0,		D32,	0 },
{"mulq_rs.ph",		"d,s,t",	0x00000115, 0xfc0007ff,	WR_1|RD_2|RD_3|WR_HILO,	0,		0,		D32,	0 },
{"mulsaq_s.w.ph",	"7,s,t",	0x00003cbc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D32,	0 },
{"packrl.ph",		"d,s,t",	0x000001ad, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"pick.ph",		"d,s,t",	0x0000022d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"pick.qb",		"d,s,t",	0x000001ed, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"precequ.ph.qbla",	"t,s",		0x0000733c, 0xfc00ffff, WR_1|RD_2,		0,		0,		D32,	0 },
{"precequ.ph.qbl",	"t,s",		0x0000713c, 0xfc00ffff, WR_1|RD_2,		0,		0,		D32,	0 },
{"precequ.ph.qbra",	"t,s",		0x0000933c, 0xfc00ffff, WR_1|RD_2,		0,		0,		D32,	0 },
{"precequ.ph.qbr",	"t,s",		0x0000913c, 0xfc00ffff, WR_1|RD_2,		0,		0,		D32,	0 },
{"preceq.w.phl",	"t,s",		0x0000513c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"preceq.w.phr",	"t,s",		0x0000613c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"preceu.ph.qbla",	"t,s",		0x0000b33c, 0xfc00ffff, WR_1|RD_2,		0,		0,		D32,	0 },
{"preceu.ph.qbl",	"t,s",		0x0000b13c, 0xfc00ffff, WR_1|RD_2,		0,		0,		D32,	0 },
{"preceu.ph.qbra",	"t,s",		0x0000d33c, 0xfc00ffff, WR_1|RD_2,		0,		0,		D32,	0 },
{"preceu.ph.qbr",	"t,s",		0x0000d13c, 0xfc00ffff, WR_1|RD_2,		0,		0,		D32,	0 },
{"precrq.ph.w",		"d,s,t",	0x000000ed, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"precrq.qb.ph",	"d,s,t",	0x000000ad, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"precrq_rs.ph.w",	"d,s,t",	0x0000012d, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"precrqu_s.qb.ph",	"d,s,t",	0x0000016d, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"raddu.w.qb",		"t,s",		0x0000f13c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"rddsp",		"t",		0x000fc67c, 0xfc1fffff,	WR_1,			0,		0,		D32,	0 },
{"rddsp",		"t,8",		0x0000067c, 0xfc103fff,	WR_1,			0,		0,		D32,	0 },
{"repl.ph",		"d,@",		0x0000003d, 0xfc0007ff,	WR_1,			0,		0,		D32,	0 },
{"repl.qb",		"t,5",		0x000005fc, 0xfc001fff,	WR_1,			0,		0,		D32,	0 },
{"replv.ph",		"t,s",		0x0000033c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"replv.qb",		"t,s",		0x0000133c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shilo",		"7,0",		0x0000001d, 0xffc03fff,	MOD_a,			0,		0,		D32,	0 },
{"shilov",		"7,s",		0x0000127c, 0xffe03fff,	RD_2|MOD_a,		0,		0,		D32,	0 },
{"shll.ph",		"t,s,4",	0x000003b5, 0xfc000fff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shll.qb",		"t,s,3",	0x0000087c, 0xfc001fff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shll_s.ph",		"t,s,4",	0x00000bb5, 0xfc000fff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shll_s.w",		"t,s,^",	0x000003f5, 0xfc0007ff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shllv.ph",		"d,t,s",	0x0000038d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"shllv.qb",		"d,t,s",	0x00000395, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"shllv_s.ph",		"d,t,s",	0x0000078d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"shllv_s.w",		"d,t,s",	0x000003d5, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"shra.ph",		"t,s,4",	0x00000335, 0xfc000fff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shra_r.ph",		"t,s,4",	0x00000735, 0xfc000fff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shra_r.w",		"t,s,^",	0x000002f5, 0xfc0007ff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shrav.ph",		"d,t,s",	0x0000018d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"shrav_r.ph",		"d,t,s",	0x0000058d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"shrav_r.w",		"d,t,s",	0x000002d5, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"shrl.qb",		"t,s,3",	0x0000187c, 0xfc001fff,	WR_1|RD_2,		0,		0,		D32,	0 },
{"shrlv.qb",		"d,t,s",	0x00000355, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"subq.ph",		"d,s,t",	0x0000020d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"subq_s.ph",		"d,s,t",	0x0000060d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"subq_s.w",		"d,s,t",	0x00000345, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"subu.qb",		"d,s,t",	0x000002cd, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"subu_s.qb",		"d,s,t",	0x000006cd, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D32,	0 },
{"wrdsp",		"t",		0x000fd67c, 0xfc1fffff,	RD_1|DSP_VOLA,		0,		0,		D32,	0 },
{"wrdsp",		"t,8",		0x0000167c, 0xfc103fff,	RD_1|DSP_VOLA,		0,		0,		D32,	0 },
/* MIPS DSP ASE Rev2.  */
{"absq_s.qb",		"t,s",		0x0000013c, 0xfc00ffff,	WR_1|RD_2,		0,		0,		D33,	0 },
{"addqh.ph",		"d,s,t",	0x0000004d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"addqh_r.ph",		"d,s,t",	0x0000044d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"addqh.w",		"d,s,t",	0x0000008d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"addqh_r.w",		"d,s,t",	0x0000048d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"addu.ph",		"d,s,t",	0x0000010d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"addu_s.ph",		"d,s,t",	0x0000050d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"adduh.qb",		"d,s,t",	0x0000014d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"adduh_r.qb",		"d,s,t",	0x0000054d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"append",		"t,s,h",	0x00000215, 0xfc0007ff,	MOD_1|RD_2,		0,		0,		D33,	0 },
{"balign",		"t,s,I",	0,    (int) M_BALIGN,	INSN_MACRO,		0,		0,		D33,	0 },
{"balign",		"t,s,2",	0x000008bc, 0xfc003fff,	MOD_1|RD_2,		0,		0,		D33,	0 },
{"cmpgdu.eq.qb",	"d,s,t", 	0x00000185, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"cmpgdu.lt.qb",	"d,s,t", 	0x000001c5, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"cmpgdu.le.qb",	"d,s,t", 	0x00000205, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"dpa.w.ph",		"7,s,t",	0x000000bc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"dpaqx_s.w.ph",	"7,s,t", 	0x000022bc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"dpaqx_sa.w.ph",	"7,s,t", 	0x000032bc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"dpax.w.ph",		"7,s,t",	0x000010bc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"dps.w.ph",		"7,s,t",	0x000004bc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"dpsqx_s.w.ph",	"7,s,t", 	0x000026bc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"dpsqx_sa.w.ph",	"7,s,t", 	0x000036bc, 0xfc003fff, RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"dpsx.w.ph",		"7,s,t",	0x000014bc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"mul.ph",		"d,s,t",	0x0000002d, 0xfc0007ff,	WR_1|RD_2|RD_3|WR_HILO,	0,		0,		D33,	0 },
{"mul_s.ph",		"d,s,t",	0x0000042d, 0xfc0007ff,	WR_1|RD_2|RD_3|WR_HILO,	0,		0,		D33,	0 },
{"mulq_rs.w",		"d,s,t",	0x00000195, 0xfc0007ff,	WR_1|RD_2|RD_3|WR_HILO,	0,		0,		D33,	0 },
{"mulq_s.ph",		"d,s,t",	0x00000155, 0xfc0007ff,	WR_1|RD_2|RD_3|WR_HILO,	0,		0,		D33,	0 },
{"mulq_s.w",		"d,s,t",	0x000001d5, 0xfc0007ff,	WR_1|RD_2|RD_3|WR_HILO,	0,		0,		D33,	0 },
{"mulsa.w.ph",		"7,s,t",	0x00002cbc, 0xfc003fff,	RD_2|RD_3|MOD_a,	0,		0,		D33,	0 },
{"precr.qb.ph",		"d,s,t", 	0x0000006d, 0xfc0007ff, WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"precr_sra.ph.w",	"t,s,h", 	0x000003cd, 0xfc0007ff, MOD_1|RD_2,		0,		0,		D33,	0 },
{"precr_sra_r.ph.w",	"t,s,h", 	0x000007cd, 0xfc0007ff, MOD_1|RD_2,		0,		0,		D33,	0 },
{"prepend",		"t,s,h",	0x00000255, 0xfc0007ff,	MOD_1|RD_2,		0,		0,		D33,	0 },
{"shra.qb",		"t,s,3",	0x000001fc, 0xfc001fff,	WR_1|RD_2,		0,		0,		D33,	0 },
{"shra_r.qb",		"t,s,3",	0x000011fc, 0xfc001fff,	WR_1|RD_2,		0,		0,		D33,	0 },
{"shrav.qb",		"d,t,s",	0x000001cd, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"shrav_r.qb",		"d,t,s",	0x000005cd, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"shrl.ph",		"t,s,4",	0x000003fc, 0xfc000fff,	WR_1|RD_2,		0,		0,		D33,	0 },
{"shrlv.ph",		"d,t,s",	0x00000315, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"subu.ph",		"d,s,t",	0x0000030d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"subu_s.ph",		"d,s,t",	0x0000070d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"subuh.qb",		"d,s,t",	0x0000034d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"subuh_r.qb",		"d,s,t",	0x0000074d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"subqh.ph",		"d,s,t",	0x0000024d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"subqh_r.ph",		"d,s,t",	0x0000064d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"subqh.w",		"d,s,t",	0x0000028d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
{"subqh_r.w",		"d,s,t",	0x0000068d, 0xfc0007ff,	WR_1|RD_2|RD_3,		0,		0,		D33,	0 },
/* MSA Extension.  */
{"sll.b",		"+d,+e,+h",	0x5800001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"sll.h",		"+d,+e,+h",	0x5820001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"sll.w",		"+d,+e,+h",	0x5840001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"sll.d",		"+d,+e,+h",	0x5860001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"slli.b",		"+d,+e,+!",	0x58700012, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"slli.h",		"+d,+e,+@",	0x58600012, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"slli.w",		"+d,+e,+x",	0x58400012, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"slli.d",		"+d,+e,+#",	0x58000012, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"sra.b",		"+d,+e,+h",	0x5880001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"sra.h",		"+d,+e,+h",	0x58a0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"sra.w",		"+d,+e,+h",	0x58c0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"sra.d",		"+d,+e,+h",	0x58e0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srai.b",		"+d,+e,+!",	0x58f00012, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srai.h",		"+d,+e,+@",	0x58e00012, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srai.w",		"+d,+e,+x",	0x58c00012, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srai.d",		"+d,+e,+#",	0x58800012, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srl.b",		"+d,+e,+h",	0x5900001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srl.h",		"+d,+e,+h",	0x5920001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srl.w",		"+d,+e,+h",	0x5940001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srl.d",		"+d,+e,+h",	0x5960001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srli.b",		"+d,+e,+!",	0x59700012, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srli.h",		"+d,+e,+@",	0x59600012, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srli.w",		"+d,+e,+x",	0x59400012, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srli.d",		"+d,+e,+#",	0x59000012, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bclr.b",		"+d,+e,+h",	0x5980001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bclr.h",		"+d,+e,+h",	0x59a0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bclr.w",		"+d,+e,+h",	0x59c0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bclr.d",		"+d,+e,+h",	0x59e0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bclri.b",		"+d,+e,+!",	0x59f00012, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bclri.h",		"+d,+e,+@",	0x59e00012, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bclri.w",		"+d,+e,+x",	0x59c00012, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bclri.d",		"+d,+e,+#",	0x59800012, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bset.b",		"+d,+e,+h",	0x5a00001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bset.h",		"+d,+e,+h",	0x5a20001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bset.w",		"+d,+e,+h",	0x5a40001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bset.d",		"+d,+e,+h",	0x5a60001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bseti.b",		"+d,+e,+!",	0x5a700012, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bseti.h",		"+d,+e,+@",	0x5a600012, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bseti.w",		"+d,+e,+x",	0x5a400012, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bseti.d",		"+d,+e,+#",	0x5a000012, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bneg.b",		"+d,+e,+h",	0x5a80001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bneg.h",		"+d,+e,+h",	0x5aa0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bneg.w",		"+d,+e,+h",	0x5ac0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bneg.d",		"+d,+e,+h",	0x5ae0001a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"bnegi.b",		"+d,+e,+!",	0x5af00012, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bnegi.h",		"+d,+e,+@",	0x5ae00012, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bnegi.w",		"+d,+e,+x",	0x5ac00012, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bnegi.d",		"+d,+e,+#",	0x5a800012, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"binsl.b",		"+d,+e,+h",	0x5b00001a, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"binsl.h",		"+d,+e,+h",	0x5b20001a, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"binsl.w",		"+d,+e,+h",	0x5b40001a, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"binsl.d",		"+d,+e,+h",	0x5b60001a, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"binsli.b",		"+d,+e,+!",	0x5b700012, 0xfff8003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"binsli.h",		"+d,+e,+@",	0x5b600012, 0xfff0003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"binsli.w",		"+d,+e,+x",	0x5b400012, 0xffe0003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"binsli.d",		"+d,+e,+#",	0x5b000012, 0xffc0003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"binsr.b",		"+d,+e,+h",	0x5b80001a, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"binsr.h",		"+d,+e,+h",	0x5ba0001a, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"binsr.w",		"+d,+e,+h",	0x5bc0001a, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"binsr.d",		"+d,+e,+h",	0x5be0001a, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"binsri.b",		"+d,+e,+!",	0x5bf00012, 0xfff8003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"binsri.h",		"+d,+e,+@",	0x5be00012, 0xfff0003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"binsri.w",		"+d,+e,+x",	0x5bc00012, 0xffe0003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"binsri.d",		"+d,+e,+#",	0x5b800012, 0xffc0003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"addv.b",		"+d,+e,+h",	0x5800002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"addv.h",		"+d,+e,+h",	0x5820002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"addv.w",		"+d,+e,+h",	0x5840002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"addv.d",		"+d,+e,+h",	0x5860002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"addvi.b",		"+d,+e,+$",	0x58000029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"addvi.h",		"+d,+e,+$",	0x58200029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"addvi.w",		"+d,+e,+$",	0x58400029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"addvi.d",		"+d,+e,+$",	0x58600029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"subv.b",		"+d,+e,+h",	0x5880002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subv.h",		"+d,+e,+h",	0x58a0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subv.w",		"+d,+e,+h",	0x58c0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subv.d",		"+d,+e,+h",	0x58e0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subvi.b",		"+d,+e,+$",	0x58800029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"subvi.h",		"+d,+e,+$",	0x58a00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"subvi.w",		"+d,+e,+$",	0x58c00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"subvi.d",		"+d,+e,+$",	0x58e00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"max_s.b",		"+d,+e,+h",	0x5900002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_s.h",		"+d,+e,+h",	0x5920002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_s.w",		"+d,+e,+h",	0x5940002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_s.d",		"+d,+e,+h",	0x5960002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"maxi_s.b",		"+d,+e,+%",	0x59000029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"maxi_s.h",		"+d,+e,+%",	0x59200029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"maxi_s.w",		"+d,+e,+%",	0x59400029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"maxi_s.d",		"+d,+e,+%",	0x59600029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"max_u.b",		"+d,+e,+h",	0x5980002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_u.h",		"+d,+e,+h",	0x59a0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_u.w",		"+d,+e,+h",	0x59c0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_u.d",		"+d,+e,+h",	0x59e0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"maxi_u.b",		"+d,+e,+$",	0x59800029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"maxi_u.h",		"+d,+e,+$",	0x59a00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"maxi_u.w",		"+d,+e,+$",	0x59c00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"maxi_u.d",		"+d,+e,+$",	0x59e00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"min_s.b",		"+d,+e,+h",	0x5a00002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_s.h",		"+d,+e,+h",	0x5a20002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_s.w",		"+d,+e,+h",	0x5a40002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_s.d",		"+d,+e,+h",	0x5a60002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mini_s.b",		"+d,+e,+%",	0x5a000029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"mini_s.h",		"+d,+e,+%",	0x5a200029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"mini_s.w",		"+d,+e,+%",	0x5a400029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"mini_s.d",		"+d,+e,+%",	0x5a600029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"min_u.b",		"+d,+e,+h",	0x5a80002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_u.h",		"+d,+e,+h",	0x5aa0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_u.w",		"+d,+e,+h",	0x5ac0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_u.d",		"+d,+e,+h",	0x5ae0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mini_u.b",		"+d,+e,+$",	0x5a800029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"mini_u.h",		"+d,+e,+$",	0x5aa00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"mini_u.w",		"+d,+e,+$",	0x5ac00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"mini_u.d",		"+d,+e,+$",	0x5ae00029, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"max_a.b",		"+d,+e,+h",	0x5b00002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_a.h",		"+d,+e,+h",	0x5b20002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_a.w",		"+d,+e,+h",	0x5b40002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"max_a.d",		"+d,+e,+h",	0x5b60002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_a.b",		"+d,+e,+h",	0x5b80002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_a.h",		"+d,+e,+h",	0x5ba0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_a.w",		"+d,+e,+h",	0x5bc0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"min_a.d",		"+d,+e,+h",	0x5be0002a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ceq.b",		"+d,+e,+h",	0x5800003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ceq.h",		"+d,+e,+h",	0x5820003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ceq.w",		"+d,+e,+h",	0x5840003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ceq.d",		"+d,+e,+h",	0x5860003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ceqi.b",		"+d,+e,+%",	0x58000039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ceqi.h",		"+d,+e,+%",	0x58200039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ceqi.w",		"+d,+e,+%",	0x58400039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ceqi.d",		"+d,+e,+%",	0x58600039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clt_s.b",		"+d,+e,+h",	0x5900003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clt_s.h",		"+d,+e,+h",	0x5920003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clt_s.w",		"+d,+e,+h",	0x5940003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clt_s.d",		"+d,+e,+h",	0x5960003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clti_s.b",		"+d,+e,+%",	0x59000039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clti_s.h",		"+d,+e,+%",	0x59200039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clti_s.w",		"+d,+e,+%",	0x59400039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clti_s.d",		"+d,+e,+%",	0x59600039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clt_u.b",		"+d,+e,+h",	0x5980003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clt_u.h",		"+d,+e,+h",	0x59a0003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clt_u.w",		"+d,+e,+h",	0x59c0003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clt_u.d",		"+d,+e,+h",	0x59e0003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clti_u.b",		"+d,+e,+$",	0x59800039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clti_u.h",		"+d,+e,+$",	0x59a00039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clti_u.w",		"+d,+e,+$",	0x59c00039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clti_u.d",		"+d,+e,+$",	0x59e00039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"cle_s.b",		"+d,+e,+h",	0x5a00003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"cle_s.h",		"+d,+e,+h",	0x5a20003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"cle_s.w",		"+d,+e,+h",	0x5a40003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"cle_s.d",		"+d,+e,+h",	0x5a60003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clei_s.b",		"+d,+e,+%",	0x5a000039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clei_s.h",		"+d,+e,+%",	0x5a200039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clei_s.w",		"+d,+e,+%",	0x5a400039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clei_s.d",		"+d,+e,+%",	0x5a600039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"cle_u.b",		"+d,+e,+h",	0x5a80003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"cle_u.h",		"+d,+e,+h",	0x5aa0003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"cle_u.w",		"+d,+e,+h",	0x5ac0003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"cle_u.d",		"+d,+e,+h",	0x5ae0003a, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"clei_u.b",		"+d,+e,+$",	0x5a800039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clei_u.h",		"+d,+e,+$",	0x5aa00039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clei_u.w",		"+d,+e,+$",	0x5ac00039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"clei_u.d",		"+d,+e,+$",	0x5ae00039, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ld.b",		"+d,+T(d)",	0x58000007, 0xfc00003f,	WR_1|RD_3|LM,		0,		0,		MSA,	0 },
{"ld.h",		"+d,+U(d)",	0x58000017, 0xfc00003f,	WR_1|RD_3|LM,		0,		0,		MSA,	0 },
{"ld.w",		"+d,+V(d)",	0x58000027, 0xfc00003f,	WR_1|RD_3|LM,		0,		0,		MSA,	0 },
{"ld.d",		"+d,+W(d)",	0x58000037, 0xfc00003f,	WR_1|RD_3|LM,		0,		0,		MSA,	0 },
{"st.b",		"+d,+T(d)",	0x5800000f, 0xfc00003f,	RD_1|RD_3|SM,		0,		0,		MSA,	0 },
{"st.h",		"+d,+U(d)",	0x5800001f, 0xfc00003f,	RD_1|RD_3|SM,		0,		0,		MSA,	0 },
{"st.w",		"+d,+V(d)",	0x5800002f, 0xfc00003f,	RD_1|RD_3|SM,		0,		0,		MSA,	0 },
{"st.d",		"+d,+W(d)",	0x5800003f, 0xfc00003f,	RD_1|RD_3|SM,		0,		0,		MSA,	0 },
{"sat_s.b",		"+d,+e,+!",	0x58700022, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"sat_s.h",		"+d,+e,+@",	0x58600022, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"sat_s.w",		"+d,+e,+x",	0x58400022, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"sat_s.d",		"+d,+e,+#",	0x58000022, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"sat_u.b",		"+d,+e,+!",	0x58f00022, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"sat_u.h",		"+d,+e,+@",	0x58e00022, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"sat_u.w",		"+d,+e,+x",	0x58c00022, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"sat_u.d",		"+d,+e,+#",	0x58800022, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"add_a.b",		"+d,+e,+h",	0x58000003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"add_a.h",		"+d,+e,+h",	0x58200003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"add_a.w",		"+d,+e,+h",	0x58400003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"add_a.d",		"+d,+e,+h",	0x58600003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_a.b",		"+d,+e,+h",	0x58800003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_a.h",		"+d,+e,+h",	0x58a00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_a.w",		"+d,+e,+h",	0x58c00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_a.d",		"+d,+e,+h",	0x58e00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_s.b",		"+d,+e,+h",	0x59000003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_s.h",		"+d,+e,+h",	0x59200003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_s.w",		"+d,+e,+h",	0x59400003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_s.d",		"+d,+e,+h",	0x59600003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_u.b",		"+d,+e,+h",	0x59800003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_u.h",		"+d,+e,+h",	0x59a00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_u.w",		"+d,+e,+h",	0x59c00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"adds_u.d",		"+d,+e,+h",	0x59e00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ave_s.b",		"+d,+e,+h",	0x5a000003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ave_s.h",		"+d,+e,+h",	0x5a200003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ave_s.w",		"+d,+e,+h",	0x5a400003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ave_s.d",		"+d,+e,+h",	0x5a600003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ave_u.b",		"+d,+e,+h",	0x5a800003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ave_u.h",		"+d,+e,+h",	0x5aa00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ave_u.w",		"+d,+e,+h",	0x5ac00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ave_u.d",		"+d,+e,+h",	0x5ae00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"aver_s.b",		"+d,+e,+h",	0x5b000003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"aver_s.h",		"+d,+e,+h",	0x5b200003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"aver_s.w",		"+d,+e,+h",	0x5b400003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"aver_s.d",		"+d,+e,+h",	0x5b600003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"aver_u.b",		"+d,+e,+h",	0x5b800003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"aver_u.h",		"+d,+e,+h",	0x5ba00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"aver_u.w",		"+d,+e,+h",	0x5bc00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"aver_u.d",		"+d,+e,+h",	0x5be00003, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subs_s.b",		"+d,+e,+h",	0x58000013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subs_s.h",		"+d,+e,+h",	0x58200013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subs_s.w",		"+d,+e,+h",	0x58400013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subs_s.d",		"+d,+e,+h",	0x58600013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subs_u.b",		"+d,+e,+h",	0x58800013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subs_u.h",		"+d,+e,+h",	0x58a00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subs_u.w",		"+d,+e,+h",	0x58c00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subs_u.d",		"+d,+e,+h",	0x58e00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subsus_u.b",		"+d,+e,+h",	0x59000013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subsus_u.h",		"+d,+e,+h",	0x59200013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subsus_u.w",		"+d,+e,+h",	0x59400013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subsus_u.d",		"+d,+e,+h",	0x59600013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subsuu_s.b",		"+d,+e,+h",	0x59800013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subsuu_s.h",		"+d,+e,+h",	0x59a00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subsuu_s.w",		"+d,+e,+h",	0x59c00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"subsuu_s.d",		"+d,+e,+h",	0x59e00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"asub_s.b",		"+d,+e,+h",	0x5a000013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"asub_s.h",		"+d,+e,+h",	0x5a200013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"asub_s.w",		"+d,+e,+h",	0x5a400013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"asub_s.d",		"+d,+e,+h",	0x5a600013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"asub_u.b",		"+d,+e,+h",	0x5a800013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"asub_u.h",		"+d,+e,+h",	0x5aa00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"asub_u.w",		"+d,+e,+h",	0x5ac00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"asub_u.d",		"+d,+e,+h",	0x5ae00013, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mulv.b",		"+d,+e,+h",	0x58000023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mulv.h",		"+d,+e,+h",	0x58200023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mulv.w",		"+d,+e,+h",	0x58400023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mulv.d",		"+d,+e,+h",	0x58600023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"maddv.b",		"+d,+e,+h",	0x58800023, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"maddv.h",		"+d,+e,+h",	0x58a00023, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"maddv.w",		"+d,+e,+h",	0x58c00023, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"maddv.d",		"+d,+e,+h",	0x58e00023, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"msubv.b",		"+d,+e,+h",	0x59000023, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"msubv.h",		"+d,+e,+h",	0x59200023, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"msubv.w",		"+d,+e,+h",	0x59400023, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"msubv.d",		"+d,+e,+h",	0x59600023, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"div_s.b",		"+d,+e,+h",	0x5a000023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"div_s.h",		"+d,+e,+h",	0x5a200023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"div_s.w",		"+d,+e,+h",	0x5a400023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"div_s.d",		"+d,+e,+h",	0x5a600023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"div_u.b",		"+d,+e,+h",	0x5a800023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"div_u.h",		"+d,+e,+h",	0x5aa00023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"div_u.w",		"+d,+e,+h",	0x5ac00023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"div_u.d",		"+d,+e,+h",	0x5ae00023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mod_s.b",		"+d,+e,+h",	0x5b000023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mod_s.h",		"+d,+e,+h",	0x5b200023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mod_s.w",		"+d,+e,+h",	0x5b400023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mod_s.d",		"+d,+e,+h",	0x5b600023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mod_u.b",		"+d,+e,+h",	0x5b800023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mod_u.h",		"+d,+e,+h",	0x5ba00023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mod_u.w",		"+d,+e,+h",	0x5bc00023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mod_u.d",		"+d,+e,+h",	0x5be00023, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"dotp_s.h",		"+d,+e,+h",	0x58200033, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"dotp_s.w",		"+d,+e,+h",	0x58400033, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"dotp_s.d",		"+d,+e,+h",	0x58600033, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"dotp_u.h",		"+d,+e,+h",	0x58a00033, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"dotp_u.w",		"+d,+e,+h",	0x58c00033, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"dotp_u.d",		"+d,+e,+h",	0x58e00033, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"dpadd_s.h",		"+d,+e,+h",	0x59200033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpadd_s.w",		"+d,+e,+h",	0x59400033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpadd_s.d",		"+d,+e,+h",	0x59600033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpadd_u.h",		"+d,+e,+h",	0x59a00033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpadd_u.w",		"+d,+e,+h",	0x59c00033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpadd_u.d",		"+d,+e,+h",	0x59e00033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpsub_s.h",		"+d,+e,+h",	0x5a200033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpsub_s.w",		"+d,+e,+h",	0x5a400033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpsub_s.d",		"+d,+e,+h",	0x5a600033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpsub_u.h",		"+d,+e,+h",	0x5aa00033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpsub_u.w",		"+d,+e,+h",	0x5ac00033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"dpsub_u.d",		"+d,+e,+h",	0x5ae00033, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"sld.b",		"+d,+e+*",	0x5800000b, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"sld.h",		"+d,+e+*",	0x5820000b, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"sld.w",		"+d,+e+*",	0x5840000b, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"sld.d",		"+d,+e+*",	0x5860000b, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"sldi.b",		"+d,+e+o",	0x58000016, 0xfff0003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"sldi.h",		"+d,+e+u",	0x58200016, 0xfff8003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"sldi.w",		"+d,+e+v",	0x58300016, 0xfffc003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"sldi.d",		"+d,+e+w",	0x58380016, 0xfffe003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"splat.b",		"+d,+e+*",	0x5880000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"splat.h",		"+d,+e+*",	0x58a0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"splat.w",		"+d,+e+*",	0x58c0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"splat.d",		"+d,+e+*",	0x58e0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"splati.b",		"+d,+e+o",	0x58400016, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"splati.h",		"+d,+e+u",	0x58600016, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"splati.w",		"+d,+e+v",	0x58700016, 0xfffc003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"splati.d",		"+d,+e+w",	0x58780016, 0xfffe003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"pckev.b",		"+d,+e,+h",	0x5900000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"pckev.h",		"+d,+e,+h",	0x5920000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"pckev.w",		"+d,+e,+h",	0x5940000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"pckev.d",		"+d,+e,+h",	0x5960000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"pckod.b",		"+d,+e,+h",	0x5980000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"pckod.h",		"+d,+e,+h",	0x59a0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"pckod.w",		"+d,+e,+h",	0x59c0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"pckod.d",		"+d,+e,+h",	0x59e0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvl.b",		"+d,+e,+h",	0x5a00000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvl.h",		"+d,+e,+h",	0x5a20000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvl.w",		"+d,+e,+h",	0x5a40000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvl.d",		"+d,+e,+h",	0x5a60000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvr.b",		"+d,+e,+h",	0x5a80000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvr.h",		"+d,+e,+h",	0x5aa0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvr.w",		"+d,+e,+h",	0x5ac0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvr.d",		"+d,+e,+h",	0x5ae0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvev.b",		"+d,+e,+h",	0x5b00000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvev.h",		"+d,+e,+h",	0x5b20000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvev.w",		"+d,+e,+h",	0x5b40000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvev.d",		"+d,+e,+h",	0x5b60000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvod.b",		"+d,+e,+h",	0x5b80000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvod.h",		"+d,+e,+h",	0x5ba0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvod.w",		"+d,+e,+h",	0x5bc0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ilvod.d",		"+d,+e,+h",	0x5be0000b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"vshf.b",		"+d,+e,+h",	0x5800001b, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"vshf.h",		"+d,+e,+h",	0x5820001b, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"vshf.w",		"+d,+e,+h",	0x5840001b, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"vshf.d",		"+d,+e,+h",	0x5860001b, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"srar.b",		"+d,+e,+h",	0x5880001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srar.h",		"+d,+e,+h",	0x58a0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srar.w",		"+d,+e,+h",	0x58c0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srar.d",		"+d,+e,+h",	0x58e0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srari.b",		"+d,+e,+!",	0x59700022, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srari.h",		"+d,+e,+@",	0x59600022, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srari.w",		"+d,+e,+x",	0x59400022, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srari.d",		"+d,+e,+#",	0x59000022, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srlr.b",		"+d,+e,+h",	0x5900001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srlr.h",		"+d,+e,+h",	0x5920001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srlr.w",		"+d,+e,+h",	0x5940001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srlr.d",		"+d,+e,+h",	0x5960001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"srlri.b",		"+d,+e,+!",	0x59f00022, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srlri.h",		"+d,+e,+@",	0x59e00022, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srlri.w",		"+d,+e,+x",	0x59c00022, 0xffe0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"srlri.d",		"+d,+e,+#",	0x59800022, 0xffc0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"hadd_s.h",		"+d,+e,+h",	0x5a20001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hadd_s.w",		"+d,+e,+h",	0x5a40001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hadd_s.d",		"+d,+e,+h",	0x5a60001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hadd_u.h",		"+d,+e,+h",	0x5aa0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hadd_u.w",		"+d,+e,+h",	0x5ac0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hadd_u.d",		"+d,+e,+h",	0x5ae0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hsub_s.h",		"+d,+e,+h",	0x5b20001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hsub_s.w",		"+d,+e,+h",	0x5b40001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hsub_s.d",		"+d,+e,+h",	0x5b60001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hsub_u.h",		"+d,+e,+h",	0x5ba0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hsub_u.w",		"+d,+e,+h",	0x5bc0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"hsub_u.d",		"+d,+e,+h",	0x5be0001b, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"and.v",		"+d,+e,+h",	0x5800002e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"andi.b",		"+d,+e,+|",	0x58000001, 0xff00003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"or.v",		"+d,+e,+h",	0x5820002e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ori.b",		"+d,+e,+|",	0x59000001, 0xff00003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nor.v",		"+d,+e,+h",	0x5840002e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"nori.b",		"+d,+e,+|",	0x5a000001, 0xff00003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"xor.v",		"+d,+e,+h",	0x5860002e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"xori.b",		"+d,+e,+|",	0x5b000001, 0xff00003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bmnz.v",		"+d,+e,+h",	0x5880002e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"bmnzi.b",		"+d,+e,+|",	0x58000011, 0xff00003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"bmz.v",		"+d,+e,+h",	0x58a0002e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"bmzi.b",		"+d,+e,+|",	0x59000011, 0xff00003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"bsel.v",		"+d,+e,+h",	0x58c0002e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"bseli.b",		"+d,+e,+|",	0x5a000011, 0xff00003f,	MOD_1|RD_2,		0,		0,		MSA,	0 },
{"shf.b",		"+d,+e,+|",	0x58000021, 0xff00003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"shf.h",		"+d,+e,+|",	0x59000021, 0xff00003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"shf.w",		"+d,+e,+|",	0x5a000021, 0xff00003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"bnz.v",		"+h,p",		0x81e00000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"bz.v",		"+h,p",		0x81600000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"fill.b",		"+d,d",		0x5b00002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fill.h",		"+d,d",		0x5b01002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fill.w",		"+d,d",		0x5b02002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fill.d",		"+d,d",		0x5b03002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA64,	0 },
{"pcnt.b",		"+d,+e",	0x5b04002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"pcnt.h",		"+d,+e",	0x5b05002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"pcnt.w",		"+d,+e",	0x5b06002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"pcnt.d",		"+d,+e",	0x5b07002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nloc.b",		"+d,+e",	0x5b08002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nloc.h",		"+d,+e",	0x5b09002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nloc.w",		"+d,+e",	0x5b0a002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nloc.d",		"+d,+e",	0x5b0b002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nlzc.b",		"+d,+e",	0x5b0c002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nlzc.h",		"+d,+e",	0x5b0d002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nlzc.w",		"+d,+e",	0x5b0e002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"nlzc.d",		"+d,+e",	0x5b0f002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"copy_s.b",		"+k,+e+o",	0x58800016, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"copy_s.h",		"+k,+e+u",	0x58a00016, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"copy_s.w",		"+k,+e+v",	0x58b00016, 0xfffc003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"copy_s.d",		"+k,+e+w",	0x58b80016, 0xfffe003f,	WR_1|RD_2,		0,		0,		MSA64,	0 },
{"copy_u.b",		"+k,+e+o",	0x58c00016, 0xfff0003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"copy_u.h",		"+k,+e+u",	0x58e00016, 0xfff8003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"copy_u.w",		"+k,+e+v",	0x58f00016, 0xfffc003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"copy_u.d",		"+k,+e+w",	0x58f80016, 0xfffe003f,	WR_1|RD_2,		0,		0,		MSA64,	0 },
{"insert.b",		"+d+o,d",	0x59000016, 0xfff0003f,	MOD_1|RD_3,		0,		0,		MSA,	0 },
{"insert.h",		"+d+u,d",	0x59200016, 0xfff8003f,	MOD_1|RD_3,		0,		0,		MSA,	0 },
{"insert.w",		"+d+v,d",	0x59300016, 0xfffc003f,	MOD_1|RD_3,		0,		0,		MSA,	0 },
{"insert.d",		"+d+w,d",	0x59380016, 0xfffe003f,	MOD_1|RD_3,		0,		0,		MSA64,	0 },
{"insve.b",		"+d+o,+e+&",	0x59400016, 0xfff0003f,	MOD_1|RD_3,		0,		0,		MSA,	0 },
{"insve.h",		"+d+u,+e+&",	0x59600016, 0xfff8003f,	MOD_1|RD_3,		0,		0,		MSA,	0 },
{"insve.w",		"+d+v,+e+&",	0x59700016, 0xfffc003f,	MOD_1|RD_3,		0,		0,		MSA,	0 },
{"insve.d",		"+d+w,+e+&",	0x59780016, 0xfffe003f,	MOD_1|RD_3,		0,		0,		MSA,	0 },
{"bnz.b",		"+h,p",		0x83800000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"bnz.h",		"+h,p",		0x83a00000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"bnz.w",		"+h,p",		0x83c00000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"bnz.d",		"+h,p",		0x83e00000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"bz.b",		"+h,p",		0x83000000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"bz.h",		"+h,p",		0x83200000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"bz.w",		"+h,p",		0x83400000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"bz.d",		"+h,p",		0x83600000, 0xffe00000,	RD_1|CBD,		0,		0,		MSA,	0 },
{"ldi.b",		"+d,+^",	0x5b000039, 0xffe0003f,	WR_1,			0,		0,		MSA,	0 },
{"ldi.h",		"+d,+^",	0x5b200039, 0xffe0003f,	WR_1,			0,		0,		MSA,	0 },
{"ldi.w",		"+d,+^",	0x5b400039, 0xffe0003f,	WR_1,			0,		0,		MSA,	0 },
{"ldi.d",		"+d,+^",	0x5b600039, 0xffe0003f,	WR_1,			0,		0,		MSA,	0 },
{"fcaf.w",		"+d,+e,+h",	0x58000026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcaf.d",		"+d,+e,+h",	0x58200026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcun.w",		"+d,+e,+h",	0x58400026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcun.d",		"+d,+e,+h",	0x58600026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fceq.w",		"+d,+e,+h",	0x58800026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fceq.d",		"+d,+e,+h",	0x58a00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcueq.w",		"+d,+e,+h",	0x58c00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcueq.d",		"+d,+e,+h",	0x58e00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fclt.w",		"+d,+e,+h",	0x59000026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fclt.d",		"+d,+e,+h",	0x59200026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcult.w",		"+d,+e,+h",	0x59400026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcult.d",		"+d,+e,+h",	0x59600026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcle.w",		"+d,+e,+h",	0x59800026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcle.d",		"+d,+e,+h",	0x59a00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcule.w",		"+d,+e,+h",	0x59c00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcule.d",		"+d,+e,+h",	0x59e00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsaf.w",		"+d,+e,+h",	0x5a000026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsaf.d",		"+d,+e,+h",	0x5a200026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsun.w",		"+d,+e,+h",	0x5a400026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsun.d",		"+d,+e,+h",	0x5a600026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fseq.w",		"+d,+e,+h",	0x5a800026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fseq.d",		"+d,+e,+h",	0x5aa00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsueq.w",		"+d,+e,+h",	0x5ac00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsueq.d",		"+d,+e,+h",	0x5ae00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fslt.w",		"+d,+e,+h",	0x5b000026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fslt.d",		"+d,+e,+h",	0x5b200026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsult.w",		"+d,+e,+h",	0x5b400026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsult.d",		"+d,+e,+h",	0x5b600026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsle.w",		"+d,+e,+h",	0x5b800026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsle.d",		"+d,+e,+h",	0x5ba00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsule.w",		"+d,+e,+h",	0x5bc00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsule.d",		"+d,+e,+h",	0x5be00026, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fadd.w",		"+d,+e,+h",	0x58000036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fadd.d",		"+d,+e,+h",	0x58200036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsub.w",		"+d,+e,+h",	0x58400036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsub.d",		"+d,+e,+h",	0x58600036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmul.w",		"+d,+e,+h",	0x58800036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmul.d",		"+d,+e,+h",	0x58a00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fdiv.w",		"+d,+e,+h",	0x58c00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fdiv.d",		"+d,+e,+h",	0x58e00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmadd.w",		"+d,+e,+h",	0x59000036, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"fmadd.d",		"+d,+e,+h",	0x59200036, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"fmsub.w",		"+d,+e,+h",	0x59400036, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"fmsub.d",		"+d,+e,+h",	0x59600036, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"fexp2.w",		"+d,+e,+h",	0x59c00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fexp2.d",		"+d,+e,+h",	0x59e00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fexdo.h",		"+d,+e,+h",	0x5a000036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fexdo.w",		"+d,+e,+h",	0x5a200036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ftq.h",		"+d,+e,+h",	0x5a800036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"ftq.w",		"+d,+e,+h",	0x5aa00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmin.w",		"+d,+e,+h",	0x5b000036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmin.d",		"+d,+e,+h",	0x5b200036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmin_a.w",		"+d,+e,+h",	0x5b400036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmin_a.d",		"+d,+e,+h",	0x5b600036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmax.w",		"+d,+e,+h",	0x5b800036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmax.d",		"+d,+e,+h",	0x5ba00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmax_a.w",		"+d,+e,+h",	0x5bc00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fmax_a.d",		"+d,+e,+h",	0x5be00036, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcor.w",		"+d,+e,+h",	0x5840000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcor.d",		"+d,+e,+h",	0x5860000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcune.w",		"+d,+e,+h",	0x5880000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcune.d",		"+d,+e,+h",	0x58a0000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcne.w",		"+d,+e,+h",	0x58c0000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fcne.d",		"+d,+e,+h",	0x58e0000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mul_q.h",		"+d,+e,+h",	0x5900000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mul_q.w",		"+d,+e,+h",	0x5920000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"madd_q.h",		"+d,+e,+h",	0x5940000e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"madd_q.w",		"+d,+e,+h",	0x5960000e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"msub_q.h",		"+d,+e,+h",	0x5980000e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"msub_q.w",		"+d,+e,+h",	0x59a0000e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"fsor.w",		"+d,+e,+h",	0x5a40000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsor.d",		"+d,+e,+h",	0x5a60000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsune.w",		"+d,+e,+h",	0x5a80000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsune.d",		"+d,+e,+h",	0x5aa0000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsne.w",		"+d,+e,+h",	0x5ac0000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"fsne.d",		"+d,+e,+h",	0x5ae0000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mulr_q.h",		"+d,+e,+h",	0x5b00000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"mulr_q.w",		"+d,+e,+h",	0x5b20000e, 0xffe0003f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"maddr_q.h",		"+d,+e,+h",	0x5b40000e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"maddr_q.w",		"+d,+e,+h",	0x5b60000e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"msubr_q.h",		"+d,+e,+h",	0x5b80000e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"msubr_q.w",		"+d,+e,+h",	0x5ba0000e, 0xffe0003f,	MOD_1|RD_2|RD_3,	0,		0,		MSA,	0 },
{"fclass.w",		"+d,+e",	0x5b20002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fclass.d",		"+d,+e",	0x5b21002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ftrunc_s.w",		"+d,+e",	0x5b22002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ftrunc_s.d",		"+d,+e",	0x5b23002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ftrunc_u.w",		"+d,+e",	0x5b24002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ftrunc_u.d",		"+d,+e",	0x5b25002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fsqrt.w",		"+d,+e",	0x5b26002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fsqrt.d",		"+d,+e",	0x5b27002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"frsqrt.w",		"+d,+e",	0x5b28002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"frsqrt.d",		"+d,+e",	0x5b29002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"frcp.w",		"+d,+e",	0x5b2a002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"frcp.d",		"+d,+e",	0x5b2b002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"frint.w",		"+d,+e",	0x5b2c002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"frint.d",		"+d,+e",	0x5b2d002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"flog2.w",		"+d,+e",	0x5b2e002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"flog2.d",		"+d,+e",	0x5b2f002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fexupl.w",		"+d,+e",	0x5b30002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fexupl.d",		"+d,+e",	0x5b31002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fexupr.w",		"+d,+e",	0x5b32002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"fexupr.d",		"+d,+e",	0x5b33002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ffql.w",		"+d,+e",	0x5b34002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ffql.d",		"+d,+e",	0x5b35002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ffqr.w",		"+d,+e",	0x5b36002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ffqr.d",		"+d,+e",	0x5b37002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ftint_s.w",		"+d,+e",	0x5b38002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ftint_s.d",		"+d,+e",	0x5b39002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ftint_u.w",		"+d,+e",	0x5b3a002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ftint_u.d",		"+d,+e",	0x5b3b002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ffint_s.w",		"+d,+e",	0x5b3c002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ffint_s.d",		"+d,+e",	0x5b3d002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ffint_u.w",		"+d,+e",	0x5b3e002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ffint_u.d",		"+d,+e",	0x5b3f002e, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"ctcmsa",		"+l,d",		0x583e0016, 0xffff003f,	RD_2,			0,		0,		MSA,	0 },
{"cfcmsa",		"+k,+n",	0x587e0016, 0xffff003f,	WR_1,			0,		0,		MSA,	0 },
{"move.v",		"+d,+e",	0x58be0016, 0xffff003f,	WR_1|RD_2,		0,		0,		MSA,	0 },
{"lsa",			"d,v,t,+~",	0x00000020, 0xfc00073f,	WR_1|RD_2|RD_3,		0,		0,		MSA,	0 },
{"dlsa",		"d,v,t,+~",	0x58000020, 0xfc00073f,	WR_1|RD_2|RD_3,		0,		0,		MSA64,	0 },
};

const int bfd_micromips_num_opcodes =
  ((sizeof micromips_opcodes) / (sizeof (micromips_opcodes[0])));
