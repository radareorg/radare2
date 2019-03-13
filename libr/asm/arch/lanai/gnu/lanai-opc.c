/*************************************************************************
 *                                                                       *
 * Table of opcodes for the Lanai.                                      *
 *                                                                       *
 * Copyright (c) 1994, 1995 by Myricom, Inc.                             *
 * All rights reserved.                                                  *
 *                                                                       *
 * This program is free software; you can redistribute it and/or modify  *
 * it under the terms of version 2 of the GNU General Public License     *
 * as published by the Free Software Foundation.  Myricom requests that  *
 * all modifications of this software be returned to Myricom, Inc. for   *
 * redistribution.  The name of Myricom, Inc. may not be used to endorse *
 * or promote products derived from this software without specific prior *
 * written permission.                                                   *
 *                                                                       *
 * Myricom, Inc. makes no representations about the suitability of this  *
 * software for any purpose.                                             *
 *                                                                       *
 * THIS FILE IS PROVIDED "AS-IS" WITHOUT WARRANTY OF ANY KIND, WHETHER   *
 * EXPRESSED OR IMPLIED, INCLUDING THE WARRANTY OF MERCHANTABILITY OR    *
 * FITNESS FOR A PARTICULAR PURPOSE.  MYRICOM, INC. SHALL HAVE NO        *
 * LIABILITY WITH RESPECT TO THE INFRINGEMENT OF COPYRIGHTS, TRADE       *
 * SECRETS OR ANY PATENTS BY THIS FILE OR ANY PART THEREOF.              *
 *                                                                       *
 * In no event will Myricom, Inc. be liable for any lost revenue         *
 * or profits or other special, indirect and consequential damages, even *
 * if Myricom has been advised of the possibility of such damages.       *
 *                                                                       *
 * Other copyrights might apply to parts of this software and are so     *
 * noted when applicable.                                                *
 *                                                                       *
 * Myricom, Inc.                    Email: info@myri.com                 *
 * 325 N. Santa Anita Ave.          World Wide Web: http://www.myri.com/ *
 * Arcadia, CA 91024                                                     *
 *************************************************************************/
 /* initial version released 5/95 */
 /* This file is based upon <> from the Gnu binutils-2.5.2 
    release, which had the following copyright notice: */

	/* Table of opcodes for the sparc.
		Copyright 1989, 1991, 1992 Free Software Foundation, Inc.

	This file is part of the BFD library.

	BFD is free software; you can redistribute it and/or modify it under
	the terms of the GNU General Public License as published by the Free
	Software Foundation; either version 2, or (at your option) any later
	version.

	BFD is distributed in the hope that it will be useful, but WITHOUT ANY
	WARRANTY; without even the implied warranty of MERCHANTABILITY or
	FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
	for more details.

	You should have received a copy of the GNU General Public License
	along with this software; see the file COPYING.  If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, 
		USA.	*/

/* FIXME-someday: perhaps the ,a's and such should be embedded in the
   instruction's name rather than the args.  This would make gas faster, pinsn
   slower, but would mess up some macros a bit.  xoxorich. */

/* v9 FIXME: Doesn't accept `iprefetch', `setX', `signx', `cleartop', `cas',
   `casx', `clrx', `clruw' synthetic instructions for v9.  */

#include <stdio.h>
#include "ansidecl.h"
#include "opcode/lanai.h"

const char *architecture_pname[] = {
	"v0",
	"v1",
	NULL,
};

/* A pair is the set of all bits that must be high or low as determined
   solely by the opcode.  This macro takes a mask and the set of
   all bits that must be high and generates the pair.  I do this 
   so the macro definitions below are simpler. */

#define GENERIC_PAIR(mask,high) \
	(high),((mask)&~(high))

/* Specifies the bits that must be set and the bits that must be cleared
	for an RI instruction. */
#define RI_PAIR(op,f,h) GENERIC_PAIR(L3_RI_MASK,			\
	L3_RI | L3_RI_OP(op) | ((f)?L3_RI_F:0) | ((h)?L3_RI_H:0) )

#define RR_PAIR(f,op) GENERIC_PAIR(L3_RR_MASK,				\
	L3_RR | ((f)?L3_RR_F:0) | L3_RR_OP(op)				\
	| ((((op)&L3_OP_MASK)==L3_SH) ? ((op)&L3_ARITH?0xc0:0x80) : 0 ))

#define LEADZ_PAIR(f) GENERIC_PAIR(L3_LEADZ_MASK,			\
	L3_LEADZ | ((f)?L3_LEADZ_F:0))

#define POPC_PAIR(f) GENERIC_PAIR(L3_POPC_MASK,				\
	L3_POPC | ((f)?L3_POPC_F:0))

#define RRR_PAIR() GENERIC_PAIR(L3_RRR_MASK,				\
	L3_RRR )

#define RM_PAIR(s,p,q) GENERIC_PAIR(L3_RM_MASK,				\
	L3_RM | ((s)?L3_RM_S:0) | ((p)?L3_RM_P:0) | ((q)?L3_RM_Q:0) )

#define RRM_PAIR(s,p,q,mode) GENERIC_PAIR(L3_RRM_MASK,			\
	L3_RRM | ((s)?L3_RRM_S:0) | ((p)?L3_RRM_P:0)			\
	| ((q)?L3_RRM_Q:0) | L3_RRM_MODE(mode) )

#define BR_PAIR(cond,r) GENERIC_PAIR(L3_BR_MASK,			\
	L3_BR | L3_BR_COND(cond) | ((r)?L3_BR_R:0) )

#define SCC_PAIR(cond) GENERIC_PAIR (L3_SCC_MASK, L3_SCC | L3_BR_COND (cond))

#define SLS_PAIR(s) GENERIC_PAIR(L3_SLS_MASK,				\
	L3_SLS | ((s)?L3_SLS_S:0) )

#define SLI_PAIR() GENERIC_PAIR(L3_SLI_MASK,				\
	L3_SLI )

#define SPLS_PAIR(s,mode,p,q) GENERIC_PAIR(L3_SPLS_MASK,		\
	L3_SPLS | L3_SPLS_MODE(mode) | ((s)?L3_SPLS_S:0)		\
	| ((p)?L3_SPLS_P:0) | ((q)?L3_SPLS_Q:0) )

#define PUNT_PAIR() GENERIC_PAIR(L3_PUNT_MASK,				\
	L3_PUNT )

#define SBR_PAIR(cond,op,r) GENERIC_PAIR(L3_SBR_MASK,			\
	L3_SBR|L3_SBR_COND(cond)|L3_SBR_OP(op)|((r)?L3_SBR_R:0))

#define PCREL_SBR_PAIR(cond) GENERIC_PAIR(L3_SBR_MASK|L3_RS1(0x1f)| \
	L3_SBR_OP(7),							 \
	L3_SBR|L3_SBR_COND(cond)|L3_SBR_OP(L3_ADD)|L3_RS1(2)|L3_SBR_R)

/* Specifies the bits that must be set and the bits that must be cleared
	for an RI "mov" instruction. Note that Rs1 is 1 for AND type moves */
#define RI_MOV_PAIR(op,f,h) GENERIC_PAIR(L3_RI_MASK|L3_RS1(31),		\
L3_RI|L3_RI_OP(op)|((f)?L3_RI_F:0)|((h)?L3_RI_H:0)|(((op)==L3_AND)?L3_RS1(1):0))

/* Similarly for RR "mov" insns */
#define RR_MOV_PAIR(f,op) GENERIC_PAIR(L3_RR_MASK|0x007c0000,		\
	L3_RR | ((f)?L3_RR_F:0) | L3_RR_OP(op)				\
	| (((op)&L3_ARITH)?1<<6:0) | ((op)==L3_SH?1<<7:0) )

/* The order of the opcodes in the table is significant:
	
	* The assembler requires that all instances of the same mnemonic must
	be consecutive.	If they aren't, the assembler will bomb at runtime.

	* The disassembler should not care about the order of the opcodes.

	* instructions with constants must come at the end of the
	  list of instructions with the same mnemonic to avoid using
	  get_expression unless it is guaranteed to work because it
	  aborts if it fails.
*/

struct lanai_opcode lanai_opcodes[] = {

  /* nop (at beginning so disassembler will use these if possible) */

  { "nop", 0x00000001,0xfffffffe			,"",  F_RI, 0},
  { "nop(RI)", 0x00000000,0x8f820000			,"",  F_RI, 0},
  { "nop(RR)", 0xc0000000,0x3f820000			,"",  F_RR, 0},
  { "nop(RRR)", 0xd0000000,0x2f820000			,"",  F_RRR, 0},
  { "nop(BR)", 0xe2000000,0x1c000000			,"",  F_BR, 0},
  { "nop(SLI)", 0xf0020000,0x0f810000			,"",  F_SLI, 0},
  { "nop(SPLS)", 0xf0030000,0x0f808000			,"",  F_SPLS, 0},
  { "nop(SBR)", 0xf203c000,0x0c003800			,"",  F_SBR, 0},

  /* mov (at beginning so disassembler will use these if possible) */

  { "mov", RR_MOV_PAIR(0,L3_ADD)			,"1,d",  F_RR, 0},
  { "mov", BR_PAIR(L3_T,0)				,"B,P",  F_ALIAS,0},
  { "mov", SLI_PAIR()					,"I,d",  F_SLI, 0},
  { "mov", RI_MOV_PAIR(L3_ADD,0,0)			,"j,d",  F_RI, 0},
  { "mov", RI_MOV_PAIR(L3_ADD,0,1)			,"J,d",  F_RI, 0},
  { "mov", RI_MOV_PAIR(L3_AND,0,0)			,"l,d",  F_RI, 0},
  { "mov", RI_MOV_PAIR(L3_AND,0,1)			,"L,d",  F_RI, 0},
/*{ "mov", RI_MOV_PAIR(L3_SUB,0,0)			,"k,d",  F_RI, 0}, */
  /* These moves used only for disassembler */
  { "mov", RI_MOV_PAIR(L3_OR,0,0)			,"j,d",  F_RI, 0},
  { "mov", RI_MOV_PAIR(L3_OR,0,1)			,"J,d",  F_RI, 0},
  { "mov", RI_MOV_PAIR(L3_OR,0,0)			,"l,d",  F_RI, 0},
  { "mov", RI_MOV_PAIR(L3_OR,0,1)			,"L,d",  F_RI, 0},

  /* add */

  { "add",	RR_PAIR(0,L3_ADD)		,"1,2,d", F_RR,0},
  { "add", 	BR_PAIR(L3_T,1)			,"p,b,P", F_UNBR|F_ALIAS,0},
  { "add",	RI_PAIR(L3_ADD,0,0)		,"1,j,d", F_RI,0},
  { "add",	RI_PAIR(L3_ADD,0,1)		,"1,J,d", F_RI,0},
/*{ "add",	RI_PAIR(L3_SUB,0,0)		,"18k,d", F_RI|F_ALIAS,0}, */
  { "add.f",	RR_PAIR(1,L3_ADD)		,"1,2,d", F_RR,0},
  { "add.f",	RI_PAIR(L3_ADD,1,0)		,"1,j,d", F_RI,0},
  { "add.f",	RI_PAIR(L3_ADD,1,1)		,"1,J,d", F_RI,0},
/*{ "add.f",	RI_PAIR(L3_SUB,1,1)		,"1,k,d", F_RI|F_ALIAS,0}, */
  { "addc",	RR_PAIR(0,L3_ADDC)		,"1,2,d", F_RR,0},
  { "addc",	RI_PAIR(L3_ADDC,0,0)		,"1,j,d", F_RI,0},
  { "addc",	RI_PAIR(L3_ADDC,0,1)		,"1,J,d", F_RI,0},
/*{ "addc",	RI_PAIR(L3_SUBB,0,0)		,"1,k,d", F_RI|F_ALIAS,0}, */
  { "addc.f",	RR_PAIR(1,L3_ADDC)		,"1,2,d", F_RR,0},
  { "addc.f",	RI_PAIR(L3_ADDC,1,0)		,"1,j,d", F_RI,0},
  { "addc.f",	RI_PAIR(L3_ADDC,1,1)		,"1,J,d", F_RI,0},
/*{ "addc.f",	RI_PAIR(L3_SUBB,0,1)		,"1,k,d", F_RI|F_ALIAS,0}, */

  /* and */

  { "and",	RR_PAIR(0,L3_AND)		,"1,2,d", F_RR,0},
  { "and",	RI_PAIR(L3_AND,0,0)		,"1,l,d", F_RI,0},
  { "and",	RI_PAIR(L3_AND,0,1)		,"1,L,d", F_RI,0},
  { "and.f",	RR_PAIR(1,L3_AND)		,"1,2,d", F_RR,0},
  { "and.f",	RI_PAIR(L3_AND,1,0)		,"1,l,d", F_RI,0},
  { "and.f",	RI_PAIR(L3_AND,1,1)		,"1,L,d", F_RI,0},

  /* b?? */

  { "bt",	BR_PAIR(L3_T,0)			,"B",     F_UNBR,0},
  { "bt",	SBR_PAIR(L3_T,0,0)		,"1",     F_UNBR,0},
  { "bt",	SBR_PAIR(L3_T,0,0)		,"143",   F_UNBR,0},
  { "bt.r",	BR_PAIR(L3_T,1)			,"b",     F_RELUNBR,0},
  { "bt.r",	PCREL_SBR_PAIR(L3_T)    	,"3",     F_RELUNBR,0},

  { "bf",	BR_PAIR(L3_F,0)			,"B",     F_BR,0},
  { "bf",	SBR_PAIR(L3_F,0,0)		,"1",     F_BR,0},
  { "bf",	SBR_PAIR(L3_F,0,0)		,"143",   F_BR,0},
  { "bf.r",	BR_PAIR(L3_F,1)			,"b",     F_BR|F_REL,0},
  { "bf.r",	PCREL_SBR_PAIR(L3_F)    	,"3",     F_BR|F_REL,0},

  { "bhi",	BR_PAIR(L3_HI,0)		,"B",     F_CONDBR,0},
  { "bhi",	SBR_PAIR(L3_HI,0,0)		,"1",     F_CONDBR,0},
  { "bhi",	SBR_PAIR(L3_HI,0,0)		,"143",   F_CONDBR,0},
  { "bhi.r",	BR_PAIR(L3_HI,1)		,"b",     F_RELCONDBR,0},
  { "bhi.r",	PCREL_SBR_PAIR(L3_HI)		,"3",     F_RELCONDBR,0},

  { "bugt",	BR_PAIR(L3_HI,0)		,"B",F_ALIAS|F_CONDBR,0},
  { "bugt",	SBR_PAIR(L3_HI,0,0)		,"1",F_ALIAS|F_CONDBR,0},
  { "bugt",	SBR_PAIR(L3_HI,0,0)		,"143",F_ALIAS|F_CONDBR,0},
  { "bugt.r",	BR_PAIR(L3_HI,1)		,"b",F_ALIAS|F_RELCONDBR,0},
  { "bugt.r",	PCREL_SBR_PAIR(L3_HI)		,"3",F_ALIAS|F_RELCONDBR,0},

  { "bls",	BR_PAIR(L3_LS,0)		,"B",     F_CONDBR,0},
  { "bls",	SBR_PAIR(L3_LS,0,0)		,"1",     F_CONDBR,0},
  { "bls",	SBR_PAIR(L3_LS,0,0)		,"143",   F_CONDBR,0},
  { "bls.r",	BR_PAIR(L3_LS,1)		,"b",     F_RELCONDBR,0},
  { "bls.r",	PCREL_SBR_PAIR(L3_LS)		,"3",     F_RELCONDBR,0},

  { "bule",	BR_PAIR(L3_LS,0)		,"B",F_ALIAS|F_CONDBR,0},
  { "bule",	SBR_PAIR(L3_LS,0,0)		,"1",F_ALIAS|F_CONDBR,0},
  { "bule",	SBR_PAIR(L3_LS,0,0)		,"143",F_ALIAS|F_CONDBR,0},
  { "bule.r",	BR_PAIR(L3_LS,1)		,"b",F_ALIAS|F_RELCONDBR,0},
  { "bule.r",	PCREL_SBR_PAIR(L3_LS)		,"3",F_ALIAS|F_RELCONDBR,0},

  { "bcc",	BR_PAIR(L3_CC,0)		,"B",     F_CONDBR,0},
  { "bcc",	SBR_PAIR(L3_CC,0,0)		,"1",     F_CONDBR,0},
  { "bcc",	SBR_PAIR(L3_CC,0,0)		,"143",   F_CONDBR,0},
  { "bcc.r",	BR_PAIR(L3_CC,1)		,"b",     F_RELCONDBR,0},
  { "bcc.r",	PCREL_SBR_PAIR(L3_CC)		,"3",     F_RELCONDBR,0},

  { "buge",	BR_PAIR(L3_CS,0)		,"B",F_ALIAS|F_CONDBR,0},
  { "buge",	SBR_PAIR(L3_CS,0,0)		,"1",F_ALIAS|F_CONDBR,0},
  { "buge",	SBR_PAIR(L3_CS,0,0)		,"143",F_ALIAS|F_CONDBR,0},
  { "buge.r",	BR_PAIR(L3_CS,1)		,"b",F_ALIAS|F_RELCONDBR,0},
  { "buge.r",	PCREL_SBR_PAIR(L3_CS)		,"3",F_ALIAS|F_RELCONDBR,0},

  { "bcs",	BR_PAIR(L3_CS,0)		,"B",     F_CONDBR,0},
  { "bcs",	SBR_PAIR(L3_CS,0,0)		,"1",     F_CONDBR,0},
  { "bcs",	SBR_PAIR(L3_CS,0,0)		,"143",   F_CONDBR,0},
  { "bcs.r",	BR_PAIR(L3_CS,1)		,"b",     F_RELCONDBR,0},
  { "bcs.r",	PCREL_SBR_PAIR(L3_CS)		,"3",     F_RELCONDBR,0},

  { "bult",	BR_PAIR(L3_CC,0)		,"B",F_ALIAS|F_CONDBR,0},
  { "bult",	SBR_PAIR(L3_CC,0,0)		,"1",F_ALIAS|F_CONDBR,0},
  { "bult",	SBR_PAIR(L3_CC,0,0)		,"143",F_ALIAS|F_CONDBR,0},
  { "bult.r",	BR_PAIR(L3_CC,1)		,"b",F_ALIAS|F_RELCONDBR,0},
  { "bult.r",	PCREL_SBR_PAIR(L3_CC)		,"3",F_ALIAS|F_RELCONDBR,0},

  { "bne",	BR_PAIR(L3_NE,0)		,"B",     F_CONDBR,0},
  { "bne",	SBR_PAIR(L3_NE,0,0)		,"1",     F_CONDBR,0},
  { "bne",	SBR_PAIR(L3_NE,0,0)		,"143",   F_CONDBR,0},
  { "bne.r",	BR_PAIR(L3_NE,1)		,"b",     F_RELCONDBR,0},
  { "bne.r",	PCREL_SBR_PAIR(L3_NE)		,"3",     F_RELCONDBR,0},

  { "beq",	BR_PAIR(L3_EQ,0)		,"B",     F_CONDBR,0},
  { "beq",	SBR_PAIR(L3_EQ,0,0)		,"1",     F_CONDBR,0},
  { "beq",	SBR_PAIR(L3_EQ,0,0)		,"143",   F_CONDBR,0},
  { "beq.r",	BR_PAIR(L3_EQ,1)		,"b",     F_RELCONDBR,0},
  { "beq.r",	PCREL_SBR_PAIR(L3_EQ)		,"3",     F_RELCONDBR,0},

  { "bvc",	BR_PAIR(L3_VC,0)		,"B",     F_CONDBR,0},
  { "bvc",	SBR_PAIR(L3_VC,0,0)		,"1",     F_CONDBR,0},
  { "bvc",	SBR_PAIR(L3_VC,0,0)		,"143",   F_CONDBR,0},
  { "bvc.r",	BR_PAIR(L3_VC,1)		,"b",     F_RELCONDBR,0},
  { "bvc.r",	PCREL_SBR_PAIR(L3_VC)		,"3",     F_RELCONDBR,0},

  { "bvs",	BR_PAIR(L3_VS,0)		,"B",     F_CONDBR,0},
  { "bvs",	SBR_PAIR(L3_VS,0,0)		,"1",     F_CONDBR,0},
  { "bvs",	SBR_PAIR(L3_VS,0,0)		,"143",   F_CONDBR,0},
  { "bvs.r",	BR_PAIR(L3_VS,1)		,"b",     F_RELCONDBR,0},
  { "bvs.r",	PCREL_SBR_PAIR(L3_VS)		,"3",     F_RELCONDBR,0},

  { "bpl",	BR_PAIR(L3_PL,0)		,"B",     F_CONDBR,0},
  { "bpl",	SBR_PAIR(L3_PL,0,0)		,"1",     F_CONDBR,0},
  { "bpl",	SBR_PAIR(L3_PL,0,0)		,"143",   F_CONDBR,0},
  { "bpl.r",	BR_PAIR(L3_PL,1)		,"b",     F_RELCONDBR,0},
  { "bpl.r",	PCREL_SBR_PAIR(L3_PL)		,"3",     F_RELCONDBR,0},

  { "bmi",	BR_PAIR(L3_MI,0)		,"B",     F_CONDBR,0},
  { "bmi",	SBR_PAIR(L3_MI,0,0)		,"1",     F_CONDBR,0},
  { "bmi",	SBR_PAIR(L3_MI,0,0)		,"143",   F_CONDBR,0},
  { "bmi.r",	BR_PAIR(L3_MI,1)		,"b",     F_RELCONDBR,0},
  { "bmi.r",	PCREL_SBR_PAIR(L3_MI)		,"3",     F_RELCONDBR,0},

  { "bge",	BR_PAIR(L3_GE,0)		,"B",     F_CONDBR,0},
  { "bge",	SBR_PAIR(L3_GE,0,0)		,"1",     F_CONDBR,0},
  { "bge",	SBR_PAIR(L3_GE,0,0)		,"143",   F_CONDBR,0},
  { "bge.r",	BR_PAIR(L3_GE,1)		,"b",     F_RELCONDBR,0},
  { "bge.r",	PCREL_SBR_PAIR(L3_GE)		,"3",     F_RELCONDBR,0},

  { "blt",	BR_PAIR(L3_LT,0)		,"B",     F_CONDBR,0},
  { "blt",	SBR_PAIR(L3_LT,0,0)		,"1",     F_CONDBR,0},
  { "blt",	SBR_PAIR(L3_LT,0,0)		,"143",   F_CONDBR,0},
  { "blt.r",	BR_PAIR(L3_LT,1)		,"b",     F_RELCONDBR,0},
  { "blt.r",	PCREL_SBR_PAIR(L3_LT)		,"3",     F_RELCONDBR,0},

  { "bgt",	BR_PAIR(L3_GT,0)		,"B",     F_CONDBR,0},
  { "bgt",	SBR_PAIR(L3_GT,0,0)		,"1",     F_CONDBR,0},
  { "bgt",	SBR_PAIR(L3_GT,0,0)		,"143",   F_CONDBR,0},
  { "bgt.r",	BR_PAIR(L3_GT,1)		,"b",     F_RELCONDBR,0},
  { "bgt.r",	PCREL_SBR_PAIR(L3_GT)		,"3",     F_RELCONDBR,0},

  { "ble",	BR_PAIR(L3_LE,0)		,"B",     F_CONDBR,0},
  { "ble",	SBR_PAIR(L3_LE,0,0)		,"1",     F_CONDBR,0},
  { "ble",	SBR_PAIR(L3_LE,0,0)		,"143",   F_CONDBR,0},
  { "ble.r",	BR_PAIR(L3_LE,1)		,"b",     F_RELCONDBR,0},
  { "ble.r",	PCREL_SBR_PAIR(L3_LE)		,"3",     F_RELCONDBR,0},

  /* ld */

  { "ld",	0x80030004,0x7000fffb		,"[++1],d",  F_RM,0},
  { "ld",	0x80010004,0x7002fffb		,"[1++],d",  F_RM,0},
  { "ld",	0x8003fffc,0x70000003		,"[--1],d",  F_RM,0},
  { "ld",	0x8001fffc,0x70020003		,"[1--],d",  F_RM,0},
  { "ld",    RRM_PAIR(0,1,0,L3_SIGNED_FULLWORD)	,"2[1],d",   F_RRM,0},
  { "ld",    RRM_PAIR(0,1,1,L3_SIGNED_FULLWORD)	,"2[*1],d",  F_RRM,0},
  { "ld",    RRM_PAIR(0,0,1,L3_SIGNED_FULLWORD)	,"2[1*],d",  F_RRM,0},
  { "ld",    RRM_PAIR(0,1,0,L3_SIGNED_FULLWORD)	,"[162],d",  F_RRM,0},
  { "ld",    RRM_PAIR(0,1,1,L3_SIGNED_FULLWORD)	,"[*162],d", F_RRM,0},
  { "ld",    RRM_PAIR(0,0,1,L3_SIGNED_FULLWORD)	,"[1*62],d", F_RRM,0},
  { "ld",	SLS_PAIR(0)			,"[Y],d",    F_SLS,0},
  { "ld",	0x80020000,0x707d0000		,"[o],d",    F_RM,0},
/*{ "ld",	RM_PAIR(0,1,0)			,"[o],d",    F_RM,0},*/
  { "ld",	RM_PAIR(0,1,0)			,"o[1],d",   F_RM,0},
  { "ld",	RM_PAIR(0,1,1)			,"o[*1],d",  F_RM,0},
  { "ld",	RM_PAIR(0,0,1)			,"o[1*],d",  F_RM,0},
 
  { "uld",	0x80030004,0x7000fffb		,"[++1],d",  F_ALIAS,0},
  { "uld",	0x80010004,0x7002fffb		,"[1++],d",  F_ALIAS,0},
  { "uld",	0x8003fffc,0x70000003		,"[--1],d",  F_ALIAS,0},
  { "uld",	0x8001fffc,0x70020003		,"[1--],d",  F_ALIAS,0},
  { "uld", RRM_PAIR(0,1,0,L3_UNSIGNED_FULLWORD)	,"2[1],d",   F_ALIAS,0},
  { "uld", RRM_PAIR(0,1,1,L3_UNSIGNED_FULLWORD)	,"2[*1],d",  F_ALIAS,0},
  { "uld", RRM_PAIR(0,0,1,L3_UNSIGNED_FULLWORD)	,"2[1*],d",  F_ALIAS,0},
  { "uld", RRM_PAIR(0,1,0,L3_UNSIGNED_FULLWORD)	,"[162],d",  F_ALIAS,0},
  { "uld", RRM_PAIR(0,1,1,L3_UNSIGNED_FULLWORD)	,"[*162],d", F_ALIAS,0},
  { "uld", RRM_PAIR(0,0,1,L3_UNSIGNED_FULLWORD)	,"[1*62],d", F_ALIAS,0},
  { "uld",      SLS_PAIR(0)			,"[Y],d",    F_SLS|F_ALIAS,0},
  /* Here, the second part of the RM_PAIR is wrong, but that's OK */
  { "uld",      RM_PAIR(0,1,0)			,"[o],d",    F_ALIAS,0},
  { "uld",      RM_PAIR(0,1,0)			,"o[1],d",   F_ALIAS,0},
  { "uld",	RM_PAIR(0,1,1)			,"o[*1],d",  F_ALIAS,0},
  { "uld",	RM_PAIR(0,0,1)			,"o[1*],d",  F_ALIAS,0},
 
  { "ld.h",	0xf0030c02,0x0000f3fd		,"[++1],d",  F_HALF|F_SPLS,0},
  { "ld.h",	0xf0030402,0x0000fbfd		,"[1++],d",  F_HALF|F_SPLS,0},
  { "ld.h",	0xf0030ffe,0x0000f001		,"[--1],d",  F_HALF|F_SPLS,0},
  { "ld.h",	0xf00307fe,0x0000f801		,"[1--],d",  F_HALF|F_SPLS,0},
  { "ld.h",  RRM_PAIR(0,1,0,L3_SIGNED_HALFWORD)	,"2[1],d",   F_HALF|F_RRM,0},
  { "ld.h",  RRM_PAIR(0,1,1,L3_SIGNED_HALFWORD)	,"2[*1],d",  F_HALF|F_RRM,0},
  { "ld.h",  RRM_PAIR(0,0,1,L3_SIGNED_HALFWORD)	,"2[1*],d",  F_HALF|F_RRM,0},
  { "ld.h",  RRM_PAIR(0,1,0,L3_SIGNED_HALFWORD)	,"[162],d",  F_HALF|F_RRM,0},
  { "ld.h",  RRM_PAIR(0,1,1,L3_SIGNED_HALFWORD)	,"[*162],d", F_HALF|F_RRM,0},
  { "ld.h",  RRM_PAIR(0,0,1,L3_SIGNED_HALFWORD)	,"[1*62],d", F_HALF|F_RRM,0},
  { "ld.h",	0xf0030800,0x007cf400		,"[i],d",    F_HALF|F_SPLS,0},
/*{ "ld.h", SPLS_PAIR(0,L3_SIGNED_HALFWORD,1,0)	,"[i],d",    F_HALF|F_SPLS,0},*/
  { "ld.h", SPLS_PAIR(0,L3_SIGNED_HALFWORD,1,0)	,"i[1],d",   F_HALF|F_SPLS,0},
  { "ld.h", SPLS_PAIR(0,L3_SIGNED_HALFWORD,1,1)	,"i[*1],d",  F_HALF|F_SPLS,0},
  { "ld.h", SPLS_PAIR(0,L3_SIGNED_HALFWORD,0,1)	,"i[1*],d",  F_HALF|F_SPLS,0},
 
  { "uld.h",	0xf0031c02,0x0000e3fd		,"[++1],d",  F_HALF|F_SPLS,0},
  { "uld.h",	0xf0031402,0x0000ebfd		,"[1++],d",  F_HALF|F_SPLS,0},
  { "uld.h",	0xf0031ffe,0x0000e001		,"[--1],d",  F_HALF|F_SPLS,0},
  { "uld.h",	0xf00317fe,0x0000e801		,"[1--],d",  F_HALF|F_SPLS,0},
  { "uld.h",RRM_PAIR(0,1,0,L3_UNSIGNED_HALFWORD),"2[1],d",   F_HALF|F_RRM,0},
  { "uld.h",RRM_PAIR(0,1,1,L3_UNSIGNED_HALFWORD),"2[*1],d",  F_HALF|F_RRM,0},
  { "uld.h",RRM_PAIR(0,0,1,L3_UNSIGNED_HALFWORD),"2[1*],d",  F_HALF|F_RRM,0},
  { "uld.h",RRM_PAIR(0,1,0,L3_UNSIGNED_HALFWORD),"[162],d",  F_HALF|F_RRM,0},
  { "uld.h",RRM_PAIR(0,1,1,L3_UNSIGNED_HALFWORD),"[*162],d", F_HALF|F_RRM,0},
  { "uld.h",RRM_PAIR(0,0,1,L3_UNSIGNED_HALFWORD),"[1*62],d", F_HALF|F_RRM,0},
  { "uld.h",	0xf0031800,0x007ce400		,"[i],d",    F_HALF|F_SPLS,0},
/*{ "uld.h",SPLS_PAIR(0,L3_UNSIGNED_HALFWORD,1,0),"[i],d",   F_HALF|F_SPLS,0},*/
  { "uld.h",SPLS_PAIR(0,L3_UNSIGNED_HALFWORD,1,0),"i[1],d",  F_HALF|F_SPLS,0},
  { "uld.h",SPLS_PAIR(0,L3_UNSIGNED_HALFWORD,1,1),"i[*1],d", F_HALF|F_SPLS,0},
  { "uld.h",SPLS_PAIR(0,L3_UNSIGNED_HALFWORD,0,1),"i[1*],d", F_HALF|F_SPLS,0},
 
  { "ld.b",	0xf0034c01,0x0000b3fe		,"[++1],d",  F_BYTE|F_SPLS,0},
  { "ld.b",	0xf0034401,0x0000bbfe		,"[1++],d",  F_BYTE|F_SPLS,0},
  { "ld.b",	0xf0034fff,0x0000b000		,"[--1],d",  F_BYTE|F_SPLS,0},
  { "ld.b",	0xf00347ff,0x0000b800		,"[1--],d",  F_BYTE|F_SPLS,0},
  { "ld.b",	RRM_PAIR(0,1,0,L3_SIGNED_BYTE)	,"2[1],d",   F_BYTE|F_RRM,0},
  { "ld.b",	RRM_PAIR(0,1,1,L3_SIGNED_BYTE)	,"2[*1],d",  F_BYTE|F_RRM,0},
  { "ld.b",	RRM_PAIR(0,0,1,L3_SIGNED_BYTE)	,"2[1*],d",  F_BYTE|F_RRM,0},
  { "ld.b",	RRM_PAIR(0,1,0,L3_SIGNED_BYTE)	,"[162],d",  F_BYTE|F_RRM,0},
  { "ld.b",	RRM_PAIR(0,1,1,L3_SIGNED_BYTE)	,"[*162],d", F_BYTE|F_RRM,0},
  { "ld.b",	RRM_PAIR(0,0,1,L3_SIGNED_BYTE)	,"[1*62],d", F_BYTE|F_RRM,0},
  { "ld.b",	0xf0034800,0x007cb400		,"[i],d",    F_BYTE|F_SPLS,0},
/*{ "ld.b",	SPLS_PAIR(0,L3_SIGNED_BYTE,1,0)	,"[i],d",    F_BYTE|F_SPLS,0},*/
  { "ld.b",	SPLS_PAIR(0,L3_SIGNED_BYTE,1,0)	,"i[1],d",   F_BYTE|F_SPLS,0},
  { "ld.b",	SPLS_PAIR(0,L3_SIGNED_BYTE,1,1)	,"i[*1],d",  F_BYTE|F_SPLS,0},
  { "ld.b",	SPLS_PAIR(0,L3_SIGNED_BYTE,0,1)	,"i[1*],d",  F_BYTE|F_SPLS,0},
 
  { "uld.b",	0xf0035c01,0x0000a3fe		,"[++1],d",  F_BYTE|F_SPLS,0},
  { "uld.b",	0xf0035401,0x0000abfe		,"[1++],d",  F_BYTE|F_SPLS,0},
  { "uld.b",	0xf0035fff,0x0000a000		,"[--1],d",  F_BYTE|F_SPLS,0},
  { "uld.b",	0xf00357ff,0x0000a800		,"[1--],d",  F_BYTE|F_SPLS,0},
  { "uld.b",  RRM_PAIR(0,1,0,L3_UNSIGNED_BYTE)	,"2[1],d",   F_BYTE|F_RRM,0},
  { "uld.b",  RRM_PAIR(0,1,1,L3_UNSIGNED_BYTE)	,"2[*1],d",  F_BYTE|F_RRM,0},
  { "uld.b",  RRM_PAIR(0,0,1,L3_UNSIGNED_BYTE)	,"2[1*],d",  F_BYTE|F_RRM,0},
  { "uld.b",  RRM_PAIR(0,1,0,L3_UNSIGNED_BYTE)	,"[162],d",  F_BYTE|F_RRM,0},
  { "uld.b",  RRM_PAIR(0,1,1,L3_UNSIGNED_BYTE)	,"[*162],d", F_BYTE|F_RRM,0},
  { "uld.b",  RRM_PAIR(0,0,1,L3_UNSIGNED_BYTE)	,"[1*62],d", F_BYTE|F_RRM,0},
  { "uld.b",	0xf0035800,0x007ca400		,"[i],d",    F_BYTE|F_SPLS,0},
/*{ "uld.b",  SPLS_PAIR(0,L3_UNSIGNED_BYTE,1,0)	,"[i],d",    F_BYTE|F_SPLS,0},*/
  { "uld.b",  SPLS_PAIR(0,L3_UNSIGNED_BYTE,1,0)	,"i[1],d",   F_BYTE|F_SPLS,0},
  { "uld.b",  SPLS_PAIR(0,L3_UNSIGNED_BYTE,1,1)	,"i[*1],d",  F_BYTE|F_SPLS,0},
  { "uld.b",  SPLS_PAIR(0,L3_UNSIGNED_BYTE,0,1)	,"i[1*],d",  F_BYTE|F_SPLS,0},

  /* leadz */

  { "leadz",	LEADZ_PAIR(0)			,"1,d",	     F_LEADZ,0},
  { "leadz.f",	LEADZ_PAIR(1)			,"1,d",	     F_LEADZ,0},
							     
  /* or */

  { "or",	RR_PAIR(0,L3_OR)		,"1,2,d",    F_RR,0},
  { "or",	RI_PAIR(L3_OR,0,0)		,"1,j,d",    F_RI,0},
  { "or",	RI_PAIR(L3_OR,0,1)		,"1,J,d",    F_RI,0},
  { "or.f",	RR_PAIR(1,L3_OR)		,"1,2,d",    F_RR,0},
  { "or.f",	RI_PAIR(L3_OR,1,0)		,"1,j,d",    F_RI,0},
  { "or.f",	RI_PAIR(L3_OR,1,1)		,"1,J,d",    F_RI,0},

  /* popc */						     
							     
  { "popc",	POPC_PAIR(0)			,"1,d",	     F_POPC,0},
  { "popc.f",	POPC_PAIR(1)			,"1,d",	     F_POPC,0},

  /* put */

  { "put",	RRR_PAIR()			,"15(243),d",F_RRR, 0},

  /* punt */

  { "punt",	0xf003ff47, 0x00000000		,"",	     F_PUNT, 0},

  /* sh */

  { "sh",	RR_PAIR(0,L3_SH)		,"1,2,d",    F_RR, 0},
  { "sh",	RI_PAIR(L3_SH,0,0)		,"1,s,d",    F_RI, 0},
  { "sh.f",	RR_PAIR(1,L3_SH)		,"1,2,d",    F_RR, 0},
  { "sh.f",	RI_PAIR(L3_SH,1,0)		,"1,s,d",    F_RI, 0},
  { "sha",	RR_PAIR(0,L3_SH|L3_ARITH)	,"1,2,d",    F_RR, 0},
  { "sha",	RI_PAIR(L3_SH,0,1)		,"1,s,d",    F_RI, 0},
  { "sha.f",	RR_PAIR(1,L3_SH|L3_ARITH)	,"1,2,d",    F_RR, 0},
  { "sha.f",	RI_PAIR(L3_SH,1,1)		,"1,s,d",    F_RI, 0},

  /* st */

  { "st",	0x90030004,0x6000fffb		,"d,[++1]",  F_RM,0},
  { "st",	0x90010004,0x6002fffb		,"d,[1++]",  F_RM,0},
  { "st",	0x9003fffc,0x60000003		,"d,[--1]",  F_RM,0},
  { "st",	0x9001fffc,0x60020003		,"d,[1--]",  F_RM,0},
  { "st",    RRM_PAIR(1,1,0,L3_SIGNED_FULLWORD)	,"d,2[1]",   F_RRM,0},
  { "st",    RRM_PAIR(1,1,1,L3_SIGNED_FULLWORD)	,"d,2[*1]",  F_RRM,0},
  { "st",    RRM_PAIR(1,0,1,L3_SIGNED_FULLWORD)	,"d,2[1*]",  F_RRM,0},
  { "st",    RRM_PAIR(1,1,0,L3_SIGNED_FULLWORD)	,"d,[162]",  F_RRM,0},
  { "st",    RRM_PAIR(1,1,1,L3_SIGNED_FULLWORD)	,"d,[*162]", F_RRM,0},
  { "st",    RRM_PAIR(1,0,1,L3_SIGNED_FULLWORD)	,"d,[1*62]", F_RRM,0},
  { "st",	SLS_PAIR(1)			,"d,[Y]",    F_SLS,0},
  { "st",	0x90020000,0x607d0000		,"d,[o]",    F_RM,0},
/*{ "st",	RM_PAIR(1,1,0)			,"d,[o]",    F_RM,0},*/
  { "st",	RM_PAIR(1,1,0)			,"d,o[1]",   F_RM,0},
  { "st",	RM_PAIR(1,1,1)			,"d,o[*1]",  F_RM,0},
  { "st",	RM_PAIR(1,0,1)			,"d,o[1*]",  F_RM,0},
 
  { "st.h",	0xf0032c02,0x0000d3fd		,"d,[++1]",  F_HALF|F_SPLS,0},
  { "st.h",	0xf0032402,0x0000dbfd		,"d,[1++]",  F_HALF|F_SPLS,0},
  { "st.h",	0xf0032ffe,0x0000d001		,"d,[--1]",  F_HALF|F_SPLS,0},
  { "st.h",	0xf00327fe,0x0000d801		,"d,[1--]",  F_HALF|F_SPLS,0},
  { "st.h",  RRM_PAIR(1,1,0,L3_SIGNED_HALFWORD)	,"d,2[1]",   F_HALF|F_RRM,0},
  { "st.h",  RRM_PAIR(1,1,1,L3_SIGNED_HALFWORD)	,"d,2[*1]",  F_HALF|F_RRM,0},
  { "st.h",  RRM_PAIR(1,0,1,L3_SIGNED_HALFWORD)	,"d,2[1*]",  F_HALF|F_RRM,0},
  { "st.h",  RRM_PAIR(1,1,0,L3_SIGNED_HALFWORD)	,"d,[162]",  F_HALF|F_RRM,0},
  { "st.h",  RRM_PAIR(1,1,1,L3_SIGNED_HALFWORD)	,"d,[*162]", F_HALF|F_RRM,0},
  { "st.h",  RRM_PAIR(1,0,1,L3_SIGNED_HALFWORD)	,"d,[1*62]", F_HALF|F_RRM,0},
  { "st.h",	0xf0032800,0x007cd400		,"d,[i]",    F_HALF|F_SPLS,0},
/*{ "st.h", SPLS_PAIR(1,L3_SIGNED_HALFWORD,1,0)	,"d,[i]",    F_HALF|F_SPLS,0},*/
  { "st.h", SPLS_PAIR(1,L3_SIGNED_HALFWORD,1,0)	,"d,i[1]",   F_HALF|F_SPLS,0},
  { "st.h", SPLS_PAIR(1,L3_SIGNED_HALFWORD,1,1)	,"d,i[*1]",  F_HALF|F_SPLS,0},
  { "st.h", SPLS_PAIR(1,L3_SIGNED_HALFWORD,0,1)	,"d,i[1*]",  F_HALF|F_SPLS,0},
 
  { "st.b",	0xf0036c01,0x000093fe		,"d,[++1]",  F_BYTE|F_SPLS,0},
  { "st.b",	0xf0036401,0x00009bfe		,"d,[1++]",  F_BYTE|F_SPLS,0},
  { "st.b",	0xf0036fff,0x00009000		,"d,[--1]",  F_BYTE|F_SPLS,0},
  { "st.b",	0xf00367ff,0x00009800		,"d,[1--]",  F_BYTE|F_SPLS,0},
  { "st.b",	RRM_PAIR(1,1,0,L3_SIGNED_BYTE)	,"d,2[1]",   F_BYTE|F_RRM,0},
  { "st.b",	RRM_PAIR(1,1,1,L3_SIGNED_BYTE)	,"d,2[*1]",  F_BYTE|F_RRM,0},
  { "st.b",	RRM_PAIR(1,0,1,L3_SIGNED_BYTE)	,"d,2[1*]",  F_BYTE|F_RRM,0},
  { "st.b",	RRM_PAIR(1,1,0,L3_SIGNED_BYTE)	,"d,[162]",  F_BYTE|F_RRM,0},
  { "st.b",	RRM_PAIR(1,1,1,L3_SIGNED_BYTE)	,"d,[*162]", F_BYTE|F_RRM,0},
  { "st.b",	RRM_PAIR(1,0,1,L3_SIGNED_BYTE)	,"d,[1*62]", F_BYTE|F_RRM,0},
  { "st.b",	0xf0036800,0x007c9400		,"d,[i]",    F_BYTE|F_SPLS,0},
/*{ "st.b",	SPLS_PAIR(1,L3_SIGNED_BYTE,1,0)	,"d,[i]",    F_BYTE|F_SPLS,0},*/
  { "st.b",	SPLS_PAIR(1,L3_SIGNED_BYTE,1,0)	,"d,i[1]",   F_BYTE|F_SPLS,0},
  { "st.b",	SPLS_PAIR(1,L3_SIGNED_BYTE,1,1)	,"d,i[*1]",  F_BYTE|F_SPLS,0},
  { "st.b",	SPLS_PAIR(1,L3_SIGNED_BYTE,0,1)	,"d,i[1*]",  F_BYTE|F_SPLS,0},

  /* sub */

  { "sub",	RR_PAIR(0,L3_SUB)		,"1,2,d",    F_RR,0},
  { "sub",	RI_PAIR(L3_SUB,0,0)		,"1,j,d",    F_RI,0},
  { "sub",	RI_PAIR(L3_SUB,0,1)		,"1,J,d",    F_RI,0},
/*{ "sub",	RI_PAIR(L3_ADD,0,0)		,"1,k,d",    F_ALIAS,0}, */
  { "sub.f",	RR_PAIR(1,L3_SUB)		,"1,2,d",    F_RR,0},
  { "sub.f",	RI_PAIR(L3_SUB,1,0)		,"1,j,d",    F_RI,0},
  { "sub.f",	RI_PAIR(L3_SUB,1,1)		,"1,J,d",    F_RI,0},
/*{ "sub.f",	RI_PAIR(L3_ADD,1,0)		,"1,k,d",    F_ALIAS,0}, */
  { "subb",	RR_PAIR(0,L3_SUBB)		,"1,2,d",    F_RR,0},
  { "subb",	RI_PAIR(L3_SUBB,0,0)		,"1,j,d",    F_RI,0},
  { "subb",	RI_PAIR(L3_SUBB,0,1)		,"1,J,d",    F_RI,0},
/*{ "subb",	RI_PAIR(L3_ADDC,0,0)		,"1,k,d",    F_ALIAS,0}, */
  { "subb.f",	RR_PAIR(1,L3_SUBB)		,"1,2,d",    F_RR,0},
  { "subb.f",	RI_PAIR(L3_SUBB,1,0)		,"1,j,d",    F_RI,0},
  { "subb.f",	RI_PAIR(L3_SUBB,1,1)		,"1,J,d",    F_RI,0},
/*{ "subb.f",	RI_PAIR(L3_ADDC,1,0)		,"1,k,d",    F_ALIAS,0}, */

  /* sCC */

  { "shi",	SCC_PAIR(L3_HI)			,"1",	  F_SCC|F_ALIAS,0},
  { "sugt",	SCC_PAIR(L3_HI)			,"1",	  F_SCC,0},
  { "sls",	SCC_PAIR(L3_LS)			,"1",	  F_SCC|F_ALIAS,0},
  { "sule",	SCC_PAIR(L3_LS)			,"1",	  F_SCC,0},
  { "scc",	SCC_PAIR(L3_CC)			,"1",	  F_SCC|F_ALIAS,0},
  { "suge",	SCC_PAIR(L3_CS)			,"1",	  F_SCC,0},
  { "scs",	SCC_PAIR(L3_CS)			,"1",	  F_SCC|F_ALIAS,0},
  { "sult",	SCC_PAIR(L3_CC)			,"1",	  F_SCC,0},
  { "sne",	SCC_PAIR(L3_NE)			,"1",	  F_SCC,0},
  { "seq",	SCC_PAIR(L3_EQ)			,"1",	  F_SCC,0},
  { "svc",	SCC_PAIR(L3_VC)			,"1",	  F_SCC,0},
  { "svs",	SCC_PAIR(L3_VS)			,"1",	  F_SCC,0},
  { "spl",	SCC_PAIR(L3_PL)			,"1",	  F_SCC,0},
  { "smi",	SCC_PAIR(L3_MI)			,"1",	  F_SCC,0},
  { "sge",	SCC_PAIR(L3_GE)			,"1",	  F_SCC,0},
  { "slt",	SCC_PAIR(L3_LT)			,"1",	  F_SCC,0},
  { "sgt",	SCC_PAIR(L3_GT)			,"1",	  F_SCC,0},
  { "sle",	SCC_PAIR(L3_LE)			,"1",	  F_SCC,0},

  /* xor */

  { "xor",	RR_PAIR(0,L3_XOR)		,"1,2,d",    F_RR,0},
  { "xor",	RI_PAIR(L3_XOR,0,0)		,"1,j,d",    F_RI,0},
  { "xor",	RI_PAIR(L3_XOR,0,1)		,"1,J,d",    F_RI,0},
  { "xor.f",	RR_PAIR(1,L3_XOR)		,"1,2,d",    F_RR,0},
  { "xor.f",	RI_PAIR(L3_XOR,1,0)		,"1,j,d",    F_RI,0},
  { "xor.f",	RI_PAIR(L3_XOR,1,1)		,"1,J,d",    F_RI,0},

};

const int bfd_lanai_num_opcodes = ((sizeof lanai_opcodes)/(sizeof lanai_opcodes[0]));
