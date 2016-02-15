/*************************************************************************
 *                                                                       *
 * Definitions for opcode table for the Lanai.                          *
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
 /* This file is based upon sparc.h from the Gnu binutils-2.5.2 
    release, which had the following copyright notice: */

	/* Definitions for opcode table for the sparc.
		Copyright 1989, 1991, 1992 Free Software Foundation, Inc.

	This file is part of GAS, the GNU Assembler, GDB, the GNU debugger, and
	the GNU Binutils.


	GAS/GDB is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2, or (at your option)
	any later version.

	GAS/GDB is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with GAS or GDB; see the file COPYING.    If not, write to
	the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, 
		USA.   */

/* The Lanai opcode table (and other related data) is defined in
   the opcodes library in lanai-opc.c.  If you change anything here, make
   sure you fix up that file, and vice versa.  */

 /* FIXME-someday: perhaps the ,a's and such should be embedded in the
    instruction's name rather than the args.  This would make gas faster, pinsn
    slower, but would mess up some macros a bit.  xoxorich. */

#define lanai_architecture	bfd_lanai_architecture
#define architecture_pname	bfd_lanai_architecture_pname
#define lanai_opcode		bfd_lanai_opcode
#define lanai_opcodes		bfd_lanai_opcodes

/*
 * Structure of an opcode table entry.
 * This enumerator must parallel the architecture_pname array
 * in bfd/opc-lanai.c.
 */
enum lanai_architecture {
	v0 = 0, v1
};

extern const char *architecture_pname[];

struct lanai_opcode {
	const char *name;
	unsigned long match;	/* Bits that must be set. */
	unsigned long lose;	/* Bits that must be clear. */
	const char *args;
	unsigned int flags;
	enum lanai_architecture architecture;
};

#define	F_ALIAS		1	/* Alias for a "real" instruction */
#define	F_JSR		2	/* Subroutine call */

#define	F_RI		0x10	
#define	F_RR		0x20	
#define	F_RRR		0x40	
#define	F_RM		0x80
#define	F_RRM		0x100
#define	F_BR		0x200
#define	F_SLS		0x400
#define	F_SLI		0x800
#define	F_SPLS		0x1000
#define	F_PUNT		0x2000
#define	F_SBR		0x4000
#define F_SCC		0x8000

#define F_BYTE		0x20000
#define F_HALF		0x10000
#define F_FULL		0x00000
#define F_DATA_SIZE(X)	(4>>((X)&0x30000))
#define	F_CONDITIONAL	0x40000
#define	F_REL		0x80000

#define F_LEADZ		0x100000
#define F_POPC		0x200000

#define	F_CONDBR	(F_BR|F_CONDITIONAL)	/* Conditional branch    */
#define	F_UNBR		(F_BR)			/* Unconditional branch  */
#define	F_RELCONDBR	(F_REL|F_BR|F_CONDITIONAL) /* Conditional branch */
#define	F_RELUNBR	(F_REL|F_BR)		/* Unconditional branch  */

/* FIXME: Add F_ANACHRONISTIC flag for v9.  */
/* FIXME: Add F_OBSOLETE flag for v9, for instructions that no longer exist? */

/*

All lanai opcodes are 32 bits.

The match component is a mask saying which bits must match a particular
opcode in order for an instruction to be an instance of that opcode.

The args component is a string containing one character for each operand of the
instruction.

Kinds of operands:
	#	Number used by optimizer.	It is ignored.
	1	Rs1 register.
	2	Rs2 register.
	3	Rs3 register.
	d	Rd register.

	4	Op1 (for RRR)
	5	Op2 (for RRR) 
	6	Op2 (for RRM)

	J	0x????0000
	j	0x0000????
	L	0x????ffff
	l	0xffff????
	k	-j
	
	o	16 bit signed offset
        s	6 bit signed shift constant
	i	10 bit signed immediate.
	I	5/16 split 21-bit unsigned immediate.
	Y	5/16 split 21-bit unsigned immediate with 2 LSB's == 0.
	B	2+23-bit absolute.
	b	2+23-bit PC relative immediate.

	P	%pc or %r2  as Rd
 	p	%pc or %r2  as Rs1
X 	Q	%apc or %r29
X 	q	%aps or %r28
X 	S	%isr or %r31
X 	M	%imr or %r30
	!	%r1
	0	%r0

Literals:([])*+- ,

*/

/* whether to use certain insns */
#define L3_USE_SI
#define L3_USE_SPLS
#define L3_USE_SLS
#define L3_USE_SLI
#define L3_USE_SBR

/* encodings of various conditions */
#define L3_T   0
#define L3_F   1
#define L3_HI  2
#define L3_LS  3
#define L3_CC  4
#define L3_CS  5
#define L3_NE  6
#define L3_EQ  7
#define L3_VC  8
#define L3_VS  9
#define L3_PL  10
#define L3_MI  11
#define L3_GE  12
#define L3_LT  13
#define L3_GT  14
#define L3_LE  15

#define L3_UGE L3_CC
#define L3_ULT L3_CS
#define L3_UGT L3_GT
#define L3_ULE L3_LE

/* opcodes */
/* NOTE: The following masks specify all the bits that can be
   determined solely by knowing which line in lanai-opc.c (in the opcodes
   directory in the gnu binutils release) matched the line of assembly
   code. The OPCODE_MASK specifies which bits of the instruction are constant
   for all instructions in the family.
*/
#define L3_RI               (0x00000000)
#define L3_RI_OPCODE_MASK   (0x80000000)
#define L3_RI_MASK          (0xf0030000)
#define L3_RR               (0xc0000000)
#define L3_RR_OPCODE_MASK   (0xf0000003)
#define L3_RR_MASK          (0xf00207fb)
#define L3_LEADZ            (0xc0000002)
#define L3_LEADZ_OPCODE_MASK L3_RR_OPCODE_MASK
#define L3_LEADZ_MASK       (0xf00207fb)
#define L3_POPC             (0xc0000003)
#define L3_POPC_OPCODE_MASK L3_RR_OPCODE_MASK
#define L3_POPC_MASK        (0xf00207fb)
#define L3_RRR              (0xd0000000)
#define L3_RRR_OPCODE_MASK  (0xf0000000)
#define L3_RRR_MASK         (0xf0000000)
#define L3_RM               (0x80000000)
#define L3_RM_OPCODE_MASK   (0xe0000000)
#define L3_RM_MASK          (0xf0030000)
#define L3_RRM              (0xa0000000)
#define L3_RRM_OPCODE_MASK  (0xe0000000)
#define L3_RRM_MASK         (0xe0030007)
#define L3_BR               (0xe0000000)
#define L3_BR_OPCODE_MASK   (0xf0000002)
#define L3_BR_MASK          (0xfe000003)
#define L3_BRR		    (0xe1000002)
#define L3_BRR_OPCODE_MASK  (0xf1000002)
#define L3_BRR_MASK         (0xff000003)
#define L3_SCC		    (0xe0000002)
#define L3_SCC_OPCODE_MASK  (0xf1000002)
#define L3_SCC_MASK         (0xff000003)
#define L3_SLS              (0xf0000000)
#define L3_SLS_OPCODE_MASK  (0xf0020000)
#define L3_SLS_MASK         (0xf0030000)
#define L3_SLI              (0xf0020000)
#define L3_SLI_OPCODE_MASK  (0xf0030000)
#define L3_SLI_MASK         (0xf0030000)
#define L3_SPLS             (0xf0030000)
#define L3_SPLS_OPCODE_MASK (0xf0038000)
#define L3_SPLS_MASK        (0xf003fc00)
#ifdef BAD
/* BAD: needs fixing */
#define L3_SI               (0xf0038000)
#define L3_SI_OPCODE_MASK   ___bogus___
#define L3_SI_MASK          (0xf003cf47)
#endif
#define L3_PUNT             (0xf003ff47)
#define L3_PUNT_OPCODE_MASK (0xf003ff47)
#define L3_PUNT_MASK        (0xf003ff47)
#define L3_SBR              (0xf003c000)
#define L3_SBR_OPCODE_MASK  (0xf003f806)
#define L3_SBR_MASK         (0xfe03f807)

/* operations */
#define L3_ADD     (0x00)
#define L3_ADDC    (0x01)
#define L3_SUB     (0x02)
#define L3_SUBB    (0x03)
#define L3_AND     (0x04)
#define L3_OR      (0x05)
#define L3_XOR     (0x06)
#define L3_SH      (0x07)
#define L3_OP_MASK (0x07)
#define L3_FLAGS   (0x08)
#define L3_ARITH   (0x10)

/* Data sizes */
#define L3_HALFWORD        0
#define L3_BYTE            4 /* was 1 */
#define L3_FULLWORD        2

/* RRM modes for BYTE and HALFWORD load */
#define L3_SIGNED          0
#define L3_UNSIGNED        1 /* was 4 */

#define L3_SIGNED_HALFWORD       ( L3_SIGNED        | L3_HALFWORD      )
#define L3_SIGNED_BYTE           ( L3_SIGNED        | L3_BYTE          )
#define L3_SIGNED_FULLWORD       ( L3_SIGNED        | L3_FULLWORD      )
#define L3_UNSIGNED_HALFWORD     ( L3_UNSIGNED      | L3_HALFWORD      )
#define L3_UNSIGNED_BYTE         ( L3_UNSIGNED      | L3_BYTE          )
#define L3_UNSIGNED_FULLWORD     ( L3_UNSIGNED      | L3_FULLWORD      )

/* flags */
#define L3_RI_F  (0x00020000)
#define L3_RI_H  (0x00010000)

#define L3_RR_F    (0x00020000)
#define L3_LEADZ_F L3_RR_F
#define L3_POPC_F  L3_RR_F

#define L3_RRR_F (0x00020000)
#define L3_RRR_H (0x00010000)

#define L3_RM_P  (0x00020000)
#define L3_RM_Q  (0x00010000)
#define L3_RM_S  (0x10000000)

#define L3_RRM_P (0x00020000)
#define L3_RRM_Q (0x00010000)
#define L3_RRM_S (0x10000000)
#define L3_RRM_Y (0x00000004)
#define L3_RRM_L (0x00000002)
#define L3_RRM_E (0x00000001)

#define L3_BR_R  (0x00000002)

#define L3_SLS_S (0x00010000)

#define L3_SPLS_Y (0x00004000)
#define L3_SPLS_S (0x00002000)
#define L3_SPLS_E (0x00001000)
#define L3_SPLS_P (0x00000800)
#define L3_SPLS_Q (0x00000400)

#define L3_SI_F   (0x00002000)

#define L3_SBR_H  (0x00000004)
#define L3_SBR_R  (0x00000002)
#define L3_SBR_N  (0x00000001)

/* masks */

#define L3_CONST_MASK      	(0x0000ffff)
#define L3_BR_CONST_MASK   	(0x01fffffc)
#define L3_SPLS_CONST_MASK 	(0x000003ff)

/* field insertion */
#define L3_RD(x)		(((x)&0x1f) << 23)
#define L3_RS1(x)		(((x)&0x1f) << 18)
#define L3_RS2(x)		(((x)&0x1f) << 11)
#define L3_RS3(x)		(((x)&0x1f) << 3)

#define L3_RI_OP(x)        	(((x)&L3_OP_MASK) << 28)
#define L3_RR_OP(x)        	(((x)&L3_OP_MASK) << 8)
#define L3_RRR_OP1(x)         	(((x)&L3_OP_MASK) << 0)
#define L3_RRR_OP2(x)         	(((x)&L3_OP_MASK) << 8)
#define L3_RRM_OP(x)          	(((x)&L3_OP_MASK) << 8)
#define L3_RRM_MODE(x)		(((x)&0x7) << 0)
#define L3_BR_COND(x)         	((((x)&0xe) << 24) | ((x)&1) )
#define L3_SBR_COND(x)        	((((x)&0xe) << 24) | ((x)&1) )
#define L3_SLS_HIBITS(x)      	(((x)&0x1f) << 18)
#define L3_SLS_CONST(x)		((((x)&0x1f) << 18) | ((x)&0xffff))
/* Delete this:
#define L3_SLI_HIBITS(x)	(((x)&0x7) << 18)
*/
#define L3_SLI_CONST(x)		((((x)&0x1f) << 18) | ((x)&0xffff))
#define L3_SPLS_MODE(x)		(((x)&0x5) << 12)
#define L3_SBR_OP(x)          	(((x)&0x7) << 8)

#define L3_OP1(x)		(((x)&0x7)  << 0)
#define L3_OP2(x)		(((x)&0x7)  << 8)


/* Sign-extend a value which is N bits long.  */
#define SEX(value, bits)                                        \
        ((((int)(value)) << ((8 * sizeof (int)) - bits) )       \
                         >> ((8 * sizeof (int)) - bits) )


/* Macros used to extract instruction fields.  Not all fields have
   macros defined here, only those which are actually used.  */

#define X_RD(i)      (((i) >> 23) & 0x1f)
#define X_RS1(i)     (((i) >> 18) & 0x1f)
#define X_RS2(i)     (((i) >> 11) & 0x1f)
#define X_RS3(i)     (((i) >>  3) & 0x1f)

#define X_OP1(i)     (((i) >>  0) & 0x07)
#define X_OP2(i)     (((i) >>  8) & 0x07)
#define X_RI_OP(i)   (((i) >> 28) & 0x07)
#define X_RR_OP(i)   X_OP2(i)
#define X_RRM_OP(i)  X_OP2(i)
#define X_RRR_OP1(i) X_OP1(i)
#define X_RRR_OP2(i) X_OP2(i)

#define X_C10(i)     ((i) & 0x3ff)
#define X_C16(i)     ((i) & 0xffff)
#define X_C21(i)     (((i) & 0xffff) | (((i) & 0x7c0000)>>2))
#define X_C25(i)     ((i) & 0x1fffffc)

extern struct lanai_opcode lanai_opcodes[];
extern const int bfd_lanai_num_opcodes;

#define NUMOPCODES bfd_lanai_num_opcodes



/* end of lanai.h */
