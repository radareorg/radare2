/* PDP-11 opcde list.
   Copyright (C) 2001-2021 Free Software Foundation, Inc.

   This file is part of GDB and GAS.

   GDB and GAS are free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GDB and GAS are distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GDB or GAS; see the file COPYING3.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* PDP-11 opcode types.  */

#define PDP11_OPCODE_NO_OPS	 0
#define PDP11_OPCODE_REG	 1	/* register */
#define PDP11_OPCODE_OP		 2	/* generic operand */
#define PDP11_OPCODE_REG_OP	 3	/* register and generic operand */
#define PDP11_OPCODE_REG_OP_REV	 4	/* register and generic operand,
					   reversed syntax */
#define PDP11_OPCODE_AC_FOP	 5	/* fpu accumulator and generic float
					   operand */
#define PDP11_OPCODE_OP_OP	 6	/* two generic operands */
#define PDP11_OPCODE_DISPL	 7	/* pc-relative displacement */
#define PDP11_OPCODE_REG_DISPL	 8	/* redister and pc-relative
					   displacement */
#define PDP11_OPCODE_IMM8	 9	/* 8-bit immediate */
#define PDP11_OPCODE_IMM6	10	/* 6-bit immediate */
#define PDP11_OPCODE_IMM3	11	/* 3-bit immediate */
#define PDP11_OPCODE_ILLEGAL	12	/* illegal instruction */
#define PDP11_OPCODE_FOP_AC	13	/* generic float argument, then fpu
					   accumulator */
#define PDP11_OPCODE_FOP	14	/* generic float operand */
#define PDP11_OPCODE_AC_OP	15	/* fpu accumulator and generic int
					   operand */
#define PDP11_OPCODE_OP_AC	16	/* generic int argument, then fpu
					   accumulator */

/*
 * PDP-11 instruction set extensions.
 *
 * Please keep the numbers low, as they are used as indices into
 * an array.
 */

#define PDP11_NONE	 0	/* not in instruction set */
#define PDP11_BASIC	 1	/* basic instruction set (11/20 etc) */
#define PDP11_CSM	 2	/* commercial instruction set */
#define PDP11_CIS	 3	/* commercial instruction set */
#define PDP11_EIS	 4	/* extended instruction set (11/45 etc) */
#define PDP11_FIS	 5	/* KEV11 floating-point instructions */
#define PDP11_FPP	 6	/* FP-11 floating-point instructions */
#define PDP11_LEIS	 7	/* limited extended instruction set
				   (11/40 etc) */
#define PDP11_MFPT	 8	/* move from processor type */
#define PDP11_MPROC	 9	/* multiprocessor instructions: tstset,
				   wrtlck */
#define PDP11_MXPS	10	/* move from/to processor status */
#define PDP11_SPL	11	/* set priority level */
#define PDP11_UCODE	12	/* microcode instructions: ldub, med, xfc */
#define PDP11_EXT_NUM	13	/* total number of extension types */

struct pdp11_opcode
{
  const char *name;
  int opcode;
  int mask;
  int type;
  int extension;
};

extern const struct pdp11_opcode pdp11_opcodes[];
extern const struct pdp11_opcode pdp11_aliases[];
extern const int pdp11_num_opcodes, pdp11_num_aliases;

/* end of pdp11.h */
