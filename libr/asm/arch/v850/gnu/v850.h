/* v850.h -- Header file for NEC V850 opcode table
   Copyright (C) 1996-2020 Free Software Foundation, Inc.
   Written by J.T. Conklin, Cygnus Support

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
   Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#ifndef V850_H
#define V850_H

#ifdef __cplusplus
extern "C" {
#endif

/* The opcode table is an array of struct v850_opcode.  */

struct v850_opcode
{
  /* The opcode name.  */
  const char *name;

  /* The opcode itself.  Those bits which will be filled in with
     operands are zeroes.  */
  unsigned long opcode;

  /* The opcode mask.  This is used by the disassembler.  This is a
     mask containing ones indicating those bits which must match the
     opcode field, and zeroes indicating those bits which need not
     match (and are presumably filled in by operands).  */
  unsigned long mask;

  /* An array of operand codes.  Each code is an index into the
     operand table.  They appear in the order which the operands must
     appear in assembly code, and are terminated by a zero.  */
  unsigned char operands[8];

  /* Which (if any) operand is a memory operand.  */
  unsigned int memop;

  /* Target processor(s).  A bit field of processors which support
     this instruction.  Note a bit field is used as some instructions
     are available on multiple, different processor types, whereas
     other instructions are only available on one specific type.  */
  unsigned int processors;
};

/* Values for architecture number.  */
#define arch_V850      0
#define arch_V850E     (arch_V850 + 1)
#define arch_V850E1    (arch_V850E + 1)
#define arch_V850E2    (arch_V850E1 + 1)
#define arch_V850E2V3  (arch_V850E2 + 1)
#define arch_V850E3V5  (arch_V850E2V3 + 1)
#define arch_separator (arch_V850E3V5 + 1)

#define opt_EXTENSION  (arch_separator)
#define opt_ALIAS      (opt_EXTENSION + 1)

/* Values for the processors field in the v850_opcode structure.  */
#define PROCESSOR_V850       (1 << (arch_V850))     /* Just the V850.  */
#define PROCESSOR_V850E      (1 << (arch_V850E))    /* Just the V850E.  */
#define PROCESSOR_V850E1     (1 << (arch_V850E1))   /* Just the V850E1.  */
#define PROCESSOR_V850E2     (1 << (arch_V850E2))   /* Just the V850E2.  */
#define PROCESSOR_V850E2V3   (1 << (arch_V850E2V3)) /* Just the V850E2V3.  */
#define PROCESSOR_V850E3V5   (1 << (arch_V850E3V5)) /* Just the V850E3V5.  */

/* UPPERS */
#define PROCESSOR_V850E3V5_UP (PROCESSOR_V850E3V5)
#define PROCESSOR_V850E2V3_UP (PROCESSOR_V850E2V3 | PROCESSOR_V850E3V5_UP)
#define PROCESSOR_V850E2_UP   (PROCESSOR_V850E2   | PROCESSOR_V850E2V3_UP)
#define PROCESSOR_V850E_UP    (PROCESSOR_V850E    | PROCESSOR_V850E1 | PROCESSOR_V850E2_UP)
#define PROCESSOR_ALL         (PROCESSOR_V850     | PROCESSOR_V850E_UP)

#define PROCESSOR_MASK        (PROCESSOR_ALL)
#define PROCESSOR_NOT_V850    (PROCESSOR_ALL & (~ PROCESSOR_V850))         /* Any processor except the V850.  */

#define PROCESSOR_UNKNOWN    ~(PROCESSOR_MASK)

/* OPTIONS */
#define PROCESSOR_OPTION_EXTENSION (1 << (opt_EXTENSION))                  /* Enable extension opcodes.  */
#define PROCESSOR_OPTION_ALIAS     (1 << (opt_ALIAS))                      /* Enable alias opcodes.  */

#define SET_PROCESSOR_MASK(mask,set)	((mask) = ((mask) & ~PROCESSOR_MASK) | (set))

/* The table itself is sorted by major opcode number, and is otherwise
   in the order in which the disassembler should consider
   instructions.  */
extern const struct v850_opcode v850_opcodes[];
extern const int v850_num_opcodes;


/* The operands table is an array of struct v850_operand.  */

struct v850_operand
{
  /* The number of bits in the operand.  */
  /* If this value is -1 then the operand's bits are in a discontinous
     distribution in the instruction. */
  int bits;

  /* (bits >= 0):  How far the operand is left shifted in the instruction.  */
  /* (bits == -1): Bit mask of the bits in the operand.  */
  int shift;

  /* Insertion function.  This is used by the assembler.  To insert an
     operand value into an instruction, check this field.

     If it is NULL, execute
         i |= (op & ((1 << o->bits) - 1)) << o->shift;
     (i is the instruction which we are filling in, o is a pointer to
     this structure, and op is the opcode value; this assumes twos
     complement arithmetic).

     If this field is not NULL, then simply call it with the
     instruction and the operand value.  It will return the new value
     of the instruction.  If the ERRMSG argument is not NULL, then if
     the operand value is illegal, *ERRMSG will be set to a warning
     string (the operand will be inserted in any case).  If the
     operand value is legal, *ERRMSG will be unchanged (most operands
     can accept any value).  */
  unsigned long (* insert)
    (unsigned long instruction, long op, const char ** errmsg);

  /* Extraction function.  This is used by the disassembler.  To
     extract this operand type from an instruction, check this field.

     If it is NULL, compute
         op = o->bits == -1 ? ((i) & o->shift) : ((i) >> o->shift) & ((1 << o->bits) - 1);
	 if (o->flags & V850_OPERAND_SIGNED)
	     op = (op << (32 - o->bits)) >> (32 - o->bits);
     (i is the instruction, o is a pointer to this structure, and op
     is the result; this assumes twos complement arithmetic).

     If this field is not NULL, then simply call it with the
     instruction value.  It will return the value of the operand.  If
     the INVALID argument is not NULL, *INVALID will be set to
     non-zero if this operand type can not actually be extracted from
     this operand (i.e., the instruction does not match).  If the
     operand is valid, *INVALID will not be changed.  */
  unsigned long (* extract) (unsigned long instruction, int * invalid);

  /* One bit syntax flags.  */
  int flags;

  int default_reloc;
};

/* Elements in the table are retrieved by indexing with values from
   the operands field of the v850_opcodes table.  */

extern const struct v850_operand v850_operands[];

/* Values defined for the flags field of a struct v850_operand.  */

/* This operand names a general purpose register.  */
#define V850_OPERAND_REG	0x01

/* This operand is the ep register.  */
#define V850_OPERAND_EP		0x02

/* This operand names a system register.  */
#define V850_OPERAND_SRG	0x04

/* Prologue eilogue type instruction, V850E specific.  */
#define V850E_OPERAND_REG_LIST	0x08

/* This operand names a condition code used in the setf instruction.  */
#define V850_OPERAND_CC		0x10

#define V850_OPERAND_FLOAT_CC	0x20

/* This operand names a vector purpose register.  */
#define V850_OPERAND_VREG	0x40

/* 16 bit immediate follows instruction, V850E specific.  */
#define V850E_IMMEDIATE16	0x80

/* hi16 bit immediate follows instruction, V850E specific.  */
#define V850E_IMMEDIATE16HI	0x100

/* 23 bit immediate follows instruction, V850E specific.  */
#define V850E_IMMEDIATE23	0x200

/* 32 bit immediate follows instruction, V850E specific.  */
#define V850E_IMMEDIATE32	0x400

/* This is a relaxable operand.   Only used for D9->D22 branch relaxing
   right now.  We may need others in the future (or maybe handle them like
   promoted operands on the mn10300?).  */
#define V850_OPERAND_RELAX	0x800

/* This operand takes signed values.  */
#define V850_OPERAND_SIGNED	0x1000

/* This operand is a displacement.  */
#define V850_OPERAND_DISP	0x2000

/* This operand is a PC displacement.  */
#define V850_PCREL		0x4000

/* The register specified must be even number.  */
#define V850_REG_EVEN		0x8000

/* The register specified must not be r0.  */
#define V850_NOT_R0	        0x20000

/* The register specified must not be 0.  */
#define V850_NOT_IMM0	        0x40000

/* The condition code must not be SA CONDITION.  */
#define V850_NOT_SA		0x80000

/* The operand has '!' prefix.  */
#define V850_OPERAND_BANG	0x100000

/* The operand has '%' prefix.  */
#define V850_OPERAND_PERCENT	0x200000

/* This operand is a cache operation.  */
#define V850_OPERAND_CACHEOP	0x400000

/* This operand is a prefetch operation.  */
#define V850_OPERAND_PREFOP	0x800000

/* A PC-relative displacement where a positive value indicates a backwards displacement.  */
#define V850_INVERSE_PCREL	0x1000000

extern int v850_msg_is_out_of_range (const char *);

#ifdef __cplusplus
}
#endif

#endif /* V850_H */
