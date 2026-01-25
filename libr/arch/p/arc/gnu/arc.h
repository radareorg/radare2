/* Opcode table for the ARC.
   Copyright (C) 1994-2026 Free Software Foundation, Inc.

   Contributed by Claudiu Zissulescu (claziss@synopsys.com)

   This file is part of GAS, the GNU Assembler, GDB, the GNU debugger, and
   the GNU Binutils.

   GAS/GDB is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   GAS/GDB is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with GAS or GDB; see the file COPYING3.  If not, write to
   the Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#ifndef OPCODE_ARC_H
#define OPCODE_ARC_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MAX_INSN_ARGS
#define MAX_INSN_ARGS	     16
#endif

#ifndef MAX_INSN_FLGS
#define MAX_INSN_FLGS	     4
#endif

/* Instruction Class.  */
typedef enum
{
  ACL,
  ARITH,
  AUXREG,
  BBIT0,
  BBIT1,
  BI,
  BIH,
  BITOP,
  BITSTREAM,
  BMU,
  BRANCH,
  BRCC,
  CONTROL,
  DBNZ,
  DIVREM,
  DMA,
  DPI,
  DSP,
  EI,
  ENTER,
  FLOAT,
  INVALID,
  JLI,
  JUMP,
  KERNEL,
  LEAVE,
  LLOCK,
  LOAD,
  LOGICAL,
  LOOP,
  MEMORY,
  MISC,
  MOVE,
  MPY,
  NET,
  PROTOCOL_DECODE,
  PMU,
  POP,
  PUSH,
  SCOND,
  SJLI,
  STORE,
  SUB,
  SWITCH,
  ULTRAIP,
  XY
} insn_class_t;

/* Instruction Subclass.  */
typedef enum
{
  NONE     = 0,
  CVT      = (1U << 1),
  BTSCN    = (1U << 2),
  CD       = (1U << 3),
  CD1      = CD,
  CD2      = CD,
  COND     = (1U << 4),
  DIV      = (1U << 5),
  DP       = (1U << 6),
  DPA      = (1U << 7),
  DPX      = (1U << 8),
  FASTMATH = (1U << 23),
  LL64     = (1U << 9),
  MPY1E    = (1U << 10),
  MPY6E    = (1U << 11),
  MPY7E    = (1U << 12),
  MPY8E    = (1U << 13),
  MPY9E    = (1U << 14),
  NPS400   = (1U << 15),
  QUARKSE1 = (1U << 16),
  QUARKSE2 = (1U << 17),
  SHFT1    = (1U << 18),
  SHFT2    = (1U << 19),
  SWAP     = (1U << 20),
  SP       = (1U << 21),
  SPX      = (1U << 22)
} insn_subclass_t;

/* Flags class.  */
typedef enum
{
  F_CLASS_NONE = 0,

  /* At most one flag from the set of flags can appear in the
     instruction.  */
  F_CLASS_OPTIONAL = (1 << 0),

  /* Exactly one from from the set of flags must appear in the
     instruction.  */
  F_CLASS_REQUIRED = (1 << 1),

  /* The conditional code can be extended over the standard variants
     via .extCondCode pseudo-op.  */
  F_CLASS_EXTEND = (1 << 2),

  /* Condition code flag.  */
  F_CLASS_COND = (1 << 3),

  /* Write back mode.  */
  F_CLASS_WB = (1 << 4),

  /* Data size.  */
  F_CLASS_ZZ = (1 << 5),

  /* Implicit flag.  */
  F_CLASS_IMPLICIT = (1 << 6)
} flag_class_t;

/* The opcode table is an array of struct arc_opcode.  */
struct arc_opcode
{
  /* The opcode name.  */
  const char * name;

  /* The opcode itself.  Those bits which will be filled in with
     operands are zeroes.  */
  unsigned long long opcode;

  /* The opcode mask.  This is used by the disassembler.  This is a
     mask containing ones indicating those bits which must match the
     opcode field, and zeroes indicating those bits which need not
     match (and are presumably filled in by operands).  */
  unsigned long long mask;

  /* One bit flags for the opcode.  These are primarily used to
     indicate specific processors and environments support the
     instructions.  The defined values are listed below.  */
  unsigned cpu;

  /* The instruction class.  This is used by gdb.  */
  insn_class_t insn_class;

  /* The instruction subclass.  */
  insn_subclass_t subclass;

  /* An array of operand codes.  Each code is an index into the
     operand table.  They appear in the order which the operands must
     appear in assembly code, and are terminated by a zero.  */
  unsigned char operands[MAX_INSN_ARGS + 1];

  /* An array of flag codes.  Each code is an index into the flag
     table.  They appear in the order which the flags must appear in
     assembly code, and are terminated by a zero.  */
  unsigned char flags[MAX_INSN_FLGS + 1];
};

/* The table itself is sorted by major opcode number, and is otherwise
   in the order in which the disassembler should consider
   instructions.  */
extern const struct arc_opcode arc_opcodes[];

/* Return length of an instruction represented by OPCODE, in bytes.  */
extern int arc_opcode_len (const struct arc_opcode *opcode);

/* CPU Availability.  */
#define ARC_OPCODE_NONE     0x0000
#define ARC_OPCODE_ARC600   0x0001  /* ARC 600 specific insns.  */
#define ARC_OPCODE_ARC700   0x0002  /* ARC 700 specific insns.  */
#define ARC_OPCODE_ARCv2EM  0x0004  /* ARCv2 EM specific insns.  */
#define ARC_OPCODE_ARCv2HS  0x0008  /* ARCv2 HS specific insns.  */

/* CPU combi.  */
#define ARC_OPCODE_ARCALL  (ARC_OPCODE_ARC600 | ARC_OPCODE_ARC700	\
			    | ARC_OPCODE_ARCv2EM | ARC_OPCODE_ARCv2HS)
#define ARC_OPCODE_ARCFPX  (ARC_OPCODE_ARC700 | ARC_OPCODE_ARCv2EM)
#define ARC_OPCODE_ARCV1   (ARC_OPCODE_ARC600 | ARC_OPCODE_ARC700)
#define ARC_OPCODE_ARCV2   (ARC_OPCODE_ARCv2EM | ARC_OPCODE_ARCv2HS)
#define ARC_OPCODE_ARCMPY6E  (ARC_OPCODE_ARC700 | ARC_OPCODE_ARCV2)

/* The operands table is an array of struct arc_operand.  */
struct arc_operand
{
  /* The number of bits in the operand.  */
  unsigned int bits;

  /* How far the operand is left shifted in the instruction.  */
  unsigned int shift;

  /* The default relocation type for this operand.  */
  signed int default_reloc;

  /* One bit syntax flags.  */
  unsigned int flags;

  /* Insertion function.  This is used by the assembler.  To insert an
     operand value into an instruction, check this field.

     If it is NULL, execute
	 i |= (op & ((1 << o->bits) - 1)) << o->shift;
     (i is the instruction which we are filling in, o is a pointer to
     this structure, and op is the opcode value; this assumes twos
     complement arithmetic).

     If this field is not NULL, then simply call it with the
     instruction and the operand value.	 It will return the new value
     of the instruction.  If the ERRMSG argument is not NULL, then if
     the operand value is illegal, *ERRMSG will be set to a warning
     string (the operand will be inserted in any case).	 If the
     operand value is legal, *ERRMSG will be unchanged (most operands
     can accept any value).  */
  unsigned long long (*insert) (unsigned long long instruction,
                                long long int op,
                                const char **errmsg);

  /* Extraction function.  This is used by the disassembler.  To
     extract this operand type from an instruction, check this field.

     If it is NULL, compute
	 op = ((i) >> o->shift) & ((1 << o->bits) - 1);
	 if ((o->flags & ARC_OPERAND_SIGNED) != 0
	     && (op & (1 << (o->bits - 1))) != 0)
	   op -= 1 << o->bits;
     (i is the instruction, o is a pointer to this structure, and op
     is the result; this assumes twos complement arithmetic).

     If this field is not NULL, then simply call it with the
     instruction value.	 It will return the value of the operand.  If
     the INVALID argument is not NULL, *INVALID will be set to
     TRUE if this operand type can not actually be extracted from
     this operand (i.e., the instruction does not match).  If the
     operand is valid, *INVALID will not be changed.  */
  long long int (*extract) (unsigned long long instruction, bool *invalid);
};

/* Elements in the table are retrieved by indexing with values from
   the operands field of the arc_opcodes table.  */
extern const struct arc_operand arc_operands[];
extern const unsigned arc_num_operands;
extern const unsigned arc_Toperand;
extern const unsigned arc_NToperand;

/* Values defined for the flags field of a struct arc_operand.  */

/* This operand does not actually exist in the assembler input.  This
   is used to support extended mnemonics, for which two operands fields
   are identical.  The assembler should call the insert function with
   any op value.  The disassembler should call the extract function,
   ignore the return value, and check the value placed in the invalid
   argument.  */
#define ARC_OPERAND_FAKE	0x0001

/* This operand names an integer register.  */
#define ARC_OPERAND_IR		0x0002

/* This operand takes signed values.  */
#define ARC_OPERAND_SIGNED	0x0004

/* This operand takes unsigned values.  This exists primarily so that
   a flags value of 0 can be treated as end-of-arguments.  */
#define ARC_OPERAND_UNSIGNED	0x0008

/* This operand takes long immediate values.  */
#define ARC_OPERAND_LIMM	0x0010

/* This operand is identical like the previous one.  */
#define ARC_OPERAND_DUPLICATE   0x0020

/* This operand is PC relative.  Used for internal relocs.  */
#define ARC_OPERAND_PCREL       0x0040

/* This operand is truncated.  The truncation is done accordingly to
   operand alignment attribute.  */
#define ARC_OPERAND_TRUNCATE    0x0080

/* This operand is 16bit aligned.  */
#define ARC_OPERAND_ALIGNED16   0x0100

/* This operand is 32bit aligned.  */
#define ARC_OPERAND_ALIGNED32   0x0200

/* This operand can be ignored by matching process if it is not
   present.  */
#define ARC_OPERAND_IGNORE      0x0400

/* Don't check the range when matching.	 */
#define ARC_OPERAND_NCHK	0x0800

/* Mark the braket possition.  */
#define ARC_OPERAND_BRAKET      0x1000

/* Address type operand for NPS400.  */
#define ARC_OPERAND_ADDRTYPE    0x2000

/* Mark the colon position.  */
#define ARC_OPERAND_COLON       0x4000

/* Mask for selecting the type for typecheck purposes.  */
#define ARC_OPERAND_TYPECHECK_MASK		 \
  (ARC_OPERAND_IR				 \
   | ARC_OPERAND_LIMM     | ARC_OPERAND_SIGNED	 \
   | ARC_OPERAND_UNSIGNED | ARC_OPERAND_BRAKET   \
   | ARC_OPERAND_ADDRTYPE | ARC_OPERAND_COLON)

/* Macro to determine if an operand is a fake operand.  */
#define ARC_OPERAND_IS_FAKE(op)                     \
  ((operand->flags & ARC_OPERAND_FAKE)              \
   && !((operand->flags & ARC_OPERAND_BRAKET)	    \
	|| (operand->flags & ARC_OPERAND_COLON)))

/* The flags structure.  */
struct arc_flag_operand
{
  /* The flag name.  */
  const char * name;

  /* The flag code.  */
  unsigned code;

  /* The number of bits in the operand.  */
  unsigned int bits;

  /* How far the operand is left shifted in the instruction.  */
  unsigned int shift;

  /* Available for disassembler.  */
  unsigned char favail;
};

/* The flag operands table.  */
extern const struct arc_flag_operand arc_flag_operands[];
extern const unsigned arc_num_flag_operands;

/* The flag's class structure.  */
struct arc_flag_class
{
  /* Flag class.  */
  flag_class_t flag_class;

  /* List of valid flags (codes).  */
  unsigned flags[256];
};

extern const struct arc_flag_class arc_flag_classes[];

/* Structure for special cases.  */
struct arc_flag_special
{
  /* Name of special case instruction.  */
  const char *name;

  /* List of flags applicable for special case instruction.  */
  unsigned flags[32];
};

extern const struct arc_flag_special arc_flag_special_cases[];
extern const unsigned arc_num_flag_special;

/* Relocation equivalence structure.  */
struct arc_reloc_equiv_tab
{
  const char * name;	   /* String to lookup.  */
  const char * mnemonic;   /* Extra matching condition.  */
  unsigned     flags[32];  /* Extra matching condition.  */
  signed int   oldreloc;   /* Old relocation.  */
  signed int   newreloc;   /* New relocation.  */
};

extern const struct arc_reloc_equiv_tab arc_reloc_equiv[];
extern const unsigned arc_num_equiv_tab;

/* Structure for operand operations for pseudo/alias instructions.  */
struct arc_operand_operation
{
  /* The index for operand from operand array.  */
  unsigned operand_idx;

  /* Defines if it needs the operand inserted by the assembler or
     whether this operand comes from the pseudo instruction's
     operands.  */
  unsigned char needs_insert;

  /* Count we have to add to the operand.  Use negative number to
     subtract from the operand.  Also use this number to add to 0 if
     the operand needs to be inserted (i.e. needs_insert == 1).  */
  int count;

  /* Index of the operand to swap with.  To be done AFTER applying
     inc_count.  */
  unsigned swap_operand_idx;
};

/* Structure for pseudo/alias instructions.  */
struct arc_pseudo_insn
{
  /* Mnemonic for pseudo/alias insn.  */
  const char * mnemonic_p;

  /* Mnemonic for real instruction.  */
  const char * mnemonic_r;

  /* Flag that will have to be added (if any).  */
  const char * flag_r;

  /* Amount of operands.  */
  unsigned operand_cnt;

  /* Array of operand operations.  */
  struct arc_operand_operation operand[6];
};

extern const struct arc_pseudo_insn arc_pseudo_insns[];
extern const unsigned arc_num_pseudo_insn;

/* Structure for AUXILIARY registers.  */
struct arc_aux_reg
{
  /* Register address.  */
  int address;

  /* One bit flags for the opcode.  These are primarily used to
     indicate specific processors and environments support the
     instructions.  */
  unsigned cpu;

  /* AUX register subclass.  */
  insn_subclass_t subclass;

  /* Register name.  */
  const char * name;

  /* Size of the string.  */
  size_t length;
};

extern const struct arc_aux_reg arc_aux_regs[];
extern const unsigned arc_num_aux_regs;

extern const struct arc_opcode arc_relax_opcodes[];
extern const unsigned arc_num_relax_opcodes;

/* Macro used for generating one class of NPS instructions.  */
#define NPS_CMEM_HIGH_VALUE 0x57f0

/* Macros to help generating regular pattern instructions.  */
#define FIELDA(word) (word & 0x3F)
#define FIELDB(word) (((word & 0x07) << 24) | (((word >> 3) & 0x07) << 12))
#define FIELDC(word) ((word & 0x3F) << 6)
#define FIELDF	     (0x01 << 15)
#define FIELDQ	     (0x1F)

#define INSN3OP(MOP,SOP)	(((MOP & 0x1F) << 27) | ((SOP & 0x3F) << 16))
#define INSN2OPX(MOP,SOP1,SOP2) (INSN3OP (MOP,SOP1) | (SOP2 & 0x3F))
#define INSN2OP(MOP,SOP)	(INSN2OPX (MOP,0x2F,SOP))

#define INSN3OP_ABC(MOP,SOP)  (INSN3OP (MOP,SOP))
#define INSN3OP_ALC(MOP,SOP)  (INSN3OP (MOP,SOP) | FIELDB (62))
#define INSN3OP_ABL(MOP,SOP)  (INSN3OP (MOP,SOP) | FIELDC (62))
#define INSN3OP_ALL(MOP,SOP)  (INSN3OP (MOP,SOP) | FIELDB (62) | FIELDC (62))
#define INSN3OP_0BC(MOP,SOP)  (INSN3OP (MOP,SOP) | FIELDA (62))
#define INSN3OP_0LC(MOP,SOP)  (INSN3OP (MOP,SOP) | FIELDA (62) | FIELDB (62))
#define INSN3OP_0BL(MOP,SOP)  (INSN3OP (MOP,SOP) | FIELDA (62) | FIELDC (62))
#define INSN3OP_0LL(MOP,SOP)					\
  (INSN3OP (MOP,SOP) | FIELDA (62) | FIELDB (62) | FIELDC (62))
#define INSN3OP_ABU(MOP,SOP)  (INSN3OP (MOP,SOP) | (0x01 << 22))
#define INSN3OP_ALU(MOP,SOP)  (INSN3OP (MOP,SOP) | (0x01 << 22) | FIELDB (62))
#define INSN3OP_0BU(MOP,SOP)  (INSN3OP (MOP,SOP) | FIELDA (62) | (0x01 << 22))
#define INSN3OP_0LU(MOP,SOP)					\
  (INSN3OP (MOP,SOP) | FIELDA (62) | (0x01 << 22) | FIELDB (62))
#define INSN3OP_BBS(MOP,SOP)  (INSN3OP (MOP,SOP) | (0x02 << 22))
#define INSN3OP_0LS(MOP,SOP)  (INSN3OP (MOP,SOP) | (0x02 << 22) | FIELDB (62))
#define INSN3OP_CBBC(MOP,SOP) (INSN3OP (MOP,SOP) | (0x03 << 22))
#define INSN3OP_CBBL(MOP,SOP) (INSN3OP (MOP,SOP) | (0x03 << 22) | FIELDC (62))
#define INSN3OP_C0LC(MOP,SOP) (INSN3OP (MOP,SOP) | (0x03 << 22) | FIELDB (62))
#define INSN3OP_C0LL(MOP,SOP)					\
  (INSN3OP (MOP,SOP) | (0x03 << 22) | FIELDC (62) | FIELDB (62))
#define INSN3OP_CBBU(MOP,SOP) (INSN3OP (MOP,SOP) | (0x03 << 22) | (0x01 << 5))
#define INSN3OP_C0LU(MOP,SOP)					\
  (INSN3OP (MOP,SOP) | (0x03 << 22) | (0x01 << 5) | FIELDB (62))

#define MASK_32BIT(VAL) (0xffffffff & (VAL))

#define MINSN3OP_ABC  (MASK_32BIT (~(FIELDF | FIELDA (63) | FIELDB (63) | FIELDC (63))))
#define MINSN3OP_ALC  (MASK_32BIT (~(FIELDF | FIELDA (63) | FIELDC (63))))
#define MINSN3OP_ABL  (MASK_32BIT (~(FIELDF | FIELDA (63) | FIELDB (63))))
#define MINSN3OP_ALL  (MASK_32BIT (~(FIELDF | FIELDA (63))))
#define MINSN3OP_0BC  (MASK_32BIT (~(FIELDF | FIELDB (63) | FIELDC (63))))
#define MINSN3OP_0LC  (MASK_32BIT (~(FIELDF | FIELDC (63))))
#define MINSN3OP_0BL  (MASK_32BIT (~(FIELDF | FIELDB (63))))
#define MINSN3OP_0LL  (MASK_32BIT (~(FIELDF)))
#define MINSN3OP_ABU  (MASK_32BIT (~(FIELDF | FIELDA (63) | FIELDB (63) | FIELDC (63))))
#define MINSN3OP_ALU  (MASK_32BIT (~(FIELDF | FIELDA (63) | FIELDC (63))))
#define MINSN3OP_0BU  (MASK_32BIT (~(FIELDF | FIELDB (63) | FIELDC (63))))
#define MINSN3OP_0LU  (MASK_32BIT (~(FIELDF | FIELDC (63))))
#define MINSN3OP_BBS  (MASK_32BIT (~(FIELDF | FIELDA (63) | FIELDB (63) | FIELDC (63))))
#define MINSN3OP_0LS  (MASK_32BIT (~(FIELDF | FIELDA (63) | FIELDC (63))))
#define MINSN3OP_CBBC (MASK_32BIT (~(FIELDF | FIELDQ | FIELDB (63) | FIELDC (63))))
#define MINSN3OP_CBBL (MASK_32BIT (~(FIELDF | FIELDQ | FIELDB (63))))
#define MINSN3OP_C0LC (MASK_32BIT (~(FIELDF | FIELDQ | FIELDC (63))))
#define MINSN3OP_C0LL (MASK_32BIT (~(FIELDF | FIELDQ)))
#define MINSN3OP_CBBU (MASK_32BIT (~(FIELDF | FIELDQ | FIELDB (63) | FIELDC (63))))
#define MINSN3OP_C0LU (MASK_32BIT (~(FIELDF | FIELDQ | FIELDC (63))))

#define INSN2OP_BC(MOP,SOP) (INSN2OP (MOP,SOP))
#define INSN2OP_BL(MOP,SOP) (INSN2OP (MOP,SOP) | FIELDC (62))
#define INSN2OP_0C(MOP,SOP) (INSN2OP (MOP,SOP) | FIELDB (62))
#define INSN2OP_0L(MOP,SOP) (INSN2OP (MOP,SOP) | FIELDB (62)  | FIELDC (62))
#define INSN2OP_BU(MOP,SOP) (INSN2OP (MOP,SOP) | (0x01 << 22))
#define INSN2OP_0U(MOP,SOP) (INSN2OP (MOP,SOP) | (0x01 << 22) | FIELDB (62))

#define MINSN2OP_BC  (MASK_32BIT ((~(FIELDF | FIELDB (63) | FIELDC (63)))))
#define MINSN2OP_BL  (MASK_32BIT ((~(FIELDF | FIELDB (63)))))
#define MINSN2OP_0C  (MASK_32BIT ((~(FIELDF | FIELDC (63)))))
#define MINSN2OP_0L  (MASK_32BIT ((~(FIELDF))))
#define MINSN2OP_BU  (MASK_32BIT ((~(FIELDF | FIELDB (63) | FIELDC (63)))))
#define MINSN2OP_0U  (MASK_32BIT ((~(FIELDF | FIELDC (63)))))

/* Various constants used when defining an extension instruction.  */
#define ARC_SYNTAX_3OP		(1 << 0)
#define ARC_SYNTAX_2OP		(1 << 1)
#define ARC_SYNTAX_1OP		(1 << 2)
#define ARC_SYNTAX_NOP		(1 << 3)
#define ARC_SYNTAX_MASK		(0x0F)

#define ARC_OP1_MUST_BE_IMM	(1 << 0)
#define ARC_OP1_IMM_IMPLIED	(1 << 1)

#define ARC_SUFFIX_NONE		(1 << 0)
#define ARC_SUFFIX_COND		(1 << 1)
#define ARC_SUFFIX_FLAG		(1 << 2)

#define ARC_REGISTER_READONLY    (1 << 0)
#define ARC_REGISTER_WRITEONLY   (1 << 1)
#define ARC_REGISTER_NOSHORT_CUT (1 << 2)

/* Constants needed to initialize extension instructions.  */
extern const unsigned char flags_none[MAX_INSN_FLGS + 1];
extern const unsigned char flags_f[MAX_INSN_FLGS + 1];
extern const unsigned char flags_cc[MAX_INSN_FLGS + 1];
extern const unsigned char flags_ccf[MAX_INSN_FLGS + 1];

extern const unsigned char arg_none[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_rarbrc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zarbrc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_rbrbrc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_rarbu6[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zarbu6[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_rbrbu6[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_rbrbs12[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_ralimmrc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_rarblimm[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zalimmrc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zarblimm[MAX_INSN_ARGS + 1];

extern const unsigned char arg_32bit_rbrblimm[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_ralimmu6[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zalimmu6[MAX_INSN_ARGS + 1];

extern const unsigned char arg_32bit_zalimms12[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_ralimmlimm[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zalimmlimm[MAX_INSN_ARGS + 1];

extern const unsigned char arg_32bit_rbrc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zarc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_rbu6[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zau6[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_rblimm[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_zalimm[MAX_INSN_ARGS + 1];

extern const unsigned char arg_32bit_limmrc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_limmu6[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_limms12[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_limmlimm[MAX_INSN_ARGS + 1];

extern const unsigned char arg_32bit_rc[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_u6[MAX_INSN_ARGS + 1];
extern const unsigned char arg_32bit_limm[MAX_INSN_ARGS + 1];

/* Address types used in the NPS-400. See page 367 of the NPS-400 CTOP
   Instruction Set Reference Manual v2.4 for a description of address types.  */

typedef enum
{
  /* Addresses in memory.  */

  /* Buffer descriptor.  */
  ARC_NPS400_ADDRTYPE_BD,

  /* Job identifier.  */
  ARC_NPS400_ADDRTYPE_JID,

  /* Linked Buffer Descriptor.  */
  ARC_NPS400_ADDRTYPE_LBD,

  /* Multicast Buffer Descriptor.  */
  ARC_NPS400_ADDRTYPE_MBD,

  /* Summarized Address.  */
  ARC_NPS400_ADDRTYPE_SD,

  /* SMEM Security Context Local Memory.  */
  ARC_NPS400_ADDRTYPE_SM,

  /* Extended Address.  */
  ARC_NPS400_ADDRTYPE_XA,

  /* Extended Summarized Address.  */
  ARC_NPS400_ADDRTYPE_XD,

  /* CMEM offset addresses.  */

  /* On-demand Counter Descriptor.  */
  ARC_NPS400_ADDRTYPE_CD,

  /* CMEM Buffer Descriptor.  */
  ARC_NPS400_ADDRTYPE_CBD,

  /* CMEM Job Identifier.  */
  ARC_NPS400_ADDRTYPE_CJID,

  /* CMEM Linked Buffer Descriptor.  */
  ARC_NPS400_ADDRTYPE_CLBD,

  /* CMEM Offset.  */
  ARC_NPS400_ADDRTYPE_CM,

  /* CMEM Summarized Address.  */
  ARC_NPS400_ADDRTYPE_CSD,

  /* CMEM Extended Address.  */
  ARC_NPS400_ADDRTYPE_CXA,

  /* CMEM Extended Summarized Address.  */
  ARC_NPS400_ADDRTYPE_CXD

} arc_nps_address_type;

#define ARC_NUM_ADDRTYPES 16

#ifdef __cplusplus
}
#endif

#endif /* OPCODE_ARC_H */
