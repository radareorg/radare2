/* NDS32-specific support for 32-bit ELF.
   Copyright (C) 2012-2013 Free Software Foundation, Inc.
   Contributed by Andes Technology Corporation.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.*/


#ifndef NDS32_ASM_H
#define NDS32_ASM_H

/* Constant values for assembler.  */
enum
{
  /* Error code for assembling an instruction.  */
  NASM_OK = 0,
  NASM_ERR_UNKNOWN_OP,
  NASM_ERR_SYNTAX,
  NASM_ERR_OPERAND,
  NASM_ERR_OUT_OF_RANGE,
  NASM_ERR_REG_REDUCED,
  NASM_ERR_JUNK_EOL,

  /* Results of parse_operand.  */
  NASM_R_CONST,
  NASM_R_SYMBOL,
  NASM_R_ILLEGAL,

  /* Flags for open description.  */
  NASM_OPEN_ARCH_V1		= 0x0,
  NASM_OPEN_ARCH_V2		= 0x1,
  NASM_OPEN_ARCH_V3		= 0x2,
  NASM_OPEN_ARCH_V3M		= 0x3,
  NASM_OPEN_ARCH_MASK		= 0xf,
  NASM_OPEN_REDUCED_REG		= 0x10,

  /* Common attributes.  */
  NASM_ATTR_ISA_V1		= 0x01,
  NASM_ATTR_ISA_V2		= 0x02,
  NASM_ATTR_ISA_V3		= 0x04,
  NASM_ATTR_ISA_V3M		= 0x08,
  NASM_ATTR_ISA_ALL		= 0x0f,

  /* Attributes for instructions.  */
  NASM_ATTR_MAC			= 0x0000100,
  NASM_ATTR_DIV			= 0x0000200,
  NASM_ATTR_FPU			= 0x0000400,
  NASM_ATTR_FPU_SP_EXT		= 0x0000800,
  NASM_ATTR_FPU_DP_EXT		= 0x0001000,
  NASM_ATTR_STR_EXT		= 0x0002000,
  NASM_ATTR_PERF_EXT		= 0x0004000,
  NASM_ATTR_PERF2_EXT		= 0x0008000,
  NASM_ATTR_AUDIO_ISAEXT	= 0x0010000,
  NASM_ATTR_IFC_EXT		= 0x0020000,
  NASM_ATTR_EX9_EXT		= 0x0040000,
  NASM_ATTR_FPU_FMA		= 0x0080000,
  NASM_ATTR_DXREG		= 0x0100000,
  NASM_ATTR_BRANCH		= 0x0200000,
  NASM_ATTR_RELAXABLE		= 0x0400000,
  NASM_ATTR_PCREL		= 0x0800000,
  NASM_ATTR_GPREL		= 0x1000000,

  /* Attributes for relocations.  */
  NASM_ATTR_HI20		= 0x10000000,
  NASM_ATTR_LO12		= 0x20000000,
  NASM_ATTR_LO20		= 0x40000000,

  /* Attributes for registers.  */
  NASM_ATTR_RDREG		= 0x000100
};

/* Macro for instruction attribute.  */
#define ATTR(attr)		NASM_ATTR_ ## attr
#define ATTR_NONE		0
#define ATTR_PCREL		(ATTR (PCREL) | ATTR (BRANCH))

#define ATTR_ALL		(ATTR (ISA_ALL))
#define ATTR_V2UP		(ATTR_ALL & ~(ATTR (ISA_V1)))
#define ATTR_V3MUP		(ATTR (ISA_V3) | ATTR (ISA_V3M))
#define ATTR_V3			(ATTR (ISA_V3))
#define ATTR_V3MEX_V1		(ATTR_ALL & ~(ATTR (ISA_V3M)))
#define ATTR_V3MEX_V2		(ATTR_V2UP & ~(ATTR (ISA_V3M)))

/* Lexical element in parsed syntax.  */
typedef int lex_t;

/* Common header for hash entries.  */
struct nds32_hash_entry
{
  const char *name;
};

typedef struct nds32_keyword
{
  const char *name;
  int value;
  uint64_t attr;
} keyword_t;

typedef struct nds32_opcode
{
  /* Opcode for the instruction.  */
  const char *opcode;
  /* Human readable string of this instruction.  */
  const char *instruction;
  /* Base value of this instruction.  */
  uint32_t value;
  /* The byte-size of the instruction.  */
  int isize;
  /* Attributes of this instruction.  */
  uint64_t attr;
  /* Implicit define/use.  */
  uint64_t defuse;
  /* Parsed string for assembling.  */
  lex_t *syntax;
  /* Number of variant.  */
  int variant;
  /* Next form of the same mnemonic.  */
  struct nds32_opcode *next;
  /* TODO: Extra constrains and verification.
	   For example, `mov55 $sp, $sp' is not allowed in v3.  */
} opcode_t;

typedef struct nds32_asm_insn
{
  /* Assembled instruction bytes.  */
  uint32_t insn;
  /* The opcode structure for this instruction.  */
  struct nds32_opcode *opcode;
  /* The field need special fix-up, used for relocation.  */
  const struct nds32_field *field;
  /* Attributes for relocation.  */
  uint64_t attr;
  /* Application-dependent data, e.g., expression.  */
  void *info;
  /* Input/output registers.  */
  uint64_t defuse;
} nds32_asm_insn_t;

typedef struct nds32_asm_desc
{
  /* The callback provided by assembler user for parse an operand,
     e.g., parse integer.  */
  int (*parse_operand) (struct nds32_asm_desc *,
			struct nds32_asm_insn *,
			char **, int64_t *);

  /* Result of assembling.  */
  int result;

  /* The mach for this assembling.  */
  int mach;

  int flags;
} nds32_asm_desc_t;

/* The field information for an operand.  */
typedef struct nds32_field
{
  /* Name of the field.  */
  const char *name;

  int bitpos;
  int bitsize;
  int shift;
  int hw_res;

  int (*parse) (struct nds32_asm_desc *,
		struct nds32_asm_insn *,
		char **, int64_t *);
} field_t;

extern void nds32_assemble (nds32_asm_desc_t *, nds32_asm_insn_t *, char *);
extern void nds32_asm_init (nds32_asm_desc_t *, int);

#endif
