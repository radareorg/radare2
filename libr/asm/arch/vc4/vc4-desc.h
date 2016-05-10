/* CPU data header for vc4.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright 1996-2010 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#ifndef VC4_CPU_H
#define VC4_CPU_H

#define CGEN_ARCH vc4

/* Given symbol S, return vc4_cgen_<S>.  */
#define CGEN_SYM(s) vc4##_cgen_##s


/* Selected cpu families.  */
#define HAVE_CPU_VIDEOCORE4

#define CGEN_INSN_LSB0_P 1

/* Minimum size of any insn (in bytes).  */
#define CGEN_MIN_INSN_SIZE 2

/* Maximum size of any insn (in bytes).  */
#define CGEN_MAX_INSN_SIZE 10

#define CGEN_MAX_EXTRA_OPCODE_OPERANDS 2

#define CGEN_INT_INSN_P 0

/* Maximum number of syntax elements in an instruction.  */
#define CGEN_ACTUAL_MAX_SYNTAX_ELEMENTS 20

/* CGEN_MNEMONIC_OPERANDS is defined if mnemonics have operands.
   e.g. In "b,a foo" the ",a" is an operand.  If mnemonics have operands
   we can't hash on everything up to the space.  */
#define CGEN_MNEMONIC_OPERANDS

/* Maximum number of fields in an instruction.  */
#define CGEN_ACTUAL_MAX_IFMT_OPERANDS 9

/* Enums.  */

/* Enum declaration for length field.  */
typedef enum insn_oplen {
  OPLEN_0, OPLEN_1, OPLEN_2, OPLEN_3
 , OPLEN_4, OPLEN_5, OPLEN_6, OPLEN_7
 , OPLEN_8, OPLEN_9, OPLEN_10, OPLEN_11
 , OPLEN_12, OPLEN_13, OPLEN_14, OPLEN_15
} INSN_OPLEN;

/* Enum declaration for insn bits 15-13.  */
typedef enum insn_op15_13 {
  OP15_13_0, OP15_13_1, OP15_13_2, OP15_13_3
 , OP15_13_4, OP15_13_5, OP15_13_6, OP15_13_7
} INSN_OP15_13;

/* Enum declaration for insn float ops.  */
typedef enum insn_floatops {
  ALUFOP_FADD, ALUFOP_FSUB, ALUFOP_FMUL, ALUFOP_FDIV
 , ALUFOP_FCMP, ALUFOP_FABS, ALUFOP_FRSB, ALUFOP_FMAX
 , ALUFOP_FRCP, ALUFOP_FRSQRT, ALUFOP_FNMUL, ALUFOP_FMIN
 , ALUFOP_FCEIL, ALUFOP_FFLOOR, ALUFOP_FLOG2, ALUFOP_FEXP2
} INSN_FLOATOPS;

/* Enum declaration for insn alu16 ops.  */
typedef enum insn_alu16op {
  ALU16OP_MOV, ALU16OP_CMN, ALU16OP_ADD, ALU16OP_BIC
 , ALU16OP_MUL, ALU16OP_EOR, ALU16OP_SUB, ALU16OP_AND
 , ALU16OP_NOT, ALU16OP_ROR, ALU16OP_CMP, ALU16OP_RSUB
 , ALU16OP_BTST, ALU16OP_OR, ALU16OP_BMASK, ALU16OP_MAX
 , ALU16OP_BSET, ALU16OP_MIN, ALU16OP_BCLR, ALU16OP_ADDS2
 , ALU16OP_BCHG, ALU16OP_ADDS4, ALU16OP_ADDS8, ALU16OP_ADDS16
 , ALU16OP_SIGNEXT, ALU16OP_NEG, ALU16OP_LSR, ALU16OP_MSB
 , ALU16OP_SHL, ALU16OP_BITREV, ALU16OP_ASR, ALU16OP_ABS
} INSN_ALU16OP;

/* Enum declaration for insn alu16 imm ops.  */
typedef enum insn_alu16opi {
  ALU16OPI_MOV, ALU16OPI_ADD, ALU16OPI_MUL, ALU16OPI_SUB
 , ALU16OPI_NOT, ALU16OPI_CMP, ALU16OPI_BTST, ALU16OPI_BMASK
 , ALU16OPI_BSET, ALU16OPI_BCLR, ALU16OPI_BCHG, ALU16OPI_ADDS8
 , ALU16OPI_SIGNEXT, ALU16OPI_LSR, ALU16OPI_SHL, ALU16OPI_ASR
} INSN_ALU16OPI;

/* Enum declaration for insn alu32 ops.  */
typedef enum insn_alu32op {
  ALU32OP_MOV, ALU32OP_CMN, ALU32OP_ADD, ALU32OP_BIC
 , ALU32OP_MUL, ALU32OP_EOR, ALU32OP_SUB, ALU32OP_AND
 , ALU32OP_NOT, ALU32OP_ROR, ALU32OP_CMP, ALU32OP_RSUB
 , ALU32OP_BTST, ALU32OP_OR, ALU32OP_BMASK, ALU32OP_MAX
 , ALU32OP_BSET, ALU32OP_MIN, ALU32OP_BCLR, ALU32OP_ADDS2
 , ALU32OP_BCHG, ALU32OP_ADDS4, ALU32OP_ADDS8, ALU32OP_ADDS16
 , ALU32OP_SIGNEXT, ALU32OP_NEG, ALU32OP_LSR, ALU32OP_MSB
 , ALU32OP_SHL, ALU32OP_BITREV, ALU32OP_ASR, ALU32OP_ABS
} INSN_ALU32OP;

/* Enum declaration for insn bits 11-8.  */
typedef enum insn_op11_8 {
  OP11_8_0, OP11_8_1, OP11_8_2, OP11_8_3
 , OP11_8_4, OP11_8_5, OP11_8_6, OP11_8_7
 , OP11_8_8, OP11_8_9, OP11_8_10, OP11_8_11
 , OP11_8_12, OP11_8_13, OP11_8_14, OP11_8_15
} INSN_OP11_8;

/* Enum declaration for insn bits 11-10.  */
typedef enum insn_op11_10 {
  OP11_10_0, OP11_10_1, OP11_10_2, OP11_10_3
} INSN_OP11_10;

/* Enum declaration for insn bit 11.  */
typedef enum insn_op11 {
  OP11_0, OP11_1
} INSN_OP11;

/* Enum declaration for insn bit 8.  */
typedef enum insn_op8 {
  OP8_0, OP8_1
} INSN_OP8;

/* Enum declaration for insn bits 7-6.  */
typedef enum insn_op7_6 {
  OP7_6_0, OP7_6_1, OP7_6_2, OP7_6_3
} INSN_OP7_6;

/* Enum declaration for access sizes.  */
typedef enum accsz_op7_6 {
  ACCSZ7_6_, ACCSZ7_6_H, ACCSZ7_6_B, ACCSZ7_6_SH
} ACCSZ_OP7_6;

/* Enum declaration for insn bits 7-5.  */
typedef enum insn_op7_5 {
  OP7_5_0, OP7_5_1, OP7_5_2, OP7_5_3
 , OP7_5_4, OP7_5_5, OP7_5_6, OP7_5_7
} INSN_OP7_5;

/* Enum declaration for insn bits 7-4.  */
typedef enum insn_op7_4 {
  OP7_4_0, OP7_4_1, OP7_4_2, OP7_4_3
 , OP7_4_4, OP7_4_5, OP7_4_6, OP7_4_7
 , OP7_4_8, OP7_4_9, OP7_4_10, OP7_4_11
 , OP7_4_12, OP7_4_13, OP7_4_14, OP7_4_15
} INSN_OP7_4;

/* Enum declaration for insn bit 7.  */
typedef enum insn_op7 {
  OP7_0, OP7_1
} INSN_OP7;

/* Enum declaration for insn bits 6-5.  */
typedef enum insn_op6_5 {
  OP6_5_0, OP6_5_6, OP6_5_16, OP6_5_24
} INSN_OP6_5;

/* Enum declaration for insn bits 4-0.  */
typedef enum insn_op4_0 {
  OP4_0_0, OP4_0_1, OP4_0_2, OP4_0_3
 , OP4_0_4, OP4_0_5, OP4_0_6, OP4_0_7
 , OP4_0_8, OP4_0_9, OP4_0_10, OP4_0_11
 , OP4_0_12, OP4_0_13, OP4_0_14, OP4_0_15
 , OP4_0_16, OP4_0_17, OP4_0_18, OP4_0_19
 , OP4_0_20, OP4_0_21, OP4_0_22, OP4_0_23
 , OP4_0_24, OP4_0_25, OP4_0_26, OP4_0_27
 , OP4_0_28, OP4_0_29, OP4_0_30, OP4_0_31
} INSN_OP4_0;

/* Enum declaration for insn bit 4.  */
typedef enum insn_op4 {
  OP4_0, OP4_1
} INSN_OP4;

/* Enum declaration for insn bits 3-0.  */
typedef enum insn_op3_0 {
  OP3_0_0, OP3_0_1, OP3_0_2, OP3_0_3
 , OP3_0_4, OP3_0_5, OP3_0_6, OP3_0_7
 , OP3_0_8, OP3_0_9, OP3_0_10, OP3_0_11
 , OP3_0_12, OP3_0_13, OP3_0_14, OP3_0_15
} INSN_OP3_0;

/* Enum declaration for insn bits 31-30.  */
typedef enum insn_op31_30 {
  OP31_30_0, OP31_30_1, OP31_30_2, OP31_30_3
} INSN_OP31_30;

/* Enum declaration for insn bits 22-21.  */
typedef enum insn_op22_21 {
  OP22_21_0, OP22_21_1, OP22_21_2, OP22_21_3
} INSN_OP22_21;

/* Attributes.  */

/* Enum declaration for machine type selection.  */
typedef enum mach_attr {
  MACH_BASE, MACH_VC4, MACH_MAX
} MACH_ATTR;

/* Enum declaration for instruction set selection.  */
typedef enum isa_attr {
  ISA_VC4, ISA_MAX
} ISA_ATTR;

/* Number of architecture variants.  */
#define MAX_ISAS  1
#define MAX_MACHS ((int) MACH_MAX)

/* Ifield support.  */

/* Ifield attribute indices.  */

/* Enum declaration for cgen_ifld attrs.  */
typedef enum cgen_ifld_attr {
  CGEN_IFLD_VIRTUAL, CGEN_IFLD_PCREL_ADDR, CGEN_IFLD_ABS_ADDR, CGEN_IFLD_RESERVED
 , CGEN_IFLD_SIGN_OPT, CGEN_IFLD_SIGNED, CGEN_IFLD_END_BOOLS, CGEN_IFLD_START_NBOOLS = 31
 , CGEN_IFLD_MACH, CGEN_IFLD_END_NBOOLS
} CGEN_IFLD_ATTR;

/* Number of non-boolean elements in cgen_ifld_attr.  */
#define CGEN_IFLD_NBOOL_ATTRS (CGEN_IFLD_END_NBOOLS - CGEN_IFLD_START_NBOOLS - 1)

/* cgen_ifld attribute accessor macros.  */
#define CGEN_ATTR_CGEN_IFLD_MACH_VALUE(attrs) ((attrs)->nonbool[CGEN_IFLD_MACH-CGEN_IFLD_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_IFLD_VIRTUAL_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_IFLD_VIRTUAL)) != 0)
#define CGEN_ATTR_CGEN_IFLD_PCREL_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_IFLD_PCREL_ADDR)) != 0)
#define CGEN_ATTR_CGEN_IFLD_ABS_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_IFLD_ABS_ADDR)) != 0)
#define CGEN_ATTR_CGEN_IFLD_RESERVED_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_IFLD_RESERVED)) != 0)
#define CGEN_ATTR_CGEN_IFLD_SIGN_OPT_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_IFLD_SIGN_OPT)) != 0)
#define CGEN_ATTR_CGEN_IFLD_SIGNED_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_IFLD_SIGNED)) != 0)

/* Enum declaration for vc4 ifield types.  */
typedef enum ifield_type {
  VC4_F_NIL, VC4_F_ANYOF, VC4_F_OPLEN, VC4_F_OP15_13
 , VC4_F_OP15_11, VC4_F_OP11_8, VC4_F_LDSTOFF, VC4_F_OP11_9
 , VC4_F_OP11_10, VC4_F_OP11, VC4_F_OP10_9, VC4_F_OP10_7
 , VC4_F_ADDSPOFFSET, VC4_F_OP10_0, VC4_F_ALU16OP, VC4_F_ALU16OPI
 , VC4_F_OP9_8, VC4_F_OP9_5, VC4_F_SPOFFSET, VC4_F_OP8_5
 , VC4_F_OP8_4, VC4_F_OP8_4_SHL3, VC4_F_OP8, VC4_F_OP7_4
 , VC4_F_OP7_4S, VC4_F_OP7_5, VC4_F_OP7_6, VC4_F_OP7
 , VC4_F_OP6_5, VC4_F_OP6_0, VC4_F_PCRELCC, VC4_F_OP5
 , VC4_F_OP5_0, VC4_F_OP4, VC4_F_OP4_0, VC4_F_OP3_0
 , VC4_F_OP4_0_BASE_0, VC4_F_OP4_0_BASE_6, VC4_F_OP4_0_BASE_16, VC4_F_OP4_0_BASE_24
 , VC4_F_OP31_30, VC4_F_OP31_27, VC4_F_OP31_16, VC4_F_OP31_16S
 , VC4_F_OP31_16S_SHL1, VC4_F_OP31_16S_SHL2, VC4_F_OP31_16S_SHL3, VC4_F_OP31_16S_SHL4
 , VC4_F_PCREL16, VC4_F_OP29_26, VC4_F_OP29_24, VC4_F_OP26_23
 , VC4_F_OP26_16, VC4_F_PCREL10, VC4_F_PCREL8, VC4_F_OP22_21
 , VC4_F_OP22, VC4_F_OP21_16, VC4_F_OP21_16S, VC4_F_OP21_16S_SHL1
 , VC4_F_OP21_16S_SHL2, VC4_F_OP21_16S_SHL3, VC4_F_OP21_16S_SHL4, VC4_F_OP21_16S_SHL5
 , VC4_F_OP21_16S_SHL6, VC4_F_OP21_16S_SHL7, VC4_F_OP21_16S_SHL8, VC4_F_OP20_16
 , VC4_F_OP47_16, VC4_F_PCREL32_48, VC4_F_OP47_43, VC4_F_OFFSET27_48
 , VC4_F_PCREL27_48, VC4_F_OP79_48, VC4_F_OFFSET23BITS, VC4_F_OFFSET27BITS
 , VC4_F_OFFSET12, VC4_F_MAX
} IFIELD_TYPE;

#define MAX_IFLD ((int) VC4_F_MAX)

/* Hardware attribute indices.  */

/* Enum declaration for cgen_hw attrs.  */
typedef enum cgen_hw_attr {
  CGEN_HW_VIRTUAL, CGEN_HW_CACHE_ADDR, CGEN_HW_PC, CGEN_HW_PROFILE
 , CGEN_HW_END_BOOLS, CGEN_HW_START_NBOOLS = 31, CGEN_HW_MACH, CGEN_HW_END_NBOOLS
} CGEN_HW_ATTR;

/* Number of non-boolean elements in cgen_hw_attr.  */
#define CGEN_HW_NBOOL_ATTRS (CGEN_HW_END_NBOOLS - CGEN_HW_START_NBOOLS - 1)

/* cgen_hw attribute accessor macros.  */
#define CGEN_ATTR_CGEN_HW_MACH_VALUE(attrs) ((attrs)->nonbool[CGEN_HW_MACH-CGEN_HW_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_HW_VIRTUAL_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_VIRTUAL)) != 0)
#define CGEN_ATTR_CGEN_HW_CACHE_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_CACHE_ADDR)) != 0)
#define CGEN_ATTR_CGEN_HW_PC_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_PC)) != 0)
#define CGEN_ATTR_CGEN_HW_PROFILE_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_HW_PROFILE)) != 0)

/* Enum declaration for vc4 hardware types.  */
typedef enum cgen_hw_type {
  HW_H_MEMORY, HW_H_SINT, HW_H_UINT, HW_H_ADDR
 , HW_H_IADDR, HW_H_REG, HW_H_FASTREG, HW_H_PPREG
 , HW_H_BASEREG, HW_H_COND, HW_H_ACCSZ, HW_H_PC
 , HW_MAX
} CGEN_HW_TYPE;

#define MAX_HW ((int) HW_MAX)

/* Operand attribute indices.  */

/* Enum declaration for cgen_operand attrs.  */
typedef enum cgen_operand_attr {
  CGEN_OPERAND_VIRTUAL, CGEN_OPERAND_PCREL_ADDR, CGEN_OPERAND_ABS_ADDR, CGEN_OPERAND_SIGN_OPT
 , CGEN_OPERAND_SIGNED, CGEN_OPERAND_NEGATIVE, CGEN_OPERAND_RELAX, CGEN_OPERAND_SEM_ONLY
 , CGEN_OPERAND_END_BOOLS, CGEN_OPERAND_START_NBOOLS = 31, CGEN_OPERAND_MACH, CGEN_OPERAND_END_NBOOLS
} CGEN_OPERAND_ATTR;

/* Number of non-boolean elements in cgen_operand_attr.  */
#define CGEN_OPERAND_NBOOL_ATTRS (CGEN_OPERAND_END_NBOOLS - CGEN_OPERAND_START_NBOOLS - 1)

/* cgen_operand attribute accessor macros.  */
#define CGEN_ATTR_CGEN_OPERAND_MACH_VALUE(attrs) ((attrs)->nonbool[CGEN_OPERAND_MACH-CGEN_OPERAND_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_OPERAND_VIRTUAL_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_VIRTUAL)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_PCREL_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_PCREL_ADDR)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_ABS_ADDR_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_ABS_ADDR)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SIGN_OPT_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SIGN_OPT)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SIGNED_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SIGNED)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_NEGATIVE_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_NEGATIVE)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_RELAX_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_RELAX)) != 0)
#define CGEN_ATTR_CGEN_OPERAND_SEM_ONLY_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_OPERAND_SEM_ONLY)) != 0)

/* Enum declaration for vc4 operand types.  */
typedef enum cgen_operand_type {
  VC4_OPERAND_PC, VC4_OPERAND_CONDCODE, VC4_OPERAND_PCRELCC, VC4_OPERAND_LDSTOFF
 , VC4_OPERAND_ALU16SREG, VC4_OPERAND_ALU16IMM, VC4_OPERAND_ALU16IMM_SHL3, VC4_OPERAND_ALU16DREG
 , VC4_OPERAND_ALU32DREG, VC4_OPERAND_IMM6, VC4_OPERAND_FLOATIMM6, VC4_OPERAND_IMM6_SHL1
 , VC4_OPERAND_IMM6_SHL2, VC4_OPERAND_IMM6_SHL3, VC4_OPERAND_IMM6_SHL4, VC4_OPERAND_IMM6_SHL5
 , VC4_OPERAND_IMM6_SHL6, VC4_OPERAND_IMM6_SHL7, VC4_OPERAND_IMM6_SHL8, VC4_OPERAND_ALU32BREG
 , VC4_OPERAND_PPSTARTREG, VC4_OPERAND_PPENDREG0, VC4_OPERAND_PPENDREG6, VC4_OPERAND_PPENDREG16
 , VC4_OPERAND_PPENDREG24, VC4_OPERAND_SWI_IMM, VC4_OPERAND_SPOFFSET, VC4_OPERAND_ADDSPOFFSET
 , VC4_OPERAND_ALU32AREG, VC4_OPERAND_ALU32COND, VC4_OPERAND_ALU48ISREG, VC4_OPERAND_ALU48IDREG
 , VC4_OPERAND_MEM48SREG, VC4_OPERAND_ALU48IMMU, VC4_OPERAND_ALU48PCREL, VC4_OPERAND_MEM48OFFSET27
 , VC4_OPERAND_MEM48PCREL27, VC4_OPERAND_ACCSZ, VC4_OPERAND_ACCSZ32, VC4_OPERAND_CONDCODEBCC32
 , VC4_OPERAND_BCC32SREG, VC4_OPERAND_PCREL10BITS, VC4_OPERAND_PCREL8BITS, VC4_OPERAND_BCC32IMM
 , VC4_OPERAND_ADDCMPBAREG, VC4_OPERAND_ADDCMPBIMM, VC4_OPERAND_OFFSET23BITS, VC4_OPERAND_OFFSET27BITS
 , VC4_OPERAND_OFFSET12, VC4_OPERAND_OFFSET16, VC4_OPERAND_OFFSET16_SHL1, VC4_OPERAND_OFFSET16_SHL2
 , VC4_OPERAND_OFFSET16_SHL3, VC4_OPERAND_OFFSET16_SHL4, VC4_OPERAND_PCREL16, VC4_OPERAND_OFF16BASEREG
 , VC4_OPERAND_OPERAND10_0, VC4_OPERAND_OPERAND47_16, VC4_OPERAND_OPERAND79_48, VC4_OPERAND_MAX
} CGEN_OPERAND_TYPE;

/* Number of operands types.  */
#define MAX_OPERANDS 59

/* Maximum number of operands referenced by any insn.  */
#define MAX_OPERAND_INSTANCES 8

/* Insn attribute indices.  */

/* Enum declaration for cgen_insn attrs.  */
typedef enum cgen_insn_attr {
  CGEN_INSN_ALIAS, CGEN_INSN_VIRTUAL, CGEN_INSN_UNCOND_CTI, CGEN_INSN_COND_CTI
 , CGEN_INSN_SKIP_CTI, CGEN_INSN_DELAY_SLOT, CGEN_INSN_RELAXABLE, CGEN_INSN_RELAXED
 , CGEN_INSN_NO_DIS, CGEN_INSN_PBB, CGEN_INSN_END_BOOLS, CGEN_INSN_START_NBOOLS = 31
 , CGEN_INSN_MACH, CGEN_INSN_END_NBOOLS
} CGEN_INSN_ATTR;

/* Number of non-boolean elements in cgen_insn_attr.  */
#define CGEN_INSN_NBOOL_ATTRS (CGEN_INSN_END_NBOOLS - CGEN_INSN_START_NBOOLS - 1)

/* cgen_insn attribute accessor macros.  */
#define CGEN_ATTR_CGEN_INSN_MACH_VALUE(attrs) ((attrs)->nonbool[CGEN_INSN_MACH-CGEN_INSN_START_NBOOLS-1].nonbitset)
#define CGEN_ATTR_CGEN_INSN_ALIAS_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_ALIAS)) != 0)
#define CGEN_ATTR_CGEN_INSN_VIRTUAL_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_VIRTUAL)) != 0)
#define CGEN_ATTR_CGEN_INSN_UNCOND_CTI_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_UNCOND_CTI)) != 0)
#define CGEN_ATTR_CGEN_INSN_COND_CTI_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_COND_CTI)) != 0)
#define CGEN_ATTR_CGEN_INSN_SKIP_CTI_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_SKIP_CTI)) != 0)
#define CGEN_ATTR_CGEN_INSN_DELAY_SLOT_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_DELAY_SLOT)) != 0)
#define CGEN_ATTR_CGEN_INSN_RELAXABLE_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_RELAXABLE)) != 0)
#define CGEN_ATTR_CGEN_INSN_RELAXED_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_RELAXED)) != 0)
#define CGEN_ATTR_CGEN_INSN_NO_DIS_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_NO_DIS)) != 0)
#define CGEN_ATTR_CGEN_INSN_PBB_VALUE(attrs) (((attrs)->bool_ & (1 << CGEN_INSN_PBB)) != 0)

/* cgen.h uses things we just defined.  */
#include "opcode/cgen.h"

extern const struct cgen_ifld vc4_cgen_ifld_table[];

/* Attributes.  */
extern const CGEN_ATTR_TABLE vc4_cgen_hardware_attr_table[];
extern const CGEN_ATTR_TABLE vc4_cgen_ifield_attr_table[];
extern const CGEN_ATTR_TABLE vc4_cgen_operand_attr_table[];
extern const CGEN_ATTR_TABLE vc4_cgen_insn_attr_table[];

/* Hardware decls.  */

extern CGEN_KEYWORD vc4_cgen_opval_h_reg;
extern CGEN_KEYWORD vc4_cgen_opval_h_fastreg;
extern CGEN_KEYWORD vc4_cgen_opval_h_ppreg;
extern CGEN_KEYWORD vc4_cgen_opval_h_basereg;
extern CGEN_KEYWORD vc4_cgen_opval_h_cond;
extern CGEN_KEYWORD vc4_cgen_opval_h_accsz;

extern const CGEN_HW_ENTRY vc4_cgen_hw_table[];



#endif /* VC4_CPU_H */
