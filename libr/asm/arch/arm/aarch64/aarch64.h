/* AArch64 assembler/disassembler support.

   Copyright 2009, 2010, 2011, 2012, 2013  Free Software Foundation, Inc.
   Contributed by ARM Ltd.

   This file is part of GNU Binutils.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the license, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

#ifndef OPCODE_AARCH64_H
#define OPCODE_AARCH64_H

//#include "bfd.h"
//#include "bfd_stdint.h"
#include <sysdep.h>
#include <assert.h>
#include <stdlib.h>

/* The offset for pc-relative addressing is currently defined to be 0.  */
#define AARCH64_PCREL_OFFSET		0

typedef uint32_t aarch64_insn;

/* The following bitmasks control CPU features.  */
#define AARCH64_FEATURE_V8	0x00000001	/* All processors.  */
#define AARCH64_FEATURE_CRYPTO	0x00010000	/* Crypto instructions.  */
#define AARCH64_FEATURE_FP	0x00020000	/* FP instructions.  */
#define AARCH64_FEATURE_SIMD	0x00040000	/* SIMD instructions.  */
#define AARCH64_FEATURE_CRC	0x00080000

/* Architectures are the sum of the base and extensions.  */
#define AARCH64_ARCH_V8		AARCH64_FEATURE (AARCH64_FEATURE_V8, \
						 AARCH64_FEATURE_FP  \
						 | AARCH64_FEATURE_SIMD)
#define AARCH64_ARCH_NONE	AARCH64_FEATURE (0, 0)
#define AARCH64_ANY		AARCH64_FEATURE (-1, 0)	/* Any basic core.  */

/* CPU-specific features.  */
typedef unsigned long aarch64_feature_set;

#define AARCH64_CPU_HAS_FEATURE(CPU,FEAT)	\
  (((CPU) & (FEAT)) != 0)

#define AARCH64_MERGE_FEATURE_SETS(TARG,F1,F2)	\
  do						\
    {						\
      (TARG) = (F1) | (F2);			\
    }						\
  while (0)

#define AARCH64_CLEAR_FEATURE(TARG,F1,F2)	\
  do						\
    { 						\
      (TARG) = (F1) &~ (F2);			\
    }						\
  while (0)

#define AARCH64_FEATURE(core,coproc) ((core) | (coproc))

#define AARCH64_OPCODE_HAS_FEATURE(OPC,FEAT)	\
  (((OPC) & (FEAT)) != 0)

enum aarch64_operand_class
{
  AARCH64_OPND_CLASS_NIL,
  AARCH64_OPND_CLASS_INT_REG,
  AARCH64_OPND_CLASS_MODIFIED_REG,
  AARCH64_OPND_CLASS_FP_REG,
  AARCH64_OPND_CLASS_SIMD_REG,
  AARCH64_OPND_CLASS_SIMD_ELEMENT,
  AARCH64_OPND_CLASS_SISD_REG,
  AARCH64_OPND_CLASS_SIMD_REGLIST,
  AARCH64_OPND_CLASS_CP_REG,
  AARCH64_OPND_CLASS_ADDRESS,
  AARCH64_OPND_CLASS_IMMEDIATE,
  AARCH64_OPND_CLASS_SYSTEM,
};

/* Operand code that helps both parsing and coding.
   Keep AARCH64_OPERANDS synced.  */

enum aarch64_opnd
{
  AARCH64_OPND_NIL,	/* no operand---MUST BE FIRST!*/

  AARCH64_OPND_Rd,	/* Integer register as destination.  */
  AARCH64_OPND_Rn,	/* Integer register as source.  */
  AARCH64_OPND_Rm,	/* Integer register as source.  */
  AARCH64_OPND_Rt,	/* Integer register used in ld/st instructions.  */
  AARCH64_OPND_Rt2,	/* Integer register used in ld/st pair instructions.  */
  AARCH64_OPND_Rs,	/* Integer register used in ld/st exclusive.  */
  AARCH64_OPND_Ra,	/* Integer register used in ddp_3src instructions.  */
  AARCH64_OPND_Rt_SYS,	/* Integer register used in system instructions.  */

  AARCH64_OPND_Rd_SP,	/* Integer Rd or SP.  */
  AARCH64_OPND_Rn_SP,	/* Integer Rn or SP.  */
  AARCH64_OPND_Rm_EXT,	/* Integer Rm extended.  */
  AARCH64_OPND_Rm_SFT,	/* Integer Rm shifted.  */

  AARCH64_OPND_Fd,	/* Floating-point Fd.  */
  AARCH64_OPND_Fn,	/* Floating-point Fn.  */
  AARCH64_OPND_Fm,	/* Floating-point Fm.  */
  AARCH64_OPND_Fa,	/* Floating-point Fa.  */
  AARCH64_OPND_Ft,	/* Floating-point Ft.  */
  AARCH64_OPND_Ft2,	/* Floating-point Ft2.  */

  AARCH64_OPND_Sd,	/* AdvSIMD Scalar Sd.  */
  AARCH64_OPND_Sn,	/* AdvSIMD Scalar Sn.  */
  AARCH64_OPND_Sm,	/* AdvSIMD Scalar Sm.  */

  AARCH64_OPND_Vd,	/* AdvSIMD Vector Vd.  */
  AARCH64_OPND_Vn,	/* AdvSIMD Vector Vn.  */
  AARCH64_OPND_Vm,	/* AdvSIMD Vector Vm.  */
  AARCH64_OPND_VdD1,	/* AdvSIMD <Vd>.D[1]; for FMOV only.  */
  AARCH64_OPND_VnD1,	/* AdvSIMD <Vn>.D[1]; for FMOV only.  */
  AARCH64_OPND_Ed,	/* AdvSIMD Vector Element Vd.  */
  AARCH64_OPND_En,	/* AdvSIMD Vector Element Vn.  */
  AARCH64_OPND_Em,	/* AdvSIMD Vector Element Vm.  */
  AARCH64_OPND_LVn,	/* AdvSIMD Vector register list used in e.g. TBL.  */
  AARCH64_OPND_LVt,	/* AdvSIMD Vector register list used in ld/st.  */
  AARCH64_OPND_LVt_AL,	/* AdvSIMD Vector register list for loading single
			   structure to all lanes.  */
  AARCH64_OPND_LEt,	/* AdvSIMD Vector Element list.  */

  AARCH64_OPND_Cn,	/* Co-processor register in CRn field.  */
  AARCH64_OPND_Cm,	/* Co-processor register in CRm field.  */

  AARCH64_OPND_IDX,	/* AdvSIMD EXT index operand.  */
  AARCH64_OPND_IMM_VLSL,/* Immediate for shifting vector registers left.  */
  AARCH64_OPND_IMM_VLSR,/* Immediate for shifting vector registers right.  */
  AARCH64_OPND_SIMD_IMM,/* AdvSIMD modified immediate without shift.  */
  AARCH64_OPND_SIMD_IMM_SFT,	/* AdvSIMD modified immediate with shift.  */
  AARCH64_OPND_SIMD_FPIMM,/* AdvSIMD 8-bit fp immediate.  */
  AARCH64_OPND_SHLL_IMM,/* Immediate shift for AdvSIMD SHLL instruction
			   (no encoding).  */
  AARCH64_OPND_IMM0,	/* Immediate for #0.  */
  AARCH64_OPND_FPIMM0,	/* Immediate for #0.0.  */
  AARCH64_OPND_FPIMM,	/* Floating-point Immediate.  */
  AARCH64_OPND_IMMR,	/* Immediate #<immr> in e.g. BFM.  */
  AARCH64_OPND_IMMS,	/* Immediate #<imms> in e.g. BFM.  */
  AARCH64_OPND_WIDTH,	/* Immediate #<width> in e.g. BFI.  */
  AARCH64_OPND_IMM,	/* Immediate.  */
  AARCH64_OPND_UIMM3_OP1,/* Unsigned 3-bit immediate in the op1 field.  */
  AARCH64_OPND_UIMM3_OP2,/* Unsigned 3-bit immediate in the op2 field.  */
  AARCH64_OPND_UIMM4,	/* Unsigned 4-bit immediate in the CRm field.  */
  AARCH64_OPND_UIMM7,	/* Unsigned 7-bit immediate in the CRm:op2 fields.  */
  AARCH64_OPND_BIT_NUM,	/* Immediate.  */
  AARCH64_OPND_EXCEPTION,/* imm16 operand in exception instructions.  */
  AARCH64_OPND_CCMP_IMM,/* Immediate in conditional compare instructions.  */
  AARCH64_OPND_NZCV,	/* Flag bit specifier giving an alternative value for
			   each condition flag.  */

  AARCH64_OPND_LIMM,	/* Logical Immediate.  */
  AARCH64_OPND_AIMM,	/* Arithmetic immediate.  */
  AARCH64_OPND_HALF,	/* #<imm16>{, LSL #<shift>} operand in move wide.  */
  AARCH64_OPND_FBITS,	/* FP #<fbits> operand in e.g. SCVTF */
  AARCH64_OPND_IMM_MOV,	/* Immediate operand for the MOV alias.  */

  AARCH64_OPND_COND,	/* Standard condition as the last operand.  */

  AARCH64_OPND_ADDR_ADRP,	/* Memory address for ADRP */
  AARCH64_OPND_ADDR_PCREL14,	/* 14-bit PC-relative address for e.g. TBZ.  */
  AARCH64_OPND_ADDR_PCREL19,	/* 19-bit PC-relative address for e.g. LDR.  */
  AARCH64_OPND_ADDR_PCREL21,	/* 21-bit PC-relative address for e.g. ADR.  */
  AARCH64_OPND_ADDR_PCREL26,	/* 26-bit PC-relative address for e.g. BL.  */

  AARCH64_OPND_ADDR_SIMPLE,	/* Address of ld/st exclusive.  */
  AARCH64_OPND_ADDR_REGOFF,	/* Address of register offset.  */
  AARCH64_OPND_ADDR_SIMM7,	/* Address of signed 7-bit immediate.  */
  AARCH64_OPND_ADDR_SIMM9,	/* Address of signed 9-bit immediate.  */
  AARCH64_OPND_ADDR_SIMM9_2,	/* Same as the above, but the immediate is
				   negative or unaligned and there is
				   no writeback allowed.  This operand code
				   is only used to support the programmer-
				   friendly feature of using LDR/STR as the
				   the mnemonic name for LDUR/STUR instructions
				   wherever there is no ambiguity.  */
  AARCH64_OPND_ADDR_UIMM12,	/* Address of unsigned 12-bit immediate.  */
  AARCH64_OPND_SIMD_ADDR_SIMPLE,/* Address of ld/st multiple structures.  */
  AARCH64_OPND_SIMD_ADDR_POST,	/* Address of ld/st multiple post-indexed.  */

  AARCH64_OPND_SYSREG,		/* System register operand.  */
  AARCH64_OPND_PSTATEFIELD,	/* PSTATE field name operand.  */
  AARCH64_OPND_SYSREG_AT,	/* System register <at_op> operand.  */
  AARCH64_OPND_SYSREG_DC,	/* System register <dc_op> operand.  */
  AARCH64_OPND_SYSREG_IC,	/* System register <ic_op> operand.  */
  AARCH64_OPND_SYSREG_TLBI,	/* System register <tlbi_op> operand.  */
  AARCH64_OPND_BARRIER,		/* Barrier operand.  */
  AARCH64_OPND_BARRIER_ISB,	/* Barrier operand for ISB.  */
  AARCH64_OPND_PRFOP,		/* Prefetch operation.  */
};

/* Qualifier constrains an operand.  It either specifies a variant of an
   operand type or limits values available to an operand type.

   N.B. Order is important; keep aarch64_opnd_qualifiers synced.  */

enum aarch64_opnd_qualifier
{
  /* Indicating no further qualification on an operand.  */
  AARCH64_OPND_QLF_NIL,

  /* Qualifying an operand which is a general purpose (integer) register;
     indicating the operand data size or a specific register.  */
  AARCH64_OPND_QLF_W,	/* Wn, WZR or WSP.  */
  AARCH64_OPND_QLF_X,	/* Xn, XZR or XSP.  */
  AARCH64_OPND_QLF_WSP,	/* WSP.  */
  AARCH64_OPND_QLF_SP,	/* SP.  */

  /* Qualifying an operand which is a floating-point register, a SIMD
     vector element or a SIMD vector element list; indicating operand data
     size or the size of each SIMD vector element in the case of a SIMD
     vector element list.
     These qualifiers are also used to qualify an address operand to
     indicate the size of data element a load/store instruction is
     accessing.
     They are also used for the immediate shift operand in e.g. SSHR.  Such
     a use is only for the ease of operand encoding/decoding and qualifier
     sequence matching; such a use should not be applied widely; use the value
     constraint qualifiers for immediate operands wherever possible.  */
  AARCH64_OPND_QLF_S_B,
  AARCH64_OPND_QLF_S_H,
  AARCH64_OPND_QLF_S_S,
  AARCH64_OPND_QLF_S_D,
  AARCH64_OPND_QLF_S_Q,

  /* Qualifying an operand which is a SIMD vector register or a SIMD vector
     register list; indicating register shape.
     They are also used for the immediate shift operand in e.g. SSHR.  Such
     a use is only for the ease of operand encoding/decoding and qualifier
     sequence matching; such a use should not be applied widely; use the value
     constraint qualifiers for immediate operands wherever possible.  */
  AARCH64_OPND_QLF_V_8B,
  AARCH64_OPND_QLF_V_16B,
  AARCH64_OPND_QLF_V_4H,
  AARCH64_OPND_QLF_V_8H,
  AARCH64_OPND_QLF_V_2S,
  AARCH64_OPND_QLF_V_4S,
  AARCH64_OPND_QLF_V_1D,
  AARCH64_OPND_QLF_V_2D,
  AARCH64_OPND_QLF_V_1Q,

  /* Constraint on value.  */
  AARCH64_OPND_QLF_imm_0_7,
  AARCH64_OPND_QLF_imm_0_15,
  AARCH64_OPND_QLF_imm_0_31,
  AARCH64_OPND_QLF_imm_0_63,
  AARCH64_OPND_QLF_imm_1_32,
  AARCH64_OPND_QLF_imm_1_64,

  /* Indicate whether an AdvSIMD modified immediate operand is shift-zeros
     or shift-ones.  */
  AARCH64_OPND_QLF_LSL,
  AARCH64_OPND_QLF_MSL,

  /* Special qualifier helping retrieve qualifier information during the
     decoding time (currently not in use).  */
  AARCH64_OPND_QLF_RETRIEVE,
};

/* Instruction class.  */

enum aarch64_insn_class
{
  addsub_carry,
  addsub_ext,
  addsub_imm,
  addsub_shift,
  asimdall,
  asimddiff,
  asimdelem,
  asimdext,
  asimdimm,
  asimdins,
  asimdmisc,
  asimdperm,
  asimdsame,
  asimdshf,
  asimdtbl,
  asisddiff,
  asisdelem,
  asisdlse,
  asisdlsep,
  asisdlso,
  asisdlsop,
  asisdmisc,
  asisdone,
  asisdpair,
  asisdsame,
  asisdshf,
  bitfield,
  branch_imm,
  branch_reg,
  compbranch,
  condbranch,
  condcmp_imm,
  condcmp_reg,
  condsel,
  cryptoaes,
  cryptosha2,
  cryptosha3,
  dp_1src,
  dp_2src,
  dp_3src,
  exception,
  extract,
  float2fix,
  float2int,
  floatccmp,
  floatcmp,
  floatdp1,
  floatdp2,
  floatdp3,
  floatimm,
  floatsel,
  ldst_immpost,
  ldst_immpre,
  ldst_imm9,	/* immpost or immpre */
  ldst_pos,
  ldst_regoff,
  ldst_unpriv,
  ldst_unscaled,
  ldstexcl,
  ldstnapair_offs,
  ldstpair_off,
  ldstpair_indexed,
  loadlit,
  log_imm,
  log_shift,
  movewide,
  pcreladdr,
  ic_system,
  testbranch,
};

/* Opcode enumerators.  */

enum aarch64_op
{
  OP_NIL,
  OP_STRB_POS,
  OP_LDRB_POS,
  OP_LDRSB_POS,
  OP_STRH_POS,
  OP_LDRH_POS,
  OP_LDRSH_POS,
  OP_STR_POS,
  OP_LDR_POS,
  OP_STRF_POS,
  OP_LDRF_POS,
  OP_LDRSW_POS,
  OP_PRFM_POS,

  OP_STURB,
  OP_LDURB,
  OP_LDURSB,
  OP_STURH,
  OP_LDURH,
  OP_LDURSH,
  OP_STUR,
  OP_LDUR,
  OP_STURV,
  OP_LDURV,
  OP_LDURSW,
  OP_PRFUM,

  OP_LDR_LIT,
  OP_LDRV_LIT,
  OP_LDRSW_LIT,
  OP_PRFM_LIT,

  OP_ADD,
  OP_B,
  OP_BL,

  OP_MOVN,
  OP_MOVZ,
  OP_MOVK,

  OP_MOV_IMM_LOG,	/* MOV alias for moving bitmask immediate.  */
  OP_MOV_IMM_WIDE,	/* MOV alias for moving wide immediate.  */
  OP_MOV_IMM_WIDEN,	/* MOV alias for moving wide immediate (negated).  */

  OP_MOV_V,		/* MOV alias for moving vector register.  */

  OP_ASR_IMM,
  OP_LSR_IMM,
  OP_LSL_IMM,

  OP_BIC,

  OP_UBFX,
  OP_BFXIL,
  OP_SBFX,
  OP_SBFIZ,
  OP_BFI,
  OP_UBFIZ,
  OP_UXTB,
  OP_UXTH,
  OP_UXTW,

  OP_CINC,
  OP_CINV,
  OP_CNEG,
  OP_CSET,
  OP_CSETM,

  OP_FCVT,
  OP_FCVTN,
  OP_FCVTN2,
  OP_FCVTL,
  OP_FCVTL2,
  OP_FCVTXN_S,		/* Scalar version.  */

  OP_ROR_IMM,

  OP_SXTL,
  OP_SXTL2,
  OP_UXTL,
  OP_UXTL2,

  OP_TOTAL_NUM,		/* Pseudo.  */
};

/* Maximum number of operands an instruction can have.  */
#define AARCH64_MAX_OPND_NUM 6
/* Maximum number of qualifier sequences an instruction can have.  */
#define AARCH64_MAX_QLF_SEQ_NUM 10
/* Operand qualifier typedef; optimized for the size.  */
typedef unsigned char aarch64_opnd_qualifier_t;
/* Operand qualifier sequence typedef.  */
typedef aarch64_opnd_qualifier_t	\
	  aarch64_opnd_qualifier_seq_t [AARCH64_MAX_OPND_NUM];

/* FIXME: improve the efficiency.  */
static inline bfd_boolean
empty_qualifier_sequence_p (const aarch64_opnd_qualifier_t *qualifiers)
{
  int i;
  for (i = 0; i < AARCH64_MAX_OPND_NUM; ++i)
    if (qualifiers[i] != AARCH64_OPND_QLF_NIL)
      return FALSE;
  return TRUE;
}

/* This structure holds information for a particular opcode.  */

struct aarch64_opcode
{
  /* The name of the mnemonic.  */
  const char *name;

  /* The opcode itself.  Those bits which will be filled in with
     operands are zeroes.  */
  aarch64_insn opcode;

  /* The opcode mask.  This is used by the disassembler.  This is a
     mask containing ones indicating those bits which must match the
     opcode field, and zeroes indicating those bits which need not
     match (and are presumably filled in by operands).  */
  aarch64_insn mask;

  /* Instruction class.  */
  enum aarch64_insn_class iclass;

  /* Enumerator identifier.  */
  enum aarch64_op op;

  /* Which architecture variant provides this instruction.  */
  const aarch64_feature_set *avariant;

  /* An array of operand codes.  Each code is an index into the
     operand table.  They appear in the order which the operands must
     appear in assembly code, and are terminated by a zero.  */
  enum aarch64_opnd operands[AARCH64_MAX_OPND_NUM];

  /* A list of operand qualifier code sequence.  Each operand qualifier
     code qualifies the corresponding operand code.  Each operand
     qualifier sequence specifies a valid opcode variant and related
     constraint on operands.  */
  aarch64_opnd_qualifier_seq_t qualifiers_list[AARCH64_MAX_QLF_SEQ_NUM];

  /* Flags providing information about this instruction */
  uint32_t flags;
};

typedef struct aarch64_opcode aarch64_opcode;

/* Table describing all the AArch64 opcodes.  */
extern aarch64_opcode aarch64_opcode_table[];

/* Opcode flags.  */
#define F_ALIAS (1 << 0)
#define F_HAS_ALIAS (1 << 1)
/* Disassembly preference priority 1-3 (the larger the higher).  If nothing
   is specified, it is the priority 0 by default, i.e. the lowest priority.  */
#define F_P1 (1 << 2)
#define F_P2 (2 << 2)
#define F_P3 (3 << 2)
/* Flag an instruction that is truly conditional executed, e.g. b.cond.  */
#define F_COND (1 << 4)
/* Instruction has the field of 'sf'.  */
#define F_SF (1 << 5)
/* Instruction has the field of 'size:Q'.  */
#define F_SIZEQ (1 << 6)
/* Floating-point instruction has the field of 'type'.  */
#define F_FPTYPE (1 << 7)
/* AdvSIMD scalar instruction has the field of 'size'.  */
#define F_SSIZE (1 << 8)
/* AdvSIMD vector register arrangement specifier encoded in "imm5<3:0>:Q".  */
#define F_T (1 << 9)
/* Size of GPR operand in AdvSIMD instructions encoded in Q.  */
#define F_GPRSIZE_IN_Q (1 << 10)
/* Size of Rt load signed instruction encoded in opc[0], i.e. bit 22.  */
#define F_LDS_SIZE (1 << 11)
/* Optional operand; assume maximum of 1 operand can be optional.  */
#define F_OPD0_OPT (1 << 12)
#define F_OPD1_OPT (2 << 12)
#define F_OPD2_OPT (3 << 12)
#define F_OPD3_OPT (4 << 12)
#define F_OPD4_OPT (5 << 12)
/* Default value for the optional operand when omitted from the assembly.  */
#define F_DEFAULT(X) (((X) & 0x1f) << 15)
/* Instruction that is an alias of another instruction needs to be
   encoded/decoded by converting it to/from the real form, followed by
   the encoding/decoding according to the rules of the real opcode.
   This compares to the direct coding using the alias's information.
   N.B. this flag requires F_ALIAS to be used together.  */
#define F_CONV (1 << 20)
/* Use together with F_ALIAS to indicate an alias opcode is a programmer
   friendly pseudo instruction available only in the assembly code (thus will
   not show up in the disassembly).  */
#define F_PSEUDO (1 << 21)
/* Instruction has miscellaneous encoding/decoding rules.  */
#define F_MISC (1 << 22)
/* Instruction has the field of 'N'; used in conjunction with F_SF.  */
#define F_N (1 << 23)
/* Opcode dependent field.  */
#define F_OD(X) (((X) & 0x7) << 24)
/* Next bit is 27.  */

static inline bfd_boolean
alias_opcode_p (const aarch64_opcode *opcode)
{
  return (opcode->flags & F_ALIAS) ? TRUE : FALSE;
}

static inline bfd_boolean
opcode_has_alias (const aarch64_opcode *opcode)
{
  return (opcode->flags & F_HAS_ALIAS) ? TRUE : FALSE;
}

/* Priority for disassembling preference.  */
static inline int
opcode_priority (const aarch64_opcode *opcode)
{
  return (opcode->flags >> 2) & 0x3;
}

static inline bfd_boolean
pseudo_opcode_p (const aarch64_opcode *opcode)
{
  return (opcode->flags & F_PSEUDO) != 0lu ? TRUE : FALSE;
}

static inline bfd_boolean
optional_operand_p (const aarch64_opcode *opcode, unsigned int idx)
{
  return (((opcode->flags >> 12) & 0x7) == idx + 1)
    ? TRUE : FALSE;
}

static inline aarch64_insn
get_optional_operand_default_value (const aarch64_opcode *opcode)
{
  return (opcode->flags >> 15) & 0x1f;
}

static inline unsigned int
get_opcode_dependent_value (const aarch64_opcode *opcode)
{
  return (opcode->flags >> 24) & 0x7;
}

static inline bfd_boolean
opcode_has_special_coder (const aarch64_opcode *opcode)
{
  return (opcode->flags & (F_SF | F_SIZEQ | F_FPTYPE | F_SSIZE | F_T
	  | F_GPRSIZE_IN_Q | F_LDS_SIZE | F_MISC | F_N | F_COND)) ? TRUE
    : FALSE;
}

struct aarch64_name_value_pair
{
  const char *  name;
  aarch64_insn	value;
};

extern const struct aarch64_name_value_pair aarch64_operand_modifiers [];
extern const struct aarch64_name_value_pair aarch64_sys_regs [];
extern const struct aarch64_name_value_pair aarch64_pstatefields [];
extern const struct aarch64_name_value_pair aarch64_barrier_options [16];
extern const struct aarch64_name_value_pair aarch64_prfops [32];

typedef struct
{
  const char *template;
  uint32_t value;
  int has_xt;
} aarch64_sys_ins_reg;

extern const aarch64_sys_ins_reg aarch64_sys_regs_ic [];
extern const aarch64_sys_ins_reg aarch64_sys_regs_dc [];
extern const aarch64_sys_ins_reg aarch64_sys_regs_at [];
extern const aarch64_sys_ins_reg aarch64_sys_regs_tlbi [];

/* Shift/extending operator kinds.
   N.B. order is important; keep aarch64_operand_modifiers synced.  */
enum aarch64_modifier_kind
{
  AARCH64_MOD_NONE,
  AARCH64_MOD_MSL,
  AARCH64_MOD_ROR,
  AARCH64_MOD_ASR,
  AARCH64_MOD_LSR,
  AARCH64_MOD_LSL,
  AARCH64_MOD_UXTB,
  AARCH64_MOD_UXTH,
  AARCH64_MOD_UXTW,
  AARCH64_MOD_UXTX,
  AARCH64_MOD_SXTB,
  AARCH64_MOD_SXTH,
  AARCH64_MOD_SXTW,
  AARCH64_MOD_SXTX,
};

bfd_boolean
aarch64_extend_operator_p (enum aarch64_modifier_kind);

enum aarch64_modifier_kind
aarch64_get_operand_modifier (const struct aarch64_name_value_pair *);
/* Condition.  */

typedef struct
{
  /* A list of names with the first one as the disassembly preference;
     terminated by NULL if fewer than 3.  */
  const char *names[3];
  aarch64_insn value;
} aarch64_cond;

extern const aarch64_cond aarch64_conds[16];

const aarch64_cond* get_cond_from_value (aarch64_insn value);
const aarch64_cond* get_inverted_cond (const aarch64_cond *cond);

/* Structure representing an operand.  */

struct aarch64_opnd_info
{
  enum aarch64_opnd type;
  aarch64_opnd_qualifier_t qualifier;
  int idx;

  union
    {
      struct
	{
	  unsigned regno;
	} reg;
      struct
	{
	  unsigned regno : 5;
	  unsigned index : 4;
	} reglane;
      /* e.g. LVn.  */
      struct
	{
	  unsigned first_regno : 5;
	  unsigned num_regs : 3;
	  /* 1 if it is a list of reg element.  */
	  unsigned has_index : 1;
	  /* Lane index; valid only when has_index is 1.  */
	  unsigned index : 4;
	} reglist;
      /* e.g. immediate or pc relative address offset.  */
      struct
	{
	  int64_t value;
	  unsigned is_fp : 1;
	} imm;
      /* e.g. address in STR (register offset).  */
      struct
	{
	  unsigned base_regno;
	  struct
	    {
	      union
		{
		  int imm;
		  unsigned regno;
		};
	      unsigned is_reg;
	    } offset;
	  unsigned pcrel : 1;		/* PC-relative.  */
	  unsigned writeback : 1;
	  unsigned preind : 1;		/* Pre-indexed.  */
	  unsigned postind : 1;		/* Post-indexed.  */
	} addr;
      const aarch64_cond *cond;
      /* The encoding of the system register.  */
      aarch64_insn sysreg;
      /* The encoding of the PSTATE field.  */
      aarch64_insn pstatefield;
      const aarch64_sys_ins_reg *sysins_op;
      const struct aarch64_name_value_pair *barrier;
      const struct aarch64_name_value_pair *prfop;
    };

  /* Operand shifter; in use when the operand is a register offset address,
     add/sub extended reg, etc. e.g. <R><m>{, <extend> {#<amount>}}.  */
  struct
    {
      enum aarch64_modifier_kind kind;
      int amount;
      unsigned operator_present: 1;	/* Only valid during encoding.  */
      /* Value of the 'S' field in ld/st reg offset; used only in decoding.  */
      unsigned amount_present: 1;
    } shifter;

  unsigned skip:1;	/* Operand is not completed if there is a fixup needed
			   to be done on it.  In some (but not all) of these
			   cases, we need to tell libopcodes to skip the
			   constraint checking and the encoding for this
			   operand, so that the libopcodes can pick up the
			   right opcode before the operand is fixed-up.  This
			   flag should only be used during the
			   assembling/encoding.  */
  unsigned present:1;	/* Whether this operand is present in the assembly
			   line; not used during the disassembly.  */
};

typedef struct aarch64_opnd_info aarch64_opnd_info;

/* Structure representing an instruction.

   It is used during both the assembling and disassembling.  The assembler
   fills an aarch64_inst after a successful parsing and then passes it to the
   encoding routine to do the encoding.  During the disassembling, the
   disassembler calls the decoding routine to decode a binary instruction; on a
   successful return, such a structure will be filled with information of the
   instruction; then the disassembler uses the information to print out the
   instruction.  */

struct aarch64_inst
{
  /* The value of the binary instruction.  */
  aarch64_insn value;

  /* Corresponding opcode entry.  */
  const aarch64_opcode *opcode;

  /* Condition for a truly conditional-executed instrutions, e.g. b.cond.  */
  const aarch64_cond *cond;

  /* Operands information.  */
  aarch64_opnd_info operands[AARCH64_MAX_OPND_NUM];
};

typedef struct aarch64_inst aarch64_inst;

/* Diagnosis related declaration and interface.  */

/* Operand error kind enumerators.

   AARCH64_OPDE_RECOVERABLE
     Less severe error found during the parsing, very possibly because that
     GAS has picked up a wrong instruction template for the parsing.

   AARCH64_OPDE_SYNTAX_ERROR
     General syntax error; it can be either a user error, or simply because
     that GAS is trying a wrong instruction template.

   AARCH64_OPDE_FATAL_SYNTAX_ERROR
     Definitely a user syntax error.

   AARCH64_OPDE_INVALID_VARIANT
     No syntax error, but the operands are not a valid combination, e.g.
     FMOV D0,S0

   AARCH64_OPDE_OUT_OF_RANGE
     Error about some immediate value out of a valid range.

   AARCH64_OPDE_UNALIGNED
     Error about some immediate value not properly aligned (i.e. not being a
     multiple times of a certain value).

   AARCH64_OPDE_REG_LIST
     Error about the register list operand having unexpected number of
     registers.

   AARCH64_OPDE_OTHER_ERROR
     Error of the highest severity and used for any severe issue that does not
     fall into any of the above categories.

   The enumerators are only interesting to GAS.  They are declared here (in
   libopcodes) because that some errors are detected (and then notified to GAS)
   by libopcodes (rather than by GAS solely).

   The first three errors are only deteced by GAS while the
   AARCH64_OPDE_INVALID_VARIANT error can only be spotted by libopcodes as
   only libopcodes has the information about the valid variants of each
   instruction.

   The enumerators have an increasing severity.  This is helpful when there are
   multiple instruction templates available for a given mnemonic name (e.g.
   FMOV); this mechanism will help choose the most suitable template from which
   the generated diagnostics can most closely describe the issues, if any.  */

enum aarch64_operand_error_kind
{
  AARCH64_OPDE_NIL,
  AARCH64_OPDE_RECOVERABLE,
  AARCH64_OPDE_SYNTAX_ERROR,
  AARCH64_OPDE_FATAL_SYNTAX_ERROR,
  AARCH64_OPDE_INVALID_VARIANT,
  AARCH64_OPDE_OUT_OF_RANGE,
  AARCH64_OPDE_UNALIGNED,
  AARCH64_OPDE_REG_LIST,
  AARCH64_OPDE_OTHER_ERROR
};

/* N.B. GAS assumes that this structure work well with shallow copy.  */
struct aarch64_operand_error
{
  enum aarch64_operand_error_kind kind;
  int index;
  const char *error;
  int data[3];	/* Some data for extra information.  */
};

typedef struct aarch64_operand_error aarch64_operand_error;

/* Encoding entrypoint.  */

extern int
aarch64_opcode_encode (const aarch64_opcode *, const aarch64_inst *,
		       aarch64_insn *, aarch64_opnd_qualifier_t *,
		       aarch64_operand_error *);

extern const aarch64_opcode *
aarch64_replace_opcode (struct aarch64_inst *,
			const aarch64_opcode *);

/* Given the opcode enumerator OP, return the pointer to the corresponding
   opcode entry.  */

extern const aarch64_opcode *
aarch64_get_opcode (enum aarch64_op);

/* Generate the string representation of an operand.  */
extern void
aarch64_print_operand (char *, size_t, bfd_vma, const aarch64_opcode *,
		       const aarch64_opnd_info *, int, int *, bfd_vma *);

/* Miscellaneous interface.  */

extern int
aarch64_operand_index (const enum aarch64_opnd *, enum aarch64_opnd);

extern aarch64_opnd_qualifier_t
aarch64_get_expected_qualifier (const aarch64_opnd_qualifier_seq_t *, int,
				const aarch64_opnd_qualifier_t, int);

extern int
aarch64_num_of_operands (const aarch64_opcode *);

extern int
aarch64_stack_pointer_p (const aarch64_opnd_info *);

extern
int aarch64_zero_register_p (const aarch64_opnd_info *);

/* Given an operand qualifier, return the expected data element size
   of a qualified operand.  */
extern unsigned char
aarch64_get_qualifier_esize (aarch64_opnd_qualifier_t);

extern enum aarch64_operand_class
aarch64_get_operand_class (enum aarch64_opnd);

extern const char *
aarch64_get_operand_name (enum aarch64_opnd);

extern const char *
aarch64_get_operand_desc (enum aarch64_opnd);

#ifdef DEBUG_AARCH64
extern int debug_dump;

extern void
aarch64_verbose (const char *, ...) __attribute__ ((format (printf, 1, 2)));

#define DEBUG_TRACE(M, ...)					\
  {								\
    if (debug_dump)						\
      aarch64_verbose ("%s: " M ".", __func__, ##__VA_ARGS__);	\
  }

#define DEBUG_TRACE_IF(C, M, ...)				\
  {								\
    if (debug_dump && (C))					\
      aarch64_verbose ("%s: " M ".", __func__, ##__VA_ARGS__);	\
  }
#else  /* !DEBUG_AARCH64 */
#define DEBUG_TRACE(M, ...) ;
#define DEBUG_TRACE_IF(C, M, ...) ;
#endif /* DEBUG_AARCH64 */

#endif /* OPCODE_AARCH64_H */
