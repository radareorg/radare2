/* aarch64-opc.c -- AArch64 opcode support.
   Copyright 2009, 2010, 2011, 2012, 2013  Free Software Foundation, Inc.
   Contributed by ARM Ltd.

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
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

#include "sysdep.h"
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>

#include "opintl.h"

#include "aarch64-opc.h"

#ifdef DEBUG_AARCH64
int debug_dump = FALSE;
#endif /* DEBUG_AARCH64 */

/* Helper functions to determine which operand to be used to encode/decode
   the size:Q fields for AdvSIMD instructions.  */

static inline bfd_boolean
vector_qualifier_p (enum aarch64_opnd_qualifier qualifier)
{
  return ((qualifier >= AARCH64_OPND_QLF_V_8B
	  && qualifier <= AARCH64_OPND_QLF_V_1Q) ? TRUE
	  : FALSE);
}

static inline bfd_boolean
fp_qualifier_p (enum aarch64_opnd_qualifier qualifier)
{
  return ((qualifier >= AARCH64_OPND_QLF_S_B
	  && qualifier <= AARCH64_OPND_QLF_S_Q) ? TRUE
	  : FALSE);
}

enum data_pattern
{
  DP_UNKNOWN,
  DP_VECTOR_3SAME,
  DP_VECTOR_LONG,
  DP_VECTOR_WIDE,
  DP_VECTOR_ACROSS_LANES,
};

static const char significant_operand_index [] =
{
  0,	/* DP_UNKNOWN, by default using operand 0.  */
  0,	/* DP_VECTOR_3SAME */
  1,	/* DP_VECTOR_LONG */
  2,	/* DP_VECTOR_WIDE */
  1,	/* DP_VECTOR_ACROSS_LANES */
};

/* Given a sequence of qualifiers in QUALIFIERS, determine and return
   the data pattern.
   N.B. QUALIFIERS is a possible sequence of qualifiers each of which
   corresponds to one of a sequence of operands.  */

static enum data_pattern
get_data_pattern (const aarch64_opnd_qualifier_seq_t qualifiers)
{
  if (vector_qualifier_p (qualifiers[0]) == TRUE)
    {
      /* e.g. v.4s, v.4s, v.4s
	   or v.4h, v.4h, v.h[3].  */
      if (qualifiers[0] == qualifiers[1]
	  && vector_qualifier_p (qualifiers[2]) == TRUE
	  && (aarch64_get_qualifier_esize (qualifiers[0])
	      == aarch64_get_qualifier_esize (qualifiers[1]))
	  && (aarch64_get_qualifier_esize (qualifiers[0])
	      == aarch64_get_qualifier_esize (qualifiers[2])))
	return DP_VECTOR_3SAME;
      /* e.g. v.8h, v.8b, v.8b.
           or v.4s, v.4h, v.h[2].
	   or v.8h, v.16b.  */
      if (vector_qualifier_p (qualifiers[1]) == TRUE
	  && aarch64_get_qualifier_esize (qualifiers[0]) != 0
	  && (aarch64_get_qualifier_esize (qualifiers[0])
	      == aarch64_get_qualifier_esize (qualifiers[1]) << 1))
	return DP_VECTOR_LONG;
      /* e.g. v.8h, v.8h, v.8b.  */
      if (qualifiers[0] == qualifiers[1]
	  && vector_qualifier_p (qualifiers[2]) == TRUE
	  && aarch64_get_qualifier_esize (qualifiers[0]) != 0
	  && (aarch64_get_qualifier_esize (qualifiers[0])
	      == aarch64_get_qualifier_esize (qualifiers[2]) << 1)
	  && (aarch64_get_qualifier_esize (qualifiers[0])
	      == aarch64_get_qualifier_esize (qualifiers[1])))
	return DP_VECTOR_WIDE;
    }
  else if (fp_qualifier_p (qualifiers[0]) == TRUE)
    {
      /* e.g. SADDLV <V><d>, <Vn>.<T>.  */
      if (vector_qualifier_p (qualifiers[1]) == TRUE
	  && qualifiers[2] == AARCH64_OPND_QLF_NIL)
	return DP_VECTOR_ACROSS_LANES;
    }

  return DP_UNKNOWN;
}

/* Select the operand to do the encoding/decoding of the 'size:Q' fields in
   the AdvSIMD instructions.  */
/* N.B. it is possible to do some optimization that doesn't call
   get_data_pattern each time when we need to select an operand.  We can
   either buffer the caculated the result or statically generate the data,
   however, it is not obvious that the optimization will bring significant
   benefit.  */

int
aarch64_select_operand_for_sizeq_field_coding (const aarch64_opcode *opcode)
{
  return
    significant_operand_index [get_data_pattern (opcode->qualifiers_list[0])];
}

const aarch64_field fields[] =
{
    {  0,  0 },	/* NIL.  */
    {  0,  4 },	/* cond2: condition in truly conditional-executed inst.  */
    {  0,  4 },	/* nzcv: flag bit specifier, encoded in the "nzcv" field.  */
    {  5,  5 },	/* defgh: d:e:f:g:h bits in AdvSIMD modified immediate.  */
    { 16,  3 },	/* abc: a:b:c bits in AdvSIMD modified immediate.  */
    {  5, 19 },	/* imm19: e.g. in CBZ.  */
    {  5, 19 },	/* immhi: e.g. in ADRP.  */
    { 29,  2 },	/* immlo: e.g. in ADRP.  */
    { 22,  2 },	/* size: in most AdvSIMD and floating-point instructions.  */
    { 10,  2 },	/* vldst_size: size field in the AdvSIMD load/store inst.  */
    { 29,  1 },	/* op: in AdvSIMD modified immediate instructions.  */
    { 30,  1 },	/* Q: in most AdvSIMD instructions.  */
    {  0,  5 },	/* Rt: in load/store instructions.  */
    {  0,  5 },	/* Rd: in many integer instructions.  */
    {  5,  5 },	/* Rn: in many integer instructions.  */
    { 10,  5 },	/* Rt2: in load/store pair instructions.  */
    { 10,  5 },	/* Ra: in fp instructions.  */
    {  5,  3 },	/* op2: in the system instructions.  */
    {  8,  4 },	/* CRm: in the system instructions.  */
    { 12,  4 },	/* CRn: in the system instructions.  */
    { 16,  3 },	/* op1: in the system instructions.  */
    { 19,  2 },	/* op0: in the system instructions.  */
    { 10,  3 },	/* imm3: in add/sub extended reg instructions.  */
    { 12,  4 },	/* cond: condition flags as a source operand.  */
    { 12,  4 },	/* opcode: in advsimd load/store instructions.  */
    { 12,  4 },	/* cmode: in advsimd modified immediate instructions.  */
    { 13,  3 },	/* asisdlso_opcode: opcode in advsimd ld/st single element.  */
    { 13,  2 },	/* len: in advsimd tbl/tbx instructions.  */
    { 16,  5 },	/* Rm: in ld/st reg offset and some integer inst.  */
    { 16,  5 },	/* Rs: in load/store exclusive instructions.  */
    { 13,  3 },	/* option: in ld/st reg offset + add/sub extended reg inst.  */
    { 12,  1 },	/* S: in load/store reg offset instructions.  */
    { 21,  2 },	/* hw: in move wide constant instructions.  */
    { 22,  2 },	/* opc: in load/store reg offset instructions.  */
    { 23,  1 },	/* opc1: in load/store reg offset instructions.  */
    { 22,  2 },	/* shift: in add/sub reg/imm shifted instructions.  */
    { 22,  2 },	/* type: floating point type field in fp data inst.  */
    { 30,  2 },	/* ldst_size: size field in ld/st reg offset inst.  */
    { 10,  6 },	/* imm6: in add/sub reg shifted instructions.  */
    { 11,  4 },	/* imm4: in advsimd ext and advsimd ins instructions.  */
    { 16,  5 },	/* imm5: in conditional compare (immediate) instructions.  */
    { 15,  7 },	/* imm7: in load/store pair pre/post index instructions.  */
    { 13,  8 },	/* imm8: in floating-point scalar move immediate inst.  */
    { 12,  9 },	/* imm9: in load/store pre/post index instructions.  */
    { 10, 12 },	/* imm12: in ld/st unsigned imm or add/sub shifted inst.  */
    {  5, 14 },	/* imm14: in test bit and branch instructions.  */
    {  5, 16 },	/* imm16: in exception instructions.  */
    {  0, 26 },	/* imm26: in unconditional branch instructions.  */
    { 10,  6 },	/* imms: in bitfield and logical immediate instructions.  */
    { 16,  6 },	/* immr: in bitfield and logical immediate instructions.  */
    { 16,  3 },	/* immb: in advsimd shift by immediate instructions.  */
    { 19,  4 },	/* immh: in advsimd shift by immediate instructions.  */
    { 22,  1 },	/* N: in logical (immediate) instructions.  */
    { 11,  1 },	/* index: in ld/st inst deciding the pre/post-index.  */
    { 24,  1 },	/* index2: in ld/st pair inst deciding the pre/post-index.  */
    { 31,  1 },	/* sf: in integer data processing instructions.  */
    { 11,  1 },	/* H: in advsimd scalar x indexed element instructions.  */
    { 21,  1 },	/* L: in advsimd scalar x indexed element instructions.  */
    { 20,  1 },	/* M: in advsimd scalar x indexed element instructions.  */
    { 31,  1 },	/* b5: in the test bit and branch instructions.  */
    { 19,  5 },	/* b40: in the test bit and branch instructions.  */
    { 10,  6 },	/* scale: in the fixed-point scalar to fp converting inst.  */
};

enum aarch64_operand_class
aarch64_get_operand_class (enum aarch64_opnd type)
{
  return aarch64_operands[type].op_class;
}

const char *
aarch64_get_operand_name (enum aarch64_opnd type)
{
  return aarch64_operands[type].name;
}

/* Get operand description string.
   This is usually for the diagnosis purpose.  */
const char *
aarch64_get_operand_desc (enum aarch64_opnd type)
{
  return aarch64_operands[type].desc;
}

/* Table of all conditional affixes.  */
const aarch64_cond aarch64_conds[16] =
{
  {{"eq"}, 0x0},
  {{"ne"}, 0x1},
  {{"cs", "hs"}, 0x2},
  {{"cc", "lo", "ul"}, 0x3},
  {{"mi"}, 0x4},
  {{"pl"}, 0x5},
  {{"vs"}, 0x6},
  {{"vc"}, 0x7},
  {{"hi"}, 0x8},
  {{"ls"}, 0x9},
  {{"ge"}, 0xa},
  {{"lt"}, 0xb},
  {{"gt"}, 0xc},
  {{"le"}, 0xd},
  {{"al"}, 0xe},
  {{"nv"}, 0xf},
};

const aarch64_cond *
get_cond_from_value (aarch64_insn value)
{
  assert (value < 16);
  return &aarch64_conds[(unsigned int) value];
}

const aarch64_cond *
get_inverted_cond (const aarch64_cond *cond)
{
  return &aarch64_conds[cond->value ^ 0x1];
}

/* Table describing the operand extension/shifting operators; indexed by
   enum aarch64_modifier_kind.

   The value column provides the most common values for encoding modifiers,
   which enables table-driven encoding/decoding for the modifiers.  */
const struct aarch64_name_value_pair aarch64_operand_modifiers [] =
{
    {"none", 0x0},
    {"msl",  0x0},
    {"ror",  0x3},
    {"asr",  0x2},
    {"lsr",  0x1},
    {"lsl",  0x0},
    {"uxtb", 0x0},
    {"uxth", 0x1},
    {"uxtw", 0x2},
    {"uxtx", 0x3},
    {"sxtb", 0x4},
    {"sxth", 0x5},
    {"sxtw", 0x6},
    {"sxtx", 0x7},
    {NULL, 0},
};

enum aarch64_modifier_kind
aarch64_get_operand_modifier (const struct aarch64_name_value_pair *desc)
{
  return desc - aarch64_operand_modifiers;
}

aarch64_insn
aarch64_get_operand_modifier_value (enum aarch64_modifier_kind kind)
{
  return aarch64_operand_modifiers[kind].value;
}

enum aarch64_modifier_kind
aarch64_get_operand_modifier_from_value (aarch64_insn value,
					 bfd_boolean extend_p)
{
  if (extend_p == TRUE)
    return AARCH64_MOD_UXTB + value;
  else
    return AARCH64_MOD_LSL - value;
}

bfd_boolean
aarch64_extend_operator_p (enum aarch64_modifier_kind kind)
{
  return (kind > AARCH64_MOD_LSL && kind <= AARCH64_MOD_SXTX)
    ? TRUE : FALSE;
}

static inline bfd_boolean
aarch64_shift_operator_p (enum aarch64_modifier_kind kind)
{
  return (kind >= AARCH64_MOD_ROR && kind <= AARCH64_MOD_LSL)
    ? TRUE : FALSE;
}

const struct aarch64_name_value_pair aarch64_barrier_options[16] =
{
    { "#0x00", 0x0 },
    { "oshld", 0x1 },
    { "oshst", 0x2 },
    { "osh",   0x3 },
    { "#0x04", 0x4 },
    { "nshld", 0x5 },
    { "nshst", 0x6 },
    { "nsh",   0x7 },
    { "#0x08", 0x8 },
    { "ishld", 0x9 },
    { "ishst", 0xa },
    { "ish",   0xb },
    { "#0x0c", 0xc },
    { "ld",    0xd },
    { "st",    0xe },
    { "sy",    0xf },
};

/* op -> op:       load = 0 instruction = 1 store = 2
   l  -> level:    1-3
   t  -> temporal: temporal (retained) = 0 non-temporal (streaming) = 1   */
#define B(op,l,t) (((op) << 3) | (((l) - 1) << 1) | (t))
const struct aarch64_name_value_pair aarch64_prfops[32] =
{
  { "pldl1keep", B(0, 1, 0) },
  { "pldl1strm", B(0, 1, 1) },
  { "pldl2keep", B(0, 2, 0) },
  { "pldl2strm", B(0, 2, 1) },
  { "pldl3keep", B(0, 3, 0) },
  { "pldl3strm", B(0, 3, 1) },
  { NULL, 0x06 },
  { NULL, 0x07 },
  { "plil1keep", B(1, 1, 0) },
  { "plil1strm", B(1, 1, 1) },
  { "plil2keep", B(1, 2, 0) },
  { "plil2strm", B(1, 2, 1) },
  { "plil3keep", B(1, 3, 0) },
  { "plil3strm", B(1, 3, 1) },
  { NULL, 0x0e },
  { NULL, 0x0f },
  { "pstl1keep", B(2, 1, 0) },
  { "pstl1strm", B(2, 1, 1) },
  { "pstl2keep", B(2, 2, 0) },
  { "pstl2strm", B(2, 2, 1) },
  { "pstl3keep", B(2, 3, 0) },
  { "pstl3strm", B(2, 3, 1) },
  { NULL, 0x16 },
  { NULL, 0x17 },
  { NULL, 0x18 },
  { NULL, 0x19 },
  { NULL, 0x1a },
  { NULL, 0x1b },
  { NULL, 0x1c },
  { NULL, 0x1d },
  { NULL, 0x1e },
  { NULL, 0x1f },
};
#undef B

/* Utilities on value constraint.  */

static inline int
value_in_range_p (int64_t value, int low, int high)
{
  return (value >= low && value <= high) ? 1 : 0;
}

static inline int
value_aligned_p (int64_t value, int align)
{
  return ((value & (align - 1)) == 0) ? 1 : 0;
}

/* A signed value fits in a field.  */
static inline int
value_fit_signed_field_p (int64_t value, unsigned width)
{
  assert (width < 32);
  if (width < sizeof (value) * 8)
    {
      int64_t lim = (int64_t)1 << (width - 1);
      if (value >= -lim && value < lim)
	return 1;
    }
  return 0;
}

/* An unsigned value fits in a field.  */
static inline int
value_fit_unsigned_field_p (int64_t value, unsigned width)
{
  assert (width < 32);
  if (width < sizeof (value) * 8)
    {
      int64_t lim = (int64_t)1 << width;
      if (value >= 0 && value < lim)
	return 1;
    }
  return 0;
}

/* Return 1 if OPERAND is SP or WSP.  */
int
aarch64_stack_pointer_p (const aarch64_opnd_info *operand)
{
  return ((aarch64_get_operand_class (operand->type)
	   == AARCH64_OPND_CLASS_INT_REG)
	  && operand_maybe_stack_pointer (aarch64_operands + operand->type)
	  && operand->reg.regno == 31);
}

/* Return 1 if OPERAND is XZR or WZP.  */
int
aarch64_zero_register_p (const aarch64_opnd_info *operand)
{
  return ((aarch64_get_operand_class (operand->type)
	   == AARCH64_OPND_CLASS_INT_REG)
	  && !operand_maybe_stack_pointer (aarch64_operands + operand->type)
	  && operand->reg.regno == 31);
}

/* Return true if the operand *OPERAND that has the operand code
   OPERAND->TYPE and been qualified by OPERAND->QUALIFIER can be also
   qualified by the qualifier TARGET.  */

static inline int
operand_also_qualified_p (const struct aarch64_opnd_info *operand,
			  aarch64_opnd_qualifier_t target)
{
  switch (operand->qualifier)
    {
    case AARCH64_OPND_QLF_W:
      if (target == AARCH64_OPND_QLF_WSP && aarch64_stack_pointer_p (operand))
	return 1;
      break;
    case AARCH64_OPND_QLF_X:
      if (target == AARCH64_OPND_QLF_SP && aarch64_stack_pointer_p (operand))
	return 1;
      break;
    case AARCH64_OPND_QLF_WSP:
      if (target == AARCH64_OPND_QLF_W
	  && operand_maybe_stack_pointer (aarch64_operands + operand->type))
	return 1;
      break;
    case AARCH64_OPND_QLF_SP:
      if (target == AARCH64_OPND_QLF_X
	  && operand_maybe_stack_pointer (aarch64_operands + operand->type))
	return 1;
      break;
    default:
      break;
    }

  return 0;
}

/* Given qualifier sequence list QSEQ_LIST and the known qualifier KNOWN_QLF
   for operand KNOWN_IDX, return the expected qualifier for operand IDX.

   Return NIL if more than one expected qualifiers are found.  */

aarch64_opnd_qualifier_t
aarch64_get_expected_qualifier (const aarch64_opnd_qualifier_seq_t *qseq_list,
				int idx,
				const aarch64_opnd_qualifier_t known_qlf,
				int known_idx)
{
  int i, saved_i;

  /* Special case.

     When the known qualifier is NIL, we have to assume that there is only
     one qualifier sequence in the *QSEQ_LIST and return the corresponding
     qualifier directly.  One scenario is that for instruction
	PRFM <prfop>, [<Xn|SP>, #:lo12:<symbol>]
     which has only one possible valid qualifier sequence
	NIL, S_D
     the caller may pass NIL in KNOWN_QLF to obtain S_D so that it can
     determine the correct relocation type (i.e. LDST64_LO12) for PRFM.

     Because the qualifier NIL has dual roles in the qualifier sequence:
     it can mean no qualifier for the operand, or the qualifer sequence is
     not in use (when all qualifiers in the sequence are NILs), we have to
     handle this special case here.  */
  if (known_qlf == AARCH64_OPND_NIL)
    {
      assert (qseq_list[0][known_idx] == AARCH64_OPND_NIL);
      return qseq_list[0][idx];
    }

  for (i = 0, saved_i = -1; i < AARCH64_MAX_QLF_SEQ_NUM; ++i)
    {
      if (qseq_list[i][known_idx] == known_qlf)
	{
	  if (saved_i != -1)
	    /* More than one sequences are found to have KNOWN_QLF at
	       KNOWN_IDX.  */
	    return AARCH64_OPND_NIL;
	  saved_i = i;
	}
    }

  return qseq_list[saved_i][idx];
}

enum operand_qualifier_kind
{
  OQK_NIL,
  OQK_OPD_VARIANT,
  OQK_VALUE_IN_RANGE,
  OQK_MISC,
};

/* Operand qualifier description.  */
struct operand_qualifier_data
{
  /* The usage of the three data fields depends on the qualifier kind.  */
  int data0;
  int data1;
  int data2;
  /* Description.  */
  const char *desc;
  /* Kind.  */
  enum operand_qualifier_kind kind;
};

/* Indexed by the operand qualifier enumerators.  */
struct operand_qualifier_data aarch64_opnd_qualifiers[] =
{
  {0, 0, 0, "NIL", OQK_NIL},

  /* Operand variant qualifiers.
     First 3 fields:
     element size, number of elements and common value for encoding.  */

  {4, 1, 0x0, "w", OQK_OPD_VARIANT},
  {8, 1, 0x1, "x", OQK_OPD_VARIANT},
  {4, 1, 0x0, "wsp", OQK_OPD_VARIANT},
  {8, 1, 0x1, "sp", OQK_OPD_VARIANT},

  {1, 1, 0x0, "b", OQK_OPD_VARIANT},
  {2, 1, 0x1, "h", OQK_OPD_VARIANT},
  {4, 1, 0x2, "s", OQK_OPD_VARIANT},
  {8, 1, 0x3, "d", OQK_OPD_VARIANT},
  {16, 1, 0x4, "q", OQK_OPD_VARIANT},

  {1, 8, 0x0, "8b", OQK_OPD_VARIANT},
  {1, 16, 0x1, "16b", OQK_OPD_VARIANT},
  {2, 4, 0x2, "4h", OQK_OPD_VARIANT},
  {2, 8, 0x3, "8h", OQK_OPD_VARIANT},
  {4, 2, 0x4, "2s", OQK_OPD_VARIANT},
  {4, 4, 0x5, "4s", OQK_OPD_VARIANT},
  {8, 1, 0x6, "1d", OQK_OPD_VARIANT},
  {8, 2, 0x7, "2d", OQK_OPD_VARIANT},
  {16, 1, 0x8, "1q", OQK_OPD_VARIANT},

  /* Qualifiers constraining the value range.
     First 3 fields:
     Lower bound, higher bound, unused.  */

  {0,  7, 0, "imm_0_7" , OQK_VALUE_IN_RANGE},
  {0, 15, 0, "imm_0_15", OQK_VALUE_IN_RANGE},
  {0, 31, 0, "imm_0_31", OQK_VALUE_IN_RANGE},
  {0, 63, 0, "imm_0_63", OQK_VALUE_IN_RANGE},
  {1, 32, 0, "imm_1_32", OQK_VALUE_IN_RANGE},
  {1, 64, 0, "imm_1_64", OQK_VALUE_IN_RANGE},

  /* Qualifiers for miscellaneous purpose.
     First 3 fields:
     unused, unused and unused.  */

  {0, 0, 0, "lsl", 0},
  {0, 0, 0, "msl", 0},

  {0, 0, 0, "retrieving", 0},
};

static inline bfd_boolean
operand_variant_qualifier_p (aarch64_opnd_qualifier_t qualifier)
{
  return (aarch64_opnd_qualifiers[qualifier].kind == OQK_OPD_VARIANT)
    ? TRUE : FALSE;
}

static inline bfd_boolean
qualifier_value_in_range_constraint_p (aarch64_opnd_qualifier_t qualifier)
{
  return (aarch64_opnd_qualifiers[qualifier].kind == OQK_VALUE_IN_RANGE)
    ? TRUE : FALSE;
}

const char*
aarch64_get_qualifier_name (aarch64_opnd_qualifier_t qualifier)
{
  return aarch64_opnd_qualifiers[qualifier].desc;
}

/* Given an operand qualifier, return the expected data element size
   of a qualified operand.  */
unsigned char
aarch64_get_qualifier_esize (aarch64_opnd_qualifier_t qualifier)
{
  assert (operand_variant_qualifier_p (qualifier) == TRUE);
  return aarch64_opnd_qualifiers[qualifier].data0;
}

unsigned char
aarch64_get_qualifier_nelem (aarch64_opnd_qualifier_t qualifier)
{
  assert (operand_variant_qualifier_p (qualifier) == TRUE);
  return aarch64_opnd_qualifiers[qualifier].data1;
}

aarch64_insn
aarch64_get_qualifier_standard_value (aarch64_opnd_qualifier_t qualifier)
{
  assert (operand_variant_qualifier_p (qualifier) == TRUE);
  return aarch64_opnd_qualifiers[qualifier].data2;
}

static int
get_lower_bound (aarch64_opnd_qualifier_t qualifier)
{
  assert (qualifier_value_in_range_constraint_p (qualifier) == TRUE);
  return aarch64_opnd_qualifiers[qualifier].data0;
}

static int
get_upper_bound (aarch64_opnd_qualifier_t qualifier)
{
  assert (qualifier_value_in_range_constraint_p (qualifier) == TRUE);
  return aarch64_opnd_qualifiers[qualifier].data1;
}

#ifdef DEBUG_AARCH64
void
aarch64_verbose (const char *str, ...)
{
  va_list ap;
  va_start (ap, str);
  printf ("#### ");
  vprintf (str, ap);
  printf ("\n");
  va_end (ap);
}

static inline void
dump_qualifier_sequence (const aarch64_opnd_qualifier_t *qualifier)
{
  int i;
  printf ("#### ");
  for (i = 0; i < AARCH64_MAX_OPND_NUM; ++i, ++qualifier)
    printf ("%s,", aarch64_get_qualifier_name (*qualifier));
  printf ("\n");
}

static void
dump_match_qualifiers (const struct aarch64_opnd_info *opnd,
		       const aarch64_opnd_qualifier_t *qualifier)
{
  int i;
  aarch64_opnd_qualifier_t curr[AARCH64_MAX_OPND_NUM];

  aarch64_verbose ("dump_match_qualifiers:");
  for (i = 0; i < AARCH64_MAX_OPND_NUM; ++i)
    curr[i] = opnd[i].qualifier;
  dump_qualifier_sequence (curr);
  aarch64_verbose ("against");
  dump_qualifier_sequence (qualifier);
}
#endif /* DEBUG_AARCH64 */

/* TODO improve this, we can have an extra field at the runtime to
   store the number of operands rather than calculating it every time.  */

int
aarch64_num_of_operands (const aarch64_opcode *opcode)
{
  int i = 0;
  const enum aarch64_opnd *opnds = opcode->operands;
  while (opnds[i++] != AARCH64_OPND_NIL)
    ;
  --i;
  assert (i >= 0 && i <= AARCH64_MAX_OPND_NUM);
  return i;
}

/* Find the best matched qualifier sequence in *QUALIFIERS_LIST for INST.
   If succeeds, fill the found sequence in *RET, return 1; otherwise return 0.

   N.B. on the entry, it is very likely that only some operands in *INST
   have had their qualifiers been established.

   If STOP_AT is not -1, the function will only try to match
   the qualifier sequence for operands before and including the operand
   of index STOP_AT; and on success *RET will only be filled with the first
   (STOP_AT+1) qualifiers.

   A couple examples of the matching algorithm:

   X,W,NIL should match
   X,W,NIL

   NIL,NIL should match
   X  ,NIL

   Apart from serving the main encoding routine, this can also be called
   during or after the operand decoding.  */

int
aarch64_find_best_match (const aarch64_inst *inst,
			 const aarch64_opnd_qualifier_seq_t *qualifiers_list,
			 int stop_at, aarch64_opnd_qualifier_t *ret)
{
  int found = 0;
  int i, num_opnds;
  const aarch64_opnd_qualifier_t *qualifiers;

  num_opnds = aarch64_num_of_operands (inst->opcode);
  if (num_opnds == 0)
    {
      DEBUG_TRACE ("SUCCEED: no operand");
      return 1;
    }

  if (stop_at < 0 || stop_at >= num_opnds)
    stop_at = num_opnds - 1;

  /* For each pattern.  */
  for (i = 0; i < AARCH64_MAX_QLF_SEQ_NUM; ++i, ++qualifiers_list)
    {
      int j;
      qualifiers = *qualifiers_list;

      /* Start as positive.  */
      found = 1;

      DEBUG_TRACE ("%d", i);
#ifdef DEBUG_AARCH64
      if (debug_dump)
	dump_match_qualifiers (inst->operands, qualifiers);
#endif

      /* Most opcodes has much fewer patterns in the list.
	 First NIL qualifier indicates the end in the list.   */
      if (empty_qualifier_sequence_p (qualifiers) == TRUE)
	{
	  DEBUG_TRACE_IF (i == 0, "SUCCEED: empty qualifier list");
	  if (i)
	    found = 0;
	  break;
	}

      for (j = 0; j < num_opnds && j <= stop_at; ++j, ++qualifiers)
	{
	  if (inst->operands[j].qualifier == AARCH64_OPND_QLF_NIL)
	    {
	      /* Either the operand does not have qualifier, or the qualifier
		 for the operand needs to be deduced from the qualifier
		 sequence.
		 In the latter case, any constraint checking related with
		 the obtained qualifier should be done later in
		 operand_general_constraint_met_p.  */
	      continue;
	    }
	  else if (*qualifiers != inst->operands[j].qualifier)
	    {
	      /* Unless the target qualifier can also qualify the operand
		 (which has already had a non-nil qualifier), non-equal
		 qualifiers are generally un-matched.  */
	      if (operand_also_qualified_p (inst->operands + j, *qualifiers))
		continue;
	      else
		{
		  found = 0;
		  break;
		}
	    }
	  else
	    continue;	/* Equal qualifiers are certainly matched.  */
	}

      /* Qualifiers established.  */
      if (found == 1)
	break;
    }

  if (found == 1)
    {
      /* Fill the result in *RET.  */
      int j;
      qualifiers = *qualifiers_list;

      DEBUG_TRACE ("complete qualifiers using list %d", i);
#ifdef DEBUG_AARCH64
      if (debug_dump)
	dump_qualifier_sequence (qualifiers);
#endif

      for (j = 0; j <= stop_at; ++j, ++qualifiers)
	ret[j] = *qualifiers;
      for (; j < AARCH64_MAX_OPND_NUM; ++j)
	ret[j] = AARCH64_OPND_QLF_NIL;

      DEBUG_TRACE ("SUCCESS");
      return 1;
    }

  DEBUG_TRACE ("FAIL");
  return 0;
}

/* Operand qualifier matching and resolving.

   Return 1 if the operand qualifier(s) in *INST match one of the qualifier
   sequences in INST->OPCODE->qualifiers_list; otherwise return 0.

   if UPDATE_P == TRUE, update the qualifier(s) in *INST after the matching
   succeeds.  */

static int
match_operands_qualifier (aarch64_inst *inst, bfd_boolean update_p)
{
  int i;
  aarch64_opnd_qualifier_seq_t qualifiers;

  if (!aarch64_find_best_match (inst, inst->opcode->qualifiers_list, -1,
			       qualifiers))
    {
      DEBUG_TRACE ("matching FAIL");
      return 0;
    }

  /* Update the qualifiers.  */
  if (update_p == TRUE)
    for (i = 0; i < AARCH64_MAX_OPND_NUM; ++i)
      {
	if (inst->opcode->operands[i] == AARCH64_OPND_NIL)
	  break;
	DEBUG_TRACE_IF (inst->operands[i].qualifier != qualifiers[i],
			"update %s with %s for operand %d",
			aarch64_get_qualifier_name (inst->operands[i].qualifier),
			aarch64_get_qualifier_name (qualifiers[i]), i);
	inst->operands[i].qualifier = qualifiers[i];
      }

  DEBUG_TRACE ("matching SUCCESS");
  return 1;
}

/* Return TRUE if VALUE is a wide constant that can be moved into a general
   register by MOVZ.

   IS32 indicates whether value is a 32-bit immediate or not.
   If SHIFT_AMOUNT is not NULL, on the return of TRUE, the logical left shift
   amount will be returned in *SHIFT_AMOUNT.  */

bfd_boolean
aarch64_wide_constant_p (int64_t value, int is32, unsigned int *shift_amount)
{
  int amount;

  DEBUG_TRACE ("enter with 0x%" PRIx64 "(%" PRIi64 ")", value, value);

  if (is32)
    {
      /* Allow all zeros or all ones in top 32-bits, so that
	 32-bit constant expressions like ~0x80000000 are
	 permitted.  */
      uint64_t ext = value;
      if (ext >> 32 != 0 && ext >> 32 != (uint64_t) 0xffffffff)
	/* Immediate out of range.  */
	return FALSE;
      value &= (int64_t) 0xffffffff;
    }

  /* first, try movz then movn */
  amount = -1;
  if ((value & ((int64_t) 0xffff << 0)) == value)
    amount = 0;
  else if ((value & ((int64_t) 0xffff << 16)) == value)
    amount = 16;
  else if (!is32 && (value & ((int64_t) 0xffff << 32)) == value)
    amount = 32;
  else if (!is32 && (value & ((int64_t) 0xffff << 48)) == value)
    amount = 48;

  if (amount == -1)
    {
      DEBUG_TRACE ("exit FALSE with 0x%" PRIx64 "(%" PRIi64 ")", value, value);
      return FALSE;
    }

  if (shift_amount != NULL)
    *shift_amount = amount;

  DEBUG_TRACE ("exit TRUE with amount %d", amount);

  return TRUE;
}

/* Build the accepted values for immediate logical SIMD instructions.

   The standard encodings of the immediate value are:
     N      imms     immr         SIMD size  R             S
     1      ssssss   rrrrrr       64      UInt(rrrrrr)  UInt(ssssss)
     0      0sssss   0rrrrr       32      UInt(rrrrr)   UInt(sssss)
     0      10ssss   00rrrr       16      UInt(rrrr)    UInt(ssss)
     0      110sss   000rrr       8       UInt(rrr)     UInt(sss)
     0      1110ss   0000rr       4       UInt(rr)      UInt(ss)
     0      11110s   00000r       2       UInt(r)       UInt(s)
   where all-ones value of S is reserved.

   Let's call E the SIMD size.

   The immediate value is: S+1 bits '1' rotated to the right by R.

   The total of valid encodings is 64*63 + 32*31 + ... + 2*1 = 5334
   (remember S != E - 1).  */

#define TOTAL_IMM_NB  5334

typedef struct
{
  uint64_t imm;
  aarch64_insn encoding;
} simd_imm_encoding;

static simd_imm_encoding simd_immediates[TOTAL_IMM_NB];

static int
simd_imm_encoding_cmp(const void *i1, const void *i2)
{
  const simd_imm_encoding *imm1 = (const simd_imm_encoding *)i1;
  const simd_imm_encoding *imm2 = (const simd_imm_encoding *)i2;

  if (imm1->imm < imm2->imm)
    return -1;
  if (imm1->imm > imm2->imm)
    return +1;
  return 0;
}

/* immediate bitfield standard encoding
   imm13<12> imm13<5:0> imm13<11:6> SIMD size R      S
   1         ssssss     rrrrrr      64        rrrrrr ssssss
   0         0sssss     0rrrrr      32        rrrrr  sssss
   0         10ssss     00rrrr      16        rrrr   ssss
   0         110sss     000rrr      8         rrr    sss
   0         1110ss     0000rr      4         rr     ss
   0         11110s     00000r      2         r      s  */
static inline int
encode_immediate_bitfield (int is64, uint32_t s, uint32_t r)
{
  return (is64 << 12) | (r << 6) | s;
}

static void
build_immediate_table (void)
{
  uint32_t log_e, e, s, r, s_mask;
  uint64_t mask, imm;
  int nb_imms;
  int is64;

  nb_imms = 0;
  for (log_e = 1; log_e <= 6; log_e++)
    {
      /* Get element size.  */
      e = 1u << log_e;
      if (log_e == 6)
	{
	  is64 = 1;
	  mask = 0xffffffffffffffffull;
	  s_mask = 0;
	}
      else
	{
	  is64 = 0;
	  mask = (1ull << e) - 1;
	  /* log_e  s_mask
	     1     ((1 << 4) - 1) << 2 = 111100
	     2     ((1 << 3) - 1) << 3 = 111000
	     3     ((1 << 2) - 1) << 4 = 110000
	     4     ((1 << 1) - 1) << 5 = 100000
	     5     ((1 << 0) - 1) << 6 = 000000  */
	  s_mask = ((1u << (5 - log_e)) - 1) << (log_e + 1);
	}
      for (s = 0; s < e - 1; s++)
	for (r = 0; r < e; r++)
	  {
	    /* s+1 consecutive bits to 1 (s < 63) */
	    imm = (1ull << (s + 1)) - 1;
	    /* rotate right by r */
	    if (r != 0)
	      imm = (imm >> r) | ((imm << (e - r)) & mask);
	    /* replicate the constant depending on SIMD size */
	    switch (log_e)
	      {
	      case 1: imm = (imm <<  2) | imm;
	      case 2: imm = (imm <<  4) | imm;
	      case 3: imm = (imm <<  8) | imm;
	      case 4: imm = (imm << 16) | imm;
	      case 5: imm = (imm << 32) | imm;
	      case 6: break;
	      default: abort ();
	      }
	    simd_immediates[nb_imms].imm = imm;
	    simd_immediates[nb_imms].encoding =
	      encode_immediate_bitfield(is64, s | s_mask, r);
	    nb_imms++;
	  }
    }
  assert (nb_imms == TOTAL_IMM_NB);
  qsort(simd_immediates, nb_imms,
	sizeof(simd_immediates[0]), simd_imm_encoding_cmp);
}

/* Return TRUE if VALUE is a valid logical immediate, i.e. bitmask, that can
   be accepted by logical (immediate) instructions
   e.g. ORR <Xd|SP>, <Xn>, #<imm>.

   IS32 indicates whether or not VALUE is a 32-bit immediate.
   If ENCODING is not NULL, on the return of TRUE, the standard encoding for
   VALUE will be returned in *ENCODING.  */

bfd_boolean
aarch64_logical_immediate_p (uint64_t value, int is32, aarch64_insn *encoding)
{
  simd_imm_encoding imm_enc;
  const simd_imm_encoding *imm_encoding;
  static bfd_boolean initialized = FALSE;

  DEBUG_TRACE ("enter with 0x%" PRIx64 "(%" PRIi64 "), is32: %d", value,
	       value, is32);

  if (initialized == FALSE)
    {
      build_immediate_table ();
      initialized = TRUE;
    }

  if (is32)
    {
      /* Allow all zeros or all ones in top 32-bits, so that
	 constant expressions like ~1 are permitted.  */
      if (value >> 32 != 0 && value >> 32 != 0xffffffff)
	return 0xffffffff;
      /* Replicate the 32 lower bits to the 32 upper bits.  */
      value &= 0xffffffff;
      value |= value << 32;
    }

  imm_enc.imm = value;
  imm_encoding = (const simd_imm_encoding *)
    bsearch(&imm_enc, simd_immediates, TOTAL_IMM_NB,
            sizeof(simd_immediates[0]), simd_imm_encoding_cmp);
  if (imm_encoding == NULL)
    {
      DEBUG_TRACE ("exit with FALSE");
      return FALSE;
    }
  if (encoding != NULL)
    *encoding = imm_encoding->encoding;
  DEBUG_TRACE ("exit with TRUE");
  return TRUE;
}

/* If 64-bit immediate IMM is in the format of
   "aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffffgggggggghhhhhhhh",
   where a, b, c, d, e, f, g and h are independently 0 or 1, return an integer
   of value "abcdefgh".  Otherwise return -1.  */
int
aarch64_shrink_expanded_imm8 (uint64_t imm)
{
  int i, ret;
  uint32_t byte;

  ret = 0;
  for (i = 0; i < 8; i++)
    {
      byte = (imm >> (8 * i)) & 0xff;
      if (byte == 0xff)
	ret |= 1 << i;
      else if (byte != 0x00)
	return -1;
    }
  return ret;
}

/* Utility inline functions for operand_general_constraint_met_p.  */

static inline void
set_error (aarch64_operand_error *mismatch_detail,
	   enum aarch64_operand_error_kind kind, int idx,
	   const char* error)
{
  if (mismatch_detail == NULL)
    return;
  mismatch_detail->kind = kind;
  mismatch_detail->index = idx;
  mismatch_detail->error = error;
}

static inline void
set_out_of_range_error (aarch64_operand_error *mismatch_detail,
			int idx, int lower_bound, int upper_bound,
			const char* error)
{
  if (mismatch_detail == NULL)
    return;
  set_error (mismatch_detail, AARCH64_OPDE_OUT_OF_RANGE, idx, error);
  mismatch_detail->data[0] = lower_bound;
  mismatch_detail->data[1] = upper_bound;
}

static inline void
set_imm_out_of_range_error (aarch64_operand_error *mismatch_detail,
			    int idx, int lower_bound, int upper_bound)
{
  if (mismatch_detail == NULL)
    return;
  set_out_of_range_error (mismatch_detail, idx, lower_bound, upper_bound,
			  _("immediate value"));
}

static inline void
set_offset_out_of_range_error (aarch64_operand_error *mismatch_detail,
			       int idx, int lower_bound, int upper_bound)
{
  if (mismatch_detail == NULL)
    return;
  set_out_of_range_error (mismatch_detail, idx, lower_bound, upper_bound,
			  _("immediate offset"));
}

static inline void
set_regno_out_of_range_error (aarch64_operand_error *mismatch_detail,
			      int idx, int lower_bound, int upper_bound)
{
  if (mismatch_detail == NULL)
    return;
  set_out_of_range_error (mismatch_detail, idx, lower_bound, upper_bound,
			  _("register number"));
}

static inline void
set_elem_idx_out_of_range_error (aarch64_operand_error *mismatch_detail,
				 int idx, int lower_bound, int upper_bound)
{
  if (mismatch_detail == NULL)
    return;
  set_out_of_range_error (mismatch_detail, idx, lower_bound, upper_bound,
			  _("register element index"));
}

static inline void
set_sft_amount_out_of_range_error (aarch64_operand_error *mismatch_detail,
				   int idx, int lower_bound, int upper_bound)
{
  if (mismatch_detail == NULL)
    return;
  set_out_of_range_error (mismatch_detail, idx, lower_bound, upper_bound,
			  _("shift amount"));
}

static inline void
set_unaligned_error (aarch64_operand_error *mismatch_detail, int idx,
		     int alignment)
{
  if (mismatch_detail == NULL)
    return;
  set_error (mismatch_detail, AARCH64_OPDE_UNALIGNED, idx, NULL);
  mismatch_detail->data[0] = alignment;
}

static inline void
set_reg_list_error (aarch64_operand_error *mismatch_detail, int idx,
		    int expected_num)
{
  if (mismatch_detail == NULL)
    return;
  set_error (mismatch_detail, AARCH64_OPDE_REG_LIST, idx, NULL);
  mismatch_detail->data[0] = expected_num;
}

static inline void
set_other_error (aarch64_operand_error *mismatch_detail, int idx,
		 const char* error)
{
  if (mismatch_detail == NULL)
    return;
  set_error (mismatch_detail, AARCH64_OPDE_OTHER_ERROR, idx, error);
}

/* General constraint checking based on operand code.

   Return 1 if OPNDS[IDX] meets the general constraint of operand code TYPE
   as the IDXth operand of opcode OPCODE.  Otherwise return 0.

   This function has to be called after the qualifiers for all operands
   have been resolved.

   Mismatching error message is returned in *MISMATCH_DETAIL upon request,
   i.e. when MISMATCH_DETAIL is non-NULL.  This avoids the generation
   of error message during the disassembling where error message is not
   wanted.  We avoid the dynamic construction of strings of error messages
   here (i.e. in libopcodes), as it is costly and complicated; instead, we
   use a combination of error code, static string and some integer data to
   represent an error.  */

static int
operand_general_constraint_met_p (const aarch64_opnd_info *opnds, int idx,
				  enum aarch64_opnd type,
				  const aarch64_opcode *opcode,
				  aarch64_operand_error *mismatch_detail)
{
  unsigned num;
  unsigned char size;
  int64_t imm;
  const aarch64_opnd_info *opnd = opnds + idx;
  aarch64_opnd_qualifier_t qualifier = opnd->qualifier;

  assert (opcode->operands[idx] == opnd->type && opnd->type == type);

  switch (aarch64_operands[type].op_class)
    {
    case AARCH64_OPND_CLASS_INT_REG:
      /* <Xt> may be optional in some IC and TLBI instructions.  */
      if (type == AARCH64_OPND_Rt_SYS)
	{
	  assert (idx == 1 && (aarch64_get_operand_class (opnds[0].type)
			       == AARCH64_OPND_CLASS_SYSTEM));
	  if (opnds[1].present && !opnds[0].sysins_op->has_xt)
	    {
	      set_other_error (mismatch_detail, idx, _("extraneous register"));
	      return 0;
	    }
	  if (!opnds[1].present && opnds[0].sysins_op->has_xt)
	    {
	      set_other_error (mismatch_detail, idx, _("missing register"));
	      return 0;
	    }
	}
      switch (qualifier)
	{
	case AARCH64_OPND_QLF_WSP:
	case AARCH64_OPND_QLF_SP:
	  if (!aarch64_stack_pointer_p (opnd))
	    {
	      set_other_error (mismatch_detail, idx,
			       _("stack pointer register expected"));
	      return 0;
	    }
	  break;
	default:
	  break;
	}
      break;

    case AARCH64_OPND_CLASS_ADDRESS:
      /* Check writeback.  */
      switch (opcode->iclass)
	{
	case ldst_pos:
	case ldst_unscaled:
	case ldstnapair_offs:
	case ldstpair_off:
	case ldst_unpriv:
	  if (opnd->addr.writeback == 1)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("unexpected address writeback"));
	      return 0;
	    }
	  break;
	case ldst_imm9:
	case ldstpair_indexed:
	case asisdlsep:
	case asisdlsop:
	  if (opnd->addr.writeback == 0)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("address writeback expected"));
	      return 0;
	    }
	  break;
	default:
	  assert (opnd->addr.writeback == 0);
	  break;
	}
      switch (type)
	{
	case AARCH64_OPND_ADDR_SIMM7:
	  /* Scaled signed 7 bits immediate offset.  */
	  /* Get the size of the data element that is accessed, which may be
	     different from that of the source register size,
	     e.g. in strb/ldrb.  */
	  size = aarch64_get_qualifier_esize (opnd->qualifier);
	  if (!value_in_range_p (opnd->addr.offset.imm, -64 * size, 63 * size))
	    {
	      set_offset_out_of_range_error (mismatch_detail, idx,
					     -64 * size, 63 * size);
	      return 0;
	    }
	  if (!value_aligned_p (opnd->addr.offset.imm, size))
	    {
	      set_unaligned_error (mismatch_detail, idx, size);
	      return 0;
	    }
	  break;
	case AARCH64_OPND_ADDR_SIMM9:
	  /* Unscaled signed 9 bits immediate offset.  */
	  if (!value_in_range_p (opnd->addr.offset.imm, -256, 255))
	    {
	      set_offset_out_of_range_error (mismatch_detail, idx, -256, 255);
	      return 0;
	    }
	  break;

	case AARCH64_OPND_ADDR_SIMM9_2:
	  /* Unscaled signed 9 bits immediate offset, which has to be negative
	     or unaligned.  */
	  size = aarch64_get_qualifier_esize (qualifier);
	  if ((value_in_range_p (opnd->addr.offset.imm, 0, 255)
	       && !value_aligned_p (opnd->addr.offset.imm, size))
	      || value_in_range_p (opnd->addr.offset.imm, -256, -1))
	    return 1;
	  set_other_error (mismatch_detail, idx,
			   _("negative or unaligned offset expected"));
	  return 0;

	case AARCH64_OPND_SIMD_ADDR_POST:
	  /* AdvSIMD load/store multiple structures, post-index.  */
	  assert (idx == 1);
	  if (opnd->addr.offset.is_reg)
	    {
	      if (value_in_range_p (opnd->addr.offset.regno, 0, 30))
		return 1;
	      else
		{
		  set_other_error (mismatch_detail, idx,
				   _("invalid register offset"));
		  return 0;
		}
	    }
	  else
	    {
	      const aarch64_opnd_info *prev = &opnds[idx-1];
	      unsigned num_bytes; /* total number of bytes transferred.  */
	      /* The opcode dependent area stores the number of elements in
		 each structure to be loaded/stored.  */
	      int is_ld1r = get_opcode_dependent_value (opcode) == 1;
	      if (opcode->operands[0] == AARCH64_OPND_LVt_AL)
		/* Special handling of loading single structure to all lane.  */
		num_bytes = (is_ld1r ? 1 : prev->reglist.num_regs)
		  * aarch64_get_qualifier_esize (prev->qualifier);
	      else
		num_bytes = prev->reglist.num_regs
		  * aarch64_get_qualifier_esize (prev->qualifier)
		  * aarch64_get_qualifier_nelem (prev->qualifier);
	      if ((int) num_bytes != opnd->addr.offset.imm)
		{
		  set_other_error (mismatch_detail, idx,
				   _("invalid post-increment amount"));
		  return 0;
		}
	    }
	  break;

	case AARCH64_OPND_ADDR_REGOFF:
	  /* Get the size of the data element that is accessed, which may be
	     different from that of the source register size,
	     e.g. in strb/ldrb.  */
	  size = aarch64_get_qualifier_esize (opnd->qualifier);
	  /* It is either no shift or shift by the binary logarithm of SIZE.  */
	  if (opnd->shifter.amount != 0
	      && opnd->shifter.amount != (int)get_logsz (size))
	    {
	      set_other_error (mismatch_detail, idx,
			       _("invalid shift amount"));
	      return 0;
	    }
	  /* Only UXTW, LSL, SXTW and SXTX are the accepted extending
	     operators.  */
	  switch (opnd->shifter.kind)
	    {
	    case AARCH64_MOD_UXTW:
	    case AARCH64_MOD_LSL:
	    case AARCH64_MOD_SXTW:
	    case AARCH64_MOD_SXTX: break;
	    default:
	      set_other_error (mismatch_detail, idx,
			       _("invalid extend/shift operator"));
	      return 0;
	    }
	  break;

	case AARCH64_OPND_ADDR_UIMM12:
	  imm = opnd->addr.offset.imm;
	  /* Get the size of the data element that is accessed, which may be
	     different from that of the source register size,
	     e.g. in strb/ldrb.  */
	  size = aarch64_get_qualifier_esize (qualifier);
	  if (!value_in_range_p (opnd->addr.offset.imm, 0, 4095 * size))
	    {
	      set_offset_out_of_range_error (mismatch_detail, idx,
					     0, 4095 * size);
	      return 0;
	    }
	  if (!value_aligned_p (opnd->addr.offset.imm, size))
	    {
	      set_unaligned_error (mismatch_detail, idx, size);
	      return 0;
	    }
	  break;

	case AARCH64_OPND_ADDR_PCREL14:
	case AARCH64_OPND_ADDR_PCREL19:
	case AARCH64_OPND_ADDR_PCREL21:
	case AARCH64_OPND_ADDR_PCREL26:
	  imm = opnd->imm.value;
	  if (operand_need_shift_by_two (get_operand_from_code (type)))
	    {
	      /* The offset value in a PC-relative branch instruction is alway
		 4-byte aligned and is encoded without the lowest 2 bits.  */
	      if (!value_aligned_p (imm, 4))
		{
		  set_unaligned_error (mismatch_detail, idx, 4);
		  return 0;
		}
	      /* Right shift by 2 so that we can carry out the following check
		 canonically.  */
	      imm >>= 2;
	    }
	  size = get_operand_fields_width (get_operand_from_code (type));
	  if (!value_fit_signed_field_p (imm, size))
	    {
	      set_other_error (mismatch_detail, idx,
			       _("immediate out of range"));
	      return 0;
	    }
	  break;

	default:
	  break;
	}
      break;

    case AARCH64_OPND_CLASS_SIMD_REGLIST:
      /* The opcode dependent area stores the number of elements in
	 each structure to be loaded/stored.  */
      num = get_opcode_dependent_value (opcode);
      switch (type)
	{
	case AARCH64_OPND_LVt:
	  assert (num >= 1 && num <= 4);
	  /* Unless LD1/ST1, the number of registers should be equal to that
	     of the structure elements.  */
	  if (num != 1 && opnd->reglist.num_regs != num)
	    {
	      set_reg_list_error (mismatch_detail, idx, num);
	      return 0;
	    }
	  break;
	case AARCH64_OPND_LVt_AL:
	case AARCH64_OPND_LEt:
	  assert (num >= 1 && num <= 4);
	  /* The number of registers should be equal to that of the structure
	     elements.  */
	  if (opnd->reglist.num_regs != num)
	    {
	      set_reg_list_error (mismatch_detail, idx, num);
	      return 0;
	    }
	  break;
	default:
	  break;
	}
      break;

    case AARCH64_OPND_CLASS_IMMEDIATE:
      /* Constraint check on immediate operand.  */
      imm = opnd->imm.value;
      /* E.g. imm_0_31 constrains value to be 0..31.  */
      if (qualifier_value_in_range_constraint_p (qualifier)
	  && !value_in_range_p (imm, get_lower_bound (qualifier),
				get_upper_bound (qualifier)))
	{
	  set_imm_out_of_range_error (mismatch_detail, idx,
				      get_lower_bound (qualifier),
				      get_upper_bound (qualifier));
	  return 0;
	}

      switch (type)
	{
	case AARCH64_OPND_AIMM:
	  if (opnd->shifter.kind != AARCH64_MOD_LSL)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("invalid shift operator"));
	      return 0;
	    }
	  if (opnd->shifter.amount != 0 && opnd->shifter.amount != 12)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("shift amount expected to be 0 or 12"));
	      return 0;
	    }
	  if (!value_fit_unsigned_field_p (opnd->imm.value, 12))
	    {
	      set_other_error (mismatch_detail, idx,
			       _("immediate out of range"));
	      return 0;
	    }
	  break;

	case AARCH64_OPND_HALF:
	  assert (idx == 1 && opnds[0].type == AARCH64_OPND_Rd);
	  if (opnd->shifter.kind != AARCH64_MOD_LSL)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("invalid shift operator"));
	      return 0;
	    }
	  size = aarch64_get_qualifier_esize (opnds[0].qualifier);
	  if (!value_aligned_p (opnd->shifter.amount, 16))
	    {
	      set_other_error (mismatch_detail, idx,
			       _("shift amount should be a multiple of 16"));
	      return 0;
	    }
	  if (!value_in_range_p (opnd->shifter.amount, 0, size * 8 - 16))
	    {
	      set_sft_amount_out_of_range_error (mismatch_detail, idx,
						 0, size * 8 - 16);
	      return 0;
	    }
	  if (opnd->imm.value < 0)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("negative immediate value not allowed"));
	      return 0;
	    }
	  if (!value_fit_unsigned_field_p (opnd->imm.value, 16))
	    {
	      set_other_error (mismatch_detail, idx,
			       _("immediate out of range"));
	      return 0;
	    }
	  break;

	case AARCH64_OPND_IMM_MOV:
	    {
	      int is32 = aarch64_get_qualifier_esize (opnds[0].qualifier) == 4;
	      imm = opnd->imm.value;
	      assert (idx == 1);
	      switch (opcode->op)
		{
		case OP_MOV_IMM_WIDEN:
		  imm = ~imm;
		  /* Fall through...  */
		case OP_MOV_IMM_WIDE:
		  if (!aarch64_wide_constant_p (imm, is32, NULL))
		    {
		      set_other_error (mismatch_detail, idx,
				       _("immediate out of range"));
		      return 0;
		    }
		  break;
		case OP_MOV_IMM_LOG:
		  if (!aarch64_logical_immediate_p (imm, is32, NULL))
		    {
		      set_other_error (mismatch_detail, idx,
				       _("immediate out of range"));
		      return 0;
		    }
		  break;
		default:
		  assert (0);
		  return 0;
		}
	    }
	  break;

	case AARCH64_OPND_NZCV:
	case AARCH64_OPND_CCMP_IMM:
	case AARCH64_OPND_EXCEPTION:
	case AARCH64_OPND_UIMM4:
	case AARCH64_OPND_UIMM7:
	case AARCH64_OPND_UIMM3_OP1:
	case AARCH64_OPND_UIMM3_OP2:
	  size = get_operand_fields_width (get_operand_from_code (type));
	  assert (size < 32);
	  if (!value_fit_unsigned_field_p (opnd->imm.value, size))
	    {
	      set_imm_out_of_range_error (mismatch_detail, idx, 0,
					  (1 << size) - 1);
	      return 0;
	    }
	  break;

	case AARCH64_OPND_WIDTH:
	  assert (idx == 3 && opnds[idx-1].type == AARCH64_OPND_IMM
		  && opnds[0].type == AARCH64_OPND_Rd);
	  size = get_upper_bound (qualifier);
	  if (opnd->imm.value + opnds[idx-1].imm.value > size)
	    /* lsb+width <= reg.size  */
	    {
	      set_imm_out_of_range_error (mismatch_detail, idx, 1,
					  size - opnds[idx-1].imm.value);
	      return 0;
	    }
	  break;

	case AARCH64_OPND_LIMM:
	    {
	      int is32 = opnds[0].qualifier == AARCH64_OPND_QLF_W;
	      uint64_t uimm = opnd->imm.value;
	      if (opcode->op == OP_BIC)
		uimm = ~uimm;
	      if (aarch64_logical_immediate_p (uimm, is32, NULL) == FALSE)
		{
		  set_other_error (mismatch_detail, idx,
				   _("immediate out of range"));
		  return 0;
		}
	    }
	  break;

	case AARCH64_OPND_IMM0:
	case AARCH64_OPND_FPIMM0:
	  if (opnd->imm.value != 0)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("immediate zero expected"));
	      return 0;
	    }
	  break;

	case AARCH64_OPND_SHLL_IMM:
	  assert (idx == 2);
	  size = 8 * aarch64_get_qualifier_esize (opnds[idx - 1].qualifier);
	  if (opnd->imm.value != size)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("invalid shift amount"));
	      return 0;
	    }
	  break;

	case AARCH64_OPND_IMM_VLSL:
	  size = aarch64_get_qualifier_esize (qualifier);
	  if (!value_in_range_p (opnd->imm.value, 0, size * 8 - 1))
	    {
	      set_imm_out_of_range_error (mismatch_detail, idx, 0,
					  size * 8 - 1);
	      return 0;
	    }
	  break;

	case AARCH64_OPND_IMM_VLSR:
	  size = aarch64_get_qualifier_esize (qualifier);
	  if (!value_in_range_p (opnd->imm.value, 1, size * 8))
	    {
	      set_imm_out_of_range_error (mismatch_detail, idx, 1, size * 8);
	      return 0;
	    }
	  break;

	case AARCH64_OPND_SIMD_IMM:
	case AARCH64_OPND_SIMD_IMM_SFT:
	  /* Qualifier check.  */
	  switch (qualifier)
	    {
	    case AARCH64_OPND_QLF_LSL:
	      if (opnd->shifter.kind != AARCH64_MOD_LSL)
		{
		  set_other_error (mismatch_detail, idx,
				   _("invalid shift operator"));
		  return 0;
		}
	      break;
	    case AARCH64_OPND_QLF_MSL:
	      if (opnd->shifter.kind != AARCH64_MOD_MSL)
		{
		  set_other_error (mismatch_detail, idx,
				   _("invalid shift operator"));
		  return 0;
		}
	      break;
	    case AARCH64_OPND_QLF_NIL:
	      if (opnd->shifter.kind != AARCH64_MOD_NONE)
		{
		  set_other_error (mismatch_detail, idx,
				   _("shift is not permitted"));
		  return 0;
		}
	      break;
	    default:
	      assert (0);
	      return 0;
	    }
	  /* Is the immediate valid?  */
	  assert (idx == 1);
	  if (aarch64_get_qualifier_esize (opnds[0].qualifier) != 8)
	    {
	      /* uimm8 or simm8 */
	      if (!value_in_range_p (opnd->imm.value, -128, 255))
		{
		  set_imm_out_of_range_error (mismatch_detail, idx, -128, 255);
		  return 0;
		}
	    }
	  else if (aarch64_shrink_expanded_imm8 (opnd->imm.value) < 0)
	    {
	      /* uimm64 is not
		 'aaaaaaaabbbbbbbbccccccccddddddddeeeeeeee
		 ffffffffgggggggghhhhhhhh'.  */
	      set_other_error (mismatch_detail, idx,
			       _("invalid value for immediate"));
	      return 0;
	    }
	  /* Is the shift amount valid?  */
	  switch (opnd->shifter.kind)
	    {
	    case AARCH64_MOD_LSL:
	      size = aarch64_get_qualifier_esize (opnds[0].qualifier);
	      if (!value_in_range_p (opnd->shifter.amount, 0, (size - 1) * 8))
		{
		  set_sft_amount_out_of_range_error (mismatch_detail, idx, 0,
						     (size - 1) * 8);
		  return 0;
		}
	      if (!value_aligned_p (opnd->shifter.amount, 8))
		{
		  set_unaligned_error (mismatch_detail, idx, 8);
		  return 0;
		}
	      break;
	    case AARCH64_MOD_MSL:
	      /* Only 8 and 16 are valid shift amount.  */
	      if (opnd->shifter.amount != 8 && opnd->shifter.amount != 16)
		{
		  set_other_error (mismatch_detail, idx,
				   _("shift amount expected to be 0 or 16"));
		  return 0;
		}
	      break;
	    default:
	      if (opnd->shifter.kind != AARCH64_MOD_NONE)
		{
		  set_other_error (mismatch_detail, idx,
				   _("invalid shift operator"));
		  return 0;
		}
	      break;
	    }
	  break;

	case AARCH64_OPND_FPIMM:
	case AARCH64_OPND_SIMD_FPIMM:
	  if (opnd->imm.is_fp == 0)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("floating-point immediate expected"));
	      return 0;
	    }
	  /* The value is expected to be an 8-bit floating-point constant with
	     sign, 3-bit exponent and normalized 4 bits of precision, encoded
	     in "a:b:c:d:e:f:g:h" or FLD_imm8 (depending on the type of the
	     instruction).  */
	  if (!value_in_range_p (opnd->imm.value, 0, 255))
	    {
	      set_other_error (mismatch_detail, idx,
			       _("immediate out of range"));
	      return 0;
	    }
	  if (opnd->shifter.kind != AARCH64_MOD_NONE)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("invalid shift operator"));
	      return 0;
	    }
	  break;

	default:
	  break;
	}
      break;

    case AARCH64_OPND_CLASS_CP_REG:
      /* Cn or Cm: 4-bit opcode field named for historical reasons.
	 valid range: C0 - C15.  */
      if (opnd->reg.regno > 15)
	{
	  set_regno_out_of_range_error (mismatch_detail, idx, 0, 15);
	  return 0;
	}
      break;

    case AARCH64_OPND_CLASS_SYSTEM:
      switch (type)
	{
	case AARCH64_OPND_PSTATEFIELD:
	  assert (idx == 0 && opnds[1].type == AARCH64_OPND_UIMM4);
	  /* MSR SPSel, #uimm4
	     Uses uimm4 as a control value to select the stack pointer: if
	     bit 0 is set it selects the current exception level's stack
	     pointer, if bit 0 is clear it selects shared EL0 stack pointer.
	     Bits 1 to 3 of uimm4 are reserved and should be zero.  */
	  if (opnd->pstatefield == 0x05 /* spsel */ && opnds[1].imm.value > 1)
	    {
	      set_imm_out_of_range_error (mismatch_detail, idx, 0, 1);
	      return 0;
	    }
	  break;
	default:
	  break;
	}
      break;

    case AARCH64_OPND_CLASS_SIMD_ELEMENT:
      /* Get the upper bound for the element index.  */
      num = 16 / aarch64_get_qualifier_esize (qualifier) - 1;
      /* Index out-of-range.  */
      if (!value_in_range_p (opnd->reglane.index, 0, num))
	{
	  set_elem_idx_out_of_range_error (mismatch_detail, idx, 0, num);
	  return 0;
	}
      /* SMLAL<Q> <Vd>.<Ta>, <Vn>.<Tb>, <Vm>.<Ts>[<index>].
	 <Vm>	Is the vector register (V0-V31) or (V0-V15), whose
	 number is encoded in "size:M:Rm":
	 size	<Vm>
	 00		RESERVED
	 01		0:Rm
	 10		M:Rm
	 11		RESERVED  */
      if (type == AARCH64_OPND_Em && qualifier == AARCH64_OPND_QLF_S_H
	  && !value_in_range_p (opnd->reglane.regno, 0, 15))
	{
	  set_regno_out_of_range_error (mismatch_detail, idx, 0, 15);
	  return 0;
	}
      break;

    case AARCH64_OPND_CLASS_MODIFIED_REG:
      assert (idx == 1 || idx == 2);
      switch (type)
	{
	case AARCH64_OPND_Rm_EXT:
	  if (aarch64_extend_operator_p (opnd->shifter.kind) == FALSE
	      && opnd->shifter.kind != AARCH64_MOD_LSL)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("extend operator expected"));
	      return 0;
	    }
	  /* It is not optional unless at least one of "Rd" or "Rn" is '11111'
	     (i.e. SP), in which case it defaults to LSL. The LSL alias is
	     only valid when "Rd" or "Rn" is '11111', and is preferred in that
	     case.  */
	  if (!aarch64_stack_pointer_p (opnds + 0)
	      && (idx != 2 || !aarch64_stack_pointer_p (opnds + 1)))
	    {
	      if (!opnd->shifter.operator_present)
		{
		  set_other_error (mismatch_detail, idx,
				   _("missing extend operator"));
		  return 0;
		}
	      else if (opnd->shifter.kind == AARCH64_MOD_LSL)
		{
		  set_other_error (mismatch_detail, idx,
				   _("'LSL' operator not allowed"));
		  return 0;
		}
	    }
	  assert (opnd->shifter.operator_present	/* Default to LSL.  */
		  || opnd->shifter.kind == AARCH64_MOD_LSL);
	  if (!value_in_range_p (opnd->shifter.amount, 0, 4))
	    {
	      set_sft_amount_out_of_range_error (mismatch_detail, idx, 0, 4);
	      return 0;
	    }
	  /* In the 64-bit form, the final register operand is written as Wm
	     for all but the (possibly omitted) UXTX/LSL and SXTX
	     operators.
	     N.B. GAS allows X register to be used with any operator as a
	     programming convenience.  */
	  if (qualifier == AARCH64_OPND_QLF_X
	      && opnd->shifter.kind != AARCH64_MOD_LSL
	      && opnd->shifter.kind != AARCH64_MOD_UXTX
	      && opnd->shifter.kind != AARCH64_MOD_SXTX)
	    {
	      set_other_error (mismatch_detail, idx, _("W register expected"));
	      return 0;
	    }
	  break;

	case AARCH64_OPND_Rm_SFT:
	  /* ROR is not available to the shifted register operand in
	     arithmetic instructions.  */
	  if (aarch64_shift_operator_p (opnd->shifter.kind) == FALSE)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("shift operator expected"));
	      return 0;
	    }
	  if (opnd->shifter.kind == AARCH64_MOD_ROR
	      && opcode->iclass != log_shift)
	    {
	      set_other_error (mismatch_detail, idx,
			       _("'ROR' operator not allowed"));
	      return 0;
	    }
	  num = qualifier == AARCH64_OPND_QLF_W ? 31 : 63;
	  if (!value_in_range_p (opnd->shifter.amount, 0, num))
	    {
	      set_sft_amount_out_of_range_error (mismatch_detail, idx, 0, num);
	      return 0;
	    }
	  break;

	default:
	  break;
	}
      break;

    default:
      break;
    }

  return 1;
}

/* Main entrypoint for the operand constraint checking.

   Return 1 if operands of *INST meet the constraint applied by the operand
   codes and operand qualifiers; otherwise return 0 and if MISMATCH_DETAIL is
   not NULL, return the detail of the error in *MISMATCH_DETAIL.  N.B. when
   adding more constraint checking, make sure MISMATCH_DETAIL->KIND is set
   with a proper error kind rather than AARCH64_OPDE_NIL (GAS asserts non-NIL
   error kind when it is notified that an instruction does not pass the check).

   Un-determined operand qualifiers may get established during the process.  */

int
aarch64_match_operands_constraint (aarch64_inst *inst,
				   aarch64_operand_error *mismatch_detail)
{
  int i;

  DEBUG_TRACE ("enter");

  /* Match operands' qualifier.
     *INST has already had qualifier establish for some, if not all, of
     its operands; we need to find out whether these established
     qualifiers match one of the qualifier sequence in
     INST->OPCODE->QUALIFIERS_LIST.  If yes, we will assign each operand
     with the corresponding qualifier in such a sequence.
     Only basic operand constraint checking is done here; the more thorough
     constraint checking will carried out by operand_general_constraint_met_p,
     which has be to called after this in order to get all of the operands'
     qualifiers established.  */
  if (match_operands_qualifier (inst, TRUE /* update_p */) == 0)
    {
      DEBUG_TRACE ("FAIL on operand qualifier matching");
      if (mismatch_detail)
	{
	  /* Return an error type to indicate that it is the qualifier
	     matching failure; we don't care about which operand as there
	     are enough information in the opcode table to reproduce it.  */
	  mismatch_detail->kind = AARCH64_OPDE_INVALID_VARIANT;
	  mismatch_detail->index = -1;
	  mismatch_detail->error = NULL;
	}
      return 0;
    }

  /* Match operands' constraint.  */
  for (i = 0; i < AARCH64_MAX_OPND_NUM; ++i)
    {
      enum aarch64_opnd type = inst->opcode->operands[i];
      if (type == AARCH64_OPND_NIL)
	break;
      if (inst->operands[i].skip)
	{
	  DEBUG_TRACE ("skip the incomplete operand %d", i);
	  continue;
	}
      if (operand_general_constraint_met_p (inst->operands, i, type,
					    inst->opcode, mismatch_detail) == 0)
	{
	  DEBUG_TRACE ("FAIL on operand %d", i);
	  return 0;
	}
    }

  DEBUG_TRACE ("PASS");

  return 1;
}

/* Replace INST->OPCODE with OPCODE and return the replaced OPCODE.
   Also updates the TYPE of each INST->OPERANDS with the corresponding
   value of OPCODE->OPERANDS.

   Note that some operand qualifiers may need to be manually cleared by
   the caller before it further calls the aarch64_opcode_encode; by
   doing this, it helps the qualifier matching facilities work
   properly.  */

const aarch64_opcode*
aarch64_replace_opcode (aarch64_inst *inst, const aarch64_opcode *opcode)
{
  int i;
  const aarch64_opcode *old = inst->opcode;

  inst->opcode = opcode;

  /* Update the operand types.  */
  for (i = 0; i < AARCH64_MAX_OPND_NUM; ++i)
    {
      inst->operands[i].type = opcode->operands[i];
      if (opcode->operands[i] == AARCH64_OPND_NIL)
	break;
    }

  DEBUG_TRACE ("replace %s with %s", old->name, opcode->name);

  return old;
}

int
aarch64_operand_index (const enum aarch64_opnd *operands, enum aarch64_opnd operand)
{
  int i;
  for (i = 0; i < AARCH64_MAX_OPND_NUM; ++i)
    if (operands[i] == operand)
      return i;
    else if (operands[i] == AARCH64_OPND_NIL)
      break;
  return -1;
}

/* [0][0]  32-bit integer regs with sp   Wn
   [0][1]  64-bit integer regs with sp   Xn  sf=1
   [1][0]  32-bit integer regs with #0   Wn
   [1][1]  64-bit integer regs with #0   Xn  sf=1 */
static const char *int_reg[2][2][32] = {
#define R32 "w"
#define R64 "x"
  { { R32  "0", R32  "1", R32  "2", R32  "3", R32  "4", R32  "5", R32  "6", R32  "7",
      R32  "8", R32  "9", R32 "10", R32 "11", R32 "12", R32 "13", R32 "14", R32 "15",
      R32 "16", R32 "17", R32 "18", R32 "19", R32 "20", R32 "21", R32 "22", R32 "23",
      R32 "24", R32 "25", R32 "26", R32 "27", R32 "28", R32 "29", R32 "30",    "wsp" },
    { R64  "0", R64  "1", R64  "2", R64  "3", R64  "4", R64  "5", R64  "6", R64  "7",
      R64  "8", R64  "9", R64 "10", R64 "11", R64 "12", R64 "13", R64 "14", R64 "15",
      R64 "16", R64 "17", R64 "18", R64 "19", R64 "20", R64 "21", R64 "22", R64 "23",
      R64 "24", R64 "25", R64 "26", R64 "27", R64 "28", R64 "29", R64 "30",     "sp" } },
  { { R32  "0", R32  "1", R32  "2", R32  "3", R32  "4", R32  "5", R32  "6", R32  "7",
      R32  "8", R32  "9", R32 "10", R32 "11", R32 "12", R32 "13", R32 "14", R32 "15",
      R32 "16", R32 "17", R32 "18", R32 "19", R32 "20", R32 "21", R32 "22", R32 "23",
      R32 "24", R32 "25", R32 "26", R32 "27", R32 "28", R32 "29", R32 "30", R32 "zr" },
    { R64  "0", R64  "1", R64  "2", R64  "3", R64  "4", R64  "5", R64  "6", R64  "7",
      R64  "8", R64  "9", R64 "10", R64 "11", R64 "12", R64 "13", R64 "14", R64 "15",
      R64 "16", R64 "17", R64 "18", R64 "19", R64 "20", R64 "21", R64 "22", R64 "23",
      R64 "24", R64 "25", R64 "26", R64 "27", R64 "28", R64 "29", R64 "30", R64 "zr" } }
#undef R64
#undef R32
};

/* Return the integer register name.
   if SP_REG_P is not 0, R31 is an SP reg, other R31 is the zero reg.  */

static inline const char *
get_int_reg_name (int regno, aarch64_opnd_qualifier_t qualifier, int sp_reg_p)
{
  const int has_zr = sp_reg_p ? 0 : 1;
  const int is_64 = aarch64_get_qualifier_esize (qualifier) == 4 ? 0 : 1;
  return int_reg[has_zr][is_64][regno];
}

/* Like get_int_reg_name, but IS_64 is always 1.  */

static inline const char *
get_64bit_int_reg_name (int regno, int sp_reg_p)
{
  const int has_zr = sp_reg_p ? 0 : 1;
  return int_reg[has_zr][1][regno];
}

/* Types for expanding an encoded 8-bit value to a floating-point value.  */

typedef union
{
  uint64_t i;
  double   d;
} double_conv_t;

typedef union
{
  uint32_t i;
  float    f;
} single_conv_t;

/* IMM8 is an 8-bit floating-point constant with sign, 3-bit exponent and
   normalized 4 bits of precision, encoded in "a:b:c:d:e:f:g:h" or FLD_imm8
   (depending on the type of the instruction).  IMM8 will be expanded to a
   single-precision floating-point value (IS_DP == 0) or a double-precision
   floating-point value (IS_DP == 1).  The expanded value is returned.  */

static uint64_t
expand_fp_imm (int is_dp, uint32_t imm8)
{
  uint64_t imm;
  uint32_t imm8_7, imm8_6_0, imm8_6, imm8_6_repl4;

  imm8_7 = (imm8 >> 7) & 0x01;	/* imm8<7>   */
  imm8_6_0 = imm8 & 0x7f;	/* imm8<6:0> */
  imm8_6 = imm8_6_0 >> 6;	/* imm8<6>   */
  imm8_6_repl4 = (imm8_6 << 3) | (imm8_6 << 2)
    | (imm8_6 << 1) | imm8_6;	/* Replicate(imm8<6>,4) */
  if (is_dp)
    {
      imm = (imm8_7 << (63-32))		/* imm8<7>  */
	| ((imm8_6 ^ 1) << (62-32))	/* NOT(imm8<6)	*/
	| (imm8_6_repl4 << (58-32)) | (imm8_6 << (57-32))
	| (imm8_6 << (56-32)) | (imm8_6 << (55-32)) /* Replicate(imm8<6>,7) */
	| (imm8_6_0 << (48-32));	/* imm8<6>:imm8<5:0>    */
      imm <<= 32;
    }
  else
    {
      imm = (imm8_7 << 31)	/* imm8<7>              */
	| ((imm8_6 ^ 1) << 30)	/* NOT(imm8<6>)         */
	| (imm8_6_repl4 << 26)	/* Replicate(imm8<6>,4) */
	| (imm8_6_0 << 19);	/* imm8<6>:imm8<5:0>    */
    }

  return imm;
}

/* Produce the string representation of the register list operand *OPND
   in the buffer pointed by BUF of size SIZE.  */
static void
print_register_list (char *buf, size_t size, const aarch64_opnd_info *opnd)
{
  const int num_regs = opnd->reglist.num_regs;
  const int first_reg = opnd->reglist.first_regno;
  const int last_reg = (first_reg + num_regs - 1) & 0x1f;
  const char *qlf_name = aarch64_get_qualifier_name (opnd->qualifier);
  char tb[8];	/* Temporary buffer.  */

  assert (opnd->type != AARCH64_OPND_LEt || opnd->reglist.has_index);
  assert (num_regs >= 1 && num_regs <= 4);

  /* Prepare the index if any.  */
  if (opnd->reglist.has_index)
    snprintf (tb, 8, "[%d]", opnd->reglist.index);
  else
    tb[0] = '\0';

  /* The hyphenated form is preferred for disassembly if there are
     more than two registers in the list, and the register numbers
     are monotonically increasing in increments of one.  */
  if (num_regs > 2 && last_reg > first_reg)
    snprintf (buf, size, "{v%d.%s-v%d.%s}%s", first_reg, qlf_name,
	      last_reg, qlf_name, tb);
  else
    {
      const int reg0 = first_reg;
      const int reg1 = (first_reg + 1) & 0x1f;
      const int reg2 = (first_reg + 2) & 0x1f;
      const int reg3 = (first_reg + 3) & 0x1f;

      switch (num_regs)
	{
	case 1:
	  snprintf (buf, size, "{v%d.%s}%s", reg0, qlf_name, tb);
	  break;
	case 2:
	  snprintf (buf, size, "{v%d.%s, v%d.%s}%s", reg0, qlf_name,
		    reg1, qlf_name, tb);
	  break;
	case 3:
	  snprintf (buf, size, "{v%d.%s, v%d.%s, v%d.%s}%s", reg0, qlf_name,
		    reg1, qlf_name, reg2, qlf_name, tb);
	  break;
	case 4:
	  snprintf (buf, size, "{v%d.%s, v%d.%s, v%d.%s, v%d.%s}%s",
		    reg0, qlf_name, reg1, qlf_name, reg2, qlf_name,
		    reg3, qlf_name, tb);
	  break;
	}
    }
}

/* Produce the string representation of the register offset address operand
   *OPND in the buffer pointed by BUF of size SIZE.  */
static void
print_register_offset_address (char *buf, size_t size,
			       const aarch64_opnd_info *opnd)
{
  const size_t tblen = 16;
  char tb[tblen];		/* Temporary buffer.  */
  bfd_boolean lsl_p = FALSE;	/* Is LSL shift operator?  */
  bfd_boolean wm_p = FALSE;	/* Should Rm be Wm?  */
  bfd_boolean print_extend_p = TRUE;
  bfd_boolean print_amount_p = TRUE;
  const char *shift_name = aarch64_operand_modifiers[opnd->shifter.kind].name;

  switch (opnd->shifter.kind)
    {
    case AARCH64_MOD_UXTW: wm_p = TRUE; break;
    case AARCH64_MOD_LSL : lsl_p = TRUE; break;
    case AARCH64_MOD_SXTW: wm_p = TRUE; break;
    case AARCH64_MOD_SXTX: break;
    default: assert (0);
    }

  if (!opnd->shifter.amount && (opnd->qualifier != AARCH64_OPND_QLF_S_B
				|| !opnd->shifter.amount_present))
    {
      /* Not print the shift/extend amount when the amount is zero and
         when it is not the special case of 8-bit load/store instruction.  */
      print_amount_p = FALSE;
      /* Likewise, no need to print the shift operator LSL in such a
	 situation.  */
      if (lsl_p)
	print_extend_p = FALSE;
    }

  /* Prepare for the extend/shift.  */
  if (print_extend_p)
    {
      if (print_amount_p)
	snprintf (tb, tblen, ",%s %d", shift_name, opnd->shifter.amount); // #
      else
	snprintf (tb, tblen, ",%s", shift_name);
    }
  else
    tb[0] = '\0';

  snprintf (buf, size, "[%s,%c%d%s]",
	    get_64bit_int_reg_name (opnd->addr.base_regno, 1),
	    wm_p ? 'w' : 'x', opnd->addr.offset.regno, tb);
}

/* Generate the string representation of the operand OPNDS[IDX] for OPCODE
   in *BUF.  The caller should pass in the maximum size of *BUF in SIZE.
   PC, PCREL_P and ADDRESS are used to pass in and return information about
   the PC-relative address calculation, where the PC value is passed in
   PC.  If the operand is pc-relative related, *PCREL_P (if PCREL_P non-NULL)
   will return 1 and *ADDRESS (if ADDRESS non-NULL) will return the
   calculated address; otherwise, *PCREL_P (if PCREL_P non-NULL) returns 0.

   The function serves both the disassembler and the assembler diagnostics
   issuer, which is the reason why it lives in this file.  */

void
aarch64_print_operand (char *buf, size_t size, bfd_vma pc,
		       const aarch64_opcode *opcode,
		       const aarch64_opnd_info *opnds, int idx, int *pcrel_p,
		       bfd_vma *address)
{
  int i;
  const char *name = NULL;
  const aarch64_opnd_info *opnd = opnds + idx;
  enum aarch64_modifier_kind kind;
  uint64_t addr;

  buf[0] = '\0';
  if (pcrel_p)
    *pcrel_p = 0;

  switch (opnd->type)
    {
    case AARCH64_OPND_Rd:
    case AARCH64_OPND_Rn:
    case AARCH64_OPND_Rm:
    case AARCH64_OPND_Rt:
    case AARCH64_OPND_Rt2:
    case AARCH64_OPND_Rs:
    case AARCH64_OPND_Ra:
    case AARCH64_OPND_Rt_SYS:
      /* The optional-ness of <Xt> in e.g. IC <ic_op>{, <Xt>} is determined by
	 the <ic_op>, therefore we we use opnd->present to override the
	 generic optional-ness information.  */
      if (opnd->type == AARCH64_OPND_Rt_SYS && !opnd->present)
	break;
      /* Omit the operand, e.g. RET.  */
      if (optional_operand_p (opcode, idx)
	  && opnd->reg.regno == get_optional_operand_default_value (opcode))
	break;
      assert (opnd->qualifier == AARCH64_OPND_QLF_W
	      || opnd->qualifier == AARCH64_OPND_QLF_X);
      snprintf (buf, size, "%s",
		get_int_reg_name (opnd->reg.regno, opnd->qualifier, 0));
      break;

    case AARCH64_OPND_Rd_SP:
    case AARCH64_OPND_Rn_SP:
      assert (opnd->qualifier == AARCH64_OPND_QLF_W
	      || opnd->qualifier == AARCH64_OPND_QLF_WSP
	      || opnd->qualifier == AARCH64_OPND_QLF_X
	      || opnd->qualifier == AARCH64_OPND_QLF_SP);
      snprintf (buf, size, "%s",
		get_int_reg_name (opnd->reg.regno, opnd->qualifier, 1));
      break;

    case AARCH64_OPND_Rm_EXT:
      kind = opnd->shifter.kind;
      assert (idx == 1 || idx == 2);
      if ((aarch64_stack_pointer_p (opnds)
	   || (idx == 2 && aarch64_stack_pointer_p (opnds + 1)))
	  && ((opnd->qualifier == AARCH64_OPND_QLF_W
	       && opnds[0].qualifier == AARCH64_OPND_QLF_W
	       && kind == AARCH64_MOD_UXTW)
	      || (opnd->qualifier == AARCH64_OPND_QLF_X
		  && kind == AARCH64_MOD_UXTX)))
	{
	  /* 'LSL' is the preferred form in this case.  */
	  kind = AARCH64_MOD_LSL;
	  if (opnd->shifter.amount == 0)
	    {
	      /* Shifter omitted.  */
	      snprintf (buf, size, "%s",
			get_int_reg_name (opnd->reg.regno, opnd->qualifier, 0));
	      break;
	    }
	}
      if (opnd->shifter.amount)
	snprintf (buf, size, "%s, %s %d", // #%d
		  get_int_reg_name (opnd->reg.regno, opnd->qualifier, 0),
		  aarch64_operand_modifiers[kind].name,
		  opnd->shifter.amount);
      else
	snprintf (buf, size, "%s, %s",
		  get_int_reg_name (opnd->reg.regno, opnd->qualifier, 0),
		  aarch64_operand_modifiers[kind].name);
      break;

    case AARCH64_OPND_Rm_SFT:
      assert (opnd->qualifier == AARCH64_OPND_QLF_W
	      || opnd->qualifier == AARCH64_OPND_QLF_X);
      if (opnd->shifter.amount == 0 && opnd->shifter.kind == AARCH64_MOD_LSL)
	snprintf (buf, size, "%s",
		  get_int_reg_name (opnd->reg.regno, opnd->qualifier, 0));
      else
	snprintf (buf, size, "%s, %s %d", // #%d
		  get_int_reg_name (opnd->reg.regno, opnd->qualifier, 0),
		  aarch64_operand_modifiers[opnd->shifter.kind].name,
		  opnd->shifter.amount);
      break;

    case AARCH64_OPND_Fd:
    case AARCH64_OPND_Fn:
    case AARCH64_OPND_Fm:
    case AARCH64_OPND_Fa:
    case AARCH64_OPND_Ft:
    case AARCH64_OPND_Ft2:
    case AARCH64_OPND_Sd:
    case AARCH64_OPND_Sn:
    case AARCH64_OPND_Sm:
      snprintf (buf, size, "%s%d", aarch64_get_qualifier_name (opnd->qualifier),
		opnd->reg.regno);
      break;

    case AARCH64_OPND_Vd:
    case AARCH64_OPND_Vn:
    case AARCH64_OPND_Vm:
      snprintf (buf, size, "v%d.%s", opnd->reg.regno,
		aarch64_get_qualifier_name (opnd->qualifier));
      break;

    case AARCH64_OPND_Ed:
    case AARCH64_OPND_En:
    case AARCH64_OPND_Em:
      snprintf (buf, size, "v%d.%s[%d]", opnd->reglane.regno,
		aarch64_get_qualifier_name (opnd->qualifier),
		opnd->reglane.index);
      break;

    case AARCH64_OPND_VdD1:
    case AARCH64_OPND_VnD1:
      snprintf (buf, size, "v%d.d[1]", opnd->reg.regno);
      break;

    case AARCH64_OPND_LVn:
    case AARCH64_OPND_LVt:
    case AARCH64_OPND_LVt_AL:
    case AARCH64_OPND_LEt:
      print_register_list (buf, size, opnd);
      break;

    case AARCH64_OPND_Cn:
    case AARCH64_OPND_Cm:
      snprintf (buf, size, "C%d", opnd->reg.regno);
      break;

    case AARCH64_OPND_IDX:
    case AARCH64_OPND_IMM:
    case AARCH64_OPND_WIDTH:
    case AARCH64_OPND_UIMM3_OP1:
    case AARCH64_OPND_UIMM3_OP2:
    case AARCH64_OPND_BIT_NUM:
    case AARCH64_OPND_IMM_VLSL:
    case AARCH64_OPND_IMM_VLSR:
    case AARCH64_OPND_SHLL_IMM:
    case AARCH64_OPND_IMM0:
    case AARCH64_OPND_IMMR:
    case AARCH64_OPND_IMMS:
    case AARCH64_OPND_FBITS:
      snprintf (buf, size, "%" PRIi64, opnd->imm.value); // #
      break;

    case AARCH64_OPND_IMM_MOV:
      switch (aarch64_get_qualifier_esize (opnds[0].qualifier))
	{
	case 4:	/* e.g. MOV Wd, #<imm32>.  */
	    {
	      int imm32 = opnd->imm.value;
	      snprintf (buf, size, "0x%x", imm32);
	      //snprintf (buf, size, "#0x%-20x // #%d", imm32, imm32);
	    }
	  break;
	case 8:	/* e.g. MOV Xd, #<imm64>.  */
	  snprintf (buf, size, "0x%" PRIx64, opnd->imm.value);
	  //snprintf (buf, size, "#0x%-20" PRIx64 " // #%" PRIi64,
	  //	    opnd->imm.value, opnd->imm.value);
	  break;
	default: assert (0);
	}
      break;

    case AARCH64_OPND_FPIMM0:
      snprintf (buf, size, "0.0");
      break;

    case AARCH64_OPND_LIMM:
    case AARCH64_OPND_AIMM:
    case AARCH64_OPND_HALF:
      if (opnd->shifter.amount)
	snprintf (buf, size, "0x%" PRIx64 ", lsl %d", opnd->imm.value, // #
		  opnd->shifter.amount);
      else
	snprintf (buf, size, "0x%" PRIx64, opnd->imm.value);
      break;

    case AARCH64_OPND_SIMD_IMM:
    case AARCH64_OPND_SIMD_IMM_SFT:
      if ((! opnd->shifter.amount && opnd->shifter.kind == AARCH64_MOD_LSL)
	  || opnd->shifter.kind == AARCH64_MOD_NONE)
	snprintf (buf, size, "0x%" PRIx64, opnd->imm.value);
      else
	snprintf (buf, size, "0x%" PRIx64 ", %s %d", opnd->imm.value, // #
		  aarch64_operand_modifiers[opnd->shifter.kind].name,
		  opnd->shifter.amount);
      break;

    case AARCH64_OPND_FPIMM:
    case AARCH64_OPND_SIMD_FPIMM:
      switch (aarch64_get_qualifier_esize (opnds[0].qualifier))
	{
	case 4:	/* e.g. FMOV <Vd>.4S, #<imm>.  */
	    {
	      single_conv_t c;
	      c.i = expand_fp_imm (0, opnd->imm.value);
	      snprintf (buf, size,  "%.18e", c.f); // #
	    }
	  break;
	case 8:	/* e.g. FMOV <Sd>, #<imm>.  */
	    {
	      double_conv_t c;
	      c.i = expand_fp_imm (1, opnd->imm.value);
	      snprintf (buf, size,  "%.18e", c.d); // #
	    }
	  break;
	default: assert (0);
	}
      break;

    case AARCH64_OPND_CCMP_IMM:
    case AARCH64_OPND_NZCV:
    case AARCH64_OPND_EXCEPTION:
    case AARCH64_OPND_UIMM4:
    case AARCH64_OPND_UIMM7:
      if (optional_operand_p (opcode, idx) == TRUE
	  && (opnd->imm.value ==
	      (int64_t) get_optional_operand_default_value (opcode)))
	/* Omit the operand, e.g. DCPS1.  */
	break;
      snprintf (buf, size, "0x%x", (unsigned int)opnd->imm.value);
      break;

    case AARCH64_OPND_COND:
      snprintf (buf, size, "%s", opnd->cond->names[0]);
      break;

    case AARCH64_OPND_ADDR_ADRP:
      addr = ((pc + AARCH64_PCREL_OFFSET) & ~(uint64_t)0xfff)
	+ opnd->imm.value;
      if (pcrel_p)
	*pcrel_p = 1;
      if (address)
	*address = addr;
      /* This is not necessary during the disassembling, as print_address_func
	 in the disassemble_info will take care of the printing.  But some
	 other callers may be still interested in getting the string in *STR,
	 so here we do snprintf regardless.  */
      snprintf (buf, size, "0x%" PRIx64, addr);
      break;

    case AARCH64_OPND_ADDR_PCREL14:
    case AARCH64_OPND_ADDR_PCREL19:
    case AARCH64_OPND_ADDR_PCREL21:
    case AARCH64_OPND_ADDR_PCREL26:
      addr = pc + AARCH64_PCREL_OFFSET + opnd->imm.value;
      if (pcrel_p)
	*pcrel_p = 1;
      if (address)
	*address = addr;
      /* This is not necessary during the disassembling, as print_address_func
	 in the disassemble_info will take care of the printing.  But some
	 other callers may be still interested in getting the string in *STR,
	 so here we do snprintf regardless.  */
      snprintf (buf, size, "0x%" PRIx64, addr);
      break;

    case AARCH64_OPND_ADDR_SIMPLE:
    case AARCH64_OPND_SIMD_ADDR_SIMPLE:
    case AARCH64_OPND_SIMD_ADDR_POST:
      name = get_64bit_int_reg_name (opnd->addr.base_regno, 1);
      if (opnd->type == AARCH64_OPND_SIMD_ADDR_POST)
	{
	  if (opnd->addr.offset.is_reg)
	    snprintf (buf, size, "[%s], x%d", name, opnd->addr.offset.regno);
	  else
	    snprintf (buf, size, "[%s], %d", name, opnd->addr.offset.imm); // #
	}
      else
	snprintf (buf, size, "[%s]", name);
      break;

    case AARCH64_OPND_ADDR_REGOFF:
      print_register_offset_address (buf, size, opnd);
      break;

    case AARCH64_OPND_ADDR_SIMM7:
    case AARCH64_OPND_ADDR_SIMM9:
    case AARCH64_OPND_ADDR_SIMM9_2:
      name = get_64bit_int_reg_name (opnd->addr.base_regno, 1);
      if (opnd->addr.writeback)
	{
	  if (opnd->addr.preind)
	    snprintf (buf, size, "[%s, %d]!", name, opnd->addr.offset.imm); // #
	  else
	    snprintf (buf, size, "[%s], %d", name, opnd->addr.offset.imm); // #
	}
      else
	{
	  if (opnd->addr.offset.imm)
	    snprintf (buf, size, "[%s, %d]", name, opnd->addr.offset.imm); // #
	  else
	    snprintf (buf, size, "[%s]", name);
	}
      break;

    case AARCH64_OPND_ADDR_UIMM12:
      name = get_64bit_int_reg_name (opnd->addr.base_regno, 1);
      if (opnd->addr.offset.imm)
	snprintf (buf, size, "[%s, %d]", name, opnd->addr.offset.imm); // #
      else
	snprintf (buf, size, "[%s]", name);
      break;

    case AARCH64_OPND_SYSREG:
      for (i = 0; aarch64_sys_regs[i].name; ++i)
	if (aarch64_sys_regs[i].value == opnd->sysreg)
	  break;
      if (aarch64_sys_regs[i].name)
	snprintf (buf, size, "%s", aarch64_sys_regs[i].name);
      else
	{
	  /* Implementation defined system register.  */
	  unsigned int value = opnd->sysreg;
	  snprintf (buf, size, "s%u_%u_c%u_c%u_%u", (value >> 14) & 0x3,
		    (value >> 11) & 0x7, (value >> 7) & 0xf, (value >> 3) & 0xf,
		    value & 0x7);
	}
      break;

    case AARCH64_OPND_PSTATEFIELD:
      for (i = 0; aarch64_pstatefields[i].name; ++i)
	if (aarch64_pstatefields[i].value == opnd->pstatefield)
	  break;
      assert (aarch64_pstatefields[i].name);
      snprintf (buf, size, "%s", aarch64_pstatefields[i].name);
      break;

    case AARCH64_OPND_SYSREG_AT:
    case AARCH64_OPND_SYSREG_DC:
    case AARCH64_OPND_SYSREG_IC:
    case AARCH64_OPND_SYSREG_TLBI:
      snprintf (buf, size, "%s", opnd->sysins_op->template);
      break;

    case AARCH64_OPND_BARRIER:
      snprintf (buf, size, "%s", opnd->barrier->name);
      break;

    case AARCH64_OPND_BARRIER_ISB:
      /* Operand can be omitted, e.g. in DCPS1.  */
      if (! optional_operand_p (opcode, idx)
	  || (opnd->barrier->value
	      != get_optional_operand_default_value (opcode)))
	snprintf (buf, size, "0x%x", opnd->barrier->value);
      break;

    case AARCH64_OPND_PRFOP:
      if (opnd->prfop->name != NULL)
	snprintf (buf, size, "%s", opnd->prfop->name);
      else
	snprintf (buf, size, "0x%02x", opnd->prfop->value);
      break;

    default:
      assert (0);
    }
}

#define CPENC(op0,op1,crn,crm,op2) \
  ((((op0) << 19) | ((op1) << 16) | ((crn) << 12) | ((crm) << 8) | ((op2) << 5)) >> 5)
  /* for 3.9.3 Instructions for Accessing Special Purpose Registers */
#define CPEN_(op1,crm,op2) CPENC(3,(op1),4,(crm),(op2))
  /* for 3.9.10 System Instructions */
#define CPENS(op1,crn,crm,op2) CPENC(1,(op1),(crn),(crm),(op2))

#define C0  0
#define C1  1
#define C2  2
#define C3  3
#define C4  4
#define C5  5
#define C6  6
#define C7  7
#define C8  8
#define C9  9
#define C10 10
#define C11 11
#define C12 12
#define C13 13
#define C14 14
#define C15 15

/* TODO there are two more issues need to be resolved
   1. handle read-only and write-only system registers
   2. handle cpu-implementation-defined system registers.  */
const struct aarch64_name_value_pair aarch64_sys_regs [] =
{
  { "spsr_el1",         CPEN_(0,C0,0)  }, /* = spsr_svc */
  { "elr_el1",          CPEN_(0,C0,1)  },
  { "sp_el0",           CPEN_(0,C1,0)  },
  { "spsel",            CPEN_(0,C2,0)  },
  { "daif",             CPEN_(3,C2,1)  },
  { "currentel",        CPEN_(0,C2,2)  }, /* RO */
  { "nzcv",             CPEN_(3,C2,0)  },
  { "fpcr",             CPEN_(3,C4,0)  },
  { "fpsr",             CPEN_(3,C4,1)  },
  { "dspsr_el0",        CPEN_(3,C5,0)  },
  { "dlr_el0",          CPEN_(3,C5,1)  },
  { "spsr_el2",         CPEN_(4,C0,0)  }, /* = spsr_hyp */
  { "elr_el2",          CPEN_(4,C0,1)  },
  { "sp_el1",           CPEN_(4,C1,0)  },
  { "spsr_irq",         CPEN_(4,C3,0)  },
  { "spsr_abt",         CPEN_(4,C3,1)  },
  { "spsr_und",         CPEN_(4,C3,2)  },
  { "spsr_fiq",         CPEN_(4,C3,3)  },
  { "spsr_el3",         CPEN_(6,C0,0)  },
  { "elr_el3",          CPEN_(6,C0,1)  },
  { "sp_el2",           CPEN_(6,C1,0)  },
  { "spsr_svc",         CPEN_(0,C0,0)  }, /* = spsr_el1 */
  { "spsr_hyp",         CPEN_(4,C0,0)  }, /* = spsr_el2 */
  { "midr_el1",         CPENC(3,0,C0,C0,0)  }, /* RO */
  { "ctr_el0",          CPENC(3,3,C0,C0,1)  }, /* RO */
  { "mpidr_el1",        CPENC(3,0,C0,C0,5)  }, /* RO */
  { "revidr_el1",       CPENC(3,0,C0,C0,6)  }, /* RO */
  { "aidr_el1",         CPENC(3,1,C0,C0,7)  }, /* RO */
  { "dczid_el0",        CPENC(3,3,C0,C0,7)  }, /* RO */
  { "id_dfr0_el1",      CPENC(3,0,C0,C1,2)  }, /* RO */
  { "id_pfr0_el1",      CPENC(3,0,C0,C1,0)  }, /* RO */
  { "id_pfr1_el1",      CPENC(3,0,C0,C1,1)  }, /* RO */
  { "id_afr0_el1",      CPENC(3,0,C0,C1,3)  }, /* RO */
  { "id_mmfr0_el1",     CPENC(3,0,C0,C1,4)  }, /* RO */
  { "id_mmfr1_el1",     CPENC(3,0,C0,C1,5)  }, /* RO */
  { "id_mmfr2_el1",     CPENC(3,0,C0,C1,6)  }, /* RO */
  { "id_mmfr3_el1",     CPENC(3,0,C0,C1,7)  }, /* RO */
  { "id_isar0_el1",     CPENC(3,0,C0,C2,0)  }, /* RO */
  { "id_isar1_el1",     CPENC(3,0,C0,C2,1)  }, /* RO */
  { "id_isar2_el1",     CPENC(3,0,C0,C2,2)  }, /* RO */
  { "id_isar3_el1",     CPENC(3,0,C0,C2,3)  }, /* RO */
  { "id_isar4_el1",     CPENC(3,0,C0,C2,4)  }, /* RO */
  { "id_isar5_el1",     CPENC(3,0,C0,C2,5)  }, /* RO */
  { "mvfr0_el1",        CPENC(3,0,C0,C3,0)  }, /* RO */
  { "mvfr1_el1",        CPENC(3,0,C0,C3,1)  }, /* RO */
  { "mvfr2_el1",        CPENC(3,0,C0,C3,2)  }, /* RO */
  { "ccsidr_el1",       CPENC(3,1,C0,C0,0)  }, /* RO */
  { "id_aa64pfr0_el1",  CPENC(3,0,C0,C4,0)  }, /* RO */
  { "id_aa64pfr1_el1",  CPENC(3,0,C0,C4,1)  }, /* RO */
  { "id_aa64dfr0_el1",  CPENC(3,0,C0,C5,0)  }, /* RO */
  { "id_aa64dfr1_el1",  CPENC(3,0,C0,C5,1)  }, /* RO */
  { "id_aa64isar0_el1", CPENC(3,0,C0,C6,0)  }, /* RO */
  { "id_aa64isar1_el1", CPENC(3,0,C0,C6,1)  }, /* RO */
  { "id_aa64mmfr0_el1", CPENC(3,0,C0,C7,0)  }, /* RO */
  { "id_aa64mmfr1_el1", CPENC(3,0,C0,C7,1)  }, /* RO */
  { "id_aa64afr0_el1",  CPENC(3,0,C0,C5,4)  }, /* RO */
  { "id_aa64afr1_el1",  CPENC(3,0,C0,C5,5)  }, /* RO */
  { "clidr_el1",        CPENC(3,1,C0,C0,1)  }, /* RO */
  { "csselr_el1",       CPENC(3,2,C0,C0,0)  }, /* RO */
  { "vpidr_el2",        CPENC(3,4,C0,C0,0)  },
  { "vmpidr_el2",       CPENC(3,4,C0,C0,5)  },
  { "sctlr_el1",        CPENC(3,0,C1,C0,0)  },
  { "sctlr_el2",        CPENC(3,4,C1,C0,0)  },
  { "sctlr_el3",        CPENC(3,6,C1,C0,0)  },
  { "actlr_el1",        CPENC(3,0,C1,C0,1)  },
  { "actlr_el2",        CPENC(3,4,C1,C0,1)  },
  { "actlr_el3",        CPENC(3,6,C1,C0,1)  },
  { "cpacr_el1",        CPENC(3,0,C1,C0,2)  },
  { "cptr_el2",         CPENC(3,4,C1,C1,2)  },
  { "cptr_el3",         CPENC(3,6,C1,C1,2)  },
  { "scr_el3",          CPENC(3,6,C1,C1,0)  },
  { "hcr_el2",          CPENC(3,4,C1,C1,0)  },
  { "mdcr_el2",         CPENC(3,4,C1,C1,1)  },
  { "mdcr_el3",         CPENC(3,6,C1,C3,1)  },
  { "hstr_el2",         CPENC(3,4,C1,C1,3)  },
  { "hacr_el2",         CPENC(3,4,C1,C1,7)  },
  { "ttbr0_el1",        CPENC(3,0,C2,C0,0)  },
  { "ttbr1_el1",        CPENC(3,0,C2,C0,1)  },
  { "ttbr0_el2",        CPENC(3,4,C2,C0,0)  },
  { "ttbr0_el3",        CPENC(3,6,C2,C0,0)  },
  { "vttbr_el2",        CPENC(3,4,C2,C1,0)  },
  { "tcr_el1",          CPENC(3,0,C2,C0,2)  },
  { "tcr_el2",          CPENC(3,4,C2,C0,2)  },
  { "tcr_el3",          CPENC(3,6,C2,C0,2)  },
  { "vtcr_el2",         CPENC(3,4,C2,C1,2)  },
  { "afsr0_el1",        CPENC(3,0,C5,C1,0)  },
  { "afsr1_el1",        CPENC(3,0,C5,C1,1)  },
  { "afsr0_el2",        CPENC(3,4,C5,C1,0)  },
  { "afsr1_el2",        CPENC(3,4,C5,C1,1)  },
  { "afsr0_el3",        CPENC(3,6,C5,C1,0)  },
  { "afsr1_el3",        CPENC(3,6,C5,C1,1)  },
  { "esr_el1",          CPENC(3,0,C5,C2,0)  },
  { "esr_el2",          CPENC(3,4,C5,C2,0)  },
  { "esr_el3",          CPENC(3,6,C5,C2,0)  },
  { "fpexc32_el2",      CPENC(3,4,C5,C3,0)  },
  { "far_el1",          CPENC(3,0,C6,C0,0)  },
  { "far_el2",          CPENC(3,4,C6,C0,0)  },
  { "far_el3",          CPENC(3,6,C6,C0,0)  },
  { "hpfar_el2",        CPENC(3,4,C6,C0,4)  },
  { "par_el1",          CPENC(3,0,C7,C4,0)  },
  { "mair_el1",         CPENC(3,0,C10,C2,0) },
  { "mair_el2",         CPENC(3,4,C10,C2,0) },
  { "mair_el3",         CPENC(3,6,C10,C2,0) },
  { "amair_el1",        CPENC(3,0,C10,C3,0) },
  { "amair_el2",        CPENC(3,4,C10,C3,0) },
  { "amair_el3",        CPENC(3,6,C10,C3,0) },
  { "vbar_el1",         CPENC(3,0,C12,C0,0) },
  { "vbar_el2",         CPENC(3,4,C12,C0,0) },
  { "vbar_el3",         CPENC(3,6,C12,C0,0) },
  { "rvbar_el1",        CPENC(3,0,C12,C0,1) }, /* RO */
  { "rvbar_el2",        CPENC(3,4,C12,C0,1) }, /* RO */
  { "rvbar_el3",        CPENC(3,6,C12,C0,1) }, /* RO */
  { "rmr_el1",          CPENC(3,0,C12,C0,2) },
  { "rmr_el2",          CPENC(3,4,C12,C0,2) },
  { "rmr_el3",          CPENC(3,6,C12,C0,2) },
  { "isr_el1",          CPENC(3,0,C12,C1,0) }, /* RO */
  { "contextidr_el1",   CPENC(3,0,C13,C0,1) },
  { "tpidr_el0",        CPENC(3,3,C13,C0,2) },
  { "tpidrro_el0",      CPENC(3,3,C13,C0,3) }, /* RO */
  { "tpidr_el1",        CPENC(3,0,C13,C0,4) },
  { "tpidr_el2",        CPENC(3,4,C13,C0,2) },
  { "tpidr_el3",        CPENC(3,6,C13,C0,2) },
  { "teecr32_el1",      CPENC(2,2,C0, C0,0) }, /* See section 3.9.7.1 */
  { "cntfrq_el0",       CPENC(3,3,C14,C0,0) }, /* RO */
  { "cntpct_el0",       CPENC(3,3,C14,C0,1) }, /* RO */
  { "cntvct_el0",       CPENC(3,3,C14,C0,2) }, /* RO */
  { "cntvoff_el2",      CPENC(3,4,C14,C0,3) },
  { "cntkctl_el1",      CPENC(3,0,C14,C1,0) },
  { "cnthctl_el2",      CPENC(3,4,C14,C1,0) },
  { "cntp_tval_el0",    CPENC(3,3,C14,C2,0) },
  { "cntp_ctl_el0",     CPENC(3,3,C14,C2,1) },
  { "cntp_cval_el0",    CPENC(3,3,C14,C2,2) },
  { "cntv_tval_el0",    CPENC(3,3,C14,C3,0) },
  { "cntv_ctl_el0",     CPENC(3,3,C14,C3,1) },
  { "cntv_cval_el0",    CPENC(3,3,C14,C3,2) },
  { "cnthp_tval_el2",   CPENC(3,4,C14,C2,0) },
  { "cnthp_ctl_el2",    CPENC(3,4,C14,C2,1) },
  { "cnthp_cval_el2",   CPENC(3,4,C14,C2,2) },
  { "cntps_tval_el1",   CPENC(3,7,C14,C2,0) },
  { "cntps_ctl_el1",    CPENC(3,7,C14,C2,1) },
  { "cntps_cval_el1",   CPENC(3,7,C14,C2,2) },
  { "dacr32_el2",       CPENC(3,4,C3,C0,0)  },
  { "ifsr32_el2",       CPENC(3,4,C5,C0,1)  },
  { "teehbr32_el1",     CPENC(2,2,C1,C0,0)  },
  { "sder32_el3",       CPENC(3,6,C1,C1,1)  },
  { "mdscr_el1",         CPENC(2,0,C0, C2, 2) },
  { "mdccsr_el0",        CPENC(2,3,C0, C1, 0) },  /* r */
  { "mdccint_el1",       CPENC(2,0,C0, C2, 0) },
  { "dbgdtr_el0",        CPENC(2,3,C0, C4, 0) },
  { "dbgdtrrx_el0",      CPENC(2,3,C0, C5, 0) },  /* r */
  { "dbgdtrtx_el0",      CPENC(2,3,C0, C5, 0) },  /* w */
  { "osdtrrx_el1",       CPENC(2,0,C0, C0, 2) },  /* r */
  { "osdtrtx_el1",       CPENC(2,0,C0, C3, 2) },  /* w */
  { "oseccr_el1",        CPENC(2,0,C0, C6, 2) },
  { "dbgvcr32_el2",      CPENC(2,4,C0, C7, 0) },
  { "dbgbvr0_el1",       CPENC(2,0,C0, C0, 4) },
  { "dbgbvr1_el1",       CPENC(2,0,C0, C1, 4) },
  { "dbgbvr2_el1",       CPENC(2,0,C0, C2, 4) },
  { "dbgbvr3_el1",       CPENC(2,0,C0, C3, 4) },
  { "dbgbvr4_el1",       CPENC(2,0,C0, C4, 4) },
  { "dbgbvr5_el1",       CPENC(2,0,C0, C5, 4) },
  { "dbgbvr6_el1",       CPENC(2,0,C0, C6, 4) },
  { "dbgbvr7_el1",       CPENC(2,0,C0, C7, 4) },
  { "dbgbvr8_el1",       CPENC(2,0,C0, C8, 4) },
  { "dbgbvr9_el1",       CPENC(2,0,C0, C9, 4) },
  { "dbgbvr10_el1",      CPENC(2,0,C0, C10,4) },
  { "dbgbvr11_el1",      CPENC(2,0,C0, C11,4) },
  { "dbgbvr12_el1",      CPENC(2,0,C0, C12,4) },
  { "dbgbvr13_el1",      CPENC(2,0,C0, C13,4) },
  { "dbgbvr14_el1",      CPENC(2,0,C0, C14,4) },
  { "dbgbvr15_el1",      CPENC(2,0,C0, C15,4) },
  { "dbgbcr0_el1",       CPENC(2,0,C0, C0, 5) },
  { "dbgbcr1_el1",       CPENC(2,0,C0, C1, 5) },
  { "dbgbcr2_el1",       CPENC(2,0,C0, C2, 5) },
  { "dbgbcr3_el1",       CPENC(2,0,C0, C3, 5) },
  { "dbgbcr4_el1",       CPENC(2,0,C0, C4, 5) },
  { "dbgbcr5_el1",       CPENC(2,0,C0, C5, 5) },
  { "dbgbcr6_el1",       CPENC(2,0,C0, C6, 5) },
  { "dbgbcr7_el1",       CPENC(2,0,C0, C7, 5) },
  { "dbgbcr8_el1",       CPENC(2,0,C0, C8, 5) },
  { "dbgbcr9_el1",       CPENC(2,0,C0, C9, 5) },
  { "dbgbcr10_el1",      CPENC(2,0,C0, C10,5) },
  { "dbgbcr11_el1",      CPENC(2,0,C0, C11,5) },
  { "dbgbcr12_el1",      CPENC(2,0,C0, C12,5) },
  { "dbgbcr13_el1",      CPENC(2,0,C0, C13,5) },
  { "dbgbcr14_el1",      CPENC(2,0,C0, C14,5) },
  { "dbgbcr15_el1",      CPENC(2,0,C0, C15,5) },
  { "dbgwvr0_el1",       CPENC(2,0,C0, C0, 6) },
  { "dbgwvr1_el1",       CPENC(2,0,C0, C1, 6) },
  { "dbgwvr2_el1",       CPENC(2,0,C0, C2, 6) },
  { "dbgwvr3_el1",       CPENC(2,0,C0, C3, 6) },
  { "dbgwvr4_el1",       CPENC(2,0,C0, C4, 6) },
  { "dbgwvr5_el1",       CPENC(2,0,C0, C5, 6) },
  { "dbgwvr6_el1",       CPENC(2,0,C0, C6, 6) },
  { "dbgwvr7_el1",       CPENC(2,0,C0, C7, 6) },
  { "dbgwvr8_el1",       CPENC(2,0,C0, C8, 6) },
  { "dbgwvr9_el1",       CPENC(2,0,C0, C9, 6) },
  { "dbgwvr10_el1",      CPENC(2,0,C0, C10,6) },
  { "dbgwvr11_el1",      CPENC(2,0,C0, C11,6) },
  { "dbgwvr12_el1",      CPENC(2,0,C0, C12,6) },
  { "dbgwvr13_el1",      CPENC(2,0,C0, C13,6) },
  { "dbgwvr14_el1",      CPENC(2,0,C0, C14,6) },
  { "dbgwvr15_el1",      CPENC(2,0,C0, C15,6) },
  { "dbgwcr0_el1",       CPENC(2,0,C0, C0, 7) },
  { "dbgwcr1_el1",       CPENC(2,0,C0, C1, 7) },
  { "dbgwcr2_el1",       CPENC(2,0,C0, C2, 7) },
  { "dbgwcr3_el1",       CPENC(2,0,C0, C3, 7) },
  { "dbgwcr4_el1",       CPENC(2,0,C0, C4, 7) },
  { "dbgwcr5_el1",       CPENC(2,0,C0, C5, 7) },
  { "dbgwcr6_el1",       CPENC(2,0,C0, C6, 7) },
  { "dbgwcr7_el1",       CPENC(2,0,C0, C7, 7) },
  { "dbgwcr8_el1",       CPENC(2,0,C0, C8, 7) },
  { "dbgwcr9_el1",       CPENC(2,0,C0, C9, 7) },
  { "dbgwcr10_el1",      CPENC(2,0,C0, C10,7) },
  { "dbgwcr11_el1",      CPENC(2,0,C0, C11,7) },
  { "dbgwcr12_el1",      CPENC(2,0,C0, C12,7) },
  { "dbgwcr13_el1",      CPENC(2,0,C0, C13,7) },
  { "dbgwcr14_el1",      CPENC(2,0,C0, C14,7) },
  { "dbgwcr15_el1",      CPENC(2,0,C0, C15,7) },
  { "mdrar_el1",         CPENC(2,0,C1, C0, 0) },  /* r */
  { "oslar_el1",         CPENC(2,0,C1, C0, 4) },  /* w */
  { "oslsr_el1",         CPENC(2,0,C1, C1, 4) },  /* r */
  { "osdlr_el1",         CPENC(2,0,C1, C3, 4) },
  { "dbgprcr_el1",       CPENC(2,0,C1, C4, 4) },
  { "dbgclaimset_el1",   CPENC(2,0,C7, C8, 6) },
  { "dbgclaimclr_el1",   CPENC(2,0,C7, C9, 6) },
  { "dbgauthstatus_el1", CPENC(2,0,C7, C14,6) },  /* r */

  { "pmcr_el0",          CPENC(3,3,C9,C12, 0) },
  { "pmcntenset_el0",    CPENC(3,3,C9,C12, 1) },
  { "pmcntenclr_el0",    CPENC(3,3,C9,C12, 2) },
  { "pmovsclr_el0",      CPENC(3,3,C9,C12, 3) },
  { "pmswinc_el0",       CPENC(3,3,C9,C12, 4) },  /* w */
  { "pmselr_el0",        CPENC(3,3,C9,C12, 5) },
  { "pmceid0_el0",       CPENC(3,3,C9,C12, 6) },  /* r */
  { "pmceid1_el0",       CPENC(3,3,C9,C12, 7) },  /* r */
  { "pmccntr_el0",       CPENC(3,3,C9,C13, 0) },
  { "pmxevtyper_el0",    CPENC(3,3,C9,C13, 1) },
  { "pmxevcntr_el0",     CPENC(3,3,C9,C13, 2) },
  { "pmuserenr_el0",     CPENC(3,3,C9,C14, 0) },
  { "pmintenset_el1",    CPENC(3,0,C9,C14, 1) },
  { "pmintenclr_el1",    CPENC(3,0,C9,C14, 2) },
  { "pmovsset_el0",      CPENC(3,3,C9,C14, 3) },
  { "pmevcntr0_el0",     CPENC(3,3,C14,C8, 0) },
  { "pmevcntr1_el0",     CPENC(3,3,C14,C8, 1) },
  { "pmevcntr2_el0",     CPENC(3,3,C14,C8, 2) },
  { "pmevcntr3_el0",     CPENC(3,3,C14,C8, 3) },
  { "pmevcntr4_el0",     CPENC(3,3,C14,C8, 4) },
  { "pmevcntr5_el0",     CPENC(3,3,C14,C8, 5) },
  { "pmevcntr6_el0",     CPENC(3,3,C14,C8, 6) },
  { "pmevcntr7_el0",     CPENC(3,3,C14,C8, 7) },
  { "pmevcntr8_el0",     CPENC(3,3,C14,C9, 0) },
  { "pmevcntr9_el0",     CPENC(3,3,C14,C9, 1) },
  { "pmevcntr10_el0",    CPENC(3,3,C14,C9, 2) },
  { "pmevcntr11_el0",    CPENC(3,3,C14,C9, 3) },
  { "pmevcntr12_el0",    CPENC(3,3,C14,C9, 4) },
  { "pmevcntr13_el0",    CPENC(3,3,C14,C9, 5) },
  { "pmevcntr14_el0",    CPENC(3,3,C14,C9, 6) },
  { "pmevcntr15_el0",    CPENC(3,3,C14,C9, 7) },
  { "pmevcntr16_el0",    CPENC(3,3,C14,C10,0) },
  { "pmevcntr17_el0",    CPENC(3,3,C14,C10,1) },
  { "pmevcntr18_el0",    CPENC(3,3,C14,C10,2) },
  { "pmevcntr19_el0",    CPENC(3,3,C14,C10,3) },
  { "pmevcntr20_el0",    CPENC(3,3,C14,C10,4) },
  { "pmevcntr21_el0",    CPENC(3,3,C14,C10,5) },
  { "pmevcntr22_el0",    CPENC(3,3,C14,C10,6) },
  { "pmevcntr23_el0",    CPENC(3,3,C14,C10,7) },
  { "pmevcntr24_el0",    CPENC(3,3,C14,C11,0) },
  { "pmevcntr25_el0",    CPENC(3,3,C14,C11,1) },
  { "pmevcntr26_el0",    CPENC(3,3,C14,C11,2) },
  { "pmevcntr27_el0",    CPENC(3,3,C14,C11,3) },
  { "pmevcntr28_el0",    CPENC(3,3,C14,C11,4) },
  { "pmevcntr29_el0",    CPENC(3,3,C14,C11,5) },
  { "pmevcntr30_el0",    CPENC(3,3,C14,C11,6) },
  { "pmevtyper0_el0",    CPENC(3,3,C14,C12,0) },
  { "pmevtyper1_el0",    CPENC(3,3,C14,C12,1) },
  { "pmevtyper2_el0",    CPENC(3,3,C14,C12,2) },
  { "pmevtyper3_el0",    CPENC(3,3,C14,C12,3) },
  { "pmevtyper4_el0",    CPENC(3,3,C14,C12,4) },
  { "pmevtyper5_el0",    CPENC(3,3,C14,C12,5) },
  { "pmevtyper6_el0",    CPENC(3,3,C14,C12,6) },
  { "pmevtyper7_el0",    CPENC(3,3,C14,C12,7) },
  { "pmevtyper8_el0",    CPENC(3,3,C14,C13,0) },
  { "pmevtyper9_el0",    CPENC(3,3,C14,C13,1) },
  { "pmevtyper10_el0",   CPENC(3,3,C14,C13,2) },
  { "pmevtyper11_el0",   CPENC(3,3,C14,C13,3) },
  { "pmevtyper12_el0",   CPENC(3,3,C14,C13,4) },
  { "pmevtyper13_el0",   CPENC(3,3,C14,C13,5) },
  { "pmevtyper14_el0",   CPENC(3,3,C14,C13,6) },
  { "pmevtyper15_el0",   CPENC(3,3,C14,C13,7) },
  { "pmevtyper16_el0",   CPENC(3,3,C14,C14,0) },
  { "pmevtyper17_el0",   CPENC(3,3,C14,C14,1) },
  { "pmevtyper18_el0",   CPENC(3,3,C14,C14,2) },
  { "pmevtyper19_el0",   CPENC(3,3,C14,C14,3) },
  { "pmevtyper20_el0",   CPENC(3,3,C14,C14,4) },
  { "pmevtyper21_el0",   CPENC(3,3,C14,C14,5) },
  { "pmevtyper22_el0",   CPENC(3,3,C14,C14,6) },
  { "pmevtyper23_el0",   CPENC(3,3,C14,C14,7) },
  { "pmevtyper24_el0",   CPENC(3,3,C14,C15,0) },
  { "pmevtyper25_el0",   CPENC(3,3,C14,C15,1) },
  { "pmevtyper26_el0",   CPENC(3,3,C14,C15,2) },
  { "pmevtyper27_el0",   CPENC(3,3,C14,C15,3) },
  { "pmevtyper28_el0",   CPENC(3,3,C14,C15,4) },
  { "pmevtyper29_el0",   CPENC(3,3,C14,C15,5) },
  { "pmevtyper30_el0",   CPENC(3,3,C14,C15,6) },
  { "pmccfiltr_el0",     CPENC(3,3,C14,C15,7) },
  { 0,          CPENC(0,0,0,0,0)  },
};

const struct aarch64_name_value_pair aarch64_pstatefields [] =
{
  { "spsel",            0x05  },
  { "daifset",          0x1e  },
  { "daifclr",          0x1f  },
  { 0,          CPENC(0,0,0,0,0)  },
};

const aarch64_sys_ins_reg aarch64_sys_regs_ic[] =
{
    { "ialluis", CPENS(0,C7,C1,0), 0 },
    { "iallu",   CPENS(0,C7,C5,0), 0 },
    { "ivau",    CPENS(3,C7,C5,1), 1 },
    { 0, CPENS(0,0,0,0), 0 }
};

const aarch64_sys_ins_reg aarch64_sys_regs_dc[] =
{
    { "zva",        CPENS(3,C7,C4,1),  1 },
    { "ivac",       CPENS(0,C7,C6,1),  1 },
    { "isw",        CPENS(0,C7,C6,2),  1 },
    { "cvac",       CPENS(3,C7,C10,1), 1 },
    { "csw",        CPENS(0,C7,C10,2), 1 },
    { "cvau",       CPENS(3,C7,C11,1), 1 },
    { "civac",      CPENS(3,C7,C14,1), 1 },
    { "cisw",       CPENS(0,C7,C14,2), 1 },
    { 0,       CPENS(0,0,0,0), 0 }
};

const aarch64_sys_ins_reg aarch64_sys_regs_at[] =
{
    { "s1e1r",      CPENS(0,C7,C8,0), 1 },
    { "s1e1w",      CPENS(0,C7,C8,1), 1 },
    { "s1e0r",      CPENS(0,C7,C8,2), 1 },
    { "s1e0w",      CPENS(0,C7,C8,3), 1 },
    { "s12e1r",     CPENS(4,C7,C8,4), 1 },
    { "s12e1w",     CPENS(4,C7,C8,5), 1 },
    { "s12e0r",     CPENS(4,C7,C8,6), 1 },
    { "s12e0w",     CPENS(4,C7,C8,7), 1 },
    { "s1e2r",      CPENS(4,C7,C8,0), 1 },
    { "s1e2w",      CPENS(4,C7,C8,1), 1 },
    { "s1e3r",      CPENS(6,C7,C8,0), 1 },
    { "s1e3w",      CPENS(6,C7,C8,1), 1 },
    { 0,       CPENS(0,0,0,0), 0 }
};

const aarch64_sys_ins_reg aarch64_sys_regs_tlbi[] =
{
    { "vmalle1",   CPENS(0,C8,C7,0), 0 },
    { "vae1",      CPENS(0,C8,C7,1), 1 },
    { "aside1",    CPENS(0,C8,C7,2), 1 },
    { "vaae1",     CPENS(0,C8,C7,3), 1 },
    { "vmalle1is", CPENS(0,C8,C3,0), 0 },
    { "vae1is",    CPENS(0,C8,C3,1), 1 },
    { "aside1is",  CPENS(0,C8,C3,2), 1 },
    { "vaae1is",   CPENS(0,C8,C3,3), 1 },
    { "ipas2e1is", CPENS(4,C8,C0,1), 1 },
    { "ipas2le1is",CPENS(4,C8,C0,5), 1 },
    { "ipas2e1",   CPENS(4,C8,C4,1), 1 },
    { "ipas2le1",  CPENS(4,C8,C4,5), 1 },
    { "vae2",      CPENS(4,C8,C7,1), 1 },
    { "vae2is",    CPENS(4,C8,C3,1), 1 },
    { "vmalls12e1",CPENS(4,C8,C7,6), 0 },
    { "vmalls12e1is",CPENS(4,C8,C3,6), 0 },
    { "vae3",      CPENS(6,C8,C7,1), 1 },
    { "vae3is",    CPENS(6,C8,C3,1), 1 },
    { "alle2",     CPENS(4,C8,C7,0), 0 },
    { "alle2is",   CPENS(4,C8,C3,0), 0 },
    { "alle1",     CPENS(4,C8,C7,4), 0 },
    { "alle1is",   CPENS(4,C8,C3,4), 0 },
    { "alle3",     CPENS(6,C8,C7,0), 0 },
    { "alle3is",   CPENS(6,C8,C3,0), 0 },
    { "vale1is",   CPENS(0,C8,C3,5), 1 },
    { "vale2is",   CPENS(4,C8,C3,5), 1 },
    { "vale3is",   CPENS(6,C8,C3,5), 1 },
    { "vaale1is",  CPENS(0,C8,C3,7), 1 },
    { "vale1",     CPENS(0,C8,C7,5), 1 },
    { "vale2",     CPENS(4,C8,C7,5), 1 },
    { "vale3",     CPENS(6,C8,C7,5), 1 },
    { "vaale1",    CPENS(0,C8,C7,7), 1 },
    { 0,       CPENS(0,0,0,0), 0 }
};

#undef C0
#undef C1
#undef C2
#undef C3
#undef C4
#undef C5
#undef C6
#undef C7
#undef C8
#undef C9
#undef C10
#undef C11
#undef C12
#undef C13
#undef C14
#undef C15

/* Include the opcode description table as well as the operand description
   table.  */
#include "aarch64-tbl.h"
