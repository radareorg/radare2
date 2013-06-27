/* aarch64-opc.h -- Header file for aarch64-opc.c and aarch64-opc-2.c.
   Copyright 2012  Free Software Foundation, Inc.
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

#ifndef OPCODES_AARCH64_OPC_H
#define OPCODES_AARCH64_OPC_H

#include <string.h>
#include "aarch64.h"

/* Instruction fields.
   Keep synced with fields.  */
enum aarch64_field_kind
{
  FLD_NIL,
  FLD_cond2,
  FLD_nzcv,
  FLD_defgh,
  FLD_abc,
  FLD_imm19,
  FLD_immhi,
  FLD_immlo,
  FLD_size,
  FLD_vldst_size,
  FLD_op,
  FLD_Q,
  FLD_Rt,
  FLD_Rd,
  FLD_Rn,
  FLD_Rt2,
  FLD_Ra,
  FLD_op2,
  FLD_CRm,
  FLD_CRn,
  FLD_op1,
  FLD_op0,
  FLD_imm3,
  FLD_cond,
  FLD_opcode,
  FLD_cmode,
  FLD_asisdlso_opcode,
  FLD_len,
  FLD_Rm,
  FLD_Rs,
  FLD_option,
  FLD_S,
  FLD_hw,
  FLD_opc,
  FLD_opc1,
  FLD_shift,
  FLD_type,
  FLD_ldst_size,
  FLD_imm6,
  FLD_imm4,
  FLD_imm5,
  FLD_imm7,
  FLD_imm8,
  FLD_imm9,
  FLD_imm12,
  FLD_imm14,
  FLD_imm16,
  FLD_imm26,
  FLD_imms,
  FLD_immr,
  FLD_immb,
  FLD_immh,
  FLD_N,
  FLD_index,
  FLD_index2,
  FLD_sf,
  FLD_H,
  FLD_L,
  FLD_M,
  FLD_b5,
  FLD_b40,
  FLD_scale,
};

/* Field description.  */
struct aarch64_field
{
  int lsb;
  int width;
};

typedef struct aarch64_field aarch64_field;

extern const aarch64_field fields[];

/* Operand description.  */

struct aarch64_operand
{
  enum aarch64_operand_class op_class;

  /* Name of the operand code; used mainly for the purpose of internal
     debugging.  */
  const char *name;

  unsigned int flags;

  /* The associated instruction bit-fields; no operand has more than 4
     bit-fields */
  enum aarch64_field_kind fields[4];

  /* Brief description */
  const char *desc;
};

typedef struct aarch64_operand aarch64_operand;

extern const aarch64_operand aarch64_operands[];

/* Operand flags.  */

#define OPD_F_HAS_INSERTER	0x00000001
#define OPD_F_HAS_EXTRACTOR	0x00000002
#define OPD_F_SEXT		0x00000004	/* Require sign-extension.  */
#define OPD_F_SHIFT_BY_2	0x00000008	/* Need to left shift the field
						   value by 2 to get the value
						   of an immediate operand.  */
#define OPD_F_MAYBE_SP		0x00000010	/* May potentially be SP.  */

static inline bfd_boolean
operand_has_inserter (const aarch64_operand *operand)
{
  return (operand->flags & OPD_F_HAS_INSERTER) ? TRUE : FALSE;
}

static inline bfd_boolean
operand_has_extractor (const aarch64_operand *operand)
{
  return (operand->flags & OPD_F_HAS_EXTRACTOR) ? TRUE : FALSE;
}

static inline bfd_boolean
operand_need_sign_extension (const aarch64_operand *operand)
{
  return (operand->flags & OPD_F_SEXT) ? TRUE : FALSE;
}

static inline bfd_boolean
operand_need_shift_by_two (const aarch64_operand *operand)
{
  return (operand->flags & OPD_F_SHIFT_BY_2) ? TRUE : FALSE;
}

static inline bfd_boolean
operand_maybe_stack_pointer (const aarch64_operand *operand)
{
  return (operand->flags & OPD_F_MAYBE_SP) ? TRUE : FALSE;
}

/* Return the total width of the operand *OPERAND.  */
static inline unsigned
get_operand_fields_width (const aarch64_operand *operand)
{
  int i = 0;
  unsigned width = 0;
  while (operand->fields[i] != FLD_NIL)
    width += fields[operand->fields[i++]].width;
  assert (width > 0 && width < 32);
  return width;
}

static inline const aarch64_operand *
get_operand_from_code (enum aarch64_opnd code)
{
  return aarch64_operands + code;
}

/* Operand qualifier and operand constraint checking.  */

int aarch64_match_operands_constraint (aarch64_inst *,
				       aarch64_operand_error *);

/* Operand qualifier related functions.  */
const char* aarch64_get_qualifier_name (aarch64_opnd_qualifier_t);
unsigned char aarch64_get_qualifier_nelem (aarch64_opnd_qualifier_t);
aarch64_insn aarch64_get_qualifier_standard_value (aarch64_opnd_qualifier_t);
int aarch64_find_best_match (const aarch64_inst *,
			     const aarch64_opnd_qualifier_seq_t *,
			     int, aarch64_opnd_qualifier_t *);

static inline void
reset_operand_qualifier (aarch64_inst *inst, int idx)
{
  assert (idx >=0 && idx < aarch64_num_of_operands (inst->opcode));
  inst->operands[idx].qualifier = AARCH64_OPND_QLF_NIL;
}

/* Inline functions operating on instruction bit-field(s).  */

/* Generate a mask that has WIDTH number of consecutive 1s.  */

static inline aarch64_insn
gen_mask (int width)
{
  return ((aarch64_insn) 1 << width) - 1;
}

/* LSB_REL is the relative location of the lsb in the sub field, starting from 0.  */
static inline int
gen_sub_field (enum aarch64_field_kind kind, int lsb_rel, int width, aarch64_field *ret)
{
  const aarch64_field *field = &fields[kind];
  if (lsb_rel < 0 || width <= 0 || lsb_rel + width > field->width)
    return 0;
  ret->lsb = field->lsb + lsb_rel;
  ret->width = width;
  return 1;
}

/* Insert VALUE into FIELD of CODE.  MASK can be zero or the base mask
   of the opcode.  */

static inline void
insert_field_2 (const aarch64_field *field, aarch64_insn *code,
		aarch64_insn value, aarch64_insn mask)
{
  assert (field->width < 32 && field->width >= 1 && field->lsb >= 0
	  && field->lsb + field->width <= 32);
  value &= gen_mask (field->width);
  value <<= field->lsb;
  /* In some opcodes, field can be part of the base opcode, e.g. the size
     field in FADD.  The following helps avoid corrupt the base opcode.  */
  value &= ~mask;
  *code |= value;
}

/* Extract FIELD of CODE and return the value.  MASK can be zero or the base
   mask of the opcode.  */

static inline aarch64_insn
extract_field_2 (const aarch64_field *field, aarch64_insn code,
		 aarch64_insn mask)
{
  aarch64_insn value;
  /* Clear any bit that is a part of the base opcode.  */
  code &= ~mask;
  value = (code >> field->lsb) & gen_mask (field->width);
  return value;
}

/* Insert VALUE into field KIND of CODE.  MASK can be zero or the base mask
   of the opcode.  */

static inline void
insert_field (enum aarch64_field_kind kind, aarch64_insn *code,
	      aarch64_insn value, aarch64_insn mask)
{
  insert_field_2 (&fields[kind], code, value, mask);
}

/* Extract field KIND of CODE and return the value.  MASK can be zero or the
   base mask of the opcode.  */

static inline aarch64_insn
extract_field (enum aarch64_field_kind kind, aarch64_insn code,
	       aarch64_insn mask)
{
  return extract_field_2 (&fields[kind], code, mask);
}

/* Inline functions selecting operand to do the encoding/decoding for a
   certain instruction bit-field.  */

/* Select the operand to do the encoding/decoding of the 'sf' field.
   The heuristic-based rule is that the result operand is respected more.  */

static inline int
select_operand_for_sf_field_coding (const aarch64_opcode *opcode)
{
  int idx = -1;
  if (aarch64_get_operand_class (opcode->operands[0])
      == AARCH64_OPND_CLASS_INT_REG)
    /* normal case.  */
    idx = 0;
  else if (aarch64_get_operand_class (opcode->operands[1])
	   == AARCH64_OPND_CLASS_INT_REG)
    /* e.g. float2fix.  */
    idx = 1;
  else
    { assert (0); abort (); }
  return idx;
}

/* Select the operand to do the encoding/decoding of the 'type' field in
   the floating-point instructions.
   The heuristic-based rule is that the source operand is respected more.  */

static inline int
select_operand_for_fptype_field_coding (const aarch64_opcode *opcode)
{
  int idx;
  if (aarch64_get_operand_class (opcode->operands[1])
      == AARCH64_OPND_CLASS_FP_REG)
    /* normal case.  */
    idx = 1;
  else if (aarch64_get_operand_class (opcode->operands[0])
	   == AARCH64_OPND_CLASS_FP_REG)
    /* e.g. float2fix.  */
    idx = 0;
  else
    { assert (0); abort (); }
  return idx;
}

/* Select the operand to do the encoding/decoding of the 'size' field in
   the AdvSIMD scalar instructions.
   The heuristic-based rule is that the destination operand is respected
   more.  */

static inline int
select_operand_for_scalar_size_field_coding (const aarch64_opcode *opcode)
{
  int src_size = 0, dst_size = 0;
  if (aarch64_get_operand_class (opcode->operands[0])
      == AARCH64_OPND_CLASS_SISD_REG)
    dst_size = aarch64_get_qualifier_esize (opcode->qualifiers_list[0][0]);
  if (aarch64_get_operand_class (opcode->operands[1])
      == AARCH64_OPND_CLASS_SISD_REG)
    src_size = aarch64_get_qualifier_esize (opcode->qualifiers_list[0][1]);
  if (src_size == dst_size && src_size == 0)
    { assert (0); abort (); }
  /* When the result is not a sisd register or it is a long operantion.  */
  if (dst_size == 0 || dst_size == src_size << 1)
    return 1;
  else
    return 0;
}

/* Select the operand to do the encoding/decoding of the 'size:Q' fields in
   the AdvSIMD instructions.  */

int aarch64_select_operand_for_sizeq_field_coding (const aarch64_opcode *);

/* Miscellaneous.  */

aarch64_insn aarch64_get_operand_modifier_value (enum aarch64_modifier_kind);
enum aarch64_modifier_kind
aarch64_get_operand_modifier_from_value (aarch64_insn, bfd_boolean);


bfd_boolean aarch64_wide_constant_p (int64_t, int, unsigned int *);
bfd_boolean aarch64_logical_immediate_p (uint64_t, int, aarch64_insn *);
int aarch64_shrink_expanded_imm8 (uint64_t);

/* Copy the content of INST->OPERANDS[SRC] to INST->OPERANDS[DST].  */
static inline void
copy_operand_info (aarch64_inst *inst, int dst, int src)
{
  assert (dst >= 0 && src >= 0 && dst < AARCH64_MAX_OPND_NUM
	  && src < AARCH64_MAX_OPND_NUM);
  memcpy (&inst->operands[dst], &inst->operands[src],
	  sizeof (aarch64_opnd_info));
  inst->operands[dst].idx = dst;
}

/* A primitive log caculator.  */

static inline unsigned int
get_logsz (unsigned int size)
{
  const unsigned char ls[16] =
    {0, 1, -1, 2, -1, -1, -1, 3, -1, -1, -1, -1, -1, -1, -1, 4};
  if (size > 16)
    {
      assert (0);
      return -1;
    }
  assert (ls[size - 1] != (unsigned char)-1);
  return ls[size - 1];
}

#endif /* OPCODES_AARCH64_OPC_H */
