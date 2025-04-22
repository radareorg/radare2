/* TI C6X opcode information.
   Copyright (C) 2010-2025 Free Software Foundation, Inc.

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
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#ifndef OPCODE_TIC6X_H
#define OPCODE_TIC6X_H

#include "../../include/mybfd.h"
#include <stdbool.h>
#include "symcat.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A field in an instruction format.  The names are based on those
   used in the architecture manuals.  */
typedef enum
  {
    tic6x_field_baseR,
    tic6x_field_cc,
    tic6x_field_creg,
    tic6x_field_cst,
    tic6x_field_csta,
    tic6x_field_cstb,
    tic6x_field_dst,
    tic6x_field_dstms,
    tic6x_field_dw,
    tic6x_field_fstgfcyc,
    tic6x_field_h,
    tic6x_field_ii,
    tic6x_field_mask,
    tic6x_field_mode,
    tic6x_field_n,
    tic6x_field_na,
    tic6x_field_offsetR,
    tic6x_field_op,
    tic6x_field_p,
    tic6x_field_ptr,
    tic6x_field_r,
    tic6x_field_s,
    tic6x_field_sc,
    tic6x_field_src,
    tic6x_field_src1,
    tic6x_field_src2,
    tic6x_field_srcdst,
    tic6x_field_srcms,
    tic6x_field_sn,
    tic6x_field_sz,
    tic6x_field_unit,
    tic6x_field_t,
    tic6x_field_x,
    tic6x_field_y,
    tic6x_field_z
  } tic6x_insn_field_id;

typedef struct
{
  /* The least-significant bit position in the field.  */
  unsigned short low_pos;

  /* The number of bits in the field.  */
  unsigned short width;
  /* The position of the bitfield in the field. */
  unsigned short pos;
} tic6x_bitfield;

/* Maximum number of subfields in composite field.  */
#define TIC6X_MAX_BITFIELDS 4

typedef struct
{
  /* The name used to reference the field.  */
  tic6x_insn_field_id field_id;
  unsigned int num_bitfields;
  tic6x_bitfield bitfields[TIC6X_MAX_BITFIELDS];
} tic6x_insn_field;

/* Maximum number of variable fields in an instruction format.  */
#define TIC6X_MAX_INSN_FIELDS 11

/* A particular instruction format.  */
typedef struct
{
  /* How many bits in the instruction.  */
  unsigned int num_bits;

  /* Constant bits in the instruction.  */
  unsigned int cst_bits;

  /* Mask matching those bits.  */
  unsigned int mask;

  /* The number of instruction fields.  */
  unsigned int num_fields;

  /* Descriptions of instruction fields.  */
  tic6x_insn_field fields[TIC6X_MAX_INSN_FIELDS];
} tic6x_insn_format;

/* An index into the table of instruction formats.  */
typedef enum
  {
#define FMT(name, num_bits, cst_bits, mask, fields)	\
  CONCAT2(tic6x_insn_format_, name),
#include "tic6x-insn-formats.h"
#undef FMT
    tic6x_insn_format_max
  } tic6x_insn_format_id;

/* The table itself.  */
extern const tic6x_insn_format tic6x_insn_format_table[tic6x_insn_format_max];

/* If instruction format FMT has a field FIELD, return a pointer to
   the description of that field; otherwise return NULL.  */

const tic6x_insn_field *tic6x_field_from_fmt (const tic6x_insn_format *fmt,
					      tic6x_insn_field_id field);

/* Description of a field (in an instruction format) whose value is
   fixed, or constrained to be in a particular range, in a particular
   opcode.  */
typedef struct
{
  /* The name of the field.  */
  tic6x_insn_field_id field_id;

  /* The least value of the field in this instruction.  */
  unsigned int min_val;

  /* The greatest value of the field in this instruction.  */
  unsigned int max_val;
} tic6x_fixed_field;

/* Pseudo opcode fields position for compact instructions
   If 16 bits instruction detected, the opcode is enriched
   [DSZ/3][BR][SAT][opcode] */
#define TIC6X_COMPACT_SAT_POS 16
#define TIC6X_COMPACT_BR_POS 17
#define TIC6X_COMPACT_DSZ_POS 18

/* Bit-masks for defining instructions present on some subset of
   processors; each indicates an instruction present on that processor
   and those that are supersets of it.  The options passed to the
   assembler determine a bit-mask ANDed with the bit-mask indicating
   when the instruction was added to determine whether the instruction
   is enabled.  */
#define TIC6X_INSN_C62X		0x0001
#define TIC6X_INSN_C64X		0x0002
#define TIC6X_INSN_C64XP	0x0004
#define TIC6X_INSN_C67X		0x0008
#define TIC6X_INSN_C67XP	0x0010
#define TIC6X_INSN_C674X	0x0020

/* Flags with further information about an opcode table entry.  */

/* Only used by the assembler, not the disassembler.  */
#define TIC6X_FLAG_MACRO	0x0001

/* Must be first in its execute packet.  */
#define TIC6X_FLAG_FIRST	0x0002

/* Multi-cycle NOP (not used for the NOP n instruction itself, which
   is only a multicycle NOP if n > 1).  */
#define TIC6X_FLAG_MCNOP	0x0004

/* Cannot be in parallel with a multi-cycle NOP.  */
#define TIC6X_FLAG_NO_MCNOP	0x0008

/* Load instruction.  */
#define TIC6X_FLAG_LOAD		0x0010

/* Store instruction.  */
#define TIC6X_FLAG_STORE	0x0020

/* Unaligned memory operation.  */
#define TIC6X_FLAG_UNALIGNED	0x0040

/* Only on side B.  */
#define TIC6X_FLAG_SIDE_B_ONLY	0x0080

/* Only on data path T2.  */
#define TIC6X_FLAG_SIDE_T2_ONLY	0x0100

/* Does not support cross paths.  */
#define TIC6X_FLAG_NO_CROSS	0x0200

/* Annotate this branch instruction as a call.  */
#define TIC6X_FLAG_CALL		0x0400

/* Annotate this branch instruction as a return.  */
#define TIC6X_FLAG_RETURN	0x0800

/* This instruction starts a software pipelined loop.  */
#define TIC6X_FLAG_SPLOOP	0x1000

/* This instruction ends a software pipelined loop.  */
#define TIC6X_FLAG_SPKERNEL	0x2000

/* This instruction takes a list of functional units as parameters;
   although described as having one parameter, the number may be 0 to
   8.  */
#define TIC6X_FLAG_SPMASK	0x4000

/* When more than one opcode matches the assembly source, prefer the
   one with the highest value for this bit-field.  If two opcode table
   entries can match the same syntactic form, they must have different
   values here.  */
#define TIC6X_PREFER_VAL(n)	(((n) & 0x8000) >> 15)
#define TIC6X_FLAG_PREFER(n)	((n) << 15)

/* 16 bits opcode is predicated by register a0 (s = 0) or b0 (s = 1) */
#define TIC6X_FLAG_INSN16_SPRED      0x00100000
/* 16 bits opcode ignores RS bit of fetch packet header */
#define TIC6X_FLAG_INSN16_NORS       0x00200000
/* 16 bits opcode only on side B */
#define TIC6X_FLAG_INSN16_BSIDE      0x00400000
/* 16 bits opcode ptr reg is b15 */
#define TIC6X_FLAG_INSN16_B15PTR     0x00800000
/* 16 bits opcode memory access modes */
#define TIC6X_INSN16_MEM_MODE(n)           ((n) << 16)
#define TIC6X_INSN16_MEM_MODE_VAL(n) (((n) & 0x000F0000) >> 16)
#define TIC6X_MEM_MODE_NEGATIVE      0
#define TIC6X_MEM_MODE_POSITIVE      1
#define TIC6X_MEM_MODE_REG_NEGATIVE  4
#define TIC6X_MEM_MODE_REG_POSITIVE  5
#define TIC6X_MEM_MODE_PREDECR       8
#define TIC6X_MEM_MODE_PREINCR       9
#define TIC6X_MEM_MODE_POSTDECR      10
#define TIC6X_MEM_MODE_POSTINCR      11

#define TIC6X_FLAG_INSN16_MEM_MODE(mode) TIC6X_INSN16_MEM_MODE(TIC6X_MEM_MODE_##mode)

#define TIC6X_NUM_PREFER	2

/* Maximum number of fixed fields for a particular opcode.  */
#define TIC6X_MAX_FIXED_FIELDS 4

/* Maximum number of operands in the opcode table for a particular
   opcode.  */
#define TIC6X_MAX_OPERANDS 4

/* Maximum number of operands in the source code for a particular
   opcode (different from the number in the opcode table for SPMASK
   and SPMASKR).  */
#define TIC6X_MAX_SOURCE_OPERANDS 8

/* Maximum number of variable fields for a particular opcode.  */
#define TIC6X_MAX_VAR_FIELDS 7

/* Which functional units an opcode uses.  This only describes the
   basic choice of D, L, M, S or no functional unit; other fields are
   used to describe further restrictions (instructions only operating
   on one side), use of cross paths and load/store instructions using
   one side for the address and the other side for the source or
   destination register.  */
typedef enum
  {
    tic6x_func_unit_d,
    tic6x_func_unit_l,
    tic6x_func_unit_m,
    tic6x_func_unit_s,
    tic6x_func_unit_nfu
  } tic6x_func_unit_base;

/* Possible forms of source operand.  */
typedef enum
  {
    /* An assembly-time constant.  */
    tic6x_operand_asm_const,
    /* A link-time constant.  */
    tic6x_operand_link_const,
    /* A register, from the same side as the functional unit
       selected.  */
    tic6x_operand_reg,
    /* A register, from the same side as the functional unit
       selected that ignore RS header bit */
    tic6x_operand_reg_nors,
    /* A register, from the b side */
    tic6x_operand_reg_bside,
    /* A register, from the b side and from the low register set */
    tic6x_operand_reg_bside_nors,
    /* A register, that is from the other side if a cross path is
       used.  */
    tic6x_operand_xreg,
    /* A register, that is from the side of the data path
       selected.  */
    tic6x_operand_dreg,
    /* An address register usable with 15-bit offsets (B14 or B15).
       This is from the same side as the functional unit if a cross
       path is not used, and the other side if a cross path is
       used.  */
    tic6x_operand_areg,
    /* The B15 register */
    tic6x_operand_b15reg,
    /* A register coded as an offset from either A16 or B16 depending
       on the value of the t bit. */
    tic6x_operand_treg,
    /* A register (A0 or B0), from the same side as the
       functional unit selected.  */
    tic6x_operand_zreg,
    /* A return address register (A3 or B3), from the same side as the
       functional unit selected.  */
    tic6x_operand_retreg,
    /* A register pair, from the same side as the functional unit
       selected.  */
    tic6x_operand_regpair,
    /* A register pair, that is from the other side if a cross path is
       used.  */
    tic6x_operand_xregpair,
    /* A register pair, from the side of the data path selected.  */
    tic6x_operand_dregpair,
    /* A register pair coded as an offset from either A16 or B16 depending
       on the value of the t bit. */
    tic6x_operand_tregpair,
    /* The literal string "irp" (case-insensitive).  */
    tic6x_operand_irp,
    /* The literal string "nrp" (case-insensitive).  */
    tic6x_operand_nrp,
    /* The literal string "ilc" (case-insensitive).  */
	tic6x_operand_ilc,
    /* A control register.  */
    tic6x_operand_ctrl,
    /* A memory reference (base and offset registers from the side of
       the functional unit selected), using either unsigned 5-bit
       constant or register offset, if any offset; register offsets
       cannot use unscaled () syntax.  */
    tic6x_operand_mem_short,
    /* A memory reference (base and offset registers from the side of
       the functional unit selected), using either unsigned 5-bit
       constant or register offset, if any offset; register offsets
       can use unscaled () syntax (for LDNDW and STNDW).  */
    tic6x_operand_mem_ndw,
    /* A memory reference using 15-bit link-time constant offset
       relative to B14 or B15.  */
    tic6x_operand_mem_long,
    /* A memory reference that only dereferences a register with no
       further adjustments (*REG), that register being from the side
       of the functional unit selected.  */
    tic6x_operand_mem_deref,
    /* A functional unit name or a list thereof (for SPMASK and
       SPMASKR).  */
    tic6x_operand_func_unit,
    /* Hardwired constant '5' in Sbu8 Scs10 and Sbu8c 16 bits
       instruction formats - spru732j.pdf Appendix F.4 */
    tic6x_operand_hw_const_minus_1,
    tic6x_operand_hw_const_0,
    tic6x_operand_hw_const_1,
    tic6x_operand_hw_const_5,
    tic6x_operand_hw_const_16,
    tic6x_operand_hw_const_24,
    tic6x_operand_hw_const_31
  } tic6x_operand_form;

/* Whether something is, or can be, read or written.  */
typedef enum
  {
    tic6x_rw_none,
    tic6x_rw_read,
    tic6x_rw_write,
    tic6x_rw_read_write
  } tic6x_rw;

/* Description of a source operand and how it is used.  */
typedef struct
{
  /* The syntactic form of the operand.  */
  tic6x_operand_form form;

  /* For non-constant operands, the size in bytes (1, 2, 4, 5 or
     8).  Ignored for constant operands.  */
  unsigned int size;

  /* Whether the operand is read, written or both.  In addition to the
     operations described here, address registers are read on cycle 1
     regardless of when the memory operand is read or written, and may
     be modified as described by the addressing mode, and control
     registers may be implicitly read by some instructions.  There are
     also some special cases not fully described by this
     structure.

     - For mpydp, the low part of src2 is read on cycles 1 and 3 but
       not 2, and the high part on cycles 2 and 4 but not 3.

     - The swap2 pseudo-operation maps to packlh2, reading the first
       operand of swap2 twice.  */
  tic6x_rw rw;

  /* The first and last cycles (1 for E1, etc.) at which the operand,
     or the low part for two-register operands, is read or
     written.  */
  unsigned short low_first;
  unsigned short low_last;

  /* Likewise, for the high part.  */
  unsigned short high_first;
  unsigned short high_last;
} tic6x_operand_info;

/* Ways of converting an operand or functional unit specifier to a
   field value.  */
typedef enum
  {
    /* Store an unsigned assembly-time constant (which must fit) in
       the field.  */
    tic6x_coding_ucst,
    /* Store a signed constant (which must fit) in the field.  This
       may be used both for assembly-time constants and for link-time
       constants.  */
    tic6x_coding_scst,
    /* Subtract one from an unsigned assembly-time constant (which
       must be strictly positive before the subtraction) and store the
       value (which must fit) in the field.  */
    tic6x_coding_ucst_minus_one,
    /* Negate a signed assembly-time constant, and store the result of
       negation (which must fit) in the field.  Used only for
       pseudo-operations.  */
    tic6x_coding_scst_negate,
    /* Store an unsigned link-time constant, implicitly DP-relative
       and counting in bytes, in the field.  For expression operands,
       assembly-time constants are encoded as-is.  For memory
       reference operands, the offset is encoded as-is if [] syntax is
       used and shifted if () is used.  */
    tic6x_coding_ulcst_dpr_byte,
    /* Store an unsigned link-time constant, implicitly DP-relative
       and counting in half-words, in the field.  For expression
       operands, assembly-time constants are encoded as-is.  For
       memory reference operands, the offset is encoded as-is if []
       syntax is used and shifted if () is used.  */
    tic6x_coding_ulcst_dpr_half,
    /* Store an unsigned link-time constant, implicitly DP-relative
       and counting in words, in the field.  For expression operands,
       assembly-time constants are encoded as-is.  For memory
       reference operands, the offset is encoded as-is if [] syntax is
       used and shifted if () is used.  */
    tic6x_coding_ulcst_dpr_word,
    /* Store the low 16 bits of a link-time constant in the field;
       considered unsigned for disassembly.  */
    tic6x_coding_lcst_low16,
    /* Store the high 16 bits of a link-time constant in the field;
       considered unsigned for disassembly.  */
    tic6x_coding_lcst_high16,
    /* Store a signed PC-relative value (address of label minus
       address of fetch packet containing the current instruction,
       counted in words) in the field.  */
    tic6x_coding_pcrel,
    /* Likewise, but counting in half-words if in a header-based fetch
       packet.  */
    tic6x_coding_pcrel_half,
    /* Store an unsigned PC-relative value used in compact insn */
    tic6x_coding_pcrel_half_unsigned,
    /* Encode the register number (even number for a register pair) in
       the field.  When applied to a memory reference, encode the base
       register.  */
    tic6x_coding_reg,
    /* Encode the register-pair's lsb (even register) for instructions
       that use src1 as port for loading lsb of double-precision
       operand value (absdp, dpint, dpsp, dptrunc, rcpdp, rsqrdp).  */
    tic6x_coding_regpair_lsb,
    /* Encode the register-pair's msb (odd register), see above.  */
    tic6x_coding_regpair_msb,
    /* Store 0 for register B14, 1 for register B15.  When applied to
       a memory reference, encode the base register.  */
    tic6x_coding_areg,
    /* Compact instruction offset base register */
    tic6x_coding_reg_ptr,
    /* Store the low part of a control register address.  */
    tic6x_coding_crlo,
    /* Store the high part of a control register address.  */
    tic6x_coding_crhi,
    /* Encode the even register number for a register pair, shifted
       right by one bit.  */
    tic6x_coding_reg_shift,
    /* Store either the offset register or the 5-bit unsigned offset
       for a memory reference.  If an offset uses the unscaled ()
       form, which is only permitted with constants, it is scaled
       according to the access size of the operand before being
       stored.  */
    tic6x_coding_mem_offset,
    /* Store either the offset register or the 5-bit unsigned offset
       for a memory reference, but with no scaling applied to the
       offset (for nonaligned doubleword operations).  */
    tic6x_coding_mem_offset_noscale,
    /* Store the addressing mode for a memory reference.  */
    tic6x_coding_mem_mode,
    /* Store whether a memory reference is scaled.  */
    tic6x_coding_scaled,
    /* Store the stage in an SPKERNEL instruction in the upper part of
       the field.  */
    tic6x_coding_fstg,
    /* Store the cycle in an SPKERNEL instruction in the lower part of
       the field.  */
    tic6x_coding_fcyc,
    /* Store the mask bits for functional units in the field in an
       SPMASK or SPMASKR instruction.  */
    tic6x_coding_spmask,
    /* Store the number of a register that is unused, or minimally
       used, in this execute packet.  The number must be the same for
       all uses of this coding in a single instruction, but may be
       different for different instructions in the execute packet.
       This is for the "zero" pseudo-operation.  This is not safe when
       reads may occur from instructions in previous execute packets;
       in such cases the programmer or compiler should use explicit
       "sub" instructions for those cases of "zero" that cannot be
       implemented as "mvk" for the processor specified.  */
    tic6x_coding_reg_unused,
    /* Store 1 if the functional unit used is on side B, 0 for side
       A.  */
    tic6x_coding_fu,
    /* Store 1 if the data path used (source register for store,
       destination for load) is on side B, 0 for side A.  */
    tic6x_coding_data_fu,
    /* Store 1 if the cross path is being used, 0 otherwise.  */
    tic6x_coding_xpath,
    /* L3i constant coding */
    tic6x_coding_scst_l3i,
    /* S3i constant coding */
    tic6x_coding_cst_s3i,
    /* mem offset minus 1 */
    tic6x_coding_mem_offset_minus_one,
    /* non aligned mem offset minus 1 */
    tic6x_coding_mem_offset_minus_one_noscale,
    tic6x_coding_rside
  } tic6x_coding_method;

/* How to generate the value of a particular field.  */
typedef struct
{
  /* The name of the field.  */
  tic6x_insn_field_id field_id;

  /* How it is encoded.  */
  tic6x_coding_method coding_method;

  /* Source operand number, if any.  */
  unsigned int operand_num;
} tic6x_coding_field;

/* Types of instruction for pipeline purposes.  The type determines
   functional unit and cross path latency (when the same functional
   unit can be used by other instructions, when the same cross path
   can be used by other instructions).  */
typedef enum
  {
    tic6x_pipeline_nop,
    tic6x_pipeline_1cycle,
    tic6x_pipeline_1616_m,
    tic6x_pipeline_store,
    tic6x_pipeline_mul_ext,
    tic6x_pipeline_load,
    tic6x_pipeline_branch,
    tic6x_pipeline_2cycle_dp,
    tic6x_pipeline_4cycle,
    tic6x_pipeline_intdp,
    tic6x_pipeline_dpcmp,
    tic6x_pipeline_addsubdp,
    tic6x_pipeline_mpyi,
    tic6x_pipeline_mpyid,
    tic6x_pipeline_mpydp,
    tic6x_pipeline_mpyspdp,
    tic6x_pipeline_mpysp2dp
  } tic6x_pipeline_type;

/* Description of a control register.  */
typedef struct
{
  /* The name of the register.  */
  const char *name;

  /* Which ISA variants include this control register.  */
  unsigned short isa_variants;

  /* Whether it can be read, written or both (in supervisor mode).
     Some registers use the same address, but different names, for
     reading and writing.  */
  tic6x_rw rw;

  /* crlo value for this register.  */
  unsigned int crlo;

  /* Mask that, ANDed with the crhi value in the instruction, must be
     0.  0 is always generated when generating code.  */
  unsigned int crhi_mask;
} tic6x_ctrl;

/* An index into the table of control registers.  */
typedef enum
  {
#define CTRL(name, isa, rw, crlo, crhi_mask)	\
    CONCAT2(tic6x_ctrl_,name),
#include "tic6x-control-registers.h"
#undef CTRL
    tic6x_ctrl_max
  } tic6x_ctrl_id;

/* The table itself.  */
extern const tic6x_ctrl tic6x_ctrl_table[tic6x_ctrl_max];

/* An entry in the opcode table.  */
typedef struct
{
  /* The name of the instruction.  */
  const char *name;

  /* Functional unit used by this instruction (basic information).  */
  tic6x_func_unit_base func_unit;

  /* The format of this instruction.  */
  tic6x_insn_format_id format;

  /* The pipeline type of this instruction.  */
  tic6x_pipeline_type type;

  /* Which ISA variants include this instruction.  */
  unsigned short isa_variants;

  /* Flags for this instruction.  */
  unsigned int flags;

  /* Number of fixed fields, or fields with restricted value ranges,
     for this instruction.  */
  unsigned int num_fixed_fields;

  /* Values of fields fixed for this instruction.  */
  tic6x_fixed_field fixed_fields[TIC6X_MAX_FIXED_FIELDS];

  /* The number of operands in the source form of this
     instruction.  */
  unsigned int num_operands;

  /* Information about individual operands.  */
  tic6x_operand_info operand_info[TIC6X_MAX_OPERANDS];

  /* The number of variable fields for this instruction with encoding
     instructions explicitly given.  */
  unsigned int num_variable_fields;

  /* How fields (other than ones with fixed value) are computed from
     the source operands and functional unit specifiers.  In addition
     to fields specified here:

     - creg, if present, is set from the predicate, along with z which
       must be present if creg is present.

     - p, if present (on all non-compact instructions), is set from
       the parallel bars.
  */
  tic6x_coding_field variable_fields[TIC6X_MAX_VAR_FIELDS];
} tic6x_opcode;

/* An index into the table of opcodes.  */
typedef enum
  {
#define INSN(name, func_unit, format, type, isa, flags, fixed, ops, var) \
    CONCAT6(tic6x_opcode_,name,_,func_unit,_,format),
#define INSNE(name, e, func_unit, format, type, isa, flags, fixed, ops, var) \
    CONCAT4(tic6x_opcode_,name,_,e),
#define INSNU(name, func_unit, format, type, isa, flags, fixed, ops, var) \
    CONCAT6(tic6x_opcode_,name,_,func_unit,_,format),
#define INSNUE(name, e, func_unit, format, type, isa, flags, fixed, ops, var) \
    CONCAT6(tic6x_opcode_,name,_,func_unit,_,e),
#include "tic6x-opcode-table.h"
#undef INSN
#undef INSNE
#undef INSNU
#undef INSNUE
    tic6x_opcode_max
  } tic6x_opcode_id;

/* The table itself.  */
extern const tic6x_opcode tic6x_opcode_table[tic6x_opcode_max];

/* A linked list of opcodes.  */
typedef struct tic6x_opcode_list_tag
{
  tic6x_opcode_id id;
  struct tic6x_opcode_list_tag *next;
} tic6x_opcode_list;

/* The information from a fetch packet header.  */
typedef struct
{
  /* The header itself.  */
  unsigned int header;

  /* Whether each word uses compact instructions.  */
  bool word_compact[7];

  /* Whether loads are protected.  */
  bool prot;

  /* Whether instructions use the high register set.  */
  bool rs;

  /* Data size.  */
  unsigned int dsz;

  /* Whether compact instructions in the S unit are decoded as
     branches.  */
  bool br;

  /* Whether compact instructions saturate.  */
  bool sat;

  /* P-bits.  */
  bool p_bits[14];
} tic6x_fetch_packet_header;

#ifdef __cplusplus
}
#endif

#endif /* OPCODE_TIC6X_H */
