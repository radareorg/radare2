/* cris.h -- Header file for CRIS opcode and register tables.
   Copyright (C) 2000, 2001, 2004 Free Software Foundation, Inc.
   Contributed by Axis Communications AB, Lund, Sweden.
   Originally written for GAS 1.38.1 by Mikael Asker.
   Updated, BFDized and GNUified by Hans-Peter Nilsson.

This file is part of GAS, GDB and the GNU binutils.

GAS, GDB, and GNU binutils is free software; you can redistribute it
and/or modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 2, or (at your
option) any later version.

GAS, GDB, and GNU binutils are distributed in the hope that they will be
useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef __CRIS_H_INCLUDED_
#define __CRIS_H_INCLUDED_

#if !defined(__STDC__) && !defined(const)
#define const
#endif


/* Registers.  */
#define MAX_REG (15)
#define REG_SP (14)
#define REG_PC (15)

/* CPU version control of disassembly and assembly of instructions.
   May affect how the instruction is assembled, at least the size of
   immediate operands.  */
enum cris_insn_version_usage
{
  /* Any version.  */
  cris_ver_version_all=0,

  /* Indeterminate (intended for disassembly only, or obsolete).  */
  cris_ver_warning,

  /* Only for v0..3 (Etrax 1..4).  */
  cris_ver_v0_3,

  /* Only for v3 or higher (ETRAX 4 and beyond).  */
  cris_ver_v3p,

  /* Only for v8 (Etrax 100).  */
  cris_ver_v8,

  /* Only for v8 or higher (ETRAX 100, ETRAX 100 LX).  */
  cris_ver_v8p,

  /* Only for v0..10.  FIXME: Not sure what to do with this.  */
  cris_ver_sim_v0_10,

  /* Only for v0..10.  */
  cris_ver_v0_10,

  /* Only for v3..10.  (ETRAX 4, ETRAX 100 and ETRAX 100 LX).  */
  cris_ver_v3_10,

  /* Only for v8..10 (ETRAX 100 and ETRAX 100 LX).  */
  cris_ver_v8_10,

  /* Only for v10 (ETRAX 100 LX) and same series.  */
  cris_ver_v10,

  /* Only for v10 (ETRAX 100 LX) and same series.  */
  cris_ver_v10p,

  /* Only for v32 or higher (codename GUINNESS).
     Of course some or all these of may change to cris_ver_v32p if/when
     there's a new revision. */
  cris_ver_v32p
};


/* Special registers.  */
struct cris_spec_reg
{
  const char *const name;
  unsigned int number;

  /* The size of the register.  */
  unsigned int reg_size;

  /* What CPU version the special register of that name is implemented
     in.  If cris_ver_warning, emit an unimplemented-warning.  */
  enum cris_insn_version_usage applicable_version;

  /* There might be a specific warning for using a special register
     here.  */
  const char *const warning;
};
extern const struct cris_spec_reg cris_spec_regs[];


/* Support registers (kind of special too, but not named as such).  */
struct cris_support_reg
{
  const char *const name;
  unsigned int number;
};
extern const struct cris_support_reg cris_support_regs[];

struct cris_cond15
{
  /* The name of the condition.  */
  const char *const name;

  /* What CPU version this condition name applies to.  */
  enum cris_insn_version_usage applicable_version;
};
extern const struct cris_cond15 cris_conds15[];

/* Opcode-dependent constants.  */
#define AUTOINCR_BIT (0x04)

/* Prefixes.  */
#define BDAP_QUICK_OPCODE (0x0100)
#define BDAP_QUICK_Z_BITS (0x0e00)

#define BIAP_OPCODE	  (0x0540)
#define BIAP_Z_BITS	  (0x0a80)

#define DIP_OPCODE	  (0x0970)
#define DIP_Z_BITS	  (0xf280)

#define BDAP_INDIR_LOW	  (0x40)
#define BDAP_INDIR_LOW_Z  (0x80)
#define BDAP_INDIR_HIGH	  (0x09)
#define BDAP_INDIR_HIGH_Z (0x02)

#define BDAP_INDIR_OPCODE (BDAP_INDIR_HIGH * 0x0100 + BDAP_INDIR_LOW)
#define BDAP_INDIR_Z_BITS (BDAP_INDIR_HIGH_Z * 0x100 + BDAP_INDIR_LOW_Z)
#define BDAP_PC_LOW	  (BDAP_INDIR_LOW + REG_PC)
#define BDAP_INCR_HIGH	  (BDAP_INDIR_HIGH + AUTOINCR_BIT)

/* No prefix must have this code for its "match" bits in the
   opcode-table.  "BCC .+2" will do nicely.  */
#define NO_CRIS_PREFIX 0

/* Definitions for condition codes.  */
#define CC_CC  0x0
#define CC_HS  0x0
#define CC_CS  0x1
#define CC_LO  0x1
#define CC_NE  0x2
#define CC_EQ  0x3
#define CC_VC  0x4
#define CC_VS  0x5
#define CC_PL  0x6
#define CC_MI  0x7
#define CC_LS  0x8
#define CC_HI  0x9
#define CC_GE  0xA
#define CC_LT  0xB
#define CC_GT  0xC
#define CC_LE  0xD
#define CC_A   0xE
#define CC_EXT 0xF

/* A table of strings "cc", "cs"... indexed with condition code
   values as above.  */
extern const char *const cris_cc_strings[];

/* Bcc quick.  */
#define BRANCH_QUICK_LOW  (0)
#define BRANCH_QUICK_HIGH (0)
#define BRANCH_QUICK_OPCODE (BRANCH_QUICK_HIGH * 0x0100 + BRANCH_QUICK_LOW)
#define BRANCH_QUICK_Z_BITS (0x0F00)

/* BA quick.  */
#define BA_QUICK_HIGH (BRANCH_QUICK_HIGH + CC_A * 0x10)
#define BA_QUICK_OPCODE (BA_QUICK_HIGH * 0x100 + BRANCH_QUICK_LOW)

/* Bcc [PC+].  */
#define BRANCH_PC_LOW	 (0xFF)
#define BRANCH_INCR_HIGH (0x0D)
#define BA_PC_INCR_OPCODE \
 ((BRANCH_INCR_HIGH + CC_A * 0x10) * 0x0100 + BRANCH_PC_LOW)

/* Jump.  */
/* Note that old versions generated special register 8 (in high bits)
   and not-that-old versions recognized it as a jump-instruction.
   That opcode now belongs to JUMPU.  */
#define JUMP_INDIR_OPCODE (0x0930)
#define JUMP_INDIR_Z_BITS (0xf2c0)
#define JUMP_PC_INCR_OPCODE \
 (JUMP_INDIR_OPCODE + AUTOINCR_BIT * 0x0100 + REG_PC)

#define MOVE_M_TO_PREG_OPCODE 0x0a30
#define MOVE_M_TO_PREG_ZBITS 0x01c0

/* BDAP.D N,PC.  */
#define MOVE_PC_INCR_OPCODE_PREFIX \
 (((BDAP_INCR_HIGH | (REG_PC << 4)) << 8) | BDAP_PC_LOW | (2 << 4))
#define MOVE_PC_INCR_OPCODE_SUFFIX \
 (MOVE_M_TO_PREG_OPCODE | REG_PC | (AUTOINCR_BIT << 8))

#define JUMP_PC_INCR_OPCODE_V32 (0x0DBF)

/* BA DWORD (V32).  */
#define BA_DWORD_OPCODE (0x0EBF)

/* Nop.  */
#define NOP_OPCODE (0x050F)
#define NOP_Z_BITS (0xFFFF ^ NOP_OPCODE)

#define NOP_OPCODE_V32 (0x05B0)
#define NOP_Z_BITS_V32 (0xFFFF ^ NOP_OPCODE_V32)

/* For the compatibility mode, let's use "MOVE R0,P0".  Doesn't affect
   registers or flags.  Unfortunately shuts off interrupts for one cycle
   for < v32, but there doesn't seem to be any alternative without that
   effect.  */
#define NOP_OPCODE_COMMON (0x630)
#define NOP_OPCODE_ZBITS_COMMON (0xffff & ~NOP_OPCODE_COMMON)

/* LAPC.D  */
#define LAPC_DWORD_OPCODE (0x0D7F)
#define LAPC_DWORD_Z_BITS (0x0fff & ~LAPC_DWORD_OPCODE)

/* Structure of an opcode table entry.  */
enum cris_imm_oprnd_size_type
{
  /* No size is applicable.  */
  SIZE_NONE,

  /* Always 32 bits.  */
  SIZE_FIX_32,

  /* Indicated by size of special register.  */
  SIZE_SPEC_REG,

  /* Indicated by size field, signed.  */
  SIZE_FIELD_SIGNED,

  /* Indicated by size field, unsigned.  */
  SIZE_FIELD_UNSIGNED,

  /* Indicated by size field, no sign implied.  */
  SIZE_FIELD
};

/* For GDB.  FIXME: Is this the best way to handle opcode
   interpretation?  */
enum cris_op_type
{
  cris_not_implemented_op = 0,
  cris_abs_op,
  cris_addi_op,
  cris_asr_op,
  cris_asrq_op,
  cris_ax_ei_setf_op,
  cris_bdap_prefix,
  cris_biap_prefix,
  cris_break_op,
  cris_btst_nop_op,
  cris_clearf_di_op,
  cris_dip_prefix,
  cris_dstep_logshift_mstep_neg_not_op,
  cris_eight_bit_offset_branch_op,
  cris_move_mem_to_reg_movem_op,
  cris_move_reg_to_mem_movem_op,
  cris_move_to_preg_op,
  cris_muls_op,
  cris_mulu_op,
  cris_none_reg_mode_add_sub_cmp_and_or_move_op,
  cris_none_reg_mode_clear_test_op,
  cris_none_reg_mode_jump_op,
  cris_none_reg_mode_move_from_preg_op,
  cris_quick_mode_add_sub_op,
  cris_quick_mode_and_cmp_move_or_op,
  cris_quick_mode_bdap_prefix,
  cris_reg_mode_add_sub_cmp_and_or_move_op,
  cris_reg_mode_clear_op,
  cris_reg_mode_jump_op,
  cris_reg_mode_move_from_preg_op,
  cris_reg_mode_test_op,
  cris_scc_op,
  cris_sixteen_bit_offset_branch_op,
  cris_three_operand_add_sub_cmp_and_or_op,
  cris_three_operand_bound_op,
  cris_two_operand_bound_op,
  cris_xor_op
};

struct cris_opcode
{
  /* The name of the insn.  */
  const char *name;

  /* Bits that must be 1 for a match.  */
  unsigned int match;

  /* Bits that must be 0 for a match.  */
  unsigned int lose;

  /* See the table in "opcodes/cris-opc.c".  */
  const char *args;

  /* Nonzero if this is a delayed branch instruction.  */
  char delayed;

  /* Size of immediate operands.  */
  enum cris_imm_oprnd_size_type imm_oprnd_size;

  /* Indicates which version this insn was first implemented in.  */
  enum cris_insn_version_usage applicable_version;

  /* What kind of operation this is.  */
  enum cris_op_type op;
};
extern const struct cris_opcode cris_opcodes[];


/* These macros are for the target-specific flags in disassemble_info
   used at disassembly.  */

/* This insn accesses memory.  This flag is more trustworthy than
   checking insn_type for "dis_dref" which does not work for
   e.g. "JSR [foo]".  */
#define CRIS_DIS_FLAG_MEMREF (1 << 0)

/* The "target" field holds a register number.  */
#define CRIS_DIS_FLAG_MEM_TARGET_IS_REG (1 << 1)

/* The "target2" field holds a register number; add it to "target".  */
#define CRIS_DIS_FLAG_MEM_TARGET2_IS_REG (1 << 2)

/* Yet another add-on: the register in "target2" must be multiplied
   by 2 before adding to "target".  */
#define CRIS_DIS_FLAG_MEM_TARGET2_MULT2 (1 << 3)

/* Yet another add-on: the register in "target2" must be multiplied
   by 4 (mutually exclusive with .._MULT2).  */
#define CRIS_DIS_FLAG_MEM_TARGET2_MULT4 (1 << 4)

/* The register in "target2" is an indirect memory reference (of the
   register there), add to "target".  Assumed size is dword (mutually
   exclusive with .._MULT[24]).  */
#define CRIS_DIS_FLAG_MEM_TARGET2_MEM (1 << 5)

/* Add-on to CRIS_DIS_FLAG_MEM_TARGET2_MEM; the memory access is "byte";
   sign-extended before adding to "target".  */
#define CRIS_DIS_FLAG_MEM_TARGET2_MEM_BYTE (1 << 6)

/* Add-on to CRIS_DIS_FLAG_MEM_TARGET2_MEM; the memory access is "word";
   sign-extended before adding to "target".  */
#define CRIS_DIS_FLAG_MEM_TARGET2_MEM_WORD (1 << 7)

#endif /* __CRIS_H_INCLUDED_ */

/*
 * Local variables:
 * eval: (c-set-style "gnu")
 * indent-tabs-mode: t
 * End:
 */
