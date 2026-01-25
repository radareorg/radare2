/* Disassembler structures definitions for the ARC.
   Copyright (C) 1994-2026 Free Software Foundation, Inc.

   Contributed by Claudiu Zissulescu (claziss@synopsys.com)

   This file is part of libopcodes.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef ARCDIS_H
#define ARCDIS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Legacy arcDisState structure needed by arcompact-dis.c */
enum NullifyMode
{
  BR_exec_when_no_jump,
  BR_exec_always,
  BR_exec_when_jump
};

enum ARC_Debugger_OperandType
{
    ARC_UNDEFINED,
    ARC_LIMM,
    ARC_SHIMM,
    ARC_REGISTER,
    ARCOMPACT_REGISTER
};

enum Flow
{
  noflow,
  direct_jump,
  direct_call,
  indirect_jump,
  indirect_call,
  invalid_instr
};

enum { no_reg = 99 };
enum { allOperandsSize = 256 };

struct arcDisState
{
  void *_this;
  int instructionLen;
  void (*err)(void*, const char*);
  const char *(*coreRegName)(void*, int);
  const char *(*auxRegName)(void*, int);
  const char *(*condCodeName)(void*, int);
  const char *(*instName)(void*, int, int, int*);

  unsigned char* instruction;
  unsigned index;
  const char *comm[6];

  union {
    unsigned int registerNum;
    unsigned int shortimm;
    unsigned int longimm;
  } source_operand;
  enum ARC_Debugger_OperandType sourceType;

  int opWidth;
  int targets[4];
  unsigned int addresses[4];
  enum Flow flow;
  int register_for_indirect_jump;
  int ea_reg1, ea_reg2, _offset;
  int _cond, _opcode;
  unsigned long words[2];
  char *commentBuffer;
  char instrBuffer[40];
  char operandBuffer[allOperandsSize];
  char _ea_present;
  char _addrWriteBack;
  char _mem_load;
  char _load_len;
  enum NullifyMode nullifyMode;
  unsigned char commNum;
  unsigned char isBranch;
  unsigned char tcnt;
  unsigned char acnt;
};

#define __TRANSLATION_REQUIRED(state)	((state).acnt != 0)

/* New arc_instruction support */
enum arc_ldst_writeback_mode
{
  ARC_WRITEBACK_NO = 0,
  ARC_WRITEBACK_AW = 1,
  ARC_WRITEBACK_A = ARC_WRITEBACK_AW,
  ARC_WRITEBACK_AB = 2,
  ARC_WRITEBACK_AS = 3,
};


enum arc_ldst_data_size
{
  ARC_SCALING_NONE = 4,
  ARC_SCALING_B = 1,
  ARC_SCALING_H = 2,
  ARC_SCALING_D = 8,
};


enum arc_condition_code
{
  ARC_CC_AL = 0x0,
  ARC_CC_RA = ARC_CC_AL,
  ARC_CC_EQ = 0x1,
  ARC_CC_Z = ARC_CC_EQ,
  ARC_CC_NE = 0x2,
  ARC_CC_NZ = ARC_CC_NE,
  ARC_CC_PL = 0x3,
  ARC_CC_P = ARC_CC_PL,
  ARC_CC_MI = 0x4,
  ARC_CC_N = ARC_CC_MI,
  ARC_CC_CS = 0x5,
  ARC_CC_C = ARC_CC_CS,
  ARC_CC_LO = ARC_CC_CS,
  ARC_CC_CC = 0x6,
  ARC_CC_NC = ARC_CC_CC,
  ARC_CC_HS = ARC_CC_CC,
  ARC_CC_VS = 0x7,
  ARC_CC_V = ARC_CC_VS,
  ARC_CC_VC = 0x8,
  ARC_CC_NV = ARC_CC_VC,
  ARC_CC_GT = 0x9,
  ARC_CC_GE = 0xA,
  ARC_CC_LT = 0xB,
  ARC_CC_LE = 0xC,
  ARC_CC_HI = 0xD,
  ARC_CC_LS = 0xE,
  ARC_CC_PNZ = 0xF,
  ARC_CC_UNDEF0 = 0x10,
  ARC_CC_UNDEF1 = 0x11,
  ARC_CC_UNDEF2 = 0x12,
  ARC_CC_UNDEF3 = 0x13,
  ARC_CC_UNDEF4 = 0x14,
  ARC_CC_UNDEF5 = 0x15,
  ARC_CC_UNDEF6 = 0x16,
  ARC_CC_UNDEF7 = 0x17,
  ARC_CC_UNDEF8 = 0x18,
  ARC_CC_UNDEF9 = 0x19,
  ARC_CC_UNDEFA = 0x1A,
  ARC_CC_UNDEFB = 0x1B,
  ARC_CC_UNDEFC = 0x1C,
  ARC_CC_UNDEFD = 0x1D,
  ARC_CC_UNDEFE = 0x1E,
  ARC_CC_UNDEFF = 0x1F
};

enum arc_operand_kind
{
  ARC_OPERAND_KIND_UNKNOWN = 0,
  ARC_OPERAND_KIND_REG,
  ARC_OPERAND_KIND_SHIMM,
  ARC_OPERAND_KIND_LIMM
};

struct arc_insn_operand
{
  /* Operand value as encoded in instruction.  */
  unsigned long value;

  enum arc_operand_kind kind;
};

/* Container for information about instruction.  Provides a higher
   level access to data that is contained in struct arc_opcode.  */

struct arc_instruction
{
  /* Address of this instruction.  */
  bfd_vma address;

  /* Whether this is a valid instruction.  */
  bool valid;

  insn_class_t insn_class;

  /* Length (without LIMM).  */
  unsigned length;

  /* Is there a LIMM in this instruction?  */
  int limm_p;

  /* Long immediate value.  */
  unsigned limm_value;

  /* Is it a branch/jump instruction?  */
  int is_control_flow;

  /* Whether this instruction has a delay slot.  */
  int has_delay_slot;

  /* Value of condition code field.  */
  enum arc_condition_code condition_code;

  /* Load/store writeback mode.  */
  enum arc_ldst_writeback_mode writeback_mode;

  /* Load/store data size.  */
  enum arc_ldst_data_size data_size_mode;

  /* Amount of operands in instruction.  Note that amount of operands
     reported by opcodes disassembler can be different from the one
     encoded in the instruction.  Notable case is "ld a,[b,offset]",
     when offset == 0.  In this case opcodes disassembler presents
     this instruction as "ld a,[b]", hence there are *two* operands,
     not three.  OPERANDS_COUNT and OPERANDS contain only those
     explicit operands, hence it is up to invoker to handle the case
     described above based on instruction opcodes.  Another notable
     thing is that in opcodes disassembler representation square
     brackets (`[' and `]') are so called fake-operands - they are in
     the list of operands, but do not have any value of they own.
     Those "operands" are not present in this array.  */
  struct arc_insn_operand operands[MAX_INSN_ARGS];

  unsigned int operands_count;
};

/* Fill INSN with data about instruction at specified ADDR.  */

void arc_insn_decode (bfd_vma addr,
		      struct disassemble_info *di,
		      disassembler_ftype func,
		      struct arc_instruction *insn);

#ifdef __cplusplus
}
#endif

#endif
