/* Disassembler structures definitions for the ARC.
   Copyright 1994, 1995, 1997, 1998, 2000, 2001, 2009
   Free Software Foundation, Inc.
   Contributed by Doug Evans (dje@cygnus.com).

   Copyright 2008-2012 Synopsys Inc.

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

#ifndef ARC_DIS_H
#define ARC_DIS_H

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
    ARCOMPACT_REGISTER /* Valid only for the
                          registers allowed in
                          16 bit mode */
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
  const char *comm[6]; /* instr name, cond, NOP, 3 operands */

  union {
    unsigned int registerNum;
    unsigned int shortimm;
    unsigned int longimm;
  } source_operand;
  enum ARC_Debugger_OperandType sourceType;

  int opWidth;
  int targets[4];
  /* START ARC LOCAL */
  unsigned int addresses[4];
  /* END ARC LOCAL */
  /* Set as a side-effect of calling the disassembler.
     Used only by the debugger.  */
  enum Flow flow;
  int register_for_indirect_jump;
  int ea_reg1, ea_reg2, _offset;
  int _cond, _opcode;
  unsigned long words[2];
  char *commentBuffer;
  char instrBuffer[40];
  char operandBuffer[allOperandsSize];
  char _ea_present;
  char _addrWriteBack; /* Address writeback */
  char _mem_load;
  char _load_len;
  enum NullifyMode nullifyMode;
  unsigned char commNum;
  unsigned char isBranch;
  unsigned char tcnt;
  unsigned char acnt;
};

#if 0
int ARCTangent_decodeInstr(bfd_vma address, disassemble_info* info);
#endif
int ARCompact_decodeInstr (bfd_vma address, disassemble_info* info);

#define __TRANSLATION_REQUIRED(state)	((state).acnt != 0)

#endif /* ARC_DIS_H */
