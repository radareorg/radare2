/* ARC target-dependent stuff.  Extension data structures.
   Copyright (C) 1995-2026 Free Software Foundation, Inc.

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
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/*This header file defines a table of extensions to the ARC processor
  architecture.  These extensions are read from the '.arcextmap' or
  '.gnu.linkonce.arcextmap.<type>.<N>' sections in the ELF file which
  is identified by the bfd parameter to the build_ARC_extmap function.

  These extensions may include:
	 core registers
	 auxiliary registers
	 instructions
	 condition codes

  Once the table has been constructed, accessor functions may be used
  to retrieve information from it.

  The build_ARC_extmap constructor function build_ARC_extmap may be
  called as many times as required; it will re-initialize the table
  each time.  */

#ifndef ARC_EXTENSIONS_H
#define ARC_EXTENSIONS_H

#include "arc.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IGNORE_FIRST_OPD 1

/* Define this if we do not want to encode instructions based on the
   ARCompact Programmer's Reference.  */
#define UNMANGLED

/* This defines the kinds of extensions which may be read from the
   ections in the executable files.  */
enum ExtOperType
{
  EXT_INSTRUCTION	     = 0,
  EXT_CORE_REGISTER	     = 1,
  EXT_AUX_REGISTER	     = 2,
  EXT_COND_CODE		     = 3,
  EXT_INSTRUCTION32	     = 4,
  EXT_AC_INSTRUCTION	     = 4,
  EXT_REMOVE_CORE_REG	     = 5,
  EXT_LONG_CORE_REGISTER     = 6,
  EXT_AUX_REGISTER_EXTENDED  = 7,
  EXT_INSTRUCTION32_EXTENDED = 8,
  EXT_CORE_REGISTER_CLASS    = 9
};

enum ExtReadWrite
{
  REG_INVALID,
  REG_READ,
  REG_WRITE,
  REG_READWRITE
};

/* Macro used when generating the patterns for an extension
   instruction.  */
#define INSERT_XOP(OP, NAME, CODE, MASK, CPU, ARG, FLG)	\
  do {							\
    (OP)->name   = NAME;				\
    (OP)->opcode = CODE;				\
    (OP)->mask   = MASK;				\
    (OP)->cpu    = CPU;					\
    (OP)->insn_class  = ARITH;				\
    (OP)->subclass = NONE;				\
    memcpy ((OP)->operands, (ARG), MAX_INSN_ARGS);	\
    memcpy ((OP)->flags, (FLG), MAX_INSN_FLGS);		\
    (OP++);						\
  } while (0)

/* Typedef to hold the extension instruction definition.  */
typedef struct ExtInstruction
{
  /* Name.  */
  char *name;

  /* Major opcode.  */
  char major;

  /* Minor(sub) opcode.  */
  char minor;

  /* Flags, holds the syntax class and modifiers.  */
  char flags;

  /* Syntax class.  Use by assembler.  */
  unsigned char syntax;

  /* Syntax class modifier.  Used by assembler.  */
  unsigned char modsyn;

  /* Suffix class.  Used by assembler.  */
  unsigned char suffix;

  /* Pointer to the next extension instruction.  */
  struct ExtInstruction* next;
} extInstruction_t;

/* Constructor function.  */
extern void build_ARC_extmap (bfd *);

/* Accessor functions.  */
extern enum ExtReadWrite arcExtMap_coreReadWrite (int);
extern const char * arcExtMap_coreRegName (int);
extern const char * arcExtMap_auxRegName (unsigned);
extern const char * arcExtMap_condCodeName (int);
extern const extInstruction_t *arcExtMap_insn (int, unsigned long long);
extern struct arc_opcode *arcExtMap_genOpcode (const extInstruction_t *,
					       unsigned arc_target,
					       const char **errmsg);

/* Dump function (for debugging).  */
extern void dump_ARC_extmap (void);

#ifdef __cplusplus
}
#endif

#endif /* ARC_EXTENSIONS_H */
