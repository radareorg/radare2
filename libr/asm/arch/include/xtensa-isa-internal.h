/* Internal definitions for configurable Xtensa ISA support.
   Copyright (C) 2003-2015 Free Software Foundation, Inc.

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
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301,
   USA.  */

#ifndef XTENSA_ISA_INTERNAL_H
#define XTENSA_ISA_INTERNAL_H

/* Flags.  */

#define XTENSA_OPERAND_IS_REGISTER	0x00000001
#define XTENSA_OPERAND_IS_PCRELATIVE	0x00000002
#define XTENSA_OPERAND_IS_INVISIBLE	0x00000004
#define XTENSA_OPERAND_IS_UNKNOWN	0x00000008

#define XTENSA_OPCODE_IS_BRANCH		0x00000001
#define XTENSA_OPCODE_IS_JUMP		0x00000002
#define XTENSA_OPCODE_IS_LOOP		0x00000004
#define XTENSA_OPCODE_IS_CALL		0x00000008

#define XTENSA_STATE_IS_EXPORTED	0x00000001
#define XTENSA_STATE_IS_SHARED_OR	0x00000002

#define XTENSA_INTERFACE_HAS_SIDE_EFFECT 0x00000001

/* Function pointer typedefs */
typedef void (*xtensa_format_encode_fn) (xtensa_insnbuf);
typedef void (*xtensa_get_slot_fn) (const xtensa_insnbuf, xtensa_insnbuf);
typedef void (*xtensa_set_slot_fn) (xtensa_insnbuf, const xtensa_insnbuf);
typedef int (*xtensa_opcode_decode_fn) (const xtensa_insnbuf);
typedef uint32 (*xtensa_get_field_fn) (const xtensa_insnbuf);
typedef void (*xtensa_set_field_fn) (xtensa_insnbuf, uint32);
typedef int (*xtensa_immed_decode_fn) (uint32 *);
typedef int (*xtensa_immed_encode_fn) (uint32 *);
typedef int (*xtensa_do_reloc_fn) (uint32 *, uint32);
typedef int (*xtensa_undo_reloc_fn) (uint32 *, uint32);
typedef void (*xtensa_opcode_encode_fn) (xtensa_insnbuf);
typedef int (*xtensa_format_decode_fn) (const xtensa_insnbuf);
typedef int (*xtensa_length_decode_fn) (const unsigned char *);

typedef struct xtensa_format_internal_struct
{
  const char *name;			/* Instruction format name.  */
  int length;				/* Instruction length in bytes.  */
  xtensa_format_encode_fn encode_fn;
  int num_slots;
  int *slot_id;				/* Array[num_slots] of slot IDs.  */
} xtensa_format_internal;

typedef struct xtensa_slot_internal_struct
{
  const char *name;			/* Not necessarily unique.  */
  const char *format;
  int position;
  xtensa_get_slot_fn get_fn;
  xtensa_set_slot_fn set_fn;
  xtensa_get_field_fn *get_field_fns;	/* Array[field_id].  */
  xtensa_set_field_fn *set_field_fns;	/* Array[field_id].  */
  xtensa_opcode_decode_fn opcode_decode_fn;
  const char *nop_name;
} xtensa_slot_internal;

typedef struct xtensa_operand_internal_struct
{
  const char *name;
  int field_id;
  xtensa_regfile regfile;		/* Register file.  */
  int num_regs;				/* Usually 1; 2 for reg pairs, etc.  */
  uint32 flags;				/* See XTENSA_OPERAND_* flags.  */
  xtensa_immed_encode_fn encode;	/* Encode the operand value.  */
  xtensa_immed_decode_fn decode;	/* Decode the value from the field.  */
  xtensa_do_reloc_fn do_reloc;		/* Perform a PC-relative reloc.  */
  xtensa_undo_reloc_fn undo_reloc;	/* Undo a PC-relative relocation.  */
} xtensa_operand_internal;

typedef struct xtensa_arg_internal_struct
{
  union {
    int operand_id;			/* For normal operands.  */
    xtensa_state state;			/* For stateOperands.  */
  } u;
  char inout;				/* Direction: 'i', 'o', or 'm'.  */
} xtensa_arg_internal;

typedef struct xtensa_iclass_internal_struct
{
  int num_operands;			/* Size of "operands" array.  */
  xtensa_arg_internal *operands;	/* Array[num_operands].  */

  int num_stateOperands;		/* Size of "stateOperands" array.  */
  xtensa_arg_internal *stateOperands;	/* Array[num_stateOperands].  */

  int num_interfaceOperands;		/* Size of "interfaceOperands".  */
  xtensa_interface *interfaceOperands;	/* Array[num_interfaceOperands].  */
} xtensa_iclass_internal;

typedef struct xtensa_opcode_internal_struct
{
  const char *name;			/* Opcode mnemonic.  */
  int iclass_id;			/* Iclass for this opcode.  */
  uint32 flags;				/* See XTENSA_OPCODE_* flags.  */
  xtensa_opcode_encode_fn *encode_fns;	/* Array[slot_id].  */
  int num_funcUnit_uses;		/* Number of funcUnit_use entries.  */
  xtensa_funcUnit_use *funcUnit_uses;	/* Array[num_funcUnit_uses].  */
} xtensa_opcode_internal;

typedef struct xtensa_regfile_internal_struct
{
  const char *name;			/* Full name of the regfile.  */
  const char *shortname;		/* Abbreviated name.  */
  xtensa_regfile parent;		/* View parent (or identity).  */
  int num_bits;				/* Width of the registers.  */
  int num_entries;			/* Number of registers.  */
} xtensa_regfile_internal;

typedef struct xtensa_interface_internal_struct
{
  const char *name;			/* Interface name.  */
  int num_bits;				/* Width of the interface.  */
  uint32 flags;				/* See XTENSA_INTERFACE_* flags.  */
  int class_id;				/* Class of related interfaces.  */
  char inout;				/* "i" or "o".  */
} xtensa_interface_internal;

typedef struct xtensa_funcUnit_internal_struct
{
  const char *name;			/* Functional unit name.  */
  int num_copies;			/* Number of instances.  */
} xtensa_funcUnit_internal;

typedef struct xtensa_state_internal_struct
{
  const char *name;			/* State name.  */
  int num_bits;				/* Number of state bits.  */
  uint32 flags;				/* See XTENSA_STATE_* flags.  */
} xtensa_state_internal;

typedef struct xtensa_sysreg_internal_struct
{
  const char *name;			/* Register name.  */
  int number;				/* Register number.  */
  int is_user;				/* Non-zero if a "user register".  */
} xtensa_sysreg_internal;

typedef struct xtensa_lookup_entry_struct
{
  const char *key;
  union
  {
    xtensa_opcode opcode;		/* Internal opcode number.  */
    xtensa_sysreg sysreg;		/* Internal sysreg number.  */
    xtensa_state state;			/* Internal state number.  */
    xtensa_interface intf;		/* Internal interface number.  */
    xtensa_funcUnit fun;		/* Internal funcUnit number.  */
  } u;
} xtensa_lookup_entry;

typedef struct xtensa_isa_internal_struct
{
  int is_big_endian;			/* Endianness.  */
  int insn_size;			/* Maximum length in bytes.  */
  int insnbuf_size;			/* Number of insnbuf_words.  */

  int num_formats;
  xtensa_format_internal *formats;
  xtensa_format_decode_fn format_decode_fn;
  xtensa_length_decode_fn length_decode_fn;

  int num_slots;
  xtensa_slot_internal *slots;

  int num_fields;

  int num_operands;
  xtensa_operand_internal *operands;

  int num_iclasses;
  xtensa_iclass_internal *iclasses;

  int num_opcodes;
  xtensa_opcode_internal *opcodes;
  xtensa_lookup_entry *opname_lookup_table;

  int num_regfiles;
  xtensa_regfile_internal *regfiles;

  int num_states;
  xtensa_state_internal *states;
  xtensa_lookup_entry *state_lookup_table;

  int num_sysregs;
  xtensa_sysreg_internal *sysregs;
  xtensa_lookup_entry *sysreg_lookup_table;

  /* The current Xtensa ISA only supports 256 of each kind of sysreg so
     we can get away with implementing lookups with tables indexed by
     the register numbers.  If we ever allow larger sysreg numbers, this
     may have to be reimplemented.  The first entry in the following
     arrays corresponds to "special" registers and the second to "user"
     registers.  */
  int max_sysreg_num[2];
  xtensa_sysreg *sysreg_table[2];

  int num_interfaces;
  xtensa_interface_internal *interfaces;
  xtensa_lookup_entry *interface_lookup_table;

  int num_funcUnits;
  xtensa_funcUnit_internal *funcUnits;
  xtensa_lookup_entry *funcUnit_lookup_table;

} xtensa_isa_internal;

extern int xtensa_isa_name_compare (const void *, const void *);

extern xtensa_isa_status xtisa_errno;
extern char xtisa_error_msg[];

#endif /* !XTENSA_ISA_INTERNAL_H */
