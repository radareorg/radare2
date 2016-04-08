/* Interface definition for configurable Xtensa ISA support.
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

#ifndef XTENSA_LIBISA_H
#define XTENSA_LIBISA_H

#ifdef __cplusplus
extern "C" {
#endif

/* Version number: This is intended to help support code that works with
   versions of this library from multiple Xtensa releases.  */

#define XTENSA_ISA_VERSION 7000

#ifndef uint32
#define uint32 unsigned int
#endif

/* This file defines the interface to the Xtensa ISA library.  This
   library contains most of the ISA-specific information for a
   particular Xtensa processor.  For example, the set of valid
   instructions, their opcode encodings and operand fields are all
   included here.

   This interface basically defines a number of abstract data types.

   . an instruction buffer - for holding the raw instruction bits
   . ISA info - information about the ISA as a whole
   . instruction formats - instruction size and slot structure
   . opcodes - information about individual instructions
   . operands - information about register and immediate instruction operands
   . stateOperands - information about processor state instruction operands
   . interfaceOperands - information about interface instruction operands
   . register files - register file information
   . processor states - internal processor state information
   . system registers - "special registers" and "user registers"
   . interfaces - TIE interfaces that are external to the processor
   . functional units - TIE shared functions

   The interface defines a set of functions to access each data type.
   With the exception of the instruction buffer, the internal
   representations of the data structures are hidden.  All accesses must
   be made through the functions defined here.  */

typedef struct xtensa_isa_opaque { int unused; } *xtensa_isa;


/* Most of the Xtensa ISA entities (e.g., opcodes, regfiles, etc.) are
   represented here using sequential integers beginning with 0.  The
   specific values are only fixed for a particular instantiation of an
   xtensa_isa structure, so these values should only be used
   internally.  */

typedef int xtensa_opcode;
typedef int xtensa_format;
typedef int xtensa_regfile;
typedef int xtensa_state;
typedef int xtensa_sysreg;
typedef int xtensa_interface;
typedef int xtensa_funcUnit;


/* Define a unique value for undefined items.  */

#define XTENSA_UNDEFINED -1


/* Overview of using this interface to decode/encode instructions:

   Each Xtensa instruction is associated with a particular instruction
   format, where the format defines a fixed number of slots for
   operations.  The formats for the core Xtensa ISA have only one slot,
   but FLIX instructions may have multiple slots.  Within each slot,
   there is a single opcode and some number of associated operands.

   The encoding and decoding functions operate on instruction buffers,
   not on the raw bytes of the instructions.  The same instruction
   buffer data structure is used for both entire instructions and
   individual slots in those instructions -- the contents of a slot need
   to be extracted from or inserted into the buffer for the instruction
   as a whole.

   Decoding an instruction involves first finding the format, which
   identifies the number of slots, and then decoding each slot
   separately.  A slot is decoded by finding the opcode and then using
   the opcode to determine how many operands there are.  For example:

   xtensa_insnbuf_from_chars
   xtensa_format_decode
   for each slot {
     xtensa_format_get_slot
     xtensa_opcode_decode
     for each operand {
       xtensa_operand_get_field
       xtensa_operand_decode
     }
   }

   Encoding an instruction is roughly the same procedure in reverse:

   xtensa_format_encode
   for each slot {
     xtensa_opcode_encode
     for each operand {
       xtensa_operand_encode
       xtensa_operand_set_field
     }
     xtensa_format_set_slot
   }
   xtensa_insnbuf_to_chars
*/


/* Error handling.  */

/* Error codes.  The code for the most recent error condition can be
   retrieved with the "errno" function.  For any result other than
   xtensa_isa_ok, an error message containing additional information
   about the problem can be retrieved using the "error_msg" function.
   The error messages are stored in an internal buffer, which should
   not be freed and may be overwritten by subsequent operations.  */

typedef enum xtensa_isa_status_enum
{
  xtensa_isa_ok = 0,
  xtensa_isa_bad_format,
  xtensa_isa_bad_slot,
  xtensa_isa_bad_opcode,
  xtensa_isa_bad_operand,
  xtensa_isa_bad_field,
  xtensa_isa_bad_iclass,
  xtensa_isa_bad_regfile,
  xtensa_isa_bad_sysreg,
  xtensa_isa_bad_state,
  xtensa_isa_bad_interface,
  xtensa_isa_bad_funcUnit,
  xtensa_isa_wrong_slot,
  xtensa_isa_no_field,
  xtensa_isa_out_of_memory,
  xtensa_isa_buffer_overflow,
  xtensa_isa_internal_error,
  xtensa_isa_bad_value
} xtensa_isa_status;

extern xtensa_isa_status
xtensa_isa_errno (xtensa_isa isa);

extern char *
xtensa_isa_error_msg (xtensa_isa isa);



/* Instruction buffers.  */

typedef uint32 xtensa_insnbuf_word;
typedef xtensa_insnbuf_word *xtensa_insnbuf;


/* Get the size in "insnbuf_words" of the xtensa_insnbuf array.  */

extern int
xtensa_insnbuf_size (xtensa_isa isa); 


/* Allocate an xtensa_insnbuf of the right size.  */

extern xtensa_insnbuf
xtensa_insnbuf_alloc (xtensa_isa isa);


/* Release an xtensa_insnbuf.  */

extern void
xtensa_insnbuf_free (xtensa_isa isa, xtensa_insnbuf buf);


/* Conversion between raw memory (char arrays) and our internal
   instruction representation.  This is complicated by the Xtensa ISA's
   variable instruction lengths.  When converting to chars, the buffer
   must contain a valid instruction so we know how many bytes to copy;
   thus, the "to_chars" function returns the number of bytes copied or
   XTENSA_UNDEFINED on error.  The "from_chars" function first reads the
   minimal number of bytes required to decode the instruction length and
   then proceeds to copy the entire instruction into the buffer; if the
   memory does not contain a valid instruction, it copies the maximum
   number of bytes required for the longest Xtensa instruction.  The
   "num_chars" argument may be used to limit the number of bytes that
   can be read or written.  Otherwise, if "num_chars" is zero, the
   functions may read or write past the end of the code.  */

extern int
xtensa_insnbuf_to_chars (xtensa_isa isa, const xtensa_insnbuf insn,
			 unsigned char *cp, int num_chars);

extern void
xtensa_insnbuf_from_chars (xtensa_isa isa, xtensa_insnbuf insn,
			   const unsigned char *cp, int num_chars);



/* ISA information.  */

/* Initialize the ISA information.  */

extern xtensa_isa
xtensa_isa_init (xtensa_isa_status *errno_p, char **error_msg_p);


/* Deallocate an xtensa_isa structure.  */

extern void
xtensa_isa_free (xtensa_isa isa);


/* Get the maximum instruction size in bytes.  */

extern int
xtensa_isa_maxlength (xtensa_isa isa); 


/* Decode the length in bytes of an instruction in raw memory (not an
   insnbuf).  This function reads only the minimal number of bytes
   required to decode the instruction length.  Returns
   XTENSA_UNDEFINED on error.  */

extern int
xtensa_isa_length_from_chars (xtensa_isa isa, const unsigned char *cp);


/* Get the number of stages in the processor's pipeline.  The pipeline
   stage values returned by other functions in this library will range
   from 0 to N-1, where N is the value returned by this function.
   Note that the stage numbers used here may not correspond to the
   actual processor hardware, e.g., the hardware may have additional
   stages before stage 0.  Returns XTENSA_UNDEFINED on error.  */

extern int
xtensa_isa_num_pipe_stages (xtensa_isa isa); 


/* Get the number of various entities that are defined for this processor.  */

extern int
xtensa_isa_num_formats (xtensa_isa isa);

extern int
xtensa_isa_num_opcodes (xtensa_isa isa);

extern int
xtensa_isa_num_regfiles (xtensa_isa isa);

extern int
xtensa_isa_num_states (xtensa_isa isa);

extern int
xtensa_isa_num_sysregs (xtensa_isa isa);

extern int
xtensa_isa_num_interfaces (xtensa_isa isa);

extern int
xtensa_isa_num_funcUnits (xtensa_isa isa);



/* Instruction formats.  */

/* Get the name of a format.  Returns null on error.  */

extern const char *
xtensa_format_name (xtensa_isa isa, xtensa_format fmt);


/* Given a format name, return the format number.  Returns
   XTENSA_UNDEFINED if the name is not a valid format.  */

extern xtensa_format
xtensa_format_lookup (xtensa_isa isa, const char *fmtname);


/* Decode the instruction format from a binary instruction buffer.
   Returns XTENSA_UNDEFINED if the format is not recognized.  */

extern xtensa_format
xtensa_format_decode (xtensa_isa isa, const xtensa_insnbuf insn);


/* Set the instruction format field(s) in a binary instruction buffer.
   All the other fields are set to zero.  Returns non-zero on error.  */

extern int
xtensa_format_encode (xtensa_isa isa, xtensa_format fmt, xtensa_insnbuf insn);


/* Find the length (in bytes) of an instruction.  Returns
   XTENSA_UNDEFINED on error.  */

extern int
xtensa_format_length (xtensa_isa isa, xtensa_format fmt);


/* Get the number of slots in an instruction.  Returns XTENSA_UNDEFINED
   on error.  */

extern int
xtensa_format_num_slots (xtensa_isa isa, xtensa_format fmt);


/* Get the opcode for a no-op in a particular slot.
   Returns XTENSA_UNDEFINED on error.  */

extern xtensa_opcode
xtensa_format_slot_nop_opcode (xtensa_isa isa, xtensa_format fmt, int slot);


/* Get the bits for a specified slot out of an insnbuf for the
   instruction as a whole and put them into an insnbuf for that one
   slot, and do the opposite to set a slot.  Return non-zero on error.  */

extern int
xtensa_format_get_slot (xtensa_isa isa, xtensa_format fmt, int slot,
			const xtensa_insnbuf insn, xtensa_insnbuf slotbuf);

extern int
xtensa_format_set_slot (xtensa_isa isa, xtensa_format fmt, int slot,
			xtensa_insnbuf insn, const xtensa_insnbuf slotbuf);



/* Opcode information.  */

/* Translate a mnemonic name to an opcode.  Returns XTENSA_UNDEFINED if
   the name is not a valid opcode mnemonic.  */

extern xtensa_opcode
xtensa_opcode_lookup (xtensa_isa isa, const char *opname);


/* Decode the opcode for one instruction slot from a binary instruction
   buffer.  Returns the opcode or XTENSA_UNDEFINED if the opcode is
   illegal.  */

extern xtensa_opcode
xtensa_opcode_decode (xtensa_isa isa, xtensa_format fmt, int slot,
		      const xtensa_insnbuf slotbuf);


/* Set the opcode field(s) for an instruction slot.  All other fields
   in the slot are set to zero.  Returns non-zero if the opcode cannot
   be encoded.  */

extern int
xtensa_opcode_encode (xtensa_isa isa, xtensa_format fmt, int slot,
		      xtensa_insnbuf slotbuf, xtensa_opcode opc);


/* Get the mnemonic name for an opcode.  Returns null on error.  */

extern const char *
xtensa_opcode_name (xtensa_isa isa, xtensa_opcode opc);


/* Check various properties of opcodes.  These functions return 0 if
   the condition is false, 1 if the condition is true, and
   XTENSA_UNDEFINED on error.  The instructions are classified as
   follows:

   branch: conditional branch; may fall through to next instruction (B*)
   jump: unconditional branch (J, JX, RET*, RF*)
   loop: zero-overhead loop (LOOP*)
   call: unconditional call; control returns to next instruction (CALL*)

   For the opcodes that affect control flow in some way, the branch
   target may be specified by an immediate operand or it may be an
   address stored in a register.  You can distinguish these by
   checking if the instruction has a PC-relative immediate
   operand.  */

extern int
xtensa_opcode_is_branch (xtensa_isa isa, xtensa_opcode opc);

extern int
xtensa_opcode_is_jump (xtensa_isa isa, xtensa_opcode opc);

extern int
xtensa_opcode_is_loop (xtensa_isa isa, xtensa_opcode opc);

extern int
xtensa_opcode_is_call (xtensa_isa isa, xtensa_opcode opc);


/* Find the number of ordinary operands, state operands, and interface
   operands for an instruction.  These return XTENSA_UNDEFINED on
   error.  */

extern int
xtensa_opcode_num_operands (xtensa_isa isa, xtensa_opcode opc);

extern int
xtensa_opcode_num_stateOperands (xtensa_isa isa, xtensa_opcode opc);

extern int
xtensa_opcode_num_interfaceOperands (xtensa_isa isa, xtensa_opcode opc);


/* Get functional unit usage requirements for an opcode.  Each "use"
   is identified by a <functional unit, pipeline stage> pair.  The
   "num_funcUnit_uses" function returns the number of these "uses" or
   XTENSA_UNDEFINED on error.  The "funcUnit_use" function returns
   a pointer to a "use" pair or null on error.  */

typedef struct xtensa_funcUnit_use_struct
{
  xtensa_funcUnit unit;
  int stage;
} xtensa_funcUnit_use;

extern int
xtensa_opcode_num_funcUnit_uses (xtensa_isa isa, xtensa_opcode opc);

extern xtensa_funcUnit_use *
xtensa_opcode_funcUnit_use (xtensa_isa isa, xtensa_opcode opc, int u);



/* Operand information.  */

/* Get the name of an operand.  Returns null on error.  */

extern const char *
xtensa_operand_name (xtensa_isa isa, xtensa_opcode opc, int opnd);


/* Some operands are "invisible", i.e., not explicitly specified in
   assembly language.  When assembling an instruction, you need not set
   the values of invisible operands, since they are either hardwired or
   derived from other field values.  The values of invisible operands
   can be examined in the same way as other operands, but remember that
   an invisible operand may get its value from another visible one, so
   the entire instruction must be available before examining the
   invisible operand values.  This function returns 1 if an operand is
   visible, 0 if it is invisible, or XTENSA_UNDEFINED on error.  Note
   that whether an operand is visible is orthogonal to whether it is
   "implicit", i.e., whether it is encoded in a field in the
   instruction.  */

extern int
xtensa_operand_is_visible (xtensa_isa isa, xtensa_opcode opc, int opnd);


/* Check if an operand is an input ('i'), output ('o'), or inout ('m')
   operand.  Note: The output operand of a conditional assignment
   (e.g., movnez) appears here as an inout ('m') even if it is declared
   in the TIE code as an output ('o'); this allows the compiler to
   properly handle register allocation for conditional assignments.
   Returns 0 on error.  */

extern char
xtensa_operand_inout (xtensa_isa isa, xtensa_opcode opc, int opnd);


/* Get and set the raw (encoded) value of the field for the specified
   operand.  The "set" function does not check if the value fits in the
   field; that is done by the "encode" function below.  Both of these
   functions return non-zero on error, e.g., if the field is not defined
   for the specified slot.  */

extern int
xtensa_operand_get_field (xtensa_isa isa, xtensa_opcode opc, int opnd,
			  xtensa_format fmt, int slot,
			  const xtensa_insnbuf slotbuf, uint32 *valp);

extern int 
xtensa_operand_set_field (xtensa_isa isa, xtensa_opcode opc, int opnd,
			  xtensa_format fmt, int slot,
			  xtensa_insnbuf slotbuf, uint32 val);


/* Encode and decode operands.  The raw bits in the operand field may
   be encoded in a variety of different ways.  These functions hide
   the details of that encoding.  The result values are returned through
   the argument pointer.  The return value is non-zero on error.  */

extern int
xtensa_operand_encode (xtensa_isa isa, xtensa_opcode opc, int opnd,
		       uint32 *valp);

extern int
xtensa_operand_decode (xtensa_isa isa, xtensa_opcode opc, int opnd,
		       uint32 *valp);


/* An operand may be either a register operand or an immediate of some
   sort (e.g., PC-relative or not).  The "is_register" function returns
   0 if the operand is an immediate, 1 if it is a register, and
   XTENSA_UNDEFINED on error.  The "regfile" function returns the
   regfile for a register operand, or XTENSA_UNDEFINED on error.  */

extern int
xtensa_operand_is_register (xtensa_isa isa, xtensa_opcode opc, int opnd);

extern xtensa_regfile
xtensa_operand_regfile (xtensa_isa isa, xtensa_opcode opc, int opnd);


/* Register operands may span multiple consecutive registers, e.g., a
   64-bit data type may occupy two 32-bit registers.  Only the first
   register is encoded in the operand field.  This function specifies
   the number of consecutive registers occupied by this operand.  For
   non-register operands, the return value is undefined.  Returns
   XTENSA_UNDEFINED on error.  */

extern int
xtensa_operand_num_regs (xtensa_isa isa, xtensa_opcode opc, int opnd);
				 

/* Some register operands do not completely identify the register being
   accessed.  For example, the operand value may be added to an internal
   state value.  By definition, this implies that the corresponding
   regfile is not allocatable.  Unknown registers should generally be
   treated with worst-case assumptions.  The function returns 0 if the
   register value is unknown, 1 if known, and XTENSA_UNDEFINED on
   error.  */

extern int
xtensa_operand_is_known_reg (xtensa_isa isa, xtensa_opcode opc, int opnd);


/* Check if an immediate operand is PC-relative.  Returns 0 for register
   operands and non-PC-relative immediates, 1 for PC-relative
   immediates, and XTENSA_UNDEFINED on error.  */
 
extern int
xtensa_operand_is_PCrelative (xtensa_isa isa, xtensa_opcode opc, int opnd);


/* For PC-relative offset operands, the interpretation of the offset may
   vary between opcodes, e.g., is it relative to the current PC or that
   of the next instruction?  The following functions are defined to
   perform PC-relative relocations and to undo them (as in the
   disassembler).  The "do_reloc" function takes the desired address
   value and the PC of the current instruction and sets the value to the
   corresponding PC-relative offset (which can then be encoded and
   stored into the operand field).  The "undo_reloc" function takes the
   unencoded offset value and the current PC and sets the value to the
   appropriate address.  The return values are non-zero on error.  Note
   that these functions do not replace the encode/decode functions; the
   operands must be encoded/decoded separately and the encode functions
   are responsible for detecting invalid operand values.  */

extern int
xtensa_operand_do_reloc (xtensa_isa isa, xtensa_opcode opc, int opnd,
			 uint32 *valp, uint32 pc);

extern int
xtensa_operand_undo_reloc (xtensa_isa isa, xtensa_opcode opc, int opnd,
			   uint32 *valp, uint32 pc);



/* State Operands.  */

/* Get the state accessed by a state operand.  Returns XTENSA_UNDEFINED
   on error.  */

extern xtensa_state
xtensa_stateOperand_state (xtensa_isa isa, xtensa_opcode opc, int stOp);


/* Check if a state operand is an input ('i'), output ('o'), or inout
   ('m') operand.  Returns 0 on error.  */

extern char
xtensa_stateOperand_inout (xtensa_isa isa, xtensa_opcode opc, int stOp);



/* Interface Operands.  */

/* Get the external interface accessed by an interface operand.
   Returns XTENSA_UNDEFINED on error.  */

extern xtensa_interface
xtensa_interfaceOperand_interface (xtensa_isa isa, xtensa_opcode opc,
				   int ifOp);



/* Register Files.  */

/* Regfiles include both "real" regfiles and "views", where a view
   allows a group of adjacent registers in a real "parent" regfile to be
   viewed as a single register.  A regfile view has all the same
   properties as its parent except for its (long) name, bit width, number
   of entries, and default ctype.  You can use the parent function to
   distinguish these two classes.  */

/* Look up a regfile by either its name or its abbreviated "short name".
   Returns XTENSA_UNDEFINED on error.  The "lookup_shortname" function
   ignores "view" regfiles since they always have the same shortname as
   their parents.  */

extern xtensa_regfile
xtensa_regfile_lookup (xtensa_isa isa, const char *name);

extern xtensa_regfile
xtensa_regfile_lookup_shortname (xtensa_isa isa, const char *shortname);


/* Get the name or abbreviated "short name" of a regfile.
   Returns null on error.  */

extern const char *
xtensa_regfile_name (xtensa_isa isa, xtensa_regfile rf);

extern const char *
xtensa_regfile_shortname (xtensa_isa isa, xtensa_regfile rf);


/* Get the parent regfile of a "view" regfile.  If the regfile is not a
   view, the result is the same as the input parameter.  Returns
   XTENSA_UNDEFINED on error.  */

extern xtensa_regfile
xtensa_regfile_view_parent (xtensa_isa isa, xtensa_regfile rf);


/* Get the bit width of a regfile or regfile view.
   Returns XTENSA_UNDEFINED on error.  */

extern int
xtensa_regfile_num_bits (xtensa_isa isa, xtensa_regfile rf);


/* Get the number of regfile entries.  Returns XTENSA_UNDEFINED on
   error.  */

extern int
xtensa_regfile_num_entries (xtensa_isa isa, xtensa_regfile rf);



/* Processor States.  */

/* Look up a state by name.  Returns XTENSA_UNDEFINED on error.  */

extern xtensa_state
xtensa_state_lookup (xtensa_isa isa, const char *name);


/* Get the name for a processor state.  Returns null on error.  */

extern const char *
xtensa_state_name (xtensa_isa isa, xtensa_state st);


/* Get the bit width for a processor state.
   Returns XTENSA_UNDEFINED on error.  */

extern int
xtensa_state_num_bits (xtensa_isa isa, xtensa_state st);


/* Check if a state is exported from the processor core.  Returns 0 if
   the condition is false, 1 if the condition is true, and
   XTENSA_UNDEFINED on error.  */

extern int
xtensa_state_is_exported (xtensa_isa isa, xtensa_state st);


/* Check for a "shared_or" state.  Returns 0 if the condition is false,
   1 if the condition is true, and XTENSA_UNDEFINED on error.  */

extern int
xtensa_state_is_shared_or (xtensa_isa isa, xtensa_state st);



/* Sysregs ("special registers" and "user registers").  */

/* Look up a register by its number and whether it is a "user register"
   or a "special register".  Returns XTENSA_UNDEFINED if the sysreg does
   not exist.  */

extern xtensa_sysreg
xtensa_sysreg_lookup (xtensa_isa isa, int num, int is_user);


/* Check if there exists a sysreg with a given name.
   If not, this function returns XTENSA_UNDEFINED.  */

extern xtensa_sysreg
xtensa_sysreg_lookup_name (xtensa_isa isa, const char *name);


/* Get the name of a sysreg.  Returns null on error.  */

extern const char *
xtensa_sysreg_name (xtensa_isa isa, xtensa_sysreg sysreg);


/* Get the register number.  Returns XTENSA_UNDEFINED on error.  */

extern int
xtensa_sysreg_number (xtensa_isa isa, xtensa_sysreg sysreg);


/* Check if a sysreg is a "special register" or a "user register".
   Returns 0 for special registers, 1 for user registers and
   XTENSA_UNDEFINED on error.  */

extern int
xtensa_sysreg_is_user (xtensa_isa isa, xtensa_sysreg sysreg);



/* Interfaces.  */

/* Find an interface by name.  The return value is XTENSA_UNDEFINED if
   the specified interface is not found.  */

extern xtensa_interface
xtensa_interface_lookup (xtensa_isa isa, const char *ifname);


/* Get the name of an interface.  Returns null on error.  */

extern const char *
xtensa_interface_name (xtensa_isa isa, xtensa_interface intf);


/* Get the bit width for an interface.
   Returns XTENSA_UNDEFINED on error.  */

extern int
xtensa_interface_num_bits (xtensa_isa isa, xtensa_interface intf);


/* Check if an interface is an input ('i') or output ('o') with respect
   to the Xtensa processor core.  Returns 0 on error.  */

extern char
xtensa_interface_inout (xtensa_isa isa, xtensa_interface intf);


/* Check if accessing an interface has potential side effects.
   Currently "data" interfaces have side effects and "control"
   interfaces do not.  Returns 1 if there are side effects, 0 if not,
   and XTENSA_UNDEFINED on error.  */

extern int
xtensa_interface_has_side_effect (xtensa_isa isa, xtensa_interface intf);


/* Some interfaces may be related such that accessing one interface
   has side effects on a set of related interfaces.  The interfaces
   are partitioned into equivalence classes of related interfaces, and
   each class is assigned a unique identifier number.  This function
   returns the class identifier for an interface, or XTENSA_UNDEFINED
   on error.  These identifiers can be compared to determine if two
   interfaces are related; the specific values of the identifiers have
   no particular meaning otherwise.  */

extern int
xtensa_interface_class_id (xtensa_isa isa, xtensa_interface intf);



/* Functional Units.  */

/* Find a functional unit by name.  The return value is XTENSA_UNDEFINED if
   the specified unit is not found.  */

extern xtensa_funcUnit
xtensa_funcUnit_lookup (xtensa_isa isa, const char *fname);


/* Get the name of a functional unit.  Returns null on error.  */

extern const char *
xtensa_funcUnit_name (xtensa_isa isa, xtensa_funcUnit fun);


/* Functional units may be replicated.  See how many instances of a
   particular function unit exist.  Returns XTENSA_UNDEFINED on error.  */

extern int
xtensa_funcUnit_num_copies (xtensa_isa isa, xtensa_funcUnit fun);


#ifdef __cplusplus
}
#endif
#endif /* XTENSA_LIBISA_H */
