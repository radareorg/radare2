/* Configurable Xtensa ISA support.
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
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../include/disas-asm.h"
#include "../../include/sysdep.h"
//#include "bfd.h"
//#include "libbfd.h"
#include "../../include/xtensa-isa.h"
#include "../../include/xtensa-isa-internal.h"
#include "r_types.h"
#include "r_util.h"
extern int filename_cmp (const char *s1, const char *s2);
xtensa_isa_status xtisa_errno;
char xtisa_error_msg[1024];


xtensa_isa_status
xtensa_isa_errno (xtensa_isa isa __attribute__ ((unused)))
{
  return xtisa_errno;
}


char *
xtensa_isa_error_msg (xtensa_isa isa __attribute__ ((unused)))
{
  return xtisa_error_msg;
}


#define CHECK_ALLOC(MEM,ERRVAL) \
  do { \
    if ((MEM) == 0) \
      { \
	xtisa_errno = xtensa_isa_out_of_memory; \
	strcpy (xtisa_error_msg, "out of memory"); \
	return (ERRVAL); \
      } \
  } while (0)

#define CHECK_ALLOC_FOR_INIT(MEM,ERRVAL,ERRNO_P,ERROR_MSG_P) \
  do { \
    if ((MEM) == 0) \
      { \
	xtisa_errno = xtensa_isa_out_of_memory; \
	strcpy (xtisa_error_msg, "out of memory"); \
	if (ERRNO_P) *(ERRNO_P) = xtisa_errno; \
	if (ERROR_MSG_P) *(ERROR_MSG_P) = xtisa_error_msg; \
	return (ERRVAL); \
      } \
  } while (0)



/* Instruction buffers.  */

int
xtensa_insnbuf_size (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->insnbuf_size;
}


xtensa_insnbuf
xtensa_insnbuf_alloc (xtensa_isa isa)
{
  xtensa_insnbuf result = (xtensa_insnbuf)
    malloc (xtensa_insnbuf_size (isa) * sizeof (xtensa_insnbuf_word));
  CHECK_ALLOC (result, 0);
  return result;
}


void
xtensa_insnbuf_free (xtensa_isa isa __attribute__ ((unused)),
		     xtensa_insnbuf buf)
{
  free (buf);
}


/* Given <byte_index>, the index of a byte in a xtensa_insnbuf, our
   internal representation of a xtensa instruction word, return the index of
   its word and the bit index of its low order byte in the xtensa_insnbuf.  */

static inline int
byte_to_word_index (int byte_index)
{
  return byte_index / sizeof (xtensa_insnbuf_word);
}


static inline int
byte_to_bit_index (int byte_index)
{
  return (byte_index & 0x3) * 8;
}


/* Copy an instruction in the 32-bit words pointed at by "insn" to
   characters pointed at by "cp".  This is more complicated than you
   might think because we want 16-bit instructions in bytes 2 & 3 for
   big-endian configurations.  This function allows us to specify
   which byte in "insn" to start with and which way to increment,
   allowing trivial implementation for both big- and little-endian
   configurations....and it seems to make pretty good code for
   both.  */

int
xtensa_insnbuf_to_chars (xtensa_isa isa,
			 const xtensa_insnbuf insn,
			 unsigned char *cp,
			 int num_chars)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int insn_size = xtensa_isa_maxlength (isa);
  int fence_post, start, increment, i, byte_count;
  xtensa_format fmt;

  if (num_chars == 0) {
	  num_chars = insn_size;
  }

  if (intisa->is_big_endian)
    {
      start = insn_size - 1;
      increment = -1;
    }
  else
    {
      start = 0;
      increment = 1;
    }

  /* Find the instruction format.  Do nothing if the buffer does not contain
     a valid instruction since we need to know how many bytes to copy.  */
  fmt = xtensa_format_decode (isa, insn);
  if (fmt == XTENSA_UNDEFINED) {
	  return XTENSA_UNDEFINED;
  }

  byte_count = xtensa_format_length (isa, fmt);
  if (byte_count == XTENSA_UNDEFINED) {
	  return XTENSA_UNDEFINED;
  }

  if (byte_count > num_chars)
    {
      xtisa_errno = xtensa_isa_buffer_overflow;
      strcpy (xtisa_error_msg, "output buffer too small for instruction");
      return XTENSA_UNDEFINED;
    }

  fence_post = start + (byte_count * increment);

  for (i = start; i != fence_post; i += increment, ++cp)
    {
      int word_inx = byte_to_word_index (i);
      int bit_inx = byte_to_bit_index (i);

      *cp = (insn[word_inx] >> bit_inx) & 0xff;
    }

  return byte_count;
}


/* Inward conversion from byte stream to xtensa_insnbuf.  See
   xtensa_insnbuf_to_chars for a discussion of why this is complicated
   by endianness.  */

void
xtensa_insnbuf_from_chars (xtensa_isa isa,
			   xtensa_insnbuf insn,
			   const unsigned char *cp,
			   int num_chars)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int max_size, insn_size, fence_post, start, increment, i;

  max_size = xtensa_isa_maxlength (isa);

  /* Decode the instruction length so we know how many bytes to read.  */
  insn_size = (intisa->length_decode_fn) (cp);
  if (insn_size == XTENSA_UNDEFINED)
    {
      /* This should never happen when the byte stream contains a
	 valid instruction.  Just read the maximum number of bytes....  */
      insn_size = max_size;
    }

    if (num_chars == 0 || num_chars > insn_size) {
	    num_chars = insn_size;
    }

    if (intisa->is_big_endian) {
	    start = max_size - 1;
	    increment = -1;
    }
  else
    {
      start = 0;
      increment = 1;
    }

  fence_post = start + (num_chars * increment);
  memset (insn, 0, xtensa_insnbuf_size (isa) * sizeof (xtensa_insnbuf_word));

  for (i = start; i != fence_post; i += increment, ++cp)
    {
      int word_inx = byte_to_word_index (i);
      int bit_inx = byte_to_bit_index (i);

      insn[word_inx] |= (*cp & 0xff) << bit_inx;
    }
}



/* ISA information.  */

extern xtensa_isa_internal xtensa_modules;

xtensa_isa
xtensa_isa_init (xtensa_isa_status *errno_p, char **error_msg_p)
{
  xtensa_isa_internal *isa = &xtensa_modules;
  int n, is_user;

  /* Set up the opcode name lookup table.  */
  isa->opname_lookup_table =
    bfd_malloc (isa->num_opcodes * sizeof (xtensa_lookup_entry));
  CHECK_ALLOC_FOR_INIT (isa->opname_lookup_table, NULL, errno_p, error_msg_p);
  for (n = 0; n < isa->num_opcodes; n++)
    {
      isa->opname_lookup_table[n].key = isa->opcodes[n].name;
      isa->opname_lookup_table[n].u.opcode = n;
    }
  qsort (isa->opname_lookup_table, isa->num_opcodes,
	 sizeof (xtensa_lookup_entry), xtensa_isa_name_compare);

  /* Set up the state name lookup table.  */
  isa->state_lookup_table =
    bfd_malloc (isa->num_states * sizeof (xtensa_lookup_entry));
  CHECK_ALLOC_FOR_INIT (isa->state_lookup_table, NULL, errno_p, error_msg_p);
  for (n = 0; n < isa->num_states; n++)
    {
      isa->state_lookup_table[n].key = isa->states[n].name;
      isa->state_lookup_table[n].u.state = n;
    }
  qsort (isa->state_lookup_table, isa->num_states,
	 sizeof (xtensa_lookup_entry), xtensa_isa_name_compare);

  /* Set up the sysreg name lookup table.  */
  isa->sysreg_lookup_table =
    bfd_malloc (isa->num_sysregs * sizeof (xtensa_lookup_entry));
  CHECK_ALLOC_FOR_INIT (isa->sysreg_lookup_table, NULL, errno_p, error_msg_p);
  for (n = 0; n < isa->num_sysregs; n++)
    {
      isa->sysreg_lookup_table[n].key = isa->sysregs[n].name;
      isa->sysreg_lookup_table[n].u.sysreg = n;
    }
  qsort (isa->sysreg_lookup_table, isa->num_sysregs,
	 sizeof (xtensa_lookup_entry), xtensa_isa_name_compare);

  /* Set up the user & system sysreg number tables.  */
  for (is_user = 0; is_user < 2; is_user++)
    {
      isa->sysreg_table[is_user] =
	bfd_malloc ((isa->max_sysreg_num[is_user] + 1)
		    * sizeof (xtensa_sysreg));
      CHECK_ALLOC_FOR_INIT (isa->sysreg_table[is_user], NULL,
			    errno_p, error_msg_p);

      for (n = 0; n <= isa->max_sysreg_num[is_user]; n++) {
	      isa->sysreg_table[is_user][n] = XTENSA_UNDEFINED;
      }
    }
  for (n = 0; n < isa->num_sysregs; n++)
    {
      xtensa_sysreg_internal *sreg = &isa->sysregs[n];
      is_user = sreg->is_user;

      isa->sysreg_table[is_user][sreg->number] = n;
    }

  /* Set up the interface lookup table.  */
  isa->interface_lookup_table =
    calloc (isa->num_interfaces, sizeof (xtensa_lookup_entry));
  CHECK_ALLOC_FOR_INIT (isa->interface_lookup_table, NULL, errno_p,
			error_msg_p);
  for (n = 0; n < isa->num_interfaces; n++)
    {
      isa->interface_lookup_table[n].key = isa->interfaces[n].name;
      isa->interface_lookup_table[n].u.intf = n;
    }
  qsort (isa->interface_lookup_table, isa->num_interfaces,
	 sizeof (xtensa_lookup_entry), xtensa_isa_name_compare);

  /* Set up the funcUnit lookup table.  */
  isa->funcUnit_lookup_table =
    bfd_malloc (isa->num_funcUnits * sizeof (xtensa_lookup_entry));
  CHECK_ALLOC_FOR_INIT (isa->funcUnit_lookup_table, NULL, errno_p,
			error_msg_p);
  for (n = 0; n < isa->num_funcUnits; n++)
    {
      isa->funcUnit_lookup_table[n].key = isa->funcUnits[n].name;
      isa->funcUnit_lookup_table[n].u.fun = n;
    }
  qsort (isa->funcUnit_lookup_table, isa->num_funcUnits,
	 sizeof (xtensa_lookup_entry), xtensa_isa_name_compare);

  isa->insnbuf_size = ((isa->insn_size + sizeof (xtensa_insnbuf_word) - 1) /
		       sizeof (xtensa_insnbuf_word));

  return (xtensa_isa) isa;
}


void
xtensa_isa_free (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int n;

  /* With this version of the code, the xtensa_isa structure is not
     dynamically allocated, so this function is not essential.  Free
     the memory allocated by xtensa_isa_init and restore the xtensa_isa
     structure to its initial state.  */

  if (intisa->opname_lookup_table)
    {
      free (intisa->opname_lookup_table);
      intisa->opname_lookup_table = 0;
    }

  if (intisa->state_lookup_table)
    {
      free (intisa->state_lookup_table);
      intisa->state_lookup_table = 0;
    }

  if (intisa->sysreg_lookup_table)
    {
      free (intisa->sysreg_lookup_table);
      intisa->sysreg_lookup_table = 0;
    }
  for (n = 0; n < 2; n++)
    {
      if (intisa->sysreg_table[n])
	{
	  free (intisa->sysreg_table[n]);
	  intisa->sysreg_table[n] = 0;
	}
    }

  if (intisa->interface_lookup_table)
    {
      free (intisa->interface_lookup_table);
      intisa->interface_lookup_table = 0;
    }

  if (intisa->funcUnit_lookup_table)
    {
      free (intisa->funcUnit_lookup_table);
      intisa->funcUnit_lookup_table = 0;
    }
}


int
xtensa_isa_name_compare (const void *v1, const void *v2)
{
  xtensa_lookup_entry *e1 = (xtensa_lookup_entry *) v1;
  xtensa_lookup_entry *e2 = (xtensa_lookup_entry *) v2;

  return r_str_casecmp (e1->key, e2->key);
}


int
xtensa_isa_maxlength (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->insn_size;
}


int
xtensa_isa_length_from_chars (xtensa_isa isa, const unsigned char *cp)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return (intisa->length_decode_fn) (cp);
}


int
xtensa_isa_num_pipe_stages (xtensa_isa isa)
{
  xtensa_opcode opcode;
  xtensa_funcUnit_use *use;
  int num_opcodes, num_uses;
  int i, stage;
  static int max_stage = XTENSA_UNDEFINED;

  /* Only compute the value once.  */
  if (max_stage != XTENSA_UNDEFINED) {
	  return max_stage + 1;
  }

  num_opcodes = xtensa_isa_num_opcodes (isa);
  for (opcode = 0; opcode < num_opcodes; opcode++)
    {
      num_uses = xtensa_opcode_num_funcUnit_uses (isa, opcode);
      for (i = 0; i < num_uses; i++)
	{
	  use = xtensa_opcode_funcUnit_use (isa, opcode, i);
	  stage = use->stage;
	  if (stage > max_stage) {
		  max_stage = stage;
	  }
	}
    }

  return max_stage + 1;
}


int
xtensa_isa_num_formats (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->num_formats;
}


int
xtensa_isa_num_opcodes (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->num_opcodes;
}


int
xtensa_isa_num_regfiles (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->num_regfiles;
}


int
xtensa_isa_num_states (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->num_states;
}


int
xtensa_isa_num_sysregs (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->num_sysregs;
}


int
xtensa_isa_num_interfaces (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->num_interfaces;
}


int
xtensa_isa_num_funcUnits (xtensa_isa isa)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  return intisa->num_funcUnits;
}



/* Instruction formats.  */


#define CHECK_FORMAT(INTISA,FMT,ERRVAL) \
  do { \
    if ((FMT) < 0 || (FMT) >= (INTISA)->num_formats) \
      { \
	xtisa_errno = xtensa_isa_bad_format; \
	strcpy (xtisa_error_msg, "invalid format specifier"); \
	return (ERRVAL); \
      } \
  } while (0)


#define CHECK_SLOT(INTISA,FMT,SLOT,ERRVAL) \
  do { \
    if ((SLOT) < 0 || (SLOT) >= (INTISA)->formats[FMT].num_slots) \
      { \
	xtisa_errno = xtensa_isa_bad_slot; \
	strcpy (xtisa_error_msg, "invalid slot specifier"); \
	return (ERRVAL); \
      } \
  } while (0)


const char *
xtensa_format_name (xtensa_isa isa, xtensa_format fmt)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_FORMAT (intisa, fmt, NULL);
  return intisa->formats[fmt].name;
}


xtensa_format
xtensa_format_lookup (xtensa_isa isa, const char *fmtname)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int fmt;

  if (!fmtname || !*fmtname)
    {
      xtisa_errno = xtensa_isa_bad_format;
      strcpy (xtisa_error_msg, "invalid format name");
      return XTENSA_UNDEFINED;
    }

  for (fmt = 0; fmt < intisa->num_formats; fmt++)
    {
	  if (r_str_casecmp (fmtname, intisa->formats[fmt].name) == 0) {
		  return fmt;
	  }
    }

  xtisa_errno = xtensa_isa_bad_format;
  sprintf (xtisa_error_msg, "format \"%s\" not recognized", fmtname);
  return XTENSA_UNDEFINED;
}


xtensa_format
xtensa_format_decode (xtensa_isa isa, const xtensa_insnbuf insn)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_format fmt;

  fmt = (intisa->format_decode_fn) (insn);
  if (fmt != XTENSA_UNDEFINED) {
	  return fmt;
  }

  xtisa_errno = xtensa_isa_bad_format;
  strcpy (xtisa_error_msg, "cannot decode instruction format");
  return XTENSA_UNDEFINED;
}


int
xtensa_format_encode (xtensa_isa isa, xtensa_format fmt, xtensa_insnbuf insn)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_FORMAT (intisa, fmt, -1);
  (*intisa->formats[fmt].encode_fn) (insn);
  return 0;
}


int
xtensa_format_length (xtensa_isa isa, xtensa_format fmt)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_FORMAT (intisa, fmt, XTENSA_UNDEFINED);
  return intisa->formats[fmt].length;
}


int
xtensa_format_num_slots (xtensa_isa isa, xtensa_format fmt)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_FORMAT (intisa, fmt, XTENSA_UNDEFINED);
  return intisa->formats[fmt].num_slots;
}


xtensa_opcode
xtensa_format_slot_nop_opcode (xtensa_isa isa, xtensa_format fmt, int slot)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int slot_id;

  CHECK_FORMAT (intisa, fmt, XTENSA_UNDEFINED);
  CHECK_SLOT (intisa, fmt, slot, XTENSA_UNDEFINED);

  slot_id = intisa->formats[fmt].slot_id[slot];
  return xtensa_opcode_lookup (isa, intisa->slots[slot_id].nop_name);
}


int
xtensa_format_get_slot (xtensa_isa isa, xtensa_format fmt, int slot,
			const xtensa_insnbuf insn, xtensa_insnbuf slotbuf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int slot_id;

  CHECK_FORMAT (intisa, fmt, -1);
  CHECK_SLOT (intisa, fmt, slot, -1);

  slot_id = intisa->formats[fmt].slot_id[slot];
  (*intisa->slots[slot_id].get_fn) (insn, slotbuf);
  return 0;
}


int
xtensa_format_set_slot (xtensa_isa isa, xtensa_format fmt, int slot,
			xtensa_insnbuf insn, const xtensa_insnbuf slotbuf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int slot_id;

  CHECK_FORMAT (intisa, fmt, -1);
  CHECK_SLOT (intisa, fmt, slot, -1);

  slot_id = intisa->formats[fmt].slot_id[slot];
  (*intisa->slots[slot_id].set_fn) (insn, slotbuf);
  return 0;
}



/* Opcode information.  */


#define CHECK_OPCODE(INTISA,OPC,ERRVAL) \
  do { \
    if ((OPC) < 0 || (OPC) >= (INTISA)->num_opcodes) \
      { \
	xtisa_errno = xtensa_isa_bad_opcode; \
	strcpy (xtisa_error_msg, "invalid opcode specifier"); \
	return (ERRVAL); \
      } \
  } while (0)


xtensa_opcode
xtensa_opcode_lookup (xtensa_isa isa, const char *opname)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_lookup_entry entry, *result = 0;

  if (!opname || !*opname)
    {
      xtisa_errno = xtensa_isa_bad_opcode;
      strcpy (xtisa_error_msg, "invalid opcode name");
      return XTENSA_UNDEFINED;
    }

  if (intisa->num_opcodes != 0)
    {
      entry.key = opname;
      result = bsearch (&entry, intisa->opname_lookup_table,
			intisa->num_opcodes, sizeof (xtensa_lookup_entry),
			xtensa_isa_name_compare);
    }

  if (!result)
    {
      xtisa_errno = xtensa_isa_bad_opcode;
      sprintf (xtisa_error_msg, "opcode \"%s\" not recognized", opname);
      return XTENSA_UNDEFINED;
    }

  return result->u.opcode;
}


xtensa_opcode
xtensa_opcode_decode (xtensa_isa isa, xtensa_format fmt, int slot,
		      const xtensa_insnbuf slotbuf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int slot_id;
  xtensa_opcode opc;

  CHECK_FORMAT (intisa, fmt, XTENSA_UNDEFINED);
  CHECK_SLOT (intisa, fmt, slot, XTENSA_UNDEFINED);

  slot_id = intisa->formats[fmt].slot_id[slot];

  opc = (intisa->slots[slot_id].opcode_decode_fn) (slotbuf);
  if (opc != XTENSA_UNDEFINED) {
	  return opc;
  }

  xtisa_errno = xtensa_isa_bad_opcode;
  strcpy (xtisa_error_msg, "cannot decode opcode");
  return XTENSA_UNDEFINED;
}


int
xtensa_opcode_encode (xtensa_isa isa, xtensa_format fmt, int slot,
		      xtensa_insnbuf slotbuf, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int slot_id;
  xtensa_opcode_encode_fn encode_fn;

  CHECK_FORMAT (intisa, fmt, -1);
  CHECK_SLOT (intisa, fmt, slot, -1);
  CHECK_OPCODE (intisa, opc, -1);

  slot_id = intisa->formats[fmt].slot_id[slot];
  encode_fn = intisa->opcodes[opc].encode_fns[slot_id];
  if (!encode_fn)
    {
      xtisa_errno = xtensa_isa_wrong_slot;
      sprintf (xtisa_error_msg,
	       "opcode \"%s\" is not allowed in slot %d of format \"%s\"",
	       intisa->opcodes[opc].name, slot, intisa->formats[fmt].name);
      return -1;
    }
  (*encode_fn) (slotbuf);
  return 0;
}


const char *
xtensa_opcode_name (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_OPCODE (intisa, opc, NULL);
  return intisa->opcodes[opc].name;
}


int
xtensa_opcode_is_branch (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  if ((intisa->opcodes[opc].flags & XTENSA_OPCODE_IS_BRANCH) != 0) {
	  return 1;
  }
  return 0;
}


int
xtensa_opcode_is_jump (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  if ((intisa->opcodes[opc].flags & XTENSA_OPCODE_IS_JUMP) != 0) {
	  return 1;
  }
  return 0;
}


int
xtensa_opcode_is_loop (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  if ((intisa->opcodes[opc].flags & XTENSA_OPCODE_IS_LOOP) != 0) {
	  return 1;
  }
  return 0;
}


int
xtensa_opcode_is_call (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  if ((intisa->opcodes[opc].flags & XTENSA_OPCODE_IS_CALL) != 0) {
	  return 1;
  }
  return 0;
}


int
xtensa_opcode_num_operands (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int iclass_id;

  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  iclass_id = intisa->opcodes[opc].iclass_id;
  return intisa->iclasses[iclass_id].num_operands;
}


int
xtensa_opcode_num_stateOperands (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int iclass_id;

  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  iclass_id = intisa->opcodes[opc].iclass_id;
  return intisa->iclasses[iclass_id].num_stateOperands;
}


int
xtensa_opcode_num_interfaceOperands (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int iclass_id;

  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  iclass_id = intisa->opcodes[opc].iclass_id;
  return intisa->iclasses[iclass_id].num_interfaceOperands;
}


int
xtensa_opcode_num_funcUnit_uses (xtensa_isa isa, xtensa_opcode opc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  return intisa->opcodes[opc].num_funcUnit_uses;
}


xtensa_funcUnit_use *
xtensa_opcode_funcUnit_use (xtensa_isa isa, xtensa_opcode opc, int u)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_OPCODE (intisa, opc, NULL);
  if (u < 0 || u >= intisa->opcodes[opc].num_funcUnit_uses)
    {
      xtisa_errno = xtensa_isa_bad_funcUnit;
      sprintf (xtisa_error_msg, "invalid functional unit use number (%d); "
	       "opcode \"%s\" has %d", u, intisa->opcodes[opc].name,
	       intisa->opcodes[opc].num_funcUnit_uses);
      return NULL;
    }
  return &intisa->opcodes[opc].funcUnit_uses[u];
}



/* Operand information.  */


#define CHECK_OPERAND(INTISA,OPC,ICLASS,OPND,ERRVAL) \
  do { \
    if ((OPND) < 0 || (OPND) >= (ICLASS)->num_operands) \
      { \
	xtisa_errno = xtensa_isa_bad_operand; \
	sprintf (xtisa_error_msg, "invalid operand number (%d); " \
		 "opcode \"%s\" has %d operands", (OPND), \
		 (INTISA)->opcodes[(OPC)].name, (ICLASS)->num_operands); \
	return (ERRVAL); \
      } \
  } while (0)


static xtensa_operand_internal *
get_operand (xtensa_isa_internal *intisa, xtensa_opcode opc, int opnd)
{
  xtensa_iclass_internal *iclass;
  int iclass_id, operand_id;

  CHECK_OPCODE (intisa, opc, NULL);
  iclass_id = intisa->opcodes[opc].iclass_id;
  iclass = &intisa->iclasses[iclass_id];
  CHECK_OPERAND (intisa, opc, iclass, opnd, NULL);
  operand_id = iclass->operands[opnd].u.operand_id;
  return &intisa->operands[operand_id];
}


const char *
xtensa_operand_name (xtensa_isa isa, xtensa_opcode opc, int opnd)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return NULL;
  }
  return intop->name;
}


int
xtensa_operand_is_visible (xtensa_isa isa, xtensa_opcode opc, int opnd)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_iclass_internal *iclass;
  int iclass_id, operand_id;
  xtensa_operand_internal *intop;

  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  iclass_id = intisa->opcodes[opc].iclass_id;
  iclass = &intisa->iclasses[iclass_id];
  CHECK_OPERAND (intisa, opc, iclass, opnd, XTENSA_UNDEFINED);

  /* Special case for "sout" operands.  */
  if (iclass->operands[opnd].inout == 's') {
	  return 0;
  }

  operand_id = iclass->operands[opnd].u.operand_id;
  intop = &intisa->operands[operand_id];

  if ((intop->flags & XTENSA_OPERAND_IS_INVISIBLE) == 0) {
	  return 1;
  }
  return 0;
}


char
xtensa_operand_inout (xtensa_isa isa, xtensa_opcode opc, int opnd)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_iclass_internal *iclass;
  int iclass_id;
  char inout;

  CHECK_OPCODE (intisa, opc, 0);
  iclass_id = intisa->opcodes[opc].iclass_id;
  iclass = &intisa->iclasses[iclass_id];
  CHECK_OPERAND (intisa, opc, iclass, opnd, 0);
  inout = iclass->operands[opnd].inout;

  /* Special case for "sout" operands.  */
  if (inout == 's') {
	  return 'o';
  }

  return inout;
}


int
xtensa_operand_get_field (xtensa_isa isa, xtensa_opcode opc, int opnd,
			  xtensa_format fmt, int slot,
			  const xtensa_insnbuf slotbuf, uint32 *valp)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;
  int slot_id;
  xtensa_get_field_fn get_fn;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return -1;
  }

  CHECK_FORMAT (intisa, fmt, -1);
  CHECK_SLOT (intisa, fmt, slot, -1);

  slot_id = intisa->formats[fmt].slot_id[slot];
  if (intop->field_id == XTENSA_UNDEFINED)
    {
      xtisa_errno = xtensa_isa_no_field;
      strcpy (xtisa_error_msg, "implicit operand has no field");
      return -1;
    }
  get_fn = intisa->slots[slot_id].get_field_fns[intop->field_id];
  if (!get_fn)
    {
      xtisa_errno = xtensa_isa_wrong_slot;
      sprintf (xtisa_error_msg,
	       "operand \"%s\" does not exist in slot %d of format \"%s\"",
	       intop->name, slot, intisa->formats[fmt].name);
      return -1;
    }
  *valp = (*get_fn) (slotbuf);
  return 0;
}


int
xtensa_operand_set_field (xtensa_isa isa, xtensa_opcode opc, int opnd,
			  xtensa_format fmt, int slot,
			  xtensa_insnbuf slotbuf, uint32 val)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;
  int slot_id;
  xtensa_set_field_fn set_fn;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return -1;
  }

  CHECK_FORMAT (intisa, fmt, -1);
  CHECK_SLOT (intisa, fmt, slot, -1);

  slot_id = intisa->formats[fmt].slot_id[slot];
  if (intop->field_id == XTENSA_UNDEFINED)
    {
      xtisa_errno = xtensa_isa_no_field;
      strcpy (xtisa_error_msg, "implicit operand has no field");
      return -1;
    }
  set_fn = intisa->slots[slot_id].set_field_fns[intop->field_id];
  if (!set_fn)
    {
      xtisa_errno = xtensa_isa_wrong_slot;
      sprintf (xtisa_error_msg,
	       "operand \"%s\" does not exist in slot %d of format \"%s\"",
	       intop->name, slot, intisa->formats[fmt].name);
      return -1;
    }
  (*set_fn) (slotbuf, val);
  return 0;
}


int
xtensa_operand_encode (xtensa_isa isa, xtensa_opcode opc, int opnd,
		       uint32 *valp)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;
  uint32 test_val, orig_val;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return -1;
  }

  if (!intop->encode)
    {
      /* This is a default operand for a field.  How can we tell if the
	 value fits in the field?  Write the value into the field,
	 read it back, and then make sure we get the same value.  */
      static xtensa_insnbuf tmpbuf = 0;
      int slot_id;

      if (!tmpbuf)
	{
	  tmpbuf = xtensa_insnbuf_alloc (isa);
	  CHECK_ALLOC (tmpbuf, -1);
	}

      /* A default operand is always associated with a field,
	 but check just to be sure....  */
      if (intop->field_id == XTENSA_UNDEFINED)
	{
	  xtisa_errno = xtensa_isa_internal_error;
	  strcpy (xtisa_error_msg, "operand has no field");
	  return -1;
	}

      /* Find some slot that includes the field.  */
      for (slot_id = 0; slot_id < intisa->num_slots; slot_id++)
	{
	  xtensa_get_field_fn get_fn =
	    intisa->slots[slot_id].get_field_fns[intop->field_id];
	  xtensa_set_field_fn set_fn =
	    intisa->slots[slot_id].set_field_fns[intop->field_id];

	  if (get_fn && set_fn)
	    {
	      (*set_fn) (tmpbuf, *valp);
	      return ((*get_fn) (tmpbuf) != *valp);
	    }
	}

      /* Couldn't find any slot containing the field....  */
      xtisa_errno = xtensa_isa_no_field;
      strcpy (xtisa_error_msg, "field does not exist in any slot");
      return -1;
    }

  /* Encode the value.  In some cases, the encoding function may detect
     errors, but most of the time the only way to determine if the value
     was successfully encoded is to decode it and check if it matches
     the original value.  */
  orig_val = *valp;
  if ((*intop->encode) (valp)
      || (test_val = *valp, (*intop->decode) (&test_val))
      || test_val != orig_val)
    {
      xtisa_errno = xtensa_isa_bad_value;
      sprintf (xtisa_error_msg, "cannot encode operand value 0x%08x", *valp);
      return -1;
    }

  return 0;
}


int
xtensa_operand_decode (xtensa_isa isa, xtensa_opcode opc, int opnd,
		       uint32 *valp)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return -1;
  }

  /* Use identity function for "default" operands.  */
  if (!intop->decode) {
	  return 0;
  }

  if ((*intop->decode) (valp))
    {
      xtisa_errno = xtensa_isa_bad_value;
      sprintf (xtisa_error_msg, "cannot decode operand value 0x%08x", *valp);
      return -1;
    }
  return 0;
}


int
xtensa_operand_is_register (xtensa_isa isa, xtensa_opcode opc, int opnd)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return XTENSA_UNDEFINED;
  }

  if ((intop->flags & XTENSA_OPERAND_IS_REGISTER) != 0) {
	  return 1;
  }
  return 0;
}


xtensa_regfile
xtensa_operand_regfile (xtensa_isa isa, xtensa_opcode opc, int opnd)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return XTENSA_UNDEFINED;
  }

  return intop->regfile;
}


int
xtensa_operand_num_regs (xtensa_isa isa, xtensa_opcode opc, int opnd)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return XTENSA_UNDEFINED;
  }

  return intop->num_regs;
}


int
xtensa_operand_is_known_reg (xtensa_isa isa, xtensa_opcode opc, int opnd)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return XTENSA_UNDEFINED;
  }

  if ((intop->flags & XTENSA_OPERAND_IS_UNKNOWN) == 0) {
	  return 1;
  }
  return 0;
}


int
xtensa_operand_is_PCrelative (xtensa_isa isa, xtensa_opcode opc, int opnd)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return XTENSA_UNDEFINED;
  }

  if ((intop->flags & XTENSA_OPERAND_IS_PCRELATIVE) != 0) {
	  return 1;
  }
  return 0;
}


int
xtensa_operand_do_reloc (xtensa_isa isa, xtensa_opcode opc, int opnd,
			 uint32 *valp, uint32 pc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return -1;
  }

  if ((intop->flags & XTENSA_OPERAND_IS_PCRELATIVE) == 0) {
	  return 0;
  }

  if (!intop->do_reloc)
    {
      xtisa_errno = xtensa_isa_internal_error;
      strcpy (xtisa_error_msg, "operand missing do_reloc function");
      return -1;
    }

  if ((*intop->do_reloc) (valp, pc))
    {
      xtisa_errno = xtensa_isa_bad_value;
      sprintf (xtisa_error_msg,
	       "do_reloc failed for value 0x%08x at PC 0x%08x", *valp, pc);
      return -1;
    }

  return 0;
}


int
xtensa_operand_undo_reloc (xtensa_isa isa, xtensa_opcode opc, int opnd,
			   uint32 *valp, uint32 pc)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_operand_internal *intop;

  intop = get_operand (intisa, opc, opnd);
  if (!intop) {
	  return -1;
  }

  if ((intop->flags & XTENSA_OPERAND_IS_PCRELATIVE) == 0) {
	  return 0;
  }

  if (!intop->undo_reloc)
    {
      xtisa_errno = xtensa_isa_internal_error;
      strcpy (xtisa_error_msg, "operand missing undo_reloc function");
      return -1;
    }

  if ((*intop->undo_reloc) (valp, pc))
    {
      xtisa_errno = xtensa_isa_bad_value;
      sprintf (xtisa_error_msg,
	       "undo_reloc failed for value 0x%08x at PC 0x%08x", *valp, pc);
      return -1;
    }

  return 0;
}



/* State Operands.  */


#define CHECK_STATE_OPERAND(INTISA,OPC,ICLASS,STOP,ERRVAL) \
  do { \
    if ((STOP) < 0 || (STOP) >= (ICLASS)->num_stateOperands) \
      { \
	xtisa_errno = xtensa_isa_bad_operand; \
	sprintf (xtisa_error_msg, "invalid state operand number (%d); " \
		 "opcode \"%s\" has %d state operands", (STOP), \
		 (INTISA)->opcodes[(OPC)].name, (ICLASS)->num_stateOperands); \
	return (ERRVAL); \
      } \
  } while (0)


xtensa_state
xtensa_stateOperand_state (xtensa_isa isa, xtensa_opcode opc, int stOp)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_iclass_internal *iclass;
  int iclass_id;

  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  iclass_id = intisa->opcodes[opc].iclass_id;
  iclass = &intisa->iclasses[iclass_id];
  CHECK_STATE_OPERAND (intisa, opc, iclass, stOp, XTENSA_UNDEFINED);
  return iclass->stateOperands[stOp].u.state;
}


char
xtensa_stateOperand_inout (xtensa_isa isa, xtensa_opcode opc, int stOp)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_iclass_internal *iclass;
  int iclass_id;

  CHECK_OPCODE (intisa, opc, 0);
  iclass_id = intisa->opcodes[opc].iclass_id;
  iclass = &intisa->iclasses[iclass_id];
  CHECK_STATE_OPERAND (intisa, opc, iclass, stOp, 0);
  return iclass->stateOperands[stOp].inout;
}



/* Interface Operands.  */


#define CHECK_INTERFACE_OPERAND(INTISA,OPC,ICLASS,IFOP,ERRVAL) \
  do { \
    if ((IFOP) < 0 || (IFOP) >= (ICLASS)->num_interfaceOperands) \
      { \
	xtisa_errno = xtensa_isa_bad_operand; \
	sprintf (xtisa_error_msg, "invalid interface operand number (%d); " \
		 "opcode \"%s\" has %d interface operands", (IFOP), \
		 (INTISA)->opcodes[(OPC)].name, \
		 (ICLASS)->num_interfaceOperands); \
	return (ERRVAL); \
      } \
  } while (0)


xtensa_interface
xtensa_interfaceOperand_interface (xtensa_isa isa, xtensa_opcode opc,
				   int ifOp)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_iclass_internal *iclass;
  int iclass_id;

  CHECK_OPCODE (intisa, opc, XTENSA_UNDEFINED);
  iclass_id = intisa->opcodes[opc].iclass_id;
  iclass = &intisa->iclasses[iclass_id];
  CHECK_INTERFACE_OPERAND (intisa, opc, iclass, ifOp, XTENSA_UNDEFINED);
  return iclass->interfaceOperands[ifOp];
}



/* Register Files.  */


#define CHECK_REGFILE(INTISA,RF,ERRVAL) \
  do { \
    if ((RF) < 0 || (RF) >= (INTISA)->num_regfiles) \
      { \
	xtisa_errno = xtensa_isa_bad_regfile; \
	strcpy (xtisa_error_msg, "invalid regfile specifier"); \
	return (ERRVAL); \
      } \
  } while (0)


xtensa_regfile
xtensa_regfile_lookup (xtensa_isa isa, const char *name)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int n;

  if (!name || !*name)
    {
      xtisa_errno = xtensa_isa_bad_regfile;
      strcpy (xtisa_error_msg, "invalid regfile name");
      return XTENSA_UNDEFINED;
    }

  /* The expected number of regfiles is small; use a linear search.  */
  for (n = 0; n < intisa->num_regfiles; n++)
    {
	  if (!filename_cmp (intisa->regfiles[n].name, name)) {
		  return n;
	  }
    }

  xtisa_errno = xtensa_isa_bad_regfile;
  sprintf (xtisa_error_msg, "regfile \"%s\" not recognized", name);
  return XTENSA_UNDEFINED;
}


xtensa_regfile
xtensa_regfile_lookup_shortname (xtensa_isa isa, const char *shortname)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  int n;

  if (!shortname || !*shortname)
    {
      xtisa_errno = xtensa_isa_bad_regfile;
      strcpy (xtisa_error_msg, "invalid regfile shortname");
      return XTENSA_UNDEFINED;
    }

  /* The expected number of regfiles is small; use a linear search.  */
  for (n = 0; n < intisa->num_regfiles; n++)
    {
      /* Ignore regfile views since they always have the same shortnames
	 as their parents.  */
      if (intisa->regfiles[n].parent != n) {
	      continue;
      }
      if (!filename_cmp (intisa->regfiles[n].shortname, shortname)) {
	      return n;
      }
    }

  xtisa_errno = xtensa_isa_bad_regfile;
  sprintf (xtisa_error_msg, "regfile shortname \"%s\" not recognized",
	   shortname);
  return XTENSA_UNDEFINED;
}


const char *
xtensa_regfile_name (xtensa_isa isa, xtensa_regfile rf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_REGFILE (intisa, rf, NULL);
  return intisa->regfiles[rf].name;
}


const char *
xtensa_regfile_shortname (xtensa_isa isa, xtensa_regfile rf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_REGFILE (intisa, rf, NULL);
  return intisa->regfiles[rf].shortname;
}


xtensa_regfile
xtensa_regfile_view_parent (xtensa_isa isa, xtensa_regfile rf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_REGFILE (intisa, rf, XTENSA_UNDEFINED);
  return intisa->regfiles[rf].parent;
}


int
xtensa_regfile_num_bits (xtensa_isa isa, xtensa_regfile rf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_REGFILE (intisa, rf, XTENSA_UNDEFINED);
  return intisa->regfiles[rf].num_bits;
}


int
xtensa_regfile_num_entries (xtensa_isa isa, xtensa_regfile rf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_REGFILE (intisa, rf, XTENSA_UNDEFINED);
  return intisa->regfiles[rf].num_entries;
}



/* Processor States.  */


#define CHECK_STATE(INTISA,ST,ERRVAL) \
  do { \
    if ((ST) < 0 || (ST) >= (INTISA)->num_states) \
      { \
	xtisa_errno = xtensa_isa_bad_state; \
	strcpy (xtisa_error_msg, "invalid state specifier"); \
	return (ERRVAL); \
      } \
  } while (0)


xtensa_state
xtensa_state_lookup (xtensa_isa isa, const char *name)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_lookup_entry entry, *result = 0;

  if (!name || !*name)
    {
      xtisa_errno = xtensa_isa_bad_state;
      strcpy (xtisa_error_msg, "invalid state name");
      return XTENSA_UNDEFINED;
    }

  if (intisa->num_states != 0)
    {
      entry.key = name;
      result = bsearch (&entry, intisa->state_lookup_table, intisa->num_states,
			sizeof (xtensa_lookup_entry), xtensa_isa_name_compare);
    }

  if (!result)
    {
      xtisa_errno = xtensa_isa_bad_state;
      sprintf (xtisa_error_msg, "state \"%s\" not recognized", name);
      return XTENSA_UNDEFINED;
    }

  return result->u.state;
}


const char *
xtensa_state_name (xtensa_isa isa, xtensa_state st)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_STATE (intisa, st, NULL);
  return intisa->states[st].name;
}


int
xtensa_state_num_bits (xtensa_isa isa, xtensa_state st)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_STATE (intisa, st, XTENSA_UNDEFINED);
  return intisa->states[st].num_bits;
}


int
xtensa_state_is_exported (xtensa_isa isa, xtensa_state st)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_STATE (intisa, st, XTENSA_UNDEFINED);
  if ((intisa->states[st].flags & XTENSA_STATE_IS_EXPORTED) != 0) {
	  return 1;
  }
  return 0;
}


int
xtensa_state_is_shared_or (xtensa_isa isa, xtensa_state st)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_STATE (intisa, st, XTENSA_UNDEFINED);
  if ((intisa->states[st].flags & XTENSA_STATE_IS_SHARED_OR) != 0) {
	  return 1;
  }
  return 0;
}



/* Sysregs.  */


#define CHECK_SYSREG(INTISA,SYSREG,ERRVAL) \
  do { \
    if ((SYSREG) < 0 || (SYSREG) >= (INTISA)->num_sysregs) \
      { \
	xtisa_errno = xtensa_isa_bad_sysreg; \
	strcpy (xtisa_error_msg, "invalid sysreg specifier"); \
	return (ERRVAL); \
      } \
  } while (0)


xtensa_sysreg
xtensa_sysreg_lookup (xtensa_isa isa, int num, int is_user)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;

  if (is_user != 0) {
	  is_user = 1;
  }

  if (num < 0 || num > intisa->max_sysreg_num[is_user]
      || intisa->sysreg_table[is_user][num] == XTENSA_UNDEFINED)
    {
      xtisa_errno = xtensa_isa_bad_sysreg;
      strcpy (xtisa_error_msg, "sysreg not recognized");
      return XTENSA_UNDEFINED;
    }

  return intisa->sysreg_table[is_user][num];
}


xtensa_sysreg
xtensa_sysreg_lookup_name (xtensa_isa isa, const char *name)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_lookup_entry entry, *result = 0;

  if (!name || !*name)
    {
      xtisa_errno = xtensa_isa_bad_sysreg;
      strcpy (xtisa_error_msg, "invalid sysreg name");
      return XTENSA_UNDEFINED;
    }

  if (intisa->num_sysregs != 0)
    {
      entry.key = name;
      result = bsearch (&entry, intisa->sysreg_lookup_table,
			intisa->num_sysregs, sizeof (xtensa_lookup_entry),
			xtensa_isa_name_compare);
    }

  if (!result)
    {
      xtisa_errno = xtensa_isa_bad_sysreg;
      sprintf (xtisa_error_msg, "sysreg \"%s\" not recognized", name);
      return XTENSA_UNDEFINED;
    }

  return result->u.sysreg;
}


const char *
xtensa_sysreg_name (xtensa_isa isa, xtensa_sysreg sysreg)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_SYSREG (intisa, sysreg, NULL);
  return intisa->sysregs[sysreg].name;
}


int
xtensa_sysreg_number (xtensa_isa isa, xtensa_sysreg sysreg)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_SYSREG (intisa, sysreg, XTENSA_UNDEFINED);
  return intisa->sysregs[sysreg].number;
}


int
xtensa_sysreg_is_user (xtensa_isa isa, xtensa_sysreg sysreg)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_SYSREG (intisa, sysreg, XTENSA_UNDEFINED);
  if (intisa->sysregs[sysreg].is_user) {
	  return 1;
  }
  return 0;
}



/* Interfaces.  */


#define CHECK_INTERFACE(INTISA,INTF,ERRVAL) \
  do { \
    if ((INTF) < 0 || (INTF) >= (INTISA)->num_interfaces) \
      { \
	xtisa_errno = xtensa_isa_bad_interface; \
	strcpy (xtisa_error_msg, "invalid interface specifier"); \
	return (ERRVAL); \
      } \
  } while (0)


xtensa_interface
xtensa_interface_lookup (xtensa_isa isa, const char *ifname)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_lookup_entry entry, *result = 0;

  if (!ifname || !*ifname)
    {
      xtisa_errno = xtensa_isa_bad_interface;
      strcpy (xtisa_error_msg, "invalid interface name");
      return XTENSA_UNDEFINED;
    }

  if (intisa->num_interfaces != 0)
    {
      entry.key = ifname;
      result = bsearch (&entry, intisa->interface_lookup_table,
			intisa->num_interfaces, sizeof (xtensa_lookup_entry),
			xtensa_isa_name_compare);
    }

  if (!result)
    {
      xtisa_errno = xtensa_isa_bad_interface;
      sprintf (xtisa_error_msg, "interface \"%s\" not recognized", ifname);
      return XTENSA_UNDEFINED;
    }

  return result->u.intf;
}


const char *
xtensa_interface_name (xtensa_isa isa, xtensa_interface intf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_INTERFACE (intisa, intf, NULL);
  return intisa->interfaces[intf].name;
}


int
xtensa_interface_num_bits (xtensa_isa isa, xtensa_interface intf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_INTERFACE (intisa, intf, XTENSA_UNDEFINED);
  return intisa->interfaces[intf].num_bits;
}


char
xtensa_interface_inout (xtensa_isa isa, xtensa_interface intf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_INTERFACE (intisa, intf, 0);
  return intisa->interfaces[intf].inout;
}


int
xtensa_interface_has_side_effect (xtensa_isa isa, xtensa_interface intf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_INTERFACE (intisa, intf, XTENSA_UNDEFINED);
  if ((intisa->interfaces[intf].flags & XTENSA_INTERFACE_HAS_SIDE_EFFECT) != 0) {
	  return 1;
  }
  return 0;
}


int
xtensa_interface_class_id (xtensa_isa isa, xtensa_interface intf)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_INTERFACE (intisa, intf, XTENSA_UNDEFINED);
  return intisa->interfaces[intf].class_id;
}



/* Functional Units.  */


#define CHECK_FUNCUNIT(INTISA,FUN,ERRVAL) \
  do { \
    if ((FUN) < 0 || (FUN) >= (INTISA)->num_funcUnits) \
      { \
	xtisa_errno = xtensa_isa_bad_funcUnit; \
	strcpy (xtisa_error_msg, "invalid functional unit specifier"); \
	return (ERRVAL); \
      } \
  } while (0)


xtensa_funcUnit
xtensa_funcUnit_lookup (xtensa_isa isa, const char *fname)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  xtensa_lookup_entry entry, *result = 0;

  if (!fname || !*fname)
    {
      xtisa_errno = xtensa_isa_bad_funcUnit;
      strcpy (xtisa_error_msg, "invalid functional unit name");
      return XTENSA_UNDEFINED;
    }

  if (intisa->num_funcUnits != 0)
    {
      entry.key = fname;
      result = bsearch (&entry, intisa->funcUnit_lookup_table,
			intisa->num_funcUnits, sizeof (xtensa_lookup_entry),
			xtensa_isa_name_compare);
    }

  if (!result)
    {
      xtisa_errno = xtensa_isa_bad_funcUnit;
      sprintf (xtisa_error_msg,
	       "functional unit \"%s\" not recognized", fname);
      return XTENSA_UNDEFINED;
    }

  return result->u.fun;
}


const char *
xtensa_funcUnit_name (xtensa_isa isa, xtensa_funcUnit fun)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_FUNCUNIT (intisa, fun, NULL);
  return intisa->funcUnits[fun].name;
}


int
xtensa_funcUnit_num_copies (xtensa_isa isa, xtensa_funcUnit fun)
{
  xtensa_isa_internal *intisa = (xtensa_isa_internal *) isa;
  CHECK_FUNCUNIT (intisa, fun, XTENSA_UNDEFINED);
  return intisa->funcUnits[fun].num_copies;
}

