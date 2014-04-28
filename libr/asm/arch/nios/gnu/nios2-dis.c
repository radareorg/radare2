/* Altera Nios II disassemble routines
   Copyright (C) 2012, 2013 Free Software Foundation, Inc.
   Contributed by Nigel Gray (ngray@altera.com).
   Contributed by Mentor Graphics, Inc.

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
   along with this file; see the file COPYING.  If not, write to the
   Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "dis-asm.h"
#include "opcode/nios2.h"
#include "libiberty.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>

/* No symbol table is available when this code runs out in an embedded
   system as when it is used for disassembler support in a monitor.  */
#if !defined(EMBEDDED_ENV)
#define SYMTAB_AVAILABLE 1
#include "elf-bfd.h"
//#include "elf/nios2.h"
#endif

/* Length of Nios II instruction in bytes.  */
#define INSNLEN 4

/* Data structures used by the opcode hash table.  */
typedef struct _nios2_opcode_hash
{
  const struct nios2_opcode *opcode;
  struct _nios2_opcode_hash *next;
} nios2_opcode_hash;

static bfd_boolean nios2_hash_init = 0;
static nios2_opcode_hash *nios2_hash[(OP_MASK_OP) + 1];

/* Separate hash table for pseudo-ops.  */
static nios2_opcode_hash *nios2_ps_hash[(OP_MASK_OP) + 1];

/* Function to initialize the opcode hash table.  */
static void
nios2_init_opcode_hash (void)
{
  unsigned int i;
  register const struct nios2_opcode *op;

  for (i = 0; i <= OP_MASK_OP; ++i)
    nios2_hash[0] = NULL;
  for (i = 0; i <= OP_MASK_OP; i++)
    for (op = nios2_opcodes; op < &nios2_opcodes[NUMOPCODES]; op++)
      {
	nios2_opcode_hash *new_hash;
	nios2_opcode_hash **bucket = NULL;

	if ((op->pinfo & NIOS2_INSN_MACRO) == NIOS2_INSN_MACRO)
	  {
	    if (i == ((op->match >> OP_SH_OP) & OP_MASK_OP)
		&& (op->pinfo & (NIOS2_INSN_MACRO_MOV | NIOS2_INSN_MACRO_MOVI)
		    & 0x7fffffff))
	      bucket = &(nios2_ps_hash[i]);
	  }
	else if (i == ((op->match >> OP_SH_OP) & OP_MASK_OP))
	  bucket = &(nios2_hash[i]);

	if (bucket)
	  {
	    new_hash =
	      (nios2_opcode_hash *) malloc (sizeof (nios2_opcode_hash));
	    if (new_hash == NULL)
	      {
		fprintf (stderr,
			 "error allocating memory...broken disassembler\n");
		abort ();
	      }
	    new_hash->opcode = op;
	    new_hash->next = NULL;
	    while (*bucket)
	      bucket = &((*bucket)->next);
	    *bucket = new_hash;
	  }
      }
  nios2_hash_init = 1;
#ifdef DEBUG_HASHTABLE
  for (i = 0; i <= OP_MASK_OP; ++i)
    {
      nios2_opcode_hash *tmp_hash = nios2_hash[i];
      printf ("index: 0x%02X	ops: ", i);
      while (tmp_hash != NULL)
	{
	  printf ("%s ", tmp_hash->opcode->name);
	  tmp_hash = tmp_hash->next;
	}
      printf ("\n");
    }

  for (i = 0; i <= OP_MASK_OP; ++i)
    {
      nios2_opcode_hash *tmp_hash = nios2_ps_hash[i];
      printf ("index: 0x%02X	ops: ", i);
      while (tmp_hash != NULL)
	{
	  printf ("%s ", tmp_hash->opcode->name);
	  tmp_hash = tmp_hash->next;
	}
      printf ("\n");
    }
#endif /* DEBUG_HASHTABLE */
}

/* Return a pointer to an nios2_opcode struct for a given instruction
   opcode, or NULL if there is an error.  */
const struct nios2_opcode *
nios2_find_opcode_hash (unsigned long opcode)
{
  nios2_opcode_hash *entry;

  /* Build a hash table to shorten the search time.  */
  if (!nios2_hash_init)
    nios2_init_opcode_hash ();

  /* First look in the pseudo-op hashtable.  */
  for (entry = nios2_ps_hash[(opcode >> OP_SH_OP) & OP_MASK_OP];
       entry; entry = entry->next)
    if (entry->opcode->match == (opcode & entry->opcode->mask))
      return entry->opcode;

  /* Otherwise look in the main hashtable.  */
  for (entry = nios2_hash[(opcode >> OP_SH_OP) & OP_MASK_OP];
       entry; entry = entry->next)
    if (entry->opcode->match == (opcode & entry->opcode->mask))
      return entry->opcode;

  return NULL;
}

/* There are 32 regular registers, 32 coprocessor registers,
   and 32 control registers.  */
#define NUMREGNAMES 32

/* Return a pointer to the base of the coprocessor register name array.  */
static struct nios2_reg *
nios2_coprocessor_regs (void)
{
  static struct nios2_reg *cached = NULL;
  
  if (!cached)
    {
      int i;
      for (i = NUMREGNAMES; i < nios2_num_regs; i++)
	if (!strcmp (nios2_regs[i].name, "c0"))
	  {
	    cached = nios2_regs + i;
	    break;
	  }
      assert (cached);
    }
  return cached;
}

/* Return a pointer to the base of the control register name array.  */
static struct nios2_reg *
nios2_control_regs (void)
{
  static struct nios2_reg *cached = NULL;
  
  if (!cached)
    {
      int i;
      for (i = NUMREGNAMES; i < nios2_num_regs; i++)
	if (!strcmp (nios2_regs[i].name, "status"))
	  {
	    cached = nios2_regs + i;
	    break;
	  }
      assert (cached);
    }
  return cached;
}

/* The function nios2_print_insn_arg uses the character pointed
   to by ARGPTR to determine how it print the next token or separator
   character in the arguments to an instruction.  */
static int
nios2_print_insn_arg (const char *argptr,
		      unsigned long opcode, bfd_vma address,
		      disassemble_info *info)
{
  unsigned long i = 0;
  struct nios2_reg *reg_base;

  switch (*argptr)
    {
    case ',':
    case '(':
    case ')':
      (*info->fprintf_func) (info->stream, "%c", *argptr);
      break;
    case 'd':
      i = GET_INSN_FIELD (RRD, opcode);

      if (GET_INSN_FIELD (OP, opcode) == OP_MATCH_CUSTOM
	  && GET_INSN_FIELD (CUSTOM_C, opcode) == 0)
	reg_base = nios2_coprocessor_regs ();
      else
	reg_base = nios2_regs;

      if (i < NUMREGNAMES)
	(*info->fprintf_func) (info->stream, "%s", reg_base[i].name);
      else
	(*info->fprintf_func) (info->stream, "unknown");
      break;
    case 's':
      i = GET_INSN_FIELD (RRS, opcode);

      if (GET_INSN_FIELD (OP, opcode) == OP_MATCH_CUSTOM
	  && GET_INSN_FIELD (CUSTOM_A, opcode) == 0)
	reg_base = nios2_coprocessor_regs ();
      else
	reg_base = nios2_regs;

      if (i < NUMREGNAMES)
	(*info->fprintf_func) (info->stream, "%s", reg_base[i].name);
      else
	(*info->fprintf_func) (info->stream, "unknown");
      break;
    case 't':
      i = GET_INSN_FIELD (RRT, opcode);

      if (GET_INSN_FIELD (OP, opcode) == OP_MATCH_CUSTOM
	  && GET_INSN_FIELD (CUSTOM_B, opcode) == 0)
	reg_base = nios2_coprocessor_regs ();
      else
	reg_base = nios2_regs;

      if (i < NUMREGNAMES)
	(*info->fprintf_func) (info->stream, "%s", reg_base[i].name);
      else
	(*info->fprintf_func) (info->stream, "unknown");
      break;
    case 'i':
      /* 16-bit signed immediate.  */
      i = (signed) (GET_INSN_FIELD (IMM16, opcode) << 16) >> 16;
      (*info->fprintf_func) (info->stream, "%ld", i);
      break;
    case 'u':
      /* 16-bit unsigned immediate.  */
      i = GET_INSN_FIELD (IMM16, opcode);
      (*info->fprintf_func) (info->stream, "%ld", i);
      break;
    case 'o':
      /* 16-bit signed immediate address offset.  */
      i = (signed) (GET_INSN_FIELD (IMM16, opcode) << 16) >> 16;
      address = address + 4 + i;
      (*info->print_address_func) (address, info);
      break;
    case 'p':
      /* 5-bit unsigned immediate.  */
      i = GET_INSN_FIELD (CACHE_OPX, opcode);
      (*info->fprintf_func) (info->stream, "%ld", i);
      break;
    case 'j':
      /* 5-bit unsigned immediate.  */
      i = GET_INSN_FIELD (IMM5, opcode);
      (*info->fprintf_func) (info->stream, "%ld", i);
      break;
    case 'l':
      /* 8-bit unsigned immediate.  */
      /* FIXME - not yet implemented */
      i = GET_INSN_FIELD (CUSTOM_N, opcode);
      (*info->fprintf_func) (info->stream, "%lu", i);
      break;
    case 'm':
      /* 26-bit unsigned immediate.  */
      i = GET_INSN_FIELD (IMM26, opcode);
      /* This translates to an address because it's only used in call
	 instructions.  */
      address = (address & 0xf0000000) | (i << 2);
      (*info->print_address_func) (address, info);
      break;
    case 'c':
      /* Control register index.  */
      i = GET_INSN_FIELD (IMM5, opcode);
      reg_base = nios2_control_regs ();
      (*info->fprintf_func) (info->stream, "%s", reg_base[i].name);
      break;
    case 'b':
      i = GET_INSN_FIELD (IMM5, opcode);
      (*info->fprintf_func) (info->stream, "%ld", i);
      break;
    default:
      (*info->fprintf_func) (info->stream, "unknown");
      break;
    }
  return 0;
}

/* nios2_disassemble does all the work of disassembling a Nios II
   instruction opcode.  */
static int
nios2_disassemble (bfd_vma address, unsigned long opcode,
		   disassemble_info *info)
{
  const struct nios2_opcode *op;

  info->bytes_per_line = INSNLEN;
  info->bytes_per_chunk = INSNLEN;
  info->display_endian = info->endian;
  info->insn_info_valid = 1;
  info->branch_delay_insns = 0;
  info->data_size = 0;
  info->insn_type = dis_nonbranch;
  info->target = 0;
  info->target2 = 0;

  /* Find the major opcode and use this to disassemble
     the instruction and its arguments.  */
  op = nios2_find_opcode_hash (opcode);

  if (op != NULL)
    {
      bfd_boolean is_nop = FALSE;
      if (op->pinfo == NIOS2_INSN_MACRO_MOV)
	{
	  /* Check for mov r0, r0 and change to nop.  */
	  int dst, src;
	  dst = GET_INSN_FIELD (RRD, opcode);
	  src = GET_INSN_FIELD (RRS, opcode);
	  if (dst == 0 && src == 0)
	    {
	      (*info->fprintf_func) (info->stream, "nop");
	      is_nop = TRUE;
	    }
	  else
	    (*info->fprintf_func) (info->stream, "%s", op->name);
	}
      else
	(*info->fprintf_func) (info->stream, "%s", op->name);

      if (!is_nop)
	{
	  const char *argstr = op->args;
	  if (argstr != NULL && *argstr != '\0')
	    {
	      (*info->fprintf_func) (info->stream, " ");
	      while (*argstr != '\0')
		{
		  nios2_print_insn_arg (argstr, opcode, address, info);
		  ++argstr;
		}
	    }
	}
    }
  else
    {
      /* Handle undefined instructions.  */
      info->insn_type = dis_noninsn;
      (*info->fprintf_func) (info->stream, "0x%lx", opcode);
    }
  /* Tell the caller how far to advance the program counter.  */
  return INSNLEN;
}


/* print_insn_nios2 is the main disassemble function for Nios II.
   The function diassembler(abfd) (source in disassemble.c) returns a
   pointer to this either print_insn_big_nios2 or
   print_insn_little_nios2, which in turn call this function when the
   bfd machine type is Nios II. print_insn_nios2 reads the
   instruction word at the address given, and prints the disassembled
   instruction on the stream info->stream using info->fprintf_func. */

static int
print_insn_nios2 (bfd_vma address, disassemble_info *info,
		  enum bfd_endian endianness)
{
  bfd_byte buffer[INSNLEN];
  int status;

  status = (*info->read_memory_func) (address, buffer, INSNLEN, info);
  if (status == 0)
    {
      unsigned long insn;
      if (endianness == BFD_ENDIAN_BIG)
	insn = (unsigned long) bfd_getb32 (buffer);
      else
	insn = (unsigned long) bfd_getl32 (buffer);
      status = nios2_disassemble (address, insn, info);
    }
  else
    {
      (*info->memory_error_func) (status, address, info);
      status = -1;
    }
  return status;
}

/* These two functions are the main entry points, accessed from
   disassemble.c.  */
int
print_insn_big_nios2 (bfd_vma address, disassemble_info *info)
{
  return print_insn_nios2 (address, info, BFD_ENDIAN_BIG);
}

int
print_insn_little_nios2 (bfd_vma address, disassemble_info *info)
{
  return print_insn_nios2 (address, info, BFD_ENDIAN_LITTLE);
}
