/* ARC target-dependent stuff.  Extension structure access functions
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

#include "../../../include/sysdep.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "../../../include/mybfd.h"
#include "arc-ext.h"
#include "elf-arc.h"
#include "../../../include/libiberty.h"

#define xstrdup strdup

/* Stub - extension map reading from ELF not needed for disassembly */
#define bfd_get_section_contents(bfd, sect, buf, off, cnt) (false)

/* This module provides support for extensions to the ARC processor
   architecture.  */


/* Local constants.  */

#define FIRST_EXTENSION_CORE_REGISTER   32
#define LAST_EXTENSION_CORE_REGISTER    59
#define FIRST_EXTENSION_CONDITION_CODE  0x10
#define LAST_EXTENSION_CONDITION_CODE   0x1f

#define NUM_EXT_CORE      \
  (LAST_EXTENSION_CORE_REGISTER  - FIRST_EXTENSION_CORE_REGISTER  + 1)
#define NUM_EXT_COND      \
  (LAST_EXTENSION_CONDITION_CODE - FIRST_EXTENSION_CONDITION_CODE + 1)
#define INST_HASH_BITS    6
#define INST_HASH_SIZE    (1 << INST_HASH_BITS)
#define INST_HASH_MASK    (INST_HASH_SIZE - 1)


/* Local types.  */

/* These types define the information stored in the table.  */

struct ExtAuxRegister
{
  unsigned		  address;
  char *		  name;
  struct ExtAuxRegister * next;
};

struct ExtCoreRegister
{
  short		    number;
  enum ExtReadWrite rw;
  char *	    name;
};

struct arcExtMap
{
  struct ExtAuxRegister* auxRegisters;
  struct ExtInstruction* instructions[INST_HASH_SIZE];
  struct ExtCoreRegister coreRegisters[NUM_EXT_CORE];
  char *		 condCodes[NUM_EXT_COND];
};


/* Local data.  */

/* Extension table.  */
static struct arcExtMap arc_extension_map;


/* Local macros.  */

/* A hash function used to map instructions into the table.  */
#define INST_HASH(MAJOR, MINOR)    ((((MAJOR) << 3) ^ (MINOR)) & INST_HASH_MASK)


/* Local functions.  */

static void
create_map (unsigned char *block,
	    unsigned long length)
{
  unsigned char *p = block;

  while (p && p < (block + length))
    {
      /* p[0] == length of record
	 p[1] == type of record
	 For instructions:
	   p[2]  = opcode
	   p[3]  = minor opcode (if opcode == 3)
	   p[4]  = flags
	   p[5]+ = name
	 For core regs and condition codes:
	   p[2]  = value
	   p[3]+ = name
	 For auxiliary regs:
	   p[2..5] = value
	   p[6]+   = name
	     (value is p[2]<<24|p[3]<<16|p[4]<<8|p[5]).  */

      /* The sequence of records is temrinated by an "empty"
	 record.  */
      if (p[0] == 0)
	break;

      switch (p[1])
	{
	case EXT_INSTRUCTION:
	  {
	    struct ExtInstruction  *insn = XNEW (struct ExtInstruction);
	    int			    major = p[2];
	    int			    minor = p[3];
	    struct ExtInstruction **bucket =
		   &arc_extension_map.instructions[INST_HASH (major, minor)];

	    insn->name  = xstrdup ((char *) (p + 5));
	    insn->major = major;
	    insn->minor = minor;
	    insn->flags = p[4];
	    insn->next  = *bucket;
	    insn->suffix = 0;
	    insn->syntax = 0;
	    insn->modsyn = 0;
	    *bucket = insn;
	    break;
	  }

	case EXT_CORE_REGISTER:
	  {
	    unsigned char number = p[2];
	    char*	  name	 = (char *) (p + 3);

	    arc_extension_map.
	      coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].number
	      = number;
	    arc_extension_map.
	      coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].rw
	      = REG_READWRITE;
	    arc_extension_map.
	      coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].name
	      = xstrdup (name);
	    break;
	  }

	case EXT_LONG_CORE_REGISTER:
	  {
	    unsigned char     number = p[2];
	    char*	      name   = (char *) (p + 7);
	    enum ExtReadWrite rw     = p[6];

	    arc_extension_map.
	      coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].number
	      = number;
	    arc_extension_map.
	      coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].rw
	      = rw;
	    arc_extension_map.
	      coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].name
	      = xstrdup (name);
	    break;
	  }

	case EXT_COND_CODE:
	  {
	    char *cc_name = xstrdup ((char *) (p + 3));

	    arc_extension_map.
	      condCodes[p[2] - FIRST_EXTENSION_CONDITION_CODE]
	      = cc_name;
	    break;
	  }

	case EXT_AUX_REGISTER:
	  {
	    /* Trickier -- need to store linked list of these.  */
	    struct ExtAuxRegister *newAuxRegister
	      = XNEW (struct ExtAuxRegister);
	    char *aux_name = xstrdup ((char *) (p + 6));

	    newAuxRegister->name = aux_name;
	    newAuxRegister->address = (((unsigned) p[2] << 24) | (p[3] << 16)
				       | (p[4] << 8) | p[5]);
	    newAuxRegister->next = arc_extension_map.auxRegisters;
	    arc_extension_map.auxRegisters = newAuxRegister;
	    break;
	  }

	default:
	  break;
	}

      p += p[0]; /* Move on to next record.  */
    }
}


/* Free memory that has been allocated for the extensions.  */

static void
destroy_map (void)
{
  struct ExtAuxRegister *r;
  unsigned int		 i;

  /* Free auxiliary registers.  */
  r = arc_extension_map.auxRegisters;
  while (r)
    {
      /* N.B. after r has been freed, r->next is invalid!  */
      struct ExtAuxRegister* next = r->next;

      free (r->name);
      free (r);
      r = next;
    }

  /* Free instructions.  */
  for (i = 0; i < INST_HASH_SIZE; i++)
    {
      struct ExtInstruction *insn = arc_extension_map.instructions[i];

      while (insn)
	{
	  /* N.B. after insn has been freed, insn->next is invalid!  */
	  struct ExtInstruction *next = insn->next;

	  free (insn->name);
	  free (insn);
	  insn = next;
	}
    }

  /* Free core registers.  */
  for (i = 0; i < NUM_EXT_CORE; i++)
    free (arc_extension_map.coreRegisters[i].name);

  /* Free condition codes.  */
  for (i = 0; i < NUM_EXT_COND; i++)
    free (arc_extension_map.condCodes[i]);

  memset (&arc_extension_map, 0, sizeof (arc_extension_map));
}


static const char *
ExtReadWrite_image (enum ExtReadWrite val)
{
    switch (val)
    {
	case REG_INVALID  : return "INVALID";
	case REG_READ	  : return "RO";
	case REG_WRITE	  : return "WO";
	case REG_READWRITE: return "R/W";
	default		  : return "???";
    }
}


/* Externally visible functions.  */

/* Get the name of an extension instruction.  */

const extInstruction_t *
arcExtMap_insn (int opcode, unsigned long long insn)
{
  /* Here the following tasks need to be done.  First of all, the
     opcode stored in the Extension Map is the real opcode.  However,
     the subopcode stored in the instruction to be disassembled is
     mangled.  We pass (in minor opcode), the instruction word.  Here
     we will un-mangle it and get the real subopcode which we can look
     for in the Extension Map.  This function is used both for the
     ARCTangent and the ARCompact, so we would also need some sort of
     a way to distinguish between the two architectures.  This is
     because the ARCTangent does not do any of this mangling so we
     have no issues there.  */

  /* If P[22:23] is 0 or 2 then un-mangle using iiiiiI.  If it is 1
     then use iiiiIi.  Now, if P is 3 then check M[5:5] and if it is 0
     then un-mangle using iiiiiI else iiiiii.  */

  unsigned char minor;
  extInstruction_t *temp;

  /* 16-bit instructions.  */
  if (0x08 <= opcode && opcode <= 0x0b)
    {
      unsigned char b, c, i;

      b = (insn & 0x0700) >> 8;
      c = (insn & 0x00e0) >> 5;
      i = (insn & 0x001f);

      if (i)
	minor = i;
      else
	minor = (c == 0x07) ? b : c;
    }
  /* 32-bit instructions.  */
  else
    {
      unsigned char I, A, B;

      I = (insn & 0x003f0000) >> 16;
      A = (insn & 0x0000003f);
      B = ((insn & 0x07000000) >> 24) | ((insn & 0x00007000) >> 9);

      if (I != 0x2f)
	{
#ifndef UNMANGLED
	  switch (P)
	    {
	    case 3:
	      if (M)
		{
		  minor = I;
		  break;
		}
	    case 0:
	    case 2:
	      minor = (I >> 1) | ((I & 0x1) << 5);
	      break;
	    case 1:
	      minor = (I >> 1) | (I & 0x1) | ((I & 0x2) << 4);
	    }
#else
	  minor = I;
#endif
	}
      else
	{
	  if (A != 0x3f)
	    minor = A;
	  else
	    minor = B;
	}
    }

  temp = arc_extension_map.instructions[INST_HASH (opcode, minor)];
  while (temp)
    {
      if ((temp->major == opcode) && (temp->minor == minor))
	{
	  return temp;
	}
      temp = temp->next;
    }

  return NULL;
}

/* Get the name of an extension core register.  */

const char *
arcExtMap_coreRegName (int regnum)
{
  if (regnum < FIRST_EXTENSION_CORE_REGISTER
      || regnum > LAST_EXTENSION_CORE_REGISTER)
    return NULL;
  return arc_extension_map.
    coreRegisters[regnum - FIRST_EXTENSION_CORE_REGISTER].name;
}

/* Get the access mode of an extension core register.  */

enum ExtReadWrite
arcExtMap_coreReadWrite (int regnum)
{
  if (regnum < FIRST_EXTENSION_CORE_REGISTER
      || regnum > LAST_EXTENSION_CORE_REGISTER)
    return REG_INVALID;
  return arc_extension_map.
    coreRegisters[regnum - FIRST_EXTENSION_CORE_REGISTER].rw;
}

/* Get the name of an extension condition code.  */

const char *
arcExtMap_condCodeName (int code)
{
  if (code < FIRST_EXTENSION_CONDITION_CODE
      || code > LAST_EXTENSION_CONDITION_CODE)
    return NULL;
  return arc_extension_map.
    condCodes[code - FIRST_EXTENSION_CONDITION_CODE];
}

/* Get the name of an extension auxiliary register.  */

const char *
arcExtMap_auxRegName (unsigned address)
{
  /* Walk the list of auxiliary register names and find the name.  */
  struct ExtAuxRegister *r;

  for (r = arc_extension_map.auxRegisters; r; r = r->next)
    {
      if (r->address == address)
	return (const char *)r->name;
    }
  return NULL;
}

/* Load extensions described in .arcextmap and
   .gnu.linkonce.arcextmap.* ELF section.  */

void
build_ARC_extmap (bfd *text_bfd)
{
  asection *sect;

  /* The map is built each time gdb loads an executable file - so free
     any existing map, as the map defined by the new file may differ
     from the old.  */
  destroy_map ();

  for (sect = text_bfd->sections; sect != NULL; sect = sect->next)
    if (!strncmp (sect->name,
		  ".gnu.linkonce.arcextmap.",
	  sizeof (".gnu.linkonce.arcextmap.") - 1)
	|| !strcmp (sect->name,".arcextmap"))
      {
	bfd_size_type  count  = bfd_section_size (text_bfd, sect);
	unsigned char* buffer = xmalloc (count);

	if (buffer)
	  {
	    if (bfd_get_section_contents (text_bfd, sect, buffer, 0, count))
	      create_map (buffer, count);
	    free (buffer);
	  }
      }
}

/* Debug function used to dump the ARC information fount in arcextmap
   sections.  */

void
dump_ARC_extmap (void)
{
    struct ExtAuxRegister *r;
    int			   i;

    r = arc_extension_map.auxRegisters;

    while (r)
    {
	printf ("AUX : %s %u\n", r->name, r->address);
	r = r->next;
    }

    for (i = 0; i < INST_HASH_SIZE; i++)
    {
	struct ExtInstruction *insn;

	for (insn = arc_extension_map.instructions[i];
	     insn != NULL; insn = insn->next)
	  {
	    printf ("INST: 0x%02x 0x%02x ", insn->major, insn->minor);
	    switch (insn->flags & ARC_SYNTAX_MASK)
	      {
	      case ARC_SYNTAX_2OP:
		printf ("SYNTAX_2OP");
		break;
	      case ARC_SYNTAX_3OP:
		printf ("SYNTAX_3OP");
		break;
	      case ARC_SYNTAX_1OP:
		printf ("SYNTAX_1OP");
		break;
	      case ARC_SYNTAX_NOP:
		printf ("SYNTAX_NOP");
		break;
	      default:
		printf ("SYNTAX_UNK");
		break;
	      }

	    if (insn->flags & 0x10)
	      printf ("|MODIFIER");

	    printf (" %s\n", insn->name);
	  }
    }

    for (i = 0; i < NUM_EXT_CORE; i++)
    {
	struct ExtCoreRegister reg = arc_extension_map.coreRegisters[i];

	if (reg.name)
	  printf ("CORE: 0x%04x %s %s\n", reg.number,
		  ExtReadWrite_image (reg.rw),
		  reg.name);
    }

    for (i = 0; i < NUM_EXT_COND; i++)
	if (arc_extension_map.condCodes[i])
	    printf ("COND: %s\n", arc_extension_map.condCodes[i]);
}

/* For a given extension instruction generate the equivalent arc
   opcode structure.  */

struct arc_opcode *
arcExtMap_genOpcode (const extInstruction_t *einsn,
		     unsigned arc_target,
		     const char **errmsg)
{
  struct arc_opcode *q, *arc_ext_opcodes = NULL;
  const unsigned char *lflags_f;
  const unsigned char *lflags_ccf;
  int count;

  /* Check for the class to see how many instructions we generate.  */
  switch (einsn->flags & ARC_SYNTAX_MASK)
    {
    case ARC_SYNTAX_3OP:
      count = (einsn->modsyn & ARC_OP1_MUST_BE_IMM) ? 10 : 20;
      break;
    case ARC_SYNTAX_2OP:
      count = (einsn->flags & 0x10) ? 7 : 6;
      break;
    case ARC_SYNTAX_1OP:
      count = 3;
      break;
    case ARC_SYNTAX_NOP:
      count = 1;
      break;
    default:
      count = 0;
      break;
    }

  /* Allocate memory.  */
  arc_ext_opcodes = (struct arc_opcode *)
    xmalloc ((count + 1) * sizeof (*arc_ext_opcodes));

  if (arc_ext_opcodes == NULL)
    {
      *errmsg = "Virtual memory exhausted";
      return NULL;
    }

  /* Generate the patterns.  */
  q = arc_ext_opcodes;

  if (einsn->suffix)
    {
      lflags_f   = flags_none;
      lflags_ccf = flags_none;
    }
  else
    {
      lflags_f   = flags_f;
      lflags_ccf = flags_ccf;
    }

  if (einsn->suffix & ARC_SUFFIX_COND)
    lflags_ccf = flags_cc;
  if (einsn->suffix & ARC_SUFFIX_FLAG)
    {
      lflags_f   = flags_f;
      lflags_ccf = flags_f;
    }
  if (einsn->suffix & (ARC_SUFFIX_FLAG | ARC_SUFFIX_COND))
    lflags_ccf = flags_ccf;

  if (einsn->flags & ARC_SYNTAX_2OP
      && !(einsn->flags & 0x10))
    {
      /* Regular 2OP instruction.  */
      if (einsn->suffix & ARC_SUFFIX_COND)
	*errmsg = "Suffix SUFFIX_COND ignored";

      INSERT_XOP (q, einsn->name,
		  INSN2OP_BC (einsn->major, einsn->minor), MINSN2OP_BC,
		  arc_target, arg_32bit_rbrc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN2OP_0C (einsn->major, einsn->minor), MINSN2OP_0C,
		  arc_target, arg_32bit_zarc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN2OP_BU (einsn->major, einsn->minor), MINSN2OP_BU,
		  arc_target, arg_32bit_rbu6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN2OP_0U (einsn->major, einsn->minor), MINSN2OP_0U,
		  arc_target, arg_32bit_zau6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN2OP_BL (einsn->major, einsn->minor), MINSN2OP_BL,
		  arc_target, arg_32bit_rblimm, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN2OP_0L (einsn->major, einsn->minor), MINSN2OP_0L,
		  arc_target, arg_32bit_zalimm, lflags_f);
    }
  else if (einsn->flags & (0x10 | ARC_SYNTAX_2OP))
    {
      /* This is actually a 3OP pattern.  The first operand is
	 immplied and is set to zero.  */
      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BC (einsn->major, einsn->minor),  MINSN3OP_0BC,
		  arc_target, arg_32bit_rbrc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BU (einsn->major, einsn->minor),  MINSN3OP_0BU,
		  arc_target, arg_32bit_rbu6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BL (einsn->major, einsn->minor),  MINSN3OP_0BL,
		  arc_target, arg_32bit_rblimm, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LC (einsn->major, einsn->minor), MINSN3OP_C0LC,
		  arc_target, arg_32bit_limmrc, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LU (einsn->major, einsn->minor), MINSN3OP_C0LU,
		  arc_target, arg_32bit_limmu6, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LS (einsn->major, einsn->minor),  MINSN3OP_0LS,
		  arc_target, arg_32bit_limms12, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LL (einsn->major, einsn->minor), MINSN3OP_C0LL,
		  arc_target, arg_32bit_limmlimm, lflags_ccf);
    }
  else if (einsn->flags & ARC_SYNTAX_3OP
	   && !(einsn->modsyn & ARC_OP1_MUST_BE_IMM))
    {
      /* Regular 3OP instruction.  */
      INSERT_XOP (q, einsn->name,
		  INSN3OP_ABC (einsn->major, einsn->minor),  MINSN3OP_ABC,
		  arc_target, arg_32bit_rarbrc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BC (einsn->major, einsn->minor),  MINSN3OP_0BC,
		  arc_target, arg_32bit_zarbrc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_CBBC (einsn->major, einsn->minor), MINSN3OP_CBBC,
		  arc_target, arg_32bit_rbrbrc, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_ABU (einsn->major, einsn->minor),  MINSN3OP_ABU,
		  arc_target, arg_32bit_rarbu6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BU (einsn->major, einsn->minor),  MINSN3OP_0BU,
		  arc_target, arg_32bit_zarbu6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_CBBU (einsn->major, einsn->minor), MINSN3OP_CBBU,
		  arc_target, arg_32bit_rbrbu6, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_BBS (einsn->major, einsn->minor),  MINSN3OP_BBS,
		  arc_target, arg_32bit_rbrbs12, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_ALC (einsn->major, einsn->minor),  MINSN3OP_ALC,
		  arc_target, arg_32bit_ralimmrc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_ABL (einsn->major, einsn->minor),  MINSN3OP_ABL,
		  arc_target, arg_32bit_rarblimm, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LC (einsn->major, einsn->minor),  MINSN3OP_0LC,
		  arc_target, arg_32bit_zalimmrc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BL (einsn->major, einsn->minor),  MINSN3OP_0BL,
		  arc_target, arg_32bit_zarblimm, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LC (einsn->major, einsn->minor), MINSN3OP_C0LC,
		  arc_target, arg_32bit_zalimmrc, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_CBBL (einsn->major, einsn->minor), MINSN3OP_CBBL,
		  arc_target, arg_32bit_rbrblimm, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_ALU (einsn->major, einsn->minor),  MINSN3OP_ALU,
		  arc_target, arg_32bit_ralimmu6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LU (einsn->major, einsn->minor),  MINSN3OP_0LU,
		  arc_target, arg_32bit_zalimmu6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LU (einsn->major, einsn->minor), MINSN3OP_C0LU,
		  arc_target, arg_32bit_zalimmu6, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LS (einsn->major, einsn->minor),  MINSN3OP_0LS,
		  arc_target, arg_32bit_zalimms12, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_ALL (einsn->major, einsn->minor),  MINSN3OP_ALL,
		  arc_target, arg_32bit_ralimmlimm, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LL (einsn->major, einsn->minor),  MINSN3OP_0LL,
		  arc_target, arg_32bit_zalimmlimm, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LL (einsn->major, einsn->minor), MINSN3OP_C0LL,
		  arc_target, arg_32bit_zalimmlimm, lflags_ccf);
    }
  else if (einsn->flags & ARC_SYNTAX_3OP)
    {
      /* 3OP instruction which accepts only zero as first
	 argument.  */
      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BC (einsn->major, einsn->minor),  MINSN3OP_0BC,
		  arc_target, arg_32bit_zarbrc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BU (einsn->major, einsn->minor),  MINSN3OP_0BU,
		  arc_target, arg_32bit_zarbu6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LC (einsn->major, einsn->minor),  MINSN3OP_0LC,
		  arc_target, arg_32bit_zalimmrc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0BL (einsn->major, einsn->minor),  MINSN3OP_0BL,
		  arc_target, arg_32bit_zarblimm, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LC (einsn->major, einsn->minor), MINSN3OP_C0LC,
		  arc_target, arg_32bit_zalimmrc, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LU (einsn->major, einsn->minor),  MINSN3OP_0LU,
		  arc_target, arg_32bit_zalimmu6, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LU (einsn->major, einsn->minor), MINSN3OP_C0LU,
		  arc_target, arg_32bit_zalimmu6, lflags_ccf);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LS (einsn->major, einsn->minor),  MINSN3OP_0LS,
		  arc_target, arg_32bit_zalimms12, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_0LL (einsn->major, einsn->minor),  MINSN3OP_0LL,
		  arc_target, arg_32bit_zalimmlimm, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN3OP_C0LL (einsn->major, einsn->minor), MINSN3OP_C0LL,
		  arc_target, arg_32bit_zalimmlimm, lflags_ccf);
    }
  else if (einsn->flags & ARC_SYNTAX_1OP)
    {
      if (einsn->suffix & ARC_SUFFIX_COND)
	*errmsg = "Suffix SUFFIX_COND ignored";

      INSERT_XOP (q, einsn->name,
		  INSN2OP (einsn->major, 0x3F) | FIELDB (einsn->minor),
		  MINSN2OP_0C, arc_target, arg_32bit_rc, lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN2OP (einsn->major, 0x3F) | FIELDB (einsn->minor)
		  | (0x01 << 22), MINSN2OP_0U, arc_target, arg_32bit_u6,
		  lflags_f);

      INSERT_XOP (q, einsn->name,
		  INSN2OP (einsn->major, 0x3F) | FIELDB (einsn->minor)
		  | FIELDC (62), MINSN2OP_0L, arc_target, arg_32bit_limm,
		  lflags_f);

    }
  else if (einsn->flags & ARC_SYNTAX_NOP)
    {
      if (einsn->suffix & ARC_SUFFIX_COND)
	*errmsg = "Suffix SUFFIX_COND ignored";

      INSERT_XOP (q, einsn->name,
		  INSN2OP (einsn->major, 0x3F) | FIELDB (einsn->minor)
		  | (0x01 << 22), MINSN2OP_0L, arc_target, arg_none, lflags_f);
    }
  else
    {
      *errmsg = "Unknown syntax";
      return NULL;
    }

  /* End marker.  */
  memset (q, 0, sizeof (*arc_ext_opcodes));

  return arc_ext_opcodes;
}

/* Compatibility stubs for legacy arcompact-dis.c */
const char *
arc_aux_reg_name (int regnum)
{
  return arcExtMap_auxRegName (regnum);
}

const char *
arcExtMap_instName (int opcode, int minor, int *flags)
{
  const extInstruction_t *einsn = arcExtMap_insn (opcode, 0);
  if (einsn && flags) {
    *flags = einsn->flags;
  }
  return einsn ? einsn->name : NULL;
}
