/* ARC target-dependent stuff. Extension structure access functions
   Copyright 1995, 1997, 2000, 2001, 2004, 2005, 2009
   Free Software Foundation, Inc.

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
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */


#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "arc-ext.h"
#include "arc.h"
#include "libiberty.h"
#include "sysdep.h"


/******************************************************************************/
/*                                                                            */
/* Outline:                                                                   */
/*     This module provides support for extensions to the ARC processor       */
/*     architecture.                                                          */
/*                                                                            */
/******************************************************************************/


/* -------------------------------------------------------------------------- */
/*                               local constants                              */
/* -------------------------------------------------------------------------- */

#define FIRST_EXTENSION_CORE_REGISTER   32
#define LAST_EXTENSION_CORE_REGISTER    59
#define FIRST_EXTENSION_CONDITION_CODE  0x10
#define LAST_EXTENSION_CONDITION_CODE   0x1f

#define NUM_EXT_CORE      (LAST_EXTENSION_CORE_REGISTER  - FIRST_EXTENSION_CORE_REGISTER  + 1)
#define NUM_EXT_COND      (LAST_EXTENSION_CONDITION_CODE - FIRST_EXTENSION_CONDITION_CODE + 1)
#define INST_HASH_BITS    6
#define INST_HASH_SIZE    (1 << INST_HASH_BITS)
#define INST_HASH_MASK    (INST_HASH_SIZE - 1)


/* -------------------------------------------------------------------------- */
/*                               local types                                  */
/* -------------------------------------------------------------------------- */

/* these types define the information stored in the table */

struct ExtInstruction
{
  char                   major;
  char                   minor;
  char                   flags;
  char*                  name;
  struct ExtInstruction* next;
};

struct ExtAuxRegister
{
  long                   address;
  char*                  name;
  struct ExtAuxRegister* next;
};

struct ExtCoreRegister
{
  short             number;
  enum ExtReadWrite rw;
  char*             name;
};

struct arcExtMap
{
  struct ExtAuxRegister* auxRegisters;
  struct ExtInstruction* instructions[INST_HASH_SIZE];
  struct ExtCoreRegister coreRegisters[NUM_EXT_CORE];
  char*                  condCodes[NUM_EXT_COND];
};


/* -------------------------------------------------------------------------- */
/*                               local data                                   */
/* -------------------------------------------------------------------------- */

/* extension table */
static struct arcExtMap arc_extension_map;


/* -------------------------------------------------------------------------- */
/*                               local macros                                 */
/* -------------------------------------------------------------------------- */

/* a hash function used to map instructions into the table */
#define INST_HASH(MAJOR, MINOR)    ((((MAJOR) << 3) ^ (MINOR)) & INST_HASH_MASK)


/* -------------------------------------------------------------------------- */
/*                               local functions                              */
/* -------------------------------------------------------------------------- */

#if 0
static void create_map(unsigned char *block, unsigned long length)
{
  unsigned char *p = block;

//printf("building ext map...\n");

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
	     (value is p[2]<<24|p[3]<<16|p[4]<<8|p[5]) */

      /* the sequence of records is temrinated by an "empty" record */
      if (p[0] == 0)
	break;

//    printf("%d byte type %d record\n", p[0], p[1]);

      switch (p[1])
	{ /* type */
	case EXT_INSTRUCTION:
	  {
	    struct ExtInstruction  *insn = XNEW (struct ExtInstruction);
	    int                     major = p[2];
	    int                     minor = p[3];
	    struct ExtInstruction **bucket =
                   &arc_extension_map.instructions[INST_HASH (major, minor)];

	    insn->name  = strdup ((char *) (p+5));
	    insn->major = major;
	    insn->minor = minor;
	    insn->flags = p[4];
	    insn->next  = *bucket;
	    *bucket = insn;
	    break;
	  }

	case EXT_CORE_REGISTER:
	  {
	    unsigned char number = p[2];
	    char*         name   = (char *) p+3;

	    arc_extension_map.coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].number = number;
	    arc_extension_map.coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].rw     = REG_READWRITE;
	    arc_extension_map.coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].name   = strdup (name);
	    break;
	  }

	case EXT_LONG_CORE_REGISTER:
	  {
	    unsigned char     number = p[2];
	    char*             name   = (char *) p+7;
	    enum ExtReadWrite rw     = p[6];

	    arc_extension_map.coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].number = number;
	    arc_extension_map.coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].rw     = rw;
	    arc_extension_map.coreRegisters[number - FIRST_EXTENSION_CORE_REGISTER].name   = strdup (name);
	  }

	case EXT_COND_CODE:
	  {
	    char *cc_name = strdup ((char *) (p+3));

	    arc_extension_map.condCodes[p[2] - FIRST_EXTENSION_CONDITION_CODE] = cc_name;
	    break;
	  }

	case EXT_AUX_REGISTER:
	  {
	    /* trickier -- need to store linked list of these */
	    struct ExtAuxRegister *newAuxRegister = XNEW (struct ExtAuxRegister);
	    char *aux_name = strdup ((char *) (p+6));

	    newAuxRegister->name           = aux_name;
	    newAuxRegister->address        = p[2]<<24 | p[3]<<16 | p[4]<<8 | p[5];
	    newAuxRegister->next           = arc_extension_map.auxRegisters;
	    arc_extension_map.auxRegisters = newAuxRegister;
	    break;
	  }

	default:
//        printf("type %d extension record skipped\n", p[1]);
	  break;
	}

      p += p[0]; /* move on to next record */
    }

//printf("ext map built\n");
}


/* Free memory that has been allocated for the extensions. */
static void destroy_map(void)
{
  struct ExtAuxRegister *r;
  unsigned int           i;

  /* free auxiliary registers */
  r = arc_extension_map.auxRegisters;
  while (r)
    {
      /* N.B. after r has been freed, r->next is invalid! */
      struct ExtAuxRegister* next = r->next;

      free (r->name);
      free (r);
      r = next;
    }

  /*  free instructions */
  for (i = 0; i < INST_HASH_SIZE; i++)
    {
      struct ExtInstruction *insn = arc_extension_map.instructions[i];

      while (insn)
        {
          /* N.B. after insn has been freed, insn->next is invalid! */
          struct ExtInstruction *next = insn->next;

          free (insn->name);
          free (insn);
          insn = next;
        }
    }

  /* free core registers */
  for (i = 0; i < NUM_EXT_CORE; i++)
    {
      if (arc_extension_map.coreRegisters[i].name)
        free (arc_extension_map.coreRegisters[i].name);
    }

  /* free condition codes */
  for (i = 0; i < NUM_EXT_COND; i++)
    {
      if (arc_extension_map.condCodes[i])
        free (arc_extension_map.condCodes[i]);
    }

  memset (&arc_extension_map, 0, sizeof (arc_extension_map));
}
#endif


static const char* ExtReadWrite_image(enum ExtReadWrite val)
{
    switch (val)
    {
        case REG_INVALID  : return "INVALID";
        case REG_READ     : return "RO";
        case REG_WRITE    : return "WO";
        case REG_READWRITE: return "R/W";
        default           : return "???";
    }
}


/* -------------------------------------------------------------------------- */
/*                               externally visible functions                 */
/* -------------------------------------------------------------------------- */

/* Get the name of an extension instruction.  */

const char *
arcExtMap_instName (int opcode, int insn, int *flags)
{
  /* Here the following tasks need to be done.  First of all, the opcode
     stored in the Extension Map is the real opcode.  However, the subopcode
     stored in the instruction to be disassembled is mangled.  We pass (in
     minor opcode), the instruction word.  Here we will un-mangle it and get
     the real subopcode which we can look for in the Extension Map.  This
     function is used both for the ARCTangent and the ARCompact, so we would
     also need some sort of a way to distinguish between the two
     architectures.  This is because the ARCTangent does not do any of this
     mangling so we have no issues there.  */

  /* If P[22:23] is 0 or 2 then un-mangle using iiiiiI.  If it is 1 then use
     iiiiIi.  Now, if P is 3 then check M[5:5] and if it is 0 then un-mangle
     using iiiiiI else iiiiii.  */

  unsigned char minor;
  struct ExtInstruction *temp;

  if (*flags != E_ARC_MACH_A4) /* ARCompact extension instructions.  */
    {
      /* 16-bit instructions.  */
      if (0x08 <= opcode && opcode <= 0x0b)
	{
	  /* I - set but not used */
	  unsigned char /* I, */ b, c, i;

	  /* I = (insn & 0xf800) >> 11; */
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
	  /* P, M - set but not used */
	  unsigned char /* P, M, */ I, A, B;

	  /* P = (insn & 0x00c00000) >> 22; */
	  /* M = (insn & 0x00000020); */
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
    }
  else /* ARCTangent extension instructions.  */
    minor = insn;

  temp = arc_extension_map.instructions[INST_HASH (opcode, minor)];
  while (temp)
    {
      if ((temp->major == opcode) && (temp->minor == minor))
	{
	  *flags = temp->flags;
	  return temp->name;
	}
      temp = temp->next;
    }

  return NULL;
}


/* get the name of an extension core register */
const char *
arcExtMap_coreRegName (int regnum)
{
  if (regnum < FIRST_EXTENSION_CORE_REGISTER || regnum > LAST_EXTENSION_CORE_REGISTER)
    return NULL;
  return arc_extension_map.coreRegisters[regnum - FIRST_EXTENSION_CORE_REGISTER].name;
}


/* get the access mode of an extension core register */
enum ExtReadWrite
arcExtMap_coreReadWrite (int regnum)
{
  if (regnum < FIRST_EXTENSION_CORE_REGISTER || regnum > LAST_EXTENSION_CORE_REGISTER)
    return REG_INVALID;
  return arc_extension_map.coreRegisters[regnum - FIRST_EXTENSION_CORE_REGISTER].rw;
}


/* get the name of an extension condition code */
const char *
arcExtMap_condCodeName (int code)
{
  if (code < FIRST_EXTENSION_CONDITION_CODE || code > LAST_EXTENSION_CONDITION_CODE)
    return NULL;
  return arc_extension_map.condCodes[code - FIRST_EXTENSION_CONDITION_CODE];
}


/* Get the name of an extension auxiliary register.  */
const char *
arcExtMap_auxRegName (long address)
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


/* Load extensions described in .arcextmap and .gnu.linkonce.arcextmap.* ELF
   section.  */
void
build_ARC_extmap (void *text_bfd)
{
#if 0
  asection *sect;

  /* the map is built each time gdb loads an executable file - so free any
   * existing map, as the map defined by the new file may differ from the old
   */
  destroy_map();

  for (sect = text_bfd->sections; sect != NULL; sect = sect->next)
    if (!strncmp (sect->name,
                  ".gnu.linkonce.arcextmap.",
          sizeof (".gnu.linkonce.arcextmap.") - 1)
        || !strcmp (sect->name,".arcextmap"))
      {
        bfd_size_type  count  = bfd_get_section_size (sect);
        unsigned char* buffer = xmalloc (count);

        if (buffer)
          {
            if (bfd_get_section_contents (text_bfd, sect, buffer, 0, count))
              create_map(buffer, count);
            free (buffer);
          }
      }
#endif
}


void dump_ARC_extmap (void)
{
    struct ExtAuxRegister* r;
    int                    i;

    r = arc_extension_map.auxRegisters;

    while (r)
    {
        printf("AUX : %s %ld\n", r->name, r->address);
        r = r->next;
    }

    for (i = 0; i < INST_HASH_SIZE; i++)
    {
        struct ExtInstruction *insn;

        for (insn = arc_extension_map.instructions[i]; insn != NULL; insn = insn->next)
            printf("INST: %d %d %x %s\n", insn->major, insn->minor, insn->flags, insn->name);
    }

    for (i = 0; i < NUM_EXT_CORE; i++)
    {
        struct ExtCoreRegister reg = arc_extension_map.coreRegisters[i];

        if (reg.name)
            printf("CORE: %s %d %s\n", reg.name, reg.number, ExtReadWrite_image(reg.rw));
    }

    for (i = 0; i < NUM_EXT_COND; i++)
        if (arc_extension_map.condCodes[i])
            printf("COND: %s\n", arc_extension_map.condCodes[i]);
}

/******************************************************************************/
