/* Print instructions for the Texas TMS320C[34]X, for GDB and GNU Binutils.

   Copyright (C) 2002-2025 Free Software Foundation, Inc.

   Contributed by Michael P. Hayes (m.hayes@elec.canterbury.ac.nz)

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
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include <math.h>
#include <stdlib.h>
#include "libiberty.h"
// #include "disassemble.h"
#include "../../include/disas-asm.h"
#include "tic4x.h"

#define TIC4X_DEBUG 0

#define TIC4X_HASH_SIZE   11   /* 11 (bits) and above should give unique entries.  */
#define TIC4X_SPESOP_SIZE 8    /* Max 8. ops for special instructions.  */

typedef enum
{
  IMMED_SINT,
  IMMED_SUINT,
  IMMED_SFLOAT,
  IMMED_INT,
  IMMED_UINT,
  IMMED_FLOAT
}
immed_t;

typedef enum
{
  INDIRECT_SHORT,
  INDIRECT_LONG,
  INDIRECT_TIC4X
}
indirect_t;

static unsigned long tic4x_version = 0;
static unsigned int tic4x_dp = 0;
static tic4x_inst_t **optab = NULL;
static tic4x_inst_t **optab_special = NULL;
static const char *registernames[REG_TABLE_SIZE];

static int
tic4x_pc_offset (unsigned int op)
{
  /* Determine the PC offset for a C[34]x instruction.
     This could be simplified using some boolean algebra
     but at the expense of readability.  */
  switch (op >> 24)
    {
    case 0x60:	/* br */
    case 0x62:	/* call  (C4x) */
    case 0x64:	/* rptb  (C4x) */
      return 1;
    case 0x61: 	/* brd */
    case 0x63: 	/* laj */
    case 0x65:	/* rptbd (C4x) */
      return 3;
    case 0x66: 	/* swi */
    case 0x67:
      return 0;
    default:
      break;
    }

  switch ((op & 0xffe00000) >> 20)
    {
    case 0x6a0:	/* bB */
    case 0x720: /* callB */
    case 0x740: /* trapB */
      return 1;

    case 0x6a2: /* bBd */
    case 0x6a6: /* bBat */
    case 0x6aa: /* bBaf */
    case 0x722:	/* lajB */
    case 0x748: /* latB */
    case 0x798: /* rptbd */
      return 3;

    default:
      break;
    }

  switch ((op & 0xfe200000) >> 20)
    {
    case 0x6e0:	/* dbB */
      return 1;

    case 0x6e2:	/* dbBd */
      return 3;

    default:
      break;
    }

  return 0;
}

static int
tic4x_print_char (struct disassemble_info * info, char ch)
{
  if (info != NULL)
    (*info->fprintf_func) (info->stream, "%c", ch);
  return 1;
}

static int
tic4x_print_str (struct disassemble_info *info, const char *str)
{
  if (info != NULL)
    (*info->fprintf_func) (info->stream, "%s", str);
  return 1;
}

static int
tic4x_print_register (struct disassemble_info *info, unsigned long regno)
{
  unsigned int i;

  if (registernames[REG_R0] == NULL)
    {
      for (i = 0; i < tic3x_num_registers; i++)
	registernames[tic3x_registers[i].regno] = tic3x_registers[i].name;
      if (IS_CPU_TIC4X (tic4x_version))
	{
	  /* Add C4x additional registers, overwriting
	     any C3x registers if necessary.  */
	  for (i = 0; i < tic4x_num_registers; i++)
	    registernames[tic4x_registers[i].regno] = tic4x_registers[i].name;
	}
    }
  if (regno > (IS_CPU_TIC4X (tic4x_version) ? TIC4X_REG_MAX : TIC3X_REG_MAX))
    return 0;
  if (info != NULL)
    (*info->fprintf_func) (info->stream, "%s", registernames[regno]);
  return 1;
}

static int
tic4x_print_addr (struct disassemble_info *info, unsigned long addr)
{
  if (info != NULL)
    (*info->print_address_func)(addr, info);
  return 1;
}

static int
tic4x_print_relative (struct disassemble_info *info,
		      unsigned long pc,
		      long offset,
		      unsigned long opcode)
{
  return tic4x_print_addr (info, pc + offset + tic4x_pc_offset (opcode));
}

static int
tic4x_print_direct (struct disassemble_info *info, unsigned long arg)
{
  if (info != NULL)
    {
      (*info->fprintf_func) (info->stream, "@");
      tic4x_print_addr (info, arg + (tic4x_dp << 16));
    }
  return 1;
}
#if 0
/* FIXME: make the floating point stuff not rely on host
   floating point arithmetic.  */

static void
tic4x_print_ftoa (unsigned int val, FILE *stream, fprintf_ftype pfunc)
{
  int e;
  int s;
  int f;
  double num = 0.0;

  e = EXTRS (val, 31, 24);	/* Exponent.  */
  if (e != -128)
    {
      s = EXTRU (val, 23, 23);	/* Sign bit.  */
      f = EXTRU (val, 22, 0);	/* Mantissa.  */
      if (s)
	f += -2 * (1 << 23);
      else
	f += (1 << 23);
      num = f / (double)(1 << 23);
      num = ldexp (num, e);
    }
  (*pfunc)(stream, "%.9g", num);
}
#endif

static int
tic4x_print_immed (struct disassemble_info *info,
		   immed_t type,
		   unsigned long arg)
{
  int s;
  int f;
  int e;
  double num = 0.0;

  if (info == NULL)
    return 1;
  switch (type)
    {
    case IMMED_SINT:
    case IMMED_INT:
      (*info->fprintf_func) (info->stream, "%ld", (long) arg);
      break;

    case IMMED_SUINT:
    case IMMED_UINT:
      (*info->fprintf_func) (info->stream, "%lu", arg);
      break;

    case IMMED_SFLOAT:
      e = EXTRS (arg, 15, 12);
      if (e != -8)
	{
	  s = EXTRU (arg, 11, 11);
	  f = EXTRU (arg, 10, 0);
	  if (s)
	    f += -2 * (1 << 11);
	  else
	    f += (1 << 11);
	  num = f / (double)(1 << 11);
	  num = ldexp (num, e);
	}
      (*info->fprintf_func) (info->stream, "%f", num);
      break;
    case IMMED_FLOAT:
      e = EXTRS (arg, 31, 24);
      if (e != -128)
	{
	  s = EXTRU (arg, 23, 23);
	  f = EXTRU (arg, 22, 0);
	  if (s)
	    f += -2 * (1 << 23);
	  else
	    f += (1 << 23);
	  num = f / (double)(1 << 23);
	  num = ldexp (num, e);
	}
      (*info->fprintf_func) (info->stream, "%f", num);
      break;
    }
  return 1;
}

static int
tic4x_print_cond (struct disassemble_info *info, unsigned int cond)
{
  static tic4x_cond_t **condtable = NULL;
  unsigned int i;

  if (condtable == NULL)
    {
      condtable = xcalloc (32, sizeof (tic4x_cond_t *));
      for (i = 0; i < tic4x_num_conds; i++)
	condtable[tic4x_conds[i].cond] = (tic4x_cond_t *)(tic4x_conds + i);
    }
  if (cond > 31 || condtable[cond] == NULL)
    return 0;
  if (info != NULL)
    (*info->fprintf_func) (info->stream, "%s", condtable[cond]->name);
  return 1;
}

static int
tic4x_print_indirect (struct disassemble_info *info,
		      indirect_t type,
		      unsigned long arg)
{
  unsigned int aregno;
  unsigned int modn;
  unsigned int disp;
  const char *a;

  aregno = 0;
  modn = 0;
  disp = 1;
  switch(type)
    {
    case INDIRECT_TIC4X:		/* *+ARn(disp) */
      disp = EXTRU (arg, 7, 3);
      aregno = EXTRU (arg, 2, 0) + REG_AR0;
      modn = 0;
      break;
    case INDIRECT_SHORT:
      disp = 1;
      aregno = EXTRU (arg, 2, 0) + REG_AR0;
      modn = EXTRU (arg, 7, 3);
      break;
    case INDIRECT_LONG:
      disp = EXTRU (arg, 7, 0);
      aregno = EXTRU (arg, 10, 8) + REG_AR0;
      modn = EXTRU (arg, 15, 11);
      if (modn > 7 && disp != 0)
	return 0;
      break;
    default:
        (*info->fprintf_func)(info->stream, "# internal error: Unknown indirect type %d", type);
        return 0;
    }
  if (modn > TIC3X_MODN_MAX)
    return 0;
  a = tic4x_indirects[modn].name;
  while (*a)
    {
      switch (*a)
	{
	case 'a':
	  tic4x_print_register (info, aregno);
	  break;
	case 'd':
	  tic4x_print_immed (info, IMMED_UINT, disp);
	  break;
	case 'y':
	  tic4x_print_str (info, "ir0");
	  break;
	case 'z':
	  tic4x_print_str (info, "ir1");
	  break;
	default:
	  tic4x_print_char (info, *a);
	  break;
	}
      a++;
    }
  return 1;
}

static int
tic4x_print_op (struct disassemble_info *info,
		unsigned long instruction,
		tic4x_inst_t *p,
		unsigned long pc)
{
  int val;
  const char *s;
  const char *parallel = NULL;

  /* Print instruction name.  */
  s = p->name;
  while (*s && parallel == NULL)
    {
      switch (*s)
	{
	case 'B':
	  if (! tic4x_print_cond (info, EXTRU (instruction, 20, 16)))
	    return 0;
	  break;
	case 'C':
	  if (! tic4x_print_cond (info, EXTRU (instruction, 27, 23)))
	    return 0;
	  break;
	case '_':
	  parallel = s + 1;	/* Skip past `_' in name.  */
	  break;
	default:
	  tic4x_print_char (info, *s);
	  break;
	}
      s++;
    }

  /* Print arguments.  */
  s = p->args;
  if (*s)
    tic4x_print_char (info, ' ');

  while (*s)
    {
      switch (*s)
	{
	case '*': /* Indirect 0--15.  */
	  if (! tic4x_print_indirect (info, INDIRECT_LONG,
				      EXTRU (instruction, 15, 0)))
	    return 0;
	  break;

	case '#': /* Only used for ldp, ldpk.  */
	  tic4x_print_immed (info, IMMED_UINT, EXTRU (instruction, 15, 0));
	  break;

	case '@': /* Direct 0--15.  */
	  tic4x_print_direct (info, EXTRU (instruction, 15, 0));
	  break;

	case 'A': /* Address register 24--22.  */
	  if (! tic4x_print_register (info, EXTRU (instruction, 24, 22) +
				      REG_AR0))
	    return 0;
	  break;

	case 'B': /* 24-bit unsigned int immediate br(d)/call/rptb
		     address 0--23.  */
	  if (IS_CPU_TIC4X (tic4x_version))
	    tic4x_print_relative (info, pc, EXTRS (instruction, 23, 0),
				  p->opcode);
	  else
	    tic4x_print_addr (info, EXTRU (instruction, 23, 0));
	  break;

	case 'C': /* Indirect (short C4x) 0--7.  */
	  if (! IS_CPU_TIC4X (tic4x_version))
	    return 0;
	  if (! tic4x_print_indirect (info, INDIRECT_TIC4X,
				      EXTRU (instruction, 7, 0)))
	    return 0;
	  break;

	case 'D':
	  /* Cockup if get here...  */
	  break;

	case 'E': /* Register 0--7.  */
        case 'e':
	  if (! tic4x_print_register (info, EXTRU (instruction, 7, 0)))
	    return 0;
	  break;

	case 'F': /* 16-bit float immediate 0--15.  */
	  tic4x_print_immed (info, IMMED_SFLOAT,
			     EXTRU (instruction, 15, 0));
	  break;

        case 'i': /* Extended indirect 0--7.  */
          if (EXTRU (instruction, 7, 5) == 7)
            {
              if (!tic4x_print_register (info, EXTRU (instruction, 4, 0)))
                return 0;
              break;
            }
          /* Fallthrough */

	case 'I': /* Indirect (short) 0--7.  */
	  if (! tic4x_print_indirect (info, INDIRECT_SHORT,
				      EXTRU (instruction, 7, 0)))
	    return 0;
	  break;

        case 'j': /* Extended indirect 8--15 */
          if (EXTRU (instruction, 15, 13) == 7)
            {
              if (! tic4x_print_register (info, EXTRU (instruction, 12, 8)))
                return 0;
              break;
            }
	  /* Fall through.  */

	case 'J': /* Indirect (short) 8--15.  */
	  if (! tic4x_print_indirect (info, INDIRECT_SHORT,
				      EXTRU (instruction, 15, 8)))
	    return 0;
	  break;

	case 'G': /* Register 8--15.  */
        case 'g':
	  if (! tic4x_print_register (info, EXTRU (instruction, 15, 8)))
	    return 0;
	  break;

	case 'H': /* Register 16--18.  */
	  if (! tic4x_print_register (info, EXTRU (instruction, 18, 16)))
	    return 0;
	  break;

	case 'K': /* Register 19--21.  */
	  if (! tic4x_print_register (info, EXTRU (instruction, 21, 19)))
	    return 0;
	  break;

	case 'L': /* Register 22--24.  */
	  if (! tic4x_print_register (info, EXTRU (instruction, 24, 22)))
	    return 0;
	  break;

	case 'M': /* Register 22--22.  */
	  tic4x_print_register (info, EXTRU (instruction, 22, 22) + REG_R2);
	  break;

	case 'N': /* Register 23--23.  */
	  tic4x_print_register (info, EXTRU (instruction, 23, 23) + REG_R0);
	  break;

	case 'O': /* Indirect (short C4x) 8--15.  */
	  if (! IS_CPU_TIC4X (tic4x_version))
	    return 0;
	  if (! tic4x_print_indirect (info, INDIRECT_TIC4X,
				      EXTRU (instruction, 15, 8)))
	    return 0;
	  break;

	case 'P': /* Displacement 0--15 (used by Bcond and BcondD).  */
	  tic4x_print_relative (info, pc, EXTRS (instruction, 15, 0),
				p->opcode);
	  break;

	case 'Q': /* Register 0--15.  */
        case 'q':
	  if (! tic4x_print_register (info, EXTRU (instruction, 15, 0)))
	    return 0;
	  break;

	case 'R': /* Register 16--20.  */
        case 'r':
	  if (! tic4x_print_register (info, EXTRU (instruction, 20, 16)))
	    return 0;
	  break;

	case 'S': /* 16-bit signed immediate 0--15.  */
	  tic4x_print_immed (info, IMMED_SINT,
			     EXTRS (instruction, 15, 0));
	  break;

	case 'T': /* 5-bit signed immediate 16--20  (C4x stik).  */
	  if (! IS_CPU_TIC4X (tic4x_version))
	    return 0;
	  if (! tic4x_print_immed (info, IMMED_SUINT,
				   EXTRU (instruction, 20, 16)))
	    return 0;
	  break;

	case 'U': /* 16-bit unsigned int immediate 0--15.  */
	  tic4x_print_immed (info, IMMED_SUINT, EXTRU (instruction, 15, 0));
	  break;

	case 'V': /* 5/9-bit unsigned vector 0--4/8.  */
	  tic4x_print_immed (info, IMMED_SUINT,
			     IS_CPU_TIC4X (tic4x_version) ?
			     EXTRU (instruction, 8, 0) :
			     EXTRU (instruction, 4, 0) & ~0x20);
	  break;

	case 'W': /* 8-bit signed immediate 0--7.  */
	  if (! IS_CPU_TIC4X (tic4x_version))
	    return 0;
	  tic4x_print_immed (info, IMMED_SINT, EXTRS (instruction, 7, 0));
	  break;

	case 'X': /* Expansion register 4--0.  */
	  val = EXTRU (instruction, 4, 0) + REG_IVTP;
	  if (val < REG_IVTP || val > REG_TVTP)
	    return 0;
	  if (! tic4x_print_register (info, val))
	    return 0;
	  break;

	case 'Y': /* Address register 16--20.  */
	  val = EXTRU (instruction, 20, 16);
	  if (val < REG_AR0 || val > REG_SP)
	    return 0;
	  if (! tic4x_print_register (info, val))
	    return 0;
	  break;

	case 'Z': /* Expansion register 16--20.  */
	  val = EXTRU (instruction, 20, 16) + REG_IVTP;
	  if (val < REG_IVTP || val > REG_TVTP)
	    return 0;
	  if (! tic4x_print_register (info, val))
	    return 0;
	  break;

	case '|':	/* Parallel instruction.  */
	  tic4x_print_str (info, " || ");
	  tic4x_print_str (info, parallel);
	  tic4x_print_char (info, ' ');
	  break;

	case ';':
	  tic4x_print_char (info, ',');
	  break;

	default:
	  tic4x_print_char (info, *s);
	  break;
	}
      s++;
    }
  return 1;
}

static void
tic4x_hash_opcode_special (tic4x_inst_t **optable_special,
			   const tic4x_inst_t *inst)
{
  int i;

  for (i = 0;i < TIC4X_SPESOP_SIZE; i++)
    if (optable_special[i] != NULL
        && optable_special[i]->opcode == inst->opcode)
      {
        /* Collision (we have it already) - overwrite.  */
        optable_special[i] = (tic4x_inst_t *) inst;
        return;
      }

  for (i = 0; i < TIC4X_SPESOP_SIZE; i++)
    if (optable_special[i] == NULL)
      {
        /* Add the new opcode.  */
        optable_special[i] = (tic4x_inst_t *) inst;
        return;
      }

  /* This should never occur. This happens if the number of special
     instructions exceeds TIC4X_SPESOP_SIZE. Please increase the variable
     of this variable */
#if TIC4X_DEBUG
  printf ("optable_special[] is full, please increase TIC4X_SPESOP_SIZE!\n");
#endif
}

static void
tic4x_hash_opcode (tic4x_inst_t **optable,
		   tic4x_inst_t **optable_special,
		   const tic4x_inst_t *inst,
		   const unsigned long tic4x_oplevel)
{
  unsigned int j;
  unsigned int opcode = inst->opcode >> (32 - TIC4X_HASH_SIZE);
  unsigned int opmask = inst->opmask >> (32 - TIC4X_HASH_SIZE);

  /* Use a TIC4X_HASH_SIZE bit index as a hash index.  We should
     have unique entries so there's no point having a linked list
     for each entry?  */
  for (j = opcode; j < opmask; j++)
    if ((j & opmask) == opcode
         && inst->oplevel & tic4x_oplevel)
      {
#if TIC4X_DEBUG
	/* We should only have collisions for synonyms like
	   ldp for ldi.  */
	if (optable[j] != NULL)
	  printf ("Collision at index %d, %s and %s\n",
		  j, optable[j]->name, inst->name);
#endif
        /* Catch those ops that collide with others already inside the
           hash, and have a opmask greater than the one we use in the
           hash. Store them in a special-list, that will handle full
           32-bit INSN, not only the first 11-bit (or so). */
        if (optable[j] != NULL
	    && inst->opmask & ~(opmask << (32 - TIC4X_HASH_SIZE)))
          {
            /* Add the instruction already on the list.  */
            tic4x_hash_opcode_special (optable_special, optable[j]);

            /* Add the new instruction.  */
            tic4x_hash_opcode_special (optable_special, inst);
          }

        optable[j] = (tic4x_inst_t *) inst;
      }
}

/* Disassemble the instruction in 'instruction'.
   'pc' should be the address of this instruction, it will
   be used to print the target address if this is a relative jump or call
   the disassembled instruction is written to 'info'.
   The function returns the length of this instruction in words.  */

static int
tic4x_disassemble (unsigned long pc,
		   unsigned long instruction,
		   struct disassemble_info *info)
{
  tic4x_inst_t *p;
  int i;
  unsigned long tic4x_oplevel;

  if (tic4x_version != info->mach)
    {
      tic4x_version = info->mach;
      /* Don't stash anything from a previous call using a different
	 machine.  */
      free (optab);
      optab = NULL;
      free (optab_special);
      optab_special = NULL;
      registernames[REG_R0] = NULL;
    }

  tic4x_oplevel  = (IS_CPU_TIC4X (tic4x_version)) ? OP_C4X : 0;
  tic4x_oplevel |= OP_C3X | OP_LPWR | OP_IDLE2 | OP_ENH;

  if (optab == NULL)
    {
      optab = xcalloc ((1 << TIC4X_HASH_SIZE), sizeof (tic4x_inst_t *));

      optab_special = xcalloc (TIC4X_SPESOP_SIZE, sizeof (tic4x_inst_t *));

      /* Install opcodes in reverse order so that preferred
	 forms overwrite synonyms.  */
      for (i = tic4x_num_insts - 1; i >= 0; i--)
	tic4x_hash_opcode (optab, optab_special, &tic4x_insts[i],
			   tic4x_oplevel);

      /* We now need to remove the insn that are special from the
	 "normal" optable, to make the disasm search this extra list
	 for them.  */
      for (i = 0; i < TIC4X_SPESOP_SIZE; i++)
	if (optab_special[i] != NULL)
	  optab[optab_special[i]->opcode >> (32 - TIC4X_HASH_SIZE)] = NULL;
    }

  /* See if we can pick up any loading of the DP register...  */
  if ((instruction >> 16) == 0x5070 || (instruction >> 16) == 0x1f70)
    tic4x_dp = EXTRU (instruction, 15, 0);

  p = optab[instruction >> (32 - TIC4X_HASH_SIZE)];
  if (p != NULL)
    {
      if (((instruction & p->opmask) == p->opcode)
	  && tic4x_print_op (NULL, instruction, p, pc))
	tic4x_print_op (info, instruction, p, pc);
      else
	(*info->fprintf_func) (info->stream, "%08lx", instruction);
    }
  else
    {
      for (i = 0; i<TIC4X_SPESOP_SIZE; i++)
	if (optab_special[i] != NULL
	    && optab_special[i]->opcode == instruction)
	  {
	    (*info->fprintf_func)(info->stream, "%s", optab_special[i]->name);
	    break;
	  }
      if (i == TIC4X_SPESOP_SIZE)
	(*info->fprintf_func) (info->stream, "%08lx", instruction);
    }

  /* Return size of insn in words.  */
  return 1;
}

/* The entry point from objdump and gdb.  */
int
print_insn_tic4x (bfd_vma memaddr, struct disassemble_info *info)
{
  int status;
  unsigned long pc;
  unsigned long op;
  bfd_byte buffer[4];

  status = (*info->read_memory_func) (memaddr, buffer, 4, info);
  if (status != 0)
    {
      (*info->memory_error_func) (status, memaddr, info);
      return -1;
    }

  pc = memaddr;
  op = bfd_getl32 (buffer);
  info->bytes_per_line = 4;
  info->bytes_per_chunk = 4;
  info->octets_per_byte = 4;
  info->display_endian = BFD_ENDIAN_LITTLE;
  return tic4x_disassemble (pc, op, info) * 4;
}
