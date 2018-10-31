/*************************************************************************
 *                                                                       *
 * Print Lanai instructions.                                            *
 *                                                                       *
 * Copyright (c) 1994, 1995 by Myricom, Inc.                             *
 * All rights reserved.                                                  *
 *                                                                       *
 * This program is free software; you can redistribute it and/or modify  *
 * it under the terms of version 2 of the GNU General Public License     *
 * as published by the Free Software Foundation.  Myricom requests that  *
 * all modifications of this software be returned to Myricom, Inc. for   *
 * redistribution.  The name of Myricom, Inc. may not be used to endorse *
 * or promote products derived from this software without specific prior *
 * written permission.                                                   *
 *                                                                       *
 * Myricom, Inc. makes no representations about the suitability of this  *
 * software for any purpose.                                             *
 *                                                                       *
 * THIS FILE IS PROVIDED "AS-IS" WITHOUT WARRANTY OF ANY KIND, WHETHER   *
 * EXPRESSED OR IMPLIED, INCLUDING THE WARRANTY OF MERCHANTABILITY OR    *
 * FITNESS FOR A PARTICULAR PURPOSE.  MYRICOM, INC. SHALL HAVE NO        *
 * LIABILITY WITH RESPECT TO THE INFRINGEMENT OF COPYRIGHTS, TRADE       *
 * SECRETS OR ANY PATENTS BY THIS FILE OR ANY PART THEREOF.              *
 *                                                                       *
 * In no event will Myricom, Inc. be liable for any lost revenue         *
 * or profits or other special, indirect and consequential damages, even *
 * if Myricom has been advised of the possibility of such damages.       *
 *                                                                       *
 * Other copyrights might apply to parts of this software and are so     *
 * noted when applicable.                                                *
 *                                                                       *
 * Myricom, Inc.                    Email: info@myri.com                 *
 * 325 N. Santa Anita Ave.          World Wide Web: http://www.myri.com/ *
 * Arcadia, CA 91024                                                     *
 *************************************************************************/
 /* initial version released 5/95 */
 /* This file is based upon <> from the Gnu binutils-2.5.2 
    release, which had the following copyright notice: */

	/* Print SPARC instructions.
	   Copyright 1989, 1991, 1992, 1993 Free Software Foundation, Inc.

	This program is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; either version 2 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "ansidecl.h"
#include "opcode/lanai.h"
#include "disas-asm.h"

static  char *reg_names[] =
{ "r0", "r1", "pc", "ps", "sp", "fp", "r6", "r7",	
  "r8", "r9","r10","r11","r12","r13","r14","r15",	
 "r16","r17","r18","r19","r20","r21","r22","r23",
 "r24","r25","r26","r27","r28","r29","r30","r31",
};

static char *op_names[] = 
{ "add", "addc", "sub", "subb", "and", "or", "xor", "sh" };

/* Nonzero if INSN is the opcode for a delayed branch.  */
static int is_delayed_branch (unsigned long insn);

static int
is_delayed_branch (insn)
     unsigned long insn;
{
  int i;

  for (i = 0; i < NUMOPCODES; ++i)
    {
      CONST struct lanai_opcode *opcode = &lanai_opcodes[i];
      if ((opcode->match & insn) == opcode->match && (opcode->lose & insn) == 0) {
	      return (opcode->flags & F_BR);
      }
    }
  return 0;
}

static int opcodes_sorted = 0;
/* extern void qsort (); */
static int compare_opcodes (char *a, char *b);

/* Print one instruction from MEMADDR on INFO->STREAM.

   We suffix the instruction with a comment that gives the absolute
   address involved, as well as its symbolic form, if the instruction
   is preceded by a findable `sethi' and it either adds an immediate
   displacement to that register, or it is an `add' or `or' instruction
   on that register.  */
int
print_insn_lanai (memaddr, info)
     bfd_vma memaddr;
     disassemble_info *info;
{
  FILE *stream = info->stream;
  bfd_byte buffer[4];
  unsigned int insn;
  register int i;

  if (!opcodes_sorted)
    {
      qsort ((char *) lanai_opcodes, NUMOPCODES,
	     sizeof (lanai_opcodes[0]),
	     (int (*)(const void *,const void *))compare_opcodes);
      opcodes_sorted = 1;
    }

  {
    int status =
      (*info->read_memory_func) (memaddr, buffer, sizeof (buffer), info);
    if (status != 0)
      {
	(*info->memory_error_func) (status, memaddr, info);
	return -1;
      }
  }

  insn = bfd_getb32 (buffer);

  info->insn_info_valid = 1;			/* We do return this info */
  info->insn_type = dis_nonbranch;		/* Assume non branch insn */
  info->branch_delay_insns = 0;			/* Assume no delay */
  info->target = 0;				/* Assume no target known */

  for (i = 0; i < NUMOPCODES; ++i)
    {
      CONST struct lanai_opcode *opcode = &lanai_opcodes[i];
      if ((opcode->match & insn) == opcode->match
	  && (opcode->lose & insn) == 0)
	{
	  /* Nonzero means that we have found an instruction which has
	     the effect of adding or or'ing the imm13 field to rs1.  */
	  int imm_added_to_rs1 = 0;

	  /* Do we have an `add' or `or' immediate instruction where rs1 is 
	     the same as rd?  */

	  if (((!(opcode->match & 0x80000000)			/* RI insn */
		&& ( !(opcode->match & 0x70000000)		/* RI add */
		     || (opcode->match & 0x70000000) == 0x50000000 /* RI or */
		     ))
	       || ((opcode->match & 0xf0000000) == 0xc0000000	/* RR insn */
		   && ( !(opcode->match & 0x00000700)		/* RR add */
			|| (opcode->match & 0x00000700) == 0x00000500 /* RR or */ )))
	      && X_RS1(insn) == X_RD(insn))
	    {
	      imm_added_to_rs1 = 1;
	    }

#ifdef BAD
	  if (X_RS1 (insn) != X_RD (insn)
	      && strchr (opcode->args, 'r') != 0)
	      /* Can't do simple format if source and dest are different.  */
	      continue;
#endif

	  (*info->fprintf_func) (stream, "%s", opcode->name);

	  {
	    register CONST char *s;
	    unsigned int imm;

	    for (s = opcode->args; *s != '\0'; ++s)
	      {

		(*info->fprintf_func) (stream, " ");
			
		switch (*s)
		  {
		  /* By default, just print the character. */
		  default:
		    (*info->fprintf_func) (stream, "%c", *s);
		    break;

#define	reg(n)	(*info->fprintf_func) (stream, "%s", reg_names[n])
// #define	reg(n)	(*info->fprintf_func) (stream, "%%%s", reg_names[n])
		  case '1':
		    reg (X_RS1 (insn));
		    break;

		  case '2':
		    reg (X_RS2 (insn));
		    break;

		  case '3':
		    reg (X_RS3 (insn));
		    break;

		  case 'd':
		    reg (X_RD (insn));
		    break;
		
#undef	reg

		  case '4': /* Op1 (for RRR) */
		    (*info->fprintf_func) (stream, "%s", op_names[X_OP1(insn)]);
		    break;
		  case '5': /* Op2 (for RRR) */
		    (*info->fprintf_func) (stream, "%s", op_names[X_OP2(insn)]);
		    if (insn & L3_RRR_F) {
			    (*info->fprintf_func) (stream, ".f");
		    }
		    break;
		  case '6': /* Op2 (for RRM) */
		    (*info->fprintf_func) (stream, "%s", op_names[X_OP2(insn)]);
		    break;

		  case 'J':
		    imm = X_C16(insn)<<16;
		    goto print_immediate;
		  case 'j':
		    imm = X_C16(insn);
		    goto print_immediate;
		  case 'L':
		    imm = (X_C16(insn)<<16)|0xffff;
		    goto print_immediate;
		  case 'l':
		    imm = X_C16(insn)|0xffff0000;
		    goto print_immediate;
		  case 'k':
		    /* This should never happen */
		    (*info->fprintf_func) (stream, "***ERROR***");
			break;
		  case 'o':
		    imm = SEX (X_C16(insn), 16);
		    if (X_RS1 (insn) == 0) {
			    goto print_address;
		    }
		    goto print_immediate;
		  case 's':
		    imm = SEX (X_C16(insn), 16);
		    goto print_immediate;
		  case 'i':
		    imm = SEX (X_C10(insn), 10);
		    if (X_RS1 (insn) == 0) {
			    goto print_address;
		    }
		    goto print_immediate;
		  case 'I':
		    imm = X_C21(insn);
		    goto print_address;
		  case 'Y':
		    imm = X_C21(insn);
		    goto print_address;
		  case 'B':
		    imm = X_C25(insn);
		    goto print_address;
		  case 'b':
		    imm = SEX (X_C25(insn), 25);
		    goto print_address;

		  print_immediate:
		    (*info->fprintf_func) (stream, "0x%x", imm);
		    break;
		  print_address:
		    info->target = imm;
                    (*info->print_address_func) (imm, info);
		    break;

		  /* Named registers */

		  case 'P':
		    (*info->fprintf_func) (stream, "%%pc");
		    break;

		  case 'p':
		    (*info->fprintf_func) (stream, "%%ps");
		    break;

		  case 'Q':
		    (*info->fprintf_func) (stream, "%%apc");
		    break;

		  case 'q':
		    (*info->fprintf_func) (stream, "%%aps");
		    break;

		  case 'S':
		    (*info->fprintf_func) (stream, "%%isr");
		    break;

		  case 'M':
		    (*info->fprintf_func) (stream, "%%imr");
		    break;

		  case '!':
		    (*info->fprintf_func) (stream, "%%r1");
		    break;

		  case '0':
		    (*info->fprintf_func) (stream, "%%r0");
		    break;

		  }
	      }
	  }

	  /* If we are adding or or'ing something to rs1, then
	     check to see whether the previous instruction was
	     a mov to the same register as in the or.
	     If so, attempt to print the result of the add or
	     or (in this context add and or do the same thing)
	     and its symbolic value.  */
	  if (imm_added_to_rs1)
	    {
	      unsigned long prev_insn;
	      int errcode;

	      errcode =
		(*info->read_memory_func)
		  (memaddr - 4, buffer, sizeof (buffer), info);
	      prev_insn = bfd_getb32 (buffer);

	      if (errcode == 0)
		{
		  /* If it is a delayed branch, we need to look at the
		     instruction before the delayed branch.  This handles
		     sequences such as

		     mov %hi(_foo), %r4
		     call _printf
		     or %r4, %lo(_foo), %r4
		     */

		  if (is_delayed_branch (prev_insn))
		    {
		      errcode = (*info->read_memory_func)
			(memaddr - 8, buffer, sizeof (buffer), info);
		      prev_insn = bfd_getb32 (buffer);
		    }
		}

	      /* If there was a problem reading memory, then assume
		 the previous instruction was not sethi.  */
	      if (errcode == 0)
		{
		  /* Is it an "{and,or} %r0,0x????????,%rd" to the same reg  */
		  if (((prev_insn & 0xf07c0000) == 0x00000000
			|| (prev_insn & 0xf07c0000) == 0x50000000 )
		      && X_RD (prev_insn) == X_RS1 (insn)
		      && X_RD (prev_insn) )
		    {
		      (*info->fprintf_func) (stream, "\t! ");
		      info->target 
			 = X_C16(     insn) << (L3_RI_H&     insn ? 16 : 0);
		      if((prev_insn & 0xf07c0000) == 0x50000000 ){
		        info->target 
			  |= X_C16(prev_insn) << (L3_RI_H&prev_insn ? 16 : 0);
		      }else{
		        info->target 
			  += X_C16(prev_insn) << (L3_RI_H&prev_insn ? 16 : 0);
		      }
		      (*info->print_address_func) (info->target, info);
		      info->insn_type = dis_dref;
		      info->data_size = 4;  /* FIXME!!! */
		    }
		}
	    }

	  info->data_size = F_DATA_SIZE(opcode->flags);

	  if (opcode->flags & (F_UNBR|F_CONDBR|F_JSR))
	    {
		/* FIXME -- check is_annulled flag */
		if (opcode->flags & F_UNBR) {
			info->insn_type = dis_branch;
		} else if (opcode->flags & F_CONDBR) {
			info->insn_type = dis_condbranch;
		} else if (opcode->flags & F_JSR) {
			info->insn_type = dis_jsr;
		} else if (opcode->flags & F_BR) {
			info->branch_delay_insns = 1;
		}
	    }

	  return sizeof (buffer);
	}
    }

  info->insn_type = dis_noninsn;	/* Mark as non-valid instruction */
  (*info->fprintf_func) (stream, "%#8x", insn);
  return sizeof (buffer);
}

/* Compare opcodes A and B.  */

static int
compare_opcodes (a, b)
     char *a, *b;
{
  struct lanai_opcode *op0 = (struct lanai_opcode *) a;
  struct lanai_opcode *op1 = (struct lanai_opcode *) b;
  unsigned long int match0 = op0->match, match1 = op1->match;
  unsigned long int lose0 = op0->lose, lose1 = op1->lose;
  register unsigned int i;

  /* If a bit is set in both match and lose, there is something
     wrong with the opcode table.  */
  if (match0 & lose0)
    {
      fprintf (stderr, "Internal error:  bad lanai-opcode.h: \"%s\", %#.8lx, %#.8lx\n",
	       op0->name, match0, lose0);
      op0->lose &= ~op0->match;
      lose0 = op0->lose;
    }

  if (match1 & lose1)
    {
      fprintf (stderr, "Internal error: bad lanai-opcode.h: \"%s\", %#.8lx, %#.8lx\n",
	       op1->name, match1, lose1);
      op1->lose &= ~op1->match;
      lose1 = op1->lose;
    }

  /* Because the bits that are variable in one opcode are constant in
     another, it is important to order the opcodes in the right order.  */
  for (i = 0; i < 32; ++i)
    {
      unsigned long int x = 1 << i;
      int x0 = (match0 & x) != 0;
      int x1 = (match1 & x) != 0;

      if (x0 != x1) {
	      return x1 - x0;
      }
    }

  for (i = 0; i < 32; ++i)
    {
      unsigned long int x = 1 << i;
      int x0 = (lose0 & x) != 0;
      int x1 = (lose1 & x) != 0;

      if (x0 != x1) {
	      return x1 - x0;
      }
    }

  /* They are functionally equal.  So as long as the opcode table is
     valid, we can put whichever one first we want, on aesthetic grounds.  */

  /* Our first aesthetic ground is that aliases defer to real insns.  */
  {
    int alias_diff = (op0->flags & F_ALIAS) - (op1->flags & F_ALIAS);
    if (alias_diff != 0) {
	    /* Put the one that isn't an alias first.  */
	    return alias_diff;
    }
  }

  /* Except for aliases, two "identical" instructions had
     better have the same opcode.  This is a sanity check on the table.  */
  i = strcmp (op0->name, op1->name);
  if (i)
    {
      if (op0->flags & F_ALIAS) /* If they're both aliases, be arbitrary. */
	{
	  return i;
	}
      else
	{
	  fprintf (stderr,
		   "Internal error: bad lanai-opcode.h: \"%s\" == \"%s\"\n",
		   op0->name, op1->name);
	}
    }
  
  /* Fewer arguments are preferred.  */
  {
    int length_diff = strlen (op0->args) - strlen (op1->args);
    if (length_diff != 0) {
	    /* Put the one with fewer arguments first.  */
	    return length_diff;
    }
  }

  /* Put 1+i before i+1.  */
  {
    char *p0 = (char *) strchr(op0->args, '+');
    char *p1 = (char *) strchr(op1->args, '+');

    if (p0 && p1)
      {
	/* There is a plus in both operands.  Note that a plus
	   sign cannot be the first character in args,
	   so the following [-1]'s are valid.  */
	if (p0[-1] == 'i' && p1[1] == 'i') {
		/* op0 is i+1 and op1 is 1+i, so op1 goes first.  */
		return 1;
	}
	if (p0[1] == 'i' && p1[-1] == 'i') {
		/* op0 is 1+i and op1 is i+1, so op0 goes first.  */
		return -1;
	}
      }
  }

  /* They are, as far as we can tell, identical.
     Since qsort may have rearranged the table partially, there is
     no way to tell which one was first in the opcode table as
     written, so just say there are equal.  */
  return 0;
}
