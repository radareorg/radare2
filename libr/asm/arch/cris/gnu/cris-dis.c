/* Disassembler code for CRIS.
   Copyright 2000, 2001, 2002, 2004, 2005, 2006, 2007
   Free Software Foundation, Inc.
   Contributed by Axis Communications AB, Lund, Sweden.
   Written by Hans-Peter Nilsson.

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

#include <stdlib.h>
#include <string.h>
#include "dis-asm.h"
#include "sysdep.h"
#include "opcode/cris.h"
#include "libiberty.h"

/* No instruction will be disassembled longer than this.  In theory, and
   in silicon, address prefixes can be cascaded.  In practice, cascading
   is not used by GCC, and not supported by the assembler.  */
#ifndef MAX_BYTES_PER_CRIS_INSN
#define MAX_BYTES_PER_CRIS_INSN 8
#endif

/* Whether or not to decode prefixes, folding it into the following
   instruction.  FIXME: Make this optional later.  */
#ifndef PARSE_PREFIX
#define PARSE_PREFIX 1
#endif

/* Sometimes we prefix all registers with this character.  */
#define REGISTER_PREFIX_CHAR '$'

/* Whether or not to trace the following sequence:
   sub* X,r%d
   bound* Y,r%d
   adds.w [pc+r%d.w],pc

   This is the assembly form of a switch-statement in C.
   The "sub is optional.  If there is none, then X will be zero.
   X is the value of the first case,
   Y is the number of cases (including default).

   This results in case offsets printed on the form:
    case N: -> case_address
   where N is an estimation on the corresponding 'case' operand in C,
   and case_address is where execution of that case continues after the
   sequence presented above.

   The old style of output was to print the offsets as instructions,
   which made it hard to follow "case"-constructs in the disassembly,
   and caused a lot of annoying warnings about undefined instructions.

   FIXME: Make this optional later.  */
#ifndef TRACE_CASE
#define TRACE_CASE (disdata->trace_case)
#endif

enum cris_disass_family
 { cris_dis_v0_v10, cris_dis_common_v10_v32, cris_dis_v32 };

/* Stored in the disasm_info->private_data member.  */
struct cris_disasm_data
{
  /* Whether to print something less confusing if we find something
     matching a switch-construct.  */
  bfd_boolean trace_case;

  /* Whether this code is flagged as crisv32.  FIXME: Should be an enum
     that includes "compatible".  */
  enum cris_disass_family distype;
};

/* Value of first element in switch.  */
static long case_offset = 0;

/* How many more case-offsets to print.  */
static long case_offset_counter = 0;

/* Number of case offsets.  */
static long no_of_case_offsets = 0;

/* Candidate for next case_offset.  */
static long last_immediate = 0;

static int cris_constraint
  (const char *, unsigned, unsigned, struct cris_disasm_data *);

/* Parse disassembler options and store state in info.  FIXME: For the
   time being, we abuse static variables.  */

bfd_boolean
cris_parse_disassembler_options (disassemble_info *info,
				 enum cris_disass_family distype)
{
  struct cris_disasm_data *disdata;

  info->private_data = calloc (1, sizeof (struct cris_disasm_data));
  disdata = (struct cris_disasm_data *) info->private_data;
  if (disdata == NULL)
    return FALSE;

  /* Default true.  */
  disdata->trace_case
    = (info->disassembler_options == NULL
       || (strcmp (info->disassembler_options, "nocase") != 0));

  disdata->distype = distype;
  return TRUE;
}

static const struct cris_spec_reg *
spec_reg_info (unsigned int sreg, enum cris_disass_family distype)
{
  int i;

  for (i = 0; cris_spec_regs[i].name != NULL; i++)
    {
      if (cris_spec_regs[i].number == sreg)
	{
	  if (distype == cris_dis_v32)
	    switch (cris_spec_regs[i].applicable_version)
	      {
	      case cris_ver_warning:
	      case cris_ver_version_all:
	      case cris_ver_v3p:
	      case cris_ver_v8p:
	      case cris_ver_v10p:
	      case cris_ver_v32p:
		/* No ambiguous sizes or register names with CRISv32.  */
		if (cris_spec_regs[i].warning == NULL)
		  return &cris_spec_regs[i];
	      default:
		;
	      }
	  else if (cris_spec_regs[i].applicable_version != cris_ver_v32p)
	    return &cris_spec_regs[i];
	}
    }

  return NULL;
}

/* Return the number of bits in the argument.  */

static int
number_of_bits (unsigned int val)
{
  int bits;

  for (bits = 0; val != 0; val &= val - 1)
    bits++;

  return bits;
}

/* Get an entry in the opcode-table.  */

static const struct cris_opcode *
get_opcode_entry (unsigned int insn,
		  unsigned int prefix_insn,
		  struct cris_disasm_data *disdata)
{
  /* For non-prefixed insns, we keep a table of pointers, indexed by the
     insn code.  Each entry is initialized when found to be NULL.  */
  static const struct cris_opcode **opc_table = NULL;

  const struct cris_opcode *max_matchedp = NULL;
  const struct cris_opcode **prefix_opc_table = NULL;

  /* We hold a table for each prefix that need to be handled differently.  */
  static const struct cris_opcode **dip_prefixes = NULL;
  static const struct cris_opcode **bdapq_m1_prefixes = NULL;
  static const struct cris_opcode **bdapq_m2_prefixes = NULL;
  static const struct cris_opcode **bdapq_m4_prefixes = NULL;
  static const struct cris_opcode **rest_prefixes = NULL;

  /* Allocate and clear the opcode-table.  */
  if (opc_table == NULL)
    {
      opc_table = malloc (65536 * sizeof (opc_table[0]));
      if (opc_table == NULL)
	return NULL;

      memset (opc_table, 0, 65536 * sizeof (const struct cris_opcode *));

      dip_prefixes
	= malloc (65536 * sizeof (const struct cris_opcode **));
      if (dip_prefixes == NULL)
	return NULL;

      memset (dip_prefixes, 0, 65536 * sizeof (dip_prefixes[0]));

      bdapq_m1_prefixes
	= malloc (65536 * sizeof (const struct cris_opcode **));
      if (bdapq_m1_prefixes == NULL)
	return NULL;

      memset (bdapq_m1_prefixes, 0, 65536 * sizeof (bdapq_m1_prefixes[0]));

      bdapq_m2_prefixes
	= malloc (65536 * sizeof (const struct cris_opcode **));
      if (bdapq_m2_prefixes == NULL)
	return NULL;

      memset (bdapq_m2_prefixes, 0, 65536 * sizeof (bdapq_m2_prefixes[0]));

      bdapq_m4_prefixes
	= malloc (65536 * sizeof (const struct cris_opcode **));
      if (bdapq_m4_prefixes == NULL)
	return NULL;

      memset (bdapq_m4_prefixes, 0, 65536 * sizeof (bdapq_m4_prefixes[0]));

      rest_prefixes
	= malloc (65536 * sizeof (const struct cris_opcode **));
      if (rest_prefixes == NULL)
	return NULL;

      memset (rest_prefixes, 0, 65536 * sizeof (rest_prefixes[0]));
    }

  /* Get the right table if this is a prefix.
     This code is connected to cris_constraints in that it knows what
     prefixes play a role in recognition of patterns; the necessary
     state is reflected by which table is used.  If constraints
     involving match or non-match of prefix insns are changed, then this
     probably needs changing too.  */
  if (prefix_insn != NO_CRIS_PREFIX)
    {
      const struct cris_opcode *popcodep
	= (opc_table[prefix_insn] != NULL
	   ? opc_table[prefix_insn]
	   : get_opcode_entry (prefix_insn, NO_CRIS_PREFIX, disdata));

      if (popcodep == NULL)
	return NULL;

      if (popcodep->match == BDAP_QUICK_OPCODE)
	{
	  /* Since some offsets are recognized with "push" macros, we
	     have to have different tables for them.  */
	  int offset = (prefix_insn & 255);

	  if (offset > 127)
	    offset -= 256;

	  switch (offset)
	    {
	    case -4:
	      prefix_opc_table = bdapq_m4_prefixes;
	      break;

	    case -2:
	      prefix_opc_table = bdapq_m2_prefixes;
	      break;

	    case -1:
	      prefix_opc_table = bdapq_m1_prefixes;
	      break;

	    default:
	      prefix_opc_table = rest_prefixes;
	      break;
	    }
	}
      else if (popcodep->match == DIP_OPCODE)
	/* We don't allow postincrement when the prefix is DIP, so use a
	   different table for DIP.  */
	prefix_opc_table = dip_prefixes;
      else
	prefix_opc_table = rest_prefixes;
    }

  if (prefix_insn != NO_CRIS_PREFIX
      && prefix_opc_table[insn] != NULL)
    max_matchedp = prefix_opc_table[insn];
  else if (prefix_insn == NO_CRIS_PREFIX && opc_table[insn] != NULL)
    max_matchedp = opc_table[insn];
  else
    {
      const struct cris_opcode *opcodep;
      int max_level_of_match = -1;

      for (opcodep = cris_opcodes;
	   opcodep->name != NULL;
	   opcodep++)
	{
	  int level_of_match;

	  if (disdata->distype == cris_dis_v32)
	    {
	      switch (opcodep->applicable_version)
		{
		case cris_ver_version_all:
		  break;

		case cris_ver_v0_3:
		case cris_ver_v0_10:
		case cris_ver_v3_10:
		case cris_ver_sim_v0_10:
		case cris_ver_v8_10:
		case cris_ver_v10:
		case cris_ver_warning:
		  continue;

		case cris_ver_v3p:
		case cris_ver_v8p:
		case cris_ver_v10p:
		case cris_ver_v32p:
		  break;

		case cris_ver_v8:
		  abort ();
		default:
		  abort ();
		}
	    }
	  else
	    {
	      switch (opcodep->applicable_version)
		{
		case cris_ver_version_all:
		case cris_ver_v0_3:
		case cris_ver_v3p:
		case cris_ver_v0_10:
		case cris_ver_v8p:
		case cris_ver_v8_10:
		case cris_ver_v10:
		case cris_ver_sim_v0_10:
		case cris_ver_v10p:
		case cris_ver_warning:
		  break;

		case cris_ver_v32p:
		  continue;

		case cris_ver_v8:
		  abort ();
		default:
		  abort ();
		}
	    }

	  /* We give a double lead for bits matching the template in
	     cris_opcodes.  Not even, because then "move p8,r10" would
	     be given 2 bits lead over "clear.d r10".  When there's a
	     tie, the first entry in the table wins.  This is
	     deliberate, to avoid a more complicated recognition
	     formula.  */
	  if ((opcodep->match & insn) == opcodep->match
	      && (opcodep->lose & insn) == 0
	      && ((level_of_match
		   = cris_constraint (opcodep->args,
				      insn,
				      prefix_insn,
				      disdata))
		  >= 0)
	      && ((level_of_match
		   += 2 * number_of_bits (opcodep->match
					  | opcodep->lose))
			  > max_level_of_match))
		    {
		      max_matchedp = opcodep;
		      max_level_of_match = level_of_match;

		      /* If there was a full match, never mind looking
			 further.  */
		      if (level_of_match >= 2 * 16)
			break;
		    }
		}
      /* Fill in the new entry.

	 If there are changes to the opcode-table involving prefixes, and
	 disassembly then does not work correctly, try removing the
	 else-clause below that fills in the prefix-table.  If that
	 helps, you need to change the prefix_opc_table setting above, or
	 something related.  */
      if (prefix_insn == NO_CRIS_PREFIX)
	opc_table[insn] = max_matchedp;
      else
	prefix_opc_table[insn] = max_matchedp;
    }

  return max_matchedp;
}

/* Return -1 if the constraints of a bitwise-matched instruction say
   that there is no match.  Otherwise return a nonnegative number
   indicating the confidence in the match (higher is better).  */

static int
cris_constraint (const char *cs,
		 unsigned int insn,
		 unsigned int prefix_insn,
		 struct cris_disasm_data *disdata)
{
  int retval = 0;
  int tmp;
  int prefix_ok = 0;
  const char *s;

  for (s = cs; *s; s++)
    switch (*s)
      {
      case '!':
	/* Do not recognize "pop" if there's a prefix and then only for
           v0..v10.  */
	if (prefix_insn != NO_CRIS_PREFIX
	    || disdata->distype != cris_dis_v0_v10)
	  return -1;
	break;

      case 'U':
	/* Not recognized at disassembly.  */
	return -1;

      case 'M':
	/* Size modifier for "clear", i.e. special register 0, 4 or 8.
	   Check that it is one of them.  Only special register 12 could
	   be mismatched, but checking for matches is more logical than
	   checking for mismatches when there are only a few cases.  */
	tmp = ((insn >> 12) & 0xf);
	if (tmp != 0 && tmp != 4 && tmp != 8)
	  return -1;
	break;

      case 'm':
	if ((insn & 0x30) == 0x30)
	  return -1;
	break;

      case 'S':
	/* A prefix operand without side-effect.  */
	if (prefix_insn != NO_CRIS_PREFIX && (insn & 0x400) == 0)
	  {
	    prefix_ok = 1;
	    break;
	  }
	else
	  return -1;

      case 's':
      case 'y':
      case 'Y':
	/* If this is a prefixed insn with postincrement (side-effect),
	   the prefix must not be DIP.  */
	if (prefix_insn != NO_CRIS_PREFIX)
	  {
	    if (insn & 0x400)
	      {
		const struct cris_opcode *prefix_opcodep
		  = get_opcode_entry (prefix_insn, NO_CRIS_PREFIX, disdata);

		if (prefix_opcodep->match == DIP_OPCODE)
		  return -1;
	      }

	    prefix_ok = 1;
	  }
	break;

      case 'B':
	/* If we don't fall through, then the prefix is ok.  */
	prefix_ok = 1;

	/* A "push" prefix.  Check for valid "push" size.
	   In case of special register, it may be != 4.  */
	if (prefix_insn != NO_CRIS_PREFIX)
	  {
	    /* Match the prefix insn to BDAPQ.  */
	    const struct cris_opcode *prefix_opcodep
	      = get_opcode_entry (prefix_insn, NO_CRIS_PREFIX, disdata);

	    if (prefix_opcodep->match == BDAP_QUICK_OPCODE)
	      {
		int pushsize = (prefix_insn & 255);

		if (pushsize > 127)
		  pushsize -= 256;

		if (s[1] == 'P')
		  {
		    unsigned int spec_reg = (insn >> 12) & 15;
		    const struct cris_spec_reg *sregp
		      = spec_reg_info (spec_reg, disdata->distype);

		    /* For a special-register, the "prefix size" must
		       match the size of the register.  */
		    if (sregp && sregp->reg_size == (unsigned int) -pushsize)
		      break;
		  }
		else if (s[1] == 'R')
		  {
		    if ((insn & 0x30) == 0x20 && pushsize == -4)
		      break;
		  }
		/* FIXME:  Should abort here; next constraint letter
		   *must* be 'P' or 'R'.  */
	      }
	  }
	return -1;

      case 'D':
	retval = (((insn >> 12) & 15) == (insn & 15));
	if (!retval)
	  return -1;
	else
	  retval += 4;
	break;

      case 'P':
	{
	  const struct cris_spec_reg *sregp
	    = spec_reg_info ((insn >> 12) & 15, disdata->distype);

	  /* Since we match four bits, we will give a value of 4-1 = 3
	     in a match.  If there is a corresponding exact match of a
	     special register in another pattern, it will get a value of
	     4, which will be higher.  This should be correct in that an
	     exact pattern would match better than a general pattern.

	     Note that there is a reason for not returning zero; the
	     pattern for "clear" is partly  matched in the bit-pattern
	     (the two lower bits must be zero), while the bit-pattern
	     for a move from a special register is matched in the
	     register constraint.  */

	  if (sregp != NULL)
	    {
	      retval += 3;
	      break;
	    }
	  else
	    return -1;
	}
      }

  if (prefix_insn != NO_CRIS_PREFIX && ! prefix_ok)
    return -1;

  return retval;
}

/* Format number as hex with a leading "0x" into outbuffer.  */

static char *
format_hex (unsigned long number,
	    char *outbuffer,
	    struct cris_disasm_data *disdata)
{
  /* Truncate negative numbers on >32-bit hosts.  */
  number &= 0xffffffff;

  sprintf (outbuffer, "0x%lx", number);

  /* Save this value for the "case" support.  */
  if (TRACE_CASE)
    last_immediate = number;

  return outbuffer + strlen (outbuffer);
}

/* Format number as decimal into outbuffer.  Parameter signedp says
   whether the number should be formatted as signed (!= 0) or
   unsigned (== 0).  */

static char *
format_dec (long number, char *outbuffer, int signedp)
{
  last_immediate = number;
  sprintf (outbuffer, signedp ? "%ld" : "%lu", number);

  return outbuffer + strlen (outbuffer);
}

/* Format the name of the general register regno into outbuffer.  */

static char *
format_reg (struct cris_disasm_data *disdata,
	    int regno,
	    char *outbuffer_start,
	    bfd_boolean with_reg_prefix)
{
  char *outbuffer = outbuffer_start;

  if (with_reg_prefix)
    *outbuffer++ = REGISTER_PREFIX_CHAR;

  switch (regno)
    {
    case 15:
      /* For v32, there is no context in which we output PC.  */
      if (disdata->distype == cris_dis_v32)
	strcpy (outbuffer, "acr");
      else
	strcpy (outbuffer, "pc");
      break;

    case 14:
      strcpy (outbuffer, "sp");
      break;

    default:
      sprintf (outbuffer, "r%d", regno);
      break;
    }

  return outbuffer_start + strlen (outbuffer_start);
}

/* Format the name of a support register into outbuffer.  */

static char *
format_sup_reg (unsigned int regno,
		char *outbuffer_start,
		bfd_boolean with_reg_prefix)
{
  char *outbuffer = outbuffer_start;
  int i;

  if (with_reg_prefix)
    *outbuffer++ = REGISTER_PREFIX_CHAR;

  for (i = 0; cris_support_regs[i].name != NULL; i++)
    if (cris_support_regs[i].number == regno)
      {
	sprintf (outbuffer, "%s", cris_support_regs[i].name);
	return outbuffer_start + strlen (outbuffer_start);
      }

  /* There's supposed to be register names covering all numbers, though
     some may be generic names.  */
  sprintf (outbuffer, "format_sup_reg-BUG");
  return outbuffer_start + strlen (outbuffer_start);
}

/* Return the length of an instruction.  */

static unsigned
bytes_to_skip (unsigned int insn,
	       const struct cris_opcode *matchedp,
	       enum cris_disass_family distype,
	       const struct cris_opcode *prefix_matchedp)
{
  /* Each insn is a word plus "immediate" operands.  */
  unsigned to_skip = 2;
  const char *template = matchedp->args;
  const char *s;

  for (s = template; *s; s++)
    if ((*s == 's' || *s == 'N' || *s == 'Y')
	&& (insn & 0x400) && (insn & 15) == 15
	&& prefix_matchedp == NULL)
      {
	/* Immediate via [pc+], so we have to check the size of the
	   operand.  */
	int mode_size = 1 << ((insn >> 4) & (*template == 'z' ? 1 : 3));

	if (matchedp->imm_oprnd_size == SIZE_FIX_32)
	  to_skip += 4;
	else if (matchedp->imm_oprnd_size == SIZE_SPEC_REG)
	  {
	    const struct cris_spec_reg *sregp
	      = spec_reg_info ((insn >> 12) & 15, distype);

	    /* FIXME: Improve error handling; should have been caught
	       earlier.  */
	    if (sregp == NULL)
	      return 2;

	    /* PC is incremented by two, not one, for a byte.  Except on
	       CRISv32, where constants are always DWORD-size for
	       special registers.  */
	    to_skip +=
	      distype == cris_dis_v32 ? 4 : (sregp->reg_size + 1) & ~1;
	  }
	else
	  to_skip += (mode_size + 1) & ~1;
      }
    else if (*s == 'n')
      to_skip += 4;
    else if (*s == 'b')
      to_skip += 2;

  return to_skip;
}

/* Print condition code flags.  */

static char *
print_flags (struct cris_disasm_data *disdata, unsigned int insn, char *cp)
{
  /* Use the v8 (Etrax 100) flag definitions for disassembly.
     The differences with v0 (Etrax 1..4) vs. Svinto are:
      v0 'd' <=> v8 'm'
      v0 'e' <=> v8 'b'.
     FIXME: Emit v0..v3 flag names somehow.  */
  static const char v8_fnames[] = "cvznxibm";
  static const char v32_fnames[] = "cvznxiup";
  const char *fnames
    = disdata->distype == cris_dis_v32 ? v32_fnames : v8_fnames;

  unsigned char flagbits = (((insn >> 8) & 0xf0) | (insn & 15));
  int i;

  for (i = 0; i < 8; i++)
    if (flagbits & (1 << i))
      *cp++ = fnames[i];

  return cp;
}

/* Print out an insn with its operands, and update the info->insn_type
   fields.  The prefix_opcodep and the rest hold a prefix insn that is
   supposed to be output as an address mode.  */

static void
print_with_operands (const struct cris_opcode *opcodep,
		     unsigned int insn,
		     unsigned char *buffer,
		     bfd_vma addr,
		     disassemble_info *info,
		     /* If a prefix insn was before this insn (and is supposed
			to be output as an address), here is a description of
			it.  */
		     const struct cris_opcode *prefix_opcodep,
		     unsigned int prefix_insn,
		     unsigned char *prefix_buffer,
		     bfd_boolean with_reg_prefix)
{
  /* Get a buffer of somewhat reasonable size where we store
     intermediate parts of the insn.  */
  char temp[sizeof (".d [$r13=$r12-2147483648],$r10") * 2];
  char *tp = temp;
  static const char mode_char[] = "bwd?";
  const char *s;
  const char *cs;
  struct cris_disasm_data *disdata
    = (struct cris_disasm_data *) info->private_data;

  /* Print out the name first thing we do.  */
  (*info->fprintf_func) (info->stream, "%s", opcodep->name);

  cs = opcodep->args;
  s = cs;

  /* Ignore any prefix indicator.  */
  if (*s == 'p')
    s++;

  if (*s == 'm' || *s == 'M' || *s == 'z')
    {
      *tp++ = '.';

      /* Get the size-letter.  */
      *tp++ = *s == 'M'
	? (insn & 0x8000 ? 'd'
	   : insn & 0x4000 ? 'w' : 'b')
	: mode_char[(insn >> 4) & (*s == 'z' ? 1 : 3)];

      /* Ignore the size and the space character that follows.  */
      s += 2;
    }

  /* Add a space if this isn't a long-branch, because for those will add
     the condition part of the name later.  */
  if (opcodep->match != (BRANCH_PC_LOW + BRANCH_INCR_HIGH * 256))
    *tp++ = ' ';

  /* Fill in the insn-type if deducible from the name (and there's no
     better way).  */
  if (opcodep->name[0] == 'j')
    {
      if (CONST_STRNEQ (opcodep->name, "jsr"))
	/* It's "jsr" or "jsrc".  */
	info->insn_type = dis_jsr;
      else
	/* Any other jump-type insn is considered a branch.  */
	info->insn_type = dis_branch;
    }

  /* We might know some more fields right now.  */
  info->branch_delay_insns = opcodep->delayed;

  /* Handle operands.  */
  for (; *s; s++)
    {
    switch (*s)
      {
      case 'T':
	tp = format_sup_reg ((insn >> 12) & 15, tp, with_reg_prefix);
	break;

      case 'A':
	if (with_reg_prefix)
	  *tp++ = REGISTER_PREFIX_CHAR;
	*tp++ = 'a';
	*tp++ = 'c';
	*tp++ = 'r';
	break;
	
      case '[':
      case ']':
      case ',':
	*tp++ = *s;
	*tp++ = ' ';
	break;

      case '!':
	/* Ignore at this point; used at earlier stages to avoid
	   recognition if there's a prefix at something that in other
	   ways looks like a "pop".  */
	break;

      case 'd':
	/* Ignore.  This is an optional ".d " on the large one of
	   relaxable insns.  */
	break;

      case 'B':
	/* This was the prefix that made this a "push".  We've already
	   handled it by recognizing it, so signal that the prefix is
	   handled by setting it to NULL.  */
	prefix_opcodep = NULL;
	break;

      case 'D':
      case 'r':
	tp = format_reg (disdata, insn & 15, tp, with_reg_prefix);
	break;

      case 'R':
	tp = format_reg (disdata, (insn >> 12) & 15, tp, with_reg_prefix);
	break;

      case 'n':
	{
	  /* Like N but pc-relative to the start of the insn.  */
	  unsigned long number
	    = (buffer[2] + buffer[3] * 256 + buffer[4] * 65536
	       + buffer[5] * 0x1000000 + addr);

	  /* Finish off and output previous formatted bytes.  */
	  *tp = 0;
	  if (temp[0])
	    (*info->fprintf_func) (info->stream, "%s", temp);
	  tp = temp;

	  (*info->print_address_func) ((bfd_vma) number, info);
	}
	break;

      case 'u':
	{
	  /* Like n but the offset is bits <3:0> in the instruction.  */
	  unsigned long number = (buffer[0] & 0xf) * 2 + addr;

	  /* Finish off and output previous formatted bytes.  */
	  *tp = 0;
	  if (temp[0])
	    (*info->fprintf_func) (info->stream, "%s", temp);
	  tp = temp;

	  (*info->print_address_func) ((bfd_vma) number, info);
	}
	break;

      case 'N':
      case 'y':
      case 'Y':
      case 'S':
      case 's':
	/* Any "normal" memory operand.  */
	if ((insn & 0x400) && (insn & 15) == 15 && prefix_opcodep == NULL)
	  {
	    /* We're looking at [pc+], i.e. we need to output an immediate
	       number, where the size can depend on different things.  */
	    long number;
	    int signedp
	      = ((*cs == 'z' && (insn & 0x20))
		 || opcodep->match == BDAP_QUICK_OPCODE);
	    int nbytes;

	    if (opcodep->imm_oprnd_size == SIZE_FIX_32)
	      nbytes = 4;
	    else if (opcodep->imm_oprnd_size == SIZE_SPEC_REG)
	      {
		const struct cris_spec_reg *sregp
		  = spec_reg_info ((insn >> 12) & 15, disdata->distype);

		/* A NULL return should have been as a non-match earlier,
		   so catch it as an internal error in the error-case
		   below.  */
		if (sregp == NULL)
		  /* Whatever non-valid size.  */
		  nbytes = 42;
		else
		  /* PC is always incremented by a multiple of two.
		     For CRISv32, immediates are always 4 bytes for
		     special registers.  */
		  nbytes = disdata->distype == cris_dis_v32
		    ? 4 : (sregp->reg_size + 1) & ~1;
	      }
	    else
	      {
		int mode_size = 1 << ((insn >> 4) & (*cs == 'z' ? 1 : 3));

		if (mode_size == 1)
		  nbytes = 2;
		else
		  nbytes = mode_size;
	      }

	    switch (nbytes)
	      {
	      case 1:
		number = buffer[2];
		if (signedp && number > 127)
		  number -= 256;
		break;

	      case 2:
		number = buffer[2] + buffer[3] * 256;
		if (signedp && number > 32767)
		  number -= 65536;
		break;

	      case 4:
		number
		  = buffer[2] + buffer[3] * 256 + buffer[4] * 65536
		  + buffer[5] * 0x1000000;
		break;

	      default:
		strcpy (tp, "bug");
		tp += 3;
		number = 42;
	      }

	    if ((*cs == 'z' && (insn & 0x20))
		|| (opcodep->match == BDAP_QUICK_OPCODE
		    && (nbytes <= 2 || buffer[1 + nbytes] == 0)))
	      tp = format_dec (number, tp, signedp);
	    else
	      {
		unsigned int highbyte = (number >> 24) & 0xff;

		/* Either output this as an address or as a number.  If it's
		   a dword with the same high-byte as the address of the
		   insn, assume it's an address, and also if it's a non-zero
		   non-0xff high-byte.  If this is a jsr or a jump, then
		   it's definitely an address.  */
		if (nbytes == 4
		    && (highbyte == ((addr >> 24) & 0xff)
			|| (highbyte != 0 && highbyte != 0xff)
			|| info->insn_type == dis_branch
			|| info->insn_type == dis_jsr))
		  {
		    /* Finish off and output previous formatted bytes.  */
		    *tp = 0;
		    tp = temp;
		    if (temp[0])
		      (*info->fprintf_func) (info->stream, "%s", temp);

		    (*info->print_address_func) ((bfd_vma) number, info);

		    info->target = number;
		  }
		else
		  tp = format_hex (number, tp, disdata);
	      }
	  }
	else
	  {
	    /* Not an immediate number.  Then this is a (possibly
	       prefixed) memory operand.  */
	    if (info->insn_type != dis_nonbranch)
	      {
		int mode_size
		  = 1 << ((insn >> 4)
			  & (opcodep->args[0] == 'z' ? 1 : 3));
		int size;
		info->insn_type = dis_dref;
		info->flags |= CRIS_DIS_FLAG_MEMREF;

		if (opcodep->imm_oprnd_size == SIZE_FIX_32)
		  size = 4;
		else if (opcodep->imm_oprnd_size == SIZE_SPEC_REG)
		  {
		    const struct cris_spec_reg *sregp
		      = spec_reg_info ((insn >> 12) & 15, disdata->distype);

		    /* FIXME: Improve error handling; should have been caught
		       earlier.  */
		    if (sregp == NULL)
		      size = 4;
		    else
		      size = sregp->reg_size;
		  }
		else
		  size = mode_size;

		info->data_size = size;
	      }

	    *tp++ = '[';

	    if (prefix_opcodep
		/* We don't match dip with a postincremented field
		   as a side-effect address mode.  */
		&& ((insn & 0x400) == 0
		    || prefix_opcodep->match != DIP_OPCODE))
	      {
		if (insn & 0x400)
		  {
		    tp = format_reg (disdata, insn & 15, tp, with_reg_prefix);
		    *tp++ = '=';
		  }


		/* We mainly ignore the prefix format string when the
		   address-mode syntax is output.  */
		switch (prefix_opcodep->match)
		  {
		  case DIP_OPCODE:
		    /* It's [r], [r+] or [pc+].  */
		    if ((prefix_insn & 0x400) && (prefix_insn & 15) == 15)
		      {
			/* It's [pc+].  This cannot possibly be anything
			   but an address.  */
			unsigned long number
			  = prefix_buffer[2] + prefix_buffer[3] * 256
			  + prefix_buffer[4] * 65536
			  + prefix_buffer[5] * 0x1000000;

			info->target = (bfd_vma) number;

			/* Finish off and output previous formatted
			   data.  */
			*tp = 0;
			tp = temp;
			if (temp[0])
			  (*info->fprintf_func) (info->stream, "%s", temp);

			(*info->print_address_func) ((bfd_vma) number, info);
		      }
		    else
		      {
			/* For a memref in an address, we use target2.
			   In this case, target is zero.  */
			info->flags
			  |= (CRIS_DIS_FLAG_MEM_TARGET2_IS_REG
			      | CRIS_DIS_FLAG_MEM_TARGET2_MEM);

			info->target2 = prefix_insn & 15;

			*tp++ = '[';
			tp = format_reg (disdata, prefix_insn & 15, tp,
					 with_reg_prefix);
			if (prefix_insn & 0x400)
			  *tp++ = '+';
			*tp++ = ']';
		      }
		    break;

		  case BDAP_QUICK_OPCODE:
		    {
		      int number;

		      number = prefix_buffer[0];
		      if (number > 127)
			number -= 256;

		      /* Output "reg+num" or, if num < 0, "reg-num".  */
		      tp = format_reg (disdata, (prefix_insn >> 12) & 15, tp,
				       with_reg_prefix);
		      if (number >= 0)
			*tp++ = '+';
		      tp = format_dec (number, tp, 1);

		      info->flags |= CRIS_DIS_FLAG_MEM_TARGET_IS_REG;
		      info->target = (prefix_insn >> 12) & 15;
		      info->target2 = (bfd_vma) number;
		      break;
		    }

		  case BIAP_OPCODE:
		    /* Output "r+R.m".  */
		    tp = format_reg (disdata, prefix_insn & 15, tp,
				     with_reg_prefix);
		    *tp++ = '+';
		    tp = format_reg (disdata, (prefix_insn >> 12) & 15, tp,
				     with_reg_prefix);
		    *tp++ = '.';
		    *tp++ = mode_char[(prefix_insn >> 4) & 3];

		    info->flags
		      |= (CRIS_DIS_FLAG_MEM_TARGET2_IS_REG
			  | CRIS_DIS_FLAG_MEM_TARGET_IS_REG

			  | ((prefix_insn & 0x8000)
			     ? CRIS_DIS_FLAG_MEM_TARGET2_MULT4
			     : ((prefix_insn & 0x8000)
				? CRIS_DIS_FLAG_MEM_TARGET2_MULT2 : 0)));

		    /* Is it the casejump?  It's a "adds.w [pc+r%d.w],pc".  */
		    if (insn == 0xf83f && (prefix_insn & ~0xf000) == 0x55f)
		      /* Then start interpreting data as offsets.  */
		      case_offset_counter = no_of_case_offsets;
		    break;

		  case BDAP_INDIR_OPCODE:
		    /* Output "r+s.m", or, if "s" is [pc+], "r+s" or
		       "r-s".  */
		    tp = format_reg (disdata, (prefix_insn >> 12) & 15, tp,
				     with_reg_prefix);

		    if ((prefix_insn & 0x400) && (prefix_insn & 15) == 15)
		      {
			long number;
			unsigned int nbytes;

			/* It's a value.  Get its size.  */
			int mode_size = 1 << ((prefix_insn >> 4) & 3);

			if (mode_size == 1)
			  nbytes = 2;
			else
			  nbytes = mode_size;

			switch (nbytes)
			  {
			  case 1:
			    number = prefix_buffer[2];
			    if (number > 127)
			      number -= 256;
			    break;

			  case 2:
			    number = prefix_buffer[2] + prefix_buffer[3] * 256;
			    if (number > 32767)
			      number -= 65536;
			    break;

			  case 4:
			    number
			      = prefix_buffer[2] + prefix_buffer[3] * 256
			      + prefix_buffer[4] * 65536
			      + prefix_buffer[5] * 0x1000000;
			    break;

			  default:
			    strcpy (tp, "bug");
			    tp += 3;
			    number = 42;
			  }

			info->flags |= CRIS_DIS_FLAG_MEM_TARGET_IS_REG;
			info->target2 = (bfd_vma) number;

			/* If the size is dword, then assume it's an
			   address.  */
			if (nbytes == 4)
			  {
			    /* Finish off and output previous formatted
			       bytes.  */
			    *tp++ = '+';
			    *tp = 0;
			    tp = temp;
			    (*info->fprintf_func) (info->stream, "%s", temp);

			    (*info->print_address_func) ((bfd_vma) number, info);
			  }
			else
			  {
			    if (number >= 0)
			      *tp++ = '+';
			    tp = format_dec (number, tp, 1);
			  }
		      }
		    else
		      {
			/* Output "r+[R].m" or "r+[R+].m".  */
			*tp++ = '+';
			*tp++ = '[';
			tp = format_reg (disdata, prefix_insn & 15, tp,
					 with_reg_prefix);
			if (prefix_insn & 0x400)
			  *tp++ = '+';
			*tp++ = ']';
			*tp++ = '.';
			*tp++ = mode_char[(prefix_insn >> 4) & 3];

			info->flags
			  |= (CRIS_DIS_FLAG_MEM_TARGET2_IS_REG
			      | CRIS_DIS_FLAG_MEM_TARGET2_MEM
			      | CRIS_DIS_FLAG_MEM_TARGET_IS_REG

			      | (((prefix_insn >> 4) == 2)
				 ? 0
				 : (((prefix_insn >> 4) & 3) == 1
				    ? CRIS_DIS_FLAG_MEM_TARGET2_MEM_WORD
				    : CRIS_DIS_FLAG_MEM_TARGET2_MEM_BYTE)));
		      }
		    break;

		  default:
		    (*info->fprintf_func) (info->stream, "?prefix-bug");
		  }

		/* To mark that the prefix is used, reset it.  */
		prefix_opcodep = NULL;
	      }
	    else
	      {
		tp = format_reg (disdata, insn & 15, tp, with_reg_prefix);

		info->flags |= CRIS_DIS_FLAG_MEM_TARGET_IS_REG;
		info->target = insn & 15;

		if (insn & 0x400)
		  *tp++ = '+';
	      }
	    *tp++ = ']';
	  }
	break;

      case 'x':
	tp = format_reg (disdata, (insn >> 12) & 15, tp, with_reg_prefix);
	*tp++ = '.';
	*tp++ = mode_char[(insn >> 4) & 3];
	break;

      case 'I':
	tp = format_dec (insn & 63, tp, 0);
	break;

      case 'b':
	{
	  int where = buffer[2] + buffer[3] * 256;

	  if (where > 32767)
	    where -= 65536;

	  where += addr + ((disdata->distype == cris_dis_v32) ? 0 : 4);

	  if (insn == BA_PC_INCR_OPCODE)
	    info->insn_type = dis_branch;
	  else
	    info->insn_type = dis_condbranch;

	  info->target = (bfd_vma) where;

	  *tp = 0;
	  tp = temp;
	  (*info->fprintf_func) (info->stream, "%s%s ",
				 temp, cris_cc_strings[insn >> 12]);

	  (*info->print_address_func) ((bfd_vma) where, info);
	}
      break;

    case 'c':
      tp = format_dec (insn & 31, tp, 0);
      break;

    case 'C':
      tp = format_dec (insn & 15, tp, 0);
      break;

    case 'o':
      {
	long offset = insn & 0xfe;
	bfd_vma target;

	if (insn & 1)
	  offset |= ~0xff;

	if (opcodep->match == BA_QUICK_OPCODE)
	  info->insn_type = dis_branch;
	else
	  info->insn_type = dis_condbranch;

	target = addr + ((disdata->distype == cris_dis_v32) ? 0 : 2) + offset;
	info->target = target;
	*tp = 0;
	tp = temp;
	(*info->fprintf_func) (info->stream, "%s", temp);
	(*info->print_address_func) (target, info);
      }
      break;

    case 'Q':
    case 'O':
      {
	long number = buffer[0];

	if (number > 127)
	  number = number - 256;

	tp = format_dec (number, tp, 1);
	*tp++ = ',';
	tp = format_reg (disdata, (insn >> 12) & 15, tp, with_reg_prefix);
      }
      break;

    case 'f':
      tp = print_flags (disdata, insn, tp);
      break;

    case 'i':
      tp = format_dec ((insn & 32) ? (insn & 31) | ~31L : insn & 31, tp, 1);
      break;

    case 'P':
      {
	const struct cris_spec_reg *sregp
	  = spec_reg_info ((insn >> 12) & 15, disdata->distype);

if (sregp) {
	if (sregp->name == NULL)
	  /* Should have been caught as a non-match eariler.  */
	  *tp++ = '?';
	else
	  {
	    if (with_reg_prefix)
	      *tp++ = REGISTER_PREFIX_CHAR;
	    strcpy (tp, sregp->name);
	    tp += strlen (tp);
	  }
}
      }
      break;

    default:
      strcpy (tp, "???");
      tp += 3;
    }
  }

  *tp = 0;

  if (prefix_opcodep)
    (*info->fprintf_func) (info->stream, " (OOPS unused prefix \"%s: %s\")",
			   prefix_opcodep->name, prefix_opcodep->args);

  (*info->fprintf_func) (info->stream, "%s", temp);

  /* Get info for matching case-tables, if we don't have any active.
     We assume that the last constant seen is used; either in the insn
     itself or in a "move.d const,rN, sub.d rN,rM"-like sequence.  */
  if (TRACE_CASE && case_offset_counter == 0)
    {
      if (CONST_STRNEQ (opcodep->name, "sub"))
	case_offset = last_immediate;

      /* It could also be an "add", if there are negative case-values.  */
      else if (CONST_STRNEQ (opcodep->name, "add"))
	/* The first case is the negated operand to the add.  */
	case_offset = -last_immediate;

      /* A bound insn will tell us the number of cases.  */
      else if (CONST_STRNEQ (opcodep->name, "bound"))
	no_of_case_offsets = last_immediate + 1;

      /* A jump or jsr or branch breaks the chain of insns for a
	 case-table, so assume default first-case again.  */
      else if (info->insn_type == dis_jsr
	       || info->insn_type == dis_branch
	       || info->insn_type == dis_condbranch)
	case_offset = 0;
    }
}


/* Print the CRIS instruction at address memaddr on stream.  Returns
   length of the instruction, in bytes.  Prefix register names with `$' if
   WITH_REG_PREFIX.  */

int
print_insn_cris_generic (bfd_vma memaddr,
			 disassemble_info *info,
			 bfd_boolean with_reg_prefix)
{
  int nbytes;
  unsigned int insn;
  const struct cris_opcode *matchedp;
  int advance = 0;
  struct cris_disasm_data *disdata
    = (struct cris_disasm_data *) info->private_data;

  /* No instruction will be disassembled as longer than this number of
     bytes; stacked prefixes will not be expanded.  */
  unsigned char buffer[MAX_BYTES_PER_CRIS_INSN];
  unsigned char *bufp;
  int status = 0;
  bfd_vma addr;

  /* There will be an "out of range" error after the last instruction.
     Reading pairs of bytes in decreasing number, we hope that we will get
     at least the amount that we will consume.

     If we can't get any data, or we do not get enough data, we print
     the error message.  */

  for (nbytes = MAX_BYTES_PER_CRIS_INSN; nbytes > 0; nbytes -= 2)
    {
      status = (*info->read_memory_func) (memaddr, buffer, nbytes, info);
      if (status == 0)
	break;
    }

  /* If we did not get all we asked for, then clear the rest.
     Hopefully this makes a reproducible result in case of errors.  */
  if (nbytes != MAX_BYTES_PER_CRIS_INSN)
    memset (buffer + nbytes, 0, MAX_BYTES_PER_CRIS_INSN - nbytes);

  addr = memaddr;
  bufp = buffer;

  /* Set some defaults for the insn info.  */
  info->insn_info_valid = 1;
  info->branch_delay_insns = 0;
  info->data_size = 0;
  info->insn_type = dis_nonbranch;
  info->flags = 0;
  info->target = 0;
  info->target2 = 0;

  /* If we got any data, disassemble it.  */
  if (nbytes != 0)
    {
      matchedp = NULL;

      insn = bufp[0] + bufp[1] * 256;

      /* If we're in a case-table, don't disassemble the offsets.  */
      if (TRACE_CASE && case_offset_counter != 0)
	{
	  info->insn_type = dis_noninsn;
	  advance += 2;

	  /* If to print data as offsets, then shortcut here.  */
	  (*info->fprintf_func) (info->stream, "case %ld%s: -> ",
				 case_offset + no_of_case_offsets
				 - case_offset_counter,
				 case_offset_counter == 1 ? "/default" :
				 "");

	  (*info->print_address_func) ((bfd_vma)
				       ((short) (insn)
					+ (long) (addr
						  - (no_of_case_offsets
						     - case_offset_counter)
						  * 2)), info);
	  case_offset_counter--;

	  /* The default case start (without a "sub" or "add") must be
	     zero.  */
	  if (case_offset_counter == 0)
	    case_offset = 0;
	}
      else if (insn == 0)
	{
	  /* We're often called to disassemble zeroes.  While this is a
	     valid "bcc .+2" insn, it is also useless enough and enough
	     of a nuiscance that we will just output "bcc .+2" for it
	     and signal it as a noninsn.  */
	  (*info->fprintf_func) (info->stream,
				 disdata->distype == cris_dis_v32
				 ? "bcc ." : "bcc .+2");
	  info->insn_type = dis_noninsn;
	  advance += 2;
	}
      else
	{
	  const struct cris_opcode *prefix_opcodep = NULL;
	  unsigned char *prefix_buffer = bufp;
	  unsigned int prefix_insn = insn;
	  int prefix_size = 0;

	  matchedp = get_opcode_entry (insn, NO_CRIS_PREFIX, disdata);

	  /* Check if we're supposed to write out prefixes as address
	     modes and if this was a prefix.  */
	  if (matchedp != NULL && PARSE_PREFIX && matchedp->args[0] == 'p')
	    {
	      /* If it's a prefix, put it into the prefix vars and get the
		 main insn.  */
	      prefix_size = bytes_to_skip (prefix_insn, matchedp,
					   disdata->distype, NULL);
	      prefix_opcodep = matchedp;

	      insn = bufp[prefix_size] + bufp[prefix_size + 1] * 256;
	      matchedp = get_opcode_entry (insn, prefix_insn, disdata);

	      if (matchedp != NULL)
		{
		  addr += prefix_size;
		  bufp += prefix_size;
		  advance += prefix_size;
		}
	      else
		{
		  /* The "main" insn wasn't valid, at least not when
		     prefixed.  Put back things enough to output the
		     prefix insn only, as a normal insn.  */
		  matchedp = prefix_opcodep;
		  insn = prefix_insn;
		  prefix_opcodep = NULL;
		}
	    }

	  if (matchedp == NULL)
	    {
	      (*info->fprintf_func) (info->stream, "??0x%x", insn);
	      advance += 2;

	      info->insn_type = dis_noninsn;
	    }
	  else
	    {
	      advance
		+= bytes_to_skip (insn, matchedp, disdata->distype,
				  prefix_opcodep);

	      /* The info_type and assorted fields will be set according
		 to the operands.   */
	      print_with_operands (matchedp, insn, bufp, addr, info,
				   prefix_opcodep, prefix_insn,
				   prefix_buffer, with_reg_prefix);
	    }
	}
    }
  else
    info->insn_type = dis_noninsn;

  /* If we read less than MAX_BYTES_PER_CRIS_INSN, i.e. we got an error
     status when reading that much, and the insn decoding indicated a
     length exceeding what we read, there is an error.  */
  if (status != 0 && (nbytes == 0 || advance > nbytes))
    {
      (*info->memory_error_func) (status, memaddr, info);
      return -1;
    }

  /* Max supported insn size with one folded prefix insn.  */
  info->bytes_per_line = MAX_BYTES_PER_CRIS_INSN;

  /* I would like to set this to a fixed value larger than the actual
     number of bytes to print in order to avoid spaces between bytes,
     but objdump.c (2.9.1) does not like that, so we print 16-bit
     chunks, which is the next choice.  */
  info->bytes_per_chunk = 2;

  /* Printing bytes in order of increasing addresses makes sense,
     especially on a little-endian target.
     This is completely the opposite of what you think; setting this to
     BFD_ENDIAN_LITTLE will print bytes in order N..0 rather than the 0..N
     we want.  */
  info->display_endian = BFD_ENDIAN_BIG;

  return advance;
}

/* Disassemble, prefixing register names with `$'.  CRIS v0..v10.  */

static int
print_insn_cris_with_register_prefix (bfd_vma vma,
				      disassemble_info *info)
{
  if (info->private_data == NULL
      && !cris_parse_disassembler_options (info, cris_dis_v0_v10))
    return -1;
  return print_insn_cris_generic (vma, info, TRUE);
}

/* Disassemble, prefixing register names with `$'.  CRIS v32.  */

static int
print_insn_crisv32_with_register_prefix (bfd_vma vma,
					 disassemble_info *info)
{
  if (info->private_data == NULL
      && !cris_parse_disassembler_options (info, cris_dis_v32))
    return -1;
  return print_insn_cris_generic (vma, info, TRUE);
}

/* Disassemble, prefixing register names with `$'.
   Common v10 and v32 subset.  */

int
print_insn_crisv10_v32_with_register_prefix (bfd_vma vma,
					     disassemble_info *info)
{
  if (info->private_data == NULL
      && !cris_parse_disassembler_options (info, cris_dis_common_v10_v32))
    return -1;
  return print_insn_cris_generic (vma, info, TRUE);
}

/* Disassemble, no prefixes on register names.  CRIS v0..v10.  */

static int
print_insn_cris_without_register_prefix (bfd_vma vma,
					 disassemble_info *info)
{
  if (info->private_data == NULL
      && !cris_parse_disassembler_options (info, cris_dis_v0_v10))
    return -1;
  return print_insn_cris_generic (vma, info, FALSE);
}

/* Disassemble, no prefixes on register names.  CRIS v32.  */

int
print_insn_crisv32_without_register_prefix (bfd_vma vma,
					    disassemble_info *info)
{
  if (info->private_data == NULL
      && !cris_parse_disassembler_options (info, cris_dis_v32))
    return -1;
  return print_insn_cris_generic (vma, info, FALSE);
}

/* Disassemble, no prefixes on register names.
   Common v10 and v32 subset.  */

int
print_insn_crisv10_v32_without_register_prefix (bfd_vma vma,
						disassemble_info *info)
{
  if (info->private_data == NULL
      && !cris_parse_disassembler_options (info, cris_dis_common_v10_v32))
    return -1;
  return print_insn_cris_generic (vma, info, FALSE);
}

/* Return a disassembler-function that prints registers with a `$' prefix,
   or one that prints registers without a prefix.
   FIXME: We should improve the solution to avoid the multitude of
   functions seen above.  */

disassembler_ftype
cris_get_disassembler (bfd *abfd)
{
const int mode = 0; // V32 by default
  /* If there's no bfd in sight, we return what is valid as input in all
     contexts if fed back to the assembler: disassembly *with* register
     prefix.  Unfortunately this will be totally wrong for v32.  */
  if (abfd == NULL)
    return print_insn_cris_with_register_prefix;

  if (bfd_get_symbol_leading_char (abfd) == 0)
    {
switch (mode) {
case 0: // V32
	return print_insn_crisv32_with_register_prefix;
case 1: // V10_V32
	return print_insn_crisv10_v32_with_register_prefix;
default:

      /* We default to v10.  This may be specifically specified in the
	 bfd mach, but is also the default setting.  */
      return print_insn_cris_with_register_prefix;
}
    }

switch (mode) {
case 0: // V32
  //if (bfd_get_mach (abfd) == bfd_mach_cris_v32)
    return print_insn_crisv32_without_register_prefix;
case 1: // V10_V32
  //if (bfd_get_mach (abfd) == bfd_mach_cris_v10_v32)
    return print_insn_crisv10_v32_without_register_prefix;
default:
  return print_insn_cris_without_register_prefix;
}
}

/* Local variables:
   eval: (c-set-style "gnu")
   indent-tabs-mode: t
   End:  */
