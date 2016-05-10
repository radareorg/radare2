/* Assembler interface for targets using CGEN. -*- C -*-
   CGEN: Cpu tools GENerator

   THIS FILE IS MACHINE GENERATED WITH CGEN.
   - the resultant file is machine generated, cgen-asm.in isn't

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2005, 2007, 2008, 2010
   Free Software Foundation, Inc.

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
   along with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */


/* ??? Eventually more and more of this stuff can go to cpu-independent files.
   Keep that in mind.  */

#include "sysdep.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ansidecl.h"
#include "mybfd.h"
#include "symcat.h"
#include "vc4-desc.h"
#include "vc4-opc.h"
#include "opintl.h"
#include "regex.h"
#include "libiberty.h"
#include "dis-asm.h"
#include <ctype.h>

#undef  min
#define min(a,b) ((a) < (b) ? (a) : (b))
#undef  max
#define max(a,b) ((a) > (b) ? (a) : (b))

static const char * parse_insn_normal
  (CGEN_CPU_DESC, const CGEN_INSN *, const char **, CGEN_FIELDS *);

/* -- assembler routines inserted here.  */

/* -- asm.c */

#include <errno.h>

union floatbits {
  float f;
  uint32_t u;
};

static const char *
parse_floatimm6 (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
		 const char **strp,
		 int opindex ATTRIBUTE_UNUSED,
		 unsigned long *valuep)
{
  const char *startptr = *strp;
  char *endptr;
  union floatbits val;
  unsigned int exponent, signbit, mantissa;

  errno = 0;
  val.f = (float) strtod (startptr, &endptr);

  if (errno != 0)
    goto err_out;

  signbit = (val.u & 0x80000000) ? 1 : 0;
  exponent = (val.u >> 23) & 0xff;
  mantissa = val.u & 0x7fffff;

  if (exponent >= 124 && exponent < 132
      && (mantissa & 0x1fffff) == 0)
    {
      exponent -= 124;
      *valuep = (signbit << 5) | (exponent << 2) | (mantissa >> 21);
      *strp = endptr;
      return NULL;
    }

err_out:
  return "Bad floating-point immediate";
}

static const char *
parse_uimm5_shl3 (CGEN_CPU_DESC cd, const char **strp, int opindex,
		  unsigned long *valuep)
{
  const char *errmsg;

  errmsg = cgen_parse_unsigned_integer (cd, strp, opindex, valuep);

  if (!errmsg && ((*valuep & 7) != 0 || *valuep > 248))
    errmsg = "out-of-range immediate";

  return errmsg;
}

static const char *
parse_shifted_imm (CGEN_CPU_DESC cd, const char **strp, int opindex,
		   long *valuep, unsigned bits, unsigned shift)
{
  const char *errmsg;
  unsigned mask = (1 << shift) - 1;
  long lo = -(1 << (bits - 1)), hi = 1 << (bits - 1);
  long value;

  errmsg = cgen_parse_signed_integer (cd, strp, opindex, &value);

  if (!errmsg && ((value & mask) != 0 || (value >> shift) < lo
		  || (value >> shift) >= hi))
    errmsg = "out-of-range immediate";
  else
    *valuep = value;

  return errmsg;
}

#define SHIFTED_IMM_FN(B,S)						\
  static const char *							\
  parse_imm##B##_shl##S (CGEN_CPU_DESC cd, const char **strp,		\
			 int opindex, long *valuep)			\
  {									\
    return parse_shifted_imm (cd, strp, opindex, valuep, (B), (S));	\
  }

SHIFTED_IMM_FN (6, 8)
SHIFTED_IMM_FN (6, 7)
SHIFTED_IMM_FN (6, 6)
SHIFTED_IMM_FN (6, 5)
SHIFTED_IMM_FN (6, 4)
SHIFTED_IMM_FN (6, 3)
SHIFTED_IMM_FN (6, 2)
SHIFTED_IMM_FN (6, 1)

SHIFTED_IMM_FN (16, 4)
SHIFTED_IMM_FN (16, 3)
SHIFTED_IMM_FN (16, 2)
SHIFTED_IMM_FN (16, 1)

static const char *
parse_imm12 (CGEN_CPU_DESC cd, const char **strp, int opindex, long *valuep)
{
  return parse_shifted_imm (cd, strp, opindex, valuep, 12, 0);
}

static const char *
parse_imm16 (CGEN_CPU_DESC cd, const char **strp, int opindex, long *valuep)
{
  return parse_shifted_imm (cd, strp, opindex, valuep, 16, 0);
}

static const char *
parse_pcrel27 (CGEN_CPU_DESC cd, const char **strp, int opindex,
	       bfd_reloc_code_real_type code,
	       enum cgen_parse_operand_result *result_type, long *valuep)
{
  /* Instructions like "st r5,(lr)" are ambiguous since "lr" can be interpreted
     as a bracketed symbolic name when we meant it to be parsed as a register
     indirection.  Special-case the former to fail.  */
  if (**strp == '(')
    {
      const char *s = *strp;

      while (isalnum (*++s))
        ;

      if (*s == ')')
        return "looks like indirection";
    }

  return cgen_parse_address (cd, strp, opindex, code, result_type, valuep);
}

/* -- */

const char * vc4_cgen_parse_operand
  (CGEN_CPU_DESC, int, const char **, CGEN_FIELDS *);

/* Main entry point for operand parsing.

   This function is basically just a big switch statement.  Earlier versions
   used tables to look up the function to use, but
   - if the table contains both assembler and disassembler functions then
     the disassembler contains much of the assembler and vice-versa,
   - there's a lot of inlining possibilities as things grow,
   - using a switch statement avoids the function call overhead.

   This function could be moved into `parse_insn_normal', but keeping it
   separate makes clear the interface between `parse_insn_normal' and each of
   the handlers.  */

const char *
vc4_cgen_parse_operand (CGEN_CPU_DESC cd,
			   int opindex,
			   const char ** strp,
			   CGEN_FIELDS * fields)
{
  const char * errmsg = NULL;
  /* Used by scalar operands that still need to be parsed.  */
  long junk ATTRIBUTE_UNUSED;

  switch (opindex)
    {
    case VC4_OPERAND_ACCSZ :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_accsz, & fields->f_op10_9);
      break;
    case VC4_OPERAND_ACCSZ32 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_accsz, & fields->f_op7_6);
      break;
    case VC4_OPERAND_ADDCMPBAREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_fastreg, & fields->f_op7_4);
      break;
    case VC4_OPERAND_ADDCMPBIMM :
      errmsg = cgen_parse_signed_integer (cd, strp, VC4_OPERAND_ADDCMPBIMM, (long *) (& fields->f_op7_4s));
      break;
    case VC4_OPERAND_ADDSPOFFSET :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_ADDSPOFFSET, (unsigned long *) (& fields->f_addspoffset));
      break;
    case VC4_OPERAND_ALU16DREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_fastreg, & fields->f_op3_0);
      break;
    case VC4_OPERAND_ALU16IMM :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_ALU16IMM, (unsigned long *) (& fields->f_op8_4));
      break;
    case VC4_OPERAND_ALU16IMM_SHL3 :
      errmsg = parse_uimm5_shl3 (cd, strp, VC4_OPERAND_ALU16IMM_SHL3, (unsigned long *) (& fields->f_op8_4_shl3));
      break;
    case VC4_OPERAND_ALU16SREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_fastreg, & fields->f_op7_4);
      break;
    case VC4_OPERAND_ALU32AREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op31_27);
      break;
    case VC4_OPERAND_ALU32BREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op20_16);
      break;
    case VC4_OPERAND_ALU32COND :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_cond, & fields->f_op26_23);
      break;
    case VC4_OPERAND_ALU32DREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0);
      break;
    case VC4_OPERAND_ALU48IDREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0);
      break;
    case VC4_OPERAND_ALU48IMMU :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_ALU48IMMU, (unsigned long *) (& fields->f_op47_16));
      break;
    case VC4_OPERAND_ALU48ISREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op9_5);
      break;
    case VC4_OPERAND_ALU48PCREL :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_ALU48PCREL, 0, NULL,  & value);
        fields->f_pcrel32_48 = value;
      }
      break;
    case VC4_OPERAND_BCC32IMM :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_BCC32IMM, (unsigned long *) (& fields->f_op29_24));
      break;
    case VC4_OPERAND_BCC32SREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_fastreg, & fields->f_op29_26);
      break;
    case VC4_OPERAND_CONDCODE :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_cond, & fields->f_op10_7);
      break;
    case VC4_OPERAND_CONDCODEBCC32 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_cond, & fields->f_op11_8);
      break;
    case VC4_OPERAND_FLOATIMM6 :
      errmsg = parse_floatimm6 (cd, strp, VC4_OPERAND_FLOATIMM6, (unsigned long *) (& fields->f_op21_16));
      break;
    case VC4_OPERAND_IMM6 :
      errmsg = cgen_parse_signed_integer (cd, strp, VC4_OPERAND_IMM6, (long *) (& fields->f_op21_16s));
      break;
    case VC4_OPERAND_IMM6_SHL1 :
      errmsg = parse_imm6_shl1 (cd, strp, VC4_OPERAND_IMM6_SHL1, (long *) (& fields->f_op21_16s_shl1));
      break;
    case VC4_OPERAND_IMM6_SHL2 :
      errmsg = parse_imm6_shl2 (cd, strp, VC4_OPERAND_IMM6_SHL2, (long *) (& fields->f_op21_16s_shl2));
      break;
    case VC4_OPERAND_IMM6_SHL3 :
      errmsg = parse_imm6_shl3 (cd, strp, VC4_OPERAND_IMM6_SHL3, (long *) (& fields->f_op21_16s_shl3));
      break;
    case VC4_OPERAND_IMM6_SHL4 :
      errmsg = parse_imm6_shl4 (cd, strp, VC4_OPERAND_IMM6_SHL4, (long *) (& fields->f_op21_16s_shl4));
      break;
    case VC4_OPERAND_IMM6_SHL5 :
      errmsg = parse_imm6_shl5 (cd, strp, VC4_OPERAND_IMM6_SHL5, (long *) (& fields->f_op21_16s_shl5));
      break;
    case VC4_OPERAND_IMM6_SHL6 :
      errmsg = parse_imm6_shl6 (cd, strp, VC4_OPERAND_IMM6_SHL6, (long *) (& fields->f_op21_16s_shl6));
      break;
    case VC4_OPERAND_IMM6_SHL7 :
      errmsg = parse_imm6_shl7 (cd, strp, VC4_OPERAND_IMM6_SHL7, (long *) (& fields->f_op21_16s_shl7));
      break;
    case VC4_OPERAND_IMM6_SHL8 :
      errmsg = parse_imm6_shl8 (cd, strp, VC4_OPERAND_IMM6_SHL8, (long *) (& fields->f_op21_16s_shl8));
      break;
    case VC4_OPERAND_LDSTOFF :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_LDSTOFF, (unsigned long *) (& fields->f_ldstoff));
      break;
    case VC4_OPERAND_MEM48OFFSET27 :
      errmsg = cgen_parse_signed_integer (cd, strp, VC4_OPERAND_MEM48OFFSET27, (long *) (& fields->f_offset27_48));
      break;
    case VC4_OPERAND_MEM48PCREL27 :
      {
        bfd_vma value = 0;
        errmsg = parse_pcrel27 (cd, strp, VC4_OPERAND_MEM48PCREL27, 0, NULL,  & value);
        fields->f_pcrel27_48 = value;
      }
      break;
    case VC4_OPERAND_MEM48SREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op47_43);
      break;
    case VC4_OPERAND_OFF16BASEREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_basereg, & fields->f_op9_8);
      break;
    case VC4_OPERAND_OFFSET12 :
      errmsg = parse_imm12 (cd, strp, VC4_OPERAND_OFFSET12, (long *) (& fields->f_offset12));
      break;
    case VC4_OPERAND_OFFSET16 :
      errmsg = parse_imm16 (cd, strp, VC4_OPERAND_OFFSET16, (long *) (& fields->f_op31_16s));
      break;
    case VC4_OPERAND_OFFSET16_SHL1 :
      errmsg = parse_imm16_shl1 (cd, strp, VC4_OPERAND_OFFSET16_SHL1, (long *) (& fields->f_op31_16s_shl1));
      break;
    case VC4_OPERAND_OFFSET16_SHL2 :
      errmsg = parse_imm16_shl2 (cd, strp, VC4_OPERAND_OFFSET16_SHL2, (long *) (& fields->f_op31_16s_shl2));
      break;
    case VC4_OPERAND_OFFSET16_SHL3 :
      errmsg = parse_imm16_shl3 (cd, strp, VC4_OPERAND_OFFSET16_SHL3, (long *) (& fields->f_op31_16s_shl3));
      break;
    case VC4_OPERAND_OFFSET16_SHL4 :
      errmsg = parse_imm16_shl4 (cd, strp, VC4_OPERAND_OFFSET16_SHL4, (long *) (& fields->f_op31_16s_shl4));
      break;
    case VC4_OPERAND_OFFSET23BITS :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_OFFSET23BITS, 0, NULL,  & value);
        fields->f_offset23bits = value;
      }
      break;
    case VC4_OPERAND_OFFSET27BITS :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_OFFSET27BITS, 0, NULL,  & value);
        fields->f_offset27bits = value;
      }
      break;
    case VC4_OPERAND_OPERAND10_0 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_OPERAND10_0, (unsigned long *) (& fields->f_op10_0));
      break;
    case VC4_OPERAND_OPERAND47_16 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_OPERAND47_16, (unsigned long *) (& fields->f_op47_16));
      break;
    case VC4_OPERAND_OPERAND79_48 :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_OPERAND79_48, (unsigned long *) (& fields->f_op79_48));
      break;
    case VC4_OPERAND_PCREL10BITS :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_PCREL10BITS, 0, NULL,  & value);
        fields->f_pcrel10 = value;
      }
      break;
    case VC4_OPERAND_PCREL16 :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_PCREL16, 0, NULL,  & value);
        fields->f_pcrel16 = value;
      }
      break;
    case VC4_OPERAND_PCREL8BITS :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_PCREL8BITS, 0, NULL,  & value);
        fields->f_pcrel8 = value;
      }
      break;
    case VC4_OPERAND_PCRELCC :
      {
        bfd_vma value = 0;
        errmsg = cgen_parse_address (cd, strp, VC4_OPERAND_PCRELCC, 0, NULL,  & value);
        fields->f_pcrelcc = value;
      }
      break;
    case VC4_OPERAND_PPENDREG0 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0_base_0);
      break;
    case VC4_OPERAND_PPENDREG16 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0_base_16);
      break;
    case VC4_OPERAND_PPENDREG24 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0_base_24);
      break;
    case VC4_OPERAND_PPENDREG6 :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_reg, & fields->f_op4_0_base_6);
      break;
    case VC4_OPERAND_PPSTARTREG :
      errmsg = cgen_parse_keyword (cd, strp, & vc4_cgen_opval_h_ppreg, & fields->f_op6_5);
      break;
    case VC4_OPERAND_SPOFFSET :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_SPOFFSET, (unsigned long *) (& fields->f_spoffset));
      break;
    case VC4_OPERAND_SWI_IMM :
      errmsg = cgen_parse_unsigned_integer (cd, strp, VC4_OPERAND_SWI_IMM, (unsigned long *) (& fields->f_op5_0));
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while parsing.\n"), opindex);
      abort ();
  }

  return errmsg;
}

cgen_parse_fn * const vc4_cgen_parse_handlers[] = 
{
  parse_insn_normal,
};

void
vc4_cgen_init_asm (CGEN_CPU_DESC cd)
{
  vc4_cgen_init_opcode_table (cd);
  vc4_cgen_init_ibld_table (cd);
  cd->parse_handlers = & vc4_cgen_parse_handlers[0];
  cd->parse_operand = vc4_cgen_parse_operand;
#ifdef CGEN_ASM_INIT_HOOK
CGEN_ASM_INIT_HOOK
#endif
}



/* Regex construction routine.

   This translates an opcode syntax string into a regex string,
   by replacing any non-character syntax element (such as an
   opcode) with the pattern '.*'

   It then compiles the regex and stores it in the opcode, for
   later use by vc4_cgen_assemble_insn

   Returns NULL for success, an error message for failure.  */

char * 
vc4_cgen_build_insn_regex (CGEN_INSN *insn)
{  
  CGEN_OPCODE *opc = (CGEN_OPCODE *) CGEN_INSN_OPCODE (insn);
  const char *mnem = CGEN_INSN_MNEMONIC (insn);
  char rxbuf[CGEN_MAX_RX_ELEMENTS];
  char *rx = rxbuf;
  const CGEN_SYNTAX_CHAR_TYPE *syn;
  int reg_err;

  syn = CGEN_SYNTAX_STRING (CGEN_OPCODE_SYNTAX (opc));

  /* Mnemonics come first in the syntax string.  */
  if (! CGEN_SYNTAX_MNEMONIC_P (* syn))
    return _("missing mnemonic in syntax string");
  ++syn;

  /* Generate a case sensitive regular expression that emulates case
     insensitive matching in the "C" locale.  We cannot generate a case
     insensitive regular expression because in Turkish locales, 'i' and 'I'
     are not equal modulo case conversion.  */

  /* Copy the literal mnemonic out of the insn.  */
  for (; *mnem; mnem++)
    {
      char c = *mnem;

      if (isalpha (c))
	{
	  *rx++ = '[';
	  *rx++ = tolower (c);
	  *rx++ = toupper (c);
	  *rx++ = ']';
	}
      else
	*rx++ = c;
    }

  /* Copy any remaining literals from the syntax string into the rx.  */
  for(; * syn != 0 && rx <= rxbuf + (CGEN_MAX_RX_ELEMENTS - 7 - 4); ++syn)
    {
      if (CGEN_SYNTAX_CHAR_P (* syn)) 
	{
	  char c = CGEN_SYNTAX_CHAR (* syn);

	  switch (c) 
	    {
	      /* Escape any regex metacharacters in the syntax.  */
	    case '.': case '[': case '\\': 
	    case '*': case '^': case '$': 

#ifdef CGEN_ESCAPE_EXTENDED_REGEX
	    case '?': case '{': case '}': 
	    case '(': case ')': case '*':
	    case '|': case '+': case ']':
#endif
	      *rx++ = '\\';
	      *rx++ = c;
	      break;

	    default:
	      if (isalpha (c))
		{
		  *rx++ = '[';
		  *rx++ = tolower (c);
		  *rx++ = toupper (c);
		  *rx++ = ']';
		}
	      else
		*rx++ = c;
	      break;
	    }
	}
      else
	{
	  /* Replace non-syntax fields with globs.  */
	  *rx++ = '.';
	  *rx++ = '*';
	}
    }

  /* Trailing whitespace ok.  */
  * rx++ = '['; 
  * rx++ = ' '; 
  * rx++ = '\t'; 
  * rx++ = ']'; 
  * rx++ = '*'; 

  /* But anchor it after that.  */
  * rx++ = '$'; 
  * rx = '\0';

  CGEN_INSN_RX (insn) = xmalloc (sizeof (regex_t));
  reg_err = regcomp ((regex_t *) CGEN_INSN_RX (insn), rxbuf, REG_NOSUB);

  if (reg_err == 0) 
    return NULL;
  else
    {
      static char msg[80];

      regerror (reg_err, (regex_t *) CGEN_INSN_RX (insn), msg, 80);
      regfree ((regex_t *) CGEN_INSN_RX (insn));
      free (CGEN_INSN_RX (insn));
      (CGEN_INSN_RX (insn)) = NULL;
      return msg;
    }
}


/* Default insn parser.

   The syntax string is scanned and operands are parsed and stored in FIELDS.
   Relocs are queued as we go via other callbacks.

   ??? Note that this is currently an all-or-nothing parser.  If we fail to
   parse the instruction, we return 0 and the caller will start over from
   the beginning.  Backtracking will be necessary in parsing subexpressions,
   but that can be handled there.  Not handling backtracking here may get
   expensive in the case of the m68k.  Deal with later.

   Returns NULL for success, an error message for failure.  */

static const char *
parse_insn_normal (CGEN_CPU_DESC cd,
		   const CGEN_INSN *insn,
		   const char **strp,
		   CGEN_FIELDS *fields)
{
  /* ??? Runtime added insns not handled yet.  */
  const CGEN_SYNTAX *syntax = CGEN_INSN_SYNTAX (insn);
  const char *str = *strp;
  const char *errmsg;
  const char *p;
  const CGEN_SYNTAX_CHAR_TYPE * syn;
#ifdef CGEN_MNEMONIC_OPERANDS
  /* FIXME: wip */
  int past_opcode_p;
#endif

  /* For now we assume the mnemonic is first (there are no leading operands).
     We can parse it without needing to set up operand parsing.
     GAS's input scrubber will ensure mnemonics are lowercase, but we may
     not be called from GAS.  */
  p = CGEN_INSN_MNEMONIC (insn);
  while (*p && tolower (*p) == tolower (*str))
    ++p, ++str;

  if (* p)
    return _("unrecognized instruction");

#ifndef CGEN_MNEMONIC_OPERANDS
  if (* str && ! isspace (* str))
    return _("unrecognized instruction");
#endif

  CGEN_INIT_PARSE (cd);
  cgen_init_parse_operand (cd);
#ifdef CGEN_MNEMONIC_OPERANDS
  past_opcode_p = 0;
#endif

  /* We don't check for (*str != '\0') here because we want to parse
     any trailing fake arguments in the syntax string.  */
  syn = CGEN_SYNTAX_STRING (syntax);

  /* Mnemonics come first for now, ensure valid string.  */
  if (! CGEN_SYNTAX_MNEMONIC_P (* syn))
    abort ();

  ++syn;

  while (* syn != 0)
    {
      /* Non operand chars must match exactly.  */
      if (CGEN_SYNTAX_CHAR_P (* syn))
	{
	  /* FIXME: While we allow for non-GAS callers above, we assume the
	     first char after the mnemonic part is a space.  */
	  /* FIXME: We also take inappropriate advantage of the fact that
	     GAS's input scrubber will remove extraneous blanks.  */
	  if (tolower (*str) == tolower (CGEN_SYNTAX_CHAR (* syn)))
	    {
#ifdef CGEN_MNEMONIC_OPERANDS
	      if (CGEN_SYNTAX_CHAR(* syn) == ' ')
		past_opcode_p = 1;
#endif
	      ++ syn;
	      ++ str;
	    }
	  else if (*str)
	    {
	      /* Syntax char didn't match.  Can't be this insn.  */
	      static char msg [80];

	      /* xgettext:c-format */
	      sprintf (msg, _("syntax error (expected char `%c', found `%c')"),
		       CGEN_SYNTAX_CHAR(*syn), *str);
	      return msg;
	    }
	  else
	    {
	      /* Ran out of input.  */
	      static char msg [80];

	      /* xgettext:c-format */
	      sprintf (msg, _("syntax error (expected char `%c', found end of instruction)"),
		       CGEN_SYNTAX_CHAR(*syn));
	      return msg;
	    }
	  continue;
	}

#ifdef CGEN_MNEMONIC_OPERANDS
      (void) past_opcode_p;
#endif
      /* We have an operand of some sort.  */
      errmsg = cd->parse_operand (cd, CGEN_SYNTAX_FIELD (*syn), &str, fields);
      if (errmsg)
	return errmsg;

      /* Done with this operand, continue with next one.  */
      ++ syn;
    }

  /* If we're at the end of the syntax string, we're done.  */
  if (* syn == 0)
    {
      /* FIXME: For the moment we assume a valid `str' can only contain
	 blanks now.  IE: We needn't try again with a longer version of
	 the insn and it is assumed that longer versions of insns appear
	 before shorter ones (eg: lsr r2,r3,1 vs lsr r2,r3).  */
      while (isspace (* str))
	++ str;

      if (* str != '\0')
	return _("junk at end of line"); /* FIXME: would like to include `str' */

      return NULL;
    }

  /* We couldn't parse it.  */
  return _("unrecognized instruction");
}

/* Main entry point.
   This routine is called for each instruction to be assembled.
   STR points to the insn to be assembled.
   We assume all necessary tables have been initialized.
   The assembled instruction, less any fixups, is stored in BUF.
   Remember that if CGEN_INT_INSN_P then BUF is an int and thus the value
   still needs to be converted to target byte order, otherwise BUF is an array
   of bytes in target byte order.
   The result is a pointer to the insn's entry in the opcode table,
   or NULL if an error occured (an error message will have already been
   printed).

   Note that when processing (non-alias) macro-insns,
   this function recurses.

   ??? It's possible to make this cpu-independent.
   One would have to deal with a few minor things.
   At this point in time doing so would be more of a curiosity than useful
   [for example this file isn't _that_ big], but keeping the possibility in
   mind helps keep the design clean.  */

const CGEN_INSN *
vc4_cgen_assemble_insn (CGEN_CPU_DESC cd,
			   const char *str,
			   CGEN_FIELDS *fields,
			   CGEN_INSN_BYTES_PTR buf,
			   char **errmsg)
{
  const char *start;
  CGEN_INSN_LIST *ilist;
  const char *parse_errmsg = NULL;
  const char *insert_errmsg = NULL;
  int recognized_mnemonic = 0;

  /* Skip leading white space.  */
  while (isspace (* str))
    ++ str;

  /* The instructions are stored in hashed lists.
     Get the first in the list.  */
  ilist = CGEN_ASM_LOOKUP_INSN (cd, str);

  /* Keep looking until we find a match.  */
  start = str;
  for ( ; ilist != NULL ; ilist = CGEN_ASM_NEXT_INSN (ilist))
    {
      const CGEN_INSN *insn = ilist->insn;
      recognized_mnemonic = 1;

#ifdef CGEN_VALIDATE_INSN_SUPPORTED 
      /* Not usually needed as unsupported opcodes
	 shouldn't be in the hash lists.  */
      /* Is this insn supported by the selected cpu?  */
      if (! vc4_cgen_insn_supported (cd, insn))
	continue;
#endif
      /* If the RELAXED attribute is set, this is an insn that shouldn't be
	 chosen immediately.  Instead, it is used during assembler/linker
	 relaxation if possible.  */
      if (CGEN_INSN_ATTR_VALUE (insn, CGEN_INSN_RELAXED) != 0)
	continue;

      str = start;

      /* Skip this insn if str doesn't look right lexically.  */
      if (CGEN_INSN_RX (insn) != NULL &&
	  regexec ((regex_t *) CGEN_INSN_RX (insn), str, 0, NULL, 0) == REG_NOMATCH)
	continue;

      /* Allow parse/insert handlers to obtain length of insn.  */
      CGEN_FIELDS_BITSIZE (fields) = CGEN_INSN_BITSIZE (insn);

      parse_errmsg = CGEN_PARSE_FN (cd, insn) (cd, insn, & str, fields);
      if (parse_errmsg != NULL)
	continue;

      /* ??? 0 is passed for `pc'.  */
      insert_errmsg = CGEN_INSERT_FN (cd, insn) (cd, insn, fields, buf,
						 (bfd_vma) 0);
      if (insert_errmsg != NULL)
        continue;

      /* It is up to the caller to actually output the insn and any
         queued relocs.  */
      return insn;
    }

  {
    static char errbuf[150];
    const char *tmp_errmsg;
#ifdef CGEN_VERBOSE_ASSEMBLER_ERRORS
#define be_verbose 1
#else
#define be_verbose 0
#endif

    if (be_verbose)
      {
	/* If requesting verbose error messages, use insert_errmsg.
	   Failing that, use parse_errmsg.  */
	tmp_errmsg = (insert_errmsg ? insert_errmsg :
		      parse_errmsg ? parse_errmsg :
		      recognized_mnemonic ?
		      _("unrecognized form of instruction") :
		      _("unrecognized instruction"));

	if (strlen (start) > 50)
	  /* xgettext:c-format */
	  sprintf (errbuf, "%s `%.50s...'", tmp_errmsg, start);
	else 
	  /* xgettext:c-format */
	  sprintf (errbuf, "%s `%.50s'", tmp_errmsg, start);
      }
    else
      {
	if (strlen (start) > 50)
	  /* xgettext:c-format */
	  sprintf (errbuf, _("bad instruction `%.50s...'"), start);
	else 
	  /* xgettext:c-format */
	  sprintf (errbuf, _("bad instruction `%.50s'"), start);
      }
      
    *errmsg = errbuf;
    return NULL;
  }
}
