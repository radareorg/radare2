/* Instruction building/extraction support for vc4. -*- C -*-

   THIS FILE IS MACHINE GENERATED WITH CGEN: Cpu tools GENerator.
   - the resultant file is machine generated, cgen-ibld.in isn't

   Copyright 1996, 1997, 1998, 1999, 2000, 2001, 2005, 2006, 2007,
   2008, 2010  Free Software Foundation, Inc.

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
#include <string.h>
#include "ansidecl.h"
#include "dis-asm.h"
#include "mybfd.h"
#include "symcat.h"
#include "vc4-desc.h"
#include "vc4-opc.h"
#include "cgen/basic-modes.h"
#include "opintl.h"
#include <ctype.h>

#undef  min
#define min(a,b) ((a) < (b) ? (a) : (b))
#undef  max
#define max(a,b) ((a) > (b) ? (a) : (b))

/* Used by the ifield rtx function.  */
#define FLD(f) (fields->f)

static const char * insert_normal
  (CGEN_CPU_DESC, long, unsigned int, unsigned int, unsigned int,
   unsigned int, unsigned int, unsigned int, CGEN_INSN_BYTES_PTR);
static const char * insert_insn_normal
  (CGEN_CPU_DESC, const CGEN_INSN *,
   CGEN_FIELDS *, CGEN_INSN_BYTES_PTR, bfd_vma);
static int extract_normal
  (CGEN_CPU_DESC, CGEN_EXTRACT_INFO *, CGEN_INSN_INT,
   unsigned int, unsigned int, unsigned int, unsigned int,
   unsigned int, unsigned int, bfd_vma, long *);
static int extract_insn_normal
  (CGEN_CPU_DESC, const CGEN_INSN *, CGEN_EXTRACT_INFO *,
   CGEN_INSN_INT, CGEN_FIELDS *, bfd_vma);
#if CGEN_INT_INSN_P
static void put_insn_int_value
  (CGEN_CPU_DESC, CGEN_INSN_BYTES_PTR, int, int, CGEN_INSN_INT);
#endif
#if ! CGEN_INT_INSN_P
static CGEN_INLINE void insert_1
  (CGEN_CPU_DESC, unsigned long, int, int, int, unsigned char *);
static CGEN_INLINE int fill_cache
  (CGEN_CPU_DESC, CGEN_EXTRACT_INFO *,  int, int, bfd_vma);
static CGEN_INLINE long extract_1
  (CGEN_CPU_DESC, CGEN_EXTRACT_INFO *, int, int, int, unsigned char *, bfd_vma);
#endif

/* Operand insertion.  */

#if ! CGEN_INT_INSN_P

/* Subroutine of insert_normal.  */

static CGEN_INLINE void
insert_1 (CGEN_CPU_DESC cd,
	  unsigned long value,
	  int start,
	  int length,
	  int word_length,
	  unsigned char *bufp)
{
  unsigned long x,mask;
  int shift;

  x = cgen_get_insn_value (cd, bufp, word_length);

  /* Written this way to avoid undefined behaviour.  */
  mask = (((1L << (length - 1)) - 1) << 1) | 1;
  if (CGEN_INSN_LSB0_P)
    shift = (start + 1) - length;
  else
    shift = (word_length - (start + length));
  x = (x & ~(mask << shift)) | ((value & mask) << shift);

  cgen_put_insn_value (cd, bufp, word_length, (bfd_vma) x);
}

#endif /* ! CGEN_INT_INSN_P */

/* Default insertion routine.

   ATTRS is a mask of the boolean attributes.
   WORD_OFFSET is the offset in bits from the start of the insn of the value.
   WORD_LENGTH is the length of the word in bits in which the value resides.
   START is the starting bit number in the word, architecture origin.
   LENGTH is the length of VALUE in bits.
   TOTAL_LENGTH is the total length of the insn in bits.

   The result is an error message or NULL if success.  */

/* ??? This duplicates functionality with bfd's howto table and
   bfd_install_relocation.  */
/* ??? This doesn't handle bfd_vma's.  Create another function when
   necessary.  */

static const char *
insert_normal (CGEN_CPU_DESC cd,
	       long value,
	       unsigned int attrs,
	       unsigned int word_offset,
	       unsigned int start,
	       unsigned int length,
	       unsigned int word_length,
	       unsigned int total_length,
	       CGEN_INSN_BYTES_PTR buffer)
{
  static char errbuf[100];
  /* Written this way to avoid undefined behaviour.  */
  unsigned long mask = (((1L << (length - 1)) - 1) << 1) | 1;

  /* If LENGTH is zero, this operand doesn't contribute to the value.  */
  if (length == 0)
    return NULL;

  if (word_length > 8 * sizeof (CGEN_INSN_INT))
    abort ();

  /* For architectures with insns smaller than the base-insn-bitsize,
     word_length may be too big.  */
  if (cd->min_insn_bitsize < cd->base_insn_bitsize)
    {
      if (word_offset == 0
	  && word_length > total_length)
	word_length = total_length;
    }

  /* Ensure VALUE will fit.  */
  if (CGEN_BOOL_ATTR (attrs, CGEN_IFLD_SIGN_OPT))
    {
      long minval = - (1L << (length - 1));
      unsigned long maxval = mask;
      
      if ((value > 0 && (unsigned long) value > maxval)
	  || value < minval)
	{
	  /* xgettext:c-format */
	  sprintf (errbuf,
		   _("operand out of range (%ld not between %ld and %lu)"),
		   value, minval, maxval);
	  return errbuf;
	}
    }
  else if (! CGEN_BOOL_ATTR (attrs, CGEN_IFLD_SIGNED))
    {
      unsigned long maxval = mask;
      unsigned long val = (unsigned long) value;

      /* For hosts with a word size > 32 check to see if value has been sign
	 extended beyond 32 bits.  If so then ignore these higher sign bits
	 as the user is attempting to store a 32-bit signed value into an
	 unsigned 32-bit field which is allowed.  */
      if (sizeof (unsigned long) > 4 && ((value >> 32) == -1))
	val &= 0xFFFFFFFF;

      if (val > maxval)
	{
	  /* xgettext:c-format */
	  sprintf (errbuf,
		   _("operand out of range (0x%lx not between 0 and 0x%lx)"),
		   val, maxval);
	  return errbuf;
	}
    }
  else
    {
      if (! cgen_signed_overflow_ok_p (cd))
	{
	  long minval = - (1L << (length - 1));
	  long maxval =   (1L << (length - 1)) - 1;
	  
	  if (value < minval || value > maxval)
	    {
	      sprintf
		/* xgettext:c-format */
		(errbuf, _("operand out of range (%ld not between %ld and %ld)"),
		 value, minval, maxval);
	      return errbuf;
	    }
	}
    }

#if CGEN_INT_INSN_P

  {
    int shift;

    if (CGEN_INSN_LSB0_P)
      shift = (word_offset + start + 1) - length;
    else
      shift = total_length - (word_offset + start + length);
    *buffer = (*buffer & ~(mask << shift)) | ((value & mask) << shift);
  }

#else /* ! CGEN_INT_INSN_P */

  {
    unsigned char *bufp = (unsigned char *) buffer + word_offset / 8;

    insert_1 (cd, value, start, length, word_length, bufp);
  }

#endif /* ! CGEN_INT_INSN_P */

  return NULL;
}

/* Default insn builder (insert handler).
   The instruction is recorded in CGEN_INT_INSN_P byte order (meaning
   that if CGEN_INSN_BYTES_PTR is an int * and thus, the value is
   recorded in host byte order, otherwise BUFFER is an array of bytes
   and the value is recorded in target byte order).
   The result is an error message or NULL if success.  */

static const char *
insert_insn_normal (CGEN_CPU_DESC cd,
		    const CGEN_INSN * insn,
		    CGEN_FIELDS * fields,
		    CGEN_INSN_BYTES_PTR buffer,
		    bfd_vma pc)
{
  const CGEN_SYNTAX *syntax = CGEN_INSN_SYNTAX (insn);
  unsigned long value;
  const CGEN_SYNTAX_CHAR_TYPE * syn;
#ifdef CGEN_MAX_EXTRA_OPCODE_OPERANDS
  unsigned int i, extra_field;
#endif

  CGEN_INIT_INSERT (cd);
  value = CGEN_INSN_BASE_VALUE (insn);

  /* If we're recording insns as numbers (rather than a string of bytes),
     target byte order handling is deferred until later.  */

#if CGEN_INT_INSN_P

#ifdef CGEN_MAX_EXTRA_OPCODE_OPERANDS
  /* The excuse for this is that CGEN_MAX_EXTRA_OPCODE_OPERANDS is only useful
     for variable-length instruction sets, and those will probably have insns
     longer than INT_INSN size.  */
#error You can't have CGEN_MAX_EXTRA_OPCODE_OPERANDS with CGEN_INT_INSN_P.
#endif

  put_insn_int_value (cd, buffer, cd->base_insn_bitsize,
		      CGEN_FIELDS_BITSIZE (fields), value);

#else

  cgen_put_insn_value (cd, buffer, min ((unsigned) cd->base_insn_bitsize,
					(unsigned) CGEN_FIELDS_BITSIZE (fields)),
		       value);

#ifdef CGEN_MAX_EXTRA_OPCODE_OPERANDS
  for (i = cd->base_insn_bitsize, extra_field = 0;
       i < (unsigned) CGEN_FIELDS_BITSIZE (fields);
       i += cd->base_insn_bitsize, extra_field++)
    {
      cgen_put_insn_value (cd, &buffer[i / 8],
			   cd->base_insn_bitsize,
			   CGEN_INSN_IFIELD_VALUE (insn, extra_field));
    }
#endif /* ! CGEN_MAX_EXTRA_OPCODE_OPERANDS */

#endif /* ! CGEN_INT_INSN_P */

  /* ??? It would be better to scan the format's fields.
     Still need to be able to insert a value based on the operand though;
     e.g. storing a branch displacement that got resolved later.
     Needs more thought first.  */

  for (syn = CGEN_SYNTAX_STRING (syntax); * syn; ++ syn)
    {
      const char *errmsg;

      if (CGEN_SYNTAX_CHAR_P (* syn))
	continue;

      errmsg = (* cd->insert_operand) (cd, CGEN_SYNTAX_FIELD (*syn),
				       fields, buffer, pc);
      if (errmsg)
	return errmsg;
    }

  return NULL;
}

#if CGEN_INT_INSN_P
/* Cover function to store an insn value into an integral insn.  Must go here
   because it needs <prefix>-desc.h for CGEN_INT_INSN_P.  */

static void
put_insn_int_value (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
		    CGEN_INSN_BYTES_PTR buf,
		    int length,
		    int insn_length,
		    CGEN_INSN_INT value)
{
  /* For architectures with insns smaller than the base-insn-bitsize,
     length may be too big.  */
  if (length > insn_length)
    *buf = value;
  else
    {
      int shift = insn_length - length;
      /* Written this way to avoid undefined behaviour.  */
      CGEN_INSN_INT mask = (((1L << (length - 1)) - 1) << 1) | 1;

      *buf = (*buf & ~(mask << shift)) | ((value & mask) << shift);
    }
}
#endif

/* Operand extraction.  */

#if ! CGEN_INT_INSN_P

/* Subroutine of extract_normal.
   Ensure sufficient bytes are cached in EX_INFO.
   OFFSET is the offset in bytes from the start of the insn of the value.
   BYTES is the length of the needed value.
   Returns 1 for success, 0 for failure.  */

static CGEN_INLINE int
fill_cache (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
	    CGEN_EXTRACT_INFO *ex_info,
	    int offset,
	    int bytes,
	    bfd_vma pc)
{
  /* It's doubtful that the middle part has already been fetched so
     we don't optimize that case.  kiss.  */
  unsigned int mask;
  disassemble_info *info = (disassemble_info *) ex_info->dis_info;

  /* First do a quick check.  */
  mask = (1 << bytes) - 1;
  if (((ex_info->valid >> offset) & mask) == mask)
    return 1;

  /* Search for the first byte we need to read.  */
  for (mask = 1 << offset; bytes > 0; --bytes, ++offset, mask <<= 1)
    if (! (mask & ex_info->valid))
      break;

  if (bytes)
    {
      int status;

      pc += offset;
      status = (*info->read_memory_func)
	(pc, ex_info->insn_bytes + offset, bytes, info);

      if (status != 0)
	{
	  (*info->memory_error_func) (status, pc, info);
	  return 0;
	}

      ex_info->valid |= ((1 << bytes) - 1) << offset;
    }

  return 1;
}

/* Subroutine of extract_normal.  */

static CGEN_INLINE long
extract_1 (CGEN_CPU_DESC cd,
	   CGEN_EXTRACT_INFO *ex_info ATTRIBUTE_UNUSED,
	   int start,
	   int length,
	   int word_length,
	   unsigned char *bufp,
	   bfd_vma pc ATTRIBUTE_UNUSED)
{
  unsigned long x;
  int shift;

  x = cgen_get_insn_value (cd, bufp, word_length);

  if (CGEN_INSN_LSB0_P)
    shift = (start + 1) - length;
  else
    shift = (word_length - (start + length));
  return x >> shift;
}

#endif /* ! CGEN_INT_INSN_P */

/* Default extraction routine.

   INSN_VALUE is the first base_insn_bitsize bits of the insn in host order,
   or sometimes less for cases like the m32r where the base insn size is 32
   but some insns are 16 bits.
   ATTRS is a mask of the boolean attributes.  We only need `SIGNED',
   but for generality we take a bitmask of all of them.
   WORD_OFFSET is the offset in bits from the start of the insn of the value.
   WORD_LENGTH is the length of the word in bits in which the value resides.
   START is the starting bit number in the word, architecture origin.
   LENGTH is the length of VALUE in bits.
   TOTAL_LENGTH is the total length of the insn in bits.

   Returns 1 for success, 0 for failure.  */

/* ??? The return code isn't properly used.  wip.  */

/* ??? This doesn't handle bfd_vma's.  Create another function when
   necessary.  */

static int
extract_normal (CGEN_CPU_DESC cd,
#if ! CGEN_INT_INSN_P
		CGEN_EXTRACT_INFO *ex_info,
#else
		CGEN_EXTRACT_INFO *ex_info ATTRIBUTE_UNUSED,
#endif
		CGEN_INSN_INT insn_value,
		unsigned int attrs,
		unsigned int word_offset,
		unsigned int start,
		unsigned int length,
		unsigned int word_length,
		unsigned int total_length,
#if ! CGEN_INT_INSN_P
		bfd_vma pc,
#else
		bfd_vma pc ATTRIBUTE_UNUSED,
#endif
		long *valuep)
{
  long value, mask;

  /* If LENGTH is zero, this operand doesn't contribute to the value
     so give it a standard value of zero.  */
  if (length == 0)
    {
      *valuep = 0;
      return 1;
    }

  if (word_length > 8 * sizeof (CGEN_INSN_INT))
    abort ();

  /* For architectures with insns smaller than the insn-base-bitsize,
     word_length may be too big.  */
  if (cd->min_insn_bitsize < cd->base_insn_bitsize)
    {
      if (word_offset + word_length > total_length)
	word_length = total_length - word_offset;
    }

  /* Does the value reside in INSN_VALUE, and at the right alignment?  */

  if (CGEN_INT_INSN_P || (word_offset == 0 && word_length == total_length))
    {
      if (CGEN_INSN_LSB0_P)
	value = insn_value >> ((word_offset + start + 1) - length);
      else
	value = insn_value >> (total_length - ( word_offset + start + length));
    }

#if ! CGEN_INT_INSN_P

  else
    {
      unsigned char *bufp = ex_info->insn_bytes + word_offset / 8;

      if (word_length > 8 * sizeof (CGEN_INSN_INT))
	abort ();

      if (fill_cache (cd, ex_info, word_offset / 8, word_length / 8, pc) == 0)
	return 0;

      value = extract_1 (cd, ex_info, start, length, word_length, bufp, pc);
    }

#endif /* ! CGEN_INT_INSN_P */

  /* Written this way to avoid undefined behaviour.  */
  mask = (((1L << (length - 1)) - 1) << 1) | 1;

  value &= mask;
  /* sign extend? */
  if (CGEN_BOOL_ATTR (attrs, CGEN_IFLD_SIGNED)
      && (value & (1L << (length - 1))))
    value |= ~mask;

  *valuep = value;

  return 1;
}

/* Default insn extractor.

   INSN_VALUE is the first base_insn_bitsize bits, translated to host order.
   The extracted fields are stored in FIELDS.
   EX_INFO is used to handle reading variable length insns.
   Return the length of the insn in bits, or 0 if no match,
   or -1 if an error occurs fetching data (memory_error_func will have
   been called).  */

static int
extract_insn_normal (CGEN_CPU_DESC cd,
		     const CGEN_INSN *insn,
		     CGEN_EXTRACT_INFO *ex_info,
		     CGEN_INSN_INT insn_value,
		     CGEN_FIELDS *fields,
		     bfd_vma pc)
{
  const CGEN_SYNTAX *syntax = CGEN_INSN_SYNTAX (insn);
  const CGEN_SYNTAX_CHAR_TYPE *syn;

  CGEN_FIELDS_BITSIZE (fields) = CGEN_INSN_BITSIZE (insn);

  CGEN_INIT_EXTRACT (cd);

  for (syn = CGEN_SYNTAX_STRING (syntax); *syn; ++syn)
    {
      int length;

      if (CGEN_SYNTAX_CHAR_P (*syn))
	continue;

      length = (* cd->extract_operand) (cd, CGEN_SYNTAX_FIELD (*syn),
					ex_info, insn_value, fields, pc);
      if (length <= 0)
	return length;
    }

  /* We recognized and successfully extracted this insn.  */
  return CGEN_INSN_BITSIZE (insn);
}

/* Machine generated code added here.  */

const char * vc4_cgen_insert_operand
  (CGEN_CPU_DESC, int, CGEN_FIELDS *, CGEN_INSN_BYTES_PTR, bfd_vma);

/* Main entry point for operand insertion.

   This function is basically just a big switch statement.  Earlier versions
   used tables to look up the function to use, but
   - if the table contains both assembler and disassembler functions then
     the disassembler contains much of the assembler and vice-versa,
   - there's a lot of inlining possibilities as things grow,
   - using a switch statement avoids the function call overhead.

   This function could be moved into `parse_insn_normal', but keeping it
   separate makes clear the interface between `parse_insn_normal' and each of
   the handlers.  It's also needed by GAS to insert operands that couldn't be
   resolved during parsing.  */

const char *
vc4_cgen_insert_operand (CGEN_CPU_DESC cd,
			     int opindex,
			     CGEN_FIELDS * fields,
			     CGEN_INSN_BYTES_PTR buffer,
			     bfd_vma pc ATTRIBUTE_UNUSED)
{
  const char * errmsg = NULL;
  unsigned int total_length = CGEN_FIELDS_BITSIZE (fields);

  switch (opindex)
    {
    case VC4_OPERAND_ACCSZ :
      errmsg = insert_normal (cd, fields->f_op10_9, 0, 0, 10, 2, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ACCSZ32 :
      errmsg = insert_normal (cd, fields->f_op7_6, 0, 0, 7, 2, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ADDCMPBAREG :
      errmsg = insert_normal (cd, fields->f_op7_4, 0, 0, 7, 4, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ADDCMPBIMM :
      errmsg = insert_normal (cd, fields->f_op7_4s, 0|(1<<CGEN_IFLD_SIGNED), 0, 7, 4, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ADDSPOFFSET :
      {
        long value = fields->f_addspoffset;
        value = ((UINT) (value) >> (2));
        errmsg = insert_normal (cd, value, 0, 0, 10, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_ALU16DREG :
      errmsg = insert_normal (cd, fields->f_op3_0, 0, 0, 3, 4, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU16IMM :
      errmsg = insert_normal (cd, fields->f_op8_4, 0, 0, 8, 5, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU16IMM_SHL3 :
      {
        long value = fields->f_op8_4_shl3;
        value = ((UINT) (value) >> (3));
        errmsg = insert_normal (cd, value, 0, 0, 8, 5, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_ALU16SREG :
      errmsg = insert_normal (cd, fields->f_op7_4, 0, 0, 7, 4, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU32AREG :
      errmsg = insert_normal (cd, fields->f_op31_27, 0, 16, 15, 5, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU32BREG :
      errmsg = insert_normal (cd, fields->f_op20_16, 0, 16, 4, 5, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU32COND :
      errmsg = insert_normal (cd, fields->f_op26_23, 0, 16, 10, 4, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU32DREG :
      errmsg = insert_normal (cd, fields->f_op4_0, 0, 0, 4, 5, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU48IDREG :
      errmsg = insert_normal (cd, fields->f_op4_0, 0, 0, 4, 5, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU48IMMU :
      errmsg = insert_normal (cd, fields->f_op47_16, 0, 16, 31, 32, 32, total_length, buffer);
      break;
    case VC4_OPERAND_ALU48ISREG :
      errmsg = insert_normal (cd, fields->f_op9_5, 0, 0, 9, 5, 16, total_length, buffer);
      break;
    case VC4_OPERAND_ALU48PCREL :
      {
        long value = fields->f_pcrel32_48;
        value = ((value) - (pc));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 31, 32, 32, total_length, buffer);
      }
      break;
    case VC4_OPERAND_BCC32IMM :
      errmsg = insert_normal (cd, fields->f_op29_24, 0, 16, 13, 6, 16, total_length, buffer);
      break;
    case VC4_OPERAND_BCC32SREG :
      errmsg = insert_normal (cd, fields->f_op29_26, 0, 16, 13, 4, 16, total_length, buffer);
      break;
    case VC4_OPERAND_CONDCODE :
      errmsg = insert_normal (cd, fields->f_op10_7, 0, 0, 10, 4, 16, total_length, buffer);
      break;
    case VC4_OPERAND_CONDCODEBCC32 :
      errmsg = insert_normal (cd, fields->f_op11_8, 0, 0, 11, 4, 16, total_length, buffer);
      break;
    case VC4_OPERAND_FLOATIMM6 :
      errmsg = insert_normal (cd, fields->f_op21_16, 0, 16, 5, 6, 16, total_length, buffer);
      break;
    case VC4_OPERAND_IMM6 :
      errmsg = insert_normal (cd, fields->f_op21_16s, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      break;
    case VC4_OPERAND_IMM6_SHL1 :
      {
        long value = fields->f_op21_16s_shl1;
        value = ((INT) (value) >> (1));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_IMM6_SHL2 :
      {
        long value = fields->f_op21_16s_shl2;
        value = ((INT) (value) >> (2));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_IMM6_SHL3 :
      {
        long value = fields->f_op21_16s_shl3;
        value = ((INT) (value) >> (3));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_IMM6_SHL4 :
      {
        long value = fields->f_op21_16s_shl4;
        value = ((INT) (value) >> (4));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_IMM6_SHL5 :
      {
        long value = fields->f_op21_16s_shl5;
        value = ((INT) (value) >> (5));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_IMM6_SHL6 :
      {
        long value = fields->f_op21_16s_shl6;
        value = ((INT) (value) >> (6));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_IMM6_SHL7 :
      {
        long value = fields->f_op21_16s_shl7;
        value = ((INT) (value) >> (7));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_IMM6_SHL8 :
      {
        long value = fields->f_op21_16s_shl8;
        value = ((INT) (value) >> (8));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_LDSTOFF :
      {
        long value = fields->f_ldstoff;
        value = ((UINT) (value) >> (2));
        errmsg = insert_normal (cd, value, 0, 0, 11, 4, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_MEM48OFFSET27 :
      errmsg = insert_normal (cd, fields->f_offset27_48, 0|(1<<CGEN_IFLD_SIGNED), 16, 26, 27, 32, total_length, buffer);
      break;
    case VC4_OPERAND_MEM48PCREL27 :
      {
        long value = fields->f_pcrel27_48;
        value = ((value) - (pc));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 26, 27, 32, total_length, buffer);
      }
      break;
    case VC4_OPERAND_MEM48SREG :
      errmsg = insert_normal (cd, fields->f_op47_43, 0, 16, 31, 5, 32, total_length, buffer);
      break;
    case VC4_OPERAND_OFF16BASEREG :
      errmsg = insert_normal (cd, fields->f_op9_8, 0, 0, 9, 2, 16, total_length, buffer);
      break;
    case VC4_OPERAND_OFFSET12 :
      {
{
  FLD (f_op8) = ((((USI) (FLD (f_offset12)) >> (11))) & (1));
  FLD (f_op26_16) = ((FLD (f_offset12)) & (2047));
}
        errmsg = insert_normal (cd, fields->f_op8, 0, 0, 8, 1, 16, total_length, buffer);
        if (errmsg)
          break;
        errmsg = insert_normal (cd, fields->f_op26_16, 0, 16, 10, 11, 16, total_length, buffer);
        if (errmsg)
          break;
      }
      break;
    case VC4_OPERAND_OFFSET16 :
      errmsg = insert_normal (cd, fields->f_op31_16s, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, buffer);
      break;
    case VC4_OPERAND_OFFSET16_SHL1 :
      {
        long value = fields->f_op31_16s_shl1;
        value = ((UINT) (value) >> (1));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_OFFSET16_SHL2 :
      {
        long value = fields->f_op31_16s_shl2;
        value = ((UINT) (value) >> (2));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_OFFSET16_SHL3 :
      {
        long value = fields->f_op31_16s_shl3;
        value = ((UINT) (value) >> (3));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_OFFSET16_SHL4 :
      {
        long value = fields->f_op31_16s_shl4;
        value = ((UINT) (value) >> (4));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_OFFSET23BITS :
      {
        fields->f_offset23bits = ((SI) (((fields->f_offset23bits) - (pc))) >> (1));
{
  FLD (f_op6_0) = ((((USI) (FLD (f_offset23bits)) >> (16))) & (127));
  FLD (f_op31_16) = ((FLD (f_offset23bits)) & (65535));
}
        errmsg = insert_normal (cd, fields->f_op6_0, 0, 0, 6, 7, 16, total_length, buffer);
        if (errmsg)
          break;
        errmsg = insert_normal (cd, fields->f_op31_16, 0, 16, 15, 16, 16, total_length, buffer);
        if (errmsg)
          break;
      }
      break;
    case VC4_OPERAND_OFFSET27BITS :
      {
        fields->f_offset27bits = ((SI) (((fields->f_offset27bits) - (pc))) >> (1));
{
  FLD (f_op11_8) = ((((USI) (FLD (f_offset27bits)) >> (23))) & (15));
  FLD (f_op6_0) = ((((USI) (FLD (f_offset27bits)) >> (16))) & (127));
  FLD (f_op31_16) = ((FLD (f_offset27bits)) & (65535));
}
        errmsg = insert_normal (cd, fields->f_op11_8, 0, 0, 11, 4, 16, total_length, buffer);
        if (errmsg)
          break;
        errmsg = insert_normal (cd, fields->f_op6_0, 0, 0, 6, 7, 16, total_length, buffer);
        if (errmsg)
          break;
        errmsg = insert_normal (cd, fields->f_op31_16, 0, 16, 15, 16, 16, total_length, buffer);
        if (errmsg)
          break;
      }
      break;
    case VC4_OPERAND_OPERAND10_0 :
      errmsg = insert_normal (cd, fields->f_op10_0, 0, 0, 10, 11, 16, total_length, buffer);
      break;
    case VC4_OPERAND_OPERAND47_16 :
      errmsg = insert_normal (cd, fields->f_op47_16, 0, 16, 31, 32, 32, total_length, buffer);
      break;
    case VC4_OPERAND_OPERAND79_48 :
      errmsg = insert_normal (cd, fields->f_op79_48, 0, 48, 31, 32, 32, total_length, buffer);
      break;
    case VC4_OPERAND_PCREL10BITS :
      {
        long value = fields->f_pcrel10;
        value = ((SI) (((value) - (pc))) >> (1));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 9, 10, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_PCREL16 :
      {
        long value = fields->f_pcrel16;
        value = ((value) - (pc));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 15, 16, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_PCREL8BITS :
      {
        long value = fields->f_pcrel8;
        value = ((SI) (((value) - (pc))) >> (1));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 7, 8, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_PCRELCC :
      {
        long value = fields->f_pcrelcc;
        value = ((SI) (((value) - (pc))) >> (1));
        errmsg = insert_normal (cd, value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 0, 6, 7, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_PPENDREG0 :
      {
        long value = fields->f_op4_0_base_0;
        value = ((((value) - (0))) & (31));
        errmsg = insert_normal (cd, value, 0, 0, 4, 5, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_PPENDREG16 :
      {
        long value = fields->f_op4_0_base_16;
        value = ((((value) - (16))) & (31));
        errmsg = insert_normal (cd, value, 0, 0, 4, 5, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_PPENDREG24 :
      {
        long value = fields->f_op4_0_base_24;
        value = ((((value) - (24))) & (31));
        errmsg = insert_normal (cd, value, 0, 0, 4, 5, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_PPENDREG6 :
      {
        long value = fields->f_op4_0_base_6;
        value = ((((value) - (6))) & (31));
        errmsg = insert_normal (cd, value, 0, 0, 4, 5, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_PPSTARTREG :
      errmsg = insert_normal (cd, fields->f_op6_5, 0, 0, 6, 2, 16, total_length, buffer);
      break;
    case VC4_OPERAND_SPOFFSET :
      {
        long value = fields->f_spoffset;
        value = ((UINT) (value) >> (2));
        errmsg = insert_normal (cd, value, 0, 0, 8, 5, 16, total_length, buffer);
      }
      break;
    case VC4_OPERAND_SWI_IMM :
      errmsg = insert_normal (cd, fields->f_op5_0, 0, 0, 5, 6, 16, total_length, buffer);
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while building insn.\n"),
	       opindex);
      abort ();
  }

  return errmsg;
}

int vc4_cgen_extract_operand
  (CGEN_CPU_DESC, int, CGEN_EXTRACT_INFO *, CGEN_INSN_INT, CGEN_FIELDS *, bfd_vma);

/* Main entry point for operand extraction.
   The result is <= 0 for error, >0 for success.
   ??? Actual values aren't well defined right now.

   This function is basically just a big switch statement.  Earlier versions
   used tables to look up the function to use, but
   - if the table contains both assembler and disassembler functions then
     the disassembler contains much of the assembler and vice-versa,
   - there's a lot of inlining possibilities as things grow,
   - using a switch statement avoids the function call overhead.

   This function could be moved into `print_insn_normal', but keeping it
   separate makes clear the interface between `print_insn_normal' and each of
   the handlers.  */

int
vc4_cgen_extract_operand (CGEN_CPU_DESC cd,
			     int opindex,
			     CGEN_EXTRACT_INFO *ex_info,
			     CGEN_INSN_INT insn_value,
			     CGEN_FIELDS * fields,
			     bfd_vma pc)
{
  /* Assume success (for those operands that are nops).  */
  int length = 1;
  unsigned int total_length = CGEN_FIELDS_BITSIZE (fields);

  switch (opindex)
    {
    case VC4_OPERAND_ACCSZ :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 10, 2, 16, total_length, pc, & fields->f_op10_9);
      break;
    case VC4_OPERAND_ACCSZ32 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 7, 2, 16, total_length, pc, & fields->f_op7_6);
      break;
    case VC4_OPERAND_ADDCMPBAREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 7, 4, 16, total_length, pc, & fields->f_op7_4);
      break;
    case VC4_OPERAND_ADDCMPBIMM :
      length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 0, 7, 4, 16, total_length, pc, & fields->f_op7_4s);
      break;
    case VC4_OPERAND_ADDSPOFFSET :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 10, 6, 16, total_length, pc, & value);
        value = ((value) << (2));
        fields->f_addspoffset = value;
      }
      break;
    case VC4_OPERAND_ALU16DREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 3, 4, 16, total_length, pc, & fields->f_op3_0);
      break;
    case VC4_OPERAND_ALU16IMM :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 8, 5, 16, total_length, pc, & fields->f_op8_4);
      break;
    case VC4_OPERAND_ALU16IMM_SHL3 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 8, 5, 16, total_length, pc, & value);
        value = ((value) << (3));
        fields->f_op8_4_shl3 = value;
      }
      break;
    case VC4_OPERAND_ALU16SREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 7, 4, 16, total_length, pc, & fields->f_op7_4);
      break;
    case VC4_OPERAND_ALU32AREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 15, 5, 16, total_length, pc, & fields->f_op31_27);
      break;
    case VC4_OPERAND_ALU32BREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 4, 5, 16, total_length, pc, & fields->f_op20_16);
      break;
    case VC4_OPERAND_ALU32COND :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 10, 4, 16, total_length, pc, & fields->f_op26_23);
      break;
    case VC4_OPERAND_ALU32DREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & fields->f_op4_0);
      break;
    case VC4_OPERAND_ALU48IDREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & fields->f_op4_0);
      break;
    case VC4_OPERAND_ALU48IMMU :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 31, 32, 32, total_length, pc, & fields->f_op47_16);
      break;
    case VC4_OPERAND_ALU48ISREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 5, 16, total_length, pc, & fields->f_op9_5);
      break;
    case VC4_OPERAND_ALU48PCREL :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 31, 32, 32, total_length, pc, & value);
        value = ((pc) + (value));
        fields->f_pcrel32_48 = value;
      }
      break;
    case VC4_OPERAND_BCC32IMM :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 13, 6, 16, total_length, pc, & fields->f_op29_24);
      break;
    case VC4_OPERAND_BCC32SREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 13, 4, 16, total_length, pc, & fields->f_op29_26);
      break;
    case VC4_OPERAND_CONDCODE :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 10, 4, 16, total_length, pc, & fields->f_op10_7);
      break;
    case VC4_OPERAND_CONDCODEBCC32 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 11, 4, 16, total_length, pc, & fields->f_op11_8);
      break;
    case VC4_OPERAND_FLOATIMM6 :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 5, 6, 16, total_length, pc, & fields->f_op21_16);
      break;
    case VC4_OPERAND_IMM6 :
      length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & fields->f_op21_16s);
      break;
    case VC4_OPERAND_IMM6_SHL1 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & value);
        value = ((value) << (1));
        fields->f_op21_16s_shl1 = value;
      }
      break;
    case VC4_OPERAND_IMM6_SHL2 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & value);
        value = ((value) << (2));
        fields->f_op21_16s_shl2 = value;
      }
      break;
    case VC4_OPERAND_IMM6_SHL3 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & value);
        value = ((value) << (3));
        fields->f_op21_16s_shl3 = value;
      }
      break;
    case VC4_OPERAND_IMM6_SHL4 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & value);
        value = ((value) << (4));
        fields->f_op21_16s_shl4 = value;
      }
      break;
    case VC4_OPERAND_IMM6_SHL5 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & value);
        value = ((value) << (5));
        fields->f_op21_16s_shl5 = value;
      }
      break;
    case VC4_OPERAND_IMM6_SHL6 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & value);
        value = ((value) << (6));
        fields->f_op21_16s_shl6 = value;
      }
      break;
    case VC4_OPERAND_IMM6_SHL7 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & value);
        value = ((value) << (7));
        fields->f_op21_16s_shl7 = value;
      }
      break;
    case VC4_OPERAND_IMM6_SHL8 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 5, 6, 16, total_length, pc, & value);
        value = ((value) << (8));
        fields->f_op21_16s_shl8 = value;
      }
      break;
    case VC4_OPERAND_LDSTOFF :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 11, 4, 16, total_length, pc, & value);
        value = ((value) << (2));
        fields->f_ldstoff = value;
      }
      break;
    case VC4_OPERAND_MEM48OFFSET27 :
      length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 26, 27, 32, total_length, pc, & fields->f_offset27_48);
      break;
    case VC4_OPERAND_MEM48PCREL27 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 26, 27, 32, total_length, pc, & value);
        value = ((pc) + (value));
        fields->f_pcrel27_48 = value;
      }
      break;
    case VC4_OPERAND_MEM48SREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 31, 5, 32, total_length, pc, & fields->f_op47_43);
      break;
    case VC4_OPERAND_OFF16BASEREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 9, 2, 16, total_length, pc, & fields->f_op9_8);
      break;
    case VC4_OPERAND_OFFSET12 :
      {
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 8, 1, 16, total_length, pc, & fields->f_op8);
        if (length <= 0) break;
        length = extract_normal (cd, ex_info, insn_value, 0, 16, 10, 11, 16, total_length, pc, & fields->f_op26_16);
        if (length <= 0) break;
{
  FLD (f_offset12) = ((((FLD (f_op8)) << (11))) | (FLD (f_op26_16)));
}
      }
      break;
    case VC4_OPERAND_OFFSET16 :
      length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, pc, & fields->f_op31_16s);
      break;
    case VC4_OPERAND_OFFSET16_SHL1 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, pc, & value);
        value = ((value) << (1));
        fields->f_op31_16s_shl1 = value;
      }
      break;
    case VC4_OPERAND_OFFSET16_SHL2 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, pc, & value);
        value = ((value) << (2));
        fields->f_op31_16s_shl2 = value;
      }
      break;
    case VC4_OPERAND_OFFSET16_SHL3 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, pc, & value);
        value = ((value) << (3));
        fields->f_op31_16s_shl3 = value;
      }
      break;
    case VC4_OPERAND_OFFSET16_SHL4 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED), 16, 15, 16, 16, total_length, pc, & value);
        value = ((value) << (4));
        fields->f_op31_16s_shl4 = value;
      }
      break;
    case VC4_OPERAND_OFFSET23BITS :
      {
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 6, 7, 16, total_length, pc, & fields->f_op6_0);
        if (length <= 0) break;
        length = extract_normal (cd, ex_info, insn_value, 0, 16, 15, 16, 16, total_length, pc, & fields->f_op31_16);
        if (length <= 0) break;
{
  FLD (f_offset23bits) = ((((((FLD (f_op6_0)) << (16))) | (FLD (f_op31_16)))) & (8388607));
}
        fields->f_offset23bits = ((pc) + (((fields->f_offset23bits) << (1))));
      }
      break;
    case VC4_OPERAND_OFFSET27BITS :
      {
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 11, 4, 16, total_length, pc, & fields->f_op11_8);
        if (length <= 0) break;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 6, 7, 16, total_length, pc, & fields->f_op6_0);
        if (length <= 0) break;
        length = extract_normal (cd, ex_info, insn_value, 0, 16, 15, 16, 16, total_length, pc, & fields->f_op31_16);
        if (length <= 0) break;
{
  FLD (f_offset27bits) = ((((((FLD (f_op11_8)) << (23))) | (((FLD (f_op6_0)) << (16))))) | (FLD (f_op31_16)));
}
        fields->f_offset27bits = ((pc) + (((fields->f_offset27bits) << (1))));
      }
      break;
    case VC4_OPERAND_OPERAND10_0 :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 10, 11, 16, total_length, pc, & fields->f_op10_0);
      break;
    case VC4_OPERAND_OPERAND47_16 :
      length = extract_normal (cd, ex_info, insn_value, 0, 16, 31, 32, 32, total_length, pc, & fields->f_op47_16);
      break;
    case VC4_OPERAND_OPERAND79_48 :
      length = extract_normal (cd, ex_info, insn_value, 0, 48, 31, 32, 32, total_length, pc, & fields->f_op79_48);
      break;
    case VC4_OPERAND_PCREL10BITS :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 9, 10, 16, total_length, pc, & value);
        value = ((pc) + (((value) << (1))));
        fields->f_pcrel10 = value;
      }
      break;
    case VC4_OPERAND_PCREL16 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 15, 16, 16, total_length, pc, & value);
        value = ((pc) + (value));
        fields->f_pcrel16 = value;
      }
      break;
    case VC4_OPERAND_PCREL8BITS :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 16, 7, 8, 16, total_length, pc, & value);
        value = ((pc) + (((value) << (1))));
        fields->f_pcrel8 = value;
      }
      break;
    case VC4_OPERAND_PCRELCC :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0|(1<<CGEN_IFLD_SIGNED)|(1<<CGEN_IFLD_PCREL_ADDR), 0, 6, 7, 16, total_length, pc, & value);
        value = ((pc) + (((value) << (1))));
        fields->f_pcrelcc = value;
      }
      break;
    case VC4_OPERAND_PPENDREG0 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & value);
        value = ((((value) + (0))) & (31));
        fields->f_op4_0_base_0 = value;
      }
      break;
    case VC4_OPERAND_PPENDREG16 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & value);
        value = ((((value) + (16))) & (31));
        fields->f_op4_0_base_16 = value;
      }
      break;
    case VC4_OPERAND_PPENDREG24 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & value);
        value = ((((value) + (24))) & (31));
        fields->f_op4_0_base_24 = value;
      }
      break;
    case VC4_OPERAND_PPENDREG6 :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 4, 5, 16, total_length, pc, & value);
        value = ((((value) + (6))) & (31));
        fields->f_op4_0_base_6 = value;
      }
      break;
    case VC4_OPERAND_PPSTARTREG :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 6, 2, 16, total_length, pc, & fields->f_op6_5);
      break;
    case VC4_OPERAND_SPOFFSET :
      {
        long value;
        length = extract_normal (cd, ex_info, insn_value, 0, 0, 8, 5, 16, total_length, pc, & value);
        value = ((value) << (2));
        fields->f_spoffset = value;
      }
      break;
    case VC4_OPERAND_SWI_IMM :
      length = extract_normal (cd, ex_info, insn_value, 0, 0, 5, 6, 16, total_length, pc, & fields->f_op5_0);
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while decoding insn.\n"),
	       opindex);
      abort ();
    }

  return length;
}

cgen_insert_fn * const vc4_cgen_insert_handlers[] = 
{
  insert_insn_normal,
};

cgen_extract_fn * const vc4_cgen_extract_handlers[] = 
{
  extract_insn_normal,
};

int vc4_cgen_get_int_operand     (CGEN_CPU_DESC, int, const CGEN_FIELDS *);
bfd_vma vc4_cgen_get_vma_operand (CGEN_CPU_DESC, int, const CGEN_FIELDS *);

/* Getting values from cgen_fields is handled by a collection of functions.
   They are distinguished by the type of the VALUE argument they return.
   TODO: floating point, inlining support, remove cases where result type
   not appropriate.  */

int
vc4_cgen_get_int_operand (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
			     int opindex,
			     const CGEN_FIELDS * fields)
{
  int value;

  switch (opindex)
    {
    case VC4_OPERAND_ACCSZ :
      value = fields->f_op10_9;
      break;
    case VC4_OPERAND_ACCSZ32 :
      value = fields->f_op7_6;
      break;
    case VC4_OPERAND_ADDCMPBAREG :
      value = fields->f_op7_4;
      break;
    case VC4_OPERAND_ADDCMPBIMM :
      value = fields->f_op7_4s;
      break;
    case VC4_OPERAND_ADDSPOFFSET :
      value = fields->f_addspoffset;
      break;
    case VC4_OPERAND_ALU16DREG :
      value = fields->f_op3_0;
      break;
    case VC4_OPERAND_ALU16IMM :
      value = fields->f_op8_4;
      break;
    case VC4_OPERAND_ALU16IMM_SHL3 :
      value = fields->f_op8_4_shl3;
      break;
    case VC4_OPERAND_ALU16SREG :
      value = fields->f_op7_4;
      break;
    case VC4_OPERAND_ALU32AREG :
      value = fields->f_op31_27;
      break;
    case VC4_OPERAND_ALU32BREG :
      value = fields->f_op20_16;
      break;
    case VC4_OPERAND_ALU32COND :
      value = fields->f_op26_23;
      break;
    case VC4_OPERAND_ALU32DREG :
      value = fields->f_op4_0;
      break;
    case VC4_OPERAND_ALU48IDREG :
      value = fields->f_op4_0;
      break;
    case VC4_OPERAND_ALU48IMMU :
      value = fields->f_op47_16;
      break;
    case VC4_OPERAND_ALU48ISREG :
      value = fields->f_op9_5;
      break;
    case VC4_OPERAND_ALU48PCREL :
      value = fields->f_pcrel32_48;
      break;
    case VC4_OPERAND_BCC32IMM :
      value = fields->f_op29_24;
      break;
    case VC4_OPERAND_BCC32SREG :
      value = fields->f_op29_26;
      break;
    case VC4_OPERAND_CONDCODE :
      value = fields->f_op10_7;
      break;
    case VC4_OPERAND_CONDCODEBCC32 :
      value = fields->f_op11_8;
      break;
    case VC4_OPERAND_FLOATIMM6 :
      value = fields->f_op21_16;
      break;
    case VC4_OPERAND_IMM6 :
      value = fields->f_op21_16s;
      break;
    case VC4_OPERAND_IMM6_SHL1 :
      value = fields->f_op21_16s_shl1;
      break;
    case VC4_OPERAND_IMM6_SHL2 :
      value = fields->f_op21_16s_shl2;
      break;
    case VC4_OPERAND_IMM6_SHL3 :
      value = fields->f_op21_16s_shl3;
      break;
    case VC4_OPERAND_IMM6_SHL4 :
      value = fields->f_op21_16s_shl4;
      break;
    case VC4_OPERAND_IMM6_SHL5 :
      value = fields->f_op21_16s_shl5;
      break;
    case VC4_OPERAND_IMM6_SHL6 :
      value = fields->f_op21_16s_shl6;
      break;
    case VC4_OPERAND_IMM6_SHL7 :
      value = fields->f_op21_16s_shl7;
      break;
    case VC4_OPERAND_IMM6_SHL8 :
      value = fields->f_op21_16s_shl8;
      break;
    case VC4_OPERAND_LDSTOFF :
      value = fields->f_ldstoff;
      break;
    case VC4_OPERAND_MEM48OFFSET27 :
      value = fields->f_offset27_48;
      break;
    case VC4_OPERAND_MEM48PCREL27 :
      value = fields->f_pcrel27_48;
      break;
    case VC4_OPERAND_MEM48SREG :
      value = fields->f_op47_43;
      break;
    case VC4_OPERAND_OFF16BASEREG :
      value = fields->f_op9_8;
      break;
    case VC4_OPERAND_OFFSET12 :
      value = fields->f_offset12;
      break;
    case VC4_OPERAND_OFFSET16 :
      value = fields->f_op31_16s;
      break;
    case VC4_OPERAND_OFFSET16_SHL1 :
      value = fields->f_op31_16s_shl1;
      break;
    case VC4_OPERAND_OFFSET16_SHL2 :
      value = fields->f_op31_16s_shl2;
      break;
    case VC4_OPERAND_OFFSET16_SHL3 :
      value = fields->f_op31_16s_shl3;
      break;
    case VC4_OPERAND_OFFSET16_SHL4 :
      value = fields->f_op31_16s_shl4;
      break;
    case VC4_OPERAND_OFFSET23BITS :
      value = fields->f_offset23bits;
      break;
    case VC4_OPERAND_OFFSET27BITS :
      value = fields->f_offset27bits;
      break;
    case VC4_OPERAND_OPERAND10_0 :
      value = fields->f_op10_0;
      break;
    case VC4_OPERAND_OPERAND47_16 :
      value = fields->f_op47_16;
      break;
    case VC4_OPERAND_OPERAND79_48 :
      value = fields->f_op79_48;
      break;
    case VC4_OPERAND_PCREL10BITS :
      value = fields->f_pcrel10;
      break;
    case VC4_OPERAND_PCREL16 :
      value = fields->f_pcrel16;
      break;
    case VC4_OPERAND_PCREL8BITS :
      value = fields->f_pcrel8;
      break;
    case VC4_OPERAND_PCRELCC :
      value = fields->f_pcrelcc;
      break;
    case VC4_OPERAND_PPENDREG0 :
      value = fields->f_op4_0_base_0;
      break;
    case VC4_OPERAND_PPENDREG16 :
      value = fields->f_op4_0_base_16;
      break;
    case VC4_OPERAND_PPENDREG24 :
      value = fields->f_op4_0_base_24;
      break;
    case VC4_OPERAND_PPENDREG6 :
      value = fields->f_op4_0_base_6;
      break;
    case VC4_OPERAND_PPSTARTREG :
      value = fields->f_op6_5;
      break;
    case VC4_OPERAND_SPOFFSET :
      value = fields->f_spoffset;
      break;
    case VC4_OPERAND_SWI_IMM :
      value = fields->f_op5_0;
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while getting int operand.\n"),
		       opindex);
      abort ();
  }

  return value;
}

bfd_vma
vc4_cgen_get_vma_operand (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
			     int opindex,
			     const CGEN_FIELDS * fields)
{
  bfd_vma value;

  switch (opindex)
    {
    case VC4_OPERAND_ACCSZ :
      value = fields->f_op10_9;
      break;
    case VC4_OPERAND_ACCSZ32 :
      value = fields->f_op7_6;
      break;
    case VC4_OPERAND_ADDCMPBAREG :
      value = fields->f_op7_4;
      break;
    case VC4_OPERAND_ADDCMPBIMM :
      value = fields->f_op7_4s;
      break;
    case VC4_OPERAND_ADDSPOFFSET :
      value = fields->f_addspoffset;
      break;
    case VC4_OPERAND_ALU16DREG :
      value = fields->f_op3_0;
      break;
    case VC4_OPERAND_ALU16IMM :
      value = fields->f_op8_4;
      break;
    case VC4_OPERAND_ALU16IMM_SHL3 :
      value = fields->f_op8_4_shl3;
      break;
    case VC4_OPERAND_ALU16SREG :
      value = fields->f_op7_4;
      break;
    case VC4_OPERAND_ALU32AREG :
      value = fields->f_op31_27;
      break;
    case VC4_OPERAND_ALU32BREG :
      value = fields->f_op20_16;
      break;
    case VC4_OPERAND_ALU32COND :
      value = fields->f_op26_23;
      break;
    case VC4_OPERAND_ALU32DREG :
      value = fields->f_op4_0;
      break;
    case VC4_OPERAND_ALU48IDREG :
      value = fields->f_op4_0;
      break;
    case VC4_OPERAND_ALU48IMMU :
      value = fields->f_op47_16;
      break;
    case VC4_OPERAND_ALU48ISREG :
      value = fields->f_op9_5;
      break;
    case VC4_OPERAND_ALU48PCREL :
      value = fields->f_pcrel32_48;
      break;
    case VC4_OPERAND_BCC32IMM :
      value = fields->f_op29_24;
      break;
    case VC4_OPERAND_BCC32SREG :
      value = fields->f_op29_26;
      break;
    case VC4_OPERAND_CONDCODE :
      value = fields->f_op10_7;
      break;
    case VC4_OPERAND_CONDCODEBCC32 :
      value = fields->f_op11_8;
      break;
    case VC4_OPERAND_FLOATIMM6 :
      value = fields->f_op21_16;
      break;
    case VC4_OPERAND_IMM6 :
      value = fields->f_op21_16s;
      break;
    case VC4_OPERAND_IMM6_SHL1 :
      value = fields->f_op21_16s_shl1;
      break;
    case VC4_OPERAND_IMM6_SHL2 :
      value = fields->f_op21_16s_shl2;
      break;
    case VC4_OPERAND_IMM6_SHL3 :
      value = fields->f_op21_16s_shl3;
      break;
    case VC4_OPERAND_IMM6_SHL4 :
      value = fields->f_op21_16s_shl4;
      break;
    case VC4_OPERAND_IMM6_SHL5 :
      value = fields->f_op21_16s_shl5;
      break;
    case VC4_OPERAND_IMM6_SHL6 :
      value = fields->f_op21_16s_shl6;
      break;
    case VC4_OPERAND_IMM6_SHL7 :
      value = fields->f_op21_16s_shl7;
      break;
    case VC4_OPERAND_IMM6_SHL8 :
      value = fields->f_op21_16s_shl8;
      break;
    case VC4_OPERAND_LDSTOFF :
      value = fields->f_ldstoff;
      break;
    case VC4_OPERAND_MEM48OFFSET27 :
      value = fields->f_offset27_48;
      break;
    case VC4_OPERAND_MEM48PCREL27 :
      value = fields->f_pcrel27_48;
      break;
    case VC4_OPERAND_MEM48SREG :
      value = fields->f_op47_43;
      break;
    case VC4_OPERAND_OFF16BASEREG :
      value = fields->f_op9_8;
      break;
    case VC4_OPERAND_OFFSET12 :
      value = fields->f_offset12;
      break;
    case VC4_OPERAND_OFFSET16 :
      value = fields->f_op31_16s;
      break;
    case VC4_OPERAND_OFFSET16_SHL1 :
      value = fields->f_op31_16s_shl1;
      break;
    case VC4_OPERAND_OFFSET16_SHL2 :
      value = fields->f_op31_16s_shl2;
      break;
    case VC4_OPERAND_OFFSET16_SHL3 :
      value = fields->f_op31_16s_shl3;
      break;
    case VC4_OPERAND_OFFSET16_SHL4 :
      value = fields->f_op31_16s_shl4;
      break;
    case VC4_OPERAND_OFFSET23BITS :
      value = fields->f_offset23bits;
      break;
    case VC4_OPERAND_OFFSET27BITS :
      value = fields->f_offset27bits;
      break;
    case VC4_OPERAND_OPERAND10_0 :
      value = fields->f_op10_0;
      break;
    case VC4_OPERAND_OPERAND47_16 :
      value = fields->f_op47_16;
      break;
    case VC4_OPERAND_OPERAND79_48 :
      value = fields->f_op79_48;
      break;
    case VC4_OPERAND_PCREL10BITS :
      value = fields->f_pcrel10;
      break;
    case VC4_OPERAND_PCREL16 :
      value = fields->f_pcrel16;
      break;
    case VC4_OPERAND_PCREL8BITS :
      value = fields->f_pcrel8;
      break;
    case VC4_OPERAND_PCRELCC :
      value = fields->f_pcrelcc;
      break;
    case VC4_OPERAND_PPENDREG0 :
      value = fields->f_op4_0_base_0;
      break;
    case VC4_OPERAND_PPENDREG16 :
      value = fields->f_op4_0_base_16;
      break;
    case VC4_OPERAND_PPENDREG24 :
      value = fields->f_op4_0_base_24;
      break;
    case VC4_OPERAND_PPENDREG6 :
      value = fields->f_op4_0_base_6;
      break;
    case VC4_OPERAND_PPSTARTREG :
      value = fields->f_op6_5;
      break;
    case VC4_OPERAND_SPOFFSET :
      value = fields->f_spoffset;
      break;
    case VC4_OPERAND_SWI_IMM :
      value = fields->f_op5_0;
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while getting vma operand.\n"),
		       opindex);
      abort ();
  }

  return value;
}

void vc4_cgen_set_int_operand  (CGEN_CPU_DESC, int, CGEN_FIELDS *, int);
void vc4_cgen_set_vma_operand  (CGEN_CPU_DESC, int, CGEN_FIELDS *, bfd_vma);

/* Stuffing values in cgen_fields is handled by a collection of functions.
   They are distinguished by the type of the VALUE argument they accept.
   TODO: floating point, inlining support, remove cases where argument type
   not appropriate.  */

void
vc4_cgen_set_int_operand (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
			     int opindex,
			     CGEN_FIELDS * fields,
			     int value)
{
  switch (opindex)
    {
    case VC4_OPERAND_ACCSZ :
      fields->f_op10_9 = value;
      break;
    case VC4_OPERAND_ACCSZ32 :
      fields->f_op7_6 = value;
      break;
    case VC4_OPERAND_ADDCMPBAREG :
      fields->f_op7_4 = value;
      break;
    case VC4_OPERAND_ADDCMPBIMM :
      fields->f_op7_4s = value;
      break;
    case VC4_OPERAND_ADDSPOFFSET :
      fields->f_addspoffset = value;
      break;
    case VC4_OPERAND_ALU16DREG :
      fields->f_op3_0 = value;
      break;
    case VC4_OPERAND_ALU16IMM :
      fields->f_op8_4 = value;
      break;
    case VC4_OPERAND_ALU16IMM_SHL3 :
      fields->f_op8_4_shl3 = value;
      break;
    case VC4_OPERAND_ALU16SREG :
      fields->f_op7_4 = value;
      break;
    case VC4_OPERAND_ALU32AREG :
      fields->f_op31_27 = value;
      break;
    case VC4_OPERAND_ALU32BREG :
      fields->f_op20_16 = value;
      break;
    case VC4_OPERAND_ALU32COND :
      fields->f_op26_23 = value;
      break;
    case VC4_OPERAND_ALU32DREG :
      fields->f_op4_0 = value;
      break;
    case VC4_OPERAND_ALU48IDREG :
      fields->f_op4_0 = value;
      break;
    case VC4_OPERAND_ALU48IMMU :
      fields->f_op47_16 = value;
      break;
    case VC4_OPERAND_ALU48ISREG :
      fields->f_op9_5 = value;
      break;
    case VC4_OPERAND_ALU48PCREL :
      fields->f_pcrel32_48 = value;
      break;
    case VC4_OPERAND_BCC32IMM :
      fields->f_op29_24 = value;
      break;
    case VC4_OPERAND_BCC32SREG :
      fields->f_op29_26 = value;
      break;
    case VC4_OPERAND_CONDCODE :
      fields->f_op10_7 = value;
      break;
    case VC4_OPERAND_CONDCODEBCC32 :
      fields->f_op11_8 = value;
      break;
    case VC4_OPERAND_FLOATIMM6 :
      fields->f_op21_16 = value;
      break;
    case VC4_OPERAND_IMM6 :
      fields->f_op21_16s = value;
      break;
    case VC4_OPERAND_IMM6_SHL1 :
      fields->f_op21_16s_shl1 = value;
      break;
    case VC4_OPERAND_IMM6_SHL2 :
      fields->f_op21_16s_shl2 = value;
      break;
    case VC4_OPERAND_IMM6_SHL3 :
      fields->f_op21_16s_shl3 = value;
      break;
    case VC4_OPERAND_IMM6_SHL4 :
      fields->f_op21_16s_shl4 = value;
      break;
    case VC4_OPERAND_IMM6_SHL5 :
      fields->f_op21_16s_shl5 = value;
      break;
    case VC4_OPERAND_IMM6_SHL6 :
      fields->f_op21_16s_shl6 = value;
      break;
    case VC4_OPERAND_IMM6_SHL7 :
      fields->f_op21_16s_shl7 = value;
      break;
    case VC4_OPERAND_IMM6_SHL8 :
      fields->f_op21_16s_shl8 = value;
      break;
    case VC4_OPERAND_LDSTOFF :
      fields->f_ldstoff = value;
      break;
    case VC4_OPERAND_MEM48OFFSET27 :
      fields->f_offset27_48 = value;
      break;
    case VC4_OPERAND_MEM48PCREL27 :
      fields->f_pcrel27_48 = value;
      break;
    case VC4_OPERAND_MEM48SREG :
      fields->f_op47_43 = value;
      break;
    case VC4_OPERAND_OFF16BASEREG :
      fields->f_op9_8 = value;
      break;
    case VC4_OPERAND_OFFSET12 :
      fields->f_offset12 = value;
      break;
    case VC4_OPERAND_OFFSET16 :
      fields->f_op31_16s = value;
      break;
    case VC4_OPERAND_OFFSET16_SHL1 :
      fields->f_op31_16s_shl1 = value;
      break;
    case VC4_OPERAND_OFFSET16_SHL2 :
      fields->f_op31_16s_shl2 = value;
      break;
    case VC4_OPERAND_OFFSET16_SHL3 :
      fields->f_op31_16s_shl3 = value;
      break;
    case VC4_OPERAND_OFFSET16_SHL4 :
      fields->f_op31_16s_shl4 = value;
      break;
    case VC4_OPERAND_OFFSET23BITS :
      fields->f_offset23bits = value;
      break;
    case VC4_OPERAND_OFFSET27BITS :
      fields->f_offset27bits = value;
      break;
    case VC4_OPERAND_OPERAND10_0 :
      fields->f_op10_0 = value;
      break;
    case VC4_OPERAND_OPERAND47_16 :
      fields->f_op47_16 = value;
      break;
    case VC4_OPERAND_OPERAND79_48 :
      fields->f_op79_48 = value;
      break;
    case VC4_OPERAND_PCREL10BITS :
      fields->f_pcrel10 = value;
      break;
    case VC4_OPERAND_PCREL16 :
      fields->f_pcrel16 = value;
      break;
    case VC4_OPERAND_PCREL8BITS :
      fields->f_pcrel8 = value;
      break;
    case VC4_OPERAND_PCRELCC :
      fields->f_pcrelcc = value;
      break;
    case VC4_OPERAND_PPENDREG0 :
      fields->f_op4_0_base_0 = value;
      break;
    case VC4_OPERAND_PPENDREG16 :
      fields->f_op4_0_base_16 = value;
      break;
    case VC4_OPERAND_PPENDREG24 :
      fields->f_op4_0_base_24 = value;
      break;
    case VC4_OPERAND_PPENDREG6 :
      fields->f_op4_0_base_6 = value;
      break;
    case VC4_OPERAND_PPSTARTREG :
      fields->f_op6_5 = value;
      break;
    case VC4_OPERAND_SPOFFSET :
      fields->f_spoffset = value;
      break;
    case VC4_OPERAND_SWI_IMM :
      fields->f_op5_0 = value;
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while setting int operand.\n"),
		       opindex);
      abort ();
  }
}

void
vc4_cgen_set_vma_operand (CGEN_CPU_DESC cd ATTRIBUTE_UNUSED,
			     int opindex,
			     CGEN_FIELDS * fields,
			     bfd_vma value)
{
  switch (opindex)
    {
    case VC4_OPERAND_ACCSZ :
      fields->f_op10_9 = value;
      break;
    case VC4_OPERAND_ACCSZ32 :
      fields->f_op7_6 = value;
      break;
    case VC4_OPERAND_ADDCMPBAREG :
      fields->f_op7_4 = value;
      break;
    case VC4_OPERAND_ADDCMPBIMM :
      fields->f_op7_4s = value;
      break;
    case VC4_OPERAND_ADDSPOFFSET :
      fields->f_addspoffset = value;
      break;
    case VC4_OPERAND_ALU16DREG :
      fields->f_op3_0 = value;
      break;
    case VC4_OPERAND_ALU16IMM :
      fields->f_op8_4 = value;
      break;
    case VC4_OPERAND_ALU16IMM_SHL3 :
      fields->f_op8_4_shl3 = value;
      break;
    case VC4_OPERAND_ALU16SREG :
      fields->f_op7_4 = value;
      break;
    case VC4_OPERAND_ALU32AREG :
      fields->f_op31_27 = value;
      break;
    case VC4_OPERAND_ALU32BREG :
      fields->f_op20_16 = value;
      break;
    case VC4_OPERAND_ALU32COND :
      fields->f_op26_23 = value;
      break;
    case VC4_OPERAND_ALU32DREG :
      fields->f_op4_0 = value;
      break;
    case VC4_OPERAND_ALU48IDREG :
      fields->f_op4_0 = value;
      break;
    case VC4_OPERAND_ALU48IMMU :
      fields->f_op47_16 = value;
      break;
    case VC4_OPERAND_ALU48ISREG :
      fields->f_op9_5 = value;
      break;
    case VC4_OPERAND_ALU48PCREL :
      fields->f_pcrel32_48 = value;
      break;
    case VC4_OPERAND_BCC32IMM :
      fields->f_op29_24 = value;
      break;
    case VC4_OPERAND_BCC32SREG :
      fields->f_op29_26 = value;
      break;
    case VC4_OPERAND_CONDCODE :
      fields->f_op10_7 = value;
      break;
    case VC4_OPERAND_CONDCODEBCC32 :
      fields->f_op11_8 = value;
      break;
    case VC4_OPERAND_FLOATIMM6 :
      fields->f_op21_16 = value;
      break;
    case VC4_OPERAND_IMM6 :
      fields->f_op21_16s = value;
      break;
    case VC4_OPERAND_IMM6_SHL1 :
      fields->f_op21_16s_shl1 = value;
      break;
    case VC4_OPERAND_IMM6_SHL2 :
      fields->f_op21_16s_shl2 = value;
      break;
    case VC4_OPERAND_IMM6_SHL3 :
      fields->f_op21_16s_shl3 = value;
      break;
    case VC4_OPERAND_IMM6_SHL4 :
      fields->f_op21_16s_shl4 = value;
      break;
    case VC4_OPERAND_IMM6_SHL5 :
      fields->f_op21_16s_shl5 = value;
      break;
    case VC4_OPERAND_IMM6_SHL6 :
      fields->f_op21_16s_shl6 = value;
      break;
    case VC4_OPERAND_IMM6_SHL7 :
      fields->f_op21_16s_shl7 = value;
      break;
    case VC4_OPERAND_IMM6_SHL8 :
      fields->f_op21_16s_shl8 = value;
      break;
    case VC4_OPERAND_LDSTOFF :
      fields->f_ldstoff = value;
      break;
    case VC4_OPERAND_MEM48OFFSET27 :
      fields->f_offset27_48 = value;
      break;
    case VC4_OPERAND_MEM48PCREL27 :
      fields->f_pcrel27_48 = value;
      break;
    case VC4_OPERAND_MEM48SREG :
      fields->f_op47_43 = value;
      break;
    case VC4_OPERAND_OFF16BASEREG :
      fields->f_op9_8 = value;
      break;
    case VC4_OPERAND_OFFSET12 :
      fields->f_offset12 = value;
      break;
    case VC4_OPERAND_OFFSET16 :
      fields->f_op31_16s = value;
      break;
    case VC4_OPERAND_OFFSET16_SHL1 :
      fields->f_op31_16s_shl1 = value;
      break;
    case VC4_OPERAND_OFFSET16_SHL2 :
      fields->f_op31_16s_shl2 = value;
      break;
    case VC4_OPERAND_OFFSET16_SHL3 :
      fields->f_op31_16s_shl3 = value;
      break;
    case VC4_OPERAND_OFFSET16_SHL4 :
      fields->f_op31_16s_shl4 = value;
      break;
    case VC4_OPERAND_OFFSET23BITS :
      fields->f_offset23bits = value;
      break;
    case VC4_OPERAND_OFFSET27BITS :
      fields->f_offset27bits = value;
      break;
    case VC4_OPERAND_OPERAND10_0 :
      fields->f_op10_0 = value;
      break;
    case VC4_OPERAND_OPERAND47_16 :
      fields->f_op47_16 = value;
      break;
    case VC4_OPERAND_OPERAND79_48 :
      fields->f_op79_48 = value;
      break;
    case VC4_OPERAND_PCREL10BITS :
      fields->f_pcrel10 = value;
      break;
    case VC4_OPERAND_PCREL16 :
      fields->f_pcrel16 = value;
      break;
    case VC4_OPERAND_PCREL8BITS :
      fields->f_pcrel8 = value;
      break;
    case VC4_OPERAND_PCRELCC :
      fields->f_pcrelcc = value;
      break;
    case VC4_OPERAND_PPENDREG0 :
      fields->f_op4_0_base_0 = value;
      break;
    case VC4_OPERAND_PPENDREG16 :
      fields->f_op4_0_base_16 = value;
      break;
    case VC4_OPERAND_PPENDREG24 :
      fields->f_op4_0_base_24 = value;
      break;
    case VC4_OPERAND_PPENDREG6 :
      fields->f_op4_0_base_6 = value;
      break;
    case VC4_OPERAND_PPSTARTREG :
      fields->f_op6_5 = value;
      break;
    case VC4_OPERAND_SPOFFSET :
      fields->f_spoffset = value;
      break;
    case VC4_OPERAND_SWI_IMM :
      fields->f_op5_0 = value;
      break;

    default :
      /* xgettext:c-format */
      fprintf (stderr, _("Unrecognized field %d while setting vma operand.\n"),
		       opindex);
      abort ();
  }
}

/* Function to call before using the instruction builder tables.  */

void
vc4_cgen_init_ibld_table (CGEN_CPU_DESC cd)
{
  cd->insert_handlers = & vc4_cgen_insert_handlers[0];
  cd->extract_handlers = & vc4_cgen_extract_handlers[0];

  cd->insert_operand = vc4_cgen_insert_operand;
  cd->extract_operand = vc4_cgen_extract_operand;

  cd->get_int_operand = vc4_cgen_get_int_operand;
  cd->set_int_operand = vc4_cgen_set_int_operand;
  cd->get_vma_operand = vc4_cgen_get_vma_operand;
  cd->set_vma_operand = vc4_cgen_set_vma_operand;
}
