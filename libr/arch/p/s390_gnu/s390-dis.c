/* s390-dis.c -- Disassemble S390 instructions
   Copyright (C) 2000-2021 Free Software Foundation, Inc.
   Contributed by Martin Schwidefsky (schwidefsky@de.ibm.com).

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

#include <stdio.h>
#include "../../include/sysdep.h"
#include "../../include/ansidecl.h"
#include "../../include/opintl.h"
#include "../../include/disas-asm.h"
#include "../../include/opcode/s390.h"
#include "../../include/libiberty.h"

static int opc_index[256];
static int current_arch_mask = 0;
static int option_use_insn_len_bits_p = 0;

typedef struct
{
  const char *name;
  const char *description;
} s390_options_t;

static const s390_options_t options[] =
{
  { "esa" ,       N_("Disassemble in ESA architecture mode") },
  { "zarch",      N_("Disassemble in z/Architecture mode") },
  { "insnlength", N_("Print unknown instructions according to "
		     "length from first two bits") }
};

/* Set up index table for first opcode byte.  */

void
disassemble_init_s390 (struct disassemble_info *info)
{
  int i;
  const char *p;

  memset (opc_index, 0, sizeof (opc_index));

  /* Reverse order, such that each opc_index ends up pointing to the
     first matching entry instead of the last.  */
  for (i = s390_num_opcodes; i--; )
    opc_index[s390_opcodes[i].opcode[0]] = i;

  current_arch_mask = 1 << S390_OPCODE_ZARCH;
  option_use_insn_len_bits_p = 0;

  for (p = info->disassembler_options; p; )
    {
      if (CONST_STRNEQ (p, "esa"))
	current_arch_mask = 1 << S390_OPCODE_ESA;
      else if (CONST_STRNEQ (p, "zarch"))
	current_arch_mask = 1 << S390_OPCODE_ZARCH;
      else if (CONST_STRNEQ (p, "insnlength"))
	option_use_insn_len_bits_p = 1;
      else {
	/* xgettext:c-format */
//	opcodes_error_handler (_("unknown S/390 disassembler option: %s"), p);
      }

      p = strchr (p, ',');
      if (p)
	p++;
    }
}

/* Derive the length of an instruction from its first byte.  */

static inline int
s390_insn_length (const bfd_byte *buffer)
{
  /* 00xxxxxx -> 2, 01xxxxxx/10xxxxxx -> 4, 11xxxxxx -> 6.  */
  return ((buffer[0] >> 6) + 3) & ~1U;
}

/* Match the instruction in BUFFER against the given OPCODE, excluding
   the first byte.  */

static inline int
s390_insn_matches_opcode (const bfd_byte *buffer,
			  const struct s390_opcode *opcode)
{
  return (buffer[1] & opcode->mask[1]) == opcode->opcode[1]
    && (buffer[2] & opcode->mask[2]) == opcode->opcode[2]
    && (buffer[3] & opcode->mask[3]) == opcode->opcode[3]
    && (buffer[4] & opcode->mask[4]) == opcode->opcode[4]
    && (buffer[5] & opcode->mask[5]) == opcode->opcode[5];
}

union operand_value
{
  int i;
  unsigned int u;
};

/* Extracts an operand value from an instruction.  */
/* We do not perform the shift operation for larl-type address
   operands here since that would lead to an overflow of the 32 bit
   integer value.  Instead the shift operation is done when printing
   the operand.  */

static inline union operand_value
s390_extract_operand (const bfd_byte *insn,
		      const struct s390_operand *operand)
{
  union operand_value ret;
  unsigned int val;
  int bits;
  const bfd_byte *orig_insn = insn;

  /* Extract fragments of the operand byte for byte.  */
  insn += operand->shift / 8;
  bits = (operand->shift & 7) + operand->bits;
  val = 0;
  do
    {
      val <<= 8;
      val |= (unsigned int) *insn++;
      bits -= 8;
    }
  while (bits > 0);
  val >>= -bits;
  val &= ((1U << (operand->bits - 1)) << 1) - 1;

  /* Check for special long displacement case.  */
  if (operand->bits == 20 && operand->shift == 20)
    val = (val & 0xff) << 12 | (val & 0xfff00) >> 8;

  /* Sign extend value if the operand is signed or pc relative.  Avoid
     integer overflows.  */
  if (operand->flags & (S390_OPERAND_SIGNED | S390_OPERAND_PCREL))
    {
      unsigned int m = 1U << (operand->bits - 1);

      if (val >= m)
	ret.i = (int) (val - m) - 1 - (int) (m - 1U);
      else
	ret.i = (int) val;
    }
  else if (operand->flags & S390_OPERAND_LENGTH)
    /* Length x in an instruction has real length x + 1.  */
    ret.u = val + 1;

  else if (operand->flags & S390_OPERAND_VR)
    {
      /* Extract the extra bits for a vector register operand stored
	 in the RXB field.  */
      unsigned vr = operand->shift == 32 ? 3
	: (unsigned) operand->shift / 4 - 2;

      ret.u = val | ((orig_insn[4] & (1 << (3 - vr))) << (vr + 1));
    }
  else
    ret.u = val;

  return ret;
}

/* Print the S390 instruction in BUFFER, assuming that it matches the
   given OPCODE.  */

static void
s390_print_insn_with_opcode (bfd_vma memaddr,
			     struct disassemble_info *info,
			     const bfd_byte *buffer,
			     const struct s390_opcode *opcode)
{
  const unsigned char *opindex;
  char separator;

  /* Mnemonic.  */
  info->fprintf_func (info->stream, "%s", opcode->name);

  /* Operands.  */
  separator = ' ';
  for (opindex = opcode->operands; *opindex != 0; opindex++)
    {
      const struct s390_operand *operand = s390_operands + *opindex;
      union operand_value val = s390_extract_operand (buffer, operand);
      unsigned long flags = operand->flags;

      if ((flags & S390_OPERAND_INDEX) && val.u == 0)
	continue;
      if ((flags & S390_OPERAND_BASE) &&
	  val.u == 0 && separator == '(')
	{
	  separator = ',';
	  continue;
	}

      /* For instructions with a last optional operand don't print it
	 if zero.  */
      if ((opcode->flags & (S390_INSTR_FLAG_OPTPARM | S390_INSTR_FLAG_OPTPARM2))
	  && val.u == 0
	  && opindex[1] == 0)
	break;

      if ((opcode->flags & S390_INSTR_FLAG_OPTPARM2)
	  && val.u == 0 && opindex[1] != 0 && opindex[2] == 0)
	{
	  union operand_value next_op_val =
	    s390_extract_operand (buffer, s390_operands + opindex[1]);
	  if (next_op_val.u == 0)
	    break;
	}

      if (flags & S390_OPERAND_GPR)
	info->fprintf_func (info->stream, "%c%%r%u", separator, val.u);
      else if (flags & S390_OPERAND_FPR)
	info->fprintf_func (info->stream, "%c%%f%u", separator, val.u);
      else if (flags & S390_OPERAND_VR)
	info->fprintf_func (info->stream, "%c%%v%i", separator, val.u);
      else if (flags & S390_OPERAND_AR)
	info->fprintf_func (info->stream, "%c%%a%u", separator, val.u);
      else if (flags & S390_OPERAND_CR)
	info->fprintf_func (info->stream, "%c%%c%u", separator, val.u);
      else if (flags & S390_OPERAND_PCREL)
	{
	  info->fprintf_func (info->stream, "%c", separator);
	  info->print_address_func (memaddr + val.i + val.i, info);
	}
      else if (flags & S390_OPERAND_SIGNED)
	info->fprintf_func (info->stream, "%c%i", separator, val.i);
      else
	{
	  if (flags & S390_OPERAND_OR1)
	    val.u &= ~1;
	  if (flags & S390_OPERAND_OR2)
	    val.u &= ~2;
	  if (flags & S390_OPERAND_OR8)
	    val.u &= ~8;

	  if ((opcode->flags & S390_INSTR_FLAG_OPTPARM)
	      && val.u == 0
	      && opindex[1] == 0)
	    break;
	  info->fprintf_func (info->stream, "%c%u", separator, val.u);
	}

      if (flags & S390_OPERAND_DISP)
	separator = '(';
      else if (flags & S390_OPERAND_BASE)
	{
	  info->fprintf_func (info->stream, ")");
	  separator = ',';
	}
      else
	separator = ',';
    }
}

/* Check whether opcode A's mask is more specific than that of B.  */

static int
opcode_mask_more_specific (const struct s390_opcode *a,
			   const struct s390_opcode *b)
{
  return (((int) a->mask[0] + a->mask[1] + a->mask[2]
	   + a->mask[3] + a->mask[4] + a->mask[5])
	  > ((int) b->mask[0] + b->mask[1] + b->mask[2]
	     + b->mask[3] + b->mask[4] + b->mask[5]));
}

/* Print a S390 instruction.  */

int
print_insn_s390 (bfd_vma memaddr, struct disassemble_info *info)
{
  bfd_byte buffer[6];
  const struct s390_opcode *opcode = NULL;
  int status, opsize, bufsize, bytes_to_dump;

  /* The output looks better if we put 6 bytes on a line.  */
  info->bytes_per_line = 6;

  /* Every S390 instruction is max 6 bytes long.  */
  memset (buffer, 0, 6);
  status = info->read_memory_func (memaddr, buffer, 6, info);
  if (status != 0)
    {
      for (bufsize = 0; bufsize < 6; bufsize++)
	if (info->read_memory_func (memaddr, buffer, bufsize + 1, info) != 0)
	  break;
      if (bufsize <= 0)
	{
	  info->memory_error_func (status, memaddr, info);
	  return -1;
	}
      opsize = s390_insn_length (buffer);
      status = opsize > bufsize;
    }
  else
    {
      bufsize = 6;
      opsize = s390_insn_length (buffer);
    }
  if (status == 0)
    {
      const struct s390_opcode *op;

      /* Find the "best match" in the opcode table.  */
      for (op = s390_opcodes + opc_index[buffer[0]];
	   op != s390_opcodes + s390_num_opcodes
	     && op->opcode[0] == buffer[0];
	   op++)
	{
	  if ((op->modes & current_arch_mask) && s390_insn_matches_opcode (buffer, op)
	      && (opcode == NULL || opcode_mask_more_specific (op, opcode)))
	    opcode = op;
	}

      if (opcode)
	{
	  /* The instruction is valid.  Print it and return its size.  */
	  s390_print_insn_with_opcode (memaddr, info, buffer, opcode);
	  return opsize;
	}
    }

  /* For code sections it makes sense to skip unknown instructions
     according to their length bits.  */
  if (status == 0
      && option_use_insn_len_bits_p
      && info->section
      && (info->section->flags & SEC_CODE))
    bytes_to_dump = opsize;
  else
    /* By default unknown instructions are printed as .long's/.short'
       depending on how many bytes are available.  */
    bytes_to_dump = bufsize >= 4 ? 4 : bufsize;

  if (bytes_to_dump == 0)
    return 0;
#if 0
  unsigned int value;
  int i;

  /* Fall back to hex print.  */
  switch (bytes_to_dump)
    {
    case 4:
      value = (unsigned int) buffer[0];
      value = (value << 8) + (unsigned int) buffer[1];
      value = (value << 8) + (unsigned int) buffer[2];
      value = (value << 8) + (unsigned int) buffer[3];
      info->fprintf_func (info->stream, ".long 0x%08x", value);
      return 4;
    case 2:
      value = (unsigned int) buffer[0];
      value = (value << 8) + (unsigned int) buffer[1];
      info->fprintf_func (info->stream, ".short 0x%04x", value);
      return 2;
    default:
      info->fprintf_func (info->stream, ".byte 0x%02x",
			  (unsigned int) buffer[0]);
      for (i = 1; i < bytes_to_dump; i++)
	info->fprintf_func (info->stream, ",0x%02x",
			  (unsigned int) buffer[i]);
      return bytes_to_dump;
    }
#endif
  return 0;
}

#if 0
const disasm_options_and_args_t *
disassembler_options_s390 (void)
{
  static disasm_options_and_args_t *opts_and_args;

  if (opts_and_args == NULL)
    {
      size_t i, num_options = ARRAY_SIZE (options);
      disasm_options_t *opts;

      opts_and_args = XNEW (disasm_options_and_args_t);
      opts_and_args->args = NULL;

      opts = &opts_and_args->options;
      opts->name = XNEWVEC (const char *, num_options + 1);
      opts->description = XNEWVEC (const char *, num_options + 1);
      opts->arg = NULL;
      for (i = 0; i < num_options; i++)
	{
	  opts->name[i] = options[i].name;
	  opts->description[i] = _(options[i].description);
	}
      /* The array we return must be NULL terminated.  */
      opts->name[i] = NULL;
      opts->description[i] = NULL;
    }

  return opts_and_args;
}
#endif

void
print_s390_disassembler_options (FILE *stream)
{
  unsigned int i, max_len = 0;
  fprintf (stream, _("\n\
The following S/390 specific disassembler options are supported for use\n\
with the -M switch (multiple options should be separated by commas):\n"));

  for (i = 0; i < ARRAY_SIZE (options); i++)
    {
      unsigned int len = strlen (options[i].name);
      if (max_len < len)
	max_len = len;
    }

  for (i = 0, max_len++; i < ARRAY_SIZE (options); i++)
    fprintf (stream, "  %s%*c %s\n",
	     options[i].name,
	     (int)(max_len - strlen (options[i].name)), ' ',
	     _(options[i].description));
}
