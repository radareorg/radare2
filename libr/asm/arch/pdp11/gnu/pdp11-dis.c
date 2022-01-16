/* Print DEC PDP-11 instructions.
   Copyright (C) 2001-2021 Free Software Foundation, Inc.

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
#include "disas-asm.h"
#include "opcode/pdp11.h"

#define AFTER_INSTRUCTION	"\t"
#define OPERAND_SEPARATOR	", "

#define JUMP	0x1000	/* Flag that this operand is used in a jump.  */

#define FPRINTF	(*info->fprintf_func)
#define F	info->stream

/* Sign-extend a 16-bit number in an int.  */
#define sign_extend(x) ((((x) & 0xffff) ^ 0x8000) - 0x8000)

static int
read_word (bfd_vma memaddr, int *word, disassemble_info *info)
{
  int status;
  bfd_byte x[2];

  status = (*info->read_memory_func) (memaddr, x, 2, info);
  if (status != 0)
    return -1;

  *word = x[1] << 8 | x[0];
  return 0;
}

static void
print_signed_octal (int n, disassemble_info *info)
{
  if (n < 0)
    FPRINTF (F, "-%o", -n);
  else
    FPRINTF (F, "%o", n);
}

static void
print_reg (int reg, disassemble_info *info)
{
  /* Mask off the addressing mode, if any.  */
  reg &= 7;

  switch (reg)
    {
    case 0: case 1: case 2: case 3: case 4: case 5:
		FPRINTF (F, "r%d", reg); break;
    case 6:	FPRINTF (F, "sp"); break;
    case 7:	FPRINTF (F, "pc"); break;
    default: ;	/* error */
    }
}

static void
print_freg (int freg, disassemble_info *info)
{
  FPRINTF (F, "fr%d", freg);
}

static int
print_operand (bfd_vma *memaddr, int code, disassemble_info *info)
{
  int mode = (code >> 3) & 7;
  int reg = code & 7;
  int disp;

  switch (mode)
    {
    case 0:
      print_reg (reg, info);
      break;
    case 1:
      FPRINTF (F, "(");
      print_reg (reg, info);
      FPRINTF (F, ")");
      break;
    case 2:
      if (reg == 7)
	{
	  int data;

	  if (read_word (*memaddr, &data, info) < 0)
	    return -1;
	  FPRINTF (F, "$");
	  print_signed_octal (sign_extend (data), info);
	  *memaddr += 2;
	}
      else
	{
	  FPRINTF (F, "(");
	  print_reg (reg, info);
	  FPRINTF (F, ")+");
	}
	break;
    case 3:
      if (reg == 7)
	{
	  int address;

	  if (read_word (*memaddr, &address, info) < 0)
	    return -1;
	  FPRINTF (F, "*$%o", address);
	  *memaddr += 2;
	}
      else
	{
	  FPRINTF (F, "*(");
	  print_reg (reg, info);
	  FPRINTF (F, ")+");
	}
	break;
    case 4:
      FPRINTF (F, "-(");
      print_reg (reg, info);
      FPRINTF (F, ")");
      break;
    case 5:
      FPRINTF (F, "*-(");
      print_reg (reg, info);
      FPRINTF (F, ")");
      break;
    case 6:
    case 7:
      if (read_word (*memaddr, &disp, info) < 0)
	return -1;
      *memaddr += 2;
      if (reg == 7)
	{
	  bfd_vma address = *memaddr + sign_extend (disp);

	  if (mode == 7)
	    FPRINTF (F, "*");
	  if (!(code & JUMP))
	    FPRINTF (F, "$");
	  (*info->print_address_func) (address, info);
	}
      else
	{
	  if (mode == 7)
	    FPRINTF (F, "*");
	  print_signed_octal (sign_extend (disp), info);
	  FPRINTF (F, "(");
	  print_reg (reg, info);
	  FPRINTF (F, ")");
	}
      break;
    }

  return 0;
}

static int
print_foperand (bfd_vma *memaddr, int code, disassemble_info *info)
{
  int mode = (code >> 3) & 7;
  int reg = code & 7;

  if (mode == 0)
    print_freg (reg, info);
  else
    return print_operand (memaddr, code, info);

  return 0;
}

/* Print the PDP-11 instruction at address MEMADDR in debugged memory,
   on INFO->STREAM.  Returns length of the instruction, in bytes.  */

int
print_insn_pdp11 (bfd_vma memaddr, disassemble_info *info)
{
  bfd_vma start_memaddr = memaddr;
  int opcode;
  int src, dst;
  int i;

  info->bytes_per_line = 6;
  info->bytes_per_chunk = 2;
  info->display_endian = BFD_ENDIAN_LITTLE;

  if (read_word (memaddr, &opcode, info) != 0)
    return -1;
  memaddr += 2;

  src = (opcode >> 6) & 0x3f;
  dst = opcode & 0x3f;

  for (i = 0; i < pdp11_num_opcodes; i++)
    {
#define OP pdp11_opcodes[i]
      if ((opcode & OP.mask) == OP.opcode)
	switch (OP.type)
	  {
	  case PDP11_OPCODE_NO_OPS:
	    FPRINTF (F, "%s", OP.name);
	    goto done;
	  case PDP11_OPCODE_REG:
	    FPRINTF (F, "%s", OP.name);
	    FPRINTF (F, AFTER_INSTRUCTION);
	    print_reg (dst, info);
	    goto done;
	  case PDP11_OPCODE_OP:
	    FPRINTF (F, "%s", OP.name);
	    FPRINTF (F, AFTER_INSTRUCTION);
	    if (strcmp (OP.name, "jmp") == 0)
	      dst |= JUMP;
	    if (print_operand (&memaddr, dst, info) < 0)
	      return -1;
	    goto done;
	  case PDP11_OPCODE_FOP:
	    FPRINTF (F, "%s", OP.name);
	    FPRINTF (F, AFTER_INSTRUCTION);
	    if (strcmp (OP.name, "jmp") == 0)
	      dst |= JUMP;
	    if (print_foperand (&memaddr, dst, info) < 0)
	      return -1;
	    goto done;
	  case PDP11_OPCODE_REG_OP:
	    FPRINTF (F, "%s", OP.name);
	    FPRINTF (F, AFTER_INSTRUCTION);
	    print_reg (src, info);
	    FPRINTF (F, OPERAND_SEPARATOR);
	    if (strcmp (OP.name, "jsr") == 0)
	      dst |= JUMP;
	    if (print_operand (&memaddr, dst, info) < 0)
	      return -1;
	    goto done;
	  case PDP11_OPCODE_REG_OP_REV:
	    FPRINTF (F, "%s", OP.name);
	    FPRINTF (F, AFTER_INSTRUCTION);
	    if (print_operand (&memaddr, dst, info) < 0)
	      return -1;
	    FPRINTF (F, OPERAND_SEPARATOR);
	    print_reg (src, info);
	    goto done;
	  case PDP11_OPCODE_AC_FOP:
	    {
	      int ac = (opcode & 0xe0) >> 6;
	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      print_freg (ac, info);
	      FPRINTF (F, OPERAND_SEPARATOR);
	      if (print_foperand (&memaddr, dst, info) < 0)
		return -1;
	      goto done;
	    }
	  case PDP11_OPCODE_FOP_AC:
	    {
	      int ac = (opcode & 0xe0) >> 6;
	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      if (print_foperand (&memaddr, dst, info) < 0)
		return -1;
	      FPRINTF (F, OPERAND_SEPARATOR);
	      print_freg (ac, info);
	      goto done;
	    }
	  case PDP11_OPCODE_AC_OP:
	    {
	      int ac = (opcode & 0xe0) >> 6;
	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      print_freg (ac, info);
	      FPRINTF (F, OPERAND_SEPARATOR);
	      if (print_operand (&memaddr, dst, info) < 0)
		return -1;
	      goto done;
	    }
	  case PDP11_OPCODE_OP_AC:
	    {
	      int ac = (opcode & 0xe0) >> 6;
	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      if (print_operand (&memaddr, dst, info) < 0)
		return -1;
	      FPRINTF (F, OPERAND_SEPARATOR);
	      print_freg (ac, info);
	      goto done;
	    }
	  case PDP11_OPCODE_OP_OP:
	    FPRINTF (F, "%s", OP.name);
	    FPRINTF (F, AFTER_INSTRUCTION);
	    if (print_operand (&memaddr, src, info) < 0)
	      return -1;
	    FPRINTF (F, OPERAND_SEPARATOR);
	    if (print_operand (&memaddr, dst, info) < 0)
	      return -1;
	    goto done;
	  case PDP11_OPCODE_DISPL:
	    {
	      int displ = (opcode & 0xff) << 8;
	      bfd_vma address = memaddr + (sign_extend (displ) >> 7);
	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      (*info->print_address_func) (address, info);
	      goto done;
	    }
	  case PDP11_OPCODE_REG_DISPL:
	    {
	      int displ = (opcode & 0x3f) << 10;
	      bfd_vma address = memaddr - (displ >> 9);

	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      print_reg (src, info);
	      FPRINTF (F, OPERAND_SEPARATOR);
	      (*info->print_address_func) (address, info);
	      goto done;
	    }
	  case PDP11_OPCODE_IMM8:
	    {
	      int code = opcode & 0xff;
	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      FPRINTF (F, "%o", code);
	      goto done;
	    }
	  case PDP11_OPCODE_IMM6:
	    {
	      int code = opcode & 0x3f;
	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      FPRINTF (F, "%o", code);
	      goto done;
	    }
	  case PDP11_OPCODE_IMM3:
	    {
	      int code = opcode & 7;
	      FPRINTF (F, "%s", OP.name);
	      FPRINTF (F, AFTER_INSTRUCTION);
	      FPRINTF (F, "%o", code);
	      goto done;
	    }
	  case PDP11_OPCODE_ILLEGAL:
	    {
	      FPRINTF (F, ".word");
	      FPRINTF (F, AFTER_INSTRUCTION);
	      FPRINTF (F, "%o", opcode);
	      goto done;
	    }
	  default:
	    /* TODO: is this a proper way of signalling an error? */
	    FPRINTF (F, "<internal error: unrecognized instruction type>");
	    return -1;
	  }
#undef OP
    }
 done:

  return memaddr - start_memaddr;
}
