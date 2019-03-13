/* Print VAX instructions.
   Copyright 1995, 1998, 2000, 2001, 2002, 2005, 2007, 2009, 2012
   Free Software Foundation, Inc.
   Contributed by Pauline Middelink <middelin@polyware.iaf.nl>

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
#include <setjmp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "vax.h"
#include "disas-asm.h"

static char *reg_names[] =
{
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "ap", "fp", "sp", "pc"
};

#if 0
/* Definitions for the function entry mask bits.  */
static char *entry_mask_bit[] =
{
  /* Registers 0 and 1 shall not be saved, since they're used to pass back
     a function's result to its caller...  */
  "~r0~", "~r1~",
  /* Registers 2 .. 11 are normal registers.  */
  "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11",
  /* Registers 12 and 13 are argument and frame pointer and must not
     be saved by using the entry mask.  */
  "~ap~", "~fp~",
  /* Bits 14 and 15 control integer and decimal overflow.  */
  "IntOvfl", "DecOvfl",
};

#endif
/* Sign-extend an (unsigned char). */
#define COERCE_SIGNED_CHAR(ch) ((signed char)(ch))

/* Get a 1 byte signed integer.  */
#define NEXTBYTE(p)  \
  ((p) += 1, FETCH_DATA (info, p), \
  COERCE_SIGNED_CHAR((p)[-1]))

/* Get a 2 byte signed integer.  */
#define COERCE16(x) ((int) (((x) ^ 0x8000) - 0x8000))
#define NEXTWORD(p)  \
  ((p) += 2, FETCH_DATA (info, p), \
   COERCE16 (((p)[-1] << 8) + (p)[-2]))

/* Get a 4 byte signed integer.  */
#define COERCE32(x) ((int) (((x) ^ 0x80000000) - 0x80000000))
#define NEXTLONG(p)  \
  ((p) += 4, FETCH_DATA (info, p), \
   (COERCE32 (((((((p)[-1] << 8) + (p)[-2]) << 8) + (p)[-3]) << 8) + (p)[-4])))

/* Maximum length of an instruction.  */
#define MAXLEN 25

struct private
{
  /* Points to first byte not fetched.  */
  bfd_byte * max_fetched;
  bfd_byte   the_buffer[MAXLEN];
  bfd_vma    insn_start;
  jmp_buf    bailout;
};

/* Make sure that bytes from INFO->PRIVATE_DATA->BUFFER (inclusive)
   to ADDR (exclusive) are valid.  Returns 1 for success, longjmps
   on error.  */
#define FETCH_DATA(info, addr) \
  ((addr) <= ((struct private *)((info)->private_data))->max_fetched \
   ? 1 : fetch_data ((info), (addr)))

static int
fetch_data (struct disassemble_info *info, bfd_byte *addr)
{
  int status;
  struct private *priv = (struct private *) info->private_data;
  bfd_vma start = priv->insn_start + (priv->max_fetched - priv->the_buffer);

  status = (*info->read_memory_func) (start,
				      priv->max_fetched,
				      addr - priv->max_fetched,
				      info);
  if (status != 0)
    {
      (*info->memory_error_func) (status, start, info);
      longjmp (priv->bailout, 1);
  } else {
	  priv->max_fetched = addr;
  }

  return 1;
}

/* Entry mask handling.  */
#if 0
static unsigned int  entry_addr_occupied_slots = 0;
static unsigned int  entry_addr_total_slots = 0;
static bfd_vma *     entry_addr = NULL;
#endif

/* Parse the VAX specific disassembler options.  These contain function
   entry addresses, which can be useful to disassemble ROM images, since
   there's no symbol table.  Returns TRUE upon success, FALSE otherwise.  */

/* Check if the given address is a known function entry point.  This is
   the case if there is a symbol of the function type at this address.
   We also check for synthetic symbols as these are used for PLT entries
   (weak undefined symbols may not have the function type set).  Finally
   the address may have been forced to be treated as an entry point.  The
   latter helps in disassembling ROM images, because there's no symbol
   table at all.  Forced entry points can be given by supplying several
   -M options to objdump: -M entry:0xffbb7730.  */

static int
print_insn_mode (const char *d,
		 int size,
		 unsigned char *p0,
		 bfd_vma addr,	/* PC for this arg to be relative to.  */
		 disassemble_info *info)
{
  unsigned char *p = p0;
  unsigned char mode, reg;

  /* Fetch and interpret mode byte.  */
  mode = (unsigned char) NEXTBYTE (p);
  reg = mode & 0xF;
  switch (mode & 0xF0)
    {
    case 0x00:
    case 0x10:
    case 0x20:
    case 0x30: /* Literal mode			$number.  */
	    if (d[1] == 'd' || d[1] == 'f' || d[1] == 'g' || d[1] == 'h') {
		    (*info->fprintf_func) (info->stream, "$0x%x [%c-float]", mode, d[1]);
	    } else {
		    (*info->fprintf_func) (info->stream, "$0x%x", mode);
	    }
	    break;
    case 0x40: /* Index:			base-addr[Rn] */
      p += print_insn_mode (d, size, p0 + 1, addr + 1, info);
      (*info->fprintf_func) (info->stream, "[%s]", reg_names[reg]);
      break;
    case 0x50: /* Register:			Rn */
      (*info->fprintf_func) (info->stream, "%s", reg_names[reg]);
      break;
    case 0x60: /* Register deferred:		(Rn) */
      (*info->fprintf_func) (info->stream, "(%s)", reg_names[reg]);
      break;
    case 0x70: /* Autodecrement:		-(Rn) */
      (*info->fprintf_func) (info->stream, "-(%s)", reg_names[reg]);
      break;
    case 0x80: /* Autoincrement:		(Rn)+ */
      if (reg == 0xF)
	{	/* Immediate?  */
	  int i;

	  FETCH_DATA (info, p + size);
	  (*info->fprintf_func) (info->stream, "$0x");
	  if (d[1] == 'd' || d[1] == 'f' || d[1] == 'g' || d[1] == 'h')
	    {
	      int float_word;

	      float_word = p[0] | (p[1] << 8);
	      if ((d[1] == 'd' || d[1] == 'f')
		  && (float_word & 0xff80) == 0x8000)
		{
		  (*info->fprintf_func) (info->stream, "[invalid %c-float]",
					 d[1]);
		}
	      else
		{
			for (i = 0; i < size; i++) {
				(*info->fprintf_func) (info->stream, "%02x",
					p[size - i - 1]);
			}
			(*info->fprintf_func) (info->stream, " [%c-float]", d[1]);
		}
	    }
	  else
	    {
		    for (i = 0; i < size; i++) {
			    (*info->fprintf_func) (info->stream, "%02x", p[size - i - 1]);
		    }
	    }
	  p += size;
      } else {
	      (*info->fprintf_func) (info->stream, "(%s)+", reg_names[reg]);
      }
      break;
    case 0x90: /* Autoincrement deferred:	@(Rn)+ */
	    if (reg == 0xF) {
		    (*info->fprintf_func) (info->stream, "*0x%x", NEXTLONG (p));
	    } else {
		    (*info->fprintf_func) (info->stream, "@(%s)+", reg_names[reg]);
	    }
	    break;
    case 0xB0: /* Displacement byte deferred:	*displ(Rn).  */
      (*info->fprintf_func) (info->stream, "*");
    case 0xA0: /* Displacement byte:		displ(Rn).  */
	    if (reg == 0xF) {
		    (*info->print_address_func) (addr + 2 + NEXTBYTE (p), info);
	    } else {
		    (*info->fprintf_func) (info->stream, "0x%x(%s)", NEXTBYTE (p),
			    reg_names[reg]);
	    }
	    break;
    case 0xD0: /* Displacement word deferred:	*displ(Rn).  */
      (*info->fprintf_func) (info->stream, "*");
    case 0xC0: /* Displacement word:		displ(Rn).  */
	    if (reg == 0xF) {
		    (*info->print_address_func) (addr + 3 + NEXTWORD (p), info);
	    } else {
		    (*info->fprintf_func) (info->stream, "0x%x(%s)", NEXTWORD (p),
			    reg_names[reg]);
	    }
	    break;
    case 0xF0: /* Displacement long deferred:	*displ(Rn).  */
      (*info->fprintf_func) (info->stream, "*");
    case 0xE0: /* Displacement long:		displ(Rn).  */
	    if (reg == 0xF) {
		    (*info->print_address_func) (addr + 5 + NEXTLONG (p), info);
	    } else {
		    (*info->fprintf_func) (info->stream, "0x%x(%s)", NEXTLONG (p),
			    reg_names[reg]);
	    }
	    break;
    }

  return p - p0;
}

/* Returns number of bytes "eaten" by the operand, or return -1 if an
   invalid operand was found, or -2 if an opcode tabel error was
   found. */

static int
print_insn_arg (const char *d,
		unsigned char *p0,
		bfd_vma addr,	/* PC for this arg to be relative to.  */
		disassemble_info *info)
{
  int arg_len;

  /* Check validity of addressing length.  */
  switch (d[1])
    {
    case 'b' : arg_len = 1;	break;
    case 'd' : arg_len = 8;	break;
    case 'f' : arg_len = 4;	break;
    case 'g' : arg_len = 8;	break;
    case 'h' : arg_len = 16;	break;
    case 'l' : arg_len = 4;	break;
    case 'o' : arg_len = 16;	break;
    case 'w' : arg_len = 2;	break;
    case 'q' : arg_len = 8;	break;
    default  : abort ();
    }

  /* Branches have no mode byte.  */
  if (d[0] == 'b')
    {
      unsigned char *p = p0;

      if (arg_len == 1) {
	      (*info->print_address_func) (addr + 1 + NEXTBYTE (p), info);
      } else {
	      (*info->print_address_func) (addr + 2 + NEXTWORD (p), info);
      }

      return p - p0;
    }

  return print_insn_mode (d, arg_len, p0, addr, info);
}

/* Print the vax instruction at address MEMADDR in debugged memory,
   on INFO->STREAM.  Returns length of the instruction, in bytes.  */

int
print_insn_vax (bfd_vma memaddr, disassemble_info *info)
{
  //static bfd_boolean parsed_disassembler_options = FALSE;
  const struct vot *votp;
  const char *argp;
  unsigned char *arg;
  struct private priv;
  bfd_byte *buffer = priv.the_buffer;

  info->private_data = & priv;
  priv.max_fetched = priv.the_buffer;
  priv.insn_start = memaddr;

  if (setjmp (priv.bailout) != 0) {
	  /* Error return.  */
	  return -1;
  }

  argp = NULL;
  /* Check if the info buffer has more than one byte left since
     the last opcode might be a single byte with no argument data.  */
  if (info->buffer_length - (memaddr - info->buffer_vma) > 1)
    {
      FETCH_DATA (info, buffer + 2);
    }
  else
    {
      FETCH_DATA (info, buffer + 1);
      buffer[1] = 0;
    }

  for (votp = &votstrs[0]; votp->name[0]; votp++)
    {
      vax_opcodeT opcode = votp->detail.code;

      /* 2 byte codes match 2 buffer pos. */
      if ((bfd_byte) opcode == buffer[0]
	  && (opcode >> 8 == 0 || opcode >> 8 == buffer[1]))
	{
	  argp = votp->detail.args;
	  break;
	}
    }
  if (!argp)
    {
      /* Handle undefined instructions. */
      (*info->fprintf_func) (info->stream, ".word 0x%x",
			     (buffer[0] << 8) + buffer[1]);
      return 2;
    }

  /* Point at first byte of argument data, and at descriptor for first
     argument.  */
  arg = buffer + ((votp->detail.code >> 8) ? 2 : 1);

  /* Make sure we have it in mem */
  FETCH_DATA (info, arg);

  (*info->fprintf_func) (info->stream, "%s", votp->name);
  if (*argp) {
	  (*info->fprintf_func) (info->stream, " ");
  }

  while (*argp)
    {
      arg += print_insn_arg (argp, arg, memaddr + arg - buffer, info);
      argp += 2;
      if (*argp) {
	      (*info->fprintf_func) (info->stream, ", ");
      }
    }

  return arg - buffer;
}

