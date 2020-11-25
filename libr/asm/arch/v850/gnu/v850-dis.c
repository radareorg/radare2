/* Disassemble V850 instructions.
   Copyright (C) 1996-2020 Free Software Foundation, Inc.

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
#include <stdio.h>
#include <string.h>
#include <mybfd.h>
#include "v850.h"
#include "libiberty.h"
#include "disas-asm.h"
#define _(x) (x)

static const int v850_cacheop_codes[] =
{
  0x00, 0x20, 0x40, 0x60, 0x61, 0x04, 0x06,
  0x07, 0x24, 0x26, 0x27, 0x44, 0x64, 0x65, -1
};

static const int v850_prefop_codes[] =
{ 0x00, 0x04, -1};

static void
print_value (int flags,
	     bfd_vma memaddr,
	     struct disassemble_info *info,
	     long value)
{
  if (flags & V850_PCREL)
    {
      bfd_vma addr = value + memaddr;

      if (flags & V850_INVERSE_PCREL)
	addr = memaddr - value;
      info->print_address_func (addr, info);
    }
  else if (flags & V850_OPERAND_DISP)
    {
      if (flags & V850_OPERAND_SIGNED)
        {
          info->fprintf_func (info->stream, "%ld", value);
        }
      else
        {
          info->fprintf_func (info->stream, "%lu", value);
        }
    }
  else if ((flags & V850E_IMMEDIATE32)
	   || (flags & V850E_IMMEDIATE16HI))
    {
      info->fprintf_func (info->stream, "0x%lx", value);
    }
  else
    {
      if (flags & V850_OPERAND_SIGNED)
	{
	  info->fprintf_func (info->stream, "%ld", value);
	}
      else
	{
	  info->fprintf_func (info->stream, "%lu", value);
	}
    }
}

static long
get_operand_value (const struct v850_operand *operand,
		   unsigned long insn,
		   int bytes_read,
		   bfd_vma memaddr,
		   struct disassemble_info * info,
		   bfd_boolean noerror,
		   int *invalid)
{
  unsigned long value;
  bfd_byte buffer[4];

  if ((operand->flags & V850E_IMMEDIATE16)
      || (operand->flags & V850E_IMMEDIATE16HI))
    {
      int status = info->read_memory_func (memaddr + bytes_read, buffer, 2, info);

      if (status == 0)
	{
	  value = bfd_getl16 (buffer);

	  if (operand->flags & V850E_IMMEDIATE16HI)
	    value <<= 16;
	  else if (value & 0x8000)
	    value |= (-1UL << 16);

	  return value;
	}

      if (!noerror)
	info->memory_error_func (status, memaddr + bytes_read, info);

      return 0;
    }

  if (operand->flags & V850E_IMMEDIATE23)
    {
      int status = info->read_memory_func (memaddr + 2, buffer, 4, info);

      if (status == 0)
	{
	  value = bfd_getl32 (buffer);

	  value = (operand->extract) (value, invalid);

	  return value;
	}

      if (!noerror)
	info->memory_error_func (status, memaddr + bytes_read, info);

      return 0;
    }

  if (operand->flags & V850E_IMMEDIATE32)
    {
      int status = info->read_memory_func (memaddr + bytes_read, buffer, 4, info);

      if (status == 0)
	{
	  bytes_read += 4;
	  value = bfd_getl32 (buffer);

	  return value;
	}

      if (!noerror)
	info->memory_error_func (status, memaddr + bytes_read, info);

      return 0;
    }

  if (operand->extract)
    value = (operand->extract) (insn, invalid);
  else
    {
      if (operand->bits == -1)
	value = (insn & operand->shift);
      else
	value = (insn >> operand->shift) & ((1ul << operand->bits) - 1);

      if (operand->flags & V850_OPERAND_SIGNED)
	{
	  unsigned long sign = 1ul << (operand->bits - 1);
	  value = (value ^ sign) - sign;
	}
    }

  return value;
}

static const char *
get_v850_sreg_name (unsigned int reg)
{
  static const char *const v850_sreg_names[] =
    {
     "eipc/vip/mpm", "eipsw/mpc", "fepc/tid", "fepsw/ppa", "ecr/vmecr", "psw/vmtid",
     "sr6/fpsr/vmadr/dcc", "sr7/fpepc/dc0",
     "sr8/fpst/vpecr/dcv1", "sr9/fpcc/vptid", "sr10/fpcfg/vpadr/spal", "sr11/spau",
     "sr12/vdecr/ipa0l", "eiic/vdtid/ipa0u", "feic/ipa1l", "dbic/ipa1u",
     "ctpc/ipa2l", "ctpsw/ipa2u", "dbpc/ipa3l", "dbpsw/ipa3u", "ctbp/dpa0l",
     "dir/dpa0u", "bpc/dpa0u", "asid/dpa1l",
     "bpav/dpa1u", "bpam/dpa2l", "bpdv/dpa2u", "bpdm/dpa3l", "eiwr/dpa3u",
     "fewr", "dbwr", "bsel"
    };

  if (reg < ARRAY_SIZE (v850_sreg_names))
    return v850_sreg_names[reg];
  return _("<invalid s-reg number>");
}

static const char *
get_v850_reg_name (unsigned int reg)
{
  static const char *const v850_reg_names[] =
    {
     "r0", "r1", "r2", "sp", "gp", "r5", "r6", "r7",
     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
     "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
     "r24", "r25", "r26", "r27", "r28", "r29", "ep", "lp"
    };

  if (reg < ARRAY_SIZE (v850_reg_names))
    return v850_reg_names[reg];
  return _("<invalid reg number>");
}

static const char *
get_v850_vreg_name (unsigned int reg)
{
  static const char *const v850_vreg_names[] =
    {
     "vr0", "vr1", "vr2", "vr3", "vr4", "vr5", "vr6", "vr7", "vr8", "vr9",
     "vr10", "vr11", "vr12", "vr13", "vr14", "vr15", "vr16", "vr17", "vr18",
     "vr19", "vr20", "vr21", "vr22", "vr23", "vr24", "vr25", "vr26", "vr27",
     "vr28", "vr29", "vr30", "vr31"
    };

  if (reg < ARRAY_SIZE (v850_vreg_names))
    return v850_vreg_names[reg];
  return _("<invalid v-reg number>");
}

static const char *
get_v850_cc_name (unsigned int reg)
{
  static const char *const v850_cc_names[] =
    {
     "v", "c/l", "z", "nh", "s/n", "t", "lt", "le",
     "nv", "nc/nl", "nz", "h", "ns/p", "sa", "ge", "gt"
    };

  if (reg < ARRAY_SIZE (v850_cc_names))
    return v850_cc_names[reg];
  return _("<invalid CC-reg number>");
}

static const char *
get_v850_float_cc_name (unsigned int reg)
{
  static const char *const v850_float_cc_names[] =
    {
     "f/t", "un/or", "eq/neq", "ueq/ogl", "olt/uge", "ult/oge", "ole/ugt", "ule/ogt",
     "sf/st", "ngle/gle", "seq/sne", "ngl/gl", "lt/nlt", "nge/ge", "le/nle", "ngt/gt"
    };

  if (reg < ARRAY_SIZE (v850_float_cc_names))
    return v850_float_cc_names[reg];
  return _("<invalid float-CC-reg number>");
}

static const char *
get_v850_cacheop_name (unsigned int reg)
{
  static const char *const v850_cacheop_names[] =
    {
     "chbii", "cibii", "cfali", "cisti", "cildi", "chbid", "chbiwbd",
     "chbwbd", "cibid", "cibiwbd", "cibwbd", "cfald", "cistd", "cildd"
    };

  if (reg < ARRAY_SIZE (v850_cacheop_names))
    return v850_cacheop_names[reg];
  return _("<invalid cacheop number>");
}

static const char *
get_v850_prefop_name (unsigned int reg)
{
  static const char *const v850_prefop_names[] =
    { "prefi", "prefd" };

  if (reg < ARRAY_SIZE (v850_prefop_names))
    return v850_prefop_names[reg];
  return _("<invalid prefop number>");
}

static int
disassemble (bfd_vma memaddr,
	     struct disassemble_info *info,
	     int bytes_read,
	     unsigned long insn)
{
  struct v850_opcode *op = (struct v850_opcode *) v850_opcodes;
  const struct v850_operand *operand;
  int match = 0;

  int target_processor = info->flavour;

  /* If this is a two byte insn, then mask off the high bits.  */
  if (bytes_read == 2)
    insn &= 0xffff;

  /* Find the opcode.  */
  while (op->name)
    {
      if ((op->mask & insn) == op->opcode
	  && (op->processors & target_processor)
	  && !(op->processors & PROCESSOR_OPTION_ALIAS))
	{
	  /* Code check start.  */
	  const unsigned char *opindex_ptr;
	  unsigned int opnum;
	  unsigned int memop;

	  for (opindex_ptr = op->operands, opnum = 1;
	       *opindex_ptr != 0;
	       opindex_ptr++, opnum++)
	    {
	      int invalid = 0;
	      long value;

	      operand = &v850_operands[*opindex_ptr];

	      value = get_operand_value (operand, insn, bytes_read, memaddr,
					 info, 1, &invalid);

	      if (invalid)
		goto next_opcode;

              if ((operand->flags & V850_NOT_R0) && value == 0 && (op->memop) <=2)
		goto next_opcode;

	      if ((operand->flags & V850_NOT_SA) && value == 0xd)
		goto next_opcode;

	      if ((operand->flags & V850_NOT_IMM0) && value == 0)
		goto next_opcode;
	    }

	  /* Code check end.  */

	  match = 1;
	  (*info->fprintf_func) (info->stream, "%s ", op->name);
#if 0
	  fprintf (stderr, "match: insn: %lx, mask: %lx, opcode: %lx, name: %s\n",
		   insn, op->mask, op->opcode, op->name );
#endif

	  memop = op->memop;
	  /* Now print the operands.

	     MEMOP is the operand number at which a memory
	     address specification starts, or zero if this
	     instruction has no memory addresses.

	     A memory address is always two arguments.

	     This information allows us to determine when to
	     insert commas into the output stream as well as
	     when to insert disp[reg] expressions onto the
	     output stream.  */

	  for (opindex_ptr = op->operands, opnum = 1;
	       *opindex_ptr != 0;
	       opindex_ptr++, opnum++)
	    {
	      bfd_boolean square = FALSE;
	      long value;
	      int flag;
	      char *prefix;

	      operand = &v850_operands[*opindex_ptr];

	      value = get_operand_value (operand, insn, bytes_read, memaddr,
					 info, 0, 0);

	      /* The first operand is always output without any
		 special handling.

		 For the following arguments:

		   If memop && opnum == memop + 1, then we need '[' since
		   we're about to output the register used in a memory
		   reference.

		   If memop && opnum == memop + 2, then we need ']' since
		   we just finished the register in a memory reference.  We
		   also need a ',' before this operand.

		   Else we just need a comma.

		   We may need to output a trailing ']' if the last operand
		   in an instruction is the register for a memory address.

		   The exception (and there's always an exception) are the
		   "jmp" insn which needs square brackets around it's only
		   register argument, and the clr1/not1/set1/tst1 insns
		   which [...] around their second register argument.  */

	      prefix = "";
	      if (operand->flags & V850_OPERAND_BANG)
		{
		  prefix = "!";
		}
	      else if (operand->flags & V850_OPERAND_PERCENT)
		{
		  prefix = "%";
		}

	      if (opnum == 1 && opnum == memop)
		{
		  info->fprintf_func (info->stream, "%s[", prefix);
		  square = TRUE;
		}
	      else if (   (strcmp ("stc.w", op->name) == 0
			|| strcmp ("cache", op->name) == 0
			|| strcmp ("pref",  op->name) == 0)
		       && opnum == 2 && opnum == memop)
		{
		  info->fprintf_func (info->stream, ", [");
		  square = TRUE;
		}
	      else if (   (strcmp (op->name, "pushsp") == 0
			|| strcmp (op->name, "popsp") == 0
			|| strcmp (op->name, "dbpush" ) == 0)
		       && opnum == 2)
		{
		  info->fprintf_func (info->stream, "-");
		}
	      else if (opnum > 1
		       && (v850_operands[*(opindex_ptr - 1)].flags
			   & V850_OPERAND_DISP) != 0
		       && opnum == memop)
		{
		  info->fprintf_func (info->stream, "%s[", prefix);
		  square = TRUE;
		}
	      else if (opnum == 2
		       && (   op->opcode == 0x00e407e0 /* clr1 */
			   || op->opcode == 0x00e207e0 /* not1 */
			   || op->opcode == 0x00e007e0 /* set1 */
			   || op->opcode == 0x00e607e0 /* tst1 */
			   ))
		{
		  info->fprintf_func (info->stream, ", %s[", prefix);
		  square = TRUE;
		}
	      else if (opnum > 1)
		info->fprintf_func (info->stream, ", %s", prefix);

 	      /* Extract the flags, ignoring ones which do not
		 effect disassembly output.  */
	      flag = operand->flags & (V850_OPERAND_REG
				       | V850_REG_EVEN
				       | V850_OPERAND_EP
				       | V850_OPERAND_SRG
				       | V850E_OPERAND_REG_LIST
				       | V850_OPERAND_CC
				       | V850_OPERAND_VREG
				       | V850_OPERAND_CACHEOP
				       | V850_OPERAND_PREFOP
				       | V850_OPERAND_FLOAT_CC);

	      switch (flag)
		{
		case V850_OPERAND_REG:
		  info->fprintf_func (info->stream, "%s", get_v850_reg_name (value));
		  break;
		case (V850_OPERAND_REG|V850_REG_EVEN):
		  info->fprintf_func (info->stream, "%s", get_v850_reg_name (value * 2));
		  break;
		case V850_OPERAND_EP:
		  info->fprintf_func (info->stream, "ep");
		  break;
		case V850_OPERAND_SRG:
		  info->fprintf_func (info->stream, "%s", get_v850_sreg_name (value));
		  break;
		case V850E_OPERAND_REG_LIST:
		  {
		    static int list12_regs[32]   = { 30, 0, 0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
						     0,  0, 0, 0, 0, 31, 29, 28, 23, 22, 21, 20, 27, 26, 25, 24 };
		    int *regs;
		    int i;
		    unsigned int mask = 0;
		    int pc = 0;

		    switch (operand->shift)
		      {
		      case 0xffe00001: regs = list12_regs; break;
		      default:
			/* xgettext:c-format */
			fprintf (stderr, "unknown operand shift: %x", operand->shift);
			return(1);
		      }

		    for (i = 0; i < 32; i++)
		      {
			if (value & (1u << i))
			  {
			    switch (regs[ i ])
			      {
			      default:
				mask |= (1u << regs[ i ]);
				break;
			      case 0:
				/* xgettext:c-format */
				fprintf (stderr, "unknown reg: %d", i);
				return (1);
				break;
			      case -1:
				pc = 1;
				break;
			      }
			  }
		      }

		    info->fprintf_func (info->stream, "{");

		    if (mask || pc)
		      {
			if (mask)
			  {
			    unsigned int bit;
			    int shown_one = 0;

			    for (bit = 0; bit < 32; bit++)
			      if (mask & (1u << bit))
				{
				  unsigned int first = bit;
				  unsigned int last;

				  if (shown_one)
				    info->fprintf_func (info->stream, ", ");
				  else
				    shown_one = 1;

				  info->fprintf_func (info->stream, "%s", get_v850_reg_name (first));

				  for (bit++; bit < 32; bit++)
				    if ((mask & (1u << bit)) == 0)
				      break;

				  last = bit;

				  if (last > first + 1)
				    {
				      info->fprintf_func (info->stream, " - %s", get_v850_reg_name (last - 1));
				    }
				}
			  }

			if (pc)
			  info->fprintf_func (info->stream, "%sPC", mask ? ", " : "");
		      }

		    info->fprintf_func (info->stream, "}");
		  }
		  break;

		case V850_OPERAND_CC:
		  info->fprintf_func (info->stream, "%s", get_v850_cc_name (value));
		  break;

		case V850_OPERAND_FLOAT_CC:
		  info->fprintf_func (info->stream, "%s", get_v850_float_cc_name (value));
		  break;

		case V850_OPERAND_CACHEOP:
		  {
		    int idx;

		    for (idx = 0; v850_cacheop_codes[idx] != -1; idx++)
		      {
			if (value == v850_cacheop_codes[idx])
			  {
			    info->fprintf_func (info->stream, "%s",
						get_v850_cacheop_name (idx));
			    goto MATCH_CACHEOP_CODE;
			  }
		      }
		    info->fprintf_func (info->stream, "%d", (int) value);
		  }
		MATCH_CACHEOP_CODE:
		  break;

		case V850_OPERAND_PREFOP:
		  {
		    int idx;

		    for (idx = 0; v850_prefop_codes[idx] != -1; idx++)
		      {
			if (value == v850_prefop_codes[idx])
			  {
			    info->fprintf_func (info->stream, "%s",
						get_v850_prefop_name (idx));
			    goto MATCH_PREFOP_CODE;
			  }
		      }
		    info->fprintf_func (info->stream, "%d", (int) value);
		  }
		MATCH_PREFOP_CODE:
		  break;

		case V850_OPERAND_VREG:
		  info->fprintf_func (info->stream, "%s", get_v850_vreg_name (value));
		  break;

		default:
		  print_value (operand->flags, memaddr, info, value);
		  break;
		}

	      if (square)
		(*info->fprintf_func) (info->stream, "]");
	    }

	  /* All done. */
	  break;
	}
    next_opcode:
      op++;
    }

  return match;
}

int
print_insn_v850 (bfd_vma memaddr, struct disassemble_info * info)
{
  int status, status2, match;
  bfd_byte buffer[8];
  int length = 0, code_length = 0;
  unsigned long insn = 0, insn2 = 0;
  int target_processor = info->flavour;
  status = info->read_memory_func (memaddr, buffer, 2, info);

  if (status)
    {
      info->memory_error_func (status, memaddr, info);
      return -1;
    }

  insn = bfd_getl16 (buffer);

  status2 = info->read_memory_func (memaddr+2, buffer, 2 , info);

  if (!status2)
    {
      insn2 = bfd_getl16 (buffer);
      /* fprintf (stderr, "insn2 0x%08lx\n", insn2); */
    }

  /* Special case.  */
  if (length == 0
      && ((target_processor & PROCESSOR_V850E2_UP) != 0))
    {
      if ((insn & 0xffff) == 0x02e0		/* jr 32bit */
	  && !status2 && (insn2 & 0x1) == 0)
	{
	  length = 2;
	  code_length = 6;
	}
      else if ((insn & 0xffe0) == 0x02e0	/* jarl 32bit */
	       && !status2 && (insn2 & 0x1) == 0)
	{
	  length = 2;
	  code_length = 6;
	}
      else if ((insn & 0xffe0) == 0x06e0	/* jmp 32bit */
	       && !status2 && (insn2 & 0x1) == 0)
	{
	  length = 2;
	  code_length = 6;
	}
    }

  if (length == 0
      && ((target_processor & PROCESSOR_V850E3V5_UP) != 0))
    {
      if (   ((insn & 0xffe0) == 0x07a0		/* ld.dw 23bit (v850e3v5) */
	      && !status2 && (insn2 & 0x000f) == 0x0009)
	  || ((insn & 0xffe0) == 0x07a0		/* st.dw 23bit (v850e3v5) */
	      && !status2 && (insn2 & 0x000f) == 0x000f))
	{
	  length = 4;
	  code_length = 6;
	}
    }

  if (length == 0
      && ((target_processor & PROCESSOR_V850E2V3_UP) != 0))
    {
      if (((insn & 0xffe0) == 0x0780		/* ld.b 23bit */
	   && !status2 && (insn2 & 0x000f) == 0x0005)
	  || ((insn & 0xffe0) == 0x07a0		/* ld.bu 23bit */
	      && !status2 && (insn2 & 0x000f) == 0x0005)
	  || ((insn & 0xffe0) == 0x0780		/* ld.h 23bit */
	      && !status2 && (insn2 & 0x000f) == 0x0007)
	  || ((insn & 0xffe0) == 0x07a0		/* ld.hu 23bit */
	      && !status2 && (insn2 & 0x000f) == 0x0007)
	  || ((insn & 0xffe0) == 0x0780		/* ld.w 23bit */
	      && !status2 && (insn2 & 0x000f) == 0x0009))
	{
	  length = 4;
	  code_length = 6;
	}
      else if (((insn & 0xffe0) == 0x0780	/* st.b 23bit */
	       && !status2 && (insn2 & 0x000f) == 0x000d)
	      || ((insn & 0xffe0) == 0x07a0	/* st.h 23bit */
		  && !status2 && (insn2 & 0x000f) == 0x000d)
	      || ((insn & 0xffe0) == 0x0780	/* st.w 23bit */
		  && !status2 && (insn2 & 0x000f) == 0x000f))
	{
	  length = 4;
	  code_length = 6;
	}
    }

  if (length == 0
      && target_processor != PROCESSOR_V850)
    {
      if ((insn & 0xffe0) == 0x0620)		/* 32 bit MOV */
	{
	  length = 2;
	  code_length = 6;
	}
      else if ((insn & 0xffc0) == 0x0780	/* prepare {list}, imm5, imm16<<16 */
	       && !status2 && (insn2 & 0x001f) == 0x0013)
	{
	  length = 4;
	  code_length = 6;
	}
      else if ((insn & 0xffc0) == 0x0780	/* prepare {list}, imm5, imm16 */
	       && !status2 && (insn2 & 0x001f) == 0x000b)
	{
	  length = 4;
	  code_length = 6;
	}
      else if ((insn & 0xffc0) == 0x0780	/* prepare {list}, imm5, imm32 */
	       && !status2 && (insn2 & 0x001f) == 0x001b)
	{
	  length = 4;
	  code_length = 8;
	}
    }

  if (length == 4
      || (length == 0
	  && (insn & 0x0600) == 0x0600))
    {
      /* This is a 4 byte insn.  */
      status = info->read_memory_func (memaddr, buffer, 4, info);
      if (!status)
	{
	  insn = bfd_getl32 (buffer);

	  if (!length)
	    length = code_length = 4;
	}
    }

  if (code_length > length)
    {
      status = info->read_memory_func (memaddr + length, buffer, code_length - length, info);
      if (status)
	length = 0;
    }

  if (length == 0 && !status)
    length = code_length = 2;

  if (length == 2)
    insn &= 0xffff;

  /* when the last 2 bytes of section is 0xffff, length will be 0 and cause infinitive loop */
  if (length == 0)
    return -1;

  match = disassemble (memaddr, info, length, insn);

  if (!match)
    {
    return -1;
      int l = 0;

      status = info->read_memory_func (memaddr, buffer, code_length, info);

      while (l < code_length)
	{
	  if (code_length - l == 2)
	    {
	      insn = bfd_getl16 (buffer + l) & 0xffff;
	      info->fprintf_func (info->stream, ".short 0x%04lx", insn);
	      l += 2;
	    }
	  else
	    {
	      insn = bfd_getl32 (buffer + l);
	      info->fprintf_func (info->stream, ".long 0x%08lx", insn);
	      l += 4;
	    }
	}
    }

  return code_length;
}
