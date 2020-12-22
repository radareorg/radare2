/* Disassembler for the PA-RISC. Somewhat derived from sparc-pinsn.c.
   Copyright (C) 1989-2014 Free Software Foundation, Inc.

   Contributed by the Center for Software Science at the
   University of Utah (pa-gdb-bugs@cs.utah.edu).

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
#include "libhppa.h"
#include "opcode/hppa.h"
#include <string.h>
#include <r_types.h>

/* Integer register names, indexed by the numbers which appear in the
   opcodes.  */
static const char *const reg_names[] =
{
  "flags", "r1", "rp", "r3", "r4", "r5", "r6", "r7", "r8", "r9",
  "r10", "r11", "r12", "r13", "r14", "r15", "r16", "r17", "r18", "r19",
  "r20", "r21", "r22", "r23", "r24", "r25", "r26", "dp", "ret0", "ret1",
  "sp", "r31"
};

/* Floating point register names, indexed by the numbers which appear in the
   opcodes.  */
static const char *const fp_reg_names[] =
{
  "fpsr", "fpe2", "fpe4", "fpe6",
  "fr4", "fr5", "fr6", "fr7", "fr8",
  "fr9", "fr10", "fr11", "fr12", "fr13", "fr14", "fr15",
  "fr16", "fr17", "fr18", "fr19", "fr20", "fr21", "fr22", "fr23",
  "fr24", "fr25", "fr26", "fr27", "fr28", "fr29", "fr30", "fr31"
};

typedef unsigned int CORE_ADDR;

/* Get at various relevant fields of an instruction word.  */

#define MASK_5  0x1f
#define MASK_10 0x3ff
#define MASK_11 0x7ff
#define MASK_14 0x3fff
#define MASK_16 0xffff
#define MASK_21 0x1fffff

/* These macros get bit fields using HP's numbering (MSB = 0).  */

#define GET_FIELD(X, FROM, TO) \
  ((X) >> (31 - (TO)) & ((1 << ((TO) - (FROM) + 1)) - 1))

#define GET_BIT(X, WHICH) \
  GET_FIELD (X, WHICH, WHICH)

/* Some of these have been converted to 2-d arrays because they
   consume less storage this way.  If the maintenance becomes a
   problem, convert them back to const 1-d pointer arrays.  */
static const char *const control_reg[] =
{
  "rctr", "cr1", "cr2", "cr3", "cr4", "cr5", "cr6", "cr7",
  "pidr1", "pidr2", "ccr", "sar", "pidr3", "pidr4",
  "iva", "eiem", "itmr", "pcsq", "pcoq", "iir", "isr",
  "ior", "ipsw", "eirr", "tr0", "tr1", "tr2", "tr3",
  "tr4", "tr5", "tr6", "tr7"
};

static const char *const compare_cond_names[] =
{
  "", ",=", ",<", ",<=", ",<<", ",<<=", ",sv", ",od",
  ",tr", ",<>", ",>=", ",>", ",>>=", ",>>", ",nsv", ",ev"
};
static const char *const compare_cond_64_names[] =
{
  ",*", ",*=", ",*<", ",*<=", ",*<<", ",*<<=", ",*sv", ",*od",
  ",*tr", ",*<>", ",*>=", ",*>", ",*>>=", ",*>>", ",*nsv", ",*ev"
};
static const char *const cmpib_cond_64_names[] =
{
  ",*<<", ",*=", ",*<", ",*<=", ",*>>=", ",*<>", ",*>=", ",*>"
};
static const char *const add_cond_names[] =
{
  "", ",=", ",<", ",<=", ",nuv", ",znv", ",sv", ",od",
  ",tr", ",<>", ",>=", ",>", ",uv", ",vnz", ",nsv", ",ev"
};
static const char *const add_cond_64_names[] =
{
  ",*", ",*=", ",*<", ",*<=", ",*nuv", ",*znv", ",*sv", ",*od",
  ",*tr", ",*<>", ",*>=", ",*>", ",*uv", ",*vnz", ",*nsv", ",*ev"
};
static const char *const wide_add_cond_names[] =
{
  "", ",=", ",<", ",<=", ",nuv", ",*=", ",*<", ",*<=",
  ",tr", ",<>", ",>=", ",>", ",uv", ",*<>", ",*>=", ",*>"
};
static const char *const logical_cond_names[] =
{
  "", ",=", ",<", ",<=", 0, 0, 0, ",od",
  ",tr", ",<>", ",>=", ",>", 0, 0, 0, ",ev"};
static const char *const logical_cond_64_names[] =
{
  ",*", ",*=", ",*<", ",*<=", 0, 0, 0, ",*od",
  ",*tr", ",*<>", ",*>=", ",*>", 0, 0, 0, ",*ev"};
static const char *const unit_cond_names[] =
{
  "", ",swz", ",sbz", ",shz", ",sdc", ",swc", ",sbc", ",shc",
  ",tr", ",nwz", ",nbz", ",nhz", ",ndc", ",nwc", ",nbc", ",nhc"
};
static const char *const unit_cond_64_names[] =
{
  ",*", ",*swz", ",*sbz", ",*shz", ",*sdc", ",*swc", ",*sbc", ",*shc",
  ",*tr", ",*nwz", ",*nbz", ",*nhz", ",*ndc", ",*nwc", ",*nbc", ",*nhc"
};
static const char *const shift_cond_names[] =
{
  "", ",=", ",<", ",od", ",tr", ",<>", ",>=", ",ev"
};
static const char *const shift_cond_64_names[] =
{
  ",*", ",*=", ",*<", ",*od", ",*tr", ",*<>", ",*>=", ",*ev"
};
static const char *const bb_cond_64_names[] =
{
  ",*<", ",*>="
};
static const char *const index_compl_names[] = {"", ",m", ",s", ",sm"};
static const char *const short_ldst_compl_names[] = {"", ",ma", "", ",mb"};
static const char *const short_bytes_compl_names[] =
{
  "", ",b,m", ",e", ",e,m"
};
static const char *const float_format_names[] = {",sgl", ",dbl", "", ",quad"};
static const char *const fcnv_fixed_names[] = {",w", ",dw", "", ",qw"};
static const char *const fcnv_ufixed_names[] = {",uw", ",udw", "", ",uqw"};
static const char *const float_comp_names[] =
{
  ",false?", ",false", ",?", ",!<=>", ",=", ",=t", ",?=", ",!<>",
  ",!?>=", ",<", ",?<", ",!>=", ",!?>", ",<=", ",?<=", ",!>",
  ",!?<=", ",>", ",?>", ",!<=", ",!?<", ",>=", ",?>=", ",!<",
  ",!?=", ",<>", ",!=", ",!=t", ",!?", ",<=>", ",true?", ",true"
};
static const char *const signed_unsigned_names[] = {",u", ",s"};
static const char *const mix_half_names[] = {",l", ",r"};
static const char *const saturation_names[] = {",us", ",ss", 0, ""};
static const char *const read_write_names[] = {",r", ",w"};
static const char *const add_compl_names[] = { 0, "", ",l", ",tsv" };

/* For a bunch of different instructions form an index into a
   completer name table.  */
#define GET_COMPL(insn) (GET_FIELD (insn, 26, 26) | \
			 GET_FIELD (insn, 18, 18) << 1)

#define GET_COND(insn) (GET_FIELD ((insn), 16, 18) + \
			(GET_FIELD ((insn), 19, 19) ? 8 : 0))

/* Utility function to print registers.  Put these first, so gcc's function
   inlining can do its stuff.  */

#define fputs_filtered(STR,F)	(*info->fprintf_func) (info->stream, "%s", STR)

static void
fput_reg (unsigned reg, disassemble_info *info)
{
  (*info->fprintf_func) (info->stream, "%s", reg ? reg_names[reg] : "r0");
}

static void
fput_fp_reg (unsigned reg, disassemble_info *info)
{
  (*info->fprintf_func) (info->stream, "%s", reg ? fp_reg_names[reg] : "fr0");
}

static void
fput_fp_reg_r (unsigned reg, disassemble_info *info)
{
  /* Special case floating point exception registers.  */
  if (reg < 4) {
	  (*info->fprintf_func) (info->stream, "fpe%d", reg * 2 + 1);
  } else {
	  (*info->fprintf_func) (info->stream, "%sR", fp_reg_names[reg]);
  }
}

static void
fput_creg (unsigned reg, disassemble_info *info)
{
  (*info->fprintf_func) (info->stream, "%s", control_reg[reg]);
}

/* Print constants with sign.  */

static void
fput_const (unsigned num, disassemble_info *info)
{
	if ((int)num < 0) {
		(*info->fprintf_func) (info->stream, "-%x", -(int)num);
	} else {
		(*info->fprintf_func) (info->stream, "%x", num);
	}
}

/* Routines to extract various sized constants out of hppa
   instructions.  */

/* Extract a 3-bit space register number from a be, ble, mtsp or mfsp.  */
static int
extract_3 (unsigned word)
{
  return GET_FIELD (word, 18, 18) << 2 | GET_FIELD (word, 16, 17);
}

static int
extract_5_load (unsigned word)
{
  return low_sign_extend (word >> 16 & MASK_5, 5);
}

/* Extract the immediate field from a st{bhw}s instruction.  */

static int
extract_5_store (unsigned word)
{
  return low_sign_extend (word & MASK_5, 5);
}

/* Extract the immediate field from a break instruction.  */

static unsigned
extract_5r_store (unsigned word)
{
  return (word & MASK_5);
}

/* Extract the immediate field from a {sr}sm instruction.  */

static unsigned
extract_5R_store (unsigned word)
{
  return (word >> 16 & MASK_5);
}

/* Extract the 10 bit immediate field from a {sr}sm instruction.  */

static unsigned
extract_10U_store (unsigned word)
{
  return (word >> 16 & MASK_10);
}

/* Extract the immediate field from a bb instruction.  */

static unsigned
extract_5Q_store (unsigned word)
{
  return (word >> 21 & MASK_5);
}

/* Extract an 11 bit immediate field.  */

static int
extract_11 (unsigned word)
{
  return low_sign_extend (word & MASK_11, 11);
}

/* Extract a 14 bit immediate field.  */

static int
extract_14 (unsigned word)
{
  return low_sign_extend (word & MASK_14, 14);
}

/* Extract a 16 bit immediate field (PA2.0 wide only).  */

static int
extract_16 (unsigned word)
{
  int m15, m0, m1;

  m0 = GET_BIT (word, 16);
  m1 = GET_BIT (word, 17);
  m15 = GET_BIT (word, 31);
  word = (word >> 1) & 0x1fff;
  word = word | (m15 << 15) | ((m15 ^ m0) << 14) | ((m15 ^ m1) << 13);
  return sign_extend (word, 16);
}

/* Extract a 21 bit constant.  */

static int
extract_21 (unsigned word)
{
  int val;

  word &= MASK_21;
  word <<= 11;
  val = GET_FIELD (word, 20, 20);
  val <<= 11;
  val |= GET_FIELD (word, 9, 19);
  val <<= 2;
  val |= GET_FIELD (word, 5, 6);
  val <<= 5;
  val |= GET_FIELD (word, 0, 4);
  val <<= 2;
  val |= GET_FIELD (word, 7, 8);
  return sign_extend (val, 21) << 11;
}

/* Extract a 12 bit constant from branch instructions.  */

static int
extract_12 (unsigned word)
{
  return sign_extend (GET_FIELD (word, 19, 28)
		      | GET_FIELD (word, 29, 29) << 10
		      | (word & 0x1) << 11, 12) << 2;
}

/* Extract a 17 bit constant from branch instructions, returning the
   19 bit signed value.  */

static int
extract_17 (unsigned word)
{
  return sign_extend (GET_FIELD (word, 19, 28)
		      | GET_FIELD (word, 29, 29) << 10
		      | GET_FIELD (word, 11, 15) << 11
		      | (word & 0x1) << 16, 17) << 2;
}

static int
extract_22 (unsigned word)
{
  return sign_extend (GET_FIELD (word, 19, 28)
		      | GET_FIELD (word, 29, 29) << 10
		      | GET_FIELD (word, 11, 15) << 11
		      | GET_FIELD (word, 6, 10) << 16
		      | (word & 0x1) << 21, 22) << 2;
}

/* Print one instruction.  */

int
print_insn_hppa (bfd_vma memaddr, disassemble_info *info)
{
  bfd_byte buffer[4];
  unsigned int insn, i;

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

  for (i = 0; i < NUMOPCODES; ++i)
    {
      const struct pa_opcode *opcode = &pa_opcodes[i];

      if ((insn & opcode->mask) == opcode->match)
	{
	  const char *s;
#ifndef BFD64
	  if (opcode->arch == pa20w)
	    continue;
#endif
	  (*info->fprintf_func) (info->stream, "%s", opcode->name);

	  if (!strchr ("cfCY?-+nHNZFIuv{", opcode->args[0])) {
		  (*info->fprintf_func) (info->stream, " ");
	  }
	  for (s = opcode->args; *s != '\0'; ++s)
	    {
	      switch (*s)
		{
		case 'x':
		  fput_reg (GET_FIELD (insn, 11, 15), info);
		  break;
		case 'a':
		case 'b':
		  fput_reg (GET_FIELD (insn, 6, 10), info);
		  break;
		case '^':
		  fput_creg (GET_FIELD (insn, 6, 10), info);
		  break;
		case 't':
		  fput_reg (GET_FIELD (insn, 27, 31), info);
		  break;

		  /* Handle floating point registers.  */
		case 'f':
		  switch (*++s)
		    {
		    case 't':
		      fput_fp_reg (GET_FIELD (insn, 27, 31), info);
		      break;
		    case 'T':
			    if (GET_FIELD (insn, 25, 25)) {
				    fput_fp_reg_r (GET_FIELD (insn, 27, 31), info);
			    } else {
				    fput_fp_reg (GET_FIELD (insn, 27, 31), info);
			    }
			    break;
		    case 'a':
			    if (GET_FIELD (insn, 25, 25)) {
				    fput_fp_reg_r (GET_FIELD (insn, 6, 10), info);
			    } else {
				    fput_fp_reg (GET_FIELD (insn, 6, 10), info);
			    }
			    break;

			    /* 'fA' will not generate a space before the register
			 name.  Normally that is fine.  Except that it
			 causes problems with xmpyu which has no FP format
			 completer.  */
		    case 'X':
		      fputs_filtered (" ", info);
		      /* FALLTHRU */

		    case 'A':
			    if (GET_FIELD (insn, 24, 24)) {
				    fput_fp_reg_r (GET_FIELD (insn, 6, 10), info);
			    } else {
				    fput_fp_reg (GET_FIELD (insn, 6, 10), info);
			    }
			    break;
		    case 'b':
			    if (GET_FIELD (insn, 25, 25)) {
				    fput_fp_reg_r (GET_FIELD (insn, 11, 15), info);
			    } else {
				    fput_fp_reg (GET_FIELD (insn, 11, 15), info);
			    }
			    break;
		    case 'B':
			    if (GET_FIELD (insn, 19, 19)) {
				    fput_fp_reg_r (GET_FIELD (insn, 11, 15), info);
			    } else {
				    fput_fp_reg (GET_FIELD (insn, 11, 15), info);
			    }
			    break;
		    case 'C':
		      {
			int reg = GET_FIELD (insn, 21, 22);
			reg |= GET_FIELD (insn, 16, 18) << 2;
			if (GET_FIELD (insn, 23, 23) != 0) {
				fput_fp_reg_r (reg, info);
			} else {
				fput_fp_reg (reg, info);
			}
			break;
		      }
		    case 'i':
		      {
			int reg = GET_FIELD (insn, 6, 10);

			reg |= (GET_FIELD (insn, 26, 26) << 4);
			fput_fp_reg (reg, info);
			break;
		      }
		    case 'j':
		      {
			int reg = GET_FIELD (insn, 11, 15);

			reg |= (GET_FIELD (insn, 26, 26) << 4);
			fput_fp_reg (reg, info);
			break;
		      }
		    case 'k':
		      {
			int reg = GET_FIELD (insn, 27, 31);

			reg |= (GET_FIELD (insn, 26, 26) << 4);
			fput_fp_reg (reg, info);
			break;
		      }
		    case 'l':
		      {
			int reg = GET_FIELD (insn, 21, 25);

			reg |= (GET_FIELD (insn, 26, 26) << 4);
			fput_fp_reg (reg, info);
			break;
		      }
		    case 'm':
		      {
			int reg = GET_FIELD (insn, 16, 20);

			reg |= (GET_FIELD (insn, 26, 26) << 4);
			fput_fp_reg (reg, info);
			break;
		      }

		      /* 'fe' will not generate a space before the register
			 name.  Normally that is fine.  Except that it
			 causes problems with fstw fe,y(b) which has no FP
			 format completer.  */
		    case 'E':
		      fputs_filtered (" ", info);
		      /* FALLTHRU */

		    case 'e':
			    if (GET_FIELD (insn, 30, 30)) {
				    fput_fp_reg_r (GET_FIELD (insn, 11, 15), info);
			    } else {
				    fput_fp_reg (GET_FIELD (insn, 11, 15), info);
			    }
			    break;
		    case 'x':
		      fput_fp_reg (GET_FIELD (insn, 11, 15), info);
		      break;
		    }
		  break;

		case '5':
		  fput_const (extract_5_load (insn), info);
		  break;
		case 's':
		  {
		    int space = GET_FIELD (insn, 16, 17);
		    /* Zero means implicit addressing, not use of sr0.  */
		    if (space != 0) {
			    (*info->fprintf_func) (info->stream, "sr%d", space);
		    }
		  }
		  break;

		case 'S':
		  (*info->fprintf_func) (info->stream, "sr%d",
					 extract_3 (insn));
		  break;

		  /* Handle completers.  */
		case 'c':
		  switch (*++s)
		    {
		    case 'x':
		      (*info->fprintf_func)
			(info->stream, "%s",
			 index_compl_names[GET_COMPL (insn)]);
		      break;
		    case 'X':
		      (*info->fprintf_func)
			(info->stream, "%s ",
			 index_compl_names[GET_COMPL (insn)]);
		      break;
		    case 'm':
		      (*info->fprintf_func)
			(info->stream, "%s",
			 short_ldst_compl_names[GET_COMPL (insn)]);
		      break;
		    case 'M':
		      (*info->fprintf_func)
			(info->stream, "%s ",
			 short_ldst_compl_names[GET_COMPL (insn)]);
		      break;
		    case 'A':
		      (*info->fprintf_func)
			(info->stream, "%s ",
			 short_bytes_compl_names[GET_COMPL (insn)]);
		      break;
		    case 's':
		      (*info->fprintf_func)
			(info->stream, "%s",
			 short_bytes_compl_names[GET_COMPL (insn)]);
		      break;
		    case 'c':
		    case 'C':
		      switch (GET_FIELD (insn, 20, 21))
			{
			case 1:
			  (*info->fprintf_func) (info->stream, ",bc ");
			  break;
			case 2:
			  (*info->fprintf_func) (info->stream, ",sl ");
			  break;
			default:
			  (*info->fprintf_func) (info->stream, " ");
			}
		      break;
		    case 'd':
		      switch (GET_FIELD (insn, 20, 21))
			{
			case 1:
			  (*info->fprintf_func) (info->stream, ",co ");
			  break;
			default:
			  (*info->fprintf_func) (info->stream, " ");
			}
		      break;
		    case 'o':
		      (*info->fprintf_func) (info->stream, ",o");
		      break;
		    case 'g':
		      (*info->fprintf_func) (info->stream, ",gate");
		      break;
		    case 'p':
		      (*info->fprintf_func) (info->stream, ",l,push");
		      break;
		    case 'P':
		      (*info->fprintf_func) (info->stream, ",pop");
		      break;
		    case 'l':
		    case 'L':
		      (*info->fprintf_func) (info->stream, ",l");
		      break;
		    case 'w':
		      (*info->fprintf_func)
			(info->stream, "%s ",
			 read_write_names[GET_FIELD (insn, 25, 25)]);
		      break;
		    case 'W':
		      (*info->fprintf_func) (info->stream, ",w ");
		      break;
		    case 'r':
			    if (GET_FIELD (insn, 23, 26) == 5) {
				    (*info->fprintf_func) (info->stream, ",r");
			    }
			    break;
		    case 'Z':
			    if (GET_FIELD (insn, 26, 26)) {
				    (*info->fprintf_func) (info->stream, ",m ");
			    } else {
				    (*info->fprintf_func) (info->stream, " ");
			    }
			    break;
		    case 'i':
			    if (GET_FIELD (insn, 25, 25)) {
				    (*info->fprintf_func) (info->stream, ",i");
			    }
			    break;
		    case 'z':
			    if (!GET_FIELD (insn, 21, 21)) {
				    (*info->fprintf_func) (info->stream, ",z");
			    }
			    break;
		    case 'a':
		      (*info->fprintf_func)
			(info->stream, "%s",
			 add_compl_names[GET_FIELD (insn, 20, 21)]);
		      break;
		    case 'Y':
		      (*info->fprintf_func)
			(info->stream, ",dc%s",
			 add_compl_names[GET_FIELD (insn, 20, 21)]);
		      break;
		    case 'y':
		      (*info->fprintf_func)
			(info->stream, ",c%s",
			 add_compl_names[GET_FIELD (insn, 20, 21)]);
		      break;
		    case 'v':
			    if (GET_FIELD (insn, 20, 20)) {
				    (*info->fprintf_func) (info->stream, ",tsv");
			    }
			    break;
		    case 't':
		      (*info->fprintf_func) (info->stream, ",tc");
		      if (GET_FIELD (insn, 20, 20)) {
			      (*info->fprintf_func) (info->stream, ",tsv");
		      }
		      break;
		    case 'B':
		      (*info->fprintf_func) (info->stream, ",db");
		      if (GET_FIELD (insn, 20, 20)) {
			      (*info->fprintf_func) (info->stream, ",tsv");
		      }
		      break;
		    case 'b':
		      (*info->fprintf_func) (info->stream, ",b");
		      if (GET_FIELD (insn, 20, 20)) {
			      (*info->fprintf_func) (info->stream, ",tsv");
		      }
		      break;
		    case 'T':
			    if (GET_FIELD (insn, 25, 25)) {
				    (*info->fprintf_func) (info->stream, ",tc");
			    }
			    break;
		    case 'S':
		      /* EXTRD/W has a following condition.  */
		      if (*(s + 1) == '?') {
			      (*info->fprintf_func) (info->stream, "%s",
				      signed_unsigned_names[GET_FIELD (insn, 21, 21)]);
		      } else {
			      (*info->fprintf_func) (info->stream, "%s ",
				      signed_unsigned_names[GET_FIELD (insn, 21, 21)]);
		      }
		      break;
		    case 'h':
		      (*info->fprintf_func)
			(info->stream, "%s",
			 mix_half_names[GET_FIELD (insn, 17, 17)]);
		      break;
		    case 'H':
		      (*info->fprintf_func)
			(info->stream, "%s ",
			 saturation_names[GET_FIELD (insn, 24, 25)]);
		      break;
		    case '*':
		      (*info->fprintf_func)
			(info->stream, ",%d%d%d%d ",
			 GET_FIELD (insn, 17, 18), GET_FIELD (insn, 20, 21),
			 GET_FIELD (insn, 22, 23), GET_FIELD (insn, 24, 25));
		      break;

		    case 'q':
		      {
			int m, a;

			m = GET_FIELD (insn, 28, 28);
			a = GET_FIELD (insn, 29, 29);

			if (m && !a) {
				fputs_filtered (",ma ", info);
			} else if (m && a) {
				fputs_filtered (",mb ", info);
			} else {
				fputs_filtered (" ", info);
			}
			break;
		      }

		    case 'J':
		      {
			int opc = GET_FIELD (insn, 0, 5);

			if (opc == 0x16 || opc == 0x1e)
			  {
				if (GET_FIELD (insn, 29, 29) == 0) {
					fputs_filtered (",ma ", info);
				} else {
					fputs_filtered (",mb ", info);
				}
			} else {
				fputs_filtered (" ", info);
			}
			break;
		      }

		    case 'e':
		      {
			int opc = GET_FIELD (insn, 0, 5);

			if (opc == 0x13 || opc == 0x1b)
			  {
				if (GET_FIELD (insn, 18, 18) == 1) {
					fputs_filtered (",mb ", info);
				} else {
					fputs_filtered (",ma ", info);
				}
			  }
			else if (opc == 0x17 || opc == 0x1f)
			  {
				  if (GET_FIELD (insn, 31, 31) == 1) {
					  fputs_filtered (",ma ", info);
				  } else {
					  fputs_filtered (",mb ", info);
				  }
			  } else {
				  fputs_filtered (" ", info);
			  }

			  break;
		      }
		    }
		  break;

		  /* Handle conditions.  */
		case '?':
		  {
		    s++;
		    switch (*s)
		      {
		      case 'f':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   float_comp_names[GET_FIELD (insn, 27, 31)]);
			break;

			/* These four conditions are for the set of instructions
			   which distinguish true/false conditions by opcode
			   rather than by the 'f' bit (sigh): comb, comib,
			   addb, addib.  */
		      case 't':
			fputs_filtered
			  (compare_cond_names[GET_FIELD (insn, 16, 18)], info);
			break;
		      case 'n':
			fputs_filtered
			  (compare_cond_names[GET_FIELD (insn, 16, 18)
					      + GET_FIELD (insn, 4, 4) * 8],
			   info);
			break;
		      case 'N':
			fputs_filtered
			  (compare_cond_64_names[GET_FIELD (insn, 16, 18)
						 + GET_FIELD (insn, 2, 2) * 8],
			   info);
			break;
		      case 'Q':
			fputs_filtered
			  (cmpib_cond_64_names[GET_FIELD (insn, 16, 18)],
			   info);
			break;
		      case '@':
			fputs_filtered
			  (add_cond_names[GET_FIELD (insn, 16, 18)
					  + GET_FIELD (insn, 4, 4) * 8],
			   info);
			break;
		      case 's':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   compare_cond_names[GET_COND (insn)]);
			break;
		      case 'S':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   compare_cond_64_names[GET_COND (insn)]);
			break;
		      case 'a':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   add_cond_names[GET_COND (insn)]);
			break;
		      case 'A':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   add_cond_64_names[GET_COND (insn)]);
			break;
		      case 'd':
			(*info->fprintf_func)
			  (info->stream, "%s",
			   add_cond_names[GET_FIELD (insn, 16, 18)]);
			break;

		      case 'W':
			(*info->fprintf_func)
			  (info->stream, "%s",
			   wide_add_cond_names[GET_FIELD (insn, 16, 18) +
					       GET_FIELD (insn, 4, 4) * 8]);
			break;

		      case 'l':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   logical_cond_names[GET_COND (insn)]);
			break;
		      case 'L':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   logical_cond_64_names[GET_COND (insn)]);
			break;
		      case 'u':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   unit_cond_names[GET_COND (insn)]);
			break;
		      case 'U':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   unit_cond_64_names[GET_COND (insn)]);
			break;
		      case 'y':
		      case 'x':
		      case 'b':
			(*info->fprintf_func)
			  (info->stream, "%s",
			   shift_cond_names[GET_FIELD (insn, 16, 18)]);

			/* If the next character in args is 'n', it will handle
			   putting out the space.  */
			if (s[1] != 'n') {
				(*info->fprintf_func) (info->stream, " ");
			}
			break;
		      case 'X':
			(*info->fprintf_func)
			  (info->stream, "%s ",
			   shift_cond_64_names[GET_FIELD (insn, 16, 18)]);
			break;
		      case 'B':
			(*info->fprintf_func)
			  (info->stream, "%s",
			   bb_cond_64_names[GET_FIELD (insn, 16, 16)]);

			/* If the next character in args is 'n', it will handle
			   putting out the space.  */
			if (s[1] != 'n') {
				(*info->fprintf_func) (info->stream, " ");
			}
			break;
		      }
		    break;
		  }

		case 'V':
		  fput_const (extract_5_store (insn), info);
		  break;
		case 'r':
		  fput_const (extract_5r_store (insn), info);
		  break;
		case 'R':
		  fput_const (extract_5R_store (insn), info);
		  break;
		case 'U':
		  fput_const (extract_10U_store (insn), info);
		  break;
		case 'B':
		case 'Q':
		  fput_const (extract_5Q_store (insn), info);
		  break;
		case 'i':
		  fput_const (extract_11 (insn), info);
		  break;
		case 'j':
		  fput_const (extract_14 (insn), info);
		  break;
		case 'k':
		  fputs_filtered ("L%", info);
		  fput_const (extract_21 (insn), info);
		  break;
		case '<':
		case 'l':
		  /* 16-bit long disp., PA2.0 wide only.  */
		  fput_const (extract_16 (insn), info);
		  break;
		case 'n':
			if (insn & 0x2) {
				(*info->fprintf_func) (info->stream, ",n ");
			} else {
				(*info->fprintf_func) (info->stream, " ");
			}
			break;
		case 'N':
			if ((insn & 0x20) && s[1]) {
				(*info->fprintf_func) (info->stream, ",n ");
			} else if (insn & 0x20) {
				(*info->fprintf_func) (info->stream, ",n");
			} else if (s[1]) {
				(*info->fprintf_func) (info->stream, " ");
			}
			break;
		case 'w':
		  (*info->print_address_func)
		    (memaddr + 8 + extract_12 (insn), info);
		  break;
		case 'W':
		  /* 17 bit PC-relative branch.  */
		  (*info->print_address_func)
		    ((memaddr + 8 + extract_17 (insn)), info);
		  break;
		case 'z':
		  /* 17 bit displacement.  This is an offset from a register
		     so it gets disasssembled as just a number, not any sort
		     of address.  */
		  fput_const (extract_17 (insn), info);
		  break;

		case 'Z':
		  /* addil %r1 implicit output.  */
		  fputs_filtered ("r1", info);
		  break;

		case 'Y':
		  /* be,l %sr0,%r31 implicit output.  */
		  fputs_filtered ("sr0,r31", info);
		  break;

		case '@':
		  (*info->fprintf_func) (info->stream, "0");
		  break;

		case '.':
		  (*info->fprintf_func) (info->stream, "%d",
					 GET_FIELD (insn, 24, 25));
		  break;
		case '*':
		  (*info->fprintf_func) (info->stream, "%d",
					 GET_FIELD (insn, 22, 25));
		  break;
		case '!':
		  fputs_filtered ("sar", info);
		  break;
		case 'p':
		  (*info->fprintf_func) (info->stream, "%d",
					 31 - GET_FIELD (insn, 22, 26));
		  break;
		case '~':
		  {
		    int num;
		    num = GET_FIELD (insn, 20, 20) << 5;
		    num |= GET_FIELD (insn, 22, 26);
		    (*info->fprintf_func) (info->stream, "%d", 63 - num);
		    break;
		  }
		case 'P':
		  (*info->fprintf_func) (info->stream, "%d",
					 GET_FIELD (insn, 22, 26));
		  break;
		case 'q':
		  {
		    int num;
		    num = GET_FIELD (insn, 20, 20) << 5;
		    num |= GET_FIELD (insn, 22, 26);
		    (*info->fprintf_func) (info->stream, "%d", num);
		    break;
		  }
		case 'T':
		  (*info->fprintf_func) (info->stream, "%d",
					 32 - GET_FIELD (insn, 27, 31));
		  break;
		case '%':
		  {
		    int num;
		    num = (GET_FIELD (insn, 23, 23) + 1) * 32;
		    num -= GET_FIELD (insn, 27, 31);
		    (*info->fprintf_func) (info->stream, "%d", num);
		    break;
		  }
		case '|':
		  {
		    int num;
		    num = (GET_FIELD (insn, 19, 19) + 1) * 32;
		    num -= GET_FIELD (insn, 27, 31);
		    (*info->fprintf_func) (info->stream, "%d", num);
		    break;
		  }
		case '$':
		  fput_const (GET_FIELD (insn, 20, 28), info);
		  break;
		case 'A':
		  fput_const (GET_FIELD (insn, 6, 18), info);
		  break;
		case 'D':
		  fput_const (GET_FIELD (insn, 6, 31), info);
		  break;
		case 'v':
		  (*info->fprintf_func) (info->stream, ",%d",
					 GET_FIELD (insn, 23, 25));
		  break;
		case 'O':
		  fput_const ((GET_FIELD (insn, 6,20) << 5 |
			       GET_FIELD (insn, 27, 31)), info);
		  break;
		case 'o':
		  fput_const (GET_FIELD (insn, 6, 20), info);
		  break;
		case '2':
		  fput_const ((GET_FIELD (insn, 6, 22) << 5 |
			       GET_FIELD (insn, 27, 31)), info);
		  break;
		case '1':
		  fput_const ((GET_FIELD (insn, 11, 20) << 5 |
			       GET_FIELD (insn, 27, 31)), info);
		  break;
		case '0':
		  fput_const ((GET_FIELD (insn, 16, 20) << 5 |
			       GET_FIELD (insn, 27, 31)), info);
		  break;
		case 'u':
		  (*info->fprintf_func) (info->stream, ",%d",
					 GET_FIELD (insn, 23, 25));
		  break;
		case 'F':
		  /* If no destination completer and not before a completer
		     for fcmp, need a space here.  */
		  if (s[1] == 'G' || s[1] == '?') {
			  fputs_filtered (float_format_names[GET_FIELD (insn, 19, 20)], info);
		  } else {
			  (*info->fprintf_func) (info->stream, "%s ",
				  float_format_names[GET_FIELD (insn, 19, 20)]);
		  }
		  break;
		case 'G':
		  (*info->fprintf_func)
		    (info->stream, "%s ",
		     float_format_names[GET_FIELD (insn, 17, 18)]);
		  break;
		case 'H':
			if (GET_FIELD (insn, 26, 26) == 1) {
				(*info->fprintf_func) (info->stream, "%s ",
					float_format_names[0]);
			} else {
				(*info->fprintf_func) (info->stream, "%s ",
					float_format_names[1]);
			}
			break;
		case 'I':
		  /* If no destination completer and not before a completer
		     for fcmp, need a space here.  */
		  if (s[1] == '?') {
			  fputs_filtered (float_format_names[GET_FIELD (insn, 20, 20)], info);
		  } else {
			  (*info->fprintf_func) (info->stream, "%s ",
				  float_format_names[GET_FIELD (insn, 20, 20)]);
		  }
		  break;

		case 'J':
		  fput_const (extract_14 (insn), info);
		  break;

		case '#':
		  {
		    int sign = GET_FIELD (insn, 31, 31);
		    int imm10 = GET_FIELD (insn, 18, 27);
		    int disp;

		    if (sign) {
			    disp = (UT64_MAX << 10) | imm10;
		    } else {
			    disp = imm10;
		    }

		    disp <<= 3;
		    fput_const (disp, info);
		    break;
		  }
		case 'K':
		case 'd':
		  {
		    int sign = GET_FIELD (insn, 31, 31);
		    int imm11 = GET_FIELD (insn, 18, 28);
		    int disp;

		    if (sign) {
			    disp = (UT64_MAX << 11) | imm11;
		    } else {
			    disp = imm11;
		    }

		    disp <<= 2;
		    fput_const (disp, info);
		    break;
		  }

		case '>':
		case 'y':
		  {
		    /* 16-bit long disp., PA2.0 wide only.  */
		    int disp = extract_16 (insn);
		    disp &= ~3;
		    fput_const (disp, info);
		    break;
		  }

		case '&':
		  {
		    /* 16-bit long disp., PA2.0 wide only.  */
		    int disp = extract_16 (insn);
		    disp &= ~7;
		    fput_const (disp, info);
		    break;
		  }

		case '_':
		  break; /* Dealt with by '{' */

		case '{':
		  {
		    int sub = GET_FIELD (insn, 14, 16);
		    int df = GET_FIELD (insn, 17, 18);
		    int sf = GET_FIELD (insn, 19, 20);
		    const char * const * source = float_format_names;
		    const char * const * dest = float_format_names;
		    char *t = "";

		    if (sub == 4)
		      {
			fputs_filtered (",UND ", info);
			break;
		      }
		      if ((sub & 3) == 3) {
			      t = ",t";
		      }
		      if ((sub & 3) == 1) {
			      source = sub & 4 ? fcnv_ufixed_names : fcnv_fixed_names;
		      }
		      if (sub & 2) {
			      dest = sub & 4 ? fcnv_ufixed_names : fcnv_fixed_names;
		      }

		      (*info->fprintf_func) (info->stream, "%s%s%s ",
			      t, source[sf], dest[df]);
		      break;
		  }

		case 'm':
		  {
		    int y = GET_FIELD (insn, 16, 18);

		    if (y != 1) {
			    fput_const ((y ^ 1) - 1, info);
		    }
		  }
		  break;

		case 'h':
		  {
		    int cbit;

		    cbit = GET_FIELD (insn, 16, 18);

		    if (cbit > 0) {
			    (*info->fprintf_func) (info->stream, ",%d", cbit - 1);
		    }
		    break;
		  }

		case '=':
		  {
		    int cond = GET_FIELD (insn, 27, 31);

		    switch (cond)
		      {
		      case  0: fputs_filtered (" ", info); break;
		      case  1: fputs_filtered ("acc ", info); break;
		      case  2: fputs_filtered ("rej ", info); break;
		      case  5: fputs_filtered ("acc8 ", info); break;
		      case  6: fputs_filtered ("rej8 ", info); break;
		      case  9: fputs_filtered ("acc6 ", info); break;
		      case 13: fputs_filtered ("acc4 ", info); break;
		      case 17: fputs_filtered ("acc2 ", info); break;
		      default: break;
		      }
		    break;
		  }

		case 'X':
		  (*info->print_address_func)
		    (memaddr + 8 + extract_22 (insn), info);
		  break;
		case 'L':
		  fputs_filtered (",rp", info);
		  break;
		default:
		  (*info->fprintf_func) (info->stream, "%c", *s);
		  break;
		}
	    }
	  return sizeof (insn);
	}
    }
  (*info->fprintf_func) (info->stream, "#%8x", insn);
  return sizeof (insn);
}
