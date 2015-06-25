/* HP PA-RISC SOM object file format:  definitions internal to BFD.
   Copyright (C) 1990-2014 Free Software Foundation, Inc.

   Contributed by the Center for Software Science at the
   University of Utah (pa-gdb-bugs@cs.utah.edu).

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#ifndef _LIBHPPA_H
#define _LIBHPPA_H

#define BYTES_IN_WORD 4
#define PA_PAGESIZE 0x1000

/* The PA instruction set variants.  */
enum pa_arch {pa10 = 10, pa11 = 11, pa20 = 20, pa20w = 25};

/* HP PA-RISC relocation types */

enum hppa_reloc_field_selector_type
  {
    R_HPPA_FSEL = 0x0,
    R_HPPA_LSSEL = 0x1,
    R_HPPA_RSSEL = 0x2,
    R_HPPA_LSEL = 0x3,
    R_HPPA_RSEL = 0x4,
    R_HPPA_LDSEL = 0x5,
    R_HPPA_RDSEL = 0x6,
    R_HPPA_LRSEL = 0x7,
    R_HPPA_RRSEL = 0x8,
    R_HPPA_NSEL  = 0x9,
    R_HPPA_NLSEL  = 0xa,
    R_HPPA_NLRSEL  = 0xb,
    R_HPPA_PSEL = 0xc,
    R_HPPA_LPSEL = 0xd,
    R_HPPA_RPSEL = 0xe,
    R_HPPA_TSEL = 0xf,
    R_HPPA_LTSEL = 0x10,
    R_HPPA_RTSEL = 0x11,
    R_HPPA_LTPSEL = 0x12,
    R_HPPA_RTPSEL = 0x13
  };

/* /usr/include/reloc.h defines these to constants.  We want to use
   them in enums, so #undef them before we start using them.  We might
   be able to fix this another way by simply managing not to include
   /usr/include/reloc.h, but currently GDB picks up these defines
   somewhere.  */
#undef e_fsel
#undef e_lssel
#undef e_rssel
#undef e_lsel
#undef e_rsel
#undef e_ldsel
#undef e_rdsel
#undef e_lrsel
#undef e_rrsel
#undef e_nsel
#undef e_nlsel
#undef e_nlrsel
#undef e_psel
#undef e_lpsel
#undef e_rpsel
#undef e_tsel
#undef e_ltsel
#undef e_rtsel
#undef e_one
#undef e_two
#undef e_pcrel
#undef e_con
#undef e_plabel
#undef e_abs

/* for compatibility */
enum hppa_reloc_field_selector_type_alt
  {
    e_fsel = R_HPPA_FSEL,
    e_lssel = R_HPPA_LSSEL,
    e_rssel = R_HPPA_RSSEL,
    e_lsel = R_HPPA_LSEL,
    e_rsel = R_HPPA_RSEL,
    e_ldsel = R_HPPA_LDSEL,
    e_rdsel = R_HPPA_RDSEL,
    e_lrsel = R_HPPA_LRSEL,
    e_rrsel = R_HPPA_RRSEL,
    e_nsel = R_HPPA_NSEL,
    e_nlsel = R_HPPA_NLSEL,
    e_nlrsel = R_HPPA_NLRSEL,
    e_psel = R_HPPA_PSEL,
    e_lpsel = R_HPPA_LPSEL,
    e_rpsel = R_HPPA_RPSEL,
    e_tsel = R_HPPA_TSEL,
    e_ltsel = R_HPPA_LTSEL,
    e_rtsel = R_HPPA_RTSEL,
    e_ltpsel = R_HPPA_LTPSEL,
    e_rtpsel = R_HPPA_RTPSEL
  };

enum hppa_reloc_expr_type
  {
    R_HPPA_E_ONE = 0,
    R_HPPA_E_TWO = 1,
    R_HPPA_E_PCREL = 2,
    R_HPPA_E_CON = 3,
    R_HPPA_E_PLABEL = 7,
    R_HPPA_E_ABS = 18
  };

/* for compatibility */
enum hppa_reloc_expr_type_alt
  {
    e_one = R_HPPA_E_ONE,
    e_two = R_HPPA_E_TWO,
    e_pcrel = R_HPPA_E_PCREL,
    e_con = R_HPPA_E_CON,
    e_plabel = R_HPPA_E_PLABEL,
    e_abs = R_HPPA_E_ABS
  };


/* Relocations for function calls must be accompanied by parameter
   relocation bits.  These bits describe exactly where the caller has
   placed the function's arguments and where it expects to find a return
   value.

   Both ELF and SOM encode this information within the addend field
   of the call relocation.  (Note this could break very badly if one
   was to make a call like bl foo + 0x12345678).

   The high order 10 bits contain parameter relocation information,
   the low order 22 bits contain the constant offset.  */

#define HPPA_R_ARG_RELOC(a)	\
  (((a) >> 22) & 0x3ff)
#define HPPA_R_CONSTANT(a)	\
  ((((bfd_signed_vma)(a)) << (BFD_ARCH_SIZE-22)) >> (BFD_ARCH_SIZE-22))
#define HPPA_R_ADDEND(r, c)	\
  (((r) << 22) + ((c) & 0x3fffff))


/* Some functions to manipulate PA instructions.  */

/* Declare the functions with the unused attribute to avoid warnings.  */
static inline int sign_extend (int, int) ATTRIBUTE_UNUSED;
static inline int low_sign_extend (int, int) ATTRIBUTE_UNUSED;
static inline int sign_unext (int, int) ATTRIBUTE_UNUSED;
static inline int low_sign_unext (int, int) ATTRIBUTE_UNUSED;
static inline int re_assemble_3 (int) ATTRIBUTE_UNUSED;
static inline int re_assemble_12 (int) ATTRIBUTE_UNUSED;
static inline int re_assemble_14 (int) ATTRIBUTE_UNUSED;
static inline int re_assemble_16 (int) ATTRIBUTE_UNUSED;
static inline int re_assemble_17 (int) ATTRIBUTE_UNUSED;
static inline int re_assemble_21 (int) ATTRIBUTE_UNUSED;
static inline int re_assemble_22 (int) ATTRIBUTE_UNUSED;
static inline bfd_signed_vma hppa_field_adjust
  (bfd_vma, bfd_signed_vma, enum hppa_reloc_field_selector_type_alt)
  ATTRIBUTE_UNUSED;
static inline int bfd_hppa_insn2fmt (bfd *, int) ATTRIBUTE_UNUSED;
static inline int hppa_rebuild_insn (int, int, int) ATTRIBUTE_UNUSED;


/* The *sign_extend functions are used to assemble various bitfields
   taken from an instruction and return the resulting immediate
   value.  */

static inline int
sign_extend (int x, int len)
{
  int signbit = (1 << (len - 1));
  int mask = (signbit << 1) - 1;
  return ((x & mask) ^ signbit) - signbit;
}

static inline int
low_sign_extend (int x, int len)
{
  return (x >> 1) - ((x & 1) << (len - 1));
}


/* The re_assemble_* functions prepare an immediate value for
   insertion into an opcode. pa-risc uses all sorts of weird bitfields
   in the instruction to hold the value.  */

static inline int
sign_unext (int x, int len)
{
  int len_ones;

  len_ones = (1 << len) - 1;

  return x & len_ones;
}

static inline int
low_sign_unext (int x, int len)
{
  int temp;
  int sign;

  sign = (x >> (len-1)) & 1;

  temp = sign_unext (x, len-1);

  return (temp << 1) | sign;
}

static inline int
re_assemble_3 (int as3)
{
  return ((  (as3 & 4) << (13-2))
	  | ((as3 & 3) << (13+1)));
}

static inline int
re_assemble_12 (int as12)
{
  return ((  (as12 & 0x800) >> 11)
	  | ((as12 & 0x400) >> (10 - 2))
	  | ((as12 & 0x3ff) << (1 + 2)));
}

static inline int
re_assemble_14 (int as14)
{
  return ((  (as14 & 0x1fff) << 1)
	  | ((as14 & 0x2000) >> 13));
}

static inline int
re_assemble_16 (int as16)
{
  int s, t;

  /* Unusual 16-bit encoding, for wide mode only.  */
  t = (as16 << 1) & 0xffff;
  s = (as16 & 0x8000);
  return (t ^ s ^ (s >> 1)) | (s >> 15);
}

static inline int
re_assemble_17 (int as17)
{
  return ((  (as17 & 0x10000) >> 16)
	  | ((as17 & 0x0f800) << (16 - 11))
	  | ((as17 & 0x00400) >> (10 - 2))
	  | ((as17 & 0x003ff) << (1 + 2)));
}

static inline int
re_assemble_21 (int as21)
{
  return ((  (as21 & 0x100000) >> 20)
	  | ((as21 & 0x0ffe00) >> 8)
	  | ((as21 & 0x000180) << 7)
	  | ((as21 & 0x00007c) << 14)
	  | ((as21 & 0x000003) << 12));
}

static inline int
re_assemble_22 (int as22)
{
  return ((  (as22 & 0x200000) >> 21)
	  | ((as22 & 0x1f0000) << (21 - 16))
	  | ((as22 & 0x00f800) << (16 - 11))
	  | ((as22 & 0x000400) >> (10 - 2))
	  | ((as22 & 0x0003ff) << (1 + 2)));
}


/* Handle field selectors for PA instructions.
   The L and R (and LS, RS etc.) selectors are used in pairs to form a
   full 32 bit address.  eg.

   LDIL	L'start,%r1		; put left part into r1
   LDW	R'start(%r1),%r2	; add r1 and right part to form address

   This function returns sign extended values in all cases.
*/

static inline bfd_signed_vma
hppa_field_adjust (bfd_vma sym_val,
		   bfd_signed_vma addend,
		   enum hppa_reloc_field_selector_type_alt r_field)
{
  bfd_signed_vma value;

  value = sym_val + addend;
  switch (r_field)
    {
    case e_fsel:
      /* F: No change.  */
      break;

    case e_nsel:
      /* N: null selector.  I don't really understand what this is all
	 about, but HP's documentation says "this indicates that zero
	 bits are to be used for the displacement on the instruction.
	 This fixup is used to identify three-instruction sequences to
	 access data (for importing shared library data)."  */
      value = 0;
      break;

    case e_lsel:
    case e_nlsel:
      /* L:  Select top 21 bits.  */
      value = value >> 11;
      break;

    case e_rsel:
      /* R:  Select bottom 11 bits.  */
      value = value & 0x7ff;
      break;

    case e_lssel:
      /* LS:  Round to nearest multiple of 2048 then select top 21 bits.  */
      value = value + 0x400;
      value = value >> 11;
      break;

    case e_rssel:
      /* RS:  Select bottom 11 bits for LS.
	 We need to return a value such that 2048 * LS'x + RS'x == x.
	 ie. RS'x = x - ((x + 0x400) & -0x800)
	 this is just a sign extension from bit 21.  */
      value = ((value & 0x7ff) ^ 0x400) - 0x400;
      break;

    case e_ldsel:
      /* LD:  Round to next multiple of 2048 then select top 21 bits.
	 Yes, if we are already on a multiple of 2048, we go up to the
	 next one.  RD in this case will be -2048.  */
      value = value + 0x800;
      value = value >> 11;
      break;

    case e_rdsel:
      /* RD:  Set bits 0-20 to one.  */
      value = value | -0x800;
      break;

    case e_lrsel:
    case e_nlrsel:
      /* LR:  L with rounding of the addend to nearest 8k.  */
      value = sym_val + ((addend + 0x1000) & -0x2000);
      value = value >> 11;
      break;

    case e_rrsel:
      /* RR:  R with rounding of the addend to nearest 8k.
	 We need to return a value such that 2048 * LR'x + RR'x == x
	 ie. RR'x = s+a - (s + (((a + 0x1000) & -0x2000) & -0x800))
	 .	  = s+a - ((s & -0x800) + ((a + 0x1000) & -0x2000))
	 .	  = (s & 0x7ff) + a - ((a + 0x1000) & -0x2000)  */
      value = (sym_val & 0x7ff) + (((addend & 0x1fff) ^ 0x1000) - 0x1000);
      break;

    default:
      return -1;
    }
  return value;
}

/* PA-RISC OPCODES */
#define get_opcode(insn)	(((insn) >> 26) & 0x3f)

enum hppa_opcode_type
{
  /* None of the opcodes in the first group generate relocs, so we
     aren't too concerned about them.  */
  OP_SYSOP   = 0x00,
  OP_MEMMNG  = 0x01,
  OP_ALU     = 0x02,
  OP_NDXMEM  = 0x03,
  OP_SPOP    = 0x04,
  OP_DIAG    = 0x05,
  OP_FMPYADD = 0x06,
  OP_UNDEF07 = 0x07,
  OP_COPRW   = 0x09,
  OP_COPRDW  = 0x0b,
  OP_COPR    = 0x0c,
  OP_FLOAT   = 0x0e,
  OP_PRDSPEC = 0x0f,
  OP_UNDEF15 = 0x15,
  OP_UNDEF1d = 0x1d,
  OP_FMPYSUB = 0x26,
  OP_FPFUSED = 0x2e,
  OP_SHEXDP0 = 0x34,
  OP_SHEXDP1 = 0x35,
  OP_SHEXDP2 = 0x36,
  OP_UNDEF37 = 0x37,
  OP_SHEXDP3 = 0x3c,
  OP_SHEXDP4 = 0x3d,
  OP_MULTMED = 0x3e,
  OP_UNDEF3f = 0x3f,

  OP_LDIL    = 0x08,
  OP_ADDIL   = 0x0a,

  OP_LDO     = 0x0d,
  OP_LDB     = 0x10,
  OP_LDH     = 0x11,
  OP_LDW     = 0x12,
  OP_LDWM    = 0x13,
  OP_STB     = 0x18,
  OP_STH     = 0x19,
  OP_STW     = 0x1a,
  OP_STWM    = 0x1b,

  OP_LDD     = 0x14,
  OP_STD     = 0x1c,

  OP_FLDW    = 0x16,
  OP_LDWL    = 0x17,
  OP_FSTW    = 0x1e,
  OP_STWL    = 0x1f,

  OP_COMBT   = 0x20,
  OP_COMIBT  = 0x21,
  OP_COMBF   = 0x22,
  OP_COMIBF  = 0x23,
  OP_CMPBDT  = 0x27,
  OP_ADDBT   = 0x28,
  OP_ADDIBT  = 0x29,
  OP_ADDBF   = 0x2a,
  OP_ADDIBF  = 0x2b,
  OP_CMPBDF  = 0x2f,
  OP_BVB     = 0x30,
  OP_BB      = 0x31,
  OP_MOVB    = 0x32,
  OP_MOVIB   = 0x33,
  OP_CMPIBD  = 0x3b,

  OP_COMICLR = 0x24,
  OP_SUBI    = 0x25,
  OP_ADDIT   = 0x2c,
  OP_ADDI    = 0x2d,

  OP_BE      = 0x38,
  OP_BLE     = 0x39,
  OP_BL      = 0x3a
};


/* Given a machine instruction, return its format.  */

static inline int
bfd_hppa_insn2fmt (bfd *abfd, int insn)
{
  enum hppa_opcode_type op = get_opcode (insn);

  switch (op)
    {
    case OP_COMICLR:
    case OP_SUBI:
    case OP_ADDIT:
    case OP_ADDI:
      return 11;

    case OP_COMBT:
    case OP_COMIBT:
    case OP_COMBF:
    case OP_COMIBF:
    case OP_CMPBDT:
    case OP_ADDBT:
    case OP_ADDIBT:
    case OP_ADDBF:
    case OP_ADDIBF:
    case OP_CMPBDF:
    case OP_BVB:
    case OP_BB:
    case OP_MOVB:
    case OP_MOVIB:
    case OP_CMPIBD:
      return 12;

    case OP_LDO:
    case OP_LDB:
    case OP_LDH:
    case OP_LDW:
    case OP_LDWM:
    case OP_STB:
    case OP_STH:
    case OP_STW:
    case OP_STWM:
      if (abfd->arch_info->mach >= 25)
	return 16;	/* Wide mode, format 16.  */
      return 14;

    case OP_FLDW:
    case OP_LDWL:
    case OP_FSTW:
    case OP_STWL:
      /* This is a hack.  Unfortunately, format 11 is already taken
	 and we're using integers rather than an enum, so it's hard
	 to describe the 11a format.  */
      if (abfd->arch_info->mach >= 25)
	return -16;	/* Wide mode, format 16a.  */
      return -11;

    case OP_LDD:
    case OP_STD:
      if (abfd->arch_info->mach >= 25)
	return -10;	/* Wide mode, format 10a.  */
      return 10;

    case OP_BL:
      if ((insn & 0x8000) != 0)
	return 22;
      /* fall thru */
    case OP_BE:
    case OP_BLE:
      return 17;

    case OP_LDIL:
    case OP_ADDIL:
      return 21;

    default:
      break;
    }
  return 32;
}


/* Insert VALUE into INSN using R_FORMAT to determine exactly what
   bits to change.  */

static inline int
hppa_rebuild_insn (int insn, int value, int r_format)
{
  switch (r_format)
    {
    case 11:
      return (insn & ~ 0x7ff) | low_sign_unext (value, 11);

    case 12:
      return (insn & ~ 0x1ffd) | re_assemble_12 (value);


    case 10:
      return (insn & ~ 0x3ff1) | re_assemble_14 (value & -8);

    case -11:
      return (insn & ~ 0x3ff9) | re_assemble_14 (value & -4);

    case 14:
      return (insn & ~ 0x3fff) | re_assemble_14 (value);


    case -10:
      return (insn & ~ 0xfff1) | re_assemble_16 (value & -8);

    case -16:
      return (insn & ~ 0xfff9) | re_assemble_16 (value & -4);

    case 16:
      return (insn & ~ 0xffff) | re_assemble_16 (value);


    case 17:
      return (insn & ~ 0x1f1ffd) | re_assemble_17 (value);

    case 21:
      return (insn & ~ 0x1fffff) | re_assemble_21 (value);

    case 22:
      return (insn & ~ 0x3ff1ffd) | re_assemble_22 (value);

    case 32:
      return value;

    default:
      return -1;
    }
  return insn;
}

#endif /* _LIBHPPA_H */
