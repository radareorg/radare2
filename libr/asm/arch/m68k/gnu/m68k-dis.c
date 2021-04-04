/* Print Motorola 68k instructions.
   Copyright (C) 1986-2021 Free Software Foundation, Inc.

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
#include "mybfd.h"
#include "disas-asm.h"
// #include "disassemble.h"
#include "../../arm/gnu/floatformat.h"
#include "libiberty.h"
#include "opintl.h"
// #include "cpu-m68k.h"
#include "opcode/m68k.h"

/* Local function prototypes.  */

const char * const fpcr_names[] =
{
  "", "%fpiar", "%fpsr", "%fpiar/%fpsr", "%fpcr",
  "%fpiar/%fpcr", "%fpsr/%fpcr", "%fpiar/%fpsr/%fpcr"
};

static char *const reg_names[] =
{
  "%d0", "%d1", "%d2", "%d3", "%d4", "%d5", "%d6", "%d7",
  "%a0", "%a1", "%a2", "%a3", "%a4", "%a5", "%fp", "%sp",
  "%ps", "%pc"
};

/* Name of register halves for MAC/EMAC.
   Seperate from reg_names since 'spu', 'fpl' look weird.  */
static char *const reg_half_names[] =
{
  "%d0", "%d1", "%d2", "%d3", "%d4", "%d5", "%d6", "%d7",
  "%a0", "%a1", "%a2", "%a3", "%a4", "%a5", "%a6", "%a7",
  "%ps", "%pc"
};

/* Sign-extend an (unsigned char).  */
#if __STDC__ == 1
#define COERCE_SIGNED_CHAR(ch) ((signed char) (ch))
#else
#define COERCE_SIGNED_CHAR(ch) ((int) (((ch) ^ 0x80) & 0xFF) - 128)
#endif

/* Error code of print_insn_arg's return value.  */

enum print_insn_arg_error
  {
    /* An invalid operand is found.  */
    PRINT_INSN_ARG_INVALID_OPERAND = -1,

    /* An opcode table error.  */
    PRINT_INSN_ARG_INVALID_OP_TABLE = -2,

    /* A memory error.  */
    PRINT_INSN_ARG_MEMORY_ERROR = -3,
  };

/* Get a 1 byte signed integer.  */
#define NEXTBYTE(p, val)			\
  do						\
    {						\
      p += 2;					\
      if (!FETCH_DATA (info, p))		\
	return PRINT_INSN_ARG_MEMORY_ERROR;	\
      val = COERCE_SIGNED_CHAR (p[-1]);		\
    }						\
  while (0)

/* Get a 2 byte signed integer.  */
#define COERCE16(x) ((int) (((x) ^ 0x8000) - 0x8000))

#define NEXTWORD(p, val, ret_val)		\
  do						\
    {						\
      p += 2;					\
      if (!FETCH_DATA (info, p))		\
	return ret_val;				\
      val = COERCE16 ((p[-2] << 8) + p[-1]);	\
    }						\
  while (0)

/* Get a 4 byte signed integer.  */
#define COERCE32(x) (((bfd_vma) (x) ^ 0x80000000) - 0x80000000)

#define NEXTLONG(p, val, ret_val)					\
  do									\
    {									\
      p += 4;								\
      if (!FETCH_DATA (info, p))					\
	return ret_val;							\
      val = COERCE32 (((((((unsigned) p[-4] << 8) + p[-3]) << 8)	\
			+ p[-2]) << 8) + p[-1]);			\
    }									\
  while (0)

/* Get a 4 byte unsigned integer.  */
#define NEXTULONG(p, val)						\
  do									\
    {									\
      p += 4;								\
      if (!FETCH_DATA (info, p))					\
	return PRINT_INSN_ARG_MEMORY_ERROR;				\
      val = (((((((unsigned) p[-4] << 8) + p[-3]) << 8)			\
	       + p[-2]) << 8) + p[-1]);					\
    }									\
  while (0)

/* Get a single precision float.  */
#define NEXTSINGLE(val, p)					\
  do								\
    {								\
      p += 4;							\
      if (!FETCH_DATA (info, p))				\
	return PRINT_INSN_ARG_MEMORY_ERROR;			\
      floatformat_to_double (& floatformat_ieee_single_big,	\
			     (char *) p - 4, & val);		\
    }								\
  while (0)

/* Get a double precision float.  */
#define NEXTDOUBLE(val, p)					\
  do								\
    {								\
      p += 8;							\
      if (!FETCH_DATA (info, p))				\
	return PRINT_INSN_ARG_MEMORY_ERROR;			\
      floatformat_to_double (& floatformat_ieee_double_big,	\
			     (char *) p - 8, & val);		\
    }								\
  while (0)

/* Get an extended precision float.  */
#define NEXTEXTEND(val, p)				\
  do							\
    {							\
      p += 12;						\
      if (!FETCH_DATA (info, p))			\
	return PRINT_INSN_ARG_MEMORY_ERROR;		\
      floatformat_to_double (& floatformat_m68881_ext,	\
			     (char *) p - 12, & val);	\
    }							\
  while (0)

/* Need a function to convert from packed to double
   precision.   Actually, it's easier to print a
   packed number than a double anyway, so maybe
   there should be a special case to handle this... */
#define NEXTPACKED(p, val)			\
  do						\
    {						\
      p += 12;					\
      if (!FETCH_DATA (info, p))		\
	return PRINT_INSN_ARG_MEMORY_ERROR;	\
      val = 0.0;				\
    }						\
  while (0)


/* Maximum length of an instruction.  */
#define MAXLEN 22

struct private
{
  /* Points to first byte not fetched.  */
  bfd_byte *max_fetched;
  bfd_byte the_buffer[MAXLEN];
  bfd_vma insn_start;
};

/* Make sure that bytes from INFO->PRIVATE_DATA->BUFFER (inclusive)
   to ADDR (exclusive) are valid.  Returns 1 for success, 0 on memory
   error.  */
#define FETCH_DATA(info, addr) \
  ((addr) <= ((struct private *) (info->private_data))->max_fetched \
   ? 1 : fetch_data ((info), (addr)))

static int
fetch_data (struct disassemble_info *info, bfd_byte *addr)
{
  int status;
  struct private *priv = (struct private *)info->private_data;
  bfd_vma start = priv->insn_start + (priv->max_fetched - priv->the_buffer);

  status = (*info->read_memory_func) (start,
				      priv->max_fetched,
				      addr - priv->max_fetched,
				      info);
  if (status != 0)
    {
      (*info->memory_error_func) (status, start, info);
      return 0;
    }
  else
    priv->max_fetched = addr;
  return 1;
}

/* This function is used to print to the bit-bucket.  */
static int
dummy_printer (FILE *file ATTRIBUTE_UNUSED,
	       const char *format ATTRIBUTE_UNUSED,
	       ...)
{
  return 0;
}

static void
dummy_print_address (bfd_vma vma ATTRIBUTE_UNUSED,
		     struct disassemble_info *info ATTRIBUTE_UNUSED)
{
}

/* Fetch BITS bits from a position in the instruction specified by CODE.
   CODE is a "place to put an argument", or 'x' for a destination
   that is a general address (mode and register).
   BUFFER contains the instruction.
   Returns -1 on failure.  */

static int
fetch_arg (unsigned char *buffer,
	   int code,
	   int bits,
	   disassemble_info *info)
{
  int val = 0;

  switch (code)
    {
    case '/': /* MAC/EMAC mask bit.  */
      val = buffer[3] >> 5;
      break;

    case 'G': /* EMAC ACC load.  */
      val = ((buffer[3] >> 3) & 0x2) | ((~buffer[1] >> 7) & 0x1);
      break;

    case 'H': /* EMAC ACC !load.  */
      val = ((buffer[3] >> 3) & 0x2) | ((buffer[1] >> 7) & 0x1);
      break;

    case ']': /* EMAC ACCEXT bit.  */
      val = buffer[0] >> 2;
      break;

    case 'I': /* MAC/EMAC scale factor.  */
      val = buffer[2] >> 1;
      break;

    case 'F': /* EMAC ACCx.  */
      val = buffer[0] >> 1;
      break;

    case 'f':
      val = buffer[1];
      break;

    case 's':
      val = buffer[1];
      break;

    case 'd':			/* Destination, for register or quick.  */
      val = (buffer[0] << 8) + buffer[1];
      val >>= 9;
      break;

    case 'x':			/* Destination, for general arg.  */
      val = (buffer[0] << 8) + buffer[1];
      val >>= 6;
      break;

    case 'k':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = (buffer[3] >> 4);
      break;

    case 'C':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = buffer[3];
      break;

    case '1':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = (buffer[2] << 8) + buffer[3];
      val >>= 12;
      break;

    case '2':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = (buffer[2] << 8) + buffer[3];
      val >>= 6;
      break;

    case '3':
    case 'j':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = (buffer[2] << 8) + buffer[3];
      break;

    case '4':
      if (! FETCH_DATA (info, buffer + 5))
	return -1;
      val = (buffer[4] << 8) + buffer[5];
      val >>= 12;
      break;

    case '5':
      if (! FETCH_DATA (info, buffer + 5))
	return -1;
      val = (buffer[4] << 8) + buffer[5];
      val >>= 6;
      break;

    case '6':
      if (! FETCH_DATA (info, buffer + 5))
	return -1;
      val = (buffer[4] << 8) + buffer[5];
      break;

    case '7':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = (buffer[2] << 8) + buffer[3];
      val >>= 7;
      break;

    case '8':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = (buffer[2] << 8) + buffer[3];
      val >>= 10;
      break;

    case '9':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = (buffer[2] << 8) + buffer[3];
      val >>= 5;
      break;

    case 'e':
      val = (buffer[1] >> 6);
      break;

    case 'E':
      if (! FETCH_DATA (info, buffer + 3))
	return -1;
      val = (buffer[2] >> 1);
      break;

    case 'm':
      val = (buffer[1] & 0x40 ? 0x8 : 0)
	| ((buffer[0] >> 1) & 0x7)
	| (buffer[3] & 0x80 ? 0x10 : 0);
      break;

    case 'n':
      val = (buffer[1] & 0x40 ? 0x8 : 0) | ((buffer[0] >> 1) & 0x7);
      break;

    case 'o':
      val = (buffer[2] >> 4) | (buffer[3] & 0x80 ? 0x10 : 0);
      break;

    case 'M':
      val = (buffer[1] & 0xf) | (buffer[3] & 0x40 ? 0x10 : 0);
      break;

    case 'N':
      val = (buffer[3] & 0xf) | (buffer[3] & 0x40 ? 0x10 : 0);
      break;

    case 'h':
      val = buffer[2] >> 2;
      break;

    default:
      return -1;
    }

  /* bits is never too big.  */
  return val & ((1 << bits) - 1);
}

/* Check if an EA is valid for a particular code.  This is required
   for the EMAC instructions since the type of source address determines
   if it is a EMAC-load instruciton if the EA is mode 2-5, otherwise it
   is a non-load EMAC instruction and the bits mean register Ry.
   A similar case exists for the movem instructions where the register
   mask is interpreted differently for different EAs.  */

static bfd_boolean
m68k_valid_ea (char code, int val)
{
  int mode, mask;
#define M(n0,n1,n2,n3,n4,n5,n6,n70,n71,n72,n73,n74) \
  (n0 | n1 << 1 | n2 << 2 | n3 << 3 | n4 << 4 | n5 << 5 | n6 << 6 \
   | n70 << 7 | n71 << 8 | n72 << 9 | n73 << 10 | n74 << 11)

  switch (code)
    {
    case '*':
      mask = M (1,1,1,1,1,1,1,1,1,1,1,1);
      break;
    case '~':
      mask = M (0,0,1,1,1,1,1,1,1,0,0,0);
      break;
    case '%':
      mask = M (1,1,1,1,1,1,1,1,1,0,0,0);
      break;
    case ';':
      mask = M (1,0,1,1,1,1,1,1,1,1,1,1);
      break;
    case '@':
      mask = M (1,0,1,1,1,1,1,1,1,1,1,0);
      break;
    case '!':
      mask = M (0,0,1,0,0,1,1,1,1,1,1,0);
      break;
    case '&':
      mask = M (0,0,1,0,0,1,1,1,1,0,0,0);
      break;
    case '$':
      mask = M (1,0,1,1,1,1,1,1,1,0,0,0);
      break;
    case '?':
      mask = M (1,0,1,0,0,1,1,1,1,0,0,0);
      break;
    case '/':
      mask = M (1,0,1,0,0,1,1,1,1,1,1,0);
      break;
    case '|':
      mask = M (0,0,1,0,0,1,1,1,1,1,1,0);
      break;
    case '>':
      mask = M (0,0,1,0,1,1,1,1,1,0,0,0);
      break;
    case '<':
      mask = M (0,0,1,1,0,1,1,1,1,1,1,0);
      break;
    case 'm':
      mask = M (1,1,1,1,1,0,0,0,0,0,0,0);
      break;
    case 'n':
      mask = M (0,0,0,0,0,1,0,0,0,1,0,0);
      break;
    case 'o':
      mask = M (0,0,0,0,0,0,1,1,1,0,1,1);
      break;
    case 'p':
      mask = M (1,1,1,1,1,1,0,0,0,0,0,0);
      break;
    case 'q':
      mask = M (1,0,1,1,1,1,0,0,0,0,0,0);
      break;
    case 'v':
      mask = M (1,0,1,1,1,1,0,1,1,0,0,0);
      break;
    case 'b':
      mask = M (1,0,1,1,1,1,0,0,0,1,0,0);
      break;
    case 'w':
      mask = M (0,0,1,1,1,1,0,0,0,1,0,0);
      break;
    case 'y':
      mask = M (0,0,1,0,0,1,0,0,0,0,0,0);
      break;
    case 'z':
      mask = M (0,0,1,0,0,1,0,0,0,1,0,0);
      break;
    case '4':
      mask = M (0,0,1,1,1,1,0,0,0,0,0,0);
      break;
    default:
      return -1;// abort ();
    }
#undef M

  mode = (val >> 3) & 7;
  if (mode == 7)
    mode += val & 7;
  return (mask & (1 << mode)) != 0;
}

/* Print a base register REGNO and displacement DISP, on INFO->STREAM.
   REGNO = -1 for pc, -2 for none (suppressed).  */

static void
print_base (int regno, bfd_vma disp, disassemble_info *info)
{
  if (regno == -1)
    {
      (*info->fprintf_func) (info->stream, "%%pc@(");
      (*info->print_address_func) (disp, info);
    }
  else
    {
      char buf[50];

      if (regno == -2)
	(*info->fprintf_func) (info->stream, "@(");
      else if (regno == -3)
	(*info->fprintf_func) (info->stream, "%%zpc@(");
      else
	(*info->fprintf_func) (info->stream, "%s@(", reg_names[regno]);

      sprintf_vma (buf, disp);
      (*info->fprintf_func) (info->stream, "%s", buf);
    }
}

/* Print an indexed argument.  The base register is BASEREG (-1 for pc).
   P points to extension word, in buffer.
   ADDR is the nominal core address of that extension word.
   Returns NULL upon error.  */

static unsigned char *
print_indexed (int basereg,
	       unsigned char *p,
	       bfd_vma addr,
	       disassemble_info *info)
{
  int word;
  static char *const scales[] = { "", ":2", ":4", ":8" };
  bfd_vma base_disp;
  bfd_vma outer_disp;
  char buf[40];
  char vmabuf[50];

  NEXTWORD (p, word, NULL);

  /* Generate the text for the index register.
     Where this will be output is not yet determined.  */
  sprintf (buf, "%s:%c%s",
	   reg_names[(word >> 12) & 0xf],
	   (word & 0x800) ? 'l' : 'w',
	   scales[(word >> 9) & 3]);

  /* Handle the 68000 style of indexing.  */

  if ((word & 0x100) == 0)
    {
      base_disp = word & 0xff;
      if ((base_disp & 0x80) != 0)
	base_disp -= 0x100;
      if (basereg == -1)
	base_disp += addr;
      print_base (basereg, base_disp, info);
      (*info->fprintf_func) (info->stream, ",%s)", buf);
      return p;
    }

  /* Handle the generalized kind.  */
  /* First, compute the displacement to add to the base register.  */
  if (word & 0200)
    {
      if (basereg == -1)
	basereg = -3;
      else
	basereg = -2;
    }
  if (word & 0100)
    buf[0] = '\0';
  base_disp = 0;
  switch ((word >> 4) & 3)
    {
    case 2:
      NEXTWORD (p, base_disp, NULL);
      break;
    case 3:
      NEXTLONG (p, base_disp, NULL);
    }
  if (basereg == -1)
    base_disp += addr;

  /* Handle single-level case (not indirect).  */
  if ((word & 7) == 0)
    {
      print_base (basereg, base_disp, info);
      if (buf[0] != '\0')
	(*info->fprintf_func) (info->stream, ",%s", buf);
      (*info->fprintf_func) (info->stream, ")");
      return p;
    }

  /* Two level.  Compute displacement to add after indirection.  */
  outer_disp = 0;
  switch (word & 3)
    {
    case 2:
      NEXTWORD (p, outer_disp, NULL);
      break;
    case 3:
      NEXTLONG (p, outer_disp, NULL);
    }

  print_base (basereg, base_disp, info);
  if ((word & 4) == 0 && buf[0] != '\0')
    {
      (*info->fprintf_func) (info->stream, ",%s", buf);
      buf[0] = '\0';
    }
  sprintf_vma (vmabuf, outer_disp);
  (*info->fprintf_func) (info->stream, ")@(%s", vmabuf);
  if (buf[0] != '\0')
    (*info->fprintf_func) (info->stream, ",%s", buf);
  (*info->fprintf_func) (info->stream, ")");

  return p;
}

#define FETCH_ARG(size, val)				\
  do							\
    {							\
      val = fetch_arg (buffer, place, size, info);	\
      if (val < 0)					\
	return PRINT_INSN_ARG_MEMORY_ERROR;		\
    }							\
  while (0)

/* Returns number of bytes "eaten" by the operand, or
   return enum print_insn_arg_error.  ADDR is the pc for this arg to be
   relative to.  */

static int
print_insn_arg (const char *d,
		unsigned char *buffer,
		unsigned char *p0,
		bfd_vma addr,
		disassemble_info *info)
{
  int val = 0;
  int place = d[1];
  unsigned char *p = p0;
  int regno;
  const char *regname;
  unsigned char *p1;
  double flval;
  int flt_p;
  bfd_signed_vma disp;
  unsigned int uval;

  switch (*d)
    {
    case 'c':		/* Cache identifier.  */
      {
        static char *const cacheFieldName[] = { "nc", "dc", "ic", "bc" };
        FETCH_ARG (2, val);
	(*info->fprintf_func) (info->stream, "%s", cacheFieldName[val]);
        break;
      }

    case 'a':		/* Address register indirect only. Cf. case '+'.  */
      {
	FETCH_ARG (3, val);
	(*info->fprintf_func) (info->stream, "%s@", reg_names[val + 8]);
        break;
      }

    case '_':		/* 32-bit absolute address for move16.  */
      {
        NEXTULONG (p, uval);
	(*info->print_address_func) (uval, info);
        break;
      }

    case 'C':
      (*info->fprintf_func) (info->stream, "%%ccr");
      break;

    case 'S':
      (*info->fprintf_func) (info->stream, "%%sr");
      break;

    case 'U':
      (*info->fprintf_func) (info->stream, "%%usp");
      break;

    case 'E':
      (*info->fprintf_func) (info->stream, "%%acc");
      break;

    case 'G':
      (*info->fprintf_func) (info->stream, "%%macsr");
      break;

    case 'H':
      (*info->fprintf_func) (info->stream, "%%mask");
      break;

    case 'J':
      {
	/* FIXME: There's a problem here, different m68k processors call the
	   same address different names.  The tables below try to get it right
	   using info->mach, but only for v4e.  */
	struct regname { char * name; int value; };
	static const struct regname names[] =
	  {
	    {"%sfc", 0x000}, {"%dfc", 0x001}, {"%cacr", 0x002},
	    {"%tc",  0x003}, {"%itt0",0x004}, {"%itt1", 0x005},
	    {"%dtt0",0x006}, {"%dtt1",0x007}, {"%buscr",0x008},
	    {"%rgpiobar", 0x009}, {"%acr4",0x00c},
	    {"%acr5",0x00d}, {"%acr6",0x00e}, {"%acr7", 0x00f},
	    {"%usp", 0x800}, {"%vbr", 0x801}, {"%caar", 0x802},
	    {"%msp", 0x803}, {"%isp", 0x804},
	    {"%pc", 0x80f},
	    /* Reg c04 is sometimes called flashbar or rambar.
	       Reg c05 is also sometimes called rambar.  */
	    {"%rambar0", 0xc04}, {"%rambar1", 0xc05},

	    /* reg c0e is sometimes called mbar2 or secmbar.
	       reg c0f is sometimes called mbar.  */
	    {"%mbar0", 0xc0e}, {"%mbar1", 0xc0f},

	    /* Should we be calling this psr like we do in case 'Y'?  */
	    {"%mmusr",0x805},

	    {"%urp", 0x806}, {"%srp", 0x807}, {"%pcr", 0x808},

	    /* Fido added these.  */
	    {"%cac", 0xffe}, {"%mbo", 0xfff}
	};
	/* Alternate names for v4e (MCF5407/5445x/MCF547x/MCF548x), at least.  */
	static const struct regname names_v4e[] =
	  {
	    {"%asid",0x003}, {"%acr0",0x004}, {"%acr1",0x005},
	    {"%acr2",0x006}, {"%acr3",0x007}, {"%mmubar",0x008},
	  };
	unsigned int arch_mask;

	arch_mask = 0; // bfd_m68k_mach_to_features (info->mach);
	FETCH_ARG (12, val);
	if (arch_mask & (mcfisa_b | mcfisa_c))
	  {
	    for (regno = ARRAY_SIZE (names_v4e); --regno >= 0;)
	      if (names_v4e[regno].value == val)
		{
		  (*info->fprintf_func) (info->stream, "%s", names_v4e[regno].name);
		  break;
		}
	    if (regno >= 0)
	      break;
	  }
	for (regno = ARRAY_SIZE (names) - 1; regno >= 0; regno--)
	  if (names[regno].value == val)
	    {
	      (*info->fprintf_func) (info->stream, "%s", names[regno].name);
	      break;
	    }
	if (regno < 0)
	  (*info->fprintf_func) (info->stream, "0x%x", val);
      }
      break;

    case 'Q':
      FETCH_ARG (3, val);
      /* 0 means 8, except for the bkpt instruction... */
      if (val == 0 && d[1] != 's')
	val = 8;
      (*info->fprintf_func) (info->stream, "#%d", val);
      break;

    case 'x':
      FETCH_ARG (3, val);
      /* 0 means -1.  */
      if (val == 0)
	val = -1;
      (*info->fprintf_func) (info->stream, "#%d", val);
      break;

    case 'j':
      FETCH_ARG (3, val);
      (*info->fprintf_func) (info->stream, "#%d", val+1);
      break;

    case 'K':
      FETCH_ARG (9, val);
      (*info->fprintf_func) (info->stream, "#%d", val);
      break;

    case 'M':
      if (place == 'h')
	{
	  static char *const scalefactor_name[] = { "<<", ">>" };

	  FETCH_ARG (1, val);
	  (*info->fprintf_func) (info->stream, "%s", scalefactor_name[val]);
	}
      else
	{
	  FETCH_ARG (8, val);
	  if (val & 0x80)
	    val = val - 0x100;
	  (*info->fprintf_func) (info->stream, "#%d", val);
	}
      break;

    case 'T':
      FETCH_ARG (4, val);
      (*info->fprintf_func) (info->stream, "#%d", val);
      break;

    case 'D':
      FETCH_ARG (3, val);
      (*info->fprintf_func) (info->stream, "%s", reg_names[val]);
      break;

    case 'A':
      FETCH_ARG (3, val);
      (*info->fprintf_func) (info->stream, "%s", reg_names[val + 010]);
      break;

    case 'R':
      FETCH_ARG (4, val);
      (*info->fprintf_func) (info->stream, "%s", reg_names[val]);
      break;

    case 'r':
      FETCH_ARG (4, regno);
      if (regno > 7)
	(*info->fprintf_func) (info->stream, "%s@", reg_names[regno]);
      else
	(*info->fprintf_func) (info->stream, "@(%s)", reg_names[regno]);
      break;

    case 'F':
      FETCH_ARG (3, val);
      (*info->fprintf_func) (info->stream, "%%fp%d", val);
      break;

    case 'O':
      FETCH_ARG (6, val);
      if (val & 0x20)
	(*info->fprintf_func) (info->stream, "%s", reg_names[val & 7]);
      else
	(*info->fprintf_func) (info->stream, "%d", val);
      break;

    case '+':
      FETCH_ARG (3, val);
      (*info->fprintf_func) (info->stream, "%s@+", reg_names[val + 8]);
      break;

    case '-':
      FETCH_ARG (3, val);
      (*info->fprintf_func) (info->stream, "%s@-", reg_names[val + 8]);
      break;

    case 'k':
      if (place == 'k')
	{
	  FETCH_ARG (3, val);
	  (*info->fprintf_func) (info->stream, "{%s}", reg_names[val]);
	}
      else if (place == 'C')
	{
	  FETCH_ARG (7, val);
	  if (val > 63)		/* This is a signed constant.  */
	    val -= 128;
	  (*info->fprintf_func) (info->stream, "{#%d}", val);
	}
      else
	return PRINT_INSN_ARG_INVALID_OPERAND;
      break;

    case '#':
    case '^':
      p1 = buffer + (*d == '#' ? 2 : 4);
      if (place == 's')
	FETCH_ARG (4, val);
      else if (place == 'C')
	FETCH_ARG (7, val);
      else if (place == '8')
	FETCH_ARG (3, val);
      else if (place == '3')
	FETCH_ARG (8, val);
      else if (place == 'b')
	NEXTBYTE (p1, val);
      else if (place == 'w' || place == 'W')
	NEXTWORD (p1, val, PRINT_INSN_ARG_MEMORY_ERROR);
      else if (place == 'l')
	NEXTLONG (p1, val, PRINT_INSN_ARG_MEMORY_ERROR);
      else
	return PRINT_INSN_ARG_INVALID_OP_TABLE;

      (*info->fprintf_func) (info->stream, "#%d", val);
      break;

    case 'B':
      if (place == 'b')
	NEXTBYTE (p, disp);
      else if (place == 'B')
	disp = COERCE_SIGNED_CHAR (buffer[1]);
      else if (place == 'w' || place == 'W')
	NEXTWORD (p, disp, PRINT_INSN_ARG_MEMORY_ERROR);
      else if (place == 'l' || place == 'L' || place == 'C')
	NEXTLONG (p, disp, PRINT_INSN_ARG_MEMORY_ERROR);
      else if (place == 'g')
	{
	  NEXTBYTE (buffer, disp);
	  if (disp == 0)
	    NEXTWORD (p, disp, PRINT_INSN_ARG_MEMORY_ERROR);
	  else if (disp == -1)
	    NEXTLONG (p, disp, PRINT_INSN_ARG_MEMORY_ERROR);
	}
      else if (place == 'c')
	{
	  if (buffer[1] & 0x40)		/* If bit six is one, long offset.  */
	    NEXTLONG (p, disp, PRINT_INSN_ARG_MEMORY_ERROR);
	  else
	    NEXTWORD (p, disp, PRINT_INSN_ARG_MEMORY_ERROR);
	}
      else
	return PRINT_INSN_ARG_INVALID_OP_TABLE;

      (*info->print_address_func) (addr + disp, info);
      break;

    case 'd':
      {
	int val1;

	NEXTWORD (p, val, PRINT_INSN_ARG_MEMORY_ERROR);
	FETCH_ARG (3, val1);
	(*info->fprintf_func) (info->stream, "%s@(%d)", reg_names[val1 + 8], val);
	break;
      }

    case 's':
      FETCH_ARG (3, val);
      (*info->fprintf_func) (info->stream, "%s", fpcr_names[val]);
      break;

    case 'e':
      FETCH_ARG (2, val);
      (*info->fprintf_func) (info->stream, "%%acc%d", val);
      break;

    case 'g':
      FETCH_ARG (1, val);
      (*info->fprintf_func) (info->stream, "%%accext%s", val == 0 ? "01" : "23");
      break;

    case 'i':
      FETCH_ARG (2, val);
      if (val == 1)
	(*info->fprintf_func) (info->stream, "<<");
      else if (val == 3)
	(*info->fprintf_func) (info->stream, ">>");
      else
	return PRINT_INSN_ARG_INVALID_OPERAND;
      break;

    case 'I':
      /* Get coprocessor ID... */
      val = fetch_arg (buffer, 'd', 3, info);
      if (val < 0)
	return PRINT_INSN_ARG_MEMORY_ERROR;
      if (val != 1)				/* Unusual coprocessor ID?  */
	(*info->fprintf_func) (info->stream, "(cpid=%d) ", val);
      break;

    case '4':
    case '*':
    case '~':
    case '%':
    case ';':
    case '@':
    case '!':
    case '$':
    case '?':
    case '/':
    case '&':
    case '|':
    case '<':
    case '>':
    case 'm':
    case 'n':
    case 'o':
    case 'p':
    case 'q':
    case 'v':
    case 'b':
    case 'w':
    case 'y':
    case 'z':
      if (place == 'd')
	{
	  val = fetch_arg (buffer, 'x', 6, info);
	  if (val < 0)
	    return PRINT_INSN_ARG_MEMORY_ERROR;
	  val = ((val & 7) << 3) + ((val >> 3) & 7);
	}
      else
	{
	  val = fetch_arg (buffer, 's', 6, info);
	  if (val < 0)
	    return PRINT_INSN_ARG_MEMORY_ERROR;
	}

      /* If the <ea> is invalid for *d, then reject this match.  */
      if (!m68k_valid_ea (*d, val))
	return PRINT_INSN_ARG_INVALID_OPERAND;

      /* Get register number assuming address register.  */
      regno = (val & 7) + 8;
      regname = reg_names[regno];
      switch (val >> 3)
	{
	case 0:
	  (*info->fprintf_func) (info->stream, "%s", reg_names[val]);
	  break;

	case 1:
	  (*info->fprintf_func) (info->stream, "%s", regname);
	  break;

	case 2:
	  (*info->fprintf_func) (info->stream, "%s@", regname);
	  break;

	case 3:
	  (*info->fprintf_func) (info->stream, "%s@+", regname);
	  break;

	case 4:
	  (*info->fprintf_func) (info->stream, "%s@-", regname);
	  break;

	case 5:
	  NEXTWORD (p, val, PRINT_INSN_ARG_MEMORY_ERROR);
	  (*info->fprintf_func) (info->stream, "%s@(%d)", regname, val);
	  break;

	case 6:
	  p = print_indexed (regno, p, addr, info);
	  if (p == NULL)
	    return PRINT_INSN_ARG_MEMORY_ERROR;
	  break;

	case 7:
	  switch (val & 7)
	    {
	    case 0:
	      NEXTWORD (p, val, PRINT_INSN_ARG_MEMORY_ERROR);
	      (*info->print_address_func) (val, info);
	      break;

	    case 1:
	      NEXTULONG (p, uval);
	      (*info->print_address_func) (uval, info);
	      break;

	    case 2:
	      NEXTWORD (p, val, PRINT_INSN_ARG_MEMORY_ERROR);
	      (*info->fprintf_func) (info->stream, "%%pc@(");
	      (*info->print_address_func) (addr + val, info);
	      (*info->fprintf_func) (info->stream, ")");
	      break;

	    case 3:
	      p = print_indexed (-1, p, addr, info);
	      if (p == NULL)
		return PRINT_INSN_ARG_MEMORY_ERROR;
	      break;

	    case 4:
	      flt_p = 1;	/* Assume it's a float... */
	      switch (place)
	      {
		case 'b':
		  NEXTBYTE (p, val);
		  flt_p = 0;
		  break;

		case 'w':
		  NEXTWORD (p, val, PRINT_INSN_ARG_MEMORY_ERROR);
		  flt_p = 0;
		  break;

		case 'l':
		  NEXTLONG (p, val, PRINT_INSN_ARG_MEMORY_ERROR);
		  flt_p = 0;
		  break;

		case 'f':
		  NEXTSINGLE (flval, p);
		  break;

		case 'F':
		  NEXTDOUBLE (flval, p);
		  break;

		case 'x':
		  NEXTEXTEND (flval, p);
		  break;

		case 'p':
		  NEXTPACKED (p, flval);
		  break;

		default:
		  return PRINT_INSN_ARG_INVALID_OPERAND;
	      }
	      if (flt_p)	/* Print a float? */
		(*info->fprintf_func) (info->stream, "#0e%g", flval);
	      else
		(*info->fprintf_func) (info->stream, "#%d", val);
	      break;

	    default:
	      return PRINT_INSN_ARG_INVALID_OPERAND;
	    }
	}

      /* If place is '/', then this is the case of the mask bit for
	 mac/emac loads. Now that the arg has been printed, grab the
	 mask bit and if set, add a '&' to the arg.  */
      if (place == '/')
	{
	  FETCH_ARG (1, val);
	  if (val)
	    info->fprintf_func (info->stream, "&");
	}
      break;

    case 'L':
    case 'l':
	if (place == 'w')
	  {
	    char doneany;
	    p1 = buffer + 2;
	    NEXTWORD (p1, val, PRINT_INSN_ARG_MEMORY_ERROR);
	    /* Move the pointer ahead if this point is farther ahead
	       than the last.  */
	    p = p1 > p ? p1 : p;
	    if (val == 0)
	      {
		(*info->fprintf_func) (info->stream, "#0");
		break;
	      }
	    if (*d == 'l')
	      {
		int newval = 0;

		for (regno = 0; regno < 16; ++regno)
		  if (val & (0x8000 >> regno))
		    newval |= 1 << regno;
		val = newval;
	      }
	    val &= 0xffff;
	    doneany = 0;
	    for (regno = 0; regno < 16; ++regno)
	      if (val & (1 << regno))
		{
		  int first_regno;

		  if (doneany)
		    (*info->fprintf_func) (info->stream, "/");
		  doneany = 1;
		  (*info->fprintf_func) (info->stream, "%s", reg_names[regno]);
		  first_regno = regno;
		  while (val & (1 << (regno + 1)))
		    ++regno;
		  if (regno > first_regno)
		    (*info->fprintf_func) (info->stream, "-%s",
					   reg_names[regno]);
		}
	  }
	else if (place == '3')
	  {
	    /* `fmovem' insn.  */
	    char doneany;

	    FETCH_ARG (8, val);
	    if (val == 0)
	      {
		(*info->fprintf_func) (info->stream, "#0");
		break;
	      }
	    if (*d == 'l')
	      {
		int newval = 0;

		for (regno = 0; regno < 8; ++regno)
		  if (val & (0x80 >> regno))
		    newval |= 1 << regno;
		val = newval;
	      }
	    val &= 0xff;
	    doneany = 0;
	    for (regno = 0; regno < 8; ++regno)
	      if (val & (1 << regno))
		{
		  int first_regno;
		  if (doneany)
		    (*info->fprintf_func) (info->stream, "/");
		  doneany = 1;
		  (*info->fprintf_func) (info->stream, "%%fp%d", regno);
		  first_regno = regno;
		  while (val & (1 << (regno + 1)))
		    ++regno;
		  if (regno > first_regno)
		    (*info->fprintf_func) (info->stream, "-%%fp%d", regno);
		}
	  }
	else if (place == '8')
	  {
	    FETCH_ARG (3, val);
	    /* fmoveml for FP status registers.  */
	    (*info->fprintf_func) (info->stream, "%s", fpcr_names[val]);
	  }
	else
	  return PRINT_INSN_ARG_INVALID_OP_TABLE;
      break;

    case 'X':
      place = '8';
      /* Fall through.  */
    case 'Y':
    case 'Z':
    case 'W':
    case '0':
    case '1':
    case '2':
    case '3':
      {
	char *name = 0;

	FETCH_ARG (5, val);
	switch (val)
	  {
	  case 2: name = "%tt0"; break;
	  case 3: name = "%tt1"; break;
	  case 0x10: name = "%tc"; break;
	  case 0x11: name = "%drp"; break;
	  case 0x12: name = "%srp"; break;
	  case 0x13: name = "%crp"; break;
	  case 0x14: name = "%cal"; break;
	  case 0x15: name = "%val"; break;
	  case 0x16: name = "%scc"; break;
	  case 0x17: name = "%ac"; break;
 	  case 0x18: name = "%psr"; break;
	  case 0x19: name = "%pcsr"; break;
	  case 0x1c:
	  case 0x1d:
	    {
	      int break_reg = ((buffer[3] >> 2) & 7);

	      (*info->fprintf_func)
		(info->stream, val == 0x1c ? "%%bad%d" : "%%bac%d",
		 break_reg);
	    }
	    break;
	  default:
	    (*info->fprintf_func) (info->stream, "<mmu register %d>", val);
	  }
	if (name)
	  (*info->fprintf_func) (info->stream, "%s", name);
      }
      break;

    case 'f':
      {
	int fc;

	FETCH_ARG (5, fc);
	if (fc == 1)
	  (*info->fprintf_func) (info->stream, "%%dfc");
	else if (fc == 0)
	  (*info->fprintf_func) (info->stream, "%%sfc");
	else
	  /* xgettext:c-format */
	  (*info->fprintf_func) (info->stream, _("<function code %d>"), fc);
      }
      break;

    case 'V':
      (*info->fprintf_func) (info->stream, "%%val");
      break;

    case 't':
      {
	int level;

	FETCH_ARG (3, level);
	(*info->fprintf_func) (info->stream, "%d", level);
      }
      break;

    case 'u':
      {
	short is_upper = 0;
	int reg;

	FETCH_ARG (5, reg);
	if (reg & 0x10)
	  {
	    is_upper = 1;
	    reg &= 0xf;
	  }
	(*info->fprintf_func) (info->stream, "%s%s",
			       reg_half_names[reg],
			       is_upper ? "u" : "l");
      }
      break;

    default:
      return PRINT_INSN_ARG_INVALID_OP_TABLE;
    }

  return p - p0;
}

/* Try to match the current instruction to best and if so, return the
   number of bytes consumed from the instruction stream, else zero.
   Return -1 on memory error.  */

static int
match_insn_m68k (bfd_vma memaddr,
		 disassemble_info * info,
		 const struct m68k_opcode * best)
{
  unsigned char *save_p;
  unsigned char *p;
  const char *d;
  const char *args = best->args;

  struct private *priv = (struct private *) info->private_data;
  bfd_byte *buffer = priv->the_buffer;
  fprintf_ftype save_printer = info->fprintf_func;
  void (* save_print_address) (bfd_vma, struct disassemble_info *)
    = info->print_address_func;

  if (*args == '.')
    args++;

  /* Point at first word of argument data,
     and at descriptor for first argument.  */
  p = buffer + 2;

  /* Figure out how long the fixed-size portion of the instruction is.
     The only place this is stored in the opcode table is
     in the arguments--look for arguments which specify fields in the 2nd
     or 3rd words of the instruction.  */
  for (d = args; *d; d += 2)
    {
      /* I don't think it is necessary to be checking d[0] here;
	 I suspect all this could be moved to the case statement below.  */
      if (d[0] == '#')
	{
	  if (d[1] == 'l' && p - buffer < 6)
	    p = buffer + 6;
	  else if (p - buffer < 4 && d[1] != 'C' && d[1] != '8')
	    p = buffer + 4;
	}

      if ((d[0] == 'L' || d[0] == 'l') && d[1] == 'w' && p - buffer < 4)
	p = buffer + 4;

      switch (d[1])
	{
	case '1':
	case '2':
	case '3':
	case '7':
	case '8':
	case '9':
	case 'i':
	  if (p - buffer < 4)
	    p = buffer + 4;
	  break;
	case '4':
	case '5':
	case '6':
	  if (p - buffer < 6)
	    p = buffer + 6;
	  break;
	default:
	  break;
	}
    }

  /* pflusha is an exceptions.  It takes no arguments but is two words
     long.  Recognize it by looking at the lower 16 bits of the mask.  */
  if (p - buffer < 4 && (best->match & 0xFFFF) != 0)
    p = buffer + 4;

  /* lpstop is another exception.  It takes a one word argument but is
     three words long.  */
  if (p - buffer < 6
      && (best->match & 0xffff) == 0xffff
      && args[0] == '#'
      && args[1] == 'w')
    {
      /* Copy the one word argument into the usual location for a one
	 word argument, to simplify printing it.  We can get away with
	 this because we know exactly what the second word is, and we
	 aren't going to print anything based on it.  */
      p = buffer + 6;
      if (!FETCH_DATA (info, p))
	return -1;
      buffer[2] = buffer[4];
      buffer[3] = buffer[5];
    }

  if (!FETCH_DATA (info, p))
    return -1;

  save_p = p;
  info->print_address_func = dummy_print_address;
  info->fprintf_func = (fprintf_ftype) dummy_printer;

  /* We scan the operands twice.  The first time we don't print anything,
     but look for errors.  */
  for (d = args; *d; d += 2)
    {
      int eaten = print_insn_arg (d, buffer, p, memaddr + (p - buffer), info);

      if (eaten >= 0)
	p += eaten;
      else if (eaten == PRINT_INSN_ARG_INVALID_OPERAND
	       || eaten == PRINT_INSN_ARG_MEMORY_ERROR)
	{
	  info->fprintf_func = save_printer;
	  info->print_address_func = save_print_address;
	  return eaten == PRINT_INSN_ARG_MEMORY_ERROR ? -1 : 0;
	}
      else
	{
	  /* We must restore the print functions before trying to print the
	     error message.  */
	  info->fprintf_func = save_printer;
	  info->print_address_func = save_print_address;
	  info->fprintf_func (info->stream,
			      /* xgettext:c-format */
			      _("<internal error in opcode table: %s %s>\n"),
			      best->name, best->args);
	  return 2;
	}
    }

  p = save_p;
  info->fprintf_func = save_printer;
  info->print_address_func = save_print_address;

  d = args;

  info->fprintf_func (info->stream, "%s", best->name);

  if (*d)
    info->fprintf_func (info->stream, " ");

  while (*d)
    {
      p += print_insn_arg (d, buffer, p, memaddr + (p - buffer), info);
      d += 2;

      if (*d && *(d - 2) != 'I' && *d != 'k')
	info->fprintf_func (info->stream, ",");
    }

  return p - buffer;
}

/* Try to interpret the instruction at address MEMADDR as one that
   can execute on a processor with the features given by ARCH_MASK.
   If successful, print the instruction to INFO->STREAM and return
   its length in bytes.  Return 0 otherwise.  Return -1 on memory
   error.  */

static int
m68k_scan_mask (bfd_vma memaddr, disassemble_info *info,
		unsigned int arch_mask)
{
  int i;
  const char *d;
  static const struct m68k_opcode **opcodes[16];
  static int numopcodes[16];
  int val;
  int major_opcode;

  struct private *priv = (struct private *) info->private_data;
  bfd_byte *buffer = priv->the_buffer;

  if (!opcodes[0])
    {
      /* Speed up the matching by sorting the opcode
	 table on the upper four bits of the opcode.  */
      const struct m68k_opcode **opc_pointer[16];

      /* First count how many opcodes are in each of the sixteen buckets.  */
      for (i = 0; i < m68k_numopcodes; i++)
	numopcodes[(m68k_opcodes[i].opcode >> 28) & 15]++;

      /* Then create a sorted table of pointers
	 that point into the unsorted table.  */
      opc_pointer[0] = xmalloc (sizeof (struct m68k_opcode *)
				* m68k_numopcodes);
      opcodes[0] = opc_pointer[0];

      for (i = 1; i < 16; i++)
	{
	  opc_pointer[i] = opc_pointer[i - 1] + numopcodes[i - 1];
	  opcodes[i] = opc_pointer[i];
	}

      for (i = 0; i < m68k_numopcodes; i++)
	*opc_pointer[(m68k_opcodes[i].opcode >> 28) & 15]++ = &m68k_opcodes[i];
    }

  if (!FETCH_DATA (info, buffer + 2))
    return -1;
  major_opcode = (buffer[0] >> 4) & 15;

  for (i = 0; i < numopcodes[major_opcode]; i++)
    {
      const struct m68k_opcode *opc = opcodes[major_opcode][i];
      unsigned long opcode = opc->opcode;
      unsigned long match = opc->match;
      const char *args = opc->args;

      if (*args == '.')
	args++;

      if (((0xff & buffer[0] & (match >> 24)) == (0xff & (opcode >> 24)))
	  && ((0xff & buffer[1] & (match >> 16)) == (0xff & (opcode >> 16)))
	  /* Only fetch the next two bytes if we need to.  */
	  && (((0xffff & match) == 0)
	      ||
	      (FETCH_DATA (info, buffer + 4)
	       && ((0xff & buffer[2] & (match >> 8)) == (0xff & (opcode >> 8)))
	       && ((0xff & buffer[3] & match) == (0xff & opcode)))
	      )
	  && (opc->arch & arch_mask) != 0)
	{
	  /* Don't use for printout the variants of divul and divsl
	     that have the same register number in two places.
	     The more general variants will match instead.  */
	  for (d = args; *d; d += 2)
	    if (d[1] == 'D')
	      break;

	  /* Don't use for printout the variants of most floating
	     point coprocessor instructions which use the same
	     register number in two places, as above.  */
	  if (*d == '\0')
	    for (d = args; *d; d += 2)
	      if (d[1] == 't')
		break;

	  /* Don't match fmovel with more than one register;
	     wait for fmoveml.  */
	  if (*d == '\0')
	    {
	      for (d = args; *d; d += 2)
		{
		  if (d[0] == 's' && d[1] == '8')
		    {
		      val = fetch_arg (buffer, d[1], 3, info);
		      if (val < 0)
			return 0;
		      if ((val & (val - 1)) != 0)
			break;
		    }
		}
	    }

	  /* Don't match FPU insns with non-default coprocessor ID.  */
	  if (*d == '\0')
	    {
	      for (d = args; *d; d += 2)
		{
		  if (d[0] == 'I')
		    {
		      val = fetch_arg (buffer, 'd', 3, info);
		      if (val != 1)
			break;
		    }
		}
	    }

	  if (*d == '\0')
	    if ((val = match_insn_m68k (memaddr, info, opc)))
	      return val;
	}
    }
  return 0;
}

/* Print the m68k instruction at address MEMADDR in debugged memory,
   on INFO->STREAM.  Returns length of the instruction, in bytes.  */

int
print_insn_m68k (bfd_vma memaddr, disassemble_info *info)
{
  unsigned int arch_mask;
  struct private priv;
  int val;

  bfd_byte *buffer = priv.the_buffer;

  info->private_data = & priv;
  /* Tell objdump to use two bytes per chunk
     and six bytes per line for displaying raw data.  */
  info->bytes_per_chunk = 2;
  info->bytes_per_line = 6;
  info->display_endian = BFD_ENDIAN_BIG;
  priv.max_fetched = priv.the_buffer;
  priv.insn_start = memaddr;

  arch_mask = 0; // bfd_m68k_mach_to_features (info->mach);
  if (!arch_mask)
    {
      /* First try printing an m680x0 instruction.  Try printing a Coldfire
	 one if that fails.  */
      val = m68k_scan_mask (memaddr, info, m68k_mask);
      if (val <= 0)
	val = m68k_scan_mask (memaddr, info, mcf_mask);
    }
  else
    {
      val = m68k_scan_mask (memaddr, info, arch_mask);
    }

  if (val == 0)
    /* Handle undefined instructions.  */
    info->fprintf_func (info->stream, ".short 0x%04x", (buffer[0] << 8) + buffer[1]);

  return val ? val : 2;
}
