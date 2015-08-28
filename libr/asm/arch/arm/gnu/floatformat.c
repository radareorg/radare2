/* IEEE floating point support routines, for GDB, the GNU Debugger.
   Copyright 1991, 1994, 1999, 2000, 2003, 2005, 2006, 2010, 2012
   Free Software Foundation, Inc.

This file is part of GDB.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

/* This is needed to pick up the NAN macro on some systems.  */
#define _GNU_SOURCE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <math.h>

#ifdef HAVE_STRING_H
#include <string.h>
#endif

/* On some platforms, <float.h> provides DBL_QNAN.  */
#ifdef STDC_HEADERS
#include <float.h>
#endif

#include "ansidecl.h"
#include "libiberty.h"
#include "floatformat.h"

#ifndef INFINITY
#ifdef HUGE_VAL
#define INFINITY HUGE_VAL
#else
#define INFINITY (1.0 / 0.0)
#endif
#endif

#ifndef NAN
#ifdef DBL_QNAN
#define NAN DBL_QNAN
#else
#define NAN (0.0 / 0.0)
#endif
#endif

static int mant_bits_set (const struct floatformat *, const unsigned char *);
static unsigned long get_field (const unsigned char *,
                                enum floatformat_byteorders,
                                unsigned int,
                                unsigned int,
                                unsigned int);
static int floatformat_always_valid (const struct floatformat *fmt,
                                     const void *from);

static int
floatformat_always_valid (const struct floatformat *fmt ATTRIBUTE_UNUSED,
                          const void *from ATTRIBUTE_UNUSED)
{
  return 1;
}

/* The odds that CHAR_BIT will be anything but 8 are low enough that I'm not
   going to bother with trying to muck around with whether it is defined in
   a system header, what we do if not, etc.  */
#define FLOATFORMAT_CHAR_BIT 8

/* floatformats for IEEE half, single and double, big and little endian.  */
const struct floatformat floatformat_ieee_half_big =
{
  floatformat_big, 16, 0, 1, 5, 15, 31, 6, 10,
  floatformat_intbit_no,
  "floatformat_ieee_half_big",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ieee_half_little =
{
  floatformat_little, 16, 0, 1, 5, 15, 31, 6, 10,
  floatformat_intbit_no,
  "floatformat_ieee_half_little",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ieee_single_big =
{
  floatformat_big, 32, 0, 1, 8, 127, 255, 9, 23,
  floatformat_intbit_no,
  "floatformat_ieee_single_big",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ieee_single_little =
{
  floatformat_little, 32, 0, 1, 8, 127, 255, 9, 23,
  floatformat_intbit_no,
  "floatformat_ieee_single_little",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ieee_double_big =
{
  floatformat_big, 64, 0, 1, 11, 1023, 2047, 12, 52,
  floatformat_intbit_no,
  "floatformat_ieee_double_big",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ieee_double_little =
{
  floatformat_little, 64, 0, 1, 11, 1023, 2047, 12, 52,
  floatformat_intbit_no,
  "floatformat_ieee_double_little",
  floatformat_always_valid,
  NULL
};

/* floatformat for IEEE double, little endian byte order, with big endian word
   ordering, as on the ARM.  */

const struct floatformat floatformat_ieee_double_littlebyte_bigword =
{
  floatformat_littlebyte_bigword, 64, 0, 1, 11, 1023, 2047, 12, 52,
  floatformat_intbit_no,
  "floatformat_ieee_double_littlebyte_bigword",
  floatformat_always_valid,
  NULL
};

/* floatformat for VAX.  Not quite IEEE, but close enough.  */

const struct floatformat floatformat_vax_f =
{
  floatformat_vax, 32, 0, 1, 8, 129, 0, 9, 23,
  floatformat_intbit_no,
  "floatformat_vax_f",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_vax_d =
{
  floatformat_vax, 64, 0, 1, 8, 129, 0, 9, 55,
  floatformat_intbit_no,
  "floatformat_vax_d",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_vax_g =
{
  floatformat_vax, 64, 0, 1, 11, 1025, 0, 12, 52,
  floatformat_intbit_no,
  "floatformat_vax_g",
  floatformat_always_valid,
  NULL
};

static int floatformat_i387_ext_is_valid (const struct floatformat *fmt,
					  const void *from);

static int
floatformat_i387_ext_is_valid (const struct floatformat *fmt, const void *from)
{
  /* In the i387 double-extended format, if the exponent is all ones,
     then the integer bit must be set.  If the exponent is neither 0
     nor ~0, the intbit must also be set.  Only if the exponent is
     zero can it be zero, and then it must be zero.  */
  unsigned long exponent, int_bit;
  const unsigned char *ufrom = (const unsigned char *) from;

  exponent = get_field (ufrom, fmt->byteorder, fmt->totalsize,
			fmt->exp_start, fmt->exp_len);
  int_bit = get_field (ufrom, fmt->byteorder, fmt->totalsize,
		       fmt->man_start, 1);

  if ((exponent == 0) != (int_bit == 0))
    return 0;
  else
    return 1;
}

const struct floatformat floatformat_i387_ext =
{
  floatformat_little, 80, 0, 1, 15, 0x3fff, 0x7fff, 16, 64,
  floatformat_intbit_yes,
  "floatformat_i387_ext",
  floatformat_i387_ext_is_valid,
  NULL
};
const struct floatformat floatformat_m68881_ext =
{
  /* Note that the bits from 16 to 31 are unused.  */
  floatformat_big, 96, 0, 1, 15, 0x3fff, 0x7fff, 32, 64,
  floatformat_intbit_yes,
  "floatformat_m68881_ext",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_i960_ext =
{
  /* Note that the bits from 0 to 15 are unused.  */
  floatformat_little, 96, 16, 17, 15, 0x3fff, 0x7fff, 32, 64,
  floatformat_intbit_yes,
  "floatformat_i960_ext",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_m88110_ext =
{
  floatformat_big, 80, 0, 1, 15, 0x3fff, 0x7fff, 16, 64,
  floatformat_intbit_yes,
  "floatformat_m88110_ext",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_m88110_harris_ext =
{
  /* Harris uses raw format 128 bytes long, but the number is just an ieee
     double, and the last 64 bits are wasted. */
  floatformat_big,128, 0, 1, 11,  0x3ff,  0x7ff, 12, 52,
  floatformat_intbit_no,
  "floatformat_m88110_ext_harris",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_arm_ext_big =
{
  /* Bits 1 to 16 are unused.  */
  floatformat_big, 96, 0, 17, 15, 0x3fff, 0x7fff, 32, 64,
  floatformat_intbit_yes,
  "floatformat_arm_ext_big",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_arm_ext_littlebyte_bigword =
{
  /* Bits 1 to 16 are unused.  */
  floatformat_littlebyte_bigword, 96, 0, 17, 15, 0x3fff, 0x7fff, 32, 64,
  floatformat_intbit_yes,
  "floatformat_arm_ext_littlebyte_bigword",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ia64_spill_big =
{
  floatformat_big, 128, 0, 1, 17, 65535, 0x1ffff, 18, 64,
  floatformat_intbit_yes,
  "floatformat_ia64_spill_big",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ia64_spill_little =
{
  floatformat_little, 128, 0, 1, 17, 65535, 0x1ffff, 18, 64,
  floatformat_intbit_yes,
  "floatformat_ia64_spill_little",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ia64_quad_big =
{
  floatformat_big, 128, 0, 1, 15, 16383, 0x7fff, 16, 112,
  floatformat_intbit_no,
  "floatformat_ia64_quad_big",
  floatformat_always_valid,
  NULL
};
const struct floatformat floatformat_ia64_quad_little =
{
  floatformat_little, 128, 0, 1, 15, 16383, 0x7fff, 16, 112,
  floatformat_intbit_no,
  "floatformat_ia64_quad_little",
  floatformat_always_valid,
  NULL
};

static int
floatformat_ibm_long_double_is_valid (const struct floatformat *fmt,
				      const void *from)
{
  const unsigned char *ufrom = (const unsigned char *) from;
  const struct floatformat *hfmt = fmt->split_half;
  long top_exp, bot_exp;
  int top_nan = 0;

  top_exp = get_field (ufrom, hfmt->byteorder, hfmt->totalsize,
		       hfmt->exp_start, hfmt->exp_len);
  bot_exp = get_field (ufrom + 8, hfmt->byteorder, hfmt->totalsize,
		       hfmt->exp_start, hfmt->exp_len);

  if ((unsigned long) top_exp == hfmt->exp_nan)
    top_nan = mant_bits_set (hfmt, ufrom);

  /* A NaN is valid with any low part.  */
  if (top_nan)
    return 1;

  /* An infinity, zero or denormal requires low part 0 (positive or
     negative).  */
  if ((unsigned long) top_exp == hfmt->exp_nan || top_exp == 0)
    {
      if (bot_exp != 0)
	return 0;

      return !mant_bits_set (hfmt, ufrom + 8);
    }

  /* The top part is now a finite normal value.  The long double value
     is the sum of the two parts, and the top part must equal the
     result of rounding the long double value to nearest double.  Thus
     the bottom part must be <= 0.5ulp of the top part in absolute
     value, and if it is < 0.5ulp then the long double is definitely
     valid.  */
  if (bot_exp < top_exp - 53)
    return 1;
  if (bot_exp > top_exp - 53 && bot_exp != 0)
    return 0;
  if (bot_exp == 0)
    {
      /* The bottom part is 0 or denormal.  Determine which, and if
	 denormal the first two set bits.  */
      int first_bit = -1, second_bit = -1, cur_bit;
      for (cur_bit = 0; (unsigned int) cur_bit < hfmt->man_len; cur_bit++)
	if (get_field (ufrom + 8, hfmt->byteorder, hfmt->totalsize,
		       hfmt->man_start + cur_bit, 1))
	  {
	    if (first_bit == -1)
	      first_bit = cur_bit;
	    else
	      {
		second_bit = cur_bit;
		break;
	      }
	  }
      /* Bottom part 0 is OK.  */
      if (first_bit == -1)
	return 1;
      /* The real exponent of the bottom part is -first_bit.  */
      if (-first_bit < top_exp - 53)
	return 1;
      if (-first_bit > top_exp - 53)
	return 0;
      /* The bottom part is at least 0.5ulp of the top part.  For this
	 to be OK, the bottom part must be exactly 0.5ulp (i.e. no
	 more bits set) and the top part must have last bit 0.  */
      if (second_bit != -1)
	return 0;
      return !get_field (ufrom, hfmt->byteorder, hfmt->totalsize,
			 hfmt->man_start + hfmt->man_len - 1, 1);
    }
  else
    {
      /* The bottom part is at least 0.5ulp of the top part.  For this
	 to be OK, it must be exactly 0.5ulp (i.e. no explicit bits
	 set) and the top part must have last bit 0.  */
      if (get_field (ufrom, hfmt->byteorder, hfmt->totalsize,
		     hfmt->man_start + hfmt->man_len - 1, 1))
	return 0;
      return !mant_bits_set (hfmt, ufrom + 8);
    }
}

const struct floatformat floatformat_ibm_long_double_big =
{
  floatformat_big, 128, 0, 1, 11, 1023, 2047, 12, 52,
  floatformat_intbit_no,
  "floatformat_ibm_long_double_big",
  floatformat_ibm_long_double_is_valid,
  &floatformat_ieee_double_big
};

const struct floatformat floatformat_ibm_long_double_little =
{
  floatformat_little, 128, 0, 1, 11, 1023, 2047, 12, 52,
  floatformat_intbit_no,
  "floatformat_ibm_long_double_little",
  floatformat_ibm_long_double_is_valid,
  &floatformat_ieee_double_little
};


#ifndef min
#define min(a, b) ((a) < (b) ? (a) : (b))
#endif

/* Return 1 if any bits are explicitly set in the mantissa of UFROM,
   format FMT, 0 otherwise.  */
static int
mant_bits_set (const struct floatformat *fmt, const unsigned char *ufrom)
{
  unsigned int mant_bits, mant_off;
  int mant_bits_left;

  mant_off = fmt->man_start;
  mant_bits_left = fmt->man_len;
  while (mant_bits_left > 0)
    {
      mant_bits = min (mant_bits_left, 32);

      if (get_field (ufrom, fmt->byteorder, fmt->totalsize,
		     mant_off, mant_bits) != 0)
	return 1;

      mant_off += mant_bits;
      mant_bits_left -= mant_bits;
    }
  return 0;
}

/* Extract a field which starts at START and is LEN bits long.  DATA and
   TOTAL_LEN are the thing we are extracting it from, in byteorder ORDER.  */
static unsigned long
get_field (const unsigned char *data, enum floatformat_byteorders order,
           unsigned int total_len, unsigned int start, unsigned int len)
{
  unsigned long result = 0;
  unsigned int cur_byte;
  int lo_bit, hi_bit, cur_bitshift = 0;
  int nextbyte = (order == floatformat_little) ? 1 : -1;

  /* Start is in big-endian bit order!  Fix that first.  */
  start = total_len - (start + len);

  /* Start at the least significant part of the field.  */
  if (order == floatformat_little)
    cur_byte = start / FLOATFORMAT_CHAR_BIT;
  else
    cur_byte = (total_len - start - 1) / FLOATFORMAT_CHAR_BIT;

  lo_bit = start % FLOATFORMAT_CHAR_BIT;
  hi_bit = min (lo_bit + len, FLOATFORMAT_CHAR_BIT);
  
  do
    {
      unsigned int shifted = *(data + cur_byte) >> lo_bit;
      unsigned int bits = hi_bit - lo_bit;
      unsigned int mask = (1 << bits) - 1;
      result |= (shifted & mask) << cur_bitshift;
      len -= bits;
      cur_bitshift += bits;
      cur_byte += nextbyte;
      lo_bit = 0;
      hi_bit = min (len, FLOATFORMAT_CHAR_BIT);
    }
  while (len != 0);

  return result;
}
  
/* Convert from FMT to a double.
   FROM is the address of the extended float.
   Store the double in *TO.  */

void
floatformat_to_double (const struct floatformat *fmt,
                       const void *from, double *to)
{
  const unsigned char *ufrom = (const unsigned char *) from;
  double dto;
  long exponent;
  unsigned long mant;
  unsigned int mant_bits, mant_off;
  int mant_bits_left;

  /* Split values are not handled specially, since the top half has
     the correctly rounded double value (in the only supported case of
     split values).  */

  exponent = get_field (ufrom, fmt->byteorder, fmt->totalsize,
			fmt->exp_start, fmt->exp_len);

  /* If the exponent indicates a NaN, we don't have information to
     decide what to do.  So we handle it like IEEE, except that we
     don't try to preserve the type of NaN.  FIXME.  */
  if ((unsigned long) exponent == fmt->exp_nan)
    {
      int nan = mant_bits_set (fmt, ufrom);

      /* On certain systems (such as GNU/Linux), the use of the
	 INFINITY macro below may generate a warning that can not be
	 silenced due to a bug in GCC (PR preprocessor/11931).  The
	 preprocessor fails to recognise the __extension__ keyword in
	 conjunction with the GNU/C99 extension for hexadecimal
	 floating point constants and will issue a warning when
	 compiling with -pedantic.  */
      if (nan)
	dto = NAN;
      else
	dto = INFINITY;

      if (get_field (ufrom, fmt->byteorder, fmt->totalsize, fmt->sign_start, 1))
	dto = -dto;

      *to = dto;

      return;
    }

  mant_bits_left = fmt->man_len;
  mant_off = fmt->man_start;
  dto = 0.0;

  /* Build the result algebraically.  Might go infinite, underflow, etc;
     who cares. */

  /* For denorms use minimum exponent.  */
  if (exponent == 0)
    exponent = 1 - fmt->exp_bias;
  else
    {
      exponent -= fmt->exp_bias;

      /* If this format uses a hidden bit, explicitly add it in now.
	 Otherwise, increment the exponent by one to account for the
	 integer bit.  */

      if (fmt->intbit == floatformat_intbit_no)
	dto = ldexp (1.0, exponent);
      else
	exponent++;
    }

  while (mant_bits_left > 0)
    {
      mant_bits = min (mant_bits_left, 32);

      mant = get_field (ufrom, fmt->byteorder, fmt->totalsize,
			 mant_off, mant_bits);

      dto += ldexp ((double) mant, exponent - mant_bits);
      exponent -= mant_bits;
      mant_off += mant_bits;
      mant_bits_left -= mant_bits;
    }

  /* Negate it if negative.  */
  if (get_field (ufrom, fmt->byteorder, fmt->totalsize, fmt->sign_start, 1))
    dto = -dto;
  *to = dto;
}

static void put_field (unsigned char *, enum floatformat_byteorders,
                       unsigned int,
                       unsigned int,
                       unsigned int,
                       unsigned long);

/* Set a field which starts at START and is LEN bits long.  DATA and
   TOTAL_LEN are the thing we are extracting it from, in byteorder ORDER.  */
static void
put_field (unsigned char *data, enum floatformat_byteorders order,
           unsigned int total_len, unsigned int start, unsigned int len,
           unsigned long stuff_to_put)
{
  unsigned int cur_byte;
  int lo_bit, hi_bit;
  int nextbyte = (order == floatformat_little) ? 1 : -1;

  /* Start is in big-endian bit order!  Fix that first.  */
  start = total_len - (start + len);

  /* Start at the least significant part of the field.  */
  if (order == floatformat_little)
    cur_byte = start / FLOATFORMAT_CHAR_BIT;
  else
    cur_byte = (total_len - start - 1) / FLOATFORMAT_CHAR_BIT;

  lo_bit = start % FLOATFORMAT_CHAR_BIT;
  hi_bit = min (lo_bit + len, FLOATFORMAT_CHAR_BIT);
  
  do
    {
      unsigned char *byte_ptr = data + cur_byte;
      unsigned int bits = hi_bit - lo_bit;
      unsigned int mask = ((1 << bits) - 1) << lo_bit;
      *byte_ptr = (*byte_ptr & ~mask) | ((stuff_to_put << lo_bit) & mask);
      stuff_to_put >>= bits;
      len -= bits;
      cur_byte += nextbyte;
      lo_bit = 0;
      hi_bit = min (len, FLOATFORMAT_CHAR_BIT);
    }
  while (len != 0);
}

/* The converse: convert the double *FROM to an extended float
   and store where TO points.  Neither FROM nor TO have any alignment
   restrictions.  */

void
floatformat_from_double (const struct floatformat *fmt,
                         const double *from, void *to)
{
  double dfrom;
  int exponent;
  double mant;
  unsigned int mant_bits, mant_off;
  int mant_bits_left;
  unsigned char *uto = (unsigned char *) to;

  dfrom = *from;
  memset (uto, 0, fmt->totalsize / FLOATFORMAT_CHAR_BIT);

  /* Split values are not handled specially, since a bottom half of
     zero is correct for any value representable as double (in the
     only supported case of split values).  */

  /* If negative, set the sign bit.  */
  if (dfrom < 0)
    {
      put_field (uto, fmt->byteorder, fmt->totalsize, fmt->sign_start, 1, 1);
      dfrom = -dfrom;
    }

  if (dfrom == 0)
    {
      /* 0.0.  */
      return;
    }

  if (dfrom != dfrom)
    {
      /* NaN.  */
      put_field (uto, fmt->byteorder, fmt->totalsize, fmt->exp_start,
		 fmt->exp_len, fmt->exp_nan);
      /* Be sure it's not infinity, but NaN value is irrelevant.  */
      put_field (uto, fmt->byteorder, fmt->totalsize, fmt->man_start,
		 32, 1);
      return;
    }

  if (dfrom + dfrom == dfrom)
    {
      /* This can only happen for an infinite value (or zero, which we
	 already handled above).  */
      put_field (uto, fmt->byteorder, fmt->totalsize, fmt->exp_start,
		 fmt->exp_len, fmt->exp_nan);
      return;
    }

  mant = frexp (dfrom, &exponent);
  if (exponent + fmt->exp_bias - 1 > 0)
    put_field (uto, fmt->byteorder, fmt->totalsize, fmt->exp_start,
	       fmt->exp_len, exponent + fmt->exp_bias - 1);
  else
    {
      /* Handle a denormalized number.  FIXME: What should we do for
	 non-IEEE formats?  */
      put_field (uto, fmt->byteorder, fmt->totalsize, fmt->exp_start,
		 fmt->exp_len, 0);
      mant = ldexp (mant, exponent + fmt->exp_bias - 1);
    }

  mant_bits_left = fmt->man_len;
  mant_off = fmt->man_start;
  while (mant_bits_left > 0)
    {
      unsigned long mant_long;
      mant_bits = mant_bits_left < 32 ? mant_bits_left : 32;

      mant *= 4294967296.0;
      mant_long = (unsigned long)mant;
      mant -= mant_long;

      /* If the integer bit is implicit, and we are not creating a
	 denormalized number, then we need to discard it.  */
      if ((unsigned int) mant_bits_left == fmt->man_len
	  && fmt->intbit == floatformat_intbit_no
	  && exponent + fmt->exp_bias - 1 > 0)
	{
	  mant_long &= 0x7fffffff;
	  mant_bits -= 1;
	}
      else if (mant_bits < 32)
	{
	  /* The bits we want are in the most significant MANT_BITS bits of
	     mant_long.  Move them to the least significant.  */
	  mant_long >>= 32 - mant_bits;
	}

      put_field (uto, fmt->byteorder, fmt->totalsize,
		 mant_off, mant_bits, mant_long);
      mant_off += mant_bits;
      mant_bits_left -= mant_bits;
    }
}

/* Return non-zero iff the data at FROM is a valid number in format FMT.  */

int
floatformat_is_valid (const struct floatformat *fmt, const void *from)
{
  return fmt->is_valid (fmt, from);
}


#ifdef IEEE_DEBUG

#include <stdio.h>

/* This is to be run on a host which uses IEEE floating point.  */

void
ieee_test (double n)
{
  double result;

  floatformat_to_double (&floatformat_ieee_double_little, &n, &result);
  if ((n != result && (! isnan (n) || ! isnan (result)))
      || (n < 0 && result >= 0)
      || (n >= 0 && result < 0))
    printf ("Differ(to): %.20g -> %.20g\n", n, result);

  floatformat_from_double (&floatformat_ieee_double_little, &n, &result);
  if ((n != result && (! isnan (n) || ! isnan (result)))
      || (n < 0 && result >= 0)
      || (n >= 0 && result < 0))
    printf ("Differ(from): %.20g -> %.20g\n", n, result);

#if 0
  {
    char exten[16];

    floatformat_from_double (&floatformat_m68881_ext, &n, exten);
    floatformat_to_double (&floatformat_m68881_ext, exten, &result);
    if (n != result)
      printf ("Differ(to+from): %.20g -> %.20g\n", n, result);
  }
#endif

#if IEEE_DEBUG > 1
  /* This is to be run on a host which uses 68881 format.  */
  {
    long double ex = *(long double *)exten;
    if (ex != n)
      printf ("Differ(from vs. extended): %.20g\n", n);
  }
#endif
}

int
main (void)
{
  ieee_test (0.0);
  ieee_test (0.5);
  ieee_test (1.1);
  ieee_test (256.0);
  ieee_test (0.12345);
  ieee_test (234235.78907234);
  ieee_test (-512.0);
  ieee_test (-0.004321);
  ieee_test (1.2E-70);
  ieee_test (1.2E-316);
  ieee_test (4.9406564584124654E-324);
  ieee_test (- 4.9406564584124654E-324);
  ieee_test (- 0.0);
  ieee_test (- INFINITY);
  ieee_test (- NAN);
  ieee_test (INFINITY);
  ieee_test (NAN);
  return 0;
}
#endif
