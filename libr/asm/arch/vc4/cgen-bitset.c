/* CGEN generic opcode support.
   Copyright 2002, 2005, 2007, 2009
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

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Functions for manipulating CGEN_BITSET.  */

#include "libiberty.h"
#include "cgen/bitset.h"
#include "dis-asm.h"
#include <string.h>

/* Create a bit mask.  */

CGEN_BITSET *
cgen_bitset_create (unsigned bit_count)
{
  CGEN_BITSET * mask = xmalloc (sizeof (* mask));
  cgen_bitset_init (mask, bit_count);
  return mask;
}

/* Initialize an existing bit mask.  */

void
cgen_bitset_init (CGEN_BITSET * mask, unsigned bit_count)
{
  if (! mask)
    return;
  mask->length = (bit_count / 8) + 1;
  mask->bits = xmalloc (mask->length);
  cgen_bitset_clear (mask);
}

/* Clear the bits of a bit mask.  */

void
cgen_bitset_clear (CGEN_BITSET * mask)
{
  unsigned i;

  if (! mask)
    return;

  for (i = 0; i < mask->length; ++i)
    mask->bits[i] = 0;
}

/* Add a bit to a bit mask.  */

void
cgen_bitset_add (CGEN_BITSET * mask, unsigned bit_num)
{
  int byte_ix, bit_ix;
  int bit_mask;

  if (! mask)
    return;
  byte_ix = bit_num / 8;
  bit_ix = bit_num % 8;
  bit_mask = 1 << (7 - bit_ix);
  mask->bits[byte_ix] |= bit_mask;
}

/* Set a bit mask.  */

void
cgen_bitset_set (CGEN_BITSET * mask, unsigned bit_num)
{
  if (! mask)
    return;
  cgen_bitset_clear (mask);
  cgen_bitset_add (mask, bit_num);
}

/* Test for a bit in a bit mask.
   Returns 1 if the bit is found  */

int
cgen_bitset_contains (CGEN_BITSET * mask, unsigned bit_num)
{
  int byte_ix, bit_ix;
  int bit_mask;

  if (! mask)
    return 1; /* No bit restrictions.  */

  byte_ix = bit_num / 8;
  bit_ix = 7 - (bit_num % 8);
  bit_mask = 1 << bit_ix;
  return (mask->bits[byte_ix] & bit_mask) >> bit_ix;
}

/* Compare two bit masks for equality.
   Returns 0 if they are equal.  */

int
cgen_bitset_compare (CGEN_BITSET * mask1, CGEN_BITSET * mask2)
{
  if (mask1 == mask2)
    return 0;
  if (! mask1 || ! mask2)
    return 1;
  if (mask1->length != mask2->length)
    return 1;
  return memcmp (mask1->bits, mask2->bits, mask1->length);
}

/* Test two bit masks for common bits.
   Returns 1 if a common bit is found.  */

int
cgen_bitset_intersect_p (CGEN_BITSET * mask1, CGEN_BITSET * mask2)
{
  unsigned i, limit;

  if (mask1 == mask2)
    return 1;
  if (! mask1 || ! mask2)
    return 0;
  limit = mask1->length < mask2->length ? mask1->length : mask2->length;

  for (i = 0; i < limit; ++i)
    if ((mask1->bits[i] & mask2->bits[i]))
      return 1;

  return 0;
}

/* Make a copy of a bit mask.  */

CGEN_BITSET *
cgen_bitset_copy (CGEN_BITSET * mask)
{
  CGEN_BITSET* newmask;

  if (! mask)
    return NULL;
  newmask = cgen_bitset_create ((mask->length * 8) - 1);
  memcpy (newmask->bits, mask->bits, mask->length);
  return newmask;
}

/* Combine two bit masks.  */

void
cgen_bitset_union (CGEN_BITSET * mask1, CGEN_BITSET * mask2,
		   CGEN_BITSET * result)
{
  unsigned i;

  if (! mask1 || ! mask2 || ! result
      || mask1->length != mask2->length
      || mask1->length != result->length)
    return;

  for (i = 0; i < result->length; ++i)
    result->bits[i] = mask1->bits[i] | mask2->bits[i];
}
