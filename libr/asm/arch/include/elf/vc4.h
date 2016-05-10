/* VC4 ELF support for BFD.
   Copyright 2012 Free Software Foundation, Inc.
   Contributed by Mark Marshall, markmarshall14@gmail.com

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
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _ELF_VC4_H
#define _ELF_VC4_H

#include "elf/reloc-macros.h"
#include <inttypes.h>

typedef struct uint128_t
{
  uint64_t hi, lo;
} uint128_t;

void uint128_shl(uint128_t *v, size_t count);
void uint128_shr(uint128_t *v, size_t count);

bfd_reloc_code_real_type vc4_bfd_fixup_get(const char *str, char code, int pc_rel, int divide);
size_t vc4_bfd_fixup_get_elf(bfd_reloc_code_real_type bfd_fixup);
size_t vc4_bfd_fixup_get_width(bfd_reloc_code_real_type bfd_fixup);
size_t vc4_bfd_fixup_get_divide(bfd_reloc_code_real_type bfd_fixup);
size_t vc4_bfd_fixup_get_ins_length(bfd_reloc_code_real_type bfd_fixup);
int vc4_bfd_fixup_get_signed(bfd_reloc_code_real_type bfd_fixup);
void vc4_bfd_fixup_set(bfd_reloc_code_real_type bfd_fixup, uint16_t *ins, long val);


/* Creating indices for reloc_map_index array.  */
START_RELOC_NUMBERS(elf_vc4_reloc_type)
  RELOC_NUMBER (R_VC4_NONE,          0)
  RELOC_NUMBER (R_VC4_PCREL7_MUL2,   1)
  RELOC_NUMBER (R_VC4_PCREL8_MUL2,   2)
  RELOC_NUMBER (R_VC4_PCREL10_MUL2,  3)
  RELOC_NUMBER (R_VC4_PCREL16,       4)
  RELOC_NUMBER (R_VC4_PCREL23_MUL2,  5)
  RELOC_NUMBER (R_VC4_PCREL27,       6)
  RELOC_NUMBER (R_VC4_PCREL27_MUL2,  7)
  RELOC_NUMBER (R_VC4_PCREL32,       8)
  RELOC_NUMBER (R_VC4_IMM5_MUL4,     9)
  RELOC_NUMBER (R_VC4_IMM5_1,        10)
  RELOC_NUMBER (R_VC4_IMM5_2,        11)
  RELOC_NUMBER (R_VC4_IMM6,          12)
  RELOC_NUMBER (R_VC4_IMM6_MUL4,     13)
  RELOC_NUMBER (R_VC4_IMM11,         14)
  RELOC_NUMBER (R_VC4_IMM12,         15)
  RELOC_NUMBER (R_VC4_IMM16,         16)
  RELOC_NUMBER (R_VC4_IMM23,         17)
  RELOC_NUMBER (R_VC4_IMM27,         18)
  RELOC_NUMBER (R_VC4_IMM32,         19)
  RELOC_NUMBER (R_VC4_IMM32_2,       20)
  RELOC_NUMBER (R_VC4_8,             21)
  RELOC_NUMBER (R_VC4_16,            22)
  RELOC_NUMBER (R_VC4_32,            23)

  RELOC_NUMBER (R_VC4_GNU_VTINHERIT,  30)
  RELOC_NUMBER (R_VC4_GNU_VTENTRY,    31)

  RELOC_NUMBER (R_VC4_max,       32)
END_RELOC_NUMBERS(R_VC4_MAX)
        
#endif /* _ELF_VC4_H */
