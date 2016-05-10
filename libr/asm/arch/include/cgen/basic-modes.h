/* Basic CGEN modes.
   Copyright 2005, 2007, 2009 Free Software Foundation, Inc.
   Contributed by Red Hat.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this library; see the file COPYING3.  If not, write to the
   Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef CGEN_BASIC_MODES_H
#define CGEN_BASIC_MODES_H

/* This file doesn't contain all modes,
   just the basic/portable ones.
   It also provides access to stdint.h (*1) so the includer doesn't have
   to deal with the portability issues.
   (*1): To the extent that bfd_stdint.h does for now.  */

/* IWBN to avoid unnecessary dependencies on bfd-anything.  */
//#include "bfd_stdint.h"
#include "inttypes.h"

typedef int8_t QI;
typedef uint8_t UQI;

typedef int16_t HI;
typedef uint16_t UHI;

typedef int32_t SI;
typedef uint32_t USI;

typedef int64_t DI;
typedef uint64_t UDI;

typedef int INT;
typedef unsigned int UINT;

/* Cover macro to create a 64-bit integer.  */
#define MAKEDI(hi, lo) ((((DI) (SI) (hi)) << 32) | ((UDI) (USI) (lo)))

#endif /* CGEN_BASIC_MODES_H */
