/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003,2006,2007  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_SETJMP_HEADER
#define GRUB_SETJMP_HEADER	1

#if defined(GRUB_UTIL) && !defined(GRUBOF)
#include <setjmp.h>
typedef jmp_buf grub_jmp_buf;
#define grub_setjmp setjmp
#define grub_longjmp longjmp
#else
/* This must define grub_jmp_buf, and declare grub_setjmp and
   grub_longjmp.  */
# include <grub/cpu/setjmp.h>
#endif

#endif /* ! GRUB_SETJMP_HEADER */
