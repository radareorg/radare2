/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2006,2007,2008,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_SYMBOL_HEADER
#define GRUB_SYMBOL_HEADER	1

#include <config.h>

/* Apple assembler requires local labels to start with a capital L */
#define LOCAL(sym)	L_ ## sym

/* Add an underscore to a C symbol in assembler code if needed. */
#if HAVE_ASM_USCORE
# define EXT_C(sym)	_ ## sym
#else
# define EXT_C(sym)	sym
#endif

#if defined (APPLE_CC)
#define FUNCTION(x)	.globl EXT_C(x) ; EXT_C(x):
#define VARIABLE(x)	.globl EXT_C(x) ; EXT_C(x):
#elif ! defined (__CYGWIN__) && ! defined (__MINGW32__)
#define FUNCTION(x)	.globl EXT_C(x) ; .type EXT_C(x), "function" ; EXT_C(x):
#define VARIABLE(x)	.globl EXT_C(x) ; .type EXT_C(x), "object" ; EXT_C(x):
#else
/* .type not supported for non-ELF targets.  XXX: Check this in configure? */
#define FUNCTION(x)	.globl EXT_C(x) ; .def EXT_C(x); .scl 2; .type 32; .endef; EXT_C(x):
#define VARIABLE(x)	.globl EXT_C(x) ; .def EXT_C(x); .scl 2; .type 0; .endef; EXT_C(x):
#endif

/* Mark an exported symbol.  */
#ifndef GRUB_SYMBOL_GENERATOR
# define EXPORT_FUNC(x)	x
# define EXPORT_VAR(x)	x
#endif /* ! GRUB_SYMBOL_GENERATOR */

#endif /* ! GRUB_SYMBOL_HEADER */
