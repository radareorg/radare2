/* Random host-dependent support code.
   Copyright (C) 1995-2018 Free Software Foundation, Inc.
   Written by Ken Raeburn.

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


/* Do system-dependent stuff, mainly driven by autoconf-detected info.

   Well, some generic common stuff is done here too, like including
   ansidecl.h.  That's because the .h files in bfd/hosts files I'm
   trying to replace often did that.  If it can be dropped from this
   file (check in a non-ANSI environment!), it should be.  */

#ifdef PACKAGE
#error sysdep.h must be included in lieu of config.h
#endif

#include "config.h"

#include "ansidecl.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef STRING_WITH_STRINGS
#include <string.h>
#include <strings.h>
#else
#ifdef HAVE_STRING_H
#include <string.h>
#else
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#endif
#endif

#if !HAVE_DECL_STPCPY
extern char *stpcpy (char *__dest, const char *__src);
#endif

#define opcodes_error_handler _bfd_error_handler

/* Use sigsetjmp/siglongjmp without saving the signal mask if possible.
   It is faster than setjmp/longjmp on systems where the signal mask is
   saved.  */

#if defined(HAVE_SIGSETJMP)
#define OPCODES_SIGJMP_BUF		sigjmp_buf
#define OPCODES_SIGSETJMP(buf)		sigsetjmp((buf), 0)
#define OPCODES_SIGLONGJMP(buf,val)	siglongjmp((buf), (val))
#else
#define OPCODES_SIGJMP_BUF		jmp_buf
#define OPCODES_SIGSETJMP(buf)		setjmp(buf)
#define OPCODES_SIGLONGJMP(buf,val)	longjmp((buf), (val))
#endif
