/* Symbol concatenation utilities.

   Copyright (C) 1998-2023 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef SYM_CAT_H
#define SYM_CAT_H

#if defined (__STDC__) || defined (ALMOST_STDC) || defined (HAVE_STRINGIZE)
#define CONCAT2(a,b)	 a##b
#define CONCAT3(a,b,c)	 a##b##c
#define CONCAT4(a,b,c,d) a##b##c##d
#define CONCAT5(a,b,c,d,e) a##b##c##d##e
#define CONCAT6(a,b,c,d,e,f) a##b##c##d##e##f
#define STRINGX(s) #s
#else
/* Note one should never pass extra whitespace to the CONCATn macros,
   e.g. CONCAT2(foo, bar) because traditonal C will keep the space between
   the two labels instead of concatenating them.  Instead, make sure to
   write CONCAT2(foo,bar).  */
#define CONCAT2(a,b)	 a/**/b
#define CONCAT3(a,b,c)	 a/**/b/**/c
#define CONCAT4(a,b,c,d) a/**/b/**/c/**/d
#define CONCAT5(a,b,c,d,e) a/**/b/**/c/**/d/**/e
#define CONCAT6(a,b,c,d,e,f) a/**/b/**/c/**/d/**/e/**/f
#define STRINGX(s) "s"
#endif

#define XCONCAT2(a,b)     CONCAT2(a,b)
#define XCONCAT3(a,b,c)   CONCAT3(a,b,c)
#define XCONCAT4(a,b,c,d) CONCAT4(a,b,c,d)
#define XCONCAT5(a,b,c,d,e) CONCAT5(a,b,c,d,e)
#define XCONCAT6(a,b,c,d,e,f) CONCAT6(a,b,c,d,e,f)

#endif /* SYM_CAT_H */
