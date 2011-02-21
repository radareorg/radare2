/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009,2010  Free Software Foundation, Inc.
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

#ifndef	GRUB_I18N_H
#define	GRUB_I18N_H	1

#include <config.h>
#include <grub/symbol.h>

extern const char *(*EXPORT_VAR(grub_gettext)) (const char *s);

/* NLS can be disabled through the configure --disable-nls option.  */
#if (defined(ENABLE_NLS) && ENABLE_NLS)

# ifdef GRUB_UTIL

#  include <locale.h>
#  include <libintl.h>

# endif /* GRUB_UTIL */

#else /* ! (defined(ENABLE_NLS) && ENABLE_NLS) */

/* Disabled NLS.
   The casts to 'const char *' serve the purpose of producing warnings
   for invalid uses of the value returned from these functions.
   On pre-ANSI systems without 'const', the config.h file is supposed to
   contain "#define const".  */
# ifdef GRUB_UTIL
#  define gettext(Msgid) ((const char *) (Msgid))
# else
#  define grub_gettext(str) ((const char *) (str))
# endif /* GRUB_UTIL */

#endif /* (defined(ENABLE_NLS) && ENABLE_NLS) */

#ifdef GRUB_UTIL
# define _(str) gettext(str)
#else
# define _(str) grub_gettext(str)
#endif /* GRUB_UTIL */

#define N_(str) str

#endif /* GRUB_I18N_H */
