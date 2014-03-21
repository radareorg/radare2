/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2010  Free Software Foundation, Inc.
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

#ifndef GRUB_LIBNVPAIR_UTIL_HEADER
#define GRUB_LIBNVPAIR_UTIL_HEADER 1

#include <config.h>

#ifdef HAVE_LIBNVPAIR_H
#include <libnvpair.h>
#else /* ! HAVE_LIBNVPAIR_H */

#include <stdio.h>	/* FILE */

typedef void nvlist_t;

int nvlist_lookup_string (nvlist_t *, const char *, char **);
int nvlist_lookup_nvlist (nvlist_t *, const char *, nvlist_t **);
int nvlist_lookup_nvlist_array (nvlist_t *, const char *, nvlist_t ***, unsigned int *);
void nvlist_print (FILE *, nvlist_t *);

#endif /* ! HAVE_LIBNVPAIR_H */

#endif
