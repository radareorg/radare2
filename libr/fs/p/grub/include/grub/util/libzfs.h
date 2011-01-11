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

#ifndef GRUB_LIBZFS_UTIL_HEADER
#define GRUB_LIBZFS_UTIL_HEADER 1

#include <config.h>

#ifdef HAVE_LIBZFS_H
#include <libzfs.h>
#else /* ! HAVE_LIBZFS_H */

#include <grub/util/libnvpair.h>

typedef void libzfs_handle_t;
typedef void zpool_handle_t;

extern libzfs_handle_t *libzfs_init (void);
extern void libzfs_fini (libzfs_handle_t *);

extern zpool_handle_t *zpool_open (libzfs_handle_t *, const char *);
extern void zpool_close (zpool_handle_t *);

extern int zpool_get_physpath (zpool_handle_t *, const char *);

extern nvlist_t *zpool_get_config (zpool_handle_t *, nvlist_t **);

#endif /* ! HAVE_LIBZFS_H */

libzfs_handle_t *grub_get_libzfs_handle (void);

#endif
