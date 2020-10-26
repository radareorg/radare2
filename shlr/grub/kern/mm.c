/* mm.c - functions for memory manager */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2007,2008,2009  Free Software Foundation, Inc.
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

#include <grub/mm.h>

#include <string.h>
#include <stdlib.h>

GRUB_EXPORT(grub_malloc);
GRUB_EXPORT(grub_zalloc);
GRUB_EXPORT(grub_free);
GRUB_EXPORT(grub_realloc);

/* Allocate SIZE bytes and return the pointer.  */
void * grub_malloc (grub_size_t size) {
  return malloc(size);
}

void *grub_zalloc (grub_size_t size) {
    void *ret;
    ret = malloc(size);
    memset (ret, 0, size);

    return ret;
}

void grub_free (void *ptr) {
    free(ptr);
}

void * grub_realloc (void *ptr, grub_size_t size) {
    return realloc(ptr, size);
}
