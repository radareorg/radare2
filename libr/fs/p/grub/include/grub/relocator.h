/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2009  Free Software Foundation, Inc.
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

#ifndef GRUB_RELOCATOR_HEADER
#define GRUB_RELOCATOR_HEADER	1

#include <grub/types.h>
#include <grub/err.h>
#include <grub/memory.h>
#include <grub/cpu/memory.h>

struct grub_relocator;
struct grub_relocator_chunk;
typedef const struct grub_relocator_chunk *grub_relocator_chunk_t;

struct grub_relocator *grub_relocator_new (void);

grub_err_t
grub_relocator_alloc_chunk_addr (struct grub_relocator *rel,
				 grub_relocator_chunk_t *out,
				 grub_phys_addr_t target, grub_size_t size);

void *
get_virtual_current_address (grub_relocator_chunk_t in);
grub_phys_addr_t
get_physical_target_address (grub_relocator_chunk_t in);

grub_err_t
grub_relocator_alloc_chunk_align (struct grub_relocator *rel, 
				  grub_relocator_chunk_t *out,
				  grub_phys_addr_t min_addr,
				  grub_phys_addr_t max_addr,
				  grub_size_t size, grub_size_t align,
				  int preference);

#define GRUB_RELOCATOR_PREFERENCE_NONE 0
#define GRUB_RELOCATOR_PREFERENCE_LOW 1
#define GRUB_RELOCATOR_PREFERENCE_HIGH 2

void
grub_relocator_unload (struct grub_relocator *rel);

#endif
