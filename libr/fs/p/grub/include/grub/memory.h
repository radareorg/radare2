/* memory.h - describe the memory map */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2007,2008  Free Software Foundation, Inc.
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

#ifndef GRUB_MEMORY_HEADER
#define GRUB_MEMORY_HEADER	1

#include <grub/types.h>
#include <grub/err.h>

typedef enum grub_memory_type
  {
    GRUB_MEMORY_AVAILABLE = 1,
    GRUB_MEMORY_RESERVED = 2,
    GRUB_MEMORY_ACPI = 3,
    GRUB_MEMORY_NVS = 4,
    GRUB_MEMORY_BADRAM = 5,
    GRUB_MEMORY_CODE = 20,
    /* This one is special: it's used internally but is never reported
       by firmware. */
    GRUB_MEMORY_HOLE = 21
  } grub_memory_type_t;

typedef int NESTED_FUNC_ATTR (*grub_memory_hook_t) (grub_uint64_t,
						    grub_uint64_t,
						    grub_memory_type_t);

grub_err_t grub_mmap_iterate (grub_memory_hook_t hook);

#if !defined (GRUB_MACHINE_EMU) && !defined (GRUB_MACHINE_EFI)
grub_err_t EXPORT_FUNC(grub_machine_mmap_iterate) (grub_memory_hook_t hook);
#else
grub_err_t grub_machine_mmap_iterate (grub_memory_hook_t hook);
#endif

int grub_mmap_register (grub_uint64_t start, grub_uint64_t size, int type);
grub_err_t grub_mmap_unregister (int handle);

void *grub_mmap_malign_and_register (grub_uint64_t align, grub_uint64_t size,
				     int *handle, int type, int flags);

void grub_mmap_free_and_unregister (int handle);

#ifndef GRUB_MMAP_REGISTER_BY_FIRMWARE

struct grub_mmap_region
{
  struct grub_mmap_region *next;
  grub_uint64_t start;
  grub_uint64_t end;
  grub_memory_type_t type;
  int handle;
};

extern struct grub_mmap_region *grub_mmap_overlays;
#endif

#endif /* ! GRUB_MEMORY_HEADER */
