/* loader.h - OS loaders */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2004,2006,2007,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_LOADER_HEADER
#define GRUB_LOADER_HEADER	1

#include <grub/file.h>
#include <grub/symbol.h>
#include <grub/err.h>
#include <grub/types.h>

/* Check if a loader is loaded.  */
int grub_loader_is_loaded (void);

/* Set loader functions. NORETURN must be set to true, if BOOT won't return
   to the original state.  */
void grub_loader_set (grub_err_t (*boot) (void),
		      grub_err_t (*unload) (void),
		      int noreturn);

/* Unset current loader, if any.  */
void grub_loader_unset (void);

/* Call the boot hook in current loader. This may or may not return,
   depending on the setting by grub_loader_set.  */
grub_err_t grub_loader_boot (void);

/* The space between numbers is intentional for the simplicity of adding new
   values even if external modules use them. */
typedef enum {
  /* A preboot hook which can use everything and turns nothing off. */
  GRUB_LOADER_PREBOOT_HOOK_PRIO_NORMAL = 400,
  /* A preboot hook which can't use disks and may stop disks. */
  GRUB_LOADER_PREBOOT_HOOK_PRIO_DISK = 300,
  /* A preboot hook which can't use disks or console and may stop console. */
  GRUB_LOADER_PREBOOT_HOOK_PRIO_CONSOLE = 200,
  /* A preboot hook which can't use disks or console, can't modify memory map
     and may stop memory services or finalize memory map. */
  GRUB_LOADER_PREBOOT_HOOK_PRIO_MEMORY = 100,
} grub_loader_preboot_hook_prio_t;

/* Register a preboot hook. */
void *grub_loader_register_preboot_hook (grub_err_t (*preboot_func) (int noret),
					 grub_err_t (*preboot_rest_func) (void),
					 grub_loader_preboot_hook_prio_t prio);

/* Unregister given preboot hook. */
void grub_loader_unregister_preboot_hook (void *hnd);

#endif /* ! GRUB_LOADER_HEADER */
