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

#ifndef GRUB_RELOCATOR_PRIVATE_HEADER
#define GRUB_RELOCATOR_PRIVATE_HEADER	1

#include <grub/types.h>
#include <grub/err.h>
#include <grub/mm_private.h>

extern grub_size_t grub_relocator_align;
extern grub_size_t grub_relocator_forward_size;
extern grub_size_t grub_relocator_backward_size;
extern grub_size_t grub_relocator_jumper_size;

void
grub_cpu_relocator_init (void);
grub_err_t
grub_relocator_prepare_relocs (struct grub_relocator *rel,
			       grub_addr_t addr,
			       void **relstart, grub_size_t *relsize);
void grub_cpu_relocator_forward (void *rels, void *src, void *tgt,
				 grub_size_t size);
void grub_cpu_relocator_backward (void *rels, void *src, void *tgt,
				 grub_size_t size);
void grub_cpu_relocator_jumper (void *rels, grub_addr_t addr);

/* Remark: GRUB_RELOCATOR_FIRMWARE_REQUESTS_QUANT_LOG = 1 or 2
   aren't supported.  */
#ifdef GRUB_MACHINE_IEEE1275
#define GRUB_RELOCATOR_HAVE_FIRMWARE_REQUESTS 1
#define GRUB_RELOCATOR_FIRMWARE_REQUESTS_QUANT_LOG 0
#elif defined (GRUB_MACHINE_EFI)
#define GRUB_RELOCATOR_HAVE_FIRMWARE_REQUESTS 1
#define GRUB_RELOCATOR_FIRMWARE_REQUESTS_QUANT_LOG 12
#else
#define GRUB_RELOCATOR_HAVE_FIRMWARE_REQUESTS 0
#endif

#if GRUB_RELOCATOR_HAVE_FIRMWARE_REQUESTS && GRUB_RELOCATOR_FIRMWARE_REQUESTS_QUANT_LOG != 0
#define GRUB_RELOCATOR_HAVE_LEFTOVERS 1
#else
#define GRUB_RELOCATOR_HAVE_LEFTOVERS 0
#endif

#if GRUB_RELOCATOR_HAVE_FIRMWARE_REQUESTS
#define GRUB_RELOCATOR_FIRMWARE_REQUESTS_QUANT (1 << GRUB_RELOCATOR_FIRMWARE_REQUESTS_QUANT_LOG)
#endif

struct grub_relocator_mmap_event
{
  enum {
    IN_REG_START = 0, 
    IN_REG_END = 1, 
    REG_BEG_START = 2, 
    REG_BEG_END = REG_BEG_START | 1,
#if GRUB_RELOCATOR_HAVE_FIRMWARE_REQUESTS
    REG_FIRMWARE_START = 4, 
    REG_FIRMWARE_END = REG_FIRMWARE_START | 1,
    /* To track the regions already in heap.  */
    FIRMWARE_BLOCK_START = 6, 
    FIRMWARE_BLOCK_END = FIRMWARE_BLOCK_START | 1,
#endif
#if GRUB_RELOCATOR_HAVE_LEFTOVERS
    REG_LEFTOVER_START = 8, 
    REG_LEFTOVER_END = REG_LEFTOVER_START | 1,
#endif
    COLLISION_START = 10,
    COLLISION_END = COLLISION_START | 1
  } type;
  grub_phys_addr_t pos;
  union
  {
    struct
    {
      grub_mm_region_t reg;
      grub_mm_header_t hancestor;
      grub_mm_region_t *regancestor;
      grub_mm_header_t head;
    };
#if GRUB_RELOCATOR_HAVE_FIRMWARE_REQUESTS
    struct grub_relocator_fw_leftover *leftover;
#endif
  };
};

/* Return 0 on failure, 1 on success. The failure here 
   can be very time-expensive, so please make sure fill events is accurate.  */
#if GRUB_RELOCATOR_HAVE_FIRMWARE_REQUESTS
int grub_relocator_firmware_alloc_region (grub_phys_addr_t start,
					  grub_size_t size);
unsigned grub_relocator_firmware_fill_events (struct grub_relocator_mmap_event *events);
unsigned grub_relocator_firmware_get_max_events (void);
void grub_relocator_firmware_free_region (grub_phys_addr_t start,
					  grub_size_t size);
#endif

#endif
