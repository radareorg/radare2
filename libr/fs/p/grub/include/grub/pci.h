/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008,2009  Free Software Foundation, Inc.
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

#ifndef	GRUB_PCI_H
#define	GRUB_PCI_H	1

#ifndef ASM_FILE
#include <grub/types.h>
#include <grub/symbol.h>
#endif

#define  GRUB_PCI_ADDR_SPACE_MASK	0x01
#define  GRUB_PCI_ADDR_SPACE_MEMORY	0x00
#define  GRUB_PCI_ADDR_SPACE_IO		0x01

#define  GRUB_PCI_ADDR_MEM_TYPE_MASK	0x06
#define  GRUB_PCI_ADDR_MEM_TYPE_32	0x00	/* 32 bit address */
#define  GRUB_PCI_ADDR_MEM_TYPE_1M	0x02	/* Below 1M [obsolete] */
#define  GRUB_PCI_ADDR_MEM_TYPE_64	0x04	/* 64 bit address */
#define  GRUB_PCI_ADDR_MEM_PREFETCH	0x08	/* prefetchable */

#define  GRUB_PCI_ADDR_MEM_MASK		~0xf
#define  GRUB_PCI_ADDR_IO_MASK		~0x03

#define  GRUB_PCI_REG_PCI_ID       0x00
#define  GRUB_PCI_REG_VENDOR       0x00
#define  GRUB_PCI_REG_DEVICE       0x02
#define  GRUB_PCI_REG_COMMAND      0x04
#define  GRUB_PCI_REG_STATUS       0x06
#define  GRUB_PCI_REG_REVISION     0x08
#define  GRUB_PCI_REG_CLASS        0x08
#define  GRUB_PCI_REG_CACHELINE    0x0c
#define  GRUB_PCI_REG_LAT_TIMER    0x0d
#define  GRUB_PCI_REG_HEADER_TYPE  0x0e
#define  GRUB_PCI_REG_BIST         0x0f
#define  GRUB_PCI_REG_ADDRESSES    0x10

/* Beware that 64-bit address takes 2 registers.  */
#define  GRUB_PCI_REG_ADDRESS_REG0 0x10
#define  GRUB_PCI_REG_ADDRESS_REG1 0x14
#define  GRUB_PCI_REG_ADDRESS_REG2 0x18
#define  GRUB_PCI_REG_ADDRESS_REG3 0x1c
#define  GRUB_PCI_REG_ADDRESS_REG4 0x20
#define  GRUB_PCI_REG_ADDRESS_REG5 0x24

#define  GRUB_PCI_REG_CIS_POINTER  0x28
#define  GRUB_PCI_REG_SUBVENDOR    0x2c
#define  GRUB_PCI_REG_SUBSYSTEM    0x2e
#define  GRUB_PCI_REG_ROM_ADDRESS  0x30
#define  GRUB_PCI_REG_CAP_POINTER  0x34
#define  GRUB_PCI_REG_IRQ_LINE     0x3c
#define  GRUB_PCI_REG_IRQ_PIN      0x3d
#define  GRUB_PCI_REG_MIN_GNT      0x3e
#define  GRUB_PCI_REG_MAX_LAT      0x3f

#define  GRUB_PCI_COMMAND_IO_ENABLED    0x0001
#define  GRUB_PCI_COMMAND_MEM_ENABLED   0x0002
#define  GRUB_PCI_COMMAND_BUS_MASTER    0x0004
#define  GRUB_PCI_COMMAND_PARITY_ERROR  0x0040
#define  GRUB_PCI_COMMAND_SERR_ENABLE   0x0100

#define  GRUB_PCI_STATUS_CAPABILITIES      0x0010
#define  GRUB_PCI_STATUS_66MHZ_CAPABLE     0x0020
#define  GRUB_PCI_STATUS_FAST_B2B_CAPABLE  0x0080

#define  GRUB_PCI_STATUS_DEVSEL_TIMING_SHIFT 9
#define  GRUB_PCI_STATUS_DEVSEL_TIMING_MASK 0x0600
#define  GRUB_PCI_CLASS_SUBCLASS_VGA  0x0300

#ifndef ASM_FILE
typedef grub_uint32_t grub_pci_id_t;

#ifdef GRUB_MACHINE_EMU
#include <grub/pciutils.h>
#else
typedef grub_uint32_t grub_pci_address_t;
struct grub_pci_device
{
  int bus;
  int device;
  int function;
};
typedef struct grub_pci_device grub_pci_device_t;
static inline int
grub_pci_get_bus (grub_pci_device_t dev)
{
  return dev.bus;
}

static inline int
grub_pci_get_device (grub_pci_device_t dev)
{
  return dev.device;
}

static inline int
grub_pci_get_function (grub_pci_device_t dev)
{
  return dev.function;
}
#include <grub/cpu/pci.h>
#endif

typedef int NESTED_FUNC_ATTR (*grub_pci_iteratefunc_t)
     (grub_pci_device_t dev, grub_pci_id_t pciid);

grub_pci_address_t EXPORT_FUNC(grub_pci_make_address) (grub_pci_device_t dev,
						       int reg);

void EXPORT_FUNC(grub_pci_iterate) (grub_pci_iteratefunc_t hook);

struct grub_pci_dma_chunk;

struct grub_pci_dma_chunk *EXPORT_FUNC(grub_memalign_dma32) (grub_size_t align,
							     grub_size_t size);
void EXPORT_FUNC(grub_dma_free) (struct grub_pci_dma_chunk *ch);
volatile void *EXPORT_FUNC(grub_dma_get_virt) (struct grub_pci_dma_chunk *ch);
grub_uint32_t EXPORT_FUNC(grub_dma_get_phys) (struct grub_pci_dma_chunk *ch);

#endif

#endif /* GRUB_PCI_H */
