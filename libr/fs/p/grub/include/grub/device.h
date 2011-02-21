/* device.h - device manager */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2005,2007  Free Software Foundation, Inc.
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

#ifndef GRUB_DEVICE_HEADER
#define GRUB_DEVICE_HEADER	1

#include <grub/symbol.h>
#include <grub/err.h>

struct grub_disk;
struct grub_net;
struct grub_fs;

struct grub_device
{
  struct grub_disk *disk;
  struct grub_net *net;
};
typedef struct grub_device *grub_device_t;

grub_device_t grub_device_open (const char *name);
grub_err_t grub_device_close (grub_device_t device);
int grub_device_iterate (int (*hook) (const char *name, void *closure),
			 void *closure);

#endif /* ! GRUB_DEVICE_HEADER */
