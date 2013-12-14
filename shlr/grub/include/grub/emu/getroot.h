/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2003, 2007, 2008, 2009  Free Software Foundation, Inc.
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

#ifndef GRUB_UTIL_GETROOT_HEADER
#define GRUB_UTIL_GETROOT_HEADER	1

#include <sys/types.h>

enum grub_dev_abstraction_types {
  GRUB_DEV_ABSTRACTION_NONE,
  GRUB_DEV_ABSTRACTION_LVM,
  GRUB_DEV_ABSTRACTION_RAID,
};

char *grub_find_device (const char *dir, dev_t dev);
char *grub_guess_root_device (const char *dir);
int grub_util_get_dev_abstraction (const char *os_dev);
char *grub_util_get_grub_dev (const char *os_dev);
char *grub_make_system_path_relative_to_its_root (const char *path);
const char *grub_util_check_block_device (const char *blk_dev);
const char *grub_util_check_char_device (const char *blk_dev);

#endif /* ! GRUB_UTIL_GETROOT_HEADER */
