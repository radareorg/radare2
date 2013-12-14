/* bufio.h - prototypes for bufio */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2008  Free Software Foundation, Inc.
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

#ifndef GRUB_BUFIO_H
#define GRUB_BUFIO_H	1

#include <grub/file.h>

grub_file_t EXPORT_FUNC (grub_bufio_open) (grub_file_t io, int size);
grub_file_t EXPORT_FUNC (grub_buffile_open) (const char *name, int size);

#endif /* ! GRUB_BUFIO_H */
