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
 *  along with GRUB.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef GRUB_DECOMPRESSOR_HEADER
#define GRUB_DECOMPRESSOR_HEADER	1

void
grub_decompress_core (void *src, void *dst, unsigned long srcsize,
		      unsigned long dstsize);

void
find_scratch (void *src, void *dst, unsigned long srcsize,
	      unsigned long dstsize);

#define GRUB_DECOMPRESSOR_DICT_SIZE (1 << 16)

extern void *grub_decompressor_scratch;

#endif
