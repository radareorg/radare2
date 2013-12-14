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
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef GRUB_REED_SOLOMON_HEADER
#define GRUB_REED_SOLOMON_HEADER	1

void
grub_reed_solomon_add_redundancy (void *buffer, grub_size_t data_size,
				  grub_size_t redundancy);

void
grub_reed_solomon_recover (void *buffer, grub_size_t data_size,
			   grub_size_t redundancy);

#endif
