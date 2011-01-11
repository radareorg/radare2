/* time.c - kernel time functions */
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

#include <grub/time.h>

typedef grub_uint64_t (*get_time_ms_func_t) (void);

/* Function pointer to the implementation in use.  */
static get_time_ms_func_t get_time_ms_func;

grub_uint64_t
grub_get_time_ms (void)
{
  return get_time_ms_func ();
}

void
grub_install_get_time_ms (get_time_ms_func_t func)
{
  get_time_ms_func = func;
}
