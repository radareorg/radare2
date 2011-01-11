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

#ifndef KERNEL_DATETIME_HEADER
#define KERNEL_DATETIME_HEADER	1

#include <grub/types.h>
#include <grub/err.h>

struct grub_datetime
{
  grub_uint16_t year;
  grub_uint8_t month;
  grub_uint8_t day;
  grub_uint8_t hour;
  grub_uint8_t minute;
  grub_uint8_t second;
};

/* Return date and time.  */
#ifdef GRUB_MACHINE_EMU
grub_err_t EXPORT_FUNC(grub_get_datetime) (struct grub_datetime *datetime);

/* Set date and time.  */
grub_err_t EXPORT_FUNC(grub_set_datetime) (struct grub_datetime *datetime);
#else
grub_err_t grub_get_datetime (struct grub_datetime *datetime);

/* Set date and time.  */
grub_err_t grub_set_datetime (struct grub_datetime *datetime);
#endif

int grub_get_weekday (struct grub_datetime *datetime);
char *grub_get_weekday_name (struct grub_datetime *datetime);

void grub_unixtime2datetime (grub_int32_t nix,
			     struct grub_datetime *datetime);


#endif /* ! KERNEL_DATETIME_HEADER */
