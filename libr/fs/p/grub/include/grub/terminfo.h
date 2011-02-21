/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2005,2007  Free Software Foundation, Inc.
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

#ifndef GRUB_TERMINFO_HEADER
#define GRUB_TERMINFO_HEADER	1

#include <grub/err.h>
#include <grub/types.h>
#include <grub/term.h>

char *grub_terminfo_get_current (void);
grub_err_t grub_terminfo_set_current (const char *);

void grub_terminfo_gotoxy (grub_uint8_t x, grub_uint8_t y,
			   grub_term_output_t oterm);
void grub_terminfo_cls (grub_term_output_t oterm);
void grub_terminfo_reverse_video_on (grub_term_output_t oterm);
void grub_terminfo_reverse_video_off (grub_term_output_t oterm);
void grub_terminfo_cursor_on (grub_term_output_t oterm);
void grub_terminfo_cursor_off (grub_term_output_t oterm);

#endif /* ! GRUB_TERMINFO_HEADER */
