/* normal.h - prototypes for the normal mode */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2002,2003,2005,2006,2007,2008,2009  Free Software Foundation, Inc.
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

#ifndef GRUB_NORMAL_HEADER
#define GRUB_NORMAL_HEADER	1

extern int grub_normal_exit_level;

/* Defined in `handler.c'.  */
void read_handler_list (void);
void free_handler_list (void);

/* Defined in `dyncmd.c'.  */
void read_command_list (const char *prefix);

/* Defined in `autofs.c'.  */
void read_fs_list (const char *prefix);

void grub_context_init (void);
void grub_context_fini (void);

void read_crypto_list (const char *prefix);

void read_terminal_list (const char *prefix);

void grub_set_more (int onoff);

int grub_normal_get_line_counter (void);
void grub_install_newline_hook (void);

#endif /* ! GRUB_NORMAL_HEADER */
