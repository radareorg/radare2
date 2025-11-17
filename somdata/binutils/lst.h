/* SOM lst definitions for BFD.
   Copyright (C) 2010-2023 Free Software Foundation, Inc.
   Contributed by Tristan Gingold <gingold@adacore.com>, AdaCore.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _SOM_LST_H
#define _SOM_LST_H

#include "clock.h"

/* See 4.2 Libraray Symbol Table Header Record.  */
struct som_external_lst_header
{
  unsigned char system_id[2];
  unsigned char a_magic[2];
  unsigned char version_id[4];
  struct som_external_clock file_time;
  unsigned char hash_loc[4];
  unsigned char hash_size[4];
  unsigned char module_count[4];
  unsigned char module_limit[4];
  unsigned char dir_loc[4];
  unsigned char export_loc[4];
  unsigned char export_count[4];
  unsigned char import_loc[4];
  unsigned char aux_loc[4];
  unsigned char aux_size[4];
  unsigned char string_loc[4];
  unsigned char string_size[4];
  unsigned char free_list[4];
  unsigned char file_end[4];
  unsigned char checksum[4];
};

#define VERSION_ID 85082112
#define LIBMAGIC 0x0619
#define LIBMAGIC_EXEC 0x0104

struct som_external_lst_symbol_record
{
  unsigned char flags[4];
  unsigned char name[4];
  unsigned char qualifier_name[4];
  unsigned char symbol_info[4];
  unsigned char symbol_value[4];
  unsigned char symbol_descriptor[4];
  unsigned char reserved;
  unsigned char max_num_args;
  unsigned char min_num_args;
  unsigned char num_args;
  unsigned char som_index[4];
  unsigned char symbol_key[4];
  unsigned char next_entry[4];
};

/* Fields of flags.  */
#define LST_SYMBOL_HIDDEN		(1u << 31)
#define LST_SYMBOL_SECONDARY_DEF	(1 << 30)
#define LST_SYMBOL_SYMBOL_TYPE_SH	24
#define LST_SYMBOL_SYMBOL_SCOPE_SH	20
#define LST_SYMBOL_CHECK_LEVEL_SH	17
#define LST_SYMBOL_MUST_QUALIFY		(1 << 16)
#define LST_SYMBOL_INITIALY_FROZEN	(1 << 15)
#define LST_SYMBOL_MEMORY_RESIDENT	(1 << 14)
#define LST_SYMBOL_IS_COMMON		(1 << 13)
#define LST_SYMBOL_DUP_COMMON		(1 << 12)
#define LST_SYMBOL_XLEAST_SH		10
#define LST_SYMBOL_ARG_RELOC_SH		0

/* According to 4.3.2 SOM Directory.  */

struct som_external_som_entry
{
  unsigned char location[4];
  unsigned char length[4];
};

#endif /* _SOM_LST_H */
