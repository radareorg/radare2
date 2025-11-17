/* SOM internal definitions for BFD.
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

#ifndef _SOM_INTERNAL_H
#define _SOM_INTERNAL_H

struct som_clock
{
  unsigned int secs;
  unsigned int nanosecs;
};

struct som_header
{
  unsigned short system_id;
  unsigned short a_magic;
  unsigned int version_id;
  struct som_clock file_time;
  unsigned int entry_space;
  unsigned int entry_subspace;
  unsigned int entry_offset;
  unsigned int aux_header_location;
  unsigned int aux_header_size;
  unsigned int som_length;
  unsigned int presumed_dp;
  unsigned int space_location;
  unsigned int space_total;
  unsigned int subspace_location;
  unsigned int subspace_total;
  unsigned int loader_fixup_location;
  unsigned int loader_fixup_total;
  unsigned int space_strings_location;
  unsigned int space_strings_size;
  unsigned int init_array_location;
  unsigned int init_array_total;
  unsigned int compiler_location;
  unsigned int compiler_total;
  unsigned int symbol_location;
  unsigned int symbol_total;
  unsigned int fixup_request_location;
  unsigned int fixup_request_total;
  unsigned int symbol_strings_location;
  unsigned int symbol_strings_size;
  unsigned int unloadable_sp_location;
  unsigned int unloadable_sp_size;
  unsigned int checksum;
};

struct som_aux_id
{
  unsigned int mandatory : 1;
  unsigned int copy : 1;
  unsigned int append : 1;
  unsigned int ignore : 1;
  unsigned int reserved : 12;

  /* Header type.  */
  unsigned int type : 16;

  /* Length of the header in bytes, without the two word identifier.  */
  unsigned int length;
};

/* Generic auxiliary string header.  */
struct som_string_auxhdr
{
  struct som_aux_id header_id;

  /* Length of the string, without the NUL.  */
  unsigned int string_length;

  /* The string.  */
  char string[1];
};

struct som_name_pt
{
  char *name;
  unsigned int strx;
};

struct som_compilation_unit
{
  /* Source file that produced the SOM.  */
  struct som_name_pt name;

  /* Name of the language used when creating this SOM.  */
  struct som_name_pt language_name;

  /* Identificaton of the compiler.  */
  struct som_name_pt product_id;

  /* Version id of the compiler.  */
  struct som_name_pt version_id;

  unsigned int flags;
  struct som_clock compile_time;
  struct som_clock source_time;
};

struct som_exec_auxhdr
{
  struct som_aux_id som_auxhdr;

  long exec_tsize;
  long exec_tmem;
  long exec_tfile;
  long exec_dsize;
  long exec_dmem;
  long exec_dfile;
  long exec_bsize;
  long exec_entry;
  long exec_flags;
  long exec_bfill;
};

struct som_space_dictionary_record
{
  unsigned int name;
  unsigned int is_loadable : 1;
  unsigned int is_defined : 1;
  unsigned int is_private : 1;
  unsigned int has_intermediate_code : 1;
  unsigned int is_tspecific : 1;
  unsigned int reserved : 11;
  unsigned int sort_key : 8;
  unsigned int reserved2 : 8;
  int space_number;
  int subspace_index;
  unsigned int subspace_quantity;
  int loader_fix_index;
  unsigned int loader_fix_quantity;
  int init_pointer_index;
  unsigned int init_pointer_quantity;
};

struct som_subspace_dictionary_record
{
  int space_index;
  unsigned int access_control_bits : 7;
  unsigned int memory_resident : 1;
  unsigned int dup_common : 1;
  unsigned int is_common : 1;
  unsigned int is_loadable : 1;
  unsigned int quadrant : 2;
  unsigned int initially_frozen : 1;
  unsigned int is_first : 1;
  unsigned int code_only : 1;
  unsigned int sort_key : 8;
  unsigned int replicate_init : 1;
  unsigned int continuation : 1;
  unsigned int is_tspecific : 1;
  unsigned int is_comdat : 1;
  unsigned int reserved : 4;
  int file_loc_init_value;
  unsigned int initialization_length;
  unsigned int subspace_start;
  unsigned int subspace_length;
  unsigned int reserved2 : 5;
  unsigned int alignment : 27;
  unsigned int name;
  int fixup_request_index;
  unsigned int fixup_request_quantity;
};

struct som_lst_header
{
  unsigned short system_id;
  unsigned short a_magic;
  unsigned int version_id;
  struct som_clock file_time;
  unsigned int hash_loc;
  unsigned int hash_size;
  unsigned int module_count;
  unsigned int module_limit;
  unsigned int dir_loc;
  unsigned int export_loc;
  unsigned int export_count;
  unsigned int import_loc;
  unsigned int aux_loc;
  unsigned int aux_size;
  unsigned int string_loc;
  unsigned int string_size;
  unsigned int free_list;
  unsigned int file_end;
  unsigned int checksum;
};

#endif /* _SOM_INTERNAL_H */
