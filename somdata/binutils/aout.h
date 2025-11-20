/* SOM a.out definitions for BFD.
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

#ifndef _SOM_AOUT_H
#define _SOM_AOUT_H

#include "clock.h"

/* Note: SOM uses bit-field in its structure.  All you need to know is:
   - CPUs supported by SOM (hppa) are big-endian,
   - the MSB is numbered 0.  */

struct som_external_header
{
  unsigned char system_id[2];
  unsigned char a_magic[2];
  unsigned char version_id[4];
  struct som_external_clock file_time;
  unsigned char entry_space[4];
  unsigned char entry_subspace[4];
  unsigned char entry_offset[4];
  unsigned char aux_header_location[4];
  unsigned char aux_header_size[4];
  unsigned char som_length[4];
  unsigned char presumed_dp[4];
  unsigned char space_location[4];
  unsigned char space_total[4];
  unsigned char subspace_location[4];
  unsigned char subspace_total[4];
  unsigned char loader_fixup_location[4];
  unsigned char loader_fixup_total[4];
  unsigned char space_strings_location[4];
  unsigned char space_strings_size[4];
  unsigned char init_array_location[4];
  unsigned char init_array_total[4];
  unsigned char compiler_location[4];
  unsigned char compiler_total[4];
  unsigned char symbol_location[4];
  unsigned char symbol_total[4];
  unsigned char fixup_request_location[4];
  unsigned char fixup_request_total[4];
  unsigned char symbol_strings_location[4];
  unsigned char symbol_strings_size[4];
  unsigned char unloadable_sp_location[4];
  unsigned char unloadable_sp_size[4];
  unsigned char checksum[4];
};

#define OLD_VERSION_ID 85082112
#define NEW_VERSION_ID 87102412

#define EXECLIBMAGIC	0x0104
#define RELOC_MAGIC	0x0106
#define EXEC_MAGIC	0x0107
#define SHARE_MAGIC	0x0108
#define SHMEM_MAGIC	0x0109
#define DEMAND_MAGIC	0x010b
#define DL_MAGIC	0x010d
#define SHL_MAGIC	0x010e

struct som_external_aux_id
{
  unsigned char flags[4];
  unsigned char length[4];
};

/* Aux id types.  */
#define VERSION_AUX_ID 6
#define COPYRIGHT_AUX_ID 9

/* Aux id flags.  */
#define SOM_AUX_ID_MANDATORY	(1u << 31)
#define SOM_AUX_ID_COPY		(1 << 30)
#define SOM_AUX_ID_APPEND	(1 << 29)
#define SOM_AUX_ID_IGNORE	(1 << 28)
#define SOM_AUX_ID_TYPE_SH	0
#define SOM_AUX_ID_TYPE_MASK	0xffff

struct som_external_string_auxhdr
{
  struct som_external_aux_id header_id;

  /* Length of the string, without the NUL.  */
  unsigned char string_length[4];

  /* The string.  */
};

struct som_external_exec_auxhdr
{
  struct som_external_aux_id som_auxhdr;

  unsigned char exec_tsize[4];
  unsigned char exec_tmem[4];
  unsigned char exec_tfile[4];
  unsigned char exec_dsize[4];
  unsigned char exec_dmem[4];
  unsigned char exec_dfile[4];
  unsigned char exec_bsize[4];
  unsigned char exec_entry[4];
  unsigned char exec_flags[4];
  unsigned char exec_bfill[4];
};

#define AUX_HDR_SIZE sizeof (struct som_external_exec_auxhdr)

struct som_external_space_dictionary_record
{
  unsigned char name[4];
  unsigned char flags[4];
  unsigned char space_number[4];
  unsigned char subspace_index[4];
  unsigned char subspace_quantity[4];
  unsigned char loader_fix_index[4];
  unsigned char loader_fix_quantity[4];
  unsigned char init_pointer_index[4];
  unsigned char init_pointer_quantity[4];
};

#define SOM_SPACE_IS_LOADABLE		(1u << 31)
#define SOM_SPACE_IS_DEFINED		(1 << 30)
#define SOM_SPACE_IS_PRIVATE		(1 << 29)
#define SOM_SPACE_HAS_INTERMEDIATE_CODE (1 << 28)
#define SOM_SPACE_IS_TSPECIFIC		(1 << 27)
#define SOM_SPACE_SORT_KEY_SH		8
#define SOM_SPACE_SORT_KEY_MASK		0xff

struct som_external_subspace_dictionary_record
{
  unsigned char space_index[4];
  unsigned char flags[4];
  unsigned char file_loc_init_value[4];
  unsigned char initialization_length[4];
  unsigned char subspace_start[4];
  unsigned char subspace_length[4];
  unsigned char alignment[4];
  unsigned char name[4];
  unsigned char fixup_request_index[4];
  unsigned char fixup_request_quantity[4];
};

#define SOM_SUBSPACE_ACCESS_CONTROL_BITS_SH	25
#define SOM_SUBSPACE_ACCESS_CONTROL_BITS_MASK	0x7fU
#define SOM_SUBSPACE_MEMORY_RESIDENT		(1U << 24)
#define SOM_SUBSPACE_DUP_COMMON			(1U << 23)
#define SOM_SUBSPACE_IS_COMMON			(1U << 22)
#define SOM_SUBSPACE_IS_LOADABLE		(1U << 21)
#define SOM_SUBSPACE_QUADRANT_SH		19
#define SOM_SUBSPACE_QUADRANT_MASK		0x3U
#define SOM_SUBSPACE_INITIALLY_FROZEN		(1U << 18)
#define SOM_SUBSPACE_IS_FIRST			(1U << 17)
#define SOM_SUBSPACE_CODE_ONLY			(1U << 16)
#define SOM_SUBSPACE_SORT_KEY_SH		8
#define SOM_SUBSPACE_SORT_KEY_MASK		0xffU
#define SOM_SUBSPACE_REPLICATE_INIT		(1U << 7)
#define SOM_SUBSPACE_CONTINUATION		(1U << 6)
#define SOM_SUBSPACE_IS_TSPECIFIC		(1U << 5)
#define SOM_SUBSPACE_IS_COMDAT			(1U << 4)

struct som_external_compilation_unit
{
  unsigned char name[4];
  unsigned char language_name[4];
  unsigned char product_id[4];
  unsigned char version_id[4];
  unsigned char flags[4];
  struct som_external_clock compile_time;
  struct som_external_clock source_time;
};

struct som_external_symbol_dictionary_record
{
  unsigned char flags[4];
  unsigned char name[4];
  unsigned char qualifier_name[4];
  unsigned char info[4];
  unsigned char symbol_value[4];
};

/* Flags fields.  */
#define SOM_SYMBOL_HIDDEN (1u << 31)
#define SOM_SYMBOL_SECONDARY_DEF (1 << 30)
#define SOM_SYMBOL_TYPE_SH 24
#define SOM_SYMBOL_TYPE_MASK 0x3f
#define SOM_SYMBOL_SCOPE_SH 20
#define SOM_SYMBOL_SCOPE_MASK 0xf
#define SOM_SYMBOL_CHECK_LEVEL_SH 17
#define SOM_SYMBOL_CHECK_LEVEL_MASK 0x7
#define SOM_SYMBOL_MUST_QUALIFY (1 << 16)
#define SOM_SYMBOL_INITIALLY_FROZEN (1 << 15)
#define SOM_SYMBOL_MEMORY_RESIDENT (1 << 14)
#define SOM_SYMBOL_IS_COMMON (1 << 13)
#define SOM_SYMBOL_DUP_COMMON (1 << 12)
#define SOM_SYMBOL_XLEAST_SH 10
#define SOM_SYMBOL_XLEAT_MASK 0x3
#define SOM_SYMBOL_ARG_RELOC_SH 0
#define SOM_SYMBOL_ARG_RELOC_MASK 0x3ff

/* Info fields.  */
#define SOM_SYMBOL_HAS_LONG_RETURN (1u << 31)
#define SOM_SYMBOL_NO_RELOCATION (1 << 30)
#define SOM_SYMBOL_IS_COMDAT (1 << 29)
#define SOM_SYMBOL_SYMBOL_INFO_SH 0
#define SOM_SYMBOL_SYMBOL_INFO_MASK 0xffffff

/* Symbol type definition.  */
#define ST_NULL		0
#define ST_ABSOLUTE	1
#define ST_DATA		2
#define ST_CODE		3
#define ST_PRI_PROG	4
#define ST_SEC_PROG	5
#define ST_ENTRY	6
#define ST_STORAGE	7
#define ST_STUB		8
#define ST_MODULE	9
#define ST_SYM_EXT	10
#define ST_ARG_EXT	11
#define ST_MILLICODE	12
#define ST_PLABEL	13
#define ST_OCT_DIS	14
#define ST_MILLI_EXT	15
#define ST_TSTORAGE	16
#define ST_COMDAT	17

/* Symbol scope.  */
#define SS_UNSAT	0
#define SS_EXTERNAL	1
#define SS_LOCAL	2
#define SS_UNIVERSAL	3

#endif /* _SOM_AOUT_H */
