/* SOM relocation definitions for BFD.
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

#ifndef _SOM_RELOC_H
#define _SOM_RELOC_H

#define R_NO_RELOCATION		0
#define R_ZEROES		0x20
#define R_UNINIT		0x22
#define R_RELOCATION		0x24
#define R_DATA_ONE_SYMBOL	0x25
#define R_DATA_PLABEL		0x27
#define R_SPACE_REF		0x29
#define R_REPEATED_INIT		0x2a
#define R_PCREL_CALL		0x30
#define R_SHORT_PCREL_MODE	0x3e
#define R_LONG_PCREL_MODE	0x3f
#define R_ABS_CALL		0x40
#define R_DP_RELATIVE		0x50
#define R_DATA_GPREL		0x72
#define R_INDIRECT_CALL		0x76
#define R_PLT_REL		0x77
#define R_DLT_REL		0x78
#define R_CODE_ONE_SYMBOL	0x80
#define R_MILLI_REL		0xae
#define R_CODE_PLABEL		0xb0
#define R_BREAKPOINT		0xb2
#define R_ENTRY			0xb3
#define R_ALT_ENTRY		0xb5
#define R_EXIT			0xb6
#define R_BEGIN_TRY		0xb7
#define R_END_TRY		0xb8
#define R_BEGIN_BRTAB		0xbb
#define R_END_BRTAB		0xbc
#define R_STATEMENT		0xbd
#define R_DATA_EXPR		0xc0
#define R_CODE_EXPR		0xc1
#define R_FSEL			0xc2
#define R_LSEL			0xc3
#define R_RSEL			0xc4
#define R_N_MODE		0xc5
#define R_S_MODE		0xc6
#define R_D_MODE		0xc7
#define R_R_MODE		0xc8
#define R_DATA_OVERRIDE		0xc9
#define R_TRANSLATED		0xce
#define R_AUX_UNWIND		0xcf
#define R_COMP1			0xd0
#define R_COMP2			0xd1
#define R_COMP3			0xd2
#define R_PREV_FIXUP		0xd3
#define R_SEC_STMT		0xd7
#define R_N0SEL			0xd8
#define R_N1SEL			0xd9
#define R_LINETAB		0xda
#define R_LINETAB_ESC		0xdb
#define R_LTP_OVERRIDE		0xdc
#define R_COMMENT		0xdd
#define R_TP_OVERRIDE		0xde
#define R_RESERVED		0xdf

#endif /* _SOM_RELOC_H */
