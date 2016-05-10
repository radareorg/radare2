/* CPU data for vc4.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright 1996-2010 Free Software Foundation, Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

   This file is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation, Inc.,
   51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#include "sysdep.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include "ansidecl.h"
#include "mybfd.h"
#include "symcat.h"
#include "vc4-desc.h"
#include "vc4-opc.h"
#include "opintl.h"
#include "libiberty.h"
#include "dis-asm.h"
#include "regex.h"

/* Attributes.  */

static const CGEN_ATTR_ENTRY bool_attr[] =
{
  { "#f", 0 },
  { "#t", 1 },
  { 0, 0 }
};

static const CGEN_ATTR_ENTRY MACH_attr[] ATTRIBUTE_UNUSED =
{
  { "base", MACH_BASE },
  { "vc4", MACH_VC4 },
  { "max", MACH_MAX },
  { 0, 0 }
};

static const CGEN_ATTR_ENTRY ISA_attr[] ATTRIBUTE_UNUSED =
{
  { "vc4", ISA_VC4 },
  { "max", ISA_MAX },
  { 0, 0 }
};

const CGEN_ATTR_TABLE vc4_cgen_ifield_attr_table[] =
{
  { "MACH", & MACH_attr[0], & MACH_attr[0] },
  { "VIRTUAL", &bool_attr[0], &bool_attr[0] },
  { "PCREL-ADDR", &bool_attr[0], &bool_attr[0] },
  { "ABS-ADDR", &bool_attr[0], &bool_attr[0] },
  { "RESERVED", &bool_attr[0], &bool_attr[0] },
  { "SIGN-OPT", &bool_attr[0], &bool_attr[0] },
  { "SIGNED", &bool_attr[0], &bool_attr[0] },
  { 0, 0, 0 }
};

const CGEN_ATTR_TABLE vc4_cgen_hardware_attr_table[] =
{
  { "MACH", & MACH_attr[0], & MACH_attr[0] },
  { "VIRTUAL", &bool_attr[0], &bool_attr[0] },
  { "CACHE-ADDR", &bool_attr[0], &bool_attr[0] },
  { "PC", &bool_attr[0], &bool_attr[0] },
  { "PROFILE", &bool_attr[0], &bool_attr[0] },
  { 0, 0, 0 }
};

const CGEN_ATTR_TABLE vc4_cgen_operand_attr_table[] =
{
  { "MACH", & MACH_attr[0], & MACH_attr[0] },
  { "VIRTUAL", &bool_attr[0], &bool_attr[0] },
  { "PCREL-ADDR", &bool_attr[0], &bool_attr[0] },
  { "ABS-ADDR", &bool_attr[0], &bool_attr[0] },
  { "SIGN-OPT", &bool_attr[0], &bool_attr[0] },
  { "SIGNED", &bool_attr[0], &bool_attr[0] },
  { "NEGATIVE", &bool_attr[0], &bool_attr[0] },
  { "RELAX", &bool_attr[0], &bool_attr[0] },
  { "SEM-ONLY", &bool_attr[0], &bool_attr[0] },
  { 0, 0, 0 }
};

const CGEN_ATTR_TABLE vc4_cgen_insn_attr_table[] =
{
  { "MACH", & MACH_attr[0], & MACH_attr[0] },
  { "ALIAS", &bool_attr[0], &bool_attr[0] },
  { "VIRTUAL", &bool_attr[0], &bool_attr[0] },
  { "UNCOND-CTI", &bool_attr[0], &bool_attr[0] },
  { "COND-CTI", &bool_attr[0], &bool_attr[0] },
  { "SKIP-CTI", &bool_attr[0], &bool_attr[0] },
  { "DELAY-SLOT", &bool_attr[0], &bool_attr[0] },
  { "RELAXABLE", &bool_attr[0], &bool_attr[0] },
  { "RELAXED", &bool_attr[0], &bool_attr[0] },
  { "NO-DIS", &bool_attr[0], &bool_attr[0] },
  { "PBB", &bool_attr[0], &bool_attr[0] },
  { 0, 0, 0 }
};

/* Instruction set variants.  */

static const CGEN_ISA vc4_cgen_isa_table[] = {
  { "vc4", 16, 16, 16, 80 },
  { 0, 0, 0, 0, 0 }
};

/* Machine variants.  */

static const CGEN_MACH vc4_cgen_mach_table[] = {
  { "vc4", "vc4", MACH_VC4, 0 },
  { 0, 0, 0, 0 }
};

static CGEN_KEYWORD_ENTRY vc4_cgen_opval_h_reg_entries[] =
{
  { "r0", 0, {0, {{{0, 0}}}}, 0, 0 },
  { "r1", 1, {0, {{{0, 0}}}}, 0, 0 },
  { "r2", 2, {0, {{{0, 0}}}}, 0, 0 },
  { "r3", 3, {0, {{{0, 0}}}}, 0, 0 },
  { "r4", 4, {0, {{{0, 0}}}}, 0, 0 },
  { "r5", 5, {0, {{{0, 0}}}}, 0, 0 },
  { "r6", 6, {0, {{{0, 0}}}}, 0, 0 },
  { "r7", 7, {0, {{{0, 0}}}}, 0, 0 },
  { "r8", 8, {0, {{{0, 0}}}}, 0, 0 },
  { "r9", 9, {0, {{{0, 0}}}}, 0, 0 },
  { "r10", 10, {0, {{{0, 0}}}}, 0, 0 },
  { "r11", 11, {0, {{{0, 0}}}}, 0, 0 },
  { "r12", 12, {0, {{{0, 0}}}}, 0, 0 },
  { "r13", 13, {0, {{{0, 0}}}}, 0, 0 },
  { "r14", 14, {0, {{{0, 0}}}}, 0, 0 },
  { "r15", 15, {0, {{{0, 0}}}}, 0, 0 },
  { "r16", 16, {0, {{{0, 0}}}}, 0, 0 },
  { "r17", 17, {0, {{{0, 0}}}}, 0, 0 },
  { "r18", 18, {0, {{{0, 0}}}}, 0, 0 },
  { "r19", 19, {0, {{{0, 0}}}}, 0, 0 },
  { "r20", 20, {0, {{{0, 0}}}}, 0, 0 },
  { "r21", 21, {0, {{{0, 0}}}}, 0, 0 },
  { "r22", 22, {0, {{{0, 0}}}}, 0, 0 },
  { "r23", 23, {0, {{{0, 0}}}}, 0, 0 },
  { "gp", 24, {0, {{{0, 0}}}}, 0, 0 },
  { "sp", 25, {0, {{{0, 0}}}}, 0, 0 },
  { "lr", 26, {0, {{{0, 0}}}}, 0, 0 },
  { "r27", 27, {0, {{{0, 0}}}}, 0, 0 },
  { "r28", 28, {0, {{{0, 0}}}}, 0, 0 },
  { "r29", 29, {0, {{{0, 0}}}}, 0, 0 },
  { "sr", 30, {0, {{{0, 0}}}}, 0, 0 },
  { "pc", 31, {0, {{{0, 0}}}}, 0, 0 }
};

CGEN_KEYWORD vc4_cgen_opval_h_reg =
{
  & vc4_cgen_opval_h_reg_entries[0],
  32,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY vc4_cgen_opval_h_fastreg_entries[] =
{
  { "r0", 0, {0, {{{0, 0}}}}, 0, 0 },
  { "r1", 1, {0, {{{0, 0}}}}, 0, 0 },
  { "r2", 2, {0, {{{0, 0}}}}, 0, 0 },
  { "r3", 3, {0, {{{0, 0}}}}, 0, 0 },
  { "r4", 4, {0, {{{0, 0}}}}, 0, 0 },
  { "r5", 5, {0, {{{0, 0}}}}, 0, 0 },
  { "r6", 6, {0, {{{0, 0}}}}, 0, 0 },
  { "r7", 7, {0, {{{0, 0}}}}, 0, 0 },
  { "r8", 8, {0, {{{0, 0}}}}, 0, 0 },
  { "r9", 9, {0, {{{0, 0}}}}, 0, 0 },
  { "r10", 10, {0, {{{0, 0}}}}, 0, 0 },
  { "r11", 11, {0, {{{0, 0}}}}, 0, 0 },
  { "r12", 12, {0, {{{0, 0}}}}, 0, 0 },
  { "r13", 13, {0, {{{0, 0}}}}, 0, 0 },
  { "r14", 14, {0, {{{0, 0}}}}, 0, 0 },
  { "r15", 15, {0, {{{0, 0}}}}, 0, 0 }
};

CGEN_KEYWORD vc4_cgen_opval_h_fastreg =
{
  & vc4_cgen_opval_h_fastreg_entries[0],
  16,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY vc4_cgen_opval_h_ppreg_entries[] =
{
  { "r0", 0, {0, {{{0, 0}}}}, 0, 0 },
  { "r6", 1, {0, {{{0, 0}}}}, 0, 0 },
  { "r16", 2, {0, {{{0, 0}}}}, 0, 0 },
  { "r24", 3, {0, {{{0, 0}}}}, 0, 0 }
};

CGEN_KEYWORD vc4_cgen_opval_h_ppreg =
{
  & vc4_cgen_opval_h_ppreg_entries[0],
  4,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY vc4_cgen_opval_h_basereg_entries[] =
{
  { "r24", 0, {0, {{{0, 0}}}}, 0, 0 },
  { "sp", 1, {0, {{{0, 0}}}}, 0, 0 },
  { "pc", 2, {0, {{{0, 0}}}}, 0, 0 },
  { "r0", 3, {0, {{{0, 0}}}}, 0, 0 }
};

CGEN_KEYWORD vc4_cgen_opval_h_basereg =
{
  & vc4_cgen_opval_h_basereg_entries[0],
  4,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY vc4_cgen_opval_h_cond_entries[] =
{
  { "eq", 0, {0, {{{0, 0}}}}, 0, 0 },
  { "ne", 1, {0, {{{0, 0}}}}, 0, 0 },
  { "cs", 2, {0, {{{0, 0}}}}, 0, 0 },
  { "lo", 2, {0, {{{0, 0}}}}, 0, 0 },
  { "cc", 3, {0, {{{0, 0}}}}, 0, 0 },
  { "hs", 3, {0, {{{0, 0}}}}, 0, 0 },
  { "mi", 4, {0, {{{0, 0}}}}, 0, 0 },
  { "pl", 5, {0, {{{0, 0}}}}, 0, 0 },
  { "vs", 6, {0, {{{0, 0}}}}, 0, 0 },
  { "vc", 7, {0, {{{0, 0}}}}, 0, 0 },
  { "hi", 8, {0, {{{0, 0}}}}, 0, 0 },
  { "ls", 9, {0, {{{0, 0}}}}, 0, 0 },
  { "ge", 10, {0, {{{0, 0}}}}, 0, 0 },
  { "lt", 11, {0, {{{0, 0}}}}, 0, 0 },
  { "gt", 12, {0, {{{0, 0}}}}, 0, 0 },
  { "le", 13, {0, {{{0, 0}}}}, 0, 0 },
  { "", 14, {0, {{{0, 0}}}}, 0, 0 },
  { "f", 15, {0, {{{0, 0}}}}, 0, 0 }
};

CGEN_KEYWORD vc4_cgen_opval_h_cond =
{
  & vc4_cgen_opval_h_cond_entries[0],
  18,
  0, 0, 0, 0, ""
};

static CGEN_KEYWORD_ENTRY vc4_cgen_opval_h_accsz_entries[] =
{
  { "", 0, {0, {{{0, 0}}}}, 0, 0 },
  { "h", 1, {0, {{{0, 0}}}}, 0, 0 },
  { "b", 2, {0, {{{0, 0}}}}, 0, 0 },
  { "sh", 3, {0, {{{0, 0}}}}, 0, 0 }
};

CGEN_KEYWORD vc4_cgen_opval_h_accsz =
{
  & vc4_cgen_opval_h_accsz_entries[0],
  4,
  0, 0, 0, 0, ""
};


/* The hardware table.  */

#define A(a) (1 << CGEN_HW_##a)

const CGEN_HW_ENTRY vc4_cgen_hw_table[] =
{
  { "h-memory", HW_H_MEMORY, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-sint", HW_H_SINT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-uint", HW_H_UINT, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-addr", HW_H_ADDR, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-iaddr", HW_H_IADDR, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-reg", HW_H_REG, CGEN_ASM_KEYWORD, (PTR) & vc4_cgen_opval_h_reg, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-fastreg", HW_H_FASTREG, CGEN_ASM_KEYWORD, (PTR) & vc4_cgen_opval_h_fastreg, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-ppreg", HW_H_PPREG, CGEN_ASM_KEYWORD, (PTR) & vc4_cgen_opval_h_ppreg, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-basereg", HW_H_BASEREG, CGEN_ASM_KEYWORD, (PTR) & vc4_cgen_opval_h_basereg, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-cond", HW_H_COND, CGEN_ASM_KEYWORD, (PTR) & vc4_cgen_opval_h_cond, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-accsz", HW_H_ACCSZ, CGEN_ASM_KEYWORD, (PTR) & vc4_cgen_opval_h_accsz, { 0, { { { (1<<MACH_BASE), 0 } } } } },
  { "h-pc", HW_H_PC, CGEN_ASM_NONE, 0, { 0|A(PC), { { { (1<<MACH_BASE), 0 } } } } },
  { 0, 0, CGEN_ASM_NONE, 0, { 0, { { { (1<<MACH_BASE), 0 } } } } }
};

#undef A


/* The instruction field table.  */

#define A(a) (1 << CGEN_IFLD_##a)

const CGEN_IFLD vc4_cgen_ifld_table[] =
{
  { VC4_F_NIL, "f-nil", 0, 0, 0, 0, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_ANYOF, "f-anyof", 0, 0, 0, 0, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OPLEN, "f-oplen", 0, 16, 15, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP15_13, "f-op15-13", 0, 16, 15, 3, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP15_11, "f-op15-11", 0, 16, 15, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP11_8, "f-op11-8", 0, 16, 11, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_LDSTOFF, "f-ldstoff", 0, 16, 11, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP11_9, "f-op11-9", 0, 16, 11, 3, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP11_10, "f-op11-10", 0, 16, 11, 2, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP11, "f-op11", 0, 16, 11, 1, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP10_9, "f-op10-9", 0, 16, 10, 2, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP10_7, "f-op10-7", 0, 16, 10, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_ADDSPOFFSET, "f-addspoffset", 0, 16, 10, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP10_0, "f-op10-0", 0, 16, 10, 11, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_ALU16OP, "f-alu16op", 0, 16, 12, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_ALU16OPI, "f-alu16opi", 0, 16, 12, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP9_8, "f-op9-8", 0, 16, 9, 2, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP9_5, "f-op9-5", 0, 16, 9, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_SPOFFSET, "f-spoffset", 0, 16, 8, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP8_5, "f-op8-5", 0, 16, 8, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP8_4, "f-op8-4", 0, 16, 8, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP8_4_SHL3, "f-op8-4-shl3", 0, 16, 8, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP8, "f-op8", 0, 16, 8, 1, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP7_4, "f-op7-4", 0, 16, 7, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP7_4S, "f-op7-4s", 0, 16, 7, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP7_5, "f-op7-5", 0, 16, 7, 3, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP7_6, "f-op7-6", 0, 16, 7, 2, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP7, "f-op7", 0, 16, 7, 1, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP6_5, "f-op6-5", 0, 16, 6, 2, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP6_0, "f-op6-0", 0, 16, 6, 7, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_PCRELCC, "f-pcrelcc", 0, 16, 6, 7, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP5, "f-op5", 0, 16, 5, 1, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP5_0, "f-op5-0", 0, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP4, "f-op4", 0, 16, 4, 1, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP4_0, "f-op4-0", 0, 16, 4, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP3_0, "f-op3-0", 0, 16, 3, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP4_0_BASE_0, "f-op4-0-base-0", 0, 16, 4, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP4_0_BASE_6, "f-op4-0-base-6", 0, 16, 4, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP4_0_BASE_16, "f-op4-0-base-16", 0, 16, 4, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP4_0_BASE_24, "f-op4-0-base-24", 0, 16, 4, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP31_30, "f-op31-30", 16, 16, 15, 2, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP31_27, "f-op31-27", 16, 16, 15, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP31_16, "f-op31-16", 16, 16, 15, 16, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP31_16S, "f-op31-16s", 16, 16, 15, 16, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP31_16S_SHL1, "f-op31-16s-shl1", 16, 16, 15, 16, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP31_16S_SHL2, "f-op31-16s-shl2", 16, 16, 15, 16, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP31_16S_SHL3, "f-op31-16s-shl3", 16, 16, 15, 16, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP31_16S_SHL4, "f-op31-16s-shl4", 16, 16, 15, 16, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_PCREL16, "f-pcrel16", 16, 16, 15, 16, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP29_26, "f-op29-26", 16, 16, 13, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP29_24, "f-op29-24", 16, 16, 13, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP26_23, "f-op26-23", 16, 16, 10, 4, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP26_16, "f-op26-16", 16, 16, 10, 11, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_PCREL10, "f-pcrel10", 16, 16, 9, 10, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_PCREL8, "f-pcrel8", 16, 16, 7, 8, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP22_21, "f-op22-21", 16, 16, 6, 2, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP22, "f-op22", 16, 16, 6, 1, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16, "f-op21-16", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S, "f-op21-16s", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S_SHL1, "f-op21-16s-shl1", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S_SHL2, "f-op21-16s-shl2", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S_SHL3, "f-op21-16s-shl3", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S_SHL4, "f-op21-16s-shl4", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S_SHL5, "f-op21-16s-shl5", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S_SHL6, "f-op21-16s-shl6", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S_SHL7, "f-op21-16s-shl7", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP21_16S_SHL8, "f-op21-16s-shl8", 16, 16, 5, 6, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP20_16, "f-op20-16", 16, 16, 4, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP47_16, "f-op47-16", 16, 32, 31, 32, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_PCREL32_48, "f-pcrel32-48", 16, 32, 31, 32, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP47_43, "f-op47-43", 16, 32, 31, 5, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OFFSET27_48, "f-offset27-48", 16, 32, 26, 27, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_PCREL27_48, "f-pcrel27-48", 16, 32, 26, 27, { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OP79_48, "f-op79-48", 48, 32, 31, 32, { 0, { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OFFSET23BITS, "f-offset23bits", 0, 0, 0, 0,{ 0|A(PCREL_ADDR)|A(VIRTUAL), { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OFFSET27BITS, "f-offset27bits", 0, 0, 0, 0,{ 0|A(PCREL_ADDR)|A(VIRTUAL), { { { (1<<MACH_BASE), 0 } } } }  },
  { VC4_F_OFFSET12, "f-offset12", 0, 0, 0, 0,{ 0|A(VIRTUAL), { { { (1<<MACH_BASE), 0 } } } }  },
  { 0, 0, 0, 0, 0, 0, { 0, { { { (1<<MACH_BASE), 0 } } } } }
};

#undef A



/* multi ifield declarations */

const CGEN_MAYBE_MULTI_IFLD VC4_F_OFFSET23BITS_MULTI_IFIELD [];
const CGEN_MAYBE_MULTI_IFLD VC4_F_OFFSET27BITS_MULTI_IFIELD [];
const CGEN_MAYBE_MULTI_IFLD VC4_F_OFFSET12_MULTI_IFIELD [];


/* multi ifield definitions */

const CGEN_MAYBE_MULTI_IFLD VC4_F_OFFSET23BITS_MULTI_IFIELD [] =
{
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP6_0] } },
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP31_16] } },
    { 0, { (const PTR) 0 } }
};
const CGEN_MAYBE_MULTI_IFLD VC4_F_OFFSET27BITS_MULTI_IFIELD [] =
{
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP11_8] } },
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP6_0] } },
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP31_16] } },
    { 0, { (const PTR) 0 } }
};
const CGEN_MAYBE_MULTI_IFLD VC4_F_OFFSET12_MULTI_IFIELD [] =
{
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP8] } },
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP26_16] } },
    { 0, { (const PTR) 0 } }
};

/* The operand table.  */

#define A(a) (1 << CGEN_OPERAND_##a)
#define OPERAND(op) VC4_OPERAND_##op

const CGEN_OPERAND vc4_cgen_operand_table[] =
{
/* pc: program counter */
  { "pc", VC4_OPERAND_PC, HW_H_PC, 0, 0,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_NIL] } }, 
    { 0|A(SEM_ONLY), { { { (1<<MACH_BASE), 0 } } } }  },
/* condcode:  */
  { "condcode", VC4_OPERAND_CONDCODE, HW_H_COND, 10, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP10_7] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* pcrelcc:  */
  { "pcrelcc", VC4_OPERAND_PCRELCC, HW_H_IADDR, 6, 7,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_PCRELCC] } }, 
    { 0|A(RELAX)|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
/* ldstoff:  */
  { "ldstoff", VC4_OPERAND_LDSTOFF, HW_H_UINT, 11, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_LDSTOFF] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* alu16sreg:  */
  { "alu16sreg", VC4_OPERAND_ALU16SREG, HW_H_FASTREG, 7, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP7_4] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* alu16imm:  */
  { "alu16imm", VC4_OPERAND_ALU16IMM, HW_H_UINT, 8, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP8_4] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* alu16imm_shl3: 5-bit immediate left-shifted by 3 */
  { "alu16imm_shl3", VC4_OPERAND_ALU16IMM_SHL3, HW_H_UINT, 8, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP8_4_SHL3] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* alu16dreg:  */
  { "alu16dreg", VC4_OPERAND_ALU16DREG, HW_H_FASTREG, 3, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP3_0] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* alu32dreg:  */
  { "alu32dreg", VC4_OPERAND_ALU32DREG, HW_H_REG, 4, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP4_0] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6:  */
  { "imm6", VC4_OPERAND_IMM6, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* floatimm6: 6-bit floating-point immediate */
  { "floatimm6", VC4_OPERAND_FLOATIMM6, HW_H_UINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6_shl1: 6-bit immediate left-shifted by 1 */
  { "imm6_shl1", VC4_OPERAND_IMM6_SHL1, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S_SHL1] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6_shl2: 6-bit immediate left-shifted by 2 */
  { "imm6_shl2", VC4_OPERAND_IMM6_SHL2, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S_SHL2] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6_shl3: 6-bit immediate left-shifted by 3 */
  { "imm6_shl3", VC4_OPERAND_IMM6_SHL3, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S_SHL3] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6_shl4: 6-bit immediate left-shifted by 4 */
  { "imm6_shl4", VC4_OPERAND_IMM6_SHL4, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S_SHL4] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6_shl5: 6-bit immediate left-shifted by 5 */
  { "imm6_shl5", VC4_OPERAND_IMM6_SHL5, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S_SHL5] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6_shl6: 6-bit immediate left-shifted by 6 */
  { "imm6_shl6", VC4_OPERAND_IMM6_SHL6, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S_SHL6] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6_shl7: 6-bit immediate left-shifted by 7 */
  { "imm6_shl7", VC4_OPERAND_IMM6_SHL7, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S_SHL7] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* imm6_shl8: 6-bit immediate left-shifted by 8 */
  { "imm6_shl8", VC4_OPERAND_IMM6_SHL8, HW_H_SINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP21_16S_SHL8] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* alu32breg:  */
  { "alu32breg", VC4_OPERAND_ALU32BREG, HW_H_REG, 4, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP20_16] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* ppstartreg:  */
  { "ppstartreg", VC4_OPERAND_PPSTARTREG, HW_H_PPREG, 6, 2,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP6_5] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* ppendreg0:  */
  { "ppendreg0", VC4_OPERAND_PPENDREG0, HW_H_REG, 4, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP4_0_BASE_0] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* ppendreg6:  */
  { "ppendreg6", VC4_OPERAND_PPENDREG6, HW_H_REG, 4, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP4_0_BASE_6] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* ppendreg16:  */
  { "ppendreg16", VC4_OPERAND_PPENDREG16, HW_H_REG, 4, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP4_0_BASE_16] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* ppendreg24:  */
  { "ppendreg24", VC4_OPERAND_PPENDREG24, HW_H_REG, 4, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP4_0_BASE_24] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* swi_imm:  */
  { "swi_imm", VC4_OPERAND_SWI_IMM, HW_H_UINT, 5, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP5_0] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* spoffset:  */
  { "spoffset", VC4_OPERAND_SPOFFSET, HW_H_UINT, 8, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_SPOFFSET] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* addspoffset:  */
  { "addspoffset", VC4_OPERAND_ADDSPOFFSET, HW_H_UINT, 10, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_ADDSPOFFSET] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* alu32areg:  */
  { "alu32areg", VC4_OPERAND_ALU32AREG, HW_H_REG, 15, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP31_27] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* alu32cond:  */
  { "alu32cond", VC4_OPERAND_ALU32COND, HW_H_COND, 10, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP26_23] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* alu48isreg:  */
  { "alu48isreg", VC4_OPERAND_ALU48ISREG, HW_H_REG, 9, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP9_5] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* alu48idreg:  */
  { "alu48idreg", VC4_OPERAND_ALU48IDREG, HW_H_REG, 4, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP4_0] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* mem48sreg:  */
  { "mem48sreg", VC4_OPERAND_MEM48SREG, HW_H_REG, 31, 5,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP47_43] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* alu48immu:  */
  { "alu48immu", VC4_OPERAND_ALU48IMMU, HW_H_UINT, 31, 32,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP47_16] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* alu48pcrel:  */
  { "alu48pcrel", VC4_OPERAND_ALU48PCREL, HW_H_ADDR, 31, 32,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_PCREL32_48] } }, 
    { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
/* mem48offset27:  */
  { "mem48offset27", VC4_OPERAND_MEM48OFFSET27, HW_H_SINT, 26, 27,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OFFSET27_48] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* mem48pcrel27: 27-bit pc-relative offset */
  { "mem48pcrel27", VC4_OPERAND_MEM48PCREL27, HW_H_ADDR, 26, 27,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_PCREL27_48] } }, 
    { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
/* accsz:  */
  { "accsz", VC4_OPERAND_ACCSZ, HW_H_ACCSZ, 10, 2,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP10_9] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* accsz32:  */
  { "accsz32", VC4_OPERAND_ACCSZ32, HW_H_ACCSZ, 7, 2,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP7_6] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* condcodebcc32:  */
  { "condcodebcc32", VC4_OPERAND_CONDCODEBCC32, HW_H_COND, 11, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP11_8] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* bcc32sreg:  */
  { "bcc32sreg", VC4_OPERAND_BCC32SREG, HW_H_FASTREG, 13, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP29_26] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* pcrel10bits:  */
  { "pcrel10bits", VC4_OPERAND_PCREL10BITS, HW_H_IADDR, 9, 10,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_PCREL10] } }, 
    { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
/* pcrel8bits:  */
  { "pcrel8bits", VC4_OPERAND_PCREL8BITS, HW_H_IADDR, 7, 8,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_PCREL8] } }, 
    { 0|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
/* bcc32imm:  */
  { "bcc32imm", VC4_OPERAND_BCC32IMM, HW_H_UINT, 13, 6,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP29_24] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* addcmpbareg:  */
  { "addcmpbareg", VC4_OPERAND_ADDCMPBAREG, HW_H_FASTREG, 7, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP7_4] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* addcmpbimm:  */
  { "addcmpbimm", VC4_OPERAND_ADDCMPBIMM, HW_H_SINT, 7, 4,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP7_4S] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* offset23bits:  */
  { "offset23bits", VC4_OPERAND_OFFSET23BITS, HW_H_IADDR, 6, 23,
    { 2, { (const PTR) &VC4_F_OFFSET23BITS_MULTI_IFIELD[0] } }, 
    { 0|A(RELAX)|A(PCREL_ADDR)|A(VIRTUAL), { { { (1<<MACH_BASE), 0 } } } }  },
/* offset27bits:  */
  { "offset27bits", VC4_OPERAND_OFFSET27BITS, HW_H_IADDR, 6, 27,
    { 3, { (const PTR) &VC4_F_OFFSET27BITS_MULTI_IFIELD[0] } }, 
    { 0|A(PCREL_ADDR)|A(VIRTUAL), { { { (1<<MACH_BASE), 0 } } } }  },
/* offset12: 12-bit immediate offset */
  { "offset12", VC4_OPERAND_OFFSET12, HW_H_SINT, 8, 12,
    { 2, { (const PTR) &VC4_F_OFFSET12_MULTI_IFIELD[0] } }, 
    { 0|A(VIRTUAL), { { { (1<<MACH_BASE), 0 } } } }  },
/* offset16: 16-bit immediate */
  { "offset16", VC4_OPERAND_OFFSET16, HW_H_SINT, 15, 16,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP31_16S] } }, 
    { 0|A(RELAX), { { { (1<<MACH_BASE), 0 } } } }  },
/* offset16_shl1: 16-bit immediate left-shifted by 1 */
  { "offset16_shl1", VC4_OPERAND_OFFSET16_SHL1, HW_H_SINT, 15, 16,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP31_16S_SHL1] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* offset16_shl2: 16-bit immediate left-shifted by 2 */
  { "offset16_shl2", VC4_OPERAND_OFFSET16_SHL2, HW_H_SINT, 15, 16,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP31_16S_SHL2] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* offset16_shl3: 16-bit immediate left-shifted by 3 */
  { "offset16_shl3", VC4_OPERAND_OFFSET16_SHL3, HW_H_SINT, 15, 16,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP31_16S_SHL3] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* offset16_shl4: 16-bit immediate left-shifted by 4 */
  { "offset16_shl4", VC4_OPERAND_OFFSET16_SHL4, HW_H_SINT, 15, 16,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP31_16S_SHL4] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* pcrel16:  */
  { "pcrel16", VC4_OPERAND_PCREL16, HW_H_ADDR, 15, 16,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_PCREL16] } }, 
    { 0|A(RELAX)|A(PCREL_ADDR), { { { (1<<MACH_BASE), 0 } } } }  },
/* off16basereg:  */
  { "off16basereg", VC4_OPERAND_OFF16BASEREG, HW_H_BASEREG, 9, 2,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP9_8] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* operand10_0:  */
  { "operand10_0", VC4_OPERAND_OPERAND10_0, HW_H_UINT, 10, 11,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP10_0] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* operand47_16:  */
  { "operand47_16", VC4_OPERAND_OPERAND47_16, HW_H_UINT, 31, 32,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP47_16] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* operand79_48:  */
  { "operand79_48", VC4_OPERAND_OPERAND79_48, HW_H_UINT, 31, 32,
    { 0, { (const PTR) &vc4_cgen_ifld_table[VC4_F_OP79_48] } }, 
    { 0, { { { (1<<MACH_BASE), 0 } } } }  },
/* sentinel */
  { 0, 0, 0, 0, 0,
    { 0, { (const PTR) 0 } },
    { 0, { { { (1<<MACH_BASE), 0 } } } } }
};

#undef A


/* The instruction table.  */

#define OP(field) CGEN_SYNTAX_MAKE_FIELD (OPERAND (field))
#define A(a) (1 << CGEN_INSN_##a)

static const CGEN_IBASE vc4_cgen_insn_table[MAX_INSNS] =
{
  /* Special null first entry.
     A `num' value of zero is thus invalid.
     Also, the special `invalid' insn resides here.  */
  { 0, 0, 0, 0, { 0, { { { (1<<MACH_BASE), 0 } } } } },
/* bkpt */
  {
    VC4_INSN_BKPT, "bkpt", "bkpt", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* nop */
  {
    VC4_INSN_NOP, "nop", "nop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sleep */
  {
    VC4_INSN_SLEEP, "sleep", "sleep", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* user */
  {
    VC4_INSN_USER, "user", "user", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ei */
  {
    VC4_INSN_EI, "ei", "ei", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* di */
  {
    VC4_INSN_DI, "di", "di", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* cbclr */
  {
    VC4_INSN_CBCLR, "cbclr", "cbclr", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* cbinc */
  {
    VC4_INSN_CBINC, "cbinc", "cbinc", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* cbchg */
  {
    VC4_INSN_CBCHG, "cbchg", "cbchg", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* cbdec */
  {
    VC4_INSN_CBDEC, "cbdec", "cbdec", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* rti */
  {
    VC4_INSN_RTI, "rti", "rti", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* swi $alu32dreg */
  {
    VC4_INSN_SWIREG, "swireg", "swi", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* rts */
  {
    VC4_INSN_RTS, "rts", "rts", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* b $alu32dreg */
  {
    VC4_INSN_BREG, "breg", "b", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bl $alu32dreg */
  {
    VC4_INSN_BLREG, "blreg", "bl", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* tbb $alu32dreg */
  {
    VC4_INSN_TBB, "tbb", "tbb", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* tbh $alu32dreg */
  {
    VC4_INSN_TBH, "tbh", "tbh", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mov $alu32dreg,cpuid */
  {
    VC4_INSN_MOVCPUID, "movcpuid", "mov", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* swi $swi_imm */
  {
    VC4_INSN_SWIIMM, "swiimm", "swi", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push $ppstartreg */
  {
    VC4_INSN_PUSHRN, "pushrn", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push $ppstartreg,lr */
  {
    VC4_INSN_PUSHRNLR, "pushrnlr", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push r0-$ppendreg0 */
  {
    VC4_INSN_PUSHRNRM0, "pushrnrm0", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push r6-$ppendreg6 */
  {
    VC4_INSN_PUSHRNRM6, "pushrnrm6", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push r16-$ppendreg16 */
  {
    VC4_INSN_PUSHRNRM16, "pushrnrm16", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push r24-$ppendreg24 */
  {
    VC4_INSN_PUSHRNRM24, "pushrnrm24", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push r0-$ppendreg0,lr */
  {
    VC4_INSN_PUSHRNRM0_LR, "pushrnrm0,lr", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push r6-$ppendreg6,lr */
  {
    VC4_INSN_PUSHRNRM6_LR, "pushrnrm6,lr", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push r16-$ppendreg16,lr */
  {
    VC4_INSN_PUSHRNRM16_LR, "pushrnrm16,lr", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* push r24-$ppendreg24,lr */
  {
    VC4_INSN_PUSHRNRM24_LR, "pushrnrm24,lr", "push", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop $ppstartreg */
  {
    VC4_INSN_POPRN, "poprn", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop $ppstartreg,pc */
  {
    VC4_INSN_POPRNPC, "poprnpc", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop r0-$ppendreg0 */
  {
    VC4_INSN_POPRNRM0, "poprnrm0", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop r6-$ppendreg6 */
  {
    VC4_INSN_POPRNRM6, "poprnrm6", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop r16-$ppendreg16 */
  {
    VC4_INSN_POPRNRM16, "poprnrm16", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop r24-$ppendreg24 */
  {
    VC4_INSN_POPRNRM24, "poprnrm24", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop r0-$ppendreg0,pc */
  {
    VC4_INSN_POPRNRM0_PC, "poprnrm0,pc", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop r6-$ppendreg6,pc */
  {
    VC4_INSN_POPRNRM6_PC, "poprnrm6,pc", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop r16-$ppendreg16,pc */
  {
    VC4_INSN_POPRNRM16_PC, "poprnrm16,pc", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* pop r24-$ppendreg24,pc */
  {
    VC4_INSN_POPRNRM24_PC, "poprnrm24,pc", "pop", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld$accsz $alu16dreg,($alu16sreg) */
  {
    VC4_INSN_LDIND, "ldind", "ld", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st$accsz $alu16dreg,($alu16sreg) */
  {
    VC4_INSN_STIND, "stind", "st", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld $alu16dreg,$ldstoff($alu16sreg) */
  {
    VC4_INSN_LDOFF, "ldoff", "ld", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st $alu16dreg,$ldstoff($alu16sreg) */
  {
    VC4_INSN_STOFF, "stoff", "st", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld$accsz32 $alu32dreg,$offset12($alu32areg) */
  {
    VC4_INSN_LDOFF12, "ldoff12", "ld", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st$accsz32 $alu32dreg,$offset12($alu32areg) */
  {
    VC4_INSN_STOFF12, "stoff12", "st", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld$accsz32 $alu32dreg,$offset16($off16basereg) */
  {
    VC4_INSN_LDOFF16, "ldoff16", "ld", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st$accsz32 $alu32dreg,$offset16($off16basereg) */
  {
    VC4_INSN_STOFF16, "stoff16", "st", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<2) */
  {
    VC4_INSN_LDCNDIDX, "ldcndidx", "ld", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldh${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1) */
  {
    VC4_INSN_LDCNDIDXH, "ldcndidxh", "ldh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldb${alu32cond} $alu32dreg,($alu32areg,$alu32breg) */
  {
    VC4_INSN_LDCNDIDXB, "ldcndidxb", "ldb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldsh${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1) */
  {
    VC4_INSN_LDCNDIDXSH, "ldcndidxsh", "ldsh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<2) */
  {
    VC4_INSN_STCNDIDX, "stcndidx", "st", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sth${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1) */
  {
    VC4_INSN_STCNDIDXH, "stcndidxh", "sth", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* stb${alu32cond} $alu32dreg,($alu32areg,$alu32breg) */
  {
    VC4_INSN_STCNDIDXB, "stcndidxb", "stb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* stsh${alu32cond} $alu32dreg,($alu32areg,$alu32breg<<1) */
  {
    VC4_INSN_STCNDIDXSH, "stcndidxsh", "stsh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    VC4_INSN_LDCNDDISP, "ldcnddisp", "ld", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldh${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    VC4_INSN_LDCNDDISPH, "ldcnddisph", "ldh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldb${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    VC4_INSN_LDCNDDISPB, "ldcnddispb", "ldb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldsh${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    VC4_INSN_LDCNDDISPSH, "ldcnddispsh", "ldsh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    VC4_INSN_STCNDDISP, "stcnddisp", "st", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sth${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    VC4_INSN_STCNDDISPH, "stcnddisph", "sth", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* stb${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    VC4_INSN_STCNDDISPB, "stcnddispb", "stb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* stsh${alu32cond} $alu32dreg,$imm6($alu32areg) */
  {
    VC4_INSN_STCNDDISPSH, "stcnddispsh", "stsh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld${alu32cond} $alu32dreg,--($alu32areg) */
  {
    VC4_INSN_LDPREDEC, "ldpredec", "ld", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldh${alu32cond} $alu32dreg,--($alu32areg) */
  {
    VC4_INSN_LDPREDECH, "ldpredech", "ldh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldb${alu32cond} $alu32dreg,--($alu32areg) */
  {
    VC4_INSN_LDPREDECB, "ldpredecb", "ldb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldsh${alu32cond} $alu32dreg,--($alu32areg) */
  {
    VC4_INSN_LDPREDECSH, "ldpredecsh", "ldsh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st${alu32cond} $alu32dreg,--($alu32areg) */
  {
    VC4_INSN_STPREDEC, "stpredec", "st", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sth${alu32cond} $alu32dreg,--($alu32areg) */
  {
    VC4_INSN_STPREDECH, "stpredech", "sth", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* stb${alu32cond} $alu32dreg,--($alu32areg) */
  {
    VC4_INSN_STPREDECB, "stpredecb", "stb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* stsh${alu32cond} $alu32dreg,--($alu32areg) */
  {
    VC4_INSN_STPREDECSH, "stpredecsh", "stsh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    VC4_INSN_LDPOSTINC, "ldpostinc", "ld", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldh${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    VC4_INSN_LDPOSTINCH, "ldpostinch", "ldh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldb${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    VC4_INSN_LDPOSTINCB, "ldpostincb", "ldb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ldsh${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    VC4_INSN_LDPOSTINCSH, "ldpostincsh", "ldsh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    VC4_INSN_STPOSTINC, "stpostinc", "st", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sth${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    VC4_INSN_STPOSTINCH, "stpostinch", "sth", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* stb${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    VC4_INSN_STPOSTINCB, "stpostincb", "stb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* stsh${alu32cond} $alu32dreg,($alu32areg)++ */
  {
    VC4_INSN_STPOSTINCSH, "stpostincsh", "stsh", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld $alu16dreg,$spoffset(sp) */
  {
    VC4_INSN_LDSP, "ldsp", "ld", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st $alu16dreg,$spoffset(sp) */
  {
    VC4_INSN_STSP, "stsp", "st", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add sp,#$addspoffset */
  {
    VC4_INSN_ADDSP, "addsp", "add", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* lea $alu32dreg,$addspoffset(sp) */
  {
    VC4_INSN_LEA, "lea", "lea", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* b$condcode $pcrelcc */
  {
    VC4_INSN_BCC, "bcc", "b", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mov $alu16dreg,$alu16sreg */
  {
    VC4_INSN_MOV16, "mov16", "mov", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmn $alu16dreg,$alu16sreg */
  {
    VC4_INSN_CMN16, "cmn16", "cmn", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu16dreg,$alu16sreg */
  {
    VC4_INSN_ADD16, "add16", "add", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bic $alu16dreg,$alu16sreg */
  {
    VC4_INSN_BIC16, "bic16", "bic", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mul $alu16dreg,$alu16sreg */
  {
    VC4_INSN_MUL16, "mul16", "mul", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* eor $alu16dreg,$alu16sreg */
  {
    VC4_INSN_EOR16, "eor16", "eor", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub $alu16dreg,$alu16sreg */
  {
    VC4_INSN_SUB16, "sub16", "sub", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* and $alu16dreg,$alu16sreg */
  {
    VC4_INSN_AND16, "and16", "and", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* not $alu16dreg,$alu16sreg */
  {
    VC4_INSN_NOT16, "not16", "not", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ror $alu16dreg,$alu16sreg */
  {
    VC4_INSN_ROR16, "ror16", "ror", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmp $alu16dreg,$alu16sreg */
  {
    VC4_INSN_CMP16, "cmp16", "cmp", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* rsub $alu16dreg,$alu16sreg */
  {
    VC4_INSN_RSUB16, "rsub16", "rsub", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* btst $alu16dreg,$alu16sreg */
  {
    VC4_INSN_BTST16, "btst16", "btst", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* or $alu16dreg,$alu16sreg */
  {
    VC4_INSN_OR16, "or16", "or", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bmask $alu16dreg,$alu16sreg */
  {
    VC4_INSN_BMASK16, "bmask16", "bmask", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* max $alu16dreg,$alu16sreg */
  {
    VC4_INSN_MAX16, "max16", "max", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bset $alu16dreg,$alu16sreg */
  {
    VC4_INSN_BSET16, "bset16", "bset", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* min $alu16dreg,$alu16sreg */
  {
    VC4_INSN_MIN16, "min16", "min", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bclr $alu16dreg,$alu16sreg */
  {
    VC4_INSN_BCLR16, "bclr16", "bclr", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* addscale $alu16dreg,$alu16sreg<<1 */
  {
    VC4_INSN_ADDS216, "adds216", "addscale", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bchg $alu16dreg,$alu16sreg */
  {
    VC4_INSN_BCHG16, "bchg16", "bchg", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* addscale $alu16dreg,$alu16sreg<<2 */
  {
    VC4_INSN_ADDS416, "adds416", "addscale", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* addscale $alu16dreg,$alu16sreg<<3 */
  {
    VC4_INSN_ADDS816, "adds816", "addscale", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* addscale $alu16dreg,$alu16sreg<<4 */
  {
    VC4_INSN_ADDS1616, "adds1616", "addscale", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* signext $alu16dreg,$alu16sreg */
  {
    VC4_INSN_SIGNEXT16, "signext16", "signext", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* neg $alu16dreg,$alu16sreg */
  {
    VC4_INSN_NEG16, "neg16", "neg", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* lsr $alu16dreg,$alu16sreg */
  {
    VC4_INSN_LSR16, "lsr16", "lsr", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* msb $alu16dreg,$alu16sreg */
  {
    VC4_INSN_MSB16, "msb16", "msb", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* shl $alu16dreg,$alu16sreg */
  {
    VC4_INSN_SHL16, "shl16", "shl", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bitrev $alu16dreg,$alu16sreg */
  {
    VC4_INSN_BITREV16, "bitrev16", "bitrev", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* asr $alu16dreg,$alu16sreg */
  {
    VC4_INSN_ASR16, "asr16", "asr", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* abs $alu16dreg,$alu16sreg */
  {
    VC4_INSN_ABS16, "abs16", "abs", 16,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mov $alu16dreg,#$alu16imm */
  {
    VC4_INSN_MOVI16, "movi16", "mov", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu16dreg,#$alu16imm */
  {
    VC4_INSN_ADDI16, "addi16", "add", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mul $alu16dreg,#$alu16imm */
  {
    VC4_INSN_MULI16, "muli16", "mul", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub $alu16dreg,#$alu16imm */
  {
    VC4_INSN_SUBI16, "subi16", "sub", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* not $alu16dreg,#$alu16imm */
  {
    VC4_INSN_NOTI16, "noti16", "not", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmp $alu16dreg,#$alu16imm */
  {
    VC4_INSN_CMPI16, "cmpi16", "cmp", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* btst $alu16dreg,#$alu16imm */
  {
    VC4_INSN_BTSTI16, "btsti16", "btst", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bmask $alu16dreg,#$alu16imm */
  {
    VC4_INSN_BMASKI16, "bmaski16", "bmask", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bset $alu16dreg,#$alu16imm */
  {
    VC4_INSN_BSETI16, "bseti16", "bset", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bclr $alu16dreg,#$alu16imm */
  {
    VC4_INSN_BCLRI16, "bclri16", "bclr", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bchg $alu16dreg,#$alu16imm */
  {
    VC4_INSN_BCHGI16, "bchgi16", "bchg", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* addscale $alu16dreg,#$alu16imm_shl3 */
  {
    VC4_INSN_ADDS8I16, "adds8i16", "addscale", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* signext $alu16dreg,#$alu16imm */
  {
    VC4_INSN_SIGNEXTI16, "signexti16", "signext", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* lsr $alu16dreg,#$alu16imm */
  {
    VC4_INSN_LSRI16, "lsri16", "lsr", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* shl $alu16dreg,#$alu16imm */
  {
    VC4_INSN_SHLI16, "shli16", "shl", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* asr $alu16dreg,#$alu16imm */
  {
    VC4_INSN_ASRI16, "asri16", "asr", 16,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* b$condcodebcc32 $alu16dreg,$bcc32sreg,$pcrel10bits */
  {
    VC4_INSN_BCC32R, "bcc32r", "b", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* b$condcodebcc32 $alu16dreg,#$bcc32imm,$pcrel8bits */
  {
    VC4_INSN_BCC32I, "bcc32i", "b", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* addcmpb$condcodebcc32 $alu16dreg,$addcmpbareg,$bcc32sreg,$pcrel10bits */
  {
    VC4_INSN_ADDCMPBRR, "addcmpbrr", "addcmpb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* addcmpb$condcodebcc32 $alu16dreg,#$addcmpbimm,$bcc32sreg,$pcrel10bits */
  {
    VC4_INSN_ADDCMPBRI, "addcmpbri", "addcmpb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* addcmpb$condcodebcc32 $alu16dreg,$addcmpbareg,#$bcc32imm,$pcrel8bits */
  {
    VC4_INSN_ADDCMPBIR, "addcmpbir", "addcmpb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* addcmpb$condcodebcc32 $alu16dreg,#$addcmpbimm,#$bcc32imm,$pcrel8bits */
  {
    VC4_INSN_ADDCMPBII, "addcmpbii", "addcmpb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* b$condcodebcc32 $offset23bits */
  {
    VC4_INSN_BCC32, "bcc32", "b", 32,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bl $offset27bits */
  {
    VC4_INSN_BL32, "bl32", "bl", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mov${alu32cond} $alu32dreg,$alu32breg */
  {
    VC4_INSN_MOV32, "mov32", "mov", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmn${alu32cond} $alu32areg,$alu32breg */
  {
    VC4_INSN_CMN32, "cmn32", "cmn", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_ADD32, "add32", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bic${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_BIC32, "bic32", "bic", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mul${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_MUL32, "mul32", "mul", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* eor${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_EOR32, "eor32", "eor", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_SUB32, "sub32", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* and${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_AND32, "and32", "and", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* not${alu32cond} $alu32dreg,$alu32breg */
  {
    VC4_INSN_NOT32, "not32", "not", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ror${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_ROR32, "ror32", "ror", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmp${alu32cond} $alu32areg,$alu32breg */
  {
    VC4_INSN_CMP32, "cmp32", "cmp", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* rsub${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_RSUB32, "rsub32", "rsub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* btst${alu32cond} $alu32areg,$alu32breg */
  {
    VC4_INSN_BTST32, "btst32", "btst", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* or${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_OR32, "or32", "or", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bmask${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_BMASK32, "bmask32", "bmask", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* max${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_MAX32, "max32", "max", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bset${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_BSET32, "bset32", "bset", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* min${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_MIN32, "min32", "min", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bclr${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_BCLR32, "bclr32", "bclr", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg<<1 */
  {
    VC4_INSN_ADDS232, "adds232", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bchg${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_BCHG32, "bchg32", "bchg", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg<<2 */
  {
    VC4_INSN_ADDS432, "adds432", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg<<3 */
  {
    VC4_INSN_ADDS832, "adds832", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,$alu32breg<<4 */
  {
    VC4_INSN_ADDS1632, "adds1632", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* signext${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_SIGNEXT32, "signext32", "signext", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* neg${alu32cond} $alu32dreg,$alu32breg */
  {
    VC4_INSN_NEG32, "neg32", "neg", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* lsr${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_LSR32, "lsr32", "lsr", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* msb${alu32cond} $alu32dreg,$alu32breg */
  {
    VC4_INSN_MSB32, "msb32", "msb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* shl${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_SHL32, "shl32", "shl", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* bitrev${alu32cond} $alu32dreg,$alu32breg */
  {
    VC4_INSN_BITREV32, "bitrev32", "bitrev", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* asr${alu32cond} $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_ASR32, "asr32", "asr", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* abs${alu32cond} $alu32dreg,$alu32breg */
  {
    VC4_INSN_ABS32, "abs32", "abs", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mov${alu32cond} $alu32dreg,#$imm6 */
  {
    VC4_INSN_MOVI32, "movi32", "mov", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmn${alu32cond} $alu32areg,#$imm6 */
  {
    VC4_INSN_CMNI32, "cmni32", "cmn", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_ADDI32, "addi32", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bic${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_BICI32, "bici32", "bic", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mul${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_MULI32, "muli32", "mul", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* eor${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_EORI32, "eori32", "eor", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_SUBI32, "subi32", "sub", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* and${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_ANDI32, "andi32", "and", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* not${alu32cond} $alu32dreg,#$imm6 */
  {
    VC4_INSN_NOTI32, "noti32", "not", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* ror${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_RORI32, "rori32", "ror", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmp${alu32cond} $alu32areg,#$imm6 */
  {
    VC4_INSN_CMPI32, "cmpi32", "cmp", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* rsub${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_RSUBI32, "rsubi32", "rsub", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* btst${alu32cond} $alu32areg,#$imm6 */
  {
    VC4_INSN_BTSTI32, "btsti32", "btst", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* or${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_ORI32, "ori32", "or", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bmask${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_BMASKI32, "bmaski32", "bmask", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* max${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_MAXI32, "maxi32", "max", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bset${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_BSETI32, "bseti32", "bset", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* min${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_MINI32, "mini32", "min", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bclr${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_BCLRI32, "bclri32", "bclr", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6_shl1 */
  {
    VC4_INSN_ADDS2I32, "adds2i32", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bchg${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_BCHGI32, "bchgi32", "bchg", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6_shl2 */
  {
    VC4_INSN_ADDS4I32, "adds4i32", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6_shl3 */
  {
    VC4_INSN_ADDS8I32, "adds8i32", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add${alu32cond} $alu32dreg,$alu32areg,#$imm6_shl4 */
  {
    VC4_INSN_ADDS16I32, "adds16i32", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* signext${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_SIGNEXTI32, "signexti32", "signext", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* neg${alu32cond} $alu32dreg,#$imm6 */
  {
    VC4_INSN_NEGI32, "negi32", "neg", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* lsr${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_LSRI32, "lsri32", "lsr", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* msb${alu32cond} $alu32dreg,#$imm6 */
  {
    VC4_INSN_MSBI32, "msbi32", "msb", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* shl${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_SHLI32, "shli32", "shl", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bitrev${alu32cond} $alu32dreg,#$imm6 */
  {
    VC4_INSN_BITREVI32, "bitrevi32", "bitrev", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* asr${alu32cond} $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_ASRI32, "asri32", "asr", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* abs${alu32cond} $alu32dreg,#$imm6 */
  {
    VC4_INSN_ABSI32, "absi32", "abs", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mulhd$alu32cond.ss $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_MULHDRSS, "mulhdrss", "mulhd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mulhd$alu32cond.su $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_MULHDRSU, "mulhdrsu", "mulhd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mulhd$alu32cond.us $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_MULHDRUS, "mulhdrus", "mulhd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mulhd$alu32cond.uu $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_MULHDRUU, "mulhdruu", "mulhd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* div$alu32cond.ss $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_DIVRSS, "divrss", "div", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* div$alu32cond.su $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_DIVRSU, "divrsu", "div", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* div$alu32cond.us $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_DIVRUS, "divrus", "div", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* div$alu32cond.uu $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_DIVRUU, "divruu", "div", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mulhd$alu32cond.ss $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_MULHDISS, "mulhdiss", "mulhd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mulhd$alu32cond.su $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_MULHDISU, "mulhdisu", "mulhd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mulhd$alu32cond.us $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_MULHDIUS, "mulhdius", "mulhd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* mulhd$alu32cond.uu $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_MULHDIUU, "mulhdiuu", "mulhd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* div$alu32cond.ss $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_DIVISS, "diviss", "div", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* div$alu32cond.su $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_DIVISU, "divisu", "div", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* div$alu32cond.us $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_DIVIUS, "divius", "div", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* div$alu32cond.uu $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_DIVIUU, "diviuu", "div", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* adds$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_ADDSATR, "addsatr", "adds", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* subs$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_SUBSATR, "subsatr", "subs", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* shls$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_SHLSATR, "shlsatr", "shls", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,$alu32breg<<5 */
  {
    VC4_INSN_ADDS5R, "adds5r", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,$alu32breg<<6 */
  {
    VC4_INSN_ADDS6R, "adds6r", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,$alu32breg<<7 */
  {
    VC4_INSN_ADDS7R, "adds7r", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,$alu32breg<<8 */
  {
    VC4_INSN_ADDS8R, "adds8r", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<1 */
  {
    VC4_INSN_SUBS1R, "subs1r", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<2 */
  {
    VC4_INSN_SUBS2R, "subs2r", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<3 */
  {
    VC4_INSN_SUBS3R, "subs3r", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<4 */
  {
    VC4_INSN_SUBS4R, "subs4r", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<5 */
  {
    VC4_INSN_SUBS5R, "subs5r", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<6 */
  {
    VC4_INSN_SUBS6R, "subs6r", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<7 */
  {
    VC4_INSN_SUBS7R, "subs7r", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,$alu32breg<<8 */
  {
    VC4_INSN_SUBS8R, "subs8r", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* clamp16$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_CLAMP16R, "clamp16r", "clamp16", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* count$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_COUNTR, "countr", "count", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* adds$alu32cond $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_ADDSATI, "addsati", "adds", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* subs$alu32cond $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_SUBSATI, "subsati", "subs", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* shls$alu32cond $alu32dreg,$alu32areg,#$imm6 */
  {
    VC4_INSN_SHLSATI, "shlsati", "shls", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,#$imm6_shl5 */
  {
    VC4_INSN_ADDS5I, "adds5i", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,#$imm6_shl6 */
  {
    VC4_INSN_ADDS6I, "adds6i", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,#$imm6_shl7 */
  {
    VC4_INSN_ADDS7I, "adds7i", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add$alu32cond $alu32dreg,$alu32areg,#$imm6_shl8 */
  {
    VC4_INSN_ADDS8I, "adds8i", "add", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl1 */
  {
    VC4_INSN_SUBS1I, "subs1i", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl2 */
  {
    VC4_INSN_SUBS2I, "subs2i", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl3 */
  {
    VC4_INSN_SUBS3I, "subs3i", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl4 */
  {
    VC4_INSN_SUBS4I, "subs4i", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl5 */
  {
    VC4_INSN_SUBS5I, "subs5i", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl6 */
  {
    VC4_INSN_SUBS6I, "subs6i", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl7 */
  {
    VC4_INSN_SUBS7I, "subs7i", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub$alu32cond $alu32dreg,$alu32areg,#$imm6_shl8 */
  {
    VC4_INSN_SUBS8I, "subs8i", "sub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* clamp16$alu32cond $alu32dreg,#$imm6 */
  {
    VC4_INSN_CLAMP16I, "clamp16i", "clamp16", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* count$alu32cond $alu32dreg,#$imm6 */
  {
    VC4_INSN_COUNTI, "counti", "count", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* lea $alu48idreg,$offset16($alu48isreg) */
  {
    VC4_INSN_LEA32R, "lea32r", "lea", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* lea $alu48idreg,$pcrel16 */
  {
    VC4_INSN_LEA32PC, "lea32pc", "lea", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mov $alu48idreg,#$offset16 */
  {
    VC4_INSN_MOVIU32, "moviu32", "mov", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmn $alu48idreg,#$offset16 */
  {
    VC4_INSN_CMNIU32, "cmniu32", "cmn", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,#$offset16 */
  {
    VC4_INSN_ADDIU32, "addiu32", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bic $alu48idreg,#$offset16 */
  {
    VC4_INSN_BICIU32, "biciu32", "bic", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mul $alu48idreg,#$offset16 */
  {
    VC4_INSN_MULIU32, "muliu32", "mul", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* eor $alu48idreg,#$offset16 */
  {
    VC4_INSN_EORIU32, "eoriu32", "eor", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub $alu48idreg,#$offset16 */
  {
    VC4_INSN_SUBIU32, "subiu32", "sub", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* and $alu48idreg,#$offset16 */
  {
    VC4_INSN_ANDIU32, "andiu32", "and", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* not $alu48idreg,#$offset16 */
  {
    VC4_INSN_NOTIU32, "notiu32", "not", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* ror $alu48idreg,#$offset16 */
  {
    VC4_INSN_RORIU32, "roriu32", "ror", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmp $alu48idreg,#$offset16 */
  {
    VC4_INSN_CMPIU32, "cmpiu32", "cmp", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* rsub $alu48idreg,#$offset16 */
  {
    VC4_INSN_RSUBIU32, "rsubiu32", "rsub", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* btst $alu48idreg,#$offset16 */
  {
    VC4_INSN_BTSTIU32, "btstiu32", "btst", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* or $alu48idreg,#$offset16 */
  {
    VC4_INSN_ORIU32, "oriu32", "or", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bmask $alu48idreg,#$offset16 */
  {
    VC4_INSN_BMASKIU32, "bmaskiu32", "bmask", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* max $alu48idreg,#$offset16 */
  {
    VC4_INSN_MAXIU32, "maxiu32", "max", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bset $alu48idreg,#$offset16 */
  {
    VC4_INSN_BSETIU32, "bsetiu32", "bset", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* min $alu48idreg,#$offset16 */
  {
    VC4_INSN_MINIU32, "miniu32", "min", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bclr $alu48idreg,#$offset16 */
  {
    VC4_INSN_BCLRIU32, "bclriu32", "bclr", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,#$offset16 */
  {
    VC4_INSN_ADDS2IU32_SHL1, "adds2iu32_shl1", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bchg $alu48idreg,#$offset16 */
  {
    VC4_INSN_BCHGIU32, "bchgiu32", "bchg", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,#$offset16 */
  {
    VC4_INSN_ADDS4IU32_SHL2, "adds4iu32_shl2", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,#$offset16 */
  {
    VC4_INSN_ADDS8IU32_SHL3, "adds8iu32_shl3", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,#$offset16 */
  {
    VC4_INSN_ADDS16IU32_SHL4, "adds16iu32_shl4", "add", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* signext $alu48idreg,#$offset16 */
  {
    VC4_INSN_SIGNEXTIU32, "signextiu32", "signext", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* neg $alu48idreg,#$offset16 */
  {
    VC4_INSN_NEGIU32, "negiu32", "neg", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* lsr $alu48idreg,#$offset16 */
  {
    VC4_INSN_LSRIU32, "lsriu32", "lsr", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* msb $alu48idreg,#$offset16 */
  {
    VC4_INSN_MSBIU32, "msbiu32", "msb", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* shl $alu48idreg,#$offset16 */
  {
    VC4_INSN_SHLIU32, "shliu32", "shl", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bitrev $alu48idreg,#$offset16 */
  {
    VC4_INSN_BITREVIU32, "bitreviu32", "bitrev", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* asr $alu48idreg,#$offset16 */
  {
    VC4_INSN_ASRIU32, "asriu32", "asr", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* abs $alu48idreg,#$offset16 */
  {
    VC4_INSN_ABSIU32, "absiu32", "abs", 32,
    { 0|A(RELAXABLE), { { { (1<<MACH_BASE), 0 } } } }
  },
/* fadd$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_FADDR, "faddr", "fadd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fsub$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_FSUBR, "fsubr", "fsub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fmul$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_FMULR, "fmulr", "fmul", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fdiv$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_FDIVR, "fdivr", "fdiv", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fcmp$alu32cond $alu32areg,$alu32breg */
  {
    VC4_INSN_FCMPR, "fcmpr", "fcmp", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fabs$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_FABSR, "fabsr", "fabs", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* frsb$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_FRSBR, "frsbr", "frsb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fmax$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_FMAXR, "fmaxr", "fmax", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* frcp$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_FRCPR, "frcpr", "frcp", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* frsqrt$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_FRSQRTR, "frsqrtr", "frsqrt", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fnmul$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_FNMULR, "fnmulr", "fnmul", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fmin$alu32cond $alu32dreg,$alu32areg,$alu32breg */
  {
    VC4_INSN_FMINR, "fminr", "fmin", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fceil$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_FCEILR, "fceilr", "fceil", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ffloor$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_FFLOORR, "ffloorr", "ffloor", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* flog2$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_FLOG2R, "flog2r", "flog2", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fexp2$alu32cond $alu32dreg,$alu32breg */
  {
    VC4_INSN_FEXP2R, "fexp2r", "fexp2", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fadd$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    VC4_INSN_FADDI, "faddi", "fadd", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fsub$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    VC4_INSN_FSUBI, "fsubi", "fsub", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fmul$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    VC4_INSN_FMULI, "fmuli", "fmul", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fdiv$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    VC4_INSN_FDIVI, "fdivi", "fdiv", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fcmp$alu32cond $alu32areg,#$floatimm6 */
  {
    VC4_INSN_FCMPI, "fcmpi", "fcmp", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fabs$alu32cond $alu32dreg,#$floatimm6 */
  {
    VC4_INSN_FABSI, "fabsi", "fabs", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* frsb$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    VC4_INSN_FRSBI, "frsbi", "frsb", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fmax$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    VC4_INSN_FMAXI, "fmaxi", "fmax", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* frcp$alu32cond $alu32dreg,#$floatimm6 */
  {
    VC4_INSN_FRCPI, "frcpi", "frcp", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* frsqrt$alu32cond $alu32dreg,#$floatimm6 */
  {
    VC4_INSN_FRSQRTI, "frsqrti", "frsqrt", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fnmul$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    VC4_INSN_FNMULI, "fnmuli", "fnmul", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fmin$alu32cond $alu32dreg,$alu32areg,#$floatimm6 */
  {
    VC4_INSN_FMINI, "fmini", "fmin", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fceil$alu32cond $alu32dreg,#$floatimm6 */
  {
    VC4_INSN_FCEILI, "fceili", "fceil", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ffloor$alu32cond $alu32dreg,#$floatimm6 */
  {
    VC4_INSN_FFLOORI, "ffloori", "ffloor", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* flog2$alu32cond $alu32dreg,#$floatimm6 */
  {
    VC4_INSN_FLOG2I, "flog2i", "flog2", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fexp2$alu32cond $alu32dreg,#$floatimm6 */
  {
    VC4_INSN_FEXP2I, "fexp2i", "fexp2", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ftrunc$alu32cond $alu32dreg,$alu32areg,sasl $alu32breg */
  {
    VC4_INSN_FTRUNCR, "ftruncr", "ftrunc", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* floor$alu32cond $alu32dreg,$alu32areg,sasl $alu32breg */
  {
    VC4_INSN_FLOORR, "floorr", "floor", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* flts$alu32cond $alu32dreg,$alu32areg,sasr $alu32breg */
  {
    VC4_INSN_FLTSR, "fltsr", "flts", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fltu$alu32cond $alu32dreg,$alu32areg,sasr $alu32breg */
  {
    VC4_INSN_FLTUR, "fltur", "fltu", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ftrunc$alu32cond $alu32dreg,$alu32areg,sasl#$imm6 */
  {
    VC4_INSN_FTRUNCI, "ftrunci", "ftrunc", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* floor$alu32cond $alu32dreg,$alu32areg,sasl#$imm6 */
  {
    VC4_INSN_FLOORI, "floori", "floor", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* flts$alu32cond $alu32dreg,$alu32areg,sasr#$imm6 */
  {
    VC4_INSN_FLTSI, "fltsi", "flts", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* fltu$alu32cond $alu32dreg,$alu32areg,sasr#$imm6 */
  {
    VC4_INSN_FLTUI, "fltui", "fltu", 32,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* lea $alu48idreg,$alu48pcrel */
  {
    VC4_INSN_LEA48, "lea48", "lea", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld$accsz32 $alu48idreg,$mem48pcrel27 */
  {
    VC4_INSN_LDPCREL27, "ldpcrel27", "ld", 48,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st$accsz32 $alu48idreg,$mem48pcrel27 */
  {
    VC4_INSN_STPCREL27, "stpcrel27", "st", 48,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* ld$accsz32 $alu48idreg,$mem48offset27($mem48sreg) */
  {
    VC4_INSN_LDOFF27, "ldoff27", "ld", 48,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* st$accsz32 $alu48idreg,$mem48offset27($mem48sreg) */
  {
    VC4_INSN_STOFF27, "stoff27", "st", 48,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,$alu48isreg,#$alu48immu */
  {
    VC4_INSN_ADD48I, "add48i", "add", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mov $alu48idreg,#$alu48immu */
  {
    VC4_INSN_MOVI48, "movi48", "mov", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmn $alu48idreg,#$alu48immu */
  {
    VC4_INSN_CMNI48, "cmni48", "cmn", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* add $alu48idreg,#$alu48immu */
  {
    VC4_INSN_ADDI48, "addi48", "add", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* bic $alu48idreg,#$alu48immu */
  {
    VC4_INSN_BICI48, "bici48", "bic", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* mul $alu48idreg,#$alu48immu */
  {
    VC4_INSN_MULI48, "muli48", "mul", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* eor $alu48idreg,#$alu48immu */
  {
    VC4_INSN_EORI48, "eori48", "eor", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* sub $alu48idreg,#$alu48immu */
  {
    VC4_INSN_SUBI48, "subi48", "sub", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* and $alu48idreg,#$alu48immu */
  {
    VC4_INSN_ANDI48, "andi48", "and", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* cmp $alu48idreg,#$alu48immu */
  {
    VC4_INSN_CMPI48, "cmpi48", "cmp", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* rsub $alu48idreg,#$alu48immu */
  {
    VC4_INSN_RSUBI48, "rsubi48", "rsub", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* or $alu48idreg,#$alu48immu */
  {
    VC4_INSN_ORI48, "ori48", "or", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* max $alu48idreg,#$alu48immu */
  {
    VC4_INSN_MAXI48, "maxi48", "max", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* min $alu48idreg,#$alu48immu */
  {
    VC4_INSN_MINI48, "mini48", "min", 48,
    { 0|A(RELAXED), { { { (1<<MACH_BASE), 0 } } } }
  },
/* vec48 $operand10_0,$operand47_16 */
  {
    VC4_INSN_VEC48, "vec48", "vec48", 48,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
/* vec80 $operand10_0,$operand47_16,$operand79_48 */
  {
    VC4_INSN_VEC80, "vec80", "vec80", 80,
    { 0, { { { (1<<MACH_BASE), 0 } } } }
  },
};

#undef OP
#undef A

/* Initialize anything needed to be done once, before any cpu_open call.  */

static void
init_tables (void)
{
}

static const CGEN_MACH * lookup_mach_via_bfd_name (const CGEN_MACH *, const char *);
static void build_hw_table      (CGEN_CPU_TABLE *);
static void build_ifield_table  (CGEN_CPU_TABLE *);
static void build_operand_table (CGEN_CPU_TABLE *);
static void build_insn_table    (CGEN_CPU_TABLE *);
static void vc4_cgen_rebuild_tables (CGEN_CPU_TABLE *);

/* Subroutine of vc4_cgen_cpu_open to look up a mach via its bfd name.  */

static const CGEN_MACH *
lookup_mach_via_bfd_name (const CGEN_MACH *table, const char *name)
{
  while (table->name)
    {
      if (strcmp (name, table->bfd_name) == 0)
	return table;
      ++table;
    }
  abort ();
}

/* Subroutine of vc4_cgen_cpu_open to build the hardware table.  */

static void
build_hw_table (CGEN_CPU_TABLE *cd)
{
  int i;
  int machs = cd->machs;
  const CGEN_HW_ENTRY *init = & vc4_cgen_hw_table[0];
  /* MAX_HW is only an upper bound on the number of selected entries.
     However each entry is indexed by it's enum so there can be holes in
     the table.  */
  const CGEN_HW_ENTRY **selected =
    (const CGEN_HW_ENTRY **) xmalloc (MAX_HW * sizeof (CGEN_HW_ENTRY *));

  cd->hw_table.init_entries = init;
  cd->hw_table.entry_size = sizeof (CGEN_HW_ENTRY);
  memset (selected, 0, MAX_HW * sizeof (CGEN_HW_ENTRY *));
  /* ??? For now we just use machs to determine which ones we want.  */
  for (i = 0; init[i].name != NULL; ++i)
    if (CGEN_HW_ATTR_VALUE (&init[i], CGEN_HW_MACH)
	& machs)
      selected[init[i].type] = &init[i];
  cd->hw_table.entries = selected;
  cd->hw_table.num_entries = MAX_HW;
}

/* Subroutine of vc4_cgen_cpu_open to build the hardware table.  */

static void
build_ifield_table (CGEN_CPU_TABLE *cd)
{
  cd->ifld_table = & vc4_cgen_ifld_table[0];
}

/* Subroutine of vc4_cgen_cpu_open to build the hardware table.  */

static void
build_operand_table (CGEN_CPU_TABLE *cd)
{
  int i;
  int machs = cd->machs;
  const CGEN_OPERAND *init = & vc4_cgen_operand_table[0];
  /* MAX_OPERANDS is only an upper bound on the number of selected entries.
     However each entry is indexed by it's enum so there can be holes in
     the table.  */
  const CGEN_OPERAND **selected = xmalloc (MAX_OPERANDS * sizeof (* selected));

  cd->operand_table.init_entries = init;
  cd->operand_table.entry_size = sizeof (CGEN_OPERAND);
  memset (selected, 0, MAX_OPERANDS * sizeof (CGEN_OPERAND *));
  /* ??? For now we just use mach to determine which ones we want.  */
  for (i = 0; init[i].name != NULL; ++i)
    if (CGEN_OPERAND_ATTR_VALUE (&init[i], CGEN_OPERAND_MACH)
	& machs)
      selected[init[i].type] = &init[i];
  cd->operand_table.entries = selected;
  cd->operand_table.num_entries = MAX_OPERANDS;
}

/* Subroutine of vc4_cgen_cpu_open to build the hardware table.
   ??? This could leave out insns not supported by the specified mach/isa,
   but that would cause errors like "foo only supported by bar" to become
   "unknown insn", so for now we include all insns and require the app to
   do the checking later.
   ??? On the other hand, parsing of such insns may require their hardware or
   operand elements to be in the table [which they mightn't be].  */

static void
build_insn_table (CGEN_CPU_TABLE *cd)
{
  int i;
  const CGEN_IBASE *ib = & vc4_cgen_insn_table[0];
  CGEN_INSN *insns = xmalloc (MAX_INSNS * sizeof (CGEN_INSN));

  memset (insns, 0, MAX_INSNS * sizeof (CGEN_INSN));
  for (i = 0; i < MAX_INSNS; ++i)
    insns[i].base = &ib[i];
  cd->insn_table.init_entries = insns;
  cd->insn_table.entry_size = sizeof (CGEN_IBASE);
  cd->insn_table.num_init_entries = MAX_INSNS;
}

/* Subroutine of vc4_cgen_cpu_open to rebuild the tables.  */

static void
vc4_cgen_rebuild_tables (CGEN_CPU_TABLE *cd)
{
  int i;
  CGEN_BITSET *isas = cd->isas;
  unsigned int machs = cd->machs;

  cd->int_insn_p = CGEN_INT_INSN_P;

  /* Data derived from the isa spec.  */
#define UNSET (CGEN_SIZE_UNKNOWN + 1)
  cd->default_insn_bitsize = UNSET;
  cd->base_insn_bitsize = UNSET;
  cd->min_insn_bitsize = 65535; /* Some ridiculously big number.  */
  cd->max_insn_bitsize = 0;
  for (i = 0; i < MAX_ISAS; ++i)
    if (cgen_bitset_contains (isas, i))
      {
	const CGEN_ISA *isa = & vc4_cgen_isa_table[i];

	/* Default insn sizes of all selected isas must be
	   equal or we set the result to 0, meaning "unknown".  */
	if (cd->default_insn_bitsize == UNSET)
	  cd->default_insn_bitsize = isa->default_insn_bitsize;
	else if (isa->default_insn_bitsize == cd->default_insn_bitsize)
	  ; /* This is ok.  */
	else
	  cd->default_insn_bitsize = CGEN_SIZE_UNKNOWN;

	/* Base insn sizes of all selected isas must be equal
	   or we set the result to 0, meaning "unknown".  */
	if (cd->base_insn_bitsize == UNSET)
	  cd->base_insn_bitsize = isa->base_insn_bitsize;
	else if (isa->base_insn_bitsize == cd->base_insn_bitsize)
	  ; /* This is ok.  */
	else
	  cd->base_insn_bitsize = CGEN_SIZE_UNKNOWN;

	/* Set min,max insn sizes.  */
	if (isa->min_insn_bitsize < cd->min_insn_bitsize)
	  cd->min_insn_bitsize = isa->min_insn_bitsize;
	if (isa->max_insn_bitsize > cd->max_insn_bitsize)
	  cd->max_insn_bitsize = isa->max_insn_bitsize;
      }

  /* Data derived from the mach spec.  */
  for (i = 0; i < MAX_MACHS; ++i)
    if (((1 << i) & machs) != 0)
      {
	const CGEN_MACH *mach = & vc4_cgen_mach_table[i];

	if (mach->insn_chunk_bitsize != 0)
	{
	  if (cd->insn_chunk_bitsize != 0 && cd->insn_chunk_bitsize != mach->insn_chunk_bitsize)
	    {
	      fprintf (stderr, "vc4_cgen_rebuild_tables: conflicting insn-chunk-bitsize values: `%d' vs. `%d'\n",
		       cd->insn_chunk_bitsize, mach->insn_chunk_bitsize);
	      abort ();
	    }

 	  cd->insn_chunk_bitsize = mach->insn_chunk_bitsize;
	}
      }

  /* Determine which hw elements are used by MACH.  */
  build_hw_table (cd);

  /* Build the ifield table.  */
  build_ifield_table (cd);

  /* Determine which operands are used by MACH/ISA.  */
  build_operand_table (cd);

  /* Build the instruction table.  */
  build_insn_table (cd);
}

/* Initialize a cpu table and return a descriptor.
   It's much like opening a file, and must be the first function called.
   The arguments are a set of (type/value) pairs, terminated with
   CGEN_CPU_OPEN_END.

   Currently supported values:
   CGEN_CPU_OPEN_ISAS:    bitmap of values in enum isa_attr
   CGEN_CPU_OPEN_MACHS:   bitmap of values in enum mach_attr
   CGEN_CPU_OPEN_BFDMACH: specify 1 mach using bfd name
   CGEN_CPU_OPEN_ENDIAN:  specify endian choice
   CGEN_CPU_OPEN_END:     terminates arguments

   ??? Simultaneous multiple isas might not make sense, but it's not (yet)
   precluded.  */

CGEN_CPU_DESC
vc4_cgen_cpu_open (enum cgen_cpu_open_arg arg_type, ...)
{
  CGEN_CPU_TABLE *cd = (CGEN_CPU_TABLE *) xmalloc (sizeof (CGEN_CPU_TABLE));
  static int init_p;
  CGEN_BITSET *isas = 0;  /* 0 = "unspecified" */
  unsigned int machs = 0; /* 0 = "unspecified" */
  enum cgen_endian endian = CGEN_ENDIAN_UNKNOWN;
  va_list ap;

  if (! init_p)
    {
      init_tables ();
      init_p = 1;
    }

  memset (cd, 0, sizeof (*cd));

  va_start (ap, arg_type);
  while (arg_type != CGEN_CPU_OPEN_END)
    {
      switch (arg_type)
	{
	case CGEN_CPU_OPEN_ISAS :
	  isas = va_arg (ap, CGEN_BITSET *);
	  break;
	case CGEN_CPU_OPEN_MACHS :
	  machs = va_arg (ap, unsigned int);
	  break;
	case CGEN_CPU_OPEN_BFDMACH :
	  {
	    const char *name = va_arg (ap, const char *);
	    const CGEN_MACH *mach =
	      lookup_mach_via_bfd_name (vc4_cgen_mach_table, name);

	    machs |= 1 << mach->num;
	    break;
	  }
	case CGEN_CPU_OPEN_ENDIAN :
	  endian = va_arg (ap, enum cgen_endian);
	  break;
	default :
	  fprintf (stderr, "vc4_cgen_cpu_open: unsupported argument `%d'\n",
		   arg_type);
	  abort (); /* ??? return NULL? */
	}
      arg_type = va_arg (ap, enum cgen_cpu_open_arg);
    }
  va_end (ap);

  /* Mach unspecified means "all".  */
  if (machs == 0)
    machs = (1 << MAX_MACHS) - 1;
  /* Base mach is always selected.  */
  machs |= 1;
  if (endian == CGEN_ENDIAN_UNKNOWN)
    {
      /* ??? If target has only one, could have a default.  */
      fprintf (stderr, "vc4_cgen_cpu_open: no endianness specified\n");
      abort ();
    }

  cd->isas = cgen_bitset_copy (isas);
  cd->machs = machs;
  cd->endian = endian;
  /* FIXME: for the sparc case we can determine insn-endianness statically.
     The worry here is where both data and insn endian can be independently
     chosen, in which case this function will need another argument.
     Actually, will want to allow for more arguments in the future anyway.  */
  cd->insn_endian = endian;

  /* Table (re)builder.  */
  cd->rebuild_tables = vc4_cgen_rebuild_tables;
  vc4_cgen_rebuild_tables (cd);

  /* Default to not allowing signed overflow.  */
  cd->signed_overflow_ok_p = 0;
  
  return (CGEN_CPU_DESC) cd;
}

/* Cover fn to vc4_cgen_cpu_open to handle the simple case of 1 isa, 1 mach.
   MACH_NAME is the bfd name of the mach.  */

CGEN_CPU_DESC
vc4_cgen_cpu_open_1 (const char *mach_name, enum cgen_endian endian)
{
  return vc4_cgen_cpu_open (CGEN_CPU_OPEN_BFDMACH, mach_name,
			       CGEN_CPU_OPEN_ENDIAN, endian,
			       CGEN_CPU_OPEN_END);
}

/* Close a cpu table.
   ??? This can live in a machine independent file, but there's currently
   no place to put this file (there's no libcgen).  libopcodes is the wrong
   place as some simulator ports use this but they don't use libopcodes.  */

void
vc4_cgen_cpu_close (CGEN_CPU_DESC cd)
{
  unsigned int i;
  const CGEN_INSN *insns;

  if (cd->macro_insn_table.init_entries)
    {
      insns = cd->macro_insn_table.init_entries;
      for (i = 0; i < cd->macro_insn_table.num_init_entries; ++i, ++insns)
	if (CGEN_INSN_RX ((insns)))
	  regfree (CGEN_INSN_RX (insns));
    }

  if (cd->insn_table.init_entries)
    {
      insns = cd->insn_table.init_entries;
      for (i = 0; i < cd->insn_table.num_init_entries; ++i, ++insns)
	if (CGEN_INSN_RX (insns))
	  regfree (CGEN_INSN_RX (insns));
    }  

  if (cd->macro_insn_table.init_entries)
    free ((CGEN_INSN *) cd->macro_insn_table.init_entries);

  if (cd->insn_table.init_entries)
    free ((CGEN_INSN *) cd->insn_table.init_entries);

  if (cd->hw_table.entries)
    free ((CGEN_HW_ENTRY *) cd->hw_table.entries);

  if (cd->operand_table.entries)
    free ((CGEN_HW_ENTRY *) cd->operand_table.entries);

  free (cd);
}

