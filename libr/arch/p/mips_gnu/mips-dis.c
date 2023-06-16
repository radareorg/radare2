/*
  Based on commits 250d07de5cf6efc81ed934c25292beb63c7e3129 from master branch
  of binutils-gdb.
*/
/* Default disassembler options are modified to match radare2 config.  */

/* Print mips instructions for GDB, the GNU debugger, or for objdump.
   Copyright (C) 1989-2021 Free Software Foundation, Inc.
   Contributed by Nobuyuki Hikichi(hikichi@sra.co.jp).

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../../include/ansidecl.h"
#include "../../include/sysdep.h"
#include "../../include/disas-asm.h"
#include "../../include/libiberty.h"
#include "../../include/elf/mips.h"
#include "../../include/opintl.h"

/* FIXME: These are needed to figure out if the code is mips16 or
   not. The low bit of the address is often a good indicator.  No
   symbol table is available when this code runs out in an embedded
   system as when it is used for disassembler support in a monitor.  */

#include "../../include/opcode/mips.h"
#if !defined(EMBEDDED_ENV)
#define SYMTAB_AVAILABLE 1
#include "../../include/elf-bfd.h"
#endif

/* Mips instructions are at maximum this many bytes long.  */
#define INSNLEN 4


/* FIXME: These should be shared with gdb somehow.  */

struct mips_cp0sel_name
{
  unsigned int cp0reg;
  unsigned int sel;
  const char * const name;
};

static const char *const mips_gpr_names_numeric[32] =
{
  "$0",   "$1",   "$2",   "$3",   "$4",   "$5",   "$6",   "$7",
  "$8",   "$9",   "$10",  "$11",  "$12",  "$13",  "$14",  "$15",
  "$16",  "$17",  "$18",  "$19",  "$20",  "$21",  "$22",  "$23",
  "$24",  "$25",  "$26",  "$27",  "$28",  "$29",  "$30",  "$31"
};

static const char *const mips_gpr_names_oldabi[32] =
{
  "zero", "at",   "v0",   "v1",   "a0",   "a1",   "a2",   "a3",
  "t0",   "t1",   "t2",   "t3",   "t4",   "t5",   "t6",   "t7",
  "s0",   "s1",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
  "t8",   "t9",   "k0",   "k1",   "gp",   "sp",   "s8",   "ra"
};

static const char *const mips_gpr_names_newabi[32] =
{
  "zero", "at",   "v0",   "v1",   "a0",   "a1",   "a2",   "a3",
  "a4",   "a5",   "a6",   "a7",   "t0",   "t1",   "t2",   "t3",
  "s0",   "s1",   "s2",   "s3",   "s4",   "s5",   "s6",   "s7",
  "t8",   "t9",   "k0",   "k1",   "gp",   "sp",   "s8",   "ra"
};

static const char *const mips_fpr_names_numeric[32] =
{
  "$f0",  "$f1",  "$f2",  "$f3",  "$f4",  "$f5",  "$f6",  "$f7",
  "$f8",  "$f9",  "$f10", "$f11", "$f12", "$f13", "$f14", "$f15",
  "$f16", "$f17", "$f18", "$f19", "$f20", "$f21", "$f22", "$f23",
  "$f24", "$f25", "$f26", "$f27", "$f28", "$f29", "$f30", "$f31"
};

static const char *const mips_fpr_names_32[32] =
{
  "fv0",  "fv0f", "fv1",  "fv1f", "ft0",  "ft0f", "ft1",  "ft1f",
  "ft2",  "ft2f", "ft3",  "ft3f", "fa0",  "fa0f", "fa1",  "fa1f",
  "ft4",  "ft4f", "ft5",  "ft5f", "fs0",  "fs0f", "fs1",  "fs1f",
  "fs2",  "fs2f", "fs3",  "fs3f", "fs4",  "fs4f", "fs5",  "fs5f"
};

static const char *const mips_fpr_names_n32[32] =
{
  "fv0",  "ft14", "fv1",  "ft15", "ft0",  "ft1",  "ft2",  "ft3",
  "ft4",  "ft5",  "ft6",  "ft7",  "fa0",  "fa1",  "fa2",  "fa3",
  "fa4",  "fa5",  "fa6",  "fa7",  "fs0",  "ft8",  "fs1",  "ft9",
  "fs2",  "ft10", "fs3",  "ft11", "fs4",  "ft12", "fs5",  "ft13"
};

static const char *const mips_fpr_names_64[32] =
{
  "fv0",  "ft12", "fv1",  "ft13", "ft0",  "ft1",  "ft2",  "ft3",
  "ft4",  "ft5",  "ft6",  "ft7",  "fa0",  "fa1",  "fa2",  "fa3",
  "fa4",  "fa5",  "fa6",  "fa7",  "ft8",  "ft9",  "ft10", "ft11",
  "fs0",  "fs1",  "fs2",  "fs3",  "fs4",  "fs5",  "fs6",  "fs7"
};

static const char *const mips_cp0_names_numeric[32] =
{
  "$0",   "$1",   "$2",   "$3",   "$4",   "$5",   "$6",   "$7",
  "$8",   "$9",   "$10",  "$11",  "$12",  "$13",  "$14",  "$15",
  "$16",  "$17",  "$18",  "$19",  "$20",  "$21",  "$22",  "$23",
  "$24",  "$25",  "$26",  "$27",  "$28",  "$29",  "$30",  "$31"
};

static const char *const mips_cp1_names_numeric[32] =
{
  "$0",   "$1",   "$2",   "$3",   "$4",   "$5",   "$6",   "$7",
  "$8",   "$9",   "$10",  "$11",  "$12",  "$13",  "$14",  "$15",
  "$16",  "$17",  "$18",  "$19",  "$20",  "$21",  "$22",  "$23",
  "$24",  "$25",  "$26",  "$27",  "$28",  "$29",  "$30",  "$31"
};

static const char *const mips_cp0_names_r3000[32] =
{
  "c0_index",     "c0_random",    "c0_entrylo",   "$3",
  "c0_context",   "$5",           "$6",           "$7",
  "c0_badvaddr",  "$9",           "c0_entryhi",   "$11",
  "c0_sr",        "c0_cause",     "c0_epc",       "c0_prid",
  "$16",          "$17",          "$18",          "$19",
  "$20",          "$21",          "$22",          "$23",
  "$24",          "$25",          "$26",          "$27",
  "$28",          "$29",          "$30",          "$31",
};

static const char *const mips_cp0_names_r4000[32] =
{
  "c0_index",     "c0_random",    "c0_entrylo0",  "c0_entrylo1",
  "c0_context",   "c0_pagemask",  "c0_wired",     "$7",
  "c0_badvaddr",  "c0_count",     "c0_entryhi",   "c0_compare",
  "c0_sr",        "c0_cause",     "c0_epc",       "c0_prid",
  "c0_config",    "c0_lladdr",    "c0_watchlo",   "c0_watchhi",
  "c0_xcontext",  "$21",          "$22",          "$23",
  "$24",          "$25",          "c0_ecc",       "c0_cacheerr",
  "c0_taglo",     "c0_taghi",     "c0_errorepc",  "$31",
};

static const char *const mips_cp0_names_r5900[32] =
{
  "c0_index",     "c0_random",    "c0_entrylo0",  "c0_entrylo1",
  "c0_context",   "c0_pagemask",  "c0_wired",     "$7",
  "c0_badvaddr",  "c0_count",     "c0_entryhi",   "c0_compare",
  "c0_sr",        "c0_cause",     "c0_epc",       "c0_prid",
  "c0_config",    "$17",          "$18",          "$19",
  "$20",          "$21",          "$22",          "c0_badpaddr",
  "c0_depc",      "c0_perfcnt",   "$26",          "$27",
  "c0_taglo",     "c0_taghi",     "c0_errorepc",  "$31"
};

static const char *const mips_cp0_names_mips3264[32] =
{
  "c0_index",     "c0_random",    "c0_entrylo0",  "c0_entrylo1",
  "c0_context",   "c0_pagemask",  "c0_wired",     "$7",
  "c0_badvaddr",  "c0_count",     "c0_entryhi",   "c0_compare",
  "c0_status",    "c0_cause",     "c0_epc",       "c0_prid",
  "c0_config",    "c0_lladdr",    "c0_watchlo",   "c0_watchhi",
  "c0_xcontext",  "$21",          "$22",          "c0_debug",
  "c0_depc",      "c0_perfcnt",   "c0_errctl",    "c0_cacheerr",
  "c0_taglo",     "c0_taghi",     "c0_errorepc",  "c0_desave",
};

static const char *const mips_cp1_names_mips3264[32] =
{
  "c1_fir",       "c1_ufr",       "$2",           "$3",
  "c1_unfr",      "$5",           "$6",           "$7",
  "$8",           "$9",           "$10",          "$11",
  "$12",          "$13",          "$14",          "$15",
  "$16",          "$17",          "$18",          "$19",
  "$20",          "$21",          "$22",          "$23",
  "$24",          "c1_fccr",      "c1_fexr",      "$27",
  "c1_fenr",      "$29",          "$30",          "c1_fcsr"
};

static const struct mips_cp0sel_name mips_cp0sel_names_mips3264[] =
{
  { 16, 1, "c0_config1"		},
  { 16, 2, "c0_config2"		},
  { 16, 3, "c0_config3"		},
  { 18, 1, "c0_watchlo,1"	},
  { 18, 2, "c0_watchlo,2"	},
  { 18, 3, "c0_watchlo,3"	},
  { 18, 4, "c0_watchlo,4"	},
  { 18, 5, "c0_watchlo,5"	},
  { 18, 6, "c0_watchlo,6"	},
  { 18, 7, "c0_watchlo,7"	},
  { 19, 1, "c0_watchhi,1"	},
  { 19, 2, "c0_watchhi,2"	},
  { 19, 3, "c0_watchhi,3"	},
  { 19, 4, "c0_watchhi,4"	},
  { 19, 5, "c0_watchhi,5"	},
  { 19, 6, "c0_watchhi,6"	},
  { 19, 7, "c0_watchhi,7"	},
  { 25, 1, "c0_perfcnt,1"	},
  { 25, 2, "c0_perfcnt,2"	},
  { 25, 3, "c0_perfcnt,3"	},
  { 25, 4, "c0_perfcnt,4"	},
  { 25, 5, "c0_perfcnt,5"	},
  { 25, 6, "c0_perfcnt,6"	},
  { 25, 7, "c0_perfcnt,7"	},
  { 27, 1, "c0_cacheerr,1"	},
  { 27, 2, "c0_cacheerr,2"	},
  { 27, 3, "c0_cacheerr,3"	},
  { 28, 1, "c0_datalo"		},
  { 29, 1, "c0_datahi"		}
};

static const char *const mips_cp0_names_mips3264r2[32] =
{
  "c0_index",     "c0_random",    "c0_entrylo0",  "c0_entrylo1",
  "c0_context",   "c0_pagemask",  "c0_wired",     "c0_hwrena",
  "c0_badvaddr",  "c0_count",     "c0_entryhi",   "c0_compare",
  "c0_status",    "c0_cause",     "c0_epc",       "c0_prid",
  "c0_config",    "c0_lladdr",    "c0_watchlo",   "c0_watchhi",
  "c0_xcontext",  "$21",          "$22",          "c0_debug",
  "c0_depc",      "c0_perfcnt",   "c0_errctl",    "c0_cacheerr",
  "c0_taglo",     "c0_taghi",     "c0_errorepc",  "c0_desave",
};

static const struct mips_cp0sel_name mips_cp0sel_names_mips3264r2[] =
{
  {  4, 1, "c0_contextconfig"	},
  {  0, 1, "c0_mvpcontrol"	},
  {  0, 2, "c0_mvpconf0"	},
  {  0, 3, "c0_mvpconf1"	},
  {  1, 1, "c0_vpecontrol"	},
  {  1, 2, "c0_vpeconf0"	},
  {  1, 3, "c0_vpeconf1"	},
  {  1, 4, "c0_yqmask"		},
  {  1, 5, "c0_vpeschedule"	},
  {  1, 6, "c0_vpeschefback"	},
  {  2, 1, "c0_tcstatus"	},
  {  2, 2, "c0_tcbind"		},
  {  2, 3, "c0_tcrestart"	},
  {  2, 4, "c0_tchalt"		},
  {  2, 5, "c0_tccontext"	},
  {  2, 6, "c0_tcschedule"	},
  {  2, 7, "c0_tcschefback"	},
  {  5, 1, "c0_pagegrain"	},
  {  6, 1, "c0_srsconf0"	},
  {  6, 2, "c0_srsconf1"	},
  {  6, 3, "c0_srsconf2"	},
  {  6, 4, "c0_srsconf3"	},
  {  6, 5, "c0_srsconf4"	},
  { 12, 1, "c0_intctl"		},
  { 12, 2, "c0_srsctl"		},
  { 12, 3, "c0_srsmap"		},
  { 15, 1, "c0_ebase"		},
  { 16, 1, "c0_config1"		},
  { 16, 2, "c0_config2"		},
  { 16, 3, "c0_config3"		},
  { 18, 1, "c0_watchlo,1"	},
  { 18, 2, "c0_watchlo,2"	},
  { 18, 3, "c0_watchlo,3"	},
  { 18, 4, "c0_watchlo,4"	},
  { 18, 5, "c0_watchlo,5"	},
  { 18, 6, "c0_watchlo,6"	},
  { 18, 7, "c0_watchlo,7"	},
  { 19, 1, "c0_watchhi,1"	},
  { 19, 2, "c0_watchhi,2"	},
  { 19, 3, "c0_watchhi,3"	},
  { 19, 4, "c0_watchhi,4"	},
  { 19, 5, "c0_watchhi,5"	},
  { 19, 6, "c0_watchhi,6"	},
  { 19, 7, "c0_watchhi,7"	},
  { 23, 1, "c0_tracecontrol"	},
  { 23, 2, "c0_tracecontrol2"	},
  { 23, 3, "c0_usertracedata"	},
  { 23, 4, "c0_tracebpc"	},
  { 25, 1, "c0_perfcnt,1"	},
  { 25, 2, "c0_perfcnt,2"	},
  { 25, 3, "c0_perfcnt,3"	},
  { 25, 4, "c0_perfcnt,4"	},
  { 25, 5, "c0_perfcnt,5"	},
  { 25, 6, "c0_perfcnt,6"	},
  { 25, 7, "c0_perfcnt,7"	},
  { 27, 1, "c0_cacheerr,1"	},
  { 27, 2, "c0_cacheerr,2"	},
  { 27, 3, "c0_cacheerr,3"	},
  { 28, 1, "c0_datalo"		},
  { 28, 2, "c0_taglo1"		},
  { 28, 3, "c0_datalo1"		},
  { 28, 4, "c0_taglo2"		},
  { 28, 5, "c0_datalo2"		},
  { 28, 6, "c0_taglo3"		},
  { 28, 7, "c0_datalo3"		},
  { 29, 1, "c0_datahi"		},
  { 29, 2, "c0_taghi1"		},
  { 29, 3, "c0_datahi1"		},
  { 29, 4, "c0_taghi2"		},
  { 29, 5, "c0_datahi2"		},
  { 29, 6, "c0_taghi3"		},
  { 29, 7, "c0_datahi3"		},
};

/* SB-1: MIPS64 (mips_cp0_names_mips3264) with minor mods.  */
static const char *const mips_cp0_names_sb1[32] =
{
  "c0_index",     "c0_random",    "c0_entrylo0",  "c0_entrylo1",
  "c0_context",   "c0_pagemask",  "c0_wired",     "$7",
  "c0_badvaddr",  "c0_count",     "c0_entryhi",   "c0_compare",
  "c0_status",    "c0_cause",     "c0_epc",       "c0_prid",
  "c0_config",    "c0_lladdr",    "c0_watchlo",   "c0_watchhi",
  "c0_xcontext",  "$21",          "$22",          "c0_debug",
  "c0_depc",      "c0_perfcnt",   "c0_errctl",    "c0_cacheerr_i",
  "c0_taglo_i",   "c0_taghi_i",   "c0_errorepc",  "c0_desave",
};

static const struct mips_cp0sel_name mips_cp0sel_names_sb1[] =
{
  { 16, 1, "c0_config1"		},
  { 18, 1, "c0_watchlo,1"	},
  { 19, 1, "c0_watchhi,1"	},
  { 22, 0, "c0_perftrace"	},
  { 23, 3, "c0_edebug"		},
  { 25, 1, "c0_perfcnt,1"	},
  { 25, 2, "c0_perfcnt,2"	},
  { 25, 3, "c0_perfcnt,3"	},
  { 25, 4, "c0_perfcnt,4"	},
  { 25, 5, "c0_perfcnt,5"	},
  { 25, 6, "c0_perfcnt,6"	},
  { 25, 7, "c0_perfcnt,7"	},
  { 26, 1, "c0_buserr_pa"	},
  { 27, 1, "c0_cacheerr_d"	},
  { 27, 3, "c0_cacheerr_d_pa"	},
  { 28, 1, "c0_datalo_i"	},
  { 28, 2, "c0_taglo_d"		},
  { 28, 3, "c0_datalo_d"	},
  { 29, 1, "c0_datahi_i"	},
  { 29, 2, "c0_taghi_d"		},
  { 29, 3, "c0_datahi_d"	},
};

/* Xlr cop0 register names.  */
static const char *const mips_cp0_names_xlr[32] = {
  "c0_index",     "c0_random",    "c0_entrylo0",  "c0_entrylo1",
  "c0_context",   "c0_pagemask",  "c0_wired",     "$7",
  "c0_badvaddr",  "c0_count",     "c0_entryhi",   "c0_compare",
  "c0_status",    "c0_cause",     "c0_epc",       "c0_prid",
  "c0_config",    "c0_lladdr",    "c0_watchlo",   "c0_watchhi",
  "c0_xcontext",  "$21",          "$22",          "c0_debug",
  "c0_depc",      "c0_perfcnt",   "c0_errctl",    "c0_cacheerr_i",
  "c0_taglo_i",   "c0_taghi_i",   "c0_errorepc",  "c0_desave",
};

/* XLR's CP0 Select Registers.  */

static const struct mips_cp0sel_name mips_cp0sel_names_xlr[] = {
  {  9, 6, "c0_extintreq"       },
  {  9, 7, "c0_extintmask"      },
  { 15, 1, "c0_ebase"           },
  { 16, 1, "c0_config1"         },
  { 16, 2, "c0_config2"         },
  { 16, 3, "c0_config3"         },
  { 16, 7, "c0_procid2"         },
  { 18, 1, "c0_watchlo,1"       },
  { 18, 2, "c0_watchlo,2"       },
  { 18, 3, "c0_watchlo,3"       },
  { 18, 4, "c0_watchlo,4"       },
  { 18, 5, "c0_watchlo,5"       },
  { 18, 6, "c0_watchlo,6"       },
  { 18, 7, "c0_watchlo,7"       },
  { 19, 1, "c0_watchhi,1"       },
  { 19, 2, "c0_watchhi,2"       },
  { 19, 3, "c0_watchhi,3"       },
  { 19, 4, "c0_watchhi,4"       },
  { 19, 5, "c0_watchhi,5"       },
  { 19, 6, "c0_watchhi,6"       },
  { 19, 7, "c0_watchhi,7"       },
  { 25, 1, "c0_perfcnt,1"       },
  { 25, 2, "c0_perfcnt,2"       },
  { 25, 3, "c0_perfcnt,3"       },
  { 25, 4, "c0_perfcnt,4"       },
  { 25, 5, "c0_perfcnt,5"       },
  { 25, 6, "c0_perfcnt,6"       },
  { 25, 7, "c0_perfcnt,7"       },
  { 27, 1, "c0_cacheerr,1"      },
  { 27, 2, "c0_cacheerr,2"      },
  { 27, 3, "c0_cacheerr,3"      },
  { 28, 1, "c0_datalo"          },
  { 29, 1, "c0_datahi"          }
};

static const char *const mips_hwr_names_numeric[32] =
{
  "$0",   "$1",   "$2",   "$3",   "$4",   "$5",   "$6",   "$7",
  "$8",   "$9",   "$10",  "$11",  "$12",  "$13",  "$14",  "$15",
  "$16",  "$17",  "$18",  "$19",  "$20",  "$21",  "$22",  "$23",
  "$24",  "$25",  "$26",  "$27",  "$28",  "$29",  "$30",  "$31"
};

static const char *const mips_hwr_names_mips3264r2[32] =
{
  "hwr_cpunum",   "hwr_synci_step", "hwr_cc",     "hwr_ccres",
  "$4",          "$5",            "$6",           "$7",
  "$8",   "$9",   "$10",  "$11",  "$12",  "$13",  "$14",  "$15",
  "$16",  "$17",  "$18",  "$19",  "$20",  "$21",  "$22",  "$23",
  "$24",  "$25",  "$26",  "$27",  "$28",  "$29",  "$30",  "$31"
};

static const char *const msa_control_names[32] =
{
  "msa_ir",	"msa_csr",	"msa_access",	"msa_save",
  "msa_modify",	"msa_request",	"msa_map",	"msa_unmap",
  "$8",   "$9",   "$10",  "$11",  "$12",  "$13",  "$14",  "$15",
  "$16",  "$17",  "$18",  "$19",  "$20",  "$21",  "$22",  "$23",
  "$24",  "$25",  "$26",  "$27",  "$28",  "$29",  "$30",  "$31"
};

struct mips_abi_choice
{
  const char * name;
  const char * const *gpr_names;
  const char * const *fpr_names;
};

//Modified for matching asm_mips_gnu.c
struct mips_abi_choice mips_abi_choices[] =
{
  { "numeric", mips_gpr_names_numeric, mips_fpr_names_numeric },
  //{ "32", mips_gpr_names_oldabi, mips_fpr_names_32 },
  { "o32", mips_gpr_names_oldabi, mips_fpr_names_32 },
  { "n32", mips_gpr_names_newabi, mips_fpr_names_n32 },
  //{ "64", mips_gpr_names_newabi, mips_fpr_names_64 },
  { "n64", mips_gpr_names_newabi, mips_fpr_names_64 },
};

struct mips_arch_choice
{
  const char *name;
  int bfd_mach_valid;
  unsigned long bfd_mach;
  int processor;
  int isa;
  int ase;
  const char * const *cp0_names;
  const struct mips_cp0sel_name *cp0sel_names;
  unsigned int cp0sel_names_len;
  const char * const *cp1_names;
  const char * const *hwr_names;
};

const struct mips_arch_choice mips_arch_choices[] =
{
  { "numeric",	0, 0, 0, 0, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },

  { "r3000",	1, bfd_mach_mips3000, CPU_R3000, ISA_MIPS1, 0,
    mips_cp0_names_r3000, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r3900",	1, bfd_mach_mips3900, CPU_R3900, ISA_MIPS1, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r4000",	1, bfd_mach_mips4000, CPU_R4000, ISA_MIPS3, 0,
    mips_cp0_names_r4000, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r4010",	1, bfd_mach_mips4010, CPU_R4010, ISA_MIPS2, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "vr4100",	1, bfd_mach_mips4100, CPU_VR4100, ISA_MIPS3, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "vr4111",	1, bfd_mach_mips4111, CPU_R4111, ISA_MIPS3, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "vr4120",	1, bfd_mach_mips4120, CPU_VR4120, ISA_MIPS3, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r4300",	1, bfd_mach_mips4300, CPU_R4300, ISA_MIPS3, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r4400",	1, bfd_mach_mips4400, CPU_R4400, ISA_MIPS3, 0,
    mips_cp0_names_r4000, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r4600",	1, bfd_mach_mips4600, CPU_R4600, ISA_MIPS3, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r4650",	1, bfd_mach_mips4650, CPU_R4650, ISA_MIPS3, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r5000",	1, bfd_mach_mips5000, CPU_R5000, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "vr5400",	1, bfd_mach_mips5400, CPU_VR5400, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "vr5500",	1, bfd_mach_mips5500, CPU_VR5500, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r5900",	1, bfd_mach_mips5900, CPU_R5900, ISA_MIPS3, 0,
    mips_cp0_names_r5900, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r6000",	1, bfd_mach_mips6000, CPU_R6000, ISA_MIPS2, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "rm7000",	1, bfd_mach_mips7000, CPU_RM7000, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "rm9000",	1, bfd_mach_mips7000, CPU_RM7000, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r8000",	1, bfd_mach_mips8000, CPU_R8000, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r10000",	1, bfd_mach_mips10000, CPU_R10000, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r12000",	1, bfd_mach_mips12000, CPU_R12000, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r14000",	1, bfd_mach_mips14000, CPU_R14000, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "r16000",	1, bfd_mach_mips16000, CPU_R16000, ISA_MIPS4, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
  { "mips5",	1, bfd_mach_mips5, CPU_MIPS5, ISA_MIPS5, 0,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },

  /* For stock MIPS32, disassemble all applicable MIPS-specified ASEs.
     Note that MIPS-3D and MDMX are not applicable to MIPS32.  (See
     _MIPS32 Architecture For Programmers Volume I: Introduction to the
     MIPS32 Architecture_ (MIPS Document Number MD00082, Revision 0.95),
     page 1.  */
  { "mips32",	1, bfd_mach_mipsisa32, CPU_MIPS32,
    ISA_MIPS32,  ASE_SMARTMIPS,
    mips_cp0_names_mips3264,
    mips_cp0sel_names_mips3264, ARRAY_SIZE (mips_cp0sel_names_mips3264),
    mips_cp1_names_mips3264, mips_hwr_names_numeric },

  { "mips32r2",	1, bfd_mach_mipsisa32r2, CPU_MIPS32R2,
    ISA_MIPS32R2,
    (ASE_SMARTMIPS | ASE_DSP | ASE_DSPR2 | ASE_EVA | ASE_MIPS3D
     | ASE_MT | ASE_MCU | ASE_VIRT | ASE_MSA | ASE_XPA),
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  { "mips32r3",	1, bfd_mach_mipsisa32r3, CPU_MIPS32R3,
    ISA_MIPS32R3,
    (ASE_SMARTMIPS | ASE_DSP | ASE_DSPR2 | ASE_EVA | ASE_MIPS3D
     | ASE_MT | ASE_MCU | ASE_VIRT | ASE_MSA | ASE_XPA),
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  { "mips32r5",	1, bfd_mach_mipsisa32r5, CPU_MIPS32R5,
    ISA_MIPS32R5,
    (ASE_SMARTMIPS | ASE_DSP | ASE_DSPR2 | ASE_EVA | ASE_MIPS3D
     | ASE_MT | ASE_MCU | ASE_VIRT | ASE_MSA | ASE_XPA),
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  { "mips32r6",	1, bfd_mach_mipsisa32r6, CPU_MIPS32R6,
    ISA_MIPS32R6,
    (ASE_EVA | ASE_MSA | ASE_VIRT | ASE_XPA | ASE_MCU | ASE_MT | ASE_DSP
     | ASE_DSPR2 | ASE_DSPR3 | ASE_CRC | ASE_GINV),
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  /* For stock MIPS64, disassemble all applicable MIPS-specified ASEs.  */
  { "mips64",	1, bfd_mach_mipsisa64, CPU_MIPS64,
    ISA_MIPS64,  ASE_MIPS3D | ASE_MDMX,
    mips_cp0_names_mips3264,
    mips_cp0sel_names_mips3264, ARRAY_SIZE (mips_cp0sel_names_mips3264),
    mips_cp1_names_mips3264, mips_hwr_names_numeric },

  { "mips64r2",	1, bfd_mach_mipsisa64r2, CPU_MIPS64R2,
    ISA_MIPS64R2,
    (ASE_MIPS3D | ASE_DSP | ASE_DSPR2 | ASE_DSP64 | ASE_EVA | ASE_MT
     | ASE_MCU | ASE_VIRT | ASE_VIRT64 | ASE_MSA | ASE_MSA64 | ASE_XPA),
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  { "mips64r3",	1, bfd_mach_mipsisa64r3, CPU_MIPS64R3,
    ISA_MIPS64R3,
    (ASE_MIPS3D | ASE_DSP | ASE_DSPR2 | ASE_DSP64 | ASE_EVA | ASE_MT
     | ASE_MCU | ASE_VIRT | ASE_VIRT64 | ASE_MSA | ASE_MSA64 | ASE_XPA),
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  { "mips64r5",	1, bfd_mach_mipsisa64r5, CPU_MIPS64R5,
    ISA_MIPS64R5,
    (ASE_MIPS3D | ASE_DSP | ASE_DSPR2 | ASE_DSP64 | ASE_EVA | ASE_MT
     | ASE_MCU | ASE_VIRT | ASE_VIRT64 | ASE_MSA | ASE_MSA64 | ASE_XPA),
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  { "mips64r6",	1, bfd_mach_mipsisa64r6, CPU_MIPS64R6,
    ISA_MIPS64R6,
    (ASE_EVA | ASE_MSA | ASE_MSA64 | ASE_XPA | ASE_VIRT | ASE_VIRT64
     | ASE_MCU | ASE_MT | ASE_DSP | ASE_DSPR2 | ASE_DSPR3 | ASE_CRC
     | ASE_CRC64 | ASE_GINV),
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  { "interaptiv-mr2",	1, bfd_mach_mips_interaptiv_mr2, CPU_INTERAPTIV_MR2,
    ISA_MIPS32R3,
    ASE_MT | ASE_EVA | ASE_DSP | ASE_DSPR2 | ASE_MIPS16E2 | ASE_MIPS16E2_MT,
    mips_cp0_names_mips3264r2,
    mips_cp0sel_names_mips3264r2, ARRAY_SIZE (mips_cp0sel_names_mips3264r2),
    mips_cp1_names_mips3264, mips_hwr_names_mips3264r2 },

  { "sb1",	1, bfd_mach_mips_sb1, CPU_SB1,
    ISA_MIPS64 | INSN_SB1,  ASE_MIPS3D,
    mips_cp0_names_sb1,
    mips_cp0sel_names_sb1, ARRAY_SIZE (mips_cp0sel_names_sb1),
    mips_cp1_names_mips3264, mips_hwr_names_numeric },

  { "loongson2e",   1, bfd_mach_mips_loongson_2e, CPU_LOONGSON_2E,
    ISA_MIPS3 | INSN_LOONGSON_2E, 0, mips_cp0_names_numeric,
    NULL, 0, mips_cp1_names_numeric, mips_hwr_names_numeric },

  { "loongson2f",   1, bfd_mach_mips_loongson_2f, CPU_LOONGSON_2F,
    ISA_MIPS3 | INSN_LOONGSON_2F, ASE_LOONGSON_MMI, mips_cp0_names_numeric,
    NULL, 0, mips_cp1_names_numeric, mips_hwr_names_numeric },

  /* The loongson3a is an alias of gs464 for compatibility */
  { "loongson3a",   1, bfd_mach_mips_gs464, CPU_GS464,
    ISA_MIPS64R2, ASE_LOONGSON_MMI | ASE_LOONGSON_CAM | ASE_LOONGSON_EXT,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_mips3264,
    mips_hwr_names_numeric },

  { "gs464",   1, bfd_mach_mips_gs464, CPU_GS464,
    ISA_MIPS64R2, ASE_LOONGSON_MMI | ASE_LOONGSON_CAM | ASE_LOONGSON_EXT,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_mips3264,
    mips_hwr_names_numeric },

  { "gs464e",   1, bfd_mach_mips_gs464e, CPU_GS464E,
    ISA_MIPS64R2, ASE_LOONGSON_MMI | ASE_LOONGSON_CAM | ASE_LOONGSON_EXT
    | ASE_LOONGSON_EXT2, mips_cp0_names_numeric, NULL, 0, mips_cp1_names_mips3264,
    mips_hwr_names_numeric },

  { "gs264e",   1, bfd_mach_mips_gs264e, CPU_GS264E,
    ISA_MIPS64R2, ASE_LOONGSON_MMI | ASE_LOONGSON_CAM | ASE_LOONGSON_EXT
    | ASE_LOONGSON_EXT2 | ASE_MSA | ASE_MSA64, mips_cp0_names_numeric, NULL,
    0, mips_cp1_names_mips3264, mips_hwr_names_numeric },

  { "octeon",   1, bfd_mach_mips_octeon, CPU_OCTEON,
    ISA_MIPS64R2 | INSN_OCTEON, 0, mips_cp0_names_numeric, NULL, 0,
    mips_cp1_names_mips3264, mips_hwr_names_numeric },

  { "octeon+",   1, bfd_mach_mips_octeonp, CPU_OCTEONP,
    ISA_MIPS64R2 | INSN_OCTEONP, 0, mips_cp0_names_numeric,
    NULL, 0, mips_cp1_names_mips3264, mips_hwr_names_numeric },

  { "octeon2",   1, bfd_mach_mips_octeon2, CPU_OCTEON2,
    ISA_MIPS64R2 | INSN_OCTEON2, 0, mips_cp0_names_numeric,
    NULL, 0, mips_cp1_names_mips3264, mips_hwr_names_numeric },

  { "octeon3",   1, bfd_mach_mips_octeon3, CPU_OCTEON3,
    ISA_MIPS64R5 | INSN_OCTEON3, ASE_VIRT | ASE_VIRT64,
    mips_cp0_names_numeric,
    NULL, 0, mips_cp1_names_mips3264, mips_hwr_names_numeric },

  { "xlr", 1, bfd_mach_mips_xlr, CPU_XLR,
    ISA_MIPS64 | INSN_XLR, 0,
    mips_cp0_names_xlr,
    mips_cp0sel_names_xlr, ARRAY_SIZE (mips_cp0sel_names_xlr),
    mips_cp1_names_mips3264, mips_hwr_names_numeric },

  /* XLP is mostly like XLR, with the prominent exception it is being
     MIPS64R2.  */
  { "xlp", 1, bfd_mach_mips_xlr, CPU_XLR,
    ISA_MIPS64R2 | INSN_XLR, 0,
    mips_cp0_names_xlr,
    mips_cp0sel_names_xlr, ARRAY_SIZE (mips_cp0sel_names_xlr),
    mips_cp1_names_mips3264, mips_hwr_names_numeric },

  /* This entry, mips16, is here only for ISA/processor selection; do
     not print its name.  */
  { "",		1, bfd_mach_mips16, CPU_MIPS16, ISA_MIPS64,
    ASE_MIPS16E2 | ASE_MIPS16E2_MT,
    mips_cp0_names_numeric, NULL, 0, mips_cp1_names_numeric,
    mips_hwr_names_numeric },
};

/* ISA and processor type to disassemble for, and register names to use.
   set_default_mips_dis_options and parse_mips_dis_options fill in these
   values.  */
static int mips_processor;
static int mips_isa;
static int mips_ase;
static int micromips_ase;
static const char *const *mips_gpr_names;
static const char *const *mips_fpr_names;
static const char *const *mips_cp0_names;
static const struct mips_cp0sel_name *mips_cp0sel_names;
static int mips_cp0sel_names_len;
static const char *const *mips_cp1_names;
static const char *const *mips_hwr_names;

/* Other options */
static int no_aliases;	/* If set disassemble as most general inst.  */

static const struct mips_abi_choice *
choose_abi_by_name (const char *name, unsigned int namelen)
{
  const struct mips_abi_choice *c;
  unsigned int i;

  for (i = 0, c = NULL; i < ARRAY_SIZE (mips_abi_choices) && c == NULL; i++)
    if (strncmp (mips_abi_choices[i].name, name, namelen) == 0
	&& strlen (mips_abi_choices[i].name) == namelen)
      c = &mips_abi_choices[i];

  return c;
}


static const struct mips_arch_choice *
choose_arch_by_name (const char *name, unsigned int namelen)
{
  const struct mips_arch_choice *c = NULL;
  unsigned int i;

  for (i = 0, c = NULL; i < ARRAY_SIZE (mips_arch_choices) && c == NULL; i++)
    if (strncmp (mips_arch_choices[i].name, name, namelen) == 0
	&& strlen (mips_arch_choices[i].name) == namelen)
      c = &mips_arch_choices[i];

  return c;
}

static const struct mips_arch_choice *
choose_arch_by_number (unsigned long mach)
{
  static unsigned long hint_bfd_mach;
  static const struct mips_arch_choice *hint_arch_choice;
  const struct mips_arch_choice *c;
  unsigned int i;

  /* We optimize this because even if the user specifies no
     flags, this will be done for every instruction!  */
  if (hint_bfd_mach == mach
      && hint_arch_choice
      && hint_arch_choice->bfd_mach == hint_bfd_mach)
    return hint_arch_choice;

  for (i = 0, c = NULL; i < ARRAY_SIZE (mips_arch_choices) && c == NULL; i++)
    {
      if (mips_arch_choices[i].bfd_mach_valid
	  && mips_arch_choices[i].bfd_mach == mach)
	{
	  c = &mips_arch_choices[i];
	  hint_bfd_mach = mach;
	  hint_arch_choice = c;
	}
    }
  return c;
}

/* Check if the object uses NewABI conventions.  */

static int
is_newabi (Elf_Internal_Ehdr *header)
{
  /* There are no old-style ABIs which use 64-bit ELF.  */
  if (header->e_ident[EI_CLASS] == ELFCLASS64)
    return 1;

  /* If a 32-bit ELF file, n32 is a new-style ABI.  */
  if ((header->e_flags & EF_MIPS_ABI2) != 0)
    return 1;

  return 0;
}

/* Check if the object has microMIPS ASE code.  */

static int
is_micromips (Elf_Internal_Ehdr *header)
{
  if ((header->e_flags & EF_MIPS_ARCH_ASE_MICROMIPS) != 0)
    return 1;

  return 0;
}

/* Convert ASE flags from .MIPS.abiflags to internal values.  */

static unsigned long
mips_convert_abiflags_ases (unsigned long afl_ases)
{
  unsigned long opcode_ases = 0;

  if (afl_ases & AFL_ASE_DSP)
    opcode_ases |= ASE_DSP;
  if (afl_ases & AFL_ASE_DSPR2)
    opcode_ases |= ASE_DSPR2;
  if (afl_ases & AFL_ASE_EVA)
    opcode_ases |= ASE_EVA;
  if (afl_ases & AFL_ASE_MCU)
    opcode_ases |= ASE_MCU;
  if (afl_ases & AFL_ASE_MDMX)
    opcode_ases |= ASE_MDMX;
  if (afl_ases & AFL_ASE_MIPS3D)
    opcode_ases |= ASE_MIPS3D;
  if (afl_ases & AFL_ASE_MT)
    opcode_ases |= ASE_MT;
  if (afl_ases & AFL_ASE_SMARTMIPS)
    opcode_ases |= ASE_SMARTMIPS;
  if (afl_ases & AFL_ASE_VIRT)
    opcode_ases |= ASE_VIRT;
  if (afl_ases & AFL_ASE_MSA)
    opcode_ases |= ASE_MSA;
  if (afl_ases & AFL_ASE_XPA)
    opcode_ases |= ASE_XPA;
  if (afl_ases & AFL_ASE_DSPR3)
    opcode_ases |= ASE_DSPR3;
  if (afl_ases & AFL_ASE_MIPS16E2)
    opcode_ases |= ASE_MIPS16E2;
  return opcode_ases;
}

/* Calculate combination ASE flags from regular ASE flags.  */

static unsigned long
mips_calculate_combination_ases (int opcode_isa, unsigned long opcode_ases)
{
  unsigned long combination_ases = 0;

  if ((opcode_ases & (ASE_XPA | ASE_VIRT)) == (ASE_XPA | ASE_VIRT))
    combination_ases |= ASE_XPA_VIRT;
  if ((opcode_ases & (ASE_MIPS16E2 | ASE_MT)) == (ASE_MIPS16E2 | ASE_MT))
    combination_ases |= ASE_MIPS16E2_MT;
  if ((opcode_ases & ASE_EVA)
      && ((opcode_isa & INSN_ISA_MASK) == ISA_MIPS64R6
	  || (opcode_isa & INSN_ISA_MASK) == ISA_MIPS32R6))
    combination_ases |= ASE_EVA_R6;
  return combination_ases;
}

static void
set_default_mips_dis_options (struct disassemble_info *info)
{
  const struct mips_arch_choice *chosen_arch;

  /* Defaults: mipsIII/r3000 (?!), no microMIPS ASE (any compressed code
     is MIPS16 ASE) (o)32-style ("oldabi") GPR names, and numeric FPR,
     CP0 register, and HWR names.  */  // Changed

  //Set to loongson 2F to match current radare2 default setting
  mips_isa = INSN_ISA3;
  mips_processor = CPU_LOONGSON_2F;
  micromips_ase = 0;
  mips_ase = 0;
  mips_gpr_names = mips_gpr_names_oldabi;
  mips_fpr_names = mips_fpr_names_numeric;
  mips_cp0_names = mips_cp0_names_numeric;
  mips_cp0sel_names = NULL;
  mips_cp0sel_names_len = 0;
  mips_cp1_names = mips_cp1_names_numeric;
  mips_hwr_names = mips_hwr_names_numeric;
  no_aliases = 0;

  /* Set ISA, architecture, and cp0 register names as best we can.  */
#if ! SYMTAB_AVAILABLE
  /* This is running out on a target machine, not in a host tool.
     FIXME: Where does mips_target_info come from?  */
  target_processor = mips_target_info.processor;
  mips_isa = mips_target_info.isa;
  mips_ase = mips_target_info.ase;
#else
  chosen_arch = choose_arch_by_number (info->mach);
  if (chosen_arch)
    {
      mips_processor = chosen_arch->processor;
      mips_isa = chosen_arch->isa;
      mips_ase = chosen_arch->ase;
      mips_cp0_names = chosen_arch->cp0_names;
      mips_cp0sel_names = chosen_arch->cp0sel_names;
      mips_cp0sel_names_len = chosen_arch->cp0sel_names_len;
      mips_cp1_names = chosen_arch->cp1_names;
      mips_hwr_names = chosen_arch->hwr_names;
    }

  /* Update settings according to the ELF file header flags.  */
  if (info->flavour == bfd_target_elf_flavour && info->section)
    {
      struct bfd *abfd = info->section->owner;
      Elf_Internal_Ehdr *header = elf_elfheader (abfd);
      Elf_Internal_ABIFlags_v0 *abiflags = NULL;

      /* We won't ever get here if !HAVE_BFD_MIPS_ELF_GET_ABIFLAGS,
	 because we won't then have a MIPS/ELF BFD, however we need
	 to guard against a link error in a `--enable-targets=...'
	 configuration with a 32-bit host where the MIPS target is
	 a secondary, or with MIPS/ECOFF configurations.  */
#ifdef HAVE_BFD_MIPS_ELF_GET_ABIFLAGS
      abiflags = bfd_mips_elf_get_abiflags (abfd);
#endif
      /* If an ELF "newabi" binary, use the n32/(n)64 GPR names.  */
      if (is_newabi (header))
	mips_gpr_names = mips_gpr_names_newabi;
      /* If a microMIPS binary, then don't use MIPS16 bindings.  */
      micromips_ase = is_micromips (header);
      /* OR in any extra ASE flags set in ELF file structures.  */
      if (abiflags)
	mips_ase |= mips_convert_abiflags_ases (abiflags->ases);
      else if (header->e_flags & EF_MIPS_ARCH_ASE_MDMX)
	mips_ase |= ASE_MDMX;
    }
#endif
  mips_ase |= mips_calculate_combination_ases (mips_isa, mips_ase);
}

/* Parse an ASE disassembler option and set the corresponding global
   ASE flag(s).  Return TRUE if successful, FALSE otherwise.  */

static bfd_boolean
parse_mips_ase_option (const char *option)
{
  if (CONST_STRNEQ (option, "msa"))
    {
      mips_ase |= ASE_MSA;
      if ((mips_isa & INSN_ISA_MASK) == ISA_MIPS64R2
	   || (mips_isa & INSN_ISA_MASK) == ISA_MIPS64R3
	   || (mips_isa & INSN_ISA_MASK) == ISA_MIPS64R5
	   || (mips_isa & INSN_ISA_MASK) == ISA_MIPS64R6)
	  mips_ase |= ASE_MSA64;
      return TRUE;
    }

  if (CONST_STRNEQ (option, "virt"))
    {
      mips_ase |= ASE_VIRT;
      if (mips_isa & ISA_MIPS64R2
	  || mips_isa & ISA_MIPS64R3
	  || mips_isa & ISA_MIPS64R5
	  || mips_isa & ISA_MIPS64R6)
	mips_ase |= ASE_VIRT64;
      return TRUE;
    }

  if (CONST_STRNEQ (option, "xpa"))
    {
      mips_ase |= ASE_XPA;
      return TRUE;
    }

  if (CONST_STRNEQ (option, "ginv"))
    {
      mips_ase |= ASE_GINV;
      return TRUE;
    }

  if (CONST_STRNEQ (option, "loongson-mmi"))
    {
      mips_ase |= ASE_LOONGSON_MMI;
      return TRUE;
    }

  if (CONST_STRNEQ (option, "loongson-cam"))
    {
      mips_ase |= ASE_LOONGSON_CAM;
      return TRUE;
    }

  /* Put here for match ext2 frist */
  if (CONST_STRNEQ (option, "loongson-ext2"))
    {
      mips_ase |= ASE_LOONGSON_EXT2;
      return TRUE;
    }

  if (CONST_STRNEQ (option, "loongson-ext"))
    {
      mips_ase |= ASE_LOONGSON_EXT;
      return TRUE;
    }

  return FALSE;
}

static void
parse_mips_dis_option (const char *option, unsigned int len)
{
  unsigned int i, optionlen, vallen;
  const char *val;
  const struct mips_abi_choice *chosen_abi;
  const struct mips_arch_choice *chosen_arch;

  /* Try to match options that are simple flags */
  if (CONST_STRNEQ (option, "no-aliases"))
    {
      no_aliases = 1;
      return;
    }

  if (parse_mips_ase_option (option))
    {
      mips_ase |= mips_calculate_combination_ases (mips_isa, mips_ase);
      return;
    }

  /* Look for the = that delimits the end of the option name.  */
  for (i = 0; i < len; i++)
    if (option[i] == '=')
      break;

  if (i == 0)		/* Invalid option: no name before '='.  */
    return;
  if (i == len)		/* Invalid option: no '='.  */
    return;
  if (i == (len - 1))	/* Invalid option: no value after '='.  */
    return;

  optionlen = i;
  val = option + (optionlen + 1);
  vallen = len - (optionlen + 1);

  // Appended option for matching options in asm_mips_gnu.c.
  if (strlen ("abi") == optionlen && !strncmp ("abi", option, optionlen)) {
	  chosen_abi = choose_abi_by_name (val, vallen);
	  if (chosen_abi) {
	  	mips_gpr_names = chosen_abi->gpr_names;
	  	mips_fpr_names = chosen_abi->fpr_names;
	  }
	  return;
  }

  if (strncmp ("gpr-names", option, optionlen) == 0
      && strlen ("gpr-names") == optionlen)
    {
      chosen_abi = choose_abi_by_name (val, vallen);
      if (chosen_abi)
	mips_gpr_names = chosen_abi->gpr_names;
      return;
    }

  if (strncmp ("fpr-names", option, optionlen) == 0
      && strlen ("fpr-names") == optionlen)
    {
      chosen_abi = choose_abi_by_name (val, vallen);
      if (chosen_abi)
	mips_fpr_names = chosen_abi->fpr_names;
      return;
    }

  if (strncmp ("cp0-names", option, optionlen) == 0
      && strlen ("cp0-names") == optionlen)
    {
      chosen_arch = choose_arch_by_name (val, vallen);
      if (chosen_arch)
	{
	  mips_cp0_names = chosen_arch->cp0_names;
	  mips_cp0sel_names = chosen_arch->cp0sel_names;
	  mips_cp0sel_names_len = chosen_arch->cp0sel_names_len;
	}
      return;
    }

  if (strncmp ("cp1-names", option, optionlen) == 0
      && strlen ("cp1-names") == optionlen)
    {
      chosen_arch = choose_arch_by_name (val, vallen);
      if (chosen_arch)
	mips_cp1_names = chosen_arch->cp1_names;
      return;
    }

  if (strncmp ("hwr-names", option, optionlen) == 0
      && strlen ("hwr-names") == optionlen)
    {
      chosen_arch = choose_arch_by_name (val, vallen);
      if (chosen_arch)
	mips_hwr_names = chosen_arch->hwr_names;
      return;
    }

  if (strncmp ("reg-names", option, optionlen) == 0
      && strlen ("reg-names") == optionlen)
    {
      /* We check both ABI and ARCH here unconditionally, so
	 that "numeric" will do the desirable thing: select
	 numeric register names for all registers.  Other than
	 that, a given name probably won't match both.  */
      chosen_abi = choose_abi_by_name (val, vallen);
      if (chosen_abi)
	{
	  mips_gpr_names = chosen_abi->gpr_names;
	  mips_fpr_names = chosen_abi->fpr_names;
	}
      chosen_arch = choose_arch_by_name (val, vallen);
      if (chosen_arch)
	{
	  mips_cp0_names = chosen_arch->cp0_names;
	  mips_cp0sel_names = chosen_arch->cp0sel_names;
	  mips_cp0sel_names_len = chosen_arch->cp0sel_names_len;
	  mips_cp1_names = chosen_arch->cp1_names;
	  mips_hwr_names = chosen_arch->hwr_names;
	}
      return;
    }

  /* Invalid option.  */
}

static void
parse_mips_dis_options (const char *options)
{
  const char *option_end;

  if (options == NULL)
    return;

  while (*options != '\0')
    {
      /* Skip empty options.  */
      if (*options == ',')
	{
	  options++;
	  continue;
	}

      /* We know that *options is neither NUL or a comma.  */
      option_end = options + 1;
      while (*option_end != ',' && *option_end != '\0')
	option_end++;

      parse_mips_dis_option (options, option_end - options);

      /* Go on to the next one.  If option_end points to a comma, it
	 will be skipped above.  */
      options = option_end;
    }
}

static const struct mips_cp0sel_name *
lookup_mips_cp0sel_name (const struct mips_cp0sel_name *names,
			 unsigned int len,
			 unsigned int cp0reg,
			 unsigned int sel)
{
  unsigned int i;

  for (i = 0; i < len; i++)
    if (names[i].cp0reg == cp0reg && names[i].sel == sel)
      return &names[i];
  return NULL;
}

/* Print insn arguments for 32/64-bit code.  */

/* Print register REGNO, of type TYPE, for instruction OPCODE.  */

static void
print_reg (struct disassemble_info *info, const struct mips_opcode *opcode,
	   enum mips_reg_operand_type type, int regno)
{
  switch (type)
    {
    case OP_REG_GP:
      info->fprintf_func (info->stream, "%s", mips_gpr_names[regno]);
      break;

    case OP_REG_FP:
      info->fprintf_func (info->stream, "%s", mips_fpr_names[regno]);
      break;

    case OP_REG_CCC:
      if (opcode->pinfo & (FP_D | FP_S))
	info->fprintf_func (info->stream, "$fcc%d", regno);
      else
	info->fprintf_func (info->stream, "$cc%d", regno);
      break;

    case OP_REG_VEC:
      if (opcode->membership & INSN_5400)
	info->fprintf_func (info->stream, "$f%d", regno);
      else
	info->fprintf_func (info->stream, "$v%d", regno);
      break;

    case OP_REG_ACC:
      info->fprintf_func (info->stream, "$ac%d", regno);
      break;

    case OP_REG_COPRO:
      if (opcode->name[strlen (opcode->name) - 1] == '0')
	info->fprintf_func (info->stream, "%s", mips_cp0_names[regno]);
      else if (opcode->name[strlen (opcode->name) - 1] == '1')
	info->fprintf_func (info->stream, "%s", mips_cp1_names[regno]);
      else
	info->fprintf_func (info->stream, "$%d", regno);
      break;

    case OP_REG_HW:
      info->fprintf_func (info->stream, "%s", mips_hwr_names[regno]);
      break;

    case OP_REG_VF:
      info->fprintf_func (info->stream, "$vf%d", regno);
      break;

    case OP_REG_VI:
      info->fprintf_func (info->stream, "$vi%d", regno);
      break;

    case OP_REG_R5900_I:
      info->fprintf_func (info->stream, "$I");
      break;

    case OP_REG_R5900_Q:
      info->fprintf_func (info->stream, "$Q");
      break;

    case OP_REG_R5900_R:
      info->fprintf_func (info->stream, "$R");
      break;

    case OP_REG_R5900_ACC:
      info->fprintf_func (info->stream, "$ACC");
      break;

    case OP_REG_MSA:
      info->fprintf_func (info->stream, "$w%d", regno);
      break;

    case OP_REG_MSA_CTRL:
      info->fprintf_func (info->stream, "%s", msa_control_names[regno]);
      break;

    }
}

/* Used to track the state carried over from previous operands in
   an instruction.  */
struct mips_print_arg_state {
  /* The value of the last OP_INT seen.  We only use this for OP_MSB,
     where the value is known to be unsigned and small.  */
  unsigned int last_int;

  /* The type and number of the last OP_REG seen.  We only use this for
     OP_REPEAT_DEST_REG and OP_REPEAT_PREV_REG.  */
  enum mips_reg_operand_type last_reg_type;
  unsigned int last_regno;
  unsigned int dest_regno;
  unsigned int seen_dest;
};

/* Initialize STATE for the start of an instruction.  */

static inline void
init_print_arg_state (struct mips_print_arg_state *state)
{
  memset (state, 0, sizeof (*state));
}

/* Print OP_VU0_SUFFIX or OP_VU0_MATCH_SUFFIX operand OPERAND,
   whose value is given by UVAL.  */

static void
print_vu0_channel (struct disassemble_info *info,
		   const struct mips_operand *operand, unsigned int uval)
{
  if (operand->size == 4)
    info->fprintf_func (info->stream, "%s%s%s%s",
			uval & 8 ? "x" : "",
			uval & 4 ? "y" : "",
			uval & 2 ? "z" : "",
			uval & 1 ? "w" : "");
  else if (operand->size == 2)
    info->fprintf_func (info->stream, "%c", "xyzw"[uval]);
  else
    abort ();
}

/* Record information about a register operand.  */

static void
mips_seen_register (struct mips_print_arg_state *state,
		    unsigned int regno,
		    enum mips_reg_operand_type reg_type)
{
  state->last_reg_type = reg_type;
  state->last_regno = regno;

  if (!state->seen_dest)
    {
      state->seen_dest = 1;
      state->dest_regno = regno;
    }
}

/* Print SAVE/RESTORE instruction operands according to the argument
   register mask AMASK, the number of static registers saved NSREG,
   the $ra, $s0 and $s1 register specifiers RA, S0 and S1 respectively,
   and the frame size FRAME_SIZE.  */

static void
mips_print_save_restore (struct disassemble_info *info, unsigned int amask,
			 unsigned int nsreg, unsigned int ra,
			 unsigned int s0, unsigned int s1,
			 unsigned int frame_size)
{
  const fprintf_ftype infprintf = info->fprintf_func;
  unsigned int nargs, nstatics, smask, i, j;
  void *is = info->stream;
  const char *sep;

  if (amask == MIPS_SVRS_ALL_ARGS)
    {
      nargs = 4;
      nstatics = 0;
    }
  else if (amask == MIPS_SVRS_ALL_STATICS)
    {
      nargs = 0;
      nstatics = 4;
    }
  else
    {
      nargs = amask >> 2;
      nstatics = amask & 3;
    }

  sep = "";
  if (nargs > 0)
    {
      infprintf (is, "%s", mips_gpr_names[4]);
      if (nargs > 1)
	infprintf (is, "-%s", mips_gpr_names[4 + nargs - 1]);
      sep = ",";
    }

  infprintf (is, "%s%d", sep, frame_size);

  if (ra)			/* $ra */
    infprintf (is, ",%s", mips_gpr_names[31]);

  smask = 0;
  if (s0)			/* $s0 */
    smask |= 1 << 0;
  if (s1)			/* $s1 */
    smask |= 1 << 1;
  if (nsreg > 0)		/* $s2-$s8 */
    smask |= ((1 << nsreg) - 1) << 2;

  for (i = 0; i < 9; i++)
    if (smask & (1 << i))
      {
	infprintf (is, ",%s", mips_gpr_names[i == 8 ? 30 : (16 + i)]);
	/* Skip over string of set bits.  */
	for (j = i; smask & (2 << j); j++)
	  continue;
	if (j > i)
	  infprintf (is, "-%s", mips_gpr_names[j == 8 ? 30 : (16 + j)]);
	i = j + 1;
      }
  /* Statics $ax - $a3.  */
  if (nstatics == 1)
    infprintf (is, ",%s", mips_gpr_names[7]);
  else if (nstatics > 0)
    infprintf (is, ",%s-%s",
	       mips_gpr_names[7 - nstatics + 1],
	       mips_gpr_names[7]);
}


/* Print operand OPERAND of OPCODE, using STATE to track inter-operand state.
   UVAL is the encoding of the operand (shifted into bit 0) and BASE_PC is
   the base address for OP_PCREL operands.  */

static void
print_insn_arg (struct disassemble_info *info,
		struct mips_print_arg_state *state,
		const struct mips_opcode *opcode,
		const struct mips_operand *operand,
		bfd_vma base_pc,
		unsigned int uval)
{
  const fprintf_ftype infprintf = info->fprintf_func;
  void *is = info->stream;

  switch (operand->type)
    {
    case OP_INT:
      {
	const struct mips_int_operand *int_op;

	int_op = (const struct mips_int_operand *) operand;
	uval = mips_decode_int_operand (int_op, uval);
	state->last_int = uval;
	if (int_op->print_hex)
	  infprintf (is, "0x%x", uval);
	else
	  infprintf (is, "%d", uval);
      }
      break;

    case OP_MAPPED_INT:
      {
	const struct mips_mapped_int_operand *mint_op;

	mint_op = (const struct mips_mapped_int_operand *) operand;
	uval = mint_op->int_map[uval];
	state->last_int = uval;
	if (mint_op->print_hex)
	  infprintf (is, "0x%x", uval);
	else
	  infprintf (is, "%d", uval);
      }
      break;

    case OP_MSB:
      {
	const struct mips_msb_operand *msb_op;

	msb_op = (const struct mips_msb_operand *) operand;
	uval += msb_op->bias;
	if (msb_op->add_lsb)
	  uval -= state->last_int;
	infprintf (is, "0x%x", uval);
      }
      break;

    case OP_REG:
    case OP_OPTIONAL_REG:
      {
	const struct mips_reg_operand *reg_op;

	reg_op = (const struct mips_reg_operand *) operand;
	uval = mips_decode_reg_operand (reg_op, uval);
	print_reg (info, opcode, reg_op->reg_type, uval);

	mips_seen_register (state, uval, reg_op->reg_type);
      }
      break;

    case OP_REG_PAIR:
      {
	const struct mips_reg_pair_operand *pair_op;

	pair_op = (const struct mips_reg_pair_operand *) operand;
	print_reg (info, opcode, pair_op->reg_type,
		   pair_op->reg1_map[uval]);
	infprintf (is, ",");
	print_reg (info, opcode, pair_op->reg_type,
		   pair_op->reg2_map[uval]);
      }
      break;

    case OP_PCREL:
      {
	const struct mips_pcrel_operand *pcrel_op;

	pcrel_op = (const struct mips_pcrel_operand *) operand;
	info->target = mips_decode_pcrel_operand (pcrel_op, base_pc, uval);

	/* For jumps and branches clear the ISA bit except for
	   the GDB disassembler.  */
	if (pcrel_op->include_isa_bit
	    && info->flavour != bfd_target_unknown_flavour)
	  info->target &= -2;

	(*info->print_address_func) (info->target, info);
      }
      break;

    case OP_PERF_REG:
      infprintf (is, "%d", uval);
      break;

    case OP_ADDIUSP_INT:
      {
	int sval;

	sval = mips_signed_operand (operand, uval) * 4;
	if (sval >= -8 && sval < 8)
	  sval ^= 0x400;
	infprintf (is, "%d", sval);
	break;
      }

    case OP_CLO_CLZ_DEST:
      {
	unsigned int reg1, reg2;

	reg1 = uval & 31;
	reg2 = uval >> 5;
	/* If one is zero use the other.  */
	if (reg1 == reg2 || reg2 == 0)
	  infprintf (is, "%s", mips_gpr_names[reg1]);
	else if (reg1 == 0)
	  infprintf (is, "%s", mips_gpr_names[reg2]);
	else
	  /* Bogus, result depends on processor.  */
	  infprintf (is, "%s or %s", mips_gpr_names[reg1],
		     mips_gpr_names[reg2]);
      }
      break;

    case OP_SAME_RS_RT:
    case OP_CHECK_PREV:
    case OP_NON_ZERO_REG:
      {
	print_reg (info, opcode, OP_REG_GP, uval & 31);
	mips_seen_register (state, uval, OP_REG_GP);
      }
      break;

    case OP_LWM_SWM_LIST:
      if (operand->size == 2)
	{
	  if (uval == 0)
	    infprintf (is, "%s,%s",
		       mips_gpr_names[16],
		       mips_gpr_names[31]);
	  else
	    infprintf (is, "%s-%s,%s",
		       mips_gpr_names[16],
		       mips_gpr_names[16 + uval],
		       mips_gpr_names[31]);
	}
      else
	{
	  int s_reg_encode;

	  s_reg_encode = uval & 0xf;
	  if (s_reg_encode != 0)
	    {
	      if (s_reg_encode == 1)
		infprintf (is, "%s", mips_gpr_names[16]);
	      else if (s_reg_encode < 9)
		infprintf (is, "%s-%s",
			   mips_gpr_names[16],
			   mips_gpr_names[15 + s_reg_encode]);
	      else if (s_reg_encode == 9)
		infprintf (is, "%s-%s,%s",
			   mips_gpr_names[16],
			   mips_gpr_names[23],
			   mips_gpr_names[30]);
	      else
		infprintf (is, "UNKNOWN");
	    }

	  if (uval & 0x10) /* For ra.  */
	    {
	      if (s_reg_encode == 0)
		infprintf (is, "%s", mips_gpr_names[31]);
	      else
		infprintf (is, ",%s", mips_gpr_names[31]);
	    }
	}
      break;

    case OP_ENTRY_EXIT_LIST:
      {
	const char *sep;
	unsigned int amask, smask;

	sep = "";
	amask = (uval >> 3) & 7;
	if (amask > 0 && amask < 5)
	  {
	    infprintf (is, "%s", mips_gpr_names[4]);
	    if (amask > 1)
	      infprintf (is, "-%s", mips_gpr_names[amask + 3]);
	    sep = ",";
	  }

	smask = (uval >> 1) & 3;
	if (smask == 3)
	  {
	    infprintf (is, "%s??", sep);
	    sep = ",";
	  }
	else if (smask > 0)
	  {
	    infprintf (is, "%s%s", sep, mips_gpr_names[16]);
	    if (smask > 1)
	      infprintf (is, "-%s", mips_gpr_names[smask + 15]);
	    sep = ",";
	  }

	if (uval & 1)
	  {
	    infprintf (is, "%s%s", sep, mips_gpr_names[31]);
	    sep = ",";
	  }

	if (amask == 5 || amask == 6)
	  {
	    infprintf (is, "%s%s", sep, mips_fpr_names[0]);
	    if (amask == 6)
	      infprintf (is, "-%s", mips_fpr_names[1]);
	  }
      }
      break;

    case OP_SAVE_RESTORE_LIST:
      /* Should be handled by the caller due to complex behavior.  */
      abort ();

    case OP_MDMX_IMM_REG:
      {
	unsigned int vsel;

	vsel = uval >> 5;
	uval &= 31;
	if ((vsel & 0x10) == 0)
	  {
	    int fmt;

	    vsel &= 0x0f;
	    for (fmt = 0; fmt < 3; fmt++, vsel >>= 1)
	      if ((vsel & 1) == 0)
		break;
	    print_reg (info, opcode, OP_REG_VEC, uval);
	    infprintf (is, "[%d]", vsel >> 1);
	  }
	else if ((vsel & 0x08) == 0)
	  print_reg (info, opcode, OP_REG_VEC, uval);
	else
	  infprintf (is, "0x%x", uval);
      }
      break;

    case OP_REPEAT_PREV_REG:
      print_reg (info, opcode, state->last_reg_type, state->last_regno);
      break;

    case OP_REPEAT_DEST_REG:
      print_reg (info, opcode, state->last_reg_type, state->dest_regno);
      break;

    case OP_PC:
      infprintf (is, "$pc");
      break;

    case OP_REG28:
      print_reg (info, opcode, OP_REG_GP, 28);
      break;

    case OP_VU0_SUFFIX:
    case OP_VU0_MATCH_SUFFIX:
      print_vu0_channel (info, operand, uval);
      break;

    case OP_IMM_INDEX:
      infprintf (is, "[%d]", uval);
      break;

    case OP_REG_INDEX:
      infprintf (is, "[");
      print_reg (info, opcode, OP_REG_GP, uval);
      infprintf (is, "]");
      break;
    }
}

/* Validate the arguments for INSN, which is described by OPCODE.
   Use DECODE_OPERAND to get the encoding of each operand.  */

static bfd_boolean
validate_insn_args (const struct mips_opcode *opcode,
		    const struct mips_operand *(*decode_operand) (const char *),
		    unsigned int insn)
{
  struct mips_print_arg_state state;
  const struct mips_operand *operand;
  const char *s;
  unsigned int uval;

  init_print_arg_state (&state);
  for (s = opcode->args; *s; ++s)
    {
      switch (*s)
	{
	case ',':
	case '(':
	case ')':
	  break;

	case '#':
	  ++s;
	  break;

	default:
	  operand = decode_operand (s);

	  if (operand)
	    {
	      uval = mips_extract_operand (operand, insn);
	      switch (operand->type)
		{
		case OP_REG:
		case OP_OPTIONAL_REG:
		  {
		    const struct mips_reg_operand *reg_op;

		    reg_op = (const struct mips_reg_operand *) operand;
		    uval = mips_decode_reg_operand (reg_op, uval);
		    mips_seen_register (&state, uval, reg_op->reg_type);
		  }
		break;

		case OP_SAME_RS_RT:
		  {
		    unsigned int reg1, reg2;

		    reg1 = uval & 31;
		    reg2 = uval >> 5;

		    if (reg1 != reg2 || reg1 == 0)
		      return FALSE;
		  }
		break;

		case OP_CHECK_PREV:
		  {
		    const struct mips_check_prev_operand *prev_op;

		    prev_op = (const struct mips_check_prev_operand *) operand;

		    if (!prev_op->zero_ok && uval == 0)
		      return FALSE;

		    if (((prev_op->less_than_ok && uval < state.last_regno)
			|| (prev_op->greater_than_ok && uval > state.last_regno)
			|| (prev_op->equal_ok && uval == state.last_regno)))
		      break;

		    return FALSE;
		  }

		case OP_NON_ZERO_REG:
		  {
		    if (uval == 0)
		      return FALSE;
		  }
		break;

		case OP_INT:
		case OP_MAPPED_INT:
		case OP_MSB:
		case OP_REG_PAIR:
		case OP_PCREL:
		case OP_PERF_REG:
		case OP_ADDIUSP_INT:
		case OP_CLO_CLZ_DEST:
		case OP_LWM_SWM_LIST:
		case OP_ENTRY_EXIT_LIST:
		case OP_MDMX_IMM_REG:
		case OP_REPEAT_PREV_REG:
		case OP_REPEAT_DEST_REG:
		case OP_PC:
		case OP_REG28:
		case OP_VU0_SUFFIX:
		case OP_VU0_MATCH_SUFFIX:
		case OP_IMM_INDEX:
		case OP_REG_INDEX:
		case OP_SAVE_RESTORE_LIST:
		  break;
		}
	    }
	  if (*s == 'm' || *s == '+' || *s == '-')
	    ++s;
	}
    }
  return TRUE;
}

/* Print the arguments for INSN, which is described by OPCODE.
   Use DECODE_OPERAND to get the encoding of each operand.  Use BASE_PC
   as the base of OP_PCREL operands, adjusting by LENGTH if the OP_PCREL
   operand is for a branch or jump.  */

static void
print_insn_args (struct disassemble_info *info,
		 const struct mips_opcode *opcode,
		 const struct mips_operand *(*decode_operand) (const char *),
		 unsigned int insn, bfd_vma insn_pc, unsigned int length)
{
  const fprintf_ftype infprintf = info->fprintf_func;
  void *is = info->stream;
  struct mips_print_arg_state state;
  const struct mips_operand *operand;
  const char *s;

  init_print_arg_state (&state);
  for (s = opcode->args; *s; ++s)
    {
      switch (*s)
	{
	case ',':
    infprintf(is, "%c ", *s);
    break;
	case '(':
	case ')':
	  infprintf (is, "%c", *s);
	  break;

	case '#':
	  ++s;
	  infprintf (is, "%c%c", *s, *s);
	  break;

	default:
	  operand = decode_operand (s);
	  if (!operand)
	    {
	      /* xgettext:c-format */
	      infprintf (is,
			 _("# internal error, undefined operand in `%s %s'"),
			 opcode->name, opcode->args);
	      return;
	    }

	  if (operand->type == OP_SAVE_RESTORE_LIST)
	    {
	      /* Handle this case here because of the complex behavior.  */
	      unsigned int amask = (insn >> 15) & 0xf;
	      unsigned int nsreg = (insn >> 23) & 0x7;
	      unsigned int ra = insn & 0x1000;			/* $ra */
	      unsigned int s0 = insn & 0x800;			/* $s0 */
	      unsigned int s1 = insn & 0x400;			/* $s1 */
	      unsigned int frame_size = (((insn >> 15) & 0xf0)
					 | ((insn >> 6) & 0x0f)) * 8;
	      mips_print_save_restore (info, amask, nsreg, ra, s0, s1,
				       frame_size);
	    }
	  else if (operand->type == OP_REG
		   && s[1] == ','
		   && s[2] == 'H'
		   && opcode->name[strlen (opcode->name) - 1] == '0')
	    {
	      /* Coprocessor register 0 with sel field.  */
	      const struct mips_cp0sel_name *n;
	      unsigned int reg, sel;

	      reg = mips_extract_operand (operand, insn);
	      s += 2;
	      operand = decode_operand (s);
	      sel = mips_extract_operand (operand, insn);

	      /* CP0 register including 'sel' code for mftc0, to be
		 printed textually if known.  If not known, print both
		 CP0 register name and sel numerically since CP0 register
		 with sel 0 may have a name unrelated to register being
		 printed.  */
	      n = lookup_mips_cp0sel_name (mips_cp0sel_names,
					   mips_cp0sel_names_len,
					   reg, sel);
	      if (n)
		infprintf (is, "%s", n->name);
	      else
		infprintf (is, "$%d,%d", reg, sel);
	    }
	  else
	    {
	      bfd_vma base_pc = insn_pc;

	      /* Adjust the PC relative base so that branch/jump insns use
		 the following PC as the base but genuinely PC relative
		 operands use the current PC.  */
	      if (operand->type == OP_PCREL)
		{
		  const struct mips_pcrel_operand *pcrel_op;

		  pcrel_op = (const struct mips_pcrel_operand *) operand;
		  /* The include_isa_bit flag is sufficient to distinguish
		     branch/jump from other PC relative operands.  */
		  if (pcrel_op->include_isa_bit)
		    base_pc += length;
		}

	      print_insn_arg (info, &state, opcode, operand, base_pc,
			      mips_extract_operand (operand, insn));
	    }
	  if (*s == 'm' || *s == '+' || *s == '-')
	    ++s;
	  break;
	}
    }
}

/* Print the mips instruction at address MEMADDR in debugged memory,
   on using INFO.  Returns length of the instruction, in bytes, which is
   always INSNLEN.  BIGENDIAN must be 1 if this is big-endian code, 0 if
   this is little-endian code.  */

static int
print_insn_mips (bfd_vma memaddr,
		 int word,
		 struct disassemble_info *info)
{
#define GET_OP(insn, field)			\
  (((insn) >> OP_SH_##field) & OP_MASK_##field)
  static const struct mips_opcode *mips_hash[OP_MASK_OP + 1];
  const fprintf_ftype infprintf = info->fprintf_func;
  const struct mips_opcode *op;
  static bfd_boolean init = 0;
  void *is = info->stream;

  /* Build a hash table to shorten the search time.  */
  if (! init)
    {
      unsigned int i;

      for (i = 0; i <= OP_MASK_OP; i++)
	{
	  for (op = mips_opcodes; op < &mips_opcodes[NUMOPCODES]; op++)
	    {
	      if (op->pinfo == INSN_MACRO
		  || (no_aliases && (op->pinfo2 & INSN2_ALIAS)))
		continue;
	      if (i == GET_OP (op->match, OP))
		{
		  mips_hash[i] = op;
		  break;
		}
	    }
	}

      init = 1;
    }

  info->bytes_per_chunk = INSNLEN;
  info->display_endian = info->endian;
  info->insn_info_valid = 1;
  info->branch_delay_insns = 0;
  info->data_size = 0;
  info->insn_type = dis_nonbranch;
  info->target = 0;
  info->target2 = 0;

  op = mips_hash[GET_OP (word, OP)];
  if (op)
    {
      for (; op < &mips_opcodes[NUMOPCODES]; op++)
	{
	  if (op->pinfo != INSN_MACRO
	      && !(no_aliases && (op->pinfo2 & INSN2_ALIAS))
	      && (word & op->mask) == op->match)
	    {
	      /* We always disassemble the jalx instruction, except for MIPS r6.  */
	      if (!opcode_is_member (op, mips_isa, mips_ase, mips_processor)
		 && (strcmp (op->name, "jalx")
		     || (mips_isa & INSN_ISA_MASK) == ISA_MIPS32R6
		     || (mips_isa & INSN_ISA_MASK) == ISA_MIPS64R6))
		continue;

	      /* Figure out instruction type and branch delay information.  */
	      if ((op->pinfo & INSN_UNCOND_BRANCH_DELAY) != 0)
	        {
		  if ((op->pinfo & (INSN_WRITE_GPR_31 | INSN_WRITE_1)) != 0)
		    info->insn_type = dis_jsr;
		  else
		    info->insn_type = dis_branch;
		  info->branch_delay_insns = 1;
		}
	      else if ((op->pinfo & (INSN_COND_BRANCH_DELAY
				     | INSN_COND_BRANCH_LIKELY)) != 0)
		{
		  if ((op->pinfo & INSN_WRITE_GPR_31) != 0)
		    info->insn_type = dis_condjsr;
		  else
		    info->insn_type = dis_condbranch;
		  info->branch_delay_insns = 1;
		}
	      else if ((op->pinfo & (INSN_STORE_MEMORY
				     | INSN_LOAD_MEMORY)) != 0)
		info->insn_type = dis_dref;

	      if (!validate_insn_args (op, decode_mips_operand, word))
		continue;

	      infprintf (is, "%s", op->name);
	      if (op->pinfo2 & INSN2_VU0_CHANNEL_SUFFIX)
		{
		  unsigned int uval;

		  infprintf (is, ".");
		  uval = mips_extract_operand (&mips_vu0_channel_mask, word);
		  print_vu0_channel (info, &mips_vu0_channel_mask, uval);
		}

	      if (op->args[0])
		{
		  //infprintf (is, "\t");
      //comaptible with radare2's visual mode
      infprintf (is, " ");
		  print_insn_args (info, op, decode_mips_operand, word,
				   memaddr, 4);
		}

	      return INSNLEN;
	    }
	}
    }
#undef GET_OP

  /* Handle undefined instructions.  */
  info->insn_type = dis_noninsn;
  infprintf (is, "0x%x", word);
  return INSNLEN;
}

/* Disassemble an operand for a mips16 instruction.  */

static void
print_mips16_insn_arg (struct disassemble_info *info,
		       struct mips_print_arg_state *state,
		       const struct mips_opcode *opcode,
		       char type, bfd_vma memaddr,
		       unsigned insn, bfd_boolean use_extend,
		       unsigned extend, bfd_boolean is_offset)
{
  const fprintf_ftype infprintf = info->fprintf_func;
  void *is = info->stream;
  const struct mips_operand *operand, *ext_operand;
  unsigned short ext_size;
  unsigned int uval;
  bfd_vma baseaddr;

  if (!use_extend)
    extend = 0;

  switch (type)
    {
    case ',':
    case '(':
    case ')':
      infprintf (is, "%c", type);
      break;

    default:
      operand = decode_mips16_operand (type, FALSE);
      if (!operand)
	{
	  /* xgettext:c-format */
	  infprintf (is, _("# internal error, undefined operand in `%s %s'"),
		     opcode->name, opcode->args);
	  return;
	}

      if (operand->type == OP_SAVE_RESTORE_LIST)
	{
	  /* Handle this case here because of the complex interaction
	     with the EXTEND opcode.  */
	  unsigned int amask = extend & 0xf;
	  unsigned int nsreg = (extend >> 8) & 0x7;
	  unsigned int ra = insn & 0x40;			/* $ra */
	  unsigned int s0 = insn & 0x20;			/* $s0 */
	  unsigned int s1 = insn & 0x10;			/* $s1 */
	  unsigned int frame_size = ((extend & 0xf0) | (insn & 0x0f)) * 8;
	  if (frame_size == 0 && !use_extend)
	    frame_size = 128;
	  mips_print_save_restore (info, amask, nsreg, ra, s0, s1, frame_size);
	  break;
	}

      if (is_offset && operand->type == OP_INT)
	{
	  const struct mips_int_operand *int_op;

	  int_op = (const struct mips_int_operand *) operand;
	  info->insn_type = dis_dref;
	  info->data_size = 1 << int_op->shift;
	}

      ext_size = 0;
      if (use_extend)
	{
	  ext_operand = decode_mips16_operand (type, TRUE);
	  if (ext_operand != operand
	      || (operand->type == OP_INT && operand->lsb == 0
		  && mips_opcode_32bit_p (opcode)))
	    {
	      ext_size = ext_operand->size;
	      operand = ext_operand;
	    }
	}
      if (operand->size == 26)
	uval = ((extend & 0x1f) << 21) | ((extend & 0x3e0) << 11) | insn;
      else if (ext_size == 16 || ext_size == 9)
	uval = ((extend & 0x1f) << 11) | (extend & 0x7e0) | (insn & 0x1f);
      else if (ext_size == 15)
	uval = ((extend & 0xf) << 11) | (extend & 0x7f0) | (insn & 0xf);
      else if (ext_size == 6)
	uval = ((extend >> 6) & 0x1f) | (extend & 0x20);
      else
	uval = mips_extract_operand (operand, (extend << 16) | insn);
      if (ext_size == 9)
	uval &= (1U << ext_size) - 1;

      baseaddr = memaddr + 2;
      if (operand->type == OP_PCREL)
	{
	  const struct mips_pcrel_operand *pcrel_op;

	  pcrel_op = (const struct mips_pcrel_operand *) operand;
	  if (!pcrel_op->include_isa_bit && use_extend)
	    baseaddr = memaddr - 2;
	  else if (!pcrel_op->include_isa_bit)
	    {
	      bfd_byte buffer[2];

	      /* If this instruction is in the delay slot of a JAL/JALX
		 instruction, the base address is the address of the
		 JAL/JALX instruction.  If it is in the delay slot of
		 a JR/JALR instruction, the base address is the address
		 of the JR/JALR instruction.  This test is unreliable:
		 we have no way of knowing whether the previous word is
		 instruction or data.  */
	      if (info->read_memory_func (memaddr - 4, buffer, 2, info) == 0
		  && (((info->endian == BFD_ENDIAN_BIG
			? bfd_getb16 (buffer)
			: bfd_getl16 (buffer))
		       & 0xf800) == 0x1800))
		baseaddr = memaddr - 4;
	      else if (info->read_memory_func (memaddr - 2, buffer, 2,
					       info) == 0
		       && (((info->endian == BFD_ENDIAN_BIG
			     ? bfd_getb16 (buffer)
			     : bfd_getl16 (buffer))
			    & 0xf89f) == 0xe800)
		       && (((info->endian == BFD_ENDIAN_BIG
			     ? bfd_getb16 (buffer)
			     : bfd_getl16 (buffer))
			    & 0x0060) != 0x0060))
		baseaddr = memaddr - 2;
	      else
		baseaddr = memaddr;
	    }
	}

      print_insn_arg (info, state, opcode, operand, baseaddr + 1, uval);
      break;
    }
}

/* Check if the given address is the last word of a MIPS16 PLT entry.
   This word is data and depending on the value it may interfere with
   disassembly of further PLT entries.  We make use of the fact PLT
   symbols are marked BSF_SYNTHETIC.  */

  /* This symbol was created by bfd_get_synthetic_symtab.  */
#define BSF_SYNTHETIC           (1 << 21)

static bfd_boolean
is_mips16_plt_tail (struct disassemble_info *info, bfd_vma addr)
{
  if (info->symbols
      && info->symbols[0]
      && (info->symbols[0]->flags & BSF_SYNTHETIC)
      && addr == bfd_asymbol_value (info->symbols[0]) + 12)
    return TRUE;

  return FALSE;
}

/* Whether none, a 32-bit or a 16-bit instruction match has been done.  */

enum match_kind
{
  MATCH_NONE,
  MATCH_FULL,
  MATCH_SHORT
};

/* Disassemble mips16 instructions.  */

static int
print_insn_mips16 (bfd_vma memaddr, struct disassemble_info *info)
{
  const fprintf_ftype infprintf = info->fprintf_func;
  int status;
  bfd_byte buffer[4];
  const struct mips_opcode *op, *opend;
  struct mips_print_arg_state state;
  void *is = info->stream;
  bfd_boolean have_second;
  bfd_boolean extend_only;
  unsigned int second;
  unsigned int first;
  unsigned int full;

  info->bytes_per_chunk = 2;
  info->display_endian = info->endian;
  info->insn_info_valid = 1;
  info->branch_delay_insns = 0;
  info->data_size = 0;
  info->target = 0;
  info->target2 = 0;

#define GET_OP(insn, field) \
  (((insn) >> MIPS16OP_SH_##field) & MIPS16OP_MASK_##field)
  /* Decode PLT entry's GOT slot address word.  */
  if (is_mips16_plt_tail (info, memaddr))
    {
      info->insn_type = dis_noninsn;
      status = (*info->read_memory_func) (memaddr, buffer, 4, info);
      if (status == 0)
	{
	  unsigned int gotslot;

	  if (info->endian == BFD_ENDIAN_BIG)
	    gotslot = bfd_getb32 (buffer);
	  else
	    gotslot = bfd_getl32 (buffer);
	  infprintf (is, ".word\t0x%x", gotslot);

	  return 4;
	}
    }
  else
    {
      info->insn_type = dis_nonbranch;
      status = (*info->read_memory_func) (memaddr, buffer, 2, info);
    }
  if (status != 0)
    {
      (*info->memory_error_func) (status, memaddr, info);
      return -1;
    }

  extend_only = FALSE;

  if (info->endian == BFD_ENDIAN_BIG)
    first = bfd_getb16 (buffer);
  else
    first = bfd_getl16 (buffer);

  status = (*info->read_memory_func) (memaddr + 2, buffer, 2, info);
  if (status == 0)
    {
      have_second = TRUE;
      if (info->endian == BFD_ENDIAN_BIG)
	second = bfd_getb16 (buffer);
      else
	second = bfd_getl16 (buffer);
      full = (first << 16) | second;
    }
  else
    {
      have_second = FALSE;
      second = 0;
      full = first;
    }

  /* FIXME: Should probably use a hash table on the major opcode here.  */

  opend = mips16_opcodes + bfd_mips16_num_opcodes;
  for (op = mips16_opcodes; op < opend; op++)
    {
      enum match_kind match;

      if (!opcode_is_member (op, mips_isa, mips_ase, mips_processor))
	continue;

      if (op->pinfo == INSN_MACRO
	  || (no_aliases && (op->pinfo2 & INSN2_ALIAS)))
	match = MATCH_NONE;
      else if (mips_opcode_32bit_p (op))
	{
	  if (have_second
	      && (full & op->mask) == op->match)
	    match = MATCH_FULL;
	  else
	    match = MATCH_NONE;
	}
      else if ((first & op->mask) == op->match)
	{
	  match = MATCH_SHORT;
	  second = 0;
	  full = first;
	}
      else if ((first & 0xf800) == 0xf000
	       && have_second
	       && !extend_only
	       && (second & op->mask) == op->match)
	{
	  if (op->pinfo2 & INSN2_SHORT_ONLY)
	    {
	      match = MATCH_NONE;
	      extend_only = TRUE;
	    }
	  else
	    match = MATCH_FULL;
	}
      else
	match = MATCH_NONE;

      if (match != MATCH_NONE)
	{
	  const char *s;

	  infprintf (is, "%s", op->name);
	  if (op->args[0] != '\0')
	    // infprintf (is, "\t");
      infprintf (is, " ");

	  init_print_arg_state (&state);
	  for (s = op->args; *s != '\0'; s++)
	    {
	      if (*s == ','
		  && s[1] == 'w'
		  && GET_OP (full, RX) == GET_OP (full, RY))
		{
		  /* Skip the register and the comma.  */
		  ++s;
		  continue;
		}
	      if (*s == ','
		  && s[1] == 'v'
		  && GET_OP (full, RZ) == GET_OP (full, RX))
		{
		  /* Skip the register and the comma.  */
		  ++s;
		  continue;
		}
	      if (s[0] == 'N'
		  && s[1] == ','
		  && s[2] == 'O'
		  && op->name[strlen (op->name) - 1] == '0')
		{
		  /* Coprocessor register 0 with sel field.  */
		  const struct mips_cp0sel_name *n;
		  const struct mips_operand *operand;
		  unsigned int reg, sel;

		  operand = decode_mips16_operand (*s, TRUE);
		  reg = mips_extract_operand (operand, (first << 16) | second);
		  s += 2;
		  operand = decode_mips16_operand (*s, TRUE);
		  sel = mips_extract_operand (operand, (first << 16) | second);

		  /* CP0 register including 'sel' code for mftc0, to be
		     printed textually if known.  If not known, print both
		     CP0 register name and sel numerically since CP0 register
		     with sel 0 may have a name unrelated to register being
		     printed.  */
		  n = lookup_mips_cp0sel_name (mips_cp0sel_names,
					       mips_cp0sel_names_len,
					       reg, sel);
		  if (n)
		    infprintf (is, "%s", n->name);
		  else
		    infprintf (is, "$%d,%d", reg, sel);
		}
	      else
		switch (match)
		  {
		    case MATCH_FULL:
		      print_mips16_insn_arg (info, &state, op, *s, memaddr + 2,
					     second, TRUE, first, s[1] == '(');
		      break;
		    case MATCH_SHORT:
		      print_mips16_insn_arg (info, &state, op, *s, memaddr,
					     first, FALSE, 0, s[1] == '(');
		      break;
		    case MATCH_NONE:	/* Stop the compiler complaining.  */
		      break;
		  }
	    }

	  /* Figure out branch instruction type and delay slot information.  */
	  if ((op->pinfo & INSN_UNCOND_BRANCH_DELAY) != 0)
	    info->branch_delay_insns = 1;
	  if ((op->pinfo & INSN_UNCOND_BRANCH_DELAY) != 0
	      || (op->pinfo2 & INSN2_UNCOND_BRANCH) != 0)
	    {
	      if ((op->pinfo & INSN_WRITE_GPR_31) != 0)
		info->insn_type = dis_jsr;
	      else
		info->insn_type = dis_branch;
	    }
	  else if ((op->pinfo2 & INSN2_COND_BRANCH) != 0)
	    info->insn_type = dis_condbranch;

	  return match == MATCH_FULL ? 4 : 2;
	}
    }
#undef GET_OP

  infprintf (is, "0x%x", first);
  info->insn_type = dis_noninsn;

  return 2;
}

/* Disassemble microMIPS instructions.  */

static int
print_insn_micromips (bfd_vma memaddr, struct disassemble_info *info)
{
  const fprintf_ftype infprintf = info->fprintf_func;
  const struct mips_opcode *op, *opend;
  void *is = info->stream;
  bfd_byte buffer[2];
  unsigned int higher;
  unsigned int length;
  int status;
  unsigned int insn;

  info->bytes_per_chunk = 2;
  info->display_endian = info->endian;
  info->insn_info_valid = 1;
  info->branch_delay_insns = 0;
  info->data_size = 0;
  info->insn_type = dis_nonbranch;
  info->target = 0;
  info->target2 = 0;

  status = (*info->read_memory_func) (memaddr, buffer, 2, info);
  if (status != 0)
    {
      (*info->memory_error_func) (status, memaddr, info);
      return -1;
    }

  length = 2;

  if (info->endian == BFD_ENDIAN_BIG)
    insn = bfd_getb16 (buffer);
  else
    insn = bfd_getl16 (buffer);

  if ((insn & 0x1c00) == 0x0000 || (insn & 0x1000) == 0x1000)
    {
      /* This is a 32-bit microMIPS instruction.  */
      higher = insn;

      status = (*info->read_memory_func) (memaddr + 2, buffer, 2, info);
      if (status != 0)
	{
	  infprintf (is, "micromips 0x%x", higher);
	  (*info->memory_error_func) (status, memaddr + 2, info);
	  return -1;
	}

      if (info->endian == BFD_ENDIAN_BIG)
	insn = bfd_getb16 (buffer);
      else
	insn = bfd_getl16 (buffer);

      insn = insn | (higher << 16);

      length += 2;
    }

  /* FIXME: Should probably use a hash table on the major opcode here.  */

  opend = micromips_opcodes + bfd_micromips_num_opcodes;
  for (op = micromips_opcodes; op < opend; op++)
    {
      if (op->pinfo != INSN_MACRO
	  && !(no_aliases && (op->pinfo2 & INSN2_ALIAS))
	  && (insn & op->mask) == op->match
	  && ((length == 2 && (op->mask & 0xffff0000) == 0)
	      || (length == 4 && (op->mask & 0xffff0000) != 0)))
	{
	  if (!validate_insn_args (op, decode_micromips_operand, insn))
	    continue;

	  infprintf (is, "%s", op->name);

	  if (op->args[0])
	    {
	      //infprintf (is, "\t");
        infprintf (is, " ");
	      print_insn_args (info, op, decode_micromips_operand, insn,
			       memaddr + 1, length);
	    }

	  /* Figure out instruction type and branch delay information.  */
	  if ((op->pinfo
	       & (INSN_UNCOND_BRANCH_DELAY | INSN_COND_BRANCH_DELAY)) != 0)
	    info->branch_delay_insns = 1;
	  if (((op->pinfo & INSN_UNCOND_BRANCH_DELAY)
	       | (op->pinfo2 & INSN2_UNCOND_BRANCH)) != 0)
	    {
	      if ((op->pinfo & (INSN_WRITE_GPR_31 | INSN_WRITE_1)) != 0)
		info->insn_type = dis_jsr;
	      else
		info->insn_type = dis_branch;
	    }
	  else if (((op->pinfo & INSN_COND_BRANCH_DELAY)
		    | (op->pinfo2 & INSN2_COND_BRANCH)) != 0)
	    {
	      if ((op->pinfo & INSN_WRITE_GPR_31) != 0)
		info->insn_type = dis_condjsr;
	      else
		info->insn_type = dis_condbranch;
	    }
	  else if ((op->pinfo
		    & (INSN_STORE_MEMORY | INSN_LOAD_MEMORY)) != 0)
	    info->insn_type = dis_dref;

	  return length;
	}
    }

  infprintf (is, "0x%x", insn);
  info->insn_type = dis_noninsn;

  return length;
}

/* Return 1 if a symbol associated with the location being disassembled
   indicates a compressed mode, either MIPS16 or microMIPS, according to
   MICROMIPS_P.  We iterate over all the symbols at the address being
   considered assuming if at least one of them indicates code compression,
   then such code has been genuinely produced here (other symbols could
   have been derived from function symbols defined elsewhere or could
   define data).  Otherwise, return 0.  */

static bfd_boolean
is_compressed_mode_p (struct disassemble_info *info, bfd_boolean micromips_p)
{
  int i;
  int l;

  for (i = info->symtab_pos, l = i + info->num_symbols; i < l; i++)
    if (((info->symtab[i])->flags & BSF_SYNTHETIC) != 0
	&& ((!micromips_p
	     && ELF_ST_IS_MIPS16 ((*info->symbols)->udata.i))
	    || (micromips_p
		&& ELF_ST_IS_MICROMIPS ((*info->symbols)->udata.i))))
      return 1;
    else if (bfd_asymbol_flavour (info->symtab[i]) == bfd_target_elf_flavour
	      && info->symtab[i]->section == info->section)
      {
	elf_symbol_type *symbol = (elf_symbol_type *) info->symtab[i];
	if ((!micromips_p
	     && ELF_ST_IS_MIPS16 (symbol->internal_elf_sym.st_other))
	    || (micromips_p
		&& ELF_ST_IS_MICROMIPS (symbol->internal_elf_sym.st_other)))
	  return 1;
      }

  return 0;
}

/* In an environment where we do not know the symbol type of the
   instruction we are forced to assume that the low order bit of the
   instructions' address may mark it as a mips16 instruction.  If we
   are single stepping, or the pc is within the disassembled function,
   this works.  Otherwise, we need a clue.  Sometimes.  */

static int
_print_insn_mips (bfd_vma memaddr,
		  struct disassemble_info *info,
		  enum bfd_endian endianness)
{
  bfd_byte buffer[INSNLEN];
  int status;

  set_default_mips_dis_options (info);
  parse_mips_dis_options (info->disassembler_options);

  if (info->mach == bfd_mach_mips16)
    return print_insn_mips16 (memaddr, info);
  if (info->mach == bfd_mach_mips_micromips)
    return print_insn_micromips (memaddr, info);

#if 1
  /* FIXME: If odd address, this is CLEARLY a compressed instruction.  */
  /* Only a few tools will work this way.  */
  if (memaddr & 0x01)
    {
      if (micromips_ase)
	return print_insn_micromips (memaddr, info);
      else
	return print_insn_mips16 (memaddr, info);
    }
#endif

#if SYMTAB_AVAILABLE
  if (is_compressed_mode_p (info, TRUE))
    return print_insn_micromips (memaddr, info);
  if (is_compressed_mode_p (info, FALSE))
    return print_insn_mips16 (memaddr, info);
#endif

  status = (*info->read_memory_func) (memaddr, buffer, INSNLEN, info);
  if (status == 0)
    {
      int insn;

      if (endianness == BFD_ENDIAN_BIG)
	insn = bfd_getb32 (buffer);
      else
	insn = bfd_getl32 (buffer);

      return print_insn_mips (memaddr, insn, info);
    }
  else
    {
      (*info->memory_error_func) (status, memaddr, info);
      return -1;
    }
}

int
print_insn_big_mips (bfd_vma memaddr, struct disassemble_info *info)
{
  return _print_insn_mips (memaddr, info, BFD_ENDIAN_BIG);
}

int
print_insn_little_mips (bfd_vma memaddr, struct disassemble_info *info)
{
  return _print_insn_mips (memaddr, info, BFD_ENDIAN_LITTLE);
}

/* Indices into option argument vector for options accepting an argument.
   Use MIPS_OPTION_ARG_NONE for options accepting no argument.  */
// typedef enum
// {
//   MIPS_OPTION_ARG_NONE = -1,
//   MIPS_OPTION_ARG_ABI,
//   MIPS_OPTION_ARG_ARCH,
//   MIPS_OPTION_ARG_SIZE
// } mips_option_arg_t;

