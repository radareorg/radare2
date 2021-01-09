/* Xtensa configuration-specific ISA information.
   Copyright (C) 2003-2015 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef ATTRIBUTE_UNUSED
#define ATTRIBUTE_UNUSED
#endif
//#include "ansidecl.h"
#include "../../include/xtensa-isa.h"
#include "../../include/xtensa-isa-internal.h"


/* Sysregs.  */

static xtensa_sysreg_internal sysregs[] = {
  { "LBEG", 0, 0 },
  { "LEND", 1, 0 },
  { "LCOUNT", 2, 0 },
  { "BR", 4, 0 },
  { "ACCLO", 16, 0 },
  { "ACCHI", 17, 0 },
  { "M0", 32, 0 },
  { "M1", 33, 0 },
  { "M2", 34, 0 },
  { "M3", 35, 0 },
  { "PTEVADDR", 83, 0 },
  { "MMID", 89, 0 },
  { "DDR", 104, 0 },
  { "176", 176, 0 },
  { "208", 208, 0 },
  { "INTERRUPT", 226, 0 },
  { "INTCLEAR", 227, 0 },
  { "CCOUNT", 234, 0 },
  { "PRID", 235, 0 },
  { "ICOUNT", 236, 0 },
  { "CCOMPARE0", 240, 0 },
  { "CCOMPARE1", 241, 0 },
  { "CCOMPARE2", 242, 0 },
  { "VECBASE", 231, 0 },
  { "EPC1", 177, 0 },
  { "EPC2", 178, 0 },
  { "EPC3", 179, 0 },
  { "EPC4", 180, 0 },
  { "EPC5", 181, 0 },
  { "EPC6", 182, 0 },
  { "EPC7", 183, 0 },
  { "EXCSAVE1", 209, 0 },
  { "EXCSAVE2", 210, 0 },
  { "EXCSAVE3", 211, 0 },
  { "EXCSAVE4", 212, 0 },
  { "EXCSAVE5", 213, 0 },
  { "EXCSAVE6", 214, 0 },
  { "EXCSAVE7", 215, 0 },
  { "EPS2", 194, 0 },
  { "EPS3", 195, 0 },
  { "EPS4", 196, 0 },
  { "EPS5", 197, 0 },
  { "EPS6", 198, 0 },
  { "EPS7", 199, 0 },
  { "EXCCAUSE", 232, 0 },
  { "DEPC", 192, 0 },
  { "EXCVADDR", 238, 0 },
  { "WINDOWBASE", 72, 0 },
  { "WINDOWSTART", 73, 0 },
  { "SAR", 3, 0 },
  { "LITBASE", 5, 0 },
  { "PS", 230, 0 },
  { "MISC0", 244, 0 },
  { "MISC1", 245, 0 },
  { "MISC2", 246, 0 },
  { "MISC3", 247, 0 },
  { "INTENABLE", 228, 0 },
  { "DBREAKA0", 144, 0 },
  { "DBREAKC0", 160, 0 },
  { "DBREAKA1", 145, 0 },
  { "DBREAKC1", 161, 0 },
  { "IBREAKA0", 128, 0 },
  { "IBREAKA1", 129, 0 },
  { "IBREAKENABLE", 96, 0 },
  { "ICOUNTLEVEL", 237, 0 },
  { "DEBUGCAUSE", 233, 0 },
  { "RASID", 90, 0 },
  { "ITLBCFG", 91, 0 },
  { "DTLBCFG", 92, 0 },
  { "CPENABLE", 224, 0 },
  { "SCOMPARE1", 12, 0 },
  { "THREADPTR", 231, 1 },
  { "FCR", 232, 1 },
  { "FSR", 233, 1 }
};

#define NUM_SYSREGS 74
#define MAX_SPECIAL_REG 247
#define MAX_USER_REG 233


/* Processor states.  */

static xtensa_state_internal states[] = {
  { "LCOUNT", 32, 0 },
  { "PC", 32, 0 },
  { "ICOUNT", 32, 0 },
  { "DDR", 32, 0 },
  { "INTERRUPT", 32, 0 },
  { "CCOUNT", 32, 0 },
  { "XTSYNC", 1, 0 },
  { "VECBASE", 22, 0 },
  { "EPC1", 32, 0 },
  { "EPC2", 32, 0 },
  { "EPC3", 32, 0 },
  { "EPC4", 32, 0 },
  { "EPC5", 32, 0 },
  { "EPC6", 32, 0 },
  { "EPC7", 32, 0 },
  { "EXCSAVE1", 32, 0 },
  { "EXCSAVE2", 32, 0 },
  { "EXCSAVE3", 32, 0 },
  { "EXCSAVE4", 32, 0 },
  { "EXCSAVE5", 32, 0 },
  { "EXCSAVE6", 32, 0 },
  { "EXCSAVE7", 32, 0 },
  { "EPS2", 15, 0 },
  { "EPS3", 15, 0 },
  { "EPS4", 15, 0 },
  { "EPS5", 15, 0 },
  { "EPS6", 15, 0 },
  { "EPS7", 15, 0 },
  { "EXCCAUSE", 6, 0 },
  { "PSINTLEVEL", 4, 0 },
  { "PSUM", 1, 0 },
  { "PSWOE", 1, 0 },
  { "PSRING", 2, 0 },
  { "PSEXCM", 1, 0 },
  { "DEPC", 32, 0 },
  { "EXCVADDR", 32, 0 },
  { "WindowBase", 4, 0 },
  { "WindowStart", 16, 0 },
  { "PSCALLINC", 2, 0 },
  { "PSOWB", 4, 0 },
  { "LBEG", 32, 0 },
  { "LEND", 32, 0 },
  { "SAR", 6, 0 },
  { "THREADPTR", 32, 0 },
  { "LITBADDR", 20, 0 },
  { "LITBEN", 1, 0 },
  { "MISC0", 32, 0 },
  { "MISC1", 32, 0 },
  { "MISC2", 32, 0 },
  { "MISC3", 32, 0 },
  { "ACC", 40, 0 },
  { "InOCDMode", 1, 0 },
  { "INTENABLE", 32, 0 },
  { "DBREAKA0", 32, 0 },
  { "DBREAKC0", 8, 0 },
  { "DBREAKA1", 32, 0 },
  { "DBREAKC1", 8, 0 },
  { "IBREAKA0", 32, 0 },
  { "IBREAKA1", 32, 0 },
  { "IBREAKENABLE", 2, 0 },
  { "ICOUNTLEVEL", 4, 0 },
  { "DEBUGCAUSE", 6, 0 },
  { "DBNUM", 4, 0 },
  { "CCOMPARE0", 32, 0 },
  { "CCOMPARE1", 32, 0 },
  { "CCOMPARE2", 32, 0 },
  { "ASID3", 8, 0 },
  { "ASID2", 8, 0 },
  { "ASID1", 8, 0 },
  { "INSTPGSZID4", 2, 0 },
  { "DATAPGSZID4", 2, 0 },
  { "PTBASE", 10, 0 },
  { "CPENABLE", 1, 0 },
  { "SCOMPARE1", 32, 0 },
  { "RoundMode", 2, 0 },
  { "InvalidEnable", 1, 0 },
  { "DivZeroEnable", 1, 0 },
  { "OverflowEnable", 1, 0 },
  { "UnderflowEnable", 1, 0 },
  { "InexactEnable", 1, 0 },
  { "InvalidFlag", 1, 0 },
  { "DivZeroFlag", 1, 0 },
  { "OverflowFlag", 1, 0 },
  { "UnderflowFlag", 1, 0 },
  { "InexactFlag", 1, 0 },
  { "FPreserved20", 20, 0 },
  { "FPreserved20a", 20, 0 },
  { "FPreserved5", 5, 0 },
  { "FPreserved7", 7, 0 }
};

#define NUM_STATES 89

/* Macros for xtensa_state numbers (for use in iclasses because the
   state numbers are not available when the iclass table is generated).  */

#define STATE_LCOUNT 0
#define STATE_PC 1
#define STATE_ICOUNT 2
#define STATE_DDR 3
#define STATE_INTERRUPT 4
#define STATE_CCOUNT 5
#define STATE_XTSYNC 6
#define STATE_VECBASE 7
#define STATE_EPC1 8
#define STATE_EPC2 9
#define STATE_EPC3 10
#define STATE_EPC4 11
#define STATE_EPC5 12
#define STATE_EPC6 13
#define STATE_EPC7 14
#define STATE_EXCSAVE1 15
#define STATE_EXCSAVE2 16
#define STATE_EXCSAVE3 17
#define STATE_EXCSAVE4 18
#define STATE_EXCSAVE5 19
#define STATE_EXCSAVE6 20
#define STATE_EXCSAVE7 21
#define STATE_EPS2 22
#define STATE_EPS3 23
#define STATE_EPS4 24
#define STATE_EPS5 25
#define STATE_EPS6 26
#define STATE_EPS7 27
#define STATE_EXCCAUSE 28
#define STATE_PSINTLEVEL 29
#define STATE_PSUM 30
#define STATE_PSWOE 31
#define STATE_PSRING 32
#define STATE_PSEXCM 33
#define STATE_DEPC 34
#define STATE_EXCVADDR 35
#define STATE_WindowBase 36
#define STATE_WindowStart 37
#define STATE_PSCALLINC 38
#define STATE_PSOWB 39
#define STATE_LBEG 40
#define STATE_LEND 41
#define STATE_SAR 42
#define STATE_THREADPTR 43
#define STATE_LITBADDR 44
#define STATE_LITBEN 45
#define STATE_MISC0 46
#define STATE_MISC1 47
#define STATE_MISC2 48
#define STATE_MISC3 49
#define STATE_ACC 50
#define STATE_InOCDMode 51
#define STATE_INTENABLE 52
#define STATE_DBREAKA0 53
#define STATE_DBREAKC0 54
#define STATE_DBREAKA1 55
#define STATE_DBREAKC1 56
#define STATE_IBREAKA0 57
#define STATE_IBREAKA1 58
#define STATE_IBREAKENABLE 59
#define STATE_ICOUNTLEVEL 60
#define STATE_DEBUGCAUSE 61
#define STATE_DBNUM 62
#define STATE_CCOMPARE0 63
#define STATE_CCOMPARE1 64
#define STATE_CCOMPARE2 65
#define STATE_ASID3 66
#define STATE_ASID2 67
#define STATE_ASID1 68
#define STATE_INSTPGSZID4 69
#define STATE_DATAPGSZID4 70
#define STATE_PTBASE 71
#define STATE_CPENABLE 72
#define STATE_SCOMPARE1 73
#define STATE_RoundMode 74
#define STATE_InvalidEnable 75
#define STATE_DivZeroEnable 76
#define STATE_OverflowEnable 77
#define STATE_UnderflowEnable 78
#define STATE_InexactEnable 79
#define STATE_InvalidFlag 80
#define STATE_DivZeroFlag 81
#define STATE_OverflowFlag 82
#define STATE_UnderflowFlag 83
#define STATE_InexactFlag 84
#define STATE_FPreserved20 85
#define STATE_FPreserved20a 86
#define STATE_FPreserved5 87
#define STATE_FPreserved7 88


/* Field definitions.  */

static unsigned
Field_t_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_t_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
}

static unsigned
Field_t_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_t_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
}

static unsigned
Field_t_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_t_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
}

static unsigned
Field_t_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_t_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
}

static unsigned
Field_t_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_t_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
}

static unsigned
Field_t_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_t_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
}

static unsigned
Field_t_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_t_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
}

static unsigned
Field_bbi4_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  return tie_t;
}

static void
Field_bbi4_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_bbi_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_bbi_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_bbi_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_bbi_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
}

static unsigned
Field_imm12_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 12) | ((insn[0] << 8) >> 20);
  return tie_t;
}

static void
Field_imm12_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 20) >> 20;
  insn[0] = (insn[0] & ~0xfff000) | (tie_t << 12);
}

static unsigned
Field_imm8_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 8) | ((insn[0] << 8) >> 24);
  return tie_t;
}

static void
Field_imm8_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 24) >> 24;
  insn[0] = (insn[0] & ~0xff0000) | (tie_t << 16);
}

static unsigned
Field_imm8_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 8) | ((insn[0] << 12) >> 24);
  return tie_t;
}

static void
Field_imm8_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 24) >> 24;
  insn[0] = (insn[0] & ~0xff000) | (tie_t << 12);
}

static unsigned
Field_imm8_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_imm8_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 24) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_s_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_s_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_s_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_s_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_s_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_s_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_s_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_s_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
}

static unsigned
Field_s_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_s_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_s_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_s_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_s_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_s_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
}

static unsigned
Field_imm12b_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  tie_t = (tie_t << 8) | ((insn[0] << 8) >> 24);
  return tie_t;
}

static void
Field_imm12b_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 24) >> 24;
  insn[0] = (insn[0] & ~0xff0000) | (tie_t << 16);
  tie_t = (val << 20) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_imm12b_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  tie_t = (tie_t << 8) | ((insn[0] << 12) >> 24);
  return tie_t;
}

static void
Field_imm12b_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 24) >> 24;
  insn[0] = (insn[0] & ~0xff000) | (tie_t << 12);
  tie_t = (val << 20) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
}

static unsigned
Field_imm12b_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 12) | ((insn[0] << 16) >> 20);
  return tie_t;
}

static void
Field_imm12b_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 20) >> 20;
  insn[0] = (insn[0] & ~0xfff0) | (tie_t << 4);
}

static unsigned
Field_imm16_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 16) | ((insn[0] << 8) >> 16);
  return tie_t;
}

static void
Field_imm16_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 16) >> 16;
  insn[0] = (insn[0] & ~0xffff00) | (tie_t << 8);
}

static unsigned
Field_imm16_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 16) | ((insn[0] << 12) >> 16);
  return tie_t;
}

static void
Field_imm16_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 16) >> 16;
  insn[0] = (insn[0] & ~0xffff0) | (tie_t << 4);
}

static unsigned
Field_m_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 24) >> 30);
  return tie_t;
}

static void
Field_m_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc0) | (tie_t << 6);
}

static unsigned
Field_m_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 28) >> 30);
  return tie_t;
}

static void
Field_m_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc) | (tie_t << 2);
}

static unsigned
Field_n_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 26) >> 30);
  return tie_t;
}

static void
Field_n_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x30) | (tie_t << 4);
}

static unsigned
Field_n_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 30) >> 30);
  return tie_t;
}

static void
Field_n_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x3) | (tie_t << 0);
}

static unsigned
Field_offset_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 18) | ((insn[0] << 8) >> 14);
  return tie_t;
}

static void
Field_offset_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 14) >> 14;
  insn[0] = (insn[0] & ~0xffffc0) | (tie_t << 6);
}

static unsigned
Field_offset_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 18) | ((insn[0] << 14) >> 14);
  return tie_t;
}

static void
Field_offset_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 14) >> 14;
  insn[0] = (insn[0] & ~0x3ffff) | (tie_t << 0);
}

static unsigned
Field_op0_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_op0_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
}

static unsigned
Field_op0_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_op0_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
}

static unsigned
Field_op0_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_op0_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
}

static unsigned
Field_op1_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 12) >> 28);
  return tie_t;
}

static void
Field_op1_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0000) | (tie_t << 16);
}

static unsigned
Field_op1_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_op1_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_op2_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 8) >> 28);
  return tie_t;
}

static void
Field_op2_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00000) | (tie_t << 20);
}

static unsigned
Field_op2_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 12) >> 28);
  return tie_t;
}

static void
Field_op2_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0000) | (tie_t << 16);
}

static unsigned
Field_op2_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_op2_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_r_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_r_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_r_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_r_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_r_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_r_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_r_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_r_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_r_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_r_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
}

static unsigned
Field_r_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_r_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
}

static unsigned
Field_r_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_r_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
}

static unsigned
Field_sa4_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 11) >> 31);
  return tie_t;
}

static void
Field_sa4_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x100000) | (tie_t << 20);
}

static unsigned
Field_sae4_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 15) >> 31);
  return tie_t;
}

static void
Field_sae4_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x10000) | (tie_t << 16);
}

static unsigned
Field_sae4_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  return tie_t;
}

static void
Field_sae4_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_sae_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 15) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_sae_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x10000) | (tie_t << 16);
}

static unsigned
Field_sae_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_sae_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_sae_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 5) | ((insn[0] << 15) >> 27);
  return tie_t;
}

static void
Field_sae_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 27) >> 27;
  insn[0] = (insn[0] & ~0x1f000) | (tie_t << 12);
}

static unsigned
Field_sal_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 11) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_sal_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x100000) | (tie_t << 20);
}

static unsigned
Field_sal_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 15) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_sal_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x10000) | (tie_t << 16);
}

static unsigned
Field_sal_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_sal_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_sargt_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 11) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_sargt_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x100000) | (tie_t << 20);
}

static unsigned
Field_sargt_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 15) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_sargt_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x10000) | (tie_t << 16);
}

static unsigned
Field_sargt_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 5) | ((insn[0] << 19) >> 27);
  return tie_t;
}

static void
Field_sargt_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 27) >> 27;
  insn[0] = (insn[0] & ~0x1f00) | (tie_t << 8);
}

static unsigned
Field_sargt_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 5) | ((insn[0] << 19) >> 27);
  return tie_t;
}

static void
Field_sargt_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 27) >> 27;
  insn[0] = (insn[0] & ~0x1f00) | (tie_t << 8);
}

static unsigned
Field_sas4_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 27) >> 31);
  return tie_t;
}

static void
Field_sas4_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x10) | (tie_t << 4);
}

static unsigned
Field_sas_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 27) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_sas_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x10) | (tie_t << 4);
}

static unsigned
Field_sas_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 31) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_sas_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x1) | (tie_t << 0);
}

static unsigned
Field_sr_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_sr_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
  tie_t = (val << 24) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_sr_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_sr_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
  tie_t = (val << 24) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_sr_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_sr_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
  tie_t = (val << 24) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_st_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_st_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 24) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_st_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_st_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 24) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_st_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  tie_t = (tie_t << 4) | ((insn[0] << 24) >> 28);
  return tie_t;
}

static void
Field_st_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf0) | (tie_t << 4);
  tie_t = (val << 24) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_thi3_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 24) >> 29);
  return tie_t;
}

static void
Field_thi3_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe0) | (tie_t << 5);
}

static unsigned
Field_thi3_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 28) >> 29);
  return tie_t;
}

static void
Field_thi3_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe) | (tie_t << 1);
}

static unsigned
Field_imm4_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm4_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_imm4_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm4_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_imm4_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm4_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_mn_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 24) >> 30);
  tie_t = (tie_t << 2) | ((insn[0] << 26) >> 30);
  return tie_t;
}

static void
Field_mn_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x30) | (tie_t << 4);
  tie_t = (val << 28) >> 30;
  insn[0] = (insn[0] & ~0xc0) | (tie_t << 6);
}

static unsigned
Field_i_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  return tie_t;
}

static void
Field_i_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_i_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  return tie_t;
}

static void
Field_i_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_imm6lo_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm6lo_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_imm6lo_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm6lo_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_imm6hi_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 26) >> 30);
  return tie_t;
}

static void
Field_imm6hi_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x30) | (tie_t << 4);
}

static unsigned
Field_imm6hi_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 26) >> 30);
  return tie_t;
}

static void
Field_imm6hi_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x30) | (tie_t << 4);
}

static unsigned
Field_imm7lo_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm7lo_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_imm7lo_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm7lo_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_imm7hi_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 25) >> 29);
  return tie_t;
}

static void
Field_imm7hi_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0x70) | (tie_t << 4);
}

static unsigned
Field_imm7hi_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 25) >> 29);
  return tie_t;
}

static void
Field_imm7hi_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0x70) | (tie_t << 4);
}

static unsigned
Field_z_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 25) >> 31);
  return tie_t;
}

static void
Field_z_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x40) | (tie_t << 6);
}

static unsigned
Field_z_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 25) >> 31);
  return tie_t;
}

static void
Field_z_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x40) | (tie_t << 6);
}

static unsigned
Field_imm6_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 26) >> 30);
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm6_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
  tie_t = (val << 26) >> 30;
  insn[0] = (insn[0] & ~0x30) | (tie_t << 4);
}

static unsigned
Field_imm6_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 26) >> 30);
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm6_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
  tie_t = (val << 26) >> 30;
  insn[0] = (insn[0] & ~0x30) | (tie_t << 4);
}

static unsigned
Field_imm7_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 25) >> 29);
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm7_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
  tie_t = (val << 25) >> 29;
  insn[0] = (insn[0] & ~0x70) | (tie_t << 4);
}

static unsigned
Field_imm7_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 25) >> 29);
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_imm7_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
  tie_t = (val << 25) >> 29;
  insn[0] = (insn[0] & ~0x70) | (tie_t << 4);
}

static unsigned
Field_imm7_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 7) | ((insn[0] << 25) >> 25);
  return tie_t;
}

static void
Field_imm7_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 25) >> 25;
  insn[0] = (insn[0] & ~0x7f) | (tie_t << 0);
}

static unsigned
Field_r3_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 16) >> 31);
  return tie_t;
}

static void
Field_r3_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x8000) | (tie_t << 15);
}

static unsigned
Field_rbit2_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 17) >> 31);
  return tie_t;
}

static void
Field_rbit2_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000) | (tie_t << 14);
}

static unsigned
Field_rhi_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 16) >> 30);
  return tie_t;
}

static void
Field_rhi_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc000) | (tie_t << 14);
}

static unsigned
Field_t3_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  return tie_t;
}

static void
Field_t3_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_tbit2_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 25) >> 31);
  return tie_t;
}

static void
Field_tbit2_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x40) | (tie_t << 6);
}

static unsigned
Field_tlo_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 26) >> 30);
  return tie_t;
}

static void
Field_tlo_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x30) | (tie_t << 4);
}

static unsigned
Field_w_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 18) >> 30);
  return tie_t;
}

static void
Field_w_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x3000) | (tie_t << 12);
}

static unsigned
Field_y_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 25) >> 31);
  return tie_t;
}

static void
Field_y_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x40) | (tie_t << 6);
}

static unsigned
Field_x_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 17) >> 31);
  return tie_t;
}

static void
Field_x_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000) | (tie_t << 14);
}

static unsigned
Field_t2_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 24) >> 29);
  return tie_t;
}

static void
Field_t2_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe0) | (tie_t << 5);
}

static unsigned
Field_t2_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 24) >> 29);
  return tie_t;
}

static void
Field_t2_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe0) | (tie_t << 5);
}

static unsigned
Field_t2_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 24) >> 29);
  return tie_t;
}

static void
Field_t2_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe0) | (tie_t << 5);
}

static unsigned
Field_s2_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 20) >> 29);
  return tie_t;
}

static void
Field_s2_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe00) | (tie_t << 9);
}

static unsigned
Field_s2_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 20) >> 29);
  return tie_t;
}

static void
Field_s2_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe00) | (tie_t << 9);
}

static unsigned
Field_s2_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 20) >> 29);
  return tie_t;
}

static void
Field_s2_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe00) | (tie_t << 9);
}

static unsigned
Field_r2_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 16) >> 29);
  return tie_t;
}

static void
Field_r2_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe000) | (tie_t << 13);
}

static unsigned
Field_r2_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 16) >> 29);
  return tie_t;
}

static void
Field_r2_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe000) | (tie_t << 13);
}

static unsigned
Field_r2_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 16) >> 29);
  return tie_t;
}

static void
Field_r2_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe000) | (tie_t << 13);
}

static unsigned
Field_t4_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 24) >> 30);
  return tie_t;
}

static void
Field_t4_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc0) | (tie_t << 6);
}

static unsigned
Field_t4_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 24) >> 30);
  return tie_t;
}

static void
Field_t4_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc0) | (tie_t << 6);
}

static unsigned
Field_t4_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 24) >> 30);
  return tie_t;
}

static void
Field_t4_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc0) | (tie_t << 6);
}

static unsigned
Field_s4_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 20) >> 30);
  return tie_t;
}

static void
Field_s4_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc00) | (tie_t << 10);
}

static unsigned
Field_s4_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 20) >> 30);
  return tie_t;
}

static void
Field_s4_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc00) | (tie_t << 10);
}

static unsigned
Field_s4_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 20) >> 30);
  return tie_t;
}

static void
Field_s4_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc00) | (tie_t << 10);
}

static unsigned
Field_r4_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 16) >> 30);
  return tie_t;
}

static void
Field_r4_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc000) | (tie_t << 14);
}

static unsigned
Field_r4_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 16) >> 30);
  return tie_t;
}

static void
Field_r4_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc000) | (tie_t << 14);
}

static unsigned
Field_r4_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 16) >> 30);
  return tie_t;
}

static void
Field_r4_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc000) | (tie_t << 14);
}

static unsigned
Field_t8_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  return tie_t;
}

static void
Field_t8_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_t8_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  return tie_t;
}

static void
Field_t8_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_t8_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  return tie_t;
}

static void
Field_t8_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_s8_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 20) >> 31);
  return tie_t;
}

static void
Field_s8_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x800) | (tie_t << 11);
}

static unsigned
Field_s8_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 20) >> 31);
  return tie_t;
}

static void
Field_s8_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x800) | (tie_t << 11);
}

static unsigned
Field_s8_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 20) >> 31);
  return tie_t;
}

static void
Field_s8_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x800) | (tie_t << 11);
}

static unsigned
Field_r8_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 16) >> 31);
  return tie_t;
}

static void
Field_r8_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x8000) | (tie_t << 15);
}

static unsigned
Field_r8_Slot_inst16a_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 16) >> 31);
  return tie_t;
}

static void
Field_r8_Slot_inst16a_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x8000) | (tie_t << 15);
}

static unsigned
Field_r8_Slot_inst16b_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 16) >> 31);
  return tie_t;
}

static void
Field_r8_Slot_inst16b_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x8000) | (tie_t << 15);
}

static unsigned
Field_xt_wbr15_imm_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 15) | ((insn[0] << 8) >> 17);
  return tie_t;
}

static void
Field_xt_wbr15_imm_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 17) >> 17;
  insn[0] = (insn[0] & ~0xfffe00) | (tie_t << 9);
}

static unsigned
Field_xt_wbr18_imm_Slot_inst_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 18) | ((insn[0] << 8) >> 14);
  return tie_t;
}

static void
Field_xt_wbr18_imm_Slot_inst_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 14) >> 14;
  insn[0] = (insn[0] & ~0xffffc0) | (tie_t << 6);
}

static unsigned
Field_xt_wbr18_imm_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 18) | ((insn[0] << 6) >> 14);
  return tie_t;
}

static void
Field_xt_wbr18_imm_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 14) >> 14;
  insn[0] = (insn[0] & ~0x3ffff00) | (tie_t << 8);
}

static unsigned
Field_op0_xt_flix64_slot0_s3_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 8) >> 28);
  return tie_t;
}

static void
Field_op0_xt_flix64_slot0_s3_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00000) | (tie_t << 20);
}

static unsigned
Field_combined3e2c5767_fld7_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 16) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld7_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe000) | (tie_t << 13);
}

static unsigned
Field_combined3e2c5767_fld8_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 16) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld8_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe000) | (tie_t << 13);
}

static unsigned
Field_combined3e2c5767_fld9_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 12) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld9_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe0000) | (tie_t << 17);
}

static unsigned
Field_combined3e2c5767_fld11_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 12) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld11_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe0000) | (tie_t << 17);
}

static unsigned
Field_combined3e2c5767_fld49xt_flix64_slot0_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 12) >> 28);
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld49xt_flix64_slot0_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
  tie_t = (val << 24) >> 28;
  insn[0] = (insn[0] & ~0xf0000) | (tie_t << 16);
}

static unsigned
Field_op0_s4_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 12) >> 30);
  return tie_t;
}

static void
Field_op0_s4_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc0000) | (tie_t << 18);
}

static unsigned
Field_combined3e2c5767_fld16_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 16) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld16_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld19xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 14) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld19xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x20000) | (tie_t << 17);
}

static unsigned
Field_combined3e2c5767_fld20xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 14) >> 30);
  return tie_t;
}

static void
Field_combined3e2c5767_fld20xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x30000) | (tie_t << 16);
}

static unsigned
Field_combined3e2c5767_fld21xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 5) | ((insn[0] << 14) >> 27);
  return tie_t;
}

static void
Field_combined3e2c5767_fld21xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 27) >> 27;
  insn[0] = (insn[0] & ~0x3e000) | (tie_t << 13);
}

static unsigned
Field_combined3e2c5767_fld22xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 6) | ((insn[0] << 14) >> 26);
  return tie_t;
}

static void
Field_combined3e2c5767_fld22xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 26) >> 26;
  insn[0] = (insn[0] & ~0x3f000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld23xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 6) | ((insn[0] << 14) >> 26);
  tie_t = (tie_t << 3) | ((insn[0] << 25) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld23xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0x70) | (tie_t << 4);
  tie_t = (val << 23) >> 26;
  insn[0] = (insn[0] & ~0x3f000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld25xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 6) | ((insn[0] << 14) >> 26);
  tie_t = (tie_t << 3) | ((insn[0] << 25) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld25xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0x70) | (tie_t << 4);
  tie_t = (val << 23) >> 26;
  insn[0] = (insn[0] & ~0x3f000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld26xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 6) | ((insn[0] << 14) >> 26);
  tie_t = (tie_t << 2) | ((insn[0] << 25) >> 30);
  return tie_t;
}

static void
Field_combined3e2c5767_fld26xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x60) | (tie_t << 5);
  tie_t = (val << 24) >> 26;
  insn[0] = (insn[0] & ~0x3f000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld28xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 6) | ((insn[0] << 14) >> 26);
  tie_t = (tie_t << 1) | ((insn[0] << 25) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld28xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x40) | (tie_t << 6);
  tie_t = (val << 25) >> 26;
  insn[0] = (insn[0] & ~0x3f000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld30xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 6) | ((insn[0] << 14) >> 26);
  tie_t = (tie_t << 2) | ((insn[0] << 22) >> 30);
  return tie_t;
}

static void
Field_combined3e2c5767_fld30xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x300) | (tie_t << 8);
  tie_t = (val << 24) >> 26;
  insn[0] = (insn[0] & ~0x3f000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld32xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 6) | ((insn[0] << 14) >> 26);
  tie_t = (tie_t << 2) | ((insn[0] << 22) >> 30);
  return tie_t;
}

static void
Field_combined3e2c5767_fld32xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x300) | (tie_t << 8);
  tie_t = (val << 24) >> 26;
  insn[0] = (insn[0] & ~0x3f000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld33xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 6) | ((insn[0] << 14) >> 26);
  tie_t = (tie_t << 1) | ((insn[0] << 22) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld33xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x200) | (tie_t << 9);
  tie_t = (val << 25) >> 26;
  insn[0] = (insn[0] & ~0x3f000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld35xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 14) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld35xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0x38000) | (tie_t << 15);
}

static unsigned
Field_combined3e2c5767_fld51xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld51xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_combined3e2c5767_fld52xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld52xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_combined3e2c5767_fld53xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 20) >> 30);
  return tie_t;
}

static void
Field_combined3e2c5767_fld53xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0xc00) | (tie_t << 10);
}

static unsigned
Field_combined3e2c5767_fld54xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 5) | ((insn[0] << 20) >> 27);
  tie_t = (tie_t << 6) | ((insn[0] << 26) >> 26);
  return tie_t;
}

static void
Field_combined3e2c5767_fld54xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 26) >> 26;
  insn[0] = (insn[0] & ~0x3f) | (tie_t << 0);
  tie_t = (val << 21) >> 27;
  insn[0] = (insn[0] & ~0xf80) | (tie_t << 7);
}

static unsigned
Field_combined3e2c5767_fld57xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld57xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld58xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 20) >> 30);
  tie_t = (tie_t << 1) | ((insn[0] << 23) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld58xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x100) | (tie_t << 8);
  tie_t = (val << 29) >> 30;
  insn[0] = (insn[0] & ~0xc00) | (tie_t << 10);
}

static unsigned
Field_combined3e2c5767_fld60xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  tie_t = (tie_t << 5) | ((insn[0] << 27) >> 27);
  return tie_t;
}

static void
Field_combined3e2c5767_fld60xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 27) >> 27;
  insn[0] = (insn[0] & ~0x1f) | (tie_t << 0);
  tie_t = (val << 26) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
}

static unsigned
Field_combined3e2c5767_fld62xt_flix64_slot1_Slot_xt_flix64_slot1_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 17) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld62xt_flix64_slot1_Slot_xt_flix64_slot1_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0x7000) | (tie_t << 12);
}

static unsigned
Field_op0_s5_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[0] << 16) >> 29);
  return tie_t;
}

static void
Field_op0_s5_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0xe000) | (tie_t << 13);
}

static unsigned
Field_combined3e2c5767_fld36xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld36xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld37xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld37xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
  tie_t = (val << 30) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld39xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  tie_t = (tie_t << 1) | ((insn[0] << 27) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld39xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x10) | (tie_t << 4);
  tie_t = (val << 30) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
  tie_t = (val << 29) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld41xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 1) | ((insn[0] << 24) >> 31);
  tie_t = (tie_t << 1) | ((insn[0] << 27) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld41xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x10) | (tie_t << 4);
  tie_t = (val << 30) >> 31;
  insn[0] = (insn[0] & ~0x80) | (tie_t << 7);
  tie_t = (val << 29) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld42xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 3) | ((insn[0] << 21) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld42xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0x700) | (tie_t << 8);
  tie_t = (val << 28) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld44xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 3) | ((insn[0] << 21) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld44xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[0] = (insn[0] & ~0x700) | (tie_t << 8);
  tie_t = (val << 28) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld45xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 2) | ((insn[0] << 21) >> 30);
  return tie_t;
}

static void
Field_combined3e2c5767_fld45xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x600) | (tie_t << 9);
  tie_t = (val << 29) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld47xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 19) >> 31);
  tie_t = (tie_t << 1) | ((insn[0] << 21) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld47xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x400) | (tie_t << 10);
  tie_t = (val << 30) >> 31;
  insn[0] = (insn[0] & ~0x1000) | (tie_t << 12);
}

static unsigned
Field_combined3e2c5767_fld63xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 2) | ((insn[0] << 25) >> 30);
  return tie_t;
}

static void
Field_combined3e2c5767_fld63xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x60) | (tie_t << 5);
}

static unsigned
Field_combined3e2c5767_fld64xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 20) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld64xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x800) | (tie_t << 11);
}

static unsigned
Field_combined3e2c5767_fld65xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 20) >> 28);
  tie_t = (tie_t << 2) | ((insn[0] << 25) >> 30);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld65xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 26) >> 30;
  insn[0] = (insn[0] & ~0x60) | (tie_t << 5);
  tie_t = (val << 22) >> 28;
  insn[0] = (insn[0] & ~0xf00) | (tie_t << 8);
}

static unsigned
Field_combined3e2c5767_fld66xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 20) >> 31);
  tie_t = (tie_t << 1) | ((insn[0] << 23) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld66xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x100) | (tie_t << 8);
  tie_t = (val << 30) >> 31;
  insn[0] = (insn[0] & ~0x800) | (tie_t << 11);
}

static unsigned
Field_combined3e2c5767_fld68xt_flix64_slot2_Slot_xt_flix64_slot2_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 1) | ((insn[0] << 20) >> 31);
  tie_t = (tie_t << 2) | ((insn[0] << 22) >> 30);
  return tie_t;
}

static void
Field_combined3e2c5767_fld68xt_flix64_slot2_Slot_xt_flix64_slot2_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 30) >> 30;
  insn[0] = (insn[0] & ~0x300) | (tie_t << 8);
  tie_t = (val << 29) >> 31;
  insn[0] = (insn[0] & ~0x800) | (tie_t << 11);
}

static unsigned
Field_op0_s6_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 5) | ((insn[0] << 0) >> 27);
  return tie_t;
}

static void
Field_op0_s6_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 27) >> 27;
  insn[0] = (insn[0] & ~0xf8000000) | (tie_t << 27);
}

static unsigned
Field_combined3e2c5767_fld70xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld70xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 24) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld71_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  return tie_t;
}

static void
Field_combined3e2c5767_fld71_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 29) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld72xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld72xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 24) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld73xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld73xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 24) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld74xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  tie_t = (tie_t << 4) | ((insn[0] << 28) >> 28);
  return tie_t;
}

static void
Field_combined3e2c5767_fld74xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf) | (tie_t << 0);
  tie_t = (val << 27) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 24) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld75xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld75xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld76xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld76xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld77xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld77xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld78xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld78xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld79xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld79xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld80xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld80xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld81xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld81xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld82xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld82xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld83xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld83xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld84xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld84xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld85xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld85xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld86xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld86xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld87xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld87xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld88xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld88xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld89xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld89xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld90xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld90xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld91xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld91xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld92xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 1) | ((insn[0] << 5) >> 31);
  return tie_t;
}

static void
Field_combined3e2c5767_fld92xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 31) >> 31;
  insn[0] = (insn[0] & ~0x4000000) | (tie_t << 26);
  tie_t = (val << 28) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_combined3e2c5767_fld93xt_flix64_slot3_Slot_xt_flix64_slot3_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 3) | ((insn[1] << 29) >> 29);
  tie_t = (tie_t << 27) | ((insn[0] << 5) >> 5);
  return tie_t;
}

static void
Field_combined3e2c5767_fld93xt_flix64_slot3_Slot_xt_flix64_slot3_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 5) >> 5;
  insn[0] = (insn[0] & ~0x7ffffff) | (tie_t << 0);
  tie_t = (val << 2) >> 29;
  insn[1] = (insn[1] & ~0x7) | (tie_t << 0);
}

static unsigned
Field_op0_xt_flix64_slot0_Slot_xt_flix64_slot0_get (const xtensa_insnbuf insn)
{
  unsigned tie_t = 0;
  tie_t = (tie_t << 4) | ((insn[0] << 8) >> 28);
  return tie_t;
}

static void
Field_op0_xt_flix64_slot0_Slot_xt_flix64_slot0_set (xtensa_insnbuf insn, uint32 val)
{
  uint32 tie_t;
  tie_t = (val << 28) >> 28;
  insn[0] = (insn[0] & ~0xf00000) | (tie_t << 20);
}

static void
Implicit_Field_set (xtensa_insnbuf insn ATTRIBUTE_UNUSED,
		    uint32 val ATTRIBUTE_UNUSED)
{
  /* Do nothing.  */
}

static unsigned
Implicit_Field_ar0_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 0;
}

static unsigned
Implicit_Field_ar4_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 4;
}

static unsigned
Implicit_Field_ar8_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 8;
}

static unsigned
Implicit_Field_ar12_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 12;
}

static unsigned
Implicit_Field_mr0_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 0;
}

static unsigned
Implicit_Field_mr1_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 1;
}

static unsigned
Implicit_Field_mr2_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 2;
}

static unsigned
Implicit_Field_mr3_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 3;
}

static unsigned
Implicit_Field_bt16_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 0;
}

static unsigned
Implicit_Field_bs16_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 0;
}

static unsigned
Implicit_Field_br16_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 0;
}

static unsigned
Implicit_Field_brall_get (const xtensa_insnbuf insn ATTRIBUTE_UNUSED)
{
  return 0;
}


/* Functional units.  */

static xtensa_funcUnit_internal funcUnits[] = {
  { 0 }
};


/* Register files.  */

static xtensa_regfile_internal regfiles[] = {
  { "AR", "a", 0, 32, 64 },
  { "MR", "m", 1, 32, 4 },
  { "BR", "b", 2, 1, 16 },
  { "FR", "f", 3, 32, 16 },
  { "BR2", "b", 2, 2, 8 },
  { "BR4", "b", 2, 4, 4 },
  { "BR8", "b", 2, 8, 2 },
  { "BR16", "b", 2, 16, 1 }
};


/* Interfaces.  */

static xtensa_interface_internal interfaces[] = {
  { 0 }
};


/* Constant tables.  */

/* constant table ai4c */
static const unsigned CONST_TBL_ai4c_0[] = {
  0xffffffff,
  0x1,
  0x2,
  0x3,
  0x4,
  0x5,
  0x6,
  0x7,
  0x8,
  0x9,
  0xa,
  0xb,
  0xc,
  0xd,
  0xe,
  0xf,
  0
};

/* constant table b4c */
static const unsigned CONST_TBL_b4c_0[] = {
  0xffffffff,
  0x1,
  0x2,
  0x3,
  0x4,
  0x5,
  0x6,
  0x7,
  0x8,
  0xa,
  0xc,
  0x10,
  0x20,
  0x40,
  0x80,
  0x100,
  0
};

/* constant table b4cu */
static const unsigned CONST_TBL_b4cu_0[] = {
  0x8000,
  0x10000,
  0x2,
  0x3,
  0x4,
  0x5,
  0x6,
  0x7,
  0x8,
  0xa,
  0xc,
  0x10,
  0x20,
  0x40,
  0x80,
  0x100,
  0
};


/* Instruction operands.  */

static int
Operand_soffsetx4_decode (uint32 *valp)
{
  unsigned soffsetx4_0, offset_0;
  offset_0 = *valp & 0x3ffff;
  soffsetx4_0 = 0x4 + ((((int) offset_0 << 14) >> 14) << 2);
  *valp = soffsetx4_0;
  return 0;
}

static int
Operand_soffsetx4_encode (uint32 *valp)
{
  unsigned offset_0, soffsetx4_0;
  soffsetx4_0 = *valp;
  offset_0 = ((soffsetx4_0 - 0x4) >> 2) & 0x3ffff;
  *valp = offset_0;
  return 0;
}

static int
Operand_soffsetx4_ator (uint32 *valp, uint32 pc)
{
  *valp -= (pc & ~0x3);
  return 0;
}

static int
Operand_soffsetx4_rtoa (uint32 *valp, uint32 pc)
{
  *valp += (pc & ~0x3);
  return 0;
}

static int
Operand_uimm12x8_decode (uint32 *valp)
{
  unsigned uimm12x8_0, imm12_0;
  imm12_0 = *valp & 0xfff;
  uimm12x8_0 = imm12_0 << 3;
  *valp = uimm12x8_0;
  return 0;
}

static int
Operand_uimm12x8_encode (uint32 *valp)
{
  unsigned imm12_0, uimm12x8_0;
  uimm12x8_0 = *valp;
  imm12_0 = ((uimm12x8_0 >> 3) & 0xfff);
  *valp = imm12_0;
  return 0;
}

static int
Operand_simm4_decode (uint32 *valp)
{
  unsigned simm4_0, mn_0;
  mn_0 = *valp & 0xf;
  simm4_0 = ((int) mn_0 << 28) >> 28;
  *valp = simm4_0;
  return 0;
}

static int
Operand_simm4_encode (uint32 *valp)
{
  unsigned mn_0, simm4_0;
  simm4_0 = *valp;
  mn_0 = (simm4_0 & 0xf);
  *valp = mn_0;
  return 0;
}

static int
Operand_arr_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_arr_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static int
Operand_ars_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_ars_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static int
Operand_art_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_art_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static int
Operand_ar0_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_ar0_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3f) != 0;
  return error;
}

static int
Operand_ar4_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_ar4_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3f) != 0;
  return error;
}

static int
Operand_ar8_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_ar8_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3f) != 0;
  return error;
}

static int
Operand_ar12_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_ar12_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3f) != 0;
  return error;
}

static int
Operand_ars_entry_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_ars_entry_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3f) != 0;
  return error;
}

static int
Operand_immrx4_decode (uint32 *valp)
{
  unsigned immrx4_0, r_0;
  r_0 = *valp & 0xf;
  immrx4_0 = (((0xfffffff) << 4) | r_0) << 2;
  *valp = immrx4_0;
  return 0;
}

static int
Operand_immrx4_encode (uint32 *valp)
{
  unsigned r_0, immrx4_0;
  immrx4_0 = *valp;
  r_0 = ((immrx4_0 >> 2) & 0xf);
  *valp = r_0;
  return 0;
}

static int
Operand_lsi4x4_decode (uint32 *valp)
{
  unsigned lsi4x4_0, r_0;
  r_0 = *valp & 0xf;
  lsi4x4_0 = r_0 << 2;
  *valp = lsi4x4_0;
  return 0;
}

static int
Operand_lsi4x4_encode (uint32 *valp)
{
  unsigned r_0, lsi4x4_0;
  lsi4x4_0 = *valp;
  r_0 = ((lsi4x4_0 >> 2) & 0xf);
  *valp = r_0;
  return 0;
}

static int
Operand_simm7_decode (uint32 *valp)
{
  unsigned simm7_0, imm7_0;
  imm7_0 = *valp & 0x7f;
  // warning C4146: unary minus operator applied to unsigned type
  simm7_0 = ((((-((((imm7_0 >> 6) & 1)) & (((imm7_0 >> 5) & 1)))) & 0x1ffffff)) << 7) | imm7_0;
  *valp = simm7_0;
  return 0;
}

static int
Operand_simm7_encode (uint32 *valp)
{
  unsigned imm7_0, simm7_0;
  simm7_0 = *valp;
  imm7_0 = (simm7_0 & 0x7f);
  *valp = imm7_0;
  return 0;
}

static int
Operand_uimm6_decode (uint32 *valp)
{
  unsigned uimm6_0, imm6_0;
  imm6_0 = *valp & 0x3f;
  uimm6_0 = 0x4 + (((0) << 6) | imm6_0);
  *valp = uimm6_0;
  return 0;
}

static int
Operand_uimm6_encode (uint32 *valp)
{
  unsigned imm6_0, uimm6_0;
  uimm6_0 = *valp;
  imm6_0 = (uimm6_0 - 0x4) & 0x3f;
  *valp = imm6_0;
  return 0;
}

static int
Operand_uimm6_ator (uint32 *valp, uint32 pc)
{
  *valp -= pc;
  return 0;
}

static int
Operand_uimm6_rtoa (uint32 *valp, uint32 pc)
{
  *valp += pc;
  return 0;
}

static int
Operand_ai4const_decode (uint32 *valp)
{
  unsigned ai4const_0, t_0;
  t_0 = *valp & 0xf;
  ai4const_0 = CONST_TBL_ai4c_0[t_0 & 0xf];
  *valp = ai4const_0;
  return 0;
}

static int
Operand_ai4const_encode (uint32 *valp)
{
  unsigned t_0, ai4const_0;
  ai4const_0 = *valp;
  switch (ai4const_0)
    {
    case 0xffffffff: t_0 = 0; break;
    case 0x1: t_0 = 0x1; break;
    case 0x2: t_0 = 0x2; break;
    case 0x3: t_0 = 0x3; break;
    case 0x4: t_0 = 0x4; break;
    case 0x5: t_0 = 0x5; break;
    case 0x6: t_0 = 0x6; break;
    case 0x7: t_0 = 0x7; break;
    case 0x8: t_0 = 0x8; break;
    case 0x9: t_0 = 0x9; break;
    case 0xa: t_0 = 0xa; break;
    case 0xb: t_0 = 0xb; break;
    case 0xc: t_0 = 0xc; break;
    case 0xd: t_0 = 0xd; break;
    case 0xe: t_0 = 0xe; break;
    default: t_0 = 0xf; break;
    }
  *valp = t_0;
  return 0;
}

static int
Operand_b4const_decode (uint32 *valp)
{
  unsigned b4const_0, r_0;
  r_0 = *valp & 0xf;
  b4const_0 = CONST_TBL_b4c_0[r_0 & 0xf];
  *valp = b4const_0;
  return 0;
}

static int
Operand_b4const_encode (uint32 *valp)
{
  unsigned r_0, b4const_0;
  b4const_0 = *valp;
  switch (b4const_0)
    {
    case 0xffffffff: r_0 = 0; break;
    case 0x1: r_0 = 0x1; break;
    case 0x2: r_0 = 0x2; break;
    case 0x3: r_0 = 0x3; break;
    case 0x4: r_0 = 0x4; break;
    case 0x5: r_0 = 0x5; break;
    case 0x6: r_0 = 0x6; break;
    case 0x7: r_0 = 0x7; break;
    case 0x8: r_0 = 0x8; break;
    case 0xa: r_0 = 0x9; break;
    case 0xc: r_0 = 0xa; break;
    case 0x10: r_0 = 0xb; break;
    case 0x20: r_0 = 0xc; break;
    case 0x40: r_0 = 0xd; break;
    case 0x80: r_0 = 0xe; break;
    default: r_0 = 0xf; break;
    }
  *valp = r_0;
  return 0;
}

static int
Operand_b4constu_decode (uint32 *valp)
{
  unsigned b4constu_0, r_0;
  r_0 = *valp & 0xf;
  b4constu_0 = CONST_TBL_b4cu_0[r_0 & 0xf];
  *valp = b4constu_0;
  return 0;
}

static int
Operand_b4constu_encode (uint32 *valp)
{
  unsigned r_0, b4constu_0;
  b4constu_0 = *valp;
  switch (b4constu_0)
    {
    case 0x8000: r_0 = 0; break;
    case 0x10000: r_0 = 0x1; break;
    case 0x2: r_0 = 0x2; break;
    case 0x3: r_0 = 0x3; break;
    case 0x4: r_0 = 0x4; break;
    case 0x5: r_0 = 0x5; break;
    case 0x6: r_0 = 0x6; break;
    case 0x7: r_0 = 0x7; break;
    case 0x8: r_0 = 0x8; break;
    case 0xa: r_0 = 0x9; break;
    case 0xc: r_0 = 0xa; break;
    case 0x10: r_0 = 0xb; break;
    case 0x20: r_0 = 0xc; break;
    case 0x40: r_0 = 0xd; break;
    case 0x80: r_0 = 0xe; break;
    default: r_0 = 0xf; break;
    }
  *valp = r_0;
  return 0;
}

static int
Operand_uimm8_decode (uint32 *valp)
{
  unsigned uimm8_0, imm8_0;
  imm8_0 = *valp & 0xff;
  uimm8_0 = imm8_0;
  *valp = uimm8_0;
  return 0;
}

static int
Operand_uimm8_encode (uint32 *valp)
{
  unsigned imm8_0, uimm8_0;
  uimm8_0 = *valp;
  imm8_0 = (uimm8_0 & 0xff);
  *valp = imm8_0;
  return 0;
}

static int
Operand_uimm8x2_decode (uint32 *valp)
{
  unsigned uimm8x2_0, imm8_0;
  imm8_0 = *valp & 0xff;
  uimm8x2_0 = imm8_0 << 1;
  *valp = uimm8x2_0;
  return 0;
}

static int
Operand_uimm8x2_encode (uint32 *valp)
{
  unsigned imm8_0, uimm8x2_0;
  uimm8x2_0 = *valp;
  imm8_0 = ((uimm8x2_0 >> 1) & 0xff);
  *valp = imm8_0;
  return 0;
}

static int
Operand_uimm8x4_decode (uint32 *valp)
{
  unsigned uimm8x4_0, imm8_0;
  imm8_0 = *valp & 0xff;
  uimm8x4_0 = imm8_0 << 2;
  *valp = uimm8x4_0;
  return 0;
}

static int
Operand_uimm8x4_encode (uint32 *valp)
{
  unsigned imm8_0, uimm8x4_0;
  uimm8x4_0 = *valp;
  imm8_0 = ((uimm8x4_0 >> 2) & 0xff);
  *valp = imm8_0;
  return 0;
}

static int
Operand_uimm4x16_decode (uint32 *valp)
{
  unsigned uimm4x16_0, op2_0;
  op2_0 = *valp & 0xf;
  uimm4x16_0 = op2_0 << 4;
  *valp = uimm4x16_0;
  return 0;
}

static int
Operand_uimm4x16_encode (uint32 *valp)
{
  unsigned op2_0, uimm4x16_0;
  uimm4x16_0 = *valp;
  op2_0 = ((uimm4x16_0 >> 4) & 0xf);
  *valp = op2_0;
  return 0;
}

static int
Operand_simm8_decode (uint32 *valp)
{
  unsigned simm8_0, imm8_0;
  imm8_0 = *valp & 0xff;
  simm8_0 = ((int) imm8_0 << 24) >> 24;
  *valp = simm8_0;
  return 0;
}

static int
Operand_simm8_encode (uint32 *valp)
{
  unsigned imm8_0, simm8_0;
  simm8_0 = *valp;
  imm8_0 = (simm8_0 & 0xff);
  *valp = imm8_0;
  return 0;
}

static int
Operand_simm8x256_decode (uint32 *valp)
{
  unsigned simm8x256_0, imm8_0;
  imm8_0 = *valp & 0xff;
  simm8x256_0 = (((int) imm8_0 << 24) >> 24) << 8;
  *valp = simm8x256_0;
  return 0;
}

static int
Operand_simm8x256_encode (uint32 *valp)
{
  unsigned imm8_0, simm8x256_0;
  simm8x256_0 = *valp;
  imm8_0 = ((simm8x256_0 >> 8) & 0xff);
  *valp = imm8_0;
  return 0;
}

static int
Operand_simm12b_decode (uint32 *valp)
{
  unsigned simm12b_0, imm12b_0;
  imm12b_0 = *valp & 0xfff;
  simm12b_0 = ((int) imm12b_0 << 20) >> 20;
  *valp = simm12b_0;
  return 0;
}

static int
Operand_simm12b_encode (uint32 *valp)
{
  unsigned imm12b_0, simm12b_0;
  simm12b_0 = *valp;
  imm12b_0 = (simm12b_0 & 0xfff);
  *valp = imm12b_0;
  return 0;
}

static int
Operand_msalp32_decode (uint32 *valp)
{
  unsigned msalp32_0, sal_0;
  sal_0 = *valp & 0x1f;
  msalp32_0 = 0x20 - sal_0;
  *valp = msalp32_0;
  return 0;
}

static int
Operand_msalp32_encode (uint32 *valp)
{
  unsigned sal_0, msalp32_0;
  msalp32_0 = *valp;
  sal_0 = (0x20 - msalp32_0) & 0x1f;
  *valp = sal_0;
  return 0;
}

static int
Operand_op2p1_decode (uint32 *valp)
{
  unsigned op2p1_0, op2_0;
  op2_0 = *valp & 0xf;
  op2p1_0 = op2_0 + 0x1;
  *valp = op2p1_0;
  return 0;
}

static int
Operand_op2p1_encode (uint32 *valp)
{
  unsigned op2_0, op2p1_0;
  op2p1_0 = *valp;
  op2_0 = (op2p1_0 - 0x1) & 0xf;
  *valp = op2_0;
  return 0;
}

static int
Operand_label8_decode (uint32 *valp)
{
  unsigned label8_0, imm8_0;
  imm8_0 = *valp & 0xff;
  label8_0 = 0x4 + (((int) imm8_0 << 24) >> 24);
  *valp = label8_0;
  return 0;
}

static int
Operand_label8_encode (uint32 *valp)
{
  unsigned imm8_0, label8_0;
  label8_0 = *valp;
  imm8_0 = (label8_0 - 0x4) & 0xff;
  *valp = imm8_0;
  return 0;
}

static int
Operand_label8_ator (uint32 *valp, uint32 pc)
{
  *valp -= pc;
  return 0;
}

static int
Operand_label8_rtoa (uint32 *valp, uint32 pc)
{
  *valp += pc;
  return 0;
}

static int
Operand_ulabel8_decode (uint32 *valp)
{
  unsigned ulabel8_0, imm8_0;
  imm8_0 = *valp & 0xff;
  ulabel8_0 = 0x4 + (((0) << 8) | imm8_0);
  *valp = ulabel8_0;
  return 0;
}

static int
Operand_ulabel8_encode (uint32 *valp)
{
  unsigned imm8_0, ulabel8_0;
  ulabel8_0 = *valp;
  imm8_0 = (ulabel8_0 - 0x4) & 0xff;
  *valp = imm8_0;
  return 0;
}

static int
Operand_ulabel8_ator (uint32 *valp, uint32 pc)
{
  *valp -= pc;
  return 0;
}

static int
Operand_ulabel8_rtoa (uint32 *valp, uint32 pc)
{
  *valp += pc;
  return 0;
}

static int
Operand_label12_decode (uint32 *valp)
{
  unsigned label12_0, imm12_0;
  imm12_0 = *valp & 0xfff;
  label12_0 = 0x4 + (((int) imm12_0 << 20) >> 20);
  *valp = label12_0;
  return 0;
}

static int
Operand_label12_encode (uint32 *valp)
{
  unsigned imm12_0, label12_0;
  label12_0 = *valp;
  imm12_0 = (label12_0 - 0x4) & 0xfff;
  *valp = imm12_0;
  return 0;
}

static int
Operand_label12_ator (uint32 *valp, uint32 pc)
{
  *valp -= pc;
  return 0;
}

static int
Operand_label12_rtoa (uint32 *valp, uint32 pc)
{
  *valp += pc;
  return 0;
}

static int
Operand_soffset_decode (uint32 *valp)
{
  unsigned soffset_0, offset_0;
  offset_0 = *valp & 0x3ffff;
  soffset_0 = 0x4 + (((int) offset_0 << 14) >> 14);
  *valp = soffset_0;
  return 0;
}

static int
Operand_soffset_encode (uint32 *valp)
{
  unsigned offset_0, soffset_0;
  soffset_0 = *valp;
  offset_0 = (soffset_0 - 0x4) & 0x3ffff;
  *valp = offset_0;
  return 0;
}

static int
Operand_soffset_ator (uint32 *valp, uint32 pc)
{
  *valp -= pc;
  return 0;
}

static int
Operand_soffset_rtoa (uint32 *valp, uint32 pc)
{
  *valp += pc;
  return 0;
}

static int
Operand_uimm16x4_decode (uint32 *valp)
{
  unsigned uimm16x4_0, imm16_0;
  imm16_0 = *valp & 0xffff;
  uimm16x4_0 = (((0xffff) << 16) | imm16_0) << 2;
  *valp = uimm16x4_0;
  return 0;
}

static int
Operand_uimm16x4_encode (uint32 *valp)
{
  unsigned imm16_0, uimm16x4_0;
  uimm16x4_0 = *valp;
  imm16_0 = (uimm16x4_0 >> 2) & 0xffff;
  *valp = imm16_0;
  return 0;
}

static int
Operand_uimm16x4_ator (uint32 *valp, uint32 pc)
{
  *valp -= ((pc + 3) & ~0x3);
  return 0;
}

static int
Operand_uimm16x4_rtoa (uint32 *valp, uint32 pc)
{
  *valp += ((pc + 3) & ~0x3);
  return 0;
}

static int
Operand_mx_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_mx_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3) != 0;
  return error;
}

static int
Operand_my_decode (uint32 *valp)
{
  *valp += 2;
  return 0;
}

static int
Operand_my_encode (uint32 *valp)
{
  int error;
  error = ((*valp & ~0x3) != 0) || ((*valp & 0x2) == 0);
  *valp = *valp & 1;
  return error;
}

static int
Operand_mw_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_mw_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3) != 0;
  return error;
}

static int
Operand_mr0_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_mr0_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3) != 0;
  return error;
}

static int
Operand_mr1_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_mr1_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3) != 0;
  return error;
}

static int
Operand_mr2_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_mr2_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3) != 0;
  return error;
}

static int
Operand_mr3_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_mr3_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0x3) != 0;
  return error;
}

static int
Operand_immt_decode (uint32 *valp)
{
  unsigned immt_0, t_0;
  t_0 = *valp & 0xf;
  immt_0 = t_0;
  *valp = immt_0;
  return 0;
}

static int
Operand_immt_encode (uint32 *valp)
{
  unsigned t_0, immt_0;
  immt_0 = *valp;
  t_0 = immt_0 & 0xf;
  *valp = t_0;
  return 0;
}

static int
Operand_imms_decode (uint32 *valp)
{
  unsigned imms_0, s_0;
  s_0 = *valp & 0xf;
  imms_0 = s_0;
  *valp = imms_0;
  return 0;
}

static int
Operand_imms_encode (uint32 *valp)
{
  unsigned s_0, imms_0;
  imms_0 = *valp;
  s_0 = imms_0 & 0xf;
  *valp = s_0;
  return 0;
}

static int
Operand_bt_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_bt_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static int
Operand_bs_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_bs_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static int
Operand_br_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_br_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static int
Operand_bt2_decode (uint32 *valp)
{
  *valp = *valp << 1;
  return 0;
}

static int
Operand_bt2_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x7 << 1)) != 0;
  *valp = *valp >> 1;
  return error;
}

static int
Operand_bs2_decode (uint32 *valp)
{
  *valp = *valp << 1;
  return 0;
}

static int
Operand_bs2_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x7 << 1)) != 0;
  *valp = *valp >> 1;
  return error;
}

static int
Operand_br2_decode (uint32 *valp)
{
  *valp = *valp << 1;
  return 0;
}

static int
Operand_br2_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x7 << 1)) != 0;
  *valp = *valp >> 1;
  return error;
}

static int
Operand_bt4_decode (uint32 *valp)
{
  *valp = *valp << 2;
  return 0;
}

static int
Operand_bt4_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x3 << 2)) != 0;
  *valp = *valp >> 2;
  return error;
}

static int
Operand_bs4_decode (uint32 *valp)
{
  *valp = *valp << 2;
  return 0;
}

static int
Operand_bs4_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x3 << 2)) != 0;
  *valp = *valp >> 2;
  return error;
}

static int
Operand_br4_decode (uint32 *valp)
{
  *valp = *valp << 2;
  return 0;
}

static int
Operand_br4_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x3 << 2)) != 0;
  *valp = *valp >> 2;
  return error;
}

static int
Operand_bt8_decode (uint32 *valp)
{
  *valp = *valp << 3;
  return 0;
}

static int
Operand_bt8_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x1 << 3)) != 0;
  *valp = *valp >> 3;
  return error;
}

static int
Operand_bs8_decode (uint32 *valp)
{
  *valp = *valp << 3;
  return 0;
}

static int
Operand_bs8_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x1 << 3)) != 0;
  *valp = *valp >> 3;
  return error;
}

static int
Operand_br8_decode (uint32 *valp)
{
  *valp = *valp << 3;
  return 0;
}

static int
Operand_br8_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0x1 << 3)) != 0;
  *valp = *valp >> 3;
  return error;
}

static int
Operand_bt16_decode (uint32 *valp)
{
  *valp = *valp << 4;
  return 0;
}

static int
Operand_bt16_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0 << 4)) != 0;
  *valp = *valp >> 4;
  return error;
}

static int
Operand_bs16_decode (uint32 *valp)
{
  *valp = *valp << 4;
  return 0;
}

static int
Operand_bs16_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0 << 4)) != 0;
  *valp = *valp >> 4;
  return error;
}

static int
Operand_br16_decode (uint32 *valp)
{
  *valp = *valp << 4;
  return 0;
}

static int
Operand_br16_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0 << 4)) != 0;
  *valp = *valp >> 4;
  return error;
}

static int
Operand_brall_decode (uint32 *valp)
{
  *valp = *valp << 4;
  return 0;
}

static int
Operand_brall_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~(0 << 4)) != 0;
  *valp = *valp >> 4;
  return error;
}

static int
Operand_tp7_decode (uint32 *valp)
{
  unsigned tp7_0, t_0;
  t_0 = *valp & 0xf;
  tp7_0 = t_0 + 0x7;
  *valp = tp7_0;
  return 0;
}

static int
Operand_tp7_encode (uint32 *valp)
{
  unsigned t_0, tp7_0;
  tp7_0 = *valp;
  t_0 = (tp7_0 - 0x7) & 0xf;
  *valp = t_0;
  return 0;
}

static int
Operand_xt_wbr15_label_decode (uint32 *valp)
{
  unsigned xt_wbr15_label_0, xt_wbr15_imm_0;
  xt_wbr15_imm_0 = *valp & 0x7fff;
  xt_wbr15_label_0 = 0x4 + (((int) xt_wbr15_imm_0 << 17) >> 17);
  *valp = xt_wbr15_label_0;
  return 0;
}

static int
Operand_xt_wbr15_label_encode (uint32 *valp)
{
  unsigned xt_wbr15_imm_0, xt_wbr15_label_0;
  xt_wbr15_label_0 = *valp;
  xt_wbr15_imm_0 = (xt_wbr15_label_0 - 0x4) & 0x7fff;
  *valp = xt_wbr15_imm_0;
  return 0;
}

static int
Operand_xt_wbr15_label_ator (uint32 *valp, uint32 pc)
{
  *valp -= pc;
  return 0;
}

static int
Operand_xt_wbr15_label_rtoa (uint32 *valp, uint32 pc)
{
  *valp += pc;
  return 0;
}

static int
Operand_xt_wbr18_label_decode (uint32 *valp)
{
  unsigned xt_wbr18_label_0, xt_wbr18_imm_0;
  xt_wbr18_imm_0 = *valp & 0x3ffff;
  xt_wbr18_label_0 = 0x4 + (((int) xt_wbr18_imm_0 << 14) >> 14);
  *valp = xt_wbr18_label_0;
  return 0;
}

static int
Operand_xt_wbr18_label_encode (uint32 *valp)
{
  unsigned xt_wbr18_imm_0, xt_wbr18_label_0;
  xt_wbr18_label_0 = *valp;
  xt_wbr18_imm_0 = (xt_wbr18_label_0 - 0x4) & 0x3ffff;
  *valp = xt_wbr18_imm_0;
  return 0;
}

static int
Operand_xt_wbr18_label_ator (uint32 *valp, uint32 pc)
{
  *valp -= pc;
  return 0;
}

static int
Operand_xt_wbr18_label_rtoa (uint32 *valp, uint32 pc)
{
  *valp += pc;
  return 0;
}

static int
Operand_cimm8x4_decode (uint32 *valp)
{
  unsigned cimm8x4_0, imm8_0;
  imm8_0 = *valp & 0xff;
  cimm8x4_0 = (imm8_0 << 2) | 0;
  *valp = cimm8x4_0;
  return 0;
}

static int
Operand_cimm8x4_encode (uint32 *valp)
{
  unsigned imm8_0, cimm8x4_0;
  cimm8x4_0 = *valp;
  imm8_0 = (cimm8x4_0 >> 2) & 0xff;
  *valp = imm8_0;
  return 0;
}

static int
Operand_frr_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_frr_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static int
Operand_frs_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_frs_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static int
Operand_frt_decode (uint32 *valp ATTRIBUTE_UNUSED)
{
  return 0;
}

static int
Operand_frt_encode (uint32 *valp)
{
  int error;
  error = (*valp & ~0xf) != 0;
  return error;
}

static xtensa_operand_internal operands[] = {
  { "soffsetx4", 10, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_soffsetx4_encode, Operand_soffsetx4_decode,
    Operand_soffsetx4_ator, Operand_soffsetx4_rtoa },
  { "uimm12x8", 3, -1, 0,
    0,
    Operand_uimm12x8_encode, Operand_uimm12x8_decode,
    0, 0 },
  { "simm4", 26, -1, 0,
    0,
    Operand_simm4_encode, Operand_simm4_decode,
    0, 0 },
  { "arr", 14, 0, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_arr_encode, Operand_arr_decode,
    0, 0 },
  { "ars", 5, 0, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_ars_encode, Operand_ars_decode,
    0, 0 },
  { "*ars_invisible", 5, 0, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_ars_encode, Operand_ars_decode,
    0, 0 },
  { "art", 0, 0, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_art_encode, Operand_art_decode,
    0, 0 },
  { "ar0", 123, 0, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_ar0_encode, Operand_ar0_decode,
    0, 0 },
  { "ar4", 124, 0, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_ar4_encode, Operand_ar4_decode,
    0, 0 },
  { "ar8", 125, 0, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_ar8_encode, Operand_ar8_decode,
    0, 0 },
  { "ar12", 126, 0, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_ar12_encode, Operand_ar12_decode,
    0, 0 },
  { "ars_entry", 5, 0, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_ars_entry_encode, Operand_ars_entry_decode,
    0, 0 },
  { "immrx4", 14, -1, 0,
    0,
    Operand_immrx4_encode, Operand_immrx4_decode,
    0, 0 },
  { "lsi4x4", 14, -1, 0,
    0,
    Operand_lsi4x4_encode, Operand_lsi4x4_decode,
    0, 0 },
  { "simm7", 34, -1, 0,
    0,
    Operand_simm7_encode, Operand_simm7_decode,
    0, 0 },
  { "uimm6", 33, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_uimm6_encode, Operand_uimm6_decode,
    Operand_uimm6_ator, Operand_uimm6_rtoa },
  { "ai4const", 0, -1, 0,
    0,
    Operand_ai4const_encode, Operand_ai4const_decode,
    0, 0 },
  { "b4const", 14, -1, 0,
    0,
    Operand_b4const_encode, Operand_b4const_decode,
    0, 0 },
  { "b4constu", 14, -1, 0,
    0,
    Operand_b4constu_encode, Operand_b4constu_decode,
    0, 0 },
  { "uimm8", 4, -1, 0,
    0,
    Operand_uimm8_encode, Operand_uimm8_decode,
    0, 0 },
  { "uimm8x2", 4, -1, 0,
    0,
    Operand_uimm8x2_encode, Operand_uimm8x2_decode,
    0, 0 },
  { "uimm8x4", 4, -1, 0,
    0,
    Operand_uimm8x4_encode, Operand_uimm8x4_decode,
    0, 0 },
  { "uimm4x16", 13, -1, 0,
    0,
    Operand_uimm4x16_encode, Operand_uimm4x16_decode,
    0, 0 },
  { "simm8", 4, -1, 0,
    0,
    Operand_simm8_encode, Operand_simm8_decode,
    0, 0 },
  { "simm8x256", 4, -1, 0,
    0,
    Operand_simm8x256_encode, Operand_simm8x256_decode,
    0, 0 },
  { "simm12b", 6, -1, 0,
    0,
    Operand_simm12b_encode, Operand_simm12b_decode,
    0, 0 },
  { "msalp32", 18, -1, 0,
    0,
    Operand_msalp32_encode, Operand_msalp32_decode,
    0, 0 },
  { "op2p1", 13, -1, 0,
    0,
    Operand_op2p1_encode, Operand_op2p1_decode,
    0, 0 },
  { "label8", 4, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_label8_encode, Operand_label8_decode,
    Operand_label8_ator, Operand_label8_rtoa },
  { "ulabel8", 4, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_ulabel8_encode, Operand_ulabel8_decode,
    Operand_ulabel8_ator, Operand_ulabel8_rtoa },
  { "label12", 3, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_label12_encode, Operand_label12_decode,
    Operand_label12_ator, Operand_label12_rtoa },
  { "soffset", 10, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_soffset_encode, Operand_soffset_decode,
    Operand_soffset_ator, Operand_soffset_rtoa },
  { "uimm16x4", 7, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_uimm16x4_encode, Operand_uimm16x4_decode,
    Operand_uimm16x4_ator, Operand_uimm16x4_rtoa },
  { "mx", 43, 1, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_UNKNOWN,
    Operand_mx_encode, Operand_mx_decode,
    0, 0 },
  { "my", 42, 1, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_UNKNOWN,
    Operand_my_encode, Operand_my_decode,
    0, 0 },
  { "mw", 41, 1, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_mw_encode, Operand_mw_decode,
    0, 0 },
  { "mr0", 127, 1, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_mr0_encode, Operand_mr0_decode,
    0, 0 },
  { "mr1", 128, 1, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_mr1_encode, Operand_mr1_decode,
    0, 0 },
  { "mr2", 129, 1, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_mr2_encode, Operand_mr2_decode,
    0, 0 },
  { "mr3", 130, 1, 1,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_mr3_encode, Operand_mr3_decode,
    0, 0 },
  { "immt", 0, -1, 0,
    0,
    Operand_immt_encode, Operand_immt_decode,
    0, 0 },
  { "imms", 5, -1, 0,
    0,
    Operand_imms_encode, Operand_imms_decode,
    0, 0 },
  { "bt", 0, 2, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bt_encode, Operand_bt_decode,
    0, 0 },
  { "bs", 5, 2, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bs_encode, Operand_bs_decode,
    0, 0 },
  { "br", 14, 2, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_br_encode, Operand_br_decode,
    0, 0 },
  { "bt2", 44, 2, 2,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bt2_encode, Operand_bt2_decode,
    0, 0 },
  { "bs2", 45, 2, 2,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bs2_encode, Operand_bs2_decode,
    0, 0 },
  { "br2", 46, 2, 2,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_br2_encode, Operand_br2_decode,
    0, 0 },
  { "bt4", 47, 2, 4,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bt4_encode, Operand_bt4_decode,
    0, 0 },
  { "bs4", 48, 2, 4,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bs4_encode, Operand_bs4_decode,
    0, 0 },
  { "br4", 49, 2, 4,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_br4_encode, Operand_br4_decode,
    0, 0 },
  { "bt8", 50, 2, 8,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bt8_encode, Operand_bt8_decode,
    0, 0 },
  { "bs8", 51, 2, 8,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bs8_encode, Operand_bs8_decode,
    0, 0 },
  { "br8", 52, 2, 8,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_br8_encode, Operand_br8_decode,
    0, 0 },
  { "bt16", 131, 2, 16,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bt16_encode, Operand_bt16_decode,
    0, 0 },
  { "bs16", 132, 2, 16,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_bs16_encode, Operand_bs16_decode,
    0, 0 },
  { "br16", 133, 2, 16,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_br16_encode, Operand_br16_decode,
    0, 0 },
  { "brall", 134, 2, 16,
    XTENSA_OPERAND_IS_REGISTER | XTENSA_OPERAND_IS_INVISIBLE,
    Operand_brall_encode, Operand_brall_decode,
    0, 0 },
  { "tp7", 0, -1, 0,
    0,
    Operand_tp7_encode, Operand_tp7_decode,
    0, 0 },
  { "xt_wbr15_label", 53, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_xt_wbr15_label_encode, Operand_xt_wbr15_label_decode,
    Operand_xt_wbr15_label_ator, Operand_xt_wbr15_label_rtoa },
  { "xt_wbr18_label", 54, -1, 0,
    XTENSA_OPERAND_IS_PCRELATIVE,
    Operand_xt_wbr18_label_encode, Operand_xt_wbr18_label_decode,
    Operand_xt_wbr18_label_ator, Operand_xt_wbr18_label_rtoa },
  { "cimm8x4", 4, -1, 0,
    0,
    Operand_cimm8x4_encode, Operand_cimm8x4_decode,
    0, 0 },
  { "frr", 14, 3, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_frr_encode, Operand_frr_decode,
    0, 0 },
  { "frs", 5, 3, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_frs_encode, Operand_frs_decode,
    0, 0 },
  { "frt", 0, 3, 1,
    XTENSA_OPERAND_IS_REGISTER,
    Operand_frt_encode, Operand_frt_decode,
    0, 0 },
  { "t", 0, -1, 0, 0, 0, 0, 0, 0 },
  { "bbi4", 1, -1, 0, 0, 0, 0, 0, 0 },
  { "bbi", 2, -1, 0, 0, 0, 0, 0, 0 },
  { "imm12", 3, -1, 0, 0, 0, 0, 0, 0 },
  { "imm8", 4, -1, 0, 0, 0, 0, 0, 0 },
  { "s", 5, -1, 0, 0, 0, 0, 0, 0 },
  { "imm12b", 6, -1, 0, 0, 0, 0, 0, 0 },
  { "imm16", 7, -1, 0, 0, 0, 0, 0, 0 },
  { "m", 8, -1, 0, 0, 0, 0, 0, 0 },
  { "n", 9, -1, 0, 0, 0, 0, 0, 0 },
  { "offset", 10, -1, 0, 0, 0, 0, 0, 0 },
  { "op0", 11, -1, 0, 0, 0, 0, 0, 0 },
  { "op1", 12, -1, 0, 0, 0, 0, 0, 0 },
  { "op2", 13, -1, 0, 0, 0, 0, 0, 0 },
  { "r", 14, -1, 0, 0, 0, 0, 0, 0 },
  { "sa4", 15, -1, 0, 0, 0, 0, 0, 0 },
  { "sae4", 16, -1, 0, 0, 0, 0, 0, 0 },
  { "sae", 17, -1, 0, 0, 0, 0, 0, 0 },
  { "sal", 18, -1, 0, 0, 0, 0, 0, 0 },
  { "sargt", 19, -1, 0, 0, 0, 0, 0, 0 },
  { "sas4", 20, -1, 0, 0, 0, 0, 0, 0 },
  { "sas", 21, -1, 0, 0, 0, 0, 0, 0 },
  { "sr", 22, -1, 0, 0, 0, 0, 0, 0 },
  { "st", 23, -1, 0, 0, 0, 0, 0, 0 },
  { "thi3", 24, -1, 0, 0, 0, 0, 0, 0 },
  { "imm4", 25, -1, 0, 0, 0, 0, 0, 0 },
  { "mn", 26, -1, 0, 0, 0, 0, 0, 0 },
  { "i", 27, -1, 0, 0, 0, 0, 0, 0 },
  { "imm6lo", 28, -1, 0, 0, 0, 0, 0, 0 },
  { "imm6hi", 29, -1, 0, 0, 0, 0, 0, 0 },
  { "imm7lo", 30, -1, 0, 0, 0, 0, 0, 0 },
  { "imm7hi", 31, -1, 0, 0, 0, 0, 0, 0 },
  { "z", 32, -1, 0, 0, 0, 0, 0, 0 },
  { "imm6", 33, -1, 0, 0, 0, 0, 0, 0 },
  { "imm7", 34, -1, 0, 0, 0, 0, 0, 0 },
  { "r3", 35, -1, 0, 0, 0, 0, 0, 0 },
  { "rbit2", 36, -1, 0, 0, 0, 0, 0, 0 },
  { "rhi", 37, -1, 0, 0, 0, 0, 0, 0 },
  { "t3", 38, -1, 0, 0, 0, 0, 0, 0 },
  { "tbit2", 39, -1, 0, 0, 0, 0, 0, 0 },
  { "tlo", 40, -1, 0, 0, 0, 0, 0, 0 },
  { "w", 41, -1, 0, 0, 0, 0, 0, 0 },
  { "y", 42, -1, 0, 0, 0, 0, 0, 0 },
  { "x", 43, -1, 0, 0, 0, 0, 0, 0 },
  { "t2", 44, -1, 0, 0, 0, 0, 0, 0 },
  { "s2", 45, -1, 0, 0, 0, 0, 0, 0 },
  { "r2", 46, -1, 0, 0, 0, 0, 0, 0 },
  { "t4", 47, -1, 0, 0, 0, 0, 0, 0 },
  { "s4", 48, -1, 0, 0, 0, 0, 0, 0 },
  { "r4", 49, -1, 0, 0, 0, 0, 0, 0 },
  { "t8", 50, -1, 0, 0, 0, 0, 0, 0 },
  { "s8", 51, -1, 0, 0, 0, 0, 0, 0 },
  { "r8", 52, -1, 0, 0, 0, 0, 0, 0 },
  { "xt_wbr15_imm", 53, -1, 0, 0, 0, 0, 0, 0 },
  { "xt_wbr18_imm", 54, -1, 0, 0, 0, 0, 0, 0 },
  { "op0_xt_flix64_slot0_s3", 55, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld7", 56, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld8", 57, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld9", 58, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld11", 59, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld49xt_flix64_slot0", 60, -1, 0, 0, 0, 0, 0, 0 },
  { "op0_s4", 61, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld16", 62, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld19xt_flix64_slot1", 63, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld20xt_flix64_slot1", 64, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld21xt_flix64_slot1", 65, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld22xt_flix64_slot1", 66, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld23xt_flix64_slot1", 67, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld25xt_flix64_slot1", 68, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld26xt_flix64_slot1", 69, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld28xt_flix64_slot1", 70, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld30xt_flix64_slot1", 71, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld32xt_flix64_slot1", 72, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld33xt_flix64_slot1", 73, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld35xt_flix64_slot1", 74, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld51xt_flix64_slot1", 75, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld52xt_flix64_slot1", 76, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld53xt_flix64_slot1", 77, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld54xt_flix64_slot1", 78, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld57xt_flix64_slot1", 79, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld58xt_flix64_slot1", 80, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld60xt_flix64_slot1", 81, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld62xt_flix64_slot1", 82, -1, 0, 0, 0, 0, 0, 0 },
  { "op0_s5", 83, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld36xt_flix64_slot2", 84, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld37xt_flix64_slot2", 85, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld39xt_flix64_slot2", 86, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld41xt_flix64_slot2", 87, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld42xt_flix64_slot2", 88, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld44xt_flix64_slot2", 89, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld45xt_flix64_slot2", 90, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld47xt_flix64_slot2", 91, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld63xt_flix64_slot2", 92, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld64xt_flix64_slot2", 93, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld65xt_flix64_slot2", 94, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld66xt_flix64_slot2", 95, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld68xt_flix64_slot2", 96, -1, 0, 0, 0, 0, 0, 0 },
  { "op0_s6", 97, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld70xt_flix64_slot3", 98, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld71", 99, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld72xt_flix64_slot3", 100, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld73xt_flix64_slot3", 101, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld74xt_flix64_slot3", 102, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld75xt_flix64_slot3", 103, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld76xt_flix64_slot3", 104, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld77xt_flix64_slot3", 105, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld78xt_flix64_slot3", 106, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld79xt_flix64_slot3", 107, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld80xt_flix64_slot3", 108, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld81xt_flix64_slot3", 109, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld82xt_flix64_slot3", 110, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld83xt_flix64_slot3", 111, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld84xt_flix64_slot3", 112, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld85xt_flix64_slot3", 113, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld86xt_flix64_slot3", 114, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld87xt_flix64_slot3", 115, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld88xt_flix64_slot3", 116, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld89xt_flix64_slot3", 117, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld90xt_flix64_slot3", 118, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld91xt_flix64_slot3", 119, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld92xt_flix64_slot3", 120, -1, 0, 0, 0, 0, 0, 0 },
  { "combined3e2c5767_fld93xt_flix64_slot3", 121, -1, 0, 0, 0, 0, 0, 0 },
  { "op0_xt_flix64_slot0", 122, -1, 0, 0, 0, 0, 0, 0 }
};


/* Iclass table.  */

static xtensa_arg_internal Iclass_xt_iclass_rfe_stateArgs[] = {
  { { STATE_PSRING }, 'i' },
  { { STATE_PSEXCM }, 'm' },
  { { STATE_EPC1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rfde_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DEPC }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_call12_args[] = {
  { { 0 /* soffsetx4 */ }, 'i' },
  { { 10 /* ar12 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_call12_stateArgs[] = {
  { { STATE_PSCALLINC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_call8_args[] = {
  { { 0 /* soffsetx4 */ }, 'i' },
  { { 9 /* ar8 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_call8_stateArgs[] = {
  { { STATE_PSCALLINC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_call4_args[] = {
  { { 0 /* soffsetx4 */ }, 'i' },
  { { 8 /* ar4 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_call4_stateArgs[] = {
  { { STATE_PSCALLINC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_callx12_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 10 /* ar12 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_callx12_stateArgs[] = {
  { { STATE_PSCALLINC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_callx8_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 9 /* ar8 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_callx8_stateArgs[] = {
  { { STATE_PSCALLINC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_callx4_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 8 /* ar4 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_callx4_stateArgs[] = {
  { { STATE_PSCALLINC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_entry_args[] = {
  { { 11 /* ars_entry */ }, 's' },
  { { 4 /* ars */ }, 'i' },
  { { 1 /* uimm12x8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_entry_stateArgs[] = {
  { { STATE_PSCALLINC }, 'i' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSWOE }, 'i' },
  { { STATE_WindowBase }, 'm' },
  { { STATE_WindowStart }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_movsp_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_movsp_stateArgs[] = {
  { { STATE_WindowBase }, 'i' },
  { { STATE_WindowStart }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rotw_args[] = {
  { { 2 /* simm4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rotw_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_WindowBase }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_retw_args[] = {
  { { 5 /* *ars_invisible */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_retw_stateArgs[] = {
  { { STATE_WindowBase }, 'm' },
  { { STATE_WindowStart }, 'm' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSWOE }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rfwou_stateArgs[] = {
  { { STATE_EPC1 }, 'i' },
  { { STATE_PSEXCM }, 'm' },
  { { STATE_PSRING }, 'i' },
  { { STATE_WindowBase }, 'm' },
  { { STATE_WindowStart }, 'm' },
  { { STATE_PSOWB }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l32e_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 12 /* immrx4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l32e_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_s32e_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' },
  { { 12 /* immrx4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_s32e_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_windowbase_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_windowbase_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_WindowBase }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_windowbase_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_windowbase_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_WindowBase }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_windowbase_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_windowbase_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_WindowBase }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_windowstart_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_windowstart_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_WindowStart }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_windowstart_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_windowstart_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_WindowStart }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_windowstart_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_windowstart_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_WindowStart }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_add_n_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_addi_n_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 16 /* ai4const */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bz6_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 15 /* uimm6 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_loadi4_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 13 /* lsi4x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mov_n_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_movi_n_args[] = {
  { { 4 /* ars */ }, 'o' },
  { { 14 /* simm7 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_retn_args[] = {
  { { 5 /* *ars_invisible */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_storei4_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' },
  { { 13 /* lsi4x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_rur_threadptr_args[] = {
  { { 3 /* arr */ }, 'o' }
};

static xtensa_arg_internal Iclass_rur_threadptr_stateArgs[] = {
  { { STATE_THREADPTR }, 'i' }
};

static xtensa_arg_internal Iclass_wur_threadptr_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_wur_threadptr_stateArgs[] = {
  { { STATE_THREADPTR }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_addi_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 23 /* simm8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_addmi_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 24 /* simm8x256 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_addsub_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bit_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bsi8_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 17 /* b4const */ }, 'i' },
  { { 28 /* label8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bsi8b_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 67 /* bbi */ }, 'i' },
  { { 28 /* label8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bsi8u_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 18 /* b4constu */ }, 'i' },
  { { 28 /* label8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bst8_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' },
  { { 28 /* label8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bsz12_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 30 /* label12 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_call0_args[] = {
  { { 0 /* soffsetx4 */ }, 'i' },
  { { 7 /* ar0 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_callx0_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 7 /* ar0 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_exti_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 6 /* art */ }, 'i' },
  { { 82 /* sae */ }, 'i' },
  { { 27 /* op2p1 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_jump_args[] = {
  { { 31 /* soffset */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_jumpx_args[] = {
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l16ui_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 20 /* uimm8x2 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l16si_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 20 /* uimm8x2 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l32i_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l32r_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 32 /* uimm16x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l32r_stateArgs[] = {
  { { STATE_LITBADDR }, 'i' },
  { { STATE_LITBEN }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l8i_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 19 /* uimm8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_loop_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 29 /* ulabel8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_loop_stateArgs[] = {
  { { STATE_LBEG }, 'o' },
  { { STATE_LEND }, 'o' },
  { { STATE_LCOUNT }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_loopz_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 29 /* ulabel8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_loopz_stateArgs[] = {
  { { STATE_LBEG }, 'o' },
  { { STATE_LEND }, 'o' },
  { { STATE_LCOUNT }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_movi_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 25 /* simm12b */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_movz_args[] = {
  { { 3 /* arr */ }, 'm' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_neg_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_return_args[] = {
  { { 5 /* *ars_invisible */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_s16i_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' },
  { { 20 /* uimm8x2 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_s32i_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_s8i_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' },
  { { 19 /* uimm8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sar_args[] = {
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sar_stateArgs[] = {
  { { STATE_SAR }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_sari_args[] = {
  { { 86 /* sas */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sari_stateArgs[] = {
  { { STATE_SAR }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_shifts_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_shifts_stateArgs[] = {
  { { STATE_SAR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_shiftst_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_shiftst_stateArgs[] = {
  { { STATE_SAR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_shiftt_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_shiftt_stateArgs[] = {
  { { STATE_SAR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_slli_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 26 /* msalp32 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_srai_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 6 /* art */ }, 'i' },
  { { 84 /* sargt */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_srli_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 6 /* art */ }, 'i' },
  { { 70 /* s */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sync_stateArgs[] = {
  { { STATE_XTSYNC }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsil_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 70 /* s */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsil_stateArgs[] = {
  { { STATE_PSWOE }, 'i' },
  { { STATE_PSCALLINC }, 'i' },
  { { STATE_PSOWB }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_PSUM }, 'i' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSINTLEVEL }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_lend_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_lend_stateArgs[] = {
  { { STATE_LEND }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_lend_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_lend_stateArgs[] = {
  { { STATE_LEND }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_lend_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_lend_stateArgs[] = {
  { { STATE_LEND }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_lcount_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_lcount_stateArgs[] = {
  { { STATE_LCOUNT }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_lcount_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_lcount_stateArgs[] = {
  { { STATE_XTSYNC }, 'o' },
  { { STATE_LCOUNT }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_lcount_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_lcount_stateArgs[] = {
  { { STATE_XTSYNC }, 'o' },
  { { STATE_LCOUNT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_lbeg_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_lbeg_stateArgs[] = {
  { { STATE_LBEG }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_lbeg_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_lbeg_stateArgs[] = {
  { { STATE_LBEG }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_lbeg_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_lbeg_stateArgs[] = {
  { { STATE_LBEG }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_sar_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_sar_stateArgs[] = {
  { { STATE_SAR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_sar_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_sar_stateArgs[] = {
  { { STATE_SAR }, 'o' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_sar_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_sar_stateArgs[] = {
  { { STATE_SAR }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_litbase_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_litbase_stateArgs[] = {
  { { STATE_LITBADDR }, 'i' },
  { { STATE_LITBEN }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_litbase_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_litbase_stateArgs[] = {
  { { STATE_LITBADDR }, 'o' },
  { { STATE_LITBEN }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_litbase_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_litbase_stateArgs[] = {
  { { STATE_LITBADDR }, 'm' },
  { { STATE_LITBEN }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_176_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_176_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_208_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_208_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ps_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ps_stateArgs[] = {
  { { STATE_PSWOE }, 'i' },
  { { STATE_PSCALLINC }, 'i' },
  { { STATE_PSOWB }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_PSUM }, 'i' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSINTLEVEL }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ps_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ps_stateArgs[] = {
  { { STATE_PSWOE }, 'o' },
  { { STATE_PSCALLINC }, 'o' },
  { { STATE_PSOWB }, 'o' },
  { { STATE_PSRING }, 'm' },
  { { STATE_PSUM }, 'o' },
  { { STATE_PSEXCM }, 'm' },
  { { STATE_PSINTLEVEL }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ps_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ps_stateArgs[] = {
  { { STATE_PSWOE }, 'm' },
  { { STATE_PSCALLINC }, 'm' },
  { { STATE_PSOWB }, 'm' },
  { { STATE_PSRING }, 'm' },
  { { STATE_PSUM }, 'm' },
  { { STATE_PSEXCM }, 'm' },
  { { STATE_PSINTLEVEL }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc1_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc1_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC1 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc1_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC1 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave1_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave1_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE1 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave1_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE1 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc2_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC2 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc2_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC2 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc2_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC2 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave2_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE2 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave2_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE2 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave2_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE2 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc3_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC3 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc3_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC3 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc3_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC3 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave3_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE3 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave3_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE3 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave3_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE3 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc4_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC4 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc4_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC4 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc4_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC4 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave4_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE4 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave4_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE4 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave4_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE4 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc5_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC5 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc5_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC5 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc5_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC5 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave5_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE5 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave5_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE5 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave5_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE5 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc6_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC6 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc6_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC6 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc6_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC6 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave6_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE6 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave6_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE6 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave6_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE6 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc7_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_epc7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC7 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc7_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_epc7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC7 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc7_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_epc7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPC7 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave7_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excsave7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE7 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave7_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excsave7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE7 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave7_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excsave7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCSAVE7 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps2_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS2 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps2_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS2 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps2_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS2 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps3_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS3 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps3_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS3 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps3_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS3 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps4_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS4 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps4_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS4 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps4_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps4_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS4 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps5_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS5 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps5_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS5 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps5_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps5_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS5 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps6_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS6 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps6_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS6 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps6_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps6_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS6 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps7_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_eps7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS7 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps7_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_eps7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS7 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps7_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_eps7_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EPS7 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excvaddr_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_excvaddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCVADDR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excvaddr_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_excvaddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCVADDR }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excvaddr_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_excvaddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCVADDR }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_depc_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_depc_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DEPC }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_depc_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_depc_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DEPC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_depc_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_depc_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DEPC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_exccause_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_exccause_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCCAUSE }, 'i' },
  { { STATE_XTSYNC }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_exccause_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_exccause_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCCAUSE }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_exccause_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_exccause_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_EXCCAUSE }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_misc0_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_misc0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC0 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_misc0_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_misc0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC0 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_misc0_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_misc0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC0 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_misc1_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_misc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_misc1_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_misc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC1 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_misc1_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_misc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC1 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_misc2_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_misc2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC2 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_misc2_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_misc2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC2 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_misc2_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_misc2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC2 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_misc3_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_misc3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC3 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_misc3_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_misc3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC3 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_misc3_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_misc3_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_MISC3 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_prid_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_prid_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_vecbase_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_vecbase_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_VECBASE }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_vecbase_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_vecbase_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_VECBASE }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_vecbase_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_vecbase_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_VECBASE }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_aa_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_aa_stateArgs[] = {
  { { STATE_ACC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_ad_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 34 /* my */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_ad_stateArgs[] = {
  { { STATE_ACC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_da_args[] = {
  { { 33 /* mx */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_da_stateArgs[] = {
  { { STATE_ACC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_dd_args[] = {
  { { 33 /* mx */ }, 'i' },
  { { 34 /* my */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_dd_stateArgs[] = {
  { { STATE_ACC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16a_aa_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16a_aa_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16a_ad_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 34 /* my */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16a_ad_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16a_da_args[] = {
  { { 33 /* mx */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16a_da_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16a_dd_args[] = {
  { { 33 /* mx */ }, 'i' },
  { { 34 /* my */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16a_dd_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16al_da_args[] = {
  { { 35 /* mw */ }, 'o' },
  { { 4 /* ars */ }, 'm' },
  { { 33 /* mx */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16al_da_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16al_dd_args[] = {
  { { 35 /* mw */ }, 'o' },
  { { 4 /* ars */ }, 'm' },
  { { 33 /* mx */ }, 'i' },
  { { 34 /* my */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16al_dd_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_mac16_l_args[] = {
  { { 35 /* mw */ }, 'o' },
  { { 4 /* ars */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_mul16_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_m0_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 36 /* mr0 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_m0_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 36 /* mr0 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_m0_args[] = {
  { { 6 /* art */ }, 'm' },
  { { 36 /* mr0 */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_m1_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 37 /* mr1 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_m1_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 37 /* mr1 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_m1_args[] = {
  { { 6 /* art */ }, 'm' },
  { { 37 /* mr1 */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_m2_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 38 /* mr2 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_m2_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 38 /* mr2 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_m2_args[] = {
  { { 6 /* art */ }, 'm' },
  { { 38 /* mr2 */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_m3_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 39 /* mr3 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_m3_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 39 /* mr3 */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_m3_args[] = {
  { { 6 /* art */ }, 'm' },
  { { 39 /* mr3 */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_acclo_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_acclo_stateArgs[] = {
  { { STATE_ACC }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_acclo_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_acclo_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_acclo_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_acclo_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_acchi_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_acchi_stateArgs[] = {
  { { STATE_ACC }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_acchi_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_acchi_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_acchi_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_acchi_stateArgs[] = {
  { { STATE_ACC }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rfi_args[] = {
  { { 70 /* s */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rfi_stateArgs[] = {
  { { STATE_PSWOE }, 'o' },
  { { STATE_PSCALLINC }, 'o' },
  { { STATE_PSOWB }, 'o' },
  { { STATE_PSRING }, 'm' },
  { { STATE_PSUM }, 'o' },
  { { STATE_PSEXCM }, 'm' },
  { { STATE_PSINTLEVEL }, 'o' },
  { { STATE_EPC1 }, 'i' },
  { { STATE_EPC2 }, 'i' },
  { { STATE_EPC3 }, 'i' },
  { { STATE_EPC4 }, 'i' },
  { { STATE_EPC5 }, 'i' },
  { { STATE_EPC6 }, 'i' },
  { { STATE_EPC7 }, 'i' },
  { { STATE_EPS2 }, 'i' },
  { { STATE_EPS3 }, 'i' },
  { { STATE_EPS4 }, 'i' },
  { { STATE_EPS5 }, 'i' },
  { { STATE_EPS6 }, 'i' },
  { { STATE_EPS7 }, 'i' },
  { { STATE_InOCDMode }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_wait_args[] = {
  { { 70 /* s */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wait_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_PSINTLEVEL }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_interrupt_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_interrupt_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_INTERRUPT }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_intset_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_intset_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' },
  { { STATE_INTERRUPT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_intclear_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_intclear_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' },
  { { STATE_INTERRUPT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_intenable_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_intenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_INTENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_intenable_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_intenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_INTENABLE }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_intenable_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_intenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_INTENABLE }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_break_args[] = {
  { { 41 /* imms */ }, 'i' },
  { { 40 /* immt */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_break_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSINTLEVEL }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_break_n_args[] = {
  { { 41 /* imms */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_break_n_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSINTLEVEL }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dbreaka0_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dbreaka0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKA0 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dbreaka0_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dbreaka0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKA0 }, 'o' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dbreaka0_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dbreaka0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKA0 }, 'm' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dbreakc0_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dbreakc0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKC0 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dbreakc0_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dbreakc0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKC0 }, 'o' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dbreakc0_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dbreakc0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKC0 }, 'm' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dbreaka1_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dbreaka1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKA1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dbreaka1_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dbreaka1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKA1 }, 'o' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dbreaka1_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dbreaka1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKA1 }, 'm' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dbreakc1_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dbreakc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKC1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dbreakc1_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dbreakc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKC1 }, 'o' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dbreakc1_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dbreakc1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DBREAKC1 }, 'm' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ibreaka0_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ibreaka0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKA0 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ibreaka0_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ibreaka0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKA0 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ibreaka0_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ibreaka0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKA0 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ibreaka1_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ibreaka1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKA1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ibreaka1_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ibreaka1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKA1 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ibreaka1_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ibreaka1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKA1 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ibreakenable_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ibreakenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ibreakenable_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ibreakenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKENABLE }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ibreakenable_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ibreakenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_IBREAKENABLE }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_debugcause_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_debugcause_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DEBUGCAUSE }, 'i' },
  { { STATE_DBNUM }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_debugcause_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_debugcause_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DEBUGCAUSE }, 'o' },
  { { STATE_DBNUM }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_debugcause_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_debugcause_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DEBUGCAUSE }, 'm' },
  { { STATE_DBNUM }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_icount_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_icount_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_ICOUNT }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_icount_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_icount_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' },
  { { STATE_ICOUNT }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_icount_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_icount_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' },
  { { STATE_ICOUNT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_icountlevel_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_icountlevel_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_ICOUNTLEVEL }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_icountlevel_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_icountlevel_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_ICOUNTLEVEL }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_icountlevel_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_icountlevel_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_ICOUNTLEVEL }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ddr_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DDR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ddr_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' },
  { { STATE_DDR }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ddr_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' },
  { { STATE_DDR }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rfdo_args[] = {
  { { 41 /* imms */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rfdo_stateArgs[] = {
  { { STATE_InOCDMode }, 'm' },
  { { STATE_EPC6 }, 'i' },
  { { STATE_PSWOE }, 'o' },
  { { STATE_PSCALLINC }, 'o' },
  { { STATE_PSOWB }, 'o' },
  { { STATE_PSRING }, 'o' },
  { { STATE_PSUM }, 'o' },
  { { STATE_PSEXCM }, 'o' },
  { { STATE_PSINTLEVEL }, 'o' },
  { { STATE_EPS6 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rfdd_stateArgs[] = {
  { { STATE_InOCDMode }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_mmid_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_mmid_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_bbool1_args[] = {
  { { 44 /* br */ }, 'o' },
  { { 43 /* bs */ }, 'i' },
  { { 42 /* bt */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bbool4_args[] = {
  { { 42 /* bt */ }, 'o' },
  { { 49 /* bs4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bbool8_args[] = {
  { { 42 /* bt */ }, 'o' },
  { { 52 /* bs8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bbranch_args[] = {
  { { 43 /* bs */ }, 'i' },
  { { 28 /* label8 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_bmove_args[] = {
  { { 3 /* arr */ }, 'm' },
  { { 4 /* ars */ }, 'i' },
  { { 42 /* bt */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_RSR_BR_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 57 /* brall */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_WSR_BR_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 57 /* brall */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_XSR_BR_args[] = {
  { { 6 /* art */ }, 'm' },
  { { 57 /* brall */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ccount_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ccount_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOUNT }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ccount_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ccount_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' },
  { { STATE_CCOUNT }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ccount_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ccount_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' },
  { { STATE_CCOUNT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ccompare0_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ccompare0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE0 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ccompare0_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ccompare0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE0 }, 'o' },
  { { STATE_INTERRUPT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ccompare0_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ccompare0_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE0 }, 'm' },
  { { STATE_INTERRUPT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ccompare1_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ccompare1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ccompare1_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ccompare1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE1 }, 'o' },
  { { STATE_INTERRUPT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ccompare1_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ccompare1_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE1 }, 'm' },
  { { STATE_INTERRUPT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ccompare2_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ccompare2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE2 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ccompare2_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ccompare2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE2 }, 'o' },
  { { STATE_INTERRUPT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ccompare2_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ccompare2_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CCOMPARE2 }, 'm' },
  { { STATE_INTERRUPT }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_icache_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_icache_lock_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 22 /* uimm4x16 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_icache_lock_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_icache_inv_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_icache_inv_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_licx_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_licx_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sicx_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sicx_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_dcache_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_dcache_ind_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 22 /* uimm4x16 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_dcache_ind_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_dcache_inv_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_dcache_inv_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_dpf_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_dcache_lock_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 22 /* uimm4x16 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_dcache_lock_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sdct_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sdct_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_ldct_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_ldct_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ptevaddr_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_ptevaddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_PTBASE }, 'o' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ptevaddr_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_ptevaddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_PTBASE }, 'i' },
  { { STATE_EXCVADDR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ptevaddr_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_ptevaddr_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_PTBASE }, 'm' },
  { { STATE_EXCVADDR }, 'i' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_rasid_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_rasid_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_ASID3 }, 'i' },
  { { STATE_ASID2 }, 'i' },
  { { STATE_ASID1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_rasid_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_rasid_stateArgs[] = {
  { { STATE_XTSYNC }, 'o' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_ASID3 }, 'o' },
  { { STATE_ASID2 }, 'o' },
  { { STATE_ASID1 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_rasid_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_rasid_stateArgs[] = {
  { { STATE_XTSYNC }, 'o' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_ASID3 }, 'm' },
  { { STATE_ASID2 }, 'm' },
  { { STATE_ASID1 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_itlbcfg_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_itlbcfg_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_INSTPGSZID4 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_itlbcfg_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_itlbcfg_stateArgs[] = {
  { { STATE_XTSYNC }, 'o' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_INSTPGSZID4 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_itlbcfg_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_itlbcfg_stateArgs[] = {
  { { STATE_XTSYNC }, 'o' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_INSTPGSZID4 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dtlbcfg_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_dtlbcfg_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DATAPGSZID4 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dtlbcfg_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_dtlbcfg_stateArgs[] = {
  { { STATE_XTSYNC }, 'o' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DATAPGSZID4 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dtlbcfg_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_dtlbcfg_stateArgs[] = {
  { { STATE_XTSYNC }, 'o' },
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_DATAPGSZID4 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_idtlb_args[] = {
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_idtlb_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rdtlb_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rdtlb_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wdtlb_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wdtlb_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_XTSYNC }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_iitlb_args[] = {
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_iitlb_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_ritlb_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_ritlb_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_witlb_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_witlb_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_ldpte_stateArgs[] = {
  { { STATE_PTBASE }, 'i' },
  { { STATE_EXCVADDR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_hwwitlba_stateArgs[] = {
  { { STATE_EXCVADDR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_hwwdtlba_stateArgs[] = {
  { { STATE_EXCVADDR }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_cpenable_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_cpenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_cpenable_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_cpenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CPENABLE }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_cpenable_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_cpenable_stateArgs[] = {
  { { STATE_PSEXCM }, 'i' },
  { { STATE_PSRING }, 'i' },
  { { STATE_CPENABLE }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_clamp_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 58 /* tp7 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_minmax_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_nsa_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_sx_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 58 /* tp7 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_l32ai_args[] = {
  { { 6 /* art */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_s32ri_args[] = {
  { { 6 /* art */ }, 'i' },
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_s32c1i_args[] = {
  { { 6 /* art */ }, 'm' },
  { { 4 /* ars */ }, 'i' },
  { { 21 /* uimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_s32c1i_stateArgs[] = {
  { { STATE_SCOMPARE1 }, 'i' },
  { { STATE_SCOMPARE1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_scompare1_args[] = {
  { { 6 /* art */ }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_rsr_scompare1_stateArgs[] = {
  { { STATE_SCOMPARE1 }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_scompare1_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wsr_scompare1_stateArgs[] = {
  { { STATE_SCOMPARE1 }, 'o' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_scompare1_args[] = {
  { { 6 /* art */ }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_xsr_scompare1_stateArgs[] = {
  { { STATE_SCOMPARE1 }, 'm' }
};

static xtensa_arg_internal Iclass_xt_iclass_div_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_mul32_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_rur_fcr_args[] = {
  { { 3 /* arr */ }, 'o' }
};

static xtensa_arg_internal Iclass_rur_fcr_stateArgs[] = {
  { { STATE_RoundMode }, 'i' },
  { { STATE_InvalidEnable }, 'i' },
  { { STATE_DivZeroEnable }, 'i' },
  { { STATE_OverflowEnable }, 'i' },
  { { STATE_UnderflowEnable }, 'i' },
  { { STATE_InexactEnable }, 'i' },
  { { STATE_FPreserved20 }, 'i' },
  { { STATE_FPreserved5 }, 'i' },
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_wur_fcr_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_wur_fcr_stateArgs[] = {
  { { STATE_RoundMode }, 'o' },
  { { STATE_InvalidEnable }, 'o' },
  { { STATE_DivZeroEnable }, 'o' },
  { { STATE_OverflowEnable }, 'o' },
  { { STATE_UnderflowEnable }, 'o' },
  { { STATE_InexactEnable }, 'o' },
  { { STATE_FPreserved20 }, 'o' },
  { { STATE_FPreserved5 }, 'o' },
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_rur_fsr_args[] = {
  { { 3 /* arr */ }, 'o' }
};

static xtensa_arg_internal Iclass_rur_fsr_stateArgs[] = {
  { { STATE_InvalidFlag }, 'i' },
  { { STATE_DivZeroFlag }, 'i' },
  { { STATE_OverflowFlag }, 'i' },
  { { STATE_UnderflowFlag }, 'i' },
  { { STATE_InexactFlag }, 'i' },
  { { STATE_FPreserved20a }, 'i' },
  { { STATE_FPreserved7 }, 'i' },
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_wur_fsr_args[] = {
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_wur_fsr_stateArgs[] = {
  { { STATE_InvalidFlag }, 'o' },
  { { STATE_DivZeroFlag }, 'o' },
  { { STATE_OverflowFlag }, 'o' },
  { { STATE_UnderflowFlag }, 'o' },
  { { STATE_InexactFlag }, 'o' },
  { { STATE_FPreserved20a }, 'o' },
  { { STATE_FPreserved7 }, 'o' },
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_args[] = {
  { { 62 /* frr */ }, 'o' },
  { { 63 /* frs */ }, 'i' },
  { { 64 /* frt */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_stateArgs[] = {
  { { STATE_RoundMode }, 'i' },
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_mac_args[] = {
  { { 62 /* frr */ }, 'm' },
  { { 63 /* frs */ }, 'i' },
  { { 64 /* frt */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_mac_stateArgs[] = {
  { { STATE_RoundMode }, 'i' },
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_cmov_args[] = {
  { { 62 /* frr */ }, 'm' },
  { { 63 /* frs */ }, 'i' },
  { { 42 /* bt */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_cmov_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_mov_args[] = {
  { { 62 /* frr */ }, 'm' },
  { { 63 /* frs */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_mov_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_mov2_args[] = {
  { { 62 /* frr */ }, 'o' },
  { { 63 /* frs */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_mov2_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_cmp_args[] = {
  { { 44 /* br */ }, 'o' },
  { { 63 /* frs */ }, 'i' },
  { { 64 /* frt */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_cmp_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_float_args[] = {
  { { 62 /* frr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 65 /* t */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_float_stateArgs[] = {
  { { STATE_RoundMode }, 'i' },
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_int_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 63 /* frs */ }, 'i' },
  { { 65 /* t */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_int_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_rfr_args[] = {
  { { 3 /* arr */ }, 'o' },
  { { 63 /* frs */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_rfr_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_wfr_args[] = {
  { { 62 /* frr */ }, 'o' },
  { { 4 /* ars */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_wfr_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_lsi_args[] = {
  { { 64 /* frt */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 61 /* cimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_lsi_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_lsiu_args[] = {
  { { 64 /* frt */ }, 'o' },
  { { 4 /* ars */ }, 'm' },
  { { 61 /* cimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_lsiu_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_lsx_args[] = {
  { { 62 /* frr */ }, 'o' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_lsx_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_lsxu_args[] = {
  { { 62 /* frr */ }, 'o' },
  { { 4 /* ars */ }, 'm' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_lsxu_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_ssi_args[] = {
  { { 64 /* frt */ }, 'i' },
  { { 4 /* ars */ }, 'i' },
  { { 61 /* cimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_ssi_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_ssiu_args[] = {
  { { 64 /* frt */ }, 'i' },
  { { 4 /* ars */ }, 'm' },
  { { 61 /* cimm8x4 */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_ssiu_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_ssx_args[] = {
  { { 62 /* frr */ }, 'i' },
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_ssx_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_fp_ssxu_args[] = {
  { { 62 /* frr */ }, 'i' },
  { { 4 /* ars */ }, 'm' },
  { { 6 /* art */ }, 'i' }
};

static xtensa_arg_internal Iclass_fp_ssxu_stateArgs[] = {
  { { STATE_CPENABLE }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wb18_0_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 60 /* xt_wbr18_label */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wb18_1_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 17 /* b4const */ }, 'i' },
  { { 60 /* xt_wbr18_label */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wb18_2_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 18 /* b4constu */ }, 'i' },
  { { 60 /* xt_wbr18_label */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wb18_3_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 67 /* bbi */ }, 'i' },
  { { 60 /* xt_wbr18_label */ }, 'i' }
};

static xtensa_arg_internal Iclass_xt_iclass_wb18_4_args[] = {
  { { 4 /* ars */ }, 'i' },
  { { 6 /* art */ }, 'i' },
  { { 60 /* xt_wbr18_label */ }, 'i' }
};

static xtensa_iclass_internal iclasses[] = {
  { 0, 0 /* xt_iclass_excw */,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_rfe */,
    3, Iclass_xt_iclass_rfe_stateArgs, 0, 0 },
  { 0, 0 /* xt_iclass_rfde */,
    3, Iclass_xt_iclass_rfde_stateArgs, 0, 0 },
  { 0, 0 /* xt_iclass_syscall */,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_simcall */,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_call12_args,
    1, Iclass_xt_iclass_call12_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_call8_args,
    1, Iclass_xt_iclass_call8_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_call4_args,
    1, Iclass_xt_iclass_call4_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_callx12_args,
    1, Iclass_xt_iclass_callx12_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_callx8_args,
    1, Iclass_xt_iclass_callx8_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_callx4_args,
    1, Iclass_xt_iclass_callx4_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_entry_args,
    5, Iclass_xt_iclass_entry_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_movsp_args,
    2, Iclass_xt_iclass_movsp_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rotw_args,
    3, Iclass_xt_iclass_rotw_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_retw_args,
    4, Iclass_xt_iclass_retw_stateArgs, 0, 0 },
  { 0, 0 /* xt_iclass_rfwou */,
    6, Iclass_xt_iclass_rfwou_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_l32e_args,
    2, Iclass_xt_iclass_l32e_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_s32e_args,
    2, Iclass_xt_iclass_s32e_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_windowbase_args,
    3, Iclass_xt_iclass_rsr_windowbase_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_windowbase_args,
    3, Iclass_xt_iclass_wsr_windowbase_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_windowbase_args,
    3, Iclass_xt_iclass_xsr_windowbase_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_windowstart_args,
    3, Iclass_xt_iclass_rsr_windowstart_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_windowstart_args,
    3, Iclass_xt_iclass_wsr_windowstart_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_windowstart_args,
    3, Iclass_xt_iclass_xsr_windowstart_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_add_n_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_addi_n_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_bz6_args,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_ill_n */,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_loadi4_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_mov_n_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_movi_n_args,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_nopn */,
    0, 0, 0, 0 },
  { 1, Iclass_xt_iclass_retn_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_storei4_args,
    0, 0, 0, 0 },
  { 1, Iclass_rur_threadptr_args,
    1, Iclass_rur_threadptr_stateArgs, 0, 0 },
  { 1, Iclass_wur_threadptr_args,
    1, Iclass_wur_threadptr_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_addi_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_addmi_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_addsub_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_bit_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_bsi8_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_bsi8b_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_bsi8u_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_bst8_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_bsz12_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_call0_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_callx0_args,
    0, 0, 0, 0 },
  { 4, Iclass_xt_iclass_exti_args,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_ill */,
    0, 0, 0, 0 },
  { 1, Iclass_xt_iclass_jump_args,
    0, 0, 0, 0 },
  { 1, Iclass_xt_iclass_jumpx_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_l16ui_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_l16si_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_l32i_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_l32r_args,
    2, Iclass_xt_iclass_l32r_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_l8i_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_loop_args,
    3, Iclass_xt_iclass_loop_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_loopz_args,
    3, Iclass_xt_iclass_loopz_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_movi_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_movz_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_neg_args,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_nop */,
    0, 0, 0, 0 },
  { 1, Iclass_xt_iclass_return_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_s16i_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_s32i_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_s8i_args,
    0, 0, 0, 0 },
  { 1, Iclass_xt_iclass_sar_args,
    1, Iclass_xt_iclass_sar_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_sari_args,
    1, Iclass_xt_iclass_sari_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_shifts_args,
    1, Iclass_xt_iclass_shifts_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_shiftst_args,
    1, Iclass_xt_iclass_shiftst_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_shiftt_args,
    1, Iclass_xt_iclass_shiftt_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_slli_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_srai_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_srli_args,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_memw */,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_extw */,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_isync */,
    0, 0, 0, 0 },
  { 0, 0 /* xt_iclass_sync */,
    1, Iclass_xt_iclass_sync_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_rsil_args,
    7, Iclass_xt_iclass_rsil_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_lend_args,
    1, Iclass_xt_iclass_rsr_lend_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_lend_args,
    1, Iclass_xt_iclass_wsr_lend_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_lend_args,
    1, Iclass_xt_iclass_xsr_lend_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_lcount_args,
    1, Iclass_xt_iclass_rsr_lcount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_lcount_args,
    2, Iclass_xt_iclass_wsr_lcount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_lcount_args,
    2, Iclass_xt_iclass_xsr_lcount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_lbeg_args,
    1, Iclass_xt_iclass_rsr_lbeg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_lbeg_args,
    1, Iclass_xt_iclass_wsr_lbeg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_lbeg_args,
    1, Iclass_xt_iclass_xsr_lbeg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_sar_args,
    1, Iclass_xt_iclass_rsr_sar_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_sar_args,
    2, Iclass_xt_iclass_wsr_sar_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_sar_args,
    1, Iclass_xt_iclass_xsr_sar_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_litbase_args,
    2, Iclass_xt_iclass_rsr_litbase_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_litbase_args,
    2, Iclass_xt_iclass_wsr_litbase_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_litbase_args,
    2, Iclass_xt_iclass_xsr_litbase_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_176_args,
    2, Iclass_xt_iclass_rsr_176_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_208_args,
    2, Iclass_xt_iclass_rsr_208_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ps_args,
    7, Iclass_xt_iclass_rsr_ps_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ps_args,
    7, Iclass_xt_iclass_wsr_ps_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ps_args,
    7, Iclass_xt_iclass_xsr_ps_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_epc1_args,
    3, Iclass_xt_iclass_rsr_epc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_epc1_args,
    3, Iclass_xt_iclass_wsr_epc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_epc1_args,
    3, Iclass_xt_iclass_xsr_epc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_excsave1_args,
    3, Iclass_xt_iclass_rsr_excsave1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_excsave1_args,
    3, Iclass_xt_iclass_wsr_excsave1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_excsave1_args,
    3, Iclass_xt_iclass_xsr_excsave1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_epc2_args,
    3, Iclass_xt_iclass_rsr_epc2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_epc2_args,
    3, Iclass_xt_iclass_wsr_epc2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_epc2_args,
    3, Iclass_xt_iclass_xsr_epc2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_excsave2_args,
    3, Iclass_xt_iclass_rsr_excsave2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_excsave2_args,
    3, Iclass_xt_iclass_wsr_excsave2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_excsave2_args,
    3, Iclass_xt_iclass_xsr_excsave2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_epc3_args,
    3, Iclass_xt_iclass_rsr_epc3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_epc3_args,
    3, Iclass_xt_iclass_wsr_epc3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_epc3_args,
    3, Iclass_xt_iclass_xsr_epc3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_excsave3_args,
    3, Iclass_xt_iclass_rsr_excsave3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_excsave3_args,
    3, Iclass_xt_iclass_wsr_excsave3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_excsave3_args,
    3, Iclass_xt_iclass_xsr_excsave3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_epc4_args,
    3, Iclass_xt_iclass_rsr_epc4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_epc4_args,
    3, Iclass_xt_iclass_wsr_epc4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_epc4_args,
    3, Iclass_xt_iclass_xsr_epc4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_excsave4_args,
    3, Iclass_xt_iclass_rsr_excsave4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_excsave4_args,
    3, Iclass_xt_iclass_wsr_excsave4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_excsave4_args,
    3, Iclass_xt_iclass_xsr_excsave4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_epc5_args,
    3, Iclass_xt_iclass_rsr_epc5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_epc5_args,
    3, Iclass_xt_iclass_wsr_epc5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_epc5_args,
    3, Iclass_xt_iclass_xsr_epc5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_excsave5_args,
    3, Iclass_xt_iclass_rsr_excsave5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_excsave5_args,
    3, Iclass_xt_iclass_wsr_excsave5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_excsave5_args,
    3, Iclass_xt_iclass_xsr_excsave5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_epc6_args,
    3, Iclass_xt_iclass_rsr_epc6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_epc6_args,
    3, Iclass_xt_iclass_wsr_epc6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_epc6_args,
    3, Iclass_xt_iclass_xsr_epc6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_excsave6_args,
    3, Iclass_xt_iclass_rsr_excsave6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_excsave6_args,
    3, Iclass_xt_iclass_wsr_excsave6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_excsave6_args,
    3, Iclass_xt_iclass_xsr_excsave6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_epc7_args,
    3, Iclass_xt_iclass_rsr_epc7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_epc7_args,
    3, Iclass_xt_iclass_wsr_epc7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_epc7_args,
    3, Iclass_xt_iclass_xsr_epc7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_excsave7_args,
    3, Iclass_xt_iclass_rsr_excsave7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_excsave7_args,
    3, Iclass_xt_iclass_wsr_excsave7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_excsave7_args,
    3, Iclass_xt_iclass_xsr_excsave7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_eps2_args,
    3, Iclass_xt_iclass_rsr_eps2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_eps2_args,
    3, Iclass_xt_iclass_wsr_eps2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_eps2_args,
    3, Iclass_xt_iclass_xsr_eps2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_eps3_args,
    3, Iclass_xt_iclass_rsr_eps3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_eps3_args,
    3, Iclass_xt_iclass_wsr_eps3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_eps3_args,
    3, Iclass_xt_iclass_xsr_eps3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_eps4_args,
    3, Iclass_xt_iclass_rsr_eps4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_eps4_args,
    3, Iclass_xt_iclass_wsr_eps4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_eps4_args,
    3, Iclass_xt_iclass_xsr_eps4_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_eps5_args,
    3, Iclass_xt_iclass_rsr_eps5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_eps5_args,
    3, Iclass_xt_iclass_wsr_eps5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_eps5_args,
    3, Iclass_xt_iclass_xsr_eps5_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_eps6_args,
    3, Iclass_xt_iclass_rsr_eps6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_eps6_args,
    3, Iclass_xt_iclass_wsr_eps6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_eps6_args,
    3, Iclass_xt_iclass_xsr_eps6_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_eps7_args,
    3, Iclass_xt_iclass_rsr_eps7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_eps7_args,
    3, Iclass_xt_iclass_wsr_eps7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_eps7_args,
    3, Iclass_xt_iclass_xsr_eps7_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_excvaddr_args,
    3, Iclass_xt_iclass_rsr_excvaddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_excvaddr_args,
    3, Iclass_xt_iclass_wsr_excvaddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_excvaddr_args,
    3, Iclass_xt_iclass_xsr_excvaddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_depc_args,
    3, Iclass_xt_iclass_rsr_depc_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_depc_args,
    3, Iclass_xt_iclass_wsr_depc_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_depc_args,
    3, Iclass_xt_iclass_xsr_depc_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_exccause_args,
    4, Iclass_xt_iclass_rsr_exccause_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_exccause_args,
    3, Iclass_xt_iclass_wsr_exccause_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_exccause_args,
    3, Iclass_xt_iclass_xsr_exccause_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_misc0_args,
    3, Iclass_xt_iclass_rsr_misc0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_misc0_args,
    3, Iclass_xt_iclass_wsr_misc0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_misc0_args,
    3, Iclass_xt_iclass_xsr_misc0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_misc1_args,
    3, Iclass_xt_iclass_rsr_misc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_misc1_args,
    3, Iclass_xt_iclass_wsr_misc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_misc1_args,
    3, Iclass_xt_iclass_xsr_misc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_misc2_args,
    3, Iclass_xt_iclass_rsr_misc2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_misc2_args,
    3, Iclass_xt_iclass_wsr_misc2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_misc2_args,
    3, Iclass_xt_iclass_xsr_misc2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_misc3_args,
    3, Iclass_xt_iclass_rsr_misc3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_misc3_args,
    3, Iclass_xt_iclass_wsr_misc3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_misc3_args,
    3, Iclass_xt_iclass_xsr_misc3_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_prid_args,
    2, Iclass_xt_iclass_rsr_prid_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_vecbase_args,
    3, Iclass_xt_iclass_rsr_vecbase_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_vecbase_args,
    3, Iclass_xt_iclass_wsr_vecbase_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_vecbase_args,
    3, Iclass_xt_iclass_xsr_vecbase_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16_aa_args,
    1, Iclass_xt_iclass_mac16_aa_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16_ad_args,
    1, Iclass_xt_iclass_mac16_ad_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16_da_args,
    1, Iclass_xt_iclass_mac16_da_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16_dd_args,
    1, Iclass_xt_iclass_mac16_dd_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16a_aa_args,
    1, Iclass_xt_iclass_mac16a_aa_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16a_ad_args,
    1, Iclass_xt_iclass_mac16a_ad_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16a_da_args,
    1, Iclass_xt_iclass_mac16a_da_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16a_dd_args,
    1, Iclass_xt_iclass_mac16a_dd_stateArgs, 0, 0 },
  { 4, Iclass_xt_iclass_mac16al_da_args,
    1, Iclass_xt_iclass_mac16al_da_stateArgs, 0, 0 },
  { 4, Iclass_xt_iclass_mac16al_dd_args,
    1, Iclass_xt_iclass_mac16al_dd_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_mac16_l_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_mul16_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_rsr_m0_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_wsr_m0_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_xsr_m0_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_rsr_m1_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_wsr_m1_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_xsr_m1_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_rsr_m2_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_wsr_m2_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_xsr_m2_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_rsr_m3_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_wsr_m3_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_xsr_m3_args,
    0, 0, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_acclo_args,
    1, Iclass_xt_iclass_rsr_acclo_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_acclo_args,
    1, Iclass_xt_iclass_wsr_acclo_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_acclo_args,
    1, Iclass_xt_iclass_xsr_acclo_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_acchi_args,
    1, Iclass_xt_iclass_rsr_acchi_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_acchi_args,
    1, Iclass_xt_iclass_wsr_acchi_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_acchi_args,
    1, Iclass_xt_iclass_xsr_acchi_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rfi_args,
    21, Iclass_xt_iclass_rfi_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wait_args,
    3, Iclass_xt_iclass_wait_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_interrupt_args,
    3, Iclass_xt_iclass_rsr_interrupt_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_intset_args,
    4, Iclass_xt_iclass_wsr_intset_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_intclear_args,
    4, Iclass_xt_iclass_wsr_intclear_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_intenable_args,
    3, Iclass_xt_iclass_rsr_intenable_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_intenable_args,
    3, Iclass_xt_iclass_wsr_intenable_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_intenable_args,
    3, Iclass_xt_iclass_xsr_intenable_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_break_args,
    2, Iclass_xt_iclass_break_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_break_n_args,
    2, Iclass_xt_iclass_break_n_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_dbreaka0_args,
    3, Iclass_xt_iclass_rsr_dbreaka0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_dbreaka0_args,
    4, Iclass_xt_iclass_wsr_dbreaka0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_dbreaka0_args,
    4, Iclass_xt_iclass_xsr_dbreaka0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_dbreakc0_args,
    3, Iclass_xt_iclass_rsr_dbreakc0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_dbreakc0_args,
    4, Iclass_xt_iclass_wsr_dbreakc0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_dbreakc0_args,
    4, Iclass_xt_iclass_xsr_dbreakc0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_dbreaka1_args,
    3, Iclass_xt_iclass_rsr_dbreaka1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_dbreaka1_args,
    4, Iclass_xt_iclass_wsr_dbreaka1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_dbreaka1_args,
    4, Iclass_xt_iclass_xsr_dbreaka1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_dbreakc1_args,
    3, Iclass_xt_iclass_rsr_dbreakc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_dbreakc1_args,
    4, Iclass_xt_iclass_wsr_dbreakc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_dbreakc1_args,
    4, Iclass_xt_iclass_xsr_dbreakc1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ibreaka0_args,
    3, Iclass_xt_iclass_rsr_ibreaka0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ibreaka0_args,
    3, Iclass_xt_iclass_wsr_ibreaka0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ibreaka0_args,
    3, Iclass_xt_iclass_xsr_ibreaka0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ibreaka1_args,
    3, Iclass_xt_iclass_rsr_ibreaka1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ibreaka1_args,
    3, Iclass_xt_iclass_wsr_ibreaka1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ibreaka1_args,
    3, Iclass_xt_iclass_xsr_ibreaka1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ibreakenable_args,
    3, Iclass_xt_iclass_rsr_ibreakenable_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ibreakenable_args,
    3, Iclass_xt_iclass_wsr_ibreakenable_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ibreakenable_args,
    3, Iclass_xt_iclass_xsr_ibreakenable_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_debugcause_args,
    4, Iclass_xt_iclass_rsr_debugcause_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_debugcause_args,
    4, Iclass_xt_iclass_wsr_debugcause_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_debugcause_args,
    4, Iclass_xt_iclass_xsr_debugcause_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_icount_args,
    3, Iclass_xt_iclass_rsr_icount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_icount_args,
    4, Iclass_xt_iclass_wsr_icount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_icount_args,
    4, Iclass_xt_iclass_xsr_icount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_icountlevel_args,
    3, Iclass_xt_iclass_rsr_icountlevel_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_icountlevel_args,
    3, Iclass_xt_iclass_wsr_icountlevel_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_icountlevel_args,
    3, Iclass_xt_iclass_xsr_icountlevel_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ddr_args,
    3, Iclass_xt_iclass_rsr_ddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ddr_args,
    4, Iclass_xt_iclass_wsr_ddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ddr_args,
    4, Iclass_xt_iclass_xsr_ddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rfdo_args,
    10, Iclass_xt_iclass_rfdo_stateArgs, 0, 0 },
  { 0, 0 /* xt_iclass_rfdd */,
    1, Iclass_xt_iclass_rfdd_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_mmid_args,
    3, Iclass_xt_iclass_wsr_mmid_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_bbool1_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_bbool4_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_bbool8_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_bbranch_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_bmove_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_RSR_BR_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_WSR_BR_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_XSR_BR_args,
    0, 0, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ccount_args,
    3, Iclass_xt_iclass_rsr_ccount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ccount_args,
    4, Iclass_xt_iclass_wsr_ccount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ccount_args,
    4, Iclass_xt_iclass_xsr_ccount_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ccompare0_args,
    3, Iclass_xt_iclass_rsr_ccompare0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ccompare0_args,
    4, Iclass_xt_iclass_wsr_ccompare0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ccompare0_args,
    4, Iclass_xt_iclass_xsr_ccompare0_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ccompare1_args,
    3, Iclass_xt_iclass_rsr_ccompare1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ccompare1_args,
    4, Iclass_xt_iclass_wsr_ccompare1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ccompare1_args,
    4, Iclass_xt_iclass_xsr_ccompare1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ccompare2_args,
    3, Iclass_xt_iclass_rsr_ccompare2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ccompare2_args,
    4, Iclass_xt_iclass_wsr_ccompare2_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ccompare2_args,
    4, Iclass_xt_iclass_xsr_ccompare2_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_icache_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_icache_lock_args,
    2, Iclass_xt_iclass_icache_lock_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_icache_inv_args,
    2, Iclass_xt_iclass_icache_inv_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_licx_args,
    2, Iclass_xt_iclass_licx_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_sicx_args,
    2, Iclass_xt_iclass_sicx_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_dcache_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_dcache_ind_args,
    2, Iclass_xt_iclass_dcache_ind_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_dcache_inv_args,
    2, Iclass_xt_iclass_dcache_inv_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_dpf_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_dcache_lock_args,
    2, Iclass_xt_iclass_dcache_lock_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_sdct_args,
    2, Iclass_xt_iclass_sdct_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_ldct_args,
    2, Iclass_xt_iclass_ldct_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_ptevaddr_args,
    4, Iclass_xt_iclass_wsr_ptevaddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_ptevaddr_args,
    4, Iclass_xt_iclass_rsr_ptevaddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_ptevaddr_args,
    5, Iclass_xt_iclass_xsr_ptevaddr_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_rasid_args,
    5, Iclass_xt_iclass_rsr_rasid_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_rasid_args,
    6, Iclass_xt_iclass_wsr_rasid_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_rasid_args,
    6, Iclass_xt_iclass_xsr_rasid_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_itlbcfg_args,
    3, Iclass_xt_iclass_rsr_itlbcfg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_itlbcfg_args,
    4, Iclass_xt_iclass_wsr_itlbcfg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_itlbcfg_args,
    4, Iclass_xt_iclass_xsr_itlbcfg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_dtlbcfg_args,
    3, Iclass_xt_iclass_rsr_dtlbcfg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_dtlbcfg_args,
    4, Iclass_xt_iclass_wsr_dtlbcfg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_dtlbcfg_args,
    4, Iclass_xt_iclass_xsr_dtlbcfg_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_idtlb_args,
    3, Iclass_xt_iclass_idtlb_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_rdtlb_args,
    2, Iclass_xt_iclass_rdtlb_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_wdtlb_args,
    3, Iclass_xt_iclass_wdtlb_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_iitlb_args,
    2, Iclass_xt_iclass_iitlb_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_ritlb_args,
    2, Iclass_xt_iclass_ritlb_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_witlb_args,
    2, Iclass_xt_iclass_witlb_stateArgs, 0, 0 },
  { 0, 0 /* xt_iclass_ldpte */,
    2, Iclass_xt_iclass_ldpte_stateArgs, 0, 0 },
  { 0, 0 /* xt_iclass_hwwitlba */,
    1, Iclass_xt_iclass_hwwitlba_stateArgs, 0, 0 },
  { 0, 0 /* xt_iclass_hwwdtlba */,
    1, Iclass_xt_iclass_hwwdtlba_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_cpenable_args,
    3, Iclass_xt_iclass_rsr_cpenable_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_cpenable_args,
    3, Iclass_xt_iclass_wsr_cpenable_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_cpenable_args,
    3, Iclass_xt_iclass_xsr_cpenable_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_clamp_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_minmax_args,
    0, 0, 0, 0 },
  { 2, Iclass_xt_iclass_nsa_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_sx_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_l32ai_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_s32ri_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_s32c1i_args,
    2, Iclass_xt_iclass_s32c1i_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_rsr_scompare1_args,
    1, Iclass_xt_iclass_rsr_scompare1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_wsr_scompare1_args,
    1, Iclass_xt_iclass_wsr_scompare1_stateArgs, 0, 0 },
  { 1, Iclass_xt_iclass_xsr_scompare1_args,
    1, Iclass_xt_iclass_xsr_scompare1_stateArgs, 0, 0 },
  { 3, Iclass_xt_iclass_div_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_mul32_args,
    0, 0, 0, 0 },
  { 1, Iclass_rur_fcr_args,
    9, Iclass_rur_fcr_stateArgs, 0, 0 },
  { 1, Iclass_wur_fcr_args,
    9, Iclass_wur_fcr_stateArgs, 0, 0 },
  { 1, Iclass_rur_fsr_args,
    8, Iclass_rur_fsr_stateArgs, 0, 0 },
  { 1, Iclass_wur_fsr_args,
    8, Iclass_wur_fsr_stateArgs, 0, 0 },
  { 3, Iclass_fp_args,
    2, Iclass_fp_stateArgs, 0, 0 },
  { 3, Iclass_fp_mac_args,
    2, Iclass_fp_mac_stateArgs, 0, 0 },
  { 3, Iclass_fp_cmov_args,
    1, Iclass_fp_cmov_stateArgs, 0, 0 },
  { 3, Iclass_fp_mov_args,
    1, Iclass_fp_mov_stateArgs, 0, 0 },
  { 2, Iclass_fp_mov2_args,
    1, Iclass_fp_mov2_stateArgs, 0, 0 },
  { 3, Iclass_fp_cmp_args,
    1, Iclass_fp_cmp_stateArgs, 0, 0 },
  { 3, Iclass_fp_float_args,
    2, Iclass_fp_float_stateArgs, 0, 0 },
  { 3, Iclass_fp_int_args,
    1, Iclass_fp_int_stateArgs, 0, 0 },
  { 2, Iclass_fp_rfr_args,
    1, Iclass_fp_rfr_stateArgs, 0, 0 },
  { 2, Iclass_fp_wfr_args,
    1, Iclass_fp_wfr_stateArgs, 0, 0 },
  { 3, Iclass_fp_lsi_args,
    1, Iclass_fp_lsi_stateArgs, 0, 0 },
  { 3, Iclass_fp_lsiu_args,
    1, Iclass_fp_lsiu_stateArgs, 0, 0 },
  { 3, Iclass_fp_lsx_args,
    1, Iclass_fp_lsx_stateArgs, 0, 0 },
  { 3, Iclass_fp_lsxu_args,
    1, Iclass_fp_lsxu_stateArgs, 0, 0 },
  { 3, Iclass_fp_ssi_args,
    1, Iclass_fp_ssi_stateArgs, 0, 0 },
  { 3, Iclass_fp_ssiu_args,
    1, Iclass_fp_ssiu_stateArgs, 0, 0 },
  { 3, Iclass_fp_ssx_args,
    1, Iclass_fp_ssx_stateArgs, 0, 0 },
  { 3, Iclass_fp_ssxu_args,
    1, Iclass_fp_ssxu_stateArgs, 0, 0 },
  { 2, Iclass_xt_iclass_wb18_0_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_wb18_1_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_wb18_2_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_wb18_3_args,
    0, 0, 0, 0 },
  { 3, Iclass_xt_iclass_wb18_4_args,
    0, 0, 0, 0 }
};


/*  Opcode encodings.  */

static void
Opcode_excw_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2080;
}

static void
Opcode_rfe_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3000;
}

static void
Opcode_rfde_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3200;
}

static void
Opcode_syscall_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5000;
}

static void
Opcode_simcall_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5100;
}

static void
Opcode_call12_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x35;
}

static void
Opcode_call8_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x25;
}

static void
Opcode_call4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x15;
}

static void
Opcode_callx12_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf0;
}

static void
Opcode_callx8_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe0;
}

static void
Opcode_callx4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd0;
}

static void
Opcode_entry_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x36;
}

static void
Opcode_movsp_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1000;
}

static void
Opcode_rotw_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x408000;
}

static void
Opcode_retw_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x90;
}

static void
Opcode_retw_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf01d;
}

static void
Opcode_rfwo_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3400;
}

static void
Opcode_rfwu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3500;
}

static void
Opcode_l32e_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x90000;
}

static void
Opcode_s32e_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x490000;
}

static void
Opcode_rsr_windowbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x34800;
}

static void
Opcode_wsr_windowbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x134800;
}

static void
Opcode_xsr_windowbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x614800;
}

static void
Opcode_rsr_windowstart_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x34900;
}

static void
Opcode_wsr_windowstart_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x134900;
}

static void
Opcode_xsr_windowstart_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x614900;
}

static void
Opcode_add_n_Slot_inst16a_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa;
}

static void
Opcode_addi_n_Slot_inst16a_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb;
}

static void
Opcode_addi_n_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3000;
}

static void
Opcode_beqz_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8c;
}

static void
Opcode_bnez_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xcc;
}

static void
Opcode_ill_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf06d;
}

static void
Opcode_l32i_n_Slot_inst16a_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8;
}

static void
Opcode_mov_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd;
}

static void
Opcode_mov_n_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6000;
}

static void
Opcode_mov_n_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa3000;
}

static void
Opcode_mov_n_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc080;
}

static void
Opcode_movi_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc;
}

static void
Opcode_movi_n_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc000;
}

static void
Opcode_nop_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf03d;
}

static void
Opcode_ret_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf00d;
}

static void
Opcode_s32i_n_Slot_inst16a_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9;
}

static void
Opcode_rur_threadptr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe30e70;
}

static void
Opcode_wur_threadptr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf3e700;
}

static void
Opcode_addi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc002;
}

static void
Opcode_addi_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x60000;
}

static void
Opcode_addi_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200c00;
}

static void
Opcode_addmi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd002;
}

static void
Opcode_addmi_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x70000;
}

static void
Opcode_addmi_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200d00;
}

static void
Opcode_add_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x800000;
}

static void
Opcode_add_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x92000;
}

static void
Opcode_add_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2000;
}

static void
Opcode_add_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x80000;
}

static void
Opcode_sub_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc00000;
}

static void
Opcode_sub_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa8000;
}

static void
Opcode_sub_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa000;
}

static void
Opcode_sub_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc0000;
}

static void
Opcode_addx2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x900000;
}

static void
Opcode_addx2_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x94000;
}

static void
Opcode_addx2_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4000;
}

static void
Opcode_addx2_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x90000;
}

static void
Opcode_addx4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa00000;
}

static void
Opcode_addx4_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x98000;
}

static void
Opcode_addx4_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5000;
}

static void
Opcode_addx4_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa0000;
}

static void
Opcode_addx8_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb00000;
}

static void
Opcode_addx8_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x93000;
}

static void
Opcode_addx8_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb0000;
}

static void
Opcode_subx2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd00000;
}

static void
Opcode_subx2_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd0000;
}

static void
Opcode_subx4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe00000;
}

static void
Opcode_subx4_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe0000;
}

static void
Opcode_subx8_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf00000;
}

static void
Opcode_subx8_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf0000;
}

static void
Opcode_and_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x100000;
}

static void
Opcode_and_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x95000;
}

static void
Opcode_and_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6000;
}

static void
Opcode_and_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x10000;
}

static void
Opcode_or_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200000;
}

static void
Opcode_or_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9e000;
}

static void
Opcode_or_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7000;
}

static void
Opcode_or_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x20000;
}

static void
Opcode_xor_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x300000;
}

static void
Opcode_xor_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb0000;
}

static void
Opcode_xor_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb000;
}

static void
Opcode_xor_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30000;
}

static void
Opcode_beqi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x26;
}

static void
Opcode_bnei_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x66;
}

static void
Opcode_bgei_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe6;
}

static void
Opcode_blti_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa6;
}

static void
Opcode_bbci_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6007;
}

static void
Opcode_bbsi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe007;
}

static void
Opcode_bgeui_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf6;
}

static void
Opcode_bltui_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb6;
}

static void
Opcode_beq_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1007;
}

static void
Opcode_bne_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9007;
}

static void
Opcode_bge_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa007;
}

static void
Opcode_blt_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2007;
}

static void
Opcode_bgeu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb007;
}

static void
Opcode_bltu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3007;
}

static void
Opcode_bany_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8007;
}

static void
Opcode_bnone_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7;
}

static void
Opcode_ball_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4007;
}

static void
Opcode_bnall_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc007;
}

static void
Opcode_bbc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5007;
}

static void
Opcode_bbs_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd007;
}

static void
Opcode_beqz_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x16;
}

static void
Opcode_bnez_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x56;
}

static void
Opcode_bgez_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd6;
}

static void
Opcode_bltz_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x96;
}

static void
Opcode_call0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5;
}

static void
Opcode_callx0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc0;
}

static void
Opcode_extui_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40000;
}

static void
Opcode_extui_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40000;
}

static void
Opcode_extui_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4000;
}

static void
Opcode_ill_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0;
}

static void
Opcode_j_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6;
}

static void
Opcode_j_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc0000;
}

static void
Opcode_jx_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa0;
}

static void
Opcode_jx_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa3010;
}

static void
Opcode_l16ui_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1002;
}

static void
Opcode_l16ui_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200100;
}

static void
Opcode_l16si_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9002;
}

static void
Opcode_l16si_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200900;
}

static void
Opcode_l32i_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2002;
}

static void
Opcode_l32i_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200200;
}

static void
Opcode_l32r_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1;
}

static void
Opcode_l32r_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x100000;
}

static void
Opcode_l8ui_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2;
}

static void
Opcode_l8ui_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200000;
}

static void
Opcode_loop_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8076;
}

static void
Opcode_loopnez_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9076;
}

static void
Opcode_loopgtz_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa076;
}

static void
Opcode_movi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa002;
}

static void
Opcode_movi_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x80000;
}

static void
Opcode_movi_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200a00;
}

static void
Opcode_moveqz_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x830000;
}

static void
Opcode_moveqz_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x96000;
}

static void
Opcode_moveqz_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x83000;
}

static void
Opcode_movnez_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x930000;
}

static void
Opcode_movnez_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9a000;
}

static void
Opcode_movnez_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x93000;
}

static void
Opcode_movltz_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa30000;
}

static void
Opcode_movltz_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x99000;
}

static void
Opcode_movltz_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa3000;
}

static void
Opcode_movgez_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb30000;
}

static void
Opcode_movgez_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x97000;
}

static void
Opcode_movgez_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb3000;
}

static void
Opcode_neg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x600000;
}

static void
Opcode_neg_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa5000;
}

static void
Opcode_neg_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd100;
}

static void
Opcode_neg_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x60000;
}

static void
Opcode_abs_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x600100;
}

static void
Opcode_abs_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd000;
}

static void
Opcode_abs_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x60010;
}

static void
Opcode_nop_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x20f0;
}

static void
Opcode_nop_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa3040;
}

static void
Opcode_nop_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc090;
}

static void
Opcode_nop_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc8000000;
  slotbuf[1] = 0;
}

static void
Opcode_nop_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x20f;
}

static void
Opcode_ret_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x80;
}

static void
Opcode_s16i_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5002;
}

static void
Opcode_s16i_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200500;
}

static void
Opcode_s32i_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6002;
}

static void
Opcode_s32i_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200600;
}

static void
Opcode_s8i_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4002;
}

static void
Opcode_s8i_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x200400;
}

static void
Opcode_ssr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x400000;
}

static void
Opcode_ssr_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40000;
}

static void
Opcode_ssl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x401000;
}

static void
Opcode_ssl_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa3020;
}

static void
Opcode_ssl_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40100;
}

static void
Opcode_ssa8l_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x402000;
}

static void
Opcode_ssa8l_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40200;
}

static void
Opcode_ssa8b_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x403000;
}

static void
Opcode_ssa8b_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40300;
}

static void
Opcode_ssai_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x404000;
}

static void
Opcode_ssai_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40400;
}

static void
Opcode_sll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa10000;
}

static void
Opcode_sll_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa6000;
}

static void
Opcode_sll_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa1000;
}

static void
Opcode_src_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x810000;
}

static void
Opcode_src_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa2000;
}

static void
Opcode_src_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x81000;
}

static void
Opcode_srl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x910000;
}

static void
Opcode_srl_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa5200;
}

static void
Opcode_srl_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd400;
}

static void
Opcode_srl_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x91000;
}

static void
Opcode_sra_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb10000;
}

static void
Opcode_sra_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa5100;
}

static void
Opcode_sra_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd200;
}

static void
Opcode_sra_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb1000;
}

static void
Opcode_slli_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x10000;
}

static void
Opcode_slli_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x90000;
}

static void
Opcode_slli_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1000;
}

static void
Opcode_srai_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x210000;
}

static void
Opcode_srai_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa0000;
}

static void
Opcode_srai_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe000;
}

static void
Opcode_srai_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x21000;
}

static void
Opcode_srli_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x410000;
}

static void
Opcode_srli_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa4000;
}

static void
Opcode_srli_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9000;
}

static void
Opcode_srli_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x41000;
}

static void
Opcode_memw_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x20c0;
}

static void
Opcode_extw_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x20d0;
}

static void
Opcode_isync_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2000;
}

static void
Opcode_rsync_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2010;
}

static void
Opcode_esync_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2020;
}

static void
Opcode_dsync_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2030;
}

static void
Opcode_rsil_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6000;
}

static void
Opcode_rsr_lend_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30100;
}

static void
Opcode_wsr_lend_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x130100;
}

static void
Opcode_xsr_lend_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x610100;
}

static void
Opcode_rsr_lcount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30200;
}

static void
Opcode_wsr_lcount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x130200;
}

static void
Opcode_xsr_lcount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x610200;
}

static void
Opcode_rsr_lbeg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30000;
}

static void
Opcode_wsr_lbeg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x130000;
}

static void
Opcode_xsr_lbeg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x610000;
}

static void
Opcode_rsr_sar_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30300;
}

static void
Opcode_wsr_sar_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x130300;
}

static void
Opcode_xsr_sar_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x610300;
}

static void
Opcode_rsr_litbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30500;
}

static void
Opcode_wsr_litbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x130500;
}

static void
Opcode_xsr_litbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x610500;
}

static void
Opcode_rsr_176_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b000;
}

static void
Opcode_rsr_208_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d000;
}

static void
Opcode_rsr_ps_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3e600;
}

static void
Opcode_wsr_ps_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13e600;
}

static void
Opcode_xsr_ps_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61e600;
}

static void
Opcode_rsr_epc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b100;
}

static void
Opcode_wsr_epc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13b100;
}

static void
Opcode_xsr_epc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61b100;
}

static void
Opcode_rsr_excsave1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d100;
}

static void
Opcode_wsr_excsave1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13d100;
}

static void
Opcode_xsr_excsave1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61d100;
}

static void
Opcode_rsr_epc2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b200;
}

static void
Opcode_wsr_epc2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13b200;
}

static void
Opcode_xsr_epc2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61b200;
}

static void
Opcode_rsr_excsave2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d200;
}

static void
Opcode_wsr_excsave2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13d200;
}

static void
Opcode_xsr_excsave2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61d200;
}

static void
Opcode_rsr_epc3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b300;
}

static void
Opcode_wsr_epc3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13b300;
}

static void
Opcode_xsr_epc3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61b300;
}

static void
Opcode_rsr_excsave3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d300;
}

static void
Opcode_wsr_excsave3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13d300;
}

static void
Opcode_xsr_excsave3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61d300;
}

static void
Opcode_rsr_epc4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b400;
}

static void
Opcode_wsr_epc4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13b400;
}

static void
Opcode_xsr_epc4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61b400;
}

static void
Opcode_rsr_excsave4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d400;
}

static void
Opcode_wsr_excsave4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13d400;
}

static void
Opcode_xsr_excsave4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61d400;
}

static void
Opcode_rsr_epc5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b500;
}

static void
Opcode_wsr_epc5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13b500;
}

static void
Opcode_xsr_epc5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61b500;
}

static void
Opcode_rsr_excsave5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d500;
}

static void
Opcode_wsr_excsave5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13d500;
}

static void
Opcode_xsr_excsave5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61d500;
}

static void
Opcode_rsr_epc6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b600;
}

static void
Opcode_wsr_epc6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13b600;
}

static void
Opcode_xsr_epc6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61b600;
}

static void
Opcode_rsr_excsave6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d600;
}

static void
Opcode_wsr_excsave6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13d600;
}

static void
Opcode_xsr_excsave6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61d600;
}

static void
Opcode_rsr_epc7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b700;
}

static void
Opcode_wsr_epc7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13b700;
}

static void
Opcode_xsr_epc7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61b700;
}

static void
Opcode_rsr_excsave7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d700;
}

static void
Opcode_wsr_excsave7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13d700;
}

static void
Opcode_xsr_excsave7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61d700;
}

static void
Opcode_rsr_eps2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3c200;
}

static void
Opcode_wsr_eps2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13c200;
}

static void
Opcode_xsr_eps2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61c200;
}

static void
Opcode_rsr_eps3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3c300;
}

static void
Opcode_wsr_eps3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13c300;
}

static void
Opcode_xsr_eps3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61c300;
}

static void
Opcode_rsr_eps4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3c400;
}

static void
Opcode_wsr_eps4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13c400;
}

static void
Opcode_xsr_eps4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61c400;
}

static void
Opcode_rsr_eps5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3c500;
}

static void
Opcode_wsr_eps5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13c500;
}

static void
Opcode_xsr_eps5_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61c500;
}

static void
Opcode_rsr_eps6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3c600;
}

static void
Opcode_wsr_eps6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13c600;
}

static void
Opcode_xsr_eps6_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61c600;
}

static void
Opcode_rsr_eps7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3c700;
}

static void
Opcode_wsr_eps7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13c700;
}

static void
Opcode_xsr_eps7_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61c700;
}

static void
Opcode_rsr_excvaddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3ee00;
}

static void
Opcode_wsr_excvaddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13ee00;
}

static void
Opcode_xsr_excvaddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61ee00;
}

static void
Opcode_rsr_depc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3c000;
}

static void
Opcode_wsr_depc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13c000;
}

static void
Opcode_xsr_depc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61c000;
}

static void
Opcode_rsr_exccause_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3e800;
}

static void
Opcode_wsr_exccause_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13e800;
}

static void
Opcode_xsr_exccause_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61e800;
}

static void
Opcode_rsr_misc0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3f400;
}

static void
Opcode_wsr_misc0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13f400;
}

static void
Opcode_xsr_misc0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61f400;
}

static void
Opcode_rsr_misc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3f500;
}

static void
Opcode_wsr_misc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13f500;
}

static void
Opcode_xsr_misc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61f500;
}

static void
Opcode_rsr_misc2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3f600;
}

static void
Opcode_wsr_misc2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13f600;
}

static void
Opcode_xsr_misc2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61f600;
}

static void
Opcode_rsr_misc3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3f700;
}

static void
Opcode_wsr_misc3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13f700;
}

static void
Opcode_xsr_misc3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61f700;
}

static void
Opcode_rsr_prid_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3eb00;
}

static void
Opcode_rsr_vecbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3e700;
}

static void
Opcode_wsr_vecbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13e700;
}

static void
Opcode_xsr_vecbase_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61e700;
}

static void
Opcode_mul_aa_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x740004;
}

static void
Opcode_mul_aa_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x750004;
}

static void
Opcode_mul_aa_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x760004;
}

static void
Opcode_mul_aa_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x770004;
}

static void
Opcode_umul_aa_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x700004;
}

static void
Opcode_umul_aa_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x710004;
}

static void
Opcode_umul_aa_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x720004;
}

static void
Opcode_umul_aa_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x730004;
}

static void
Opcode_mul_ad_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x340004;
}

static void
Opcode_mul_ad_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x350004;
}

static void
Opcode_mul_ad_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x360004;
}

static void
Opcode_mul_ad_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x370004;
}

static void
Opcode_mul_da_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x640004;
}

static void
Opcode_mul_da_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x650004;
}

static void
Opcode_mul_da_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x660004;
}

static void
Opcode_mul_da_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x670004;
}

static void
Opcode_mul_dd_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x240004;
}

static void
Opcode_mul_dd_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x250004;
}

static void
Opcode_mul_dd_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x260004;
}

static void
Opcode_mul_dd_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x270004;
}

static void
Opcode_mula_aa_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x780004;
}

static void
Opcode_mula_aa_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x790004;
}

static void
Opcode_mula_aa_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7a0004;
}

static void
Opcode_mula_aa_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7b0004;
}

static void
Opcode_muls_aa_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7c0004;
}

static void
Opcode_muls_aa_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7d0004;
}

static void
Opcode_muls_aa_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7e0004;
}

static void
Opcode_muls_aa_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7f0004;
}

static void
Opcode_mula_ad_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x380004;
}

static void
Opcode_mula_ad_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x390004;
}

static void
Opcode_mula_ad_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3a0004;
}

static void
Opcode_mula_ad_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b0004;
}

static void
Opcode_muls_ad_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3c0004;
}

static void
Opcode_muls_ad_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3d0004;
}

static void
Opcode_muls_ad_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3e0004;
}

static void
Opcode_muls_ad_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3f0004;
}

static void
Opcode_mula_da_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x680004;
}

static void
Opcode_mula_da_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x690004;
}

static void
Opcode_mula_da_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6a0004;
}

static void
Opcode_mula_da_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6b0004;
}

static void
Opcode_muls_da_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6c0004;
}

static void
Opcode_muls_da_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6d0004;
}

static void
Opcode_muls_da_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6e0004;
}

static void
Opcode_muls_da_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6f0004;
}

static void
Opcode_mula_dd_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x280004;
}

static void
Opcode_mula_dd_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x290004;
}

static void
Opcode_mula_dd_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2a0004;
}

static void
Opcode_mula_dd_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2b0004;
}

static void
Opcode_muls_dd_ll_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2c0004;
}

static void
Opcode_muls_dd_hl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2d0004;
}

static void
Opcode_muls_dd_lh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2e0004;
}

static void
Opcode_muls_dd_hh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2f0004;
}

static void
Opcode_mula_da_ll_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x580004;
}

static void
Opcode_mula_da_ll_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x480004;
}

static void
Opcode_mula_da_hl_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x590004;
}

static void
Opcode_mula_da_hl_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x490004;
}

static void
Opcode_mula_da_lh_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5a0004;
}

static void
Opcode_mula_da_lh_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4a0004;
}

static void
Opcode_mula_da_hh_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5b0004;
}

static void
Opcode_mula_da_hh_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4b0004;
}

static void
Opcode_mula_dd_ll_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x180004;
}

static void
Opcode_mula_dd_ll_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x80004;
}

static void
Opcode_mula_dd_hl_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x190004;
}

static void
Opcode_mula_dd_hl_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x90004;
}

static void
Opcode_mula_dd_lh_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1a0004;
}

static void
Opcode_mula_dd_lh_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa0004;
}

static void
Opcode_mula_dd_hh_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1b0004;
}

static void
Opcode_mula_dd_hh_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb0004;
}

static void
Opcode_lddec_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x900004;
}

static void
Opcode_ldinc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x800004;
}

static void
Opcode_mul16u_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc10000;
}

static void
Opcode_mul16u_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9b000;
}

static void
Opcode_mul16u_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc1000;
}

static void
Opcode_mul16s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd10000;
}

static void
Opcode_mul16s_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9c000;
}

static void
Opcode_mul16s_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd1000;
}

static void
Opcode_rsr_m0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x32000;
}

static void
Opcode_wsr_m0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x132000;
}

static void
Opcode_xsr_m0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x612000;
}

static void
Opcode_rsr_m1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x32100;
}

static void
Opcode_wsr_m1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x132100;
}

static void
Opcode_xsr_m1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x612100;
}

static void
Opcode_rsr_m2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x32200;
}

static void
Opcode_wsr_m2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x132200;
}

static void
Opcode_xsr_m2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x612200;
}

static void
Opcode_rsr_m3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x32300;
}

static void
Opcode_wsr_m3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x132300;
}

static void
Opcode_xsr_m3_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x612300;
}

static void
Opcode_rsr_acclo_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x31000;
}

static void
Opcode_wsr_acclo_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x131000;
}

static void
Opcode_xsr_acclo_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x611000;
}

static void
Opcode_rsr_acchi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x31100;
}

static void
Opcode_wsr_acchi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x131100;
}

static void
Opcode_xsr_acchi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x611100;
}

static void
Opcode_rfi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3010;
}

static void
Opcode_waiti_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7000;
}

static void
Opcode_rsr_interrupt_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3e200;
}

static void
Opcode_wsr_intset_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13e200;
}

static void
Opcode_wsr_intclear_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13e300;
}

static void
Opcode_rsr_intenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3e400;
}

static void
Opcode_wsr_intenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13e400;
}

static void
Opcode_xsr_intenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61e400;
}

static void
Opcode_break_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4000;
}

static void
Opcode_break_n_Slot_inst16b_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf02d;
}

static void
Opcode_rsr_dbreaka0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x39000;
}

static void
Opcode_wsr_dbreaka0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x139000;
}

static void
Opcode_xsr_dbreaka0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x619000;
}

static void
Opcode_rsr_dbreakc0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3a000;
}

static void
Opcode_wsr_dbreakc0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13a000;
}

static void
Opcode_xsr_dbreakc0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61a000;
}

static void
Opcode_rsr_dbreaka1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x39100;
}

static void
Opcode_wsr_dbreaka1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x139100;
}

static void
Opcode_xsr_dbreaka1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x619100;
}

static void
Opcode_rsr_dbreakc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3a100;
}

static void
Opcode_wsr_dbreakc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13a100;
}

static void
Opcode_xsr_dbreakc1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61a100;
}

static void
Opcode_rsr_ibreaka0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x38000;
}

static void
Opcode_wsr_ibreaka0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x138000;
}

static void
Opcode_xsr_ibreaka0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x618000;
}

static void
Opcode_rsr_ibreaka1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x38100;
}

static void
Opcode_wsr_ibreaka1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x138100;
}

static void
Opcode_xsr_ibreaka1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x618100;
}

static void
Opcode_rsr_ibreakenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x36000;
}

static void
Opcode_wsr_ibreakenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x136000;
}

static void
Opcode_xsr_ibreakenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x616000;
}

static void
Opcode_rsr_debugcause_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3e900;
}

static void
Opcode_wsr_debugcause_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13e900;
}

static void
Opcode_xsr_debugcause_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61e900;
}

static void
Opcode_rsr_icount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3ec00;
}

static void
Opcode_wsr_icount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13ec00;
}

static void
Opcode_xsr_icount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61ec00;
}

static void
Opcode_rsr_icountlevel_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3ed00;
}

static void
Opcode_wsr_icountlevel_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13ed00;
}

static void
Opcode_xsr_icountlevel_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61ed00;
}

static void
Opcode_rsr_ddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x36800;
}

static void
Opcode_wsr_ddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x136800;
}

static void
Opcode_xsr_ddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x616800;
}

static void
Opcode_rfdo_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf1e000;
}

static void
Opcode_rfdd_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf1e010;
}

static void
Opcode_wsr_mmid_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x135900;
}

static void
Opcode_andb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x20000;
}

static void
Opcode_andbc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x120000;
}

static void
Opcode_orb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x220000;
}

static void
Opcode_orbc_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x320000;
}

static void
Opcode_xorb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x420000;
}

static void
Opcode_any4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8000;
}

static void
Opcode_all4_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9000;
}

static void
Opcode_any8_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa000;
}

static void
Opcode_all8_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb000;
}

static void
Opcode_bf_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x76;
}

static void
Opcode_bt_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1076;
}

static void
Opcode_movf_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc30000;
}

static void
Opcode_movt_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd30000;
}

static void
Opcode_rsr_br_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30400;
}

static void
Opcode_wsr_br_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x130400;
}

static void
Opcode_xsr_br_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x610400;
}

static void
Opcode_rsr_ccount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3ea00;
}

static void
Opcode_wsr_ccount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13ea00;
}

static void
Opcode_xsr_ccount_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61ea00;
}

static void
Opcode_rsr_ccompare0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3f000;
}

static void
Opcode_wsr_ccompare0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13f000;
}

static void
Opcode_xsr_ccompare0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61f000;
}

static void
Opcode_rsr_ccompare1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3f100;
}

static void
Opcode_wsr_ccompare1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13f100;
}

static void
Opcode_xsr_ccompare1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61f100;
}

static void
Opcode_rsr_ccompare2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3f200;
}

static void
Opcode_wsr_ccompare2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13f200;
}

static void
Opcode_xsr_ccompare2_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61f200;
}

static void
Opcode_ipf_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x70c2;
}

static void
Opcode_ihi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x70e2;
}

static void
Opcode_ipfl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x70d2;
}

static void
Opcode_ihu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x270d2;
}

static void
Opcode_iiu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x370d2;
}

static void
Opcode_iii_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x70f2;
}

static void
Opcode_lict_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf10000;
}

static void
Opcode_licw_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf12000;
}

static void
Opcode_sict_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf11000;
}

static void
Opcode_sicw_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf13000;
}

static void
Opcode_dhwb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7042;
}

static void
Opcode_dhwbi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7052;
}

static void
Opcode_diwb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x47082;
}

static void
Opcode_diwbi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x57082;
}

static void
Opcode_dhi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7062;
}

static void
Opcode_dii_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7072;
}

static void
Opcode_dpfr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7002;
}

static void
Opcode_dpfw_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7012;
}

static void
Opcode_dpfro_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7022;
}

static void
Opcode_dpfwo_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7032;
}

static void
Opcode_dpfl_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7082;
}

static void
Opcode_dhu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x27082;
}

static void
Opcode_diu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x37082;
}

static void
Opcode_sdct_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf19000;
}

static void
Opcode_ldct_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf18000;
}

static void
Opcode_wsr_ptevaddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x135300;
}

static void
Opcode_rsr_ptevaddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x35300;
}

static void
Opcode_xsr_ptevaddr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x615300;
}

static void
Opcode_rsr_rasid_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x35a00;
}

static void
Opcode_wsr_rasid_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x135a00;
}

static void
Opcode_xsr_rasid_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x615a00;
}

static void
Opcode_rsr_itlbcfg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x35b00;
}

static void
Opcode_wsr_itlbcfg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x135b00;
}

static void
Opcode_xsr_itlbcfg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x615b00;
}

static void
Opcode_rsr_dtlbcfg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x35c00;
}

static void
Opcode_wsr_dtlbcfg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x135c00;
}

static void
Opcode_xsr_dtlbcfg_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x615c00;
}

static void
Opcode_idtlb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x50c000;
}

static void
Opcode_pdtlb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x50d000;
}

static void
Opcode_rdtlb0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x50b000;
}

static void
Opcode_rdtlb1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x50f000;
}

static void
Opcode_wdtlb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x50e000;
}

static void
Opcode_iitlb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x504000;
}

static void
Opcode_pitlb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x505000;
}

static void
Opcode_ritlb0_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x503000;
}

static void
Opcode_ritlb1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x507000;
}

static void
Opcode_witlb_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x506000;
}

static void
Opcode_ldpte_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf1f000;
}

static void
Opcode_hwwitlba_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x501000;
}

static void
Opcode_hwwdtlba_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x509000;
}

static void
Opcode_rsr_cpenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3e000;
}

static void
Opcode_wsr_cpenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x13e000;
}

static void
Opcode_xsr_cpenable_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x61e000;
}

static void
Opcode_clamps_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x330000;
}

static void
Opcode_clamps_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x33000;
}

static void
Opcode_min_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x430000;
}

static void
Opcode_min_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x43000;
}

static void
Opcode_max_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x530000;
}

static void
Opcode_max_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x53000;
}

static void
Opcode_minu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x630000;
}

static void
Opcode_minu_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x63000;
}

static void
Opcode_maxu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x730000;
}

static void
Opcode_maxu_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x73000;
}

static void
Opcode_nsa_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40e000;
}

static void
Opcode_nsa_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40e00;
}

static void
Opcode_nsau_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40f000;
}

static void
Opcode_nsau_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40f00;
}

static void
Opcode_sext_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x230000;
}

static void
Opcode_sext_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9f000;
}

static void
Opcode_sext_Slot_xt_flix64_slot2_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8000;
}

static void
Opcode_sext_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x23000;
}

static void
Opcode_l32ai_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb002;
}

static void
Opcode_s32ri_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf002;
}

static void
Opcode_s32c1i_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe002;
}

static void
Opcode_rsr_scompare1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30c00;
}

static void
Opcode_wsr_scompare1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x130c00;
}

static void
Opcode_xsr_scompare1_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x610c00;
}

static void
Opcode_quou_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc20000;
}

static void
Opcode_quos_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xd20000;
}

static void
Opcode_remu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe20000;
}

static void
Opcode_rems_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf20000;
}

static void
Opcode_mull_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x820000;
}

static void
Opcode_mull_Slot_xt_flix64_slot1_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9d000;
}

static void
Opcode_mull_Slot_xt_flix64_slot0_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x82000;
}

static void
Opcode_muluh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa20000;
}

static void
Opcode_mulsh_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb20000;
}

static void
Opcode_rur_fcr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe30e80;
}

static void
Opcode_wur_fcr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf3e800;
}

static void
Opcode_rur_fsr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xe30e90;
}

static void
Opcode_wur_fsr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xf3e900;
}

static void
Opcode_add_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa0000;
}

static void
Opcode_sub_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1a0000;
}

static void
Opcode_mul_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2a0000;
}

static void
Opcode_madd_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4a0000;
}

static void
Opcode_msub_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5a0000;
}

static void
Opcode_movf_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xcb0000;
}

static void
Opcode_movt_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xdb0000;
}

static void
Opcode_moveqz_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8b0000;
}

static void
Opcode_movnez_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9b0000;
}

static void
Opcode_movltz_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xab0000;
}

static void
Opcode_movgez_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xbb0000;
}

static void
Opcode_abs_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xfa0010;
}

static void
Opcode_mov_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xfa0000;
}

static void
Opcode_neg_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xfa0060;
}

static void
Opcode_un_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x1b0000;
}

static void
Opcode_oeq_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x2b0000;
}

static void
Opcode_ueq_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3b0000;
}

static void
Opcode_olt_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4b0000;
}

static void
Opcode_ult_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x5b0000;
}

static void
Opcode_ole_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x6b0000;
}

static void
Opcode_ule_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x7b0000;
}

static void
Opcode_float_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xca0000;
}

static void
Opcode_ufloat_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xda0000;
}

static void
Opcode_round_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8a0000;
}

static void
Opcode_ceil_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xba0000;
}

static void
Opcode_floor_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xaa0000;
}

static void
Opcode_trunc_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x9a0000;
}

static void
Opcode_utrunc_s_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xea0000;
}

static void
Opcode_rfr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xfa0040;
}

static void
Opcode_wfr_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xfa0050;
}

static void
Opcode_lsi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x3;
}

static void
Opcode_lsiu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8003;
}

static void
Opcode_lsx_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x80000;
}

static void
Opcode_lsxu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x180000;
}

static void
Opcode_ssi_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x4003;
}

static void
Opcode_ssiu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc003;
}

static void
Opcode_ssx_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x480000;
}

static void
Opcode_ssxu_Slot_inst_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x580000;
}

static void
Opcode_beqz_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa8000000;
  slotbuf[1] = 0;
}

static void
Opcode_bnez_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xc0000000;
  slotbuf[1] = 0;
}

static void
Opcode_bgez_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb0000000;
  slotbuf[1] = 0;
}

static void
Opcode_bltz_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xb8000000;
  slotbuf[1] = 0;
}

static void
Opcode_beqi_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x40000000;
  slotbuf[1] = 0;
}

static void
Opcode_bnei_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x98000000;
  slotbuf[1] = 0;
}

static void
Opcode_bgei_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x50000000;
  slotbuf[1] = 0;
}

static void
Opcode_blti_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x70000000;
  slotbuf[1] = 0;
}

static void
Opcode_bgeui_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x60000000;
  slotbuf[1] = 0;
}

static void
Opcode_bltui_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x80000000;
  slotbuf[1] = 0;
}

static void
Opcode_bbci_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x8000000;
  slotbuf[1] = 0;
}

static void
Opcode_bbsi_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x10000000;
  slotbuf[1] = 0;
}

static void
Opcode_beq_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x38000000;
  slotbuf[1] = 0;
}

static void
Opcode_bne_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x90000000;
  slotbuf[1] = 0;
}

static void
Opcode_bge_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x48000000;
  slotbuf[1] = 0;
}

static void
Opcode_blt_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x68000000;
  slotbuf[1] = 0;
}

static void
Opcode_bgeu_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x58000000;
  slotbuf[1] = 0;
}

static void
Opcode_bltu_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x78000000;
  slotbuf[1] = 0;
}

static void
Opcode_bany_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x20000000;
  slotbuf[1] = 0;
}

static void
Opcode_bnone_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0xa0000000;
  slotbuf[1] = 0;
}

static void
Opcode_ball_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x18000000;
  slotbuf[1] = 0;
}

static void
Opcode_bnall_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x88000000;
  slotbuf[1] = 0;
}

static void
Opcode_bbc_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x28000000;
  slotbuf[1] = 0;
}

static void
Opcode_bbs_w18_Slot_xt_flix64_slot3_encode (xtensa_insnbuf slotbuf)
{
  slotbuf[0] = 0x30000000;
  slotbuf[1] = 0;
}

xtensa_opcode_encode_fn Opcode_excw_encode_fns[] = {
  Opcode_excw_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rfe_encode_fns[] = {
  Opcode_rfe_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rfde_encode_fns[] = {
  Opcode_rfde_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_syscall_encode_fns[] = {
  Opcode_syscall_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_simcall_encode_fns[] = {
  Opcode_simcall_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_call12_encode_fns[] = {
  Opcode_call12_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_call8_encode_fns[] = {
  Opcode_call8_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_call4_encode_fns[] = {
  Opcode_call4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_callx12_encode_fns[] = {
  Opcode_callx12_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_callx8_encode_fns[] = {
  Opcode_callx8_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_callx4_encode_fns[] = {
  Opcode_callx4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_entry_encode_fns[] = {
  Opcode_entry_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movsp_encode_fns[] = {
  Opcode_movsp_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rotw_encode_fns[] = {
  Opcode_rotw_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_retw_encode_fns[] = {
  Opcode_retw_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_retw_n_encode_fns[] = {
  0, 0, Opcode_retw_n_Slot_inst16b_encode, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rfwo_encode_fns[] = {
  Opcode_rfwo_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rfwu_encode_fns[] = {
  Opcode_rfwu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_l32e_encode_fns[] = {
  Opcode_l32e_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_s32e_encode_fns[] = {
  Opcode_s32e_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_windowbase_encode_fns[] = {
  Opcode_rsr_windowbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_windowbase_encode_fns[] = {
  Opcode_wsr_windowbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_windowbase_encode_fns[] = {
  Opcode_xsr_windowbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_windowstart_encode_fns[] = {
  Opcode_rsr_windowstart_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_windowstart_encode_fns[] = {
  Opcode_wsr_windowstart_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_windowstart_encode_fns[] = {
  Opcode_xsr_windowstart_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_add_n_encode_fns[] = {
  0, Opcode_add_n_Slot_inst16a_encode, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_addi_n_encode_fns[] = {
  0, Opcode_addi_n_Slot_inst16a_encode, 0, 0, 0, 0, Opcode_addi_n_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_beqz_n_encode_fns[] = {
  0, 0, Opcode_beqz_n_Slot_inst16b_encode, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bnez_n_encode_fns[] = {
  0, 0, Opcode_bnez_n_Slot_inst16b_encode, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ill_n_encode_fns[] = {
  0, 0, Opcode_ill_n_Slot_inst16b_encode, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_l32i_n_encode_fns[] = {
  0, Opcode_l32i_n_Slot_inst16a_encode, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mov_n_encode_fns[] = {
  0, 0, Opcode_mov_n_Slot_inst16b_encode, Opcode_mov_n_Slot_xt_flix64_slot0_encode, Opcode_mov_n_Slot_xt_flix64_slot0_encode, Opcode_mov_n_Slot_xt_flix64_slot1_encode, Opcode_mov_n_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_movi_n_encode_fns[] = {
  0, 0, Opcode_movi_n_Slot_inst16b_encode, 0, 0, 0, Opcode_movi_n_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_nop_n_encode_fns[] = {
  0, 0, Opcode_nop_n_Slot_inst16b_encode, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ret_n_encode_fns[] = {
  0, 0, Opcode_ret_n_Slot_inst16b_encode, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_s32i_n_encode_fns[] = {
  0, Opcode_s32i_n_Slot_inst16a_encode, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rur_threadptr_encode_fns[] = {
  Opcode_rur_threadptr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wur_threadptr_encode_fns[] = {
  Opcode_wur_threadptr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_addi_encode_fns[] = {
  Opcode_addi_Slot_inst_encode, 0, 0, Opcode_addi_Slot_xt_flix64_slot0_encode, Opcode_addi_Slot_xt_flix64_slot0_encode, Opcode_addi_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_addmi_encode_fns[] = {
  Opcode_addmi_Slot_inst_encode, 0, 0, Opcode_addmi_Slot_xt_flix64_slot0_encode, Opcode_addmi_Slot_xt_flix64_slot0_encode, Opcode_addmi_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_add_encode_fns[] = {
  Opcode_add_Slot_inst_encode, 0, 0, Opcode_add_Slot_xt_flix64_slot0_encode, Opcode_add_Slot_xt_flix64_slot0_encode, Opcode_add_Slot_xt_flix64_slot1_encode, Opcode_add_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_sub_encode_fns[] = {
  Opcode_sub_Slot_inst_encode, 0, 0, Opcode_sub_Slot_xt_flix64_slot0_encode, Opcode_sub_Slot_xt_flix64_slot0_encode, Opcode_sub_Slot_xt_flix64_slot1_encode, Opcode_sub_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_addx2_encode_fns[] = {
  Opcode_addx2_Slot_inst_encode, 0, 0, Opcode_addx2_Slot_xt_flix64_slot0_encode, Opcode_addx2_Slot_xt_flix64_slot0_encode, Opcode_addx2_Slot_xt_flix64_slot1_encode, Opcode_addx2_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_addx4_encode_fns[] = {
  Opcode_addx4_Slot_inst_encode, 0, 0, Opcode_addx4_Slot_xt_flix64_slot0_encode, Opcode_addx4_Slot_xt_flix64_slot0_encode, Opcode_addx4_Slot_xt_flix64_slot1_encode, Opcode_addx4_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_addx8_encode_fns[] = {
  Opcode_addx8_Slot_inst_encode, 0, 0, Opcode_addx8_Slot_xt_flix64_slot0_encode, Opcode_addx8_Slot_xt_flix64_slot0_encode, Opcode_addx8_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_subx2_encode_fns[] = {
  Opcode_subx2_Slot_inst_encode, 0, 0, Opcode_subx2_Slot_xt_flix64_slot0_encode, Opcode_subx2_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_subx4_encode_fns[] = {
  Opcode_subx4_Slot_inst_encode, 0, 0, Opcode_subx4_Slot_xt_flix64_slot0_encode, Opcode_subx4_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_subx8_encode_fns[] = {
  Opcode_subx8_Slot_inst_encode, 0, 0, Opcode_subx8_Slot_xt_flix64_slot0_encode, Opcode_subx8_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_and_encode_fns[] = {
  Opcode_and_Slot_inst_encode, 0, 0, Opcode_and_Slot_xt_flix64_slot0_encode, Opcode_and_Slot_xt_flix64_slot0_encode, Opcode_and_Slot_xt_flix64_slot1_encode, Opcode_and_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_or_encode_fns[] = {
  Opcode_or_Slot_inst_encode, 0, 0, Opcode_or_Slot_xt_flix64_slot0_encode, Opcode_or_Slot_xt_flix64_slot0_encode, Opcode_or_Slot_xt_flix64_slot1_encode, Opcode_or_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_xor_encode_fns[] = {
  Opcode_xor_Slot_inst_encode, 0, 0, Opcode_xor_Slot_xt_flix64_slot0_encode, Opcode_xor_Slot_xt_flix64_slot0_encode, Opcode_xor_Slot_xt_flix64_slot1_encode, Opcode_xor_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_beqi_encode_fns[] = {
  Opcode_beqi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bnei_encode_fns[] = {
  Opcode_bnei_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bgei_encode_fns[] = {
  Opcode_bgei_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_blti_encode_fns[] = {
  Opcode_blti_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bbci_encode_fns[] = {
  Opcode_bbci_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bbsi_encode_fns[] = {
  Opcode_bbsi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bgeui_encode_fns[] = {
  Opcode_bgeui_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bltui_encode_fns[] = {
  Opcode_bltui_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_beq_encode_fns[] = {
  Opcode_beq_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bne_encode_fns[] = {
  Opcode_bne_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bge_encode_fns[] = {
  Opcode_bge_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_blt_encode_fns[] = {
  Opcode_blt_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bgeu_encode_fns[] = {
  Opcode_bgeu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bltu_encode_fns[] = {
  Opcode_bltu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bany_encode_fns[] = {
  Opcode_bany_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bnone_encode_fns[] = {
  Opcode_bnone_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ball_encode_fns[] = {
  Opcode_ball_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bnall_encode_fns[] = {
  Opcode_bnall_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bbc_encode_fns[] = {
  Opcode_bbc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bbs_encode_fns[] = {
  Opcode_bbs_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_beqz_encode_fns[] = {
  Opcode_beqz_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bnez_encode_fns[] = {
  Opcode_bnez_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bgez_encode_fns[] = {
  Opcode_bgez_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bltz_encode_fns[] = {
  Opcode_bltz_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_call0_encode_fns[] = {
  Opcode_call0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_callx0_encode_fns[] = {
  Opcode_callx0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_extui_encode_fns[] = {
  Opcode_extui_Slot_inst_encode, 0, 0, Opcode_extui_Slot_xt_flix64_slot0_encode, Opcode_extui_Slot_xt_flix64_slot0_encode, Opcode_extui_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_ill_encode_fns[] = {
  Opcode_ill_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_j_encode_fns[] = {
  Opcode_j_Slot_inst_encode, 0, 0, 0, 0, Opcode_j_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_jx_encode_fns[] = {
  Opcode_jx_Slot_inst_encode, 0, 0, 0, 0, Opcode_jx_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_l16ui_encode_fns[] = {
  Opcode_l16ui_Slot_inst_encode, 0, 0, Opcode_l16ui_Slot_xt_flix64_slot0_encode, Opcode_l16ui_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_l16si_encode_fns[] = {
  Opcode_l16si_Slot_inst_encode, 0, 0, Opcode_l16si_Slot_xt_flix64_slot0_encode, Opcode_l16si_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_l32i_encode_fns[] = {
  Opcode_l32i_Slot_inst_encode, 0, 0, Opcode_l32i_Slot_xt_flix64_slot0_encode, Opcode_l32i_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_l32r_encode_fns[] = {
  Opcode_l32r_Slot_inst_encode, 0, 0, Opcode_l32r_Slot_xt_flix64_slot0_encode, Opcode_l32r_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_l8ui_encode_fns[] = {
  Opcode_l8ui_Slot_inst_encode, 0, 0, Opcode_l8ui_Slot_xt_flix64_slot0_encode, Opcode_l8ui_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_loop_encode_fns[] = {
  Opcode_loop_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_loopnez_encode_fns[] = {
  Opcode_loopnez_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_loopgtz_encode_fns[] = {
  Opcode_loopgtz_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movi_encode_fns[] = {
  Opcode_movi_Slot_inst_encode, 0, 0, Opcode_movi_Slot_xt_flix64_slot0_encode, Opcode_movi_Slot_xt_flix64_slot0_encode, Opcode_movi_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_moveqz_encode_fns[] = {
  Opcode_moveqz_Slot_inst_encode, 0, 0, Opcode_moveqz_Slot_xt_flix64_slot0_encode, Opcode_moveqz_Slot_xt_flix64_slot0_encode, Opcode_moveqz_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_movnez_encode_fns[] = {
  Opcode_movnez_Slot_inst_encode, 0, 0, Opcode_movnez_Slot_xt_flix64_slot0_encode, Opcode_movnez_Slot_xt_flix64_slot0_encode, Opcode_movnez_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_movltz_encode_fns[] = {
  Opcode_movltz_Slot_inst_encode, 0, 0, Opcode_movltz_Slot_xt_flix64_slot0_encode, Opcode_movltz_Slot_xt_flix64_slot0_encode, Opcode_movltz_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_movgez_encode_fns[] = {
  Opcode_movgez_Slot_inst_encode, 0, 0, Opcode_movgez_Slot_xt_flix64_slot0_encode, Opcode_movgez_Slot_xt_flix64_slot0_encode, Opcode_movgez_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_neg_encode_fns[] = {
  Opcode_neg_Slot_inst_encode, 0, 0, Opcode_neg_Slot_xt_flix64_slot0_encode, Opcode_neg_Slot_xt_flix64_slot0_encode, Opcode_neg_Slot_xt_flix64_slot1_encode, Opcode_neg_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_abs_encode_fns[] = {
  Opcode_abs_Slot_inst_encode, 0, 0, Opcode_abs_Slot_xt_flix64_slot0_encode, Opcode_abs_Slot_xt_flix64_slot0_encode, 0, Opcode_abs_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_nop_encode_fns[] = {
  Opcode_nop_Slot_inst_encode, 0, 0, Opcode_nop_Slot_xt_flix64_slot0_encode, Opcode_nop_Slot_xt_flix64_slot0_encode, Opcode_nop_Slot_xt_flix64_slot1_encode, Opcode_nop_Slot_xt_flix64_slot2_encode, Opcode_nop_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_ret_encode_fns[] = {
  Opcode_ret_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_s16i_encode_fns[] = {
  Opcode_s16i_Slot_inst_encode, 0, 0, Opcode_s16i_Slot_xt_flix64_slot0_encode, Opcode_s16i_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_s32i_encode_fns[] = {
  Opcode_s32i_Slot_inst_encode, 0, 0, Opcode_s32i_Slot_xt_flix64_slot0_encode, Opcode_s32i_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_s8i_encode_fns[] = {
  Opcode_s8i_Slot_inst_encode, 0, 0, Opcode_s8i_Slot_xt_flix64_slot0_encode, Opcode_s8i_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssr_encode_fns[] = {
  Opcode_ssr_Slot_inst_encode, 0, 0, Opcode_ssr_Slot_xt_flix64_slot0_encode, Opcode_ssr_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssl_encode_fns[] = {
  Opcode_ssl_Slot_inst_encode, 0, 0, Opcode_ssl_Slot_xt_flix64_slot0_encode, Opcode_ssl_Slot_xt_flix64_slot0_encode, Opcode_ssl_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssa8l_encode_fns[] = {
  Opcode_ssa8l_Slot_inst_encode, 0, 0, Opcode_ssa8l_Slot_xt_flix64_slot0_encode, Opcode_ssa8l_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssa8b_encode_fns[] = {
  Opcode_ssa8b_Slot_inst_encode, 0, 0, Opcode_ssa8b_Slot_xt_flix64_slot0_encode, Opcode_ssa8b_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssai_encode_fns[] = {
  Opcode_ssai_Slot_inst_encode, 0, 0, Opcode_ssai_Slot_xt_flix64_slot0_encode, Opcode_ssai_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_sll_encode_fns[] = {
  Opcode_sll_Slot_inst_encode, 0, 0, Opcode_sll_Slot_xt_flix64_slot0_encode, Opcode_sll_Slot_xt_flix64_slot0_encode, Opcode_sll_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_src_encode_fns[] = {
  Opcode_src_Slot_inst_encode, 0, 0, Opcode_src_Slot_xt_flix64_slot0_encode, Opcode_src_Slot_xt_flix64_slot0_encode, Opcode_src_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_srl_encode_fns[] = {
  Opcode_srl_Slot_inst_encode, 0, 0, Opcode_srl_Slot_xt_flix64_slot0_encode, Opcode_srl_Slot_xt_flix64_slot0_encode, Opcode_srl_Slot_xt_flix64_slot1_encode, Opcode_srl_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_sra_encode_fns[] = {
  Opcode_sra_Slot_inst_encode, 0, 0, Opcode_sra_Slot_xt_flix64_slot0_encode, Opcode_sra_Slot_xt_flix64_slot0_encode, Opcode_sra_Slot_xt_flix64_slot1_encode, Opcode_sra_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_slli_encode_fns[] = {
  Opcode_slli_Slot_inst_encode, 0, 0, Opcode_slli_Slot_xt_flix64_slot0_encode, Opcode_slli_Slot_xt_flix64_slot0_encode, Opcode_slli_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_srai_encode_fns[] = {
  Opcode_srai_Slot_inst_encode, 0, 0, Opcode_srai_Slot_xt_flix64_slot0_encode, Opcode_srai_Slot_xt_flix64_slot0_encode, Opcode_srai_Slot_xt_flix64_slot1_encode, Opcode_srai_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_srli_encode_fns[] = {
  Opcode_srli_Slot_inst_encode, 0, 0, Opcode_srli_Slot_xt_flix64_slot0_encode, Opcode_srli_Slot_xt_flix64_slot0_encode, Opcode_srli_Slot_xt_flix64_slot1_encode, Opcode_srli_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_memw_encode_fns[] = {
  Opcode_memw_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_extw_encode_fns[] = {
  Opcode_extw_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_isync_encode_fns[] = {
  Opcode_isync_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsync_encode_fns[] = {
  Opcode_rsync_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_esync_encode_fns[] = {
  Opcode_esync_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dsync_encode_fns[] = {
  Opcode_dsync_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsil_encode_fns[] = {
  Opcode_rsil_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_lend_encode_fns[] = {
  Opcode_rsr_lend_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_lend_encode_fns[] = {
  Opcode_wsr_lend_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_lend_encode_fns[] = {
  Opcode_xsr_lend_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_lcount_encode_fns[] = {
  Opcode_rsr_lcount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_lcount_encode_fns[] = {
  Opcode_wsr_lcount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_lcount_encode_fns[] = {
  Opcode_xsr_lcount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_lbeg_encode_fns[] = {
  Opcode_rsr_lbeg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_lbeg_encode_fns[] = {
  Opcode_wsr_lbeg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_lbeg_encode_fns[] = {
  Opcode_xsr_lbeg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_sar_encode_fns[] = {
  Opcode_rsr_sar_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_sar_encode_fns[] = {
  Opcode_wsr_sar_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_sar_encode_fns[] = {
  Opcode_xsr_sar_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_litbase_encode_fns[] = {
  Opcode_rsr_litbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_litbase_encode_fns[] = {
  Opcode_wsr_litbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_litbase_encode_fns[] = {
  Opcode_xsr_litbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_176_encode_fns[] = {
  Opcode_rsr_176_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_208_encode_fns[] = {
  Opcode_rsr_208_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ps_encode_fns[] = {
  Opcode_rsr_ps_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ps_encode_fns[] = {
  Opcode_wsr_ps_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ps_encode_fns[] = {
  Opcode_xsr_ps_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_epc1_encode_fns[] = {
  Opcode_rsr_epc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_epc1_encode_fns[] = {
  Opcode_wsr_epc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_epc1_encode_fns[] = {
  Opcode_xsr_epc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_excsave1_encode_fns[] = {
  Opcode_rsr_excsave1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_excsave1_encode_fns[] = {
  Opcode_wsr_excsave1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_excsave1_encode_fns[] = {
  Opcode_xsr_excsave1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_epc2_encode_fns[] = {
  Opcode_rsr_epc2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_epc2_encode_fns[] = {
  Opcode_wsr_epc2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_epc2_encode_fns[] = {
  Opcode_xsr_epc2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_excsave2_encode_fns[] = {
  Opcode_rsr_excsave2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_excsave2_encode_fns[] = {
  Opcode_wsr_excsave2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_excsave2_encode_fns[] = {
  Opcode_xsr_excsave2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_epc3_encode_fns[] = {
  Opcode_rsr_epc3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_epc3_encode_fns[] = {
  Opcode_wsr_epc3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_epc3_encode_fns[] = {
  Opcode_xsr_epc3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_excsave3_encode_fns[] = {
  Opcode_rsr_excsave3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_excsave3_encode_fns[] = {
  Opcode_wsr_excsave3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_excsave3_encode_fns[] = {
  Opcode_xsr_excsave3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_epc4_encode_fns[] = {
  Opcode_rsr_epc4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_epc4_encode_fns[] = {
  Opcode_wsr_epc4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_epc4_encode_fns[] = {
  Opcode_xsr_epc4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_excsave4_encode_fns[] = {
  Opcode_rsr_excsave4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_excsave4_encode_fns[] = {
  Opcode_wsr_excsave4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_excsave4_encode_fns[] = {
  Opcode_xsr_excsave4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_epc5_encode_fns[] = {
  Opcode_rsr_epc5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_epc5_encode_fns[] = {
  Opcode_wsr_epc5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_epc5_encode_fns[] = {
  Opcode_xsr_epc5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_excsave5_encode_fns[] = {
  Opcode_rsr_excsave5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_excsave5_encode_fns[] = {
  Opcode_wsr_excsave5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_excsave5_encode_fns[] = {
  Opcode_xsr_excsave5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_epc6_encode_fns[] = {
  Opcode_rsr_epc6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_epc6_encode_fns[] = {
  Opcode_wsr_epc6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_epc6_encode_fns[] = {
  Opcode_xsr_epc6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_excsave6_encode_fns[] = {
  Opcode_rsr_excsave6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_excsave6_encode_fns[] = {
  Opcode_wsr_excsave6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_excsave6_encode_fns[] = {
  Opcode_xsr_excsave6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_epc7_encode_fns[] = {
  Opcode_rsr_epc7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_epc7_encode_fns[] = {
  Opcode_wsr_epc7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_epc7_encode_fns[] = {
  Opcode_xsr_epc7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_excsave7_encode_fns[] = {
  Opcode_rsr_excsave7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_excsave7_encode_fns[] = {
  Opcode_wsr_excsave7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_excsave7_encode_fns[] = {
  Opcode_xsr_excsave7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_eps2_encode_fns[] = {
  Opcode_rsr_eps2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_eps2_encode_fns[] = {
  Opcode_wsr_eps2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_eps2_encode_fns[] = {
  Opcode_xsr_eps2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_eps3_encode_fns[] = {
  Opcode_rsr_eps3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_eps3_encode_fns[] = {
  Opcode_wsr_eps3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_eps3_encode_fns[] = {
  Opcode_xsr_eps3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_eps4_encode_fns[] = {
  Opcode_rsr_eps4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_eps4_encode_fns[] = {
  Opcode_wsr_eps4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_eps4_encode_fns[] = {
  Opcode_xsr_eps4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_eps5_encode_fns[] = {
  Opcode_rsr_eps5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_eps5_encode_fns[] = {
  Opcode_wsr_eps5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_eps5_encode_fns[] = {
  Opcode_xsr_eps5_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_eps6_encode_fns[] = {
  Opcode_rsr_eps6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_eps6_encode_fns[] = {
  Opcode_wsr_eps6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_eps6_encode_fns[] = {
  Opcode_xsr_eps6_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_eps7_encode_fns[] = {
  Opcode_rsr_eps7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_eps7_encode_fns[] = {
  Opcode_wsr_eps7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_eps7_encode_fns[] = {
  Opcode_xsr_eps7_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_excvaddr_encode_fns[] = {
  Opcode_rsr_excvaddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_excvaddr_encode_fns[] = {
  Opcode_wsr_excvaddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_excvaddr_encode_fns[] = {
  Opcode_xsr_excvaddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_depc_encode_fns[] = {
  Opcode_rsr_depc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_depc_encode_fns[] = {
  Opcode_wsr_depc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_depc_encode_fns[] = {
  Opcode_xsr_depc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_exccause_encode_fns[] = {
  Opcode_rsr_exccause_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_exccause_encode_fns[] = {
  Opcode_wsr_exccause_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_exccause_encode_fns[] = {
  Opcode_xsr_exccause_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_misc0_encode_fns[] = {
  Opcode_rsr_misc0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_misc0_encode_fns[] = {
  Opcode_wsr_misc0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_misc0_encode_fns[] = {
  Opcode_xsr_misc0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_misc1_encode_fns[] = {
  Opcode_rsr_misc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_misc1_encode_fns[] = {
  Opcode_wsr_misc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_misc1_encode_fns[] = {
  Opcode_xsr_misc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_misc2_encode_fns[] = {
  Opcode_rsr_misc2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_misc2_encode_fns[] = {
  Opcode_wsr_misc2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_misc2_encode_fns[] = {
  Opcode_xsr_misc2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_misc3_encode_fns[] = {
  Opcode_rsr_misc3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_misc3_encode_fns[] = {
  Opcode_wsr_misc3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_misc3_encode_fns[] = {
  Opcode_xsr_misc3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_prid_encode_fns[] = {
  Opcode_rsr_prid_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_vecbase_encode_fns[] = {
  Opcode_rsr_vecbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_vecbase_encode_fns[] = {
  Opcode_wsr_vecbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_vecbase_encode_fns[] = {
  Opcode_xsr_vecbase_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_aa_ll_encode_fns[] = {
  Opcode_mul_aa_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_aa_hl_encode_fns[] = {
  Opcode_mul_aa_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_aa_lh_encode_fns[] = {
  Opcode_mul_aa_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_aa_hh_encode_fns[] = {
  Opcode_mul_aa_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_umul_aa_ll_encode_fns[] = {
  Opcode_umul_aa_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_umul_aa_hl_encode_fns[] = {
  Opcode_umul_aa_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_umul_aa_lh_encode_fns[] = {
  Opcode_umul_aa_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_umul_aa_hh_encode_fns[] = {
  Opcode_umul_aa_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_ad_ll_encode_fns[] = {
  Opcode_mul_ad_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_ad_hl_encode_fns[] = {
  Opcode_mul_ad_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_ad_lh_encode_fns[] = {
  Opcode_mul_ad_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_ad_hh_encode_fns[] = {
  Opcode_mul_ad_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_da_ll_encode_fns[] = {
  Opcode_mul_da_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_da_hl_encode_fns[] = {
  Opcode_mul_da_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_da_lh_encode_fns[] = {
  Opcode_mul_da_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_da_hh_encode_fns[] = {
  Opcode_mul_da_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_dd_ll_encode_fns[] = {
  Opcode_mul_dd_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_dd_hl_encode_fns[] = {
  Opcode_mul_dd_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_dd_lh_encode_fns[] = {
  Opcode_mul_dd_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_dd_hh_encode_fns[] = {
  Opcode_mul_dd_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_aa_ll_encode_fns[] = {
  Opcode_mula_aa_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_aa_hl_encode_fns[] = {
  Opcode_mula_aa_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_aa_lh_encode_fns[] = {
  Opcode_mula_aa_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_aa_hh_encode_fns[] = {
  Opcode_mula_aa_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_aa_ll_encode_fns[] = {
  Opcode_muls_aa_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_aa_hl_encode_fns[] = {
  Opcode_muls_aa_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_aa_lh_encode_fns[] = {
  Opcode_muls_aa_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_aa_hh_encode_fns[] = {
  Opcode_muls_aa_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_ad_ll_encode_fns[] = {
  Opcode_mula_ad_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_ad_hl_encode_fns[] = {
  Opcode_mula_ad_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_ad_lh_encode_fns[] = {
  Opcode_mula_ad_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_ad_hh_encode_fns[] = {
  Opcode_mula_ad_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_ad_ll_encode_fns[] = {
  Opcode_muls_ad_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_ad_hl_encode_fns[] = {
  Opcode_muls_ad_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_ad_lh_encode_fns[] = {
  Opcode_muls_ad_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_ad_hh_encode_fns[] = {
  Opcode_muls_ad_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_ll_encode_fns[] = {
  Opcode_mula_da_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_hl_encode_fns[] = {
  Opcode_mula_da_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_lh_encode_fns[] = {
  Opcode_mula_da_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_hh_encode_fns[] = {
  Opcode_mula_da_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_da_ll_encode_fns[] = {
  Opcode_muls_da_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_da_hl_encode_fns[] = {
  Opcode_muls_da_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_da_lh_encode_fns[] = {
  Opcode_muls_da_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_da_hh_encode_fns[] = {
  Opcode_muls_da_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_ll_encode_fns[] = {
  Opcode_mula_dd_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_hl_encode_fns[] = {
  Opcode_mula_dd_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_lh_encode_fns[] = {
  Opcode_mula_dd_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_hh_encode_fns[] = {
  Opcode_mula_dd_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_dd_ll_encode_fns[] = {
  Opcode_muls_dd_ll_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_dd_hl_encode_fns[] = {
  Opcode_muls_dd_hl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_dd_lh_encode_fns[] = {
  Opcode_muls_dd_lh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_muls_dd_hh_encode_fns[] = {
  Opcode_muls_dd_hh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_ll_lddec_encode_fns[] = {
  Opcode_mula_da_ll_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_ll_ldinc_encode_fns[] = {
  Opcode_mula_da_ll_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_hl_lddec_encode_fns[] = {
  Opcode_mula_da_hl_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_hl_ldinc_encode_fns[] = {
  Opcode_mula_da_hl_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_lh_lddec_encode_fns[] = {
  Opcode_mula_da_lh_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_lh_ldinc_encode_fns[] = {
  Opcode_mula_da_lh_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_hh_lddec_encode_fns[] = {
  Opcode_mula_da_hh_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_da_hh_ldinc_encode_fns[] = {
  Opcode_mula_da_hh_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_ll_lddec_encode_fns[] = {
  Opcode_mula_dd_ll_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_ll_ldinc_encode_fns[] = {
  Opcode_mula_dd_ll_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_hl_lddec_encode_fns[] = {
  Opcode_mula_dd_hl_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_hl_ldinc_encode_fns[] = {
  Opcode_mula_dd_hl_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_lh_lddec_encode_fns[] = {
  Opcode_mula_dd_lh_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_lh_ldinc_encode_fns[] = {
  Opcode_mula_dd_lh_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_hh_lddec_encode_fns[] = {
  Opcode_mula_dd_hh_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mula_dd_hh_ldinc_encode_fns[] = {
  Opcode_mula_dd_hh_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_lddec_encode_fns[] = {
  Opcode_lddec_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ldinc_encode_fns[] = {
  Opcode_ldinc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul16u_encode_fns[] = {
  Opcode_mul16u_Slot_inst_encode, 0, 0, Opcode_mul16u_Slot_xt_flix64_slot0_encode, Opcode_mul16u_Slot_xt_flix64_slot0_encode, Opcode_mul16u_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul16s_encode_fns[] = {
  Opcode_mul16s_Slot_inst_encode, 0, 0, Opcode_mul16s_Slot_xt_flix64_slot0_encode, Opcode_mul16s_Slot_xt_flix64_slot0_encode, Opcode_mul16s_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_m0_encode_fns[] = {
  Opcode_rsr_m0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_m0_encode_fns[] = {
  Opcode_wsr_m0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_m0_encode_fns[] = {
  Opcode_xsr_m0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_m1_encode_fns[] = {
  Opcode_rsr_m1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_m1_encode_fns[] = {
  Opcode_wsr_m1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_m1_encode_fns[] = {
  Opcode_xsr_m1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_m2_encode_fns[] = {
  Opcode_rsr_m2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_m2_encode_fns[] = {
  Opcode_wsr_m2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_m2_encode_fns[] = {
  Opcode_xsr_m2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_m3_encode_fns[] = {
  Opcode_rsr_m3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_m3_encode_fns[] = {
  Opcode_wsr_m3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_m3_encode_fns[] = {
  Opcode_xsr_m3_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_acclo_encode_fns[] = {
  Opcode_rsr_acclo_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_acclo_encode_fns[] = {
  Opcode_wsr_acclo_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_acclo_encode_fns[] = {
  Opcode_xsr_acclo_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_acchi_encode_fns[] = {
  Opcode_rsr_acchi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_acchi_encode_fns[] = {
  Opcode_wsr_acchi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_acchi_encode_fns[] = {
  Opcode_xsr_acchi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rfi_encode_fns[] = {
  Opcode_rfi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_waiti_encode_fns[] = {
  Opcode_waiti_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_interrupt_encode_fns[] = {
  Opcode_rsr_interrupt_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_intset_encode_fns[] = {
  Opcode_wsr_intset_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_intclear_encode_fns[] = {
  Opcode_wsr_intclear_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_intenable_encode_fns[] = {
  Opcode_rsr_intenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_intenable_encode_fns[] = {
  Opcode_wsr_intenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_intenable_encode_fns[] = {
  Opcode_xsr_intenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_break_encode_fns[] = {
  Opcode_break_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_break_n_encode_fns[] = {
  0, 0, Opcode_break_n_Slot_inst16b_encode, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_dbreaka0_encode_fns[] = {
  Opcode_rsr_dbreaka0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_dbreaka0_encode_fns[] = {
  Opcode_wsr_dbreaka0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_dbreaka0_encode_fns[] = {
  Opcode_xsr_dbreaka0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_dbreakc0_encode_fns[] = {
  Opcode_rsr_dbreakc0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_dbreakc0_encode_fns[] = {
  Opcode_wsr_dbreakc0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_dbreakc0_encode_fns[] = {
  Opcode_xsr_dbreakc0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_dbreaka1_encode_fns[] = {
  Opcode_rsr_dbreaka1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_dbreaka1_encode_fns[] = {
  Opcode_wsr_dbreaka1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_dbreaka1_encode_fns[] = {
  Opcode_xsr_dbreaka1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_dbreakc1_encode_fns[] = {
  Opcode_rsr_dbreakc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_dbreakc1_encode_fns[] = {
  Opcode_wsr_dbreakc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_dbreakc1_encode_fns[] = {
  Opcode_xsr_dbreakc1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ibreaka0_encode_fns[] = {
  Opcode_rsr_ibreaka0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ibreaka0_encode_fns[] = {
  Opcode_wsr_ibreaka0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ibreaka0_encode_fns[] = {
  Opcode_xsr_ibreaka0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ibreaka1_encode_fns[] = {
  Opcode_rsr_ibreaka1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ibreaka1_encode_fns[] = {
  Opcode_wsr_ibreaka1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ibreaka1_encode_fns[] = {
  Opcode_xsr_ibreaka1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ibreakenable_encode_fns[] = {
  Opcode_rsr_ibreakenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ibreakenable_encode_fns[] = {
  Opcode_wsr_ibreakenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ibreakenable_encode_fns[] = {
  Opcode_xsr_ibreakenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_debugcause_encode_fns[] = {
  Opcode_rsr_debugcause_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_debugcause_encode_fns[] = {
  Opcode_wsr_debugcause_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_debugcause_encode_fns[] = {
  Opcode_xsr_debugcause_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_icount_encode_fns[] = {
  Opcode_rsr_icount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_icount_encode_fns[] = {
  Opcode_wsr_icount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_icount_encode_fns[] = {
  Opcode_xsr_icount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_icountlevel_encode_fns[] = {
  Opcode_rsr_icountlevel_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_icountlevel_encode_fns[] = {
  Opcode_wsr_icountlevel_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_icountlevel_encode_fns[] = {
  Opcode_xsr_icountlevel_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ddr_encode_fns[] = {
  Opcode_rsr_ddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ddr_encode_fns[] = {
  Opcode_wsr_ddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ddr_encode_fns[] = {
  Opcode_xsr_ddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rfdo_encode_fns[] = {
  Opcode_rfdo_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rfdd_encode_fns[] = {
  Opcode_rfdd_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_mmid_encode_fns[] = {
  Opcode_wsr_mmid_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_andb_encode_fns[] = {
  Opcode_andb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_andbc_encode_fns[] = {
  Opcode_andbc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_orb_encode_fns[] = {
  Opcode_orb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_orbc_encode_fns[] = {
  Opcode_orbc_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xorb_encode_fns[] = {
  Opcode_xorb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_any4_encode_fns[] = {
  Opcode_any4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_all4_encode_fns[] = {
  Opcode_all4_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_any8_encode_fns[] = {
  Opcode_any8_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_all8_encode_fns[] = {
  Opcode_all8_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bf_encode_fns[] = {
  Opcode_bf_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_bt_encode_fns[] = {
  Opcode_bt_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movf_encode_fns[] = {
  Opcode_movf_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movt_encode_fns[] = {
  Opcode_movt_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_br_encode_fns[] = {
  Opcode_rsr_br_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_br_encode_fns[] = {
  Opcode_wsr_br_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_br_encode_fns[] = {
  Opcode_xsr_br_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ccount_encode_fns[] = {
  Opcode_rsr_ccount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ccount_encode_fns[] = {
  Opcode_wsr_ccount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ccount_encode_fns[] = {
  Opcode_xsr_ccount_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ccompare0_encode_fns[] = {
  Opcode_rsr_ccompare0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ccompare0_encode_fns[] = {
  Opcode_wsr_ccompare0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ccompare0_encode_fns[] = {
  Opcode_xsr_ccompare0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ccompare1_encode_fns[] = {
  Opcode_rsr_ccompare1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ccompare1_encode_fns[] = {
  Opcode_wsr_ccompare1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ccompare1_encode_fns[] = {
  Opcode_xsr_ccompare1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ccompare2_encode_fns[] = {
  Opcode_rsr_ccompare2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ccompare2_encode_fns[] = {
  Opcode_wsr_ccompare2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ccompare2_encode_fns[] = {
  Opcode_xsr_ccompare2_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ipf_encode_fns[] = {
  Opcode_ipf_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ihi_encode_fns[] = {
  Opcode_ihi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ipfl_encode_fns[] = {
  Opcode_ipfl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ihu_encode_fns[] = {
  Opcode_ihu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_iiu_encode_fns[] = {
  Opcode_iiu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_iii_encode_fns[] = {
  Opcode_iii_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_lict_encode_fns[] = {
  Opcode_lict_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_licw_encode_fns[] = {
  Opcode_licw_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_sict_encode_fns[] = {
  Opcode_sict_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_sicw_encode_fns[] = {
  Opcode_sicw_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dhwb_encode_fns[] = {
  Opcode_dhwb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dhwbi_encode_fns[] = {
  Opcode_dhwbi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_diwb_encode_fns[] = {
  Opcode_diwb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_diwbi_encode_fns[] = {
  Opcode_diwbi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dhi_encode_fns[] = {
  Opcode_dhi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dii_encode_fns[] = {
  Opcode_dii_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dpfr_encode_fns[] = {
  Opcode_dpfr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dpfw_encode_fns[] = {
  Opcode_dpfw_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dpfro_encode_fns[] = {
  Opcode_dpfro_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dpfwo_encode_fns[] = {
  Opcode_dpfwo_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dpfl_encode_fns[] = {
  Opcode_dpfl_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_dhu_encode_fns[] = {
  Opcode_dhu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_diu_encode_fns[] = {
  Opcode_diu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_sdct_encode_fns[] = {
  Opcode_sdct_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ldct_encode_fns[] = {
  Opcode_ldct_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_ptevaddr_encode_fns[] = {
  Opcode_wsr_ptevaddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_ptevaddr_encode_fns[] = {
  Opcode_rsr_ptevaddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_ptevaddr_encode_fns[] = {
  Opcode_xsr_ptevaddr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_rasid_encode_fns[] = {
  Opcode_rsr_rasid_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_rasid_encode_fns[] = {
  Opcode_wsr_rasid_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_rasid_encode_fns[] = {
  Opcode_xsr_rasid_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_itlbcfg_encode_fns[] = {
  Opcode_rsr_itlbcfg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_itlbcfg_encode_fns[] = {
  Opcode_wsr_itlbcfg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_itlbcfg_encode_fns[] = {
  Opcode_xsr_itlbcfg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_dtlbcfg_encode_fns[] = {
  Opcode_rsr_dtlbcfg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_dtlbcfg_encode_fns[] = {
  Opcode_wsr_dtlbcfg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_dtlbcfg_encode_fns[] = {
  Opcode_xsr_dtlbcfg_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_idtlb_encode_fns[] = {
  Opcode_idtlb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_pdtlb_encode_fns[] = {
  Opcode_pdtlb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rdtlb0_encode_fns[] = {
  Opcode_rdtlb0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rdtlb1_encode_fns[] = {
  Opcode_rdtlb1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wdtlb_encode_fns[] = {
  Opcode_wdtlb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_iitlb_encode_fns[] = {
  Opcode_iitlb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_pitlb_encode_fns[] = {
  Opcode_pitlb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ritlb0_encode_fns[] = {
  Opcode_ritlb0_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ritlb1_encode_fns[] = {
  Opcode_ritlb1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_witlb_encode_fns[] = {
  Opcode_witlb_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ldpte_encode_fns[] = {
  Opcode_ldpte_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_hwwitlba_encode_fns[] = {
  Opcode_hwwitlba_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_hwwdtlba_encode_fns[] = {
  Opcode_hwwdtlba_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_cpenable_encode_fns[] = {
  Opcode_rsr_cpenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_cpenable_encode_fns[] = {
  Opcode_wsr_cpenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_cpenable_encode_fns[] = {
  Opcode_xsr_cpenable_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_clamps_encode_fns[] = {
  Opcode_clamps_Slot_inst_encode, 0, 0, Opcode_clamps_Slot_xt_flix64_slot0_encode, Opcode_clamps_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_min_encode_fns[] = {
  Opcode_min_Slot_inst_encode, 0, 0, Opcode_min_Slot_xt_flix64_slot0_encode, Opcode_min_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_max_encode_fns[] = {
  Opcode_max_Slot_inst_encode, 0, 0, Opcode_max_Slot_xt_flix64_slot0_encode, Opcode_max_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_minu_encode_fns[] = {
  Opcode_minu_Slot_inst_encode, 0, 0, Opcode_minu_Slot_xt_flix64_slot0_encode, Opcode_minu_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_maxu_encode_fns[] = {
  Opcode_maxu_Slot_inst_encode, 0, 0, Opcode_maxu_Slot_xt_flix64_slot0_encode, Opcode_maxu_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_nsa_encode_fns[] = {
  Opcode_nsa_Slot_inst_encode, 0, 0, Opcode_nsa_Slot_xt_flix64_slot0_encode, Opcode_nsa_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_nsau_encode_fns[] = {
  Opcode_nsau_Slot_inst_encode, 0, 0, Opcode_nsau_Slot_xt_flix64_slot0_encode, Opcode_nsau_Slot_xt_flix64_slot0_encode, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_sext_encode_fns[] = {
  Opcode_sext_Slot_inst_encode, 0, 0, Opcode_sext_Slot_xt_flix64_slot0_encode, Opcode_sext_Slot_xt_flix64_slot0_encode, Opcode_sext_Slot_xt_flix64_slot1_encode, Opcode_sext_Slot_xt_flix64_slot2_encode, 0
};

xtensa_opcode_encode_fn Opcode_l32ai_encode_fns[] = {
  Opcode_l32ai_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_s32ri_encode_fns[] = {
  Opcode_s32ri_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_s32c1i_encode_fns[] = {
  Opcode_s32c1i_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rsr_scompare1_encode_fns[] = {
  Opcode_rsr_scompare1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wsr_scompare1_encode_fns[] = {
  Opcode_wsr_scompare1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_xsr_scompare1_encode_fns[] = {
  Opcode_xsr_scompare1_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_quou_encode_fns[] = {
  Opcode_quou_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_quos_encode_fns[] = {
  Opcode_quos_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_remu_encode_fns[] = {
  Opcode_remu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rems_encode_fns[] = {
  Opcode_rems_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mull_encode_fns[] = {
  Opcode_mull_Slot_inst_encode, 0, 0, Opcode_mull_Slot_xt_flix64_slot0_encode, Opcode_mull_Slot_xt_flix64_slot0_encode, Opcode_mull_Slot_xt_flix64_slot1_encode, 0, 0
};

xtensa_opcode_encode_fn Opcode_muluh_encode_fns[] = {
  Opcode_muluh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mulsh_encode_fns[] = {
  Opcode_mulsh_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rur_fcr_encode_fns[] = {
  Opcode_rur_fcr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wur_fcr_encode_fns[] = {
  Opcode_wur_fcr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rur_fsr_encode_fns[] = {
  Opcode_rur_fsr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wur_fsr_encode_fns[] = {
  Opcode_wur_fsr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_add_s_encode_fns[] = {
  Opcode_add_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_sub_s_encode_fns[] = {
  Opcode_sub_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mul_s_encode_fns[] = {
  Opcode_mul_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_madd_s_encode_fns[] = {
  Opcode_madd_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_msub_s_encode_fns[] = {
  Opcode_msub_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movf_s_encode_fns[] = {
  Opcode_movf_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movt_s_encode_fns[] = {
  Opcode_movt_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_moveqz_s_encode_fns[] = {
  Opcode_moveqz_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movnez_s_encode_fns[] = {
  Opcode_movnez_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movltz_s_encode_fns[] = {
  Opcode_movltz_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_movgez_s_encode_fns[] = {
  Opcode_movgez_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_abs_s_encode_fns[] = {
  Opcode_abs_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_mov_s_encode_fns[] = {
  Opcode_mov_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_neg_s_encode_fns[] = {
  Opcode_neg_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_un_s_encode_fns[] = {
  Opcode_un_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_oeq_s_encode_fns[] = {
  Opcode_oeq_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ueq_s_encode_fns[] = {
  Opcode_ueq_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_olt_s_encode_fns[] = {
  Opcode_olt_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ult_s_encode_fns[] = {
  Opcode_ult_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ole_s_encode_fns[] = {
  Opcode_ole_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ule_s_encode_fns[] = {
  Opcode_ule_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_float_s_encode_fns[] = {
  Opcode_float_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ufloat_s_encode_fns[] = {
  Opcode_ufloat_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_round_s_encode_fns[] = {
  Opcode_round_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ceil_s_encode_fns[] = {
  Opcode_ceil_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_floor_s_encode_fns[] = {
  Opcode_floor_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_trunc_s_encode_fns[] = {
  Opcode_trunc_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_utrunc_s_encode_fns[] = {
  Opcode_utrunc_s_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_rfr_encode_fns[] = {
  Opcode_rfr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_wfr_encode_fns[] = {
  Opcode_wfr_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_lsi_encode_fns[] = {
  Opcode_lsi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_lsiu_encode_fns[] = {
  Opcode_lsiu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_lsx_encode_fns[] = {
  Opcode_lsx_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_lsxu_encode_fns[] = {
  Opcode_lsxu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssi_encode_fns[] = {
  Opcode_ssi_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssiu_encode_fns[] = {
  Opcode_ssiu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssx_encode_fns[] = {
  Opcode_ssx_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_ssxu_encode_fns[] = {
  Opcode_ssxu_Slot_inst_encode, 0, 0, 0, 0, 0, 0, 0
};

xtensa_opcode_encode_fn Opcode_beqz_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_beqz_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bnez_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bnez_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bgez_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bgez_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bltz_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bltz_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_beqi_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_beqi_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bnei_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bnei_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bgei_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bgei_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_blti_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_blti_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bgeui_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bgeui_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bltui_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bltui_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bbci_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bbci_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bbsi_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bbsi_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_beq_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_beq_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bne_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bne_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bge_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bge_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_blt_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_blt_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bgeu_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bgeu_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bltu_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bltu_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bany_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bany_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bnone_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bnone_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_ball_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_ball_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bnall_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bnall_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bbc_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bbc_w18_Slot_xt_flix64_slot3_encode
};

xtensa_opcode_encode_fn Opcode_bbs_w18_encode_fns[] = {
  0, 0, 0, 0, 0, 0, 0, Opcode_bbs_w18_Slot_xt_flix64_slot3_encode
};


/* Opcode table.  */

static xtensa_opcode_internal opcodes[] = {
  { "excw", 0 /* xt_iclass_excw */,
    0,
    Opcode_excw_encode_fns, 0, 0 },
  { "rfe", 1 /* xt_iclass_rfe */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_rfe_encode_fns, 0, 0 },
  { "rfde", 2 /* xt_iclass_rfde */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_rfde_encode_fns, 0, 0 },
  { "syscall", 3 /* xt_iclass_syscall */,
    0,
    Opcode_syscall_encode_fns, 0, 0 },
  { "simcall", 4 /* xt_iclass_simcall */,
    0,
    Opcode_simcall_encode_fns, 0, 0 },
  { "call12", 5 /* xt_iclass_call12 */,
    XTENSA_OPCODE_IS_CALL,
    Opcode_call12_encode_fns, 0, 0 },
  { "call8", 6 /* xt_iclass_call8 */,
    XTENSA_OPCODE_IS_CALL,
    Opcode_call8_encode_fns, 0, 0 },
  { "call4", 7 /* xt_iclass_call4 */,
    XTENSA_OPCODE_IS_CALL,
    Opcode_call4_encode_fns, 0, 0 },
  { "callx12", 8 /* xt_iclass_callx12 */,
    XTENSA_OPCODE_IS_CALL,
    Opcode_callx12_encode_fns, 0, 0 },
  { "callx8", 9 /* xt_iclass_callx8 */,
    XTENSA_OPCODE_IS_CALL,
    Opcode_callx8_encode_fns, 0, 0 },
  { "callx4", 10 /* xt_iclass_callx4 */,
    XTENSA_OPCODE_IS_CALL,
    Opcode_callx4_encode_fns, 0, 0 },
  { "entry", 11 /* xt_iclass_entry */,
    0,
    Opcode_entry_encode_fns, 0, 0 },
  { "movsp", 12 /* xt_iclass_movsp */,
    0,
    Opcode_movsp_encode_fns, 0, 0 },
  { "rotw", 13 /* xt_iclass_rotw */,
    0,
    Opcode_rotw_encode_fns, 0, 0 },
  { "retw", 14 /* xt_iclass_retw */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_retw_encode_fns, 0, 0 },
  { "retw.n", 14 /* xt_iclass_retw */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_retw_n_encode_fns, 0, 0 },
  { "rfwo", 15 /* xt_iclass_rfwou */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_rfwo_encode_fns, 0, 0 },
  { "rfwu", 15 /* xt_iclass_rfwou */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_rfwu_encode_fns, 0, 0 },
  { "l32e", 16 /* xt_iclass_l32e */,
    0,
    Opcode_l32e_encode_fns, 0, 0 },
  { "s32e", 17 /* xt_iclass_s32e */,
    0,
    Opcode_s32e_encode_fns, 0, 0 },
  { "rsr.windowbase", 18 /* xt_iclass_rsr.windowbase */,
    0,
    Opcode_rsr_windowbase_encode_fns, 0, 0 },
  { "wsr.windowbase", 19 /* xt_iclass_wsr.windowbase */,
    0,
    Opcode_wsr_windowbase_encode_fns, 0, 0 },
  { "xsr.windowbase", 20 /* xt_iclass_xsr.windowbase */,
    0,
    Opcode_xsr_windowbase_encode_fns, 0, 0 },
  { "rsr.windowstart", 21 /* xt_iclass_rsr.windowstart */,
    0,
    Opcode_rsr_windowstart_encode_fns, 0, 0 },
  { "wsr.windowstart", 22 /* xt_iclass_wsr.windowstart */,
    0,
    Opcode_wsr_windowstart_encode_fns, 0, 0 },
  { "xsr.windowstart", 23 /* xt_iclass_xsr.windowstart */,
    0,
    Opcode_xsr_windowstart_encode_fns, 0, 0 },
  { "add.n", 24 /* xt_iclass_add.n */,
    0,
    Opcode_add_n_encode_fns, 0, 0 },
  { "addi.n", 25 /* xt_iclass_addi.n */,
    0,
    Opcode_addi_n_encode_fns, 0, 0 },
  { "beqz.n", 26 /* xt_iclass_bz6 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_beqz_n_encode_fns, 0, 0 },
  { "bnez.n", 26 /* xt_iclass_bz6 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnez_n_encode_fns, 0, 0 },
  { "ill.n", 27 /* xt_iclass_ill.n */,
    0,
    Opcode_ill_n_encode_fns, 0, 0 },
  { "l32i.n", 28 /* xt_iclass_loadi4 */,
    0,
    Opcode_l32i_n_encode_fns, 0, 0 },
  { "mov.n", 29 /* xt_iclass_mov.n */,
    0,
    Opcode_mov_n_encode_fns, 0, 0 },
  { "movi.n", 30 /* xt_iclass_movi.n */,
    0,
    Opcode_movi_n_encode_fns, 0, 0 },
  { "nop.n", 31 /* xt_iclass_nopn */,
    0,
    Opcode_nop_n_encode_fns, 0, 0 },
  { "ret.n", 32 /* xt_iclass_retn */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_ret_n_encode_fns, 0, 0 },
  { "s32i.n", 33 /* xt_iclass_storei4 */,
    0,
    Opcode_s32i_n_encode_fns, 0, 0 },
  { "rur.threadptr", 34 /* rur_threadptr */,
    0,
    Opcode_rur_threadptr_encode_fns, 0, 0 },
  { "wur.threadptr", 35 /* wur_threadptr */,
    0,
    Opcode_wur_threadptr_encode_fns, 0, 0 },
  { "addi", 36 /* xt_iclass_addi */,
    0,
    Opcode_addi_encode_fns, 0, 0 },
  { "addmi", 37 /* xt_iclass_addmi */,
    0,
    Opcode_addmi_encode_fns, 0, 0 },
  { "add", 38 /* xt_iclass_addsub */,
    0,
    Opcode_add_encode_fns, 0, 0 },
  { "sub", 38 /* xt_iclass_addsub */,
    0,
    Opcode_sub_encode_fns, 0, 0 },
  { "addx2", 38 /* xt_iclass_addsub */,
    0,
    Opcode_addx2_encode_fns, 0, 0 },
  { "addx4", 38 /* xt_iclass_addsub */,
    0,
    Opcode_addx4_encode_fns, 0, 0 },
  { "addx8", 38 /* xt_iclass_addsub */,
    0,
    Opcode_addx8_encode_fns, 0, 0 },
  { "subx2", 38 /* xt_iclass_addsub */,
    0,
    Opcode_subx2_encode_fns, 0, 0 },
  { "subx4", 38 /* xt_iclass_addsub */,
    0,
    Opcode_subx4_encode_fns, 0, 0 },
  { "subx8", 38 /* xt_iclass_addsub */,
    0,
    Opcode_subx8_encode_fns, 0, 0 },
  { "and", 39 /* xt_iclass_bit */,
    0,
    Opcode_and_encode_fns, 0, 0 },
  { "or", 39 /* xt_iclass_bit */,
    0,
    Opcode_or_encode_fns, 0, 0 },
  { "xor", 39 /* xt_iclass_bit */,
    0,
    Opcode_xor_encode_fns, 0, 0 },
  { "beqi", 40 /* xt_iclass_bsi8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_beqi_encode_fns, 0, 0 },
  { "bnei", 40 /* xt_iclass_bsi8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnei_encode_fns, 0, 0 },
  { "bgei", 40 /* xt_iclass_bsi8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bgei_encode_fns, 0, 0 },
  { "blti", 40 /* xt_iclass_bsi8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_blti_encode_fns, 0, 0 },
  { "bbci", 41 /* xt_iclass_bsi8b */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bbci_encode_fns, 0, 0 },
  { "bbsi", 41 /* xt_iclass_bsi8b */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bbsi_encode_fns, 0, 0 },
  { "bgeui", 42 /* xt_iclass_bsi8u */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bgeui_encode_fns, 0, 0 },
  { "bltui", 42 /* xt_iclass_bsi8u */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bltui_encode_fns, 0, 0 },
  { "beq", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_beq_encode_fns, 0, 0 },
  { "bne", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bne_encode_fns, 0, 0 },
  { "bge", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bge_encode_fns, 0, 0 },
  { "blt", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_blt_encode_fns, 0, 0 },
  { "bgeu", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bgeu_encode_fns, 0, 0 },
  { "bltu", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bltu_encode_fns, 0, 0 },
  { "bany", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bany_encode_fns, 0, 0 },
  { "bnone", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnone_encode_fns, 0, 0 },
  { "ball", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_ball_encode_fns, 0, 0 },
  { "bnall", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnall_encode_fns, 0, 0 },
  { "bbc", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bbc_encode_fns, 0, 0 },
  { "bbs", 43 /* xt_iclass_bst8 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bbs_encode_fns, 0, 0 },
  { "beqz", 44 /* xt_iclass_bsz12 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_beqz_encode_fns, 0, 0 },
  { "bnez", 44 /* xt_iclass_bsz12 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnez_encode_fns, 0, 0 },
  { "bgez", 44 /* xt_iclass_bsz12 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bgez_encode_fns, 0, 0 },
  { "bltz", 44 /* xt_iclass_bsz12 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bltz_encode_fns, 0, 0 },
  { "call0", 45 /* xt_iclass_call0 */,
    XTENSA_OPCODE_IS_CALL,
    Opcode_call0_encode_fns, 0, 0 },
  { "callx0", 46 /* xt_iclass_callx0 */,
    XTENSA_OPCODE_IS_CALL,
    Opcode_callx0_encode_fns, 0, 0 },
  { "extui", 47 /* xt_iclass_exti */,
    0,
    Opcode_extui_encode_fns, 0, 0 },
  { "ill", 48 /* xt_iclass_ill */,
    0,
    Opcode_ill_encode_fns, 0, 0 },
  { "j", 49 /* xt_iclass_jump */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_j_encode_fns, 0, 0 },
  { "jx", 50 /* xt_iclass_jumpx */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_jx_encode_fns, 0, 0 },
  { "l16ui", 51 /* xt_iclass_l16ui */,
    0,
    Opcode_l16ui_encode_fns, 0, 0 },
  { "l16si", 52 /* xt_iclass_l16si */,
    0,
    Opcode_l16si_encode_fns, 0, 0 },
  { "l32i", 53 /* xt_iclass_l32i */,
    0,
    Opcode_l32i_encode_fns, 0, 0 },
  { "l32r", 54 /* xt_iclass_l32r */,
    0,
    Opcode_l32r_encode_fns, 0, 0 },
  { "l8ui", 55 /* xt_iclass_l8i */,
    0,
    Opcode_l8ui_encode_fns, 0, 0 },
  { "loop", 56 /* xt_iclass_loop */,
    XTENSA_OPCODE_IS_LOOP,
    Opcode_loop_encode_fns, 0, 0 },
  { "loopnez", 57 /* xt_iclass_loopz */,
    XTENSA_OPCODE_IS_LOOP,
    Opcode_loopnez_encode_fns, 0, 0 },
  { "loopgtz", 57 /* xt_iclass_loopz */,
    XTENSA_OPCODE_IS_LOOP,
    Opcode_loopgtz_encode_fns, 0, 0 },
  { "movi", 58 /* xt_iclass_movi */,
    0,
    Opcode_movi_encode_fns, 0, 0 },
  { "moveqz", 59 /* xt_iclass_movz */,
    0,
    Opcode_moveqz_encode_fns, 0, 0 },
  { "movnez", 59 /* xt_iclass_movz */,
    0,
    Opcode_movnez_encode_fns, 0, 0 },
  { "movltz", 59 /* xt_iclass_movz */,
    0,
    Opcode_movltz_encode_fns, 0, 0 },
  { "movgez", 59 /* xt_iclass_movz */,
    0,
    Opcode_movgez_encode_fns, 0, 0 },
  { "neg", 60 /* xt_iclass_neg */,
    0,
    Opcode_neg_encode_fns, 0, 0 },
  { "abs", 60 /* xt_iclass_neg */,
    0,
    Opcode_abs_encode_fns, 0, 0 },
  { "nop", 61 /* xt_iclass_nop */,
    0,
    Opcode_nop_encode_fns, 0, 0 },
  { "ret", 62 /* xt_iclass_return */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_ret_encode_fns, 0, 0 },
  { "s16i", 63 /* xt_iclass_s16i */,
    0,
    Opcode_s16i_encode_fns, 0, 0 },
  { "s32i", 64 /* xt_iclass_s32i */,
    0,
    Opcode_s32i_encode_fns, 0, 0 },
  { "s8i", 65 /* xt_iclass_s8i */,
    0,
    Opcode_s8i_encode_fns, 0, 0 },
  { "ssr", 66 /* xt_iclass_sar */,
    0,
    Opcode_ssr_encode_fns, 0, 0 },
  { "ssl", 66 /* xt_iclass_sar */,
    0,
    Opcode_ssl_encode_fns, 0, 0 },
  { "ssa8l", 66 /* xt_iclass_sar */,
    0,
    Opcode_ssa8l_encode_fns, 0, 0 },
  { "ssa8b", 66 /* xt_iclass_sar */,
    0,
    Opcode_ssa8b_encode_fns, 0, 0 },
  { "ssai", 67 /* xt_iclass_sari */,
    0,
    Opcode_ssai_encode_fns, 0, 0 },
  { "sll", 68 /* xt_iclass_shifts */,
    0,
    Opcode_sll_encode_fns, 0, 0 },
  { "src", 69 /* xt_iclass_shiftst */,
    0,
    Opcode_src_encode_fns, 0, 0 },
  { "srl", 70 /* xt_iclass_shiftt */,
    0,
    Opcode_srl_encode_fns, 0, 0 },
  { "sra", 70 /* xt_iclass_shiftt */,
    0,
    Opcode_sra_encode_fns, 0, 0 },
  { "slli", 71 /* xt_iclass_slli */,
    0,
    Opcode_slli_encode_fns, 0, 0 },
  { "srai", 72 /* xt_iclass_srai */,
    0,
    Opcode_srai_encode_fns, 0, 0 },
  { "srli", 73 /* xt_iclass_srli */,
    0,
    Opcode_srli_encode_fns, 0, 0 },
  { "memw", 74 /* xt_iclass_memw */,
    0,
    Opcode_memw_encode_fns, 0, 0 },
  { "extw", 75 /* xt_iclass_extw */,
    0,
    Opcode_extw_encode_fns, 0, 0 },
  { "isync", 76 /* xt_iclass_isync */,
    0,
    Opcode_isync_encode_fns, 0, 0 },
  { "rsync", 77 /* xt_iclass_sync */,
    0,
    Opcode_rsync_encode_fns, 0, 0 },
  { "esync", 77 /* xt_iclass_sync */,
    0,
    Opcode_esync_encode_fns, 0, 0 },
  { "dsync", 77 /* xt_iclass_sync */,
    0,
    Opcode_dsync_encode_fns, 0, 0 },
  { "rsil", 78 /* xt_iclass_rsil */,
    0,
    Opcode_rsil_encode_fns, 0, 0 },
  { "rsr.lend", 79 /* xt_iclass_rsr.lend */,
    0,
    Opcode_rsr_lend_encode_fns, 0, 0 },
  { "wsr.lend", 80 /* xt_iclass_wsr.lend */,
    0,
    Opcode_wsr_lend_encode_fns, 0, 0 },
  { "xsr.lend", 81 /* xt_iclass_xsr.lend */,
    0,
    Opcode_xsr_lend_encode_fns, 0, 0 },
  { "rsr.lcount", 82 /* xt_iclass_rsr.lcount */,
    0,
    Opcode_rsr_lcount_encode_fns, 0, 0 },
  { "wsr.lcount", 83 /* xt_iclass_wsr.lcount */,
    0,
    Opcode_wsr_lcount_encode_fns, 0, 0 },
  { "xsr.lcount", 84 /* xt_iclass_xsr.lcount */,
    0,
    Opcode_xsr_lcount_encode_fns, 0, 0 },
  { "rsr.lbeg", 85 /* xt_iclass_rsr.lbeg */,
    0,
    Opcode_rsr_lbeg_encode_fns, 0, 0 },
  { "wsr.lbeg", 86 /* xt_iclass_wsr.lbeg */,
    0,
    Opcode_wsr_lbeg_encode_fns, 0, 0 },
  { "xsr.lbeg", 87 /* xt_iclass_xsr.lbeg */,
    0,
    Opcode_xsr_lbeg_encode_fns, 0, 0 },
  { "rsr.sar", 88 /* xt_iclass_rsr.sar */,
    0,
    Opcode_rsr_sar_encode_fns, 0, 0 },
  { "wsr.sar", 89 /* xt_iclass_wsr.sar */,
    0,
    Opcode_wsr_sar_encode_fns, 0, 0 },
  { "xsr.sar", 90 /* xt_iclass_xsr.sar */,
    0,
    Opcode_xsr_sar_encode_fns, 0, 0 },
  { "rsr.litbase", 91 /* xt_iclass_rsr.litbase */,
    0,
    Opcode_rsr_litbase_encode_fns, 0, 0 },
  { "wsr.litbase", 92 /* xt_iclass_wsr.litbase */,
    0,
    Opcode_wsr_litbase_encode_fns, 0, 0 },
  { "xsr.litbase", 93 /* xt_iclass_xsr.litbase */,
    0,
    Opcode_xsr_litbase_encode_fns, 0, 0 },
  { "rsr.176", 94 /* xt_iclass_rsr.176 */,
    0,
    Opcode_rsr_176_encode_fns, 0, 0 },
  { "rsr.208", 95 /* xt_iclass_rsr.208 */,
    0,
    Opcode_rsr_208_encode_fns, 0, 0 },
  { "rsr.ps", 96 /* xt_iclass_rsr.ps */,
    0,
    Opcode_rsr_ps_encode_fns, 0, 0 },
  { "wsr.ps", 97 /* xt_iclass_wsr.ps */,
    0,
    Opcode_wsr_ps_encode_fns, 0, 0 },
  { "xsr.ps", 98 /* xt_iclass_xsr.ps */,
    0,
    Opcode_xsr_ps_encode_fns, 0, 0 },
  { "rsr.epc1", 99 /* xt_iclass_rsr.epc1 */,
    0,
    Opcode_rsr_epc1_encode_fns, 0, 0 },
  { "wsr.epc1", 100 /* xt_iclass_wsr.epc1 */,
    0,
    Opcode_wsr_epc1_encode_fns, 0, 0 },
  { "xsr.epc1", 101 /* xt_iclass_xsr.epc1 */,
    0,
    Opcode_xsr_epc1_encode_fns, 0, 0 },
  { "rsr.excsave1", 102 /* xt_iclass_rsr.excsave1 */,
    0,
    Opcode_rsr_excsave1_encode_fns, 0, 0 },
  { "wsr.excsave1", 103 /* xt_iclass_wsr.excsave1 */,
    0,
    Opcode_wsr_excsave1_encode_fns, 0, 0 },
  { "xsr.excsave1", 104 /* xt_iclass_xsr.excsave1 */,
    0,
    Opcode_xsr_excsave1_encode_fns, 0, 0 },
  { "rsr.epc2", 105 /* xt_iclass_rsr.epc2 */,
    0,
    Opcode_rsr_epc2_encode_fns, 0, 0 },
  { "wsr.epc2", 106 /* xt_iclass_wsr.epc2 */,
    0,
    Opcode_wsr_epc2_encode_fns, 0, 0 },
  { "xsr.epc2", 107 /* xt_iclass_xsr.epc2 */,
    0,
    Opcode_xsr_epc2_encode_fns, 0, 0 },
  { "rsr.excsave2", 108 /* xt_iclass_rsr.excsave2 */,
    0,
    Opcode_rsr_excsave2_encode_fns, 0, 0 },
  { "wsr.excsave2", 109 /* xt_iclass_wsr.excsave2 */,
    0,
    Opcode_wsr_excsave2_encode_fns, 0, 0 },
  { "xsr.excsave2", 110 /* xt_iclass_xsr.excsave2 */,
    0,
    Opcode_xsr_excsave2_encode_fns, 0, 0 },
  { "rsr.epc3", 111 /* xt_iclass_rsr.epc3 */,
    0,
    Opcode_rsr_epc3_encode_fns, 0, 0 },
  { "wsr.epc3", 112 /* xt_iclass_wsr.epc3 */,
    0,
    Opcode_wsr_epc3_encode_fns, 0, 0 },
  { "xsr.epc3", 113 /* xt_iclass_xsr.epc3 */,
    0,
    Opcode_xsr_epc3_encode_fns, 0, 0 },
  { "rsr.excsave3", 114 /* xt_iclass_rsr.excsave3 */,
    0,
    Opcode_rsr_excsave3_encode_fns, 0, 0 },
  { "wsr.excsave3", 115 /* xt_iclass_wsr.excsave3 */,
    0,
    Opcode_wsr_excsave3_encode_fns, 0, 0 },
  { "xsr.excsave3", 116 /* xt_iclass_xsr.excsave3 */,
    0,
    Opcode_xsr_excsave3_encode_fns, 0, 0 },
  { "rsr.epc4", 117 /* xt_iclass_rsr.epc4 */,
    0,
    Opcode_rsr_epc4_encode_fns, 0, 0 },
  { "wsr.epc4", 118 /* xt_iclass_wsr.epc4 */,
    0,
    Opcode_wsr_epc4_encode_fns, 0, 0 },
  { "xsr.epc4", 119 /* xt_iclass_xsr.epc4 */,
    0,
    Opcode_xsr_epc4_encode_fns, 0, 0 },
  { "rsr.excsave4", 120 /* xt_iclass_rsr.excsave4 */,
    0,
    Opcode_rsr_excsave4_encode_fns, 0, 0 },
  { "wsr.excsave4", 121 /* xt_iclass_wsr.excsave4 */,
    0,
    Opcode_wsr_excsave4_encode_fns, 0, 0 },
  { "xsr.excsave4", 122 /* xt_iclass_xsr.excsave4 */,
    0,
    Opcode_xsr_excsave4_encode_fns, 0, 0 },
  { "rsr.epc5", 123 /* xt_iclass_rsr.epc5 */,
    0,
    Opcode_rsr_epc5_encode_fns, 0, 0 },
  { "wsr.epc5", 124 /* xt_iclass_wsr.epc5 */,
    0,
    Opcode_wsr_epc5_encode_fns, 0, 0 },
  { "xsr.epc5", 125 /* xt_iclass_xsr.epc5 */,
    0,
    Opcode_xsr_epc5_encode_fns, 0, 0 },
  { "rsr.excsave5", 126 /* xt_iclass_rsr.excsave5 */,
    0,
    Opcode_rsr_excsave5_encode_fns, 0, 0 },
  { "wsr.excsave5", 127 /* xt_iclass_wsr.excsave5 */,
    0,
    Opcode_wsr_excsave5_encode_fns, 0, 0 },
  { "xsr.excsave5", 128 /* xt_iclass_xsr.excsave5 */,
    0,
    Opcode_xsr_excsave5_encode_fns, 0, 0 },
  { "rsr.epc6", 129 /* xt_iclass_rsr.epc6 */,
    0,
    Opcode_rsr_epc6_encode_fns, 0, 0 },
  { "wsr.epc6", 130 /* xt_iclass_wsr.epc6 */,
    0,
    Opcode_wsr_epc6_encode_fns, 0, 0 },
  { "xsr.epc6", 131 /* xt_iclass_xsr.epc6 */,
    0,
    Opcode_xsr_epc6_encode_fns, 0, 0 },
  { "rsr.excsave6", 132 /* xt_iclass_rsr.excsave6 */,
    0,
    Opcode_rsr_excsave6_encode_fns, 0, 0 },
  { "wsr.excsave6", 133 /* xt_iclass_wsr.excsave6 */,
    0,
    Opcode_wsr_excsave6_encode_fns, 0, 0 },
  { "xsr.excsave6", 134 /* xt_iclass_xsr.excsave6 */,
    0,
    Opcode_xsr_excsave6_encode_fns, 0, 0 },
  { "rsr.epc7", 135 /* xt_iclass_rsr.epc7 */,
    0,
    Opcode_rsr_epc7_encode_fns, 0, 0 },
  { "wsr.epc7", 136 /* xt_iclass_wsr.epc7 */,
    0,
    Opcode_wsr_epc7_encode_fns, 0, 0 },
  { "xsr.epc7", 137 /* xt_iclass_xsr.epc7 */,
    0,
    Opcode_xsr_epc7_encode_fns, 0, 0 },
  { "rsr.excsave7", 138 /* xt_iclass_rsr.excsave7 */,
    0,
    Opcode_rsr_excsave7_encode_fns, 0, 0 },
  { "wsr.excsave7", 139 /* xt_iclass_wsr.excsave7 */,
    0,
    Opcode_wsr_excsave7_encode_fns, 0, 0 },
  { "xsr.excsave7", 140 /* xt_iclass_xsr.excsave7 */,
    0,
    Opcode_xsr_excsave7_encode_fns, 0, 0 },
  { "rsr.eps2", 141 /* xt_iclass_rsr.eps2 */,
    0,
    Opcode_rsr_eps2_encode_fns, 0, 0 },
  { "wsr.eps2", 142 /* xt_iclass_wsr.eps2 */,
    0,
    Opcode_wsr_eps2_encode_fns, 0, 0 },
  { "xsr.eps2", 143 /* xt_iclass_xsr.eps2 */,
    0,
    Opcode_xsr_eps2_encode_fns, 0, 0 },
  { "rsr.eps3", 144 /* xt_iclass_rsr.eps3 */,
    0,
    Opcode_rsr_eps3_encode_fns, 0, 0 },
  { "wsr.eps3", 145 /* xt_iclass_wsr.eps3 */,
    0,
    Opcode_wsr_eps3_encode_fns, 0, 0 },
  { "xsr.eps3", 146 /* xt_iclass_xsr.eps3 */,
    0,
    Opcode_xsr_eps3_encode_fns, 0, 0 },
  { "rsr.eps4", 147 /* xt_iclass_rsr.eps4 */,
    0,
    Opcode_rsr_eps4_encode_fns, 0, 0 },
  { "wsr.eps4", 148 /* xt_iclass_wsr.eps4 */,
    0,
    Opcode_wsr_eps4_encode_fns, 0, 0 },
  { "xsr.eps4", 149 /* xt_iclass_xsr.eps4 */,
    0,
    Opcode_xsr_eps4_encode_fns, 0, 0 },
  { "rsr.eps5", 150 /* xt_iclass_rsr.eps5 */,
    0,
    Opcode_rsr_eps5_encode_fns, 0, 0 },
  { "wsr.eps5", 151 /* xt_iclass_wsr.eps5 */,
    0,
    Opcode_wsr_eps5_encode_fns, 0, 0 },
  { "xsr.eps5", 152 /* xt_iclass_xsr.eps5 */,
    0,
    Opcode_xsr_eps5_encode_fns, 0, 0 },
  { "rsr.eps6", 153 /* xt_iclass_rsr.eps6 */,
    0,
    Opcode_rsr_eps6_encode_fns, 0, 0 },
  { "wsr.eps6", 154 /* xt_iclass_wsr.eps6 */,
    0,
    Opcode_wsr_eps6_encode_fns, 0, 0 },
  { "xsr.eps6", 155 /* xt_iclass_xsr.eps6 */,
    0,
    Opcode_xsr_eps6_encode_fns, 0, 0 },
  { "rsr.eps7", 156 /* xt_iclass_rsr.eps7 */,
    0,
    Opcode_rsr_eps7_encode_fns, 0, 0 },
  { "wsr.eps7", 157 /* xt_iclass_wsr.eps7 */,
    0,
    Opcode_wsr_eps7_encode_fns, 0, 0 },
  { "xsr.eps7", 158 /* xt_iclass_xsr.eps7 */,
    0,
    Opcode_xsr_eps7_encode_fns, 0, 0 },
  { "rsr.excvaddr", 159 /* xt_iclass_rsr.excvaddr */,
    0,
    Opcode_rsr_excvaddr_encode_fns, 0, 0 },
  { "wsr.excvaddr", 160 /* xt_iclass_wsr.excvaddr */,
    0,
    Opcode_wsr_excvaddr_encode_fns, 0, 0 },
  { "xsr.excvaddr", 161 /* xt_iclass_xsr.excvaddr */,
    0,
    Opcode_xsr_excvaddr_encode_fns, 0, 0 },
  { "rsr.depc", 162 /* xt_iclass_rsr.depc */,
    0,
    Opcode_rsr_depc_encode_fns, 0, 0 },
  { "wsr.depc", 163 /* xt_iclass_wsr.depc */,
    0,
    Opcode_wsr_depc_encode_fns, 0, 0 },
  { "xsr.depc", 164 /* xt_iclass_xsr.depc */,
    0,
    Opcode_xsr_depc_encode_fns, 0, 0 },
  { "rsr.exccause", 165 /* xt_iclass_rsr.exccause */,
    0,
    Opcode_rsr_exccause_encode_fns, 0, 0 },
  { "wsr.exccause", 166 /* xt_iclass_wsr.exccause */,
    0,
    Opcode_wsr_exccause_encode_fns, 0, 0 },
  { "xsr.exccause", 167 /* xt_iclass_xsr.exccause */,
    0,
    Opcode_xsr_exccause_encode_fns, 0, 0 },
  { "rsr.misc0", 168 /* xt_iclass_rsr.misc0 */,
    0,
    Opcode_rsr_misc0_encode_fns, 0, 0 },
  { "wsr.misc0", 169 /* xt_iclass_wsr.misc0 */,
    0,
    Opcode_wsr_misc0_encode_fns, 0, 0 },
  { "xsr.misc0", 170 /* xt_iclass_xsr.misc0 */,
    0,
    Opcode_xsr_misc0_encode_fns, 0, 0 },
  { "rsr.misc1", 171 /* xt_iclass_rsr.misc1 */,
    0,
    Opcode_rsr_misc1_encode_fns, 0, 0 },
  { "wsr.misc1", 172 /* xt_iclass_wsr.misc1 */,
    0,
    Opcode_wsr_misc1_encode_fns, 0, 0 },
  { "xsr.misc1", 173 /* xt_iclass_xsr.misc1 */,
    0,
    Opcode_xsr_misc1_encode_fns, 0, 0 },
  { "rsr.misc2", 174 /* xt_iclass_rsr.misc2 */,
    0,
    Opcode_rsr_misc2_encode_fns, 0, 0 },
  { "wsr.misc2", 175 /* xt_iclass_wsr.misc2 */,
    0,
    Opcode_wsr_misc2_encode_fns, 0, 0 },
  { "xsr.misc2", 176 /* xt_iclass_xsr.misc2 */,
    0,
    Opcode_xsr_misc2_encode_fns, 0, 0 },
  { "rsr.misc3", 177 /* xt_iclass_rsr.misc3 */,
    0,
    Opcode_rsr_misc3_encode_fns, 0, 0 },
  { "wsr.misc3", 178 /* xt_iclass_wsr.misc3 */,
    0,
    Opcode_wsr_misc3_encode_fns, 0, 0 },
  { "xsr.misc3", 179 /* xt_iclass_xsr.misc3 */,
    0,
    Opcode_xsr_misc3_encode_fns, 0, 0 },
  { "rsr.prid", 180 /* xt_iclass_rsr.prid */,
    0,
    Opcode_rsr_prid_encode_fns, 0, 0 },
  { "rsr.vecbase", 181 /* xt_iclass_rsr.vecbase */,
    0,
    Opcode_rsr_vecbase_encode_fns, 0, 0 },
  { "wsr.vecbase", 182 /* xt_iclass_wsr.vecbase */,
    0,
    Opcode_wsr_vecbase_encode_fns, 0, 0 },
  { "xsr.vecbase", 183 /* xt_iclass_xsr.vecbase */,
    0,
    Opcode_xsr_vecbase_encode_fns, 0, 0 },
  { "mul.aa.ll", 184 /* xt_iclass_mac16_aa */,
    0,
    Opcode_mul_aa_ll_encode_fns, 0, 0 },
  { "mul.aa.hl", 184 /* xt_iclass_mac16_aa */,
    0,
    Opcode_mul_aa_hl_encode_fns, 0, 0 },
  { "mul.aa.lh", 184 /* xt_iclass_mac16_aa */,
    0,
    Opcode_mul_aa_lh_encode_fns, 0, 0 },
  { "mul.aa.hh", 184 /* xt_iclass_mac16_aa */,
    0,
    Opcode_mul_aa_hh_encode_fns, 0, 0 },
  { "umul.aa.ll", 184 /* xt_iclass_mac16_aa */,
    0,
    Opcode_umul_aa_ll_encode_fns, 0, 0 },
  { "umul.aa.hl", 184 /* xt_iclass_mac16_aa */,
    0,
    Opcode_umul_aa_hl_encode_fns, 0, 0 },
  { "umul.aa.lh", 184 /* xt_iclass_mac16_aa */,
    0,
    Opcode_umul_aa_lh_encode_fns, 0, 0 },
  { "umul.aa.hh", 184 /* xt_iclass_mac16_aa */,
    0,
    Opcode_umul_aa_hh_encode_fns, 0, 0 },
  { "mul.ad.ll", 185 /* xt_iclass_mac16_ad */,
    0,
    Opcode_mul_ad_ll_encode_fns, 0, 0 },
  { "mul.ad.hl", 185 /* xt_iclass_mac16_ad */,
    0,
    Opcode_mul_ad_hl_encode_fns, 0, 0 },
  { "mul.ad.lh", 185 /* xt_iclass_mac16_ad */,
    0,
    Opcode_mul_ad_lh_encode_fns, 0, 0 },
  { "mul.ad.hh", 185 /* xt_iclass_mac16_ad */,
    0,
    Opcode_mul_ad_hh_encode_fns, 0, 0 },
  { "mul.da.ll", 186 /* xt_iclass_mac16_da */,
    0,
    Opcode_mul_da_ll_encode_fns, 0, 0 },
  { "mul.da.hl", 186 /* xt_iclass_mac16_da */,
    0,
    Opcode_mul_da_hl_encode_fns, 0, 0 },
  { "mul.da.lh", 186 /* xt_iclass_mac16_da */,
    0,
    Opcode_mul_da_lh_encode_fns, 0, 0 },
  { "mul.da.hh", 186 /* xt_iclass_mac16_da */,
    0,
    Opcode_mul_da_hh_encode_fns, 0, 0 },
  { "mul.dd.ll", 187 /* xt_iclass_mac16_dd */,
    0,
    Opcode_mul_dd_ll_encode_fns, 0, 0 },
  { "mul.dd.hl", 187 /* xt_iclass_mac16_dd */,
    0,
    Opcode_mul_dd_hl_encode_fns, 0, 0 },
  { "mul.dd.lh", 187 /* xt_iclass_mac16_dd */,
    0,
    Opcode_mul_dd_lh_encode_fns, 0, 0 },
  { "mul.dd.hh", 187 /* xt_iclass_mac16_dd */,
    0,
    Opcode_mul_dd_hh_encode_fns, 0, 0 },
  { "mula.aa.ll", 188 /* xt_iclass_mac16a_aa */,
    0,
    Opcode_mula_aa_ll_encode_fns, 0, 0 },
  { "mula.aa.hl", 188 /* xt_iclass_mac16a_aa */,
    0,
    Opcode_mula_aa_hl_encode_fns, 0, 0 },
  { "mula.aa.lh", 188 /* xt_iclass_mac16a_aa */,
    0,
    Opcode_mula_aa_lh_encode_fns, 0, 0 },
  { "mula.aa.hh", 188 /* xt_iclass_mac16a_aa */,
    0,
    Opcode_mula_aa_hh_encode_fns, 0, 0 },
  { "muls.aa.ll", 188 /* xt_iclass_mac16a_aa */,
    0,
    Opcode_muls_aa_ll_encode_fns, 0, 0 },
  { "muls.aa.hl", 188 /* xt_iclass_mac16a_aa */,
    0,
    Opcode_muls_aa_hl_encode_fns, 0, 0 },
  { "muls.aa.lh", 188 /* xt_iclass_mac16a_aa */,
    0,
    Opcode_muls_aa_lh_encode_fns, 0, 0 },
  { "muls.aa.hh", 188 /* xt_iclass_mac16a_aa */,
    0,
    Opcode_muls_aa_hh_encode_fns, 0, 0 },
  { "mula.ad.ll", 189 /* xt_iclass_mac16a_ad */,
    0,
    Opcode_mula_ad_ll_encode_fns, 0, 0 },
  { "mula.ad.hl", 189 /* xt_iclass_mac16a_ad */,
    0,
    Opcode_mula_ad_hl_encode_fns, 0, 0 },
  { "mula.ad.lh", 189 /* xt_iclass_mac16a_ad */,
    0,
    Opcode_mula_ad_lh_encode_fns, 0, 0 },
  { "mula.ad.hh", 189 /* xt_iclass_mac16a_ad */,
    0,
    Opcode_mula_ad_hh_encode_fns, 0, 0 },
  { "muls.ad.ll", 189 /* xt_iclass_mac16a_ad */,
    0,
    Opcode_muls_ad_ll_encode_fns, 0, 0 },
  { "muls.ad.hl", 189 /* xt_iclass_mac16a_ad */,
    0,
    Opcode_muls_ad_hl_encode_fns, 0, 0 },
  { "muls.ad.lh", 189 /* xt_iclass_mac16a_ad */,
    0,
    Opcode_muls_ad_lh_encode_fns, 0, 0 },
  { "muls.ad.hh", 189 /* xt_iclass_mac16a_ad */,
    0,
    Opcode_muls_ad_hh_encode_fns, 0, 0 },
  { "mula.da.ll", 190 /* xt_iclass_mac16a_da */,
    0,
    Opcode_mula_da_ll_encode_fns, 0, 0 },
  { "mula.da.hl", 190 /* xt_iclass_mac16a_da */,
    0,
    Opcode_mula_da_hl_encode_fns, 0, 0 },
  { "mula.da.lh", 190 /* xt_iclass_mac16a_da */,
    0,
    Opcode_mula_da_lh_encode_fns, 0, 0 },
  { "mula.da.hh", 190 /* xt_iclass_mac16a_da */,
    0,
    Opcode_mula_da_hh_encode_fns, 0, 0 },
  { "muls.da.ll", 190 /* xt_iclass_mac16a_da */,
    0,
    Opcode_muls_da_ll_encode_fns, 0, 0 },
  { "muls.da.hl", 190 /* xt_iclass_mac16a_da */,
    0,
    Opcode_muls_da_hl_encode_fns, 0, 0 },
  { "muls.da.lh", 190 /* xt_iclass_mac16a_da */,
    0,
    Opcode_muls_da_lh_encode_fns, 0, 0 },
  { "muls.da.hh", 190 /* xt_iclass_mac16a_da */,
    0,
    Opcode_muls_da_hh_encode_fns, 0, 0 },
  { "mula.dd.ll", 191 /* xt_iclass_mac16a_dd */,
    0,
    Opcode_mula_dd_ll_encode_fns, 0, 0 },
  { "mula.dd.hl", 191 /* xt_iclass_mac16a_dd */,
    0,
    Opcode_mula_dd_hl_encode_fns, 0, 0 },
  { "mula.dd.lh", 191 /* xt_iclass_mac16a_dd */,
    0,
    Opcode_mula_dd_lh_encode_fns, 0, 0 },
  { "mula.dd.hh", 191 /* xt_iclass_mac16a_dd */,
    0,
    Opcode_mula_dd_hh_encode_fns, 0, 0 },
  { "muls.dd.ll", 191 /* xt_iclass_mac16a_dd */,
    0,
    Opcode_muls_dd_ll_encode_fns, 0, 0 },
  { "muls.dd.hl", 191 /* xt_iclass_mac16a_dd */,
    0,
    Opcode_muls_dd_hl_encode_fns, 0, 0 },
  { "muls.dd.lh", 191 /* xt_iclass_mac16a_dd */,
    0,
    Opcode_muls_dd_lh_encode_fns, 0, 0 },
  { "muls.dd.hh", 191 /* xt_iclass_mac16a_dd */,
    0,
    Opcode_muls_dd_hh_encode_fns, 0, 0 },
  { "mula.da.ll.lddec", 192 /* xt_iclass_mac16al_da */,
    0,
    Opcode_mula_da_ll_lddec_encode_fns, 0, 0 },
  { "mula.da.ll.ldinc", 192 /* xt_iclass_mac16al_da */,
    0,
    Opcode_mula_da_ll_ldinc_encode_fns, 0, 0 },
  { "mula.da.hl.lddec", 192 /* xt_iclass_mac16al_da */,
    0,
    Opcode_mula_da_hl_lddec_encode_fns, 0, 0 },
  { "mula.da.hl.ldinc", 192 /* xt_iclass_mac16al_da */,
    0,
    Opcode_mula_da_hl_ldinc_encode_fns, 0, 0 },
  { "mula.da.lh.lddec", 192 /* xt_iclass_mac16al_da */,
    0,
    Opcode_mula_da_lh_lddec_encode_fns, 0, 0 },
  { "mula.da.lh.ldinc", 192 /* xt_iclass_mac16al_da */,
    0,
    Opcode_mula_da_lh_ldinc_encode_fns, 0, 0 },
  { "mula.da.hh.lddec", 192 /* xt_iclass_mac16al_da */,
    0,
    Opcode_mula_da_hh_lddec_encode_fns, 0, 0 },
  { "mula.da.hh.ldinc", 192 /* xt_iclass_mac16al_da */,
    0,
    Opcode_mula_da_hh_ldinc_encode_fns, 0, 0 },
  { "mula.dd.ll.lddec", 193 /* xt_iclass_mac16al_dd */,
    0,
    Opcode_mula_dd_ll_lddec_encode_fns, 0, 0 },
  { "mula.dd.ll.ldinc", 193 /* xt_iclass_mac16al_dd */,
    0,
    Opcode_mula_dd_ll_ldinc_encode_fns, 0, 0 },
  { "mula.dd.hl.lddec", 193 /* xt_iclass_mac16al_dd */,
    0,
    Opcode_mula_dd_hl_lddec_encode_fns, 0, 0 },
  { "mula.dd.hl.ldinc", 193 /* xt_iclass_mac16al_dd */,
    0,
    Opcode_mula_dd_hl_ldinc_encode_fns, 0, 0 },
  { "mula.dd.lh.lddec", 193 /* xt_iclass_mac16al_dd */,
    0,
    Opcode_mula_dd_lh_lddec_encode_fns, 0, 0 },
  { "mula.dd.lh.ldinc", 193 /* xt_iclass_mac16al_dd */,
    0,
    Opcode_mula_dd_lh_ldinc_encode_fns, 0, 0 },
  { "mula.dd.hh.lddec", 193 /* xt_iclass_mac16al_dd */,
    0,
    Opcode_mula_dd_hh_lddec_encode_fns, 0, 0 },
  { "mula.dd.hh.ldinc", 193 /* xt_iclass_mac16al_dd */,
    0,
    Opcode_mula_dd_hh_ldinc_encode_fns, 0, 0 },
  { "lddec", 194 /* xt_iclass_mac16_l */,
    0,
    Opcode_lddec_encode_fns, 0, 0 },
  { "ldinc", 194 /* xt_iclass_mac16_l */,
    0,
    Opcode_ldinc_encode_fns, 0, 0 },
  { "mul16u", 195 /* xt_iclass_mul16 */,
    0,
    Opcode_mul16u_encode_fns, 0, 0 },
  { "mul16s", 195 /* xt_iclass_mul16 */,
    0,
    Opcode_mul16s_encode_fns, 0, 0 },
  { "rsr.m0", 196 /* xt_iclass_rsr.m0 */,
    0,
    Opcode_rsr_m0_encode_fns, 0, 0 },
  { "wsr.m0", 197 /* xt_iclass_wsr.m0 */,
    0,
    Opcode_wsr_m0_encode_fns, 0, 0 },
  { "xsr.m0", 198 /* xt_iclass_xsr.m0 */,
    0,
    Opcode_xsr_m0_encode_fns, 0, 0 },
  { "rsr.m1", 199 /* xt_iclass_rsr.m1 */,
    0,
    Opcode_rsr_m1_encode_fns, 0, 0 },
  { "wsr.m1", 200 /* xt_iclass_wsr.m1 */,
    0,
    Opcode_wsr_m1_encode_fns, 0, 0 },
  { "xsr.m1", 201 /* xt_iclass_xsr.m1 */,
    0,
    Opcode_xsr_m1_encode_fns, 0, 0 },
  { "rsr.m2", 202 /* xt_iclass_rsr.m2 */,
    0,
    Opcode_rsr_m2_encode_fns, 0, 0 },
  { "wsr.m2", 203 /* xt_iclass_wsr.m2 */,
    0,
    Opcode_wsr_m2_encode_fns, 0, 0 },
  { "xsr.m2", 204 /* xt_iclass_xsr.m2 */,
    0,
    Opcode_xsr_m2_encode_fns, 0, 0 },
  { "rsr.m3", 205 /* xt_iclass_rsr.m3 */,
    0,
    Opcode_rsr_m3_encode_fns, 0, 0 },
  { "wsr.m3", 206 /* xt_iclass_wsr.m3 */,
    0,
    Opcode_wsr_m3_encode_fns, 0, 0 },
  { "xsr.m3", 207 /* xt_iclass_xsr.m3 */,
    0,
    Opcode_xsr_m3_encode_fns, 0, 0 },
  { "rsr.acclo", 208 /* xt_iclass_rsr.acclo */,
    0,
    Opcode_rsr_acclo_encode_fns, 0, 0 },
  { "wsr.acclo", 209 /* xt_iclass_wsr.acclo */,
    0,
    Opcode_wsr_acclo_encode_fns, 0, 0 },
  { "xsr.acclo", 210 /* xt_iclass_xsr.acclo */,
    0,
    Opcode_xsr_acclo_encode_fns, 0, 0 },
  { "rsr.acchi", 211 /* xt_iclass_rsr.acchi */,
    0,
    Opcode_rsr_acchi_encode_fns, 0, 0 },
  { "wsr.acchi", 212 /* xt_iclass_wsr.acchi */,
    0,
    Opcode_wsr_acchi_encode_fns, 0, 0 },
  { "xsr.acchi", 213 /* xt_iclass_xsr.acchi */,
    0,
    Opcode_xsr_acchi_encode_fns, 0, 0 },
  { "rfi", 214 /* xt_iclass_rfi */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_rfi_encode_fns, 0, 0 },
  { "waiti", 215 /* xt_iclass_wait */,
    0,
    Opcode_waiti_encode_fns, 0, 0 },
  { "rsr.interrupt", 216 /* xt_iclass_rsr.interrupt */,
    0,
    Opcode_rsr_interrupt_encode_fns, 0, 0 },
  { "wsr.intset", 217 /* xt_iclass_wsr.intset */,
    0,
    Opcode_wsr_intset_encode_fns, 0, 0 },
  { "wsr.intclear", 218 /* xt_iclass_wsr.intclear */,
    0,
    Opcode_wsr_intclear_encode_fns, 0, 0 },
  { "rsr.intenable", 219 /* xt_iclass_rsr.intenable */,
    0,
    Opcode_rsr_intenable_encode_fns, 0, 0 },
  { "wsr.intenable", 220 /* xt_iclass_wsr.intenable */,
    0,
    Opcode_wsr_intenable_encode_fns, 0, 0 },
  { "xsr.intenable", 221 /* xt_iclass_xsr.intenable */,
    0,
    Opcode_xsr_intenable_encode_fns, 0, 0 },
  { "break", 222 /* xt_iclass_break */,
    0,
    Opcode_break_encode_fns, 0, 0 },
  { "break.n", 223 /* xt_iclass_break.n */,
    0,
    Opcode_break_n_encode_fns, 0, 0 },
  { "rsr.dbreaka0", 224 /* xt_iclass_rsr.dbreaka0 */,
    0,
    Opcode_rsr_dbreaka0_encode_fns, 0, 0 },
  { "wsr.dbreaka0", 225 /* xt_iclass_wsr.dbreaka0 */,
    0,
    Opcode_wsr_dbreaka0_encode_fns, 0, 0 },
  { "xsr.dbreaka0", 226 /* xt_iclass_xsr.dbreaka0 */,
    0,
    Opcode_xsr_dbreaka0_encode_fns, 0, 0 },
  { "rsr.dbreakc0", 227 /* xt_iclass_rsr.dbreakc0 */,
    0,
    Opcode_rsr_dbreakc0_encode_fns, 0, 0 },
  { "wsr.dbreakc0", 228 /* xt_iclass_wsr.dbreakc0 */,
    0,
    Opcode_wsr_dbreakc0_encode_fns, 0, 0 },
  { "xsr.dbreakc0", 229 /* xt_iclass_xsr.dbreakc0 */,
    0,
    Opcode_xsr_dbreakc0_encode_fns, 0, 0 },
  { "rsr.dbreaka1", 230 /* xt_iclass_rsr.dbreaka1 */,
    0,
    Opcode_rsr_dbreaka1_encode_fns, 0, 0 },
  { "wsr.dbreaka1", 231 /* xt_iclass_wsr.dbreaka1 */,
    0,
    Opcode_wsr_dbreaka1_encode_fns, 0, 0 },
  { "xsr.dbreaka1", 232 /* xt_iclass_xsr.dbreaka1 */,
    0,
    Opcode_xsr_dbreaka1_encode_fns, 0, 0 },
  { "rsr.dbreakc1", 233 /* xt_iclass_rsr.dbreakc1 */,
    0,
    Opcode_rsr_dbreakc1_encode_fns, 0, 0 },
  { "wsr.dbreakc1", 234 /* xt_iclass_wsr.dbreakc1 */,
    0,
    Opcode_wsr_dbreakc1_encode_fns, 0, 0 },
  { "xsr.dbreakc1", 235 /* xt_iclass_xsr.dbreakc1 */,
    0,
    Opcode_xsr_dbreakc1_encode_fns, 0, 0 },
  { "rsr.ibreaka0", 236 /* xt_iclass_rsr.ibreaka0 */,
    0,
    Opcode_rsr_ibreaka0_encode_fns, 0, 0 },
  { "wsr.ibreaka0", 237 /* xt_iclass_wsr.ibreaka0 */,
    0,
    Opcode_wsr_ibreaka0_encode_fns, 0, 0 },
  { "xsr.ibreaka0", 238 /* xt_iclass_xsr.ibreaka0 */,
    0,
    Opcode_xsr_ibreaka0_encode_fns, 0, 0 },
  { "rsr.ibreaka1", 239 /* xt_iclass_rsr.ibreaka1 */,
    0,
    Opcode_rsr_ibreaka1_encode_fns, 0, 0 },
  { "wsr.ibreaka1", 240 /* xt_iclass_wsr.ibreaka1 */,
    0,
    Opcode_wsr_ibreaka1_encode_fns, 0, 0 },
  { "xsr.ibreaka1", 241 /* xt_iclass_xsr.ibreaka1 */,
    0,
    Opcode_xsr_ibreaka1_encode_fns, 0, 0 },
  { "rsr.ibreakenable", 242 /* xt_iclass_rsr.ibreakenable */,
    0,
    Opcode_rsr_ibreakenable_encode_fns, 0, 0 },
  { "wsr.ibreakenable", 243 /* xt_iclass_wsr.ibreakenable */,
    0,
    Opcode_wsr_ibreakenable_encode_fns, 0, 0 },
  { "xsr.ibreakenable", 244 /* xt_iclass_xsr.ibreakenable */,
    0,
    Opcode_xsr_ibreakenable_encode_fns, 0, 0 },
  { "rsr.debugcause", 245 /* xt_iclass_rsr.debugcause */,
    0,
    Opcode_rsr_debugcause_encode_fns, 0, 0 },
  { "wsr.debugcause", 246 /* xt_iclass_wsr.debugcause */,
    0,
    Opcode_wsr_debugcause_encode_fns, 0, 0 },
  { "xsr.debugcause", 247 /* xt_iclass_xsr.debugcause */,
    0,
    Opcode_xsr_debugcause_encode_fns, 0, 0 },
  { "rsr.icount", 248 /* xt_iclass_rsr.icount */,
    0,
    Opcode_rsr_icount_encode_fns, 0, 0 },
  { "wsr.icount", 249 /* xt_iclass_wsr.icount */,
    0,
    Opcode_wsr_icount_encode_fns, 0, 0 },
  { "xsr.icount", 250 /* xt_iclass_xsr.icount */,
    0,
    Opcode_xsr_icount_encode_fns, 0, 0 },
  { "rsr.icountlevel", 251 /* xt_iclass_rsr.icountlevel */,
    0,
    Opcode_rsr_icountlevel_encode_fns, 0, 0 },
  { "wsr.icountlevel", 252 /* xt_iclass_wsr.icountlevel */,
    0,
    Opcode_wsr_icountlevel_encode_fns, 0, 0 },
  { "xsr.icountlevel", 253 /* xt_iclass_xsr.icountlevel */,
    0,
    Opcode_xsr_icountlevel_encode_fns, 0, 0 },
  { "rsr.ddr", 254 /* xt_iclass_rsr.ddr */,
    0,
    Opcode_rsr_ddr_encode_fns, 0, 0 },
  { "wsr.ddr", 255 /* xt_iclass_wsr.ddr */,
    0,
    Opcode_wsr_ddr_encode_fns, 0, 0 },
  { "xsr.ddr", 256 /* xt_iclass_xsr.ddr */,
    0,
    Opcode_xsr_ddr_encode_fns, 0, 0 },
  { "rfdo", 257 /* xt_iclass_rfdo */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_rfdo_encode_fns, 0, 0 },
  { "rfdd", 258 /* xt_iclass_rfdd */,
    XTENSA_OPCODE_IS_JUMP,
    Opcode_rfdd_encode_fns, 0, 0 },
  { "wsr.mmid", 259 /* xt_iclass_wsr.mmid */,
    0,
    Opcode_wsr_mmid_encode_fns, 0, 0 },
  { "andb", 260 /* xt_iclass_bbool1 */,
    0,
    Opcode_andb_encode_fns, 0, 0 },
  { "andbc", 260 /* xt_iclass_bbool1 */,
    0,
    Opcode_andbc_encode_fns, 0, 0 },
  { "orb", 260 /* xt_iclass_bbool1 */,
    0,
    Opcode_orb_encode_fns, 0, 0 },
  { "orbc", 260 /* xt_iclass_bbool1 */,
    0,
    Opcode_orbc_encode_fns, 0, 0 },
  { "xorb", 260 /* xt_iclass_bbool1 */,
    0,
    Opcode_xorb_encode_fns, 0, 0 },
  { "any4", 261 /* xt_iclass_bbool4 */,
    0,
    Opcode_any4_encode_fns, 0, 0 },
  { "all4", 261 /* xt_iclass_bbool4 */,
    0,
    Opcode_all4_encode_fns, 0, 0 },
  { "any8", 262 /* xt_iclass_bbool8 */,
    0,
    Opcode_any8_encode_fns, 0, 0 },
  { "all8", 262 /* xt_iclass_bbool8 */,
    0,
    Opcode_all8_encode_fns, 0, 0 },
  { "bf", 263 /* xt_iclass_bbranch */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bf_encode_fns, 0, 0 },
  { "bt", 263 /* xt_iclass_bbranch */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bt_encode_fns, 0, 0 },
  { "movf", 264 /* xt_iclass_bmove */,
    0,
    Opcode_movf_encode_fns, 0, 0 },
  { "movt", 264 /* xt_iclass_bmove */,
    0,
    Opcode_movt_encode_fns, 0, 0 },
  { "rsr.br", 265 /* xt_iclass_RSR.BR */,
    0,
    Opcode_rsr_br_encode_fns, 0, 0 },
  { "wsr.br", 266 /* xt_iclass_WSR.BR */,
    0,
    Opcode_wsr_br_encode_fns, 0, 0 },
  { "xsr.br", 267 /* xt_iclass_XSR.BR */,
    0,
    Opcode_xsr_br_encode_fns, 0, 0 },
  { "rsr.ccount", 268 /* xt_iclass_rsr.ccount */,
    0,
    Opcode_rsr_ccount_encode_fns, 0, 0 },
  { "wsr.ccount", 269 /* xt_iclass_wsr.ccount */,
    0,
    Opcode_wsr_ccount_encode_fns, 0, 0 },
  { "xsr.ccount", 270 /* xt_iclass_xsr.ccount */,
    0,
    Opcode_xsr_ccount_encode_fns, 0, 0 },
  { "rsr.ccompare0", 271 /* xt_iclass_rsr.ccompare0 */,
    0,
    Opcode_rsr_ccompare0_encode_fns, 0, 0 },
  { "wsr.ccompare0", 272 /* xt_iclass_wsr.ccompare0 */,
    0,
    Opcode_wsr_ccompare0_encode_fns, 0, 0 },
  { "xsr.ccompare0", 273 /* xt_iclass_xsr.ccompare0 */,
    0,
    Opcode_xsr_ccompare0_encode_fns, 0, 0 },
  { "rsr.ccompare1", 274 /* xt_iclass_rsr.ccompare1 */,
    0,
    Opcode_rsr_ccompare1_encode_fns, 0, 0 },
  { "wsr.ccompare1", 275 /* xt_iclass_wsr.ccompare1 */,
    0,
    Opcode_wsr_ccompare1_encode_fns, 0, 0 },
  { "xsr.ccompare1", 276 /* xt_iclass_xsr.ccompare1 */,
    0,
    Opcode_xsr_ccompare1_encode_fns, 0, 0 },
  { "rsr.ccompare2", 277 /* xt_iclass_rsr.ccompare2 */,
    0,
    Opcode_rsr_ccompare2_encode_fns, 0, 0 },
  { "wsr.ccompare2", 278 /* xt_iclass_wsr.ccompare2 */,
    0,
    Opcode_wsr_ccompare2_encode_fns, 0, 0 },
  { "xsr.ccompare2", 279 /* xt_iclass_xsr.ccompare2 */,
    0,
    Opcode_xsr_ccompare2_encode_fns, 0, 0 },
  { "ipf", 280 /* xt_iclass_icache */,
    0,
    Opcode_ipf_encode_fns, 0, 0 },
  { "ihi", 280 /* xt_iclass_icache */,
    0,
    Opcode_ihi_encode_fns, 0, 0 },
  { "ipfl", 281 /* xt_iclass_icache_lock */,
    0,
    Opcode_ipfl_encode_fns, 0, 0 },
  { "ihu", 281 /* xt_iclass_icache_lock */,
    0,
    Opcode_ihu_encode_fns, 0, 0 },
  { "iiu", 281 /* xt_iclass_icache_lock */,
    0,
    Opcode_iiu_encode_fns, 0, 0 },
  { "iii", 282 /* xt_iclass_icache_inv */,
    0,
    Opcode_iii_encode_fns, 0, 0 },
  { "lict", 283 /* xt_iclass_licx */,
    0,
    Opcode_lict_encode_fns, 0, 0 },
  { "licw", 283 /* xt_iclass_licx */,
    0,
    Opcode_licw_encode_fns, 0, 0 },
  { "sict", 284 /* xt_iclass_sicx */,
    0,
    Opcode_sict_encode_fns, 0, 0 },
  { "sicw", 284 /* xt_iclass_sicx */,
    0,
    Opcode_sicw_encode_fns, 0, 0 },
  { "dhwb", 285 /* xt_iclass_dcache */,
    0,
    Opcode_dhwb_encode_fns, 0, 0 },
  { "dhwbi", 285 /* xt_iclass_dcache */,
    0,
    Opcode_dhwbi_encode_fns, 0, 0 },
  { "diwb", 286 /* xt_iclass_dcache_ind */,
    0,
    Opcode_diwb_encode_fns, 0, 0 },
  { "diwbi", 286 /* xt_iclass_dcache_ind */,
    0,
    Opcode_diwbi_encode_fns, 0, 0 },
  { "dhi", 287 /* xt_iclass_dcache_inv */,
    0,
    Opcode_dhi_encode_fns, 0, 0 },
  { "dii", 287 /* xt_iclass_dcache_inv */,
    0,
    Opcode_dii_encode_fns, 0, 0 },
  { "dpfr", 288 /* xt_iclass_dpf */,
    0,
    Opcode_dpfr_encode_fns, 0, 0 },
  { "dpfw", 288 /* xt_iclass_dpf */,
    0,
    Opcode_dpfw_encode_fns, 0, 0 },
  { "dpfro", 288 /* xt_iclass_dpf */,
    0,
    Opcode_dpfro_encode_fns, 0, 0 },
  { "dpfwo", 288 /* xt_iclass_dpf */,
    0,
    Opcode_dpfwo_encode_fns, 0, 0 },
  { "dpfl", 289 /* xt_iclass_dcache_lock */,
    0,
    Opcode_dpfl_encode_fns, 0, 0 },
  { "dhu", 289 /* xt_iclass_dcache_lock */,
    0,
    Opcode_dhu_encode_fns, 0, 0 },
  { "diu", 289 /* xt_iclass_dcache_lock */,
    0,
    Opcode_diu_encode_fns, 0, 0 },
  { "sdct", 290 /* xt_iclass_sdct */,
    0,
    Opcode_sdct_encode_fns, 0, 0 },
  { "ldct", 291 /* xt_iclass_ldct */,
    0,
    Opcode_ldct_encode_fns, 0, 0 },
  { "wsr.ptevaddr", 292 /* xt_iclass_wsr.ptevaddr */,
    0,
    Opcode_wsr_ptevaddr_encode_fns, 0, 0 },
  { "rsr.ptevaddr", 293 /* xt_iclass_rsr.ptevaddr */,
    0,
    Opcode_rsr_ptevaddr_encode_fns, 0, 0 },
  { "xsr.ptevaddr", 294 /* xt_iclass_xsr.ptevaddr */,
    0,
    Opcode_xsr_ptevaddr_encode_fns, 0, 0 },
  { "rsr.rasid", 295 /* xt_iclass_rsr.rasid */,
    0,
    Opcode_rsr_rasid_encode_fns, 0, 0 },
  { "wsr.rasid", 296 /* xt_iclass_wsr.rasid */,
    0,
    Opcode_wsr_rasid_encode_fns, 0, 0 },
  { "xsr.rasid", 297 /* xt_iclass_xsr.rasid */,
    0,
    Opcode_xsr_rasid_encode_fns, 0, 0 },
  { "rsr.itlbcfg", 298 /* xt_iclass_rsr.itlbcfg */,
    0,
    Opcode_rsr_itlbcfg_encode_fns, 0, 0 },
  { "wsr.itlbcfg", 299 /* xt_iclass_wsr.itlbcfg */,
    0,
    Opcode_wsr_itlbcfg_encode_fns, 0, 0 },
  { "xsr.itlbcfg", 300 /* xt_iclass_xsr.itlbcfg */,
    0,
    Opcode_xsr_itlbcfg_encode_fns, 0, 0 },
  { "rsr.dtlbcfg", 301 /* xt_iclass_rsr.dtlbcfg */,
    0,
    Opcode_rsr_dtlbcfg_encode_fns, 0, 0 },
  { "wsr.dtlbcfg", 302 /* xt_iclass_wsr.dtlbcfg */,
    0,
    Opcode_wsr_dtlbcfg_encode_fns, 0, 0 },
  { "xsr.dtlbcfg", 303 /* xt_iclass_xsr.dtlbcfg */,
    0,
    Opcode_xsr_dtlbcfg_encode_fns, 0, 0 },
  { "idtlb", 304 /* xt_iclass_idtlb */,
    0,
    Opcode_idtlb_encode_fns, 0, 0 },
  { "pdtlb", 305 /* xt_iclass_rdtlb */,
    0,
    Opcode_pdtlb_encode_fns, 0, 0 },
  { "rdtlb0", 305 /* xt_iclass_rdtlb */,
    0,
    Opcode_rdtlb0_encode_fns, 0, 0 },
  { "rdtlb1", 305 /* xt_iclass_rdtlb */,
    0,
    Opcode_rdtlb1_encode_fns, 0, 0 },
  { "wdtlb", 306 /* xt_iclass_wdtlb */,
    0,
    Opcode_wdtlb_encode_fns, 0, 0 },
  { "iitlb", 307 /* xt_iclass_iitlb */,
    0,
    Opcode_iitlb_encode_fns, 0, 0 },
  { "pitlb", 308 /* xt_iclass_ritlb */,
    0,
    Opcode_pitlb_encode_fns, 0, 0 },
  { "ritlb0", 308 /* xt_iclass_ritlb */,
    0,
    Opcode_ritlb0_encode_fns, 0, 0 },
  { "ritlb1", 308 /* xt_iclass_ritlb */,
    0,
    Opcode_ritlb1_encode_fns, 0, 0 },
  { "witlb", 309 /* xt_iclass_witlb */,
    0,
    Opcode_witlb_encode_fns, 0, 0 },
  { "ldpte", 310 /* xt_iclass_ldpte */,
    0,
    Opcode_ldpte_encode_fns, 0, 0 },
  { "hwwitlba", 311 /* xt_iclass_hwwitlba */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_hwwitlba_encode_fns, 0, 0 },
  { "hwwdtlba", 312 /* xt_iclass_hwwdtlba */,
    0,
    Opcode_hwwdtlba_encode_fns, 0, 0 },
  { "rsr.cpenable", 313 /* xt_iclass_rsr.cpenable */,
    0,
    Opcode_rsr_cpenable_encode_fns, 0, 0 },
  { "wsr.cpenable", 314 /* xt_iclass_wsr.cpenable */,
    0,
    Opcode_wsr_cpenable_encode_fns, 0, 0 },
  { "xsr.cpenable", 315 /* xt_iclass_xsr.cpenable */,
    0,
    Opcode_xsr_cpenable_encode_fns, 0, 0 },
  { "clamps", 316 /* xt_iclass_clamp */,
    0,
    Opcode_clamps_encode_fns, 0, 0 },
  { "min", 317 /* xt_iclass_minmax */,
    0,
    Opcode_min_encode_fns, 0, 0 },
  { "max", 317 /* xt_iclass_minmax */,
    0,
    Opcode_max_encode_fns, 0, 0 },
  { "minu", 317 /* xt_iclass_minmax */,
    0,
    Opcode_minu_encode_fns, 0, 0 },
  { "maxu", 317 /* xt_iclass_minmax */,
    0,
    Opcode_maxu_encode_fns, 0, 0 },
  { "nsa", 318 /* xt_iclass_nsa */,
    0,
    Opcode_nsa_encode_fns, 0, 0 },
  { "nsau", 318 /* xt_iclass_nsa */,
    0,
    Opcode_nsau_encode_fns, 0, 0 },
  { "sext", 319 /* xt_iclass_sx */,
    0,
    Opcode_sext_encode_fns, 0, 0 },
  { "l32ai", 320 /* xt_iclass_l32ai */,
    0,
    Opcode_l32ai_encode_fns, 0, 0 },
  { "s32ri", 321 /* xt_iclass_s32ri */,
    0,
    Opcode_s32ri_encode_fns, 0, 0 },
  { "s32c1i", 322 /* xt_iclass_s32c1i */,
    0,
    Opcode_s32c1i_encode_fns, 0, 0 },
  { "rsr.scompare1", 323 /* xt_iclass_rsr.scompare1 */,
    0,
    Opcode_rsr_scompare1_encode_fns, 0, 0 },
  { "wsr.scompare1", 324 /* xt_iclass_wsr.scompare1 */,
    0,
    Opcode_wsr_scompare1_encode_fns, 0, 0 },
  { "xsr.scompare1", 325 /* xt_iclass_xsr.scompare1 */,
    0,
    Opcode_xsr_scompare1_encode_fns, 0, 0 },
  { "quou", 326 /* xt_iclass_div */,
    0,
    Opcode_quou_encode_fns, 0, 0 },
  { "quos", 326 /* xt_iclass_div */,
    0,
    Opcode_quos_encode_fns, 0, 0 },
  { "remu", 326 /* xt_iclass_div */,
    0,
    Opcode_remu_encode_fns, 0, 0 },
  { "rems", 326 /* xt_iclass_div */,
    0,
    Opcode_rems_encode_fns, 0, 0 },
  { "mull", 327 /* xt_mul32 */,
    0,
    Opcode_mull_encode_fns, 0, 0 },
  { "muluh", 327 /* xt_mul32 */,
    0,
    Opcode_muluh_encode_fns, 0, 0 },
  { "mulsh", 327 /* xt_mul32 */,
    0,
    Opcode_mulsh_encode_fns, 0, 0 },
  { "rur.fcr", 328 /* rur_fcr */,
    0,
    Opcode_rur_fcr_encode_fns, 0, 0 },
  { "wur.fcr", 329 /* wur_fcr */,
    0,
    Opcode_wur_fcr_encode_fns, 0, 0 },
  { "rur.fsr", 330 /* rur_fsr */,
    0,
    Opcode_rur_fsr_encode_fns, 0, 0 },
  { "wur.fsr", 331 /* wur_fsr */,
    0,
    Opcode_wur_fsr_encode_fns, 0, 0 },
  { "add.s", 332 /* fp */,
    0,
    Opcode_add_s_encode_fns, 0, 0 },
  { "sub.s", 332 /* fp */,
    0,
    Opcode_sub_s_encode_fns, 0, 0 },
  { "mul.s", 332 /* fp */,
    0,
    Opcode_mul_s_encode_fns, 0, 0 },
  { "madd.s", 333 /* fp_mac */,
    0,
    Opcode_madd_s_encode_fns, 0, 0 },
  { "msub.s", 333 /* fp_mac */,
    0,
    Opcode_msub_s_encode_fns, 0, 0 },
  { "movf.s", 334 /* fp_cmov */,
    0,
    Opcode_movf_s_encode_fns, 0, 0 },
  { "movt.s", 334 /* fp_cmov */,
    0,
    Opcode_movt_s_encode_fns, 0, 0 },
  { "moveqz.s", 335 /* fp_mov */,
    0,
    Opcode_moveqz_s_encode_fns, 0, 0 },
  { "movnez.s", 335 /* fp_mov */,
    0,
    Opcode_movnez_s_encode_fns, 0, 0 },
  { "movltz.s", 335 /* fp_mov */,
    0,
    Opcode_movltz_s_encode_fns, 0, 0 },
  { "movgez.s", 335 /* fp_mov */,
    0,
    Opcode_movgez_s_encode_fns, 0, 0 },
  { "abs.s", 336 /* fp_mov2 */,
    0,
    Opcode_abs_s_encode_fns, 0, 0 },
  { "mov.s", 336 /* fp_mov2 */,
    0,
    Opcode_mov_s_encode_fns, 0, 0 },
  { "neg.s", 336 /* fp_mov2 */,
    0,
    Opcode_neg_s_encode_fns, 0, 0 },
  { "un.s", 337 /* fp_cmp */,
    0,
    Opcode_un_s_encode_fns, 0, 0 },
  { "oeq.s", 337 /* fp_cmp */,
    0,
    Opcode_oeq_s_encode_fns, 0, 0 },
  { "ueq.s", 337 /* fp_cmp */,
    0,
    Opcode_ueq_s_encode_fns, 0, 0 },
  { "olt.s", 337 /* fp_cmp */,
    0,
    Opcode_olt_s_encode_fns, 0, 0 },
  { "ult.s", 337 /* fp_cmp */,
    0,
    Opcode_ult_s_encode_fns, 0, 0 },
  { "ole.s", 337 /* fp_cmp */,
    0,
    Opcode_ole_s_encode_fns, 0, 0 },
  { "ule.s", 337 /* fp_cmp */,
    0,
    Opcode_ule_s_encode_fns, 0, 0 },
  { "float.s", 338 /* fp_float */,
    0,
    Opcode_float_s_encode_fns, 0, 0 },
  { "ufloat.s", 338 /* fp_float */,
    0,
    Opcode_ufloat_s_encode_fns, 0, 0 },
  { "round.s", 339 /* fp_int */,
    0,
    Opcode_round_s_encode_fns, 0, 0 },
  { "ceil.s", 339 /* fp_int */,
    0,
    Opcode_ceil_s_encode_fns, 0, 0 },
  { "floor.s", 339 /* fp_int */,
    0,
    Opcode_floor_s_encode_fns, 0, 0 },
  { "trunc.s", 339 /* fp_int */,
    0,
    Opcode_trunc_s_encode_fns, 0, 0 },
  { "utrunc.s", 339 /* fp_int */,
    0,
    Opcode_utrunc_s_encode_fns, 0, 0 },
  { "rfr", 340 /* fp_rfr */,
    0,
    Opcode_rfr_encode_fns, 0, 0 },
  { "wfr", 341 /* fp_wfr */,
    0,
    Opcode_wfr_encode_fns, 0, 0 },
  { "lsi", 342 /* fp_lsi */,
    0,
    Opcode_lsi_encode_fns, 0, 0 },
  { "lsiu", 343 /* fp_lsiu */,
    0,
    Opcode_lsiu_encode_fns, 0, 0 },
  { "lsx", 344 /* fp_lsx */,
    0,
    Opcode_lsx_encode_fns, 0, 0 },
  { "lsxu", 345 /* fp_lsxu */,
    0,
    Opcode_lsxu_encode_fns, 0, 0 },
  { "ssi", 346 /* fp_ssi */,
    0,
    Opcode_ssi_encode_fns, 0, 0 },
  { "ssiu", 347 /* fp_ssiu */,
    0,
    Opcode_ssiu_encode_fns, 0, 0 },
  { "ssx", 348 /* fp_ssx */,
    0,
    Opcode_ssx_encode_fns, 0, 0 },
  { "ssxu", 349 /* fp_ssxu */,
    0,
    Opcode_ssxu_encode_fns, 0, 0 },
  { "beqz.w18", 350 /* xt_iclass_wb18_0 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_beqz_w18_encode_fns, 0, 0 },
  { "bnez.w18", 350 /* xt_iclass_wb18_0 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnez_w18_encode_fns, 0, 0 },
  { "bgez.w18", 350 /* xt_iclass_wb18_0 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bgez_w18_encode_fns, 0, 0 },
  { "bltz.w18", 350 /* xt_iclass_wb18_0 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bltz_w18_encode_fns, 0, 0 },
  { "beqi.w18", 351 /* xt_iclass_wb18_1 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_beqi_w18_encode_fns, 0, 0 },
  { "bnei.w18", 351 /* xt_iclass_wb18_1 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnei_w18_encode_fns, 0, 0 },
  { "bgei.w18", 351 /* xt_iclass_wb18_1 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bgei_w18_encode_fns, 0, 0 },
  { "blti.w18", 351 /* xt_iclass_wb18_1 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_blti_w18_encode_fns, 0, 0 },
  { "bgeui.w18", 352 /* xt_iclass_wb18_2 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bgeui_w18_encode_fns, 0, 0 },
  { "bltui.w18", 352 /* xt_iclass_wb18_2 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bltui_w18_encode_fns, 0, 0 },
  { "bbci.w18", 353 /* xt_iclass_wb18_3 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bbci_w18_encode_fns, 0, 0 },
  { "bbsi.w18", 353 /* xt_iclass_wb18_3 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bbsi_w18_encode_fns, 0, 0 },
  { "beq.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_beq_w18_encode_fns, 0, 0 },
  { "bne.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bne_w18_encode_fns, 0, 0 },
  { "bge.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bge_w18_encode_fns, 0, 0 },
  { "blt.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_blt_w18_encode_fns, 0, 0 },
  { "bgeu.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bgeu_w18_encode_fns, 0, 0 },
  { "bltu.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bltu_w18_encode_fns, 0, 0 },
  { "bany.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bany_w18_encode_fns, 0, 0 },
  { "bnone.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnone_w18_encode_fns, 0, 0 },
  { "ball.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_ball_w18_encode_fns, 0, 0 },
  { "bnall.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bnall_w18_encode_fns, 0, 0 },
  { "bbc.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bbc_w18_encode_fns, 0, 0 },
  { "bbs.w18", 354 /* xt_iclass_wb18_4 */,
    XTENSA_OPCODE_IS_BRANCH,
    Opcode_bbs_w18_encode_fns, 0, 0 }
};


/* Slot-specific opcode decode functions.  */

static int
Slot_inst_decode (const xtensa_insnbuf insn)
{
  switch (Field_op0_Slot_inst_get (insn))
    {
    case 0:
      switch (Field_op1_Slot_inst_get (insn))
	{
	case 0:
	  switch (Field_op2_Slot_inst_get (insn))
	    {
	    case 0:
	      switch (Field_r_Slot_inst_get (insn))
		{
		case 0:
		  switch (Field_m_Slot_inst_get (insn))
		    {
		    case 0:
			    if (Field_s_Slot_inst_get (insn) == 0 &&
				    Field_n_Slot_inst_get (insn) == 0) {
				    return 79; /* ill */
			    }
			    break;
		    case 2:
		      switch (Field_n_Slot_inst_get (insn))
			{
			case 0:
			  return 98; /* ret */
			case 1:
			  return 14; /* retw */
			case 2:
			  return 81; /* jx */
			}
		      break;
		    case 3:
		      switch (Field_n_Slot_inst_get (insn))
			{
			case 0:
			  return 77; /* callx0 */
			case 1:
			  return 10; /* callx4 */
			case 2:
			  return 9; /* callx8 */
			case 3:
			  return 8; /* callx12 */
			}
		      break;
		    }
		  break;
		case 1:
		  return 12; /* movsp */
		case 2:
		  if (Field_s_Slot_inst_get (insn) == 0)
		    {
		      switch (Field_t_Slot_inst_get (insn))
			{
			case 0:
			  return 116; /* isync */
			case 1:
			  return 117; /* rsync */
			case 2:
			  return 118; /* esync */
			case 3:
			  return 119; /* dsync */
			case 8:
			  return 0; /* excw */
			case 12:
			  return 114; /* memw */
			case 13:
			  return 115; /* extw */
			case 15:
			  return 97; /* nop */
			}
		    }
		  break;
		case 3:
		  switch (Field_t_Slot_inst_get (insn))
		    {
		    case 0:
		      switch (Field_s_Slot_inst_get (insn))
			{
			case 0:
			  return 1; /* rfe */
			case 2:
			  return 2; /* rfde */
			case 4:
			  return 16; /* rfwo */
			case 5:
			  return 17; /* rfwu */
			}
		      break;
		    case 1:
		      return 316; /* rfi */
		    }
		  break;
		case 4:
		  return 324; /* break */
		case 5:
		  switch (Field_s_Slot_inst_get (insn))
		    {
		    case 0:
			    if (Field_t_Slot_inst_get (insn) == 0) {
				    return 3; /* syscall */
			    }
			    break;
		    case 1:
			    if (Field_t_Slot_inst_get (insn) == 0) {
				    return 4; /* simcall */
			    }
			    break;
		    }
		  break;
		case 6:
		  return 120; /* rsil */
		case 7:
			if (Field_t_Slot_inst_get (insn) == 0) {
				return 317; /* waiti */
			}
			break;
		case 8:
		  return 367; /* any4 */
		case 9:
		  return 368; /* all4 */
		case 10:
		  return 369; /* any8 */
		case 11:
		  return 370; /* all8 */
		}
	      break;
	    case 1:
	      return 49; /* and */
	    case 2:
	      return 50; /* or */
	    case 3:
	      return 51; /* xor */
	    case 4:
	      switch (Field_r_Slot_inst_get (insn))
		{
		case 0:
			if (Field_t_Slot_inst_get (insn) == 0) {
				return 102; /* ssr */
			}
			break;
		case 1:
			if (Field_t_Slot_inst_get (insn) == 0) {
				return 103; /* ssl */
			}
			break;
		case 2:
			if (Field_t_Slot_inst_get (insn) == 0) {
				return 104; /* ssa8l */
			}
			break;
		case 3:
			if (Field_t_Slot_inst_get (insn) == 0) {
				return 105; /* ssa8b */
			}
			break;
		case 4:
			if (Field_thi3_Slot_inst_get (insn) == 0) {
				return 106; /* ssai */
			}
			break;
		case 8:
			if (Field_s_Slot_inst_get (insn) == 0) {
				return 13; /* rotw */
			}
			break;
		case 14:
		  return 448; /* nsa */
		case 15:
		  return 449; /* nsau */
		}
	      break;
	    case 5:
	      switch (Field_r_Slot_inst_get (insn))
		{
		case 1:
		  return 438; /* hwwitlba */
		case 3:
		  return 434; /* ritlb0 */
		case 4:
			if (Field_t_Slot_inst_get (insn) == 0) {
				return 432; /* iitlb */
			}
			break;
		case 5:
		  return 433; /* pitlb */
		case 6:
		  return 436; /* witlb */
		case 7:
		  return 435; /* ritlb1 */
		case 9:
		  return 439; /* hwwdtlba */
		case 11:
		  return 429; /* rdtlb0 */
		case 12:
			if (Field_t_Slot_inst_get (insn) == 0) {
				return 427; /* idtlb */
			}
			break;
		case 13:
		  return 428; /* pdtlb */
		case 14:
		  return 431; /* wdtlb */
		case 15:
		  return 430; /* rdtlb1 */
		}
	      break;
	    case 6:
	      switch (Field_s_Slot_inst_get (insn))
		{
		case 0:
		  return 95; /* neg */
		case 1:
		  return 96; /* abs */
		}
	      break;
	    case 8:
	      return 41; /* add */
	    case 9:
	      return 43; /* addx2 */
	    case 10:
	      return 44; /* addx4 */
	    case 11:
	      return 45; /* addx8 */
	    case 12:
	      return 42; /* sub */
	    case 13:
	      return 46; /* subx2 */
	    case 14:
	      return 47; /* subx4 */
	    case 15:
	      return 48; /* subx8 */
	    }
	  break;
	case 1:
	  switch (Field_op2_Slot_inst_get (insn))
	    {
	    case 0:
	    case 1:
	      return 111; /* slli */
	    case 2:
	    case 3:
	      return 112; /* srai */
	    case 4:
	      return 113; /* srli */
	    case 6:
	      switch (Field_sr_Slot_inst_get (insn))
		{
		case 0:
		  return 129; /* xsr.lbeg */
		case 1:
		  return 123; /* xsr.lend */
		case 2:
		  return 126; /* xsr.lcount */
		case 3:
		  return 132; /* xsr.sar */
		case 4:
		  return 377; /* xsr.br */
		case 5:
		  return 135; /* xsr.litbase */
		case 12:
		  return 456; /* xsr.scompare1 */
		case 16:
		  return 312; /* xsr.acclo */
		case 17:
		  return 315; /* xsr.acchi */
		case 32:
		  return 300; /* xsr.m0 */
		case 33:
		  return 303; /* xsr.m1 */
		case 34:
		  return 306; /* xsr.m2 */
		case 35:
		  return 309; /* xsr.m3 */
		case 72:
		  return 22; /* xsr.windowbase */
		case 73:
		  return 25; /* xsr.windowstart */
		case 83:
		  return 417; /* xsr.ptevaddr */
		case 90:
		  return 420; /* xsr.rasid */
		case 91:
		  return 423; /* xsr.itlbcfg */
		case 92:
		  return 426; /* xsr.dtlbcfg */
		case 96:
		  return 346; /* xsr.ibreakenable */
		case 104:
		  return 358; /* xsr.ddr */
		case 128:
		  return 340; /* xsr.ibreaka0 */
		case 129:
		  return 343; /* xsr.ibreaka1 */
		case 144:
		  return 328; /* xsr.dbreaka0 */
		case 145:
		  return 334; /* xsr.dbreaka1 */
		case 160:
		  return 331; /* xsr.dbreakc0 */
		case 161:
		  return 337; /* xsr.dbreakc1 */
		case 177:
		  return 143; /* xsr.epc1 */
		case 178:
		  return 149; /* xsr.epc2 */
		case 179:
		  return 155; /* xsr.epc3 */
		case 180:
		  return 161; /* xsr.epc4 */
		case 181:
		  return 167; /* xsr.epc5 */
		case 182:
		  return 173; /* xsr.epc6 */
		case 183:
		  return 179; /* xsr.epc7 */
		case 192:
		  return 206; /* xsr.depc */
		case 194:
		  return 185; /* xsr.eps2 */
		case 195:
		  return 188; /* xsr.eps3 */
		case 196:
		  return 191; /* xsr.eps4 */
		case 197:
		  return 194; /* xsr.eps5 */
		case 198:
		  return 197; /* xsr.eps6 */
		case 199:
		  return 200; /* xsr.eps7 */
		case 209:
		  return 146; /* xsr.excsave1 */
		case 210:
		  return 152; /* xsr.excsave2 */
		case 211:
		  return 158; /* xsr.excsave3 */
		case 212:
		  return 164; /* xsr.excsave4 */
		case 213:
		  return 170; /* xsr.excsave5 */
		case 214:
		  return 176; /* xsr.excsave6 */
		case 215:
		  return 182; /* xsr.excsave7 */
		case 224:
		  return 442; /* xsr.cpenable */
		case 228:
		  return 323; /* xsr.intenable */
		case 230:
		  return 140; /* xsr.ps */
		case 231:
		  return 225; /* xsr.vecbase */
		case 232:
		  return 209; /* xsr.exccause */
		case 233:
		  return 349; /* xsr.debugcause */
		case 234:
		  return 380; /* xsr.ccount */
		case 236:
		  return 352; /* xsr.icount */
		case 237:
		  return 355; /* xsr.icountlevel */
		case 238:
		  return 203; /* xsr.excvaddr */
		case 240:
		  return 383; /* xsr.ccompare0 */
		case 241:
		  return 386; /* xsr.ccompare1 */
		case 242:
		  return 389; /* xsr.ccompare2 */
		case 244:
		  return 212; /* xsr.misc0 */
		case 245:
		  return 215; /* xsr.misc1 */
		case 246:
		  return 218; /* xsr.misc2 */
		case 247:
		  return 221; /* xsr.misc3 */
		}
	      break;
	    case 8:
	      return 108; /* src */
	    case 9:
		    if (Field_s_Slot_inst_get (insn) == 0) {
			    return 109; /* srl */
		    }
		    break;
	    case 10:
		    if (Field_t_Slot_inst_get (insn) == 0) {
			    return 107; /* sll */
		    }
		    break;
	    case 11:
		    if (Field_s_Slot_inst_get (insn) == 0) {
			    return 110; /* sra */
		    }
		    break;
	    case 12:
	      return 296; /* mul16u */
	    case 13:
	      return 297; /* mul16s */
	    case 15:
	      switch (Field_r_Slot_inst_get (insn))
		{
		case 0:
		  return 396; /* lict */
		case 1:
		  return 398; /* sict */
		case 2:
		  return 397; /* licw */
		case 3:
		  return 399; /* sicw */
		case 8:
		  return 414; /* ldct */
		case 9:
		  return 413; /* sdct */
		case 14:
			if (Field_t_Slot_inst_get (insn) == 0) {
				return 359; /* rfdo */
			}
			if (Field_t_Slot_inst_get (insn) == 1) {
				return 360; /* rfdd */
			}
			break;
		case 15:
		  return 437; /* ldpte */
		}
	      break;
	    }
	  break;
	case 2:
	  switch (Field_op2_Slot_inst_get (insn))
	    {
	    case 0:
	      return 362; /* andb */
	    case 1:
	      return 363; /* andbc */
	    case 2:
	      return 364; /* orb */
	    case 3:
	      return 365; /* orbc */
	    case 4:
	      return 366; /* xorb */
	    case 8:
	      return 461; /* mull */
	    case 10:
	      return 462; /* muluh */
	    case 11:
	      return 463; /* mulsh */
	    case 12:
	      return 457; /* quou */
	    case 13:
	      return 458; /* quos */
	    case 14:
	      return 459; /* remu */
	    case 15:
	      return 460; /* rems */
	    }
	  break;
	case 3:
	  switch (Field_op2_Slot_inst_get (insn))
	    {
	    case 0:
	      switch (Field_sr_Slot_inst_get (insn))
		{
		case 0:
		  return 127; /* rsr.lbeg */
		case 1:
		  return 121; /* rsr.lend */
		case 2:
		  return 124; /* rsr.lcount */
		case 3:
		  return 130; /* rsr.sar */
		case 4:
		  return 375; /* rsr.br */
		case 5:
		  return 133; /* rsr.litbase */
		case 12:
		  return 454; /* rsr.scompare1 */
		case 16:
		  return 310; /* rsr.acclo */
		case 17:
		  return 313; /* rsr.acchi */
		case 32:
		  return 298; /* rsr.m0 */
		case 33:
		  return 301; /* rsr.m1 */
		case 34:
		  return 304; /* rsr.m2 */
		case 35:
		  return 307; /* rsr.m3 */
		case 72:
		  return 20; /* rsr.windowbase */
		case 73:
		  return 23; /* rsr.windowstart */
		case 83:
		  return 416; /* rsr.ptevaddr */
		case 90:
		  return 418; /* rsr.rasid */
		case 91:
		  return 421; /* rsr.itlbcfg */
		case 92:
		  return 424; /* rsr.dtlbcfg */
		case 96:
		  return 344; /* rsr.ibreakenable */
		case 104:
		  return 356; /* rsr.ddr */
		case 128:
		  return 338; /* rsr.ibreaka0 */
		case 129:
		  return 341; /* rsr.ibreaka1 */
		case 144:
		  return 326; /* rsr.dbreaka0 */
		case 145:
		  return 332; /* rsr.dbreaka1 */
		case 160:
		  return 329; /* rsr.dbreakc0 */
		case 161:
		  return 335; /* rsr.dbreakc1 */
		case 176:
		  return 136; /* rsr.176 */
		case 177:
		  return 141; /* rsr.epc1 */
		case 178:
		  return 147; /* rsr.epc2 */
		case 179:
		  return 153; /* rsr.epc3 */
		case 180:
		  return 159; /* rsr.epc4 */
		case 181:
		  return 165; /* rsr.epc5 */
		case 182:
		  return 171; /* rsr.epc6 */
		case 183:
		  return 177; /* rsr.epc7 */
		case 192:
		  return 204; /* rsr.depc */
		case 194:
		  return 183; /* rsr.eps2 */
		case 195:
		  return 186; /* rsr.eps3 */
		case 196:
		  return 189; /* rsr.eps4 */
		case 197:
		  return 192; /* rsr.eps5 */
		case 198:
		  return 195; /* rsr.eps6 */
		case 199:
		  return 198; /* rsr.eps7 */
		case 208:
		  return 137; /* rsr.208 */
		case 209:
		  return 144; /* rsr.excsave1 */
		case 210:
		  return 150; /* rsr.excsave2 */
		case 211:
		  return 156; /* rsr.excsave3 */
		case 212:
		  return 162; /* rsr.excsave4 */
		case 213:
		  return 168; /* rsr.excsave5 */
		case 214:
		  return 174; /* rsr.excsave6 */
		case 215:
		  return 180; /* rsr.excsave7 */
		case 224:
		  return 440; /* rsr.cpenable */
		case 226:
		  return 318; /* rsr.interrupt */
		case 228:
		  return 321; /* rsr.intenable */
		case 230:
		  return 138; /* rsr.ps */
		case 231:
		  return 223; /* rsr.vecbase */
		case 232:
		  return 207; /* rsr.exccause */
		case 233:
		  return 347; /* rsr.debugcause */
		case 234:
		  return 378; /* rsr.ccount */
		case 235:
		  return 222; /* rsr.prid */
		case 236:
		  return 350; /* rsr.icount */
		case 237:
		  return 353; /* rsr.icountlevel */
		case 238:
		  return 201; /* rsr.excvaddr */
		case 240:
		  return 381; /* rsr.ccompare0 */
		case 241:
		  return 384; /* rsr.ccompare1 */
		case 242:
		  return 387; /* rsr.ccompare2 */
		case 244:
		  return 210; /* rsr.misc0 */
		case 245:
		  return 213; /* rsr.misc1 */
		case 246:
		  return 216; /* rsr.misc2 */
		case 247:
		  return 219; /* rsr.misc3 */
		}
	      break;
	    case 1:
	      switch (Field_sr_Slot_inst_get (insn))
		{
		case 0:
		  return 128; /* wsr.lbeg */
		case 1:
		  return 122; /* wsr.lend */
		case 2:
		  return 125; /* wsr.lcount */
		case 3:
		  return 131; /* wsr.sar */
		case 4:
		  return 376; /* wsr.br */
		case 5:
		  return 134; /* wsr.litbase */
		case 12:
		  return 455; /* wsr.scompare1 */
		case 16:
		  return 311; /* wsr.acclo */
		case 17:
		  return 314; /* wsr.acchi */
		case 32:
		  return 299; /* wsr.m0 */
		case 33:
		  return 302; /* wsr.m1 */
		case 34:
		  return 305; /* wsr.m2 */
		case 35:
		  return 308; /* wsr.m3 */
		case 72:
		  return 21; /* wsr.windowbase */
		case 73:
		  return 24; /* wsr.windowstart */
		case 83:
		  return 415; /* wsr.ptevaddr */
		case 89:
		  return 361; /* wsr.mmid */
		case 90:
		  return 419; /* wsr.rasid */
		case 91:
		  return 422; /* wsr.itlbcfg */
		case 92:
		  return 425; /* wsr.dtlbcfg */
		case 96:
		  return 345; /* wsr.ibreakenable */
		case 104:
		  return 357; /* wsr.ddr */
		case 128:
		  return 339; /* wsr.ibreaka0 */
		case 129:
		  return 342; /* wsr.ibreaka1 */
		case 144:
		  return 327; /* wsr.dbreaka0 */
		case 145:
		  return 333; /* wsr.dbreaka1 */
		case 160:
		  return 330; /* wsr.dbreakc0 */
		case 161:
		  return 336; /* wsr.dbreakc1 */
		case 177:
		  return 142; /* wsr.epc1 */
		case 178:
		  return 148; /* wsr.epc2 */
		case 179:
		  return 154; /* wsr.epc3 */
		case 180:
		  return 160; /* wsr.epc4 */
		case 181:
		  return 166; /* wsr.epc5 */
		case 182:
		  return 172; /* wsr.epc6 */
		case 183:
		  return 178; /* wsr.epc7 */
		case 192:
		  return 205; /* wsr.depc */
		case 194:
		  return 184; /* wsr.eps2 */
		case 195:
		  return 187; /* wsr.eps3 */
		case 196:
		  return 190; /* wsr.eps4 */
		case 197:
		  return 193; /* wsr.eps5 */
		case 198:
		  return 196; /* wsr.eps6 */
		case 199:
		  return 199; /* wsr.eps7 */
		case 209:
		  return 145; /* wsr.excsave1 */
		case 210:
		  return 151; /* wsr.excsave2 */
		case 211:
		  return 157; /* wsr.excsave3 */
		case 212:
		  return 163; /* wsr.excsave4 */
		case 213:
		  return 169; /* wsr.excsave5 */
		case 214:
		  return 175; /* wsr.excsave6 */
		case 215:
		  return 181; /* wsr.excsave7 */
		case 224:
		  return 441; /* wsr.cpenable */
		case 226:
		  return 319; /* wsr.intset */
		case 227:
		  return 320; /* wsr.intclear */
		case 228:
		  return 322; /* wsr.intenable */
		case 230:
		  return 139; /* wsr.ps */
		case 231:
		  return 224; /* wsr.vecbase */
		case 232:
		  return 208; /* wsr.exccause */
		case 233:
		  return 348; /* wsr.debugcause */
		case 234:
		  return 379; /* wsr.ccount */
		case 236:
		  return 351; /* wsr.icount */
		case 237:
		  return 354; /* wsr.icountlevel */
		case 238:
		  return 202; /* wsr.excvaddr */
		case 240:
		  return 382; /* wsr.ccompare0 */
		case 241:
		  return 385; /* wsr.ccompare1 */
		case 242:
		  return 388; /* wsr.ccompare2 */
		case 244:
		  return 211; /* wsr.misc0 */
		case 245:
		  return 214; /* wsr.misc1 */
		case 246:
		  return 217; /* wsr.misc2 */
		case 247:
		  return 220; /* wsr.misc3 */
		}
	      break;
	    case 2:
	      return 450; /* sext */
	    case 3:
	      return 443; /* clamps */
	    case 4:
	      return 444; /* min */
	    case 5:
	      return 445; /* max */
	    case 6:
	      return 446; /* minu */
	    case 7:
	      return 447; /* maxu */
	    case 8:
	      return 91; /* moveqz */
	    case 9:
	      return 92; /* movnez */
	    case 10:
	      return 93; /* movltz */
	    case 11:
	      return 94; /* movgez */
	    case 12:
	      return 373; /* movf */
	    case 13:
	      return 374; /* movt */
	    case 14:
	      switch (Field_st_Slot_inst_get (insn))
		{
		case 231:
		  return 37; /* rur.threadptr */
		case 232:
		  return 464; /* rur.fcr */
		case 233:
		  return 466; /* rur.fsr */
		}
	      break;
	    case 15:
	      switch (Field_sr_Slot_inst_get (insn))
		{
		case 231:
		  return 38; /* wur.threadptr */
		case 232:
		  return 465; /* wur.fcr */
		case 233:
		  return 467; /* wur.fsr */
		}
	      break;
	    }
	  break;
	case 4:
	case 5:
	  return 78; /* extui */
	case 8:
	  switch (Field_op2_Slot_inst_get (insn))
	    {
	    case 0:
	      return 500; /* lsx */
	    case 1:
	      return 501; /* lsxu */
	    case 4:
	      return 504; /* ssx */
	    case 5:
	      return 505; /* ssxu */
	    }
	  break;
	case 9:
	  switch (Field_op2_Slot_inst_get (insn))
	    {
	    case 0:
	      return 18; /* l32e */
	    case 4:
	      return 19; /* s32e */
	    }
	  break;
	case 10:
	  switch (Field_op2_Slot_inst_get (insn))
	    {
	    case 0:
	      return 468; /* add.s */
	    case 1:
	      return 469; /* sub.s */
	    case 2:
	      return 470; /* mul.s */
	    case 4:
	      return 471; /* madd.s */
	    case 5:
	      return 472; /* msub.s */
	    case 8:
	      return 491; /* round.s */
	    case 9:
	      return 494; /* trunc.s */
	    case 10:
	      return 493; /* floor.s */
	    case 11:
	      return 492; /* ceil.s */
	    case 12:
	      return 489; /* float.s */
	    case 13:
	      return 490; /* ufloat.s */
	    case 14:
	      return 495; /* utrunc.s */
	    case 15:
	      switch (Field_t_Slot_inst_get (insn))
		{
		case 0:
		  return 480; /* mov.s */
		case 1:
		  return 479; /* abs.s */
		case 4:
		  return 496; /* rfr */
		case 5:
		  return 497; /* wfr */
		case 6:
		  return 481; /* neg.s */
		}
	      break;
	    }
	  break;
	case 11:
	  switch (Field_op2_Slot_inst_get (insn))
	    {
	    case 1:
	      return 482; /* un.s */
	    case 2:
	      return 483; /* oeq.s */
	    case 3:
	      return 484; /* ueq.s */
	    case 4:
	      return 485; /* olt.s */
	    case 5:
	      return 486; /* ult.s */
	    case 6:
	      return 487; /* ole.s */
	    case 7:
	      return 488; /* ule.s */
	    case 8:
	      return 475; /* moveqz.s */
	    case 9:
	      return 476; /* movnez.s */
	    case 10:
	      return 477; /* movltz.s */
	    case 11:
	      return 478; /* movgez.s */
	    case 12:
	      return 473; /* movf.s */
	    case 13:
	      return 474; /* movt.s */
	    }
	  break;
	}
      break;
    case 1:
      return 85; /* l32r */
    case 2:
      switch (Field_r_Slot_inst_get (insn))
	{
	case 0:
	  return 86; /* l8ui */
	case 1:
	  return 82; /* l16ui */
	case 2:
	  return 84; /* l32i */
	case 4:
	  return 101; /* s8i */
	case 5:
	  return 99; /* s16i */
	case 6:
	  return 100; /* s32i */
	case 7:
	  switch (Field_t_Slot_inst_get (insn))
	    {
	    case 0:
	      return 406; /* dpfr */
	    case 1:
	      return 407; /* dpfw */
	    case 2:
	      return 408; /* dpfro */
	    case 3:
	      return 409; /* dpfwo */
	    case 4:
	      return 400; /* dhwb */
	    case 5:
	      return 401; /* dhwbi */
	    case 6:
	      return 404; /* dhi */
	    case 7:
	      return 405; /* dii */
	    case 8:
	      switch (Field_op1_Slot_inst_get (insn))
		{
		case 0:
		  return 410; /* dpfl */
		case 2:
		  return 411; /* dhu */
		case 3:
		  return 412; /* diu */
		case 4:
		  return 402; /* diwb */
		case 5:
		  return 403; /* diwbi */
		}
	      break;
	    case 12:
	      return 390; /* ipf */
	    case 13:
	      switch (Field_op1_Slot_inst_get (insn))
		{
		case 0:
		  return 392; /* ipfl */
		case 2:
		  return 393; /* ihu */
		case 3:
		  return 394; /* iiu */
		}
	      break;
	    case 14:
	      return 391; /* ihi */
	    case 15:
	      return 395; /* iii */
	    }
	  break;
	case 9:
	  return 83; /* l16si */
	case 10:
	  return 90; /* movi */
	case 11:
	  return 451; /* l32ai */
	case 12:
	  return 39; /* addi */
	case 13:
	  return 40; /* addmi */
	case 14:
	  return 453; /* s32c1i */
	case 15:
	  return 452; /* s32ri */
	}
      break;
    case 3:
      switch (Field_r_Slot_inst_get (insn))
	{
	case 0:
	  return 498; /* lsi */
	case 4:
	  return 502; /* ssi */
	case 8:
	  return 499; /* lsiu */
	case 12:
	  return 503; /* ssiu */
	}
      break;
    case 4:
      switch (Field_op2_Slot_inst_get (insn))
	{
	case 0:
	  switch (Field_op1_Slot_inst_get (insn))
	    {
	    case 8:
		    if (Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 287; /* mula.dd.ll.ldinc */
		    }
		    break;
	    case 9:
		    if (Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 289; /* mula.dd.hl.ldinc */
		    }
		    break;
	    case 10:
		    if (Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 291; /* mula.dd.lh.ldinc */
		    }
		    break;
	    case 11:
		    if (Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 293; /* mula.dd.hh.ldinc */
		    }
		    break;
	    }
	  break;
	case 1:
	  switch (Field_op1_Slot_inst_get (insn))
	    {
	    case 8:
		    if (Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 286; /* mula.dd.ll.lddec */
		    }
		    break;
	    case 9:
		    if (Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 288; /* mula.dd.hl.lddec */
		    }
		    break;
	    case 10:
		    if (Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 290; /* mula.dd.lh.lddec */
		    }
		    break;
	    case 11:
		    if (Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 292; /* mula.dd.hh.lddec */
		    }
		    break;
	    }
	  break;
	case 2:
	  switch (Field_op1_Slot_inst_get (insn))
	    {
	    case 4:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 242; /* mul.dd.ll */
		    }
		    break;
	    case 5:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 243; /* mul.dd.hl */
		    }
		    break;
	    case 6:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 244; /* mul.dd.lh */
		    }
		    break;
	    case 7:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 245; /* mul.dd.hh */
		    }
		    break;
	    case 8:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 270; /* mula.dd.ll */
		    }
		    break;
	    case 9:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 271; /* mula.dd.hl */
		    }
		    break;
	    case 10:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 272; /* mula.dd.lh */
		    }
		    break;
	    case 11:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 273; /* mula.dd.hh */
		    }
		    break;
	    case 12:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 274; /* muls.dd.ll */
		    }
		    break;
	    case 13:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 275; /* muls.dd.hl */
		    }
		    break;
	    case 14:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 276; /* muls.dd.lh */
		    }
		    break;
	    case 15:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 277; /* muls.dd.hh */
		    }
		    break;
	    }
	  break;
	case 3:
	  switch (Field_op1_Slot_inst_get (insn))
	    {
	    case 4:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 234; /* mul.ad.ll */
		    }
		    break;
	    case 5:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 235; /* mul.ad.hl */
		    }
		    break;
	    case 6:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 236; /* mul.ad.lh */
		    }
		    break;
	    case 7:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 237; /* mul.ad.hh */
		    }
		    break;
	    case 8:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 254; /* mula.ad.ll */
		    }
		    break;
	    case 9:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 255; /* mula.ad.hl */
		    }
		    break;
	    case 10:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 256; /* mula.ad.lh */
		    }
		    break;
	    case 11:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 257; /* mula.ad.hh */
		    }
		    break;
	    case 12:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 258; /* muls.ad.ll */
		    }
		    break;
	    case 13:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 259; /* muls.ad.hl */
		    }
		    break;
	    case 14:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 260; /* muls.ad.lh */
		    }
		    break;
	    case 15:
		    if (Field_r_Slot_inst_get (insn) == 0 &&
			    Field_t3_Slot_inst_get (insn) == 0 &&
			    Field_tlo_Slot_inst_get (insn) == 0) {
			    return 261; /* muls.ad.hh */
		    }
		    break;
	    }
	  break;
	case 4:
	  switch (Field_op1_Slot_inst_get (insn))
	    {
	    case 8:
		    if (Field_r3_Slot_inst_get (insn) == 0) {
			    return 279; /* mula.da.ll.ldinc */
		    }
		    break;
	    case 9:
		    if (Field_r3_Slot_inst_get (insn) == 0) {
			    return 281; /* mula.da.hl.ldinc */
		    }
		    break;
	    case 10:
		    if (Field_r3_Slot_inst_get (insn) == 0) {
			    return 283; /* mula.da.lh.ldinc */
		    }
		    break;
	    case 11:
		    if (Field_r3_Slot_inst_get (insn) == 0) {
			    return 285; /* mula.da.hh.ldinc */
		    }
		    break;
	    }
	  break;
	case 5:
	  switch (Field_op1_Slot_inst_get (insn))
	    {
	    case 8:
		    if (Field_r3_Slot_inst_get (insn) == 0) {
			    return 278; /* mula.da.ll.lddec */
		    }
		    break;
	    case 9:
		    if (Field_r3_Slot_inst_get (insn) == 0) {
			    return 280; /* mula.da.hl.lddec */
		    }
		    break;
	    case 10:
		    if (Field_r3_Slot_inst_get (insn) == 0) {
			    return 282; /* mula.da.lh.lddec */
		    }
		    break;
	    case 11:
		    if (Field_r3_Slot_inst_get (insn) == 0) {
			    return 284; /* mula.da.hh.lddec */
		    }
		    break;
	    }
	  break;
	case 6:
	  switch (Field_op1_Slot_inst_get (insn))
	    {
	    case 4:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 238; /* mul.da.ll */
		    }
		    break;
	    case 5:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 239; /* mul.da.hl */
		    }
		    break;
	    case 6:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 240; /* mul.da.lh */
		    }
		    break;
	    case 7:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 241; /* mul.da.hh */
		    }
		    break;
	    case 8:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 262; /* mula.da.ll */
		    }
		    break;
	    case 9:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 263; /* mula.da.hl */
		    }
		    break;
	    case 10:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 264; /* mula.da.lh */
		    }
		    break;
	    case 11:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 265; /* mula.da.hh */
		    }
		    break;
	    case 12:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 266; /* muls.da.ll */
		    }
		    break;
	    case 13:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 267; /* muls.da.hl */
		    }
		    break;
	    case 14:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 268; /* muls.da.lh */
		    }
		    break;
	    case 15:
		    if (Field_s_Slot_inst_get (insn) == 0 &&
			    Field_w_Slot_inst_get (insn) == 0 &&
			    Field_r3_Slot_inst_get (insn) == 0) {
			    return 269; /* muls.da.hh */
		    }
		    break;
	    }
	  break;
	case 7:
	  switch (Field_op1_Slot_inst_get (insn))
	    {
	    case 0:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 230; /* umul.aa.ll */
		    }
		    break;
	    case 1:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 231; /* umul.aa.hl */
		    }
		    break;
	    case 2:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 232; /* umul.aa.lh */
		    }
		    break;
	    case 3:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 233; /* umul.aa.hh */
		    }
		    break;
	    case 4:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 226; /* mul.aa.ll */
		    }
		    break;
	    case 5:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 227; /* mul.aa.hl */
		    }
		    break;
	    case 6:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 228; /* mul.aa.lh */
		    }
		    break;
	    case 7:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 229; /* mul.aa.hh */
		    }
		    break;
	    case 8:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 246; /* mula.aa.ll */
		    }
		    break;
	    case 9:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 247; /* mula.aa.hl */
		    }
		    break;
	    case 10:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 248; /* mula.aa.lh */
		    }
		    break;
	    case 11:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 249; /* mula.aa.hh */
		    }
		    break;
	    case 12:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 250; /* muls.aa.ll */
		    }
		    break;
	    case 13:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 251; /* muls.aa.hl */
		    }
		    break;
	    case 14:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 252; /* muls.aa.lh */
		    }
		    break;
	    case 15:
		    if (Field_r_Slot_inst_get (insn) == 0) {
			    return 253; /* muls.aa.hh */
		    }
		    break;
	    }
	  break;
	case 8:
		if (Field_op1_Slot_inst_get (insn) == 0 &&
			Field_t_Slot_inst_get (insn) == 0 &&
			Field_rhi_Slot_inst_get (insn) == 0) {
			return 295; /* ldinc */
		}
		break;
	case 9:
		if (Field_op1_Slot_inst_get (insn) == 0 &&
			Field_t_Slot_inst_get (insn) == 0 &&
			Field_rhi_Slot_inst_get (insn) == 0) {
			return 294; /* lddec */
		}
		break;
	}
      break;
    case 5:
      switch (Field_n_Slot_inst_get (insn))
	{
	case 0:
	  return 76; /* call0 */
	case 1:
	  return 7; /* call4 */
	case 2:
	  return 6; /* call8 */
	case 3:
	  return 5; /* call12 */
	}
      break;
    case 6:
      switch (Field_n_Slot_inst_get (insn))
	{
	case 0:
	  return 80; /* j */
	case 1:
	  switch (Field_m_Slot_inst_get (insn))
	    {
	    case 0:
	      return 72; /* beqz */
	    case 1:
	      return 73; /* bnez */
	    case 2:
	      return 75; /* bltz */
	    case 3:
	      return 74; /* bgez */
	    }
	  break;
	case 2:
	  switch (Field_m_Slot_inst_get (insn))
	    {
	    case 0:
	      return 52; /* beqi */
	    case 1:
	      return 53; /* bnei */
	    case 2:
	      return 55; /* blti */
	    case 3:
	      return 54; /* bgei */
	    }
	  break;
	case 3:
	  switch (Field_m_Slot_inst_get (insn))
	    {
	    case 0:
	      return 11; /* entry */
	    case 1:
	      switch (Field_r_Slot_inst_get (insn))
		{
		case 0:
		  return 371; /* bf */
		case 1:
		  return 372; /* bt */
		case 8:
		  return 87; /* loop */
		case 9:
		  return 88; /* loopnez */
		case 10:
		  return 89; /* loopgtz */
		}
	      break;
	    case 2:
	      return 59; /* bltui */
	    case 3:
	      return 58; /* bgeui */
	    }
	  break;
	}
      break;
    case 7:
      switch (Field_r_Slot_inst_get (insn))
	{
	case 0:
	  return 67; /* bnone */
	case 1:
	  return 60; /* beq */
	case 2:
	  return 63; /* blt */
	case 3:
	  return 65; /* bltu */
	case 4:
	  return 68; /* ball */
	case 5:
	  return 70; /* bbc */
	case 6:
	case 7:
	  return 56; /* bbci */
	case 8:
	  return 66; /* bany */
	case 9:
	  return 61; /* bne */
	case 10:
	  return 62; /* bge */
	case 11:
	  return 64; /* bgeu */
	case 12:
	  return 69; /* bnall */
	case 13:
	  return 71; /* bbs */
	case 14:
	case 15:
	  return 57; /* bbsi */
	}
      break;
    }
  return 0;
}

static int
Slot_inst16b_decode (const xtensa_insnbuf insn)
{
  switch (Field_op0_Slot_inst16b_get (insn))
    {
    case 12:
      switch (Field_i_Slot_inst16b_get (insn))
	{
	case 0:
	  return 33; /* movi.n */
	case 1:
	  switch (Field_z_Slot_inst16b_get (insn))
	    {
	    case 0:
	      return 28; /* beqz.n */
	    case 1:
	      return 29; /* bnez.n */
	    }
	  break;
	}
      break;
    case 13:
      switch (Field_r_Slot_inst16b_get (insn))
	{
	case 0:
	  return 32; /* mov.n */
	case 15:
	  switch (Field_t_Slot_inst16b_get (insn))
	    {
	    case 0:
	      return 35; /* ret.n */
	    case 1:
	      return 15; /* retw.n */
	    case 2:
	      return 325; /* break.n */
	    case 3:
		    if (Field_s_Slot_inst16b_get (insn) == 0) {
			    return 34; /* nop.n */
		    }
		    break;
	    case 6:
		    if (Field_s_Slot_inst16b_get (insn) == 0) {
			    return 30; /* ill.n */
		    }
		    break;
	    }
	  break;
	}
      break;
    }
  return 0;
}

static int
Slot_inst16a_decode (const xtensa_insnbuf insn)
{
  switch (Field_op0_Slot_inst16a_get (insn))
    {
    case 8:
      return 31; /* l32i.n */
    case 9:
      return 36; /* s32i.n */
    case 10:
      return 26; /* add.n */
    case 11:
      return 27; /* addi.n */
    }
  return 0;
}

static int
Slot_xt_flix64_slot2_decode (const xtensa_insnbuf insn)
{
  switch (Field_combined3e2c5767_fld36xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn))
    {
    case 0:
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 1) {
		    return 41; /* add */
	    }
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 5) {
		    return 42; /* sub */
	    }
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 2) {
		    return 43; /* addx2 */
	    }
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 3) {
		    return 49; /* and */
	    }
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 4) {
		    return 450; /* sext */
	    }
	    break;
    case 1:
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 1) {
		    return 27; /* addi.n */
	    }
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 2) {
		    return 44; /* addx4 */
	    }
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 3) {
		    return 50; /* or */
	    }
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 5) {
		    return 51; /* xor */
	    }
	    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 4) {
		    return 113; /* srli */
	    }
	    break;
    }
    if (Field_combined3e2c5767_fld37xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 0 &&
	    Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 6) {
	    return 33; /* movi.n */
    }
    if (Field_combined3e2c5767_fld39xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 2 &&
	    Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 6 &&
	    Field_combined3e2c5767_fld63xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 0) {
	    return 32; /* mov.n */
    }
    if (Field_combined3e2c5767_fld41xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 3 &&
	    Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 6 &&
	    Field_combined3e2c5767_fld65xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 0) {
	    return 97; /* nop */
    }
    if (Field_combined3e2c5767_fld42xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 8 &&
	    Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 6 &&
	    Field_combined3e2c5767_fld64xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 0) {
	    return 96; /* abs */
    }
    if (Field_combined3e2c5767_fld44xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 9 &&
	    Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 6 &&
	    Field_combined3e2c5767_fld64xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 0) {
	    return 95; /* neg */
    }
    if (Field_combined3e2c5767_fld45xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 5 &&
	    Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 6 &&
	    Field_combined3e2c5767_fld66xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 0) {
	    return 110; /* sra */
    }
    if (Field_combined3e2c5767_fld47xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 3 &&
	    Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 6 &&
	    Field_combined3e2c5767_fld68xt_flix64_slot2_Slot_xt_flix64_slot2_get (insn) == 0) {
	    return 109; /* srl */
    }
    if (Field_op0_s5_Slot_xt_flix64_slot2_get (insn) == 7) {
	    return 112; /* srai */
    }
    return 0;
}

static int
Slot_xt_flix64_slot0_decode (const xtensa_insnbuf insn)
{
  switch (Field_op0_xt_flix64_slot0_Slot_xt_flix64_slot0_get (insn))
    {
    case 0:
	    if (Field_combined3e2c5767_fld7_Slot_xt_flix64_slot0_get (insn) == 2) {
		    return 78; /* extui */
	    }
	    switch (Field_op1_Slot_xt_flix64_slot0_get (insn)) {
	    case 0:
		    switch (Field_op2_Slot_xt_flix64_slot0_get (insn)) {
		    case 0:
			    if (Field_r_Slot_xt_flix64_slot0_get (insn) == 2) {
				    if (Field_s_Slot_xt_flix64_slot0_get (insn) == 0) {
					    if (Field_t_Slot_xt_flix64_slot0_get (insn) == 15) {
						    return 97; /* nop */
					    }
				    }
			    }
			    break;
		    case 1:
			    return 49; /* and */
		    case 2:
			    return 50; /* or */
		    case 3:
			    return 51; /* xor */
		    case 4:
			    switch (Field_r_Slot_xt_flix64_slot0_get (insn)) {
			    case 0:
				    if (Field_t_Slot_xt_flix64_slot0_get (insn) == 0) {
					    return 102; /* ssr */
				    }
				    break;
			    case 1:
				    if (Field_t_Slot_xt_flix64_slot0_get (insn) == 0) {
					    return 103; /* ssl */
				    }
				    break;
			    case 2:
				    if (Field_t_Slot_xt_flix64_slot0_get (insn) == 0) {
					    return 104; /* ssa8l */
				    }
				    break;
			    case 3:
				    if (Field_t_Slot_xt_flix64_slot0_get (insn) == 0) {
					    return 105; /* ssa8b */
				    }
				    break;
			    case 4:
				    if (Field_thi3_Slot_xt_flix64_slot0_get (insn) == 0) {
					    return 106; /* ssai */
				    }
				    break;
			    case 14:
				    return 448; /* nsa */
			    case 15:
				    return 449; /* nsau */
			    }
			    break;
		    case 6:
			    switch (Field_s_Slot_xt_flix64_slot0_get (insn)) {
			    case 0:
				    return 95; /* neg */
			    case 1:
				    return 96; /* abs */
			    }
			    break;
		    case 8:
			    return 41; /* add */
		    case 9:
			    return 43; /* addx2 */
		    case 10:
			    return 44; /* addx4 */
		    case 11:
			    return 45; /* addx8 */
		    case 12:
			    return 42; /* sub */
		    case 13:
			    return 46; /* subx2 */
		    case 14:
			    return 47; /* subx4 */
		    case 15:
			    return 48; /* subx8 */
		    }
		    break;
	    case 1:
		    if (Field_combined3e2c5767_fld11_Slot_xt_flix64_slot0_get (insn) == 1) {
			    return 112; /* srai */
		    }
		    if (Field_combined3e2c5767_fld9_Slot_xt_flix64_slot0_get (insn) == 0) {
			    return 111; /* slli */
		    }
		    switch (Field_op2_Slot_xt_flix64_slot0_get (insn)) {
		    case 4:
			    return 113; /* srli */
		    case 8:
			    return 108; /* src */
		    case 9:
			    if (Field_s_Slot_xt_flix64_slot0_get (insn) == 0) {
				    return 109; /* srl */
			    }
			    break;
		    case 10:
			    if (Field_t_Slot_xt_flix64_slot0_get (insn) == 0) {
				    return 107; /* sll */
			    }
			    break;
		    case 11:
			    if (Field_s_Slot_xt_flix64_slot0_get (insn) == 0) {
				    return 110; /* sra */
			    }
			    break;
		    case 12:
			    return 296; /* mul16u */
		    case 13:
			    return 297; /* mul16s */
		    }
		    break;
	    case 2:
		    if (Field_op2_Slot_xt_flix64_slot0_get (insn) == 8) {
			    return 461; /* mull */
		    }
		    break;
	    case 3:
		    switch (Field_op2_Slot_xt_flix64_slot0_get (insn)) {
		    case 2:
			    return 450; /* sext */
		    case 3:
			    return 443; /* clamps */
		    case 4:
			    return 444; /* min */
		    case 5:
			    return 445; /* max */
		    case 6:
			    return 446; /* minu */
		    case 7:
			    return 447; /* maxu */
		    case 8:
			    return 91; /* moveqz */
		    case 9:
			    return 92; /* movnez */
		    case 10:
			    return 93; /* movltz */
		    case 11:
			    return 94; /* movgez */
		    }
		    break;
	}
      break;
    case 2:
      switch (Field_r_Slot_xt_flix64_slot0_get (insn))
	{
	case 0:
	  return 86; /* l8ui */
	case 1:
	  return 82; /* l16ui */
	case 2:
	  return 84; /* l32i */
	case 4:
	  return 101; /* s8i */
	case 5:
	  return 99; /* s16i */
	case 6:
	  return 100; /* s32i */
	case 9:
	  return 83; /* l16si */
	case 10:
	  return 90; /* movi */
	case 12:
	  return 39; /* addi */
	case 13:
	  return 40; /* addmi */
	}
      break;
    }
    if (Field_op0_xt_flix64_slot0_s3_Slot_xt_flix64_slot0_get (insn) == 1) {
	    return 85; /* l32r */
    }
    if (Field_sae4_Slot_xt_flix64_slot0_get (insn) == 0 &&
	    Field_combined3e2c5767_fld8_Slot_xt_flix64_slot0_get (insn) == 3 &&
	    Field_op0_xt_flix64_slot0_s3_Slot_xt_flix64_slot0_get (insn) == 0 &&
	    Field_combined3e2c5767_fld49xt_flix64_slot0_Slot_xt_flix64_slot0_get (insn) == 0) {
	    return 32; /* mov.n */
    }
    return 0;
}

static int
Slot_xt_flix64_slot1_decode (const xtensa_insnbuf insn)
{
	if (Field_combined3e2c5767_fld19xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0 &&
		Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 1) {
		return 78; /* extui */
	}
	switch (Field_combined3e2c5767_fld20xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn)) {
	case 0:
		if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
			return 90; /* movi */
		}
		break;
	case 2:
		if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 1) {
			return 39; /* addi */
		}
		break;
	case 3:
		if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 1) {
			return 40; /* addmi */
		}
		if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
			Field_combined3e2c5767_fld16_Slot_xt_flix64_slot1_get (insn) == 0) {
			return 51; /* xor */
		}
		break;
    }
  switch (Field_combined3e2c5767_fld21xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn))
    {
    case 8:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 111; /* slli */
	    }
	    break;
    case 16:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 112; /* srai */
	    }
	    break;
    case 19:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
		    Field_combined3e2c5767_fld57xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
		    return 107; /* sll */
	    }
	    break;
    }
  switch (Field_combined3e2c5767_fld22xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn))
    {
    case 18:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 41; /* add */
	    }
	    break;
    case 19:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 45; /* addx8 */
	    }
	    break;
    case 20:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 43; /* addx2 */
	    }
	    break;
    case 21:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 49; /* and */
	    }
	    break;
    case 22:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 91; /* moveqz */
	    }
	    break;
    case 23:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 94; /* movgez */
	    }
	    break;
    case 24:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 44; /* addx4 */
	    }
	    break;
    case 25:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 93; /* movltz */
	    }
	    break;
    case 26:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 92; /* movnez */
	    }
	    break;
    case 27:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 296; /* mul16u */
	    }
	    break;
    case 28:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 297; /* mul16s */
	    }
	    break;
    case 29:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 461; /* mull */
	    }
	    break;
    case 30:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 50; /* or */
	    }
	    break;
    case 31:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 450; /* sext */
	    }
	    break;
    case 34:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 108; /* src */
	    }
	    break;
    case 36:
	    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2) {
		    return 113; /* srli */
	    }
	    break;
    }
    if (Field_combined3e2c5767_fld23xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 280 &&
	    Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
	    Field_combined3e2c5767_fld51xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
	    return 32; /* mov.n */
    }
    if (Field_combined3e2c5767_fld25xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 281 &&
	    Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
	    Field_combined3e2c5767_fld52xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
	    return 81; /* jx */
    }
    if (Field_combined3e2c5767_fld26xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 141 &&
	    Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
	    Field_combined3e2c5767_fld60xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
	    return 103; /* ssl */
    }
    if (Field_combined3e2c5767_fld28xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 71 &&
	    Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
	    Field_combined3e2c5767_fld54xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
	    return 97; /* nop */
    }
    if (Field_combined3e2c5767_fld30xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 148 &&
	    Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
	    Field_combined3e2c5767_fld53xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
	    return 95; /* neg */
    }
    if (Field_combined3e2c5767_fld32xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 149 &&
	    Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
	    Field_combined3e2c5767_fld53xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
	    return 110; /* sra */
    }
    if (Field_combined3e2c5767_fld33xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 75 &&
	    Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
	    Field_combined3e2c5767_fld58xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
	    return 109; /* srl */
    }
    if (Field_combined3e2c5767_fld35xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 5 &&
	    Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 2 &&
	    Field_combined3e2c5767_fld62xt_flix64_slot1_Slot_xt_flix64_slot1_get (insn) == 0) {
	    return 42; /* sub */
    }
    if (Field_op0_s4_Slot_xt_flix64_slot1_get (insn) == 3) {
	    return 80; /* j */
    }
    return 0;
}

static int
Slot_xt_flix64_slot3_decode (const xtensa_insnbuf insn)
{
  switch (Field_op0_s6_Slot_xt_flix64_slot3_get (insn))
    {
    case 1:
	    if (Field_combined3e2c5767_fld71_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 516; /* bbci.w18 */
	    }
	    break;
    case 2:
	    if (Field_combined3e2c5767_fld71_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 517; /* bbsi.w18 */
	    }
	    break;
    case 3:
	    if (Field_combined3e2c5767_fld89xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 526; /* ball.w18 */
	    }
	    break;
    case 4:
	    if (Field_combined3e2c5767_fld87xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 524; /* bany.w18 */
	    }
	    break;
    case 5:
	    if (Field_combined3e2c5767_fld91xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 528; /* bbc.w18 */
	    }
	    break;
    case 6:
	    if (Field_combined3e2c5767_fld92xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 529; /* bbs.w18 */
	    }
	    break;
    case 7:
	    if (Field_combined3e2c5767_fld81xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 518; /* beq.w18 */
	    }
	    break;
    case 8:
	    if (Field_combined3e2c5767_fld75xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 510; /* beqi.w18 */
	    }
	    break;
    case 9:
	    if (Field_combined3e2c5767_fld83xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 520; /* bge.w18 */
	    }
	    break;
    case 10:
	    if (Field_combined3e2c5767_fld77xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 512; /* bgei.w18 */
	    }
	    break;
    case 11:
	    if (Field_combined3e2c5767_fld85xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 522; /* bgeu.w18 */
	    }
	    break;
    case 12:
	    if (Field_combined3e2c5767_fld79xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 514; /* bgeui.w18 */
	    }
	    break;
    case 13:
	    if (Field_combined3e2c5767_fld84xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 521; /* blt.w18 */
	    }
	    break;
    case 14:
	    if (Field_combined3e2c5767_fld78xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 513; /* blti.w18 */
	    }
	    break;
    case 15:
	    if (Field_combined3e2c5767_fld86xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 523; /* bltu.w18 */
	    }
	    break;
    case 16:
	    if (Field_combined3e2c5767_fld80xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 515; /* bltui.w18 */
	    }
	    break;
    case 17:
	    if (Field_combined3e2c5767_fld90xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 527; /* bnall.w18 */
	    }
	    break;
    case 18:
	    if (Field_combined3e2c5767_fld82xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 519; /* bne.w18 */
	    }
	    break;
    case 19:
	    if (Field_combined3e2c5767_fld76xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 511; /* bnei.w18 */
	    }
	    break;
    case 20:
	    if (Field_combined3e2c5767_fld88xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 525; /* bnone.w18 */
	    }
	    break;
    case 21:
	    if (Field_combined3e2c5767_fld70xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 506; /* beqz.w18 */
	    }
	    break;
    case 22:
	    if (Field_combined3e2c5767_fld73xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 508; /* bgez.w18 */
	    }
	    break;
    case 23:
	    if (Field_combined3e2c5767_fld74xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 509; /* bltz.w18 */
	    }
	    break;
    case 24:
	    if (Field_combined3e2c5767_fld72xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 507; /* bnez.w18 */
	    }
	    break;
    case 25:
	    if (Field_combined3e2c5767_fld93xt_flix64_slot3_Slot_xt_flix64_slot3_get (insn) == 0) {
		    return 97; /* nop */
	    }
	    break;
    }
  return 0;
}


/* Instruction slots.  */

static void
Slot_x24_Format_inst_0_get (const xtensa_insnbuf insn,
			    xtensa_insnbuf slotbuf)
{
  slotbuf[1] = 0;
  slotbuf[0] = (insn[0] & 0xffffff);
}

static void
Slot_x24_Format_inst_0_set (xtensa_insnbuf insn,
			    const xtensa_insnbuf slotbuf)
{
  insn[0] = (insn[0] & ~0xffffff) | (slotbuf[0] & 0xffffff);
}

static void
Slot_x16a_Format_inst16a_0_get (const xtensa_insnbuf insn,
				xtensa_insnbuf slotbuf)
{
  slotbuf[1] = 0;
  slotbuf[0] = (insn[0] & 0xffff);
}

static void
Slot_x16a_Format_inst16a_0_set (xtensa_insnbuf insn,
				const xtensa_insnbuf slotbuf)
{
  insn[0] = (insn[0] & ~0xffff) | (slotbuf[0] & 0xffff);
}

static void
Slot_x16b_Format_inst16b_0_get (const xtensa_insnbuf insn,
				xtensa_insnbuf slotbuf)
{
  slotbuf[1] = 0;
  slotbuf[0] = (insn[0] & 0xffff);
}

static void
Slot_x16b_Format_inst16b_0_set (xtensa_insnbuf insn,
				const xtensa_insnbuf slotbuf)
{
  insn[0] = (insn[0] & ~0xffff) | (slotbuf[0] & 0xffff);
}

static void
Slot_xt_format1_Format_xt_flix64_slot0_4_get (const xtensa_insnbuf insn,
					      xtensa_insnbuf slotbuf)
{
  slotbuf[1] = 0;
  slotbuf[0] = ((insn[0] & 0xffffff0) >> 4);
}

static void
Slot_xt_format1_Format_xt_flix64_slot0_4_set (xtensa_insnbuf insn,
					      const xtensa_insnbuf slotbuf)
{
  insn[0] = (insn[0] & ~0xffffff0) | ((slotbuf[0] & 0xffffff) << 4);
}

static void
Slot_xt_format2_Format_xt_flix64_slot0_4_get (const xtensa_insnbuf insn,
					      xtensa_insnbuf slotbuf)
{
  slotbuf[1] = 0;
  slotbuf[0] = ((insn[0] & 0xffffff0) >> 4);
}

static void
Slot_xt_format2_Format_xt_flix64_slot0_4_set (xtensa_insnbuf insn,
					      const xtensa_insnbuf slotbuf)
{
  insn[0] = (insn[0] & ~0xffffff0) | ((slotbuf[0] & 0xffffff) << 4);
}

static void
Slot_xt_format1_Format_xt_flix64_slot1_28_get (const xtensa_insnbuf insn,
					      xtensa_insnbuf slotbuf)
{
  slotbuf[1] = 0;
  slotbuf[0] = ((insn[0] & 0xf0000000) >> 28);
  slotbuf[0] = (slotbuf[0] & ~0xffff0) | ((insn[1] & 0xffff) << 4);
}

static void
Slot_xt_format1_Format_xt_flix64_slot1_28_set (xtensa_insnbuf insn,
					      const xtensa_insnbuf slotbuf)
{
  insn[0] = (insn[0] & ~0xf0000000) | ((slotbuf[0] & 0xf) << 28);
  insn[1] = (insn[1] & ~0xffff) | ((slotbuf[0] & 0xffff0) >> 4);
}

static void
Slot_xt_format1_Format_xt_flix64_slot2_48_get (const xtensa_insnbuf insn,
					      xtensa_insnbuf slotbuf)
{
  slotbuf[1] = 0;
  slotbuf[0] = ((insn[1] & 0xffff0000) >> 16);
}

static void
Slot_xt_format1_Format_xt_flix64_slot2_48_set (xtensa_insnbuf insn,
					      const xtensa_insnbuf slotbuf)
{
  insn[1] = (insn[1] & ~0xffff0000) | ((slotbuf[0] & 0xffff) << 16);
}

static void
Slot_xt_format2_Format_xt_flix64_slot3_28_get (const xtensa_insnbuf insn,
					      xtensa_insnbuf slotbuf)
{
  slotbuf[0] = ((insn[0] & 0xf0000000) >> 28);
  slotbuf[0] = (slotbuf[0] & ~0xfffffff0) | ((insn[1] & 0xfffffff) << 4);
  slotbuf[1] = ((insn[1] & 0x70000000) >> 28);
}

static void
Slot_xt_format2_Format_xt_flix64_slot3_28_set (xtensa_insnbuf insn,
					      const xtensa_insnbuf slotbuf)
{
  insn[0] = (insn[0] & ~0xf0000000) | ((slotbuf[0] & 0xf) << 28);
  insn[1] = (insn[1] & ~0xfffffff) | ((slotbuf[0] & 0xfffffff0) >> 4);
  insn[1] = (insn[1] & ~0x70000000) | ((slotbuf[1] & 0x7) << 28);
}

static xtensa_get_field_fn
Slot_inst_get_field_fns[] = {
  Field_t_Slot_inst_get,
  Field_bbi4_Slot_inst_get,
  Field_bbi_Slot_inst_get,
  Field_imm12_Slot_inst_get,
  Field_imm8_Slot_inst_get,
  Field_s_Slot_inst_get,
  Field_imm12b_Slot_inst_get,
  Field_imm16_Slot_inst_get,
  Field_m_Slot_inst_get,
  Field_n_Slot_inst_get,
  Field_offset_Slot_inst_get,
  Field_op0_Slot_inst_get,
  Field_op1_Slot_inst_get,
  Field_op2_Slot_inst_get,
  Field_r_Slot_inst_get,
  Field_sa4_Slot_inst_get,
  Field_sae4_Slot_inst_get,
  Field_sae_Slot_inst_get,
  Field_sal_Slot_inst_get,
  Field_sargt_Slot_inst_get,
  Field_sas4_Slot_inst_get,
  Field_sas_Slot_inst_get,
  Field_sr_Slot_inst_get,
  Field_st_Slot_inst_get,
  Field_thi3_Slot_inst_get,
  Field_imm4_Slot_inst_get,
  Field_mn_Slot_inst_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_r3_Slot_inst_get,
  Field_rbit2_Slot_inst_get,
  Field_rhi_Slot_inst_get,
  Field_t3_Slot_inst_get,
  Field_tbit2_Slot_inst_get,
  Field_tlo_Slot_inst_get,
  Field_w_Slot_inst_get,
  Field_y_Slot_inst_get,
  Field_x_Slot_inst_get,
  Field_t2_Slot_inst_get,
  Field_s2_Slot_inst_get,
  Field_r2_Slot_inst_get,
  Field_t4_Slot_inst_get,
  Field_s4_Slot_inst_get,
  Field_r4_Slot_inst_get,
  Field_t8_Slot_inst_get,
  Field_s8_Slot_inst_get,
  Field_r8_Slot_inst_get,
  Field_xt_wbr15_imm_Slot_inst_get,
  Field_xt_wbr18_imm_Slot_inst_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_ar0_get,
  Implicit_Field_ar4_get,
  Implicit_Field_ar8_get,
  Implicit_Field_ar12_get,
  Implicit_Field_mr0_get,
  Implicit_Field_mr1_get,
  Implicit_Field_mr2_get,
  Implicit_Field_mr3_get,
  Implicit_Field_bt16_get,
  Implicit_Field_bs16_get,
  Implicit_Field_br16_get,
  Implicit_Field_brall_get
};

static xtensa_set_field_fn
Slot_inst_set_field_fns[] = {
  Field_t_Slot_inst_set,
  Field_bbi4_Slot_inst_set,
  Field_bbi_Slot_inst_set,
  Field_imm12_Slot_inst_set,
  Field_imm8_Slot_inst_set,
  Field_s_Slot_inst_set,
  Field_imm12b_Slot_inst_set,
  Field_imm16_Slot_inst_set,
  Field_m_Slot_inst_set,
  Field_n_Slot_inst_set,
  Field_offset_Slot_inst_set,
  Field_op0_Slot_inst_set,
  Field_op1_Slot_inst_set,
  Field_op2_Slot_inst_set,
  Field_r_Slot_inst_set,
  Field_sa4_Slot_inst_set,
  Field_sae4_Slot_inst_set,
  Field_sae_Slot_inst_set,
  Field_sal_Slot_inst_set,
  Field_sargt_Slot_inst_set,
  Field_sas4_Slot_inst_set,
  Field_sas_Slot_inst_set,
  Field_sr_Slot_inst_set,
  Field_st_Slot_inst_set,
  Field_thi3_Slot_inst_set,
  Field_imm4_Slot_inst_set,
  Field_mn_Slot_inst_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_r3_Slot_inst_set,
  Field_rbit2_Slot_inst_set,
  Field_rhi_Slot_inst_set,
  Field_t3_Slot_inst_set,
  Field_tbit2_Slot_inst_set,
  Field_tlo_Slot_inst_set,
  Field_w_Slot_inst_set,
  Field_y_Slot_inst_set,
  Field_x_Slot_inst_set,
  Field_t2_Slot_inst_set,
  Field_s2_Slot_inst_set,
  Field_r2_Slot_inst_set,
  Field_t4_Slot_inst_set,
  Field_s4_Slot_inst_set,
  Field_r4_Slot_inst_set,
  Field_t8_Slot_inst_set,
  Field_s8_Slot_inst_set,
  Field_r8_Slot_inst_set,
  Field_xt_wbr15_imm_Slot_inst_set,
  Field_xt_wbr18_imm_Slot_inst_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set
};

static xtensa_get_field_fn
Slot_inst16a_get_field_fns[] = {
  Field_t_Slot_inst16a_get,
  0,
  0,
  0,
  0,
  Field_s_Slot_inst16a_get,
  0,
  0,
  0,
  0,
  0,
  Field_op0_Slot_inst16a_get,
  0,
  0,
  Field_r_Slot_inst16a_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_sr_Slot_inst16a_get,
  Field_st_Slot_inst16a_get,
  0,
  Field_imm4_Slot_inst16a_get,
  0,
  Field_i_Slot_inst16a_get,
  Field_imm6lo_Slot_inst16a_get,
  Field_imm6hi_Slot_inst16a_get,
  Field_imm7lo_Slot_inst16a_get,
  Field_imm7hi_Slot_inst16a_get,
  Field_z_Slot_inst16a_get,
  Field_imm6_Slot_inst16a_get,
  Field_imm7_Slot_inst16a_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_t2_Slot_inst16a_get,
  Field_s2_Slot_inst16a_get,
  Field_r2_Slot_inst16a_get,
  Field_t4_Slot_inst16a_get,
  Field_s4_Slot_inst16a_get,
  Field_r4_Slot_inst16a_get,
  Field_t8_Slot_inst16a_get,
  Field_s8_Slot_inst16a_get,
  Field_r8_Slot_inst16a_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_ar0_get,
  Implicit_Field_ar4_get,
  Implicit_Field_ar8_get,
  Implicit_Field_ar12_get,
  Implicit_Field_mr0_get,
  Implicit_Field_mr1_get,
  Implicit_Field_mr2_get,
  Implicit_Field_mr3_get,
  Implicit_Field_bt16_get,
  Implicit_Field_bs16_get,
  Implicit_Field_br16_get,
  Implicit_Field_brall_get
};

static xtensa_set_field_fn
Slot_inst16a_set_field_fns[] = {
  Field_t_Slot_inst16a_set,
  0,
  0,
  0,
  0,
  Field_s_Slot_inst16a_set,
  0,
  0,
  0,
  0,
  0,
  Field_op0_Slot_inst16a_set,
  0,
  0,
  Field_r_Slot_inst16a_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_sr_Slot_inst16a_set,
  Field_st_Slot_inst16a_set,
  0,
  Field_imm4_Slot_inst16a_set,
  0,
  Field_i_Slot_inst16a_set,
  Field_imm6lo_Slot_inst16a_set,
  Field_imm6hi_Slot_inst16a_set,
  Field_imm7lo_Slot_inst16a_set,
  Field_imm7hi_Slot_inst16a_set,
  Field_z_Slot_inst16a_set,
  Field_imm6_Slot_inst16a_set,
  Field_imm7_Slot_inst16a_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_t2_Slot_inst16a_set,
  Field_s2_Slot_inst16a_set,
  Field_r2_Slot_inst16a_set,
  Field_t4_Slot_inst16a_set,
  Field_s4_Slot_inst16a_set,
  Field_r4_Slot_inst16a_set,
  Field_t8_Slot_inst16a_set,
  Field_s8_Slot_inst16a_set,
  Field_r8_Slot_inst16a_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set
};

static xtensa_get_field_fn
Slot_inst16b_get_field_fns[] = {
  Field_t_Slot_inst16b_get,
  0,
  0,
  0,
  0,
  Field_s_Slot_inst16b_get,
  0,
  0,
  0,
  0,
  0,
  Field_op0_Slot_inst16b_get,
  0,
  0,
  Field_r_Slot_inst16b_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_sr_Slot_inst16b_get,
  Field_st_Slot_inst16b_get,
  0,
  Field_imm4_Slot_inst16b_get,
  0,
  Field_i_Slot_inst16b_get,
  Field_imm6lo_Slot_inst16b_get,
  Field_imm6hi_Slot_inst16b_get,
  Field_imm7lo_Slot_inst16b_get,
  Field_imm7hi_Slot_inst16b_get,
  Field_z_Slot_inst16b_get,
  Field_imm6_Slot_inst16b_get,
  Field_imm7_Slot_inst16b_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_t2_Slot_inst16b_get,
  Field_s2_Slot_inst16b_get,
  Field_r2_Slot_inst16b_get,
  Field_t4_Slot_inst16b_get,
  Field_s4_Slot_inst16b_get,
  Field_r4_Slot_inst16b_get,
  Field_t8_Slot_inst16b_get,
  Field_s8_Slot_inst16b_get,
  Field_r8_Slot_inst16b_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_ar0_get,
  Implicit_Field_ar4_get,
  Implicit_Field_ar8_get,
  Implicit_Field_ar12_get,
  Implicit_Field_mr0_get,
  Implicit_Field_mr1_get,
  Implicit_Field_mr2_get,
  Implicit_Field_mr3_get,
  Implicit_Field_bt16_get,
  Implicit_Field_bs16_get,
  Implicit_Field_br16_get,
  Implicit_Field_brall_get
};

static xtensa_set_field_fn
Slot_inst16b_set_field_fns[] = {
  Field_t_Slot_inst16b_set,
  0,
  0,
  0,
  0,
  Field_s_Slot_inst16b_set,
  0,
  0,
  0,
  0,
  0,
  Field_op0_Slot_inst16b_set,
  0,
  0,
  Field_r_Slot_inst16b_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_sr_Slot_inst16b_set,
  Field_st_Slot_inst16b_set,
  0,
  Field_imm4_Slot_inst16b_set,
  0,
  Field_i_Slot_inst16b_set,
  Field_imm6lo_Slot_inst16b_set,
  Field_imm6hi_Slot_inst16b_set,
  Field_imm7lo_Slot_inst16b_set,
  Field_imm7hi_Slot_inst16b_set,
  Field_z_Slot_inst16b_set,
  Field_imm6_Slot_inst16b_set,
  Field_imm7_Slot_inst16b_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_t2_Slot_inst16b_set,
  Field_s2_Slot_inst16b_set,
  Field_r2_Slot_inst16b_set,
  Field_t4_Slot_inst16b_set,
  Field_s4_Slot_inst16b_set,
  Field_r4_Slot_inst16b_set,
  Field_t8_Slot_inst16b_set,
  Field_s8_Slot_inst16b_set,
  Field_r8_Slot_inst16b_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set
};

static xtensa_get_field_fn
Slot_xt_flix64_slot0_get_field_fns[] = {
  Field_t_Slot_xt_flix64_slot0_get,
  0,
  0,
  0,
  Field_imm8_Slot_xt_flix64_slot0_get,
  Field_s_Slot_xt_flix64_slot0_get,
  Field_imm12b_Slot_xt_flix64_slot0_get,
  Field_imm16_Slot_xt_flix64_slot0_get,
  Field_m_Slot_xt_flix64_slot0_get,
  Field_n_Slot_xt_flix64_slot0_get,
  0,
  0,
  Field_op1_Slot_xt_flix64_slot0_get,
  Field_op2_Slot_xt_flix64_slot0_get,
  Field_r_Slot_xt_flix64_slot0_get,
  0,
  Field_sae4_Slot_xt_flix64_slot0_get,
  Field_sae_Slot_xt_flix64_slot0_get,
  Field_sal_Slot_xt_flix64_slot0_get,
  Field_sargt_Slot_xt_flix64_slot0_get,
  0,
  Field_sas_Slot_xt_flix64_slot0_get,
  0,
  0,
  Field_thi3_Slot_xt_flix64_slot0_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_xt_flix64_slot0_s3_Slot_xt_flix64_slot0_get,
  Field_combined3e2c5767_fld7_Slot_xt_flix64_slot0_get,
  Field_combined3e2c5767_fld8_Slot_xt_flix64_slot0_get,
  Field_combined3e2c5767_fld9_Slot_xt_flix64_slot0_get,
  Field_combined3e2c5767_fld11_Slot_xt_flix64_slot0_get,
  Field_combined3e2c5767_fld49xt_flix64_slot0_Slot_xt_flix64_slot0_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_xt_flix64_slot0_Slot_xt_flix64_slot0_get,
  Implicit_Field_ar0_get,
  Implicit_Field_ar4_get,
  Implicit_Field_ar8_get,
  Implicit_Field_ar12_get,
  Implicit_Field_mr0_get,
  Implicit_Field_mr1_get,
  Implicit_Field_mr2_get,
  Implicit_Field_mr3_get,
  Implicit_Field_bt16_get,
  Implicit_Field_bs16_get,
  Implicit_Field_br16_get,
  Implicit_Field_brall_get
};

static xtensa_set_field_fn
Slot_xt_flix64_slot0_set_field_fns[] = {
  Field_t_Slot_xt_flix64_slot0_set,
  0,
  0,
  0,
  Field_imm8_Slot_xt_flix64_slot0_set,
  Field_s_Slot_xt_flix64_slot0_set,
  Field_imm12b_Slot_xt_flix64_slot0_set,
  Field_imm16_Slot_xt_flix64_slot0_set,
  Field_m_Slot_xt_flix64_slot0_set,
  Field_n_Slot_xt_flix64_slot0_set,
  0,
  0,
  Field_op1_Slot_xt_flix64_slot0_set,
  Field_op2_Slot_xt_flix64_slot0_set,
  Field_r_Slot_xt_flix64_slot0_set,
  0,
  Field_sae4_Slot_xt_flix64_slot0_set,
  Field_sae_Slot_xt_flix64_slot0_set,
  Field_sal_Slot_xt_flix64_slot0_set,
  Field_sargt_Slot_xt_flix64_slot0_set,
  0,
  Field_sas_Slot_xt_flix64_slot0_set,
  0,
  0,
  Field_thi3_Slot_xt_flix64_slot0_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_xt_flix64_slot0_s3_Slot_xt_flix64_slot0_set,
  Field_combined3e2c5767_fld7_Slot_xt_flix64_slot0_set,
  Field_combined3e2c5767_fld8_Slot_xt_flix64_slot0_set,
  Field_combined3e2c5767_fld9_Slot_xt_flix64_slot0_set,
  Field_combined3e2c5767_fld11_Slot_xt_flix64_slot0_set,
  Field_combined3e2c5767_fld49xt_flix64_slot0_Slot_xt_flix64_slot0_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_xt_flix64_slot0_Slot_xt_flix64_slot0_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set
};

static xtensa_get_field_fn
Slot_xt_flix64_slot1_get_field_fns[] = {
  Field_t_Slot_xt_flix64_slot1_get,
  0,
  0,
  0,
  Field_imm8_Slot_xt_flix64_slot1_get,
  Field_s_Slot_xt_flix64_slot1_get,
  Field_imm12b_Slot_xt_flix64_slot1_get,
  0,
  0,
  0,
  Field_offset_Slot_xt_flix64_slot1_get,
  0,
  0,
  Field_op2_Slot_xt_flix64_slot1_get,
  Field_r_Slot_xt_flix64_slot1_get,
  0,
  0,
  Field_sae_Slot_xt_flix64_slot1_get,
  Field_sal_Slot_xt_flix64_slot1_get,
  Field_sargt_Slot_xt_flix64_slot1_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_s4_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld16_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld19xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld20xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld21xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld22xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld23xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld25xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld26xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld28xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld30xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld32xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld33xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld35xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld51xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld52xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld53xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld54xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld57xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld58xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld60xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  Field_combined3e2c5767_fld62xt_flix64_slot1_Slot_xt_flix64_slot1_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_ar0_get,
  Implicit_Field_ar4_get,
  Implicit_Field_ar8_get,
  Implicit_Field_ar12_get,
  Implicit_Field_mr0_get,
  Implicit_Field_mr1_get,
  Implicit_Field_mr2_get,
  Implicit_Field_mr3_get,
  Implicit_Field_bt16_get,
  Implicit_Field_bs16_get,
  Implicit_Field_br16_get,
  Implicit_Field_brall_get
};

static xtensa_set_field_fn
Slot_xt_flix64_slot1_set_field_fns[] = {
  Field_t_Slot_xt_flix64_slot1_set,
  0,
  0,
  0,
  Field_imm8_Slot_xt_flix64_slot1_set,
  Field_s_Slot_xt_flix64_slot1_set,
  Field_imm12b_Slot_xt_flix64_slot1_set,
  0,
  0,
  0,
  Field_offset_Slot_xt_flix64_slot1_set,
  0,
  0,
  Field_op2_Slot_xt_flix64_slot1_set,
  Field_r_Slot_xt_flix64_slot1_set,
  0,
  0,
  Field_sae_Slot_xt_flix64_slot1_set,
  Field_sal_Slot_xt_flix64_slot1_set,
  Field_sargt_Slot_xt_flix64_slot1_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_s4_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld16_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld19xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld20xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld21xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld22xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld23xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld25xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld26xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld28xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld30xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld32xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld33xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld35xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld51xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld52xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld53xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld54xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld57xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld58xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld60xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  Field_combined3e2c5767_fld62xt_flix64_slot1_Slot_xt_flix64_slot1_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set
};

static xtensa_get_field_fn
Slot_xt_flix64_slot2_get_field_fns[] = {
  Field_t_Slot_xt_flix64_slot2_get,
  0,
  0,
  0,
  0,
  Field_s_Slot_xt_flix64_slot2_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_r_Slot_xt_flix64_slot2_get,
  0,
  0,
  0,
  0,
  Field_sargt_Slot_xt_flix64_slot2_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_imm7_Slot_xt_flix64_slot2_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_s5_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld36xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld37xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld39xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld41xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld42xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld44xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld45xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld47xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld63xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld64xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld65xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld66xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  Field_combined3e2c5767_fld68xt_flix64_slot2_Slot_xt_flix64_slot2_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_ar0_get,
  Implicit_Field_ar4_get,
  Implicit_Field_ar8_get,
  Implicit_Field_ar12_get,
  Implicit_Field_mr0_get,
  Implicit_Field_mr1_get,
  Implicit_Field_mr2_get,
  Implicit_Field_mr3_get,
  Implicit_Field_bt16_get,
  Implicit_Field_bs16_get,
  Implicit_Field_br16_get,
  Implicit_Field_brall_get
};

static xtensa_set_field_fn
Slot_xt_flix64_slot2_set_field_fns[] = {
  Field_t_Slot_xt_flix64_slot2_set,
  0,
  0,
  0,
  0,
  Field_s_Slot_xt_flix64_slot2_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_r_Slot_xt_flix64_slot2_set,
  0,
  0,
  0,
  0,
  Field_sargt_Slot_xt_flix64_slot2_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_imm7_Slot_xt_flix64_slot2_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_s5_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld36xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld37xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld39xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld41xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld42xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld44xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld45xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld47xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld63xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld64xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld65xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld66xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  Field_combined3e2c5767_fld68xt_flix64_slot2_Slot_xt_flix64_slot2_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set
};

static xtensa_get_field_fn
Slot_xt_flix64_slot3_get_field_fns[] = {
  Field_t_Slot_xt_flix64_slot3_get,
  0,
  Field_bbi_Slot_xt_flix64_slot3_get,
  0,
  0,
  Field_s_Slot_xt_flix64_slot3_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_r_Slot_xt_flix64_slot3_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_xt_wbr18_imm_Slot_xt_flix64_slot3_get,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_s6_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld70xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld71_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld72xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld73xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld74xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld75xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld76xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld77xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld78xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld79xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld80xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld81xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld82xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld83xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld84xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld85xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld86xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld87xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld88xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld89xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld90xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld91xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld92xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  Field_combined3e2c5767_fld93xt_flix64_slot3_Slot_xt_flix64_slot3_get,
  0,
  Implicit_Field_ar0_get,
  Implicit_Field_ar4_get,
  Implicit_Field_ar8_get,
  Implicit_Field_ar12_get,
  Implicit_Field_mr0_get,
  Implicit_Field_mr1_get,
  Implicit_Field_mr2_get,
  Implicit_Field_mr3_get,
  Implicit_Field_bt16_get,
  Implicit_Field_bs16_get,
  Implicit_Field_br16_get,
  Implicit_Field_brall_get
};

static xtensa_set_field_fn
Slot_xt_flix64_slot3_set_field_fns[] = {
  Field_t_Slot_xt_flix64_slot3_set,
  0,
  Field_bbi_Slot_xt_flix64_slot3_set,
  0,
  0,
  Field_s_Slot_xt_flix64_slot3_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_r_Slot_xt_flix64_slot3_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_xt_wbr18_imm_Slot_xt_flix64_slot3_set,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  0,
  Field_op0_s6_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld70xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld71_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld72xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld73xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld74xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld75xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld76xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld77xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld78xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld79xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld80xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld81xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld82xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld83xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld84xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld85xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld86xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld87xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld88xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld89xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld90xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld91xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld92xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  Field_combined3e2c5767_fld93xt_flix64_slot3_Slot_xt_flix64_slot3_set,
  0,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set,
  Implicit_Field_set
};

static xtensa_slot_internal slots[] = {
  { "Inst", "x24", 0,
    Slot_x24_Format_inst_0_get, Slot_x24_Format_inst_0_set,
    Slot_inst_get_field_fns, Slot_inst_set_field_fns,
    Slot_inst_decode, "nop" },
  { "Inst16a", "x16a", 0,
    Slot_x16a_Format_inst16a_0_get, Slot_x16a_Format_inst16a_0_set,
    Slot_inst16a_get_field_fns, Slot_inst16a_set_field_fns,
    Slot_inst16a_decode, "" },
  { "Inst16b", "x16b", 0,
    Slot_x16b_Format_inst16b_0_get, Slot_x16b_Format_inst16b_0_set,
    Slot_inst16b_get_field_fns, Slot_inst16b_set_field_fns,
    Slot_inst16b_decode, "nop.n" },
  { "xt_flix64_slot0", "xt_format1", 0,
    Slot_xt_format1_Format_xt_flix64_slot0_4_get, Slot_xt_format1_Format_xt_flix64_slot0_4_set,
    Slot_xt_flix64_slot0_get_field_fns, Slot_xt_flix64_slot0_set_field_fns,
    Slot_xt_flix64_slot0_decode, "nop" },
  { "xt_flix64_slot0", "xt_format2", 0,
    Slot_xt_format2_Format_xt_flix64_slot0_4_get, Slot_xt_format2_Format_xt_flix64_slot0_4_set,
    Slot_xt_flix64_slot0_get_field_fns, Slot_xt_flix64_slot0_set_field_fns,
    Slot_xt_flix64_slot0_decode, "nop" },
  { "xt_flix64_slot1", "xt_format1", 1,
    Slot_xt_format1_Format_xt_flix64_slot1_28_get, Slot_xt_format1_Format_xt_flix64_slot1_28_set,
    Slot_xt_flix64_slot1_get_field_fns, Slot_xt_flix64_slot1_set_field_fns,
    Slot_xt_flix64_slot1_decode, "nop" },
  { "xt_flix64_slot2", "xt_format1", 2,
    Slot_xt_format1_Format_xt_flix64_slot2_48_get, Slot_xt_format1_Format_xt_flix64_slot2_48_set,
    Slot_xt_flix64_slot2_get_field_fns, Slot_xt_flix64_slot2_set_field_fns,
    Slot_xt_flix64_slot2_decode, "nop" },
  { "xt_flix64_slot3", "xt_format2", 1,
    Slot_xt_format2_Format_xt_flix64_slot3_28_get, Slot_xt_format2_Format_xt_flix64_slot3_28_set,
    Slot_xt_flix64_slot3_get_field_fns, Slot_xt_flix64_slot3_set_field_fns,
    Slot_xt_flix64_slot3_decode, "nop" }
};


/* Instruction formats.  */

static void
Format_x24_encode (xtensa_insnbuf insn)
{
  insn[0] = 0;
  insn[1] = 0;
}

static void
Format_x16a_encode (xtensa_insnbuf insn)
{
  insn[0] = 0x8;
  insn[1] = 0;
}

static void
Format_x16b_encode (xtensa_insnbuf insn)
{
  insn[0] = 0xc;
  insn[1] = 0;
}

static void
Format_xt_format1_encode (xtensa_insnbuf insn)
{
  insn[0] = 0xe;
  insn[1] = 0;
}

static void
Format_xt_format2_encode (xtensa_insnbuf insn)
{
  insn[0] = 0xf;
  insn[1] = 0;
}

static int Format_x24_slots[] = { 0 };

static int Format_x16a_slots[] = { 1 };

static int Format_x16b_slots[] = { 2 };

static int Format_xt_format1_slots[] = { 3, 5, 6 };

static int Format_xt_format2_slots[] = { 4, 7 };

static xtensa_format_internal formats[] = {
  { "x24", 3, Format_x24_encode, 1, Format_x24_slots },
  { "x16a", 2, Format_x16a_encode, 1, Format_x16a_slots },
  { "x16b", 2, Format_x16b_encode, 1, Format_x16b_slots },
  { "xt_format1", 8, Format_xt_format1_encode, 3, Format_xt_format1_slots },
  { "xt_format2", 8, Format_xt_format2_encode, 2, Format_xt_format2_slots }
};


static int
format_decoder (const xtensa_insnbuf insn)
{
	if ((insn[0] & 0x8) == 0 && (insn[1] & 0) == 0) {
		return 0; /* x24 */
	}
	if ((insn[0] & 0xc) == 0x8 && (insn[1] & 0) == 0) {
		return 1; /* x16a */
	}
	if ((insn[0] & 0xe) == 0xc && (insn[1] & 0) == 0) {
		return 2; /* x16b */
	}
	if ((insn[0] & 0xf) == 0xe && (insn[1] & 0) == 0) {
		return 3; /* xt_format1 */
	}
	if ((insn[0] & 0xf) == 0xf && (insn[1] & 0x80000000) == 0) {
		return 4; /* xt_format2 */
	}
	return -1;
}

static int length_table[16] = {
  3,
  3,
  3,
  3,
  3,
  3,
  3,
  3,
  2,
  2,
  2,
  2,
  2,
  2,
  8,
  8
};

static int
length_decoder (const unsigned char *insn)
{
  int op0 = insn[0] & 0xf;
  return length_table[op0];
}


/* Top-level ISA structure.  */

xtensa_isa_internal xtensa_modules = {
  0 /* little-endian */,
  8 /* insn_size */, 0,
  5, formats, format_decoder, length_decoder,
  8, slots,
  135 /* num_fields */,
  188, operands,
  355, iclasses,
  530, opcodes, 0,
  8, regfiles,
  NUM_STATES, states, 0,
  NUM_SYSREGS, sysregs, 0,
  { MAX_SPECIAL_REG, MAX_USER_REG }, { 0, 0 },
  0, interfaces, 0,
  0, funcUnits, 0
};
