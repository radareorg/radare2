/* NDS32-specific support for 32-bit ELF.
   Copyright (C) 2012-2013 Free Software Foundation, Inc.
   Contributed by Andes Technology Corporation.

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
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.*/

#include "../../include/sysdep.h"
#include "../../include/mybfd.h"
#include "../../include/disas-asm.h"
#include "../arm/gnu/floatformat.h"
#include "../../include/libiberty.h"
#include "../../include/opintl.h"

#undef OP6
#undef RA5
/* Get fields */
#define OP6(insn)	((insn >> 25) & 0x3F)
#define RT5(insn)	((insn >> 20) & 0x1F)
#define RA5(insn)	((insn >> 15) & 0x1F)
#define RB5(insn)	((insn >> 10) & 0x1F)
#define RD5(insn)	((insn >> 5) & 0x1F)
#define SUB5(insn)	((insn >> 0) & 0x1F)
#define SUB10(insn)	((insn >> 0) & 0x3FF)
#define IMMU(insn, bs)	(insn & ((1 << bs) - 1))
#define IMMS(insn, bs)	__SEXT ((insn & ((1 << bs) - 1)), bs)
#define IMM1U(insn)	IMMU ((insn >> 10), 5)
#define IMM1S(insn)	IMMS ((insn >> 10), 5)
#define IMM2U(insn)	IMMU ((insn >> 5), 5)
#define IMM2S(insn)	IMMS ((insn >> 5), 5)

/* Default text to print if an instruction isn't recognized.  */
#define UNKNOWN_INSN_MSG _("*unknown*")

static const char *mnemonic_op6[] =
{
  "lbi",  "lhi",   "lwi",  "ldi",    "lbi.bi",  "lhi.bi",  "lwi.bi",  "ldi.bi",
  "sbi",  "shi",   "swi",  "sdi",    "sbi.bi",  "shi.bi",  "swi.bi",  "sdi.bi",
  "lbsi", "lhsi",  "lwsi", "dprefi", "lbsi.bi", "lhsi.bi", "lwsi.bi", "lbgp",
  "lwc",  "swc",   "ldc",  "sdc",    "mem",     "lsmw",    "hwgp",    "sbgp",
  "alu1", "alu2",  "movi", "sethi",  "ji",      "jreg",    "br1",     "br2",
  "addi", "subri", "andi", "xori",   "ori",     "br3",     "slti",    "sltsi",
  "aext", "cext",  "misc", "bitci",  "op_64",   "cop"
};

static const char *mnemonic_mem[] =
{
  "lb",   "lh",  "lw",   "ld",    "lb.bi",  "lh.bi",  "lw.bi",  "ld.bi",
  "sb",   "sh",  "sw",   "sd",    "sb.bi",  "sh.bi",  "sw.bi",  "sd.bi",
  "lbs",  "lhs", "lws",  "dpref", "lbs.bi", "lhs.bi", "lws.bi", "27",
  "llw",  "scw", "32",   "33",    "34",     "35",     "36",     "37",
  "lbup", "41",  "lwup", "43",    "44",     "45",     "46",     "47",
  "sbup", "51",  "swup"
};

static const char *mnemonic_alu1[] =
{
  "add",  "sub",  "and",   "xor",   "or",       "nor",      "slt",      "slts",
  "slli", "srli", "srai",  "rotri", "sll",      "srl",      "sra",      "rotr",
  "seb",  "seh",  "bitc",  "zeh",   "wsbh",     "or_srli",  "divsr",    "divr",
  "sva",  "svs",  "cmovz", "cmovn", "add_srli", "sub_srli", "and_srli", "xor_srli"
};


static const char *mnemonic_alu20[] =
{
  "max",     "min",    "ave",     "abs",    "clips",   "clip",   "clo",    "clz",
  "bset",    "bclr",   "btgl",    "btst",   "bse",     "bsp",    "ffb",    "ffmism",
  "add.sc",  "sub.sc", "add.wc",  "sub.wc", "24",      "25",     "26",     "ffzmism",
  "qadd",    "qsub",   "32",      "33",     "34",      "35",     "36",     "37",
  "mfusr",   "mtusr",  "42",      "43",     "mul",     "45",     "46",     "47",
  "mults64", "mult64", "madds64", "madd64", "msubs64", "msub64", "divs", "div",
  "60",      "mult32", "62",      "madd32", "64",      "msub32", "65",   "66",
  "dmadd",   "dmaddc", "dmsub",   "dmsubc", "rmfhi",   "qmflo"
};

static const char *mnemonic_alu21[] =
{
  "00",      "01",     "02", "03",      "04", "05",      "06",   "07",
  "10",      "11",     "12", "13",      "14", "15",      "ffbi", "flmism",
  "20",      "21",     "22", "23",      "24", "25",      "26",   "27",
  "30",      "31",     "32", "33",      "34", "35",      "36",   "37",
  "40",      "41",     "42", "43",      "44", "45",      "46",   "47",
  "mulsr64", "mulr64", "52", "53",      "54", "55",      "56",   "57",
  "60",      "61",     "62", "maddr32", "64", "msubr32", "66",   "67",
  "70",      "71",     "72", "73",      "74", "75",      "76",   "77"
};

static const char *mnemonic_br2[] =
{
  "ifcall", "01", "beqz", "bnez", "bgez",   "bltz",   "bgtz", "blez",
  "10",     "11", "12",   "13",   "bgezal", "bltzal", "b16", "?"
};

static const char *mnemonic_misc[] =
{
  "standby", "cctl", "mfsr",  "mtsr",    "iret",  "trap",  "teqz", "tnez",
  "dsb",     "isb",  "break", "syscall", "msync", "isync", "tlbop", "?"
};

static const char *mnemonic_hwgp[] =
{
  "lhi.gp", "lhi.gp", "lhsi.gp", "lhsi.gp",
  "shi.gp", "shi.gp", "lwi.gp", "swi.gp"
};

static const char *keyword_dpref[] =
{
  "SRD", "MRD", "SWR", "MWR", "PTE", "CLWR", "6",  "7",
  "8",   "9",   "10",  "11",  "12",  "13",   "14", "15"
};

static const char *mnemonic_alu[] =
{
  "fadds",   "fsubs",   "fcpynss", "fcpyss",  "fmadds",
  "fmsubs",  "fcmovns", "fcmovzs", "fnmadds", "fnmsubs",
  "10",      "11",      "fmuls",   "fdivs",   "faddd",
  "fsubd",   "fcpynsd", "fcpysd",  "fmaddd",  "fmsubd",
  "fcmovnd", "fcmovzd", "fnmaddd", "fnmsubd", "24",
  "25",      "fmuld",   "fdivd"
};

static const char *mnemonic_fpu_2op[] =
{
  "fs2d",  "fsqrts",  "2",     "3",  "4",       "fabss",  "6",      "7",
  "fui2s", "9",       "10",    "11", "fsi2s",   "13",     "14",     "15",
  "fs2ui", "17",      "18",    "19", "fs2ui.z", "21",     "22",     "23",
  "fs2si", "25",      "26",    "27", "fs2si.z", "fd2s",   "fsqrtd", "31",
  "32",    "33",      "fabsd", "35", "36",      "fui2d",  "38",     "39",
  "40",    "fsi2d",   "42",    "43", "44",      "fd2ui",  "46",     "47",
  "48",    "fd2ui.z", "50",    "51", "52",      "fd2si",  "54",     "55",
  "56",    "fd2si.z"
};

static const char *mnemonic_fs2_cmp[] =
{
  "fcmpeqs", "fcmpeqs.e", "fcmplts", "fcmplts.e",
  "fcmples", "fcmples.e", "fcmpuns", "fcmpuns.e",
  "fcmp.unk0", "fcmp.unk1",
};

static const char *mnemonic_fd2_cmp[] =
{
  "fcmpeqd", "fcmpeqd.e", "fcmpltd", "fcmpltd.e",
  "fcmpled", "fcmpled.e", "fcmpund", "fcmpund.e"
};

/* Register name table.  */
/* General purpose register.  */

static const char *gpr_map[] =
{
  "$a0", "$a1", "$a2", "$a3", "$a4", "$a5", "$s0", "$s1",
  "$s2", "$s3", "$s4", "$s5", "$s6", "$s7", "$s8", "$ta",
  "$t0", "$t1", "$t2", "$t3", "$t4", "$t5", "$t6", "$t7",
  "$t8", "$t9", "$p0", "$p1", "$fp", "$gp", "$lp", "$sp"
};

/* User special register.  */

static const char *usr_map[][32] =
{
  {
    "d0.lo", "d0.hi", "d1.lo", "d1.hi", "4",  "5",  "6",  "7",
    "8",     "9",     "10",    "11",    "12", "13", "14", "15",
    "16",    "17",    "18",    "19",    "20", "21", "22", "23",
    "24",    "25",    "26",    "27",    "28", "29", "30", "pc"
  },
  {
    "DMA_CFG",     "DMA_GCSW",    "DMA_CHNSEL", "DMA_ACT",    "DMA_SETUP",
    "DMA_ISADDR",  "DMA_ESADDR",  "DMA_TCNT",   "DMA_STATUS", "DMA_2DSET",
    "10",          "11",          "12",         "13",         "14",
    "15",          "16",          "17",         "18",         "19",
    "20",          "21",          "22",         "23",         "24",
    "DMA_2DSCTL"
  },
  {
    "PFMC0", "PFMC1", "PFMC2", "3", "PFM_CTL"
  }
};

/* System register.  */
/* Major Minor Extension.  */
static const char *sr_map[8][16][8] =
{
  {
    {"CPU_VER", "CORE_ID"},
    {"ICM_CFG"},
    {"DCM_CFG"},
    {"MMU_CFG"},
    {"MSC_CFG"}
  },
  {
    {"PSW", "IPSW", "P_IPSW"},
    {"0", "IVB", "INT_CTRL"},
    {"0", "EVA", "P_EVA"},
    {"0", "ITYPE", "P_ITYPE"},
    {"0", "MERR"},
    {"0", "IPC", "P_IPC", "OIPC"},
    {"0", "1", "P_P0"},
    {"0", "1", "P_P1"},
    {"INT_MASK", "INT_MASK2"},
    {"INT_PEND", "INT_PEND2", "2", "3", "INT_TRIGGER"},
    {"SP_USR", "SP_PRIV"},
    {"INT_PRI", "INT_PRI2"}
  },
  {
    {"MMU_CTL"},
    {"L1_PPTB"},
    {"TLB_VPN"},
    {"TLB_DATA"},
    {"TLB_MISC"},
    {"VLPT_IDX"},
    {"ILMB"},
    {"DLMB"},
    {"CACHE_CTL"},
    {"HSMP_SADDR", "HSMP_EADDR"},
    {"0"},
    {"0"},
    {"0"},
    {"0"},
    {"0"},
    {"SDZ_CTL", "MISC_CTL"}
  },
  {
    {"BPC0", "BPC1", "BPC2", "BPC3", "BPC4", "BPC5", "BPC6", "BPC7"},
    {"BPA0", "BPA1", "BPA2", "BPA3", "BPA4", "BPA5", "BPA6", "BPA7"},
    {"BPAM0", "BPAM1", "BPAM2", "BPAM3", "BPAM4", "BPAM5", "BPAM6", "BPAM7"},
    {"BPV0", "BPV1", "BPV2", "BPV3", "BPV4", "BPV5", "BPV6", "BPV7"},
    {"BPCID0", "BPCID1", "BPCID2", "BPCID3", "BPCID4", "BPCID5", "BPCID6", "BPCID7"},
    {"EDM_CFG"},
    {"EDMSW"},
    {"EDM_CTL"},
    {"EDM_DTR"},
    {"BPMTC"},
    {"DIMBR"},
    {"EDM_PROBE"},
    {"0"},
    {"0"},
    {"TECR0", "TECR1"}
  },
  {
    {"PFMC0", "PFMC1", "PFMC2"},
    {"PFM_CTL"},
    {"0"},
    {"0"},
    {"PRUSR_ACC_CTL"},
    {"FUCOP_CTL"}
  },
  {
    {"DMA_CFG"},
    {"DMA_GCSW"},
    {"DMA_CHNSEL"},
    {"DMA_ACT"},
    {"DMA_SETUP"},
    {"DMA_ISADDR"},
    {"DMA_ESADDR"},
    {"DMA_TCNT"},
    {"DMA_STATUS"},
    {"DMA_2DSET", "DMA_2DSCTL"}
  }
};

static void
print_insn16 (bfd_vma pc, disassemble_info *info, uint32_t insn)
{
  static char r4map[] =
    {
      0, 1, 2, 3, 4, 5, 6, 7,
      8, 9, 10, 11, 16, 17, 18, 19
    };
  const int rt5 = __GF (insn, 5, 5);
  const int ra5 = __GF (insn, 0, 5);
  const int rt4 = r4map[__GF (insn, 5, 4)];
  const int imm5u = IMMU (insn, 5);
  const int imm9u = IMMU (insn, 9);
  const int rt3 = __GF (insn, 6, 3);
  const int ra3 = __GF (insn, 3, 3);
  const int rb3 = __GF (insn, 0, 3);
  const int rt38 = __GF (insn, 8, 3);
  const int imm3u = rb3;
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;

  static const char *mnemonic_96[] =
  {
    "0x1",        "0x1",       "0x2",     "0x3",
    "add45",      "sub45",     "addi45",  "subi45",
    "srai45",     "srli45",    "slli333", "0xb",
    "add333",     "sub333",    "addi333", "subi333",
    "lwi333",     "lwi333.bi", "lhi333",  "lbi333",
    "swi333",     "swi333.bi", "shi333",  "sbi333",
    "addri36.sp", "lwi45.fe",  "lwi450",  "swi450",
    "0x1c",       "0x1d",      "0x1e",    "0x1f",
    "0x20",       "0x21",      "0x22",    "0x23",
    "0x24",       "0x25",      "0x26",    "0x27",
    "0x28",       "0x29",      "0x2a",    "0x2b",
    "0x2c",       "0x2d",      "0x2e",    "0x2f",
    "slts45",     "slt45",     "sltsi45", "slti45",
    "0x34",       "0x35",      "0x36",    "0x37",
    "0x38",       "0x39",      "0x3a",    "0x3b",
    "ifcall9",    "movpi45"
  };

  static const char *mnemonic_misc33[] =
  {
    "misc33_0", "misc33_1", "neg33", "not33", "mul33", "xor33", "and33", "or33",
  };

  static const char *mnemonic_0xb[] =
  {
    "zeb33", "zeh33", "seb33", "seh33", "xlsb33", "x11b33", "bmski33", "fexti33"
  };

  static const char *mnemonic_bnes38[] =
  {
    "jr5", "jral5", "ex9.it", "?", "ret5", "add5.pc"
  };

  switch (__GF (insn, 7, 8))
    {
    case 0xf8:			/* push25 */
    case 0xf9:			/* pop25 */
      {
	uint32_t res[] = { 6, 8, 10, 14 };
	uint32_t re = res[__GF (insn, 5, 2)];

	func (stream, "%s\t%s, %d", (insn & __BIT (7)) ? "pop25" : "push25",
	      gpr_map[re], imm5u << 3);
      }
      return;
    }

  if (__GF (insn, 8, 7) == 0x7d)	/* movd44 */
    {
      int rt5e = __GF (insn, 4, 4) << 1;
      int ra5e = IMMU (insn, 4) << 1;

      func (stream, "movd44\t%s, %d", gpr_map[rt5e], ra5e);
      return;
    }

  switch (__GF (insn, 9, 6))
    {
    case 0x4:			/* add45 */
    case 0x5:			/* sub45 */
    case 0x30:			/* slts45 */
    case 0x31:			/* slt45 */
      func (stream, "%s\t%s, %s", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt4], gpr_map[ra5]);
      return;
    case 0x6:			/* addi45 */
    case 0x7:			/* subi45 */
    case 0x8:			/* srai45 */
    case 0x9:			/* srli45 */
    case 0x32:			/* sltsi45 */
    case 0x33:			/* slti45 */
      func (stream, "%s\t%s, %d", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt4], ra5);
      return;
    case 0xc:			/* add333 */
    case 0xd:			/* sub333 */
      func (stream, "%s\t%s, %s, %s", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt3], gpr_map[ra3], gpr_map[rb3]);
      return;
    case 0xa:			/* slli333 */
    case 0xe:			/* addi333 */
    case 0xf:			/* subi333 */
      func (stream, "%s\t%s, %s, %d", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt3], gpr_map[ra3], imm3u);
      return;
    case 0x10:			/* lwi333 */
    case 0x14:			/* swi333 */
      func (stream, "%s\t%s, [%s + %d]", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt3], gpr_map[ra3], imm3u << 2);
      return;
    case 0x12:			/* lhi333 */
    case 0x16:			/* shi333 */
      func (stream, "%s\t%s, [%s + %d]", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt3], gpr_map[ra3], imm3u << 1);
      return;
    case 0x13:			/* lbi333 */
    case 0x17:			/* sbi333 */
      func (stream, "%s\t%s, [%s + %d]", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt3], gpr_map[ra3], imm3u);
      return;
    case 0x11:			/* lwi333.bi */
    case 0x15:			/* swi333.bi */
      func (stream, "%s\t%s, [%s], %d", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt3], gpr_map[ra3], imm3u << 2);
      return;
    case 0x18:			/* addri36.sp */
      func (stream, "%s\t%s, %d", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt3], IMMU (insn, 6) << 2);
      return;
    case 0x19:			/* lwi45.fe */
      func (stream, "%s\t%s, %d", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt4], -((32 - imm5u) << 2));
      return;
    case 0x1a:			/* lwi450 */
    case 0x1b:			/* swi450 */
      func (stream, "%s\t%s, [%s]", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt4], gpr_map[ra5]);
      return;
    case 0x34:			/* beqzs8, bnezs8 */
      func (stream, "%s\t", ((insn & __BIT (8)) ? "bnezs8" : "beqzs8"));
      info->print_address_func ((IMMS (insn, 8) << 1) + pc, info);
      return;
    case 0x35:			/* break16, ex9.it */
      /* FIXME: Check bfd_mach.  */
      if (imm9u < 32)		/* break16 */
        func (stream, "break16\t%d", imm9u);
      else
        func (stream, "ex9.it\t%d", imm9u);
      return;
    case 0x3c:			/* ifcall9 */
      func (stream, "%s\t", mnemonic_96[__GF (insn, 9, 6)]);
      info->print_address_func ((IMMU (insn, 9) << 1) + pc, info);
      return;
    case 0x3d:			/* movpi45 */
      func (stream, "%s\t%s, %d", mnemonic_96[__GF (insn, 9, 6)],
	    gpr_map[rt4], ra5 + 16);
      return;
    case 0x3f:			/* MISC33 */
      func (stream, "%s\t%s, %s", mnemonic_misc33[rb3],
	    gpr_map[rt3], gpr_map[ra3]);
      return;
    case 0xb:			/* ...  */
      func (stream, "%s\t%s, %s", mnemonic_0xb[rb3],
	   gpr_map[rt3], gpr_map[ra3]);
      return;
    }

  switch (__GF (insn, 10, 5))
    {
    case 0x0:			/* mov55 or ifret16 */
      /* FIXME: Check bfd_mach.  */
      if (rt5 == ra5 && rt5 == 31)
        func (stream, "ifret16");
      else
        func (stream, "mov55\t%s, %s", gpr_map[rt5], gpr_map[ra5]);
      return;
    case 0x1:			/* movi55 */
      func (stream, "movi55\t%s, %d", gpr_map[rt5], IMMS (insn, 5));
      return;
    case 0x1b:			/* addi10s (V2) */
      func (stream, "addi10s\t%d", IMMS (insn, 10));
      return;
    }

  switch (__GF (insn, 11, 4))
    {
    case 0x7:			/* lwi37.fp/swi37.fp */
      func (stream, "%s\t%s, [$fp + 0x%x]",
	    ((insn & __BIT (7)) ? "swi37" : "lwi37"),
	    gpr_map[rt38], IMMU (insn, 7) << 2);
      return;
    case 0x8:			/* beqz38 */
    case 0x9:			/* bnez38 */
      func (stream, "%s\t%s, ",
	    ((__GF (insn, 11, 4) & 1) ? "bnez38" : "beqz38"), gpr_map[rt38]);
      info->print_address_func ((IMMS (insn, 8) << 1) + pc, info);
      return;
    case 0xa:			/* beqs38/j8, implied r5 */
      if (rt38 == 5)
	{
	  func (stream, "j8\t");
	  info->print_address_func ((IMMS (insn, 8) << 1) + pc, info);
	}
     else
	{
	  func (stream, "beqs38\t%s, ", gpr_map[rt38]);
	  info->print_address_func ((IMMS (insn, 8) << 1) + pc, info);
	}
      return;
    case 0xb:			/* bnes38 and others */
      if (rt38 == 5)
	{
	  switch (__GF (insn, 5, 3))
	    {
	    case 0:		/* jr5 */
	    case 1:		/* jral5 */
	    case 4:		/* ret5 */
	      func (stream, "%s\t%s", mnemonic_bnes38[__GF (insn, 5, 3)],
		    gpr_map[ra5]);
	      return;
	    case 2:		/* ex9.it imm5 */
	    case 5:		/* add5.pc */
	      func (stream, "%s\t%d", mnemonic_bnes38[__GF (insn, 5, 3)], ra5);
	      return;
	    default:
	      func (stream, UNKNOWN_INSN_MSG);
	      return;
	    }
	}
      else
	{
	  func (stream, "bnes38\t%s", gpr_map[rt3]);
	  info->print_address_func ((IMMS (insn, 8) << 1) + pc, info);
	}
      return;
    case 0xe:			/* lwi37/swi37 */
      func (stream, "%s\t%s, [+ 0x%x]",
	    ((insn & __BIT (7)) ? "swi37.sp" : "lwi37.sp"),
	    gpr_map[rt38], IMMU (insn, 7) << 2);
      return;
    }
}


static void
print_insn32_mem (bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info *info,
		  uint32_t insn)
{
  const int rt = RT5 (insn);
  const int ra = RA5 (insn);
  const int rb = RB5 (insn);
  const int sv = __GF (insn, 8, 2);
  const int op = insn & 0xFF;
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;

  switch (op)
    {
    case 0x0:			/* lb */
    case 0x1:			/* lh */
    case 0x2:			/* lw */
    case 0x3:			/* ld */
    case 0x8:			/* sb */
    case 0x9:			/* sh */
    case 0xa:			/* sw */
    case 0xb:			/* sd */
    case 0x10:			/* lbs */
    case 0x11:			/* lhs */
    case 0x12:			/* lws */
    case 0x18:			/* llw */
    case 0x19:			/* scw */
    case 0x20:			/* lbup */
    case 0x22:			/* lwup */
    case 0x28:			/* sbup */
    case 0x2a:			/* swup */
      func (stream, "%s\t%s, [%s + (%s << %d)]",
	    mnemonic_mem[op], gpr_map[rt], gpr_map[ra], gpr_map[rb], sv);
      break;
    case 0x4:			/* lb.bi */
    case 0x5:			/* lh.bi */
    case 0x6:			/* lw.bi */
    case 0x7:			/* ld.bi */
    case 0xc:			/* sb.bi */
    case 0xd:			/* sh.bi */
    case 0xe:			/* sw.bi */
    case 0xf:			/* sd.bi */
    case 0x14:			/* lbs.bi */
    case 0x15:			/* lhs.bi */
    case 0x16:			/* lws.bi */
      func (stream, "%s\t%s, [%s], (%s << %d)",
	    mnemonic_mem[op], gpr_map[rt], gpr_map[ra], gpr_map[rb], sv);
      break;
    case 0x13:			/* dpref */
      {
	const char *subtype = "???";

	if ((rt & 0xf) < ARRAY_SIZE (keyword_dpref))
	  subtype = keyword_dpref[rt & 0xf];

	func (stream, "%s\t%s, [%s + (%s << %d)]",
	      "dpref", subtype, gpr_map[ra], gpr_map[rb], sv);
      }
      break;
    default:
      func (stream, UNKNOWN_INSN_MSG);
      return;
    }
}

static void
print_insn32_alu1 (bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info *info, uint32_t insn)
{
  int op = insn & 0x1f;
  const int rt = RT5 (insn);
  const int ra = RA5 (insn);
  const int rb = RB5 (insn);
  const int rd = RD5 (insn);
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;

  switch (op)
    {
    case 0x0:			/* add, add_slli */
    case 0x1:			/* sub, sub_slli */
    case 0x2:			/* and, add_slli */
    case 0x3:			/* xor, xor_slli */
    case 0x4:			/* or, or_slli */
      if (rd != 0)
	{
	  func (stream, "%s_slli\t%s, %s, %s, #%d",
	        mnemonic_alu1[op], gpr_map[rt], gpr_map[ra], gpr_map[rb], rd);
	}
      else
	{
	  func (stream, "%s\t%s, %s, %s",
	        mnemonic_alu1[op], gpr_map[rt], gpr_map[ra], gpr_map[rb]);
	}
      return;
    case 0x1c:			/* add_srli */
    case 0x1d:			/* sub_srli */
    case 0x1e:			/* and_srli */
    case 0x1f:			/* xor_srli */
    case 0x15:			/* or_srli */
      func (stream, "%s\t%s, %s, %s, #%d",
	    mnemonic_alu1[op], gpr_map[rt], gpr_map[ra], gpr_map[rb], rd);
      return;
    case 0x5:			/* nor */
    case 0x6:			/* slt */
    case 0x7:			/* slts */
    case 0xc:			/* sll */
    case 0xd:			/* srl */
    case 0xe:			/* sra */
    case 0xf:			/* rotr */
    case 0x12:			/* bitc */
    case 0x18:			/* sva */
    case 0x19:			/* svs */
    case 0x1a:			/* cmovz */
    case 0x1b:			/* cmovn */
      func (stream, "%s\t%s, %s, %s",
	    mnemonic_alu1[op], gpr_map[rt], gpr_map[ra], gpr_map[rb]);
      return;
    case 0x9:			/* srli */
      if (ra ==0 && rb == 0 && rb==0)
	{
	  func (stream, "nop");
	  return;
	}
    case 0x8:			/* slli */
    case 0xa:			/* srai */
    case 0xb:			/* rotri */
      func (stream, "%s\t%s, %s, #%d",
	    mnemonic_alu1[op], gpr_map[rt], gpr_map[ra], rb);
      return;
    case 0x10:			/* seb */
    case 0x11:			/* seh */
    case 0x13:			/* zeh */
    case 0x14:			/* wsbh */
      func (stream, "%s\t%s, %s",
	    mnemonic_alu1[op], gpr_map[rt], gpr_map[ra]);
      return;
    case 0x16:			/* divsr */
    case 0x17:			/* divr */
      func (stream, "%s\t%s, %s, %s, %s",
	    mnemonic_alu1[op], gpr_map[rt], gpr_map[rd], gpr_map[ra], gpr_map[rb]);
      return;
    default:
      func (stream, UNKNOWN_INSN_MSG);
      return;
    }

  return;
}

static void
print_insn32_alu2 (bfd_vma pc ATTRIBUTE_UNUSED,
		   disassemble_info *info,
		   uint32_t insn)
{
  int op = insn & 0x3ff;
  const int rt = RT5 (insn);
  const int ra = RA5 (insn);
  const int rb = RB5 (insn);
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;

  if ((insn & 0x7f) == 0x4e)	/* ffbi */
    {
      func (stream, "ffbi\t%s, %s, #0x%x",
	    gpr_map[rt], gpr_map[ra], __GF (insn, 7, 8));
      return;
    }

  switch (op)
    {
    case 0x0:			/* max */
    case 0x1:			/* min */
    case 0x2:			/* ave */
    case 0xc:			/* bse */
    case 0xd:			/* bsp */
    case 0xe:			/* ffb */
    case 0xf:			/* ffmism */
    case 0x17:			/* ffzmism */
    case 0x24:			/* mul */
      func (stream, "%s\t%s, %s, %s", mnemonic_alu20[op],
	    gpr_map[rt], gpr_map[ra], gpr_map[rb]);
      return;

    case 0x3:			/* abs */
    case 0x6:			/* clo */
    case 0x7:			/* clz */
      func (stream, "%s\t%s, %s", mnemonic_alu20[op], gpr_map[rt], gpr_map[ra]);
      return;

    case 0x4:			/* clips */
    case 0x5:			/* clip */
    case 0x8:			/* bset */
    case 0x9:			/* bclr */
    case 0xa:			/* btgl */
    case 0xb:			/* btst */
      func (stream, "%s\t%s, %s, #%d", mnemonic_alu20[op],
	    gpr_map[rt], gpr_map[ra], IMM1U (insn));
      return;

    case 0x20:			/* mfusr */
    case 0x21:			/* mtusr */
      {
	    int i = __GF (insn, 10, 5);
	    int j = __GF (insn, 15, 5);
	    const char *usrmap;
	    if (i < 0 || i > 2) {
		usrmap = "?";
	    } else {
	    	usrmap = usr_map[i][j];
	    }
      	func (stream, "%s\t%s, $%s", mnemonic_alu20[op], gpr_map[rt], usrmap);
      return;
      }
    case 0x28:			/* mults64 */
    case 0x29:			/* mult64 */
    case 0x2a:			/* madds64 */
    case 0x2b:			/* madd64 */
    case 0x2c:			/* msubs64 */
    case 0x2d:			/* msub64 */
    case 0x2e:			/* divs */
    case 0x2f:			/* div */
    case 0x31:			/* mult32 */
    case 0x33:			/* madd32 */
    case 0x35:			/* msub32 */
      func (stream, "%s\t$d%d, %s, %s", mnemonic_alu20[op],
	    rt >> 1, gpr_map[ra], gpr_map[rb]);
      return;

    case 0x4f:			/* flmism */
    case 0x68:			/* mulsr64 */
    case 0x69:			/* mulr64 */
    case 0x73:			/* maddr32 */
    case 0x75:			/* msubr32 */
      op = insn & 0x3f;
      func (stream, "%s\t%s, %s, %s", mnemonic_alu21[op],
	    gpr_map[rt], gpr_map[ra], gpr_map[rb]);
      return;
    default:
      func (stream, UNKNOWN_INSN_MSG);
      return;
    }
}

static void
print_insn32_jreg (bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info *info, uint32_t insn)
{
  int op = insn & 0xff;
  const int rt = RT5 (insn);
  const int rb = RB5 (insn);
  const char *dtit_on[] = { "", ".iton", ".dton", ".ton" };
  const char *dtit_off[] = { "", ".itoff", ".dtoff", ".toff" };
  const char *mnemonic_jreg[] = { "jr", "jral", "jrnez", "jralnez" };
  const char *mnemonic_ret[] = { "jr", "ret", NULL, "ifret" };
  const int dtit = __GF (insn, 8, 2);
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;

  switch (op)
    {
    case 0:		/* jr */
      func (stream, "%s%s\t%s", mnemonic_ret[op >> 5],
	    dtit_on[dtit], gpr_map[rb]);
      return;

    case 0x20:		/* ret */
      func (stream, "%s%s\t%s", mnemonic_ret[op >> 5],
	    dtit_off[dtit], gpr_map[rb]);
      return;
    case 0x60:		/* ifret */
      break;
    case 1:		/* jral */
    case 2:		/* jrnez */
    case 3:		/* jralnez */
      func (stream, "%s%s\t%s, %s", mnemonic_jreg[op],
	    dtit_on[dtit], gpr_map[rt], gpr_map[rb]);
      return;
    default:		/* unknown */
      func (stream, UNKNOWN_INSN_MSG);
      break;
    }
}

static void
print_insn32_misc (bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info *info,
		   uint32_t insn)
{
  int op = insn & 0x1f;
  int rt = RT5 (insn);
  unsigned int id;
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;

  static const char *keyword_standby[] =
    {
      "no_wake_grant", "wake_grant", "wait_done",
    };
  static const char *keyword_tlbop[] =
    {
      "TRD", "TWR", "RWR", "RWLK", "UNLK", "PB", "INV", "FLUA"
    };

  switch (op)
    {
    case 0x0:			/* standby */
      id = __GF (insn, 5, 20);
      if (id < ARRAY_SIZE (keyword_standby))
	func (stream, "standby\t%s", keyword_standby[id]);
      else
	func (stream, "standby\t%d", id);
      return;
    case 0x1:			/* cctl */
      func (stream, "cctl\t!FIXME");
      return;
    case 0x8:			/* dsb */
    case 0x9:			/* isb */
    case 0xd:			/* isync */
    case 0xc:			/* msync */
    case 0x4:			/* iret */
      func (stream, "%s", mnemonic_misc[op]);
      return;
    case 0x5:			/* trap */
    case 0xa:			/* break */
    case 0xb:			/* syscall */
      id = __GF (insn, 5, 15);
      func (stream, "%s\t%d", mnemonic_misc[op], id);
      return;
    case 0x2:			/* mfsr */
    case 0x3:			/* mtsr */
      /* FIXME: setend, setgie.  */
      func (stream, "%s\t%s, $%s", mnemonic_misc[op], gpr_map[rt],
	    sr_map[__GF(insn, 17, 3)][__GF(insn, 13, 4)][__GF(insn, 10, 3)]);
      return;
    case 0x6:			/* teqz */
    case 0x7:			/* tnez */
      id = __GF (insn, 5, 15);
      func (stream, "%s\t%s, %d", mnemonic_misc[op], gpr_map[rt], id);
      return;
    case 0xe:			/* tlbop */
      id = __GF (insn, 5, 5);
      if (id < ARRAY_SIZE (keyword_tlbop))
	func (stream, "tlbop\t%s", keyword_tlbop[id]);
      else
	func (stream, "tlbop\t%d", id);
      return;
    }
}

static void
print_insn32_fpu (bfd_vma pc ATTRIBUTE_UNUSED, disassemble_info *info,
		  uint32_t insn)
{
  int op = insn & 0xf;
  int mask_sub_op = (insn & 0x3c0) >> 6;
  int mask_bi = (insn & 0x80) >> 7;
  int mask_cfg = (insn & 0x7c00) >> 10;
  int mask_f2op = (insn & 0x7c00) >> 10;
  int dp = 0;
  int dp_insn = 0;
  char wd = 's';
  const int rt = RT5 (insn);
  const int ra = RA5 (insn);
  const int rb = RB5 (insn);
  const int sv = __GF (insn, 8, 2);
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;

  switch (op)
    {
    case 0x0:			/* fs1 */
    case 0x8:			/* fd1 */
      dp = (op & 0x8) ? 1 : 0;
      if (dp)
	{
	  wd = 'd';
	  dp_insn = 14;
	}
      else
	{
	  wd = 's';
	  dp_insn = 0;
	}
      switch (mask_sub_op)
	{
	case 0x0:
	case 0x1:
	case 0x2:
	case 0x3:
	case 0x4:
	case 0x5:
	case 0x8:
	case 0x9:
	case 0xc:
	case 0xd:
	  func (stream, "%s\t$f%c%d, $f%c%d, $f%c%d",
		mnemonic_alu[mask_sub_op + dp_insn],
		wd, rt, wd, ra, wd, rb);
	  return;
	case 0x6:
	case 0x7:
	  func (stream, "%s\t$f%c%d, $f%c%d, $fs%d",
		mnemonic_alu[mask_sub_op + dp_insn],
		wd, rt, wd, ra, rb);
	  return;
	case 0xf:
	  if (dp)
	    {
	      wd = 'd';
	      dp_insn = 0x1d;
	    }
	  else
	    {
	      wd = 's';
	      dp_insn = 0;
	    }

	  switch (mask_f2op)
	    {
	    case 0x0:
	      if (dp)
		func (stream, "%s\t$fs%d, $fd%d",
		      mnemonic_fpu_2op[mask_f2op + dp_insn], rt, ra);
	      else
		func (stream, "%s\t$fd%d, $fs%d",
		      mnemonic_fpu_2op[mask_f2op + dp_insn], rt, ra);
	      return;
	    case 0x1:
	    case 0x5:
	      func (stream, "%s\t$f%c%d, $f%c%d",
		    mnemonic_fpu_2op[mask_f2op + dp_insn], wd, rt, wd, ra);
	      return;
	    case 0x8:
	    case 0xc:
	      func (stream, "%s\t$f%c%d, $fs%d",
		    mnemonic_fpu_2op[mask_f2op + dp_insn], wd, rt, ra);
	      return;
	    case 0x10:
	    case 0x14:
	    case 0x18:
	    case 0x1c:
	      func (stream, "%s\t$fs%d, $f%c%d",
		    mnemonic_fpu_2op[mask_f2op + dp_insn], rt, wd, ra);
	      return;
	    }
	}
    case 0x1:			/* mfcp */
      switch (mask_sub_op)
	{
	case 0x0:
	  func (stream, "fmfsr\t%s, $fs%d", gpr_map[rt], ra);
	  return;
	case 0x1:
	  func (stream, "fmfdr\t%s, $fd%d", gpr_map[rt], ra);
	  return;
	case 0xc:
	  if (mask_cfg)
	    func (stream, "fmfcsr\t%s", gpr_map[rt]);
	  else
	    func (stream, "fmfcfg\t%s", gpr_map[rt]);
	  return;
	}
    case 0x2:			/* fls */
      if (mask_bi)
	func (stream, "fls.bi\t$fs%d, [%s], (%s << %d)",
	      rt, gpr_map[ra], gpr_map[rb], sv);
      else
	func (stream, "fls\t$fs%d, [%s + (%s << %d)]",
	      rt, gpr_map[ra], gpr_map[rb], sv);
      return;
    case 0x3:			/* fld */
      if (mask_bi)
	func (stream, "fld.bi\t$fd%d, [%s], (%s << %d)",
	      rt, gpr_map[ra], gpr_map[rb], sv);
      else
	func (stream, "fld\t$fd%d, [%s + (%s << %d)]",
	      rt, gpr_map[ra], gpr_map[rb], sv);
      return;
    case 0x4:			/* fs2 */
      {
	    const char *fs2cmp = mask_sub_op < 10? mnemonic_fs2_cmp[mask_sub_op]: "fs2cmp?";
	    func (stream, "%s\t$fs%d, $fs%d, $fs%d", fs2cmp, rt, ra, rb);
      }
      return;
    case 0x9:			/* mtcp */
      switch (mask_sub_op)
	{
	case 0x0:
	  func (stream, "fmtsr\t%s, $fs%d", gpr_map[rt], ra);
	  return;
	case 0x1:
	  func (stream, "fmtdr\t%s, $fd%d", gpr_map[rt], ra);
	  return;
	case 0xc:
	    func (stream, "fmtcsr\t%s", gpr_map[rt]);
	  return;
	}
    case 0xa:			/* fss */
      if (mask_bi)
	func (stream, "fss.bi\t$fs%d, [%s], (%s << %d)",
	      rt, gpr_map[ra], gpr_map[rb], sv);
      else
	func (stream, "fss\t$fs%d, [%s + (%s << %d)]",
	      rt, gpr_map[ra], gpr_map[rb], sv);
      return;
    case 0xb:			/* fsd */
      if (mask_bi)
	func (stream, "fsd.bi\t$fd%d, [%s], (%s << %d)",
	      rt, gpr_map[ra], gpr_map[rb], sv);
      else
	func (stream, "fsd\t$fd%d, [%s + (%s << %d)]",
	      rt, gpr_map[ra], gpr_map[rb], sv);
      return;
    case 0xc:			/* fd2 */
      if (mask_sub_op >= 0 && mask_sub_op < 8) {
      func (stream, "%s\t$fs%d, $fd%d, $fd%d",
	    mnemonic_fd2_cmp[mask_sub_op], rt, ra, rb);
      } else {
      func (stream, "%s%d\t$fs%d, $fd%d, $fd%d",
	    "fd2cmp", mask_sub_op, rt, ra, rb);
      }
      return;
    }
}

static void
print_insn32 (bfd_vma pc, disassemble_info *info, uint32_t insn)
{
  int op = OP6 (insn);
  const int rt = RT5 (insn);
  const int ra = RA5 (insn);
  const int rb = RB5 (insn);
  const unsigned int imm15s = IMMS (insn, 15);
  const unsigned int imm15u = IMMU (insn, 15);
  uint32_t shift;
  fprintf_ftype func = info->fprintf_func;
  void *stream = info->stream;

  switch (op)
    {
    case 0x0:			/* lbi */
    case 0x1:			/* lhi */
    case 0x2:			/* lwi */
    case 0x3:			/* ldi */
    case 0x8:			/* sbi */
    case 0x9:			/* shi */
    case 0xa:			/* swi */
    case 0xb:			/* sdi */
    case 0x10:			/* lbsi */
    case 0x11:			/* lhsi */
    case 0x12:			/* lwsi */
      shift = op & 0x3;
      func (stream, "%s\t%s, [%s + #%d]",
	    mnemonic_op6[op], gpr_map[rt], gpr_map[ra], imm15s << shift);
      return;
    case 0x4:			/* lbi.bi */
    case 0x5:			/* lhi.bi */
    case 0x6:			/* lwi.bi */
    case 0x7:			/* ldi.bi */
    case 0xc:			/* sbi.bi */
    case 0xd:			/* shi.bi */
    case 0xe:			/* swi.bi */
    case 0xf:			/* sdi.bi */
    case 0x14:			/* lbsi.bi */
    case 0x15:			/* lhsi.bi */
    case 0x16:			/* lwsi.bi */
      shift = op & 0x3;
      func (stream, "%s\t%s, [%s], #%d",
	    mnemonic_op6[op], gpr_map[rt], gpr_map[ra], imm15s << shift);
      return;
    case 0x13:			/* dprefi */
      {
	const char *subtype = "???";
	char wd = 'w';

	shift = 2;

	/* d-bit */
	if (rt & 0x10)
	  {
	    wd = 'd';
	    shift = 3;
	  }

	if ((rt & 0xf) < ARRAY_SIZE (keyword_dpref))
	  subtype = keyword_dpref[rt & 0xf];

	func (stream, "%s.%c\t%s, [%s + #%d]",
	      mnemonic_op6[op], wd, subtype, gpr_map[ra], imm15s << shift);
      }
      return;
    case 0x17:			/* LBGP */
      func (stream, "%s\t%s, [+ %d]",
	    ((insn & __BIT (19)) ? "lbsi.gp" : "lbi.gp"),
	    gpr_map[rt], IMMS (insn, 19));
      return;
    case 0x18:			/* LWC */
    case 0x19:			/* SWC */
    case 0x1a:			/* LDC */
    case 0x1b:			/* SDC */
      if (__GF (insn, 13, 2) == 0)
	{
	  char ls = (op & 1) ? 's' : 'l';
	  char wd = (op & 2) ? 'd' : 's';

	  if (insn & __BIT (12))
	    {
	      func (stream, "f%c%ci.bi\t$f%c%d, [%s], %d", ls, wd,
		    wd, rt, gpr_map[ra], IMMS (insn, 12) << 2);
	    }
	  else
	    {
	      func (stream, "f%c%ci\t$f%c%d, [%s + %d]", ls, wd,
		    wd, rt, gpr_map[ra], IMMS (insn, 12) << 2);
	    }
	}
      else
	{
	  char ls = (op & 1) ? 's' : 'l';
	  char wd = (op & 2) ? 'd' : 'w';
	  int cp = __GF (insn, 13, 2);

	  if (insn & __BIT (12))
	    {
	      func (stream, "cp%c%ci\tcp%d, $cpr%d, [%s], %d", ls, wd,
		    cp, rt, gpr_map[ra], IMMS (insn, 12) << 2);
	    }
	  else
	    {
	      func (stream, "cp%c%ci\tcp%d, $cpr%d, [%s + %d]", ls, wd,
		    cp, rt, gpr_map[ra], IMMS (insn, 12) << 2);
	    }
	}
      return;
    case 0x1c:			/* MEM */
      print_insn32_mem (pc, info, insn);
      return;
    case 0x1d:			/* LSMW */
      {
	int enb4 = __GF (insn, 6, 4);
	char ls = (insn & __BIT (5)) ? 's' : 'l';
	char ab = (insn & __BIT (4)) ? 'a' : 'b';
	char *di = (insn & __BIT (3)) ? "d" : "i";
	char *m = (insn & __BIT (2)) ? "m" : "";
	static const char *s[] = {"", "a", "zb", "?"};

	/* lsmwzb only always increase.  */
	if ((insn & 0x3) == 2)
	  di = "";

	func (stream, "%cmw%s.%c%s%s\t%s, [%s], %s, 0x%x",
	      ls, s[insn & 0x3], ab, di, m, gpr_map[rt],
	      gpr_map[ra], gpr_map[rb], enb4);
      }
      return;
    case 0x1e:			/* HWGP */
      op = __GF (insn, 17, 3);
      switch (op)
	{
	case 0: case 1:		/* lhi.gp */
	case 2: case 3:		/* lhsi.gp */
	case 4: case 5:		/* shi.gp */
	  func (stream, "%s\t%s, [+ %d]",
		mnemonic_hwgp[op], gpr_map[rt], IMMS (insn, 18) << 1);
	  return;
	case 6:			/* lwi.gp */
	case 7:			/* swi.gp */
	  func (stream, "%s\t%s, [+ %d]",
		mnemonic_hwgp[op], gpr_map[rt], IMMS (insn, 17) << 2);
	  return;
	}
      return;
    case 0x1f:			/* SBGP */
      if (insn & __BIT (19))
	func (stream, "addi.gp\t%s, %d",
	      gpr_map[rt], IMMS (insn, 19));
      else
	func (stream, "sbi.gp\t%s, [+ %d]",
	      gpr_map[rt], IMMS (insn, 19));
      return;
    case 0x20:			/* ALU_1 */
      print_insn32_alu1 (pc, info, insn);
      return;
    case 0x21:			/* ALU_2 */
      print_insn32_alu2 (pc, info, insn);
      return;
    case 0x22:			/* movi */
      func (stream, "movi\t%s, %d", gpr_map[rt], IMMS (insn, 20));
      return;
    case 0x23:			/* sethi */
      func (stream, "sethi\t%s, 0x%x", gpr_map[rt], IMMU (insn, 20));
      return;
    case 0x24:			/* ji, jal */
      /* FIXME: Handle relocation.  */
      if (info->flags & INSN_HAS_RELOC)
	pc = 0;
      func (stream, "%s\t", ((insn & __BIT (24)) ? "jal" : "j"));
      info->print_address_func ((IMMS (insn, 24) << 1) + pc, info);
      return;
    case 0x25:			/* jreg */
      print_insn32_jreg (pc, info, insn);
      return;
    case 0x26:			/* br1 */
      func (stream, "%s\t%s, %s, ", ((insn & __BIT (14)) ? "bne" : "beq"),
	    gpr_map[rt], gpr_map[ra]);
      info->print_address_func ((IMMS (insn, 14) << 1) + pc, info);
      return;
    case 0x27:			/* br2 */
      func (stream, "%s\t%s, ", mnemonic_br2[__GF (insn, 16, 4)],
	    gpr_map[rt]);
      info->print_address_func ((IMMS (insn, 16) << 1) + pc, info);
      return;
    case 0x28:			/* addi */
    case 0x2e:			/* slti */
    case 0x2f:			/* sltsi */
    case 0x29:			/* subri */
      func (stream, "%s\t%s, %s, %d",
	    mnemonic_op6[op], gpr_map[rt], gpr_map[ra], imm15s);
      return;
    case 0x2a:			/* andi */
    case 0x2b:			/* xori */
    case 0x2c:			/* ori */
    case 0x33:			/* bitci */
      func (stream, "%s\t%s, %s, %d",
	    mnemonic_op6[op], gpr_map[rt], gpr_map[ra], imm15u);
      return;
    case 0x2d:			/* br3, beqc, bnec */
      func (stream, "%s\t%s, %d, ", ((insn & __BIT (19)) ? "bnec" : "beqc"),
	    gpr_map[rt], __SEXT (__GF (insn, 8, 11), 11));
      info->print_address_func ((IMMS (insn, 8) << 1) + pc, info);
      return;
    case 0x32:			/* misc */
      print_insn32_misc (pc, info, insn);
      return;
    case 0x35:			/* FPU */
      print_insn32_fpu (pc, info, insn);
      return;
    }
}

int
print_insn_nds32 (bfd_vma pc, disassemble_info *info)
{
  int status;
  bfd_byte buf[4];
  uint32_t insn;

  status = info->read_memory_func (pc, (bfd_byte *) buf, 2, info);
  if (status)
    return -1;

  /* 16-bit instruction.  */
  if (buf[0] & 0x80)
    {
      insn = bfd_getb16 (buf);
      print_insn16 (pc, info, insn);
      return 2;
    }

  /* 32-bit instructions.  */
  status = info->read_memory_func (pc + 2, (bfd_byte *) buf + 2, 2, info);
  if (status)
    return -1;

  insn = bfd_getb32 (buf);
  print_insn32 (pc, info, insn);

  return 4;
}
