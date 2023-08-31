/* nds32.h -- Header file for nds32 opcode table
   Copyright (C) 2012-2013 Free Software Foundation, Inc.
   Contributed by Andes Technology Corporation.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston, MA
   02110-1301, USA.  */

#ifndef OPCODE_NDS32_H
#define OPCODE_NDS32_H

/* Registers.  */
#define REG_R5		5
#define REG_R8		8
#define REG_R10		10
#define REG_R12		12
#define REG_R15		15
#define REG_R16		16
#define REG_R20		20
#define REG_TA		15
#define REG_FP		28
#define REG_GP		29
#define REG_LP		30
#define REG_SP		31

/* Macros for extracting fields or making an instruction.  */
static const int nds32_r45map[] =
{
  0, 1, 2,  3,  4,  5,  6,  7,
  8, 9, 10, 11, 16, 17, 18, 19
};

static const int nds32_r54map[] =
{
   0,  1,  2,  3,  4,  5,  6,  7,
   8,  9, 10, 11, -1, -1, -1, -1,
  12, 13, 14, 15, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1
};

#define __BIT(n)		(1 << (n))
#define __MASK(n)		(__BIT (n) - 1)
#define __MF(v, off, bs)	(((v) & __MASK (bs)) << (off))
#define __GF(v, off, bs)	(((v) >> off) & __MASK (bs))
#define __SEXT(v, bs)		((((v) & ((1 << (bs)) - 1)) ^ (1 << ((bs) - 1))) - (1 << ((bs) - 1)))

/* Make nds32 instructions.  */

#define N32_TYPE4(op6, rt5, ra5, rb5, rd5, sub5)  \
	(__MF (N32_OP6_##op6, 25, 6) | __MF (rt5, 20, 5) \
	 | __MF (ra5, 15, 5) | __MF (rb5, 10, 5) \
	 | __MF (rd5, 5, 5) | __MF (sub5, 0, 5))
#define N32_TYPE3(op6, rt5, ra5, rb5, sub10) \
	(N32_TYPE4 (op6, rt5, ra5, rb5, 0, 0) \
	 | __MF (sub10, 0, 10))
#define N32_TYPE2(op6, rt5, ra5, imm15)	\
	(N32_TYPE3 (op6, rt5, ra5, 0, 0) | __MF (imm15, 0, 15))
#define N32_TYPE1(op6, rt5, imm20) \
	(N32_TYPE2 (op6, rt5, 0, 0) | __MF (imm20, 0, 20))
#define N32_TYPE0(op6, imm25) \
	(N32_TYPE1 (op6, 0, 0) | __MF (imm25, 0, 25))
#define N32_ALU1(sub, rt, ra, rb) \
	N32_TYPE4 (ALU1, rt, ra, rb, 0, N32_ALU1_##sub)
#define N32_ALU1_SH(sub, rt, ra, rb, rd) \
	N32_TYPE4 (ALU1, rt, ra, rb, rd, N32_ALU1_##sub)
#define N32_ALU2(sub, rt, ra, rb) \
	N32_TYPE3 (ALU2, rt, ra, rb, N32_ALU2_##sub)
#define N32_BR1(sub, rt, ra, imm14s) \
	N32_TYPE2 (BR1, rt, ra, (N32_BR1_##sub << 14) | (imm14s & __MASK (14)))
#define N32_BR2(sub, rt, imm16s) \
	N32_TYPE1 (BR2, rt, (N32_BR2_##sub << 16) | (imm16s & __MASK (16)))
#define N32_BR3(sub, rt, imm11s, imm8s) \
	N32_TYPE1 (BR3, rt, (N32_BR3_##sub << 19) \
			    | ((imm11s & __MASK (11)) << 8) \
			    | (imm8s & __MASK (8)))
#define N32_JI(sub, imm24s) \
	N32_TYPE0 (JI, (N32_JI_##sub << 24) | (imm24s & __MASK (24)))
#define N32_JREG(sub, rt, rb, dtit, hint) \
	N32_TYPE4(JREG, rt, 0, rb, (dtit << 3) | (hint & 7), N32_JREG_##sub)
#define N32_MEM(sub, rt, ra, rb, sv) \
	N32_TYPE3 (MEM, rt, ra, rb, (sv << 8) | N32_MEM_##sub)

#define N16_TYPE55(op5, rt5, ra5) \
	(0x8000 | __MF (N16_T55_##op5, 10, 5) | __MF (rt5, 5, 5) \
	 | __MF (ra5, 0, 5))
#define N16_TYPE45(op6, rt4, ra5) \
	(0x8000 | __MF (N16_T45_##op6, 9, 6) | __MF (rt4, 5, 4) \
	 | __MF (ra5, 0, 5))
#define N16_TYPE333(op6, rt3, ra3, rb3)	\
	(0x8000 | __MF (N16_T333_##op6, 9, 6) | __MF (rt3, 6, 3) \
	 | __MF (ra3, 3, 3) | __MF (rb3, 0, 3))
#define N16_TYPE36(op6, rt3, imm6) \
	(0x8000 | __MF (N16_T36_##op6, 9, 6) | __MF (rt3, 6, 3) \
	 | __MF (imm6, 0, 6))
#define N16_TYPE38(op4, rt3, imm8) \
	(0x8000 | __MF (N16_T38_##op4, 11, 4) | __MF (rt3, 8, 3) \
	 | __MF (imm8, 0, 8))
#define N16_TYPE37(op4, rt3, ls, imm7) \
	(0x8000 | __MF (N16_T37_##op4, 11, 4) | __MF (rt3, 8, 3) \
	 | __MF (imm7, 0, 7) | __MF (ls, 7, 1))
#define N16_TYPE5(op10, imm5) \
	(0x8000 | __MF (N16_T5_##op10, 5, 10) | __MF (imm5, 0, 5))
#define N16_TYPE8(op7, imm8) \
	(0x8000 | __MF (N16_T8_##op7, 8, 7) | __MF (imm8, 0, 8))
#define N16_TYPE9(op6, imm9) \
	(0x8000 | __MF (N16_T9_##op6, 9, 6) | __MF (imm9, 0, 9))
#define N16_TYPE10(op5, imm10) \
	(0x8000 | __MF (N16_T10_##op5, 10, 5) | __MF (imm10, 0, 10))
#define N16_TYPE25(op8, re, imm5) \
	(0x8000 | __MF (N16_T25_##op8, 7, 8) | __MF (re, 5, 2) \
	 | __MF (imm5, 0, 5))

#define N16_MISC33(sub, rt, ra) \
	N16_TYPE333 (MISC33, rt, ra, N16_MISC33_##sub)
#define N16_BFMI333(sub, rt, ra) \
	N16_TYPE333 (BFMI333, rt, ra, N16_BFMI333_##sub)

/* Get instruction fields.

   Macros used for handling 32-bit and 16-bit instructions are
   prefixed with N32_ and N16_ respectively.  */

#define N32_OP6(insn)		(((insn) >> 25) & 0x3f)
#define N32_RT5(insn)		(((insn) >> 20) & 0x1f)
#define N32_RT53(insn)		(N32_RT5 (insn) & 0x7)
#define N32_RT54(insn)		nds32_r54map[N32_RT5 (insn)]
#define N32_RA5(insn)		(((insn) >> 15) & 0x1f)
#define N32_RA53(insn)		(N32_RA5 (insn) & 0x7)
#define N32_RA54(insn)		nds32_r54map[N32_RA5 (insn)]
#define N32_RB5(insn)		(((insn) >> 10) & 0x1f)
#define N32_UB5(insn)		(((insn) >> 10) & 0x1f)
#define N32_RB53(insn)		(N32_RB5 (insn) & 0x7)
#define N32_RB54(insn)		nds32_r54map[N32_RB5 (insn)]
#define N32_RD5(insn)		(((insn) >> 5) & 0x1f)
#define N32_SH5(insn)		(((insn) >> 5) & 0x1f)
#define N32_SUB5(insn)		(((insn) >> 0) & 0x1f)
#define N32_SWID(insn)		(((insn) >> 5) & 0x3ff)
#define N32_IMMU(insn, bs)	((insn) & __MASK (bs))
#define N32_IMMS(insn, bs)	((signed) __SEXT (((insn) & __MASK (bs)), bs))
#define N32_IMM5U(insn)		N32_IMMU (insn, 5)
#define N32_IMM12S(insn)	N32_IMMS (insn, 12)
#define N32_IMM14S(insn)	N32_IMMS (insn, 14)
#define N32_IMM15U(insn)	N32_IMMU (insn, 15)
#define N32_IMM15S(insn)	N32_IMMS (insn, 15)
#define N32_IMM16S(insn)	N32_IMMS (insn, 16)
#define N32_IMM17S(insn)	N32_IMMS (insn, 17)
#define N32_IMM20S(insn)	N32_IMMS (insn, 20)
#define N32_IMM20U(insn)	N32_IMMU (insn, 20)
#define N32_IMM24S(insn)	N32_IMMS (insn, 24)

#define N16_RT5(insn)		(((insn) >> 5) & 0x1f)
#define N16_RT4(insn)		nds32_r45map[(((insn) >> 5) & 0xf)]
#define N16_RT3(insn)		(((insn) >> 6) & 0x7)
#define N16_RT38(insn)		(((insn) >> 8) & 0x7)
#define N16_RT8(insn)		(((insn) >> 8) & 0x7)
#define N16_RA5(insn)		((insn) & 0x1f)
#define N16_RA3(insn)		(((insn) >> 3) & 0x7)
#define N16_RB3(insn)		((insn) & 0x7)
#define N16_IMM3U(insn)		N32_IMMU (insn, 3)
#define N16_IMM5U(insn)		N32_IMMU (insn, 5)
#define N16_IMM5S(insn)		N32_IMMS (insn, 5)
#define N16_IMM6U(insn)		N32_IMMU (insn, 6)
#define N16_IMM7U(insn)		N32_IMMU (insn, 7)
#define N16_IMM8S(insn)		N32_IMMS (insn, 8)
#define N16_IMM9U(insn)		N32_IMMU (insn, 9)
#define N16_IMM10S(insn)	N32_IMMS (insn, 10)

#define IS_WITHIN_U(v, n)	(((v) >> n) == 0)
#define IS_WITHIN_S(v, n)	IS_WITHIN_U ((v) + (1 << ((n) - 1)), n)

/* Get fields for specific instruction.  */
#define N32_JREG_T(insn)	(((insn) >> 8) & 0x3)
#define N32_JREG_HINT(insn)	(((insn) >> 5) & 0x7)
#define N32_BR2_SUB(insn)	(((insn) >> 16) & 0xf)
#define N32_COP_SUB(insn)	((insn) & 0xf)
#define N32_COP_CP(insn)	(((insn) >> 4) & 0x3)

/* Check fields.  */
#define N32_IS_RT3(insn)	(N32_RT5 (insn) < 8)
#define N32_IS_RA3(insn)	(N32_RA5 (insn) < 8)
#define N32_IS_RB3(insn)	(N32_RB5 (insn) < 8)
#define N32_IS_RT4(insn)	(nds32_r54map[N32_RT5 (insn)] != -1)
#define N32_IS_RA4(insn)	(nds32_r54map[N32_RA5 (insn)] != -1)
#define N32_IS_RB4(insn)	(nds32_r54map[N32_RB5 (insn)] != -1)


/* These are opcodes for Nxx_TYPE macros.
   They are prefixed by corresponding TYPE to avoid misusing.  */

enum n32_opcodes
{
  /* Main opcodes (OP6).  */

  N32_OP6_LBI = 0x0,
  N32_OP6_LHI,
  N32_OP6_LWI,
  N32_OP6_LDI,
  N32_OP6_LBI_BI,
  N32_OP6_LHI_BI,
  N32_OP6_LWI_BI,
  N32_OP6_LDI_BI,

  N32_OP6_SBI = 0x8,
  N32_OP6_SHI,
  N32_OP6_SWI,
  N32_OP6_SDI,
  N32_OP6_SBI_BI,
  N32_OP6_SHI_BI,
  N32_OP6_SWI_BI,
  N32_OP6_SDI_BI,

  N32_OP6_LBSI = 0x10,
  N32_OP6_LHSI,
  N32_OP6_LWSI,
  N32_OP6_DPREFI,
  N32_OP6_LBSI_BI,
  N32_OP6_LHSI_BI,
  N32_OP6_LWSI_BI,
  N32_OP6_LBGP,

  N32_OP6_LWC = 0x18,
  N32_OP6_SWC,
  N32_OP6_LDC,
  N32_OP6_SDC,
  N32_OP6_MEM,
  N32_OP6_LSMW,
  N32_OP6_HWGP,
  N32_OP6_SBGP,

  N32_OP6_ALU1 = 0x20,
  N32_OP6_ALU2,
  N32_OP6_MOVI,
  N32_OP6_SETHI,
  N32_OP6_JI,
  N32_OP6_JREG,
  N32_OP6_BR1,
  N32_OP6_BR2,

  N32_OP6_ADDI = 0x28,
  N32_OP6_SUBRI,
  N32_OP6_ANDI,
  N32_OP6_XORI,
  N32_OP6_ORI,
  N32_OP6_BR3,
  N32_OP6_SLTI,
  N32_OP6_SLTSI,

  N32_OP6_AEXT = 0x30,
  N32_OP6_CEXT,
  N32_OP6_MISC,
  N32_OP6_BITCI,
  N32_OP6_0x34,
  N32_OP6_COP,
  N32_OP6_0x36,
  N32_OP6_0x37,

  N32_OP6_SIMD = 0x38,

  /* Sub-opcodes of specific opcode.  */

  /* bit-24 */
  N32_BR1_BEQ = 0,
  N32_BR1_BNE = 1,

  /* bit[16:19] */
  N32_BR2_IFCALL = 0,
  N32_BR2_BEQZ = 2,
  N32_BR2_BNEZ = 3,
  N32_BR2_BGEZ = 4,
  N32_BR2_BLTZ = 5,
  N32_BR2_BGTZ = 6,
  N32_BR2_BLEZ = 7,
  N32_BR2_BGEZAL = 0xc,
  N32_BR2_BLTZAL = 0xd,

  /* bit-19 */
  N32_BR3_BEQC = 0,
  N32_BR3_BNEC = 1,

  /* bit-24 */
  N32_JI_J = 0,
  N32_JI_JAL = 1,

  /* bit[0:4] */
  N32_JREG_JR = 0,
  N32_JREG_JRAL = 1,
  N32_JREG_JRNEZ = 2,
  N32_JREG_JRALNEZ = 3,

  /* bit[0:4] */
  N32_ALU1_ADD_SLLI = 0x0,
  N32_ALU1_SUB_SLLI,
  N32_ALU1_AND_SLLI,
  N32_ALU1_XOR_SLLI,
  N32_ALU1_OR_SLLI,
  N32_ALU1_ADD = 0x0,
  N32_ALU1_SUB,
  N32_ALU1_AND,
  N32_ALU1_XOR,
  N32_ALU1_OR,
  N32_ALU1_NOR,
  N32_ALU1_SLT,
  N32_ALU1_SLTS,
  N32_ALU1_SLLI = 0x8,
  N32_ALU1_SRLI,
  N32_ALU1_SRAI,
  N32_ALU1_ROTRI,
  N32_ALU1_SLL,
  N32_ALU1_SRL,
  N32_ALU1_SRA,
  N32_ALU1_ROTR,
  N32_ALU1_SEB = 0x10,
  N32_ALU1_SEH,
  N32_ALU1_BITC,
  N32_ALU1_ZEH,
  N32_ALU1_WSBH,
  N32_ALU1_OR_SRLI,
  N32_ALU1_DIVSR,
  N32_ALU1_DIVR,
  N32_ALU1_SVA = 0x18,
  N32_ALU1_SVS,
  N32_ALU1_CMOVZ,
  N32_ALU1_CMOVN,
  N32_ALU1_ADD_SRLI,
  N32_ALU1_SUB_SRLI,
  N32_ALU1_AND_SRLI,
  N32_ALU1_XOR_SRLI,

  /* bit[0:5], where bit[6:9] == 0 */
  N32_ALU2_MAX = 0,
  N32_ALU2_MIN,
  N32_ALU2_AVE,
  N32_ALU2_ABS,
  N32_ALU2_CLIPS,
  N32_ALU2_CLIP,
  N32_ALU2_CLO,
  N32_ALU2_CLZ,
  N32_ALU2_BSET = 0x8,
  N32_ALU2_BCLR,
  N32_ALU2_BTGL,
  N32_ALU2_BTST,
  N32_ALU2_BSE,
  N32_ALU2_BSP,
  N32_ALU2_FFB,
  N32_ALU2_FFMISM,
  N32_ALU2_ADD_SC = 0x10,
  N32_ALU2_SUB_SC,
  N32_ALU2_ADD_WC,
  N32_ALU2_SUB_WC,
  N32_ALU2_0x14,
  N32_ALU2_0x15,
  N32_ALU2_0x16,
  N32_ALU2_FFZMISM,
  N32_ALU2_QADD = 0x18,
  N32_ALU2_QSUB,
  N32_ALU2_MFUSR = 0x20,
  N32_ALU2_MTUSR,
  N32_ALU2_0x22,
  N32_ALU2_0x23,
  N32_ALU2_MUL,
  N32_ALU2_0x25,
  N32_ALU2_0x26,
  N32_ALU2_MULTS64 = 0x28,
  N32_ALU2_MULT64,
  N32_ALU2_MADDS64,
  N32_ALU2_MADD64,
  N32_ALU2_MSUBS64,
  N32_ALU2_MSUB64,
  N32_ALU2_DIVS,
  N32_ALU2_DIV,
  N32_ALU2_0x30 = 0x30,
  N32_ALU2_MULT32,
  N32_ALU2_0x32,
  N32_ALU2_MADD32,
  N32_ALU2_0x34,
  N32_ALU2_MSUB32,

  /* bit[0:5], where bit[6:9] != 0  */
  N32_ALU2_FFBI = 0xe,
  N32_ALU2_FLMISM = 0xf,
  N32_ALU2_MULSR64 = 0x28,
  N32_ALU2_MULR64 = 0x29,
  N32_ALU2_MADDR32 = 0x33,
  N32_ALU2_MSUBR32 = 0x35,

  /* bit[0:5] */
  N32_MEM_LB = 0,
  N32_MEM_LH,
  N32_MEM_LW,
  N32_MEM_LD,
  N32_MEM_LB_BI,
  N32_MEM_LH_BI,
  N32_MEM_LW_BI,
  N32_MEM_LD_BI,
  N32_MEM_SB,
  N32_MEM_SH,
  N32_MEM_SW,
  N32_MEM_SD,
  N32_MEM_SB_BI,
  N32_MEM_SH_BI,
  N32_MEM_SW_BI,
  N32_MEM_SD_BI,
  N32_MEM_LBS,
  N32_MEM_LHS,
  N32_MEM_LWS, /* Not used.  */
  N32_MEM_DPREF,
  N32_MEM_LBS_BI,
  N32_MEM_LHS_BI,
  N32_MEM_LWS_BI, /* Not used.  */
  N32_MEM_0x17, /* Not used.  */
  N32_MEM_LLW,
  N32_MEM_SCW,
  N32_MEM_LBUP = 0x20,
  N32_MEM_LWUP = 0x22,
  N32_MEM_SBUP = 0x28,
  N32_MEM_SWUP = 0x2a,

  /* bit[0:1] */
  N32_LSMW_LSMW = 0,
  N32_LSMW_LSMWA,
  N32_LSMW_LSMWZB,

  /* bit[2:4] */
  N32_LSMW_BI = 0,
  N32_LSMW_BIM,
  N32_LSMW_BD,
  N32_LSMW_BDM,
  N32_LSMW_AI,
  N32_LSMW_AIM,
  N32_LSMW_AD,
  N32_LSMW_ADM,

  /* bit[0:4] */
  N32_MISC_STANDBY = 0,
  N32_MISC_CCTL,
  N32_MISC_MFSR,
  N32_MISC_MTSR,
  N32_MISC_IRET,
  N32_MISC_TRAP,
  N32_MISC_TEQZ,
  N32_MISC_TNEZ,
  N32_MISC_DSB = 0x8,
  N32_MISC_ISB,
  N32_MISC_BREAK,
  N32_MISC_SYSCALL,
  N32_MISC_MSYNC,
  N32_MISC_ISYNC,
  N32_MISC_TLBOP,
  N32_MISC_0xf,

  /* bit[0;4] */
  N32_SIMD_PBSAD = 0,
  N32_SIMD_PBSADA = 1,

  /* bit[0:3] */
  N32_COP_CPE1 = 0,
  N32_COP_MFCP,
  N32_COP_CPLW,
  N32_COP_CPLD,
  N32_COP_CPE2,
  N32_COP_CPE3 = 8,
  N32_COP_MTCP,
  N32_COP_CPSW,
  N32_COP_CPSD,
  N32_COP_CPE4,

  /* cop/0 b[3:0] */
  N32_FPU_FS1 = 0,
  N32_FPU_MFCP,
  N32_FPU_FLS,
  N32_FPU_FLD,
  N32_FPU_FS2,
  N32_FPU_FD1 = 8,
  N32_FPU_MTCP,
  N32_FPU_FSS,
  N32_FPU_FSD,
  N32_FPU_FD2,

  /* FS1 b[9:6] */
  N32_FPU_FS1_FADDS = 0,
  N32_FPU_FS1_FSUBS,
  N32_FPU_FS1_FCPYNSS,
  N32_FPU_FS1_FCPYSS,
  N32_FPU_FS1_FMADDS,
  N32_FPU_FS1_FMSUBS,
  N32_FPU_FS1_FCMOVNS,
  N32_FPU_FS1_FCMOVZS,
  N32_FPU_FS1_FNMADDS,
  N32_FPU_FS1_FNMSUBS,
  N32_FPU_FS1_10,
  N32_FPU_FS1_11,
  N32_FPU_FS1_FMULS = 12,
  N32_FPU_FS1_FDIVS,
  N32_FPU_FS1_14,
  N32_FPU_FS1_F2OP = 15,

  /* FS1/F2OP b[14:10] */
  N32_FPU_FS1_F2OP_FS2D = 0x00,
  N32_FPU_FS1_F2OP_FSQRTS  = 0x01,
  N32_FPU_FS1_F2OP_FABSS  = 0x05,
  N32_FPU_FS1_F2OP_FUI2S  = 0x08,
  N32_FPU_FS1_F2OP_FSI2S  = 0x0c,
  N32_FPU_FS1_F2OP_FS2UI  = 0x10,
  N32_FPU_FS1_F2OP_FS2UI_Z = 0x14,
  N32_FPU_FS1_F2OP_FS2SI  = 0x18,
  N32_FPU_FS1_F2OP_FS2SI_Z = 0x1c,

  /* FS2 b[9:6] */
  N32_FPU_FS2_FCMPEQS = 0x0,
  N32_FPU_FS2_FCMPLTS = 0x2,
  N32_FPU_FS2_FCMPLES = 0x4,
  N32_FPU_FS2_FCMPUNS = 0x6,
  N32_FPU_FS2_FCMPEQS_E = 0x1,
  N32_FPU_FS2_FCMPLTS_E = 0x3,
  N32_FPU_FS2_FCMPLES_E = 0x5,
  N32_FPU_FS2_FCMPUNS_E = 0x7,

  /* FD1 b[9:6] */
  N32_FPU_FD1_FADDD = 0,
  N32_FPU_FD1_FSUBD,
  N32_FPU_FD1_FCPYNSD,
  N32_FPU_FD1_FCPYSD,
  N32_FPU_FD1_FMADDD,
  N32_FPU_FD1_FMSUBD,
  N32_FPU_FD1_FCMOVND,
  N32_FPU_FD1_FCMOVZD,
  N32_FPU_FD1_FNMADDD,
  N32_FPU_FD1_FNMSUBD,
  N32_FPU_FD1_10,
  N32_FPU_FD1_11,
  N32_FPU_FD1_FMULD = 12,
  N32_FPU_FD1_FDIVD,
  N32_FPU_FD1_14,
  N32_FPU_FD1_F2OP = 15,

  /* FD1/F2OP b[14:10] */
  N32_FPU_FD1_F2OP_FD2S = 0x00,
  N32_FPU_FD1_F2OP_FSQRTD = 0x01,
  N32_FPU_FD1_F2OP_FABSD = 0x05,
  N32_FPU_FD1_F2OP_FUI2D = 0x08,
  N32_FPU_FD1_F2OP_FSI2D = 0x0c,
  N32_FPU_FD1_F2OP_FD2UI = 0x10,
  N32_FPU_FD1_F2OP_FD2UI_Z = 0x14,
  N32_FPU_FD1_F2OP_FD2SI = 0x18,
  N32_FPU_FD1_F2OP_FD2SI_Z = 0x1c,

  /* FD2 b[9:6] */
  N32_FPU_FD2_FCMPEQD = 0x0,
  N32_FPU_FD2_FCMPLTD = 0x2,
  N32_FPU_FD2_FCMPLED = 0x4,
  N32_FPU_FD2_FCMPUND = 0x6,
  N32_FPU_FD2_FCMPEQD_E = 0x1,
  N32_FPU_FD2_FCMPLTD_E = 0x3,
  N32_FPU_FD2_FCMPLED_E = 0x5,
  N32_FPU_FD2_FCMPUND_E = 0x7,

  /* MFCP b[9:6] */
  N32_FPU_MFCP_FMFSR = 0x0,
  N32_FPU_MFCP_FMFDR = 0x1,
  N32_FPU_MFCP_XR = 0xc,

  /* MFCP/XR b[14:10] */
  N32_FPU_MFCP_XR_FMFCFG = 0x0,
  N32_FPU_MFCP_XR_FMFCSR = 0x1,

  /* MTCP b[9:6] */
  N32_FPU_MTCP_FMTSR = 0x0,
  N32_FPU_MTCP_FMTDR = 0x1,
  N32_FPU_MTCP_XR = 0xc,

  /* MTCP/XR b[14:10] */
  N32_FPU_MTCP_XR_FMTCSR = 0x1
};

enum n16_opcodes
{
  N16_T55_MOV55 = 0x0,
  N16_T55_MOVI55 = 0x1,

  N16_T45_0 = 0,
  N16_T45_ADD45 = 0x4,
  N16_T45_SUB45 = 0x5,
  N16_T45_ADDI45 = 0x6,
  N16_T45_SUBI45 = 0x7,
  N16_T45_SRAI45 = 0x8,
  N16_T45_SRLI45 = 0x9,
  N16_T45_LWI45_FE = 0x19,
  N16_T45_LWI450 = 0x1a,
  N16_T45_SWI450 = 0x1b,
  N16_T45_SLTS45 = 0x30,
  N16_T45_SLT45 = 0x31,
  N16_T45_SLTSI45 = 0x32,
  N16_T45_SLTI45 = 0x33,
  N16_T45_MOVPI45 = 0x3d,

  N15_T44_MOVD44 = 0x7d,

  N16_T333_0 = 0,
  N16_T333_SLLI333 = 0xa,
  N16_T333_BFMI333 = 0xb,
  N16_T333_ADD333 = 0xc,
  N16_T333_SUB333 = 0xd,
  N16_T333_ADDI333 = 0xe,
  N16_T333_SUBI333 = 0xf,
  N16_T333_LWI333 = 0x10,
  N16_T333_LWI333_BI = 0x11,
  N16_T333_LHI333 = 0x12,
  N16_T333_LBI333 = 0x13,
  N16_T333_SWI333 = 0x14,
  N16_T333_SWI333_BI = 0x15,
  N16_T333_SHI333 = 0x16,
  N16_T333_SBI333 = 0x17,
  N16_T333_MISC33 = 0x3f,

  N16_T36_ADDRI36_SP = 0x18,

  N16_T37_XWI37 = 0x7,
  N16_T37_XWI37SP = 0xe,

  N16_T38_BEQZ38 = 0x8,
  N16_T38_BNEZ38 = 0x9,
  N16_T38_BEQS38 = 0xa,
  N16_T38_BNES38 = 0xb,

  N16_T5_JR5 = 0x2e8,
  N16_T5_JRAL5 = 0x2e9,
  N16_T5_EX9IT = 0x2ea,
  /* 0x2eb reserved.  */
  N16_T5_RET5 = 0x2ec,
  N16_T5_ADD5PC = 0x2ed,
  /* 0x2e[ef] reserved.  */
  N16_T5_BREAK16 = 0x350,

  N16_T8_J8 = 0x55,
  N16_T8_BEQZS8 = 0x68,
  N16_T8_BNEZS8 = 0x69,

  /* N16_T9_BREAK16 = 0x35
     Since v3, SWID of BREAK16 above 32 are used for encoding EX9.IT.  */
  N16_T9_EX9IT = 0x35,
  N16_T9_IFCALL9 = 0x3c,

  N16_T10_ADDI10S = 0x1b,

  N16_T25_PUSH25 = 0xf8,
  N16_T25_POP25 = 0xf9,

  /* Sub-opcodes.  */
  N16_MISC33_0 = 0,
  N16_MISC33_1 = 1,
  N16_MISC33_NEG33 = 2,
  N16_MISC33_NOT33 = 3,
  N16_MISC33_MUL33 = 4,
  N16_MISC33_XOR33 = 5,
  N16_MISC33_AND33 = 6,
  N16_MISC33_OR33 = 7,

  N16_BFMI333_ZEB33 = 0,
  N16_BFMI333_ZEH33 = 1,
  N16_BFMI333_SEB33 = 2,
  N16_BFMI333_SEH33 = 3,
  N16_BFMI333_XLSB33 = 4,
  N16_BFMI333_X11B33 = 5,
  N16_BFMI333_BMSKI33 = 6,
  N16_BFMI333_FEXTI33 = 7
};

/* These macros a deprecated.  DO NOT use them anymore.
   And please help rewrite code used them.  */

/* 32-bit instructions without operands.  */
#define INSN_SETHI  0x46000000
#define INSN_ORI    0x58000000
#define INSN_JR     0x4a000000
#define INSN_RET    0x4a000020
#define INSN_JAL    0x49000000
#define INSN_J      0x48000000
#define INSN_JRAL   0x4a000001
#define INSN_BGEZAL 0x4e0c0000
#define INSN_BLTZAL 0x4e0d0000
#define INSN_BEQ    0x4c000000
#define INSN_BNE    0x4c004000
#define INSN_BEQZ   0x4e020000
#define INSN_BNEZ   0x4e030000
#define INSN_BGEZ   0x4e040000
#define INSN_BLTZ   0x4e050000
#define INSN_BGTZ   0x4e060000
#define INSN_BLEZ   0x4e070000
#define INSN_MOVI   0x44000000
#define INSN_ADDI   0x50000000
#define INSN_ANDI   0x54000000
#define INSN_LDI    0x06000000
#define INSN_SDI    0x16000000
#define INSN_LWI    0x04000000
#define INSN_LWSI   0x24000000
#define INSN_LWIP   0x0c000000
#define INSN_LHI    0x02000000
#define INSN_LHSI   0x22000000
#define INSN_LBI    0x00000000
#define INSN_LBSI   0x20000000
#define INSN_SWI    0x14000000
#define INSN_SWIP   0x1c000000
#define INSN_SHI    0x12000000
#define INSN_SBI    0x10000000
#define INSN_SLTI   0x5c000000
#define INSN_SLTSI  0x5e000000
#define INSN_ADD    0x40000000
#define INSN_SUB    0x40000001
#define INSN_SLT    0x40000006
#define INSN_SLTS   0x40000007
#define INSN_SLLI   0x40000008
#define INSN_SRLI   0x40000009
#define INSN_SRAI   0x4000000a
#define INSN_SEB    0x40000010
#define INSN_SEH    0x40000011
#define INSN_ZEB    INSN_ANDI + 0xFF
#define INSN_ZEH    0x40000013
#define INSN_BREAK  0x6400000a
#define INSN_NOP    0x40000009
#define INSN_FLSI   0x30000000
#define INSN_FSSI   0x32000000
#define INSN_FLDI   0x34000000
#define INSN_FSDI   0x36000000
#define INSN_BEQC   0x5a000000
#define INSN_BNEC   0x5a080000
#define INSN_DSB    0x64000008
#define INSN_IFCALL 0x4e000000
#define INSN_IFRET  0x4a000060
#define INSN_BR1    0x4c000000
#define INSN_BR2    0x4e000000

/* 16-bit instructions without operand.  */
#define INSN_MOV55	0x8000
#define INSN_MOVI55	0x8400
#define INSN_ADD45	0x8800
#define INSN_SUB45	0x8a00
#define INSN_ADDI45	0x8c00
#define INSN_SUBI45	0x8e00
#define INSN_SRAI45	0x9000
#define INSN_SRLI45	0x9200
#define INSN_SLLI333	0x9400
#define INSN_BFMI333	0x9600
#define INSN_ADD333	0x9800
#define INSN_SUB333	0x9a00
#define INSN_ADDI333	0x9c00
#define INSN_SUBI333	0x9e00
#define INSN_LWI333	0xa000
#define INSN_LWI333P	0xa200
#define INSN_LHI333	0xa400
#define INSN_LBI333	0xa600
#define INSN_SWI333	0xa800
#define INSN_SWI333P	0xaa00
#define INSN_SHI333	0xac00
#define INSN_SBI333	0xae00
#define INSN_RSV01	0xb000
#define INSN_RSV02	0xb200
#define INSN_LWI450	0xb400
#define INSN_SWI450	0xb600
#define INSN_LWI37	0xb800
#define INSN_SWI37	0xb880
#define INSN_BEQZ38	0xc000
#define INSN_BNEZ38	0xc800
#define INSN_BEQS38	0xd000
#define INSN_J8		0xd500
#define INSN_BNES38	0xd800
#define INSN_JR5	0xdd00
#define INSN_RET5	0xdd80
#define INSN_JRAL5	0xdd20
#define INSN_EX9_IT_2	0xdd40
#define INSN_SLTS45	0xe000
#define INSN_SLT45	0xe200
#define INSN_SLTSI45	0xe400
#define INSN_SLTI45	0xe600
#define INSN_BEQZS8	0xe800
#define INSN_BNEZS8	0xe900
#define INSN_BREAK16	0xea00
#define INSN_EX9_IT_1	0xea00
#define INSN_NOP16	0x9200
/* 16-bit version 2.  */
#define INSN_ADDI10_SP	0xec00
#define INSN_LWI37SP	0xf000
#define INSN_SWI37SP	0xf080
/* 16-bit version 3.  */
#define INSN_IFRET16	0x83ff
#define INSN_ADDRI36_SP	0xb000
#define INSN_LWI45_FE	0xb200
#define INSN_IFCALL9	0xf800
#define INSN_MISC33	0xfe00

/* Instruction with specific operands.  */
#define INSN_ADDI_GP_TO_FP	0x51cd8000	/* BASELINE_V1.  */
#define INSN_ADDIGP_TO_FP	0x3fc80000	/* BASELINE_V2.  */
#define INSN_MOVI_TO_FP		0x45c00000
#define INSN_MFUSR_PC		0x420F8020
#define INSN_MFUSR_PC_MASK	0xFE0FFFFF

/* Instructions use $ta register as operand.  */
#define INSN_SETHI_TA	(INSN_SETHI | (REG_TA << 20))
#define INSN_ORI_TA	(INSN_ORI | (REG_TA << 20) | (REG_TA << 15))
#define INSN_ADD_TA	(INSN_ADD | (REG_TA << 20))
#define INSN_ADD45_TA	(INSN_ADD45 | (REG_TA << 5))
#define INSN_JR5_TA	(INSN_JR5 | (REG_TA << 0))
#define INSN_RET5_TA	(INSN_RET5 | (REG_TA << 0))
#define INSN_JR_TA	(INSN_JR | (REG_TA << 10))
#define INSN_RET_TA	(INSN_RET | (REG_TA << 10))
#define INSN_JRAL_TA	(INSN_JRAL | (REG_LP << 20) | (REG_TA << 10))
#define INSN_JRAL5_TA	(INSN_JRAL5 | (REG_TA << 0))
#define INSN_BEQZ_TA	(INSN_BEQZ | (REG_TA << 20))
#define INSN_BNEZ_TA	(INSN_BNEZ | (REG_TA << 20))
#define INSN_MOVI_TA	(INSN_MOVI | (REG_TA << 20))
#define INSN_BEQ_TA	(INSN_BEQ | (REG_TA << 15))
#define INSN_BNE_TA	(INSN_BNE | (REG_TA << 15))

/* Instructions use $r5 register as operand.  */
#define INSN_BNE_R5	(INSN_BNE | (REG_R5 << 15))
#define INSN_BEQ_R5	(INSN_BEQ | (REG_R5 << 15))

#endif
