/* Definitions dealing with TriCore/PCP opcodes and core registers.
   Copyright (C) 1998-2003 Free Software Foundation, Inc.
   Contributed by Michael Schumacher (mike@hightec-rt.com).

This file is part of GDB, GAS, and the GNU binutils.

GDB, GAS, and the GNU binutils are free software; you can redistribute
them and/or modify them under the terms of the GNU General Public
License as published by the Free Software Foundation; either version
1, or (at your option) any later version.

GDB, GAS, and the GNU binutils are distributed in the hope that they
will be useful, but WITHOUT ANY WARRANTY; without even the implied
warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
the GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this file; see the file COPYING.  If not, write to the Free
Software Foundation, 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

/* Supported TriCore and PCP instruction set architectures.  */

typedef enum _tricore_opcode_arch_val
{
  TRICORE_GENERIC = 0x00000000,
  TRICORE_RIDER_A = 0x00000001,
  TRICORE_RIDER_B = 0x00000002,
  TRICORE_RIDER_D = TRICORE_RIDER_B,
  TRICORE_V2      = 0x00000004,
  TRICORE_PCP     = 0x00000010,
  TRICORE_PCP2    = 0x00000020
} tricore_isa;


#define bfd_mach_rider_a       0x0001
#define bfd_mach_rider_b       0x0002
#define bfd_mach_rider_c       0x0003
#define bfd_mach_rider_2       0x0004
#define bfd_mach_rider_d       0x0002
#define bfd_mach_rider_mask    0x000f

#define SEC_ARCH_BIT_0 0x008
/* Some handy definitions for upward/downward compatibility of insns.  */

#define TRICORE_V2_UP      TRICORE_V2
#define TRICORE_RIDER_D_UP (TRICORE_RIDER_D | TRICORE_V2_UP)
#define TRICORE_RIDER_B_UP (TRICORE_RIDER_B | TRICORE_RIDER_D_UP)

#define TRICORE_RIDER_B_DN TRICORE_RIDER_B
#define TRICORE_RIDER_D_DN (TRICORE_RIDER_D | TRICORE_RIDER_B_DN)
#define TRICORE_V2_DN      (TRICORE_V2 | TRICORE_RIDER_D_DN)

/* The various instruction formats of the TriCore architecture.  */

typedef enum _tricore_fmt
{
  /* 32-bit formats */

  TRICORE_FMT_ABS,
  TRICORE_FMT_ABSB,
  TRICORE_FMT_B,
  TRICORE_FMT_BIT,
  TRICORE_FMT_BO,
  TRICORE_FMT_BOL,
  TRICORE_FMT_BRC,
  TRICORE_FMT_BRN,
  TRICORE_FMT_BRR,
  TRICORE_FMT_RC,
  TRICORE_FMT_RCPW,
  TRICORE_FMT_RCR,
  TRICORE_FMT_RCRR,
  TRICORE_FMT_RCRW,
  TRICORE_FMT_RLC,
  TRICORE_FMT_RR,
  TRICORE_FMT_RR1,
  TRICORE_FMT_RR2,
  TRICORE_FMT_RRPW,
  TRICORE_FMT_RRR,
  TRICORE_FMT_RRR1,
  TRICORE_FMT_RRR2,
  TRICORE_FMT_RRRR,
  TRICORE_FMT_RRRW,
  TRICORE_FMT_SYS,

  /* 16-bit formats */

  TRICORE_FMT_SB,
  TRICORE_FMT_SBC,
  TRICORE_FMT_SBR,
  TRICORE_FMT_SBRN,
  TRICORE_FMT_SC,
  TRICORE_FMT_SLR,
  TRICORE_FMT_SLRO,
  TRICORE_FMT_SR,
  TRICORE_FMT_SRC,
  TRICORE_FMT_SRO,
  TRICORE_FMT_SRR,
  TRICORE_FMT_SRRS,
  TRICORE_FMT_SSR,
  TRICORE_FMT_SSRO,
  TRICORE_FMT_MAX /* Sentinel.  */
} tricore_fmt;

#if defined(__STDC__) || defined(ALMOST_STDC)
# define F(x) TRICORE_FMT_ ## x
#else
# define F(x) TRICORE_FMT_/**/x
#endif

/* Opcode masks for the instruction formats above.  */

extern unsigned long tricore_mask_abs;
extern unsigned long tricore_mask_absb;
extern unsigned long tricore_mask_b;
extern unsigned long tricore_mask_bit;
extern unsigned long tricore_mask_bo;
extern unsigned long tricore_mask_bol;
extern unsigned long tricore_mask_brc;
extern unsigned long tricore_mask_brn;
extern unsigned long tricore_mask_brr;
extern unsigned long tricore_mask_rc;
extern unsigned long tricore_mask_rcpw;
extern unsigned long tricore_mask_rcr;
extern unsigned long tricore_mask_rcrr;
extern unsigned long tricore_mask_rcrw;
extern unsigned long tricore_mask_rlc;
extern unsigned long tricore_mask_rr;
extern unsigned long tricore_mask_rr1;
extern unsigned long tricore_mask_rr2;
extern unsigned long tricore_mask_rrpw;
extern unsigned long tricore_mask_rrr;
extern unsigned long tricore_mask_rrr1;
extern unsigned long tricore_mask_rrr2;
extern unsigned long tricore_mask_rrrr;
extern unsigned long tricore_mask_rrrw;
extern unsigned long tricore_mask_sys;
extern unsigned long tricore_mask_sb;
extern unsigned long tricore_mask_sbc;
extern unsigned long tricore_mask_sbr;
extern unsigned long tricore_mask_sbrn;
extern unsigned long tricore_mask_sc;
extern unsigned long tricore_mask_slr;
extern unsigned long tricore_mask_slro;
extern unsigned long tricore_mask_sr;
extern unsigned long tricore_mask_src;
extern unsigned long tricore_mask_sro;
extern unsigned long tricore_mask_srr;
extern unsigned long tricore_mask_srrs;
extern unsigned long tricore_mask_ssr;
extern unsigned long tricore_mask_ssro;
extern unsigned long tricore_opmask[];

extern void tricore_init_arch_vars PARAMS ((unsigned long));

/* This structure describes TriCore opcodes.  */

struct tricore_opcode
{
  const char *name;		/* The opcode's mnemonic name.  */
  const int len32;		/* 1 if it's a 32-bit insn.  */
  const unsigned long opcode;	/* The binary code of this opcode.  */
  const unsigned long lose;	/* Mask for bits that must not be set.  */
  const tricore_fmt format;	/* The instruction format.  */
  const int nr_operands;	/* The number of operands.  */
  const char *args;	/* Kinds of operands (see below).  */
  const char *fields;	/* Where to put the operands (see below).  */
  const tricore_isa isa;	/* Instruction set architecture.  */
  int insind;			/* The insn's index (computed at runtime).  */
  int inslast;			/* Index of last insn w/ that name (dito).  */
};

extern struct tricore_opcode tricore_opcodes[];
extern const int tricore_numopcodes;
extern unsigned long tricore_opmask[];

/* This structure describes PCP/PCP2 opcodes.  */

struct pcp_opcode
{
  const char *name;		/* The opcode's mnemonic name.  */
  const int len32;		/* 1 if it's a 32-bit insn.  */
  const unsigned long opcode;	/* The binary code of this opcode.  */
  const unsigned long lose;	/* Mask for bits that must not be set.  */
  const int fmt_group;		/* The group ID of the instruction format.  */
  const int ooo;		/* 1 if operands may be given out of order.  */
  const int nr_operands;	/* The number of operands.  */
  const char *args;	/* Kinds of operands (see below),  */
  const tricore_isa isa;	/* PCP instruction set architecture.  */
  int insind;			/* The insn's index (computed at runtime).  */
  int inslast;			/* Index of last insn w/ that name (dito).  */
};

extern struct pcp_opcode pcp_opcodes[];
extern const int pcp_numopcodes;

/* This structure describes TriCore core registers (SFRs).  */

struct tricore_core_register
{
  const char *name;		/* The name of the register ($-prepended).  */
  const unsigned long addr;	/* The memory address of the register.  */
  const tricore_isa isa;	/* Instruction set architecture.  */
};

extern const struct tricore_core_register tricore_sfrs[];
extern const int tricore_numsfrs;

/* Kinds of operands for TriCore instructions:
   d  A simple data register (%d0-%d15).
   g  A simple data register with an 'l' suffix.
   G  A simple data register with an 'u' suffix.
   -  A simple data register with an 'll' suffix.
   +  A simple data register with an 'uu' suffix.
   l  A simple data register with an 'lu' suffix.
   L  A simple data register with an 'ul' suffix.
   D  An extended data register (d-register pair; %e0, %e2, ..., %e14).
   i  Implicit data register %d15.
   a  A simple address register (%a0-%a15).
   A  An extended address register (a-register pair; %a0, %a2, ..., %a14).
   I  Implicit address register %a15.
   P  Implicit stack register %a10.
   c  A core register ($psw, $pc etc.).
   1  A 1-bit zero-extended constant.
   2  A 2-bit zero-extended constant.
   3  A 3-bit zero-extended constant.
   4  A 4-bit sign-extended constant.
   f  A 4-bit zero-extended constant.
   5  A 5-bit zero-extended constant.
   F  A 5-bit sign-extended constant.
   v  A 5-bit zero-extended constant with bit 0 == 0 (=> 4bit/2).
   6  A 6-bit zero-extended constant with bits 0,1 == 0 (=> 4bit/4).
   8  A 8-bit zero-extended constant.
   9  A 9-bit sign-extended constant.
   n  A 9-bit zero-extended constant.
   k  A 10-bit zero-extended constant with bits 0,1 == 0 (=> 8bit/4).
   0  A 10-bit sign-extended constant.
   q  A 15-bit zero-extended constant.
   w  A 16-bit sign-extended constant.
   W  A 16-bit zero-extended constant.
   M  A 32-bit memory address.
   m  A 4-bit PC-relative offset (zero-extended, /2).
   r  A 4-bit PC-relative offset (one-extended, /2).
   x  A 5-bit PC-relative offset (zero-extended, /2).
   R  A 8-bit PC-relative offset (sign-extended, /2).
   o  A 15-bit PC-relative offset (sign-extended, /2).
   O  A 24-bit PC-relative offset (sign-extended, /2).
   t  A 18-bit absolute memory address (segmented).
   T  A 24-bit absolute memory address (segmented, /2).
   U  A symbol whose value isn't known yet.
   @  Register indirect ([%an]).
   &  SP indirect ([%sp] or [%a10]).
   <  Pre-incremented register indirect ([+%an]).
   >  Post-incremented register indirect ([%an+]).
   *  Circular address mode ([%An+c]).
   #  Bitreverse address mode ([%An+r]).
   ?  Indexed address mode ([%An+i]).
   S  Implicit base ([%a15]).
*/

/* The instruction fields where operands are stored.  */

#define FMT_ABS_NONE	'0'
#define FMT_ABS_OFF18	'1'
#define FMT_ABS_S1_D	'2'
#define FMT_ABSB_NONE	'0'
#define FMT_ABSB_OFF18	'1'
#define FMT_ABSB_B	'2'
#define FMT_ABSB_BPOS3	'3'
#define FMT_B_NONE	'0'
#define FMT_B_DISP24	'1'
#define FMT_BIT_NONE	'0'
#define FMT_BIT_D	'1'
#define FMT_BIT_P2	'2'
#define FMT_BIT_P1	'3'
#define FMT_BIT_S2	'4'
#define FMT_BIT_S1	'5'
#define FMT_BO_NONE	'0'
#define FMT_BO_OFF10	'1'
#define FMT_BO_S2	'2'
#define FMT_BO_S1_D	'3'
#define FMT_BOL_NONE	'0'
#define FMT_BOL_OFF16	'1'
#define FMT_BOL_S2	'2'
#define FMT_BOL_S1_D	'3'
#define FMT_BRC_NONE	'0'
#define FMT_BRC_DISP15	'1'
#define FMT_BRC_CONST4	'2'
#define FMT_BRC_S1	'3'
#define FMT_BRN_NONE	'0'
#define FMT_BRN_DISP15	'1'
#define FMT_BRN_N	'2'
#define FMT_BRN_S1	'3'
#define FMT_BRR_NONE	'0'
#define FMT_BRR_DISP15	'1'
#define FMT_BRR_S2	'2'
#define FMT_BRR_S1	'3'
#define FMT_RC_NONE	'0'
#define FMT_RC_D	'1'
#define FMT_RC_CONST9	'2'
#define FMT_RC_S1	'3'
#define FMT_RCPW_NONE	'0'
#define FMT_RCPW_D	'1'
#define FMT_RCPW_P	'2'
#define FMT_RCPW_W	'3'
#define FMT_RCPW_CONST4	'4'
#define FMT_RCPW_S1	'5'
#define FMT_RCR_NONE	'0'
#define FMT_RCR_D	'1'
#define FMT_RCR_S3	'2'
#define FMT_RCR_CONST9	'3'
#define FMT_RCR_S1	'4'
#define FMT_RCRR_NONE	'0'
#define FMT_RCRR_D	'1'
#define FMT_RCRR_S3	'2'
#define FMT_RCRR_CONST4	'3'
#define FMT_RCRR_S1	'4'
#define FMT_RCRW_NONE	'0'
#define FMT_RCRW_D	'1'
#define FMT_RCRW_S3	'2'
#define FMT_RCRW_W	'3'
#define FMT_RCRW_CONST4	'4'
#define FMT_RCRW_S1	'5'
#define FMT_RLC_NONE	'0'
#define FMT_RLC_D	'1'
#define FMT_RLC_CONST16	'2'
#define FMT_RLC_S1	'3'
#define FMT_RR_NONE	'0'
#define FMT_RR_D	'1'
#define FMT_RR_N	'2'
#define FMT_RR_S2	'3'
#define FMT_RR_S1	'4'
#define FMT_RR1_NONE	'0'
#define FMT_RR1_D	'1'
#define FMT_RR1_N	'2'
#define FMT_RR1_S2	'3'
#define FMT_RR1_S1	'4'
#define FMT_RR2_NONE	'0'
#define FMT_RR2_D	'1'
#define FMT_RR2_S2	'2'
#define FMT_RR2_S1	'3'
#define FMT_RRPW_NONE	'0'
#define FMT_RRPW_D	'1'
#define FMT_RRPW_P	'2'
#define FMT_RRPW_W	'3'
#define FMT_RRPW_S2	'4'
#define FMT_RRPW_S1	'5'
#define FMT_RRR_NONE	'0'
#define FMT_RRR_D	'1'
#define FMT_RRR_S3	'2'
#define FMT_RRR_N	'3'
#define FMT_RRR_S2	'4'
#define FMT_RRR_S1	'5'
#define FMT_RRR1_NONE	'0'
#define FMT_RRR1_D	'1'
#define FMT_RRR1_S3	'2'
#define FMT_RRR1_N	'3'
#define FMT_RRR1_S2	'4'
#define FMT_RRR1_S1	'5'
#define FMT_RRR2_NONE	'0'
#define FMT_RRR2_D	'1'
#define FMT_RRR2_S3	'2'
#define FMT_RRR2_S2	'3'
#define FMT_RRR2_S1	'4'
#define FMT_RRRR_NONE	'0'
#define FMT_RRRR_D	'1'
#define FMT_RRRR_S3	'2'
#define FMT_RRRR_S2	'3'
#define FMT_RRRR_S1	'4'
#define FMT_RRRW_NONE	'0'
#define FMT_RRRW_D	'1'
#define FMT_RRRW_S3	'2'
#define FMT_RRRW_W	'3'
#define FMT_RRRW_S2	'4'
#define FMT_RRRW_S1	'5'
#define FMT_SYS_NONE	'0'
#define FMT_SYS_S1_D	'1'
#define FMT_SB_NONE	'0'
#define FMT_SB_DISP8	'1'
#define FMT_SBC_NONE	'0'
#define FMT_SBC_CONST4	'1'
#define FMT_SBC_DISP4	'2'
#define FMT_SBR_NONE	'0'
#define FMT_SBR_S2	'1'
#define FMT_SBR_DISP4	'2'
#define FMT_SBRN_NONE	'0'
#define FMT_SBRN_N	'1'
#define FMT_SBRN_DISP4	'2'
#define FMT_SC_NONE	'0'
#define FMT_SC_CONST8	'1'
#define FMT_SLR_NONE	'0'
#define FMT_SLR_S2	'1'
#define FMT_SLR_D	'2'
#define FMT_SLRO_NONE	'0'
#define FMT_SLRO_OFF4	'1'
#define FMT_SLRO_D	'2'
#define FMT_SR_NONE	'0'
#define FMT_SR_S1_D	'1'
#define FMT_SRC_NONE	'0'
#define FMT_SRC_CONST4	'1'
#define FMT_SRC_S1_D	'2'
#define FMT_SRO_NONE	'0'
#define FMT_SRO_S2	'1'
#define FMT_SRO_OFF4	'2'
#define FMT_SRR_NONE	'0'
#define FMT_SRR_S2	'1'
#define FMT_SRR_S1_D	'2'
#define FMT_SRRS_NONE	'0'
#define FMT_SRRS_S2	'1'
#define FMT_SRRS_S1_D	'2'
#define FMT_SRRS_N	'3'
#define FMT_SSR_NONE	'0'
#define FMT_SSR_S2	'1'
#define FMT_SSR_S1	'2'
#define FMT_SSRO_NONE	'0'
#define FMT_SSRO_OFF4	'1'
#define FMT_SSRO_S1	'2'

/* Kinds of operands for PCP instructions:
   a  Condition code 0-7 (CONDCA).
   b  Condition code 8-15 (CONDCB).
   c  CNC=[0,1,2].
   d  DST{+,-}.
   e  A constant expression.
   E  An indirect constant expression.
   f  SIZE=[8,16,32].
   g  ST=[0,1].
   h  EC=[0,1].
   i  INT=[0,1].
   j  EP=[0,1].
   k  SET (const value 1).
   l  CLR (const value 0).
   m  DAC=[0,1].
   n  CNT0=[1..8] for COPY, or [2,4,8] for BCOPY.
   o  RTA=[0,1].
   p  EDA=[0,1].
   q  SDB=[0,1].
   r  A direct register (R0-R7).
   R  An indirect register ([R0]-[R7]).
   s  SRC{+,-}.
   u  A direct symbol whose value isn't known yet.
   U  An indirect symbol whose value isn't known yet.
*/

/* End of tricore.h.  */
