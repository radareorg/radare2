/* Disassemble TriCore and PCP instructions.
   Copyright (C) 1998-2003 Free Software Foundation, Inc.
   Contributed by Michael Schumacher (mike@hightec-rt.com), condret (2016).

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335 USA. */

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>

#include "ansidecl.h"
#include "sysdep.h"
#include "opcode/tricore.h"
#include "disas-asm.h"
#ifndef _MSC_VER
#include "libiberty.h"
#else
#include <stdlib.h>
#define XNEWVEC(T, N)		((T *) malloc (sizeof (T) * (N)))
#define XCNEWVEC(T, N)		((T *) calloc ((N), sizeof (T)))
#define XNEW(T)			((T *) malloc (sizeof (T)))
#define xmalloc malloc
#endif

#if 0
#define REGPREFIX "%%"
#else
#define REGPREFIX ""
#endif

#define NUMOPCS tricore_numopcodes
#define NUMSFRS tricore_numsfrs
#define NUMPCPOPCS pcp_numopcodes
#define MAX_OPS 5
#define MATCHES_ISA(isa) \
	  (((isa) == TRICORE_GENERIC) \
	   || (((isa) & bfd_mach_rider_mask) & current_isa))

/* Some handy shortcuts.  */

typedef struct tricore_opcode opcode_t;
typedef struct pcp_opcode pcp_opcode_t;
typedef const struct tricore_core_register sfr_t;

/* For faster lookup, we hash instruction opcodes and SFRs.  */

struct insnlist
{
  opcode_t *code;
  struct insnlist *next;
};

/* TriCore insns have only 6 significant bits (because of the 16-bit
   SRRS format), so the hash table needs being restricted to 64 entries.  */

static struct insnlist *insns[64];
static struct insnlist *insnlink;

/* PCP insns have only 5 significant bits (because of encoding group 0).  */

struct pcplist
{
  pcp_opcode_t *code;
  struct pcplist *next;
};

static struct pcplist *pcpinsns[32];
static struct pcplist *pcplink;

/* The hash key for SFRs is their LSB.  */

struct sfrlist
{
  sfr_t *sfr;
  struct sfrlist *next;
};

static struct sfrlist *sfrs[256];
static struct sfrlist *sfrlink;

/* 1 if the hash tables are initialized.  */

static int initialized = 0;

/* Which TriCore instruction set architecture are we dealing with?  */

static tricore_isa current_isa = TRICORE_RIDER_B;

/* If we can find the instruction matching a given opcode, we decode
   its operands and store them in the following structure.  */

struct decoded_insn
{
  opcode_t *code;
  unsigned long opcode;
  int regs[MAX_OPS];
  unsigned long cexp[MAX_OPS];
};

static struct decoded_insn dec_insn;

/* Forward declarations of decoding functions.  */

static void decode_abs PARAMS ((void));
static void decode_absb PARAMS ((void));
static void decode_b PARAMS ((void));
static void decode_bit PARAMS ((void));
static void decode_bo PARAMS ((void));
static void decode_bol PARAMS ((void));
static void decode_brc PARAMS ((void));
static void decode_brn PARAMS ((void));
static void decode_brr PARAMS ((void));
static void decode_rc PARAMS ((void));
static void decode_rcpw PARAMS ((void));
static void decode_rcr PARAMS ((void));
static void decode_rcrr PARAMS ((void));
static void decode_rcrw PARAMS ((void));
static void decode_rlc PARAMS ((void));
static void decode_rr PARAMS ((void));
static void decode_rr1 PARAMS ((void));
static void decode_rr2 PARAMS ((void));
static void decode_rrpw PARAMS ((void));
static void decode_rrr PARAMS ((void));
static void decode_rrr1 PARAMS ((void));
static void decode_rrr2 PARAMS ((void));
static void decode_rrrr PARAMS ((void));
static void decode_rrrw PARAMS ((void));
static void decode_sys PARAMS ((void));
static void decode_sb PARAMS ((void));
static void decode_sbc PARAMS ((void));
static void decode_sbr PARAMS ((void));
static void decode_sbrn PARAMS ((void));
static void decode_sc PARAMS ((void));
static void decode_slr PARAMS ((void));
static void decode_slro PARAMS ((void));
static void decode_sr PARAMS ((void));
static void decode_src PARAMS ((void));
static void decode_sro PARAMS ((void));
static void decode_srr PARAMS ((void));
static void decode_srrs PARAMS ((void));
static void decode_ssr PARAMS ((void));
static void decode_ssro PARAMS ((void));

/* Array of function pointers to decoding functions.  */

static void (*decode[]) PARAMS ((void)) =
{
  /* 32-bit formats.  */
  decode_abs, decode_absb, decode_b, decode_bit, decode_bo, decode_bol,
  decode_brc, decode_brn, decode_brr, decode_rc, decode_rcpw, decode_rcr,
  decode_rcrr, decode_rcrw, decode_rlc, decode_rr, decode_rr1, decode_rr2,
  decode_rrpw, decode_rrr, decode_rrr1, decode_rrr2, decode_rrrr,
  decode_rrrw, decode_sys,

  /* 16-bit formats.  */
  decode_sb, decode_sbc, decode_sbr, decode_sbrn, decode_sc, decode_slr,
  decode_slro, decode_sr, decode_src, decode_sro, decode_srr,
  decode_srrs, decode_ssr, decode_ssro
};

/* More forward declarations.  */

static unsigned long extract_off18 PARAMS ((void));
static void init_hash_tables PARAMS ((void));
static const char *find_core_reg PARAMS ((unsigned long));
static void print_decoded_insn PARAMS ((bfd_vma, struct disassemble_info *));
static int decode_tricore_insn PARAMS ((bfd_vma, unsigned long, int,
					struct disassemble_info *));
static int decode_pcp_insn PARAMS ((bfd_vma, bfd_byte [4],
				    struct disassemble_info *));

/* Here come the decoding functions.  If you thought that the encoding
   functions in the assembler were somewhat, umm,  boring, you should
   take a serious look at their counterparts below.  They're even more so!
   *yawn*   */

static unsigned long
extract_off18 ()
{
  unsigned long o1, o2, o3, o4;
  unsigned long val = dec_insn.opcode;

  o1 = (val & 0x003f0000) >> 16;
  o2 = (val & 0xf0000000) >> 22;
  o3 = (val & 0x03c00000) >> 12;
  o4 = (val & 0x0000f000) << 2;
  return o1 | o2 | o3 | o4;
}

static void
decode_abs ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_ABS_OFF18:
		  dec_insn.cexp[i] = extract_off18 ();
		  break;

	  case FMT_ABS_S1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf00) >> 8;
		  break;
	  }
  }
}

static void
decode_absb ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_ABSB_OFF18:
		  dec_insn.cexp[i] = extract_off18 ();
		  break;

	  case FMT_ABSB_B:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x800) >> 11;
		  break;

	  case FMT_ABSB_BPOS3:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x700) >> 8;
		  break;
	  }
  }
}

static void
decode_b ()
{
  int i;
  unsigned long o1, o2;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_B_DISP24:
		  o1 = (dec_insn.opcode & 0xffff0000) >> 16;
		  o2 = (dec_insn.opcode & 0x0000ff00) << 8;
		  dec_insn.cexp[i] = o1 | o2;
		  break;
	  }
  }
}

static void
decode_bit ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_BIT_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_BIT_P2:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0f800000) >> 23;
		  break;

	  case FMT_BIT_P1:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x001f0000) >> 16;
		  break;

	  case FMT_BIT_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_BIT_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_bo ()
{
  int i;
  unsigned long o1, o2;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_BO_OFF10:
		  o1 = (dec_insn.opcode & 0x003f0000) >> 16;
		  o2 = (dec_insn.opcode & 0xf0000000) >> 22;
		  dec_insn.cexp[i] = o1 | o2;
		  break;

	  case FMT_BO_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_BO_S1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_bol ()
{
  int i;
  unsigned long o1, o2, o3;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_BOL_OFF16:
		  o1 = (dec_insn.opcode & 0x003f0000) >> 16;
		  o2 = (dec_insn.opcode & 0xf0000000) >> 22;
		  o3 = (dec_insn.opcode & 0x0fc00000) >> 12;
		  dec_insn.cexp[i] = o1 | o2 | o3;
		  break;

	  case FMT_BOL_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_BOL_S1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_brc ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_BRC_DISP15:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x7fff0000) >> 16;
		  break;

	  case FMT_BRC_CONST4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_BRC_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_brn ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_BRN_DISP15:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x7fff0000) >> 16;
		  break;

	  case FMT_BRN_N:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  dec_insn.cexp[i] |= (dec_insn.opcode & 0x00000080) >> 3;
		  break;

	  case FMT_BRN_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_brr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_BRR_DISP15:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x7fff0000) >> 16;
		  break;

	  case FMT_BRR_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_BRR_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rc ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RC_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RC_CONST9:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x001ff000) >> 12;
		  break;

	  case FMT_RC_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
	  }
  }
}

static void
decode_rcpw ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RCPW_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RCPW_P:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0f800000) >> 23;
		  break;

	  case FMT_RCPW_W:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x001f0000) >> 16;
		  break;

	  case FMT_RCPW_CONST4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RCPW_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rcr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RCR_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RCR_S3:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f000000) >> 24;
		  break;

	  case FMT_RCR_CONST9:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x001ff000) >> 12;
		  break;

	  case FMT_RCR_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rcrr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RCRR_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RCRR_S3:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f000000) >> 24;
		  break;

	  case FMT_RCRR_CONST4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RCRR_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rcrw ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RCRW_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RCRW_S3:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f000000) >> 24;
		  break;

	  case FMT_RCRW_W:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x001f0000) >> 16;
		  break;

	  case FMT_RCRW_CONST4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RCRW_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rlc ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RLC_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RLC_CONST16:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0ffff000) >> 12;
		  break;

	  case FMT_RLC_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RR_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RR_N:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x00030000) >> 16;
		  break;

	  case FMT_RR_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RR_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rr1 ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RR1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RR1_N:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x00030000) >> 16;
		  break;

	  case FMT_RR1_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RR1_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rr2 ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RR2_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RR2_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RR2_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rrpw ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RRPW_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RRPW_P:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0f800000) >> 23;
		  break;

	  case FMT_RRPW_W:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x001f0000) >> 16;
		  break;

	  case FMT_RRPW_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RRPW_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rrr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RRR_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RRR_S3:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f000000) >> 24;
		  break;

	  case FMT_RRR_N:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x00030000) >> 16;
		  break;

	  case FMT_RRR_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RRR_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rrr1 ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RRR1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RRR1_S3:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f000000) >> 24;
		  break;

	  case FMT_RRR1_N:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x00030000) >> 16;
		  break;

	  case FMT_RRR1_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RRR1_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rrr2 ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RRR2_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RRR2_S3:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f000000) >> 24;
		  break;

	  case FMT_RRR2_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RRR2_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rrrr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RRRR_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RRRR_S3:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f000000) >> 24;
		  break;

	  case FMT_RRRR_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RRRR_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_rrrw ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_RRRW_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf0000000) >> 28;
		  break;

	  case FMT_RRRW_S3:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f000000) >> 24;
		  break;

	  case FMT_RRRW_W:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x001f0000) >> 16;
		  break;

	  case FMT_RRRW_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0000f000) >> 12;
		  break;

	  case FMT_RRRW_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_sys ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SYS_S1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x00000f00) >> 8;
		  break;
	  }
  }
}

static void
decode_sb ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SB_DISP8:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0xff00) >> 8;
		  break;
	  }
  }
}

static void
decode_sbc ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SBC_CONST4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SBC_DISP4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  if (dec_insn.code->args[i] == 'x') {
			  dec_insn.cexp[i] += 0x10;
		  }
		  break;
	  }
  }
}

static void
decode_sbr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SBR_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SBR_DISP4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  if (dec_insn.code->args[i] == 'x') {
			  dec_insn.cexp[i] += 0x10;
		  }
		  break;
	  }
  }
}

static void
decode_sbrn ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SBRN_N:
		  if (dec_insn.code->args[i] == '5') {
			  dec_insn.cexp[i] = (dec_insn.opcode & 0xf000) >> 12;
			  dec_insn.cexp[i] |= (dec_insn.opcode & 0x0080) >> 3;
		  } else {
			  dec_insn.cexp[i] = (dec_insn.opcode & 0xf000) >> 12;
		  }
		  break;

	  case FMT_SBRN_DISP4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

static void
decode_sc ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SC_CONST8:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0xff00) >> 8;
		  break;
	  }
  }
}

static void
decode_slr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SLR_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SLR_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

static void
decode_slro ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SLRO_OFF4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SLRO_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

static void
decode_sr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SR_S1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

static void
decode_src ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SRC_CONST4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SRC_S1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

static void
decode_sro ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SRO_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SRO_OFF4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

static void
decode_srr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SRR_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SRR_S1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

static void
decode_srrs ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SRRS_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SRRS_S1_D:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;

	  case FMT_SRRS_N:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0x00c0) >> 6;
		  break;
	  }
  }
}

static void
decode_ssr ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SSR_S2:
		  dec_insn.regs[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SSR_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

static void
decode_ssro ()
{
  int i;

  for (i = 0; i < dec_insn.code->nr_operands; ++i) {
	  switch (dec_insn.code->fields[i]) {
	  case FMT_SSRO_OFF4:
		  dec_insn.cexp[i] = (dec_insn.opcode & 0xf000) >> 12;
		  break;

	  case FMT_SSRO_S1:
		  dec_insn.regs[i] = (dec_insn.opcode & 0x0f00) >> 8;
		  break;
	  }
  }
}

/* Initialize the hash tables for instructions and SFRs.  */

static void
init_hash_tables ()
{
  opcode_t *pop;
  pcp_opcode_t *ppop;
  sfr_t *psfr;
  int i, idx;

  insnlink = (struct insnlist *) xmalloc (NUMOPCS * sizeof (struct insnlist));
  pcplink = (struct pcplist *) xmalloc (NUMPCPOPCS * sizeof (struct pcplist));
  sfrlink = (struct sfrlist *) xmalloc (NUMSFRS * sizeof (struct sfrlist));
  memset ((char *) insns, 0, sizeof (insns));
  memset ((char *) insnlink, 0, NUMOPCS * sizeof (struct insnlist));
  memset ((char *) pcpinsns, 0, sizeof (pcpinsns));
  memset ((char *) pcplink, 0, NUMPCPOPCS * sizeof (struct pcplist));
  memset ((char *) sfrs, 0, sizeof (sfrs));
  memset ((char *) sfrlink, 0, NUMSFRS * sizeof (struct sfrlist));

  for (i = 0, pop = tricore_opcodes; i < NUMOPCS; ++i, ++pop)
    {
	  if (!MATCHES_ISA (pop->isa)) {
		  continue;
	  }

	  idx = pop->opcode & 0x3f;
	  if (insns[idx]) {
		  insnlink[i].next = insns[idx];
	  }
	  insns[idx] = &insnlink[i];
	  insnlink[i].code = pop;
    }

  for (i = 0, ppop = pcp_opcodes; i < NUMPCPOPCS; ++i, ++ppop)
    {
      idx = (ppop->opcode >> 11) & 0x1f;
      if (pcpinsns[idx]) {
	      pcplink[i].next = pcpinsns[idx];
      }
      pcpinsns[idx] = &pcplink[i];
      pcplink[i].code = ppop;
    }

  for (i = 0, psfr = tricore_sfrs; i < NUMSFRS; ++i, ++psfr)
    {
	  if (!MATCHES_ISA (psfr->isa)) {
		  continue;
	  }

	  idx = psfr->addr & 0xff;
	  if (sfrs[idx]) {
		  sfrlink[i].next = sfrs[idx];
	  }
	  sfrs[idx] = &sfrlink[i];
	  sfrlink[i].sfr = psfr;
    }
}

/* Return the name of the core register (SFR) located at offset ADDR.  */

static const char *
find_core_reg (addr)
     unsigned long addr;
{
  struct sfrlist *psfr;
  int idx = addr & 0xff;

  for (psfr = sfrs[idx]; psfr != NULL; psfr = psfr->next) {
	  if ((psfr->sfr->addr == addr) && MATCHES_ISA (psfr->sfr->isa)) {
		  return psfr->sfr->name;
	  }
  }

  return (char *) 0;
}

/* Print the decoded TriCore instruction starting at MEMADDR.  */

static void
print_decoded_insn (memaddr, info)
     bfd_vma memaddr;
     struct disassemble_info *info;
{
  opcode_t *insn = dec_insn.code;
  int i, needs_creg = 0, need_comma;
  const char *creg;
  bfd_vma abs;
  static bfd_vma next_addr = 0;
  static bool expect_lea = false;
#define NO_AREG	16
  static int load_areg[NO_AREG] = {false,false,false,false,false,false,false,false,false,false,false,false,false,false,false,false};
  static unsigned long load_hi_addr[NO_AREG] = {0};
  static unsigned long load_addr = 0;
  static bool print_symbolic_address = false;
#define DPRINT (*info->fprintf_func)
#define DFILE info->stream

  /* Special cases: "nor %dn" / "nor %dn,%dn,0" -> "not %dn"  */
  if (((*insn->name == 'n') && !strcmp (insn->name, "nor"))
      && ((insn->nr_operands == 1)
          || ((insn->nr_operands == 3)
	      && (insn->args[2] == 'n')
              && (dec_insn.regs[0] == dec_insn.regs[1])
	      && (dec_insn.cexp[2] == 0))))
    {
      DPRINT (DFILE, "not "REGPREFIX"d%d", dec_insn.regs[0]);
      return;
  } else {
	  DPRINT (DFILE, "%s ", insn->name);
  }

  /* Being a child of the RISC generation, a TriCore-based CPU generally
     must load a 32-bit wide address in two steps, usually by executing
     an instruction sequence like "movh.a %an,hi:sym; lea %am,[%an]lo:sym"
     (an optimizing compiler performing instruction scheduling, such as
     GCC, may insert other instructions between "movh.a" and "lea", but
     that doesn't matter at all, because it doesn't change the execution
     order of the two instructions, and this function can only disassemble
     a single instruction at a time, anyway).  We would like to see which
     address is being loaded (or, more precisely, which symbol lives at
     the address being loaded), so we keep track of "movh.a" and "lea"
     instructions, and print the symbolic address after a "lea" insn
     if we can be reasonably sure that it is part of the load sequence
     described above.  Note that "lea" is used here as a generic insn;
     it actually may also be any load or store instruction.  */
  if (memaddr != next_addr) {
	  expect_lea = print_symbolic_address = false;
  }
  next_addr = memaddr + (insn->len32 ? 4 : 2);

  if (!strcmp (insn->name, "movh.a"))
    {
      load_areg[dec_insn.regs[0]] = true;
      load_hi_addr[dec_insn.regs[0]] = dec_insn.cexp[1] << 16;
      expect_lea = true;
      print_symbolic_address = false;
    }
  else if (expect_lea
	   && (!strcmp (insn->name, "lea")
	       || !strncmp (insn->name, "ld.", 3)
	       || !strncmp (insn->name, "st.", 3)
	       || !strncmp (insn->name, "swap", 4)
	       || !strcmp (insn->name, "ldmst")))
    {
      if (insn->nr_operands == 3)
	{
	  if ((!strcmp (insn->name, "lea")
	       || !strncmp (insn->name, "ld.", 3)
	       || !strcmp (insn->name, "ldmst"))
		 ) {
	     if ((true == load_areg[dec_insn.regs[1]]))
	    {
	      load_addr = load_hi_addr[dec_insn.regs[1]] + (short) dec_insn.cexp[2];
	      print_symbolic_address = true;
	    }
      }
	  else if (true == load_areg[dec_insn.regs[0]])
	    {
	      load_addr = load_hi_addr[dec_insn.regs[0]] + (short) dec_insn.cexp[1];
	      print_symbolic_address = true;
	    }
	}
    } else {
	    print_symbolic_address = false;
    }

    if (!strncmp (insn->name, "ld.a", 4)) {
	    load_areg[dec_insn.regs[0]] = false;
    } else if (!strncmp (insn->name, "add.a", 5) || !strncmp (insn->name, "sub.a", 5) || !strcmp (insn->name, "mov.a") || !strncmp (insn->name, "addsc.a", 7)) {
	    load_areg[dec_insn.regs[0]] = false;
    } else if (!strcmp (insn->name, "mov.aa")) {
	    load_areg[dec_insn.regs[0]] = load_areg[dec_insn.regs[1]];
    } else if (!strncmp (insn->name, "call", 4)) {
	    int i = 0;
	    for (i = 2; i < 8; i++) {
		    load_areg[i] = false;
	    }
  }
  else
  if (!strncmp(insn->name,"ret",3)) {
	int i = 0;
	for (i = 2; i < 8; i++) {
		load_areg[i] = false;
	}
	for (i = 10; i < 16; i++) {
		load_areg[i] = false;
	}
  }

  if (!strcmp (insn->name, "mfcr") || !strcmp (insn->name, "mtcr")) {
	  needs_creg = 1;
  }

  for (i = 0; i < insn->nr_operands; ++i)
    {
      need_comma = (i < (insn->nr_operands - 1));
      switch (insn->args[i])
        {
	case 'd':
	  DPRINT (DFILE, ""REGPREFIX"d%d", dec_insn.regs[i]);
	  break;

	case 'g':
	  DPRINT (DFILE, ""REGPREFIX"d%dl", dec_insn.regs[i]);
	  break;

	case 'G':
	  DPRINT (DFILE, ""REGPREFIX"d%du", dec_insn.regs[i]);
	  break;

	case '-':
	  DPRINT (DFILE, ""REGPREFIX"d%dll", dec_insn.regs[i]);
	  break;

	case '+':
	  DPRINT (DFILE, ""REGPREFIX"d%duu", dec_insn.regs[i]);
	  break;

	case 'l':
	  DPRINT (DFILE, ""REGPREFIX"d%dlu", dec_insn.regs[i]);
	  break;

	case 'L':
	  DPRINT (DFILE, ""REGPREFIX"d%dul", dec_insn.regs[i]);
	  break;

	case 'D':
	  DPRINT (DFILE, ""REGPREFIX"e%d", dec_insn.regs[i]);
	  break;

	case 'i':
	  DPRINT (DFILE, ""REGPREFIX"d15");
	  break;

	case 'a':
	case 'A':
	  if (dec_insn.regs[i] == 10) {
	    DPRINT (DFILE, ""REGPREFIX"sp");
	  } else {
		  DPRINT (DFILE, "" REGPREFIX "a%d", dec_insn.regs[i]);
	  }
	  break;

	case 'I':
	  DPRINT (DFILE, ""REGPREFIX"a15");
	  break;

	case 'P':
	  DPRINT (DFILE, ""REGPREFIX"sp");
	  break;

	case 'k':
        case '6':
	  dec_insn.cexp[i] <<= 1;
	  /* Fall through. */
	case 'v':
	  dec_insn.cexp[i] <<= 1;
	  /* Fall through. */
	case '1':
	case '2':
	case '3':
	case 'f':
	case '5':
	case '8':
	case 'n':
	case 'M':
	  DPRINT (DFILE, "%lu", dec_insn.cexp[i]);
	  break;

	case '4':
		if (dec_insn.cexp[i] & 0x8) {
			dec_insn.cexp[i] |= ~0xf;
		}
		DPRINT (DFILE, "%ld", dec_insn.cexp[i]);
		break;

	case 'F':
		if (dec_insn.cexp[i] & 0x10) {
			dec_insn.cexp[i] |= ~0x1f;
		}
		DPRINT (DFILE, "%ld", dec_insn.cexp[i]);
		break;

	case '9':
		if (dec_insn.cexp[i] & 0x100) {
			dec_insn.cexp[i] |= ~0x1ff;
		}
		DPRINT (DFILE, "%ld", dec_insn.cexp[i]);
		break;

	case '0':
		if (dec_insn.cexp[i] & 0x200) {
			dec_insn.cexp[i] |= ~0x3ff;
		}
		DPRINT (DFILE, "%ld", dec_insn.cexp[i]);
		if (print_symbolic_address) {
			DPRINT (DFILE, " <");
			(*info->print_address_func) (load_addr, info);
			DPRINT (DFILE, ">");
	    }
	  break;

	case 'w':
		if (dec_insn.cexp[i] & 0x8000) {
			dec_insn.cexp[i] |= ~0xffff;
		}
		DPRINT (DFILE, "%ld", dec_insn.cexp[i]);
		if (print_symbolic_address) {
			DPRINT (DFILE, " <");
			(*info->print_address_func) (load_addr, info);
			DPRINT (DFILE, ">");
	    }
	  break;

	case 't':
	  abs =  (dec_insn.cexp[i] & 0x00003fff);
	  abs |= (dec_insn.cexp[i] & 0x0003c000) << 14;
	  (*info->print_address_func) (abs, info);
	  break;

	case 'T':
	  abs =  (dec_insn.cexp[i] & 0x000fffff) << 1;
	  abs |= (dec_insn.cexp[i] & 0x00f00000) << 8;
	  (*info->print_address_func) (abs, info);
	  break;

	case 'o':
		if (dec_insn.cexp[i] & 0x4000) {
			dec_insn.cexp[i] |= ~0x7fff;
		}
		abs = (dec_insn.cexp[i] << 1) + memaddr;
		(*info->print_address_func) (abs, info);
		break;

	case 'O':
		if (dec_insn.cexp[i] & 0x800000) {
			dec_insn.cexp[i] |= ~0xffffff;
		}
		abs = (dec_insn.cexp[i] << 1) + memaddr;
		(*info->print_address_func) (abs, info);
		break;

	case 'R':
		if (dec_insn.cexp[i] & 0x80) {
			dec_insn.cexp[i] |= ~0xff;
		}
		abs = (dec_insn.cexp[i] << 1) + memaddr;
		(*info->print_address_func) (abs, info);
		break;

	case 'r':
	  dec_insn.cexp[i] |= ~0xf;
	  /* Fall through. */
	case 'm':
	case 'x':
	  abs = (dec_insn.cexp[i] << 1) + memaddr;
	  (*info->print_address_func) (abs, info);
	  break;
	  
	case 'c':
	  needs_creg = 1;
	  /* Fall through. */
	case 'W':
	  if (needs_creg)
	    {
	      creg = find_core_reg (dec_insn.cexp[i]);
	      if (creg) {
#ifdef RESOLVE_SFR_NAMES
		      DPRINT (DFILE, "%s", creg);
#else
		      DPRINT (DFILE, "#0x%04lx", dec_insn.cexp[i]);
#endif
	      } else {
		      DPRINT (DFILE, "$0x%04lx (unknown SFR)", dec_insn.cexp[i]);
	      }
	  } else {
		  DPRINT (DFILE, "%ld", dec_insn.cexp[i]);
	  }
	  break;

	case '&':
	  dec_insn.regs[i] = 10;
	  /* Fall through. */ 
	case '@':
		if (dec_insn.regs[i] == 10) {
			DPRINT (DFILE, "[" REGPREFIX "sp]");
		} else {
			DPRINT (DFILE, "[" REGPREFIX "a%d]", dec_insn.regs[i]);
		}
		if (need_comma) {
			if ((insn->args[i + 1] == 'a') || (insn->args[i + 1] == 'd')) {
				need_comma = 1;
			} else {
				need_comma = 0;
			}
	    }
	  break;

	case '<':
		if (dec_insn.regs[i] == 10) {
			DPRINT (DFILE, "[+" REGPREFIX "sp]");
		} else {
			DPRINT (DFILE, "[+" REGPREFIX "a%d]", dec_insn.regs[i]);
		}
		need_comma = 0;
		break;

	case '>':
		if (dec_insn.regs[i] == 10) {
			DPRINT (DFILE, "[" REGPREFIX "sp+]");
		} else {
			DPRINT (DFILE, "[" REGPREFIX "a%d+]", dec_insn.regs[i]);
		}
		if (need_comma) {
			if ((insn->args[i + 1] == 'a') || (insn->args[i + 1] == 'd')) {
				need_comma = 1;
			} else {
				need_comma = 0;
			}
	    }
	  break;

	case '*':
		if (dec_insn.regs[i] == 10) {
			DPRINT (DFILE, "[" REGPREFIX "sp+c]");
		} else {
			DPRINT (DFILE, "[" REGPREFIX "a%d+c]", dec_insn.regs[i]);
		}
		need_comma = 0;
		break;

	case '#':
		if (dec_insn.regs[i] == 10) {
			DPRINT (DFILE, "[" REGPREFIX "sp+r]");
		} else {
			DPRINT (DFILE, "[" REGPREFIX "a%d+r]", dec_insn.regs[i]);
		}
		break;

	case '?':
		if (dec_insn.regs[i] == 10) {
			DPRINT (DFILE, "[" REGPREFIX "sp+i]");
		} else {
			DPRINT (DFILE, "[" REGPREFIX "a%d+i]", dec_insn.regs[i]);
		}
		break;

	case 'S':
	  DPRINT (DFILE, "["REGPREFIX"a15]"); 
	  need_comma = 0;
	  break;
	}

	if (need_comma) {
		DPRINT (DFILE, ", ");
	}
    }

#undef DPRINT
#undef DFILE
}

/* Decode the (LEN32 ? 32 : 16)-bit instruction located at MEMADDR.
   INSN already contains its bytes in the correct order, and INFO
   contains (among others) pointers to functions for printing the
   decoded insn.  Return the number of actually decoded bytes.  */

static int
decode_tricore_insn (memaddr, insn, len32, info)
     bfd_vma memaddr;
     unsigned long insn;
     int len32;
     struct disassemble_info *info;
{
  int idx = insn & 0x3f;
  struct insnlist *pinsn;
  unsigned long mask;
  tricore_fmt fmt;

  /* Try to find the instruction matching the given opcode.  */
  for (pinsn = insns[idx]; pinsn != NULL; pinsn = pinsn->next)
    {
	  if ((pinsn->code->len32 != len32) || (insn & pinsn->code->lose)) {
		  continue;
	  }

	  fmt = pinsn->code->format;
	  mask = tricore_opmask[fmt];
	  if ((insn & mask) != pinsn->code->opcode) {
		  continue;
	  }

	  /* A valid instruction was found.  Go print it. */
	  dec_insn.code = pinsn->code;
	  dec_insn.opcode = insn;
	  decode[fmt]();
	  print_decoded_insn (memaddr, info);
	  return len32 ? 4 : 2;
    }

  /* Oops -- this isn't a valid TriCore insn!  Since we know that
     MEMADDR is an even address (otherwise it already would have 
     been handled by print_insn_tricore below) and that TriCore
     insns can only start at even addresses, we just print the
     lower 16 bits of INSN as a .hword pseudo-opcode and return 2,
     no matter what LEN32 says.  */
  (*info->fprintf_func) (info->stream, ".hword 0x%04lx", (insn & 0xffff));

  return 2;
}

/* Decode the PCP instruction located at MEMADDR.  Its first two bytes
   are already stored in BUFFER.  INFO contains (among others) pointers
   to functions for printing the decoded insn.  Return the number of
   actually decoded bytes (2 or 4).  */

static int
decode_pcp_insn (memaddr, buffer, info)
     bfd_vma memaddr;
     bfd_byte buffer[4];
     struct disassemble_info *info;
{
  unsigned long insn = 0, insn2 = 0, val;
  int idx, fail, rb, ra;
  struct pcplist *pinsn;
  pcp_opcode_t *pop = (pcp_opcode_t *) NULL;
  static const char *pcp_ccodes[] =
  {
    "uc", "z", "nz", "v", "c/ult", "ugt", "slt", "sgt",    /* CONDCA  */
    "n", "nn", "nv", "nc/uge", "sge", "sle", "cnz", "cnn"  /* CONDCB  */
  };
#define DPRINT (*info->fprintf_func)
#define DFILE info->stream

  /* Try to find the PCP instruction matching the given opcode.  */
  insn = bfd_getl16 (buffer);
  idx = (insn >> 11) & 0x1f;
  for (pinsn = pcpinsns[idx]; pinsn != NULL; pinsn = pinsn->next)
    {
	  if (((insn & pinsn->code->opcode) != pinsn->code->opcode) || (insn & pinsn->code->lose)) {
		  continue;
	  }

	  /* A valid instruction was found.  */
	  pop = pinsn->code;
	  if (pop->len32) {
		  /* This is a 32-bit insn; try to read 2 more bytes.  */
		  fail = (*info->read_memory_func) (memaddr + 2, &buffer[2], 2, info);
		  if (fail) {
			  DPRINT (DFILE, ".hword 0x%04lx", insn);
			  return 2;
		  }
		  insn2 = bfd_getl16 (buffer + 2);
	}

      break;
    }

  if (!pop)
    {
      /* No valid instruction was found; print it as a 16-bit word.  */
      DPRINT (DFILE, ".hword 0x%04lx", (insn & 0xffff));

      return 2;
    }

  /* Print the instruction.  */
  DPRINT (DFILE, "%s  ", pop->name);
  switch (pop->fmt_group)
    {
    case 0:
      for (idx = 0; idx < pop->nr_operands; ++idx)
        {
	  switch (pop->args[idx])
	    {
	    case 'd':
	      val = (insn >> 9) & 0x3;
	      if (val == 0) {
		      DPRINT (DFILE, "dst");
	      } else if (val == 1) {
		      DPRINT (DFILE, "dst+");
	      } else if (val == 2) {
		      DPRINT (DFILE, "dst-");
	      } else {
		      DPRINT (DFILE, "dst *ILLEGAL*");
	      }
	      break;

	    case 's':
	      val = (insn >> 7) & 0x3;
	      if (val == 0) {
		      DPRINT (DFILE, "src");
	      } else if (val == 1) {
		      DPRINT (DFILE, "src+");
	      } else if (val == 2) {
		      DPRINT (DFILE, "src-");
	      } else {
		      DPRINT (DFILE, "src *ILLEGAL*");
	      }
	      break;

	    case 'c':
	      val = (insn >> 5) & 0x3;
	      DPRINT (DFILE, "cnc=%lu", val);
	      break;

	    case 'n':
		    if (!strcmp (pop->name, "copy")) {
			    val = ((insn >> 2) & 0x7) + 1;
		    } else {
			    val = (insn >> 2) & 0x3;
			    if (val == 0) {
				    val = 8;
			    } else if (val == 3) {
				    val = 4;
			    }
		}
	      DPRINT (DFILE, "cnt0=%lu", val);
	      break;

	    case 'f':
	      val = 8 << (insn & 0x3);
	      DPRINT (DFILE, "size=%lu", val);
	      break;

	    case 'a':
	    case 'b':
	      val = insn & 0xf;
	      DPRINT (DFILE, "cc_%s", pcp_ccodes[val]);
	      break;

	    case 'g':
	      val = (insn >> 10) & 0x1;
	      DPRINT (DFILE, "st=%lu", val);
	      break;

	    case 'i':
	      val = (insn >> 9) & 0x1;
	      DPRINT (DFILE, "int=%lu", val);
	      break;

	    case 'j':
	      val = (insn >> 8) & 0x1;
	      DPRINT (DFILE, "ep=%lu", val);
	      break;

	    case 'h':
	      val = (insn >> 7) & 0x1;
	      DPRINT (DFILE, "ec=%lu", val);
	      break;

	    default:
	      DPRINT (DFILE, "***UNKNOWN OPERAND `%c'***", pop->args[idx]);
	      break;
	    }
	    if (idx < (pop->nr_operands - 1)) {
		    DPRINT (DFILE, ", ");
	    }
	}
      break;

    case 1:
      rb = (insn >> 6) & 0x7;
      ra = (insn >> 3) & 0x7;
      val = 8 << (insn & 0x3);
      DPRINT (DFILE, "r%d, [r%d], size=%lu", rb, ra, val);
      break;

    case 2:
      ra = (insn >> 6) & 0x7;
      val = insn & 0x3f;
      DPRINT (DFILE, "r%d, [%lu]", ra, val);
      break;

    case 3:
      rb = (insn >> 6) & 0x7;
      ra = (insn >> 3) & 0x7;
      val = insn & 0x7;
      if (!strcmp (pop->name, "ld.p") || !strcmp (pop->name, "st.p")) {
	      DPRINT (DFILE, "cc_%s, r%d, [r%d]", pcp_ccodes[val], rb, ra);
      } else {
	      DPRINT (DFILE, "cc_%s, r%d, r%d", pcp_ccodes[val], rb, ra);
      }
      break;

    case 4:
      ra = (insn >> 6) & 0x7;
      val = insn & 0x3f;
      if (!strcmp (pop->name, "chkb")) {
	      DPRINT (DFILE, "r%d, %lu, %s", ra, val & 0x1f,
		      (val & 0x20) ? "set" : "clr");
      } else if (!strcmp (pop->name, "ldl.il")) {
	      DPRINT (DFILE, "r%d, 0x....%04lx", ra, insn2);
      } else if (!strcmp (pop->name, "ldl.iu")) {
	      DPRINT (DFILE, "r%d, 0x%04lx....", ra, insn2);
      } else {
	      DPRINT (DFILE, "r%d, %lu", ra, val);
      }
      break;

    case 5:
      ra = (insn >> 6) & 0x7;
      val = 8 << (((insn >> 5) & 0x1) | ((insn >> 8) & 0x2));
      if ((!strcmp (pop->name, "set.f") || !strcmp (pop->name, "clr.f")) && ((insn & 0x1f) >= val)) {
	      DPRINT (DFILE, "[r%d], %lu ***ILLEGAL VALUE***, size=%lu", ra,
		      insn & 0x1f, val);
      } else {
	      DPRINT (DFILE, "[r%d], %lu, size=%lu", ra, insn & 0x1f, val);
      }
      break;

    case 6:
      rb = (insn >> 6) & 0x7;
      ra = (insn >> 3) & 0x7;
      if ((rb == 0) || (ra == 0) || (rb == 7) || (ra == 7) || (rb == ra)) {
	      DPRINT (DFILE, "r%d, r%d ***ILLEGAL REGISTER USE***", rb, ra);
      } else {
	      DPRINT (DFILE, "r%d, r%d", rb, ra);
      }
      break;

    case 7:
      for (idx = 0; idx < pop->nr_operands; ++idx)
        {
	  switch (pop->args[idx])
	    {
	    case 'r':
	    case 'R':
	      DPRINT (DFILE, "[r%lu]", (insn >> 3) & 0x7);
	      break;

	    case 'm':
	      DPRINT (DFILE, "dac=%lu", (insn >> 3) & 0x1);
	      break;

	    case 'a':
	    case 'b':
	      DPRINT (DFILE, "cc_%s", pcp_ccodes[(insn >> 6) & 0xf]);
	      break;

	    case 'o':
	      DPRINT (DFILE, "rta=%lu", (insn >> 2) & 0x1);
	      break;

	    case 'p':
	      DPRINT (DFILE, "eda=%lu", (insn >> 1) & 0x1);
	      break;

	    case 'q':
	      DPRINT (DFILE, "sdb=%lu", insn & 1);
	      break;

	    case 'e':
	      if (!strcmp (pop->name, "jl"))
	        {
		  val = insn & 0x3ff;
		  if (val & 0x200) {
			  val |= ~0x3ff;
		  }
		  (*info->print_address_func) (memaddr + 2 + (val << 1), info);
		}
	      else if (!strcmp (pop->name, "jc"))
	        {
		  val = insn & 0x3f;
		  if (val & 0x20) {
			  val |= ~0x3f;
		  }
		  (*info->print_address_func) (memaddr + 2 + (val << 1), info);
		} else if (!strcmp (pop->name, "jc.a")) {
			/* FIXME: address should be PCODE_BASE + (insn2 << 1).  */
			(*info->print_address_func) ((memaddr & 0xffff0000) + (insn2 << 1), info);
		} else {
			DPRINT (DFILE, "***ILLEGAL expr FOR %s***", pop->name);
		}
		break;

	    default:
	      DPRINT (DFILE, "***UNKNOWN OPERAND `%c'***", pop->args[idx]);
	      break;
	    }
	    if (idx < (pop->nr_operands - 1)) {
		    DPRINT (DFILE, ", ");
	    }
	}
      break;

    default:
      DPRINT (DFILE, "***ILLEGAL FORMAT GROUP %d***", pop->fmt_group);
      break;
    }

  return pop->len32 ? 4 : 2;
#undef DPRINT
#undef DFILE
}

/* Read, decode and print the byte(s) starting at MEMADDR.  Return -1
   if a read error occurs, or else the number of decoded bytes.  We
   do expect to find a valid TriCore instruction at MEMADDR, but we'll
   happily just print the byte(s) as ".byte"/".hword" pseudo-ops if
   this is not the case.  We only read as many bytes as necessary
   (or possible) to decode a single instruction or a pseudo-op, i.e.
   1, 2 or 4 bytes.  */

int 
print_insn_tricore (memaddr, info)
     bfd_vma memaddr;
     struct disassemble_info *info;
{
  bfd_byte buffer[4];
  int len32 = 0, failure;
  unsigned long insn = 0;

  if (!initialized)
    {
      /* Set the current instruction set architecture.  */
      switch (info->mach & bfd_mach_rider_mask)
        {
	case bfd_mach_rider_a:
	  current_isa = TRICORE_RIDER_A;
	  break;

	case bfd_mach_rider_b: /* Matches also rider_d!  */
	  current_isa = TRICORE_RIDER_B;
	  break;

	case bfd_mach_rider_2:
	  current_isa = TRICORE_V2;
	  break;
	}

      /* Initialize architecture-dependent variables.  */
      tricore_init_arch_vars (info->mach);

      /* Initialize the hash tables.  */
      init_hash_tables ();
      initialized = 1;
    }

  memset ((char *) buffer, 0, sizeof (buffer));
  failure = (*info->read_memory_func) (memaddr, buffer, 1, info);
  if (failure)
    {
      (*info->memory_error_func) (failure, memaddr, info);
      return -1;
    }

  /* Try to read the 2nd byte.  */
  failure = (*info->read_memory_func) (memaddr + 1, &buffer[1], 1, info);
  if (failure)
    {
      /* Maybe MEMADDR isn't even and we reached the end of a section.  */
      (*info->fprintf_func) (info->stream, ".byte 0x%02x", buffer[0]);
      return 1;
    }

  /* Check if we're disassembling .pcp{text,data} sections.  */
    if (info->section && (info->section->flags & SEC_ARCH_BIT_0)) {
	    return decode_pcp_insn (memaddr, buffer, info);
    }

    /* Handle TriCore sections.  */
    if (buffer[0] & 1) {
	    /* Looks like this is a 32-bit insn; try to read 2 more bytes.  */
	    failure = (*info->read_memory_func) (memaddr + 2, &buffer[2], 2, info);
	    if (failure) {
		    insn = bfd_getl16 (buffer);
		    (*info->fprintf_func) (info->stream, ".hword 0x%04lx", insn);
		    return 2;
	    } else {
		    len32 = 1;
	    }
    }

    if (len32) {
	    insn = bfd_getl32 (buffer);
    } else {
	    insn = bfd_getl16 (buffer);
    }

    return decode_tricore_insn (memaddr, insn, len32, info);
}

/* End of tricore-dis.c.  */
