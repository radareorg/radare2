/* Instruction opcode table for arc.

THIS FILE IS MACHINE GENERATED WITH CGEN.

Copyright 1996-2005 Free Software Foundation, Inc.

Copyright 2008-2012 Synopsys Inc.

This file is part of the GNU Binutils and/or GDB, the GNU debugger.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.

*/

#include "sysdep.h"
#include "ansidecl.h"
#include "bfd.h"
#include "symcat.h"
#include "arc-desc.h"
#include "arc-opc-cgen.h"
#include "libiberty.h"

/* -- opc.c */
unsigned int
arc_cgen_dis_hash (const char * buf, int big_p)
{
  const unsigned char *ubuf = (unsigned char*) buf;
  int b0 = ubuf[0], b1 = ubuf[1], w;

  if (big_p)
    w = (b0 << 8) + b1;
  else
    w = (b1 << 8) + b0;

  switch (w >> 11)
    {
    case 0x01: /* branches */
      return ((w >> 6) | w);
    case 0x04: /* general operations */
    case 0x05: case 0x06: case 0x07: /* 32 bit extension instructions */
      return ((w >> 3) & 768) | (w & 255);
    case 0x0c: /* .s load/add register-register */
    case 0x0d: /* .s add/sub/shift register-immediate */
    case 0x0e: /* .s mov/cmp/add with high register */
      return ((w >> 6) & 992) | (w & 24);
    case 0x0f: /* 16 bit general operations */
      return ((w >> 6) & 992) | (w & 31);
    case 0x17: /* .s shift/subtract/bit immediate */
    case 0x18: /* .s stack-pointer based */
      return ((w >> 6) & 992) | ((w >> 5) & 7);
    case 0x19: /* load/add GP-relative */
    case 0x1e: /* branch conditionally */
      return ((w >> 6) & (992 | 24));
    case 0x1c: /* add/cmp immediate */
    case 0x1d: /* branch on compare register with zero */
      return ((w >> 6) & (992 | 2));
    default:
      return ((w >> 6) & 992);
    }
}

/* -- */
/* The hash functions are recorded here to help keep assembler code out of
   the disassembler and vice versa.  */

static int asm_hash_insn_p        (const CGEN_INSN *);
static unsigned int asm_hash_insn (const char *);
static int dis_hash_insn_p        (const CGEN_INSN *);
static unsigned int dis_hash_insn (const char *, CGEN_INSN_INT, int);

/* Instruction formats.  */

#if defined (__STDC__) || defined (ALMOST_STDC) || defined (HAVE_STRINGIZE)
#define F(f) & arc_cgen_ifld_table[ARC_##f]
#else
#define F(f) & arc_cgen_ifld_table[ARC_/**/f]
#endif
static const CGEN_IFMT ifmt_empty ATTRIBUTE_UNUSED = {
  0, 0, 0x0, { { 0 } }
};

static const CGEN_IFMT ifmt_b_s ATTRIBUTE_UNUSED = {
  32, 32, 0xf8000000, { { F (F_OPM) }, { F (F_COND_I2) }, { F (F_REL10) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_bcc_s ATTRIBUTE_UNUSED = {
  32, 32, 0xfe000000, { { F (F_OPM) }, { F (F_COND_I2) }, { F (F_COND_I3) }, { F (F_REL7) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_brcc_s ATTRIBUTE_UNUSED = {
  32, 32, 0xf8000000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_BRSCOND) }, { F (F_REL8) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_bcc_l ATTRIBUTE_UNUSED = {
  32, 32, 0xf8010020, { { F (F_OPM) }, { F (F_REL21) }, { F (F_BUF) }, { F (F_DELAY_N) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_b_l ATTRIBUTE_UNUSED = {
  32, 32, 0xf8010030, { { F (F_OPM) }, { F (F_REL25) }, { F (F_BUF) }, { F (F_DELAY_N) }, { F (F_RES27) }, { 0 } }
};

static const CGEN_IFMT ifmt_brcc_RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8010030, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_REL9) }, { F (F_BUF) }, { F (F_OP_C) }, { F (F_DELAY_N) }, { F (F_BR) }, { F (F_BRCOND) }, { 0 } }
};

static const CGEN_IFMT ifmt_brcc_U6 ATTRIBUTE_UNUSED = {
  32, 32, 0xf8010030, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_REL9) }, { F (F_BUF) }, { F (F_U6) }, { F (F_DELAY_N) }, { F (F_BR) }, { F (F_BRCOND) }, { 0 } }
};

static const CGEN_IFMT ifmt_bl_s ATTRIBUTE_UNUSED = {
  32, 32, 0xf8000000, { { F (F_OPM) }, { F (F_REL13BL) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_blcc ATTRIBUTE_UNUSED = {
  32, 32, 0xf8030020, { { F (F_OPM) }, { F (F_REL21BL) }, { F (F_BLUF) }, { F (F_BUF) }, { F (F_DELAY_N) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_bl ATTRIBUTE_UNUSED = {
  32, 32, 0xf8030030, { { F (F_OPM) }, { F (F_REL25BL) }, { F (F_BLUF) }, { F (F_BUF) }, { F (F_DELAY_N) }, { F (F_RES27) }, { 0 } }
};

static const CGEN_IFMT ifmt_ld_abs ATTRIBUTE_UNUSED = {
  32, 32, 0xf80007c0, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_S9) }, { F (F_LDODI) }, { F (F_LDOAA) }, { F (F_LDOZZX) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_ld_abc ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_LDRAA) }, { F (F_LDR6ZZX) }, { F (F_LDRDI) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_ld_s_abc ATTRIBUTE_UNUSED = {
  32, 32, 0xf8180000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_I16_43) }, { F (F_OP__A) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_ld_s_abu ATTRIBUTE_UNUSED = {
  32, 32, 0xf8000000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_U5X4) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_ld_s_absp ATTRIBUTE_UNUSED = {
  32, 32, 0xf8e00000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_U5X4) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_ld_s_gprel ATTRIBUTE_UNUSED = {
  32, 32, 0xfe000000, { { F (F_OPM) }, { F (F_I16_GP_TYPE) }, { F (F_S9X4) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_ld_s_pcrel ATTRIBUTE_UNUSED = {
  32, 32, 0xf8000000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_U8X4) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldb_s_abu ATTRIBUTE_UNUSED = {
  32, 32, 0xf8000000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_U5) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldb_s_gprel ATTRIBUTE_UNUSED = {
  32, 32, 0xfe000000, { { F (F_OPM) }, { F (F_I16_GP_TYPE) }, { F (F_S9X1) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldw_s_abu ATTRIBUTE_UNUSED = {
  32, 32, 0xf8000000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_U5X2) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_ldw_s_gprel ATTRIBUTE_UNUSED = {
  32, 32, 0xfe000000, { { F (F_OPM) }, { F (F_I16_GP_TYPE) }, { F (F_S9X2) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_st_abs ATTRIBUTE_UNUSED = {
  32, 32, 0xf800001f, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_S9) }, { F (F_LDODI) }, { F (F_OP_C) }, { F (F_STOAA) }, { F (F_STOZZR) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_L_s12__RA_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_S12) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_ccu6__RA_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_L_u6__RA_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_L_r_r__RA__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_cc__RA__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_s_cbu3 ATTRIBUTE_UNUSED = {
  32, 32, 0xf8180000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_I16_43) }, { F (F_U3) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_s_mcah ATTRIBUTE_UNUSED = {
  32, 32, 0xf8180000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP_H) }, { F (F_I16_43) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_s_asspsp ATTRIBUTE_UNUSED = {
  32, 32, 0xffe00000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_U5X4) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_s_gp ATTRIBUTE_UNUSED = {
  32, 32, 0xfe000000, { { F (F_OPM) }, { F (F_I16_GP_TYPE) }, { F (F_S9X4) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_add_s_r_u7 ATTRIBUTE_UNUSED = {
  32, 32, 0xf8800000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_I16ADDCMPU7_TYPE) }, { F (F_U7) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_I16_GO_SUB_s_go ATTRIBUTE_UNUSED = {
  32, 32, 0xf81f0000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_I16_GO) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_sub_s_go_sub_ne ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_I16_GO) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_sub_s_ssb ATTRIBUTE_UNUSED = {
  32, 32, 0xf8e00000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_U5) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_mov_L_u6_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_mov_L_r_r__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_mov_s_r_u7 ATTRIBUTE_UNUSED = {
  32, 32, 0xf8000000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_U8) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_tst_L_s12_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_S12) }, { 0 } }
};

static const CGEN_IFMT ifmt_tst_ccu6_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_tst_L_u6_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_tst_L_r_r__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_tst_cc__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_L_r_r___RC_noilink_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_CJ) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_cc___RC_noilink_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_CJ) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_L_r_r___RC_ilink_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_CJ) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_cc___RC_ilink_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_CJ) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_L_s12_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_S12) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_ccu6_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_L_u6_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_s__S ATTRIBUTE_UNUSED = {
  32, 32, 0xffff0000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_I16_GO) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_L_r_r_d___RC_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_j_cc_d___RC_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_lp_L_s12_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_S12X2) }, { 0 } }
};

static const CGEN_IFMT ifmt_lpcc_ccu6 ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6X2) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_lr_L_r_r___RC_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_lr_L_s12_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_S12) }, { 0 } }
};

static const CGEN_IFMT ifmt_asl_L_r_r__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff003f, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_asl_L_u6_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff003f, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_ex_L_r_r__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff003f, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_ex_L_u6_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff003f, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_swi ATTRIBUTE_UNUSED = {
  32, 32, 0xffff7fff, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_B_5_3) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_trap_s ATTRIBUTE_UNUSED = {
  32, 32, 0xf81f0000, { { F (F_OPM) }, { F (F_TRAPNUM) }, { F (F_I16_GO) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_brk_s ATTRIBUTE_UNUSED = {
  32, 32, 0xffff0000, { { F (F_OPM) }, { F (F_TRAPNUM) }, { F (F_I16_GO) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_divaw_ccu6__RA_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_divaw_L_u6__RA_ ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_U6) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_divaw_L_r_r__RA__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

static const CGEN_IFMT ifmt_divaw_cc__RA__RC ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0020, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_GO_CC_TYPE) }, { F (F_COND_Q) }, { 0 } }
};

static const CGEN_IFMT ifmt_pop_s_b ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff0000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_U5) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_pop_s_blink ATTRIBUTE_UNUSED = {
  32, 32, 0xffff0000, { { F (F_OPM) }, { F (F_OP__B) }, { F (F_OP__C) }, { F (F_U5) }, { F (F_DUMMY) }, { 0 } }
};

static const CGEN_IFMT ifmt_current_loop_end ATTRIBUTE_UNUSED = {
  32, 32, 0xf8ff003f, { { F (F_OPM) }, { F (F_OP_B) }, { F (F_GO_TYPE) }, { F (F_GO_OP) }, { F (F_F) }, { F (F_OP_C) }, { F (F_OP_A) }, { 0 } }
};

#undef F

#if defined (__STDC__) || defined (ALMOST_STDC) || defined (HAVE_STRINGIZE)
#define A(a) (1 << CGEN_INSN_##a)
#else
#define A(a) (1 << CGEN_INSN_/**/a)
#endif
#if defined (__STDC__) || defined (ALMOST_STDC) || defined (HAVE_STRINGIZE)
#define OPERAND(op) ARC_OPERAND_##op
#else
#define OPERAND(op) ARC_OPERAND_/**/op
#endif
#define MNEM CGEN_SYNTAX_MNEMONIC /* syntax value for mnemonic */
#define OP(field) CGEN_SYNTAX_MAKE_FIELD (OPERAND (field))

/* The instruction table.  */

static const CGEN_OPCODE arc_cgen_insn_opcode_table[MAX_INSNS] =
{
  /* Special null first entry.
     A `num' value of zero is thus invalid.
     Also, the special `invalid' insn resides here.  */
  { { 0, 0, 0, 0 }, {{0}}, 0, {0}},
/* b$i2cond $label10 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (I2COND), ' ', OP (LABEL10), 0 } },
    & ifmt_b_s, { 0xf0000000 }
  },
/* b$i3cond$_S $label7 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (I3COND), OP (_S), ' ', OP (LABEL7), 0 } },
    & ifmt_bcc_s, { 0xf6000000 }
  },
/* br$RccS$_S $R_b,0,$label8 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (RCCS), OP (_S), ' ', OP (R_B), ',', '0', ',', OP (LABEL8), 0 } },
    & ifmt_brcc_s, { 0xe8000000 }
  },
/* b$Qcondb$_L $label21 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDB), OP (_L), ' ', OP (LABEL21), 0 } },
    & ifmt_bcc_l, { 0x0 }
  },
/* b$Qcondb$_L.d $label21 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDB), OP (_L), '.', 'd', ' ', OP (LABEL21), 0 } },
    & ifmt_bcc_l, { 0x20 }
  },
/* b$uncondb$_L $label25 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (UNCONDB), OP (_L), ' ', OP (LABEL25), 0 } },
    & ifmt_b_l, { 0x10000 }
  },
/* b$uncondb$_L.d $label25 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (UNCONDB), OP (_L), '.', 'd', ' ', OP (LABEL25), 0 } },
    & ifmt_b_l, { 0x10020 }
  },
/* b$Rcc $RB,$RC,$label9 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (RCC), ' ', OP (RB), ',', OP (RC), ',', OP (LABEL9), 0 } },
    & ifmt_brcc_RC, { 0x8010000 }
  },
/* b$Rcc.d $RB,$RC,$label9 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (RCC), '.', 'd', ' ', OP (RB), ',', OP (RC), ',', OP (LABEL9), 0 } },
    & ifmt_brcc_RC, { 0x8010020 }
  },
/* b$Rcc $RB,$U6,$label9 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (RCC), ' ', OP (RB), ',', OP (U6), ',', OP (LABEL9), 0 } },
    & ifmt_brcc_U6, { 0x8010010 }
  },
/* b$Rcc.d $RB,$U6,$label9 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (RCC), '.', 'd', ' ', OP (RB), ',', OP (U6), ',', OP (LABEL9), 0 } },
    & ifmt_brcc_U6, { 0x8010030 }
  },
/* bl$uncondj$_S $label13a */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (UNCONDJ), OP (_S), ' ', OP (LABEL13A), 0 } },
    & ifmt_bl_s, { 0xf8000000 }
  },
/* bl$Qcondj$_L $label21 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDJ), OP (_L), ' ', OP (LABEL21), 0 } },
    & ifmt_blcc, { 0x8000000 }
  },
/* bl$Qcondj$_L.d $label21 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDJ), OP (_L), '.', 'd', ' ', OP (LABEL21), 0 } },
    & ifmt_blcc, { 0x8000020 }
  },
/* bl$uncondj$_L $label25a */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (UNCONDJ), OP (_L), ' ', OP (LABEL25A), 0 } },
    & ifmt_bl, { 0x8020000 }
  },
/* bl$uncondj$_L.d $label25a */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (UNCONDJ), OP (_L), '.', 'd', ' ', OP (LABEL25A), 0 } },
    & ifmt_bl, { 0x8020020 }
  },
/* ld$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000000 }
  },
/* ld$_AW$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000200 }
  },
/* ld.ab$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000400 }
  },
/* ld.as$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000600 }
  },
/* ld$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20300000 }
  },
/* ld$_AW$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20700000 }
  },
/* ld.ab$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20b00000 }
  },
/* ld.as$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20f00000 }
  },
/* ld$_S $R_a,[$R_b,$R_c] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_A), ',', '[', OP (R_B), ',', OP (R_C), ']', 0 } },
    & ifmt_ld_s_abc, { 0x60000000 }
  },
/* ld$_S $R_c,[$R_b,$sc_u5_] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', '[', OP (R_B), ',', OP (SC_U5_), ']', 0 } },
    & ifmt_ld_s_abu, { 0x80000000 }
  },
/* ld$_S $R_b,[$SP,$u5x4] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', '[', OP (SP), ',', OP (U5X4), ']', 0 } },
    & ifmt_ld_s_absp, { 0xc0000000 }
  },
/* ld$_S $R_b,[$GP,$sc_s9_] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', '[', OP (GP), ',', OP (SC_S9_), ']', 0 } },
    & ifmt_ld_s_gprel, { 0xc8000000 }
  },
/* ld$_S $R_b,[$PCL,$u8x4] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', '[', OP (PCL), ',', OP (U8X4), ']', 0 } },
    & ifmt_ld_s_pcrel, { 0xd0000000 }
  },
/* ldb$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000080 }
  },
/* ldb$_AW$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000280 }
  },
/* ldb.ab$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000480 }
  },
/* ldb.as$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000680 }
  },
/* ldb$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20320000 }
  },
/* ldb$_AW$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20720000 }
  },
/* ldb.ab$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20b20000 }
  },
/* ldb.as$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20f20000 }
  },
/* ldb$_S $R_a,[$R_b,$R_c] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_A), ',', '[', OP (R_B), ',', OP (R_C), ']', 0 } },
    & ifmt_ld_s_abc, { 0x60080000 }
  },
/* ldb$_S $R_c,[$R_b,$sc_u5b] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', '[', OP (R_B), ',', OP (SC_U5B), ']', 0 } },
    & ifmt_ldb_s_abu, { 0x88000000 }
  },
/* ldb$_S $R_b,[$SP,$u5x4] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', '[', OP (SP), ',', OP (U5X4), ']', 0 } },
    & ifmt_ld_s_absp, { 0xc0200000 }
  },
/* ldb$_S $R_b,[$GP,$sc_s9b] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', '[', OP (GP), ',', OP (SC_S9B), ']', 0 } },
    & ifmt_ldb_s_gprel, { 0xca000000 }
  },
/* ldb.x$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x100000c0 }
  },
/* ldb$_AW.x$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), '.', 'x', OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x100002c0 }
  },
/* ldb.ab.x$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x100004c0 }
  },
/* ldb.as.x$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x100006c0 }
  },
/* ldb.x$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20330000 }
  },
/* ldb$_AW.x$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), '.', 'x', OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20730000 }
  },
/* ldb.ab.x$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20b30000 }
  },
/* ldb.as.x$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20f30000 }
  },
/* ldw$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000100 }
  },
/* ldw$_AW$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000300 }
  },
/* ldw.ab$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000500 }
  },
/* ldw.as$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000700 }
  },
/* ldw$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20340000 }
  },
/* ldw$_AW$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20740000 }
  },
/* ldw.ab$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20b40000 }
  },
/* ldw.as$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20f40000 }
  },
/* ldw$_S $R_a,[$R_b,$R_c] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_A), ',', '[', OP (R_B), ',', OP (R_C), ']', 0 } },
    & ifmt_ld_s_abc, { 0x60100000 }
  },
/* ldw$_S $R_c,[$R_b,$sc_u5w] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', '[', OP (R_B), ',', OP (SC_U5W), ']', 0 } },
    & ifmt_ldw_s_abu, { 0x90000000 }
  },
/* ldw$_S $R_b,[$GP,$sc_s9w] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', '[', OP (GP), ',', OP (SC_S9W), ']', 0 } },
    & ifmt_ldw_s_gprel, { 0xcc000000 }
  },
/* ldw.x$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000140 }
  },
/* ldw$_AW.x$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), '.', 'x', OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000340 }
  },
/* ldw.ab.x$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000540 }
  },
/* ldw.as.x$LDODi $RA,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDODI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_ld_abs, { 0x10000740 }
  },
/* ldw.x$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20350000 }
  },
/* ldw$_AW.x$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), '.', 'x', OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20750000 }
  },
/* ldw.ab.x$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20b50000 }
  },
/* ldw.as.x$LDRDi $RA,[$RB,$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (LDRDI), ' ', OP (RA), ',', '[', OP (RB), ',', OP (RC), ']', 0 } },
    & ifmt_ld_abc, { 0x20f50000 }
  },
/* ldw$_S.x $R_c,[$R_b,$sc_u5w] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), '.', 'x', ' ', OP (R_C), ',', '[', OP (R_B), ',', OP (SC_U5W), ']', 0 } },
    & ifmt_ldw_s_abu, { 0x98000000 }
  },
/* st$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x18000000 }
  },
/* st$_AW$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x18000008 }
  },
/* st.ab$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x18000010 }
  },
/* st.as$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x18000018 }
  },
/* st$_S $R_c,[$R_b,$sc_u5_] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', '[', OP (R_B), ',', OP (SC_U5_), ']', 0 } },
    & ifmt_ld_s_abu, { 0xa0000000 }
  },
/* st$_S $R_b,[$SP,$u5x4] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', '[', OP (SP), ',', OP (U5X4), ']', 0 } },
    & ifmt_ld_s_absp, { 0xc0400000 }
  },
/* stb$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x18000002 }
  },
/* stb$_AW$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x1800000a }
  },
/* stb.ab$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x18000012 }
  },
/* stb.as$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x1800001a }
  },
/* stb$_S $R_c,[$R_b,$sc_u5b] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', '[', OP (R_B), ',', OP (SC_U5B), ']', 0 } },
    & ifmt_ldb_s_abu, { 0xa8000000 }
  },
/* stb$_S $R_b,[$SP,$u5x4] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', '[', OP (SP), ',', OP (U5X4), ']', 0 } },
    & ifmt_ld_s_absp, { 0xc0600000 }
  },
/* stw$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x18000004 }
  },
/* stw$_AW$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_AW), OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x1800000c }
  },
/* stw.ab$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x18000014 }
  },
/* stw.as$STODi $RC,[$RB,$s9] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (STODI), ' ', OP (RC), ',', '[', OP (RB), ',', OP (S9), ']', 0 } },
    & ifmt_st_abs, { 0x1800001c }
  },
/* stw$_S $R_c,[$R_b,$sc_u5w] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', '[', OP (R_B), ',', OP (SC_U5W), ']', 0 } },
    & ifmt_ldw_s_abu, { 0xb0000000 }
  },
/* add$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20800000 }
  },
/* add$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c00020 }
  },
/* add$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20400000 }
  },
/* add$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20000000 }
  },
/* add$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c00000 }
  },
/* add$_S $R_a,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_A), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_ld_s_abc, { 0x60180000 }
  },
/* add$_S $R_c,$R_b,$u3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', OP (R_B), ',', OP (U3), 0 } },
    & ifmt_add_s_cbu3, { 0x68000000 }
  },
/* add$_S $R_b,$R_b,$Rh */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (RH), 0 } },
    & ifmt_add_s_mcah, { 0x70000000 }
  },
/* add$_S $R_b,$SP,$u5x4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (SP), ',', OP (U5X4), 0 } },
    & ifmt_ld_s_absp, { 0xc0800000 }
  },
/* add$_S $SP,$SP,$u5x4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (SP), ',', OP (SP), ',', OP (U5X4), 0 } },
    & ifmt_add_s_asspsp, { 0xc0a00000 }
  },
/* add$_S $R0,$GP,$s9x4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R0), ',', OP (GP), ',', OP (S9X4), 0 } },
    & ifmt_add_s_gp, { 0xce000000 }
  },
/* add$_S $R_b,$R_b,$u7 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (U7), 0 } },
    & ifmt_add_s_r_u7, { 0xe0000000 }
  },
/* adc$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20810000 }
  },
/* adc$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c10020 }
  },
/* adc$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20410000 }
  },
/* adc$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20010000 }
  },
/* adc$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c10000 }
  },
/* sub$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20820000 }
  },
/* sub$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c20020 }
  },
/* sub$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20420000 }
  },
/* sub$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20020000 }
  },
/* sub$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c20000 }
  },
/* sub$_S $R_c,$R_b,$u3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', OP (R_B), ',', OP (U3), 0 } },
    & ifmt_add_s_cbu3, { 0x68080000 }
  },
/* sub$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78020000 }
  },
/* sub$_S $NE$R_b,$R_b,$R_b */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (NE), OP (R_B), ',', OP (R_B), ',', OP (R_B), 0 } },
    & ifmt_sub_s_go_sub_ne, { 0x78c00000 }
  },
/* sub$_S $R_b,$R_b,$u5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (U5), 0 } },
    & ifmt_sub_s_ssb, { 0xb8600000 }
  },
/* sub$_S $SP,$SP,$u5x4 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (SP), ',', OP (SP), ',', OP (U5X4), 0 } },
    & ifmt_add_s_asspsp, { 0xc1a00000 }
  },
/* sbc$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20830000 }
  },
/* sbc$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c30020 }
  },
/* sbc$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20430000 }
  },
/* sbc$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20030000 }
  },
/* sbc$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c30000 }
  },
/* and$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20840000 }
  },
/* and$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c40020 }
  },
/* and$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20440000 }
  },
/* and$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20040000 }
  },
/* and$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c40000 }
  },
/* and$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78040000 }
  },
/* or$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20850000 }
  },
/* or$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c50020 }
  },
/* or$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20450000 }
  },
/* or$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20050000 }
  },
/* or$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c50000 }
  },
/* or$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78050000 }
  },
/* bic$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20860000 }
  },
/* bic$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c60020 }
  },
/* bic$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20460000 }
  },
/* bic$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20060000 }
  },
/* bic$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c60000 }
  },
/* bic$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78060000 }
  },
/* xor$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20870000 }
  },
/* xor$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c70020 }
  },
/* xor$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20470000 }
  },
/* xor$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20070000 }
  },
/* xor$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c70000 }
  },
/* xor$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78070000 }
  },
/* max$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20880000 }
  },
/* max$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c80020 }
  },
/* max$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20480000 }
  },
/* max$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20080000 }
  },
/* max$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c80000 }
  },
/* min$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20890000 }
  },
/* min$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20c90020 }
  },
/* min$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20490000 }
  },
/* min$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20090000 }
  },
/* min$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20c90000 }
  },
/* mov$_L$F $RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x208a0000 }
  },
/* mov$Qcondi$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20ca0020 }
  },
/* mov$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_mov_L_u6_, { 0x204a0000 }
  },
/* mov$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_mov_L_r_r__RC, { 0x200a0000 }
  },
/* mov$Qcondi$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20ca0000 }
  },
/* mov$_S $R_b,$Rh */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (RH), 0 } },
    & ifmt_add_s_mcah, { 0x70080000 }
  },
/* mov$_S $Rh,$R_b */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (RH), ',', OP (R_B), 0 } },
    & ifmt_add_s_mcah, { 0x70180000 }
  },
/* mov$_S $R_b,$u7 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (U7), 0 } },
    & ifmt_mov_s_r_u7, { 0xd8000000 }
  },
/* tst$_L$F1 $RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (S12), 0 } },
    & ifmt_tst_L_s12_, { 0x208b0000 }
  },
/* tst$Qcondi$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_ccu6_, { 0x20cb0020 }
  },
/* tst$_L$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_L_u6_, { 0x204b0000 }
  },
/* tst$_L$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_L_r_r__RC, { 0x200b0000 }
  },
/* tst$Qcondi$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_cc__RC, { 0x20cb0000 }
  },
/* tst$_S $R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x780b0000 }
  },
/* cmp$_L$F1 $RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (S12), 0 } },
    & ifmt_tst_L_s12_, { 0x208c0000 }
  },
/* cmp$Qcondi$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_ccu6_, { 0x20cc0020 }
  },
/* cmp$_L$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_L_u6_, { 0x204c0000 }
  },
/* cmp$_L$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_L_r_r__RC, { 0x200c0000 }
  },
/* cmp$Qcondi$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_cc__RC, { 0x20cc0000 }
  },
/* cmp$_S $R_b,$Rh */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (RH), 0 } },
    & ifmt_add_s_mcah, { 0x70100000 }
  },
/* cmp$_S $R_b,$u7 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (U7), 0 } },
    & ifmt_add_s_r_u7, { 0xe0800000 }
  },
/* rcmp$_L$F1 $RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (S12), 0 } },
    & ifmt_tst_L_s12_, { 0x208d0000 }
  },
/* rcmp$Qcondi$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_ccu6_, { 0x20cd0020 }
  },
/* rcmp$_L$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_L_u6_, { 0x204d0000 }
  },
/* rcmp$_L$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_L_r_r__RC, { 0x200d0000 }
  },
/* rcmp$Qcondi$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_cc__RC, { 0x20cd0000 }
  },
/* rsub$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x208e0000 }
  },
/* rsub$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20ce0020 }
  },
/* rsub$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x204e0000 }
  },
/* rsub$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x200e0000 }
  },
/* rsub$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20ce0000 }
  },
/* bset$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x208f0000 }
  },
/* bset$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20cf0020 }
  },
/* bset$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x204f0000 }
  },
/* bset$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x200f0000 }
  },
/* bset$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20cf0000 }
  },
/* bset$_S $R_b,$R_b,$u5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (U5), 0 } },
    & ifmt_sub_s_ssb, { 0xb8800000 }
  },
/* bclr$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20900000 }
  },
/* bclr$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d00020 }
  },
/* bclr$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20500000 }
  },
/* bclr$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20100000 }
  },
/* bclr$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d00000 }
  },
/* bclr$_S $R_b,$R_b,$u5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (U5), 0 } },
    & ifmt_sub_s_ssb, { 0xb8a00000 }
  },
/* btst$_L$F1 $RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (S12), 0 } },
    & ifmt_tst_L_s12_, { 0x20910000 }
  },
/* btst$Qcondi$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_ccu6_, { 0x20d10020 }
  },
/* btst$_L$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_L_u6_, { 0x20510000 }
  },
/* btst$_L$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_L_r_r__RC, { 0x20110000 }
  },
/* btst$Qcondi$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_cc__RC, { 0x20d10000 }
  },
/* btst$_S $R_b,$u5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (U5), 0 } },
    & ifmt_sub_s_ssb, { 0xb8e00000 }
  },
/* bxor$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20920000 }
  },
/* bxor$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d20020 }
  },
/* bxor$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20520000 }
  },
/* bxor$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20120000 }
  },
/* bxor$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d20000 }
  },
/* bmsk$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20930000 }
  },
/* bmsk$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d30020 }
  },
/* bmsk$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20530000 }
  },
/* bmsk$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20130000 }
  },
/* bmsk$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d30000 }
  },
/* bmsk$_S $R_b,$R_b,$u5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (U5), 0 } },
    & ifmt_sub_s_ssb, { 0xb8c00000 }
  },
/* add1$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20940000 }
  },
/* add1$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d40020 }
  },
/* add1$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20540000 }
  },
/* add1$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20140000 }
  },
/* add1$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d40000 }
  },
/* add1$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78140000 }
  },
/* add2$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20950000 }
  },
/* add2$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d50020 }
  },
/* add2$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20550000 }
  },
/* add2$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20150000 }
  },
/* add2$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d50000 }
  },
/* add2$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78150000 }
  },
/* add3$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20960000 }
  },
/* add3$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d60020 }
  },
/* add3$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20560000 }
  },
/* add3$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20160000 }
  },
/* add3$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d60000 }
  },
/* add3$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78160000 }
  },
/* sub1$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20970000 }
  },
/* sub1$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d70020 }
  },
/* sub1$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20570000 }
  },
/* sub1$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20170000 }
  },
/* sub1$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d70000 }
  },
/* sub2$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20980000 }
  },
/* sub2$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d80020 }
  },
/* sub2$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20580000 }
  },
/* sub2$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20180000 }
  },
/* sub2$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d80000 }
  },
/* sub3$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x20990000 }
  },
/* sub3$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20d90020 }
  },
/* sub3$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x20590000 }
  },
/* sub3$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x20190000 }
  },
/* sub3$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20d90000 }
  },
/* mpy$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x209a0000 }
  },
/* mpy$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20da0020 }
  },
/* mpy$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x205a0000 }
  },
/* mpy$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x201a0000 }
  },
/* mpy$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20da0000 }
  },
/* mpyh$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x209b0000 }
  },
/* mpyh$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20db0020 }
  },
/* mpyh$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x205b0000 }
  },
/* mpyh$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x201b0000 }
  },
/* mpyh$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20db0000 }
  },
/* mpyhu$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x209c0000 }
  },
/* mpyhu$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20dc0020 }
  },
/* mpyhu$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x205c0000 }
  },
/* mpyhu$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x201c0000 }
  },
/* mpyhu$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20dc0000 }
  },
/* mpyu$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x209d0000 }
  },
/* mpyu$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x20dd0020 }
  },
/* mpyu$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x205d0000 }
  },
/* mpyu$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x201d0000 }
  },
/* mpyu$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x20dd0000 }
  },
/* j$_L$F0 [$RC_noilink] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', '[', OP (RC_NOILINK), ']', 0 } },
    & ifmt_j_L_r_r___RC_noilink_, { 0x20200000 }
  },
/* j$Qcondi$F0 [$RC_noilink] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', '[', OP (RC_NOILINK), ']', 0 } },
    & ifmt_j_cc___RC_noilink_, { 0x20e00000 }
  },
/* j$_L$F1F [$RC_ilink] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1F), ' ', '[', OP (RC_ILINK), ']', 0 } },
    & ifmt_j_L_r_r___RC_ilink_, { 0x20200000 }
  },
/* j$Qcondi$F1F [$RC_ilink] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1F), ' ', '[', OP (RC_ILINK), ']', 0 } },
    & ifmt_j_cc___RC_ilink_, { 0x20e00000 }
  },
/* j$_L$F0 $s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (S12), 0 } },
    & ifmt_j_L_s12_, { 0x20a00000 }
  },
/* j$Qcondi$F0 $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', OP (U6), 0 } },
    & ifmt_j_ccu6_, { 0x20e00020 }
  },
/* j$_L$F0 $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (U6), 0 } },
    & ifmt_j_L_u6_, { 0x20600000 }
  },
/* j$_S [$R_b] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', '[', OP (R_B), ']', 0 } },
    & ifmt_sub_s_go_sub_ne, { 0x78000000 }
  },
/* j$_S [$R31] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', '[', OP (R31), ']', 0 } },
    & ifmt_j_s__S, { 0x7ee00000 }
  },
/* jeq$_S [$R31] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', '[', OP (R31), ']', 0 } },
    & ifmt_j_s__S, { 0x7ce00000 }
  },
/* jne$_S [$R31] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', '[', OP (R31), ']', 0 } },
    & ifmt_j_s__S, { 0x7de00000 }
  },
/* j$_L$F0.d $s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), '.', 'd', ' ', OP (S12), 0 } },
    & ifmt_j_L_s12_, { 0x20a10000 }
  },
/* j$Qcondi$F0.d $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), '.', 'd', ' ', OP (U6), 0 } },
    & ifmt_j_ccu6_, { 0x20e10020 }
  },
/* j$_L$F0.d $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), '.', 'd', ' ', OP (U6), 0 } },
    & ifmt_j_L_u6_, { 0x20610000 }
  },
/* j$_L$F0.d [$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), '.', 'd', ' ', '[', OP (RC), ']', 0 } },
    & ifmt_j_L_r_r_d___RC_, { 0x20210000 }
  },
/* j$Qcondi$F0.d [$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), '.', 'd', ' ', '[', OP (RC), ']', 0 } },
    & ifmt_j_cc_d___RC_, { 0x20e10000 }
  },
/* j$_S.d [$R_b] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), '.', 'd', ' ', '[', OP (R_B), ']', 0 } },
    & ifmt_sub_s_go_sub_ne, { 0x78200000 }
  },
/* j$_S.d [$R31] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), '.', 'd', ' ', '[', OP (R31), ']', 0 } },
    & ifmt_j_s__S, { 0x7fe00000 }
  },
/* jl$_L$F0 $s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (S12), 0 } },
    & ifmt_j_L_s12_, { 0x20a20000 }
  },
/* jl$Qcondi$F0 $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', OP (U6), 0 } },
    & ifmt_j_ccu6_, { 0x20e20020 }
  },
/* jl$_L$F0 $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (U6), 0 } },
    & ifmt_j_L_u6_, { 0x20620000 }
  },
/* jl$_S [$R_b] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', '[', OP (R_B), ']', 0 } },
    & ifmt_sub_s_go_sub_ne, { 0x78400000 }
  },
/* jl$_L$F0 [$RC_noilink] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', '[', OP (RC_NOILINK), ']', 0 } },
    & ifmt_j_L_r_r___RC_noilink_, { 0x20220000 }
  },
/* jl$Qcondi$F0 [$RC_noilink] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', '[', OP (RC_NOILINK), ']', 0 } },
    & ifmt_j_cc___RC_noilink_, { 0x20e20000 }
  },
/* jl$_L$F0.d $s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), '.', 'd', ' ', OP (S12), 0 } },
    & ifmt_j_L_s12_, { 0x20a30000 }
  },
/* jl$Qcondi$F0.d $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), '.', 'd', ' ', OP (U6), 0 } },
    & ifmt_j_ccu6_, { 0x20e30020 }
  },
/* jl$_L$F0.d $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), '.', 'd', ' ', OP (U6), 0 } },
    & ifmt_j_L_u6_, { 0x20630000 }
  },
/* jl$_L$F0.d [$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), '.', 'd', ' ', '[', OP (RC), ']', 0 } },
    & ifmt_j_L_r_r_d___RC_, { 0x20230000 }
  },
/* jl$Qcondi$F0.d [$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), '.', 'd', ' ', '[', OP (RC), ']', 0 } },
    & ifmt_j_cc_d___RC_, { 0x20e30000 }
  },
/* jl$_S.d [$R_b] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), '.', 'd', ' ', '[', OP (R_B), ']', 0 } },
    & ifmt_sub_s_go_sub_ne, { 0x78600000 }
  },
/* lp$_L$F0 $s12x2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (S12X2), 0 } },
    & ifmt_lp_L_s12_, { 0x20a80000 }
  },
/* lp$Qcondi$F0 $U6x2 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', OP (U6X2), 0 } },
    & ifmt_lpcc_ccu6, { 0x20e80020 }
  },
/* flag$_L$F0 $s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (S12), 0 } },
    & ifmt_j_L_s12_, { 0x20a90000 }
  },
/* flag$Qcondi$F0 $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', OP (U6), 0 } },
    & ifmt_j_ccu6_, { 0x20e90020 }
  },
/* flag$_L$F0 $U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (U6), 0 } },
    & ifmt_j_L_u6_, { 0x20690000 }
  },
/* flag$_L$F0 $RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (RC), 0 } },
    & ifmt_j_L_r_r_d___RC_, { 0x20290000 }
  },
/* flag$Qcondi$F0 $RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', OP (RC), 0 } },
    & ifmt_j_cc_d___RC_, { 0x20e90000 }
  },
/* lr$_L$F0 $RB,[$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (RB), ',', '[', OP (RC), ']', 0 } },
    & ifmt_lr_L_r_r___RC_, { 0x202a0000 }
  },
/* lr$_L$F0 $RB,[$s12] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (RB), ',', '[', OP (S12), ']', 0 } },
    & ifmt_lr_L_s12_, { 0x20aa0000 }
  },
/* sr$_L$F0 $RB,[$RC] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (RB), ',', '[', OP (RC), ']', 0 } },
    & ifmt_lr_L_r_r___RC_, { 0x202b0000 }
  },
/* sr$_L$F0 $RB,[$s12] */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (RB), ',', '[', OP (S12), ']', 0 } },
    & ifmt_lr_L_s12_, { 0x20ab0000 }
  },
/* asl$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0000 }
  },
/* asl$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0000 }
  },
/* asl$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x781b0000 }
  },
/* asr$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0001 }
  },
/* asr$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0001 }
  },
/* asr$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x781c0000 }
  },
/* lsr$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0002 }
  },
/* lsr$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0002 }
  },
/* lsr$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x781d0000 }
  },
/* ror$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0003 }
  },
/* ror$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0003 }
  },
/* rrc$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0004 }
  },
/* rrc$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0004 }
  },
/* sexb$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0005 }
  },
/* sexb$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0005 }
  },
/* sexb$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x780d0000 }
  },
/* sexw$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0006 }
  },
/* sexw$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0006 }
  },
/* sexw$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x780e0000 }
  },
/* extb$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0007 }
  },
/* extb$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0007 }
  },
/* extb$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x780f0000 }
  },
/* extw$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0008 }
  },
/* extw$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0008 }
  },
/* extw$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78100000 }
  },
/* abs$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f0009 }
  },
/* abs$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f0009 }
  },
/* abs$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78110000 }
  },
/* not$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f000a }
  },
/* not$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f000a }
  },
/* not$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78120000 }
  },
/* rlc$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x202f000b }
  },
/* rlc$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x206f000b }
  },
/* ex$_L$EXDi $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (EXDI), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_ex_L_r_r__RC, { 0x202f000c }
  },
/* ex$_L$EXDi $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (EXDI), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_ex_L_u6_, { 0x206f000c }
  },
/* neg$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78130000 }
  },
/* swi */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_swi, { 0x226f003f }
  },
/* trap$_S $trapnum */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (TRAPNUM), 0 } },
    & ifmt_trap_s, { 0x781e0000 }
  },
/* brk */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_swi, { 0x256f003f }
  },
/* brk_s */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_brk_s, { 0x7fff0000 }
  },
/* asl$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x28800000 }
  },
/* asl$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28c00020 }
  },
/* asl$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x28400000 }
  },
/* asl$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x28000000 }
  },
/* asl$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28c00000 }
  },
/* asl$_S $R_c,$R_b,$u3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', OP (R_B), ',', OP (U3), 0 } },
    & ifmt_add_s_cbu3, { 0x68100000 }
  },
/* asl$_S $R_b,$R_b,$u5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (U5), 0 } },
    & ifmt_sub_s_ssb, { 0xb8000000 }
  },
/* asl$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78180000 }
  },
/* lsr$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x28810000 }
  },
/* lsr$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28c10020 }
  },
/* lsr$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x28410000 }
  },
/* lsr$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x28010000 }
  },
/* lsr$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28c10000 }
  },
/* lsr$_S $R_b,$R_b,$u5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (U5), 0 } },
    & ifmt_sub_s_ssb, { 0xb8200000 }
  },
/* lsr$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x78190000 }
  },
/* asr$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x28820000 }
  },
/* asr$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28c20020 }
  },
/* asr$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x28420000 }
  },
/* asr$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x28020000 }
  },
/* asr$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28c20000 }
  },
/* asr$_S $R_c,$R_b,$u3 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_C), ',', OP (R_B), ',', OP (U3), 0 } },
    & ifmt_add_s_cbu3, { 0x68180000 }
  },
/* asr$_S $R_b,$R_b,$u5 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (U5), 0 } },
    & ifmt_sub_s_ssb, { 0xb8400000 }
  },
/* asr$_S $R_b,$R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x781a0000 }
  },
/* ror$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x28830000 }
  },
/* ror$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28c30020 }
  },
/* ror$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x28430000 }
  },
/* ror$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x28030000 }
  },
/* ror$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28c30000 }
  },
/* mul64$_L$F1 $RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (S12), 0 } },
    & ifmt_tst_L_s12_, { 0x28840000 }
  },
/* mul64$Qcondi$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_ccu6_, { 0x28c40020 }
  },
/* mul64$_L$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_L_u6_, { 0x28440000 }
  },
/* mul64$_L$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_L_r_r__RC, { 0x28040000 }
  },
/* mul64$Qcondi$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_cc__RC, { 0x28c40000 }
  },
/* mul64$_S $R_b,$R_c */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), ',', OP (R_C), 0 } },
    & ifmt_I16_GO_SUB_s_go, { 0x780c0000 }
  },
/* mulu64$_L$F1 $RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (S12), 0 } },
    & ifmt_tst_L_s12_, { 0x28850000 }
  },
/* mulu64$Qcondi$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_ccu6_, { 0x28c50020 }
  },
/* mulu64$_L$F1 $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_tst_L_u6_, { 0x28450000 }
  },
/* mulu64$_L$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_L_r_r__RC, { 0x28050000 }
  },
/* mulu64$Qcondi$F1 $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F1), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_tst_cc__RC, { 0x28c50000 }
  },
/* adds$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x28860000 }
  },
/* adds$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28c60020 }
  },
/* adds$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x28460000 }
  },
/* adds$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x28060000 }
  },
/* adds$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28c60000 }
  },
/* subs$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x28870000 }
  },
/* subs$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28c70020 }
  },
/* subs$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x28470000 }
  },
/* subs$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x28070000 }
  },
/* subs$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28c70000 }
  },
/* divaw$_L$F0 $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_lr_L_s12_, { 0x28880000 }
  },
/* divaw$Qcondi$F0 $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_divaw_ccu6__RA_, { 0x28c80020 }
  },
/* divaw$_L$F0 $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_divaw_L_u6__RA_, { 0x28480000 }
  },
/* divaw$_L$F0 $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F0), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_divaw_L_r_r__RA__RC, { 0x28080000 }
  },
/* divaw$Qcondi$F0 $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F0), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_divaw_cc__RA__RC, { 0x28c80000 }
  },
/* asls$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x288a0000 }
  },
/* asls$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28ca0020 }
  },
/* asls$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x284a0000 }
  },
/* asls$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x280a0000 }
  },
/* asls$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28ca0000 }
  },
/* asrs$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x288b0000 }
  },
/* asrs$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28cb0020 }
  },
/* asrs$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x284b0000 }
  },
/* asrs$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x280b0000 }
  },
/* asrs$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28cb0000 }
  },
/* addsdw$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x28a80000 }
  },
/* addsdw$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28e80020 }
  },
/* addsdw$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x28680000 }
  },
/* addsdw$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x28280000 }
  },
/* addsdw$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28e80000 }
  },
/* subsdw$_L$F $RB,$RB,$s12 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (S12), 0 } },
    & ifmt_add_L_s12__RA_, { 0x28a90000 }
  },
/* subsdw$Qcondi$F $RB,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_ccu6__RA_, { 0x28e90020 }
  },
/* subsdw$_L$F $RA,$RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (U6), 0 } },
    & ifmt_add_L_u6__RA_, { 0x28690000 }
  },
/* subsdw$_L$F $RA,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RA), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_L_r_r__RA__RC, { 0x28290000 }
  },
/* subsdw$Qcondi$F $RB,$RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (QCONDI), OP (F), ' ', OP (RB), ',', OP (RB), ',', OP (RC), 0 } },
    & ifmt_add_cc__RA__RC, { 0x28e90000 }
  },
/* swap$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x282f0000 }
  },
/* swap$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x286f0000 }
  },
/* norm$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x282f0001 }
  },
/* norm$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x286f0001 }
  },
/* rnd16$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x282f0003 }
  },
/* rnd16$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x286f0003 }
  },
/* abssw$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x282f0004 }
  },
/* abssw$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x286f0004 }
  },
/* abss$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x282f0005 }
  },
/* abss$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x286f0005 }
  },
/* negsw$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x282f0006 }
  },
/* negsw$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x286f0006 }
  },
/* negs$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x282f0007 }
  },
/* negs$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x286f0007 }
  },
/* normw$_L$F $RB,$RC */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (RC), 0 } },
    & ifmt_asl_L_r_r__RC, { 0x282f0008 }
  },
/* normw$_L$F $RB,$U6 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_L), OP (F), ' ', OP (RB), ',', OP (U6), 0 } },
    & ifmt_asl_L_u6_, { 0x286f0008 }
  },
/* nop_s */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_j_s__S, { 0x78e00000 }
  },
/* unimp_s */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_j_s__S, { 0x79e00000 }
  },
/* pop$_S $R_b */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), 0 } },
    & ifmt_pop_s_b, { 0xc0c10000 }
  },
/* pop$_S $R31 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R31), 0 } },
    & ifmt_pop_s_blink, { 0xc0d10000 }
  },
/* push$_S $R_b */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R_B), 0 } },
    & ifmt_pop_s_b, { 0xc0e10000 }
  },
/* push$_S $R31 */
  {
    { 0, 0, 0, 0 },
    { { MNEM, OP (_S), ' ', OP (R31), 0 } },
    & ifmt_pop_s_blink, { 0xc0f10000 }
  },
/*  */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_current_loop_end, { 0x202f003e }
  },
/*  */
  {
    { 0, 0, 0, 0 },
    { { MNEM, 0 } },
    & ifmt_current_loop_end, { 0x202f003e }
  },
};

#undef A
#undef OPERAND
#undef MNEM
#undef OP

/* Formats for ALIAS macro-insns.  */

#if defined (__STDC__) || defined (ALMOST_STDC) || defined (HAVE_STRINGIZE)
#define F(f) & arc_cgen_ifld_table[ARC_##f]
#else
#define F(f) & arc_cgen_ifld_table[ARC_/**/f]
#endif
#undef F

/* Each non-simple macro entry points to an array of expansion possibilities.  */

#if defined (__STDC__) || defined (ALMOST_STDC) || defined (HAVE_STRINGIZE)
#define A(a) (1 << CGEN_INSN_##a)
#else
#define A(a) (1 << CGEN_INSN_/**/a)
#endif
#if defined (__STDC__) || defined (ALMOST_STDC) || defined (HAVE_STRINGIZE)
#define OPERAND(op) ARC_OPERAND_##op
#else
#define OPERAND(op) ARC_OPERAND_/**/op
#endif
#define MNEM CGEN_SYNTAX_MNEMONIC /* syntax value for mnemonic */
#define OP(field) CGEN_SYNTAX_MAKE_FIELD (OPERAND (field))

/* The macro instruction table.  */

static const CGEN_IBASE arc_cgen_macro_insn_table[] =
{
};

/* The macro instruction opcode table.  */

static const CGEN_OPCODE arc_cgen_macro_insn_opcode_table[] =
{
};

#undef A
#undef OPERAND
#undef MNEM
#undef OP

#ifndef CGEN_ASM_HASH_P
#define CGEN_ASM_HASH_P(insn) 1
#endif

#ifndef CGEN_DIS_HASH_P
#define CGEN_DIS_HASH_P(insn) 1
#endif

/* Return non-zero if INSN is to be added to the hash table.
   Targets are free to override CGEN_{ASM,DIS}_HASH_P in the .opc file.  */

static int
asm_hash_insn_p (insn)
     const CGEN_INSN *insn ATTRIBUTE_UNUSED;
{
  return CGEN_ASM_HASH_P (insn);
}

static int
dis_hash_insn_p (insn)
     const CGEN_INSN *insn;
{
  /* If building the hash table and the NO-DIS attribute is present,
     ignore.  */
  if (CGEN_INSN_ATTR_VALUE (insn, CGEN_INSN_NO_DIS))
    return 0;
  return CGEN_DIS_HASH_P (insn);
}

#ifndef CGEN_ASM_HASH
#define CGEN_ASM_HASH_SIZE 127
#ifdef CGEN_MNEMONIC_OPERANDS
#define CGEN_ASM_HASH(mnem) (*(unsigned char *) (mnem) % CGEN_ASM_HASH_SIZE)
#else
#define CGEN_ASM_HASH(mnem) (*(unsigned char *) (mnem) % CGEN_ASM_HASH_SIZE) /*FIXME*/
#endif
#endif

/* It doesn't make much sense to provide a default here,
   but while this is under development we do.
   BUFFER is a pointer to the bytes of the insn, target order.
   VALUE is the first base_insn_bitsize bits as an int in host order.  */

#ifndef CGEN_DIS_HASH
#define CGEN_DIS_HASH_SIZE 256
#define CGEN_DIS_HASH(buf, value, big_p) (*(unsigned char *) (buf))
#endif

/* The result is the hash value of the insn.
   Targets are free to override CGEN_{ASM,DIS}_HASH in the .opc file.  */

static unsigned int
asm_hash_insn (mnem)
     const char * mnem;
{
  return CGEN_ASM_HASH (mnem);
}

/* BUF is a pointer to the bytes of the insn, target order.
   VALUE is the first base_insn_bitsize bits as an int in host order.  */

static unsigned int
dis_hash_insn (buf, value, big_p)
     const char * buf ATTRIBUTE_UNUSED;
     CGEN_INSN_INT value ATTRIBUTE_UNUSED;
     int big_p ATTRIBUTE_UNUSED;
{
  return CGEN_DIS_HASH (buf, value, big_p);
}

/* Set the recorded length of the insn in the CGEN_FIELDS struct.  */

static void
set_fields_bitsize (CGEN_FIELDS *fields, int size)
{
  CGEN_FIELDS_BITSIZE (fields) = size;
}

/* Function to call before using the operand instance table.
   This plugs the opcode entries and macro instructions into the cpu table.  */

void
arc_cgen_init_opcode_table (CGEN_CPU_DESC cd)
{
  int i;
  int num_macros = (sizeof (arc_cgen_macro_insn_table) /
		    sizeof (arc_cgen_macro_insn_table[0]));
  const CGEN_IBASE *ib = & arc_cgen_macro_insn_table[0];
  const CGEN_OPCODE *oc = & arc_cgen_macro_insn_opcode_table[0];
  CGEN_INSN *insns = malloc (num_macros * sizeof (CGEN_INSN));

/* ??? This is a manual patch to avoid a compiler warning about a zero-sized
   memset.  cgen should be fixed not to emit or comment out this code when
   <target>_cgen_macro_insn_table is empty.  */
#if 0
  memset (insns, 0, num_macros * sizeof (CGEN_INSN));
  for (i = 0; i < num_macros; ++i)
    {
      insns[i].base = &ib[i];
      insns[i].opcode = &oc[i];
      arc_cgen_build_insn_regex (& insns[i]);
    }
#endif
  cd->macro_insn_table.init_entries = insns;
  cd->macro_insn_table.entry_size = sizeof (CGEN_IBASE);
  cd->macro_insn_table.num_init_entries = num_macros;

  oc = & arc_cgen_insn_opcode_table[0];
  insns = (CGEN_INSN *) cd->insn_table.init_entries;
  for (i = 0; i < MAX_INSNS; ++i)
    {
      insns[i].opcode = &oc[i];
      arc_cgen_build_insn_regex (& insns[i]);
    }

  cd->sizeof_fields = sizeof (CGEN_FIELDS);
  cd->set_fields_bitsize = set_fields_bitsize;

  cd->asm_hash_p = asm_hash_insn_p;
  cd->asm_hash = asm_hash_insn;
  cd->asm_hash_size = CGEN_ASM_HASH_SIZE;

  cd->dis_hash_p = dis_hash_insn_p;
  cd->dis_hash = dis_hash_insn;
  cd->dis_hash_size = CGEN_DIS_HASH_SIZE;
}
