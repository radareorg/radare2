/* ARC instruction defintions.
   Copyright (C) 2016-2026 Free Software Foundation, Inc.

   Contributed by Claudiu Zissulescu (claziss@synopsys.com)

   This file is part of libopcodes.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

/* Common combinations of FLAGS.  */
#define FLAGS_NONE { 0 }
#define FLAGS_F    { C_F }
#define FLAGS_CC   { C_CC }
#define FLAGS_CCF  { C_CC, C_F }

/* Common combination of arguments.  */
#define ARG_NONE		{ 0 }
#define ARG_32BIT_RARBRC	{ RA, RB, RC }
#define ARG_32BIT_ZARBRC	{ ZA, RB, RC }
#define ARG_32BIT_RBRBRC	{ RB, RBdup, RC }
#define ARG_32BIT_RARBU6	{ RA, RB, UIMM6_20 }
#define ARG_32BIT_ZARBU6	{ ZA, RB, UIMM6_20 }
#define ARG_32BIT_RBRBU6	{ RB, RBdup, UIMM6_20 }
#define ARG_32BIT_RBRBS12	{ RB, RBdup, SIMM12_20 }
#define ARG_32BIT_RALIMMRC	{ RA, LIMM, RC }
#define ARG_32BIT_RARBLIMM	{ RA, RB, LIMM }
#define ARG_32BIT_ZALIMMRC	{ ZA, LIMM, RC }
#define ARG_32BIT_ZARBLIMM	{ ZA, RB, LIMM }

#define ARG_32BIT_RBRBLIMM	{ RB, RBdup, LIMM }
#define ARG_32BIT_RALIMMU6	{ RA, LIMM, UIMM6_20 }
#define ARG_32BIT_ZALIMMU6	{ ZA, LIMM, UIMM6_20 }

#define ARG_32BIT_ZALIMMS12	{ ZA, LIMM, SIMM12_20 }
#define ARG_32BIT_RALIMMLIMM	{ RA, LIMM, LIMMdup }
#define ARG_32BIT_ZALIMMLIMM	{ ZA, LIMM, LIMMdup }

#define ARG_32BIT_RBRC   { RB, RC }
#define ARG_32BIT_ZARC   { ZA, RC }
#define ARG_32BIT_RBU6   { RB, UIMM6_20 }
#define ARG_32BIT_ZAU6   { ZA, UIMM6_20 }
#define ARG_32BIT_RBLIMM { RB, LIMM }
#define ARG_32BIT_ZALIMM { ZA, LIMM }

/* Macro to generate 2 operand extension instruction.  */
#define EXTINSN2OPF(NAME, CPU, CLASS, SCLASS, MOP, SOP, FL)	 \
  { NAME, INSN2OP_BC (MOP,SOP), MINSN2OP_BC, CPU, CLASS, SCLASS, \
      ARG_32BIT_RBRC,   FL },					 \
  { NAME, INSN2OP_0C (MOP,SOP), MINSN2OP_0C, CPU, CLASS, SCLASS, \
      ARG_32BIT_ZARC,   FL },					 \
  { NAME, INSN2OP_BU (MOP,SOP), MINSN2OP_BU, CPU, CLASS, SCLASS, \
      ARG_32BIT_RBU6,   FL },					 \
  { NAME, INSN2OP_0U (MOP,SOP), MINSN2OP_0U, CPU, CLASS, SCLASS, \
      ARG_32BIT_ZAU6,   FL },					 \
  { NAME, INSN2OP_BL (MOP,SOP), MINSN2OP_BL, CPU, CLASS, SCLASS, \
      ARG_32BIT_RBLIMM, FL },					 \
  { NAME, INSN2OP_0L (MOP,SOP), MINSN2OP_0L, CPU, CLASS, SCLASS, \
      ARG_32BIT_ZALIMM, FL },

#define EXTINSN2OP(NAME, CPU, CLASS, SCLASS, MOP, SOP)		 \
  EXTINSN2OPF(NAME, CPU, CLASS, SCLASS, MOP, SOP, FLAGS_F)

/* Macro to generate 3 operand extesion instruction.  */
#define EXTINSN3OP(NAME, CPU, CLASS, SCLASS, MOP, SOP)			\
  { NAME, INSN3OP_ABC (MOP,SOP),  MINSN3OP_ABC,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_RARBRC,     FLAGS_F },					\
  { NAME, INSN3OP_0BC (MOP,SOP),  MINSN3OP_0BC,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZARBRC,     FLAGS_F   },				\
  { NAME, INSN3OP_CBBC (MOP,SOP), MINSN3OP_CBBC, CPU, CLASS, SCLASS,	\
      ARG_32BIT_RBRBRC,     FLAGS_CCF },				\
  { NAME, INSN3OP_ABU (MOP,SOP),  MINSN3OP_ABU,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_RARBU6,     FLAGS_F   },				\
  { NAME, INSN3OP_0BU (MOP,SOP),  MINSN3OP_0BU,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZARBU6,     FLAGS_F   },				\
  { NAME, INSN3OP_CBBU (MOP,SOP), MINSN3OP_CBBU, CPU, CLASS, SCLASS,	\
      ARG_32BIT_RBRBU6,     FLAGS_CCF },				\
  { NAME, INSN3OP_BBS (MOP,SOP),  MINSN3OP_BBS,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_RBRBS12,    FLAGS_F   },				\
  { NAME, INSN3OP_ALC (MOP,SOP),  MINSN3OP_ALC,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_RALIMMRC,   FLAGS_F   },				\
  { NAME, INSN3OP_ABL (MOP,SOP),  MINSN3OP_ABL,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_RARBLIMM,   FLAGS_F   },				\
  { NAME, INSN3OP_0LC (MOP,SOP),  MINSN3OP_0LC,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZALIMMRC,   FLAGS_F   },				\
  { NAME, INSN3OP_0BL (MOP,SOP),  MINSN3OP_0BL,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZARBLIMM,   FLAGS_F   },				\
  { NAME, INSN3OP_C0LC (MOP,SOP), MINSN3OP_C0LC, CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZALIMMRC,   FLAGS_CCF },				\
  { NAME, INSN3OP_CBBL (MOP,SOP), MINSN3OP_CBBL, CPU, CLASS, SCLASS,	\
      ARG_32BIT_RBRBLIMM,   FLAGS_CCF },				\
  { NAME, INSN3OP_ALU (MOP,SOP),  MINSN3OP_ALU,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_RALIMMU6,   FLAGS_F   },				\
  { NAME, INSN3OP_0LU (MOP,SOP),  MINSN3OP_0LU,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZALIMMU6,   FLAGS_F   },				\
  { NAME, INSN3OP_C0LU (MOP,SOP), MINSN3OP_C0LU, CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZALIMMU6,   FLAGS_CCF },				\
  { NAME, INSN3OP_0LS (MOP,SOP),  MINSN3OP_0LS,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZALIMMS12,  FLAGS_F   },				\
  { NAME, INSN3OP_ALL (MOP,SOP),  MINSN3OP_ALL,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_RALIMMLIMM, FLAGS_F   },				\
  { NAME, INSN3OP_0LL (MOP,SOP),  MINSN3OP_0LL,  CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZALIMMLIMM, FLAGS_F   },				\
  { NAME, INSN3OP_C0LL (MOP,SOP), MINSN3OP_C0LL, CPU, CLASS, SCLASS,	\
      ARG_32BIT_ZALIMMLIMM, FLAGS_CCF },

/* Extension instruction declarations.  */
EXTINSN2OP ("dsp_fp_flt2i",  ARC_OPCODE_ARCv2EM, FLOAT, QUARKSE1, 7, 43)
EXTINSN2OP ("dsp_fp_i2flt",  ARC_OPCODE_ARCv2EM, FLOAT, QUARKSE1, 7, 44)
EXTINSN2OP ("dsp_fp_sqrt",   ARC_OPCODE_ARCv2EM, FLOAT, QUARKSE2, 7, 45)

EXTINSN3OP ("dsp_fp_div", ARC_OPCODE_ARCv2EM, FLOAT, QUARKSE2, 7, 42)
EXTINSN3OP ("dsp_fp_cmp", ARC_OPCODE_ARCv2EM, FLOAT, QUARKSE1, 7, 43)
