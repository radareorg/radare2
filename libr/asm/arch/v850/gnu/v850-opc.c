/* Assemble V850 instructions.
   Copyright (C) 1996-2020 Free Software Foundation, Inc.

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

#include "sysdep.h"
#include <stdio.h>
#include "v850.h"
#include "mybfd.h"
#include "opintl.h"

/* Regular opcodes.  */
#define OP(x)		((x & 0x3f) << 5)
#define OP_MASK		OP (0x3f)

/* Conditional branch opcodes (Format III).  */
#define BOP(x)		((0x58 << 4) | (x & 0x0f))
#define BOP_MASK	((0x78 << 4) | 0x0f)

/* Conditional branch opcodes (Format VII).  */
#define BOP7(x)		(0x107e0 | (x & 0xf))
#define BOP7_MASK	(0x1ffe0 | 0xf)

/* One-word opcodes.  */
#define one(x)		((unsigned int) (x))

/* Two-word opcodes.  */
#define two(x,y)	((unsigned int) (x) | ((unsigned int) (y) << 16))


/* The functions used to insert and extract complicated operands.  */

/* Note: There is a conspiracy between these functions and
   v850_insert_operand() in gas/config/tc-v850.c.  Error messages
   containing the string 'out of range' will be ignored unless a
   specific command line option is given to GAS.  */

static const char * not_valid    = N_ ("displacement value is not in range and is not aligned");
static const char * out_of_range = N_ ("displacement value is out of range");
static const char * not_aligned  = N_ ("displacement value is not aligned");

static const char * immediate_out_of_range = N_ ("immediate value is out of range");
static const char * branch_out_of_range = N_ ("branch value out of range");
static const char * branch_out_of_range_and_odd_offset = N_ ("branch value not in range and to odd offset");
static const char * branch_to_odd_offset = N_ ("branch to odd offset");
static const char * pos_out_of_range = N_ ("position value is out of range");
static const char * width_out_of_range = N_ ("width value is out of range");
static const char * selid_out_of_range = N_ ("SelID is out of range");
static const char * vector8_out_of_range = N_ ("vector8 is out of range");
static const char * vector5_out_of_range = N_ ("vector5 is out of range");
static const char * imm10_out_of_range = N_ ("imm10 is out of range");
static const char * sr_selid_out_of_range = N_ ("SR/SelID is out of range");

int
v850_msg_is_out_of_range (const char* msg)
{
  return msg == out_of_range
    || msg == immediate_out_of_range
    || msg == branch_out_of_range;
}

static unsigned long
insert_i5div1 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 30 || value < 2)
    {
      if (value & 1)
	* errmsg = _(not_valid);
      else
	* errmsg = _(out_of_range);
    }
  else if (value & 1)
    * errmsg = _(not_aligned);

  value = (32 - value)/2;

  return (insn | ((value << (2+16)) & 0x3c0000));
}

static unsigned long
extract_i5div1 (unsigned long insn, int * invalid)
{
  unsigned long ret = (insn & 0x003c0000) >> (16+2);
  ret = 32 - (ret * 2);

  if (invalid != 0)
    *invalid = (ret > 30 || ret < 2) ? 1 : 0;
  return ret;
}

static unsigned long
insert_i5div2 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 30 || value < 4)
    {
      if (value & 1)
	* errmsg = _(not_valid);
      else
	* errmsg = _(out_of_range);
    }
  else if (value & 1)
    * errmsg = _(not_aligned);

  value = (32 - value)/2;

  return insn | ((value << (2 + 16)) & 0x3c0000);
}

static unsigned long
extract_i5div2 (unsigned long insn, int * invalid)
{
  unsigned long ret = (insn & 0x003c0000) >> (16+2);
  ret = 32 - (ret * 2);

  if (invalid != 0)
    *invalid = (ret > 30 || ret < 4) ? 1 : 0;
  return ret;
}

static unsigned long
insert_i5div3 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 32 || value < 2)
    {
      if (value & 1)
	* errmsg = _(not_valid);
      else
	* errmsg = _(out_of_range);
    }
  else if (value & 1)
    * errmsg = _(not_aligned);

  value = (32 - value)/2;

  return insn | ((value << (2+16)) & 0x3c0000);
}

static unsigned long
extract_i5div3 (unsigned long insn, int * invalid)
{
  unsigned long ret = (insn & 0x003c0000) >> (16+2);
  ret = 32 - (ret * 2);

  if (invalid != 0)
    *invalid = (ret > 32 || ret < 2) ? 1 : 0;
  return ret;
}

static unsigned long
insert_d5_4 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0x1f || value < 0)
    {
      if (value & 1)
	* errmsg = _(not_valid);
      else
	* errmsg = _(out_of_range);
    }
  else if (value & 1)
    * errmsg = _(not_aligned);

  value >>= 1;

  return insn | (value & 0x0f);
}

static unsigned long
extract_d5_4 (unsigned long insn, int * invalid)
{
  unsigned long ret = (insn & 0x0f);

  ret <<= 1;

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_d8_6 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0xff || value < 0)
    {
      if ((value % 4) != 0)
	* errmsg = _(not_valid);
      else
	* errmsg = _(out_of_range);
    }
  else if ((value % 4) != 0)
    * errmsg = _(not_aligned);

  value >>= 1;

  return insn | (value & 0x7e);
}

static unsigned long
extract_d8_6 (unsigned long insn, int * invalid)
{
  unsigned long ret = (insn & 0x7e);

  ret <<= 1;

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_d8_7 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0xff || value < 0)
    {
      if ((value % 2) != 0)
	* errmsg = _(not_valid);
      else
	* errmsg = _(out_of_range);
    }
  else if ((value % 2) != 0)
    * errmsg = _(not_aligned);

  value >>= 1;

  return insn | (value & 0x7f);
}

static unsigned long
extract_d8_7 (unsigned long insn, int * invalid)
{
  unsigned long ret = (insn & 0x7f);

  ret <<= 1;

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_v8 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0xff || value < 0)
    * errmsg = _(immediate_out_of_range);

  return insn | (value & 0x1f) | ((value & 0xe0) << (27-5));
}

static unsigned long
extract_v8 (unsigned long insn, int * invalid)
{
  unsigned long ret = (insn & 0x1f) | ((insn >> (27-5)) & 0xe0);

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_d9 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0xff || value < -0x100)
    {
      if ((value % 2) != 0)
	* errmsg = branch_out_of_range_and_odd_offset;
      else
	* errmsg = branch_out_of_range;
    }
  else if ((value % 2) != 0)
    * errmsg = branch_to_odd_offset;

  return insn | ((value & 0x1f0) << 7) | ((value & 0x0e) << 3);
}

static unsigned long
extract_d9 (unsigned long insn, int * invalid)
{
  signed long ret = ((insn >> 7) & 0x1f0) | ((insn >> 3) & 0x0e);

  ret = (ret ^ 0x100) - 0x100;

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_u16_loop (unsigned long insn, long value, const char ** errmsg)
{
  /* Loop displacement is encoded as a positive value,
     even though the instruction branches backwards.  */
  if (value < 0 || value > 0xffff)
    {
      if ((value % 2) != 0)
	* errmsg = branch_out_of_range_and_odd_offset;
      else
	* errmsg = branch_out_of_range;
    }
  else if ((value % 2) != 0)
    * errmsg = branch_to_odd_offset;

  return insn | ((value & 0xfffe) << 16);
}

static unsigned long
extract_u16_loop (unsigned long insn, int * invalid)
{
  long ret = (insn >> 16) & 0xfffe;

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_d16_15 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0x7fff || value < -0x8000)
    {
      if ((value % 2) != 0)
	* errmsg = _(not_valid);
      else
	* errmsg = _(out_of_range);
    }
  else if ((value % 2) != 0)
    * errmsg = _(not_aligned);

  return insn | ((value & 0xfffe) << 16);
}

static unsigned long
extract_d16_15 (unsigned long insn, int * invalid)
{
  signed long ret = (insn >> 16) & 0xfffe;

  ret = (ret ^ 0x8000) - 0x8000;

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_d16_16 (unsigned long insn, signed long value, const char ** errmsg)
{
  if (value > 0x7fff || value < -0x8000)
    * errmsg = _(out_of_range);

  return insn | ((value & 0xfffe) << 16) | ((value & 1) << 5);
}

static unsigned long
extract_d16_16 (unsigned long insn, int * invalid)
{
  signed long ret = ((insn >> 16) & 0xfffe) | ((insn >> 5) & 1);

  ret = (ret ^ 0x8000) - 0x8000;

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_d17_16 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0xffff || value < -0x10000)
    * errmsg = _(out_of_range);

  return insn | ((value & 0xfffe) << 16) | ((value & 0x10000) >> (16 - 4));
}

static unsigned long
extract_d17_16 (unsigned long insn, int * invalid)
{
  signed long ret = ((insn >> 16) & 0xfffe) | ((insn << (16 - 4)) & 0x10000);

  ret = (ret ^ 0x10000) - 0x10000;

  if (invalid != 0)
    *invalid = 0;
  return (unsigned long)ret;
}

static unsigned long
insert_d22 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0x1fffff || value < -0x200000)
    {
      if ((value % 2) != 0)
	* errmsg = branch_out_of_range_and_odd_offset;
      else
	* errmsg = branch_out_of_range;
    }
  else if ((value % 2) != 0)
    * errmsg = branch_to_odd_offset;

  return insn | ((value & 0xfffe) << 16) | ((value & 0x3f0000) >> 16);
}

static unsigned long
extract_d22 (unsigned long insn, int * invalid)
{
  signed long ret = ((insn >> 16) & 0xfffe) | ((insn << 16) & 0x3f0000);

  ret = (ret ^ 0x200000) - 0x200000;

  if (invalid != 0)
    *invalid = 0;
  return (unsigned long) ret;
}

static unsigned long
insert_d23 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0x3fffff || value < -0x400000)
    * errmsg = out_of_range;

  return insn | ((value & 0x7f) << 4) | ((value & 0x7fff80) << (16-7));
}

static unsigned long
insert_d23_align1 (unsigned long insn, long value, const char ** errmsg)
{
  if (value > 0x3fffff || value < -0x400000)
    {
      if (value & 0x1)
	* errmsg = _(not_valid);
      else
	* errmsg = _(out_of_range);
    }
  else if (value & 0x1)
    * errmsg = _(not_aligned);

  return insn | ((value & 0x7e) << 4) | ((value & 0x7fff80) << (16 - 7));
}

static unsigned long
extract_d23 (unsigned long insn, int * invalid)
{
  signed long ret = ((insn >> 4) & 0x7f) | ((insn >> (16-7)) & 0x7fff80);

  ret = (ret ^ 0x400000) - 0x400000;

  if (invalid != 0)
    *invalid = 0;
  return (unsigned long) ret;
}

static unsigned long
insert_i9 (unsigned long insn, signed long value, const char ** errmsg)
{
  if (value > 0xff || value < -0x100)
    * errmsg = _(immediate_out_of_range);

  return insn | ((value & 0x1e0) << 13) | (value & 0x1f);
}

static unsigned long
extract_i9 (unsigned long insn, int * invalid)
{
  signed long ret = ((insn >> 13) & 0x1e0) | (insn & 0x1f);

  ret = (ret ^ 0x100) - 0x100;

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_u9 (unsigned long insn, long v, const char ** errmsg)
{
  unsigned long value = (unsigned long) v;

  if (value > 0x1ff)
    * errmsg = _(immediate_out_of_range);

  return insn | ((value & 0x1e0) << 13) | (value & 0x1f);
}

static unsigned long
extract_u9 (unsigned long insn, int * invalid)
{
  unsigned long ret = ((insn >> 13) & 0x1e0) | (insn & 0x1f);

  if (invalid != 0)
    *invalid = 0;
  return ret;
}

static unsigned long
insert_spe (unsigned long insn, long v, const char ** errmsg)
{
  unsigned long value = (unsigned long) v;

  if (value != 3)
    * errmsg = _("invalid register for stack adjustment");

  return insn & ~0x180000;
}

static unsigned long
extract_spe (unsigned long insn ATTRIBUTE_UNUSED, int * invalid)
{
  if (invalid != 0)
    *invalid = 0;

  return 3;
}

static unsigned long
insert_r4 (unsigned long insn, long v, const char ** errmsg)
{
  unsigned long value = (unsigned long) v;

  if (value >= 32)
    * errmsg = _("invalid register name");

  return insn | ((value & 0x01) << 23) | ((value & 0x1e) << 16);
}

static unsigned long
extract_r4 (unsigned long insn, int * invalid)
{
  unsigned long r4;
  unsigned long insn2;

  insn2 = insn >> 16;
  r4 = (((insn2 & 0x0080) >> 7) | (insn2 & 0x001e));

  if (invalid != 0)
    *invalid = 0;

  return r4;
}

static unsigned long G_pos;

static unsigned long
insert_POS (unsigned long insn, long pos, const char ** errmsg)
{
  if (pos > 0x1f || pos < 0)
    * errmsg = _(pos_out_of_range);

  G_pos = (unsigned long) pos;

  return insn; /* Not an oparaton until WIDTH.  */
}

static unsigned long
extract_POS_U (unsigned long insn, int * invalid)
{
  unsigned long pos,lsb;
  unsigned long insn2;
  insn2 = insn >> 16;

  lsb = ((insn2 & 0x0800) >>  8)
      | ((insn2 & 0x000e) >>  1);
  lsb += 16;
  pos = lsb;

  if (invalid != 0)
    *invalid = 0;

  return pos;
}

static unsigned long
extract_POS_L (unsigned long insn, int * invalid)
{
  unsigned long pos,lsb;
  unsigned long insn2;
  insn2 = insn >> 16;

  lsb = ((insn2 & 0x0800) >>  8)
      | ((insn2 & 0x000e) >>  1);
  pos = lsb;

  if (invalid != 0)
    *invalid = 0;

  return pos;
}

static unsigned long
insert_WIDTH (unsigned long insn, long width, const char ** errmsg)
{
  unsigned long msb, lsb, opc, ret;
  unsigned long msb_expand, lsb_expand;

  msb = (unsigned long)width + G_pos - 1;
  lsb = G_pos;
  opc = 0;
  G_pos = 0;

  if (width > 0x20 || width < 0)
    * errmsg = _(width_out_of_range);

  if ((msb >= 16) && (lsb >= 16))
    opc = 0x0090;
  else if ((msb >= 16) && (lsb < 16))
    opc = 0x00b0;
  else if ((msb < 16) && (lsb < 16))
    opc = 0x00d0;
  else
    * errmsg = _(width_out_of_range);

  msb &= 0x0f;
  msb_expand = msb << 12;
  lsb &= 0x0f;
  lsb_expand = ((lsb & 0x8) << 8)|((lsb & 0x7) << 1);

  ret = (insn & 0x0000ffff) | ((opc | msb_expand | lsb_expand) << 16);

  return ret;
}

static unsigned long
extract_WIDTH_U (unsigned long insn, int * invalid)
{
  unsigned long width, msb, lsb;
  unsigned long insn2;
  insn2 = insn >> 16;

  msb = ((insn2 & 0xf000) >> 12);
  msb += 16;
  lsb = ((insn2 & 0x0800) >>  8)
      | ((insn2 & 0x000e) >>  1);
  lsb += 16;

  if (invalid != 0)
    *invalid = 0;

  width = msb - lsb + 1;

  return width;
}

static unsigned long
extract_WIDTH_M (unsigned long insn, int * invalid)
{
  unsigned long width, msb, lsb;
  unsigned long insn2;
  insn2 = insn >> 16;

  msb = ((insn2 & 0xf000) >> 12) ;
  msb += 16;
  lsb = ((insn2 & 0x0800) >>  8)
      | ((insn2 & 0x000e) >>  1);

  if (invalid != 0)
    *invalid = 0;

  width = msb - lsb + 1;

  return width;
}

static unsigned long
extract_WIDTH_L (unsigned long insn, int * invalid)
{
  unsigned long width, msb, lsb;
  unsigned long insn2;
  insn2 = insn >> 16;

  msb = ((insn2 & 0xf000) >> 12) ;
  lsb = ((insn2 & 0x0800) >>  8)
      | ((insn2 & 0x000e) >>  1);

  if (invalid != 0)
    *invalid = 0;

  width = msb - lsb + 1;

  return width;
}

static unsigned long
insert_SELID (unsigned long insn, long selid, const char ** errmsg)
{
  if ((unsigned long) selid > 0x1f)
    * errmsg = _(selid_out_of_range);

  return insn | ((selid & 0x1fUL) << 27);
}

static unsigned long
extract_SELID (unsigned long insn, int * invalid)
{
  unsigned long selid;
  unsigned long insn2;

  insn2 = insn >> 16;

  selid = ((insn2 & 0xf800) >> 11);

  if (invalid != 0)
    *invalid = 0;

  return selid;
}

static unsigned long
insert_VECTOR8 (unsigned long insn, long vector8, const char ** errmsg)
{
  unsigned long ret;
  unsigned long VVV,vvvvv;

  if (vector8 > 0xff || vector8 < 0)
    * errmsg = _(vector8_out_of_range);

  VVV   = (vector8 & 0xe0) >> 5;
  vvvvv = (vector8 & 0x1f);

  ret = (insn | (VVV << 27) | vvvvv);

  return ret;
}

static unsigned long
extract_VECTOR8 (unsigned long insn, int * invalid)
{
  unsigned long vector8;
  unsigned long VVV,vvvvv;
  unsigned long insn2;

  insn2   = insn >> 16;
  VVV     = ((insn2 & 0x3800) >> 11);
  vvvvv   = (insn & 0x001f);
  vector8 = VVV << 5 | vvvvv;

  if (invalid != 0)
    *invalid = 0;

  return vector8;
}

static unsigned long
insert_VECTOR5 (unsigned long insn, long vector5, const char ** errmsg)
{
  unsigned long ret;
  unsigned long vvvvv;

  if (vector5 > 0x1f || vector5 < 0)
    * errmsg = _(vector5_out_of_range);

  vvvvv = (vector5 & 0x1f);

  ret = (insn | vvvvv);

  return ret;
}

static unsigned long
extract_VECTOR5 (unsigned long insn, int * invalid)
{
  unsigned long vector5;

  vector5 = (insn & 0x001f);

  if (invalid != 0)
    *invalid = 0;

  return vector5;
}

static unsigned long
insert_CACHEOP (unsigned long insn, long cacheop, const char ** errmsg ATTRIBUTE_UNUSED)
{
  unsigned long ret;
  unsigned long pp,PPPPP;

  pp    = (cacheop & 0x60) >> 5;
  PPPPP = (cacheop & 0x1f);

  ret = insn | (pp << 11) | (PPPPP << 27);

  return ret;
}

static unsigned long
extract_CACHEOP (unsigned long insn, int * invalid)
{
  unsigned long ret;
  unsigned long pp,PPPPP;
  unsigned long insn2;

  insn2 = insn >> 16;

  PPPPP = ((insn2 & 0xf800) >> 11);
  pp    = ((insn  & 0x1800) >> 11);

  ret   = (pp << 5) | PPPPP;

  if (invalid != 0)
    *invalid = 0;

  return ret;
}

static unsigned long
insert_PREFOP (unsigned long insn, long prefop, const char ** errmsg ATTRIBUTE_UNUSED)
{
  unsigned long ret;
  unsigned long PPPPP;

  PPPPP = (prefop & 0x1f);

  ret = insn | (PPPPP << 27);

  return ret;
}

static unsigned long
extract_PREFOP (unsigned long insn, int * invalid)
{
  unsigned long ret;
  unsigned long PPPPP;
  unsigned long insn2;

  insn2 = insn >> 16;

  PPPPP = (insn2 & 0xf800) >> 11;

  ret   = PPPPP;

  if (invalid != 0)
    *invalid = 0;

  return ret;
}

static unsigned long
insert_IMM10U (unsigned long insn, long value, const char ** errmsg)
{
  unsigned long imm10, ret;
  unsigned long iiiii,IIIII;

  if (value > 0x3ff || value < 0)
    * errmsg = _(imm10_out_of_range);

  imm10 = ((unsigned long) value) & 0x3ff;
  IIIII = (imm10 >> 5) & 0x1f;
  iiiii =  imm10       & 0x1f;

  ret = insn | IIIII << 27 | iiiii;

  return ret;
}

static unsigned long
extract_IMM10U (unsigned long insn, int * invalid)
{
  unsigned long ret;
  unsigned long iiiii,IIIII;
  unsigned long insn2;
  insn2 = insn >> 16;

  IIIII = ((insn2 & 0xf800) >> 11);
  iiiii = (insn   & 0x001f);

  ret = (IIIII << 5) | iiiii;

  if (invalid != 0)
    *invalid = 0;

  return ret;
}

static unsigned long
insert_SRSEL1 (unsigned long insn, long value, const char ** errmsg)
{
  unsigned long imm10, ret;
  unsigned long sr,selid;

  if (value > 0x3ff || value < 0)
    * errmsg = _(sr_selid_out_of_range);

  imm10 = (unsigned long) value;
  selid = (imm10 & 0x3e0) >> 5;
  sr    =  imm10 & 0x1f;

  ret   = insn | selid << 27 | sr;

  return ret;
}

static unsigned long
extract_SRSEL1 (unsigned long insn, int * invalid)
{
  unsigned long ret;
  unsigned long sr, selid;
  unsigned long insn2;

  insn2 = insn >> 16;

  selid = ((insn2 & 0xf800) >> 11);
  sr    = (insn  & 0x001f);

  ret   = (selid << 5) | sr;

  if (invalid != 0)
    *invalid = 0;

  return ret;
}

static unsigned long
insert_SRSEL2 (unsigned long insn, long value, const char ** errmsg)
{
  unsigned long imm10, ret;
  unsigned long sr, selid;

  if (value > 0x3ff || value < 0)
    * errmsg = _(sr_selid_out_of_range);

  imm10 = (unsigned long) value;
  selid = (imm10 & 0x3e0) >> 5;
  sr    =  imm10 & 0x1f;

  ret   = insn | selid << 27 | sr << 11;

  return ret;
}

static unsigned long
extract_SRSEL2 (unsigned long insn, int * invalid)
{
  unsigned long ret;
  unsigned long sr, selid;
  unsigned long insn2;

  insn2 = insn >> 16;

  selid = ((insn2 & 0xf800) >> 11);
  sr    = ((insn  & 0xf800) >> 11);

  ret   = (selid << 5) | sr;

  if (invalid != 0)
    *invalid = 0;

  return ret;
}

/* Warning: code in gas/config/tc-v850.c examines the contents of this array.
   If you change any of the values here, be sure to look for side effects in
   that code.  */
const struct v850_operand v850_operands[] =
{
#define UNUSED	0
  { 0, 0, NULL, NULL, 0, BFD_RELOC_NONE },

/* The R1 field in a format 1, 6, 7, 9, C insn.  */
#define R1	(UNUSED + 1)
  { 5, 0, NULL, NULL, V850_OPERAND_REG, BFD_RELOC_NONE },

/* As above, but register 0 is not allowed.  */
#define R1_NOTR0 (R1 + 1)
  { 5, 0, NULL, NULL, V850_OPERAND_REG | V850_NOT_R0, BFD_RELOC_NONE },

/* Even register is allowed.  */
#define R1_EVEN (R1_NOTR0 + 1)
  { 4, 1, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN, BFD_RELOC_NONE },

/* Bang (bit reverse).  */
#define R1_BANG (R1_EVEN + 1)
  { 5, 0, NULL, NULL, V850_OPERAND_REG | V850_OPERAND_BANG, BFD_RELOC_NONE },

/* Percent (modulo).  */
#define R1_PERCENT (R1_BANG + 1)
  { 5, 0, NULL, NULL, V850_OPERAND_REG | V850_OPERAND_PERCENT, BFD_RELOC_NONE },

/* The R2 field in a format 1, 2, 4, 5, 6, 7, 9, C insn.  */
#define R2 (R1_PERCENT + 1)
  { 5, 11, NULL, NULL, V850_OPERAND_REG, BFD_RELOC_NONE },

/* As above, but register 0 is not allowed.  */
#define R2_NOTR0 (R2 + 1)
  { 5, 11, NULL, NULL, V850_OPERAND_REG | V850_NOT_R0, BFD_RELOC_NONE },

/* Even register is allowed.  */
#define R2_EVEN (R2_NOTR0 + 1)
  { 4, 12, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN, BFD_RELOC_NONE },

/* Reg2 in dispose instruction.  */
#define R2_DISPOSE	(R2_EVEN + 1)
  { 5, 16, NULL, NULL, V850_OPERAND_REG | V850_NOT_R0, BFD_RELOC_NONE },

/* The R3 field in a format 11, 12, C insn.  */
#define R3	(R2_DISPOSE + 1)
  { 5, 27, NULL, NULL, V850_OPERAND_REG, BFD_RELOC_NONE },

/* As above, but register 0 is not allowed.  */
#define R3_NOTR0	(R3 + 1)
  { 5, 27, NULL, NULL, V850_OPERAND_REG | V850_NOT_R0, BFD_RELOC_NONE },

/* As above, but odd number registers are not allowed.  */
#define R3_EVEN	(R3_NOTR0 + 1)
  { 4, 28, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN, BFD_RELOC_NONE },

/* As above, but register 0 is not allowed.  */
#define R3_EVEN_NOTR0	(R3_EVEN + 1)
  { 4, 28, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN | V850_NOT_R0, BFD_RELOC_NONE },

/* Forth register in FPU Instruction.  */
#define R4	(R3_EVEN_NOTR0 + 1)
  { 5, 0, insert_r4, extract_r4, V850_OPERAND_REG, BFD_RELOC_NONE },

/* As above, but odd number registers are not allowed.  */
#define R4_EVEN	(R4 + 1)
  { 4, 17, NULL, NULL, V850_OPERAND_REG | V850_REG_EVEN, BFD_RELOC_NONE },

/* Stack pointer in prepare instruction.  */
#define SP	(R4_EVEN + 1)
  { 2, 0, insert_spe, extract_spe, V850_OPERAND_REG, BFD_RELOC_NONE },

/* EP Register.  */
#define EP	(SP + 1)
  { 0, 0, NULL, NULL, V850_OPERAND_EP, BFD_RELOC_NONE },

/* A list of registers in a prepare/dispose instruction.  */
#define LIST12	(EP + 1)
  { -1, 0xffe00001, NULL, NULL, V850E_OPERAND_REG_LIST, BFD_RELOC_NONE },

/* System register operands.  */
#define OLDSR1	(LIST12 + 1)
  { 5, 0, NULL, NULL, V850_OPERAND_SRG, BFD_RELOC_NONE },

#define SR1	(OLDSR1 + 1)
  { 0, 0, insert_SRSEL1, extract_SRSEL1, V850_OPERAND_SRG, BFD_RELOC_NONE },

/* The R2 field as a system register.  */
#define OLDSR2	(SR1 + 1)
  { 5, 11, NULL, NULL, V850_OPERAND_SRG, BFD_RELOC_NONE },

#define SR2	(OLDSR2 + 1)
  { 0, 0, insert_SRSEL2, extract_SRSEL2, V850_OPERAND_SRG, BFD_RELOC_NONE },

/* FPU CC bit position.  */
#define FFF (SR2 + 1)
  { 3, 17, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 4 bit condition code in a setf instruction.  */
#define CCCC	(FFF + 1)
  { 4, 0, NULL, NULL, V850_OPERAND_CC, BFD_RELOC_NONE },

/* Condition code in adf,sdf.  */
#define CCCC_NOTSA	(CCCC + 1)
  { 4, 17, NULL, NULL, V850_OPERAND_CC|V850_NOT_SA, BFD_RELOC_NONE },

/* Condition code in conditional moves.  */
#define MOVCC	(CCCC_NOTSA + 1)
  { 4, 17, NULL, NULL, V850_OPERAND_CC, BFD_RELOC_NONE },

/* Condition code in FPU.  */
#define FLOAT_CCCC	(MOVCC + 1)
  { 4, 27, NULL, NULL, V850_OPERAND_FLOAT_CC, BFD_RELOC_NONE },

/* The 1 bit immediate field in format C insn.  */
#define VI1	(FLOAT_CCCC + 1)
  { 1, 3, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 1 bit immediate field in format C insn.  */
#define VC1	(VI1 + 1)
  { 1, 0, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 2 bit immediate field in format C insn.  */
#define DI2	(VC1 + 1)
  { 2, 17, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 2 bit immediate field in format C insn.  */
#define VI2	(DI2 + 1)
  { 2, 0, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 2 bit immediate field in format C - DUP insn.  */
#define VI2DUP	(VI2 + 1)
  { 2, 2, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 3 bit immediate field in format 8 insn.  */
#define B3	(VI2DUP + 1)
  { 3, 11, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 3 bit immediate field in format C insn.  */
#define DI3	(B3 + 1)
  { 3, 17, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 3 bit immediate field in format C insn.  */
#define I3U	(DI3 + 1)
  { 3, 0, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 4 bit immediate field in format C insn.  */
#define I4U	(I3U + 1)
  { 4, 0, NULL, NULL, 0, BFD_RELOC_NONE },

/* The 4 bit immediate field in fetrap.  */
#define I4U_NOTIMM0	(I4U + 1)
  { 4, 11, NULL, NULL, V850_NOT_IMM0, BFD_RELOC_NONE },

/* The unsigned disp4 field in a sld.bu.  */
#define D4U	(I4U_NOTIMM0 + 1)
  { 4, 0, NULL, NULL, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_4_4_OFFSET },

/* The imm5 field in a format 2 insn.  */
#define I5	(D4U + 1)
  { 5, 0, NULL, NULL, V850_OPERAND_SIGNED, BFD_RELOC_NONE },

/* The imm5 field in a format 11 insn.  */
#define I5DIV1	(I5 + 1)
  { 5, 0, insert_i5div1, extract_i5div1, 0, BFD_RELOC_NONE },

#define I5DIV2	(I5DIV1 + 1)
  { 5, 0, insert_i5div2, extract_i5div2, 0, BFD_RELOC_NONE },

#define I5DIV3	(I5DIV2 + 1)
  { 5, 0, insert_i5div3, extract_i5div3, 0, BFD_RELOC_NONE },

/* The unsigned imm5 field in a format 2 insn.  */
#define I5U	(I5DIV3 + 1)
  { 5, 0, NULL, NULL, 0, BFD_RELOC_NONE },

/* The imm5 field in a prepare/dispose instruction.  */
#define IMM5	(I5U + 1)
  { 5, 1, NULL, NULL, 0, BFD_RELOC_NONE },

/* The unsigned disp5 field in a sld.hu.  */
#define D5_4U	(IMM5 + 1)
  { 5, 0, insert_d5_4, extract_d5_4, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_4_5_OFFSET },

/* The IMM6 field in a callt instruction.  */
#define IMM6	(D5_4U + 1)
  { 6, 0, NULL, NULL, 0, BFD_RELOC_V850_CALLT_6_7_OFFSET },

/* The signed disp7 field in a format 4 insn.  */
#define D7U	(IMM6 + 1)
  { 7, 0, NULL, NULL, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_7_7_OFFSET },

/* The unsigned DISP8 field in a format 4 insn.  */
#define D8_7U	(D7U + 1)
  { 8, 0, insert_d8_7, extract_d8_7, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_7_8_OFFSET },

/* The unsigned DISP8 field in a format 4 insn.  */
#define D8_6U	(D8_7U + 1)
  { 8, 0, insert_d8_6, extract_d8_6, V850_OPERAND_DISP, BFD_RELOC_V850_TDA_6_8_OFFSET },

/* The unsigned DISP8 field in a format 4 insn.  */
#define V8	(D8_6U + 1)
  { 8, 0, insert_v8, extract_v8, 0, BFD_RELOC_NONE },

/* The imm9 field in a multiply word.  */
#define I9	(V8 + 1)
  { 9, 0, insert_i9, extract_i9, V850_OPERAND_SIGNED, BFD_RELOC_NONE },

/* The unsigned imm9 field in a multiply word.  */
#define U9	(I9 + 1)
  { 9, 0, insert_u9, extract_u9, 0, BFD_RELOC_NONE },

/* The DISP9 field in a format 3 insn.  */
#define D9	(U9 + 1)
  { 9, 0, insert_d9, extract_d9, V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_9_PCREL },

/* The DISP9 field in a format 3 insn, relaxable.  */
#define D9_RELAX	(D9 + 1)
  { 9, 0, insert_d9, extract_d9, V850_OPERAND_RELAX | V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_9_PCREL },

/* The imm16 field in a format 6 insn.  */
#define I16	(D9_RELAX + 1)
  { 16, 16, NULL, NULL, V850_OPERAND_SIGNED, BFD_RELOC_16 },

/* The signed 16 bit immediate following a prepare instruction.  */
#define IMM16LO	(I16 + 1)
  { 16, 32, NULL, NULL, V850E_IMMEDIATE16 | V850_OPERAND_SIGNED, BFD_RELOC_LO16 },

/* The hi 16 bit immediate following a 32 bit instruction.  */
#define IMM16HI	(IMM16LO + 1)
  { 16, 16, NULL, NULL, V850E_IMMEDIATE16HI, BFD_RELOC_HI16 },

/* The unsigned imm16 in a format 6 insn.  */
#define I16U	(IMM16HI + 1)
  { 16, 16, NULL, NULL, 0, BFD_RELOC_16 },

/* The disp16 field in a format 8 insn.  */
#define D16	(I16U + 1)
  { 16, 16, NULL, NULL, V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_16 },

/* The disp16 field in an format 7 unsigned byte load insn.  */
#define D16_16	(D16 + 1)
  { 16, 0, insert_d16_16, extract_d16_16, V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_V850_16_SPLIT_OFFSET },

/* The disp16 field in a format 6 insn.  */
#define D16_15	(D16_16 + 1)
  { 16, 0, insert_d16_15, extract_d16_15, V850_OPERAND_SIGNED | V850_OPERAND_DISP , BFD_RELOC_V850_16_S1 },

/* The unsigned DISP16 field in a format 7 insn.  */
#define D16_LOOP	(D16_15 + 1)
  { 16, 0, insert_u16_loop, extract_u16_loop, V850_OPERAND_RELAX | V850_OPERAND_DISP | V850_PCREL | V850_INVERSE_PCREL, BFD_RELOC_V850_16_PCREL },

/* The DISP17 field in a format 7 insn.  */
#define D17_16	(D16_LOOP + 1)
  { 17, 0, insert_d17_16, extract_d17_16, V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_17_PCREL },

/* The DISP22 field in a format 4 insn, relaxable.
   This _must_ follow D9_RELAX; the assembler assumes that the longer
   version immediately follows the shorter version for relaxing.  */
#define D22	(D17_16 + 1)
  { 22, 0, insert_d22, extract_d22, V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_22_PCREL },

#define D23	(D22 + 1)
  { 23, 0, insert_d23, extract_d23, V850E_IMMEDIATE23 | V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_V850_23 },

#define D23_ALIGN1	(D23 + 1)
  { 23, 0, insert_d23_align1, extract_d23, V850E_IMMEDIATE23 | V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_V850_23 },

/* The 32 bit immediate following a 32 bit instruction.  */
#define IMM32	(D23_ALIGN1 + 1)
  { 32, 32, NULL, NULL, V850E_IMMEDIATE32, BFD_RELOC_32 },

#define D32_31	(IMM32 + 1)
  { 32, 32, NULL, NULL, V850E_IMMEDIATE32 | V850_OPERAND_SIGNED | V850_OPERAND_DISP, BFD_RELOC_V850_32_ABS },

#define D32_31_PCREL	(D32_31 + 1)
  { 32, 32, NULL, NULL, V850E_IMMEDIATE32 | V850_OPERAND_SIGNED | V850_OPERAND_DISP | V850_PCREL, BFD_RELOC_V850_32_PCREL },

#define POS_U	(D32_31_PCREL + 1)
  { 0, 0, insert_POS, extract_POS_U, 0, BFD_RELOC_NONE },

#define POS_M	(POS_U + 1)
  { 0, 0, insert_POS, extract_POS_L, 0, BFD_RELOC_NONE },

#define POS_L	(POS_M + 1)
  { 0, 0, insert_POS, extract_POS_L, 0, BFD_RELOC_NONE },

#define WIDTH_U	(POS_L + 1)
  { 0, 0, insert_WIDTH, extract_WIDTH_U, 0, BFD_RELOC_NONE },

#define WIDTH_M	(WIDTH_U + 1)
  { 0, 0, insert_WIDTH, extract_WIDTH_M, 0, BFD_RELOC_NONE },

#define WIDTH_L	(WIDTH_M + 1)
  { 0, 0, insert_WIDTH, extract_WIDTH_L, 0, BFD_RELOC_NONE },

#define SELID	(WIDTH_L + 1)
  { 5, 27, insert_SELID, extract_SELID, 0, BFD_RELOC_NONE },

#define RIE_IMM5	(SELID + 1)
  { 5, 11, NULL, NULL, 0, BFD_RELOC_NONE },

#define RIE_IMM4	(RIE_IMM5 + 1)
  { 4, 0, NULL, NULL, 0, BFD_RELOC_NONE },

#define VECTOR8	(RIE_IMM4 + 1)
  { 0, 0, insert_VECTOR8, extract_VECTOR8, 0, BFD_RELOC_NONE },

#define VECTOR5	(VECTOR8 + 1)
  { 0, 0, insert_VECTOR5, extract_VECTOR5, 0, BFD_RELOC_NONE },

#define VR1	(VECTOR5 + 1)
  { 5, 0, NULL, NULL, V850_OPERAND_VREG, BFD_RELOC_NONE },

#define VR2	(VR1 + 1)
  { 5, 11, NULL, NULL, V850_OPERAND_VREG, BFD_RELOC_NONE },

#define CACHEOP	(VR2 + 1)
  { 0, 0, insert_CACHEOP, extract_CACHEOP, V850_OPERAND_CACHEOP, BFD_RELOC_NONE },

#define PREFOP	(CACHEOP + 1)
  { 0, 0, insert_PREFOP, extract_PREFOP, V850_OPERAND_PREFOP, BFD_RELOC_NONE },

#define IMM10U	(PREFOP + 1)
  { 0, 0, insert_IMM10U, extract_IMM10U, 0, BFD_RELOC_NONE },
};


/* Reg - Reg instruction format (Format I).  */
#define IF1	{R1, R2}

/* Imm - Reg instruction format (Format II).  */
#define IF2	{I5, R2}

/* Conditional branch instruction format (Format III).  */
#define IF3	{D9_RELAX}

/* 3 operand instruction (Format VI).  */
#define IF6	{I16, R1, R2}

/* 3 operand instruction (Format VI).  */
#define IF6U	{I16U, R1, R2}

/* Conditional branch instruction format (Format VII).  */
#define IF7	{D17_16}


/* The opcode table.

   The format of the opcode table is:

   NAME		OPCODE			MASK		       { OPERANDS }	   MEMOP    PROCESSOR

   NAME is the name of the instruction.
   OPCODE is the instruction opcode.
   MASK is the opcode mask; this is used to tell the disassembler
     which bits in the actual opcode must match OPCODE.
   OPERANDS is the list of operands.
   MEMOP specifies which operand (if any) is a memory operand.
   PROCESSORS specifies which CPU(s) support the opcode.

   The disassembler reads the table in order and prints the first
   instruction which matches, so this table is sorted to put more
   specific instructions before more general instructions.  It is also
   sorted by major opcode.

   The table is also sorted by name.  This is used by the assembler.
   When parsing an instruction the assembler finds the first occurance
   of the name of the instruciton in this table and then attempts to
   match the instruction's arguments with description of the operands
   associated with the entry it has just found in this table.  If the
   match fails the assembler looks at the next entry in this table.
   If that entry has the same name as the previous entry, then it
   tries to match the instruction against that entry and so on.  This
   is how the assembler copes with multiple, different formats of the
   same instruction.  */

const struct v850_opcode v850_opcodes[] =
{
/* Standard instructions.  */
{ "add",	OP  (0x0e),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },
{ "add",	OP  (0x12),		OP_MASK,		IF2, 			0, PROCESSOR_ALL },

{ "addi",	OP  (0x30),		OP_MASK,		IF6, 			0, PROCESSOR_ALL },

{ "adf",	two (0x07e0, 0x03a0),	two (0x07e0, 0x07e1),	{CCCC_NOTSA, R1, R2, R3},    	0, PROCESSOR_V850E2_UP },

{ "and",	OP (0x0a),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },

{ "andi",	OP (0x36),		OP_MASK,		IF6U, 			0, PROCESSOR_ALL },

	/* Signed integer.  */
{ "bge",	BOP (0xe),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bgt",	BOP (0xf),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "ble",	BOP (0x7),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "blt",	BOP (0x6),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
	/* Unsigned integer.  */
{ "bh",		BOP (0xb),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bl",		BOP (0x1),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bnh",	BOP (0x3),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bnl",	BOP (0x9),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
	/* Common.  */
{ "be",		BOP (0x2),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bne",	BOP (0xa),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
	/* Others.  */
{ "bc",		BOP (0x1),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bf",		BOP (0xa),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bn",		BOP (0x4),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bnc",	BOP (0x9),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bnv",	BOP (0x8),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bnz",	BOP (0xa),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bp",		BOP (0xc),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "br",		BOP (0x5),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bsa",	BOP (0xd),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bt",		BOP (0x2),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bv",		BOP (0x0),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "bz",		BOP (0x2),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },

/* Signed integer.  */
{ "bge",  two (0x07ee, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bgt",  two (0x07ef, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "ble",  two (0x07e7, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "blt",  two (0x07e6, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
/* Unsigned integer.  */
{ "bh",   two (0x07eb, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bl",   two (0x07e1, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bnh",  two (0x07e3, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bnl",  two (0x07e9, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
/* Common.  */
{ "be",   two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bne",  two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
/* Others.  */
{ "bc",   two (0x07e1, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bf",   two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bn",   two (0x07e4, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bnc",  two (0x07e9, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bnv",  two (0x07e8, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bnz",  two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bp",   two (0x07ec, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "br",   two (0x07e5, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bsa",  two (0x07ed, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bt",   two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bv",   two (0x07e0, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
{ "bz",   two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP },
/* Bcond disp17 Gas local alias(not defined in spec).  */

/* Signed integer.  */
{ "bge17",  two (0x07ee, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bgt17",  two (0x07ef, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "ble17",  two (0x07e7, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "blt17",  two (0x07e6, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
/* Unsigned integer.  */
{ "bh17",   two (0x07eb, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bl17",   two (0x07e1, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bnh17",  two (0x07e3, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bnl17",  two (0x07e9, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
/* Common.  */
{ "be17",   two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bne17",  two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
/* Others.  */
{ "bc17",   two (0x07e1, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bf17",   two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bn17",   two (0x07e4, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bnc17",  two (0x07e9, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bnv17",  two (0x07e8, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bnz17",  two (0x07ea, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bp17",   two (0x07ec, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "br17",   two (0x07e5, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bsa17",  two (0x07ed, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bt17",   two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bv17",   two (0x07e0, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "bz17",   two (0x07e2, 0x0001), two (0xffef, 0x0001), IF7, 0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },

{ "bsh",	two (0x07e0, 0x0342),	two (0x07ff, 0x07ff), 	{R2, R3}, 		0, PROCESSOR_NOT_V850 },

{ "bsw",	two (0x07e0, 0x0340),	two (0x07ff, 0x07ff), 	{R2, R3}, 		0, PROCESSOR_NOT_V850 },

/* v850e3v5 bitfield instructions.  */
{ "bins",	two (0x07e0, 0x0090),	two (0x07e0, 0x07f1), {R1, POS_U, WIDTH_U, R2}, 		0, PROCESSOR_V850E3V5_UP },
{ "bins",	two (0x07e0, 0x00b0),	two (0x07e0, 0x07f1), {R1, POS_M, WIDTH_M, R2}, 		0, PROCESSOR_V850E3V5_UP },
{ "bins",	two (0x07e0, 0x00d0),	two (0x07e0, 0x07f1), {R1, POS_L, WIDTH_L, R2}, 		0, PROCESSOR_V850E3V5_UP },
/* Gas local alias(not defined in spec).  */
{ "binsu",two (0x07e0, 0x0090),	two (0x07e0, 0x07f1), {R1, POS_U, WIDTH_U, R2},			0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "binsm",two (0x07e0, 0x00b0),	two (0x07e0, 0x07f1), {R1, POS_M, WIDTH_M, R2}, 		0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },
{ "binsl",two (0x07e0, 0x00d0),	two (0x07e0, 0x07f1), {R1, POS_L, WIDTH_L, R2}, 		0, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },

{ "cache",	two (0xe7e0, 0x0160),	two (0xe7e0, 0x07ff),	{CACHEOP, R1}, 		2, PROCESSOR_V850E3V5_UP },

{ "callt",	one (0x0200),		one (0xffc0), 	      	{IMM6},			0, PROCESSOR_NOT_V850 },

{ "caxi",	two (0x07e0, 0x00ee),	two (0x07e0, 0x07ff),	{R1, R2, R3},		1, PROCESSOR_V850E2_UP },

{ "clr1",	two (0x87c0, 0x0000),	two (0xc7e0, 0x0000),	{B3, D16, R1}, 		3, PROCESSOR_ALL },
{ "clr1",	two (0x07e0, 0x00e4),	two (0x07e0, 0xffff),   {R2, R1},    		3, PROCESSOR_NOT_V850 },

{ "cmov",	two (0x07e0, 0x0320),	two (0x07e0, 0x07e1), 	{MOVCC, R1, R2, R3}, 	0, PROCESSOR_NOT_V850 },
{ "cmov",	two (0x07e0, 0x0300),	two (0x07e0, 0x07e1), 	{MOVCC, I5, R2, R3}, 	0, PROCESSOR_NOT_V850 },

{ "cmp",	OP  (0x0f),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },
{ "cmp",	OP  (0x13),		OP_MASK,		IF2, 			0, PROCESSOR_ALL },

{ "ctret", 	two (0x07e0, 0x0144),	two (0xffff, 0xffff), 	{0}, 			0, PROCESSOR_NOT_V850 },

{ "dbcp",	one (0xe840),		one (0xffff),		{0},			0, PROCESSOR_V850E3V5_UP },

{ "dbhvtrap",	one (0xe040),		one (0xffff),		{0},			0, PROCESSOR_V850E3V5_UP },

{ "dbpush",	two (0x5fe0, 0x0160),	two (0xffe0, 0x07ff),	{R1, R3}, 		0, PROCESSOR_V850E3V5_UP },

{ "dbret",	two (0x07e0, 0x0146),	two (0xffff, 0xffff),	{0},			0, PROCESSOR_NOT_V850 },

{ "dbtag",	two (0xcfe0, 0x0160),	two (0xffe0, 0x07ff),	{IMM10U},		0, PROCESSOR_V850E3V5_UP },

{ "dbtrap",	one (0xf840),		one (0xffff),		{0},			0, PROCESSOR_NOT_V850 },

{ "di",		two (0x07e0, 0x0160),	two (0xffff, 0xffff),	{0}, 			0, PROCESSOR_ALL },

{ "dispose",	two (0x0640, 0x0000),   two (0xffc0, 0x0000),   {IMM5, LIST12, R2_DISPOSE},3, PROCESSOR_NOT_V850 },
{ "dispose",	two (0x0640, 0x0000),   two (0xffc0, 0x001f), 	{IMM5, LIST12}, 	0, PROCESSOR_NOT_V850 },

{ "div",	two (0x07e0, 0x02c0),	two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_NOT_V850 },

{ "divh",	two (0x07e0, 0x0280),   two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_NOT_V850 },
{ "divh",	OP  (0x02),		OP_MASK,		{R1_NOTR0, R2_NOTR0},	0, PROCESSOR_ALL },

{ "divhn",	two (0x07e0, 0x0280),	two (0x07e0, 0x07c3), 	{I5DIV1, R1, R2, R3},	0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_EXTENSION },

{ "divhu",	two (0x07e0, 0x0282),   two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_NOT_V850 },

{ "divhun",	two (0x07e0, 0x0282),	two (0x07e0, 0x07c3), 	{I5DIV1, R1, R2, R3}, 	0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_EXTENSION },
{ "divn",	two (0x07e0, 0x02c0),	two (0x07e0, 0x07c3), 	{I5DIV2, R1, R2, R3}, 	0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_EXTENSION },

{ "divq",	two (0x07e0, 0x02fc),   two (0x07e0, 0x07ff), 	{R1, R2, R3},		0, PROCESSOR_V850E2_UP },

{ "divqu",	two (0x07e0, 0x02fe),   two (0x07e0, 0x07ff), 	{R1, R2, R3},		0, PROCESSOR_V850E2_UP },

{ "divu",	two (0x07e0, 0x02c2),	two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_NOT_V850 },

{ "divun",	two (0x07e0, 0x02c2),	two (0x07e0, 0x07c3), 	{I5DIV2, R1, R2, R3}, 	0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_EXTENSION },

{ "dst",	two (0x07e0, 0x0134),	two (0xfffff, 0xffff),	{0}, 		0, PROCESSOR_V850E3V5_UP },

{ "ei",		two (0x87e0, 0x0160),	two (0xffff, 0xffff),	{0}, 			0, PROCESSOR_ALL },

{ "eiret",	two (0x07e0, 0x0148),	two (0xffff, 0xffff),	{0},			0, PROCESSOR_V850E2_UP },

{ "est",	two (0x07e0, 0x0132),	two (0xfffff, 0xffff),	{0}, 		0, PROCESSOR_V850E3V5_UP },

{ "feret",	two (0x07e0, 0x014a),	two (0xffff, 0xffff),	{0},			0, PROCESSOR_V850E2_UP },

{ "fetrap",	one (0x0040),		one (0x87ff),		{I4U_NOTIMM0},		0, PROCESSOR_V850E2_UP },

{ "halt",	two (0x07e0, 0x0120),	two (0xffff, 0xffff),	{0}, 			0, PROCESSOR_ALL },

{ "hsh",	two (0x07e0, 0x0346),	two (0x07ff, 0x07ff), 	{R2, R3}, 		0, PROCESSOR_V850E2_UP },

{ "hsw",	two (0x07e0, 0x0344),	two (0x07ff, 0x07ff), 	{R2, R3}, 		0, PROCESSOR_NOT_V850 },

{ "hvcall",	two (0xd7e0, 0x4160),	two (0xffe0, 0x41ff),	{VECTOR8}, 		0, PROCESSOR_V850E3V5_UP },
{ "hvtrap",	two (0x07e0, 0x0110),	two (0xffe0, 0xffff),	{VECTOR5}, 		0, PROCESSOR_V850E3V5_UP },

{ "jarl",	two (0xc7e0, 0x0160),	two (0xffe0, 0x07ff),	{R1, R3_NOTR0},   	1, PROCESSOR_V850E3V5_UP},
{ "jarl",	two (0x0780, 0x0000),	two (0x07c0, 0x0001),	{D22, R2_NOTR0}, 	0, PROCESSOR_ALL},
{ "jarl",	one (0x02e0),		one (0xffe0),		{D32_31_PCREL, R1_NOTR0}, 	0, PROCESSOR_V850E2_UP },
/* Gas local alias (not defined in spec).  */
{ "jarlr", two (0xc7e0, 0x0160),	two (0xffe0, 0x07ff),	{R1, R3_NOTR0}, 1, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS},
/* Gas local alias of jarl imm22 (not defined in spec).  */
{ "jarl22",	two (0x0780, 0x0000),	two (0x07c0, 0x0001),	{D22, R2_NOTR0}, 	0, PROCESSOR_ALL | PROCESSOR_OPTION_ALIAS},
/* Gas local alias of jarl imm32 (not defined in spec).  */
{ "jarl32",	one (0x02e0),		one (0xffe0),		{D32_31_PCREL, R1_NOTR0}, 	0, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },
{ "jarlw",	one (0x02e0),		one (0xffe0),		{D32_31_PCREL, R1_NOTR0}, 	0, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "jmp",	two (0x06e0, 0x0000),	two (0xffe0, 0x0001),	{D32_31, R1}, 		2, PROCESSOR_V850E3V5_UP },
{ "jmp",	one (0x06e0),		one (0xffe0),		{D32_31, R1}, 		2, PROCESSOR_V850E2 | PROCESSOR_V850E2V3 },
{ "jmp",	one (0x0060),		one (0xffe0),	      	{R1}, 			1, PROCESSOR_ALL },
/* Gas local alias of jmp disp22(not defined in spec).  */
{ "jmp22",	one (0x0060),		one (0xffe0),	      	{R1}, 			1, PROCESSOR_ALL | PROCESSOR_OPTION_ALIAS },
/* Gas local alias of jmp disp32(not defined in spec).  */
{ "jmp32",	one (0x06e0),		one (0xffe0),		{D32_31, R1}, 		2, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },
{ "jmpw",	one (0x06e0),		one (0xffe0),		{D32_31, R1}, 		2, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "jr",		two (0x0780, 0x0000),	two (0xffc0, 0x0001),	{D22}, 			0, PROCESSOR_ALL },
{ "jr",		one (0x02e0),		one (0xffff),		{D32_31_PCREL},		0, PROCESSOR_V850E2_UP },
/* Gas local alias of mov imm22(not defined in spec).  */
{ "jr22",	two (0x0780, 0x0000),	two (0xffc0, 0x0001),	{D22}, 			0, PROCESSOR_ALL | PROCESSOR_OPTION_ALIAS },
/* Gas local alias of mov imm32(not defined in spec).  */
{ "jr32",	one (0x02e0),		one (0xffff),		{D32_31_PCREL},		0, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

/* Alias of bcond (same as CA850).  */
{ "jgt",	BOP (0xf),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jge",	BOP (0xe),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jlt",	BOP (0x6),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jle",	BOP (0x7),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
	/* Unsigned integer.  */
{ "jh",		BOP (0xb),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jnh",	BOP (0x3),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jl",		BOP (0x1),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jnl",	BOP (0x9),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
	/* Common.  */
{ "je",		BOP (0x2),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jne",	BOP (0xa),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
	/* Others.  */
{ "jv",		BOP (0x0),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jnv",	BOP (0x8),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jn",		BOP (0x4),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jp",		BOP (0xc),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jc",		BOP (0x1),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jnc",	BOP (0x9),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jz",		BOP (0x2),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jnz",	BOP (0xa),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },
{ "jbr",	BOP (0x5),		BOP_MASK,		IF3, 			0, PROCESSOR_ALL },


{ "ldacc",	two (0x07e0, 0x0bc4),	two (0x07e0, 0xffff),	{R1, R2},		0, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_EXTENSION },

{ "ld.b",	two (0x0700, 0x0000),	two (0x07e0, 0x0000), 	{D16, R1, R2}, 		2, PROCESSOR_ALL },
{ "ld.b",	two (0x0780, 0x0005),	two (0xffe0, 0x000f), 	{D23, R1, R3}, 		2, PROCESSOR_V850E2_UP },
{ "ld.b23",	two (0x0780, 0x0005),	two (0x07e0, 0x000f), 	{D23, R1, R3}, 		2, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "ld.bu",	two (0x0780, 0x0001),   two (0x07c0, 0x0001), 	{D16_16, R1, R2_NOTR0},	2, PROCESSOR_NOT_V850 },
{ "ld.bu",	two (0x07a0, 0x0005),	two (0xffe0, 0x000f), 	{D23, R1, R3}, 		2, PROCESSOR_V850E2_UP },
{ "ld.bu23",	two (0x07a0, 0x0005),	two (0x07e0, 0x000f), 	{D23, R1, R3}, 		2, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "ld.dw",   	two (0x07a0, 0x0009), 	two (0xffe0, 0x001f), {D23_ALIGN1, R1, R3_EVEN}, 2, PROCESSOR_V850E3V5_UP },
{ "ld.dw23", 	two (0x07a0, 0x0009), 	two (0xffe0, 0x001f), {D23_ALIGN1, R1, R3_EVEN}, 2, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },

{ "ld.h",	two (0x0720, 0x0000),	two (0x07e0, 0x0001), 	{D16_15, R1, R2}, 	2, PROCESSOR_ALL },
{ "ld.h",	two (0x0780, 0x0007),	two (0x07e0, 0x000f), 	{D23_ALIGN1, R1, R3}, 	2, PROCESSOR_V850E2_UP },
{ "ld.h23",	two (0x0780, 0x0007),	two (0x07e0, 0x000f), 	{D23_ALIGN1, R1, R3}, 	2, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "ld.hu",	two (0x07e0, 0x0001),   two (0x07e0, 0x0001), 	{D16_15, R1, R2_NOTR0},	2, PROCESSOR_NOT_V850 },
{ "ld.hu",	two (0x07a0, 0x0007),	two (0x07e0, 0x000f), 	{D23_ALIGN1, R1, R3}, 	2, PROCESSOR_V850E2_UP },
{ "ld.hu23",	two (0x07a0, 0x0007),	two (0x07e0, 0x000f), 	{D23_ALIGN1, R1, R3}, 	2, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "ld.w",	two (0x0720, 0x0001),	two (0x07e0, 0x0001), 	{D16_15, R1, R2}, 	2, PROCESSOR_ALL },
{ "ld.w",	two (0x0780, 0x0009),	two (0xffe0, 0x001f), 	{D23_ALIGN1, R1, R3}, 	2, PROCESSOR_V850E2_UP },
{ "ld.w23",	two (0x0780, 0x0009),	two (0x07e0, 0x001f), 	{D23_ALIGN1, R1, R3}, 	2, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "ldl.w",	two (0x07e0, 0x0378),	two (0xffe0, 0x07ff),	{R1, R3}, 		1, PROCESSOR_V850E3V5_UP },

{ "ldsr",	two (0x07e0, 0x0020),	two (0x07e0, 0x07ff),	{R1, SR2, SELID}, 	0, PROCESSOR_V850E3V5_UP },
{ "ldsr",	two (0x07e0, 0x0020),	two (0x07e0, 0x07ff),	{R1, SR2}, 		0, PROCESSOR_V850E3V5_UP },
{ "ldsr",	two (0x07e0, 0x0020),	two (0x07e0, 0x07ff),	{R1, OLDSR2}, 		0, (PROCESSOR_ALL & (~ PROCESSOR_V850E3V5_UP)) },

{ "ldtc.gr",	two (0x07e0, 0x0032),	two (0x07e0, 0xffff),	{R1, R2}, 		0, PROCESSOR_V850E3V5_UP },
{ "ldtc.sr",	two (0x07e0, 0x0030),	two (0x07e0, 0x07ff),	{R1, SR2, SELID}, 	0, PROCESSOR_V850E3V5_UP },
{ "ldtc.sr",	two (0x07e0, 0x0030),	two (0x07e0, 0x07ff),	{R1, SR2},	 	0, PROCESSOR_V850E3V5_UP },

{ "ldtc.vr",	two (0x07e0, 0x0832),	two (0x07e0, 0xffff),	{R1, VR2}, 		0, PROCESSOR_V850E3V5_UP },
{ "ldtc.pc",	two (0x07e0, 0xf832),	two (0x07e0, 0xffff),	{R1}, 			0, PROCESSOR_V850E3V5_UP },

{ "ldvc.sr",	two (0x07e0, 0x0034),	two (0x07e0, 0x07ff),	{R1, SR2, SELID}, 	0, PROCESSOR_V850E3V5_UP },
{ "ldvc.sr",	two (0x07e0, 0x0034),	two (0x07e0, 0x07ff),	{R1, SR2},	 	0, PROCESSOR_V850E3V5_UP },

{ "loop",	two (0x06e0, 0x0001),	two (0xffe0, 0x0001), 	{R1, D16_LOOP}, 	0, PROCESSOR_V850E3V5_UP },

{ "macacc",	two (0x07e0, 0x0bc0),	two (0x07e0, 0xffff),	{R1, R2},		0, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_EXTENSION },

{ "mac",	two (0x07e0, 0x03c0),	two (0x07e0, 0x0fe1),	{R1, R2, R3_EVEN, R4_EVEN},    	0, PROCESSOR_V850E2_UP },

{ "macu",	two (0x07e0, 0x03e0),	two (0x07e0, 0x0fe1),	{R1, R2, R3_EVEN, R4_EVEN},  	0, PROCESSOR_V850E2_UP },

{ "macuacc",	two (0x07e0, 0x0bc2),	two (0x07e0, 0xffff),	{R1, R2},		0, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_EXTENSION },

{ "mov",        OP  (0x00),		OP_MASK,		{R1, R2_NOTR0},		0, PROCESSOR_ALL },
{ "mov",	OP  (0x10),		OP_MASK,		{I5, R2_NOTR0},		0, PROCESSOR_ALL },
{ "mov",	one (0x0620),		one (0xffe0),		{IMM32, R1},		0, PROCESSOR_NOT_V850 },
/* Gas local alias of mov imm32(not defined in spec).  */
{ "movl",	one (0x0620),		one (0xffe0),		{IMM32, R1},		0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_ALIAS },

{ "movea",	OP  (0x31),		OP_MASK,		{I16, R1, R2_NOTR0},	0, PROCESSOR_ALL },

{ "movhi",	OP  (0x32),		OP_MASK,		{I16, R1, R2_NOTR0},	0, PROCESSOR_ALL },

{ "mul",	two (0x07e0, 0x0220),	two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_NOT_V850 },
{ "mul",	two (0x07e0, 0x0240),	two (0x07e0, 0x07c3), 	{I9, R2, R3}, 		0, PROCESSOR_NOT_V850 },

{ "mulh",	OP  (0x17),		OP_MASK,		{I5, R2_NOTR0},		0, PROCESSOR_ALL },
{ "mulh",	OP  (0x07),		OP_MASK,		{R1, R2_NOTR0},		0, PROCESSOR_ALL },

{ "mulhi",	OP  (0x37),		OP_MASK,		{I16, R1, R2_NOTR0},	0, PROCESSOR_ALL },

{ "mulu",	two (0x07e0, 0x0222),	two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_NOT_V850 },
{ "mulu",	two (0x07e0, 0x0242),	two (0x07e0, 0x07c3), 	{U9, R2, R3}, 		0, PROCESSOR_NOT_V850 },

{ "nop",	one (0x00),		one (0xffff),		{0}, 			0, PROCESSOR_ALL },

{ "not",	OP (0x01),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },

{ "not1",	two (0x47c0, 0x0000),	two (0xc7e0, 0x0000),	{B3, D16, R1}, 		3, PROCESSOR_ALL },
{ "not1",	two (0x07e0, 0x00e2),	two (0x07e0, 0xffff),	{R2, R1},    		3, PROCESSOR_NOT_V850 },

{ "or",		OP (0x08),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },

{ "ori",	OP (0x34),		OP_MASK,		IF6U, 			0, PROCESSOR_ALL },

{ "popsp",	two (0x67e0, 0x0160),	two (0xffe0, 0x07ff),	{R1, R3}, 		0, PROCESSOR_V850E3V5_UP },

{ "pref",	two (0xdfe0, 0x0160),	two (0xffe0, 0x07ff),	{PREFOP, R1}, 		2, PROCESSOR_V850E3V5_UP },

{ "prepare",    two (0x0780, 0x0003),	two (0xffc0, 0x001f), 	{LIST12, IMM5, SP}, 	0, PROCESSOR_NOT_V850 },
{ "prepare",    two (0x0780, 0x000b),	two (0xffc0, 0x001f), 	{LIST12, IMM5, IMM16LO},0, PROCESSOR_NOT_V850 },
{ "prepare",    two (0x0780, 0x0013),	two (0xffc0, 0x001f), 	{LIST12, IMM5, IMM16HI},0, PROCESSOR_NOT_V850 },
{ "prepare",    two (0x0780, 0x001b),	two (0xffc0, 0x001f), 	{LIST12, IMM5, IMM32}, 	0, PROCESSOR_NOT_V850 },
{ "prepare",    two (0x0780, 0x0001),	two (0xffc0, 0x001f), 	{LIST12, IMM5}, 	0, PROCESSOR_NOT_V850 },

{ "pushsp",	two (0x47e0, 0x0160),	two (0xffe0, 0x07ff),	{R1, R3}, 		0, PROCESSOR_V850E3V5_UP },

{ "rotl",	two (0x07e0, 0x00c6),	two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_V850E3V5_UP },
{ "rotl",	two (0x07e0, 0x00c4),	two (0x07e0, 0x07ff), 	{I5U, R2, R3}, 		0, PROCESSOR_V850E3V5_UP },

{ "reti",	two (0x07e0, 0x0140),	two (0xffff, 0xffff),	{0}, 			0, PROCESSOR_ALL },

{ "sar",	two (0x07e0, 0x00a2),	two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_V850E2_UP },
{ "sar",	OP (0x15),		OP_MASK,		{I5U, R2}, 		0, PROCESSOR_ALL },
{ "sar",	two (0x07e0, 0x00a0),	two (0x07e0, 0xffff), 	{R1,  R2}, 		0, PROCESSOR_ALL },

{ "sasf",       two (0x07e0, 0x0200),	two (0x07f0, 0xffff), 	{CCCC, R2}, 		0, PROCESSOR_NOT_V850 },

{ "satadd",	two (0x07e0, 0x03ba),	two (0x07e0, 0x07ff), 	{R1, R2, R3},		0, PROCESSOR_V850E2_UP },
{ "satadd",	OP (0x11),		OP_MASK,		{I5, R2_NOTR0},		0, PROCESSOR_ALL },
{ "satadd",	OP (0x06),		OP_MASK,		{R1, R2_NOTR0},		0, PROCESSOR_ALL },

{ "satsub",	two (0x07e0, 0x039a),	two (0x07e0, 0x07ff), 	{R1, R2, R3},		0, PROCESSOR_V850E2_UP },
{ "satsub",	OP (0x05),		OP_MASK,		{R1, R2_NOTR0},		0, PROCESSOR_ALL },

{ "satsubi",	OP (0x33),		OP_MASK,		{I16, R1, R2_NOTR0},	0, PROCESSOR_ALL },

{ "satsubr",	OP (0x04),		OP_MASK,		{R1, R2_NOTR0},		0, PROCESSOR_ALL },

{ "sbf",	two (0x07e0, 0x0380),	two (0x07e0, 0x07e1),	{CCCC_NOTSA, R1, R2, R3},    	0, PROCESSOR_V850E2_UP },

{ "sch0l",	two (0x07e0, 0x0364),	two (0x07ff, 0x07ff), 	{R2, R3}, 		0, PROCESSOR_V850E2_UP },

{ "sch0r",	two (0x07e0, 0x0360),	two (0x07ff, 0x07ff), 	{R2, R3}, 		0, PROCESSOR_V850E2_UP },

{ "sch1l",	two (0x07e0, 0x0366),	two (0x07ff, 0x07ff), 	{R2, R3}, 		0, PROCESSOR_V850E2_UP },

{ "sch1r",	two (0x07e0, 0x0362),	two (0x07ff, 0x07ff), 	{R2, R3}, 		0, PROCESSOR_V850E2_UP },

{ "sdivhn",	two (0x07e0, 0x0180),	two (0x07e0, 0x07c3), 	{I5DIV3, R1, R2, R3}, 	0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_EXTENSION },
{ "sdivhun",	two (0x07e0, 0x0182),	two (0x07e0, 0x07c3), 	{I5DIV3, R1, R2, R3}, 	0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_EXTENSION },
{ "sdivn",	two (0x07e0, 0x01c0),	two (0x07e0, 0x07c3), 	{I5DIV3, R1, R2, R3}, 	0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_EXTENSION },
{ "sdivun",	two (0x07e0, 0x01c2),	two (0x07e0, 0x07c3), 	{I5DIV3, R1, R2, R3}, 	0, PROCESSOR_NOT_V850 | PROCESSOR_OPTION_EXTENSION },

{ "set1",	two (0x07c0, 0x0000),	two (0xc7e0, 0x0000),	{B3, D16, R1}, 		3, PROCESSOR_ALL },
{ "set1",	two (0x07e0, 0x00e0),	two (0x07e0, 0xffff),	{R2, R1},    		3, PROCESSOR_NOT_V850 },

{ "setf",	two (0x07e0, 0x0000),	two (0x07f0, 0xffff), 	{CCCC, R2}, 		0, PROCESSOR_ALL },

{ "shl",	two (0x07e0, 0x00c2),	two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_V850E2_UP },
{ "shl",	OP  (0x16),		OP_MASK,	      	{I5U, R2}, 		0, PROCESSOR_ALL },
{ "shl",	two (0x07e0, 0x00c0),	two (0x07e0, 0xffff), 	{R1,  R2}, 		0, PROCESSOR_ALL },

{ "shr",	two (0x07e0, 0x0082),	two (0x07e0, 0x07ff), 	{R1, R2, R3}, 		0, PROCESSOR_V850E2_UP },
{ "shr",	OP  (0x14),		OP_MASK,	      	{I5U, R2}, 		0, PROCESSOR_ALL },
{ "shr",	two (0x07e0, 0x0080),	two (0x07e0, 0xffff), 	{R1,  R2}, 		0, PROCESSOR_ALL },

{ "sld.b",	one (0x0300),		one (0x0780),	      	{D7U,  EP,   R2},	2, PROCESSOR_ALL },

{ "sld.bu",     one (0x0060),		one (0x07f0),         	{D4U,  EP,   R2_NOTR0},	2, PROCESSOR_NOT_V850 },

{ "sld.h",	one (0x0400),		one (0x0780),	      	{D8_7U,EP,   R2}, 	2, PROCESSOR_ALL },

{ "sld.hu",     one (0x0070),		one (0x07f0),         	{D5_4U,EP,   R2_NOTR0},	2, PROCESSOR_NOT_V850 },

{ "sld.w",	one (0x0500),		one (0x0781),	      	{D8_6U,EP,   R2}, 	2, PROCESSOR_ALL },

{ "snooze",	two (0x0fe0, 0x0120),	two (0xffff, 0xffff),	{0},	 		0, PROCESSOR_V850E3V5_UP },

{ "sst.b",	one (0x0380),		one (0x0780),	      	{R2,   D7U,  EP}, 	3, PROCESSOR_ALL },

{ "sst.h",	one (0x0480),		one (0x0780),	      	{R2,   D8_7U,EP}, 	3, PROCESSOR_ALL },

{ "sst.w",	one (0x0501),		one (0x0781),	      	{R2,   D8_6U,EP}, 	3, PROCESSOR_ALL },

{ "stacch",	two (0x07e0, 0x0bca),	two (0x07ff, 0xffff),	{R2},			0, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_EXTENSION },
{ "staccl",	two (0x07e0, 0x0bc8),	two (0x07ff, 0xffff),	{R2},			0, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_EXTENSION },

{ "st.b",	two (0x0740, 0x0000),	two (0x07e0, 0x0000), 	{R2, D16, R1}, 		3, PROCESSOR_ALL },
{ "st.b",	two (0x0780, 0x000d),	two (0x07e0, 0x000f), 	{R3, D23, R1}, 		3, PROCESSOR_V850E2_UP },
{ "st.b23",	two (0x0780, 0x000d),	two (0x07e0, 0x000f), 	{R3, D23, R1}, 		3, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "st.dw",   	two (0x07a0, 0x000f), 	two (0xffe0, 0x001f), {R3_EVEN, D23_ALIGN1, R1}, 3, PROCESSOR_V850E3V5_UP },
{ "st.dw23", 	two (0x07a0, 0x000f), 	two (0xffe0, 0x001f), {R3_EVEN, D23_ALIGN1, R1}, 3, PROCESSOR_V850E3V5_UP | PROCESSOR_OPTION_ALIAS },

{ "st.h",	two (0x0760, 0x0000),	two (0x07e0, 0x0001), 	{R2, D16_15, R1}, 	3, PROCESSOR_ALL },
{ "st.h",	two (0x07a0, 0x000d),	two (0x07e0, 0x000f), 	{R3, D23_ALIGN1, R1}, 	3, PROCESSOR_V850E2_UP },
{ "st.h23",	two (0x07a0, 0x000d),	two (0x07e0, 0x000f), 	{R3, D23_ALIGN1, R1}, 	3, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "st.w",	two (0x0760, 0x0001),	two (0x07e0, 0x0001), 	{R2, D16_15, R1}, 	3, PROCESSOR_ALL },
{ "st.w",	two (0x0780, 0x000f),	two (0x07e0, 0x000f), 	{R3, D23_ALIGN1, R1}, 	3, PROCESSOR_V850E2_UP },
{ "st.w23",	two (0x0780, 0x000f),	two (0x07e0, 0x000f), 	{R3, D23_ALIGN1, R1}, 	3, PROCESSOR_V850E2_UP | PROCESSOR_OPTION_ALIAS },

{ "stc.w",	two (0x07e0, 0x037a),	two (0xffe0, 0x07ff),	{R3, R1},		2, PROCESSOR_V850E3V5_UP },

{ "stsr",	two (0x07e0, 0x0040),	two (0x07e0, 0x07ff),	{SR1, R2, SELID}, 	0, PROCESSOR_V850E3V5_UP },
{ "stsr",	two (0x07e0, 0x0040),	two (0x07e0, 0x07ff),	{SR1, R2}, 		0, PROCESSOR_V850E3V5_UP },
{ "stsr",	two (0x07e0, 0x0040),	two (0x07e0, 0x07ff),	{OLDSR1, R2}, 		0, (PROCESSOR_ALL & (~ PROCESSOR_V850E3V5_UP)) },

{ "sttc.gr",	two (0x07e0, 0x0052),	two (0x07e0, 0xffff),	{R1, R2}, 		0, PROCESSOR_V850E3V5_UP },
{ "sttc.sr",	two (0x07e0, 0x0050),	two (0x07e0, 0x07ff),	{SR1, R2, SELID}, 	0, PROCESSOR_V850E3V5_UP },
{ "sttc.sr",	two (0x07e0, 0x0050),	two (0x07e0, 0x07ff),	{SR1, R2},	 	0, PROCESSOR_V850E3V5_UP },
{ "sttc.vr",	two (0x07e0, 0x0852),	two (0x07e0, 0xffff),	{VR1, R2}, 		0, PROCESSOR_V850E3V5_UP },
{ "sttc.pc",	two (0x07e0, 0xf852),	two (0x07e0, 0xffff),	{R2}, 			0, PROCESSOR_V850E3V5_UP },

{ "stvc.sr",	two (0x07e0, 0x0054),	two (0x07e0, 0x07ff),	{SR1, R2, SELID}, 	0, PROCESSOR_V850E3V5_UP },
{ "stvc.sr",	two (0x07e0, 0x0054),	two (0x07e0, 0x07ff),	{SR1, R2},	 	0, PROCESSOR_V850E3V5_UP },

{ "sub",	OP  (0x0d),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },

{ "subr", 	OP  (0x0c),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },

{ "switch",	one (0x0040),		one (0xffe0), 	      	{R1_NOTR0}, 		0, PROCESSOR_NOT_V850 },

{ "sxb",	one (0x00a0),		one (0xffe0), 	      	{R1},			0, PROCESSOR_NOT_V850 },

{ "sxh",	one (0x00e0),		one (0xffe0),	      	{R1},			0, PROCESSOR_NOT_V850 },

{ "tlbai",	two (0x87e0, 0x8960),	two (0xffff, 0xffff),	{0},	 		0, PROCESSOR_V850E3V5_UP },
{ "tlbr",	two (0x87e0, 0xe960),	two (0xffff, 0xffff),	{0},	 		0, PROCESSOR_V850E3V5_UP },
{ "tlbs",	two (0x87e0, 0xc160),	two (0xffff, 0xffff),	{0},	 		0, PROCESSOR_V850E3V5_UP },
{ "tlbvi",	two (0x87e0, 0x8160),	two (0xffff, 0xffff),	{0},	 		0, PROCESSOR_V850E3V5_UP },
{ "tlbw",	two (0x87e0, 0xe160),	two (0xffff, 0xffff),	{0},	 		0, PROCESSOR_V850E3V5_UP },

{ "trap",	two (0x07e0, 0x0100),	two (0xffe0, 0xffff),	{I5U}, 			0, PROCESSOR_ALL },

{ "tst",	OP (0x0b),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },

{ "tst1",	two (0xc7c0, 0x0000),	two (0xc7e0, 0x0000),	{B3, D16, R1}, 		3, PROCESSOR_ALL },
{ "tst1",	two (0x07e0, 0x00e6),	two (0x07e0, 0xffff),	{R2, R1},    		3, PROCESSOR_NOT_V850 },

{ "xor",	OP (0x09),		OP_MASK,		IF1, 			0, PROCESSOR_ALL },

{ "xori",	OP (0x35),		OP_MASK,		IF6U, 			0, PROCESSOR_ALL },

{ "zxb",	one (0x0080),		one (0xffe0), 	      	{R1},			0, PROCESSOR_NOT_V850 },

{ "zxh",	one (0x00c0),		one (0xffe0), 	      	{R1},			0, PROCESSOR_NOT_V850 },

/* Floating point operation.  */
{ "absf.d",	two (0x07e0, 0x0458),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "absf.s",	two (0x07e0, 0x0448),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "addf.d",	two (0x07e0, 0x0470),	two (0x0fe1, 0x0fff),	{R1_EVEN, R2_EVEN, R3_EVEN},		0, PROCESSOR_V850E2V3_UP },
{ "addf.s",	two (0x07e0, 0x0460),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "ceilf.dl",	two (0x07e2, 0x0454),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "ceilf.dul",	two (0x07f2, 0x0454),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "ceilf.duw",	two (0x07f2, 0x0450),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "ceilf.dw",	two (0x07e2, 0x0450),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "ceilf.sl",	two (0x07e2, 0x0444),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "ceilf.sul",	two (0x07f2, 0x0444),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "ceilf.suw",	two (0x07f2, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "ceilf.sw",	two (0x07e2, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cmovf.d",	two (0x07e0, 0x0410),	two (0x0fe1, 0x0ff1),	{FFF, R1_EVEN, R2_EVEN, R3_EVEN_NOTR0},	0, PROCESSOR_V850E2V3_UP },
/* Default value for FFF is 0(not defined in spec).  */
{ "cmovf.d",	two (0x07e0, 0x0410),	two (0x0fe1, 0x0fff),	{R1_EVEN, R2_EVEN, R3_EVEN_NOTR0},	0, PROCESSOR_V850E2V3_UP },
{ "cmovf.s",	two (0x07e0, 0x0400),	two (0x07e0, 0x07f1),	{FFF, R1, R2, R3_NOTR0},		0, PROCESSOR_V850E2V3_UP },
/* Default value for FFF is 0(not defined in spec).  */
{ "cmovf.s",	two (0x07e0, 0x0400),	two (0x07e0, 0x07ff),	{R1, R2, R3_NOTR0},			0, PROCESSOR_V850E2V3_UP },
{ "cmpf.d",	two (0x07e0, 0x0430),	two (0x0fe1, 0x87f1),	{FLOAT_CCCC, R2_EVEN, R1_EVEN, FFF},	0, PROCESSOR_V850E2V3_UP },
{ "cmpf.d",	two (0x07e0, 0x0430),	two (0x0fe1, 0x87ff),	{FLOAT_CCCC, R2_EVEN, R1_EVEN},		0, PROCESSOR_V850E2V3_UP },
{ "cmpf.s",	two (0x07e0, 0x0420),	two (0x07e0, 0x87f1),	{FLOAT_CCCC, R2, R1, FFF},		0, PROCESSOR_V850E2V3_UP },
{ "cmpf.s",	two (0x07e0, 0x0420),	two (0x07e0, 0x87ff),	{FLOAT_CCCC, R2, R1},			0, PROCESSOR_V850E2V3_UP },
{ "cvtf.dl",	two (0x07e4, 0x0454),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "cvtf.ds",	two (0x07e3, 0x0452),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.dul",	two (0x07f4, 0x0454),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "cvtf.duw",	two (0x07f4, 0x0450),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.dw",	two (0x07e4, 0x0450),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.hs",	two (0x07e2, 0x0442),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E3V5_UP },
{ "cvtf.ld",	two (0x07e1, 0x0452),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "cvtf.ls",	two (0x07e1, 0x0442),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.sd",	two (0x07e2, 0x0452),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.sl",	two (0x07e4, 0x0444),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.sh",	two (0x07e3, 0x0442),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E3V5_UP },
{ "cvtf.sul",	two (0x07f4, 0x0444),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.suw",	two (0x07f4, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.sw",	two (0x07e4, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.uld",	two (0x07f1, 0x0452),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "cvtf.uls",	two (0x07f1, 0x0442),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.uwd",	two (0x07f0, 0x0452),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.uws",	two (0x07f0, 0x0442),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.wd",	two (0x07e0, 0x0452),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "cvtf.ws",	two (0x07e0, 0x0442),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "divf.d",	two (0x07e0, 0x047e),	two (0x0fe1, 0x0fff),	{R1_EVEN, R2_EVEN, R3_EVEN},		0, PROCESSOR_V850E2V3_UP },
{ "divf.s",	two (0x07e0, 0x046e),	two (0x07e0, 0x07ff),	{R1_NOTR0, R2, R3},			0, PROCESSOR_V850E2V3_UP },
{ "floorf.dl",	two (0x07e3, 0x0454),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "floorf.dul",	two (0x07f3, 0x0454),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "floorf.duw",	two (0x07f3, 0x0450),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "floorf.dw",	two (0x07e3, 0x0450),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "floorf.sl",	two (0x07e3, 0x0444),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "floorf.sul",	two (0x07f3, 0x0444),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "floorf.suw",	two (0x07f3, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "floorf.sw",	two (0x07e3, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "maddf.s",	two (0x07e0, 0x0500),	two (0x07e0, 0x0761),	{R1, R2, R3, R4},			0, PROCESSOR_V850E2V3 },
{ "fmaf.s",	two (0x07e0, 0x04e0),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E3V5_UP },
{ "maxf.d",	two (0x07e0, 0x0478),	two (0x0fe1, 0x0fff),	{R1_EVEN, R2_EVEN, R3_EVEN},		0, PROCESSOR_V850E2V3_UP },
{ "maxf.s",	two (0x07e0, 0x0468),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "minf.d",	two (0x07e0, 0x047a),	two (0x0fe1, 0x0fff),	{R1_EVEN, R2_EVEN, R3_EVEN},		0, PROCESSOR_V850E2V3_UP },
{ "minf.s",	two (0x07e0, 0x046a),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "msubf.s",	two (0x07e0, 0x0520),	two (0x07e0, 0x0761),	{R1, R2, R3, R4},			0, PROCESSOR_V850E2V3 },
{ "fmsf.s",	two (0x07e0, 0x04e2),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E3V5_UP },
{ "mulf.d",	two (0x07e0, 0x0474),	two (0x0fe1, 0x0fff),	{R1_EVEN, R2_EVEN, R3_EVEN},		0, PROCESSOR_V850E2V3_UP },
{ "mulf.s",	two (0x07e0, 0x0464),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "negf.d",	two (0x07e1, 0x0458),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "negf.s",	two (0x07e1, 0x0448),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "nmaddf.s",	two (0x07e0, 0x0540),	two (0x07e0, 0x0761),	{R1, R2, R3, R4},			0, PROCESSOR_V850E2V3 },
{ "fnmaf.s",	two (0x07e0, 0x04e4),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E3V5_UP },
{ "nmsubf.s",	two (0x07e0, 0x0560),	two (0x07e0, 0x0761),	{R1, R2, R3, R4},			0, PROCESSOR_V850E2V3 },
{ "fnmsf.s",	two (0x07e0, 0x04e6),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E3V5_UP },
{ "recipf.d",	two (0x07e1, 0x045e),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "recipf.s",	two (0x07e1, 0x044e),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },

{ "roundf.dl",	two (0x07e0, 0x0454),   two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_EXTENSION },
{ "roundf.dul",	two (0x07f0, 0x0454),   two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_EXTENSION },
{ "roundf.duw",	two (0x07f0, 0x0450),   two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_EXTENSION },
{ "roundf.dw",	two (0x07e0, 0x0450),   two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_EXTENSION },
{ "roundf.sl",	two (0x07e0, 0x0444),   two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_EXTENSION },
{ "roundf.sul",	two (0x07f0, 0x0444),   two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_EXTENSION },
{ "roundf.suw",	two (0x07f0, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_EXTENSION },
{ "roundf.sw",	two (0x07e0, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_EXTENSION },

{ "rsqrtf.d",	two (0x07e2, 0x045e),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "rsqrtf.s",	two (0x07e2, 0x044e),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "sqrtf.d",	two (0x07e0, 0x045e),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "sqrtf.s",	two (0x07e0, 0x044e),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "subf.d",	two (0x07e0, 0x0472),	two (0x0fe1, 0x0fff),	{R1_EVEN, R2_EVEN, R3_EVEN},		0, PROCESSOR_V850E2V3_UP },
{ "subf.s",	two (0x07e0, 0x0462),	two (0x07e0, 0x07ff),	{R1, R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "trfsr",	two (0x07e0, 0x0400),	two (0xffff, 0xfff1),	{FFF},					0, PROCESSOR_V850E2V3_UP },
{ "trfsr",	two (0x07e0, 0x0400),	two (0xffff, 0xffff),	{0},					0, PROCESSOR_V850E2V3_UP },
{ "trncf.dl",	two (0x07e1, 0x0454),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "trncf.dul",	two (0x07f1, 0x0454),	two (0x0fff, 0x0fff),	{R2_EVEN, R3_EVEN},			0, PROCESSOR_V850E2V3_UP },
{ "trncf.duw",	two (0x07f1, 0x0450),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "trncf.dw",	two (0x07e1, 0x0450),	two (0x0fff, 0x07ff),	{R2_EVEN, R3},				0, PROCESSOR_V850E2V3_UP },
{ "trncf.sl",	two (0x07e1, 0x0444),	two (0x07ff, 0x0fff),	{R2, R3_EVEN},				0, PROCESSOR_V850E2V3_UP },
{ "trncf.sul",	two (0x07f1, 0x0444),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "trncf.suw",	two (0x07f1, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },
{ "trncf.sw",	two (0x07e1, 0x0440),	two (0x07ff, 0x07ff),	{R2, R3},				0, PROCESSOR_V850E2V3_UP },

  /* Special instruction (from gdb) mov 1, r0.  */
{ "breakpoint",	one (0x0001),		one (0xffff),		{UNUSED},				0, PROCESSOR_ALL },

{ "synci",	one (0x001c),		one (0xffff),		{0},					0, PROCESSOR_V850E3V5_UP },

{ "synce",	one (0x001d),		one (0xffff),		{0},					0, PROCESSOR_V850E2V3_UP },
{ "syncm",	one (0x001e),		one (0xffff),		{0},					0, PROCESSOR_V850E2V3_UP },
{ "syncp",	one (0x001f),		one (0xffff),		{0},					0, PROCESSOR_V850E2V3_UP },
{ "syscall",	two (0xd7e0, 0x0160),	two (0xffe0, 0xc7ff),	{V8},					0, PROCESSOR_V850E2V3_UP },
  /* Alias of syncp.  */
{ "sync",	one (0x001f),		one (0xffff),		{0},					0, PROCESSOR_V850E2V3_UP | PROCESSOR_OPTION_ALIAS },
{ "rmtrap",	one (0xf040),		one (0xffff),		{0},					0, PROCESSOR_V850E2V3_UP },
{ "rie",	one (0x0040),		one (0xffff),		{0},					0, PROCESSOR_V850E2V3_UP },
{ "rie",	two (0x07f0, 0x0000),	two (0x07f0, 0xffff),	{RIE_IMM5,RIE_IMM4},			0, PROCESSOR_V850E2V3_UP },

{ 0, 0, 0, {0}, 0, 0 },
} ;

const int v850_num_opcodes =
  sizeof (v850_opcodes) / sizeof (v850_opcodes[0]);
