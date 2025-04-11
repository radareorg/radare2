/* TI C6X opcode table.
   Copyright (C) 2010-2025 Free Software Foundation, Inc.

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
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

/* Define the INSN macro before including this file; it takes as
   arguments the fields from tic6x_opcode (defined in tic6x.h).  The
   name is given as an identifier; the subsequent four operands should
   have "tic6x_func_unit_", "tic6x_insn_format_", "tic6x_pipeline_"
   and "TIC6X_INSN_", respectively, prepended to them by the macro
   definition.  Also define INSNE, which has a second argument that
   goes after tic6x_opcode_NAME_ to form the enumeration value for
   this instruction, where the value otherwise formed from the name,
   functional unit and format is ambiguous, but otherwise has the same
   arguments as INSN.  */

#define TIC6X_INSN_C64X_AND_C67X TIC6X_INSN_C64X|TIC6X_INSN_C67X
#define tic6x_insn_format_nfu_s_branch_nop_cst	\
  tic6x_insn_format_s_branch_nop_cst
#define tic6x_insn_format_s_l_1_or_2_src tic6x_insn_format_l_1_or_2_src
#define RAN(id, min, max) { CONCAT2(tic6x_field_,id), (min), (max) }
#define FIX(id, val) RAN(id, val, val)
#define FIX0() 0, { { 0, 0, 0 } }
#define FIX1(a) 1, { a }
#define FIX2(a, b) 2, { a, b }
#define FIX3(a, b, c) 3, { a, b, c }
#define FIX4(a, b, c, d) 4, { a, b, c, d }
#define OP0() 0, { { 0, 0, false, 0, 0, 0, 0 } }
#define OP1(a) 1, { a }
#define OP2(a, b) 2, { a, b }
#define OP3(a, b, c) 3, { a, b, c }
#define OP4(a, b, c, d) 4, { a, b, c, d }
#define OACST { tic6x_operand_asm_const, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OLCST { tic6x_operand_link_const, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OHWCSTM1 { tic6x_operand_hw_const_minus_1, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OHWCST0 { tic6x_operand_hw_const_0, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OHWCST1 { tic6x_operand_hw_const_1, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OHWCST5 { tic6x_operand_hw_const_5, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OHWCST16 { tic6x_operand_hw_const_16, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OHWCST24 { tic6x_operand_hw_const_24, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OHWCST31 { tic6x_operand_hw_const_31, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define OFULIST { tic6x_operand_func_unit, 0, tic6x_rw_none, 0, 0, 0, 0 }
#define ORIRP1 { tic6x_operand_irp, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define ORNRP1 { tic6x_operand_nrp, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define OWREG1 { tic6x_operand_reg, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define OWREG1Z { tic6x_operand_zreg, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define OWREG1NORS { tic6x_operand_reg_nors, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define ORREG1B { tic6x_operand_reg_bside, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define ORREG1BNORS { tic6x_operand_reg_bside_nors, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define OWRETREG1 { tic6x_operand_retreg, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define ORREG1 { tic6x_operand_reg, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define ORDREG1 { tic6x_operand_dreg, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define ORTREG1 { tic6x_operand_treg, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define ORWREG1 { tic6x_operand_reg, 4, tic6x_rw_read_write, 1, 1, 0, 0 }
#define ORB15REG1 { tic6x_operand_b15reg, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define OWB15REG1 { tic6x_operand_b15reg, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define ORAREG1 { tic6x_operand_areg, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define ORXREG1 { tic6x_operand_xreg, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define ORREG12 { tic6x_operand_reg, 4, tic6x_rw_read, 1, 2, 0, 0 }
#define ORREG14 { tic6x_operand_reg, 4, tic6x_rw_read, 1, 4, 0, 0 }
#define ORXREG14 { tic6x_operand_xreg, 4, tic6x_rw_read, 1, 4, 0, 0 }
#define OWREG2 { tic6x_operand_reg, 4, tic6x_rw_write, 2, 2, 0, 0 }
#define OWREG4 { tic6x_operand_reg, 4, tic6x_rw_write, 4, 4, 0, 0 }
#define OWREG9 { tic6x_operand_reg, 4, tic6x_rw_write, 9, 9, 0, 0 }
#define OWDREG5 { tic6x_operand_dreg, 4, tic6x_rw_write, 5, 5, 0, 0 }
#define OWTREG5 { tic6x_operand_treg, 4, tic6x_rw_write, 5, 5, 0, 0 }
#define OWREGL1 { tic6x_operand_regpair, 5, tic6x_rw_write, 1, 1, 1, 1 }
#define ORREGL1 { tic6x_operand_regpair, 5, tic6x_rw_read, 1, 1, 1, 1 }
#define OWREGD1 { tic6x_operand_regpair, 8, tic6x_rw_write, 1, 1, 1, 1 }
#define OWREGD12 { tic6x_operand_regpair, 8, tic6x_rw_write, 1, 1, 2, 2 }
#define OWREGD4 { tic6x_operand_regpair, 8, tic6x_rw_write, 4, 4, 4, 4 }
#define ORREGD1 { tic6x_operand_regpair, 8, tic6x_rw_read, 1, 1, 1, 1 }
#define OWREGD45 { tic6x_operand_regpair, 8, tic6x_rw_write, 4, 4, 5, 5 }
#define OWREGD67 { tic6x_operand_regpair, 8, tic6x_rw_write, 6, 6, 7, 7 }
#define ORDREGD1 { tic6x_operand_dregpair, 8, tic6x_rw_read, 1, 1, 1, 1 }
#define ORTREGD1 { tic6x_operand_tregpair, 8, tic6x_rw_read, 1, 1, 1, 1 }
#define OWDREGD5 { tic6x_operand_dregpair, 8, tic6x_rw_write, 5, 5, 5, 5 }
#define OWTREGD5 { tic6x_operand_tregpair, 8, tic6x_rw_write, 5, 5, 5, 5 }
#define ORREGD12 { tic6x_operand_regpair, 8, tic6x_rw_read, 1, 1, 2, 2 }
#define ORXREGD12 { tic6x_operand_xregpair, 8, tic6x_rw_read, 1, 1, 2, 2 }
#define ORREGD1234 { tic6x_operand_regpair, 8, tic6x_rw_read, 1, 2, 3, 4 }
#define ORXREGD1324 { tic6x_operand_xregpair, 8, tic6x_rw_read, 1, 3, 2, 4 }
#define OWREGD910 { tic6x_operand_regpair, 8, tic6x_rw_write, 9, 9, 10, 10 }
#define ORCREG1 { tic6x_operand_ctrl, 4, tic6x_rw_read, 1, 1, 0, 0 }
#define OWCREG1 { tic6x_operand_ctrl, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define OWILC1 { tic6x_operand_ilc, 4, tic6x_rw_write, 1, 1, 0, 0 }
#define ORMEMDW { tic6x_operand_mem_deref, 4, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMDW { tic6x_operand_mem_deref, 4, tic6x_rw_write, 3, 3, 0, 0 }
#define ORMEMSB { tic6x_operand_mem_short, 1, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMSB { tic6x_operand_mem_short, 1, tic6x_rw_write, 3, 3, 0, 0 }
#define ORMEMLB { tic6x_operand_mem_long, 1, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMLB { tic6x_operand_mem_long, 1, tic6x_rw_write, 3, 3, 0, 0 }
#define ORMEMSH { tic6x_operand_mem_short, 2, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMSH { tic6x_operand_mem_short, 2, tic6x_rw_write, 3, 3, 0, 0 }
#define ORMEMLH { tic6x_operand_mem_long, 2, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMLH { tic6x_operand_mem_long, 2, tic6x_rw_write, 3, 3, 0, 0 }
#define ORMEMSW { tic6x_operand_mem_short, 4, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMSW { tic6x_operand_mem_short, 4, tic6x_rw_write, 3, 3, 0, 0 }
#define ORMEMLW { tic6x_operand_mem_long, 4, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMLW { tic6x_operand_mem_long, 4, tic6x_rw_write, 3, 3, 0, 0 }
#define ORMEMSD { tic6x_operand_mem_short, 8, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMSD { tic6x_operand_mem_short, 8, tic6x_rw_write, 3, 3, 0, 0 }
#define ORMEMND { tic6x_operand_mem_ndw, 8, tic6x_rw_read, 3, 3, 0, 0 }
#define OWMEMND { tic6x_operand_mem_ndw, 8, tic6x_rw_write, 3, 3, 0, 0 }
#define ENC(id, meth, op) {			\
    CONCAT2(tic6x_field_,id),			\
    CONCAT2(tic6x_coding_,meth),		\
    op						\
  }
#define ENC0() 0, { { 0, 0, 0 } }
#define ENC1(a) 1, { a }
#define ENC2(a, b) 2, { a, b }
#define ENC3(a, b, c) 3, { a, b, c }
#define ENC4(a, b, c, d) 4, { a, b, c, d }
#define ENC5(a, b, c, d, e) 5, { a, b, c, d, e }
#define ENC6(a, b, c, d, e, f) 6, { a, b, c, d, e, f }
#define ENC7(a, b, c, d, e, f, g) 7, { a, b, c, d, e, f, g }

INSN(abs, l, unary, 1cycle, C62X, 0,
     FIX1(FIX(op, 0)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))
INSN(abs, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX3(FIX(op, 0x38), FIX(x, 0), FIX(src1, 0)),
     OP2(ORREGL1, OWREGL1),
     ENC3(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(dst, reg, 1)))

INSN(abs2, l, unary, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x4)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(absdp, s, 1_or_2_src, 2cycle_dp, C67X, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x2c), FIX(x, 0)),
     OP2(ORREGD1, OWREGD12),
     ENC4(ENC(s, fu, 0), ENC(src2, regpair_msb, 0), ENC(src1, regpair_lsb, 0),
	  ENC(dst, reg, 1)))

INSN(abssp, s, unary, 1cycle, C67X, 0,
     FIX1(FIX(op, 0)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSNE(add, l_si_xsi_si, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x3)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(add, l_si_xsi_sl, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x23)),
      OP3(ORREG1, ORXREG1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(add, l_xsi_sl_sl, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x21)),
      OP3(ORXREG1, ORREGL1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(add, l_s5_xsi_si, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x2)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(add, l_s5_sl_sl, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x20), FIX(x, 0)),
      OP3(OACST, ORREGL1, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src1, scst, 0), ENC(src2, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(add, s_si_xsi_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x7)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(add, s_s5_xsi_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x6)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(add, d_si_si_si, d, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x10)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(add, d_si_u5_si, d, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x12)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))
INSNE(add, d_si_xsi_si, d, ext_1_or_2_src, 1cycle, C64X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0xa)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(add, d_xsi_s5_si, d, ext_1_or_2_src, 1cycle, C64X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0xb)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, scst, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(add, l, l3_sat_0, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x0)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
          ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(add, l, l3i, 1cycle, C64XP, 0,
     FIX0(),
     OP3(OACST, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(cst, scst_l3i, 0),
          ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(add, l, lx1, 1cycle, C64XP,
     TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(op, 0x3)),
     OP3(OHWCSTM1, ORREG1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 1), ENC(srcdst, reg, 2)))
INSN(add, s, s3_sat_0, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x0)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
          ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(add, s, sx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x3)),
      OP3(OHWCSTM1, ORREG1, OWREG1),
      ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 1), ENC(srcdst, reg, 2)))
INSN(add, s, sx2op, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x0)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2),
           ENC(src2, reg, 1), ENC(x, xpath, 1)))
INSN(add, d, dx2op, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x0)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 1), ENC(srcdst, reg, 0),
          ENC(src2, reg, 1), ENC(srcdst, reg, 2)))
INSNU(add, l, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x5), FIX(unit, 0x0)),
     OP3(ORREG1, OHWCST1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2)))
INSNU(add, s, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x5), FIX(unit, 0x1)),
     OP3(ORREG1, OHWCST1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2)))
INSNU(add, d, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x5), FIX(unit, 0x2)),
     OP3(ORREG1, OHWCST1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2)))
/**/

INSNE(addab, d_si_si_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x30)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(addab, d_si_u5_si, d, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x32)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))
INSN(addab, d, adda_long, 1cycle, C64XP, TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 3)),
     OP3(ORAREG1, OLCST, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(y, areg, 0), ENC(offsetR, ulcst_dpr_byte, 1),
	  ENC(dst, reg, 2)))

INSNE(addad, d_si_si_si, d, 1_or_2_src, 1cycle, C64X_AND_C67X,
      TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x3c)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(addad, d_si_u5_si, d, 1_or_2_src, 1cycle, C64X_AND_C67X,
      TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x3d)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))

INSNE(addah, d_si_si_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x34)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(addah, d_si_u5_si, d, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x36)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))
INSN(addah, d, adda_long, 1cycle, C64XP, TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 5)),
     OP3(ORAREG1, OLCST, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(y, areg, 0), ENC(offsetR, ulcst_dpr_half, 1),
	  ENC(dst, reg, 2)))

INSNE(addaw, d_si_si_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x38)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(addaw, d_si_u5_si, d, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x3a)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))
INSN(addaw, d, adda_long, 1cycle, C64XP, TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 7)),
     OP3(ORAREG1, OLCST, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(y, areg, 0), ENC(offsetR, ulcst_dpr_word, 1),
	  ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(addaw, d, dx5, 1cycle, C64XP, TIC6X_FLAG_INSN16_BSIDE,
     FIX0(),
     OP3(ORB15REG1, OACST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, ucst, 1), ENC(dst, reg, 2)))
INSN(addaw, d, dx5p, 1cycle, C64XP, TIC6X_FLAG_INSN16_BSIDE,
     FIX1(FIX(op, 0)),
     OP3(ORB15REG1, OACST, OWB15REG1),
     ENC2(ENC(s, fu, 0), ENC(cst, ucst, 1)))
/**/

INSN(adddp, l, 1_or_2_src, addsubdp, C67X, 0,
     FIX1(FIX(op, 0x18)),
     OP3(ORREGD12, ORXREGD12, OWREGD67),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(adddp, s, l_1_or_2_src, addsubdp, C67XP, 0,
     FIX1(FIX(op, 0x72)),
     OP3(ORREGD12, ORXREGD12, OWREGD67),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(addk, s, addk, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX0(),
     OP2(OLCST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, scst, 0), ENC(dst, reg, 1)))

/* 16 bits insn */
INSN(addk, s, sx5, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX0(),
     OP2(OACST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(dst, reg, 1)))
/**/

INSN(addkpc, s, addkpc, 1cycle, C64X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP|TIC6X_FLAG_SIDE_B_ONLY,
     FIX1(FIX(s, 1)),
     OP3(OLCST, OWREG1, OACST),
     ENC3(ENC(src1, pcrel, 0), ENC(dst, reg, 1), ENC(src2, ucst, 2)))

INSN(addsp, l, 1_or_2_src, 4cycle, C67X, 0,
     FIX1(FIX(op, 0x10)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(addsp, s, l_1_or_2_src, 4cycle, C67XP, 0,
     FIX1(FIX(op, 0x70)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(addsub, l, 1_or_2_src_noncond, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0xc)),
     OP3(ORREG1, ORXREG1, OWREGD1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(addsub2, l, 1_or_2_src_noncond, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0xd)),
     OP3(ORREG1, ORXREG1, OWREGD1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(addu, l_ui_xui_ul, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x2b)),
      OP3(ORREG1, ORXREG1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(addu, l_xui_ul_ul, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x29)),
      OP3(ORXREG1, ORREGL1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(add2, s, 1_or_2_src, 1cycle, C62X, 0,
     FIX1(FIX(op, 0x1)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(add2, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x5)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(add2, d, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x4)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(add4, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x65)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(and, l_ui_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x7b)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(and, l_s5_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x7a)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(and, s_ui_xui_ui, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x1f)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(and, s_s5_xui_ui, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x1e)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(and, d_ui_xui_ui, d, ext_1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x6)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(and, d_s5_xui_ui, d, ext_1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x7)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(and, l, l2c, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0)),
      OP3(ORREG1, ORXREG1, OWREG1NORS),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(andn, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x7c)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(andn, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x6)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(andn, d, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x0)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(avg2, m, compound, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x13)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(avgu4, m, compound, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x12)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(b, s, ext_branch_cond_imm, branch, C62X, TIC6X_FLAG_NO_CROSS,
     FIX0(),
     OP1(OLCST),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel, 0)))
INSN(b, s, branch, branch, C62X, TIC6X_FLAG_SIDE_B_ONLY,
     FIX1(FIX(s, 1)),
     OP1(ORXREG1),
     ENC2(ENC(x, xpath, 0), ENC(src2, reg, 0)))
INSN(b, s, b_irp, branch, C62X, TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY,
     FIX3(FIX(s, 1), FIX(x, 0), FIX(dst, 0)),
     OP1(ORIRP1),
     ENC0())
INSN(b, s, b_nrp, branch, C62X, TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY,
     FIX3(FIX(s, 1), FIX(x, 0), FIX(dst, 0)),
     OP1(ORNRP1),
     ENC0())

INSN(bdec, s, bdec, branch, C64X, TIC6X_FLAG_NO_CROSS,
     FIX0(),
     OP2(OLCST, ORWREG1),
     ENC3(ENC(s, fu, 0), ENC(src, pcrel, 0), ENC(dst, reg, 1)))

INSN(bitc4, m, unary, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x1e)),
     OP2(ORXREG1, OWREG2),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(bitr, m, unary, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x1f)),
     OP2(ORXREG1, OWREG2),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(bnop, s, branch_nop_cst, branch, C64X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP,
     FIX0(),
     OP2(OLCST, OACST),
     ENC3(ENC(s, fu, 0), ENC(src2, pcrel_half, 0), ENC(src1, ucst, 1)))
INSN(bnop, nfu, s_branch_nop_cst, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_MCNOP,
     FIX1(FIX(s, 0)),
     OP2(OLCST, OACST),
     ENC2(ENC(src2, pcrel, 0), ENC(src1, ucst, 1)))
INSN(bnop, s, branch_nop_reg, branch, C64X,
     TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MCNOP,
     FIX1(FIX(s, 1)),
     OP2(ORXREG1, OACST),
     ENC3(ENC(x, xpath, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1)))

/* 16 bits insn format */
INSN(bnop, s, sbu8, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP,
     FIX0(),
     OP2(OLCST, OHWCST5),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel_half_unsigned, 0)))
INSN(bnop, s, sbs7, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP,
     FIX0(),
     OP2(OLCST, OACST),
     ENC3(ENC(s, fu, 0), ENC(cst, pcrel_half, 0), ENC(n, ucst, 1)))
INSN(bnop, s, sbu8c, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP|TIC6X_FLAG_INSN16_SPRED,
     FIX0(),
     OP2(OLCST, OHWCST5),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel_half_unsigned, 0)))
INSN(bnop, s, sbs7c, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP|TIC6X_FLAG_INSN16_SPRED,
     FIX0(),
     OP2(OLCST, OACST),
     ENC3(ENC(s, fu, 0), ENC(cst, pcrel_half, 0), ENC(n, ucst, 1)))
INSN(bnop, s, sx1b, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP,
     FIX0(),
     OP2(ORREG1BNORS, OACST),
     ENC3(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(n, ucst, 1)))
/**/

INSN(bpos, s, bpos, branch, C64X, TIC6X_FLAG_NO_CROSS,
     FIX0(),
     OP2(OLCST, ORREG1),
     ENC3(ENC(s, fu, 0), ENC(src, pcrel, 0), ENC(dst, reg, 1)))

INSN(call, s, ext_branch_cond_imm, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_CALL,
     FIX0(),
     OP1(OLCST),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel, 0)))
INSN(call, s, branch, branch, C62X,
     TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_CALL,
     FIX1(FIX(s, 1)),
     OP1(ORXREG1),
     ENC2(ENC(x, xpath, 0), ENC(src2, reg, 0)))
INSN(call, s, b_irp, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_CALL,
     FIX3(FIX(s, 1), FIX(x, 0), FIX(dst, 0)),
     OP1(ORIRP1),
     ENC0())
INSN(call, s, b_nrp, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_CALL,
     FIX3(FIX(s, 1), FIX(x, 0), FIX(dst, 0)),
     OP1(ORNRP1),
     ENC0())

INSN(callnop, s, branch_nop_cst, branch, C64X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_MCNOP|TIC6X_FLAG_CALL,
     FIX0(),
     OP2(OLCST, OACST),
     ENC3(ENC(s, fu, 0), ENC(src2, pcrel, 0), ENC(src1, ucst, 1)))
INSN(callnop, nfu, s_branch_nop_cst, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_MCNOP|TIC6X_FLAG_CALL,
     FIX1(FIX(s, 0)),
     OP2(OLCST, OACST),
     ENC2(ENC(src2, pcrel, 0), ENC(src1, ucst, 1)))
INSN(callnop, s, branch_nop_reg, branch, C64X,
     TIC6X_FLAG_MACRO|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MCNOP|TIC6X_FLAG_CALL,
     FIX1(FIX(s, 1)),
     OP2(ORXREG1, OACST),
     ENC3(ENC(x, xpath, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1)))


INSN(callp, s, call_imm_nop, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP,
     FIX1(FIX(z, 1)),
     OP2(OLCST, OWRETREG1),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel, 0)))

/* 16 bits insn format */
INSN(callp, s, scs10, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP,
     FIX0(),
     OP2(OLCST, OWRETREG1),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel, 0)))
/**/

INSN(callret, s, ext_branch_cond_imm, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_CALL|TIC6X_FLAG_RETURN,
     FIX0(),
     OP1(OLCST),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel, 0)))
INSN(callret, s, branch, branch, C62X,
     TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_CALL|TIC6X_FLAG_RETURN,
     FIX1(FIX(s, 1)),
     OP1(ORXREG1),
     ENC2(ENC(x, xpath, 0), ENC(src2, reg, 0)))
INSN(callret, s, b_irp, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_CALL|TIC6X_FLAG_RETURN,
     FIX3(FIX(s, 1), FIX(x, 0), FIX(dst, 0)),
     OP1(ORIRP1),
     ENC0())
INSN(callret, s, b_nrp, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_CALL|TIC6X_FLAG_RETURN,
     FIX3(FIX(s, 1), FIX(x, 0), FIX(dst, 0)),
     OP1(ORNRP1),
     ENC0())

INSN(clr, s, field, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(op, 0x3)),
     OP4(ORREG1, OACST, OACST, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(csta, ucst, 1),
	  ENC(cstb, ucst, 2), ENC(dst, reg, 3)))
INSN(clr, s, 1_or_2_src, 1cycle, C62X, 0,
     FIX1(FIX(op, 0x3f)),
     OP3(ORXREG1, ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(clr, s, sc5, 1cycle, C64XP, 0,
     FIX1(FIX(op, 2)),
     OP4(ORREG1, OACST, OACST, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(cst, ucst, 1),
          ENC(cst, ucst, 2), ENC(srcdst, reg, 3)))
/**/

INSNE(cmpeq, l_si_xsi_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x53)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpeq, l_s5_xsi_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x52)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpeq, l_xsi_sl_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x51)),
      OP3(ORXREG1, ORREGL1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpeq, l_s5_sl_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x50), FIX(x, 0)),
      OP3(OACST, ORREGL1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, scst, 0), ENC(src2, reg, 1),
	   ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(cmpeq, l, lx3c, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
      FIX0(),
      OP3(OACST, ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(src2, reg, 1),
           ENC(dst, reg, 2)))

INSN(cmpeq, l, l2c, 1cycle, C64XP, 0,
      FIX1(FIX(op, 3)),
      OP3(ORREG1, ORXREG1, OWREG1NORS),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(cmpeq2, s, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x1d)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmpeq4, s, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x1c)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmpeqdp, s, 1_or_2_src, dpcmp, C67X, 0,
     FIX1(FIX(op, 0x28)),
     OP3(ORREGD12, ORXREGD12, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmpeqsp, s, 1_or_2_src, 1cycle, C67X, 0,
     FIX1(FIX(op, 0x38)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(cmpgt, l_si_xsi_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x47)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpgt, l_s5_xsi_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x46)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpgt, l_xsi_sl_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x45)),
      OP3(ORXREG1, ORREGL1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpgt, l_s5_sl_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x44), FIX(x, 0)),
      OP3(OACST, ORREGL1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, scst, 0), ENC(src2, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(cmpgt, l_xsi_si_ui, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_MACRO|TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x57)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 1),
	   ENC(src2, reg, 0), ENC(dst, reg, 2)))
INSNE(cmpgt, l_xsi_s5_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX1(FIX(op, 0x56)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 1),
	   ENC(src2, reg, 0), ENC(dst, reg, 2)))
INSNE(cmpgt, l_sl_xsi_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX1(FIX(op, 0x55)),
      OP3(ORREGL1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 1),
	   ENC(src2, reg, 0), ENC(dst, reg, 2)))
INSNE(cmpgt, l_sl_s5_ui, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_MACRO|TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x54), FIX(x, 0)),
      OP3(ORREGL1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, scst, 1), ENC(src2, reg, 0),
	   ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(cmpgt, l, lx1c, 1cycle, C64XP, 0,
     FIX1(FIX(op, 1)),
     OP3(OACST, ORREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(src2, reg, 1),
          ENC(dst, reg, 2)))
INSN(cmpgt, l, l2c, 1cycle, C64XP, 0,
      FIX1(FIX(op, 5)),
      OP3(ORREG1, ORXREG1, OWREG1NORS),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(cmpgt2, s, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x14)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmpgtdp, s, 1_or_2_src, dpcmp, C67X, 0,
     FIX1(FIX(op, 0x29)),
     OP3(ORREGD12, ORXREGD12, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmpgtsp, s, 1_or_2_src, 1cycle, C67X, 0,
     FIX1(FIX(op, 0x39)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(cmpgtu, l_ui_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x4f)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpgtu, l_u4_xui_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX2(FIX(op, 0x4e), RAN(src1, 0, 15)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, ucst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
/* Although not mentioned in SPRUFE8, CMPGTU and CMPLTU support a
   5-bit unsigned constant operand on C64X and above.  */
INSNE(cmpgtu, l_u5_xui_ui, l, 1_or_2_src, 1cycle, C64X, 0,
      FIX2(FIX(op, 0x4e), RAN(src1, 16, 31)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, ucst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpgtu, l_xui_ul_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x4d)),
      OP3(ORXREG1, ORREGL1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpgtu, l_u4_ul_ui, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
      FIX3(FIX(op, 0x4c), FIX(x, 0), RAN(src1, 0, 15)),
      OP3(OACST, ORREGL1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, ucst, 0), ENC(src2, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(cmpgtu, l_u5_ul_ui, l, 1_or_2_src, 1cycle, C64X, TIC6X_FLAG_NO_CROSS,
      FIX3(FIX(op, 0x4c), FIX(x, 0), RAN(src1, 16, 31)),
      OP3(OACST, ORREGL1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, ucst, 0), ENC(src2, reg, 1),
	   ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(cmpgtu, l, lx1c, 1cycle, C64XP, 0,
     FIX1(FIX(op, 3)),
     OP3(OACST, ORREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(src2, reg, 1),
          ENC(dst, reg, 2)))
INSN(cmpgtu, l, l2c, 1cycle, C64XP, 0,
      FIX1(FIX(op, 7)),
      OP3(ORREG1, ORXREG1, OWREG1NORS),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(cmpgtu4, s, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x15)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(cmplt, l_si_xsi_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x57)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmplt, l_s5_xsi_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x56)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmplt, l_xsi_sl_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x55)),
      OP3(ORXREG1, ORREGL1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmplt, l_s5_sl_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x54), FIX(x, 0)),
      OP3(OACST, ORREGL1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, scst, 0), ENC(src2, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(cmplt, l_xsi_si_ui, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_MACRO|TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x47)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 1),
	   ENC(src2, reg, 0), ENC(dst, reg, 2)))
INSNE(cmplt, l_xsi_s5_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX1(FIX(op, 0x46)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 1),
	   ENC(src2, reg, 0), ENC(dst, reg, 2)))
INSNE(cmplt, l_sl_xsi_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX1(FIX(op, 0x45)),
      OP3(ORREGL1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 1),
	   ENC(src2, reg, 0), ENC(dst, reg, 2)))
INSNE(cmplt, l_sl_s5_ui, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_MACRO|TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x44), FIX(x, 0)),
      OP3(ORREGL1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, scst, 1), ENC(src2, reg, 0),
	   ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(cmplt, l, lx1c, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0)),
     OP3(OACST, ORREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(src2, reg, 1),
          ENC(dst, reg, 2)))
INSN(cmplt, l, l2c, 1cycle, C64XP, 0,
      FIX1(FIX(op, 4)),
      OP3(ORREG1, ORXREG1, OWREG1NORS),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(cmplt2, s, 1_or_2_src, 1cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x14)),
     OP3(ORXREG1, ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(cmpltdp, s, 1_or_2_src, dpcmp, C67X, 0,
     FIX1(FIX(op, 0x2a)),
     OP3(ORREGD12, ORXREGD12, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmpltsp, s, 1_or_2_src, 1cycle, C67X, 0,
     FIX1(FIX(op, 0x3a)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(cmpltu, l_ui_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x5f)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpltu, l_u4_xui_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX2(FIX(op, 0x5e), RAN(src1, 0, 15)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, ucst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpltu, l_u5_xui_ui, l, 1_or_2_src, 1cycle, C64X, 0,
      FIX2(FIX(op, 0x5e), RAN(src1, 16, 31)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, ucst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpltu, l_xui_ul_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x5d)),
      OP3(ORXREG1, ORREGL1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(cmpltu, l_u4_ul_ui, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
      FIX3(FIX(op, 0x5c), FIX(x, 0), RAN(src1, 0, 15)),
      OP3(OACST, ORREGL1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, ucst, 0), ENC(src2, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(cmpltu, l_u5_ul_ui, l, 1_or_2_src, 1cycle, C64X, TIC6X_FLAG_NO_CROSS,
      FIX3(FIX(op, 0x5c), FIX(x, 0), RAN(src1, 16, 31)),
      OP3(OACST, ORREGL1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, ucst, 0), ENC(src2, reg, 1),
	   ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(cmpltu, l, lx1c, 1cycle, C64XP, 0,
     FIX1(FIX(op, 2)),
     OP3(OACST, ORREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(src2, reg, 1),
          ENC(dst, reg, 2)))
INSN(cmpltu, l, l2c, 1cycle, C64XP, 0,
      FIX1(FIX(op, 6)),
      OP3(ORREG1, ORXREG1, OWREG1NORS),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(cmpltu4, s, 1_or_2_src, 1cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x15)),
     OP3(ORXREG1, ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(cmpy, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0xa)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmpyr, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0xb)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmpyr1, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0xc)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(cmtl, d, 1_or_2_src, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_SIDE_T2_ONLY|TIC6X_FLAG_NO_CROSS,
     FIX3(FIX(s, 1), FIX(op, 0xe), FIX(src1, 0)),
     OP2(ORMEMDW, OWDREG5),
     ENC2(ENC(src2, reg, 0), ENC(dst, reg, 1)))

INSN(ddotp4, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x18)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(ddotph2, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x17)),
     OP3(ORREGD1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(ddotph2r, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x15)),
     OP3(ORREGD1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(ddotpl2, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x16)),
     OP3(ORREGD1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(ddotpl2r, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x14)),
     OP3(ORREGD1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(deal, m, unary, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x1d)),
     OP2(ORXREG1, OWREG2),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(dint, nfu, dint, 1cycle, C64XP, 0,
     FIX1(FIX(s, 0)),
     OP0(),
     ENC0())

INSN(dmv, s, ext_1_or_2_src, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0xb)),
     OP3(ORREG1, ORXREG1, OWREGD1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(dotp2, m_s2_xs2_si, m, compound, 4cycle, C64X, 0,
      FIX1(FIX(op, 0xc)),
      OP3(ORREG1, ORXREG1, OWREG4),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(dotp2, m_s2_xs2_sll, m, compound, 4cycle, C64X, 0,
      FIX1(FIX(op, 0xb)),
      OP3(ORREG1, ORXREG1, OWREGD4),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(dotpn2, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x9)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(dotpnrsu2, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x7)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(dotpnrus2, m, compound, 4cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x7)),
     OP3(ORXREG1, ORREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(dotprsu2, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0xd)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(dotprus2, m, compound, 4cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0xd)),
     OP3(ORXREG1, ORREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(dotpsu4, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x2)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(dotpus4, m, compound, 4cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x2)),
     OP3(ORXREG1, ORREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(dotpu4, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x6)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(dpack2, l, 1_or_2_src_noncond, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x34)),
     OP3(ORREG1, ORXREG1, OWREGD1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(dpackx2, l, 1_or_2_src_noncond, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x33)),
     OP3(ORREG1, ORXREG1, OWREGD1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(dpint, l, 1_or_2_src, 4cycle, C67X, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x8), FIX(x, 0)),
     OP2(ORREGD1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(src2, regpair_msb, 0), ENC(src1, regpair_lsb, 0),
	  ENC(dst, reg, 1)))

INSN(dpsp, l, 1_or_2_src, 4cycle, C67X, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x9), FIX(x, 0)),
     OP2(ORREGD1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(src2, regpair_msb, 0), ENC(src1, regpair_lsb, 0),
	  ENC(dst, reg, 1)))

INSN(dptrunc, l, 1_or_2_src, 4cycle, C67X, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x1), FIX(x, 0)),
     OP2(ORREGD1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(src2, regpair_msb, 0), ENC(src1, regpair_lsb, 0),
	  ENC(dst, reg, 1)))

INSN(ext, s, field, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(op, 0x1)),
     OP4(ORREG1, OACST, OACST, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(csta, ucst, 1),
	  ENC(cstb, ucst, 2), ENC(dst, reg, 3)))
INSN(ext, s, 1_or_2_src, 1cycle, C62X, 0,
     FIX1(FIX(op, 0x2f)),
     OP3(ORXREG1, ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSNE(ext, hwcst16, s, s2ext, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x0)),
     OP4(ORREG1, OHWCST16, OHWCST16, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(src, reg, 0), ENC(dst, reg, 3)))
INSNE(ext, hwcst24, s, s2ext, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x1)),
     OP4(ORREG1, OHWCST24, OHWCST24, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(src, reg, 0), ENC(dst, reg, 3)))
/**/

INSN(extu, s, field, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(op, 0x0)),
     OP4(ORREG1, OACST, OACST, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(csta, ucst, 1),
	  ENC(cstb, ucst, 2), ENC(dst, reg, 3)))
INSN(extu, s, 1_or_2_src, 1cycle, C62X, 0,
     FIX1(FIX(op, 0x2b)),
     OP3(ORXREG1, ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSNE(extu, hwcst16, s, s2ext, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x2)),
     OP4(ORREG1, OHWCST16, OHWCST16, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(src, reg, 0), ENC(dst, reg, 3)))
INSNE(extu, hwcst24, s, s2ext, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x3)),
     OP4(ORREG1, OHWCST24, OHWCST24, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(src, reg, 0), ENC(dst, reg, 3)))
INSN(extu, s, sc5, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0)),
     OP4(ORREG1, OACST, OHWCST31, OWREG1Z),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(cst, ucst, 1)))
/**/

INSN(gmpy, m, 1_or_2_src, 4cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x1f), FIX(x, 0)),
     OP3(ORREG1, ORREG1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(src1, reg, 0), ENC(src2, reg, 1),
	  ENC(dst, reg, 2)))

/* This instruction can be predicated as usual; SPRUFE8 is incorrect
   where it shows the "z" field as fixed to 1.  */
INSN(gmpy4, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x11)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(idle, nfu, nop_idle, nop, C62X, TIC6X_FLAG_MCNOP,
     FIX2(FIX(s, 0), FIX(op, 0xf)),
     OP0(),
     ENC0())

INSN(intdp, l, 1_or_2_src, intdp, C67X, 0,
     FIX2(FIX(op, 0x39), FIX(src1, 0)),
     OP2(ORXREG1, OWREGD45),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(intdpu, l, 1_or_2_src, intdp, C67X, 0,
     FIX2(FIX(op, 0x3b), FIX(src1, 0)),
     OP2(ORXREG1, OWREGD45),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(intsp, l, 1_or_2_src, 4cycle, C67X, 0,
     FIX2(FIX(op, 0x4a), FIX(src1, 0)),
     OP2(ORXREG1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(intspu, l, 1_or_2_src, 4cycle, C67X, 0,
     FIX2(FIX(op, 0x49), FIX(src1, 0)),
     OP2(ORXREG1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(ldb, d, load_store, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
     FIX2(FIX(op, 2), FIX(r, 0)),
     OP2(ORMEMSB, OWDREG5),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 0),
	  ENC(offsetR, mem_offset, 0), ENC(baseR, reg, 0),
	  ENC(srcdst, reg, 1)))
INSN(ldb, d, load_store_long, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 2)),
     OP2(ORMEMLB, OWDREG5),
     ENC4(ENC(s, data_fu, 0), ENC(y, areg, 0), ENC(offsetR, ulcst_dpr_byte, 0),
	  ENC(dst, reg, 1)))

/* 16 bits insn */
INSN(ldb, d, doff4_dsz_x01, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSB, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset, 0)))
INSN(ldb, d, dind_dsz_x01, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSB, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(src1, mem_offset, 0)))
INSN(ldb, d, dinc_dsz_x01, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSB, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0),  ENC(cst, mem_offset_minus_one, 0)))
INSN(ldb, d, ddec_dsz_x01, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSB, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
/**/

INSN(ldbu, d, load_store, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
     FIX2(FIX(op, 1), FIX(r, 0)),
     OP2(ORMEMSB, OWDREG5),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 0),
	  ENC(offsetR, mem_offset, 0), ENC(baseR, reg, 0),
	  ENC(srcdst, reg, 1)))
INSN(ldbu, d, load_store_long, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 1)),
     OP2(ORMEMLB, OWDREG5),
     ENC4(ENC(s, data_fu, 0), ENC(y, areg, 0), ENC(offsetR, ulcst_dpr_byte, 0),
	  ENC(dst, reg, 1)))

/* 16 bits insn */
INSN(ldbu, d, dinc_dsz_000, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSB, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset_minus_one, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg, 1)))
INSN(ldbu, d, dind_dsz_000, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSB, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(src1, mem_offset, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg, 1)))
INSN(ldbu, d, doff4_dsz_000, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSB, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg, 1)))
INSN(ldbu, d, ddec_dsz_000, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSB, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset_minus_one, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg, 1)))
/**/

INSN(lddw, d, load_store, load, C64X_AND_C67X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 6), FIX(r, 1)),
     OP2(ORMEMSD, OWDREGD5),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 0),
	  ENC(offsetR, mem_offset, 0), ENC(baseR, reg, 0),
	  ENC(srcdst, reg, 1)))

/* 16 bits insn */
INSN(lddw, d, dpp, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREINCR)|TIC6X_FLAG_INSN16_B15PTR|TIC6X_FLAG_INSN16_NORS,
     FIX2(FIX(op, 1), FIX(dw, 1)),
     OP2(ORMEMSD, OWDREGD5),
     ENC4(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
	  ENC(cst, mem_offset_minus_one, 0)))
INSN(lddw, d, ddecdw, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX3(FIX(op, 1), FIX(na, 0), FIX(sz, 0)),
     OP2(ORMEMSD, OWTREGD5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg_shift, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(lddw, d, dincdw, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX3(FIX(op, 1), FIX(na, 0), FIX(sz, 0)),
     OP2(ORMEMSD, OWTREGD5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg_shift, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(lddw, d, dinddw, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX3(FIX(op, 1), FIX(na, 0), FIX(sz, 0)),
     OP2(ORMEMSD, OWTREGD5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(src1, mem_offset, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg_shift, 1)))
INSN(lddw, d, doff4dw, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX3(FIX(op, 1), FIX(na, 0), FIX(sz, 0)),
     OP2(ORMEMSD, OWTREGD5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg_shift, 1)))
/**/

INSN(ldh, d, load_store, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
     FIX2(FIX(op, 4), FIX(r, 0)),
     OP2(ORMEMSH, OWDREG5),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 0),
	  ENC(offsetR, mem_offset, 0), ENC(baseR, reg, 0),
	  ENC(srcdst, reg, 1)))
INSN(ldh, d, load_store_long, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 4)),
     OP2(ORMEMLH, OWDREG5),
     ENC4(ENC(s, data_fu, 0), ENC(y, areg, 0), ENC(offsetR, ulcst_dpr_half, 0),
	  ENC(dst, reg, 1)))

/* 16 bits insn */
INSN(ldh, d, doff4_dsz_x11, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSH, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg, 1)))
INSN(ldh, d, dind_dsz_x11, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSH, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(src1, mem_offset, 0)))
INSN(ldh, d, dinc_dsz_x11, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSH, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(ldh, d, ddec_dsz_x11, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSH, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
/**/

INSN(ldhu, d, load_store, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
     FIX2(FIX(op, 0), FIX(r, 0)),
     OP2(ORMEMSH, OWDREG5),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 0),
	  ENC(offsetR, mem_offset, 0), ENC(baseR, reg, 0),
	  ENC(srcdst, reg, 1)))
INSN(ldhu, d, load_store_long, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 0)),
     OP2(ORMEMLH, OWDREG5),
     ENC4(ENC(s, data_fu, 0), ENC(y, areg, 0), ENC(offsetR, ulcst_dpr_half, 0),
	  ENC(dst, reg, 1)))

/* 16 bits insn */
INSN(ldhu, d, doff4_dsz_010, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSH, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg, 1)))
INSN(ldhu, d, dind_dsz_010, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSH, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(src1, mem_offset, 0)))
INSN(ldhu, d, dinc_dsz_010, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSH, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(ldhu, d, ddec_dsz_010, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSH, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
/**/

INSN(ldndw, d, load_nonaligned, load, C64X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED,
     FIX0(),
     OP2(ORMEMND, OWDREGD5),
     ENC7(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 0),
	  ENC(offsetR, mem_offset_noscale, 0), ENC(baseR, reg, 0),
	  ENC(sc, scaled, 0), ENC(dst, reg_shift, 1)))

/* 16 bits insn */
INSN(ldndw, d, ddecdw, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX3(FIX(op, 1), FIX(na, 1), FIX(sz, 0)),
     OP2(ORMEMND, OWTREGD5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg_shift, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one_noscale, 0)))
INSN(ldndw, d, dincdw, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX3(FIX(op, 1), FIX(na, 1), FIX(sz, 0)),
     OP2(ORMEMND, OWTREGD5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg_shift, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one_noscale, 0)))
INSN(ldndw, d, dinddw, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX3(FIX(op, 1), FIX(na, 1), FIX(sz, 0)),
     OP2(ORMEMND, OWTREGD5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(src1, mem_offset_noscale, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg_shift, 1)))
INSN(ldndw, d, doff4dw, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX3(FIX(op, 1), FIX(na, 1), FIX(sz, 0)),
     OP2(ORMEMND, OWTREGD5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset_noscale, 0),
          ENC(ptr, reg_ptr, 0), ENC(srcdst, reg_shift, 1)))
/**/

INSN(ldnw, d, load_store, load, C64X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED,
     FIX2(FIX(op, 3), FIX(r, 1)),
     OP2(ORMEMSW, OWDREG5),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 0),
	  ENC(offsetR, mem_offset, 0), ENC(baseR, reg, 0),
	  ENC(srcdst, reg, 1)))

/* 16 bits insn */
INSN(ldnw, d, doff4_dsz_110, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset, 0)))
INSN(ldnw, d, dind_dsz_110, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(src1, mem_offset, 0)))
INSN(ldnw, d, dinc_dsz_110, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(ldnw, d, ddec_dsz_110, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
/**/

INSN(ldw, d, load_store, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
     FIX2(FIX(op, 6), FIX(r, 0)),
     OP2(ORMEMSW, OWDREG5),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 0),
	  ENC(offsetR, mem_offset, 0), ENC(baseR, reg, 0),
	  ENC(srcdst, reg, 1)))
INSN(ldw, d, load_store_long, load, C62X,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 6)),
     OP2(ORMEMLW, OWDREG5),
     ENC4(ENC(s, data_fu, 0), ENC(y, areg, 0), ENC(offsetR, ulcst_dpr_word, 0),
	  ENC(dst, reg, 1)))

/* 16 bits insn */
INSN(ldw, d, doff4_dsz_0xx, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 0)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset, 0)))
INSN(ldw, d, doff4_dsz_100, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset, 0)))
INSN(ldw, d, dind_dsz_0xx, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 0)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(src1, mem_offset, 0)))
INSN(ldw, d, dind_dsz_100, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(src1, mem_offset, 0)))
INSN(ldw, d, dinc_dsz_0xx, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 1), FIX(sz, 0)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(ldw, d, dinc_dsz_100, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(ldw, d, ddec_dsz_0xx, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 1), FIX(sz, 0)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(ldw, d, ddec_dsz_100, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 1), FIX(sz, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
          ENC(ptr, reg_ptr, 0), ENC(cst, mem_offset_minus_one, 0)))
INSN(ldw, d, dpp, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREINCR)|TIC6X_FLAG_INSN16_B15PTR|TIC6X_FLAG_INSN16_NORS,
     FIX2(FIX(op, 1), FIX(dw, 0)),
     OP2(ORMEMSW, OWTREG5),
     ENC4(ENC(s, fu, 0), ENC(t, rside, 0),  ENC(srcdst, reg, 1),
	  ENC(cst, mem_offset_minus_one, 0)))
INSN(ldw, d, dstk, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE)|TIC6X_FLAG_INSN16_B15PTR,
     FIX2(FIX(op, 0x1), FIX(s, 1)),
     OP2(ORMEMSW, OWTREG5),
     ENC4(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 1),
	  ENC(cst, mem_offset, 0)))
/**/

INSN(ll, d, 1_or_2_src, load, C64XP,
     TIC6X_FLAG_LOAD|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_SIDE_T2_ONLY|TIC6X_FLAG_NO_CROSS,
     FIX3(FIX(s, 1), FIX(op, 0xc), FIX(src1, 0)),
     OP2(ORMEMDW, OWDREG5),
     ENC2(ENC(src2, reg, 0), ENC(dst, reg, 1)))

INSNE(lmbd, l_ui_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x6b)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(lmbd, l_s5_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x6a)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(max2, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x42)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(max2, s, ext_1_or_2_src, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0xd)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(maxu4, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x43)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(min2, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x41)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(min2, s, ext_1_or_2_src, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0xc)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(minu4, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x48)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(mpy, m_sl16_xsl16_si, m, mpy, 1616_m, C62X, 0,
      FIX1(FIX(op, 0x19)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(mpy, m_s5_xsl16_si, m, mpy, 1616_m, C62X, 0,
      FIX1(FIX(op, 0x18)),
      OP3(OACST, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16-bit insn.  */
INSN(mpy, m, m3_sat_0, 1616_m, C67X, 0,
      FIX1(FIX(op, 0x0)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg_shift, 2)))

INSN(mpydp, m, mpy, mpydp, C67X, 0,
     FIX1(FIX(op, 0x0e)),
     OP3(ORREGD1234, ORXREGD1324, OWREGD910),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyh, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x01)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(mpyh, m, m3_sat_0, 1616_m, C67X, 0,
      FIX1(FIX(op, 0x1)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg_shift, 2)))
/**/ 

INSN(mpyhi, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x14)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyhir, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x10)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyhl, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x09)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(mpyhl, m, m3_sat_0, 1616_m, C67X, 0,
      FIX1(FIX(op, 0x3)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg_shift, 2)))
/**/ 

INSN(mpyhlu, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x0f)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyhslu, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x0b)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyhsu, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x03)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyhu, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x07)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyhuls, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x0d)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyhus, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x05)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(mpyi, m_si_xsi_si, m, mpy, mpyi, C67X, 0,
      FIX1(FIX(op, 0x04)),
      OP3(ORREG14, ORXREG14, OWREG9),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(mpyi, m_s5_xsi_si, m, mpy, mpyi, C67X, 0,
      FIX1(FIX(op, 0x06)),
      OP3(OACST, ORXREG14, OWREG9),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(mpyid, m_si_xsi_sll, m, mpy, mpyid, C67X, 0,
      FIX1(FIX(op, 0x08)),
      OP3(ORREG14, ORXREG14, OWREGD910),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(mpyid, m_s5_xsi_sll, m, mpy, mpyid, C67X, 0,
      FIX1(FIX(op, 0x0c)),
      OP3(OACST, ORXREG14, OWREGD910),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyih, m, compound, 4cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x14)),
     OP3(ORXREG1, ORREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(mpyihr, m, compound, 4cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x10)),
     OP3(ORXREG1, ORREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(mpyil, m, compound, 4cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x15)),
     OP3(ORXREG1, ORREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(mpyilr, m, compound, 4cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x0e)),
     OP3(ORXREG1, ORREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(mpylh, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x11)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(mpylh, m, m3_sat_0, 1616_m, C67X, 0,
      FIX1(FIX(op, 0x2)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg_shift, 2)))
/**/ 

INSN(mpylhu, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x17)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyli, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x15)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpylir, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x0e)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpylshu, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x13)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyluhs, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x15)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpysp, m, mpy, 4cycle, C67X, 0,
     FIX1(FIX(op, 0x1c)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* Contrary to SPRU733A, MPYSPDP and MPYSP2DP are on both C67X and
   C67X+.  */
INSN(mpyspdp, m, compound, mpyspdp, C67X, 0,
     FIX1(FIX(op, 0x16)),
     OP3(ORREG12, ORXREGD12, OWREGD67),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpysp2dp, m, compound, mpyspdp, C67X, 0,
     FIX1(FIX(op, 0x17)),
     OP3(ORREG1, ORXREG1, OWREGD45),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(mpysu, m_sl16_xul16_si, m, mpy, 1616_m, C62X, 0,
      FIX1(FIX(op, 0x1b)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(mpysu, m_s5_xul16_si, m, mpy, 1616_m, C62X, 0,
      FIX1(FIX(op, 0x1e)),
      OP3(OACST, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpysu4, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x05)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyu, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x1f)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyu4, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x04)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyus, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x1d)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpyus4, m, compound, 4cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x05)),
     OP3(ORXREG1, ORREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(mpy2, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x00)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpy2ir, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x0f)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(mpy32, 32_32_32, m, mpy, 4cycle, C64XP, 0,
      FIX1(FIX(op, 0x10)),
      OP3(ORREG1, ORXREG1, OWREG4),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(mpy32, 32_32_64, m, mpy, 4cycle, C64XP, 0,
      FIX1(FIX(op, 0x14)),
      OP3(ORREG1, ORXREG1, OWREGD4),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpy32su, m, mpy, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x16)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpy32u, m, compound, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x18)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(mpy32us, m, compound, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x19)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* "or" forms of "mv" are preferred over "add" forms when available
   because "or" uses less power.  However, 40-bit moves are only
   available through "add", and before C64X D-unit moves are only
   available through "add" (without cross paths being available).  */
INSNE(mv, l_xui_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX2(FIX(op, 0x7e), FIX(src1, 0)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(dst, reg, 1)))
INSNE(mv, l_sl_sl, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO,
      FIX3(FIX(op, 0x20), FIX(x, 0), FIX(src1, 0)),
      OP2(ORREGL1, OWREGL1),
      ENC3(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(dst, reg, 1)))
INSNE(mv, s_xui_ui, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX2(FIX(op, 0x1a), FIX(src1, 0)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(dst, reg, 1)))
INSNE(mv, d_si_si, d, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_MACRO|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(0),
      FIX2(FIX(op, 0x12), FIX(src1, 0)),
      OP2(ORREG1, OWREG1),
      ENC3(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(dst, reg, 1)))
INSNE(mv, d_xui_ui, d, ext_1_or_2_src, 1cycle, C64X,
      TIC6X_FLAG_MACRO|TIC6X_FLAG_PREFER(1),
      FIX2(FIX(op, 0x3), FIX(src1, 0)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(dst, reg, 1)))

/* 16 bits insn */
INSNU(mv, l, lsdmvto, 1cycle, C64X, 0,
      FIX1(FIX(unit, 0x0)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(x, xpath, 0), ENC(dst, reg, 1)))

INSNU(mv, s, lsdmvto, 1cycle, C64X, 0,
      FIX1(FIX(unit, 0x1)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(x, xpath, 0), ENC(dst, reg, 1)))

INSNU(mv, d, lsdmvto, 1cycle, C64X, 0,
      FIX1(FIX(unit, 0x2)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(x, xpath, 0), ENC(dst, reg, 1)))

INSNU(mv, l, lsdmvfr, 1cycle, C64X, 0,
      FIX1(FIX(unit, 0x0)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(x, xpath, 0), ENC(dst, reg, 1)))

INSNU(mv, s, lsdmvfr, 1cycle, C64X, 0,
      FIX1(FIX(unit, 0x1)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(x, xpath, 0), ENC(dst, reg, 1)))

INSNU(mv, d, lsdmvfr, 1cycle, C64X, 0,
      FIX1(FIX(unit, 0x2)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(x, xpath, 0), ENC(dst, reg, 1)))
/**/

INSNE(mvc, from_cr, s, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_NO_CROSS,
      FIX3(FIX(s, 1), FIX(op, 0x0f), FIX(x, 0)),
      OP2(ORCREG1, OWREG1),
      ENC3(ENC(src1, crhi, 0), ENC(src2, crlo, 0), ENC(dst, reg, 1)))
INSNE(mvc, to_cr, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_SIDE_B_ONLY,
      FIX2(FIX(s, 1), FIX(op, 0x0e)),
      OP2(ORXREG1, OWCREG1),
      ENC4(ENC(x, xpath, 0), ENC(src2, reg, 0), ENC(src1, crhi, 1),
	   ENC(dst, crlo, 1)))

/* 16 bits insn */
INSN(mvc, s, sx1, 1cycle, C64XP,
      TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x6)),
      OP2(ORREG1B, OWILC1),
      ENC2(ENC(s, fu, 0), ENC(srcdst, reg, 0)))
/**/

INSN(mvd, m, unary, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x1a)),
     OP2(ORXREG1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(mvk, s, mvk, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(h, 0)),
     OP2(OLCST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, scst, 0), ENC(dst, reg, 1)))
INSN(mvk, l, unary, 1cycle, C64X, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(x, 0), FIX(op, 0x05)),
     OP2(OACST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(src2, scst, 0), ENC(dst, reg, 1)))
INSN(mvk, d, 1_or_2_src, 1cycle, C64X, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x00), FIX(src2, 0)),
     OP2(OACST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(src1, scst, 0), ENC(dst, reg, 1)))

/* 16 bits insn */
INSN(mvk, l, lx5, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX0(),
     OP2(OLCST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, scst, 0), ENC(dst, reg, 1)))
INSN(mvk, s, smvk8, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX0(),
     OP2(OLCST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(dst, reg, 1)))
INSNU(mvk, l, lsdx1c, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_SPRED,
     FIX1(FIX(unit, 0x0)),
     OP2(OACST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(dst, reg, 1)))
INSNU(mvk, s, lsdx1c, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_SPRED,
     FIX1(FIX(unit, 0x1)),
     OP2(OACST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(dst, reg, 1)))
INSNU(mvk, d, lsdx1c, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_SPRED,
     FIX1(FIX(unit, 0x2)),
     OP2(OACST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, ucst, 0), ENC(dst, reg, 1)))
INSNUE(mvk, zero, l, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0), FIX(unit, 0x0)),
     OP2(OHWCST0, OWREG1),
     ENC2(ENC(s, fu, 0), ENC(srcdst, reg, 1)))
INSNUE(mvk, zero, s, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0), FIX(unit, 0x1)),
     OP2(OHWCST0, OWREG1),
     ENC2(ENC(s, fu, 0), ENC(srcdst, reg, 1)))
INSNUE(mvk, zero, d, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0), FIX(unit, 0x2)),
     OP2(OHWCST0, OWREG1),
     ENC2(ENC(s, fu, 0), ENC(srcdst, reg, 1)))
INSNUE(mvk, one, l, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 1), FIX(unit, 0x0)),
     OP2(OHWCST1, OWREG1),
     ENC2(ENC(s, fu, 0), ENC(srcdst, reg, 1)))
INSNUE(mvk, one, s, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 1), FIX(unit, 0x1)),
     OP2(OHWCST1, OWREG1),
     ENC2(ENC(s, fu, 0), ENC(srcdst, reg, 1)))
INSNUE(mvk, one, d, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 1), FIX(unit, 0x2)),
     OP2(OHWCST1, OWREG1),
     ENC2(ENC(s, fu, 0), ENC(srcdst, reg, 1)))
/**/

INSN(mvkh, s, mvk, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(h, 1)),
     OP2(OLCST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, lcst_high16, 0), ENC(dst, reg, 1)))

INSN(mvklh, s, mvk, 1cycle, C62X, TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO,
     FIX1(FIX(h, 1)),
     OP2(OLCST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, lcst_low16, 0), ENC(dst, reg, 1)))

INSN(mvkl, s, mvk, 1cycle, C62X, TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO,
     FIX1(FIX(h, 0)),
     OP2(OLCST, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(cst, lcst_low16, 0), ENC(dst, reg, 1)))

INSNE(neg, s_xsi_si, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX2(FIX(op, 0x16), FIX(src1, 0)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(dst, reg, 1)))
INSNE(neg, l_xsi_si, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX2(FIX(op, 0x06), FIX(src1, 0)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(dst, reg, 1)))
INSNE(neg, l_sl_sl, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO,
      FIX2(FIX(op, 0x24), FIX(src1, 0)),
      OP2(ORREGL1, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(dst, reg, 1)))

INSN(nop, nfu, nop_idle, nop, C62X, 0,
     FIX2(FIX(s, 0), RAN(op, 0, 8)),
     OP1(OACST),
     ENC1(ENC(op, ucst_minus_one, 0)))
INSNE(nop, 1, nfu, nop_idle, nop, C62X, TIC6X_FLAG_MACRO,
      FIX2(FIX(s, 0), FIX(op, 0)),
      OP0(),
      ENC0())

/* 16 bits insn */
/* contrary to sprufe8b.pdf p767, and accordingly to
 * dis6x.exe output, unop3 opcode is decoded as NOP N3 + 1 */
INSN(nop, nfu, unop, nop, C64XP, 0,
     FIX0(),
     OP1(OACST),
     ENC1(ENC(n, ucst_minus_one, 0)))
/**/

INSNE(norm, l_xsi_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX2(FIX(op, 0x63), FIX(src1, 0)),
      OP2(ORXREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(dst, reg, 1)))
INSNE(norm, l_sl_ui, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX3(FIX(op, 0x60), FIX(x, 0), FIX(src1, 0)),
      OP2(ORREGL1, OWREG1),
      ENC3(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(dst, reg, 1)))

INSN(not, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
     FIX2(FIX(op, 0x6e), FIX(src1, 0x1f)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))
INSN(not, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
     FIX2(FIX(op, 0x0a), FIX(src1, 0x1f)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))
INSN(not, d, ext_1_or_2_src, 1cycle, C64X, TIC6X_FLAG_MACRO,
     FIX2(FIX(op, 0xf), FIX(src1, 0x1f)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSNE(or, d_ui_xui_ui, d, ext_1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x2)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(or, d_s5_xui_ui, d, ext_1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x3)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(or, l_ui_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x7f)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(or, l_s5_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x7e)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(or, s_ui_xui_ui, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x1b)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(or, s_s5_xui_ui, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x1a)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(or, l, l2c, 1cycle, C64XP, 0,
      FIX1(FIX(op, 1)),
      OP3(ORREG1, ORXREG1, OWREG1NORS),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(pack2, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x0)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(pack2, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0xf)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(packh2, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x1e)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(packh2, s, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x9)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(packh4, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x69)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(packhl2, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x1c)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(packhl2, s, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x8)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(packlh2, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x1b)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(packlh2, s, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x10)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(packl4, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x68)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(rcpdp, s, 1_or_2_src, 2cycle_dp, C67X, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x2d), FIX(x, 0)),
     OP2(ORREGD1, OWREGD12),
     ENC4(ENC(s, fu, 0), ENC(src2, regpair_msb, 0), ENC(src1, regpair_lsb, 0),
	  ENC(dst, reg, 1)))

INSN(rcpsp, s, 1_or_2_src, 1cycle, C67X, 0,
     FIX2(FIX(op, 0x3d), FIX(src1, 0)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(ret, s, ext_branch_cond_imm, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_RETURN,
     FIX0(),
     OP1(OLCST),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel, 0)))
INSN(ret, s, branch, branch, C62X,
     TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_RETURN,
     FIX1(FIX(s, 1)),
     OP1(ORXREG1),
     ENC2(ENC(x, xpath, 0), ENC(src2, reg, 0)))
INSN(ret, s, b_irp, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_RETURN,
     FIX3(FIX(s, 1), FIX(x, 0), FIX(dst, 0)),
     OP1(ORIRP1),
     ENC0())
INSN(ret, s, b_nrp, branch, C62X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_MACRO|TIC6X_FLAG_RETURN,
     FIX3(FIX(s, 1), FIX(x, 0), FIX(dst, 0)),
     OP1(ORNRP1),
     ENC0())

INSN(retp, s, call_imm_nop, branch, C64XP,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MCNOP|TIC6X_FLAG_MACRO|TIC6X_FLAG_RETURN,
     FIX1(FIX(z, 1)),
     OP2(OLCST, OWRETREG1),
     ENC2(ENC(s, fu, 0), ENC(cst, pcrel, 0)))

INSN(rint, nfu, rint, 1cycle, C64XP, 0,
     FIX1(FIX(s, 0)),
     OP0(),
     ENC0())

INSNE(rotl, m_ui_xui_ui, m, compound, 1616_m, C64X, 0,
      FIX1(FIX(op, 0x1d)),
      OP3(ORXREG1, ORREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(rotl, m_u5_xui_ui, m, compound, 1616_m, C64X, 0,
      FIX1(FIX(op, 0x1e)),
      OP3(ORXREG1, OACST, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, ucst, 1), ENC(dst, reg, 2)))

INSN(rpack2, s, ext_1_or_2_src_noncond, 1cycle, C64XP, 0,
     FIX2(FIX(op, 0xb), FIX(z, 1)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(rsqrdp, s, 1_or_2_src, 2cycle_dp, C67X, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x2e), FIX(x, 0)),
     OP2(ORREGD1, OWREGD12),
     ENC4(ENC(s, fu, 0), ENC(src2, regpair_msb, 0), ENC(src1, regpair_lsb, 0),
	  ENC(dst, reg, 1)))

INSN(rsqrsp, s, 1_or_2_src, 1cycle, C67X, 0,
     FIX2(FIX(op, 0x3e), FIX(src1, 0)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSNE(sadd, l_si_xsi_si, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x13)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sadd, l_xsi_sl_sl, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x31)),
      OP3(ORXREG1, ORREGL1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sadd, l_s5_xsi_si, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x12)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sadd, l_s5_sl_sl, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x30)),
      OP3(OACST, ORREGL1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sadd, s_si_xsi_si, s, 1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x20)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(sadd, l, l3_sat_1, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
          ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(sadd, s, s3_sat_1, 1cycle, C64XP,0,
     FIX1(FIX(op, 0x0)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
          ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(sadd2, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x0)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(saddsub, l, 1_or_2_src_noncond, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x0e)),
     OP3(ORREG1, ORXREG1, OWREGD1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(saddsub2, l, 1_or_2_src_noncond, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x0f)),
     OP3(ORREG1, ORXREG1, OWREGD1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(saddsu2, s, ext_1_or_2_src, 1cycle, C64X, TIC6X_FLAG_MACRO,
     FIX1(FIX(op, 0x1)),
     OP3(ORXREG1, ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSN(saddus2, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x1)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(saddu4, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x3)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(sat, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX3(FIX(op, 0x40), FIX(x, 0), FIX(src1, 0)),
     OP2(ORREGL1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(dst, reg, 1)))

INSN(set, s, field, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(op, 0x2)),
     OP4(ORREG1, OACST, OACST, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(csta, ucst, 1),
	  ENC(cstb, ucst, 2), ENC(dst, reg, 3)))
INSN(set, s, 1_or_2_src, 1cycle, C62X, 0,
     FIX1(FIX(op, 0x3b)),
     OP3(ORXREG1, ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(set, s, sc5, 1cycle, C64XP, 0,
     FIX1(FIX(op, 1)),
     OP4(ORREG1, OACST, OACST, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(cst, ucst, 1),
          ENC(cst, ucst, 2), ENC(srcdst, reg, 3)))
/**/

INSN(shfl, m, unary, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x1c)),
     OP2(ORXREG1, OWREG2),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(shfl3, l, 1_or_2_src_noncond, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x36)),
     OP3(ORREG1, ORXREG1, OWREGD1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(shl, s_xsi_ui_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x33)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(shl, s_sl_ui_sl, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x31), FIX(x, 0)),
      OP3(ORREGL1, ORREG1, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(shl, s_xui_ui_ul, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x13)),
      OP3(ORXREG1, ORREG1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(shl, s_xsi_u5_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x32)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, ucst, 1), ENC(dst, reg, 2)))
INSNE(shl, s_sl_u5_sl, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x30), FIX(x, 0)),
      OP3(ORREGL1, OACST, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))
INSNE(shl, s_xui_u5_ul, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x12)),
      OP3(ORXREG1, OACST, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, ucst, 1), ENC(dst, reg, 2)))

/* 16bit insn */
INSN(shl, s, s3i, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x0)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
           ENC(cst, cst_s3i, 1), ENC(dst, reg, 2)))
INSN(shl, s, ssh5_sat_x, 1cycle, C64XP,
      TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x0)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(srcdst, reg, 0),
           ENC(cst, ucst, 1),  ENC(srcdst, reg, 2)))
INSN(shl, s, s2sh, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x0)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(src1, reg, 1),
           ENC(srcdst, reg, 2)))
/**/

INSN(shlmb, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x61)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(shlmb, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x9)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(shr, s_xsi_ui_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x37)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(shr, s_sl_ui_sl, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x35), FIX(x, 0)),
      OP3(ORREGL1, ORREG1, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(shr, s_xsi_u5_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x36)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, ucst, 1), ENC(dst, reg, 2)))
INSNE(shr, s_sl_u5_sl, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x34), FIX(x, 0)),
      OP3(ORREGL1, OACST, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))

/* 16bit insn */
INSN(shr, s, s3i, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x1)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
           ENC(cst, cst_s3i, 1), ENC(dst, reg, 2)))
INSN(shr, s, ssh5_sat_x, 1cycle, C64XP,
      TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x1)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(srcdst, reg, 0),
           ENC(cst, ucst, 1),  ENC(srcdst, reg, 2)))
INSN(shr, s, s2sh, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x1)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(src1, reg, 1),
           ENC(srcdst, reg, 2)))
/**/

INSNE(shr2, s_xs2_ui_s2, s, ext_1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x7)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(shr2, s_xs2_u5_s2, s, 1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x18)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, ucst, 1), ENC(dst, reg, 2)))

INSN(shrmb, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x62)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(shrmb, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0xa)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(shru, s_xui_ui_ui, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x27)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(shru, s_ul_ui_ul, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x25), FIX(x, 0)),
      OP3(ORREGL1, ORREG1, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(shru, s_xui_u5_ui, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x26)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, ucst, 1), ENC(dst, reg, 2)))
INSNE(shru, s_ul_u5_ul, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x24), FIX(x, 0)),
      OP3(ORREGL1, OACST, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(shru, s, ssh5_sat_0, 1cycle, C64XP,
      TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x2)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(srcdst, reg, 0),
           ENC(cst, ucst, 1),  ENC(srcdst, reg, 2)))
INSN(shru, s, s2sh, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x2)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(src1, reg, 1),
           ENC(srcdst, reg, 2)))
/**/

INSNE(shru2, s_xu2_ui_u2, s, ext_1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x8)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(shru2, s_xu2_u5_u2, s, 1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0x19)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, ucst, 1), ENC(dst, reg, 2)))

INSN(sl, d, 1_or_2_src, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_SIDE_T2_ONLY|TIC6X_FLAG_NO_CROSS,
     FIX3(FIX(s, 1), FIX(op, 0xd), FIX(src1, 0)),
     OP2(ORDREG1, OWMEMDW),
     ENC2(ENC(dst, reg, 0), ENC(src2, reg, 1)))

INSN(smpy, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x1a)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(smpy, m, m3_sat_1, 1616_m, C67X, 0,
      FIX1(FIX(op, 0x0)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg_shift, 2)))
/**/ 

INSN(smpyh, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x02)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(smpyh, m, m3_sat_1, 1616_m, C67X, 0,
      FIX1(FIX(op, 0x1)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg_shift, 2)))
/**/ 

INSN(smpyhl, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x0a)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(smpyhl, m, m3_sat_1, 1616_m, C67X, 0,
      FIX1(FIX(op, 0x3)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg_shift, 2)))
/**/ 

INSN(smpylh, m, mpy, 1616_m, C62X, 0,
     FIX1(FIX(op, 0x12)),
     OP3(ORREG1, ORXREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(smpylh, m, m3_sat_1, 1616_m, C67X, 0,
      FIX1(FIX(op, 0x2)),
      OP3(ORREG1, ORXREG1, OWREG2),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg_shift, 2)))
/**/ 

INSN(smpy2, m, compound, 4cycle, C64X, 0,
     FIX1(FIX(op, 0x01)),
     OP3(ORREG1, ORXREG1, OWREGD4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* Contrary to SPRUFE8, this is the correct operand order for this
   instruction.  */
INSN(smpy32, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x19)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(spack2, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x2)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(spacku4, s, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x4)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(spdp, s, 1_or_2_src, 2cycle_dp, C67X, 0,
     FIX2(FIX(op, 0x02), FIX(src1, 0)),
     OP2(ORXREG1, OWREGD12),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(spint, l, 1_or_2_src, 4cycle, C67X, 0,
     FIX2(FIX(op, 0x0a), FIX(src1, 0)),
     OP2(ORXREG1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSNE(spkernel, nfu_2, nfu, spkernel, 1cycle, C64XP,
      TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPKERNEL,
      FIX1(FIX(s, 0)),
      OP2(OACST, OACST),
      ENC2(ENC(fstgfcyc, fstg, 0), ENC(fstgfcyc, fcyc, 1)))
INSNE(spkernel, nfu_0, nfu, spkernel, 1cycle, C64XP,
      TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPKERNEL|TIC6X_FLAG_MACRO,
      FIX2(FIX(s, 0), FIX(fstgfcyc, 0)),
      OP0(),
      ENC0())

/* 16 bits insn */
INSN(spkernel, nfu, uspk, 1cycle, C64XP,
      TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPKERNEL,
      FIX0(),
      OP2(OACST, OACST),
      ENC2(ENC(fstgfcyc, fstg, 0), ENC(fstgfcyc, fcyc, 1)))
/**/

INSN(spkernelr, nfu, spkernelr, 1cycle, C64XP,
     TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPKERNEL,
     FIX1(FIX(s, 0)),
     OP0(),
     ENC0())

INSN(sploop, nfu, loop_buffer, 1cycle, C64XP,
     TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPLOOP,
     FIX4(FIX(s, 0), FIX(op, 0xc), FIX(csta, 0), RAN(cstb, 0, 13)),
     OP1(OACST),
     ENC1(ENC(cstb, ucst_minus_one, 0)))

INSN(sploopd, nfu, loop_buffer, 1cycle, C64XP,
     TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPLOOP,
     FIX4(FIX(s, 0), FIX(op, 0xd), FIX(csta, 0), RAN(cstb, 0, 13)),
     OP1(OACST),
     ENC1(ENC(cstb, ucst_minus_one, 0)))

INSN(sploopw, nfu, loop_buffer, 1cycle, C64XP,
     TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPLOOP,
     FIX4(FIX(s, 0), FIX(op, 0xf), FIX(csta, 0), RAN(cstb, 0, 13)),
     OP1(OACST),
     ENC1(ENC(cstb, ucst_minus_one, 0)))

/* 16 bits insn */
INSN(sploop, nfu, uspl, 1cycle, C64XP,
     TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPLOOP,
     FIX1(FIX(op, 0)),
     OP1(OACST),
     ENC1(ENC(ii, ucst_minus_one, 0)))

INSN(sploopd, nfu, uspl, 1cycle, C64XP,
     TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPLOOP,
     FIX1(FIX(op, 1)),
     OP1(OACST),
     ENC1(ENC(ii, ucst_minus_one, 0)))

INSN(sploopd, nfu, uspldr, 1cycle, C64XP,
     TIC6X_FLAG_FIRST|TIC6X_FLAG_NO_MCNOP|TIC6X_FLAG_SPLOOP|TIC6X_FLAG_INSN16_SPRED,
     FIX0(),
     OP1(OACST),
     ENC1(ENC(ii, ucst_minus_one, 0)))
/**/


/* Contrary to SPRUFE8, this is the correct encoding for this
   instruction.  */
INSN(spmask, nfu, spmask, 1cycle, C64XP, TIC6X_FLAG_FIRST|TIC6X_FLAG_SPMASK,
     FIX2(FIX(s, 0), FIX(op, 0x8)),
     OP1(OFULIST),
     ENC1(ENC(mask, spmask, 0)))

/* 16 bits insn */
INSN(spmask, nfu, uspma, 1cycle, C64XP, TIC6X_FLAG_FIRST|TIC6X_FLAG_SPMASK,
     FIX0(),
     OP1(OFULIST),
     ENC1(ENC(mask, spmask, 0)))
/**/

INSN(spmaskr, nfu, spmask, 1cycle, C64XP, TIC6X_FLAG_FIRST|TIC6X_FLAG_SPMASK,
     FIX2(FIX(s, 0), FIX(op, 0x9)),
     OP1(OFULIST),
     ENC1(ENC(mask, spmask, 0)))

/* 16 bits insn */
INSN(spmaskr, nfu, uspmb, 1cycle, C64XP, TIC6X_FLAG_FIRST|TIC6X_FLAG_SPMASK,
     FIX0(),
     OP1(OFULIST),
     ENC1(ENC(mask, spmask, 0)))
/**/

INSN(sptrunc, l, 1_or_2_src, 4cycle, C67X, 0,
     FIX2(FIX(op, 0x0b), FIX(src1, 0)),
     OP2(ORXREG1, OWREG4),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSNE(sshl, s_xsi_ui_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x23)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(sshl, s_xsi_u5_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x22)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, ucst, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(sshl, s, ssh5_sat_1, 1cycle, C64XP,
      TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x2)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(srcdst, reg, 0),
           ENC(cst, ucst, 1),  ENC(srcdst, reg, 2)))
INSN(sshl, s, s2sh, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x3)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(src1, reg, 1),
           ENC(srcdst, reg, 2)))
/**/

INSN(sshvl, m, compound, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x1c)),
     OP3(ORXREG1, ORREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

/* Contrary to SPRUFE8, this is the correct encoding for this
   instruction.  */
INSN(sshvr, m, compound, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x1a)),
     OP3(ORXREG1, ORREG1, OWREG2),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSNE(ssub, l_si_xsi_si, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x0f)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(ssub, l_xsi_si_si, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x1f)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(ssub, l_s5_xsi_si, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x0e)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(ssub, l_s5_sl_sl, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x2c)),
      OP3(OACST, ORREGL1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(ssub, l, l3_sat_1, 1cycle, C64XP, 0,
     FIX1(FIX(op, 1)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
          ENC(src2, reg, 1), ENC(dst, reg, 2)))
/**/

INSN(ssub2, l, 1_or_2_src, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x64)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(stb, d, load_store, store, C62X,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
     FIX2(FIX(op, 3), FIX(r, 0)),
     OP2(ORDREG1, OWMEMSB),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 1),
	  ENC(offsetR, mem_offset, 1), ENC(baseR, reg, 1),
	  ENC(srcdst, reg, 0)))
INSN(stb, d, load_store_long, store, C62X,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 3)),
     OP2(ORDREG1, OWMEMLB),
     ENC4(ENC(s, data_fu, 0), ENC(y, areg, 1), ENC(offsetR, ulcst_dpr_byte, 1),
	  ENC(dst, reg, 0)))

/* 16 bits insn */
INSN(stb, d, doff4_dsz_000, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSB),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset, 1)))
INSN(stb, d, doff4_dsz_x01, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSB),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset, 1)))
INSN(stb, d, dind_dsz_000, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSB),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(src1, mem_offset, 1),
          ENC(ptr, reg_ptr, 1), ENC(srcdst, reg, 0)))
INSN(stb, d, dind_dsz_x01, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSB),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(src1, mem_offset, 1),
          ENC(ptr, reg_ptr, 1), ENC(srcdst, reg, 0)))
INSN(stb, d, dinc_dsz_000, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSB),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stb, d, dinc_dsz_x01, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSB),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stb, d, ddec_dsz_000, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSB),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stb, d, ddec_dsz_x01, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSB),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
/**/

INSN(stdw, d, load_store, store, C64X, TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 4), FIX(r, 1)),
     OP2(ORDREGD1, OWMEMSD),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 1),
	  ENC(offsetR, mem_offset, 1), ENC(baseR, reg, 1),
	  ENC(srcdst, reg, 0)))

/* 16 bits insn */
INSN(stdw, d, dpp, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTDECR)|TIC6X_FLAG_INSN16_B15PTR|TIC6X_FLAG_INSN16_NORS,
     FIX3(FIX(op, 0), FIX(dw, 1), FIX(s, 1)),
     OP2(ORTREGD1, OWMEMSD),
     ENC4(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
	  ENC(cst, mem_offset_minus_one, 1)))
INSN(stdw, d, ddecdw, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX3(FIX(op, 0), FIX(na, 0), FIX(sz, 0)),
     OP2(ORTREGD1, OWMEMSD),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg_shift, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stdw, d, dincdw, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX3(FIX(op, 0), FIX(na, 0), FIX(sz, 0)),
     OP2(ORTREGD1, OWMEMSD),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg_shift, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stdw, d, dinddw, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX3(FIX(op, 0), FIX(na, 0), FIX(sz, 0)),
     OP2(ORTREGD1, OWMEMSD),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(src1, mem_offset, 1),
          ENC(ptr, reg_ptr, 1), ENC(srcdst, reg_shift, 0)))
INSN(stdw, d, doff4dw, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX3(FIX(op, 0), FIX(na, 0), FIX(sz, 0)),
     OP2(ORTREGD1, OWMEMSD),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset, 1),
          ENC(ptr, reg_ptr, 1), ENC(srcdst, reg_shift, 0)))
/**/

INSN(sth, d, load_store, store, C62X,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
     FIX2(FIX(op, 5), FIX(r, 0)),
     OP2(ORDREG1, OWMEMSH),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 1),
	  ENC(offsetR, mem_offset, 1), ENC(baseR, reg, 1),
	  ENC(srcdst, reg, 0)))
INSN(sth, d, load_store_long, store, C62X,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 5)),
     OP2(ORDREG1, OWMEMLH),
     ENC4(ENC(s, data_fu, 0), ENC(y, areg, 1), ENC(offsetR, ulcst_dpr_half, 1),
	  ENC(dst, reg, 0)))

/* 16 bits insn */
INSN(sth, d, doff4_dsz_01x, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSH),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset, 1)))
INSN(sth, d, doff4_dsz_111, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSH),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset, 1)))
INSN(sth, d, dind_dsz_01x, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSH),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(src1, mem_offset, 1)))
INSN(sth, d, dind_dsz_111, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSH),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(src1, mem_offset, 1)))
INSN(sth, d, dinc_dsz_01x, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSH),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(sth, d, dinc_dsz_111, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSH),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(sth, d, ddec_dsz_01x, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSH),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(sth, d, ddec_dsz_111, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSH),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
/**/

INSN(stndw, d, store_nonaligned, store, C64X,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED,
     FIX0(),
     OP2(ORDREGD1, OWMEMND),
     ENC7(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 1),
	  ENC(offsetR, mem_offset_noscale, 1), ENC(baseR, reg, 1),
	  ENC(sc, scaled, 1), ENC(src, reg_shift, 0)))

/* 16 bits insn */
INSN(stndw, d, ddecdw, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX3(FIX(op, 0), FIX(na, 1), FIX(sz, 0)),
     OP2(ORTREGD1, OWMEMND),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg_shift, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one_noscale, 1)))
INSN(stndw, d, dincdw, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX3(FIX(op, 0), FIX(na, 1), FIX(sz, 0)),
     OP2(ORTREGD1, OWMEMND),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg_shift, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one_noscale, 1)))
INSN(stndw, d, dinddw, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX3(FIX(op, 0), FIX(na, 1), FIX(sz, 0)),
     OP2(ORTREGD1, OWMEMND),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(src1, mem_offset_noscale, 1),
          ENC(ptr, reg_ptr, 1), ENC(srcdst, reg_shift, 0)))
INSN(stndw, d, doff4dw, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX3(FIX(op, 0), FIX(na, 1), FIX(sz, 0)),
     OP2(ORTREGD1, OWMEMND),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(cst, mem_offset_noscale, 1),
          ENC(ptr, reg_ptr, 1), ENC(srcdst, reg_shift, 0)))
/**/

INSN(stnw, d, load_store, store, C64X,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_UNALIGNED,
     FIX2(FIX(op, 5), FIX(r, 1)),
     OP2(ORDREG1, OWMEMSW),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 1),
	  ENC(offsetR, mem_offset, 1), ENC(baseR, reg, 1),
	  ENC(srcdst, reg, 0)))

/* 16 bits insn */
INSN(stnw, d, doff4_dsz_110, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset, 1)))
INSN(stnw, d, dind_dsz_110, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(src1, mem_offset, 1)))
INSN(stnw, d, dinc_dsz_110, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stnw, d, ddec_dsz_110, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
/**/

INSN(stw, d, load_store, store, C62X,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
     FIX2(FIX(op, 7), FIX(r, 0)),
     OP2(ORDREG1, OWMEMSW),
     ENC6(ENC(s, data_fu, 0), ENC(y, fu, 0), ENC(mode, mem_mode, 1),
	  ENC(offsetR, mem_offset, 1), ENC(baseR, reg, 1),
	  ENC(srcdst, reg, 0)))
INSN(stw, d, load_store_long, store, C62X,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_SIDE_B_ONLY|TIC6X_FLAG_PREFER(0),
     FIX1(FIX(op, 7)),
     OP2(ORDREG1, OWMEMLW),
     ENC4(ENC(s, data_fu, 0), ENC(y, areg, 1), ENC(offsetR, ulcst_dpr_word, 1),
	  ENC(dst, reg, 0)))

/* 16 bits insn */
INSN(stw, d, doff4_dsz_0xx, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 0)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset, 1)))
INSN(stw, d, doff4_dsz_100, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset, 1)))
INSN(stw, d, dind_dsz_0xx, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 0)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(src1, mem_offset, 1)))
INSN(stw, d, dind_dsz_100, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(REG_POSITIVE),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(src1, mem_offset, 1)))
INSN(stw, d, dinc_dsz_0xx, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 0), FIX(sz, 0)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stw, d, dinc_dsz_100, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTINCR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stw, d, ddec_dsz_0xx, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 0), FIX(sz, 0)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stw, d, ddec_dsz_100, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(PREDECR),
     FIX2(FIX(op, 0), FIX(sz, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC5(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
          ENC(ptr, reg_ptr, 1), ENC(cst, mem_offset_minus_one, 1)))
INSN(stw, d, dpp, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSTDECR)|TIC6X_FLAG_INSN16_B15PTR|TIC6X_FLAG_INSN16_NORS,
     FIX2(FIX(op, 0), FIX(dw, 0)),
     OP2(ORTREG1, OWMEMSW),
     ENC4(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
	  ENC(cst, mem_offset_minus_one, 1)))
INSN(stw, d, dstk, store, C64XP,
     TIC6X_FLAG_STORE|TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_INSN16_MEM_MODE(POSITIVE)|TIC6X_FLAG_INSN16_B15PTR,
     FIX2(FIX(op, 0x0), FIX(s, 1)),
     OP2(ORTREG1, OWMEMSW),
     ENC4(ENC(s, fu, 0), ENC(t, rside, 0), ENC(srcdst, reg, 0),
	  ENC(cst, mem_offset, 1)))
/**/

INSNE(sub, l_si_xsi_si, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x07)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sub, l_xsi_si_si, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x17)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sub, l_si_xsi_sl, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x27)),
      OP3(ORREG1, ORXREG1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sub, l_xsi_si_sl, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x37)),
      OP3(ORXREG1, ORREG1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sub, l_s5_xsi_si, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x06)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sub, l_s5_sl_sl, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x24)),
      OP3(OACST, ORREGL1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sub, l_xsi_s5_si, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX1(FIX(op, 0x2)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst_negate, 1),
	   ENC(src2, reg, 0), ENC(dst, reg, 2)))
INSNE(sub, l_sl_s5_sl, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_MACRO|TIC6X_FLAG_NO_CROSS,
      FIX2(FIX(op, 0x20), FIX(x, 0)),
      OP3(ORREGL1, OACST, OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src1, scst_negate, 1), ENC(src2, reg, 0),
	   ENC(dst, reg, 2)))
INSNE(sub, s_si_xsi_si, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x17)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(sub, s_s5_xsi_si, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x16)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
/* Contrary to SPRUFE8, this is the correct encoding for this
   instruction; this instruction can be predicated.  */
INSNE(sub, s_xsi_si_si, s, ext_1_or_2_src, 1cycle, C64X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x5)),
      OP3(ORXREG1, ORREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))
INSNE(sub, s_xsi_s5_si, s, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_MACRO,
      FIX1(FIX(op, 0x6)),
      OP3(ORXREG1, OACST, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst_negate, 1),
	   ENC(src2, reg, 0), ENC(dst, reg, 2)))
INSNE(sub, d_si_si_si, d, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x11)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(sub, d_si_u5_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x13)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))
INSNE(sub, d_si_xsi_si, d, ext_1_or_2_src, 1cycle, C64X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0xc)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(sub, l, l3_sat_0, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x1)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
          ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(sub, l, lx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(op, 0x2)),
     OP3(OHWCST0, ORREG1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 1), ENC(srcdst, reg, 2)))
INSN(sub, s, sx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x2)),
      OP3(OHWCST0, ORREG1, OWREG1),
      ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 1), ENC(srcdst, reg, 2)))
INSN(sub, s, sx2op, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x1)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2),
           ENC(src2, reg, 1), ENC(x, xpath, 1)))
INSN(sub, s, s3_sat_x, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x1)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
          ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(sub, d, dx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX1(FIX(op, 0x3)),
     OP3(ORREG1, OHWCST1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2)))
INSN(sub, d, dx2op, 1cycle, C64XP, 0,
     FIX1(FIX(op, 0x1)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(srcdst, reg, 0),
          ENC(src2, reg, 1), ENC(srcdst, reg, 2)))
/**/

INSNE(subab, d_si_si_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x31)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(subab, d_si_u5_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x33)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))

INSN(subabs4, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x5a)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(subah, d_si_si_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x35)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(subah, d_si_u5_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x37)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))

INSNE(subaw, d_si_si_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x39)),
      OP3(ORREG1, ORREG1, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, reg, 1),
	   ENC(dst, reg, 2)))
INSNE(subaw, d_si_u5_si, d, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_NO_CROSS,
      FIX1(FIX(op, 0x3b)),
      OP3(ORREG1, OACST, OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg, 0), ENC(src1, ucst, 1),
	   ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(subaw, d, dx5p, 1cycle, C64XP, 0,
     FIX1(FIX(op, 1)),
     OP3(ORB15REG1, OACST, OWB15REG1),
     ENC2(ENC(s, fu, 0), ENC(cst, ucst, 1)))
/**/

INSN(subc, l, 1_or_2_src, 1cycle, C62X, 0,
     FIX1(FIX(op, 0x4b)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSNE(subdp, l_dp_xdp_dp, l, 1_or_2_src, addsubdp, C67X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x19)),
      OP3(ORREGD12, ORXREGD12, OWREGD67),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(subdp, l_xdp_dp_dp, l, 1_or_2_src, addsubdp, C67X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x1d)),
      OP3(ORXREGD12, ORREGD12, OWREGD67),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(subdp, s_dp_xdp_dp, s, l_1_or_2_src, addsubdp, C67XP,
      TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x73)),
      OP3(ORREGD12, ORXREGD12, OWREGD67),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(subdp, s_xdp_dp_dp, s, l_1_or_2_src, addsubdp, C67XP,
      TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x77)),
      OP3(ORXREGD12, ORREGD12, OWREGD67),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSNE(subsp, l_sp_xsp_sp, l, 1_or_2_src, 4cycle, C67X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x11)),
      OP3(ORREG1, ORXREG1, OWREG4),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(subsp, l_xsp_sp_sp, l, 1_or_2_src, 4cycle, C67X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x15)),
      OP3(ORXREG1, ORREG1, OWREG4),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(subsp, s_sp_xsp_sp, s, l_1_or_2_src, 4cycle, C67XP,
      TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x71)),
      OP3(ORREG1, ORXREG1, OWREG4),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(subsp, s_xsp_sp_sp, s, l_1_or_2_src, 4cycle, C67XP,
      TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x75)),
      OP3(ORXREG1, ORREG1, OWREG4),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	   ENC(src1, reg, 1), ENC(dst, reg, 2)))

INSNE(subu, l_ui_xui_ul, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(1),
      FIX1(FIX(op, 0x2f)),
      OP3(ORREG1, ORXREG1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(subu, l_xui_ui_ul, l, 1_or_2_src, 1cycle, C62X, TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x3f)),
      OP3(ORXREG1, ORREG1, OWREGL1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(sub2, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x04)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(sub2, s, 1_or_2_src, 1cycle, C62X, 0,
     FIX1(FIX(op, 0x11)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSN(sub2, d, ext_1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x5)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(sub4, l, 1_or_2_src, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x66)),
     OP3(ORREG1, ORXREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(swap2, l, 1_or_2_src, 1cycle, C64X, TIC6X_FLAG_MACRO|TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x1b), FIX(x, 0)),
     OP2(ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 0), ENC(dst, reg, 1)))
INSN(swap2, s, 1_or_2_src, 1cycle, C64X, TIC6X_FLAG_MACRO|TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x10), FIX(x, 0)),
     OP2(ORREG1, OWREG1),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 0), ENC(dst, reg, 1)))

/* Contrary to SPRUFE8, this is the correct encoding for this
   instruction.  */
INSN(swap4, l, unary, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x1)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(swe, nfu, swe, 1cycle, C64XP, 0,
     FIX1(FIX(s, 0)),
     OP0(),
     ENC0())

INSN(swenr, nfu, swenr, 1cycle, C64XP, 0,
     FIX1(FIX(s, 0)),
     OP0(),
     ENC0())

INSN(unpkhu4, l, unary, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x03)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))
INSN(unpkhu4, s, unary, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x03)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(unpklu4, l, unary, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x02)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))
INSN(unpklu4, s, unary, 1cycle, C64X, 0,
     FIX1(FIX(op, 0x02)),
     OP2(ORXREG1, OWREG1),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSNE(xor, l_ui_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x6f)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(xor, l_s5_xui_ui, l, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x6e)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(xor, s_ui_xui_ui, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x0b)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(xor, s_s5_xui_ui, s, 1_or_2_src, 1cycle, C62X, 0,
      FIX1(FIX(op, 0x0a)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(xor, d_ui_xui_ui, d, ext_1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0xe)),
      OP3(ORREG1, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNE(xor, d_s5_xui_ui, d, ext_1_or_2_src, 1cycle, C64X, 0,
      FIX1(FIX(op, 0xf)),
      OP3(OACST, ORXREG1, OWREG1),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, scst, 0),
	   ENC(src2, reg, 1), ENC(dst, reg, 2)))

/* 16 bits insn */
INSN(xor, l, l2c, 1cycle, C64XP, 0,
      FIX1(FIX(op, 0x2)),
      OP3(ORREG1, ORXREG1, OWREG1NORS),
      ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
           ENC(src2, reg, 1), ENC(dst, reg, 2)))
INSNU(xor, l, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x7), FIX(unit, 0x0)),
     OP3(ORREG1, OHWCST1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2)))
INSNU(xor, s, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x7), FIX(unit, 0x1)),
     OP3(ORREG1, OHWCST1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2)))
INSNU(xor, d, lsdx1, 1cycle, C64XP, TIC6X_FLAG_NO_CROSS,
     FIX2(FIX(op, 0x7), FIX(unit, 0x2)),
     OP3(ORREG1, OHWCST1, OWREG1),
     ENC3(ENC(s, fu, 0), ENC(srcdst, reg, 0), ENC(srcdst, reg, 2)))
/**/

INSN(xormpy, m, 1_or_2_src, 4cycle, C64XP, 0,
     FIX1(FIX(op, 0x1b)),
     OP3(ORREG1, ORXREG1, OWREG4),
     ENC5(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src1, reg, 0),
	  ENC(src2, reg, 1), ENC(dst, reg, 2)))

INSN(xpnd2, m, unary, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x19)),
     OP2(ORXREG1, OWREG2),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(xpnd4, m, unary, 1616_m, C64X, 0,
     FIX1(FIX(op, 0x18)),
     OP2(ORXREG1, OWREG2),
     ENC4(ENC(s, fu, 0), ENC(x, xpath, 0), ENC(src2, reg, 0),
	  ENC(dst, reg, 1)))

INSN(zero, s, mvk, 1cycle, C62X, TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO,
     FIX2(FIX(h, 0), FIX(cst, 0)),
     OP1(OWREG1),
     ENC2(ENC(s, fu, 0), ENC(dst, reg, 0)))
INSN(zero, l, unary, 1cycle, C64X,
     TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_PREFER(1),
     FIX3(FIX(x, 0), FIX(op, 0x05), FIX(src2, 0)),
     OP1(OWREG1),
     ENC2(ENC(s, fu, 0), ENC(dst, reg, 0)))
INSNE(zero, l_sub, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_PREFER(0),
      FIX2(FIX(op, 0x07), FIX(x, 0)),
      OP1(OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src1, reg_unused, 0), ENC(src2, reg_unused, 0),
	   ENC(dst, reg, 0)))
INSNE(zero, l_sub_sl, l, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO,
      FIX2(FIX(op, 0x27), FIX(x, 0)),
      OP1(OWREGL1),
      ENC4(ENC(s, fu, 0), ENC(src1, reg_unused, 0), ENC(src2, reg_unused, 0),
	   ENC(dst, reg, 0)))
INSNE(zero, d_mvk, d, 1_or_2_src, 1cycle, C64X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_PREFER(1),
      FIX3(FIX(op, 0x00), FIX(src1, 0), FIX(src2, 0)),
      OP1(OWREG1),
      ENC2(ENC(s, fu, 0), ENC(dst, reg, 0)))
INSNE(zero, d_sub, d, 1_or_2_src, 1cycle, C62X,
      TIC6X_FLAG_NO_CROSS|TIC6X_FLAG_MACRO|TIC6X_FLAG_PREFER(0),
      FIX1(FIX(op, 0x11)),
      OP1(OWREG1),
      ENC4(ENC(s, fu, 0), ENC(src2, reg_unused, 0), ENC(src1, reg_unused, 0),
	   ENC(dst, reg, 0)))

#undef TIC6X_INSN_C64X_AND_C67X
#undef tic6x_insn_format_nfu_s_branch_nop_cst
#undef tic6x_insn_format_s_l_1_or_2_src
#undef RAN
#undef FIX
#undef FIX0
#undef FIX1
#undef FIX2
#undef FIX3
#undef FIX4
#undef OP0
#undef OP1
#undef OP2
#undef OP3
#undef OP4
#undef OACST
#undef OLCST
#undef OHWCSTM1
#undef OHWCST0
#undef OHWCST1
#undef OHWCST5
#undef OHWCST16
#undef OHWCST24
#undef OHWCST31
#undef OFULIST
#undef ORIRP1
#undef ORNRP1
#undef OWREG1
#undef OWRETREG1
#undef ORREG1
#undef ORDREG1
#undef ORWREG1
#undef ORAREG1
#undef ORXREG1
#undef ORREG12
#undef ORREG14
#undef ORXREG14
#undef OWREG2
#undef OWREG4
#undef OWREG9
#undef OWDREG5
#undef OWREGL1
#undef ORREGL1
#undef OWREGD1
#undef ORTREG1
#undef ORTREGD1
#undef OWTREG5
#undef OWTREGD5
#undef OWREGD12
#undef OWREGD4
#undef ORREGD1
#undef OWREGD45
#undef OWREGD67
#undef ORDREGD1
#undef OWDREGD5
#undef ORREGD12
#undef ORXREGD12
#undef ORXREGD1234
#undef ORREGD1324
#undef OWREGD910
#undef OWILC1
#undef ORCREG1
#undef OWCREG1
#undef OWREG1Z
#undef ORB15REG1
#undef OWB15REG1
#undef ORMEMDW
#undef OWMEMDW
#undef ORMEMSB
#undef OWMEMSB
#undef ORMEMLB
#undef OWMEMLB
#undef ORMEMSH
#undef OWMEMSH
#undef ORMEMLH
#undef OWMEMLH
#undef ORMEMSW
#undef OWMEMSW
#undef ORMEMLW
#undef OWMEMLW
#undef ORMEMSD
#undef OWMEMSD
#undef ORMEMND
#undef OWMEMND
#undef ENC
#undef ENC0
#undef ENC1
#undef ENC2
#undef ENC3
#undef ENC4
#undef ENC5
#undef ENC6
#undef ENC7
