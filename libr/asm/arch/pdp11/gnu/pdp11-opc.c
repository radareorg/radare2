/* Opcode table for PDP-11.
   Copyright (C) 2001-2021 Free Software Foundation, Inc.

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
   along with this file; see the file COPYING.  If not, write to the
   Free Software Foundation, 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "opcode/pdp11.h"

const struct pdp11_opcode pdp11_opcodes[] =
{
  /* name,	pattern, mask,	opcode type,		insn type,    alias */
  { "halt",	0x0000,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "wait",	0x0001,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "rti",	0x0002,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "bpt",	0x0003,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "iot",	0x0004,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "reset",	0x0005,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "rtt",	0x0006,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_LEIS },
  { "mfpt",	0x0007,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_MFPT },
  { "jmp",	0x0040,	0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "rts",	0x0080,	0xfff8, PDP11_OPCODE_REG,	PDP11_BASIC },
  { "",		0x0088, 0xfff8, PDP11_OPCODE_ILLEGAL,	PDP11_NONE },
  { "",		0x0090, 0xfff8, PDP11_OPCODE_ILLEGAL,	PDP11_NONE },
  { "spl",	0x0098,	0xfff8, PDP11_OPCODE_IMM3,	PDP11_SPL },
  { "nop",	0x00a0,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "clc",	0x00a1,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "clv",	0x00a2,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_3",	0x00a3,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "clz",	0x00a4,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_5",	0x00a5,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_6",	0x00a6,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_7",	0x00a7,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cln",	0x00a8,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_9",	0x00a9,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_a",	0x00aa,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_b",	0x00ab,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_c",	0x00ac,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_d",	0x00ad,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "cl_e",	0x00ae,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "ccc",	0x00af,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_0",	0x00b0,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "sec",	0x00b1,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "sev",	0x00b2,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_3",	0x00b3,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "sez",	0x00b4,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_5",	0x00b5,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_6",	0x00b6,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_7",	0x00b7,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "sen",	0x00b8,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_9",	0x00b9,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_a",	0x00ba,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_b",	0x00bb,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_c",	0x00bc,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_d",	0x00bd,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "se_e",	0x00be,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "scc",	0x00bf,	0xffff, PDP11_OPCODE_NO_OPS,	PDP11_BASIC },
  { "swab",	0x00c0,	0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "br",	0x0100, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "bne",	0x0200, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "beq",	0x0300, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "bge",	0x0400, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "blt",	0x0500, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "bgt",	0x0600, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "ble",	0x0700, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "jsr",	0x0800, 0xfe00, PDP11_OPCODE_REG_OP,	PDP11_BASIC },
  { "clr",	0x0a00, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "com",	0x0a40, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "inc",	0x0a80, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "dec",	0x0ac0, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "neg",	0x0b00, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "adc",	0x0b40, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "sbc",	0x0b80, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "tst",	0x0bc0, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "ror",	0x0c00, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "rol",	0x0c40, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "asr",	0x0c80, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "asl",	0x0cc0, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "mark",	0x0d00, 0xffc0, PDP11_OPCODE_IMM6,	PDP11_LEIS },
  { "mfpi",	0x0d40, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "mtpi",	0x0d80, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "sxt",	0x0dc0, 0xffc0, PDP11_OPCODE_OP,	PDP11_LEIS },
  { "csm",	0x0e00, 0xffc0, PDP11_OPCODE_OP,	PDP11_CSM },
  { "tstset",	0x0e40, 0xffc0, PDP11_OPCODE_OP,	PDP11_MPROC },
  { "wrtlck",	0x0e80, 0xffc0, PDP11_OPCODE_OP,	PDP11_MPROC },
/*{ "",		0x0ec0, 0xffe0, PDP11_OPCODE_ILLEGAL,	PDP11_NONE },*/
  { "mov",	0x1000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "cmp",	0x2000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "bit",	0x3000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "bic",	0x4000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "bis",	0x5000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "add",	0x6000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "mul",	0x7000, 0xfe00, PDP11_OPCODE_REG_OP_REV,PDP11_EIS },
  { "div",	0x7200, 0xfe00, PDP11_OPCODE_REG_OP_REV,PDP11_EIS },
  { "ash",	0x7400, 0xfe00, PDP11_OPCODE_REG_OP_REV,PDP11_EIS },
  { "ashc",	0x7600, 0xfe00, PDP11_OPCODE_REG_OP_REV,PDP11_EIS },
  { "xor",	0x7800, 0xfe00, PDP11_OPCODE_REG_OP,	PDP11_LEIS },
  { "fadd",	0x7a00, 0xfff8, PDP11_OPCODE_REG,	PDP11_FIS },
  { "fsub",	0x7a08, 0xfff8, PDP11_OPCODE_REG,	PDP11_FIS },
  { "fmul",	0x7a10, 0xfff8, PDP11_OPCODE_REG,	PDP11_FIS },
  { "fdiv",	0x7a18, 0xfff8, PDP11_OPCODE_REG,	PDP11_FIS },
/*{ "",		0x7a20, 0xffe0, PDP11_OPCODE_ILLEGAL,	PDP11_NONE },*/
/*{ "",		0x7a40, 0xffc0, PDP11_OPCODE_ILLEGAL,	PDP11_NONE },*/
/*{ "",		0x7a80, 0xff80, PDP11_OPCODE_ILLEGAL,	PDP11_NONE },*/
/*{ "",		0x7b00, 0xffe0, PDP11_OPCODE_ILLEGAL,	PDP11_NONE },*/
  { "l2dr",	0x7c10, 0xfff8, PDP11_OPCODE_REG,	PDP11_CIS },/*l2d*/
  { "movc",	0x7c18, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "movrc",	0x7c19, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "movtc",	0x7c1a, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "locc",	0x7c20, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "skpc",	0x7c21, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "scanc",	0x7c22, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "spanc",	0x7c23, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cmpc",	0x7c24, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "matc",	0x7c25, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "addn",	0x7c28, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "subn",	0x7c29, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cmpn",	0x7c2a, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtnl",	0x7c2b, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtpn",	0x7c2c, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtnp",	0x7c2d, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "ashn",	0x7c2e, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtln",	0x7c2f, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "l3dr",	0x7c30, 0xfff8, PDP11_OPCODE_REG,	PDP11_CIS },/*l3d*/
  { "addp",	0x7c38, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "subp",	0x7c39, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cmpp",	0x7c3a, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtpl",	0x7c3b, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "mulp",	0x7c3c, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "divp",	0x7c3d, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "ashp",	0x7c3e, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtlp",	0x7c3f, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "movci",	0x7c58, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "movrci",	0x7c59, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "movtci",	0x7c5a, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "locci",	0x7c60, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "skpci",	0x7c61, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "scanci",	0x7c62, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "spanci",	0x7c63, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cmpci",	0x7c64, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "matci",	0x7c65, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "addni",	0x7c68, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "subni",	0x7c69, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cmpni",	0x7c6a, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtnli",	0x7c6b, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtpni",	0x7c6c, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtnpi",	0x7c6d, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "ashni",	0x7c6e, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtlni",	0x7c6f, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "addpi",	0x7c78, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "subpi",	0x7c79, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cmppi",	0x7c7a, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtpli",	0x7c7b, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "mulpi",	0x7c7c, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "divpi",	0x7c7d, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "ashpi",	0x7c7e, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "cvtlpi",	0x7c7f, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_CIS },
  { "med",	0x7d80, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_UCODE },
  { "xfc",	0x7dc0, 0xffc0, PDP11_OPCODE_IMM6,	PDP11_UCODE },
  { "sob",	0x7e00, 0xfe00, PDP11_OPCODE_REG_DISPL,	PDP11_LEIS },
  { "bpl",	0x8000, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "bmi",	0x8100, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "bhi",	0x8200, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "blos",	0x8300, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "bvc",	0x8400, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "bvs",	0x8500, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "bcc",	0x8600, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },/*bhis*/
  { "bcs",	0x8700, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },/*blo*/
  { "emt",	0x8800, 0xff00, PDP11_OPCODE_IMM8,	PDP11_BASIC },
  { "sys",	0x8900, 0xff00, PDP11_OPCODE_IMM8,	PDP11_BASIC },/*trap*/
  { "clrb",	0x8a00, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "comb",	0x8a40, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "incb",	0x8a80, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "decb",	0x8ac0, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "negb",	0x8b00, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "adcb",	0x8b40, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "sbcb",	0x8b80, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "tstb",	0x8bc0, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "rorb",	0x8c00, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "rolb",	0x8c40, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "asrb",	0x8c80, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "aslb",	0x8cc0, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "mtps",	0x8d00, 0xffc0, PDP11_OPCODE_OP,	PDP11_MXPS },
  { "mfpd",	0x8d40, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "mtpd",	0x8d80, 0xffc0, PDP11_OPCODE_OP,	PDP11_BASIC },
  { "mfps",	0x8dc0, 0xffc0, PDP11_OPCODE_OP,	PDP11_MXPS },
  { "movb",	0x9000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "cmpb",	0xa000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "bitb",	0xb000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "bicb",	0xc000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "bisb",	0xd000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "sub",	0xe000, 0xf000, PDP11_OPCODE_OP_OP,	PDP11_BASIC },
  { "cfcc",	0xf000, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_FPP },
  { "setf",	0xf001, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_FPP },
  { "seti",	0xf002, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_FPP },
  { "ldub",	0xf003, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_UCODE },
  /* fpp trap	0xf004..0xf008 */
  { "setd",	0xf009, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_FPP },
  { "setl",	0xf00a, 0xffff, PDP11_OPCODE_NO_OPS,	PDP11_FPP },
  /* fpp trap	0xf00b..0xf03f */
  { "ldfps",	0xf040, 0xffc0, PDP11_OPCODE_OP,	PDP11_FPP },
  { "stfps",	0xf080, 0xffc0, PDP11_OPCODE_OP,	PDP11_FPP },
  { "stst",	0xf0c0, 0xffc0, PDP11_OPCODE_OP,	PDP11_FPP },
  { "clrf",	0xf100, 0xffc0, PDP11_OPCODE_FOP,	PDP11_FPP },
  { "tstf",	0xf140, 0xffc0, PDP11_OPCODE_FOP,	PDP11_FPP },
  { "absf",	0xf180, 0xffc0, PDP11_OPCODE_FOP,	PDP11_FPP },
  { "negf",	0xf1c0, 0xffc0, PDP11_OPCODE_FOP,	PDP11_FPP },
  { "mulf",	0xf200, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "modf",	0xf300, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "addf",	0xf400, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "ldf",	0xf500, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },/*movif*/
  { "subf",	0xf600, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "cmpf",	0xf700, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "stf",	0xf800, 0xff00, PDP11_OPCODE_AC_FOP,	PDP11_FPP },/*movfi*/
  { "divf",	0xf900, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "stexp",	0xfa00, 0xff00, PDP11_OPCODE_AC_OP,	PDP11_FPP },
  { "stcfi",	0xfb00, 0xff00, PDP11_OPCODE_AC_OP,	PDP11_FPP },
  { "stcff",	0xfc00, 0xff00, PDP11_OPCODE_AC_FOP,	PDP11_FPP },/* ? */
  { "ldexp",	0xfd00, 0xff00, PDP11_OPCODE_OP_AC,	PDP11_FPP },
  { "ldcif",	0xfe00, 0xff00, PDP11_OPCODE_OP_AC,	PDP11_FPP },
  { "ldcff",	0xff00, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },/* ? */
/* This entry MUST be last; it is a "catch-all" entry that will match when no
 * other opcode entry matches during disassembly.
 */
  { "",		0x0000, 0x0000, PDP11_OPCODE_ILLEGAL,	PDP11_NONE },
};

const struct pdp11_opcode pdp11_aliases[] =
{
  /* name,	pattern, mask,	opcode type,		insn type */
  { "l2d",	0x7c10, 0xfff8, PDP11_OPCODE_REG,	PDP11_CIS },
  { "l3d",	0x7c30, 0xfff8, PDP11_OPCODE_REG,	PDP11_CIS },
  { "bhis",	0x8600, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "blo",	0x8700, 0xff00, PDP11_OPCODE_DISPL,	PDP11_BASIC },
  { "trap",	0x8900, 0xff00, PDP11_OPCODE_IMM8,	PDP11_BASIC },
  /* fpp xxxd alternate names to xxxf opcodes */
  { "clrd",	0xf100, 0xffc0, PDP11_OPCODE_FOP,	PDP11_FPP },
  { "tstd",	0xf140, 0xffc0, PDP11_OPCODE_FOP,	PDP11_FPP },
  { "absd",	0xf180, 0xffc0, PDP11_OPCODE_FOP,	PDP11_FPP },
  { "negd",	0xf1c0, 0xffc0, PDP11_OPCODE_FOP,	PDP11_FPP },
  { "muld",	0xf200, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "modd",	0xf300, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "addd",	0xf400, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "ldd",	0xf500, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },/*movif*/
  { "subd",	0xf600, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "cmpd",	0xf700, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "std",	0xf800, 0xff00, PDP11_OPCODE_AC_FOP,	PDP11_FPP },/*movfi*/
  { "divd",	0xf900, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },
  { "stcfl",	0xfb00, 0xff00, PDP11_OPCODE_AC_OP,	PDP11_FPP },
  { "stcdi",	0xfb00, 0xff00, PDP11_OPCODE_AC_OP,	PDP11_FPP },
  { "stcdl",	0xfb00, 0xff00, PDP11_OPCODE_AC_OP,	PDP11_FPP },
  { "stcfd",	0xfc00, 0xff00, PDP11_OPCODE_AC_FOP,	PDP11_FPP },/* ? */
  { "stcdf",	0xfc00, 0xff00, PDP11_OPCODE_AC_FOP,	PDP11_FPP },/* ? */
  { "ldcid",	0xfe00, 0xff00, PDP11_OPCODE_OP_AC,	PDP11_FPP },
  { "ldclf",	0xfe00, 0xff00, PDP11_OPCODE_OP_AC,	PDP11_FPP },
  { "ldcld",	0xfe00, 0xff00, PDP11_OPCODE_OP_AC,	PDP11_FPP },
  { "ldcfd",	0xff00, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },/* ? */
  { "ldcdf",	0xff00, 0xff00, PDP11_OPCODE_FOP_AC,	PDP11_FPP },/* ? */
};

const int pdp11_num_opcodes = sizeof pdp11_opcodes / sizeof pdp11_opcodes[0];
const int pdp11_num_aliases = sizeof pdp11_aliases / sizeof pdp11_aliases[0];
