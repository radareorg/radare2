/* TI C6X instruction format information.
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

/* Define the FMT macro before including this file; it takes a name
   and the fields from tic6x_insn_format (defined in tic6x.h).  */

/* Expansion fields values for 16 bits insn.  */
#define SAT(a) (((a) & 1) << TIC6X_COMPACT_SAT_POS)
#define BR(a) (((a) & 1) << TIC6X_COMPACT_BR_POS)
#define DSZ(a) (((a) & 7) << TIC6X_COMPACT_DSZ_POS)
/* Composite fields for 16 bits insn.  */
#define BFLD(low_pos, width, pos) { (low_pos), (width), (pos) }
#define BFLD1(a) 1, { a }
#define BFLD2(a, b) 2, { a, b }
#define BFLD3(a, b, c) 3, { a, b, c }
#define BFLD4(a, b, c, d) 4, { a, b, c, d }
#define COMPFLD(name, bitfields) { CONCAT2(tic6x_field_,name),  bitfields }
/**/
#define FLD(name, pos, width) { CONCAT2(tic6x_field_,name), BFLD1(BFLD(pos, width, 0)) }
#define CFLDS FLD(p, 0, 1), FLD(creg, 29, 3), FLD(z, 28, 1)
#define CFLDS2(a, b) 5, { CFLDS, a, b }
#define CFLDS3(a, b, c) 6, { CFLDS, a, b, c }
#define CFLDS4(a, b, c, d) 7, { CFLDS, a, b, c, d }
#define CFLDS5(a, b, c, d, e) 8, { CFLDS, a, b, c, d, e }
#define CFLDS6(a, b, c, d, e, f) 9, { CFLDS, a, b, c, d, e, f }
#define CFLDS7(a, b, c, d, e, f, g) 10, { CFLDS, a, b, c, d, e, f, g }
#define CFLDS8(a, b, c, d, e, f, g, h) 11, { CFLDS, a, b, c, d, e, f, g, h }
#define NFLDS FLD(p, 0, 1)
#define NFLDS1(a) 2, { NFLDS, a }
#define NFLDS2(a, b) 3, { NFLDS, a, b }
#define NFLDS3(a, b, c) 4, { NFLDS, a, b, c }
#define NFLDS5(a, b, c, d, e) 6, { NFLDS, a, b, c, d, e }
#define NFLDS6(a, b, c, d, e, f) 7, { NFLDS, a, b, c, d, e, f }
#define NFLDS7(a, b, c, d, e, f, g) 8, { NFLDS, a, b, c, d, e, f, g }
/* 16 bits insn */
#define FLDS1(a) 1, { a }
#define FLDS2(a, b) 2, { a, b }
#define FLDS3(a, b, c) 3, { a, b, c }
#define FLDS4(a, b, c, d) 4, { a, b, c, d }
#define FLDS5(a, b, c, d, e) 5, { a, b, c, d, e }
#define SFLDS FLD(s, 0, 1)
#define SFLDS1(a) 2, { SFLDS, a }
#define SFLDS2(a, b) 3, { SFLDS, a, b }
#define SFLDS3(a, b, c) 4, { SFLDS, a, b, c }
#define SFLDS4(a, b, c, d) 5, { SFLDS, a, b, c, d }
#define SFLDS5(a, b, c, d, e) 6, { SFLDS, a, b, c, d, e }
#define SFLDS6(a, b, c, d, e, f) 7, { SFLDS, a, b, c, d, e, f }
#define SFLDS7(a, b, c, d, e, f, g) 8, { SFLDS, a, b, c, d, e, f, g }
/**/

/* These are in the order from SPRUFE8, appendices C-H.  */

/* Appendix C 32-bit formats.  */

FMT(d_1_or_2_src, 32, 0x40, 0x7c,
    CFLDS5(FLD(s, 1, 1), FLD(op, 7, 6), FLD(src1, 13, 5), FLD(src2, 18, 5),
	   FLD(dst, 23, 5)))
FMT(d_ext_1_or_2_src, 32, 0x830, 0xc3c,
    CFLDS6(FLD(s, 1, 1), FLD(op, 6, 4), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5)))
FMT(d_load_store, 32, 0x4, 0xc,
    CFLDS8(FLD(s, 1, 1), FLD(op, 4, 3), FLD(y, 7, 1), FLD(r, 8, 1),
	   FLD(mode, 9, 4), FLD(offsetR, 13, 5), FLD(baseR, 18, 5),
	   FLD(srcdst, 23, 5)))
/* The nonaligned loads and stores have the formats shown in the
   individual instruction descriptions; the appendix is incorrect.  */
FMT(d_load_nonaligned, 32, 0x124, 0x17c,
    CFLDS7(FLD(s, 1, 1), FLD(y, 7, 1), FLD(mode, 9, 4), FLD(offsetR, 13, 5),
	   FLD(baseR, 18, 5), FLD(sc, 23, 1), FLD(dst, 24, 4)))
FMT(d_store_nonaligned, 32, 0x174, 0x17c,
    CFLDS7(FLD(s, 1, 1), FLD(y, 7, 1), FLD(mode, 9, 4), FLD(offsetR, 13, 5),
	   FLD(baseR, 18, 5), FLD(sc, 23, 1), FLD(src, 24, 4)))
FMT(d_load_store_long, 32, 0xc, 0xc,
    CFLDS5(FLD(s, 1, 1), FLD(op, 4, 3), FLD(y, 7, 1), FLD(offsetR, 8, 15),
	   FLD(dst, 23, 5)))
FMT(d_adda_long, 32, 0x1000000c, 0xf000000c,
    NFLDS5(FLD(s, 1, 1), FLD(op, 4, 3), FLD(y, 7, 1), FLD(offsetR, 8, 15),
	   FLD(dst, 23, 5)))

/* Appendix C 16-bit formats will go here.  */

/* C-8 */
FMT(d_doff4_dsz_0xx, 16, DSZ(0) | 0x0004, DSZ(0x4) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 
FMT(d_doff4_dsz_100, 16, DSZ(4) | 0x0004, DSZ(0x7) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 
FMT(d_doff4_dsz_000, 16, DSZ(0) | 0x0004, DSZ(0x7) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 
FMT(d_doff4_dsz_x01, 16, DSZ(1) | 0x0004, DSZ(0x3) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 
FMT(d_doff4_dsz_01x, 16, DSZ(2) | 0x0004, DSZ(0x6) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 
FMT(d_doff4_dsz_111, 16, DSZ(7) | 0x0004, DSZ(0x7) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 
FMT(d_doff4_dsz_x11, 16, DSZ(3) | 0x0004, DSZ(0x3) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 
FMT(d_doff4_dsz_010, 16, DSZ(2) | 0x0004, DSZ(0x7) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 
FMT(d_doff4_dsz_110, 16, DSZ(6) | 0x0004, DSZ(0x7) | 0x0406,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 

/* C-9 */
FMT(d_doff4dw, 16, DSZ(4) | 0x0004, DSZ(0x4) | 0x0406,
    SFLDS7(FLD(op, 3, 1), FLD(na, 4, 1), FLD(srcdst, 5, 2), FLD(ptr, 7, 2), FLD(sz, 9, 1), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3))))) 

/* C-10 */
FMT(d_dind_dsz_0xx, 16, DSZ(0) | 0x0404, DSZ(0x4) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

FMT(d_dind_dsz_x01, 16, DSZ(1) | 0x0404, DSZ(0x3) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

FMT(d_dind_dsz_x11, 16, DSZ(3) | 0x0404, DSZ(0x3) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

FMT(d_dind_dsz_01x, 16, DSZ(2) | 0x0404, DSZ(0x6) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

FMT(d_dind_dsz_000, 16, DSZ(0) | 0x0404, DSZ(0x7) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

FMT(d_dind_dsz_010, 16, DSZ(2) | 0x0404, DSZ(0x7) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

FMT(d_dind_dsz_100, 16, DSZ(4) | 0x0404, DSZ(0x7) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

FMT(d_dind_dsz_110, 16, DSZ(6) | 0x0404, DSZ(0x7) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

FMT(d_dind_dsz_111, 16, DSZ(7) | 0x0404, DSZ(0x7) | 0x0c06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(src1, 13, 3)))

/* C-11 */
FMT(d_dinddw, 16, DSZ(4) | 0x0404, DSZ(0x4) | 0x0c06,
    SFLDS7(FLD(op, 3, 1), FLD(na, 4, 1), FLD(srcdst, 5, 2), FLD(ptr, 7, 2),
           FLD(sz, 9, 1), FLD(t, 12, 1), FLD(src1, 13, 3)))

/* C-12 */
FMT(d_dinc_dsz_x01, 16, DSZ(1) | 0x0c04, DSZ(0x3) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_dinc_dsz_0xx, 16, DSZ(0) | 0x0c04, DSZ(0x4) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_dinc_dsz_01x, 16, DSZ(2) | 0x0c04, DSZ(0x6) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_dinc_dsz_x11,16, DSZ(3) | 0x0c04, DSZ(0x3) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_dinc_dsz_000, 16, DSZ(0) | 0x0c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_dinc_dsz_010, 16, DSZ(2) | 0x0c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_dinc_dsz_100, 16, DSZ(4) | 0x0c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_dinc_dsz_110, 16, DSZ(6) | 0x0c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_dinc_dsz_111, 16, DSZ(7) | 0x0c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

/* C-13*/
FMT(d_dincdw, 16, DSZ(4) | 0x0c04, DSZ(0x4) | 0xcc06,
    SFLDS7(FLD(op, 3, 1), FLD(na, 4, 1), FLD(srcdst, 5, 2), FLD(ptr, 7, 2),
           FLD(sz, 9, 1), FLD(t, 12, 1), FLD(cst, 13, 1)))

/* C-14 */
FMT(d_ddec_dsz_01x, 16, DSZ(2) | 0x4c04, DSZ(0x6) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_ddec_dsz_0xx, 16, DSZ(0) | 0x4c04, DSZ(0x4) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_ddec_dsz_x01, 16, DSZ(1) | 0x4c04, DSZ(0x3) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_ddec_dsz_x11, 16, DSZ(3) | 0x4c04, DSZ(0x3) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_ddec_dsz_000, 16, DSZ(0) | 0x4c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_ddec_dsz_010, 16, DSZ(2) | 0x4c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_ddec_dsz_100, 16, DSZ(4) | 0x4c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_ddec_dsz_110, 16, DSZ(6) | 0x4c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

FMT(d_ddec_dsz_111, 16, DSZ(7) | 0x4c04, DSZ(0x7) | 0xcc06,
    SFLDS6(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(ptr, 7, 2), FLD(sz, 9, 1),
           FLD(t, 12, 1), FLD(cst, 13, 1)))

/* C-15 */
FMT(d_ddecdw, 16, DSZ(4) | 0x4c04, DSZ(0x4) | 0xcc06,
    SFLDS7(FLD(op, 3, 1), FLD(na, 4, 1),  FLD(srcdst, 5, 2), FLD(ptr, 7, 2),
           FLD(sz, 9, 1), FLD(t, 12, 1), FLD(cst, 13, 1)))

/* C-16 */
FMT(d_dstk, 16, 0x8c04, 0x8c06,
    SFLDS4(FLD(op, 3, 1), FLD(srcdst, 4, 3), FLD(t, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(7, 3, 2), BFLD(13, 2, 0)))))

/* C-17 */
FMT(d_dx2op, 16, 0x0036, 0x047e,
    SFLDS4(FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1), FLD(srcdst, 13, 3)))

/* C-18 */
FMT(d_dx5, 16, 0x0436, 0x047e,
    SFLDS2(FLD(dst, 7, 3), 
           COMPFLD(cst, BFLD2(BFLD(11, 2, 3), BFLD(13, 3, 0)))))

/* C-19 */
FMT(d_dx5p, 16, 0x0c76, 0x1c7e,
    SFLDS2(FLD(op, 7, 1),
           COMPFLD(cst, BFLD2(BFLD(8, 2, 3), BFLD(13, 3, 0)))))

/* C-20 */
FMT(d_dx1, 16, 0x1876, 0x1c7e,
    SFLDS2(FLD(srcdst, 7, 3), FLD(op, 13, 3)))

/* C-21 */
FMT(d_dpp, 16, 0x0077, 0x087f,
    SFLDS5(FLD(srcdst, 7, 4), FLD(t, 12, 1), FLD(cst, 13, 1), FLD(op, 14, 1),
           FLD(dw, 15, 1)))

/* Appendix D 32-bit formats.  */

FMT(l_1_or_2_src, 32, 0x18, 0x1c,
    CFLDS6(FLD(s, 1, 1), FLD(op, 5, 7), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5)))
FMT(l_1_or_2_src_noncond, 32, 0x10000018, 0xf000001c,
    NFLDS6(FLD(s, 1, 1), FLD(op, 5, 7), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5)))
FMT(l_unary, 32, 0x358, 0xffc,
    CFLDS5(FLD(s, 1, 1), FLD(x, 12, 1), FLD(op, 13, 5), FLD(src2, 18, 5),
	   FLD(dst, 23, 5)))

/* Appendix D 16-bit formats will go here.  */

/* D-4 */
FMT(l_l3_sat_0, 16, SAT(0) | 0x0000, SAT(1) | 0x040e,
    SFLDS5(FLD(dst, 4, 3), FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1),
           FLD(src1, 13, 3)))

FMT(l_l3_sat_1, 16, SAT(1) | 0x0000, SAT(1) | 0x040e,
    SFLDS5(FLD(dst, 4, 3), FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1),
           FLD(src1, 13, 3)))

/* D-5 - combine cst3 and n fields into a single field cst */
FMT(l_l3i, 16, 0x0400, 0x040e,
    SFLDS5(FLD(dst, 4, 3), FLD(src2, 7, 3), FLD(sn, 11, 1), FLD(x, 12, 1),
           COMPFLD(cst, BFLD2(BFLD(13, 3, 0), BFLD(11, 1, 3)))))

/* D-6 Mtbd ? */

/* D-7 */
FMT(l_l2c, 16, 0x0408, 0x040e,
    SFLDS5(FLD(dst, 4, 1), FLD(src2, 7, 3), FLD(x, 12, 1), FLD(src1, 13, 3),
           COMPFLD(op, BFLD2(BFLD(5, 2, 0), BFLD(11, 1, 2)))))

/* D-8 */
FMT(l_lx5, 16, 0x0426, 0x047e,
    SFLDS2(FLD(dst, 7, 3),
           COMPFLD(cst, BFLD2(BFLD(11, 2, 3), BFLD(13, 3, 0)))))

/* D-9 */
FMT(l_lx3c, 16, 0x0026, 0x147e,
    SFLDS3(FLD(src2, 7, 3), FLD(dst, 11, 1), FLD(cst, 13, 3)))

/* D-10 */
FMT(l_lx1c, 16, 0x1026, 0x147e,
    SFLDS4(FLD(src2, 7, 3), FLD(dst, 11, 1), FLD(cst, 13, 1), FLD(op, 14, 2)))

/* D-11 */
FMT(l_lx1, 16, 0x1866, 0x1c7e,
    SFLDS2(FLD(srcdst, 7, 3), FLD(op, 13, 3)))

/* Appendix E 32-bit formats.  */

FMT(m_compound, 32, 0x30, 0x83c,
    CFLDS6(FLD(s, 1, 1), FLD(op, 6, 5), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5)))
FMT(m_1_or_2_src, 32, 0x10000030, 0xf000083c,
    NFLDS6(FLD(s, 1, 1), FLD(op, 6, 5), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5)))
/* Contrary to SPRUFE8, this does have predicate fields.  */
FMT(m_unary, 32, 0xf0, 0xffc,
    CFLDS5(FLD(s, 1, 1), FLD(x, 12, 1), FLD(op, 13, 5), FLD(src2, 18, 5),
	   FLD(dst, 23, 5)))

/* M-unit formats missing from Appendix E.  */
FMT(m_mpy, 32, 0x0, 0x7c,
    CFLDS6(FLD(s, 1, 1), FLD(op, 7, 5), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5)))

/* Appendix E 16-bit formats will go here.  */
FMT(m_m3_sat_0, 16, SAT(0) | 0x001e, SAT(1) | 0x001e,
    SFLDS5(FLD(op, 5, 2), FLD(src2, 7, 3), FLD(dst, 10, 2),
           FLD(x, 12, 1), FLD(src1, 13, 3)))
FMT(m_m3_sat_1, 16, SAT(1) | 0x001e, SAT(1) | 0x001e,
    SFLDS5(FLD(op, 5, 2), FLD(src2, 7, 3), FLD(dst, 10, 2),
           FLD(x, 12, 1), FLD(src1, 13, 3)))

/* Appendix F 32-bit formats.  */

FMT(s_1_or_2_src, 32, 0x20, 0x3c,
    CFLDS6(FLD(s, 1, 1), FLD(op, 6, 6), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23 ,5)))
FMT(s_ext_1_or_2_src, 32, 0xc30, 0xc3c,
    CFLDS6(FLD(s, 1, 1), FLD(op, 6, 4), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5)))
FMT(s_ext_1_or_2_src_noncond, 32, 0xc30, 0xe0000c3c,
    NFLDS7(FLD(s, 1, 1), FLD(op, 6, 4), FLD(x, 12, 1), FLD(src1, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5), FLD(z, 28, 1)))
FMT(s_unary, 32, 0xf20, 0xffc,
    CFLDS5(FLD(s, 1, 1), FLD(x, 12, 1), FLD(op, 13, 5), FLD(src2, 18, 5),
	   FLD(dst, 23, 5)))
FMT(s_ext_branch_cond_imm, 32, 0x10, 0x7c,
    CFLDS2(FLD(s, 1, 1), FLD(cst, 7, 21)))
FMT(s_call_imm_nop, 32, 0x10, 0xe000007c,
    NFLDS3(FLD(s, 1, 1), FLD(cst, 7, 21), FLD(z, 28, 1)))
FMT(s_branch_nop_cst, 32, 0x120, 0x1ffc,
    CFLDS3(FLD(s, 1, 1), FLD(src1, 13, 3), FLD(src2, 16, 12)))
FMT(s_branch_nop_reg, 32, 0x800360, 0xf830ffc,
    CFLDS4(FLD(s, 1, 1), FLD(x, 12, 1), FLD(src1, 13, 3), FLD(src2, 18, 5)))
FMT(s_branch, 32, 0x360, 0xf83effc,
    CFLDS3(FLD(s, 1, 1), FLD(x, 12, 1), FLD(src2, 18, 5)))
FMT(s_mvk, 32, 0x28, 0x3c,
    CFLDS4(FLD(s, 1, 1), FLD(h, 6, 1), FLD(cst, 7, 16), FLD(dst, 23, 5)))
FMT(s_field, 32, 0x8, 0x3c,
    CFLDS6(FLD(s, 1, 1), FLD(op, 6, 2), FLD(cstb, 8, 5), FLD(csta, 13, 5),
	   FLD(src2, 18, 5), FLD(dst, 23, 5)))

/* S-unit formats missing from Appendix F.  */
FMT(s_addk, 32, 0x50, 0x7c,
    CFLDS3(FLD(s, 1, 1), FLD(cst, 7, 16), FLD(dst, 23, 5)))
FMT(s_addkpc, 32, 0x160, 0x1ffc,
    CFLDS4(FLD(s, 1, 1), FLD(src2, 13, 3), FLD(src1, 16, 7), FLD(dst, 23, 5)))
FMT(s_b_irp, 32, 0x1800e0, 0x7feffc,
    CFLDS3(FLD(s, 1, 1), FLD(x, 12, 1), FLD(dst, 23, 5)))
FMT(s_b_nrp, 32, 0x1c00e0, 0x7feffc,
    CFLDS3(FLD(s, 1, 1), FLD(x, 12, 1), FLD(dst, 23, 5)))
FMT(s_bdec, 32, 0x1020, 0x1ffc,
    CFLDS3(FLD(s, 1, 1), FLD(src, 13, 10), FLD(dst, 23, 5)))
FMT(s_bpos, 32, 0x20, 0x1ffc,
    CFLDS3(FLD(s, 1, 1), FLD(src, 13, 10), FLD(dst, 23, 5)))

/* Appendix F 16-bit formats will go here.  */

/* F-17 Sbs7 Instruction Format */
FMT(s_sbs7, 16, BR(1) | 0x000a, BR(1) | 0x003e,
    SFLDS2(FLD(cst, 6, 7), FLD(n, 13, 3)))

/* F-18 Sbu8 Instruction Format */
FMT(s_sbu8, 16, BR(1) | 0xc00a, BR(1) | 0xc03e,
    SFLDS1(FLD(cst, 6, 8)))

/* F-19 Scs10 Instruction Format */
FMT(s_scs10, 16, BR(1) | 0x001a, BR(1) | 0x003e,
    SFLDS1(FLD(cst, 6, 10)))

/* F-20 Sbs7c Instruction Format */
FMT(s_sbs7c, 16, BR(1) | 0x002a, BR(1) | 0x002e,
    SFLDS3(FLD(z, 4, 1), FLD(cst, 6, 7), FLD(n, 13, 3)))

/* F-21 Sbu8c Instruction Format */
FMT(s_sbu8c, 16, BR(1) | 0xc02a, BR(1) |  0xc02e,
    SFLDS2(FLD(z, 4, 1), FLD(cst, 6, 8)))

/* F-22 S3 Instruction Format */
FMT(s_s3, 16, BR(0) | 0x000a, BR(1) | 0x040e,
    SFLDS5(FLD(dst, 4, 3), FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1),
          FLD(src1, 13, 3)))

FMT(s_s3_sat_x, 16, BR(0) | SAT(0) | 0x000a, BR(1) | SAT(0) | 0x040e,
    SFLDS5(FLD(dst, 4, 3), FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1),
          FLD(src1, 13, 3)))

FMT(s_s3_sat_0, 16, BR(0) | SAT(0) | 0x000a, BR(1) | SAT(1) | 0x040e,
    SFLDS5(FLD(dst, 4, 3), FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1),
          FLD(src1, 13, 3)))

FMT(s_s3_sat_1, 16, BR(0) | SAT(1) | 0x000a, BR(1) | SAT(1) |	 0x040e,
    SFLDS5(FLD(dst, 4, 3), FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1),
          FLD(src1, 13, 3)))

/* F-23 S3i Instruction Format */
FMT(s_s3i, 16, BR(0) | 0x040a, BR(1) | 0x040e,
    SFLDS5(FLD(dst, 4, 3), FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1),
           FLD(cst, 13, 3)))

/* F-24 Smvk8 Instruction Format */
FMT(s_smvk8, 16, 0x0012, 0x001e,
    SFLDS2(FLD(dst, 7, 3),
           COMPFLD(cst, BFLD4(BFLD(10, 1, 7), BFLD(5, 2, 5), BFLD(11, 2, 3), BFLD(13, 3, 0)))))

/* F-25 Ssh5 Instruction Format */
FMT(s_ssh5_sat_x, 16, SAT(0) | 0x0402, SAT(0) | 0x041e,
    SFLDS3(FLD(op, 5, 2), FLD(srcdst, 7, 3),
           COMPFLD(cst, BFLD2(BFLD(11, 2, 3), BFLD(13, 3, 0)))))
FMT(s_ssh5_sat_0, 16, SAT(0) | 0x0402, SAT(1) | 0x041e,
    SFLDS3(FLD(op, 5, 2), FLD(srcdst, 7, 3),
           COMPFLD(cst, BFLD2(BFLD(11, 2, 3), BFLD(13, 3, 0)))))
FMT(s_ssh5_sat_1, 16, SAT(1) | 0x0402, SAT(1) | 0x041e,
    SFLDS3(FLD(op, 5, 2), FLD(srcdst, 7, 3),
           COMPFLD(cst, BFLD2(BFLD(11, 2, 3), BFLD(13, 3, 0)))))

/* F-26 S2sh Instruction Format */
FMT(s_s2sh, 16, 0x0462, 0x047e,
    SFLDS3(FLD(srcdst, 7, 3), FLD(op, 11, 2), FLD(src1, 13, 3)))

/* F-27 Sc5 Instruction Format */
FMT(s_sc5, 16, 0x0002, 0x041e,
    SFLDS3(FLD(op, 5, 2), FLD(srcdst, 7, 3),
           COMPFLD(cst, BFLD2(BFLD(11, 2, 3), BFLD(13, 3, 0)))))

/* F-28 S2ext Instruction Format */
FMT(s_s2ext, 16, 0x0062, 0x047e,
    SFLDS3(FLD(src, 7, 3), FLD(op, 11, 2), FLD(dst, 13, 3)))

/* F-29 Sx2op Instruction Format */
FMT(s_sx2op, 16, 0x002e, 0x047e,
    SFLDS4(FLD(src2, 7, 3), FLD(op, 11, 1), FLD(x, 12, 1),
           FLD(srcdst, 13, 3)))

/* F-30 Sx5 Instruction Format */
FMT(s_sx5, 16, 0x042e, 0x047e,
    SFLDS2(FLD(dst, 7, 3),
           COMPFLD(cst, BFLD2(BFLD(11, 2, 3), BFLD(13, 3, 0)))))

/* F-31 Sx1 Instruction Format */
FMT(s_sx1, 16, 0x186e, 0x1c7e,
    SFLDS2(FLD(srcdst, 7, 3), FLD(op, 13, 3)))

/* F-32 Sx1b Instruction Format */
FMT(s_sx1b, 16, 0x006e, 0x187e,
    SFLDS2(FLD(src2, 7, 4), FLD(n, 13, 3)))

/* Appendix G 16-bit formats will go here.  */
FMT(lsdmvto, 16, 0x0006, 0x0066,
    SFLDS4(FLD(unit, 3, 2), 
           FLD(x, 12, 1), FLD(dst, 13, 3),
           COMPFLD(src2, BFLD2(BFLD(10, 2, 3), BFLD(7, 3, 0)))))

FMT(lsdmvfr, 16, 0x0046, 0x0066,
    SFLDS4(FLD(unit, 3, 2), FLD(src2, 7, 3), FLD(x, 12, 1),
           COMPFLD(dst, BFLD2(BFLD(10, 2, 3), BFLD(13, 3, 0)))))

/* G-3 */
FMT(lsdx1c, 16, 0x0866, 0x1c66,
    SFLDS4(FLD(unit, 3, 2), FLD(dst, 7, 3), FLD(cst, 13, 1),
           FLD(cc, 14, 2)))

/* G-4 */
FMT(lsdx1, 16, 0x1866, 0x1c66,
    SFLDS3(FLD(unit, 3, 2), FLD(srcdst, 7, 3), FLD(op, 13, 3)))

/* Appendix H 32-bit formats.  */

FMT(nfu_loop_buffer, 32, 0x00020000, 0x00021ffc,
    CFLDS4(FLD(s, 1, 1), FLD(op, 13, 4), FLD(csta, 18, 5), FLD(cstb, 23, 5)))
/* Corrected relative to Appendix H.  */
FMT(nfu_nop_idle, 32, 0x00000000, 0xfffe1ffc,
    NFLDS2(FLD(s, 1, 1), FLD(op, 13, 4)))

/* No-unit formats missing from Appendix H (given the NOP and IDLE
   correction).  */
FMT(nfu_dint, 32, 0x10004000, 0xfffffffc,
    NFLDS1(FLD(s, 1, 1)))
FMT(nfu_rint, 32, 0x10006000, 0xfffffffc,
    NFLDS1(FLD(s, 1, 1)))
FMT(nfu_swe, 32, 0x10000000, 0xfffffffc,
    NFLDS1(FLD(s, 1, 1)))
FMT(nfu_swenr, 32, 0x10002000, 0xfffffffc,
    NFLDS1(FLD(s, 1, 1)))
/* Although formally covered by the loop buffer format, the fields in
   that format are not useful for all such instructions and not all
   instructions can be predicated.  */
FMT(nfu_spkernel, 32, 0x00034000, 0xf03ffffc,
    NFLDS2(FLD(s, 1, 1), FLD(fstgfcyc, 22, 6)))
FMT(nfu_spkernelr, 32, 0x00036000, 0xfffffffc,
    NFLDS1(FLD(s, 1, 1)))
FMT(nfu_spmask, 32, 0x00020000, 0xfc021ffc,
    NFLDS3(FLD(s, 1, 1), FLD(op, 13, 4), FLD(mask, 18, 8)))

/* Appendix H 16-bit formats will go here.  */

/* H-5 */
FMT(nfu_uspl, 16, 0x0c66, 0xbc7e,
   FLDS2(FLD(op, 0, 1), COMPFLD(ii, BFLD2(BFLD(7, 3, 0), BFLD(14, 1, 3)))))

/* H-6 */
/* make up some fields to pretend to have s and z fields s for this format
   so as to fit in other predicated compact instruction to avoid special-
   casing this instruction in tic6x-dis.c 
   use op field as a predicate adress register selector (s field)
   use the first zeroed bit as a z value as this insn only supports [a0]
   and [b0] predicate forms.
*/
FMT(nfu_uspldr, 16, 0x8c66, 0xbc7e,
   FLDS4(FLD(op, 0, 1), FLD(s, 0, 1), FLD(z, 3, 1),
         COMPFLD(ii, BFLD2(BFLD(7, 3, 0), BFLD(14, 1, 3)))))

/* H-7 */
FMT(nfu_uspk, 16, 0x1c66, 0x3c7e,
   FLDS1(COMPFLD(fstgfcyc, BFLD3(BFLD(0, 1, 0), BFLD(7, 3, 1), BFLD(14, 2, 4)))))

/* H-8a */
FMT(nfu_uspma, 16, 0x2c66, 0x3c7e,
   FLDS1(COMPFLD(mask, BFLD3(BFLD(0, 1, 0), BFLD(7, 3, 1), BFLD(14, 2, 4)))))

/* H-8b */
FMT(nfu_uspmb, 16, 0x3c66, 0x3c7e,
   FLDS1(COMPFLD(mask, BFLD3(BFLD(0, 1, 0), BFLD(7, 3, 1), BFLD(14, 2, 4)))))

/* H-9 */
FMT(nfu_unop, 16, 0x0c6e, 0x1fff,
   FLDS1(FLD(n, 13, 3)))

#undef FLD
#undef CFLDS
#undef CFLDS2
#undef CFLDS3
#undef CFLDS4
#undef CFLDS5
#undef CFLDS6
#undef CFLDS7
#undef CFLDS8
#undef NFLDS
#undef NFLDS1
#undef NFLDS2
#undef NFLDS3
#undef NFLDS5
#undef NFLDS6
#undef NFLDS7
#undef SFLDS
#undef SFLDS1
#undef SFLDS2
#undef SFLDS3
#undef SFLDS4
#undef SFLDS5
#undef SFLDS6
#undef SFLDS7
#undef BFLD
#undef BFLD1
#undef BFLD2
#undef BFLD3
#undef BFLD4
#undef FLDS1
#undef FLDS2
#undef FLDS3
#undef FLDS4
#undef FLDS5
#undef COMPFLD
#undef DSZ
#undef BR
#undef SAT
