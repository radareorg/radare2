/* aarch64-dis.h -- Header file for aarch64-dis.c and aarch64-dis-2.c.
   Copyright (C) 2012-2018 Free Software Foundation, Inc.
   Contributed by ARM Ltd.

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
   along with this program; see the file COPYING3. If not,
   see <http://www.gnu.org/licenses/>.  */

#ifndef OPCODES_AARCH64_DIS_H
#define OPCODES_AARCH64_DIS_H
// #include "bfd_stdint.h"
#include "aarch64-opc.h"

/* Lookup opcode WORD in the opcode table.

   In the case of multiple aarch64_opcode candidates, one of them will be
   returned; for other candidate(s), call aarch64_find_next_opcode to
   obtain.  Note that aarch64_find_next_opcode finds the next
   aarch64_opcode candidate in a way as if all related aarch64_opcode
   entries were in a single-link list.

   N.B. all alias opcodes are ignored here.  */

const aarch64_opcode* aarch64_opcode_lookup (uint32_t);
const aarch64_opcode* aarch64_find_next_opcode (const aarch64_opcode *);

/* Given OPCODE, return its alias, e.g. given UBFM, return LSL.

   In the case of multiple alias candidates, the one of the highest priority
   (or one of several aliases of the same highest priority) will be
   returned; for the other candidate(s), call aarch64_find_next_alias_opcode
   to obtain.  Note that aarch64_find_next_alias_opcode finds the next
   alias candidate in a way as if all related aliases were in a single-link
   list with priority from the highest to the least.  */

const aarch64_opcode* aarch64_find_alias_opcode (const aarch64_opcode *);
const aarch64_opcode* aarch64_find_next_alias_opcode (const aarch64_opcode *);

/* Switch-table-based high-level operand extractor.  */

bfd_boolean
aarch64_extract_operand (const aarch64_operand *, aarch64_opnd_info *,
			 const aarch64_insn, const aarch64_inst *,
			 aarch64_operand_error *);

/* Operand extractors.  */

#define AARCH64_DECL_OPD_EXTRACTOR(x)	\
  bfd_boolean aarch64_##x (const aarch64_operand *, aarch64_opnd_info *, \
			   const aarch64_insn, const aarch64_inst *, \
			   aarch64_operand_error *)

AARCH64_DECL_OPD_EXTRACTOR (ext_regno);
AARCH64_DECL_OPD_EXTRACTOR (ext_regno_pair);
AARCH64_DECL_OPD_EXTRACTOR (ext_regrt_sysins);
AARCH64_DECL_OPD_EXTRACTOR (ext_reglane);
AARCH64_DECL_OPD_EXTRACTOR (ext_reglist);
AARCH64_DECL_OPD_EXTRACTOR (ext_ldst_reglist);
AARCH64_DECL_OPD_EXTRACTOR (ext_ldst_reglist_r);
AARCH64_DECL_OPD_EXTRACTOR (ext_ldst_elemlist);
AARCH64_DECL_OPD_EXTRACTOR (ext_advsimd_imm_shift);
AARCH64_DECL_OPD_EXTRACTOR (ext_shll_imm);
AARCH64_DECL_OPD_EXTRACTOR (ext_imm);
AARCH64_DECL_OPD_EXTRACTOR (ext_imm_half);
AARCH64_DECL_OPD_EXTRACTOR (ext_advsimd_imm_modified);
AARCH64_DECL_OPD_EXTRACTOR (ext_fpimm);
AARCH64_DECL_OPD_EXTRACTOR (ext_fbits);
AARCH64_DECL_OPD_EXTRACTOR (ext_aimm);
AARCH64_DECL_OPD_EXTRACTOR (ext_limm);
AARCH64_DECL_OPD_EXTRACTOR (ext_inv_limm);
AARCH64_DECL_OPD_EXTRACTOR (ext_ft);
AARCH64_DECL_OPD_EXTRACTOR (ext_addr_simple);
AARCH64_DECL_OPD_EXTRACTOR (ext_addr_offset);
AARCH64_DECL_OPD_EXTRACTOR (ext_addr_regoff);
AARCH64_DECL_OPD_EXTRACTOR (ext_addr_simm);
AARCH64_DECL_OPD_EXTRACTOR (ext_addr_simm10);
AARCH64_DECL_OPD_EXTRACTOR (ext_addr_uimm12);
AARCH64_DECL_OPD_EXTRACTOR (ext_simd_addr_post);
AARCH64_DECL_OPD_EXTRACTOR (ext_cond);
AARCH64_DECL_OPD_EXTRACTOR (ext_sysreg);
AARCH64_DECL_OPD_EXTRACTOR (ext_pstatefield);
AARCH64_DECL_OPD_EXTRACTOR (ext_sysins_op);
AARCH64_DECL_OPD_EXTRACTOR (ext_barrier);
AARCH64_DECL_OPD_EXTRACTOR (ext_hint);
AARCH64_DECL_OPD_EXTRACTOR (ext_prfop);
AARCH64_DECL_OPD_EXTRACTOR (ext_reg_extended);
AARCH64_DECL_OPD_EXTRACTOR (ext_reg_shifted);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_ri_s4);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_ri_s4xvl);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_ri_s6xvl);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_ri_s9xvl);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_ri_u6);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_rr_lsl);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_rz_xtw);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_zi_u5);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_zz_lsl);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_zz_sxtw);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_addr_zz_uxtw);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_aimm);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_asimm);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_float_half_one);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_float_half_two);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_float_zero_one);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_index);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_limm_mov);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_quad_index);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_reglist);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_scale);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_shlimm);
AARCH64_DECL_OPD_EXTRACTOR (ext_sve_shrimm);
AARCH64_DECL_OPD_EXTRACTOR (ext_imm_rotate1);
AARCH64_DECL_OPD_EXTRACTOR (ext_imm_rotate2);

#undef AARCH64_DECL_OPD_EXTRACTOR

#endif /* OPCODES_AARCH64_DIS_H */
