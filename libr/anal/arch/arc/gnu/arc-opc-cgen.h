/* Instruction opcode header for arc.

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

#ifndef ARC_OPC_CGEN_H
#define ARC_OPC_CGEN_H

/* -- opc.h */

#undef  CGEN_DIS_HASH_SIZE
#define CGEN_DIS_HASH_SIZE 1024
#undef  CGEN_DIS_HASH
#define CGEN_DIS_HASH(buffer, value, big_p) \
  arc_cgen_dis_hash (buffer, big_p)
extern unsigned int arc_cgen_dis_hash (const char *, int);
/* Override CGEN_INSN_BITSIZE for sim/common/cgen-trace.c .
   insn extraction for simulation is fine with 32 bits, since we fetch long
   immediates as part of the semantics if required, but for disassembly
   we must make sure we read all the bits while we have the information how
   to read them.  */
#define CGEN_INSN_DISASM_BITSIZE(insn) 64
extern char arc_limm_str[];

/* cgen can't generate correct decoders for variable-length insns,
   so we have it generate a decoder that assumes all insns are 32 bit.
   And even if the decoder generator bug were fixed, having the decoder
   understand long immediates would be messy.
   The simulator calculates instruction sizes as part of the semantics.
   For disassembly, we redefine CGEN_EXTRACT_FN so that we can correct
   the calculated instruction length.  */
#undef CGEN_EXTRACT_FN
#define CGEN_EXTRACT_FN(cd, insn) ARC_CGEN_EXTRACT_FN
extern int arc_insn_length (unsigned long insn_value, const CGEN_INSN *insn,
			   CGEN_EXTRACT_INFO *info, bfd_vma pc);
static inline int
ARC_CGEN_EXTRACT_FN (CGEN_CPU_DESC cd, const CGEN_INSN *insn,
		     CGEN_EXTRACT_INFO *info, CGEN_INSN_INT insn_value,
		     CGEN_FIELDS *fields, bfd_vma pc)
{
  static int initialized = 0;
  /* ??? There is no suitable hook for one-time initialization.  */
  if (!initialized)
    {
      static CGEN_KEYWORD_ENTRY arc_cgen_opval_limm_entry0 =
	{ arc_limm_str, 62, {0, {{{0, 0}}}}, 0, 0 };
      static CGEN_KEYWORD_ENTRY arc_cgen_opval_limm_entry1 =
	{ arc_limm_str, 62, {0, {{{0, 0}}}}, 0, 0 };

      cgen_keyword_add (&arc_cgen_opval_cr_names, &arc_cgen_opval_limm_entry0);
      cgen_keyword_add (&arc_cgen_opval_h_noilink, &arc_cgen_opval_limm_entry1);
      initialized = 1;
    }
  /* ??? sim/common/cgen-trace.c:sim_cgen_disassemble_insn uses its own
     home-brewn instruction target-to-host conversion, which gets the
     endianness wrong for ARC.  */
  if (cd->endian == CGEN_ENDIAN_LITTLE)
    insn_value = ((insn_value >> 16) & 0xffff) | (insn_value << 16);

  /* First, do the normal extract handler call, but ignore its value.  */
  ((cd)->extract_handlers[(insn)->opcode->handlers.extract]
    (cd, insn, info, insn_value, fields, pc));
  /* Now calculate the actual insn length, and extract any long immediate
     if present.  */
  return arc_insn_length (insn_value, insn, info, pc);
}

/* -- */
/* Enum declaration for arc instruction types.  */
typedef enum cgen_insn_type {
  ARC_INSN_INVALID, ARC_INSN_B_S, ARC_INSN_BCC_S, ARC_INSN_BRCC_S
 , ARC_INSN_BCC_L, ARC_INSN_BCC_L_D, ARC_INSN_B_L, ARC_INSN_B_L_D
 , ARC_INSN_BRCC_RC, ARC_INSN_BRCC_RC_D, ARC_INSN_BRCC_U6, ARC_INSN_BRCC_U6_D
 , ARC_INSN_BL_S, ARC_INSN_BLCC, ARC_INSN_BLCC_D, ARC_INSN_BL
 , ARC_INSN_BL_D, ARC_INSN_LD_ABS, ARC_INSN_LD__AW_ABS, ARC_INSN_LD_AB_ABS
 , ARC_INSN_LD_AS_ABS, ARC_INSN_LD_ABC, ARC_INSN_LD__AW_ABC, ARC_INSN_LD_AB_ABC
 , ARC_INSN_LD_AS_ABC, ARC_INSN_LD_S_ABC, ARC_INSN_LD_S_ABU, ARC_INSN_LD_S_ABSP
 , ARC_INSN_LD_S_GPREL, ARC_INSN_LD_S_PCREL, ARC_INSN_LDB_ABS, ARC_INSN_LDB__AW_ABS
 , ARC_INSN_LDB_AB_ABS, ARC_INSN_LDB_AS_ABS, ARC_INSN_LDB_ABC, ARC_INSN_LDB__AW_ABC
 , ARC_INSN_LDB_AB_ABC, ARC_INSN_LDB_AS_ABC, ARC_INSN_LDB_S_ABC, ARC_INSN_LDB_S_ABU
 , ARC_INSN_LDB_S_ABSP, ARC_INSN_LDB_S_GPREL, ARC_INSN_LDB_X_ABS, ARC_INSN_LDB__AW_X_ABS
 , ARC_INSN_LDB_AB_X_ABS, ARC_INSN_LDB_AS_X_ABS, ARC_INSN_LDB_X_ABC, ARC_INSN_LDB__AW_X_ABC
 , ARC_INSN_LDB_AB_X_ABC, ARC_INSN_LDB_AS_X_ABC, ARC_INSN_LDW_ABS, ARC_INSN_LDW__AW_ABS
 , ARC_INSN_LDW_AB_ABS, ARC_INSN_LDW_AS_ABS, ARC_INSN_LDW_ABC, ARC_INSN_LDW__AW_ABC
 , ARC_INSN_LDW_AB_ABC, ARC_INSN_LDW_AS_ABC, ARC_INSN_LDW_S_ABC, ARC_INSN_LDW_S_ABU
 , ARC_INSN_LDW_S_GPREL, ARC_INSN_LDW_X_ABS, ARC_INSN_LDW__AW_X_ABS, ARC_INSN_LDW_AB_X_ABS
 , ARC_INSN_LDW_AS_X_ABS, ARC_INSN_LDW_X_ABC, ARC_INSN_LDW__AW_X_ABC, ARC_INSN_LDW_AB_X_ABC
 , ARC_INSN_LDW_AS_X_ABC, ARC_INSN_LDW_S_X_ABU, ARC_INSN_ST_ABS, ARC_INSN_ST__AW_ABS
 , ARC_INSN_ST_AB_ABS, ARC_INSN_ST_AS_ABS, ARC_INSN_ST_S_ABU, ARC_INSN_ST_S_ABSP
 , ARC_INSN_STB_ABS, ARC_INSN_STB__AW_ABS, ARC_INSN_STB_AB_ABS, ARC_INSN_STB_AS_ABS
 , ARC_INSN_STB_S_ABU, ARC_INSN_STB_S_ABSP, ARC_INSN_STW_ABS, ARC_INSN_STW__AW_ABS
 , ARC_INSN_STW_AB_ABS, ARC_INSN_STW_AS_ABS, ARC_INSN_STW_S_ABU, ARC_INSN_ADD_L_S12__RA_
 , ARC_INSN_ADD_CCU6__RA_, ARC_INSN_ADD_L_U6__RA_, ARC_INSN_ADD_L_R_R__RA__RC, ARC_INSN_ADD_CC__RA__RC
 , ARC_INSN_ADD_S_ABC, ARC_INSN_ADD_S_CBU3, ARC_INSN_ADD_S_MCAH, ARC_INSN_ADD_S_ABSP
 , ARC_INSN_ADD_S_ASSPSP, ARC_INSN_ADD_S_GP, ARC_INSN_ADD_S_R_U7, ARC_INSN_ADC_L_S12__RA_
 , ARC_INSN_ADC_CCU6__RA_, ARC_INSN_ADC_L_U6__RA_, ARC_INSN_ADC_L_R_R__RA__RC, ARC_INSN_ADC_CC__RA__RC
 , ARC_INSN_SUB_L_S12__RA_, ARC_INSN_SUB_CCU6__RA_, ARC_INSN_SUB_L_U6__RA_, ARC_INSN_SUB_L_R_R__RA__RC
 , ARC_INSN_SUB_CC__RA__RC, ARC_INSN_SUB_S_CBU3, ARC_INSN_I16_GO_SUB_S_GO, ARC_INSN_SUB_S_GO_SUB_NE
 , ARC_INSN_SUB_S_SSB, ARC_INSN_SUB_S_ASSPSP, ARC_INSN_SBC_L_S12__RA_, ARC_INSN_SBC_CCU6__RA_
 , ARC_INSN_SBC_L_U6__RA_, ARC_INSN_SBC_L_R_R__RA__RC, ARC_INSN_SBC_CC__RA__RC, ARC_INSN_AND_L_S12__RA_
 , ARC_INSN_AND_CCU6__RA_, ARC_INSN_AND_L_U6__RA_, ARC_INSN_AND_L_R_R__RA__RC, ARC_INSN_AND_CC__RA__RC
 , ARC_INSN_I16_GO_AND_S_GO, ARC_INSN_OR_L_S12__RA_, ARC_INSN_OR_CCU6__RA_, ARC_INSN_OR_L_U6__RA_
 , ARC_INSN_OR_L_R_R__RA__RC, ARC_INSN_OR_CC__RA__RC, ARC_INSN_I16_GO_OR_S_GO, ARC_INSN_BIC_L_S12__RA_
 , ARC_INSN_BIC_CCU6__RA_, ARC_INSN_BIC_L_U6__RA_, ARC_INSN_BIC_L_R_R__RA__RC, ARC_INSN_BIC_CC__RA__RC
 , ARC_INSN_I16_GO_BIC_S_GO, ARC_INSN_XOR_L_S12__RA_, ARC_INSN_XOR_CCU6__RA_, ARC_INSN_XOR_L_U6__RA_
 , ARC_INSN_XOR_L_R_R__RA__RC, ARC_INSN_XOR_CC__RA__RC, ARC_INSN_I16_GO_XOR_S_GO, ARC_INSN_MAX_L_S12__RA_
 , ARC_INSN_MAX_CCU6__RA_, ARC_INSN_MAX_L_U6__RA_, ARC_INSN_MAX_L_R_R__RA__RC, ARC_INSN_MAX_CC__RA__RC
 , ARC_INSN_MIN_L_S12__RA_, ARC_INSN_MIN_CCU6__RA_, ARC_INSN_MIN_L_U6__RA_, ARC_INSN_MIN_L_R_R__RA__RC
 , ARC_INSN_MIN_CC__RA__RC, ARC_INSN_MOV_L_S12_, ARC_INSN_MOV_CCU6_, ARC_INSN_MOV_L_U6_
 , ARC_INSN_MOV_L_R_R__RC, ARC_INSN_MOV_CC__RC, ARC_INSN_MOV_S_MCAH, ARC_INSN_MOV_S_MCAHB
 , ARC_INSN_MOV_S_R_U7, ARC_INSN_TST_L_S12_, ARC_INSN_TST_CCU6_, ARC_INSN_TST_L_U6_
 , ARC_INSN_TST_L_R_R__RC, ARC_INSN_TST_CC__RC, ARC_INSN_TST_S_GO, ARC_INSN_CMP_L_S12_
 , ARC_INSN_CMP_CCU6_, ARC_INSN_CMP_L_U6_, ARC_INSN_CMP_L_R_R__RC, ARC_INSN_CMP_CC__RC
 , ARC_INSN_CMP_S_MCAH, ARC_INSN_CMP_S_R_U7, ARC_INSN_RCMP_L_S12_, ARC_INSN_RCMP_CCU6_
 , ARC_INSN_RCMP_L_U6_, ARC_INSN_RCMP_L_R_R__RC, ARC_INSN_RCMP_CC__RC, ARC_INSN_RSUB_L_S12__RA_
 , ARC_INSN_RSUB_CCU6__RA_, ARC_INSN_RSUB_L_U6__RA_, ARC_INSN_RSUB_L_R_R__RA__RC, ARC_INSN_RSUB_CC__RA__RC
 , ARC_INSN_BSET_L_S12__RA_, ARC_INSN_BSET_CCU6__RA_, ARC_INSN_BSET_L_U6__RA_, ARC_INSN_BSET_L_R_R__RA__RC
 , ARC_INSN_BSET_CC__RA__RC, ARC_INSN_BSET_S_SSB, ARC_INSN_BCLR_L_S12__RA_, ARC_INSN_BCLR_CCU6__RA_
 , ARC_INSN_BCLR_L_U6__RA_, ARC_INSN_BCLR_L_R_R__RA__RC, ARC_INSN_BCLR_CC__RA__RC, ARC_INSN_BCLR_S_SSB
 , ARC_INSN_BTST_L_S12_, ARC_INSN_BTST_CCU6_, ARC_INSN_BTST_L_U6_, ARC_INSN_BTST_L_R_R__RC
 , ARC_INSN_BTST_CC__RC, ARC_INSN_BTST_S_SSB, ARC_INSN_BXOR_L_S12__RA_, ARC_INSN_BXOR_CCU6__RA_
 , ARC_INSN_BXOR_L_U6__RA_, ARC_INSN_BXOR_L_R_R__RA__RC, ARC_INSN_BXOR_CC__RA__RC, ARC_INSN_BMSK_L_S12__RA_
 , ARC_INSN_BMSK_CCU6__RA_, ARC_INSN_BMSK_L_U6__RA_, ARC_INSN_BMSK_L_R_R__RA__RC, ARC_INSN_BMSK_CC__RA__RC
 , ARC_INSN_BMSK_S_SSB, ARC_INSN_ADD1_L_S12__RA_, ARC_INSN_ADD1_CCU6__RA_, ARC_INSN_ADD1_L_U6__RA_
 , ARC_INSN_ADD1_L_R_R__RA__RC, ARC_INSN_ADD1_CC__RA__RC, ARC_INSN_I16_GO_ADD1_S_GO, ARC_INSN_ADD2_L_S12__RA_
 , ARC_INSN_ADD2_CCU6__RA_, ARC_INSN_ADD2_L_U6__RA_, ARC_INSN_ADD2_L_R_R__RA__RC, ARC_INSN_ADD2_CC__RA__RC
 , ARC_INSN_I16_GO_ADD2_S_GO, ARC_INSN_ADD3_L_S12__RA_, ARC_INSN_ADD3_CCU6__RA_, ARC_INSN_ADD3_L_U6__RA_
 , ARC_INSN_ADD3_L_R_R__RA__RC, ARC_INSN_ADD3_CC__RA__RC, ARC_INSN_I16_GO_ADD3_S_GO, ARC_INSN_SUB1_L_S12__RA_
 , ARC_INSN_SUB1_CCU6__RA_, ARC_INSN_SUB1_L_U6__RA_, ARC_INSN_SUB1_L_R_R__RA__RC, ARC_INSN_SUB1_CC__RA__RC
 , ARC_INSN_SUB2_L_S12__RA_, ARC_INSN_SUB2_CCU6__RA_, ARC_INSN_SUB2_L_U6__RA_, ARC_INSN_SUB2_L_R_R__RA__RC
 , ARC_INSN_SUB2_CC__RA__RC, ARC_INSN_SUB3_L_S12__RA_, ARC_INSN_SUB3_CCU6__RA_, ARC_INSN_SUB3_L_U6__RA_
 , ARC_INSN_SUB3_L_R_R__RA__RC, ARC_INSN_SUB3_CC__RA__RC, ARC_INSN_MPY_L_S12__RA_, ARC_INSN_MPY_CCU6__RA_
 , ARC_INSN_MPY_L_U6__RA_, ARC_INSN_MPY_L_R_R__RA__RC, ARC_INSN_MPY_CC__RA__RC, ARC_INSN_MPYH_L_S12__RA_
 , ARC_INSN_MPYH_CCU6__RA_, ARC_INSN_MPYH_L_U6__RA_, ARC_INSN_MPYH_L_R_R__RA__RC, ARC_INSN_MPYH_CC__RA__RC
 , ARC_INSN_MPYHU_L_S12__RA_, ARC_INSN_MPYHU_CCU6__RA_, ARC_INSN_MPYHU_L_U6__RA_, ARC_INSN_MPYHU_L_R_R__RA__RC
 , ARC_INSN_MPYHU_CC__RA__RC, ARC_INSN_MPYU_L_S12__RA_, ARC_INSN_MPYU_CCU6__RA_, ARC_INSN_MPYU_L_U6__RA_
 , ARC_INSN_MPYU_L_R_R__RA__RC, ARC_INSN_MPYU_CC__RA__RC, ARC_INSN_J_L_R_R___RC_NOILINK_, ARC_INSN_J_CC___RC_NOILINK_
 , ARC_INSN_J_L_R_R___RC_ILINK_, ARC_INSN_J_CC___RC_ILINK_, ARC_INSN_J_L_S12_, ARC_INSN_J_CCU6_
 , ARC_INSN_J_L_U6_, ARC_INSN_J_S, ARC_INSN_J_S__S, ARC_INSN_J_SEQ__S
 , ARC_INSN_J_SNE__S, ARC_INSN_J_L_S12_D_, ARC_INSN_J_CCU6_D_, ARC_INSN_J_L_U6_D_
 , ARC_INSN_J_L_R_R_D___RC_, ARC_INSN_J_CC_D___RC_, ARC_INSN_J_S_D, ARC_INSN_J_S__S_D
 , ARC_INSN_JL_L_S12_, ARC_INSN_JL_CCU6_, ARC_INSN_JL_L_U6_, ARC_INSN_JL_S
 , ARC_INSN_JL_L_R_R___RC_NOILINK_, ARC_INSN_JL_CC___RC_NOILINK_, ARC_INSN_JL_L_S12_D_, ARC_INSN_JL_CCU6_D_
 , ARC_INSN_JL_L_U6_D_, ARC_INSN_JL_L_R_R_D___RC_, ARC_INSN_JL_CC_D___RC_, ARC_INSN_JL_S_D
 , ARC_INSN_LP_L_S12_, ARC_INSN_LPCC_CCU6, ARC_INSN_FLAG_L_S12_, ARC_INSN_FLAG_CCU6_
 , ARC_INSN_FLAG_L_U6_, ARC_INSN_FLAG_L_R_R__RC, ARC_INSN_FLAG_CC__RC, ARC_INSN_LR_L_R_R___RC_
 , ARC_INSN_LR_L_S12_, ARC_INSN_SR_L_R_R___RC_, ARC_INSN_SR_L_S12_, ARC_INSN_ASL_L_R_R__RC
 , ARC_INSN_ASL_L_U6_, ARC_INSN_I16_GO_ASL_S_GO, ARC_INSN_ASR_L_R_R__RC, ARC_INSN_ASR_L_U6_
 , ARC_INSN_I16_GO_ASR_S_GO, ARC_INSN_LSR_L_R_R__RC, ARC_INSN_LSR_L_U6_, ARC_INSN_I16_GO_LSR_S_GO
 , ARC_INSN_ROR_L_R_R__RC, ARC_INSN_ROR_L_U6_, ARC_INSN_RRC_L_R_R__RC, ARC_INSN_RRC_L_U6_
 , ARC_INSN_SEXB_L_R_R__RC, ARC_INSN_SEXB_L_U6_, ARC_INSN_I16_GO_SEXB_S_GO, ARC_INSN_SEXW_L_R_R__RC
 , ARC_INSN_SEXW_L_U6_, ARC_INSN_I16_GO_SEXW_S_GO, ARC_INSN_EXTB_L_R_R__RC, ARC_INSN_EXTB_L_U6_
 , ARC_INSN_I16_GO_EXTB_S_GO, ARC_INSN_EXTW_L_R_R__RC, ARC_INSN_EXTW_L_U6_, ARC_INSN_I16_GO_EXTW_S_GO
 , ARC_INSN_ABS_L_R_R__RC, ARC_INSN_ABS_L_U6_, ARC_INSN_I16_GO_ABS_S_GO, ARC_INSN_NOT_L_R_R__RC
 , ARC_INSN_NOT_L_U6_, ARC_INSN_I16_GO_NOT_S_GO, ARC_INSN_RLC_L_R_R__RC, ARC_INSN_RLC_L_U6_
 , ARC_INSN_EX_L_R_R__RC, ARC_INSN_EX_L_U6_, ARC_INSN_I16_GO_NEG_S_GO, ARC_INSN_SWI
 , ARC_INSN_TRAP_S, ARC_INSN_BRK, ARC_INSN_BRK_S, ARC_INSN_ASL_L_S12__RA_
 , ARC_INSN_ASL_CCU6__RA_, ARC_INSN_ASL_L_U6__RA_, ARC_INSN_ASL_L_R_R__RA__RC, ARC_INSN_ASL_CC__RA__RC
 , ARC_INSN_ASL_S_CBU3, ARC_INSN_ASL_S_SSB, ARC_INSN_I16_GO_ASLM_S_GO, ARC_INSN_LSR_L_S12__RA_
 , ARC_INSN_LSR_CCU6__RA_, ARC_INSN_LSR_L_U6__RA_, ARC_INSN_LSR_L_R_R__RA__RC, ARC_INSN_LSR_CC__RA__RC
 , ARC_INSN_LSR_S_SSB, ARC_INSN_I16_GO_LSRM_S_GO, ARC_INSN_ASR_L_S12__RA_, ARC_INSN_ASR_CCU6__RA_
 , ARC_INSN_ASR_L_U6__RA_, ARC_INSN_ASR_L_R_R__RA__RC, ARC_INSN_ASR_CC__RA__RC, ARC_INSN_ASR_S_CBU3
 , ARC_INSN_ASR_S_SSB, ARC_INSN_I16_GO_ASRM_S_GO, ARC_INSN_ROR_L_S12__RA_, ARC_INSN_ROR_CCU6__RA_
 , ARC_INSN_ROR_L_U6__RA_, ARC_INSN_ROR_L_R_R__RA__RC, ARC_INSN_ROR_CC__RA__RC, ARC_INSN_MUL64_L_S12_
 , ARC_INSN_MUL64_CCU6_, ARC_INSN_MUL64_L_U6_, ARC_INSN_MUL64_L_R_R__RC, ARC_INSN_MUL64_CC__RC
 , ARC_INSN_MUL64_S_GO, ARC_INSN_MULU64_L_S12_, ARC_INSN_MULU64_CCU6_, ARC_INSN_MULU64_L_U6_
 , ARC_INSN_MULU64_L_R_R__RC, ARC_INSN_MULU64_CC__RC, ARC_INSN_ADDS_L_S12__RA_, ARC_INSN_ADDS_CCU6__RA_
 , ARC_INSN_ADDS_L_U6__RA_, ARC_INSN_ADDS_L_R_R__RA__RC, ARC_INSN_ADDS_CC__RA__RC, ARC_INSN_SUBS_L_S12__RA_
 , ARC_INSN_SUBS_CCU6__RA_, ARC_INSN_SUBS_L_U6__RA_, ARC_INSN_SUBS_L_R_R__RA__RC, ARC_INSN_SUBS_CC__RA__RC
 , ARC_INSN_DIVAW_L_S12__RA_, ARC_INSN_DIVAW_CCU6__RA_, ARC_INSN_DIVAW_L_U6__RA_, ARC_INSN_DIVAW_L_R_R__RA__RC
 , ARC_INSN_DIVAW_CC__RA__RC, ARC_INSN_ASLS_L_S12__RA_, ARC_INSN_ASLS_CCU6__RA_, ARC_INSN_ASLS_L_U6__RA_
 , ARC_INSN_ASLS_L_R_R__RA__RC, ARC_INSN_ASLS_CC__RA__RC, ARC_INSN_ASRS_L_S12__RA_, ARC_INSN_ASRS_CCU6__RA_
 , ARC_INSN_ASRS_L_U6__RA_, ARC_INSN_ASRS_L_R_R__RA__RC, ARC_INSN_ASRS_CC__RA__RC, ARC_INSN_ADDSDW_L_S12__RA_
 , ARC_INSN_ADDSDW_CCU6__RA_, ARC_INSN_ADDSDW_L_U6__RA_, ARC_INSN_ADDSDW_L_R_R__RA__RC, ARC_INSN_ADDSDW_CC__RA__RC
 , ARC_INSN_SUBSDW_L_S12__RA_, ARC_INSN_SUBSDW_CCU6__RA_, ARC_INSN_SUBSDW_L_U6__RA_, ARC_INSN_SUBSDW_L_R_R__RA__RC
 , ARC_INSN_SUBSDW_CC__RA__RC, ARC_INSN_SWAP_L_R_R__RC, ARC_INSN_SWAP_L_U6_, ARC_INSN_NORM_L_R_R__RC
 , ARC_INSN_NORM_L_U6_, ARC_INSN_RND16_L_R_R__RC, ARC_INSN_RND16_L_U6_, ARC_INSN_ABSSW_L_R_R__RC
 , ARC_INSN_ABSSW_L_U6_, ARC_INSN_ABSS_L_R_R__RC, ARC_INSN_ABSS_L_U6_, ARC_INSN_NEGSW_L_R_R__RC
 , ARC_INSN_NEGSW_L_U6_, ARC_INSN_NEGS_L_R_R__RC, ARC_INSN_NEGS_L_U6_, ARC_INSN_NORMW_L_R_R__RC
 , ARC_INSN_NORMW_L_U6_, ARC_INSN_NOP_S, ARC_INSN_UNIMP_S, ARC_INSN_POP_S_B
 , ARC_INSN_POP_S_BLINK, ARC_INSN_PUSH_S_B, ARC_INSN_PUSH_S_BLINK, ARC_INSN_CURRENT_LOOP_END
 , ARC_INSN_CURRENT_LOOP_END_AFTER_BRANCH
} CGEN_INSN_TYPE;

/* Index of `invalid' insn place holder.  */
#define CGEN_INSN_INVALID ARC_INSN_INVALID

/* Total number of insns in table.  */
#define MAX_INSNS ((int) ARC_INSN_CURRENT_LOOP_END_AFTER_BRANCH + 1)

/* This struct records data prior to insertion or after extraction.  */
struct cgen_fields
{
  int length;
  long f_nil;
  long f_anyof;
  long f_cond_Q;
  long f_cond_i2;
  long f_cond_i3;
  long f_brcond;
  long f_op__a;
  long f_op__b;
  long f_op__c;
  long f_B_5_3;
  long f_op_B;
  long f_op_C;
  long f_op_Cj;
  long f_h_2_0;
  long f_h_5_3;
  long f_op_h;
  long f_u6;
  long f_u6x2;
  long f_delay_N;
  long f_res27;
  long f_F;
  long f_cbranch_imm;
  long f_op_A;
  long f_s12h;
  long f_s12;
  long f_s12x2;
  long f_rel10;
  long f_rel7;
  long f_rel8;
  long f_rel13bl;
  long f_d21l;
  long f_d21bl;
  long f_d21h;
  long f_d25m;
  long f_d25h;
  long f_rel21;
  long f_rel21bl;
  long f_rel25;
  long f_rel25bl;
  long f_d9l;
  long f_d9h;
  long f_rel9;
  long f_u3;
  long f_u5;
  long f_u7;
  long f_u8;
  long f_s9;
  long f_u5x2;
  long f_u5x4;
  long f_u8x4;
  long f_s9x1;
  long f_s9x2;
  long f_s9x4;
  long f_dummy;
  long f_opm;
  long f_go_type;
  long f_go_cc_type;
  long f_go_op;
  long f_i16_43;
  long f_i16_go;
  long f_i16_gp_type;
  long f_i16addcmpu7_type;
  long f_buf;
  long f_br;
  long f_bluf;
  long f_brscond;
  long f_ldozzx;
  long f_ldr6zzx;
  long f_stozzr;
  long f_ldoaa;
  long f_ldraa;
  long f_stoaa;
  long f_LDODi;
  long f_LDRDi;
  long f_STODi;
  long f_trapnum;
};

#define CGEN_INIT_PARSE(od) \
{\
}
#define CGEN_INIT_INSERT(od) \
{\
}
#define CGEN_INIT_EXTRACT(od) \
{\
}
#define CGEN_INIT_PRINT(od) \
{\
}


#endif /* ARC_OPC_CGEN_H */
