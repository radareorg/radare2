/* GENERATED FILE - DO NOT MODIFY - SUBMIT GITHUB ISSUE IF PROBLEM FOUND */

#include <stddef.h>
#include <stdbool.h>

#include "operations.h"
#include "encodings.h"
#include "arm64dis.h"
#include "decode2.h"
#include "pcode.h"

int decode_iclass_sve_int_bin_pred_log(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return orr_z_p_zz(ctx, dec); // -> orr_z_p_zz_
	if(opc==1) return eor_z_p_zz(ctx, dec); // -> eor_z_p_zz_
	if(opc==2) return and_z_p_zz(ctx, dec); // -> and_z_p_zz_
	if(opc==3) return bic_z_p_zz(ctx, dec); // -> bic_z_p_zz_
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_144);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_arit_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return add_z_p_zz(ctx, dec); // -> add_z_p_zz_
	if(opc==1) return sub_z_p_zz(ctx, dec); // -> sub_z_p_zz_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_128);
	if(opc==3) return subr_z_p_zz(ctx, dec); // -> subr_z_p_zz_
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_131);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_div(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!R && !U) return sdiv_z_p_zz(ctx, dec); // -> sdiv_z_p_zz_
	if(!R && U) return udiv_z_p_zz(ctx, dec); // -> udiv_z_p_zz_
	if(R && !U) return sdivr_z_p_zz(ctx, dec); // -> sdivr_z_p_zz_
	if(R && U) return udivr_z_p_zz(ctx, dec); // -> udivr_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_arit_1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(!opc && !U) return smax_z_p_zz(ctx, dec); // -> smax_z_p_zz_
	if(!opc && U) return umax_z_p_zz(ctx, dec); // -> umax_z_p_zz_
	if(opc==1 && !U) return smin_z_p_zz(ctx, dec); // -> smin_z_p_zz_
	if(opc==1 && U) return umin_z_p_zz(ctx, dec); // -> umin_z_p_zz_
	if(opc==2 && !U) return sabd_z_p_zz(ctx, dec); // -> sabd_z_p_zz_
	if(opc==2 && U) return uabd_z_p_zz(ctx, dec); // -> uabd_z_p_zz_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_137);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_arit_2(context *ctx, Instruction *dec)
{
	uint32_t H=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!H && !U) return mul_z_p_zz(ctx, dec); // -> mul_z_p_zz_
	if(!H && U) UNALLOCATED(ENC_UNALLOCATED_138);
	if(H && !U) return smulh_z_p_zz(ctx, dec); // -> smulh_z_p_zz_
	if(H && U) return umulh_z_p_zz(ctx, dec); // -> umulh_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_2(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return orv_r_p_z(ctx, dec); // -> orv_r_p_z_
	if(opc==1) return eorv_r_p_z(ctx, dec); // -> eorv_r_p_z_
	if(opc==2) return andv_r_p_z(ctx, dec); // -> andv_r_p_z_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_143);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_145);
	UNMATCHED;
}

int decode_iclass_sve_int_movprfx_pred(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3;
	if(!opc) return movprfx_z_p_z(ctx, dec); // -> movprfx_z_p_z_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_139);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_141);
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(!opc && !U) return saddv_r_p_z(ctx, dec); // -> saddv_r_p_z_
	if(!opc && U) return uaddv_r_p_z(ctx, dec); // -> uaddv_r_p_z_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_129);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_132);
	UNMATCHED;
}

int decode_iclass_sve_int_reduce_1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(!opc && !U) return smaxv_r_p_z(ctx, dec); // -> smaxv_r_p_z_
	if(!opc && U) return umaxv_r_p_z(ctx, dec); // -> umaxv_r_p_z_
	if(opc==1 && !U) return sminv_r_p_z(ctx, dec); // -> sminv_r_p_z_
	if(opc==1 && U) return uminv_r_p_z(ctx, dec); // -> uminv_r_p_z_
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_136);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_shift_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>18)&3, L=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!opc && !L && !U) return asr_z_p_zi(ctx, dec); // -> asr_z_p_zi_
	if(!opc && !L && U) return lsr_z_p_zi(ctx, dec); // -> lsr_z_p_zi_
	if(!opc && L && !U) UNALLOCATED(ENC_UNALLOCATED_130);
	if(!opc && L && U) return lsl_z_p_zi(ctx, dec); // -> lsl_z_p_zi_
	if(opc==1 && !L && !U) return asrd_z_p_zi(ctx, dec); // -> asrd_z_p_zi_
	if(opc==1 && !L && U) UNALLOCATED(ENC_UNALLOCATED_133);
	if(opc==1 && L) UNALLOCATED(ENC_UNALLOCATED_134);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_135);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_shift_1(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>18)&1, L=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!R && !L && !U) return asr_z_p_zz(ctx, dec); // -> asr_z_p_zz_
	if(!R && !L && U) return lsr_z_p_zz(ctx, dec); // -> lsr_z_p_zz_
	if(!R && L && U) return lsl_z_p_zz(ctx, dec); // -> lsl_z_p_zz_
	if(R && !L && !U) return asrr_z_p_zz(ctx, dec); // -> asrr_z_p_zz_
	if(R && !L && U) return lsrr_z_p_zz(ctx, dec); // -> lsrr_z_p_zz_
	if(R && L && U) return lslr_z_p_zz(ctx, dec); // -> lslr_z_p_zz_
	if(L && !U) UNALLOCATED(ENC_UNALLOCATED_140);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_pred_shift_2(context *ctx, Instruction *dec)
{
	uint32_t R=(INSWORD>>18)&1, L=(INSWORD>>17)&1, U=(INSWORD>>16)&1;
	if(!R && !L && !U) return asr_z_p_zw(ctx, dec); // -> asr_z_p_zw_
	if(!R && !L && U) return lsr_z_p_zw(ctx, dec); // -> lsr_z_p_zw_
	if(!R && L && !U) UNALLOCATED(ENC_UNALLOCATED_142);
	if(!R && L && U) return lsl_z_p_zw(ctx, dec); // -> lsl_z_p_zw_
	if(R) UNALLOCATED(ENC_UNALLOCATED_146);
	UNMATCHED;
}

int decode_iclass_barriers(context *ctx, Instruction *dec)
{
	uint32_t CRm=(INSWORD>>8)&15, op2=(INSWORD>>5)&7, Rt=INSWORD&0x1f;
	if(!CRm && op2==4 && Rt==0x1f) return SSBB(ctx, dec); // -> SSBB_only_barriers
	if(CRm==4 && op2==4 && Rt==0x1f) return PSSBB(ctx, dec); // -> PSSBB_only_barriers
	if(CRm&11 && op2==4 && Rt==0x1f) return DSB(ctx, dec); // -> DSB_BO_barriers
	if(op2==1 && Rt!=0x1f) UNALLOCATED(ENC_UNALLOCATED_11_BARRIERS);
	if(op2==2 && Rt==0x1f) return CLREX(ctx, dec); // -> CLREX_BN_barriers
	if(op2==5 && Rt==0x1f) return DMB(ctx, dec); // -> DMB_BO_barriers
	if(op2==6 && Rt==0x1f) return ISB(ctx, dec); // -> ISB_BI_barriers
	if(op2==7 && Rt!=0x1f) UNALLOCATED(ENC_UNALLOCATED_25_BARRIERS);
	if(op2==7 && Rt==0x1f) return SB(ctx, dec); // -> SB_only_barriers
	if(CRm==1 && op2==3) UNALLOCATED(ENC_UNALLOCATED_15_BARRIERS);
	if((CRm&14)==2 && op2==3) UNALLOCATED(ENC_UNALLOCATED_16_BARRIERS);
	if((CRm&12)==4 && op2==3) UNALLOCATED(ENC_UNALLOCATED_17_BARRIERS);
	if((CRm&8)==8 && op2==3) UNALLOCATED(ENC_UNALLOCATED_18_BARRIERS);
	if(!op2) UNALLOCATED(ENC_UNALLOCATED_10_BARRIERS);
	UNMATCHED;
}

int decode_iclass_compbranch(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>24)&1;
	if(!sf && !op) return CBZ(ctx, dec); // -> CBZ_32_compbranch
	if(!sf && op) return CBNZ(ctx, dec); // -> CBNZ_32_compbranch
	if(sf && !op) return CBZ(ctx, dec); // -> CBZ_64_compbranch
	if(sf && op) return CBNZ(ctx, dec); // -> CBNZ_64_compbranch
	UNMATCHED;
}

int decode_iclass_condbranch(context *ctx, Instruction *dec)
{
	uint32_t o1=(INSWORD>>24)&1, o0=(INSWORD>>4)&1;
	if(!o1 && !o0) return B_cond(ctx, dec); // -> B_only_condbranch
	if(!o1 && o0) UNALLOCATED(ENC_UNALLOCATED_11_CONDBRANCH);
	if(o1) UNALLOCATED(ENC_UNALLOCATED_12_CONDBRANCH);
	UNMATCHED;
}

int decode_iclass_exception(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>21)&7, op2=(INSWORD>>2)&7, LL=INSWORD&3;
	if(!opc && !op2 && !LL) UNALLOCATED(ENC_UNALLOCATED_10_EXCEPTION);
	if(!opc && !op2 && LL==1) return SVC(ctx, dec); // -> SVC_EX_exception
	if(!opc && !op2 && LL==2) return HVC(ctx, dec); // -> HVC_EX_exception
	if(!opc && !op2 && LL==3) return SMC(ctx, dec); // -> SMC_EX_exception
	if(opc==1 && !op2 && !LL) return BRK(ctx, dec); // -> BRK_EX_exception
	if(opc==2 && !op2 && !LL) return HLT(ctx, dec); // -> HLT_EX_exception
	if(opc==3 && !op2 && LL==1) UNALLOCATED(ENC_UNALLOCATED_21_EXCEPTION);
	if(opc==5 && !op2 && !LL) UNALLOCATED(ENC_UNALLOCATED_24_EXCEPTION);
	if(opc==5 && !op2 && LL==1) return DCPS1(ctx, dec); // -> DCPS1_DC_exception
	if(opc==5 && !op2 && LL==2) return DCPS2(ctx, dec); // -> DCPS2_DC_exception
	if(opc==5 && !op2 && LL==3) return DCPS3(ctx, dec); // -> DCPS3_DC_exception
	if(opc==1 && !op2 && LL&1) UNALLOCATED(ENC_UNALLOCATED_15_EXCEPTION);
	if(opc==1 && !op2 && (LL&2)==2) UNALLOCATED(ENC_UNALLOCATED_16_EXCEPTION);
	if(opc==2 && !op2 && LL&1) UNALLOCATED(ENC_UNALLOCATED_18_EXCEPTION);
	if(opc==2 && !op2 && (LL&2)==2) UNALLOCATED(ENC_UNALLOCATED_19_EXCEPTION);
	if(opc==3 && !op2 && (LL&2)==2) UNALLOCATED(ENC_UNALLOCATED_22_EXCEPTION);
	if(opc==4 && !op2) UNALLOCATED(ENC_UNALLOCATED_23_EXCEPTION);
	if(opc==6 && !op2) UNALLOCATED(ENC_UNALLOCATED_28_EXCEPTION);
	if(opc==7 && !op2) UNALLOCATED(ENC_UNALLOCATED_29_EXCEPTION);
	if(op2==1) UNALLOCATED(ENC_UNALLOCATED_30_EXCEPTION);
	if((op2&6)==2) UNALLOCATED(ENC_UNALLOCATED_31_EXCEPTION);
	if((op2&4)==4) UNALLOCATED(ENC_UNALLOCATED_32_EXCEPTION);
	UNMATCHED;
}

int decode_iclass_hints(context *ctx, Instruction *dec)
{
	uint32_t CRm=(INSWORD>>8)&15, op2=(INSWORD>>5)&7;
	if(!CRm && !op2) return NOP(ctx, dec); // -> NOP_HI_hints
	if(!CRm && op2==1) return YIELD(ctx, dec); // -> YIELD_HI_hints
	if(!CRm && op2==2) return WFE(ctx, dec); // -> WFE_HI_hints
	if(!CRm && op2==3) return WFI(ctx, dec); // -> WFI_HI_hints
	if(!CRm && op2==4) return SEV(ctx, dec); // -> SEV_HI_hints
	if(!CRm && op2==5) return SEVL(ctx, dec); // -> SEVL_HI_hints
	if(!CRm && op2==6 && HasDGH()) return DGH(ctx, dec); // -> DGH_HI_hints
	if(!CRm && op2==7 && HasPAuth()) return XPAC(ctx, dec); // -> XPACLRI_HI_hints
	if(CRm==1 && !op2 && HasPAuth()) return PACIA(ctx, dec); // -> PACIA1716_HI_hints
	if(CRm==1 && op2==2 && HasPAuth()) return PACIB(ctx, dec); // -> PACIB1716_HI_hints
	if(CRm==1 && op2==4 && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIA1716_HI_hints
	if(CRm==1 && op2==6 && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIB1716_HI_hints
	if(CRm==2 && !op2 && HasPAuth()) return ESB(ctx, dec); // -> ESB_HI_hints
	if(CRm==2 && op2==1 && HasPAuth()) return PSB(ctx, dec); // -> PSB_HC_hints
	if(CRm==2 && op2==2 && HasTrace()) return TSB(ctx, dec); // -> TSB_HC_hints
	if(CRm==2 && op2==4) return CSDB(ctx, dec); // -> CSDB_HI_hints
	if(CRm==3 && !op2 && HasPAuth()) return PACIA(ctx, dec); // -> PACIAZ_HI_hints
	if(CRm==3 && op2==1 && HasPAuth()) return PACIA(ctx, dec); // -> PACIASP_HI_hints
	if(CRm==3 && op2==2 && HasPAuth()) return PACIB(ctx, dec); // -> PACIBZ_HI_hints
	if(CRm==3 && op2==3 && HasPAuth()) return PACIB(ctx, dec); // -> PACIBSP_HI_hints
	if(CRm==3 && op2==4 && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIAZ_HI_hints
	if(CRm==3 && op2==5 && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIASP_HI_hints
	if(CRm==3 && op2==6 && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIBZ_HI_hints
	if(CRm==3 && op2==7 && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIBSP_HI_hints
	if(CRm==4 && !(op2&1) && HasBTI()) return BTI(ctx, dec); // -> BTI_HB_hints
	UNMATCHED;
}

int decode_iclass_pstate(context *ctx, Instruction *dec)
{
	uint32_t op1=(INSWORD>>16)&7, op2=(INSWORD>>5)&7, Rt=INSWORD&0x1f;
	if(!op1 && !op2 && Rt==0x1f && HasCondM()) return CFINV(ctx, dec); // -> CFINV_M_pstate
	if(!op1 && op2==1 && Rt==0x1f && HasCondM()) return XAFLAG(ctx, dec); // -> XAFLAG_M_pstate
	if(!op1 && op2==2 && Rt==0x1f && HasCondM()) return AXFLAG(ctx, dec); // -> AXFLAG_M_pstate
	if(Rt!=0x1f) UNALLOCATED(ENC_UNALLOCATED_10_PSTATE);
	if(Rt==0x1f) return MSR_imm(ctx, dec); // -> MSR_SI_pstate
	UNMATCHED;
}

int decode_iclass_systeminstrs(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>21)&1;
	if(!L) return SYS(ctx, dec); // -> SYS_CR_systeminstrs
	if(L) return SYSL(ctx, dec); // -> SYSL_RC_systeminstrs
	UNMATCHED;
}

int decode_iclass_systemmove(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>21)&1;
	if(!L) return MSR_reg(ctx, dec); // -> MSR_SR_systemmove
	if(L) return MRS(ctx, dec); // -> MRS_RS_systemmove
	UNMATCHED;
}

int decode_iclass_testbranch(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>24)&1;
	if(!op) return TBZ(ctx, dec); // -> TBZ_only_testbranch
	if(op) return TBNZ(ctx, dec); // -> TBNZ_only_testbranch
	UNMATCHED;
}

int decode_iclass_branch_imm(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD>>31;
	if(!op) return B_uncond(ctx, dec); // -> B_only_branch_imm
	if(op) return BL(ctx, dec); // -> BL_only_branch_imm
	UNMATCHED;
}

int decode_iclass_branch_reg(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>21)&15, op2=(INSWORD>>16)&0x1f, op3=(INSWORD>>10)&0x3f, Rn=(INSWORD>>5)&0x1f, op4=INSWORD&0x1f;
	if(opc==2 && op2==0x1f && op3==2 && Rn!=0x1f && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_37_BRANCH_REG);
	if(opc==2 && op2==0x1f && op3==2 && Rn==0x1f && op4==0x1f && HasPAuth()) return RETA(ctx, dec); // -> RETAA_64E_branch_reg
	if(opc==2 && op2==0x1f && op3==3 && Rn!=0x1f && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_39_BRANCH_REG);
	if(opc==2 && op2==0x1f && op3==3 && Rn==0x1f && op4==0x1f && HasPAuth()) return RETA(ctx, dec); // -> RETAB_64E_branch_reg
	if(opc==4 && op2==0x1f && !op3 && Rn!=0x1f && op4) UNALLOCATED(ENC_UNALLOCATED_48_BRANCH_REG);
	if(opc==4 && op2==0x1f && !op3 && Rn!=0x1f && !op4) UNALLOCATED(ENC_UNALLOCATED_46_BRANCH_REG);
	if(opc==4 && op2==0x1f && !op3 && Rn==0x1f && op4) UNALLOCATED(ENC_UNALLOCATED_47_BRANCH_REG);
	if(opc==4 && op2==0x1f && !op3 && Rn==0x1f && !op4) return ERET(ctx, dec); // -> ERET_64E_branch_reg
	if(opc==4 && op2==0x1f && op3==2 && Rn!=0x1f && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_53_BRANCH_REG);
	if(opc==4 && op2==0x1f && op3==2 && Rn!=0x1f && op4==0x1f) UNALLOCATED(ENC_UNALLOCATED_52_BRANCH_REG);
	if(opc==4 && op2==0x1f && op3==2 && Rn==0x1f && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_51_BRANCH_REG);
	if(opc==4 && op2==0x1f && op3==2 && Rn==0x1f && op4==0x1f && HasPAuth()) return ERETA(ctx, dec); // -> ERETAA_64E_branch_reg
	if(opc==4 && op2==0x1f && op3==3 && Rn!=0x1f && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_57_BRANCH_REG);
	if(opc==4 && op2==0x1f && op3==3 && Rn!=0x1f && op4==0x1f) UNALLOCATED(ENC_UNALLOCATED_56_BRANCH_REG);
	if(opc==4 && op2==0x1f && op3==3 && Rn==0x1f && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_55_BRANCH_REG);
	if(opc==4 && op2==0x1f && op3==3 && Rn==0x1f && op4==0x1f && HasPAuth()) return ERETA(ctx, dec); // -> ERETAB_64E_branch_reg
	if(opc==5 && op2==0x1f && !op3 && Rn!=0x1f && op4) UNALLOCATED(ENC_UNALLOCATED_65_BRANCH_REG);
	if(opc==5 && op2==0x1f && !op3 && Rn!=0x1f && !op4) UNALLOCATED(ENC_UNALLOCATED_63_BRANCH_REG);
	if(opc==5 && op2==0x1f && !op3 && Rn==0x1f && op4) UNALLOCATED(ENC_UNALLOCATED_64_BRANCH_REG);
	if(opc==5 && op2==0x1f && !op3 && Rn==0x1f && !op4) return DRPS(ctx, dec); // -> DRPS_64E_branch_reg
	if(!opc && op2==0x1f && !op3 && op4) UNALLOCATED(ENC_UNALLOCATED_12_BRANCH_REG);
	if(!opc && op2==0x1f && !op3 && !op4) return BR(ctx, dec); // -> BR_64_branch_reg
	if(!opc && op2==0x1f && op3==2 && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_15_BRANCH_REG);
	if(!opc && op2==0x1f && op3==2 && op4==0x1f && HasPAuth()) return BRA(ctx, dec); // -> BRAAZ_64_branch_reg
	if(!opc && op2==0x1f && op3==3 && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_17_BRANCH_REG);
	if(!opc && op2==0x1f && op3==3 && op4==0x1f && HasPAuth()) return BRA(ctx, dec); // -> BRABZ_64_branch_reg
	if(opc==1 && op2==0x1f && !op3 && op4) UNALLOCATED(ENC_UNALLOCATED_23_BRANCH_REG);
	if(opc==1 && op2==0x1f && !op3 && !op4) return BLR(ctx, dec); // -> BLR_64_branch_reg
	if(opc==1 && op2==0x1f && op3==2 && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_26_BRANCH_REG);
	if(opc==1 && op2==0x1f && op3==2 && op4==0x1f && HasPAuth()) return BLRA(ctx, dec); // -> BLRAAZ_64_branch_reg
	if(opc==1 && op2==0x1f && op3==3 && op4!=0x1f) UNALLOCATED(ENC_UNALLOCATED_28_BRANCH_REG);
	if(opc==1 && op2==0x1f && op3==3 && op4==0x1f && HasPAuth()) return BLRA(ctx, dec); // -> BLRABZ_64_branch_reg
	if(opc==2 && op2==0x1f && !op3 && op4) UNALLOCATED(ENC_UNALLOCATED_34_BRANCH_REG);
	if(opc==2 && op2==0x1f && !op3 && !op4) return RET(ctx, dec); // -> RET_64R_branch_reg
	if(!opc && op2==0x1f && op3==1) UNALLOCATED(ENC_UNALLOCATED_13_BRANCH_REG);
	if(opc==1 && op2==0x1f && op3==1) UNALLOCATED(ENC_UNALLOCATED_24_BRANCH_REG);
	if(opc==2 && op2==0x1f && op3==1) UNALLOCATED(ENC_UNALLOCATED_35_BRANCH_REG);
	if(opc==4 && op2==0x1f && op3==1) UNALLOCATED(ENC_UNALLOCATED_49_BRANCH_REG);
	if(opc==5 && op2==0x1f && op3) UNALLOCATED(ENC_UNALLOCATED_66_BRANCH_REG);
	if(opc==8 && op2==0x1f && op3==2 && HasPAuth()) return BRA(ctx, dec); // -> BRAA_64P_branch_reg
	if(opc==8 && op2==0x1f && op3==3 && HasPAuth()) return BRA(ctx, dec); // -> BRAB_64P_branch_reg
	if(opc==9 && op2==0x1f && op3==2 && HasPAuth()) return BLRA(ctx, dec); // -> BLRAA_64P_branch_reg
	if(opc==9 && op2==0x1f && op3==3 && HasPAuth()) return BLRA(ctx, dec); // -> BLRAB_64P_branch_reg
	if(opc==8 && op2==0x1f && !(op3&0x3e)) UNALLOCATED(ENC_UNALLOCATED_68_BRANCH_REG);
	if(opc==9 && op2==0x1f && !(op3&0x3e)) UNALLOCATED(ENC_UNALLOCATED_75_BRANCH_REG);
	if(!opc && op2==0x1f && (op3&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_18_BRANCH_REG);
	if(opc==1 && op2==0x1f && (op3&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_29_BRANCH_REG);
	if(opc==2 && op2==0x1f && (op3&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_40_BRANCH_REG);
	if(opc==4 && op2==0x1f && (op3&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_58_BRANCH_REG);
	if(opc==8 && op2==0x1f && (op3&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_71_BRANCH_REG);
	if(opc==9 && op2==0x1f && (op3&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_78_BRANCH_REG);
	if(!opc && op2==0x1f && (op3&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_19_BRANCH_REG);
	if(opc==1 && op2==0x1f && (op3&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_30_BRANCH_REG);
	if(opc==2 && op2==0x1f && (op3&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_41_BRANCH_REG);
	if(opc==4 && op2==0x1f && (op3&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_59_BRANCH_REG);
	if(opc==8 && op2==0x1f && (op3&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_72_BRANCH_REG);
	if(opc==9 && op2==0x1f && (op3&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_79_BRANCH_REG);
	if(!opc && op2==0x1f && (op3&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_20_BRANCH_REG);
	if(opc==1 && op2==0x1f && (op3&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_31_BRANCH_REG);
	if(opc==2 && op2==0x1f && (op3&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_42_BRANCH_REG);
	if(opc==4 && op2==0x1f && (op3&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_60_BRANCH_REG);
	if(opc==8 && op2==0x1f && (op3&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_73_BRANCH_REG);
	if(opc==9 && op2==0x1f && (op3&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_80_BRANCH_REG);
	if(!opc && op2==0x1f && (op3&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_21_BRANCH_REG);
	if(opc==1 && op2==0x1f && (op3&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_32_BRANCH_REG);
	if(opc==2 && op2==0x1f && (op3&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_43_BRANCH_REG);
	if(opc==4 && op2==0x1f && (op3&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_61_BRANCH_REG);
	if(opc==8 && op2==0x1f && (op3&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_74_BRANCH_REG);
	if(opc==9 && op2==0x1f && (op3&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_81_BRANCH_REG);
	if(opc==3 && op2==0x1f) UNALLOCATED(ENC_UNALLOCATED_44_BRANCH_REG);
	if((opc&14)==6 && op2==0x1f) UNALLOCATED(ENC_UNALLOCATED_67_BRANCH_REG);
	if((opc&14)==10 && op2==0x1f) UNALLOCATED(ENC_UNALLOCATED_82_BRANCH_REG);
	if((opc&12)==12 && op2==0x1f) UNALLOCATED(ENC_UNALLOCATED_83_BRANCH_REG);
	if(op2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_10_BRANCH_REG);
	UNMATCHED;
}

int decode_iclass_sve_int_un_pred_arit_1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return cls_z_p_z(ctx, dec); // -> cls_z_p_z_
	if(opc==1) return clz_z_p_z(ctx, dec); // -> clz_z_p_z_
	if(opc==2) return cnt_z_p_z(ctx, dec); // -> cnt_z_p_z_
	if(opc==3) return cnot_z_p_z(ctx, dec); // -> cnot_z_p_z_
	if(opc==4) return fabs_z_p_z(ctx, dec); // -> fabs_z_p_z_
	if(opc==5) return fneg_z_p_z(ctx, dec); // -> fneg_z_p_z_
	if(opc==6) return not_z_p_z(ctx, dec); // -> not_z_p_z_
	if(opc==7) UNALLOCATED(ENC_UNALLOCATED_147);
	UNMATCHED;
}

int decode_iclass_sve_int_un_pred_arit_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return sxtb_z_p_z(ctx, dec); // -> sxtb_z_p_z_
	if(opc==1) return uxtb_z_p_z(ctx, dec); // -> uxtb_z_p_z_
	if(opc==2) return sxtb_z_p_z(ctx, dec); // -> sxth_z_p_z_
	if(opc==3) return uxtb_z_p_z(ctx, dec); // -> uxth_z_p_z_
	if(opc==4) return sxtb_z_p_z(ctx, dec); // -> sxtw_z_p_z_
	if(opc==5) return uxtb_z_p_z(ctx, dec); // -> uxtw_z_p_z_
	if(opc==6) return abs_z_p_z(ctx, dec); // -> abs_z_p_z_
	if(opc==7) return neg_z_p_z(ctx, dec); // -> neg_z_p_z_
	UNMATCHED;
}

int decode_iclass_asisdlse(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>22)&1, opcode=(INSWORD>>12)&15;
	if(!L && !opcode) return ST4_advsimd_mult(ctx, dec); // -> ST4_asisdlse_R4
	if(!L && opcode==1) UNALLOCATED(ENC_UNALLOCATED_12_ASISDLSE);
	if(!L && opcode==2) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlse_R4_4v
	if(!L && opcode==3) UNALLOCATED(ENC_UNALLOCATED_14_ASISDLSE);
	if(!L && opcode==4) return ST3_advsimd_mult(ctx, dec); // -> ST3_asisdlse_R3
	if(!L && opcode==5) UNALLOCATED(ENC_UNALLOCATED_16_ASISDLSE);
	if(!L && opcode==6) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlse_R3_3v
	if(!L && opcode==7) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlse_R1_1v
	if(!L && opcode==8) return ST2_advsimd_mult(ctx, dec); // -> ST2_asisdlse_R2
	if(!L && opcode==9) UNALLOCATED(ENC_UNALLOCATED_20_ASISDLSE);
	if(!L && opcode==10) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlse_R2_2v
	if(!L && opcode==11) UNALLOCATED(ENC_UNALLOCATED_22_ASISDLSE);
	if(L && !opcode) return LD4_advsimd_mult(ctx, dec); // -> LD4_asisdlse_R4
	if(L && opcode==1) UNALLOCATED(ENC_UNALLOCATED_25_ASISDLSE);
	if(L && opcode==2) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlse_R4_4v
	if(L && opcode==3) UNALLOCATED(ENC_UNALLOCATED_27_ASISDLSE);
	if(L && opcode==4) return LD3_advsimd_mult(ctx, dec); // -> LD3_asisdlse_R3
	if(L && opcode==5) UNALLOCATED(ENC_UNALLOCATED_29_ASISDLSE);
	if(L && opcode==6) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlse_R3_3v
	if(L && opcode==7) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlse_R1_1v
	if(L && opcode==8) return LD2_advsimd_mult(ctx, dec); // -> LD2_asisdlse_R2
	if(L && opcode==9) UNALLOCATED(ENC_UNALLOCATED_33_ASISDLSE);
	if(L && opcode==10) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlse_R2_2v
	if(L && opcode==11) UNALLOCATED(ENC_UNALLOCATED_35_ASISDLSE);
	if(!L && (opcode&12)==12) UNALLOCATED(ENC_UNALLOCATED_23_ASISDLSE);
	if(L && (opcode&12)==12) UNALLOCATED(ENC_UNALLOCATED_36_ASISDLSE);
	UNMATCHED;
}

int decode_iclass_asisdlsep(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>22)&1, Rm=(INSWORD>>16)&0x1f, opcode=(INSWORD>>12)&15;
	if(!L && Rm!=0x1f && !opcode) return ST4_advsimd_mult(ctx, dec); // -> ST4_asisdlsep_R4_r
	if(!L && Rm!=0x1f && opcode==2) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_R4_r4
	if(!L && Rm!=0x1f && opcode==4) return ST3_advsimd_mult(ctx, dec); // -> ST3_asisdlsep_R3_r
	if(!L && Rm!=0x1f && opcode==6) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_R3_r3
	if(!L && Rm!=0x1f && opcode==7) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_R1_r1
	if(!L && Rm!=0x1f && opcode==8) return ST2_advsimd_mult(ctx, dec); // -> ST2_asisdlsep_R2_r
	if(!L && Rm!=0x1f && opcode==10) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_R2_r2
	if(!L && Rm==0x1f && !opcode) return ST4_advsimd_mult(ctx, dec); // -> ST4_asisdlsep_I4_i
	if(!L && Rm==0x1f && opcode==2) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_I4_i4
	if(!L && Rm==0x1f && opcode==4) return ST3_advsimd_mult(ctx, dec); // -> ST3_asisdlsep_I3_i
	if(!L && Rm==0x1f && opcode==6) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_I3_i3
	if(!L && Rm==0x1f && opcode==7) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_I1_i1
	if(!L && Rm==0x1f && opcode==8) return ST2_advsimd_mult(ctx, dec); // -> ST2_asisdlsep_I2_i
	if(!L && Rm==0x1f && opcode==10) return ST1_advsimd_mult(ctx, dec); // -> ST1_asisdlsep_I2_i2
	if(L && Rm!=0x1f && !opcode) return LD4_advsimd_mult(ctx, dec); // -> LD4_asisdlsep_R4_r
	if(L && Rm!=0x1f && opcode==2) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_R4_r4
	if(L && Rm!=0x1f && opcode==4) return LD3_advsimd_mult(ctx, dec); // -> LD3_asisdlsep_R3_r
	if(L && Rm!=0x1f && opcode==6) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_R3_r3
	if(L && Rm!=0x1f && opcode==7) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_R1_r1
	if(L && Rm!=0x1f && opcode==8) return LD2_advsimd_mult(ctx, dec); // -> LD2_asisdlsep_R2_r
	if(L && Rm!=0x1f && opcode==10) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_R2_r2
	if(L && Rm==0x1f && !opcode) return LD4_advsimd_mult(ctx, dec); // -> LD4_asisdlsep_I4_i
	if(L && Rm==0x1f && opcode==2) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_I4_i4
	if(L && Rm==0x1f && opcode==4) return LD3_advsimd_mult(ctx, dec); // -> LD3_asisdlsep_I3_i
	if(L && Rm==0x1f && opcode==6) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_I3_i3
	if(L && Rm==0x1f && opcode==7) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_I1_i1
	if(L && Rm==0x1f && opcode==8) return LD2_advsimd_mult(ctx, dec); // -> LD2_asisdlsep_I2_i
	if(L && Rm==0x1f && opcode==10) return LD1_advsimd_mult(ctx, dec); // -> LD1_asisdlsep_I2_i2
	if(!L && opcode==1) UNALLOCATED(ENC_UNALLOCATED_13_ASISDLSEP);
	if(!L && opcode==3) UNALLOCATED(ENC_UNALLOCATED_16_ASISDLSEP);
	if(!L && opcode==5) UNALLOCATED(ENC_UNALLOCATED_19_ASISDLSEP);
	if(!L && opcode==9) UNALLOCATED(ENC_UNALLOCATED_26_ASISDLSEP);
	if(!L && opcode==11) UNALLOCATED(ENC_UNALLOCATED_29_ASISDLSEP);
	if(L && opcode==1) UNALLOCATED(ENC_UNALLOCATED_33_ASISDLSEP);
	if(L && opcode==3) UNALLOCATED(ENC_UNALLOCATED_36_ASISDLSEP);
	if(L && opcode==5) UNALLOCATED(ENC_UNALLOCATED_39_ASISDLSEP);
	if(L && opcode==9) UNALLOCATED(ENC_UNALLOCATED_46_ASISDLSEP);
	if(L && opcode==11) UNALLOCATED(ENC_UNALLOCATED_49_ASISDLSEP);
	if(!L && (opcode&12)==12) UNALLOCATED(ENC_UNALLOCATED_30_ASISDLSEP);
	if(L && (opcode&12)==12) UNALLOCATED(ENC_UNALLOCATED_50_ASISDLSEP);
	UNMATCHED;
}

int decode_iclass_asisdlso(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>22)&1, R=(INSWORD>>21)&1, opcode=(INSWORD>>13)&7, S=(INSWORD>>12)&1, size=(INSWORD>>10)&3;
	if(!L && !R && opcode==4 && !S && size==1) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlso_D1_1d
	if(!L && !R && opcode==4 && S && size==1) UNALLOCATED(ENC_UNALLOCATED_18_ASISDLSO);
	if(!L && !R && opcode==5 && !S && size==1) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlso_D3_3d
	if(!L && !R && opcode==5 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_33_ASISDLSO);
	if(!L && R && opcode==4 && !S && size==1) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlso_D2_2d
	if(!L && R && opcode==4 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_25_ASISDLSO);
	if(!L && R && opcode==5 && !S && size==1) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlso_D4_4d
	if(!L && R && opcode==5 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_41_ASISDLSO);
	if(L && !R && opcode==4 && !S && size==1) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlso_D1_1d
	if(L && !R && opcode==4 && S && size==1) UNALLOCATED(ENC_UNALLOCATED_48_ASISDLSO);
	if(L && !R && opcode==5 && !S && size==1) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlso_D3_3d
	if(L && !R && opcode==5 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_68_ASISDLSO);
	if(L && R && opcode==4 && !S && size==1) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlso_D2_2d
	if(L && R && opcode==4 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_58_ASISDLSO);
	if(L && R && opcode==5 && !S && size==1) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlso_D4_4d
	if(L && R && opcode==5 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_78_ASISDLSO);
	if(!L && !R && opcode==4 && !size) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlso_S1_1s
	if(!L && !R && opcode==5 && !size) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlso_S3_3s
	if(!L && !R && opcode==5 && size==2) UNALLOCATED(ENC_UNALLOCATED_31_ASISDLSO);
	if(!L && !R && opcode==5 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_34_ASISDLSO);
	if(!L && R && opcode==4 && !size) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlso_S2_2s
	if(!L && R && opcode==4 && size==2) UNALLOCATED(ENC_UNALLOCATED_23_ASISDLSO);
	if(!L && R && opcode==4 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_26_ASISDLSO);
	if(!L && R && opcode==5 && !size) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlso_S4_4s
	if(!L && R && opcode==5 && size==2) UNALLOCATED(ENC_UNALLOCATED_39_ASISDLSO);
	if(!L && R && opcode==5 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_42_ASISDLSO);
	if(L && !R && opcode==4 && !size) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlso_S1_1s
	if(L && !R && opcode==5 && !size) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlso_S3_3s
	if(L && !R && opcode==5 && size==2) UNALLOCATED(ENC_UNALLOCATED_66_ASISDLSO);
	if(L && !R && opcode==5 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_69_ASISDLSO);
	if(L && R && opcode==4 && !size) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlso_S2_2s
	if(L && R && opcode==4 && size==2) UNALLOCATED(ENC_UNALLOCATED_56_ASISDLSO);
	if(L && R && opcode==4 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_59_ASISDLSO);
	if(L && R && opcode==5 && !size) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlso_S4_4s
	if(L && R && opcode==5 && size==2) UNALLOCATED(ENC_UNALLOCATED_76_ASISDLSO);
	if(L && R && opcode==5 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_79_ASISDLSO);
	if(!L && !R && opcode==2 && !(size&1)) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlso_H1_1h
	if(!L && !R && opcode==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_14_ASISDLSO);
	if(!L && !R && opcode==3 && !(size&1)) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlso_H3_3h
	if(!L && !R && opcode==3 && size&1) UNALLOCATED(ENC_UNALLOCATED_29_ASISDLSO);
	if(!L && !R && opcode==4 && (size&2)==2) UNALLOCATED(ENC_UNALLOCATED_16_ASISDLSO);
	if(!L && R && opcode==2 && !(size&1)) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlso_H2_2h
	if(!L && R && opcode==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_21_ASISDLSO);
	if(!L && R && opcode==3 && !(size&1)) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlso_H4_4h
	if(!L && R && opcode==3 && size&1) UNALLOCATED(ENC_UNALLOCATED_37_ASISDLSO);
	if(L && !R && opcode==2 && !(size&1)) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlso_H1_1h
	if(L && !R && opcode==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_45_ASISDLSO);
	if(L && !R && opcode==3 && !(size&1)) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlso_H3_3h
	if(L && !R && opcode==3 && size&1) UNALLOCATED(ENC_UNALLOCATED_64_ASISDLSO);
	if(L && !R && opcode==4 && (size&2)==2) UNALLOCATED(ENC_UNALLOCATED_49_ASISDLSO);
	if(L && !R && opcode==6 && !S) return LD1R_advsimd(ctx, dec); // -> LD1R_asisdlso_R1
	if(L && !R && opcode==6 && S) UNALLOCATED(ENC_UNALLOCATED_51_ASISDLSO);
	if(L && !R && opcode==7 && !S) return LD3R_advsimd(ctx, dec); // -> LD3R_asisdlso_R3
	if(L && !R && opcode==7 && S) UNALLOCATED(ENC_UNALLOCATED_71_ASISDLSO);
	if(L && R && opcode==2 && !(size&1)) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlso_H2_2h
	if(L && R && opcode==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_54_ASISDLSO);
	if(L && R && opcode==3 && !(size&1)) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlso_H4_4h
	if(L && R && opcode==3 && size&1) UNALLOCATED(ENC_UNALLOCATED_74_ASISDLSO);
	if(L && R && opcode==6 && !S) return LD2R_advsimd(ctx, dec); // -> LD2R_asisdlso_R2
	if(L && R && opcode==6 && S) UNALLOCATED(ENC_UNALLOCATED_61_ASISDLSO);
	if(L && R && opcode==7 && !S) return LD4R_advsimd(ctx, dec); // -> LD4R_asisdlso_R4
	if(L && R && opcode==7 && S) UNALLOCATED(ENC_UNALLOCATED_81_ASISDLSO);
	if(!L && !R && !opcode) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlso_B1_1b
	if(!L && !R && opcode==1) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlso_B3_3b
	if(!L && R && !opcode) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlso_B2_2b
	if(!L && R && opcode==1) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlso_B4_4b
	if(L && !R && !opcode) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlso_B1_1b
	if(L && !R && opcode==1) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlso_B3_3b
	if(L && R && !opcode) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlso_B2_2b
	if(L && R && opcode==1) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlso_B4_4b
	if(!L && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_11_ASISDLSO);
	UNMATCHED;
}

int decode_iclass_asisdlsop(context *ctx, Instruction *dec)
{
	uint32_t L=(INSWORD>>22)&1, R=(INSWORD>>21)&1, Rm=(INSWORD>>16)&0x1f, opcode=(INSWORD>>13)&7, S=(INSWORD>>12)&1, size=(INSWORD>>10)&3;
	if(!L && !R && Rm!=0x1f && opcode==4 && !S && size==1) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_DX1_r1d
	if(!L && !R && Rm!=0x1f && opcode==5 && !S && size==1) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_DX3_r3d
	if(!L && !R && Rm==0x1f && opcode==4 && !S && size==1) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_D1_i1d
	if(!L && !R && Rm==0x1f && opcode==5 && !S && size==1) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_D3_i3d
	if(!L && R && Rm!=0x1f && opcode==4 && !S && size==1) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_DX2_r2d
	if(!L && R && Rm!=0x1f && opcode==5 && !S && size==1) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_DX4_r4d
	if(!L && R && Rm==0x1f && opcode==4 && !S && size==1) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_D2_i2d
	if(!L && R && Rm==0x1f && opcode==5 && !S && size==1) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_D4_i4d
	if(L && !R && Rm!=0x1f && opcode==4 && !S && size==1) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_DX1_r1d
	if(L && !R && Rm!=0x1f && opcode==5 && !S && size==1) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_DX3_r3d
	if(L && !R && Rm==0x1f && opcode==4 && !S && size==1) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_D1_i1d
	if(L && !R && Rm==0x1f && opcode==5 && !S && size==1) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_D3_i3d
	if(L && R && Rm!=0x1f && opcode==4 && !S && size==1) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_DX2_r2d
	if(L && R && Rm!=0x1f && opcode==5 && !S && size==1) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_DX4_r4d
	if(L && R && Rm==0x1f && opcode==4 && !S && size==1) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_D2_i2d
	if(L && R && Rm==0x1f && opcode==5 && !S && size==1) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_D4_i4d
	if(!L && !R && Rm!=0x1f && opcode==4 && !size) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_SX1_r1s
	if(!L && !R && Rm!=0x1f && opcode==5 && !size) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_SX3_r3s
	if(!L && !R && Rm==0x1f && opcode==4 && !size) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_S1_i1s
	if(!L && !R && Rm==0x1f && opcode==5 && !size) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_S3_i3s
	if(!L && R && Rm!=0x1f && opcode==4 && !size) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_SX2_r2s
	if(!L && R && Rm!=0x1f && opcode==5 && !size) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_SX4_r4s
	if(!L && R && Rm==0x1f && opcode==4 && !size) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_S2_i2s
	if(!L && R && Rm==0x1f && opcode==5 && !size) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_S4_i4s
	if(L && !R && Rm!=0x1f && opcode==4 && !size) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_SX1_r1s
	if(L && !R && Rm!=0x1f && opcode==5 && !size) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_SX3_r3s
	if(L && !R && Rm==0x1f && opcode==4 && !size) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_S1_i1s
	if(L && !R && Rm==0x1f && opcode==5 && !size) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_S3_i3s
	if(L && R && Rm!=0x1f && opcode==4 && !size) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_SX2_r2s
	if(L && R && Rm!=0x1f && opcode==5 && !size) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_SX4_r4s
	if(L && R && Rm==0x1f && opcode==4 && !size) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_S2_i2s
	if(L && R && Rm==0x1f && opcode==5 && !size) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_S4_i4s
	if(!L && !R && Rm!=0x1f && opcode==2 && !(size&1)) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_HX1_r1h
	if(!L && !R && Rm!=0x1f && opcode==3 && !(size&1)) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_HX3_r3h
	if(!L && !R && Rm==0x1f && opcode==2 && !(size&1)) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_H1_i1h
	if(!L && !R && Rm==0x1f && opcode==3 && !(size&1)) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_H3_i3h
	if(!L && R && Rm!=0x1f && opcode==2 && !(size&1)) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_HX2_r2h
	if(!L && R && Rm!=0x1f && opcode==3 && !(size&1)) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_HX4_r4h
	if(!L && R && Rm==0x1f && opcode==2 && !(size&1)) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_H2_i2h
	if(!L && R && Rm==0x1f && opcode==3 && !(size&1)) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_H4_i4h
	if(L && !R && Rm!=0x1f && opcode==2 && !(size&1)) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_HX1_r1h
	if(L && !R && Rm!=0x1f && opcode==3 && !(size&1)) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_HX3_r3h
	if(L && !R && Rm!=0x1f && opcode==6 && !S) return LD1R_advsimd(ctx, dec); // -> LD1R_asisdlsop_RX1_r
	if(L && !R && Rm!=0x1f && opcode==7 && !S) return LD3R_advsimd(ctx, dec); // -> LD3R_asisdlsop_RX3_r
	if(L && !R && Rm==0x1f && opcode==2 && !(size&1)) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_H1_i1h
	if(L && !R && Rm==0x1f && opcode==3 && !(size&1)) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_H3_i3h
	if(L && !R && Rm==0x1f && opcode==6 && !S) return LD1R_advsimd(ctx, dec); // -> LD1R_asisdlsop_R1_i
	if(L && !R && Rm==0x1f && opcode==7 && !S) return LD3R_advsimd(ctx, dec); // -> LD3R_asisdlsop_R3_i
	if(L && R && Rm!=0x1f && opcode==2 && !(size&1)) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_HX2_r2h
	if(L && R && Rm!=0x1f && opcode==3 && !(size&1)) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_HX4_r4h
	if(L && R && Rm!=0x1f && opcode==6 && !S) return LD2R_advsimd(ctx, dec); // -> LD2R_asisdlsop_RX2_r
	if(L && R && Rm!=0x1f && opcode==7 && !S) return LD4R_advsimd(ctx, dec); // -> LD4R_asisdlsop_RX4_r
	if(L && R && Rm==0x1f && opcode==2 && !(size&1)) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_H2_i2h
	if(L && R && Rm==0x1f && opcode==3 && !(size&1)) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_H4_i4h
	if(L && R && Rm==0x1f && opcode==6 && !S) return LD2R_advsimd(ctx, dec); // -> LD2R_asisdlsop_R2_i
	if(L && R && Rm==0x1f && opcode==7 && !S) return LD4R_advsimd(ctx, dec); // -> LD4R_asisdlsop_R4_i
	if(!L && !R && Rm!=0x1f && !opcode) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_BX1_r1b
	if(!L && !R && Rm!=0x1f && opcode==1) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_BX3_r3b
	if(!L && !R && Rm==0x1f && !opcode) return ST1_advsimd_sngl(ctx, dec); // -> ST1_asisdlsop_B1_i1b
	if(!L && !R && Rm==0x1f && opcode==1) return ST3_advsimd_sngl(ctx, dec); // -> ST3_asisdlsop_B3_i3b
	if(!L && R && Rm!=0x1f && !opcode) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_BX2_r2b
	if(!L && R && Rm!=0x1f && opcode==1) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_BX4_r4b
	if(!L && R && Rm==0x1f && !opcode) return ST2_advsimd_sngl(ctx, dec); // -> ST2_asisdlsop_B2_i2b
	if(!L && R && Rm==0x1f && opcode==1) return ST4_advsimd_sngl(ctx, dec); // -> ST4_asisdlsop_B4_i4b
	if(L && !R && Rm!=0x1f && !opcode) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_BX1_r1b
	if(L && !R && Rm!=0x1f && opcode==1) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_BX3_r3b
	if(L && !R && Rm==0x1f && !opcode) return LD1_advsimd_sngl(ctx, dec); // -> LD1_asisdlsop_B1_i1b
	if(L && !R && Rm==0x1f && opcode==1) return LD3_advsimd_sngl(ctx, dec); // -> LD3_asisdlsop_B3_i3b
	if(L && R && Rm!=0x1f && !opcode) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_BX2_r2b
	if(L && R && Rm!=0x1f && opcode==1) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_BX4_r4b
	if(L && R && Rm==0x1f && !opcode) return LD2_advsimd_sngl(ctx, dec); // -> LD2_asisdlsop_B2_i2b
	if(L && R && Rm==0x1f && opcode==1) return LD4_advsimd_sngl(ctx, dec); // -> LD4_asisdlsop_B4_i4b
	if(!L && !R && opcode==4 && S && size==1) UNALLOCATED(ENC_UNALLOCATED_18_ASISDLSOP);
	if(!L && !R && opcode==5 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_33_ASISDLSOP);
	if(!L && R && opcode==4 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_25_ASISDLSOP);
	if(!L && R && opcode==5 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_41_ASISDLSOP);
	if(L && !R && opcode==4 && S && size==1) UNALLOCATED(ENC_UNALLOCATED_48_ASISDLSOP);
	if(L && !R && opcode==5 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_68_ASISDLSOP);
	if(L && R && opcode==4 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_58_ASISDLSOP);
	if(L && R && opcode==5 && !S && size==3) UNALLOCATED(ENC_UNALLOCATED_78_ASISDLSOP);
	if(!L && !R && opcode==5 && size==2) UNALLOCATED(ENC_UNALLOCATED_31_ASISDLSOP);
	if(!L && !R && opcode==5 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_34_ASISDLSOP);
	if(!L && R && opcode==4 && size==2) UNALLOCATED(ENC_UNALLOCATED_23_ASISDLSOP);
	if(!L && R && opcode==4 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_26_ASISDLSOP);
	if(!L && R && opcode==5 && size==2) UNALLOCATED(ENC_UNALLOCATED_39_ASISDLSOP);
	if(!L && R && opcode==5 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_42_ASISDLSOP);
	if(L && !R && opcode==5 && size==2) UNALLOCATED(ENC_UNALLOCATED_66_ASISDLSOP);
	if(L && !R && opcode==5 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_69_ASISDLSOP);
	if(L && R && opcode==4 && size==2) UNALLOCATED(ENC_UNALLOCATED_56_ASISDLSOP);
	if(L && R && opcode==4 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_59_ASISDLSOP);
	if(L && R && opcode==5 && size==2) UNALLOCATED(ENC_UNALLOCATED_76_ASISDLSOP);
	if(L && R && opcode==5 && S && size&1) UNALLOCATED(ENC_UNALLOCATED_79_ASISDLSOP);
	if(!L && !R && opcode==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_14_ASISDLSOP);
	if(!L && !R && opcode==3 && size&1) UNALLOCATED(ENC_UNALLOCATED_29_ASISDLSOP);
	if(!L && !R && opcode==4 && (size&2)==2) UNALLOCATED(ENC_UNALLOCATED_16_ASISDLSOP);
	if(!L && R && opcode==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_21_ASISDLSOP);
	if(!L && R && opcode==3 && size&1) UNALLOCATED(ENC_UNALLOCATED_37_ASISDLSOP);
	if(L && !R && opcode==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_45_ASISDLSOP);
	if(L && !R && opcode==3 && size&1) UNALLOCATED(ENC_UNALLOCATED_64_ASISDLSOP);
	if(L && !R && opcode==4 && (size&2)==2) UNALLOCATED(ENC_UNALLOCATED_49_ASISDLSOP);
	if(L && !R && opcode==6 && S) UNALLOCATED(ENC_UNALLOCATED_51_ASISDLSOP);
	if(L && !R && opcode==7 && S) UNALLOCATED(ENC_UNALLOCATED_71_ASISDLSOP);
	if(L && R && opcode==2 && size&1) UNALLOCATED(ENC_UNALLOCATED_54_ASISDLSOP);
	if(L && R && opcode==3 && size&1) UNALLOCATED(ENC_UNALLOCATED_74_ASISDLSOP);
	if(L && R && opcode==6 && S) UNALLOCATED(ENC_UNALLOCATED_61_ASISDLSOP);
	if(L && R && opcode==7 && S) UNALLOCATED(ENC_UNALLOCATED_81_ASISDLSOP);
	if(!L && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_11_ASISDLSOP);
	UNMATCHED;
}

int decode_iclass_memop(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, V=(INSWORD>>26)&1, A=(INSWORD>>23)&1, R=(INSWORD>>22)&1, o3=(INSWORD>>15)&1, opc=(INSWORD>>12)&7;
	if(!size && !V && !A && !R && !o3 && !opc && HasLSE()) return LDADDB(ctx, dec); // -> LDADDB_32_memop
	if(!size && !V && !A && !R && !o3 && opc==1 && HasLSE()) return LDCLRB(ctx, dec); // -> LDCLRB_32_memop
	if(!size && !V && !A && !R && !o3 && opc==2 && HasLSE()) return LDEORB(ctx, dec); // -> LDEORB_32_memop
	if(!size && !V && !A && !R && !o3 && opc==3 && HasLSE()) return LDSETB(ctx, dec); // -> LDSETB_32_memop
	if(!size && !V && !A && !R && !o3 && opc==4 && HasLSE()) return LDSMAXB(ctx, dec); // -> LDSMAXB_32_memop
	if(!size && !V && !A && !R && !o3 && opc==5 && HasLSE()) return LDSMINB(ctx, dec); // -> LDSMINB_32_memop
	if(!size && !V && !A && !R && !o3 && opc==6 && HasLSE()) return LDUMAXB(ctx, dec); // -> LDUMAXB_32_memop
	if(!size && !V && !A && !R && !o3 && opc==7 && HasLSE()) return LDUMINB(ctx, dec); // -> LDUMINB_32_memop
	if(!size && !V && !A && !R && o3 && !opc && HasLSE()) return SWPB(ctx, dec); // -> SWPB_32_memop
	if(!size && !V && !A && !R && o3 && opc==1) UNALLOCATED(ENC_UNALLOCATED_154_MEMOP);
	if(!size && !V && !A && !R && o3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_161_MEMOP);
	if(!size && !V && !A && !R && o3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_168_MEMOP);
	if(!size && !V && !A && !R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_181_MEMOP);
	if(!size && !V && !A && R && !o3 && !opc && HasLSE()) return LDADDB(ctx, dec); // -> LDADDLB_32_memop
	if(!size && !V && !A && R && !o3 && opc==1 && HasLSE()) return LDCLRB(ctx, dec); // -> LDCLRLB_32_memop
	if(!size && !V && !A && R && !o3 && opc==2 && HasLSE()) return LDEORB(ctx, dec); // -> LDEORLB_32_memop
	if(!size && !V && !A && R && !o3 && opc==3 && HasLSE()) return LDSETB(ctx, dec); // -> LDSETLB_32_memop
	if(!size && !V && !A && R && !o3 && opc==4 && HasLSE()) return LDSMAXB(ctx, dec); // -> LDSMAXLB_32_memop
	if(!size && !V && !A && R && !o3 && opc==5 && HasLSE()) return LDSMINB(ctx, dec); // -> LDSMINLB_32_memop
	if(!size && !V && !A && R && !o3 && opc==6 && HasLSE()) return LDUMAXB(ctx, dec); // -> LDUMAXLB_32_memop
	if(!size && !V && !A && R && !o3 && opc==7 && HasLSE()) return LDUMINB(ctx, dec); // -> LDUMINLB_32_memop
	if(!size && !V && !A && R && o3 && !opc && HasLSE()) return SWPB(ctx, dec); // -> SWPLB_32_memop
	if(!size && !V && A && !R && !o3 && !opc && HasLSE()) return LDADDB(ctx, dec); // -> LDADDAB_32_memop
	if(!size && !V && A && !R && !o3 && opc==1 && HasLSE()) return LDCLRB(ctx, dec); // -> LDCLRAB_32_memop
	if(!size && !V && A && !R && !o3 && opc==2 && HasLSE()) return LDEORB(ctx, dec); // -> LDEORAB_32_memop
	if(!size && !V && A && !R && !o3 && opc==3 && HasLSE()) return LDSETB(ctx, dec); // -> LDSETAB_32_memop
	if(!size && !V && A && !R && !o3 && opc==4 && HasLSE()) return LDSMAXB(ctx, dec); // -> LDSMAXAB_32_memop
	if(!size && !V && A && !R && !o3 && opc==5 && HasLSE()) return LDSMINB(ctx, dec); // -> LDSMINAB_32_memop
	if(!size && !V && A && !R && !o3 && opc==6 && HasLSE()) return LDUMAXB(ctx, dec); // -> LDUMAXAB_32_memop
	if(!size && !V && A && !R && !o3 && opc==7 && HasLSE()) return LDUMINB(ctx, dec); // -> LDUMINAB_32_memop
	if(!size && !V && A && !R && o3 && !opc && HasLSE()) return SWPB(ctx, dec); // -> SWPAB_32_memop
	if(!size && !V && A && !R && o3 && opc==4 && HasRCPC()) return LDAPRB(ctx, dec); // -> LDAPRB_32L_memop
	if(!size && !V && A && R && !o3 && !opc && HasLSE()) return LDADDB(ctx, dec); // -> LDADDALB_32_memop
	if(!size && !V && A && R && !o3 && opc==1 && HasLSE()) return LDCLRB(ctx, dec); // -> LDCLRALB_32_memop
	if(!size && !V && A && R && !o3 && opc==2 && HasLSE()) return LDEORB(ctx, dec); // -> LDEORALB_32_memop
	if(!size && !V && A && R && !o3 && opc==3 && HasLSE()) return LDSETB(ctx, dec); // -> LDSETALB_32_memop
	if(!size && !V && A && R && !o3 && opc==4 && HasLSE()) return LDSMAXB(ctx, dec); // -> LDSMAXALB_32_memop
	if(!size && !V && A && R && !o3 && opc==5 && HasLSE()) return LDSMINB(ctx, dec); // -> LDSMINALB_32_memop
	if(!size && !V && A && R && !o3 && opc==6 && HasLSE()) return LDUMAXB(ctx, dec); // -> LDUMAXALB_32_memop
	if(!size && !V && A && R && !o3 && opc==7 && HasLSE()) return LDUMINB(ctx, dec); // -> LDUMINALB_32_memop
	if(!size && !V && A && R && o3 && !opc && HasLSE()) return SWPB(ctx, dec); // -> SWPALB_32_memop
	if(size==1 && !V && !A && !R && !o3 && !opc && HasLSE()) return LDADDH(ctx, dec); // -> LDADDH_32_memop
	if(size==1 && !V && !A && !R && !o3 && opc==1 && HasLSE()) return LDCLRH(ctx, dec); // -> LDCLRH_32_memop
	if(size==1 && !V && !A && !R && !o3 && opc==2 && HasLSE()) return LDEORH(ctx, dec); // -> LDEORH_32_memop
	if(size==1 && !V && !A && !R && !o3 && opc==3 && HasLSE()) return LDSETH(ctx, dec); // -> LDSETH_32_memop
	if(size==1 && !V && !A && !R && !o3 && opc==4 && HasLSE()) return LDSMAXH(ctx, dec); // -> LDSMAXH_32_memop
	if(size==1 && !V && !A && !R && !o3 && opc==5 && HasLSE()) return LDSMINH(ctx, dec); // -> LDSMINH_32_memop
	if(size==1 && !V && !A && !R && !o3 && opc==6 && HasLSE()) return LDUMAXH(ctx, dec); // -> LDUMAXH_32_memop
	if(size==1 && !V && !A && !R && !o3 && opc==7 && HasLSE()) return LDUMINH(ctx, dec); // -> LDUMINH_32_memop
	if(size==1 && !V && !A && !R && o3 && !opc && HasLSE()) return SWPH(ctx, dec); // -> SWPH_32_memop
	if(size==1 && !V && !A && !R && o3 && opc==1) UNALLOCATED(ENC_UNALLOCATED_155_MEMOP);
	if(size==1 && !V && !A && !R && o3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_162_MEMOP);
	if(size==1 && !V && !A && !R && o3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_169_MEMOP);
	if(size==1 && !V && !A && !R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_182_MEMOP);
	if(size==1 && !V && !A && R && !o3 && !opc && HasLSE()) return LDADDH(ctx, dec); // -> LDADDLH_32_memop
	if(size==1 && !V && !A && R && !o3 && opc==1 && HasLSE()) return LDCLRH(ctx, dec); // -> LDCLRLH_32_memop
	if(size==1 && !V && !A && R && !o3 && opc==2 && HasLSE()) return LDEORH(ctx, dec); // -> LDEORLH_32_memop
	if(size==1 && !V && !A && R && !o3 && opc==3 && HasLSE()) return LDSETH(ctx, dec); // -> LDSETLH_32_memop
	if(size==1 && !V && !A && R && !o3 && opc==4 && HasLSE()) return LDSMAXH(ctx, dec); // -> LDSMAXLH_32_memop
	if(size==1 && !V && !A && R && !o3 && opc==5 && HasLSE()) return LDSMINH(ctx, dec); // -> LDSMINLH_32_memop
	if(size==1 && !V && !A && R && !o3 && opc==6 && HasLSE()) return LDUMAXH(ctx, dec); // -> LDUMAXLH_32_memop
	if(size==1 && !V && !A && R && !o3 && opc==7 && HasLSE()) return LDUMINH(ctx, dec); // -> LDUMINLH_32_memop
	if(size==1 && !V && !A && R && o3 && !opc && HasLSE()) return SWPH(ctx, dec); // -> SWPLH_32_memop
	if(size==1 && !V && A && !R && !o3 && !opc && HasLSE()) return LDADDH(ctx, dec); // -> LDADDAH_32_memop
	if(size==1 && !V && A && !R && !o3 && opc==1 && HasLSE()) return LDCLRH(ctx, dec); // -> LDCLRAH_32_memop
	if(size==1 && !V && A && !R && !o3 && opc==2 && HasLSE()) return LDEORH(ctx, dec); // -> LDEORAH_32_memop
	if(size==1 && !V && A && !R && !o3 && opc==3 && HasLSE()) return LDSETH(ctx, dec); // -> LDSETAH_32_memop
	if(size==1 && !V && A && !R && !o3 && opc==4 && HasLSE()) return LDSMAXH(ctx, dec); // -> LDSMAXAH_32_memop
	if(size==1 && !V && A && !R && !o3 && opc==5 && HasLSE()) return LDSMINH(ctx, dec); // -> LDSMINAH_32_memop
	if(size==1 && !V && A && !R && !o3 && opc==6 && HasLSE()) return LDUMAXH(ctx, dec); // -> LDUMAXAH_32_memop
	if(size==1 && !V && A && !R && !o3 && opc==7 && HasLSE()) return LDUMINH(ctx, dec); // -> LDUMINAH_32_memop
	if(size==1 && !V && A && !R && o3 && !opc && HasLSE()) return SWPH(ctx, dec); // -> SWPAH_32_memop
	if(size==1 && !V && A && !R && o3 && opc==4 && HasRCPC()) return LDAPRH(ctx, dec); // -> LDAPRH_32L_memop
	if(size==1 && !V && A && R && !o3 && !opc && HasLSE()) return LDADDH(ctx, dec); // -> LDADDALH_32_memop
	if(size==1 && !V && A && R && !o3 && opc==1 && HasLSE()) return LDCLRH(ctx, dec); // -> LDCLRALH_32_memop
	if(size==1 && !V && A && R && !o3 && opc==2 && HasLSE()) return LDEORH(ctx, dec); // -> LDEORALH_32_memop
	if(size==1 && !V && A && R && !o3 && opc==3 && HasLSE()) return LDSETH(ctx, dec); // -> LDSETALH_32_memop
	if(size==1 && !V && A && R && !o3 && opc==4 && HasLSE()) return LDSMAXH(ctx, dec); // -> LDSMAXALH_32_memop
	if(size==1 && !V && A && R && !o3 && opc==5 && HasLSE()) return LDSMINH(ctx, dec); // -> LDSMINALH_32_memop
	if(size==1 && !V && A && R && !o3 && opc==6 && HasLSE()) return LDUMAXH(ctx, dec); // -> LDUMAXALH_32_memop
	if(size==1 && !V && A && R && !o3 && opc==7 && HasLSE()) return LDUMINH(ctx, dec); // -> LDUMINALH_32_memop
	if(size==1 && !V && A && R && o3 && !opc && HasLSE()) return SWPH(ctx, dec); // -> SWPALH_32_memop
	if(size==2 && !V && !A && !R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADD_32_memop
	if(size==2 && !V && !A && !R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLR_32_memop
	if(size==2 && !V && !A && !R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEOR_32_memop
	if(size==2 && !V && !A && !R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSET_32_memop
	if(size==2 && !V && !A && !R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAX_32_memop
	if(size==2 && !V && !A && !R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMIN_32_memop
	if(size==2 && !V && !A && !R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAX_32_memop
	if(size==2 && !V && !A && !R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMIN_32_memop
	if(size==2 && !V && !A && !R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWP_32_memop
	if(size==2 && !V && !A && !R && o3 && opc==1) UNALLOCATED(ENC_UNALLOCATED_156_MEMOP);
	if(size==2 && !V && !A && !R && o3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_163_MEMOP);
	if(size==2 && !V && !A && !R && o3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_170_MEMOP);
	if(size==2 && !V && !A && !R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_183_MEMOP);
	if(size==2 && !V && !A && R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDL_32_memop
	if(size==2 && !V && !A && R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRL_32_memop
	if(size==2 && !V && !A && R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORL_32_memop
	if(size==2 && !V && !A && R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETL_32_memop
	if(size==2 && !V && !A && R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXL_32_memop
	if(size==2 && !V && !A && R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINL_32_memop
	if(size==2 && !V && !A && R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXL_32_memop
	if(size==2 && !V && !A && R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINL_32_memop
	if(size==2 && !V && !A && R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPL_32_memop
	if(size==2 && !V && A && !R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDA_32_memop
	if(size==2 && !V && A && !R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRA_32_memop
	if(size==2 && !V && A && !R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORA_32_memop
	if(size==2 && !V && A && !R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETA_32_memop
	if(size==2 && !V && A && !R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXA_32_memop
	if(size==2 && !V && A && !R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINA_32_memop
	if(size==2 && !V && A && !R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXA_32_memop
	if(size==2 && !V && A && !R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINA_32_memop
	if(size==2 && !V && A && !R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPA_32_memop
	if(size==2 && !V && A && !R && o3 && opc==4 && HasRCPC()) return LDAPR(ctx, dec); // -> LDAPR_32L_memop
	if(size==2 && !V && A && R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDAL_32_memop
	if(size==2 && !V && A && R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRAL_32_memop
	if(size==2 && !V && A && R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORAL_32_memop
	if(size==2 && !V && A && R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETAL_32_memop
	if(size==2 && !V && A && R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXAL_32_memop
	if(size==2 && !V && A && R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINAL_32_memop
	if(size==2 && !V && A && R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXAL_32_memop
	if(size==2 && !V && A && R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINAL_32_memop
	if(size==2 && !V && A && R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPAL_32_memop
	if(size==3 && !V && !A && !R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADD_64_memop
	if(size==3 && !V && !A && !R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLR_64_memop
	if(size==3 && !V && !A && !R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEOR_64_memop
	if(size==3 && !V && !A && !R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSET_64_memop
	if(size==3 && !V && !A && !R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAX_64_memop
	if(size==3 && !V && !A && !R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMIN_64_memop
	if(size==3 && !V && !A && !R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAX_64_memop
	if(size==3 && !V && !A && !R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMIN_64_memop
	if(size==3 && !V && !A && !R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWP_64_memop
	if(size==3 && !V && !A && R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDL_64_memop
	if(size==3 && !V && !A && R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRL_64_memop
	if(size==3 && !V && !A && R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORL_64_memop
	if(size==3 && !V && !A && R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETL_64_memop
	if(size==3 && !V && !A && R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXL_64_memop
	if(size==3 && !V && !A && R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINL_64_memop
	if(size==3 && !V && !A && R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXL_64_memop
	if(size==3 && !V && !A && R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINL_64_memop
	if(size==3 && !V && !A && R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPL_64_memop
	if(size==3 && !V && A && !R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDA_64_memop
	if(size==3 && !V && A && !R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRA_64_memop
	if(size==3 && !V && A && !R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORA_64_memop
	if(size==3 && !V && A && !R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETA_64_memop
	if(size==3 && !V && A && !R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXA_64_memop
	if(size==3 && !V && A && !R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINA_64_memop
	if(size==3 && !V && A && !R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXA_64_memop
	if(size==3 && !V && A && !R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINA_64_memop
	if(size==3 && !V && A && !R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPA_64_memop
	if(size==3 && !V && A && !R && o3 && opc==4 && HasRCPC()) return LDAPR(ctx, dec); // -> LDAPR_64L_memop
	if(size==3 && !V && A && R && !o3 && !opc && HasLSE()) return LDADD(ctx, dec); // -> LDADDAL_64_memop
	if(size==3 && !V && A && R && !o3 && opc==1 && HasLSE()) return LDCLR(ctx, dec); // -> LDCLRAL_64_memop
	if(size==3 && !V && A && R && !o3 && opc==2 && HasLSE()) return LDEOR(ctx, dec); // -> LDEORAL_64_memop
	if(size==3 && !V && A && R && !o3 && opc==3 && HasLSE()) return LDSET(ctx, dec); // -> LDSETAL_64_memop
	if(size==3 && !V && A && R && !o3 && opc==4 && HasLSE()) return LDSMAX(ctx, dec); // -> LDSMAXAL_64_memop
	if(size==3 && !V && A && R && !o3 && opc==5 && HasLSE()) return LDSMIN(ctx, dec); // -> LDSMINAL_64_memop
	if(size==3 && !V && A && R && !o3 && opc==6 && HasLSE()) return LDUMAX(ctx, dec); // -> LDUMAXAL_64_memop
	if(size==3 && !V && A && R && !o3 && opc==7 && HasLSE()) return LDUMIN(ctx, dec); // -> LDUMINAL_64_memop
	if(size==3 && !V && A && R && o3 && !opc && HasLSE()) return SWP(ctx, dec); // -> SWPAL_64_memop
	if(!V && !A && R && o3 && opc==1) UNALLOCATED(ENC_UNALLOCATED_158_MEMOP);
	if(!V && !A && R && o3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_165_MEMOP);
	if(!V && !A && R && o3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_172_MEMOP);
	if(!V && !A && R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_185_MEMOP);
	if(!V && A && !R && o3 && opc==1) UNALLOCATED(ENC_UNALLOCATED_159_MEMOP);
	if(!V && A && !R && o3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_166_MEMOP);
	if(!V && A && !R && o3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_173_MEMOP);
	if(!V && A && !R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_186_MEMOP);
	if(!V && A && R && o3 && opc==1) UNALLOCATED(ENC_UNALLOCATED_160_MEMOP);
	if(!V && A && R && o3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_167_MEMOP);
	if(!V && A && R && o3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_174_MEMOP);
	if(!V && A && R && o3 && opc==4) UNALLOCATED(ENC_UNALLOCATED_180_MEMOP);
	if(!V && A && R && o3 && opc==5) UNALLOCATED(ENC_UNALLOCATED_187_MEMOP);
	if(!V && !A && o3 && opc==4) UNALLOCATED(ENC_UNALLOCATED_175_MEMOP);
	if(!V && o3 && (opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_188_MEMOP);
	if(V) UNALLOCATED(ENC_UNALLOCATED_189_MEMOP);
	UNMATCHED;
}

int decode_iclass_ldapstl_unscaled(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, opc=(INSWORD>>22)&3;
	if(!size && !opc && HasRCPC_84()) return STLURB(ctx, dec); // -> STLURB_32_ldapstl_unscaled
	if(!size && opc==1 && HasRCPC_84()) return LDAPURB(ctx, dec); // -> LDAPURB_32_ldapstl_unscaled
	if(!size && opc==2 && HasRCPC_84()) return LDAPURSB(ctx, dec); // -> LDAPURSB_64_ldapstl_unscaled
	if(!size && opc==3 && HasRCPC_84()) return LDAPURSB(ctx, dec); // -> LDAPURSB_32_ldapstl_unscaled
	if(size==1 && !opc && HasRCPC_84()) return STLURH(ctx, dec); // -> STLURH_32_ldapstl_unscaled
	if(size==1 && opc==1 && HasRCPC_84()) return LDAPURH(ctx, dec); // -> LDAPURH_32_ldapstl_unscaled
	if(size==1 && opc==2 && HasRCPC_84()) return LDAPURSH(ctx, dec); // -> LDAPURSH_64_ldapstl_unscaled
	if(size==1 && opc==3 && HasRCPC_84()) return LDAPURSH(ctx, dec); // -> LDAPURSH_32_ldapstl_unscaled
	if(size==2 && !opc && HasRCPC_84()) return STLUR_gen(ctx, dec); // -> STLUR_32_ldapstl_unscaled
	if(size==2 && opc==1 && HasRCPC_84()) return LDAPUR_gen(ctx, dec); // -> LDAPUR_32_ldapstl_unscaled
	if(size==2 && opc==2 && HasRCPC_84()) return LDAPURSW(ctx, dec); // -> LDAPURSW_64_ldapstl_unscaled
	if(size==2 && opc==3) UNALLOCATED(ENC_UNALLOCATED_24_LDAPSTL_UNSCALED);
	if(size==3 && !opc && HasRCPC_84()) return STLUR_gen(ctx, dec); // -> STLUR_64_ldapstl_unscaled
	if(size==3 && opc==1 && HasRCPC_84()) return LDAPUR_gen(ctx, dec); // -> LDAPUR_64_ldapstl_unscaled
	if(size==3 && opc==2) UNALLOCATED(ENC_UNALLOCATED_21_LDAPSTL_UNSCALED);
	if(size==3 && opc==3) UNALLOCATED(ENC_UNALLOCATED_25_LDAPSTL_UNSCALED);
	UNMATCHED;
}

int decode_iclass_loadlit(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, V=(INSWORD>>26)&1;
	if(!opc && !V) return LDR_lit_gen(ctx, dec); // -> LDR_32_loadlit
	if(!opc && V) return LDR_lit_fpsimd(ctx, dec); // -> LDR_S_loadlit
	if(opc==1 && !V) return LDR_lit_gen(ctx, dec); // -> LDR_64_loadlit
	if(opc==1 && V) return LDR_lit_fpsimd(ctx, dec); // -> LDR_D_loadlit
	if(opc==2 && !V) return LDRSW_lit(ctx, dec); // -> LDRSW_64_loadlit
	if(opc==2 && V) return LDR_lit_fpsimd(ctx, dec); // -> LDR_Q_loadlit
	if(opc==3 && !V) return PRFM_lit(ctx, dec); // -> PRFM_P_loadlit
	if(opc==3 && V) UNALLOCATED(ENC_UNALLOCATED_17_LOADLIT);
	UNMATCHED;
}

int decode_iclass_ldstexcl(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, o2=(INSWORD>>23)&1, L=(INSWORD>>22)&1, o1=(INSWORD>>21)&1, o0=(INSWORD>>15)&1, Rt2=(INSWORD>>10)&0x1f;
	if(!size && !o2 && !L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASP_CP32_ldstexcl
	if(!size && !o2 && !L && o1 && o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPL_CP32_ldstexcl
	if(!size && !o2 && L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPA_CP32_ldstexcl
	if(!size && !o2 && L && o1 && o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPAL_CP32_ldstexcl
	if(!size && o2 && !L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CASB(ctx, dec); // -> CASB_C32_ldstexcl
	if(!size && o2 && !L && o1 && o0 && Rt2==0x1f && HasLSE()) return CASB(ctx, dec); // -> CASLB_C32_ldstexcl
	if(!size && o2 && L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CASB(ctx, dec); // -> CASAB_C32_ldstexcl
	if(!size && o2 && L && o1 && o0 && Rt2==0x1f && HasLSE()) return CASB(ctx, dec); // -> CASALB_C32_ldstexcl
	if(size==1 && !o2 && !L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASP_CP64_ldstexcl
	if(size==1 && !o2 && !L && o1 && o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPL_CP64_ldstexcl
	if(size==1 && !o2 && L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPA_CP64_ldstexcl
	if(size==1 && !o2 && L && o1 && o0 && Rt2==0x1f && HasLSE()) return CASP(ctx, dec); // -> CASPAL_CP64_ldstexcl
	if(size==1 && o2 && !L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CASH(ctx, dec); // -> CASH_C32_ldstexcl
	if(size==1 && o2 && !L && o1 && o0 && Rt2==0x1f && HasLSE()) return CASH(ctx, dec); // -> CASLH_C32_ldstexcl
	if(size==1 && o2 && L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CASH(ctx, dec); // -> CASAH_C32_ldstexcl
	if(size==1 && o2 && L && o1 && o0 && Rt2==0x1f && HasLSE()) return CASH(ctx, dec); // -> CASALH_C32_ldstexcl
	if(size==2 && o2 && !L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CAS_C32_ldstexcl
	if(size==2 && o2 && !L && o1 && o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASL_C32_ldstexcl
	if(size==2 && o2 && L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASA_C32_ldstexcl
	if(size==2 && o2 && L && o1 && o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASAL_C32_ldstexcl
	if(size==3 && o2 && !L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CAS_C64_ldstexcl
	if(size==3 && o2 && !L && o1 && o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASL_C64_ldstexcl
	if(size==3 && o2 && L && o1 && !o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASA_C64_ldstexcl
	if(size==3 && o2 && L && o1 && o0 && Rt2==0x1f && HasLSE()) return CAS(ctx, dec); // -> CASAL_C64_ldstexcl
	if(!(size&2) && !o2 && o1 && Rt2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_26_LDSTEXCL);
	if(o2 && o1 && Rt2!=0x1f) UNALLOCATED(ENC_UNALLOCATED_59_LDSTEXCL);
	if(!size && !o2 && !L && !o1 && !o0) return STXRB(ctx, dec); // -> STXRB_SR32_ldstexcl
	if(!size && !o2 && !L && !o1 && o0) return STLXRB(ctx, dec); // -> STLXRB_SR32_ldstexcl
	if(!size && !o2 && L && !o1 && !o0) return LDXRB(ctx, dec); // -> LDXRB_LR32_ldstexcl
	if(!size && !o2 && L && !o1 && o0) return LDAXRB(ctx, dec); // -> LDAXRB_LR32_ldstexcl
	if(!size && o2 && !L && !o1 && !o0 && HasLOR()) return STLLRB(ctx, dec); // -> STLLRB_SL32_ldstexcl
	if(!size && o2 && !L && !o1 && o0) return STLRB(ctx, dec); // -> STLRB_SL32_ldstexcl
	if(!size && o2 && L && !o1 && !o0 && HasLOR()) return LDLARB(ctx, dec); // -> LDLARB_LR32_ldstexcl
	if(!size && o2 && L && !o1 && o0) return LDARB(ctx, dec); // -> LDARB_LR32_ldstexcl
	if(size==1 && !o2 && !L && !o1 && !o0) return STXRH(ctx, dec); // -> STXRH_SR32_ldstexcl
	if(size==1 && !o2 && !L && !o1 && o0) return STLXRH(ctx, dec); // -> STLXRH_SR32_ldstexcl
	if(size==1 && !o2 && L && !o1 && !o0) return LDXRH(ctx, dec); // -> LDXRH_LR32_ldstexcl
	if(size==1 && !o2 && L && !o1 && o0) return LDAXRH(ctx, dec); // -> LDAXRH_LR32_ldstexcl
	if(size==1 && o2 && !L && !o1 && !o0 && HasLOR()) return STLLRH(ctx, dec); // -> STLLRH_SL32_ldstexcl
	if(size==1 && o2 && !L && !o1 && o0) return STLRH(ctx, dec); // -> STLRH_SL32_ldstexcl
	if(size==1 && o2 && L && !o1 && !o0 && HasLOR()) return LDLARH(ctx, dec); // -> LDLARH_LR32_ldstexcl
	if(size==1 && o2 && L && !o1 && o0) return LDARH(ctx, dec); // -> LDARH_LR32_ldstexcl
	if(size==2 && !o2 && !L && !o1 && !o0) return STXR(ctx, dec); // -> STXR_SR32_ldstexcl
	if(size==2 && !o2 && !L && !o1 && o0) return STLXR(ctx, dec); // -> STLXR_SR32_ldstexcl
	if(size==2 && !o2 && !L && o1 && !o0) return STXP(ctx, dec); // -> STXP_SP32_ldstexcl
	if(size==2 && !o2 && !L && o1 && o0) return STLXP(ctx, dec); // -> STLXP_SP32_ldstexcl
	if(size==2 && !o2 && L && !o1 && !o0) return LDXR(ctx, dec); // -> LDXR_LR32_ldstexcl
	if(size==2 && !o2 && L && !o1 && o0) return LDAXR(ctx, dec); // -> LDAXR_LR32_ldstexcl
	if(size==2 && !o2 && L && o1 && !o0) return LDXP(ctx, dec); // -> LDXP_LP32_ldstexcl
	if(size==2 && !o2 && L && o1 && o0) return LDAXP(ctx, dec); // -> LDAXP_LP32_ldstexcl
	if(size==2 && o2 && !L && !o1 && !o0 && HasLOR()) return STLLR(ctx, dec); // -> STLLR_SL32_ldstexcl
	if(size==2 && o2 && !L && !o1 && o0) return STLR(ctx, dec); // -> STLR_SL32_ldstexcl
	if(size==2 && o2 && L && !o1 && !o0 && HasLOR()) return LDLAR(ctx, dec); // -> LDLAR_LR32_ldstexcl
	if(size==2 && o2 && L && !o1 && o0) return LDAR(ctx, dec); // -> LDAR_LR32_ldstexcl
	if(size==3 && !o2 && !L && !o1 && !o0) return STXR(ctx, dec); // -> STXR_SR64_ldstexcl
	if(size==3 && !o2 && !L && !o1 && o0) return STLXR(ctx, dec); // -> STLXR_SR64_ldstexcl
	if(size==3 && !o2 && !L && o1 && !o0) return STXP(ctx, dec); // -> STXP_SP64_ldstexcl
	if(size==3 && !o2 && !L && o1 && o0) return STLXP(ctx, dec); // -> STLXP_SP64_ldstexcl
	if(size==3 && !o2 && L && !o1 && !o0) return LDXR(ctx, dec); // -> LDXR_LR64_ldstexcl
	if(size==3 && !o2 && L && !o1 && o0) return LDAXR(ctx, dec); // -> LDAXR_LR64_ldstexcl
	if(size==3 && !o2 && L && o1 && !o0) return LDXP(ctx, dec); // -> LDXP_LP64_ldstexcl
	if(size==3 && !o2 && L && o1 && o0) return LDAXP(ctx, dec); // -> LDAXP_LP64_ldstexcl
	if(size==3 && o2 && !L && !o1 && !o0 && HasLOR()) return STLLR(ctx, dec); // -> STLLR_SL64_ldstexcl
	if(size==3 && o2 && !L && !o1 && o0) return STLR(ctx, dec); // -> STLR_SL64_ldstexcl
	if(size==3 && o2 && L && !o1 && !o0 && HasLOR()) return LDLAR(ctx, dec); // -> LDLAR_LR64_ldstexcl
	if(size==3 && o2 && L && !o1 && o0) return LDAR(ctx, dec); // -> LDAR_LR64_ldstexcl
	UNMATCHED;
}

int decode_iclass_ldsttags(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, imm9=(INSWORD>>12)&0x1ff, op2=(INSWORD>>10)&3;
	if(!opc && !imm9 && !op2 && HasMemTag()) return STZGM(ctx, dec); // -> STZGM_64bulk_ldsttags
	if(opc==2 && imm9 && !op2) UNALLOCATED(ENC_UNALLOCATED_13_LDSTTAGS);
	if(opc==2 && !imm9 && !op2 && HasMemTag()) return STGM(ctx, dec); // -> STGM_64bulk_ldsttags
	if(opc==3 && imm9 && !op2) UNALLOCATED(ENC_UNALLOCATED_15_LDSTTAGS);
	if(opc==3 && !imm9 && !op2 && HasMemTag()) return LDGM(ctx, dec); // -> LDGM_64bulk_ldsttags
	if(!opc && op2==1 && HasMemTag()) return STG(ctx, dec); // -> STG_64Spost_ldsttags
	if(!opc && op2==2 && HasMemTag()) return STG(ctx, dec); // -> STG_64Soffset_ldsttags
	if(!opc && op2==3 && HasMemTag()) return STG(ctx, dec); // -> STG_64Spre_ldsttags
	if(opc==1 && !op2 && HasMemTag()) return LDG(ctx, dec); // -> LDG_64Loffset_ldsttags
	if(opc==1 && op2==1 && HasMemTag()) return STZG(ctx, dec); // -> STZG_64Spost_ldsttags
	if(opc==1 && op2==2 && HasMemTag()) return STZG(ctx, dec); // -> STZG_64Soffset_ldsttags
	if(opc==1 && op2==3 && HasMemTag()) return STZG(ctx, dec); // -> STZG_64Spre_ldsttags
	if(opc==2 && op2==1 && HasMemTag()) return ST2G(ctx, dec); // -> ST2G_64Spost_ldsttags
	if(opc==2 && op2==2 && HasMemTag()) return ST2G(ctx, dec); // -> ST2G_64Soffset_ldsttags
	if(opc==2 && op2==3 && HasMemTag()) return ST2G(ctx, dec); // -> ST2G_64Spre_ldsttags
	if(opc==3 && op2==1 && HasMemTag()) return STZ2G(ctx, dec); // -> STZ2G_64Spost_ldsttags
	if(opc==3 && op2==2 && HasMemTag()) return STZ2G(ctx, dec); // -> STZ2G_64Soffset_ldsttags
	if(opc==3 && op2==3 && HasMemTag()) return STZ2G(ctx, dec); // -> STZ2G_64Spre_ldsttags
	UNMATCHED;
}

int decode_iclass_ldstnapair_offs(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, V=(INSWORD>>26)&1, L=(INSWORD>>22)&1;
	if(!opc && !V && !L) return STNP_gen(ctx, dec); // -> STNP_32_ldstnapair_offs
	if(!opc && !V && L) return LDNP_gen(ctx, dec); // -> LDNP_32_ldstnapair_offs
	if(!opc && V && !L) return STNP_fpsimd(ctx, dec); // -> STNP_S_ldstnapair_offs
	if(!opc && V && L) return LDNP_fpsimd(ctx, dec); // -> LDNP_S_ldstnapair_offs
	if(opc==1 && V && !L) return STNP_fpsimd(ctx, dec); // -> STNP_D_ldstnapair_offs
	if(opc==1 && V && L) return LDNP_fpsimd(ctx, dec); // -> LDNP_D_ldstnapair_offs
	if(opc==2 && !V && !L) return STNP_gen(ctx, dec); // -> STNP_64_ldstnapair_offs
	if(opc==2 && !V && L) return LDNP_gen(ctx, dec); // -> LDNP_64_ldstnapair_offs
	if(opc==2 && V && !L) return STNP_fpsimd(ctx, dec); // -> STNP_Q_ldstnapair_offs
	if(opc==2 && V && L) return LDNP_fpsimd(ctx, dec); // -> LDNP_Q_ldstnapair_offs
	if(opc==1 && !V) UNALLOCATED(ENC_UNALLOCATED_12_LDSTNAPAIR_OFFS);
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_21_LDSTNAPAIR_OFFS);
	UNMATCHED;
}

int decode_iclass_ldst_immpost(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, V=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !V && !opc) return STRB_imm(ctx, dec); // -> STRB_32_ldst_immpost
	if(!size && !V && opc==1) return LDRB_imm(ctx, dec); // -> LDRB_32_ldst_immpost
	if(!size && !V && opc==2) return LDRSB_imm(ctx, dec); // -> LDRSB_64_ldst_immpost
	if(!size && !V && opc==3) return LDRSB_imm(ctx, dec); // -> LDRSB_32_ldst_immpost
	if(!size && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_B_ldst_immpost
	if(!size && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_B_ldst_immpost
	if(!size && V && opc==2) return STR_imm_fpsimd(ctx, dec); // -> STR_Q_ldst_immpost
	if(!size && V && opc==3) return LDR_imm_fpsimd(ctx, dec); // -> LDR_Q_ldst_immpost
	if(size==1 && !V && !opc) return STRH_imm(ctx, dec); // -> STRH_32_ldst_immpost
	if(size==1 && !V && opc==1) return LDRH_imm(ctx, dec); // -> LDRH_32_ldst_immpost
	if(size==1 && !V && opc==2) return LDRSH_imm(ctx, dec); // -> LDRSH_64_ldst_immpost
	if(size==1 && !V && opc==3) return LDRSH_imm(ctx, dec); // -> LDRSH_32_ldst_immpost
	if(size==1 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_H_ldst_immpost
	if(size==1 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_H_ldst_immpost
	if(size==2 && !V && !opc) return STR_imm_gen(ctx, dec); // -> STR_32_ldst_immpost
	if(size==2 && !V && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_32_ldst_immpost
	if(size==2 && !V && opc==2) return LDRSW_imm(ctx, dec); // -> LDRSW_64_ldst_immpost
	if(size==2 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_S_ldst_immpost
	if(size==2 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_S_ldst_immpost
	if(size==3 && !V && !opc) return STR_imm_gen(ctx, dec); // -> STR_64_ldst_immpost
	if(size==3 && !V && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_64_ldst_immpost
	if(size==3 && !V && opc==2) UNALLOCATED(ENC_UNALLOCATED_21_LDST_IMMPOST);
	if(size==3 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_D_ldst_immpost
	if(size==3 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_D_ldst_immpost
	if((size&2)==2 && !V && opc==3) UNALLOCATED(ENC_UNALLOCATED_24_LDST_IMMPOST);
	if(size&1 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_35_LDST_IMMPOST);
	if((size&2)==2 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_36_LDST_IMMPOST);
	UNMATCHED;
}

int decode_iclass_ldst_immpre(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, V=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !V && !opc) return STRB_imm(ctx, dec); // -> STRB_32_ldst_immpre
	if(!size && !V && opc==1) return LDRB_imm(ctx, dec); // -> LDRB_32_ldst_immpre
	if(!size && !V && opc==2) return LDRSB_imm(ctx, dec); // -> LDRSB_64_ldst_immpre
	if(!size && !V && opc==3) return LDRSB_imm(ctx, dec); // -> LDRSB_32_ldst_immpre
	if(!size && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_B_ldst_immpre
	if(!size && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_B_ldst_immpre
	if(!size && V && opc==2) return STR_imm_fpsimd(ctx, dec); // -> STR_Q_ldst_immpre
	if(!size && V && opc==3) return LDR_imm_fpsimd(ctx, dec); // -> LDR_Q_ldst_immpre
	if(size==1 && !V && !opc) return STRH_imm(ctx, dec); // -> STRH_32_ldst_immpre
	if(size==1 && !V && opc==1) return LDRH_imm(ctx, dec); // -> LDRH_32_ldst_immpre
	if(size==1 && !V && opc==2) return LDRSH_imm(ctx, dec); // -> LDRSH_64_ldst_immpre
	if(size==1 && !V && opc==3) return LDRSH_imm(ctx, dec); // -> LDRSH_32_ldst_immpre
	if(size==1 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_H_ldst_immpre
	if(size==1 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_H_ldst_immpre
	if(size==2 && !V && !opc) return STR_imm_gen(ctx, dec); // -> STR_32_ldst_immpre
	if(size==2 && !V && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_32_ldst_immpre
	if(size==2 && !V && opc==2) return LDRSW_imm(ctx, dec); // -> LDRSW_64_ldst_immpre
	if(size==2 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_S_ldst_immpre
	if(size==2 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_S_ldst_immpre
	if(size==3 && !V && !opc) return STR_imm_gen(ctx, dec); // -> STR_64_ldst_immpre
	if(size==3 && !V && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_64_ldst_immpre
	if(size==3 && !V && opc==2) UNALLOCATED(ENC_UNALLOCATED_21_LDST_IMMPRE);
	if(size==3 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_D_ldst_immpre
	if(size==3 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_D_ldst_immpre
	if((size&2)==2 && !V && opc==3) UNALLOCATED(ENC_UNALLOCATED_24_LDST_IMMPRE);
	if(size&1 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_35_LDST_IMMPRE);
	if((size&2)==2 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_36_LDST_IMMPRE);
	UNMATCHED;
}

int decode_iclass_ldst_pac(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, V=(INSWORD>>26)&1, M=(INSWORD>>23)&1, W=(INSWORD>>11)&1;
	if(size==3 && !V && !M && !W && HasPAuth()) return LDRA(ctx, dec); // -> LDRAA_64_ldst_pac
	if(size==3 && !V && !M && W && HasPAuth()) return LDRA(ctx, dec); // -> LDRAA_64W_ldst_pac
	if(size==3 && !V && M && !W && HasPAuth()) return LDRA(ctx, dec); // -> LDRAB_64_ldst_pac
	if(size==3 && !V && M && W && HasPAuth()) return LDRA(ctx, dec); // -> LDRAB_64W_ldst_pac
	if(size==3 && V) UNALLOCATED(ENC_UNALLOCATED_15_LDST_PAC);
	if(size!=3) UNALLOCATED(ENC_UNALLOCATED_14_LDST_PAC);
	UNMATCHED;
}

int decode_iclass_ldst_regoff(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, V=(INSWORD>>26)&1, opc=(INSWORD>>22)&3, option=(INSWORD>>13)&7;
	if(!size && !V && !opc && option!=3) return STRB_reg(ctx, dec); // -> STRB_32B_ldst_regoff
	if(!size && !V && !opc && option==3) return STRB_reg(ctx, dec); // -> STRB_32BL_ldst_regoff
	if(!size && !V && opc==1 && option!=3) return LDRB_reg(ctx, dec); // -> LDRB_32B_ldst_regoff
	if(!size && !V && opc==1 && option==3) return LDRB_reg(ctx, dec); // -> LDRB_32BL_ldst_regoff
	if(!size && !V && opc==2 && option!=3) return LDRSB_reg(ctx, dec); // -> LDRSB_64B_ldst_regoff
	if(!size && !V && opc==2 && option==3) return LDRSB_reg(ctx, dec); // -> LDRSB_64BL_ldst_regoff
	if(!size && !V && opc==3 && option!=3) return LDRSB_reg(ctx, dec); // -> LDRSB_32B_ldst_regoff
	if(!size && !V && opc==3 && option==3) return LDRSB_reg(ctx, dec); // -> LDRSB_32BL_ldst_regoff
	if(!size && V && !opc && option!=3) return STR_reg_fpsimd(ctx, dec); // -> STR_B_ldst_regoff
	if(!size && V && !opc && option==3) return STR_reg_fpsimd(ctx, dec); // -> STR_BL_ldst_regoff
	if(!size && V && opc==1 && option!=3) return LDR_reg_fpsimd(ctx, dec); // -> LDR_B_ldst_regoff
	if(!size && V && opc==1 && option==3) return LDR_reg_fpsimd(ctx, dec); // -> LDR_BL_ldst_regoff
	if(!size && V && opc==2) return STR_reg_fpsimd(ctx, dec); // -> STR_Q_ldst_regoff
	if(!size && V && opc==3) return LDR_reg_fpsimd(ctx, dec); // -> LDR_Q_ldst_regoff
	if(size==1 && !V && !opc) return STRH_reg(ctx, dec); // -> STRH_32_ldst_regoff
	if(size==1 && !V && opc==1) return LDRH_reg(ctx, dec); // -> LDRH_32_ldst_regoff
	if(size==1 && !V && opc==2) return LDRSH_reg(ctx, dec); // -> LDRSH_64_ldst_regoff
	if(size==1 && !V && opc==3) return LDRSH_reg(ctx, dec); // -> LDRSH_32_ldst_regoff
	if(size==1 && V && !opc) return STR_reg_fpsimd(ctx, dec); // -> STR_H_ldst_regoff
	if(size==1 && V && opc==1) return LDR_reg_fpsimd(ctx, dec); // -> LDR_H_ldst_regoff
	if(size==2 && !V && !opc) return STR_reg_gen(ctx, dec); // -> STR_32_ldst_regoff
	if(size==2 && !V && opc==1) return LDR_reg_gen(ctx, dec); // -> LDR_32_ldst_regoff
	if(size==2 && !V && opc==2) return LDRSW_reg(ctx, dec); // -> LDRSW_64_ldst_regoff
	if(size==2 && V && !opc) return STR_reg_fpsimd(ctx, dec); // -> STR_S_ldst_regoff
	if(size==2 && V && opc==1) return LDR_reg_fpsimd(ctx, dec); // -> LDR_S_ldst_regoff
	if(size==3 && !V && !opc) return STR_reg_gen(ctx, dec); // -> STR_64_ldst_regoff
	if(size==3 && !V && opc==1) return LDR_reg_gen(ctx, dec); // -> LDR_64_ldst_regoff
	if(size==3 && !V && opc==2) return PRFM_reg(ctx, dec); // -> PRFM_P_ldst_regoff
	if(size==3 && V && !opc) return STR_reg_fpsimd(ctx, dec); // -> STR_D_ldst_regoff
	if(size==3 && V && opc==1) return LDR_reg_fpsimd(ctx, dec); // -> LDR_D_ldst_regoff
	if((size&2)==2 && !V && opc==3) UNALLOCATED(ENC_UNALLOCATED_28_LDST_REGOFF);
	if(size&1 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_41_LDST_REGOFF);
	if((size&2)==2 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_42_LDST_REGOFF);
	UNMATCHED;
}

int decode_iclass_ldst_unpriv(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, V=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !V && !opc) return STTRB(ctx, dec); // -> STTRB_32_ldst_unpriv
	if(!size && !V && opc==1) return LDTRB(ctx, dec); // -> LDTRB_32_ldst_unpriv
	if(!size && !V && opc==2) return LDTRSB(ctx, dec); // -> LDTRSB_64_ldst_unpriv
	if(!size && !V && opc==3) return LDTRSB(ctx, dec); // -> LDTRSB_32_ldst_unpriv
	if(size==1 && !V && !opc) return STTRH(ctx, dec); // -> STTRH_32_ldst_unpriv
	if(size==1 && !V && opc==1) return LDTRH(ctx, dec); // -> LDTRH_32_ldst_unpriv
	if(size==1 && !V && opc==2) return LDTRSH(ctx, dec); // -> LDTRSH_64_ldst_unpriv
	if(size==1 && !V && opc==3) return LDTRSH(ctx, dec); // -> LDTRSH_32_ldst_unpriv
	if(size==2 && !V && !opc) return STTR(ctx, dec); // -> STTR_32_ldst_unpriv
	if(size==2 && !V && opc==1) return LDTR(ctx, dec); // -> LDTR_32_ldst_unpriv
	if(size==2 && !V && opc==2) return LDTRSW(ctx, dec); // -> LDTRSW_64_ldst_unpriv
	if(size==3 && !V && !opc) return STTR(ctx, dec); // -> STTR_64_ldst_unpriv
	if(size==3 && !V && opc==1) return LDTR(ctx, dec); // -> LDTR_64_ldst_unpriv
	if(size==3 && !V && opc==2) UNALLOCATED(ENC_UNALLOCATED_21_LDST_UNPRIV);
	if((size&2)==2 && !V && opc==3) UNALLOCATED(ENC_UNALLOCATED_24_LDST_UNPRIV);
	if(V) UNALLOCATED(ENC_UNALLOCATED_25_LDST_UNPRIV);
	UNMATCHED;
}

int decode_iclass_ldst_unscaled(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, V=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !V && !opc) return STURB(ctx, dec); // -> STURB_32_ldst_unscaled
	if(!size && !V && opc==1) return LDURB(ctx, dec); // -> LDURB_32_ldst_unscaled
	if(!size && !V && opc==2) return LDURSB(ctx, dec); // -> LDURSB_64_ldst_unscaled
	if(!size && !V && opc==3) return LDURSB(ctx, dec); // -> LDURSB_32_ldst_unscaled
	if(!size && V && !opc) return STUR_fpsimd(ctx, dec); // -> STUR_B_ldst_unscaled
	if(!size && V && opc==1) return LDUR_fpsimd(ctx, dec); // -> LDUR_B_ldst_unscaled
	if(!size && V && opc==2) return STUR_fpsimd(ctx, dec); // -> STUR_Q_ldst_unscaled
	if(!size && V && opc==3) return LDUR_fpsimd(ctx, dec); // -> LDUR_Q_ldst_unscaled
	if(size==1 && !V && !opc) return STURH(ctx, dec); // -> STURH_32_ldst_unscaled
	if(size==1 && !V && opc==1) return LDURH(ctx, dec); // -> LDURH_32_ldst_unscaled
	if(size==1 && !V && opc==2) return LDURSH(ctx, dec); // -> LDURSH_64_ldst_unscaled
	if(size==1 && !V && opc==3) return LDURSH(ctx, dec); // -> LDURSH_32_ldst_unscaled
	if(size==1 && V && !opc) return STUR_fpsimd(ctx, dec); // -> STUR_H_ldst_unscaled
	if(size==1 && V && opc==1) return LDUR_fpsimd(ctx, dec); // -> LDUR_H_ldst_unscaled
	if(size==2 && !V && !opc) return STUR_gen(ctx, dec); // -> STUR_32_ldst_unscaled
	if(size==2 && !V && opc==1) return LDUR_gen(ctx, dec); // -> LDUR_32_ldst_unscaled
	if(size==2 && !V && opc==2) return LDURSW(ctx, dec); // -> LDURSW_64_ldst_unscaled
	if(size==2 && V && !opc) return STUR_fpsimd(ctx, dec); // -> STUR_S_ldst_unscaled
	if(size==2 && V && opc==1) return LDUR_fpsimd(ctx, dec); // -> LDUR_S_ldst_unscaled
	if(size==3 && !V && !opc) return STUR_gen(ctx, dec); // -> STUR_64_ldst_unscaled
	if(size==3 && !V && opc==1) return LDUR_gen(ctx, dec); // -> LDUR_64_ldst_unscaled
	if(size==3 && !V && opc==2) return PRFUM(ctx, dec); // -> PRFUM_P_ldst_unscaled
	if(size==3 && V && !opc) return STUR_fpsimd(ctx, dec); // -> STUR_D_ldst_unscaled
	if(size==3 && V && opc==1) return LDUR_fpsimd(ctx, dec); // -> LDUR_D_ldst_unscaled
	if((size&2)==2 && !V && opc==3) UNALLOCATED(ENC_UNALLOCATED_24_LDST_UNSCALED);
	if(size&1 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_35_LDST_UNSCALED);
	if((size&2)==2 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_36_LDST_UNSCALED);
	UNMATCHED;
}

int decode_iclass_ldst_pos(context *ctx, Instruction *dec)
{
	uint32_t size=INSWORD>>30, V=(INSWORD>>26)&1, opc=(INSWORD>>22)&3;
	if(!size && !V && !opc) return STRB_imm(ctx, dec); // -> STRB_32_ldst_pos
	if(!size && !V && opc==1) return LDRB_imm(ctx, dec); // -> LDRB_32_ldst_pos
	if(!size && !V && opc==2) return LDRSB_imm(ctx, dec); // -> LDRSB_64_ldst_pos
	if(!size && !V && opc==3) return LDRSB_imm(ctx, dec); // -> LDRSB_32_ldst_pos
	if(!size && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_B_ldst_pos
	if(!size && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_B_ldst_pos
	if(!size && V && opc==2) return STR_imm_fpsimd(ctx, dec); // -> STR_Q_ldst_pos
	if(!size && V && opc==3) return LDR_imm_fpsimd(ctx, dec); // -> LDR_Q_ldst_pos
	if(size==1 && !V && !opc) return STRH_imm(ctx, dec); // -> STRH_32_ldst_pos
	if(size==1 && !V && opc==1) return LDRH_imm(ctx, dec); // -> LDRH_32_ldst_pos
	if(size==1 && !V && opc==2) return LDRSH_imm(ctx, dec); // -> LDRSH_64_ldst_pos
	if(size==1 && !V && opc==3) return LDRSH_imm(ctx, dec); // -> LDRSH_32_ldst_pos
	if(size==1 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_H_ldst_pos
	if(size==1 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_H_ldst_pos
	if(size==2 && !V && !opc) return STR_imm_gen(ctx, dec); // -> STR_32_ldst_pos
	if(size==2 && !V && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_32_ldst_pos
	if(size==2 && !V && opc==2) return LDRSW_imm(ctx, dec); // -> LDRSW_64_ldst_pos
	if(size==2 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_S_ldst_pos
	if(size==2 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_S_ldst_pos
	if(size==3 && !V && !opc) return STR_imm_gen(ctx, dec); // -> STR_64_ldst_pos
	if(size==3 && !V && opc==1) return LDR_imm_gen(ctx, dec); // -> LDR_64_ldst_pos
	if(size==3 && !V && opc==2) return PRFM_imm(ctx, dec); // -> PRFM_P_ldst_pos
	if(size==3 && V && !opc) return STR_imm_fpsimd(ctx, dec); // -> STR_D_ldst_pos
	if(size==3 && V && opc==1) return LDR_imm_fpsimd(ctx, dec); // -> LDR_D_ldst_pos
	if((size&2)==2 && !V && opc==3) UNALLOCATED(ENC_UNALLOCATED_24_LDST_POS);
	if(size&1 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_35_LDST_POS);
	if((size&2)==2 && V && (opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_36_LDST_POS);
	UNMATCHED;
}

int decode_iclass_ldstpair_off(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, V=(INSWORD>>26)&1, L=(INSWORD>>22)&1;
	if(!opc && !V && !L) return STP_gen(ctx, dec); // -> STP_32_ldstpair_off
	if(!opc && !V && L) return LDP_gen(ctx, dec); // -> LDP_32_ldstpair_off
	if(!opc && V && !L) return STP_fpsimd(ctx, dec); // -> STP_S_ldstpair_off
	if(!opc && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_S_ldstpair_off
	if(opc==1 && !V && !L && HasMemTag()) return STGP(ctx, dec); // -> STGP_64_ldstpair_off
	if(opc==1 && !V && L) return LDPSW(ctx, dec); // -> LDPSW_64_ldstpair_off
	if(opc==1 && V && !L) return STP_fpsimd(ctx, dec); // -> STP_D_ldstpair_off
	if(opc==1 && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_D_ldstpair_off
	if(opc==2 && !V && !L) return STP_gen(ctx, dec); // -> STP_64_ldstpair_off
	if(opc==2 && !V && L) return LDP_gen(ctx, dec); // -> LDP_64_ldstpair_off
	if(opc==2 && V && !L) return STP_fpsimd(ctx, dec); // -> STP_Q_ldstpair_off
	if(opc==2 && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_Q_ldstpair_off
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_22_LDSTPAIR_OFF);
	UNMATCHED;
}

int decode_iclass_ldstpair_post(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, V=(INSWORD>>26)&1, L=(INSWORD>>22)&1;
	if(!opc && !V && !L) return STP_gen(ctx, dec); // -> STP_32_ldstpair_post
	if(!opc && !V && L) return LDP_gen(ctx, dec); // -> LDP_32_ldstpair_post
	if(!opc && V && !L) return STP_fpsimd(ctx, dec); // -> STP_S_ldstpair_post
	if(!opc && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_S_ldstpair_post
	if(opc==1 && !V && !L && HasMemTag()) return STGP(ctx, dec); // -> STGP_64_ldstpair_post
	if(opc==1 && !V && L) return LDPSW(ctx, dec); // -> LDPSW_64_ldstpair_post
	if(opc==1 && V && !L) return STP_fpsimd(ctx, dec); // -> STP_D_ldstpair_post
	if(opc==1 && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_D_ldstpair_post
	if(opc==2 && !V && !L) return STP_gen(ctx, dec); // -> STP_64_ldstpair_post
	if(opc==2 && !V && L) return LDP_gen(ctx, dec); // -> LDP_64_ldstpair_post
	if(opc==2 && V && !L) return STP_fpsimd(ctx, dec); // -> STP_Q_ldstpair_post
	if(opc==2 && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_Q_ldstpair_post
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_22_LDSTPAIR_POST);
	UNMATCHED;
}

int decode_iclass_ldstpair_pre(context *ctx, Instruction *dec)
{
	uint32_t opc=INSWORD>>30, V=(INSWORD>>26)&1, L=(INSWORD>>22)&1;
	if(!opc && !V && !L) return STP_gen(ctx, dec); // -> STP_32_ldstpair_pre
	if(!opc && !V && L) return LDP_gen(ctx, dec); // -> LDP_32_ldstpair_pre
	if(!opc && V && !L) return STP_fpsimd(ctx, dec); // -> STP_S_ldstpair_pre
	if(!opc && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_S_ldstpair_pre
	if(opc==1 && !V && !L && HasMemTag()) return STGP(ctx, dec); // -> STGP_64_ldstpair_pre
	if(opc==1 && !V && L) return LDPSW(ctx, dec); // -> LDPSW_64_ldstpair_pre
	if(opc==1 && V && !L) return STP_fpsimd(ctx, dec); // -> STP_D_ldstpair_pre
	if(opc==1 && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_D_ldstpair_pre
	if(opc==2 && !V && !L) return STP_gen(ctx, dec); // -> STP_64_ldstpair_pre
	if(opc==2 && !V && L) return LDP_gen(ctx, dec); // -> LDP_64_ldstpair_pre
	if(opc==2 && V && !L) return STP_fpsimd(ctx, dec); // -> STP_Q_ldstpair_pre
	if(opc==2 && V && L) return LDP_fpsimd(ctx, dec); // -> LDP_Q_ldstpair_pre
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_22_LDSTPAIR_PRE);
	UNMATCHED;
}

int decode_iclass_sve_int_mlas_vvv_pred(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>13)&1;
	if(!op) return mla_z_p_zzz(ctx, dec); // -> mla_z_p_zzz_
	if(op) return mls_z_p_zzz(ctx, dec); // -> mls_z_p_zzz_
	UNMATCHED;
}

int decode_iclass_sve_int_mladdsub_vvv_pred(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>13)&1;
	if(!op) return mad_z_p_zzz(ctx, dec); // -> mad_z_p_zzz_
	if(op) return msb_z_p_zzz(ctx, dec); // -> msb_z_p_zzz_
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_arit_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&7;
	if(!opc) return add_z_zz(ctx, dec); // -> add_z_zz_
	if(opc==1) return sub_z_zz(ctx, dec); // -> sub_z_zz_
	if(opc==4) return sqadd_z_zz(ctx, dec); // -> sqadd_z_zz_
	if(opc==5) return uqadd_z_zz(ctx, dec); // -> uqadd_z_zz_
	if(opc==6) return sqsub_z_zz(ctx, dec); // -> sqsub_z_zz_
	if(opc==7) return uqsub_z_zz(ctx, dec); // -> uqsub_z_zz_
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_148);
	UNMATCHED;
}

int decode_iclass_addsub_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1;
	if(!sf && !op && !S) return ADD_addsub_imm(ctx, dec); // -> ADD_32_addsub_imm
	if(!sf && !op && S) return ADDS_addsub_imm(ctx, dec); // -> ADDS_32S_addsub_imm
	if(!sf && op && !S) return SUB_addsub_imm(ctx, dec); // -> SUB_32_addsub_imm
	if(!sf && op && S) return SUBS_addsub_imm(ctx, dec); // -> SUBS_32S_addsub_imm
	if(sf && !op && !S) return ADD_addsub_imm(ctx, dec); // -> ADD_64_addsub_imm
	if(sf && !op && S) return ADDS_addsub_imm(ctx, dec); // -> ADDS_64S_addsub_imm
	if(sf && op && !S) return SUB_addsub_imm(ctx, dec); // -> SUB_64_addsub_imm
	if(sf && op && S) return SUBS_addsub_imm(ctx, dec); // -> SUBS_64S_addsub_imm
	UNMATCHED;
}

int decode_iclass_addsub_immtags(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, o2=(INSWORD>>22)&1;
	if(sf && !op && !S && !o2 && HasMemTag()) return ADDG(ctx, dec); // -> ADDG_64_addsub_immtags
	if(sf && op && !S && !o2 && HasMemTag()) return SUBG(ctx, dec); // -> SUBG_64_addsub_immtags
	if(sf && S && !o2) UNALLOCATED(ENC_UNALLOCATED_11_ADDSUB_IMMTAGS);
	if(!sf && !o2) UNALLOCATED(ENC_UNALLOCATED_10_ADDSUB_IMMTAGS);
	if(o2) UNALLOCATED(ENC_UNALLOCATED_14_ADDSUB_IMMTAGS);
	UNMATCHED;
}

int decode_iclass_bitfield(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>29)&3, N=(INSWORD>>22)&1;
	if(!sf && !opc && !N) return SBFM(ctx, dec); // -> SBFM_32M_bitfield
	if(!sf && opc==1 && !N) return BFM(ctx, dec); // -> BFM_32M_bitfield
	if(!sf && opc==2 && !N) return UBFM(ctx, dec); // -> UBFM_32M_bitfield
	if(sf && !opc && N) return SBFM(ctx, dec); // -> SBFM_64M_bitfield
	if(sf && opc==1 && N) return BFM(ctx, dec); // -> BFM_64M_bitfield
	if(sf && opc==2 && N) return UBFM(ctx, dec); // -> UBFM_64M_bitfield
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_19_BITFIELD);
	if(!sf && N) UNALLOCATED(ENC_UNALLOCATED_12_BITFIELD);
	if(sf && !N) UNALLOCATED(ENC_UNALLOCATED_11_BITFIELD);
	UNMATCHED;
}

int decode_iclass_extract(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op21=(INSWORD>>29)&3, N=(INSWORD>>22)&1, o0=(INSWORD>>21)&1, imms=(INSWORD>>10)&0x3f;
	if(!sf && !op21 && !N && !o0 && !(imms&0x20)) return EXTR(ctx, dec); // -> EXTR_32_extract
	if(sf && !op21 && N && !o0) return EXTR(ctx, dec); // -> EXTR_64_extract
	if(!op21 && o0) UNALLOCATED(ENC_UNALLOCATED_16_EXTRACT);
	if(!sf && (imms&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_13_EXTRACT);
	if(!sf && N) UNALLOCATED(ENC_UNALLOCATED_12_EXTRACT);
	if(sf && !N) UNALLOCATED(ENC_UNALLOCATED_11_EXTRACT);
	if(op21&1) UNALLOCATED(ENC_UNALLOCATED_17_EXTRACT);
	if((op21&2)==2) UNALLOCATED(ENC_UNALLOCATED_18_EXTRACT);
	UNMATCHED;
}

int decode_iclass_log_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>29)&3, N=(INSWORD>>22)&1;
	if(!sf && !opc && !N) return AND_log_imm(ctx, dec); // -> AND_32_log_imm
	if(!sf && opc==1 && !N) return ORR_log_imm(ctx, dec); // -> ORR_32_log_imm
	if(!sf && opc==2 && !N) return EOR_log_imm(ctx, dec); // -> EOR_32_log_imm
	if(!sf && opc==3 && !N) return ANDS_log_imm(ctx, dec); // -> ANDS_32S_log_imm
	if(sf && !opc) return AND_log_imm(ctx, dec); // -> AND_64_log_imm
	if(sf && opc==1) return ORR_log_imm(ctx, dec); // -> ORR_64_log_imm
	if(sf && opc==2) return EOR_log_imm(ctx, dec); // -> EOR_64_log_imm
	if(sf && opc==3) return ANDS_log_imm(ctx, dec); // -> ANDS_64S_log_imm
	if(!sf && N) UNALLOCATED(ENC_UNALLOCATED_10_LOG_IMM);
	UNMATCHED;
}

int decode_iclass_movewide(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>29)&3, hw=(INSWORD>>21)&3;
	if(!sf && !opc && !(hw&2)) return MOVN(ctx, dec); // -> MOVN_32_movewide
	if(!sf && opc==2 && !(hw&2)) return MOVZ(ctx, dec); // -> MOVZ_32_movewide
	if(!sf && opc==3 && !(hw&2)) return MOVK(ctx, dec); // -> MOVK_32_movewide
	if(sf && !opc) return MOVN(ctx, dec); // -> MOVN_64_movewide
	if(sf && opc==2) return MOVZ(ctx, dec); // -> MOVZ_64_movewide
	if(sf && opc==3) return MOVK(ctx, dec); // -> MOVK_64_movewide
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_13_MOVEWIDE);
	if(!sf && (hw&2)==2) UNALLOCATED(ENC_UNALLOCATED_10_MOVEWIDE);
	UNMATCHED;
}

int decode_iclass_pcreladdr(context *ctx, Instruction *dec)
{
	uint32_t op=INSWORD>>31;
	if(!op) return ADR(ctx, dec); // -> ADR_only_pcreladdr
	if(op) return ADRP(ctx, dec); // -> ADRP_only_pcreladdr
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_log(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc) return and_z_zz(ctx, dec); // -> and_z_zz_
	if(opc==1) return orr_z_zz(ctx, dec); // -> orr_z_zz_
	if(opc==2) return eor_z_zz(ctx, dec); // -> eor_z_zz_
	if(opc==3) return bic_z_zz(ctx, dec); // -> bic_z_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_index_ii(context *ctx, Instruction *dec)
{
	return index_z_ii(ctx, dec);
}

int decode_iclass_sve_int_index_ir(context *ctx, Instruction *dec)
{
	return index_z_ir(ctx, dec);
}

int decode_iclass_sve_int_index_ri(context *ctx, Instruction *dec)
{
	return index_z_ri(ctx, dec);
}

int decode_iclass_sve_int_index_rr(context *ctx, Instruction *dec)
{
	return index_z_rr(ctx, dec);
}

int decode_iclass_sve_int_arith_vl(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1;
	if(!op) return addvl_r_ri(ctx, dec); // -> addvl_r_ri_
	if(op) return addpl_r_ri(ctx, dec); // -> addpl_r_ri_
	UNMATCHED;
}

int decode_iclass_sve_int_read_vl_a(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, opc2=(INSWORD>>16)&0x1f;
	if(!op && opc2==0x1e) UNALLOCATED(ENC_UNALLOCATED_171);
	if(!op && opc2==0x1f) return rdvl_r_i(ctx, dec); // -> rdvl_r_i_
	if(!op && (opc2&0x1e)==0x1c) UNALLOCATED(ENC_UNALLOCATED_170);
	if(!op && (opc2&0x1c)==0x18) UNALLOCATED(ENC_UNALLOCATED_169);
	if(!op && (opc2&0x18)==0x10) UNALLOCATED(ENC_UNALLOCATED_168);
	if(!op && !(opc2&0x10)) UNALLOCATED(ENC_UNALLOCATED_166);
	if(op) UNALLOCATED(ENC_UNALLOCATED_172);
	UNMATCHED;
}

int decode_iclass_addsub_ext(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, opt=(INSWORD>>22)&3, imm3=(INSWORD>>10)&7;
	if(!sf && !op && !S && !opt) return ADD_addsub_ext(ctx, dec); // -> ADD_32_addsub_ext
	if(!sf && !op && S && !opt) return ADDS_addsub_ext(ctx, dec); // -> ADDS_32S_addsub_ext
	if(!sf && op && !S && !opt) return SUB_addsub_ext(ctx, dec); // -> SUB_32_addsub_ext
	if(!sf && op && S && !opt) return SUBS_addsub_ext(ctx, dec); // -> SUBS_32S_addsub_ext
	if(sf && !op && !S && !opt) return ADD_addsub_ext(ctx, dec); // -> ADD_64_addsub_ext
	if(sf && !op && S && !opt) return ADDS_addsub_ext(ctx, dec); // -> ADDS_64S_addsub_ext
	if(sf && op && !S && !opt) return SUB_addsub_ext(ctx, dec); // -> SUB_64_addsub_ext
	if(sf && op && S && !opt) return SUBS_addsub_ext(ctx, dec); // -> SUBS_64S_addsub_ext
	if((imm3&5)==5) UNALLOCATED(ENC_UNALLOCATED_12_ADDSUB_EXT);
	if((imm3&6)==6) UNALLOCATED(ENC_UNALLOCATED_13_ADDSUB_EXT);
	if(opt&1) UNALLOCATED(ENC_UNALLOCATED_11_ADDSUB_EXT);
	if((opt&2)==2) UNALLOCATED(ENC_UNALLOCATED_10_ADDSUB_EXT);
	UNMATCHED;
}

int decode_iclass_addsub_shift(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, shift=(INSWORD>>22)&3, imm6=(INSWORD>>10)&0x3f;
	if(!sf && !op && !S) return ADD_addsub_shift(ctx, dec); // -> ADD_32_addsub_shift
	if(!sf && !op && S) return ADDS_addsub_shift(ctx, dec); // -> ADDS_32_addsub_shift
	if(!sf && op && !S) return SUB_addsub_shift(ctx, dec); // -> SUB_32_addsub_shift
	if(!sf && op && S) return SUBS_addsub_shift(ctx, dec); // -> SUBS_32_addsub_shift
	if(sf && !op && !S) return ADD_addsub_shift(ctx, dec); // -> ADD_64_addsub_shift
	if(sf && !op && S) return ADDS_addsub_shift(ctx, dec); // -> ADDS_64_addsub_shift
	if(sf && op && !S) return SUB_addsub_shift(ctx, dec); // -> SUB_64_addsub_shift
	if(sf && op && S) return SUBS_addsub_shift(ctx, dec); // -> SUBS_64_addsub_shift
	if(shift==3) UNALLOCATED(ENC_UNALLOCATED_10_ADDSUB_SHIFT);
	if(!sf && (imm6&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_11_ADDSUB_SHIFT);
	UNMATCHED;
}

int decode_iclass_addsub_carry(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1;
	if(!sf && !op && !S) return ADC(ctx, dec); // -> ADC_32_addsub_carry
	if(!sf && !op && S) return ADCS(ctx, dec); // -> ADCS_32_addsub_carry
	if(!sf && op && !S) return SBC(ctx, dec); // -> SBC_32_addsub_carry
	if(!sf && op && S) return SBCS(ctx, dec); // -> SBCS_32_addsub_carry
	if(sf && !op && !S) return ADC(ctx, dec); // -> ADC_64_addsub_carry
	if(sf && !op && S) return ADCS(ctx, dec); // -> ADCS_64_addsub_carry
	if(sf && op && !S) return SBC(ctx, dec); // -> SBC_64_addsub_carry
	if(sf && op && S) return SBCS(ctx, dec); // -> SBCS_64_addsub_carry
	UNMATCHED;
}

int decode_iclass_condcmp_imm(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, o2=(INSWORD>>10)&1, o3=(INSWORD>>4)&1;
	if(!sf && !op && S && !o2 && !o3) return CCMN_imm(ctx, dec); // -> CCMN_32_condcmp_imm
	if(!sf && op && S && !o2 && !o3) return CCMP_imm(ctx, dec); // -> CCMP_32_condcmp_imm
	if(sf && !op && S && !o2 && !o3) return CCMN_imm(ctx, dec); // -> CCMN_64_condcmp_imm
	if(sf && op && S && !o2 && !o3) return CCMP_imm(ctx, dec); // -> CCMP_64_condcmp_imm
	if(o3) UNALLOCATED(ENC_UNALLOCATED_11_CONDCMP_IMM);
	if(o2) UNALLOCATED(ENC_UNALLOCATED_10_CONDCMP_IMM);
	if(!S) UNALLOCATED(ENC_UNALLOCATED_12_CONDCMP_IMM);
	UNMATCHED;
}

int decode_iclass_condcmp_reg(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, o2=(INSWORD>>10)&1, o3=(INSWORD>>4)&1;
	if(!sf && !op && S && !o2 && !o3) return CCMN_reg(ctx, dec); // -> CCMN_32_condcmp_reg
	if(!sf && op && S && !o2 && !o3) return CCMP_reg(ctx, dec); // -> CCMP_32_condcmp_reg
	if(sf && !op && S && !o2 && !o3) return CCMN_reg(ctx, dec); // -> CCMN_64_condcmp_reg
	if(sf && op && S && !o2 && !o3) return CCMP_reg(ctx, dec); // -> CCMP_64_condcmp_reg
	if(o3) UNALLOCATED(ENC_UNALLOCATED_11_CONDCMP_REG);
	if(o2) UNALLOCATED(ENC_UNALLOCATED_10_CONDCMP_REG);
	if(!S) UNALLOCATED(ENC_UNALLOCATED_12_CONDCMP_REG);
	UNMATCHED;
}

int decode_iclass_condsel(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, op2=(INSWORD>>10)&3;
	if(!sf && !op && !S && !op2) return CSEL(ctx, dec); // -> CSEL_32_condsel
	if(!sf && !op && !S && op2==1) return CSINC(ctx, dec); // -> CSINC_32_condsel
	if(!sf && op && !S && !op2) return CSINV(ctx, dec); // -> CSINV_32_condsel
	if(!sf && op && !S && op2==1) return CSNEG(ctx, dec); // -> CSNEG_32_condsel
	if(sf && !op && !S && !op2) return CSEL(ctx, dec); // -> CSEL_64_condsel
	if(sf && !op && !S && op2==1) return CSINC(ctx, dec); // -> CSINC_64_condsel
	if(sf && op && !S && !op2) return CSINV(ctx, dec); // -> CSINV_64_condsel
	if(sf && op && !S && op2==1) return CSNEG(ctx, dec); // -> CSNEG_64_condsel
	if((op2&2)==2) UNALLOCATED(ENC_UNALLOCATED_10_CONDSEL);
	if(S) UNALLOCATED(ENC_UNALLOCATED_11_CONDSEL);
	UNMATCHED;
}

int decode_iclass_dp_1src(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, S=(INSWORD>>29)&1, opcode2=(INSWORD>>16)&0x1f, opcode=(INSWORD>>10)&0x3f, Rn=(INSWORD>>5)&0x1f;
	if(sf && !S && opcode2==1 && opcode==8 && Rn==0x1f && HasPAuth()) return PACIA(ctx, dec); // -> PACIZA_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==9 && Rn==0x1f && HasPAuth()) return PACIB(ctx, dec); // -> PACIZB_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==10 && Rn==0x1f && HasPAuth()) return PACDA(ctx, dec); // -> PACDZA_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==11 && Rn==0x1f && HasPAuth()) return PACDB(ctx, dec); // -> PACDZB_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==12 && Rn==0x1f && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIZA_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==13 && Rn==0x1f && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIZB_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==14 && Rn==0x1f && HasPAuth()) return AUTDA(ctx, dec); // -> AUTDZA_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==15 && Rn==0x1f && HasPAuth()) return AUTDB(ctx, dec); // -> AUTDZB_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x10 && Rn==0x1f && HasPAuth()) return XPAC(ctx, dec); // -> XPACI_64Z_dp_1src
	if(sf && !S && opcode2==1 && opcode==0x11 && Rn==0x1f && HasPAuth()) return XPAC(ctx, dec); // -> XPACD_64Z_dp_1src
	if(!sf && !S && !opcode2 && !opcode) return RBIT_int(ctx, dec); // -> RBIT_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==1) return REV16_int(ctx, dec); // -> REV16_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==2) return REV(ctx, dec); // -> REV_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==3) UNALLOCATED(ENC_UNALLOCATED_28_DP_1SRC);
	if(!sf && !S && !opcode2 && opcode==4) return CLZ_int(ctx, dec); // -> CLZ_32_dp_1src
	if(!sf && !S && !opcode2 && opcode==5) return CLS_int(ctx, dec); // -> CLS_32_dp_1src
	if(sf && !S && !opcode2 && !opcode) return RBIT_int(ctx, dec); // -> RBIT_64_dp_1src
	if(sf && !S && !opcode2 && opcode==1) return REV16_int(ctx, dec); // -> REV16_64_dp_1src
	if(sf && !S && !opcode2 && opcode==2) return REV32_int(ctx, dec); // -> REV32_64_dp_1src
	if(sf && !S && !opcode2 && opcode==3) return REV(ctx, dec); // -> REV_64_dp_1src
	if(sf && !S && !opcode2 && opcode==4) return CLZ_int(ctx, dec); // -> CLZ_64_dp_1src
	if(sf && !S && !opcode2 && opcode==5) return CLS_int(ctx, dec); // -> CLS_64_dp_1src
	if(sf && !S && opcode2==1 && !opcode && HasPAuth()) return PACIA(ctx, dec); // -> PACIA_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==1 && HasPAuth()) return PACIB(ctx, dec); // -> PACIB_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==2 && HasPAuth()) return PACDA(ctx, dec); // -> PACDA_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==3 && HasPAuth()) return PACDB(ctx, dec); // -> PACDB_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==4 && HasPAuth()) return AUTIA(ctx, dec); // -> AUTIA_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==5 && HasPAuth()) return AUTIB(ctx, dec); // -> AUTIB_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==6 && HasPAuth()) return AUTDA(ctx, dec); // -> AUTDA_64P_dp_1src
	if(sf && !S && opcode2==1 && opcode==7 && HasPAuth()) return AUTDB(ctx, dec); // -> AUTDB_64P_dp_1src
	if(sf && !S && opcode2==1 && (opcode&0x3e)==0x12) UNALLOCATED(ENC_UNALLOCATED_15_DP_1SRC);
	if(!S && !opcode2 && (opcode&0x3e)==6) UNALLOCATED(ENC_UNALLOCATED_34_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x3c)==0x14) UNALLOCATED(ENC_UNALLOCATED_16_DP_1SRC);
	if(sf && !S && opcode2==1 && (opcode&0x38)==0x18) UNALLOCATED(ENC_UNALLOCATED_17_DP_1SRC);
	if(!S && !opcode2 && (opcode&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_11_DP_1SRC);
	if(!S && !opcode2 && (opcode&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_12_DP_1SRC);
	if(!sf && opcode2==1) UNALLOCATED(ENC_UNALLOCATED_14_DP_1SRC);
	if((opcode&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_13_DP_1SRC);
	if((opcode2&2)==2) UNALLOCATED(ENC_UNALLOCATED_18_DP_1SRC);
	if((opcode2&4)==4) UNALLOCATED(ENC_UNALLOCATED_19_DP_1SRC);
	if((opcode2&8)==8) UNALLOCATED(ENC_UNALLOCATED_20_DP_1SRC);
	if((opcode2&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_21_DP_1SRC);
	if(S) UNALLOCATED(ENC_UNALLOCATED_10_DP_1SRC);
	UNMATCHED;
}

int decode_iclass_dp_2src(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, S=(INSWORD>>29)&1, opcode=(INSWORD>>10)&0x3f;
	if(!sf && !S && opcode==2) return UDIV(ctx, dec); // -> UDIV_32_dp_2src
	if(!sf && !S && opcode==3) return SDIV(ctx, dec); // -> SDIV_32_dp_2src
	if(!sf && !S && opcode==8) return LSLV(ctx, dec); // -> LSLV_32_dp_2src
	if(!sf && !S && opcode==9) return LSRV(ctx, dec); // -> LSRV_32_dp_2src
	if(!sf && !S && opcode==10) return ASRV(ctx, dec); // -> ASRV_32_dp_2src
	if(!sf && !S && opcode==11) return RORV(ctx, dec); // -> RORV_32_dp_2src
	if(!sf && !S && opcode==12) UNALLOCATED(ENC_UNALLOCATED_36_DP_2SRC);
	if(!sf && !S && opcode==0x10) return CRC32(ctx, dec); // -> CRC32B_32C_dp_2src
	if(!sf && !S && opcode==0x11) return CRC32(ctx, dec); // -> CRC32H_32C_dp_2src
	if(!sf && !S && opcode==0x12) return CRC32(ctx, dec); // -> CRC32W_32C_dp_2src
	if(!sf && !S && opcode==0x14) return CRC32C(ctx, dec); // -> CRC32CB_32C_dp_2src
	if(!sf && !S && opcode==0x15) return CRC32C(ctx, dec); // -> CRC32CH_32C_dp_2src
	if(!sf && !S && opcode==0x16) return CRC32C(ctx, dec); // -> CRC32CW_32C_dp_2src
	if(sf && !S && !opcode && HasMemTag()) return SUBP(ctx, dec); // -> SUBP_64S_dp_2src
	if(sf && !S && opcode==2) return UDIV(ctx, dec); // -> UDIV_64_dp_2src
	if(sf && !S && opcode==3) return SDIV(ctx, dec); // -> SDIV_64_dp_2src
	if(sf && !S && opcode==4 && HasMemTag()) return IRG(ctx, dec); // -> IRG_64I_dp_2src
	if(sf && !S && opcode==5 && HasMemTag()) return GMI(ctx, dec); // -> GMI_64G_dp_2src
	if(sf && !S && opcode==8) return LSLV(ctx, dec); // -> LSLV_64_dp_2src
	if(sf && !S && opcode==9) return LSRV(ctx, dec); // -> LSRV_64_dp_2src
	if(sf && !S && opcode==10) return ASRV(ctx, dec); // -> ASRV_64_dp_2src
	if(sf && !S && opcode==11) return RORV(ctx, dec); // -> RORV_64_dp_2src
	if(sf && !S && opcode==12 && HasPAuth()) return PACGA(ctx, dec); // -> PACGA_64P_dp_2src
	if(sf && !S && opcode==0x13) return CRC32(ctx, dec); // -> CRC32X_64C_dp_2src
	if(sf && !S && opcode==0x17) return CRC32C(ctx, dec); // -> CRC32CX_64C_dp_2src
	if(sf && S && !opcode && HasMemTag()) return SUBPS(ctx, dec); // -> SUBPS_64S_dp_2src
	if(!S && opcode==13) UNALLOCATED(ENC_UNALLOCATED_34_DP_2SRC);
	if(!sf && !opcode) UNALLOCATED(ENC_UNALLOCATED_11_DP_2SRC);
	if(!sf && !S && (opcode&0x3e)==4) UNALLOCATED(ENC_UNALLOCATED_21_DP_2SRC);
	if(!sf && !S && (opcode&0x3b)==0x13) UNALLOCATED(ENC_UNALLOCATED_47_DP_2SRC);
	if(opcode==1) UNALLOCATED(ENC_UNALLOCATED_14_DP_2SRC);
	if(!S && (opcode&0x3e)==6) UNALLOCATED(ENC_UNALLOCATED_24_DP_2SRC);
	if(!S && (opcode&0x3e)==14) UNALLOCATED(ENC_UNALLOCATED_35_DP_2SRC);
	if(S && (opcode&0x3e)==2) UNALLOCATED(ENC_UNALLOCATED_15_DP_2SRC);
	if(sf && !S && (opcode&0x39)==0x10) UNALLOCATED(ENC_UNALLOCATED_49_DP_2SRC);
	if(sf && !S && (opcode&0x3a)==0x10) UNALLOCATED(ENC_UNALLOCATED_48_DP_2SRC);
	if(S && (opcode&0x3c)==4) UNALLOCATED(ENC_UNALLOCATED_20_DP_2SRC);
	if(S && (opcode&0x38)==8) UNALLOCATED(ENC_UNALLOCATED_25_DP_2SRC);
	if((opcode&0x38)==0x18) UNALLOCATED(ENC_UNALLOCATED_50_DP_2SRC);
	if(S && (opcode&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_38_DP_2SRC);
	if((opcode&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_51_DP_2SRC);
	UNMATCHED;
}

int decode_iclass_dp_3src(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op54=(INSWORD>>29)&3, op31=(INSWORD>>21)&7, o0=(INSWORD>>15)&1;
	if(!sf && !op54 && !op31 && !o0) return MADD(ctx, dec); // -> MADD_32A_dp_3src
	if(!sf && !op54 && !op31 && o0) return MSUB(ctx, dec); // -> MSUB_32A_dp_3src
	if(!sf && !op54 && op31==1 && !o0) UNALLOCATED(ENC_UNALLOCATED_14_DP_3SRC);
	if(!sf && !op54 && op31==1 && o0) UNALLOCATED(ENC_UNALLOCATED_16_DP_3SRC);
	if(!sf && !op54 && op31==2 && !o0) UNALLOCATED(ENC_UNALLOCATED_18_DP_3SRC);
	if(!sf && !op54 && op31==5 && !o0) UNALLOCATED(ENC_UNALLOCATED_23_DP_3SRC);
	if(!sf && !op54 && op31==5 && o0) UNALLOCATED(ENC_UNALLOCATED_25_DP_3SRC);
	if(!sf && !op54 && op31==6 && !o0) UNALLOCATED(ENC_UNALLOCATED_27_DP_3SRC);
	if(sf && !op54 && !op31 && !o0) return MADD(ctx, dec); // -> MADD_64A_dp_3src
	if(sf && !op54 && !op31 && o0) return MSUB(ctx, dec); // -> MSUB_64A_dp_3src
	if(sf && !op54 && op31==1 && !o0) return SMADDL(ctx, dec); // -> SMADDL_64WA_dp_3src
	if(sf && !op54 && op31==1 && o0) return SMSUBL(ctx, dec); // -> SMSUBL_64WA_dp_3src
	if(sf && !op54 && op31==2 && !o0) return SMULH(ctx, dec); // -> SMULH_64_dp_3src
	if(sf && !op54 && op31==5 && !o0) return UMADDL(ctx, dec); // -> UMADDL_64WA_dp_3src
	if(sf && !op54 && op31==5 && o0) return UMSUBL(ctx, dec); // -> UMSUBL_64WA_dp_3src
	if(sf && !op54 && op31==6 && !o0) return UMULH(ctx, dec); // -> UMULH_64_dp_3src
	if(!op54 && op31==2 && o0) UNALLOCATED(ENC_UNALLOCATED_20_DP_3SRC);
	if(!op54 && op31==6 && o0) UNALLOCATED(ENC_UNALLOCATED_29_DP_3SRC);
	if(!op54 && op31==3) UNALLOCATED(ENC_UNALLOCATED_21_DP_3SRC);
	if(!op54 && op31==4) UNALLOCATED(ENC_UNALLOCATED_22_DP_3SRC);
	if(!op54 && op31==7) UNALLOCATED(ENC_UNALLOCATED_30_DP_3SRC);
	if(op54==1) UNALLOCATED(ENC_UNALLOCATED_31_DP_3SRC);
	if((op54&2)==2) UNALLOCATED(ENC_UNALLOCATED_32_DP_3SRC);
	UNMATCHED;
}

int decode_iclass_setf(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, opcode2=(INSWORD>>15)&0x3f, sz=(INSWORD>>14)&1, o3=(INSWORD>>4)&1, mask=INSWORD&15;
	if(!sf && !op && S && !opcode2 && !sz && !o3 && mask==13 && HasCondM()) return SETF(ctx, dec); // -> SETF8_only_setf
	if(!sf && !op && S && !opcode2 && sz && !o3 && mask==13 && HasCondM()) return SETF(ctx, dec); // -> SETF16_only_setf
	if(!sf && !op && S && !opcode2 && !o3 && mask!=13) UNALLOCATED(ENC_UNALLOCATED_11_SETF);
	if(!sf && !op && S && !opcode2 && o3) UNALLOCATED(ENC_UNALLOCATED_14_SETF);
	if(!sf && !op && S && opcode2) UNALLOCATED(ENC_UNALLOCATED_15_SETF);
	if(!sf && !op && !S) UNALLOCATED(ENC_UNALLOCATED_10_SETF);
	if(!sf && op) UNALLOCATED(ENC_UNALLOCATED_16_SETF);
	if(sf) UNALLOCATED(ENC_UNALLOCATED_17_SETF);
	UNMATCHED;
}

int decode_iclass_log_shift(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, opc=(INSWORD>>29)&3, N=(INSWORD>>21)&1, imm6=(INSWORD>>10)&0x3f;
	if(!sf && !opc && !N) return AND_log_shift(ctx, dec); // -> AND_32_log_shift
	if(!sf && !opc && N) return BIC_log_shift(ctx, dec); // -> BIC_32_log_shift
	if(!sf && opc==1 && !N) return ORR_log_shift(ctx, dec); // -> ORR_32_log_shift
	if(!sf && opc==1 && N) return ORN_log_shift(ctx, dec); // -> ORN_32_log_shift
	if(!sf && opc==2 && !N) return EOR_log_shift(ctx, dec); // -> EOR_32_log_shift
	if(!sf && opc==2 && N) return EON(ctx, dec); // -> EON_32_log_shift
	if(!sf && opc==3 && !N) return ANDS_log_shift(ctx, dec); // -> ANDS_32_log_shift
	if(!sf && opc==3 && N) return BICS(ctx, dec); // -> BICS_32_log_shift
	if(sf && !opc && !N) return AND_log_shift(ctx, dec); // -> AND_64_log_shift
	if(sf && !opc && N) return BIC_log_shift(ctx, dec); // -> BIC_64_log_shift
	if(sf && opc==1 && !N) return ORR_log_shift(ctx, dec); // -> ORR_64_log_shift
	if(sf && opc==1 && N) return ORN_log_shift(ctx, dec); // -> ORN_64_log_shift
	if(sf && opc==2 && !N) return EOR_log_shift(ctx, dec); // -> EOR_64_log_shift
	if(sf && opc==2 && N) return EON(ctx, dec); // -> EON_64_log_shift
	if(sf && opc==3 && !N) return ANDS_log_shift(ctx, dec); // -> ANDS_64_log_shift
	if(sf && opc==3 && N) return BICS(ctx, dec); // -> BICS_64_log_shift
	if(!sf && (imm6&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_10_LOG_SHIFT);
	UNMATCHED;
}

int decode_iclass_rmif(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, op=(INSWORD>>30)&1, S=(INSWORD>>29)&1, o2=(INSWORD>>4)&1;
	if(sf && !op && S && !o2 && HasCondM()) return RMIF(ctx, dec); // -> RMIF_only_rmif
	if(sf && !op && S && o2) UNALLOCATED(ENC_UNALLOCATED_13_RMIF);
	if(sf && !op && !S) UNALLOCATED(ENC_UNALLOCATED_11_RMIF);
	if(sf && op) UNALLOCATED(ENC_UNALLOCATED_14_RMIF);
	if(!sf) UNALLOCATED(ENC_UNALLOCATED_10_RMIF);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_shift_b(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc) return asr_z_zi(ctx, dec); // -> asr_z_zi_
	if(opc==1) return lsr_z_zi(ctx, dec); // -> lsr_z_zi_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_150);
	if(opc==3) return lsl_z_zi(ctx, dec); // -> lsl_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_shift_a(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&3;
	if(!opc) return asr_z_zw(ctx, dec); // -> asr_z_zw_
	if(opc==1) return lsr_z_zw(ctx, dec); // -> lsr_z_zw_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_149);
	if(opc==3) return lsl_z_zw(ctx, dec); // -> lsl_z_zw_
	UNMATCHED;
}

int decode_iclass_asimdall(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!U && !size && opcode==12 && HasFP16()) return FMAXNMV_advsimd(ctx, dec); // -> FMAXNMV_asimdall_only_H
	if(!U && !size && opcode==15 && HasFP16()) return FMAXV_advsimd(ctx, dec); // -> FMAXV_asimdall_only_H
	if(!U && size==1 && opcode==12) UNALLOCATED(ENC_UNALLOCATED_21_ASIMDALL);
	if(!U && size==1 && opcode==15) UNALLOCATED(ENC_UNALLOCATED_29_ASIMDALL);
	if(!U && size==2 && opcode==12 && HasFP16()) return FMINNMV_advsimd(ctx, dec); // -> FMINNMV_asimdall_only_H
	if(!U && size==2 && opcode==15 && HasFP16()) return FMINV_advsimd(ctx, dec); // -> FMINV_asimdall_only_H
	if(!U && size==3 && opcode==12) UNALLOCATED(ENC_UNALLOCATED_24_ASIMDALL);
	if(!U && size==3 && opcode==15) UNALLOCATED(ENC_UNALLOCATED_32_ASIMDALL);
	if(U && !(size&2) && opcode==12) return FMAXNMV_advsimd(ctx, dec); // -> FMAXNMV_asimdall_only_SD
	if(U && !(size&2) && opcode==15) return FMAXV_advsimd(ctx, dec); // -> FMAXV_asimdall_only_SD
	if(U && (size&2)==2 && opcode==12) return FMINNMV_advsimd(ctx, dec); // -> FMINNMV_asimdall_only_SD
	if(U && (size&2)==2 && opcode==15) return FMINV_advsimd(ctx, dec); // -> FMINV_asimdall_only_SD
	if(!U && opcode==3) return SADDLV_advsimd(ctx, dec); // -> SADDLV_asimdall_only
	if(!U && opcode==10) return SMAXV_advsimd(ctx, dec); // -> SMAXV_asimdall_only
	if(!U && opcode==0x1a) return SMINV_advsimd(ctx, dec); // -> SMINV_asimdall_only
	if(!U && opcode==0x1b) return ADDV_advsimd(ctx, dec); // -> ADDV_asimdall_only
	if(U && opcode==3) return UADDLV_advsimd(ctx, dec); // -> UADDLV_asimdall_only
	if(U && opcode==10) return UMAXV_advsimd(ctx, dec); // -> UMAXV_asimdall_only
	if(U && opcode==0x1a) return UMINV_advsimd(ctx, dec); // -> UMINV_asimdall_only
	if(U && opcode==0x1b) UNALLOCATED(ENC_UNALLOCATED_39_ASIMDALL);
	if(opcode==2) UNALLOCATED(ENC_UNALLOCATED_12_ASIMDALL);
	if(opcode==11) UNALLOCATED(ENC_UNALLOCATED_19_ASIMDALL);
	if(opcode==13) UNALLOCATED(ENC_UNALLOCATED_26_ASIMDALL);
	if(opcode==14) UNALLOCATED(ENC_UNALLOCATED_27_ASIMDALL);
	if(!(opcode&0x1e)) UNALLOCATED(ENC_UNALLOCATED_11_ASIMDALL);
	if((opcode&0x1e)==8) UNALLOCATED(ENC_UNALLOCATED_16_ASIMDALL);
	if((opcode&0x1e)==0x18) UNALLOCATED(ENC_UNALLOCATED_35_ASIMDALL);
	if((opcode&0x1c)==4) UNALLOCATED(ENC_UNALLOCATED_15_ASIMDALL);
	if((opcode&0x1c)==0x1c) UNALLOCATED(ENC_UNALLOCATED_40_ASIMDALL);
	if((opcode&0x18)==0x10) UNALLOCATED(ENC_UNALLOCATED_34_ASIMDALL);
	UNMATCHED;
}

int decode_iclass_asimdins(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, op=(INSWORD>>29)&1, imm5=(INSWORD>>16)&0x1f, imm4=(INSWORD>>11)&15;
	if(Q && !op && (imm5&15)==8 && imm4==7) return UMOV_advsimd(ctx, dec); // -> UMOV_asimdins_X_x
	if(!Q && !op && imm4==3) UNALLOCATED(ENC_UNALLOCATED_17_ASIMDINS);
	if(!Q && !op && imm4==5) return SMOV_advsimd(ctx, dec); // -> SMOV_asimdins_W_w
	if(!Q && !op && imm4==7) return UMOV_advsimd(ctx, dec); // -> UMOV_asimdins_W_w
	if(Q && !op && imm4==3) return INS_advsimd_gen(ctx, dec); // -> INS_asimdins_IR_r
	if(Q && !op && imm4==5) return SMOV_advsimd(ctx, dec); // -> SMOV_asimdins_X_x
	if(!op && !imm4) return DUP_advsimd_elt(ctx, dec); // -> DUP_asimdins_DV_v
	if(!op && imm4==1) return DUP_advsimd_gen(ctx, dec); // -> DUP_asimdins_DR_r
	if(!op && imm4==2) UNALLOCATED(ENC_UNALLOCATED_15_ASIMDINS);
	if(!op && imm4==4) UNALLOCATED(ENC_UNALLOCATED_18_ASIMDINS);
	if(!op && imm4==6) UNALLOCATED(ENC_UNALLOCATED_21_ASIMDINS);
	if(!(imm5&15)) UNALLOCATED(ENC_UNALLOCATED_11_ASIMDINS);
	if(!op && (imm4&8)==8) UNALLOCATED(ENC_UNALLOCATED_24_ASIMDINS);
	if(!Q && op) UNALLOCATED(ENC_UNALLOCATED_12_ASIMDINS);
	if(Q && op) return INS_advsimd_elt(ctx, dec); // -> INS_asimdins_IV_v
	UNMATCHED;
}

int decode_iclass_asimdext(context *ctx, Instruction *dec)
{
	uint32_t op2=(INSWORD>>22)&3;
	if(!op2) return EXT_advsimd(ctx, dec); // -> EXT_asimdext_only
	if(op2&1) UNALLOCATED(ENC_UNALLOCATED_11_ASIMDEXT);
	if((op2&2)==2) UNALLOCATED(ENC_UNALLOCATED_12_ASIMDEXT);
	UNMATCHED;
}

int decode_iclass_asimdimm(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, op=(INSWORD>>29)&1, cmode=(INSWORD>>12)&15, o2=(INSWORD>>11)&1;
	if(!Q && op && cmode==14 && !o2) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_D_ds
	if(!Q && op && cmode==15 && !o2) UNALLOCATED(ENC_UNALLOCATED_26_ASIMDIMM);
	if(Q && op && cmode==14 && !o2) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_D2_d
	if(Q && op && cmode==15 && !o2) return FMOV_advsimd(ctx, dec); // -> FMOV_asimdimm_D2_d
	if(!op && cmode==14 && !o2) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_N_b
	if(!op && cmode==14 && o2) UNALLOCATED(ENC_UNALLOCATED_31_ASIMDIMM);
	if(!op && cmode==15 && !o2) return FMOV_advsimd(ctx, dec); // -> FMOV_asimdimm_S_s
	if(!op && cmode==15 && o2 && HasFP16()) return FMOV_advsimd(ctx, dec); // -> FMOV_asimdimm_H_h
	if(!op && (cmode&13)==8 && !o2) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_L_hl
	if(!op && (cmode&13)==9 && !o2) return ORR_advsimd_imm(ctx, dec); // -> ORR_asimdimm_L_hl
	if(!op && (cmode&14)==12 && !o2) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_M_sm
	if(!op && (cmode&14)==12 && o2) UNALLOCATED(ENC_UNALLOCATED_30_ASIMDIMM);
	if(op && (cmode&13)==8 && !o2) return MVNI_advsimd(ctx, dec); // -> MVNI_asimdimm_L_hl
	if(op && (cmode&13)==9 && !o2) return BIC_advsimd_imm(ctx, dec); // -> BIC_asimdimm_L_hl
	if(op && (cmode&14)==12 && !o2) return MVNI_advsimd(ctx, dec); // -> MVNI_asimdimm_M_sm
	if(!op && !(cmode&9) && !o2) return MOVI_advsimd(ctx, dec); // -> MOVI_asimdimm_L_sl
	if(!op && (cmode&9)==1 && !o2) return ORR_advsimd_imm(ctx, dec); // -> ORR_asimdimm_L_sl
	if(!op && (cmode&12)==8 && o2) UNALLOCATED(ENC_UNALLOCATED_29_ASIMDIMM);
	if(op && !(cmode&9) && !o2) return MVNI_advsimd(ctx, dec); // -> MVNI_asimdimm_L_sl
	if(op && (cmode&9)==1 && !o2) return BIC_advsimd_imm(ctx, dec); // -> BIC_asimdimm_L_sl
	if(!op && !(cmode&8) && o2) UNALLOCATED(ENC_UNALLOCATED_28_ASIMDIMM);
	if(op && o2) UNALLOCATED(ENC_UNALLOCATED_27_ASIMDIMM);
	UNMATCHED;
}

int decode_iclass_asimdperm(context *ctx, Instruction *dec)
{
	uint32_t opcode=(INSWORD>>12)&7;
	if(!opcode) UNALLOCATED(ENC_UNALLOCATED_11_ASIMDPERM);
	if(opcode==1) return UZP1_advsimd(ctx, dec); // -> UZP1_asimdperm_only
	if(opcode==2) return TRN1_advsimd(ctx, dec); // -> TRN1_asimdperm_only
	if(opcode==3) return ZIP1_advsimd(ctx, dec); // -> ZIP1_asimdperm_only
	if(opcode==4) UNALLOCATED(ENC_UNALLOCATED_15_ASIMDPERM);
	if(opcode==5) return UZP2_advsimd(ctx, dec); // -> UZP2_asimdperm_only
	if(opcode==6) return TRN2_advsimd(ctx, dec); // -> TRN2_asimdperm_only
	if(opcode==7) return ZIP2_advsimd(ctx, dec); // -> ZIP2_asimdperm_only
	UNMATCHED;
}

int decode_iclass_asisdone(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>29)&1, imm5=(INSWORD>>16)&0x1f, imm4=(INSWORD>>11)&15;
	if(!op && !(imm5&15) && !imm4) UNALLOCATED(ENC_UNALLOCATED_16_ASISDONE);
	if(!op && !imm4) return DUP_advsimd_elt(ctx, dec); // -> DUP_asisdone_only
	if(!op && imm4&1) UNALLOCATED(ENC_UNALLOCATED_15_ASISDONE);
	if(!op && (imm4&2)==2) UNALLOCATED(ENC_UNALLOCATED_14_ASISDONE);
	if(!op && (imm4&4)==4) UNALLOCATED(ENC_UNALLOCATED_13_ASISDONE);
	if(!op && (imm4&8)==8) UNALLOCATED(ENC_UNALLOCATED_12_ASISDONE);
	if(op) UNALLOCATED(ENC_UNALLOCATED_18_ASISDONE);
	UNMATCHED;
}

int decode_iclass_asisdpair(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!U && !size && opcode==12 && HasFP16()) return FMAXNMP_advsimd_pair(ctx, dec); // -> FMAXNMP_asisdpair_only_H
	if(!U && !size && opcode==13 && HasFP16()) return FADDP_advsimd_pair(ctx, dec); // -> FADDP_asisdpair_only_H
	if(!U && !size && opcode==15 && HasFP16()) return FMAXP_advsimd_pair(ctx, dec); // -> FMAXP_asisdpair_only_H
	if(!U && size==1 && opcode==12) UNALLOCATED(ENC_UNALLOCATED_14_ASISDPAIR);
	if(!U && size==1 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_20_ASISDPAIR);
	if(!U && size==1 && opcode==15) UNALLOCATED(ENC_UNALLOCATED_25_ASISDPAIR);
	if(!U && size==2 && opcode==12 && HasFP16()) return FMINNMP_advsimd_pair(ctx, dec); // -> FMINNMP_asisdpair_only_H
	if(!U && size==2 && opcode==15 && HasFP16()) return FMINP_advsimd_pair(ctx, dec); // -> FMINP_asisdpair_only_H
	if(!U && size==3 && opcode==12) UNALLOCATED(ENC_UNALLOCATED_17_ASISDPAIR);
	if(!U && size==3 && opcode==15) UNALLOCATED(ENC_UNALLOCATED_28_ASISDPAIR);
	if(U && !(size&2) && opcode==12) return FMAXNMP_advsimd_pair(ctx, dec); // -> FMAXNMP_asisdpair_only_SD
	if(U && !(size&2) && opcode==13) return FADDP_advsimd_pair(ctx, dec); // -> FADDP_asisdpair_only_SD
	if(U && !(size&2) && opcode==15) return FMAXP_advsimd_pair(ctx, dec); // -> FMAXP_asisdpair_only_SD
	if(U && (size&2)==2 && opcode==12) return FMINNMP_advsimd_pair(ctx, dec); // -> FMINNMP_asisdpair_only_SD
	if(U && (size&2)==2 && opcode==15) return FMINP_advsimd_pair(ctx, dec); // -> FMINP_asisdpair_only_SD
	if((size&2)==2 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_22_ASISDPAIR);
	if(!U && opcode==0x1b) return ADDP_advsimd_pair(ctx, dec); // -> ADDP_asisdpair_only
	if(U && opcode==0x1b) UNALLOCATED(ENC_UNALLOCATED_34_ASISDPAIR);
	if(opcode==14) UNALLOCATED(ENC_UNALLOCATED_23_ASISDPAIR);
	if(opcode==0x1a) UNALLOCATED(ENC_UNALLOCATED_32_ASISDPAIR);
	if((opcode&0x1e)==0x18) UNALLOCATED(ENC_UNALLOCATED_31_ASISDPAIR);
	if((opcode&0x1c)==8) UNALLOCATED(ENC_UNALLOCATED_12_ASISDPAIR);
	if((opcode&0x1c)==0x1c) UNALLOCATED(ENC_UNALLOCATED_35_ASISDPAIR);
	if(!(opcode&0x18)) UNALLOCATED(ENC_UNALLOCATED_11_ASISDPAIR);
	if((opcode&0x18)==0x10) UNALLOCATED(ENC_UNALLOCATED_30_ASISDPAIR);
	UNMATCHED;
}

int decode_iclass_asisdshf(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, immh=(INSWORD>>19)&15, opcode=(INSWORD>>11)&0x1f;
	if(!U && immh && !opcode) return SSHR_advsimd(ctx, dec); // -> SSHR_asisdshf_R
	if(!U && immh && opcode==2) return SSRA_advsimd(ctx, dec); // -> SSRA_asisdshf_R
	if(!U && immh && opcode==4) return SRSHR_advsimd(ctx, dec); // -> SRSHR_asisdshf_R
	if(!U && immh && opcode==6) return SRSRA_advsimd(ctx, dec); // -> SRSRA_asisdshf_R
	if(!U && immh && opcode==8) UNALLOCATED(ENC_UNALLOCATED_24_ASISDSHF);
	if(!U && immh && opcode==10) return SHL_advsimd(ctx, dec); // -> SHL_asisdshf_R
	if(!U && immh && opcode==12) UNALLOCATED(ENC_UNALLOCATED_30_ASISDSHF);
	if(!U && immh && opcode==14) return SQSHL_advsimd_imm(ctx, dec); // -> SQSHL_asisdshf_R
	if(!U && immh && opcode==0x10) UNALLOCATED(ENC_UNALLOCATED_36_ASISDSHF);
	if(!U && immh && opcode==0x11) UNALLOCATED(ENC_UNALLOCATED_38_ASISDSHF);
	if(!U && immh && opcode==0x12) return SQSHRN_advsimd(ctx, dec); // -> SQSHRN_asisdshf_N
	if(!U && immh && opcode==0x13) return SQRSHRN_advsimd(ctx, dec); // -> SQRSHRN_asisdshf_N
	if(!U && immh && opcode==0x1c) return SCVTF_advsimd_fix(ctx, dec); // -> SCVTF_asisdshf_C
	if(!U && immh && opcode==0x1f) return FCVTZS_advsimd_fix(ctx, dec); // -> FCVTZS_asisdshf_C
	if(U && immh && !opcode) return USHR_advsimd(ctx, dec); // -> USHR_asisdshf_R
	if(U && immh && opcode==2) return USRA_advsimd(ctx, dec); // -> USRA_asisdshf_R
	if(U && immh && opcode==4) return URSHR_advsimd(ctx, dec); // -> URSHR_asisdshf_R
	if(U && immh && opcode==6) return URSRA_advsimd(ctx, dec); // -> URSRA_asisdshf_R
	if(U && immh && opcode==8) return SRI_advsimd(ctx, dec); // -> SRI_asisdshf_R
	if(U && immh && opcode==10) return SLI_advsimd(ctx, dec); // -> SLI_asisdshf_R
	if(U && immh && opcode==12) return SQSHLU_advsimd(ctx, dec); // -> SQSHLU_asisdshf_R
	if(U && immh && opcode==14) return UQSHL_advsimd_imm(ctx, dec); // -> UQSHL_asisdshf_R
	if(U && immh && opcode==0x10) return SQSHRUN_advsimd(ctx, dec); // -> SQSHRUN_asisdshf_N
	if(U && immh && opcode==0x11) return SQRSHRUN_advsimd(ctx, dec); // -> SQRSHRUN_asisdshf_N
	if(U && immh && opcode==0x12) return UQSHRN_advsimd(ctx, dec); // -> UQSHRN_asisdshf_N
	if(U && immh && opcode==0x13) return UQRSHRN_advsimd(ctx, dec); // -> UQRSHRN_asisdshf_N
	if(U && immh && opcode==0x1c) return UCVTF_advsimd_fix(ctx, dec); // -> UCVTF_asisdshf_C
	if(U && immh && opcode==0x1f) return FCVTZU_advsimd_fix(ctx, dec); // -> FCVTZU_asisdshf_C
	if(immh && opcode==1) UNALLOCATED(ENC_UNALLOCATED_14_ASISDSHF);
	if(immh && opcode==3) UNALLOCATED(ENC_UNALLOCATED_17_ASISDSHF);
	if(immh && opcode==5) UNALLOCATED(ENC_UNALLOCATED_20_ASISDSHF);
	if(immh && opcode==7) UNALLOCATED(ENC_UNALLOCATED_23_ASISDSHF);
	if(immh && opcode==9) UNALLOCATED(ENC_UNALLOCATED_26_ASISDSHF);
	if(immh && opcode==11) UNALLOCATED(ENC_UNALLOCATED_29_ASISDSHF);
	if(immh && opcode==13) UNALLOCATED(ENC_UNALLOCATED_32_ASISDSHF);
	if(immh && opcode==15) UNALLOCATED(ENC_UNALLOCATED_35_ASISDSHF);
	if(immh && opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_48_ASISDSHF);
	if(immh && opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_49_ASISDSHF);
	if(immh && (opcode&0x1c)==0x14) UNALLOCATED(ENC_UNALLOCATED_44_ASISDSHF);
	if(immh && (opcode&0x1c)==0x18) UNALLOCATED(ENC_UNALLOCATED_45_ASISDSHF);
	if(!immh) UNALLOCATED(ENC_UNALLOCATED_11_ASISDSHF);
	UNMATCHED;
}

int decode_iclass_asisddiff(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, opcode=(INSWORD>>12)&15;
	if(!U && opcode==9) return SQDMLAL_advsimd_vec(ctx, dec); // -> SQDMLAL_asisddiff_only
	if(!U && opcode==11) return SQDMLSL_advsimd_vec(ctx, dec); // -> SQDMLSL_asisddiff_only
	if(!U && opcode==13) return SQDMULL_advsimd_vec(ctx, dec); // -> SQDMULL_asisddiff_only
	if(U && opcode==9) UNALLOCATED(ENC_UNALLOCATED_15_ASISDDIFF);
	if(U && opcode==11) UNALLOCATED(ENC_UNALLOCATED_18_ASISDDIFF);
	if(U && opcode==13) UNALLOCATED(ENC_UNALLOCATED_21_ASISDDIFF);
	if(opcode==8) UNALLOCATED(ENC_UNALLOCATED_13_ASISDDIFF);
	if(opcode==10) UNALLOCATED(ENC_UNALLOCATED_16_ASISDDIFF);
	if(opcode==12) UNALLOCATED(ENC_UNALLOCATED_19_ASISDDIFF);
	if((opcode&14)==14) UNALLOCATED(ENC_UNALLOCATED_22_ASISDDIFF);
	if(!(opcode&12)) UNALLOCATED(ENC_UNALLOCATED_11_ASISDDIFF);
	if((opcode&12)==4) UNALLOCATED(ENC_UNALLOCATED_12_ASISDDIFF);
	UNMATCHED;
}

int decode_iclass_asisdsame(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>11)&0x1f;
	if(!U && !(size&2) && opcode==0x18) RESERVED(ENC_RESERVED_44_ASISDSAME);
	if(!U && !(size&2) && opcode==0x19) RESERVED(ENC_RESERVED_48_ASISDSAME);
	if(!U && !(size&2) && opcode==0x1a) RESERVED(ENC_RESERVED_52_ASISDSAME);
	if(!U && !(size&2) && opcode==0x1b) return FMULX_advsimd_vec(ctx, dec); // -> FMULX_asisdsame_only
	if(!U && !(size&2) && opcode==0x1c) return FCMEQ_advsimd_reg(ctx, dec); // -> FCMEQ_asisdsame_only
	if(!U && !(size&2) && opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_63_ASISDSAME);
	if(!U && !(size&2) && opcode==0x1e) RESERVED(ENC_RESERVED_67_ASISDSAME);
	if(!U && !(size&2) && opcode==0x1f) return FRECPS_advsimd(ctx, dec); // -> FRECPS_asisdsame_only
	if(!U && (size&2)==2 && opcode==0x18) RESERVED(ENC_RESERVED_46_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x19) RESERVED(ENC_RESERVED_50_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x1a) RESERVED(ENC_RESERVED_54_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_61_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_65_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x1e) RESERVED(ENC_RESERVED_69_ASISDSAME);
	if(!U && (size&2)==2 && opcode==0x1f) return FRSQRTS_advsimd(ctx, dec); // -> FRSQRTS_asisdsame_only
	if(U && !(size&2) && opcode==0x18) RESERVED(ENC_RESERVED_45_ASISDSAME);
	if(U && !(size&2) && opcode==0x19) UNALLOCATED(ENC_UNALLOCATED_49_ASISDSAME);
	if(U && !(size&2) && opcode==0x1a) RESERVED(ENC_RESERVED_53_ASISDSAME);
	if(U && !(size&2) && opcode==0x1b) RESERVED(ENC_RESERVED_57_ASISDSAME);
	if(U && !(size&2) && opcode==0x1c) return FCMGE_advsimd_reg(ctx, dec); // -> FCMGE_asisdsame_only
	if(U && !(size&2) && opcode==0x1d) return FACGE_advsimd(ctx, dec); // -> FACGE_asisdsame_only
	if(U && !(size&2) && opcode==0x1e) RESERVED(ENC_RESERVED_68_ASISDSAME);
	if(U && !(size&2) && opcode==0x1f) RESERVED(ENC_RESERVED_72_ASISDSAME);
	if(U && (size&2)==2 && opcode==0x18) RESERVED(ENC_RESERVED_47_ASISDSAME);
	if(U && (size&2)==2 && opcode==0x19) UNALLOCATED(ENC_UNALLOCATED_51_ASISDSAME);
	if(U && (size&2)==2 && opcode==0x1a) return FABD_advsimd(ctx, dec); // -> FABD_asisdsame_only
	if(U && (size&2)==2 && opcode==0x1c) return FCMGT_advsimd_reg(ctx, dec); // -> FCMGT_asisdsame_only
	if(U && (size&2)==2 && opcode==0x1d) return FACGT_advsimd(ctx, dec); // -> FACGT_asisdsame_only
	if(U && (size&2)==2 && opcode==0x1e) RESERVED(ENC_RESERVED_70_ASISDSAME);
	if(U && (size&2)==2 && opcode==0x1f) RESERVED(ENC_RESERVED_74_ASISDSAME);
	if((size&2)==2 && opcode==0x1b) UNALLOCATED(ENC_UNALLOCATED_58_ASISDSAME);
	if(!U && opcode==1) return SQADD_advsimd(ctx, dec); // -> SQADD_asisdsame_only
	if(!U && opcode==5) return SQSUB_advsimd(ctx, dec); // -> SQSUB_asisdsame_only
	if(!U && opcode==6) return CMGT_advsimd_reg(ctx, dec); // -> CMGT_asisdsame_only
	if(!U && opcode==7) return CMGE_advsimd_reg(ctx, dec); // -> CMGE_asisdsame_only
	if(!U && opcode==8) return SSHL_advsimd(ctx, dec); // -> SSHL_asisdsame_only
	if(!U && opcode==9) return SQSHL_advsimd_reg(ctx, dec); // -> SQSHL_asisdsame_only
	if(!U && opcode==10) return SRSHL_advsimd(ctx, dec); // -> SRSHL_asisdsame_only
	if(!U && opcode==11) return SQRSHL_advsimd(ctx, dec); // -> SQRSHL_asisdsame_only
	if(!U && opcode==0x10) return ADD_advsimd(ctx, dec); // -> ADD_asisdsame_only
	if(!U && opcode==0x11) return CMTST_advsimd(ctx, dec); // -> CMTST_asisdsame_only
	if(!U && opcode==0x14) RESERVED(ENC_RESERVED_36_ASISDSAME);
	if(!U && opcode==0x15) RESERVED(ENC_RESERVED_38_ASISDSAME);
	if(!U && opcode==0x16) return SQDMULH_advsimd_vec(ctx, dec); // -> SQDMULH_asisdsame_only
	if(!U && opcode==0x17) RESERVED(ENC_RESERVED_42_ASISDSAME);
	if(U && opcode==1) return UQADD_advsimd(ctx, dec); // -> UQADD_asisdsame_only
	if(U && opcode==5) return UQSUB_advsimd(ctx, dec); // -> UQSUB_asisdsame_only
	if(U && opcode==6) return CMHI_advsimd(ctx, dec); // -> CMHI_asisdsame_only
	if(U && opcode==7) return CMHS_advsimd(ctx, dec); // -> CMHS_asisdsame_only
	if(U && opcode==8) return USHL_advsimd(ctx, dec); // -> USHL_asisdsame_only
	if(U && opcode==9) return UQSHL_advsimd_reg(ctx, dec); // -> UQSHL_asisdsame_only
	if(U && opcode==10) return URSHL_advsimd(ctx, dec); // -> URSHL_asisdsame_only
	if(U && opcode==11) return UQRSHL_advsimd(ctx, dec); // -> UQRSHL_asisdsame_only
	if(U && opcode==0x10) return SUB_advsimd(ctx, dec); // -> SUB_asisdsame_only
	if(U && opcode==0x11) return CMEQ_advsimd_reg(ctx, dec); // -> CMEQ_asisdsame_only
	if(U && opcode==0x14) RESERVED(ENC_RESERVED_37_ASISDSAME);
	if(U && opcode==0x15) RESERVED(ENC_RESERVED_39_ASISDSAME);
	if(U && opcode==0x16) return SQRDMULH_advsimd_vec(ctx, dec); // -> SQRDMULH_asisdsame_only
	if(U && opcode==0x17) UNALLOCATED(ENC_UNALLOCATED_43_ASISDSAME);
	if(!opcode) UNALLOCATED(ENC_UNALLOCATED_11_ASISDSAME);
	if(opcode==4) UNALLOCATED(ENC_UNALLOCATED_15_ASISDSAME);
	if((opcode&0x1e)==2) UNALLOCATED(ENC_UNALLOCATED_14_ASISDSAME);
	if((opcode&0x1e)==0x12) UNALLOCATED(ENC_UNALLOCATED_35_ASISDSAME);
	if((opcode&0x1c)==12) UNALLOCATED(ENC_UNALLOCATED_30_ASISDSAME);
	UNMATCHED;
}

int decode_iclass_asisdsamefp16(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, a=(INSWORD>>23)&1, opcode=(INSWORD>>11)&7;
	if(!U && !a && opcode==3 && HasFP16()) return FMULX_advsimd_vec(ctx, dec); // -> FMULX_asisdsamefp16_only
	if(!U && !a && opcode==4 && HasFP16()) return FCMEQ_advsimd_reg(ctx, dec); // -> FCMEQ_asisdsamefp16_only
	if(!U && !a && opcode==5) UNALLOCATED(ENC_UNALLOCATED_19_ASISDSAMEFP16);
	if(!U && !a && opcode==7 && HasFP16()) return FRECPS_advsimd(ctx, dec); // -> FRECPS_asisdsamefp16_only
	if(!U && a && opcode==4) UNALLOCATED(ENC_UNALLOCATED_17_ASISDSAMEFP16);
	if(!U && a && opcode==5) UNALLOCATED(ENC_UNALLOCATED_21_ASISDSAMEFP16);
	if(!U && a && opcode==7 && HasFP16()) return FRSQRTS_advsimd(ctx, dec); // -> FRSQRTS_asisdsamefp16_only
	if(U && !a && opcode==3) UNALLOCATED(ENC_UNALLOCATED_13_ASISDSAMEFP16);
	if(U && !a && opcode==4 && HasFP16()) return FCMGE_advsimd_reg(ctx, dec); // -> FCMGE_asisdsamefp16_only
	if(U && !a && opcode==5 && HasFP16()) return FACGE_advsimd(ctx, dec); // -> FACGE_asisdsamefp16_only
	if(U && !a && opcode==7) UNALLOCATED(ENC_UNALLOCATED_25_ASISDSAMEFP16);
	if(U && a && opcode==2 && HasFP16()) return FABD_advsimd(ctx, dec); // -> FABD_asisdsamefp16_only
	if(U && a && opcode==4 && HasFP16()) return FCMGT_advsimd_reg(ctx, dec); // -> FCMGT_asisdsamefp16_only
	if(U && a && opcode==5 && HasFP16()) return FACGT_advsimd(ctx, dec); // -> FACGT_asisdsamefp16_only
	if(U && a && opcode==7) UNALLOCATED(ENC_UNALLOCATED_27_ASISDSAMEFP16);
	if(a && opcode==3) UNALLOCATED(ENC_UNALLOCATED_14_ASISDSAMEFP16);
	if(opcode==6) UNALLOCATED(ENC_UNALLOCATED_23_ASISDSAMEFP16);
	UNMATCHED;
}

int decode_iclass_asisdsame2(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, opcode=(INSWORD>>11)&15;
	if(!U && !opcode) UNALLOCATED(ENC_UNALLOCATED_11_ASISDSAME2);
	if(!U && opcode==1) UNALLOCATED(ENC_UNALLOCATED_13_ASISDSAME2);
	if(U && !opcode && HasRDMA()) return SQRDMLAH_advsimd_vec(ctx, dec); // -> SQRDMLAH_asisdsame2_only
	if(U && opcode==1 && HasRDMA()) return SQRDMLSH_advsimd_vec(ctx, dec); // -> SQRDMLSH_asisdsame2_only
	if((opcode&14)==2) UNALLOCATED(ENC_UNALLOCATED_15_ASISDSAME2);
	if((opcode&12)==4) UNALLOCATED(ENC_UNALLOCATED_16_ASISDSAME2);
	if((opcode&8)==8) UNALLOCATED(ENC_UNALLOCATED_17_ASISDSAME2);
	UNMATCHED;
}

int decode_iclass_asisdmisc(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!U && !(size&2) && opcode==0x16) UNALLOCATED(ENC_UNALLOCATED_42_ASISDMISC);
	if(!U && !(size&2) && opcode==0x1a) return FCVTNS_advsimd(ctx, dec); // -> FCVTNS_asisdmisc_R
	if(!U && !(size&2) && opcode==0x1b) return FCVTMS_advsimd(ctx, dec); // -> FCVTMS_asisdmisc_R
	if(!U && !(size&2) && opcode==0x1c) return FCVTAS_advsimd(ctx, dec); // -> FCVTAS_asisdmisc_R
	if(!U && !(size&2) && opcode==0x1d) return SCVTF_advsimd_int(ctx, dec); // -> SCVTF_asisdmisc_R
	if(!U && (size&2)==2 && opcode==12) return FCMGT_advsimd_zero(ctx, dec); // -> FCMGT_asisdmisc_FZ
	if(!U && (size&2)==2 && opcode==13) return FCMEQ_advsimd_zero(ctx, dec); // -> FCMEQ_asisdmisc_FZ
	if(!U && (size&2)==2 && opcode==14) return FCMLT_advsimd(ctx, dec); // -> FCMLT_asisdmisc_FZ
	if(!U && (size&2)==2 && opcode==0x1a) return FCVTPS_advsimd(ctx, dec); // -> FCVTPS_asisdmisc_R
	if(!U && (size&2)==2 && opcode==0x1b) return FCVTZS_advsimd_int(ctx, dec); // -> FCVTZS_asisdmisc_R
	if(!U && (size&2)==2 && opcode==0x1d) return FRECPE_advsimd(ctx, dec); // -> FRECPE_asisdmisc_R
	if(!U && (size&2)==2 && opcode==0x1f) return FRECPX_advsimd(ctx, dec); // -> FRECPX_asisdmisc_R
	if(U && !(size&2) && opcode==0x16) return FCVTXN_advsimd(ctx, dec); // -> FCVTXN_asisdmisc_N
	if(U && !(size&2) && opcode==0x1a) return FCVTNU_advsimd(ctx, dec); // -> FCVTNU_asisdmisc_R
	if(U && !(size&2) && opcode==0x1b) return FCVTMU_advsimd(ctx, dec); // -> FCVTMU_asisdmisc_R
	if(U && !(size&2) && opcode==0x1c) return FCVTAU_advsimd(ctx, dec); // -> FCVTAU_asisdmisc_R
	if(U && !(size&2) && opcode==0x1d) return UCVTF_advsimd_int(ctx, dec); // -> UCVTF_asisdmisc_R
	if(U && (size&2)==2 && opcode==12) return FCMGE_advsimd_zero(ctx, dec); // -> FCMGE_asisdmisc_FZ
	if(U && (size&2)==2 && opcode==13) return FCMLE_advsimd(ctx, dec); // -> FCMLE_asisdmisc_FZ
	if(U && (size&2)==2 && opcode==14) UNALLOCATED(ENC_UNALLOCATED_33_ASISDMISC);
	if(U && (size&2)==2 && opcode==0x1a) return FCVTPU_advsimd(ctx, dec); // -> FCVTPU_asisdmisc_R
	if(U && (size&2)==2 && opcode==0x1b) return FCVTZU_advsimd_int(ctx, dec); // -> FCVTZU_asisdmisc_R
	if(U && (size&2)==2 && opcode==0x1d) return FRSQRTE_advsimd(ctx, dec); // -> FRSQRTE_asisdmisc_R
	if(U && (size&2)==2 && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_65_ASISDMISC);
	if(!(size&2) && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_63_ASISDMISC);
	if((size&2)==2 && opcode==0x16) UNALLOCATED(ENC_UNALLOCATED_44_ASISDMISC);
	if((size&2)==2 && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_57_ASISDMISC);
	if(!U && opcode==3) return SUQADD_advsimd(ctx, dec); // -> SUQADD_asisdmisc_R
	if(!U && opcode==7) return SQABS_advsimd(ctx, dec); // -> SQABS_asisdmisc_R
	if(!U && opcode==8) return CMGT_advsimd_zero(ctx, dec); // -> CMGT_asisdmisc_Z
	if(!U && opcode==9) return CMEQ_advsimd_zero(ctx, dec); // -> CMEQ_asisdmisc_Z
	if(!U && opcode==10) return CMLT_advsimd(ctx, dec); // -> CMLT_asisdmisc_Z
	if(!U && opcode==11) return ABS_advsimd(ctx, dec); // -> ABS_asisdmisc_R
	if(!U && opcode==0x12) UNALLOCATED(ENC_UNALLOCATED_36_ASISDMISC);
	if(!U && opcode==0x14) return SQXTN_advsimd(ctx, dec); // -> SQXTN_asisdmisc_N
	if(U && opcode==3) return USQADD_advsimd(ctx, dec); // -> USQADD_asisdmisc_R
	if(U && opcode==7) return SQNEG_advsimd(ctx, dec); // -> SQNEG_asisdmisc_R
	if(U && opcode==8) return CMGE_advsimd_zero(ctx, dec); // -> CMGE_asisdmisc_Z
	if(U && opcode==9) return CMLE_advsimd(ctx, dec); // -> CMLE_asisdmisc_Z
	if(U && opcode==10) UNALLOCATED(ENC_UNALLOCATED_24_ASISDMISC);
	if(U && opcode==11) return NEG_advsimd(ctx, dec); // -> NEG_asisdmisc_R
	if(U && opcode==0x12) return SQXTUN_advsimd(ctx, dec); // -> SQXTUN_asisdmisc_N
	if(U && opcode==0x14) return UQXTN_advsimd(ctx, dec); // -> UQXTN_asisdmisc_N
	if(opcode==2) UNALLOCATED(ENC_UNALLOCATED_12_ASISDMISC);
	if(opcode==6) UNALLOCATED(ENC_UNALLOCATED_16_ASISDMISC);
	if(opcode==15) UNALLOCATED(ENC_UNALLOCATED_34_ASISDMISC);
	if(opcode==0x13) UNALLOCATED(ENC_UNALLOCATED_38_ASISDMISC);
	if(opcode==0x15) UNALLOCATED(ENC_UNALLOCATED_41_ASISDMISC);
	if(opcode==0x17) UNALLOCATED(ENC_UNALLOCATED_45_ASISDMISC);
	if(opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_62_ASISDMISC);
	if(!(opcode&0x1e)) UNALLOCATED(ENC_UNALLOCATED_11_ASISDMISC);
	if((opcode&0x1e)==4) UNALLOCATED(ENC_UNALLOCATED_15_ASISDMISC);
	if((opcode&0x1e)==0x10) UNALLOCATED(ENC_UNALLOCATED_35_ASISDMISC);
	if((opcode&0x1e)==0x18) UNALLOCATED(ENC_UNALLOCATED_46_ASISDMISC);
	if(!(size&2) && (opcode&0x1c)==12) UNALLOCATED(ENC_UNALLOCATED_27_ASISDMISC);
	UNMATCHED;
}

int decode_iclass_asisdmiscfp16(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, a=(INSWORD>>23)&1, opcode=(INSWORD>>12)&0x1f;
	if(!U && !a && opcode==0x1a && HasFP16()) return FCVTNS_advsimd(ctx, dec); // -> FCVTNS_asisdmiscfp16_R
	if(!U && !a && opcode==0x1b && HasFP16()) return FCVTMS_advsimd(ctx, dec); // -> FCVTMS_asisdmiscfp16_R
	if(!U && !a && opcode==0x1c && HasFP16()) return FCVTAS_advsimd(ctx, dec); // -> FCVTAS_asisdmiscfp16_R
	if(!U && !a && opcode==0x1d && HasFP16()) return SCVTF_advsimd_int(ctx, dec); // -> SCVTF_asisdmiscfp16_R
	if(!U && a && opcode==12 && HasFP16()) return FCMGT_advsimd_zero(ctx, dec); // -> FCMGT_asisdmiscfp16_FZ
	if(!U && a && opcode==13 && HasFP16()) return FCMEQ_advsimd_zero(ctx, dec); // -> FCMEQ_asisdmiscfp16_FZ
	if(!U && a && opcode==14 && HasFP16()) return FCMLT_advsimd(ctx, dec); // -> FCMLT_asisdmiscfp16_FZ
	if(!U && a && opcode==0x1a && HasFP16()) return FCVTPS_advsimd(ctx, dec); // -> FCVTPS_asisdmiscfp16_R
	if(!U && a && opcode==0x1b && HasFP16()) return FCVTZS_advsimd_int(ctx, dec); // -> FCVTZS_asisdmiscfp16_R
	if(!U && a && opcode==0x1d && HasFP16()) return FRECPE_advsimd(ctx, dec); // -> FRECPE_asisdmiscfp16_R
	if(!U && a && opcode==0x1f && HasFP16()) return FRECPX_advsimd(ctx, dec); // -> FRECPX_asisdmiscfp16_R
	if(U && !a && opcode==0x1a && HasFP16()) return FCVTNU_advsimd(ctx, dec); // -> FCVTNU_asisdmiscfp16_R
	if(U && !a && opcode==0x1b && HasFP16()) return FCVTMU_advsimd(ctx, dec); // -> FCVTMU_asisdmiscfp16_R
	if(U && !a && opcode==0x1c && HasFP16()) return FCVTAU_advsimd(ctx, dec); // -> FCVTAU_asisdmiscfp16_R
	if(U && !a && opcode==0x1d && HasFP16()) return UCVTF_advsimd_int(ctx, dec); // -> UCVTF_asisdmiscfp16_R
	if(U && a && opcode==12 && HasFP16()) return FCMGE_advsimd_zero(ctx, dec); // -> FCMGE_asisdmiscfp16_FZ
	if(U && a && opcode==13 && HasFP16()) return FCMLE_advsimd(ctx, dec); // -> FCMLE_asisdmiscfp16_FZ
	if(U && a && opcode==14) UNALLOCATED(ENC_UNALLOCATED_19_ASISDMISCFP16);
	if(U && a && opcode==0x1a && HasFP16()) return FCVTPU_advsimd(ctx, dec); // -> FCVTPU_asisdmiscfp16_R
	if(U && a && opcode==0x1b && HasFP16()) return FCVTZU_advsimd_int(ctx, dec); // -> FCVTZU_asisdmiscfp16_R
	if(U && a && opcode==0x1d && HasFP16()) return FRSQRTE_advsimd(ctx, dec); // -> FRSQRTE_asisdmiscfp16_R
	if(U && a && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_41_ASISDMISCFP16);
	if(!a && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_39_ASISDMISCFP16);
	if(a && opcode==15) UNALLOCATED(ENC_UNALLOCATED_20_ASISDMISCFP16);
	if(a && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_33_ASISDMISCFP16);
	if(opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_38_ASISDMISCFP16);
	if((opcode&0x1e)==0x18) UNALLOCATED(ENC_UNALLOCATED_22_ASISDMISCFP16);
	if(!a && (opcode&0x1c)==12) UNALLOCATED(ENC_UNALLOCATED_13_ASISDMISCFP16);
	if((opcode&0x1c)==8) UNALLOCATED(ENC_UNALLOCATED_12_ASISDMISCFP16);
	if(!(opcode&0x18)) UNALLOCATED(ENC_UNALLOCATED_11_ASISDMISCFP16);
	if((opcode&0x18)==0x10) UNALLOCATED(ENC_UNALLOCATED_21_ASISDMISCFP16);
	UNMATCHED;
}

int decode_iclass_asisdelem(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&15;
	if(!U && !size && opcode==1 && HasFP16()) return FMLA_advsimd_elt(ctx, dec); // -> FMLA_asisdelem_RH_H
	if(!U && !size && opcode==5 && HasFP16()) return FMLS_advsimd_elt(ctx, dec); // -> FMLS_asisdelem_RH_H
	if(!U && !size && opcode==9 && HasFP16()) return FMUL_advsimd_elt(ctx, dec); // -> FMUL_asisdelem_RH_H
	if(U && !size && opcode==1) UNALLOCATED(ENC_UNALLOCATED_13_ASISDELEM);
	if(U && !size && opcode==5) UNALLOCATED(ENC_UNALLOCATED_22_ASISDELEM);
	if(U && !size && opcode==9 && HasFP16()) return FMULX_advsimd_elt(ctx, dec); // -> FMULX_asisdelem_RH_H
	if(size==1 && opcode==1) UNALLOCATED(ENC_UNALLOCATED_14_ASISDELEM);
	if(size==1 && opcode==5) UNALLOCATED(ENC_UNALLOCATED_23_ASISDELEM);
	if(size==1 && opcode==9) UNALLOCATED(ENC_UNALLOCATED_32_ASISDELEM);
	if(!U && (size&2)==2 && opcode==1) return FMLA_advsimd_elt(ctx, dec); // -> FMLA_asisdelem_R_SD
	if(!U && (size&2)==2 && opcode==5) return FMLS_advsimd_elt(ctx, dec); // -> FMLS_asisdelem_R_SD
	if(!U && (size&2)==2 && opcode==9) return FMUL_advsimd_elt(ctx, dec); // -> FMUL_asisdelem_R_SD
	if(U && (size&2)==2 && opcode==1) UNALLOCATED(ENC_UNALLOCATED_16_ASISDELEM);
	if(U && (size&2)==2 && opcode==5) UNALLOCATED(ENC_UNALLOCATED_25_ASISDELEM);
	if(U && (size&2)==2 && opcode==9) return FMULX_advsimd_elt(ctx, dec); // -> FMULX_asisdelem_R_SD
	if(!U && opcode==3) return SQDMLAL_advsimd_elt(ctx, dec); // -> SQDMLAL_asisdelem_L
	if(!U && opcode==7) return SQDMLSL_advsimd_elt(ctx, dec); // -> SQDMLSL_asisdelem_L
	if(!U && opcode==11) return SQDMULL_advsimd_elt(ctx, dec); // -> SQDMULL_asisdelem_L
	if(!U && opcode==12) return SQDMULH_advsimd_elt(ctx, dec); // -> SQDMULH_asisdelem_R
	if(!U && opcode==13) return SQRDMULH_advsimd_elt(ctx, dec); // -> SQRDMULH_asisdelem_R
	if(!U && opcode==15) UNALLOCATED(ENC_UNALLOCATED_43_ASISDELEM);
	if(U && opcode==3) UNALLOCATED(ENC_UNALLOCATED_19_ASISDELEM);
	if(U && opcode==7) UNALLOCATED(ENC_UNALLOCATED_28_ASISDELEM);
	if(U && opcode==11) UNALLOCATED(ENC_UNALLOCATED_37_ASISDELEM);
	if(U && opcode==12) UNALLOCATED(ENC_UNALLOCATED_39_ASISDELEM);
	if(U && opcode==13 && HasRDMA()) return SQRDMLAH_advsimd_elt(ctx, dec); // -> SQRDMLAH_asisdelem_R
	if(U && opcode==15 && HasRDMA()) return SQRDMLSH_advsimd_elt(ctx, dec); // -> SQRDMLSH_asisdelem_R
	if(!opcode) UNALLOCATED(ENC_UNALLOCATED_11_ASISDELEM);
	if(opcode==2) UNALLOCATED(ENC_UNALLOCATED_17_ASISDELEM);
	if(opcode==4) UNALLOCATED(ENC_UNALLOCATED_20_ASISDELEM);
	if(opcode==6) UNALLOCATED(ENC_UNALLOCATED_26_ASISDELEM);
	if(opcode==8) UNALLOCATED(ENC_UNALLOCATED_29_ASISDELEM);
	if(opcode==10) UNALLOCATED(ENC_UNALLOCATED_35_ASISDELEM);
	if(opcode==14) UNALLOCATED(ENC_UNALLOCATED_42_ASISDELEM);
	UNMATCHED;
}

int decode_iclass_asimdshf(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, opcode=(INSWORD>>11)&0x1f;
	if(!U && !opcode) return SSHR_advsimd(ctx, dec); // -> SSHR_asimdshf_R
	if(!U && opcode==2) return SSRA_advsimd(ctx, dec); // -> SSRA_asimdshf_R
	if(!U && opcode==4) return SRSHR_advsimd(ctx, dec); // -> SRSHR_asimdshf_R
	if(!U && opcode==6) return SRSRA_advsimd(ctx, dec); // -> SRSRA_asimdshf_R
	if(!U && opcode==8) UNALLOCATED(ENC_UNALLOCATED_23_ASIMDSHF);
	if(!U && opcode==10) return SHL_advsimd(ctx, dec); // -> SHL_asimdshf_R
	if(!U && opcode==12) UNALLOCATED(ENC_UNALLOCATED_29_ASIMDSHF);
	if(!U && opcode==14) return SQSHL_advsimd_imm(ctx, dec); // -> SQSHL_asimdshf_R
	if(!U && opcode==0x10) return SHRN_advsimd(ctx, dec); // -> SHRN_asimdshf_N
	if(!U && opcode==0x11) return RSHRN_advsimd(ctx, dec); // -> RSHRN_asimdshf_N
	if(!U && opcode==0x12) return SQSHRN_advsimd(ctx, dec); // -> SQSHRN_asimdshf_N
	if(!U && opcode==0x13) return SQRSHRN_advsimd(ctx, dec); // -> SQRSHRN_asimdshf_N
	if(!U && opcode==0x14) return SSHLL_advsimd(ctx, dec); // -> SSHLL_asimdshf_L
	if(!U && opcode==0x1c) return SCVTF_advsimd_fix(ctx, dec); // -> SCVTF_asimdshf_C
	if(!U && opcode==0x1f) return FCVTZS_advsimd_fix(ctx, dec); // -> FCVTZS_asimdshf_C
	if(U && !opcode) return USHR_advsimd(ctx, dec); // -> USHR_asimdshf_R
	if(U && opcode==2) return USRA_advsimd(ctx, dec); // -> USRA_asimdshf_R
	if(U && opcode==4) return URSHR_advsimd(ctx, dec); // -> URSHR_asimdshf_R
	if(U && opcode==6) return URSRA_advsimd(ctx, dec); // -> URSRA_asimdshf_R
	if(U && opcode==8) return SRI_advsimd(ctx, dec); // -> SRI_asimdshf_R
	if(U && opcode==10) return SLI_advsimd(ctx, dec); // -> SLI_asimdshf_R
	if(U && opcode==12) return SQSHLU_advsimd(ctx, dec); // -> SQSHLU_asimdshf_R
	if(U && opcode==14) return UQSHL_advsimd_imm(ctx, dec); // -> UQSHL_asimdshf_R
	if(U && opcode==0x10) return SQSHRUN_advsimd(ctx, dec); // -> SQSHRUN_asimdshf_N
	if(U && opcode==0x11) return SQRSHRUN_advsimd(ctx, dec); // -> SQRSHRUN_asimdshf_N
	if(U && opcode==0x12) return UQSHRN_advsimd(ctx, dec); // -> UQSHRN_asimdshf_N
	if(U && opcode==0x13) return UQRSHRN_advsimd(ctx, dec); // -> UQRSHRN_asimdshf_N
	if(U && opcode==0x14) return USHLL_advsimd(ctx, dec); // -> USHLL_asimdshf_L
	if(U && opcode==0x1c) return UCVTF_advsimd_fix(ctx, dec); // -> UCVTF_asimdshf_C
	if(U && opcode==0x1f) return FCVTZU_advsimd_fix(ctx, dec); // -> FCVTZU_asimdshf_C
	if(opcode==1) UNALLOCATED(ENC_UNALLOCATED_13_ASIMDSHF);
	if(opcode==3) UNALLOCATED(ENC_UNALLOCATED_16_ASIMDSHF);
	if(opcode==5) UNALLOCATED(ENC_UNALLOCATED_19_ASIMDSHF);
	if(opcode==7) UNALLOCATED(ENC_UNALLOCATED_22_ASIMDSHF);
	if(opcode==9) UNALLOCATED(ENC_UNALLOCATED_25_ASIMDSHF);
	if(opcode==11) UNALLOCATED(ENC_UNALLOCATED_28_ASIMDSHF);
	if(opcode==13) UNALLOCATED(ENC_UNALLOCATED_31_ASIMDSHF);
	if(opcode==15) UNALLOCATED(ENC_UNALLOCATED_34_ASIMDSHF);
	if(opcode==0x15) UNALLOCATED(ENC_UNALLOCATED_45_ASIMDSHF);
	if(opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_50_ASIMDSHF);
	if(opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_51_ASIMDSHF);
	if((opcode&0x1e)==0x16) UNALLOCATED(ENC_UNALLOCATED_46_ASIMDSHF);
	if((opcode&0x1c)==0x18) UNALLOCATED(ENC_UNALLOCATED_47_ASIMDSHF);
	UNMATCHED;
}

int decode_iclass_asimdtbl(context *ctx, Instruction *dec)
{
	uint32_t op2=(INSWORD>>22)&3, len=(INSWORD>>13)&3, op=(INSWORD>>12)&1;
	if(!op2 && !len && !op) return TBL_advsimd(ctx, dec); // -> TBL_asimdtbl_L1_1
	if(!op2 && !len && op) return TBX_advsimd(ctx, dec); // -> TBX_asimdtbl_L1_1
	if(!op2 && len==1 && !op) return TBL_advsimd(ctx, dec); // -> TBL_asimdtbl_L2_2
	if(!op2 && len==1 && op) return TBX_advsimd(ctx, dec); // -> TBX_asimdtbl_L2_2
	if(!op2 && len==2 && !op) return TBL_advsimd(ctx, dec); // -> TBL_asimdtbl_L3_3
	if(!op2 && len==2 && op) return TBX_advsimd(ctx, dec); // -> TBX_asimdtbl_L3_3
	if(!op2 && len==3 && !op) return TBL_advsimd(ctx, dec); // -> TBL_asimdtbl_L4_4
	if(!op2 && len==3 && op) return TBX_advsimd(ctx, dec); // -> TBX_asimdtbl_L4_4
	if(op2&1) UNALLOCATED(ENC_UNALLOCATED_11_ASIMDTBL);
	if((op2&2)==2) UNALLOCATED(ENC_UNALLOCATED_12_ASIMDTBL);
	UNMATCHED;
}

int decode_iclass_asimddiff(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, opcode=(INSWORD>>12)&15;
	if(!U && !opcode) return SADDL_advsimd(ctx, dec); // -> SADDL_asimddiff_L
	if(!U && opcode==1) return SADDW_advsimd(ctx, dec); // -> SADDW_asimddiff_W
	if(!U && opcode==2) return SSUBL_advsimd(ctx, dec); // -> SSUBL_asimddiff_L
	if(!U && opcode==3) return SSUBW_advsimd(ctx, dec); // -> SSUBW_asimddiff_W
	if(!U && opcode==4) return ADDHN_advsimd(ctx, dec); // -> ADDHN_asimddiff_N
	if(!U && opcode==5) return SABAL_advsimd(ctx, dec); // -> SABAL_asimddiff_L
	if(!U && opcode==6) return SUBHN_advsimd(ctx, dec); // -> SUBHN_asimddiff_N
	if(!U && opcode==7) return SABDL_advsimd(ctx, dec); // -> SABDL_asimddiff_L
	if(!U && opcode==8) return SMLAL_advsimd_vec(ctx, dec); // -> SMLAL_asimddiff_L
	if(!U && opcode==9) return SQDMLAL_advsimd_vec(ctx, dec); // -> SQDMLAL_asimddiff_L
	if(!U && opcode==10) return SMLSL_advsimd_vec(ctx, dec); // -> SMLSL_asimddiff_L
	if(!U && opcode==11) return SQDMLSL_advsimd_vec(ctx, dec); // -> SQDMLSL_asimddiff_L
	if(!U && opcode==12) return SMULL_advsimd_vec(ctx, dec); // -> SMULL_asimddiff_L
	if(!U && opcode==13) return SQDMULL_advsimd_vec(ctx, dec); // -> SQDMULL_asimddiff_L
	if(!U && opcode==14) return PMULL_advsimd(ctx, dec); // -> PMULL_asimddiff_L
	if(U && !opcode) return UADDL_advsimd(ctx, dec); // -> UADDL_asimddiff_L
	if(U && opcode==1) return UADDW_advsimd(ctx, dec); // -> UADDW_asimddiff_W
	if(U && opcode==2) return USUBL_advsimd(ctx, dec); // -> USUBL_asimddiff_L
	if(U && opcode==3) return USUBW_advsimd(ctx, dec); // -> USUBW_asimddiff_W
	if(U && opcode==4) return RADDHN_advsimd(ctx, dec); // -> RADDHN_asimddiff_N
	if(U && opcode==5) return UABAL_advsimd(ctx, dec); // -> UABAL_asimddiff_L
	if(U && opcode==6) return RSUBHN_advsimd(ctx, dec); // -> RSUBHN_asimddiff_N
	if(U && opcode==7) return UABDL_advsimd(ctx, dec); // -> UABDL_asimddiff_L
	if(U && opcode==8) return UMLAL_advsimd_vec(ctx, dec); // -> UMLAL_asimddiff_L
	if(U && opcode==9) UNALLOCATED(ENC_UNALLOCATED_32_ASIMDDIFF);
	if(U && opcode==10) return UMLSL_advsimd_vec(ctx, dec); // -> UMLSL_asimddiff_L
	if(U && opcode==11) UNALLOCATED(ENC_UNALLOCATED_34_ASIMDDIFF);
	if(U && opcode==12) return UMULL_advsimd_vec(ctx, dec); // -> UMULL_asimddiff_L
	if(U && opcode==13) UNALLOCATED(ENC_UNALLOCATED_38_ASIMDDIFF);
	if(U && opcode==14) UNALLOCATED(ENC_UNALLOCATED_40_ASIMDDIFF);
	if(opcode==15) UNALLOCATED(ENC_UNALLOCATED_41_ASIMDDIFF);
	UNMATCHED;
}

int decode_iclass_asimdsame(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>11)&0x1f;
	if(!U && !size && opcode==3) return AND_advsimd(ctx, dec); // -> AND_asimdsame_only
	if(!U && !size && opcode==0x1d && HasFHM()) return FMLAL_advsimd_vec(ctx, dec); // -> FMLAL_asimdsame_F
	if(!U && size==1 && opcode==3) return BIC_advsimd_reg(ctx, dec); // -> BIC_asimdsame_only
	if(!U && size==1 && opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_88_ASIMDSAME);
	if(!U && size==2 && opcode==3) return ORR_advsimd_reg(ctx, dec); // -> ORR_asimdsame_only
	if(!U && size==2 && opcode==0x1d && HasFHM()) return FMLSL_advsimd_vec(ctx, dec); // -> FMLSL_asimdsame_F
	if(!U && size==3 && opcode==3) return ORN_advsimd(ctx, dec); // -> ORN_asimdsame_only
	if(!U && size==3 && opcode==0x1d) UNALLOCATED(ENC_UNALLOCATED_91_ASIMDSAME);
	if(U && !size && opcode==3) return EOR_advsimd(ctx, dec); // -> EOR_asimdsame_only
	if(U && !size && opcode==0x19 && HasFHM()) return FMLAL_advsimd_vec(ctx, dec); // -> FMLAL2_asimdsame_F
	if(U && size==1 && opcode==3) return BSL_advsimd(ctx, dec); // -> BSL_asimdsame_only
	if(U && size==1 && opcode==0x19) UNALLOCATED(ENC_UNALLOCATED_71_ASIMDSAME);
	if(U && size==2 && opcode==3) return BIT_advsimd(ctx, dec); // -> BIT_asimdsame_only
	if(U && size==2 && opcode==0x19 && HasFHM()) return FMLSL_advsimd_vec(ctx, dec); // -> FMLSL2_asimdsame_F
	if(U && size==3 && opcode==3) return BIF_advsimd(ctx, dec); // -> BIF_asimdsame_only
	if(U && size==3 && opcode==0x19) UNALLOCATED(ENC_UNALLOCATED_74_ASIMDSAME);
	if(!U && !(size&2) && opcode==0x18) return FMAXNM_advsimd(ctx, dec); // -> FMAXNM_asimdsame_only
	if(!U && !(size&2) && opcode==0x19) return FMLA_advsimd_vec(ctx, dec); // -> FMLA_asimdsame_only
	if(!U && !(size&2) && opcode==0x1a) return FADD_advsimd(ctx, dec); // -> FADD_asimdsame_only
	if(!U && !(size&2) && opcode==0x1b) return FMULX_advsimd_vec(ctx, dec); // -> FMULX_asimdsame_only
	if(!U && !(size&2) && opcode==0x1c) return FCMEQ_advsimd_reg(ctx, dec); // -> FCMEQ_asimdsame_only
	if(!U && !(size&2) && opcode==0x1e) return FMAX_advsimd(ctx, dec); // -> FMAX_asimdsame_only
	if(!U && !(size&2) && opcode==0x1f) return FRECPS_advsimd(ctx, dec); // -> FRECPS_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x18) return FMINNM_advsimd(ctx, dec); // -> FMINNM_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x19) return FMLS_advsimd_vec(ctx, dec); // -> FMLS_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x1a) return FSUB_advsimd(ctx, dec); // -> FSUB_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x1b) UNALLOCATED(ENC_UNALLOCATED_81_ASIMDSAME);
	if(!U && (size&2)==2 && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_85_ASIMDSAME);
	if(!U && (size&2)==2 && opcode==0x1e) return FMIN_advsimd(ctx, dec); // -> FMIN_asimdsame_only
	if(!U && (size&2)==2 && opcode==0x1f) return FRSQRTS_advsimd(ctx, dec); // -> FRSQRTS_asimdsame_only
	if(U && !(size&2) && opcode==0x18) return FMAXNMP_advsimd_vec(ctx, dec); // -> FMAXNMP_asimdsame_only
	if(U && !(size&2) && opcode==0x1a) return FADDP_advsimd_vec(ctx, dec); // -> FADDP_asimdsame_only
	if(U && !(size&2) && opcode==0x1b) return FMUL_advsimd_vec(ctx, dec); // -> FMUL_asimdsame_only
	if(U && !(size&2) && opcode==0x1c) return FCMGE_advsimd_reg(ctx, dec); // -> FCMGE_asimdsame_only
	if(U && !(size&2) && opcode==0x1d) return FACGE_advsimd(ctx, dec); // -> FACGE_asimdsame_only
	if(U && !(size&2) && opcode==0x1e) return FMAXP_advsimd_vec(ctx, dec); // -> FMAXP_asimdsame_only
	if(U && !(size&2) && opcode==0x1f) return FDIV_advsimd(ctx, dec); // -> FDIV_asimdsame_only
	if(U && (size&2)==2 && opcode==0x18) return FMINNMP_advsimd_vec(ctx, dec); // -> FMINNMP_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1a) return FABD_advsimd(ctx, dec); // -> FABD_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1b) UNALLOCATED(ENC_UNALLOCATED_82_ASIMDSAME);
	if(U && (size&2)==2 && opcode==0x1c) return FCMGT_advsimd_reg(ctx, dec); // -> FCMGT_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1d) return FACGT_advsimd(ctx, dec); // -> FACGT_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1e) return FMINP_advsimd_vec(ctx, dec); // -> FMINP_asimdsame_only
	if(U && (size&2)==2 && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_100_ASIMDSAME);
	if(!U && !opcode) return SHADD_advsimd(ctx, dec); // -> SHADD_asimdsame_only
	if(!U && opcode==1) return SQADD_advsimd(ctx, dec); // -> SQADD_asimdsame_only
	if(!U && opcode==2) return SRHADD_advsimd(ctx, dec); // -> SRHADD_asimdsame_only
	if(!U && opcode==4) return SHSUB_advsimd(ctx, dec); // -> SHSUB_asimdsame_only
	if(!U && opcode==5) return SQSUB_advsimd(ctx, dec); // -> SQSUB_asimdsame_only
	if(!U && opcode==6) return CMGT_advsimd_reg(ctx, dec); // -> CMGT_asimdsame_only
	if(!U && opcode==7) return CMGE_advsimd_reg(ctx, dec); // -> CMGE_asimdsame_only
	if(!U && opcode==8) return SSHL_advsimd(ctx, dec); // -> SSHL_asimdsame_only
	if(!U && opcode==9) return SQSHL_advsimd_reg(ctx, dec); // -> SQSHL_asimdsame_only
	if(!U && opcode==10) return SRSHL_advsimd(ctx, dec); // -> SRSHL_asimdsame_only
	if(!U && opcode==11) return SQRSHL_advsimd(ctx, dec); // -> SQRSHL_asimdsame_only
	if(!U && opcode==12) return SMAX_advsimd(ctx, dec); // -> SMAX_asimdsame_only
	if(!U && opcode==13) return SMIN_advsimd(ctx, dec); // -> SMIN_asimdsame_only
	if(!U && opcode==14) return SABD_advsimd(ctx, dec); // -> SABD_asimdsame_only
	if(!U && opcode==15) return SABA_advsimd(ctx, dec); // -> SABA_asimdsame_only
	if(!U && opcode==0x10) return ADD_advsimd(ctx, dec); // -> ADD_asimdsame_only
	if(!U && opcode==0x11) return CMTST_advsimd(ctx, dec); // -> CMTST_asimdsame_only
	if(!U && opcode==0x12) return MLA_advsimd_vec(ctx, dec); // -> MLA_asimdsame_only
	if(!U && opcode==0x13) return MUL_advsimd_vec(ctx, dec); // -> MUL_asimdsame_only
	if(!U && opcode==0x14) return SMAXP_advsimd(ctx, dec); // -> SMAXP_asimdsame_only
	if(!U && opcode==0x15) return SMINP_advsimd(ctx, dec); // -> SMINP_asimdsame_only
	if(!U && opcode==0x16) return SQDMULH_advsimd_vec(ctx, dec); // -> SQDMULH_asimdsame_only
	if(!U && opcode==0x17) return ADDP_advsimd_vec(ctx, dec); // -> ADDP_asimdsame_only
	if(U && !opcode) return UHADD_advsimd(ctx, dec); // -> UHADD_asimdsame_only
	if(U && opcode==1) return UQADD_advsimd(ctx, dec); // -> UQADD_asimdsame_only
	if(U && opcode==2) return URHADD_advsimd(ctx, dec); // -> URHADD_asimdsame_only
	if(U && opcode==4) return UHSUB_advsimd(ctx, dec); // -> UHSUB_asimdsame_only
	if(U && opcode==5) return UQSUB_advsimd(ctx, dec); // -> UQSUB_asimdsame_only
	if(U && opcode==6) return CMHI_advsimd(ctx, dec); // -> CMHI_asimdsame_only
	if(U && opcode==7) return CMHS_advsimd(ctx, dec); // -> CMHS_asimdsame_only
	if(U && opcode==8) return USHL_advsimd(ctx, dec); // -> USHL_asimdsame_only
	if(U && opcode==9) return UQSHL_advsimd_reg(ctx, dec); // -> UQSHL_asimdsame_only
	if(U && opcode==10) return URSHL_advsimd(ctx, dec); // -> URSHL_asimdsame_only
	if(U && opcode==11) return UQRSHL_advsimd(ctx, dec); // -> UQRSHL_asimdsame_only
	if(U && opcode==12) return UMAX_advsimd(ctx, dec); // -> UMAX_asimdsame_only
	if(U && opcode==13) return UMIN_advsimd(ctx, dec); // -> UMIN_asimdsame_only
	if(U && opcode==14) return UABD_advsimd(ctx, dec); // -> UABD_asimdsame_only
	if(U && opcode==15) return UABA_advsimd(ctx, dec); // -> UABA_asimdsame_only
	if(U && opcode==0x10) return SUB_advsimd(ctx, dec); // -> SUB_asimdsame_only
	if(U && opcode==0x11) return CMEQ_advsimd_reg(ctx, dec); // -> CMEQ_asimdsame_only
	if(U && opcode==0x12) return MLS_advsimd_vec(ctx, dec); // -> MLS_asimdsame_only
	if(U && opcode==0x13) return PMUL_advsimd(ctx, dec); // -> PMUL_asimdsame_only
	if(U && opcode==0x14) return UMAXP_advsimd(ctx, dec); // -> UMAXP_asimdsame_only
	if(U && opcode==0x15) return UMINP_advsimd(ctx, dec); // -> UMINP_asimdsame_only
	if(U && opcode==0x16) return SQRDMULH_advsimd_vec(ctx, dec); // -> SQRDMULH_asimdsame_only
	if(U && opcode==0x17) UNALLOCATED(ENC_UNALLOCATED_64_ASIMDSAME);
	UNMATCHED;
}

int decode_iclass_asimdsamefp16(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, a=(INSWORD>>23)&1, opcode=(INSWORD>>11)&7;
	if(!U && !a && !opcode && HasFP16()) return FMAXNM_advsimd(ctx, dec); // -> FMAXNM_asimdsamefp16_only
	if(!U && !a && opcode==1 && HasFP16()) return FMLA_advsimd_vec(ctx, dec); // -> FMLA_asimdsamefp16_only
	if(!U && !a && opcode==2 && HasFP16()) return FADD_advsimd(ctx, dec); // -> FADD_asimdsamefp16_only
	if(!U && !a && opcode==3 && HasFP16()) return FMULX_advsimd_vec(ctx, dec); // -> FMULX_asimdsamefp16_only
	if(!U && !a && opcode==4 && HasFP16()) return FCMEQ_advsimd_reg(ctx, dec); // -> FCMEQ_asimdsamefp16_only
	if(!U && !a && opcode==5) UNALLOCATED(ENC_UNALLOCATED_31_ASIMDSAMEFP16);
	if(!U && !a && opcode==6 && HasFP16()) return FMAX_advsimd(ctx, dec); // -> FMAX_asimdsamefp16_only
	if(!U && !a && opcode==7 && HasFP16()) return FRECPS_advsimd(ctx, dec); // -> FRECPS_asimdsamefp16_only
	if(!U && a && !opcode && HasFP16()) return FMINNM_advsimd(ctx, dec); // -> FMINNM_asimdsamefp16_only
	if(!U && a && opcode==1 && HasFP16()) return FMLS_advsimd_vec(ctx, dec); // -> FMLS_asimdsamefp16_only
	if(!U && a && opcode==2 && HasFP16()) return FSUB_advsimd(ctx, dec); // -> FSUB_asimdsamefp16_only
	if(!U && a && opcode==3) UNALLOCATED(ENC_UNALLOCATED_25_ASIMDSAMEFP16);
	if(!U && a && opcode==4) UNALLOCATED(ENC_UNALLOCATED_29_ASIMDSAMEFP16);
	if(!U && a && opcode==5) UNALLOCATED(ENC_UNALLOCATED_33_ASIMDSAMEFP16);
	if(!U && a && opcode==6 && HasFP16()) return FMIN_advsimd(ctx, dec); // -> FMIN_asimdsamefp16_only
	if(!U && a && opcode==7 && HasFP16()) return FRSQRTS_advsimd(ctx, dec); // -> FRSQRTS_asimdsamefp16_only
	if(U && !a && !opcode && HasFP16()) return FMAXNMP_advsimd_vec(ctx, dec); // -> FMAXNMP_asimdsamefp16_only
	if(U && !a && opcode==1) UNALLOCATED(ENC_UNALLOCATED_16_ASIMDSAMEFP16);
	if(U && !a && opcode==2 && HasFP16()) return FADDP_advsimd_vec(ctx, dec); // -> FADDP_asimdsamefp16_only
	if(U && !a && opcode==3 && HasFP16()) return FMUL_advsimd_vec(ctx, dec); // -> FMUL_asimdsamefp16_only
	if(U && !a && opcode==4 && HasFP16()) return FCMGE_advsimd_reg(ctx, dec); // -> FCMGE_asimdsamefp16_only
	if(U && !a && opcode==5 && HasFP16()) return FACGE_advsimd(ctx, dec); // -> FACGE_asimdsamefp16_only
	if(U && !a && opcode==6 && HasFP16()) return FMAXP_advsimd_vec(ctx, dec); // -> FMAXP_asimdsamefp16_only
	if(U && !a && opcode==7 && HasFP16()) return FDIV_advsimd(ctx, dec); // -> FDIV_asimdsamefp16_only
	if(U && a && !opcode && HasFP16()) return FMINNMP_advsimd_vec(ctx, dec); // -> FMINNMP_asimdsamefp16_only
	if(U && a && opcode==1) UNALLOCATED(ENC_UNALLOCATED_18_ASIMDSAMEFP16);
	if(U && a && opcode==2 && HasFP16()) return FABD_advsimd(ctx, dec); // -> FABD_asimdsamefp16_only
	if(U && a && opcode==3) UNALLOCATED(ENC_UNALLOCATED_26_ASIMDSAMEFP16);
	if(U && a && opcode==4 && HasFP16()) return FCMGT_advsimd_reg(ctx, dec); // -> FCMGT_asimdsamefp16_only
	if(U && a && opcode==5 && HasFP16()) return FACGT_advsimd(ctx, dec); // -> FACGT_asimdsamefp16_only
	if(U && a && opcode==6 && HasFP16()) return FMINP_advsimd_vec(ctx, dec); // -> FMINP_asimdsamefp16_only
	if(U && a && opcode==7) UNALLOCATED(ENC_UNALLOCATED_42_ASIMDSAMEFP16);
	UNMATCHED;
}

int decode_iclass_asimdsame2(context *ctx, Instruction *dec)
{
	uint32_t Q=(INSWORD>>30)&1, U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>11)&15;
	if(!Q && U && size==1 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_32_ASIMDSAME2);
	if(Q && !U && size==2 && opcode==4 && HasI8MM()) return SMMLA_advsimd_vec(ctx, dec); // -> SMMLA_asimdsame2_G
	if(Q && !U && size==2 && opcode==5 && HasI8MM()) return USMMLA_advsimd_vec(ctx, dec); // -> USMMLA_asimdsame2_G
	if(Q && U && size==1 && opcode==13 && HasBF16()) return BFMMLA_advsimd(ctx, dec); // -> BFMMLA_asimdsame2_E
	if(Q && U && size==2 && opcode==4 && HasI8MM()) return UMMLA_advsimd_vec(ctx, dec); // -> UMMLA_asimdsame2_G
	if(Q && U && size==2 && opcode==5) UNALLOCATED(ENC_UNALLOCATED_26_ASIMDSAME2);
	if(!U && size==2 && opcode==3 && HasI8MM()) return USDOT_advsimd_vec(ctx, dec); // -> USDOT_asimdsame2_D
	if(U && !size && opcode==13) UNALLOCATED(ENC_UNALLOCATED_31_ASIMDSAME2);
	if(U && !size && opcode==15) UNALLOCATED(ENC_UNALLOCATED_35_ASIMDSAME2);
	if(U && size==1 && opcode==15 && HasBF16()) return BFDOT_advsimd_vec(ctx, dec); // -> BFDOT_asimdsame2_D
	if(U && size==2 && opcode==3) UNALLOCATED(ENC_UNALLOCATED_19_ASIMDSAME2);
	if(U && size==2 && opcode==15) UNALLOCATED(ENC_UNALLOCATED_38_ASIMDSAME2);
	if(U && size==3 && opcode==15 && HasBF16()) return BFMLAL_advsimd_vec(ctx, dec); // -> BFMLAL_asimdsame2_F_
	if(size==3 && opcode==3) UNALLOCATED(ENC_UNALLOCATED_20_ASIMDSAME2);
	if(U && (size&2)==2 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_34_ASIMDSAME2);
	if(!(size&2) && opcode==3) UNALLOCATED(ENC_UNALLOCATED_17_ASIMDSAME2);
	if(!U && !opcode) UNALLOCATED(ENC_UNALLOCATED_11_ASIMDSAME2);
	if(!U && opcode==1) UNALLOCATED(ENC_UNALLOCATED_13_ASIMDSAME2);
	if(!U && opcode==2 && HasDotProd()) return SDOT_advsimd_vec(ctx, dec); // -> SDOT_asimdsame2_D
	if(U && !opcode && HasRDMA()) return SQRDMLAH_advsimd_vec(ctx, dec); // -> SQRDMLAH_asimdsame2_only
	if(U && opcode==1 && HasRDMA()) return SQRDMLSH_advsimd_vec(ctx, dec); // -> SQRDMLSH_asimdsame2_only
	if(U && opcode==2 && HasDotProd()) return UDOT_advsimd_vec(ctx, dec); // -> UDOT_asimdsame2_D
	if(Q && (size&2)==2 && (opcode&14)==6) UNALLOCATED(ENC_UNALLOCATED_27_ASIMDSAME2);
	if(U && (opcode&13)==12 && HasCompNum()) return FCADD_advsimd_vec(ctx, dec); // -> FCADD_asimdsame2_C
	if(Q && !(size&2) && (opcode&12)==4) UNALLOCATED(ENC_UNALLOCATED_22_ASIMDSAME2);
	if(U && (opcode&12)==8 && HasCompNum()) return FCMLA_advsimd_vec(ctx, dec); // -> FCMLA_asimdsame2_C
	if(!Q && (opcode&12)==4) UNALLOCATED(ENC_UNALLOCATED_21_ASIMDSAME2);
	if(!U && (opcode&8)==8) UNALLOCATED(ENC_UNALLOCATED_28_ASIMDSAME2);
	UNMATCHED;
}

int decode_iclass_asimdmisc(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!U && size==2 && opcode==0x16 && HasBF16()) return BFCVTN_advsimd(ctx, dec); // -> BFCVTN_asimdmisc_4S
	if(U && !size && opcode==5) return NOT_advsimd(ctx, dec); // -> NOT_asimdmisc_R
	if(U && size==1 && opcode==5) return RBIT_advsimd(ctx, dec); // -> RBIT_asimdmisc_R
	if(U && size==2 && opcode==0x16) UNALLOCATED(ENC_UNALLOCATED_57_ASIMDMISC);
	if(size==3 && opcode==0x16) UNALLOCATED(ENC_UNALLOCATED_58_ASIMDMISC);
	if(!U && !(size&2) && opcode==0x16) return FCVTN_advsimd(ctx, dec); // -> FCVTN_asimdmisc_N
	if(!U && !(size&2) && opcode==0x17) return FCVTL_advsimd(ctx, dec); // -> FCVTL_asimdmisc_L
	if(!U && !(size&2) && opcode==0x18) return FRINTN_advsimd(ctx, dec); // -> FRINTN_asimdmisc_R
	if(!U && !(size&2) && opcode==0x19) return FRINTM_advsimd(ctx, dec); // -> FRINTM_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1a) return FCVTNS_advsimd(ctx, dec); // -> FCVTNS_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1b) return FCVTMS_advsimd(ctx, dec); // -> FCVTMS_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1c) return FCVTAS_advsimd(ctx, dec); // -> FCVTAS_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1d) return SCVTF_advsimd_int(ctx, dec); // -> SCVTF_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1e && HasFRINT()) return FRINT32Z_advsimd(ctx, dec); // -> FRINT32Z_asimdmisc_R
	if(!U && !(size&2) && opcode==0x1f && HasFRINT()) return FRINT64Z_advsimd(ctx, dec); // -> FRINT64Z_asimdmisc_R
	if(!U && (size&2)==2 && opcode==12) return FCMGT_advsimd_zero(ctx, dec); // -> FCMGT_asimdmisc_FZ
	if(!U && (size&2)==2 && opcode==13) return FCMEQ_advsimd_zero(ctx, dec); // -> FCMEQ_asimdmisc_FZ
	if(!U && (size&2)==2 && opcode==14) return FCMLT_advsimd(ctx, dec); // -> FCMLT_asimdmisc_FZ
	if(!U && (size&2)==2 && opcode==15) return FABS_advsimd(ctx, dec); // -> FABS_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x18) return FRINTP_advsimd(ctx, dec); // -> FRINTP_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x19) return FRINTZ_advsimd(ctx, dec); // -> FRINTZ_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1a) return FCVTPS_advsimd(ctx, dec); // -> FCVTPS_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1b) return FCVTZS_advsimd_int(ctx, dec); // -> FCVTZS_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1c) return URECPE_advsimd(ctx, dec); // -> URECPE_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1d) return FRECPE_advsimd(ctx, dec); // -> FRECPE_asimdmisc_R
	if(!U && (size&2)==2 && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_91_ASIMDMISC);
	if(U && !(size&2) && opcode==0x16) return FCVTXN_advsimd(ctx, dec); // -> FCVTXN_asimdmisc_N
	if(U && !(size&2) && opcode==0x17) UNALLOCATED(ENC_UNALLOCATED_60_ASIMDMISC);
	if(U && !(size&2) && opcode==0x18) return FRINTA_advsimd(ctx, dec); // -> FRINTA_asimdmisc_R
	if(U && !(size&2) && opcode==0x19) return FRINTX_advsimd(ctx, dec); // -> FRINTX_asimdmisc_R
	if(U && !(size&2) && opcode==0x1a) return FCVTNU_advsimd(ctx, dec); // -> FCVTNU_asimdmisc_R
	if(U && !(size&2) && opcode==0x1b) return FCVTMU_advsimd(ctx, dec); // -> FCVTMU_asimdmisc_R
	if(U && !(size&2) && opcode==0x1c) return FCVTAU_advsimd(ctx, dec); // -> FCVTAU_asimdmisc_R
	if(U && !(size&2) && opcode==0x1d) return UCVTF_advsimd_int(ctx, dec); // -> UCVTF_asimdmisc_R
	if(U && !(size&2) && opcode==0x1e && HasFRINT()) return FRINT32X_advsimd(ctx, dec); // -> FRINT32X_asimdmisc_R
	if(U && !(size&2) && opcode==0x1f && HasFRINT()) return FRINT64X_advsimd(ctx, dec); // -> FRINT64X_asimdmisc_R
	if(U && (size&2)==2 && opcode==5) UNALLOCATED(ENC_UNALLOCATED_24_ASIMDMISC);
	if(U && (size&2)==2 && opcode==12) return FCMGE_advsimd_zero(ctx, dec); // -> FCMGE_asimdmisc_FZ
	if(U && (size&2)==2 && opcode==13) return FCMLE_advsimd(ctx, dec); // -> FCMLE_asimdmisc_FZ
	if(U && (size&2)==2 && opcode==14) UNALLOCATED(ENC_UNALLOCATED_43_ASIMDMISC);
	if(U && (size&2)==2 && opcode==15) return FNEG_advsimd(ctx, dec); // -> FNEG_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x18) UNALLOCATED(ENC_UNALLOCATED_65_ASIMDMISC);
	if(U && (size&2)==2 && opcode==0x19) return FRINTI_advsimd(ctx, dec); // -> FRINTI_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1a) return FCVTPU_advsimd(ctx, dec); // -> FCVTPU_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1b) return FCVTZU_advsimd_int(ctx, dec); // -> FCVTZU_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1c) return URSQRTE_advsimd(ctx, dec); // -> URSQRTE_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1d) return FRSQRTE_advsimd(ctx, dec); // -> FRSQRTE_asimdmisc_R
	if(U && (size&2)==2 && opcode==0x1f) return FSQRT_advsimd(ctx, dec); // -> FSQRT_asimdmisc_R
	if((size&2)==2 && opcode==0x17) UNALLOCATED(ENC_UNALLOCATED_61_ASIMDMISC);
	if((size&2)==2 && opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_88_ASIMDMISC);
	if(!U && !opcode) return REV64_advsimd(ctx, dec); // -> REV64_asimdmisc_R
	if(!U && opcode==1) return REV16_advsimd(ctx, dec); // -> REV16_asimdmisc_R
	if(!U && opcode==2) return SADDLP_advsimd(ctx, dec); // -> SADDLP_asimdmisc_P
	if(!U && opcode==3) return SUQADD_advsimd(ctx, dec); // -> SUQADD_asimdmisc_R
	if(!U && opcode==4) return CLS_advsimd(ctx, dec); // -> CLS_asimdmisc_R
	if(!U && opcode==5) return CNT_advsimd(ctx, dec); // -> CNT_asimdmisc_R
	if(!U && opcode==6) return SADALP_advsimd(ctx, dec); // -> SADALP_asimdmisc_P
	if(!U && opcode==7) return SQABS_advsimd(ctx, dec); // -> SQABS_asimdmisc_R
	if(!U && opcode==8) return CMGT_advsimd_zero(ctx, dec); // -> CMGT_asimdmisc_Z
	if(!U && opcode==9) return CMEQ_advsimd_zero(ctx, dec); // -> CMEQ_asimdmisc_Z
	if(!U && opcode==10) return CMLT_advsimd(ctx, dec); // -> CMLT_asimdmisc_Z
	if(!U && opcode==11) return ABS_advsimd(ctx, dec); // -> ABS_asimdmisc_R
	if(!U && opcode==0x12) return XTN_advsimd(ctx, dec); // -> XTN_asimdmisc_N
	if(!U && opcode==0x13) UNALLOCATED(ENC_UNALLOCATED_49_ASIMDMISC);
	if(!U && opcode==0x14) return SQXTN_advsimd(ctx, dec); // -> SQXTN_asimdmisc_N
	if(U && !opcode) return REV32_advsimd(ctx, dec); // -> REV32_asimdmisc_R
	if(U && opcode==1) UNALLOCATED(ENC_UNALLOCATED_14_ASIMDMISC);
	if(U && opcode==2) return UADDLP_advsimd(ctx, dec); // -> UADDLP_asimdmisc_P
	if(U && opcode==3) return USQADD_advsimd(ctx, dec); // -> USQADD_asimdmisc_R
	if(U && opcode==4) return CLZ_advsimd(ctx, dec); // -> CLZ_asimdmisc_R
	if(U && opcode==6) return UADALP_advsimd(ctx, dec); // -> UADALP_asimdmisc_P
	if(U && opcode==7) return SQNEG_advsimd(ctx, dec); // -> SQNEG_asimdmisc_R
	if(U && opcode==8) return CMGE_advsimd_zero(ctx, dec); // -> CMGE_asimdmisc_Z
	if(U && opcode==9) return CMLE_advsimd(ctx, dec); // -> CMLE_asimdmisc_Z
	if(U && opcode==10) UNALLOCATED(ENC_UNALLOCATED_34_ASIMDMISC);
	if(U && opcode==11) return NEG_advsimd(ctx, dec); // -> NEG_asimdmisc_R
	if(U && opcode==0x12) return SQXTUN_advsimd(ctx, dec); // -> SQXTUN_asimdmisc_N
	if(U && opcode==0x13) return SHLL_advsimd(ctx, dec); // -> SHLL_asimdmisc_S
	if(U && opcode==0x14) return UQXTN_advsimd(ctx, dec); // -> UQXTN_asimdmisc_N
	if(opcode==0x15) UNALLOCATED(ENC_UNALLOCATED_53_ASIMDMISC);
	if((opcode&0x1e)==0x10) UNALLOCATED(ENC_UNALLOCATED_46_ASIMDMISC);
	if(!(size&2) && (opcode&0x1c)==12) UNALLOCATED(ENC_UNALLOCATED_37_ASIMDMISC);
	UNMATCHED;
}

int decode_iclass_asimdmiscfp16(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, a=(INSWORD>>23)&1, opcode=(INSWORD>>12)&0x1f;
	if(!U && !a && opcode==0x18 && HasFP16()) return FRINTN_advsimd(ctx, dec); // -> FRINTN_asimdmiscfp16_R
	if(!U && !a && opcode==0x19 && HasFP16()) return FRINTM_advsimd(ctx, dec); // -> FRINTM_asimdmiscfp16_R
	if(!U && !a && opcode==0x1a && HasFP16()) return FCVTNS_advsimd(ctx, dec); // -> FCVTNS_asimdmiscfp16_R
	if(!U && !a && opcode==0x1b && HasFP16()) return FCVTMS_advsimd(ctx, dec); // -> FCVTMS_asimdmiscfp16_R
	if(!U && !a && opcode==0x1c && HasFP16()) return FCVTAS_advsimd(ctx, dec); // -> FCVTAS_asimdmiscfp16_R
	if(!U && !a && opcode==0x1d && HasFP16()) return SCVTF_advsimd_int(ctx, dec); // -> SCVTF_asimdmiscfp16_R
	if(!U && a && opcode==12 && HasFP16()) return FCMGT_advsimd_zero(ctx, dec); // -> FCMGT_asimdmiscfp16_FZ
	if(!U && a && opcode==13 && HasFP16()) return FCMEQ_advsimd_zero(ctx, dec); // -> FCMEQ_asimdmiscfp16_FZ
	if(!U && a && opcode==14 && HasFP16()) return FCMLT_advsimd(ctx, dec); // -> FCMLT_asimdmiscfp16_FZ
	if(!U && a && opcode==15 && HasFP16()) return FABS_advsimd(ctx, dec); // -> FABS_asimdmiscfp16_R
	if(!U && a && opcode==0x18 && HasFP16()) return FRINTP_advsimd(ctx, dec); // -> FRINTP_asimdmiscfp16_R
	if(!U && a && opcode==0x19 && HasFP16()) return FRINTZ_advsimd(ctx, dec); // -> FRINTZ_asimdmiscfp16_R
	if(!U && a && opcode==0x1a && HasFP16()) return FCVTPS_advsimd(ctx, dec); // -> FCVTPS_asimdmiscfp16_R
	if(!U && a && opcode==0x1b && HasFP16()) return FCVTZS_advsimd_int(ctx, dec); // -> FCVTZS_asimdmiscfp16_R
	if(!U && a && opcode==0x1d && HasFP16()) return FRECPE_advsimd(ctx, dec); // -> FRECPE_asimdmiscfp16_R
	if(!U && a && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_48_ASIMDMISCFP16);
	if(U && !a && opcode==0x18 && HasFP16()) return FRINTA_advsimd(ctx, dec); // -> FRINTA_asimdmiscfp16_R
	if(U && !a && opcode==0x19 && HasFP16()) return FRINTX_advsimd(ctx, dec); // -> FRINTX_asimdmiscfp16_R
	if(U && !a && opcode==0x1a && HasFP16()) return FCVTNU_advsimd(ctx, dec); // -> FCVTNU_asimdmiscfp16_R
	if(U && !a && opcode==0x1b && HasFP16()) return FCVTMU_advsimd(ctx, dec); // -> FCVTMU_asimdmiscfp16_R
	if(U && !a && opcode==0x1c && HasFP16()) return FCVTAU_advsimd(ctx, dec); // -> FCVTAU_asimdmiscfp16_R
	if(U && !a && opcode==0x1d && HasFP16()) return UCVTF_advsimd_int(ctx, dec); // -> UCVTF_asimdmiscfp16_R
	if(U && a && opcode==12 && HasFP16()) return FCMGE_advsimd_zero(ctx, dec); // -> FCMGE_asimdmiscfp16_FZ
	if(U && a && opcode==13 && HasFP16()) return FCMLE_advsimd(ctx, dec); // -> FCMLE_asimdmiscfp16_FZ
	if(U && a && opcode==14) UNALLOCATED(ENC_UNALLOCATED_19_ASIMDMISCFP16);
	if(U && a && opcode==15 && HasFP16()) return FNEG_advsimd(ctx, dec); // -> FNEG_asimdmiscfp16_R
	if(U && a && opcode==0x18) UNALLOCATED(ENC_UNALLOCATED_26_ASIMDMISCFP16);
	if(U && a && opcode==0x19 && HasFP16()) return FRINTI_advsimd(ctx, dec); // -> FRINTI_asimdmiscfp16_R
	if(U && a && opcode==0x1a && HasFP16()) return FCVTPU_advsimd(ctx, dec); // -> FCVTPU_asimdmiscfp16_R
	if(U && a && opcode==0x1b && HasFP16()) return FCVTZU_advsimd_int(ctx, dec); // -> FCVTZU_asimdmiscfp16_R
	if(U && a && opcode==0x1d && HasFP16()) return FRSQRTE_advsimd(ctx, dec); // -> FRSQRTE_asimdmiscfp16_R
	if(U && a && opcode==0x1f && HasFP16()) return FSQRT_advsimd(ctx, dec); // -> FSQRT_asimdmiscfp16_R
	if(!a && opcode==0x1f) UNALLOCATED(ENC_UNALLOCATED_47_ASIMDMISCFP16);
	if(a && opcode==0x1c) UNALLOCATED(ENC_UNALLOCATED_41_ASIMDMISCFP16);
	if(opcode==0x1e) UNALLOCATED(ENC_UNALLOCATED_46_ASIMDMISCFP16);
	if(!a && (opcode&0x1c)==12) UNALLOCATED(ENC_UNALLOCATED_13_ASIMDMISCFP16);
	if((opcode&0x1c)==8) UNALLOCATED(ENC_UNALLOCATED_12_ASIMDMISCFP16);
	if(!(opcode&0x18)) UNALLOCATED(ENC_UNALLOCATED_11_ASIMDMISCFP16);
	if((opcode&0x18)==0x10) UNALLOCATED(ENC_UNALLOCATED_22_ASIMDMISCFP16);
	UNMATCHED;
}

int decode_iclass_asimdelem(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>29)&1, size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&15;
	if(!U && !size && opcode==1 && HasFP16()) return FMLA_advsimd_elt(ctx, dec); // -> FMLA_asimdelem_RH_H
	if(!U && !size && opcode==5 && HasFP16()) return FMLS_advsimd_elt(ctx, dec); // -> FMLS_asimdelem_RH_H
	if(!U && !size && opcode==9 && HasFP16()) return FMUL_advsimd_elt(ctx, dec); // -> FMUL_asimdelem_RH_H
	if(!U && !size && opcode==15 && HasI8MM()) return SUDOT_advsimd_elt(ctx, dec); // -> SUDOT_asimdelem_D
	if(!U && size==1 && opcode==1) UNALLOCATED(ENC_UNALLOCATED_17_ASIMDELEM);
	if(!U && size==1 && opcode==5) UNALLOCATED(ENC_UNALLOCATED_33_ASIMDELEM);
	if(!U && size==1 && opcode==15 && HasBF16()) return BFDOT_advsimd_elt(ctx, dec); // -> BFDOT_asimdelem_E
	if(!U && size==2 && !opcode && HasFHM()) return FMLAL_advsimd_elt(ctx, dec); // -> FMLAL_asimdelem_LH
	if(!U && size==2 && opcode==4 && HasFHM()) return FMLSL_advsimd_elt(ctx, dec); // -> FMLSL_asimdelem_LH
	if(!U && size==2 && opcode==15 && HasI8MM()) return USDOT_advsimd_elt(ctx, dec); // -> USDOT_asimdelem_D
	if(!U && size==3 && !opcode) UNALLOCATED(ENC_UNALLOCATED_13_ASIMDELEM);
	if(!U && size==3 && opcode==4) UNALLOCATED(ENC_UNALLOCATED_29_ASIMDELEM);
	if(!U && size==3 && opcode==15 && HasBF16()) return BFMLAL_advsimd_elt(ctx, dec); // -> BFMLAL_asimdelem_F
	if(U && !size && opcode==1) UNALLOCATED(ENC_UNALLOCATED_16_ASIMDELEM);
	if(U && !size && opcode==3) UNALLOCATED(ENC_UNALLOCATED_25_ASIMDELEM);
	if(U && !size && opcode==5) UNALLOCATED(ENC_UNALLOCATED_32_ASIMDELEM);
	if(U && !size && opcode==7) UNALLOCATED(ENC_UNALLOCATED_39_ASIMDELEM);
	if(U && !size && opcode==9 && HasFP16()) return FMULX_advsimd_elt(ctx, dec); // -> FMULX_asimdelem_RH_H
	if(U && size==2 && opcode==8 && HasFHM()) return FMLAL_advsimd_elt(ctx, dec); // -> FMLAL2_asimdelem_LH
	if(U && size==2 && opcode==12 && HasFHM()) return FMLSL_advsimd_elt(ctx, dec); // -> FMLSL2_asimdelem_LH
	if(U && size==3 && opcode==1) RESERVED(ENC_RESERVED_21_ASIMDELEM);
	if(U && size==3 && opcode==3) UNALLOCATED(ENC_UNALLOCATED_26_ASIMDELEM);
	if(U && size==3 && opcode==5) RESERVED(ENC_RESERVED_35_ASIMDELEM);
	if(U && size==3 && opcode==7) UNALLOCATED(ENC_UNALLOCATED_40_ASIMDELEM);
	if(U && size==3 && opcode==8) UNALLOCATED(ENC_UNALLOCATED_44_ASIMDELEM);
	if(U && size==3 && opcode==12) UNALLOCATED(ENC_UNALLOCATED_57_ASIMDELEM);
	if(size==1 && opcode==9) UNALLOCATED(ENC_UNALLOCATED_47_ASIMDELEM);
	if(!U && !(size&2) && !opcode) UNALLOCATED(ENC_UNALLOCATED_11_ASIMDELEM);
	if(!U && !(size&2) && opcode==4) UNALLOCATED(ENC_UNALLOCATED_27_ASIMDELEM);
	if(!U && (size&2)==2 && opcode==1) return FMLA_advsimd_elt(ctx, dec); // -> FMLA_asimdelem_R_SD
	if(!U && (size&2)==2 && opcode==5) return FMLS_advsimd_elt(ctx, dec); // -> FMLS_asimdelem_R_SD
	if(!U && (size&2)==2 && opcode==9) return FMUL_advsimd_elt(ctx, dec); // -> FMUL_asimdelem_R_SD
	if(U && !(size&2) && opcode==8) UNALLOCATED(ENC_UNALLOCATED_42_ASIMDELEM);
	if(U && !(size&2) && opcode==12) UNALLOCATED(ENC_UNALLOCATED_55_ASIMDELEM);
	if(U && (size&2)==2 && opcode==9) return FMULX_advsimd_elt(ctx, dec); // -> FMULX_asimdelem_R_SD
	if(!U && opcode==2) return SMLAL_advsimd_elt(ctx, dec); // -> SMLAL_asimdelem_L
	if(!U && opcode==3) return SQDMLAL_advsimd_elt(ctx, dec); // -> SQDMLAL_asimdelem_L
	if(!U && opcode==6) return SMLSL_advsimd_elt(ctx, dec); // -> SMLSL_asimdelem_L
	if(!U && opcode==7) return SQDMLSL_advsimd_elt(ctx, dec); // -> SQDMLSL_asimdelem_L
	if(!U && opcode==8) return MUL_advsimd_elt(ctx, dec); // -> MUL_asimdelem_R
	if(!U && opcode==10) return SMULL_advsimd_elt(ctx, dec); // -> SMULL_asimdelem_L
	if(!U && opcode==11) return SQDMULL_advsimd_elt(ctx, dec); // -> SQDMULL_asimdelem_L
	if(!U && opcode==12) return SQDMULH_advsimd_elt(ctx, dec); // -> SQDMULH_asimdelem_R
	if(!U && opcode==13) return SQRDMULH_advsimd_elt(ctx, dec); // -> SQRDMULH_asimdelem_R
	if(!U && opcode==14 && HasDotProd()) return SDOT_advsimd_elt(ctx, dec); // -> SDOT_asimdelem_D
	if(U && !opcode) return MLA_advsimd_elt(ctx, dec); // -> MLA_asimdelem_R
	if(U && opcode==2) return UMLAL_advsimd_elt(ctx, dec); // -> UMLAL_asimdelem_L
	if(U && opcode==4) return MLS_advsimd_elt(ctx, dec); // -> MLS_asimdelem_R
	if(U && opcode==6) return UMLSL_advsimd_elt(ctx, dec); // -> UMLSL_asimdelem_L
	if(U && opcode==10) return UMULL_advsimd_elt(ctx, dec); // -> UMULL_asimdelem_L
	if(U && opcode==11) UNALLOCATED(ENC_UNALLOCATED_53_ASIMDELEM);
	if(U && opcode==13 && HasRDMA()) return SQRDMLAH_advsimd_elt(ctx, dec); // -> SQRDMLAH_asimdelem_R
	if(U && opcode==14 && HasDotProd()) return UDOT_advsimd_elt(ctx, dec); // -> UDOT_asimdelem_D
	if(U && opcode==15 && HasRDMA()) return SQRDMLSH_advsimd_elt(ctx, dec); // -> SQRDMLSH_asimdelem_R
	if(U && size==1 && (opcode&9)==1 && HasCompNum()) return FCMLA_advsimd_elt(ctx, dec); // -> FCMLA_asimdelem_C_H
	if(U && size==2 && (opcode&9)==1 && HasCompNum()) return FCMLA_advsimd_elt(ctx, dec); // -> FCMLA_asimdelem_C_S
	UNMATCHED;
}

int decode_iclass_float2fix(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3, rmode=(INSWORD>>19)&3, opcode=(INSWORD>>16)&7, scale=(INSWORD>>10)&0x3f;
	if(!sf && !S && !ptype && !rmode && opcode==2) return SCVTF_float_fix(ctx, dec); // -> SCVTF_S32_float2fix
	if(!sf && !S && !ptype && !rmode && opcode==3) return UCVTF_float_fix(ctx, dec); // -> UCVTF_S32_float2fix
	if(!sf && !S && !ptype && rmode==3 && !opcode) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_32S_float2fix
	if(!sf && !S && !ptype && rmode==3 && opcode==1) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_32S_float2fix
	if(!sf && !S && ptype==1 && !rmode && opcode==2) return SCVTF_float_fix(ctx, dec); // -> SCVTF_D32_float2fix
	if(!sf && !S && ptype==1 && !rmode && opcode==3) return UCVTF_float_fix(ctx, dec); // -> UCVTF_D32_float2fix
	if(!sf && !S && ptype==1 && rmode==3 && !opcode) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_32D_float2fix
	if(!sf && !S && ptype==1 && rmode==3 && opcode==1) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_32D_float2fix
	if(!sf && !S && ptype==3 && !rmode && opcode==2 && HasFP16()) return SCVTF_float_fix(ctx, dec); // -> SCVTF_H32_float2fix
	if(!sf && !S && ptype==3 && !rmode && opcode==3 && HasFP16()) return UCVTF_float_fix(ctx, dec); // -> UCVTF_H32_float2fix
	if(!sf && !S && ptype==3 && rmode==3 && !opcode && HasFP16()) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_32H_float2fix
	if(!sf && !S && ptype==3 && rmode==3 && opcode==1 && HasFP16()) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_32H_float2fix
	if(sf && !S && !ptype && !rmode && opcode==2) return SCVTF_float_fix(ctx, dec); // -> SCVTF_S64_float2fix
	if(sf && !S && !ptype && !rmode && opcode==3) return UCVTF_float_fix(ctx, dec); // -> UCVTF_S64_float2fix
	if(sf && !S && !ptype && rmode==3 && !opcode) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_64S_float2fix
	if(sf && !S && !ptype && rmode==3 && opcode==1) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_64S_float2fix
	if(sf && !S && ptype==1 && !rmode && opcode==2) return SCVTF_float_fix(ctx, dec); // -> SCVTF_D64_float2fix
	if(sf && !S && ptype==1 && !rmode && opcode==3) return UCVTF_float_fix(ctx, dec); // -> UCVTF_D64_float2fix
	if(sf && !S && ptype==1 && rmode==3 && !opcode) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_64D_float2fix
	if(sf && !S && ptype==1 && rmode==3 && opcode==1) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_64D_float2fix
	if(sf && !S && ptype==3 && !rmode && opcode==2 && HasFP16()) return SCVTF_float_fix(ctx, dec); // -> SCVTF_H64_float2fix
	if(sf && !S && ptype==3 && !rmode && opcode==3 && HasFP16()) return UCVTF_float_fix(ctx, dec); // -> UCVTF_H64_float2fix
	if(sf && !S && ptype==3 && rmode==3 && !opcode && HasFP16()) return FCVTZS_float_fix(ctx, dec); // -> FCVTZS_64H_float2fix
	if(sf && !S && ptype==3 && rmode==3 && opcode==1 && HasFP16()) return FCVTZU_float_fix(ctx, dec); // -> FCVTZU_64H_float2fix
	if(!(rmode&1) && !(opcode&6)) UNALLOCATED(ENC_UNALLOCATED_13_FLOAT2FIX);
	if(rmode&1 && (opcode&6)==2) UNALLOCATED(ENC_UNALLOCATED_15_FLOAT2FIX);
	if(!(rmode&2) && !(opcode&6)) UNALLOCATED(ENC_UNALLOCATED_14_FLOAT2FIX);
	if((rmode&2)==2 && (opcode&6)==2) UNALLOCATED(ENC_UNALLOCATED_16_FLOAT2FIX);
	if(ptype==2) UNALLOCATED(ENC_UNALLOCATED_11_FLOAT2FIX);
	if(!sf && !(scale&0x20)) UNALLOCATED(ENC_UNALLOCATED_12_FLOAT2FIX);
	if((opcode&4)==4) UNALLOCATED(ENC_UNALLOCATED_17_FLOAT2FIX);
	if(S) UNALLOCATED(ENC_UNALLOCATED_10_FLOAT2FIX);
	UNMATCHED;
}

int decode_iclass_float2int(context *ctx, Instruction *dec)
{
	uint32_t sf=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3, rmode=(INSWORD>>19)&3, opcode=(INSWORD>>16)&7;
	if(!sf && !S && !ptype && !rmode && !opcode) return FCVTNS_float(ctx, dec); // -> FCVTNS_32S_float2int
	if(!sf && !S && !ptype && !rmode && opcode==1) return FCVTNU_float(ctx, dec); // -> FCVTNU_32S_float2int
	if(!sf && !S && !ptype && !rmode && opcode==2) return SCVTF_float_int(ctx, dec); // -> SCVTF_S32_float2int
	if(!sf && !S && !ptype && !rmode && opcode==3) return UCVTF_float_int(ctx, dec); // -> UCVTF_S32_float2int
	if(!sf && !S && !ptype && !rmode && opcode==4) return FCVTAS_float(ctx, dec); // -> FCVTAS_32S_float2int
	if(!sf && !S && !ptype && !rmode && opcode==5) return FCVTAU_float(ctx, dec); // -> FCVTAU_32S_float2int
	if(!sf && !S && !ptype && !rmode && opcode==6) return FMOV_float_gen(ctx, dec); // -> FMOV_32S_float2int
	if(!sf && !S && !ptype && !rmode && opcode==7) return FMOV_float_gen(ctx, dec); // -> FMOV_S32_float2int
	if(!sf && !S && !ptype && rmode==1 && !opcode) return FCVTPS_float(ctx, dec); // -> FCVTPS_32S_float2int
	if(!sf && !S && !ptype && rmode==1 && opcode==1) return FCVTPU_float(ctx, dec); // -> FCVTPU_32S_float2int
	if(!sf && !S && !ptype && rmode==2 && !opcode) return FCVTMS_float(ctx, dec); // -> FCVTMS_32S_float2int
	if(!sf && !S && !ptype && rmode==2 && opcode==1) return FCVTMU_float(ctx, dec); // -> FCVTMU_32S_float2int
	if(!sf && !S && !ptype && rmode==3 && !opcode) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_32S_float2int
	if(!sf && !S && !ptype && rmode==3 && opcode==1) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_32S_float2int
	if(!sf && !S && ptype==1 && !rmode && !opcode) return FCVTNS_float(ctx, dec); // -> FCVTNS_32D_float2int
	if(!sf && !S && ptype==1 && !rmode && opcode==1) return FCVTNU_float(ctx, dec); // -> FCVTNU_32D_float2int
	if(!sf && !S && ptype==1 && !rmode && opcode==2) return SCVTF_float_int(ctx, dec); // -> SCVTF_D32_float2int
	if(!sf && !S && ptype==1 && !rmode && opcode==3) return UCVTF_float_int(ctx, dec); // -> UCVTF_D32_float2int
	if(!sf && !S && ptype==1 && !rmode && opcode==4) return FCVTAS_float(ctx, dec); // -> FCVTAS_32D_float2int
	if(!sf && !S && ptype==1 && !rmode && opcode==5) return FCVTAU_float(ctx, dec); // -> FCVTAU_32D_float2int
	if(!sf && !S && ptype==1 && rmode==1 && !opcode) return FCVTPS_float(ctx, dec); // -> FCVTPS_32D_float2int
	if(!sf && !S && ptype==1 && rmode==1 && opcode==1) return FCVTPU_float(ctx, dec); // -> FCVTPU_32D_float2int
	if(!sf && !S && ptype==1 && rmode==2 && !opcode) return FCVTMS_float(ctx, dec); // -> FCVTMS_32D_float2int
	if(!sf && !S && ptype==1 && rmode==2 && opcode==1) return FCVTMU_float(ctx, dec); // -> FCVTMU_32D_float2int
	if(!sf && !S && ptype==1 && rmode==3 && !opcode) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_32D_float2int
	if(!sf && !S && ptype==1 && rmode==3 && opcode==1) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_32D_float2int
	if(!sf && !S && ptype==1 && rmode==3 && opcode==6 && HasJConv()) return FJCVTZS(ctx, dec); // -> FJCVTZS_32D_float2int
	if(!sf && !S && ptype==1 && rmode==3 && opcode==7) UNALLOCATED(ENC_UNALLOCATED_71_FLOAT2INT);
	if(!sf && !S && ptype==3 && !rmode && !opcode && HasFP16()) return FCVTNS_float(ctx, dec); // -> FCVTNS_32H_float2int
	if(!sf && !S && ptype==3 && !rmode && opcode==1 && HasFP16()) return FCVTNU_float(ctx, dec); // -> FCVTNU_32H_float2int
	if(!sf && !S && ptype==3 && !rmode && opcode==2 && HasFP16()) return SCVTF_float_int(ctx, dec); // -> SCVTF_H32_float2int
	if(!sf && !S && ptype==3 && !rmode && opcode==3 && HasFP16()) return UCVTF_float_int(ctx, dec); // -> UCVTF_H32_float2int
	if(!sf && !S && ptype==3 && !rmode && opcode==4 && HasFP16()) return FCVTAS_float(ctx, dec); // -> FCVTAS_32H_float2int
	if(!sf && !S && ptype==3 && !rmode && opcode==5 && HasFP16()) return FCVTAU_float(ctx, dec); // -> FCVTAU_32H_float2int
	if(!sf && !S && ptype==3 && !rmode && opcode==6 && HasFP16()) return FMOV_float_gen(ctx, dec); // -> FMOV_32H_float2int
	if(!sf && !S && ptype==3 && !rmode && opcode==7 && HasFP16()) return FMOV_float_gen(ctx, dec); // -> FMOV_H32_float2int
	if(!sf && !S && ptype==3 && rmode==1 && !opcode && HasFP16()) return FCVTPS_float(ctx, dec); // -> FCVTPS_32H_float2int
	if(!sf && !S && ptype==3 && rmode==1 && opcode==1 && HasFP16()) return FCVTPU_float(ctx, dec); // -> FCVTPU_32H_float2int
	if(!sf && !S && ptype==3 && rmode==2 && !opcode && HasFP16()) return FCVTMS_float(ctx, dec); // -> FCVTMS_32H_float2int
	if(!sf && !S && ptype==3 && rmode==2 && opcode==1 && HasFP16()) return FCVTMU_float(ctx, dec); // -> FCVTMU_32H_float2int
	if(!sf && !S && ptype==3 && rmode==3 && !opcode && HasFP16()) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_32H_float2int
	if(!sf && !S && ptype==3 && rmode==3 && opcode==1 && HasFP16()) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_32H_float2int
	if(sf && !S && !ptype && !rmode && !opcode) return FCVTNS_float(ctx, dec); // -> FCVTNS_64S_float2int
	if(sf && !S && !ptype && !rmode && opcode==1) return FCVTNU_float(ctx, dec); // -> FCVTNU_64S_float2int
	if(sf && !S && !ptype && !rmode && opcode==2) return SCVTF_float_int(ctx, dec); // -> SCVTF_S64_float2int
	if(sf && !S && !ptype && !rmode && opcode==3) return UCVTF_float_int(ctx, dec); // -> UCVTF_S64_float2int
	if(sf && !S && !ptype && !rmode && opcode==4) return FCVTAS_float(ctx, dec); // -> FCVTAS_64S_float2int
	if(sf && !S && !ptype && !rmode && opcode==5) return FCVTAU_float(ctx, dec); // -> FCVTAU_64S_float2int
	if(sf && !S && !ptype && rmode==1 && !opcode) return FCVTPS_float(ctx, dec); // -> FCVTPS_64S_float2int
	if(sf && !S && !ptype && rmode==1 && opcode==1) return FCVTPU_float(ctx, dec); // -> FCVTPU_64S_float2int
	if(sf && !S && !ptype && rmode==2 && !opcode) return FCVTMS_float(ctx, dec); // -> FCVTMS_64S_float2int
	if(sf && !S && !ptype && rmode==2 && opcode==1) return FCVTMU_float(ctx, dec); // -> FCVTMU_64S_float2int
	if(sf && !S && !ptype && rmode==3 && !opcode) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_64S_float2int
	if(sf && !S && !ptype && rmode==3 && opcode==1) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_64S_float2int
	if(sf && !S && ptype==1 && !rmode && !opcode) return FCVTNS_float(ctx, dec); // -> FCVTNS_64D_float2int
	if(sf && !S && ptype==1 && !rmode && opcode==1) return FCVTNU_float(ctx, dec); // -> FCVTNU_64D_float2int
	if(sf && !S && ptype==1 && !rmode && opcode==2) return SCVTF_float_int(ctx, dec); // -> SCVTF_D64_float2int
	if(sf && !S && ptype==1 && !rmode && opcode==3) return UCVTF_float_int(ctx, dec); // -> UCVTF_D64_float2int
	if(sf && !S && ptype==1 && !rmode && opcode==4) return FCVTAS_float(ctx, dec); // -> FCVTAS_64D_float2int
	if(sf && !S && ptype==1 && !rmode && opcode==5) return FCVTAU_float(ctx, dec); // -> FCVTAU_64D_float2int
	if(sf && !S && ptype==1 && !rmode && opcode==6) return FMOV_float_gen(ctx, dec); // -> FMOV_64D_float2int
	if(sf && !S && ptype==1 && !rmode && opcode==7) return FMOV_float_gen(ctx, dec); // -> FMOV_D64_float2int
	if(sf && !S && ptype==1 && rmode==1 && !opcode) return FCVTPS_float(ctx, dec); // -> FCVTPS_64D_float2int
	if(sf && !S && ptype==1 && rmode==1 && opcode==1) return FCVTPU_float(ctx, dec); // -> FCVTPU_64D_float2int
	if(sf && !S && ptype==1 && rmode==2 && !opcode) return FCVTMS_float(ctx, dec); // -> FCVTMS_64D_float2int
	if(sf && !S && ptype==1 && rmode==2 && opcode==1) return FCVTMU_float(ctx, dec); // -> FCVTMU_64D_float2int
	if(sf && !S && ptype==1 && rmode==3 && !opcode) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_64D_float2int
	if(sf && !S && ptype==1 && rmode==3 && opcode==1) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_64D_float2int
	if(sf && !S && ptype==2 && rmode==1 && opcode==6) return FMOV_float_gen(ctx, dec); // -> FMOV_64VX_float2int
	if(sf && !S && ptype==2 && rmode==1 && opcode==7) return FMOV_float_gen(ctx, dec); // -> FMOV_V64I_float2int
	if(sf && !S && ptype==3 && !rmode && !opcode && HasFP16()) return FCVTNS_float(ctx, dec); // -> FCVTNS_64H_float2int
	if(sf && !S && ptype==3 && !rmode && opcode==1 && HasFP16()) return FCVTNU_float(ctx, dec); // -> FCVTNU_64H_float2int
	if(sf && !S && ptype==3 && !rmode && opcode==2 && HasFP16()) return SCVTF_float_int(ctx, dec); // -> SCVTF_H64_float2int
	if(sf && !S && ptype==3 && !rmode && opcode==3 && HasFP16()) return UCVTF_float_int(ctx, dec); // -> UCVTF_H64_float2int
	if(sf && !S && ptype==3 && !rmode && opcode==4 && HasFP16()) return FCVTAS_float(ctx, dec); // -> FCVTAS_64H_float2int
	if(sf && !S && ptype==3 && !rmode && opcode==5 && HasFP16()) return FCVTAU_float(ctx, dec); // -> FCVTAU_64H_float2int
	if(sf && !S && ptype==3 && !rmode && opcode==6 && HasFP16()) return FMOV_float_gen(ctx, dec); // -> FMOV_64H_float2int
	if(sf && !S && ptype==3 && !rmode && opcode==7 && HasFP16()) return FMOV_float_gen(ctx, dec); // -> FMOV_H64_float2int
	if(sf && !S && ptype==3 && rmode==1 && !opcode && HasFP16()) return FCVTPS_float(ctx, dec); // -> FCVTPS_64H_float2int
	if(sf && !S && ptype==3 && rmode==1 && opcode==1 && HasFP16()) return FCVTPU_float(ctx, dec); // -> FCVTPU_64H_float2int
	if(sf && !S && ptype==3 && rmode==2 && !opcode && HasFP16()) return FCVTMS_float(ctx, dec); // -> FCVTMS_64H_float2int
	if(sf && !S && ptype==3 && rmode==2 && opcode==1 && HasFP16()) return FCVTMU_float(ctx, dec); // -> FCVTMU_64H_float2int
	if(sf && !S && ptype==3 && rmode==3 && !opcode && HasFP16()) return FCVTZS_float_int(ctx, dec); // -> FCVTZS_64H_float2int
	if(sf && !S && ptype==3 && rmode==3 && opcode==1 && HasFP16()) return FCVTZU_float_int(ctx, dec); // -> FCVTZU_64H_float2int
	if(!sf && !S && ptype==1 && rmode==2 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_69_FLOAT2INT);
	if(!sf && !S && !ptype && rmode&1 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_40_FLOAT2INT);
	if(!sf && !S && !ptype && (rmode&2)==2 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_41_FLOAT2INT);
	if(!sf && !S && ptype==1 && !(rmode&2) && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_68_FLOAT2INT);
	if(sf && !S && ptype==1 && rmode&1 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_72_FLOAT2INT);
	if(sf && !S && ptype==1 && (rmode&2)==2 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_73_FLOAT2INT);
	if(sf && !S && ptype==2 && !(rmode&1) && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_79_FLOAT2INT);
	if(sf && !S && ptype==2 && (rmode&2)==2 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_80_FLOAT2INT);
	if(!sf && !S && ptype==2 && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_78_FLOAT2INT);
	if(sf && !S && !ptype && (opcode&6)==6) UNALLOCATED(ENC_UNALLOCATED_39_FLOAT2INT);
	if(!S && ptype==2 && (opcode&6)==4) UNALLOCATED(ENC_UNALLOCATED_77_FLOAT2INT);
	if(!S && ptype==2 && !(opcode&4)) UNALLOCATED(ENC_UNALLOCATED_76_FLOAT2INT);
	if(rmode&1 && (opcode&6)==2) UNALLOCATED(ENC_UNALLOCATED_11_FLOAT2INT);
	if(rmode&1 && (opcode&6)==4) UNALLOCATED(ENC_UNALLOCATED_13_FLOAT2INT);
	if((rmode&2)==2 && (opcode&6)==2) UNALLOCATED(ENC_UNALLOCATED_12_FLOAT2INT);
	if((rmode&2)==2 && (opcode&6)==4) UNALLOCATED(ENC_UNALLOCATED_14_FLOAT2INT);
	if(S) UNALLOCATED(ENC_UNALLOCATED_10_FLOAT2INT);
	UNMATCHED;
}

int decode_iclass_cryptoaes(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!size && opcode==4) return AESE_advsimd(ctx, dec); // -> AESE_B_cryptoaes
	if(!size && opcode==5) return AESD_advsimd(ctx, dec); // -> AESD_B_cryptoaes
	if(!size && opcode==6) return AESMC_advsimd(ctx, dec); // -> AESMC_B_cryptoaes
	if(!size && opcode==7) return AESIMC_advsimd(ctx, dec); // -> AESIMC_B_cryptoaes
	if(!(opcode&0x1c)) UNALLOCATED(ENC_UNALLOCATED_13_CRYPTOAES);
	if((opcode&8)==8) UNALLOCATED(ENC_UNALLOCATED_18_CRYPTOAES);
	if((opcode&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_19_CRYPTOAES);
	if(size&1) UNALLOCATED(ENC_UNALLOCATED_12_CRYPTOAES);
	if((size&2)==2) UNALLOCATED(ENC_UNALLOCATED_11_CRYPTOAES);
	UNMATCHED;
}

int decode_iclass_crypto4(context *ctx, Instruction *dec)
{
	uint32_t Op0=(INSWORD>>21)&3;
	if(!Op0 && HasSHA3()) return EOR3_advsimd(ctx, dec); // -> EOR3_VVV16_crypto4
	if(Op0==1 && HasSHA3()) return BCAX_advsimd(ctx, dec); // -> BCAX_VVV16_crypto4
	if(Op0==2 && HasSM3()) return SM3SS1_advsimd(ctx, dec); // -> SM3SS1_VVV4_crypto4
	if(Op0==3) UNALLOCATED(ENC_UNALLOCATED_14_CRYPTO4);
	UNMATCHED;
}

int decode_iclass_cryptosha3(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&7;
	if(!size && !opcode) return SHA1C_advsimd(ctx, dec); // -> SHA1C_QSV_cryptosha3
	if(!size && opcode==1) return SHA1P_advsimd(ctx, dec); // -> SHA1P_QSV_cryptosha3
	if(!size && opcode==2) return SHA1M_advsimd(ctx, dec); // -> SHA1M_QSV_cryptosha3
	if(!size && opcode==3) return SHA1SU0_advsimd(ctx, dec); // -> SHA1SU0_VVV_cryptosha3
	if(!size && opcode==4) return SHA256H_advsimd(ctx, dec); // -> SHA256H_QQV_cryptosha3
	if(!size && opcode==5) return SHA256H2_advsimd(ctx, dec); // -> SHA256H2_QQV_cryptosha3
	if(!size && opcode==6) return SHA256SU1_advsimd(ctx, dec); // -> SHA256SU1_VVV_cryptosha3
	if(opcode==7) UNALLOCATED(ENC_UNALLOCATED_20_CRYPTOSHA3);
	if(size&1) UNALLOCATED(ENC_UNALLOCATED_11_CRYPTOSHA3);
	if((size&2)==2) UNALLOCATED(ENC_UNALLOCATED_12_CRYPTOSHA3);
	UNMATCHED;
}

int decode_iclass_cryptosha512_3(context *ctx, Instruction *dec)
{
	uint32_t O=(INSWORD>>14)&1, opcode=(INSWORD>>10)&3;
	if(!O && !opcode && HasSHA2()) return SHA512H_advsimd(ctx, dec); // -> SHA512H_QQV_cryptosha512_3
	if(!O && opcode==1 && HasSHA2()) return SHA512H2_advsimd(ctx, dec); // -> SHA512H2_QQV_cryptosha512_3
	if(!O && opcode==2 && HasSHA2()) return SHA512SU1_advsimd(ctx, dec); // -> SHA512SU1_VVV2_cryptosha512_3
	if(!O && opcode==3 && HasSHA3()) return RAX1_advsimd(ctx, dec); // -> RAX1_VVV2_cryptosha512_3
	if(O && !opcode && HasSM3()) return SM3PARTW1_advsimd(ctx, dec); // -> SM3PARTW1_VVV4_cryptosha512_3
	if(O && opcode==1 && HasSM3()) return SM3PARTW2_advsimd(ctx, dec); // -> SM3PARTW2_VVV4_cryptosha512_3
	if(O && opcode==2 && HasSM4()) return SM4EKEY_advsimd(ctx, dec); // -> SM4EKEY_VVV4_cryptosha512_3
	if(O && opcode==3) UNALLOCATED(ENC_UNALLOCATED_18_CRYPTOSHA512_3);
	UNMATCHED;
}

int decode_iclass_crypto3_imm2(context *ctx, Instruction *dec)
{
	uint32_t opcode=(INSWORD>>10)&3;
	if(!opcode && HasSM3()) return SM3TT1A_advsimd(ctx, dec); // -> SM3TT1A_VVV4_crypto3_imm2
	if(opcode==1 && HasSM3()) return SM3TT1B_advsimd(ctx, dec); // -> SM3TT1B_VVV4_crypto3_imm2
	if(opcode==2 && HasSM3()) return SM3TT2A_advsimd(ctx, dec); // -> SM3TT2A_VVV4_crypto3_imm2
	if(opcode==3 && HasSM3()) return SM3TT2B_advsimd(ctx, dec); // -> SM3TT2B_VVV_crypto3_imm2
	UNMATCHED;
}

int decode_iclass_crypto3_imm6(context *ctx, Instruction *dec)
{
	return XAR_advsimd(ctx, dec);
}

int decode_iclass_cryptosha2(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, opcode=(INSWORD>>12)&0x1f;
	if(!size && !opcode) return SHA1H_advsimd(ctx, dec); // -> SHA1H_SS_cryptosha2
	if(!size && opcode==1) return SHA1SU1_advsimd(ctx, dec); // -> SHA1SU1_VV_cryptosha2
	if(!size && opcode==2) return SHA256SU0_advsimd(ctx, dec); // -> SHA256SU0_VV_cryptosha2
	if(!size && opcode==3) UNALLOCATED(ENC_UNALLOCATED_16_CRYPTOSHA2);
	if((opcode&4)==4) UNALLOCATED(ENC_UNALLOCATED_17_CRYPTOSHA2);
	if((opcode&8)==8) UNALLOCATED(ENC_UNALLOCATED_18_CRYPTOSHA2);
	if((opcode&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_19_CRYPTOSHA2);
	if(size&1) UNALLOCATED(ENC_UNALLOCATED_11_CRYPTOSHA2);
	if((size&2)==2) UNALLOCATED(ENC_UNALLOCATED_12_CRYPTOSHA2);
	UNMATCHED;
}

int decode_iclass_cryptosha512_2(context *ctx, Instruction *dec)
{
	uint32_t opcode=(INSWORD>>10)&3;
	if(!opcode && HasSHA2()) return SHA512SU0_advsimd(ctx, dec); // -> SHA512SU0_VV2_cryptosha512_2
	if(opcode==1 && HasSM4()) return SM4E_advsimd(ctx, dec); // -> SM4E_VV4_cryptosha512_2
	if((opcode&2)==2) UNALLOCATED(ENC_UNALLOCATED_11_CRYPTOSHA512_2);
	UNMATCHED;
}

int decode_iclass_floatcmp(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3, op=(INSWORD>>14)&3, opcode2=INSWORD&0x1f;
	if(!M && !S && !ptype && !op && !opcode2) return FCMP_float(ctx, dec); // -> FCMP_S_floatcmp
	if(!M && !S && !ptype && !op && opcode2==8) return FCMP_float(ctx, dec); // -> FCMP_SZ_floatcmp
	if(!M && !S && !ptype && !op && opcode2==0x10) return FCMPE_float(ctx, dec); // -> FCMPE_S_floatcmp
	if(!M && !S && !ptype && !op && opcode2==0x18) return FCMPE_float(ctx, dec); // -> FCMPE_SZ_floatcmp
	if(!M && !S && ptype==1 && !op && !opcode2) return FCMP_float(ctx, dec); // -> FCMP_D_floatcmp
	if(!M && !S && ptype==1 && !op && opcode2==8) return FCMP_float(ctx, dec); // -> FCMP_DZ_floatcmp
	if(!M && !S && ptype==1 && !op && opcode2==0x10) return FCMPE_float(ctx, dec); // -> FCMPE_D_floatcmp
	if(!M && !S && ptype==1 && !op && opcode2==0x18) return FCMPE_float(ctx, dec); // -> FCMPE_DZ_floatcmp
	if(!M && !S && ptype==3 && !op && !opcode2 && HasFP16()) return FCMP_float(ctx, dec); // -> FCMP_H_floatcmp
	if(!M && !S && ptype==3 && !op && opcode2==8 && HasFP16()) return FCMP_float(ctx, dec); // -> FCMP_HZ_floatcmp
	if(!M && !S && ptype==3 && !op && opcode2==0x10 && HasFP16()) return FCMPE_float(ctx, dec); // -> FCMPE_H_floatcmp
	if(!M && !S && ptype==3 && !op && opcode2==0x18 && HasFP16()) return FCMPE_float(ctx, dec); // -> FCMPE_HZ_floatcmp
	if(ptype==2) UNALLOCATED(ENC_UNALLOCATED_17_FLOATCMP);
	if(opcode2&1) UNALLOCATED(ENC_UNALLOCATED_12_FLOATCMP);
	if((opcode2&2)==2) UNALLOCATED(ENC_UNALLOCATED_13_FLOATCMP);
	if((opcode2&4)==4) UNALLOCATED(ENC_UNALLOCATED_14_FLOATCMP);
	if(op&1) UNALLOCATED(ENC_UNALLOCATED_15_FLOATCMP);
	if((op&2)==2) UNALLOCATED(ENC_UNALLOCATED_16_FLOATCMP);
	if(S) UNALLOCATED(ENC_UNALLOCATED_10_FLOATCMP);
	if(M) UNALLOCATED(ENC_UNALLOCATED_11_FLOATCMP);
	UNMATCHED;
}

int decode_iclass_floatccmp(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3, op=(INSWORD>>4)&1;
	if(!M && !S && !ptype && !op) return FCCMP_float(ctx, dec); // -> FCCMP_S_floatccmp
	if(!M && !S && !ptype && op) return FCCMPE_float(ctx, dec); // -> FCCMPE_S_floatccmp
	if(!M && !S && ptype==1 && !op) return FCCMP_float(ctx, dec); // -> FCCMP_D_floatccmp
	if(!M && !S && ptype==1 && op) return FCCMPE_float(ctx, dec); // -> FCCMPE_D_floatccmp
	if(!M && !S && ptype==3 && !op && HasFP16()) return FCCMP_float(ctx, dec); // -> FCCMP_H_floatccmp
	if(!M && !S && ptype==3 && op && HasFP16()) return FCCMPE_float(ctx, dec); // -> FCCMPE_H_floatccmp
	if(ptype==2) UNALLOCATED(ENC_UNALLOCATED_12_FLOATCCMP);
	if(S) UNALLOCATED(ENC_UNALLOCATED_10_FLOATCCMP);
	if(M) UNALLOCATED(ENC_UNALLOCATED_11_FLOATCCMP);
	UNMATCHED;
}

int decode_iclass_floatsel(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3;
	if(!M && !S && !ptype) return FCSEL_float(ctx, dec); // -> FCSEL_S_floatsel
	if(!M && !S && ptype==1) return FCSEL_float(ctx, dec); // -> FCSEL_D_floatsel
	if(!M && !S && ptype==3 && HasFP16()) return FCSEL_float(ctx, dec); // -> FCSEL_H_floatsel
	if(ptype==2) UNALLOCATED(ENC_UNALLOCATED_12_FLOATSEL);
	if(S) UNALLOCATED(ENC_UNALLOCATED_10_FLOATSEL);
	if(M) UNALLOCATED(ENC_UNALLOCATED_11_FLOATSEL);
	UNMATCHED;
}

int decode_iclass_floatdp1(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3, opcode=(INSWORD>>15)&0x3f;
	if(!M && !S && !ptype && !opcode) return FMOV_float(ctx, dec); // -> FMOV_S_floatdp1
	if(!M && !S && !ptype && opcode==1) return FABS_float(ctx, dec); // -> FABS_S_floatdp1
	if(!M && !S && !ptype && opcode==2) return FNEG_float(ctx, dec); // -> FNEG_S_floatdp1
	if(!M && !S && !ptype && opcode==3) return FSQRT_float(ctx, dec); // -> FSQRT_S_floatdp1
	if(!M && !S && !ptype && opcode==4) UNALLOCATED(ENC_UNALLOCATED_17_FLOATDP1);
	if(!M && !S && !ptype && opcode==5) return FCVT_float(ctx, dec); // -> FCVT_DS_floatdp1
	if(!M && !S && !ptype && opcode==6) UNALLOCATED(ENC_UNALLOCATED_19_FLOATDP1);
	if(!M && !S && !ptype && opcode==7) return FCVT_float(ctx, dec); // -> FCVT_HS_floatdp1
	if(!M && !S && !ptype && opcode==8) return FRINTN_float(ctx, dec); // -> FRINTN_S_floatdp1
	if(!M && !S && !ptype && opcode==9) return FRINTP_float(ctx, dec); // -> FRINTP_S_floatdp1
	if(!M && !S && !ptype && opcode==10) return FRINTM_float(ctx, dec); // -> FRINTM_S_floatdp1
	if(!M && !S && !ptype && opcode==11) return FRINTZ_float(ctx, dec); // -> FRINTZ_S_floatdp1
	if(!M && !S && !ptype && opcode==12) return FRINTA_float(ctx, dec); // -> FRINTA_S_floatdp1
	if(!M && !S && !ptype && opcode==13) UNALLOCATED(ENC_UNALLOCATED_26_FLOATDP1);
	if(!M && !S && !ptype && opcode==14) return FRINTX_float(ctx, dec); // -> FRINTX_S_floatdp1
	if(!M && !S && !ptype && opcode==15) return FRINTI_float(ctx, dec); // -> FRINTI_S_floatdp1
	if(!M && !S && !ptype && opcode==0x10 && HasFRINT()) return FRINT32Z_float(ctx, dec); // -> FRINT32Z_S_floatdp1
	if(!M && !S && !ptype && opcode==0x11 && HasFRINT()) return FRINT32X_float(ctx, dec); // -> FRINT32X_S_floatdp1
	if(!M && !S && !ptype && opcode==0x12 && HasFRINT()) return FRINT64Z_float(ctx, dec); // -> FRINT64Z_S_floatdp1
	if(!M && !S && !ptype && opcode==0x13 && HasFRINT()) return FRINT64X_float(ctx, dec); // -> FRINT64X_S_floatdp1
	if(!M && !S && ptype==1 && !opcode) return FMOV_float(ctx, dec); // -> FMOV_D_floatdp1
	if(!M && !S && ptype==1 && opcode==1) return FABS_float(ctx, dec); // -> FABS_D_floatdp1
	if(!M && !S && ptype==1 && opcode==2) return FNEG_float(ctx, dec); // -> FNEG_D_floatdp1
	if(!M && !S && ptype==1 && opcode==3) return FSQRT_float(ctx, dec); // -> FSQRT_D_floatdp1
	if(!M && !S && ptype==1 && opcode==4) return FCVT_float(ctx, dec); // -> FCVT_SD_floatdp1
	if(!M && !S && ptype==1 && opcode==5) UNALLOCATED(ENC_UNALLOCATED_40_FLOATDP1);
	if(!M && !S && ptype==1 && opcode==6 && HasBF16()) return BFCVT_float(ctx, dec); // -> BFCVT_BS_floatdp1
	if(!M && !S && ptype==1 && opcode==7) return FCVT_float(ctx, dec); // -> FCVT_HD_floatdp1
	if(!M && !S && ptype==1 && opcode==8) return FRINTN_float(ctx, dec); // -> FRINTN_D_floatdp1
	if(!M && !S && ptype==1 && opcode==9) return FRINTP_float(ctx, dec); // -> FRINTP_D_floatdp1
	if(!M && !S && ptype==1 && opcode==10) return FRINTM_float(ctx, dec); // -> FRINTM_D_floatdp1
	if(!M && !S && ptype==1 && opcode==11) return FRINTZ_float(ctx, dec); // -> FRINTZ_D_floatdp1
	if(!M && !S && ptype==1 && opcode==12) return FRINTA_float(ctx, dec); // -> FRINTA_D_floatdp1
	if(!M && !S && ptype==1 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_48_FLOATDP1);
	if(!M && !S && ptype==1 && opcode==14) return FRINTX_float(ctx, dec); // -> FRINTX_D_floatdp1
	if(!M && !S && ptype==1 && opcode==15) return FRINTI_float(ctx, dec); // -> FRINTI_D_floatdp1
	if(!M && !S && ptype==1 && opcode==0x10 && HasFRINT()) return FRINT32Z_float(ctx, dec); // -> FRINT32Z_D_floatdp1
	if(!M && !S && ptype==1 && opcode==0x11 && HasFRINT()) return FRINT32X_float(ctx, dec); // -> FRINT32X_D_floatdp1
	if(!M && !S && ptype==1 && opcode==0x12 && HasFRINT()) return FRINT64Z_float(ctx, dec); // -> FRINT64Z_D_floatdp1
	if(!M && !S && ptype==1 && opcode==0x13 && HasFRINT()) return FRINT64X_float(ctx, dec); // -> FRINT64X_D_floatdp1
	if(!M && !S && ptype==3 && !opcode && HasFP16()) return FMOV_float(ctx, dec); // -> FMOV_H_floatdp1
	if(!M && !S && ptype==3 && opcode==1 && HasFP16()) return FABS_float(ctx, dec); // -> FABS_H_floatdp1
	if(!M && !S && ptype==3 && opcode==2 && HasFP16()) return FNEG_float(ctx, dec); // -> FNEG_H_floatdp1
	if(!M && !S && ptype==3 && opcode==3 && HasFP16()) return FSQRT_float(ctx, dec); // -> FSQRT_H_floatdp1
	if(!M && !S && ptype==3 && opcode==4) return FCVT_float(ctx, dec); // -> FCVT_SH_floatdp1
	if(!M && !S && ptype==3 && opcode==5) return FCVT_float(ctx, dec); // -> FCVT_DH_floatdp1
	if(!M && !S && ptype==3 && opcode==8 && HasFP16()) return FRINTN_float(ctx, dec); // -> FRINTN_H_floatdp1
	if(!M && !S && ptype==3 && opcode==9 && HasFP16()) return FRINTP_float(ctx, dec); // -> FRINTP_H_floatdp1
	if(!M && !S && ptype==3 && opcode==10 && HasFP16()) return FRINTM_float(ctx, dec); // -> FRINTM_H_floatdp1
	if(!M && !S && ptype==3 && opcode==11 && HasFP16()) return FRINTZ_float(ctx, dec); // -> FRINTZ_H_floatdp1
	if(!M && !S && ptype==3 && opcode==12 && HasFP16()) return FRINTA_float(ctx, dec); // -> FRINTA_H_floatdp1
	if(!M && !S && ptype==3 && opcode==13) UNALLOCATED(ENC_UNALLOCATED_70_FLOATDP1);
	if(!M && !S && ptype==3 && opcode==14 && HasFP16()) return FRINTX_float(ctx, dec); // -> FRINTX_H_floatdp1
	if(!M && !S && ptype==3 && opcode==15 && HasFP16()) return FRINTI_float(ctx, dec); // -> FRINTI_H_floatdp1
	if(!M && !S && ptype==3 && (opcode&0x3e)==6) UNALLOCATED(ENC_UNALLOCATED_64_FLOATDP1);
	if(!M && !S && !ptype && (opcode&0x3c)==0x14) UNALLOCATED(ENC_UNALLOCATED_33_FLOATDP1);
	if(!M && !S && ptype==1 && (opcode&0x3c)==0x14) UNALLOCATED(ENC_UNALLOCATED_55_FLOATDP1);
	if(!M && !S && !ptype && (opcode&0x38)==0x18) UNALLOCATED(ENC_UNALLOCATED_34_FLOATDP1);
	if(!M && !S && ptype==1 && (opcode&0x38)==0x18) UNALLOCATED(ENC_UNALLOCATED_56_FLOATDP1);
	if(!M && !S && ptype==3 && (opcode&0x30)==0x10) UNALLOCATED(ENC_UNALLOCATED_73_FLOATDP1);
	if(!M && !S && ptype==2 && !(opcode&0x20)) UNALLOCATED(ENC_UNALLOCATED_57_FLOATDP1);
	if((opcode&0x20)==0x20) UNALLOCATED(ENC_UNALLOCATED_12_FLOATDP1);
	if(S) UNALLOCATED(ENC_UNALLOCATED_10_FLOATDP1);
	if(M) UNALLOCATED(ENC_UNALLOCATED_11_FLOATDP1);
	UNMATCHED;
}

int decode_iclass_floatdp2(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3, opcode=(INSWORD>>12)&15;
	if(!M && !S && !ptype && !opcode) return FMUL_float(ctx, dec); // -> FMUL_S_floatdp2
	if(!M && !S && !ptype && opcode==1) return FDIV_float(ctx, dec); // -> FDIV_S_floatdp2
	if(!M && !S && !ptype && opcode==2) return FADD_float(ctx, dec); // -> FADD_S_floatdp2
	if(!M && !S && !ptype && opcode==3) return FSUB_float(ctx, dec); // -> FSUB_S_floatdp2
	if(!M && !S && !ptype && opcode==4) return FMAX_float(ctx, dec); // -> FMAX_S_floatdp2
	if(!M && !S && !ptype && opcode==5) return FMIN_float(ctx, dec); // -> FMIN_S_floatdp2
	if(!M && !S && !ptype && opcode==6) return FMAXNM_float(ctx, dec); // -> FMAXNM_S_floatdp2
	if(!M && !S && !ptype && opcode==7) return FMINNM_float(ctx, dec); // -> FMINNM_S_floatdp2
	if(!M && !S && !ptype && opcode==8) return FNMUL_float(ctx, dec); // -> FNMUL_S_floatdp2
	if(!M && !S && ptype==1 && !opcode) return FMUL_float(ctx, dec); // -> FMUL_D_floatdp2
	if(!M && !S && ptype==1 && opcode==1) return FDIV_float(ctx, dec); // -> FDIV_D_floatdp2
	if(!M && !S && ptype==1 && opcode==2) return FADD_float(ctx, dec); // -> FADD_D_floatdp2
	if(!M && !S && ptype==1 && opcode==3) return FSUB_float(ctx, dec); // -> FSUB_D_floatdp2
	if(!M && !S && ptype==1 && opcode==4) return FMAX_float(ctx, dec); // -> FMAX_D_floatdp2
	if(!M && !S && ptype==1 && opcode==5) return FMIN_float(ctx, dec); // -> FMIN_D_floatdp2
	if(!M && !S && ptype==1 && opcode==6) return FMAXNM_float(ctx, dec); // -> FMAXNM_D_floatdp2
	if(!M && !S && ptype==1 && opcode==7) return FMINNM_float(ctx, dec); // -> FMINNM_D_floatdp2
	if(!M && !S && ptype==1 && opcode==8) return FNMUL_float(ctx, dec); // -> FNMUL_D_floatdp2
	if(!M && !S && ptype==3 && !opcode && HasFP16()) return FMUL_float(ctx, dec); // -> FMUL_H_floatdp2
	if(!M && !S && ptype==3 && opcode==1 && HasFP16()) return FDIV_float(ctx, dec); // -> FDIV_H_floatdp2
	if(!M && !S && ptype==3 && opcode==2 && HasFP16()) return FADD_float(ctx, dec); // -> FADD_H_floatdp2
	if(!M && !S && ptype==3 && opcode==3 && HasFP16()) return FSUB_float(ctx, dec); // -> FSUB_H_floatdp2
	if(!M && !S && ptype==3 && opcode==4 && HasFP16()) return FMAX_float(ctx, dec); // -> FMAX_H_floatdp2
	if(!M && !S && ptype==3 && opcode==5 && HasFP16()) return FMIN_float(ctx, dec); // -> FMIN_H_floatdp2
	if(!M && !S && ptype==3 && opcode==6 && HasFP16()) return FMAXNM_float(ctx, dec); // -> FMAXNM_H_floatdp2
	if(!M && !S && ptype==3 && opcode==7 && HasFP16()) return FMINNM_float(ctx, dec); // -> FMINNM_H_floatdp2
	if(!M && !S && ptype==3 && opcode==8 && HasFP16()) return FNMUL_float(ctx, dec); // -> FNMUL_H_floatdp2
	if((opcode&9)==9) UNALLOCATED(ENC_UNALLOCATED_13_FLOATDP2);
	if((opcode&10)==10) UNALLOCATED(ENC_UNALLOCATED_14_FLOATDP2);
	if((opcode&12)==12) UNALLOCATED(ENC_UNALLOCATED_15_FLOATDP2);
	if(ptype==2) UNALLOCATED(ENC_UNALLOCATED_10_FLOATDP2);
	if(S) UNALLOCATED(ENC_UNALLOCATED_11_FLOATDP2);
	if(M) UNALLOCATED(ENC_UNALLOCATED_12_FLOATDP2);
	UNMATCHED;
}

int decode_iclass_floatdp3(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3, o1=(INSWORD>>21)&1, o0=(INSWORD>>15)&1;
	if(!M && !S && !ptype && !o1 && !o0) return FMADD_float(ctx, dec); // -> FMADD_S_floatdp3
	if(!M && !S && !ptype && !o1 && o0) return FMSUB_float(ctx, dec); // -> FMSUB_S_floatdp3
	if(!M && !S && !ptype && o1 && !o0) return FNMADD_float(ctx, dec); // -> FNMADD_S_floatdp3
	if(!M && !S && !ptype && o1 && o0) return FNMSUB_float(ctx, dec); // -> FNMSUB_S_floatdp3
	if(!M && !S && ptype==1 && !o1 && !o0) return FMADD_float(ctx, dec); // -> FMADD_D_floatdp3
	if(!M && !S && ptype==1 && !o1 && o0) return FMSUB_float(ctx, dec); // -> FMSUB_D_floatdp3
	if(!M && !S && ptype==1 && o1 && !o0) return FNMADD_float(ctx, dec); // -> FNMADD_D_floatdp3
	if(!M && !S && ptype==1 && o1 && o0) return FNMSUB_float(ctx, dec); // -> FNMSUB_D_floatdp3
	if(!M && !S && ptype==3 && !o1 && !o0 && HasFP16()) return FMADD_float(ctx, dec); // -> FMADD_H_floatdp3
	if(!M && !S && ptype==3 && !o1 && o0 && HasFP16()) return FMSUB_float(ctx, dec); // -> FMSUB_H_floatdp3
	if(!M && !S && ptype==3 && o1 && !o0 && HasFP16()) return FNMADD_float(ctx, dec); // -> FNMADD_H_floatdp3
	if(!M && !S && ptype==3 && o1 && o0 && HasFP16()) return FNMSUB_float(ctx, dec); // -> FNMSUB_H_floatdp3
	if(ptype==2) UNALLOCATED(ENC_UNALLOCATED_10_FLOATDP3);
	if(S) UNALLOCATED(ENC_UNALLOCATED_12_FLOATDP3);
	if(M) UNALLOCATED(ENC_UNALLOCATED_11_FLOATDP3);
	UNMATCHED;
}

int decode_iclass_floatimm(context *ctx, Instruction *dec)
{
	uint32_t M=INSWORD>>31, S=(INSWORD>>29)&1, ptype=(INSWORD>>22)&3, imm5=(INSWORD>>5)&0x1f;
	if(!M && !S && !ptype && !imm5) return FMOV_float_imm(ctx, dec); // -> FMOV_S_floatimm
	if(!M && !S && ptype==1 && !imm5) return FMOV_float_imm(ctx, dec); // -> FMOV_D_floatimm
	if(!M && !S && ptype==3 && !imm5 && HasFP16()) return FMOV_float_imm(ctx, dec); // -> FMOV_H_floatimm
	if(ptype==2) UNALLOCATED(ENC_UNALLOCATED_17_FLOATIMM);
	if(imm5&1) UNALLOCATED(ENC_UNALLOCATED_10_FLOATIMM);
	if((imm5&2)==2) UNALLOCATED(ENC_UNALLOCATED_11_FLOATIMM);
	if((imm5&4)==4) UNALLOCATED(ENC_UNALLOCATED_12_FLOATIMM);
	if((imm5&8)==8) UNALLOCATED(ENC_UNALLOCATED_13_FLOATIMM);
	if((imm5&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_14_FLOATIMM);
	if(S) UNALLOCATED(ENC_UNALLOCATED_15_FLOATIMM);
	if(M) UNALLOCATED(ENC_UNALLOCATED_16_FLOATIMM);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_misc_0_a(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc) return adr_z_az(ctx, dec); // -> adr_z_az_d_s32_scaled
	if(opc==1) return adr_z_az(ctx, dec); // -> adr_z_az_d_u32_scaled
	if((opc&2)==2) return adr_z_az(ctx, dec); // -> adr_z_az_sd_same_scaled
	UNMATCHED;
}

int decode_iclass_perm_undef(context *ctx, Instruction *dec)
{
	return UDF_perm_undef(ctx, dec);
}

int decode_iclass_sve_int_bin_cons_misc_0_d(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>16)&0x1f;
	if(!opc && !opc2) return movprfx_z_z(ctx, dec); // -> movprfx_z_z_
	if(!opc && opc2==1) UNALLOCATED(ENC_UNALLOCATED_155);
	if(!opc && (opc2&0x1e)==2) UNALLOCATED(ENC_UNALLOCATED_157);
	if(!opc && (opc2&0x1c)==4) UNALLOCATED(ENC_UNALLOCATED_159);
	if(!opc && (opc2&0x18)==8) UNALLOCATED(ENC_UNALLOCATED_161);
	if(!opc && (opc2&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_163);
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_165);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_167);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_misc_0_c(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&0x1f;
	if(!opc) return fexpa_z_z(ctx, dec); // -> fexpa_z_z_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_154);
	if((opc&0x1e)==2) UNALLOCATED(ENC_UNALLOCATED_156);
	if((opc&0x1c)==4) UNALLOCATED(ENC_UNALLOCATED_158);
	if((opc&0x18)==8) UNALLOCATED(ENC_UNALLOCATED_160);
	if((opc&0x10)==0x10) UNALLOCATED(ENC_UNALLOCATED_162);
	UNMATCHED;
}

int decode_iclass_sve_int_bin_cons_misc_0_b(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>10)&1;
	if(!op) return ftssel_z_zz(ctx, dec); // -> ftssel_z_zz_
	if(op) UNALLOCATED(ENC_UNALLOCATED_151);
	UNMATCHED;
}

int decode_iclass_sve_int_count(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>10)&1;
	if(!size && !op) return cntb_r_s(ctx, dec); // -> cntb_r_s_
	if(size==1 && !op) return cntb_r_s(ctx, dec); // -> cnth_r_s_
	if(size==2 && !op) return cntb_r_s(ctx, dec); // -> cntw_r_s_
	if(size==3 && !op) return cntb_r_s(ctx, dec); // -> cntd_r_s_
	if(op) UNALLOCATED(ENC_UNALLOCATED_153);
	UNMATCHED;
}

int decode_iclass_sve_int_pred_pattern_a(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, D=(INSWORD>>10)&1;
	if(!size && !D) return incb_r_rs(ctx, dec); // -> incb_r_rs_
	if(!size && D) return decb_r_rs(ctx, dec); // -> decb_r_rs_
	if(size==1 && !D) return incb_r_rs(ctx, dec); // -> inch_r_rs_
	if(size==1 && D) return decb_r_rs(ctx, dec); // -> dech_r_rs_
	if(size==2 && !D) return incb_r_rs(ctx, dec); // -> incw_r_rs_
	if(size==2 && D) return decb_r_rs(ctx, dec); // -> decw_r_rs_
	if(size==3 && !D) return incb_r_rs(ctx, dec); // -> incd_r_rs_
	if(size==3 && D) return decb_r_rs(ctx, dec); // -> decd_r_rs_
	UNMATCHED;
}

int decode_iclass_sve_int_countvlv1(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, D=(INSWORD>>10)&1;
	if(size==1 && !D) return incd_z_zs(ctx, dec); // -> inch_z_zs_
	if(size==1 && D) return decd_z_zs(ctx, dec); // -> dech_z_zs_
	if(size==2 && !D) return incd_z_zs(ctx, dec); // -> incw_z_zs_
	if(size==2 && D) return decd_z_zs(ctx, dec); // -> decw_z_zs_
	if(size==3 && !D) return incd_z_zs(ctx, dec); // -> incd_z_zs_
	if(size==3 && D) return decd_z_zs(ctx, dec); // -> decd_z_zs_
	if(!size) UNALLOCATED(ENC_UNALLOCATED_164);
	UNMATCHED;
}

int decode_iclass_sve_int_pred_pattern_b(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, sf=(INSWORD>>20)&1, D=(INSWORD>>11)&1, U=(INSWORD>>10)&1;
	if(!size && !sf && !D && !U) return sqincb_r_rs(ctx, dec); // -> sqincb_r_rs_sx
	if(!size && !sf && !D && U) return uqincb_r_rs(ctx, dec); // -> uqincb_r_rs_uw
	if(!size && !sf && D && !U) return sqdecb_r_rs(ctx, dec); // -> sqdecb_r_rs_sx
	if(!size && !sf && D && U) return uqdecb_r_rs(ctx, dec); // -> uqdecb_r_rs_uw
	if(!size && sf && !D && !U) return sqincb_r_rs(ctx, dec); // -> sqincb_r_rs_x
	if(!size && sf && !D && U) return uqincb_r_rs(ctx, dec); // -> uqincb_r_rs_x
	if(!size && sf && D && !U) return sqdecb_r_rs(ctx, dec); // -> sqdecb_r_rs_x
	if(!size && sf && D && U) return uqdecb_r_rs(ctx, dec); // -> uqdecb_r_rs_x
	if(size==1 && !sf && !D && !U) return sqinch_r_rs(ctx, dec); // -> sqinch_r_rs_sx
	if(size==1 && !sf && !D && U) return uqinch_r_rs(ctx, dec); // -> uqinch_r_rs_uw
	if(size==1 && !sf && D && !U) return sqdech_r_rs(ctx, dec); // -> sqdech_r_rs_sx
	if(size==1 && !sf && D && U) return uqdech_r_rs(ctx, dec); // -> uqdech_r_rs_uw
	if(size==1 && sf && !D && !U) return sqinch_r_rs(ctx, dec); // -> sqinch_r_rs_x
	if(size==1 && sf && !D && U) return uqinch_r_rs(ctx, dec); // -> uqinch_r_rs_x
	if(size==1 && sf && D && !U) return sqdech_r_rs(ctx, dec); // -> sqdech_r_rs_x
	if(size==1 && sf && D && U) return uqdech_r_rs(ctx, dec); // -> uqdech_r_rs_x
	if(size==2 && !sf && !D && !U) return sqincw_r_rs(ctx, dec); // -> sqincw_r_rs_sx
	if(size==2 && !sf && !D && U) return uqincw_r_rs(ctx, dec); // -> uqincw_r_rs_uw
	if(size==2 && !sf && D && !U) return sqdecw_r_rs(ctx, dec); // -> sqdecw_r_rs_sx
	if(size==2 && !sf && D && U) return uqdecw_r_rs(ctx, dec); // -> uqdecw_r_rs_uw
	if(size==2 && sf && !D && !U) return sqincw_r_rs(ctx, dec); // -> sqincw_r_rs_x
	if(size==2 && sf && !D && U) return uqincw_r_rs(ctx, dec); // -> uqincw_r_rs_x
	if(size==2 && sf && D && !U) return sqdecw_r_rs(ctx, dec); // -> sqdecw_r_rs_x
	if(size==2 && sf && D && U) return uqdecw_r_rs(ctx, dec); // -> uqdecw_r_rs_x
	if(size==3 && !sf && !D && !U) return sqincd_r_rs(ctx, dec); // -> sqincd_r_rs_sx
	if(size==3 && !sf && !D && U) return uqincd_r_rs(ctx, dec); // -> uqincd_r_rs_uw
	if(size==3 && !sf && D && !U) return sqdecd_r_rs(ctx, dec); // -> sqdecd_r_rs_sx
	if(size==3 && !sf && D && U) return uqdecd_r_rs(ctx, dec); // -> uqdecd_r_rs_uw
	if(size==3 && sf && !D && !U) return sqincd_r_rs(ctx, dec); // -> sqincd_r_rs_x
	if(size==3 && sf && !D && U) return uqincd_r_rs(ctx, dec); // -> uqincd_r_rs_x
	if(size==3 && sf && D && !U) return sqdecd_r_rs(ctx, dec); // -> sqdecd_r_rs_x
	if(size==3 && sf && D && U) return uqdecd_r_rs(ctx, dec); // -> uqdecd_r_rs_x
	UNMATCHED;
}

int decode_iclass_sve_int_countvlv0(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, D=(INSWORD>>11)&1, U=(INSWORD>>10)&1;
	if(size==1 && !D && !U) return sqinch_z_zs(ctx, dec); // -> sqinch_z_zs_
	if(size==1 && !D && U) return uqinch_z_zs(ctx, dec); // -> uqinch_z_zs_
	if(size==1 && D && !U) return sqdech_z_zs(ctx, dec); // -> sqdech_z_zs_
	if(size==1 && D && U) return uqdech_z_zs(ctx, dec); // -> uqdech_z_zs_
	if(size==2 && !D && !U) return sqincw_z_zs(ctx, dec); // -> sqincw_z_zs_
	if(size==2 && !D && U) return uqincw_z_zs(ctx, dec); // -> uqincw_z_zs_
	if(size==2 && D && !U) return sqdecw_z_zs(ctx, dec); // -> sqdecw_z_zs_
	if(size==2 && D && U) return uqdecw_z_zs(ctx, dec); // -> uqdecw_z_zs_
	if(size==3 && !D && !U) return sqincd_z_zs(ctx, dec); // -> sqincd_z_zs_
	if(size==3 && !D && U) return uqincd_z_zs(ctx, dec); // -> uqincd_z_zs_
	if(size==3 && D && !U) return sqdecd_z_zs(ctx, dec); // -> sqdecd_z_zs_
	if(size==3 && D && U) return uqdecd_z_zs(ctx, dec); // -> uqdecd_z_zs_
	if(!size) UNALLOCATED(ENC_UNALLOCATED_152);
	UNMATCHED;
}

int decode_iclass_sve_int_perm_extract_i(context *ctx, Instruction *dec)
{
	return ext_z_zi(ctx, dec);
}

int decode_iclass_sve_int_perm_bin_long_perm_zz(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1, opc2=(INSWORD>>10)&7;
	if(!op && !opc2) return zip1_z_zz(ctx, dec); // -> zip1_z_zz_q
	if(!op && opc2==1) return zip1_z_zz(ctx, dec); // -> zip2_z_zz_q
	if(!op && opc2==2) return uzp1_z_zz(ctx, dec); // -> uzp1_z_zz_q
	if(!op && opc2==3) return uzp1_z_zz(ctx, dec); // -> uzp2_z_zz_q
	if(!op && opc2==6) return trn1_z_zz(ctx, dec); // -> trn1_z_zz_q
	if(!op && opc2==7) return trn1_z_zz(ctx, dec); // -> trn2_z_zz_q
	if(!op && (opc2&6)==4) UNALLOCATED(ENC_UNALLOCATED_175);
	if(op) UNALLOCATED(ENC_UNALLOCATED_176);
	UNMATCHED;
}

int decode_iclass_sve_int_log_imm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc) return orr_z_zi(ctx, dec); // -> orr_z_zi_
	if(opc==1) return eor_z_zi(ctx, dec); // -> eor_z_zi_
	if(opc==2) return and_z_zi(ctx, dec); // -> and_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_int_dup_mask_imm(context *ctx, Instruction *dec)
{
	return dupm_z_i(ctx, dec);
}

int decode_iclass_sve_int_dup_fpimm_pred(context *ctx, Instruction *dec)
{
	return fcpy_z_p_i(ctx, dec);
}

int decode_iclass_sve_int_dup_imm_pred(context *ctx, Instruction *dec)
{
	uint32_t M=(INSWORD>>14)&1;
	if(!M) return cpy_z_o_i(ctx, dec); // -> cpy_z_o_i_
	if(M) return cpy_z_p_i(ctx, dec); // -> cpy_z_p_i_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_dup_r(context *ctx, Instruction *dec)
{
	return dup_z_r(ctx, dec);
}

int decode_iclass_sve_int_perm_dup_i(context *ctx, Instruction *dec)
{
	return dup_z_zi(ctx, dec);
}

int decode_iclass_sve_int_perm_insrv(context *ctx, Instruction *dec)
{
	return insr_z_v(ctx, dec);
}

int decode_iclass_sve_int_perm_insrs(context *ctx, Instruction *dec)
{
	return insr_z_r(ctx, dec);
}

int decode_iclass_sve_int_perm_reverse_z(context *ctx, Instruction *dec)
{
	return rev_z_z(ctx, dec);
}

int decode_iclass_sve_int_perm_tbl(context *ctx, Instruction *dec)
{
	return tbl_z_zz(ctx, dec);
}

int decode_iclass_sve_int_perm_unpk(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>17)&1, H=(INSWORD>>16)&1;
	if(!U && !H) return sunpkhi_z_z(ctx, dec); // -> sunpklo_z_z_
	if(!U && H) return sunpkhi_z_z(ctx, dec); // -> sunpkhi_z_z_
	if(U && !H) return uunpkhi_z_z(ctx, dec); // -> uunpklo_z_z_
	if(U && H) return uunpkhi_z_z(ctx, dec); // -> uunpkhi_z_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_bin_perm_pp(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>11)&3, H=(INSWORD>>10)&1;
	if(!opc && !H) return zip1_p_pp(ctx, dec); // -> zip1_p_pp_
	if(!opc && H) return zip1_p_pp(ctx, dec); // -> zip2_p_pp_
	if(opc==1 && !H) return uzp1_p_pp(ctx, dec); // -> uzp1_p_pp_
	if(opc==1 && H) return uzp1_p_pp(ctx, dec); // -> uzp2_p_pp_
	if(opc==2 && !H) return trn1_p_pp(ctx, dec); // -> trn1_p_pp_
	if(opc==2 && H) return trn1_p_pp(ctx, dec); // -> trn2_p_pp_
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_173);
	UNMATCHED;
}

int decode_iclass_sve_int_perm_reverse_p(context *ctx, Instruction *dec)
{
	return rev_p_p(ctx, dec);
}

int decode_iclass_sve_int_perm_punpk(context *ctx, Instruction *dec)
{
	uint32_t H=(INSWORD>>16)&1;
	if(!H) return punpkhi_p_p(ctx, dec); // -> punpklo_p_p_
	if(H) return punpkhi_p_p(ctx, dec); // -> punpkhi_p_p_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_bin_perm_zz(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&7;
	if(!opc) return zip1_z_zz(ctx, dec); // -> zip1_z_zz_
	if(opc==1) return zip1_z_zz(ctx, dec); // -> zip2_z_zz_
	if(opc==2) return uzp1_z_zz(ctx, dec); // -> uzp1_z_zz_
	if(opc==3) return uzp1_z_zz(ctx, dec); // -> uzp2_z_zz_
	if(opc==4) return trn1_z_zz(ctx, dec); // -> trn1_z_zz_
	if(opc==5) return trn1_z_zz(ctx, dec); // -> trn2_z_zz_
	if((opc&6)==6) UNALLOCATED(ENC_UNALLOCATED_174);
	UNMATCHED;
}

int decode_iclass_sve_int_perm_compact(context *ctx, Instruction *dec)
{
	return compact_z_p_z(ctx, dec);
}

int decode_iclass_sve_int_perm_clast_zz(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B) return clasta_z_p_zz(ctx, dec); // -> clasta_z_p_zz_
	if(B) return clastb_z_p_zz(ctx, dec); // -> clastb_z_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_clast_vz(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B) return clasta_v_p_z(ctx, dec); // -> clasta_v_p_z_
	if(B) return clastb_v_p_z(ctx, dec); // -> clastb_v_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_clast_rz(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B) return clasta_r_p_z(ctx, dec); // -> clasta_r_p_z_
	if(B) return clastb_r_p_z(ctx, dec); // -> clastb_r_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_cpy_v(context *ctx, Instruction *dec)
{
	return cpy_z_p_v(ctx, dec);
}

int decode_iclass_sve_int_perm_cpy_r(context *ctx, Instruction *dec)
{
	return cpy_z_p_r(ctx, dec);
}

int decode_iclass_sve_int_perm_last_v(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B) return lasta_v_p_z(ctx, dec); // -> lasta_v_p_z_
	if(B) return lastb_v_p_z(ctx, dec); // -> lastb_v_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_last_r(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>16)&1;
	if(!B) return lasta_r_p_z(ctx, dec); // -> lasta_r_p_z_
	if(B) return lastb_r_p_z(ctx, dec); // -> lastb_r_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_rev(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&3;
	if(!opc) return revb_z_z(ctx, dec); // -> revb_z_z_
	if(opc==1) return revb_z_z(ctx, dec); // -> revh_z_z_
	if(opc==2) return revb_z_z(ctx, dec); // -> revw_z_z_
	if(opc==3) return rbit_z_p_z(ctx, dec); // -> rbit_z_p_z_
	UNMATCHED;
}

int decode_iclass_sve_int_perm_splice(context *ctx, Instruction *dec)
{
	return splice_z_p_zz(ctx, dec);
}

int decode_iclass_sve_int_sel_vvv(context *ctx, Instruction *dec)
{
	return sel_z_p_zz(ctx, dec);
}

int decode_iclass_sve_int_cmp_0(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>15)&1, o2=(INSWORD>>13)&1, ne=(INSWORD>>4)&1;
	if(!op && !o2 && !ne) return cmpeq_p_p_zz(ctx, dec); // -> cmphs_p_p_zz_
	if(!op && !o2 && ne) return cmpeq_p_p_zz(ctx, dec); // -> cmphi_p_p_zz_
	if(!op && o2 && !ne) return cmpeq_p_p_zw(ctx, dec); // -> cmpeq_p_p_zw_
	if(!op && o2 && ne) return cmpeq_p_p_zw(ctx, dec); // -> cmpne_p_p_zw_
	if(op && !o2 && !ne) return cmpeq_p_p_zz(ctx, dec); // -> cmpge_p_p_zz_
	if(op && !o2 && ne) return cmpeq_p_p_zz(ctx, dec); // -> cmpgt_p_p_zz_
	if(op && o2 && !ne) return cmpeq_p_p_zz(ctx, dec); // -> cmpeq_p_p_zz_
	if(op && o2 && ne) return cmpeq_p_p_zz(ctx, dec); // -> cmpne_p_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_int_cmp_1(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>15)&1, lt=(INSWORD>>13)&1, ne=(INSWORD>>4)&1;
	if(!U && !lt && !ne) return cmpeq_p_p_zw(ctx, dec); // -> cmpge_p_p_zw_
	if(!U && !lt && ne) return cmpeq_p_p_zw(ctx, dec); // -> cmpgt_p_p_zw_
	if(!U && lt && !ne) return cmpeq_p_p_zw(ctx, dec); // -> cmplt_p_p_zw_
	if(!U && lt && ne) return cmpeq_p_p_zw(ctx, dec); // -> cmple_p_p_zw_
	if(U && !lt && !ne) return cmpeq_p_p_zw(ctx, dec); // -> cmphs_p_p_zw_
	if(U && !lt && ne) return cmpeq_p_p_zw(ctx, dec); // -> cmphi_p_p_zw_
	if(U && lt && !ne) return cmpeq_p_p_zw(ctx, dec); // -> cmplo_p_p_zw_
	if(U && lt && ne) return cmpeq_p_p_zw(ctx, dec); // -> cmpls_p_p_zw_
	UNMATCHED;
}

int decode_iclass_sve_int_ucmp_vi(context *ctx, Instruction *dec)
{
	uint32_t lt=(INSWORD>>13)&1, ne=(INSWORD>>4)&1;
	if(!lt && !ne) return cmpeq_p_p_zi(ctx, dec); // -> cmphs_p_p_zi_
	if(!lt && ne) return cmpeq_p_p_zi(ctx, dec); // -> cmphi_p_p_zi_
	if(lt && !ne) return cmpeq_p_p_zi(ctx, dec); // -> cmplo_p_p_zi_
	if(lt && ne) return cmpeq_p_p_zi(ctx, dec); // -> cmpls_p_p_zi_
	UNMATCHED;
}

int decode_iclass_sve_int_pred_log(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1, o2=(INSWORD>>9)&1, o3=(INSWORD>>4)&1;
	if(!op && !S && !o2 && !o3) return and_p_p_pp(ctx, dec); // -> and_p_p_pp_z
	if(!op && !S && !o2 && o3) return bic_p_p_pp(ctx, dec); // -> bic_p_p_pp_z
	if(!op && !S && o2 && !o3) return eor_p_p_pp(ctx, dec); // -> eor_p_p_pp_z
	if(!op && !S && o2 && o3) return sel_p_p_pp(ctx, dec); // -> sel_p_p_pp_
	if(!op && S && !o2 && !o3) return and_p_p_pp(ctx, dec); // -> ands_p_p_pp_z
	if(!op && S && !o2 && o3) return bic_p_p_pp(ctx, dec); // -> bics_p_p_pp_z
	if(!op && S && o2 && !o3) return eor_p_p_pp(ctx, dec); // -> eors_p_p_pp_z
	if(!op && S && o2 && o3) UNALLOCATED(ENC_UNALLOCATED_207);
	if(op && !S && !o2 && !o3) return orr_p_p_pp(ctx, dec); // -> orr_p_p_pp_z
	if(op && !S && !o2 && o3) return orn_p_p_pp(ctx, dec); // -> orn_p_p_pp_z
	if(op && !S && o2 && !o3) return nor_p_p_pp(ctx, dec); // -> nor_p_p_pp_z
	if(op && !S && o2 && o3) return nand_p_p_pp(ctx, dec); // -> nand_p_p_pp_z
	if(op && S && !o2 && !o3) return orr_p_p_pp(ctx, dec); // -> orrs_p_p_pp_z
	if(op && S && !o2 && o3) return orn_p_p_pp(ctx, dec); // -> orns_p_p_pp_z
	if(op && S && o2 && !o3) return nor_p_p_pp(ctx, dec); // -> nors_p_p_pp_z
	if(op && S && o2 && o3) return nand_p_p_pp(ctx, dec); // -> nands_p_p_pp_z
	UNMATCHED;
}

int decode_iclass_sve_int_brkp(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1, B=(INSWORD>>4)&1;
	if(!op && !S && !B) return brkpa_p_p_pp(ctx, dec); // -> brkpa_p_p_pp_
	if(!op && !S && B) return brkpb_p_p_pp(ctx, dec); // -> brkpb_p_p_pp_
	if(!op && S && !B) return brkpa_p_p_pp(ctx, dec); // -> brkpas_p_p_pp_
	if(!op && S && B) return brkpb_p_p_pp(ctx, dec); // -> brkpbs_p_p_pp_
	if(op) UNALLOCATED(ENC_UNALLOCATED_217);
	UNMATCHED;
}

int decode_iclass_sve_int_break(context *ctx, Instruction *dec)
{
	uint32_t B=(INSWORD>>23)&1, S=(INSWORD>>22)&1, M=(INSWORD>>4)&1;
	if(!B && S && !M) return brka_p_p_p(ctx, dec); // -> brkas_p_p_p_z
	if(B && S && !M) return brkb_p_p_p(ctx, dec); // -> brkbs_p_p_p_z
	if(S && M) UNALLOCATED(ENC_UNALLOCATED_208);
	if(!B && !S) return brka_p_p_p(ctx, dec); // -> brka_p_p_p_
	if(B && !S) return brkb_p_p_p(ctx, dec); // -> brkb_p_p_p_
	UNMATCHED;
}

int decode_iclass_sve_int_brkn(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>22)&1;
	if(!S) return brkn_p_p_pp(ctx, dec); // -> brkn_p_p_pp_
	if(S) return brkn_p_p_pp(ctx, dec); // -> brkns_p_p_pp_
	UNMATCHED;
}

int decode_iclass_sve_int_pfirst(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1;
	if(!op && !S) UNALLOCATED(ENC_UNALLOCATED_179);
	if(!op && S) return pfirst_p_p_p(ctx, dec); // -> pfirst_p_p_p_
	if(op) UNALLOCATED(ENC_UNALLOCATED_219);
	UNMATCHED;
}

int decode_iclass_sve_int_ptrue(context *ctx, Instruction *dec)
{
	uint32_t S=(INSWORD>>16)&1;
	if(!S) return ptrue_p_s(ctx, dec); // -> ptrue_p_s_
	if(S) return ptrue_p_s(ctx, dec); // -> ptrues_p_s_
	UNMATCHED;
}

int decode_iclass_sve_int_pnext(context *ctx, Instruction *dec)
{
	return pnext_p_p_p(ctx, dec);
}

int decode_iclass_sve_int_rdffr(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1;
	if(!op && !S) return rdffr_p_p_f(ctx, dec); // -> rdffr_p_p_f_
	if(!op && S) return rdffr_p_p_f(ctx, dec); // -> rdffrs_p_p_f_
	if(op) UNALLOCATED(ENC_UNALLOCATED_221);
	UNMATCHED;
}

int decode_iclass_sve_int_rdffr_2(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1;
	if(!op && !S) return rdffr_p_f(ctx, dec); // -> rdffr_p_f_
	if(!op && S) UNALLOCATED(ENC_UNALLOCATED_214);
	if(op) UNALLOCATED(ENC_UNALLOCATED_222);
	UNMATCHED;
}

int decode_iclass_sve_int_ptest(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1, opc2=INSWORD&15;
	if(!op && S && !opc2) return ptest_p_p(ctx, dec); // -> ptest_p_p_
	if(!op && S && opc2==1) UNALLOCATED(ENC_UNALLOCATED_209);
	if(!op && S && (opc2&14)==2) UNALLOCATED(ENC_UNALLOCATED_210);
	if(!op && S && (opc2&12)==4) UNALLOCATED(ENC_UNALLOCATED_211);
	if(!op && S && (opc2&8)==8) UNALLOCATED(ENC_UNALLOCATED_212);
	if(!op && !S) UNALLOCATED(ENC_UNALLOCATED_178);
	if(op) UNALLOCATED(ENC_UNALLOCATED_218);
	UNMATCHED;
}

int decode_iclass_sve_int_pfalse(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, S=(INSWORD>>22)&1;
	if(!op && !S) return pfalse_p(ctx, dec); // -> pfalse_p_
	if(!op && S) UNALLOCATED(ENC_UNALLOCATED_213);
	if(op) UNALLOCATED(ENC_UNALLOCATED_220);
	UNMATCHED;
}

int decode_iclass_sve_int_scmp_vi(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>15)&1, o2=(INSWORD>>13)&1, ne=(INSWORD>>4)&1;
	if(!op && !o2 && !ne) return cmpeq_p_p_zi(ctx, dec); // -> cmpge_p_p_zi_
	if(!op && !o2 && ne) return cmpeq_p_p_zi(ctx, dec); // -> cmpgt_p_p_zi_
	if(!op && o2 && !ne) return cmpeq_p_p_zi(ctx, dec); // -> cmplt_p_p_zi_
	if(!op && o2 && ne) return cmpeq_p_p_zi(ctx, dec); // -> cmple_p_p_zi_
	if(op && !o2 && !ne) return cmpeq_p_p_zi(ctx, dec); // -> cmpeq_p_p_zi_
	if(op && !o2 && ne) return cmpeq_p_p_zi(ctx, dec); // -> cmpne_p_p_zi_
	if(op && o2) UNALLOCATED(ENC_UNALLOCATED_177);
	UNMATCHED;
}

int decode_iclass_sve_int_pcount_pred(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7, o2=(INSWORD>>9)&1;
	if(!opc && !o2) return cntp_r_p_p(ctx, dec); // -> cntp_r_p_p_
	if(!opc && o2) UNALLOCATED(ENC_UNALLOCATED_182);
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_183);
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_184);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_186);
	UNMATCHED;
}

int decode_iclass_sve_int_count_r(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>17)&1, D=(INSWORD>>16)&1, opc2=(INSWORD>>9)&3;
	if(!op && !D && !opc2) return incp_r_p_r(ctx, dec); // -> incp_r_p_r_
	if(!op && D && !opc2) return decp_r_p_r(ctx, dec); // -> decp_r_p_r_
	if(!op && opc2==1) UNALLOCATED(ENC_UNALLOCATED_193);
	if(!op && (opc2&2)==2) UNALLOCATED(ENC_UNALLOCATED_194);
	if(op) UNALLOCATED(ENC_UNALLOCATED_197);
	UNMATCHED;
}

int decode_iclass_sve_int_count_v(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>17)&1, D=(INSWORD>>16)&1, opc2=(INSWORD>>9)&3;
	if(!op && !D && !opc2) return incp_z_p_z(ctx, dec); // -> incp_z_p_z_
	if(!op && D && !opc2) return decp_z_p_z(ctx, dec); // -> decp_z_p_z_
	if(!op && opc2==1) UNALLOCATED(ENC_UNALLOCATED_191);
	if(!op && (opc2&2)==2) UNALLOCATED(ENC_UNALLOCATED_192);
	if(op) UNALLOCATED(ENC_UNALLOCATED_196);
	UNMATCHED;
}

int decode_iclass_sve_int_count_r_sat(context *ctx, Instruction *dec)
{
	uint32_t D=(INSWORD>>17)&1, U=(INSWORD>>16)&1, sf=(INSWORD>>10)&1, op=(INSWORD>>9)&1;
	if(!D && !U && !sf && !op) return sqincp_r_p_r(ctx, dec); // -> sqincp_r_p_r_sx
	if(!D && !U && sf && !op) return sqincp_r_p_r(ctx, dec); // -> sqincp_r_p_r_x
	if(!D && U && !sf && !op) return uqincp_r_p_r(ctx, dec); // -> uqincp_r_p_r_uw
	if(!D && U && sf && !op) return uqincp_r_p_r(ctx, dec); // -> uqincp_r_p_r_x
	if(D && !U && !sf && !op) return sqdecp_r_p_r(ctx, dec); // -> sqdecp_r_p_r_sx
	if(D && !U && sf && !op) return sqdecp_r_p_r(ctx, dec); // -> sqdecp_r_p_r_x
	if(D && U && !sf && !op) return uqdecp_r_p_r(ctx, dec); // -> uqdecp_r_p_r_uw
	if(D && U && sf && !op) return uqdecp_r_p_r(ctx, dec); // -> uqdecp_r_p_r_x
	if(op) UNALLOCATED(ENC_UNALLOCATED_189);
	UNMATCHED;
}

int decode_iclass_sve_int_count_v_sat(context *ctx, Instruction *dec)
{
	uint32_t D=(INSWORD>>17)&1, U=(INSWORD>>16)&1, opc=(INSWORD>>9)&3;
	if(!D && !U && !opc) return sqincp_z_p_z(ctx, dec); // -> sqincp_z_p_z_
	if(!D && U && !opc) return uqincp_z_p_z(ctx, dec); // -> uqincp_z_p_z_
	if(D && !U && !opc) return sqdecp_z_p_z(ctx, dec); // -> sqdecp_z_p_z_
	if(D && U && !opc) return uqdecp_z_p_z(ctx, dec); // -> uqdecp_z_p_z_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_187);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_188);
	UNMATCHED;
}

int decode_iclass_sve_int_setffr(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc) return setffr_f(ctx, dec); // -> setffr_f_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_216);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_224);
	UNMATCHED;
}

int decode_iclass_sve_int_wrffr(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc) return wrffr_f_p(ctx, dec); // -> wrffr_f_p_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_215);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_223);
	UNMATCHED;
}

int decode_iclass_sve_int_cterm(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>23)&1, ne=(INSWORD>>4)&1;
	if(op && !ne) return ctermeq_rr(ctx, dec); // -> ctermeq_rr_
	if(op && ne) return ctermeq_rr(ctx, dec); // -> ctermne_rr_
	if(!op) UNALLOCATED(ENC_UNALLOCATED_181);
	UNMATCHED;
}

int decode_iclass_sve_int_while_rr(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>11)&1, lt=(INSWORD>>10)&1, eq=(INSWORD>>4)&1;
	if(!U && lt && !eq) return whilelt_p_p_rr(ctx, dec); // -> whilelt_p_p_rr_
	if(!U && lt && eq) return whilele_p_p_rr(ctx, dec); // -> whilele_p_p_rr_
	if(U && lt && !eq) return whilelo_p_p_rr(ctx, dec); // -> whilelo_p_p_rr_
	if(U && lt && eq) return whilels_p_p_rr(ctx, dec); // -> whilels_p_p_rr_
	if(!lt) UNALLOCATED(ENC_UNALLOCATED_180);
	UNMATCHED;
}

int decode_iclass_sve_int_dup_fpimm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3, o2=(INSWORD>>13)&1;
	if(!opc && !o2) return fdup_z_i(ctx, dec); // -> fdup_z_i_
	if(!opc && o2) UNALLOCATED(ENC_UNALLOCATED_202);
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_204);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_206);
	UNMATCHED;
}

int decode_iclass_sve_int_dup_imm(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>17)&3;
	if(!opc) return dup_z_i(ctx, dec); // -> dup_z_i_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_203);
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_205);
	UNMATCHED;
}

int decode_iclass_sve_int_arith_imm0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return add_z_zi(ctx, dec); // -> add_z_zi_
	if(opc==1) return sub_z_zi(ctx, dec); // -> sub_z_zi_
	if(opc==2) UNALLOCATED(ENC_UNALLOCATED_185);
	if(opc==3) return subr_z_zi(ctx, dec); // -> subr_z_zi_
	if(opc==4) return sqadd_z_zi(ctx, dec); // -> sqadd_z_zi_
	if(opc==5) return uqadd_z_zi(ctx, dec); // -> uqadd_z_zi_
	if(opc==6) return sqsub_z_zi(ctx, dec); // -> sqsub_z_zi_
	if(opc==7) return uqsub_z_zi(ctx, dec); // -> uqsub_z_zi_
	UNMATCHED;
}

int decode_iclass_sve_int_arith_imm1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7, o2=(INSWORD>>13)&1;
	if(!opc && !o2) return smax_z_zi(ctx, dec); // -> smax_z_zi_
	if(opc==1 && !o2) return umax_z_zi(ctx, dec); // -> umax_z_zi_
	if(opc==2 && !o2) return smin_z_zi(ctx, dec); // -> smin_z_zi_
	if(opc==3 && !o2) return umin_z_zi(ctx, dec); // -> umin_z_zi_
	if(!(opc&4) && o2) UNALLOCATED(ENC_UNALLOCATED_190);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_195);
	UNMATCHED;
}

int decode_iclass_sve_int_arith_imm2(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7, o2=(INSWORD>>13)&1;
	if(!opc && !o2) return mul_z_zi(ctx, dec); // -> mul_z_zi_
	if(!opc && o2) UNALLOCATED(ENC_UNALLOCATED_198);
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_199);
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_200);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_201);
	UNMATCHED;
}

int decode_iclass_sve_intx_dot(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>10)&1;
	if(!U) return sdot_z_zzz(ctx, dec); // -> sdot_z_zzz_
	if(U) return udot_z_zzz(ctx, dec); // -> udot_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_intx_mixed_dot(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2) return usdot_z_zzz(ctx, dec); // -> usdot_z_zzz_s
	if(size==3) UNALLOCATED(ENC_UNALLOCATED_228);
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_225);
	UNMATCHED;
}

int decode_iclass_sve_intx_dot_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, U=(INSWORD>>10)&1;
	if(size==2 && !U) return sdot_z_zzzi(ctx, dec); // -> sdot_z_zzzi_s
	if(size==2 && U) return udot_z_zzzi(ctx, dec); // -> udot_z_zzzi_s
	if(size==3 && !U) return sdot_z_zzzi(ctx, dec); // -> sdot_z_zzzi_d
	if(size==3 && U) return udot_z_zzzi(ctx, dec); // -> udot_z_zzzi_d
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_226);
	UNMATCHED;
}

int decode_iclass_sve_intx_mixed_dot_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, U=(INSWORD>>10)&1;
	if(size==2 && !U) return usdot_z_zzzi(ctx, dec); // -> usdot_z_zzzi_s
	if(size==2 && U) return sudot_z_zzzi(ctx, dec); // -> sudot_z_zzzi_s
	if(size==3) UNALLOCATED(ENC_UNALLOCATED_229);
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_227);
	UNMATCHED;
}

int decode_iclass_sve_intx_mmla(context *ctx, Instruction *dec)
{
	uint32_t uns=(INSWORD>>22)&3;
	if(!uns) return smmla_z_zzz(ctx, dec); // -> smmla_z_zzz_
	if(uns==1) UNALLOCATED(ENC_UNALLOCATED_230);
	if(uns==2) return usmmla_z_zzz(ctx, dec); // -> usmmla_z_zzz_
	if(uns==3) return ummla_z_zzz(ctx, dec); // -> ummla_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_fp_fcadd(context *ctx, Instruction *dec)
{
	return fcadd_z_p_zz(ctx, dec);
}

int decode_iclass_sve_fp_fcvt2(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>16)&3;
	if(opc==2 && opc2==2) return bfcvtnt_z_p_z(ctx, dec); // -> bfcvtnt_z_p_z_s2bf
	if(opc==2 && opc2==3) UNALLOCATED(ENC_UNALLOCATED_237);
	if(opc==2 && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_236);
	if(opc==3) UNALLOCATED(ENC_UNALLOCATED_240);
	if(!(opc&2)) UNALLOCATED(ENC_UNALLOCATED_231);
	UNMATCHED;
}

int decode_iclass_sve_fp_fcmla(context *ctx, Instruction *dec)
{
	return fcmla_z_p_zzz(ctx, dec);
}

int decode_iclass_sve_fp_fma_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3, op=(INSWORD>>10)&1;
	if(size==2 && !op) return fmla_z_zzzi(ctx, dec); // -> fmla_z_zzzi_s
	if(size==2 && op) return fmls_z_zzzi(ctx, dec); // -> fmls_z_zzzi_s
	if(size==3 && !op) return fmla_z_zzzi(ctx, dec); // -> fmla_z_zzzi_d
	if(size==3 && op) return fmls_z_zzzi(ctx, dec); // -> fmls_z_zzzi_d
	if(!(size&2) && !op) return fmla_z_zzzi(ctx, dec); // -> fmla_z_zzzi_h
	if(!(size&2) && op) return fmls_z_zzzi(ctx, dec); // -> fmls_z_zzzi_h
	UNMATCHED;
}

int decode_iclass_sve_fp_fcmla_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2) return fcmla_z_zzzi(ctx, dec); // -> fcmla_z_zzzi_h
	if(size==3) return fcmla_z_zzzi(ctx, dec); // -> fcmla_z_zzzi_s
	if(!(size&2)) UNALLOCATED(ENC_UNALLOCATED_232);
	UNMATCHED;
}

int decode_iclass_sve_fp_fmul_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t size=(INSWORD>>22)&3;
	if(size==2) return fmul_z_zzi(ctx, dec); // -> fmul_z_zzi_s
	if(size==3) return fmul_z_zzi(ctx, dec); // -> fmul_z_zzi_d
	if(!(size&2)) return fmul_z_zzi(ctx, dec); // -> fmul_z_zzi_h
	UNMATCHED;
}

int decode_iclass_sve_fp_fdot_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1;
	if(!op) UNALLOCATED(ENC_UNALLOCATED_233);
	if(op) return bfdot_z_zzzi(ctx, dec); // -> bfdot_z_zzzi_
	UNMATCHED;
}

int decode_iclass_sve_fp_fma_long_by_indexed_elem(context *ctx, Instruction *dec)
{
	uint32_t o2=(INSWORD>>22)&1, op=(INSWORD>>13)&1, T=(INSWORD>>10)&1;
	if(o2 && !op && !T) return bfmlalb_z_zzzi(ctx, dec); // -> bfmlalb_z_zzzi_
	if(o2 && !op && T) return bfmlalt_z_zzzi(ctx, dec); // -> bfmlalt_z_zzzi_
	if(o2 && op) UNALLOCATED(ENC_UNALLOCATED_241);
	if(!o2) UNALLOCATED(ENC_UNALLOCATED_238);
	UNMATCHED;
}

int decode_iclass_sve_fp_fdot(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>22)&1;
	if(!op) UNALLOCATED(ENC_UNALLOCATED_234);
	if(op) return bfdot_z_zzz(ctx, dec); // -> bfdot_z_zzz_
	UNMATCHED;
}

int decode_iclass_sve_fp_fma_long(context *ctx, Instruction *dec)
{
	uint32_t o2=(INSWORD>>22)&1, op=(INSWORD>>13)&1, T=(INSWORD>>10)&1;
	if(o2 && !op && !T) return bfmlalb_z_zzz(ctx, dec); // -> bfmlalb_z_zzz_
	if(o2 && !op && T) return bfmlalt_z_zzz(ctx, dec); // -> bfmlalt_z_zzz_
	if(o2 && op) UNALLOCATED(ENC_UNALLOCATED_242);
	if(!o2) UNALLOCATED(ENC_UNALLOCATED_239);
	UNMATCHED;
}

int decode_iclass_sve_fp_fmmla(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3;
	if(!opc) UNALLOCATED(ENC_UNALLOCATED_235);
	if(opc==1) return bfmmla_z_zzz(ctx, dec); // -> bfmmla_z_zzz_
	if(opc==2) return fmmla_z_zzz(ctx, dec); // -> fmmla_z_zzz_s
	if(opc==3) return fmmla_z_zzz(ctx, dec); // -> fmmla_z_zzz_d
	UNMATCHED;
}

int decode_iclass_sve_fp_fast_red(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return faddv_v_p_z(ctx, dec); // -> faddv_v_p_z_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_245);
	if(opc==4) return fmaxnmv_v_p_z(ctx, dec); // -> fmaxnmv_v_p_z_
	if(opc==5) return fminnmv_v_p_z(ctx, dec); // -> fminnmv_v_p_z_
	if(opc==6) return fmaxv_v_p_z(ctx, dec); // -> fmaxv_v_p_z_
	if(opc==7) return fminv_v_p_z(ctx, dec); // -> fminv_v_p_z_
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_246);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_u_zd(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(opc==6) return frecpe_z_z(ctx, dec); // -> frecpe_z_z_
	if(opc==7) return frsqrte_z_z(ctx, dec); // -> frsqrte_z_z_
	if((opc&6)==4) UNALLOCATED(ENC_UNALLOCATED_251);
	if(!(opc&4)) UNALLOCATED(ENC_UNALLOCATED_248);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_pd(context *ctx, Instruction *dec)
{
	uint32_t eq=(INSWORD>>17)&1, lt=(INSWORD>>16)&1, ne=(INSWORD>>4)&1;
	if(!eq && !lt && !ne) return fcmeq_p_p_z0(ctx, dec); // -> fcmge_p_p_z0_
	if(!eq && !lt && ne) return fcmeq_p_p_z0(ctx, dec); // -> fcmgt_p_p_z0_
	if(!eq && lt && !ne) return fcmeq_p_p_z0(ctx, dec); // -> fcmlt_p_p_z0_
	if(!eq && lt && ne) return fcmeq_p_p_z0(ctx, dec); // -> fcmle_p_p_z0_
	if(eq && !lt && !ne) return fcmeq_p_p_z0(ctx, dec); // -> fcmeq_p_p_z0_
	if(eq && lt && !ne) return fcmeq_p_p_z0(ctx, dec); // -> fcmne_p_p_z0_
	if(eq && ne) UNALLOCATED(ENC_UNALLOCATED_255);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_vd(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return fadda_v_p_z(ctx, dec); // -> fadda_v_p_z_
	if(opc==1) UNALLOCATED(ENC_UNALLOCATED_257);
	if((opc&6)==2) UNALLOCATED(ENC_UNALLOCATED_258);
	if((opc&4)==4) UNALLOCATED(ENC_UNALLOCATED_259);
	UNMATCHED;
}

int decode_iclass_sve_fp_3op_u_zd(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>10)&7;
	if(!opc) return fadd_z_zz(ctx, dec); // -> fadd_z_zz_
	if(opc==1) return fsub_z_zz(ctx, dec); // -> fsub_z_zz_
	if(opc==2) return fmul_z_zz(ctx, dec); // -> fmul_z_zz_
	if(opc==3) return ftsmul_z_zz(ctx, dec); // -> ftsmul_z_zz_
	if(opc==6) return frecps_z_zz(ctx, dec); // -> frecps_z_zz_
	if(opc==7) return frsqrts_z_zz(ctx, dec); // -> frsqrts_z_zz_
	if((opc&6)==4) UNALLOCATED(ENC_UNALLOCATED_243);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zds(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&15;
	if(!opc) return fadd_z_p_zz(ctx, dec); // -> fadd_z_p_zz_
	if(opc==1) return fsub_z_p_zz(ctx, dec); // -> fsub_z_p_zz_
	if(opc==2) return fmul_z_p_zz(ctx, dec); // -> fmul_z_p_zz_
	if(opc==3) return fsubr_z_p_zz(ctx, dec); // -> fsubr_z_p_zz_
	if(opc==4) return fmaxnm_z_p_zz(ctx, dec); // -> fmaxnm_z_p_zz_
	if(opc==5) return fminnm_z_p_zz(ctx, dec); // -> fminnm_z_p_zz_
	if(opc==6) return fmax_z_p_zz(ctx, dec); // -> fmax_z_p_zz_
	if(opc==7) return fmin_z_p_zz(ctx, dec); // -> fmin_z_p_zz_
	if(opc==8) return fabd_z_p_zz(ctx, dec); // -> fabd_z_p_zz_
	if(opc==9) return fscale_z_p_zz(ctx, dec); // -> fscale_z_p_zz_
	if(opc==10) return fmulx_z_p_zz(ctx, dec); // -> fmulx_z_p_zz_
	if(opc==11) UNALLOCATED(ENC_UNALLOCATED_250);
	if(opc==12) return fdivr_z_p_zz(ctx, dec); // -> fdivr_z_p_zz_
	if(opc==13) return fdiv_z_p_zz(ctx, dec); // -> fdiv_z_p_zz_
	if((opc&14)==14) UNALLOCATED(ENC_UNALLOCATED_252);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_i_p_zds(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return fadd_z_p_zs(ctx, dec); // -> fadd_z_p_zs_
	if(opc==1) return fsub_z_p_zs(ctx, dec); // -> fsub_z_p_zs_
	if(opc==2) return fmul_z_p_zs(ctx, dec); // -> fmul_z_p_zs_
	if(opc==3) return fsubr_z_p_zs(ctx, dec); // -> fsubr_z_p_zs_
	if(opc==4) return fmaxnm_z_p_zs(ctx, dec); // -> fmaxnm_z_p_zs_
	if(opc==5) return fminnm_z_p_zs(ctx, dec); // -> fminnm_z_p_zs_
	if(opc==6) return fmax_z_p_zs(ctx, dec); // -> fmax_z_p_zs_
	if(opc==7) return fmin_z_p_zs(ctx, dec); // -> fmin_z_p_zs_
	UNMATCHED;
}

int decode_iclass_sve_fp_ftmad(context *ctx, Instruction *dec)
{
	return ftmad_z_zzi(ctx, dec);
}

int decode_iclass_sve_fp_2op_p_zd_b_0(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>16)&3;
	if(opc==2 && !opc2) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_s2h
	if(opc==2 && opc2==1) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_h2s
	if(opc==2 && opc2==2) return bfcvt_z_p_z(ctx, dec); // -> bfcvt_z_p_z_s2bf
	if(opc==2 && opc2==3) UNALLOCATED(ENC_UNALLOCATED_262);
	if(opc==3 && !opc2) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_d2h
	if(opc==3 && opc2==1) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_h2d
	if(opc==3 && opc2==2) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_d2s
	if(opc==3 && opc2==3) return fcvt_z_p_z(ctx, dec); // -> fcvt_z_p_z_s2d
	if(!(opc&2)) UNALLOCATED(ENC_UNALLOCATED_249);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_d(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(opc==1 && opc2==1 && !U) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162h
	if(opc==1 && opc2==1 && U) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162h
	if(opc==1 && opc2==2 && !U) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162w
	if(opc==1 && opc2==2 && U) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162w
	if(opc==1 && opc2==3 && !U) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_fp162x
	if(opc==1 && opc2==3 && U) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_fp162x
	if(opc==2 && opc2==2 && !U) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_s2w
	if(opc==2 && opc2==2 && U) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_s2w
	if(opc==3 && !opc2 && !U) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_d2w
	if(opc==3 && !opc2 && U) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_d2w
	if(opc==3 && opc2==2 && !U) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_s2x
	if(opc==3 && opc2==2 && U) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_s2x
	if(opc==3 && opc2==3 && !U) return fcvtzs_z_p_z(ctx, dec); // -> fcvtzs_z_p_z_d2x
	if(opc==3 && opc2==3 && U) return fcvtzu_z_p_z(ctx, dec); // -> fcvtzu_z_p_z_d2x
	if(opc==1 && !opc2) UNALLOCATED(ENC_UNALLOCATED_261);
	if(opc==2 && opc2==3) UNALLOCATED(ENC_UNALLOCATED_266);
	if(opc==3 && opc2==1) UNALLOCATED(ENC_UNALLOCATED_268);
	if(opc==2 && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_265);
	if(!opc) UNALLOCATED(ENC_UNALLOCATED_256);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_a(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&7;
	if(!opc) return frinta_z_p_z(ctx, dec); // -> frintn_z_p_z_
	if(opc==1) return frinta_z_p_z(ctx, dec); // -> frintp_z_p_z_
	if(opc==2) return frinta_z_p_z(ctx, dec); // -> frintm_z_p_z_
	if(opc==3) return frinta_z_p_z(ctx, dec); // -> frintz_z_p_z_
	if(opc==4) return frinta_z_p_z(ctx, dec); // -> frinta_z_p_z_
	if(opc==5) UNALLOCATED(ENC_UNALLOCATED_247);
	if(opc==6) return frinta_z_p_z(ctx, dec); // -> frintx_z_p_z_
	if(opc==7) return frinta_z_p_z(ctx, dec); // -> frinti_z_p_z_
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_b_1(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>16)&3;
	if(!opc) return frecpx_z_p_z(ctx, dec); // -> frecpx_z_p_z_
	if(opc==1) return fsqrt_z_p_z(ctx, dec); // -> fsqrt_z_p_z_
	if((opc&2)==2) UNALLOCATED(ENC_UNALLOCATED_253);
	UNMATCHED;
}

int decode_iclass_sve_fp_2op_p_zd_c(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&3, opc2=(INSWORD>>17)&3, U=(INSWORD>>16)&1;
	if(opc==1 && opc2==1 && !U) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_h2fp16
	if(opc==1 && opc2==1 && U) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_h2fp16
	if(opc==1 && opc2==2 && !U) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2fp16
	if(opc==1 && opc2==2 && U) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2fp16
	if(opc==1 && opc2==3 && !U) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2fp16
	if(opc==1 && opc2==3 && U) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2fp16
	if(opc==2 && opc2==2 && !U) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2s
	if(opc==2 && opc2==2 && U) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2s
	if(opc==3 && !opc2 && !U) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_w2d
	if(opc==3 && !opc2 && U) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_w2d
	if(opc==3 && opc2==2 && !U) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2s
	if(opc==3 && opc2==2 && U) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2s
	if(opc==3 && opc2==3 && !U) return scvtf_z_p_z(ctx, dec); // -> scvtf_z_p_z_x2d
	if(opc==3 && opc2==3 && U) return ucvtf_z_p_z(ctx, dec); // -> ucvtf_z_p_z_x2d
	if(opc==1 && !opc2) UNALLOCATED(ENC_UNALLOCATED_260);
	if(opc==2 && opc2==3) UNALLOCATED(ENC_UNALLOCATED_264);
	if(opc==3 && opc2==1) UNALLOCATED(ENC_UNALLOCATED_267);
	if(opc==2 && !(opc2&2)) UNALLOCATED(ENC_UNALLOCATED_263);
	if(!opc) UNALLOCATED(ENC_UNALLOCATED_254);
	UNMATCHED;
}

int decode_iclass_sve_fp_3op_p_pd(context *ctx, Instruction *dec)
{
	uint32_t op=(INSWORD>>15)&1, o2=(INSWORD>>13)&1, o3=(INSWORD>>4)&1;
	if(!op && !o2 && !o3) return fcmeq_p_p_zz(ctx, dec); // -> fcmge_p_p_zz_
	if(!op && !o2 && o3) return fcmeq_p_p_zz(ctx, dec); // -> fcmgt_p_p_zz_
	if(!op && o2 && !o3) return fcmeq_p_p_zz(ctx, dec); // -> fcmeq_p_p_zz_
	if(!op && o2 && o3) return fcmeq_p_p_zz(ctx, dec); // -> fcmne_p_p_zz_
	if(op && !o2 && !o3) return fcmeq_p_p_zz(ctx, dec); // -> fcmuo_p_p_zz_
	if(op && !o2 && o3) return facge_p_p_zz(ctx, dec); // -> facge_p_p_zz_
	if(op && o2 && !o3) UNALLOCATED(ENC_UNALLOCATED_244);
	if(op && o2 && o3) return facge_p_p_zz(ctx, dec); // -> facgt_p_p_zz_
	UNMATCHED;
}

int decode_iclass_sve_fp_3op_p_zds_a(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>13)&3;
	if(!opc) return fmla_z_p_zzz(ctx, dec); // -> fmla_z_p_zzz_
	if(opc==1) return fmls_z_p_zzz(ctx, dec); // -> fmls_z_p_zzz_
	if(opc==2) return fnmla_z_p_zzz(ctx, dec); // -> fnmla_z_p_zzz_
	if(opc==3) return fnmls_z_p_zzz(ctx, dec); // -> fnmls_z_p_zzz_
	UNMATCHED;
}

int decode_iclass_sve_fp_3op_p_zds_b(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>13)&3;
	if(!opc) return fmad_z_p_zzz(ctx, dec); // -> fmad_z_p_zzz_
	if(opc==1) return fmsb_z_p_zzz(ctx, dec); // -> fmsb_z_p_zzz_
	if(opc==2) return fnmad_z_p_zzz(ctx, dec); // -> fnmad_z_p_zzz_
	if(opc==3) return fnmsb_z_p_zzz(ctx, dec); // -> fnmsb_z_p_zzz_
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gld_vs(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!opc && !U && !ff) return ld1sb_z_p_bz(ctx, dec); // -> ld1sb_z_p_bz_s_x32_unscaled
	if(!opc && !U && ff) return ldff1sb_z_p_bz(ctx, dec); // -> ldff1sb_z_p_bz_s_x32_unscaled
	if(!opc && U && !ff) return ld1b_z_p_bz(ctx, dec); // -> ld1b_z_p_bz_s_x32_unscaled
	if(!opc && U && ff) return ldff1b_z_p_bz(ctx, dec); // -> ldff1b_z_p_bz_s_x32_unscaled
	if(opc==1 && !U && !ff) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_s_x32_unscaled
	if(opc==1 && !U && ff) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_s_x32_unscaled
	if(opc==1 && U && !ff) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_s_x32_unscaled
	if(opc==1 && U && ff) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_s_x32_unscaled
	if(opc==2 && U && !ff) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_s_x32_unscaled
	if(opc==2 && U && ff) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_s_x32_unscaled
	if(opc==2 && !U) UNALLOCATED(ENC_UNALLOCATED_269);
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gld_vi(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!msz && !U && !ff) return ld1sb_z_p_ai(ctx, dec); // -> ld1sb_z_p_ai_s
	if(!msz && !U && ff) return ldff1sb_z_p_ai(ctx, dec); // -> ldff1sb_z_p_ai_s
	if(!msz && U && !ff) return ld1b_z_p_ai(ctx, dec); // -> ld1b_z_p_ai_s
	if(!msz && U && ff) return ldff1b_z_p_ai(ctx, dec); // -> ldff1b_z_p_ai_s
	if(msz==1 && !U && !ff) return ld1sh_z_p_ai(ctx, dec); // -> ld1sh_z_p_ai_s
	if(msz==1 && !U && ff) return ldff1sh_z_p_ai(ctx, dec); // -> ldff1sh_z_p_ai_s
	if(msz==1 && U && !ff) return ld1h_z_p_ai(ctx, dec); // -> ld1h_z_p_ai_s
	if(msz==1 && U && ff) return ldff1h_z_p_ai(ctx, dec); // -> ldff1h_z_p_ai_s
	if(msz==2 && U && !ff) return ld1w_z_p_ai(ctx, dec); // -> ld1w_z_p_ai_s
	if(msz==2 && U && ff) return ldff1w_z_p_ai(ctx, dec); // -> ldff1w_z_p_ai_s
	if(msz==2 && !U) UNALLOCATED(ENC_UNALLOCATED_271);
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_272);
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gld_sv_a(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!U && !ff) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_s_x32_scaled
	if(!U && ff) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_s_x32_scaled
	if(U && !ff) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_s_x32_scaled
	if(U && ff) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_s_x32_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_gld_sv_b(context *ctx, Instruction *dec)
{
	uint32_t U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(U && !ff) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_s_x32_scaled
	if(U && ff) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_s_x32_scaled
	if(!U) UNALLOCATED(ENC_UNALLOCATED_270);
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_prfm_sv(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3;
	if(!msz) return prfb_i_p_bz(ctx, dec); // -> prfb_i_p_bz_s_x32_scaled
	if(msz==1) return prfh_i_p_bz(ctx, dec); // -> prfh_i_p_bz_s_x32_scaled
	if(msz==2) return prfw_i_p_bz(ctx, dec); // -> prfw_i_p_bz_s_x32_scaled
	if(msz==3) return prfd_i_p_bz(ctx, dec); // -> prfd_i_p_bz_s_x32_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_prfm_vi(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return prfb_i_p_ai(ctx, dec); // -> prfb_i_p_ai_s
	if(msz==1) return prfh_i_p_ai(ctx, dec); // -> prfh_i_p_ai_s
	if(msz==2) return prfw_i_p_ai(ctx, dec); // -> prfw_i_p_ai_s
	if(msz==3) return prfd_i_p_ai(ctx, dec); // -> prfd_i_p_ai_s
	UNMATCHED;
}

int decode_iclass_sve_mem_prfm_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3;
	if(!msz) return prfb_i_p_bi(ctx, dec); // -> prfb_i_p_bi_s
	if(msz==1) return prfh_i_p_bi(ctx, dec); // -> prfh_i_p_bi_s
	if(msz==2) return prfw_i_p_bi(ctx, dec); // -> prfw_i_p_bi_s
	if(msz==3) return prfd_i_p_bi(ctx, dec); // -> prfd_i_p_bi_s
	UNMATCHED;
}

int decode_iclass_sve_mem_prfm_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return prfb_i_p_br(ctx, dec); // -> prfb_i_p_br_s
	if(msz==1) return prfh_i_p_br(ctx, dec); // -> prfh_i_p_br_s
	if(msz==2) return prfw_i_p_br(ctx, dec); // -> prfw_i_p_br_s
	if(msz==3) return prfd_i_p_br(ctx, dec); // -> prfd_i_p_br_s
	UNMATCHED;
}

int decode_iclass_sve_mem_ld_dup(context *ctx, Instruction *dec)
{
	uint32_t dtypeh=(INSWORD>>23)&3, dtypel=(INSWORD>>13)&3;
	if(!dtypeh && !dtypel) return ld1rb_z_p_bi(ctx, dec); // -> ld1rb_z_p_bi_u8
	if(!dtypeh && dtypel==1) return ld1rb_z_p_bi(ctx, dec); // -> ld1rb_z_p_bi_u16
	if(!dtypeh && dtypel==2) return ld1rb_z_p_bi(ctx, dec); // -> ld1rb_z_p_bi_u32
	if(!dtypeh && dtypel==3) return ld1rb_z_p_bi(ctx, dec); // -> ld1rb_z_p_bi_u64
	if(dtypeh==1 && !dtypel) return ld1rsw_z_p_bi(ctx, dec); // -> ld1rsw_z_p_bi_s64
	if(dtypeh==1 && dtypel==1) return ld1rh_z_p_bi(ctx, dec); // -> ld1rh_z_p_bi_u16
	if(dtypeh==1 && dtypel==2) return ld1rh_z_p_bi(ctx, dec); // -> ld1rh_z_p_bi_u32
	if(dtypeh==1 && dtypel==3) return ld1rh_z_p_bi(ctx, dec); // -> ld1rh_z_p_bi_u64
	if(dtypeh==2 && !dtypel) return ld1rsh_z_p_bi(ctx, dec); // -> ld1rsh_z_p_bi_s64
	if(dtypeh==2 && dtypel==1) return ld1rsh_z_p_bi(ctx, dec); // -> ld1rsh_z_p_bi_s32
	if(dtypeh==2 && dtypel==2) return ld1rw_z_p_bi(ctx, dec); // -> ld1rw_z_p_bi_u32
	if(dtypeh==2 && dtypel==3) return ld1rw_z_p_bi(ctx, dec); // -> ld1rw_z_p_bi_u64
	if(dtypeh==3 && !dtypel) return ld1rsb_z_p_bi(ctx, dec); // -> ld1rsb_z_p_bi_s64
	if(dtypeh==3 && dtypel==1) return ld1rsb_z_p_bi(ctx, dec); // -> ld1rsb_z_p_bi_s32
	if(dtypeh==3 && dtypel==2) return ld1rsb_z_p_bi(ctx, dec); // -> ld1rsb_z_p_bi_s16
	if(dtypeh==3 && dtypel==3) return ld1rd_z_p_bi(ctx, dec); // -> ld1rd_z_p_bi_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_32b_pfill(context *ctx, Instruction *dec)
{
	return ldr_p_bi(ctx, dec);
}

int decode_iclass_sve_mem_32b_fill(context *ctx, Instruction *dec)
{
	return ldr_z_bi(ctx, dec);
}

int decode_iclass_sve_mem_cldff_ss(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>21)&15;
	if(!dtype) return ldff1b_z_p_br(ctx, dec); // -> ldff1b_z_p_br_u8
	if(dtype==1) return ldff1b_z_p_br(ctx, dec); // -> ldff1b_z_p_br_u16
	if(dtype==2) return ldff1b_z_p_br(ctx, dec); // -> ldff1b_z_p_br_u32
	if(dtype==3) return ldff1b_z_p_br(ctx, dec); // -> ldff1b_z_p_br_u64
	if(dtype==4) return ldff1sw_z_p_br(ctx, dec); // -> ldff1sw_z_p_br_s64
	if(dtype==5) return ldff1h_z_p_br(ctx, dec); // -> ldff1h_z_p_br_u16
	if(dtype==6) return ldff1h_z_p_br(ctx, dec); // -> ldff1h_z_p_br_u32
	if(dtype==7) return ldff1h_z_p_br(ctx, dec); // -> ldff1h_z_p_br_u64
	if(dtype==8) return ldff1sh_z_p_br(ctx, dec); // -> ldff1sh_z_p_br_s64
	if(dtype==9) return ldff1sh_z_p_br(ctx, dec); // -> ldff1sh_z_p_br_s32
	if(dtype==10) return ldff1w_z_p_br(ctx, dec); // -> ldff1w_z_p_br_u32
	if(dtype==11) return ldff1w_z_p_br(ctx, dec); // -> ldff1w_z_p_br_u64
	if(dtype==12) return ldff1sb_z_p_br(ctx, dec); // -> ldff1sb_z_p_br_s64
	if(dtype==13) return ldff1sb_z_p_br(ctx, dec); // -> ldff1sb_z_p_br_s32
	if(dtype==14) return ldff1sb_z_p_br(ctx, dec); // -> ldff1sb_z_p_br_s16
	if(dtype==15) return ldff1d_z_p_br(ctx, dec); // -> ldff1d_z_p_br_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_cld_si(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>21)&15;
	if(!dtype) return ld1b_z_p_bi(ctx, dec); // -> ld1b_z_p_bi_u8
	if(dtype==1) return ld1b_z_p_bi(ctx, dec); // -> ld1b_z_p_bi_u16
	if(dtype==2) return ld1b_z_p_bi(ctx, dec); // -> ld1b_z_p_bi_u32
	if(dtype==3) return ld1b_z_p_bi(ctx, dec); // -> ld1b_z_p_bi_u64
	if(dtype==4) return ld1sw_z_p_bi(ctx, dec); // -> ld1sw_z_p_bi_s64
	if(dtype==5) return ld1h_z_p_bi(ctx, dec); // -> ld1h_z_p_bi_u16
	if(dtype==6) return ld1h_z_p_bi(ctx, dec); // -> ld1h_z_p_bi_u32
	if(dtype==7) return ld1h_z_p_bi(ctx, dec); // -> ld1h_z_p_bi_u64
	if(dtype==8) return ld1sh_z_p_bi(ctx, dec); // -> ld1sh_z_p_bi_s64
	if(dtype==9) return ld1sh_z_p_bi(ctx, dec); // -> ld1sh_z_p_bi_s32
	if(dtype==10) return ld1w_z_p_bi(ctx, dec); // -> ld1w_z_p_bi_u32
	if(dtype==11) return ld1w_z_p_bi(ctx, dec); // -> ld1w_z_p_bi_u64
	if(dtype==12) return ld1sb_z_p_bi(ctx, dec); // -> ld1sb_z_p_bi_s64
	if(dtype==13) return ld1sb_z_p_bi(ctx, dec); // -> ld1sb_z_p_bi_s32
	if(dtype==14) return ld1sb_z_p_bi(ctx, dec); // -> ld1sb_z_p_bi_s16
	if(dtype==15) return ld1d_z_p_bi(ctx, dec); // -> ld1d_z_p_bi_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_cld_ss(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>21)&15;
	if(!dtype) return ld1b_z_p_br(ctx, dec); // -> ld1b_z_p_br_u8
	if(dtype==1) return ld1b_z_p_br(ctx, dec); // -> ld1b_z_p_br_u16
	if(dtype==2) return ld1b_z_p_br(ctx, dec); // -> ld1b_z_p_br_u32
	if(dtype==3) return ld1b_z_p_br(ctx, dec); // -> ld1b_z_p_br_u64
	if(dtype==4) return ld1sw_z_p_br(ctx, dec); // -> ld1sw_z_p_br_s64
	if(dtype==5) return ld1h_z_p_br(ctx, dec); // -> ld1h_z_p_br_u16
	if(dtype==6) return ld1h_z_p_br(ctx, dec); // -> ld1h_z_p_br_u32
	if(dtype==7) return ld1h_z_p_br(ctx, dec); // -> ld1h_z_p_br_u64
	if(dtype==8) return ld1sh_z_p_br(ctx, dec); // -> ld1sh_z_p_br_s64
	if(dtype==9) return ld1sh_z_p_br(ctx, dec); // -> ld1sh_z_p_br_s32
	if(dtype==10) return ld1w_z_p_br(ctx, dec); // -> ld1w_z_p_br_u32
	if(dtype==11) return ld1w_z_p_br(ctx, dec); // -> ld1w_z_p_br_u64
	if(dtype==12) return ld1sb_z_p_br(ctx, dec); // -> ld1sb_z_p_br_s64
	if(dtype==13) return ld1sb_z_p_br(ctx, dec); // -> ld1sb_z_p_br_s32
	if(dtype==14) return ld1sb_z_p_br(ctx, dec); // -> ld1sb_z_p_br_s16
	if(dtype==15) return ld1d_z_p_br(ctx, dec); // -> ld1d_z_p_br_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_cldnf_si(context *ctx, Instruction *dec)
{
	uint32_t dtype=(INSWORD>>21)&15;
	if(!dtype) return ldnf1b_z_p_bi(ctx, dec); // -> ldnf1b_z_p_bi_u8
	if(dtype==1) return ldnf1b_z_p_bi(ctx, dec); // -> ldnf1b_z_p_bi_u16
	if(dtype==2) return ldnf1b_z_p_bi(ctx, dec); // -> ldnf1b_z_p_bi_u32
	if(dtype==3) return ldnf1b_z_p_bi(ctx, dec); // -> ldnf1b_z_p_bi_u64
	if(dtype==4) return ldnf1sw_z_p_bi(ctx, dec); // -> ldnf1sw_z_p_bi_s64
	if(dtype==5) return ldnf1h_z_p_bi(ctx, dec); // -> ldnf1h_z_p_bi_u16
	if(dtype==6) return ldnf1h_z_p_bi(ctx, dec); // -> ldnf1h_z_p_bi_u32
	if(dtype==7) return ldnf1h_z_p_bi(ctx, dec); // -> ldnf1h_z_p_bi_u64
	if(dtype==8) return ldnf1sh_z_p_bi(ctx, dec); // -> ldnf1sh_z_p_bi_s64
	if(dtype==9) return ldnf1sh_z_p_bi(ctx, dec); // -> ldnf1sh_z_p_bi_s32
	if(dtype==10) return ldnf1w_z_p_bi(ctx, dec); // -> ldnf1w_z_p_bi_u32
	if(dtype==11) return ldnf1w_z_p_bi(ctx, dec); // -> ldnf1w_z_p_bi_u64
	if(dtype==12) return ldnf1sb_z_p_bi(ctx, dec); // -> ldnf1sb_z_p_bi_s64
	if(dtype==13) return ldnf1sb_z_p_bi(ctx, dec); // -> ldnf1sb_z_p_bi_s32
	if(dtype==14) return ldnf1sb_z_p_bi(ctx, dec); // -> ldnf1sb_z_p_bi_s16
	if(dtype==15) return ldnf1d_z_p_bi(ctx, dec); // -> ldnf1d_z_p_bi_u64
	UNMATCHED;
}

int decode_iclass_sve_mem_cldnt_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return ldnt1b_z_p_bi(ctx, dec); // -> ldnt1b_z_p_bi_contiguous
	if(msz==1) return ldnt1h_z_p_bi(ctx, dec); // -> ldnt1h_z_p_bi_contiguous
	if(msz==2) return ldnt1w_z_p_bi(ctx, dec); // -> ldnt1w_z_p_bi_contiguous
	if(msz==3) return ldnt1d_z_p_bi(ctx, dec); // -> ldnt1d_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_cldnt_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return ldnt1b_z_p_br(ctx, dec); // -> ldnt1b_z_p_br_contiguous
	if(msz==1) return ldnt1h_z_p_br(ctx, dec); // -> ldnt1h_z_p_br_contiguous
	if(msz==2) return ldnt1w_z_p_br(ctx, dec); // -> ldnt1w_z_p_br_contiguous
	if(msz==3) return ldnt1d_z_p_br(ctx, dec); // -> ldnt1d_z_p_br_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_ldqr_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, ssz=(INSWORD>>21)&3;
	if(!msz && !ssz) return ld1rqb_z_p_bi(ctx, dec); // -> ld1rqb_z_p_bi_u8
	if(!msz && ssz==1) return ld1rob_z_p_bi(ctx, dec); // -> ld1rob_z_p_bi_u8
	if(msz==1 && !ssz) return ld1rqh_z_p_bi(ctx, dec); // -> ld1rqh_z_p_bi_u16
	if(msz==1 && ssz==1) return ld1roh_z_p_bi(ctx, dec); // -> ld1roh_z_p_bi_u16
	if(msz==2 && !ssz) return ld1rqw_z_p_bi(ctx, dec); // -> ld1rqw_z_p_bi_u32
	if(msz==2 && ssz==1) return ld1row_z_p_bi(ctx, dec); // -> ld1row_z_p_bi_u32
	if(msz==3 && !ssz) return ld1rqd_z_p_bi(ctx, dec); // -> ld1rqd_z_p_bi_u64
	if(msz==3 && ssz==1) return ld1rod_z_p_bi(ctx, dec); // -> ld1rod_z_p_bi_u64
	if((ssz&2)==2) UNALLOCATED(ENC_UNALLOCATED_274);
	UNMATCHED;
}

int decode_iclass_sve_mem_ldqr_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, ssz=(INSWORD>>21)&3;
	if(!msz && !ssz) return ld1rqb_z_p_br(ctx, dec); // -> ld1rqb_z_p_br_contiguous
	if(!msz && ssz==1) return ld1rob_z_p_br(ctx, dec); // -> ld1rob_z_p_br_contiguous
	if(msz==1 && !ssz) return ld1rqh_z_p_br(ctx, dec); // -> ld1rqh_z_p_br_contiguous
	if(msz==1 && ssz==1) return ld1roh_z_p_br(ctx, dec); // -> ld1roh_z_p_br_contiguous
	if(msz==2 && !ssz) return ld1rqw_z_p_br(ctx, dec); // -> ld1rqw_z_p_br_contiguous
	if(msz==2 && ssz==1) return ld1row_z_p_br(ctx, dec); // -> ld1row_z_p_br_contiguous
	if(msz==3 && !ssz) return ld1rqd_z_p_br(ctx, dec); // -> ld1rqd_z_p_br_contiguous
	if(msz==3 && ssz==1) return ld1rod_z_p_br(ctx, dec); // -> ld1rod_z_p_br_contiguous
	if((ssz&2)==2) UNALLOCATED(ENC_UNALLOCATED_273);
	UNMATCHED;
}

int decode_iclass_sve_mem_eld_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3;
	if(!msz && opc==1) return ld2b_z_p_bi(ctx, dec); // -> ld2b_z_p_bi_contiguous
	if(!msz && opc==2) return ld3b_z_p_bi(ctx, dec); // -> ld3b_z_p_bi_contiguous
	if(!msz && opc==3) return ld4b_z_p_bi(ctx, dec); // -> ld4b_z_p_bi_contiguous
	if(msz==1 && opc==1) return ld2h_z_p_bi(ctx, dec); // -> ld2h_z_p_bi_contiguous
	if(msz==1 && opc==2) return ld3h_z_p_bi(ctx, dec); // -> ld3h_z_p_bi_contiguous
	if(msz==1 && opc==3) return ld4h_z_p_bi(ctx, dec); // -> ld4h_z_p_bi_contiguous
	if(msz==2 && opc==1) return ld2w_z_p_bi(ctx, dec); // -> ld2w_z_p_bi_contiguous
	if(msz==2 && opc==2) return ld3w_z_p_bi(ctx, dec); // -> ld3w_z_p_bi_contiguous
	if(msz==2 && opc==3) return ld4w_z_p_bi(ctx, dec); // -> ld4w_z_p_bi_contiguous
	if(msz==3 && opc==1) return ld2d_z_p_bi(ctx, dec); // -> ld2d_z_p_bi_contiguous
	if(msz==3 && opc==2) return ld3d_z_p_bi(ctx, dec); // -> ld3d_z_p_bi_contiguous
	if(msz==3 && opc==3) return ld4d_z_p_bi(ctx, dec); // -> ld4d_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_eld_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3;
	if(!msz && opc==1) return ld2b_z_p_br(ctx, dec); // -> ld2b_z_p_br_contiguous
	if(!msz && opc==2) return ld3b_z_p_br(ctx, dec); // -> ld3b_z_p_br_contiguous
	if(!msz && opc==3) return ld4b_z_p_br(ctx, dec); // -> ld4b_z_p_br_contiguous
	if(msz==1 && opc==1) return ld2h_z_p_br(ctx, dec); // -> ld2h_z_p_br_contiguous
	if(msz==1 && opc==2) return ld3h_z_p_br(ctx, dec); // -> ld3h_z_p_br_contiguous
	if(msz==1 && opc==3) return ld4h_z_p_br(ctx, dec); // -> ld4h_z_p_br_contiguous
	if(msz==2 && opc==1) return ld2w_z_p_br(ctx, dec); // -> ld2w_z_p_br_contiguous
	if(msz==2 && opc==2) return ld3w_z_p_br(ctx, dec); // -> ld3w_z_p_br_contiguous
	if(msz==2 && opc==3) return ld4w_z_p_br(ctx, dec); // -> ld4w_z_p_br_contiguous
	if(msz==3 && opc==1) return ld2d_z_p_br(ctx, dec); // -> ld2d_z_p_br_contiguous
	if(msz==3 && opc==2) return ld3d_z_p_br(ctx, dec); // -> ld3d_z_p_br_contiguous
	if(msz==3 && opc==3) return ld4d_z_p_br(ctx, dec); // -> ld4d_z_p_br_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_sv(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(opc==1 && !U && !ff) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_d_x32_scaled
	if(opc==1 && !U && ff) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_d_x32_scaled
	if(opc==1 && U && !ff) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_d_x32_scaled
	if(opc==1 && U && ff) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_d_x32_scaled
	if(opc==2 && !U && !ff) return ld1sw_z_p_bz(ctx, dec); // -> ld1sw_z_p_bz_d_x32_scaled
	if(opc==2 && !U && ff) return ldff1sw_z_p_bz(ctx, dec); // -> ldff1sw_z_p_bz_d_x32_scaled
	if(opc==2 && U && !ff) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_d_x32_scaled
	if(opc==2 && U && ff) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_d_x32_scaled
	if(opc==3 && U && !ff) return ld1d_z_p_bz(ctx, dec); // -> ld1d_z_p_bz_d_x32_scaled
	if(opc==3 && U && ff) return ldff1d_z_p_bz(ctx, dec); // -> ldff1d_z_p_bz_d_x32_scaled
	if(opc==3 && !U) UNALLOCATED(ENC_UNALLOCATED_276);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_sv2(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(opc==1 && !U && !ff) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_d_64_scaled
	if(opc==1 && !U && ff) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_d_64_scaled
	if(opc==1 && U && !ff) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_d_64_scaled
	if(opc==1 && U && ff) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_d_64_scaled
	if(opc==2 && !U && !ff) return ld1sw_z_p_bz(ctx, dec); // -> ld1sw_z_p_bz_d_64_scaled
	if(opc==2 && !U && ff) return ldff1sw_z_p_bz(ctx, dec); // -> ldff1sw_z_p_bz_d_64_scaled
	if(opc==2 && U && !ff) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_d_64_scaled
	if(opc==2 && U && ff) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_d_64_scaled
	if(opc==3 && U && !ff) return ld1d_z_p_bz(ctx, dec); // -> ld1d_z_p_bz_d_64_scaled
	if(opc==3 && U && ff) return ldff1d_z_p_bz(ctx, dec); // -> ldff1d_z_p_bz_d_64_scaled
	if(opc==3 && !U) UNALLOCATED(ENC_UNALLOCATED_279);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_vs2(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!msz && !U && !ff) return ld1sb_z_p_bz(ctx, dec); // -> ld1sb_z_p_bz_d_64_unscaled
	if(!msz && !U && ff) return ldff1sb_z_p_bz(ctx, dec); // -> ldff1sb_z_p_bz_d_64_unscaled
	if(!msz && U && !ff) return ld1b_z_p_bz(ctx, dec); // -> ld1b_z_p_bz_d_64_unscaled
	if(!msz && U && ff) return ldff1b_z_p_bz(ctx, dec); // -> ldff1b_z_p_bz_d_64_unscaled
	if(msz==1 && !U && !ff) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_d_64_unscaled
	if(msz==1 && !U && ff) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_d_64_unscaled
	if(msz==1 && U && !ff) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_d_64_unscaled
	if(msz==1 && U && ff) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_d_64_unscaled
	if(msz==2 && !U && !ff) return ld1sw_z_p_bz(ctx, dec); // -> ld1sw_z_p_bz_d_64_unscaled
	if(msz==2 && !U && ff) return ldff1sw_z_p_bz(ctx, dec); // -> ldff1sw_z_p_bz_d_64_unscaled
	if(msz==2 && U && !ff) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_d_64_unscaled
	if(msz==2 && U && ff) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_d_64_unscaled
	if(msz==3 && U && !ff) return ld1d_z_p_bz(ctx, dec); // -> ld1d_z_p_bz_d_64_unscaled
	if(msz==3 && U && ff) return ldff1d_z_p_bz(ctx, dec); // -> ldff1d_z_p_bz_d_64_unscaled
	if(msz==3 && !U) UNALLOCATED(ENC_UNALLOCATED_278);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_vs(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!msz && !U && !ff) return ld1sb_z_p_bz(ctx, dec); // -> ld1sb_z_p_bz_d_x32_unscaled
	if(!msz && !U && ff) return ldff1sb_z_p_bz(ctx, dec); // -> ldff1sb_z_p_bz_d_x32_unscaled
	if(!msz && U && !ff) return ld1b_z_p_bz(ctx, dec); // -> ld1b_z_p_bz_d_x32_unscaled
	if(!msz && U && ff) return ldff1b_z_p_bz(ctx, dec); // -> ldff1b_z_p_bz_d_x32_unscaled
	if(msz==1 && !U && !ff) return ld1sh_z_p_bz(ctx, dec); // -> ld1sh_z_p_bz_d_x32_unscaled
	if(msz==1 && !U && ff) return ldff1sh_z_p_bz(ctx, dec); // -> ldff1sh_z_p_bz_d_x32_unscaled
	if(msz==1 && U && !ff) return ld1h_z_p_bz(ctx, dec); // -> ld1h_z_p_bz_d_x32_unscaled
	if(msz==1 && U && ff) return ldff1h_z_p_bz(ctx, dec); // -> ldff1h_z_p_bz_d_x32_unscaled
	if(msz==2 && !U && !ff) return ld1sw_z_p_bz(ctx, dec); // -> ld1sw_z_p_bz_d_x32_unscaled
	if(msz==2 && !U && ff) return ldff1sw_z_p_bz(ctx, dec); // -> ldff1sw_z_p_bz_d_x32_unscaled
	if(msz==2 && U && !ff) return ld1w_z_p_bz(ctx, dec); // -> ld1w_z_p_bz_d_x32_unscaled
	if(msz==2 && U && ff) return ldff1w_z_p_bz(ctx, dec); // -> ldff1w_z_p_bz_d_x32_unscaled
	if(msz==3 && U && !ff) return ld1d_z_p_bz(ctx, dec); // -> ld1d_z_p_bz_d_x32_unscaled
	if(msz==3 && U && ff) return ldff1d_z_p_bz(ctx, dec); // -> ldff1d_z_p_bz_d_x32_unscaled
	if(msz==3 && !U) UNALLOCATED(ENC_UNALLOCATED_275);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_gld_vi(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, U=(INSWORD>>14)&1, ff=(INSWORD>>13)&1;
	if(!msz && !U && !ff) return ld1sb_z_p_ai(ctx, dec); // -> ld1sb_z_p_ai_d
	if(!msz && !U && ff) return ldff1sb_z_p_ai(ctx, dec); // -> ldff1sb_z_p_ai_d
	if(!msz && U && !ff) return ld1b_z_p_ai(ctx, dec); // -> ld1b_z_p_ai_d
	if(!msz && U && ff) return ldff1b_z_p_ai(ctx, dec); // -> ldff1b_z_p_ai_d
	if(msz==1 && !U && !ff) return ld1sh_z_p_ai(ctx, dec); // -> ld1sh_z_p_ai_d
	if(msz==1 && !U && ff) return ldff1sh_z_p_ai(ctx, dec); // -> ldff1sh_z_p_ai_d
	if(msz==1 && U && !ff) return ld1h_z_p_ai(ctx, dec); // -> ld1h_z_p_ai_d
	if(msz==1 && U && ff) return ldff1h_z_p_ai(ctx, dec); // -> ldff1h_z_p_ai_d
	if(msz==2 && !U && !ff) return ld1sw_z_p_ai(ctx, dec); // -> ld1sw_z_p_ai_d
	if(msz==2 && !U && ff) return ldff1sw_z_p_ai(ctx, dec); // -> ldff1sw_z_p_ai_d
	if(msz==2 && U && !ff) return ld1w_z_p_ai(ctx, dec); // -> ld1w_z_p_ai_d
	if(msz==2 && U && ff) return ldff1w_z_p_ai(ctx, dec); // -> ldff1w_z_p_ai_d
	if(msz==3 && U && !ff) return ld1d_z_p_ai(ctx, dec); // -> ld1d_z_p_ai_d
	if(msz==3 && U && ff) return ldff1d_z_p_ai(ctx, dec); // -> ldff1d_z_p_ai_d
	if(msz==3 && !U) UNALLOCATED(ENC_UNALLOCATED_277);
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_prfm_sv2(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3;
	if(!msz) return prfb_i_p_bz(ctx, dec); // -> prfb_i_p_bz_d_64_scaled
	if(msz==1) return prfh_i_p_bz(ctx, dec); // -> prfh_i_p_bz_d_64_scaled
	if(msz==2) return prfw_i_p_bz(ctx, dec); // -> prfw_i_p_bz_d_64_scaled
	if(msz==3) return prfd_i_p_bz(ctx, dec); // -> prfd_i_p_bz_d_64_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_prfm_sv(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>13)&3;
	if(!msz) return prfb_i_p_bz(ctx, dec); // -> prfb_i_p_bz_d_x32_scaled
	if(msz==1) return prfh_i_p_bz(ctx, dec); // -> prfh_i_p_bz_d_x32_scaled
	if(msz==2) return prfw_i_p_bz(ctx, dec); // -> prfw_i_p_bz_d_x32_scaled
	if(msz==3) return prfd_i_p_bz(ctx, dec); // -> prfd_i_p_bz_d_x32_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_64b_prfm_vi(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return prfb_i_p_ai(ctx, dec); // -> prfb_i_p_ai_d
	if(msz==1) return prfh_i_p_ai(ctx, dec); // -> prfh_i_p_ai_d
	if(msz==2) return prfw_i_p_ai(ctx, dec); // -> prfw_i_p_ai_d
	if(msz==3) return prfd_i_p_ai(ctx, dec); // -> prfd_i_p_ai_d
	UNMATCHED;
}

int decode_iclass_sve_mem_cst_ss(context *ctx, Instruction *dec)
{
	uint32_t opc=(INSWORD>>22)&7, o2=(INSWORD>>21)&1;
	if(opc==7 && !o2) UNALLOCATED(ENC_UNALLOCATED_283);
	if(opc==7 && o2) return st1d_z_p_br(ctx, dec); // -> st1d_z_p_br_
	if(!(opc&6)) return st1b_z_p_br(ctx, dec); // -> st1b_z_p_br_
	if((opc&6)==2) return st1h_z_p_br(ctx, dec); // -> st1h_z_p_br_
	if((opc&6)==4) return st1w_z_p_br(ctx, dec); // -> st1w_z_p_br_
	UNMATCHED;
}

int decode_iclass_sve_mem_pspill(context *ctx, Instruction *dec)
{
	return str_p_bi(ctx, dec);
}

int decode_iclass_sve_mem_spill(context *ctx, Instruction *dec)
{
	return str_z_bi(ctx, dec);
}

int decode_iclass_sve_mem_cstnt_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return stnt1b_z_p_br(ctx, dec); // -> stnt1b_z_p_br_contiguous
	if(msz==1) return stnt1h_z_p_br(ctx, dec); // -> stnt1h_z_p_br_contiguous
	if(msz==2) return stnt1w_z_p_br(ctx, dec); // -> stnt1w_z_p_br_contiguous
	if(msz==3) return stnt1d_z_p_br(ctx, dec); // -> stnt1d_z_p_br_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_est_ss(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3;
	if(!msz && opc==1) return st2b_z_p_br(ctx, dec); // -> st2b_z_p_br_contiguous
	if(!msz && opc==2) return st3b_z_p_br(ctx, dec); // -> st3b_z_p_br_contiguous
	if(!msz && opc==3) return st4b_z_p_br(ctx, dec); // -> st4b_z_p_br_contiguous
	if(msz==1 && opc==1) return st2h_z_p_br(ctx, dec); // -> st2h_z_p_br_contiguous
	if(msz==1 && opc==2) return st3h_z_p_br(ctx, dec); // -> st3h_z_p_br_contiguous
	if(msz==1 && opc==3) return st4h_z_p_br(ctx, dec); // -> st4h_z_p_br_contiguous
	if(msz==2 && opc==1) return st2w_z_p_br(ctx, dec); // -> st2w_z_p_br_contiguous
	if(msz==2 && opc==2) return st3w_z_p_br(ctx, dec); // -> st3w_z_p_br_contiguous
	if(msz==2 && opc==3) return st4w_z_p_br(ctx, dec); // -> st4w_z_p_br_contiguous
	if(msz==3 && opc==1) return st2d_z_p_br(ctx, dec); // -> st2d_z_p_br_contiguous
	if(msz==3 && opc==2) return st3d_z_p_br(ctx, dec); // -> st3d_z_p_br_contiguous
	if(msz==3 && opc==3) return st4d_z_p_br(ctx, dec); // -> st4d_z_p_br_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vi_b(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return st1b_z_p_ai(ctx, dec); // -> st1b_z_p_ai_s
	if(msz==1) return st1h_z_p_ai(ctx, dec); // -> st1h_z_p_ai_s
	if(msz==2) return st1w_z_p_ai(ctx, dec); // -> st1w_z_p_ai_s
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_286);
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_sv2(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) UNALLOCATED(ENC_UNALLOCATED_281);
	if(msz==1) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_d_64_scaled
	if(msz==2) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_d_64_scaled
	if(msz==3) return st1d_z_p_bz(ctx, dec); // -> st1d_z_p_bz_d_64_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vs2(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return st1b_z_p_bz(ctx, dec); // -> st1b_z_p_bz_d_64_unscaled
	if(msz==1) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_d_64_unscaled
	if(msz==2) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_d_64_unscaled
	if(msz==3) return st1d_z_p_bz(ctx, dec); // -> st1d_z_p_bz_d_64_unscaled
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vi_a(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return st1b_z_p_ai(ctx, dec); // -> st1b_z_p_ai_d
	if(msz==1) return st1h_z_p_ai(ctx, dec); // -> st1h_z_p_ai_d
	if(msz==2) return st1w_z_p_ai(ctx, dec); // -> st1w_z_p_ai_d
	if(msz==3) return st1d_z_p_ai(ctx, dec); // -> st1d_z_p_ai_d
	UNMATCHED;
}

int decode_iclass_sve_mem_cstnt_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return stnt1b_z_p_bi(ctx, dec); // -> stnt1b_z_p_bi_contiguous
	if(msz==1) return stnt1h_z_p_bi(ctx, dec); // -> stnt1h_z_p_bi_contiguous
	if(msz==2) return stnt1w_z_p_bi(ctx, dec); // -> stnt1w_z_p_bi_contiguous
	if(msz==3) return stnt1d_z_p_bi(ctx, dec); // -> stnt1d_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_cst_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return st1b_z_p_bi(ctx, dec); // -> st1b_z_p_bi_
	if(msz==1) return st1h_z_p_bi(ctx, dec); // -> st1h_z_p_bi_
	if(msz==2) return st1w_z_p_bi(ctx, dec); // -> st1w_z_p_bi_
	if(msz==3) return st1d_z_p_bi(ctx, dec); // -> st1d_z_p_bi_
	UNMATCHED;
}

int decode_iclass_sve_mem_est_si(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3, opc=(INSWORD>>21)&3;
	if(!msz && opc==1) return st2b_z_p_bi(ctx, dec); // -> st2b_z_p_bi_contiguous
	if(!msz && opc==2) return st3b_z_p_bi(ctx, dec); // -> st3b_z_p_bi_contiguous
	if(!msz && opc==3) return st4b_z_p_bi(ctx, dec); // -> st4b_z_p_bi_contiguous
	if(msz==1 && opc==1) return st2h_z_p_bi(ctx, dec); // -> st2h_z_p_bi_contiguous
	if(msz==1 && opc==2) return st3h_z_p_bi(ctx, dec); // -> st3h_z_p_bi_contiguous
	if(msz==1 && opc==3) return st4h_z_p_bi(ctx, dec); // -> st4h_z_p_bi_contiguous
	if(msz==2 && opc==1) return st2w_z_p_bi(ctx, dec); // -> st2w_z_p_bi_contiguous
	if(msz==2 && opc==2) return st3w_z_p_bi(ctx, dec); // -> st3w_z_p_bi_contiguous
	if(msz==2 && opc==3) return st4w_z_p_bi(ctx, dec); // -> st4w_z_p_bi_contiguous
	if(msz==3 && opc==1) return st2d_z_p_bi(ctx, dec); // -> st2d_z_p_bi_contiguous
	if(msz==3 && opc==2) return st3d_z_p_bi(ctx, dec); // -> st3d_z_p_bi_contiguous
	if(msz==3 && opc==3) return st4d_z_p_bi(ctx, dec); // -> st4d_z_p_bi_contiguous
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_sv_b(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) UNALLOCATED(ENC_UNALLOCATED_282);
	if(msz==1) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_s_x32_scaled
	if(msz==2) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_s_x32_scaled
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_285);
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vs_b(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return st1b_z_p_bz(ctx, dec); // -> st1b_z_p_bz_s_x32_unscaled
	if(msz==1) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_s_x32_unscaled
	if(msz==2) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_s_x32_unscaled
	if(msz==3) UNALLOCATED(ENC_UNALLOCATED_284);
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_sv_a(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) UNALLOCATED(ENC_UNALLOCATED_280);
	if(msz==1) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_d_x32_scaled
	if(msz==2) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_d_x32_scaled
	if(msz==3) return st1d_z_p_bz(ctx, dec); // -> st1d_z_p_bz_d_x32_scaled
	UNMATCHED;
}

int decode_iclass_sve_mem_sst_vs_a(context *ctx, Instruction *dec)
{
	uint32_t msz=(INSWORD>>23)&3;
	if(!msz) return st1b_z_p_bz(ctx, dec); // -> st1b_z_p_bz_d_x32_unscaled
	if(msz==1) return st1h_z_p_bz(ctx, dec); // -> st1h_z_p_bz_d_x32_unscaled
	if(msz==2) return st1w_z_p_bz(ctx, dec); // -> st1w_z_p_bz_d_x32_unscaled
	if(msz==3) return st1d_z_p_bz(ctx, dec); // -> st1d_z_p_bz_d_x32_unscaled
	UNMATCHED;
}

