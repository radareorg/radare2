/* GENERATED FILE - DO NOT MODIFY - SUBMIT GITHUB ISSUE IF PROBLEM FOUND */

#include "operations.h"
#include "encodings.h"

const char *enc_to_str(enum ENCODING enc)
{
	switch(enc) {
		case ENC_ABS_ASIMDMISC_R: return "ABS_asimdmisc_R";
		case ENC_ABS_ASISDMISC_R: return "ABS_asisdmisc_R";
		case ENC_ADCS_32_ADDSUB_CARRY: return "ADCS_32_addsub_carry";
		case ENC_ADCS_64_ADDSUB_CARRY: return "ADCS_64_addsub_carry";
		case ENC_ADC_32_ADDSUB_CARRY: return "ADC_32_addsub_carry";
		case ENC_ADC_64_ADDSUB_CARRY: return "ADC_64_addsub_carry";
		case ENC_ADDG_64_ADDSUB_IMMTAGS: return "ADDG_64_addsub_immtags";
		case ENC_ADDHN_ASIMDDIFF_N: return "ADDHN_asimddiff_N";
		case ENC_ADDP_ASIMDSAME_ONLY: return "ADDP_asimdsame_only";
		case ENC_ADDP_ASISDPAIR_ONLY: return "ADDP_asisdpair_only";
		case ENC_ADDS_32S_ADDSUB_EXT: return "ADDS_32S_addsub_ext";
		case ENC_ADDS_32S_ADDSUB_IMM: return "ADDS_32S_addsub_imm";
		case ENC_ADDS_32_ADDSUB_SHIFT: return "ADDS_32_addsub_shift";
		case ENC_ADDS_64S_ADDSUB_EXT: return "ADDS_64S_addsub_ext";
		case ENC_ADDS_64S_ADDSUB_IMM: return "ADDS_64S_addsub_imm";
		case ENC_ADDS_64_ADDSUB_SHIFT: return "ADDS_64_addsub_shift";
		case ENC_ADDV_ASIMDALL_ONLY: return "ADDV_asimdall_only";
		case ENC_ADD_32_ADDSUB_EXT: return "ADD_32_addsub_ext";
		case ENC_ADD_32_ADDSUB_IMM: return "ADD_32_addsub_imm";
		case ENC_ADD_32_ADDSUB_SHIFT: return "ADD_32_addsub_shift";
		case ENC_ADD_64_ADDSUB_EXT: return "ADD_64_addsub_ext";
		case ENC_ADD_64_ADDSUB_IMM: return "ADD_64_addsub_imm";
		case ENC_ADD_64_ADDSUB_SHIFT: return "ADD_64_addsub_shift";
		case ENC_ADD_ASIMDSAME_ONLY: return "ADD_asimdsame_only";
		case ENC_ADD_ASISDSAME_ONLY: return "ADD_asisdsame_only";
		case ENC_ADRP_ONLY_PCRELADDR: return "ADRP_only_pcreladdr";
		case ENC_ADR_ONLY_PCRELADDR: return "ADR_only_pcreladdr";
		case ENC_AESD_B_CRYPTOAES: return "AESD_B_cryptoaes";
		case ENC_AESE_B_CRYPTOAES: return "AESE_B_cryptoaes";
		case ENC_AESIMC_B_CRYPTOAES: return "AESIMC_B_cryptoaes";
		case ENC_AESMC_B_CRYPTOAES: return "AESMC_B_cryptoaes";
		case ENC_ANDS_32S_LOG_IMM: return "ANDS_32S_log_imm";
		case ENC_ANDS_32_LOG_SHIFT: return "ANDS_32_log_shift";
		case ENC_ANDS_64S_LOG_IMM: return "ANDS_64S_log_imm";
		case ENC_ANDS_64_LOG_SHIFT: return "ANDS_64_log_shift";
		case ENC_AND_32_LOG_IMM: return "AND_32_log_imm";
		case ENC_AND_32_LOG_SHIFT: return "AND_32_log_shift";
		case ENC_AND_64_LOG_IMM: return "AND_64_log_imm";
		case ENC_AND_64_LOG_SHIFT: return "AND_64_log_shift";
		case ENC_AND_ASIMDSAME_ONLY: return "AND_asimdsame_only";
		case ENC_ASRV_32_DP_2SRC: return "ASRV_32_dp_2src";
		case ENC_ASRV_64_DP_2SRC: return "ASRV_64_dp_2src";
		case ENC_ASR_ASRV_32_DP_2SRC: return "ASR_ASRV_32_dp_2src";
		case ENC_ASR_ASRV_64_DP_2SRC: return "ASR_ASRV_64_dp_2src";
		case ENC_ASR_SBFM_32M_BITFIELD: return "ASR_SBFM_32M_bitfield";
		case ENC_ASR_SBFM_64M_BITFIELD: return "ASR_SBFM_64M_bitfield";
		case ENC_AT_SYS_CR_SYSTEMINSTRS: return "AT_SYS_CR_systeminstrs";
		case ENC_AUTDA_64P_DP_1SRC: return "AUTDA_64P_dp_1src";
		case ENC_AUTDB_64P_DP_1SRC: return "AUTDB_64P_dp_1src";
		case ENC_AUTDZA_64Z_DP_1SRC: return "AUTDZA_64Z_dp_1src";
		case ENC_AUTDZB_64Z_DP_1SRC: return "AUTDZB_64Z_dp_1src";
		case ENC_AUTIA1716_HI_HINTS: return "AUTIA1716_HI_hints";
		case ENC_AUTIASP_HI_HINTS: return "AUTIASP_HI_hints";
		case ENC_AUTIAZ_HI_HINTS: return "AUTIAZ_HI_hints";
		case ENC_AUTIA_64P_DP_1SRC: return "AUTIA_64P_dp_1src";
		case ENC_AUTIB1716_HI_HINTS: return "AUTIB1716_HI_hints";
		case ENC_AUTIBSP_HI_HINTS: return "AUTIBSP_HI_hints";
		case ENC_AUTIBZ_HI_HINTS: return "AUTIBZ_HI_hints";
		case ENC_AUTIB_64P_DP_1SRC: return "AUTIB_64P_dp_1src";
		case ENC_AUTIZA_64Z_DP_1SRC: return "AUTIZA_64Z_dp_1src";
		case ENC_AUTIZB_64Z_DP_1SRC: return "AUTIZB_64Z_dp_1src";
		case ENC_AXFLAG_M_PSTATE: return "AXFLAG_M_pstate";
		case ENC_BCAX_VVV16_CRYPTO4: return "BCAX_VVV16_crypto4";
		case ENC_BFCVTN_ASIMDMISC_4S: return "BFCVTN_asimdmisc_4S";
		case ENC_BFCVT_BS_FLOATDP1: return "BFCVT_BS_floatdp1";
		case ENC_BFC_BFM_32M_BITFIELD: return "BFC_BFM_32M_bitfield";
		case ENC_BFC_BFM_64M_BITFIELD: return "BFC_BFM_64M_bitfield";
		case ENC_BFDOT_ASIMDELEM_E: return "BFDOT_asimdelem_E";
		case ENC_BFDOT_ASIMDSAME2_D: return "BFDOT_asimdsame2_D";
		case ENC_BFI_BFM_32M_BITFIELD: return "BFI_BFM_32M_bitfield";
		case ENC_BFI_BFM_64M_BITFIELD: return "BFI_BFM_64M_bitfield";
		case ENC_BFMLAL_ASIMDELEM_F: return "BFMLAL_asimdelem_F";
		case ENC_BFMLAL_ASIMDSAME2_F_: return "BFMLAL_asimdsame2_F_";
		case ENC_BFMMLA_ASIMDSAME2_E: return "BFMMLA_asimdsame2_E";
		case ENC_BFM_32M_BITFIELD: return "BFM_32M_bitfield";
		case ENC_BFM_64M_BITFIELD: return "BFM_64M_bitfield";
		case ENC_BFXIL_BFM_32M_BITFIELD: return "BFXIL_BFM_32M_bitfield";
		case ENC_BFXIL_BFM_64M_BITFIELD: return "BFXIL_BFM_64M_bitfield";
		case ENC_BICS_32_LOG_SHIFT: return "BICS_32_log_shift";
		case ENC_BICS_64_LOG_SHIFT: return "BICS_64_log_shift";
		case ENC_BIC_32_LOG_SHIFT: return "BIC_32_log_shift";
		case ENC_BIC_64_LOG_SHIFT: return "BIC_64_log_shift";
		case ENC_BIC_AND_Z_ZI_: return "BIC_and_z_zi_";
		case ENC_BIC_ASIMDIMM_L_HL: return "BIC_asimdimm_L_hl";
		case ENC_BIC_ASIMDIMM_L_SL: return "BIC_asimdimm_L_sl";
		case ENC_BIC_ASIMDSAME_ONLY: return "BIC_asimdsame_only";
		case ENC_BIF_ASIMDSAME_ONLY: return "BIF_asimdsame_only";
		case ENC_BIT_ASIMDSAME_ONLY: return "BIT_asimdsame_only";
		case ENC_BLRAAZ_64_BRANCH_REG: return "BLRAAZ_64_branch_reg";
		case ENC_BLRAA_64P_BRANCH_REG: return "BLRAA_64P_branch_reg";
		case ENC_BLRABZ_64_BRANCH_REG: return "BLRABZ_64_branch_reg";
		case ENC_BLRAB_64P_BRANCH_REG: return "BLRAB_64P_branch_reg";
		case ENC_BLR_64_BRANCH_REG: return "BLR_64_branch_reg";
		case ENC_BL_ONLY_BRANCH_IMM: return "BL_only_branch_imm";
		case ENC_BRAAZ_64_BRANCH_REG: return "BRAAZ_64_branch_reg";
		case ENC_BRAA_64P_BRANCH_REG: return "BRAA_64P_branch_reg";
		case ENC_BRABZ_64_BRANCH_REG: return "BRABZ_64_branch_reg";
		case ENC_BRAB_64P_BRANCH_REG: return "BRAB_64P_branch_reg";
		case ENC_BRK_EX_EXCEPTION: return "BRK_EX_exception";
		case ENC_BR_64_BRANCH_REG: return "BR_64_branch_reg";
		case ENC_BSL_ASIMDSAME_ONLY: return "BSL_asimdsame_only";
		case ENC_BTI_HB_HINTS: return "BTI_HB_hints";
		case ENC_B_ONLY_BRANCH_IMM: return "B_only_branch_imm";
		case ENC_B_ONLY_CONDBRANCH: return "B_only_condbranch";
		case ENC_CASAB_C32_LDSTEXCL: return "CASAB_C32_ldstexcl";
		case ENC_CASAH_C32_LDSTEXCL: return "CASAH_C32_ldstexcl";
		case ENC_CASALB_C32_LDSTEXCL: return "CASALB_C32_ldstexcl";
		case ENC_CASALH_C32_LDSTEXCL: return "CASALH_C32_ldstexcl";
		case ENC_CASAL_C32_LDSTEXCL: return "CASAL_C32_ldstexcl";
		case ENC_CASAL_C64_LDSTEXCL: return "CASAL_C64_ldstexcl";
		case ENC_CASA_C32_LDSTEXCL: return "CASA_C32_ldstexcl";
		case ENC_CASA_C64_LDSTEXCL: return "CASA_C64_ldstexcl";
		case ENC_CASB_C32_LDSTEXCL: return "CASB_C32_ldstexcl";
		case ENC_CASH_C32_LDSTEXCL: return "CASH_C32_ldstexcl";
		case ENC_CASLB_C32_LDSTEXCL: return "CASLB_C32_ldstexcl";
		case ENC_CASLH_C32_LDSTEXCL: return "CASLH_C32_ldstexcl";
		case ENC_CASL_C32_LDSTEXCL: return "CASL_C32_ldstexcl";
		case ENC_CASL_C64_LDSTEXCL: return "CASL_C64_ldstexcl";
		case ENC_CASPAL_CP32_LDSTEXCL: return "CASPAL_CP32_ldstexcl";
		case ENC_CASPAL_CP64_LDSTEXCL: return "CASPAL_CP64_ldstexcl";
		case ENC_CASPA_CP32_LDSTEXCL: return "CASPA_CP32_ldstexcl";
		case ENC_CASPA_CP64_LDSTEXCL: return "CASPA_CP64_ldstexcl";
		case ENC_CASPL_CP32_LDSTEXCL: return "CASPL_CP32_ldstexcl";
		case ENC_CASPL_CP64_LDSTEXCL: return "CASPL_CP64_ldstexcl";
		case ENC_CASP_CP32_LDSTEXCL: return "CASP_CP32_ldstexcl";
		case ENC_CASP_CP64_LDSTEXCL: return "CASP_CP64_ldstexcl";
		case ENC_CAS_C32_LDSTEXCL: return "CAS_C32_ldstexcl";
		case ENC_CAS_C64_LDSTEXCL: return "CAS_C64_ldstexcl";
		case ENC_CBNZ_32_COMPBRANCH: return "CBNZ_32_compbranch";
		case ENC_CBNZ_64_COMPBRANCH: return "CBNZ_64_compbranch";
		case ENC_CBZ_32_COMPBRANCH: return "CBZ_32_compbranch";
		case ENC_CBZ_64_COMPBRANCH: return "CBZ_64_compbranch";
		case ENC_CCMN_32_CONDCMP_IMM: return "CCMN_32_condcmp_imm";
		case ENC_CCMN_32_CONDCMP_REG: return "CCMN_32_condcmp_reg";
		case ENC_CCMN_64_CONDCMP_IMM: return "CCMN_64_condcmp_imm";
		case ENC_CCMN_64_CONDCMP_REG: return "CCMN_64_condcmp_reg";
		case ENC_CCMP_32_CONDCMP_IMM: return "CCMP_32_condcmp_imm";
		case ENC_CCMP_32_CONDCMP_REG: return "CCMP_32_condcmp_reg";
		case ENC_CCMP_64_CONDCMP_IMM: return "CCMP_64_condcmp_imm";
		case ENC_CCMP_64_CONDCMP_REG: return "CCMP_64_condcmp_reg";
		case ENC_CFINV_M_PSTATE: return "CFINV_M_pstate";
		case ENC_CFP_SYS_CR_SYSTEMINSTRS: return "CFP_SYS_CR_systeminstrs";
		case ENC_CINC_CSINC_32_CONDSEL: return "CINC_CSINC_32_condsel";
		case ENC_CINC_CSINC_64_CONDSEL: return "CINC_CSINC_64_condsel";
		case ENC_CINV_CSINV_32_CONDSEL: return "CINV_CSINV_32_condsel";
		case ENC_CINV_CSINV_64_CONDSEL: return "CINV_CSINV_64_condsel";
		case ENC_CLREX_BN_BARRIERS: return "CLREX_BN_barriers";
		case ENC_CLS_32_DP_1SRC: return "CLS_32_dp_1src";
		case ENC_CLS_64_DP_1SRC: return "CLS_64_dp_1src";
		case ENC_CLS_ASIMDMISC_R: return "CLS_asimdmisc_R";
		case ENC_CLZ_32_DP_1SRC: return "CLZ_32_dp_1src";
		case ENC_CLZ_64_DP_1SRC: return "CLZ_64_dp_1src";
		case ENC_CLZ_ASIMDMISC_R: return "CLZ_asimdmisc_R";
		case ENC_CMEQ_ASIMDMISC_Z: return "CMEQ_asimdmisc_Z";
		case ENC_CMEQ_ASIMDSAME_ONLY: return "CMEQ_asimdsame_only";
		case ENC_CMEQ_ASISDMISC_Z: return "CMEQ_asisdmisc_Z";
		case ENC_CMEQ_ASISDSAME_ONLY: return "CMEQ_asisdsame_only";
		case ENC_CMGE_ASIMDMISC_Z: return "CMGE_asimdmisc_Z";
		case ENC_CMGE_ASIMDSAME_ONLY: return "CMGE_asimdsame_only";
		case ENC_CMGE_ASISDMISC_Z: return "CMGE_asisdmisc_Z";
		case ENC_CMGE_ASISDSAME_ONLY: return "CMGE_asisdsame_only";
		case ENC_CMGT_ASIMDMISC_Z: return "CMGT_asimdmisc_Z";
		case ENC_CMGT_ASIMDSAME_ONLY: return "CMGT_asimdsame_only";
		case ENC_CMGT_ASISDMISC_Z: return "CMGT_asisdmisc_Z";
		case ENC_CMGT_ASISDSAME_ONLY: return "CMGT_asisdsame_only";
		case ENC_CMHI_ASIMDSAME_ONLY: return "CMHI_asimdsame_only";
		case ENC_CMHI_ASISDSAME_ONLY: return "CMHI_asisdsame_only";
		case ENC_CMHS_ASIMDSAME_ONLY: return "CMHS_asimdsame_only";
		case ENC_CMHS_ASISDSAME_ONLY: return "CMHS_asisdsame_only";
		case ENC_CMLE_ASIMDMISC_Z: return "CMLE_asimdmisc_Z";
		case ENC_CMLE_ASISDMISC_Z: return "CMLE_asisdmisc_Z";
		case ENC_CMLT_ASIMDMISC_Z: return "CMLT_asimdmisc_Z";
		case ENC_CMLT_ASISDMISC_Z: return "CMLT_asisdmisc_Z";
		case ENC_CMN_ADDS_32S_ADDSUB_EXT: return "CMN_ADDS_32S_addsub_ext";
		case ENC_CMN_ADDS_32S_ADDSUB_IMM: return "CMN_ADDS_32S_addsub_imm";
		case ENC_CMN_ADDS_32_ADDSUB_SHIFT: return "CMN_ADDS_32_addsub_shift";
		case ENC_CMN_ADDS_64S_ADDSUB_EXT: return "CMN_ADDS_64S_addsub_ext";
		case ENC_CMN_ADDS_64S_ADDSUB_IMM: return "CMN_ADDS_64S_addsub_imm";
		case ENC_CMN_ADDS_64_ADDSUB_SHIFT: return "CMN_ADDS_64_addsub_shift";
		case ENC_CMPLE_CMPGE_P_P_ZZ_: return "CMPLE_cmpge_p_p_zz_";
		case ENC_CMPLO_CMPHI_P_P_ZZ_: return "CMPLO_cmphi_p_p_zz_";
		case ENC_CMPLS_CMPHS_P_P_ZZ_: return "CMPLS_cmphs_p_p_zz_";
		case ENC_CMPLT_CMPGT_P_P_ZZ_: return "CMPLT_cmpgt_p_p_zz_";
		case ENC_CMPP_SUBPS_64S_DP_2SRC: return "CMPP_SUBPS_64S_dp_2src";
		case ENC_CMP_SUBS_32S_ADDSUB_EXT: return "CMP_SUBS_32S_addsub_ext";
		case ENC_CMP_SUBS_32S_ADDSUB_IMM: return "CMP_SUBS_32S_addsub_imm";
		case ENC_CMP_SUBS_32_ADDSUB_SHIFT: return "CMP_SUBS_32_addsub_shift";
		case ENC_CMP_SUBS_64S_ADDSUB_EXT: return "CMP_SUBS_64S_addsub_ext";
		case ENC_CMP_SUBS_64S_ADDSUB_IMM: return "CMP_SUBS_64S_addsub_imm";
		case ENC_CMP_SUBS_64_ADDSUB_SHIFT: return "CMP_SUBS_64_addsub_shift";
		case ENC_CMTST_ASIMDSAME_ONLY: return "CMTST_asimdsame_only";
		case ENC_CMTST_ASISDSAME_ONLY: return "CMTST_asisdsame_only";
		case ENC_CNEG_CSNEG_32_CONDSEL: return "CNEG_CSNEG_32_condsel";
		case ENC_CNEG_CSNEG_64_CONDSEL: return "CNEG_CSNEG_64_condsel";
		case ENC_CNT_ASIMDMISC_R: return "CNT_asimdmisc_R";
		case ENC_CPP_SYS_CR_SYSTEMINSTRS: return "CPP_SYS_CR_systeminstrs";
		case ENC_CRC32B_32C_DP_2SRC: return "CRC32B_32C_dp_2src";
		case ENC_CRC32CB_32C_DP_2SRC: return "CRC32CB_32C_dp_2src";
		case ENC_CRC32CH_32C_DP_2SRC: return "CRC32CH_32C_dp_2src";
		case ENC_CRC32CW_32C_DP_2SRC: return "CRC32CW_32C_dp_2src";
		case ENC_CRC32CX_64C_DP_2SRC: return "CRC32CX_64C_dp_2src";
		case ENC_CRC32H_32C_DP_2SRC: return "CRC32H_32C_dp_2src";
		case ENC_CRC32W_32C_DP_2SRC: return "CRC32W_32C_dp_2src";
		case ENC_CRC32X_64C_DP_2SRC: return "CRC32X_64C_dp_2src";
		case ENC_CSDB_HI_HINTS: return "CSDB_HI_hints";
		case ENC_CSEL_32_CONDSEL: return "CSEL_32_condsel";
		case ENC_CSEL_64_CONDSEL: return "CSEL_64_condsel";
		case ENC_CSETM_CSINV_32_CONDSEL: return "CSETM_CSINV_32_condsel";
		case ENC_CSETM_CSINV_64_CONDSEL: return "CSETM_CSINV_64_condsel";
		case ENC_CSET_CSINC_32_CONDSEL: return "CSET_CSINC_32_condsel";
		case ENC_CSET_CSINC_64_CONDSEL: return "CSET_CSINC_64_condsel";
		case ENC_CSINC_32_CONDSEL: return "CSINC_32_condsel";
		case ENC_CSINC_64_CONDSEL: return "CSINC_64_condsel";
		case ENC_CSINV_32_CONDSEL: return "CSINV_32_condsel";
		case ENC_CSINV_64_CONDSEL: return "CSINV_64_condsel";
		case ENC_CSNEG_32_CONDSEL: return "CSNEG_32_condsel";
		case ENC_CSNEG_64_CONDSEL: return "CSNEG_64_condsel";
		case ENC_DCPS1_DC_EXCEPTION: return "DCPS1_DC_exception";
		case ENC_DCPS2_DC_EXCEPTION: return "DCPS2_DC_exception";
		case ENC_DCPS3_DC_EXCEPTION: return "DCPS3_DC_exception";
		case ENC_DC_SYS_CR_SYSTEMINSTRS: return "DC_SYS_CR_systeminstrs";
		case ENC_DGH_HI_HINTS: return "DGH_HI_hints";
		case ENC_DMB_BO_BARRIERS: return "DMB_BO_barriers";
		case ENC_DRPS_64E_BRANCH_REG: return "DRPS_64E_branch_reg";
		case ENC_DSB_BO_BARRIERS: return "DSB_BO_barriers";
		case ENC_DUP_ASIMDINS_DR_R: return "DUP_asimdins_DR_r";
		case ENC_DUP_ASIMDINS_DV_V: return "DUP_asimdins_DV_v";
		case ENC_DUP_ASISDONE_ONLY: return "DUP_asisdone_only";
		case ENC_DVP_SYS_CR_SYSTEMINSTRS: return "DVP_SYS_CR_systeminstrs";
		case ENC_EON_32_LOG_SHIFT: return "EON_32_log_shift";
		case ENC_EON_64_LOG_SHIFT: return "EON_64_log_shift";
		case ENC_EON_EOR_Z_ZI_: return "EON_eor_z_zi_";
		case ENC_EOR3_VVV16_CRYPTO4: return "EOR3_VVV16_crypto4";
		case ENC_EOR_32_LOG_IMM: return "EOR_32_log_imm";
		case ENC_EOR_32_LOG_SHIFT: return "EOR_32_log_shift";
		case ENC_EOR_64_LOG_IMM: return "EOR_64_log_imm";
		case ENC_EOR_64_LOG_SHIFT: return "EOR_64_log_shift";
		case ENC_EOR_ASIMDSAME_ONLY: return "EOR_asimdsame_only";
		case ENC_ERETAA_64E_BRANCH_REG: return "ERETAA_64E_branch_reg";
		case ENC_ERETAB_64E_BRANCH_REG: return "ERETAB_64E_branch_reg";
		case ENC_ERET_64E_BRANCH_REG: return "ERET_64E_branch_reg";
		case ENC_ESB_HI_HINTS: return "ESB_HI_hints";
		case ENC_EXTR_32_EXTRACT: return "EXTR_32_extract";
		case ENC_EXTR_64_EXTRACT: return "EXTR_64_extract";
		case ENC_EXT_ASIMDEXT_ONLY: return "EXT_asimdext_only";
		case ENC_FABD_ASIMDSAME_ONLY: return "FABD_asimdsame_only";
		case ENC_FABD_ASIMDSAMEFP16_ONLY: return "FABD_asimdsamefp16_only";
		case ENC_FABD_ASISDSAME_ONLY: return "FABD_asisdsame_only";
		case ENC_FABD_ASISDSAMEFP16_ONLY: return "FABD_asisdsamefp16_only";
		case ENC_FABS_D_FLOATDP1: return "FABS_D_floatdp1";
		case ENC_FABS_H_FLOATDP1: return "FABS_H_floatdp1";
		case ENC_FABS_S_FLOATDP1: return "FABS_S_floatdp1";
		case ENC_FABS_ASIMDMISC_R: return "FABS_asimdmisc_R";
		case ENC_FABS_ASIMDMISCFP16_R: return "FABS_asimdmiscfp16_R";
		case ENC_FACGE_ASIMDSAME_ONLY: return "FACGE_asimdsame_only";
		case ENC_FACGE_ASIMDSAMEFP16_ONLY: return "FACGE_asimdsamefp16_only";
		case ENC_FACGE_ASISDSAME_ONLY: return "FACGE_asisdsame_only";
		case ENC_FACGE_ASISDSAMEFP16_ONLY: return "FACGE_asisdsamefp16_only";
		case ENC_FACGT_ASIMDSAME_ONLY: return "FACGT_asimdsame_only";
		case ENC_FACGT_ASIMDSAMEFP16_ONLY: return "FACGT_asimdsamefp16_only";
		case ENC_FACGT_ASISDSAME_ONLY: return "FACGT_asisdsame_only";
		case ENC_FACGT_ASISDSAMEFP16_ONLY: return "FACGT_asisdsamefp16_only";
		case ENC_FACLE_FACGE_P_P_ZZ_: return "FACLE_facge_p_p_zz_";
		case ENC_FACLT_FACGT_P_P_ZZ_: return "FACLT_facgt_p_p_zz_";
		case ENC_FADDP_ASIMDSAME_ONLY: return "FADDP_asimdsame_only";
		case ENC_FADDP_ASIMDSAMEFP16_ONLY: return "FADDP_asimdsamefp16_only";
		case ENC_FADDP_ASISDPAIR_ONLY_H: return "FADDP_asisdpair_only_H";
		case ENC_FADDP_ASISDPAIR_ONLY_SD: return "FADDP_asisdpair_only_SD";
		case ENC_FADD_D_FLOATDP2: return "FADD_D_floatdp2";
		case ENC_FADD_H_FLOATDP2: return "FADD_H_floatdp2";
		case ENC_FADD_S_FLOATDP2: return "FADD_S_floatdp2";
		case ENC_FADD_ASIMDSAME_ONLY: return "FADD_asimdsame_only";
		case ENC_FADD_ASIMDSAMEFP16_ONLY: return "FADD_asimdsamefp16_only";
		case ENC_FCADD_ASIMDSAME2_C: return "FCADD_asimdsame2_C";
		case ENC_FCCMPE_D_FLOATCCMP: return "FCCMPE_D_floatccmp";
		case ENC_FCCMPE_H_FLOATCCMP: return "FCCMPE_H_floatccmp";
		case ENC_FCCMPE_S_FLOATCCMP: return "FCCMPE_S_floatccmp";
		case ENC_FCCMP_D_FLOATCCMP: return "FCCMP_D_floatccmp";
		case ENC_FCCMP_H_FLOATCCMP: return "FCCMP_H_floatccmp";
		case ENC_FCCMP_S_FLOATCCMP: return "FCCMP_S_floatccmp";
		case ENC_FCMEQ_ASIMDMISC_FZ: return "FCMEQ_asimdmisc_FZ";
		case ENC_FCMEQ_ASIMDMISCFP16_FZ: return "FCMEQ_asimdmiscfp16_FZ";
		case ENC_FCMEQ_ASIMDSAME_ONLY: return "FCMEQ_asimdsame_only";
		case ENC_FCMEQ_ASIMDSAMEFP16_ONLY: return "FCMEQ_asimdsamefp16_only";
		case ENC_FCMEQ_ASISDMISC_FZ: return "FCMEQ_asisdmisc_FZ";
		case ENC_FCMEQ_ASISDMISCFP16_FZ: return "FCMEQ_asisdmiscfp16_FZ";
		case ENC_FCMEQ_ASISDSAME_ONLY: return "FCMEQ_asisdsame_only";
		case ENC_FCMEQ_ASISDSAMEFP16_ONLY: return "FCMEQ_asisdsamefp16_only";
		case ENC_FCMGE_ASIMDMISC_FZ: return "FCMGE_asimdmisc_FZ";
		case ENC_FCMGE_ASIMDMISCFP16_FZ: return "FCMGE_asimdmiscfp16_FZ";
		case ENC_FCMGE_ASIMDSAME_ONLY: return "FCMGE_asimdsame_only";
		case ENC_FCMGE_ASIMDSAMEFP16_ONLY: return "FCMGE_asimdsamefp16_only";
		case ENC_FCMGE_ASISDMISC_FZ: return "FCMGE_asisdmisc_FZ";
		case ENC_FCMGE_ASISDMISCFP16_FZ: return "FCMGE_asisdmiscfp16_FZ";
		case ENC_FCMGE_ASISDSAME_ONLY: return "FCMGE_asisdsame_only";
		case ENC_FCMGE_ASISDSAMEFP16_ONLY: return "FCMGE_asisdsamefp16_only";
		case ENC_FCMGT_ASIMDMISC_FZ: return "FCMGT_asimdmisc_FZ";
		case ENC_FCMGT_ASIMDMISCFP16_FZ: return "FCMGT_asimdmiscfp16_FZ";
		case ENC_FCMGT_ASIMDSAME_ONLY: return "FCMGT_asimdsame_only";
		case ENC_FCMGT_ASIMDSAMEFP16_ONLY: return "FCMGT_asimdsamefp16_only";
		case ENC_FCMGT_ASISDMISC_FZ: return "FCMGT_asisdmisc_FZ";
		case ENC_FCMGT_ASISDMISCFP16_FZ: return "FCMGT_asisdmiscfp16_FZ";
		case ENC_FCMGT_ASISDSAME_ONLY: return "FCMGT_asisdsame_only";
		case ENC_FCMGT_ASISDSAMEFP16_ONLY: return "FCMGT_asisdsamefp16_only";
		case ENC_FCMLA_ASIMDELEM_C_H: return "FCMLA_asimdelem_C_H";
		case ENC_FCMLA_ASIMDELEM_C_S: return "FCMLA_asimdelem_C_S";
		case ENC_FCMLA_ASIMDSAME2_C: return "FCMLA_asimdsame2_C";
		case ENC_FCMLE_ASIMDMISC_FZ: return "FCMLE_asimdmisc_FZ";
		case ENC_FCMLE_ASIMDMISCFP16_FZ: return "FCMLE_asimdmiscfp16_FZ";
		case ENC_FCMLE_ASISDMISC_FZ: return "FCMLE_asisdmisc_FZ";
		case ENC_FCMLE_ASISDMISCFP16_FZ: return "FCMLE_asisdmiscfp16_FZ";
		case ENC_FCMLE_FCMGE_P_P_ZZ_: return "FCMLE_fcmge_p_p_zz_";
		case ENC_FCMLT_ASIMDMISC_FZ: return "FCMLT_asimdmisc_FZ";
		case ENC_FCMLT_ASIMDMISCFP16_FZ: return "FCMLT_asimdmiscfp16_FZ";
		case ENC_FCMLT_ASISDMISC_FZ: return "FCMLT_asisdmisc_FZ";
		case ENC_FCMLT_ASISDMISCFP16_FZ: return "FCMLT_asisdmiscfp16_FZ";
		case ENC_FCMLT_FCMGT_P_P_ZZ_: return "FCMLT_fcmgt_p_p_zz_";
		case ENC_FCMPE_DZ_FLOATCMP: return "FCMPE_DZ_floatcmp";
		case ENC_FCMPE_D_FLOATCMP: return "FCMPE_D_floatcmp";
		case ENC_FCMPE_HZ_FLOATCMP: return "FCMPE_HZ_floatcmp";
		case ENC_FCMPE_H_FLOATCMP: return "FCMPE_H_floatcmp";
		case ENC_FCMPE_SZ_FLOATCMP: return "FCMPE_SZ_floatcmp";
		case ENC_FCMPE_S_FLOATCMP: return "FCMPE_S_floatcmp";
		case ENC_FCMP_DZ_FLOATCMP: return "FCMP_DZ_floatcmp";
		case ENC_FCMP_D_FLOATCMP: return "FCMP_D_floatcmp";
		case ENC_FCMP_HZ_FLOATCMP: return "FCMP_HZ_floatcmp";
		case ENC_FCMP_H_FLOATCMP: return "FCMP_H_floatcmp";
		case ENC_FCMP_SZ_FLOATCMP: return "FCMP_SZ_floatcmp";
		case ENC_FCMP_S_FLOATCMP: return "FCMP_S_floatcmp";
		case ENC_FCSEL_D_FLOATSEL: return "FCSEL_D_floatsel";
		case ENC_FCSEL_H_FLOATSEL: return "FCSEL_H_floatsel";
		case ENC_FCSEL_S_FLOATSEL: return "FCSEL_S_floatsel";
		case ENC_FCVTAS_32D_FLOAT2INT: return "FCVTAS_32D_float2int";
		case ENC_FCVTAS_32H_FLOAT2INT: return "FCVTAS_32H_float2int";
		case ENC_FCVTAS_32S_FLOAT2INT: return "FCVTAS_32S_float2int";
		case ENC_FCVTAS_64D_FLOAT2INT: return "FCVTAS_64D_float2int";
		case ENC_FCVTAS_64H_FLOAT2INT: return "FCVTAS_64H_float2int";
		case ENC_FCVTAS_64S_FLOAT2INT: return "FCVTAS_64S_float2int";
		case ENC_FCVTAS_ASIMDMISC_R: return "FCVTAS_asimdmisc_R";
		case ENC_FCVTAS_ASIMDMISCFP16_R: return "FCVTAS_asimdmiscfp16_R";
		case ENC_FCVTAS_ASISDMISC_R: return "FCVTAS_asisdmisc_R";
		case ENC_FCVTAS_ASISDMISCFP16_R: return "FCVTAS_asisdmiscfp16_R";
		case ENC_FCVTAU_32D_FLOAT2INT: return "FCVTAU_32D_float2int";
		case ENC_FCVTAU_32H_FLOAT2INT: return "FCVTAU_32H_float2int";
		case ENC_FCVTAU_32S_FLOAT2INT: return "FCVTAU_32S_float2int";
		case ENC_FCVTAU_64D_FLOAT2INT: return "FCVTAU_64D_float2int";
		case ENC_FCVTAU_64H_FLOAT2INT: return "FCVTAU_64H_float2int";
		case ENC_FCVTAU_64S_FLOAT2INT: return "FCVTAU_64S_float2int";
		case ENC_FCVTAU_ASIMDMISC_R: return "FCVTAU_asimdmisc_R";
		case ENC_FCVTAU_ASIMDMISCFP16_R: return "FCVTAU_asimdmiscfp16_R";
		case ENC_FCVTAU_ASISDMISC_R: return "FCVTAU_asisdmisc_R";
		case ENC_FCVTAU_ASISDMISCFP16_R: return "FCVTAU_asisdmiscfp16_R";
		case ENC_FCVTL_ASIMDMISC_L: return "FCVTL_asimdmisc_L";
		case ENC_FCVTMS_32D_FLOAT2INT: return "FCVTMS_32D_float2int";
		case ENC_FCVTMS_32H_FLOAT2INT: return "FCVTMS_32H_float2int";
		case ENC_FCVTMS_32S_FLOAT2INT: return "FCVTMS_32S_float2int";
		case ENC_FCVTMS_64D_FLOAT2INT: return "FCVTMS_64D_float2int";
		case ENC_FCVTMS_64H_FLOAT2INT: return "FCVTMS_64H_float2int";
		case ENC_FCVTMS_64S_FLOAT2INT: return "FCVTMS_64S_float2int";
		case ENC_FCVTMS_ASIMDMISC_R: return "FCVTMS_asimdmisc_R";
		case ENC_FCVTMS_ASIMDMISCFP16_R: return "FCVTMS_asimdmiscfp16_R";
		case ENC_FCVTMS_ASISDMISC_R: return "FCVTMS_asisdmisc_R";
		case ENC_FCVTMS_ASISDMISCFP16_R: return "FCVTMS_asisdmiscfp16_R";
		case ENC_FCVTMU_32D_FLOAT2INT: return "FCVTMU_32D_float2int";
		case ENC_FCVTMU_32H_FLOAT2INT: return "FCVTMU_32H_float2int";
		case ENC_FCVTMU_32S_FLOAT2INT: return "FCVTMU_32S_float2int";
		case ENC_FCVTMU_64D_FLOAT2INT: return "FCVTMU_64D_float2int";
		case ENC_FCVTMU_64H_FLOAT2INT: return "FCVTMU_64H_float2int";
		case ENC_FCVTMU_64S_FLOAT2INT: return "FCVTMU_64S_float2int";
		case ENC_FCVTMU_ASIMDMISC_R: return "FCVTMU_asimdmisc_R";
		case ENC_FCVTMU_ASIMDMISCFP16_R: return "FCVTMU_asimdmiscfp16_R";
		case ENC_FCVTMU_ASISDMISC_R: return "FCVTMU_asisdmisc_R";
		case ENC_FCVTMU_ASISDMISCFP16_R: return "FCVTMU_asisdmiscfp16_R";
		case ENC_FCVTNS_32D_FLOAT2INT: return "FCVTNS_32D_float2int";
		case ENC_FCVTNS_32H_FLOAT2INT: return "FCVTNS_32H_float2int";
		case ENC_FCVTNS_32S_FLOAT2INT: return "FCVTNS_32S_float2int";
		case ENC_FCVTNS_64D_FLOAT2INT: return "FCVTNS_64D_float2int";
		case ENC_FCVTNS_64H_FLOAT2INT: return "FCVTNS_64H_float2int";
		case ENC_FCVTNS_64S_FLOAT2INT: return "FCVTNS_64S_float2int";
		case ENC_FCVTNS_ASIMDMISC_R: return "FCVTNS_asimdmisc_R";
		case ENC_FCVTNS_ASIMDMISCFP16_R: return "FCVTNS_asimdmiscfp16_R";
		case ENC_FCVTNS_ASISDMISC_R: return "FCVTNS_asisdmisc_R";
		case ENC_FCVTNS_ASISDMISCFP16_R: return "FCVTNS_asisdmiscfp16_R";
		case ENC_FCVTNU_32D_FLOAT2INT: return "FCVTNU_32D_float2int";
		case ENC_FCVTNU_32H_FLOAT2INT: return "FCVTNU_32H_float2int";
		case ENC_FCVTNU_32S_FLOAT2INT: return "FCVTNU_32S_float2int";
		case ENC_FCVTNU_64D_FLOAT2INT: return "FCVTNU_64D_float2int";
		case ENC_FCVTNU_64H_FLOAT2INT: return "FCVTNU_64H_float2int";
		case ENC_FCVTNU_64S_FLOAT2INT: return "FCVTNU_64S_float2int";
		case ENC_FCVTNU_ASIMDMISC_R: return "FCVTNU_asimdmisc_R";
		case ENC_FCVTNU_ASIMDMISCFP16_R: return "FCVTNU_asimdmiscfp16_R";
		case ENC_FCVTNU_ASISDMISC_R: return "FCVTNU_asisdmisc_R";
		case ENC_FCVTNU_ASISDMISCFP16_R: return "FCVTNU_asisdmiscfp16_R";
		case ENC_FCVTN_ASIMDMISC_N: return "FCVTN_asimdmisc_N";
		case ENC_FCVTPS_32D_FLOAT2INT: return "FCVTPS_32D_float2int";
		case ENC_FCVTPS_32H_FLOAT2INT: return "FCVTPS_32H_float2int";
		case ENC_FCVTPS_32S_FLOAT2INT: return "FCVTPS_32S_float2int";
		case ENC_FCVTPS_64D_FLOAT2INT: return "FCVTPS_64D_float2int";
		case ENC_FCVTPS_64H_FLOAT2INT: return "FCVTPS_64H_float2int";
		case ENC_FCVTPS_64S_FLOAT2INT: return "FCVTPS_64S_float2int";
		case ENC_FCVTPS_ASIMDMISC_R: return "FCVTPS_asimdmisc_R";
		case ENC_FCVTPS_ASIMDMISCFP16_R: return "FCVTPS_asimdmiscfp16_R";
		case ENC_FCVTPS_ASISDMISC_R: return "FCVTPS_asisdmisc_R";
		case ENC_FCVTPS_ASISDMISCFP16_R: return "FCVTPS_asisdmiscfp16_R";
		case ENC_FCVTPU_32D_FLOAT2INT: return "FCVTPU_32D_float2int";
		case ENC_FCVTPU_32H_FLOAT2INT: return "FCVTPU_32H_float2int";
		case ENC_FCVTPU_32S_FLOAT2INT: return "FCVTPU_32S_float2int";
		case ENC_FCVTPU_64D_FLOAT2INT: return "FCVTPU_64D_float2int";
		case ENC_FCVTPU_64H_FLOAT2INT: return "FCVTPU_64H_float2int";
		case ENC_FCVTPU_64S_FLOAT2INT: return "FCVTPU_64S_float2int";
		case ENC_FCVTPU_ASIMDMISC_R: return "FCVTPU_asimdmisc_R";
		case ENC_FCVTPU_ASIMDMISCFP16_R: return "FCVTPU_asimdmiscfp16_R";
		case ENC_FCVTPU_ASISDMISC_R: return "FCVTPU_asisdmisc_R";
		case ENC_FCVTPU_ASISDMISCFP16_R: return "FCVTPU_asisdmiscfp16_R";
		case ENC_FCVTXN_ASIMDMISC_N: return "FCVTXN_asimdmisc_N";
		case ENC_FCVTXN_ASISDMISC_N: return "FCVTXN_asisdmisc_N";
		case ENC_FCVTZS_32D_FLOAT2FIX: return "FCVTZS_32D_float2fix";
		case ENC_FCVTZS_32D_FLOAT2INT: return "FCVTZS_32D_float2int";
		case ENC_FCVTZS_32H_FLOAT2FIX: return "FCVTZS_32H_float2fix";
		case ENC_FCVTZS_32H_FLOAT2INT: return "FCVTZS_32H_float2int";
		case ENC_FCVTZS_32S_FLOAT2FIX: return "FCVTZS_32S_float2fix";
		case ENC_FCVTZS_32S_FLOAT2INT: return "FCVTZS_32S_float2int";
		case ENC_FCVTZS_64D_FLOAT2FIX: return "FCVTZS_64D_float2fix";
		case ENC_FCVTZS_64D_FLOAT2INT: return "FCVTZS_64D_float2int";
		case ENC_FCVTZS_64H_FLOAT2FIX: return "FCVTZS_64H_float2fix";
		case ENC_FCVTZS_64H_FLOAT2INT: return "FCVTZS_64H_float2int";
		case ENC_FCVTZS_64S_FLOAT2FIX: return "FCVTZS_64S_float2fix";
		case ENC_FCVTZS_64S_FLOAT2INT: return "FCVTZS_64S_float2int";
		case ENC_FCVTZS_ASIMDMISC_R: return "FCVTZS_asimdmisc_R";
		case ENC_FCVTZS_ASIMDMISCFP16_R: return "FCVTZS_asimdmiscfp16_R";
		case ENC_FCVTZS_ASIMDSHF_C: return "FCVTZS_asimdshf_C";
		case ENC_FCVTZS_ASISDMISC_R: return "FCVTZS_asisdmisc_R";
		case ENC_FCVTZS_ASISDMISCFP16_R: return "FCVTZS_asisdmiscfp16_R";
		case ENC_FCVTZS_ASISDSHF_C: return "FCVTZS_asisdshf_C";
		case ENC_FCVTZU_32D_FLOAT2FIX: return "FCVTZU_32D_float2fix";
		case ENC_FCVTZU_32D_FLOAT2INT: return "FCVTZU_32D_float2int";
		case ENC_FCVTZU_32H_FLOAT2FIX: return "FCVTZU_32H_float2fix";
		case ENC_FCVTZU_32H_FLOAT2INT: return "FCVTZU_32H_float2int";
		case ENC_FCVTZU_32S_FLOAT2FIX: return "FCVTZU_32S_float2fix";
		case ENC_FCVTZU_32S_FLOAT2INT: return "FCVTZU_32S_float2int";
		case ENC_FCVTZU_64D_FLOAT2FIX: return "FCVTZU_64D_float2fix";
		case ENC_FCVTZU_64D_FLOAT2INT: return "FCVTZU_64D_float2int";
		case ENC_FCVTZU_64H_FLOAT2FIX: return "FCVTZU_64H_float2fix";
		case ENC_FCVTZU_64H_FLOAT2INT: return "FCVTZU_64H_float2int";
		case ENC_FCVTZU_64S_FLOAT2FIX: return "FCVTZU_64S_float2fix";
		case ENC_FCVTZU_64S_FLOAT2INT: return "FCVTZU_64S_float2int";
		case ENC_FCVTZU_ASIMDMISC_R: return "FCVTZU_asimdmisc_R";
		case ENC_FCVTZU_ASIMDMISCFP16_R: return "FCVTZU_asimdmiscfp16_R";
		case ENC_FCVTZU_ASIMDSHF_C: return "FCVTZU_asimdshf_C";
		case ENC_FCVTZU_ASISDMISC_R: return "FCVTZU_asisdmisc_R";
		case ENC_FCVTZU_ASISDMISCFP16_R: return "FCVTZU_asisdmiscfp16_R";
		case ENC_FCVTZU_ASISDSHF_C: return "FCVTZU_asisdshf_C";
		case ENC_FCVT_DH_FLOATDP1: return "FCVT_DH_floatdp1";
		case ENC_FCVT_DS_FLOATDP1: return "FCVT_DS_floatdp1";
		case ENC_FCVT_HD_FLOATDP1: return "FCVT_HD_floatdp1";
		case ENC_FCVT_HS_FLOATDP1: return "FCVT_HS_floatdp1";
		case ENC_FCVT_SD_FLOATDP1: return "FCVT_SD_floatdp1";
		case ENC_FCVT_SH_FLOATDP1: return "FCVT_SH_floatdp1";
		case ENC_FDIV_D_FLOATDP2: return "FDIV_D_floatdp2";
		case ENC_FDIV_H_FLOATDP2: return "FDIV_H_floatdp2";
		case ENC_FDIV_S_FLOATDP2: return "FDIV_S_floatdp2";
		case ENC_FDIV_ASIMDSAME_ONLY: return "FDIV_asimdsame_only";
		case ENC_FDIV_ASIMDSAMEFP16_ONLY: return "FDIV_asimdsamefp16_only";
		case ENC_FJCVTZS_32D_FLOAT2INT: return "FJCVTZS_32D_float2int";
		case ENC_FMADD_D_FLOATDP3: return "FMADD_D_floatdp3";
		case ENC_FMADD_H_FLOATDP3: return "FMADD_H_floatdp3";
		case ENC_FMADD_S_FLOATDP3: return "FMADD_S_floatdp3";
		case ENC_FMAXNMP_ASIMDSAME_ONLY: return "FMAXNMP_asimdsame_only";
		case ENC_FMAXNMP_ASIMDSAMEFP16_ONLY: return "FMAXNMP_asimdsamefp16_only";
		case ENC_FMAXNMP_ASISDPAIR_ONLY_H: return "FMAXNMP_asisdpair_only_H";
		case ENC_FMAXNMP_ASISDPAIR_ONLY_SD: return "FMAXNMP_asisdpair_only_SD";
		case ENC_FMAXNMV_ASIMDALL_ONLY_H: return "FMAXNMV_asimdall_only_H";
		case ENC_FMAXNMV_ASIMDALL_ONLY_SD: return "FMAXNMV_asimdall_only_SD";
		case ENC_FMAXNM_D_FLOATDP2: return "FMAXNM_D_floatdp2";
		case ENC_FMAXNM_H_FLOATDP2: return "FMAXNM_H_floatdp2";
		case ENC_FMAXNM_S_FLOATDP2: return "FMAXNM_S_floatdp2";
		case ENC_FMAXNM_ASIMDSAME_ONLY: return "FMAXNM_asimdsame_only";
		case ENC_FMAXNM_ASIMDSAMEFP16_ONLY: return "FMAXNM_asimdsamefp16_only";
		case ENC_FMAXP_ASIMDSAME_ONLY: return "FMAXP_asimdsame_only";
		case ENC_FMAXP_ASIMDSAMEFP16_ONLY: return "FMAXP_asimdsamefp16_only";
		case ENC_FMAXP_ASISDPAIR_ONLY_H: return "FMAXP_asisdpair_only_H";
		case ENC_FMAXP_ASISDPAIR_ONLY_SD: return "FMAXP_asisdpair_only_SD";
		case ENC_FMAXV_ASIMDALL_ONLY_H: return "FMAXV_asimdall_only_H";
		case ENC_FMAXV_ASIMDALL_ONLY_SD: return "FMAXV_asimdall_only_SD";
		case ENC_FMAX_D_FLOATDP2: return "FMAX_D_floatdp2";
		case ENC_FMAX_H_FLOATDP2: return "FMAX_H_floatdp2";
		case ENC_FMAX_S_FLOATDP2: return "FMAX_S_floatdp2";
		case ENC_FMAX_ASIMDSAME_ONLY: return "FMAX_asimdsame_only";
		case ENC_FMAX_ASIMDSAMEFP16_ONLY: return "FMAX_asimdsamefp16_only";
		case ENC_FMINNMP_ASIMDSAME_ONLY: return "FMINNMP_asimdsame_only";
		case ENC_FMINNMP_ASIMDSAMEFP16_ONLY: return "FMINNMP_asimdsamefp16_only";
		case ENC_FMINNMP_ASISDPAIR_ONLY_H: return "FMINNMP_asisdpair_only_H";
		case ENC_FMINNMP_ASISDPAIR_ONLY_SD: return "FMINNMP_asisdpair_only_SD";
		case ENC_FMINNMV_ASIMDALL_ONLY_H: return "FMINNMV_asimdall_only_H";
		case ENC_FMINNMV_ASIMDALL_ONLY_SD: return "FMINNMV_asimdall_only_SD";
		case ENC_FMINNM_D_FLOATDP2: return "FMINNM_D_floatdp2";
		case ENC_FMINNM_H_FLOATDP2: return "FMINNM_H_floatdp2";
		case ENC_FMINNM_S_FLOATDP2: return "FMINNM_S_floatdp2";
		case ENC_FMINNM_ASIMDSAME_ONLY: return "FMINNM_asimdsame_only";
		case ENC_FMINNM_ASIMDSAMEFP16_ONLY: return "FMINNM_asimdsamefp16_only";
		case ENC_FMINP_ASIMDSAME_ONLY: return "FMINP_asimdsame_only";
		case ENC_FMINP_ASIMDSAMEFP16_ONLY: return "FMINP_asimdsamefp16_only";
		case ENC_FMINP_ASISDPAIR_ONLY_H: return "FMINP_asisdpair_only_H";
		case ENC_FMINP_ASISDPAIR_ONLY_SD: return "FMINP_asisdpair_only_SD";
		case ENC_FMINV_ASIMDALL_ONLY_H: return "FMINV_asimdall_only_H";
		case ENC_FMINV_ASIMDALL_ONLY_SD: return "FMINV_asimdall_only_SD";
		case ENC_FMIN_D_FLOATDP2: return "FMIN_D_floatdp2";
		case ENC_FMIN_H_FLOATDP2: return "FMIN_H_floatdp2";
		case ENC_FMIN_S_FLOATDP2: return "FMIN_S_floatdp2";
		case ENC_FMIN_ASIMDSAME_ONLY: return "FMIN_asimdsame_only";
		case ENC_FMIN_ASIMDSAMEFP16_ONLY: return "FMIN_asimdsamefp16_only";
		case ENC_FMLAL2_ASIMDELEM_LH: return "FMLAL2_asimdelem_LH";
		case ENC_FMLAL2_ASIMDSAME_F: return "FMLAL2_asimdsame_F";
		case ENC_FMLAL_ASIMDELEM_LH: return "FMLAL_asimdelem_LH";
		case ENC_FMLAL_ASIMDSAME_F: return "FMLAL_asimdsame_F";
		case ENC_FMLA_ASIMDELEM_RH_H: return "FMLA_asimdelem_RH_H";
		case ENC_FMLA_ASIMDELEM_R_SD: return "FMLA_asimdelem_R_SD";
		case ENC_FMLA_ASIMDSAME_ONLY: return "FMLA_asimdsame_only";
		case ENC_FMLA_ASIMDSAMEFP16_ONLY: return "FMLA_asimdsamefp16_only";
		case ENC_FMLA_ASISDELEM_RH_H: return "FMLA_asisdelem_RH_H";
		case ENC_FMLA_ASISDELEM_R_SD: return "FMLA_asisdelem_R_SD";
		case ENC_FMLSL2_ASIMDELEM_LH: return "FMLSL2_asimdelem_LH";
		case ENC_FMLSL2_ASIMDSAME_F: return "FMLSL2_asimdsame_F";
		case ENC_FMLSL_ASIMDELEM_LH: return "FMLSL_asimdelem_LH";
		case ENC_FMLSL_ASIMDSAME_F: return "FMLSL_asimdsame_F";
		case ENC_FMLS_ASIMDELEM_RH_H: return "FMLS_asimdelem_RH_H";
		case ENC_FMLS_ASIMDELEM_R_SD: return "FMLS_asimdelem_R_SD";
		case ENC_FMLS_ASIMDSAME_ONLY: return "FMLS_asimdsame_only";
		case ENC_FMLS_ASIMDSAMEFP16_ONLY: return "FMLS_asimdsamefp16_only";
		case ENC_FMLS_ASISDELEM_RH_H: return "FMLS_asisdelem_RH_H";
		case ENC_FMLS_ASISDELEM_R_SD: return "FMLS_asisdelem_R_SD";
		case ENC_FMOV_32H_FLOAT2INT: return "FMOV_32H_float2int";
		case ENC_FMOV_32S_FLOAT2INT: return "FMOV_32S_float2int";
		case ENC_FMOV_64D_FLOAT2INT: return "FMOV_64D_float2int";
		case ENC_FMOV_64H_FLOAT2INT: return "FMOV_64H_float2int";
		case ENC_FMOV_64VX_FLOAT2INT: return "FMOV_64VX_float2int";
		case ENC_FMOV_D64_FLOAT2INT: return "FMOV_D64_float2int";
		case ENC_FMOV_D_FLOATDP1: return "FMOV_D_floatdp1";
		case ENC_FMOV_D_FLOATIMM: return "FMOV_D_floatimm";
		case ENC_FMOV_H32_FLOAT2INT: return "FMOV_H32_float2int";
		case ENC_FMOV_H64_FLOAT2INT: return "FMOV_H64_float2int";
		case ENC_FMOV_H_FLOATDP1: return "FMOV_H_floatdp1";
		case ENC_FMOV_H_FLOATIMM: return "FMOV_H_floatimm";
		case ENC_FMOV_S32_FLOAT2INT: return "FMOV_S32_float2int";
		case ENC_FMOV_S_FLOATDP1: return "FMOV_S_floatdp1";
		case ENC_FMOV_S_FLOATIMM: return "FMOV_S_floatimm";
		case ENC_FMOV_V64I_FLOAT2INT: return "FMOV_V64I_float2int";
		case ENC_FMOV_ASIMDIMM_D2_D: return "FMOV_asimdimm_D2_d";
		case ENC_FMOV_ASIMDIMM_H_H: return "FMOV_asimdimm_H_h";
		case ENC_FMOV_ASIMDIMM_S_S: return "FMOV_asimdimm_S_s";
		case ENC_FMOV_CPY_Z_P_I_: return "FMOV_cpy_z_p_i_";
		case ENC_FMOV_DUP_Z_I_: return "FMOV_dup_z_i_";
		case ENC_FMOV_FCPY_Z_P_I_: return "FMOV_fcpy_z_p_i_";
		case ENC_FMOV_FDUP_Z_I_: return "FMOV_fdup_z_i_";
		case ENC_FMSUB_D_FLOATDP3: return "FMSUB_D_floatdp3";
		case ENC_FMSUB_H_FLOATDP3: return "FMSUB_H_floatdp3";
		case ENC_FMSUB_S_FLOATDP3: return "FMSUB_S_floatdp3";
		case ENC_FMULX_ASIMDELEM_RH_H: return "FMULX_asimdelem_RH_H";
		case ENC_FMULX_ASIMDELEM_R_SD: return "FMULX_asimdelem_R_SD";
		case ENC_FMULX_ASIMDSAME_ONLY: return "FMULX_asimdsame_only";
		case ENC_FMULX_ASIMDSAMEFP16_ONLY: return "FMULX_asimdsamefp16_only";
		case ENC_FMULX_ASISDELEM_RH_H: return "FMULX_asisdelem_RH_H";
		case ENC_FMULX_ASISDELEM_R_SD: return "FMULX_asisdelem_R_SD";
		case ENC_FMULX_ASISDSAME_ONLY: return "FMULX_asisdsame_only";
		case ENC_FMULX_ASISDSAMEFP16_ONLY: return "FMULX_asisdsamefp16_only";
		case ENC_FMUL_D_FLOATDP2: return "FMUL_D_floatdp2";
		case ENC_FMUL_H_FLOATDP2: return "FMUL_H_floatdp2";
		case ENC_FMUL_S_FLOATDP2: return "FMUL_S_floatdp2";
		case ENC_FMUL_ASIMDELEM_RH_H: return "FMUL_asimdelem_RH_H";
		case ENC_FMUL_ASIMDELEM_R_SD: return "FMUL_asimdelem_R_SD";
		case ENC_FMUL_ASIMDSAME_ONLY: return "FMUL_asimdsame_only";
		case ENC_FMUL_ASIMDSAMEFP16_ONLY: return "FMUL_asimdsamefp16_only";
		case ENC_FMUL_ASISDELEM_RH_H: return "FMUL_asisdelem_RH_H";
		case ENC_FMUL_ASISDELEM_R_SD: return "FMUL_asisdelem_R_SD";
		case ENC_FNEG_D_FLOATDP1: return "FNEG_D_floatdp1";
		case ENC_FNEG_H_FLOATDP1: return "FNEG_H_floatdp1";
		case ENC_FNEG_S_FLOATDP1: return "FNEG_S_floatdp1";
		case ENC_FNEG_ASIMDMISC_R: return "FNEG_asimdmisc_R";
		case ENC_FNEG_ASIMDMISCFP16_R: return "FNEG_asimdmiscfp16_R";
		case ENC_FNMADD_D_FLOATDP3: return "FNMADD_D_floatdp3";
		case ENC_FNMADD_H_FLOATDP3: return "FNMADD_H_floatdp3";
		case ENC_FNMADD_S_FLOATDP3: return "FNMADD_S_floatdp3";
		case ENC_FNMSUB_D_FLOATDP3: return "FNMSUB_D_floatdp3";
		case ENC_FNMSUB_H_FLOATDP3: return "FNMSUB_H_floatdp3";
		case ENC_FNMSUB_S_FLOATDP3: return "FNMSUB_S_floatdp3";
		case ENC_FNMUL_D_FLOATDP2: return "FNMUL_D_floatdp2";
		case ENC_FNMUL_H_FLOATDP2: return "FNMUL_H_floatdp2";
		case ENC_FNMUL_S_FLOATDP2: return "FNMUL_S_floatdp2";
		case ENC_FRECPE_ASIMDMISC_R: return "FRECPE_asimdmisc_R";
		case ENC_FRECPE_ASIMDMISCFP16_R: return "FRECPE_asimdmiscfp16_R";
		case ENC_FRECPE_ASISDMISC_R: return "FRECPE_asisdmisc_R";
		case ENC_FRECPE_ASISDMISCFP16_R: return "FRECPE_asisdmiscfp16_R";
		case ENC_FRECPS_ASIMDSAME_ONLY: return "FRECPS_asimdsame_only";
		case ENC_FRECPS_ASIMDSAMEFP16_ONLY: return "FRECPS_asimdsamefp16_only";
		case ENC_FRECPS_ASISDSAME_ONLY: return "FRECPS_asisdsame_only";
		case ENC_FRECPS_ASISDSAMEFP16_ONLY: return "FRECPS_asisdsamefp16_only";
		case ENC_FRECPX_ASISDMISC_R: return "FRECPX_asisdmisc_R";
		case ENC_FRECPX_ASISDMISCFP16_R: return "FRECPX_asisdmiscfp16_R";
		case ENC_FRINT32X_D_FLOATDP1: return "FRINT32X_D_floatdp1";
		case ENC_FRINT32X_S_FLOATDP1: return "FRINT32X_S_floatdp1";
		case ENC_FRINT32X_ASIMDMISC_R: return "FRINT32X_asimdmisc_R";
		case ENC_FRINT32Z_D_FLOATDP1: return "FRINT32Z_D_floatdp1";
		case ENC_FRINT32Z_S_FLOATDP1: return "FRINT32Z_S_floatdp1";
		case ENC_FRINT32Z_ASIMDMISC_R: return "FRINT32Z_asimdmisc_R";
		case ENC_FRINT64X_D_FLOATDP1: return "FRINT64X_D_floatdp1";
		case ENC_FRINT64X_S_FLOATDP1: return "FRINT64X_S_floatdp1";
		case ENC_FRINT64X_ASIMDMISC_R: return "FRINT64X_asimdmisc_R";
		case ENC_FRINT64Z_D_FLOATDP1: return "FRINT64Z_D_floatdp1";
		case ENC_FRINT64Z_S_FLOATDP1: return "FRINT64Z_S_floatdp1";
		case ENC_FRINT64Z_ASIMDMISC_R: return "FRINT64Z_asimdmisc_R";
		case ENC_FRINTA_D_FLOATDP1: return "FRINTA_D_floatdp1";
		case ENC_FRINTA_H_FLOATDP1: return "FRINTA_H_floatdp1";
		case ENC_FRINTA_S_FLOATDP1: return "FRINTA_S_floatdp1";
		case ENC_FRINTA_ASIMDMISC_R: return "FRINTA_asimdmisc_R";
		case ENC_FRINTA_ASIMDMISCFP16_R: return "FRINTA_asimdmiscfp16_R";
		case ENC_FRINTI_D_FLOATDP1: return "FRINTI_D_floatdp1";
		case ENC_FRINTI_H_FLOATDP1: return "FRINTI_H_floatdp1";
		case ENC_FRINTI_S_FLOATDP1: return "FRINTI_S_floatdp1";
		case ENC_FRINTI_ASIMDMISC_R: return "FRINTI_asimdmisc_R";
		case ENC_FRINTI_ASIMDMISCFP16_R: return "FRINTI_asimdmiscfp16_R";
		case ENC_FRINTM_D_FLOATDP1: return "FRINTM_D_floatdp1";
		case ENC_FRINTM_H_FLOATDP1: return "FRINTM_H_floatdp1";
		case ENC_FRINTM_S_FLOATDP1: return "FRINTM_S_floatdp1";
		case ENC_FRINTM_ASIMDMISC_R: return "FRINTM_asimdmisc_R";
		case ENC_FRINTM_ASIMDMISCFP16_R: return "FRINTM_asimdmiscfp16_R";
		case ENC_FRINTN_D_FLOATDP1: return "FRINTN_D_floatdp1";
		case ENC_FRINTN_H_FLOATDP1: return "FRINTN_H_floatdp1";
		case ENC_FRINTN_S_FLOATDP1: return "FRINTN_S_floatdp1";
		case ENC_FRINTN_ASIMDMISC_R: return "FRINTN_asimdmisc_R";
		case ENC_FRINTN_ASIMDMISCFP16_R: return "FRINTN_asimdmiscfp16_R";
		case ENC_FRINTP_D_FLOATDP1: return "FRINTP_D_floatdp1";
		case ENC_FRINTP_H_FLOATDP1: return "FRINTP_H_floatdp1";
		case ENC_FRINTP_S_FLOATDP1: return "FRINTP_S_floatdp1";
		case ENC_FRINTP_ASIMDMISC_R: return "FRINTP_asimdmisc_R";
		case ENC_FRINTP_ASIMDMISCFP16_R: return "FRINTP_asimdmiscfp16_R";
		case ENC_FRINTX_D_FLOATDP1: return "FRINTX_D_floatdp1";
		case ENC_FRINTX_H_FLOATDP1: return "FRINTX_H_floatdp1";
		case ENC_FRINTX_S_FLOATDP1: return "FRINTX_S_floatdp1";
		case ENC_FRINTX_ASIMDMISC_R: return "FRINTX_asimdmisc_R";
		case ENC_FRINTX_ASIMDMISCFP16_R: return "FRINTX_asimdmiscfp16_R";
		case ENC_FRINTZ_D_FLOATDP1: return "FRINTZ_D_floatdp1";
		case ENC_FRINTZ_H_FLOATDP1: return "FRINTZ_H_floatdp1";
		case ENC_FRINTZ_S_FLOATDP1: return "FRINTZ_S_floatdp1";
		case ENC_FRINTZ_ASIMDMISC_R: return "FRINTZ_asimdmisc_R";
		case ENC_FRINTZ_ASIMDMISCFP16_R: return "FRINTZ_asimdmiscfp16_R";
		case ENC_FRSQRTE_ASIMDMISC_R: return "FRSQRTE_asimdmisc_R";
		case ENC_FRSQRTE_ASIMDMISCFP16_R: return "FRSQRTE_asimdmiscfp16_R";
		case ENC_FRSQRTE_ASISDMISC_R: return "FRSQRTE_asisdmisc_R";
		case ENC_FRSQRTE_ASISDMISCFP16_R: return "FRSQRTE_asisdmiscfp16_R";
		case ENC_FRSQRTS_ASIMDSAME_ONLY: return "FRSQRTS_asimdsame_only";
		case ENC_FRSQRTS_ASIMDSAMEFP16_ONLY: return "FRSQRTS_asimdsamefp16_only";
		case ENC_FRSQRTS_ASISDSAME_ONLY: return "FRSQRTS_asisdsame_only";
		case ENC_FRSQRTS_ASISDSAMEFP16_ONLY: return "FRSQRTS_asisdsamefp16_only";
		case ENC_FSQRT_D_FLOATDP1: return "FSQRT_D_floatdp1";
		case ENC_FSQRT_H_FLOATDP1: return "FSQRT_H_floatdp1";
		case ENC_FSQRT_S_FLOATDP1: return "FSQRT_S_floatdp1";
		case ENC_FSQRT_ASIMDMISC_R: return "FSQRT_asimdmisc_R";
		case ENC_FSQRT_ASIMDMISCFP16_R: return "FSQRT_asimdmiscfp16_R";
		case ENC_FSUB_D_FLOATDP2: return "FSUB_D_floatdp2";
		case ENC_FSUB_H_FLOATDP2: return "FSUB_H_floatdp2";
		case ENC_FSUB_S_FLOATDP2: return "FSUB_S_floatdp2";
		case ENC_FSUB_ASIMDSAME_ONLY: return "FSUB_asimdsame_only";
		case ENC_FSUB_ASIMDSAMEFP16_ONLY: return "FSUB_asimdsamefp16_only";
		case ENC_GMI_64G_DP_2SRC: return "GMI_64G_dp_2src";
		case ENC_HINT_HM_HINTS: return "HINT_HM_hints";
		case ENC_HLT_EX_EXCEPTION: return "HLT_EX_exception";
		case ENC_HVC_EX_EXCEPTION: return "HVC_EX_exception";
		case ENC_IC_SYS_CR_SYSTEMINSTRS: return "IC_SYS_CR_systeminstrs";
		case ENC_INS_ASIMDINS_IR_R: return "INS_asimdins_IR_r";
		case ENC_INS_ASIMDINS_IV_V: return "INS_asimdins_IV_v";
		case ENC_IRG_64I_DP_2SRC: return "IRG_64I_dp_2src";
		case ENC_ISB_BI_BARRIERS: return "ISB_BI_barriers";
		case ENC_LD1R_ASISDLSO_R1: return "LD1R_asisdlso_R1";
		case ENC_LD1R_ASISDLSOP_R1_I: return "LD1R_asisdlsop_R1_i";
		case ENC_LD1R_ASISDLSOP_RX1_R: return "LD1R_asisdlsop_RX1_r";
		case ENC_LD1_ASISDLSE_R1_1V: return "LD1_asisdlse_R1_1v";
		case ENC_LD1_ASISDLSE_R2_2V: return "LD1_asisdlse_R2_2v";
		case ENC_LD1_ASISDLSE_R3_3V: return "LD1_asisdlse_R3_3v";
		case ENC_LD1_ASISDLSE_R4_4V: return "LD1_asisdlse_R4_4v";
		case ENC_LD1_ASISDLSEP_I1_I1: return "LD1_asisdlsep_I1_i1";
		case ENC_LD1_ASISDLSEP_I2_I2: return "LD1_asisdlsep_I2_i2";
		case ENC_LD1_ASISDLSEP_I3_I3: return "LD1_asisdlsep_I3_i3";
		case ENC_LD1_ASISDLSEP_I4_I4: return "LD1_asisdlsep_I4_i4";
		case ENC_LD1_ASISDLSEP_R1_R1: return "LD1_asisdlsep_R1_r1";
		case ENC_LD1_ASISDLSEP_R2_R2: return "LD1_asisdlsep_R2_r2";
		case ENC_LD1_ASISDLSEP_R3_R3: return "LD1_asisdlsep_R3_r3";
		case ENC_LD1_ASISDLSEP_R4_R4: return "LD1_asisdlsep_R4_r4";
		case ENC_LD1_ASISDLSO_B1_1B: return "LD1_asisdlso_B1_1b";
		case ENC_LD1_ASISDLSO_D1_1D: return "LD1_asisdlso_D1_1d";
		case ENC_LD1_ASISDLSO_H1_1H: return "LD1_asisdlso_H1_1h";
		case ENC_LD1_ASISDLSO_S1_1S: return "LD1_asisdlso_S1_1s";
		case ENC_LD1_ASISDLSOP_B1_I1B: return "LD1_asisdlsop_B1_i1b";
		case ENC_LD1_ASISDLSOP_BX1_R1B: return "LD1_asisdlsop_BX1_r1b";
		case ENC_LD1_ASISDLSOP_D1_I1D: return "LD1_asisdlsop_D1_i1d";
		case ENC_LD1_ASISDLSOP_DX1_R1D: return "LD1_asisdlsop_DX1_r1d";
		case ENC_LD1_ASISDLSOP_H1_I1H: return "LD1_asisdlsop_H1_i1h";
		case ENC_LD1_ASISDLSOP_HX1_R1H: return "LD1_asisdlsop_HX1_r1h";
		case ENC_LD1_ASISDLSOP_S1_I1S: return "LD1_asisdlsop_S1_i1s";
		case ENC_LD1_ASISDLSOP_SX1_R1S: return "LD1_asisdlsop_SX1_r1s";
		case ENC_LD2R_ASISDLSO_R2: return "LD2R_asisdlso_R2";
		case ENC_LD2R_ASISDLSOP_R2_I: return "LD2R_asisdlsop_R2_i";
		case ENC_LD2R_ASISDLSOP_RX2_R: return "LD2R_asisdlsop_RX2_r";
		case ENC_LD2_ASISDLSE_R2: return "LD2_asisdlse_R2";
		case ENC_LD2_ASISDLSEP_I2_I: return "LD2_asisdlsep_I2_i";
		case ENC_LD2_ASISDLSEP_R2_R: return "LD2_asisdlsep_R2_r";
		case ENC_LD2_ASISDLSO_B2_2B: return "LD2_asisdlso_B2_2b";
		case ENC_LD2_ASISDLSO_D2_2D: return "LD2_asisdlso_D2_2d";
		case ENC_LD2_ASISDLSO_H2_2H: return "LD2_asisdlso_H2_2h";
		case ENC_LD2_ASISDLSO_S2_2S: return "LD2_asisdlso_S2_2s";
		case ENC_LD2_ASISDLSOP_B2_I2B: return "LD2_asisdlsop_B2_i2b";
		case ENC_LD2_ASISDLSOP_BX2_R2B: return "LD2_asisdlsop_BX2_r2b";
		case ENC_LD2_ASISDLSOP_D2_I2D: return "LD2_asisdlsop_D2_i2d";
		case ENC_LD2_ASISDLSOP_DX2_R2D: return "LD2_asisdlsop_DX2_r2d";
		case ENC_LD2_ASISDLSOP_H2_I2H: return "LD2_asisdlsop_H2_i2h";
		case ENC_LD2_ASISDLSOP_HX2_R2H: return "LD2_asisdlsop_HX2_r2h";
		case ENC_LD2_ASISDLSOP_S2_I2S: return "LD2_asisdlsop_S2_i2s";
		case ENC_LD2_ASISDLSOP_SX2_R2S: return "LD2_asisdlsop_SX2_r2s";
		case ENC_LD3R_ASISDLSO_R3: return "LD3R_asisdlso_R3";
		case ENC_LD3R_ASISDLSOP_R3_I: return "LD3R_asisdlsop_R3_i";
		case ENC_LD3R_ASISDLSOP_RX3_R: return "LD3R_asisdlsop_RX3_r";
		case ENC_LD3_ASISDLSE_R3: return "LD3_asisdlse_R3";
		case ENC_LD3_ASISDLSEP_I3_I: return "LD3_asisdlsep_I3_i";
		case ENC_LD3_ASISDLSEP_R3_R: return "LD3_asisdlsep_R3_r";
		case ENC_LD3_ASISDLSO_B3_3B: return "LD3_asisdlso_B3_3b";
		case ENC_LD3_ASISDLSO_D3_3D: return "LD3_asisdlso_D3_3d";
		case ENC_LD3_ASISDLSO_H3_3H: return "LD3_asisdlso_H3_3h";
		case ENC_LD3_ASISDLSO_S3_3S: return "LD3_asisdlso_S3_3s";
		case ENC_LD3_ASISDLSOP_B3_I3B: return "LD3_asisdlsop_B3_i3b";
		case ENC_LD3_ASISDLSOP_BX3_R3B: return "LD3_asisdlsop_BX3_r3b";
		case ENC_LD3_ASISDLSOP_D3_I3D: return "LD3_asisdlsop_D3_i3d";
		case ENC_LD3_ASISDLSOP_DX3_R3D: return "LD3_asisdlsop_DX3_r3d";
		case ENC_LD3_ASISDLSOP_H3_I3H: return "LD3_asisdlsop_H3_i3h";
		case ENC_LD3_ASISDLSOP_HX3_R3H: return "LD3_asisdlsop_HX3_r3h";
		case ENC_LD3_ASISDLSOP_S3_I3S: return "LD3_asisdlsop_S3_i3s";
		case ENC_LD3_ASISDLSOP_SX3_R3S: return "LD3_asisdlsop_SX3_r3s";
		case ENC_LD4R_ASISDLSO_R4: return "LD4R_asisdlso_R4";
		case ENC_LD4R_ASISDLSOP_R4_I: return "LD4R_asisdlsop_R4_i";
		case ENC_LD4R_ASISDLSOP_RX4_R: return "LD4R_asisdlsop_RX4_r";
		case ENC_LD4_ASISDLSE_R4: return "LD4_asisdlse_R4";
		case ENC_LD4_ASISDLSEP_I4_I: return "LD4_asisdlsep_I4_i";
		case ENC_LD4_ASISDLSEP_R4_R: return "LD4_asisdlsep_R4_r";
		case ENC_LD4_ASISDLSO_B4_4B: return "LD4_asisdlso_B4_4b";
		case ENC_LD4_ASISDLSO_D4_4D: return "LD4_asisdlso_D4_4d";
		case ENC_LD4_ASISDLSO_H4_4H: return "LD4_asisdlso_H4_4h";
		case ENC_LD4_ASISDLSO_S4_4S: return "LD4_asisdlso_S4_4s";
		case ENC_LD4_ASISDLSOP_B4_I4B: return "LD4_asisdlsop_B4_i4b";
		case ENC_LD4_ASISDLSOP_BX4_R4B: return "LD4_asisdlsop_BX4_r4b";
		case ENC_LD4_ASISDLSOP_D4_I4D: return "LD4_asisdlsop_D4_i4d";
		case ENC_LD4_ASISDLSOP_DX4_R4D: return "LD4_asisdlsop_DX4_r4d";
		case ENC_LD4_ASISDLSOP_H4_I4H: return "LD4_asisdlsop_H4_i4h";
		case ENC_LD4_ASISDLSOP_HX4_R4H: return "LD4_asisdlsop_HX4_r4h";
		case ENC_LD4_ASISDLSOP_S4_I4S: return "LD4_asisdlsop_S4_i4s";
		case ENC_LD4_ASISDLSOP_SX4_R4S: return "LD4_asisdlsop_SX4_r4s";
		case ENC_LDADDAB_32_MEMOP: return "LDADDAB_32_memop";
		case ENC_LDADDAH_32_MEMOP: return "LDADDAH_32_memop";
		case ENC_LDADDALB_32_MEMOP: return "LDADDALB_32_memop";
		case ENC_LDADDALH_32_MEMOP: return "LDADDALH_32_memop";
		case ENC_LDADDAL_32_MEMOP: return "LDADDAL_32_memop";
		case ENC_LDADDAL_64_MEMOP: return "LDADDAL_64_memop";
		case ENC_LDADDA_32_MEMOP: return "LDADDA_32_memop";
		case ENC_LDADDA_64_MEMOP: return "LDADDA_64_memop";
		case ENC_LDADDB_32_MEMOP: return "LDADDB_32_memop";
		case ENC_LDADDH_32_MEMOP: return "LDADDH_32_memop";
		case ENC_LDADDLB_32_MEMOP: return "LDADDLB_32_memop";
		case ENC_LDADDLH_32_MEMOP: return "LDADDLH_32_memop";
		case ENC_LDADDL_32_MEMOP: return "LDADDL_32_memop";
		case ENC_LDADDL_64_MEMOP: return "LDADDL_64_memop";
		case ENC_LDADD_32_MEMOP: return "LDADD_32_memop";
		case ENC_LDADD_64_MEMOP: return "LDADD_64_memop";
		case ENC_LDAPRB_32L_MEMOP: return "LDAPRB_32L_memop";
		case ENC_LDAPRH_32L_MEMOP: return "LDAPRH_32L_memop";
		case ENC_LDAPR_32L_MEMOP: return "LDAPR_32L_memop";
		case ENC_LDAPR_64L_MEMOP: return "LDAPR_64L_memop";
		case ENC_LDAPURB_32_LDAPSTL_UNSCALED: return "LDAPURB_32_ldapstl_unscaled";
		case ENC_LDAPURH_32_LDAPSTL_UNSCALED: return "LDAPURH_32_ldapstl_unscaled";
		case ENC_LDAPURSB_32_LDAPSTL_UNSCALED: return "LDAPURSB_32_ldapstl_unscaled";
		case ENC_LDAPURSB_64_LDAPSTL_UNSCALED: return "LDAPURSB_64_ldapstl_unscaled";
		case ENC_LDAPURSH_32_LDAPSTL_UNSCALED: return "LDAPURSH_32_ldapstl_unscaled";
		case ENC_LDAPURSH_64_LDAPSTL_UNSCALED: return "LDAPURSH_64_ldapstl_unscaled";
		case ENC_LDAPURSW_64_LDAPSTL_UNSCALED: return "LDAPURSW_64_ldapstl_unscaled";
		case ENC_LDAPUR_32_LDAPSTL_UNSCALED: return "LDAPUR_32_ldapstl_unscaled";
		case ENC_LDAPUR_64_LDAPSTL_UNSCALED: return "LDAPUR_64_ldapstl_unscaled";
		case ENC_LDARB_LR32_LDSTEXCL: return "LDARB_LR32_ldstexcl";
		case ENC_LDARH_LR32_LDSTEXCL: return "LDARH_LR32_ldstexcl";
		case ENC_LDAR_LR32_LDSTEXCL: return "LDAR_LR32_ldstexcl";
		case ENC_LDAR_LR64_LDSTEXCL: return "LDAR_LR64_ldstexcl";
		case ENC_LDAXP_LP32_LDSTEXCL: return "LDAXP_LP32_ldstexcl";
		case ENC_LDAXP_LP64_LDSTEXCL: return "LDAXP_LP64_ldstexcl";
		case ENC_LDAXRB_LR32_LDSTEXCL: return "LDAXRB_LR32_ldstexcl";
		case ENC_LDAXRH_LR32_LDSTEXCL: return "LDAXRH_LR32_ldstexcl";
		case ENC_LDAXR_LR32_LDSTEXCL: return "LDAXR_LR32_ldstexcl";
		case ENC_LDAXR_LR64_LDSTEXCL: return "LDAXR_LR64_ldstexcl";
		case ENC_LDCLRAB_32_MEMOP: return "LDCLRAB_32_memop";
		case ENC_LDCLRAH_32_MEMOP: return "LDCLRAH_32_memop";
		case ENC_LDCLRALB_32_MEMOP: return "LDCLRALB_32_memop";
		case ENC_LDCLRALH_32_MEMOP: return "LDCLRALH_32_memop";
		case ENC_LDCLRAL_32_MEMOP: return "LDCLRAL_32_memop";
		case ENC_LDCLRAL_64_MEMOP: return "LDCLRAL_64_memop";
		case ENC_LDCLRA_32_MEMOP: return "LDCLRA_32_memop";
		case ENC_LDCLRA_64_MEMOP: return "LDCLRA_64_memop";
		case ENC_LDCLRB_32_MEMOP: return "LDCLRB_32_memop";
		case ENC_LDCLRH_32_MEMOP: return "LDCLRH_32_memop";
		case ENC_LDCLRLB_32_MEMOP: return "LDCLRLB_32_memop";
		case ENC_LDCLRLH_32_MEMOP: return "LDCLRLH_32_memop";
		case ENC_LDCLRL_32_MEMOP: return "LDCLRL_32_memop";
		case ENC_LDCLRL_64_MEMOP: return "LDCLRL_64_memop";
		case ENC_LDCLR_32_MEMOP: return "LDCLR_32_memop";
		case ENC_LDCLR_64_MEMOP: return "LDCLR_64_memop";
		case ENC_LDEORAB_32_MEMOP: return "LDEORAB_32_memop";
		case ENC_LDEORAH_32_MEMOP: return "LDEORAH_32_memop";
		case ENC_LDEORALB_32_MEMOP: return "LDEORALB_32_memop";
		case ENC_LDEORALH_32_MEMOP: return "LDEORALH_32_memop";
		case ENC_LDEORAL_32_MEMOP: return "LDEORAL_32_memop";
		case ENC_LDEORAL_64_MEMOP: return "LDEORAL_64_memop";
		case ENC_LDEORA_32_MEMOP: return "LDEORA_32_memop";
		case ENC_LDEORA_64_MEMOP: return "LDEORA_64_memop";
		case ENC_LDEORB_32_MEMOP: return "LDEORB_32_memop";
		case ENC_LDEORH_32_MEMOP: return "LDEORH_32_memop";
		case ENC_LDEORLB_32_MEMOP: return "LDEORLB_32_memop";
		case ENC_LDEORLH_32_MEMOP: return "LDEORLH_32_memop";
		case ENC_LDEORL_32_MEMOP: return "LDEORL_32_memop";
		case ENC_LDEORL_64_MEMOP: return "LDEORL_64_memop";
		case ENC_LDEOR_32_MEMOP: return "LDEOR_32_memop";
		case ENC_LDEOR_64_MEMOP: return "LDEOR_64_memop";
		case ENC_LDGM_64BULK_LDSTTAGS: return "LDGM_64bulk_ldsttags";
		case ENC_LDG_64LOFFSET_LDSTTAGS: return "LDG_64Loffset_ldsttags";
		case ENC_LDLARB_LR32_LDSTEXCL: return "LDLARB_LR32_ldstexcl";
		case ENC_LDLARH_LR32_LDSTEXCL: return "LDLARH_LR32_ldstexcl";
		case ENC_LDLAR_LR32_LDSTEXCL: return "LDLAR_LR32_ldstexcl";
		case ENC_LDLAR_LR64_LDSTEXCL: return "LDLAR_LR64_ldstexcl";
		case ENC_LDNP_32_LDSTNAPAIR_OFFS: return "LDNP_32_ldstnapair_offs";
		case ENC_LDNP_64_LDSTNAPAIR_OFFS: return "LDNP_64_ldstnapair_offs";
		case ENC_LDNP_D_LDSTNAPAIR_OFFS: return "LDNP_D_ldstnapair_offs";
		case ENC_LDNP_Q_LDSTNAPAIR_OFFS: return "LDNP_Q_ldstnapair_offs";
		case ENC_LDNP_S_LDSTNAPAIR_OFFS: return "LDNP_S_ldstnapair_offs";
		case ENC_LDPSW_64_LDSTPAIR_OFF: return "LDPSW_64_ldstpair_off";
		case ENC_LDPSW_64_LDSTPAIR_POST: return "LDPSW_64_ldstpair_post";
		case ENC_LDPSW_64_LDSTPAIR_PRE: return "LDPSW_64_ldstpair_pre";
		case ENC_LDP_32_LDSTPAIR_OFF: return "LDP_32_ldstpair_off";
		case ENC_LDP_32_LDSTPAIR_POST: return "LDP_32_ldstpair_post";
		case ENC_LDP_32_LDSTPAIR_PRE: return "LDP_32_ldstpair_pre";
		case ENC_LDP_64_LDSTPAIR_OFF: return "LDP_64_ldstpair_off";
		case ENC_LDP_64_LDSTPAIR_POST: return "LDP_64_ldstpair_post";
		case ENC_LDP_64_LDSTPAIR_PRE: return "LDP_64_ldstpair_pre";
		case ENC_LDP_D_LDSTPAIR_OFF: return "LDP_D_ldstpair_off";
		case ENC_LDP_D_LDSTPAIR_POST: return "LDP_D_ldstpair_post";
		case ENC_LDP_D_LDSTPAIR_PRE: return "LDP_D_ldstpair_pre";
		case ENC_LDP_Q_LDSTPAIR_OFF: return "LDP_Q_ldstpair_off";
		case ENC_LDP_Q_LDSTPAIR_POST: return "LDP_Q_ldstpair_post";
		case ENC_LDP_Q_LDSTPAIR_PRE: return "LDP_Q_ldstpair_pre";
		case ENC_LDP_S_LDSTPAIR_OFF: return "LDP_S_ldstpair_off";
		case ENC_LDP_S_LDSTPAIR_POST: return "LDP_S_ldstpair_post";
		case ENC_LDP_S_LDSTPAIR_PRE: return "LDP_S_ldstpair_pre";
		case ENC_LDRAA_64W_LDST_PAC: return "LDRAA_64W_ldst_pac";
		case ENC_LDRAA_64_LDST_PAC: return "LDRAA_64_ldst_pac";
		case ENC_LDRAB_64W_LDST_PAC: return "LDRAB_64W_ldst_pac";
		case ENC_LDRAB_64_LDST_PAC: return "LDRAB_64_ldst_pac";
		case ENC_LDRB_32BL_LDST_REGOFF: return "LDRB_32BL_ldst_regoff";
		case ENC_LDRB_32B_LDST_REGOFF: return "LDRB_32B_ldst_regoff";
		case ENC_LDRB_32_LDST_IMMPOST: return "LDRB_32_ldst_immpost";
		case ENC_LDRB_32_LDST_IMMPRE: return "LDRB_32_ldst_immpre";
		case ENC_LDRB_32_LDST_POS: return "LDRB_32_ldst_pos";
		case ENC_LDRH_32_LDST_IMMPOST: return "LDRH_32_ldst_immpost";
		case ENC_LDRH_32_LDST_IMMPRE: return "LDRH_32_ldst_immpre";
		case ENC_LDRH_32_LDST_POS: return "LDRH_32_ldst_pos";
		case ENC_LDRH_32_LDST_REGOFF: return "LDRH_32_ldst_regoff";
		case ENC_LDRSB_32BL_LDST_REGOFF: return "LDRSB_32BL_ldst_regoff";
		case ENC_LDRSB_32B_LDST_REGOFF: return "LDRSB_32B_ldst_regoff";
		case ENC_LDRSB_32_LDST_IMMPOST: return "LDRSB_32_ldst_immpost";
		case ENC_LDRSB_32_LDST_IMMPRE: return "LDRSB_32_ldst_immpre";
		case ENC_LDRSB_32_LDST_POS: return "LDRSB_32_ldst_pos";
		case ENC_LDRSB_64BL_LDST_REGOFF: return "LDRSB_64BL_ldst_regoff";
		case ENC_LDRSB_64B_LDST_REGOFF: return "LDRSB_64B_ldst_regoff";
		case ENC_LDRSB_64_LDST_IMMPOST: return "LDRSB_64_ldst_immpost";
		case ENC_LDRSB_64_LDST_IMMPRE: return "LDRSB_64_ldst_immpre";
		case ENC_LDRSB_64_LDST_POS: return "LDRSB_64_ldst_pos";
		case ENC_LDRSH_32_LDST_IMMPOST: return "LDRSH_32_ldst_immpost";
		case ENC_LDRSH_32_LDST_IMMPRE: return "LDRSH_32_ldst_immpre";
		case ENC_LDRSH_32_LDST_POS: return "LDRSH_32_ldst_pos";
		case ENC_LDRSH_32_LDST_REGOFF: return "LDRSH_32_ldst_regoff";
		case ENC_LDRSH_64_LDST_IMMPOST: return "LDRSH_64_ldst_immpost";
		case ENC_LDRSH_64_LDST_IMMPRE: return "LDRSH_64_ldst_immpre";
		case ENC_LDRSH_64_LDST_POS: return "LDRSH_64_ldst_pos";
		case ENC_LDRSH_64_LDST_REGOFF: return "LDRSH_64_ldst_regoff";
		case ENC_LDRSW_64_LDST_IMMPOST: return "LDRSW_64_ldst_immpost";
		case ENC_LDRSW_64_LDST_IMMPRE: return "LDRSW_64_ldst_immpre";
		case ENC_LDRSW_64_LDST_POS: return "LDRSW_64_ldst_pos";
		case ENC_LDRSW_64_LDST_REGOFF: return "LDRSW_64_ldst_regoff";
		case ENC_LDRSW_64_LOADLIT: return "LDRSW_64_loadlit";
		case ENC_LDR_32_LDST_IMMPOST: return "LDR_32_ldst_immpost";
		case ENC_LDR_32_LDST_IMMPRE: return "LDR_32_ldst_immpre";
		case ENC_LDR_32_LDST_POS: return "LDR_32_ldst_pos";
		case ENC_LDR_32_LDST_REGOFF: return "LDR_32_ldst_regoff";
		case ENC_LDR_32_LOADLIT: return "LDR_32_loadlit";
		case ENC_LDR_64_LDST_IMMPOST: return "LDR_64_ldst_immpost";
		case ENC_LDR_64_LDST_IMMPRE: return "LDR_64_ldst_immpre";
		case ENC_LDR_64_LDST_POS: return "LDR_64_ldst_pos";
		case ENC_LDR_64_LDST_REGOFF: return "LDR_64_ldst_regoff";
		case ENC_LDR_64_LOADLIT: return "LDR_64_loadlit";
		case ENC_LDR_BL_LDST_REGOFF: return "LDR_BL_ldst_regoff";
		case ENC_LDR_B_LDST_IMMPOST: return "LDR_B_ldst_immpost";
		case ENC_LDR_B_LDST_IMMPRE: return "LDR_B_ldst_immpre";
		case ENC_LDR_B_LDST_POS: return "LDR_B_ldst_pos";
		case ENC_LDR_B_LDST_REGOFF: return "LDR_B_ldst_regoff";
		case ENC_LDR_D_LDST_IMMPOST: return "LDR_D_ldst_immpost";
		case ENC_LDR_D_LDST_IMMPRE: return "LDR_D_ldst_immpre";
		case ENC_LDR_D_LDST_POS: return "LDR_D_ldst_pos";
		case ENC_LDR_D_LDST_REGOFF: return "LDR_D_ldst_regoff";
		case ENC_LDR_D_LOADLIT: return "LDR_D_loadlit";
		case ENC_LDR_H_LDST_IMMPOST: return "LDR_H_ldst_immpost";
		case ENC_LDR_H_LDST_IMMPRE: return "LDR_H_ldst_immpre";
		case ENC_LDR_H_LDST_POS: return "LDR_H_ldst_pos";
		case ENC_LDR_H_LDST_REGOFF: return "LDR_H_ldst_regoff";
		case ENC_LDR_Q_LDST_IMMPOST: return "LDR_Q_ldst_immpost";
		case ENC_LDR_Q_LDST_IMMPRE: return "LDR_Q_ldst_immpre";
		case ENC_LDR_Q_LDST_POS: return "LDR_Q_ldst_pos";
		case ENC_LDR_Q_LDST_REGOFF: return "LDR_Q_ldst_regoff";
		case ENC_LDR_Q_LOADLIT: return "LDR_Q_loadlit";
		case ENC_LDR_S_LDST_IMMPOST: return "LDR_S_ldst_immpost";
		case ENC_LDR_S_LDST_IMMPRE: return "LDR_S_ldst_immpre";
		case ENC_LDR_S_LDST_POS: return "LDR_S_ldst_pos";
		case ENC_LDR_S_LDST_REGOFF: return "LDR_S_ldst_regoff";
		case ENC_LDR_S_LOADLIT: return "LDR_S_loadlit";
		case ENC_LDSETAB_32_MEMOP: return "LDSETAB_32_memop";
		case ENC_LDSETAH_32_MEMOP: return "LDSETAH_32_memop";
		case ENC_LDSETALB_32_MEMOP: return "LDSETALB_32_memop";
		case ENC_LDSETALH_32_MEMOP: return "LDSETALH_32_memop";
		case ENC_LDSETAL_32_MEMOP: return "LDSETAL_32_memop";
		case ENC_LDSETAL_64_MEMOP: return "LDSETAL_64_memop";
		case ENC_LDSETA_32_MEMOP: return "LDSETA_32_memop";
		case ENC_LDSETA_64_MEMOP: return "LDSETA_64_memop";
		case ENC_LDSETB_32_MEMOP: return "LDSETB_32_memop";
		case ENC_LDSETH_32_MEMOP: return "LDSETH_32_memop";
		case ENC_LDSETLB_32_MEMOP: return "LDSETLB_32_memop";
		case ENC_LDSETLH_32_MEMOP: return "LDSETLH_32_memop";
		case ENC_LDSETL_32_MEMOP: return "LDSETL_32_memop";
		case ENC_LDSETL_64_MEMOP: return "LDSETL_64_memop";
		case ENC_LDSET_32_MEMOP: return "LDSET_32_memop";
		case ENC_LDSET_64_MEMOP: return "LDSET_64_memop";
		case ENC_LDSMAXAB_32_MEMOP: return "LDSMAXAB_32_memop";
		case ENC_LDSMAXAH_32_MEMOP: return "LDSMAXAH_32_memop";
		case ENC_LDSMAXALB_32_MEMOP: return "LDSMAXALB_32_memop";
		case ENC_LDSMAXALH_32_MEMOP: return "LDSMAXALH_32_memop";
		case ENC_LDSMAXAL_32_MEMOP: return "LDSMAXAL_32_memop";
		case ENC_LDSMAXAL_64_MEMOP: return "LDSMAXAL_64_memop";
		case ENC_LDSMAXA_32_MEMOP: return "LDSMAXA_32_memop";
		case ENC_LDSMAXA_64_MEMOP: return "LDSMAXA_64_memop";
		case ENC_LDSMAXB_32_MEMOP: return "LDSMAXB_32_memop";
		case ENC_LDSMAXH_32_MEMOP: return "LDSMAXH_32_memop";
		case ENC_LDSMAXLB_32_MEMOP: return "LDSMAXLB_32_memop";
		case ENC_LDSMAXLH_32_MEMOP: return "LDSMAXLH_32_memop";
		case ENC_LDSMAXL_32_MEMOP: return "LDSMAXL_32_memop";
		case ENC_LDSMAXL_64_MEMOP: return "LDSMAXL_64_memop";
		case ENC_LDSMAX_32_MEMOP: return "LDSMAX_32_memop";
		case ENC_LDSMAX_64_MEMOP: return "LDSMAX_64_memop";
		case ENC_LDSMINAB_32_MEMOP: return "LDSMINAB_32_memop";
		case ENC_LDSMINAH_32_MEMOP: return "LDSMINAH_32_memop";
		case ENC_LDSMINALB_32_MEMOP: return "LDSMINALB_32_memop";
		case ENC_LDSMINALH_32_MEMOP: return "LDSMINALH_32_memop";
		case ENC_LDSMINAL_32_MEMOP: return "LDSMINAL_32_memop";
		case ENC_LDSMINAL_64_MEMOP: return "LDSMINAL_64_memop";
		case ENC_LDSMINA_32_MEMOP: return "LDSMINA_32_memop";
		case ENC_LDSMINA_64_MEMOP: return "LDSMINA_64_memop";
		case ENC_LDSMINB_32_MEMOP: return "LDSMINB_32_memop";
		case ENC_LDSMINH_32_MEMOP: return "LDSMINH_32_memop";
		case ENC_LDSMINLB_32_MEMOP: return "LDSMINLB_32_memop";
		case ENC_LDSMINLH_32_MEMOP: return "LDSMINLH_32_memop";
		case ENC_LDSMINL_32_MEMOP: return "LDSMINL_32_memop";
		case ENC_LDSMINL_64_MEMOP: return "LDSMINL_64_memop";
		case ENC_LDSMIN_32_MEMOP: return "LDSMIN_32_memop";
		case ENC_LDSMIN_64_MEMOP: return "LDSMIN_64_memop";
		case ENC_LDTRB_32_LDST_UNPRIV: return "LDTRB_32_ldst_unpriv";
		case ENC_LDTRH_32_LDST_UNPRIV: return "LDTRH_32_ldst_unpriv";
		case ENC_LDTRSB_32_LDST_UNPRIV: return "LDTRSB_32_ldst_unpriv";
		case ENC_LDTRSB_64_LDST_UNPRIV: return "LDTRSB_64_ldst_unpriv";
		case ENC_LDTRSH_32_LDST_UNPRIV: return "LDTRSH_32_ldst_unpriv";
		case ENC_LDTRSH_64_LDST_UNPRIV: return "LDTRSH_64_ldst_unpriv";
		case ENC_LDTRSW_64_LDST_UNPRIV: return "LDTRSW_64_ldst_unpriv";
		case ENC_LDTR_32_LDST_UNPRIV: return "LDTR_32_ldst_unpriv";
		case ENC_LDTR_64_LDST_UNPRIV: return "LDTR_64_ldst_unpriv";
		case ENC_LDUMAXAB_32_MEMOP: return "LDUMAXAB_32_memop";
		case ENC_LDUMAXAH_32_MEMOP: return "LDUMAXAH_32_memop";
		case ENC_LDUMAXALB_32_MEMOP: return "LDUMAXALB_32_memop";
		case ENC_LDUMAXALH_32_MEMOP: return "LDUMAXALH_32_memop";
		case ENC_LDUMAXAL_32_MEMOP: return "LDUMAXAL_32_memop";
		case ENC_LDUMAXAL_64_MEMOP: return "LDUMAXAL_64_memop";
		case ENC_LDUMAXA_32_MEMOP: return "LDUMAXA_32_memop";
		case ENC_LDUMAXA_64_MEMOP: return "LDUMAXA_64_memop";
		case ENC_LDUMAXB_32_MEMOP: return "LDUMAXB_32_memop";
		case ENC_LDUMAXH_32_MEMOP: return "LDUMAXH_32_memop";
		case ENC_LDUMAXLB_32_MEMOP: return "LDUMAXLB_32_memop";
		case ENC_LDUMAXLH_32_MEMOP: return "LDUMAXLH_32_memop";
		case ENC_LDUMAXL_32_MEMOP: return "LDUMAXL_32_memop";
		case ENC_LDUMAXL_64_MEMOP: return "LDUMAXL_64_memop";
		case ENC_LDUMAX_32_MEMOP: return "LDUMAX_32_memop";
		case ENC_LDUMAX_64_MEMOP: return "LDUMAX_64_memop";
		case ENC_LDUMINAB_32_MEMOP: return "LDUMINAB_32_memop";
		case ENC_LDUMINAH_32_MEMOP: return "LDUMINAH_32_memop";
		case ENC_LDUMINALB_32_MEMOP: return "LDUMINALB_32_memop";
		case ENC_LDUMINALH_32_MEMOP: return "LDUMINALH_32_memop";
		case ENC_LDUMINAL_32_MEMOP: return "LDUMINAL_32_memop";
		case ENC_LDUMINAL_64_MEMOP: return "LDUMINAL_64_memop";
		case ENC_LDUMINA_32_MEMOP: return "LDUMINA_32_memop";
		case ENC_LDUMINA_64_MEMOP: return "LDUMINA_64_memop";
		case ENC_LDUMINB_32_MEMOP: return "LDUMINB_32_memop";
		case ENC_LDUMINH_32_MEMOP: return "LDUMINH_32_memop";
		case ENC_LDUMINLB_32_MEMOP: return "LDUMINLB_32_memop";
		case ENC_LDUMINLH_32_MEMOP: return "LDUMINLH_32_memop";
		case ENC_LDUMINL_32_MEMOP: return "LDUMINL_32_memop";
		case ENC_LDUMINL_64_MEMOP: return "LDUMINL_64_memop";
		case ENC_LDUMIN_32_MEMOP: return "LDUMIN_32_memop";
		case ENC_LDUMIN_64_MEMOP: return "LDUMIN_64_memop";
		case ENC_LDURB_32_LDST_UNSCALED: return "LDURB_32_ldst_unscaled";
		case ENC_LDURH_32_LDST_UNSCALED: return "LDURH_32_ldst_unscaled";
		case ENC_LDURSB_32_LDST_UNSCALED: return "LDURSB_32_ldst_unscaled";
		case ENC_LDURSB_64_LDST_UNSCALED: return "LDURSB_64_ldst_unscaled";
		case ENC_LDURSH_32_LDST_UNSCALED: return "LDURSH_32_ldst_unscaled";
		case ENC_LDURSH_64_LDST_UNSCALED: return "LDURSH_64_ldst_unscaled";
		case ENC_LDURSW_64_LDST_UNSCALED: return "LDURSW_64_ldst_unscaled";
		case ENC_LDUR_32_LDST_UNSCALED: return "LDUR_32_ldst_unscaled";
		case ENC_LDUR_64_LDST_UNSCALED: return "LDUR_64_ldst_unscaled";
		case ENC_LDUR_B_LDST_UNSCALED: return "LDUR_B_ldst_unscaled";
		case ENC_LDUR_D_LDST_UNSCALED: return "LDUR_D_ldst_unscaled";
		case ENC_LDUR_H_LDST_UNSCALED: return "LDUR_H_ldst_unscaled";
		case ENC_LDUR_Q_LDST_UNSCALED: return "LDUR_Q_ldst_unscaled";
		case ENC_LDUR_S_LDST_UNSCALED: return "LDUR_S_ldst_unscaled";
		case ENC_LDXP_LP32_LDSTEXCL: return "LDXP_LP32_ldstexcl";
		case ENC_LDXP_LP64_LDSTEXCL: return "LDXP_LP64_ldstexcl";
		case ENC_LDXRB_LR32_LDSTEXCL: return "LDXRB_LR32_ldstexcl";
		case ENC_LDXRH_LR32_LDSTEXCL: return "LDXRH_LR32_ldstexcl";
		case ENC_LDXR_LR32_LDSTEXCL: return "LDXR_LR32_ldstexcl";
		case ENC_LDXR_LR64_LDSTEXCL: return "LDXR_LR64_ldstexcl";
		case ENC_LSLV_32_DP_2SRC: return "LSLV_32_dp_2src";
		case ENC_LSLV_64_DP_2SRC: return "LSLV_64_dp_2src";
		case ENC_LSL_LSLV_32_DP_2SRC: return "LSL_LSLV_32_dp_2src";
		case ENC_LSL_LSLV_64_DP_2SRC: return "LSL_LSLV_64_dp_2src";
		case ENC_LSL_UBFM_32M_BITFIELD: return "LSL_UBFM_32M_bitfield";
		case ENC_LSL_UBFM_64M_BITFIELD: return "LSL_UBFM_64M_bitfield";
		case ENC_LSRV_32_DP_2SRC: return "LSRV_32_dp_2src";
		case ENC_LSRV_64_DP_2SRC: return "LSRV_64_dp_2src";
		case ENC_LSR_LSRV_32_DP_2SRC: return "LSR_LSRV_32_dp_2src";
		case ENC_LSR_LSRV_64_DP_2SRC: return "LSR_LSRV_64_dp_2src";
		case ENC_LSR_UBFM_32M_BITFIELD: return "LSR_UBFM_32M_bitfield";
		case ENC_LSR_UBFM_64M_BITFIELD: return "LSR_UBFM_64M_bitfield";
		case ENC_MADD_32A_DP_3SRC: return "MADD_32A_dp_3src";
		case ENC_MADD_64A_DP_3SRC: return "MADD_64A_dp_3src";
		case ENC_MLA_ASIMDELEM_R: return "MLA_asimdelem_R";
		case ENC_MLA_ASIMDSAME_ONLY: return "MLA_asimdsame_only";
		case ENC_MLS_ASIMDELEM_R: return "MLS_asimdelem_R";
		case ENC_MLS_ASIMDSAME_ONLY: return "MLS_asimdsame_only";
		case ENC_MNEG_MSUB_32A_DP_3SRC: return "MNEG_MSUB_32A_dp_3src";
		case ENC_MNEG_MSUB_64A_DP_3SRC: return "MNEG_MSUB_64A_dp_3src";
		case ENC_MOVI_ASIMDIMM_D2_D: return "MOVI_asimdimm_D2_d";
		case ENC_MOVI_ASIMDIMM_D_DS: return "MOVI_asimdimm_D_ds";
		case ENC_MOVI_ASIMDIMM_L_HL: return "MOVI_asimdimm_L_hl";
		case ENC_MOVI_ASIMDIMM_L_SL: return "MOVI_asimdimm_L_sl";
		case ENC_MOVI_ASIMDIMM_M_SM: return "MOVI_asimdimm_M_sm";
		case ENC_MOVI_ASIMDIMM_N_B: return "MOVI_asimdimm_N_b";
		case ENC_MOVK_32_MOVEWIDE: return "MOVK_32_movewide";
		case ENC_MOVK_64_MOVEWIDE: return "MOVK_64_movewide";
		case ENC_MOVN_32_MOVEWIDE: return "MOVN_32_movewide";
		case ENC_MOVN_64_MOVEWIDE: return "MOVN_64_movewide";
		case ENC_MOVS_ANDS_P_P_PP_Z: return "MOVS_ands_p_p_pp_z";
		case ENC_MOVS_ORRS_P_P_PP_Z: return "MOVS_orrs_p_p_pp_z";
		case ENC_MOVZ_32_MOVEWIDE: return "MOVZ_32_movewide";
		case ENC_MOVZ_64_MOVEWIDE: return "MOVZ_64_movewide";
		case ENC_MOV_ADD_32_ADDSUB_IMM: return "MOV_ADD_32_addsub_imm";
		case ENC_MOV_ADD_64_ADDSUB_IMM: return "MOV_ADD_64_addsub_imm";
		case ENC_MOV_DUP_ASISDONE_ONLY: return "MOV_DUP_asisdone_only";
		case ENC_MOV_INS_ASIMDINS_IR_R: return "MOV_INS_asimdins_IR_r";
		case ENC_MOV_INS_ASIMDINS_IV_V: return "MOV_INS_asimdins_IV_v";
		case ENC_MOV_MOVN_32_MOVEWIDE: return "MOV_MOVN_32_movewide";
		case ENC_MOV_MOVN_64_MOVEWIDE: return "MOV_MOVN_64_movewide";
		case ENC_MOV_MOVZ_32_MOVEWIDE: return "MOV_MOVZ_32_movewide";
		case ENC_MOV_MOVZ_64_MOVEWIDE: return "MOV_MOVZ_64_movewide";
		case ENC_MOV_ORR_32_LOG_IMM: return "MOV_ORR_32_log_imm";
		case ENC_MOV_ORR_32_LOG_SHIFT: return "MOV_ORR_32_log_shift";
		case ENC_MOV_ORR_64_LOG_IMM: return "MOV_ORR_64_log_imm";
		case ENC_MOV_ORR_64_LOG_SHIFT: return "MOV_ORR_64_log_shift";
		case ENC_MOV_ORR_ASIMDSAME_ONLY: return "MOV_ORR_asimdsame_only";
		case ENC_MOV_UMOV_ASIMDINS_W_W: return "MOV_UMOV_asimdins_W_w";
		case ENC_MOV_UMOV_ASIMDINS_X_X: return "MOV_UMOV_asimdins_X_x";
		case ENC_MOV_AND_P_P_PP_Z: return "MOV_and_p_p_pp_z";
		case ENC_MOV_CPY_Z_O_I_: return "MOV_cpy_z_o_i_";
		case ENC_MOV_CPY_Z_P_I_: return "MOV_cpy_z_p_i_";
		case ENC_MOV_CPY_Z_P_R_: return "MOV_cpy_z_p_r_";
		case ENC_MOV_CPY_Z_P_V_: return "MOV_cpy_z_p_v_";
		case ENC_MOV_DUP_Z_I_: return "MOV_dup_z_i_";
		case ENC_MOV_DUP_Z_R_: return "MOV_dup_z_r_";
		case ENC_MOV_DUP_Z_ZI_: return "MOV_dup_z_zi_";
		case ENC_MOV_DUP_Z_ZI_2: return "MOV_dup_z_zi_2";
		case ENC_MOV_DUPM_Z_I_: return "MOV_dupm_z_i_";
		case ENC_MOV_ORR_P_P_PP_Z: return "MOV_orr_p_p_pp_z";
		case ENC_MOV_ORR_Z_ZZ_: return "MOV_orr_z_zz_";
		case ENC_MOV_SEL_P_P_PP_: return "MOV_sel_p_p_pp_";
		case ENC_MOV_SEL_Z_P_ZZ_: return "MOV_sel_z_p_zz_";
		case ENC_MRS_RS_SYSTEMMOVE: return "MRS_RS_systemmove";
		case ENC_MSR_SI_PSTATE: return "MSR_SI_pstate";
		case ENC_MSR_SR_SYSTEMMOVE: return "MSR_SR_systemmove";
		case ENC_MSUB_32A_DP_3SRC: return "MSUB_32A_dp_3src";
		case ENC_MSUB_64A_DP_3SRC: return "MSUB_64A_dp_3src";
		case ENC_MUL_MADD_32A_DP_3SRC: return "MUL_MADD_32A_dp_3src";
		case ENC_MUL_MADD_64A_DP_3SRC: return "MUL_MADD_64A_dp_3src";
		case ENC_MUL_ASIMDELEM_R: return "MUL_asimdelem_R";
		case ENC_MUL_ASIMDSAME_ONLY: return "MUL_asimdsame_only";
		case ENC_MVNI_ASIMDIMM_L_HL: return "MVNI_asimdimm_L_hl";
		case ENC_MVNI_ASIMDIMM_L_SL: return "MVNI_asimdimm_L_sl";
		case ENC_MVNI_ASIMDIMM_M_SM: return "MVNI_asimdimm_M_sm";
		case ENC_MVN_NOT_ASIMDMISC_R: return "MVN_NOT_asimdmisc_R";
		case ENC_MVN_ORN_32_LOG_SHIFT: return "MVN_ORN_32_log_shift";
		case ENC_MVN_ORN_64_LOG_SHIFT: return "MVN_ORN_64_log_shift";
		case ENC_NEGS_SUBS_32_ADDSUB_SHIFT: return "NEGS_SUBS_32_addsub_shift";
		case ENC_NEGS_SUBS_64_ADDSUB_SHIFT: return "NEGS_SUBS_64_addsub_shift";
		case ENC_NEG_SUB_32_ADDSUB_SHIFT: return "NEG_SUB_32_addsub_shift";
		case ENC_NEG_SUB_64_ADDSUB_SHIFT: return "NEG_SUB_64_addsub_shift";
		case ENC_NEG_ASIMDMISC_R: return "NEG_asimdmisc_R";
		case ENC_NEG_ASISDMISC_R: return "NEG_asisdmisc_R";
		case ENC_NGCS_SBCS_32_ADDSUB_CARRY: return "NGCS_SBCS_32_addsub_carry";
		case ENC_NGCS_SBCS_64_ADDSUB_CARRY: return "NGCS_SBCS_64_addsub_carry";
		case ENC_NGC_SBC_32_ADDSUB_CARRY: return "NGC_SBC_32_addsub_carry";
		case ENC_NGC_SBC_64_ADDSUB_CARRY: return "NGC_SBC_64_addsub_carry";
		case ENC_NOP_HI_HINTS: return "NOP_HI_hints";
		case ENC_NOTS_EORS_P_P_PP_Z: return "NOTS_eors_p_p_pp_z";
		case ENC_NOT_ASIMDMISC_R: return "NOT_asimdmisc_R";
		case ENC_NOT_EOR_P_P_PP_Z: return "NOT_eor_p_p_pp_z";
		case ENC_ORN_32_LOG_SHIFT: return "ORN_32_log_shift";
		case ENC_ORN_64_LOG_SHIFT: return "ORN_64_log_shift";
		case ENC_ORN_ASIMDSAME_ONLY: return "ORN_asimdsame_only";
		case ENC_ORN_ORR_Z_ZI_: return "ORN_orr_z_zi_";
		case ENC_ORR_32_LOG_IMM: return "ORR_32_log_imm";
		case ENC_ORR_32_LOG_SHIFT: return "ORR_32_log_shift";
		case ENC_ORR_64_LOG_IMM: return "ORR_64_log_imm";
		case ENC_ORR_64_LOG_SHIFT: return "ORR_64_log_shift";
		case ENC_ORR_ASIMDIMM_L_HL: return "ORR_asimdimm_L_hl";
		case ENC_ORR_ASIMDIMM_L_SL: return "ORR_asimdimm_L_sl";
		case ENC_ORR_ASIMDSAME_ONLY: return "ORR_asimdsame_only";
		case ENC_PACDA_64P_DP_1SRC: return "PACDA_64P_dp_1src";
		case ENC_PACDB_64P_DP_1SRC: return "PACDB_64P_dp_1src";
		case ENC_PACDZA_64Z_DP_1SRC: return "PACDZA_64Z_dp_1src";
		case ENC_PACDZB_64Z_DP_1SRC: return "PACDZB_64Z_dp_1src";
		case ENC_PACGA_64P_DP_2SRC: return "PACGA_64P_dp_2src";
		case ENC_PACIA1716_HI_HINTS: return "PACIA1716_HI_hints";
		case ENC_PACIASP_HI_HINTS: return "PACIASP_HI_hints";
		case ENC_PACIAZ_HI_HINTS: return "PACIAZ_HI_hints";
		case ENC_PACIA_64P_DP_1SRC: return "PACIA_64P_dp_1src";
		case ENC_PACIB1716_HI_HINTS: return "PACIB1716_HI_hints";
		case ENC_PACIBSP_HI_HINTS: return "PACIBSP_HI_hints";
		case ENC_PACIBZ_HI_HINTS: return "PACIBZ_HI_hints";
		case ENC_PACIB_64P_DP_1SRC: return "PACIB_64P_dp_1src";
		case ENC_PACIZA_64Z_DP_1SRC: return "PACIZA_64Z_dp_1src";
		case ENC_PACIZB_64Z_DP_1SRC: return "PACIZB_64Z_dp_1src";
		case ENC_PMULL_ASIMDDIFF_L: return "PMULL_asimddiff_L";
		case ENC_PMUL_ASIMDSAME_ONLY: return "PMUL_asimdsame_only";
		case ENC_PRFM_P_LDST_POS: return "PRFM_P_ldst_pos";
		case ENC_PRFM_P_LDST_REGOFF: return "PRFM_P_ldst_regoff";
		case ENC_PRFM_P_LOADLIT: return "PRFM_P_loadlit";
		case ENC_PRFUM_P_LDST_UNSCALED: return "PRFUM_P_ldst_unscaled";
		case ENC_PSB_HC_HINTS: return "PSB_HC_hints";
		case ENC_PSSBB_ONLY_BARRIERS: return "PSSBB_only_barriers";
		case ENC_RADDHN_ASIMDDIFF_N: return "RADDHN_asimddiff_N";
		case ENC_RAX1_VVV2_CRYPTOSHA512_3: return "RAX1_VVV2_cryptosha512_3";
		case ENC_RBIT_32_DP_1SRC: return "RBIT_32_dp_1src";
		case ENC_RBIT_64_DP_1SRC: return "RBIT_64_dp_1src";
		case ENC_RBIT_ASIMDMISC_R: return "RBIT_asimdmisc_R";
		case ENC_RESERVED_21_ASIMDELEM: return "RESERVED_21_asimdelem";
		case ENC_RESERVED_35_ASIMDELEM: return "RESERVED_35_asimdelem";
		case ENC_RESERVED_36_ASISDSAME: return "RESERVED_36_asisdsame";
		case ENC_RESERVED_37_ASISDSAME: return "RESERVED_37_asisdsame";
		case ENC_RESERVED_38_ASISDSAME: return "RESERVED_38_asisdsame";
		case ENC_RESERVED_39_ASISDSAME: return "RESERVED_39_asisdsame";
		case ENC_RESERVED_42_ASISDSAME: return "RESERVED_42_asisdsame";
		case ENC_RESERVED_44_ASISDSAME: return "RESERVED_44_asisdsame";
		case ENC_RESERVED_45_ASISDSAME: return "RESERVED_45_asisdsame";
		case ENC_RESERVED_46_ASISDSAME: return "RESERVED_46_asisdsame";
		case ENC_RESERVED_47_ASISDSAME: return "RESERVED_47_asisdsame";
		case ENC_RESERVED_48_ASISDSAME: return "RESERVED_48_asisdsame";
		case ENC_RESERVED_50_ASISDSAME: return "RESERVED_50_asisdsame";
		case ENC_RESERVED_52_ASISDSAME: return "RESERVED_52_asisdsame";
		case ENC_RESERVED_53_ASISDSAME: return "RESERVED_53_asisdsame";
		case ENC_RESERVED_54_ASISDSAME: return "RESERVED_54_asisdsame";
		case ENC_RESERVED_57_ASISDSAME: return "RESERVED_57_asisdsame";
		case ENC_RESERVED_67_ASISDSAME: return "RESERVED_67_asisdsame";
		case ENC_RESERVED_68_ASISDSAME: return "RESERVED_68_asisdsame";
		case ENC_RESERVED_69_ASISDSAME: return "RESERVED_69_asisdsame";
		case ENC_RESERVED_70_ASISDSAME: return "RESERVED_70_asisdsame";
		case ENC_RESERVED_72_ASISDSAME: return "RESERVED_72_asisdsame";
		case ENC_RESERVED_74_ASISDSAME: return "RESERVED_74_asisdsame";
		case ENC_RETAA_64E_BRANCH_REG: return "RETAA_64E_branch_reg";
		case ENC_RETAB_64E_BRANCH_REG: return "RETAB_64E_branch_reg";
		case ENC_RET_64R_BRANCH_REG: return "RET_64R_branch_reg";
		case ENC_REV16_32_DP_1SRC: return "REV16_32_dp_1src";
		case ENC_REV16_64_DP_1SRC: return "REV16_64_dp_1src";
		case ENC_REV16_ASIMDMISC_R: return "REV16_asimdmisc_R";
		case ENC_REV32_64_DP_1SRC: return "REV32_64_dp_1src";
		case ENC_REV32_ASIMDMISC_R: return "REV32_asimdmisc_R";
		case ENC_REV64_REV_64_DP_1SRC: return "REV64_REV_64_dp_1src";
		case ENC_REV64_ASIMDMISC_R: return "REV64_asimdmisc_R";
		case ENC_REV_32_DP_1SRC: return "REV_32_dp_1src";
		case ENC_REV_64_DP_1SRC: return "REV_64_dp_1src";
		case ENC_RMIF_ONLY_RMIF: return "RMIF_only_rmif";
		case ENC_RORV_32_DP_2SRC: return "RORV_32_dp_2src";
		case ENC_RORV_64_DP_2SRC: return "RORV_64_dp_2src";
		case ENC_ROR_EXTR_32_EXTRACT: return "ROR_EXTR_32_extract";
		case ENC_ROR_EXTR_64_EXTRACT: return "ROR_EXTR_64_extract";
		case ENC_ROR_RORV_32_DP_2SRC: return "ROR_RORV_32_dp_2src";
		case ENC_ROR_RORV_64_DP_2SRC: return "ROR_RORV_64_dp_2src";
		case ENC_RSHRN_ASIMDSHF_N: return "RSHRN_asimdshf_N";
		case ENC_RSUBHN_ASIMDDIFF_N: return "RSUBHN_asimddiff_N";
		case ENC_SABAL_ASIMDDIFF_L: return "SABAL_asimddiff_L";
		case ENC_SABA_ASIMDSAME_ONLY: return "SABA_asimdsame_only";
		case ENC_SABDL_ASIMDDIFF_L: return "SABDL_asimddiff_L";
		case ENC_SABD_ASIMDSAME_ONLY: return "SABD_asimdsame_only";
		case ENC_SADALP_ASIMDMISC_P: return "SADALP_asimdmisc_P";
		case ENC_SADDLP_ASIMDMISC_P: return "SADDLP_asimdmisc_P";
		case ENC_SADDLV_ASIMDALL_ONLY: return "SADDLV_asimdall_only";
		case ENC_SADDL_ASIMDDIFF_L: return "SADDL_asimddiff_L";
		case ENC_SADDW_ASIMDDIFF_W: return "SADDW_asimddiff_W";
		case ENC_SBCS_32_ADDSUB_CARRY: return "SBCS_32_addsub_carry";
		case ENC_SBCS_64_ADDSUB_CARRY: return "SBCS_64_addsub_carry";
		case ENC_SBC_32_ADDSUB_CARRY: return "SBC_32_addsub_carry";
		case ENC_SBC_64_ADDSUB_CARRY: return "SBC_64_addsub_carry";
		case ENC_SBFIZ_SBFM_32M_BITFIELD: return "SBFIZ_SBFM_32M_bitfield";
		case ENC_SBFIZ_SBFM_64M_BITFIELD: return "SBFIZ_SBFM_64M_bitfield";
		case ENC_SBFM_32M_BITFIELD: return "SBFM_32M_bitfield";
		case ENC_SBFM_64M_BITFIELD: return "SBFM_64M_bitfield";
		case ENC_SBFX_SBFM_32M_BITFIELD: return "SBFX_SBFM_32M_bitfield";
		case ENC_SBFX_SBFM_64M_BITFIELD: return "SBFX_SBFM_64M_bitfield";
		case ENC_SB_ONLY_BARRIERS: return "SB_only_barriers";
		case ENC_SCVTF_D32_FLOAT2FIX: return "SCVTF_D32_float2fix";
		case ENC_SCVTF_D32_FLOAT2INT: return "SCVTF_D32_float2int";
		case ENC_SCVTF_D64_FLOAT2FIX: return "SCVTF_D64_float2fix";
		case ENC_SCVTF_D64_FLOAT2INT: return "SCVTF_D64_float2int";
		case ENC_SCVTF_H32_FLOAT2FIX: return "SCVTF_H32_float2fix";
		case ENC_SCVTF_H32_FLOAT2INT: return "SCVTF_H32_float2int";
		case ENC_SCVTF_H64_FLOAT2FIX: return "SCVTF_H64_float2fix";
		case ENC_SCVTF_H64_FLOAT2INT: return "SCVTF_H64_float2int";
		case ENC_SCVTF_S32_FLOAT2FIX: return "SCVTF_S32_float2fix";
		case ENC_SCVTF_S32_FLOAT2INT: return "SCVTF_S32_float2int";
		case ENC_SCVTF_S64_FLOAT2FIX: return "SCVTF_S64_float2fix";
		case ENC_SCVTF_S64_FLOAT2INT: return "SCVTF_S64_float2int";
		case ENC_SCVTF_ASIMDMISC_R: return "SCVTF_asimdmisc_R";
		case ENC_SCVTF_ASIMDMISCFP16_R: return "SCVTF_asimdmiscfp16_R";
		case ENC_SCVTF_ASIMDSHF_C: return "SCVTF_asimdshf_C";
		case ENC_SCVTF_ASISDMISC_R: return "SCVTF_asisdmisc_R";
		case ENC_SCVTF_ASISDMISCFP16_R: return "SCVTF_asisdmiscfp16_R";
		case ENC_SCVTF_ASISDSHF_C: return "SCVTF_asisdshf_C";
		case ENC_SDIV_32_DP_2SRC: return "SDIV_32_dp_2src";
		case ENC_SDIV_64_DP_2SRC: return "SDIV_64_dp_2src";
		case ENC_SDOT_ASIMDELEM_D: return "SDOT_asimdelem_D";
		case ENC_SDOT_ASIMDSAME2_D: return "SDOT_asimdsame2_D";
		case ENC_SETF16_ONLY_SETF: return "SETF16_only_setf";
		case ENC_SETF8_ONLY_SETF: return "SETF8_only_setf";
		case ENC_SEVL_HI_HINTS: return "SEVL_HI_hints";
		case ENC_SEV_HI_HINTS: return "SEV_HI_hints";
		case ENC_SHA1C_QSV_CRYPTOSHA3: return "SHA1C_QSV_cryptosha3";
		case ENC_SHA1H_SS_CRYPTOSHA2: return "SHA1H_SS_cryptosha2";
		case ENC_SHA1M_QSV_CRYPTOSHA3: return "SHA1M_QSV_cryptosha3";
		case ENC_SHA1P_QSV_CRYPTOSHA3: return "SHA1P_QSV_cryptosha3";
		case ENC_SHA1SU0_VVV_CRYPTOSHA3: return "SHA1SU0_VVV_cryptosha3";
		case ENC_SHA1SU1_VV_CRYPTOSHA2: return "SHA1SU1_VV_cryptosha2";
		case ENC_SHA256H2_QQV_CRYPTOSHA3: return "SHA256H2_QQV_cryptosha3";
		case ENC_SHA256H_QQV_CRYPTOSHA3: return "SHA256H_QQV_cryptosha3";
		case ENC_SHA256SU0_VV_CRYPTOSHA2: return "SHA256SU0_VV_cryptosha2";
		case ENC_SHA256SU1_VVV_CRYPTOSHA3: return "SHA256SU1_VVV_cryptosha3";
		case ENC_SHA512H2_QQV_CRYPTOSHA512_3: return "SHA512H2_QQV_cryptosha512_3";
		case ENC_SHA512H_QQV_CRYPTOSHA512_3: return "SHA512H_QQV_cryptosha512_3";
		case ENC_SHA512SU0_VV2_CRYPTOSHA512_2: return "SHA512SU0_VV2_cryptosha512_2";
		case ENC_SHA512SU1_VVV2_CRYPTOSHA512_3: return "SHA512SU1_VVV2_cryptosha512_3";
		case ENC_SHADD_ASIMDSAME_ONLY: return "SHADD_asimdsame_only";
		case ENC_SHLL_ASIMDMISC_S: return "SHLL_asimdmisc_S";
		case ENC_SHL_ASIMDSHF_R: return "SHL_asimdshf_R";
		case ENC_SHL_ASISDSHF_R: return "SHL_asisdshf_R";
		case ENC_SHRN_ASIMDSHF_N: return "SHRN_asimdshf_N";
		case ENC_SHSUB_ASIMDSAME_ONLY: return "SHSUB_asimdsame_only";
		case ENC_SLI_ASIMDSHF_R: return "SLI_asimdshf_R";
		case ENC_SLI_ASISDSHF_R: return "SLI_asisdshf_R";
		case ENC_SM3PARTW1_VVV4_CRYPTOSHA512_3: return "SM3PARTW1_VVV4_cryptosha512_3";
		case ENC_SM3PARTW2_VVV4_CRYPTOSHA512_3: return "SM3PARTW2_VVV4_cryptosha512_3";
		case ENC_SM3SS1_VVV4_CRYPTO4: return "SM3SS1_VVV4_crypto4";
		case ENC_SM3TT1A_VVV4_CRYPTO3_IMM2: return "SM3TT1A_VVV4_crypto3_imm2";
		case ENC_SM3TT1B_VVV4_CRYPTO3_IMM2: return "SM3TT1B_VVV4_crypto3_imm2";
		case ENC_SM3TT2A_VVV4_CRYPTO3_IMM2: return "SM3TT2A_VVV4_crypto3_imm2";
		case ENC_SM3TT2B_VVV_CRYPTO3_IMM2: return "SM3TT2B_VVV_crypto3_imm2";
		case ENC_SM4EKEY_VVV4_CRYPTOSHA512_3: return "SM4EKEY_VVV4_cryptosha512_3";
		case ENC_SM4E_VV4_CRYPTOSHA512_2: return "SM4E_VV4_cryptosha512_2";
		case ENC_SMADDL_64WA_DP_3SRC: return "SMADDL_64WA_dp_3src";
		case ENC_SMAXP_ASIMDSAME_ONLY: return "SMAXP_asimdsame_only";
		case ENC_SMAXV_ASIMDALL_ONLY: return "SMAXV_asimdall_only";
		case ENC_SMAX_ASIMDSAME_ONLY: return "SMAX_asimdsame_only";
		case ENC_SMC_EX_EXCEPTION: return "SMC_EX_exception";
		case ENC_SMINP_ASIMDSAME_ONLY: return "SMINP_asimdsame_only";
		case ENC_SMINV_ASIMDALL_ONLY: return "SMINV_asimdall_only";
		case ENC_SMIN_ASIMDSAME_ONLY: return "SMIN_asimdsame_only";
		case ENC_SMLAL_ASIMDDIFF_L: return "SMLAL_asimddiff_L";
		case ENC_SMLAL_ASIMDELEM_L: return "SMLAL_asimdelem_L";
		case ENC_SMLSL_ASIMDDIFF_L: return "SMLSL_asimddiff_L";
		case ENC_SMLSL_ASIMDELEM_L: return "SMLSL_asimdelem_L";
		case ENC_SMMLA_ASIMDSAME2_G: return "SMMLA_asimdsame2_G";
		case ENC_SMNEGL_SMSUBL_64WA_DP_3SRC: return "SMNEGL_SMSUBL_64WA_dp_3src";
		case ENC_SMOV_ASIMDINS_W_W: return "SMOV_asimdins_W_w";
		case ENC_SMOV_ASIMDINS_X_X: return "SMOV_asimdins_X_x";
		case ENC_SMSUBL_64WA_DP_3SRC: return "SMSUBL_64WA_dp_3src";
		case ENC_SMULH_64_DP_3SRC: return "SMULH_64_dp_3src";
		case ENC_SMULL_SMADDL_64WA_DP_3SRC: return "SMULL_SMADDL_64WA_dp_3src";
		case ENC_SMULL_ASIMDDIFF_L: return "SMULL_asimddiff_L";
		case ENC_SMULL_ASIMDELEM_L: return "SMULL_asimdelem_L";
		case ENC_SQABS_ASIMDMISC_R: return "SQABS_asimdmisc_R";
		case ENC_SQABS_ASISDMISC_R: return "SQABS_asisdmisc_R";
		case ENC_SQADD_ASIMDSAME_ONLY: return "SQADD_asimdsame_only";
		case ENC_SQADD_ASISDSAME_ONLY: return "SQADD_asisdsame_only";
		case ENC_SQDMLAL_ASIMDDIFF_L: return "SQDMLAL_asimddiff_L";
		case ENC_SQDMLAL_ASIMDELEM_L: return "SQDMLAL_asimdelem_L";
		case ENC_SQDMLAL_ASISDDIFF_ONLY: return "SQDMLAL_asisddiff_only";
		case ENC_SQDMLAL_ASISDELEM_L: return "SQDMLAL_asisdelem_L";
		case ENC_SQDMLSL_ASIMDDIFF_L: return "SQDMLSL_asimddiff_L";
		case ENC_SQDMLSL_ASIMDELEM_L: return "SQDMLSL_asimdelem_L";
		case ENC_SQDMLSL_ASISDDIFF_ONLY: return "SQDMLSL_asisddiff_only";
		case ENC_SQDMLSL_ASISDELEM_L: return "SQDMLSL_asisdelem_L";
		case ENC_SQDMULH_ASIMDELEM_R: return "SQDMULH_asimdelem_R";
		case ENC_SQDMULH_ASIMDSAME_ONLY: return "SQDMULH_asimdsame_only";
		case ENC_SQDMULH_ASISDELEM_R: return "SQDMULH_asisdelem_R";
		case ENC_SQDMULH_ASISDSAME_ONLY: return "SQDMULH_asisdsame_only";
		case ENC_SQDMULL_ASIMDDIFF_L: return "SQDMULL_asimddiff_L";
		case ENC_SQDMULL_ASIMDELEM_L: return "SQDMULL_asimdelem_L";
		case ENC_SQDMULL_ASISDDIFF_ONLY: return "SQDMULL_asisddiff_only";
		case ENC_SQDMULL_ASISDELEM_L: return "SQDMULL_asisdelem_L";
		case ENC_SQNEG_ASIMDMISC_R: return "SQNEG_asimdmisc_R";
		case ENC_SQNEG_ASISDMISC_R: return "SQNEG_asisdmisc_R";
		case ENC_SQRDMLAH_ASIMDELEM_R: return "SQRDMLAH_asimdelem_R";
		case ENC_SQRDMLAH_ASIMDSAME2_ONLY: return "SQRDMLAH_asimdsame2_only";
		case ENC_SQRDMLAH_ASISDELEM_R: return "SQRDMLAH_asisdelem_R";
		case ENC_SQRDMLAH_ASISDSAME2_ONLY: return "SQRDMLAH_asisdsame2_only";
		case ENC_SQRDMLSH_ASIMDELEM_R: return "SQRDMLSH_asimdelem_R";
		case ENC_SQRDMLSH_ASIMDSAME2_ONLY: return "SQRDMLSH_asimdsame2_only";
		case ENC_SQRDMLSH_ASISDELEM_R: return "SQRDMLSH_asisdelem_R";
		case ENC_SQRDMLSH_ASISDSAME2_ONLY: return "SQRDMLSH_asisdsame2_only";
		case ENC_SQRDMULH_ASIMDELEM_R: return "SQRDMULH_asimdelem_R";
		case ENC_SQRDMULH_ASIMDSAME_ONLY: return "SQRDMULH_asimdsame_only";
		case ENC_SQRDMULH_ASISDELEM_R: return "SQRDMULH_asisdelem_R";
		case ENC_SQRDMULH_ASISDSAME_ONLY: return "SQRDMULH_asisdsame_only";
		case ENC_SQRSHL_ASIMDSAME_ONLY: return "SQRSHL_asimdsame_only";
		case ENC_SQRSHL_ASISDSAME_ONLY: return "SQRSHL_asisdsame_only";
		case ENC_SQRSHRN_ASIMDSHF_N: return "SQRSHRN_asimdshf_N";
		case ENC_SQRSHRN_ASISDSHF_N: return "SQRSHRN_asisdshf_N";
		case ENC_SQRSHRUN_ASIMDSHF_N: return "SQRSHRUN_asimdshf_N";
		case ENC_SQRSHRUN_ASISDSHF_N: return "SQRSHRUN_asisdshf_N";
		case ENC_SQSHLU_ASIMDSHF_R: return "SQSHLU_asimdshf_R";
		case ENC_SQSHLU_ASISDSHF_R: return "SQSHLU_asisdshf_R";
		case ENC_SQSHL_ASIMDSAME_ONLY: return "SQSHL_asimdsame_only";
		case ENC_SQSHL_ASIMDSHF_R: return "SQSHL_asimdshf_R";
		case ENC_SQSHL_ASISDSAME_ONLY: return "SQSHL_asisdsame_only";
		case ENC_SQSHL_ASISDSHF_R: return "SQSHL_asisdshf_R";
		case ENC_SQSHRN_ASIMDSHF_N: return "SQSHRN_asimdshf_N";
		case ENC_SQSHRN_ASISDSHF_N: return "SQSHRN_asisdshf_N";
		case ENC_SQSHRUN_ASIMDSHF_N: return "SQSHRUN_asimdshf_N";
		case ENC_SQSHRUN_ASISDSHF_N: return "SQSHRUN_asisdshf_N";
		case ENC_SQSUB_ASIMDSAME_ONLY: return "SQSUB_asimdsame_only";
		case ENC_SQSUB_ASISDSAME_ONLY: return "SQSUB_asisdsame_only";
		case ENC_SQXTN_ASIMDMISC_N: return "SQXTN_asimdmisc_N";
		case ENC_SQXTN_ASISDMISC_N: return "SQXTN_asisdmisc_N";
		case ENC_SQXTUN_ASIMDMISC_N: return "SQXTUN_asimdmisc_N";
		case ENC_SQXTUN_ASISDMISC_N: return "SQXTUN_asisdmisc_N";
		case ENC_SRHADD_ASIMDSAME_ONLY: return "SRHADD_asimdsame_only";
		case ENC_SRI_ASIMDSHF_R: return "SRI_asimdshf_R";
		case ENC_SRI_ASISDSHF_R: return "SRI_asisdshf_R";
		case ENC_SRSHL_ASIMDSAME_ONLY: return "SRSHL_asimdsame_only";
		case ENC_SRSHL_ASISDSAME_ONLY: return "SRSHL_asisdsame_only";
		case ENC_SRSHR_ASIMDSHF_R: return "SRSHR_asimdshf_R";
		case ENC_SRSHR_ASISDSHF_R: return "SRSHR_asisdshf_R";
		case ENC_SRSRA_ASIMDSHF_R: return "SRSRA_asimdshf_R";
		case ENC_SRSRA_ASISDSHF_R: return "SRSRA_asisdshf_R";
		case ENC_SSBB_ONLY_BARRIERS: return "SSBB_only_barriers";
		case ENC_SSHLL_ASIMDSHF_L: return "SSHLL_asimdshf_L";
		case ENC_SSHL_ASIMDSAME_ONLY: return "SSHL_asimdsame_only";
		case ENC_SSHL_ASISDSAME_ONLY: return "SSHL_asisdsame_only";
		case ENC_SSHR_ASIMDSHF_R: return "SSHR_asimdshf_R";
		case ENC_SSHR_ASISDSHF_R: return "SSHR_asisdshf_R";
		case ENC_SSRA_ASIMDSHF_R: return "SSRA_asimdshf_R";
		case ENC_SSRA_ASISDSHF_R: return "SSRA_asisdshf_R";
		case ENC_SSUBL_ASIMDDIFF_L: return "SSUBL_asimddiff_L";
		case ENC_SSUBW_ASIMDDIFF_W: return "SSUBW_asimddiff_W";
		case ENC_ST1_ASISDLSE_R1_1V: return "ST1_asisdlse_R1_1v";
		case ENC_ST1_ASISDLSE_R2_2V: return "ST1_asisdlse_R2_2v";
		case ENC_ST1_ASISDLSE_R3_3V: return "ST1_asisdlse_R3_3v";
		case ENC_ST1_ASISDLSE_R4_4V: return "ST1_asisdlse_R4_4v";
		case ENC_ST1_ASISDLSEP_I1_I1: return "ST1_asisdlsep_I1_i1";
		case ENC_ST1_ASISDLSEP_I2_I2: return "ST1_asisdlsep_I2_i2";
		case ENC_ST1_ASISDLSEP_I3_I3: return "ST1_asisdlsep_I3_i3";
		case ENC_ST1_ASISDLSEP_I4_I4: return "ST1_asisdlsep_I4_i4";
		case ENC_ST1_ASISDLSEP_R1_R1: return "ST1_asisdlsep_R1_r1";
		case ENC_ST1_ASISDLSEP_R2_R2: return "ST1_asisdlsep_R2_r2";
		case ENC_ST1_ASISDLSEP_R3_R3: return "ST1_asisdlsep_R3_r3";
		case ENC_ST1_ASISDLSEP_R4_R4: return "ST1_asisdlsep_R4_r4";
		case ENC_ST1_ASISDLSO_B1_1B: return "ST1_asisdlso_B1_1b";
		case ENC_ST1_ASISDLSO_D1_1D: return "ST1_asisdlso_D1_1d";
		case ENC_ST1_ASISDLSO_H1_1H: return "ST1_asisdlso_H1_1h";
		case ENC_ST1_ASISDLSO_S1_1S: return "ST1_asisdlso_S1_1s";
		case ENC_ST1_ASISDLSOP_B1_I1B: return "ST1_asisdlsop_B1_i1b";
		case ENC_ST1_ASISDLSOP_BX1_R1B: return "ST1_asisdlsop_BX1_r1b";
		case ENC_ST1_ASISDLSOP_D1_I1D: return "ST1_asisdlsop_D1_i1d";
		case ENC_ST1_ASISDLSOP_DX1_R1D: return "ST1_asisdlsop_DX1_r1d";
		case ENC_ST1_ASISDLSOP_H1_I1H: return "ST1_asisdlsop_H1_i1h";
		case ENC_ST1_ASISDLSOP_HX1_R1H: return "ST1_asisdlsop_HX1_r1h";
		case ENC_ST1_ASISDLSOP_S1_I1S: return "ST1_asisdlsop_S1_i1s";
		case ENC_ST1_ASISDLSOP_SX1_R1S: return "ST1_asisdlsop_SX1_r1s";
		case ENC_ST2G_64SOFFSET_LDSTTAGS: return "ST2G_64Soffset_ldsttags";
		case ENC_ST2G_64SPOST_LDSTTAGS: return "ST2G_64Spost_ldsttags";
		case ENC_ST2G_64SPRE_LDSTTAGS: return "ST2G_64Spre_ldsttags";
		case ENC_ST2_ASISDLSE_R2: return "ST2_asisdlse_R2";
		case ENC_ST2_ASISDLSEP_I2_I: return "ST2_asisdlsep_I2_i";
		case ENC_ST2_ASISDLSEP_R2_R: return "ST2_asisdlsep_R2_r";
		case ENC_ST2_ASISDLSO_B2_2B: return "ST2_asisdlso_B2_2b";
		case ENC_ST2_ASISDLSO_D2_2D: return "ST2_asisdlso_D2_2d";
		case ENC_ST2_ASISDLSO_H2_2H: return "ST2_asisdlso_H2_2h";
		case ENC_ST2_ASISDLSO_S2_2S: return "ST2_asisdlso_S2_2s";
		case ENC_ST2_ASISDLSOP_B2_I2B: return "ST2_asisdlsop_B2_i2b";
		case ENC_ST2_ASISDLSOP_BX2_R2B: return "ST2_asisdlsop_BX2_r2b";
		case ENC_ST2_ASISDLSOP_D2_I2D: return "ST2_asisdlsop_D2_i2d";
		case ENC_ST2_ASISDLSOP_DX2_R2D: return "ST2_asisdlsop_DX2_r2d";
		case ENC_ST2_ASISDLSOP_H2_I2H: return "ST2_asisdlsop_H2_i2h";
		case ENC_ST2_ASISDLSOP_HX2_R2H: return "ST2_asisdlsop_HX2_r2h";
		case ENC_ST2_ASISDLSOP_S2_I2S: return "ST2_asisdlsop_S2_i2s";
		case ENC_ST2_ASISDLSOP_SX2_R2S: return "ST2_asisdlsop_SX2_r2s";
		case ENC_ST3_ASISDLSE_R3: return "ST3_asisdlse_R3";
		case ENC_ST3_ASISDLSEP_I3_I: return "ST3_asisdlsep_I3_i";
		case ENC_ST3_ASISDLSEP_R3_R: return "ST3_asisdlsep_R3_r";
		case ENC_ST3_ASISDLSO_B3_3B: return "ST3_asisdlso_B3_3b";
		case ENC_ST3_ASISDLSO_D3_3D: return "ST3_asisdlso_D3_3d";
		case ENC_ST3_ASISDLSO_H3_3H: return "ST3_asisdlso_H3_3h";
		case ENC_ST3_ASISDLSO_S3_3S: return "ST3_asisdlso_S3_3s";
		case ENC_ST3_ASISDLSOP_B3_I3B: return "ST3_asisdlsop_B3_i3b";
		case ENC_ST3_ASISDLSOP_BX3_R3B: return "ST3_asisdlsop_BX3_r3b";
		case ENC_ST3_ASISDLSOP_D3_I3D: return "ST3_asisdlsop_D3_i3d";
		case ENC_ST3_ASISDLSOP_DX3_R3D: return "ST3_asisdlsop_DX3_r3d";
		case ENC_ST3_ASISDLSOP_H3_I3H: return "ST3_asisdlsop_H3_i3h";
		case ENC_ST3_ASISDLSOP_HX3_R3H: return "ST3_asisdlsop_HX3_r3h";
		case ENC_ST3_ASISDLSOP_S3_I3S: return "ST3_asisdlsop_S3_i3s";
		case ENC_ST3_ASISDLSOP_SX3_R3S: return "ST3_asisdlsop_SX3_r3s";
		case ENC_ST4_ASISDLSE_R4: return "ST4_asisdlse_R4";
		case ENC_ST4_ASISDLSEP_I4_I: return "ST4_asisdlsep_I4_i";
		case ENC_ST4_ASISDLSEP_R4_R: return "ST4_asisdlsep_R4_r";
		case ENC_ST4_ASISDLSO_B4_4B: return "ST4_asisdlso_B4_4b";
		case ENC_ST4_ASISDLSO_D4_4D: return "ST4_asisdlso_D4_4d";
		case ENC_ST4_ASISDLSO_H4_4H: return "ST4_asisdlso_H4_4h";
		case ENC_ST4_ASISDLSO_S4_4S: return "ST4_asisdlso_S4_4s";
		case ENC_ST4_ASISDLSOP_B4_I4B: return "ST4_asisdlsop_B4_i4b";
		case ENC_ST4_ASISDLSOP_BX4_R4B: return "ST4_asisdlsop_BX4_r4b";
		case ENC_ST4_ASISDLSOP_D4_I4D: return "ST4_asisdlsop_D4_i4d";
		case ENC_ST4_ASISDLSOP_DX4_R4D: return "ST4_asisdlsop_DX4_r4d";
		case ENC_ST4_ASISDLSOP_H4_I4H: return "ST4_asisdlsop_H4_i4h";
		case ENC_ST4_ASISDLSOP_HX4_R4H: return "ST4_asisdlsop_HX4_r4h";
		case ENC_ST4_ASISDLSOP_S4_I4S: return "ST4_asisdlsop_S4_i4s";
		case ENC_ST4_ASISDLSOP_SX4_R4S: return "ST4_asisdlsop_SX4_r4s";
		case ENC_STADDB_LDADDB_32_MEMOP: return "STADDB_LDADDB_32_memop";
		case ENC_STADDH_LDADDH_32_MEMOP: return "STADDH_LDADDH_32_memop";
		case ENC_STADDLB_LDADDLB_32_MEMOP: return "STADDLB_LDADDLB_32_memop";
		case ENC_STADDLH_LDADDLH_32_MEMOP: return "STADDLH_LDADDLH_32_memop";
		case ENC_STADDL_LDADDL_32_MEMOP: return "STADDL_LDADDL_32_memop";
		case ENC_STADDL_LDADDL_64_MEMOP: return "STADDL_LDADDL_64_memop";
		case ENC_STADD_LDADD_32_MEMOP: return "STADD_LDADD_32_memop";
		case ENC_STADD_LDADD_64_MEMOP: return "STADD_LDADD_64_memop";
		case ENC_STCLRB_LDCLRB_32_MEMOP: return "STCLRB_LDCLRB_32_memop";
		case ENC_STCLRH_LDCLRH_32_MEMOP: return "STCLRH_LDCLRH_32_memop";
		case ENC_STCLRLB_LDCLRLB_32_MEMOP: return "STCLRLB_LDCLRLB_32_memop";
		case ENC_STCLRLH_LDCLRLH_32_MEMOP: return "STCLRLH_LDCLRLH_32_memop";
		case ENC_STCLRL_LDCLRL_32_MEMOP: return "STCLRL_LDCLRL_32_memop";
		case ENC_STCLRL_LDCLRL_64_MEMOP: return "STCLRL_LDCLRL_64_memop";
		case ENC_STCLR_LDCLR_32_MEMOP: return "STCLR_LDCLR_32_memop";
		case ENC_STCLR_LDCLR_64_MEMOP: return "STCLR_LDCLR_64_memop";
		case ENC_STEORB_LDEORB_32_MEMOP: return "STEORB_LDEORB_32_memop";
		case ENC_STEORH_LDEORH_32_MEMOP: return "STEORH_LDEORH_32_memop";
		case ENC_STEORLB_LDEORLB_32_MEMOP: return "STEORLB_LDEORLB_32_memop";
		case ENC_STEORLH_LDEORLH_32_MEMOP: return "STEORLH_LDEORLH_32_memop";
		case ENC_STEORL_LDEORL_32_MEMOP: return "STEORL_LDEORL_32_memop";
		case ENC_STEORL_LDEORL_64_MEMOP: return "STEORL_LDEORL_64_memop";
		case ENC_STEOR_LDEOR_32_MEMOP: return "STEOR_LDEOR_32_memop";
		case ENC_STEOR_LDEOR_64_MEMOP: return "STEOR_LDEOR_64_memop";
		case ENC_STGM_64BULK_LDSTTAGS: return "STGM_64bulk_ldsttags";
		case ENC_STGP_64_LDSTPAIR_OFF: return "STGP_64_ldstpair_off";
		case ENC_STGP_64_LDSTPAIR_POST: return "STGP_64_ldstpair_post";
		case ENC_STGP_64_LDSTPAIR_PRE: return "STGP_64_ldstpair_pre";
		case ENC_STG_64SOFFSET_LDSTTAGS: return "STG_64Soffset_ldsttags";
		case ENC_STG_64SPOST_LDSTTAGS: return "STG_64Spost_ldsttags";
		case ENC_STG_64SPRE_LDSTTAGS: return "STG_64Spre_ldsttags";
		case ENC_STLLRB_SL32_LDSTEXCL: return "STLLRB_SL32_ldstexcl";
		case ENC_STLLRH_SL32_LDSTEXCL: return "STLLRH_SL32_ldstexcl";
		case ENC_STLLR_SL32_LDSTEXCL: return "STLLR_SL32_ldstexcl";
		case ENC_STLLR_SL64_LDSTEXCL: return "STLLR_SL64_ldstexcl";
		case ENC_STLRB_SL32_LDSTEXCL: return "STLRB_SL32_ldstexcl";
		case ENC_STLRH_SL32_LDSTEXCL: return "STLRH_SL32_ldstexcl";
		case ENC_STLR_SL32_LDSTEXCL: return "STLR_SL32_ldstexcl";
		case ENC_STLR_SL64_LDSTEXCL: return "STLR_SL64_ldstexcl";
		case ENC_STLURB_32_LDAPSTL_UNSCALED: return "STLURB_32_ldapstl_unscaled";
		case ENC_STLURH_32_LDAPSTL_UNSCALED: return "STLURH_32_ldapstl_unscaled";
		case ENC_STLUR_32_LDAPSTL_UNSCALED: return "STLUR_32_ldapstl_unscaled";
		case ENC_STLUR_64_LDAPSTL_UNSCALED: return "STLUR_64_ldapstl_unscaled";
		case ENC_STLXP_SP32_LDSTEXCL: return "STLXP_SP32_ldstexcl";
		case ENC_STLXP_SP64_LDSTEXCL: return "STLXP_SP64_ldstexcl";
		case ENC_STLXRB_SR32_LDSTEXCL: return "STLXRB_SR32_ldstexcl";
		case ENC_STLXRH_SR32_LDSTEXCL: return "STLXRH_SR32_ldstexcl";
		case ENC_STLXR_SR32_LDSTEXCL: return "STLXR_SR32_ldstexcl";
		case ENC_STLXR_SR64_LDSTEXCL: return "STLXR_SR64_ldstexcl";
		case ENC_STNP_32_LDSTNAPAIR_OFFS: return "STNP_32_ldstnapair_offs";
		case ENC_STNP_64_LDSTNAPAIR_OFFS: return "STNP_64_ldstnapair_offs";
		case ENC_STNP_D_LDSTNAPAIR_OFFS: return "STNP_D_ldstnapair_offs";
		case ENC_STNP_Q_LDSTNAPAIR_OFFS: return "STNP_Q_ldstnapair_offs";
		case ENC_STNP_S_LDSTNAPAIR_OFFS: return "STNP_S_ldstnapair_offs";
		case ENC_STP_32_LDSTPAIR_OFF: return "STP_32_ldstpair_off";
		case ENC_STP_32_LDSTPAIR_POST: return "STP_32_ldstpair_post";
		case ENC_STP_32_LDSTPAIR_PRE: return "STP_32_ldstpair_pre";
		case ENC_STP_64_LDSTPAIR_OFF: return "STP_64_ldstpair_off";
		case ENC_STP_64_LDSTPAIR_POST: return "STP_64_ldstpair_post";
		case ENC_STP_64_LDSTPAIR_PRE: return "STP_64_ldstpair_pre";
		case ENC_STP_D_LDSTPAIR_OFF: return "STP_D_ldstpair_off";
		case ENC_STP_D_LDSTPAIR_POST: return "STP_D_ldstpair_post";
		case ENC_STP_D_LDSTPAIR_PRE: return "STP_D_ldstpair_pre";
		case ENC_STP_Q_LDSTPAIR_OFF: return "STP_Q_ldstpair_off";
		case ENC_STP_Q_LDSTPAIR_POST: return "STP_Q_ldstpair_post";
		case ENC_STP_Q_LDSTPAIR_PRE: return "STP_Q_ldstpair_pre";
		case ENC_STP_S_LDSTPAIR_OFF: return "STP_S_ldstpair_off";
		case ENC_STP_S_LDSTPAIR_POST: return "STP_S_ldstpair_post";
		case ENC_STP_S_LDSTPAIR_PRE: return "STP_S_ldstpair_pre";
		case ENC_STRB_32BL_LDST_REGOFF: return "STRB_32BL_ldst_regoff";
		case ENC_STRB_32B_LDST_REGOFF: return "STRB_32B_ldst_regoff";
		case ENC_STRB_32_LDST_IMMPOST: return "STRB_32_ldst_immpost";
		case ENC_STRB_32_LDST_IMMPRE: return "STRB_32_ldst_immpre";
		case ENC_STRB_32_LDST_POS: return "STRB_32_ldst_pos";
		case ENC_STRH_32_LDST_IMMPOST: return "STRH_32_ldst_immpost";
		case ENC_STRH_32_LDST_IMMPRE: return "STRH_32_ldst_immpre";
		case ENC_STRH_32_LDST_POS: return "STRH_32_ldst_pos";
		case ENC_STRH_32_LDST_REGOFF: return "STRH_32_ldst_regoff";
		case ENC_STR_32_LDST_IMMPOST: return "STR_32_ldst_immpost";
		case ENC_STR_32_LDST_IMMPRE: return "STR_32_ldst_immpre";
		case ENC_STR_32_LDST_POS: return "STR_32_ldst_pos";
		case ENC_STR_32_LDST_REGOFF: return "STR_32_ldst_regoff";
		case ENC_STR_64_LDST_IMMPOST: return "STR_64_ldst_immpost";
		case ENC_STR_64_LDST_IMMPRE: return "STR_64_ldst_immpre";
		case ENC_STR_64_LDST_POS: return "STR_64_ldst_pos";
		case ENC_STR_64_LDST_REGOFF: return "STR_64_ldst_regoff";
		case ENC_STR_BL_LDST_REGOFF: return "STR_BL_ldst_regoff";
		case ENC_STR_B_LDST_IMMPOST: return "STR_B_ldst_immpost";
		case ENC_STR_B_LDST_IMMPRE: return "STR_B_ldst_immpre";
		case ENC_STR_B_LDST_POS: return "STR_B_ldst_pos";
		case ENC_STR_B_LDST_REGOFF: return "STR_B_ldst_regoff";
		case ENC_STR_D_LDST_IMMPOST: return "STR_D_ldst_immpost";
		case ENC_STR_D_LDST_IMMPRE: return "STR_D_ldst_immpre";
		case ENC_STR_D_LDST_POS: return "STR_D_ldst_pos";
		case ENC_STR_D_LDST_REGOFF: return "STR_D_ldst_regoff";
		case ENC_STR_H_LDST_IMMPOST: return "STR_H_ldst_immpost";
		case ENC_STR_H_LDST_IMMPRE: return "STR_H_ldst_immpre";
		case ENC_STR_H_LDST_POS: return "STR_H_ldst_pos";
		case ENC_STR_H_LDST_REGOFF: return "STR_H_ldst_regoff";
		case ENC_STR_Q_LDST_IMMPOST: return "STR_Q_ldst_immpost";
		case ENC_STR_Q_LDST_IMMPRE: return "STR_Q_ldst_immpre";
		case ENC_STR_Q_LDST_POS: return "STR_Q_ldst_pos";
		case ENC_STR_Q_LDST_REGOFF: return "STR_Q_ldst_regoff";
		case ENC_STR_S_LDST_IMMPOST: return "STR_S_ldst_immpost";
		case ENC_STR_S_LDST_IMMPRE: return "STR_S_ldst_immpre";
		case ENC_STR_S_LDST_POS: return "STR_S_ldst_pos";
		case ENC_STR_S_LDST_REGOFF: return "STR_S_ldst_regoff";
		case ENC_STSETB_LDSETB_32_MEMOP: return "STSETB_LDSETB_32_memop";
		case ENC_STSETH_LDSETH_32_MEMOP: return "STSETH_LDSETH_32_memop";
		case ENC_STSETLB_LDSETLB_32_MEMOP: return "STSETLB_LDSETLB_32_memop";
		case ENC_STSETLH_LDSETLH_32_MEMOP: return "STSETLH_LDSETLH_32_memop";
		case ENC_STSETL_LDSETL_32_MEMOP: return "STSETL_LDSETL_32_memop";
		case ENC_STSETL_LDSETL_64_MEMOP: return "STSETL_LDSETL_64_memop";
		case ENC_STSET_LDSET_32_MEMOP: return "STSET_LDSET_32_memop";
		case ENC_STSET_LDSET_64_MEMOP: return "STSET_LDSET_64_memop";
		case ENC_STSMAXB_LDSMAXB_32_MEMOP: return "STSMAXB_LDSMAXB_32_memop";
		case ENC_STSMAXH_LDSMAXH_32_MEMOP: return "STSMAXH_LDSMAXH_32_memop";
		case ENC_STSMAXLB_LDSMAXLB_32_MEMOP: return "STSMAXLB_LDSMAXLB_32_memop";
		case ENC_STSMAXLH_LDSMAXLH_32_MEMOP: return "STSMAXLH_LDSMAXLH_32_memop";
		case ENC_STSMAXL_LDSMAXL_32_MEMOP: return "STSMAXL_LDSMAXL_32_memop";
		case ENC_STSMAXL_LDSMAXL_64_MEMOP: return "STSMAXL_LDSMAXL_64_memop";
		case ENC_STSMAX_LDSMAX_32_MEMOP: return "STSMAX_LDSMAX_32_memop";
		case ENC_STSMAX_LDSMAX_64_MEMOP: return "STSMAX_LDSMAX_64_memop";
		case ENC_STSMINB_LDSMINB_32_MEMOP: return "STSMINB_LDSMINB_32_memop";
		case ENC_STSMINH_LDSMINH_32_MEMOP: return "STSMINH_LDSMINH_32_memop";
		case ENC_STSMINLB_LDSMINLB_32_MEMOP: return "STSMINLB_LDSMINLB_32_memop";
		case ENC_STSMINLH_LDSMINLH_32_MEMOP: return "STSMINLH_LDSMINLH_32_memop";
		case ENC_STSMINL_LDSMINL_32_MEMOP: return "STSMINL_LDSMINL_32_memop";
		case ENC_STSMINL_LDSMINL_64_MEMOP: return "STSMINL_LDSMINL_64_memop";
		case ENC_STSMIN_LDSMIN_32_MEMOP: return "STSMIN_LDSMIN_32_memop";
		case ENC_STSMIN_LDSMIN_64_MEMOP: return "STSMIN_LDSMIN_64_memop";
		case ENC_STTRB_32_LDST_UNPRIV: return "STTRB_32_ldst_unpriv";
		case ENC_STTRH_32_LDST_UNPRIV: return "STTRH_32_ldst_unpriv";
		case ENC_STTR_32_LDST_UNPRIV: return "STTR_32_ldst_unpriv";
		case ENC_STTR_64_LDST_UNPRIV: return "STTR_64_ldst_unpriv";
		case ENC_STUMAXB_LDUMAXB_32_MEMOP: return "STUMAXB_LDUMAXB_32_memop";
		case ENC_STUMAXH_LDUMAXH_32_MEMOP: return "STUMAXH_LDUMAXH_32_memop";
		case ENC_STUMAXLB_LDUMAXLB_32_MEMOP: return "STUMAXLB_LDUMAXLB_32_memop";
		case ENC_STUMAXLH_LDUMAXLH_32_MEMOP: return "STUMAXLH_LDUMAXLH_32_memop";
		case ENC_STUMAXL_LDUMAXL_32_MEMOP: return "STUMAXL_LDUMAXL_32_memop";
		case ENC_STUMAXL_LDUMAXL_64_MEMOP: return "STUMAXL_LDUMAXL_64_memop";
		case ENC_STUMAX_LDUMAX_32_MEMOP: return "STUMAX_LDUMAX_32_memop";
		case ENC_STUMAX_LDUMAX_64_MEMOP: return "STUMAX_LDUMAX_64_memop";
		case ENC_STUMINB_LDUMINB_32_MEMOP: return "STUMINB_LDUMINB_32_memop";
		case ENC_STUMINH_LDUMINH_32_MEMOP: return "STUMINH_LDUMINH_32_memop";
		case ENC_STUMINLB_LDUMINLB_32_MEMOP: return "STUMINLB_LDUMINLB_32_memop";
		case ENC_STUMINLH_LDUMINLH_32_MEMOP: return "STUMINLH_LDUMINLH_32_memop";
		case ENC_STUMINL_LDUMINL_32_MEMOP: return "STUMINL_LDUMINL_32_memop";
		case ENC_STUMINL_LDUMINL_64_MEMOP: return "STUMINL_LDUMINL_64_memop";
		case ENC_STUMIN_LDUMIN_32_MEMOP: return "STUMIN_LDUMIN_32_memop";
		case ENC_STUMIN_LDUMIN_64_MEMOP: return "STUMIN_LDUMIN_64_memop";
		case ENC_STURB_32_LDST_UNSCALED: return "STURB_32_ldst_unscaled";
		case ENC_STURH_32_LDST_UNSCALED: return "STURH_32_ldst_unscaled";
		case ENC_STUR_32_LDST_UNSCALED: return "STUR_32_ldst_unscaled";
		case ENC_STUR_64_LDST_UNSCALED: return "STUR_64_ldst_unscaled";
		case ENC_STUR_B_LDST_UNSCALED: return "STUR_B_ldst_unscaled";
		case ENC_STUR_D_LDST_UNSCALED: return "STUR_D_ldst_unscaled";
		case ENC_STUR_H_LDST_UNSCALED: return "STUR_H_ldst_unscaled";
		case ENC_STUR_Q_LDST_UNSCALED: return "STUR_Q_ldst_unscaled";
		case ENC_STUR_S_LDST_UNSCALED: return "STUR_S_ldst_unscaled";
		case ENC_STXP_SP32_LDSTEXCL: return "STXP_SP32_ldstexcl";
		case ENC_STXP_SP64_LDSTEXCL: return "STXP_SP64_ldstexcl";
		case ENC_STXRB_SR32_LDSTEXCL: return "STXRB_SR32_ldstexcl";
		case ENC_STXRH_SR32_LDSTEXCL: return "STXRH_SR32_ldstexcl";
		case ENC_STXR_SR32_LDSTEXCL: return "STXR_SR32_ldstexcl";
		case ENC_STXR_SR64_LDSTEXCL: return "STXR_SR64_ldstexcl";
		case ENC_STZ2G_64SOFFSET_LDSTTAGS: return "STZ2G_64Soffset_ldsttags";
		case ENC_STZ2G_64SPOST_LDSTTAGS: return "STZ2G_64Spost_ldsttags";
		case ENC_STZ2G_64SPRE_LDSTTAGS: return "STZ2G_64Spre_ldsttags";
		case ENC_STZGM_64BULK_LDSTTAGS: return "STZGM_64bulk_ldsttags";
		case ENC_STZG_64SOFFSET_LDSTTAGS: return "STZG_64Soffset_ldsttags";
		case ENC_STZG_64SPOST_LDSTTAGS: return "STZG_64Spost_ldsttags";
		case ENC_STZG_64SPRE_LDSTTAGS: return "STZG_64Spre_ldsttags";
		case ENC_SUBG_64_ADDSUB_IMMTAGS: return "SUBG_64_addsub_immtags";
		case ENC_SUBHN_ASIMDDIFF_N: return "SUBHN_asimddiff_N";
		case ENC_SUBPS_64S_DP_2SRC: return "SUBPS_64S_dp_2src";
		case ENC_SUBP_64S_DP_2SRC: return "SUBP_64S_dp_2src";
		case ENC_SUBS_32S_ADDSUB_EXT: return "SUBS_32S_addsub_ext";
		case ENC_SUBS_32S_ADDSUB_IMM: return "SUBS_32S_addsub_imm";
		case ENC_SUBS_32_ADDSUB_SHIFT: return "SUBS_32_addsub_shift";
		case ENC_SUBS_64S_ADDSUB_EXT: return "SUBS_64S_addsub_ext";
		case ENC_SUBS_64S_ADDSUB_IMM: return "SUBS_64S_addsub_imm";
		case ENC_SUBS_64_ADDSUB_SHIFT: return "SUBS_64_addsub_shift";
		case ENC_SUB_32_ADDSUB_EXT: return "SUB_32_addsub_ext";
		case ENC_SUB_32_ADDSUB_IMM: return "SUB_32_addsub_imm";
		case ENC_SUB_32_ADDSUB_SHIFT: return "SUB_32_addsub_shift";
		case ENC_SUB_64_ADDSUB_EXT: return "SUB_64_addsub_ext";
		case ENC_SUB_64_ADDSUB_IMM: return "SUB_64_addsub_imm";
		case ENC_SUB_64_ADDSUB_SHIFT: return "SUB_64_addsub_shift";
		case ENC_SUB_ASIMDSAME_ONLY: return "SUB_asimdsame_only";
		case ENC_SUB_ASISDSAME_ONLY: return "SUB_asisdsame_only";
		case ENC_SUDOT_ASIMDELEM_D: return "SUDOT_asimdelem_D";
		case ENC_SUQADD_ASIMDMISC_R: return "SUQADD_asimdmisc_R";
		case ENC_SUQADD_ASISDMISC_R: return "SUQADD_asisdmisc_R";
		case ENC_SVC_EX_EXCEPTION: return "SVC_EX_exception";
		case ENC_SWPAB_32_MEMOP: return "SWPAB_32_memop";
		case ENC_SWPAH_32_MEMOP: return "SWPAH_32_memop";
		case ENC_SWPALB_32_MEMOP: return "SWPALB_32_memop";
		case ENC_SWPALH_32_MEMOP: return "SWPALH_32_memop";
		case ENC_SWPAL_32_MEMOP: return "SWPAL_32_memop";
		case ENC_SWPAL_64_MEMOP: return "SWPAL_64_memop";
		case ENC_SWPA_32_MEMOP: return "SWPA_32_memop";
		case ENC_SWPA_64_MEMOP: return "SWPA_64_memop";
		case ENC_SWPB_32_MEMOP: return "SWPB_32_memop";
		case ENC_SWPH_32_MEMOP: return "SWPH_32_memop";
		case ENC_SWPLB_32_MEMOP: return "SWPLB_32_memop";
		case ENC_SWPLH_32_MEMOP: return "SWPLH_32_memop";
		case ENC_SWPL_32_MEMOP: return "SWPL_32_memop";
		case ENC_SWPL_64_MEMOP: return "SWPL_64_memop";
		case ENC_SWP_32_MEMOP: return "SWP_32_memop";
		case ENC_SWP_64_MEMOP: return "SWP_64_memop";
		case ENC_SXTB_SBFM_32M_BITFIELD: return "SXTB_SBFM_32M_bitfield";
		case ENC_SXTB_SBFM_64M_BITFIELD: return "SXTB_SBFM_64M_bitfield";
		case ENC_SXTH_SBFM_32M_BITFIELD: return "SXTH_SBFM_32M_bitfield";
		case ENC_SXTH_SBFM_64M_BITFIELD: return "SXTH_SBFM_64M_bitfield";
		case ENC_SXTL_SSHLL_ASIMDSHF_L: return "SXTL_SSHLL_asimdshf_L";
		case ENC_SXTW_SBFM_64M_BITFIELD: return "SXTW_SBFM_64M_bitfield";
		case ENC_SYSL_RC_SYSTEMINSTRS: return "SYSL_RC_systeminstrs";
		case ENC_SYS_CR_SYSTEMINSTRS: return "SYS_CR_systeminstrs";
		case ENC_TBL_ASIMDTBL_L1_1: return "TBL_asimdtbl_L1_1";
		case ENC_TBL_ASIMDTBL_L2_2: return "TBL_asimdtbl_L2_2";
		case ENC_TBL_ASIMDTBL_L3_3: return "TBL_asimdtbl_L3_3";
		case ENC_TBL_ASIMDTBL_L4_4: return "TBL_asimdtbl_L4_4";
		case ENC_TBNZ_ONLY_TESTBRANCH: return "TBNZ_only_testbranch";
		case ENC_TBX_ASIMDTBL_L1_1: return "TBX_asimdtbl_L1_1";
		case ENC_TBX_ASIMDTBL_L2_2: return "TBX_asimdtbl_L2_2";
		case ENC_TBX_ASIMDTBL_L3_3: return "TBX_asimdtbl_L3_3";
		case ENC_TBX_ASIMDTBL_L4_4: return "TBX_asimdtbl_L4_4";
		case ENC_TBZ_ONLY_TESTBRANCH: return "TBZ_only_testbranch";
		case ENC_TLBI_SYS_CR_SYSTEMINSTRS: return "TLBI_SYS_CR_systeminstrs";
		case ENC_TRN1_ASIMDPERM_ONLY: return "TRN1_asimdperm_only";
		case ENC_TRN2_ASIMDPERM_ONLY: return "TRN2_asimdperm_only";
		case ENC_TSB_HC_HINTS: return "TSB_HC_hints";
		case ENC_TST_ANDS_32S_LOG_IMM: return "TST_ANDS_32S_log_imm";
		case ENC_TST_ANDS_32_LOG_SHIFT: return "TST_ANDS_32_log_shift";
		case ENC_TST_ANDS_64S_LOG_IMM: return "TST_ANDS_64S_log_imm";
		case ENC_TST_ANDS_64_LOG_SHIFT: return "TST_ANDS_64_log_shift";
		case ENC_UABAL_ASIMDDIFF_L: return "UABAL_asimddiff_L";
		case ENC_UABA_ASIMDSAME_ONLY: return "UABA_asimdsame_only";
		case ENC_UABDL_ASIMDDIFF_L: return "UABDL_asimddiff_L";
		case ENC_UABD_ASIMDSAME_ONLY: return "UABD_asimdsame_only";
		case ENC_UADALP_ASIMDMISC_P: return "UADALP_asimdmisc_P";
		case ENC_UADDLP_ASIMDMISC_P: return "UADDLP_asimdmisc_P";
		case ENC_UADDLV_ASIMDALL_ONLY: return "UADDLV_asimdall_only";
		case ENC_UADDL_ASIMDDIFF_L: return "UADDL_asimddiff_L";
		case ENC_UADDW_ASIMDDIFF_W: return "UADDW_asimddiff_W";
		case ENC_UBFIZ_UBFM_32M_BITFIELD: return "UBFIZ_UBFM_32M_bitfield";
		case ENC_UBFIZ_UBFM_64M_BITFIELD: return "UBFIZ_UBFM_64M_bitfield";
		case ENC_UBFM_32M_BITFIELD: return "UBFM_32M_bitfield";
		case ENC_UBFM_64M_BITFIELD: return "UBFM_64M_bitfield";
		case ENC_UBFX_UBFM_32M_BITFIELD: return "UBFX_UBFM_32M_bitfield";
		case ENC_UBFX_UBFM_64M_BITFIELD: return "UBFX_UBFM_64M_bitfield";
		case ENC_UCVTF_D32_FLOAT2FIX: return "UCVTF_D32_float2fix";
		case ENC_UCVTF_D32_FLOAT2INT: return "UCVTF_D32_float2int";
		case ENC_UCVTF_D64_FLOAT2FIX: return "UCVTF_D64_float2fix";
		case ENC_UCVTF_D64_FLOAT2INT: return "UCVTF_D64_float2int";
		case ENC_UCVTF_H32_FLOAT2FIX: return "UCVTF_H32_float2fix";
		case ENC_UCVTF_H32_FLOAT2INT: return "UCVTF_H32_float2int";
		case ENC_UCVTF_H64_FLOAT2FIX: return "UCVTF_H64_float2fix";
		case ENC_UCVTF_H64_FLOAT2INT: return "UCVTF_H64_float2int";
		case ENC_UCVTF_S32_FLOAT2FIX: return "UCVTF_S32_float2fix";
		case ENC_UCVTF_S32_FLOAT2INT: return "UCVTF_S32_float2int";
		case ENC_UCVTF_S64_FLOAT2FIX: return "UCVTF_S64_float2fix";
		case ENC_UCVTF_S64_FLOAT2INT: return "UCVTF_S64_float2int";
		case ENC_UCVTF_ASIMDMISC_R: return "UCVTF_asimdmisc_R";
		case ENC_UCVTF_ASIMDMISCFP16_R: return "UCVTF_asimdmiscfp16_R";
		case ENC_UCVTF_ASIMDSHF_C: return "UCVTF_asimdshf_C";
		case ENC_UCVTF_ASISDMISC_R: return "UCVTF_asisdmisc_R";
		case ENC_UCVTF_ASISDMISCFP16_R: return "UCVTF_asisdmiscfp16_R";
		case ENC_UCVTF_ASISDSHF_C: return "UCVTF_asisdshf_C";
		case ENC_UDF_ONLY_PERM_UNDEF: return "UDF_only_perm_undef";
		case ENC_UDIV_32_DP_2SRC: return "UDIV_32_dp_2src";
		case ENC_UDIV_64_DP_2SRC: return "UDIV_64_dp_2src";
		case ENC_UDOT_ASIMDELEM_D: return "UDOT_asimdelem_D";
		case ENC_UDOT_ASIMDSAME2_D: return "UDOT_asimdsame2_D";
		case ENC_UHADD_ASIMDSAME_ONLY: return "UHADD_asimdsame_only";
		case ENC_UHSUB_ASIMDSAME_ONLY: return "UHSUB_asimdsame_only";
		case ENC_UMADDL_64WA_DP_3SRC: return "UMADDL_64WA_dp_3src";
		case ENC_UMAXP_ASIMDSAME_ONLY: return "UMAXP_asimdsame_only";
		case ENC_UMAXV_ASIMDALL_ONLY: return "UMAXV_asimdall_only";
		case ENC_UMAX_ASIMDSAME_ONLY: return "UMAX_asimdsame_only";
		case ENC_UMINP_ASIMDSAME_ONLY: return "UMINP_asimdsame_only";
		case ENC_UMINV_ASIMDALL_ONLY: return "UMINV_asimdall_only";
		case ENC_UMIN_ASIMDSAME_ONLY: return "UMIN_asimdsame_only";
		case ENC_UMLAL_ASIMDDIFF_L: return "UMLAL_asimddiff_L";
		case ENC_UMLAL_ASIMDELEM_L: return "UMLAL_asimdelem_L";
		case ENC_UMLSL_ASIMDDIFF_L: return "UMLSL_asimddiff_L";
		case ENC_UMLSL_ASIMDELEM_L: return "UMLSL_asimdelem_L";
		case ENC_UMMLA_ASIMDSAME2_G: return "UMMLA_asimdsame2_G";
		case ENC_UMNEGL_UMSUBL_64WA_DP_3SRC: return "UMNEGL_UMSUBL_64WA_dp_3src";
		case ENC_UMOV_ASIMDINS_W_W: return "UMOV_asimdins_W_w";
		case ENC_UMOV_ASIMDINS_X_X: return "UMOV_asimdins_X_x";
		case ENC_UMSUBL_64WA_DP_3SRC: return "UMSUBL_64WA_dp_3src";
		case ENC_UMULH_64_DP_3SRC: return "UMULH_64_dp_3src";
		case ENC_UMULL_UMADDL_64WA_DP_3SRC: return "UMULL_UMADDL_64WA_dp_3src";
		case ENC_UMULL_ASIMDDIFF_L: return "UMULL_asimddiff_L";
		case ENC_UMULL_ASIMDELEM_L: return "UMULL_asimdelem_L";
		case ENC_UNALLOCATED_100_ASIMDSAME: return "UNALLOCATED_100_asimdsame";
		case ENC_UNALLOCATED_10_ADDSUB_EXT: return "UNALLOCATED_10_addsub_ext";
		case ENC_UNALLOCATED_10_ADDSUB_IMMTAGS: return "UNALLOCATED_10_addsub_immtags";
		case ENC_UNALLOCATED_10_ADDSUB_SHIFT: return "UNALLOCATED_10_addsub_shift";
		case ENC_UNALLOCATED_10_BARRIERS: return "UNALLOCATED_10_barriers";
		case ENC_UNALLOCATED_10_BRANCH_REG: return "UNALLOCATED_10_branch_reg";
		case ENC_UNALLOCATED_10_CONDCMP_IMM: return "UNALLOCATED_10_condcmp_imm";
		case ENC_UNALLOCATED_10_CONDCMP_REG: return "UNALLOCATED_10_condcmp_reg";
		case ENC_UNALLOCATED_10_CONDSEL: return "UNALLOCATED_10_condsel";
		case ENC_UNALLOCATED_10_DP_1SRC: return "UNALLOCATED_10_dp_1src";
		case ENC_UNALLOCATED_10_EXCEPTION: return "UNALLOCATED_10_exception";
		case ENC_UNALLOCATED_10_FLOAT2FIX: return "UNALLOCATED_10_float2fix";
		case ENC_UNALLOCATED_10_FLOAT2INT: return "UNALLOCATED_10_float2int";
		case ENC_UNALLOCATED_10_FLOATCCMP: return "UNALLOCATED_10_floatccmp";
		case ENC_UNALLOCATED_10_FLOATCMP: return "UNALLOCATED_10_floatcmp";
		case ENC_UNALLOCATED_10_FLOATDP1: return "UNALLOCATED_10_floatdp1";
		case ENC_UNALLOCATED_10_FLOATDP2: return "UNALLOCATED_10_floatdp2";
		case ENC_UNALLOCATED_10_FLOATDP3: return "UNALLOCATED_10_floatdp3";
		case ENC_UNALLOCATED_10_FLOATIMM: return "UNALLOCATED_10_floatimm";
		case ENC_UNALLOCATED_10_FLOATSEL: return "UNALLOCATED_10_floatsel";
		case ENC_UNALLOCATED_10_LOG_IMM: return "UNALLOCATED_10_log_imm";
		case ENC_UNALLOCATED_10_LOG_SHIFT: return "UNALLOCATED_10_log_shift";
		case ENC_UNALLOCATED_10_MOVEWIDE: return "UNALLOCATED_10_movewide";
		case ENC_UNALLOCATED_10_PSTATE: return "UNALLOCATED_10_pstate";
		case ENC_UNALLOCATED_10_RMIF: return "UNALLOCATED_10_rmif";
		case ENC_UNALLOCATED_10_SETF: return "UNALLOCATED_10_setf";
		case ENC_UNALLOCATED_11_ADDSUB_EXT: return "UNALLOCATED_11_addsub_ext";
		case ENC_UNALLOCATED_11_ADDSUB_IMMTAGS: return "UNALLOCATED_11_addsub_immtags";
		case ENC_UNALLOCATED_11_ADDSUB_SHIFT: return "UNALLOCATED_11_addsub_shift";
		case ENC_UNALLOCATED_11_ASIMDALL: return "UNALLOCATED_11_asimdall";
		case ENC_UNALLOCATED_11_ASIMDELEM: return "UNALLOCATED_11_asimdelem";
		case ENC_UNALLOCATED_11_ASIMDEXT: return "UNALLOCATED_11_asimdext";
		case ENC_UNALLOCATED_11_ASIMDINS: return "UNALLOCATED_11_asimdins";
		case ENC_UNALLOCATED_11_ASIMDMISCFP16: return "UNALLOCATED_11_asimdmiscfp16";
		case ENC_UNALLOCATED_11_ASIMDPERM: return "UNALLOCATED_11_asimdperm";
		case ENC_UNALLOCATED_11_ASIMDSAME2: return "UNALLOCATED_11_asimdsame2";
		case ENC_UNALLOCATED_11_ASIMDTBL: return "UNALLOCATED_11_asimdtbl";
		case ENC_UNALLOCATED_11_ASISDDIFF: return "UNALLOCATED_11_asisddiff";
		case ENC_UNALLOCATED_11_ASISDELEM: return "UNALLOCATED_11_asisdelem";
		case ENC_UNALLOCATED_11_ASISDLSO: return "UNALLOCATED_11_asisdlso";
		case ENC_UNALLOCATED_11_ASISDLSOP: return "UNALLOCATED_11_asisdlsop";
		case ENC_UNALLOCATED_11_ASISDMISC: return "UNALLOCATED_11_asisdmisc";
		case ENC_UNALLOCATED_11_ASISDMISCFP16: return "UNALLOCATED_11_asisdmiscfp16";
		case ENC_UNALLOCATED_11_ASISDPAIR: return "UNALLOCATED_11_asisdpair";
		case ENC_UNALLOCATED_11_ASISDSAME: return "UNALLOCATED_11_asisdsame";
		case ENC_UNALLOCATED_11_ASISDSAME2: return "UNALLOCATED_11_asisdsame2";
		case ENC_UNALLOCATED_11_ASISDSHF: return "UNALLOCATED_11_asisdshf";
		case ENC_UNALLOCATED_11_BARRIERS: return "UNALLOCATED_11_barriers";
		case ENC_UNALLOCATED_11_BITFIELD: return "UNALLOCATED_11_bitfield";
		case ENC_UNALLOCATED_11_CONDBRANCH: return "UNALLOCATED_11_condbranch";
		case ENC_UNALLOCATED_11_CONDCMP_IMM: return "UNALLOCATED_11_condcmp_imm";
		case ENC_UNALLOCATED_11_CONDCMP_REG: return "UNALLOCATED_11_condcmp_reg";
		case ENC_UNALLOCATED_11_CONDSEL: return "UNALLOCATED_11_condsel";
		case ENC_UNALLOCATED_11_CRYPTOAES: return "UNALLOCATED_11_cryptoaes";
		case ENC_UNALLOCATED_11_CRYPTOSHA2: return "UNALLOCATED_11_cryptosha2";
		case ENC_UNALLOCATED_11_CRYPTOSHA3: return "UNALLOCATED_11_cryptosha3";
		case ENC_UNALLOCATED_11_CRYPTOSHA512_2: return "UNALLOCATED_11_cryptosha512_2";
		case ENC_UNALLOCATED_11_DP_1SRC: return "UNALLOCATED_11_dp_1src";
		case ENC_UNALLOCATED_11_DP_2SRC: return "UNALLOCATED_11_dp_2src";
		case ENC_UNALLOCATED_11_EXTRACT: return "UNALLOCATED_11_extract";
		case ENC_UNALLOCATED_11_FLOAT2FIX: return "UNALLOCATED_11_float2fix";
		case ENC_UNALLOCATED_11_FLOAT2INT: return "UNALLOCATED_11_float2int";
		case ENC_UNALLOCATED_11_FLOATCCMP: return "UNALLOCATED_11_floatccmp";
		case ENC_UNALLOCATED_11_FLOATCMP: return "UNALLOCATED_11_floatcmp";
		case ENC_UNALLOCATED_11_FLOATDP1: return "UNALLOCATED_11_floatdp1";
		case ENC_UNALLOCATED_11_FLOATDP2: return "UNALLOCATED_11_floatdp2";
		case ENC_UNALLOCATED_11_FLOATDP3: return "UNALLOCATED_11_floatdp3";
		case ENC_UNALLOCATED_11_FLOATIMM: return "UNALLOCATED_11_floatimm";
		case ENC_UNALLOCATED_11_FLOATSEL: return "UNALLOCATED_11_floatsel";
		case ENC_UNALLOCATED_11_RMIF: return "UNALLOCATED_11_rmif";
		case ENC_UNALLOCATED_11_SETF: return "UNALLOCATED_11_setf";
		case ENC_UNALLOCATED_128: return "UNALLOCATED_128";
		case ENC_UNALLOCATED_129: return "UNALLOCATED_129";
		case ENC_UNALLOCATED_12_ADDSUB_EXT: return "UNALLOCATED_12_addsub_ext";
		case ENC_UNALLOCATED_12_ASIMDALL: return "UNALLOCATED_12_asimdall";
		case ENC_UNALLOCATED_12_ASIMDEXT: return "UNALLOCATED_12_asimdext";
		case ENC_UNALLOCATED_12_ASIMDINS: return "UNALLOCATED_12_asimdins";
		case ENC_UNALLOCATED_12_ASIMDMISCFP16: return "UNALLOCATED_12_asimdmiscfp16";
		case ENC_UNALLOCATED_12_ASIMDTBL: return "UNALLOCATED_12_asimdtbl";
		case ENC_UNALLOCATED_12_ASISDDIFF: return "UNALLOCATED_12_asisddiff";
		case ENC_UNALLOCATED_12_ASISDLSE: return "UNALLOCATED_12_asisdlse";
		case ENC_UNALLOCATED_12_ASISDMISC: return "UNALLOCATED_12_asisdmisc";
		case ENC_UNALLOCATED_12_ASISDMISCFP16: return "UNALLOCATED_12_asisdmiscfp16";
		case ENC_UNALLOCATED_12_ASISDONE: return "UNALLOCATED_12_asisdone";
		case ENC_UNALLOCATED_12_ASISDPAIR: return "UNALLOCATED_12_asisdpair";
		case ENC_UNALLOCATED_12_BITFIELD: return "UNALLOCATED_12_bitfield";
		case ENC_UNALLOCATED_12_BRANCH_REG: return "UNALLOCATED_12_branch_reg";
		case ENC_UNALLOCATED_12_CONDBRANCH: return "UNALLOCATED_12_condbranch";
		case ENC_UNALLOCATED_12_CONDCMP_IMM: return "UNALLOCATED_12_condcmp_imm";
		case ENC_UNALLOCATED_12_CONDCMP_REG: return "UNALLOCATED_12_condcmp_reg";
		case ENC_UNALLOCATED_12_CRYPTOAES: return "UNALLOCATED_12_cryptoaes";
		case ENC_UNALLOCATED_12_CRYPTOSHA2: return "UNALLOCATED_12_cryptosha2";
		case ENC_UNALLOCATED_12_CRYPTOSHA3: return "UNALLOCATED_12_cryptosha3";
		case ENC_UNALLOCATED_12_DP_1SRC: return "UNALLOCATED_12_dp_1src";
		case ENC_UNALLOCATED_12_EXTRACT: return "UNALLOCATED_12_extract";
		case ENC_UNALLOCATED_12_FLOAT2FIX: return "UNALLOCATED_12_float2fix";
		case ENC_UNALLOCATED_12_FLOAT2INT: return "UNALLOCATED_12_float2int";
		case ENC_UNALLOCATED_12_FLOATCCMP: return "UNALLOCATED_12_floatccmp";
		case ENC_UNALLOCATED_12_FLOATCMP: return "UNALLOCATED_12_floatcmp";
		case ENC_UNALLOCATED_12_FLOATDP1: return "UNALLOCATED_12_floatdp1";
		case ENC_UNALLOCATED_12_FLOATDP2: return "UNALLOCATED_12_floatdp2";
		case ENC_UNALLOCATED_12_FLOATDP3: return "UNALLOCATED_12_floatdp3";
		case ENC_UNALLOCATED_12_FLOATIMM: return "UNALLOCATED_12_floatimm";
		case ENC_UNALLOCATED_12_FLOATSEL: return "UNALLOCATED_12_floatsel";
		case ENC_UNALLOCATED_12_LDSTNAPAIR_OFFS: return "UNALLOCATED_12_ldstnapair_offs";
		case ENC_UNALLOCATED_130: return "UNALLOCATED_130";
		case ENC_UNALLOCATED_131: return "UNALLOCATED_131";
		case ENC_UNALLOCATED_132: return "UNALLOCATED_132";
		case ENC_UNALLOCATED_133: return "UNALLOCATED_133";
		case ENC_UNALLOCATED_134: return "UNALLOCATED_134";
		case ENC_UNALLOCATED_135: return "UNALLOCATED_135";
		case ENC_UNALLOCATED_136: return "UNALLOCATED_136";
		case ENC_UNALLOCATED_137: return "UNALLOCATED_137";
		case ENC_UNALLOCATED_138: return "UNALLOCATED_138";
		case ENC_UNALLOCATED_139: return "UNALLOCATED_139";
		case ENC_UNALLOCATED_13_ADDSUB_EXT: return "UNALLOCATED_13_addsub_ext";
		case ENC_UNALLOCATED_13_ASIMDELEM: return "UNALLOCATED_13_asimdelem";
		case ENC_UNALLOCATED_13_ASIMDMISCFP16: return "UNALLOCATED_13_asimdmiscfp16";
		case ENC_UNALLOCATED_13_ASIMDSAME2: return "UNALLOCATED_13_asimdsame2";
		case ENC_UNALLOCATED_13_ASIMDSHF: return "UNALLOCATED_13_asimdshf";
		case ENC_UNALLOCATED_13_ASISDDIFF: return "UNALLOCATED_13_asisddiff";
		case ENC_UNALLOCATED_13_ASISDELEM: return "UNALLOCATED_13_asisdelem";
		case ENC_UNALLOCATED_13_ASISDLSEP: return "UNALLOCATED_13_asisdlsep";
		case ENC_UNALLOCATED_13_ASISDMISCFP16: return "UNALLOCATED_13_asisdmiscfp16";
		case ENC_UNALLOCATED_13_ASISDONE: return "UNALLOCATED_13_asisdone";
		case ENC_UNALLOCATED_13_ASISDSAME2: return "UNALLOCATED_13_asisdsame2";
		case ENC_UNALLOCATED_13_ASISDSAMEFP16: return "UNALLOCATED_13_asisdsamefp16";
		case ENC_UNALLOCATED_13_BRANCH_REG: return "UNALLOCATED_13_branch_reg";
		case ENC_UNALLOCATED_13_CRYPTOAES: return "UNALLOCATED_13_cryptoaes";
		case ENC_UNALLOCATED_13_DP_1SRC: return "UNALLOCATED_13_dp_1src";
		case ENC_UNALLOCATED_13_EXTRACT: return "UNALLOCATED_13_extract";
		case ENC_UNALLOCATED_13_FLOAT2FIX: return "UNALLOCATED_13_float2fix";
		case ENC_UNALLOCATED_13_FLOAT2INT: return "UNALLOCATED_13_float2int";
		case ENC_UNALLOCATED_13_FLOATCMP: return "UNALLOCATED_13_floatcmp";
		case ENC_UNALLOCATED_13_FLOATDP2: return "UNALLOCATED_13_floatdp2";
		case ENC_UNALLOCATED_13_FLOATIMM: return "UNALLOCATED_13_floatimm";
		case ENC_UNALLOCATED_13_LDSTTAGS: return "UNALLOCATED_13_ldsttags";
		case ENC_UNALLOCATED_13_MOVEWIDE: return "UNALLOCATED_13_movewide";
		case ENC_UNALLOCATED_13_RMIF: return "UNALLOCATED_13_rmif";
		case ENC_UNALLOCATED_140: return "UNALLOCATED_140";
		case ENC_UNALLOCATED_141: return "UNALLOCATED_141";
		case ENC_UNALLOCATED_142: return "UNALLOCATED_142";
		case ENC_UNALLOCATED_143: return "UNALLOCATED_143";
		case ENC_UNALLOCATED_144: return "UNALLOCATED_144";
		case ENC_UNALLOCATED_145: return "UNALLOCATED_145";
		case ENC_UNALLOCATED_146: return "UNALLOCATED_146";
		case ENC_UNALLOCATED_147: return "UNALLOCATED_147";
		case ENC_UNALLOCATED_148: return "UNALLOCATED_148";
		case ENC_UNALLOCATED_149: return "UNALLOCATED_149";
		case ENC_UNALLOCATED_14_ADDSUB_IMMTAGS: return "UNALLOCATED_14_addsub_immtags";
		case ENC_UNALLOCATED_14_ASIMDMISC: return "UNALLOCATED_14_asimdmisc";
		case ENC_UNALLOCATED_14_ASISDELEM: return "UNALLOCATED_14_asisdelem";
		case ENC_UNALLOCATED_14_ASISDLSE: return "UNALLOCATED_14_asisdlse";
		case ENC_UNALLOCATED_14_ASISDLSO: return "UNALLOCATED_14_asisdlso";
		case ENC_UNALLOCATED_14_ASISDLSOP: return "UNALLOCATED_14_asisdlsop";
		case ENC_UNALLOCATED_14_ASISDONE: return "UNALLOCATED_14_asisdone";
		case ENC_UNALLOCATED_14_ASISDPAIR: return "UNALLOCATED_14_asisdpair";
		case ENC_UNALLOCATED_14_ASISDSAME: return "UNALLOCATED_14_asisdsame";
		case ENC_UNALLOCATED_14_ASISDSAMEFP16: return "UNALLOCATED_14_asisdsamefp16";
		case ENC_UNALLOCATED_14_ASISDSHF: return "UNALLOCATED_14_asisdshf";
		case ENC_UNALLOCATED_14_CRYPTO4: return "UNALLOCATED_14_crypto4";
		case ENC_UNALLOCATED_14_DP_1SRC: return "UNALLOCATED_14_dp_1src";
		case ENC_UNALLOCATED_14_DP_2SRC: return "UNALLOCATED_14_dp_2src";
		case ENC_UNALLOCATED_14_DP_3SRC: return "UNALLOCATED_14_dp_3src";
		case ENC_UNALLOCATED_14_FLOAT2FIX: return "UNALLOCATED_14_float2fix";
		case ENC_UNALLOCATED_14_FLOAT2INT: return "UNALLOCATED_14_float2int";
		case ENC_UNALLOCATED_14_FLOATCMP: return "UNALLOCATED_14_floatcmp";
		case ENC_UNALLOCATED_14_FLOATDP2: return "UNALLOCATED_14_floatdp2";
		case ENC_UNALLOCATED_14_FLOATIMM: return "UNALLOCATED_14_floatimm";
		case ENC_UNALLOCATED_14_LDST_PAC: return "UNALLOCATED_14_ldst_pac";
		case ENC_UNALLOCATED_14_RMIF: return "UNALLOCATED_14_rmif";
		case ENC_UNALLOCATED_14_SETF: return "UNALLOCATED_14_setf";
		case ENC_UNALLOCATED_150: return "UNALLOCATED_150";
		case ENC_UNALLOCATED_151: return "UNALLOCATED_151";
		case ENC_UNALLOCATED_152: return "UNALLOCATED_152";
		case ENC_UNALLOCATED_153: return "UNALLOCATED_153";
		case ENC_UNALLOCATED_154: return "UNALLOCATED_154";
		case ENC_UNALLOCATED_154_MEMOP: return "UNALLOCATED_154_memop";
		case ENC_UNALLOCATED_155: return "UNALLOCATED_155";
		case ENC_UNALLOCATED_155_MEMOP: return "UNALLOCATED_155_memop";
		case ENC_UNALLOCATED_156: return "UNALLOCATED_156";
		case ENC_UNALLOCATED_156_MEMOP: return "UNALLOCATED_156_memop";
		case ENC_UNALLOCATED_157: return "UNALLOCATED_157";
		case ENC_UNALLOCATED_158: return "UNALLOCATED_158";
		case ENC_UNALLOCATED_158_MEMOP: return "UNALLOCATED_158_memop";
		case ENC_UNALLOCATED_159: return "UNALLOCATED_159";
		case ENC_UNALLOCATED_159_MEMOP: return "UNALLOCATED_159_memop";
		case ENC_UNALLOCATED_15_ASIMDALL: return "UNALLOCATED_15_asimdall";
		case ENC_UNALLOCATED_15_ASIMDINS: return "UNALLOCATED_15_asimdins";
		case ENC_UNALLOCATED_15_ASIMDPERM: return "UNALLOCATED_15_asimdperm";
		case ENC_UNALLOCATED_15_ASISDDIFF: return "UNALLOCATED_15_asisddiff";
		case ENC_UNALLOCATED_15_ASISDMISC: return "UNALLOCATED_15_asisdmisc";
		case ENC_UNALLOCATED_15_ASISDONE: return "UNALLOCATED_15_asisdone";
		case ENC_UNALLOCATED_15_ASISDSAME: return "UNALLOCATED_15_asisdsame";
		case ENC_UNALLOCATED_15_ASISDSAME2: return "UNALLOCATED_15_asisdsame2";
		case ENC_UNALLOCATED_15_BARRIERS: return "UNALLOCATED_15_barriers";
		case ENC_UNALLOCATED_15_BRANCH_REG: return "UNALLOCATED_15_branch_reg";
		case ENC_UNALLOCATED_15_DP_1SRC: return "UNALLOCATED_15_dp_1src";
		case ENC_UNALLOCATED_15_DP_2SRC: return "UNALLOCATED_15_dp_2src";
		case ENC_UNALLOCATED_15_EXCEPTION: return "UNALLOCATED_15_exception";
		case ENC_UNALLOCATED_15_FLOAT2FIX: return "UNALLOCATED_15_float2fix";
		case ENC_UNALLOCATED_15_FLOATCMP: return "UNALLOCATED_15_floatcmp";
		case ENC_UNALLOCATED_15_FLOATDP2: return "UNALLOCATED_15_floatdp2";
		case ENC_UNALLOCATED_15_FLOATIMM: return "UNALLOCATED_15_floatimm";
		case ENC_UNALLOCATED_15_LDST_PAC: return "UNALLOCATED_15_ldst_pac";
		case ENC_UNALLOCATED_15_LDSTTAGS: return "UNALLOCATED_15_ldsttags";
		case ENC_UNALLOCATED_15_SETF: return "UNALLOCATED_15_setf";
		case ENC_UNALLOCATED_160: return "UNALLOCATED_160";
		case ENC_UNALLOCATED_160_MEMOP: return "UNALLOCATED_160_memop";
		case ENC_UNALLOCATED_161: return "UNALLOCATED_161";
		case ENC_UNALLOCATED_161_MEMOP: return "UNALLOCATED_161_memop";
		case ENC_UNALLOCATED_162: return "UNALLOCATED_162";
		case ENC_UNALLOCATED_162_MEMOP: return "UNALLOCATED_162_memop";
		case ENC_UNALLOCATED_163: return "UNALLOCATED_163";
		case ENC_UNALLOCATED_163_MEMOP: return "UNALLOCATED_163_memop";
		case ENC_UNALLOCATED_164: return "UNALLOCATED_164";
		case ENC_UNALLOCATED_165: return "UNALLOCATED_165";
		case ENC_UNALLOCATED_165_MEMOP: return "UNALLOCATED_165_memop";
		case ENC_UNALLOCATED_166: return "UNALLOCATED_166";
		case ENC_UNALLOCATED_166_MEMOP: return "UNALLOCATED_166_memop";
		case ENC_UNALLOCATED_167: return "UNALLOCATED_167";
		case ENC_UNALLOCATED_167_MEMOP: return "UNALLOCATED_167_memop";
		case ENC_UNALLOCATED_168: return "UNALLOCATED_168";
		case ENC_UNALLOCATED_168_MEMOP: return "UNALLOCATED_168_memop";
		case ENC_UNALLOCATED_169: return "UNALLOCATED_169";
		case ENC_UNALLOCATED_169_MEMOP: return "UNALLOCATED_169_memop";
		case ENC_UNALLOCATED_16_ASIMDALL: return "UNALLOCATED_16_asimdall";
		case ENC_UNALLOCATED_16_ASIMDELEM: return "UNALLOCATED_16_asimdelem";
		case ENC_UNALLOCATED_16_ASIMDSAMEFP16: return "UNALLOCATED_16_asimdsamefp16";
		case ENC_UNALLOCATED_16_ASIMDSHF: return "UNALLOCATED_16_asimdshf";
		case ENC_UNALLOCATED_16_ASISDDIFF: return "UNALLOCATED_16_asisddiff";
		case ENC_UNALLOCATED_16_ASISDELEM: return "UNALLOCATED_16_asisdelem";
		case ENC_UNALLOCATED_16_ASISDLSE: return "UNALLOCATED_16_asisdlse";
		case ENC_UNALLOCATED_16_ASISDLSEP: return "UNALLOCATED_16_asisdlsep";
		case ENC_UNALLOCATED_16_ASISDLSO: return "UNALLOCATED_16_asisdlso";
		case ENC_UNALLOCATED_16_ASISDLSOP: return "UNALLOCATED_16_asisdlsop";
		case ENC_UNALLOCATED_16_ASISDMISC: return "UNALLOCATED_16_asisdmisc";
		case ENC_UNALLOCATED_16_ASISDONE: return "UNALLOCATED_16_asisdone";
		case ENC_UNALLOCATED_16_ASISDSAME2: return "UNALLOCATED_16_asisdsame2";
		case ENC_UNALLOCATED_16_BARRIERS: return "UNALLOCATED_16_barriers";
		case ENC_UNALLOCATED_16_CRYPTOSHA2: return "UNALLOCATED_16_cryptosha2";
		case ENC_UNALLOCATED_16_DP_1SRC: return "UNALLOCATED_16_dp_1src";
		case ENC_UNALLOCATED_16_DP_3SRC: return "UNALLOCATED_16_dp_3src";
		case ENC_UNALLOCATED_16_EXCEPTION: return "UNALLOCATED_16_exception";
		case ENC_UNALLOCATED_16_EXTRACT: return "UNALLOCATED_16_extract";
		case ENC_UNALLOCATED_16_FLOAT2FIX: return "UNALLOCATED_16_float2fix";
		case ENC_UNALLOCATED_16_FLOATCMP: return "UNALLOCATED_16_floatcmp";
		case ENC_UNALLOCATED_16_FLOATIMM: return "UNALLOCATED_16_floatimm";
		case ENC_UNALLOCATED_16_SETF: return "UNALLOCATED_16_setf";
		case ENC_UNALLOCATED_170: return "UNALLOCATED_170";
		case ENC_UNALLOCATED_170_MEMOP: return "UNALLOCATED_170_memop";
		case ENC_UNALLOCATED_171: return "UNALLOCATED_171";
		case ENC_UNALLOCATED_172: return "UNALLOCATED_172";
		case ENC_UNALLOCATED_172_MEMOP: return "UNALLOCATED_172_memop";
		case ENC_UNALLOCATED_173: return "UNALLOCATED_173";
		case ENC_UNALLOCATED_173_MEMOP: return "UNALLOCATED_173_memop";
		case ENC_UNALLOCATED_174: return "UNALLOCATED_174";
		case ENC_UNALLOCATED_174_MEMOP: return "UNALLOCATED_174_memop";
		case ENC_UNALLOCATED_175: return "UNALLOCATED_175";
		case ENC_UNALLOCATED_175_MEMOP: return "UNALLOCATED_175_memop";
		case ENC_UNALLOCATED_176: return "UNALLOCATED_176";
		case ENC_UNALLOCATED_177: return "UNALLOCATED_177";
		case ENC_UNALLOCATED_178: return "UNALLOCATED_178";
		case ENC_UNALLOCATED_179: return "UNALLOCATED_179";
		case ENC_UNALLOCATED_17_ASIMDELEM: return "UNALLOCATED_17_asimdelem";
		case ENC_UNALLOCATED_17_ASIMDINS: return "UNALLOCATED_17_asimdins";
		case ENC_UNALLOCATED_17_ASIMDSAME2: return "UNALLOCATED_17_asimdsame2";
		case ENC_UNALLOCATED_17_ASISDELEM: return "UNALLOCATED_17_asisdelem";
		case ENC_UNALLOCATED_17_ASISDPAIR: return "UNALLOCATED_17_asisdpair";
		case ENC_UNALLOCATED_17_ASISDSAME2: return "UNALLOCATED_17_asisdsame2";
		case ENC_UNALLOCATED_17_ASISDSAMEFP16: return "UNALLOCATED_17_asisdsamefp16";
		case ENC_UNALLOCATED_17_ASISDSHF: return "UNALLOCATED_17_asisdshf";
		case ENC_UNALLOCATED_17_BARRIERS: return "UNALLOCATED_17_barriers";
		case ENC_UNALLOCATED_17_BRANCH_REG: return "UNALLOCATED_17_branch_reg";
		case ENC_UNALLOCATED_17_CRYPTOSHA2: return "UNALLOCATED_17_cryptosha2";
		case ENC_UNALLOCATED_17_DP_1SRC: return "UNALLOCATED_17_dp_1src";
		case ENC_UNALLOCATED_17_EXTRACT: return "UNALLOCATED_17_extract";
		case ENC_UNALLOCATED_17_FLOAT2FIX: return "UNALLOCATED_17_float2fix";
		case ENC_UNALLOCATED_17_FLOATCMP: return "UNALLOCATED_17_floatcmp";
		case ENC_UNALLOCATED_17_FLOATDP1: return "UNALLOCATED_17_floatdp1";
		case ENC_UNALLOCATED_17_FLOATIMM: return "UNALLOCATED_17_floatimm";
		case ENC_UNALLOCATED_17_LOADLIT: return "UNALLOCATED_17_loadlit";
		case ENC_UNALLOCATED_17_SETF: return "UNALLOCATED_17_setf";
		case ENC_UNALLOCATED_180: return "UNALLOCATED_180";
		case ENC_UNALLOCATED_180_MEMOP: return "UNALLOCATED_180_memop";
		case ENC_UNALLOCATED_181: return "UNALLOCATED_181";
		case ENC_UNALLOCATED_181_MEMOP: return "UNALLOCATED_181_memop";
		case ENC_UNALLOCATED_182: return "UNALLOCATED_182";
		case ENC_UNALLOCATED_182_MEMOP: return "UNALLOCATED_182_memop";
		case ENC_UNALLOCATED_183: return "UNALLOCATED_183";
		case ENC_UNALLOCATED_183_MEMOP: return "UNALLOCATED_183_memop";
		case ENC_UNALLOCATED_184: return "UNALLOCATED_184";
		case ENC_UNALLOCATED_185: return "UNALLOCATED_185";
		case ENC_UNALLOCATED_185_MEMOP: return "UNALLOCATED_185_memop";
		case ENC_UNALLOCATED_186: return "UNALLOCATED_186";
		case ENC_UNALLOCATED_186_MEMOP: return "UNALLOCATED_186_memop";
		case ENC_UNALLOCATED_187: return "UNALLOCATED_187";
		case ENC_UNALLOCATED_187_MEMOP: return "UNALLOCATED_187_memop";
		case ENC_UNALLOCATED_188: return "UNALLOCATED_188";
		case ENC_UNALLOCATED_188_MEMOP: return "UNALLOCATED_188_memop";
		case ENC_UNALLOCATED_189: return "UNALLOCATED_189";
		case ENC_UNALLOCATED_189_MEMOP: return "UNALLOCATED_189_memop";
		case ENC_UNALLOCATED_18_ASIMDINS: return "UNALLOCATED_18_asimdins";
		case ENC_UNALLOCATED_18_ASIMDSAMEFP16: return "UNALLOCATED_18_asimdsamefp16";
		case ENC_UNALLOCATED_18_ASISDDIFF: return "UNALLOCATED_18_asisddiff";
		case ENC_UNALLOCATED_18_ASISDLSO: return "UNALLOCATED_18_asisdlso";
		case ENC_UNALLOCATED_18_ASISDLSOP: return "UNALLOCATED_18_asisdlsop";
		case ENC_UNALLOCATED_18_ASISDONE: return "UNALLOCATED_18_asisdone";
		case ENC_UNALLOCATED_18_BARRIERS: return "UNALLOCATED_18_barriers";
		case ENC_UNALLOCATED_18_BRANCH_REG: return "UNALLOCATED_18_branch_reg";
		case ENC_UNALLOCATED_18_CRYPTOAES: return "UNALLOCATED_18_cryptoaes";
		case ENC_UNALLOCATED_18_CRYPTOSHA2: return "UNALLOCATED_18_cryptosha2";
		case ENC_UNALLOCATED_18_CRYPTOSHA512_3: return "UNALLOCATED_18_cryptosha512_3";
		case ENC_UNALLOCATED_18_DP_1SRC: return "UNALLOCATED_18_dp_1src";
		case ENC_UNALLOCATED_18_DP_3SRC: return "UNALLOCATED_18_dp_3src";
		case ENC_UNALLOCATED_18_EXCEPTION: return "UNALLOCATED_18_exception";
		case ENC_UNALLOCATED_18_EXTRACT: return "UNALLOCATED_18_extract";
		case ENC_UNALLOCATED_190: return "UNALLOCATED_190";
		case ENC_UNALLOCATED_191: return "UNALLOCATED_191";
		case ENC_UNALLOCATED_192: return "UNALLOCATED_192";
		case ENC_UNALLOCATED_193: return "UNALLOCATED_193";
		case ENC_UNALLOCATED_194: return "UNALLOCATED_194";
		case ENC_UNALLOCATED_195: return "UNALLOCATED_195";
		case ENC_UNALLOCATED_196: return "UNALLOCATED_196";
		case ENC_UNALLOCATED_197: return "UNALLOCATED_197";
		case ENC_UNALLOCATED_198: return "UNALLOCATED_198";
		case ENC_UNALLOCATED_199: return "UNALLOCATED_199";
		case ENC_UNALLOCATED_19_ASIMDALL: return "UNALLOCATED_19_asimdall";
		case ENC_UNALLOCATED_19_ASIMDMISCFP16: return "UNALLOCATED_19_asimdmiscfp16";
		case ENC_UNALLOCATED_19_ASIMDSAME2: return "UNALLOCATED_19_asimdsame2";
		case ENC_UNALLOCATED_19_ASIMDSHF: return "UNALLOCATED_19_asimdshf";
		case ENC_UNALLOCATED_19_ASISDDIFF: return "UNALLOCATED_19_asisddiff";
		case ENC_UNALLOCATED_19_ASISDELEM: return "UNALLOCATED_19_asisdelem";
		case ENC_UNALLOCATED_19_ASISDLSEP: return "UNALLOCATED_19_asisdlsep";
		case ENC_UNALLOCATED_19_ASISDMISCFP16: return "UNALLOCATED_19_asisdmiscfp16";
		case ENC_UNALLOCATED_19_ASISDSAMEFP16: return "UNALLOCATED_19_asisdsamefp16";
		case ENC_UNALLOCATED_19_BITFIELD: return "UNALLOCATED_19_bitfield";
		case ENC_UNALLOCATED_19_BRANCH_REG: return "UNALLOCATED_19_branch_reg";
		case ENC_UNALLOCATED_19_CRYPTOAES: return "UNALLOCATED_19_cryptoaes";
		case ENC_UNALLOCATED_19_CRYPTOSHA2: return "UNALLOCATED_19_cryptosha2";
		case ENC_UNALLOCATED_19_DP_1SRC: return "UNALLOCATED_19_dp_1src";
		case ENC_UNALLOCATED_19_EXCEPTION: return "UNALLOCATED_19_exception";
		case ENC_UNALLOCATED_19_FLOATDP1: return "UNALLOCATED_19_floatdp1";
		case ENC_UNALLOCATED_200: return "UNALLOCATED_200";
		case ENC_UNALLOCATED_201: return "UNALLOCATED_201";
		case ENC_UNALLOCATED_202: return "UNALLOCATED_202";
		case ENC_UNALLOCATED_203: return "UNALLOCATED_203";
		case ENC_UNALLOCATED_204: return "UNALLOCATED_204";
		case ENC_UNALLOCATED_205: return "UNALLOCATED_205";
		case ENC_UNALLOCATED_206: return "UNALLOCATED_206";
		case ENC_UNALLOCATED_207: return "UNALLOCATED_207";
		case ENC_UNALLOCATED_208: return "UNALLOCATED_208";
		case ENC_UNALLOCATED_209: return "UNALLOCATED_209";
		case ENC_UNALLOCATED_20_ASIMDSAME2: return "UNALLOCATED_20_asimdsame2";
		case ENC_UNALLOCATED_20_ASISDELEM: return "UNALLOCATED_20_asisdelem";
		case ENC_UNALLOCATED_20_ASISDLSE: return "UNALLOCATED_20_asisdlse";
		case ENC_UNALLOCATED_20_ASISDMISCFP16: return "UNALLOCATED_20_asisdmiscfp16";
		case ENC_UNALLOCATED_20_ASISDPAIR: return "UNALLOCATED_20_asisdpair";
		case ENC_UNALLOCATED_20_ASISDSHF: return "UNALLOCATED_20_asisdshf";
		case ENC_UNALLOCATED_20_BRANCH_REG: return "UNALLOCATED_20_branch_reg";
		case ENC_UNALLOCATED_20_CRYPTOSHA3: return "UNALLOCATED_20_cryptosha3";
		case ENC_UNALLOCATED_20_DP_1SRC: return "UNALLOCATED_20_dp_1src";
		case ENC_UNALLOCATED_20_DP_2SRC: return "UNALLOCATED_20_dp_2src";
		case ENC_UNALLOCATED_20_DP_3SRC: return "UNALLOCATED_20_dp_3src";
		case ENC_UNALLOCATED_210: return "UNALLOCATED_210";
		case ENC_UNALLOCATED_211: return "UNALLOCATED_211";
		case ENC_UNALLOCATED_212: return "UNALLOCATED_212";
		case ENC_UNALLOCATED_213: return "UNALLOCATED_213";
		case ENC_UNALLOCATED_214: return "UNALLOCATED_214";
		case ENC_UNALLOCATED_215: return "UNALLOCATED_215";
		case ENC_UNALLOCATED_216: return "UNALLOCATED_216";
		case ENC_UNALLOCATED_217: return "UNALLOCATED_217";
		case ENC_UNALLOCATED_218: return "UNALLOCATED_218";
		case ENC_UNALLOCATED_219: return "UNALLOCATED_219";
		case ENC_UNALLOCATED_21_ASIMDALL: return "UNALLOCATED_21_asimdall";
		case ENC_UNALLOCATED_21_ASIMDINS: return "UNALLOCATED_21_asimdins";
		case ENC_UNALLOCATED_21_ASIMDSAME2: return "UNALLOCATED_21_asimdsame2";
		case ENC_UNALLOCATED_21_ASISDDIFF: return "UNALLOCATED_21_asisddiff";
		case ENC_UNALLOCATED_21_ASISDLSO: return "UNALLOCATED_21_asisdlso";
		case ENC_UNALLOCATED_21_ASISDLSOP: return "UNALLOCATED_21_asisdlsop";
		case ENC_UNALLOCATED_21_ASISDMISCFP16: return "UNALLOCATED_21_asisdmiscfp16";
		case ENC_UNALLOCATED_21_ASISDSAMEFP16: return "UNALLOCATED_21_asisdsamefp16";
		case ENC_UNALLOCATED_21_BRANCH_REG: return "UNALLOCATED_21_branch_reg";
		case ENC_UNALLOCATED_21_DP_1SRC: return "UNALLOCATED_21_dp_1src";
		case ENC_UNALLOCATED_21_DP_2SRC: return "UNALLOCATED_21_dp_2src";
		case ENC_UNALLOCATED_21_DP_3SRC: return "UNALLOCATED_21_dp_3src";
		case ENC_UNALLOCATED_21_EXCEPTION: return "UNALLOCATED_21_exception";
		case ENC_UNALLOCATED_21_LDAPSTL_UNSCALED: return "UNALLOCATED_21_ldapstl_unscaled";
		case ENC_UNALLOCATED_21_LDST_IMMPOST: return "UNALLOCATED_21_ldst_immpost";
		case ENC_UNALLOCATED_21_LDST_IMMPRE: return "UNALLOCATED_21_ldst_immpre";
		case ENC_UNALLOCATED_21_LDST_UNPRIV: return "UNALLOCATED_21_ldst_unpriv";
		case ENC_UNALLOCATED_21_LDSTNAPAIR_OFFS: return "UNALLOCATED_21_ldstnapair_offs";
		case ENC_UNALLOCATED_220: return "UNALLOCATED_220";
		case ENC_UNALLOCATED_221: return "UNALLOCATED_221";
		case ENC_UNALLOCATED_222: return "UNALLOCATED_222";
		case ENC_UNALLOCATED_223: return "UNALLOCATED_223";
		case ENC_UNALLOCATED_224: return "UNALLOCATED_224";
		case ENC_UNALLOCATED_225: return "UNALLOCATED_225";
		case ENC_UNALLOCATED_226: return "UNALLOCATED_226";
		case ENC_UNALLOCATED_227: return "UNALLOCATED_227";
		case ENC_UNALLOCATED_228: return "UNALLOCATED_228";
		case ENC_UNALLOCATED_229: return "UNALLOCATED_229";
		case ENC_UNALLOCATED_22_ASIMDMISCFP16: return "UNALLOCATED_22_asimdmiscfp16";
		case ENC_UNALLOCATED_22_ASIMDSAME2: return "UNALLOCATED_22_asimdsame2";
		case ENC_UNALLOCATED_22_ASIMDSHF: return "UNALLOCATED_22_asimdshf";
		case ENC_UNALLOCATED_22_ASISDDIFF: return "UNALLOCATED_22_asisddiff";
		case ENC_UNALLOCATED_22_ASISDELEM: return "UNALLOCATED_22_asisdelem";
		case ENC_UNALLOCATED_22_ASISDLSE: return "UNALLOCATED_22_asisdlse";
		case ENC_UNALLOCATED_22_ASISDMISCFP16: return "UNALLOCATED_22_asisdmiscfp16";
		case ENC_UNALLOCATED_22_ASISDPAIR: return "UNALLOCATED_22_asisdpair";
		case ENC_UNALLOCATED_22_DP_3SRC: return "UNALLOCATED_22_dp_3src";
		case ENC_UNALLOCATED_22_EXCEPTION: return "UNALLOCATED_22_exception";
		case ENC_UNALLOCATED_22_LDSTPAIR_OFF: return "UNALLOCATED_22_ldstpair_off";
		case ENC_UNALLOCATED_22_LDSTPAIR_POST: return "UNALLOCATED_22_ldstpair_post";
		case ENC_UNALLOCATED_22_LDSTPAIR_PRE: return "UNALLOCATED_22_ldstpair_pre";
		case ENC_UNALLOCATED_230: return "UNALLOCATED_230";
		case ENC_UNALLOCATED_231: return "UNALLOCATED_231";
		case ENC_UNALLOCATED_232: return "UNALLOCATED_232";
		case ENC_UNALLOCATED_233: return "UNALLOCATED_233";
		case ENC_UNALLOCATED_234: return "UNALLOCATED_234";
		case ENC_UNALLOCATED_235: return "UNALLOCATED_235";
		case ENC_UNALLOCATED_236: return "UNALLOCATED_236";
		case ENC_UNALLOCATED_237: return "UNALLOCATED_237";
		case ENC_UNALLOCATED_238: return "UNALLOCATED_238";
		case ENC_UNALLOCATED_239: return "UNALLOCATED_239";
		case ENC_UNALLOCATED_23_ASIMDSHF: return "UNALLOCATED_23_asimdshf";
		case ENC_UNALLOCATED_23_ASISDELEM: return "UNALLOCATED_23_asisdelem";
		case ENC_UNALLOCATED_23_ASISDLSE: return "UNALLOCATED_23_asisdlse";
		case ENC_UNALLOCATED_23_ASISDLSO: return "UNALLOCATED_23_asisdlso";
		case ENC_UNALLOCATED_23_ASISDLSOP: return "UNALLOCATED_23_asisdlsop";
		case ENC_UNALLOCATED_23_ASISDPAIR: return "UNALLOCATED_23_asisdpair";
		case ENC_UNALLOCATED_23_ASISDSAMEFP16: return "UNALLOCATED_23_asisdsamefp16";
		case ENC_UNALLOCATED_23_ASISDSHF: return "UNALLOCATED_23_asisdshf";
		case ENC_UNALLOCATED_23_BRANCH_REG: return "UNALLOCATED_23_branch_reg";
		case ENC_UNALLOCATED_23_DP_3SRC: return "UNALLOCATED_23_dp_3src";
		case ENC_UNALLOCATED_23_EXCEPTION: return "UNALLOCATED_23_exception";
		case ENC_UNALLOCATED_240: return "UNALLOCATED_240";
		case ENC_UNALLOCATED_241: return "UNALLOCATED_241";
		case ENC_UNALLOCATED_242: return "UNALLOCATED_242";
		case ENC_UNALLOCATED_243: return "UNALLOCATED_243";
		case ENC_UNALLOCATED_244: return "UNALLOCATED_244";
		case ENC_UNALLOCATED_245: return "UNALLOCATED_245";
		case ENC_UNALLOCATED_246: return "UNALLOCATED_246";
		case ENC_UNALLOCATED_247: return "UNALLOCATED_247";
		case ENC_UNALLOCATED_248: return "UNALLOCATED_248";
		case ENC_UNALLOCATED_249: return "UNALLOCATED_249";
		case ENC_UNALLOCATED_24_ASIMDALL: return "UNALLOCATED_24_asimdall";
		case ENC_UNALLOCATED_24_ASIMDINS: return "UNALLOCATED_24_asimdins";
		case ENC_UNALLOCATED_24_ASIMDMISC: return "UNALLOCATED_24_asimdmisc";
		case ENC_UNALLOCATED_24_ASISDMISC: return "UNALLOCATED_24_asisdmisc";
		case ENC_UNALLOCATED_24_ASISDSHF: return "UNALLOCATED_24_asisdshf";
		case ENC_UNALLOCATED_24_BRANCH_REG: return "UNALLOCATED_24_branch_reg";
		case ENC_UNALLOCATED_24_DP_2SRC: return "UNALLOCATED_24_dp_2src";
		case ENC_UNALLOCATED_24_EXCEPTION: return "UNALLOCATED_24_exception";
		case ENC_UNALLOCATED_24_LDAPSTL_UNSCALED: return "UNALLOCATED_24_ldapstl_unscaled";
		case ENC_UNALLOCATED_24_LDST_IMMPOST: return "UNALLOCATED_24_ldst_immpost";
		case ENC_UNALLOCATED_24_LDST_IMMPRE: return "UNALLOCATED_24_ldst_immpre";
		case ENC_UNALLOCATED_24_LDST_POS: return "UNALLOCATED_24_ldst_pos";
		case ENC_UNALLOCATED_24_LDST_UNPRIV: return "UNALLOCATED_24_ldst_unpriv";
		case ENC_UNALLOCATED_24_LDST_UNSCALED: return "UNALLOCATED_24_ldst_unscaled";
		case ENC_UNALLOCATED_250: return "UNALLOCATED_250";
		case ENC_UNALLOCATED_251: return "UNALLOCATED_251";
		case ENC_UNALLOCATED_252: return "UNALLOCATED_252";
		case ENC_UNALLOCATED_253: return "UNALLOCATED_253";
		case ENC_UNALLOCATED_254: return "UNALLOCATED_254";
		case ENC_UNALLOCATED_255: return "UNALLOCATED_255";
		case ENC_UNALLOCATED_256: return "UNALLOCATED_256";
		case ENC_UNALLOCATED_257: return "UNALLOCATED_257";
		case ENC_UNALLOCATED_258: return "UNALLOCATED_258";
		case ENC_UNALLOCATED_259: return "UNALLOCATED_259";
		case ENC_UNALLOCATED_25_ASIMDELEM: return "UNALLOCATED_25_asimdelem";
		case ENC_UNALLOCATED_25_ASIMDSAMEFP16: return "UNALLOCATED_25_asimdsamefp16";
		case ENC_UNALLOCATED_25_ASIMDSHF: return "UNALLOCATED_25_asimdshf";
		case ENC_UNALLOCATED_25_ASISDELEM: return "UNALLOCATED_25_asisdelem";
		case ENC_UNALLOCATED_25_ASISDLSE: return "UNALLOCATED_25_asisdlse";
		case ENC_UNALLOCATED_25_ASISDLSO: return "UNALLOCATED_25_asisdlso";
		case ENC_UNALLOCATED_25_ASISDLSOP: return "UNALLOCATED_25_asisdlsop";
		case ENC_UNALLOCATED_25_ASISDPAIR: return "UNALLOCATED_25_asisdpair";
		case ENC_UNALLOCATED_25_ASISDSAMEFP16: return "UNALLOCATED_25_asisdsamefp16";
		case ENC_UNALLOCATED_25_BARRIERS: return "UNALLOCATED_25_barriers";
		case ENC_UNALLOCATED_25_DP_2SRC: return "UNALLOCATED_25_dp_2src";
		case ENC_UNALLOCATED_25_DP_3SRC: return "UNALLOCATED_25_dp_3src";
		case ENC_UNALLOCATED_25_LDAPSTL_UNSCALED: return "UNALLOCATED_25_ldapstl_unscaled";
		case ENC_UNALLOCATED_25_LDST_UNPRIV: return "UNALLOCATED_25_ldst_unpriv";
		case ENC_UNALLOCATED_260: return "UNALLOCATED_260";
		case ENC_UNALLOCATED_261: return "UNALLOCATED_261";
		case ENC_UNALLOCATED_262: return "UNALLOCATED_262";
		case ENC_UNALLOCATED_263: return "UNALLOCATED_263";
		case ENC_UNALLOCATED_264: return "UNALLOCATED_264";
		case ENC_UNALLOCATED_265: return "UNALLOCATED_265";
		case ENC_UNALLOCATED_266: return "UNALLOCATED_266";
		case ENC_UNALLOCATED_267: return "UNALLOCATED_267";
		case ENC_UNALLOCATED_268: return "UNALLOCATED_268";
		case ENC_UNALLOCATED_269: return "UNALLOCATED_269";
		case ENC_UNALLOCATED_26_ASIMDALL: return "UNALLOCATED_26_asimdall";
		case ENC_UNALLOCATED_26_ASIMDELEM: return "UNALLOCATED_26_asimdelem";
		case ENC_UNALLOCATED_26_ASIMDIMM: return "UNALLOCATED_26_asimdimm";
		case ENC_UNALLOCATED_26_ASIMDMISCFP16: return "UNALLOCATED_26_asimdmiscfp16";
		case ENC_UNALLOCATED_26_ASIMDSAME2: return "UNALLOCATED_26_asimdsame2";
		case ENC_UNALLOCATED_26_ASIMDSAMEFP16: return "UNALLOCATED_26_asimdsamefp16";
		case ENC_UNALLOCATED_26_ASISDELEM: return "UNALLOCATED_26_asisdelem";
		case ENC_UNALLOCATED_26_ASISDLSEP: return "UNALLOCATED_26_asisdlsep";
		case ENC_UNALLOCATED_26_ASISDLSO: return "UNALLOCATED_26_asisdlso";
		case ENC_UNALLOCATED_26_ASISDLSOP: return "UNALLOCATED_26_asisdlsop";
		case ENC_UNALLOCATED_26_ASISDSHF: return "UNALLOCATED_26_asisdshf";
		case ENC_UNALLOCATED_26_BRANCH_REG: return "UNALLOCATED_26_branch_reg";
		case ENC_UNALLOCATED_26_FLOATDP1: return "UNALLOCATED_26_floatdp1";
		case ENC_UNALLOCATED_26_LDSTEXCL: return "UNALLOCATED_26_ldstexcl";
		case ENC_UNALLOCATED_270: return "UNALLOCATED_270";
		case ENC_UNALLOCATED_271: return "UNALLOCATED_271";
		case ENC_UNALLOCATED_272: return "UNALLOCATED_272";
		case ENC_UNALLOCATED_273: return "UNALLOCATED_273";
		case ENC_UNALLOCATED_274: return "UNALLOCATED_274";
		case ENC_UNALLOCATED_275: return "UNALLOCATED_275";
		case ENC_UNALLOCATED_276: return "UNALLOCATED_276";
		case ENC_UNALLOCATED_277: return "UNALLOCATED_277";
		case ENC_UNALLOCATED_278: return "UNALLOCATED_278";
		case ENC_UNALLOCATED_279: return "UNALLOCATED_279";
		case ENC_UNALLOCATED_27_ASIMDALL: return "UNALLOCATED_27_asimdall";
		case ENC_UNALLOCATED_27_ASIMDELEM: return "UNALLOCATED_27_asimdelem";
		case ENC_UNALLOCATED_27_ASIMDIMM: return "UNALLOCATED_27_asimdimm";
		case ENC_UNALLOCATED_27_ASIMDSAME2: return "UNALLOCATED_27_asimdsame2";
		case ENC_UNALLOCATED_27_ASISDLSE: return "UNALLOCATED_27_asisdlse";
		case ENC_UNALLOCATED_27_ASISDMISC: return "UNALLOCATED_27_asisdmisc";
		case ENC_UNALLOCATED_27_ASISDSAMEFP16: return "UNALLOCATED_27_asisdsamefp16";
		case ENC_UNALLOCATED_27_DP_3SRC: return "UNALLOCATED_27_dp_3src";
		case ENC_UNALLOCATED_280: return "UNALLOCATED_280";
		case ENC_UNALLOCATED_281: return "UNALLOCATED_281";
		case ENC_UNALLOCATED_282: return "UNALLOCATED_282";
		case ENC_UNALLOCATED_283: return "UNALLOCATED_283";
		case ENC_UNALLOCATED_284: return "UNALLOCATED_284";
		case ENC_UNALLOCATED_285: return "UNALLOCATED_285";
		case ENC_UNALLOCATED_286: return "UNALLOCATED_286";
		case ENC_UNALLOCATED_28_ASIMDIMM: return "UNALLOCATED_28_asimdimm";
		case ENC_UNALLOCATED_28_ASIMDSAME2: return "UNALLOCATED_28_asimdsame2";
		case ENC_UNALLOCATED_28_ASIMDSHF: return "UNALLOCATED_28_asimdshf";
		case ENC_UNALLOCATED_28_ASISDELEM: return "UNALLOCATED_28_asisdelem";
		case ENC_UNALLOCATED_28_ASISDPAIR: return "UNALLOCATED_28_asisdpair";
		case ENC_UNALLOCATED_28_BRANCH_REG: return "UNALLOCATED_28_branch_reg";
		case ENC_UNALLOCATED_28_DP_1SRC: return "UNALLOCATED_28_dp_1src";
		case ENC_UNALLOCATED_28_EXCEPTION: return "UNALLOCATED_28_exception";
		case ENC_UNALLOCATED_28_LDST_REGOFF: return "UNALLOCATED_28_ldst_regoff";
		case ENC_UNALLOCATED_29_ASIMDALL: return "UNALLOCATED_29_asimdall";
		case ENC_UNALLOCATED_29_ASIMDELEM: return "UNALLOCATED_29_asimdelem";
		case ENC_UNALLOCATED_29_ASIMDIMM: return "UNALLOCATED_29_asimdimm";
		case ENC_UNALLOCATED_29_ASIMDSAMEFP16: return "UNALLOCATED_29_asimdsamefp16";
		case ENC_UNALLOCATED_29_ASIMDSHF: return "UNALLOCATED_29_asimdshf";
		case ENC_UNALLOCATED_29_ASISDELEM: return "UNALLOCATED_29_asisdelem";
		case ENC_UNALLOCATED_29_ASISDLSE: return "UNALLOCATED_29_asisdlse";
		case ENC_UNALLOCATED_29_ASISDLSEP: return "UNALLOCATED_29_asisdlsep";
		case ENC_UNALLOCATED_29_ASISDLSO: return "UNALLOCATED_29_asisdlso";
		case ENC_UNALLOCATED_29_ASISDLSOP: return "UNALLOCATED_29_asisdlsop";
		case ENC_UNALLOCATED_29_ASISDSHF: return "UNALLOCATED_29_asisdshf";
		case ENC_UNALLOCATED_29_BRANCH_REG: return "UNALLOCATED_29_branch_reg";
		case ENC_UNALLOCATED_29_DP_3SRC: return "UNALLOCATED_29_dp_3src";
		case ENC_UNALLOCATED_29_EXCEPTION: return "UNALLOCATED_29_exception";
		case ENC_UNALLOCATED_30_ASIMDIMM: return "UNALLOCATED_30_asimdimm";
		case ENC_UNALLOCATED_30_ASISDLSEP: return "UNALLOCATED_30_asisdlsep";
		case ENC_UNALLOCATED_30_ASISDPAIR: return "UNALLOCATED_30_asisdpair";
		case ENC_UNALLOCATED_30_ASISDSAME: return "UNALLOCATED_30_asisdsame";
		case ENC_UNALLOCATED_30_ASISDSHF: return "UNALLOCATED_30_asisdshf";
		case ENC_UNALLOCATED_30_BRANCH_REG: return "UNALLOCATED_30_branch_reg";
		case ENC_UNALLOCATED_30_DP_3SRC: return "UNALLOCATED_30_dp_3src";
		case ENC_UNALLOCATED_30_EXCEPTION: return "UNALLOCATED_30_exception";
		case ENC_UNALLOCATED_31_ASIMDIMM: return "UNALLOCATED_31_asimdimm";
		case ENC_UNALLOCATED_31_ASIMDSAME2: return "UNALLOCATED_31_asimdsame2";
		case ENC_UNALLOCATED_31_ASIMDSAMEFP16: return "UNALLOCATED_31_asimdsamefp16";
		case ENC_UNALLOCATED_31_ASIMDSHF: return "UNALLOCATED_31_asimdshf";
		case ENC_UNALLOCATED_31_ASISDLSO: return "UNALLOCATED_31_asisdlso";
		case ENC_UNALLOCATED_31_ASISDLSOP: return "UNALLOCATED_31_asisdlsop";
		case ENC_UNALLOCATED_31_ASISDPAIR: return "UNALLOCATED_31_asisdpair";
		case ENC_UNALLOCATED_31_BRANCH_REG: return "UNALLOCATED_31_branch_reg";
		case ENC_UNALLOCATED_31_DP_3SRC: return "UNALLOCATED_31_dp_3src";
		case ENC_UNALLOCATED_31_EXCEPTION: return "UNALLOCATED_31_exception";
		case ENC_UNALLOCATED_32_ASIMDALL: return "UNALLOCATED_32_asimdall";
		case ENC_UNALLOCATED_32_ASIMDDIFF: return "UNALLOCATED_32_asimddiff";
		case ENC_UNALLOCATED_32_ASIMDELEM: return "UNALLOCATED_32_asimdelem";
		case ENC_UNALLOCATED_32_ASIMDSAME2: return "UNALLOCATED_32_asimdsame2";
		case ENC_UNALLOCATED_32_ASISDELEM: return "UNALLOCATED_32_asisdelem";
		case ENC_UNALLOCATED_32_ASISDPAIR: return "UNALLOCATED_32_asisdpair";
		case ENC_UNALLOCATED_32_ASISDSHF: return "UNALLOCATED_32_asisdshf";
		case ENC_UNALLOCATED_32_BRANCH_REG: return "UNALLOCATED_32_branch_reg";
		case ENC_UNALLOCATED_32_DP_3SRC: return "UNALLOCATED_32_dp_3src";
		case ENC_UNALLOCATED_32_EXCEPTION: return "UNALLOCATED_32_exception";
		case ENC_UNALLOCATED_33_ASIMDELEM: return "UNALLOCATED_33_asimdelem";
		case ENC_UNALLOCATED_33_ASIMDSAMEFP16: return "UNALLOCATED_33_asimdsamefp16";
		case ENC_UNALLOCATED_33_ASISDLSE: return "UNALLOCATED_33_asisdlse";
		case ENC_UNALLOCATED_33_ASISDLSEP: return "UNALLOCATED_33_asisdlsep";
		case ENC_UNALLOCATED_33_ASISDLSO: return "UNALLOCATED_33_asisdlso";
		case ENC_UNALLOCATED_33_ASISDLSOP: return "UNALLOCATED_33_asisdlsop";
		case ENC_UNALLOCATED_33_ASISDMISC: return "UNALLOCATED_33_asisdmisc";
		case ENC_UNALLOCATED_33_ASISDMISCFP16: return "UNALLOCATED_33_asisdmiscfp16";
		case ENC_UNALLOCATED_33_FLOATDP1: return "UNALLOCATED_33_floatdp1";
		case ENC_UNALLOCATED_34_ASIMDALL: return "UNALLOCATED_34_asimdall";
		case ENC_UNALLOCATED_34_ASIMDDIFF: return "UNALLOCATED_34_asimddiff";
		case ENC_UNALLOCATED_34_ASIMDMISC: return "UNALLOCATED_34_asimdmisc";
		case ENC_UNALLOCATED_34_ASIMDSAME2: return "UNALLOCATED_34_asimdsame2";
		case ENC_UNALLOCATED_34_ASIMDSHF: return "UNALLOCATED_34_asimdshf";
		case ENC_UNALLOCATED_34_ASISDLSO: return "UNALLOCATED_34_asisdlso";
		case ENC_UNALLOCATED_34_ASISDLSOP: return "UNALLOCATED_34_asisdlsop";
		case ENC_UNALLOCATED_34_ASISDMISC: return "UNALLOCATED_34_asisdmisc";
		case ENC_UNALLOCATED_34_ASISDPAIR: return "UNALLOCATED_34_asisdpair";
		case ENC_UNALLOCATED_34_BRANCH_REG: return "UNALLOCATED_34_branch_reg";
		case ENC_UNALLOCATED_34_DP_1SRC: return "UNALLOCATED_34_dp_1src";
		case ENC_UNALLOCATED_34_DP_2SRC: return "UNALLOCATED_34_dp_2src";
		case ENC_UNALLOCATED_34_FLOATDP1: return "UNALLOCATED_34_floatdp1";
		case ENC_UNALLOCATED_35_ASIMDALL: return "UNALLOCATED_35_asimdall";
		case ENC_UNALLOCATED_35_ASIMDSAME2: return "UNALLOCATED_35_asimdsame2";
		case ENC_UNALLOCATED_35_ASISDELEM: return "UNALLOCATED_35_asisdelem";
		case ENC_UNALLOCATED_35_ASISDLSE: return "UNALLOCATED_35_asisdlse";
		case ENC_UNALLOCATED_35_ASISDMISC: return "UNALLOCATED_35_asisdmisc";
		case ENC_UNALLOCATED_35_ASISDPAIR: return "UNALLOCATED_35_asisdpair";
		case ENC_UNALLOCATED_35_ASISDSAME: return "UNALLOCATED_35_asisdsame";
		case ENC_UNALLOCATED_35_ASISDSHF: return "UNALLOCATED_35_asisdshf";
		case ENC_UNALLOCATED_35_BRANCH_REG: return "UNALLOCATED_35_branch_reg";
		case ENC_UNALLOCATED_35_DP_2SRC: return "UNALLOCATED_35_dp_2src";
		case ENC_UNALLOCATED_35_LDST_IMMPOST: return "UNALLOCATED_35_ldst_immpost";
		case ENC_UNALLOCATED_35_LDST_IMMPRE: return "UNALLOCATED_35_ldst_immpre";
		case ENC_UNALLOCATED_35_LDST_POS: return "UNALLOCATED_35_ldst_pos";
		case ENC_UNALLOCATED_35_LDST_UNSCALED: return "UNALLOCATED_35_ldst_unscaled";
		case ENC_UNALLOCATED_36_ASISDLSE: return "UNALLOCATED_36_asisdlse";
		case ENC_UNALLOCATED_36_ASISDLSEP: return "UNALLOCATED_36_asisdlsep";
		case ENC_UNALLOCATED_36_ASISDMISC: return "UNALLOCATED_36_asisdmisc";
		case ENC_UNALLOCATED_36_ASISDSHF: return "UNALLOCATED_36_asisdshf";
		case ENC_UNALLOCATED_36_DP_2SRC: return "UNALLOCATED_36_dp_2src";
		case ENC_UNALLOCATED_36_LDST_IMMPOST: return "UNALLOCATED_36_ldst_immpost";
		case ENC_UNALLOCATED_36_LDST_IMMPRE: return "UNALLOCATED_36_ldst_immpre";
		case ENC_UNALLOCATED_36_LDST_POS: return "UNALLOCATED_36_ldst_pos";
		case ENC_UNALLOCATED_36_LDST_UNSCALED: return "UNALLOCATED_36_ldst_unscaled";
		case ENC_UNALLOCATED_37_ASIMDMISC: return "UNALLOCATED_37_asimdmisc";
		case ENC_UNALLOCATED_37_ASISDELEM: return "UNALLOCATED_37_asisdelem";
		case ENC_UNALLOCATED_37_ASISDLSO: return "UNALLOCATED_37_asisdlso";
		case ENC_UNALLOCATED_37_ASISDLSOP: return "UNALLOCATED_37_asisdlsop";
		case ENC_UNALLOCATED_37_BRANCH_REG: return "UNALLOCATED_37_branch_reg";
		case ENC_UNALLOCATED_38_ASIMDDIFF: return "UNALLOCATED_38_asimddiff";
		case ENC_UNALLOCATED_38_ASIMDSAME2: return "UNALLOCATED_38_asimdsame2";
		case ENC_UNALLOCATED_38_ASISDMISC: return "UNALLOCATED_38_asisdmisc";
		case ENC_UNALLOCATED_38_ASISDMISCFP16: return "UNALLOCATED_38_asisdmiscfp16";
		case ENC_UNALLOCATED_38_ASISDSHF: return "UNALLOCATED_38_asisdshf";
		case ENC_UNALLOCATED_38_DP_2SRC: return "UNALLOCATED_38_dp_2src";
		case ENC_UNALLOCATED_39_ASIMDALL: return "UNALLOCATED_39_asimdall";
		case ENC_UNALLOCATED_39_ASIMDELEM: return "UNALLOCATED_39_asimdelem";
		case ENC_UNALLOCATED_39_ASISDELEM: return "UNALLOCATED_39_asisdelem";
		case ENC_UNALLOCATED_39_ASISDLSEP: return "UNALLOCATED_39_asisdlsep";
		case ENC_UNALLOCATED_39_ASISDLSO: return "UNALLOCATED_39_asisdlso";
		case ENC_UNALLOCATED_39_ASISDLSOP: return "UNALLOCATED_39_asisdlsop";
		case ENC_UNALLOCATED_39_ASISDMISCFP16: return "UNALLOCATED_39_asisdmiscfp16";
		case ENC_UNALLOCATED_39_BRANCH_REG: return "UNALLOCATED_39_branch_reg";
		case ENC_UNALLOCATED_39_FLOAT2INT: return "UNALLOCATED_39_float2int";
		case ENC_UNALLOCATED_40_ASIMDALL: return "UNALLOCATED_40_asimdall";
		case ENC_UNALLOCATED_40_ASIMDDIFF: return "UNALLOCATED_40_asimddiff";
		case ENC_UNALLOCATED_40_ASIMDELEM: return "UNALLOCATED_40_asimdelem";
		case ENC_UNALLOCATED_40_BRANCH_REG: return "UNALLOCATED_40_branch_reg";
		case ENC_UNALLOCATED_40_FLOAT2INT: return "UNALLOCATED_40_float2int";
		case ENC_UNALLOCATED_40_FLOATDP1: return "UNALLOCATED_40_floatdp1";
		case ENC_UNALLOCATED_41_ASIMDDIFF: return "UNALLOCATED_41_asimddiff";
		case ENC_UNALLOCATED_41_ASIMDMISCFP16: return "UNALLOCATED_41_asimdmiscfp16";
		case ENC_UNALLOCATED_41_ASISDLSO: return "UNALLOCATED_41_asisdlso";
		case ENC_UNALLOCATED_41_ASISDLSOP: return "UNALLOCATED_41_asisdlsop";
		case ENC_UNALLOCATED_41_ASISDMISC: return "UNALLOCATED_41_asisdmisc";
		case ENC_UNALLOCATED_41_ASISDMISCFP16: return "UNALLOCATED_41_asisdmiscfp16";
		case ENC_UNALLOCATED_41_BRANCH_REG: return "UNALLOCATED_41_branch_reg";
		case ENC_UNALLOCATED_41_FLOAT2INT: return "UNALLOCATED_41_float2int";
		case ENC_UNALLOCATED_41_LDST_REGOFF: return "UNALLOCATED_41_ldst_regoff";
		case ENC_UNALLOCATED_42_ASIMDELEM: return "UNALLOCATED_42_asimdelem";
		case ENC_UNALLOCATED_42_ASIMDSAMEFP16: return "UNALLOCATED_42_asimdsamefp16";
		case ENC_UNALLOCATED_42_ASISDELEM: return "UNALLOCATED_42_asisdelem";
		case ENC_UNALLOCATED_42_ASISDLSO: return "UNALLOCATED_42_asisdlso";
		case ENC_UNALLOCATED_42_ASISDLSOP: return "UNALLOCATED_42_asisdlsop";
		case ENC_UNALLOCATED_42_ASISDMISC: return "UNALLOCATED_42_asisdmisc";
		case ENC_UNALLOCATED_42_BRANCH_REG: return "UNALLOCATED_42_branch_reg";
		case ENC_UNALLOCATED_42_LDST_REGOFF: return "UNALLOCATED_42_ldst_regoff";
		case ENC_UNALLOCATED_43_ASIMDMISC: return "UNALLOCATED_43_asimdmisc";
		case ENC_UNALLOCATED_43_ASISDELEM: return "UNALLOCATED_43_asisdelem";
		case ENC_UNALLOCATED_43_ASISDSAME: return "UNALLOCATED_43_asisdsame";
		case ENC_UNALLOCATED_43_BRANCH_REG: return "UNALLOCATED_43_branch_reg";
		case ENC_UNALLOCATED_44_ASIMDELEM: return "UNALLOCATED_44_asimdelem";
		case ENC_UNALLOCATED_44_ASISDMISC: return "UNALLOCATED_44_asisdmisc";
		case ENC_UNALLOCATED_44_ASISDSHF: return "UNALLOCATED_44_asisdshf";
		case ENC_UNALLOCATED_44_BRANCH_REG: return "UNALLOCATED_44_branch_reg";
		case ENC_UNALLOCATED_45_ASIMDSHF: return "UNALLOCATED_45_asimdshf";
		case ENC_UNALLOCATED_45_ASISDLSO: return "UNALLOCATED_45_asisdlso";
		case ENC_UNALLOCATED_45_ASISDLSOP: return "UNALLOCATED_45_asisdlsop";
		case ENC_UNALLOCATED_45_ASISDMISC: return "UNALLOCATED_45_asisdmisc";
		case ENC_UNALLOCATED_45_ASISDSHF: return "UNALLOCATED_45_asisdshf";
		case ENC_UNALLOCATED_46_ASIMDMISC: return "UNALLOCATED_46_asimdmisc";
		case ENC_UNALLOCATED_46_ASIMDMISCFP16: return "UNALLOCATED_46_asimdmiscfp16";
		case ENC_UNALLOCATED_46_ASIMDSHF: return "UNALLOCATED_46_asimdshf";
		case ENC_UNALLOCATED_46_ASISDLSEP: return "UNALLOCATED_46_asisdlsep";
		case ENC_UNALLOCATED_46_ASISDMISC: return "UNALLOCATED_46_asisdmisc";
		case ENC_UNALLOCATED_46_BRANCH_REG: return "UNALLOCATED_46_branch_reg";
		case ENC_UNALLOCATED_47_ASIMDELEM: return "UNALLOCATED_47_asimdelem";
		case ENC_UNALLOCATED_47_ASIMDMISCFP16: return "UNALLOCATED_47_asimdmiscfp16";
		case ENC_UNALLOCATED_47_ASIMDSHF: return "UNALLOCATED_47_asimdshf";
		case ENC_UNALLOCATED_47_BRANCH_REG: return "UNALLOCATED_47_branch_reg";
		case ENC_UNALLOCATED_47_DP_2SRC: return "UNALLOCATED_47_dp_2src";
		case ENC_UNALLOCATED_48_ASIMDMISCFP16: return "UNALLOCATED_48_asimdmiscfp16";
		case ENC_UNALLOCATED_48_ASISDLSO: return "UNALLOCATED_48_asisdlso";
		case ENC_UNALLOCATED_48_ASISDLSOP: return "UNALLOCATED_48_asisdlsop";
		case ENC_UNALLOCATED_48_ASISDSHF: return "UNALLOCATED_48_asisdshf";
		case ENC_UNALLOCATED_48_BRANCH_REG: return "UNALLOCATED_48_branch_reg";
		case ENC_UNALLOCATED_48_DP_2SRC: return "UNALLOCATED_48_dp_2src";
		case ENC_UNALLOCATED_48_FLOATDP1: return "UNALLOCATED_48_floatdp1";
		case ENC_UNALLOCATED_49_ASIMDMISC: return "UNALLOCATED_49_asimdmisc";
		case ENC_UNALLOCATED_49_ASISDLSEP: return "UNALLOCATED_49_asisdlsep";
		case ENC_UNALLOCATED_49_ASISDLSO: return "UNALLOCATED_49_asisdlso";
		case ENC_UNALLOCATED_49_ASISDLSOP: return "UNALLOCATED_49_asisdlsop";
		case ENC_UNALLOCATED_49_ASISDSAME: return "UNALLOCATED_49_asisdsame";
		case ENC_UNALLOCATED_49_ASISDSHF: return "UNALLOCATED_49_asisdshf";
		case ENC_UNALLOCATED_49_BRANCH_REG: return "UNALLOCATED_49_branch_reg";
		case ENC_UNALLOCATED_49_DP_2SRC: return "UNALLOCATED_49_dp_2src";
		case ENC_UNALLOCATED_50_ASIMDSHF: return "UNALLOCATED_50_asimdshf";
		case ENC_UNALLOCATED_50_ASISDLSEP: return "UNALLOCATED_50_asisdlsep";
		case ENC_UNALLOCATED_50_DP_2SRC: return "UNALLOCATED_50_dp_2src";
		case ENC_UNALLOCATED_51_ASIMDSHF: return "UNALLOCATED_51_asimdshf";
		case ENC_UNALLOCATED_51_ASISDLSO: return "UNALLOCATED_51_asisdlso";
		case ENC_UNALLOCATED_51_ASISDLSOP: return "UNALLOCATED_51_asisdlsop";
		case ENC_UNALLOCATED_51_ASISDSAME: return "UNALLOCATED_51_asisdsame";
		case ENC_UNALLOCATED_51_BRANCH_REG: return "UNALLOCATED_51_branch_reg";
		case ENC_UNALLOCATED_51_DP_2SRC: return "UNALLOCATED_51_dp_2src";
		case ENC_UNALLOCATED_52_BRANCH_REG: return "UNALLOCATED_52_branch_reg";
		case ENC_UNALLOCATED_53_ASIMDELEM: return "UNALLOCATED_53_asimdelem";
		case ENC_UNALLOCATED_53_ASIMDMISC: return "UNALLOCATED_53_asimdmisc";
		case ENC_UNALLOCATED_53_BRANCH_REG: return "UNALLOCATED_53_branch_reg";
		case ENC_UNALLOCATED_54_ASISDLSO: return "UNALLOCATED_54_asisdlso";
		case ENC_UNALLOCATED_54_ASISDLSOP: return "UNALLOCATED_54_asisdlsop";
		case ENC_UNALLOCATED_55_ASIMDELEM: return "UNALLOCATED_55_asimdelem";
		case ENC_UNALLOCATED_55_BRANCH_REG: return "UNALLOCATED_55_branch_reg";
		case ENC_UNALLOCATED_55_FLOATDP1: return "UNALLOCATED_55_floatdp1";
		case ENC_UNALLOCATED_56_ASISDLSO: return "UNALLOCATED_56_asisdlso";
		case ENC_UNALLOCATED_56_ASISDLSOP: return "UNALLOCATED_56_asisdlsop";
		case ENC_UNALLOCATED_56_BRANCH_REG: return "UNALLOCATED_56_branch_reg";
		case ENC_UNALLOCATED_56_FLOATDP1: return "UNALLOCATED_56_floatdp1";
		case ENC_UNALLOCATED_57_ASIMDELEM: return "UNALLOCATED_57_asimdelem";
		case ENC_UNALLOCATED_57_ASIMDMISC: return "UNALLOCATED_57_asimdmisc";
		case ENC_UNALLOCATED_57_ASISDMISC: return "UNALLOCATED_57_asisdmisc";
		case ENC_UNALLOCATED_57_BRANCH_REG: return "UNALLOCATED_57_branch_reg";
		case ENC_UNALLOCATED_57_FLOATDP1: return "UNALLOCATED_57_floatdp1";
		case ENC_UNALLOCATED_58_ASIMDMISC: return "UNALLOCATED_58_asimdmisc";
		case ENC_UNALLOCATED_58_ASISDLSO: return "UNALLOCATED_58_asisdlso";
		case ENC_UNALLOCATED_58_ASISDLSOP: return "UNALLOCATED_58_asisdlsop";
		case ENC_UNALLOCATED_58_ASISDSAME: return "UNALLOCATED_58_asisdsame";
		case ENC_UNALLOCATED_58_BRANCH_REG: return "UNALLOCATED_58_branch_reg";
		case ENC_UNALLOCATED_59_ASISDLSO: return "UNALLOCATED_59_asisdlso";
		case ENC_UNALLOCATED_59_ASISDLSOP: return "UNALLOCATED_59_asisdlsop";
		case ENC_UNALLOCATED_59_BRANCH_REG: return "UNALLOCATED_59_branch_reg";
		case ENC_UNALLOCATED_59_LDSTEXCL: return "UNALLOCATED_59_ldstexcl";
		case ENC_UNALLOCATED_60_ASIMDMISC: return "UNALLOCATED_60_asimdmisc";
		case ENC_UNALLOCATED_60_BRANCH_REG: return "UNALLOCATED_60_branch_reg";
		case ENC_UNALLOCATED_61_ASIMDMISC: return "UNALLOCATED_61_asimdmisc";
		case ENC_UNALLOCATED_61_ASISDLSO: return "UNALLOCATED_61_asisdlso";
		case ENC_UNALLOCATED_61_ASISDLSOP: return "UNALLOCATED_61_asisdlsop";
		case ENC_UNALLOCATED_61_ASISDSAME: return "UNALLOCATED_61_asisdsame";
		case ENC_UNALLOCATED_61_BRANCH_REG: return "UNALLOCATED_61_branch_reg";
		case ENC_UNALLOCATED_62_ASISDMISC: return "UNALLOCATED_62_asisdmisc";
		case ENC_UNALLOCATED_63_ASISDMISC: return "UNALLOCATED_63_asisdmisc";
		case ENC_UNALLOCATED_63_ASISDSAME: return "UNALLOCATED_63_asisdsame";
		case ENC_UNALLOCATED_63_BRANCH_REG: return "UNALLOCATED_63_branch_reg";
		case ENC_UNALLOCATED_64_ASIMDSAME: return "UNALLOCATED_64_asimdsame";
		case ENC_UNALLOCATED_64_ASISDLSO: return "UNALLOCATED_64_asisdlso";
		case ENC_UNALLOCATED_64_ASISDLSOP: return "UNALLOCATED_64_asisdlsop";
		case ENC_UNALLOCATED_64_BRANCH_REG: return "UNALLOCATED_64_branch_reg";
		case ENC_UNALLOCATED_64_FLOATDP1: return "UNALLOCATED_64_floatdp1";
		case ENC_UNALLOCATED_65_ASIMDMISC: return "UNALLOCATED_65_asimdmisc";
		case ENC_UNALLOCATED_65_ASISDMISC: return "UNALLOCATED_65_asisdmisc";
		case ENC_UNALLOCATED_65_ASISDSAME: return "UNALLOCATED_65_asisdsame";
		case ENC_UNALLOCATED_65_BRANCH_REG: return "UNALLOCATED_65_branch_reg";
		case ENC_UNALLOCATED_66_ASISDLSO: return "UNALLOCATED_66_asisdlso";
		case ENC_UNALLOCATED_66_ASISDLSOP: return "UNALLOCATED_66_asisdlsop";
		case ENC_UNALLOCATED_66_BRANCH_REG: return "UNALLOCATED_66_branch_reg";
		case ENC_UNALLOCATED_67_BRANCH_REG: return "UNALLOCATED_67_branch_reg";
		case ENC_UNALLOCATED_68_ASISDLSO: return "UNALLOCATED_68_asisdlso";
		case ENC_UNALLOCATED_68_ASISDLSOP: return "UNALLOCATED_68_asisdlsop";
		case ENC_UNALLOCATED_68_BRANCH_REG: return "UNALLOCATED_68_branch_reg";
		case ENC_UNALLOCATED_68_FLOAT2INT: return "UNALLOCATED_68_float2int";
		case ENC_UNALLOCATED_69_ASISDLSO: return "UNALLOCATED_69_asisdlso";
		case ENC_UNALLOCATED_69_ASISDLSOP: return "UNALLOCATED_69_asisdlsop";
		case ENC_UNALLOCATED_69_FLOAT2INT: return "UNALLOCATED_69_float2int";
		case ENC_UNALLOCATED_70_FLOATDP1: return "UNALLOCATED_70_floatdp1";
		case ENC_UNALLOCATED_71_ASIMDSAME: return "UNALLOCATED_71_asimdsame";
		case ENC_UNALLOCATED_71_ASISDLSO: return "UNALLOCATED_71_asisdlso";
		case ENC_UNALLOCATED_71_ASISDLSOP: return "UNALLOCATED_71_asisdlsop";
		case ENC_UNALLOCATED_71_BRANCH_REG: return "UNALLOCATED_71_branch_reg";
		case ENC_UNALLOCATED_71_FLOAT2INT: return "UNALLOCATED_71_float2int";
		case ENC_UNALLOCATED_72_BRANCH_REG: return "UNALLOCATED_72_branch_reg";
		case ENC_UNALLOCATED_72_FLOAT2INT: return "UNALLOCATED_72_float2int";
		case ENC_UNALLOCATED_73_BRANCH_REG: return "UNALLOCATED_73_branch_reg";
		case ENC_UNALLOCATED_73_FLOAT2INT: return "UNALLOCATED_73_float2int";
		case ENC_UNALLOCATED_73_FLOATDP1: return "UNALLOCATED_73_floatdp1";
		case ENC_UNALLOCATED_74_ASIMDSAME: return "UNALLOCATED_74_asimdsame";
		case ENC_UNALLOCATED_74_ASISDLSO: return "UNALLOCATED_74_asisdlso";
		case ENC_UNALLOCATED_74_ASISDLSOP: return "UNALLOCATED_74_asisdlsop";
		case ENC_UNALLOCATED_74_BRANCH_REG: return "UNALLOCATED_74_branch_reg";
		case ENC_UNALLOCATED_75_BRANCH_REG: return "UNALLOCATED_75_branch_reg";
		case ENC_UNALLOCATED_76_ASISDLSO: return "UNALLOCATED_76_asisdlso";
		case ENC_UNALLOCATED_76_ASISDLSOP: return "UNALLOCATED_76_asisdlsop";
		case ENC_UNALLOCATED_76_FLOAT2INT: return "UNALLOCATED_76_float2int";
		case ENC_UNALLOCATED_77_FLOAT2INT: return "UNALLOCATED_77_float2int";
		case ENC_UNALLOCATED_78_ASISDLSO: return "UNALLOCATED_78_asisdlso";
		case ENC_UNALLOCATED_78_ASISDLSOP: return "UNALLOCATED_78_asisdlsop";
		case ENC_UNALLOCATED_78_BRANCH_REG: return "UNALLOCATED_78_branch_reg";
		case ENC_UNALLOCATED_78_FLOAT2INT: return "UNALLOCATED_78_float2int";
		case ENC_UNALLOCATED_79_ASISDLSO: return "UNALLOCATED_79_asisdlso";
		case ENC_UNALLOCATED_79_ASISDLSOP: return "UNALLOCATED_79_asisdlsop";
		case ENC_UNALLOCATED_79_BRANCH_REG: return "UNALLOCATED_79_branch_reg";
		case ENC_UNALLOCATED_79_FLOAT2INT: return "UNALLOCATED_79_float2int";
		case ENC_UNALLOCATED_80_BRANCH_REG: return "UNALLOCATED_80_branch_reg";
		case ENC_UNALLOCATED_80_FLOAT2INT: return "UNALLOCATED_80_float2int";
		case ENC_UNALLOCATED_81_ASIMDSAME: return "UNALLOCATED_81_asimdsame";
		case ENC_UNALLOCATED_81_ASISDLSO: return "UNALLOCATED_81_asisdlso";
		case ENC_UNALLOCATED_81_ASISDLSOP: return "UNALLOCATED_81_asisdlsop";
		case ENC_UNALLOCATED_81_BRANCH_REG: return "UNALLOCATED_81_branch_reg";
		case ENC_UNALLOCATED_82_ASIMDSAME: return "UNALLOCATED_82_asimdsame";
		case ENC_UNALLOCATED_82_BRANCH_REG: return "UNALLOCATED_82_branch_reg";
		case ENC_UNALLOCATED_83_BRANCH_REG: return "UNALLOCATED_83_branch_reg";
		case ENC_UNALLOCATED_85_ASIMDSAME: return "UNALLOCATED_85_asimdsame";
		case ENC_UNALLOCATED_88_ASIMDMISC: return "UNALLOCATED_88_asimdmisc";
		case ENC_UNALLOCATED_88_ASIMDSAME: return "UNALLOCATED_88_asimdsame";
		case ENC_UNALLOCATED_91_ASIMDMISC: return "UNALLOCATED_91_asimdmisc";
		case ENC_UNALLOCATED_91_ASIMDSAME: return "UNALLOCATED_91_asimdsame";
		case ENC_UQADD_ASIMDSAME_ONLY: return "UQADD_asimdsame_only";
		case ENC_UQADD_ASISDSAME_ONLY: return "UQADD_asisdsame_only";
		case ENC_UQRSHL_ASIMDSAME_ONLY: return "UQRSHL_asimdsame_only";
		case ENC_UQRSHL_ASISDSAME_ONLY: return "UQRSHL_asisdsame_only";
		case ENC_UQRSHRN_ASIMDSHF_N: return "UQRSHRN_asimdshf_N";
		case ENC_UQRSHRN_ASISDSHF_N: return "UQRSHRN_asisdshf_N";
		case ENC_UQSHL_ASIMDSAME_ONLY: return "UQSHL_asimdsame_only";
		case ENC_UQSHL_ASIMDSHF_R: return "UQSHL_asimdshf_R";
		case ENC_UQSHL_ASISDSAME_ONLY: return "UQSHL_asisdsame_only";
		case ENC_UQSHL_ASISDSHF_R: return "UQSHL_asisdshf_R";
		case ENC_UQSHRN_ASIMDSHF_N: return "UQSHRN_asimdshf_N";
		case ENC_UQSHRN_ASISDSHF_N: return "UQSHRN_asisdshf_N";
		case ENC_UQSUB_ASIMDSAME_ONLY: return "UQSUB_asimdsame_only";
		case ENC_UQSUB_ASISDSAME_ONLY: return "UQSUB_asisdsame_only";
		case ENC_UQXTN_ASIMDMISC_N: return "UQXTN_asimdmisc_N";
		case ENC_UQXTN_ASISDMISC_N: return "UQXTN_asisdmisc_N";
		case ENC_URECPE_ASIMDMISC_R: return "URECPE_asimdmisc_R";
		case ENC_URHADD_ASIMDSAME_ONLY: return "URHADD_asimdsame_only";
		case ENC_URSHL_ASIMDSAME_ONLY: return "URSHL_asimdsame_only";
		case ENC_URSHL_ASISDSAME_ONLY: return "URSHL_asisdsame_only";
		case ENC_URSHR_ASIMDSHF_R: return "URSHR_asimdshf_R";
		case ENC_URSHR_ASISDSHF_R: return "URSHR_asisdshf_R";
		case ENC_URSQRTE_ASIMDMISC_R: return "URSQRTE_asimdmisc_R";
		case ENC_URSRA_ASIMDSHF_R: return "URSRA_asimdshf_R";
		case ENC_URSRA_ASISDSHF_R: return "URSRA_asisdshf_R";
		case ENC_USDOT_ASIMDELEM_D: return "USDOT_asimdelem_D";
		case ENC_USDOT_ASIMDSAME2_D: return "USDOT_asimdsame2_D";
		case ENC_USHLL_ASIMDSHF_L: return "USHLL_asimdshf_L";
		case ENC_USHL_ASIMDSAME_ONLY: return "USHL_asimdsame_only";
		case ENC_USHL_ASISDSAME_ONLY: return "USHL_asisdsame_only";
		case ENC_USHR_ASIMDSHF_R: return "USHR_asimdshf_R";
		case ENC_USHR_ASISDSHF_R: return "USHR_asisdshf_R";
		case ENC_USMMLA_ASIMDSAME2_G: return "USMMLA_asimdsame2_G";
		case ENC_USQADD_ASIMDMISC_R: return "USQADD_asimdmisc_R";
		case ENC_USQADD_ASISDMISC_R: return "USQADD_asisdmisc_R";
		case ENC_USRA_ASIMDSHF_R: return "USRA_asimdshf_R";
		case ENC_USRA_ASISDSHF_R: return "USRA_asisdshf_R";
		case ENC_USUBL_ASIMDDIFF_L: return "USUBL_asimddiff_L";
		case ENC_USUBW_ASIMDDIFF_W: return "USUBW_asimddiff_W";
		case ENC_UXTB_UBFM_32M_BITFIELD: return "UXTB_UBFM_32M_bitfield";
		case ENC_UXTH_UBFM_32M_BITFIELD: return "UXTH_UBFM_32M_bitfield";
		case ENC_UXTL_USHLL_ASIMDSHF_L: return "UXTL_USHLL_asimdshf_L";
		case ENC_UZP1_ASIMDPERM_ONLY: return "UZP1_asimdperm_only";
		case ENC_UZP2_ASIMDPERM_ONLY: return "UZP2_asimdperm_only";
		case ENC_WFE_HI_HINTS: return "WFE_HI_hints";
		case ENC_WFI_HI_HINTS: return "WFI_HI_hints";
		case ENC_XAFLAG_M_PSTATE: return "XAFLAG_M_pstate";
		case ENC_XAR_VVV2_CRYPTO3_IMM6: return "XAR_VVV2_crypto3_imm6";
		case ENC_XPACD_64Z_DP_1SRC: return "XPACD_64Z_dp_1src";
		case ENC_XPACI_64Z_DP_1SRC: return "XPACI_64Z_dp_1src";
		case ENC_XPACLRI_HI_HINTS: return "XPACLRI_HI_hints";
		case ENC_XTN_ASIMDMISC_N: return "XTN_asimdmisc_N";
		case ENC_YIELD_HI_HINTS: return "YIELD_HI_hints";
		case ENC_ZIP1_ASIMDPERM_ONLY: return "ZIP1_asimdperm_only";
		case ENC_ZIP2_ASIMDPERM_ONLY: return "ZIP2_asimdperm_only";
		case ENC_ABS_Z_P_Z_: return "abs_z_p_z_";
		case ENC_ADD_Z_P_ZZ_: return "add_z_p_zz_";
		case ENC_ADD_Z_ZI_: return "add_z_zi_";
		case ENC_ADD_Z_ZZ_: return "add_z_zz_";
		case ENC_ADDPL_R_RI_: return "addpl_r_ri_";
		case ENC_ADDVL_R_RI_: return "addvl_r_ri_";
		case ENC_ADR_Z_AZ_D_S32_SCALED: return "adr_z_az_d_s32_scaled";
		case ENC_ADR_Z_AZ_D_U32_SCALED: return "adr_z_az_d_u32_scaled";
		case ENC_ADR_Z_AZ_SD_SAME_SCALED: return "adr_z_az_sd_same_scaled";
		case ENC_AND_P_P_PP_Z: return "and_p_p_pp_z";
		case ENC_AND_Z_P_ZZ_: return "and_z_p_zz_";
		case ENC_AND_Z_ZI_: return "and_z_zi_";
		case ENC_AND_Z_ZZ_: return "and_z_zz_";
		case ENC_ANDS_P_P_PP_Z: return "ands_p_p_pp_z";
		case ENC_ANDV_R_P_Z_: return "andv_r_p_z_";
		case ENC_ASR_Z_P_ZI_: return "asr_z_p_zi_";
		case ENC_ASR_Z_P_ZW_: return "asr_z_p_zw_";
		case ENC_ASR_Z_P_ZZ_: return "asr_z_p_zz_";
		case ENC_ASR_Z_ZI_: return "asr_z_zi_";
		case ENC_ASR_Z_ZW_: return "asr_z_zw_";
		case ENC_ASRD_Z_P_ZI_: return "asrd_z_p_zi_";
		case ENC_ASRR_Z_P_ZZ_: return "asrr_z_p_zz_";
		case ENC_BFCVT_Z_P_Z_S2BF: return "bfcvt_z_p_z_s2bf";
		case ENC_BFCVTNT_Z_P_Z_S2BF: return "bfcvtnt_z_p_z_s2bf";
		case ENC_BFDOT_Z_ZZZ_: return "bfdot_z_zzz_";
		case ENC_BFDOT_Z_ZZZI_: return "bfdot_z_zzzi_";
		case ENC_BFMLALB_Z_ZZZ_: return "bfmlalb_z_zzz_";
		case ENC_BFMLALB_Z_ZZZI_: return "bfmlalb_z_zzzi_";
		case ENC_BFMLALT_Z_ZZZ_: return "bfmlalt_z_zzz_";
		case ENC_BFMLALT_Z_ZZZI_: return "bfmlalt_z_zzzi_";
		case ENC_BFMMLA_Z_ZZZ_: return "bfmmla_z_zzz_";
		case ENC_BIC_P_P_PP_Z: return "bic_p_p_pp_z";
		case ENC_BIC_Z_P_ZZ_: return "bic_z_p_zz_";
		case ENC_BIC_Z_ZZ_: return "bic_z_zz_";
		case ENC_BICS_P_P_PP_Z: return "bics_p_p_pp_z";
		case ENC_BRKA_P_P_P_: return "brka_p_p_p_";
		case ENC_BRKAS_P_P_P_Z: return "brkas_p_p_p_z";
		case ENC_BRKB_P_P_P_: return "brkb_p_p_p_";
		case ENC_BRKBS_P_P_P_Z: return "brkbs_p_p_p_z";
		case ENC_BRKN_P_P_PP_: return "brkn_p_p_pp_";
		case ENC_BRKNS_P_P_PP_: return "brkns_p_p_pp_";
		case ENC_BRKPA_P_P_PP_: return "brkpa_p_p_pp_";
		case ENC_BRKPAS_P_P_PP_: return "brkpas_p_p_pp_";
		case ENC_BRKPB_P_P_PP_: return "brkpb_p_p_pp_";
		case ENC_BRKPBS_P_P_PP_: return "brkpbs_p_p_pp_";
		case ENC_CLASTA_R_P_Z_: return "clasta_r_p_z_";
		case ENC_CLASTA_V_P_Z_: return "clasta_v_p_z_";
		case ENC_CLASTA_Z_P_ZZ_: return "clasta_z_p_zz_";
		case ENC_CLASTB_R_P_Z_: return "clastb_r_p_z_";
		case ENC_CLASTB_V_P_Z_: return "clastb_v_p_z_";
		case ENC_CLASTB_Z_P_ZZ_: return "clastb_z_p_zz_";
		case ENC_CLS_Z_P_Z_: return "cls_z_p_z_";
		case ENC_CLZ_Z_P_Z_: return "clz_z_p_z_";
		case ENC_CMPEQ_P_P_ZI_: return "cmpeq_p_p_zi_";
		case ENC_CMPEQ_P_P_ZW_: return "cmpeq_p_p_zw_";
		case ENC_CMPEQ_P_P_ZZ_: return "cmpeq_p_p_zz_";
		case ENC_CMPGE_P_P_ZI_: return "cmpge_p_p_zi_";
		case ENC_CMPGE_P_P_ZW_: return "cmpge_p_p_zw_";
		case ENC_CMPGE_P_P_ZZ_: return "cmpge_p_p_zz_";
		case ENC_CMPGT_P_P_ZI_: return "cmpgt_p_p_zi_";
		case ENC_CMPGT_P_P_ZW_: return "cmpgt_p_p_zw_";
		case ENC_CMPGT_P_P_ZZ_: return "cmpgt_p_p_zz_";
		case ENC_CMPHI_P_P_ZI_: return "cmphi_p_p_zi_";
		case ENC_CMPHI_P_P_ZW_: return "cmphi_p_p_zw_";
		case ENC_CMPHI_P_P_ZZ_: return "cmphi_p_p_zz_";
		case ENC_CMPHS_P_P_ZI_: return "cmphs_p_p_zi_";
		case ENC_CMPHS_P_P_ZW_: return "cmphs_p_p_zw_";
		case ENC_CMPHS_P_P_ZZ_: return "cmphs_p_p_zz_";
		case ENC_CMPLE_P_P_ZI_: return "cmple_p_p_zi_";
		case ENC_CMPLE_P_P_ZW_: return "cmple_p_p_zw_";
		case ENC_CMPLO_P_P_ZI_: return "cmplo_p_p_zi_";
		case ENC_CMPLO_P_P_ZW_: return "cmplo_p_p_zw_";
		case ENC_CMPLS_P_P_ZI_: return "cmpls_p_p_zi_";
		case ENC_CMPLS_P_P_ZW_: return "cmpls_p_p_zw_";
		case ENC_CMPLT_P_P_ZI_: return "cmplt_p_p_zi_";
		case ENC_CMPLT_P_P_ZW_: return "cmplt_p_p_zw_";
		case ENC_CMPNE_P_P_ZI_: return "cmpne_p_p_zi_";
		case ENC_CMPNE_P_P_ZW_: return "cmpne_p_p_zw_";
		case ENC_CMPNE_P_P_ZZ_: return "cmpne_p_p_zz_";
		case ENC_CNOT_Z_P_Z_: return "cnot_z_p_z_";
		case ENC_CNT_Z_P_Z_: return "cnt_z_p_z_";
		case ENC_CNTB_R_S_: return "cntb_r_s_";
		case ENC_CNTD_R_S_: return "cntd_r_s_";
		case ENC_CNTH_R_S_: return "cnth_r_s_";
		case ENC_CNTP_R_P_P_: return "cntp_r_p_p_";
		case ENC_CNTW_R_S_: return "cntw_r_s_";
		case ENC_COMPACT_Z_P_Z_: return "compact_z_p_z_";
		case ENC_CPY_Z_O_I_: return "cpy_z_o_i_";
		case ENC_CPY_Z_P_I_: return "cpy_z_p_i_";
		case ENC_CPY_Z_P_R_: return "cpy_z_p_r_";
		case ENC_CPY_Z_P_V_: return "cpy_z_p_v_";
		case ENC_CTERMEQ_RR_: return "ctermeq_rr_";
		case ENC_CTERMNE_RR_: return "ctermne_rr_";
		case ENC_DECB_R_RS_: return "decb_r_rs_";
		case ENC_DECD_R_RS_: return "decd_r_rs_";
		case ENC_DECD_Z_ZS_: return "decd_z_zs_";
		case ENC_DECH_R_RS_: return "dech_r_rs_";
		case ENC_DECH_Z_ZS_: return "dech_z_zs_";
		case ENC_DECP_R_P_R_: return "decp_r_p_r_";
		case ENC_DECP_Z_P_Z_: return "decp_z_p_z_";
		case ENC_DECW_R_RS_: return "decw_r_rs_";
		case ENC_DECW_Z_ZS_: return "decw_z_zs_";
		case ENC_DUP_Z_I_: return "dup_z_i_";
		case ENC_DUP_Z_R_: return "dup_z_r_";
		case ENC_DUP_Z_ZI_: return "dup_z_zi_";
		case ENC_DUPM_Z_I_: return "dupm_z_i_";
		case ENC_EOR_P_P_PP_Z: return "eor_p_p_pp_z";
		case ENC_EOR_Z_P_ZZ_: return "eor_z_p_zz_";
		case ENC_EOR_Z_ZI_: return "eor_z_zi_";
		case ENC_EOR_Z_ZZ_: return "eor_z_zz_";
		case ENC_EORS_P_P_PP_Z: return "eors_p_p_pp_z";
		case ENC_EORV_R_P_Z_: return "eorv_r_p_z_";
		case ENC_EXT_Z_ZI_DES: return "ext_z_zi_des";
		case ENC_FABD_Z_P_ZZ_: return "fabd_z_p_zz_";
		case ENC_FABS_Z_P_Z_: return "fabs_z_p_z_";
		case ENC_FACGE_P_P_ZZ_: return "facge_p_p_zz_";
		case ENC_FACGT_P_P_ZZ_: return "facgt_p_p_zz_";
		case ENC_FADD_Z_P_ZS_: return "fadd_z_p_zs_";
		case ENC_FADD_Z_P_ZZ_: return "fadd_z_p_zz_";
		case ENC_FADD_Z_ZZ_: return "fadd_z_zz_";
		case ENC_FADDA_V_P_Z_: return "fadda_v_p_z_";
		case ENC_FADDV_V_P_Z_: return "faddv_v_p_z_";
		case ENC_FCADD_Z_P_ZZ_: return "fcadd_z_p_zz_";
		case ENC_FCMEQ_P_P_Z0_: return "fcmeq_p_p_z0_";
		case ENC_FCMEQ_P_P_ZZ_: return "fcmeq_p_p_zz_";
		case ENC_FCMGE_P_P_Z0_: return "fcmge_p_p_z0_";
		case ENC_FCMGE_P_P_ZZ_: return "fcmge_p_p_zz_";
		case ENC_FCMGT_P_P_Z0_: return "fcmgt_p_p_z0_";
		case ENC_FCMGT_P_P_ZZ_: return "fcmgt_p_p_zz_";
		case ENC_FCMLA_Z_P_ZZZ_: return "fcmla_z_p_zzz_";
		case ENC_FCMLA_Z_ZZZI_H: return "fcmla_z_zzzi_h";
		case ENC_FCMLA_Z_ZZZI_S: return "fcmla_z_zzzi_s";
		case ENC_FCMLE_P_P_Z0_: return "fcmle_p_p_z0_";
		case ENC_FCMLT_P_P_Z0_: return "fcmlt_p_p_z0_";
		case ENC_FCMNE_P_P_Z0_: return "fcmne_p_p_z0_";
		case ENC_FCMNE_P_P_ZZ_: return "fcmne_p_p_zz_";
		case ENC_FCMUO_P_P_ZZ_: return "fcmuo_p_p_zz_";
		case ENC_FCPY_Z_P_I_: return "fcpy_z_p_i_";
		case ENC_FCVT_Z_P_Z_D2H: return "fcvt_z_p_z_d2h";
		case ENC_FCVT_Z_P_Z_D2S: return "fcvt_z_p_z_d2s";
		case ENC_FCVT_Z_P_Z_H2D: return "fcvt_z_p_z_h2d";
		case ENC_FCVT_Z_P_Z_H2S: return "fcvt_z_p_z_h2s";
		case ENC_FCVT_Z_P_Z_S2D: return "fcvt_z_p_z_s2d";
		case ENC_FCVT_Z_P_Z_S2H: return "fcvt_z_p_z_s2h";
		case ENC_FCVTZS_Z_P_Z_D2W: return "fcvtzs_z_p_z_d2w";
		case ENC_FCVTZS_Z_P_Z_D2X: return "fcvtzs_z_p_z_d2x";
		case ENC_FCVTZS_Z_P_Z_FP162H: return "fcvtzs_z_p_z_fp162h";
		case ENC_FCVTZS_Z_P_Z_FP162W: return "fcvtzs_z_p_z_fp162w";
		case ENC_FCVTZS_Z_P_Z_FP162X: return "fcvtzs_z_p_z_fp162x";
		case ENC_FCVTZS_Z_P_Z_S2W: return "fcvtzs_z_p_z_s2w";
		case ENC_FCVTZS_Z_P_Z_S2X: return "fcvtzs_z_p_z_s2x";
		case ENC_FCVTZU_Z_P_Z_D2W: return "fcvtzu_z_p_z_d2w";
		case ENC_FCVTZU_Z_P_Z_D2X: return "fcvtzu_z_p_z_d2x";
		case ENC_FCVTZU_Z_P_Z_FP162H: return "fcvtzu_z_p_z_fp162h";
		case ENC_FCVTZU_Z_P_Z_FP162W: return "fcvtzu_z_p_z_fp162w";
		case ENC_FCVTZU_Z_P_Z_FP162X: return "fcvtzu_z_p_z_fp162x";
		case ENC_FCVTZU_Z_P_Z_S2W: return "fcvtzu_z_p_z_s2w";
		case ENC_FCVTZU_Z_P_Z_S2X: return "fcvtzu_z_p_z_s2x";
		case ENC_FDIV_Z_P_ZZ_: return "fdiv_z_p_zz_";
		case ENC_FDIVR_Z_P_ZZ_: return "fdivr_z_p_zz_";
		case ENC_FDUP_Z_I_: return "fdup_z_i_";
		case ENC_FEXPA_Z_Z_: return "fexpa_z_z_";
		case ENC_FMAD_Z_P_ZZZ_: return "fmad_z_p_zzz_";
		case ENC_FMAX_Z_P_ZS_: return "fmax_z_p_zs_";
		case ENC_FMAX_Z_P_ZZ_: return "fmax_z_p_zz_";
		case ENC_FMAXNM_Z_P_ZS_: return "fmaxnm_z_p_zs_";
		case ENC_FMAXNM_Z_P_ZZ_: return "fmaxnm_z_p_zz_";
		case ENC_FMAXNMV_V_P_Z_: return "fmaxnmv_v_p_z_";
		case ENC_FMAXV_V_P_Z_: return "fmaxv_v_p_z_";
		case ENC_FMIN_Z_P_ZS_: return "fmin_z_p_zs_";
		case ENC_FMIN_Z_P_ZZ_: return "fmin_z_p_zz_";
		case ENC_FMINNM_Z_P_ZS_: return "fminnm_z_p_zs_";
		case ENC_FMINNM_Z_P_ZZ_: return "fminnm_z_p_zz_";
		case ENC_FMINNMV_V_P_Z_: return "fminnmv_v_p_z_";
		case ENC_FMINV_V_P_Z_: return "fminv_v_p_z_";
		case ENC_FMLA_Z_P_ZZZ_: return "fmla_z_p_zzz_";
		case ENC_FMLA_Z_ZZZI_D: return "fmla_z_zzzi_d";
		case ENC_FMLA_Z_ZZZI_H: return "fmla_z_zzzi_h";
		case ENC_FMLA_Z_ZZZI_S: return "fmla_z_zzzi_s";
		case ENC_FMLS_Z_P_ZZZ_: return "fmls_z_p_zzz_";
		case ENC_FMLS_Z_ZZZI_D: return "fmls_z_zzzi_d";
		case ENC_FMLS_Z_ZZZI_H: return "fmls_z_zzzi_h";
		case ENC_FMLS_Z_ZZZI_S: return "fmls_z_zzzi_s";
		case ENC_FMMLA_Z_ZZZ_D: return "fmmla_z_zzz_d";
		case ENC_FMMLA_Z_ZZZ_S: return "fmmla_z_zzz_s";
		case ENC_FMSB_Z_P_ZZZ_: return "fmsb_z_p_zzz_";
		case ENC_FMUL_Z_P_ZS_: return "fmul_z_p_zs_";
		case ENC_FMUL_Z_P_ZZ_: return "fmul_z_p_zz_";
		case ENC_FMUL_Z_ZZ_: return "fmul_z_zz_";
		case ENC_FMUL_Z_ZZI_D: return "fmul_z_zzi_d";
		case ENC_FMUL_Z_ZZI_H: return "fmul_z_zzi_h";
		case ENC_FMUL_Z_ZZI_S: return "fmul_z_zzi_s";
		case ENC_FMULX_Z_P_ZZ_: return "fmulx_z_p_zz_";
		case ENC_FNEG_Z_P_Z_: return "fneg_z_p_z_";
		case ENC_FNMAD_Z_P_ZZZ_: return "fnmad_z_p_zzz_";
		case ENC_FNMLA_Z_P_ZZZ_: return "fnmla_z_p_zzz_";
		case ENC_FNMLS_Z_P_ZZZ_: return "fnmls_z_p_zzz_";
		case ENC_FNMSB_Z_P_ZZZ_: return "fnmsb_z_p_zzz_";
		case ENC_FRECPE_Z_Z_: return "frecpe_z_z_";
		case ENC_FRECPS_Z_ZZ_: return "frecps_z_zz_";
		case ENC_FRECPX_Z_P_Z_: return "frecpx_z_p_z_";
		case ENC_FRINTA_Z_P_Z_: return "frinta_z_p_z_";
		case ENC_FRINTI_Z_P_Z_: return "frinti_z_p_z_";
		case ENC_FRINTM_Z_P_Z_: return "frintm_z_p_z_";
		case ENC_FRINTN_Z_P_Z_: return "frintn_z_p_z_";
		case ENC_FRINTP_Z_P_Z_: return "frintp_z_p_z_";
		case ENC_FRINTX_Z_P_Z_: return "frintx_z_p_z_";
		case ENC_FRINTZ_Z_P_Z_: return "frintz_z_p_z_";
		case ENC_FRSQRTE_Z_Z_: return "frsqrte_z_z_";
		case ENC_FRSQRTS_Z_ZZ_: return "frsqrts_z_zz_";
		case ENC_FSCALE_Z_P_ZZ_: return "fscale_z_p_zz_";
		case ENC_FSQRT_Z_P_Z_: return "fsqrt_z_p_z_";
		case ENC_FSUB_Z_P_ZS_: return "fsub_z_p_zs_";
		case ENC_FSUB_Z_P_ZZ_: return "fsub_z_p_zz_";
		case ENC_FSUB_Z_ZZ_: return "fsub_z_zz_";
		case ENC_FSUBR_Z_P_ZS_: return "fsubr_z_p_zs_";
		case ENC_FSUBR_Z_P_ZZ_: return "fsubr_z_p_zz_";
		case ENC_FTMAD_Z_ZZI_: return "ftmad_z_zzi_";
		case ENC_FTSMUL_Z_ZZ_: return "ftsmul_z_zz_";
		case ENC_FTSSEL_Z_ZZ_: return "ftssel_z_zz_";
		case ENC_INCB_R_RS_: return "incb_r_rs_";
		case ENC_INCD_R_RS_: return "incd_r_rs_";
		case ENC_INCD_Z_ZS_: return "incd_z_zs_";
		case ENC_INCH_R_RS_: return "inch_r_rs_";
		case ENC_INCH_Z_ZS_: return "inch_z_zs_";
		case ENC_INCP_R_P_R_: return "incp_r_p_r_";
		case ENC_INCP_Z_P_Z_: return "incp_z_p_z_";
		case ENC_INCW_R_RS_: return "incw_r_rs_";
		case ENC_INCW_Z_ZS_: return "incw_z_zs_";
		case ENC_INDEX_Z_II_: return "index_z_ii_";
		case ENC_INDEX_Z_IR_: return "index_z_ir_";
		case ENC_INDEX_Z_RI_: return "index_z_ri_";
		case ENC_INDEX_Z_RR_: return "index_z_rr_";
		case ENC_INSR_Z_R_: return "insr_z_r_";
		case ENC_INSR_Z_V_: return "insr_z_v_";
		case ENC_LASTA_R_P_Z_: return "lasta_r_p_z_";
		case ENC_LASTA_V_P_Z_: return "lasta_v_p_z_";
		case ENC_LASTB_R_P_Z_: return "lastb_r_p_z_";
		case ENC_LASTB_V_P_Z_: return "lastb_v_p_z_";
		case ENC_LD1B_Z_P_AI_D: return "ld1b_z_p_ai_d";
		case ENC_LD1B_Z_P_AI_S: return "ld1b_z_p_ai_s";
		case ENC_LD1B_Z_P_BI_U16: return "ld1b_z_p_bi_u16";
		case ENC_LD1B_Z_P_BI_U32: return "ld1b_z_p_bi_u32";
		case ENC_LD1B_Z_P_BI_U64: return "ld1b_z_p_bi_u64";
		case ENC_LD1B_Z_P_BI_U8: return "ld1b_z_p_bi_u8";
		case ENC_LD1B_Z_P_BR_U16: return "ld1b_z_p_br_u16";
		case ENC_LD1B_Z_P_BR_U32: return "ld1b_z_p_br_u32";
		case ENC_LD1B_Z_P_BR_U64: return "ld1b_z_p_br_u64";
		case ENC_LD1B_Z_P_BR_U8: return "ld1b_z_p_br_u8";
		case ENC_LD1B_Z_P_BZ_D_64_UNSCALED: return "ld1b_z_p_bz_d_64_unscaled";
		case ENC_LD1B_Z_P_BZ_D_X32_UNSCALED: return "ld1b_z_p_bz_d_x32_unscaled";
		case ENC_LD1B_Z_P_BZ_S_X32_UNSCALED: return "ld1b_z_p_bz_s_x32_unscaled";
		case ENC_LD1D_Z_P_AI_D: return "ld1d_z_p_ai_d";
		case ENC_LD1D_Z_P_BI_U64: return "ld1d_z_p_bi_u64";
		case ENC_LD1D_Z_P_BR_U64: return "ld1d_z_p_br_u64";
		case ENC_LD1D_Z_P_BZ_D_64_SCALED: return "ld1d_z_p_bz_d_64_scaled";
		case ENC_LD1D_Z_P_BZ_D_64_UNSCALED: return "ld1d_z_p_bz_d_64_unscaled";
		case ENC_LD1D_Z_P_BZ_D_X32_SCALED: return "ld1d_z_p_bz_d_x32_scaled";
		case ENC_LD1D_Z_P_BZ_D_X32_UNSCALED: return "ld1d_z_p_bz_d_x32_unscaled";
		case ENC_LD1H_Z_P_AI_D: return "ld1h_z_p_ai_d";
		case ENC_LD1H_Z_P_AI_S: return "ld1h_z_p_ai_s";
		case ENC_LD1H_Z_P_BI_U16: return "ld1h_z_p_bi_u16";
		case ENC_LD1H_Z_P_BI_U32: return "ld1h_z_p_bi_u32";
		case ENC_LD1H_Z_P_BI_U64: return "ld1h_z_p_bi_u64";
		case ENC_LD1H_Z_P_BR_U16: return "ld1h_z_p_br_u16";
		case ENC_LD1H_Z_P_BR_U32: return "ld1h_z_p_br_u32";
		case ENC_LD1H_Z_P_BR_U64: return "ld1h_z_p_br_u64";
		case ENC_LD1H_Z_P_BZ_D_64_SCALED: return "ld1h_z_p_bz_d_64_scaled";
		case ENC_LD1H_Z_P_BZ_D_64_UNSCALED: return "ld1h_z_p_bz_d_64_unscaled";
		case ENC_LD1H_Z_P_BZ_D_X32_SCALED: return "ld1h_z_p_bz_d_x32_scaled";
		case ENC_LD1H_Z_P_BZ_D_X32_UNSCALED: return "ld1h_z_p_bz_d_x32_unscaled";
		case ENC_LD1H_Z_P_BZ_S_X32_SCALED: return "ld1h_z_p_bz_s_x32_scaled";
		case ENC_LD1H_Z_P_BZ_S_X32_UNSCALED: return "ld1h_z_p_bz_s_x32_unscaled";
		case ENC_LD1RB_Z_P_BI_U16: return "ld1rb_z_p_bi_u16";
		case ENC_LD1RB_Z_P_BI_U32: return "ld1rb_z_p_bi_u32";
		case ENC_LD1RB_Z_P_BI_U64: return "ld1rb_z_p_bi_u64";
		case ENC_LD1RB_Z_P_BI_U8: return "ld1rb_z_p_bi_u8";
		case ENC_LD1RD_Z_P_BI_U64: return "ld1rd_z_p_bi_u64";
		case ENC_LD1RH_Z_P_BI_U16: return "ld1rh_z_p_bi_u16";
		case ENC_LD1RH_Z_P_BI_U32: return "ld1rh_z_p_bi_u32";
		case ENC_LD1RH_Z_P_BI_U64: return "ld1rh_z_p_bi_u64";
		case ENC_LD1ROB_Z_P_BI_U8: return "ld1rob_z_p_bi_u8";
		case ENC_LD1ROB_Z_P_BR_CONTIGUOUS: return "ld1rob_z_p_br_contiguous";
		case ENC_LD1ROD_Z_P_BI_U64: return "ld1rod_z_p_bi_u64";
		case ENC_LD1ROD_Z_P_BR_CONTIGUOUS: return "ld1rod_z_p_br_contiguous";
		case ENC_LD1ROH_Z_P_BI_U16: return "ld1roh_z_p_bi_u16";
		case ENC_LD1ROH_Z_P_BR_CONTIGUOUS: return "ld1roh_z_p_br_contiguous";
		case ENC_LD1ROW_Z_P_BI_U32: return "ld1row_z_p_bi_u32";
		case ENC_LD1ROW_Z_P_BR_CONTIGUOUS: return "ld1row_z_p_br_contiguous";
		case ENC_LD1RQB_Z_P_BI_U8: return "ld1rqb_z_p_bi_u8";
		case ENC_LD1RQB_Z_P_BR_CONTIGUOUS: return "ld1rqb_z_p_br_contiguous";
		case ENC_LD1RQD_Z_P_BI_U64: return "ld1rqd_z_p_bi_u64";
		case ENC_LD1RQD_Z_P_BR_CONTIGUOUS: return "ld1rqd_z_p_br_contiguous";
		case ENC_LD1RQH_Z_P_BI_U16: return "ld1rqh_z_p_bi_u16";
		case ENC_LD1RQH_Z_P_BR_CONTIGUOUS: return "ld1rqh_z_p_br_contiguous";
		case ENC_LD1RQW_Z_P_BI_U32: return "ld1rqw_z_p_bi_u32";
		case ENC_LD1RQW_Z_P_BR_CONTIGUOUS: return "ld1rqw_z_p_br_contiguous";
		case ENC_LD1RSB_Z_P_BI_S16: return "ld1rsb_z_p_bi_s16";
		case ENC_LD1RSB_Z_P_BI_S32: return "ld1rsb_z_p_bi_s32";
		case ENC_LD1RSB_Z_P_BI_S64: return "ld1rsb_z_p_bi_s64";
		case ENC_LD1RSH_Z_P_BI_S32: return "ld1rsh_z_p_bi_s32";
		case ENC_LD1RSH_Z_P_BI_S64: return "ld1rsh_z_p_bi_s64";
		case ENC_LD1RSW_Z_P_BI_S64: return "ld1rsw_z_p_bi_s64";
		case ENC_LD1RW_Z_P_BI_U32: return "ld1rw_z_p_bi_u32";
		case ENC_LD1RW_Z_P_BI_U64: return "ld1rw_z_p_bi_u64";
		case ENC_LD1SB_Z_P_AI_D: return "ld1sb_z_p_ai_d";
		case ENC_LD1SB_Z_P_AI_S: return "ld1sb_z_p_ai_s";
		case ENC_LD1SB_Z_P_BI_S16: return "ld1sb_z_p_bi_s16";
		case ENC_LD1SB_Z_P_BI_S32: return "ld1sb_z_p_bi_s32";
		case ENC_LD1SB_Z_P_BI_S64: return "ld1sb_z_p_bi_s64";
		case ENC_LD1SB_Z_P_BR_S16: return "ld1sb_z_p_br_s16";
		case ENC_LD1SB_Z_P_BR_S32: return "ld1sb_z_p_br_s32";
		case ENC_LD1SB_Z_P_BR_S64: return "ld1sb_z_p_br_s64";
		case ENC_LD1SB_Z_P_BZ_D_64_UNSCALED: return "ld1sb_z_p_bz_d_64_unscaled";
		case ENC_LD1SB_Z_P_BZ_D_X32_UNSCALED: return "ld1sb_z_p_bz_d_x32_unscaled";
		case ENC_LD1SB_Z_P_BZ_S_X32_UNSCALED: return "ld1sb_z_p_bz_s_x32_unscaled";
		case ENC_LD1SH_Z_P_AI_D: return "ld1sh_z_p_ai_d";
		case ENC_LD1SH_Z_P_AI_S: return "ld1sh_z_p_ai_s";
		case ENC_LD1SH_Z_P_BI_S32: return "ld1sh_z_p_bi_s32";
		case ENC_LD1SH_Z_P_BI_S64: return "ld1sh_z_p_bi_s64";
		case ENC_LD1SH_Z_P_BR_S32: return "ld1sh_z_p_br_s32";
		case ENC_LD1SH_Z_P_BR_S64: return "ld1sh_z_p_br_s64";
		case ENC_LD1SH_Z_P_BZ_D_64_SCALED: return "ld1sh_z_p_bz_d_64_scaled";
		case ENC_LD1SH_Z_P_BZ_D_64_UNSCALED: return "ld1sh_z_p_bz_d_64_unscaled";
		case ENC_LD1SH_Z_P_BZ_D_X32_SCALED: return "ld1sh_z_p_bz_d_x32_scaled";
		case ENC_LD1SH_Z_P_BZ_D_X32_UNSCALED: return "ld1sh_z_p_bz_d_x32_unscaled";
		case ENC_LD1SH_Z_P_BZ_S_X32_SCALED: return "ld1sh_z_p_bz_s_x32_scaled";
		case ENC_LD1SH_Z_P_BZ_S_X32_UNSCALED: return "ld1sh_z_p_bz_s_x32_unscaled";
		case ENC_LD1SW_Z_P_AI_D: return "ld1sw_z_p_ai_d";
		case ENC_LD1SW_Z_P_BI_S64: return "ld1sw_z_p_bi_s64";
		case ENC_LD1SW_Z_P_BR_S64: return "ld1sw_z_p_br_s64";
		case ENC_LD1SW_Z_P_BZ_D_64_SCALED: return "ld1sw_z_p_bz_d_64_scaled";
		case ENC_LD1SW_Z_P_BZ_D_64_UNSCALED: return "ld1sw_z_p_bz_d_64_unscaled";
		case ENC_LD1SW_Z_P_BZ_D_X32_SCALED: return "ld1sw_z_p_bz_d_x32_scaled";
		case ENC_LD1SW_Z_P_BZ_D_X32_UNSCALED: return "ld1sw_z_p_bz_d_x32_unscaled";
		case ENC_LD1W_Z_P_AI_D: return "ld1w_z_p_ai_d";
		case ENC_LD1W_Z_P_AI_S: return "ld1w_z_p_ai_s";
		case ENC_LD1W_Z_P_BI_U32: return "ld1w_z_p_bi_u32";
		case ENC_LD1W_Z_P_BI_U64: return "ld1w_z_p_bi_u64";
		case ENC_LD1W_Z_P_BR_U32: return "ld1w_z_p_br_u32";
		case ENC_LD1W_Z_P_BR_U64: return "ld1w_z_p_br_u64";
		case ENC_LD1W_Z_P_BZ_D_64_SCALED: return "ld1w_z_p_bz_d_64_scaled";
		case ENC_LD1W_Z_P_BZ_D_64_UNSCALED: return "ld1w_z_p_bz_d_64_unscaled";
		case ENC_LD1W_Z_P_BZ_D_X32_SCALED: return "ld1w_z_p_bz_d_x32_scaled";
		case ENC_LD1W_Z_P_BZ_D_X32_UNSCALED: return "ld1w_z_p_bz_d_x32_unscaled";
		case ENC_LD1W_Z_P_BZ_S_X32_SCALED: return "ld1w_z_p_bz_s_x32_scaled";
		case ENC_LD1W_Z_P_BZ_S_X32_UNSCALED: return "ld1w_z_p_bz_s_x32_unscaled";
		case ENC_LD2B_Z_P_BI_CONTIGUOUS: return "ld2b_z_p_bi_contiguous";
		case ENC_LD2B_Z_P_BR_CONTIGUOUS: return "ld2b_z_p_br_contiguous";
		case ENC_LD2D_Z_P_BI_CONTIGUOUS: return "ld2d_z_p_bi_contiguous";
		case ENC_LD2D_Z_P_BR_CONTIGUOUS: return "ld2d_z_p_br_contiguous";
		case ENC_LD2H_Z_P_BI_CONTIGUOUS: return "ld2h_z_p_bi_contiguous";
		case ENC_LD2H_Z_P_BR_CONTIGUOUS: return "ld2h_z_p_br_contiguous";
		case ENC_LD2W_Z_P_BI_CONTIGUOUS: return "ld2w_z_p_bi_contiguous";
		case ENC_LD2W_Z_P_BR_CONTIGUOUS: return "ld2w_z_p_br_contiguous";
		case ENC_LD3B_Z_P_BI_CONTIGUOUS: return "ld3b_z_p_bi_contiguous";
		case ENC_LD3B_Z_P_BR_CONTIGUOUS: return "ld3b_z_p_br_contiguous";
		case ENC_LD3D_Z_P_BI_CONTIGUOUS: return "ld3d_z_p_bi_contiguous";
		case ENC_LD3D_Z_P_BR_CONTIGUOUS: return "ld3d_z_p_br_contiguous";
		case ENC_LD3H_Z_P_BI_CONTIGUOUS: return "ld3h_z_p_bi_contiguous";
		case ENC_LD3H_Z_P_BR_CONTIGUOUS: return "ld3h_z_p_br_contiguous";
		case ENC_LD3W_Z_P_BI_CONTIGUOUS: return "ld3w_z_p_bi_contiguous";
		case ENC_LD3W_Z_P_BR_CONTIGUOUS: return "ld3w_z_p_br_contiguous";
		case ENC_LD4B_Z_P_BI_CONTIGUOUS: return "ld4b_z_p_bi_contiguous";
		case ENC_LD4B_Z_P_BR_CONTIGUOUS: return "ld4b_z_p_br_contiguous";
		case ENC_LD4D_Z_P_BI_CONTIGUOUS: return "ld4d_z_p_bi_contiguous";
		case ENC_LD4D_Z_P_BR_CONTIGUOUS: return "ld4d_z_p_br_contiguous";
		case ENC_LD4H_Z_P_BI_CONTIGUOUS: return "ld4h_z_p_bi_contiguous";
		case ENC_LD4H_Z_P_BR_CONTIGUOUS: return "ld4h_z_p_br_contiguous";
		case ENC_LD4W_Z_P_BI_CONTIGUOUS: return "ld4w_z_p_bi_contiguous";
		case ENC_LD4W_Z_P_BR_CONTIGUOUS: return "ld4w_z_p_br_contiguous";
		case ENC_LDFF1B_Z_P_AI_D: return "ldff1b_z_p_ai_d";
		case ENC_LDFF1B_Z_P_AI_S: return "ldff1b_z_p_ai_s";
		case ENC_LDFF1B_Z_P_BR_U16: return "ldff1b_z_p_br_u16";
		case ENC_LDFF1B_Z_P_BR_U32: return "ldff1b_z_p_br_u32";
		case ENC_LDFF1B_Z_P_BR_U64: return "ldff1b_z_p_br_u64";
		case ENC_LDFF1B_Z_P_BR_U8: return "ldff1b_z_p_br_u8";
		case ENC_LDFF1B_Z_P_BZ_D_64_UNSCALED: return "ldff1b_z_p_bz_d_64_unscaled";
		case ENC_LDFF1B_Z_P_BZ_D_X32_UNSCALED: return "ldff1b_z_p_bz_d_x32_unscaled";
		case ENC_LDFF1B_Z_P_BZ_S_X32_UNSCALED: return "ldff1b_z_p_bz_s_x32_unscaled";
		case ENC_LDFF1D_Z_P_AI_D: return "ldff1d_z_p_ai_d";
		case ENC_LDFF1D_Z_P_BR_U64: return "ldff1d_z_p_br_u64";
		case ENC_LDFF1D_Z_P_BZ_D_64_SCALED: return "ldff1d_z_p_bz_d_64_scaled";
		case ENC_LDFF1D_Z_P_BZ_D_64_UNSCALED: return "ldff1d_z_p_bz_d_64_unscaled";
		case ENC_LDFF1D_Z_P_BZ_D_X32_SCALED: return "ldff1d_z_p_bz_d_x32_scaled";
		case ENC_LDFF1D_Z_P_BZ_D_X32_UNSCALED: return "ldff1d_z_p_bz_d_x32_unscaled";
		case ENC_LDFF1H_Z_P_AI_D: return "ldff1h_z_p_ai_d";
		case ENC_LDFF1H_Z_P_AI_S: return "ldff1h_z_p_ai_s";
		case ENC_LDFF1H_Z_P_BR_U16: return "ldff1h_z_p_br_u16";
		case ENC_LDFF1H_Z_P_BR_U32: return "ldff1h_z_p_br_u32";
		case ENC_LDFF1H_Z_P_BR_U64: return "ldff1h_z_p_br_u64";
		case ENC_LDFF1H_Z_P_BZ_D_64_SCALED: return "ldff1h_z_p_bz_d_64_scaled";
		case ENC_LDFF1H_Z_P_BZ_D_64_UNSCALED: return "ldff1h_z_p_bz_d_64_unscaled";
		case ENC_LDFF1H_Z_P_BZ_D_X32_SCALED: return "ldff1h_z_p_bz_d_x32_scaled";
		case ENC_LDFF1H_Z_P_BZ_D_X32_UNSCALED: return "ldff1h_z_p_bz_d_x32_unscaled";
		case ENC_LDFF1H_Z_P_BZ_S_X32_SCALED: return "ldff1h_z_p_bz_s_x32_scaled";
		case ENC_LDFF1H_Z_P_BZ_S_X32_UNSCALED: return "ldff1h_z_p_bz_s_x32_unscaled";
		case ENC_LDFF1SB_Z_P_AI_D: return "ldff1sb_z_p_ai_d";
		case ENC_LDFF1SB_Z_P_AI_S: return "ldff1sb_z_p_ai_s";
		case ENC_LDFF1SB_Z_P_BR_S16: return "ldff1sb_z_p_br_s16";
		case ENC_LDFF1SB_Z_P_BR_S32: return "ldff1sb_z_p_br_s32";
		case ENC_LDFF1SB_Z_P_BR_S64: return "ldff1sb_z_p_br_s64";
		case ENC_LDFF1SB_Z_P_BZ_D_64_UNSCALED: return "ldff1sb_z_p_bz_d_64_unscaled";
		case ENC_LDFF1SB_Z_P_BZ_D_X32_UNSCALED: return "ldff1sb_z_p_bz_d_x32_unscaled";
		case ENC_LDFF1SB_Z_P_BZ_S_X32_UNSCALED: return "ldff1sb_z_p_bz_s_x32_unscaled";
		case ENC_LDFF1SH_Z_P_AI_D: return "ldff1sh_z_p_ai_d";
		case ENC_LDFF1SH_Z_P_AI_S: return "ldff1sh_z_p_ai_s";
		case ENC_LDFF1SH_Z_P_BR_S32: return "ldff1sh_z_p_br_s32";
		case ENC_LDFF1SH_Z_P_BR_S64: return "ldff1sh_z_p_br_s64";
		case ENC_LDFF1SH_Z_P_BZ_D_64_SCALED: return "ldff1sh_z_p_bz_d_64_scaled";
		case ENC_LDFF1SH_Z_P_BZ_D_64_UNSCALED: return "ldff1sh_z_p_bz_d_64_unscaled";
		case ENC_LDFF1SH_Z_P_BZ_D_X32_SCALED: return "ldff1sh_z_p_bz_d_x32_scaled";
		case ENC_LDFF1SH_Z_P_BZ_D_X32_UNSCALED: return "ldff1sh_z_p_bz_d_x32_unscaled";
		case ENC_LDFF1SH_Z_P_BZ_S_X32_SCALED: return "ldff1sh_z_p_bz_s_x32_scaled";
		case ENC_LDFF1SH_Z_P_BZ_S_X32_UNSCALED: return "ldff1sh_z_p_bz_s_x32_unscaled";
		case ENC_LDFF1SW_Z_P_AI_D: return "ldff1sw_z_p_ai_d";
		case ENC_LDFF1SW_Z_P_BR_S64: return "ldff1sw_z_p_br_s64";
		case ENC_LDFF1SW_Z_P_BZ_D_64_SCALED: return "ldff1sw_z_p_bz_d_64_scaled";
		case ENC_LDFF1SW_Z_P_BZ_D_64_UNSCALED: return "ldff1sw_z_p_bz_d_64_unscaled";
		case ENC_LDFF1SW_Z_P_BZ_D_X32_SCALED: return "ldff1sw_z_p_bz_d_x32_scaled";
		case ENC_LDFF1SW_Z_P_BZ_D_X32_UNSCALED: return "ldff1sw_z_p_bz_d_x32_unscaled";
		case ENC_LDFF1W_Z_P_AI_D: return "ldff1w_z_p_ai_d";
		case ENC_LDFF1W_Z_P_AI_S: return "ldff1w_z_p_ai_s";
		case ENC_LDFF1W_Z_P_BR_U32: return "ldff1w_z_p_br_u32";
		case ENC_LDFF1W_Z_P_BR_U64: return "ldff1w_z_p_br_u64";
		case ENC_LDFF1W_Z_P_BZ_D_64_SCALED: return "ldff1w_z_p_bz_d_64_scaled";
		case ENC_LDFF1W_Z_P_BZ_D_64_UNSCALED: return "ldff1w_z_p_bz_d_64_unscaled";
		case ENC_LDFF1W_Z_P_BZ_D_X32_SCALED: return "ldff1w_z_p_bz_d_x32_scaled";
		case ENC_LDFF1W_Z_P_BZ_D_X32_UNSCALED: return "ldff1w_z_p_bz_d_x32_unscaled";
		case ENC_LDFF1W_Z_P_BZ_S_X32_SCALED: return "ldff1w_z_p_bz_s_x32_scaled";
		case ENC_LDFF1W_Z_P_BZ_S_X32_UNSCALED: return "ldff1w_z_p_bz_s_x32_unscaled";
		case ENC_LDNF1B_Z_P_BI_U16: return "ldnf1b_z_p_bi_u16";
		case ENC_LDNF1B_Z_P_BI_U32: return "ldnf1b_z_p_bi_u32";
		case ENC_LDNF1B_Z_P_BI_U64: return "ldnf1b_z_p_bi_u64";
		case ENC_LDNF1B_Z_P_BI_U8: return "ldnf1b_z_p_bi_u8";
		case ENC_LDNF1D_Z_P_BI_U64: return "ldnf1d_z_p_bi_u64";
		case ENC_LDNF1H_Z_P_BI_U16: return "ldnf1h_z_p_bi_u16";
		case ENC_LDNF1H_Z_P_BI_U32: return "ldnf1h_z_p_bi_u32";
		case ENC_LDNF1H_Z_P_BI_U64: return "ldnf1h_z_p_bi_u64";
		case ENC_LDNF1SB_Z_P_BI_S16: return "ldnf1sb_z_p_bi_s16";
		case ENC_LDNF1SB_Z_P_BI_S32: return "ldnf1sb_z_p_bi_s32";
		case ENC_LDNF1SB_Z_P_BI_S64: return "ldnf1sb_z_p_bi_s64";
		case ENC_LDNF1SH_Z_P_BI_S32: return "ldnf1sh_z_p_bi_s32";
		case ENC_LDNF1SH_Z_P_BI_S64: return "ldnf1sh_z_p_bi_s64";
		case ENC_LDNF1SW_Z_P_BI_S64: return "ldnf1sw_z_p_bi_s64";
		case ENC_LDNF1W_Z_P_BI_U32: return "ldnf1w_z_p_bi_u32";
		case ENC_LDNF1W_Z_P_BI_U64: return "ldnf1w_z_p_bi_u64";
		case ENC_LDNT1B_Z_P_BI_CONTIGUOUS: return "ldnt1b_z_p_bi_contiguous";
		case ENC_LDNT1B_Z_P_BR_CONTIGUOUS: return "ldnt1b_z_p_br_contiguous";
		case ENC_LDNT1D_Z_P_BI_CONTIGUOUS: return "ldnt1d_z_p_bi_contiguous";
		case ENC_LDNT1D_Z_P_BR_CONTIGUOUS: return "ldnt1d_z_p_br_contiguous";
		case ENC_LDNT1H_Z_P_BI_CONTIGUOUS: return "ldnt1h_z_p_bi_contiguous";
		case ENC_LDNT1H_Z_P_BR_CONTIGUOUS: return "ldnt1h_z_p_br_contiguous";
		case ENC_LDNT1W_Z_P_BI_CONTIGUOUS: return "ldnt1w_z_p_bi_contiguous";
		case ENC_LDNT1W_Z_P_BR_CONTIGUOUS: return "ldnt1w_z_p_br_contiguous";
		case ENC_LDR_P_BI_: return "ldr_p_bi_";
		case ENC_LDR_Z_BI_: return "ldr_z_bi_";
		case ENC_LSL_Z_P_ZI_: return "lsl_z_p_zi_";
		case ENC_LSL_Z_P_ZW_: return "lsl_z_p_zw_";
		case ENC_LSL_Z_P_ZZ_: return "lsl_z_p_zz_";
		case ENC_LSL_Z_ZI_: return "lsl_z_zi_";
		case ENC_LSL_Z_ZW_: return "lsl_z_zw_";
		case ENC_LSLR_Z_P_ZZ_: return "lslr_z_p_zz_";
		case ENC_LSR_Z_P_ZI_: return "lsr_z_p_zi_";
		case ENC_LSR_Z_P_ZW_: return "lsr_z_p_zw_";
		case ENC_LSR_Z_P_ZZ_: return "lsr_z_p_zz_";
		case ENC_LSR_Z_ZI_: return "lsr_z_zi_";
		case ENC_LSR_Z_ZW_: return "lsr_z_zw_";
		case ENC_LSRR_Z_P_ZZ_: return "lsrr_z_p_zz_";
		case ENC_MAD_Z_P_ZZZ_: return "mad_z_p_zzz_";
		case ENC_MLA_Z_P_ZZZ_: return "mla_z_p_zzz_";
		case ENC_MLS_Z_P_ZZZ_: return "mls_z_p_zzz_";
		case ENC_MOVPRFX_Z_P_Z_: return "movprfx_z_p_z_";
		case ENC_MOVPRFX_Z_Z_: return "movprfx_z_z_";
		case ENC_MSB_Z_P_ZZZ_: return "msb_z_p_zzz_";
		case ENC_MUL_Z_P_ZZ_: return "mul_z_p_zz_";
		case ENC_MUL_Z_ZI_: return "mul_z_zi_";
		case ENC_NAND_P_P_PP_Z: return "nand_p_p_pp_z";
		case ENC_NANDS_P_P_PP_Z: return "nands_p_p_pp_z";
		case ENC_NEG_Z_P_Z_: return "neg_z_p_z_";
		case ENC_NOR_P_P_PP_Z: return "nor_p_p_pp_z";
		case ENC_NORS_P_P_PP_Z: return "nors_p_p_pp_z";
		case ENC_NOT_Z_P_Z_: return "not_z_p_z_";
		case ENC_ORN_P_P_PP_Z: return "orn_p_p_pp_z";
		case ENC_ORNS_P_P_PP_Z: return "orns_p_p_pp_z";
		case ENC_ORR_P_P_PP_Z: return "orr_p_p_pp_z";
		case ENC_ORR_Z_P_ZZ_: return "orr_z_p_zz_";
		case ENC_ORR_Z_ZI_: return "orr_z_zi_";
		case ENC_ORR_Z_ZZ_: return "orr_z_zz_";
		case ENC_ORRS_P_P_PP_Z: return "orrs_p_p_pp_z";
		case ENC_ORV_R_P_Z_: return "orv_r_p_z_";
		case ENC_PFALSE_P_: return "pfalse_p_";
		case ENC_PFIRST_P_P_P_: return "pfirst_p_p_p_";
		case ENC_PNEXT_P_P_P_: return "pnext_p_p_p_";
		case ENC_PRFB_I_P_AI_D: return "prfb_i_p_ai_d";
		case ENC_PRFB_I_P_AI_S: return "prfb_i_p_ai_s";
		case ENC_PRFB_I_P_BI_S: return "prfb_i_p_bi_s";
		case ENC_PRFB_I_P_BR_S: return "prfb_i_p_br_s";
		case ENC_PRFB_I_P_BZ_D_64_SCALED: return "prfb_i_p_bz_d_64_scaled";
		case ENC_PRFB_I_P_BZ_D_X32_SCALED: return "prfb_i_p_bz_d_x32_scaled";
		case ENC_PRFB_I_P_BZ_S_X32_SCALED: return "prfb_i_p_bz_s_x32_scaled";
		case ENC_PRFD_I_P_AI_D: return "prfd_i_p_ai_d";
		case ENC_PRFD_I_P_AI_S: return "prfd_i_p_ai_s";
		case ENC_PRFD_I_P_BI_S: return "prfd_i_p_bi_s";
		case ENC_PRFD_I_P_BR_S: return "prfd_i_p_br_s";
		case ENC_PRFD_I_P_BZ_D_64_SCALED: return "prfd_i_p_bz_d_64_scaled";
		case ENC_PRFD_I_P_BZ_D_X32_SCALED: return "prfd_i_p_bz_d_x32_scaled";
		case ENC_PRFD_I_P_BZ_S_X32_SCALED: return "prfd_i_p_bz_s_x32_scaled";
		case ENC_PRFH_I_P_AI_D: return "prfh_i_p_ai_d";
		case ENC_PRFH_I_P_AI_S: return "prfh_i_p_ai_s";
		case ENC_PRFH_I_P_BI_S: return "prfh_i_p_bi_s";
		case ENC_PRFH_I_P_BR_S: return "prfh_i_p_br_s";
		case ENC_PRFH_I_P_BZ_D_64_SCALED: return "prfh_i_p_bz_d_64_scaled";
		case ENC_PRFH_I_P_BZ_D_X32_SCALED: return "prfh_i_p_bz_d_x32_scaled";
		case ENC_PRFH_I_P_BZ_S_X32_SCALED: return "prfh_i_p_bz_s_x32_scaled";
		case ENC_PRFW_I_P_AI_D: return "prfw_i_p_ai_d";
		case ENC_PRFW_I_P_AI_S: return "prfw_i_p_ai_s";
		case ENC_PRFW_I_P_BI_S: return "prfw_i_p_bi_s";
		case ENC_PRFW_I_P_BR_S: return "prfw_i_p_br_s";
		case ENC_PRFW_I_P_BZ_D_64_SCALED: return "prfw_i_p_bz_d_64_scaled";
		case ENC_PRFW_I_P_BZ_D_X32_SCALED: return "prfw_i_p_bz_d_x32_scaled";
		case ENC_PRFW_I_P_BZ_S_X32_SCALED: return "prfw_i_p_bz_s_x32_scaled";
		case ENC_PTEST_P_P_: return "ptest_p_p_";
		case ENC_PTRUE_P_S_: return "ptrue_p_s_";
		case ENC_PTRUES_P_S_: return "ptrues_p_s_";
		case ENC_PUNPKHI_P_P_: return "punpkhi_p_p_";
		case ENC_PUNPKLO_P_P_: return "punpklo_p_p_";
		case ENC_RBIT_Z_P_Z_: return "rbit_z_p_z_";
		case ENC_RDFFR_P_F_: return "rdffr_p_f_";
		case ENC_RDFFR_P_P_F_: return "rdffr_p_p_f_";
		case ENC_RDFFRS_P_P_F_: return "rdffrs_p_p_f_";
		case ENC_RDVL_R_I_: return "rdvl_r_i_";
		case ENC_REV_P_P_: return "rev_p_p_";
		case ENC_REV_Z_Z_: return "rev_z_z_";
		case ENC_REVB_Z_Z_: return "revb_z_z_";
		case ENC_REVH_Z_Z_: return "revh_z_z_";
		case ENC_REVW_Z_Z_: return "revw_z_z_";
		case ENC_SABD_Z_P_ZZ_: return "sabd_z_p_zz_";
		case ENC_SADDV_R_P_Z_: return "saddv_r_p_z_";
		case ENC_SCVTF_Z_P_Z_H2FP16: return "scvtf_z_p_z_h2fp16";
		case ENC_SCVTF_Z_P_Z_W2D: return "scvtf_z_p_z_w2d";
		case ENC_SCVTF_Z_P_Z_W2FP16: return "scvtf_z_p_z_w2fp16";
		case ENC_SCVTF_Z_P_Z_W2S: return "scvtf_z_p_z_w2s";
		case ENC_SCVTF_Z_P_Z_X2D: return "scvtf_z_p_z_x2d";
		case ENC_SCVTF_Z_P_Z_X2FP16: return "scvtf_z_p_z_x2fp16";
		case ENC_SCVTF_Z_P_Z_X2S: return "scvtf_z_p_z_x2s";
		case ENC_SDIV_Z_P_ZZ_: return "sdiv_z_p_zz_";
		case ENC_SDIVR_Z_P_ZZ_: return "sdivr_z_p_zz_";
		case ENC_SDOT_Z_ZZZ_: return "sdot_z_zzz_";
		case ENC_SDOT_Z_ZZZI_D: return "sdot_z_zzzi_d";
		case ENC_SDOT_Z_ZZZI_S: return "sdot_z_zzzi_s";
		case ENC_SEL_P_P_PP_: return "sel_p_p_pp_";
		case ENC_SEL_Z_P_ZZ_: return "sel_z_p_zz_";
		case ENC_SETFFR_F_: return "setffr_f_";
		case ENC_SMAX_Z_P_ZZ_: return "smax_z_p_zz_";
		case ENC_SMAX_Z_ZI_: return "smax_z_zi_";
		case ENC_SMAXV_R_P_Z_: return "smaxv_r_p_z_";
		case ENC_SMIN_Z_P_ZZ_: return "smin_z_p_zz_";
		case ENC_SMIN_Z_ZI_: return "smin_z_zi_";
		case ENC_SMINV_R_P_Z_: return "sminv_r_p_z_";
		case ENC_SMMLA_Z_ZZZ_: return "smmla_z_zzz_";
		case ENC_SMULH_Z_P_ZZ_: return "smulh_z_p_zz_";
		case ENC_SPLICE_Z_P_ZZ_DES: return "splice_z_p_zz_des";
		case ENC_SQADD_Z_ZI_: return "sqadd_z_zi_";
		case ENC_SQADD_Z_ZZ_: return "sqadd_z_zz_";
		case ENC_SQDECB_R_RS_SX: return "sqdecb_r_rs_sx";
		case ENC_SQDECB_R_RS_X: return "sqdecb_r_rs_x";
		case ENC_SQDECD_R_RS_SX: return "sqdecd_r_rs_sx";
		case ENC_SQDECD_R_RS_X: return "sqdecd_r_rs_x";
		case ENC_SQDECD_Z_ZS_: return "sqdecd_z_zs_";
		case ENC_SQDECH_R_RS_SX: return "sqdech_r_rs_sx";
		case ENC_SQDECH_R_RS_X: return "sqdech_r_rs_x";
		case ENC_SQDECH_Z_ZS_: return "sqdech_z_zs_";
		case ENC_SQDECP_R_P_R_SX: return "sqdecp_r_p_r_sx";
		case ENC_SQDECP_R_P_R_X: return "sqdecp_r_p_r_x";
		case ENC_SQDECP_Z_P_Z_: return "sqdecp_z_p_z_";
		case ENC_SQDECW_R_RS_SX: return "sqdecw_r_rs_sx";
		case ENC_SQDECW_R_RS_X: return "sqdecw_r_rs_x";
		case ENC_SQDECW_Z_ZS_: return "sqdecw_z_zs_";
		case ENC_SQINCB_R_RS_SX: return "sqincb_r_rs_sx";
		case ENC_SQINCB_R_RS_X: return "sqincb_r_rs_x";
		case ENC_SQINCD_R_RS_SX: return "sqincd_r_rs_sx";
		case ENC_SQINCD_R_RS_X: return "sqincd_r_rs_x";
		case ENC_SQINCD_Z_ZS_: return "sqincd_z_zs_";
		case ENC_SQINCH_R_RS_SX: return "sqinch_r_rs_sx";
		case ENC_SQINCH_R_RS_X: return "sqinch_r_rs_x";
		case ENC_SQINCH_Z_ZS_: return "sqinch_z_zs_";
		case ENC_SQINCP_R_P_R_SX: return "sqincp_r_p_r_sx";
		case ENC_SQINCP_R_P_R_X: return "sqincp_r_p_r_x";
		case ENC_SQINCP_Z_P_Z_: return "sqincp_z_p_z_";
		case ENC_SQINCW_R_RS_SX: return "sqincw_r_rs_sx";
		case ENC_SQINCW_R_RS_X: return "sqincw_r_rs_x";
		case ENC_SQINCW_Z_ZS_: return "sqincw_z_zs_";
		case ENC_SQSUB_Z_ZI_: return "sqsub_z_zi_";
		case ENC_SQSUB_Z_ZZ_: return "sqsub_z_zz_";
		case ENC_ST1B_Z_P_AI_D: return "st1b_z_p_ai_d";
		case ENC_ST1B_Z_P_AI_S: return "st1b_z_p_ai_s";
		case ENC_ST1B_Z_P_BI_: return "st1b_z_p_bi_";
		case ENC_ST1B_Z_P_BR_: return "st1b_z_p_br_";
		case ENC_ST1B_Z_P_BZ_D_64_UNSCALED: return "st1b_z_p_bz_d_64_unscaled";
		case ENC_ST1B_Z_P_BZ_D_X32_UNSCALED: return "st1b_z_p_bz_d_x32_unscaled";
		case ENC_ST1B_Z_P_BZ_S_X32_UNSCALED: return "st1b_z_p_bz_s_x32_unscaled";
		case ENC_ST1D_Z_P_AI_D: return "st1d_z_p_ai_d";
		case ENC_ST1D_Z_P_BI_: return "st1d_z_p_bi_";
		case ENC_ST1D_Z_P_BR_: return "st1d_z_p_br_";
		case ENC_ST1D_Z_P_BZ_D_64_SCALED: return "st1d_z_p_bz_d_64_scaled";
		case ENC_ST1D_Z_P_BZ_D_64_UNSCALED: return "st1d_z_p_bz_d_64_unscaled";
		case ENC_ST1D_Z_P_BZ_D_X32_SCALED: return "st1d_z_p_bz_d_x32_scaled";
		case ENC_ST1D_Z_P_BZ_D_X32_UNSCALED: return "st1d_z_p_bz_d_x32_unscaled";
		case ENC_ST1H_Z_P_AI_D: return "st1h_z_p_ai_d";
		case ENC_ST1H_Z_P_AI_S: return "st1h_z_p_ai_s";
		case ENC_ST1H_Z_P_BI_: return "st1h_z_p_bi_";
		case ENC_ST1H_Z_P_BR_: return "st1h_z_p_br_";
		case ENC_ST1H_Z_P_BZ_D_64_SCALED: return "st1h_z_p_bz_d_64_scaled";
		case ENC_ST1H_Z_P_BZ_D_64_UNSCALED: return "st1h_z_p_bz_d_64_unscaled";
		case ENC_ST1H_Z_P_BZ_D_X32_SCALED: return "st1h_z_p_bz_d_x32_scaled";
		case ENC_ST1H_Z_P_BZ_D_X32_UNSCALED: return "st1h_z_p_bz_d_x32_unscaled";
		case ENC_ST1H_Z_P_BZ_S_X32_SCALED: return "st1h_z_p_bz_s_x32_scaled";
		case ENC_ST1H_Z_P_BZ_S_X32_UNSCALED: return "st1h_z_p_bz_s_x32_unscaled";
		case ENC_ST1W_Z_P_AI_D: return "st1w_z_p_ai_d";
		case ENC_ST1W_Z_P_AI_S: return "st1w_z_p_ai_s";
		case ENC_ST1W_Z_P_BI_: return "st1w_z_p_bi_";
		case ENC_ST1W_Z_P_BR_: return "st1w_z_p_br_";
		case ENC_ST1W_Z_P_BZ_D_64_SCALED: return "st1w_z_p_bz_d_64_scaled";
		case ENC_ST1W_Z_P_BZ_D_64_UNSCALED: return "st1w_z_p_bz_d_64_unscaled";
		case ENC_ST1W_Z_P_BZ_D_X32_SCALED: return "st1w_z_p_bz_d_x32_scaled";
		case ENC_ST1W_Z_P_BZ_D_X32_UNSCALED: return "st1w_z_p_bz_d_x32_unscaled";
		case ENC_ST1W_Z_P_BZ_S_X32_SCALED: return "st1w_z_p_bz_s_x32_scaled";
		case ENC_ST1W_Z_P_BZ_S_X32_UNSCALED: return "st1w_z_p_bz_s_x32_unscaled";
		case ENC_ST2B_Z_P_BI_CONTIGUOUS: return "st2b_z_p_bi_contiguous";
		case ENC_ST2B_Z_P_BR_CONTIGUOUS: return "st2b_z_p_br_contiguous";
		case ENC_ST2D_Z_P_BI_CONTIGUOUS: return "st2d_z_p_bi_contiguous";
		case ENC_ST2D_Z_P_BR_CONTIGUOUS: return "st2d_z_p_br_contiguous";
		case ENC_ST2H_Z_P_BI_CONTIGUOUS: return "st2h_z_p_bi_contiguous";
		case ENC_ST2H_Z_P_BR_CONTIGUOUS: return "st2h_z_p_br_contiguous";
		case ENC_ST2W_Z_P_BI_CONTIGUOUS: return "st2w_z_p_bi_contiguous";
		case ENC_ST2W_Z_P_BR_CONTIGUOUS: return "st2w_z_p_br_contiguous";
		case ENC_ST3B_Z_P_BI_CONTIGUOUS: return "st3b_z_p_bi_contiguous";
		case ENC_ST3B_Z_P_BR_CONTIGUOUS: return "st3b_z_p_br_contiguous";
		case ENC_ST3D_Z_P_BI_CONTIGUOUS: return "st3d_z_p_bi_contiguous";
		case ENC_ST3D_Z_P_BR_CONTIGUOUS: return "st3d_z_p_br_contiguous";
		case ENC_ST3H_Z_P_BI_CONTIGUOUS: return "st3h_z_p_bi_contiguous";
		case ENC_ST3H_Z_P_BR_CONTIGUOUS: return "st3h_z_p_br_contiguous";
		case ENC_ST3W_Z_P_BI_CONTIGUOUS: return "st3w_z_p_bi_contiguous";
		case ENC_ST3W_Z_P_BR_CONTIGUOUS: return "st3w_z_p_br_contiguous";
		case ENC_ST4B_Z_P_BI_CONTIGUOUS: return "st4b_z_p_bi_contiguous";
		case ENC_ST4B_Z_P_BR_CONTIGUOUS: return "st4b_z_p_br_contiguous";
		case ENC_ST4D_Z_P_BI_CONTIGUOUS: return "st4d_z_p_bi_contiguous";
		case ENC_ST4D_Z_P_BR_CONTIGUOUS: return "st4d_z_p_br_contiguous";
		case ENC_ST4H_Z_P_BI_CONTIGUOUS: return "st4h_z_p_bi_contiguous";
		case ENC_ST4H_Z_P_BR_CONTIGUOUS: return "st4h_z_p_br_contiguous";
		case ENC_ST4W_Z_P_BI_CONTIGUOUS: return "st4w_z_p_bi_contiguous";
		case ENC_ST4W_Z_P_BR_CONTIGUOUS: return "st4w_z_p_br_contiguous";
		case ENC_STNT1B_Z_P_BI_CONTIGUOUS: return "stnt1b_z_p_bi_contiguous";
		case ENC_STNT1B_Z_P_BR_CONTIGUOUS: return "stnt1b_z_p_br_contiguous";
		case ENC_STNT1D_Z_P_BI_CONTIGUOUS: return "stnt1d_z_p_bi_contiguous";
		case ENC_STNT1D_Z_P_BR_CONTIGUOUS: return "stnt1d_z_p_br_contiguous";
		case ENC_STNT1H_Z_P_BI_CONTIGUOUS: return "stnt1h_z_p_bi_contiguous";
		case ENC_STNT1H_Z_P_BR_CONTIGUOUS: return "stnt1h_z_p_br_contiguous";
		case ENC_STNT1W_Z_P_BI_CONTIGUOUS: return "stnt1w_z_p_bi_contiguous";
		case ENC_STNT1W_Z_P_BR_CONTIGUOUS: return "stnt1w_z_p_br_contiguous";
		case ENC_STR_P_BI_: return "str_p_bi_";
		case ENC_STR_Z_BI_: return "str_z_bi_";
		case ENC_SUB_Z_P_ZZ_: return "sub_z_p_zz_";
		case ENC_SUB_Z_ZI_: return "sub_z_zi_";
		case ENC_SUB_Z_ZZ_: return "sub_z_zz_";
		case ENC_SUBR_Z_P_ZZ_: return "subr_z_p_zz_";
		case ENC_SUBR_Z_ZI_: return "subr_z_zi_";
		case ENC_SUDOT_Z_ZZZI_S: return "sudot_z_zzzi_s";
		case ENC_SUNPKHI_Z_Z_: return "sunpkhi_z_z_";
		case ENC_SUNPKLO_Z_Z_: return "sunpklo_z_z_";
		case ENC_SXTB_Z_P_Z_: return "sxtb_z_p_z_";
		case ENC_SXTH_Z_P_Z_: return "sxth_z_p_z_";
		case ENC_SXTW_Z_P_Z_: return "sxtw_z_p_z_";
		case ENC_TBL_Z_ZZ_1: return "tbl_z_zz_1";
		case ENC_TRN1_P_PP_: return "trn1_p_pp_";
		case ENC_TRN1_Z_ZZ_: return "trn1_z_zz_";
		case ENC_TRN1_Z_ZZ_Q: return "trn1_z_zz_q";
		case ENC_TRN2_P_PP_: return "trn2_p_pp_";
		case ENC_TRN2_Z_ZZ_: return "trn2_z_zz_";
		case ENC_TRN2_Z_ZZ_Q: return "trn2_z_zz_q";
		case ENC_UABD_Z_P_ZZ_: return "uabd_z_p_zz_";
		case ENC_UADDV_R_P_Z_: return "uaddv_r_p_z_";
		case ENC_UCVTF_Z_P_Z_H2FP16: return "ucvtf_z_p_z_h2fp16";
		case ENC_UCVTF_Z_P_Z_W2D: return "ucvtf_z_p_z_w2d";
		case ENC_UCVTF_Z_P_Z_W2FP16: return "ucvtf_z_p_z_w2fp16";
		case ENC_UCVTF_Z_P_Z_W2S: return "ucvtf_z_p_z_w2s";
		case ENC_UCVTF_Z_P_Z_X2D: return "ucvtf_z_p_z_x2d";
		case ENC_UCVTF_Z_P_Z_X2FP16: return "ucvtf_z_p_z_x2fp16";
		case ENC_UCVTF_Z_P_Z_X2S: return "ucvtf_z_p_z_x2s";
		case ENC_UDIV_Z_P_ZZ_: return "udiv_z_p_zz_";
		case ENC_UDIVR_Z_P_ZZ_: return "udivr_z_p_zz_";
		case ENC_UDOT_Z_ZZZ_: return "udot_z_zzz_";
		case ENC_UDOT_Z_ZZZI_D: return "udot_z_zzzi_d";
		case ENC_UDOT_Z_ZZZI_S: return "udot_z_zzzi_s";
		case ENC_UMAX_Z_P_ZZ_: return "umax_z_p_zz_";
		case ENC_UMAX_Z_ZI_: return "umax_z_zi_";
		case ENC_UMAXV_R_P_Z_: return "umaxv_r_p_z_";
		case ENC_UMIN_Z_P_ZZ_: return "umin_z_p_zz_";
		case ENC_UMIN_Z_ZI_: return "umin_z_zi_";
		case ENC_UMINV_R_P_Z_: return "uminv_r_p_z_";
		case ENC_UMMLA_Z_ZZZ_: return "ummla_z_zzz_";
		case ENC_UMULH_Z_P_ZZ_: return "umulh_z_p_zz_";
		case ENC_UQADD_Z_ZI_: return "uqadd_z_zi_";
		case ENC_UQADD_Z_ZZ_: return "uqadd_z_zz_";
		case ENC_UQDECB_R_RS_UW: return "uqdecb_r_rs_uw";
		case ENC_UQDECB_R_RS_X: return "uqdecb_r_rs_x";
		case ENC_UQDECD_R_RS_UW: return "uqdecd_r_rs_uw";
		case ENC_UQDECD_R_RS_X: return "uqdecd_r_rs_x";
		case ENC_UQDECD_Z_ZS_: return "uqdecd_z_zs_";
		case ENC_UQDECH_R_RS_UW: return "uqdech_r_rs_uw";
		case ENC_UQDECH_R_RS_X: return "uqdech_r_rs_x";
		case ENC_UQDECH_Z_ZS_: return "uqdech_z_zs_";
		case ENC_UQDECP_R_P_R_UW: return "uqdecp_r_p_r_uw";
		case ENC_UQDECP_R_P_R_X: return "uqdecp_r_p_r_x";
		case ENC_UQDECP_Z_P_Z_: return "uqdecp_z_p_z_";
		case ENC_UQDECW_R_RS_UW: return "uqdecw_r_rs_uw";
		case ENC_UQDECW_R_RS_X: return "uqdecw_r_rs_x";
		case ENC_UQDECW_Z_ZS_: return "uqdecw_z_zs_";
		case ENC_UQINCB_R_RS_UW: return "uqincb_r_rs_uw";
		case ENC_UQINCB_R_RS_X: return "uqincb_r_rs_x";
		case ENC_UQINCD_R_RS_UW: return "uqincd_r_rs_uw";
		case ENC_UQINCD_R_RS_X: return "uqincd_r_rs_x";
		case ENC_UQINCD_Z_ZS_: return "uqincd_z_zs_";
		case ENC_UQINCH_R_RS_UW: return "uqinch_r_rs_uw";
		case ENC_UQINCH_R_RS_X: return "uqinch_r_rs_x";
		case ENC_UQINCH_Z_ZS_: return "uqinch_z_zs_";
		case ENC_UQINCP_R_P_R_UW: return "uqincp_r_p_r_uw";
		case ENC_UQINCP_R_P_R_X: return "uqincp_r_p_r_x";
		case ENC_UQINCP_Z_P_Z_: return "uqincp_z_p_z_";
		case ENC_UQINCW_R_RS_UW: return "uqincw_r_rs_uw";
		case ENC_UQINCW_R_RS_X: return "uqincw_r_rs_x";
		case ENC_UQINCW_Z_ZS_: return "uqincw_z_zs_";
		case ENC_UQSUB_Z_ZI_: return "uqsub_z_zi_";
		case ENC_UQSUB_Z_ZZ_: return "uqsub_z_zz_";
		case ENC_USDOT_Z_ZZZ_S: return "usdot_z_zzz_s";
		case ENC_USDOT_Z_ZZZI_S: return "usdot_z_zzzi_s";
		case ENC_USMMLA_Z_ZZZ_: return "usmmla_z_zzz_";
		case ENC_UUNPKHI_Z_Z_: return "uunpkhi_z_z_";
		case ENC_UUNPKLO_Z_Z_: return "uunpklo_z_z_";
		case ENC_UXTB_Z_P_Z_: return "uxtb_z_p_z_";
		case ENC_UXTH_Z_P_Z_: return "uxth_z_p_z_";
		case ENC_UXTW_Z_P_Z_: return "uxtw_z_p_z_";
		case ENC_UZP1_P_PP_: return "uzp1_p_pp_";
		case ENC_UZP1_Z_ZZ_: return "uzp1_z_zz_";
		case ENC_UZP1_Z_ZZ_Q: return "uzp1_z_zz_q";
		case ENC_UZP2_P_PP_: return "uzp2_p_pp_";
		case ENC_UZP2_Z_ZZ_: return "uzp2_z_zz_";
		case ENC_UZP2_Z_ZZ_Q: return "uzp2_z_zz_q";
		case ENC_WHILELE_P_P_RR_: return "whilele_p_p_rr_";
		case ENC_WHILELO_P_P_RR_: return "whilelo_p_p_rr_";
		case ENC_WHILELS_P_P_RR_: return "whilels_p_p_rr_";
		case ENC_WHILELT_P_P_RR_: return "whilelt_p_p_rr_";
		case ENC_WRFFR_F_P_: return "wrffr_f_p_";
		case ENC_ZIP1_P_PP_: return "zip1_p_pp_";
		case ENC_ZIP1_Z_ZZ_: return "zip1_z_zz_";
		case ENC_ZIP1_Z_ZZ_Q: return "zip1_z_zz_q";
		case ENC_ZIP2_P_PP_: return "zip2_p_pp_";
		case ENC_ZIP2_Z_ZZ_: return "zip2_z_zz_";
		case ENC_ZIP2_Z_ZZ_Q: return "zip2_z_zz_q";
		default: return "error";
	}
}

const char *enc_to_xml(enum ENCODING enc)
{
	switch(enc) {
		case ENC_ABS_ASIMDMISC_R: return "abs_advsimd.xml";
		case ENC_ABS_ASISDMISC_R: return "abs_advsimd.xml";
		case ENC_ADCS_32_ADDSUB_CARRY: return "adcs.xml";
		case ENC_ADCS_64_ADDSUB_CARRY: return "adcs.xml";
		case ENC_ADC_32_ADDSUB_CARRY: return "adc.xml";
		case ENC_ADC_64_ADDSUB_CARRY: return "adc.xml";
		case ENC_ADDG_64_ADDSUB_IMMTAGS: return "addg.xml";
		case ENC_ADDHN_ASIMDDIFF_N: return "addhn_advsimd.xml";
		case ENC_ADDP_ASIMDSAME_ONLY: return "addp_advsimd_vec.xml";
		case ENC_ADDP_ASISDPAIR_ONLY: return "addp_advsimd_pair.xml";
		case ENC_ADDS_32S_ADDSUB_EXT: return "adds_addsub_ext.xml";
		case ENC_ADDS_32S_ADDSUB_IMM: return "adds_addsub_imm.xml";
		case ENC_ADDS_32_ADDSUB_SHIFT: return "adds_addsub_shift.xml";
		case ENC_ADDS_64S_ADDSUB_EXT: return "adds_addsub_ext.xml";
		case ENC_ADDS_64S_ADDSUB_IMM: return "adds_addsub_imm.xml";
		case ENC_ADDS_64_ADDSUB_SHIFT: return "adds_addsub_shift.xml";
		case ENC_ADDV_ASIMDALL_ONLY: return "addv_advsimd.xml";
		case ENC_ADD_32_ADDSUB_EXT: return "add_addsub_ext.xml";
		case ENC_ADD_32_ADDSUB_IMM: return "add_addsub_imm.xml";
		case ENC_ADD_32_ADDSUB_SHIFT: return "add_addsub_shift.xml";
		case ENC_ADD_64_ADDSUB_EXT: return "add_addsub_ext.xml";
		case ENC_ADD_64_ADDSUB_IMM: return "add_addsub_imm.xml";
		case ENC_ADD_64_ADDSUB_SHIFT: return "add_addsub_shift.xml";
		case ENC_ADD_ASIMDSAME_ONLY: return "add_advsimd.xml";
		case ENC_ADD_ASISDSAME_ONLY: return "add_advsimd.xml";
		case ENC_ADRP_ONLY_PCRELADDR: return "adrp.xml";
		case ENC_ADR_ONLY_PCRELADDR: return "adr.xml";
		case ENC_AESD_B_CRYPTOAES: return "aesd_advsimd.xml";
		case ENC_AESE_B_CRYPTOAES: return "aese_advsimd.xml";
		case ENC_AESIMC_B_CRYPTOAES: return "aesimc_advsimd.xml";
		case ENC_AESMC_B_CRYPTOAES: return "aesmc_advsimd.xml";
		case ENC_ANDS_32S_LOG_IMM: return "ands_log_imm.xml";
		case ENC_ANDS_32_LOG_SHIFT: return "ands_log_shift.xml";
		case ENC_ANDS_64S_LOG_IMM: return "ands_log_imm.xml";
		case ENC_ANDS_64_LOG_SHIFT: return "ands_log_shift.xml";
		case ENC_AND_32_LOG_IMM: return "and_log_imm.xml";
		case ENC_AND_32_LOG_SHIFT: return "and_log_shift.xml";
		case ENC_AND_64_LOG_IMM: return "and_log_imm.xml";
		case ENC_AND_64_LOG_SHIFT: return "and_log_shift.xml";
		case ENC_AND_ASIMDSAME_ONLY: return "and_advsimd.xml";
		case ENC_ASRV_32_DP_2SRC: return "asrv.xml";
		case ENC_ASRV_64_DP_2SRC: return "asrv.xml";
		case ENC_ASR_ASRV_32_DP_2SRC: return "asr_asrv.xml";
		case ENC_ASR_ASRV_64_DP_2SRC: return "asr_asrv.xml";
		case ENC_ASR_SBFM_32M_BITFIELD: return "asr_sbfm.xml";
		case ENC_ASR_SBFM_64M_BITFIELD: return "asr_sbfm.xml";
		case ENC_AT_SYS_CR_SYSTEMINSTRS: return "at_sys.xml";
		case ENC_AUTDA_64P_DP_1SRC: return "autda.xml";
		case ENC_AUTDB_64P_DP_1SRC: return "autdb.xml";
		case ENC_AUTDZA_64Z_DP_1SRC: return "autda.xml";
		case ENC_AUTDZB_64Z_DP_1SRC: return "autdb.xml";
		case ENC_AUTIA1716_HI_HINTS: return "autia.xml";
		case ENC_AUTIASP_HI_HINTS: return "autia.xml";
		case ENC_AUTIAZ_HI_HINTS: return "autia.xml";
		case ENC_AUTIA_64P_DP_1SRC: return "autia.xml";
		case ENC_AUTIB1716_HI_HINTS: return "autib.xml";
		case ENC_AUTIBSP_HI_HINTS: return "autib.xml";
		case ENC_AUTIBZ_HI_HINTS: return "autib.xml";
		case ENC_AUTIB_64P_DP_1SRC: return "autib.xml";
		case ENC_AUTIZA_64Z_DP_1SRC: return "autia.xml";
		case ENC_AUTIZB_64Z_DP_1SRC: return "autib.xml";
		case ENC_AXFLAG_M_PSTATE: return "axflag.xml";
		case ENC_BCAX_VVV16_CRYPTO4: return "bcax_advsimd.xml";
		case ENC_BFCVTN_ASIMDMISC_4S: return "bfcvtn_advsimd.xml";
		case ENC_BFCVT_BS_FLOATDP1: return "bfcvt_float.xml";
		case ENC_BFC_BFM_32M_BITFIELD: return "bfc_bfm.xml";
		case ENC_BFC_BFM_64M_BITFIELD: return "bfc_bfm.xml";
		case ENC_BFDOT_ASIMDELEM_E: return "bfdot_advsimd_elt.xml";
		case ENC_BFDOT_ASIMDSAME2_D: return "bfdot_advsimd_vec.xml";
		case ENC_BFI_BFM_32M_BITFIELD: return "bfi_bfm.xml";
		case ENC_BFI_BFM_64M_BITFIELD: return "bfi_bfm.xml";
		case ENC_BFMLAL_ASIMDELEM_F: return "bfmlal_advsimd_elt.xml";
		case ENC_BFMLAL_ASIMDSAME2_F_: return "bfmlal_advsimd_vec.xml";
		case ENC_BFMMLA_ASIMDSAME2_E: return "bfmmla_advsimd.xml";
		case ENC_BFM_32M_BITFIELD: return "bfm.xml";
		case ENC_BFM_64M_BITFIELD: return "bfm.xml";
		case ENC_BFXIL_BFM_32M_BITFIELD: return "bfxil_bfm.xml";
		case ENC_BFXIL_BFM_64M_BITFIELD: return "bfxil_bfm.xml";
		case ENC_BICS_32_LOG_SHIFT: return "bics.xml";
		case ENC_BICS_64_LOG_SHIFT: return "bics.xml";
		case ENC_BIC_32_LOG_SHIFT: return "bic_log_shift.xml";
		case ENC_BIC_64_LOG_SHIFT: return "bic_log_shift.xml";
		case ENC_BIC_AND_Z_ZI_: return "bic_and_z_zi.xml";
		case ENC_BIC_ASIMDIMM_L_HL: return "bic_advsimd_imm.xml";
		case ENC_BIC_ASIMDIMM_L_SL: return "bic_advsimd_imm.xml";
		case ENC_BIC_ASIMDSAME_ONLY: return "bic_advsimd_reg.xml";
		case ENC_BIF_ASIMDSAME_ONLY: return "bif_advsimd.xml";
		case ENC_BIT_ASIMDSAME_ONLY: return "bit_advsimd.xml";
		case ENC_BLRAAZ_64_BRANCH_REG: return "blra.xml";
		case ENC_BLRAA_64P_BRANCH_REG: return "blra.xml";
		case ENC_BLRABZ_64_BRANCH_REG: return "blra.xml";
		case ENC_BLRAB_64P_BRANCH_REG: return "blra.xml";
		case ENC_BLR_64_BRANCH_REG: return "blr.xml";
		case ENC_BL_ONLY_BRANCH_IMM: return "bl.xml";
		case ENC_BRAAZ_64_BRANCH_REG: return "bra.xml";
		case ENC_BRAA_64P_BRANCH_REG: return "bra.xml";
		case ENC_BRABZ_64_BRANCH_REG: return "bra.xml";
		case ENC_BRAB_64P_BRANCH_REG: return "bra.xml";
		case ENC_BRK_EX_EXCEPTION: return "brk.xml";
		case ENC_BR_64_BRANCH_REG: return "br.xml";
		case ENC_BSL_ASIMDSAME_ONLY: return "bsl_advsimd.xml";
		case ENC_BTI_HB_HINTS: return "bti.xml";
		case ENC_B_ONLY_BRANCH_IMM: return "b_uncond.xml";
		case ENC_B_ONLY_CONDBRANCH: return "b_cond.xml";
		case ENC_CASAB_C32_LDSTEXCL: return "casb.xml";
		case ENC_CASAH_C32_LDSTEXCL: return "cash.xml";
		case ENC_CASALB_C32_LDSTEXCL: return "casb.xml";
		case ENC_CASALH_C32_LDSTEXCL: return "cash.xml";
		case ENC_CASAL_C32_LDSTEXCL: return "cas.xml";
		case ENC_CASAL_C64_LDSTEXCL: return "cas.xml";
		case ENC_CASA_C32_LDSTEXCL: return "cas.xml";
		case ENC_CASA_C64_LDSTEXCL: return "cas.xml";
		case ENC_CASB_C32_LDSTEXCL: return "casb.xml";
		case ENC_CASH_C32_LDSTEXCL: return "cash.xml";
		case ENC_CASLB_C32_LDSTEXCL: return "casb.xml";
		case ENC_CASLH_C32_LDSTEXCL: return "cash.xml";
		case ENC_CASL_C32_LDSTEXCL: return "cas.xml";
		case ENC_CASL_C64_LDSTEXCL: return "cas.xml";
		case ENC_CASPAL_CP32_LDSTEXCL: return "casp.xml";
		case ENC_CASPAL_CP64_LDSTEXCL: return "casp.xml";
		case ENC_CASPA_CP32_LDSTEXCL: return "casp.xml";
		case ENC_CASPA_CP64_LDSTEXCL: return "casp.xml";
		case ENC_CASPL_CP32_LDSTEXCL: return "casp.xml";
		case ENC_CASPL_CP64_LDSTEXCL: return "casp.xml";
		case ENC_CASP_CP32_LDSTEXCL: return "casp.xml";
		case ENC_CASP_CP64_LDSTEXCL: return "casp.xml";
		case ENC_CAS_C32_LDSTEXCL: return "cas.xml";
		case ENC_CAS_C64_LDSTEXCL: return "cas.xml";
		case ENC_CBNZ_32_COMPBRANCH: return "cbnz.xml";
		case ENC_CBNZ_64_COMPBRANCH: return "cbnz.xml";
		case ENC_CBZ_32_COMPBRANCH: return "cbz.xml";
		case ENC_CBZ_64_COMPBRANCH: return "cbz.xml";
		case ENC_CCMN_32_CONDCMP_IMM: return "ccmn_imm.xml";
		case ENC_CCMN_32_CONDCMP_REG: return "ccmn_reg.xml";
		case ENC_CCMN_64_CONDCMP_IMM: return "ccmn_imm.xml";
		case ENC_CCMN_64_CONDCMP_REG: return "ccmn_reg.xml";
		case ENC_CCMP_32_CONDCMP_IMM: return "ccmp_imm.xml";
		case ENC_CCMP_32_CONDCMP_REG: return "ccmp_reg.xml";
		case ENC_CCMP_64_CONDCMP_IMM: return "ccmp_imm.xml";
		case ENC_CCMP_64_CONDCMP_REG: return "ccmp_reg.xml";
		case ENC_CFINV_M_PSTATE: return "cfinv.xml";
		case ENC_CFP_SYS_CR_SYSTEMINSTRS: return "cfp_sys.xml";
		case ENC_CINC_CSINC_32_CONDSEL: return "cinc_csinc.xml";
		case ENC_CINC_CSINC_64_CONDSEL: return "cinc_csinc.xml";
		case ENC_CINV_CSINV_32_CONDSEL: return "cinv_csinv.xml";
		case ENC_CINV_CSINV_64_CONDSEL: return "cinv_csinv.xml";
		case ENC_CLREX_BN_BARRIERS: return "clrex.xml";
		case ENC_CLS_32_DP_1SRC: return "cls_int.xml";
		case ENC_CLS_64_DP_1SRC: return "cls_int.xml";
		case ENC_CLS_ASIMDMISC_R: return "cls_advsimd.xml";
		case ENC_CLZ_32_DP_1SRC: return "clz_int.xml";
		case ENC_CLZ_64_DP_1SRC: return "clz_int.xml";
		case ENC_CLZ_ASIMDMISC_R: return "clz_advsimd.xml";
		case ENC_CMEQ_ASIMDMISC_Z: return "cmeq_advsimd_zero.xml";
		case ENC_CMEQ_ASIMDSAME_ONLY: return "cmeq_advsimd_reg.xml";
		case ENC_CMEQ_ASISDMISC_Z: return "cmeq_advsimd_zero.xml";
		case ENC_CMEQ_ASISDSAME_ONLY: return "cmeq_advsimd_reg.xml";
		case ENC_CMGE_ASIMDMISC_Z: return "cmge_advsimd_zero.xml";
		case ENC_CMGE_ASIMDSAME_ONLY: return "cmge_advsimd_reg.xml";
		case ENC_CMGE_ASISDMISC_Z: return "cmge_advsimd_zero.xml";
		case ENC_CMGE_ASISDSAME_ONLY: return "cmge_advsimd_reg.xml";
		case ENC_CMGT_ASIMDMISC_Z: return "cmgt_advsimd_zero.xml";
		case ENC_CMGT_ASIMDSAME_ONLY: return "cmgt_advsimd_reg.xml";
		case ENC_CMGT_ASISDMISC_Z: return "cmgt_advsimd_zero.xml";
		case ENC_CMGT_ASISDSAME_ONLY: return "cmgt_advsimd_reg.xml";
		case ENC_CMHI_ASIMDSAME_ONLY: return "cmhi_advsimd.xml";
		case ENC_CMHI_ASISDSAME_ONLY: return "cmhi_advsimd.xml";
		case ENC_CMHS_ASIMDSAME_ONLY: return "cmhs_advsimd.xml";
		case ENC_CMHS_ASISDSAME_ONLY: return "cmhs_advsimd.xml";
		case ENC_CMLE_ASIMDMISC_Z: return "cmle_advsimd.xml";
		case ENC_CMLE_ASISDMISC_Z: return "cmle_advsimd.xml";
		case ENC_CMLT_ASIMDMISC_Z: return "cmlt_advsimd.xml";
		case ENC_CMLT_ASISDMISC_Z: return "cmlt_advsimd.xml";
		case ENC_CMN_ADDS_32S_ADDSUB_EXT: return "cmn_adds_addsub_ext.xml";
		case ENC_CMN_ADDS_32S_ADDSUB_IMM: return "cmn_adds_addsub_imm.xml";
		case ENC_CMN_ADDS_32_ADDSUB_SHIFT: return "cmn_adds_addsub_shift.xml";
		case ENC_CMN_ADDS_64S_ADDSUB_EXT: return "cmn_adds_addsub_ext.xml";
		case ENC_CMN_ADDS_64S_ADDSUB_IMM: return "cmn_adds_addsub_imm.xml";
		case ENC_CMN_ADDS_64_ADDSUB_SHIFT: return "cmn_adds_addsub_shift.xml";
		case ENC_CMPLE_CMPGE_P_P_ZZ_: return "cmple_cmpeq_p_p_zz.xml";
		case ENC_CMPLO_CMPHI_P_P_ZZ_: return "cmplo_cmpeq_p_p_zz.xml";
		case ENC_CMPLS_CMPHS_P_P_ZZ_: return "cmpls_cmpeq_p_p_zz.xml";
		case ENC_CMPLT_CMPGT_P_P_ZZ_: return "cmplt_cmpeq_p_p_zz.xml";
		case ENC_CMPP_SUBPS_64S_DP_2SRC: return "cmpp_subps.xml";
		case ENC_CMP_SUBS_32S_ADDSUB_EXT: return "cmp_subs_addsub_ext.xml";
		case ENC_CMP_SUBS_32S_ADDSUB_IMM: return "cmp_subs_addsub_imm.xml";
		case ENC_CMP_SUBS_32_ADDSUB_SHIFT: return "cmp_subs_addsub_shift.xml";
		case ENC_CMP_SUBS_64S_ADDSUB_EXT: return "cmp_subs_addsub_ext.xml";
		case ENC_CMP_SUBS_64S_ADDSUB_IMM: return "cmp_subs_addsub_imm.xml";
		case ENC_CMP_SUBS_64_ADDSUB_SHIFT: return "cmp_subs_addsub_shift.xml";
		case ENC_CMTST_ASIMDSAME_ONLY: return "cmtst_advsimd.xml";
		case ENC_CMTST_ASISDSAME_ONLY: return "cmtst_advsimd.xml";
		case ENC_CNEG_CSNEG_32_CONDSEL: return "cneg_csneg.xml";
		case ENC_CNEG_CSNEG_64_CONDSEL: return "cneg_csneg.xml";
		case ENC_CNT_ASIMDMISC_R: return "cnt_advsimd.xml";
		case ENC_CPP_SYS_CR_SYSTEMINSTRS: return "cpp_sys.xml";
		case ENC_CRC32B_32C_DP_2SRC: return "crc32.xml";
		case ENC_CRC32CB_32C_DP_2SRC: return "crc32c.xml";
		case ENC_CRC32CH_32C_DP_2SRC: return "crc32c.xml";
		case ENC_CRC32CW_32C_DP_2SRC: return "crc32c.xml";
		case ENC_CRC32CX_64C_DP_2SRC: return "crc32c.xml";
		case ENC_CRC32H_32C_DP_2SRC: return "crc32.xml";
		case ENC_CRC32W_32C_DP_2SRC: return "crc32.xml";
		case ENC_CRC32X_64C_DP_2SRC: return "crc32.xml";
		case ENC_CSDB_HI_HINTS: return "csdb.xml";
		case ENC_CSEL_32_CONDSEL: return "csel.xml";
		case ENC_CSEL_64_CONDSEL: return "csel.xml";
		case ENC_CSETM_CSINV_32_CONDSEL: return "csetm_csinv.xml";
		case ENC_CSETM_CSINV_64_CONDSEL: return "csetm_csinv.xml";
		case ENC_CSET_CSINC_32_CONDSEL: return "cset_csinc.xml";
		case ENC_CSET_CSINC_64_CONDSEL: return "cset_csinc.xml";
		case ENC_CSINC_32_CONDSEL: return "csinc.xml";
		case ENC_CSINC_64_CONDSEL: return "csinc.xml";
		case ENC_CSINV_32_CONDSEL: return "csinv.xml";
		case ENC_CSINV_64_CONDSEL: return "csinv.xml";
		case ENC_CSNEG_32_CONDSEL: return "csneg.xml";
		case ENC_CSNEG_64_CONDSEL: return "csneg.xml";
		case ENC_DCPS1_DC_EXCEPTION: return "dcps1.xml";
		case ENC_DCPS2_DC_EXCEPTION: return "dcps2.xml";
		case ENC_DCPS3_DC_EXCEPTION: return "dcps3.xml";
		case ENC_DC_SYS_CR_SYSTEMINSTRS: return "dc_sys.xml";
		case ENC_DGH_HI_HINTS: return "dgh.xml";
		case ENC_DMB_BO_BARRIERS: return "dmb.xml";
		case ENC_DRPS_64E_BRANCH_REG: return "drps.xml";
		case ENC_DSB_BO_BARRIERS: return "dsb.xml";
		case ENC_DUP_ASIMDINS_DR_R: return "dup_advsimd_gen.xml";
		case ENC_DUP_ASIMDINS_DV_V: return "dup_advsimd_elt.xml";
		case ENC_DUP_ASISDONE_ONLY: return "dup_advsimd_elt.xml";
		case ENC_DVP_SYS_CR_SYSTEMINSTRS: return "dvp_sys.xml";
		case ENC_EON_32_LOG_SHIFT: return "eon.xml";
		case ENC_EON_64_LOG_SHIFT: return "eon.xml";
		case ENC_EON_EOR_Z_ZI_: return "eon_eor_z_zi.xml";
		case ENC_EOR3_VVV16_CRYPTO4: return "eor3_advsimd.xml";
		case ENC_EOR_32_LOG_IMM: return "eor_log_imm.xml";
		case ENC_EOR_32_LOG_SHIFT: return "eor_log_shift.xml";
		case ENC_EOR_64_LOG_IMM: return "eor_log_imm.xml";
		case ENC_EOR_64_LOG_SHIFT: return "eor_log_shift.xml";
		case ENC_EOR_ASIMDSAME_ONLY: return "eor_advsimd.xml";
		case ENC_ERETAA_64E_BRANCH_REG: return "ereta.xml";
		case ENC_ERETAB_64E_BRANCH_REG: return "ereta.xml";
		case ENC_ERET_64E_BRANCH_REG: return "eret.xml";
		case ENC_ESB_HI_HINTS: return "esb.xml";
		case ENC_EXTR_32_EXTRACT: return "extr.xml";
		case ENC_EXTR_64_EXTRACT: return "extr.xml";
		case ENC_EXT_ASIMDEXT_ONLY: return "ext_advsimd.xml";
		case ENC_FABD_ASIMDSAME_ONLY: return "fabd_advsimd.xml";
		case ENC_FABD_ASIMDSAMEFP16_ONLY: return "fabd_advsimd.xml";
		case ENC_FABD_ASISDSAME_ONLY: return "fabd_advsimd.xml";
		case ENC_FABD_ASISDSAMEFP16_ONLY: return "fabd_advsimd.xml";
		case ENC_FABS_D_FLOATDP1: return "fabs_float.xml";
		case ENC_FABS_H_FLOATDP1: return "fabs_float.xml";
		case ENC_FABS_S_FLOATDP1: return "fabs_float.xml";
		case ENC_FABS_ASIMDMISC_R: return "fabs_advsimd.xml";
		case ENC_FABS_ASIMDMISCFP16_R: return "fabs_advsimd.xml";
		case ENC_FACGE_ASIMDSAME_ONLY: return "facge_advsimd.xml";
		case ENC_FACGE_ASIMDSAMEFP16_ONLY: return "facge_advsimd.xml";
		case ENC_FACGE_ASISDSAME_ONLY: return "facge_advsimd.xml";
		case ENC_FACGE_ASISDSAMEFP16_ONLY: return "facge_advsimd.xml";
		case ENC_FACGT_ASIMDSAME_ONLY: return "facgt_advsimd.xml";
		case ENC_FACGT_ASIMDSAMEFP16_ONLY: return "facgt_advsimd.xml";
		case ENC_FACGT_ASISDSAME_ONLY: return "facgt_advsimd.xml";
		case ENC_FACGT_ASISDSAMEFP16_ONLY: return "facgt_advsimd.xml";
		case ENC_FACLE_FACGE_P_P_ZZ_: return "facle_facge_p_p_zz.xml";
		case ENC_FACLT_FACGT_P_P_ZZ_: return "faclt_facge_p_p_zz.xml";
		case ENC_FADDP_ASIMDSAME_ONLY: return "faddp_advsimd_vec.xml";
		case ENC_FADDP_ASIMDSAMEFP16_ONLY: return "faddp_advsimd_vec.xml";
		case ENC_FADDP_ASISDPAIR_ONLY_H: return "faddp_advsimd_pair.xml";
		case ENC_FADDP_ASISDPAIR_ONLY_SD: return "faddp_advsimd_pair.xml";
		case ENC_FADD_D_FLOATDP2: return "fadd_float.xml";
		case ENC_FADD_H_FLOATDP2: return "fadd_float.xml";
		case ENC_FADD_S_FLOATDP2: return "fadd_float.xml";
		case ENC_FADD_ASIMDSAME_ONLY: return "fadd_advsimd.xml";
		case ENC_FADD_ASIMDSAMEFP16_ONLY: return "fadd_advsimd.xml";
		case ENC_FCADD_ASIMDSAME2_C: return "fcadd_advsimd_vec.xml";
		case ENC_FCCMPE_D_FLOATCCMP: return "fccmpe_float.xml";
		case ENC_FCCMPE_H_FLOATCCMP: return "fccmpe_float.xml";
		case ENC_FCCMPE_S_FLOATCCMP: return "fccmpe_float.xml";
		case ENC_FCCMP_D_FLOATCCMP: return "fccmp_float.xml";
		case ENC_FCCMP_H_FLOATCCMP: return "fccmp_float.xml";
		case ENC_FCCMP_S_FLOATCCMP: return "fccmp_float.xml";
		case ENC_FCMEQ_ASIMDMISC_FZ: return "fcmeq_advsimd_zero.xml";
		case ENC_FCMEQ_ASIMDMISCFP16_FZ: return "fcmeq_advsimd_zero.xml";
		case ENC_FCMEQ_ASIMDSAME_ONLY: return "fcmeq_advsimd_reg.xml";
		case ENC_FCMEQ_ASIMDSAMEFP16_ONLY: return "fcmeq_advsimd_reg.xml";
		case ENC_FCMEQ_ASISDMISC_FZ: return "fcmeq_advsimd_zero.xml";
		case ENC_FCMEQ_ASISDMISCFP16_FZ: return "fcmeq_advsimd_zero.xml";
		case ENC_FCMEQ_ASISDSAME_ONLY: return "fcmeq_advsimd_reg.xml";
		case ENC_FCMEQ_ASISDSAMEFP16_ONLY: return "fcmeq_advsimd_reg.xml";
		case ENC_FCMGE_ASIMDMISC_FZ: return "fcmge_advsimd_zero.xml";
		case ENC_FCMGE_ASIMDMISCFP16_FZ: return "fcmge_advsimd_zero.xml";
		case ENC_FCMGE_ASIMDSAME_ONLY: return "fcmge_advsimd_reg.xml";
		case ENC_FCMGE_ASIMDSAMEFP16_ONLY: return "fcmge_advsimd_reg.xml";
		case ENC_FCMGE_ASISDMISC_FZ: return "fcmge_advsimd_zero.xml";
		case ENC_FCMGE_ASISDMISCFP16_FZ: return "fcmge_advsimd_zero.xml";
		case ENC_FCMGE_ASISDSAME_ONLY: return "fcmge_advsimd_reg.xml";
		case ENC_FCMGE_ASISDSAMEFP16_ONLY: return "fcmge_advsimd_reg.xml";
		case ENC_FCMGT_ASIMDMISC_FZ: return "fcmgt_advsimd_zero.xml";
		case ENC_FCMGT_ASIMDMISCFP16_FZ: return "fcmgt_advsimd_zero.xml";
		case ENC_FCMGT_ASIMDSAME_ONLY: return "fcmgt_advsimd_reg.xml";
		case ENC_FCMGT_ASIMDSAMEFP16_ONLY: return "fcmgt_advsimd_reg.xml";
		case ENC_FCMGT_ASISDMISC_FZ: return "fcmgt_advsimd_zero.xml";
		case ENC_FCMGT_ASISDMISCFP16_FZ: return "fcmgt_advsimd_zero.xml";
		case ENC_FCMGT_ASISDSAME_ONLY: return "fcmgt_advsimd_reg.xml";
		case ENC_FCMGT_ASISDSAMEFP16_ONLY: return "fcmgt_advsimd_reg.xml";
		case ENC_FCMLA_ASIMDELEM_C_H: return "fcmla_advsimd_elt.xml";
		case ENC_FCMLA_ASIMDELEM_C_S: return "fcmla_advsimd_elt.xml";
		case ENC_FCMLA_ASIMDSAME2_C: return "fcmla_advsimd_vec.xml";
		case ENC_FCMLE_ASIMDMISC_FZ: return "fcmle_advsimd.xml";
		case ENC_FCMLE_ASIMDMISCFP16_FZ: return "fcmle_advsimd.xml";
		case ENC_FCMLE_ASISDMISC_FZ: return "fcmle_advsimd.xml";
		case ENC_FCMLE_ASISDMISCFP16_FZ: return "fcmle_advsimd.xml";
		case ENC_FCMLE_FCMGE_P_P_ZZ_: return "fcmle_fcmeq_p_p_zz.xml";
		case ENC_FCMLT_ASIMDMISC_FZ: return "fcmlt_advsimd.xml";
		case ENC_FCMLT_ASIMDMISCFP16_FZ: return "fcmlt_advsimd.xml";
		case ENC_FCMLT_ASISDMISC_FZ: return "fcmlt_advsimd.xml";
		case ENC_FCMLT_ASISDMISCFP16_FZ: return "fcmlt_advsimd.xml";
		case ENC_FCMLT_FCMGT_P_P_ZZ_: return "fcmlt_fcmeq_p_p_zz.xml";
		case ENC_FCMPE_DZ_FLOATCMP: return "fcmpe_float.xml";
		case ENC_FCMPE_D_FLOATCMP: return "fcmpe_float.xml";
		case ENC_FCMPE_HZ_FLOATCMP: return "fcmpe_float.xml";
		case ENC_FCMPE_H_FLOATCMP: return "fcmpe_float.xml";
		case ENC_FCMPE_SZ_FLOATCMP: return "fcmpe_float.xml";
		case ENC_FCMPE_S_FLOATCMP: return "fcmpe_float.xml";
		case ENC_FCMP_DZ_FLOATCMP: return "fcmp_float.xml";
		case ENC_FCMP_D_FLOATCMP: return "fcmp_float.xml";
		case ENC_FCMP_HZ_FLOATCMP: return "fcmp_float.xml";
		case ENC_FCMP_H_FLOATCMP: return "fcmp_float.xml";
		case ENC_FCMP_SZ_FLOATCMP: return "fcmp_float.xml";
		case ENC_FCMP_S_FLOATCMP: return "fcmp_float.xml";
		case ENC_FCSEL_D_FLOATSEL: return "fcsel_float.xml";
		case ENC_FCSEL_H_FLOATSEL: return "fcsel_float.xml";
		case ENC_FCSEL_S_FLOATSEL: return "fcsel_float.xml";
		case ENC_FCVTAS_32D_FLOAT2INT: return "fcvtas_float.xml";
		case ENC_FCVTAS_32H_FLOAT2INT: return "fcvtas_float.xml";
		case ENC_FCVTAS_32S_FLOAT2INT: return "fcvtas_float.xml";
		case ENC_FCVTAS_64D_FLOAT2INT: return "fcvtas_float.xml";
		case ENC_FCVTAS_64H_FLOAT2INT: return "fcvtas_float.xml";
		case ENC_FCVTAS_64S_FLOAT2INT: return "fcvtas_float.xml";
		case ENC_FCVTAS_ASIMDMISC_R: return "fcvtas_advsimd.xml";
		case ENC_FCVTAS_ASIMDMISCFP16_R: return "fcvtas_advsimd.xml";
		case ENC_FCVTAS_ASISDMISC_R: return "fcvtas_advsimd.xml";
		case ENC_FCVTAS_ASISDMISCFP16_R: return "fcvtas_advsimd.xml";
		case ENC_FCVTAU_32D_FLOAT2INT: return "fcvtau_float.xml";
		case ENC_FCVTAU_32H_FLOAT2INT: return "fcvtau_float.xml";
		case ENC_FCVTAU_32S_FLOAT2INT: return "fcvtau_float.xml";
		case ENC_FCVTAU_64D_FLOAT2INT: return "fcvtau_float.xml";
		case ENC_FCVTAU_64H_FLOAT2INT: return "fcvtau_float.xml";
		case ENC_FCVTAU_64S_FLOAT2INT: return "fcvtau_float.xml";
		case ENC_FCVTAU_ASIMDMISC_R: return "fcvtau_advsimd.xml";
		case ENC_FCVTAU_ASIMDMISCFP16_R: return "fcvtau_advsimd.xml";
		case ENC_FCVTAU_ASISDMISC_R: return "fcvtau_advsimd.xml";
		case ENC_FCVTAU_ASISDMISCFP16_R: return "fcvtau_advsimd.xml";
		case ENC_FCVTL_ASIMDMISC_L: return "fcvtl_advsimd.xml";
		case ENC_FCVTMS_32D_FLOAT2INT: return "fcvtms_float.xml";
		case ENC_FCVTMS_32H_FLOAT2INT: return "fcvtms_float.xml";
		case ENC_FCVTMS_32S_FLOAT2INT: return "fcvtms_float.xml";
		case ENC_FCVTMS_64D_FLOAT2INT: return "fcvtms_float.xml";
		case ENC_FCVTMS_64H_FLOAT2INT: return "fcvtms_float.xml";
		case ENC_FCVTMS_64S_FLOAT2INT: return "fcvtms_float.xml";
		case ENC_FCVTMS_ASIMDMISC_R: return "fcvtms_advsimd.xml";
		case ENC_FCVTMS_ASIMDMISCFP16_R: return "fcvtms_advsimd.xml";
		case ENC_FCVTMS_ASISDMISC_R: return "fcvtms_advsimd.xml";
		case ENC_FCVTMS_ASISDMISCFP16_R: return "fcvtms_advsimd.xml";
		case ENC_FCVTMU_32D_FLOAT2INT: return "fcvtmu_float.xml";
		case ENC_FCVTMU_32H_FLOAT2INT: return "fcvtmu_float.xml";
		case ENC_FCVTMU_32S_FLOAT2INT: return "fcvtmu_float.xml";
		case ENC_FCVTMU_64D_FLOAT2INT: return "fcvtmu_float.xml";
		case ENC_FCVTMU_64H_FLOAT2INT: return "fcvtmu_float.xml";
		case ENC_FCVTMU_64S_FLOAT2INT: return "fcvtmu_float.xml";
		case ENC_FCVTMU_ASIMDMISC_R: return "fcvtmu_advsimd.xml";
		case ENC_FCVTMU_ASIMDMISCFP16_R: return "fcvtmu_advsimd.xml";
		case ENC_FCVTMU_ASISDMISC_R: return "fcvtmu_advsimd.xml";
		case ENC_FCVTMU_ASISDMISCFP16_R: return "fcvtmu_advsimd.xml";
		case ENC_FCVTNS_32D_FLOAT2INT: return "fcvtns_float.xml";
		case ENC_FCVTNS_32H_FLOAT2INT: return "fcvtns_float.xml";
		case ENC_FCVTNS_32S_FLOAT2INT: return "fcvtns_float.xml";
		case ENC_FCVTNS_64D_FLOAT2INT: return "fcvtns_float.xml";
		case ENC_FCVTNS_64H_FLOAT2INT: return "fcvtns_float.xml";
		case ENC_FCVTNS_64S_FLOAT2INT: return "fcvtns_float.xml";
		case ENC_FCVTNS_ASIMDMISC_R: return "fcvtns_advsimd.xml";
		case ENC_FCVTNS_ASIMDMISCFP16_R: return "fcvtns_advsimd.xml";
		case ENC_FCVTNS_ASISDMISC_R: return "fcvtns_advsimd.xml";
		case ENC_FCVTNS_ASISDMISCFP16_R: return "fcvtns_advsimd.xml";
		case ENC_FCVTNU_32D_FLOAT2INT: return "fcvtnu_float.xml";
		case ENC_FCVTNU_32H_FLOAT2INT: return "fcvtnu_float.xml";
		case ENC_FCVTNU_32S_FLOAT2INT: return "fcvtnu_float.xml";
		case ENC_FCVTNU_64D_FLOAT2INT: return "fcvtnu_float.xml";
		case ENC_FCVTNU_64H_FLOAT2INT: return "fcvtnu_float.xml";
		case ENC_FCVTNU_64S_FLOAT2INT: return "fcvtnu_float.xml";
		case ENC_FCVTNU_ASIMDMISC_R: return "fcvtnu_advsimd.xml";
		case ENC_FCVTNU_ASIMDMISCFP16_R: return "fcvtnu_advsimd.xml";
		case ENC_FCVTNU_ASISDMISC_R: return "fcvtnu_advsimd.xml";
		case ENC_FCVTNU_ASISDMISCFP16_R: return "fcvtnu_advsimd.xml";
		case ENC_FCVTN_ASIMDMISC_N: return "fcvtn_advsimd.xml";
		case ENC_FCVTPS_32D_FLOAT2INT: return "fcvtps_float.xml";
		case ENC_FCVTPS_32H_FLOAT2INT: return "fcvtps_float.xml";
		case ENC_FCVTPS_32S_FLOAT2INT: return "fcvtps_float.xml";
		case ENC_FCVTPS_64D_FLOAT2INT: return "fcvtps_float.xml";
		case ENC_FCVTPS_64H_FLOAT2INT: return "fcvtps_float.xml";
		case ENC_FCVTPS_64S_FLOAT2INT: return "fcvtps_float.xml";
		case ENC_FCVTPS_ASIMDMISC_R: return "fcvtps_advsimd.xml";
		case ENC_FCVTPS_ASIMDMISCFP16_R: return "fcvtps_advsimd.xml";
		case ENC_FCVTPS_ASISDMISC_R: return "fcvtps_advsimd.xml";
		case ENC_FCVTPS_ASISDMISCFP16_R: return "fcvtps_advsimd.xml";
		case ENC_FCVTPU_32D_FLOAT2INT: return "fcvtpu_float.xml";
		case ENC_FCVTPU_32H_FLOAT2INT: return "fcvtpu_float.xml";
		case ENC_FCVTPU_32S_FLOAT2INT: return "fcvtpu_float.xml";
		case ENC_FCVTPU_64D_FLOAT2INT: return "fcvtpu_float.xml";
		case ENC_FCVTPU_64H_FLOAT2INT: return "fcvtpu_float.xml";
		case ENC_FCVTPU_64S_FLOAT2INT: return "fcvtpu_float.xml";
		case ENC_FCVTPU_ASIMDMISC_R: return "fcvtpu_advsimd.xml";
		case ENC_FCVTPU_ASIMDMISCFP16_R: return "fcvtpu_advsimd.xml";
		case ENC_FCVTPU_ASISDMISC_R: return "fcvtpu_advsimd.xml";
		case ENC_FCVTPU_ASISDMISCFP16_R: return "fcvtpu_advsimd.xml";
		case ENC_FCVTXN_ASIMDMISC_N: return "fcvtxn_advsimd.xml";
		case ENC_FCVTXN_ASISDMISC_N: return "fcvtxn_advsimd.xml";
		case ENC_FCVTZS_32D_FLOAT2FIX: return "fcvtzs_float_fix.xml";
		case ENC_FCVTZS_32D_FLOAT2INT: return "fcvtzs_float_int.xml";
		case ENC_FCVTZS_32H_FLOAT2FIX: return "fcvtzs_float_fix.xml";
		case ENC_FCVTZS_32H_FLOAT2INT: return "fcvtzs_float_int.xml";
		case ENC_FCVTZS_32S_FLOAT2FIX: return "fcvtzs_float_fix.xml";
		case ENC_FCVTZS_32S_FLOAT2INT: return "fcvtzs_float_int.xml";
		case ENC_FCVTZS_64D_FLOAT2FIX: return "fcvtzs_float_fix.xml";
		case ENC_FCVTZS_64D_FLOAT2INT: return "fcvtzs_float_int.xml";
		case ENC_FCVTZS_64H_FLOAT2FIX: return "fcvtzs_float_fix.xml";
		case ENC_FCVTZS_64H_FLOAT2INT: return "fcvtzs_float_int.xml";
		case ENC_FCVTZS_64S_FLOAT2FIX: return "fcvtzs_float_fix.xml";
		case ENC_FCVTZS_64S_FLOAT2INT: return "fcvtzs_float_int.xml";
		case ENC_FCVTZS_ASIMDMISC_R: return "fcvtzs_advsimd_int.xml";
		case ENC_FCVTZS_ASIMDMISCFP16_R: return "fcvtzs_advsimd_int.xml";
		case ENC_FCVTZS_ASIMDSHF_C: return "fcvtzs_advsimd_fix.xml";
		case ENC_FCVTZS_ASISDMISC_R: return "fcvtzs_advsimd_int.xml";
		case ENC_FCVTZS_ASISDMISCFP16_R: return "fcvtzs_advsimd_int.xml";
		case ENC_FCVTZS_ASISDSHF_C: return "fcvtzs_advsimd_fix.xml";
		case ENC_FCVTZU_32D_FLOAT2FIX: return "fcvtzu_float_fix.xml";
		case ENC_FCVTZU_32D_FLOAT2INT: return "fcvtzu_float_int.xml";
		case ENC_FCVTZU_32H_FLOAT2FIX: return "fcvtzu_float_fix.xml";
		case ENC_FCVTZU_32H_FLOAT2INT: return "fcvtzu_float_int.xml";
		case ENC_FCVTZU_32S_FLOAT2FIX: return "fcvtzu_float_fix.xml";
		case ENC_FCVTZU_32S_FLOAT2INT: return "fcvtzu_float_int.xml";
		case ENC_FCVTZU_64D_FLOAT2FIX: return "fcvtzu_float_fix.xml";
		case ENC_FCVTZU_64D_FLOAT2INT: return "fcvtzu_float_int.xml";
		case ENC_FCVTZU_64H_FLOAT2FIX: return "fcvtzu_float_fix.xml";
		case ENC_FCVTZU_64H_FLOAT2INT: return "fcvtzu_float_int.xml";
		case ENC_FCVTZU_64S_FLOAT2FIX: return "fcvtzu_float_fix.xml";
		case ENC_FCVTZU_64S_FLOAT2INT: return "fcvtzu_float_int.xml";
		case ENC_FCVTZU_ASIMDMISC_R: return "fcvtzu_advsimd_int.xml";
		case ENC_FCVTZU_ASIMDMISCFP16_R: return "fcvtzu_advsimd_int.xml";
		case ENC_FCVTZU_ASIMDSHF_C: return "fcvtzu_advsimd_fix.xml";
		case ENC_FCVTZU_ASISDMISC_R: return "fcvtzu_advsimd_int.xml";
		case ENC_FCVTZU_ASISDMISCFP16_R: return "fcvtzu_advsimd_int.xml";
		case ENC_FCVTZU_ASISDSHF_C: return "fcvtzu_advsimd_fix.xml";
		case ENC_FCVT_DH_FLOATDP1: return "fcvt_float.xml";
		case ENC_FCVT_DS_FLOATDP1: return "fcvt_float.xml";
		case ENC_FCVT_HD_FLOATDP1: return "fcvt_float.xml";
		case ENC_FCVT_HS_FLOATDP1: return "fcvt_float.xml";
		case ENC_FCVT_SD_FLOATDP1: return "fcvt_float.xml";
		case ENC_FCVT_SH_FLOATDP1: return "fcvt_float.xml";
		case ENC_FDIV_D_FLOATDP2: return "fdiv_float.xml";
		case ENC_FDIV_H_FLOATDP2: return "fdiv_float.xml";
		case ENC_FDIV_S_FLOATDP2: return "fdiv_float.xml";
		case ENC_FDIV_ASIMDSAME_ONLY: return "fdiv_advsimd.xml";
		case ENC_FDIV_ASIMDSAMEFP16_ONLY: return "fdiv_advsimd.xml";
		case ENC_FJCVTZS_32D_FLOAT2INT: return "fjcvtzs.xml";
		case ENC_FMADD_D_FLOATDP3: return "fmadd_float.xml";
		case ENC_FMADD_H_FLOATDP3: return "fmadd_float.xml";
		case ENC_FMADD_S_FLOATDP3: return "fmadd_float.xml";
		case ENC_FMAXNMP_ASIMDSAME_ONLY: return "fmaxnmp_advsimd_vec.xml";
		case ENC_FMAXNMP_ASIMDSAMEFP16_ONLY: return "fmaxnmp_advsimd_vec.xml";
		case ENC_FMAXNMP_ASISDPAIR_ONLY_H: return "fmaxnmp_advsimd_pair.xml";
		case ENC_FMAXNMP_ASISDPAIR_ONLY_SD: return "fmaxnmp_advsimd_pair.xml";
		case ENC_FMAXNMV_ASIMDALL_ONLY_H: return "fmaxnmv_advsimd.xml";
		case ENC_FMAXNMV_ASIMDALL_ONLY_SD: return "fmaxnmv_advsimd.xml";
		case ENC_FMAXNM_D_FLOATDP2: return "fmaxnm_float.xml";
		case ENC_FMAXNM_H_FLOATDP2: return "fmaxnm_float.xml";
		case ENC_FMAXNM_S_FLOATDP2: return "fmaxnm_float.xml";
		case ENC_FMAXNM_ASIMDSAME_ONLY: return "fmaxnm_advsimd.xml";
		case ENC_FMAXNM_ASIMDSAMEFP16_ONLY: return "fmaxnm_advsimd.xml";
		case ENC_FMAXP_ASIMDSAME_ONLY: return "fmaxp_advsimd_vec.xml";
		case ENC_FMAXP_ASIMDSAMEFP16_ONLY: return "fmaxp_advsimd_vec.xml";
		case ENC_FMAXP_ASISDPAIR_ONLY_H: return "fmaxp_advsimd_pair.xml";
		case ENC_FMAXP_ASISDPAIR_ONLY_SD: return "fmaxp_advsimd_pair.xml";
		case ENC_FMAXV_ASIMDALL_ONLY_H: return "fmaxv_advsimd.xml";
		case ENC_FMAXV_ASIMDALL_ONLY_SD: return "fmaxv_advsimd.xml";
		case ENC_FMAX_D_FLOATDP2: return "fmax_float.xml";
		case ENC_FMAX_H_FLOATDP2: return "fmax_float.xml";
		case ENC_FMAX_S_FLOATDP2: return "fmax_float.xml";
		case ENC_FMAX_ASIMDSAME_ONLY: return "fmax_advsimd.xml";
		case ENC_FMAX_ASIMDSAMEFP16_ONLY: return "fmax_advsimd.xml";
		case ENC_FMINNMP_ASIMDSAME_ONLY: return "fminnmp_advsimd_vec.xml";
		case ENC_FMINNMP_ASIMDSAMEFP16_ONLY: return "fminnmp_advsimd_vec.xml";
		case ENC_FMINNMP_ASISDPAIR_ONLY_H: return "fminnmp_advsimd_pair.xml";
		case ENC_FMINNMP_ASISDPAIR_ONLY_SD: return "fminnmp_advsimd_pair.xml";
		case ENC_FMINNMV_ASIMDALL_ONLY_H: return "fminnmv_advsimd.xml";
		case ENC_FMINNMV_ASIMDALL_ONLY_SD: return "fminnmv_advsimd.xml";
		case ENC_FMINNM_D_FLOATDP2: return "fminnm_float.xml";
		case ENC_FMINNM_H_FLOATDP2: return "fminnm_float.xml";
		case ENC_FMINNM_S_FLOATDP2: return "fminnm_float.xml";
		case ENC_FMINNM_ASIMDSAME_ONLY: return "fminnm_advsimd.xml";
		case ENC_FMINNM_ASIMDSAMEFP16_ONLY: return "fminnm_advsimd.xml";
		case ENC_FMINP_ASIMDSAME_ONLY: return "fminp_advsimd_vec.xml";
		case ENC_FMINP_ASIMDSAMEFP16_ONLY: return "fminp_advsimd_vec.xml";
		case ENC_FMINP_ASISDPAIR_ONLY_H: return "fminp_advsimd_pair.xml";
		case ENC_FMINP_ASISDPAIR_ONLY_SD: return "fminp_advsimd_pair.xml";
		case ENC_FMINV_ASIMDALL_ONLY_H: return "fminv_advsimd.xml";
		case ENC_FMINV_ASIMDALL_ONLY_SD: return "fminv_advsimd.xml";
		case ENC_FMIN_D_FLOATDP2: return "fmin_float.xml";
		case ENC_FMIN_H_FLOATDP2: return "fmin_float.xml";
		case ENC_FMIN_S_FLOATDP2: return "fmin_float.xml";
		case ENC_FMIN_ASIMDSAME_ONLY: return "fmin_advsimd.xml";
		case ENC_FMIN_ASIMDSAMEFP16_ONLY: return "fmin_advsimd.xml";
		case ENC_FMLAL2_ASIMDELEM_LH: return "fmlal_advsimd_elt.xml";
		case ENC_FMLAL2_ASIMDSAME_F: return "fmlal_advsimd_vec.xml";
		case ENC_FMLAL_ASIMDELEM_LH: return "fmlal_advsimd_elt.xml";
		case ENC_FMLAL_ASIMDSAME_F: return "fmlal_advsimd_vec.xml";
		case ENC_FMLA_ASIMDELEM_RH_H: return "fmla_advsimd_elt.xml";
		case ENC_FMLA_ASIMDELEM_R_SD: return "fmla_advsimd_elt.xml";
		case ENC_FMLA_ASIMDSAME_ONLY: return "fmla_advsimd_vec.xml";
		case ENC_FMLA_ASIMDSAMEFP16_ONLY: return "fmla_advsimd_vec.xml";
		case ENC_FMLA_ASISDELEM_RH_H: return "fmla_advsimd_elt.xml";
		case ENC_FMLA_ASISDELEM_R_SD: return "fmla_advsimd_elt.xml";
		case ENC_FMLSL2_ASIMDELEM_LH: return "fmlsl_advsimd_elt.xml";
		case ENC_FMLSL2_ASIMDSAME_F: return "fmlsl_advsimd_vec.xml";
		case ENC_FMLSL_ASIMDELEM_LH: return "fmlsl_advsimd_elt.xml";
		case ENC_FMLSL_ASIMDSAME_F: return "fmlsl_advsimd_vec.xml";
		case ENC_FMLS_ASIMDELEM_RH_H: return "fmls_advsimd_elt.xml";
		case ENC_FMLS_ASIMDELEM_R_SD: return "fmls_advsimd_elt.xml";
		case ENC_FMLS_ASIMDSAME_ONLY: return "fmls_advsimd_vec.xml";
		case ENC_FMLS_ASIMDSAMEFP16_ONLY: return "fmls_advsimd_vec.xml";
		case ENC_FMLS_ASISDELEM_RH_H: return "fmls_advsimd_elt.xml";
		case ENC_FMLS_ASISDELEM_R_SD: return "fmls_advsimd_elt.xml";
		case ENC_FMOV_32H_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_32S_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_64D_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_64H_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_64VX_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_D64_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_D_FLOATDP1: return "fmov_float.xml";
		case ENC_FMOV_D_FLOATIMM: return "fmov_float_imm.xml";
		case ENC_FMOV_H32_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_H64_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_H_FLOATDP1: return "fmov_float.xml";
		case ENC_FMOV_H_FLOATIMM: return "fmov_float_imm.xml";
		case ENC_FMOV_S32_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_S_FLOATDP1: return "fmov_float.xml";
		case ENC_FMOV_S_FLOATIMM: return "fmov_float_imm.xml";
		case ENC_FMOV_V64I_FLOAT2INT: return "fmov_float_gen.xml";
		case ENC_FMOV_ASIMDIMM_D2_D: return "fmov_advsimd.xml";
		case ENC_FMOV_ASIMDIMM_H_H: return "fmov_advsimd.xml";
		case ENC_FMOV_ASIMDIMM_S_S: return "fmov_advsimd.xml";
		case ENC_FMOV_CPY_Z_P_I_: return "fmov_cpy_z_p_i.xml";
		case ENC_FMOV_DUP_Z_I_: return "fmov_dup_z_i.xml";
		case ENC_FMOV_FCPY_Z_P_I_: return "fmov_fcpy_z_p_i.xml";
		case ENC_FMOV_FDUP_Z_I_: return "fmov_fdup_z_i.xml";
		case ENC_FMSUB_D_FLOATDP3: return "fmsub_float.xml";
		case ENC_FMSUB_H_FLOATDP3: return "fmsub_float.xml";
		case ENC_FMSUB_S_FLOATDP3: return "fmsub_float.xml";
		case ENC_FMULX_ASIMDELEM_RH_H: return "fmulx_advsimd_elt.xml";
		case ENC_FMULX_ASIMDELEM_R_SD: return "fmulx_advsimd_elt.xml";
		case ENC_FMULX_ASIMDSAME_ONLY: return "fmulx_advsimd_vec.xml";
		case ENC_FMULX_ASIMDSAMEFP16_ONLY: return "fmulx_advsimd_vec.xml";
		case ENC_FMULX_ASISDELEM_RH_H: return "fmulx_advsimd_elt.xml";
		case ENC_FMULX_ASISDELEM_R_SD: return "fmulx_advsimd_elt.xml";
		case ENC_FMULX_ASISDSAME_ONLY: return "fmulx_advsimd_vec.xml";
		case ENC_FMULX_ASISDSAMEFP16_ONLY: return "fmulx_advsimd_vec.xml";
		case ENC_FMUL_D_FLOATDP2: return "fmul_float.xml";
		case ENC_FMUL_H_FLOATDP2: return "fmul_float.xml";
		case ENC_FMUL_S_FLOATDP2: return "fmul_float.xml";
		case ENC_FMUL_ASIMDELEM_RH_H: return "fmul_advsimd_elt.xml";
		case ENC_FMUL_ASIMDELEM_R_SD: return "fmul_advsimd_elt.xml";
		case ENC_FMUL_ASIMDSAME_ONLY: return "fmul_advsimd_vec.xml";
		case ENC_FMUL_ASIMDSAMEFP16_ONLY: return "fmul_advsimd_vec.xml";
		case ENC_FMUL_ASISDELEM_RH_H: return "fmul_advsimd_elt.xml";
		case ENC_FMUL_ASISDELEM_R_SD: return "fmul_advsimd_elt.xml";
		case ENC_FNEG_D_FLOATDP1: return "fneg_float.xml";
		case ENC_FNEG_H_FLOATDP1: return "fneg_float.xml";
		case ENC_FNEG_S_FLOATDP1: return "fneg_float.xml";
		case ENC_FNEG_ASIMDMISC_R: return "fneg_advsimd.xml";
		case ENC_FNEG_ASIMDMISCFP16_R: return "fneg_advsimd.xml";
		case ENC_FNMADD_D_FLOATDP3: return "fnmadd_float.xml";
		case ENC_FNMADD_H_FLOATDP3: return "fnmadd_float.xml";
		case ENC_FNMADD_S_FLOATDP3: return "fnmadd_float.xml";
		case ENC_FNMSUB_D_FLOATDP3: return "fnmsub_float.xml";
		case ENC_FNMSUB_H_FLOATDP3: return "fnmsub_float.xml";
		case ENC_FNMSUB_S_FLOATDP3: return "fnmsub_float.xml";
		case ENC_FNMUL_D_FLOATDP2: return "fnmul_float.xml";
		case ENC_FNMUL_H_FLOATDP2: return "fnmul_float.xml";
		case ENC_FNMUL_S_FLOATDP2: return "fnmul_float.xml";
		case ENC_FRECPE_ASIMDMISC_R: return "frecpe_advsimd.xml";
		case ENC_FRECPE_ASIMDMISCFP16_R: return "frecpe_advsimd.xml";
		case ENC_FRECPE_ASISDMISC_R: return "frecpe_advsimd.xml";
		case ENC_FRECPE_ASISDMISCFP16_R: return "frecpe_advsimd.xml";
		case ENC_FRECPS_ASIMDSAME_ONLY: return "frecps_advsimd.xml";
		case ENC_FRECPS_ASIMDSAMEFP16_ONLY: return "frecps_advsimd.xml";
		case ENC_FRECPS_ASISDSAME_ONLY: return "frecps_advsimd.xml";
		case ENC_FRECPS_ASISDSAMEFP16_ONLY: return "frecps_advsimd.xml";
		case ENC_FRECPX_ASISDMISC_R: return "frecpx_advsimd.xml";
		case ENC_FRECPX_ASISDMISCFP16_R: return "frecpx_advsimd.xml";
		case ENC_FRINT32X_D_FLOATDP1: return "frint32x_float.xml";
		case ENC_FRINT32X_S_FLOATDP1: return "frint32x_float.xml";
		case ENC_FRINT32X_ASIMDMISC_R: return "frint32x_advsimd.xml";
		case ENC_FRINT32Z_D_FLOATDP1: return "frint32z_float.xml";
		case ENC_FRINT32Z_S_FLOATDP1: return "frint32z_float.xml";
		case ENC_FRINT32Z_ASIMDMISC_R: return "frint32z_advsimd.xml";
		case ENC_FRINT64X_D_FLOATDP1: return "frint64x_float.xml";
		case ENC_FRINT64X_S_FLOATDP1: return "frint64x_float.xml";
		case ENC_FRINT64X_ASIMDMISC_R: return "frint64x_advsimd.xml";
		case ENC_FRINT64Z_D_FLOATDP1: return "frint64z_float.xml";
		case ENC_FRINT64Z_S_FLOATDP1: return "frint64z_float.xml";
		case ENC_FRINT64Z_ASIMDMISC_R: return "frint64z_advsimd.xml";
		case ENC_FRINTA_D_FLOATDP1: return "frinta_float.xml";
		case ENC_FRINTA_H_FLOATDP1: return "frinta_float.xml";
		case ENC_FRINTA_S_FLOATDP1: return "frinta_float.xml";
		case ENC_FRINTA_ASIMDMISC_R: return "frinta_advsimd.xml";
		case ENC_FRINTA_ASIMDMISCFP16_R: return "frinta_advsimd.xml";
		case ENC_FRINTI_D_FLOATDP1: return "frinti_float.xml";
		case ENC_FRINTI_H_FLOATDP1: return "frinti_float.xml";
		case ENC_FRINTI_S_FLOATDP1: return "frinti_float.xml";
		case ENC_FRINTI_ASIMDMISC_R: return "frinti_advsimd.xml";
		case ENC_FRINTI_ASIMDMISCFP16_R: return "frinti_advsimd.xml";
		case ENC_FRINTM_D_FLOATDP1: return "frintm_float.xml";
		case ENC_FRINTM_H_FLOATDP1: return "frintm_float.xml";
		case ENC_FRINTM_S_FLOATDP1: return "frintm_float.xml";
		case ENC_FRINTM_ASIMDMISC_R: return "frintm_advsimd.xml";
		case ENC_FRINTM_ASIMDMISCFP16_R: return "frintm_advsimd.xml";
		case ENC_FRINTN_D_FLOATDP1: return "frintn_float.xml";
		case ENC_FRINTN_H_FLOATDP1: return "frintn_float.xml";
		case ENC_FRINTN_S_FLOATDP1: return "frintn_float.xml";
		case ENC_FRINTN_ASIMDMISC_R: return "frintn_advsimd.xml";
		case ENC_FRINTN_ASIMDMISCFP16_R: return "frintn_advsimd.xml";
		case ENC_FRINTP_D_FLOATDP1: return "frintp_float.xml";
		case ENC_FRINTP_H_FLOATDP1: return "frintp_float.xml";
		case ENC_FRINTP_S_FLOATDP1: return "frintp_float.xml";
		case ENC_FRINTP_ASIMDMISC_R: return "frintp_advsimd.xml";
		case ENC_FRINTP_ASIMDMISCFP16_R: return "frintp_advsimd.xml";
		case ENC_FRINTX_D_FLOATDP1: return "frintx_float.xml";
		case ENC_FRINTX_H_FLOATDP1: return "frintx_float.xml";
		case ENC_FRINTX_S_FLOATDP1: return "frintx_float.xml";
		case ENC_FRINTX_ASIMDMISC_R: return "frintx_advsimd.xml";
		case ENC_FRINTX_ASIMDMISCFP16_R: return "frintx_advsimd.xml";
		case ENC_FRINTZ_D_FLOATDP1: return "frintz_float.xml";
		case ENC_FRINTZ_H_FLOATDP1: return "frintz_float.xml";
		case ENC_FRINTZ_S_FLOATDP1: return "frintz_float.xml";
		case ENC_FRINTZ_ASIMDMISC_R: return "frintz_advsimd.xml";
		case ENC_FRINTZ_ASIMDMISCFP16_R: return "frintz_advsimd.xml";
		case ENC_FRSQRTE_ASIMDMISC_R: return "frsqrte_advsimd.xml";
		case ENC_FRSQRTE_ASIMDMISCFP16_R: return "frsqrte_advsimd.xml";
		case ENC_FRSQRTE_ASISDMISC_R: return "frsqrte_advsimd.xml";
		case ENC_FRSQRTE_ASISDMISCFP16_R: return "frsqrte_advsimd.xml";
		case ENC_FRSQRTS_ASIMDSAME_ONLY: return "frsqrts_advsimd.xml";
		case ENC_FRSQRTS_ASIMDSAMEFP16_ONLY: return "frsqrts_advsimd.xml";
		case ENC_FRSQRTS_ASISDSAME_ONLY: return "frsqrts_advsimd.xml";
		case ENC_FRSQRTS_ASISDSAMEFP16_ONLY: return "frsqrts_advsimd.xml";
		case ENC_FSQRT_D_FLOATDP1: return "fsqrt_float.xml";
		case ENC_FSQRT_H_FLOATDP1: return "fsqrt_float.xml";
		case ENC_FSQRT_S_FLOATDP1: return "fsqrt_float.xml";
		case ENC_FSQRT_ASIMDMISC_R: return "fsqrt_advsimd.xml";
		case ENC_FSQRT_ASIMDMISCFP16_R: return "fsqrt_advsimd.xml";
		case ENC_FSUB_D_FLOATDP2: return "fsub_float.xml";
		case ENC_FSUB_H_FLOATDP2: return "fsub_float.xml";
		case ENC_FSUB_S_FLOATDP2: return "fsub_float.xml";
		case ENC_FSUB_ASIMDSAME_ONLY: return "fsub_advsimd.xml";
		case ENC_FSUB_ASIMDSAMEFP16_ONLY: return "fsub_advsimd.xml";
		case ENC_GMI_64G_DP_2SRC: return "gmi.xml";
		case ENC_HINT_HM_HINTS: return "hint.xml";
		case ENC_HLT_EX_EXCEPTION: return "hlt.xml";
		case ENC_HVC_EX_EXCEPTION: return "hvc.xml";
		case ENC_IC_SYS_CR_SYSTEMINSTRS: return "ic_sys.xml";
		case ENC_INS_ASIMDINS_IR_R: return "ins_advsimd_gen.xml";
		case ENC_INS_ASIMDINS_IV_V: return "ins_advsimd_elt.xml";
		case ENC_IRG_64I_DP_2SRC: return "irg.xml";
		case ENC_ISB_BI_BARRIERS: return "isb.xml";
		case ENC_LD1R_ASISDLSO_R1: return "ld1r_advsimd.xml";
		case ENC_LD1R_ASISDLSOP_R1_I: return "ld1r_advsimd.xml";
		case ENC_LD1R_ASISDLSOP_RX1_R: return "ld1r_advsimd.xml";
		case ENC_LD1_ASISDLSE_R1_1V: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSE_R2_2V: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSE_R3_3V: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSE_R4_4V: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSEP_I1_I1: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSEP_I2_I2: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSEP_I3_I3: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSEP_I4_I4: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSEP_R1_R1: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSEP_R2_R2: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSEP_R3_R3: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSEP_R4_R4: return "ld1_advsimd_mult.xml";
		case ENC_LD1_ASISDLSO_B1_1B: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSO_D1_1D: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSO_H1_1H: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSO_S1_1S: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSOP_B1_I1B: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSOP_BX1_R1B: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSOP_D1_I1D: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSOP_DX1_R1D: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSOP_H1_I1H: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSOP_HX1_R1H: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSOP_S1_I1S: return "ld1_advsimd_sngl.xml";
		case ENC_LD1_ASISDLSOP_SX1_R1S: return "ld1_advsimd_sngl.xml";
		case ENC_LD2R_ASISDLSO_R2: return "ld2r_advsimd.xml";
		case ENC_LD2R_ASISDLSOP_R2_I: return "ld2r_advsimd.xml";
		case ENC_LD2R_ASISDLSOP_RX2_R: return "ld2r_advsimd.xml";
		case ENC_LD2_ASISDLSE_R2: return "ld2_advsimd_mult.xml";
		case ENC_LD2_ASISDLSEP_I2_I: return "ld2_advsimd_mult.xml";
		case ENC_LD2_ASISDLSEP_R2_R: return "ld2_advsimd_mult.xml";
		case ENC_LD2_ASISDLSO_B2_2B: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSO_D2_2D: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSO_H2_2H: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSO_S2_2S: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSOP_B2_I2B: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSOP_BX2_R2B: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSOP_D2_I2D: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSOP_DX2_R2D: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSOP_H2_I2H: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSOP_HX2_R2H: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSOP_S2_I2S: return "ld2_advsimd_sngl.xml";
		case ENC_LD2_ASISDLSOP_SX2_R2S: return "ld2_advsimd_sngl.xml";
		case ENC_LD3R_ASISDLSO_R3: return "ld3r_advsimd.xml";
		case ENC_LD3R_ASISDLSOP_R3_I: return "ld3r_advsimd.xml";
		case ENC_LD3R_ASISDLSOP_RX3_R: return "ld3r_advsimd.xml";
		case ENC_LD3_ASISDLSE_R3: return "ld3_advsimd_mult.xml";
		case ENC_LD3_ASISDLSEP_I3_I: return "ld3_advsimd_mult.xml";
		case ENC_LD3_ASISDLSEP_R3_R: return "ld3_advsimd_mult.xml";
		case ENC_LD3_ASISDLSO_B3_3B: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSO_D3_3D: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSO_H3_3H: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSO_S3_3S: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSOP_B3_I3B: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSOP_BX3_R3B: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSOP_D3_I3D: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSOP_DX3_R3D: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSOP_H3_I3H: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSOP_HX3_R3H: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSOP_S3_I3S: return "ld3_advsimd_sngl.xml";
		case ENC_LD3_ASISDLSOP_SX3_R3S: return "ld3_advsimd_sngl.xml";
		case ENC_LD4R_ASISDLSO_R4: return "ld4r_advsimd.xml";
		case ENC_LD4R_ASISDLSOP_R4_I: return "ld4r_advsimd.xml";
		case ENC_LD4R_ASISDLSOP_RX4_R: return "ld4r_advsimd.xml";
		case ENC_LD4_ASISDLSE_R4: return "ld4_advsimd_mult.xml";
		case ENC_LD4_ASISDLSEP_I4_I: return "ld4_advsimd_mult.xml";
		case ENC_LD4_ASISDLSEP_R4_R: return "ld4_advsimd_mult.xml";
		case ENC_LD4_ASISDLSO_B4_4B: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSO_D4_4D: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSO_H4_4H: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSO_S4_4S: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSOP_B4_I4B: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSOP_BX4_R4B: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSOP_D4_I4D: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSOP_DX4_R4D: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSOP_H4_I4H: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSOP_HX4_R4H: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSOP_S4_I4S: return "ld4_advsimd_sngl.xml";
		case ENC_LD4_ASISDLSOP_SX4_R4S: return "ld4_advsimd_sngl.xml";
		case ENC_LDADDAB_32_MEMOP: return "ldaddb.xml";
		case ENC_LDADDAH_32_MEMOP: return "ldaddh.xml";
		case ENC_LDADDALB_32_MEMOP: return "ldaddb.xml";
		case ENC_LDADDALH_32_MEMOP: return "ldaddh.xml";
		case ENC_LDADDAL_32_MEMOP: return "ldadd.xml";
		case ENC_LDADDAL_64_MEMOP: return "ldadd.xml";
		case ENC_LDADDA_32_MEMOP: return "ldadd.xml";
		case ENC_LDADDA_64_MEMOP: return "ldadd.xml";
		case ENC_LDADDB_32_MEMOP: return "ldaddb.xml";
		case ENC_LDADDH_32_MEMOP: return "ldaddh.xml";
		case ENC_LDADDLB_32_MEMOP: return "ldaddb.xml";
		case ENC_LDADDLH_32_MEMOP: return "ldaddh.xml";
		case ENC_LDADDL_32_MEMOP: return "ldadd.xml";
		case ENC_LDADDL_64_MEMOP: return "ldadd.xml";
		case ENC_LDADD_32_MEMOP: return "ldadd.xml";
		case ENC_LDADD_64_MEMOP: return "ldadd.xml";
		case ENC_LDAPRB_32L_MEMOP: return "ldaprb.xml";
		case ENC_LDAPRH_32L_MEMOP: return "ldaprh.xml";
		case ENC_LDAPR_32L_MEMOP: return "ldapr.xml";
		case ENC_LDAPR_64L_MEMOP: return "ldapr.xml";
		case ENC_LDAPURB_32_LDAPSTL_UNSCALED: return "ldapurb.xml";
		case ENC_LDAPURH_32_LDAPSTL_UNSCALED: return "ldapurh.xml";
		case ENC_LDAPURSB_32_LDAPSTL_UNSCALED: return "ldapursb.xml";
		case ENC_LDAPURSB_64_LDAPSTL_UNSCALED: return "ldapursb.xml";
		case ENC_LDAPURSH_32_LDAPSTL_UNSCALED: return "ldapursh.xml";
		case ENC_LDAPURSH_64_LDAPSTL_UNSCALED: return "ldapursh.xml";
		case ENC_LDAPURSW_64_LDAPSTL_UNSCALED: return "ldapursw.xml";
		case ENC_LDAPUR_32_LDAPSTL_UNSCALED: return "ldapur_gen.xml";
		case ENC_LDAPUR_64_LDAPSTL_UNSCALED: return "ldapur_gen.xml";
		case ENC_LDARB_LR32_LDSTEXCL: return "ldarb.xml";
		case ENC_LDARH_LR32_LDSTEXCL: return "ldarh.xml";
		case ENC_LDAR_LR32_LDSTEXCL: return "ldar.xml";
		case ENC_LDAR_LR64_LDSTEXCL: return "ldar.xml";
		case ENC_LDAXP_LP32_LDSTEXCL: return "ldaxp.xml";
		case ENC_LDAXP_LP64_LDSTEXCL: return "ldaxp.xml";
		case ENC_LDAXRB_LR32_LDSTEXCL: return "ldaxrb.xml";
		case ENC_LDAXRH_LR32_LDSTEXCL: return "ldaxrh.xml";
		case ENC_LDAXR_LR32_LDSTEXCL: return "ldaxr.xml";
		case ENC_LDAXR_LR64_LDSTEXCL: return "ldaxr.xml";
		case ENC_LDCLRAB_32_MEMOP: return "ldclrb.xml";
		case ENC_LDCLRAH_32_MEMOP: return "ldclrh.xml";
		case ENC_LDCLRALB_32_MEMOP: return "ldclrb.xml";
		case ENC_LDCLRALH_32_MEMOP: return "ldclrh.xml";
		case ENC_LDCLRAL_32_MEMOP: return "ldclr.xml";
		case ENC_LDCLRAL_64_MEMOP: return "ldclr.xml";
		case ENC_LDCLRA_32_MEMOP: return "ldclr.xml";
		case ENC_LDCLRA_64_MEMOP: return "ldclr.xml";
		case ENC_LDCLRB_32_MEMOP: return "ldclrb.xml";
		case ENC_LDCLRH_32_MEMOP: return "ldclrh.xml";
		case ENC_LDCLRLB_32_MEMOP: return "ldclrb.xml";
		case ENC_LDCLRLH_32_MEMOP: return "ldclrh.xml";
		case ENC_LDCLRL_32_MEMOP: return "ldclr.xml";
		case ENC_LDCLRL_64_MEMOP: return "ldclr.xml";
		case ENC_LDCLR_32_MEMOP: return "ldclr.xml";
		case ENC_LDCLR_64_MEMOP: return "ldclr.xml";
		case ENC_LDEORAB_32_MEMOP: return "ldeorb.xml";
		case ENC_LDEORAH_32_MEMOP: return "ldeorh.xml";
		case ENC_LDEORALB_32_MEMOP: return "ldeorb.xml";
		case ENC_LDEORALH_32_MEMOP: return "ldeorh.xml";
		case ENC_LDEORAL_32_MEMOP: return "ldeor.xml";
		case ENC_LDEORAL_64_MEMOP: return "ldeor.xml";
		case ENC_LDEORA_32_MEMOP: return "ldeor.xml";
		case ENC_LDEORA_64_MEMOP: return "ldeor.xml";
		case ENC_LDEORB_32_MEMOP: return "ldeorb.xml";
		case ENC_LDEORH_32_MEMOP: return "ldeorh.xml";
		case ENC_LDEORLB_32_MEMOP: return "ldeorb.xml";
		case ENC_LDEORLH_32_MEMOP: return "ldeorh.xml";
		case ENC_LDEORL_32_MEMOP: return "ldeor.xml";
		case ENC_LDEORL_64_MEMOP: return "ldeor.xml";
		case ENC_LDEOR_32_MEMOP: return "ldeor.xml";
		case ENC_LDEOR_64_MEMOP: return "ldeor.xml";
		case ENC_LDGM_64BULK_LDSTTAGS: return "ldgm.xml";
		case ENC_LDG_64LOFFSET_LDSTTAGS: return "ldg.xml";
		case ENC_LDLARB_LR32_LDSTEXCL: return "ldlarb.xml";
		case ENC_LDLARH_LR32_LDSTEXCL: return "ldlarh.xml";
		case ENC_LDLAR_LR32_LDSTEXCL: return "ldlar.xml";
		case ENC_LDLAR_LR64_LDSTEXCL: return "ldlar.xml";
		case ENC_LDNP_32_LDSTNAPAIR_OFFS: return "ldnp_gen.xml";
		case ENC_LDNP_64_LDSTNAPAIR_OFFS: return "ldnp_gen.xml";
		case ENC_LDNP_D_LDSTNAPAIR_OFFS: return "ldnp_fpsimd.xml";
		case ENC_LDNP_Q_LDSTNAPAIR_OFFS: return "ldnp_fpsimd.xml";
		case ENC_LDNP_S_LDSTNAPAIR_OFFS: return "ldnp_fpsimd.xml";
		case ENC_LDPSW_64_LDSTPAIR_OFF: return "ldpsw.xml";
		case ENC_LDPSW_64_LDSTPAIR_POST: return "ldpsw.xml";
		case ENC_LDPSW_64_LDSTPAIR_PRE: return "ldpsw.xml";
		case ENC_LDP_32_LDSTPAIR_OFF: return "ldp_gen.xml";
		case ENC_LDP_32_LDSTPAIR_POST: return "ldp_gen.xml";
		case ENC_LDP_32_LDSTPAIR_PRE: return "ldp_gen.xml";
		case ENC_LDP_64_LDSTPAIR_OFF: return "ldp_gen.xml";
		case ENC_LDP_64_LDSTPAIR_POST: return "ldp_gen.xml";
		case ENC_LDP_64_LDSTPAIR_PRE: return "ldp_gen.xml";
		case ENC_LDP_D_LDSTPAIR_OFF: return "ldp_fpsimd.xml";
		case ENC_LDP_D_LDSTPAIR_POST: return "ldp_fpsimd.xml";
		case ENC_LDP_D_LDSTPAIR_PRE: return "ldp_fpsimd.xml";
		case ENC_LDP_Q_LDSTPAIR_OFF: return "ldp_fpsimd.xml";
		case ENC_LDP_Q_LDSTPAIR_POST: return "ldp_fpsimd.xml";
		case ENC_LDP_Q_LDSTPAIR_PRE: return "ldp_fpsimd.xml";
		case ENC_LDP_S_LDSTPAIR_OFF: return "ldp_fpsimd.xml";
		case ENC_LDP_S_LDSTPAIR_POST: return "ldp_fpsimd.xml";
		case ENC_LDP_S_LDSTPAIR_PRE: return "ldp_fpsimd.xml";
		case ENC_LDRAA_64W_LDST_PAC: return "ldra.xml";
		case ENC_LDRAA_64_LDST_PAC: return "ldra.xml";
		case ENC_LDRAB_64W_LDST_PAC: return "ldra.xml";
		case ENC_LDRAB_64_LDST_PAC: return "ldra.xml";
		case ENC_LDRB_32BL_LDST_REGOFF: return "ldrb_reg.xml";
		case ENC_LDRB_32B_LDST_REGOFF: return "ldrb_reg.xml";
		case ENC_LDRB_32_LDST_IMMPOST: return "ldrb_imm.xml";
		case ENC_LDRB_32_LDST_IMMPRE: return "ldrb_imm.xml";
		case ENC_LDRB_32_LDST_POS: return "ldrb_imm.xml";
		case ENC_LDRH_32_LDST_IMMPOST: return "ldrh_imm.xml";
		case ENC_LDRH_32_LDST_IMMPRE: return "ldrh_imm.xml";
		case ENC_LDRH_32_LDST_POS: return "ldrh_imm.xml";
		case ENC_LDRH_32_LDST_REGOFF: return "ldrh_reg.xml";
		case ENC_LDRSB_32BL_LDST_REGOFF: return "ldrsb_reg.xml";
		case ENC_LDRSB_32B_LDST_REGOFF: return "ldrsb_reg.xml";
		case ENC_LDRSB_32_LDST_IMMPOST: return "ldrsb_imm.xml";
		case ENC_LDRSB_32_LDST_IMMPRE: return "ldrsb_imm.xml";
		case ENC_LDRSB_32_LDST_POS: return "ldrsb_imm.xml";
		case ENC_LDRSB_64BL_LDST_REGOFF: return "ldrsb_reg.xml";
		case ENC_LDRSB_64B_LDST_REGOFF: return "ldrsb_reg.xml";
		case ENC_LDRSB_64_LDST_IMMPOST: return "ldrsb_imm.xml";
		case ENC_LDRSB_64_LDST_IMMPRE: return "ldrsb_imm.xml";
		case ENC_LDRSB_64_LDST_POS: return "ldrsb_imm.xml";
		case ENC_LDRSH_32_LDST_IMMPOST: return "ldrsh_imm.xml";
		case ENC_LDRSH_32_LDST_IMMPRE: return "ldrsh_imm.xml";
		case ENC_LDRSH_32_LDST_POS: return "ldrsh_imm.xml";
		case ENC_LDRSH_32_LDST_REGOFF: return "ldrsh_reg.xml";
		case ENC_LDRSH_64_LDST_IMMPOST: return "ldrsh_imm.xml";
		case ENC_LDRSH_64_LDST_IMMPRE: return "ldrsh_imm.xml";
		case ENC_LDRSH_64_LDST_POS: return "ldrsh_imm.xml";
		case ENC_LDRSH_64_LDST_REGOFF: return "ldrsh_reg.xml";
		case ENC_LDRSW_64_LDST_IMMPOST: return "ldrsw_imm.xml";
		case ENC_LDRSW_64_LDST_IMMPRE: return "ldrsw_imm.xml";
		case ENC_LDRSW_64_LDST_POS: return "ldrsw_imm.xml";
		case ENC_LDRSW_64_LDST_REGOFF: return "ldrsw_reg.xml";
		case ENC_LDRSW_64_LOADLIT: return "ldrsw_lit.xml";
		case ENC_LDR_32_LDST_IMMPOST: return "ldr_imm_gen.xml";
		case ENC_LDR_32_LDST_IMMPRE: return "ldr_imm_gen.xml";
		case ENC_LDR_32_LDST_POS: return "ldr_imm_gen.xml";
		case ENC_LDR_32_LDST_REGOFF: return "ldr_reg_gen.xml";
		case ENC_LDR_32_LOADLIT: return "ldr_lit_gen.xml";
		case ENC_LDR_64_LDST_IMMPOST: return "ldr_imm_gen.xml";
		case ENC_LDR_64_LDST_IMMPRE: return "ldr_imm_gen.xml";
		case ENC_LDR_64_LDST_POS: return "ldr_imm_gen.xml";
		case ENC_LDR_64_LDST_REGOFF: return "ldr_reg_gen.xml";
		case ENC_LDR_64_LOADLIT: return "ldr_lit_gen.xml";
		case ENC_LDR_BL_LDST_REGOFF: return "ldr_reg_fpsimd.xml";
		case ENC_LDR_B_LDST_IMMPOST: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_B_LDST_IMMPRE: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_B_LDST_POS: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_B_LDST_REGOFF: return "ldr_reg_fpsimd.xml";
		case ENC_LDR_D_LDST_IMMPOST: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_D_LDST_IMMPRE: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_D_LDST_POS: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_D_LDST_REGOFF: return "ldr_reg_fpsimd.xml";
		case ENC_LDR_D_LOADLIT: return "ldr_lit_fpsimd.xml";
		case ENC_LDR_H_LDST_IMMPOST: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_H_LDST_IMMPRE: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_H_LDST_POS: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_H_LDST_REGOFF: return "ldr_reg_fpsimd.xml";
		case ENC_LDR_Q_LDST_IMMPOST: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_Q_LDST_IMMPRE: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_Q_LDST_POS: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_Q_LDST_REGOFF: return "ldr_reg_fpsimd.xml";
		case ENC_LDR_Q_LOADLIT: return "ldr_lit_fpsimd.xml";
		case ENC_LDR_S_LDST_IMMPOST: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_S_LDST_IMMPRE: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_S_LDST_POS: return "ldr_imm_fpsimd.xml";
		case ENC_LDR_S_LDST_REGOFF: return "ldr_reg_fpsimd.xml";
		case ENC_LDR_S_LOADLIT: return "ldr_lit_fpsimd.xml";
		case ENC_LDSETAB_32_MEMOP: return "ldsetb.xml";
		case ENC_LDSETAH_32_MEMOP: return "ldseth.xml";
		case ENC_LDSETALB_32_MEMOP: return "ldsetb.xml";
		case ENC_LDSETALH_32_MEMOP: return "ldseth.xml";
		case ENC_LDSETAL_32_MEMOP: return "ldset.xml";
		case ENC_LDSETAL_64_MEMOP: return "ldset.xml";
		case ENC_LDSETA_32_MEMOP: return "ldset.xml";
		case ENC_LDSETA_64_MEMOP: return "ldset.xml";
		case ENC_LDSETB_32_MEMOP: return "ldsetb.xml";
		case ENC_LDSETH_32_MEMOP: return "ldseth.xml";
		case ENC_LDSETLB_32_MEMOP: return "ldsetb.xml";
		case ENC_LDSETLH_32_MEMOP: return "ldseth.xml";
		case ENC_LDSETL_32_MEMOP: return "ldset.xml";
		case ENC_LDSETL_64_MEMOP: return "ldset.xml";
		case ENC_LDSET_32_MEMOP: return "ldset.xml";
		case ENC_LDSET_64_MEMOP: return "ldset.xml";
		case ENC_LDSMAXAB_32_MEMOP: return "ldsmaxb.xml";
		case ENC_LDSMAXAH_32_MEMOP: return "ldsmaxh.xml";
		case ENC_LDSMAXALB_32_MEMOP: return "ldsmaxb.xml";
		case ENC_LDSMAXALH_32_MEMOP: return "ldsmaxh.xml";
		case ENC_LDSMAXAL_32_MEMOP: return "ldsmax.xml";
		case ENC_LDSMAXAL_64_MEMOP: return "ldsmax.xml";
		case ENC_LDSMAXA_32_MEMOP: return "ldsmax.xml";
		case ENC_LDSMAXA_64_MEMOP: return "ldsmax.xml";
		case ENC_LDSMAXB_32_MEMOP: return "ldsmaxb.xml";
		case ENC_LDSMAXH_32_MEMOP: return "ldsmaxh.xml";
		case ENC_LDSMAXLB_32_MEMOP: return "ldsmaxb.xml";
		case ENC_LDSMAXLH_32_MEMOP: return "ldsmaxh.xml";
		case ENC_LDSMAXL_32_MEMOP: return "ldsmax.xml";
		case ENC_LDSMAXL_64_MEMOP: return "ldsmax.xml";
		case ENC_LDSMAX_32_MEMOP: return "ldsmax.xml";
		case ENC_LDSMAX_64_MEMOP: return "ldsmax.xml";
		case ENC_LDSMINAB_32_MEMOP: return "ldsminb.xml";
		case ENC_LDSMINAH_32_MEMOP: return "ldsminh.xml";
		case ENC_LDSMINALB_32_MEMOP: return "ldsminb.xml";
		case ENC_LDSMINALH_32_MEMOP: return "ldsminh.xml";
		case ENC_LDSMINAL_32_MEMOP: return "ldsmin.xml";
		case ENC_LDSMINAL_64_MEMOP: return "ldsmin.xml";
		case ENC_LDSMINA_32_MEMOP: return "ldsmin.xml";
		case ENC_LDSMINA_64_MEMOP: return "ldsmin.xml";
		case ENC_LDSMINB_32_MEMOP: return "ldsminb.xml";
		case ENC_LDSMINH_32_MEMOP: return "ldsminh.xml";
		case ENC_LDSMINLB_32_MEMOP: return "ldsminb.xml";
		case ENC_LDSMINLH_32_MEMOP: return "ldsminh.xml";
		case ENC_LDSMINL_32_MEMOP: return "ldsmin.xml";
		case ENC_LDSMINL_64_MEMOP: return "ldsmin.xml";
		case ENC_LDSMIN_32_MEMOP: return "ldsmin.xml";
		case ENC_LDSMIN_64_MEMOP: return "ldsmin.xml";
		case ENC_LDTRB_32_LDST_UNPRIV: return "ldtrb.xml";
		case ENC_LDTRH_32_LDST_UNPRIV: return "ldtrh.xml";
		case ENC_LDTRSB_32_LDST_UNPRIV: return "ldtrsb.xml";
		case ENC_LDTRSB_64_LDST_UNPRIV: return "ldtrsb.xml";
		case ENC_LDTRSH_32_LDST_UNPRIV: return "ldtrsh.xml";
		case ENC_LDTRSH_64_LDST_UNPRIV: return "ldtrsh.xml";
		case ENC_LDTRSW_64_LDST_UNPRIV: return "ldtrsw.xml";
		case ENC_LDTR_32_LDST_UNPRIV: return "ldtr.xml";
		case ENC_LDTR_64_LDST_UNPRIV: return "ldtr.xml";
		case ENC_LDUMAXAB_32_MEMOP: return "ldumaxb.xml";
		case ENC_LDUMAXAH_32_MEMOP: return "ldumaxh.xml";
		case ENC_LDUMAXALB_32_MEMOP: return "ldumaxb.xml";
		case ENC_LDUMAXALH_32_MEMOP: return "ldumaxh.xml";
		case ENC_LDUMAXAL_32_MEMOP: return "ldumax.xml";
		case ENC_LDUMAXAL_64_MEMOP: return "ldumax.xml";
		case ENC_LDUMAXA_32_MEMOP: return "ldumax.xml";
		case ENC_LDUMAXA_64_MEMOP: return "ldumax.xml";
		case ENC_LDUMAXB_32_MEMOP: return "ldumaxb.xml";
		case ENC_LDUMAXH_32_MEMOP: return "ldumaxh.xml";
		case ENC_LDUMAXLB_32_MEMOP: return "ldumaxb.xml";
		case ENC_LDUMAXLH_32_MEMOP: return "ldumaxh.xml";
		case ENC_LDUMAXL_32_MEMOP: return "ldumax.xml";
		case ENC_LDUMAXL_64_MEMOP: return "ldumax.xml";
		case ENC_LDUMAX_32_MEMOP: return "ldumax.xml";
		case ENC_LDUMAX_64_MEMOP: return "ldumax.xml";
		case ENC_LDUMINAB_32_MEMOP: return "lduminb.xml";
		case ENC_LDUMINAH_32_MEMOP: return "lduminh.xml";
		case ENC_LDUMINALB_32_MEMOP: return "lduminb.xml";
		case ENC_LDUMINALH_32_MEMOP: return "lduminh.xml";
		case ENC_LDUMINAL_32_MEMOP: return "ldumin.xml";
		case ENC_LDUMINAL_64_MEMOP: return "ldumin.xml";
		case ENC_LDUMINA_32_MEMOP: return "ldumin.xml";
		case ENC_LDUMINA_64_MEMOP: return "ldumin.xml";
		case ENC_LDUMINB_32_MEMOP: return "lduminb.xml";
		case ENC_LDUMINH_32_MEMOP: return "lduminh.xml";
		case ENC_LDUMINLB_32_MEMOP: return "lduminb.xml";
		case ENC_LDUMINLH_32_MEMOP: return "lduminh.xml";
		case ENC_LDUMINL_32_MEMOP: return "ldumin.xml";
		case ENC_LDUMINL_64_MEMOP: return "ldumin.xml";
		case ENC_LDUMIN_32_MEMOP: return "ldumin.xml";
		case ENC_LDUMIN_64_MEMOP: return "ldumin.xml";
		case ENC_LDURB_32_LDST_UNSCALED: return "ldurb.xml";
		case ENC_LDURH_32_LDST_UNSCALED: return "ldurh.xml";
		case ENC_LDURSB_32_LDST_UNSCALED: return "ldursb.xml";
		case ENC_LDURSB_64_LDST_UNSCALED: return "ldursb.xml";
		case ENC_LDURSH_32_LDST_UNSCALED: return "ldursh.xml";
		case ENC_LDURSH_64_LDST_UNSCALED: return "ldursh.xml";
		case ENC_LDURSW_64_LDST_UNSCALED: return "ldursw.xml";
		case ENC_LDUR_32_LDST_UNSCALED: return "ldur_gen.xml";
		case ENC_LDUR_64_LDST_UNSCALED: return "ldur_gen.xml";
		case ENC_LDUR_B_LDST_UNSCALED: return "ldur_fpsimd.xml";
		case ENC_LDUR_D_LDST_UNSCALED: return "ldur_fpsimd.xml";
		case ENC_LDUR_H_LDST_UNSCALED: return "ldur_fpsimd.xml";
		case ENC_LDUR_Q_LDST_UNSCALED: return "ldur_fpsimd.xml";
		case ENC_LDUR_S_LDST_UNSCALED: return "ldur_fpsimd.xml";
		case ENC_LDXP_LP32_LDSTEXCL: return "ldxp.xml";
		case ENC_LDXP_LP64_LDSTEXCL: return "ldxp.xml";
		case ENC_LDXRB_LR32_LDSTEXCL: return "ldxrb.xml";
		case ENC_LDXRH_LR32_LDSTEXCL: return "ldxrh.xml";
		case ENC_LDXR_LR32_LDSTEXCL: return "ldxr.xml";
		case ENC_LDXR_LR64_LDSTEXCL: return "ldxr.xml";
		case ENC_LSLV_32_DP_2SRC: return "lslv.xml";
		case ENC_LSLV_64_DP_2SRC: return "lslv.xml";
		case ENC_LSL_LSLV_32_DP_2SRC: return "lsl_lslv.xml";
		case ENC_LSL_LSLV_64_DP_2SRC: return "lsl_lslv.xml";
		case ENC_LSL_UBFM_32M_BITFIELD: return "lsl_ubfm.xml";
		case ENC_LSL_UBFM_64M_BITFIELD: return "lsl_ubfm.xml";
		case ENC_LSRV_32_DP_2SRC: return "lsrv.xml";
		case ENC_LSRV_64_DP_2SRC: return "lsrv.xml";
		case ENC_LSR_LSRV_32_DP_2SRC: return "lsr_lsrv.xml";
		case ENC_LSR_LSRV_64_DP_2SRC: return "lsr_lsrv.xml";
		case ENC_LSR_UBFM_32M_BITFIELD: return "lsr_ubfm.xml";
		case ENC_LSR_UBFM_64M_BITFIELD: return "lsr_ubfm.xml";
		case ENC_MADD_32A_DP_3SRC: return "madd.xml";
		case ENC_MADD_64A_DP_3SRC: return "madd.xml";
		case ENC_MLA_ASIMDELEM_R: return "mla_advsimd_elt.xml";
		case ENC_MLA_ASIMDSAME_ONLY: return "mla_advsimd_vec.xml";
		case ENC_MLS_ASIMDELEM_R: return "mls_advsimd_elt.xml";
		case ENC_MLS_ASIMDSAME_ONLY: return "mls_advsimd_vec.xml";
		case ENC_MNEG_MSUB_32A_DP_3SRC: return "mneg_msub.xml";
		case ENC_MNEG_MSUB_64A_DP_3SRC: return "mneg_msub.xml";
		case ENC_MOVI_ASIMDIMM_D2_D: return "movi_advsimd.xml";
		case ENC_MOVI_ASIMDIMM_D_DS: return "movi_advsimd.xml";
		case ENC_MOVI_ASIMDIMM_L_HL: return "movi_advsimd.xml";
		case ENC_MOVI_ASIMDIMM_L_SL: return "movi_advsimd.xml";
		case ENC_MOVI_ASIMDIMM_M_SM: return "movi_advsimd.xml";
		case ENC_MOVI_ASIMDIMM_N_B: return "movi_advsimd.xml";
		case ENC_MOVK_32_MOVEWIDE: return "movk.xml";
		case ENC_MOVK_64_MOVEWIDE: return "movk.xml";
		case ENC_MOVN_32_MOVEWIDE: return "movn.xml";
		case ENC_MOVN_64_MOVEWIDE: return "movn.xml";
		case ENC_MOVS_ANDS_P_P_PP_Z: return "movs_and_p_p_pp.xml";
		case ENC_MOVS_ORRS_P_P_PP_Z: return "movs_orr_p_p_pp.xml";
		case ENC_MOVZ_32_MOVEWIDE: return "movz.xml";
		case ENC_MOVZ_64_MOVEWIDE: return "movz.xml";
		case ENC_MOV_ADD_32_ADDSUB_IMM: return "mov_add_addsub_imm.xml";
		case ENC_MOV_ADD_64_ADDSUB_IMM: return "mov_add_addsub_imm.xml";
		case ENC_MOV_DUP_ASISDONE_ONLY: return "mov_dup_advsimd_elt.xml";
		case ENC_MOV_INS_ASIMDINS_IR_R: return "mov_ins_advsimd_gen.xml";
		case ENC_MOV_INS_ASIMDINS_IV_V: return "mov_ins_advsimd_elt.xml";
		case ENC_MOV_MOVN_32_MOVEWIDE: return "mov_movn.xml";
		case ENC_MOV_MOVN_64_MOVEWIDE: return "mov_movn.xml";
		case ENC_MOV_MOVZ_32_MOVEWIDE: return "mov_movz.xml";
		case ENC_MOV_MOVZ_64_MOVEWIDE: return "mov_movz.xml";
		case ENC_MOV_ORR_32_LOG_IMM: return "mov_orr_log_imm.xml";
		case ENC_MOV_ORR_32_LOG_SHIFT: return "mov_orr_log_shift.xml";
		case ENC_MOV_ORR_64_LOG_IMM: return "mov_orr_log_imm.xml";
		case ENC_MOV_ORR_64_LOG_SHIFT: return "mov_orr_log_shift.xml";
		case ENC_MOV_ORR_ASIMDSAME_ONLY: return "mov_orr_advsimd_reg.xml";
		case ENC_MOV_UMOV_ASIMDINS_W_W: return "mov_umov_advsimd.xml";
		case ENC_MOV_UMOV_ASIMDINS_X_X: return "mov_umov_advsimd.xml";
		case ENC_MOV_AND_P_P_PP_Z: return "mov_and_p_p_pp.xml";
		case ENC_MOV_CPY_Z_O_I_: return "mov_cpy_z_o_i.xml";
		case ENC_MOV_CPY_Z_P_I_: return "mov_cpy_z_p_i.xml";
		case ENC_MOV_CPY_Z_P_R_: return "mov_cpy_z_p_r.xml";
		case ENC_MOV_CPY_Z_P_V_: return "mov_cpy_z_p_v.xml";
		case ENC_MOV_DUP_Z_I_: return "mov_dup_z_i.xml";
		case ENC_MOV_DUP_Z_R_: return "mov_dup_z_r.xml";
		case ENC_MOV_DUP_Z_ZI_: return "mov_dup_z_zi.xml";
		case ENC_MOV_DUP_Z_ZI_2: return "mov_dup_z_zi.xml";
		case ENC_MOV_DUPM_Z_I_: return "mov_dupm_z_i.xml";
		case ENC_MOV_ORR_P_P_PP_Z: return "mov_orr_p_p_pp.xml";
		case ENC_MOV_ORR_Z_ZZ_: return "mov_orr_z_zz.xml";
		case ENC_MOV_SEL_P_P_PP_: return "mov_sel_p_p_pp.xml";
		case ENC_MOV_SEL_Z_P_ZZ_: return "mov_sel_z_p_zz.xml";
		case ENC_MRS_RS_SYSTEMMOVE: return "mrs.xml";
		case ENC_MSR_SI_PSTATE: return "msr_imm.xml";
		case ENC_MSR_SR_SYSTEMMOVE: return "msr_reg.xml";
		case ENC_MSUB_32A_DP_3SRC: return "msub.xml";
		case ENC_MSUB_64A_DP_3SRC: return "msub.xml";
		case ENC_MUL_MADD_32A_DP_3SRC: return "mul_madd.xml";
		case ENC_MUL_MADD_64A_DP_3SRC: return "mul_madd.xml";
		case ENC_MUL_ASIMDELEM_R: return "mul_advsimd_elt.xml";
		case ENC_MUL_ASIMDSAME_ONLY: return "mul_advsimd_vec.xml";
		case ENC_MVNI_ASIMDIMM_L_HL: return "mvni_advsimd.xml";
		case ENC_MVNI_ASIMDIMM_L_SL: return "mvni_advsimd.xml";
		case ENC_MVNI_ASIMDIMM_M_SM: return "mvni_advsimd.xml";
		case ENC_MVN_NOT_ASIMDMISC_R: return "mvn_not_advsimd.xml";
		case ENC_MVN_ORN_32_LOG_SHIFT: return "mvn_orn_log_shift.xml";
		case ENC_MVN_ORN_64_LOG_SHIFT: return "mvn_orn_log_shift.xml";
		case ENC_NEGS_SUBS_32_ADDSUB_SHIFT: return "negs_subs_addsub_shift.xml";
		case ENC_NEGS_SUBS_64_ADDSUB_SHIFT: return "negs_subs_addsub_shift.xml";
		case ENC_NEG_SUB_32_ADDSUB_SHIFT: return "neg_sub_addsub_shift.xml";
		case ENC_NEG_SUB_64_ADDSUB_SHIFT: return "neg_sub_addsub_shift.xml";
		case ENC_NEG_ASIMDMISC_R: return "neg_advsimd.xml";
		case ENC_NEG_ASISDMISC_R: return "neg_advsimd.xml";
		case ENC_NGCS_SBCS_32_ADDSUB_CARRY: return "ngcs_sbcs.xml";
		case ENC_NGCS_SBCS_64_ADDSUB_CARRY: return "ngcs_sbcs.xml";
		case ENC_NGC_SBC_32_ADDSUB_CARRY: return "ngc_sbc.xml";
		case ENC_NGC_SBC_64_ADDSUB_CARRY: return "ngc_sbc.xml";
		case ENC_NOP_HI_HINTS: return "nop.xml";
		case ENC_NOTS_EORS_P_P_PP_Z: return "nots_eor_p_p_pp.xml";
		case ENC_NOT_ASIMDMISC_R: return "not_advsimd.xml";
		case ENC_NOT_EOR_P_P_PP_Z: return "not_eor_p_p_pp.xml";
		case ENC_ORN_32_LOG_SHIFT: return "orn_log_shift.xml";
		case ENC_ORN_64_LOG_SHIFT: return "orn_log_shift.xml";
		case ENC_ORN_ASIMDSAME_ONLY: return "orn_advsimd.xml";
		case ENC_ORN_ORR_Z_ZI_: return "orn_orr_z_zi.xml";
		case ENC_ORR_32_LOG_IMM: return "orr_log_imm.xml";
		case ENC_ORR_32_LOG_SHIFT: return "orr_log_shift.xml";
		case ENC_ORR_64_LOG_IMM: return "orr_log_imm.xml";
		case ENC_ORR_64_LOG_SHIFT: return "orr_log_shift.xml";
		case ENC_ORR_ASIMDIMM_L_HL: return "orr_advsimd_imm.xml";
		case ENC_ORR_ASIMDIMM_L_SL: return "orr_advsimd_imm.xml";
		case ENC_ORR_ASIMDSAME_ONLY: return "orr_advsimd_reg.xml";
		case ENC_PACDA_64P_DP_1SRC: return "pacda.xml";
		case ENC_PACDB_64P_DP_1SRC: return "pacdb.xml";
		case ENC_PACDZA_64Z_DP_1SRC: return "pacda.xml";
		case ENC_PACDZB_64Z_DP_1SRC: return "pacdb.xml";
		case ENC_PACGA_64P_DP_2SRC: return "pacga.xml";
		case ENC_PACIA1716_HI_HINTS: return "pacia.xml";
		case ENC_PACIASP_HI_HINTS: return "pacia.xml";
		case ENC_PACIAZ_HI_HINTS: return "pacia.xml";
		case ENC_PACIA_64P_DP_1SRC: return "pacia.xml";
		case ENC_PACIB1716_HI_HINTS: return "pacib.xml";
		case ENC_PACIBSP_HI_HINTS: return "pacib.xml";
		case ENC_PACIBZ_HI_HINTS: return "pacib.xml";
		case ENC_PACIB_64P_DP_1SRC: return "pacib.xml";
		case ENC_PACIZA_64Z_DP_1SRC: return "pacia.xml";
		case ENC_PACIZB_64Z_DP_1SRC: return "pacib.xml";
		case ENC_PMULL_ASIMDDIFF_L: return "pmull_advsimd.xml";
		case ENC_PMUL_ASIMDSAME_ONLY: return "pmul_advsimd.xml";
		case ENC_PRFM_P_LDST_POS: return "prfm_imm.xml";
		case ENC_PRFM_P_LDST_REGOFF: return "prfm_reg.xml";
		case ENC_PRFM_P_LOADLIT: return "prfm_lit.xml";
		case ENC_PRFUM_P_LDST_UNSCALED: return "prfum.xml";
		case ENC_PSB_HC_HINTS: return "psb.xml";
		case ENC_PSSBB_ONLY_BARRIERS: return "pssbb.xml";
		case ENC_RADDHN_ASIMDDIFF_N: return "raddhn_advsimd.xml";
		case ENC_RAX1_VVV2_CRYPTOSHA512_3: return "rax1_advsimd.xml";
		case ENC_RBIT_32_DP_1SRC: return "rbit_int.xml";
		case ENC_RBIT_64_DP_1SRC: return "rbit_int.xml";
		case ENC_RBIT_ASIMDMISC_R: return "rbit_advsimd.xml";
		case ENC_RETAA_64E_BRANCH_REG: return "reta.xml";
		case ENC_RETAB_64E_BRANCH_REG: return "reta.xml";
		case ENC_RET_64R_BRANCH_REG: return "ret.xml";
		case ENC_REV16_32_DP_1SRC: return "rev16_int.xml";
		case ENC_REV16_64_DP_1SRC: return "rev16_int.xml";
		case ENC_REV16_ASIMDMISC_R: return "rev16_advsimd.xml";
		case ENC_REV32_64_DP_1SRC: return "rev32_int.xml";
		case ENC_REV32_ASIMDMISC_R: return "rev32_advsimd.xml";
		case ENC_REV64_REV_64_DP_1SRC: return "rev64_rev.xml";
		case ENC_REV64_ASIMDMISC_R: return "rev64_advsimd.xml";
		case ENC_REV_32_DP_1SRC: return "rev.xml";
		case ENC_REV_64_DP_1SRC: return "rev.xml";
		case ENC_RMIF_ONLY_RMIF: return "rmif.xml";
		case ENC_RORV_32_DP_2SRC: return "rorv.xml";
		case ENC_RORV_64_DP_2SRC: return "rorv.xml";
		case ENC_ROR_EXTR_32_EXTRACT: return "ror_extr.xml";
		case ENC_ROR_EXTR_64_EXTRACT: return "ror_extr.xml";
		case ENC_ROR_RORV_32_DP_2SRC: return "ror_rorv.xml";
		case ENC_ROR_RORV_64_DP_2SRC: return "ror_rorv.xml";
		case ENC_RSHRN_ASIMDSHF_N: return "rshrn_advsimd.xml";
		case ENC_RSUBHN_ASIMDDIFF_N: return "rsubhn_advsimd.xml";
		case ENC_SABAL_ASIMDDIFF_L: return "sabal_advsimd.xml";
		case ENC_SABA_ASIMDSAME_ONLY: return "saba_advsimd.xml";
		case ENC_SABDL_ASIMDDIFF_L: return "sabdl_advsimd.xml";
		case ENC_SABD_ASIMDSAME_ONLY: return "sabd_advsimd.xml";
		case ENC_SADALP_ASIMDMISC_P: return "sadalp_advsimd.xml";
		case ENC_SADDLP_ASIMDMISC_P: return "saddlp_advsimd.xml";
		case ENC_SADDLV_ASIMDALL_ONLY: return "saddlv_advsimd.xml";
		case ENC_SADDL_ASIMDDIFF_L: return "saddl_advsimd.xml";
		case ENC_SADDW_ASIMDDIFF_W: return "saddw_advsimd.xml";
		case ENC_SBCS_32_ADDSUB_CARRY: return "sbcs.xml";
		case ENC_SBCS_64_ADDSUB_CARRY: return "sbcs.xml";
		case ENC_SBC_32_ADDSUB_CARRY: return "sbc.xml";
		case ENC_SBC_64_ADDSUB_CARRY: return "sbc.xml";
		case ENC_SBFIZ_SBFM_32M_BITFIELD: return "sbfiz_sbfm.xml";
		case ENC_SBFIZ_SBFM_64M_BITFIELD: return "sbfiz_sbfm.xml";
		case ENC_SBFM_32M_BITFIELD: return "sbfm.xml";
		case ENC_SBFM_64M_BITFIELD: return "sbfm.xml";
		case ENC_SBFX_SBFM_32M_BITFIELD: return "sbfx_sbfm.xml";
		case ENC_SBFX_SBFM_64M_BITFIELD: return "sbfx_sbfm.xml";
		case ENC_SB_ONLY_BARRIERS: return "sb.xml";
		case ENC_SCVTF_D32_FLOAT2FIX: return "scvtf_float_fix.xml";
		case ENC_SCVTF_D32_FLOAT2INT: return "scvtf_float_int.xml";
		case ENC_SCVTF_D64_FLOAT2FIX: return "scvtf_float_fix.xml";
		case ENC_SCVTF_D64_FLOAT2INT: return "scvtf_float_int.xml";
		case ENC_SCVTF_H32_FLOAT2FIX: return "scvtf_float_fix.xml";
		case ENC_SCVTF_H32_FLOAT2INT: return "scvtf_float_int.xml";
		case ENC_SCVTF_H64_FLOAT2FIX: return "scvtf_float_fix.xml";
		case ENC_SCVTF_H64_FLOAT2INT: return "scvtf_float_int.xml";
		case ENC_SCVTF_S32_FLOAT2FIX: return "scvtf_float_fix.xml";
		case ENC_SCVTF_S32_FLOAT2INT: return "scvtf_float_int.xml";
		case ENC_SCVTF_S64_FLOAT2FIX: return "scvtf_float_fix.xml";
		case ENC_SCVTF_S64_FLOAT2INT: return "scvtf_float_int.xml";
		case ENC_SCVTF_ASIMDMISC_R: return "scvtf_advsimd_int.xml";
		case ENC_SCVTF_ASIMDMISCFP16_R: return "scvtf_advsimd_int.xml";
		case ENC_SCVTF_ASIMDSHF_C: return "scvtf_advsimd_fix.xml";
		case ENC_SCVTF_ASISDMISC_R: return "scvtf_advsimd_int.xml";
		case ENC_SCVTF_ASISDMISCFP16_R: return "scvtf_advsimd_int.xml";
		case ENC_SCVTF_ASISDSHF_C: return "scvtf_advsimd_fix.xml";
		case ENC_SDIV_32_DP_2SRC: return "sdiv.xml";
		case ENC_SDIV_64_DP_2SRC: return "sdiv.xml";
		case ENC_SDOT_ASIMDELEM_D: return "sdot_advsimd_elt.xml";
		case ENC_SDOT_ASIMDSAME2_D: return "sdot_advsimd_vec.xml";
		case ENC_SETF16_ONLY_SETF: return "setf.xml";
		case ENC_SETF8_ONLY_SETF: return "setf.xml";
		case ENC_SEVL_HI_HINTS: return "sevl.xml";
		case ENC_SEV_HI_HINTS: return "sev.xml";
		case ENC_SHA1C_QSV_CRYPTOSHA3: return "sha1c_advsimd.xml";
		case ENC_SHA1H_SS_CRYPTOSHA2: return "sha1h_advsimd.xml";
		case ENC_SHA1M_QSV_CRYPTOSHA3: return "sha1m_advsimd.xml";
		case ENC_SHA1P_QSV_CRYPTOSHA3: return "sha1p_advsimd.xml";
		case ENC_SHA1SU0_VVV_CRYPTOSHA3: return "sha1su0_advsimd.xml";
		case ENC_SHA1SU1_VV_CRYPTOSHA2: return "sha1su1_advsimd.xml";
		case ENC_SHA256H2_QQV_CRYPTOSHA3: return "sha256h2_advsimd.xml";
		case ENC_SHA256H_QQV_CRYPTOSHA3: return "sha256h_advsimd.xml";
		case ENC_SHA256SU0_VV_CRYPTOSHA2: return "sha256su0_advsimd.xml";
		case ENC_SHA256SU1_VVV_CRYPTOSHA3: return "sha256su1_advsimd.xml";
		case ENC_SHA512H2_QQV_CRYPTOSHA512_3: return "sha512h2_advsimd.xml";
		case ENC_SHA512H_QQV_CRYPTOSHA512_3: return "sha512h_advsimd.xml";
		case ENC_SHA512SU0_VV2_CRYPTOSHA512_2: return "sha512su0_advsimd.xml";
		case ENC_SHA512SU1_VVV2_CRYPTOSHA512_3: return "sha512su1_advsimd.xml";
		case ENC_SHADD_ASIMDSAME_ONLY: return "shadd_advsimd.xml";
		case ENC_SHLL_ASIMDMISC_S: return "shll_advsimd.xml";
		case ENC_SHL_ASIMDSHF_R: return "shl_advsimd.xml";
		case ENC_SHL_ASISDSHF_R: return "shl_advsimd.xml";
		case ENC_SHRN_ASIMDSHF_N: return "shrn_advsimd.xml";
		case ENC_SHSUB_ASIMDSAME_ONLY: return "shsub_advsimd.xml";
		case ENC_SLI_ASIMDSHF_R: return "sli_advsimd.xml";
		case ENC_SLI_ASISDSHF_R: return "sli_advsimd.xml";
		case ENC_SM3PARTW1_VVV4_CRYPTOSHA512_3: return "sm3partw1_advsimd.xml";
		case ENC_SM3PARTW2_VVV4_CRYPTOSHA512_3: return "sm3partw2_advsimd.xml";
		case ENC_SM3SS1_VVV4_CRYPTO4: return "sm3ss1_advsimd.xml";
		case ENC_SM3TT1A_VVV4_CRYPTO3_IMM2: return "sm3tt1a_advsimd.xml";
		case ENC_SM3TT1B_VVV4_CRYPTO3_IMM2: return "sm3tt1b_advsimd.xml";
		case ENC_SM3TT2A_VVV4_CRYPTO3_IMM2: return "sm3tt2a_advsimd.xml";
		case ENC_SM3TT2B_VVV_CRYPTO3_IMM2: return "sm3tt2b_advsimd.xml";
		case ENC_SM4EKEY_VVV4_CRYPTOSHA512_3: return "sm4ekey_advsimd.xml";
		case ENC_SM4E_VV4_CRYPTOSHA512_2: return "sm4e_advsimd.xml";
		case ENC_SMADDL_64WA_DP_3SRC: return "smaddl.xml";
		case ENC_SMAXP_ASIMDSAME_ONLY: return "smaxp_advsimd.xml";
		case ENC_SMAXV_ASIMDALL_ONLY: return "smaxv_advsimd.xml";
		case ENC_SMAX_ASIMDSAME_ONLY: return "smax_advsimd.xml";
		case ENC_SMC_EX_EXCEPTION: return "smc.xml";
		case ENC_SMINP_ASIMDSAME_ONLY: return "sminp_advsimd.xml";
		case ENC_SMINV_ASIMDALL_ONLY: return "sminv_advsimd.xml";
		case ENC_SMIN_ASIMDSAME_ONLY: return "smin_advsimd.xml";
		case ENC_SMLAL_ASIMDDIFF_L: return "smlal_advsimd_vec.xml";
		case ENC_SMLAL_ASIMDELEM_L: return "smlal_advsimd_elt.xml";
		case ENC_SMLSL_ASIMDDIFF_L: return "smlsl_advsimd_vec.xml";
		case ENC_SMLSL_ASIMDELEM_L: return "smlsl_advsimd_elt.xml";
		case ENC_SMMLA_ASIMDSAME2_G: return "smmla_advsimd_vec.xml";
		case ENC_SMNEGL_SMSUBL_64WA_DP_3SRC: return "smnegl_smsubl.xml";
		case ENC_SMOV_ASIMDINS_W_W: return "smov_advsimd.xml";
		case ENC_SMOV_ASIMDINS_X_X: return "smov_advsimd.xml";
		case ENC_SMSUBL_64WA_DP_3SRC: return "smsubl.xml";
		case ENC_SMULH_64_DP_3SRC: return "smulh.xml";
		case ENC_SMULL_SMADDL_64WA_DP_3SRC: return "smull_smaddl.xml";
		case ENC_SMULL_ASIMDDIFF_L: return "smull_advsimd_vec.xml";
		case ENC_SMULL_ASIMDELEM_L: return "smull_advsimd_elt.xml";
		case ENC_SQABS_ASIMDMISC_R: return "sqabs_advsimd.xml";
		case ENC_SQABS_ASISDMISC_R: return "sqabs_advsimd.xml";
		case ENC_SQADD_ASIMDSAME_ONLY: return "sqadd_advsimd.xml";
		case ENC_SQADD_ASISDSAME_ONLY: return "sqadd_advsimd.xml";
		case ENC_SQDMLAL_ASIMDDIFF_L: return "sqdmlal_advsimd_vec.xml";
		case ENC_SQDMLAL_ASIMDELEM_L: return "sqdmlal_advsimd_elt.xml";
		case ENC_SQDMLAL_ASISDDIFF_ONLY: return "sqdmlal_advsimd_vec.xml";
		case ENC_SQDMLAL_ASISDELEM_L: return "sqdmlal_advsimd_elt.xml";
		case ENC_SQDMLSL_ASIMDDIFF_L: return "sqdmlsl_advsimd_vec.xml";
		case ENC_SQDMLSL_ASIMDELEM_L: return "sqdmlsl_advsimd_elt.xml";
		case ENC_SQDMLSL_ASISDDIFF_ONLY: return "sqdmlsl_advsimd_vec.xml";
		case ENC_SQDMLSL_ASISDELEM_L: return "sqdmlsl_advsimd_elt.xml";
		case ENC_SQDMULH_ASIMDELEM_R: return "sqdmulh_advsimd_elt.xml";
		case ENC_SQDMULH_ASIMDSAME_ONLY: return "sqdmulh_advsimd_vec.xml";
		case ENC_SQDMULH_ASISDELEM_R: return "sqdmulh_advsimd_elt.xml";
		case ENC_SQDMULH_ASISDSAME_ONLY: return "sqdmulh_advsimd_vec.xml";
		case ENC_SQDMULL_ASIMDDIFF_L: return "sqdmull_advsimd_vec.xml";
		case ENC_SQDMULL_ASIMDELEM_L: return "sqdmull_advsimd_elt.xml";
		case ENC_SQDMULL_ASISDDIFF_ONLY: return "sqdmull_advsimd_vec.xml";
		case ENC_SQDMULL_ASISDELEM_L: return "sqdmull_advsimd_elt.xml";
		case ENC_SQNEG_ASIMDMISC_R: return "sqneg_advsimd.xml";
		case ENC_SQNEG_ASISDMISC_R: return "sqneg_advsimd.xml";
		case ENC_SQRDMLAH_ASIMDELEM_R: return "sqrdmlah_advsimd_elt.xml";
		case ENC_SQRDMLAH_ASIMDSAME2_ONLY: return "sqrdmlah_advsimd_vec.xml";
		case ENC_SQRDMLAH_ASISDELEM_R: return "sqrdmlah_advsimd_elt.xml";
		case ENC_SQRDMLAH_ASISDSAME2_ONLY: return "sqrdmlah_advsimd_vec.xml";
		case ENC_SQRDMLSH_ASIMDELEM_R: return "sqrdmlsh_advsimd_elt.xml";
		case ENC_SQRDMLSH_ASIMDSAME2_ONLY: return "sqrdmlsh_advsimd_vec.xml";
		case ENC_SQRDMLSH_ASISDELEM_R: return "sqrdmlsh_advsimd_elt.xml";
		case ENC_SQRDMLSH_ASISDSAME2_ONLY: return "sqrdmlsh_advsimd_vec.xml";
		case ENC_SQRDMULH_ASIMDELEM_R: return "sqrdmulh_advsimd_elt.xml";
		case ENC_SQRDMULH_ASIMDSAME_ONLY: return "sqrdmulh_advsimd_vec.xml";
		case ENC_SQRDMULH_ASISDELEM_R: return "sqrdmulh_advsimd_elt.xml";
		case ENC_SQRDMULH_ASISDSAME_ONLY: return "sqrdmulh_advsimd_vec.xml";
		case ENC_SQRSHL_ASIMDSAME_ONLY: return "sqrshl_advsimd.xml";
		case ENC_SQRSHL_ASISDSAME_ONLY: return "sqrshl_advsimd.xml";
		case ENC_SQRSHRN_ASIMDSHF_N: return "sqrshrn_advsimd.xml";
		case ENC_SQRSHRN_ASISDSHF_N: return "sqrshrn_advsimd.xml";
		case ENC_SQRSHRUN_ASIMDSHF_N: return "sqrshrun_advsimd.xml";
		case ENC_SQRSHRUN_ASISDSHF_N: return "sqrshrun_advsimd.xml";
		case ENC_SQSHLU_ASIMDSHF_R: return "sqshlu_advsimd.xml";
		case ENC_SQSHLU_ASISDSHF_R: return "sqshlu_advsimd.xml";
		case ENC_SQSHL_ASIMDSAME_ONLY: return "sqshl_advsimd_reg.xml";
		case ENC_SQSHL_ASIMDSHF_R: return "sqshl_advsimd_imm.xml";
		case ENC_SQSHL_ASISDSAME_ONLY: return "sqshl_advsimd_reg.xml";
		case ENC_SQSHL_ASISDSHF_R: return "sqshl_advsimd_imm.xml";
		case ENC_SQSHRN_ASIMDSHF_N: return "sqshrn_advsimd.xml";
		case ENC_SQSHRN_ASISDSHF_N: return "sqshrn_advsimd.xml";
		case ENC_SQSHRUN_ASIMDSHF_N: return "sqshrun_advsimd.xml";
		case ENC_SQSHRUN_ASISDSHF_N: return "sqshrun_advsimd.xml";
		case ENC_SQSUB_ASIMDSAME_ONLY: return "sqsub_advsimd.xml";
		case ENC_SQSUB_ASISDSAME_ONLY: return "sqsub_advsimd.xml";
		case ENC_SQXTN_ASIMDMISC_N: return "sqxtn_advsimd.xml";
		case ENC_SQXTN_ASISDMISC_N: return "sqxtn_advsimd.xml";
		case ENC_SQXTUN_ASIMDMISC_N: return "sqxtun_advsimd.xml";
		case ENC_SQXTUN_ASISDMISC_N: return "sqxtun_advsimd.xml";
		case ENC_SRHADD_ASIMDSAME_ONLY: return "srhadd_advsimd.xml";
		case ENC_SRI_ASIMDSHF_R: return "sri_advsimd.xml";
		case ENC_SRI_ASISDSHF_R: return "sri_advsimd.xml";
		case ENC_SRSHL_ASIMDSAME_ONLY: return "srshl_advsimd.xml";
		case ENC_SRSHL_ASISDSAME_ONLY: return "srshl_advsimd.xml";
		case ENC_SRSHR_ASIMDSHF_R: return "srshr_advsimd.xml";
		case ENC_SRSHR_ASISDSHF_R: return "srshr_advsimd.xml";
		case ENC_SRSRA_ASIMDSHF_R: return "srsra_advsimd.xml";
		case ENC_SRSRA_ASISDSHF_R: return "srsra_advsimd.xml";
		case ENC_SSBB_ONLY_BARRIERS: return "ssbb.xml";
		case ENC_SSHLL_ASIMDSHF_L: return "sshll_advsimd.xml";
		case ENC_SSHL_ASIMDSAME_ONLY: return "sshl_advsimd.xml";
		case ENC_SSHL_ASISDSAME_ONLY: return "sshl_advsimd.xml";
		case ENC_SSHR_ASIMDSHF_R: return "sshr_advsimd.xml";
		case ENC_SSHR_ASISDSHF_R: return "sshr_advsimd.xml";
		case ENC_SSRA_ASIMDSHF_R: return "ssra_advsimd.xml";
		case ENC_SSRA_ASISDSHF_R: return "ssra_advsimd.xml";
		case ENC_SSUBL_ASIMDDIFF_L: return "ssubl_advsimd.xml";
		case ENC_SSUBW_ASIMDDIFF_W: return "ssubw_advsimd.xml";
		case ENC_ST1_ASISDLSE_R1_1V: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSE_R2_2V: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSE_R3_3V: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSE_R4_4V: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSEP_I1_I1: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSEP_I2_I2: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSEP_I3_I3: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSEP_I4_I4: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSEP_R1_R1: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSEP_R2_R2: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSEP_R3_R3: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSEP_R4_R4: return "st1_advsimd_mult.xml";
		case ENC_ST1_ASISDLSO_B1_1B: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSO_D1_1D: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSO_H1_1H: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSO_S1_1S: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSOP_B1_I1B: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSOP_BX1_R1B: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSOP_D1_I1D: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSOP_DX1_R1D: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSOP_H1_I1H: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSOP_HX1_R1H: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSOP_S1_I1S: return "st1_advsimd_sngl.xml";
		case ENC_ST1_ASISDLSOP_SX1_R1S: return "st1_advsimd_sngl.xml";
		case ENC_ST2G_64SOFFSET_LDSTTAGS: return "st2g.xml";
		case ENC_ST2G_64SPOST_LDSTTAGS: return "st2g.xml";
		case ENC_ST2G_64SPRE_LDSTTAGS: return "st2g.xml";
		case ENC_ST2_ASISDLSE_R2: return "st2_advsimd_mult.xml";
		case ENC_ST2_ASISDLSEP_I2_I: return "st2_advsimd_mult.xml";
		case ENC_ST2_ASISDLSEP_R2_R: return "st2_advsimd_mult.xml";
		case ENC_ST2_ASISDLSO_B2_2B: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSO_D2_2D: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSO_H2_2H: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSO_S2_2S: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSOP_B2_I2B: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSOP_BX2_R2B: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSOP_D2_I2D: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSOP_DX2_R2D: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSOP_H2_I2H: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSOP_HX2_R2H: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSOP_S2_I2S: return "st2_advsimd_sngl.xml";
		case ENC_ST2_ASISDLSOP_SX2_R2S: return "st2_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSE_R3: return "st3_advsimd_mult.xml";
		case ENC_ST3_ASISDLSEP_I3_I: return "st3_advsimd_mult.xml";
		case ENC_ST3_ASISDLSEP_R3_R: return "st3_advsimd_mult.xml";
		case ENC_ST3_ASISDLSO_B3_3B: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSO_D3_3D: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSO_H3_3H: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSO_S3_3S: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSOP_B3_I3B: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSOP_BX3_R3B: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSOP_D3_I3D: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSOP_DX3_R3D: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSOP_H3_I3H: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSOP_HX3_R3H: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSOP_S3_I3S: return "st3_advsimd_sngl.xml";
		case ENC_ST3_ASISDLSOP_SX3_R3S: return "st3_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSE_R4: return "st4_advsimd_mult.xml";
		case ENC_ST4_ASISDLSEP_I4_I: return "st4_advsimd_mult.xml";
		case ENC_ST4_ASISDLSEP_R4_R: return "st4_advsimd_mult.xml";
		case ENC_ST4_ASISDLSO_B4_4B: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSO_D4_4D: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSO_H4_4H: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSO_S4_4S: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSOP_B4_I4B: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSOP_BX4_R4B: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSOP_D4_I4D: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSOP_DX4_R4D: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSOP_H4_I4H: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSOP_HX4_R4H: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSOP_S4_I4S: return "st4_advsimd_sngl.xml";
		case ENC_ST4_ASISDLSOP_SX4_R4S: return "st4_advsimd_sngl.xml";
		case ENC_STADDB_LDADDB_32_MEMOP: return "staddb_ldaddb.xml";
		case ENC_STADDH_LDADDH_32_MEMOP: return "staddh_ldaddh.xml";
		case ENC_STADDLB_LDADDLB_32_MEMOP: return "staddb_ldaddb.xml";
		case ENC_STADDLH_LDADDLH_32_MEMOP: return "staddh_ldaddh.xml";
		case ENC_STADDL_LDADDL_32_MEMOP: return "stadd_ldadd.xml";
		case ENC_STADDL_LDADDL_64_MEMOP: return "stadd_ldadd.xml";
		case ENC_STADD_LDADD_32_MEMOP: return "stadd_ldadd.xml";
		case ENC_STADD_LDADD_64_MEMOP: return "stadd_ldadd.xml";
		case ENC_STCLRB_LDCLRB_32_MEMOP: return "stclrb_ldclrb.xml";
		case ENC_STCLRH_LDCLRH_32_MEMOP: return "stclrh_ldclrh.xml";
		case ENC_STCLRLB_LDCLRLB_32_MEMOP: return "stclrb_ldclrb.xml";
		case ENC_STCLRLH_LDCLRLH_32_MEMOP: return "stclrh_ldclrh.xml";
		case ENC_STCLRL_LDCLRL_32_MEMOP: return "stclr_ldclr.xml";
		case ENC_STCLRL_LDCLRL_64_MEMOP: return "stclr_ldclr.xml";
		case ENC_STCLR_LDCLR_32_MEMOP: return "stclr_ldclr.xml";
		case ENC_STCLR_LDCLR_64_MEMOP: return "stclr_ldclr.xml";
		case ENC_STEORB_LDEORB_32_MEMOP: return "steorb_ldeorb.xml";
		case ENC_STEORH_LDEORH_32_MEMOP: return "steorh_ldeorh.xml";
		case ENC_STEORLB_LDEORLB_32_MEMOP: return "steorb_ldeorb.xml";
		case ENC_STEORLH_LDEORLH_32_MEMOP: return "steorh_ldeorh.xml";
		case ENC_STEORL_LDEORL_32_MEMOP: return "steor_ldeor.xml";
		case ENC_STEORL_LDEORL_64_MEMOP: return "steor_ldeor.xml";
		case ENC_STEOR_LDEOR_32_MEMOP: return "steor_ldeor.xml";
		case ENC_STEOR_LDEOR_64_MEMOP: return "steor_ldeor.xml";
		case ENC_STGM_64BULK_LDSTTAGS: return "stgm.xml";
		case ENC_STGP_64_LDSTPAIR_OFF: return "stgp.xml";
		case ENC_STGP_64_LDSTPAIR_POST: return "stgp.xml";
		case ENC_STGP_64_LDSTPAIR_PRE: return "stgp.xml";
		case ENC_STG_64SOFFSET_LDSTTAGS: return "stg.xml";
		case ENC_STG_64SPOST_LDSTTAGS: return "stg.xml";
		case ENC_STG_64SPRE_LDSTTAGS: return "stg.xml";
		case ENC_STLLRB_SL32_LDSTEXCL: return "stllrb.xml";
		case ENC_STLLRH_SL32_LDSTEXCL: return "stllrh.xml";
		case ENC_STLLR_SL32_LDSTEXCL: return "stllr.xml";
		case ENC_STLLR_SL64_LDSTEXCL: return "stllr.xml";
		case ENC_STLRB_SL32_LDSTEXCL: return "stlrb.xml";
		case ENC_STLRH_SL32_LDSTEXCL: return "stlrh.xml";
		case ENC_STLR_SL32_LDSTEXCL: return "stlr.xml";
		case ENC_STLR_SL64_LDSTEXCL: return "stlr.xml";
		case ENC_STLURB_32_LDAPSTL_UNSCALED: return "stlurb.xml";
		case ENC_STLURH_32_LDAPSTL_UNSCALED: return "stlurh.xml";
		case ENC_STLUR_32_LDAPSTL_UNSCALED: return "stlur_gen.xml";
		case ENC_STLUR_64_LDAPSTL_UNSCALED: return "stlur_gen.xml";
		case ENC_STLXP_SP32_LDSTEXCL: return "stlxp.xml";
		case ENC_STLXP_SP64_LDSTEXCL: return "stlxp.xml";
		case ENC_STLXRB_SR32_LDSTEXCL: return "stlxrb.xml";
		case ENC_STLXRH_SR32_LDSTEXCL: return "stlxrh.xml";
		case ENC_STLXR_SR32_LDSTEXCL: return "stlxr.xml";
		case ENC_STLXR_SR64_LDSTEXCL: return "stlxr.xml";
		case ENC_STNP_32_LDSTNAPAIR_OFFS: return "stnp_gen.xml";
		case ENC_STNP_64_LDSTNAPAIR_OFFS: return "stnp_gen.xml";
		case ENC_STNP_D_LDSTNAPAIR_OFFS: return "stnp_fpsimd.xml";
		case ENC_STNP_Q_LDSTNAPAIR_OFFS: return "stnp_fpsimd.xml";
		case ENC_STNP_S_LDSTNAPAIR_OFFS: return "stnp_fpsimd.xml";
		case ENC_STP_32_LDSTPAIR_OFF: return "stp_gen.xml";
		case ENC_STP_32_LDSTPAIR_POST: return "stp_gen.xml";
		case ENC_STP_32_LDSTPAIR_PRE: return "stp_gen.xml";
		case ENC_STP_64_LDSTPAIR_OFF: return "stp_gen.xml";
		case ENC_STP_64_LDSTPAIR_POST: return "stp_gen.xml";
		case ENC_STP_64_LDSTPAIR_PRE: return "stp_gen.xml";
		case ENC_STP_D_LDSTPAIR_OFF: return "stp_fpsimd.xml";
		case ENC_STP_D_LDSTPAIR_POST: return "stp_fpsimd.xml";
		case ENC_STP_D_LDSTPAIR_PRE: return "stp_fpsimd.xml";
		case ENC_STP_Q_LDSTPAIR_OFF: return "stp_fpsimd.xml";
		case ENC_STP_Q_LDSTPAIR_POST: return "stp_fpsimd.xml";
		case ENC_STP_Q_LDSTPAIR_PRE: return "stp_fpsimd.xml";
		case ENC_STP_S_LDSTPAIR_OFF: return "stp_fpsimd.xml";
		case ENC_STP_S_LDSTPAIR_POST: return "stp_fpsimd.xml";
		case ENC_STP_S_LDSTPAIR_PRE: return "stp_fpsimd.xml";
		case ENC_STRB_32BL_LDST_REGOFF: return "strb_reg.xml";
		case ENC_STRB_32B_LDST_REGOFF: return "strb_reg.xml";
		case ENC_STRB_32_LDST_IMMPOST: return "strb_imm.xml";
		case ENC_STRB_32_LDST_IMMPRE: return "strb_imm.xml";
		case ENC_STRB_32_LDST_POS: return "strb_imm.xml";
		case ENC_STRH_32_LDST_IMMPOST: return "strh_imm.xml";
		case ENC_STRH_32_LDST_IMMPRE: return "strh_imm.xml";
		case ENC_STRH_32_LDST_POS: return "strh_imm.xml";
		case ENC_STRH_32_LDST_REGOFF: return "strh_reg.xml";
		case ENC_STR_32_LDST_IMMPOST: return "str_imm_gen.xml";
		case ENC_STR_32_LDST_IMMPRE: return "str_imm_gen.xml";
		case ENC_STR_32_LDST_POS: return "str_imm_gen.xml";
		case ENC_STR_32_LDST_REGOFF: return "str_reg_gen.xml";
		case ENC_STR_64_LDST_IMMPOST: return "str_imm_gen.xml";
		case ENC_STR_64_LDST_IMMPRE: return "str_imm_gen.xml";
		case ENC_STR_64_LDST_POS: return "str_imm_gen.xml";
		case ENC_STR_64_LDST_REGOFF: return "str_reg_gen.xml";
		case ENC_STR_BL_LDST_REGOFF: return "str_reg_fpsimd.xml";
		case ENC_STR_B_LDST_IMMPOST: return "str_imm_fpsimd.xml";
		case ENC_STR_B_LDST_IMMPRE: return "str_imm_fpsimd.xml";
		case ENC_STR_B_LDST_POS: return "str_imm_fpsimd.xml";
		case ENC_STR_B_LDST_REGOFF: return "str_reg_fpsimd.xml";
		case ENC_STR_D_LDST_IMMPOST: return "str_imm_fpsimd.xml";
		case ENC_STR_D_LDST_IMMPRE: return "str_imm_fpsimd.xml";
		case ENC_STR_D_LDST_POS: return "str_imm_fpsimd.xml";
		case ENC_STR_D_LDST_REGOFF: return "str_reg_fpsimd.xml";
		case ENC_STR_H_LDST_IMMPOST: return "str_imm_fpsimd.xml";
		case ENC_STR_H_LDST_IMMPRE: return "str_imm_fpsimd.xml";
		case ENC_STR_H_LDST_POS: return "str_imm_fpsimd.xml";
		case ENC_STR_H_LDST_REGOFF: return "str_reg_fpsimd.xml";
		case ENC_STR_Q_LDST_IMMPOST: return "str_imm_fpsimd.xml";
		case ENC_STR_Q_LDST_IMMPRE: return "str_imm_fpsimd.xml";
		case ENC_STR_Q_LDST_POS: return "str_imm_fpsimd.xml";
		case ENC_STR_Q_LDST_REGOFF: return "str_reg_fpsimd.xml";
		case ENC_STR_S_LDST_IMMPOST: return "str_imm_fpsimd.xml";
		case ENC_STR_S_LDST_IMMPRE: return "str_imm_fpsimd.xml";
		case ENC_STR_S_LDST_POS: return "str_imm_fpsimd.xml";
		case ENC_STR_S_LDST_REGOFF: return "str_reg_fpsimd.xml";
		case ENC_STSETB_LDSETB_32_MEMOP: return "stsetb_ldsetb.xml";
		case ENC_STSETH_LDSETH_32_MEMOP: return "stseth_ldseth.xml";
		case ENC_STSETLB_LDSETLB_32_MEMOP: return "stsetb_ldsetb.xml";
		case ENC_STSETLH_LDSETLH_32_MEMOP: return "stseth_ldseth.xml";
		case ENC_STSETL_LDSETL_32_MEMOP: return "stset_ldset.xml";
		case ENC_STSETL_LDSETL_64_MEMOP: return "stset_ldset.xml";
		case ENC_STSET_LDSET_32_MEMOP: return "stset_ldset.xml";
		case ENC_STSET_LDSET_64_MEMOP: return "stset_ldset.xml";
		case ENC_STSMAXB_LDSMAXB_32_MEMOP: return "stsmaxb_ldsmaxb.xml";
		case ENC_STSMAXH_LDSMAXH_32_MEMOP: return "stsmaxh_ldsmaxh.xml";
		case ENC_STSMAXLB_LDSMAXLB_32_MEMOP: return "stsmaxb_ldsmaxb.xml";
		case ENC_STSMAXLH_LDSMAXLH_32_MEMOP: return "stsmaxh_ldsmaxh.xml";
		case ENC_STSMAXL_LDSMAXL_32_MEMOP: return "stsmax_ldsmax.xml";
		case ENC_STSMAXL_LDSMAXL_64_MEMOP: return "stsmax_ldsmax.xml";
		case ENC_STSMAX_LDSMAX_32_MEMOP: return "stsmax_ldsmax.xml";
		case ENC_STSMAX_LDSMAX_64_MEMOP: return "stsmax_ldsmax.xml";
		case ENC_STSMINB_LDSMINB_32_MEMOP: return "stsminb_ldsminb.xml";
		case ENC_STSMINH_LDSMINH_32_MEMOP: return "stsminh_ldsminh.xml";
		case ENC_STSMINLB_LDSMINLB_32_MEMOP: return "stsminb_ldsminb.xml";
		case ENC_STSMINLH_LDSMINLH_32_MEMOP: return "stsminh_ldsminh.xml";
		case ENC_STSMINL_LDSMINL_32_MEMOP: return "stsmin_ldsmin.xml";
		case ENC_STSMINL_LDSMINL_64_MEMOP: return "stsmin_ldsmin.xml";
		case ENC_STSMIN_LDSMIN_32_MEMOP: return "stsmin_ldsmin.xml";
		case ENC_STSMIN_LDSMIN_64_MEMOP: return "stsmin_ldsmin.xml";
		case ENC_STTRB_32_LDST_UNPRIV: return "sttrb.xml";
		case ENC_STTRH_32_LDST_UNPRIV: return "sttrh.xml";
		case ENC_STTR_32_LDST_UNPRIV: return "sttr.xml";
		case ENC_STTR_64_LDST_UNPRIV: return "sttr.xml";
		case ENC_STUMAXB_LDUMAXB_32_MEMOP: return "stumaxb_ldumaxb.xml";
		case ENC_STUMAXH_LDUMAXH_32_MEMOP: return "stumaxh_ldumaxh.xml";
		case ENC_STUMAXLB_LDUMAXLB_32_MEMOP: return "stumaxb_ldumaxb.xml";
		case ENC_STUMAXLH_LDUMAXLH_32_MEMOP: return "stumaxh_ldumaxh.xml";
		case ENC_STUMAXL_LDUMAXL_32_MEMOP: return "stumax_ldumax.xml";
		case ENC_STUMAXL_LDUMAXL_64_MEMOP: return "stumax_ldumax.xml";
		case ENC_STUMAX_LDUMAX_32_MEMOP: return "stumax_ldumax.xml";
		case ENC_STUMAX_LDUMAX_64_MEMOP: return "stumax_ldumax.xml";
		case ENC_STUMINB_LDUMINB_32_MEMOP: return "stuminb_lduminb.xml";
		case ENC_STUMINH_LDUMINH_32_MEMOP: return "stuminh_lduminh.xml";
		case ENC_STUMINLB_LDUMINLB_32_MEMOP: return "stuminb_lduminb.xml";
		case ENC_STUMINLH_LDUMINLH_32_MEMOP: return "stuminh_lduminh.xml";
		case ENC_STUMINL_LDUMINL_32_MEMOP: return "stumin_ldumin.xml";
		case ENC_STUMINL_LDUMINL_64_MEMOP: return "stumin_ldumin.xml";
		case ENC_STUMIN_LDUMIN_32_MEMOP: return "stumin_ldumin.xml";
		case ENC_STUMIN_LDUMIN_64_MEMOP: return "stumin_ldumin.xml";
		case ENC_STURB_32_LDST_UNSCALED: return "sturb.xml";
		case ENC_STURH_32_LDST_UNSCALED: return "sturh.xml";
		case ENC_STUR_32_LDST_UNSCALED: return "stur_gen.xml";
		case ENC_STUR_64_LDST_UNSCALED: return "stur_gen.xml";
		case ENC_STUR_B_LDST_UNSCALED: return "stur_fpsimd.xml";
		case ENC_STUR_D_LDST_UNSCALED: return "stur_fpsimd.xml";
		case ENC_STUR_H_LDST_UNSCALED: return "stur_fpsimd.xml";
		case ENC_STUR_Q_LDST_UNSCALED: return "stur_fpsimd.xml";
		case ENC_STUR_S_LDST_UNSCALED: return "stur_fpsimd.xml";
		case ENC_STXP_SP32_LDSTEXCL: return "stxp.xml";
		case ENC_STXP_SP64_LDSTEXCL: return "stxp.xml";
		case ENC_STXRB_SR32_LDSTEXCL: return "stxrb.xml";
		case ENC_STXRH_SR32_LDSTEXCL: return "stxrh.xml";
		case ENC_STXR_SR32_LDSTEXCL: return "stxr.xml";
		case ENC_STXR_SR64_LDSTEXCL: return "stxr.xml";
		case ENC_STZ2G_64SOFFSET_LDSTTAGS: return "stz2g.xml";
		case ENC_STZ2G_64SPOST_LDSTTAGS: return "stz2g.xml";
		case ENC_STZ2G_64SPRE_LDSTTAGS: return "stz2g.xml";
		case ENC_STZGM_64BULK_LDSTTAGS: return "stzgm.xml";
		case ENC_STZG_64SOFFSET_LDSTTAGS: return "stzg.xml";
		case ENC_STZG_64SPOST_LDSTTAGS: return "stzg.xml";
		case ENC_STZG_64SPRE_LDSTTAGS: return "stzg.xml";
		case ENC_SUBG_64_ADDSUB_IMMTAGS: return "subg.xml";
		case ENC_SUBHN_ASIMDDIFF_N: return "subhn_advsimd.xml";
		case ENC_SUBPS_64S_DP_2SRC: return "subps.xml";
		case ENC_SUBP_64S_DP_2SRC: return "subp.xml";
		case ENC_SUBS_32S_ADDSUB_EXT: return "subs_addsub_ext.xml";
		case ENC_SUBS_32S_ADDSUB_IMM: return "subs_addsub_imm.xml";
		case ENC_SUBS_32_ADDSUB_SHIFT: return "subs_addsub_shift.xml";
		case ENC_SUBS_64S_ADDSUB_EXT: return "subs_addsub_ext.xml";
		case ENC_SUBS_64S_ADDSUB_IMM: return "subs_addsub_imm.xml";
		case ENC_SUBS_64_ADDSUB_SHIFT: return "subs_addsub_shift.xml";
		case ENC_SUB_32_ADDSUB_EXT: return "sub_addsub_ext.xml";
		case ENC_SUB_32_ADDSUB_IMM: return "sub_addsub_imm.xml";
		case ENC_SUB_32_ADDSUB_SHIFT: return "sub_addsub_shift.xml";
		case ENC_SUB_64_ADDSUB_EXT: return "sub_addsub_ext.xml";
		case ENC_SUB_64_ADDSUB_IMM: return "sub_addsub_imm.xml";
		case ENC_SUB_64_ADDSUB_SHIFT: return "sub_addsub_shift.xml";
		case ENC_SUB_ASIMDSAME_ONLY: return "sub_advsimd.xml";
		case ENC_SUB_ASISDSAME_ONLY: return "sub_advsimd.xml";
		case ENC_SUDOT_ASIMDELEM_D: return "sudot_advsimd_elt.xml";
		case ENC_SUQADD_ASIMDMISC_R: return "suqadd_advsimd.xml";
		case ENC_SUQADD_ASISDMISC_R: return "suqadd_advsimd.xml";
		case ENC_SVC_EX_EXCEPTION: return "svc.xml";
		case ENC_SWPAB_32_MEMOP: return "swpb.xml";
		case ENC_SWPAH_32_MEMOP: return "swph.xml";
		case ENC_SWPALB_32_MEMOP: return "swpb.xml";
		case ENC_SWPALH_32_MEMOP: return "swph.xml";
		case ENC_SWPAL_32_MEMOP: return "swp.xml";
		case ENC_SWPAL_64_MEMOP: return "swp.xml";
		case ENC_SWPA_32_MEMOP: return "swp.xml";
		case ENC_SWPA_64_MEMOP: return "swp.xml";
		case ENC_SWPB_32_MEMOP: return "swpb.xml";
		case ENC_SWPH_32_MEMOP: return "swph.xml";
		case ENC_SWPLB_32_MEMOP: return "swpb.xml";
		case ENC_SWPLH_32_MEMOP: return "swph.xml";
		case ENC_SWPL_32_MEMOP: return "swp.xml";
		case ENC_SWPL_64_MEMOP: return "swp.xml";
		case ENC_SWP_32_MEMOP: return "swp.xml";
		case ENC_SWP_64_MEMOP: return "swp.xml";
		case ENC_SXTB_SBFM_32M_BITFIELD: return "sxtb_sbfm.xml";
		case ENC_SXTB_SBFM_64M_BITFIELD: return "sxtb_sbfm.xml";
		case ENC_SXTH_SBFM_32M_BITFIELD: return "sxth_sbfm.xml";
		case ENC_SXTH_SBFM_64M_BITFIELD: return "sxth_sbfm.xml";
		case ENC_SXTL_SSHLL_ASIMDSHF_L: return "sxtl_sshll_advsimd.xml";
		case ENC_SXTW_SBFM_64M_BITFIELD: return "sxtw_sbfm.xml";
		case ENC_SYSL_RC_SYSTEMINSTRS: return "sysl.xml";
		case ENC_SYS_CR_SYSTEMINSTRS: return "sys.xml";
		case ENC_TBL_ASIMDTBL_L1_1: return "tbl_advsimd.xml";
		case ENC_TBL_ASIMDTBL_L2_2: return "tbl_advsimd.xml";
		case ENC_TBL_ASIMDTBL_L3_3: return "tbl_advsimd.xml";
		case ENC_TBL_ASIMDTBL_L4_4: return "tbl_advsimd.xml";
		case ENC_TBNZ_ONLY_TESTBRANCH: return "tbnz.xml";
		case ENC_TBX_ASIMDTBL_L1_1: return "tbx_advsimd.xml";
		case ENC_TBX_ASIMDTBL_L2_2: return "tbx_advsimd.xml";
		case ENC_TBX_ASIMDTBL_L3_3: return "tbx_advsimd.xml";
		case ENC_TBX_ASIMDTBL_L4_4: return "tbx_advsimd.xml";
		case ENC_TBZ_ONLY_TESTBRANCH: return "tbz.xml";
		case ENC_TLBI_SYS_CR_SYSTEMINSTRS: return "tlbi_sys.xml";
		case ENC_TRN1_ASIMDPERM_ONLY: return "trn1_advsimd.xml";
		case ENC_TRN2_ASIMDPERM_ONLY: return "trn2_advsimd.xml";
		case ENC_TSB_HC_HINTS: return "tsb.xml";
		case ENC_TST_ANDS_32S_LOG_IMM: return "tst_ands_log_imm.xml";
		case ENC_TST_ANDS_32_LOG_SHIFT: return "tst_ands_log_shift.xml";
		case ENC_TST_ANDS_64S_LOG_IMM: return "tst_ands_log_imm.xml";
		case ENC_TST_ANDS_64_LOG_SHIFT: return "tst_ands_log_shift.xml";
		case ENC_UABAL_ASIMDDIFF_L: return "uabal_advsimd.xml";
		case ENC_UABA_ASIMDSAME_ONLY: return "uaba_advsimd.xml";
		case ENC_UABDL_ASIMDDIFF_L: return "uabdl_advsimd.xml";
		case ENC_UABD_ASIMDSAME_ONLY: return "uabd_advsimd.xml";
		case ENC_UADALP_ASIMDMISC_P: return "uadalp_advsimd.xml";
		case ENC_UADDLP_ASIMDMISC_P: return "uaddlp_advsimd.xml";
		case ENC_UADDLV_ASIMDALL_ONLY: return "uaddlv_advsimd.xml";
		case ENC_UADDL_ASIMDDIFF_L: return "uaddl_advsimd.xml";
		case ENC_UADDW_ASIMDDIFF_W: return "uaddw_advsimd.xml";
		case ENC_UBFIZ_UBFM_32M_BITFIELD: return "ubfiz_ubfm.xml";
		case ENC_UBFIZ_UBFM_64M_BITFIELD: return "ubfiz_ubfm.xml";
		case ENC_UBFM_32M_BITFIELD: return "ubfm.xml";
		case ENC_UBFM_64M_BITFIELD: return "ubfm.xml";
		case ENC_UBFX_UBFM_32M_BITFIELD: return "ubfx_ubfm.xml";
		case ENC_UBFX_UBFM_64M_BITFIELD: return "ubfx_ubfm.xml";
		case ENC_UCVTF_D32_FLOAT2FIX: return "ucvtf_float_fix.xml";
		case ENC_UCVTF_D32_FLOAT2INT: return "ucvtf_float_int.xml";
		case ENC_UCVTF_D64_FLOAT2FIX: return "ucvtf_float_fix.xml";
		case ENC_UCVTF_D64_FLOAT2INT: return "ucvtf_float_int.xml";
		case ENC_UCVTF_H32_FLOAT2FIX: return "ucvtf_float_fix.xml";
		case ENC_UCVTF_H32_FLOAT2INT: return "ucvtf_float_int.xml";
		case ENC_UCVTF_H64_FLOAT2FIX: return "ucvtf_float_fix.xml";
		case ENC_UCVTF_H64_FLOAT2INT: return "ucvtf_float_int.xml";
		case ENC_UCVTF_S32_FLOAT2FIX: return "ucvtf_float_fix.xml";
		case ENC_UCVTF_S32_FLOAT2INT: return "ucvtf_float_int.xml";
		case ENC_UCVTF_S64_FLOAT2FIX: return "ucvtf_float_fix.xml";
		case ENC_UCVTF_S64_FLOAT2INT: return "ucvtf_float_int.xml";
		case ENC_UCVTF_ASIMDMISC_R: return "ucvtf_advsimd_int.xml";
		case ENC_UCVTF_ASIMDMISCFP16_R: return "ucvtf_advsimd_int.xml";
		case ENC_UCVTF_ASIMDSHF_C: return "ucvtf_advsimd_fix.xml";
		case ENC_UCVTF_ASISDMISC_R: return "ucvtf_advsimd_int.xml";
		case ENC_UCVTF_ASISDMISCFP16_R: return "ucvtf_advsimd_int.xml";
		case ENC_UCVTF_ASISDSHF_C: return "ucvtf_advsimd_fix.xml";
		case ENC_UDF_ONLY_PERM_UNDEF: return "udf_perm_undef.xml";
		case ENC_UDIV_32_DP_2SRC: return "udiv.xml";
		case ENC_UDIV_64_DP_2SRC: return "udiv.xml";
		case ENC_UDOT_ASIMDELEM_D: return "udot_advsimd_elt.xml";
		case ENC_UDOT_ASIMDSAME2_D: return "udot_advsimd_vec.xml";
		case ENC_UHADD_ASIMDSAME_ONLY: return "uhadd_advsimd.xml";
		case ENC_UHSUB_ASIMDSAME_ONLY: return "uhsub_advsimd.xml";
		case ENC_UMADDL_64WA_DP_3SRC: return "umaddl.xml";
		case ENC_UMAXP_ASIMDSAME_ONLY: return "umaxp_advsimd.xml";
		case ENC_UMAXV_ASIMDALL_ONLY: return "umaxv_advsimd.xml";
		case ENC_UMAX_ASIMDSAME_ONLY: return "umax_advsimd.xml";
		case ENC_UMINP_ASIMDSAME_ONLY: return "uminp_advsimd.xml";
		case ENC_UMINV_ASIMDALL_ONLY: return "uminv_advsimd.xml";
		case ENC_UMIN_ASIMDSAME_ONLY: return "umin_advsimd.xml";
		case ENC_UMLAL_ASIMDDIFF_L: return "umlal_advsimd_vec.xml";
		case ENC_UMLAL_ASIMDELEM_L: return "umlal_advsimd_elt.xml";
		case ENC_UMLSL_ASIMDDIFF_L: return "umlsl_advsimd_vec.xml";
		case ENC_UMLSL_ASIMDELEM_L: return "umlsl_advsimd_elt.xml";
		case ENC_UMMLA_ASIMDSAME2_G: return "ummla_advsimd_vec.xml";
		case ENC_UMNEGL_UMSUBL_64WA_DP_3SRC: return "umnegl_umsubl.xml";
		case ENC_UMOV_ASIMDINS_W_W: return "umov_advsimd.xml";
		case ENC_UMOV_ASIMDINS_X_X: return "umov_advsimd.xml";
		case ENC_UMSUBL_64WA_DP_3SRC: return "umsubl.xml";
		case ENC_UMULH_64_DP_3SRC: return "umulh.xml";
		case ENC_UMULL_UMADDL_64WA_DP_3SRC: return "umull_umaddl.xml";
		case ENC_UMULL_ASIMDDIFF_L: return "umull_advsimd_vec.xml";
		case ENC_UMULL_ASIMDELEM_L: return "umull_advsimd_elt.xml";
		case ENC_UQADD_ASIMDSAME_ONLY: return "uqadd_advsimd.xml";
		case ENC_UQADD_ASISDSAME_ONLY: return "uqadd_advsimd.xml";
		case ENC_UQRSHL_ASIMDSAME_ONLY: return "uqrshl_advsimd.xml";
		case ENC_UQRSHL_ASISDSAME_ONLY: return "uqrshl_advsimd.xml";
		case ENC_UQRSHRN_ASIMDSHF_N: return "uqrshrn_advsimd.xml";
		case ENC_UQRSHRN_ASISDSHF_N: return "uqrshrn_advsimd.xml";
		case ENC_UQSHL_ASIMDSAME_ONLY: return "uqshl_advsimd_reg.xml";
		case ENC_UQSHL_ASIMDSHF_R: return "uqshl_advsimd_imm.xml";
		case ENC_UQSHL_ASISDSAME_ONLY: return "uqshl_advsimd_reg.xml";
		case ENC_UQSHL_ASISDSHF_R: return "uqshl_advsimd_imm.xml";
		case ENC_UQSHRN_ASIMDSHF_N: return "uqshrn_advsimd.xml";
		case ENC_UQSHRN_ASISDSHF_N: return "uqshrn_advsimd.xml";
		case ENC_UQSUB_ASIMDSAME_ONLY: return "uqsub_advsimd.xml";
		case ENC_UQSUB_ASISDSAME_ONLY: return "uqsub_advsimd.xml";
		case ENC_UQXTN_ASIMDMISC_N: return "uqxtn_advsimd.xml";
		case ENC_UQXTN_ASISDMISC_N: return "uqxtn_advsimd.xml";
		case ENC_URECPE_ASIMDMISC_R: return "urecpe_advsimd.xml";
		case ENC_URHADD_ASIMDSAME_ONLY: return "urhadd_advsimd.xml";
		case ENC_URSHL_ASIMDSAME_ONLY: return "urshl_advsimd.xml";
		case ENC_URSHL_ASISDSAME_ONLY: return "urshl_advsimd.xml";
		case ENC_URSHR_ASIMDSHF_R: return "urshr_advsimd.xml";
		case ENC_URSHR_ASISDSHF_R: return "urshr_advsimd.xml";
		case ENC_URSQRTE_ASIMDMISC_R: return "ursqrte_advsimd.xml";
		case ENC_URSRA_ASIMDSHF_R: return "ursra_advsimd.xml";
		case ENC_URSRA_ASISDSHF_R: return "ursra_advsimd.xml";
		case ENC_USDOT_ASIMDELEM_D: return "usdot_advsimd_elt.xml";
		case ENC_USDOT_ASIMDSAME2_D: return "usdot_advsimd_vec.xml";
		case ENC_USHLL_ASIMDSHF_L: return "ushll_advsimd.xml";
		case ENC_USHL_ASIMDSAME_ONLY: return "ushl_advsimd.xml";
		case ENC_USHL_ASISDSAME_ONLY: return "ushl_advsimd.xml";
		case ENC_USHR_ASIMDSHF_R: return "ushr_advsimd.xml";
		case ENC_USHR_ASISDSHF_R: return "ushr_advsimd.xml";
		case ENC_USMMLA_ASIMDSAME2_G: return "usmmla_advsimd_vec.xml";
		case ENC_USQADD_ASIMDMISC_R: return "usqadd_advsimd.xml";
		case ENC_USQADD_ASISDMISC_R: return "usqadd_advsimd.xml";
		case ENC_USRA_ASIMDSHF_R: return "usra_advsimd.xml";
		case ENC_USRA_ASISDSHF_R: return "usra_advsimd.xml";
		case ENC_USUBL_ASIMDDIFF_L: return "usubl_advsimd.xml";
		case ENC_USUBW_ASIMDDIFF_W: return "usubw_advsimd.xml";
		case ENC_UXTB_UBFM_32M_BITFIELD: return "uxtb_ubfm.xml";
		case ENC_UXTH_UBFM_32M_BITFIELD: return "uxth_ubfm.xml";
		case ENC_UXTL_USHLL_ASIMDSHF_L: return "uxtl_ushll_advsimd.xml";
		case ENC_UZP1_ASIMDPERM_ONLY: return "uzp1_advsimd.xml";
		case ENC_UZP2_ASIMDPERM_ONLY: return "uzp2_advsimd.xml";
		case ENC_WFE_HI_HINTS: return "wfe.xml";
		case ENC_WFI_HI_HINTS: return "wfi.xml";
		case ENC_XAFLAG_M_PSTATE: return "xaflag.xml";
		case ENC_XAR_VVV2_CRYPTO3_IMM6: return "xar_advsimd.xml";
		case ENC_XPACD_64Z_DP_1SRC: return "xpac.xml";
		case ENC_XPACI_64Z_DP_1SRC: return "xpac.xml";
		case ENC_XPACLRI_HI_HINTS: return "xpac.xml";
		case ENC_XTN_ASIMDMISC_N: return "xtn_advsimd.xml";
		case ENC_YIELD_HI_HINTS: return "yield.xml";
		case ENC_ZIP1_ASIMDPERM_ONLY: return "zip1_advsimd.xml";
		case ENC_ZIP2_ASIMDPERM_ONLY: return "zip2_advsimd.xml";
		case ENC_ABS_Z_P_Z_: return "abs_z_p_z.xml";
		case ENC_ADD_Z_P_ZZ_: return "add_z_p_zz.xml";
		case ENC_ADD_Z_ZI_: return "add_z_zi.xml";
		case ENC_ADD_Z_ZZ_: return "add_z_zz.xml";
		case ENC_ADDPL_R_RI_: return "addpl_r_ri.xml";
		case ENC_ADDVL_R_RI_: return "addvl_r_ri.xml";
		case ENC_ADR_Z_AZ_D_S32_SCALED: return "adr_z_az.xml";
		case ENC_ADR_Z_AZ_D_U32_SCALED: return "adr_z_az.xml";
		case ENC_ADR_Z_AZ_SD_SAME_SCALED: return "adr_z_az.xml";
		case ENC_AND_P_P_PP_Z: return "and_p_p_pp.xml";
		case ENC_AND_Z_P_ZZ_: return "and_z_p_zz.xml";
		case ENC_AND_Z_ZI_: return "and_z_zi.xml";
		case ENC_AND_Z_ZZ_: return "and_z_zz.xml";
		case ENC_ANDS_P_P_PP_Z: return "and_p_p_pp.xml";
		case ENC_ANDV_R_P_Z_: return "andv_r_p_z.xml";
		case ENC_ASR_Z_P_ZI_: return "asr_z_p_zi.xml";
		case ENC_ASR_Z_P_ZW_: return "asr_z_p_zw.xml";
		case ENC_ASR_Z_P_ZZ_: return "asr_z_p_zz.xml";
		case ENC_ASR_Z_ZI_: return "asr_z_zi.xml";
		case ENC_ASR_Z_ZW_: return "asr_z_zw.xml";
		case ENC_ASRD_Z_P_ZI_: return "asrd_z_p_zi.xml";
		case ENC_ASRR_Z_P_ZZ_: return "asrr_z_p_zz.xml";
		case ENC_BFCVT_Z_P_Z_S2BF: return "bfcvt_z_p_z.xml";
		case ENC_BFCVTNT_Z_P_Z_S2BF: return "bfcvtnt_z_p_z.xml";
		case ENC_BFDOT_Z_ZZZ_: return "bfdot_z_zzz.xml";
		case ENC_BFDOT_Z_ZZZI_: return "bfdot_z_zzzi.xml";
		case ENC_BFMLALB_Z_ZZZ_: return "bfmlalb_z_zzz.xml";
		case ENC_BFMLALB_Z_ZZZI_: return "bfmlalb_z_zzzi.xml";
		case ENC_BFMLALT_Z_ZZZ_: return "bfmlalt_z_zzz.xml";
		case ENC_BFMLALT_Z_ZZZI_: return "bfmlalt_z_zzzi.xml";
		case ENC_BFMMLA_Z_ZZZ_: return "bfmmla_z_zzz.xml";
		case ENC_BIC_P_P_PP_Z: return "bic_p_p_pp.xml";
		case ENC_BIC_Z_P_ZZ_: return "bic_z_p_zz.xml";
		case ENC_BIC_Z_ZZ_: return "bic_z_zz.xml";
		case ENC_BICS_P_P_PP_Z: return "bic_p_p_pp.xml";
		case ENC_BRKA_P_P_P_: return "brka_p_p_p.xml";
		case ENC_BRKAS_P_P_P_Z: return "brka_p_p_p.xml";
		case ENC_BRKB_P_P_P_: return "brkb_p_p_p.xml";
		case ENC_BRKBS_P_P_P_Z: return "brkb_p_p_p.xml";
		case ENC_BRKN_P_P_PP_: return "brkn_p_p_pp.xml";
		case ENC_BRKNS_P_P_PP_: return "brkn_p_p_pp.xml";
		case ENC_BRKPA_P_P_PP_: return "brkpa_p_p_pp.xml";
		case ENC_BRKPAS_P_P_PP_: return "brkpa_p_p_pp.xml";
		case ENC_BRKPB_P_P_PP_: return "brkpb_p_p_pp.xml";
		case ENC_BRKPBS_P_P_PP_: return "brkpb_p_p_pp.xml";
		case ENC_CLASTA_R_P_Z_: return "clasta_r_p_z.xml";
		case ENC_CLASTA_V_P_Z_: return "clasta_v_p_z.xml";
		case ENC_CLASTA_Z_P_ZZ_: return "clasta_z_p_zz.xml";
		case ENC_CLASTB_R_P_Z_: return "clastb_r_p_z.xml";
		case ENC_CLASTB_V_P_Z_: return "clastb_v_p_z.xml";
		case ENC_CLASTB_Z_P_ZZ_: return "clastb_z_p_zz.xml";
		case ENC_CLS_Z_P_Z_: return "cls_z_p_z.xml";
		case ENC_CLZ_Z_P_Z_: return "clz_z_p_z.xml";
		case ENC_CMPEQ_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPEQ_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPEQ_P_P_ZZ_: return "cmpeq_p_p_zz.xml";
		case ENC_CMPGE_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPGE_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPGE_P_P_ZZ_: return "cmpeq_p_p_zz.xml";
		case ENC_CMPGT_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPGT_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPGT_P_P_ZZ_: return "cmpeq_p_p_zz.xml";
		case ENC_CMPHI_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPHI_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPHI_P_P_ZZ_: return "cmpeq_p_p_zz.xml";
		case ENC_CMPHS_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPHS_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPHS_P_P_ZZ_: return "cmpeq_p_p_zz.xml";
		case ENC_CMPLE_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPLE_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPLO_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPLO_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPLS_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPLS_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPLT_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPLT_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPNE_P_P_ZI_: return "cmpeq_p_p_zi.xml";
		case ENC_CMPNE_P_P_ZW_: return "cmpeq_p_p_zw.xml";
		case ENC_CMPNE_P_P_ZZ_: return "cmpeq_p_p_zz.xml";
		case ENC_CNOT_Z_P_Z_: return "cnot_z_p_z.xml";
		case ENC_CNT_Z_P_Z_: return "cnt_z_p_z.xml";
		case ENC_CNTB_R_S_: return "cntb_r_s.xml";
		case ENC_CNTD_R_S_: return "cntb_r_s.xml";
		case ENC_CNTH_R_S_: return "cntb_r_s.xml";
		case ENC_CNTP_R_P_P_: return "cntp_r_p_p.xml";
		case ENC_CNTW_R_S_: return "cntb_r_s.xml";
		case ENC_COMPACT_Z_P_Z_: return "compact_z_p_z.xml";
		case ENC_CPY_Z_O_I_: return "cpy_z_o_i.xml";
		case ENC_CPY_Z_P_I_: return "cpy_z_p_i.xml";
		case ENC_CPY_Z_P_R_: return "cpy_z_p_r.xml";
		case ENC_CPY_Z_P_V_: return "cpy_z_p_v.xml";
		case ENC_CTERMEQ_RR_: return "ctermeq_rr.xml";
		case ENC_CTERMNE_RR_: return "ctermeq_rr.xml";
		case ENC_DECB_R_RS_: return "decb_r_rs.xml";
		case ENC_DECD_R_RS_: return "decb_r_rs.xml";
		case ENC_DECD_Z_ZS_: return "decd_z_zs.xml";
		case ENC_DECH_R_RS_: return "decb_r_rs.xml";
		case ENC_DECH_Z_ZS_: return "decd_z_zs.xml";
		case ENC_DECP_R_P_R_: return "decp_r_p_r.xml";
		case ENC_DECP_Z_P_Z_: return "decp_z_p_z.xml";
		case ENC_DECW_R_RS_: return "decb_r_rs.xml";
		case ENC_DECW_Z_ZS_: return "decd_z_zs.xml";
		case ENC_DUP_Z_I_: return "dup_z_i.xml";
		case ENC_DUP_Z_R_: return "dup_z_r.xml";
		case ENC_DUP_Z_ZI_: return "dup_z_zi.xml";
		case ENC_DUPM_Z_I_: return "dupm_z_i.xml";
		case ENC_EOR_P_P_PP_Z: return "eor_p_p_pp.xml";
		case ENC_EOR_Z_P_ZZ_: return "eor_z_p_zz.xml";
		case ENC_EOR_Z_ZI_: return "eor_z_zi.xml";
		case ENC_EOR_Z_ZZ_: return "eor_z_zz.xml";
		case ENC_EORS_P_P_PP_Z: return "eor_p_p_pp.xml";
		case ENC_EORV_R_P_Z_: return "eorv_r_p_z.xml";
		case ENC_EXT_Z_ZI_DES: return "ext_z_zi.xml";
		case ENC_FABD_Z_P_ZZ_: return "fabd_z_p_zz.xml";
		case ENC_FABS_Z_P_Z_: return "fabs_z_p_z.xml";
		case ENC_FACGE_P_P_ZZ_: return "facge_p_p_zz.xml";
		case ENC_FACGT_P_P_ZZ_: return "facge_p_p_zz.xml";
		case ENC_FADD_Z_P_ZS_: return "fadd_z_p_zs.xml";
		case ENC_FADD_Z_P_ZZ_: return "fadd_z_p_zz.xml";
		case ENC_FADD_Z_ZZ_: return "fadd_z_zz.xml";
		case ENC_FADDA_V_P_Z_: return "fadda_v_p_z.xml";
		case ENC_FADDV_V_P_Z_: return "faddv_v_p_z.xml";
		case ENC_FCADD_Z_P_ZZ_: return "fcadd_z_p_zz.xml";
		case ENC_FCMEQ_P_P_Z0_: return "fcmeq_p_p_z0.xml";
		case ENC_FCMEQ_P_P_ZZ_: return "fcmeq_p_p_zz.xml";
		case ENC_FCMGE_P_P_Z0_: return "fcmeq_p_p_z0.xml";
		case ENC_FCMGE_P_P_ZZ_: return "fcmeq_p_p_zz.xml";
		case ENC_FCMGT_P_P_Z0_: return "fcmeq_p_p_z0.xml";
		case ENC_FCMGT_P_P_ZZ_: return "fcmeq_p_p_zz.xml";
		case ENC_FCMLA_Z_P_ZZZ_: return "fcmla_z_p_zzz.xml";
		case ENC_FCMLA_Z_ZZZI_H: return "fcmla_z_zzzi.xml";
		case ENC_FCMLA_Z_ZZZI_S: return "fcmla_z_zzzi.xml";
		case ENC_FCMLE_P_P_Z0_: return "fcmeq_p_p_z0.xml";
		case ENC_FCMLT_P_P_Z0_: return "fcmeq_p_p_z0.xml";
		case ENC_FCMNE_P_P_Z0_: return "fcmeq_p_p_z0.xml";
		case ENC_FCMNE_P_P_ZZ_: return "fcmeq_p_p_zz.xml";
		case ENC_FCMUO_P_P_ZZ_: return "fcmeq_p_p_zz.xml";
		case ENC_FCPY_Z_P_I_: return "fcpy_z_p_i.xml";
		case ENC_FCVT_Z_P_Z_D2H: return "fcvt_z_p_z.xml";
		case ENC_FCVT_Z_P_Z_D2S: return "fcvt_z_p_z.xml";
		case ENC_FCVT_Z_P_Z_H2D: return "fcvt_z_p_z.xml";
		case ENC_FCVT_Z_P_Z_H2S: return "fcvt_z_p_z.xml";
		case ENC_FCVT_Z_P_Z_S2D: return "fcvt_z_p_z.xml";
		case ENC_FCVT_Z_P_Z_S2H: return "fcvt_z_p_z.xml";
		case ENC_FCVTZS_Z_P_Z_D2W: return "fcvtzs_z_p_z.xml";
		case ENC_FCVTZS_Z_P_Z_D2X: return "fcvtzs_z_p_z.xml";
		case ENC_FCVTZS_Z_P_Z_FP162H: return "fcvtzs_z_p_z.xml";
		case ENC_FCVTZS_Z_P_Z_FP162W: return "fcvtzs_z_p_z.xml";
		case ENC_FCVTZS_Z_P_Z_FP162X: return "fcvtzs_z_p_z.xml";
		case ENC_FCVTZS_Z_P_Z_S2W: return "fcvtzs_z_p_z.xml";
		case ENC_FCVTZS_Z_P_Z_S2X: return "fcvtzs_z_p_z.xml";
		case ENC_FCVTZU_Z_P_Z_D2W: return "fcvtzu_z_p_z.xml";
		case ENC_FCVTZU_Z_P_Z_D2X: return "fcvtzu_z_p_z.xml";
		case ENC_FCVTZU_Z_P_Z_FP162H: return "fcvtzu_z_p_z.xml";
		case ENC_FCVTZU_Z_P_Z_FP162W: return "fcvtzu_z_p_z.xml";
		case ENC_FCVTZU_Z_P_Z_FP162X: return "fcvtzu_z_p_z.xml";
		case ENC_FCVTZU_Z_P_Z_S2W: return "fcvtzu_z_p_z.xml";
		case ENC_FCVTZU_Z_P_Z_S2X: return "fcvtzu_z_p_z.xml";
		case ENC_FDIV_Z_P_ZZ_: return "fdiv_z_p_zz.xml";
		case ENC_FDIVR_Z_P_ZZ_: return "fdivr_z_p_zz.xml";
		case ENC_FDUP_Z_I_: return "fdup_z_i.xml";
		case ENC_FEXPA_Z_Z_: return "fexpa_z_z.xml";
		case ENC_FMAD_Z_P_ZZZ_: return "fmad_z_p_zzz.xml";
		case ENC_FMAX_Z_P_ZS_: return "fmax_z_p_zs.xml";
		case ENC_FMAX_Z_P_ZZ_: return "fmax_z_p_zz.xml";
		case ENC_FMAXNM_Z_P_ZS_: return "fmaxnm_z_p_zs.xml";
		case ENC_FMAXNM_Z_P_ZZ_: return "fmaxnm_z_p_zz.xml";
		case ENC_FMAXNMV_V_P_Z_: return "fmaxnmv_v_p_z.xml";
		case ENC_FMAXV_V_P_Z_: return "fmaxv_v_p_z.xml";
		case ENC_FMIN_Z_P_ZS_: return "fmin_z_p_zs.xml";
		case ENC_FMIN_Z_P_ZZ_: return "fmin_z_p_zz.xml";
		case ENC_FMINNM_Z_P_ZS_: return "fminnm_z_p_zs.xml";
		case ENC_FMINNM_Z_P_ZZ_: return "fminnm_z_p_zz.xml";
		case ENC_FMINNMV_V_P_Z_: return "fminnmv_v_p_z.xml";
		case ENC_FMINV_V_P_Z_: return "fminv_v_p_z.xml";
		case ENC_FMLA_Z_P_ZZZ_: return "fmla_z_p_zzz.xml";
		case ENC_FMLA_Z_ZZZI_D: return "fmla_z_zzzi.xml";
		case ENC_FMLA_Z_ZZZI_H: return "fmla_z_zzzi.xml";
		case ENC_FMLA_Z_ZZZI_S: return "fmla_z_zzzi.xml";
		case ENC_FMLS_Z_P_ZZZ_: return "fmls_z_p_zzz.xml";
		case ENC_FMLS_Z_ZZZI_D: return "fmls_z_zzzi.xml";
		case ENC_FMLS_Z_ZZZI_H: return "fmls_z_zzzi.xml";
		case ENC_FMLS_Z_ZZZI_S: return "fmls_z_zzzi.xml";
		case ENC_FMMLA_Z_ZZZ_D: return "fmmla_z_zzz.xml";
		case ENC_FMMLA_Z_ZZZ_S: return "fmmla_z_zzz.xml";
		case ENC_FMSB_Z_P_ZZZ_: return "fmsb_z_p_zzz.xml";
		case ENC_FMUL_Z_P_ZS_: return "fmul_z_p_zs.xml";
		case ENC_FMUL_Z_P_ZZ_: return "fmul_z_p_zz.xml";
		case ENC_FMUL_Z_ZZ_: return "fmul_z_zz.xml";
		case ENC_FMUL_Z_ZZI_D: return "fmul_z_zzi.xml";
		case ENC_FMUL_Z_ZZI_H: return "fmul_z_zzi.xml";
		case ENC_FMUL_Z_ZZI_S: return "fmul_z_zzi.xml";
		case ENC_FMULX_Z_P_ZZ_: return "fmulx_z_p_zz.xml";
		case ENC_FNEG_Z_P_Z_: return "fneg_z_p_z.xml";
		case ENC_FNMAD_Z_P_ZZZ_: return "fnmad_z_p_zzz.xml";
		case ENC_FNMLA_Z_P_ZZZ_: return "fnmla_z_p_zzz.xml";
		case ENC_FNMLS_Z_P_ZZZ_: return "fnmls_z_p_zzz.xml";
		case ENC_FNMSB_Z_P_ZZZ_: return "fnmsb_z_p_zzz.xml";
		case ENC_FRECPE_Z_Z_: return "frecpe_z_z.xml";
		case ENC_FRECPS_Z_ZZ_: return "frecps_z_zz.xml";
		case ENC_FRECPX_Z_P_Z_: return "frecpx_z_p_z.xml";
		case ENC_FRINTA_Z_P_Z_: return "frinta_z_p_z.xml";
		case ENC_FRINTI_Z_P_Z_: return "frinta_z_p_z.xml";
		case ENC_FRINTM_Z_P_Z_: return "frinta_z_p_z.xml";
		case ENC_FRINTN_Z_P_Z_: return "frinta_z_p_z.xml";
		case ENC_FRINTP_Z_P_Z_: return "frinta_z_p_z.xml";
		case ENC_FRINTX_Z_P_Z_: return "frinta_z_p_z.xml";
		case ENC_FRINTZ_Z_P_Z_: return "frinta_z_p_z.xml";
		case ENC_FRSQRTE_Z_Z_: return "frsqrte_z_z.xml";
		case ENC_FRSQRTS_Z_ZZ_: return "frsqrts_z_zz.xml";
		case ENC_FSCALE_Z_P_ZZ_: return "fscale_z_p_zz.xml";
		case ENC_FSQRT_Z_P_Z_: return "fsqrt_z_p_z.xml";
		case ENC_FSUB_Z_P_ZS_: return "fsub_z_p_zs.xml";
		case ENC_FSUB_Z_P_ZZ_: return "fsub_z_p_zz.xml";
		case ENC_FSUB_Z_ZZ_: return "fsub_z_zz.xml";
		case ENC_FSUBR_Z_P_ZS_: return "fsubr_z_p_zs.xml";
		case ENC_FSUBR_Z_P_ZZ_: return "fsubr_z_p_zz.xml";
		case ENC_FTMAD_Z_ZZI_: return "ftmad_z_zzi.xml";
		case ENC_FTSMUL_Z_ZZ_: return "ftsmul_z_zz.xml";
		case ENC_FTSSEL_Z_ZZ_: return "ftssel_z_zz.xml";
		case ENC_INCB_R_RS_: return "incb_r_rs.xml";
		case ENC_INCD_R_RS_: return "incb_r_rs.xml";
		case ENC_INCD_Z_ZS_: return "incd_z_zs.xml";
		case ENC_INCH_R_RS_: return "incb_r_rs.xml";
		case ENC_INCH_Z_ZS_: return "incd_z_zs.xml";
		case ENC_INCP_R_P_R_: return "incp_r_p_r.xml";
		case ENC_INCP_Z_P_Z_: return "incp_z_p_z.xml";
		case ENC_INCW_R_RS_: return "incb_r_rs.xml";
		case ENC_INCW_Z_ZS_: return "incd_z_zs.xml";
		case ENC_INDEX_Z_II_: return "index_z_ii.xml";
		case ENC_INDEX_Z_IR_: return "index_z_ir.xml";
		case ENC_INDEX_Z_RI_: return "index_z_ri.xml";
		case ENC_INDEX_Z_RR_: return "index_z_rr.xml";
		case ENC_INSR_Z_R_: return "insr_z_r.xml";
		case ENC_INSR_Z_V_: return "insr_z_v.xml";
		case ENC_LASTA_R_P_Z_: return "lasta_r_p_z.xml";
		case ENC_LASTA_V_P_Z_: return "lasta_v_p_z.xml";
		case ENC_LASTB_R_P_Z_: return "lastb_r_p_z.xml";
		case ENC_LASTB_V_P_Z_: return "lastb_v_p_z.xml";
		case ENC_LD1B_Z_P_AI_D: return "ld1b_z_p_ai.xml";
		case ENC_LD1B_Z_P_AI_S: return "ld1b_z_p_ai.xml";
		case ENC_LD1B_Z_P_BI_U16: return "ld1b_z_p_bi.xml";
		case ENC_LD1B_Z_P_BI_U32: return "ld1b_z_p_bi.xml";
		case ENC_LD1B_Z_P_BI_U64: return "ld1b_z_p_bi.xml";
		case ENC_LD1B_Z_P_BI_U8: return "ld1b_z_p_bi.xml";
		case ENC_LD1B_Z_P_BR_U16: return "ld1b_z_p_br.xml";
		case ENC_LD1B_Z_P_BR_U32: return "ld1b_z_p_br.xml";
		case ENC_LD1B_Z_P_BR_U64: return "ld1b_z_p_br.xml";
		case ENC_LD1B_Z_P_BR_U8: return "ld1b_z_p_br.xml";
		case ENC_LD1B_Z_P_BZ_D_64_UNSCALED: return "ld1b_z_p_bz.xml";
		case ENC_LD1B_Z_P_BZ_D_X32_UNSCALED: return "ld1b_z_p_bz.xml";
		case ENC_LD1B_Z_P_BZ_S_X32_UNSCALED: return "ld1b_z_p_bz.xml";
		case ENC_LD1D_Z_P_AI_D: return "ld1d_z_p_ai.xml";
		case ENC_LD1D_Z_P_BI_U64: return "ld1d_z_p_bi.xml";
		case ENC_LD1D_Z_P_BR_U64: return "ld1d_z_p_br.xml";
		case ENC_LD1D_Z_P_BZ_D_64_SCALED: return "ld1d_z_p_bz.xml";
		case ENC_LD1D_Z_P_BZ_D_64_UNSCALED: return "ld1d_z_p_bz.xml";
		case ENC_LD1D_Z_P_BZ_D_X32_SCALED: return "ld1d_z_p_bz.xml";
		case ENC_LD1D_Z_P_BZ_D_X32_UNSCALED: return "ld1d_z_p_bz.xml";
		case ENC_LD1H_Z_P_AI_D: return "ld1h_z_p_ai.xml";
		case ENC_LD1H_Z_P_AI_S: return "ld1h_z_p_ai.xml";
		case ENC_LD1H_Z_P_BI_U16: return "ld1h_z_p_bi.xml";
		case ENC_LD1H_Z_P_BI_U32: return "ld1h_z_p_bi.xml";
		case ENC_LD1H_Z_P_BI_U64: return "ld1h_z_p_bi.xml";
		case ENC_LD1H_Z_P_BR_U16: return "ld1h_z_p_br.xml";
		case ENC_LD1H_Z_P_BR_U32: return "ld1h_z_p_br.xml";
		case ENC_LD1H_Z_P_BR_U64: return "ld1h_z_p_br.xml";
		case ENC_LD1H_Z_P_BZ_D_64_SCALED: return "ld1h_z_p_bz.xml";
		case ENC_LD1H_Z_P_BZ_D_64_UNSCALED: return "ld1h_z_p_bz.xml";
		case ENC_LD1H_Z_P_BZ_D_X32_SCALED: return "ld1h_z_p_bz.xml";
		case ENC_LD1H_Z_P_BZ_D_X32_UNSCALED: return "ld1h_z_p_bz.xml";
		case ENC_LD1H_Z_P_BZ_S_X32_SCALED: return "ld1h_z_p_bz.xml";
		case ENC_LD1H_Z_P_BZ_S_X32_UNSCALED: return "ld1h_z_p_bz.xml";
		case ENC_LD1RB_Z_P_BI_U16: return "ld1rb_z_p_bi.xml";
		case ENC_LD1RB_Z_P_BI_U32: return "ld1rb_z_p_bi.xml";
		case ENC_LD1RB_Z_P_BI_U64: return "ld1rb_z_p_bi.xml";
		case ENC_LD1RB_Z_P_BI_U8: return "ld1rb_z_p_bi.xml";
		case ENC_LD1RD_Z_P_BI_U64: return "ld1rd_z_p_bi.xml";
		case ENC_LD1RH_Z_P_BI_U16: return "ld1rh_z_p_bi.xml";
		case ENC_LD1RH_Z_P_BI_U32: return "ld1rh_z_p_bi.xml";
		case ENC_LD1RH_Z_P_BI_U64: return "ld1rh_z_p_bi.xml";
		case ENC_LD1ROB_Z_P_BI_U8: return "ld1rob_z_p_bi.xml";
		case ENC_LD1ROB_Z_P_BR_CONTIGUOUS: return "ld1rob_z_p_br.xml";
		case ENC_LD1ROD_Z_P_BI_U64: return "ld1rod_z_p_bi.xml";
		case ENC_LD1ROD_Z_P_BR_CONTIGUOUS: return "ld1rod_z_p_br.xml";
		case ENC_LD1ROH_Z_P_BI_U16: return "ld1roh_z_p_bi.xml";
		case ENC_LD1ROH_Z_P_BR_CONTIGUOUS: return "ld1roh_z_p_br.xml";
		case ENC_LD1ROW_Z_P_BI_U32: return "ld1row_z_p_bi.xml";
		case ENC_LD1ROW_Z_P_BR_CONTIGUOUS: return "ld1row_z_p_br.xml";
		case ENC_LD1RQB_Z_P_BI_U8: return "ld1rqb_z_p_bi.xml";
		case ENC_LD1RQB_Z_P_BR_CONTIGUOUS: return "ld1rqb_z_p_br.xml";
		case ENC_LD1RQD_Z_P_BI_U64: return "ld1rqd_z_p_bi.xml";
		case ENC_LD1RQD_Z_P_BR_CONTIGUOUS: return "ld1rqd_z_p_br.xml";
		case ENC_LD1RQH_Z_P_BI_U16: return "ld1rqh_z_p_bi.xml";
		case ENC_LD1RQH_Z_P_BR_CONTIGUOUS: return "ld1rqh_z_p_br.xml";
		case ENC_LD1RQW_Z_P_BI_U32: return "ld1rqw_z_p_bi.xml";
		case ENC_LD1RQW_Z_P_BR_CONTIGUOUS: return "ld1rqw_z_p_br.xml";
		case ENC_LD1RSB_Z_P_BI_S16: return "ld1rsb_z_p_bi.xml";
		case ENC_LD1RSB_Z_P_BI_S32: return "ld1rsb_z_p_bi.xml";
		case ENC_LD1RSB_Z_P_BI_S64: return "ld1rsb_z_p_bi.xml";
		case ENC_LD1RSH_Z_P_BI_S32: return "ld1rsh_z_p_bi.xml";
		case ENC_LD1RSH_Z_P_BI_S64: return "ld1rsh_z_p_bi.xml";
		case ENC_LD1RSW_Z_P_BI_S64: return "ld1rsw_z_p_bi.xml";
		case ENC_LD1RW_Z_P_BI_U32: return "ld1rw_z_p_bi.xml";
		case ENC_LD1RW_Z_P_BI_U64: return "ld1rw_z_p_bi.xml";
		case ENC_LD1SB_Z_P_AI_D: return "ld1sb_z_p_ai.xml";
		case ENC_LD1SB_Z_P_AI_S: return "ld1sb_z_p_ai.xml";
		case ENC_LD1SB_Z_P_BI_S16: return "ld1sb_z_p_bi.xml";
		case ENC_LD1SB_Z_P_BI_S32: return "ld1sb_z_p_bi.xml";
		case ENC_LD1SB_Z_P_BI_S64: return "ld1sb_z_p_bi.xml";
		case ENC_LD1SB_Z_P_BR_S16: return "ld1sb_z_p_br.xml";
		case ENC_LD1SB_Z_P_BR_S32: return "ld1sb_z_p_br.xml";
		case ENC_LD1SB_Z_P_BR_S64: return "ld1sb_z_p_br.xml";
		case ENC_LD1SB_Z_P_BZ_D_64_UNSCALED: return "ld1sb_z_p_bz.xml";
		case ENC_LD1SB_Z_P_BZ_D_X32_UNSCALED: return "ld1sb_z_p_bz.xml";
		case ENC_LD1SB_Z_P_BZ_S_X32_UNSCALED: return "ld1sb_z_p_bz.xml";
		case ENC_LD1SH_Z_P_AI_D: return "ld1sh_z_p_ai.xml";
		case ENC_LD1SH_Z_P_AI_S: return "ld1sh_z_p_ai.xml";
		case ENC_LD1SH_Z_P_BI_S32: return "ld1sh_z_p_bi.xml";
		case ENC_LD1SH_Z_P_BI_S64: return "ld1sh_z_p_bi.xml";
		case ENC_LD1SH_Z_P_BR_S32: return "ld1sh_z_p_br.xml";
		case ENC_LD1SH_Z_P_BR_S64: return "ld1sh_z_p_br.xml";
		case ENC_LD1SH_Z_P_BZ_D_64_SCALED: return "ld1sh_z_p_bz.xml";
		case ENC_LD1SH_Z_P_BZ_D_64_UNSCALED: return "ld1sh_z_p_bz.xml";
		case ENC_LD1SH_Z_P_BZ_D_X32_SCALED: return "ld1sh_z_p_bz.xml";
		case ENC_LD1SH_Z_P_BZ_D_X32_UNSCALED: return "ld1sh_z_p_bz.xml";
		case ENC_LD1SH_Z_P_BZ_S_X32_SCALED: return "ld1sh_z_p_bz.xml";
		case ENC_LD1SH_Z_P_BZ_S_X32_UNSCALED: return "ld1sh_z_p_bz.xml";
		case ENC_LD1SW_Z_P_AI_D: return "ld1sw_z_p_ai.xml";
		case ENC_LD1SW_Z_P_BI_S64: return "ld1sw_z_p_bi.xml";
		case ENC_LD1SW_Z_P_BR_S64: return "ld1sw_z_p_br.xml";
		case ENC_LD1SW_Z_P_BZ_D_64_SCALED: return "ld1sw_z_p_bz.xml";
		case ENC_LD1SW_Z_P_BZ_D_64_UNSCALED: return "ld1sw_z_p_bz.xml";
		case ENC_LD1SW_Z_P_BZ_D_X32_SCALED: return "ld1sw_z_p_bz.xml";
		case ENC_LD1SW_Z_P_BZ_D_X32_UNSCALED: return "ld1sw_z_p_bz.xml";
		case ENC_LD1W_Z_P_AI_D: return "ld1w_z_p_ai.xml";
		case ENC_LD1W_Z_P_AI_S: return "ld1w_z_p_ai.xml";
		case ENC_LD1W_Z_P_BI_U32: return "ld1w_z_p_bi.xml";
		case ENC_LD1W_Z_P_BI_U64: return "ld1w_z_p_bi.xml";
		case ENC_LD1W_Z_P_BR_U32: return "ld1w_z_p_br.xml";
		case ENC_LD1W_Z_P_BR_U64: return "ld1w_z_p_br.xml";
		case ENC_LD1W_Z_P_BZ_D_64_SCALED: return "ld1w_z_p_bz.xml";
		case ENC_LD1W_Z_P_BZ_D_64_UNSCALED: return "ld1w_z_p_bz.xml";
		case ENC_LD1W_Z_P_BZ_D_X32_SCALED: return "ld1w_z_p_bz.xml";
		case ENC_LD1W_Z_P_BZ_D_X32_UNSCALED: return "ld1w_z_p_bz.xml";
		case ENC_LD1W_Z_P_BZ_S_X32_SCALED: return "ld1w_z_p_bz.xml";
		case ENC_LD1W_Z_P_BZ_S_X32_UNSCALED: return "ld1w_z_p_bz.xml";
		case ENC_LD2B_Z_P_BI_CONTIGUOUS: return "ld2b_z_p_bi.xml";
		case ENC_LD2B_Z_P_BR_CONTIGUOUS: return "ld2b_z_p_br.xml";
		case ENC_LD2D_Z_P_BI_CONTIGUOUS: return "ld2d_z_p_bi.xml";
		case ENC_LD2D_Z_P_BR_CONTIGUOUS: return "ld2d_z_p_br.xml";
		case ENC_LD2H_Z_P_BI_CONTIGUOUS: return "ld2h_z_p_bi.xml";
		case ENC_LD2H_Z_P_BR_CONTIGUOUS: return "ld2h_z_p_br.xml";
		case ENC_LD2W_Z_P_BI_CONTIGUOUS: return "ld2w_z_p_bi.xml";
		case ENC_LD2W_Z_P_BR_CONTIGUOUS: return "ld2w_z_p_br.xml";
		case ENC_LD3B_Z_P_BI_CONTIGUOUS: return "ld3b_z_p_bi.xml";
		case ENC_LD3B_Z_P_BR_CONTIGUOUS: return "ld3b_z_p_br.xml";
		case ENC_LD3D_Z_P_BI_CONTIGUOUS: return "ld3d_z_p_bi.xml";
		case ENC_LD3D_Z_P_BR_CONTIGUOUS: return "ld3d_z_p_br.xml";
		case ENC_LD3H_Z_P_BI_CONTIGUOUS: return "ld3h_z_p_bi.xml";
		case ENC_LD3H_Z_P_BR_CONTIGUOUS: return "ld3h_z_p_br.xml";
		case ENC_LD3W_Z_P_BI_CONTIGUOUS: return "ld3w_z_p_bi.xml";
		case ENC_LD3W_Z_P_BR_CONTIGUOUS: return "ld3w_z_p_br.xml";
		case ENC_LD4B_Z_P_BI_CONTIGUOUS: return "ld4b_z_p_bi.xml";
		case ENC_LD4B_Z_P_BR_CONTIGUOUS: return "ld4b_z_p_br.xml";
		case ENC_LD4D_Z_P_BI_CONTIGUOUS: return "ld4d_z_p_bi.xml";
		case ENC_LD4D_Z_P_BR_CONTIGUOUS: return "ld4d_z_p_br.xml";
		case ENC_LD4H_Z_P_BI_CONTIGUOUS: return "ld4h_z_p_bi.xml";
		case ENC_LD4H_Z_P_BR_CONTIGUOUS: return "ld4h_z_p_br.xml";
		case ENC_LD4W_Z_P_BI_CONTIGUOUS: return "ld4w_z_p_bi.xml";
		case ENC_LD4W_Z_P_BR_CONTIGUOUS: return "ld4w_z_p_br.xml";
		case ENC_LDFF1B_Z_P_AI_D: return "ldff1b_z_p_ai.xml";
		case ENC_LDFF1B_Z_P_AI_S: return "ldff1b_z_p_ai.xml";
		case ENC_LDFF1B_Z_P_BR_U16: return "ldff1b_z_p_br.xml";
		case ENC_LDFF1B_Z_P_BR_U32: return "ldff1b_z_p_br.xml";
		case ENC_LDFF1B_Z_P_BR_U64: return "ldff1b_z_p_br.xml";
		case ENC_LDFF1B_Z_P_BR_U8: return "ldff1b_z_p_br.xml";
		case ENC_LDFF1B_Z_P_BZ_D_64_UNSCALED: return "ldff1b_z_p_bz.xml";
		case ENC_LDFF1B_Z_P_BZ_D_X32_UNSCALED: return "ldff1b_z_p_bz.xml";
		case ENC_LDFF1B_Z_P_BZ_S_X32_UNSCALED: return "ldff1b_z_p_bz.xml";
		case ENC_LDFF1D_Z_P_AI_D: return "ldff1d_z_p_ai.xml";
		case ENC_LDFF1D_Z_P_BR_U64: return "ldff1d_z_p_br.xml";
		case ENC_LDFF1D_Z_P_BZ_D_64_SCALED: return "ldff1d_z_p_bz.xml";
		case ENC_LDFF1D_Z_P_BZ_D_64_UNSCALED: return "ldff1d_z_p_bz.xml";
		case ENC_LDFF1D_Z_P_BZ_D_X32_SCALED: return "ldff1d_z_p_bz.xml";
		case ENC_LDFF1D_Z_P_BZ_D_X32_UNSCALED: return "ldff1d_z_p_bz.xml";
		case ENC_LDFF1H_Z_P_AI_D: return "ldff1h_z_p_ai.xml";
		case ENC_LDFF1H_Z_P_AI_S: return "ldff1h_z_p_ai.xml";
		case ENC_LDFF1H_Z_P_BR_U16: return "ldff1h_z_p_br.xml";
		case ENC_LDFF1H_Z_P_BR_U32: return "ldff1h_z_p_br.xml";
		case ENC_LDFF1H_Z_P_BR_U64: return "ldff1h_z_p_br.xml";
		case ENC_LDFF1H_Z_P_BZ_D_64_SCALED: return "ldff1h_z_p_bz.xml";
		case ENC_LDFF1H_Z_P_BZ_D_64_UNSCALED: return "ldff1h_z_p_bz.xml";
		case ENC_LDFF1H_Z_P_BZ_D_X32_SCALED: return "ldff1h_z_p_bz.xml";
		case ENC_LDFF1H_Z_P_BZ_D_X32_UNSCALED: return "ldff1h_z_p_bz.xml";
		case ENC_LDFF1H_Z_P_BZ_S_X32_SCALED: return "ldff1h_z_p_bz.xml";
		case ENC_LDFF1H_Z_P_BZ_S_X32_UNSCALED: return "ldff1h_z_p_bz.xml";
		case ENC_LDFF1SB_Z_P_AI_D: return "ldff1sb_z_p_ai.xml";
		case ENC_LDFF1SB_Z_P_AI_S: return "ldff1sb_z_p_ai.xml";
		case ENC_LDFF1SB_Z_P_BR_S16: return "ldff1sb_z_p_br.xml";
		case ENC_LDFF1SB_Z_P_BR_S32: return "ldff1sb_z_p_br.xml";
		case ENC_LDFF1SB_Z_P_BR_S64: return "ldff1sb_z_p_br.xml";
		case ENC_LDFF1SB_Z_P_BZ_D_64_UNSCALED: return "ldff1sb_z_p_bz.xml";
		case ENC_LDFF1SB_Z_P_BZ_D_X32_UNSCALED: return "ldff1sb_z_p_bz.xml";
		case ENC_LDFF1SB_Z_P_BZ_S_X32_UNSCALED: return "ldff1sb_z_p_bz.xml";
		case ENC_LDFF1SH_Z_P_AI_D: return "ldff1sh_z_p_ai.xml";
		case ENC_LDFF1SH_Z_P_AI_S: return "ldff1sh_z_p_ai.xml";
		case ENC_LDFF1SH_Z_P_BR_S32: return "ldff1sh_z_p_br.xml";
		case ENC_LDFF1SH_Z_P_BR_S64: return "ldff1sh_z_p_br.xml";
		case ENC_LDFF1SH_Z_P_BZ_D_64_SCALED: return "ldff1sh_z_p_bz.xml";
		case ENC_LDFF1SH_Z_P_BZ_D_64_UNSCALED: return "ldff1sh_z_p_bz.xml";
		case ENC_LDFF1SH_Z_P_BZ_D_X32_SCALED: return "ldff1sh_z_p_bz.xml";
		case ENC_LDFF1SH_Z_P_BZ_D_X32_UNSCALED: return "ldff1sh_z_p_bz.xml";
		case ENC_LDFF1SH_Z_P_BZ_S_X32_SCALED: return "ldff1sh_z_p_bz.xml";
		case ENC_LDFF1SH_Z_P_BZ_S_X32_UNSCALED: return "ldff1sh_z_p_bz.xml";
		case ENC_LDFF1SW_Z_P_AI_D: return "ldff1sw_z_p_ai.xml";
		case ENC_LDFF1SW_Z_P_BR_S64: return "ldff1sw_z_p_br.xml";
		case ENC_LDFF1SW_Z_P_BZ_D_64_SCALED: return "ldff1sw_z_p_bz.xml";
		case ENC_LDFF1SW_Z_P_BZ_D_64_UNSCALED: return "ldff1sw_z_p_bz.xml";
		case ENC_LDFF1SW_Z_P_BZ_D_X32_SCALED: return "ldff1sw_z_p_bz.xml";
		case ENC_LDFF1SW_Z_P_BZ_D_X32_UNSCALED: return "ldff1sw_z_p_bz.xml";
		case ENC_LDFF1W_Z_P_AI_D: return "ldff1w_z_p_ai.xml";
		case ENC_LDFF1W_Z_P_AI_S: return "ldff1w_z_p_ai.xml";
		case ENC_LDFF1W_Z_P_BR_U32: return "ldff1w_z_p_br.xml";
		case ENC_LDFF1W_Z_P_BR_U64: return "ldff1w_z_p_br.xml";
		case ENC_LDFF1W_Z_P_BZ_D_64_SCALED: return "ldff1w_z_p_bz.xml";
		case ENC_LDFF1W_Z_P_BZ_D_64_UNSCALED: return "ldff1w_z_p_bz.xml";
		case ENC_LDFF1W_Z_P_BZ_D_X32_SCALED: return "ldff1w_z_p_bz.xml";
		case ENC_LDFF1W_Z_P_BZ_D_X32_UNSCALED: return "ldff1w_z_p_bz.xml";
		case ENC_LDFF1W_Z_P_BZ_S_X32_SCALED: return "ldff1w_z_p_bz.xml";
		case ENC_LDFF1W_Z_P_BZ_S_X32_UNSCALED: return "ldff1w_z_p_bz.xml";
		case ENC_LDNF1B_Z_P_BI_U16: return "ldnf1b_z_p_bi.xml";
		case ENC_LDNF1B_Z_P_BI_U32: return "ldnf1b_z_p_bi.xml";
		case ENC_LDNF1B_Z_P_BI_U64: return "ldnf1b_z_p_bi.xml";
		case ENC_LDNF1B_Z_P_BI_U8: return "ldnf1b_z_p_bi.xml";
		case ENC_LDNF1D_Z_P_BI_U64: return "ldnf1d_z_p_bi.xml";
		case ENC_LDNF1H_Z_P_BI_U16: return "ldnf1h_z_p_bi.xml";
		case ENC_LDNF1H_Z_P_BI_U32: return "ldnf1h_z_p_bi.xml";
		case ENC_LDNF1H_Z_P_BI_U64: return "ldnf1h_z_p_bi.xml";
		case ENC_LDNF1SB_Z_P_BI_S16: return "ldnf1sb_z_p_bi.xml";
		case ENC_LDNF1SB_Z_P_BI_S32: return "ldnf1sb_z_p_bi.xml";
		case ENC_LDNF1SB_Z_P_BI_S64: return "ldnf1sb_z_p_bi.xml";
		case ENC_LDNF1SH_Z_P_BI_S32: return "ldnf1sh_z_p_bi.xml";
		case ENC_LDNF1SH_Z_P_BI_S64: return "ldnf1sh_z_p_bi.xml";
		case ENC_LDNF1SW_Z_P_BI_S64: return "ldnf1sw_z_p_bi.xml";
		case ENC_LDNF1W_Z_P_BI_U32: return "ldnf1w_z_p_bi.xml";
		case ENC_LDNF1W_Z_P_BI_U64: return "ldnf1w_z_p_bi.xml";
		case ENC_LDNT1B_Z_P_BI_CONTIGUOUS: return "ldnt1b_z_p_bi.xml";
		case ENC_LDNT1B_Z_P_BR_CONTIGUOUS: return "ldnt1b_z_p_br.xml";
		case ENC_LDNT1D_Z_P_BI_CONTIGUOUS: return "ldnt1d_z_p_bi.xml";
		case ENC_LDNT1D_Z_P_BR_CONTIGUOUS: return "ldnt1d_z_p_br.xml";
		case ENC_LDNT1H_Z_P_BI_CONTIGUOUS: return "ldnt1h_z_p_bi.xml";
		case ENC_LDNT1H_Z_P_BR_CONTIGUOUS: return "ldnt1h_z_p_br.xml";
		case ENC_LDNT1W_Z_P_BI_CONTIGUOUS: return "ldnt1w_z_p_bi.xml";
		case ENC_LDNT1W_Z_P_BR_CONTIGUOUS: return "ldnt1w_z_p_br.xml";
		case ENC_LDR_P_BI_: return "ldr_p_bi.xml";
		case ENC_LDR_Z_BI_: return "ldr_z_bi.xml";
		case ENC_LSL_Z_P_ZI_: return "lsl_z_p_zi.xml";
		case ENC_LSL_Z_P_ZW_: return "lsl_z_p_zw.xml";
		case ENC_LSL_Z_P_ZZ_: return "lsl_z_p_zz.xml";
		case ENC_LSL_Z_ZI_: return "lsl_z_zi.xml";
		case ENC_LSL_Z_ZW_: return "lsl_z_zw.xml";
		case ENC_LSLR_Z_P_ZZ_: return "lslr_z_p_zz.xml";
		case ENC_LSR_Z_P_ZI_: return "lsr_z_p_zi.xml";
		case ENC_LSR_Z_P_ZW_: return "lsr_z_p_zw.xml";
		case ENC_LSR_Z_P_ZZ_: return "lsr_z_p_zz.xml";
		case ENC_LSR_Z_ZI_: return "lsr_z_zi.xml";
		case ENC_LSR_Z_ZW_: return "lsr_z_zw.xml";
		case ENC_LSRR_Z_P_ZZ_: return "lsrr_z_p_zz.xml";
		case ENC_MAD_Z_P_ZZZ_: return "mad_z_p_zzz.xml";
		case ENC_MLA_Z_P_ZZZ_: return "mla_z_p_zzz.xml";
		case ENC_MLS_Z_P_ZZZ_: return "mls_z_p_zzz.xml";
		case ENC_MOVPRFX_Z_P_Z_: return "movprfx_z_p_z.xml";
		case ENC_MOVPRFX_Z_Z_: return "movprfx_z_z.xml";
		case ENC_MSB_Z_P_ZZZ_: return "msb_z_p_zzz.xml";
		case ENC_MUL_Z_P_ZZ_: return "mul_z_p_zz.xml";
		case ENC_MUL_Z_ZI_: return "mul_z_zi.xml";
		case ENC_NAND_P_P_PP_Z: return "nand_p_p_pp.xml";
		case ENC_NANDS_P_P_PP_Z: return "nand_p_p_pp.xml";
		case ENC_NEG_Z_P_Z_: return "neg_z_p_z.xml";
		case ENC_NOR_P_P_PP_Z: return "nor_p_p_pp.xml";
		case ENC_NORS_P_P_PP_Z: return "nor_p_p_pp.xml";
		case ENC_NOT_Z_P_Z_: return "not_z_p_z.xml";
		case ENC_ORN_P_P_PP_Z: return "orn_p_p_pp.xml";
		case ENC_ORNS_P_P_PP_Z: return "orn_p_p_pp.xml";
		case ENC_ORR_P_P_PP_Z: return "orr_p_p_pp.xml";
		case ENC_ORR_Z_P_ZZ_: return "orr_z_p_zz.xml";
		case ENC_ORR_Z_ZI_: return "orr_z_zi.xml";
		case ENC_ORR_Z_ZZ_: return "orr_z_zz.xml";
		case ENC_ORRS_P_P_PP_Z: return "orr_p_p_pp.xml";
		case ENC_ORV_R_P_Z_: return "orv_r_p_z.xml";
		case ENC_PFALSE_P_: return "pfalse_p.xml";
		case ENC_PFIRST_P_P_P_: return "pfirst_p_p_p.xml";
		case ENC_PNEXT_P_P_P_: return "pnext_p_p_p.xml";
		case ENC_PRFB_I_P_AI_D: return "prfb_i_p_ai.xml";
		case ENC_PRFB_I_P_AI_S: return "prfb_i_p_ai.xml";
		case ENC_PRFB_I_P_BI_S: return "prfb_i_p_bi.xml";
		case ENC_PRFB_I_P_BR_S: return "prfb_i_p_br.xml";
		case ENC_PRFB_I_P_BZ_D_64_SCALED: return "prfb_i_p_bz.xml";
		case ENC_PRFB_I_P_BZ_D_X32_SCALED: return "prfb_i_p_bz.xml";
		case ENC_PRFB_I_P_BZ_S_X32_SCALED: return "prfb_i_p_bz.xml";
		case ENC_PRFD_I_P_AI_D: return "prfd_i_p_ai.xml";
		case ENC_PRFD_I_P_AI_S: return "prfd_i_p_ai.xml";
		case ENC_PRFD_I_P_BI_S: return "prfd_i_p_bi.xml";
		case ENC_PRFD_I_P_BR_S: return "prfd_i_p_br.xml";
		case ENC_PRFD_I_P_BZ_D_64_SCALED: return "prfd_i_p_bz.xml";
		case ENC_PRFD_I_P_BZ_D_X32_SCALED: return "prfd_i_p_bz.xml";
		case ENC_PRFD_I_P_BZ_S_X32_SCALED: return "prfd_i_p_bz.xml";
		case ENC_PRFH_I_P_AI_D: return "prfh_i_p_ai.xml";
		case ENC_PRFH_I_P_AI_S: return "prfh_i_p_ai.xml";
		case ENC_PRFH_I_P_BI_S: return "prfh_i_p_bi.xml";
		case ENC_PRFH_I_P_BR_S: return "prfh_i_p_br.xml";
		case ENC_PRFH_I_P_BZ_D_64_SCALED: return "prfh_i_p_bz.xml";
		case ENC_PRFH_I_P_BZ_D_X32_SCALED: return "prfh_i_p_bz.xml";
		case ENC_PRFH_I_P_BZ_S_X32_SCALED: return "prfh_i_p_bz.xml";
		case ENC_PRFW_I_P_AI_D: return "prfw_i_p_ai.xml";
		case ENC_PRFW_I_P_AI_S: return "prfw_i_p_ai.xml";
		case ENC_PRFW_I_P_BI_S: return "prfw_i_p_bi.xml";
		case ENC_PRFW_I_P_BR_S: return "prfw_i_p_br.xml";
		case ENC_PRFW_I_P_BZ_D_64_SCALED: return "prfw_i_p_bz.xml";
		case ENC_PRFW_I_P_BZ_D_X32_SCALED: return "prfw_i_p_bz.xml";
		case ENC_PRFW_I_P_BZ_S_X32_SCALED: return "prfw_i_p_bz.xml";
		case ENC_PTEST_P_P_: return "ptest_p_p.xml";
		case ENC_PTRUE_P_S_: return "ptrue_p_s.xml";
		case ENC_PTRUES_P_S_: return "ptrue_p_s.xml";
		case ENC_PUNPKHI_P_P_: return "punpkhi_p_p.xml";
		case ENC_PUNPKLO_P_P_: return "punpkhi_p_p.xml";
		case ENC_RBIT_Z_P_Z_: return "rbit_z_p_z.xml";
		case ENC_RDFFR_P_F_: return "rdffr_p_f.xml";
		case ENC_RDFFR_P_P_F_: return "rdffr_p_p_f.xml";
		case ENC_RDFFRS_P_P_F_: return "rdffr_p_p_f.xml";
		case ENC_RDVL_R_I_: return "rdvl_r_i.xml";
		case ENC_REV_P_P_: return "rev_p_p.xml";
		case ENC_REV_Z_Z_: return "rev_z_z.xml";
		case ENC_REVB_Z_Z_: return "revb_z_z.xml";
		case ENC_REVH_Z_Z_: return "revb_z_z.xml";
		case ENC_REVW_Z_Z_: return "revb_z_z.xml";
		case ENC_SABD_Z_P_ZZ_: return "sabd_z_p_zz.xml";
		case ENC_SADDV_R_P_Z_: return "saddv_r_p_z.xml";
		case ENC_SCVTF_Z_P_Z_H2FP16: return "scvtf_z_p_z.xml";
		case ENC_SCVTF_Z_P_Z_W2D: return "scvtf_z_p_z.xml";
		case ENC_SCVTF_Z_P_Z_W2FP16: return "scvtf_z_p_z.xml";
		case ENC_SCVTF_Z_P_Z_W2S: return "scvtf_z_p_z.xml";
		case ENC_SCVTF_Z_P_Z_X2D: return "scvtf_z_p_z.xml";
		case ENC_SCVTF_Z_P_Z_X2FP16: return "scvtf_z_p_z.xml";
		case ENC_SCVTF_Z_P_Z_X2S: return "scvtf_z_p_z.xml";
		case ENC_SDIV_Z_P_ZZ_: return "sdiv_z_p_zz.xml";
		case ENC_SDIVR_Z_P_ZZ_: return "sdivr_z_p_zz.xml";
		case ENC_SDOT_Z_ZZZ_: return "sdot_z_zzz.xml";
		case ENC_SDOT_Z_ZZZI_D: return "sdot_z_zzzi.xml";
		case ENC_SDOT_Z_ZZZI_S: return "sdot_z_zzzi.xml";
		case ENC_SEL_P_P_PP_: return "sel_p_p_pp.xml";
		case ENC_SEL_Z_P_ZZ_: return "sel_z_p_zz.xml";
		case ENC_SETFFR_F_: return "setffr_f.xml";
		case ENC_SMAX_Z_P_ZZ_: return "smax_z_p_zz.xml";
		case ENC_SMAX_Z_ZI_: return "smax_z_zi.xml";
		case ENC_SMAXV_R_P_Z_: return "smaxv_r_p_z.xml";
		case ENC_SMIN_Z_P_ZZ_: return "smin_z_p_zz.xml";
		case ENC_SMIN_Z_ZI_: return "smin_z_zi.xml";
		case ENC_SMINV_R_P_Z_: return "sminv_r_p_z.xml";
		case ENC_SMMLA_Z_ZZZ_: return "smmla_z_zzz.xml";
		case ENC_SMULH_Z_P_ZZ_: return "smulh_z_p_zz.xml";
		case ENC_SPLICE_Z_P_ZZ_DES: return "splice_z_p_zz.xml";
		case ENC_SQADD_Z_ZI_: return "sqadd_z_zi.xml";
		case ENC_SQADD_Z_ZZ_: return "sqadd_z_zz.xml";
		case ENC_SQDECB_R_RS_SX: return "sqdecb_r_rs.xml";
		case ENC_SQDECB_R_RS_X: return "sqdecb_r_rs.xml";
		case ENC_SQDECD_R_RS_SX: return "sqdecd_r_rs.xml";
		case ENC_SQDECD_R_RS_X: return "sqdecd_r_rs.xml";
		case ENC_SQDECD_Z_ZS_: return "sqdecd_z_zs.xml";
		case ENC_SQDECH_R_RS_SX: return "sqdech_r_rs.xml";
		case ENC_SQDECH_R_RS_X: return "sqdech_r_rs.xml";
		case ENC_SQDECH_Z_ZS_: return "sqdech_z_zs.xml";
		case ENC_SQDECP_R_P_R_SX: return "sqdecp_r_p_r.xml";
		case ENC_SQDECP_R_P_R_X: return "sqdecp_r_p_r.xml";
		case ENC_SQDECP_Z_P_Z_: return "sqdecp_z_p_z.xml";
		case ENC_SQDECW_R_RS_SX: return "sqdecw_r_rs.xml";
		case ENC_SQDECW_R_RS_X: return "sqdecw_r_rs.xml";
		case ENC_SQDECW_Z_ZS_: return "sqdecw_z_zs.xml";
		case ENC_SQINCB_R_RS_SX: return "sqincb_r_rs.xml";
		case ENC_SQINCB_R_RS_X: return "sqincb_r_rs.xml";
		case ENC_SQINCD_R_RS_SX: return "sqincd_r_rs.xml";
		case ENC_SQINCD_R_RS_X: return "sqincd_r_rs.xml";
		case ENC_SQINCD_Z_ZS_: return "sqincd_z_zs.xml";
		case ENC_SQINCH_R_RS_SX: return "sqinch_r_rs.xml";
		case ENC_SQINCH_R_RS_X: return "sqinch_r_rs.xml";
		case ENC_SQINCH_Z_ZS_: return "sqinch_z_zs.xml";
		case ENC_SQINCP_R_P_R_SX: return "sqincp_r_p_r.xml";
		case ENC_SQINCP_R_P_R_X: return "sqincp_r_p_r.xml";
		case ENC_SQINCP_Z_P_Z_: return "sqincp_z_p_z.xml";
		case ENC_SQINCW_R_RS_SX: return "sqincw_r_rs.xml";
		case ENC_SQINCW_R_RS_X: return "sqincw_r_rs.xml";
		case ENC_SQINCW_Z_ZS_: return "sqincw_z_zs.xml";
		case ENC_SQSUB_Z_ZI_: return "sqsub_z_zi.xml";
		case ENC_SQSUB_Z_ZZ_: return "sqsub_z_zz.xml";
		case ENC_ST1B_Z_P_AI_D: return "st1b_z_p_ai.xml";
		case ENC_ST1B_Z_P_AI_S: return "st1b_z_p_ai.xml";
		case ENC_ST1B_Z_P_BI_: return "st1b_z_p_bi.xml";
		case ENC_ST1B_Z_P_BR_: return "st1b_z_p_br.xml";
		case ENC_ST1B_Z_P_BZ_D_64_UNSCALED: return "st1b_z_p_bz.xml";
		case ENC_ST1B_Z_P_BZ_D_X32_UNSCALED: return "st1b_z_p_bz.xml";
		case ENC_ST1B_Z_P_BZ_S_X32_UNSCALED: return "st1b_z_p_bz.xml";
		case ENC_ST1D_Z_P_AI_D: return "st1d_z_p_ai.xml";
		case ENC_ST1D_Z_P_BI_: return "st1d_z_p_bi.xml";
		case ENC_ST1D_Z_P_BR_: return "st1d_z_p_br.xml";
		case ENC_ST1D_Z_P_BZ_D_64_SCALED: return "st1d_z_p_bz.xml";
		case ENC_ST1D_Z_P_BZ_D_64_UNSCALED: return "st1d_z_p_bz.xml";
		case ENC_ST1D_Z_P_BZ_D_X32_SCALED: return "st1d_z_p_bz.xml";
		case ENC_ST1D_Z_P_BZ_D_X32_UNSCALED: return "st1d_z_p_bz.xml";
		case ENC_ST1H_Z_P_AI_D: return "st1h_z_p_ai.xml";
		case ENC_ST1H_Z_P_AI_S: return "st1h_z_p_ai.xml";
		case ENC_ST1H_Z_P_BI_: return "st1h_z_p_bi.xml";
		case ENC_ST1H_Z_P_BR_: return "st1h_z_p_br.xml";
		case ENC_ST1H_Z_P_BZ_D_64_SCALED: return "st1h_z_p_bz.xml";
		case ENC_ST1H_Z_P_BZ_D_64_UNSCALED: return "st1h_z_p_bz.xml";
		case ENC_ST1H_Z_P_BZ_D_X32_SCALED: return "st1h_z_p_bz.xml";
		case ENC_ST1H_Z_P_BZ_D_X32_UNSCALED: return "st1h_z_p_bz.xml";
		case ENC_ST1H_Z_P_BZ_S_X32_SCALED: return "st1h_z_p_bz.xml";
		case ENC_ST1H_Z_P_BZ_S_X32_UNSCALED: return "st1h_z_p_bz.xml";
		case ENC_ST1W_Z_P_AI_D: return "st1w_z_p_ai.xml";
		case ENC_ST1W_Z_P_AI_S: return "st1w_z_p_ai.xml";
		case ENC_ST1W_Z_P_BI_: return "st1w_z_p_bi.xml";
		case ENC_ST1W_Z_P_BR_: return "st1w_z_p_br.xml";
		case ENC_ST1W_Z_P_BZ_D_64_SCALED: return "st1w_z_p_bz.xml";
		case ENC_ST1W_Z_P_BZ_D_64_UNSCALED: return "st1w_z_p_bz.xml";
		case ENC_ST1W_Z_P_BZ_D_X32_SCALED: return "st1w_z_p_bz.xml";
		case ENC_ST1W_Z_P_BZ_D_X32_UNSCALED: return "st1w_z_p_bz.xml";
		case ENC_ST1W_Z_P_BZ_S_X32_SCALED: return "st1w_z_p_bz.xml";
		case ENC_ST1W_Z_P_BZ_S_X32_UNSCALED: return "st1w_z_p_bz.xml";
		case ENC_ST2B_Z_P_BI_CONTIGUOUS: return "st2b_z_p_bi.xml";
		case ENC_ST2B_Z_P_BR_CONTIGUOUS: return "st2b_z_p_br.xml";
		case ENC_ST2D_Z_P_BI_CONTIGUOUS: return "st2d_z_p_bi.xml";
		case ENC_ST2D_Z_P_BR_CONTIGUOUS: return "st2d_z_p_br.xml";
		case ENC_ST2H_Z_P_BI_CONTIGUOUS: return "st2h_z_p_bi.xml";
		case ENC_ST2H_Z_P_BR_CONTIGUOUS: return "st2h_z_p_br.xml";
		case ENC_ST2W_Z_P_BI_CONTIGUOUS: return "st2w_z_p_bi.xml";
		case ENC_ST2W_Z_P_BR_CONTIGUOUS: return "st2w_z_p_br.xml";
		case ENC_ST3B_Z_P_BI_CONTIGUOUS: return "st3b_z_p_bi.xml";
		case ENC_ST3B_Z_P_BR_CONTIGUOUS: return "st3b_z_p_br.xml";
		case ENC_ST3D_Z_P_BI_CONTIGUOUS: return "st3d_z_p_bi.xml";
		case ENC_ST3D_Z_P_BR_CONTIGUOUS: return "st3d_z_p_br.xml";
		case ENC_ST3H_Z_P_BI_CONTIGUOUS: return "st3h_z_p_bi.xml";
		case ENC_ST3H_Z_P_BR_CONTIGUOUS: return "st3h_z_p_br.xml";
		case ENC_ST3W_Z_P_BI_CONTIGUOUS: return "st3w_z_p_bi.xml";
		case ENC_ST3W_Z_P_BR_CONTIGUOUS: return "st3w_z_p_br.xml";
		case ENC_ST4B_Z_P_BI_CONTIGUOUS: return "st4b_z_p_bi.xml";
		case ENC_ST4B_Z_P_BR_CONTIGUOUS: return "st4b_z_p_br.xml";
		case ENC_ST4D_Z_P_BI_CONTIGUOUS: return "st4d_z_p_bi.xml";
		case ENC_ST4D_Z_P_BR_CONTIGUOUS: return "st4d_z_p_br.xml";
		case ENC_ST4H_Z_P_BI_CONTIGUOUS: return "st4h_z_p_bi.xml";
		case ENC_ST4H_Z_P_BR_CONTIGUOUS: return "st4h_z_p_br.xml";
		case ENC_ST4W_Z_P_BI_CONTIGUOUS: return "st4w_z_p_bi.xml";
		case ENC_ST4W_Z_P_BR_CONTIGUOUS: return "st4w_z_p_br.xml";
		case ENC_STNT1B_Z_P_BI_CONTIGUOUS: return "stnt1b_z_p_bi.xml";
		case ENC_STNT1B_Z_P_BR_CONTIGUOUS: return "stnt1b_z_p_br.xml";
		case ENC_STNT1D_Z_P_BI_CONTIGUOUS: return "stnt1d_z_p_bi.xml";
		case ENC_STNT1D_Z_P_BR_CONTIGUOUS: return "stnt1d_z_p_br.xml";
		case ENC_STNT1H_Z_P_BI_CONTIGUOUS: return "stnt1h_z_p_bi.xml";
		case ENC_STNT1H_Z_P_BR_CONTIGUOUS: return "stnt1h_z_p_br.xml";
		case ENC_STNT1W_Z_P_BI_CONTIGUOUS: return "stnt1w_z_p_bi.xml";
		case ENC_STNT1W_Z_P_BR_CONTIGUOUS: return "stnt1w_z_p_br.xml";
		case ENC_STR_P_BI_: return "str_p_bi.xml";
		case ENC_STR_Z_BI_: return "str_z_bi.xml";
		case ENC_SUB_Z_P_ZZ_: return "sub_z_p_zz.xml";
		case ENC_SUB_Z_ZI_: return "sub_z_zi.xml";
		case ENC_SUB_Z_ZZ_: return "sub_z_zz.xml";
		case ENC_SUBR_Z_P_ZZ_: return "subr_z_p_zz.xml";
		case ENC_SUBR_Z_ZI_: return "subr_z_zi.xml";
		case ENC_SUDOT_Z_ZZZI_S: return "sudot_z_zzzi.xml";
		case ENC_SUNPKHI_Z_Z_: return "sunpkhi_z_z.xml";
		case ENC_SUNPKLO_Z_Z_: return "sunpkhi_z_z.xml";
		case ENC_SXTB_Z_P_Z_: return "sxtb_z_p_z.xml";
		case ENC_SXTH_Z_P_Z_: return "sxtb_z_p_z.xml";
		case ENC_SXTW_Z_P_Z_: return "sxtb_z_p_z.xml";
		case ENC_TBL_Z_ZZ_1: return "tbl_z_zz.xml";
		case ENC_TRN1_P_PP_: return "trn1_p_pp.xml";
		case ENC_TRN1_Z_ZZ_: return "trn1_z_zz.xml";
		case ENC_TRN1_Z_ZZ_Q: return "trn1_z_zz.xml";
		case ENC_TRN2_P_PP_: return "trn1_p_pp.xml";
		case ENC_TRN2_Z_ZZ_: return "trn1_z_zz.xml";
		case ENC_TRN2_Z_ZZ_Q: return "trn1_z_zz.xml";
		case ENC_UABD_Z_P_ZZ_: return "uabd_z_p_zz.xml";
		case ENC_UADDV_R_P_Z_: return "uaddv_r_p_z.xml";
		case ENC_UCVTF_Z_P_Z_H2FP16: return "ucvtf_z_p_z.xml";
		case ENC_UCVTF_Z_P_Z_W2D: return "ucvtf_z_p_z.xml";
		case ENC_UCVTF_Z_P_Z_W2FP16: return "ucvtf_z_p_z.xml";
		case ENC_UCVTF_Z_P_Z_W2S: return "ucvtf_z_p_z.xml";
		case ENC_UCVTF_Z_P_Z_X2D: return "ucvtf_z_p_z.xml";
		case ENC_UCVTF_Z_P_Z_X2FP16: return "ucvtf_z_p_z.xml";
		case ENC_UCVTF_Z_P_Z_X2S: return "ucvtf_z_p_z.xml";
		case ENC_UDIV_Z_P_ZZ_: return "udiv_z_p_zz.xml";
		case ENC_UDIVR_Z_P_ZZ_: return "udivr_z_p_zz.xml";
		case ENC_UDOT_Z_ZZZ_: return "udot_z_zzz.xml";
		case ENC_UDOT_Z_ZZZI_D: return "udot_z_zzzi.xml";
		case ENC_UDOT_Z_ZZZI_S: return "udot_z_zzzi.xml";
		case ENC_UMAX_Z_P_ZZ_: return "umax_z_p_zz.xml";
		case ENC_UMAX_Z_ZI_: return "umax_z_zi.xml";
		case ENC_UMAXV_R_P_Z_: return "umaxv_r_p_z.xml";
		case ENC_UMIN_Z_P_ZZ_: return "umin_z_p_zz.xml";
		case ENC_UMIN_Z_ZI_: return "umin_z_zi.xml";
		case ENC_UMINV_R_P_Z_: return "uminv_r_p_z.xml";
		case ENC_UMMLA_Z_ZZZ_: return "ummla_z_zzz.xml";
		case ENC_UMULH_Z_P_ZZ_: return "umulh_z_p_zz.xml";
		case ENC_UQADD_Z_ZI_: return "uqadd_z_zi.xml";
		case ENC_UQADD_Z_ZZ_: return "uqadd_z_zz.xml";
		case ENC_UQDECB_R_RS_UW: return "uqdecb_r_rs.xml";
		case ENC_UQDECB_R_RS_X: return "uqdecb_r_rs.xml";
		case ENC_UQDECD_R_RS_UW: return "uqdecd_r_rs.xml";
		case ENC_UQDECD_R_RS_X: return "uqdecd_r_rs.xml";
		case ENC_UQDECD_Z_ZS_: return "uqdecd_z_zs.xml";
		case ENC_UQDECH_R_RS_UW: return "uqdech_r_rs.xml";
		case ENC_UQDECH_R_RS_X: return "uqdech_r_rs.xml";
		case ENC_UQDECH_Z_ZS_: return "uqdech_z_zs.xml";
		case ENC_UQDECP_R_P_R_UW: return "uqdecp_r_p_r.xml";
		case ENC_UQDECP_R_P_R_X: return "uqdecp_r_p_r.xml";
		case ENC_UQDECP_Z_P_Z_: return "uqdecp_z_p_z.xml";
		case ENC_UQDECW_R_RS_UW: return "uqdecw_r_rs.xml";
		case ENC_UQDECW_R_RS_X: return "uqdecw_r_rs.xml";
		case ENC_UQDECW_Z_ZS_: return "uqdecw_z_zs.xml";
		case ENC_UQINCB_R_RS_UW: return "uqincb_r_rs.xml";
		case ENC_UQINCB_R_RS_X: return "uqincb_r_rs.xml";
		case ENC_UQINCD_R_RS_UW: return "uqincd_r_rs.xml";
		case ENC_UQINCD_R_RS_X: return "uqincd_r_rs.xml";
		case ENC_UQINCD_Z_ZS_: return "uqincd_z_zs.xml";
		case ENC_UQINCH_R_RS_UW: return "uqinch_r_rs.xml";
		case ENC_UQINCH_R_RS_X: return "uqinch_r_rs.xml";
		case ENC_UQINCH_Z_ZS_: return "uqinch_z_zs.xml";
		case ENC_UQINCP_R_P_R_UW: return "uqincp_r_p_r.xml";
		case ENC_UQINCP_R_P_R_X: return "uqincp_r_p_r.xml";
		case ENC_UQINCP_Z_P_Z_: return "uqincp_z_p_z.xml";
		case ENC_UQINCW_R_RS_UW: return "uqincw_r_rs.xml";
		case ENC_UQINCW_R_RS_X: return "uqincw_r_rs.xml";
		case ENC_UQINCW_Z_ZS_: return "uqincw_z_zs.xml";
		case ENC_UQSUB_Z_ZI_: return "uqsub_z_zi.xml";
		case ENC_UQSUB_Z_ZZ_: return "uqsub_z_zz.xml";
		case ENC_USDOT_Z_ZZZ_S: return "usdot_z_zzz.xml";
		case ENC_USDOT_Z_ZZZI_S: return "usdot_z_zzzi.xml";
		case ENC_USMMLA_Z_ZZZ_: return "usmmla_z_zzz.xml";
		case ENC_UUNPKHI_Z_Z_: return "uunpkhi_z_z.xml";
		case ENC_UUNPKLO_Z_Z_: return "uunpkhi_z_z.xml";
		case ENC_UXTB_Z_P_Z_: return "uxtb_z_p_z.xml";
		case ENC_UXTH_Z_P_Z_: return "uxtb_z_p_z.xml";
		case ENC_UXTW_Z_P_Z_: return "uxtb_z_p_z.xml";
		case ENC_UZP1_P_PP_: return "uzp1_p_pp.xml";
		case ENC_UZP1_Z_ZZ_: return "uzp1_z_zz.xml";
		case ENC_UZP1_Z_ZZ_Q: return "uzp1_z_zz.xml";
		case ENC_UZP2_P_PP_: return "uzp1_p_pp.xml";
		case ENC_UZP2_Z_ZZ_: return "uzp1_z_zz.xml";
		case ENC_UZP2_Z_ZZ_Q: return "uzp1_z_zz.xml";
		case ENC_WHILELE_P_P_RR_: return "whilele_p_p_rr.xml";
		case ENC_WHILELO_P_P_RR_: return "whilelo_p_p_rr.xml";
		case ENC_WHILELS_P_P_RR_: return "whilels_p_p_rr.xml";
		case ENC_WHILELT_P_P_RR_: return "whilelt_p_p_rr.xml";
		case ENC_WRFFR_F_P_: return "wrffr_f_p.xml";
		case ENC_ZIP1_P_PP_: return "zip1_p_pp.xml";
		case ENC_ZIP1_Z_ZZ_: return "zip1_z_zz.xml";
		case ENC_ZIP1_Z_ZZ_Q: return "zip1_z_zz.xml";
		case ENC_ZIP2_P_PP_: return "zip1_p_pp.xml";
		case ENC_ZIP2_Z_ZZ_: return "zip1_z_zz.xml";
		case ENC_ZIP2_Z_ZZ_Q: return "zip1_z_zz.xml";
		default: return "error";
	}
}

enum Operation enc_to_oper(enum ENCODING enc)
{
	switch(enc) {
		case ENC_ABS_ASISDMISC_R:
		case ENC_ABS_ASIMDMISC_R:
		case ENC_ABS_Z_P_Z_:
			return ARM64_ABS;
		case ENC_ADC_32_ADDSUB_CARRY:
		case ENC_ADC_64_ADDSUB_CARRY:
			return ARM64_ADC;
		case ENC_ADCS_32_ADDSUB_CARRY:
		case ENC_ADCS_64_ADDSUB_CARRY:
			return ARM64_ADCS;
		case ENC_ADD_32_ADDSUB_EXT:
		case ENC_ADD_64_ADDSUB_EXT:
		case ENC_ADD_32_ADDSUB_IMM:
		case ENC_ADD_64_ADDSUB_IMM:
		case ENC_ADD_32_ADDSUB_SHIFT:
		case ENC_ADD_64_ADDSUB_SHIFT:
		case ENC_ADD_ASISDSAME_ONLY:
		case ENC_ADD_ASIMDSAME_ONLY:
		case ENC_ADD_Z_P_ZZ_:
		case ENC_ADD_Z_ZI_:
		case ENC_ADD_Z_ZZ_:
			return ARM64_ADD;
		case ENC_ADDG_64_ADDSUB_IMMTAGS:
			return ARM64_ADDG;
		case ENC_ADDHN_ASIMDDIFF_N:
			return ARM64_ADDHN;
		//case ENC_ADDHN_ASIMDDIFF_N:
		//	return ARM64_ADDHN2;
		case ENC_ADDP_ASISDPAIR_ONLY:
		case ENC_ADDP_ASIMDSAME_ONLY:
			return ARM64_ADDP;
		case ENC_ADDPL_R_RI_:
			return ARM64_ADDPL;
		case ENC_ADDS_32S_ADDSUB_EXT:
		case ENC_ADDS_64S_ADDSUB_EXT:
		case ENC_ADDS_32S_ADDSUB_IMM:
		case ENC_ADDS_64S_ADDSUB_IMM:
		case ENC_ADDS_32_ADDSUB_SHIFT:
		case ENC_ADDS_64_ADDSUB_SHIFT:
			return ARM64_ADDS;
		case ENC_ADDV_ASIMDALL_ONLY:
			return ARM64_ADDV;
		case ENC_ADDVL_R_RI_:
			return ARM64_ADDVL;
		case ENC_ADR_ONLY_PCRELADDR:
		case ENC_ADR_Z_AZ_SD_SAME_SCALED:
		case ENC_ADR_Z_AZ_D_S32_SCALED:
		case ENC_ADR_Z_AZ_D_U32_SCALED:
			return ARM64_ADR;
		case ENC_ADRP_ONLY_PCRELADDR:
			return ARM64_ADRP;
		case ENC_AESD_B_CRYPTOAES:
			return ARM64_AESD;
		case ENC_AESE_B_CRYPTOAES:
			return ARM64_AESE;
		case ENC_AESIMC_B_CRYPTOAES:
			return ARM64_AESIMC;
		case ENC_AESMC_B_CRYPTOAES:
			return ARM64_AESMC;
		case ENC_AND_ASIMDSAME_ONLY:
		case ENC_AND_32_LOG_IMM:
		case ENC_AND_64_LOG_IMM:
		case ENC_AND_32_LOG_SHIFT:
		case ENC_AND_64_LOG_SHIFT:
		case ENC_AND_P_P_PP_Z:
		case ENC_AND_Z_P_ZZ_:
		case ENC_AND_Z_ZI_:
		case ENC_AND_Z_ZZ_:
			return ARM64_AND;
		case ENC_ANDS_32S_LOG_IMM:
		case ENC_ANDS_64S_LOG_IMM:
		case ENC_ANDS_32_LOG_SHIFT:
		case ENC_ANDS_64_LOG_SHIFT:
		case ENC_ANDS_P_P_PP_Z:
			return ARM64_ANDS;
		case ENC_ANDV_R_P_Z_:
			return ARM64_ANDV;
		case ENC_ASR_ASRV_32_DP_2SRC:
		case ENC_ASR_ASRV_64_DP_2SRC:
		case ENC_ASR_SBFM_32M_BITFIELD:
		case ENC_ASR_SBFM_64M_BITFIELD:
		case ENC_ASR_Z_P_ZI_:
		case ENC_ASR_Z_P_ZW_:
		case ENC_ASR_Z_P_ZZ_:
		case ENC_ASR_Z_ZI_:
		case ENC_ASR_Z_ZW_:
			return ARM64_ASR;
		case ENC_ASRD_Z_P_ZI_:
			return ARM64_ASRD;
		case ENC_ASRR_Z_P_ZZ_:
			return ARM64_ASRR;
		case ENC_ASRV_32_DP_2SRC:
		case ENC_ASRV_64_DP_2SRC:
			return ARM64_ASRV;
		case ENC_AT_SYS_CR_SYSTEMINSTRS:
			return ARM64_AT;
		case ENC_AUTDA_64P_DP_1SRC:
			return ARM64_AUTDA;
		case ENC_AUTDB_64P_DP_1SRC:
			return ARM64_AUTDB;
		case ENC_AUTDZA_64Z_DP_1SRC:
			return ARM64_AUTDZA;
		case ENC_AUTDZB_64Z_DP_1SRC:
			return ARM64_AUTDZB;
		case ENC_AUTIA_64P_DP_1SRC:
			return ARM64_AUTIA;
		case ENC_AUTIA1716_HI_HINTS:
			return ARM64_AUTIA1716;
		case ENC_AUTIASP_HI_HINTS:
			return ARM64_AUTIASP;
		case ENC_AUTIAZ_HI_HINTS:
			return ARM64_AUTIAZ;
		case ENC_AUTIB_64P_DP_1SRC:
			return ARM64_AUTIB;
		case ENC_AUTIB1716_HI_HINTS:
			return ARM64_AUTIB1716;
		case ENC_AUTIBSP_HI_HINTS:
			return ARM64_AUTIBSP;
		case ENC_AUTIBZ_HI_HINTS:
			return ARM64_AUTIBZ;
		case ENC_AUTIZA_64Z_DP_1SRC:
			return ARM64_AUTIZA;
		case ENC_AUTIZB_64Z_DP_1SRC:
			return ARM64_AUTIZB;
		case ENC_AXFLAG_M_PSTATE:
			return ARM64_AXFLAG;
		case ENC_B_ONLY_CONDBRANCH:
		case ENC_B_ONLY_BRANCH_IMM:
			return ARM64_B;
		case ENC_BCAX_VVV16_CRYPTO4:
			return ARM64_BCAX;
		case ENC_BFC_BFM_32M_BITFIELD:
		case ENC_BFC_BFM_64M_BITFIELD:
			return ARM64_BFC;
		case ENC_BFCVT_BS_FLOATDP1:
		case ENC_BFCVT_Z_P_Z_S2BF:
			return ARM64_BFCVT;
		case ENC_BFCVTN_ASIMDMISC_4S:
			return ARM64_BFCVTN;
		//case ENC_BFCVTN_ASIMDMISC_4S:
		//	return ARM64_BFCVTN2;
		case ENC_BFCVTNT_Z_P_Z_S2BF:
			return ARM64_BFCVTNT;
		case ENC_BFDOT_ASIMDELEM_E:
		case ENC_BFDOT_ASIMDSAME2_D:
		case ENC_BFDOT_Z_ZZZ_:
		case ENC_BFDOT_Z_ZZZI_:
			return ARM64_BFDOT;
		case ENC_BFI_BFM_32M_BITFIELD:
		case ENC_BFI_BFM_64M_BITFIELD:
			return ARM64_BFI;
		case ENC_BFM_32M_BITFIELD:
		case ENC_BFM_64M_BITFIELD:
			return ARM64_BFM;
		case ENC_BFMLAL_ASIMDELEM_F:
		case ENC_BFMLAL_ASIMDSAME2_F_:
			return ARM64_BFMLAL;
		case ENC_BFMLALB_Z_ZZZ_:
		case ENC_BFMLALB_Z_ZZZI_:
			return ARM64_BFMLALB;
		case ENC_BFMLALT_Z_ZZZ_:
		case ENC_BFMLALT_Z_ZZZI_:
			return ARM64_BFMLALT;
		case ENC_BFMMLA_ASIMDSAME2_E:
		case ENC_BFMMLA_Z_ZZZ_:
			return ARM64_BFMMLA;
		case ENC_BFXIL_BFM_32M_BITFIELD:
		case ENC_BFXIL_BFM_64M_BITFIELD:
			return ARM64_BFXIL;
		case ENC_BIC_ASIMDIMM_L_HL:
		case ENC_BIC_ASIMDIMM_L_SL:
		case ENC_BIC_ASIMDSAME_ONLY:
		case ENC_BIC_AND_Z_ZI_:
		case ENC_BIC_32_LOG_SHIFT:
		case ENC_BIC_64_LOG_SHIFT:
		case ENC_BIC_P_P_PP_Z:
		case ENC_BIC_Z_P_ZZ_:
		case ENC_BIC_Z_ZZ_:
			return ARM64_BIC;
		case ENC_BICS_32_LOG_SHIFT:
		case ENC_BICS_64_LOG_SHIFT:
		case ENC_BICS_P_P_PP_Z:
			return ARM64_BICS;
		case ENC_BIF_ASIMDSAME_ONLY:
			return ARM64_BIF;
		case ENC_BIT_ASIMDSAME_ONLY:
			return ARM64_BIT;
		case ENC_BL_ONLY_BRANCH_IMM:
			return ARM64_BL;
		case ENC_BLR_64_BRANCH_REG:
			return ARM64_BLR;
		case ENC_BLRAA_64P_BRANCH_REG:
			return ARM64_BLRAA;
		case ENC_BLRAAZ_64_BRANCH_REG:
			return ARM64_BLRAAZ;
		case ENC_BLRAB_64P_BRANCH_REG:
			return ARM64_BLRAB;
		case ENC_BLRABZ_64_BRANCH_REG:
			return ARM64_BLRABZ;
		case ENC_BR_64_BRANCH_REG:
			return ARM64_BR;
		case ENC_BRAA_64P_BRANCH_REG:
			return ARM64_BRAA;
		case ENC_BRAAZ_64_BRANCH_REG:
			return ARM64_BRAAZ;
		case ENC_BRAB_64P_BRANCH_REG:
			return ARM64_BRAB;
		case ENC_BRABZ_64_BRANCH_REG:
			return ARM64_BRABZ;
		case ENC_BRK_EX_EXCEPTION:
			return ARM64_BRK;
		case ENC_BRKA_P_P_P_:
			return ARM64_BRKA;
		case ENC_BRKAS_P_P_P_Z:
			return ARM64_BRKAS;
		case ENC_BRKB_P_P_P_:
			return ARM64_BRKB;
		case ENC_BRKBS_P_P_P_Z:
			return ARM64_BRKBS;
		case ENC_BRKN_P_P_PP_:
			return ARM64_BRKN;
		case ENC_BRKNS_P_P_PP_:
			return ARM64_BRKNS;
		case ENC_BRKPA_P_P_PP_:
			return ARM64_BRKPA;
		case ENC_BRKPAS_P_P_PP_:
			return ARM64_BRKPAS;
		case ENC_BRKPB_P_P_PP_:
			return ARM64_BRKPB;
		case ENC_BRKPBS_P_P_PP_:
			return ARM64_BRKPBS;
		case ENC_BSL_ASIMDSAME_ONLY:
			return ARM64_BSL;
		case ENC_BTI_HB_HINTS:
			return ARM64_BTI;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_AL;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_CC;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_CS;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_EQ;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_GE;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_GT;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_HI;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_LE;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_LS;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_LT;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_MI;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_NE;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_NV;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_PL;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_VC;
		//case ENC_B_ONLY_CONDBRANCH:
		//	return ARM64_B_VS;
		case ENC_CAS_C32_LDSTEXCL:
		case ENC_CAS_C64_LDSTEXCL:
			return ARM64_CAS;
		case ENC_CASA_C32_LDSTEXCL:
		case ENC_CASA_C64_LDSTEXCL:
			return ARM64_CASA;
		case ENC_CASAB_C32_LDSTEXCL:
			return ARM64_CASAB;
		case ENC_CASAH_C32_LDSTEXCL:
			return ARM64_CASAH;
		case ENC_CASAL_C32_LDSTEXCL:
		case ENC_CASAL_C64_LDSTEXCL:
			return ARM64_CASAL;
		case ENC_CASALB_C32_LDSTEXCL:
			return ARM64_CASALB;
		case ENC_CASALH_C32_LDSTEXCL:
			return ARM64_CASALH;
		case ENC_CASB_C32_LDSTEXCL:
			return ARM64_CASB;
		case ENC_CASH_C32_LDSTEXCL:
			return ARM64_CASH;
		case ENC_CASL_C32_LDSTEXCL:
		case ENC_CASL_C64_LDSTEXCL:
			return ARM64_CASL;
		case ENC_CASLB_C32_LDSTEXCL:
			return ARM64_CASLB;
		case ENC_CASLH_C32_LDSTEXCL:
			return ARM64_CASLH;
		case ENC_CASP_CP32_LDSTEXCL:
		case ENC_CASP_CP64_LDSTEXCL:
			return ARM64_CASP;
		case ENC_CASPA_CP32_LDSTEXCL:
		case ENC_CASPA_CP64_LDSTEXCL:
			return ARM64_CASPA;
		case ENC_CASPAL_CP32_LDSTEXCL:
		case ENC_CASPAL_CP64_LDSTEXCL:
			return ARM64_CASPAL;
		case ENC_CASPL_CP32_LDSTEXCL:
		case ENC_CASPL_CP64_LDSTEXCL:
			return ARM64_CASPL;
		case ENC_CBNZ_32_COMPBRANCH:
		case ENC_CBNZ_64_COMPBRANCH:
			return ARM64_CBNZ;
		case ENC_CBZ_32_COMPBRANCH:
		case ENC_CBZ_64_COMPBRANCH:
			return ARM64_CBZ;
		case ENC_CCMN_32_CONDCMP_IMM:
		case ENC_CCMN_64_CONDCMP_IMM:
		case ENC_CCMN_32_CONDCMP_REG:
		case ENC_CCMN_64_CONDCMP_REG:
			return ARM64_CCMN;
		case ENC_CCMP_32_CONDCMP_IMM:
		case ENC_CCMP_64_CONDCMP_IMM:
		case ENC_CCMP_32_CONDCMP_REG:
		case ENC_CCMP_64_CONDCMP_REG:
			return ARM64_CCMP;
		case ENC_CFINV_M_PSTATE:
			return ARM64_CFINV;
		case ENC_CFP_SYS_CR_SYSTEMINSTRS:
			return ARM64_CFP;
		case ENC_CINC_CSINC_32_CONDSEL:
		case ENC_CINC_CSINC_64_CONDSEL:
			return ARM64_CINC;
		case ENC_CINV_CSINV_32_CONDSEL:
		case ENC_CINV_CSINV_64_CONDSEL:
			return ARM64_CINV;
		case ENC_CLASTA_R_P_Z_:
		case ENC_CLASTA_V_P_Z_:
		case ENC_CLASTA_Z_P_ZZ_:
			return ARM64_CLASTA;
		case ENC_CLASTB_R_P_Z_:
		case ENC_CLASTB_V_P_Z_:
		case ENC_CLASTB_Z_P_ZZ_:
			return ARM64_CLASTB;
		case ENC_CLREX_BN_BARRIERS:
			return ARM64_CLREX;
		case ENC_CLS_ASIMDMISC_R:
		case ENC_CLS_32_DP_1SRC:
		case ENC_CLS_64_DP_1SRC:
		case ENC_CLS_Z_P_Z_:
			return ARM64_CLS;
		case ENC_CLZ_ASIMDMISC_R:
		case ENC_CLZ_32_DP_1SRC:
		case ENC_CLZ_64_DP_1SRC:
		case ENC_CLZ_Z_P_Z_:
			return ARM64_CLZ;
		case ENC_CMEQ_ASISDSAME_ONLY:
		case ENC_CMEQ_ASIMDSAME_ONLY:
		case ENC_CMEQ_ASISDMISC_Z:
		case ENC_CMEQ_ASIMDMISC_Z:
			return ARM64_CMEQ;
		case ENC_CMGE_ASISDSAME_ONLY:
		case ENC_CMGE_ASIMDSAME_ONLY:
		case ENC_CMGE_ASISDMISC_Z:
		case ENC_CMGE_ASIMDMISC_Z:
			return ARM64_CMGE;
		case ENC_CMGT_ASISDSAME_ONLY:
		case ENC_CMGT_ASIMDSAME_ONLY:
		case ENC_CMGT_ASISDMISC_Z:
		case ENC_CMGT_ASIMDMISC_Z:
			return ARM64_CMGT;
		case ENC_CMHI_ASISDSAME_ONLY:
		case ENC_CMHI_ASIMDSAME_ONLY:
			return ARM64_CMHI;
		case ENC_CMHS_ASISDSAME_ONLY:
		case ENC_CMHS_ASIMDSAME_ONLY:
			return ARM64_CMHS;
		case ENC_CMLE_ASISDMISC_Z:
		case ENC_CMLE_ASIMDMISC_Z:
			return ARM64_CMLE;
		case ENC_CMLT_ASISDMISC_Z:
		case ENC_CMLT_ASIMDMISC_Z:
			return ARM64_CMLT;
		case ENC_CMN_ADDS_32S_ADDSUB_EXT:
		case ENC_CMN_ADDS_64S_ADDSUB_EXT:
		case ENC_CMN_ADDS_32S_ADDSUB_IMM:
		case ENC_CMN_ADDS_64S_ADDSUB_IMM:
		case ENC_CMN_ADDS_32_ADDSUB_SHIFT:
		case ENC_CMN_ADDS_64_ADDSUB_SHIFT:
			return ARM64_CMN;
		case ENC_CMP_SUBS_32S_ADDSUB_EXT:
		case ENC_CMP_SUBS_64S_ADDSUB_EXT:
		case ENC_CMP_SUBS_32S_ADDSUB_IMM:
		case ENC_CMP_SUBS_64S_ADDSUB_IMM:
		case ENC_CMP_SUBS_32_ADDSUB_SHIFT:
		case ENC_CMP_SUBS_64_ADDSUB_SHIFT:
			return ARM64_CMP;
		case ENC_CMPEQ_P_P_ZI_:
		case ENC_CMPEQ_P_P_ZW_:
		case ENC_CMPEQ_P_P_ZZ_:
			return ARM64_CMPEQ;
		case ENC_CMPGE_P_P_ZI_:
		case ENC_CMPGE_P_P_ZW_:
		case ENC_CMPGE_P_P_ZZ_:
			return ARM64_CMPGE;
		case ENC_CMPGT_P_P_ZI_:
		case ENC_CMPGT_P_P_ZW_:
		case ENC_CMPGT_P_P_ZZ_:
			return ARM64_CMPGT;
		case ENC_CMPHI_P_P_ZI_:
		case ENC_CMPHI_P_P_ZW_:
		case ENC_CMPHI_P_P_ZZ_:
			return ARM64_CMPHI;
		case ENC_CMPHS_P_P_ZI_:
		case ENC_CMPHS_P_P_ZW_:
		case ENC_CMPHS_P_P_ZZ_:
			return ARM64_CMPHS;
		case ENC_CMPLE_CMPGE_P_P_ZZ_:
		case ENC_CMPLE_P_P_ZI_:
		case ENC_CMPLE_P_P_ZW_:
			return ARM64_CMPLE;
		case ENC_CMPLO_CMPHI_P_P_ZZ_:
		case ENC_CMPLO_P_P_ZI_:
		case ENC_CMPLO_P_P_ZW_:
			return ARM64_CMPLO;
		case ENC_CMPLS_CMPHS_P_P_ZZ_:
		case ENC_CMPLS_P_P_ZI_:
		case ENC_CMPLS_P_P_ZW_:
			return ARM64_CMPLS;
		case ENC_CMPLT_CMPGT_P_P_ZZ_:
		case ENC_CMPLT_P_P_ZI_:
		case ENC_CMPLT_P_P_ZW_:
			return ARM64_CMPLT;
		case ENC_CMPNE_P_P_ZI_:
		case ENC_CMPNE_P_P_ZW_:
		case ENC_CMPNE_P_P_ZZ_:
			return ARM64_CMPNE;
		case ENC_CMPP_SUBPS_64S_DP_2SRC:
			return ARM64_CMPP;
		case ENC_CMTST_ASISDSAME_ONLY:
		case ENC_CMTST_ASIMDSAME_ONLY:
			return ARM64_CMTST;
		case ENC_CNEG_CSNEG_32_CONDSEL:
		case ENC_CNEG_CSNEG_64_CONDSEL:
			return ARM64_CNEG;
		case ENC_CNOT_Z_P_Z_:
			return ARM64_CNOT;
		case ENC_CNT_ASIMDMISC_R:
		case ENC_CNT_Z_P_Z_:
			return ARM64_CNT;
		case ENC_CNTB_R_S_:
			return ARM64_CNTB;
		case ENC_CNTD_R_S_:
			return ARM64_CNTD;
		case ENC_CNTH_R_S_:
			return ARM64_CNTH;
		case ENC_CNTP_R_P_P_:
			return ARM64_CNTP;
		case ENC_CNTW_R_S_:
			return ARM64_CNTW;
		case ENC_COMPACT_Z_P_Z_:
			return ARM64_COMPACT;
		case ENC_CPP_SYS_CR_SYSTEMINSTRS:
			return ARM64_CPP;
		case ENC_CPY_Z_O_I_:
		case ENC_CPY_Z_P_I_:
		case ENC_CPY_Z_P_R_:
		case ENC_CPY_Z_P_V_:
			return ARM64_CPY;
		case ENC_CRC32B_32C_DP_2SRC:
			return ARM64_CRC32B;
		case ENC_CRC32CB_32C_DP_2SRC:
			return ARM64_CRC32CB;
		case ENC_CRC32CH_32C_DP_2SRC:
			return ARM64_CRC32CH;
		case ENC_CRC32CW_32C_DP_2SRC:
			return ARM64_CRC32CW;
		case ENC_CRC32CX_64C_DP_2SRC:
			return ARM64_CRC32CX;
		case ENC_CRC32H_32C_DP_2SRC:
			return ARM64_CRC32H;
		case ENC_CRC32W_32C_DP_2SRC:
			return ARM64_CRC32W;
		case ENC_CRC32X_64C_DP_2SRC:
			return ARM64_CRC32X;
		case ENC_CSDB_HI_HINTS:
			return ARM64_CSDB;
		case ENC_CSEL_32_CONDSEL:
		case ENC_CSEL_64_CONDSEL:
			return ARM64_CSEL;
		case ENC_CSET_CSINC_32_CONDSEL:
		case ENC_CSET_CSINC_64_CONDSEL:
			return ARM64_CSET;
		case ENC_CSETM_CSINV_32_CONDSEL:
		case ENC_CSETM_CSINV_64_CONDSEL:
			return ARM64_CSETM;
		case ENC_CSINC_32_CONDSEL:
		case ENC_CSINC_64_CONDSEL:
			return ARM64_CSINC;
		case ENC_CSINV_32_CONDSEL:
		case ENC_CSINV_64_CONDSEL:
			return ARM64_CSINV;
		case ENC_CSNEG_32_CONDSEL:
		case ENC_CSNEG_64_CONDSEL:
			return ARM64_CSNEG;
		case ENC_CTERMEQ_RR_:
			return ARM64_CTERMEQ;
		case ENC_CTERMNE_RR_:
			return ARM64_CTERMNE;
		case ENC_DC_SYS_CR_SYSTEMINSTRS:
			return ARM64_DC;
		case ENC_DCPS1_DC_EXCEPTION:
			return ARM64_DCPS1;
		case ENC_DCPS2_DC_EXCEPTION:
			return ARM64_DCPS2;
		case ENC_DCPS3_DC_EXCEPTION:
			return ARM64_DCPS3;
		case ENC_DECB_R_RS_:
			return ARM64_DECB;
		case ENC_DECD_R_RS_:
		case ENC_DECD_Z_ZS_:
			return ARM64_DECD;
		case ENC_DECH_R_RS_:
		case ENC_DECH_Z_ZS_:
			return ARM64_DECH;
		case ENC_DECP_R_P_R_:
		case ENC_DECP_Z_P_Z_:
			return ARM64_DECP;
		case ENC_DECW_R_RS_:
		case ENC_DECW_Z_ZS_:
			return ARM64_DECW;
		case ENC_DGH_HI_HINTS:
			return ARM64_DGH;
		case ENC_DMB_BO_BARRIERS:
			return ARM64_DMB;
		case ENC_DRPS_64E_BRANCH_REG:
			return ARM64_DRPS;
		case ENC_DSB_BO_BARRIERS:
			return ARM64_DSB;
		case ENC_DUP_ASISDONE_ONLY:
		case ENC_DUP_ASIMDINS_DV_V:
		case ENC_DUP_ASIMDINS_DR_R:
		case ENC_DUP_Z_I_:
		case ENC_DUP_Z_R_:
		case ENC_DUP_Z_ZI_:
			return ARM64_DUP;
		case ENC_DUPM_Z_I_:
			return ARM64_DUPM;
		case ENC_DVP_SYS_CR_SYSTEMINSTRS:
			return ARM64_DVP;
		case ENC_EON_32_LOG_SHIFT:
		case ENC_EON_64_LOG_SHIFT:
		case ENC_EON_EOR_Z_ZI_:
			return ARM64_EON;
		case ENC_EOR_ASIMDSAME_ONLY:
		case ENC_EOR_32_LOG_IMM:
		case ENC_EOR_64_LOG_IMM:
		case ENC_EOR_32_LOG_SHIFT:
		case ENC_EOR_64_LOG_SHIFT:
		case ENC_EOR_P_P_PP_Z:
		case ENC_EOR_Z_P_ZZ_:
		case ENC_EOR_Z_ZI_:
		case ENC_EOR_Z_ZZ_:
			return ARM64_EOR;
		case ENC_EOR3_VVV16_CRYPTO4:
			return ARM64_EOR3;
		case ENC_EORS_P_P_PP_Z:
			return ARM64_EORS;
		case ENC_EORV_R_P_Z_:
			return ARM64_EORV;
		case ENC_ERET_64E_BRANCH_REG:
			return ARM64_ERET;
		case ENC_ERETAA_64E_BRANCH_REG:
			return ARM64_ERETAA;
		case ENC_ERETAB_64E_BRANCH_REG:
			return ARM64_ERETAB;
		case ENC_ESB_HI_HINTS:
			return ARM64_ESB;
		case ENC_EXT_ASIMDEXT_ONLY:
		case ENC_EXT_Z_ZI_DES:
			return ARM64_EXT;
		case ENC_EXTR_32_EXTRACT:
		case ENC_EXTR_64_EXTRACT:
			return ARM64_EXTR;
		case ENC_FABD_ASISDSAMEFP16_ONLY:
		case ENC_FABD_ASISDSAME_ONLY:
		case ENC_FABD_ASIMDSAMEFP16_ONLY:
		case ENC_FABD_ASIMDSAME_ONLY:
		case ENC_FABD_Z_P_ZZ_:
			return ARM64_FABD;
		case ENC_FABS_ASIMDMISCFP16_R:
		case ENC_FABS_ASIMDMISC_R:
		case ENC_FABS_H_FLOATDP1:
		case ENC_FABS_S_FLOATDP1:
		case ENC_FABS_D_FLOATDP1:
		case ENC_FABS_Z_P_Z_:
			return ARM64_FABS;
		case ENC_FACGE_ASISDSAMEFP16_ONLY:
		case ENC_FACGE_ASISDSAME_ONLY:
		case ENC_FACGE_ASIMDSAMEFP16_ONLY:
		case ENC_FACGE_ASIMDSAME_ONLY:
		case ENC_FACGE_P_P_ZZ_:
			return ARM64_FACGE;
		case ENC_FACGT_ASISDSAMEFP16_ONLY:
		case ENC_FACGT_ASISDSAME_ONLY:
		case ENC_FACGT_ASIMDSAMEFP16_ONLY:
		case ENC_FACGT_ASIMDSAME_ONLY:
		case ENC_FACGT_P_P_ZZ_:
			return ARM64_FACGT;
		case ENC_FACLE_FACGE_P_P_ZZ_:
			return ARM64_FACLE;
		case ENC_FACLT_FACGT_P_P_ZZ_:
			return ARM64_FACLT;
		case ENC_FADD_ASIMDSAMEFP16_ONLY:
		case ENC_FADD_ASIMDSAME_ONLY:
		case ENC_FADD_H_FLOATDP2:
		case ENC_FADD_S_FLOATDP2:
		case ENC_FADD_D_FLOATDP2:
		case ENC_FADD_Z_P_ZS_:
		case ENC_FADD_Z_P_ZZ_:
		case ENC_FADD_Z_ZZ_:
			return ARM64_FADD;
		case ENC_FADDA_V_P_Z_:
			return ARM64_FADDA;
		case ENC_FADDP_ASISDPAIR_ONLY_H:
		case ENC_FADDP_ASISDPAIR_ONLY_SD:
		case ENC_FADDP_ASIMDSAMEFP16_ONLY:
		case ENC_FADDP_ASIMDSAME_ONLY:
			return ARM64_FADDP;
		case ENC_FADDV_V_P_Z_:
			return ARM64_FADDV;
		case ENC_FCADD_ASIMDSAME2_C:
		case ENC_FCADD_Z_P_ZZ_:
			return ARM64_FCADD;
		case ENC_FCCMP_H_FLOATCCMP:
		case ENC_FCCMP_S_FLOATCCMP:
		case ENC_FCCMP_D_FLOATCCMP:
			return ARM64_FCCMP;
		case ENC_FCCMPE_H_FLOATCCMP:
		case ENC_FCCMPE_S_FLOATCCMP:
		case ENC_FCCMPE_D_FLOATCCMP:
			return ARM64_FCCMPE;
		case ENC_FCMEQ_ASISDSAMEFP16_ONLY:
		case ENC_FCMEQ_ASISDSAME_ONLY:
		case ENC_FCMEQ_ASIMDSAMEFP16_ONLY:
		case ENC_FCMEQ_ASIMDSAME_ONLY:
		case ENC_FCMEQ_ASISDMISCFP16_FZ:
		case ENC_FCMEQ_ASISDMISC_FZ:
		case ENC_FCMEQ_ASIMDMISCFP16_FZ:
		case ENC_FCMEQ_ASIMDMISC_FZ:
		case ENC_FCMEQ_P_P_Z0_:
		case ENC_FCMEQ_P_P_ZZ_:
			return ARM64_FCMEQ;
		case ENC_FCMGE_ASISDSAMEFP16_ONLY:
		case ENC_FCMGE_ASISDSAME_ONLY:
		case ENC_FCMGE_ASIMDSAMEFP16_ONLY:
		case ENC_FCMGE_ASIMDSAME_ONLY:
		case ENC_FCMGE_ASISDMISCFP16_FZ:
		case ENC_FCMGE_ASISDMISC_FZ:
		case ENC_FCMGE_ASIMDMISCFP16_FZ:
		case ENC_FCMGE_ASIMDMISC_FZ:
		case ENC_FCMGE_P_P_Z0_:
		case ENC_FCMGE_P_P_ZZ_:
			return ARM64_FCMGE;
		case ENC_FCMGT_ASISDSAMEFP16_ONLY:
		case ENC_FCMGT_ASISDSAME_ONLY:
		case ENC_FCMGT_ASIMDSAMEFP16_ONLY:
		case ENC_FCMGT_ASIMDSAME_ONLY:
		case ENC_FCMGT_ASISDMISCFP16_FZ:
		case ENC_FCMGT_ASISDMISC_FZ:
		case ENC_FCMGT_ASIMDMISCFP16_FZ:
		case ENC_FCMGT_ASIMDMISC_FZ:
		case ENC_FCMGT_P_P_Z0_:
		case ENC_FCMGT_P_P_ZZ_:
			return ARM64_FCMGT;
		case ENC_FCMLA_ASIMDELEM_C_H:
		case ENC_FCMLA_ASIMDELEM_C_S:
		case ENC_FCMLA_ASIMDSAME2_C:
		case ENC_FCMLA_Z_P_ZZZ_:
		case ENC_FCMLA_Z_ZZZI_H:
		case ENC_FCMLA_Z_ZZZI_S:
			return ARM64_FCMLA;
		case ENC_FCMLE_ASISDMISCFP16_FZ:
		case ENC_FCMLE_ASISDMISC_FZ:
		case ENC_FCMLE_ASIMDMISCFP16_FZ:
		case ENC_FCMLE_ASIMDMISC_FZ:
		case ENC_FCMLE_FCMGE_P_P_ZZ_:
		case ENC_FCMLE_P_P_Z0_:
			return ARM64_FCMLE;
		case ENC_FCMLT_ASISDMISCFP16_FZ:
		case ENC_FCMLT_ASISDMISC_FZ:
		case ENC_FCMLT_ASIMDMISCFP16_FZ:
		case ENC_FCMLT_ASIMDMISC_FZ:
		case ENC_FCMLT_FCMGT_P_P_ZZ_:
		case ENC_FCMLT_P_P_Z0_:
			return ARM64_FCMLT;
		case ENC_FCMNE_P_P_Z0_:
		case ENC_FCMNE_P_P_ZZ_:
			return ARM64_FCMNE;
		case ENC_FCMP_H_FLOATCMP:
		case ENC_FCMP_HZ_FLOATCMP:
		case ENC_FCMP_S_FLOATCMP:
		case ENC_FCMP_SZ_FLOATCMP:
		case ENC_FCMP_D_FLOATCMP:
		case ENC_FCMP_DZ_FLOATCMP:
			return ARM64_FCMP;
		case ENC_FCMPE_H_FLOATCMP:
		case ENC_FCMPE_HZ_FLOATCMP:
		case ENC_FCMPE_S_FLOATCMP:
		case ENC_FCMPE_SZ_FLOATCMP:
		case ENC_FCMPE_D_FLOATCMP:
		case ENC_FCMPE_DZ_FLOATCMP:
			return ARM64_FCMPE;
		case ENC_FCMUO_P_P_ZZ_:
			return ARM64_FCMUO;
		case ENC_FCPY_Z_P_I_:
			return ARM64_FCPY;
		case ENC_FCSEL_H_FLOATSEL:
		case ENC_FCSEL_S_FLOATSEL:
		case ENC_FCSEL_D_FLOATSEL:
			return ARM64_FCSEL;
		case ENC_FCVT_SH_FLOATDP1:
		case ENC_FCVT_DH_FLOATDP1:
		case ENC_FCVT_HS_FLOATDP1:
		case ENC_FCVT_DS_FLOATDP1:
		case ENC_FCVT_HD_FLOATDP1:
		case ENC_FCVT_SD_FLOATDP1:
		case ENC_FCVT_Z_P_Z_H2S:
		case ENC_FCVT_Z_P_Z_H2D:
		case ENC_FCVT_Z_P_Z_S2H:
		case ENC_FCVT_Z_P_Z_S2D:
		case ENC_FCVT_Z_P_Z_D2H:
		case ENC_FCVT_Z_P_Z_D2S:
			return ARM64_FCVT;
		case ENC_FCVTAS_ASISDMISCFP16_R:
		case ENC_FCVTAS_ASISDMISC_R:
		case ENC_FCVTAS_ASIMDMISCFP16_R:
		case ENC_FCVTAS_ASIMDMISC_R:
		case ENC_FCVTAS_32H_FLOAT2INT:
		case ENC_FCVTAS_64H_FLOAT2INT:
		case ENC_FCVTAS_32S_FLOAT2INT:
		case ENC_FCVTAS_64S_FLOAT2INT:
		case ENC_FCVTAS_32D_FLOAT2INT:
		case ENC_FCVTAS_64D_FLOAT2INT:
			return ARM64_FCVTAS;
		case ENC_FCVTAU_ASISDMISCFP16_R:
		case ENC_FCVTAU_ASISDMISC_R:
		case ENC_FCVTAU_ASIMDMISCFP16_R:
		case ENC_FCVTAU_ASIMDMISC_R:
		case ENC_FCVTAU_32H_FLOAT2INT:
		case ENC_FCVTAU_64H_FLOAT2INT:
		case ENC_FCVTAU_32S_FLOAT2INT:
		case ENC_FCVTAU_64S_FLOAT2INT:
		case ENC_FCVTAU_32D_FLOAT2INT:
		case ENC_FCVTAU_64D_FLOAT2INT:
			return ARM64_FCVTAU;
		case ENC_FCVTL_ASIMDMISC_L:
			return ARM64_FCVTL;
		//case ENC_FCVTL_ASIMDMISC_L:
		//	return ARM64_FCVTL2;
		case ENC_FCVTMS_ASISDMISCFP16_R:
		case ENC_FCVTMS_ASISDMISC_R:
		case ENC_FCVTMS_ASIMDMISCFP16_R:
		case ENC_FCVTMS_ASIMDMISC_R:
		case ENC_FCVTMS_32H_FLOAT2INT:
		case ENC_FCVTMS_64H_FLOAT2INT:
		case ENC_FCVTMS_32S_FLOAT2INT:
		case ENC_FCVTMS_64S_FLOAT2INT:
		case ENC_FCVTMS_32D_FLOAT2INT:
		case ENC_FCVTMS_64D_FLOAT2INT:
			return ARM64_FCVTMS;
		case ENC_FCVTMU_ASISDMISCFP16_R:
		case ENC_FCVTMU_ASISDMISC_R:
		case ENC_FCVTMU_ASIMDMISCFP16_R:
		case ENC_FCVTMU_ASIMDMISC_R:
		case ENC_FCVTMU_32H_FLOAT2INT:
		case ENC_FCVTMU_64H_FLOAT2INT:
		case ENC_FCVTMU_32S_FLOAT2INT:
		case ENC_FCVTMU_64S_FLOAT2INT:
		case ENC_FCVTMU_32D_FLOAT2INT:
		case ENC_FCVTMU_64D_FLOAT2INT:
			return ARM64_FCVTMU;
		case ENC_FCVTN_ASIMDMISC_N:
			return ARM64_FCVTN;
		//case ENC_FCVTN_ASIMDMISC_N:
		//	return ARM64_FCVTN2;
		case ENC_FCVTNS_ASISDMISCFP16_R:
		case ENC_FCVTNS_ASISDMISC_R:
		case ENC_FCVTNS_ASIMDMISCFP16_R:
		case ENC_FCVTNS_ASIMDMISC_R:
		case ENC_FCVTNS_32H_FLOAT2INT:
		case ENC_FCVTNS_64H_FLOAT2INT:
		case ENC_FCVTNS_32S_FLOAT2INT:
		case ENC_FCVTNS_64S_FLOAT2INT:
		case ENC_FCVTNS_32D_FLOAT2INT:
		case ENC_FCVTNS_64D_FLOAT2INT:
			return ARM64_FCVTNS;
		case ENC_FCVTNU_ASISDMISCFP16_R:
		case ENC_FCVTNU_ASISDMISC_R:
		case ENC_FCVTNU_ASIMDMISCFP16_R:
		case ENC_FCVTNU_ASIMDMISC_R:
		case ENC_FCVTNU_32H_FLOAT2INT:
		case ENC_FCVTNU_64H_FLOAT2INT:
		case ENC_FCVTNU_32S_FLOAT2INT:
		case ENC_FCVTNU_64S_FLOAT2INT:
		case ENC_FCVTNU_32D_FLOAT2INT:
		case ENC_FCVTNU_64D_FLOAT2INT:
			return ARM64_FCVTNU;
		case ENC_FCVTPS_ASISDMISCFP16_R:
		case ENC_FCVTPS_ASISDMISC_R:
		case ENC_FCVTPS_ASIMDMISCFP16_R:
		case ENC_FCVTPS_ASIMDMISC_R:
		case ENC_FCVTPS_32H_FLOAT2INT:
		case ENC_FCVTPS_64H_FLOAT2INT:
		case ENC_FCVTPS_32S_FLOAT2INT:
		case ENC_FCVTPS_64S_FLOAT2INT:
		case ENC_FCVTPS_32D_FLOAT2INT:
		case ENC_FCVTPS_64D_FLOAT2INT:
			return ARM64_FCVTPS;
		case ENC_FCVTPU_ASISDMISCFP16_R:
		case ENC_FCVTPU_ASISDMISC_R:
		case ENC_FCVTPU_ASIMDMISCFP16_R:
		case ENC_FCVTPU_ASIMDMISC_R:
		case ENC_FCVTPU_32H_FLOAT2INT:
		case ENC_FCVTPU_64H_FLOAT2INT:
		case ENC_FCVTPU_32S_FLOAT2INT:
		case ENC_FCVTPU_64S_FLOAT2INT:
		case ENC_FCVTPU_32D_FLOAT2INT:
		case ENC_FCVTPU_64D_FLOAT2INT:
			return ARM64_FCVTPU;
		case ENC_FCVTXN_ASISDMISC_N:
		case ENC_FCVTXN_ASIMDMISC_N:
			return ARM64_FCVTXN;
		//case ENC_FCVTXN_ASIMDMISC_N:
		//	return ARM64_FCVTXN2;
		case ENC_FCVTZS_ASISDSHF_C:
		case ENC_FCVTZS_ASIMDSHF_C:
		case ENC_FCVTZS_ASISDMISCFP16_R:
		case ENC_FCVTZS_ASISDMISC_R:
		case ENC_FCVTZS_ASIMDMISCFP16_R:
		case ENC_FCVTZS_ASIMDMISC_R:
		case ENC_FCVTZS_32H_FLOAT2FIX:
		case ENC_FCVTZS_64H_FLOAT2FIX:
		case ENC_FCVTZS_32S_FLOAT2FIX:
		case ENC_FCVTZS_64S_FLOAT2FIX:
		case ENC_FCVTZS_32D_FLOAT2FIX:
		case ENC_FCVTZS_64D_FLOAT2FIX:
		case ENC_FCVTZS_32H_FLOAT2INT:
		case ENC_FCVTZS_64H_FLOAT2INT:
		case ENC_FCVTZS_32S_FLOAT2INT:
		case ENC_FCVTZS_64S_FLOAT2INT:
		case ENC_FCVTZS_32D_FLOAT2INT:
		case ENC_FCVTZS_64D_FLOAT2INT:
		case ENC_FCVTZS_Z_P_Z_FP162H:
		case ENC_FCVTZS_Z_P_Z_FP162W:
		case ENC_FCVTZS_Z_P_Z_FP162X:
		case ENC_FCVTZS_Z_P_Z_S2W:
		case ENC_FCVTZS_Z_P_Z_S2X:
		case ENC_FCVTZS_Z_P_Z_D2W:
		case ENC_FCVTZS_Z_P_Z_D2X:
			return ARM64_FCVTZS;
		case ENC_FCVTZU_ASISDSHF_C:
		case ENC_FCVTZU_ASIMDSHF_C:
		case ENC_FCVTZU_ASISDMISCFP16_R:
		case ENC_FCVTZU_ASISDMISC_R:
		case ENC_FCVTZU_ASIMDMISCFP16_R:
		case ENC_FCVTZU_ASIMDMISC_R:
		case ENC_FCVTZU_32H_FLOAT2FIX:
		case ENC_FCVTZU_64H_FLOAT2FIX:
		case ENC_FCVTZU_32S_FLOAT2FIX:
		case ENC_FCVTZU_64S_FLOAT2FIX:
		case ENC_FCVTZU_32D_FLOAT2FIX:
		case ENC_FCVTZU_64D_FLOAT2FIX:
		case ENC_FCVTZU_32H_FLOAT2INT:
		case ENC_FCVTZU_64H_FLOAT2INT:
		case ENC_FCVTZU_32S_FLOAT2INT:
		case ENC_FCVTZU_64S_FLOAT2INT:
		case ENC_FCVTZU_32D_FLOAT2INT:
		case ENC_FCVTZU_64D_FLOAT2INT:
		case ENC_FCVTZU_Z_P_Z_FP162H:
		case ENC_FCVTZU_Z_P_Z_FP162W:
		case ENC_FCVTZU_Z_P_Z_FP162X:
		case ENC_FCVTZU_Z_P_Z_S2W:
		case ENC_FCVTZU_Z_P_Z_S2X:
		case ENC_FCVTZU_Z_P_Z_D2W:
		case ENC_FCVTZU_Z_P_Z_D2X:
			return ARM64_FCVTZU;
		case ENC_FDIV_ASIMDSAMEFP16_ONLY:
		case ENC_FDIV_ASIMDSAME_ONLY:
		case ENC_FDIV_H_FLOATDP2:
		case ENC_FDIV_S_FLOATDP2:
		case ENC_FDIV_D_FLOATDP2:
		case ENC_FDIV_Z_P_ZZ_:
			return ARM64_FDIV;
		case ENC_FDIVR_Z_P_ZZ_:
			return ARM64_FDIVR;
		case ENC_FDUP_Z_I_:
			return ARM64_FDUP;
		case ENC_FEXPA_Z_Z_:
			return ARM64_FEXPA;
		case ENC_FJCVTZS_32D_FLOAT2INT:
			return ARM64_FJCVTZS;
		case ENC_FMAD_Z_P_ZZZ_:
			return ARM64_FMAD;
		case ENC_FMADD_H_FLOATDP3:
		case ENC_FMADD_S_FLOATDP3:
		case ENC_FMADD_D_FLOATDP3:
			return ARM64_FMADD;
		case ENC_FMAX_ASIMDSAMEFP16_ONLY:
		case ENC_FMAX_ASIMDSAME_ONLY:
		case ENC_FMAX_H_FLOATDP2:
		case ENC_FMAX_S_FLOATDP2:
		case ENC_FMAX_D_FLOATDP2:
		case ENC_FMAX_Z_P_ZS_:
		case ENC_FMAX_Z_P_ZZ_:
			return ARM64_FMAX;
		case ENC_FMAXNM_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXNM_ASIMDSAME_ONLY:
		case ENC_FMAXNM_H_FLOATDP2:
		case ENC_FMAXNM_S_FLOATDP2:
		case ENC_FMAXNM_D_FLOATDP2:
		case ENC_FMAXNM_Z_P_ZS_:
		case ENC_FMAXNM_Z_P_ZZ_:
			return ARM64_FMAXNM;
		case ENC_FMAXNMP_ASISDPAIR_ONLY_H:
		case ENC_FMAXNMP_ASISDPAIR_ONLY_SD:
		case ENC_FMAXNMP_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXNMP_ASIMDSAME_ONLY:
			return ARM64_FMAXNMP;
		case ENC_FMAXNMV_ASIMDALL_ONLY_H:
		case ENC_FMAXNMV_ASIMDALL_ONLY_SD:
		case ENC_FMAXNMV_V_P_Z_:
			return ARM64_FMAXNMV;
		case ENC_FMAXP_ASISDPAIR_ONLY_H:
		case ENC_FMAXP_ASISDPAIR_ONLY_SD:
		case ENC_FMAXP_ASIMDSAMEFP16_ONLY:
		case ENC_FMAXP_ASIMDSAME_ONLY:
			return ARM64_FMAXP;
		case ENC_FMAXV_ASIMDALL_ONLY_H:
		case ENC_FMAXV_ASIMDALL_ONLY_SD:
		case ENC_FMAXV_V_P_Z_:
			return ARM64_FMAXV;
		case ENC_FMIN_ASIMDSAMEFP16_ONLY:
		case ENC_FMIN_ASIMDSAME_ONLY:
		case ENC_FMIN_H_FLOATDP2:
		case ENC_FMIN_S_FLOATDP2:
		case ENC_FMIN_D_FLOATDP2:
		case ENC_FMIN_Z_P_ZS_:
		case ENC_FMIN_Z_P_ZZ_:
			return ARM64_FMIN;
		case ENC_FMINNM_ASIMDSAMEFP16_ONLY:
		case ENC_FMINNM_ASIMDSAME_ONLY:
		case ENC_FMINNM_H_FLOATDP2:
		case ENC_FMINNM_S_FLOATDP2:
		case ENC_FMINNM_D_FLOATDP2:
		case ENC_FMINNM_Z_P_ZS_:
		case ENC_FMINNM_Z_P_ZZ_:
			return ARM64_FMINNM;
		case ENC_FMINNMP_ASISDPAIR_ONLY_H:
		case ENC_FMINNMP_ASISDPAIR_ONLY_SD:
		case ENC_FMINNMP_ASIMDSAMEFP16_ONLY:
		case ENC_FMINNMP_ASIMDSAME_ONLY:
			return ARM64_FMINNMP;
		case ENC_FMINNMV_ASIMDALL_ONLY_H:
		case ENC_FMINNMV_ASIMDALL_ONLY_SD:
		case ENC_FMINNMV_V_P_Z_:
			return ARM64_FMINNMV;
		case ENC_FMINP_ASISDPAIR_ONLY_H:
		case ENC_FMINP_ASISDPAIR_ONLY_SD:
		case ENC_FMINP_ASIMDSAMEFP16_ONLY:
		case ENC_FMINP_ASIMDSAME_ONLY:
			return ARM64_FMINP;
		case ENC_FMINV_ASIMDALL_ONLY_H:
		case ENC_FMINV_ASIMDALL_ONLY_SD:
		case ENC_FMINV_V_P_Z_:
			return ARM64_FMINV;
		case ENC_FMLA_ASISDELEM_RH_H:
		case ENC_FMLA_ASISDELEM_R_SD:
		case ENC_FMLA_ASIMDELEM_RH_H:
		case ENC_FMLA_ASIMDELEM_R_SD:
		case ENC_FMLA_ASIMDSAMEFP16_ONLY:
		case ENC_FMLA_ASIMDSAME_ONLY:
		case ENC_FMLA_Z_P_ZZZ_:
		case ENC_FMLA_Z_ZZZI_H:
		case ENC_FMLA_Z_ZZZI_S:
		case ENC_FMLA_Z_ZZZI_D:
			return ARM64_FMLA;
		case ENC_FMLAL_ASIMDELEM_LH:
		case ENC_FMLAL_ASIMDSAME_F:
			return ARM64_FMLAL;
		case ENC_FMLAL2_ASIMDELEM_LH:
		case ENC_FMLAL2_ASIMDSAME_F:
			return ARM64_FMLAL2;
		case ENC_FMLS_ASISDELEM_RH_H:
		case ENC_FMLS_ASISDELEM_R_SD:
		case ENC_FMLS_ASIMDELEM_RH_H:
		case ENC_FMLS_ASIMDELEM_R_SD:
		case ENC_FMLS_ASIMDSAMEFP16_ONLY:
		case ENC_FMLS_ASIMDSAME_ONLY:
		case ENC_FMLS_Z_P_ZZZ_:
		case ENC_FMLS_Z_ZZZI_H:
		case ENC_FMLS_Z_ZZZI_S:
		case ENC_FMLS_Z_ZZZI_D:
			return ARM64_FMLS;
		case ENC_FMLSL_ASIMDELEM_LH:
		case ENC_FMLSL_ASIMDSAME_F:
			return ARM64_FMLSL;
		case ENC_FMLSL2_ASIMDELEM_LH:
		case ENC_FMLSL2_ASIMDSAME_F:
			return ARM64_FMLSL2;
		case ENC_FMMLA_Z_ZZZ_S:
		case ENC_FMMLA_Z_ZZZ_D:
			return ARM64_FMMLA;
		case ENC_FMOV_ASIMDIMM_H_H:
		case ENC_FMOV_ASIMDIMM_S_S:
		case ENC_FMOV_ASIMDIMM_D2_D:
		case ENC_FMOV_CPY_Z_P_I_:
		case ENC_FMOV_DUP_Z_I_:
		case ENC_FMOV_FCPY_Z_P_I_:
		case ENC_FMOV_FDUP_Z_I_:
		case ENC_FMOV_H_FLOATDP1:
		case ENC_FMOV_S_FLOATDP1:
		case ENC_FMOV_D_FLOATDP1:
		case ENC_FMOV_32H_FLOAT2INT:
		case ENC_FMOV_64H_FLOAT2INT:
		case ENC_FMOV_H32_FLOAT2INT:
		case ENC_FMOV_S32_FLOAT2INT:
		case ENC_FMOV_32S_FLOAT2INT:
		case ENC_FMOV_H64_FLOAT2INT:
		case ENC_FMOV_D64_FLOAT2INT:
		case ENC_FMOV_V64I_FLOAT2INT:
		case ENC_FMOV_64D_FLOAT2INT:
		case ENC_FMOV_64VX_FLOAT2INT:
		case ENC_FMOV_H_FLOATIMM:
		case ENC_FMOV_S_FLOATIMM:
		case ENC_FMOV_D_FLOATIMM:
			return ARM64_FMOV;
		case ENC_FMSB_Z_P_ZZZ_:
			return ARM64_FMSB;
		case ENC_FMSUB_H_FLOATDP3:
		case ENC_FMSUB_S_FLOATDP3:
		case ENC_FMSUB_D_FLOATDP3:
			return ARM64_FMSUB;
		case ENC_FMUL_ASISDELEM_RH_H:
		case ENC_FMUL_ASISDELEM_R_SD:
		case ENC_FMUL_ASIMDELEM_RH_H:
		case ENC_FMUL_ASIMDELEM_R_SD:
		case ENC_FMUL_ASIMDSAMEFP16_ONLY:
		case ENC_FMUL_ASIMDSAME_ONLY:
		case ENC_FMUL_H_FLOATDP2:
		case ENC_FMUL_S_FLOATDP2:
		case ENC_FMUL_D_FLOATDP2:
		case ENC_FMUL_Z_P_ZS_:
		case ENC_FMUL_Z_P_ZZ_:
		case ENC_FMUL_Z_ZZ_:
		case ENC_FMUL_Z_ZZI_H:
		case ENC_FMUL_Z_ZZI_S:
		case ENC_FMUL_Z_ZZI_D:
			return ARM64_FMUL;
		case ENC_FMULX_ASISDELEM_RH_H:
		case ENC_FMULX_ASISDELEM_R_SD:
		case ENC_FMULX_ASIMDELEM_RH_H:
		case ENC_FMULX_ASIMDELEM_R_SD:
		case ENC_FMULX_ASISDSAMEFP16_ONLY:
		case ENC_FMULX_ASISDSAME_ONLY:
		case ENC_FMULX_ASIMDSAMEFP16_ONLY:
		case ENC_FMULX_ASIMDSAME_ONLY:
		case ENC_FMULX_Z_P_ZZ_:
			return ARM64_FMULX;
		case ENC_FNEG_ASIMDMISCFP16_R:
		case ENC_FNEG_ASIMDMISC_R:
		case ENC_FNEG_H_FLOATDP1:
		case ENC_FNEG_S_FLOATDP1:
		case ENC_FNEG_D_FLOATDP1:
		case ENC_FNEG_Z_P_Z_:
			return ARM64_FNEG;
		case ENC_FNMAD_Z_P_ZZZ_:
			return ARM64_FNMAD;
		case ENC_FNMADD_H_FLOATDP3:
		case ENC_FNMADD_S_FLOATDP3:
		case ENC_FNMADD_D_FLOATDP3:
			return ARM64_FNMADD;
		case ENC_FNMLA_Z_P_ZZZ_:
			return ARM64_FNMLA;
		case ENC_FNMLS_Z_P_ZZZ_:
			return ARM64_FNMLS;
		case ENC_FNMSB_Z_P_ZZZ_:
			return ARM64_FNMSB;
		case ENC_FNMSUB_H_FLOATDP3:
		case ENC_FNMSUB_S_FLOATDP3:
		case ENC_FNMSUB_D_FLOATDP3:
			return ARM64_FNMSUB;
		case ENC_FNMUL_H_FLOATDP2:
		case ENC_FNMUL_S_FLOATDP2:
		case ENC_FNMUL_D_FLOATDP2:
			return ARM64_FNMUL;
		case ENC_FRECPE_ASISDMISCFP16_R:
		case ENC_FRECPE_ASISDMISC_R:
		case ENC_FRECPE_ASIMDMISCFP16_R:
		case ENC_FRECPE_ASIMDMISC_R:
		case ENC_FRECPE_Z_Z_:
			return ARM64_FRECPE;
		case ENC_FRECPS_ASISDSAMEFP16_ONLY:
		case ENC_FRECPS_ASISDSAME_ONLY:
		case ENC_FRECPS_ASIMDSAMEFP16_ONLY:
		case ENC_FRECPS_ASIMDSAME_ONLY:
		case ENC_FRECPS_Z_ZZ_:
			return ARM64_FRECPS;
		case ENC_FRECPX_ASISDMISCFP16_R:
		case ENC_FRECPX_ASISDMISC_R:
		case ENC_FRECPX_Z_P_Z_:
			return ARM64_FRECPX;
		case ENC_FRINT32X_ASIMDMISC_R:
		case ENC_FRINT32X_S_FLOATDP1:
		case ENC_FRINT32X_D_FLOATDP1:
			return ARM64_FRINT32X;
		case ENC_FRINT32Z_ASIMDMISC_R:
		case ENC_FRINT32Z_S_FLOATDP1:
		case ENC_FRINT32Z_D_FLOATDP1:
			return ARM64_FRINT32Z;
		case ENC_FRINT64X_ASIMDMISC_R:
		case ENC_FRINT64X_S_FLOATDP1:
		case ENC_FRINT64X_D_FLOATDP1:
			return ARM64_FRINT64X;
		case ENC_FRINT64Z_ASIMDMISC_R:
		case ENC_FRINT64Z_S_FLOATDP1:
		case ENC_FRINT64Z_D_FLOATDP1:
			return ARM64_FRINT64Z;
		case ENC_FRINTA_ASIMDMISCFP16_R:
		case ENC_FRINTA_ASIMDMISC_R:
		case ENC_FRINTA_H_FLOATDP1:
		case ENC_FRINTA_S_FLOATDP1:
		case ENC_FRINTA_D_FLOATDP1:
		case ENC_FRINTA_Z_P_Z_:
			return ARM64_FRINTA;
		case ENC_FRINTI_ASIMDMISCFP16_R:
		case ENC_FRINTI_ASIMDMISC_R:
		case ENC_FRINTI_H_FLOATDP1:
		case ENC_FRINTI_S_FLOATDP1:
		case ENC_FRINTI_D_FLOATDP1:
		case ENC_FRINTI_Z_P_Z_:
			return ARM64_FRINTI;
		case ENC_FRINTM_ASIMDMISCFP16_R:
		case ENC_FRINTM_ASIMDMISC_R:
		case ENC_FRINTM_H_FLOATDP1:
		case ENC_FRINTM_S_FLOATDP1:
		case ENC_FRINTM_D_FLOATDP1:
		case ENC_FRINTM_Z_P_Z_:
			return ARM64_FRINTM;
		case ENC_FRINTN_ASIMDMISCFP16_R:
		case ENC_FRINTN_ASIMDMISC_R:
		case ENC_FRINTN_H_FLOATDP1:
		case ENC_FRINTN_S_FLOATDP1:
		case ENC_FRINTN_D_FLOATDP1:
		case ENC_FRINTN_Z_P_Z_:
			return ARM64_FRINTN;
		case ENC_FRINTP_ASIMDMISCFP16_R:
		case ENC_FRINTP_ASIMDMISC_R:
		case ENC_FRINTP_H_FLOATDP1:
		case ENC_FRINTP_S_FLOATDP1:
		case ENC_FRINTP_D_FLOATDP1:
		case ENC_FRINTP_Z_P_Z_:
			return ARM64_FRINTP;
		case ENC_FRINTX_ASIMDMISCFP16_R:
		case ENC_FRINTX_ASIMDMISC_R:
		case ENC_FRINTX_H_FLOATDP1:
		case ENC_FRINTX_S_FLOATDP1:
		case ENC_FRINTX_D_FLOATDP1:
		case ENC_FRINTX_Z_P_Z_:
			return ARM64_FRINTX;
		case ENC_FRINTZ_ASIMDMISCFP16_R:
		case ENC_FRINTZ_ASIMDMISC_R:
		case ENC_FRINTZ_H_FLOATDP1:
		case ENC_FRINTZ_S_FLOATDP1:
		case ENC_FRINTZ_D_FLOATDP1:
		case ENC_FRINTZ_Z_P_Z_:
			return ARM64_FRINTZ;
		case ENC_FRSQRTE_ASISDMISCFP16_R:
		case ENC_FRSQRTE_ASISDMISC_R:
		case ENC_FRSQRTE_ASIMDMISCFP16_R:
		case ENC_FRSQRTE_ASIMDMISC_R:
		case ENC_FRSQRTE_Z_Z_:
			return ARM64_FRSQRTE;
		case ENC_FRSQRTS_ASISDSAMEFP16_ONLY:
		case ENC_FRSQRTS_ASISDSAME_ONLY:
		case ENC_FRSQRTS_ASIMDSAMEFP16_ONLY:
		case ENC_FRSQRTS_ASIMDSAME_ONLY:
		case ENC_FRSQRTS_Z_ZZ_:
			return ARM64_FRSQRTS;
		case ENC_FSCALE_Z_P_ZZ_:
			return ARM64_FSCALE;
		case ENC_FSQRT_ASIMDMISCFP16_R:
		case ENC_FSQRT_ASIMDMISC_R:
		case ENC_FSQRT_H_FLOATDP1:
		case ENC_FSQRT_S_FLOATDP1:
		case ENC_FSQRT_D_FLOATDP1:
		case ENC_FSQRT_Z_P_Z_:
			return ARM64_FSQRT;
		case ENC_FSUB_ASIMDSAMEFP16_ONLY:
		case ENC_FSUB_ASIMDSAME_ONLY:
		case ENC_FSUB_H_FLOATDP2:
		case ENC_FSUB_S_FLOATDP2:
		case ENC_FSUB_D_FLOATDP2:
		case ENC_FSUB_Z_P_ZS_:
		case ENC_FSUB_Z_P_ZZ_:
		case ENC_FSUB_Z_ZZ_:
			return ARM64_FSUB;
		case ENC_FSUBR_Z_P_ZS_:
		case ENC_FSUBR_Z_P_ZZ_:
			return ARM64_FSUBR;
		case ENC_FTMAD_Z_ZZI_:
			return ARM64_FTMAD;
		case ENC_FTSMUL_Z_ZZ_:
			return ARM64_FTSMUL;
		case ENC_FTSSEL_Z_ZZ_:
			return ARM64_FTSSEL;
		case ENC_GMI_64G_DP_2SRC:
			return ARM64_GMI;
		case ENC_HINT_HM_HINTS:
			return ARM64_HINT;
		case ENC_HLT_EX_EXCEPTION:
			return ARM64_HLT;
		case ENC_HVC_EX_EXCEPTION:
			return ARM64_HVC;
		case ENC_IC_SYS_CR_SYSTEMINSTRS:
			return ARM64_IC;
		case ENC_INCB_R_RS_:
			return ARM64_INCB;
		case ENC_INCD_R_RS_:
		case ENC_INCD_Z_ZS_:
			return ARM64_INCD;
		case ENC_INCH_R_RS_:
		case ENC_INCH_Z_ZS_:
			return ARM64_INCH;
		case ENC_INCP_R_P_R_:
		case ENC_INCP_Z_P_Z_:
			return ARM64_INCP;
		case ENC_INCW_R_RS_:
		case ENC_INCW_Z_ZS_:
			return ARM64_INCW;
		case ENC_INDEX_Z_II_:
		case ENC_INDEX_Z_IR_:
		case ENC_INDEX_Z_RI_:
		case ENC_INDEX_Z_RR_:
			return ARM64_INDEX;
		case ENC_INS_ASIMDINS_IV_V:
		case ENC_INS_ASIMDINS_IR_R:
			return ARM64_INS;
		case ENC_INSR_Z_R_:
		case ENC_INSR_Z_V_:
			return ARM64_INSR;
		case ENC_IRG_64I_DP_2SRC:
			return ARM64_IRG;
		case ENC_ISB_BI_BARRIERS:
			return ARM64_ISB;
		case ENC_LASTA_R_P_Z_:
		case ENC_LASTA_V_P_Z_:
			return ARM64_LASTA;
		case ENC_LASTB_R_P_Z_:
		case ENC_LASTB_V_P_Z_:
			return ARM64_LASTB;
		case ENC_LD1_ASISDLSE_R1_1V:
		case ENC_LD1_ASISDLSE_R2_2V:
		case ENC_LD1_ASISDLSE_R3_3V:
		case ENC_LD1_ASISDLSE_R4_4V:
		case ENC_LD1_ASISDLSEP_I1_I1:
		case ENC_LD1_ASISDLSEP_R1_R1:
		case ENC_LD1_ASISDLSEP_I2_I2:
		case ENC_LD1_ASISDLSEP_R2_R2:
		case ENC_LD1_ASISDLSEP_I3_I3:
		case ENC_LD1_ASISDLSEP_R3_R3:
		case ENC_LD1_ASISDLSEP_I4_I4:
		case ENC_LD1_ASISDLSEP_R4_R4:
		case ENC_LD1_ASISDLSO_B1_1B:
		case ENC_LD1_ASISDLSO_H1_1H:
		case ENC_LD1_ASISDLSO_S1_1S:
		case ENC_LD1_ASISDLSO_D1_1D:
		case ENC_LD1_ASISDLSOP_B1_I1B:
		case ENC_LD1_ASISDLSOP_BX1_R1B:
		case ENC_LD1_ASISDLSOP_H1_I1H:
		case ENC_LD1_ASISDLSOP_HX1_R1H:
		case ENC_LD1_ASISDLSOP_S1_I1S:
		case ENC_LD1_ASISDLSOP_SX1_R1S:
		case ENC_LD1_ASISDLSOP_D1_I1D:
		case ENC_LD1_ASISDLSOP_DX1_R1D:
			return ARM64_LD1;
		case ENC_LD1B_Z_P_AI_S:
		case ENC_LD1B_Z_P_AI_D:
		case ENC_LD1B_Z_P_BI_U8:
		case ENC_LD1B_Z_P_BI_U16:
		case ENC_LD1B_Z_P_BI_U32:
		case ENC_LD1B_Z_P_BI_U64:
		case ENC_LD1B_Z_P_BR_U8:
		case ENC_LD1B_Z_P_BR_U16:
		case ENC_LD1B_Z_P_BR_U32:
		case ENC_LD1B_Z_P_BR_U64:
		case ENC_LD1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1B_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LD1B;
		case ENC_LD1D_Z_P_AI_D:
		case ENC_LD1D_Z_P_BI_U64:
		case ENC_LD1D_Z_P_BR_U64:
		case ENC_LD1D_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1D_Z_P_BZ_D_64_SCALED:
		case ENC_LD1D_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LD1D;
		case ENC_LD1H_Z_P_AI_S:
		case ENC_LD1H_Z_P_AI_D:
		case ENC_LD1H_Z_P_BI_U16:
		case ENC_LD1H_Z_P_BI_U32:
		case ENC_LD1H_Z_P_BI_U64:
		case ENC_LD1H_Z_P_BR_U16:
		case ENC_LD1H_Z_P_BR_U32:
		case ENC_LD1H_Z_P_BR_U64:
		case ENC_LD1H_Z_P_BZ_S_X32_SCALED:
		case ENC_LD1H_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1H_Z_P_BZ_D_64_SCALED:
		case ENC_LD1H_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LD1H;
		case ENC_LD1R_ASISDLSO_R1:
		case ENC_LD1R_ASISDLSOP_R1_I:
		case ENC_LD1R_ASISDLSOP_RX1_R:
			return ARM64_LD1R;
		case ENC_LD1RB_Z_P_BI_U8:
		case ENC_LD1RB_Z_P_BI_U16:
		case ENC_LD1RB_Z_P_BI_U32:
		case ENC_LD1RB_Z_P_BI_U64:
			return ARM64_LD1RB;
		case ENC_LD1RD_Z_P_BI_U64:
			return ARM64_LD1RD;
		case ENC_LD1RH_Z_P_BI_U16:
		case ENC_LD1RH_Z_P_BI_U32:
		case ENC_LD1RH_Z_P_BI_U64:
			return ARM64_LD1RH;
		case ENC_LD1ROB_Z_P_BI_U8:
		case ENC_LD1ROB_Z_P_BR_CONTIGUOUS:
			return ARM64_LD1ROB;
		case ENC_LD1ROD_Z_P_BI_U64:
		case ENC_LD1ROD_Z_P_BR_CONTIGUOUS:
			return ARM64_LD1ROD;
		case ENC_LD1ROH_Z_P_BI_U16:
		case ENC_LD1ROH_Z_P_BR_CONTIGUOUS:
			return ARM64_LD1ROH;
		case ENC_LD1ROW_Z_P_BI_U32:
		case ENC_LD1ROW_Z_P_BR_CONTIGUOUS:
			return ARM64_LD1ROW;
		case ENC_LD1RQB_Z_P_BI_U8:
		case ENC_LD1RQB_Z_P_BR_CONTIGUOUS:
			return ARM64_LD1RQB;
		case ENC_LD1RQD_Z_P_BI_U64:
		case ENC_LD1RQD_Z_P_BR_CONTIGUOUS:
			return ARM64_LD1RQD;
		case ENC_LD1RQH_Z_P_BI_U16:
		case ENC_LD1RQH_Z_P_BR_CONTIGUOUS:
			return ARM64_LD1RQH;
		case ENC_LD1RQW_Z_P_BI_U32:
		case ENC_LD1RQW_Z_P_BR_CONTIGUOUS:
			return ARM64_LD1RQW;
		case ENC_LD1RSB_Z_P_BI_S16:
		case ENC_LD1RSB_Z_P_BI_S32:
		case ENC_LD1RSB_Z_P_BI_S64:
			return ARM64_LD1RSB;
		case ENC_LD1RSH_Z_P_BI_S32:
		case ENC_LD1RSH_Z_P_BI_S64:
			return ARM64_LD1RSH;
		case ENC_LD1RSW_Z_P_BI_S64:
			return ARM64_LD1RSW;
		case ENC_LD1RW_Z_P_BI_U32:
		case ENC_LD1RW_Z_P_BI_U64:
			return ARM64_LD1RW;
		case ENC_LD1SB_Z_P_AI_S:
		case ENC_LD1SB_Z_P_AI_D:
		case ENC_LD1SB_Z_P_BI_S16:
		case ENC_LD1SB_Z_P_BI_S32:
		case ENC_LD1SB_Z_P_BI_S64:
		case ENC_LD1SB_Z_P_BR_S16:
		case ENC_LD1SB_Z_P_BR_S32:
		case ENC_LD1SB_Z_P_BR_S64:
		case ENC_LD1SB_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SB_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LD1SB;
		case ENC_LD1SH_Z_P_AI_S:
		case ENC_LD1SH_Z_P_AI_D:
		case ENC_LD1SH_Z_P_BI_S32:
		case ENC_LD1SH_Z_P_BI_S64:
		case ENC_LD1SH_Z_P_BR_S32:
		case ENC_LD1SH_Z_P_BR_S64:
		case ENC_LD1SH_Z_P_BZ_S_X32_SCALED:
		case ENC_LD1SH_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1SH_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1SH_Z_P_BZ_D_64_SCALED:
		case ENC_LD1SH_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LD1SH;
		case ENC_LD1SW_Z_P_AI_D:
		case ENC_LD1SW_Z_P_BI_S64:
		case ENC_LD1SW_Z_P_BR_S64:
		case ENC_LD1SW_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1SW_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1SW_Z_P_BZ_D_64_SCALED:
		case ENC_LD1SW_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LD1SW;
		case ENC_LD1W_Z_P_AI_S:
		case ENC_LD1W_Z_P_AI_D:
		case ENC_LD1W_Z_P_BI_U32:
		case ENC_LD1W_Z_P_BI_U64:
		case ENC_LD1W_Z_P_BR_U32:
		case ENC_LD1W_Z_P_BR_U64:
		case ENC_LD1W_Z_P_BZ_S_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_D_X32_SCALED:
		case ENC_LD1W_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LD1W_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LD1W_Z_P_BZ_D_64_SCALED:
		case ENC_LD1W_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LD1W;
		case ENC_LD2_ASISDLSE_R2:
		case ENC_LD2_ASISDLSEP_I2_I:
		case ENC_LD2_ASISDLSEP_R2_R:
		case ENC_LD2_ASISDLSO_B2_2B:
		case ENC_LD2_ASISDLSO_H2_2H:
		case ENC_LD2_ASISDLSO_S2_2S:
		case ENC_LD2_ASISDLSO_D2_2D:
		case ENC_LD2_ASISDLSOP_B2_I2B:
		case ENC_LD2_ASISDLSOP_BX2_R2B:
		case ENC_LD2_ASISDLSOP_H2_I2H:
		case ENC_LD2_ASISDLSOP_HX2_R2H:
		case ENC_LD2_ASISDLSOP_S2_I2S:
		case ENC_LD2_ASISDLSOP_SX2_R2S:
		case ENC_LD2_ASISDLSOP_D2_I2D:
		case ENC_LD2_ASISDLSOP_DX2_R2D:
			return ARM64_LD2;
		case ENC_LD2B_Z_P_BI_CONTIGUOUS:
		case ENC_LD2B_Z_P_BR_CONTIGUOUS:
			return ARM64_LD2B;
		case ENC_LD2D_Z_P_BI_CONTIGUOUS:
		case ENC_LD2D_Z_P_BR_CONTIGUOUS:
			return ARM64_LD2D;
		case ENC_LD2H_Z_P_BI_CONTIGUOUS:
		case ENC_LD2H_Z_P_BR_CONTIGUOUS:
			return ARM64_LD2H;
		case ENC_LD2R_ASISDLSO_R2:
		case ENC_LD2R_ASISDLSOP_R2_I:
		case ENC_LD2R_ASISDLSOP_RX2_R:
			return ARM64_LD2R;
		case ENC_LD2W_Z_P_BI_CONTIGUOUS:
		case ENC_LD2W_Z_P_BR_CONTIGUOUS:
			return ARM64_LD2W;
		case ENC_LD3_ASISDLSE_R3:
		case ENC_LD3_ASISDLSEP_I3_I:
		case ENC_LD3_ASISDLSEP_R3_R:
		case ENC_LD3_ASISDLSO_B3_3B:
		case ENC_LD3_ASISDLSO_H3_3H:
		case ENC_LD3_ASISDLSO_S3_3S:
		case ENC_LD3_ASISDLSO_D3_3D:
		case ENC_LD3_ASISDLSOP_B3_I3B:
		case ENC_LD3_ASISDLSOP_BX3_R3B:
		case ENC_LD3_ASISDLSOP_H3_I3H:
		case ENC_LD3_ASISDLSOP_HX3_R3H:
		case ENC_LD3_ASISDLSOP_S3_I3S:
		case ENC_LD3_ASISDLSOP_SX3_R3S:
		case ENC_LD3_ASISDLSOP_D3_I3D:
		case ENC_LD3_ASISDLSOP_DX3_R3D:
			return ARM64_LD3;
		case ENC_LD3B_Z_P_BI_CONTIGUOUS:
		case ENC_LD3B_Z_P_BR_CONTIGUOUS:
			return ARM64_LD3B;
		case ENC_LD3D_Z_P_BI_CONTIGUOUS:
		case ENC_LD3D_Z_P_BR_CONTIGUOUS:
			return ARM64_LD3D;
		case ENC_LD3H_Z_P_BI_CONTIGUOUS:
		case ENC_LD3H_Z_P_BR_CONTIGUOUS:
			return ARM64_LD3H;
		case ENC_LD3R_ASISDLSO_R3:
		case ENC_LD3R_ASISDLSOP_R3_I:
		case ENC_LD3R_ASISDLSOP_RX3_R:
			return ARM64_LD3R;
		case ENC_LD3W_Z_P_BI_CONTIGUOUS:
		case ENC_LD3W_Z_P_BR_CONTIGUOUS:
			return ARM64_LD3W;
		case ENC_LD4_ASISDLSE_R4:
		case ENC_LD4_ASISDLSEP_I4_I:
		case ENC_LD4_ASISDLSEP_R4_R:
		case ENC_LD4_ASISDLSO_B4_4B:
		case ENC_LD4_ASISDLSO_H4_4H:
		case ENC_LD4_ASISDLSO_S4_4S:
		case ENC_LD4_ASISDLSO_D4_4D:
		case ENC_LD4_ASISDLSOP_B4_I4B:
		case ENC_LD4_ASISDLSOP_BX4_R4B:
		case ENC_LD4_ASISDLSOP_H4_I4H:
		case ENC_LD4_ASISDLSOP_HX4_R4H:
		case ENC_LD4_ASISDLSOP_S4_I4S:
		case ENC_LD4_ASISDLSOP_SX4_R4S:
		case ENC_LD4_ASISDLSOP_D4_I4D:
		case ENC_LD4_ASISDLSOP_DX4_R4D:
			return ARM64_LD4;
		case ENC_LD4B_Z_P_BI_CONTIGUOUS:
		case ENC_LD4B_Z_P_BR_CONTIGUOUS:
			return ARM64_LD4B;
		case ENC_LD4D_Z_P_BI_CONTIGUOUS:
		case ENC_LD4D_Z_P_BR_CONTIGUOUS:
			return ARM64_LD4D;
		case ENC_LD4H_Z_P_BI_CONTIGUOUS:
		case ENC_LD4H_Z_P_BR_CONTIGUOUS:
			return ARM64_LD4H;
		case ENC_LD4R_ASISDLSO_R4:
		case ENC_LD4R_ASISDLSOP_R4_I:
		case ENC_LD4R_ASISDLSOP_RX4_R:
			return ARM64_LD4R;
		case ENC_LD4W_Z_P_BI_CONTIGUOUS:
		case ENC_LD4W_Z_P_BR_CONTIGUOUS:
			return ARM64_LD4W;
		case ENC_LDADD_32_MEMOP:
		case ENC_LDADD_64_MEMOP:
			return ARM64_LDADD;
		case ENC_LDADDA_32_MEMOP:
		case ENC_LDADDA_64_MEMOP:
			return ARM64_LDADDA;
		case ENC_LDADDAB_32_MEMOP:
			return ARM64_LDADDAB;
		case ENC_LDADDAH_32_MEMOP:
			return ARM64_LDADDAH;
		case ENC_LDADDAL_32_MEMOP:
		case ENC_LDADDAL_64_MEMOP:
			return ARM64_LDADDAL;
		case ENC_LDADDALB_32_MEMOP:
			return ARM64_LDADDALB;
		case ENC_LDADDALH_32_MEMOP:
			return ARM64_LDADDALH;
		case ENC_LDADDB_32_MEMOP:
			return ARM64_LDADDB;
		case ENC_LDADDH_32_MEMOP:
			return ARM64_LDADDH;
		case ENC_LDADDL_32_MEMOP:
		case ENC_LDADDL_64_MEMOP:
			return ARM64_LDADDL;
		case ENC_LDADDLB_32_MEMOP:
			return ARM64_LDADDLB;
		case ENC_LDADDLH_32_MEMOP:
			return ARM64_LDADDLH;
		case ENC_LDAPR_32L_MEMOP:
		case ENC_LDAPR_64L_MEMOP:
			return ARM64_LDAPR;
		case ENC_LDAPRB_32L_MEMOP:
			return ARM64_LDAPRB;
		case ENC_LDAPRH_32L_MEMOP:
			return ARM64_LDAPRH;
		case ENC_LDAPUR_32_LDAPSTL_UNSCALED:
		case ENC_LDAPUR_64_LDAPSTL_UNSCALED:
			return ARM64_LDAPUR;
		case ENC_LDAPURB_32_LDAPSTL_UNSCALED:
			return ARM64_LDAPURB;
		case ENC_LDAPURH_32_LDAPSTL_UNSCALED:
			return ARM64_LDAPURH;
		case ENC_LDAPURSB_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSB_64_LDAPSTL_UNSCALED:
			return ARM64_LDAPURSB;
		case ENC_LDAPURSH_32_LDAPSTL_UNSCALED:
		case ENC_LDAPURSH_64_LDAPSTL_UNSCALED:
			return ARM64_LDAPURSH;
		case ENC_LDAPURSW_64_LDAPSTL_UNSCALED:
			return ARM64_LDAPURSW;
		case ENC_LDAR_LR32_LDSTEXCL:
		case ENC_LDAR_LR64_LDSTEXCL:
			return ARM64_LDAR;
		case ENC_LDARB_LR32_LDSTEXCL:
			return ARM64_LDARB;
		case ENC_LDARH_LR32_LDSTEXCL:
			return ARM64_LDARH;
		case ENC_LDAXP_LP32_LDSTEXCL:
		case ENC_LDAXP_LP64_LDSTEXCL:
			return ARM64_LDAXP;
		case ENC_LDAXR_LR32_LDSTEXCL:
		case ENC_LDAXR_LR64_LDSTEXCL:
			return ARM64_LDAXR;
		case ENC_LDAXRB_LR32_LDSTEXCL:
			return ARM64_LDAXRB;
		case ENC_LDAXRH_LR32_LDSTEXCL:
			return ARM64_LDAXRH;
		case ENC_LDCLR_32_MEMOP:
		case ENC_LDCLR_64_MEMOP:
			return ARM64_LDCLR;
		case ENC_LDCLRA_32_MEMOP:
		case ENC_LDCLRA_64_MEMOP:
			return ARM64_LDCLRA;
		case ENC_LDCLRAB_32_MEMOP:
			return ARM64_LDCLRAB;
		case ENC_LDCLRAH_32_MEMOP:
			return ARM64_LDCLRAH;
		case ENC_LDCLRAL_32_MEMOP:
		case ENC_LDCLRAL_64_MEMOP:
			return ARM64_LDCLRAL;
		case ENC_LDCLRALB_32_MEMOP:
			return ARM64_LDCLRALB;
		case ENC_LDCLRALH_32_MEMOP:
			return ARM64_LDCLRALH;
		case ENC_LDCLRB_32_MEMOP:
			return ARM64_LDCLRB;
		case ENC_LDCLRH_32_MEMOP:
			return ARM64_LDCLRH;
		case ENC_LDCLRL_32_MEMOP:
		case ENC_LDCLRL_64_MEMOP:
			return ARM64_LDCLRL;
		case ENC_LDCLRLB_32_MEMOP:
			return ARM64_LDCLRLB;
		case ENC_LDCLRLH_32_MEMOP:
			return ARM64_LDCLRLH;
		case ENC_LDEOR_32_MEMOP:
		case ENC_LDEOR_64_MEMOP:
			return ARM64_LDEOR;
		case ENC_LDEORA_32_MEMOP:
		case ENC_LDEORA_64_MEMOP:
			return ARM64_LDEORA;
		case ENC_LDEORAB_32_MEMOP:
			return ARM64_LDEORAB;
		case ENC_LDEORAH_32_MEMOP:
			return ARM64_LDEORAH;
		case ENC_LDEORAL_32_MEMOP:
		case ENC_LDEORAL_64_MEMOP:
			return ARM64_LDEORAL;
		case ENC_LDEORALB_32_MEMOP:
			return ARM64_LDEORALB;
		case ENC_LDEORALH_32_MEMOP:
			return ARM64_LDEORALH;
		case ENC_LDEORB_32_MEMOP:
			return ARM64_LDEORB;
		case ENC_LDEORH_32_MEMOP:
			return ARM64_LDEORH;
		case ENC_LDEORL_32_MEMOP:
		case ENC_LDEORL_64_MEMOP:
			return ARM64_LDEORL;
		case ENC_LDEORLB_32_MEMOP:
			return ARM64_LDEORLB;
		case ENC_LDEORLH_32_MEMOP:
			return ARM64_LDEORLH;
		case ENC_LDFF1B_Z_P_AI_S:
		case ENC_LDFF1B_Z_P_AI_D:
		case ENC_LDFF1B_Z_P_BR_U8:
		case ENC_LDFF1B_Z_P_BR_U16:
		case ENC_LDFF1B_Z_P_BR_U32:
		case ENC_LDFF1B_Z_P_BR_U64:
		case ENC_LDFF1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1B_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LDFF1B;
		case ENC_LDFF1D_Z_P_AI_D:
		case ENC_LDFF1D_Z_P_BR_U64:
		case ENC_LDFF1D_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1D_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1D_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LDFF1D;
		case ENC_LDFF1H_Z_P_AI_S:
		case ENC_LDFF1H_Z_P_AI_D:
		case ENC_LDFF1H_Z_P_BR_U16:
		case ENC_LDFF1H_Z_P_BR_U32:
		case ENC_LDFF1H_Z_P_BR_U64:
		case ENC_LDFF1H_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1H_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1H_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LDFF1H;
		case ENC_LDFF1SB_Z_P_AI_S:
		case ENC_LDFF1SB_Z_P_AI_D:
		case ENC_LDFF1SB_Z_P_BR_S16:
		case ENC_LDFF1SB_Z_P_BR_S32:
		case ENC_LDFF1SB_Z_P_BR_S64:
		case ENC_LDFF1SB_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SB_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LDFF1SB;
		case ENC_LDFF1SH_Z_P_AI_S:
		case ENC_LDFF1SH_Z_P_AI_D:
		case ENC_LDFF1SH_Z_P_BR_S32:
		case ENC_LDFF1SH_Z_P_BR_S64:
		case ENC_LDFF1SH_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1SH_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LDFF1SH;
		case ENC_LDFF1SW_Z_P_AI_D:
		case ENC_LDFF1SW_Z_P_BR_S64:
		case ENC_LDFF1SW_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1SW_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LDFF1SW;
		case ENC_LDFF1W_Z_P_AI_S:
		case ENC_LDFF1W_Z_P_AI_D:
		case ENC_LDFF1W_Z_P_BR_U32:
		case ENC_LDFF1W_Z_P_BR_U64:
		case ENC_LDFF1W_Z_P_BZ_S_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_X32_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_X32_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_S_X32_UNSCALED:
		case ENC_LDFF1W_Z_P_BZ_D_64_SCALED:
		case ENC_LDFF1W_Z_P_BZ_D_64_UNSCALED:
			return ARM64_LDFF1W;
		case ENC_LDG_64LOFFSET_LDSTTAGS:
			return ARM64_LDG;
		case ENC_LDGM_64BULK_LDSTTAGS:
			return ARM64_LDGM;
		case ENC_LDLAR_LR32_LDSTEXCL:
		case ENC_LDLAR_LR64_LDSTEXCL:
			return ARM64_LDLAR;
		case ENC_LDLARB_LR32_LDSTEXCL:
			return ARM64_LDLARB;
		case ENC_LDLARH_LR32_LDSTEXCL:
			return ARM64_LDLARH;
		case ENC_LDNF1B_Z_P_BI_U8:
		case ENC_LDNF1B_Z_P_BI_U16:
		case ENC_LDNF1B_Z_P_BI_U32:
		case ENC_LDNF1B_Z_P_BI_U64:
			return ARM64_LDNF1B;
		case ENC_LDNF1D_Z_P_BI_U64:
			return ARM64_LDNF1D;
		case ENC_LDNF1H_Z_P_BI_U16:
		case ENC_LDNF1H_Z_P_BI_U32:
		case ENC_LDNF1H_Z_P_BI_U64:
			return ARM64_LDNF1H;
		case ENC_LDNF1SB_Z_P_BI_S16:
		case ENC_LDNF1SB_Z_P_BI_S32:
		case ENC_LDNF1SB_Z_P_BI_S64:
			return ARM64_LDNF1SB;
		case ENC_LDNF1SH_Z_P_BI_S32:
		case ENC_LDNF1SH_Z_P_BI_S64:
			return ARM64_LDNF1SH;
		case ENC_LDNF1SW_Z_P_BI_S64:
			return ARM64_LDNF1SW;
		case ENC_LDNF1W_Z_P_BI_U32:
		case ENC_LDNF1W_Z_P_BI_U64:
			return ARM64_LDNF1W;
		case ENC_LDNP_S_LDSTNAPAIR_OFFS:
		case ENC_LDNP_D_LDSTNAPAIR_OFFS:
		case ENC_LDNP_Q_LDSTNAPAIR_OFFS:
		case ENC_LDNP_32_LDSTNAPAIR_OFFS:
		case ENC_LDNP_64_LDSTNAPAIR_OFFS:
			return ARM64_LDNP;
		case ENC_LDNT1B_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1B_Z_P_BR_CONTIGUOUS:
			return ARM64_LDNT1B;
		case ENC_LDNT1D_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1D_Z_P_BR_CONTIGUOUS:
			return ARM64_LDNT1D;
		case ENC_LDNT1H_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1H_Z_P_BR_CONTIGUOUS:
			return ARM64_LDNT1H;
		case ENC_LDNT1W_Z_P_BI_CONTIGUOUS:
		case ENC_LDNT1W_Z_P_BR_CONTIGUOUS:
			return ARM64_LDNT1W;
		case ENC_LDP_S_LDSTPAIR_POST:
		case ENC_LDP_D_LDSTPAIR_POST:
		case ENC_LDP_Q_LDSTPAIR_POST:
		case ENC_LDP_S_LDSTPAIR_PRE:
		case ENC_LDP_D_LDSTPAIR_PRE:
		case ENC_LDP_Q_LDSTPAIR_PRE:
		case ENC_LDP_S_LDSTPAIR_OFF:
		case ENC_LDP_D_LDSTPAIR_OFF:
		case ENC_LDP_Q_LDSTPAIR_OFF:
		case ENC_LDP_32_LDSTPAIR_POST:
		case ENC_LDP_64_LDSTPAIR_POST:
		case ENC_LDP_32_LDSTPAIR_PRE:
		case ENC_LDP_64_LDSTPAIR_PRE:
		case ENC_LDP_32_LDSTPAIR_OFF:
		case ENC_LDP_64_LDSTPAIR_OFF:
			return ARM64_LDP;
		case ENC_LDPSW_64_LDSTPAIR_POST:
		case ENC_LDPSW_64_LDSTPAIR_PRE:
		case ENC_LDPSW_64_LDSTPAIR_OFF:
			return ARM64_LDPSW;
		case ENC_LDR_B_LDST_IMMPOST:
		case ENC_LDR_H_LDST_IMMPOST:
		case ENC_LDR_S_LDST_IMMPOST:
		case ENC_LDR_D_LDST_IMMPOST:
		case ENC_LDR_Q_LDST_IMMPOST:
		case ENC_LDR_B_LDST_IMMPRE:
		case ENC_LDR_H_LDST_IMMPRE:
		case ENC_LDR_S_LDST_IMMPRE:
		case ENC_LDR_D_LDST_IMMPRE:
		case ENC_LDR_Q_LDST_IMMPRE:
		case ENC_LDR_B_LDST_POS:
		case ENC_LDR_H_LDST_POS:
		case ENC_LDR_S_LDST_POS:
		case ENC_LDR_D_LDST_POS:
		case ENC_LDR_Q_LDST_POS:
		case ENC_LDR_32_LDST_IMMPOST:
		case ENC_LDR_64_LDST_IMMPOST:
		case ENC_LDR_32_LDST_IMMPRE:
		case ENC_LDR_64_LDST_IMMPRE:
		case ENC_LDR_32_LDST_POS:
		case ENC_LDR_64_LDST_POS:
		case ENC_LDR_S_LOADLIT:
		case ENC_LDR_D_LOADLIT:
		case ENC_LDR_Q_LOADLIT:
		case ENC_LDR_32_LOADLIT:
		case ENC_LDR_64_LOADLIT:
		case ENC_LDR_B_LDST_REGOFF:
		case ENC_LDR_BL_LDST_REGOFF:
		case ENC_LDR_H_LDST_REGOFF:
		case ENC_LDR_S_LDST_REGOFF:
		case ENC_LDR_D_LDST_REGOFF:
		case ENC_LDR_Q_LDST_REGOFF:
		case ENC_LDR_32_LDST_REGOFF:
		case ENC_LDR_64_LDST_REGOFF:
		case ENC_LDR_P_BI_:
		case ENC_LDR_Z_BI_:
			return ARM64_LDR;
		case ENC_LDRAA_64_LDST_PAC:
		case ENC_LDRAA_64W_LDST_PAC:
			return ARM64_LDRAA;
		case ENC_LDRAB_64_LDST_PAC:
		case ENC_LDRAB_64W_LDST_PAC:
			return ARM64_LDRAB;
		case ENC_LDRB_32_LDST_IMMPOST:
		case ENC_LDRB_32_LDST_IMMPRE:
		case ENC_LDRB_32_LDST_POS:
		case ENC_LDRB_32B_LDST_REGOFF:
		case ENC_LDRB_32BL_LDST_REGOFF:
			return ARM64_LDRB;
		case ENC_LDRH_32_LDST_IMMPOST:
		case ENC_LDRH_32_LDST_IMMPRE:
		case ENC_LDRH_32_LDST_POS:
		case ENC_LDRH_32_LDST_REGOFF:
			return ARM64_LDRH;
		case ENC_LDRSB_32_LDST_IMMPOST:
		case ENC_LDRSB_64_LDST_IMMPOST:
		case ENC_LDRSB_32_LDST_IMMPRE:
		case ENC_LDRSB_64_LDST_IMMPRE:
		case ENC_LDRSB_32_LDST_POS:
		case ENC_LDRSB_64_LDST_POS:
		case ENC_LDRSB_32B_LDST_REGOFF:
		case ENC_LDRSB_32BL_LDST_REGOFF:
		case ENC_LDRSB_64B_LDST_REGOFF:
		case ENC_LDRSB_64BL_LDST_REGOFF:
			return ARM64_LDRSB;
		case ENC_LDRSH_32_LDST_IMMPOST:
		case ENC_LDRSH_64_LDST_IMMPOST:
		case ENC_LDRSH_32_LDST_IMMPRE:
		case ENC_LDRSH_64_LDST_IMMPRE:
		case ENC_LDRSH_32_LDST_POS:
		case ENC_LDRSH_64_LDST_POS:
		case ENC_LDRSH_32_LDST_REGOFF:
		case ENC_LDRSH_64_LDST_REGOFF:
			return ARM64_LDRSH;
		case ENC_LDRSW_64_LDST_IMMPOST:
		case ENC_LDRSW_64_LDST_IMMPRE:
		case ENC_LDRSW_64_LDST_POS:
		case ENC_LDRSW_64_LOADLIT:
		case ENC_LDRSW_64_LDST_REGOFF:
			return ARM64_LDRSW;
		case ENC_LDSET_32_MEMOP:
		case ENC_LDSET_64_MEMOP:
			return ARM64_LDSET;
		case ENC_LDSETA_32_MEMOP:
		case ENC_LDSETA_64_MEMOP:
			return ARM64_LDSETA;
		case ENC_LDSETAB_32_MEMOP:
			return ARM64_LDSETAB;
		case ENC_LDSETAH_32_MEMOP:
			return ARM64_LDSETAH;
		case ENC_LDSETAL_32_MEMOP:
		case ENC_LDSETAL_64_MEMOP:
			return ARM64_LDSETAL;
		case ENC_LDSETALB_32_MEMOP:
			return ARM64_LDSETALB;
		case ENC_LDSETALH_32_MEMOP:
			return ARM64_LDSETALH;
		case ENC_LDSETB_32_MEMOP:
			return ARM64_LDSETB;
		case ENC_LDSETH_32_MEMOP:
			return ARM64_LDSETH;
		case ENC_LDSETL_32_MEMOP:
		case ENC_LDSETL_64_MEMOP:
			return ARM64_LDSETL;
		case ENC_LDSETLB_32_MEMOP:
			return ARM64_LDSETLB;
		case ENC_LDSETLH_32_MEMOP:
			return ARM64_LDSETLH;
		case ENC_LDSMAX_32_MEMOP:
		case ENC_LDSMAX_64_MEMOP:
			return ARM64_LDSMAX;
		case ENC_LDSMAXA_32_MEMOP:
		case ENC_LDSMAXA_64_MEMOP:
			return ARM64_LDSMAXA;
		case ENC_LDSMAXAB_32_MEMOP:
			return ARM64_LDSMAXAB;
		case ENC_LDSMAXAH_32_MEMOP:
			return ARM64_LDSMAXAH;
		case ENC_LDSMAXAL_32_MEMOP:
		case ENC_LDSMAXAL_64_MEMOP:
			return ARM64_LDSMAXAL;
		case ENC_LDSMAXALB_32_MEMOP:
			return ARM64_LDSMAXALB;
		case ENC_LDSMAXALH_32_MEMOP:
			return ARM64_LDSMAXALH;
		case ENC_LDSMAXB_32_MEMOP:
			return ARM64_LDSMAXB;
		case ENC_LDSMAXH_32_MEMOP:
			return ARM64_LDSMAXH;
		case ENC_LDSMAXL_32_MEMOP:
		case ENC_LDSMAXL_64_MEMOP:
			return ARM64_LDSMAXL;
		case ENC_LDSMAXLB_32_MEMOP:
			return ARM64_LDSMAXLB;
		case ENC_LDSMAXLH_32_MEMOP:
			return ARM64_LDSMAXLH;
		case ENC_LDSMIN_32_MEMOP:
		case ENC_LDSMIN_64_MEMOP:
			return ARM64_LDSMIN;
		case ENC_LDSMINA_32_MEMOP:
		case ENC_LDSMINA_64_MEMOP:
			return ARM64_LDSMINA;
		case ENC_LDSMINAB_32_MEMOP:
			return ARM64_LDSMINAB;
		case ENC_LDSMINAH_32_MEMOP:
			return ARM64_LDSMINAH;
		case ENC_LDSMINAL_32_MEMOP:
		case ENC_LDSMINAL_64_MEMOP:
			return ARM64_LDSMINAL;
		case ENC_LDSMINALB_32_MEMOP:
			return ARM64_LDSMINALB;
		case ENC_LDSMINALH_32_MEMOP:
			return ARM64_LDSMINALH;
		case ENC_LDSMINB_32_MEMOP:
			return ARM64_LDSMINB;
		case ENC_LDSMINH_32_MEMOP:
			return ARM64_LDSMINH;
		case ENC_LDSMINL_32_MEMOP:
		case ENC_LDSMINL_64_MEMOP:
			return ARM64_LDSMINL;
		case ENC_LDSMINLB_32_MEMOP:
			return ARM64_LDSMINLB;
		case ENC_LDSMINLH_32_MEMOP:
			return ARM64_LDSMINLH;
		case ENC_LDTR_32_LDST_UNPRIV:
		case ENC_LDTR_64_LDST_UNPRIV:
			return ARM64_LDTR;
		case ENC_LDTRB_32_LDST_UNPRIV:
			return ARM64_LDTRB;
		case ENC_LDTRH_32_LDST_UNPRIV:
			return ARM64_LDTRH;
		case ENC_LDTRSB_32_LDST_UNPRIV:
		case ENC_LDTRSB_64_LDST_UNPRIV:
			return ARM64_LDTRSB;
		case ENC_LDTRSH_32_LDST_UNPRIV:
		case ENC_LDTRSH_64_LDST_UNPRIV:
			return ARM64_LDTRSH;
		case ENC_LDTRSW_64_LDST_UNPRIV:
			return ARM64_LDTRSW;
		case ENC_LDUMAX_32_MEMOP:
		case ENC_LDUMAX_64_MEMOP:
			return ARM64_LDUMAX;
		case ENC_LDUMAXA_32_MEMOP:
		case ENC_LDUMAXA_64_MEMOP:
			return ARM64_LDUMAXA;
		case ENC_LDUMAXAB_32_MEMOP:
			return ARM64_LDUMAXAB;
		case ENC_LDUMAXAH_32_MEMOP:
			return ARM64_LDUMAXAH;
		case ENC_LDUMAXAL_32_MEMOP:
		case ENC_LDUMAXAL_64_MEMOP:
			return ARM64_LDUMAXAL;
		case ENC_LDUMAXALB_32_MEMOP:
			return ARM64_LDUMAXALB;
		case ENC_LDUMAXALH_32_MEMOP:
			return ARM64_LDUMAXALH;
		case ENC_LDUMAXB_32_MEMOP:
			return ARM64_LDUMAXB;
		case ENC_LDUMAXH_32_MEMOP:
			return ARM64_LDUMAXH;
		case ENC_LDUMAXL_32_MEMOP:
		case ENC_LDUMAXL_64_MEMOP:
			return ARM64_LDUMAXL;
		case ENC_LDUMAXLB_32_MEMOP:
			return ARM64_LDUMAXLB;
		case ENC_LDUMAXLH_32_MEMOP:
			return ARM64_LDUMAXLH;
		case ENC_LDUMIN_32_MEMOP:
		case ENC_LDUMIN_64_MEMOP:
			return ARM64_LDUMIN;
		case ENC_LDUMINA_32_MEMOP:
		case ENC_LDUMINA_64_MEMOP:
			return ARM64_LDUMINA;
		case ENC_LDUMINAB_32_MEMOP:
			return ARM64_LDUMINAB;
		case ENC_LDUMINAH_32_MEMOP:
			return ARM64_LDUMINAH;
		case ENC_LDUMINAL_32_MEMOP:
		case ENC_LDUMINAL_64_MEMOP:
			return ARM64_LDUMINAL;
		case ENC_LDUMINALB_32_MEMOP:
			return ARM64_LDUMINALB;
		case ENC_LDUMINALH_32_MEMOP:
			return ARM64_LDUMINALH;
		case ENC_LDUMINB_32_MEMOP:
			return ARM64_LDUMINB;
		case ENC_LDUMINH_32_MEMOP:
			return ARM64_LDUMINH;
		case ENC_LDUMINL_32_MEMOP:
		case ENC_LDUMINL_64_MEMOP:
			return ARM64_LDUMINL;
		case ENC_LDUMINLB_32_MEMOP:
			return ARM64_LDUMINLB;
		case ENC_LDUMINLH_32_MEMOP:
			return ARM64_LDUMINLH;
		case ENC_LDUR_B_LDST_UNSCALED:
		case ENC_LDUR_H_LDST_UNSCALED:
		case ENC_LDUR_S_LDST_UNSCALED:
		case ENC_LDUR_D_LDST_UNSCALED:
		case ENC_LDUR_Q_LDST_UNSCALED:
		case ENC_LDUR_32_LDST_UNSCALED:
		case ENC_LDUR_64_LDST_UNSCALED:
			return ARM64_LDUR;
		case ENC_LDURB_32_LDST_UNSCALED:
			return ARM64_LDURB;
		case ENC_LDURH_32_LDST_UNSCALED:
			return ARM64_LDURH;
		case ENC_LDURSB_32_LDST_UNSCALED:
		case ENC_LDURSB_64_LDST_UNSCALED:
			return ARM64_LDURSB;
		case ENC_LDURSH_32_LDST_UNSCALED:
		case ENC_LDURSH_64_LDST_UNSCALED:
			return ARM64_LDURSH;
		case ENC_LDURSW_64_LDST_UNSCALED:
			return ARM64_LDURSW;
		case ENC_LDXP_LP32_LDSTEXCL:
		case ENC_LDXP_LP64_LDSTEXCL:
			return ARM64_LDXP;
		case ENC_LDXR_LR32_LDSTEXCL:
		case ENC_LDXR_LR64_LDSTEXCL:
			return ARM64_LDXR;
		case ENC_LDXRB_LR32_LDSTEXCL:
			return ARM64_LDXRB;
		case ENC_LDXRH_LR32_LDSTEXCL:
			return ARM64_LDXRH;
		case ENC_LSL_LSLV_32_DP_2SRC:
		case ENC_LSL_LSLV_64_DP_2SRC:
		case ENC_LSL_UBFM_32M_BITFIELD:
		case ENC_LSL_UBFM_64M_BITFIELD:
		case ENC_LSL_Z_P_ZI_:
		case ENC_LSL_Z_P_ZW_:
		case ENC_LSL_Z_P_ZZ_:
		case ENC_LSL_Z_ZI_:
		case ENC_LSL_Z_ZW_:
			return ARM64_LSL;
		case ENC_LSLR_Z_P_ZZ_:
			return ARM64_LSLR;
		case ENC_LSLV_32_DP_2SRC:
		case ENC_LSLV_64_DP_2SRC:
			return ARM64_LSLV;
		case ENC_LSR_LSRV_32_DP_2SRC:
		case ENC_LSR_LSRV_64_DP_2SRC:
		case ENC_LSR_UBFM_32M_BITFIELD:
		case ENC_LSR_UBFM_64M_BITFIELD:
		case ENC_LSR_Z_P_ZI_:
		case ENC_LSR_Z_P_ZW_:
		case ENC_LSR_Z_P_ZZ_:
		case ENC_LSR_Z_ZI_:
		case ENC_LSR_Z_ZW_:
			return ARM64_LSR;
		case ENC_LSRR_Z_P_ZZ_:
			return ARM64_LSRR;
		case ENC_LSRV_32_DP_2SRC:
		case ENC_LSRV_64_DP_2SRC:
			return ARM64_LSRV;
		case ENC_MAD_Z_P_ZZZ_:
			return ARM64_MAD;
		case ENC_MADD_32A_DP_3SRC:
		case ENC_MADD_64A_DP_3SRC:
			return ARM64_MADD;
		case ENC_MLA_ASIMDELEM_R:
		case ENC_MLA_ASIMDSAME_ONLY:
		case ENC_MLA_Z_P_ZZZ_:
			return ARM64_MLA;
		case ENC_MLS_ASIMDELEM_R:
		case ENC_MLS_ASIMDSAME_ONLY:
		case ENC_MLS_Z_P_ZZZ_:
			return ARM64_MLS;
		case ENC_MNEG_MSUB_32A_DP_3SRC:
		case ENC_MNEG_MSUB_64A_DP_3SRC:
			return ARM64_MNEG;
		case ENC_MOV_ADD_32_ADDSUB_IMM:
		case ENC_MOV_ADD_64_ADDSUB_IMM:
		case ENC_MOV_DUP_ASISDONE_ONLY:
		case ENC_MOV_INS_ASIMDINS_IV_V:
		case ENC_MOV_INS_ASIMDINS_IR_R:
		case ENC_MOV_MOVN_32_MOVEWIDE:
		case ENC_MOV_MOVN_64_MOVEWIDE:
		case ENC_MOV_MOVZ_32_MOVEWIDE:
		case ENC_MOV_MOVZ_64_MOVEWIDE:
		case ENC_MOV_ORR_ASIMDSAME_ONLY:
		case ENC_MOV_ORR_32_LOG_IMM:
		case ENC_MOV_ORR_64_LOG_IMM:
		case ENC_MOV_ORR_32_LOG_SHIFT:
		case ENC_MOV_ORR_64_LOG_SHIFT:
		case ENC_MOV_UMOV_ASIMDINS_W_W:
		case ENC_MOV_UMOV_ASIMDINS_X_X:
		case ENC_MOV_AND_P_P_PP_Z:
		case ENC_MOV_CPY_Z_O_I_:
		case ENC_MOV_CPY_Z_P_I_:
		case ENC_MOV_CPY_Z_P_R_:
		case ENC_MOV_CPY_Z_P_V_:
		case ENC_MOV_DUP_Z_I_:
		case ENC_MOV_DUP_Z_R_:
		case ENC_MOV_DUP_Z_ZI_:
		case ENC_MOV_DUP_Z_ZI_2:
		case ENC_MOV_DUPM_Z_I_:
		case ENC_MOV_ORR_P_P_PP_Z:
		case ENC_MOV_ORR_Z_ZZ_:
		case ENC_MOV_SEL_P_P_PP_:
		case ENC_MOV_SEL_Z_P_ZZ_:
			return ARM64_MOV;
		case ENC_MOVI_ASIMDIMM_N_B:
		case ENC_MOVI_ASIMDIMM_L_HL:
		case ENC_MOVI_ASIMDIMM_L_SL:
		case ENC_MOVI_ASIMDIMM_M_SM:
		case ENC_MOVI_ASIMDIMM_D_DS:
		case ENC_MOVI_ASIMDIMM_D2_D:
			return ARM64_MOVI;
		case ENC_MOVK_32_MOVEWIDE:
		case ENC_MOVK_64_MOVEWIDE:
			return ARM64_MOVK;
		case ENC_MOVN_32_MOVEWIDE:
		case ENC_MOVN_64_MOVEWIDE:
			return ARM64_MOVN;
		case ENC_MOVPRFX_Z_P_Z_:
		case ENC_MOVPRFX_Z_Z_:
			return ARM64_MOVPRFX;
		case ENC_MOVS_ANDS_P_P_PP_Z:
		case ENC_MOVS_ORRS_P_P_PP_Z:
			return ARM64_MOVS;
		case ENC_MOVZ_32_MOVEWIDE:
		case ENC_MOVZ_64_MOVEWIDE:
			return ARM64_MOVZ;
		case ENC_MRS_RS_SYSTEMMOVE:
			return ARM64_MRS;
		case ENC_MSB_Z_P_ZZZ_:
			return ARM64_MSB;
		case ENC_MSR_SI_PSTATE:
		case ENC_MSR_SR_SYSTEMMOVE:
			return ARM64_MSR;
		case ENC_MSUB_32A_DP_3SRC:
		case ENC_MSUB_64A_DP_3SRC:
			return ARM64_MSUB;
		case ENC_MUL_MADD_32A_DP_3SRC:
		case ENC_MUL_MADD_64A_DP_3SRC:
		case ENC_MUL_ASIMDELEM_R:
		case ENC_MUL_ASIMDSAME_ONLY:
		case ENC_MUL_Z_P_ZZ_:
		case ENC_MUL_Z_ZI_:
			return ARM64_MUL;
		case ENC_MVN_NOT_ASIMDMISC_R:
		case ENC_MVN_ORN_32_LOG_SHIFT:
		case ENC_MVN_ORN_64_LOG_SHIFT:
			return ARM64_MVN;
		case ENC_MVNI_ASIMDIMM_L_HL:
		case ENC_MVNI_ASIMDIMM_L_SL:
		case ENC_MVNI_ASIMDIMM_M_SM:
			return ARM64_MVNI;
		case ENC_NAND_P_P_PP_Z:
			return ARM64_NAND;
		case ENC_NANDS_P_P_PP_Z:
			return ARM64_NANDS;
		case ENC_NEG_SUB_32_ADDSUB_SHIFT:
		case ENC_NEG_SUB_64_ADDSUB_SHIFT:
		case ENC_NEG_ASISDMISC_R:
		case ENC_NEG_ASIMDMISC_R:
		case ENC_NEG_Z_P_Z_:
			return ARM64_NEG;
		case ENC_NEGS_SUBS_32_ADDSUB_SHIFT:
		case ENC_NEGS_SUBS_64_ADDSUB_SHIFT:
			return ARM64_NEGS;
		case ENC_NGC_SBC_32_ADDSUB_CARRY:
		case ENC_NGC_SBC_64_ADDSUB_CARRY:
			return ARM64_NGC;
		case ENC_NGCS_SBCS_32_ADDSUB_CARRY:
		case ENC_NGCS_SBCS_64_ADDSUB_CARRY:
			return ARM64_NGCS;
		case ENC_NOP_HI_HINTS:
			return ARM64_NOP;
		case ENC_NOR_P_P_PP_Z:
			return ARM64_NOR;
		case ENC_NORS_P_P_PP_Z:
			return ARM64_NORS;
		case ENC_NOT_ASIMDMISC_R:
		case ENC_NOT_EOR_P_P_PP_Z:
		case ENC_NOT_Z_P_Z_:
			return ARM64_NOT;
		case ENC_NOTS_EORS_P_P_PP_Z:
			return ARM64_NOTS;
		case ENC_ORN_ASIMDSAME_ONLY:
		case ENC_ORN_32_LOG_SHIFT:
		case ENC_ORN_64_LOG_SHIFT:
		case ENC_ORN_ORR_Z_ZI_:
		case ENC_ORN_P_P_PP_Z:
			return ARM64_ORN;
		case ENC_ORNS_P_P_PP_Z:
			return ARM64_ORNS;
		case ENC_ORR_ASIMDIMM_L_HL:
		case ENC_ORR_ASIMDIMM_L_SL:
		case ENC_ORR_ASIMDSAME_ONLY:
		case ENC_ORR_32_LOG_IMM:
		case ENC_ORR_64_LOG_IMM:
		case ENC_ORR_32_LOG_SHIFT:
		case ENC_ORR_64_LOG_SHIFT:
		case ENC_ORR_P_P_PP_Z:
		case ENC_ORR_Z_P_ZZ_:
		case ENC_ORR_Z_ZI_:
		case ENC_ORR_Z_ZZ_:
			return ARM64_ORR;
		case ENC_ORRS_P_P_PP_Z:
			return ARM64_ORRS;
		case ENC_ORV_R_P_Z_:
			return ARM64_ORV;
		case ENC_PACDA_64P_DP_1SRC:
			return ARM64_PACDA;
		case ENC_PACDB_64P_DP_1SRC:
			return ARM64_PACDB;
		case ENC_PACDZA_64Z_DP_1SRC:
			return ARM64_PACDZA;
		case ENC_PACDZB_64Z_DP_1SRC:
			return ARM64_PACDZB;
		case ENC_PACGA_64P_DP_2SRC:
			return ARM64_PACGA;
		case ENC_PACIA_64P_DP_1SRC:
			return ARM64_PACIA;
		case ENC_PACIA1716_HI_HINTS:
			return ARM64_PACIA1716;
		case ENC_PACIASP_HI_HINTS:
			return ARM64_PACIASP;
		case ENC_PACIAZ_HI_HINTS:
			return ARM64_PACIAZ;
		case ENC_PACIB_64P_DP_1SRC:
			return ARM64_PACIB;
		case ENC_PACIB1716_HI_HINTS:
			return ARM64_PACIB1716;
		case ENC_PACIBSP_HI_HINTS:
			return ARM64_PACIBSP;
		case ENC_PACIBZ_HI_HINTS:
			return ARM64_PACIBZ;
		case ENC_PACIZA_64Z_DP_1SRC:
			return ARM64_PACIZA;
		case ENC_PACIZB_64Z_DP_1SRC:
			return ARM64_PACIZB;
		case ENC_PFALSE_P_:
			return ARM64_PFALSE;
		case ENC_PFIRST_P_P_P_:
			return ARM64_PFIRST;
		case ENC_PMUL_ASIMDSAME_ONLY:
			return ARM64_PMUL;
		case ENC_PMULL_ASIMDDIFF_L:
			return ARM64_PMULL;
		//case ENC_PMULL_ASIMDDIFF_L:
		//	return ARM64_PMULL2;
		case ENC_PNEXT_P_P_P_:
			return ARM64_PNEXT;
		case ENC_PRFB_I_P_AI_S:
		case ENC_PRFB_I_P_AI_D:
		case ENC_PRFB_I_P_BI_S:
		case ENC_PRFB_I_P_BR_S:
		case ENC_PRFB_I_P_BZ_S_X32_SCALED:
		case ENC_PRFB_I_P_BZ_D_X32_SCALED:
		case ENC_PRFB_I_P_BZ_D_64_SCALED:
			return ARM64_PRFB;
		case ENC_PRFD_I_P_AI_S:
		case ENC_PRFD_I_P_AI_D:
		case ENC_PRFD_I_P_BI_S:
		case ENC_PRFD_I_P_BR_S:
		case ENC_PRFD_I_P_BZ_S_X32_SCALED:
		case ENC_PRFD_I_P_BZ_D_X32_SCALED:
		case ENC_PRFD_I_P_BZ_D_64_SCALED:
			return ARM64_PRFD;
		case ENC_PRFH_I_P_AI_S:
		case ENC_PRFH_I_P_AI_D:
		case ENC_PRFH_I_P_BI_S:
		case ENC_PRFH_I_P_BR_S:
		case ENC_PRFH_I_P_BZ_S_X32_SCALED:
		case ENC_PRFH_I_P_BZ_D_X32_SCALED:
		case ENC_PRFH_I_P_BZ_D_64_SCALED:
			return ARM64_PRFH;
		case ENC_PRFM_P_LDST_POS:
		case ENC_PRFM_P_LOADLIT:
		case ENC_PRFM_P_LDST_REGOFF:
			return ARM64_PRFM;
		case ENC_PRFUM_P_LDST_UNSCALED:
			return ARM64_PRFUM;
		case ENC_PRFW_I_P_AI_S:
		case ENC_PRFW_I_P_AI_D:
		case ENC_PRFW_I_P_BI_S:
		case ENC_PRFW_I_P_BR_S:
		case ENC_PRFW_I_P_BZ_S_X32_SCALED:
		case ENC_PRFW_I_P_BZ_D_X32_SCALED:
		case ENC_PRFW_I_P_BZ_D_64_SCALED:
			return ARM64_PRFW;
		case ENC_PSB_HC_HINTS:
			return ARM64_PSB;
		case ENC_PSSBB_ONLY_BARRIERS:
			return ARM64_PSSBB;
		case ENC_PTEST_P_P_:
			return ARM64_PTEST;
		case ENC_PTRUE_P_S_:
			return ARM64_PTRUE;
		case ENC_PTRUES_P_S_:
			return ARM64_PTRUES;
		case ENC_PUNPKHI_P_P_:
			return ARM64_PUNPKHI;
		case ENC_PUNPKLO_P_P_:
			return ARM64_PUNPKLO;
		case ENC_RADDHN_ASIMDDIFF_N:
			return ARM64_RADDHN;
		//case ENC_RADDHN_ASIMDDIFF_N:
		//	return ARM64_RADDHN2;
		case ENC_RAX1_VVV2_CRYPTOSHA512_3:
			return ARM64_RAX1;
		case ENC_RBIT_ASIMDMISC_R:
		case ENC_RBIT_32_DP_1SRC:
		case ENC_RBIT_64_DP_1SRC:
		case ENC_RBIT_Z_P_Z_:
			return ARM64_RBIT;
		case ENC_RDFFR_P_F_:
		case ENC_RDFFR_P_P_F_:
			return ARM64_RDFFR;
		case ENC_RDFFRS_P_P_F_:
			return ARM64_RDFFRS;
		case ENC_RDVL_R_I_:
			return ARM64_RDVL;
		case ENC_RET_64R_BRANCH_REG:
			return ARM64_RET;
		case ENC_RETAA_64E_BRANCH_REG:
			return ARM64_RETAA;
		case ENC_RETAB_64E_BRANCH_REG:
			return ARM64_RETAB;
		case ENC_REV_32_DP_1SRC:
		case ENC_REV_64_DP_1SRC:
		case ENC_REV_P_P_:
		case ENC_REV_Z_Z_:
			return ARM64_REV;
		case ENC_REV16_ASIMDMISC_R:
		case ENC_REV16_32_DP_1SRC:
		case ENC_REV16_64_DP_1SRC:
			return ARM64_REV16;
		case ENC_REV32_ASIMDMISC_R:
		case ENC_REV32_64_DP_1SRC:
			return ARM64_REV32;
		case ENC_REV64_REV_64_DP_1SRC:
		case ENC_REV64_ASIMDMISC_R:
			return ARM64_REV64;
		case ENC_REVB_Z_Z_:
			return ARM64_REVB;
		case ENC_REVH_Z_Z_:
			return ARM64_REVH;
		case ENC_REVW_Z_Z_:
			return ARM64_REVW;
		case ENC_RMIF_ONLY_RMIF:
			return ARM64_RMIF;
		case ENC_ROR_EXTR_32_EXTRACT:
		case ENC_ROR_EXTR_64_EXTRACT:
		case ENC_ROR_RORV_32_DP_2SRC:
		case ENC_ROR_RORV_64_DP_2SRC:
			return ARM64_ROR;
		case ENC_RORV_32_DP_2SRC:
		case ENC_RORV_64_DP_2SRC:
			return ARM64_RORV;
		case ENC_RSHRN_ASIMDSHF_N:
			return ARM64_RSHRN;
		//case ENC_RSHRN_ASIMDSHF_N:
		//	return ARM64_RSHRN2;
		case ENC_RSUBHN_ASIMDDIFF_N:
			return ARM64_RSUBHN;
		//case ENC_RSUBHN_ASIMDDIFF_N:
		//	return ARM64_RSUBHN2;
		case ENC_SABA_ASIMDSAME_ONLY:
			return ARM64_SABA;
		case ENC_SABAL_ASIMDDIFF_L:
			return ARM64_SABAL;
		//case ENC_SABAL_ASIMDDIFF_L:
		//	return ARM64_SABAL2;
		case ENC_SABD_ASIMDSAME_ONLY:
		case ENC_SABD_Z_P_ZZ_:
			return ARM64_SABD;
		case ENC_SABDL_ASIMDDIFF_L:
			return ARM64_SABDL;
		//case ENC_SABDL_ASIMDDIFF_L:
		//	return ARM64_SABDL2;
		case ENC_SADALP_ASIMDMISC_P:
			return ARM64_SADALP;
		case ENC_SADDL_ASIMDDIFF_L:
			return ARM64_SADDL;
		//case ENC_SADDL_ASIMDDIFF_L:
		//	return ARM64_SADDL2;
		case ENC_SADDLP_ASIMDMISC_P:
			return ARM64_SADDLP;
		case ENC_SADDLV_ASIMDALL_ONLY:
			return ARM64_SADDLV;
		case ENC_SADDV_R_P_Z_:
			return ARM64_SADDV;
		case ENC_SADDW_ASIMDDIFF_W:
			return ARM64_SADDW;
		//case ENC_SADDW_ASIMDDIFF_W:
		//	return ARM64_SADDW2;
		case ENC_SB_ONLY_BARRIERS:
			return ARM64_SB;
		case ENC_SBC_32_ADDSUB_CARRY:
		case ENC_SBC_64_ADDSUB_CARRY:
			return ARM64_SBC;
		case ENC_SBCS_32_ADDSUB_CARRY:
		case ENC_SBCS_64_ADDSUB_CARRY:
			return ARM64_SBCS;
		case ENC_SBFIZ_SBFM_32M_BITFIELD:
		case ENC_SBFIZ_SBFM_64M_BITFIELD:
			return ARM64_SBFIZ;
		case ENC_SBFM_32M_BITFIELD:
		case ENC_SBFM_64M_BITFIELD:
			return ARM64_SBFM;
		case ENC_SBFX_SBFM_32M_BITFIELD:
		case ENC_SBFX_SBFM_64M_BITFIELD:
			return ARM64_SBFX;
		case ENC_SCVTF_ASISDSHF_C:
		case ENC_SCVTF_ASIMDSHF_C:
		case ENC_SCVTF_ASISDMISCFP16_R:
		case ENC_SCVTF_ASISDMISC_R:
		case ENC_SCVTF_ASIMDMISCFP16_R:
		case ENC_SCVTF_ASIMDMISC_R:
		case ENC_SCVTF_H32_FLOAT2FIX:
		case ENC_SCVTF_S32_FLOAT2FIX:
		case ENC_SCVTF_D32_FLOAT2FIX:
		case ENC_SCVTF_H64_FLOAT2FIX:
		case ENC_SCVTF_S64_FLOAT2FIX:
		case ENC_SCVTF_D64_FLOAT2FIX:
		case ENC_SCVTF_H32_FLOAT2INT:
		case ENC_SCVTF_S32_FLOAT2INT:
		case ENC_SCVTF_D32_FLOAT2INT:
		case ENC_SCVTF_H64_FLOAT2INT:
		case ENC_SCVTF_S64_FLOAT2INT:
		case ENC_SCVTF_D64_FLOAT2INT:
		case ENC_SCVTF_Z_P_Z_H2FP16:
		case ENC_SCVTF_Z_P_Z_W2FP16:
		case ENC_SCVTF_Z_P_Z_W2S:
		case ENC_SCVTF_Z_P_Z_W2D:
		case ENC_SCVTF_Z_P_Z_X2FP16:
		case ENC_SCVTF_Z_P_Z_X2S:
		case ENC_SCVTF_Z_P_Z_X2D:
			return ARM64_SCVTF;
		case ENC_SDIV_32_DP_2SRC:
		case ENC_SDIV_64_DP_2SRC:
		case ENC_SDIV_Z_P_ZZ_:
			return ARM64_SDIV;
		case ENC_SDIVR_Z_P_ZZ_:
			return ARM64_SDIVR;
		case ENC_SDOT_ASIMDELEM_D:
		case ENC_SDOT_ASIMDSAME2_D:
		case ENC_SDOT_Z_ZZZ_:
		case ENC_SDOT_Z_ZZZI_S:
		case ENC_SDOT_Z_ZZZI_D:
			return ARM64_SDOT;
		case ENC_SEL_P_P_PP_:
		case ENC_SEL_Z_P_ZZ_:
			return ARM64_SEL;
		case ENC_SETF16_ONLY_SETF:
			return ARM64_SETF16;
		case ENC_SETF8_ONLY_SETF:
			return ARM64_SETF8;
		case ENC_SETFFR_F_:
			return ARM64_SETFFR;
		case ENC_SEV_HI_HINTS:
			return ARM64_SEV;
		case ENC_SEVL_HI_HINTS:
			return ARM64_SEVL;
		case ENC_SHA1C_QSV_CRYPTOSHA3:
			return ARM64_SHA1C;
		case ENC_SHA1H_SS_CRYPTOSHA2:
			return ARM64_SHA1H;
		case ENC_SHA1M_QSV_CRYPTOSHA3:
			return ARM64_SHA1M;
		case ENC_SHA1P_QSV_CRYPTOSHA3:
			return ARM64_SHA1P;
		case ENC_SHA1SU0_VVV_CRYPTOSHA3:
			return ARM64_SHA1SU0;
		case ENC_SHA1SU1_VV_CRYPTOSHA2:
			return ARM64_SHA1SU1;
		case ENC_SHA256H_QQV_CRYPTOSHA3:
			return ARM64_SHA256H;
		case ENC_SHA256H2_QQV_CRYPTOSHA3:
			return ARM64_SHA256H2;
		case ENC_SHA256SU0_VV_CRYPTOSHA2:
			return ARM64_SHA256SU0;
		case ENC_SHA256SU1_VVV_CRYPTOSHA3:
			return ARM64_SHA256SU1;
		case ENC_SHA512H_QQV_CRYPTOSHA512_3:
			return ARM64_SHA512H;
		case ENC_SHA512H2_QQV_CRYPTOSHA512_3:
			return ARM64_SHA512H2;
		case ENC_SHA512SU0_VV2_CRYPTOSHA512_2:
			return ARM64_SHA512SU0;
		case ENC_SHA512SU1_VVV2_CRYPTOSHA512_3:
			return ARM64_SHA512SU1;
		case ENC_SHADD_ASIMDSAME_ONLY:
			return ARM64_SHADD;
		case ENC_SHL_ASISDSHF_R:
		case ENC_SHL_ASIMDSHF_R:
			return ARM64_SHL;
		case ENC_SHLL_ASIMDMISC_S:
			return ARM64_SHLL;
		//case ENC_SHLL_ASIMDMISC_S:
		//	return ARM64_SHLL2;
		case ENC_SHRN_ASIMDSHF_N:
			return ARM64_SHRN;
		//case ENC_SHRN_ASIMDSHF_N:
		//	return ARM64_SHRN2;
		case ENC_SHSUB_ASIMDSAME_ONLY:
			return ARM64_SHSUB;
		case ENC_SLI_ASISDSHF_R:
		case ENC_SLI_ASIMDSHF_R:
			return ARM64_SLI;
		case ENC_SM3PARTW1_VVV4_CRYPTOSHA512_3:
			return ARM64_SM3PARTW1;
		case ENC_SM3PARTW2_VVV4_CRYPTOSHA512_3:
			return ARM64_SM3PARTW2;
		case ENC_SM3SS1_VVV4_CRYPTO4:
			return ARM64_SM3SS1;
		case ENC_SM3TT1A_VVV4_CRYPTO3_IMM2:
			return ARM64_SM3TT1A;
		case ENC_SM3TT1B_VVV4_CRYPTO3_IMM2:
			return ARM64_SM3TT1B;
		case ENC_SM3TT2A_VVV4_CRYPTO3_IMM2:
			return ARM64_SM3TT2A;
		case ENC_SM3TT2B_VVV_CRYPTO3_IMM2:
			return ARM64_SM3TT2B;
		case ENC_SM4E_VV4_CRYPTOSHA512_2:
			return ARM64_SM4E;
		case ENC_SM4EKEY_VVV4_CRYPTOSHA512_3:
			return ARM64_SM4EKEY;
		case ENC_SMADDL_64WA_DP_3SRC:
			return ARM64_SMADDL;
		case ENC_SMAX_ASIMDSAME_ONLY:
		case ENC_SMAX_Z_P_ZZ_:
		case ENC_SMAX_Z_ZI_:
			return ARM64_SMAX;
		case ENC_SMAXP_ASIMDSAME_ONLY:
			return ARM64_SMAXP;
		case ENC_SMAXV_ASIMDALL_ONLY:
		case ENC_SMAXV_R_P_Z_:
			return ARM64_SMAXV;
		case ENC_SMC_EX_EXCEPTION:
			return ARM64_SMC;
		case ENC_SMIN_ASIMDSAME_ONLY:
		case ENC_SMIN_Z_P_ZZ_:
		case ENC_SMIN_Z_ZI_:
			return ARM64_SMIN;
		case ENC_SMINP_ASIMDSAME_ONLY:
			return ARM64_SMINP;
		case ENC_SMINV_ASIMDALL_ONLY:
		case ENC_SMINV_R_P_Z_:
			return ARM64_SMINV;
		case ENC_SMLAL_ASIMDELEM_L:
		case ENC_SMLAL_ASIMDDIFF_L:
			return ARM64_SMLAL;
		//case ENC_SMLAL_ASIMDELEM_L:
		//case ENC_SMLAL_ASIMDDIFF_L:
		//	return ARM64_SMLAL2;
		case ENC_SMLSL_ASIMDELEM_L:
		case ENC_SMLSL_ASIMDDIFF_L:
			return ARM64_SMLSL;
		//case ENC_SMLSL_ASIMDELEM_L:
		//case ENC_SMLSL_ASIMDDIFF_L:
		//	return ARM64_SMLSL2;
		case ENC_SMMLA_ASIMDSAME2_G:
		case ENC_SMMLA_Z_ZZZ_:
			return ARM64_SMMLA;
		case ENC_SMNEGL_SMSUBL_64WA_DP_3SRC:
			return ARM64_SMNEGL;
		case ENC_SMOV_ASIMDINS_W_W:
		case ENC_SMOV_ASIMDINS_X_X:
			return ARM64_SMOV;
		case ENC_SMSUBL_64WA_DP_3SRC:
			return ARM64_SMSUBL;
		case ENC_SMULH_64_DP_3SRC:
		case ENC_SMULH_Z_P_ZZ_:
			return ARM64_SMULH;
		case ENC_SMULL_SMADDL_64WA_DP_3SRC:
		case ENC_SMULL_ASIMDELEM_L:
		case ENC_SMULL_ASIMDDIFF_L:
			return ARM64_SMULL;
		//case ENC_SMULL_ASIMDELEM_L:
		//case ENC_SMULL_ASIMDDIFF_L:
		//	return ARM64_SMULL2;
		case ENC_SPLICE_Z_P_ZZ_DES:
			return ARM64_SPLICE;
		case ENC_SQABS_ASISDMISC_R:
		case ENC_SQABS_ASIMDMISC_R:
			return ARM64_SQABS;
		case ENC_SQADD_ASISDSAME_ONLY:
		case ENC_SQADD_ASIMDSAME_ONLY:
		case ENC_SQADD_Z_ZI_:
		case ENC_SQADD_Z_ZZ_:
			return ARM64_SQADD;
		case ENC_SQDECB_R_RS_SX:
		case ENC_SQDECB_R_RS_X:
			return ARM64_SQDECB;
		case ENC_SQDECD_R_RS_SX:
		case ENC_SQDECD_R_RS_X:
		case ENC_SQDECD_Z_ZS_:
			return ARM64_SQDECD;
		case ENC_SQDECH_R_RS_SX:
		case ENC_SQDECH_R_RS_X:
		case ENC_SQDECH_Z_ZS_:
			return ARM64_SQDECH;
		case ENC_SQDECP_R_P_R_SX:
		case ENC_SQDECP_R_P_R_X:
		case ENC_SQDECP_Z_P_Z_:
			return ARM64_SQDECP;
		case ENC_SQDECW_R_RS_SX:
		case ENC_SQDECW_R_RS_X:
		case ENC_SQDECW_Z_ZS_:
			return ARM64_SQDECW;
		case ENC_SQDMLAL_ASISDELEM_L:
		case ENC_SQDMLAL_ASIMDELEM_L:
		case ENC_SQDMLAL_ASISDDIFF_ONLY:
		case ENC_SQDMLAL_ASIMDDIFF_L:
			return ARM64_SQDMLAL;
		//case ENC_SQDMLAL_ASIMDELEM_L:
		//case ENC_SQDMLAL_ASIMDDIFF_L:
		//	return ARM64_SQDMLAL2;
		case ENC_SQDMLSL_ASISDELEM_L:
		case ENC_SQDMLSL_ASIMDELEM_L:
		case ENC_SQDMLSL_ASISDDIFF_ONLY:
		case ENC_SQDMLSL_ASIMDDIFF_L:
			return ARM64_SQDMLSL;
		//case ENC_SQDMLSL_ASIMDELEM_L:
		//case ENC_SQDMLSL_ASIMDDIFF_L:
		//	return ARM64_SQDMLSL2;
		case ENC_SQDMULH_ASISDELEM_R:
		case ENC_SQDMULH_ASIMDELEM_R:
		case ENC_SQDMULH_ASISDSAME_ONLY:
		case ENC_SQDMULH_ASIMDSAME_ONLY:
			return ARM64_SQDMULH;
		case ENC_SQDMULL_ASISDELEM_L:
		case ENC_SQDMULL_ASIMDELEM_L:
		case ENC_SQDMULL_ASISDDIFF_ONLY:
		case ENC_SQDMULL_ASIMDDIFF_L:
			return ARM64_SQDMULL;
		//case ENC_SQDMULL_ASIMDELEM_L:
		//case ENC_SQDMULL_ASIMDDIFF_L:
		//	return ARM64_SQDMULL2;
		case ENC_SQINCB_R_RS_SX:
		case ENC_SQINCB_R_RS_X:
			return ARM64_SQINCB;
		case ENC_SQINCD_R_RS_SX:
		case ENC_SQINCD_R_RS_X:
		case ENC_SQINCD_Z_ZS_:
			return ARM64_SQINCD;
		case ENC_SQINCH_R_RS_SX:
		case ENC_SQINCH_R_RS_X:
		case ENC_SQINCH_Z_ZS_:
			return ARM64_SQINCH;
		case ENC_SQINCP_R_P_R_SX:
		case ENC_SQINCP_R_P_R_X:
		case ENC_SQINCP_Z_P_Z_:
			return ARM64_SQINCP;
		case ENC_SQINCW_R_RS_SX:
		case ENC_SQINCW_R_RS_X:
		case ENC_SQINCW_Z_ZS_:
			return ARM64_SQINCW;
		case ENC_SQNEG_ASISDMISC_R:
		case ENC_SQNEG_ASIMDMISC_R:
			return ARM64_SQNEG;
		case ENC_SQRDMLAH_ASISDELEM_R:
		case ENC_SQRDMLAH_ASIMDELEM_R:
		case ENC_SQRDMLAH_ASISDSAME2_ONLY:
		case ENC_SQRDMLAH_ASIMDSAME2_ONLY:
			return ARM64_SQRDMLAH;
		case ENC_SQRDMLSH_ASISDELEM_R:
		case ENC_SQRDMLSH_ASIMDELEM_R:
		case ENC_SQRDMLSH_ASISDSAME2_ONLY:
		case ENC_SQRDMLSH_ASIMDSAME2_ONLY:
			return ARM64_SQRDMLSH;
		case ENC_SQRDMULH_ASISDELEM_R:
		case ENC_SQRDMULH_ASIMDELEM_R:
		case ENC_SQRDMULH_ASISDSAME_ONLY:
		case ENC_SQRDMULH_ASIMDSAME_ONLY:
			return ARM64_SQRDMULH;
		case ENC_SQRSHL_ASISDSAME_ONLY:
		case ENC_SQRSHL_ASIMDSAME_ONLY:
			return ARM64_SQRSHL;
		case ENC_SQRSHRN_ASISDSHF_N:
		case ENC_SQRSHRN_ASIMDSHF_N:
			return ARM64_SQRSHRN;
		//case ENC_SQRSHRN_ASIMDSHF_N:
		//	return ARM64_SQRSHRN2;
		case ENC_SQRSHRUN_ASISDSHF_N:
		case ENC_SQRSHRUN_ASIMDSHF_N:
			return ARM64_SQRSHRUN;
		//case ENC_SQRSHRUN_ASIMDSHF_N:
		//	return ARM64_SQRSHRUN2;
		case ENC_SQSHL_ASISDSHF_R:
		case ENC_SQSHL_ASIMDSHF_R:
		case ENC_SQSHL_ASISDSAME_ONLY:
		case ENC_SQSHL_ASIMDSAME_ONLY:
			return ARM64_SQSHL;
		case ENC_SQSHLU_ASISDSHF_R:
		case ENC_SQSHLU_ASIMDSHF_R:
			return ARM64_SQSHLU;
		case ENC_SQSHRN_ASISDSHF_N:
		case ENC_SQSHRN_ASIMDSHF_N:
			return ARM64_SQSHRN;
		//case ENC_SQSHRN_ASIMDSHF_N:
		//	return ARM64_SQSHRN2;
		case ENC_SQSHRUN_ASISDSHF_N:
		case ENC_SQSHRUN_ASIMDSHF_N:
			return ARM64_SQSHRUN;
		//case ENC_SQSHRUN_ASIMDSHF_N:
		//	return ARM64_SQSHRUN2;
		case ENC_SQSUB_ASISDSAME_ONLY:
		case ENC_SQSUB_ASIMDSAME_ONLY:
		case ENC_SQSUB_Z_ZI_:
		case ENC_SQSUB_Z_ZZ_:
			return ARM64_SQSUB;
		case ENC_SQXTN_ASISDMISC_N:
		case ENC_SQXTN_ASIMDMISC_N:
			return ARM64_SQXTN;
		//case ENC_SQXTN_ASIMDMISC_N:
		//	return ARM64_SQXTN2;
		case ENC_SQXTUN_ASISDMISC_N:
		case ENC_SQXTUN_ASIMDMISC_N:
			return ARM64_SQXTUN;
		//case ENC_SQXTUN_ASIMDMISC_N:
		//	return ARM64_SQXTUN2;
		case ENC_SRHADD_ASIMDSAME_ONLY:
			return ARM64_SRHADD;
		case ENC_SRI_ASISDSHF_R:
		case ENC_SRI_ASIMDSHF_R:
			return ARM64_SRI;
		case ENC_SRSHL_ASISDSAME_ONLY:
		case ENC_SRSHL_ASIMDSAME_ONLY:
			return ARM64_SRSHL;
		case ENC_SRSHR_ASISDSHF_R:
		case ENC_SRSHR_ASIMDSHF_R:
			return ARM64_SRSHR;
		case ENC_SRSRA_ASISDSHF_R:
		case ENC_SRSRA_ASIMDSHF_R:
			return ARM64_SRSRA;
		case ENC_SSBB_ONLY_BARRIERS:
			return ARM64_SSBB;
		case ENC_SSHL_ASISDSAME_ONLY:
		case ENC_SSHL_ASIMDSAME_ONLY:
			return ARM64_SSHL;
		case ENC_SSHLL_ASIMDSHF_L:
			return ARM64_SSHLL;
		//case ENC_SSHLL_ASIMDSHF_L:
		//	return ARM64_SSHLL2;
		case ENC_SSHR_ASISDSHF_R:
		case ENC_SSHR_ASIMDSHF_R:
			return ARM64_SSHR;
		case ENC_SSRA_ASISDSHF_R:
		case ENC_SSRA_ASIMDSHF_R:
			return ARM64_SSRA;
		case ENC_SSUBL_ASIMDDIFF_L:
			return ARM64_SSUBL;
		//case ENC_SSUBL_ASIMDDIFF_L:
		//	return ARM64_SSUBL2;
		case ENC_SSUBW_ASIMDDIFF_W:
			return ARM64_SSUBW;
		//case ENC_SSUBW_ASIMDDIFF_W:
		//	return ARM64_SSUBW2;
		case ENC_ST1_ASISDLSE_R1_1V:
		case ENC_ST1_ASISDLSE_R2_2V:
		case ENC_ST1_ASISDLSE_R3_3V:
		case ENC_ST1_ASISDLSE_R4_4V:
		case ENC_ST1_ASISDLSEP_I1_I1:
		case ENC_ST1_ASISDLSEP_R1_R1:
		case ENC_ST1_ASISDLSEP_I2_I2:
		case ENC_ST1_ASISDLSEP_R2_R2:
		case ENC_ST1_ASISDLSEP_I3_I3:
		case ENC_ST1_ASISDLSEP_R3_R3:
		case ENC_ST1_ASISDLSEP_I4_I4:
		case ENC_ST1_ASISDLSEP_R4_R4:
		case ENC_ST1_ASISDLSO_B1_1B:
		case ENC_ST1_ASISDLSO_H1_1H:
		case ENC_ST1_ASISDLSO_S1_1S:
		case ENC_ST1_ASISDLSO_D1_1D:
		case ENC_ST1_ASISDLSOP_B1_I1B:
		case ENC_ST1_ASISDLSOP_BX1_R1B:
		case ENC_ST1_ASISDLSOP_H1_I1H:
		case ENC_ST1_ASISDLSOP_HX1_R1H:
		case ENC_ST1_ASISDLSOP_S1_I1S:
		case ENC_ST1_ASISDLSOP_SX1_R1S:
		case ENC_ST1_ASISDLSOP_D1_I1D:
		case ENC_ST1_ASISDLSOP_DX1_R1D:
			return ARM64_ST1;
		case ENC_ST1B_Z_P_AI_S:
		case ENC_ST1B_Z_P_AI_D:
		case ENC_ST1B_Z_P_BI_:
		case ENC_ST1B_Z_P_BR_:
		case ENC_ST1B_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1B_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1B_Z_P_BZ_D_64_UNSCALED:
			return ARM64_ST1B;
		case ENC_ST1D_Z_P_AI_D:
		case ENC_ST1D_Z_P_BI_:
		case ENC_ST1D_Z_P_BR_:
		case ENC_ST1D_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1D_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1D_Z_P_BZ_D_64_SCALED:
		case ENC_ST1D_Z_P_BZ_D_64_UNSCALED:
			return ARM64_ST1D;
		case ENC_ST1H_Z_P_AI_S:
		case ENC_ST1H_Z_P_AI_D:
		case ENC_ST1H_Z_P_BI_:
		case ENC_ST1H_Z_P_BR_:
		case ENC_ST1H_Z_P_BZ_S_X32_SCALED:
		case ENC_ST1H_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1H_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1H_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1H_Z_P_BZ_D_64_SCALED:
		case ENC_ST1H_Z_P_BZ_D_64_UNSCALED:
			return ARM64_ST1H;
		case ENC_ST1W_Z_P_AI_S:
		case ENC_ST1W_Z_P_AI_D:
		case ENC_ST1W_Z_P_BI_:
		case ENC_ST1W_Z_P_BR_:
		case ENC_ST1W_Z_P_BZ_S_X32_SCALED:
		case ENC_ST1W_Z_P_BZ_D_X32_SCALED:
		case ENC_ST1W_Z_P_BZ_D_X32_UNSCALED:
		case ENC_ST1W_Z_P_BZ_S_X32_UNSCALED:
		case ENC_ST1W_Z_P_BZ_D_64_SCALED:
		case ENC_ST1W_Z_P_BZ_D_64_UNSCALED:
			return ARM64_ST1W;
		case ENC_ST2_ASISDLSE_R2:
		case ENC_ST2_ASISDLSEP_I2_I:
		case ENC_ST2_ASISDLSEP_R2_R:
		case ENC_ST2_ASISDLSO_B2_2B:
		case ENC_ST2_ASISDLSO_H2_2H:
		case ENC_ST2_ASISDLSO_S2_2S:
		case ENC_ST2_ASISDLSO_D2_2D:
		case ENC_ST2_ASISDLSOP_B2_I2B:
		case ENC_ST2_ASISDLSOP_BX2_R2B:
		case ENC_ST2_ASISDLSOP_H2_I2H:
		case ENC_ST2_ASISDLSOP_HX2_R2H:
		case ENC_ST2_ASISDLSOP_S2_I2S:
		case ENC_ST2_ASISDLSOP_SX2_R2S:
		case ENC_ST2_ASISDLSOP_D2_I2D:
		case ENC_ST2_ASISDLSOP_DX2_R2D:
			return ARM64_ST2;
		case ENC_ST2B_Z_P_BI_CONTIGUOUS:
		case ENC_ST2B_Z_P_BR_CONTIGUOUS:
			return ARM64_ST2B;
		case ENC_ST2D_Z_P_BI_CONTIGUOUS:
		case ENC_ST2D_Z_P_BR_CONTIGUOUS:
			return ARM64_ST2D;
		case ENC_ST2G_64SPOST_LDSTTAGS:
		case ENC_ST2G_64SPRE_LDSTTAGS:
		case ENC_ST2G_64SOFFSET_LDSTTAGS:
			return ARM64_ST2G;
		case ENC_ST2H_Z_P_BI_CONTIGUOUS:
		case ENC_ST2H_Z_P_BR_CONTIGUOUS:
			return ARM64_ST2H;
		case ENC_ST2W_Z_P_BI_CONTIGUOUS:
		case ENC_ST2W_Z_P_BR_CONTIGUOUS:
			return ARM64_ST2W;
		case ENC_ST3_ASISDLSE_R3:
		case ENC_ST3_ASISDLSEP_I3_I:
		case ENC_ST3_ASISDLSEP_R3_R:
		case ENC_ST3_ASISDLSO_B3_3B:
		case ENC_ST3_ASISDLSO_H3_3H:
		case ENC_ST3_ASISDLSO_S3_3S:
		case ENC_ST3_ASISDLSO_D3_3D:
		case ENC_ST3_ASISDLSOP_B3_I3B:
		case ENC_ST3_ASISDLSOP_BX3_R3B:
		case ENC_ST3_ASISDLSOP_H3_I3H:
		case ENC_ST3_ASISDLSOP_HX3_R3H:
		case ENC_ST3_ASISDLSOP_S3_I3S:
		case ENC_ST3_ASISDLSOP_SX3_R3S:
		case ENC_ST3_ASISDLSOP_D3_I3D:
		case ENC_ST3_ASISDLSOP_DX3_R3D:
			return ARM64_ST3;
		case ENC_ST3B_Z_P_BI_CONTIGUOUS:
		case ENC_ST3B_Z_P_BR_CONTIGUOUS:
			return ARM64_ST3B;
		case ENC_ST3D_Z_P_BI_CONTIGUOUS:
		case ENC_ST3D_Z_P_BR_CONTIGUOUS:
			return ARM64_ST3D;
		case ENC_ST3H_Z_P_BI_CONTIGUOUS:
		case ENC_ST3H_Z_P_BR_CONTIGUOUS:
			return ARM64_ST3H;
		case ENC_ST3W_Z_P_BI_CONTIGUOUS:
		case ENC_ST3W_Z_P_BR_CONTIGUOUS:
			return ARM64_ST3W;
		case ENC_ST4_ASISDLSE_R4:
		case ENC_ST4_ASISDLSEP_I4_I:
		case ENC_ST4_ASISDLSEP_R4_R:
		case ENC_ST4_ASISDLSO_B4_4B:
		case ENC_ST4_ASISDLSO_H4_4H:
		case ENC_ST4_ASISDLSO_S4_4S:
		case ENC_ST4_ASISDLSO_D4_4D:
		case ENC_ST4_ASISDLSOP_B4_I4B:
		case ENC_ST4_ASISDLSOP_BX4_R4B:
		case ENC_ST4_ASISDLSOP_H4_I4H:
		case ENC_ST4_ASISDLSOP_HX4_R4H:
		case ENC_ST4_ASISDLSOP_S4_I4S:
		case ENC_ST4_ASISDLSOP_SX4_R4S:
		case ENC_ST4_ASISDLSOP_D4_I4D:
		case ENC_ST4_ASISDLSOP_DX4_R4D:
			return ARM64_ST4;
		case ENC_ST4B_Z_P_BI_CONTIGUOUS:
		case ENC_ST4B_Z_P_BR_CONTIGUOUS:
			return ARM64_ST4B;
		case ENC_ST4D_Z_P_BI_CONTIGUOUS:
		case ENC_ST4D_Z_P_BR_CONTIGUOUS:
			return ARM64_ST4D;
		case ENC_ST4H_Z_P_BI_CONTIGUOUS:
		case ENC_ST4H_Z_P_BR_CONTIGUOUS:
			return ARM64_ST4H;
		case ENC_ST4W_Z_P_BI_CONTIGUOUS:
		case ENC_ST4W_Z_P_BR_CONTIGUOUS:
			return ARM64_ST4W;
		case ENC_STADD_LDADD_32_MEMOP:
		case ENC_STADD_LDADD_64_MEMOP:
			return ARM64_STADD;
		case ENC_STADDB_LDADDB_32_MEMOP:
			return ARM64_STADDB;
		case ENC_STADDH_LDADDH_32_MEMOP:
			return ARM64_STADDH;
		case ENC_STADDL_LDADDL_32_MEMOP:
		case ENC_STADDL_LDADDL_64_MEMOP:
			return ARM64_STADDL;
		case ENC_STADDLB_LDADDLB_32_MEMOP:
			return ARM64_STADDLB;
		case ENC_STADDLH_LDADDLH_32_MEMOP:
			return ARM64_STADDLH;
		case ENC_STCLR_LDCLR_32_MEMOP:
		case ENC_STCLR_LDCLR_64_MEMOP:
			return ARM64_STCLR;
		case ENC_STCLRB_LDCLRB_32_MEMOP:
			return ARM64_STCLRB;
		case ENC_STCLRH_LDCLRH_32_MEMOP:
			return ARM64_STCLRH;
		case ENC_STCLRL_LDCLRL_32_MEMOP:
		case ENC_STCLRL_LDCLRL_64_MEMOP:
			return ARM64_STCLRL;
		case ENC_STCLRLB_LDCLRLB_32_MEMOP:
			return ARM64_STCLRLB;
		case ENC_STCLRLH_LDCLRLH_32_MEMOP:
			return ARM64_STCLRLH;
		case ENC_STEOR_LDEOR_32_MEMOP:
		case ENC_STEOR_LDEOR_64_MEMOP:
			return ARM64_STEOR;
		case ENC_STEORB_LDEORB_32_MEMOP:
			return ARM64_STEORB;
		case ENC_STEORH_LDEORH_32_MEMOP:
			return ARM64_STEORH;
		case ENC_STEORL_LDEORL_32_MEMOP:
		case ENC_STEORL_LDEORL_64_MEMOP:
			return ARM64_STEORL;
		case ENC_STEORLB_LDEORLB_32_MEMOP:
			return ARM64_STEORLB;
		case ENC_STEORLH_LDEORLH_32_MEMOP:
			return ARM64_STEORLH;
		case ENC_STG_64SPOST_LDSTTAGS:
		case ENC_STG_64SPRE_LDSTTAGS:
		case ENC_STG_64SOFFSET_LDSTTAGS:
			return ARM64_STG;
		case ENC_STGM_64BULK_LDSTTAGS:
			return ARM64_STGM;
		case ENC_STGP_64_LDSTPAIR_POST:
		case ENC_STGP_64_LDSTPAIR_PRE:
		case ENC_STGP_64_LDSTPAIR_OFF:
			return ARM64_STGP;
		case ENC_STLLR_SL32_LDSTEXCL:
		case ENC_STLLR_SL64_LDSTEXCL:
			return ARM64_STLLR;
		case ENC_STLLRB_SL32_LDSTEXCL:
			return ARM64_STLLRB;
		case ENC_STLLRH_SL32_LDSTEXCL:
			return ARM64_STLLRH;
		case ENC_STLR_SL32_LDSTEXCL:
		case ENC_STLR_SL64_LDSTEXCL:
			return ARM64_STLR;
		case ENC_STLRB_SL32_LDSTEXCL:
			return ARM64_STLRB;
		case ENC_STLRH_SL32_LDSTEXCL:
			return ARM64_STLRH;
		case ENC_STLUR_32_LDAPSTL_UNSCALED:
		case ENC_STLUR_64_LDAPSTL_UNSCALED:
			return ARM64_STLUR;
		case ENC_STLURB_32_LDAPSTL_UNSCALED:
			return ARM64_STLURB;
		case ENC_STLURH_32_LDAPSTL_UNSCALED:
			return ARM64_STLURH;
		case ENC_STLXP_SP32_LDSTEXCL:
		case ENC_STLXP_SP64_LDSTEXCL:
			return ARM64_STLXP;
		case ENC_STLXR_SR32_LDSTEXCL:
		case ENC_STLXR_SR64_LDSTEXCL:
			return ARM64_STLXR;
		case ENC_STLXRB_SR32_LDSTEXCL:
			return ARM64_STLXRB;
		case ENC_STLXRH_SR32_LDSTEXCL:
			return ARM64_STLXRH;
		case ENC_STNP_S_LDSTNAPAIR_OFFS:
		case ENC_STNP_D_LDSTNAPAIR_OFFS:
		case ENC_STNP_Q_LDSTNAPAIR_OFFS:
		case ENC_STNP_32_LDSTNAPAIR_OFFS:
		case ENC_STNP_64_LDSTNAPAIR_OFFS:
			return ARM64_STNP;
		case ENC_STNT1B_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1B_Z_P_BR_CONTIGUOUS:
			return ARM64_STNT1B;
		case ENC_STNT1D_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1D_Z_P_BR_CONTIGUOUS:
			return ARM64_STNT1D;
		case ENC_STNT1H_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1H_Z_P_BR_CONTIGUOUS:
			return ARM64_STNT1H;
		case ENC_STNT1W_Z_P_BI_CONTIGUOUS:
		case ENC_STNT1W_Z_P_BR_CONTIGUOUS:
			return ARM64_STNT1W;
		case ENC_STP_S_LDSTPAIR_POST:
		case ENC_STP_D_LDSTPAIR_POST:
		case ENC_STP_Q_LDSTPAIR_POST:
		case ENC_STP_S_LDSTPAIR_PRE:
		case ENC_STP_D_LDSTPAIR_PRE:
		case ENC_STP_Q_LDSTPAIR_PRE:
		case ENC_STP_S_LDSTPAIR_OFF:
		case ENC_STP_D_LDSTPAIR_OFF:
		case ENC_STP_Q_LDSTPAIR_OFF:
		case ENC_STP_32_LDSTPAIR_POST:
		case ENC_STP_64_LDSTPAIR_POST:
		case ENC_STP_32_LDSTPAIR_PRE:
		case ENC_STP_64_LDSTPAIR_PRE:
		case ENC_STP_32_LDSTPAIR_OFF:
		case ENC_STP_64_LDSTPAIR_OFF:
			return ARM64_STP;
		case ENC_STR_B_LDST_IMMPOST:
		case ENC_STR_H_LDST_IMMPOST:
		case ENC_STR_S_LDST_IMMPOST:
		case ENC_STR_D_LDST_IMMPOST:
		case ENC_STR_Q_LDST_IMMPOST:
		case ENC_STR_B_LDST_IMMPRE:
		case ENC_STR_H_LDST_IMMPRE:
		case ENC_STR_S_LDST_IMMPRE:
		case ENC_STR_D_LDST_IMMPRE:
		case ENC_STR_Q_LDST_IMMPRE:
		case ENC_STR_B_LDST_POS:
		case ENC_STR_H_LDST_POS:
		case ENC_STR_S_LDST_POS:
		case ENC_STR_D_LDST_POS:
		case ENC_STR_Q_LDST_POS:
		case ENC_STR_32_LDST_IMMPOST:
		case ENC_STR_64_LDST_IMMPOST:
		case ENC_STR_32_LDST_IMMPRE:
		case ENC_STR_64_LDST_IMMPRE:
		case ENC_STR_32_LDST_POS:
		case ENC_STR_64_LDST_POS:
		case ENC_STR_B_LDST_REGOFF:
		case ENC_STR_BL_LDST_REGOFF:
		case ENC_STR_H_LDST_REGOFF:
		case ENC_STR_S_LDST_REGOFF:
		case ENC_STR_D_LDST_REGOFF:
		case ENC_STR_Q_LDST_REGOFF:
		case ENC_STR_32_LDST_REGOFF:
		case ENC_STR_64_LDST_REGOFF:
		case ENC_STR_P_BI_:
		case ENC_STR_Z_BI_:
			return ARM64_STR;
		case ENC_STRB_32_LDST_IMMPOST:
		case ENC_STRB_32_LDST_IMMPRE:
		case ENC_STRB_32_LDST_POS:
		case ENC_STRB_32B_LDST_REGOFF:
		case ENC_STRB_32BL_LDST_REGOFF:
			return ARM64_STRB;
		case ENC_STRH_32_LDST_IMMPOST:
		case ENC_STRH_32_LDST_IMMPRE:
		case ENC_STRH_32_LDST_POS:
		case ENC_STRH_32_LDST_REGOFF:
			return ARM64_STRH;
		case ENC_STSET_LDSET_32_MEMOP:
		case ENC_STSET_LDSET_64_MEMOP:
			return ARM64_STSET;
		case ENC_STSETB_LDSETB_32_MEMOP:
			return ARM64_STSETB;
		case ENC_STSETH_LDSETH_32_MEMOP:
			return ARM64_STSETH;
		case ENC_STSETL_LDSETL_32_MEMOP:
		case ENC_STSETL_LDSETL_64_MEMOP:
			return ARM64_STSETL;
		case ENC_STSETLB_LDSETLB_32_MEMOP:
			return ARM64_STSETLB;
		case ENC_STSETLH_LDSETLH_32_MEMOP:
			return ARM64_STSETLH;
		case ENC_STSMAX_LDSMAX_32_MEMOP:
		case ENC_STSMAX_LDSMAX_64_MEMOP:
			return ARM64_STSMAX;
		case ENC_STSMAXB_LDSMAXB_32_MEMOP:
			return ARM64_STSMAXB;
		case ENC_STSMAXH_LDSMAXH_32_MEMOP:
			return ARM64_STSMAXH;
		case ENC_STSMAXL_LDSMAXL_32_MEMOP:
		case ENC_STSMAXL_LDSMAXL_64_MEMOP:
			return ARM64_STSMAXL;
		case ENC_STSMAXLB_LDSMAXLB_32_MEMOP:
			return ARM64_STSMAXLB;
		case ENC_STSMAXLH_LDSMAXLH_32_MEMOP:
			return ARM64_STSMAXLH;
		case ENC_STSMIN_LDSMIN_32_MEMOP:
		case ENC_STSMIN_LDSMIN_64_MEMOP:
			return ARM64_STSMIN;
		case ENC_STSMINB_LDSMINB_32_MEMOP:
			return ARM64_STSMINB;
		case ENC_STSMINH_LDSMINH_32_MEMOP:
			return ARM64_STSMINH;
		case ENC_STSMINL_LDSMINL_32_MEMOP:
		case ENC_STSMINL_LDSMINL_64_MEMOP:
			return ARM64_STSMINL;
		case ENC_STSMINLB_LDSMINLB_32_MEMOP:
			return ARM64_STSMINLB;
		case ENC_STSMINLH_LDSMINLH_32_MEMOP:
			return ARM64_STSMINLH;
		case ENC_STTR_32_LDST_UNPRIV:
		case ENC_STTR_64_LDST_UNPRIV:
			return ARM64_STTR;
		case ENC_STTRB_32_LDST_UNPRIV:
			return ARM64_STTRB;
		case ENC_STTRH_32_LDST_UNPRIV:
			return ARM64_STTRH;
		case ENC_STUMAX_LDUMAX_32_MEMOP:
		case ENC_STUMAX_LDUMAX_64_MEMOP:
			return ARM64_STUMAX;
		case ENC_STUMAXB_LDUMAXB_32_MEMOP:
			return ARM64_STUMAXB;
		case ENC_STUMAXH_LDUMAXH_32_MEMOP:
			return ARM64_STUMAXH;
		case ENC_STUMAXL_LDUMAXL_32_MEMOP:
		case ENC_STUMAXL_LDUMAXL_64_MEMOP:
			return ARM64_STUMAXL;
		case ENC_STUMAXLB_LDUMAXLB_32_MEMOP:
			return ARM64_STUMAXLB;
		case ENC_STUMAXLH_LDUMAXLH_32_MEMOP:
			return ARM64_STUMAXLH;
		case ENC_STUMIN_LDUMIN_32_MEMOP:
		case ENC_STUMIN_LDUMIN_64_MEMOP:
			return ARM64_STUMIN;
		case ENC_STUMINB_LDUMINB_32_MEMOP:
			return ARM64_STUMINB;
		case ENC_STUMINH_LDUMINH_32_MEMOP:
			return ARM64_STUMINH;
		case ENC_STUMINL_LDUMINL_32_MEMOP:
		case ENC_STUMINL_LDUMINL_64_MEMOP:
			return ARM64_STUMINL;
		case ENC_STUMINLB_LDUMINLB_32_MEMOP:
			return ARM64_STUMINLB;
		case ENC_STUMINLH_LDUMINLH_32_MEMOP:
			return ARM64_STUMINLH;
		case ENC_STUR_B_LDST_UNSCALED:
		case ENC_STUR_H_LDST_UNSCALED:
		case ENC_STUR_S_LDST_UNSCALED:
		case ENC_STUR_D_LDST_UNSCALED:
		case ENC_STUR_Q_LDST_UNSCALED:
		case ENC_STUR_32_LDST_UNSCALED:
		case ENC_STUR_64_LDST_UNSCALED:
			return ARM64_STUR;
		case ENC_STURB_32_LDST_UNSCALED:
			return ARM64_STURB;
		case ENC_STURH_32_LDST_UNSCALED:
			return ARM64_STURH;
		case ENC_STXP_SP32_LDSTEXCL:
		case ENC_STXP_SP64_LDSTEXCL:
			return ARM64_STXP;
		case ENC_STXR_SR32_LDSTEXCL:
		case ENC_STXR_SR64_LDSTEXCL:
			return ARM64_STXR;
		case ENC_STXRB_SR32_LDSTEXCL:
			return ARM64_STXRB;
		case ENC_STXRH_SR32_LDSTEXCL:
			return ARM64_STXRH;
		case ENC_STZ2G_64SPOST_LDSTTAGS:
		case ENC_STZ2G_64SPRE_LDSTTAGS:
		case ENC_STZ2G_64SOFFSET_LDSTTAGS:
			return ARM64_STZ2G;
		case ENC_STZG_64SPOST_LDSTTAGS:
		case ENC_STZG_64SPRE_LDSTTAGS:
		case ENC_STZG_64SOFFSET_LDSTTAGS:
			return ARM64_STZG;
		case ENC_STZGM_64BULK_LDSTTAGS:
			return ARM64_STZGM;
		case ENC_SUB_32_ADDSUB_EXT:
		case ENC_SUB_64_ADDSUB_EXT:
		case ENC_SUB_32_ADDSUB_IMM:
		case ENC_SUB_64_ADDSUB_IMM:
		case ENC_SUB_32_ADDSUB_SHIFT:
		case ENC_SUB_64_ADDSUB_SHIFT:
		case ENC_SUB_ASISDSAME_ONLY:
		case ENC_SUB_ASIMDSAME_ONLY:
		case ENC_SUB_Z_P_ZZ_:
		case ENC_SUB_Z_ZI_:
		case ENC_SUB_Z_ZZ_:
			return ARM64_SUB;
		case ENC_SUBG_64_ADDSUB_IMMTAGS:
			return ARM64_SUBG;
		case ENC_SUBHN_ASIMDDIFF_N:
			return ARM64_SUBHN;
		//case ENC_SUBHN_ASIMDDIFF_N:
		//	return ARM64_SUBHN2;
		case ENC_SUBP_64S_DP_2SRC:
			return ARM64_SUBP;
		case ENC_SUBPS_64S_DP_2SRC:
			return ARM64_SUBPS;
		case ENC_SUBR_Z_P_ZZ_:
		case ENC_SUBR_Z_ZI_:
			return ARM64_SUBR;
		case ENC_SUBS_32S_ADDSUB_EXT:
		case ENC_SUBS_64S_ADDSUB_EXT:
		case ENC_SUBS_32S_ADDSUB_IMM:
		case ENC_SUBS_64S_ADDSUB_IMM:
		case ENC_SUBS_32_ADDSUB_SHIFT:
		case ENC_SUBS_64_ADDSUB_SHIFT:
			return ARM64_SUBS;
		case ENC_SUDOT_ASIMDELEM_D:
		case ENC_SUDOT_Z_ZZZI_S:
			return ARM64_SUDOT;
		case ENC_SUNPKHI_Z_Z_:
			return ARM64_SUNPKHI;
		case ENC_SUNPKLO_Z_Z_:
			return ARM64_SUNPKLO;
		case ENC_SUQADD_ASISDMISC_R:
		case ENC_SUQADD_ASIMDMISC_R:
			return ARM64_SUQADD;
		case ENC_SVC_EX_EXCEPTION:
			return ARM64_SVC;
		case ENC_SWP_32_MEMOP:
		case ENC_SWP_64_MEMOP:
			return ARM64_SWP;
		case ENC_SWPA_32_MEMOP:
		case ENC_SWPA_64_MEMOP:
			return ARM64_SWPA;
		case ENC_SWPAB_32_MEMOP:
			return ARM64_SWPAB;
		case ENC_SWPAH_32_MEMOP:
			return ARM64_SWPAH;
		case ENC_SWPAL_32_MEMOP:
		case ENC_SWPAL_64_MEMOP:
			return ARM64_SWPAL;
		case ENC_SWPALB_32_MEMOP:
			return ARM64_SWPALB;
		case ENC_SWPALH_32_MEMOP:
			return ARM64_SWPALH;
		case ENC_SWPB_32_MEMOP:
			return ARM64_SWPB;
		case ENC_SWPH_32_MEMOP:
			return ARM64_SWPH;
		case ENC_SWPL_32_MEMOP:
		case ENC_SWPL_64_MEMOP:
			return ARM64_SWPL;
		case ENC_SWPLB_32_MEMOP:
			return ARM64_SWPLB;
		case ENC_SWPLH_32_MEMOP:
			return ARM64_SWPLH;
		case ENC_SXTB_SBFM_32M_BITFIELD:
		case ENC_SXTB_SBFM_64M_BITFIELD:
		case ENC_SXTB_Z_P_Z_:
			return ARM64_SXTB;
		case ENC_SXTH_SBFM_32M_BITFIELD:
		case ENC_SXTH_SBFM_64M_BITFIELD:
		case ENC_SXTH_Z_P_Z_:
			return ARM64_SXTH;
		case ENC_SXTL_SSHLL_ASIMDSHF_L:
			return ARM64_SXTL;
		//case ENC_SXTL_SSHLL_ASIMDSHF_L:
		//	return ARM64_SXTL2;
		case ENC_SXTW_SBFM_64M_BITFIELD:
		case ENC_SXTW_Z_P_Z_:
			return ARM64_SXTW;
		case ENC_SYS_CR_SYSTEMINSTRS:
			return ARM64_SYS;
		case ENC_SYSL_RC_SYSTEMINSTRS:
			return ARM64_SYSL;
		case ENC_TBL_ASIMDTBL_L2_2:
		case ENC_TBL_ASIMDTBL_L3_3:
		case ENC_TBL_ASIMDTBL_L4_4:
		case ENC_TBL_ASIMDTBL_L1_1:
		case ENC_TBL_Z_ZZ_1:
			return ARM64_TBL;
		case ENC_TBNZ_ONLY_TESTBRANCH:
			return ARM64_TBNZ;
		case ENC_TBX_ASIMDTBL_L2_2:
		case ENC_TBX_ASIMDTBL_L3_3:
		case ENC_TBX_ASIMDTBL_L4_4:
		case ENC_TBX_ASIMDTBL_L1_1:
			return ARM64_TBX;
		case ENC_TBZ_ONLY_TESTBRANCH:
			return ARM64_TBZ;
		case ENC_TLBI_SYS_CR_SYSTEMINSTRS:
			return ARM64_TLBI;
		case ENC_TRN1_ASIMDPERM_ONLY:
		case ENC_TRN1_P_PP_:
		case ENC_TRN1_Z_ZZ_:
		case ENC_TRN1_Z_ZZ_Q:
			return ARM64_TRN1;
		case ENC_TRN2_ASIMDPERM_ONLY:
		case ENC_TRN2_P_PP_:
		case ENC_TRN2_Z_ZZ_:
		case ENC_TRN2_Z_ZZ_Q:
			return ARM64_TRN2;
		case ENC_TSB_HC_HINTS:
			return ARM64_TSB;
		case ENC_TST_ANDS_32S_LOG_IMM:
		case ENC_TST_ANDS_64S_LOG_IMM:
		case ENC_TST_ANDS_32_LOG_SHIFT:
		case ENC_TST_ANDS_64_LOG_SHIFT:
			return ARM64_TST;
		case ENC_UABA_ASIMDSAME_ONLY:
			return ARM64_UABA;
		case ENC_UABAL_ASIMDDIFF_L:
			return ARM64_UABAL;
		//case ENC_UABAL_ASIMDDIFF_L:
		//	return ARM64_UABAL2;
		case ENC_UABD_ASIMDSAME_ONLY:
		case ENC_UABD_Z_P_ZZ_:
			return ARM64_UABD;
		case ENC_UABDL_ASIMDDIFF_L:
			return ARM64_UABDL;
		//case ENC_UABDL_ASIMDDIFF_L:
		//	return ARM64_UABDL2;
		case ENC_UADALP_ASIMDMISC_P:
			return ARM64_UADALP;
		case ENC_UADDL_ASIMDDIFF_L:
			return ARM64_UADDL;
		//case ENC_UADDL_ASIMDDIFF_L:
		//	return ARM64_UADDL2;
		case ENC_UADDLP_ASIMDMISC_P:
			return ARM64_UADDLP;
		case ENC_UADDLV_ASIMDALL_ONLY:
			return ARM64_UADDLV;
		case ENC_UADDV_R_P_Z_:
			return ARM64_UADDV;
		case ENC_UADDW_ASIMDDIFF_W:
			return ARM64_UADDW;
		//case ENC_UADDW_ASIMDDIFF_W:
		//	return ARM64_UADDW2;
		case ENC_UBFIZ_UBFM_32M_BITFIELD:
		case ENC_UBFIZ_UBFM_64M_BITFIELD:
			return ARM64_UBFIZ;
		case ENC_UBFM_32M_BITFIELD:
		case ENC_UBFM_64M_BITFIELD:
			return ARM64_UBFM;
		case ENC_UBFX_UBFM_32M_BITFIELD:
		case ENC_UBFX_UBFM_64M_BITFIELD:
			return ARM64_UBFX;
		case ENC_UCVTF_ASISDSHF_C:
		case ENC_UCVTF_ASIMDSHF_C:
		case ENC_UCVTF_ASISDMISCFP16_R:
		case ENC_UCVTF_ASISDMISC_R:
		case ENC_UCVTF_ASIMDMISCFP16_R:
		case ENC_UCVTF_ASIMDMISC_R:
		case ENC_UCVTF_H32_FLOAT2FIX:
		case ENC_UCVTF_S32_FLOAT2FIX:
		case ENC_UCVTF_D32_FLOAT2FIX:
		case ENC_UCVTF_H64_FLOAT2FIX:
		case ENC_UCVTF_S64_FLOAT2FIX:
		case ENC_UCVTF_D64_FLOAT2FIX:
		case ENC_UCVTF_H32_FLOAT2INT:
		case ENC_UCVTF_S32_FLOAT2INT:
		case ENC_UCVTF_D32_FLOAT2INT:
		case ENC_UCVTF_H64_FLOAT2INT:
		case ENC_UCVTF_S64_FLOAT2INT:
		case ENC_UCVTF_D64_FLOAT2INT:
		case ENC_UCVTF_Z_P_Z_H2FP16:
		case ENC_UCVTF_Z_P_Z_W2FP16:
		case ENC_UCVTF_Z_P_Z_W2S:
		case ENC_UCVTF_Z_P_Z_W2D:
		case ENC_UCVTF_Z_P_Z_X2FP16:
		case ENC_UCVTF_Z_P_Z_X2S:
		case ENC_UCVTF_Z_P_Z_X2D:
			return ARM64_UCVTF;
		case ENC_UDF_ONLY_PERM_UNDEF:
			return ARM64_UDF;
		case ENC_UDIV_32_DP_2SRC:
		case ENC_UDIV_64_DP_2SRC:
		case ENC_UDIV_Z_P_ZZ_:
			return ARM64_UDIV;
		case ENC_UDIVR_Z_P_ZZ_:
			return ARM64_UDIVR;
		case ENC_UDOT_ASIMDELEM_D:
		case ENC_UDOT_ASIMDSAME2_D:
		case ENC_UDOT_Z_ZZZ_:
		case ENC_UDOT_Z_ZZZI_S:
		case ENC_UDOT_Z_ZZZI_D:
			return ARM64_UDOT;
		case ENC_UHADD_ASIMDSAME_ONLY:
			return ARM64_UHADD;
		case ENC_UHSUB_ASIMDSAME_ONLY:
			return ARM64_UHSUB;
		case ENC_UMADDL_64WA_DP_3SRC:
			return ARM64_UMADDL;
		case ENC_UMAX_ASIMDSAME_ONLY:
		case ENC_UMAX_Z_P_ZZ_:
		case ENC_UMAX_Z_ZI_:
			return ARM64_UMAX;
		case ENC_UMAXP_ASIMDSAME_ONLY:
			return ARM64_UMAXP;
		case ENC_UMAXV_ASIMDALL_ONLY:
		case ENC_UMAXV_R_P_Z_:
			return ARM64_UMAXV;
		case ENC_UMIN_ASIMDSAME_ONLY:
		case ENC_UMIN_Z_P_ZZ_:
		case ENC_UMIN_Z_ZI_:
			return ARM64_UMIN;
		case ENC_UMINP_ASIMDSAME_ONLY:
			return ARM64_UMINP;
		case ENC_UMINV_ASIMDALL_ONLY:
		case ENC_UMINV_R_P_Z_:
			return ARM64_UMINV;
		case ENC_UMLAL_ASIMDELEM_L:
		case ENC_UMLAL_ASIMDDIFF_L:
			return ARM64_UMLAL;
		//case ENC_UMLAL_ASIMDELEM_L:
		//case ENC_UMLAL_ASIMDDIFF_L:
		//	return ARM64_UMLAL2;
		case ENC_UMLSL_ASIMDELEM_L:
		case ENC_UMLSL_ASIMDDIFF_L:
			return ARM64_UMLSL;
		//case ENC_UMLSL_ASIMDELEM_L:
		//case ENC_UMLSL_ASIMDDIFF_L:
		//	return ARM64_UMLSL2;
		case ENC_UMMLA_ASIMDSAME2_G:
		case ENC_UMMLA_Z_ZZZ_:
			return ARM64_UMMLA;
		case ENC_UMNEGL_UMSUBL_64WA_DP_3SRC:
			return ARM64_UMNEGL;
		case ENC_UMOV_ASIMDINS_W_W:
		case ENC_UMOV_ASIMDINS_X_X:
			return ARM64_UMOV;
		case ENC_UMSUBL_64WA_DP_3SRC:
			return ARM64_UMSUBL;
		case ENC_UMULH_64_DP_3SRC:
		case ENC_UMULH_Z_P_ZZ_:
			return ARM64_UMULH;
		case ENC_UMULL_UMADDL_64WA_DP_3SRC:
		case ENC_UMULL_ASIMDELEM_L:
		case ENC_UMULL_ASIMDDIFF_L:
			return ARM64_UMULL;
		//case ENC_UMULL_ASIMDELEM_L:
		//case ENC_UMULL_ASIMDDIFF_L:
		//	return ARM64_UMULL2;
		case ENC_UQADD_ASISDSAME_ONLY:
		case ENC_UQADD_ASIMDSAME_ONLY:
		case ENC_UQADD_Z_ZI_:
		case ENC_UQADD_Z_ZZ_:
			return ARM64_UQADD;
		case ENC_UQDECB_R_RS_UW:
		case ENC_UQDECB_R_RS_X:
			return ARM64_UQDECB;
		case ENC_UQDECD_R_RS_UW:
		case ENC_UQDECD_R_RS_X:
		case ENC_UQDECD_Z_ZS_:
			return ARM64_UQDECD;
		case ENC_UQDECH_R_RS_UW:
		case ENC_UQDECH_R_RS_X:
		case ENC_UQDECH_Z_ZS_:
			return ARM64_UQDECH;
		case ENC_UQDECP_R_P_R_UW:
		case ENC_UQDECP_R_P_R_X:
		case ENC_UQDECP_Z_P_Z_:
			return ARM64_UQDECP;
		case ENC_UQDECW_R_RS_UW:
		case ENC_UQDECW_R_RS_X:
		case ENC_UQDECW_Z_ZS_:
			return ARM64_UQDECW;
		case ENC_UQINCB_R_RS_UW:
		case ENC_UQINCB_R_RS_X:
			return ARM64_UQINCB;
		case ENC_UQINCD_R_RS_UW:
		case ENC_UQINCD_R_RS_X:
		case ENC_UQINCD_Z_ZS_:
			return ARM64_UQINCD;
		case ENC_UQINCH_R_RS_UW:
		case ENC_UQINCH_R_RS_X:
		case ENC_UQINCH_Z_ZS_:
			return ARM64_UQINCH;
		case ENC_UQINCP_R_P_R_UW:
		case ENC_UQINCP_R_P_R_X:
		case ENC_UQINCP_Z_P_Z_:
			return ARM64_UQINCP;
		case ENC_UQINCW_R_RS_UW:
		case ENC_UQINCW_R_RS_X:
		case ENC_UQINCW_Z_ZS_:
			return ARM64_UQINCW;
		case ENC_UQRSHL_ASISDSAME_ONLY:
		case ENC_UQRSHL_ASIMDSAME_ONLY:
			return ARM64_UQRSHL;
		case ENC_UQRSHRN_ASISDSHF_N:
		case ENC_UQRSHRN_ASIMDSHF_N:
			return ARM64_UQRSHRN;
		//case ENC_UQRSHRN_ASIMDSHF_N:
		//	return ARM64_UQRSHRN2;
		case ENC_UQSHL_ASISDSHF_R:
		case ENC_UQSHL_ASIMDSHF_R:
		case ENC_UQSHL_ASISDSAME_ONLY:
		case ENC_UQSHL_ASIMDSAME_ONLY:
			return ARM64_UQSHL;
		case ENC_UQSHRN_ASISDSHF_N:
		case ENC_UQSHRN_ASIMDSHF_N:
			return ARM64_UQSHRN;
		//case ENC_UQSHRN_ASIMDSHF_N:
		//	return ARM64_UQSHRN2;
		case ENC_UQSUB_ASISDSAME_ONLY:
		case ENC_UQSUB_ASIMDSAME_ONLY:
		case ENC_UQSUB_Z_ZI_:
		case ENC_UQSUB_Z_ZZ_:
			return ARM64_UQSUB;
		case ENC_UQXTN_ASISDMISC_N:
		case ENC_UQXTN_ASIMDMISC_N:
			return ARM64_UQXTN;
		//case ENC_UQXTN_ASIMDMISC_N:
		//	return ARM64_UQXTN2;
		case ENC_URECPE_ASIMDMISC_R:
			return ARM64_URECPE;
		case ENC_URHADD_ASIMDSAME_ONLY:
			return ARM64_URHADD;
		case ENC_URSHL_ASISDSAME_ONLY:
		case ENC_URSHL_ASIMDSAME_ONLY:
			return ARM64_URSHL;
		case ENC_URSHR_ASISDSHF_R:
		case ENC_URSHR_ASIMDSHF_R:
			return ARM64_URSHR;
		case ENC_URSQRTE_ASIMDMISC_R:
			return ARM64_URSQRTE;
		case ENC_URSRA_ASISDSHF_R:
		case ENC_URSRA_ASIMDSHF_R:
			return ARM64_URSRA;
		case ENC_USDOT_ASIMDELEM_D:
		case ENC_USDOT_ASIMDSAME2_D:
		case ENC_USDOT_Z_ZZZ_S:
		case ENC_USDOT_Z_ZZZI_S:
			return ARM64_USDOT;
		case ENC_USHL_ASISDSAME_ONLY:
		case ENC_USHL_ASIMDSAME_ONLY:
			return ARM64_USHL;
		case ENC_USHLL_ASIMDSHF_L:
			return ARM64_USHLL;
		//case ENC_USHLL_ASIMDSHF_L:
		//	return ARM64_USHLL2;
		case ENC_USHR_ASISDSHF_R:
		case ENC_USHR_ASIMDSHF_R:
			return ARM64_USHR;
		case ENC_USMMLA_ASIMDSAME2_G:
		case ENC_USMMLA_Z_ZZZ_:
			return ARM64_USMMLA;
		case ENC_USQADD_ASISDMISC_R:
		case ENC_USQADD_ASIMDMISC_R:
			return ARM64_USQADD;
		case ENC_USRA_ASISDSHF_R:
		case ENC_USRA_ASIMDSHF_R:
			return ARM64_USRA;
		case ENC_USUBL_ASIMDDIFF_L:
			return ARM64_USUBL;
		//case ENC_USUBL_ASIMDDIFF_L:
		//	return ARM64_USUBL2;
		case ENC_USUBW_ASIMDDIFF_W:
			return ARM64_USUBW;
		//case ENC_USUBW_ASIMDDIFF_W:
		//	return ARM64_USUBW2;
		case ENC_UUNPKHI_Z_Z_:
			return ARM64_UUNPKHI;
		case ENC_UUNPKLO_Z_Z_:
			return ARM64_UUNPKLO;
		case ENC_UXTB_UBFM_32M_BITFIELD:
		case ENC_UXTB_Z_P_Z_:
			return ARM64_UXTB;
		case ENC_UXTH_UBFM_32M_BITFIELD:
		case ENC_UXTH_Z_P_Z_:
			return ARM64_UXTH;
		case ENC_UXTL_USHLL_ASIMDSHF_L:
			return ARM64_UXTL;
		//case ENC_UXTL_USHLL_ASIMDSHF_L:
		//	return ARM64_UXTL2;
		case ENC_UXTW_Z_P_Z_:
			return ARM64_UXTW;
		case ENC_UZP1_ASIMDPERM_ONLY:
		case ENC_UZP1_P_PP_:
		case ENC_UZP1_Z_ZZ_:
		case ENC_UZP1_Z_ZZ_Q:
			return ARM64_UZP1;
		case ENC_UZP2_ASIMDPERM_ONLY:
		case ENC_UZP2_P_PP_:
		case ENC_UZP2_Z_ZZ_:
		case ENC_UZP2_Z_ZZ_Q:
			return ARM64_UZP2;
		case ENC_WFE_HI_HINTS:
			return ARM64_WFE;
		case ENC_WFI_HI_HINTS:
			return ARM64_WFI;
		case ENC_WHILELE_P_P_RR_:
			return ARM64_WHILELE;
		case ENC_WHILELO_P_P_RR_:
			return ARM64_WHILELO;
		case ENC_WHILELS_P_P_RR_:
			return ARM64_WHILELS;
		case ENC_WHILELT_P_P_RR_:
			return ARM64_WHILELT;
		case ENC_WRFFR_F_P_:
			return ARM64_WRFFR;
		case ENC_XAFLAG_M_PSTATE:
			return ARM64_XAFLAG;
		case ENC_XAR_VVV2_CRYPTO3_IMM6:
			return ARM64_XAR;
		case ENC_XPACD_64Z_DP_1SRC:
			return ARM64_XPACD;
		case ENC_XPACI_64Z_DP_1SRC:
			return ARM64_XPACI;
		case ENC_XPACLRI_HI_HINTS:
			return ARM64_XPACLRI;
		case ENC_XTN_ASIMDMISC_N:
			return ARM64_XTN;
		//case ENC_XTN_ASIMDMISC_N:
		//	return ARM64_XTN2;
		case ENC_YIELD_HI_HINTS:
			return ARM64_YIELD;
		case ENC_ZIP1_ASIMDPERM_ONLY:
		case ENC_ZIP1_P_PP_:
		case ENC_ZIP1_Z_ZZ_:
		case ENC_ZIP1_Z_ZZ_Q:
			return ARM64_ZIP1;
		case ENC_ZIP2_ASIMDPERM_ONLY:
		case ENC_ZIP2_P_PP_:
		case ENC_ZIP2_Z_ZZ_:
		case ENC_ZIP2_Z_ZZ_Q:
			return ARM64_ZIP2;
		default:
			return ARM64_ERROR;
	}
}

enum Operation enc_to_oper2(enum ENCODING enc)
{
	switch(enc) {
		case ENC_ADDHN_ASIMDDIFF_N:
			return ARM64_ADDHN2;
		case ENC_BFCVTN_ASIMDMISC_4S:
			return ARM64_BFCVTN2;
		case ENC_FCVTL_ASIMDMISC_L:
			return ARM64_FCVTL2;
		case ENC_FCVTN_ASIMDMISC_N:
			return ARM64_FCVTN2;
		case ENC_FCVTXN_ASIMDMISC_N:
			return ARM64_FCVTXN2;
		case ENC_PMULL_ASIMDDIFF_L:
			return ARM64_PMULL2;
		case ENC_RADDHN_ASIMDDIFF_N:
			return ARM64_RADDHN2;
		case ENC_RSHRN_ASIMDSHF_N:
			return ARM64_RSHRN2;
		case ENC_RSUBHN_ASIMDDIFF_N:
			return ARM64_RSUBHN2;
		case ENC_SABAL_ASIMDDIFF_L:
			return ARM64_SABAL2;
		case ENC_SABDL_ASIMDDIFF_L:
			return ARM64_SABDL2;
		case ENC_SADDL_ASIMDDIFF_L:
			return ARM64_SADDL2;
		case ENC_SADDW_ASIMDDIFF_W:
			return ARM64_SADDW2;
		case ENC_SHLL_ASIMDMISC_S:
			return ARM64_SHLL2;
		case ENC_SHRN_ASIMDSHF_N:
			return ARM64_SHRN2;
		case ENC_SMLAL_ASIMDELEM_L:
		case ENC_SMLAL_ASIMDDIFF_L:
			return ARM64_SMLAL2;
		case ENC_SMLSL_ASIMDELEM_L:
		case ENC_SMLSL_ASIMDDIFF_L:
			return ARM64_SMLSL2;
		case ENC_SMULL_ASIMDELEM_L:
		case ENC_SMULL_ASIMDDIFF_L:
			return ARM64_SMULL2;
		case ENC_SQDMLAL_ASIMDELEM_L:
		case ENC_SQDMLAL_ASIMDDIFF_L:
			return ARM64_SQDMLAL2;
		case ENC_SQDMLSL_ASIMDELEM_L:
		case ENC_SQDMLSL_ASIMDDIFF_L:
			return ARM64_SQDMLSL2;
		case ENC_SQDMULL_ASIMDELEM_L:
		case ENC_SQDMULL_ASIMDDIFF_L:
			return ARM64_SQDMULL2;
		case ENC_SQRSHRN_ASIMDSHF_N:
			return ARM64_SQRSHRN2;
		case ENC_SQRSHRUN_ASIMDSHF_N:
			return ARM64_SQRSHRUN2;
		case ENC_SQSHRN_ASIMDSHF_N:
			return ARM64_SQSHRN2;
		case ENC_SQSHRUN_ASIMDSHF_N:
			return ARM64_SQSHRUN2;
		case ENC_SQXTN_ASIMDMISC_N:
			return ARM64_SQXTN2;
		case ENC_SQXTUN_ASIMDMISC_N:
			return ARM64_SQXTUN2;
		case ENC_SSHLL_ASIMDSHF_L:
			return ARM64_SSHLL2;
		case ENC_SSUBL_ASIMDDIFF_L:
			return ARM64_SSUBL2;
		case ENC_SSUBW_ASIMDDIFF_W:
			return ARM64_SSUBW2;
		case ENC_SUBHN_ASIMDDIFF_N:
			return ARM64_SUBHN2;
		case ENC_SXTL_SSHLL_ASIMDSHF_L:
			return ARM64_SXTL2;
		case ENC_UABAL_ASIMDDIFF_L:
			return ARM64_UABAL2;
		case ENC_UABDL_ASIMDDIFF_L:
			return ARM64_UABDL2;
		case ENC_UADDL_ASIMDDIFF_L:
			return ARM64_UADDL2;
		case ENC_UADDW_ASIMDDIFF_W:
			return ARM64_UADDW2;
		case ENC_UMLAL_ASIMDELEM_L:
		case ENC_UMLAL_ASIMDDIFF_L:
			return ARM64_UMLAL2;
		case ENC_UMLSL_ASIMDELEM_L:
		case ENC_UMLSL_ASIMDDIFF_L:
			return ARM64_UMLSL2;
		case ENC_UMULL_ASIMDELEM_L:
		case ENC_UMULL_ASIMDDIFF_L:
			return ARM64_UMULL2;
		case ENC_UQRSHRN_ASIMDSHF_N:
			return ARM64_UQRSHRN2;
		case ENC_UQSHRN_ASIMDSHF_N:
			return ARM64_UQSHRN2;
		case ENC_UQXTN_ASIMDMISC_N:
			return ARM64_UQXTN2;
		case ENC_USHLL_ASIMDSHF_L:
			return ARM64_USHLL2;
		case ENC_USUBL_ASIMDDIFF_L:
			return ARM64_USUBL2;
		case ENC_USUBW_ASIMDDIFF_W:
			return ARM64_USUBW2;
		case ENC_UXTL_USHLL_ASIMDSHF_L:
			return ARM64_UXTL2;
		case ENC_XTN_ASIMDMISC_N:
			return ARM64_XTN2;
		default:
			return ARM64_ERROR;
	}
}
