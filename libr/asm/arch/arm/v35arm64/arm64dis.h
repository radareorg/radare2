#pragma once
#include <inttypes.h>
#include <stdint.h>
#if defined(_MSC_VER)
		#undef REG_NONE
		#define snprintf _snprintf
		#define restrict __restrict
		#define inline __inline
#else
		#include <stdlib.h>
		#ifdef __cplusplus
		#define restrict __restrict
		#endif
#endif

#define MAX_OPERANDS 5
#define ARRAY_SIZE(array) (sizeof((array))/sizeof((array)[0]))

#ifdef __clang__
#define FALL_THROUGH
#elif defined(__GNUC__) && __GNUC__ >= 7
#define FALL_THROUGH __attribute__((fallthrough));
#else
#define FALL_THROUGH
#endif

#ifdef __cplusplus
#define restrict __restrict

namespace arm64
{
#endif

	enum Operation {
		ARM64_UNDEFINED = 0,
		ARM64_ABS,
		ARM64_ADC,
		ARM64_ADCS,
		ARM64_ADD,
		ARM64_ADDG, //Added for MTE
		ARM64_ADDHN,
		ARM64_ADDHN2,
		ARM64_ADDP,
		ARM64_ADDS,
		ARM64_ADDV,
		ARM64_ADR,
		ARM64_ADRP,
		ARM64_AESD,
		ARM64_AESE,
		ARM64_AESIMC,
		ARM64_AESMC,
		ARM64_AND,
		ARM64_ANDS,
		ARM64_ASR,
		ARM64_AT,
		ARM64_AUTDA, //Added for 8.3
		ARM64_AUTDB, //Added for 8.3
		ARM64_AUTDZA, //Added for 8.3
		ARM64_AUTDZB, //Added for 8.3
		ARM64_AUTIA, //Added for 8.3
		ARM64_AUTIA1716, //Added for 8.3
		ARM64_AUTIASP, //Added for 8.3
		ARM64_AUTIAZ, //Added for 8.3
		ARM64_AUTIB, //Added for 8.3
		ARM64_AUTIB1716, //Added for 8.3
		ARM64_AUTIBSP, //Added for 8.3
		ARM64_AUTIBZ, //Added for 8.3
		ARM64_AUTIZA, //Added for 8.3
		ARM64_AUTIZB, //Added for 8.3
		ARM64_B,
		ARM64_B_AL,
		ARM64_B_CC,
		ARM64_B_CS,
		ARM64_B_EQ,
		ARM64_BFI,
		ARM64_BFM,
		ARM64_BFXIL,
		ARM64_B_GE,
		ARM64_B_GT,
		ARM64_B_HI,
		ARM64_BIC,
		ARM64_BICS,
		ARM64_BIF,
		ARM64_BIT,
		ARM64_BL,
		ARM64_B_LE,
		ARM64_BLR,
		ARM64_BLRAA,
		ARM64_BLRAAZ,
		ARM64_BLRAB,
		ARM64_BLRABZ,
		ARM64_B_LS,
		ARM64_B_LT,
		ARM64_B_MI,
		ARM64_B_NE,
		ARM64_B_NV,
		ARM64_B_PL,
		ARM64_BR,
		ARM64_BRAA,
		ARM64_BRAAZ,
		ARM64_BRAB,
		ARM64_BRABZ,
		ARM64_BRK,
		ARM64_BSL,
		ARM64_B_VC,
		ARM64_B_VS,
		ARM64_CBNZ,
		ARM64_CBZ,
		ARM64_CCMN,
		ARM64_CCMP,
		ARM64_CINC,
		ARM64_CINV,
		ARM64_CLREX,
		ARM64_CLS,
		ARM64_CLZ,
		ARM64_CMEQ,
		ARM64_CMGE,
		ARM64_CMGT,
		ARM64_CMHI,
		ARM64_CMHS,
		ARM64_CMLE,
		ARM64_CMLT,
		ARM64_CMN,
		ARM64_CMP,
		ARM64_CMPP, //Added for MTE
		ARM64_CMTST,
		ARM64_CNEG,
		ARM64_CNT,
		ARM64_CRC32B,
		ARM64_CRC32CB,
		ARM64_CRC32CH,
		ARM64_CRC32CW,
		ARM64_CRC32CX,
		ARM64_CRC32H,
		ARM64_CRC32W,
		ARM64_CRC32X,
		ARM64_CSEL,
		ARM64_CSET,
		ARM64_CSETM,
		ARM64_CSINC,
		ARM64_CSINV,
		ARM64_CSNEG,
		ARM64_DC,
		ARM64_DCPS1,
		ARM64_DCPS2,
		ARM64_DCPS3,
		ARM64_DMB,
		ARM64_DRPS,
		ARM64_DSB,
		ARM64_DUP,
		ARM64_EON,
		ARM64_EOR,
		ARM64_ERET,
		ARM64_ERETAA, //Added for 8.3
		ARM64_ERETAB, //Added for 8.3
		ARM64_ESB, //Added for 8.2
		ARM64_EXT,
		ARM64_EXTR,
		ARM64_FABD,
		ARM64_FABS,
		ARM64_FACGE,
		ARM64_FACGT,
		ARM64_FADD,
		ARM64_FADDP,
		ARM64_FCCMP,
		ARM64_FCCMPE,
		ARM64_FCMEQ,
		ARM64_FCMGE,
		ARM64_FCMGT,
		ARM64_FCMLE,
		ARM64_FCMLT,
		ARM64_FCMP,
		ARM64_FCMPE,
		ARM64_FCSEL,
		ARM64_FCTNS,
		ARM64_FCTNU,
		ARM64_FCVT,
		ARM64_FCVTAS,
		ARM64_FCVTAU,
		ARM64_FCVTL,
		ARM64_FCVTL2,
		ARM64_FCVTMS,
		ARM64_FCVTMU,
		ARM64_FCVTN,
		ARM64_FCVTN2,
		ARM64_FCVTNS,
		ARM64_FCVTNU,
		ARM64_FCVTPS,
		ARM64_FCVTPU,
		ARM64_FCVTXN,
		ARM64_FCVTXN2,
		ARM64_FCVTZS,
		ARM64_FCVTZU,
		ARM64_FDIV,
		ARM64_FMADD,
		ARM64_FMAX,
		ARM64_FMAXNM,
		ARM64_FMAXNMP,
		ARM64_FMAXNMV,
		ARM64_FMAXP,
		ARM64_FMAXV,
		ARM64_FMIN,
		ARM64_FMINNM,
		ARM64_FMINNMP,
		ARM64_FMINNMV,
		ARM64_FMINP,
		ARM64_FMINV,
		ARM64_FMLA,
		ARM64_FMLS,
		ARM64_FMOV,
		ARM64_FMSUB,
		ARM64_FMUL,
		ARM64_FMULX,
		ARM64_FNEG,
		ARM64_FNMADD,
		ARM64_FNMSUB,
		ARM64_FNMUL,
		ARM64_FRECPE,
		ARM64_FRECPS,
		ARM64_FRECPX,
		ARM64_FRINTA,
		ARM64_FRINTI,
		ARM64_FRINTM,
		ARM64_FRINTN,
		ARM64_FRINTP,
		ARM64_FRINTX,
		ARM64_FRINTZ,
		ARM64_FRSQRTE,
		ARM64_FRSQRTS,
		ARM64_FSQRT,
		ARM64_FSUB,
		ARM64_GMI, //Added for MTE
		ARM64_HINT,
		ARM64_HLT,
		ARM64_HVC,
		ARM64_IC,
		ARM64_INS,
		ARM64_IRG, //Added for MTE
		ARM64_ISB,
		ARM64_LD1,
		ARM64_LD1R,
		ARM64_LD2,
		ARM64_LD2R,
		ARM64_LD3,
		ARM64_LD3R,
		ARM64_LD4,
		ARM64_LD4R,
		ARM64_LDAR,
		ARM64_LDARB,
		ARM64_LDARH,
		ARM64_LDAXP,
		ARM64_LDAXR,
		ARM64_LDAXRB,
		ARM64_LDAXRH,
		ARM64_LDG, //Added for MTE
		ARM64_LDGM, //Added for MTE
		ARM64_LDNP,
		ARM64_LDP,
		ARM64_LDPSW,
		ARM64_LDR,
		ARM64_LDRAA, //Added for 8.3
		ARM64_LDRAB, //Added for 8.3
		ARM64_LDRB,
		ARM64_LDRH,
		ARM64_LDRSB,
		ARM64_LDRSH,
		ARM64_LDRSW,
		ARM64_LDTR,
		ARM64_LDTRB,
		ARM64_LDTRH,
		ARM64_LDTRSB,
		ARM64_LDTRSH,
		ARM64_LDTRSW,
		ARM64_LDUR,
		ARM64_LDURB,
		ARM64_LDURH,
		ARM64_LDURSB,
		ARM64_LDURSH,
		ARM64_LDURSW,
		ARM64_LDXP,
		ARM64_LDXR,
		ARM64_LDXRB,
		ARM64_LDXRH,
		ARM64_LSL,
		ARM64_LSR,
		ARM64_MADD,
		ARM64_MLA,
		ARM64_MLS,
		ARM64_MNEG,
		ARM64_MOV,
		ARM64_MOVI,
		ARM64_MOVK,
		ARM64_MOVN,
		ARM64_MOVZ,
		ARM64_MRS,
		ARM64_MSR,
		ARM64_MSUB,
		ARM64_MUL,
		ARM64_MVN,
		ARM64_MVNI,
		ARM64_NEG,
		ARM64_NEGS,
		ARM64_NGC,
		ARM64_NGCS,
		ARM64_NOP,
		ARM64_NOT,
		ARM64_ORN,
		ARM64_ORR,
		ARM64_PACDA, //Added for 8.3
		ARM64_PACDB, //Added for 8.3
		ARM64_PACDZA, //Added for 8.3
		ARM64_PACDZB, //Added for 8.3
		ARM64_PACIA, //Added for 8.3
		ARM64_PACIA1716, //Added for 8.3
		ARM64_PACIASP, //Added for 8.3
		ARM64_PACIAZ, //Added for 8.3
		ARM64_PACIB, //Added for 8.3
		ARM64_PACIB1716, //Added for 8.3
		ARM64_PACIBSP, //Added for 8.3
		ARM64_PACIBZ, //Added for 8.3
		ARM64_PACIZA, //Added for 8.3
		ARM64_PACIZB, //Added for 8.3
		ARM64_PMUL,
		ARM64_PMULL,
		ARM64_PMULL2,
		ARM64_PRFM,
		ARM64_PRFUM,
		ARM64_PSBCSYNC, //Added for 8.2
		ARM64_RADDHN,
		ARM64_RADDHN2,
		ARM64_RBIT,
		ARM64_RET,
		ARM64_RETAA, //Added for 8.3
		ARM64_RETAB, //Added for 8.3
		ARM64_REV,
		ARM64_REV16,
		ARM64_REV32,
		ARM64_REV64,
		ARM64_ROR,
		ARM64_RSHRN,
		ARM64_RSHRN2,
		ARM64_RSUBHN,
		ARM64_RSUBHN2,
		ARM64_SABA,
		ARM64_SABAL,
		ARM64_SABAL2,
		ARM64_SABD,
		ARM64_SABDL,
		ARM64_SABDL2,
		ARM64_SADALP,
		ARM64_SADDL,
		ARM64_SADDL2,
		ARM64_SADDLP,
		ARM64_SADDLV,
		ARM64_SADDW,
		ARM64_SADDW2,
		ARM64_SBC,
		ARM64_SBCS,
		ARM64_SBFIZ,
		ARM64_SBFM,
		ARM64_SBFX,
		ARM64_SCVTF,
		ARM64_SDIV,
		ARM64_SEV,
		ARM64_SEVL,
		ARM64_SHA1C,
		ARM64_SHA1H,
		ARM64_SHA1M,
		ARM64_SHA1P,
		ARM64_SHA1SU0,
		ARM64_SHA1SU1,
		ARM64_SHA256H,
		ARM64_SHA256H2,
		ARM64_SHA256SU0,
		ARM64_SHA256SU1,
		ARM64_SHADD,
		ARM64_SHL,
		ARM64_SHLL,
		ARM64_SHLL2,
		ARM64_SHRN,
		ARM64_SHRN2,
		ARM64_SHSUB,
		ARM64_SLI,
		ARM64_SMADDL,
		ARM64_SMAX,
		ARM64_SMAXP,
		ARM64_SMAXV,
		ARM64_SMC,
		ARM64_SMIN,
		ARM64_SMINP,
		ARM64_SMINV,
		ARM64_SMLAL,
		ARM64_SMLAL2,
		ARM64_SMLSL,
		ARM64_SMLSL2,
		ARM64_SMNEGL,
		ARM64_SMOV,
		ARM64_SMSUBL,
		ARM64_SMULH,
		ARM64_SMULL,
		ARM64_SMULL2,
		ARM64_SQABS,
		ARM64_SQADD,
		ARM64_SQDMLAL,
		ARM64_SQDMLAL2,
		ARM64_SQDMLSL,
		ARM64_SQDMLSL2,
		ARM64_SQDMULH,
		ARM64_SQDMULL,
		ARM64_SQDMULL2,
		ARM64_SQNEG,
		ARM64_SQRDMULH,
		ARM64_SQRSHL,
		ARM64_SQRSHRN,
		ARM64_SQRSHRN2,
		ARM64_SQRSHRUN,
		ARM64_SQRSHRUN2,
		ARM64_SQSHL,
		ARM64_SQSHLU,
		ARM64_SQSHRN,
		ARM64_SQSHRN2,
		ARM64_SQSHRUN,
		ARM64_SQSHRUN2,
		ARM64_SQSUB,
		ARM64_SQXTN,
		ARM64_SQXTN2,
		ARM64_SQXTUN,
		ARM64_SQXTUN2,
		ARM64_SRHADD,
		ARM64_SRI,
		ARM64_SRSHL,
		ARM64_SRSHR,
		ARM64_SRSRA,
		ARM64_SSHL,
		ARM64_SSHLL,
		ARM64_SSHLL2,
		ARM64_SSHR,
		ARM64_SSRA,
		ARM64_SSUBL,
		ARM64_SSUBL2,
		ARM64_SSUBW,
		ARM64_SSUBW2,
		ARM64_ST1,
		ARM64_ST2,
		ARM64_ST2G, //Added for MTE
		ARM64_ST3,
		ARM64_ST4,
		ARM64_STG, //Added for MTE
		ARM64_STGM, //Added for MTE
		ARM64_STGP, //Added for MTE
		ARM64_STLR,
		ARM64_STLRB,
		ARM64_STLRH,
		ARM64_STLXP,
		ARM64_STLXR,
		ARM64_STLXRB,
		ARM64_STLXRH,
		ARM64_STNP,
		ARM64_STP,
		ARM64_STR,
		ARM64_STRB,
		ARM64_STRH,
		ARM64_STTR,
		ARM64_STTRB,
		ARM64_STTRH,
		ARM64_STUR,
		ARM64_STURB,
		ARM64_STURH,
		ARM64_STXP,
		ARM64_STXR,
		ARM64_STXRB,
		ARM64_STXRH,
		ARM64_STZ2G, //Added for MTE
		ARM64_STZG, //Added for MTE
		ARM64_STZGM, //Added for MTE
		ARM64_SUB,
		ARM64_SUBG, //Added for MTE
		ARM64_SUBHN,
		ARM64_SUBHN2,
		ARM64_SUBP, //Added for MTE
		ARM64_SUBPS, //Added for MTE
		ARM64_SUBS,
		ARM64_SUQADD,
		ARM64_SVC,
		ARM64_SXTB,
		ARM64_SXTH,
		ARM64_SXTW,
		ARM64_SYS,
		ARM64_SYSL,
		ARM64_TBL,
		ARM64_TBNZ,
		ARM64_TBX,
		ARM64_TBZ,
		ARM64_TLBI,
		ARM64_TRN1,
		ARM64_TRN2,
		ARM64_TST,
		ARM64_UABA,
		ARM64_UABAL,
		ARM64_UABAL2,
		ARM64_UABD,
		ARM64_UABDL,
		ARM64_UABDL2,
		ARM64_UADALP,
		ARM64_UADDL,
		ARM64_UADDL2,
		ARM64_UADDLP,
		ARM64_UADDLV,
		ARM64_UADDW,
		ARM64_UADDW2,
		ARM64_UBFIZ,
		ARM64_UBFM,
		ARM64_UBFX,
		ARM64_UCVTF,
		ARM64_UDIV,
		ARM64_UHADD,
		ARM64_UHSUB,
		ARM64_UMADDL,
		ARM64_UMAX,
		ARM64_UMAXP,
		ARM64_UMAXV,
		ARM64_UMIN,
		ARM64_UMINP,
		ARM64_UMINV,
		ARM64_UMLAL,
		ARM64_UMLAL2,
		ARM64_UMLSL,
		ARM64_UMLSL2,
		ARM64_UMNEGL,
		ARM64_UMOV,
		ARM64_UMSUBL,
		ARM64_UMULH,
		ARM64_UMULL,
		ARM64_UMULL2,
		ARM64_UQADD,
		ARM64_UQRSHL,
		ARM64_UQRSHRN,
		ARM64_UQRSHRN2,
		ARM64_UQSHL,
		ARM64_UQSHRN,
		ARM64_UQSHRN2,
		ARM64_UQSUB,
		ARM64_UQXTN,
		ARM64_UQXTN2,
		ARM64_URECPE,
		ARM64_URHADD,
		ARM64_URSHL,
		ARM64_URSHR,
		ARM64_URSQRTE,
		ARM64_URSRA,
		ARM64_USHL,
		ARM64_USHLL,
		ARM64_USHLL2,
		ARM64_USHR,
		ARM64_USQADD,
		ARM64_USRA,
		ARM64_USUBL,
		ARM64_USUBL2,
		ARM64_USUBW,
		ARM64_USUBW2,
		ARM64_UXTB,
		ARM64_UXTH,
		ARM64_UZP1,
		ARM64_UZP2,
		ARM64_WFE,
		ARM64_WFI,
		ARM64_XPACD, //Added for 8.3
		ARM64_XPACI, //Added for 8.3
		ARM64_XPACLRI, //Added for 8.3
		ARM64_XTN,
		ARM64_XTN2,
		ARM64_YIELD,
		ARM64_ZIP1,
		ARM64_ZIP2,

		AMD64_END_TYPE //Not real instruction
	};

	//---------------------------------------------
	//C4.4 Data processing - immediate
	//---------------------------------------------

	struct PC_REL_ADDRESSING {
		uint32_t Rd:5;
		int32_t immhi:19;
		uint32_t group1:5;
		uint32_t immlo:2;
		uint32_t op:1;
	};

	struct ADD_SUB_IMM {
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t imm:12;
		uint32_t shift:2;
		uint32_t group1:5;
		uint32_t S:1;
		uint32_t op:1;
		uint32_t sf:1;
	};

	struct ADD_SUB_IMM_TAGS {
		uint32_t Xd:5;
		uint32_t Xn:5;
		uint32_t uimm4:4;
		uint32_t op3:2;
		uint32_t uimm6:6;
		uint32_t padding:10;
	};

	struct LOGICAL_IMM {
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t imms:6;
		uint32_t immr:6;
		uint32_t N:1;
		uint32_t group1:6;
		uint32_t opc:2;
		uint32_t sf:1;
	};

	struct MOVE_WIDE_IMM {
		uint32_t Rd:5;
		uint32_t imm:16;
		uint32_t hw:2;
		uint32_t group1:6;
		uint32_t opc:2;
		uint32_t sf:1;
	};

	struct BITFIELD {
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t imms:6;
		uint32_t immr:6;
		uint32_t N:1;
		uint32_t group1:6;
		uint32_t opc:2;
		uint32_t sf:1;
	};

	struct EXTRACT {
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t imms:6;
		uint32_t Rm:5;
		uint32_t o0:1;
		uint32_t N:1;
		uint32_t group1:6;
		uint32_t op21:2;
		uint32_t sf:1;
	};

	//--------------------------------------------------------
	// C4.2  Branches, exception generating and system instructions
	//--------------------------------------------------------

	struct UNCONDITIONAL_BRANCH{
		int32_t imm:26;
		uint32_t opcode:5;
		uint32_t op:1;
	};

	struct COMPARE_BRANCH_IMM {
		uint32_t Rt:5;
		int32_t imm:19;
		uint32_t op:1;
		uint32_t opcode:6;
		uint32_t sf:1;
	};

	struct TEST_AND_BRANCH{
		uint32_t Rt:5;
		int32_t imm:14;
		uint32_t b40:5;
		uint32_t op:1;
		uint32_t opcode:6;
		uint32_t b5:1;
	};

	struct CONDITIONAL_BRANCH_IMM {
		uint32_t cond:4;
		uint32_t o0:1;
		int32_t imm:19;
		uint32_t o1:1;
		uint32_t opcode:7;
	};

	struct EXCEPTION_GENERATION {
		uint32_t LL:2;
		uint32_t op2:3;
		uint32_t imm:16;
		uint32_t opc:3;
		uint32_t opcode:8;
	};

	struct SYSTEM{
		uint32_t Rt:5;
		uint32_t op2:3;
		uint32_t CRm:4;
		uint32_t CRn:4;
		uint32_t op1:3;
		uint32_t op0:2;
		uint32_t L:1;
		uint32_t group1:10;
	};

	struct UNCONDITIONAL_BRANCH_REG{
		uint32_t op4:5;
		uint32_t Rn:5;
		uint32_t op3:6;
		uint32_t op2:5;
		uint32_t opc:4;
		uint32_t opcode:7;
	};

	//--------------------------------------------------------
	// C4.3 Loads and stores
	//--------------------------------------------------------
	struct LDST_TAGS {
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t op2:2;
		uint32_t imm9:9;
		uint32_t anon0:1;
		uint32_t opc:2;
		uint32_t anon1:8;
	};

	struct LDST_EXCLUSIVE {
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t Rt2:5;
		uint32_t o0:1;
		uint32_t Rs:5;
		uint32_t o1:1;
		uint32_t L:1;
		uint32_t o2:1;
		uint32_t group1:6;
		uint32_t size:2;
	};

	struct LOAD_REGISTER_LITERAL {
		uint32_t Rt:5;
		int32_t imm:19;
		uint32_t group1:2;
		uint32_t V:1;
		uint32_t group2:3;
		uint32_t opc:2;
	};

	struct LDST_NO_ALLOC_PAIR{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t Rt2:5;
		int32_t imm:7;
		uint32_t L:1;
		uint32_t group1:3;
		uint32_t V:1;
		uint32_t group2:3;
		uint32_t opc:2;
	};

	struct LDST_REG_PAIR_POST_IDX{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		int32_t imm:9;
		uint32_t group2:1;
		uint32_t opc:2;
		uint32_t group3:2;
		uint32_t V:1;
		uint32_t group4:3;
		uint32_t size:2;
	};

	struct LDST_REG_PAIR_OFFSET{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t Rt2:5;
		int32_t imm:7;
		uint32_t L:1;
		uint32_t group1:3;
		uint32_t V:1;
		uint32_t group2:3;
		uint32_t opc:2;
	};

	struct LDST_REG_PAIR_PRE_IDX{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t Rt2:5;
		uint32_t imm:7;
		uint32_t L:1;
		uint32_t group1:3;
		uint32_t V:1;
		uint32_t group2:3;
		uint32_t opc:2;
	};

	struct LDST_REG_UNSCALED_IMM{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		int32_t imm:9;
		uint32_t group2:1;
		uint32_t opc:2;
		uint32_t group3:2;
		uint32_t V:1;
		uint32_t group4:3;
		uint32_t size:2;
	};

	struct LDST_REG_IMM_POST_IDX{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t imm:9;
		uint32_t group2:1;
		uint32_t opc:2;
		uint32_t group3:2;
		uint32_t V:1;
		uint32_t group4:3;
		uint32_t size:2;
	};

	struct LDST_REGISTER_UNPRIV{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		int32_t imm:9;
		uint32_t group2:1;
		uint32_t opc:2;
		uint32_t group3:2;
		uint32_t V:1;
		uint32_t group4:3;
		uint32_t size:2;
	};

	struct LDST_REG_IMM_PRE_IDX{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		int32_t imm:9;
		uint32_t group2:1;
		uint32_t opc:2;
		uint32_t group3:2;
		uint32_t V:1;
		uint32_t group4:3;
		uint32_t size:2;
	};

	struct LDST_REG_REG_OFFSET{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t S:1;
		uint32_t option:3;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t opc:2;
		uint32_t group3:2;
		uint32_t V:1;
		uint32_t group4:3;
		uint32_t size:2;
	};

	struct LDST_REG_UNSIGNED_IMM{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t imm:12;
		uint32_t opc:2;
		uint32_t group1:2;
		uint32_t V:1;
		uint32_t group2:3;
		uint32_t size:2;
	};

	struct LDST_REG_IMM_PAC{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t W:1;
		uint32_t imm:9;
		uint32_t group2:1;
		uint32_t S:1;
		uint32_t M:1;
		uint32_t group3:2;
		uint32_t V:1;
		uint32_t group4:3;
		uint32_t size:2;
	};

	struct SIMD_LDST_MULT{
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t size:2;
		uint32_t opcode:4;
		uint32_t group1:6;
		uint32_t L:1;
		uint32_t group2:7;
		uint32_t Q:1;
		uint32_t group3:1;
	};

	struct SIMD_LDST_MULT_PI {
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t size:2;
		uint32_t opcode:4;
		uint32_t Rm:5;
		uint32_t group1:1;
		uint32_t L:1;
		uint32_t group2:7;
		uint32_t Q:1;
		uint32_t group3:1;
	};

	struct SIMD_LDST_SINGLE {
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t size:2;
		uint32_t S:1;
		uint32_t opcode:3;
		uint32_t group1:5;
		uint32_t R:1;
		uint32_t L:1;
		uint32_t group2:7;
		uint32_t Q:1;
		uint32_t group3:1;
	};

	struct SIMD_LDST_SINGLE_PI {
		uint32_t Rt:5;
		uint32_t Rn:5;
		uint32_t size:2;
		uint32_t S:1;
		uint32_t opcode:3;
		uint32_t Rm:5;
		uint32_t R:1;
		uint32_t L:1;
		uint32_t group1:7;
		uint32_t Q:1;
		uint32_t group2:1;
	};

	//--------------------------------------------------------
	// C4.5 Data processing - register
	//--------------------------------------------------------

	struct LOGICAL_SHIFTED_REG{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t imm:6;
		uint32_t Rm:5;
		uint32_t N:1;
		uint32_t shift:2;
		uint32_t group1:5;
		uint32_t opc:2;
		uint32_t sf:1;
	};

	struct ADD_SUB_SHIFTED_REG{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t imm:6;
		uint32_t Rm:5;
		uint32_t group1:1;
		uint32_t shift:2;
		uint32_t group2:5;
		uint32_t S:1;
		uint32_t op:1;
		uint32_t sf:1;
	};

	struct ADD_SUB_EXTENDED_REG{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t imm:3;
		uint32_t option:3;
		uint32_t Rm:5;
		uint32_t group1:1;
		uint32_t opt:2;
		uint32_t group2:5;
		uint32_t S:1;
		uint32_t op:1;
		uint32_t sf:1;
	};

	struct ADD_SUB_WITH_CARRY{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t opcode2:6;
		uint32_t Rm:5;
		uint32_t group1:8;
		uint32_t S:1;
		uint32_t op:1;
		uint32_t sf:1;
	};

	struct CONDITIONAL_COMPARE_REG{
		uint32_t nzcv:4;
		uint32_t o3:1;
		uint32_t Rn:5;
		uint32_t o2:1;
		uint32_t group1:1;
		uint32_t cond:4;
		uint32_t Rm:5;
		uint32_t group2:8;
		uint32_t S:1;
		uint32_t op:1;
		uint32_t sf:1;
	};

	struct CONDITIONAL_COMPARE_IMM{
		uint32_t nzcv:4;
		uint32_t o3:1;
		uint32_t Rn:5;
		uint32_t o2:1;
		uint32_t group1:1;
		uint32_t cond:4;
		uint32_t imm:5;
		uint32_t group2:8;
		uint32_t S:1;
		uint32_t op:1;
		uint32_t sf:1;
	};

	struct CONDITIONAL_SELECT{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t op2:2;
		uint32_t cond:4;
		uint32_t Rm:5;
		uint32_t group1:8;
		uint32_t S:1;
		uint32_t op:1;
		uint32_t sf:1;
	};

	struct DATA_PROCESSING_3{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t Ra:5;
		uint32_t o0:1;
		uint32_t Rm:5;
		uint32_t op31:3;
		uint32_t group1:5;
		uint32_t op54:2;
		uint32_t sf:1;
	};

	struct DATA_PROCESSING_2{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t opcode:6;
		uint32_t Rm:5;
		uint32_t group1:8;
		uint32_t S:1;
		uint32_t group2:1;
		uint32_t sf:1;
	};

	struct DATA_PROCESSING_1{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t opcode:6;
		uint32_t opcode2:5;
		uint32_t group1:8;
		uint32_t S:1;
		uint32_t group2:1;
		uint32_t sf:1;
	};

	//--------------------------------------------------------
	// C4.6 - Data Processing -SIMD and floating point
	//--------------------------------------------------------

	struct FLOATING_FIXED_CONVERSION{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t scale:6;
		uint32_t opcode:3;
		uint32_t mode:2;
		uint32_t group1:1;
		uint32_t type:2;
		uint32_t group2:5;
		uint32_t S:1;
		uint32_t group3:1;
		uint32_t sf:1;
	};

	struct FLOATING_CONDITIONAL_COMPARE{
		uint32_t nzvb:4;
		uint32_t op:1;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t cond:4;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t type:2;
		uint32_t group3:5;
		uint32_t S:1;
		uint32_t group4:1;
		uint32_t M:1;
	};

	struct FLOATING_DATA_PROCESSING_2{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:4;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t type:2;
		uint32_t group3:5;
		uint32_t S:1;
		uint32_t group4:1;
		uint32_t M:1;
	};

	struct FLOATING_CONDITIONAL_SELECT{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t cond:4;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t type:2;
		uint32_t group3:5;
		uint32_t S:1;
		uint32_t group4:1;
		uint32_t M:1;
	};

	struct FLOATING_IMM{
		uint32_t Rd:5;
		uint32_t imm5:5;
		uint32_t group1:3;
		uint32_t imm8:8;
		uint32_t group2:1;
		uint32_t type:2;
		uint32_t group3:5;
		uint32_t S:1;
		uint32_t group4:1;
		uint32_t M:1;
	};

	struct FLOATING_COMPARE{
		uint32_t opcode2:5;
		uint32_t Rn:5;
		uint32_t group1:4;
		uint32_t op:2;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t type:2;
		uint32_t group3:5;
		uint32_t S:1;
		uint32_t group4:1;
		uint32_t M:1;
	};

	struct FLOATING_DATA_PROCESSING_1{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:5;
		uint32_t opcode:6;
		uint32_t group2:1;
		uint32_t type:2;
		uint32_t group3:5;
		uint32_t S:1;
		uint32_t group4:1;
		uint32_t M:1;
	};

	struct FLOATING_INTEGER_CONVERSION{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:6;
		uint32_t opcode:3;
		uint32_t rmode:2;
		uint32_t group2:1;
		uint32_t type:2;
		uint32_t group3:5;
		uint32_t S:1;
		uint32_t group4:1;
		uint32_t sf:1;
	};

	struct FLOATING_DATA_PROCESSING_3{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t Ra:5;
		uint32_t o0:1;
		uint32_t Rm:5;
		uint32_t o1:1;
		uint32_t type:2;
		uint32_t group1:5;
		uint32_t S:1;
		uint32_t group2:1;
		uint32_t M:1;
	};

	struct SIMD_3_SAME{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t opcode:5;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t size:2;
		uint32_t group3:5;
		uint32_t U:1;
		uint32_t Q:1;
		uint32_t group4:1;
	};

	struct SIMD_3_DIFFERENT{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:4;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t size:2;
		uint32_t group3:5;
		uint32_t U:1;
		uint32_t Q:1;
		uint32_t group4:1;
	};

	struct SIMD_2_REG_MISC{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:5;
		uint32_t group2:5;
		uint32_t size:2;
		uint32_t group3:5;
		uint32_t U:1;
		uint32_t Q:1;
		uint32_t group4:1;
	};

	struct SIMD_ACROSS_LANES{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:5;
		uint32_t group2:5;
		uint32_t size:2;
		uint32_t group3:5;
		uint32_t U:1;
		uint32_t Q:1;
		uint32_t group4:1;
	};

	struct SIMD_COPY{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t imm4:4;
		uint32_t group2:1;
		uint32_t imm5:5;
		uint32_t group3:8;
		uint32_t op:1;
		uint32_t Q:1;
		uint32_t group4:1;
	};

	struct SIMD_VECTOR_X_INDEXED_ELEMENT{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t H:1;
		uint32_t opcode:4;
		uint32_t Rm:4;
		uint32_t M:1;
		uint32_t L:1;
		uint32_t size:2;
		uint32_t group2:5;
		uint32_t U:1;
		uint32_t Q:1;
		uint32_t group3:1;
	};

	struct SIMD_MODIFIED_IMM{
		uint32_t Rd:5;
		uint32_t h:1;
		uint32_t g:1;
		uint32_t f:1;
		uint32_t e:1;
		uint32_t d:1;
		uint32_t group1:1;
		uint32_t o2:1;
		uint32_t cmode:4;
		uint32_t c:1;
		uint32_t b:1;
		uint32_t a:1;
		uint32_t group2:10;
		uint32_t op:1;
		uint32_t Q:1;
		uint32_t group3:1;
	};

	struct SIMD_SHIFT_BY_IMM{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t opcode:5;
		uint32_t immb:3;
		uint32_t immh:4;
		uint32_t group2:6;
		uint32_t U:1;
		uint32_t Q:1;
		uint32_t group3:1;
	};

	struct SIMD_TABLE_LOOKUP{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t op:1;
		uint32_t len:2;
		uint32_t group2:1;
		uint32_t Rm:5;
		uint32_t group3:9;
		uint32_t Q:1;
		uint32_t group4:1;
	};

	struct SIMD_PERMUTE{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:3;
		uint32_t group2:1;
		uint32_t Rm:5;
		uint32_t group3:1;
		uint32_t size:2;
		uint32_t group4:6;
		uint32_t Q:1;
		uint32_t group5:1;
	};

	struct SIMD_EXTRACT{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t imm:4;
		uint32_t group2:1;
		uint32_t Rm:5;
		uint32_t group3:1;
		uint32_t op2:2;
		uint32_t group4:6;
		uint32_t Q:1;
		uint32_t group5:1;
	};

	struct SIMD_SCALAR_3_SAME{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t opcode:5;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t size:2;
		uint32_t group3:5;
		uint32_t U:1;
		uint32_t group4:2;
	};

	struct SIMD_SCALAR_3_DIFFERENT{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:4;
		uint32_t Rm:5;
		uint32_t group2:1;
		uint32_t size:2;
		uint32_t group3:5;
		uint32_t U:1;
		uint32_t group4:2;
	};

	struct SIMD_SCALAR_2_REGISTER_MISC{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:5;
		uint32_t group2:5;
		uint32_t size:2;
		uint32_t group3:5;
		uint32_t U:1;
		uint32_t group4:2;
	};

	struct SIMD_SCALAR_PAIRWISE{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:5;
		uint32_t group2:5;
		uint32_t size:2;
		uint32_t group3:5;
		uint32_t U:1;
		uint32_t group4:2;
	};

	struct SIMD_SCALAR_COPY{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t imm4:4;
		uint32_t group2:1;
		uint32_t imm5:5;
		uint32_t group3:8;
		uint32_t op:1;
		uint32_t group4:2;
	};

	struct SIMD_SCALAR_X_INDEXED_ELEMENT{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t H:1;
		uint32_t opcode:4;
		uint32_t Rm:4;
		uint32_t M:1;
		uint32_t L:1;
		uint32_t size:2;
		uint32_t group2:5;
		uint32_t U:1;
		uint32_t group3:2;
	};

	struct SIMD_SCALAR_SHIFT_BY_IMM{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:1;
		uint32_t opcode:5;
		uint32_t immb:3;
		uint32_t immh:4;
		uint32_t group2:6;
		uint32_t U:1;
		uint32_t group3:2;
	};

	struct CRYPTOGRAPHIC_AES{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:5;
		uint32_t group2:5;
		uint32_t size:2;
		uint32_t group3:8;
	};

	struct CRYPTOGRAPHIC_3_REG_SHA{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:3;
		uint32_t group2:1;
		uint32_t Rm:5;
		uint32_t group3:1;
		uint32_t size:2;
		uint32_t group4:8;
	};

	struct CRYPTOGRAPHIC_2_REG_SHA{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:2;
		uint32_t opcode:5;
		uint32_t group2:5;
		uint32_t size:2;
		uint32_t group3:8;
	};

	struct POINTER_AUTH{
		uint32_t Rd:5;
		uint32_t Rn:5;
		uint32_t group1:3;
		uint32_t Z:1;
		uint32_t group2:18;
	};

#ifndef __cplusplus
	typedef struct PC_REL_ADDRESSING PC_REL_ADDRESSING;
	typedef struct ADD_SUB_IMM ADD_SUB_IMM;
	typedef struct ADD_SUB_IMM_TAGS ADD_SUB_IMM_TAGS;
	typedef struct LOGICAL_IMM LOGICAL_IMM;
	typedef struct MOVE_WIDE_IMM MOVE_WIDE_IMM;
	typedef struct BITFIELD BITFIELD;
	typedef struct EXTRACT EXTRACT;
	typedef struct UNCONDITIONAL_BRANCH UNCONDITIONAL_BRANCH;
	typedef struct COMPARE_BRANCH_IMM COMPARE_BRANCH_IMM;
	typedef struct TEST_AND_BRANCH TEST_AND_BRANCH;
	typedef struct CONDITIONAL_BRANCH_IMM CONDITIONAL_BRANCH_IMM;
	typedef struct EXCEPTION_GENERATION EXCEPTION_GENERATION;
	typedef struct SYSTEM SYSTEM;
	typedef struct UNCONDITIONAL_BRANCH_REG UNCONDITIONAL_BRANCH_REG;
	typedef struct LDST_TAGS LDST_TAGS;
	typedef struct LDST_EXCLUSIVE LDST_EXCLUSIVE;
	typedef struct LOAD_REGISTER_LITERAL LOAD_REGISTER_LITERAL;
	typedef struct LDST_NO_ALLOC_PAIR LDST_NO_ALLOC_PAIR;
	typedef struct LDST_REG_PAIR_POST_IDX LDST_REG_PAIR_POST_IDX;
	typedef struct LDST_REG_PAIR_OFFSET LDST_REG_PAIR_OFFSET;
	typedef struct LDST_REG_PAIR_PRE_IDX LDST_REG_PAIR_PRE_IDX;
	typedef struct LDST_REG_UNSCALED_IMM LDST_REG_UNSCALED_IMM;
	typedef struct LDST_REG_IMM_POST_IDX LDST_REG_IMM_POST_IDX;
	typedef struct LDST_REGISTER_UNPRIV LDST_REGISTER_UNPRIV;
	typedef struct LDST_REG_IMM_PRE_IDX LDST_REG_IMM_PRE_IDX;
	typedef struct LDST_REG_REG_OFFSET LDST_REG_REG_OFFSET;
	typedef struct LDST_REG_UNSIGNED_IMM LDST_REG_UNSIGNED_IMM;
	typedef struct LDST_REG_IMM_PAC LDST_REG_IMM_PAC;
	typedef struct SIMD_LDST_MULT SIMD_LDST_MULT;
	typedef struct SIMD_LDST_MULT_PI SIMD_LDST_MULT_PI;
	typedef struct SIMD_LDST_SINGLE SIMD_LDST_SINGLE;
	typedef struct SIMD_LDST_SINGLE_PI SIMD_LDST_SINGLE_PI;
	typedef struct LOGICAL_SHIFTED_REG LOGICAL_SHIFTED_REG;
	typedef struct ADD_SUB_SHIFTED_REG ADD_SUB_SHIFTED_REG;
	typedef struct ADD_SUB_EXTENDED_REG ADD_SUB_EXTENDED_REG;
	typedef struct ADD_SUB_WITH_CARRY ADD_SUB_WITH_CARRY;
	typedef struct CONDITIONAL_COMPARE_REG CONDITIONAL_COMPARE_REG;
	typedef struct CONDITIONAL_COMPARE_IMM CONDITIONAL_COMPARE_IMM;
	typedef struct CONDITIONAL_SELECT CONDITIONAL_SELECT;
	typedef struct DATA_PROCESSING_3 DATA_PROCESSING_3;
	typedef struct DATA_PROCESSING_2 DATA_PROCESSING_2;
	typedef struct DATA_PROCESSING_1 DATA_PROCESSING_1;
	typedef struct FLOATING_FIXED_CONVERSION FLOATING_FIXED_CONVERSION;
	typedef struct FLOATING_CONDITIONAL_COMPARE FLOATING_CONDITIONAL_COMPARE;
	typedef struct FLOATING_DATA_PROCESSING_2 FLOATING_DATA_PROCESSING_2;
	typedef struct FLOATING_CONDITIONAL_SELECT FLOATING_CONDITIONAL_SELECT;
	typedef struct FLOATING_IMM FLOATING_IMM;
	typedef struct FLOATING_COMPARE FLOATING_COMPARE;
	typedef struct FLOATING_DATA_PROCESSING_1 FLOATING_DATA_PROCESSING_1;
	typedef struct FLOATING_INTEGER_CONVERSION FLOATING_INTEGER_CONVERSION;
	typedef struct FLOATING_DATA_PROCESSING_3 FLOATING_DATA_PROCESSING_3;
	typedef struct SIMD_3_SAME SIMD_3_SAME;
	typedef struct SIMD_3_DIFFERENT SIMD_3_DIFFERENT;
	typedef struct SIMD_2_REG_MISC SIMD_2_REG_MISC;
	typedef struct SIMD_ACROSS_LANES SIMD_ACROSS_LANES;
	typedef struct SIMD_COPY SIMD_COPY;
	typedef struct SIMD_VECTOR_X_INDEXED_ELEMENT SIMD_VECTOR_X_INDEXED_ELEMENT;
	typedef struct SIMD_MODIFIED_IMM SIMD_MODIFIED_IMM;
	typedef struct SIMD_SHIFT_BY_IMM SIMD_SHIFT_BY_IMM;
	typedef struct SIMD_TABLE_LOOKUP SIMD_TABLE_LOOKUP;
	typedef struct SIMD_PERMUTE SIMD_PERMUTE;
	typedef struct SIMD_EXTRACT SIMD_EXTRACT;
	typedef struct SIMD_SCALAR_3_SAME SIMD_SCALAR_3_SAME;
	typedef struct SIMD_SCALAR_3_DIFFERENT SIMD_SCALAR_3_DIFFERENT;
	typedef struct SIMD_SCALAR_2_REGISTER_MISC SIMD_SCALAR_2_REGISTER_MISC;
	typedef struct SIMD_SCALAR_PAIRWISE SIMD_SCALAR_PAIRWISE;
	typedef struct SIMD_SCALAR_COPY SIMD_SCALAR_COPY;
	typedef struct SIMD_SCALAR_X_INDEXED_ELEMENT SIMD_SCALAR_X_INDEXED_ELEMENT;
	typedef struct SIMD_SCALAR_SHIFT_BY_IMM SIMD_SCALAR_SHIFT_BY_IMM;
	typedef struct CRYPTOGRAPHIC_AES CRYPTOGRAPHIC_AES;
	typedef struct CRYPTOGRAPHIC_3_REG_SHA CRYPTOGRAPHIC_3_REG_SHA;
	typedef struct CRYPTOGRAPHIC_2_REG_SHA CRYPTOGRAPHIC_2_REG_SHA;
	typedef struct POINTER_AUTH POINTER_AUTH;
#endif

	enum SystemReg {
		SYSREG_NONE,
		REG_ACTLR_EL1,
		REG_ACTLR_EL2,
		REG_ACTLR_EL3,
		REG_AFSR0_EL1,
		REG_AFSR1_EL2,
		REG_AFSR0_EL2,
		REG_AFSR0_EL3,
		REG_AFSR1_EL1,
		REG_AFSR1_EL3,
		REG_AIDR_EL1,
		REG_ALLE1,
		REG_ALLE1IS,
		REG_ALLE2,
		REG_ALLE2IS,
		REG_ALLE3,
		REG_ALLE3IS,
		REG_AMAIR_EL1,
		REG_AMAIR_EL2,
		REG_AMAIR_EL3,
		REG_ASIDE1,
		REG_ASIDE1IS,
		REG_CCSIDR_EL1,
		REG_CISW,
		REG_CIVAC,
		REG_CLIDR_EL1,
		REG_CNTFRQ_EL0,
		REG_CNTHCTL_EL2,
		REG_CNTHP_CTL_EL2,
		REG_CNTHP_CVAL_EL2,
		REG_CNTHP_TVAL_EL2,
		REG_CNTKCTL_EL1,
		REG_CNTPCT_EL0,
		REG_CNTPS_CTL_EL1,
		REG_CNTPS_CVAL_EL1,
		REG_CNTPS_TVAL_EL1,
		REG_CNTP_CTL_EL0,
		REG_CNTP_CVAL_EL0,
		REG_CNTP_TVAL_EL0,
		REG_CNTVCT_EL0,
		REG_CNTV_CTL_EL0,
		REG_CNTV_CVAL_EL0,
		REG_CNTV_TVAL_EL0,
		REG_CONTEXTIDR_EL1,
		REG_CPACR_EL1,
		REG_CPTR_EL2,
		REG_CPTR_EL3,
		REG_CSSELR_EL1,
		REG_CSW,
		REG_CTR_EL0,
		REG_CVAC,
		REG_CVAU,
		REG_DACR32_EL2,
		REG_DAIFCLR,
		REG_DAIFSET,
		REG_DBGAUTHSTATUS_EL1,
		REG_DBGCLAIMCLR_EL1,
		REG_DBGCLAIMSET_EL1,
		REG_DBGBCR0_EL1,
		REG_DBGBCR10_EL1,
		REG_DBGBCR11_EL1,
		REG_DBGBCR12_EL1,
		REG_DBGBCR13_EL1,
		REG_DBGBCR14_EL1,
		REG_DBGBCR15_EL1,
		REG_DBGBCR1_EL1,
		REG_DBGBCR2_EL1,
		REG_DBGBCR3_EL1,
		REG_DBGBCR4_EL1,
		REG_DBGBCR5_EL1,
		REG_DBGBCR6_EL1,
		REG_DBGBCR7_EL1,
		REG_DBGBCR8_EL1,
		REG_DBGBCR9_EL1,
		REG_DBGDTRRX_EL0,
		REG_DBGDTRTX_EL0,
		REG_DBGDTR_EL0,
		REG_DBGPRCR_EL1,
		REG_DBGVCR32_EL2,
		REG_DBGBVR0_EL1,
		REG_DBGBVR10_EL1,
		REG_DBGBVR11_EL1,
		REG_DBGBVR12_EL1,
		REG_DBGBVR13_EL1,
		REG_DBGBVR14_EL1,
		REG_DBGBVR15_EL1,
		REG_DBGBVR1_EL1,
		REG_DBGBVR2_EL1,
		REG_DBGBVR3_EL1,
		REG_DBGBVR4_EL1,
		REG_DBGBVR5_EL1,
		REG_DBGBVR6_EL1,
		REG_DBGBVR7_EL1,
		REG_DBGBVR8_EL1,
		REG_DBGBVR9_EL1,
		REG_DBGWCR0_EL1,
		REG_DBGWCR10_EL1,
		REG_DBGWCR11_EL1,
		REG_DBGWCR12_EL1,
		REG_DBGWCR13_EL1,
		REG_DBGWCR14_EL1,
		REG_DBGWCR15_EL1,
		REG_DBGWCR1_EL1,
		REG_DBGWCR2_EL1,
		REG_DBGWCR3_EL1,
		REG_DBGWCR4_EL1,
		REG_DBGWCR5_EL1,
		REG_DBGWCR6_EL1,
		REG_DBGWCR7_EL1,
		REG_DBGWCR8_EL1,
		REG_DBGWCR9_EL1,
		REG_DBGWVR0_EL1,
		REG_DBGWVR10_EL1,
		REG_DBGWVR11_EL1,
		REG_DBGWVR12_EL1,
		REG_DBGWVR13_EL1,
		REG_DBGWVR14_EL1,
		REG_DBGWVR15_EL1,
		REG_DBGWVR1_EL1,
		REG_DBGWVR2_EL1,
		REG_DBGWVR3_EL1,
		REG_DBGWVR4_EL1,
		REG_DBGWVR5_EL1,
		REG_DBGWVR6_EL1,
		REG_DBGWVR7_EL1,
		REG_DBGWVR8_EL1,
		REG_DBGWVR9_EL1,
		REG_DCZID_EL0,
		REG_EL1,
		REG_ESR_EL1,
		REG_ESR_EL2,
		REG_ESR_EL3,
		REG_FAR_EL1,
		REG_FAR_EL2,
		REG_FAR_EL3,
		REG_HACR_EL2,
		REG_HCR_EL2,
		REG_HPFAR_EL2,
		REG_HSTR_EL2,
		REG_IALLU,
		REG_IVAU,
		REG_IALLUIS,
		REG_ID_AA64DFR0_EL1,
		REG_ID_AA64ISAR0_EL1,
		REG_ID_AA64ISAR1_EL1,
		REG_ID_AA64MMFR0_EL1,
		REG_ID_AA64MMFR1_EL1,
		REG_ID_AA64PFR0_EL1,
		REG_ID_AA64PFR1_EL1,
		REG_IPAS2E1IS,
		REG_IPAS2LE1IS,
		REG_IPAS2E1,
		REG_IPAS2LE1,
		REG_ISW,
		REG_IVAC,
		REG_MAIR_EL1,
		REG_MAIR_EL2,
		REG_MAIR_EL3,
		REG_MDCCINT_EL1,
		REG_MDCCSR_EL0,
		REG_MDCR_EL2,
		REG_MDCR_EL3,
		REG_MDRAR_EL1,
		REG_MDSCR_EL1,
		REG_MVFR0_EL1,
		REG_MVFR1_EL1,
		REG_MVFR2_EL1,
		REG_OSDTRRX_EL1,
		REG_OSDTRTX_EL1,
		REG_OSECCR_EL1,
		REG_OSLAR_EL1,
		REG_OSDLR_EL1,
		REG_OSLSR_EL1,
		REG_PAN,
		REG_PAR_EL1,
		REG_PMCCNTR_EL0,
		REG_PMCEID0_EL0,
		REG_PMCEID1_EL0,
		REG_PMCNTENSET_EL0,
		REG_PMCR_EL0,
		REG_PMCNTENCLR_EL0,
		REG_PMINTENCLR_EL1,
		REG_PMINTENSET_EL1,
		REG_PMOVSCLR_EL0,
		REG_PMOVSSET_EL0,
		REG_PMSELR_EL0,
		REG_PMSWINC_EL0,
		REG_PMUSERENR_EL0,
		REG_PMXEVCNTR_EL0,
		REG_PMXEVTYPER_EL0,
		REG_RMR_EL1,
		REG_RMR_EL2,
		REG_RMR_EL3,
		REG_RVBAR_EL1,
		REG_RVBAR_EL2,
		REG_RVBAR_EL3,
		REG_S12E0R,
		REG_S12E0W,
		REG_S12E1R,
		REG_S12E1W,
		REG_S1E0R,
		REG_S1E0W,
		REG_S1E1R,
		REG_S1E1W,
		REG_S1E2R,
		REG_S1E2W,
		REG_S1E3R,
		REG_S1E3W,
		REG_SCR_EL3,
		REG_SDER32_EL3,
		REG_SCTLR_EL1,
		REG_SCTLR_EL2,
		REG_SCTLR_EL3,
		REG_SPSEL,
		REG_TCR_EL1,
		REG_TCR_EL2,
		REG_TCR_EL3,
		REG_TPIDRRO_EL0,
		REG_TPIDR_EL0,
		REG_TPIDR_EL1,
		REG_TPIDR_EL2,
		REG_TPIDR_EL3,
		REG_TTBR0_EL1,
		REG_TTBR1_EL1,
		REG_TTBR0_EL2,
		REG_TTBR0_EL3,
		REG_VAAE1,
		REG_VAAE1IS,
		REG_VAALE1,
		REG_VAALE1IS,
		REG_VAE1,
		REG_VAE1IS,
		REG_VAE2,
		REG_VAE2IS,
		REG_VAE3,
		REG_VAE3IS,
		REG_VALE1,
		REG_VALE1IS,
		REG_VALE2,
		REG_VALE2IS,
		REG_VALE3,
		REG_VALE3IS,
		REG_VBAR_EL1,
		REG_VBAR_EL2,
		REG_VBAR_EL3,
		REG_VMALLE1,
		REG_VMALLE1IS,
		REG_VMALLS12E1,
		REG_VMALLS12E1IS,
		REG_VMPIDR_EL0,
		REG_VPIDR_EL2,
		REG_VTCR_EL2,
		REG_VTTBR_EL2,
		REG_ZVA,
		REG_NUMBER0,
		REG_OSHLD,
		REG_OSHST,
		REG_OSH,
		REG_NUMBER4,
		REG_NSHLD,
		REG_NSHST,
		REG_NSH,
		REG_NUMBER8,
		REG_ISHLD,
		REG_ISHST,
		REG_ISH,
		REG_NUMBER12,
		REG_LD,
		REG_ST,
		REG_SY,
		REG_PMEVCNTR0_EL0,
		REG_PMEVCNTR1_EL0,
		REG_PMEVCNTR2_EL0,
		REG_PMEVCNTR3_EL0,
		REG_PMEVCNTR4_EL0,
		REG_PMEVCNTR5_EL0,
		REG_PMEVCNTR6_EL0,
		REG_PMEVCNTR7_EL0,
		REG_PMEVCNTR8_EL0,
		REG_PMEVCNTR9_EL0,
		REG_PMEVCNTR10_EL0,
		REG_PMEVCNTR11_EL0,
		REG_PMEVCNTR12_EL0,
		REG_PMEVCNTR13_EL0,
		REG_PMEVCNTR14_EL0,
		REG_PMEVCNTR15_EL0,
		REG_PMEVCNTR16_EL0,
		REG_PMEVCNTR17_EL0,
		REG_PMEVCNTR18_EL0,
		REG_PMEVCNTR19_EL0,
		REG_PMEVCNTR20_EL0,
		REG_PMEVCNTR21_EL0,
		REG_PMEVCNTR22_EL0,
		REG_PMEVCNTR23_EL0,
		REG_PMEVCNTR24_EL0,
		REG_PMEVCNTR25_EL0,
		REG_PMEVCNTR26_EL0,
		REG_PMEVCNTR27_EL0,
		REG_PMEVCNTR28_EL0,
		REG_PMEVCNTR29_EL0,
		REG_PMEVCNTR30_EL0,
		REG_PMEVTYPER0_EL0,
		REG_PMEVTYPER1_EL0,
		REG_PMEVTYPER2_EL0,
		REG_PMEVTYPER3_EL0,
		REG_PMEVTYPER4_EL0,
		REG_PMEVTYPER5_EL0,
		REG_PMEVTYPER6_EL0,
		REG_PMEVTYPER7_EL0,
		REG_PMEVTYPER8_EL0,
		REG_PMEVTYPER9_EL0,
		REG_PMEVTYPER10_EL0,
		REG_PMEVTYPER11_EL0,
		REG_PMEVTYPER12_EL0,
		REG_PMEVTYPER13_EL0,
		REG_PMEVTYPER14_EL0,
		REG_PMEVTYPER15_EL0,
		REG_PMEVTYPER16_EL0,
		REG_PMEVTYPER17_EL0,
		REG_PMEVTYPER18_EL0,
		REG_PMEVTYPER19_EL0,
		REG_PMEVTYPER20_EL0,
		REG_PMEVTYPER21_EL0,
		REG_PMEVTYPER22_EL0,
		REG_PMEVTYPER23_EL0,
		REG_PMEVTYPER24_EL0,
		REG_PMEVTYPER25_EL0,
		REG_PMEVTYPER26_EL0,
		REG_PMEVTYPER27_EL0,
		REG_PMEVTYPER28_EL0,
		REG_PMEVTYPER29_EL0,
		REG_PMEVTYPER30_EL0,
		REG_PMCCFILTR_EL0,
		REG_C0,
		REG_C1,
		REG_C2,
		REG_C3,
		REG_C4,
		REG_C5,
		REG_C6,
		REG_C7,
		REG_C8,
		REG_C9,
		REG_C10,
		REG_C11,
		REG_C12,
		REG_C13,
		REG_C14,
		REG_C15,

		REG_SPSR_EL1,
		REG_ELR_EL1,
		REG_SP_EL0,
		REG_CURRENT_EL,
		REG_NZCV,
		REG_FPCR,
		REG_DSPSR_EL0,
		REG_DAIF,
		REG_FPSR,
		REG_DLR_EL0,
		REG_SPSR_EL2,
		REG_ELR_EL2,
		REG_SP_EL1,
		REG_SP_EL2,
		REG_SPSR_IRQ,
		REG_SPSR_ABT,
		REG_SPSR_UND,
		REG_SPSR_FIQ,
		REG_SPSR_EL3,
		REG_ELR_EL3,
		REG_IFSR32_EL2,
		REG_FPEXC32_EL2,
		REG_CNTVOFF_EL2,

		REG_MIDR_EL1,
		REG_MPIDR_EL1,
		REG_REVIDR_EL1,
		REG_ID_PFR0_EL1,
		REG_ID_PFR1_EL1,
		REG_ID_DFR0_EL1,
		REG_ID_AFR0_EL1,
		REG_ID_MMFR0_EL1,
		REG_ID_MMFR1_EL1,
		REG_ID_MMFR2_EL1,
		REG_ID_MMFR3_EL1,
		REG_ID_ISAR0_EL1,
		REG_ID_ISAR1_EL1,
		REG_ID_ISAR2_EL1,
		REG_ID_ISAR3_EL1,
		REG_ID_ISAR4_EL1,
		REG_ID_ISAR5_EL1,
		REG_ID_MMFR4_EL1,

		REG_ICC_IAR0_EL1,
		REG_ICC_EOIR0_EL1,
		REG_ICC_HPPIR0_EL1,
		REG_ICC_BPR0_EL1,
		REG_ICC_AP0R0_EL1,
		REG_ICC_AP0R1_EL1,
		REG_ICC_AP0R2_EL1,
		REG_ICC_AP0R3_EL1,
		REG_ICC_AP1R0_EL1,
		REG_ICC_AP1R1_EL1,
		REG_ICC_AP1R2_EL1,
		REG_ICC_AP1R3_EL1,
		REG_ICC_DIR_EL1,
		REG_ICC_RPR_EL1,
		REG_ICC_IAR1_EL1,
		REG_ICC_EOIR1_EL1,
		REG_ICC_HPPIR1_EL1,
		REG_ICC_BPR1_EL1,
		REG_ICC_CTLR_EL1,
		REG_ICC_SRE_EL1,
		REG_ICC_IGRPEN0_EL1,
		REG_ICC_IGRPEN1_EL1,

		REG_ICC_ASGI1R_EL2,
		REG_ICC_SGI0R_EL2,
		REG_ICH_AP0R0_EL2,
		REG_ICH_AP0R1_EL2,
		REG_ICH_AP0R2_EL2,
		REG_ICH_AP0R3_EL2,
		REG_ICH_AP1R0_EL2,
		REG_ICH_AP1R1_EL2,
		REG_ICH_AP1R2_EL2,
		REG_ICH_AP1R3_EL2,
		REG_ICH_AP1R4_EL2,
		REG_ICC_HSRE_EL2,
		REG_ICH_HCR_EL2,
		REG_ICH_VTR_EL2,
		REG_ICH_MISR_EL2,
		REG_ICH_EISR_EL2,
		REG_ICH_ELRSR_EL2,
		REG_ICH_VMCR_EL2,

		REG_ICH_LR0_EL2,
		REG_ICH_LR1_EL2,
		REG_ICH_LR2_EL2,
		REG_ICH_LR3_EL2,
		REG_ICH_LR4_EL2,
		REG_ICH_LR5_EL2,
		REG_ICH_LR6_EL2,
		REG_ICH_LR7_EL2,
		REG_ICH_LR8_EL2,
		REG_ICH_LR9_EL2,
		REG_ICH_LR10_EL2,
		REG_ICH_LR11_EL2,
		REG_ICH_LR12_EL2,
		REG_ICH_LR13_EL2,
		REG_ICH_LR14_EL2,
		REG_ICH_LR15_EL2,

		REG_ICH_LRC0_EL2,
		REG_ICH_LRC1_EL2,
		REG_ICH_LRC2_EL2,
		REG_ICH_LRC3_EL2,
		REG_ICH_LRC4_EL2,
		REG_ICH_LRC5_EL2,
		REG_ICH_LRC6_EL2,
		REG_ICH_LRC7_EL2,
		REG_ICH_LRC8_EL2,
		REG_ICH_LRC9_EL2,
		REG_ICH_LRC10_EL2,
		REG_ICH_LRC11_EL2,
		REG_ICH_LRC12_EL2,
		REG_ICH_LRC13_EL2,
		REG_ICH_LRC14_EL2,
		REG_ICH_LRC15_EL2,

		REG_ICC_MCTLR_EL3,
		REG_ICC_MSRE_EL3,
		REG_ICC_MGRPEN1_EL3,

		REG_TEECR32_EL1,
		REG_TEEHBR32_EL1,

		REG_ICC_PMR_EL1,
		REG_ICC_SGI1R_EL1,
		REG_ICC_SGI0R_EL1,
		REG_ICC_ASGI1R_EL1,
		REG_ICC_SEIEN_EL1,
		REG_END_REG
	};

	typedef union _ieee754 {
		uint32_t value;
		struct {
			uint32_t fraction:23;
			uint32_t exponent:8;
			uint32_t sign:1;
		};
		float fvalue;
	}ieee754;

	enum OperandClass {
		NONE = 0,
		IMM32,
		IMM64,
		FIMM32,
		REG,
		MULTI_REG,
		SYS_REG,
		MEM_REG,
		MEM_PRE_IDX,
		MEM_POST_IDX,
		MEM_OFFSET,
		MEM_EXTENDED,
		LABEL,
		CONDITION,
		IMPLEMENTATION_SPECIFIC
	};

	enum Register{
		REG_NONE,
		REG_W0,  REG_W1,  REG_W2,  REG_W3,  REG_W4,  REG_W5,  REG_W6,  REG_W7,
		REG_W8,  REG_W9,  REG_W10, REG_W11, REG_W12, REG_W13, REG_W14, REG_W15,
		REG_W16, REG_W17, REG_W18, REG_W19, REG_W20, REG_W21, REG_W22, REG_W23,
		REG_W24, REG_W25, REG_W26, REG_W27, REG_W28, REG_W29, REG_W30, REG_WZR, REG_WSP,
		REG_X0,  REG_X1,  REG_X2,  REG_X3,  REG_X4,  REG_X5,  REG_X6,  REG_X7,
		REG_X8,  REG_X9,  REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
		REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
		REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30, REG_XZR, REG_SP,
		REG_V0,  REG_V1,  REG_V2,  REG_V3,  REG_V4,  REG_V5,  REG_V6,  REG_V7,
		REG_V8,  REG_V9,  REG_V10, REG_V11, REG_V12, REG_V13, REG_V14, REG_V15,
		REG_V16, REG_V17, REG_V18, REG_V19, REG_V20, REG_V21, REG_V22, REG_V23,
		REG_V24, REG_V25, REG_V26, REG_V27, REG_V28, REG_V29, REG_V30, REG_VZR, REG_V31,
		REG_B0,  REG_B1,  REG_B2,  REG_B3,  REG_B4,  REG_B5,  REG_B6,  REG_B7,
		REG_B8,  REG_B9,  REG_B10, REG_B11, REG_B12, REG_B13, REG_B14, REG_B15,
		REG_B16, REG_B17, REG_B18, REG_B19, REG_B20, REG_B21, REG_B22, REG_B23,
		REG_B24, REG_B25, REG_B26, REG_B27, REG_B28, REG_B29, REG_B30, REG_BZR, REG_B31,
		REG_H0,  REG_H1,  REG_H2,  REG_H3,  REG_H4,  REG_H5,  REG_H6,  REG_H7,
		REG_H8,  REG_H9,  REG_H10, REG_H11, REG_H12, REG_H13, REG_H14, REG_H15,
		REG_H16, REG_H17, REG_H18, REG_H19, REG_H20, REG_H21, REG_H22, REG_H23,
		REG_H24, REG_H25, REG_H26, REG_H27, REG_H28, REG_H29, REG_H30, REG_HZR, REG_H31,
		REG_S0,  REG_S1,  REG_S2,  REG_S3,  REG_S4,  REG_S5,  REG_S6,  REG_S7,
		REG_S8,  REG_S9,  REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
		REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
		REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_SZR, REG_S31,
		REG_D0,  REG_D1,  REG_D2,  REG_D3,  REG_D4,  REG_D5,  REG_D6,  REG_D7,
		REG_D8,  REG_D9,  REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,
		REG_D16, REG_D17, REG_D18, REG_D19, REG_D20, REG_D21, REG_D22, REG_D23,
		REG_D24, REG_D25, REG_D26, REG_D27, REG_D28, REG_D29, REG_D30, REG_DZR, REG_D31,
		REG_Q0,  REG_Q1,  REG_Q2,  REG_Q3,  REG_Q4,  REG_Q5,  REG_Q6,  REG_Q7,
		REG_Q8,  REG_Q9,  REG_Q10, REG_Q11, REG_Q12, REG_Q13, REG_Q14, REG_Q15,
		REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23,
		REG_Q24, REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_QZR, REG_Q31,
		REG_PF0,  REG_PF1,  REG_PF2,  REG_PF3,  REG_PF4,  REG_PF5,  REG_PF6,  REG_PF7,
		REG_PF8,  REG_PF9,  REG_PF10, REG_PF11, REG_PF12, REG_PF13, REG_PF14, REG_PF15,
		REG_PF16, REG_PF17, REG_PF18, REG_PF19, REG_PF20, REG_PF21, REG_PF22, REG_PF23,
		REG_PF24, REG_PF25, REG_PF26, REG_PF27, REG_PF28, REG_PF29, REG_PF30, REG_PF31,
		REG_END
	};


	enum Condition {
		COND_EQ,
		COND_NE,
		COND_CS,
		COND_CC,
		COND_MI,
		COND_PL,
		COND_VS,
		COND_VC,
		COND_HI,
		COND_LS,
		COND_GE,
		COND_LT,
		COND_GT,
		COND_LE,
		COND_AL,
		COND_NV,
		END_CONDITION
	};

#define INVERT_CONDITION(N) ((N)^1)

	enum ShiftType {
		SHIFT_NONE, SHIFT_LSL, SHIFT_LSR, SHIFT_ASR,
		SHIFT_ROR,  SHIFT_UXTW, SHIFT_SXTW, SHIFT_SXTX,
		SHIFT_UXTX, SHIFT_SXTB, SHIFT_SXTH, SHIFT_UXTH,
		SHIFT_UXTB, SHIFT_MSL, END_SHIFT
	};

	enum FailureCodes{
		DISASM_SUCCESS,
		INVALID_ARGUMENTS,
		FAILED_TO_DISASSEMBLE_OPERAND,
		FAILED_TO_DISASSEMBLE_OPERATION,
		FAILED_TO_DISASSEMBLE_REGISTER,
		FAILED_TO_DECODE_INSTRUCTION,
		OUTPUT_BUFFER_TOO_SMALL,
		OPERAND_IS_NOT_REGISTER,
		NOT_MEMORY_OPERAND
	};


	enum Group {
		GROUP_UNALLOCATED,
		GROUP_DATA_PROCESSING_IMM,
		GROUP_BRANCH_EXCEPTION_SYSTEM,
		GROUP_LOAD_STORE,
		GROUP_DATA_PROCESSING_REG,
		GROUP_DATA_PROCESSING_SIMD,
		GROUP_DATA_PROCESSING_SIMD2,
		END_GROUP
	};
#ifndef __cplusplus
	typedef enum SystemReg SystemReg;
	typedef enum OperandClass OperandClass;
	typedef enum Register Register;
	typedef enum Condition Condition;
	typedef enum ShiftType ShiftType;
	typedef enum FailureCodes FailureCodes;
	typedef enum Operation Operation;
	typedef enum Group Group;
#endif

	struct InstructionOperand {
		OperandClass operandClass;
		uint32_t reg[5]; //registers or conditions
		uint32_t scale;
		uint32_t dataSize;
		uint32_t elementSize;
		uint32_t index;
		uint64_t immediate;
		ShiftType shiftType;
		uint32_t shiftValueUsed;
		uint32_t shiftValue;
		ShiftType extend;
		uint32_t signedImm;
	};

#ifndef __cplusplus
	typedef struct InstructionOperand InstructionOperand;
#endif

	struct Instruction{
		Group group;
		Operation operation;
		InstructionOperand operands[MAX_OPERANDS];
	};

#ifndef __cplusplus
	typedef struct Instruction Instruction;
#endif


#ifdef __cplusplus
	extern "C" {
#endif
		//Given a uint32_t instructionValue decopose the instruction
		//into its components -> instruction
		uint32_t aarch64_decompose(
				uint32_t instructionValue,
				Instruction* restrict instruction,
				uint64_t address);

		//Get a text representation of the decomposed instruction
		//into outBuffer
		uint32_t aarch64_disassemble(
				Instruction* restrict instruction,
				char* outBuffer,
				uint32_t outBufferSize);

		//Get the text value of the instruction mnemonic
		const char* get_operation(const Instruction* restrict instruction);

		//Get the text value of a given register enumeration (including prefetch registers)
		//This doesn't handle vectored registers
		const char* get_register_name(Register reg);

		//Get the text value of a given system register
		const char* get_system_register_name(SystemReg reg);

		//Get the text value of a given shift type
		const char* get_shift(ShiftType shift);

		const char* get_condition(Condition cond);

		uint32_t get_implementation_specific(
				const InstructionOperand* restrict operand,
				char* outBuffer,
				uint32_t outBufferSize);

		uint32_t get_register_size(Register reg);
#ifdef __cplusplus
	}
}//end namespace
#endif
