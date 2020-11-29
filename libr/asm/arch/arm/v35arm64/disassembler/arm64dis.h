#pragma once

#include <stdint.h>

#ifdef _MSC_VER
#undef REG_NONE // collides with winnt's define
#endif

#ifdef __cplusplus
#define restrict __restrict
#endif

//-----------------------------------------------------------------------------
// registers (non-system)
//-----------------------------------------------------------------------------

enum Register {
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
	REG_Z0,  REG_Z1,  REG_Z2,  REG_Z3,  REG_Z4,  REG_Z5,  REG_Z6,  REG_Z7,
	REG_Z8,  REG_Z9,  REG_Z10, REG_Z11, REG_Z12, REG_Z13, REG_Z14, REG_Z15,
	REG_Z16, REG_Z17, REG_Z18, REG_Z19, REG_Z20, REG_Z21, REG_Z22, REG_Z23,
	REG_Z24, REG_Z25, REG_Z26, REG_Z27, REG_Z28, REG_Z29, REG_Z30, REG_ZZR, REG_Z31,
	REG_P0,  REG_P1,  REG_P2,  REG_P3,  REG_P4,  REG_P5,  REG_P6,  REG_P7,
	REG_P8,  REG_P9,  REG_P10, REG_P11, REG_P12, REG_P13, REG_P14, REG_P15,
	REG_P16, REG_P17, REG_P18, REG_P19, REG_P20, REG_P21, REG_P22, REG_P23,
	REG_P24, REG_P25, REG_P26, REG_P27, REG_P28, REG_P29, REG_P30, REG_P31,
	REG_PF0,  REG_PF1,  REG_PF2,  REG_PF3,  REG_PF4,  REG_PF5,  REG_PF6,  REG_PF7,
	REG_PF8,  REG_PF9,  REG_PF10, REG_PF11, REG_PF12, REG_PF13, REG_PF14, REG_PF15,
	REG_PF16, REG_PF17, REG_PF18, REG_PF19, REG_PF20, REG_PF21, REG_PF22, REG_PF23,
	REG_PF24, REG_PF25, REG_PF26, REG_PF27, REG_PF28, REG_PF29, REG_PF30, REG_PF31,
	REG_END
};

/* DDDDDD EEEEEE XXXXXXXXXXXXXXXXXXXX
	data_sz is 6 bits
	elem_sz is 6 bits
	enum    is 20 bits */
#define REG_ENUM(x) ((enum Register)((x) & 0xFFFFF))
#define REG_ESIZE(x) (((x)>>20) & 0x3F)
#define REG_DSIZE(x) (((x)>>26) & 0x3F)
#define REG_ARRSPEC(x) (((x)>>20) & 0xFFF)
#define REG_CONSTRUCT(DSIZE,ESIZE,ENUM_ID) ( ((DSIZE)<<26) | ((ESIZE)<<20) | (ENUM_ID) )

//-----------------------------------------------------------------------------
// disassembly target features
//-----------------------------------------------------------------------------

/* see encodingindex.xml for strings like "arch_version="ARMv8.X-XXX" */
/* see also the HasXXX() functions in pcode */
#define ARCH_FEATURE_DGH ((uint64_t)1<<0) // added in ARMv8.0
#define ARCH_FEATURE_LOR ((uint64_t)1<<1) // added in ARMv8.1
#define ARCH_FEATURE_LSE ((uint64_t)1<<2) // added in ARMv8.1
#define ARCH_FEATURE_RDMA ((uint64_t)1<<3) // added in ARMv8.1
#define ARCH_FEATURE_BF16 ((uint64_t)1<<4) // added in ARMv8.2
#define ARCH_FEATURE_DotProd ((uint64_t)1<<5) // added in ARMv8.2
#define ARCH_FEATURE_FHM ((uint64_t)1<<6) // added in ARMv8.2
#define ARCH_FEATURE_FP16 ((uint64_t)1<<7) // added in ARMv8.2
#define ARCH_FEATURE_I8MM ((uint64_t)1<<8) // added in ARMv8.2
#define ARCH_FEATURE_SHA2 ((uint64_t)1<<9) // added in ARMv8.2
#define ARCH_FEATURE_SHA3 ((uint64_t)1<<10) // added in ARMv8.2
#define ARCH_FEATURE_SM3 ((uint64_t)1<<11) // added in ARMv8.2
#define ARCH_FEATURE_SM4 ((uint64_t)1<<12) // added in ARMv8.2
#define ARCH_FEATURE_CompNum ((uint64_t)1<<13) // added in ARMv8.3
#define ARCH_FEATURE_JConv ((uint64_t)1<<14) // added in ARMv8.3
#define ARCH_FEATURE_PAuth ((uint64_t)1<<15) // added in ARMv8.3
#define ARCH_FEATURE_RCPC ((uint64_t)1<<16) // added in ARMv8.3
#define ARCH_FEATURE_CondM ((uint64_t)1<<17) // added in ARMv8.4
#define ARCH_FEATURE_RCPC_84 ((uint64_t)1<<18) // added in ARMv8.4, corresponding to "ARMv8.4-RCPC" in spec
#define ARCH_FEATURE_Trace ((uint64_t)1<<19) // added in ARMv8.4
#define ARCH_FEATURE_BTI ((uint64_t)1<<20) // added in ARMv8.5, branch target identification
#define ARCH_FEATURE_CondM_85 ((uint64_t)1<<21) // added in ARMv8.5, corresponding to "ARMv8.5-CondM" in spec
#define ARCH_FEATURE_FRINT ((uint64_t)1<<22) // added in ARMv8.5
#define ARCH_FEATURE_MemTag ((uint64_t)1<<23) // added in ARMv8.5
#define ARCH_FEATURE_RAS ((uint64_t)1<<24) // ?
#define ARCH_FEATURE_SPE ((uint64_t)1<<25) // ?
#define ARCH_FEATURE_ARMv8_0 ((uint64_t)1<<26)
#define ARCH_FEATURE_ARMv8_1 ((uint64_t)1<<27)
#define ARCH_FEATURE_ARMv8_2 ((uint64_t)1<<28)
#define ARCH_FEATURE_ARMv8_3 ((uint64_t)1<<29)
#define ARCH_FEATURE_ARMv8_4 ((uint64_t)1<<30)
#define ARCH_FEATURE_ARMv8_5 ((uint64_t)1<<31)

/* see the HaveXXX() functions in pcode */
#define ARCH_FEATURE_AESExt ((uint64_t)1<<0)
#define ARCH_FEATURE_AtomicExt ((uint64_t)1<<1)
#define ARCH_FEATURE_BF16Ext ((uint64_t)1<<2)
#define ARCH_FEATURE_BTIExt ((uint64_t)1<<3)
#define ARCH_FEATURE_Bit128PMULLExt ((uint64_t)1<<4)
#define ARCH_FEATURE_CRCExt ((uint64_t)1<<5)
#define ARCH_FEATURE_DGHExt ((uint64_t)1<<6)
#define ARCH_FEATURE_DITExt ((uint64_t)1<<7)
#define ARCH_FEATURE_DOTPExt ((uint64_t)1<<8)
#define ARCH_FEATURE_FCADDExt ((uint64_t)1<<9)
#define ARCH_FEATURE_FJCVTZSExt ((uint64_t)1<<10)
#define ARCH_FEATURE_FP16Ext ((uint64_t)1<<11)
#define ARCH_FEATURE_FP16MulNoRoundingToFP32Ext ((uint64_t)1<<12)
#define ARCH_FEATURE_FlagFormatExt ((uint64_t)1<<13)
#define ARCH_FEATURE_FlagManipulateExt ((uint64_t)1<<14)
#define ARCH_FEATURE_FrintExt ((uint64_t)1<<15)
#define ARCH_FEATURE_Int8MatMulExt ((uint64_t)1<<16)
#define ARCH_FEATURE_MTEExt ((uint64_t)1<<17)
#define ARCH_FEATURE_PACExt ((uint64_t)1<<18)
#define ARCH_FEATURE_PANExt ((uint64_t)1<<19)
#define ARCH_FEATURE_QRDMLAHExt ((uint64_t)1<<20)
#define ARCH_FEATURE_RASExt ((uint64_t)1<<21)
#define ARCH_FEATURE_SBExt ((uint64_t)1<<22)
#define ARCH_FEATURE_SHA1Ext ((uint64_t)1<<23)
#define ARCH_FEATURE_SHA256Ext ((uint64_t)1<<24)
#define ARCH_FEATURE_SHA3Ext ((uint64_t)1<<25)
#define ARCH_FEATURE_SHA512Ext ((uint64_t)1<<26)
#define ARCH_FEATURE_SM3Ext ((uint64_t)1<<27)
#define ARCH_FEATURE_SM4Ext ((uint64_t)1<<28)
#define ARCH_FEATURE_SSBSExt ((uint64_t)1<<29)
#define ARCH_FEATURE_SVE ((uint64_t)1<<30)
#define ARCH_FEATURE_SVEFP32MatMulExt ((uint64_t)1<<31)
#define ARCH_FEATURE_SVEFP64MatMulExt ((uint64_t)1<<32)
#define ARCH_FEATURE_SelfHostedTrace ((uint64_t)1<<33)
#define ARCH_FEATURE_StatisticalProfiling ((uint64_t)1<<34)
#define ARCH_FEATURE_UAOExt ((uint64_t)1<<35)
#define ARCH_FEATURE_NVExt ((uint64_t)1<<36)
#define ARCH_FEATURE_VirtHostExt ((uint64_t)1<<37)
#define ARCH_FEATURE_TLBI ((uint64_t)1<<38) // ARMv8.4-TLBI, see tlbi_sys.html
#define ARCH_FEATURE_DCPoP ((uint64_t)1<<39) // ARMv8.2-DCPoP
#define ARCH_FEATURE_DCCVADP ((uint64_t)1<<40) // ARMv8.2-DCCVADP

#define ARCH_FEATURES_ALL 0xFFFFFFFFFFFFFFFF

//-----------------------------------------------------------------------------
// decode return values
//-----------------------------------------------------------------------------

#define DECODE_STATUS_OK 0 // success! the resulting named encoding is accurate
#define DECODE_STATUS_RESERVED -1 // spec says this space is reserved, eg: RESERVED_36_asisdsame
#define DECODE_STATUS_UNMATCHED -2 // decoding logic fell through the spec's checks
#define DECODE_STATUS_UNALLOCATED -3 // spec says this space is unallocated, eg: UNALLOCATED_10_branch_reg
#define DECODE_STATUS_UNDEFINED -4 // spec says this encoding is undefined, often due to a disallowed field
									// or a missing feature, eg: "if !HaveBF16Ext() then UNDEFINED;"
#define DECODE_STATUS_END_OF_INSTRUCTION -5 // spec decode EndOfInstruction(), instruction executes as NOP
#define DECODE_STATUS_LOST -6 // descended past a checks, ie: "SEE encoding_up_higher"
#define DECODE_STATUS_UNREACHABLE -7 // ran into pcode Unreachable()

//-----------------------------------------------------------------------------
// floating point condition register values
//-----------------------------------------------------------------------------

#define FPCR_AHP ((uint64_t)1 << 26)
#define FPCR_DN ((uint64_t)1 << 25)
#define FPCR_FZ ((uint64_t)1 << 24)
#define FPCR_RMode (uint64_t)0xC00000 // [23,22]
#define FPCR_Stride (uint64_t)0x300000 // [21,20]
#define FPCR_FZ16 ((uint64_t)1 << 19)
#define FPCR_Len (uint64_t)0x30000 // [18:16]
#define FPCR_IDE ((uint64_t)1 << 15)
#define FPCR_IXE ((uint64_t)1 << 12)
#define FPCR_UFE ((uint64_t)1 << 11)
#define FPCR_OFE ((uint64_t)1 << 10)
#define FPCR_DZE ((uint64_t)1 << 9)
#define FPCR_IOE ((uint64_t)1 << 8)

#define FPCR_GET_AHP(X) SLICE(X,26,26)
#define FPCR_GET_DN(X) SLICE(X,25,25)
#define FPCR_GET_FZ(X) SLICE(X,24,24)
#define FPCR_GET_RMode(X) SLICE(X,23,22)
#define FPCR_GET_Stride(X) SLICE(X,21,20)
#define FPCR_GET_FZ16(X) SLICE(X,19,19)
#define FPCR_GET_Len(X) SLICE(X,18,16)
#define FPCR_GET_IDE(X) SLICE(X,15,15)
#define FPCR_GET_IXE(X) SLICE(X,12,12)
#define FPCR_GET_UFE(X) SLICE(X,11,11)
#define FPCR_GET_OFE(X) SLICE(X,10,10)
#define FPCR_GET_DZE(X) SLICE(X,9,9)
#define FPCR_GET_IOE(X) SLICE(X,8,8)

//-----------------------------------------------------------------------------
// disassembly context (INPUT into disassembler)
//-----------------------------------------------------------------------------

typedef struct context_ {
	uint32_t insword;
	uint64_t address;
	uint64_t features0; // bitmask of ARCH_FEATURE_XXX
	uint64_t features1; // bitmask of ARCH_FEATURE_XXX
	//uint32_t exception_level; // used by AArch64.CheckSystemAccess()
	//uint32_t security_state;
	uint8_t pstate_btype; // used by BTypeCompatible_BTI()
	bool BTypeCompatible;
	uint8_t BTypeNext;
	bool halted; // is CPU halted? used by Halted()
	uint64_t FPCR; // floating point control register
} context;

//-----------------------------------------------------------------------------
// Instruction definition (OUTPUT from disassembler)
//-----------------------------------------------------------------------------

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
	STR_IMM,
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
	NAME,
	IMPLEMENTATION_SPECIFIC
};

enum Condition {
	COND_EQ, COND_NE, COND_CS, COND_CC,
	COND_MI, COND_PL, COND_VS, COND_VC,
	COND_HI, COND_LS, COND_GE, COND_LT,
	COND_GT, COND_LE, COND_AL, COND_NV,
	END_CONDITION
};

enum FailureCodes {
	FC_OK = 0, FC_ERR
};

enum ShiftType {
	ShiftType_NONE, ShiftType_LSL, ShiftType_LSR, ShiftType_ASR,
	ShiftType_ROR, ShiftType_UXTW, ShiftType_SXTW, ShiftType_SXTX,
	ShiftType_UXTX, ShiftType_SXTB, ShiftType_SXTH, ShiftType_UXTH,
	ShiftType_UXTB, ShiftType_MSL, ShiftType_END,
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
	uint32_t indexUsed;
	uint32_t index;
	uint64_t immediate;
	ShiftType shiftType;
	uint32_t shiftValueUsed;
	uint32_t shiftValue;
	ShiftType extend;
	uint32_t signedImm;
	char pred_qual; // predicate register qualifier ('z' or 'm')
	char mul_vl; // whether MEM_OFFSET has the offset "mul vl"
	char name[8];
};

#ifndef __cplusplus
	typedef struct InstructionOperand InstructionOperand;
#endif

#define MAX_OPERANDS 5

struct Instruction {
	uint32_t insword;
	enum ENCODING encoding;

	enum Operation operation;
	InstructionOperand operands[MAX_OPERANDS];

	/* specification scratchpad: ~300 possible named fields */
	uint64_t A;
	uint64_t ADD;
	uint64_t AccType_NORMAL;
	uint64_t AccType_STREAM;
	uint64_t AccType_UNPRIV;
	uint64_t AccType_VEC;
	uint64_t AccType_VECSTREAM;
	uint64_t B;
	uint64_t C;
	uint64_t CRm;
	uint64_t CRn;
	uint64_t D;
	uint64_t E;
	uint64_t EDSCR_HDE;
	uint64_t H;
	uint64_t HCR_EL2_E2H, HCR_EL2_NV, HCR_EL2_NV1, HCR_EL2_TGE;
	uint64_t L;
	uint64_t LL;
	uint64_t M;
	uint64_t N;
	uint64_t O;
	uint64_t Op0, Op3;
	uint64_t P;
	uint64_t PSTATE_EL;
	uint64_t PSTATE_UAO;
	uint64_t Pd, Pdm, Pdn, Pg, Pm, Pn, Pt;
	uint64_t Q, Qa, Qd, Qm, Qn, Qt, Qt2;
	uint64_t R, Ra, Rd, Rdn, Rm, Rmhi, Rn, Rs, Rt, Rt2;
	uint64_t S, Sa, Sd, Sm, Sn, St, St2;
	uint64_t S10;
	uint64_t SCTLR_EL1_UMA;
	uint64_t Sys_AT;
	uint64_t Sys_DC;
	uint64_t Sys_IC;
	uint64_t Sys_TLBI;
	uint64_t T;
	uint64_t U;
	uint64_t US;
	uint64_t V, Va, Vd, Vdn, Vm, Vn, Vt, Vt2;
	uint64_t W, Wa, Wd, Wdn, Wm, Wn, Ws, Wt, Wt2;
	uint64_t Xa, Xd, Xdn, Xm, Xn, Xs, Xt, Xt2;
	uint64_t Z, Za, Zd, Zda, Zdn, Zm, Zn, Zt;
	uint64_t a;
	uint64_t abs;
	uint64_t ac;
	uint64_t acc;
	uint64_t acctype;
	uint64_t accumulate;
	uint64_t amount;
	uint64_t and_test;
	uint64_t asimdimm;
	uint64_t b;
	uint64_t b40;
	uint64_t b5;
	uint64_t bit_pos;
	uint64_t bit_val;
	uint64_t branch_type;
	uint64_t c;
	uint64_t cmode;
	uint64_t cmp, cmph, cmpl, cmp_eq, cmp_with_zero;
	uint64_t comment;
	uint64_t comparison;
	uint64_t cond;
	uint64_t condition;
	uint64_t container_size;
	uint64_t containers;
	uint64_t countop;
	uint64_t crc32c;
	uint64_t csize;
	uint64_t d;
	uint64_t dtype, dtypeh, dtypel;
	uint64_t d_esize;
	uint64_t da;
	uint64_t data;
	uint64_t datasize;
	uint64_t decrypt;
	uint64_t destsize;
	uint64_t dm;
	uint64_t dn;
	uint64_t domain;
	uint64_t dst_index;
	uint64_t dst_unsigned;
	uint64_t dstsize;
	uint64_t e;
	uint64_t elements;
	uint64_t elements_per_container;
	uint64_t else_inc;
	uint64_t else_inv;
	uint64_t elsize;
	uint64_t eq;
	uint64_t esize;
	uint64_t exact;
	uint64_t extend;
	uint64_t extend_type;
	uint64_t f, ff;
	uint64_t field;
	uint64_t flags;
	uint64_t fltsize;
	uint64_t fpop;
	uint64_t fracbits;
	uint64_t ftype;
	uint64_t g;
	uint64_t h;
	uint64_t has_result;
	uint64_t hi;
	uint64_t hw;
	uint64_t i, i1, i2, i3h, i3l;
	uint64_t idxdsize;
	uint64_t imm;
	uint64_t imm1;
	uint64_t imm12;
	uint64_t imm13;
	uint64_t imm14;
	uint64_t imm16;
	uint64_t imm19;
	uint64_t imm2;
	uint64_t imm26;
	uint64_t imm3;
	uint64_t imm4;
	uint64_t imm5;
	uint64_t imm5b;
	uint64_t imm6;
	uint64_t imm64;
	uint64_t imm7;
	uint64_t imm8;
	uint64_t imm8h;
	uint64_t imm8l;
	uint64_t imm9;
	uint64_t imm9h;
	uint64_t imm9l;
	uint64_t immb;
	uint64_t immh;
	uint64_t immhi;
	uint64_t immlo;
	uint64_t immr;
	uint64_t imms;
	uint64_t index;
	uint64_t intsize;
	uint64_t int_U;
	uint64_t invert;
	uint64_t inzero;
	uint64_t isBefore;
	uint64_t is_tbl;
	uint64_t iszero;
	uint64_t ldacctype;
	uint64_t len;
	uint64_t level;
	uint64_t lsb;
	uint64_t lt;
	uint64_t m;
	uint64_t mask;
	uint64_t mbytes;
	uint64_t memop;
	uint64_t merging;
	uint64_t min;
	uint64_t minimum;
	uint64_t msb;
	uint64_t msize;
	uint64_t msz;
	uint64_t mulx_op;
	uint64_t n;
	uint64_t ne;
	uint64_t neg;
	uint64_t neg_i;
	uint64_t neg_r;
	uint64_t negated;
	uint64_t nreg;
	uint64_t nzcv;
	uint64_t o0, o1, o2, o3;
	uint64_t offs_size;
	uint64_t offs_unsigned;
	uint64_t offset;
	uint64_t op1_neg;
	uint64_t op1_unsigned;
	uint64_t op, op0, op1, op2, op3, op4, op21, op31, op54;
	uint64_t op2_unsigned;
	uint64_t op3_neg;
	uint64_t opa_neg;
	uint64_t opc;
	uint64_t opc2;
	uint64_t opcode, opcode2;
	uint64_t operand;
	uint64_t operation_;
	uint64_t opt, option;
	uint64_t osize;
	uint64_t pac;
	uint64_t page;
	uint64_t pair;
	uint64_t pairs;
	uint64_t part;
	uint64_t part1;
	uint64_t pat;
	uint64_t pattern;
	uint64_t poly;
	uint64_t pos;
	uint64_t position;
	uint64_t postindex;
	uint64_t pref_hint;
	uint64_t prfop;
	uint64_t ptype;
	uint64_t rd;
	uint64_t read;
	uint64_t regs;
	uint64_t regsize;
	uint64_t replicate;
	uint64_t rmode;
	uint64_t rot;
	uint64_t round;
	uint64_t rounding;
	uint64_t rpt;
	uint64_t rsize;
	uint64_t s;
	uint64_t s_esize;
	uint64_t saturating;
	uint64_t scale;
	uint64_t sel;
	uint64_t sel_a;
	uint64_t sel_b;
	uint64_t selem;
	uint64_t setflags;
	uint64_t sf;
	uint64_t sh;
	uint64_t shift;
	uint64_t shift_amount;
	uint64_t shift_type;
	uint64_t signal_all_nans;
	uint64_t signed_;
	uint64_t simm7;
	uint64_t size;
	uint64_t source_is_sp;
	uint64_t src_index;
	uint64_t src_unsigned;
	uint64_t srcsize;
	uint64_t ssize, ssz;
	uint64_t stacctype;
	uint64_t stream;
	uint64_t sub_i;
	uint64_t sub_op;
	uint64_t sub_r;
	uint64_t swsize;
	uint64_t sys_crm;
	uint64_t sys_crn;
	uint64_t sys_op0;
	uint64_t sys_op1;
	uint64_t sys_op2;
	uint64_t sz;
	uint64_t t;
	uint64_t t2;
	uint64_t tag_checked;
	uint64_t tag_offset;
	uint64_t target_level;
	uint64_t tmask;
	uint64_t tsize;
	uint64_t tsz;
	uint64_t tszh;
	uint64_t tszl;
	uint64_t types;
	uint64_t uimm4;
	uint64_t uimm6;
	uint64_t unpriv_at_el1;
	uint64_t unpriv_at_el2;
	uint64_t uns;
	uint64_t unsigned_;
	uint64_t use_key_a;
	uint64_t user_access_override;
	uint64_t wback;
	uint64_t wmask;
	uint64_t writeback;
	uint64_t xs;
	uint64_t zero_data;
};

#ifndef __cplusplus
typedef struct Instruction Instruction;
#endif

//-----------------------------------------------------------------------------
// disassembly function prototypes, return values
//-----------------------------------------------------------------------------

/* these get returned by the disassemble_instruction() function */
enum FailureCode {
	DISASM_SUCCESS=0,
	INVALID_ARGUMENTS,
	FAILED_TO_DISASSEMBLE_OPERAND,
	FAILED_TO_DISASSEMBLE_OPERATION,
	FAILED_TO_DISASSEMBLE_REGISTER,
	FAILED_TO_DECODE_INSTRUCTION,
	OUTPUT_BUFFER_TOO_SMALL,
	OPERAND_IS_NOT_REGISTER,
	NOT_MEMORY_OPERAND
};

#ifdef __cplusplus
extern "C" {
#endif
// given a uint32_t instructionValue decompose the instruction
// into its components -> instruction
int aarch64_decompose(uint32_t insword, Instruction *inst, uint64_t addr);

// get a text representation of the decomposed instruction
// into outBuffer
int aarch64_disassemble(Instruction *instruction, char *buf, size_t buf_sz);

// get the text value of the instruction mnemonic
const char *get_operation(const Instruction *instruction);

// get the text value of a given register enumeration (including prefetch registers)
// includes data size and element size
const char *get_register_name(uint32_t reg);
const char *get_register_arrspec(uint32_t reg);
int get_register_full(uint32_t reg, char *result);
unsigned get_register_size(uint32_t reg);

//Get the text value of a given shift type
const char *get_shift(ShiftType shift);

const char *get_condition(Condition cond);

uint32_t get_implementation_specific(
		const InstructionOperand *operand,
		char *outBuffer,
		uint32_t outBufferSize);

/* undocumented: */
void print_instruction(Instruction *instr);

#ifdef __cplusplus
}
#endif


