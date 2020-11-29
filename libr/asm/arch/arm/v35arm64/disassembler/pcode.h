#define INSWORD (ctx->insword)
#define UNDEFINED { return DECODE_STATUS_UNDEFINED; }
#define UNMATCHED { return DECODE_STATUS_UNMATCHED; }
#define RESERVED(X) { return DECODE_STATUS_RESERVED; }
#define UNALLOCATED(X) {dec->encoding = (X); return DECODE_STATUS_UNALLOCATED; }
#define ENDOFINSTRUCTION { return DECODE_STATUS_END_OF_INSTRUCTION; }
#define SEE { return DECODE_STATUS_LOST; }
#define UNREACHABLE { return DECODE_STATUS_UNREACHABLE; }
/* do NOT return immediately! post-decode pcode might still need to run */ 
#define OK(X) {dec->encoding = (X); dec->operation = enc_to_oper(X); rc = DECODE_STATUS_OK; }

#define BITMASK(N) (((uint64_t)1<<(N))-1)
#define SLICE(X,MSB,LSB) (((X)>>(LSB)) & BITMASK((MSB)-(LSB)+1)) /* get bits [MSB,LSB] */
#define CONCAT(A,B,B_WIDTH) (((A)<<(B_WIDTH))|(B))
#define NOT(X,X_WIDTH) ((X) ^ BITMASK(X_WIDTH))

#define DecodeBitMasksCheckUndefined(N,imms) if((N==0 && (imms==0x3D || imms==0x3B || imms==0x37 || imms==0x2F || imms==0x1F)) || (N==1 && imms==0x3F)) { return DECODE_STATUS_UNDEFINED; }

#define UINT(x) (unsigned int)(x)
#define SInt(X,X_WIDTH) SignExtend((X),(X_WIDTH))
#define INT(x) (signed int)(x)
#define ZeroExtend(X,Y) (uint64_t)(X)
#define LSL(X,Y) ((X)<<(Y))

#define LOG2_TAG_GRANULE 4
#define TAG_GRANULE (1<<LOG2_TAG_GRANULE)

/* pcode -> cpp booleans */
#define TRUE true
#define FALSE false

/* these calls just check generated per-iform boolean variables */
#define EncodingLabeled32Bit() (encoding32)
#define EncodingLabeled64Bit() (encoding64)

#define HasARMv8_0() ((ctx->features0) & ARCH_FEATURE_ARMv8_0)
#define HasARMv8_1() ((ctx->features0) & ARCH_FEATURE_ARMv8_1)
#define HasARMv8_2() ((ctx->features0) & ARCH_FEATURE_ARMv8_2)
#define HasARMv8_3() ((ctx->features0) & ARCH_FEATURE_ARMv8_3)
#define HasARMv8_4() ((ctx->features0) & ARCH_FEATURE_ARMv8_4)
#define HasARMv8_5() ((ctx->features0) & ARCH_FEATURE_ARMv8_5)

#define HasDGH() ((ctx->features0) & ARCH_FEATURE_DGH)
#define HasLOR() ((ctx->features0) & ARCH_FEATURE_LOR)
#define HasLSE() ((ctx->features0) & ARCH_FEATURE_LSE)
#define HasRDMA() ((ctx->features0) & ARCH_FEATURE_RDMA)
#define HasBF16() ((ctx->features0) & ARCH_FEATURE_BF16)
#define HasDotProd() ((ctx->features0) & ARCH_FEATURE_DotProd)
#define HasFHM() ((ctx->features0) & ARCH_FEATURE_FHM)
#define HasFP16() ((ctx->features0) & ARCH_FEATURE_FP16)
#define HasI8MM() ((ctx->features0) & ARCH_FEATURE_I8MM)
#define HasSHA2() ((ctx->features0) & ARCH_FEATURE_SHA2)
#define HasSHA3() ((ctx->features0) & ARCH_FEATURE_SHA3)
#define HasSM3() ((ctx->features0) & ARCH_FEATURE_SM3)
#define HasSM4() ((ctx->features0) & ARCH_FEATURE_SM4)
#define HasCompNum() ((ctx->features0) & ARCH_FEATURE_CompNum)
#define HasJConv() ((ctx->features0) & ARCH_FEATURE_JConv)
#define HasPAuth() ((ctx->features0) & ARCH_FEATURE_PAuth)
#define HasRCPC() ((ctx->features0) & ARCH_FEATURE_RCPC)
#define HasCondM() ((ctx->features0) & ARCH_FEATURE_CondM)
#define HasRCPC_84() ((ctx->features0) & ARCH_FEATURE_RCPC_84)
#define HasTrace() ((ctx->features0) & ARCH_FEATURE_Trace)
#define HasBTI() ((ctx->features0) & ARCH_FEATURE_BTI)
#define HasCondM_85() ((ctx->features0) & ARCH_FEATURE_CondM_85)
#define HasFRINT() ((ctx->features0) & ARCH_FEATURE_FRINT)
#define HasMemTag() ((ctx->features0) & ARCH_FEATURE_MemTag)
#define HasRAS() ((ctx->features0) & ARCH_FEATURE_RAS)
#define HasSPE() ((ctx->features0) & ARCH_FEATURE_SPE)

#define HaveAESExt() ((ctx->features1) & ARCH_FEATURE_AESExt)
#define HaveAtomicExt() ((ctx->features1) & ARCH_FEATURE_AtomicExt)
#define HaveBF16Ext() ((ctx->features1) & ARCH_FEATURE_BF16Ext)
#define HaveBTIExt() ((ctx->features1) & ARCH_FEATURE_BTIExt)
#define HaveBit128PMULLExt() ((ctx->features1) & ARCH_FEATURE_Bit128PMULLExt)
#define HaveCRCExt() ((ctx->features1) & ARCH_FEATURE_CRCExt)
#define HaveDGHExt() ((ctx->features1) & ARCH_FEATURE_DGHExt)
#define HaveDITExt() ((ctx->features1) & ARCH_FEATURE_DITExt)
#define HaveDOTPExt() ((ctx->features1) & ARCH_FEATURE_DOTPExt)
#define HaveFCADDExt() ((ctx->features1) & ARCH_FEATURE_FCADDExt)
#define HaveFJCVTZSExt() ((ctx->features1) & ARCH_FEATURE_FJCVTZSExt)
#define HaveFP16Ext() ((ctx->features1) & ARCH_FEATURE_FP16Ext)
#define HaveFP16MulNoRoundingToFP32Ext() ((ctx->features1) & ARCH_FEATURE_FP16MulNoRoundingToFP32Ext)
#define HaveFlagFormatExt() ((ctx->features1) & ARCH_FEATURE_FlagFormatExt)
#define HaveFlagManipulateExt() ((ctx->features1) & ARCH_FEATURE_FlagManipulateExt)
#define HaveFrintExt() ((ctx->features1) & ARCH_FEATURE_FrintExt)
#define HaveInt8MatMulExt() ((ctx->features1) & ARCH_FEATURE_Int8MatMulExt)
#define HaveMTEExt() ((ctx->features1) & ARCH_FEATURE_MTEExt)
#define HavePACExt() ((ctx->features1) & ARCH_FEATURE_PACExt)
#define HavePANExt() ((ctx->features1) & ARCH_FEATURE_PANExt)
#define HaveQRDMLAHExt() ((ctx->features1) & ARCH_FEATURE_QRDMLAHExt)
#define HaveRASExt() ((ctx->features1) & ARCH_FEATURE_RASExt)
#define HaveSBExt() ((ctx->features1) & ARCH_FEATURE_SBExt)
#define HaveSHA1Ext() ((ctx->features1) & ARCH_FEATURE_SHA1Ext)
#define HaveSHA256Ext() ((ctx->features1) & ARCH_FEATURE_SHA256Ext)
#define HaveSHA3Ext() ((ctx->features1) & ARCH_FEATURE_SHA3Ext)
#define HaveSHA512Ext() ((ctx->features1) & ARCH_FEATURE_SHA512Ext)
#define HaveSM3Ext() ((ctx->features1) & ARCH_FEATURE_SM3Ext)
#define HaveSM4Ext() ((ctx->features1) & ARCH_FEATURE_SM4Ext)
#define HaveSSBSExt() ((ctx->features1) & ARCH_FEATURE_SSBSExt)
#define HaveSVE() ((ctx->features1) & ARCH_FEATURE_SVE)
#define HaveSVEFP32MatMulExt() ((ctx->features1) & ARCH_FEATURE_SVEFP32MatMulExt)
#define HaveSVEFP64MatMulExt() ((ctx->features1) & ARCH_FEATURE_SVEFP64MatMulExt)
#define HaveSelfHostedTrace() ((ctx->features1) & ARCH_FEATURE_SelfHostedTrace)
#define HaveStatisticalProfiling() ((ctx->features1) & ARCH_FEATURE_StatisticalProfiling)
#define HaveUAOExt() ((ctx->features1) & ARCH_FEATURE_UAOExt)
#define HaveNVExt() ((ctx->features1) & ARCH_FEATURE_NVExt)
#define HaveVirtHostExt() ((ctx->features1) & ARCH_FEATURE_VirtHostExt)
#define HaveTLBI() ((ctx->features1) & ARCH_FEATURE_TLBI)
#define HaveDCPoP() ((ctx->features1) & ARCH_FEATURE_DCPoP)
#define HaveDCCVADP() ((ctx->features1) & ARCH_FEATURE_DCCVADP)

#define SetBTypeCompatible(X) ctx->BTypeCompatible = (X)
#define SetBTypeNext(X) ctx->BTypeNext = (X)
#define Halted() ctx->halted

enum SystemOp {
	Sys_ERROR=0,
	Sys_AT,
	Sys_DC,
	Sys_IC,
	Sys_TLBI
};

enum ReduceOp {
	ReduceOp_ERROR=0,
	ReduceOp_ADD,
	ReduceOp_FADD,
	ReduceOp_FMIN,
	ReduceOp_FMAX,
	ReduceOp_FMINNUM,
	ReduceOp_FMAXNUM,
};

enum LogicalOp {
	LogicalOp_ERROR=0,
	LogicalOp_AND,
	LogicalOp_EOR,
	LogicalOp_ORR
};

enum BranchType {
	BranchType_ERROR=0,
	BranchType_DIRCALL,	 // Direct Branch with link
	BranchType_INDCALL,	 // Indirect Branch with link
	BranchType_ERET,		// Exception return (indirect)
	BranchType_DBGEXIT,	 // Exit from Debug state
	BranchType_RET,		 // Indirect branch with function return hint
	BranchType_DIR,		 // Direct branch
	BranchType_INDIR,	   // Indirect branch
	BranchType_EXCEPTION,   // Exception entry
	BranchType_RESET,	   // Reset
	BranchType_UNKNOWN	// Other
};

enum VBitOp {
	VBitOp_ERROR=0,
	VBitOp_VBIF,
	VBitOp_VBIT,
	VBitOp_VBSL,
	VBitOp_VEOR
};

enum SystemHintOp {
	SystemHintOp_ERROR=0,
	SystemHintOp_NOP,
	SystemHintOp_YIELD,
	SystemHintOp_WFE,
	SystemHintOp_WFI,
	SystemHintOp_SEV,
	SystemHintOp_SEVL,
	SystemHintOp_DGH,
	SystemHintOp_ESB,
	SystemHintOp_PSB,
	SystemHintOp_TSB,
	SystemHintOp_BTI,
	SystemHintOp_CSDB
};

enum ImmediateOp {
	ImmediateOp_ERROR=0,
	ImmediateOp_MOVI,
	ImmediateOp_MVNI,
	ImmediateOp_ORR,
	ImmediateOp_BIC
};

enum AccType {
	AccType_ERROR=0,
	AccType_ATOMICRW,
	AccType_ATOMIC,
	AccType_LIMITEDORDERED,
	AccType_ORDEREDATOMICRW,
	AccType_ORDEREDATOMIC,
	AccType_ORDERED
};

enum CompareOp {
	CompareOp_ERROR=0,
	CompareOp_EQ,
	CompareOp_GE,
	CompareOp_GT,
	CompareOp_LE,
	CompareOp_LT
};

enum CountOp {
	CountOp_ERROR=0,
	CountOp_CLS,
	CountOp_CLZ
};

enum MBReqDomain {
	MBReqDomain_ERROR=0,
	MBReqDomain_Nonshareable,
	MBReqDomain_InnerShareable,
	MBReqDomain_OuterShareable,
	MBReqDomain_FullSystem
};

enum MBReqTypes {
	MBReqTypes_ERROR=0,
	MBReqTypes_Reads,
	MBReqTypes_Writes,
	MBReqTypes_All
};

enum FPUnaryOp {
	FPUnaryOp_ERROR=0,
	FPUnaryOp_ABS,
	FPUnaryOp_MOV,
	FPUnaryOp_NEG,
	FPUnaryOp_SQRT
};

enum FPConvOp {
	FPConvOp_ERROR=0,
	FPConvOp_CVT_FtoI,
	FPConvOp_CVT_ItoF,
	FPConvOp_MOV_FtoI,
	FPConvOp_MOV_ItoF,
	FPConvOp_CVT_FtoI_JS
};

enum FPMaxMinOp {
	FPMaxMinOp_ERROR=0,
	FPMaxMinOp_MAX,
	FPMaxMinOp_MIN,
	FPMaxMinOp_MAXNUM,
	FPMaxMinOp_MINNUM
};

enum FPRounding {
	FPRounding_ERROR=0,
	FPRounding_TIEEVEN,
	FPRounding_POSINF,
	FPRounding_NEGINF,
	FPRounding_ZERO,
	FPRounding_TIEAWAY,
	FPRounding_ODD
};

enum MemAtomicOp {
	MemAtomicOp_ERROR=0,
	MemAtomicOp_ADD,
	MemAtomicOp_BIC,
	MemAtomicOp_EOR,
	MemAtomicOp_ORR,
	MemAtomicOp_SMAX,
	MemAtomicOp_SMIN,
	MemAtomicOp_UMAX,
	MemAtomicOp_UMIN,
	MemAtomicOp_SWP
};

enum MemOp {
	MemOp_ERROR=0,
	MemOp_LOAD,
	MemOp_STORE,
	MemOp_PREFETCH
};

enum MoveWideOp {
	MoveWideOp_ERROR=0,
	MoveWideOp_N,
	MoveWideOp_Z,
	MoveWideOp_K
};

enum PSTATEField {
	PSTATEField_ERROR=0,
	PSTATEField_DAIFSet,
	PSTATEField_DAIFClr,
	PSTATEField_PAN, // Armv8.1
	PSTATEField_UAO, // Armv8.2
	PSTATEField_DIT, // Armv8.4
	PSTATEField_SSBS,
	PSTATEField_TCO, // Armv8.5
	PSTATEField_SP
};

enum SVECmp {
	Cmp_ERROR=-1,
	Cmp_EQ,
	Cmp_NE,
	Cmp_GE,
	Cmp_GT,
	Cmp_LT,
	Cmp_LE,
	Cmp_UN
};

enum PrefetchHint {
	Prefetch_ERROR=-1,
	Prefetch_READ,
	Prefetch_WRITE,
	Prefetch_EXEC
};

typedef struct DecodeBitMasks_ReturnType_ {
	uint64_t wmask;
	uint64_t tmask;
} DecodeBitMasks_ReturnType;

int HighestSetBit(uint64_t x);
int LowestSetBit(uint64_t x);

bool BFXPreferred(uint32_t sf, uint32_t uns, uint32_t imms, uint32_t immr);
int BitCount(uint32_t x);
DecodeBitMasks_ReturnType DecodeBitMasks(uint8_t /*bit*/ immN, uint8_t /*bit(6)*/ imms, uint8_t /*bit(6)*/ immr);
bool MoveWidePreferred(uint32_t sf, uint32_t immN, uint32_t imms, uint32_t immr);
bool SVEMoveMaskPreferred(uint32_t imm13);
enum ShiftType DecodeRegExtend(uint8_t op);
enum ShiftType DecodeShift(uint8_t op);
enum SystemOp SysOp(uint32_t op1, uint32_t CRn, uint32_t CRm, uint32_t op2);
uint32_t UInt(uint32_t);
uint32_t BitSlice(uint64_t, int hi, int lo); // including the endpoints
bool IsZero(uint64_t foo);
bool IsOnes(uint64_t foo, int width);
uint64_t Replicate(uint64_t val, uint8_t times, uint64_t width);
uint64_t AdvSIMDExpandImm(uint8_t op, uint8_t cmode, uint64_t imm8);

bool BTypeCompatible_BTI(uint8_t hintcode, uint8_t pstate_btype);
bool BTypeCompatible_PACIXSP(void);

enum FPRounding FPDecodeRounding(uint8_t RMode);
enum FPRounding FPRoundingMode(uint64_t fpcr);

bool HaltingAllowed(void);
void SystemAccessTrap(uint32_t a, uint32_t b);
void CheckSystemAccess(uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t, uint8_t);

uint64_t VFPExpandImm(uint8_t imm8, unsigned width);

#define EL0 0
#define EL1 1
#define EL2 2
#define EL3 3
bool EL2Enabled(void);
bool ELUsingAArch32(uint8_t);

uint64_t FPOne(bool sign, int width);
uint64_t FPTwo(bool sign, int width);
uint64_t FPPointFive(bool sign, int width);

uint64_t SignExtend(uint64_t x, int width);
