/* radare - LGPL - Copyright 2021-2024 - junchao82@qq.com;zhaojunchao@loongson.cn love lanhy*/

#include <r_arch.h>
#include "../../include/disas-asm.h"
#include "loongarch-private.h"

struct loongarch_anal_opcode {
	const ut32 match;
	const ut32 mask; /* High 1 byte is main opcode and it must be 0xf. */
	const char * const name;
	const ut32 index;
	const ut32 r_type; /*R_ANAL_OP_TYPE*/
};

#define HT_NUM 32
struct loongarch_ASE {
	const struct loongarch_anal_opcode *const opcode;
	const struct loongarch_anal_opcode *la_opcode_ht[HT_NUM];
	ut8 opc_htab_inited;
};

#define INSNLEN 4

typedef struct plugin_data_t {
	ut64 insn_offset;
	ut8 insn_bytes[INSNLEN];
	struct loongarch_ASE la_ases[8];
} PluginData;

//use bit[30:26] to cal hash index
#define LA_INSN_HASH(insn) (((insn) & 0x7c000000) >> 26)

/**
 * sign_extend32 - sign extend a 32-bit value using specified bit as sign-bit
 * @value: value to sign extend
 * @index: 0 based bit index (0<=index<32) to sign bit
 *
 * This is safe to use for 16- and 8-bit types as well.
 */
R_UNUSED static inline st32 sign_extend32(ut32 value, int index) {
	ut8 shift = 31 - index;
	return (st32)(value << shift) >> shift;
}

/**
 * sign_extend64 - sign extend a 64-bit value using specified bit as sign-bit
 * @value: value to sign extend
 * @index: 0 based bit index (0<=index<64) to sign bit
 */
static inline st64 sign_extend64(ut64 value, int index) {
	ut8 shift = 63 - index;
	return (st64)(value << shift) >> shift;
}

#define UL(x) (x##UL)
#define ULL(x) (x##ULL)
#define LA_PFM PFMT64x

#define GENMASK_ULL(h, l) \
	(((~ULL(0)) - (ULL(1) << (l)) + 1) & \
	 (~ULL(0) >> (64 - 1 - (h))))

#define GET_BIT(op, h, l) (((op)&GENMASK_ULL(h,l))>>(l))

/*Get the reg name by index*/
#define LA_RD() loongarch_r_lp64_name[GET_BIT((opcode), 4, 0)]
#define LA_RJ() loongarch_r_lp64_name[GET_BIT((opcode), 9, 5)]
#define LA_RK() loongarch_r_lp64_name[GET_BIT((opcode), 14, 10)]

/*Get the imm in different format instructions*/
#define I_I26(op) ((((op)>>10) & 0xffff) | (((op)&0x3ff)<<16))  //26bit number
#define I_I21(op) ((((op)>>10) & 0xffff)|(((op)&0x1f)<<16))
#define I_I20(op) (((op)>>5) & 0xfffff)
#define I_I16(op) (((op)>>10) & 0xffff)
#define I_I14(op) (((op)>>10) & 0x3fff)
#define I_I12(op) (((op)>>10) & 0xfff)
#define I_I6(op) (((op)>>10) & 0x3f)
#define I_I5(op) (((op)>>10) & 0x1f)
#define I_SA2(op) (((op)>>15) & 0x3)
#define I_SA3(op) (((op)>>15) & 0x7)

#define I_I26s2(op) (I_I26((op)) << 2)
#define I_I21s2(op) (I_I21((op))<<2)
#define I_I14s2(op) (I_I14((op))<<2)
#define I_I16s2(op) (I_I16((op)) <<2)

#define I12_SX(op) sign_extend64(I_I12((op)), 11)
#define I16_SX(op) sign_extend64(I_I16((op)), 15)

/*not is esil syntax*/
#define I16s2_SX(op) sign_extend64(I_I16s2((op)), 16+1)
#define I14s2_SX(op) sign_extend64(I_I14s2((op)), 16+1)
#define I21s2_SX(op) sign_extend64(I_I21s2((op)), 21+1)
#define I26s2_SX(op) sign_extend64(I_I26s2((op)), 26+1)

#define ES_SX32(x) "32,"x",~"
#define ES_B(x) "0xff,"x",&"
#define ES_H(x) "0xffff,"x",&"
#define ES_W(x) "0xffffffff,"x",&"
#define ES_WH(x) "32,0xffffffff00000000,"x",&,>>"

/*Maybe should be moved to another file*/
typedef enum la_insn {
	LA_INS_INVALID = 0,
	LA_INS_ADDI_D,
	LA_INS_ADDI_W,
	LA_INS_ADDU16I_D,
	LA_INS_ADD_D,
	LA_INS_ADD_W,
	LA_INS_ALSL_D,
	LA_INS_ALSL_W,
	LA_INS_ALSL_WU,
	LA_INS_AMADD_D,
	LA_INS_AMADD_DB_D,
	LA_INS_AMADD_DB_W,
	LA_INS_AMADD_W,
	LA_INS_AMAND_D,
	LA_INS_AMAND_DB_D,
	LA_INS_AMAND_DB_W,
	LA_INS_AMAND_W,
	LA_INS_AMMAX_D,
	LA_INS_AMMAX_DB_D,
	LA_INS_AMMAX_DB_DU,
	LA_INS_AMMAX_DB_W,
	LA_INS_AMMAX_DB_WU,
	LA_INS_AMMAX_DU,
	LA_INS_AMMAX_W,
	LA_INS_AMMAX_WU,
	LA_INS_AMMIN_D,
	LA_INS_AMMIN_DB_D,
	LA_INS_AMMIN_DB_DU,
	LA_INS_AMMIN_DB_W,
	LA_INS_AMMIN_DB_WU,
	LA_INS_AMMIN_DU,
	LA_INS_AMMIN_W,
	LA_INS_AMMIN_WU,
	LA_INS_AMOR_D,
	LA_INS_AMOR_DB_D,
	LA_INS_AMOR_DB_W,
	LA_INS_AMOR_W,
	LA_INS_AMSWAP_D,
	LA_INS_AMSWAP_DB_D,
	LA_INS_AMSWAP_DB_W,
	LA_INS_AMSWAP_W,
	LA_INS_AMXOR_D,
	LA_INS_AMXOR_DB_D,
	LA_INS_AMXOR_DB_W,
	LA_INS_AMXOR_W,
	LA_INS_AND,
	LA_INS_ANDI,
	LA_INS_ANDN,
	LA_INS_ASRTGT_D,
	LA_INS_ASRTLE_D,
	LA_INS_B,
	LA_INS_BCEQZ,
	LA_INS_BCNEZ,
	LA_INS_BEQ,
	LA_INS_BEQZ,
	LA_INS_BGE,
	LA_INS_BGEU,
	LA_INS_BGEZ,
	LA_INS_BGT,
	LA_INS_BGTU,
	LA_INS_BGTZ,
	LA_INS_BITREV_4B,
	LA_INS_BITREV_8B,
	LA_INS_BITREV_D,
	LA_INS_BITREV_W,
	LA_INS_BL,
	LA_INS_BLE,
	LA_INS_BLEU,
	LA_INS_BLEZ,
	LA_INS_BLT,
	LA_INS_BLTU,
	LA_INS_BLTZ,
	LA_INS_BNE,
	LA_INS_BNEZ,
	LA_INS_BREAK,
	LA_INS_BSTRINS_D,
	LA_INS_BSTRINS_W,
	LA_INS_BSTRPICK_D,
	LA_INS_BSTRPICK_W,
	LA_INS_BYTEPICK_D,
	LA_INS_BYTEPICK_W,
	LA_INS_CACOP,
	LA_INS_CLO_D,
	LA_INS_CLO_W,
	LA_INS_CLZ_D,
	LA_INS_CLZ_W,
	LA_INS_CPUCFG,
	LA_INS_CRCC_W_B_W,
	LA_INS_CRCC_W_D_W,
	LA_INS_CRCC_W_H_W,
	LA_INS_CRCC_W_W_W,
	LA_INS_CRC_W_B_W,
	LA_INS_CRC_W_D_W,
	LA_INS_CRC_W_H_W,
	LA_INS_CRC_W_W_W,
	LA_INS_CSRRD,
	LA_INS_CSRWR,
	LA_INS_CSRXCHG,
	LA_INS_CTO_D,
	LA_INS_CTO_W,
	LA_INS_CTZ_D,
	LA_INS_CTZ_W,
	LA_INS_DBAR,
	LA_INS_DBCL,
	LA_INS_DIV_D,
	LA_INS_DIV_DU,
	LA_INS_DIV_W,
	LA_INS_DIV_WU,
	LA_INS_ERTN,
	LA_INS_EXT_W_B,
	LA_INS_EXT_W_H,
	LA_INS_FABS_D,
	LA_INS_FABS_S,
	LA_INS_FADD_D,
	LA_INS_FADD_S,
	LA_INS_FCLASS_D,
	LA_INS_FCLASS_S,
	LA_INS_FCMP_CAF_D,
	LA_INS_FCMP_CAF_S,
	LA_INS_FCMP_CEQ_D,
	LA_INS_FCMP_CEQ_S,
	LA_INS_FCMP_CLE_D,
	LA_INS_FCMP_CLE_S,
	LA_INS_FCMP_CLT_D,
	LA_INS_FCMP_CLT_S,
	LA_INS_FCMP_CNE_D,
	LA_INS_FCMP_CNE_S,
	LA_INS_FCMP_COR_D,
	LA_INS_FCMP_COR_S,
	LA_INS_FCMP_CUEQ_D,
	LA_INS_FCMP_CUEQ_S,
	LA_INS_FCMP_CUGE_D,
	LA_INS_FCMP_CUGE_S,
	LA_INS_FCMP_CUGT_D,
	LA_INS_FCMP_CUGT_S,
	LA_INS_FCMP_CULE_D,
	LA_INS_FCMP_CULE_S,
	LA_INS_FCMP_CULT_D,
	LA_INS_FCMP_CULT_S,
	LA_INS_FCMP_CUNE_D,
	LA_INS_FCMP_CUNE_S,
	LA_INS_FCMP_CUN_D,
	LA_INS_FCMP_CUN_S,
	LA_INS_FCMP_SAF_D,
	LA_INS_FCMP_SAF_S,
	LA_INS_FCMP_SEQ_D,
	LA_INS_FCMP_SEQ_S,
	LA_INS_FCMP_SGE_D,
	LA_INS_FCMP_SGE_S,
	LA_INS_FCMP_SGT_D,
	LA_INS_FCMP_SGT_S,
	LA_INS_FCMP_SLE_D,
	LA_INS_FCMP_SLE_S,
	LA_INS_FCMP_SLT_D,
	LA_INS_FCMP_SLT_S,
	LA_INS_FCMP_SNE_D,
	LA_INS_FCMP_SNE_S,
	LA_INS_FCMP_SOR_D,
	LA_INS_FCMP_SOR_S,
	LA_INS_FCMP_SUEQ_D,
	LA_INS_FCMP_SUEQ_S,
	LA_INS_FCMP_SULE_D,
	LA_INS_FCMP_SULE_S,
	LA_INS_FCMP_SULT_D,
	LA_INS_FCMP_SULT_S,
	LA_INS_FCMP_SUNE_D,
	LA_INS_FCMP_SUNE_S,
	LA_INS_FCMP_SUN_D,
	LA_INS_FCMP_SUN_S,
	LA_INS_FCOPYSIGN_D,
	LA_INS_FCOPYSIGN_S,
	LA_INS_FCVT_D_S,
	LA_INS_FCVT_S_D,
	LA_INS_FDIV_D,
	LA_INS_FDIV_S,
	LA_INS_FFINT_D_L,
	LA_INS_FFINT_D_W,
	LA_INS_FFINT_S_L,
	LA_INS_FFINT_S_W,
	LA_INS_FLDGT_D,
	LA_INS_FLDGT_S,
	LA_INS_FLDLE_D,
	LA_INS_FLDLE_S,
	LA_INS_FLDX_D,
	LA_INS_FLDX_S,
	LA_INS_FLD_D,
	LA_INS_FLD_S,
	LA_INS_FLOGB_D,
	LA_INS_FLOGB_S,
	LA_INS_FMADD_D,
	LA_INS_FMADD_S,
	LA_INS_FMAXA_D,
	LA_INS_FMAXA_S,
	LA_INS_FMAX_D,
	LA_INS_FMAX_S,
	LA_INS_FMINA_D,
	LA_INS_FMINA_S,
	LA_INS_FMIN_D,
	LA_INS_FMIN_S,
	LA_INS_FMOV_D,
	LA_INS_FMOV_S,
	LA_INS_FMSUB_D,
	LA_INS_FMSUB_S,
	LA_INS_FMUL_D,
	LA_INS_FMUL_S,
	LA_INS_FNEG_D,
	LA_INS_FNEG_S,
	LA_INS_FNMADD_D,
	LA_INS_FNMADD_S,
	LA_INS_FNMSUB_D,
	LA_INS_FNMSUB_S,
	LA_INS_FRECIP_D,
	LA_INS_FRECIP_S,
	LA_INS_FRINT_D,
	LA_INS_FRINT_S,
	LA_INS_FRSQRT_D,
	LA_INS_FRSQRT_S,
	LA_INS_FSCALEB_D,
	LA_INS_FSCALEB_S,
	LA_INS_FSEL,
	LA_INS_FSQRT_D,
	LA_INS_FSQRT_S,
	LA_INS_FSTGT_D,
	LA_INS_FSTGT_S,
	LA_INS_FSTLE_D,
	LA_INS_FSTLE_S,
	LA_INS_FSTX_D,
	LA_INS_FSTX_S,
	LA_INS_FST_D,
	LA_INS_FST_S,
	LA_INS_FSUB_D,
	LA_INS_FSUB_S,
	LA_INS_FTINTRM_L_D,
	LA_INS_FTINTRM_L_S,
	LA_INS_FTINTRM_W_D,
	LA_INS_FTINTRM_W_S,
	LA_INS_FTINTRNE_L_D,
	LA_INS_FTINTRNE_L_S,
	LA_INS_FTINTRNE_W_D,
	LA_INS_FTINTRNE_W_S,
	LA_INS_FTINTRP_L_D,
	LA_INS_FTINTRP_L_S,
	LA_INS_FTINTRP_W_D,
	LA_INS_FTINTRP_W_S,
	LA_INS_FTINTRZ_L_D,
	LA_INS_FTINTRZ_L_S,
	LA_INS_FTINTRZ_W_D,
	LA_INS_FTINTRZ_W_S,
	LA_INS_FTINT_L_D,
	LA_INS_FTINT_L_S,
	LA_INS_FTINT_W_D,
	LA_INS_FTINT_W_S,
	LA_INS_IBAR,
	LA_INS_IDLE,
	LA_INS_INVTLB,
	LA_INS_IOCSRRD_B,
	LA_INS_IOCSRRD_D,
	LA_INS_IOCSRRD_H,
	LA_INS_IOCSRRD_W,
	LA_INS_IOCSRWR_B,
	LA_INS_IOCSRWR_D,
	LA_INS_IOCSRWR_H,
	LA_INS_IOCSRWR_W,
	LA_INS_JIRL,
	LA_INS_LDDIR,
	LA_INS_LDGT_B,
	LA_INS_LDGT_D,
	LA_INS_LDGT_H,
	LA_INS_LDGT_W,
	LA_INS_LDLE_B,
	LA_INS_LDLE_D,
	LA_INS_LDLE_H,
	LA_INS_LDLE_W,
	LA_INS_LDPTE,
	LA_INS_LDPTR_D,
	LA_INS_LDPTR_W,
	LA_INS_LDX_B,
	LA_INS_LDX_BU,
	LA_INS_LDX_D,
	LA_INS_LDX_H,
	LA_INS_LDX_HU,
	LA_INS_LDX_W,
	LA_INS_LDX_WU,
	LA_INS_LD_B,
	LA_INS_LD_BU,
	LA_INS_LD_D,
	LA_INS_LD_H,
	LA_INS_LD_HU,
	LA_INS_LD_W,
	LA_INS_LD_WU,
	LA_INS_LL_D,
	LA_INS_LL_W,
	LA_INS_LU12I_W,
	LA_INS_LU32I_D,
	LA_INS_LU52I_D,
	LA_INS_MASKEQZ,
	LA_INS_MASKNEZ,
	LA_INS_MOD_D,
	LA_INS_MOD_DU,
	LA_INS_MOD_W,
	LA_INS_MOD_WU,
	LA_INS_MOVCF2FR,
	LA_INS_MOVCF2GR,
	LA_INS_MOVE,
	LA_INS_MOVFCSR2GR,
	LA_INS_MOVFR2CF,
	LA_INS_MOVFR2GR_D,
	LA_INS_MOVFR2GR_S,
	LA_INS_MOVFRH2GR_S,
	LA_INS_MOVGR2CF,
	LA_INS_MOVGR2FCSR,
	LA_INS_MOVGR2FRH_W,
	LA_INS_MOVGR2FR_D,
	LA_INS_MOVGR2FR_W,
	LA_INS_MULH_D,
	LA_INS_MULH_DU,
	LA_INS_MULH_W,
	LA_INS_MULH_WU,
	LA_INS_MULW_D_W,
	LA_INS_MULW_D_WU,
	LA_INS_MUL_D,
	LA_INS_MUL_W,
	LA_INS_NOR,
	LA_INS_OR,
	LA_INS_ORI,
	LA_INS_ORN,
	LA_INS_PCADDI,
	LA_INS_PCADDU12I,
	LA_INS_PCADDU18I,
	LA_INS_PCALAU12I,
	LA_INS_PRELD,
	LA_INS_PRELDX,
	LA_INS_RDTIMEH_W,
	LA_INS_RDTIMEL_W,
	LA_INS_RDTIME_D,
	LA_INS_REVB_2H,
	LA_INS_REVB_2W,
	LA_INS_REVB_4H,
	LA_INS_REVB_D,
	LA_INS_REVH_2W,
	LA_INS_REVH_D,
	LA_INS_ROTRI_D,
	LA_INS_ROTRI_W,
	LA_INS_ROTR_D,
	LA_INS_ROTR_W,
	LA_INS_SC_D,
	LA_INS_SC_W,
	LA_INS_SLLI_D,
	LA_INS_SLLI_W,
	LA_INS_SLL_D,
	LA_INS_SLL_W,
	LA_INS_SLT,
	LA_INS_SLTI,
	LA_INS_SLTU,
	LA_INS_SLTUI,
	LA_INS_SRAI_D,
	LA_INS_SRAI_W,
	LA_INS_SRA_D,
	LA_INS_SRA_W,
	LA_INS_SRLI_D,
	LA_INS_SRLI_W,
	LA_INS_SRL_D,
	LA_INS_SRL_W,
	LA_INS_STGT_B,
	LA_INS_STGT_D,
	LA_INS_STGT_H,
	LA_INS_STGT_W,
	LA_INS_STLE_B,
	LA_INS_STLE_D,
	LA_INS_STLE_H,
	LA_INS_STLE_W,
	LA_INS_STPTR_D,
	LA_INS_STPTR_W,
	LA_INS_STX_B,
	LA_INS_STX_D,
	LA_INS_STX_H,
	LA_INS_STX_W,
	LA_INS_ST_B,
	LA_INS_ST_D,
	LA_INS_ST_H,
	LA_INS_ST_W,
	LA_INS_SUB_D,
	LA_INS_SUB_W,
	LA_INS_SYSCALL,
	LA_INS_TLBCLR,
	LA_INS_TLBFILL,
	LA_INS_TLBFLUSH,
	LA_INS_TLBRD,
	LA_INS_TLBSRCH,
	LA_INS_TLBWR,
	LA_INS_XOR,
	LA_INS_XORI,

	LA_INS_ENDING,
} la_insn;

static const struct loongarch_anal_opcode la_lmm_opcodes[] = {
	{ 0x2000000, 0xffc00000, "slti", LA_INS_SLTI },
	{ 0x2400000, 0xffc00000, "sltui", LA_INS_SLTUI },
	{ 0x2800000, 0xffc00000, "addi.w", LA_INS_ADDI_W },
	{ 0x2c00000, 0xffc00000, "addi.d", LA_INS_ADDI_D },
	{ 0x3000000, 0xffc00000, "lu52i.d", LA_INS_LU52I_D },
	{ 0x3400000, 0xffc00000, "andi", LA_INS_ANDI, R_ANAL_OP_TYPE_AND },
	{ 0x3800000, 0xffc00000, "ori", LA_INS_ORI, R_ANAL_OP_TYPE_OR},
	{ 0x3c00000, 0xffc00000, "xori", LA_INS_XORI, R_ANAL_OP_TYPE_XOR },
	{ 0x10000000, 0xfc000000, "addu16i.d", LA_INS_ADDU16I_D, R_ANAL_OP_TYPE_ADD },
	{ 0x14000000, 0xfe000000, "lu12i.w", LA_INS_LU12I_W },
	{ 0x16000000, 0xfe000000, "lu32i.d", LA_INS_LU32I_D },
	{ 0x18000000, 0xfe000000, "pcaddi", LA_INS_PCADDI, R_ANAL_OP_TYPE_ADD},
	{ 0x1a000000, 0xfe000000, "pcalau12i", LA_INS_PCALAU12I, R_ANAL_OP_TYPE_ADD },
	{ 0x1c000000, 0xfe000000, "pcaddu12i", LA_INS_PCADDU12I, R_ANAL_OP_TYPE_ADD},
	{ 0x1e000000, 0xfe000000, "pcaddu18i", LA_INS_PCADDU18I, R_ANAL_OP_TYPE_ADD },
	{0}
};

static const struct loongarch_anal_opcode la_privilege_opcodes[] = {
	{ 0x4000000, 0xff0003e0, "csrrd", LA_INS_CSRRD },
	{ 0x4000020, 0xff0003e0, "csrwr", LA_INS_CSRWR },
	{ 0x4000000, 0xff000000, "csrxchg", LA_INS_CSRXCHG },
	{ 0x6000000, 0xffc00000, "cacop", LA_INS_CACOP },
	{ 0x6400000, 0xfffc0000, "lddir", LA_INS_LDDIR },
	{ 0x6440000, 0xfffc001f, "ldpte", LA_INS_LDPTE },
	{ 0x6480000, 0xfffffc00, "iocsrrd.b", LA_INS_IOCSRRD_B },
	{ 0x6480400, 0xfffffc00, "iocsrrd.h", LA_INS_IOCSRRD_H },
	{ 0x6480800, 0xfffffc00, "iocsrrd.w", LA_INS_IOCSRRD_W },
	{ 0x6480c00, 0xfffffc00, "iocsrrd.d", LA_INS_IOCSRRD_D },
	{ 0x6481000, 0xfffffc00, "iocsrwr.b", LA_INS_IOCSRWR_B },
	{ 0x6481400, 0xfffffc00, "iocsrwr.h", LA_INS_IOCSRWR_H },
	{ 0x6481800, 0xfffffc00, "iocsrwr.w", LA_INS_IOCSRWR_W },
	{ 0x6481c00, 0xfffffc00, "iocsrwr.d", LA_INS_IOCSRWR_D },
	{ 0x6482000, 0xffffffff, "tlbclr", LA_INS_TLBCLR },
	{ 0x6482400, 0xffffffff, "tlbflush", LA_INS_TLBFLUSH },
	{ 0x6482800, 0xffffffff, "tlbsrch", LA_INS_TLBSRCH },
	{ 0x6482c00, 0xffffffff, "tlbrd", LA_INS_TLBRD },
	{ 0x6483000, 0xffffffff, "tlbwr", LA_INS_TLBWR },
	{ 0x6483400, 0xffffffff, "tlbfill", LA_INS_TLBFILL },
	{ 0x6483800, 0xffffffff, "ertn", LA_INS_ERTN },
	{ 0x6488000, 0xffff8000, "idle", LA_INS_IDLE },
	{ 0x6498000, 0xffff8000, "invtlb", LA_INS_INVTLB },
	{0}
};

static const struct loongarch_anal_opcode la_jmp_opcodes[] = {
	{ 0x40000000, 0xfc000000, "beqz", LA_INS_BEQZ, R_ANAL_OP_TYPE_CJMP },
	{ 0x44000000, 0xfc000000, "bnez", LA_INS_BNEZ, R_ANAL_OP_TYPE_CJMP },
	{ 0x48000000, 0xfc000300, "bceqz", LA_INS_BCEQZ, R_ANAL_OP_TYPE_CJMP },
	{ 0x48000100, 0xfc000300, "bcnez", LA_INS_BCNEZ, R_ANAL_OP_TYPE_CJMP },
	{ 0x4c000000, 0xfc000000, "jirl", LA_INS_JIRL, R_ANAL_OP_TYPE_RCALL },
	{ 0x50000000, 0xfc000000, "b", LA_INS_B, R_ANAL_OP_TYPE_JMP },
	{ 0x54000000, 0xfc000000, "bl", LA_INS_BL, R_ANAL_OP_TYPE_CALL },
	{ 0x58000000, 0xfc000000, "beq", LA_INS_BEQ, R_ANAL_OP_TYPE_CJMP },
	{ 0x5c000000, 0xfc000000, "bne", LA_INS_BNE, R_ANAL_OP_TYPE_CJMP },
	{ 0x60000000, 0xfc000000, "blt", LA_INS_BLT, R_ANAL_OP_TYPE_CJMP },
	{ 0x60000000, 0xfc000000, "bgt", LA_INS_BGT, R_ANAL_OP_TYPE_CJMP },
	{ 0x60000000, 0xfc00001f, "bltz", LA_INS_BLTZ, R_ANAL_OP_TYPE_CJMP },
	{ 0x60000000, 0xfc0003e0, "bgtz", LA_INS_BGTZ, R_ANAL_OP_TYPE_CJMP },
	{ 0x64000000, 0xfc000000, "bge", LA_INS_BGE, R_ANAL_OP_TYPE_CJMP },
	{ 0x64000000, 0xfc000000, "ble", LA_INS_BLE, R_ANAL_OP_TYPE_CJMP },
	{ 0x64000000, 0xfc00001f, "bgez", LA_INS_BGEZ, R_ANAL_OP_TYPE_CJMP },
	{ 0x64000000, 0xfc0003e0, "blez", LA_INS_BLEZ, R_ANAL_OP_TYPE_CJMP },
	{ 0x68000000, 0xfc000000, "bltu", LA_INS_BLTU, R_ANAL_OP_TYPE_CJMP },
	{ 0x68000000, 0xfc000000, "bgtu", LA_INS_BGTU, R_ANAL_OP_TYPE_CJMP },
	{ 0x6c000000, 0xfc000000, "bgeu", LA_INS_BGEU, R_ANAL_OP_TYPE_CJMP },
	{ 0x6c000000, 0xfc000000, "bleu", LA_INS_BLEU, R_ANAL_OP_TYPE_CJMP },
	{0}
};

static struct loongarch_anal_opcode la_load_opcodes[] = {
	{ 0x20000000, 0xff000000, "ll.w", LA_INS_LL_W, R_ANAL_OP_TYPE_LOAD },
	{ 0x21000000, 0xff000000, "sc.w", LA_INS_SC_W, R_ANAL_OP_TYPE_STORE },
	{ 0x22000000, 0xff000000, "ll.d", LA_INS_LL_D, R_ANAL_OP_TYPE_LOAD },
	{ 0x23000000, 0xff000000, "sc.d", LA_INS_SC_D, R_ANAL_OP_TYPE_STORE },
	{ 0x24000000, 0xff000000, "ldptr.w", LA_INS_LDPTR_W, R_ANAL_OP_TYPE_LOAD },
	{ 0x25000000, 0xff000000, "stptr.w", LA_INS_STPTR_W, R_ANAL_OP_TYPE_STORE },
	{ 0x26000000, 0xff000000, "ldptr.d", LA_INS_LDPTR_D, R_ANAL_OP_TYPE_LOAD },
	{ 0x27000000, 0xff000000, "stptr.d", LA_INS_STPTR_D, R_ANAL_OP_TYPE_STORE },
	{ 0x28000000, 0xffc00000, "ld.b", LA_INS_LD_B, R_ANAL_OP_TYPE_LOAD },
	{ 0x28400000, 0xffc00000, "ld.h", LA_INS_LD_H, R_ANAL_OP_TYPE_LOAD },
	{ 0x28800000, 0xffc00000, "ld.w", LA_INS_LD_W, R_ANAL_OP_TYPE_LOAD },
	{ 0x28c00000, 0xffc00000, "ld.d", LA_INS_LD_D, R_ANAL_OP_TYPE_LOAD },
	{ 0x29000000, 0xffc00000, "st.b", LA_INS_ST_B, R_ANAL_OP_TYPE_LOAD },
	{ 0x29400000, 0xffc00000, "st.h", LA_INS_ST_H, R_ANAL_OP_TYPE_LOAD },
	{ 0x29800000, 0xffc00000, "st.w", LA_INS_ST_W, R_ANAL_OP_TYPE_LOAD },
	{ 0x29c00000, 0xffc00000, "st.d", LA_INS_ST_D, R_ANAL_OP_TYPE_LOAD },
	{ 0x2a000000, 0xffc00000, "ld.bu", LA_INS_LD_BU, R_ANAL_OP_TYPE_LOAD },
	{ 0x2a400000, 0xffc00000, "ld.hu", LA_INS_LD_HU, R_ANAL_OP_TYPE_LOAD },
	{ 0x2a800000, 0xffc00000, "ld.wu", LA_INS_LD_WU, R_ANAL_OP_TYPE_LOAD },
	{ 0x2ac00000, 0xffc00000, "preld", LA_INS_PRELD, R_ANAL_OP_TYPE_LOAD },
	{ 0x2b000000, 0xffc00000, "fld.s", LA_INS_FLD_S, R_ANAL_OP_TYPE_LOAD },
	{ 0x2b400000, 0xffc00000, "fst.s", LA_INS_FST_S, R_ANAL_OP_TYPE_STORE },
	{ 0x2b800000, 0xffc00000, "fld.d", LA_INS_FLD_D, R_ANAL_OP_TYPE_LOAD },
	{ 0x2bc00000, 0xffc00000, "fst.d", LA_INS_FST_D, R_ANAL_OP_TYPE_STORE },
	{ 0x38000000, 0xffff8000, "ldx.b", LA_INS_LDX_B, R_ANAL_OP_TYPE_LOAD },
	{ 0x38040000, 0xffff8000, "ldx.h", LA_INS_LDX_H, R_ANAL_OP_TYPE_LOAD },
	{ 0x38080000, 0xffff8000, "ldx.w", LA_INS_LDX_W, R_ANAL_OP_TYPE_LOAD },
	{ 0x380c0000, 0xffff8000, "ldx.d", LA_INS_LDX_D, R_ANAL_OP_TYPE_LOAD },
	{ 0x38100000, 0xffff8000, "stx.b", LA_INS_STX_B, R_ANAL_OP_TYPE_STORE },
	{ 0x38140000, 0xffff8000, "stx.h", LA_INS_STX_H, R_ANAL_OP_TYPE_STORE },
	{ 0x38180000, 0xffff8000, "stx.w", LA_INS_STX_W, R_ANAL_OP_TYPE_STORE },
	{ 0x381c0000, 0xffff8000, "stx.d", LA_INS_STX_D, R_ANAL_OP_TYPE_STORE },
	{ 0x38200000, 0xffff8000, "ldx.bu", LA_INS_LDX_BU, R_ANAL_OP_TYPE_LOAD },
	{ 0x38240000, 0xffff8000, "ldx.hu", LA_INS_LDX_HU, R_ANAL_OP_TYPE_LOAD },
	{ 0x38280000, 0xffff8000, "ldx.wu", LA_INS_LDX_WU, R_ANAL_OP_TYPE_LOAD },
	{ 0x382c0000, 0xffff8000, "preldx", LA_INS_PRELDX, R_ANAL_OP_TYPE_LOAD },
	{ 0x38300000, 0xffff8000, "fldx.s", LA_INS_FLDX_S, R_ANAL_OP_TYPE_LOAD },
	{ 0x38340000, 0xffff8000, "fldx.d", LA_INS_FLDX_D, R_ANAL_OP_TYPE_LOAD },
	{ 0x38380000, 0xffff8000, "fstx.s", LA_INS_FSTX_S, R_ANAL_OP_TYPE_STORE },
	{ 0x383c0000, 0xffff8000, "fstx.d", LA_INS_FSTX_D, R_ANAL_OP_TYPE_STORE },
	{ 0x38600000, 0xffff8000, "amswap.w", LA_INS_AMSWAP_W, R_ANAL_OP_TYPE_XCHG },
	{ 0x38608000, 0xffff8000, "amswap.d", LA_INS_AMSWAP_D, R_ANAL_OP_TYPE_XCHG },
	{ 0x38610000, 0xffff8000, "amadd.w", LA_INS_AMADD_W, R_ANAL_OP_TYPE_ADD },
	{ 0x38618000, 0xffff8000, "amadd.d", LA_INS_AMADD_D, R_ANAL_OP_TYPE_ADD },
	{ 0x38620000, 0xffff8000, "amand.w", LA_INS_AMAND_W },
	{ 0x38628000, 0xffff8000, "amand.d", LA_INS_AMAND_D },
	{ 0x38630000, 0xffff8000, "amor.w", LA_INS_AMOR_W },
	{ 0x38638000, 0xffff8000, "amor.d", LA_INS_AMOR_D },
	{ 0x38640000, 0xffff8000, "amxor.w", LA_INS_AMXOR_W },
	{ 0x38648000, 0xffff8000, "amxor.d", LA_INS_AMXOR_D },
	{ 0x38650000, 0xffff8000, "ammax.w", LA_INS_AMMAX_W },
	{ 0x38658000, 0xffff8000, "ammax.d", LA_INS_AMMAX_D },
	{ 0x38660000, 0xffff8000, "ammin.w", LA_INS_AMMIN_W },
	{ 0x38668000, 0xffff8000, "ammin.d", LA_INS_AMMIN_D },
	{ 0x38670000, 0xffff8000, "ammax.wu", LA_INS_AMMAX_WU },
	{ 0x38678000, 0xffff8000, "ammax.du", LA_INS_AMMAX_DU },
	{ 0x38680000, 0xffff8000, "ammin.wu", LA_INS_AMMIN_WU },
	{ 0x38688000, 0xffff8000, "ammin.du", LA_INS_AMMIN_DU },
	{ 0x38690000, 0xffff8000, "amswap_db.w", LA_INS_AMSWAP_DB_W, R_ANAL_OP_TYPE_XCHG },
	{ 0x38698000, 0xffff8000, "amswap_db.d", LA_INS_AMSWAP_DB_D, R_ANAL_OP_TYPE_XCHG },
	{ 0x386a0000, 0xffff8000, "amadd_db.w", LA_INS_AMADD_DB_W, R_ANAL_OP_TYPE_ADD },
	{ 0x386a8000, 0xffff8000, "amadd_db.d", LA_INS_AMADD_DB_D, R_ANAL_OP_TYPE_ADD },
	{ 0x386b0000, 0xffff8000, "amand_db.w", LA_INS_AMAND_DB_W },
	{ 0x386b8000, 0xffff8000, "amand_db.d", LA_INS_AMAND_DB_D },
	{ 0x386c0000, 0xffff8000, "amor_db.w", LA_INS_AMOR_DB_W },
	{ 0x386c8000, 0xffff8000, "amor_db.d", LA_INS_AMOR_DB_D },
	{ 0x386d0000, 0xffff8000, "amxor_db.w", LA_INS_AMXOR_DB_W },
	{ 0x386d8000, 0xffff8000, "amxor_db.d", LA_INS_AMXOR_DB_D },
	{ 0x386e0000, 0xffff8000, "ammax_db.w", LA_INS_AMMAX_DB_W },
	{ 0x386e8000, 0xffff8000, "ammax_db.d", LA_INS_AMMAX_DB_D },
	{ 0x386f0000, 0xffff8000, "ammin_db.w", LA_INS_AMMIN_DB_W },
	{ 0x386f8000, 0xffff8000, "ammin_db.d", LA_INS_AMMIN_DB_D },
	{ 0x38700000, 0xffff8000, "ammax_db.wu", LA_INS_AMMAX_DB_WU },
	{ 0x38708000, 0xffff8000, "ammax_db.du", LA_INS_AMMAX_DB_DU },
	{ 0x38710000, 0xffff8000, "ammin_db.wu", LA_INS_AMMIN_DB_WU },
	{ 0x38718000, 0xffff8000, "ammin_db.du", LA_INS_AMMIN_DB_DU },
	{ 0x38720000, 0xffff8000, "dbar", LA_INS_DBAR },
	{ 0x38728000, 0xffff8000, "ibar", LA_INS_IBAR },
	{ 0x38740000, 0xffff8000, "fldgt.s", LA_INS_FLDGT_S },
	{ 0x38748000, 0xffff8000, "fldgt.d", LA_INS_FLDGT_D },
	{ 0x38750000, 0xffff8000, "fldle.s", LA_INS_FLDLE_S },
	{ 0x38758000, 0xffff8000, "fldle.d", LA_INS_FLDLE_D },
	{ 0x38760000, 0xffff8000, "fstgt.s", LA_INS_FSTGT_S },
	{ 0x38768000, 0xffff8000, "fstgt.d", LA_INS_FSTGT_D },
	{ 0x38770000, 0xffff8000, "fstle.s", LA_INS_FSTLE_S },
	{ 0x38778000, 0xffff8000, "fstle.d", LA_INS_FSTLE_D },
	{ 0x38780000, 0xffff8000, "ldgt.b", LA_INS_LDGT_B },
	{ 0x38788000, 0xffff8000, "ldgt.h", LA_INS_LDGT_H },
	{ 0x38790000, 0xffff8000, "ldgt.w", LA_INS_LDGT_W },
	{ 0x38798000, 0xffff8000, "ldgt.d", LA_INS_LDGT_D },
	{ 0x387a0000, 0xffff8000, "ldle.b", LA_INS_LDLE_B },
	{ 0x387a8000, 0xffff8000, "ldle.h", LA_INS_LDLE_H },
	{ 0x387b0000, 0xffff8000, "ldle.w", LA_INS_LDLE_W },
	{ 0x387b8000, 0xffff8000, "ldle.d", LA_INS_LDLE_D },
	{ 0x387c0000, 0xffff8000, "stgt.b", LA_INS_STGT_B },
	{ 0x387c8000, 0xffff8000, "stgt.h", LA_INS_STGT_H },
	{ 0x387d0000, 0xffff8000, "stgt.w", LA_INS_STGT_W },
	{ 0x387d8000, 0xffff8000, "stgt.d", LA_INS_STGT_D },
	{ 0x387e0000, 0xffff8000, "stle.b", LA_INS_STLE_B },
	{ 0x387e8000, 0xffff8000, "stle.h", LA_INS_STLE_H },
	{ 0x387f0000, 0xffff8000, "stle.w", LA_INS_STLE_W },
	{ 0x387f8000, 0xffff8000, "stle.d", LA_INS_STLE_D },
	{0}
};

static struct loongarch_anal_opcode la_fix_opcodes[] = {
	{ 0x1000, 0xfffffc00, "clo.w", LA_INS_CLO_W },
	{ 0x1400, 0xfffffc00, "clz.w", LA_INS_CLZ_W },
	{ 0x1800, 0xfffffc00, "cto.w", LA_INS_CTO_W },
	{ 0x1c00, 0xfffffc00, "ctz.w", LA_INS_CTZ_W },
	{ 0x2000, 0xfffffc00, "clo.d", LA_INS_CLO_D },
	{ 0x2400, 0xfffffc00, "clz.d", LA_INS_CLZ_D },
	{ 0x2800, 0xfffffc00, "cto.d", LA_INS_CTO_D },
	{ 0x2c00, 0xfffffc00, "ctz.d", LA_INS_CTZ_D },
	{ 0x3000, 0xfffffc00, "revb.2h", LA_INS_REVB_2H },
	{ 0x3400, 0xfffffc00, "revb.4h", LA_INS_REVB_4H },
	{ 0x3800, 0xfffffc00, "revb.2w", LA_INS_REVB_2W },
	{ 0x3c00, 0xfffffc00, "revb.d", LA_INS_REVB_D },
	{ 0x4000, 0xfffffc00, "revh.2w", LA_INS_REVH_2W },
	{ 0x4400, 0xfffffc00, "revh.d", LA_INS_REVH_D },
	{ 0x4800, 0xfffffc00, "bitrev.4b", LA_INS_BITREV_4B },
	{ 0x4c00, 0xfffffc00, "bitrev.8b", LA_INS_BITREV_8B },
	{ 0x5000, 0xfffffc00, "bitrev.w", LA_INS_BITREV_W },
	{ 0x5400, 0xfffffc00, "bitrev.d", LA_INS_BITREV_D },
	{ 0x5800, 0xfffffc00, "ext.w.h", LA_INS_EXT_W_H },
	{ 0x5c00, 0xfffffc00, "ext.w.b", LA_INS_EXT_W_B },
	{ 0x6000, 0xfffffc00, "rdtimel.w", LA_INS_RDTIMEL_W },
	{ 0x6400, 0xfffffc00, "rdtimeh.w", LA_INS_RDTIMEH_W },
	{ 0x6800, 0xfffffc00, "rdtime.d", LA_INS_RDTIME_D },
	{ 0x6c00, 0xfffffc00, "cpucfg", LA_INS_CPUCFG },
	{ 0x10000, 0xffff801f, "asrtle.d", LA_INS_ASRTLE_D },
	{ 0x18000, 0xffff801f, "asrtgt.d", LA_INS_ASRTGT_D },
	{ 0x40000, 0xfffe0000, "alsl.w", LA_INS_ALSL_W },
	{ 0x60000, 0xfffe0000, "alsl.wu", LA_INS_ALSL_WU },
	{ 0x80000, 0xfffe0000, "bytepick.w", LA_INS_BYTEPICK_W },
	{ 0xc0000, 0xfffc0000, "bytepick.d", LA_INS_BYTEPICK_D },
	{ 0x100000, 0xffff8000, "add.w", LA_INS_ADD_W, R_ANAL_OP_TYPE_ADD },
	{ 0x108000, 0xffff8000, "add.d", LA_INS_ADD_D, R_ANAL_OP_TYPE_ADD },
	{ 0x110000, 0xffff8000, "sub.w", LA_INS_SUB_W, R_ANAL_OP_TYPE_SUB },
	{ 0x118000, 0xffff8000, "sub.d", LA_INS_SUB_D, R_ANAL_OP_TYPE_SUB },
	{ 0x120000, 0xffff8000, "slt", LA_INS_SLT },
	{ 0x128000, 0xffff8000, "sltu", LA_INS_SLTU },
	{ 0x130000, 0xffff8000, "maskeqz", LA_INS_MASKEQZ },
	{ 0x138000, 0xffff8000, "masknez", LA_INS_MASKNEZ },
	{ 0x140000, 0xffff8000, "nor", LA_INS_NOR, R_ANAL_OP_TYPE_NOR },
	{ 0x148000, 0xffff8000, "and", LA_INS_AND, R_ANAL_OP_TYPE_AND },
	{ 0x150000, 0xfffffc00, "move", LA_INS_MOVE, R_ANAL_OP_TYPE_MOV },
	{ 0x150000, 0xffff8000, "or", LA_INS_OR, R_ANAL_OP_TYPE_OR },
	{ 0x158000, 0xffff8000, "xor", LA_INS_XOR, R_ANAL_OP_TYPE_XOR },
	{ 0x160000, 0xffff8000, "orn", LA_INS_ORN },
	{ 0x168000, 0xffff8000, "andn", LA_INS_ANDN },
	{ 0x170000, 0xffff8000, "sll.w", LA_INS_SLL_W, R_ANAL_OP_TYPE_SHL },
	{ 0x178000, 0xffff8000, "srl.w", LA_INS_SRL_W, R_ANAL_OP_TYPE_SHR },
	{ 0x180000, 0xffff8000, "sra.w", LA_INS_SRA_W, R_ANAL_OP_TYPE_SHR },
	{ 0x188000, 0xffff8000, "sll.d", LA_INS_SLL_D, R_ANAL_OP_TYPE_SHL },
	{ 0x190000, 0xffff8000, "srl.d", LA_INS_SRL_D, R_ANAL_OP_TYPE_SHL },
	{ 0x198000, 0xffff8000, "sra.d", LA_INS_SRA_D, R_ANAL_OP_TYPE_SHR },
	{ 0x1b0000, 0xffff8000, "rotr.w", LA_INS_ROTR_W, R_ANAL_OP_TYPE_ROR },
	{ 0x1b8000, 0xffff8000, "rotr.d", LA_INS_ROTR_D, R_ANAL_OP_TYPE_ROR },
	{ 0x1c0000, 0xffff8000, "mul.w", LA_INS_MUL_W, R_ANAL_OP_TYPE_MUL },
	{ 0x1c8000, 0xffff8000, "mulh.w", LA_INS_MULH_W, R_ANAL_OP_TYPE_MUL },
	{ 0x1d0000, 0xffff8000, "mulh.wu", LA_INS_MULH_WU, R_ANAL_OP_TYPE_MUL },
	{ 0x1d8000, 0xffff8000, "mul.d", LA_INS_MUL_D, R_ANAL_OP_TYPE_MUL },
	{ 0x1e0000, 0xffff8000, "mulh.d", LA_INS_MULH_D, R_ANAL_OP_TYPE_MUL },
	{ 0x1e8000, 0xffff8000, "mulh.du", LA_INS_MULH_DU, R_ANAL_OP_TYPE_MUL },
	{ 0x1f0000, 0xffff8000, "mulw.d.w", LA_INS_MULW_D_W, R_ANAL_OP_TYPE_MUL },
	{ 0x1f8000, 0xffff8000, "mulw.d.wu", LA_INS_MULW_D_WU, R_ANAL_OP_TYPE_MUL },
	{ 0x200000, 0xffff8000, "div.w", LA_INS_DIV_W, R_ANAL_OP_TYPE_DIV },
	{ 0x208000, 0xffff8000, "mod.w", LA_INS_MOD_W, R_ANAL_OP_TYPE_MOD },
	{ 0x210000, 0xffff8000, "div.wu", LA_INS_DIV_WU, R_ANAL_OP_TYPE_DIV },
	{ 0x218000, 0xffff8000, "mod.wu", LA_INS_MOD_WU, R_ANAL_OP_TYPE_MOD },
	{ 0x220000, 0xffff8000, "div.d", LA_INS_DIV_D, R_ANAL_OP_TYPE_DIV },
	{ 0x228000, 0xffff8000, "mod.d", LA_INS_MOD_D, R_ANAL_OP_TYPE_MOD },
	{ 0x230000, 0xffff8000, "div.du", LA_INS_DIV_DU, R_ANAL_OP_TYPE_DIV },
	{ 0x238000, 0xffff8000, "mod.du", LA_INS_MOD_DU, R_ANAL_OP_TYPE_MOD },
	{ 0x240000, 0xffff8000, "crc.w.b.w", LA_INS_CRC_W_B_W },
	{ 0x248000, 0xffff8000, "crc.w.h.w", LA_INS_CRC_W_H_W },
	{ 0x250000, 0xffff8000, "crc.w.w.w", LA_INS_CRC_W_W_W },
	{ 0x258000, 0xffff8000, "crc.w.d.w", LA_INS_CRC_W_D_W },
	{ 0x260000, 0xffff8000, "crcc.w.b.w", LA_INS_CRCC_W_B_W },
	{ 0x268000, 0xffff8000, "crcc.w.h.w", LA_INS_CRCC_W_H_W },
	{ 0x270000, 0xffff8000, "crcc.w.w.w", LA_INS_CRCC_W_W_W },
	{ 0x278000, 0xffff8000, "crcc.w.d.w", LA_INS_CRCC_W_D_W },
	{ 0x2a0000, 0xffff8000, "break", LA_INS_BREAK },
	{ 0x2a8000, 0xffff8000, "dbcl", LA_INS_DBCL },
	{ 0x2b0000, 0xffff8000, "syscall", LA_INS_SYSCALL },
	{ 0x2c0000, 0xfffe0000, "alsl.d", LA_INS_ALSL_D , R_ANAL_OP_TYPE_SHL},
	{ 0x408000, 0xffff8000, "slli.w", LA_INS_SLLI_W, R_ANAL_OP_TYPE_SHL },
	{ 0x410000, 0xffff0000, "slli.d", LA_INS_SLLI_D, R_ANAL_OP_TYPE_SHL },
	{ 0x448000, 0xffff8000, "srli.w", LA_INS_SRLI_W, R_ANAL_OP_TYPE_SHL },
	{ 0x450000, 0xffff0000, "srli.d", LA_INS_SRLI_D, R_ANAL_OP_TYPE_SHL },
	{ 0x488000, 0xffff8000, "srai.w", LA_INS_SRAI_W, R_ANAL_OP_TYPE_SHR },
	{ 0x490000, 0xffff0000, "srai.d", LA_INS_SRAI_D, R_ANAL_OP_TYPE_SHR },
	{ 0x4c8000, 0xffff8000, "rotri.w", LA_INS_ROTRI_W, R_ANAL_OP_TYPE_ROR },
	{ 0x4d0000, 0xffff0000, "rotri.d", LA_INS_ROTRI_D, R_ANAL_OP_TYPE_ROR },
	{ 0x600000, 0xffe08000, "bstrins.w", LA_INS_BSTRINS_W },
	{ 0x608000, 0xffe08000, "bstrpick.w", LA_INS_BSTRPICK_W },
	{ 0x800000, 0xffc00000, "bstrins.d", LA_INS_BSTRINS_D },
	{ 0xc00000, 0xffc00000, "bstrpick.d", LA_INS_BSTRPICK_D },
	{0}
};
//TODO add float type
static struct loongarch_anal_opcode la_4opt_opcodes[] = {
	{ 0x8100000, 0xfff00000, "fmadd.s", LA_INS_FMADD_S },
	{ 0x8200000, 0xfff00000, "fmadd.d", LA_INS_FMADD_D },
	{ 0x8500000, 0xfff00000, "fmsub.s", LA_INS_FMSUB_S },
	{ 0x8900000, 0xfff00000, "fnmadd.s", LA_INS_FNMADD_S },
	{ 0x8a00000, 0xfff00000, "fnmadd.d", LA_INS_FNMADD_D },
	{ 0x8d00000, 0xfff00000, "fnmsub.s", LA_INS_FNMSUB_S },
	{ 0x8e00000, 0xfff00000, "fnmsub.d", LA_INS_FNMSUB_D },
	{ 0xc100000, 0xffff8018, "fcmp.caf.s", LA_INS_FCMP_CAF_S },
	{ 0xc108000, 0xffff8018, "fcmp.saf.s", LA_INS_FCMP_SAF_S },
	{ 0xc110000, 0xffff8018, "fcmp.clt.s", LA_INS_FCMP_CLT_S },
	{ 0xc118000, 0xffff8018, "fcmp.slt.s", LA_INS_FCMP_SLT_S },
	{ 0xc118000, 0xffff8018, "fcmp.sgt.s", LA_INS_FCMP_SGT_S },
	{ 0xc120000, 0xffff8018, "fcmp.ceq.s", LA_INS_FCMP_CEQ_S },
	{ 0xc128000, 0xffff8018, "fcmp.seq.s", LA_INS_FCMP_SEQ_S },
	{ 0xc130000, 0xffff8018, "fcmp.cle.s", LA_INS_FCMP_CLE_S },
	{ 0xc138000, 0xffff8018, "fcmp.sle.s", LA_INS_FCMP_SLE_S },
	{ 0xc138000, 0xffff8018, "fcmp.sge.s", LA_INS_FCMP_SGE_S },
	{ 0xc140000, 0xffff8018, "fcmp.cun.s", LA_INS_FCMP_CUN_S },
	{ 0xc148000, 0xffff8018, "fcmp.sun.s", LA_INS_FCMP_SUN_S },
	{ 0xc150000, 0xffff8018, "fcmp.cult.s", LA_INS_FCMP_CULT_S },
	{ 0xc150000, 0xffff8018, "fcmp.cugt.s", LA_INS_FCMP_CUGT_S },
	{ 0xc158000, 0xffff8018, "fcmp.sult.s", LA_INS_FCMP_SULT_S },
	{ 0xc160000, 0xffff8018, "fcmp.cueq.s", LA_INS_FCMP_CUEQ_S },
	{ 0xc168000, 0xffff8018, "fcmp.sueq.s", LA_INS_FCMP_SUEQ_S },
	{ 0xc170000, 0xffff8018, "fcmp.cule.s", LA_INS_FCMP_CULE_S },
	{ 0xc170000, 0xffff8018, "fcmp.cuge.s", LA_INS_FCMP_CUGE_S },
	{ 0xc178000, 0xffff8018, "fcmp.sule.s", LA_INS_FCMP_SULE_S },
	{ 0xc180000, 0xffff8018, "fcmp.cne.s", LA_INS_FCMP_CNE_S },
	{ 0xc188000, 0xffff8018, "fcmp.sne.s", LA_INS_FCMP_SNE_S },
	{ 0xc1a0000, 0xffff8018, "fcmp.cor.s", LA_INS_FCMP_COR_S },
	{ 0xc1a8000, 0xffff8018, "fcmp.sor.s", LA_INS_FCMP_SOR_S },
	{ 0xc1c0000, 0xffff8018, "fcmp.cune.s", LA_INS_FCMP_CUNE_S },
	{ 0xc1c8000, 0xffff8018, "fcmp.sune.s", LA_INS_FCMP_SUNE_S },
	{ 0xc200000, 0xffff8018, "fcmp.caf.d", LA_INS_FCMP_CAF_D },
	{ 0xc208000, 0xffff8018, "fcmp.saf.d", LA_INS_FCMP_SAF_D },
	{ 0xc210000, 0xffff8018, "fcmp.clt.d", LA_INS_FCMP_CLT_D },
	{ 0xc218000, 0xffff8018, "fcmp.slt.d", LA_INS_FCMP_SLT_D },
	{ 0xc218000, 0xffff8018, "fcmp.sgt.d", LA_INS_FCMP_SGT_D },
	{ 0xc220000, 0xffff8018, "fcmp.ceq.d", LA_INS_FCMP_CEQ_D },
	{ 0xc228000, 0xffff8018, "fcmp.seq.d", LA_INS_FCMP_SEQ_D },
	{ 0xc230000, 0xffff8018, "fcmp.cle.d", LA_INS_FCMP_CLE_D },
	{ 0xc238000, 0xffff8018, "fcmp.sle.d", LA_INS_FCMP_SLE_D },
	{ 0xc238000, 0xffff8018, "fcmp.sge.d", LA_INS_FCMP_SGE_D },
	{ 0xc240000, 0xffff8018, "fcmp.cun.d", LA_INS_FCMP_CUN_D },
	{ 0xc248000, 0xffff8018, "fcmp.sun.d", LA_INS_FCMP_SUN_D },
	{ 0xc250000, 0xffff8018, "fcmp.cult.d", LA_INS_FCMP_CULT_D },
	{ 0xc250000, 0xffff8018, "fcmp.cugt.d", LA_INS_FCMP_CUGT_D },
	{ 0xc258000, 0xffff8018, "fcmp.sult.d", LA_INS_FCMP_SULT_D },
	{ 0xc260000, 0xffff8018, "fcmp.cueq.d", LA_INS_FCMP_CUEQ_D },
	{ 0xc268000, 0xffff8018, "fcmp.sueq.d", LA_INS_FCMP_SUEQ_D },
	{ 0xc270000, 0xffff8018, "fcmp.cule.d", LA_INS_FCMP_CULE_D },
	{ 0xc270000, 0xffff8018, "fcmp.cuge.d", LA_INS_FCMP_CUGE_D },
	{ 0xc278000, 0xffff8018, "fcmp.sule.d", LA_INS_FCMP_SULE_D },
	{ 0xc280000, 0xffff8018, "fcmp.cne.d", LA_INS_FCMP_CNE_D },
	{ 0xc288000, 0xffff8018, "fcmp.sne.d", LA_INS_FCMP_SNE_D },
	{ 0xc2a0000, 0xffff8018, "fcmp.cor.d", LA_INS_FCMP_COR_D },
	{ 0xc2a8000, 0xffff8018, "fcmp.sor.d", LA_INS_FCMP_SOR_D },
	{ 0xc2c0000, 0xffff8018, "fcmp.cune.d", LA_INS_FCMP_CUNE_D },
	{ 0xc2c8000, 0xffff8018, "fcmp.sune.d", LA_INS_FCMP_SUNE_D },
	{ 0xd000000, 0xfffc0000, "fsel", LA_INS_FSEL },
	{0}
};

static struct loongarch_anal_opcode la_float_opcodes[] = {
	{ 0x1008000, 0xffff8000, "fadd.s", LA_INS_FADD_S },
	{ 0x1010000, 0xffff8000, "fadd.d", LA_INS_FADD_D },
	{ 0x1028000, 0xffff8000, "fsub.s", LA_INS_FSUB_S },
	{ 0x1030000, 0xffff8000, "fsub.d", LA_INS_FSUB_D },
	{ 0x1048000, 0xffff8000, "fmul.s", LA_INS_FMUL_S },
	{ 0x1050000, 0xffff8000, "fmul.d", LA_INS_FMUL_D },
	{ 0x1068000, 0xffff8000, "fdiv.s", LA_INS_FDIV_S },
	{ 0x1070000, 0xffff8000, "fdiv.d", LA_INS_FDIV_D },
	{ 0x1088000, 0xffff8000, "fmax.s", LA_INS_FMAX_S },
	{ 0x1090000, 0xffff8000, "fmax.d", LA_INS_FMAX_D },
	{ 0x10a8000, 0xffff8000, "fmin.s", LA_INS_FMIN_S },
	{ 0x10b0000, 0xffff8000, "fmin.d", LA_INS_FMIN_D },
	{ 0x10c8000, 0xffff8000, "fmaxa.s", LA_INS_FMAXA_S },
	{ 0x10d0000, 0xffff8000, "fmaxa.d", LA_INS_FMAXA_D },
	{ 0x10e8000, 0xffff8000, "fmina.s", LA_INS_FMINA_S },
	{ 0x10f0000, 0xffff8000, "fmina.d", LA_INS_FMINA_D },
	{ 0x1108000, 0xffff8000, "fscaleb.s", LA_INS_FSCALEB_S },
	{ 0x1110000, 0xffff8000, "fscaleb.d", LA_INS_FSCALEB_D },
	{ 0x1128000, 0xffff8000, "fcopysign.s", LA_INS_FCOPYSIGN_S },
	{ 0x1130000, 0xffff8000, "fcopysign.d", LA_INS_FCOPYSIGN_D },
	{ 0x1140400, 0xfffffc00, "fabs.s", LA_INS_FABS_S },
	{ 0x1140800, 0xfffffc00, "fabs.d", LA_INS_FABS_D },
	{ 0x1141400, 0xfffffc00, "fneg.s", LA_INS_FNEG_S },
	{ 0x1141800, 0xfffffc00, "fneg.d", LA_INS_FNEG_D },
	{ 0x1142400, 0xfffffc00, "flogb.s", LA_INS_FLOGB_S },
	{ 0x1142800, 0xfffffc00, "flogb.d", LA_INS_FLOGB_D },
	{ 0x1143400, 0xfffffc00, "fclass.s", LA_INS_FCLASS_S },
	{ 0x1143800, 0xfffffc00, "fclass.d", LA_INS_FCLASS_D },
	{ 0x1144400, 0xfffffc00, "fsqrt.s", LA_INS_FSQRT_S },
	{ 0x1144800, 0xfffffc00, "fsqrt.d", LA_INS_FSQRT_D },
	{ 0x1145400, 0xfffffc00, "frecip.s", LA_INS_FRECIP_S },
	{ 0x1145800, 0xfffffc00, "frecip.d", LA_INS_FRECIP_D },
	{ 0x1146400, 0xfffffc00, "frsqrt.s", LA_INS_FRSQRT_S },
	{ 0x1146800, 0xfffffc00, "frsqrt.d", LA_INS_FRSQRT_D },
	{ 0x1149400, 0xfffffc00, "fmov.s", LA_INS_FMOV_S },
	{ 0x1149800, 0xfffffc00, "fmov.d", LA_INS_FMOV_D },
	{ 0x114a400, 0xfffffc00, "movgr2fr.w", LA_INS_MOVGR2FR_W },
	{ 0x114a800, 0xfffffc00, "movgr2fr.d", LA_INS_MOVGR2FR_D },
	{ 0x114ac00, 0xfffffc00, "movgr2frh.w", LA_INS_MOVGR2FRH_W },
	{ 0x114b400, 0xfffffc00, "movfr2gr.s", LA_INS_MOVFR2GR_S },
	{ 0x114b800, 0xfffffc00, "movfr2gr.d", LA_INS_MOVFR2GR_D },
	{ 0x114bc00, 0xfffffc00, "movfrh2gr.s", LA_INS_MOVFRH2GR_S },
	{ 0x114c000, 0xfffffc00, "movgr2fcsr", LA_INS_MOVGR2FCSR },
	{ 0x114c800, 0xfffffc00, "movfcsr2gr", LA_INS_MOVFCSR2GR },
	{ 0x114d000, 0xfffffc18, "movfr2cf", LA_INS_MOVFR2CF },
	{ 0x114d400, 0xffffff00, "movcf2fr", LA_INS_MOVCF2FR },
	{ 0x114d800, 0xfffffc18, "movgr2cf", LA_INS_MOVGR2CF },
	{ 0x114dc00, 0xffffff00, "movcf2gr", LA_INS_MOVCF2GR },
	{ 0x11a0400, 0xfffffc00, "ftintrm.w.s", LA_INS_FTINTRM_W_S },
	{ 0x11a0800, 0xfffffc00, "ftintrm.w.d", LA_INS_FTINTRM_W_D },
	{ 0x11a2400, 0xfffffc00, "ftintrm.l.s", LA_INS_FTINTRM_L_S },
	{ 0x11a2800, 0xfffffc00, "ftintrm.l.d", LA_INS_FTINTRM_L_D },
	{ 0x11a4400, 0xfffffc00, "ftintrp.w.s", LA_INS_FTINTRP_W_S },
	{ 0x11a4800, 0xfffffc00, "ftintrp.w.d", LA_INS_FTINTRP_W_D },
	{ 0x11a6400, 0xfffffc00, "ftintrp.l.s", LA_INS_FTINTRP_L_S },
	{ 0x11a6800, 0xfffffc00, "ftintrp.l.d", LA_INS_FTINTRP_L_D },
	{ 0x11a8400, 0xfffffc00, "ftintrz.w.s", LA_INS_FTINTRZ_W_S },
	{ 0x11a8800, 0xfffffc00, "ftintrz.w.d", LA_INS_FTINTRZ_W_D },
	{ 0x11aa400, 0xfffffc00, "ftintrz.l.s", LA_INS_FTINTRZ_L_S },
	{ 0x11aa800, 0xfffffc00, "ftintrz.l.d", LA_INS_FTINTRZ_L_D },
	{ 0x11ac400, 0xfffffc00, "ftintrne.w.s", LA_INS_FTINTRNE_W_S },
	{ 0x11ac800, 0xfffffc00, "ftintrne.w.d", LA_INS_FTINTRNE_W_D },
	{ 0x11ae400, 0xfffffc00, "ftintrne.l.s", LA_INS_FTINTRNE_L_S },
	{ 0x11ae800, 0xfffffc00, "ftintrne.l.d", LA_INS_FTINTRNE_L_D },
	{ 0x11b0400, 0xfffffc00, "ftint.w.s", LA_INS_FTINT_W_S },
	{ 0x11b0800, 0xfffffc00, "ftint.w.d", LA_INS_FTINT_W_D },
	{ 0x11b2400, 0xfffffc00, "ftint.l.s", LA_INS_FTINT_L_S },
	{ 0x11b2800, 0xfffffc00, "ftint.l.d", LA_INS_FTINT_L_D },
	{ 0x11d1000, 0xfffffc00, "ffint.s.w", LA_INS_FFINT_S_W },
	{ 0x11d1800, 0xfffffc00, "ffint.s.l", LA_INS_FFINT_S_L },
	{ 0x11d2000, 0xfffffc00, "ffint.d.w", LA_INS_FFINT_D_W },
	{ 0x11d2800, 0xfffffc00, "ffint.d.l", LA_INS_FFINT_D_L },
	{ 0x11e4400, 0xfffffc00, "frint.s", LA_INS_FRINT_S },
	{ 0x11e4800, 0xfffffc00, "frint.d", LA_INS_FRINT_D },
	{0}
};

static const struct loongarch_ASE la_ases_initial[] = {
	{la_lmm_opcodes, {0}, 0},
	{la_privilege_opcodes, {0}, 0},
	{la_jmp_opcodes, {0}, 0},
	{la_load_opcodes, {0}, 0},
	{la_fix_opcodes, {0}, 0},
	{la_4opt_opcodes, {0}, 0},
	{la_float_opcodes, {0}, 0},
	{0}
};

static int analop_esil(RArchSession *as, RAnalOp *op, ut32 opcode) {
	ut32 insn_id = op->id;

	switch (insn_id) {
	case LA_INS_PCADDU12I:
		r_strbuf_appendf (&op->esil, "0x%"LA_PFM",0x%x,+,%s,=", op->addr, I_I20(opcode), LA_RD());
		break;
	case LA_INS_LU12I_W:
		r_strbuf_appendf (&op->esil, "%d,12,<<,%s,=", I_I20(opcode), LA_RD());
		break;
	case LA_INS_LU32I_D:
		r_strbuf_appendf (&op->esil, "32,0x%x,<<,%s,0xffffffff,&,+,%s,=", I_I20(opcode), LA_RD(), LA_RD());
		break;
	case LA_INS_LU52I_D:
		r_strbuf_appendf (&op->esil, "52,0x%x,<<,%s,+,%s,=", I_I12(opcode), LA_RD(), LA_RD());
		break;
		/* FIXME U means unsigned comparison*/
	case LA_INS_LDX_BU:
	case LA_INS_LDX_B:
		r_strbuf_appendf (&op->esil, "%s,%s,+,[1],%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_LDX_HU:
	case LA_INS_LDX_H:
		r_strbuf_appendf (&op->esil, "%s,%s,+,[2],%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_LDX_WU:
	case LA_INS_LDX_W:
		r_strbuf_appendf (&op->esil, "%s,%s,+,[4],%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_LDX_D:
		r_strbuf_appendf (&op->esil, "%s,%s,+,[8],%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_LD_BU:
	case LA_INS_LD_B:
		r_strbuf_appendf (&op->esil, "%s,0x%"LA_PFM",+,[1],%s,=", LA_RJ(),I12_SX(opcode), LA_RD());
		break;
	case LA_INS_LD_HU:
	case LA_INS_LD_H:
		r_strbuf_appendf (&op->esil, "%s,0x%"LA_PFM",+,[2],%s,=", LA_RJ(),I12_SX(opcode), LA_RD());
		break;
	case LA_INS_LD_WU:
	case LA_INS_LD_W:
		r_strbuf_appendf (&op->esil, "%s,0x%"LA_PFM",+,[4],%s,=", LA_RJ(),I12_SX(opcode), LA_RD());
		break;
	case LA_INS_LD_D:
		r_strbuf_appendf (&op->esil, "%s,0x%"LA_PFM",+,[8],%s,=", LA_RJ(),I12_SX(opcode), LA_RD());
		break;
	case LA_INS_LDPTR_W:
		r_strbuf_appendf (&op->esil, "%s,0x%"LA_PFM",+,[4],%s,=", LA_RJ(), I14s2_SX(opcode), LA_RD());
		break;
	case LA_INS_LDPTR_D:
		r_strbuf_appendf (&op->esil,"%s,0x%"LA_PFM",+,[8],%s,=", LA_RJ(), I14s2_SX(opcode), LA_RD());
		break;
	case LA_INS_ST_B:
		r_strbuf_appendf (&op->esil, "%s,%s,0x%"LA_PFM",+,=[1]", LA_RD(), LA_RJ(), I12_SX(opcode));
		break;
	case LA_INS_ST_H:
		r_strbuf_appendf (&op->esil, "%s,%s,0x%"LA_PFM",+,=[2]", LA_RD(), LA_RJ(), I12_SX(opcode));
		break;
	case LA_INS_ST_W:
		r_strbuf_appendf (&op->esil, "%s,%s,0x%"LA_PFM",+,=[4]", LA_RD(), LA_RJ(), I12_SX(opcode));
		break;
	case LA_INS_ST_D:
		r_strbuf_appendf (&op->esil, "%s,%s,0x%"LA_PFM",+,=[8]", LA_RD(), LA_RJ(), I12_SX(opcode));
		break;
	case LA_INS_STPTR_W:
		r_strbuf_appendf (&op->esil, "%s,%s,0x%"LA_PFM",+,=[8]", LA_RD(), LA_RJ(), I14s2_SX(opcode));
		break;
	case LA_INS_STPTR_D:
		r_strbuf_appendf (&op->esil, "%s,%s,0x%"LA_PFM",+,=[8]", LA_RD(), LA_RJ(), I14s2_SX(opcode));
		break;
	case LA_INS_SLTU:
	case LA_INS_SLT:
		r_strbuf_appendf (&op->esil, "0,%s,=,%s,%s,<,?{,1,%s,=,}", LA_RD(), LA_RK(), LA_RJ(),LA_RD());
		break;
	case LA_INS_SLTUI:
	case LA_INS_SLTI:
		r_strbuf_appendf (&op->esil, "0,%s,=,0x%"LA_PFM",%s,<,?{,1,%s,=,}", LA_RD(), I12_SX(opcode), LA_RJ(),LA_RD());
		break;
		//FIXME maybe Lack of signed expansion
	case LA_INS_ADD_W:
		r_strbuf_appendf (&op->esil, ES_SX32("%s,%s,+")",%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_ADD_D:
		r_strbuf_appendf (&op->esil, "%s,%s,+,%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_ADDI_W:
		r_strbuf_appendf (&op->esil, ES_SX32("%s,0x%"LA_PFM",+")",%s,=", LA_RJ(), I12_SX(opcode), LA_RD());
		break;
	case LA_INS_ADDU16I_D:
		r_strbuf_appendf (&op->esil, "16,0x%"LA_PFM",<<,%s,+,%s,=", I16_SX(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_SUB_W:
		r_strbuf_appendf (&op->esil, ES_SX32(ES_W("%s")","ES_W("%s")",-")",%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_SUB_D:
		r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_MUL_W:
		r_strbuf_appendf (&op->esil, ES_SX32(ES_W(ES_W("%s")","ES_W("%s")",*"))",%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_MULH_WU:
	case LA_INS_MULH_W:
		r_strbuf_appendf (&op->esil, ES_WH(ES_W("%s")","ES_W("%s")",*")",%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_MUL_D:
		r_strbuf_appendf (&op->esil, "%s,%s,*,%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
		/* FIXME */
	case LA_INS_MULH_DU:
	case LA_INS_MULH_D:
		break;
	case LA_INS_DIV_WU:
	case LA_INS_DIV_W:
		r_strbuf_appendf (&op->esil, ES_W("%s")","ES_W("%s")",/,%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
	case LA_INS_MOD_WU:
	case LA_INS_MOD_W:
		r_strbuf_appendf (&op->esil, ES_SX32(ES_W("%s")","ES_W("%s")",%%")",%s,=", LA_RJ(), LA_RK(), LA_RD());
		break;
		/* FIXME rk only bits 0~4 are used*/
	case LA_INS_SLL_W:
		r_strbuf_appendf (&op->esil, ES_SX32("%s,"ES_W("%s")",<<")",%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_SRL_W:
		r_strbuf_appendf (&op->esil,ES_SX32("%s,"ES_W("%s")",>>")",%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_SRA_W:
		r_strbuf_appendf (&op->esil,ES_SX32("%s,"ES_W("%s")",>>>>")",%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_ROTR_W:
		r_strbuf_appendf (&op->esil,ES_SX32("%s,"ES_W("%s")",>>>")",%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_SLLI_W:
		r_strbuf_appendf (&op->esil,ES_SX32("%d,"ES_W("%s")",<<")",%s,=", I_I5(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_SRLI_W:
		r_strbuf_appendf (&op->esil,ES_SX32("%d,"ES_W("%s")",>>")",%s,=", I_I5(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_SRAI_W:
		r_strbuf_appendf (&op->esil,ES_SX32("%d,"ES_W("%s")",>>>>")",%s,=", I_I5(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_ROTRI_W:
		r_strbuf_appendf (&op->esil,ES_SX32("%d,"ES_W("%s")",>>>")",%s,=", I_I5(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_ALSL_WU:
	case LA_INS_ALSL_W:
		r_strbuf_appendf (&op->esil,ES_W(ES_W("%s")",%d,"ES_W("%s")",<<,+")",%s,=",LA_RK() ,I_SA2(opcode)+1, LA_RJ(), LA_RD());
		break;
	case LA_INS_ALSL_D:
		r_strbuf_appendf (&op->esil,"%s,%d,%s,<<,+,%s,=", LA_RK(), I_SA2(opcode), LA_RJ(), LA_RD());
		break;
		/* FIXME rk only bits 0~5 are used*/
	case LA_INS_SLL_D:
		r_strbuf_appendf (&op->esil,"%s,%s,<<,%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_SRL_D:
		r_strbuf_appendf (&op->esil,"%s,%s,>>,%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_SRA_D:
		r_strbuf_appendf (&op->esil,"%s,%s,>>>>,%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_ROTR_D:
		r_strbuf_appendf (&op->esil,"%s,%s,>>>,%s,=", LA_RK(), LA_RJ(), LA_RD());
		break;
	case LA_INS_SLLI_D:
		r_strbuf_appendf (&op->esil,"%d,%s,<<,%s,=", I_I6(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_SRLI_D:
		r_strbuf_appendf (&op->esil,"%d,%s,>>,%s,=", I_I6(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_SRAI_D:
		r_strbuf_appendf (&op->esil,"%d,%s,>>>>,%s,=", I_I6(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_ROTRI_D:
		r_strbuf_appendf (&op->esil,"%d,%s,>>>,%s,=", I_I6(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_MOVE:
		r_strbuf_appendf (&op->esil,"%s,%s,=",LA_RJ(), LA_RD());
		break;
	case LA_INS_AND:
		r_strbuf_appendf (&op->esil,"%s,%s,&,%s,=", LA_RJ(), LA_RK(),LA_RD());
		break;
	case LA_INS_OR:
		r_strbuf_appendf (&op->esil,"%s,%s,|,%s,=", LA_RJ(), LA_RK(),LA_RD());
		break;
	case LA_INS_XOR:
		r_strbuf_appendf (&op->esil,"%s,%s,^,%s,=", LA_RJ(), LA_RK(),LA_RD());
		break;
	case LA_INS_NOR:
		r_strbuf_appendf (&op->esil,"%s,%s,|,0xffffffff,^,%s,=", LA_RJ(), LA_RK(),LA_RD());
		break;
	case LA_INS_ANDN:
		r_strbuf_appendf (&op->esil,"%s,^,0xffffffff,%s,&,%s,=", LA_RK(), LA_RJ(),LA_RD());
		break;
	case LA_INS_ORN:
		r_strbuf_appendf (&op->esil,"%s,^,0xffffffff,%s,|,%s,=", LA_RK(), LA_RJ(),LA_RD());
		break;
	case LA_INS_ANDI:
		r_strbuf_appendf (&op->esil,"%d,%s,&,%s,=", I_I12(opcode), LA_RJ(),LA_RD());
		break;
	case LA_INS_ORI:
		r_strbuf_appendf (&op->esil,"%d,%s,|,%s,=", I_I12(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_XORI:
		r_strbuf_appendf (&op->esil,"%d,%s,^,%s,=", I_I12(opcode), LA_RJ(), LA_RD());
		break;
	case LA_INS_B:
		r_strbuf_appendf (&op->esil,"0x%"LA_PFM",pc,+,pc,=", I26s2_SX(opcode));
		break;
	case LA_INS_BL:
		r_strbuf_appendf (&op->esil,"4,pc,+,ra,=,0x%"LA_PFM",pc,+,pc,=", I26s2_SX(opcode));
		break;
	case LA_INS_JIRL:
		r_strbuf_appendf (&op->esil,"4,pc,+,%s,=,0x%"LA_PFM",pc,+,pc,=",LA_RD(), I16s2_SX(opcode));
		break;
	case LA_INS_BEQ:
		r_strbuf_appendf (&op->esil,"%s,%s,==,$z,?{,0x%"LA_PFM",pc,+,pc,=,}",LA_RJ(), LA_RD(), I16s2_SX(opcode));
		break;
	case LA_INS_BEQZ:
		r_strbuf_appendf (&op->esil,"%s,0,==,$z,?{,0x%"LA_PFM",pc,+,pc,=,}",LA_RJ(),  I21s2_SX(opcode));
		break;
	case LA_INS_BNEZ:
		r_strbuf_appendf (&op->esil,"%s,0,==,$z,!,?{,0x%"LA_PFM",pc,+,pc,=,}",LA_RJ(),  I21s2_SX(opcode));
		break;
	case LA_INS_BNE:
		r_strbuf_appendf (&op->esil,"%s,%s,==,$z,!,?{,0x%"LA_PFM",pc,+,pc,=,}",LA_RJ(), LA_RD(), I16s2_SX(opcode));
		break;
		/* FIXME U means unsigned comparison*/
	case LA_INS_BLTU:
	case LA_INS_BLT:
		r_strbuf_appendf (&op->esil, "%s,%s,<,?{,0x%"LA_PFM",pc,+,pc,=,}",LA_RD(), LA_RJ(), I16s2_SX(opcode));
		break;
	case LA_INS_BGEU:
	case LA_INS_BGE:
		r_strbuf_appendf (&op->esil, "%s,%s,>,?{,0x%"LA_PFM",pc,+,pc,=,}",LA_RD(), LA_RJ(), I16s2_SX(opcode));
		break;
	default:
		break;
	}
	return 0;
}

static int insn_fprintf_func(void *stream, const char *format, ...) {
	int ret = 1;
	va_list ap;
	if (!stream || !format) {
		return 0;
	}
	va_start (ap, format);
	ret = r_strbuf_vappendf (stream, format, ap);
	va_end (ap);

	return ret;
}

static int insn_read_func(bfd_vma memaddr, bfd_byte *addr, unsigned int length, struct disassemble_info *info) {
	PluginData *pd = info->private_data;
	int delta = (memaddr - pd->insn_offset);
	if (delta < 0) {
		return -1;      // disable backward reads
	}
	if ((delta + length) > INSNLEN) {
		return -1;
	}
	memcpy (addr, pd->insn_bytes + delta, length);
	return 0;
}

static void insn_memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//TODO
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *b = op->bytes;
	const int len = op->size;

	struct loongarch_ASE *ase = NULL;
	const struct loongarch_anal_opcode *it;
	ut32 opcode; // , optype;
	ut32 insn_id = 0;
	if (!op || (len < INSNLEN)) {
		return false;
	}
	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = INSNLEN;
	op->addr = addr;
	// Be endian aware
	opcode = r_read_le32 (b);

	/* eprintf("opcode: 0x%x \n", opcode); */
	// optype = 0;

	PluginData *pd = as->data;
	for (ase = pd->la_ases; ase->opcode; ase++) {
		if (!ase->opc_htab_inited) {
			for (it=ase->opcode; it->match; it++) {
				if (!ase->la_opcode_ht[LA_INSN_HASH(it->match)]) {
					ase->la_opcode_ht[LA_INSN_HASH(it->match)] = it;
				}
			}
			int i;
			for (i = 0; i < HT_NUM; i++) {
				if (!ase->la_opcode_ht[i]) {
					ase->la_opcode_ht[i]=it;
				}
			}
			ase->opc_htab_inited = 1;
		}

		it = ase->la_opcode_ht[LA_INSN_HASH(opcode)];
		/* it = ase->opcode; */
		for (; it->match; it++) {
			// optype ++;
			if ((opcode & it->mask) == it->match) {
				insn_id = it->index;
				op->type = it->r_type;
				/* break; //FIXME */
			}
		}
	}
	op->id = insn_id;

	switch (insn_id) {
	case LA_INS_BEQ:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_EQ;
		break;
	case LA_INS_BNE:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_NE;
		break;
	case LA_INS_BLT:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_LT;
		break;
	case LA_INS_BGE:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_GE;
		break;
	case LA_INS_BGEU:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_GE;
		break;
	case LA_INS_BGT:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_GT;
		break;
	case LA_INS_BGTU:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_GT;
		break;
	case LA_INS_BGEZ:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_GE;
		break;
	case LA_INS_BLTU:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_LT;
		break;
	case LA_INS_BLTZ:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_LT;
		break;
	case LA_INS_BLE:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_LE;
		break;
	case LA_INS_BLEZ:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_LE;
		break;
	case LA_INS_BLEU:
		op->jump = addr + I16s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I16s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_LE;
		break;
	case LA_INS_BEQZ:
		op->jump = addr + I21s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I21s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_EQ;
		break;
	case LA_INS_BNEZ:
		op->jump = addr + I21s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I21s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_NE;
		break;
	case LA_INS_BCEQZ:
		op->jump = addr + I21s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I21s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_EQ;
		break;
	case LA_INS_BCNEZ:
		op->jump = addr + I21s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I21s2_SX(opcode);
		op->cond = R_ANAL_CONDTYPE_NE;
		break;
	case LA_INS_B:
		op->jump = addr + I26s2_SX(opcode);
		op->val = I26s2_SX(opcode);
		break;
	case LA_INS_BL:
		op->jump = addr + I26s2_SX(opcode);
		op->fail = addr + INSNLEN;
		op->val = I26s2_SX(opcode);
		break;
	case LA_INS_JIRL:
		op->reg = LA_RJ();
		op->val = I16s2_SX(opcode);
		break;
	case LA_INS_LD_B:
		break;
	case LA_INS_PCADDU12I:
		//TODO
		/* op->val = sign_extend32(I_I20(opcode)<<12, 32); */
		break;
	default:
		if (op->type == R_ANAL_OP_TYPE_CJMP) {
			eprintf ("UNK %d\n", insn_id);
		}
		break;
	}

	if (mask & R_ARCH_OP_MASK_ESIL) {
		if (analop_esil (as, op, opcode)) {
			r_strbuf_fini (&op->esil);
		}
	}
	if (mask & R_ARCH_OP_MASK_VAL) {
		//TODO: add op_fillval (anal, op, &insn);
	}

	if (mask & R_ARCH_OP_MASK_DISASM) {
		PluginData *pd = as->data;
		struct disassemble_info disasm_obj;
		int n = 0;
		RStrBuf *insn_strbuf = r_strbuf_new ("");

		pd->insn_offset = addr;
		/*Looks kind of lame*/
		memcpy (pd->insn_bytes, b, INSNLEN);

		disasm_obj.private_data = pd;
		disasm_obj.fprintf_func = &insn_fprintf_func;
		disasm_obj.memory_error_func = &insn_memory_error_func;
		disasm_obj.read_memory_func = &insn_read_func;
		disasm_obj.stream = insn_strbuf;
		n = print_insn_loongarch (addr, &disasm_obj);
		if (n < 0) {
			op->mnemonic = strdup ("invalid");
		} else {
			op->mnemonic = strdup (insn_strbuf->buf);
		}
		r_strbuf_free (insn_strbuf);
	}
	return true;
}

static int archinfo(RArchSession *as, ut32 q) {
	return INSNLEN;
}

/* Set the profile register */
static char *regs(RArchSession* as) {
	const char *p =
	"=PC	pc\n"
	"=SP	sp\n"
	"=BP	fp\n"
	"=SN	v0\n"
	"=A0	a0\n"
	"=A1	a1\n"
	"=A2	a2\n"
	"=A3	a3\n"
	"=A4	a4\n"
	"=A5	a5\n"
	"=A6	a6\n"
	"=A7	a7\n"
	"=R0    v0\n"
	"=R1    v1\n"
	"gpr	zero	.64	?	0\n"
	"gpr	ra	.64	8	0\n"
	"gpr	tp	.64	16	0\n"
	"gpr	sp	.64	24	0\n"
	/* args */
	"gpr	a0	.64	32	0\n"
	"gpr	a1	.64	40	0\n"
	/*FIXME v0 v1 and a0 a1 are overlapping*/
	"gpr	a2	.64	48	0\n"
	"gpr	a3	.64	56	0\n"
	"gpr	a4	.64	64	0\n"
	"gpr	a5	.64	72	0\n"
	"gpr	a6	.64	80	0\n"
	"gpr	a7	.64	88	0\n"
	/* tmp */
	"gpr	t0	.64	96	0\n"
	"gpr	t1	.64	104	0\n"
	"gpr	t2	.64	112	0\n"
	"gpr	t3	.64	120	0\n"
	"gpr	t4	.64	128	0\n"
	"gpr	t5	.64	136	0\n"
	"gpr	t6	.64	144	0\n"
	"gpr	t7	.64	152	0\n"
	"gpr	t8	.64	160	0\n"
	"gpr	x	.64	168	0\n"
	"gpr	fp	.64	176	0\n"
	/* saved */
	"gpr	s0	.64	184	0\n"
	"gpr	s1	.64	192	0\n"
	"gpr	s2	.64	200	0\n"
	"gpr	s3	.64	208	0\n"
	"gpr	s4	.64	216	0\n"
	"gpr	s5	.64	224	0\n"
	"gpr	s6	.64	232	0\n"
	"gpr	s7	.64	240	0\n"
	"gpr	s8	.64	248	0\n"
	/* extra */
	"gpr	pc	.64	272	0\n"
	;
	return strdup (p);
}

static bool init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (s->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	s->data = R_NEW0 (PluginData);
	PluginData *pd = s->data;
	if (!pd) {
		return false;
	}

	memcpy (pd->la_ases, la_ases_initial, sizeof (la_ases_initial));
	return true;
}

static bool fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	R_FREE (s->data);
	return true;
}

const RArchPlugin r_arch_plugin_loongarch_gnu = {
	.meta = {
		.name = "loongarch",
		.author = "junchao82,zhaojunchao",
		.desc = "Loongson / loongarch / mips-like architecture",
		.license = "LGPL-3.0-only",
	},
	.arch = "loongarch",
	.bits = 64,
	.info = archinfo,
	.decode = decode,
	.regs = regs,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_loongarch_gnu
};
#endif
