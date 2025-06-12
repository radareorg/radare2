/* radare - LGPL - Copyright 2010-2024 - pancake */

#include <r_arch.h>
#include "../../include/disas-asm.h"
#include "../../include/opcode/mips.h"

typedef struct plugin_data_t {
	char *pre_cpu;
	ut64 t9_pre;
} PluginData;

static int symbol_at_address(bfd_vma addr, struct disassemble_info *info) {
	return 0;
}

static void memory_error_func(int status, bfd_vma memaddr, struct disassemble_info *info) {
	//--
}

static int mips_buffer_read_memory(bfd_vma memaddr, bfd_byte *myaddr, unsigned int length, struct disassemble_info *info) {
	int delta = (memaddr - info->buffer_vma);
	if (delta < 0) {
		return -1; // disable backward reads
	}
	if ((delta + length) > 4) {
		return -1;
	}
	ut8 *bytes = info->buffer;
	memcpy (myaddr, bytes + delta, length);
	return 0;
}

DECLARE_GENERIC_PRINT_ADDRESS_FUNC_NOGLOBALS ()
DECLARE_GENERIC_FPRINTF_FUNC_NOGLOBALS ()

#define REG_BUF_MAX 32
// ESIL macros:

// put the sign bit on the stack
#define ES_IS_NEGATIVE(arg) "1," arg ",<<<,1,&"

#define ES_B(x) "0xff," x ",&"
#define ES_H(x) "0xffff," x ",&"
#define ES_W(x) "0xffffffff," x ",&"
// call with delay slot
#define ES_CALL_DR(ra, addr) "pc,4,+," ra ",=," ES_J (addr)
#define ES_CALL_D(addr)      ES_CALL_DR ("ra", addr)

// call without delay slot
#define ES_CALL_NDR(ra, addr) "pc," ra ",=," ES_J (addr)
#define ES_CALL_ND(addr)      ES_CALL_NDR ("ra", addr)

#define USE_DS 0
#if USE_DS
// emit ERR trap if executed in a delay slot
#define ES_TRAP_DS() "$ds,!,!,?{,$$,1,TRAP,BREAK,},"
// jump to address
#define ES_J(addr) addr ",SETJT,1,SETD"
#else
#define ES_TRAP_DS() ""
#define ES_J(addr)   addr ",pc,:="
#endif

#define ES_SIGN32_64(arg) es_sign_n_64 (as, op, arg, 32)
#define ES_SIGN16_64(arg) es_sign_n_64 (as, op, arg, 16)

#define ES_ADD_CK32_OVERF(x, y, z) es_add_ck (op, x, y, z, 32)
#define ES_ADD_CK64_OVERF(x, y, z) es_add_ck (op, x, y, z, 64)

static inline void es_sign_n_64(RArchSession *as, RAnalOp *op, const char *arg, int bit) {
	if (as->config->bits == 64) {
		r_strbuf_appendf (&op->esil, ",%d,%s,~,%s,=,", bit, arg, arg);
	} else {
		r_strbuf_append (&op->esil, ",");
	}
}

static inline void es_add_ck(RAnalOp *op, const char *a1, const char *a2, const char *re, int bit) {
	ut64 mask = 1ULL << (bit - 1);
	r_strbuf_appendf (&op->esil,
		"%d,0x%" PFMT64x ",%s,%s,^,&,>>,%d,0x%" PFMT64x ",%s,%s,+,&,>>,|,1,==,$z,?{,0x%" PFMT64x ",1,TRAP,}{,%s,%s,+,%s,=,}",
		bit - 2, mask, a1, a2, bit - 1, mask, a1, a2, op->addr, a1, a2, re);
}
// MIPS instruction
typedef enum mips_insn {
	MIPS_INS_INVALID = 0,

	MIPS_INS_ABSQ_S,
	MIPS_INS_ADD,
	MIPS_INS_ADDIUPC,
	MIPS_INS_ADDIUR1SP,
	MIPS_INS_ADDIUR2,
	MIPS_INS_ADDIUS5,
	MIPS_INS_ADDIUSP,
	MIPS_INS_ADDQH,
	MIPS_INS_ADDQH_R,
	MIPS_INS_ADDQ,
	MIPS_INS_ADDQ_S,
	MIPS_INS_ADDSC,
	MIPS_INS_ADDS_A,
	MIPS_INS_ADDS_S,
	MIPS_INS_ADDS_U,
	MIPS_INS_ADDU16,
	MIPS_INS_ADDUH,
	MIPS_INS_ADDUH_R,
	MIPS_INS_ADDU,
	MIPS_INS_ADDU_S,
	MIPS_INS_ADDVI,
	MIPS_INS_ADDV,
	MIPS_INS_ADDWC,
	MIPS_INS_ADD_A,
	MIPS_INS_ADDI,
	MIPS_INS_ADDIU,
	MIPS_INS_ALIGN,
	MIPS_INS_ALUIPC,
	MIPS_INS_AND,
	MIPS_INS_AND16,
	MIPS_INS_ANDI16,
	MIPS_INS_ANDI,
	MIPS_INS_APPEND,
	MIPS_INS_ASUB_S,
	MIPS_INS_ASUB_U,
	MIPS_INS_AUI,
	MIPS_INS_AUIPC,
	MIPS_INS_AVER_S,
	MIPS_INS_AVER_U,
	MIPS_INS_AVE_S,
	MIPS_INS_AVE_U,
	MIPS_INS_B16,
	MIPS_INS_BADDU,
	MIPS_INS_BAL,
	MIPS_INS_BALC,
	MIPS_INS_BALIGN,
	MIPS_INS_BBIT0,
	MIPS_INS_BBIT032,
	MIPS_INS_BBIT1,
	MIPS_INS_BBIT132,
	MIPS_INS_BC,
	MIPS_INS_BC0F,
	MIPS_INS_BC0FL,
	MIPS_INS_BC0T,
	MIPS_INS_BC0TL,
	MIPS_INS_BC1EQZ,
	MIPS_INS_BC1F,
	MIPS_INS_BC1FL,
	MIPS_INS_BC1NEZ,
	MIPS_INS_BC1T,
	MIPS_INS_BC1TL,
	MIPS_INS_BC2EQZ,
	MIPS_INS_BC2F,
	MIPS_INS_BC2FL,
	MIPS_INS_BC2NEZ,
	MIPS_INS_BC2T,
	MIPS_INS_BC2TL,
	MIPS_INS_BC3F,
	MIPS_INS_BC3FL,
	MIPS_INS_BC3T,
	MIPS_INS_BC3TL,
	MIPS_INS_BCLRI,
	MIPS_INS_BCLR,
	MIPS_INS_BEQ,
	MIPS_INS_BEQC,
	MIPS_INS_BEQL,
	MIPS_INS_BEQZ16,
	MIPS_INS_BEQZALC,
	MIPS_INS_BEQZC,
	MIPS_INS_BGEC,
	MIPS_INS_BGEUC,
	MIPS_INS_BGEZ,
	MIPS_INS_BGEZAL,
	MIPS_INS_BGEZALC,
	MIPS_INS_BGEZALL,
	MIPS_INS_BGEZALS,
	MIPS_INS_BGEZC,
	MIPS_INS_BGEZL,
	MIPS_INS_BGTZ,
	MIPS_INS_BGTZALC,
	MIPS_INS_BGTZC,
	MIPS_INS_BGTZL,
	MIPS_INS_BINSLI,
	MIPS_INS_BINSL,
	MIPS_INS_BINSRI,
	MIPS_INS_BINSR,
	MIPS_INS_BITREV,
	MIPS_INS_BITSWAP,
	MIPS_INS_BLEZ,
	MIPS_INS_BLEZALC,
	MIPS_INS_BLEZC,
	MIPS_INS_BLEZL,
	MIPS_INS_BLTC,
	MIPS_INS_BLTUC,
	MIPS_INS_BLTZ,
	MIPS_INS_BLTZAL,
	MIPS_INS_BLTZALC,
	MIPS_INS_BLTZALL,
	MIPS_INS_BLTZALS,
	MIPS_INS_BLTZC,
	MIPS_INS_BLTZL,
	MIPS_INS_BMNZI,
	MIPS_INS_BMNZ,
	MIPS_INS_BMZI,
	MIPS_INS_BMZ,
	MIPS_INS_BNE,
	MIPS_INS_BNEC,
	MIPS_INS_BNEGI,
	MIPS_INS_BNEG,
	MIPS_INS_BNEL,
	MIPS_INS_BNEZ16,
	MIPS_INS_BNEZALC,
	MIPS_INS_BNEZC,
	MIPS_INS_BNVC,
	MIPS_INS_BNZ,
	MIPS_INS_BOVC,
	MIPS_INS_BPOSGE32,
	MIPS_INS_BREAK,
	MIPS_INS_BREAK16,
	MIPS_INS_BSELI,
	MIPS_INS_BSEL,
	MIPS_INS_BSETI,
	MIPS_INS_BSET,
	MIPS_INS_BZ,
	MIPS_INS_BEQZ,
	MIPS_INS_B,
	MIPS_INS_BNEZ,
	MIPS_INS_BTEQZ,
	MIPS_INS_BTNEZ,
	MIPS_INS_CACHE,
	MIPS_INS_CEIL,
	MIPS_INS_CEQI,
	MIPS_INS_CEQ,
	MIPS_INS_CFC1,
	MIPS_INS_CFCMSA,
	MIPS_INS_CINS,
	MIPS_INS_CINS32,
	MIPS_INS_CLASS,
	MIPS_INS_CLEI_S,
	MIPS_INS_CLEI_U,
	MIPS_INS_CLE_S,
	MIPS_INS_CLE_U,
	MIPS_INS_CLO,
	MIPS_INS_CLTI_S,
	MIPS_INS_CLTI_U,
	MIPS_INS_CLT_S,
	MIPS_INS_CLT_U,
	MIPS_INS_CLZ,
	MIPS_INS_CMPGDU,
	MIPS_INS_CMPGU,
	MIPS_INS_CMPU,
	MIPS_INS_CMP,
	MIPS_INS_COPY_S,
	MIPS_INS_COPY_U,
	MIPS_INS_CTC1,
	MIPS_INS_CTCMSA,
	MIPS_INS_CVT,
	MIPS_INS_C,
	MIPS_INS_CMPI,
	MIPS_INS_DADD,
	MIPS_INS_DADDI,
	MIPS_INS_DADDIU,
	MIPS_INS_DADDU,
	MIPS_INS_DAHI,
	MIPS_INS_DALIGN,
	MIPS_INS_DATI,
	MIPS_INS_DAUI,
	MIPS_INS_DBITSWAP,
	MIPS_INS_DCLO,
	MIPS_INS_DCLZ,
	MIPS_INS_DDIV,
	MIPS_INS_DDIVU,
	MIPS_INS_DERET,
	MIPS_INS_DEXT,
	MIPS_INS_DEXTM,
	MIPS_INS_DEXTU,
	MIPS_INS_DI,
	MIPS_INS_DINS,
	MIPS_INS_DINSM,
	MIPS_INS_DINSU,
	MIPS_INS_DIV,
	MIPS_INS_DIVU,
	MIPS_INS_DIV_S,
	MIPS_INS_DIV_U,
	MIPS_INS_DLSA,
	MIPS_INS_DMFC0,
	MIPS_INS_DMFC1,
	MIPS_INS_DMFC2,
	MIPS_INS_DMOD,
	MIPS_INS_DMODU,
	MIPS_INS_DMTC0,
	MIPS_INS_DMTC1,
	MIPS_INS_DMTC2,
	MIPS_INS_DMUH,
	MIPS_INS_DMUHU,
	MIPS_INS_DMUL,
	MIPS_INS_DMULT,
	MIPS_INS_DMULTU,
	MIPS_INS_DMULU,
	MIPS_INS_DOTP_S,
	MIPS_INS_DOTP_U,
	MIPS_INS_DPADD_S,
	MIPS_INS_DPADD_U,
	MIPS_INS_DPAQX_SA,
	MIPS_INS_DPAQX_S,
	MIPS_INS_DPAQ_SA,
	MIPS_INS_DPAQ_S,
	MIPS_INS_DPAU,
	MIPS_INS_DPAX,
	MIPS_INS_DPA,
	MIPS_INS_DPOP,
	MIPS_INS_DPSQX_SA,
	MIPS_INS_DPSQX_S,
	MIPS_INS_DPSQ_SA,
	MIPS_INS_DPSQ_S,
	MIPS_INS_DPSUB_S,
	MIPS_INS_DPSUB_U,
	MIPS_INS_DPSU,
	MIPS_INS_DPSX,
	MIPS_INS_DPS,
	MIPS_INS_DROTR,
	MIPS_INS_DROTR32,
	MIPS_INS_DROTRV,
	MIPS_INS_DSBH,
	MIPS_INS_DSHD,
	MIPS_INS_DSLL,
	MIPS_INS_DSLL32,
	MIPS_INS_DSLLV,
	MIPS_INS_DSRA,
	MIPS_INS_DSRA32,
	MIPS_INS_DSRAV,
	MIPS_INS_DSRL,
	MIPS_INS_DSRL32,
	MIPS_INS_DSRLV,
	MIPS_INS_DSUB,
	MIPS_INS_DSUBU,
	MIPS_INS_EHB,
	MIPS_INS_EI,
	MIPS_INS_ERET,
	MIPS_INS_EXT,
	MIPS_INS_EXTP,
	MIPS_INS_EXTPDP,
	MIPS_INS_EXTPDPV,
	MIPS_INS_EXTPV,
	MIPS_INS_EXTRV_RS,
	MIPS_INS_EXTRV_R,
	MIPS_INS_EXTRV_S,
	MIPS_INS_EXTRV,
	MIPS_INS_EXTR_RS,
	MIPS_INS_EXTR_R,
	MIPS_INS_EXTR_S,
	MIPS_INS_EXTR,
	MIPS_INS_EXTS,
	MIPS_INS_EXTS32,
	MIPS_INS_ABS,
	MIPS_INS_FADD,
	MIPS_INS_FCAF,
	MIPS_INS_FCEQ,
	MIPS_INS_FCLASS,
	MIPS_INS_FCLE,
	MIPS_INS_FCLT,
	MIPS_INS_FCNE,
	MIPS_INS_FCOR,
	MIPS_INS_FCUEQ,
	MIPS_INS_FCULE,
	MIPS_INS_FCULT,
	MIPS_INS_FCUNE,
	MIPS_INS_FCUN,
	MIPS_INS_FDIV,
	MIPS_INS_FEXDO,
	MIPS_INS_FEXP2,
	MIPS_INS_FEXUPL,
	MIPS_INS_FEXUPR,
	MIPS_INS_FFINT_S,
	MIPS_INS_FFINT_U,
	MIPS_INS_FFQL,
	MIPS_INS_FFQR,
	MIPS_INS_FILL,
	MIPS_INS_FLOG2,
	MIPS_INS_FLOOR,
	MIPS_INS_FMADD,
	MIPS_INS_FMAX_A,
	MIPS_INS_FMAX,
	MIPS_INS_FMIN_A,
	MIPS_INS_FMIN,
	MIPS_INS_MOV,
	MIPS_INS_FMSUB,
	MIPS_INS_FMUL,
	MIPS_INS_MUL,
	MIPS_INS_NEG,
	MIPS_INS_FRCP,
	MIPS_INS_FRINT,
	MIPS_INS_FRSQRT,
	MIPS_INS_FSAF,
	MIPS_INS_FSEQ,
	MIPS_INS_FSLE,
	MIPS_INS_FSLT,
	MIPS_INS_FSNE,
	MIPS_INS_FSOR,
	MIPS_INS_FSQRT,
	MIPS_INS_SQRT,
	MIPS_INS_FSUB,
	MIPS_INS_SUB,
	MIPS_INS_FSUEQ,
	MIPS_INS_FSULE,
	MIPS_INS_FSULT,
	MIPS_INS_FSUNE,
	MIPS_INS_FSUN,
	MIPS_INS_FTINT_S,
	MIPS_INS_FTINT_U,
	MIPS_INS_FTQ,
	MIPS_INS_FTRUNC_S,
	MIPS_INS_FTRUNC_U,
	MIPS_INS_HADD_S,
	MIPS_INS_HADD_U,
	MIPS_INS_HSUB_S,
	MIPS_INS_HSUB_U,
	MIPS_INS_ILVEV,
	MIPS_INS_ILVL,
	MIPS_INS_ILVOD,
	MIPS_INS_ILVR,
	MIPS_INS_INS,
	MIPS_INS_INSERT,
	MIPS_INS_INSV,
	MIPS_INS_INSVE,
	MIPS_INS_J,
	MIPS_INS_JAL,
	MIPS_INS_JALR,
	MIPS_INS_JALRS16,
	MIPS_INS_JALRS,
	MIPS_INS_JALS,
	MIPS_INS_JALX,
	MIPS_INS_JIALC,
	MIPS_INS_JIC,
	MIPS_INS_JR,
	MIPS_INS_JR16,
	MIPS_INS_JRADDIUSP,
	MIPS_INS_JRC,
	MIPS_INS_JALRC,
	MIPS_INS_LB,
	MIPS_INS_LBU16,
	MIPS_INS_LBUX,
	MIPS_INS_LBU,
	MIPS_INS_LD,
	MIPS_INS_LDC1,
	MIPS_INS_LDC2,
	MIPS_INS_LDC3,
	MIPS_INS_LDI,
	MIPS_INS_LDL,
	MIPS_INS_LDPC,
	MIPS_INS_LDR,
	MIPS_INS_LDXC1,
	MIPS_INS_LH,
	MIPS_INS_LHU16,
	MIPS_INS_LHX,
	MIPS_INS_LHU,
	MIPS_INS_LI16,
	MIPS_INS_LL,
	MIPS_INS_LLD,
	MIPS_INS_LSA,
	MIPS_INS_LUXC1,
	MIPS_INS_LUI,
	MIPS_INS_LW,
	MIPS_INS_LW16,
	MIPS_INS_LWC1,
	MIPS_INS_LWC2,
	MIPS_INS_LWC3,
	MIPS_INS_LWL,
	MIPS_INS_LWM16,
	MIPS_INS_LWM32,
	MIPS_INS_LWPC,
	MIPS_INS_LWP,
	MIPS_INS_LWR,
	MIPS_INS_LWUPC,
	MIPS_INS_LWU,
	MIPS_INS_LWX,
	MIPS_INS_LWXC1,
	MIPS_INS_LWXS,
	MIPS_INS_LI,
	MIPS_INS_MADD,
	MIPS_INS_MADDF,
	MIPS_INS_MADDR_Q,
	MIPS_INS_MADDU,
	MIPS_INS_MADDV,
	MIPS_INS_MADD_Q,
	MIPS_INS_MAQ_SA,
	MIPS_INS_MAQ_S,
	MIPS_INS_MAXA,
	MIPS_INS_MAXI_S,
	MIPS_INS_MAXI_U,
	MIPS_INS_MAX_A,
	MIPS_INS_MAX,
	MIPS_INS_MAX_S,
	MIPS_INS_MAX_U,
	MIPS_INS_MFC0,
	MIPS_INS_MFC1,
	MIPS_INS_MFC2,
	MIPS_INS_MFHC1,
	MIPS_INS_MFHI,
	MIPS_INS_MFLO,
	MIPS_INS_MINA,
	MIPS_INS_MINI_S,
	MIPS_INS_MINI_U,
	MIPS_INS_MIN_A,
	MIPS_INS_MIN,
	MIPS_INS_MIN_S,
	MIPS_INS_MIN_U,
	MIPS_INS_MOD,
	MIPS_INS_MODSUB,
	MIPS_INS_MODU,
	MIPS_INS_MOD_S,
	MIPS_INS_MOD_U,
	MIPS_INS_MOVE,
	MIPS_INS_MOVEP,
	MIPS_INS_MOVF,
	MIPS_INS_MOVN,
	MIPS_INS_MOVT,
	MIPS_INS_MOVZ,
	MIPS_INS_MSUB,
	MIPS_INS_MSUBF,
	MIPS_INS_MSUBR_Q,
	MIPS_INS_MSUBU,
	MIPS_INS_MSUBV,
	MIPS_INS_MSUB_Q,
	MIPS_INS_MTC0,
	MIPS_INS_MTC1,
	MIPS_INS_MTC2,
	MIPS_INS_MTHC1,
	MIPS_INS_MTHI,
	MIPS_INS_MTHLIP,
	MIPS_INS_MTLO,
	MIPS_INS_MTM0,
	MIPS_INS_MTM1,
	MIPS_INS_MTM2,
	MIPS_INS_MTP0,
	MIPS_INS_MTP1,
	MIPS_INS_MTP2,
	MIPS_INS_MUH,
	MIPS_INS_MUHU,
	MIPS_INS_MULEQ_S,
	MIPS_INS_MULEU_S,
	MIPS_INS_MULQ_RS,
	MIPS_INS_MULQ_S,
	MIPS_INS_MULR_Q,
	MIPS_INS_MULSAQ_S,
	MIPS_INS_MULSA,
	MIPS_INS_MULT,
	MIPS_INS_MULTU,
	MIPS_INS_MULU,
	MIPS_INS_MULV,
	MIPS_INS_MUL_Q,
	MIPS_INS_MUL_S,
	MIPS_INS_NLOC,
	MIPS_INS_NLZC,
	MIPS_INS_NMADD,
	MIPS_INS_NMSUB,
	MIPS_INS_NOR,
	MIPS_INS_NORI,
	MIPS_INS_NOT16,
	MIPS_INS_NOT,
	MIPS_INS_OR,
	MIPS_INS_OR16,
	MIPS_INS_ORI,
	MIPS_INS_PACKRL,
	MIPS_INS_PAUSE,
	MIPS_INS_PCKEV,
	MIPS_INS_PCKOD,
	MIPS_INS_PCNT,
	MIPS_INS_PICK,
	MIPS_INS_POP,
	MIPS_INS_PRECEQU,
	MIPS_INS_PRECEQ,
	MIPS_INS_PRECEU,
	MIPS_INS_PRECRQU_S,
	MIPS_INS_PRECRQ,
	MIPS_INS_PRECRQ_RS,
	MIPS_INS_PRECR,
	MIPS_INS_PRECR_SRA,
	MIPS_INS_PRECR_SRA_R,
	MIPS_INS_PREF,
	MIPS_INS_PREPEND,
	MIPS_INS_RADDU,
	MIPS_INS_RDDSP,
	MIPS_INS_RDHWR,
	MIPS_INS_REPLV,
	MIPS_INS_REPL,
	MIPS_INS_RINT,
	MIPS_INS_ROTR,
	MIPS_INS_ROTRV,
	MIPS_INS_ROUND,
	MIPS_INS_SAT_S,
	MIPS_INS_SAT_U,
	MIPS_INS_SB,
	MIPS_INS_SB16,
	MIPS_INS_SC,
	MIPS_INS_SCD,
	MIPS_INS_SD,
	MIPS_INS_SDBBP,
	MIPS_INS_SDBBP16,
	MIPS_INS_SDC1,
	MIPS_INS_SDC2,
	MIPS_INS_SDC3,
	MIPS_INS_SDL,
	MIPS_INS_SDR,
	MIPS_INS_SDXC1,
	MIPS_INS_SEB,
	MIPS_INS_SEH,
	MIPS_INS_SELEQZ,
	MIPS_INS_SELNEZ,
	MIPS_INS_SEL,
	MIPS_INS_SEQ,
	MIPS_INS_SEQI,
	MIPS_INS_SH,
	MIPS_INS_SH16,
	MIPS_INS_SHF,
	MIPS_INS_SHILO,
	MIPS_INS_SHILOV,
	MIPS_INS_SHLLV,
	MIPS_INS_SHLLV_S,
	MIPS_INS_SHLL,
	MIPS_INS_SHLL_S,
	MIPS_INS_SHRAV,
	MIPS_INS_SHRAV_R,
	MIPS_INS_SHRA,
	MIPS_INS_SHRA_R,
	MIPS_INS_SHRLV,
	MIPS_INS_SHRL,
	MIPS_INS_SLDI,
	MIPS_INS_SLD,
	MIPS_INS_SLL,
	MIPS_INS_SLL16,
	MIPS_INS_SLLI,
	MIPS_INS_SLLV,
	MIPS_INS_SLT,
	MIPS_INS_SLTI,
	MIPS_INS_SLTIU,
	MIPS_INS_SLTU,
	MIPS_INS_SNE,
	MIPS_INS_SNEI,
	MIPS_INS_SPLATI,
	MIPS_INS_SPLAT,
	MIPS_INS_SRA,
	MIPS_INS_SRAI,
	MIPS_INS_SRARI,
	MIPS_INS_SRAR,
	MIPS_INS_SRAV,
	MIPS_INS_SRL,
	MIPS_INS_SRL16,
	MIPS_INS_SRLI,
	MIPS_INS_SRLRI,
	MIPS_INS_SRLR,
	MIPS_INS_SRLV,
	MIPS_INS_SSNOP,
	MIPS_INS_ST,
	MIPS_INS_SUBQH,
	MIPS_INS_SUBQH_R,
	MIPS_INS_SUBQ,
	MIPS_INS_SUBQ_S,
	MIPS_INS_SUBSUS_U,
	MIPS_INS_SUBSUU_S,
	MIPS_INS_SUBS_S,
	MIPS_INS_SUBS_U,
	MIPS_INS_SUBU16,
	MIPS_INS_SUBUH,
	MIPS_INS_SUBUH_R,
	MIPS_INS_SUBU,
	MIPS_INS_SUBU_S,
	MIPS_INS_SUBVI,
	MIPS_INS_SUBV,
	MIPS_INS_SUXC1,
	MIPS_INS_SW,
	MIPS_INS_SW16,
	MIPS_INS_SWC1,
	MIPS_INS_SWC2,
	MIPS_INS_SWC3,
	MIPS_INS_SWL,
	MIPS_INS_SWM16,
	MIPS_INS_SWM32,
	MIPS_INS_SWP,
	MIPS_INS_SWR,
	MIPS_INS_SWXC1,
	MIPS_INS_SYNC,
	MIPS_INS_SYNCI,
	MIPS_INS_SYSCALL,
	MIPS_INS_TEQ,
	MIPS_INS_TEQI,
	MIPS_INS_TGE,
	MIPS_INS_TGEI,
	MIPS_INS_TGEIU,
	MIPS_INS_TGEU,
	MIPS_INS_TLBP,
	MIPS_INS_TLBR,
	MIPS_INS_TLBWI,
	MIPS_INS_TLBWR,
	MIPS_INS_TLT,
	MIPS_INS_TLTI,
	MIPS_INS_TLTIU,
	MIPS_INS_TLTU,
	MIPS_INS_TNE,
	MIPS_INS_TNEI,
	MIPS_INS_TRUNC,
	MIPS_INS_V3MULU,
	MIPS_INS_VMM0,
	MIPS_INS_VMULU,
	MIPS_INS_VSHF,
	MIPS_INS_WAIT,
	MIPS_INS_WRDSP,
	MIPS_INS_WSBH,
	MIPS_INS_XOR,
	MIPS_INS_XOR16,
	MIPS_INS_XORI,

	//> some alias instructions
	MIPS_INS_NOP,
	MIPS_INS_NEGU,

	//> special instructions
	MIPS_INS_JALR_HB, // jump and link with Hazard Barrier
	MIPS_INS_JR_HB, // jump register with Hazard Barrier

	MIPS_INS_ENDING,
} mips_insn;

struct gnu_rreg {
	const char *rs;
	const char *rt;
	const char *rd;
	ut8 sa[REG_BUF_MAX];
};

struct gnu_jreg {
	ut8 jump[REG_BUF_MAX];
};

struct gnu_ireg {
	const char *rs;
	const char *rt;
	union {
		ut8 imm[REG_BUF_MAX];
		ut8 jump[REG_BUF_MAX];
	};
};

typedef struct gnu_insn {
	ut8 optype;
	ut32 id;
	union {
		struct gnu_rreg r_reg;
		struct gnu_ireg i_reg;
		struct gnu_jreg j_reg;
	};
} gnu_insn;

#define R_REG(x) ((const char *)insn->r_reg.x)
#define I_REG(x) ((const char *)insn->i_reg.x)
#define J_REG(x) ((const char *)insn->j_reg.x)

/* Return a mapping from the register number i.e. $0 .. $31 to string name */
static const char *mips_reg_decode(ut32 reg_num) {
	/* See page 36 of "See Mips Run Linux, 2e, D. Sweetman, 2007"*/
	static const char *REGISTERS[32] = {
		"zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
		"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
		"s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7",
		"t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"
	};
	if (reg_num < 32) {
		return REGISTERS[reg_num];
	}
	return NULL;
}

static int analop_esil(RArchSession *as, RAnalOp *op, ut64 addr, gnu_insn *insn) {
	switch (insn->id) {
	case MIPS_INS_NOP:
		r_strbuf_set (&op->esil, ",");
		break;
	case MIPS_INS_BREAK:
		// r_strbuf_setf (&op->esil, "%d,%d,TRAP", IMM (0), IMM (0));
		break;
	case MIPS_INS_SD:
		r_strbuf_appendf (&op->esil, "%s,%s,%s,+,=[8]",
			I_REG (rt), I_REG (imm), I_REG (rs));
		break;
	case MIPS_INS_SW:
	case MIPS_INS_SWL:
	case MIPS_INS_SWR:
		r_strbuf_appendf (&op->esil, "%s,%s,%s,+,=[4]",
			I_REG (rt), I_REG (imm), I_REG (rs));
		break;
	case MIPS_INS_SH:
		r_strbuf_appendf (&op->esil, "%s,%s,%s,+,=[2]",
			I_REG (rt), I_REG (imm), I_REG (rs));
		break;
	case MIPS_INS_SWC1:
	case MIPS_INS_SWC2:
		break;
	case MIPS_INS_SB:
		r_strbuf_appendf (&op->esil, "%s,%s,%s,+,=[1]",
			I_REG (rt), I_REG (imm), I_REG (rs));
		break;
	case MIPS_INS_CMP:
	case MIPS_INS_CMPU:
	case MIPS_INS_CMPGU:
	case MIPS_INS_CMPGDU:
	case MIPS_INS_CMPI:
		break;
	case MIPS_INS_SHRAV:
	case MIPS_INS_SHRAV_R:
	case MIPS_INS_SHRA:
	case MIPS_INS_SHRA_R:
		break;
	case MIPS_INS_SRA:
		r_strbuf_appendf (&op->esil,
			ES_W ("%s,%s") ",>>,31,%s,>>,?{,%s,32,-,0xffffffff,<<,0xffffffff,&,}{,0,},|,%s,=",
			R_REG (sa), R_REG (rt), R_REG (rt), R_REG (sa), R_REG (rd));
		break;
	case MIPS_INS_DSRA:
		r_strbuf_appendf (&op->esil,
			"%s,%s,>>,31,%s,>>,?{,32,%s,32,-,0xffffffff,<<,0xffffffff,&,<<,}{,0,},|,%s,=",
			R_REG (sa), R_REG (rt), R_REG (rt), R_REG (sa), R_REG (rd));
		break;
	case MIPS_INS_SHRL:
		// suffix 'S' forces conditional flag to be updated
		break;
	case MIPS_INS_SRLV:
	case MIPS_INS_SRL:
		r_strbuf_appendf (&op->esil, "%s,%s,>>,%s,=",
			R_REG (rs) ? R_REG (rs) : R_REG (sa), R_REG (rt), R_REG (rd));
		break;
	case MIPS_INS_SLLV:
	case MIPS_INS_SLL:
		r_strbuf_appendf (&op->esil, "%s,%s,<<,%s,=",
			R_REG (rs) ? R_REG (rs) : R_REG (sa), R_REG (rt), R_REG (rd));
		break;
	case MIPS_INS_BAL:
	case MIPS_INS_JAL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "" ES_CALL_D ("%s"), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_JALR:
	case MIPS_INS_JALRS:
		if (!strcmp (R_REG (rd), "rd")) {
			r_strbuf_appendf (&op->esil, ES_TRAP_DS () "" ES_CALL_D ("%s"), R_REG (rs));
		} else {
			r_strbuf_appendf (&op->esil, ES_TRAP_DS () "" ES_CALL_DR ("%s", "%s"), R_REG (rd), R_REG (rs));
		}
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_JR:
	case MIPS_INS_JRC:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "" ES_J ("%s"), R_REG (rs));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_J:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "" ES_J ("%s"), J_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
	case MIPS_INS_B:
		// jump to address with conditional
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "" ES_J ("%s"), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BNE: // bne $s, $t, offset
	case MIPS_INS_BNEL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "%s,%s,==,$z,!,?{," ES_J ("%s") ",}",
			I_REG (rs), I_REG (rt), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BEQ:
	case MIPS_INS_BEQL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "%s,%s,==,$z,?{," ES_J ("%s") ",}",
			I_REG (rs), I_REG (rt), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BZ:
	case MIPS_INS_BEQZ:
	case MIPS_INS_BEQZC:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "%s,0,==,$z,?{," ES_J ("%s") ",}",
			I_REG (rs), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BNEZ:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "%s,0,==,$z,!,?{," ES_J ("%s") ",}",
			I_REG (rs), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BLEZ:
	case MIPS_INS_BLEZC:
	case MIPS_INS_BLEZL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "0,%s,==,$z,?{," ES_J ("%s") ",BREAK,},",
			I_REG (rs), I_REG (jump));
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "1," ES_IS_NEGATIVE ("%s") ",==,$z,?{," ES_J ("%s") ",}",
			I_REG (rs), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BGEZ:
	case MIPS_INS_BGEZC:
	case MIPS_INS_BGEZL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "0," ES_IS_NEGATIVE ("%s") ",==,$z,?{," ES_J ("%s") ",}",
			I_REG (rs), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BGEZAL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "0," ES_IS_NEGATIVE ("%s") ",==,$z,?{," ES_CALL_D ("%s") ",}",
			I_REG (rs), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BLTZAL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "1," ES_IS_NEGATIVE ("%s") ",==,$z,?{," ES_CALL_D ("%s") ",}",
			I_REG (rs), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BLTZ:
	case MIPS_INS_BLTZC:
	case MIPS_INS_BLTZL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "1," ES_IS_NEGATIVE ("%s") ",==,$z,?{," ES_J ("%s") ",}",
			I_REG (rs), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BGTZ:
	case MIPS_INS_BGTZC:
	case MIPS_INS_BGTZL:
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "0,%s,==,$z,?{,BREAK,},", I_REG (rs));
		r_strbuf_appendf (&op->esil, ES_TRAP_DS () "0," ES_IS_NEGATIVE ("%s") ",==,$z,?{," ES_J ("%s") ",}",
			I_REG (rs), I_REG (jump));
#if USE_DS
		r_strbuf_replacef (&op->esil, "$$", "0x%"PFMT64x, addr);
#endif
		break;
	case MIPS_INS_BTEQZ:
		break;
	case MIPS_INS_BTNEZ:
		break;
	case MIPS_INS_MOV:
	case MIPS_INS_MOVE:
		r_strbuf_appendf (&op->esil, "%s,%s,=", R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_MOVZ:
	case MIPS_INS_MOVF:
		r_strbuf_appendf (&op->esil, "0,%s,==,$z,?{,%s,%s,=,}",
			R_REG (rt), R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_MOVN:
		r_strbuf_appendf (&op->esil, "0,%s,==,$z,!,?{,%s,%s,=,}",
			R_REG (rt), R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_MOVT:
		r_strbuf_appendf (&op->esil, "1,%s,==,$z,?{,%s,%s,=,}",
			R_REG (rt), R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_FSUB:
	case MIPS_INS_SUB:
	case MIPS_INS_SUBU:
	case MIPS_INS_DSUB:
	case MIPS_INS_DSUBU:
		r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=",
			R_REG (rt), R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_NEG:
	case MIPS_INS_NEGU:
		break;
	/** signed -- sets overflow flag */
	case MIPS_INS_ADD:
		ES_ADD_CK32_OVERF (R_REG (rs), R_REG (rt), R_REG (rd));
		break;
	case MIPS_INS_ADDI:
		ES_ADD_CK32_OVERF (I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_DADD:
		ES_ADD_CK64_OVERF (R_REG (rs), R_REG (rt), R_REG (rd));
		break;
	case MIPS_INS_DADDU:
	case MIPS_INS_ADDU:
		r_strbuf_appendf (&op->esil, "%s,%s,+,%s,=",
			R_REG (rt), R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_DADDI:
		ES_ADD_CK64_OVERF (I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_ADDIU:
	case MIPS_INS_DADDIU:
		r_strbuf_appendf (&op->esil, "%s,%s,+,%s,=",
			I_REG (imm), I_REG (rs), I_REG (rt));
		ES_SIGN32_64 (I_REG (rt));
		break;
	case MIPS_INS_LI:
	case MIPS_INS_LDI:
		r_strbuf_appendf (&op->esil, "%s,%s,=", I_REG (imm), I_REG (rt));
		break;
	case MIPS_INS_LUI:
		r_strbuf_appendf (&op->esil, "%s0000,%s,=", I_REG (imm), I_REG (rt));
		break;
	case MIPS_INS_LB:
		op->sign = true; // To load a byte from memory as a signed value
		/* fallthrough */
	case MIPS_INS_LBU:
		// one of these is wrong
		r_strbuf_appendf (&op->esil, "%s,%s,+,[1],%s,=",
			I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_LW:
	case MIPS_INS_LWC1:
	case MIPS_INS_LWC2:
	case MIPS_INS_LWL:
	case MIPS_INS_LWR:
	case MIPS_INS_LWU:
	case MIPS_INS_LL:
		r_strbuf_appendf (&op->esil, "%s,%s,+,[4],%s,=",
			I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_LDL:
	case MIPS_INS_LDC1:
	case MIPS_INS_LDC2:
	case MIPS_INS_LLD:
	case MIPS_INS_LD:
		r_strbuf_appendf (&op->esil, "%s,%s,+,[8],%s,=",
			I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_LH:
		op->sign = true; // To load a byte from memory as a signed value
		/* fallthrough */
	case MIPS_INS_LHU:
		r_strbuf_appendf (&op->esil, "%s,%s,+,[2],%s,=",
			I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_LHX:
	case MIPS_INS_LWX:
		break;
	case MIPS_INS_AND:
		r_strbuf_appendf (&op->esil, "%s,%s,&,%s,=", R_REG (rt), R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_ANDI:
		r_strbuf_appendf (&op->esil, "%s,%s,&,%s,=", I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_OR:
		r_strbuf_appendf (&op->esil, "%s,%s,|,%s,=", R_REG (rt), R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_ORI:
		r_strbuf_appendf (&op->esil, "%s,%s,|,%s,=", I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_XOR:
		r_strbuf_appendf (&op->esil, "%s,%s,^,%s,=", R_REG (rt), R_REG (rs), R_REG (rd));
		break;
	case MIPS_INS_XORI:
		r_strbuf_appendf (&op->esil, "%s,%s,^,%s,=", I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_NOR:
		r_strbuf_appendf (&op->esil, "%s,%s,|,0xffffffff,^,%s,=", R_REG (rs), R_REG (rt), R_REG (rd));
		break;
	case MIPS_INS_SLT:
		r_strbuf_appendf (&op->esil, "%s,%s,<,t,=", R_REG (rs), R_REG (rt));
		break;
	case MIPS_INS_SLTI:
		r_strbuf_appendf (&op->esil, "%s,%s,<,%s,=", I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_SLTU:
		r_strbuf_appendf (&op->esil, "%s,0xffffffff,&,%s,0xffffffff,&,<,t,=",
			R_REG (rs), R_REG (rt));
		break;
	case MIPS_INS_SLTIU:
		r_strbuf_appendf (&op->esil, "%s,0xffffffff,&,%s,0xffffffff,&,<,%s,=",
			I_REG (imm), I_REG (rs), I_REG (rt));
		break;
	case MIPS_INS_MUL:
		r_strbuf_appendf (&op->esil, ES_W ("%s,%s,*") ",%s,=", R_REG (rs), R_REG (rt), R_REG (rd));
		ES_SIGN32_64 (R_REG (rd));
		break;
	case MIPS_INS_MULT:
	case MIPS_INS_MULTU:
		r_strbuf_appendf (&op->esil, ES_W ("%s,%s,*") ",lo,=", R_REG (rs), R_REG (rt));
		ES_SIGN32_64 ("lo");
		r_strbuf_appendf (&op->esil, ES_W ("32,%s,%s,*,>>") ",hi,=", R_REG (rs), R_REG (rt));
		ES_SIGN32_64 ("hi");
		break;
	case MIPS_INS_MFLO:
		r_strbuf_appendf (&op->esil, "lo,%s,=", R_REG (rd));
		break;
	case MIPS_INS_MFHI:
		r_strbuf_appendf (&op->esil, "hi,%s,=", R_REG (rd));
		break;
	case MIPS_INS_MTLO:
		r_strbuf_appendf (&op->esil, "%s,lo,=,", R_REG (rs));
		ES_SIGN32_64 ("lo");
		break;
	case MIPS_INS_MTHI:
		r_strbuf_appendf (&op->esil, "%s,hi,=,", R_REG (rs));
		ES_SIGN32_64 ("hi");
		break;
	default:
		return -1;
	}
	return 0;
}

static int disassemble(RArchSession *as, RAnalOp *op, const ut8 *buf, int len) {
	ut8 bytes[8] = { 0 };
	int minopsz = 4;
	struct disassemble_info disasm_obj = { 0 };
	if (len < 2) {
		return -1;
	}
	RStrBuf *sb = r_strbuf_new ("");
	memcpy (&bytes, buf, R_MIN (len, sizeof (bytes)));

	const char *cpu = as->config->cpu;
	if (as->config->bits == 16) {
		len = 2;
	}

	/* prepare disassembler */
	PluginData *pd = as->data;
	if (cpu && (!pd->pre_cpu || !strcmp (cpu, pd->pre_cpu))) {
		if (!r_str_casecmp (cpu, "mips64r2")) {
			disasm_obj.mach = bfd_mach_mipsisa64r2;
		} else if (!r_str_casecmp (cpu, "micro")) {
			disasm_obj.mach = bfd_mach_mips_micromips;
			minopsz = 2;
		} else if (!r_str_casecmp (cpu, "mips32r2")) {
			disasm_obj.mach = bfd_mach_mipsisa32r2;
		} else if (!r_str_casecmp (cpu, "mips64")) {
			disasm_obj.mach = bfd_mach_mipsisa64;
		} else if (!r_str_casecmp (cpu, "mips32")) {
			disasm_obj.mach = bfd_mach_mipsisa32;
		} else if (!r_str_casecmp (cpu, "loongson3a")) {
			disasm_obj.mach = bfd_mach_mips_gs464;
		} else if (!r_str_casecmp (cpu, "gs464")) {
			disasm_obj.mach = bfd_mach_mips_gs464;
		} else if (!r_str_casecmp (cpu, "gs464e")) {
			disasm_obj.mach = bfd_mach_mips_gs464e;
		} else if (!r_str_casecmp (cpu, "gs264e")) {
			disasm_obj.mach = bfd_mach_mips_gs264e;
		} else if (!r_str_casecmp (cpu, "loongson2e")) {
			disasm_obj.mach = bfd_mach_mips_loongson_2e;
		} else if (!r_str_casecmp (cpu, "loongson2f")) {
			disasm_obj.mach = bfd_mach_mips_loongson_2f;
		} else if (!r_str_casecmp (cpu, "mips32/64")) {
			// Fallback for default config
			disasm_obj.mach = bfd_mach_mips_loongson_2f;
		}
		free (pd->pre_cpu);
		pd->pre_cpu = strdup (cpu);
	} else {
		disasm_obj.mach = bfd_mach_mips_loongson_2f;
	}

	const char *abi = as->config->abi;
	// const char *features = as->config->features;
	disasm_obj.disassembler_options = NULL;
	if (R_STR_ISNOTEMPTY (abi)) {
		// n32, n64, o32
		disasm_obj.disassembler_options = r_str_newf ("abi=%s", abi);
	}
	if (len < minopsz) {
		return -1;
	}

	const ut64 addr = op->addr;
	disasm_obj.arch = CPU_LOONGSON_2F; // XXX should be different see .mach
	disasm_obj.buffer = (ut8 *)&bytes;
	disasm_obj.read_memory_func = &mips_buffer_read_memory;
	disasm_obj.symbol_at_address_func = &symbol_at_address;
	disasm_obj.memory_error_func = &memory_error_func;
	disasm_obj.print_address_func = &generic_print_address_func;
	disasm_obj.buffer_vma = addr;
	disasm_obj.buffer_length = 4;
	// is micromips always big endian? different code endian and data endian? must move to arch
	disasm_obj.endian = !R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	disasm_obj.fprintf_func = &generic_fprintf_func;
	disasm_obj.stream = sb;
	op->size = (disasm_obj.endian == BFD_ENDIAN_LITTLE)
		? print_insn_little_mips ((bfd_vma)addr, &disasm_obj)
		: print_insn_big_mips ((bfd_vma)addr, &disasm_obj);
	if (op->size == -1) {
		op->mnemonic = strdup ("(data)");
		r_strbuf_free (sb);
	} else {
		op->mnemonic = r_strbuf_drain (sb);
	}
	free (disasm_obj.disassembler_options);
	return op->size;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *b = op->bytes;
	const int len = op->size;
	ut32 opcode = 0;
	int oplen = 4;
	const ut8 *buf;
	gnu_insn insn = {0};

	if (!op) {
		return false; // XXX true?
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->addr = addr;
		int res = disassemble (as, op, b, len);
		if (res > 0) {
			op->size = res;
		}
		oplen = op->size;
	}

	op->type = R_ANAL_OP_TYPE_UNK;
	op->size = oplen;
	op->addr = addr;
	// Be endian aware
	if (len >= 4) {
#if R_SYS_ENDIAN
		opcode = r_read_ble32 (b, !R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config));
#else
		opcode = r_read_ble32 (b, R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config));
#endif
	} else if (len >= 2) {
		opcode = r_read_ble16 (b, R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config));
	}

	// eprintf ("MIPS: %02x %02x %02x %02x (after endian: big=%d)\n", buf[0], buf[1], buf[2], buf[3], as->big_endian);
	if (opcode == 0) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return oplen;
	}

	opcode = r_swap_ut32 (opcode);
	buf = (ut8 *)&opcode;

	int optype = buf[0] >> 2;
	insn.optype = optype;
	insn.id = 0;
	PluginData *pd = as->data;
	if (optype == 0) {
		/*
			R-TYPE
			======
			opcode (6)  rs (5)  rt (5)  rd (5)  sa (5)  function (6)
			rs = register source
			rt = register target
			rd = register destination
			sa =
			fu =
				 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
				 1111 1111  1111 1111  1111 1111  1111 1111
				 \_op__/\_rs__/\_rt_/  \_rd_/\_sa__/\_fun_/
				   |      |      |       |      |      |
				 buf[0]>>2  |  (buf[1]&31)   |      |   buf[3]&63
					  |          (buf[2]>>3)  |
				  (buf[0]&3)<<3)+(buf[1]>>5)   (buf[2]&7)+(buf[3]>>6)
		*/
		int rs = ((buf[0] & 3) << 3) + (buf[1] >> 5);
		int rt = buf[1] & 31;
		int rd = buf[2] >> 3;
		int sa = ((buf[2] & 7) << 2) + (buf[3] >> 6);
		int fun = buf[3] & 63;

		insn.r_reg.rs = mips_reg_decode (rs);
		insn.r_reg.rd = mips_reg_decode (rd);
		insn.r_reg.rt = mips_reg_decode (rt);
		snprintf ((char *)insn.r_reg.sa, REG_BUF_MAX, "%" PFMT32d, sa);

		switch (fun) {
		case 0: // sll
			insn.id = MIPS_INS_SLL;
			insn.r_reg.rs = NULL;
			op->val = sa;
		case 4: // sllv
			insn.id = MIPS_INS_SLLV;
			op->type = R_ANAL_OP_TYPE_SHL;
			break;
		case 2: // srl
			insn.id = MIPS_INS_SRL;
			insn.r_reg.rs = NULL;
			op->val = sa;
		case 6: // srlv
			insn.id = MIPS_INS_SRLV;
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		case 3: // sra
			insn.id = MIPS_INS_SRA;
			op->type = R_ANAL_OP_TYPE_SAR;
			break;
		case 7: // srav
			insn.id = MIPS_INS_SRAV;
			op->type = R_ANAL_OP_TYPE_SAR;
			break;
		case 59: // dsra
			insn.id = MIPS_INS_DSRA; // TODO double
			op->type = R_ANAL_OP_TYPE_SAR;
			break;
		case 63: // dsra32
			insn.id = MIPS_INS_DSRA32;
			op->type = R_ANAL_OP_TYPE_SAR;
			break;
		case 8: // jr
			// eprintf ("%llx jr\n", addr);
			//  TODO: check return value or gtfo
			op->delay = 1;
			insn.id = MIPS_INS_JR;
			if (rs == 31) {
				op->type = R_ANAL_OP_TYPE_RET;
			} else if (rs == 25) {
				op->type = R_ANAL_OP_TYPE_RJMP;
				op->jump = pd->t9_pre;
			} else {
				op->type = R_ANAL_OP_TYPE_RJMP;
			}
			break;
		case 9: // jalr
			// eprintf ("%llx jalr\n", addr);
			op->delay = 1;
			insn.id = MIPS_INS_JALR;
			if (rs == 25) {
				op->type = R_ANAL_OP_TYPE_RCALL;
				op->jump = pd->t9_pre;
				break;
			}
			op->type = R_ANAL_OP_TYPE_UCALL;
			break;
		case 10: // movz
			insn.id = MIPS_INS_MOVZ;
			break;
		case 12: // syscall
			op->type = R_ANAL_OP_TYPE_SWI;
			break;
		case 13: // break
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case 16: // mfhi
			insn.id = MIPS_INS_MFHI;
			break;
		case 18: // mflo
			insn.id = MIPS_INS_MFLO;
			break;
		case 17: // mthi
			insn.id = MIPS_INS_MTHI;
			break;
		case 19: // mtlo
			insn.id = MIPS_INS_MTLO;
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case 24: // mult
			insn.id = MIPS_INS_MULT;
		case 25: // multu
			insn.id = MIPS_INS_MULTU;
			op->type = R_ANAL_OP_TYPE_MUL;
			break;
		case 26: // div
		case 27: // divu
			op->type = R_ANAL_OP_TYPE_DIV;
			insn.id = MIPS_INS_DIV;
			break;
		case 32: // add
			insn.id = MIPS_INS_ADD;
		case 33: // addu	//TODO:表明位数
			insn.id = MIPS_INS_ADDU;
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 44: // dadd
			insn.id = MIPS_INS_DADD;
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 45: // daddu move
			if (rt == 0) {
				op->type = R_ANAL_OP_TYPE_MOV;
				insn.id = MIPS_INS_MOV;
				break;
			}
			op->type = R_ANAL_OP_TYPE_ADD;
			insn.id = MIPS_INS_DADDU;
			break;
		case 34: // sub
		case 35: // subu
			insn.id = MIPS_INS_SUB;
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 46: // dsub
			insn.id = MIPS_INS_SUB;
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 47: // dsubu
			insn.id = MIPS_INS_SUB;
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case 36: // and
			insn.id = MIPS_INS_AND;
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 37: // or
			insn.id = MIPS_INS_OR;
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 38: // xor
			insn.id = MIPS_INS_XOR;
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 39: // nor
			insn.id = MIPS_INS_NOR;
			op->type = R_ANAL_OP_TYPE_NOR;
			break;
		case 42: // slt
			insn.id = MIPS_INS_SLT;
			break;
		case 43: // sltu
			insn.id = MIPS_INS_SLTU;
			break;
		default:
			//	eprintf ("%llx %d\n", addr, optype);
			break;
		}
		// family = 'R';
	} else if ((optype & 0x3e) == 2) {
		/*
				// J-TYPE
				 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
				 1111 1111  1111 1111  1111 1111  1111 1111
				 \_op__/\______address____________________/
				   |             |
			       (buf[0]>>2)  ((buf[0]&3)<<24)+(buf[1]<<16)+(buf[2]<<8)+buf[3]
		*/
		// FIXME: what happens when addr is using a virtual map?
		// ANS: address will be E 0x000000..0x0ffffffc
		//      but addr could be anywhere
		//      so address needs to be adjusted for that, somehow...
		// MIPS is strange.  For example, the same code memory may be
		// mapped simultaneously to 0x00600000 and 0x80600000.  The program is
		// executing at 0x80600000 if we are operating in 'KSEG0' space
		// (unmapped cached mode) vs 0x00600000 (KUSEG or user space)
		// An immediate jump can only reach within 2^28 bits.
		// HACK: if the user specified a mapping for the program
		// then assume that they know which MIPS segment they
		// are analysing in, and use the high order bits of addr
		// to be add to the jump.
		// WARNING: it is possible that this may not be the case
		// in all situations!
		// Maybe better solution: use a cfg. variable to do
		// the offset... but I dont yet know how to get to that
		// from this static function
		int address = (((buf[0] & 3) << 24) + (buf[1] << 16) + (buf[2] << 8) + buf[3]) << 2;
		ut64 page_hack = addr & 0xf0000000;

		switch (optype) {
		case 2: // j
			insn.id = MIPS_INS_J;
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = page_hack + address;
			op->delay = 1;
			snprintf ((char *)insn.j_reg.jump, REG_BUF_MAX, "0x%" PFMT64x, op->jump);
			break;
		case 3: // jal
			insn.id = MIPS_INS_JAL;
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = page_hack + address;
			op->fail = addr + 8;
			op->delay = 1;
			snprintf ((char *)insn.j_reg.jump, REG_BUF_MAX, "0x%" PFMT64x, op->jump);
			break;
		}
		// family = 'J';
	} else if ((optype & 0x3c) == 0x10) {
/*
	C-TYPE
	======
	opcode (6) format (5) ft (5) fs (5) fd (5) function (6)

		 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
		 1111 1111  1111 1111  1111 1111  1111 1111
		 \_op__/\_fmt_/\_ft_/  \_fs_/\_fd__/\_fun_/
		   |      |      |       |      |      |
		 buf[0]>>2  |  (buf[1]&31)   |      |   buf[3]&63
			  |          (buf[2]>>3)  |
		  (buf[0]&3)<<3)+(buf[1]>>5)   (buf[2]&7)+(buf[3]>>6)
*/
#if WIP
		int fmt = ((buf[0] & 3) << 3) + (buf[1] >> 5);
		int ft = (buf[1] & 31);
		int fs = (buf[2] >> 3);
		int fd = (buf[2] & 7) + (buf[3] >> 6);
#endif
		int fun = (buf[3] & 63);
		// family = 'C';
		switch (fun) {
		case 0: // mtc1
			break;
		case 1: // sub.s
			break;
		case 2: // mul.s
			break;
		case 3: // div.s
			break;
			// ....
		}
	} else {
		/*
			I-TYPE
			======
			all opcodes but 000000 000001x and 0100xx
			opcode (6)  rs (5)  rt (5) immediate (16)

				 |--[0]--|  |--[1]--|  |--[2]--|  |--[3]--|
				 1111 1111  1111 1111  1111 1111  1111 1111
				 \_op__/\_rs__/\_rt_/  \_______imm________/
				   |      |      |              |
				 buf[0]>>2  |  (buf[1]&31)          |
					  |                     |
				 ((buf[0]&3)<<3)+(buf[1]>>5)   (buf[2]<<8)+buf[3]
		*/
		op->refptr = 0;
		int rs = ((buf[0] & 3) << 3) + (buf[1] >> 5);
		int rt = buf[1] & 31;
		int imm = (buf[2] << 8) + buf[3];
		if (((optype >> 2) ^ 0x3) && (imm & 0x8000)) {
			imm = 0 - (0x10000 - imm);
		}

		insn.i_reg.rs = mips_reg_decode (rs);
		insn.i_reg.rt = mips_reg_decode (rt);
		snprintf ((char *)insn.i_reg.imm, REG_BUF_MAX, "%" PFMT32d, imm);

		// eprintf ("OPTYPE %d\n", optype);
		RAnalValue *src, *dst;
		switch (optype) {
		case 1:
			switch (rt) {
			case 0: // bltz
				insn.id = MIPS_INS_BLTZ;
				break;
			case 1: // bgez
				insn.id = MIPS_INS_BGEZ;
				break;
			case 17: // bal  bgezal
				if (rs == 0) {
					op->jump = addr + ((ut64)imm << 2) + 4;
					snprintf ((char *)insn.i_reg.jump, REG_BUF_MAX, "0x%" PFMT64x, op->jump);
					insn.id = MIPS_INS_BAL;
				} else {
					op->fail = addr + 8;
					insn.id = MIPS_INS_BGEZAL;
				}
				op->delay = 1;
				op->type = R_ANAL_OP_TYPE_CALL;
				break;
			default:
				op->delay = 1;
				op->fail = addr + 8;
				break;
			}
			break;
		case 4: // beq
			if (!insn.id) {
				insn.id = MIPS_INS_BEQ;
				if (rt == 0) {
					insn.id = MIPS_INS_BEQZ;
				}
			}
		case 5: // bne // also bnez
			if (!insn.id) {
				insn.id = MIPS_INS_BNE;
				if (rt == 0) {
					insn.id = MIPS_INS_BNEZ;
				}
			}
		case 6: // blez
			if (!insn.id) {
				insn.id = MIPS_INS_BLEZ;
			}
		case 7: // bgtz
			// XXX: use imm here
			if (!insn.id) {
				insn.id = MIPS_INS_BGTZ;
			}
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = addr + ((ut64)imm << 2) + 4;
			op->fail = addr + 8;
			op->delay = 1;

			snprintf ((char *)insn.i_reg.jump, REG_BUF_MAX, "0x%" PFMT64x, op->jump);
			break;
		// The following idiom is very common in mips 32 bit:
		//
		//     lui a0,0x8123
		//     ; maybe other opcodes
		//     ; maybe even a jump with branch delay
		//     addui a0,a0,-12345
		//
		// Here, a0 might typically be any a0 or s0 register, and -12345 is a signed 16-bit number
		// This is used to address const or static data in a 64kb page
		// 0x8123 is the upper 16 bits of the register
		// The net result: a0 := 0x8122cfc7
		// The cases vary, so for now leave the smarts in a human generated macro to decide
		// but the macro needs the opcode values as input
		//
		// TODO: this is a stop-gap. Really we need some smarts in here to tie this into the
		// flags directly, as suggested here: https://github.com/radareorg/radare2/issues/949#issuecomment-43654922
		case 15: // lui
			op->type = R_ANAL_OP_TYPE_LOAD;
			insn.id = MIPS_INS_LUI;
			snprintf ((char *)insn.i_reg.imm, REG_BUF_MAX, "0x%" PFMT32x, imm);
			dst = r_vector_push (&op->dsts, NULL);
#if 0
			dst->reg = r_reg_get (as->reg, mips_reg_decode (rt), R_REG_TYPE_GPR);
#else
			dst->reg = NULL;
#endif
			// TODO: currently there is no way for the macro to get access to this register
			op->val = imm;
			break;
		case 9: // addiu
			insn.id = MIPS_INS_ADDIU;
			op->type = R_ANAL_OP_TYPE_ADD;
			dst = r_vector_push (&op->dsts, NULL);
#if 0
			dst->reg = r_reg_get (as->reg, mips_reg_decode (rt), R_REG_TYPE_GPR);
#else
			dst->reg = NULL;
#endif
			// TODO: currently there is no way for the macro to get access to this register
			src = r_vector_push (&op->srcs, NULL);
#if 0
			src->reg = r_reg_get (as->reg, mips_reg_decode (rs), R_REG_TYPE_GPR);
#else
			src->reg = NULL;
#endif
			op->val = imm; // Beware: this one is signed... use `?vi $v`
			if (rs == 0) {
				insn.id = MIPS_INS_LI;
				snprintf ((char *)insn.i_reg.imm, REG_BUF_MAX, "0x%" PFMT32x, imm);
			}
			break;
		case 8: // addi
			insn.id = MIPS_INS_ADDI;
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 10: // slti
			insn.id = MIPS_INS_SLTI;
			op->type = R_ANAL_OP_TYPE_CMOV; // maybe cmp too?
			break;
		case 11: // sltiu
			op->type = R_ANAL_OP_TYPE_CMOV; // maybe cmp too?
			insn.id = MIPS_INS_SLTIU;
			break;
		case 12: // andi
			insn.id = MIPS_INS_ANDI;
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case 13: // ori
			insn.id = MIPS_INS_ORI;
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case 14: // xori
			insn.id = MIPS_INS_XORI;
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case 24: // daddi
			insn.id = MIPS_INS_DADDI;
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case 25: // daddiu
			insn.id = MIPS_INS_DADDIU;
			op->type = R_ANAL_OP_TYPE_ADD;
			if (rs == 0) {
				insn.id = MIPS_INS_LDI;
				snprintf ((char *)insn.i_reg.imm, REG_BUF_MAX, "0x%" PFMT32x, imm);
			}
			break;
		case 32: // lb
			op->refptr = 1;
			insn.id = MIPS_INS_LB;
			/* fallthrough */
		case 33: // lh
			if (!op->refptr) {
				op->refptr = 2;
				insn.id = MIPS_INS_LB;
			}
			/* fallthrough */
		case 35: // lw
			if (!op->refptr) {
				op->refptr = 4;
				insn.id = MIPS_INS_LW;
			}
			/* fallthrough */
		case 55: // ld
			if (!op->refptr) {
				op->refptr = 8;
				insn.id = MIPS_INS_LD;
			}

			if (rs == 28) {
				op->ptr = as->config->gp + imm;
			} else {
				op->ptr = imm;
			}
			if (rt == 25) {
				pd->t9_pre = op->ptr;
			}
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 36: // lbu
			insn.id = MIPS_INS_LBU;
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 37: // lhu
			insn.id = MIPS_INS_LHU;
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case 40: // sb
			insn.id = MIPS_INS_SB;
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 41: // sh
			insn.id = MIPS_INS_SH;
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 43: // sw
			insn.id = MIPS_INS_SW;
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 63: // sd
			insn.id = MIPS_INS_SD;
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case 49: // lwc1
		case 57: // swc1
			break;
		case 29: // jalx
			insn.id = MIPS_INS_JALX;
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = addr + 4 * ((buf[3] | buf[2] << 8 | buf[1] << 16));
			op->fail = addr + 8;
			op->delay = 1;
			snprintf ((char *)insn.i_reg.jump, REG_BUF_MAX, "0x%" PFMT64x, op->jump);

			break;
		}
		// family = 'I';
	}

	if (mask & R_ARCH_OP_MASK_ESIL) {
		if (analop_esil (as, op, addr, &insn)) {
			r_strbuf_fini (&op->esil);
		}
	}
	if (mask & R_ARCH_OP_MASK_VAL) {
		// TODO: add op_fillval (anal, op, &insn);
	}
	if (oplen < 1) {
		oplen = 2;
	}
	return oplen > 0;
	/*
	 R - all instructions that only take registers as arguments (jalr, jr)
	     opcode 000000
	     opcode (6) 	rs (5) 	rt (5) 	rd (5) 	sa (5) 	function (6)
			add 	rd, rs, rt 	100000
			addu 	rd, rs, rt 	100001
			and 	rd, rs, rt 	100100
			break 		001101
			div 	rs, rt 	011010
			divu 	rs, rt 	011011
			jalr 	rd, rs 	001001
			jr 	rs 	001000

			mfhi 	rd 	010000
			mflo 	rd 	010010
			mthi 	rs 	010001
			mtlo 	rs 	010011
			mult 	rs, rt 	011000
			multu 	rs, rt 	011001

			nor 	rd, rs, rt 	100111
			or 	rd, rs, rt 	100101
			sll 	rd, rt, sa 	000000
			sllv 	rd, rt, rs 	000100
			slt 	rd, rs, rt 	101010
			sltu 	rd, rs, rt 	101011

			sra 	rd, rt, sa 	000011
			srav 	rd, rt, rs 	000111

			srl 	rd, rt, sa 	000010
			srlv 	rd, rt, rs 	000110

			sub 	rd, rs, rt 	100010
			subu 	rd, rs, rt 	100011
			syscall 		001100
			xor 	rd, rs, rt 	100110
	 I - instructions with immediate operand, load/store/..
	     all opcodes but 000000 000001x and 0100xx
	     opcode (6) 	rs (5) 	rt (5) 	immediate (16)
			addi 	rt, rs, immediate 	001000
			addiu 	rt, rs, immediate 	001001
			andi 	rt, rs, immediate 	001100
			beq 	rs, rt, label 	000100

			bgez 	rs, label 	000001 	rt = 00001

			bgtz 	rs, label 	000111 	rt = 00000
			blez 	rs, label 	000110 	rt = 00000

			bltz 	rs, label 	000001 	rt = 00000
			bne 	rs, rt, label 	000101
			lb 	rt, immediate(rs) 	100000
			lbu 	rt, immediate(rs) 	100100

			lh 	rt, immediate(rs) 	100001
			lhu 	rt, immediate(rs) 	100101

			lui 	rt, immediate 	 	001111

			lw 	rt, immediate(rs) 	100011
			lwc1 	rt, immediate(rs) 	110001

			ori 	rt, rs, immediate 	001101
			sb 	rt, immediate(rs) 	101000

			slti 	rt, rs, immediate 	001010
			sltiu 	rt, rs, immediate 	001011
			sh 	rt, immediate(rs) 	101001
			sw 	rt, immediate(rs) 	101011
			swc1 	rt, immediate(rs) 	111001
			xori 	rt, rs, immediate 	001110
	 J - require memory address like j, jal
	     00001x
	     opcode (6) 	target (26)
			j 	label 	000010 	coded address of label
			jal 	label 	000011 	coded address of label
	 C - coprocessor insutrctions that use cp0, cp1, ..
	     0100xx
	     opcode (6) 	format (5) 	ft (5) 	fs (5) 	fd (5) 	function (6)
			add.s 	fd, fs, ft 	000000 	10000
			cvt.s.w	fd, fs, ft 	100000 	10100
			cvt.w.s	fd, fs, ft 	100100 	10000
			div.s 	fd, fs, ft 	000011 	10000
			mfc1 	ft, fs 		000000 	00000
			mov.s 	fd, fs 		000110 	10000
			mtc1 	ft, fs 		000000 	00100
			mul.s 	fd, fs, ft 	000010 	10000
			sub.s 	fd, fs, ft 	000001 	10000
	*/
	return op->size > 0;
}
/* Set the profile register */
static char *regs(RArchSession *as) {
	const char *p =
		// take the one from the debugger //
		"=PC	pc\n"
		"=SN    v0\n"
		"=SP	sp\n"
		"=BP	fp\n"
		"=A0	a0\n"
		"=A1	a1\n"
		"=A2	a2\n"
		"=A3	a3\n"
		"gpr	zero	.64	0	0\n"
		"gpr	at	.64	8	0\n"
		"gpr	v0	.64	16	0\n"
		"gpr	v1	.64	24	0\n"
		/* args */
		"gpr	a0	.64	32	0\n"
		"gpr	a1	.64	40	0\n"
		"gpr	a2	.64	48	0\n"
		"gpr	a3	.64	56	0\n"
		/* tmp */
		"gpr	t0	.64	64	0\n"
		"gpr	t1	.64	72	0\n"
		"gpr	t2	.64	80	0\n"
		"gpr	t3	.64	88	0\n"
		"gpr	t4	.64	96	0\n"
		"gpr	t5	.64	104	0\n"
		"gpr	t6	.64	112	0\n"
		"gpr	t7	.64	120	0\n"
		/* saved */
		"gpr	s0	.64	128	0\n"
		"gpr	s1	.64	136	0\n"
		"gpr	s2	.64	144	0\n"
		"gpr	s3	.64	152	0\n"
		"gpr	s4	.64	160	0\n"
		"gpr	s5	.64	168	0\n"
		"gpr	s6	.64	176	0\n"
		"gpr	s7	.64	184	0\n"
		"gpr	t8	.64	192	0\n"
		"gpr	t9	.64	200	0\n"
		/* special */
		"gpr	k0	.64	208	0\n"
		"gpr	k1	.64	216	0\n"
		"gpr	gp	.64	224	0\n"
		"gpr	sp	.64	232	0\n"
		"gpr	fp	.64	240	0\n"
		"gpr	ra	.64	248	0\n"
		/* extra */
		"gpr	pc	.64	272	0\n";
	return strdup (p);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_CODE_ALIGN:
	case R_ARCH_INFO_MINOP_SIZE:
		{
			const char *cpu = as->config->cpu;
			if (cpu && !strcmp (cpu, "micro")) {
				return 2; // (as->bits == 16) ? 2: 4;
			}
		}
		break;
	}
	return 4;
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (PluginData);
	PluginData *pd = as->data;
	if (!pd) {
		R_LOG_ERROR ("Cannot initialize mips_gnu plugin");
		return false;
	}

	pd->t9_pre = UT64_MAX;
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	PluginData *pd = as->data;
	R_FREE (pd->pre_cpu);
	R_FREE (as->data);
	return true;
}

const RArchPlugin r_arch_plugin_mips_gnu = {
	.meta = {
		.name = "mips.gnu",
		.author = "pancake",
		.desc = "MIPS RISC architecture",
		.license = "LGPL-3.0-only",
	},
	.cpus = "micro,mips64r2,mips32r2,mips64,mips32,loongson3a,gs464,gs464e,gs264e,loongson2e,loongson2f,mips32/64",
	.arch = "mips",
	.bits = R_SYS_BITS_PACK1 (32),
	.info = archinfo,
	.decode = decode,
	.regs = regs,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_mips_gnu
};
#endif
