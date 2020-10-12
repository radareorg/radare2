/* radare2 - LGPL - Copyright 2013-2020 - pancake */

#include <r_anal.h>
#include <r_lib.h>
#include <ht_uu.h>
#include <arm.h>
#include <capstone.h>
#include <arm.h>
#include <r_util/r_assert.h>
#include "./anal_arm_hacks.inc"
#include "../../asm/arch/arm/v35arm64/arm64dis.h"
#include "../../asm/arch/arm/v35arm64/arm64dis.c"


#define esilprintf(op, fmt, ...) r_strbuf_setf (&op->esil, fmt, ##__VA_ARGS__)


static void set_opdir(RAnalOp *op) {
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_LOAD:
		op->direction = R_ANAL_OP_DIR_READ;
		break;
	case R_ANAL_OP_TYPE_STORE:
		op->direction = R_ANAL_OP_DIR_WRITE;
		break;
	case R_ANAL_OP_TYPE_LEA:
		op->direction = R_ANAL_OP_DIR_REF;
		break;
	case R_ANAL_OP_TYPE_CALL:
	case R_ANAL_OP_TYPE_JMP:
	case R_ANAL_OP_TYPE_UJMP:
	case R_ANAL_OP_TYPE_UCALL:
		op->direction = R_ANAL_OP_DIR_EXEC;
		break;
	default:
		break;
        }
}

static void op_fillval(RAnalOp *op , csh handle, cs_insn *insn, int bits) {
	//create_src_dst (op);
	switch (op->type & R_ANAL_OP_TYPE_MASK) {
	case R_ANAL_OP_TYPE_MOV:
	case R_ANAL_OP_TYPE_CMP:
	case R_ANAL_OP_TYPE_ADD:
	case R_ANAL_OP_TYPE_SUB:
	case R_ANAL_OP_TYPE_MUL:
	case R_ANAL_OP_TYPE_DIV:
	case R_ANAL_OP_TYPE_SHR:
	case R_ANAL_OP_TYPE_SHL:
	case R_ANAL_OP_TYPE_SAL:
	case R_ANAL_OP_TYPE_SAR:
	case R_ANAL_OP_TYPE_OR:
	case R_ANAL_OP_TYPE_AND:
	case R_ANAL_OP_TYPE_XOR:
	case R_ANAL_OP_TYPE_NOR:
	case R_ANAL_OP_TYPE_NOT:
	case R_ANAL_OP_TYPE_LOAD:
	case R_ANAL_OP_TYPE_LEA:
	case R_ANAL_OP_TYPE_ROR:
	case R_ANAL_OP_TYPE_ROL:
	case R_ANAL_OP_TYPE_CAST:
#if 0
		set_src_dst (op->src[2], &handle, insn, 3, bits);
		set_src_dst (op->src[1], &handle, insn, 2, bits);
		set_src_dst (op->src[0], &handle, insn, 1, bits);
		set_src_dst (op->dst, &handle, insn, 0, bits);
		break;
	case R_ANAL_OP_TYPE_STORE:
		set_src_dst (op->dst, &handle, insn, 1, bits);
		set_src_dst (op->src[0], &handle, insn, 0, bits);
#endif
		break;
	default:
		break;
	}
#if 0
	if ((bits == 64) && HASMEMINDEX64 (1)) {
		op->ireg = r_str_get (cs_reg_name (handle, INSOP64 (1).mem.index));
	} else if (HASMEMINDEX (1)) {
		op->ireg = r_str_get (cs_reg_name (handle, INSOP (1).mem.index));
		op->scale = INSOP (1).mem.scale;
	}
#endif
}

static int opanal(RAnal *a, RAnalOp *op, Instruction *insn) {
	switch (insn->operation) {
	case ARM64_ABS:
		break;
	case ARM64_ADC:
	case ARM64_ADCS:
	case ARM64_ADD:
	case ARM64_ADDG: //Added for MTE
	case ARM64_ADDHN:
	case ARM64_ADDHN2:
	case ARM64_ADDP:
	case ARM64_ADDS:
	case ARM64_ADDV:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM64_ADR:
	case ARM64_ADRP:
		op->type = R_ANAL_OP_TYPE_LEA;
		break;
#if 0
	case ARM64_AESD:
	case ARM64_AESE:
	case ARM64_AESIMC:
	case ARM64_AESMC:
#endif
	case ARM64_AND:
	case ARM64_ANDS:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
#if 0
	case ARM64_ASR:
	case ARM64_AT:
	case ARM64_AUTDA: //Added for 8.3
	case ARM64_AUTDB: //Added for 8.3
	case ARM64_AUTDZA: //Added for 8.3
	case ARM64_AUTDZB: //Added for 8.3
	case ARM64_AUTIA: //Added for 8.3
	case ARM64_AUTIA1716: //Added for 8.3
	case ARM64_AUTIASP: //Added for 8.3
	case ARM64_AUTIAZ: //Added for 8.3
	case ARM64_AUTIB: //Added for 8.3
	case ARM64_AUTIB1716: //Added for 8.3
	case ARM64_AUTIBSP: //Added for 8.3
	case ARM64_AUTIBZ: //Added for 8.3
	case ARM64_AUTIZA: //Added for 8.3
	case ARM64_AUTIZB: //Added for 8.3
#endif
	case ARM64_B:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = insn->operands[0].immediate;
		break;
	case ARM64_B_AL:
	case ARM64_B_CC:
	case ARM64_B_CS:
	case ARM64_B_EQ:
	case ARM64_BFI:
	case ARM64_BFM:
	case ARM64_BFXIL:
	case ARM64_B_GE:
	case ARM64_B_GT:
	case ARM64_B_HI:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = insn->operands[0].immediate;
		op->fail = op->addr + 4;

		break;
#if 0
	case ARM64_BIC:
	case ARM64_BICS:
	case ARM64_BIF:
	case ARM64_BIT:
#endif
	case ARM64_BL:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = insn->operands[0].immediate;
		op->fail = op->addr + 4;
		break;
	case ARM64_B_LE:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = insn->operands[0].immediate;
		op->fail = op->addr + 4;
		break;
	case ARM64_BLR:
	case ARM64_BLRAA:
	case ARM64_BLRAAZ:
	case ARM64_BLRAB:
	case ARM64_BLRABZ:
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = insn->operands[0].immediate;
		op->fail = op->addr + 4;
		break;
	case ARM64_B_LS:
	case ARM64_B_LT:
	case ARM64_B_MI:
	case ARM64_B_NE:
	case ARM64_B_NV:
	case ARM64_B_PL:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = insn->operands[0].immediate;
		op->fail = op->addr + 4;
		break;
	case ARM64_BR:
	case ARM64_BRAA:
	case ARM64_BRAAZ:
	case ARM64_BRAB:
	case ARM64_BRABZ:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = insn->operands[0].immediate;
		op->fail = op->addr + 4;
		break;
#if 0
	case ARM64_BRK:
	case ARM64_BSL:
	case ARM64_B_VC:
	case ARM64_B_VS:
	case ARM64_CBNZ:
	case ARM64_CBZ:
	case ARM64_CCMN:
	case ARM64_CCMP:
	case ARM64_CINC:
	case ARM64_CINV:
	case ARM64_CLREX:
	case ARM64_CLS:
	case ARM64_CLZ:
	case ARM64_CMEQ:
	case ARM64_CMGE:
	case ARM64_CMGT:
	case ARM64_CMHI:
	case ARM64_CMHS:
	case ARM64_CMLE:
	case ARM64_CMLT:
	case ARM64_CMN:
#endif
	case ARM64_CMP:
	case ARM64_CMPP: //Added for MTE
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
#if 0
	case ARM64_CMTST:
	case ARM64_CNEG:
	case ARM64_CNT:
	case ARM64_CRC32B:
	case ARM64_CRC32CB:
	case ARM64_CRC32CH:
	case ARM64_CRC32CW:
	case ARM64_CRC32CX:
	case ARM64_CRC32H:
	case ARM64_CRC32W:
	case ARM64_CRC32X:
	case ARM64_CSEL:
	case ARM64_CSET:
	case ARM64_CSETM:
	case ARM64_CSINC:
	case ARM64_CSINV:
	case ARM64_CSNEG:
	case ARM64_DC:
	case ARM64_DCPS1:
	case ARM64_DCPS2:
	case ARM64_DCPS3:
	case ARM64_DMB:
	case ARM64_DRPS:
	case ARM64_DSB:
	case ARM64_DUP:
	case ARM64_EON:
#endif
	case ARM64_EOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ARM64_ERET:
	case ARM64_ERETAA: //Added for 8.3
	case ARM64_ERETAB: //Added for 8.3
		op->type = R_ANAL_OP_TYPE_RET;
		break;
#if 0
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
#endif
	case ARM64_LD1:
	case ARM64_LD1R:
	case ARM64_LD2:
	case ARM64_LD2R:
	case ARM64_LD3:
	case ARM64_LD3R:
	case ARM64_LD4:
	case ARM64_LD4R:
	case ARM64_LDAR:
	case ARM64_LDARB:
	case ARM64_LDARH:
	case ARM64_LDAXP:
	case ARM64_LDAXR:
	case ARM64_LDAXRB:
	case ARM64_LDAXRH:
	case ARM64_LDG: //Added for MTE
	case ARM64_LDGM: //Added for MTE
	case ARM64_LDNP:
	case ARM64_LDP:
	case ARM64_LDPSW:
	case ARM64_LDR:
	case ARM64_LDRAA: //Added for 8.3
	case ARM64_LDRAB: //Added for 8.3
	case ARM64_LDRB:
	case ARM64_LDRH:
	case ARM64_LDRSB:
	case ARM64_LDRSH:
	case ARM64_LDRSW:
	case ARM64_LDTR:
	case ARM64_LDTRB:
	case ARM64_LDTRH:
	case ARM64_LDTRSB:
	case ARM64_LDTRSH:
	case ARM64_LDTRSW:
	case ARM64_LDUR:
	case ARM64_LDURB:
	case ARM64_LDURH:
	case ARM64_LDURSB:
	case ARM64_LDURSH:
	case ARM64_LDURSW:
	case ARM64_LDXP:
	case ARM64_LDXR:
	case ARM64_LDXRB:
	case ARM64_LDXRH:
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case ARM64_LSL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ARM64_LSR:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
#if 0
		ARM64_MADD,
		ARM64_MLA,
		ARM64_MLS,
		ARM64_MNEG,
#endif
	case ARM64_MOV:
	case ARM64_MOVI:
	case ARM64_MOVK:
	case ARM64_MOVN:
	case ARM64_MOVZ:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
#if 0
	case ARM64_MRS:
	case ARM64_MSR:
	case ARM64_MSUB:
	case ARM64_MUL:
	case ARM64_MVN:
	case ARM64_MVNI:
	case ARM64_NEG:
	case ARM64_NEGS:
	case ARM64_NGC:
	case ARM64_NGCS:
#endif
	case ARM64_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case ARM64_NOT:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case ARM64_ORN:
	case ARM64_ORR:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
#if 0
	case ARM64_PACDA: //Added for 8.3
	case ARM64_PACDB: //Added for 8.3
	case ARM64_PACDZA: //Added for 8.3
	case ARM64_PACDZB: //Added for 8.3
	case ARM64_PACIA: //Added for 8.3
	case ARM64_PACIA1716: //Added for 8.3
	case ARM64_PACIASP: //Added for 8.3
	case ARM64_PACIAZ: //Added for 8.3
	case ARM64_PACIB: //Added for 8.3
	case ARM64_PACIB1716: //Added for 8.3
	case ARM64_PACIBSP: //Added for 8.3
	case ARM64_PACIBZ: //Added for 8.3
	case ARM64_PACIZA: //Added for 8.3
	case ARM64_PACIZB: //Added for 8.3
	case ARM64_PMUL:
	case ARM64_PMULL:
	case ARM64_PMULL2:
	case ARM64_PRFM:
	case ARM64_PRFUM:
	case ARM64_PSBCSYNC: //Added for 8.2
	case ARM64_RADDHN:
	case ARM64_RADDHN2:
	case ARM64_RBIT:
#endif
	case ARM64_RET:
	case ARM64_RETAA: //Added for 8.3
	case ARM64_RETAB: //Added for 8.3
		op->type = R_ANAL_OP_TYPE_RET;
		break;
#if 0
	case ARM64_REV:
	case ARM64_REV16:
	case ARM64_REV32:
	case ARM64_REV64:
	case ARM64_ROR:
	case ARM64_RSHRN:
	case ARM64_RSHRN2:
	case ARM64_RSUBHN:
	case ARM64_RSUBHN2:
	case ARM64_SABA:
	case ARM64_SABAL:
	case ARM64_SABAL2:
	case ARM64_SABD:
	case ARM64_SABDL:
	case ARM64_SABDL2:
	case ARM64_SADALP:
	case ARM64_SADDL:
	case ARM64_SADDL2:
	case ARM64_SADDLP:
	case ARM64_SADDLV:
	case ARM64_SADDW:
	case ARM64_SADDW2:
	case ARM64_SBC:
	case ARM64_SBCS:
	case ARM64_SBFIZ:
	case ARM64_SBFM:
	case ARM64_SBFX:
	case ARM64_SCVTF:
	case ARM64_SDIV:
	case ARM64_SEV:
	case ARM64_SEVL:
	case ARM64_SHA1C:
	case ARM64_SHA1H:
	case ARM64_SHA1M:
	case ARM64_SHA1P:
	case ARM64_SHA1SU0:
	case ARM64_SHA1SU1:
	case ARM64_SHA256H:
	case ARM64_SHA256H2:
	case ARM64_SHA256SU0:
	case ARM64_SHA256SU1:
	case ARM64_SHADD:
	case ARM64_SHL:
	case ARM64_SHLL:
	case ARM64_SHLL2:
	case ARM64_SHRN:
	case ARM64_SHRN2:
	case ARM64_SHSUB:
	case ARM64_SLI:
	case ARM64_SMADDL:
	case ARM64_SMAX:
	case ARM64_SMAXP:
	case ARM64_SMAXV:
	case ARM64_SMC:
	case ARM64_SMIN:
	case ARM64_SMINP:
	case ARM64_SMINV:
	case ARM64_SMLAL:
	case ARM64_SMLAL2:
	case ARM64_SMLSL:
	case ARM64_SMLSL2:
	case ARM64_SMNEGL:
	case ARM64_SMOV:
	case ARM64_SMSUBL:
	case ARM64_SMULH:
	case ARM64_SMULL:
	case ARM64_SMULL2:
	case ARM64_SQABS:
	case ARM64_SQADD:
	case ARM64_SQDMLAL:
	case ARM64_SQDMLAL2:
	case ARM64_SQDMLSL:
	case ARM64_SQDMLSL2:
	case ARM64_SQDMULH:
	case ARM64_SQDMULL:
	case ARM64_SQDMULL2:
	case ARM64_SQNEG:
	case ARM64_SQRDMULH:
	case ARM64_SQRSHL:
	case ARM64_SQRSHRN:
	case ARM64_SQRSHRN2:
	case ARM64_SQRSHRUN:
	case ARM64_SQRSHRUN2:
	case ARM64_SQSHL:
	case ARM64_SQSHLU:
	case ARM64_SQSHRN:
	case ARM64_SQSHRN2:
	case ARM64_SQSHRUN:
	case ARM64_SQSHRUN2:
	case ARM64_SQSUB:
	case ARM64_SQXTN:
	case ARM64_SQXTN2:
	case ARM64_SQXTUN:
	case ARM64_SQXTUN2:
	case ARM64_SRHADD:
	case ARM64_SRI:
	case ARM64_SRSHL:
	case ARM64_SRSHR:
	case ARM64_SRSRA:
	case ARM64_SSHL:
	case ARM64_SSHLL:
	case ARM64_SSHLL2:
	case ARM64_SSHR:
	case ARM64_SSRA:
	case ARM64_SSUBL:
	case ARM64_SSUBL2:
	case ARM64_SSUBW:
	case ARM64_SSUBW2:
#endif
	case ARM64_ST1:
	case ARM64_ST2:
	case ARM64_ST2G: //Added for MTE
	case ARM64_ST3:
	case ARM64_ST4:
	case ARM64_STG: //Added for MTE
	case ARM64_STGM: //Added for MTE
	case ARM64_STGP: //Added for MTE
	case ARM64_STLR:
	case ARM64_STLRB:
	case ARM64_STLRH:
	case ARM64_STLXP:
	case ARM64_STLXR:
	case ARM64_STLXRB:
	case ARM64_STLXRH:
	case ARM64_STNP:
	case ARM64_STP:
	case ARM64_STR:
	case ARM64_STRB:
	case ARM64_STRH:
	case ARM64_STTR:
	case ARM64_STTRB:
	case ARM64_STTRH:
	case ARM64_STUR:
	case ARM64_STURB:
	case ARM64_STURH:
	case ARM64_STXP:
	case ARM64_STXR:
	case ARM64_STXRB:
	case ARM64_STXRH:
	case ARM64_STZ2G: //Added for MTE
	case ARM64_STZG: //Added for MTE
	case ARM64_STZGM: //Added for MTE
		op->type = R_ANAL_OP_TYPE_STORE;
break;
	case ARM64_SUB:
	case ARM64_SUBG: //Added for MTE
	case ARM64_SUBHN:
	case ARM64_SUBHN2:
	case ARM64_SUBP: //Added for MTE
	case ARM64_SUBPS: //Added for MTE
	case ARM64_SUBS:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
#if 0
		ARM64_SUQADD,
#endif
	case ARM64_SVC:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case ARM64_SXTB:
	case ARM64_SXTH:
	case ARM64_SXTW:
		op->type = R_ANAL_OP_TYPE_STORE;
		break;
#if 0
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
#endif
	}
	return 0;
}

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	Instruction insn = {0};
	char output[256];
	op->addr = addr;
	op->size = 4;
	if (len < 4) {
		return -1;
	}
	ut32 n = r_read_le32 (buf);
	FailureCodes fc = aarch64_decompose (n, &insn, addr);
	if (fc != DISASM_SUCCESS) {
		return -1;
	}
	output[0] = 0;
	fc = aarch64_disassemble (&insn, output, sizeof (output));
	if (fc == DISASM_SUCCESS) {
		if (*output) {
			// XXX trim tailing newline on UNDEFINED string
			/// output[strlen (output) - 2] = 0;
		}
		r_str_trim_tail (output);
		r_str_replace_char (output, '\t', ' ');
		r_str_replace_char (output, '#', ' ');
		if (r_str_startswith (output, "UNDEF")) {
			//r_strbuf_set (&op->buf_asm, "undefined");
			return 4;
		}
		//r_strbuf_set (&op->buf_asm, output);
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ANAL_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		opanal (a, op, &insn);
		return op->size;
	}
	if (mask & R_ANAL_OP_MASK_DISASM) {
		op->mnemonic = strdup ("invalid");
	}
	//r_strbuf_set (&op->buf_asm, "invalid");
	// this can be moved into op.c
	set_opdir (op);
	return 4;

	

#if 0
	int haa = hackyArmAnal (a, op, buf, len);
	if (haa > 0) {
		return haa;
	}
		if (mask & R_ANAL_OP_MASK_VAL) {
			op_fillval (op, handle, insn, a->bits);
		}

	if (mask & R_ANAL_OP_MASK_OPEX) {
		opex64 (&op->opex, handle, insn);
	}
	if (mask & R_ANAL_OP_MASK_ESIL) {
		analop64_esil (a, op, addr, buf, len, &handle, insn);
	}
#endif
}

static char *get_reg_profile(RAnal *anal) {
	const char *p;
	if (anal->bits == 64) {
		p = \
		"=PC	pc\n"
		"=SP	sp\n"
		"=BP	x29\n"
		"=A0	x0\n"
		"=A1	x1\n"
		"=A2	x2\n"
		"=A3	x3\n"
		"=ZF	zf\n"
		"=SF	nf\n"
		"=OF	vf\n"
		"=CF	cf\n"
		"=SN	x16\n" // x8 on linux?

		/* 8bit sub-registers */
		"gpr	b0	.8	0	0\n"
		"gpr	b1	.8	8	0\n"
		"gpr	b2	.8	16	0\n"
		"gpr	b3	.8	24	0\n"
		"gpr	b4	.8	32	0\n"
		"gpr	b5	.8	40	0\n"
		"gpr	b6	.8	48	0\n"
		"gpr	b7	.8	56	0\n"
		"gpr	b8	.8	64	0\n"
		"gpr	b9	.8	72	0\n"
		"gpr	b10	.8	80	0\n"
		"gpr	b11	.8	88	0\n"
		"gpr	b12	.8	96	0\n"
		"gpr	b13	.8	104	0\n"
		"gpr	b14	.8	112	0\n"
		"gpr	b15	.8	120	0\n"
		"gpr	b16	.8	128	0\n"
		"gpr	b17	.8	136	0\n"
		"gpr	b18	.8	144	0\n"
		"gpr	b19	.8	152	0\n"
		"gpr	b20	.8	160	0\n"
		"gpr	b21	.8	168	0\n"
		"gpr	b22	.8	176	0\n"
		"gpr	b23	.8	184	0\n"
		"gpr	b24	.8	192	0\n"
		"gpr	b25	.8	200	0\n"
		"gpr	b26	.8	208	0\n"
		"gpr	b27	.8	216	0\n"
		"gpr	b28	.8	224	0\n"
		"gpr	b29	.8	232	0\n"
		"gpr	b30	.8	240	0\n"
		"gpr	bsp	.8	248	0\n"

		/* 16bit sub-registers */
		"gpr	h0	.16	0	0\n"
		"gpr	h1	.16	8	0\n"
		"gpr	h2	.16	16	0\n"
		"gpr	h3	.16	24	0\n"
		"gpr	h4	.16	32	0\n"
		"gpr	h5	.16	40	0\n"
		"gpr	h6	.16	48	0\n"
		"gpr	h7	.16	56	0\n"
		"gpr	h8	.16	64	0\n"
		"gpr	h9	.16	72	0\n"
		"gpr	h10	.16	80	0\n"
		"gpr	h11	.16	88	0\n"
		"gpr	h12	.16	96	0\n"
		"gpr	h13	.16	104	0\n"
		"gpr	h14	.16	112	0\n"
		"gpr	h15	.16	120	0\n"
		"gpr	h16	.16	128	0\n"
		"gpr	h17	.16	136	0\n"
		"gpr	h18	.16	144	0\n"
		"gpr	h19	.16	152	0\n"
		"gpr	h20	.16	160	0\n"
		"gpr	h21	.16	168	0\n"
		"gpr	h22	.16	176	0\n"
		"gpr	h23	.16	184	0\n"
		"gpr	h24	.16	192	0\n"
		"gpr	h25	.16	200	0\n"
		"gpr	h26	.16	208	0\n"
		"gpr	h27	.16	216	0\n"
		"gpr	h28	.16	224	0\n"
		"gpr	h29	.16	232	0\n"
		"gpr	h30	.16	240	0\n"

		/* 32bit sub-registers */
		"gpr	w0	.32	0	0\n"
		"gpr	w1	.32	8	0\n"
		"gpr	w2	.32	16	0\n"
		"gpr	w3	.32	24	0\n"
		"gpr	w4	.32	32	0\n"
		"gpr	w5	.32	40	0\n"
		"gpr	w6	.32	48	0\n"
		"gpr	w7	.32	56	0\n"
		"gpr	w8	.32	64	0\n"
		"gpr	w9	.32	72	0\n"
		"gpr	w10	.32	80	0\n"
		"gpr	w11	.32	88	0\n"
		"gpr	w12	.32	96	0\n"
		"gpr	w13	.32	104	0\n"
		"gpr	w14	.32	112	0\n"
		"gpr	w15	.32	120	0\n"
		"gpr	w16	.32	128	0\n"
		"gpr	w17	.32	136	0\n"
		"gpr	w18	.32	144	0\n"
		"gpr	w19	.32	152	0\n"
		"gpr	w20	.32	160	0\n"
		"gpr	w21	.32	168	0\n"
		"gpr	w22	.32	176	0\n"
		"gpr	w23	.32	184	0\n"
		"gpr	w24	.32	192	0\n"
		"gpr	w25	.32	200	0\n"
		"gpr	w26	.32	208	0\n"
		"gpr	w27	.32	216	0\n"
		"gpr	w28	.32	224	0\n"
		"gpr	w29	.32	232	0\n"
		"gpr	w30	.32	240	0\n"
		"gpr	wsp	.32	248	0\n"
		"gpr	wzr	.32	?	0\n"

		/* 32bit float sub-registers */
		"gpr	s0	.32	0	0\n"
		"gpr	s1	.32	8	0\n"
		"gpr	s2	.32	16	0\n"
		"gpr	s3	.32	24	0\n"
		"gpr	s4	.32	32	0\n"
		"gpr	s5	.32	40	0\n"
		"gpr	s6	.32	48	0\n"
		"gpr	s7	.32	56	0\n"
		"gpr	s8	.32	64	0\n"
		"gpr	s9	.32	72	0\n"
		"gpr	s10	.32	80	0\n"
		"gpr	s11	.32	88	0\n"
		"gpr	s12	.32	96	0\n"
		"gpr	s13	.32	104	0\n"
		"gpr	s14	.32	112	0\n"
		"gpr	s15	.32	120	0\n"
		"gpr	s16	.32	128	0\n"
		"gpr	s17	.32	136	0\n"
		"gpr	s18	.32	144	0\n"
		"gpr	s19	.32	152	0\n"
		"gpr	s20	.32	160	0\n"
		"gpr	s21	.32	168	0\n"
		"gpr	s22	.32	176	0\n"
		"gpr	s23	.32	184	0\n"
		"gpr	s24	.32	192	0\n"
		"gpr	s25	.32	200	0\n"
		"gpr	s26	.32	208	0\n"
		"gpr	s27	.32	216	0\n"
		"gpr	s28	.32	224	0\n"
		"gpr	s29	.32	232	0\n"
		"gpr	s30	.32	240	0\n"
		/* 64bit */
		"gpr	x0	.64	0	0\n" // x0
		"gpr	x1	.64	8	0\n" // x0
		"gpr	x2	.64	16	0\n" // x0
		"gpr	x3	.64	24	0\n" // x0
		"gpr	x4	.64	32	0\n" // x0
		"gpr	x5	.64	40	0\n" // x0
		"gpr	x6	.64	48	0\n" // x0
		"gpr	x7	.64	56	0\n" // x0
		"gpr	x8	.64	64	0\n" // x0
		"gpr	x9	.64	72	0\n" // x0
		"gpr	x10	.64	80	0\n" // x0
		"gpr	x11	.64	88	0\n" // x0
		"gpr	x12	.64	96	0\n" // x0
		"gpr	x13	.64	104	0\n" // x0
		"gpr	x14	.64	112	0\n" // x0
		"gpr	x15	.64	120	0\n" // x0
		"gpr	x16	.64	128	0\n" // x0
		"gpr	x17	.64	136	0\n" // x0
		"gpr	x18	.64	144	0\n" // x0
		"gpr	x19	.64	152	0\n" // x0
		"gpr	x20	.64	160	0\n" // x0
		"gpr	x21	.64	168	0\n" // x0
		"gpr	x22	.64	176	0\n" // x0
		"gpr	x23	.64	184	0\n" // x0
		"gpr	x24	.64	192	0\n" // x0
		"gpr	x25	.64	200	0\n" // x0
		"gpr	x26	.64	208	0\n" // x0
		"gpr	x27	.64	216	0\n"
		"gpr	x28	.64	224	0\n"
		"gpr	x29	.64	232	0\n"
		"gpr	x30	.64	240	0\n"
		"gpr	tmp	.64	288	0\n"
		/* 64bit double */
		"gpr	d0	.64	0	0\n" // x0
		"gpr	d1	.64	8	0\n" // x0
		"gpr	d2	.64	16	0\n" // x0
		"gpr	d3	.64	24	0\n" // x0
		"gpr	d4	.64	32	0\n" // x0
		"gpr	d5	.64	40	0\n" // x0
		"gpr	d6	.64	48	0\n" // x0
		"gpr	d7	.64	56	0\n" // x0
		"gpr	d8	.64	64	0\n" // x0
		"gpr	d9	.64	72	0\n" // x0
		"gpr	d10	.64	80	0\n" // x0
		"gpr	d11	.64	88	0\n" // x0
		"gpr	d12	.64	96	0\n" // x0
		"gpr	d13	.64	104	0\n" // x0
		"gpr	d14	.64	112	0\n" // x0
		"gpr	d15	.64	120	0\n" // x0
		"gpr	d16	.64	128	0\n" // x0
		"gpr	d17	.64	136	0\n" // x0
		"gpr	d18	.64	144	0\n" // x0
		"gpr	d19	.64	152	0\n" // x0
		"gpr	d20	.64	160	0\n" // x0
		"gpr	d21	.64	168	0\n" // x0
		"gpr	d22	.64	176	0\n" // x0
		"gpr	d23	.64	184	0\n" // x0
		"gpr	d24	.64	192	0\n" // x0
		"gpr	d25	.64	200	0\n" // x0
		"gpr	d26	.64	208	0\n" // x0
		"gpr	d27	.64	216	0\n"
		"gpr	d28	.64	224	0\n"
		"gpr	d29	.64	232	0\n"
		"gpr	d30	.64	240	0\n"
		"gpr	dsp	.64	248	0\n"
		/*  foo */
		"gpr	fp	.64	232	0\n" // fp = x29
		"gpr	lr	.64	240	0\n" // lr = x30
		"gpr	sp	.64	248	0\n"
		"gpr	pc	.64	256	0\n"
		"gpr	zr	.64	?	0\n"
		"gpr	xzr	.64	?	0\n"
		"flg	pstate	.64	280	0   _____tfiae_____________j__qvczn\n" // x0
		//"flg	cpsr	.32	280	0\n" //	_____tfiae_____________j__qvczn\n"
		"flg	vf	.1	280.28	0	overflow\n" // set if overflows
		"flg	cf	.1	280.29	0	carry\n" // set if last op carries
		"flg	zf	.1	280.30	0	zero\n" // set if last op is 0
		"flg	nf	.1	280.31	0	sign\n"; // msb bit of last op
	} else {
		p = \
		"=PC	r15\n"
		"=LR	r14\n"
		"=SP	sp\n"
		"=BP	fp\n"
		"=A0	r0\n"
		"=A1	r1\n"
		"=A2	r2\n"
		"=A3	r3\n"
		"=ZF	zf\n"
		"=SF	nf\n"
		"=OF	vf\n"
		"=CF	cf\n"
		"=SN	r7\n"
		"gpr	sb	.32	36	0\n" // r9
		"gpr	sl	.32	40	0\n" // rl0
		"gpr	fp	.32	44	0\n" // r11
		"gpr	ip	.32	48	0\n" // r12
		"gpr	sp	.32	52	0\n" // r13
		"gpr	lr	.32	56	0\n" // r14
		"gpr	pc	.32	60	0\n" // r15

		"gpr	r0	.32	0	0\n"
		"gpr	r1	.32	4	0\n"
		"gpr	r2	.32	8	0\n"
		"gpr	r3	.32	12	0\n"
		"gpr	r4	.32	16	0\n"
		"gpr	r5	.32	20	0\n"
		"gpr	r6	.32	24	0\n"
		"gpr	r7	.32	28	0\n"
		"gpr	r8	.32	32	0\n"
		"gpr	r9	.32	36	0\n"
		"gpr	r10	.32	40	0\n"
		"gpr	r11	.32	44	0\n"
		"gpr	r12	.32	48	0\n"
		"gpr	r13	.32	52	0\n"
		"gpr	r14	.32	56	0\n"
		"gpr	r15	.32	60	0\n"
		"flg	cpsr	.32	64	0\n"

		  // CPSR bit fields:
		  // 576-580 Mode fields (and register sets associated to each field):
		  //10000 	User 	R0-R14, CPSR, PC
		  //10001 	FIQ 	R0-R7, R8_fiq-R14_fiq, CPSR, SPSR_fiq, PC
		  //10010 	IRQ 	R0-R12, R13_irq, R14_irq, CPSR, SPSR_irq, PC
		  //10011 	SVC (supervisor) 	R0-R12, R13_svc R14_svc CPSR, SPSR_irq, PC
		  //10111 	Abort 	R0-R12, R13_abt R14_abt CPSR, SPSR_abt PC
		  //11011 	Undefined 	R0-R12, R13_und R14_und, CPSR, SPSR_und PC
		  //11111 	System (ARMv4+) 	R0-R14, CPSR, PC
		"flg	tf	.1	.517	0	thumb\n" // +5
		  // 582 FIQ disable bit
		  // 583 IRQ disable bit
		  // 584 Disable imprecise aborts flag
		"flg	ef	.1	.521	0	endian\n" // +9
		"flg	itc	.4	.522	0	if_then_count\n" // +10
		  // Reserved
		"flg	gef	.4	.528	0	great_or_equal\n" // +16
		"flg	jf	.1	.536	0	java\n" // +24
		  // Reserved
		"flg	qf	.1	.539	0	sticky_overflow\n" // +27
		"flg	vf	.1	.540	0	overflow\n" // +28
		"flg	cf	.1	.541	0	carry\n" // +29
		"flg	zf	.1	.542	0	zero\n" // +30
		"flg	nf	.1	.543	0	negative\n" // +31

		/* NEON and VFP registers */
		/* 32bit float sub-registers */
		"fpu	s0	.32	68	0\n"
		"fpu	s1	.32	72	0\n"
		"fpu	s2	.32	76	0\n"
		"fpu	s3	.32	80	0\n"
		"fpu	s4	.32	84	0\n"
		"fpu	s5	.32	88	0\n"
		"fpu	s6	.32	92	0\n"
		"fpu	s7	.32	96	0\n"
		"fpu	s8	.32	100	0\n"
		"fpu	s9	.32	104	0\n"
		"fpu	s10	.32	108	0\n"
		"fpu	s11	.32	112	0\n"
		"fpu	s12	.32	116	0\n"
		"fpu	s13	.32	120	0\n"
		"fpu	s14	.32	124	0\n"
		"fpu	s15	.32	128	0\n"
		"fpu	s16	.32	132	0\n"
		"fpu	s17	.32	136	0\n"
		"fpu	s18	.32	140	0\n"
		"fpu	s19	.32	144	0\n"
		"fpu	s20	.32	148	0\n"
		"fpu	s21	.32	152	0\n"
		"fpu	s22	.32	156	0\n"
		"fpu	s23	.32	160	0\n"
		"fpu	s24	.32	164	0\n"
		"fpu	s25	.32	168	0\n"
		"fpu	s26	.32	172	0\n"
		"fpu	s27	.32	176	0\n"
		"fpu	s28	.32	180	0\n"
		"fpu	s29	.32	184	0\n"
		"fpu	s30	.32	188	0\n"
		"fpu	s31	.32	192	0\n"

		/* 64bit double */
		"fpu	d0	.64	68	0\n"
		"fpu	d1	.64	76	0\n"
		"fpu	d2	.64	84	0\n"
		"fpu	d3	.64	92	0\n"
		"fpu	d4	.64	100	0\n"
		"fpu	d5	.64	108	0\n"
		"fpu	d6	.64	116	0\n"
		"fpu	d7	.64	124	0\n"
		"fpu	d8	.64	132	0\n"
		"fpu	d9	.64	140	0\n"
		"fpu	d10	.64	148	0\n"
		"fpu	d11	.64	156	0\n"
		"fpu	d12	.64	164	0\n"
		"fpu	d13	.64	172	0\n"
		"fpu	d14	.64	180	0\n"
		"fpu	d15	.64	188	0\n"
		"fpu	d16	.64	196	0\n"
		"fpu	d17	.64	204	0\n"
		"fpu	d18	.64	212	0\n"
		"fpu	d19	.64	220	0\n"
		"fpu	d20	.64	228	0\n"
		"fpu	d21	.64	236	0\n"
		"fpu	d22	.64	244	0\n"
		"fpu	d23	.64	252	0\n"
		"fpu	d24	.64	260	0\n"
		"fpu	d25	.64	268	0\n"
		"fpu	d26	.64	276	0\n"
		"fpu	d27	.64	284	0\n"
		"fpu	d28	.64	292	0\n"
		"fpu	d29	.64	300	0\n"
		"fpu	d30	.64	308	0\n"
		"fpu	d31	.64	316	0\n"

		/* 128bit double */
		"fpu	q0	.128	68	0\n"
		"fpu	q1	.128	84	0\n"
		"fpu	q2	.128	100	0\n"
		"fpu	q3	.128	116	0\n"
		"fpu	q4	.128	132	0\n"
		"fpu	q5	.128	148	0\n"
		"fpu	q6	.128	164	0\n"
		"fpu	q7	.128	180	0\n"
		"fpu	q8	.128	196	0\n"
		"fpu	q9	.128	212	0\n"
		"fpu	q10	.128	228	0\n"
		"fpu	q11	.128	244	0\n"
		"fpu	q12	.128	260	0\n"
		"fpu	q13	.128	276	0\n"
		"fpu	q14	.128	292	0\n"
		"fpu	q15	.128	308	0\n"
		;
	}
	return strdup (p);
}

static int archinfo(RAnal *anal, int q) {
	if (q == R_ANAL_ARCHINFO_DATA_ALIGN) {
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_ALIGN) {
		if (anal && anal->bits == 16) {
			return 2;
		}
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_MAX_OP_SIZE) {
		return 4;
	}
	if (q == R_ANAL_ARCHINFO_MIN_OP_SIZE) {
		if (anal && anal->bits == 16) {
			return 2;
		}
		return 4;
	}
	return 4; // XXX
}


static RList *anal_preludes(RAnal *anal) {
	RList *l = r_list_newf (r_search_keyword_free);
#define KW(d,ds,m,ms) r_list_append (l, r_search_keyword_new((const ut8*)d,ds,(const ut8*)m, ms, NULL))
	KW ("\xf0\x00\x00\xd1", 4, "\xf0\x00\x00\xff", 4);
	KW ("\xf0\x00\x00\xa9", 4, "\xf0\x00\x00\xff", 4);
	KW ("\x7f\x23\x03\xd5\xff", 5, NULL, 0);
	return l;
}

RAnalPlugin r_anal_plugin_arm_v35 = {
	.name = "arm.v35",
	.desc = "Vector35 ARM analyzer",
	.license = "BSD",
	.esil = false,
	.arch = "arm",
	.archinfo = archinfo,
	.get_reg_profile = get_reg_profile,
	.preludes = anal_preludes,
	.bits = 64,
	.op = &analop,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_arm_v35,
	.version = R2_VERSION
};
#endif
