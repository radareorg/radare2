/* radare2 - LGPL - Copyright 2015-2019 - pancake */

#include <r_asm.h>
#include <r_lib.h>
#include <capstone.h>

#if CS_API_MAJOR >= 4 && CS_API_MINOR >= 0
#define CAPSTONE_HAS_M680X 1
#else
#define CAPSTONE_HAS_M680X 0
#endif

#if !CAPSTONE_HAS_M680X
#ifdef _MSC_VER
#pragma message ("Cannot find support for m680x in capstone")
#else
#warning Cannot find capstone-m680x support
#endif
#endif

#if CAPSTONE_HAS_M680X
#include <m680x.h>

static int m680xmode(const char *str) {
	if (!str) {
		return CS_MODE_M680X_6800;
	}
	// replace this with the asm.features?
	if (str && strstr (str, "6800")) {
		return CS_MODE_M680X_6800;
	}
	if (str && strstr (str, "6801")) {
		return CS_MODE_M680X_6801;
	} else if (str && strstr (str, "6805")) {
		return CS_MODE_M680X_6805;
	} else if (str && strstr (str, "6808")) {
		return CS_MODE_M680X_6808;
	} else if (str && strstr (str, "6809")) {
		return CS_MODE_M680X_6809;
	} else if (str && strstr (str, "6811")) {
		return CS_MODE_M680X_6811;
	}
//
	if (str && strstr (str, "cpu12")) {
		return CS_MODE_M680X_CPU12;
	}
	if (str && strstr (str, "6301")) {
		return CS_MODE_M680X_6301;
	}
	if (str && strstr (str, "6309")) {
		return CS_MODE_M680X_6309;
	}
	if (str && strstr (str, "hcs08")) {
		return CS_MODE_M680X_HCS08;
	}
	return CS_MODE_M680X_6800;
}

#define IMM(x) insn->detail->m680x.operands[x].imm
#define REL(x) insn->detail->m680x.operands[x].rel

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	int n, ret, opsize = -1;
	static csh handle = 0;
	static int omode = -1;
	static int obits = 32;
	cs_insn* insn;

	int mode = m680xmode (a->cpu);

	if (mode != omode || a->bits != obits) {
		cs_close (&handle);
		handle = 0;
		omode = mode;
		obits = a->bits;
	}
	op->size = 4;
	if (handle == 0) {
		ret = cs_open (CS_ARCH_M680X, mode, &handle);
		if (ret != CS_ERR_OK) {
			goto fin;
		}
		cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	}
	n = cs_disasm (handle, (ut8*)buf, len, addr, 1, &insn);
	if (n < 1 || insn->size < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
		opsize = -1;
		goto beach;
	}
	if (!memcmp (buf, "\xff\xff", R_MIN (len, 2))) {
		op->type = R_ANAL_OP_TYPE_ILL;
		op->size = 2;
		opsize = -1;
		goto beach;
	}
	op->id = insn->id;
	opsize = op->size = insn->size;
	switch (insn->id) {
	case M680X_INS_INVLD:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case M680X_INS_ABA: ///< M6800/1/2/3
	case M680X_INS_ABX:
	case M680X_INS_ABY:
		break;
	case M680X_INS_ADC:
	case M680X_INS_ADCA:
	case M680X_INS_ADCB:
	case M680X_INS_ADCD:
	case M680X_INS_ADCR:
	case M680X_INS_ADD:
	case M680X_INS_ADDA:
	case M680X_INS_ADDB:
	case M680X_INS_ADDD:
	case M680X_INS_ADDE:
	case M680X_INS_ADDF:
	case M680X_INS_ADDR:
	case M680X_INS_ADDW:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case M680X_INS_AIM:
	case M680X_INS_AIS:
	case M680X_INS_AIX:
	case M680X_INS_AND:
	case M680X_INS_ANDA:
	case M680X_INS_ANDB:
	case M680X_INS_ANDCC:
	case M680X_INS_ANDD:
	case M680X_INS_ANDR:
	case M680X_INS_ASL:
	case M680X_INS_ASLA:
	case M680X_INS_ASLB:
	case M680X_INS_ASLD: ///< or LSLD
	case M680X_INS_ASR:
	case M680X_INS_ASRA:
	case M680X_INS_ASRB:
	case M680X_INS_ASRD:
	case M680X_INS_ASRX:
	case M680X_INS_BAND:
	case M680X_INS_BCC: ///< or BHS
	case M680X_INS_BCLR:
	case M680X_INS_BCS: ///< or BLO
	case M680X_INS_BEOR:
		break;
	case M680X_INS_BIAND:
	case M680X_INS_BIEOR:
	case M680X_INS_BIH:
	case M680X_INS_BIL:
	case M680X_INS_BIOR:
	case M680X_INS_BIT:
	case M680X_INS_BITA:
	case M680X_INS_BITB:
	case M680X_INS_BITD:
	case M680X_INS_BITMD:
		break;
	case M680X_INS_BRA:
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + op->size + REL(0).offset;
		op->fail = UT64_MAX;
		break;
	case M680X_INS_BEQ:
	case M680X_INS_BGE:
	case M680X_INS_BGND:
	case M680X_INS_BGT:
	case M680X_INS_BHCC:
	case M680X_INS_BHCS:
	case M680X_INS_BHI:
	case M680X_INS_BLE:
	case M680X_INS_BLS:
	case M680X_INS_BLT:
	case M680X_INS_BMC:
	case M680X_INS_BMI:
	case M680X_INS_BMS:
	case M680X_INS_BNE:
	case M680X_INS_BOR:
	case M680X_INS_BPL:
	case M680X_INS_BRCLR:
	case M680X_INS_BRSET:
	case M680X_INS_BRN:
	case M680X_INS_BSET:
	case M680X_INS_BSR:
	case M680X_INS_BVC:
	case M680X_INS_BVS:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + op->size + REL(0).offset;
		op->fail = addr + op->size;
		break;
	case M680X_INS_CALL:
	case M680X_INS_CBA: ///< M6800/1/2/3
	case M680X_INS_CBEQ:
	case M680X_INS_CBEQA:
	case M680X_INS_CBEQX:
	case M680X_INS_CLC: ///< M6800/1/2/3
	case M680X_INS_CLI: ///< M6800/1/2/3
	case M680X_INS_CLR:
	case M680X_INS_CLRA:
	case M680X_INS_CLRB:
	case M680X_INS_CLRD:
	case M680X_INS_CLRE:
	case M680X_INS_CLRF:
	case M680X_INS_CLRH:
	case M680X_INS_CLRW:
	case M680X_INS_CLRX:
	case M680X_INS_CLV: ///< M6800/1/2/3
		break;
	case M680X_INS_CMP:
	case M680X_INS_CMPA:
	case M680X_INS_CMPB:
	case M680X_INS_CMPD:
	case M680X_INS_CMPE:
	case M680X_INS_CMPF:
	case M680X_INS_CMPR:
	case M680X_INS_CMPS:
	case M680X_INS_CMPU:
	case M680X_INS_CMPW:
	case M680X_INS_CMPX:
	case M680X_INS_CMPY:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case M680X_INS_COM:
	case M680X_INS_COMA:
	case M680X_INS_COMB:
	case M680X_INS_COMD:
	case M680X_INS_COME:
	case M680X_INS_COMF:
	case M680X_INS_COMW:
	case M680X_INS_COMX:
	case M680X_INS_CPD:
	case M680X_INS_CPHX:
	case M680X_INS_CPS:
	case M680X_INS_CPX: ///< M6800/1/2/3
	case M680X_INS_CPY:
	case M680X_INS_CWAI:
	case M680X_INS_DAA:
	case M680X_INS_DBEQ:
	case M680X_INS_DBNE:
	case M680X_INS_DBNZ:
	case M680X_INS_DBNZA:
	case M680X_INS_DBNZX:
	case M680X_INS_DEC:
	case M680X_INS_DECA:
	case M680X_INS_DECB:
	case M680X_INS_DECD:
	case M680X_INS_DECE:
	case M680X_INS_DECF:
	case M680X_INS_DECW:
	case M680X_INS_DECX:
	case M680X_INS_DES: ///< M6800/1/2/3
	case M680X_INS_DEX: ///< M6800/1/2/3
	case M680X_INS_DEY:
	case M680X_INS_DIV:
	case M680X_INS_DIVD:
	case M680X_INS_DIVQ:
	case M680X_INS_EDIV:
	case M680X_INS_EDIVS:
	case M680X_INS_EIM:
	case M680X_INS_EMACS:
	case M680X_INS_EMAXD:
	case M680X_INS_EMAXM:
	case M680X_INS_EMIND:
	case M680X_INS_EMINM:
		break;
	case M680X_INS_EMUL:
	case M680X_INS_EMULS:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case M680X_INS_EOR:
	case M680X_INS_EORA:
	case M680X_INS_EORB:
	case M680X_INS_EORD:
	case M680X_INS_EORR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case M680X_INS_ETBL:
	case M680X_INS_EXG:
	case M680X_INS_FDIV:
	case M680X_INS_IBEQ:
	case M680X_INS_IBNE:
		break;
	case M680X_INS_IDIV:
	case M680X_INS_IDIVS:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case M680X_INS_ILLGL:
		break;
	case M680X_INS_INC:
	case M680X_INS_INCA:
	case M680X_INS_INCB:
	case M680X_INS_INCD:
	case M680X_INS_INCE:
	case M680X_INS_INCF:
	case M680X_INS_INCW:
	case M680X_INS_INCX:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case M680X_INS_INS: ///< M6800/1/2/3
	case M680X_INS_INX: ///< M6800/1/2/3
	case M680X_INS_INY:
		break;
	case M680X_INS_JMP:
		op->type = R_ANAL_OP_TYPE_JMP;
		break;
	case M680X_INS_JSR:
		op->type = R_ANAL_OP_TYPE_RJMP;
		break;
	case M680X_INS_LBCC: ///< or LBHS
	case M680X_INS_LBCS: ///< or LBLO
	case M680X_INS_LBEQ:
	case M680X_INS_LBGE:
	case M680X_INS_LBGT:
	case M680X_INS_LBHI:
	case M680X_INS_LBLE:
	case M680X_INS_LBLS:
	case M680X_INS_LBLT:
	case M680X_INS_LBMI:
	case M680X_INS_LBNE:
	case M680X_INS_LBPL:
	case M680X_INS_LBRA:
	case M680X_INS_LBRN:
	case M680X_INS_LBSR:
	case M680X_INS_LBVC:
	case M680X_INS_LBVS:
	case M680X_INS_LDA:
	case M680X_INS_LDAA: ///< M6800/1/2/3
	case M680X_INS_LDAB: ///< M6800/1/2/3
	case M680X_INS_LDB:
	case M680X_INS_LDBT:
	case M680X_INS_LDD:
	case M680X_INS_LDE:
	case M680X_INS_LDF:
	case M680X_INS_LDHX:
	case M680X_INS_LDMD:
	case M680X_INS_LDQ:
	case M680X_INS_LDS:
	case M680X_INS_LDU:
	case M680X_INS_LDW:
	case M680X_INS_LDX:
	case M680X_INS_LDY:
	case M680X_INS_LEAS:
	case M680X_INS_LEAU:
	case M680X_INS_LEAX:
	case M680X_INS_LEAY:
	case M680X_INS_LSL:
	case M680X_INS_LSLA:
	case M680X_INS_LSLB:
	case M680X_INS_LSLD:
	case M680X_INS_LSLX:
	case M680X_INS_LSR:
	case M680X_INS_LSRA:
	case M680X_INS_LSRB:
	case M680X_INS_LSRD: ///< or ASRD
	case M680X_INS_LSRW:
	case M680X_INS_LSRX:
	case M680X_INS_MAXA:
	case M680X_INS_MAXM:
	case M680X_INS_MEM:
	case M680X_INS_MINA:
	case M680X_INS_MINM:
		break;
	case M680X_INS_MOV:
	case M680X_INS_MOVB:
	case M680X_INS_MOVW:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case M680X_INS_MUL:
	case M680X_INS_MULD:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case M680X_INS_NEG:
	case M680X_INS_NEGA:
	case M680X_INS_NEGB:
	case M680X_INS_NEGD:
	case M680X_INS_NEGX:
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case M680X_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case M680X_INS_NSA:
	case M680X_INS_OIM:
	case M680X_INS_ORA:
	case M680X_INS_ORAA: ///< M6800/1/2/3
	case M680X_INS_ORAB: ///< M6800/1/2/3
	case M680X_INS_ORB:
	case M680X_INS_ORCC:
	case M680X_INS_ORD:
	case M680X_INS_ORR:
	case M680X_INS_PSHA: ///< M6800/1/2/3
	case M680X_INS_PSHB: ///< M6800/1/2/3
	case M680X_INS_PSHC:
	case M680X_INS_PSHD:
	case M680X_INS_PSHH:
	case M680X_INS_PSHS:
	case M680X_INS_PSHSW:
	case M680X_INS_PSHU:
	case M680X_INS_PSHUW:
	case M680X_INS_PSHX: ///< M6800/1/2/3
	case M680X_INS_PSHY:
	case M680X_INS_PULA: ///< M6800/1/2/3
	case M680X_INS_PULB: ///< M6800/1/2/3
	case M680X_INS_PULC:
	case M680X_INS_PULD:
	case M680X_INS_PULH:
	case M680X_INS_PULS:
	case M680X_INS_PULSW:
	case M680X_INS_PULU:
	case M680X_INS_PULUW:
	case M680X_INS_PULX: ///< M6800/1/2/3
	case M680X_INS_PULY:
	case M680X_INS_REV:
	case M680X_INS_REVW:
	case M680X_INS_ROL:
	case M680X_INS_ROLA:
	case M680X_INS_ROLB:
	case M680X_INS_ROLD:
	case M680X_INS_ROLW:
	case M680X_INS_ROLX:
	case M680X_INS_ROR:
	case M680X_INS_RORA:
	case M680X_INS_RORB:
	case M680X_INS_RORD:
	case M680X_INS_RORW:
	case M680X_INS_RORX:
	case M680X_INS_RSP:
	case M680X_INS_RTC:
	case M680X_INS_RTI:
	case M680X_INS_RTS:
	case M680X_INS_SBA: ///< M6800/1/2/3
	case M680X_INS_SBC:
	case M680X_INS_SBCA:
	case M680X_INS_SBCB:
	case M680X_INS_SBCD:
	case M680X_INS_SBCR:
	case M680X_INS_SEC:
	case M680X_INS_SEI:
	case M680X_INS_SEV:
	case M680X_INS_SEX:
	case M680X_INS_SEXW:
	case M680X_INS_SLP:
	case M680X_INS_STA:
	case M680X_INS_STAA: ///< M6800/1/2/3
	case M680X_INS_STAB: ///< M6800/1/2/3
	case M680X_INS_STB:
	case M680X_INS_STBT:
	case M680X_INS_STD:
	case M680X_INS_STE:
	case M680X_INS_STF:
	case M680X_INS_STOP:
	case M680X_INS_STHX:
	case M680X_INS_STQ:
	case M680X_INS_STS:
	case M680X_INS_STU:
	case M680X_INS_STW:
	case M680X_INS_STX:
	case M680X_INS_STY:
	case M680X_INS_SUB:
	case M680X_INS_SUBA:
	case M680X_INS_SUBB:
	case M680X_INS_SUBD:
	case M680X_INS_SUBE:
	case M680X_INS_SUBF:
	case M680X_INS_SUBR:
	case M680X_INS_SUBW:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case M680X_INS_SWI:
	case M680X_INS_SWI2:
	case M680X_INS_SWI3:
		op->type = R_ANAL_OP_TYPE_SWI;
		break;
	case M680X_INS_SYNC:
	case M680X_INS_TAB: ///< M6800/1/2/3
	case M680X_INS_TAP: ///< M6800/1/2/3
	case M680X_INS_TAX:
		break;
	case M680X_INS_TBA: ///< M6800/1/2/3
	case M680X_INS_TBEQ:
	case M680X_INS_TBL:
	case M680X_INS_TBNE:
	case M680X_INS_TEST:
	case M680X_INS_TFM:
	case M680X_INS_TFR:
	case M680X_INS_TIM:
	case M680X_INS_TPA: ///< M6800/1/2/3
	case M680X_INS_TST:
	case M680X_INS_TSTA:
	case M680X_INS_TSTB:
	case M680X_INS_TSTD:
	case M680X_INS_TSTE:
	case M680X_INS_TSTF:
	case M680X_INS_TSTW:
	case M680X_INS_TSTX:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case M680X_INS_TSX: ///< M6800/1/2/3
	case M680X_INS_TSY:
	case M680X_INS_TXA:
	case M680X_INS_TXS: ///< M6800/1/2/3
	case M680X_INS_TYS:
	case M680X_INS_WAI: ///< M6800/1/2/3
	case M680X_INS_WAIT:
	case M680X_INS_WAV:
	case M680X_INS_WAVR:
	case M680X_INS_XGDX: ///< HD6301
	case M680X_INS_XGDY:
		break;
	}
beach:
	cs_free (insn, n);
	//cs_close (&handle);
fin:
	return opsize;
}

// XXX
static bool set_reg_profile(RAnal *anal) {
	const char *p = \
		"=PC    pc\n"
		"=SP    sp\n"
		"=A0    a0\n"
		"=A1    a1\n"
		"gpr	pc	.16	48	0\n"
		"gpr	sp	.16	48	0\n"
		"gpr	a0	.16	48	0\n"
		"gpr	a1	.16	48	0\n";
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_m680x_cs = {
	.name = "m680x",
	.desc = "Capstone M680X analysis plugin",
	.license = "BSD",
	.esil = false,
	.arch = "m680x",
	.set_reg_profile = &set_reg_profile,
	.bits = 16 | 32,
	.op = &analop,
};
#else
RAnalPlugin r_anal_plugin_m680x_cs = {
	.name = "m680x (unsupported)",
	.desc = "Capstone M680X analyzer (unsupported)",
	.license = "BSD",
	.arch = "m680x",
	.bits = 32,
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_m680x_cs,
	.version = R2_VERSION
};
#endif
