/* radare2 - LGPL - Copyright 2015-2025 - pancake */

#include <r_arch.h>
#include <capstone/capstone.h>

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
#include <capstone/m680x.h>

static int m680xmode(const char *str) {
	if (R_STR_ISEMPTY (str)) {
		return CS_MODE_M680X_6800;
	}
	// replace this with the asm.features?
	if (strstr (str, "6800")) {
		return CS_MODE_M680X_6800;
	}
	if (strstr (str, "6801")) {
		return CS_MODE_M680X_6801;
	} else if (strstr (str, "6805")) {
		return CS_MODE_M680X_6805;
	} else if (strstr (str, "6808")) {
		return CS_MODE_M680X_6808;
	} else if (strstr (str, "6809")) {
		return CS_MODE_M680X_6809;
	} else if (strstr (str, "6811")) {
		return CS_MODE_M680X_6811;
	}
	if (strstr (str, "cpu12")) {
		return CS_MODE_M680X_CPU12;
	}
	if (strstr (str, "6301")) {
		return CS_MODE_M680X_6301;
	}
	if (strstr (str, "6309")) {
		return CS_MODE_M680X_6309;
	}
	if (strstr (str, "hcs08")) {
		return CS_MODE_M680X_HCS08;
	}
	return CS_MODE_M680X_6800;
}

#define CSINC M680X
#define CSINC_MODE m680xmode(as->config->cpu)
#include "../capstone.inc.c"

#define IMM(x) insn->detail->m680x.operands[x].imm
#define REL(x) insn->detail->m680x.operands[x].rel

static inline csh cs_handle_for_session (RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static char *filter_intel_syntax (char *mnemonic) {
	// we don't really output operands in intel order but we can clean up
	// XXX: this is not finished
	mnemonic = r_str_replace (mnemonic, "$", "0x", true);
	mnemonic = r_str_replace (mnemonic, "lda ", "lda [", true);
	mnemonic = r_str_replace (mnemonic, "ldx ", "ldx [", true);
	mnemonic = r_str_replace (mnemonic, "and ", "and [", true);
	mnemonic = r_str_replace (mnemonic, "ora ", "ora [", true);
	mnemonic = r_str_replace (mnemonic, " [#", " ", true);
	if (strstr (mnemonic, "[")) {
		mnemonic = r_str_append (mnemonic, "]");
	}
	return mnemonic;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	csh handle = cs_handle_for_session (as);
	if (handle == 0) {
		return false;
	}

	int n, opsize = -1;
	cs_insn* insn;

	op->size = 4;
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
	op->nopcode = 1;
	op->id = insn->id;
	opsize = op->size = insn->size;
	op->family = R_ANAL_OP_FAMILY_CPU; // almost everything is CPU
	op->type = R_ANAL_OP_TYPE_UNK;
	if (insn->detail->groups_count > 0) {
		// do we really need this anyway?
		switch (insn->detail->groups[0]) {
		case M680X_GRP_JUMP:
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case M680X_GRP_CALL:
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case M680X_GRP_RET:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case M680X_GRP_INT:
			op->type = R_ANAL_OP_TYPE_SWI;
			break;
		case M680X_GRP_IRET:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case M680X_GRP_BRAREL: // all relative branching instructions
			op->type = R_ANAL_OP_TYPE_RJMP;
			break;
		case M680X_GRP_PRIV: // not used
		default:
			break;
		}
	}
	op->prefix = 0;
	op->cond = 0;
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
		break;
	case M680X_INS_AND:
	case M680X_INS_ANDA:
	case M680X_INS_ANDB:
	case M680X_INS_ANDCC:
	case M680X_INS_ANDD:
	case M680X_INS_ANDR:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case M680X_INS_ASL:
	case M680X_INS_ASLA:
	case M680X_INS_ASLB:
	case M680X_INS_ASLD: ///< or LSLD
		op->type = R_ANAL_OP_TYPE_SAL;
		break;
	case M680X_INS_ASR:
	case M680X_INS_ASRA:
	case M680X_INS_ASRB:
	case M680X_INS_ASRD:
	case M680X_INS_ASRX:
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case M680X_INS_BAND:
		break;
	case M680X_INS_BCC: ///< or BHS
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case M680X_INS_BCLR:
		break;
	case M680X_INS_BCS: ///< or BLO
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
	case M680X_INS_BEOR:
		break;
	case M680X_INS_BIAND:
	case M680X_INS_BIEOR:
		break;
	case M680X_INS_BIH:
	case M680X_INS_BIL:
		op->type = R_ANAL_OP_TYPE_CJMP;
		break;
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
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + op->size + REL(0).offset;
		op->fail = addr + op->size;
		break;
	case M680X_INS_BRN:
		op->type = R_ANAL_OP_TYPE_NOP;
		break;
	case M680X_INS_BSET:
		break;
	case M680X_INS_BSR:
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case M680X_INS_BVC:
	case M680X_INS_BVS:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + op->size + REL(0).offset;
		op->fail = addr + op->size;
		break;
	case M680X_INS_CALL:
		op->type = R_ANAL_OP_TYPE_CALL;
		break;
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
		op->type = R_ANAL_OP_TYPE_CALL;
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
		break;
	case M680X_INS_LSL:
	case M680X_INS_LSLA:
	case M680X_INS_LSLB:
	case M680X_INS_LSLD:
	case M680X_INS_LSLX:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case M680X_INS_LSR:
	case M680X_INS_LSRA:
	case M680X_INS_LSRB:
	case M680X_INS_LSRD: ///< or ASRD
	case M680X_INS_LSRW:
	case M680X_INS_LSRX:
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
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
		break;
	case M680X_INS_RTI:
	case M680X_INS_RTS:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
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
		break;
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
		break;
	case M680X_INS_TAX:
		op->type = R_ANAL_OP_TYPE_MOV;
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
	if (mask & R_ARCH_OP_MASK_DISASM) {
		if (op->type == R_ANAL_OP_TYPE_ILL) {
			op->mnemonic = strdup ("invalid");
		} else {
			op->mnemonic = r_str_newf ("%s%s%s", insn->mnemonic,
					insn->op_str[0]?" ": "", insn->op_str);
			r_str_replace_in (op->mnemonic, strlen (op->mnemonic) + 1,
				"ptr ", "", true);
			if (as->config->syntax == R_ARCH_SYNTAX_INTEL) {
				// XXX: should it be an option?
				op->mnemonic = filter_intel_syntax (op->mnemonic);
			}
		}
	}
	cs_free (insn, n);
	return opsize > 0;
}

// XXX
static char *regs(RArchSession *as) {
	const char *p = \
		"=PC    pc\n"
		"=SP    s\n"
		"gpr	pc	.16	0	0\n" ///< M6800/1/2/3/9, M6301/9
		"gpr	s	.16	2	0\n" ///< M6809/M6309 system stack (=sp on others)
		"gpr	cc	.8	4	0\n" ///< M6800/1/2/3/9, M6301/9
		"flg	C	.1	4.0	0\n"
		"flg	V	.1	4.1	0\n" // At least 6805 lacks it? Are the others shifted??
		"flg	Z	.1	4.2	0\n"
		"flg	N	.1	4.3	0\n"
		"flg	I	.1	4.4	0\n"
		"flg	H	.1	4.5	0\n"
		"flg	F	.1	4.6	0\n"
		"flg	E	.1	4.7	0\n"
		"gpr	dp	.8	5	0\n" ///< M6809/M6309
		"gpr	f	.8	6	0\n" ///< HD6309
		"gpr	e	.8	7	0\n" ///< HD6309
		"gpr	w	.16	6	0\n" ///< HD6309
		"gpr	b	.8	8	0\n" ///< M6800/1/2/3/9, HD6301/9
		"gpr	a	.8	9	0\n" ///< M6800/1/2/3/5/9, HD6301/9
		"gpr	d	.16	8	0\n" ///< M6801/3/9, HD6301/9
		"gpr	q	.32	6	0\n" ///< M6309
		"gpr	x	.16	10	0\n" ///< M6800/1/2/3/9, M6301/9 Also 6808 but capstone disagrees
		"gpr	y	.16	12	0\n" ///< M6809/M6309
		"gpr	u	.16	14	0\n" ///< M6809/M6309
		"gpr	v	.16	16	0\n" ///< M6309
		"gpr	zero	.16	18	0\n" ///< HD6309
		"gpr	tmp2	.16	20	0\n"  ///< CPU12
		"gpr	tmp3	.16	22	0\n" ///< CPU12
		"gpr	md	.8	24	0\n" ///< M6309
		"flg	EM	.1	24.0	0\n"
		"flg	FM	.1	24.1	0\n"
		"flg	IE	.1	24.6	0\n"
		"flg	ZD	.1	24.7	0\n";
	return strdup (p);
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (CapstonePluginData);
	CapstonePluginData *cpd = as->data;
	if (!r_arch_cs_init (as, &cpd->cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	cs_close (&cpd->cs_handle);
	R_FREE (s->data);
	return true;
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

const RArchPlugin r_arch_plugin_m680x_cs = {
	.meta = {
		.name = "m680x",
		.desc = "Capstone M680X",
		.license = "Apache-2.0",
	},
	.arch = "m680x",
	.cpus = "6800,6801,6805,6808,6809,6811,6301,6309,cpu12,hcs08",
	.regs = regs,
	.bits = R_SYS_BITS_PACK2 (16, 32),
	.endian = R_SYS_ENDIAN_BIG,
	.decode = decode,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};
#else
const RArchPlugin r_anal_plugin_m680x_cs = {
	.meta = {
		.name = "m680x (unsupported)",
		.desc = "Capstone M680X (unsupported)",
		.license = "Apache-2.0",
	},
	.arch = "m680x",
	.bits = R_SYS_BITS_PACK1 (32),
};
#endif

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_anal_plugin_m680x_cs,
	.version = R2_VERSION
};
#endif
