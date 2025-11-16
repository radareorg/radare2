/* radare2 - LGPL - Copyright 2013-2025 - pancake */

#include <r_arch.h>
#include <sdb/ht_uu.h>

#define CAPSTONE_AARCH64_COMPAT_HEADER
#define CAPSTONE_ARM_COMPAT_HEADER
#include <capstone/capstone.h>
#include <capstone/arm.h>
#include <r_util/r_assert.h>
#include "arm_hacks.inc.c"
#include "asm_arm_hacks.inc.c"
#include "arm_regprofile.inc.c"

typedef char RStringShort[32];

typedef struct plugin_data_t {
	bool bigendian;
	int bits;
	char *cpu;
	csh cs_handle;
	HtUU *ht_itblock;
	HtUU *ht_it;
} PluginData;

static inline csh *cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	PluginData *pd = (PluginData*) as->data;
	return &(pd->cs_handle);
}

static inline HtUU *ht_itblock_for_session (RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	PluginData *pd = (PluginData*) as->data;
	return pd->ht_itblock;
}

static inline HtUU *ht_it_for_session (RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, NULL);
	PluginData *pd = (PluginData*) as->data;
	return pd->ht_it;
}

/* arm64 */
#define IMM64(x) (ut64)(insn->detail->arm64.operands[x].imm)
#define INSOP64(x) insn->detail->arm64.operands[x]

/* arm32 */
#define REG(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm.operands[x].reg))
#define REG64(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm64.operands[x].reg))
#define REGID64(x) insn->detail->arm64.operands[x].reg
#define REGID(x) insn->detail->arm.operands[x].reg
#define IMM(x) (ut32)(insn->detail->arm.operands[x].imm)
#define INSOP(x) insn->detail->arm.operands[x]
#define MEMBASE(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm.operands[x].mem.base))
#define MEMBASE64(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm64.operands[x].mem.base))
#define REGBASE(x) insn->detail->arm.operands[x].mem.base
#define REGBASE64(x) insn->detail->arm64.operands[x].mem.base
// s/index/base|reg/
#define MEMINDEX(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm.operands[x].mem.index))
#define HASMEMINDEX(x) (insn->detail->arm.operands[x].mem.index != ARM_REG_INVALID)
#define MEMINDEX64(x) r_str_getf (cs_reg_name (*handle, insn->detail->arm64.operands[x].mem.index))
#define HASMEMINDEX64(x) ((arm64_reg)insn->detail->arm64.operands[x].mem.index != ARM64_REG_INVALID)
#define ISMEMINDEXSUB(x) insn->detail->arm.operands[x].subtracted
#define MEMDISP(x) insn->detail->arm.operands[x].mem.disp
#define MEMDISP64(x) (ut64)insn->detail->arm64.operands[x].mem.disp
#define ISIMM(x) (insn->detail->arm.operands[x].type == ARM_OP_IMM)
#define ISIMM64(x) ((arm64_op_type)insn->detail->arm64.operands[x].type & (ARM64_OP_IMM | ARM64_OP_CIMM | ARM64_OP_FP))
#define ISREG(x) (insn->detail->arm.operands[x].type == ARM_OP_REG)
#define ISREG64(x) ((arm64_op_type)insn->detail->arm64.operands[x].type == ARM64_OP_REG)
#define ISMEM(x) (insn->detail->arm.operands[x].type == ARM_OP_MEM)
#define ISMEM64(x) ((arm64_op_type)insn->detail->arm64.operands[x].type == ARM64_OP_MEM)
#define EXT64(x) decode_sign_ext (insn->detail->arm64.operands[x].ext)

#if CS_API_MAJOR > 3
#define LSHIFT(x) insn->detail->arm.operands[x].mem.lshift
#define LSHIFT2(x) insn->detail->arm.operands[x].shift.value // Dangerous, returns value even if isn't LSL
#define LSHIFT2_64(x) insn->detail->arm64.operands[x].shift.value
#else
#define LSHIFT(x) 0
#define LSHIFT2(x) 0
#define LSHIFT2_64(x) 0
#endif
#define OPCOUNT() insn->detail->arm.op_count
#define OPCOUNT64() insn->detail->arm64.op_count
#define ISSHIFTED(x) (insn->detail->arm.operands[x].shift.type != ARM_SFT_INVALID && insn->detail->arm.operands[x].shift.value != 0)
#define ISSHIFTED64(x) ((arm64_shifter)insn->detail->arm64.operands[x].shift.type != ARM64_SFT_INVALID && insn->detail->arm64.operands[x].shift.value != 0)
#define SHIFTTYPE(x) insn->detail->arm.operands[x].shift.type
#define SHIFTVALUE(x) insn->detail->arm.operands[x].shift.value

#if CS_API_MAJOR < 6
#define SHIFTTYPEREG(x) (\
		SHIFTTYPE(x) == ARM_SFT_ASR_REG || SHIFTTYPE(x) == ARM_SFT_LSL_REG || \
		SHIFTTYPE(x) == ARM_SFT_LSR_REG || SHIFTTYPE(x) == ARM_SFT_ROR_REG || \
		SHIFTTYPE(x) == ARM_SFT_RRX_REG)
#define ISWRITEBACK32() (insn->detail->arm.writeback == true)
#define ISWRITEBACK64() (insn->detail->arm64.writeback == true)
#define PSTATE() op->pstate
#define SYS() (ut64)op->sys
#define PREFETCH() op->prefetch
#define BARRIER() op->barrier
#else
// *********************
// CS6 compatibility:
#define SHIFTTYPEREG(x) (\
		SHIFTTYPE(x) == ARM_SFT_ASR_REG || SHIFTTYPE(x) == ARM_SFT_LSL_REG || \
		SHIFTTYPE(x) == ARM_SFT_LSR_REG || SHIFTTYPE(x) == ARM_SFT_ROR_REG)
#define ISWRITEBACK32() (insn->detail->writeback == true)
#define ISWRITEBACK64() ISWRITEBACK32 ()
#define PSTATE() op->sysop.alias.pstateimm0_15
#define SYS() (ut64)op->sysop.reg.tlbi
#define PREFETCH() op->sysop.alias.prfm
#define BARRIER() op->sysop.alias.db
// *********************
#endif

#define ISPREINDEX32() (((OPCOUNT () == 2) && (ISMEM (1)) && (ISWRITEBACK32 ())) || ((OPCOUNT () == 3) && (ISMEM (2)) && (ISWRITEBACK32 ())))
#define ISPOSTINDEX32() (((OPCOUNT () == 3) && (ISIMM (2) || ISREG (2)) && (ISWRITEBACK32 ())) || ((OPCOUNT () == 4) && (ISIMM (3) || ISREG (3)) && (ISWRITEBACK32 ())))
#define ISPREINDEX64() (((OPCOUNT64 () == 2) && (ISMEM64 (1)) && (ISWRITEBACK64 ())) || ((OPCOUNT64 () == 3) && (ISMEM64 (2)) && (ISWRITEBACK64 ())))
#define ISPOSTINDEX64() (((OPCOUNT64 () == 3) && (ISIMM64 (2)) && (ISWRITEBACK64 ())) || ((OPCOUNT64 () == 4) && (ISIMM64 (3)) && (ISWRITEBACK64 ())))

// *********************
// CS6 compatibility:
#if CS_API_MAJOR == 6

#define ARM_INS_NOP ARM_INS_ALIAS_NOP

#define ARM64_INS_MNEG ARM64_INS_ALIAS_MNEG
#define ARM64_INS_NOP ARM64_INS_ALIAS_NOP
#define ARM64_INS_CMP ARM64_INS_ALIAS_CMP
#define ARM64_INS_CMN ARM64_INS_ALIAS_CMN
#define ARM64_INS_TST ARM64_INS_ALIAS_TST
#define ARM64_INS_CSET ARM64_INS_ALIAS_CSET
#define ARM64_INS_CINC ARM64_INS_ALIAS_CINC
#define ARM64_INS_MVN ARM64_INS_ALIAS_MVN
#define ARM64_INS_BFI ARM64_INS_ALIAS_BFI
#define ARM64_INS_BFXIL ARM64_INS_ALIAS_BFXIL
#define ARM64_INS_SBFIZ ARM64_INS_ALIAS_SBFIZ
#define ARM64_INS_UBFIZ ARM64_INS_ALIAS_UBFIZ
#define ARM64_INS_SBFX ARM64_INS_ALIAS_SBFX
#define ARM64_INS_UBFX ARM64_INS_ALIAS_UBFX
#define ARM64_INS_NEGS ARM64_INS_ALIAS_NEGS
#define ARM64_INS_PACIA1716 ARM64_INS_ALIAS_PACIA1716
#define ARM64_INS_PACIASP ARM64_INS_ALIAS_PACIASP
#define ARM64_INS_PACIAZ ARM64_INS_ALIAS_PACIAZ
#define ARM64_INS_PACIB1716 ARM64_INS_ALIAS_PACIB1716
#define ARM64_INS_PACIBSP ARM64_INS_ALIAS_PACIBSP
#define ARM64_INS_PACIBZ ARM64_INS_ALIAS_PACIBZ
#define ARM64_INS_AUTIA1716 ARM64_INS_ALIAS_AUTIA1716
#define ARM64_INS_AUTIASP ARM64_INS_ALIAS_AUTIASP
#define ARM64_INS_AUTIAZ ARM64_INS_ALIAS_AUTIAZ
#define ARM64_INS_AUTIB1716 ARM64_INS_ALIAS_AUTIB1716
#define ARM64_INS_AUTIBSP ARM64_INS_ALIAS_AUTIBSP
#define ARM64_INS_AUTIBZ ARM64_INS_ALIAS_AUTIBZ
#define ARM64_INS_XPACLRI ARM64_INS_ALIAS_XPACLRI
#define ARM64_INS_IC ARM64_INS_ALIAS_IC
#define ARM64_INS_DC ARM64_INS_ALIAS_DC
#define ARM64_INS_NEGS ARM64_INS_ALIAS_NEGS

// ARM64_OP_*:

#define ARM64_OP_PSTATE ARM64_OP_PSTATEIMM0_15
#define ARM64_PSTATE_SPSEL ARM64_PSTATEIMM0_15_SPSEL
#define ARM64_PSTATE_DAIFSET ARM64_PSTATEIMM0_15_DAIFSET
#define ARM64_PSTATE_DAIFCLR ARM64_PSTATEIMM0_15_DAIFCLR

#define ARM64_OP_SYS ARM64_OP_TLBI
#define ARM64_OP_PREFETCH ARM64_OP_PRFM
#define ARM64_OP_BARRIER ARM64_OP_DB

// GRP
#define ARM64_GRP_CRC ARM64_FEATURE_HASCRC
#define ARM64_GRP_NEON ARM64_FEATURE_HASNEON
#define ARM64_GRP_FPARMV8 ARM64_FEATURE_HASFPARMV8

#define ARM_GRP_CRC ARM_FEATURE_HASCRC
#define ARM_GRP_NEON ARM_FEATURE_HASNEON
#define ARM_GRP_FPARMV8 ARM_FEATURE_HASFPARMV8
#endif
// *********************

#define BITMASK_BY_WIDTH_COUNT 64
static const ut64 bitmask_by_width[BITMASK_BY_WIDTH_COUNT] = {
	0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff,
	0xfff, 0x1fff, 0x3fff, 0x7fff, 0xffff, 0x1ffff, 0x3ffff, 0x7ffff,
	0xfffff, 0x1fffff, 0x3fffff, 0x7fffff, 0xffffff, 0x1ffffffLL, 0x3ffffffLL,
	0x7ffffffLL, 0xfffffffLL, 0x1fffffffLL, 0x3fffffffLL, 0x7fffffffLL, 0xffffffffLL,
	0x1ffffffffLL, 0x3ffffffffLL, 0x7ffffffffLL, 0xfffffffffLL, 0x1fffffffffLL,
	0x3fffffffffLL, 0x7fffffffffLL, 0xffffffffffLL, 0x1ffffffffffLL, 0x3ffffffffffLL,
	0x7ffffffffffLL, 0xfffffffffffLL, 0x1fffffffffffLL, 0x3fffffffffffLL, 0x7fffffffffffLL,
	0xffffffffffffLL, 0x1ffffffffffffLL, 0x3ffffffffffffLL, 0x7ffffffffffffLL,
	0xfffffffffffffLL, 0x1fffffffffffffLL, 0x3fffffffffffffLL, 0x7fffffffffffffLL,
	0xffffffffffffffLL, 0x1ffffffffffffffLL, 0x3ffffffffffffffLL, 0x7ffffffffffffffLL,
	0xfffffffffffffffLL, 0x1fffffffffffffffLL, 0x3fffffffffffffffLL, 0x7fffffffffffffffLL, 0xffffffffffffffffLL
};

static const char *shift_type_name(arm_shifter type) {
	switch (type) {
	case ARM_SFT_ASR:
		return "asr";
	case ARM_SFT_LSL:
		return "lsl";
	case ARM_SFT_LSR:
		return "lsr";
	case ARM_SFT_ROR:
		return "ror";
	case ARM_SFT_RRX:
		return "rrx";
	case ARM_SFT_ASR_REG:
		return "asr_reg";
	case ARM_SFT_LSL_REG:
		return "lsl_reg";
	case ARM_SFT_LSR_REG:
		return "lsr_reg";
	case ARM_SFT_ROR_REG:
		return "ror_reg";
#if CS_API_MAJOR < 6
	case ARM_SFT_RRX_REG:
		return "rrx_reg";
#endif
	default:
		return "";
	}
}

static const char *vector_data_type_name(arm_vectordata_type type) {
	switch (type) {
	case ARM_VECTORDATA_I8:
		return "i8";
	case ARM_VECTORDATA_I16:
		return "i16";
	case ARM_VECTORDATA_I32:
		return "i32";
	case ARM_VECTORDATA_I64:
		return "i64";
	case ARM_VECTORDATA_S8:
		return "s8";
	case ARM_VECTORDATA_S16:
		return "s16";
	case ARM_VECTORDATA_S32:
		return "s32";
	case ARM_VECTORDATA_S64:
		return "s64";
	case ARM_VECTORDATA_U8:
		return "u8";
	case ARM_VECTORDATA_U16:
		return "u16";
	case ARM_VECTORDATA_U32:
		return "u32";
	case ARM_VECTORDATA_U64:
		return "u64";
	case ARM_VECTORDATA_P8:
		return "p8";
	case ARM_VECTORDATA_F32:
		return "f32";
	case ARM_VECTORDATA_F64:
		return "f64";
	case ARM_VECTORDATA_F16F64:
		return "f16.f64";
	case ARM_VECTORDATA_F64F16:
		return "f64.f16";
	case ARM_VECTORDATA_F32F16:
		return "f32.f16";
	case ARM_VECTORDATA_F16F32:
		return "f16.f32";
	case ARM_VECTORDATA_F64F32:
		return "f64.f32";
	case ARM_VECTORDATA_F32F64:
		return "f32.f64";
	case ARM_VECTORDATA_S32F32:
		return "s32.f32";
	case ARM_VECTORDATA_U32F32:
		return "u32.f32";
	case ARM_VECTORDATA_F32S32:
		return "f32.s32";
	case ARM_VECTORDATA_F32U32:
		return "f32.u32";
	case ARM_VECTORDATA_F64S16:
		return "f64.s16";
	case ARM_VECTORDATA_F32S16:
		return "f32.s16";
	case ARM_VECTORDATA_F64S32:
		return "f64.s32";
	case ARM_VECTORDATA_S16F64:
		return "s16.f64";
	case ARM_VECTORDATA_S16F32:
		return "s16.f64";
	case ARM_VECTORDATA_S32F64:
		return "s32.f64";
	case ARM_VECTORDATA_U16F64:
		return "u16.f64";
	case ARM_VECTORDATA_U16F32:
		return "u16.f32";
	case ARM_VECTORDATA_U32F64:
		return "u32.f64";
	case ARM_VECTORDATA_F64U16:
		return "f64.u16";
	case ARM_VECTORDATA_F32U16:
		return "f32.u16";
	case ARM_VECTORDATA_F64U32:
		return "f64.u32";
	default:
		return "";
	}
}

static const char *cc_name(arm_cc cc) {
	switch (cc) {
	case ARM_CC_EQ: // Equal                      Equal
		return "eq";
	case ARM_CC_NE: // Not equal                  Not equal, or unordered
		return "ne";
	case ARM_CC_HS: // Carry set                  >, ==, or unordered
		return "hs";
	case ARM_CC_LO: // Carry clear                Less than
		return "lo";
	case ARM_CC_MI: // Minus, negative            Less than
		return "mi";
	case ARM_CC_PL: // Plus, positive or zero     >, ==, or unordered
		return "pl";
	case ARM_CC_VS: // Overflow                   Unordered
		return "vs";
	case ARM_CC_VC: // No overflow                Not unordered
		return "vc";
	case ARM_CC_HI: // Unsigned higher            Greater than, or unordered
		return "hi";
	case ARM_CC_LS: // Unsigned lower or same     Less than or equal
		return "ls";
	case ARM_CC_GE: // Greater than or equal      Greater than or equal
		return "ge";
	case ARM_CC_LT: // Less than                  Less than, or unordered
		return "lt";
	case ARM_CC_GT: // Greater than               Greater than
		return "gt";
	case ARM_CC_LE: // Less than or equal         <, ==, or unordered
		return "le";
	default:
		return "";
	}
}

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_arm *x = &insn->detail->arm;
	for (i = 0; i < x->op_count; i++) {
		cs_arm_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case ARM_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case ARM_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_ki (pj, "value", op->imm);
			break;
		case ARM_OP_MEM:
			pj_ks (pj, "type", "mem");
			if (op->mem.base != ARM_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			if (op->mem.index != ARM_REG_INVALID) {
				pj_ks (pj, "index", cs_reg_name (handle, op->mem.index));
			}
			pj_ki (pj, "scale", op->mem.scale);
			pj_ki (pj, "disp", op->mem.disp);
			break;
		case ARM_OP_FP:
			pj_ks (pj, "type", "fp");
			pj_kd (pj, "value", op->fp);
			break;
		case ARM_OP_CIMM:
			pj_ks (pj, "type", "cimm");
			pj_ki (pj, "value", op->imm);
			break;
		case ARM_OP_PIMM:
			pj_ks (pj, "type", "pimm");
			pj_ki (pj, "value", op->imm);
			break;
		case ARM_OP_SETEND:
			pj_ks (pj, "type", "setend");
			switch (op->setend) {
			case ARM_SETEND_BE:
				pj_ks (pj, "value", "be");
				break;
			case ARM_SETEND_LE:
				pj_ks (pj, "value", "le");
				break;
			default:
				pj_ks (pj, "value", "invalid");
				break;
			}
			break;
		case ARM_OP_SYSREG:
			pj_ks (pj, "type", "sysreg");
			pj_ks (pj, "value", r_str_get_fail (cs_reg_name (handle, op->reg), ""));
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		if (op->shift.type != ARM_SFT_INVALID) {
			pj_ko (pj, "shift");
			switch (op->shift.type) {
			case ARM_SFT_ASR:
			case ARM_SFT_LSL:
			case ARM_SFT_LSR:
			case ARM_SFT_ROR:
			case ARM_SFT_RRX:
				pj_ks (pj, "type", shift_type_name (op->shift.type));
				pj_kn (pj, "value", (ut64)op->shift.value);
				break;
			case ARM_SFT_ASR_REG:
			case ARM_SFT_LSL_REG:
			case ARM_SFT_LSR_REG:
			case ARM_SFT_ROR_REG:
#if CS_API_MAJOR < 6
			case ARM_SFT_RRX_REG:
				pj_ks (pj, "type", shift_type_name (op->shift.type));
				pj_ks (pj, "value", cs_reg_name (handle, op->shift.value));
				break;
#endif
			default:
				break;
			}
			pj_end (pj); /* o shift */
		}
		if (op->vector_index != -1) {
			pj_ki (pj, "vector_index", op->vector_index);
		}
		if (op->subtracted) {
			pj_kb (pj, "subtracted", true);
		}
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	if (x->usermode) {
		pj_kb (pj, "usermode", true);
	}
	if (x->update_flags) {
		pj_kb (pj, "update_flags", true);
	}
	if (ISWRITEBACK32 ()) {
		pj_kb (pj, "writeback", true);
	}
	if (x->vector_size) {
		pj_ki (pj, "vector_size", x->vector_size);
	}
	if (x->vector_data != ARM_VECTORDATA_INVALID) {
		pj_ks (pj, "vector_data", vector_data_type_name (x->vector_data));
	}
	if (x->cps_mode != ARM_CPSMODE_INVALID) {
		pj_ki (pj, "cps_mode", x->cps_mode);
	}
	if (x->cps_flag != ARM_CPSFLAG_INVALID) {
		pj_ki (pj, "cps_flag", x->cps_flag);
	}
	if ((arm_cc)x->cc != ARM_CC_INVALID && (arm_cc)x->cc != ARM_CC_AL) {
		pj_ks (pj, "cc", cc_name (x->cc));
	}
	// XXX: No ARM_MB_INVALID for cs6
	if (x->mem_barrier /* != ARM_MB_INVALID */) {
		pj_ki (pj, "mem_barrier", x->mem_barrier - 1);
	}
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

static int arm64_reg_width(int reg) {
	switch (reg) {
	case ARM64_REG_W0:
	case ARM64_REG_W1:
	case ARM64_REG_W2:
	case ARM64_REG_W3:
	case ARM64_REG_W4:
	case ARM64_REG_W5:
	case ARM64_REG_W6:
	case ARM64_REG_W7:
	case ARM64_REG_W8:
	case ARM64_REG_W9:
	case ARM64_REG_W10:
	case ARM64_REG_W11:
	case ARM64_REG_W12:
	case ARM64_REG_W13:
	case ARM64_REG_W14:
	case ARM64_REG_W15:
	case ARM64_REG_W16:
	case ARM64_REG_W17:
	case ARM64_REG_W18:
	case ARM64_REG_W19:
	case ARM64_REG_W20:
	case ARM64_REG_W21:
	case ARM64_REG_W22:
	case ARM64_REG_W23:
	case ARM64_REG_W24:
	case ARM64_REG_W25:
	case ARM64_REG_W26:
	case ARM64_REG_W27:
	case ARM64_REG_W28:
	case ARM64_REG_W29:
	case ARM64_REG_W30:
	case ARM64_REG_S0:
	case ARM64_REG_S1:
	case ARM64_REG_S2:
	case ARM64_REG_S3:
	case ARM64_REG_S4:
	case ARM64_REG_S5:
	case ARM64_REG_S6:
	case ARM64_REG_S7:
	case ARM64_REG_S8:
	case ARM64_REG_S9:
	case ARM64_REG_S10:
	case ARM64_REG_S11:
	case ARM64_REG_S12:
	case ARM64_REG_S13:
	case ARM64_REG_S14:
	case ARM64_REG_S15:
	case ARM64_REG_S16:
	case ARM64_REG_S17:
	case ARM64_REG_S18:
	case ARM64_REG_S19:
	case ARM64_REG_S20:
	case ARM64_REG_S21:
	case ARM64_REG_S22:
	case ARM64_REG_S23:
	case ARM64_REG_S24:
	case ARM64_REG_S25:
	case ARM64_REG_S26:
	case ARM64_REG_S27:
	case ARM64_REG_S28:
	case ARM64_REG_S29:
	case ARM64_REG_S30:
	case ARM64_REG_S31:
		return 32;
	default:
		break;
	}
	return 64;
}

static const char *cc_name64(arm64_cc cc) {
	switch (cc) {
	case ARM64_CC_EQ: // Equal
		return "eq";
	case ARM64_CC_NE: // Not equal:                 Not equal, or unordered
		return "ne";
	case ARM64_CC_HS: // Unsigned higher or same:   >, ==, or unordered
		return "hs";
	case ARM64_CC_LO: // Unsigned lower or same:    Less than
		return "lo";
	case ARM64_CC_MI: // Minus, negative:           Less than
		return "mi";
	case ARM64_CC_PL: // Plus, positive or zero:    >, ==, or unordered
		return "pl";
	case ARM64_CC_VS: // Overflow:                  Unordered
		return "vs";
	case ARM64_CC_VC: // No overflow:               Ordered
		return "vc";
	case ARM64_CC_HI: // Unsigned higher:           Greater than, or unordered
		return "hi";
	case ARM64_CC_LS: // Unsigned lower or same:    Less than or equal
		return "ls";
	case ARM64_CC_GE: // Greater than or equal:     Greater than or equal
		return "ge";
	case ARM64_CC_LT: // Less than:                 Less than, or unordered
		return "lt";
	case ARM64_CC_GT: // Signed greater than:       Greater than
		return "gt";
	case ARM64_CC_LE: // Signed less than or equal: <, ==, or unordered
		return "le";
	default:
		return "";
	}
}

static const char *extender_name(arm64_extender extender) {
	switch (extender) {
	case ARM64_EXT_UXTB:
		return "uxtb";
	case ARM64_EXT_UXTH:
		return "uxth";
	case ARM64_EXT_UXTW:
		return "uxtw";
	case ARM64_EXT_UXTX:
		return "uxtx";
	case ARM64_EXT_SXTB:
		return "sxtb";
	case ARM64_EXT_SXTH:
		return "sxth";
	case ARM64_EXT_SXTW:
		return "sxtw";
	case ARM64_EXT_SXTX:
		return "sxtx";
	default:
		return "";
	}
}

static const char *vas_name(arm64_vas vas) {
	switch (vas) {
	case ARM64_VAS_8B:
		return "8b";
	case ARM64_VAS_16B:
		return "16b";
	case ARM64_VAS_4H:
		return "4h";
	case ARM64_VAS_8H:
		return "8h";
	case ARM64_VAS_2S:
		return "2s";
	case ARM64_VAS_4S:
		return "4s";
	case ARM64_VAS_2D:
		return "2d";
	case ARM64_VAS_1D:
		return "1d";
	case ARM64_VAS_1Q:
		return "1q";
#if CS_API_MAJOR > 4
	case ARM64_VAS_4B:
		return "8b";
	case ARM64_VAS_2H:
		return "2h";
	case ARM64_VAS_1S:
		return "1s";
#if CS_API_MAJOR < 6
	case ARM64_VAS_1B:
		return "8b";
	case ARM64_VAS_1H:
		return "1h";
#endif
#endif
	default:
		return "";
	}
}

static int vas_size(arm64_vas vas) {
	switch (vas) {
	case ARM64_VAS_8B:
	case ARM64_VAS_16B:
		return 8;
	case ARM64_VAS_4H:
	case ARM64_VAS_8H:
		return 16;
	case ARM64_VAS_2S:
	case ARM64_VAS_4S:
		return 32;
	case ARM64_VAS_2D:
	case ARM64_VAS_1D:
		return 64;
	case ARM64_VAS_1Q:
		return 128;
#if CS_API_MAJOR > 4
	case ARM64_VAS_4B:
		return 8;
	case ARM64_VAS_2H:
		return 16;
	case ARM64_VAS_1S:
		return 32;
#if CS_API_MAJOR < 6
	case ARM64_VAS_1B:
		return 8;
	case ARM64_VAS_1H:
		return 16;
#endif
#endif
	default:
		return 64;
	}
}

static int vas_count(arm64_vas vas) {
	switch (vas) {
	case ARM64_VAS_16B:
		return 16;
	case ARM64_VAS_8B:
	case ARM64_VAS_8H:
		return 8;
	case ARM64_VAS_4S:
	case ARM64_VAS_4H:
		return 4;
	case ARM64_VAS_2D:
	case ARM64_VAS_2S:
		return 2;
	case ARM64_VAS_1D:
	case ARM64_VAS_1Q:
		return 1;
#if CS_API_MAJOR > 4
	case ARM64_VAS_4B:
		return 4;
	case ARM64_VAS_2H:
		return 2;
#if CS_API_MAJOR < 6
	case ARM64_VAS_1B:
	case ARM64_VAS_1H:
#endif
	case ARM64_VAS_1S:
		return 1;
#endif
	default:
		return 64;
	}
}

#if CS_API_MAJOR == 4
static const char *vess_name(arm64_vess vess) {
	switch (vess) {
	case ARM64_VESS_B:
		return "b";
	case ARM64_VESS_H:
		return "h";
	case ARM64_VESS_S:
		return "s";
	case ARM64_VESS_D:
		return "d";
	default:
		return "";
	}
}
#endif

#if CS_API_MAJOR == 4
static int vess_size(arm64_vess vess) {
	switch (vess) {
	case ARM64_VESS_B:
		return 8;
	case ARM64_VESS_H:
		return 16;
	case ARM64_VESS_S:
		return 32;
	case ARM64_VESS_D:
		return 64;
	default:
		return 64;
	}
}
#endif

static void opex64(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_arm64 *x = &insn->detail->arm64;
	for (i = 0; i < x->op_count; i++) {
		cs_arm64_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case ARM64_OP_REG:
			{
			pj_ks (pj, "type", "reg");
			const char *rn = cs_reg_name (handle, op->reg);
			if (rn) {
				pj_ks (pj, "value", rn);
			}
			}
			break;
		case ARM64_OP_REG_MRS:
			pj_ks (pj, "type", "reg_mrs");
			// TODO value
			break;
		case ARM64_OP_REG_MSR:
			pj_ks (pj, "type", "reg_msr");
			// TODO value
			break;
		case ARM64_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_kN (pj, "value", op->imm);
			break;
		case ARM64_OP_MEM:
			pj_ks (pj, "type", "mem");
			if ((arm64_reg) op->mem.base != ARM64_REG_INVALID) {
				pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
			}
			if ((arm64_reg) op->mem.index != ARM64_REG_INVALID) {
				pj_ks (pj, "index", cs_reg_name (handle, op->mem.index));
			}
			pj_ki (pj, "disp", op->mem.disp);
			break;
		case ARM64_OP_FP:
			pj_ks (pj, "type", "fp");
			pj_kd (pj, "value", op->fp);
			break;
		case ARM64_OP_CIMM:
			pj_ks (pj, "type", "cimm");
			pj_kN (pj, "value", op->imm);
			break;
		case ARM64_OP_PSTATE:
			pj_ks (pj, "type", "pstate");
			switch (PSTATE ()) {
			case ARM64_PSTATE_SPSEL:
				pj_ks (pj, "value", "spsel");
				break;
			case ARM64_PSTATE_DAIFSET:
				pj_ks (pj, "value", "daifset");
				break;
			case ARM64_PSTATE_DAIFCLR:
				pj_ks (pj, "value", "daifclr");
				break;
			default:
				pj_ki (pj, "value", PSTATE ());
			}
			break;
		case ARM64_OP_SYS:
			pj_ks (pj, "type", "sys");
			pj_kn (pj, "value", SYS ());
			break;
		case ARM64_OP_PREFETCH:
			pj_ks (pj, "type", "prefetch");
			pj_ki (pj, "value", PREFETCH () - 1);
			break;
		case ARM64_OP_BARRIER:
			pj_ks (pj, "type", "prefetch");
			pj_ki (pj, "value", BARRIER () - 1);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		if ((arm64_shifter)op->shift.type != ARM64_SFT_INVALID) {
			pj_ko (pj, "shift");
			switch (op->shift.type) {
			case ARM64_SFT_LSL:
				pj_ks (pj, "type", "lsl");
				break;
			case ARM64_SFT_MSL:
				pj_ks (pj, "type", "msl");
				break;
			case ARM64_SFT_LSR:
				pj_ks (pj, "type", "lsr");
				break;
			case ARM64_SFT_ASR:
				pj_ks (pj, "type", "asr");
				break;
			case ARM64_SFT_ROR:
				pj_ks (pj, "type", "ror");
				break;
			default:
				break;
			}
			pj_kn (pj, "value", (ut64)op->shift.value);
			pj_end (pj);
		}
		if ((arm64_extender) op->ext != ARM64_EXT_INVALID) {
			pj_ks (pj, "ext", extender_name (op->ext));
		}
		if (op->vector_index != -1) {
			pj_ki (pj, "vector_index", op->vector_index);
		}
		if ((arm64_vas)op->vas != ARM64_VAS_INVALID) {
			pj_ks (pj, "vas", vas_name (op->vas));
		}
#if CS_API_MAJOR == 4
		if (op->vess != ARM64_VESS_INVALID) {
			pj_ks (pj, "vess", vess_name (op->vess));
		}
#endif
		pj_end (pj);
	}
	pj_end (pj);
	if (x->update_flags) {
		pj_kb (pj, "update_flags", true);
	}
	if (ISWRITEBACK32 ()) {
		pj_kb (pj, "writeback", true);
	}
	if ((arm64_cc)x->cc != ARM64_CC_INVALID && (arm64_cc)x->cc != ARM64_CC_AL && (arm64_cc)x->cc != ARM64_CC_NV) {
		pj_ks (pj, "cc", cc_name64 (x->cc));
	}
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

static int decode_sign_ext(arm64_extender extender) {
	switch (extender) {
	case ARM64_EXT_UXTB:
	case ARM64_EXT_UXTH:
	case ARM64_EXT_UXTW:
	case ARM64_EXT_UXTX:
		return 0; // nothing needs to be done for unsigned
	case ARM64_EXT_SXTB:
		return 8;
	case ARM64_EXT_SXTH:
		return 16;
	case ARM64_EXT_SXTW:
		return 32;
	case ARM64_EXT_SXTX:
		return 64;
	default:
		break;
	}

	return 0;
}

static const char *E_OP_SR = ">>";
static const char *E_OP_SL = "<<";
static const char *E_OP_RR = ">>>";
static const char *E_OP_ASR = ">>>>";
static const char *E_OP_AR = ">>>>";
static const char *E_OP_VOID = "";

static const char *decode_shift(arm_shifter shift) {
	switch (shift) {
	case ARM_SFT_ASR:
	case ARM_SFT_ASR_REG:
		return E_OP_ASR;
	case ARM_SFT_LSR:
	case ARM_SFT_LSR_REG:
		return E_OP_SR;
	case ARM_SFT_LSL:
	case ARM_SFT_LSL_REG:
		return E_OP_SL;
	case ARM_SFT_ROR:
	case ARM_SFT_RRX:
	case ARM_SFT_ROR_REG:
#if CS_API_MAJOR < 6
	case ARM_SFT_RRX_REG:
		return E_OP_RR;
#endif
	default:
		break;
	}
	return E_OP_VOID;
}

static const char *decode_shift_64(arm64_shifter shift) {
	switch (shift) {
	case ARM64_SFT_ASR:
		return E_OP_AR;
	case ARM64_SFT_LSR:
		return E_OP_SR;
	case ARM64_SFT_LSL:
	case ARM64_SFT_MSL:
		return E_OP_SL;
	case ARM64_SFT_ROR:
		return E_OP_RR;
	default:
		break;
	}
	return E_OP_VOID;
}

#define DECODE_SHIFT(x) decode_shift(insn->detail->arm.operands[x].shift.type)
#define DECODE_SHIFT64(x) decode_shift_64(insn->detail->arm64.operands[x].shift.type)

static unsigned int regsize32(cs_insn *insn, int n) {
	R_RETURN_VAL_IF_FAIL (n >= 0 && n < insn->detail->arm.op_count, 0);
	unsigned int reg = insn->detail->arm.operands[n].reg;
	if (reg >= ARM_REG_D0 && reg <= ARM_REG_D31) {
		return 8;
	}
	if (reg >= ARM_REG_Q0 && reg <= ARM_REG_Q15) {
		return 16;
	}
	return 4; // s0-s31, r0-r15
}

static int regsize64(cs_insn *insn, int n) {
	unsigned int reg = insn->detail->arm64.operands[n].reg;
	if ((reg >= ARM64_REG_S0 && reg <= ARM64_REG_S31) ||
		(reg >= ARM64_REG_W0 && reg <= ARM64_REG_W30) ||
		reg == ARM64_REG_WZR) {
		return 4;
	}
	if (reg >= ARM64_REG_B0 && reg <= ARM64_REG_B31) {
		return 1;
	}
	if (reg >= ARM64_REG_H0 && reg <= ARM64_REG_H31) {
		return 2;
	}
	if ((reg >= ARM64_REG_Q0 && reg <= ARM64_REG_Q31) ||
#if CS_API_MAJOR < 6
		(reg >= ARM64_REG_V0 && reg <= ARM64_REG_V31) ) {
#else
		(false) ) {
#endif
		return 16;
	}
	return 8;
}

#define REGSIZE64(x) regsize64 (insn, x)
#define REGSIZE32(x) regsize32 (insn, x)
#define REGBITS64(x) (8 * regsize64 (insn, x))
#define REGBITS32(x) (8 * regsize32 (insn, x))

#define SET_FLAGS() r_strbuf_appendf (&op->esil, ",$z,zf,:=,%d,$s,nf,:=,%d,$c,cf,:=,%d,$o,vf,:=", REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) -1);

static int vector_size(cs_arm64_op *op) {
#if CS_API_MAJOR == 4
	if (op->vess) {
		return vess_size (op->vess);
	}
#endif
	if (op->vas) {
		return vas_size (op->vas);
	}
	return 64;
}

// return postfix
const char* arm_prefix_cond(RAnalOp *op, int cond_type) {
	const char *close_cond[2];
	close_cond[0] = "\0";
	close_cond[1] = ",}\0";
	int close_type = 0;
	switch (cond_type) {
	case ARM_CC_EQ:
		close_type = 1;
		r_strbuf_append (&op->esil, "zf,?{,");
		break;
	case ARM_CC_NE:
		close_type = 1;
		r_strbuf_append (&op->esil, "zf,!,?{,");
		break;
	case ARM_CC_HS:
		close_type = 1;
		r_strbuf_append (&op->esil, "cf,?{,");
		break;
	case ARM_CC_LO:
		close_type = 1;
		r_strbuf_append (&op->esil, "cf,!,?{,");
		break;
	case ARM_CC_MI:
		close_type = 1;
		r_strbuf_append (&op->esil, "nf,?{,");
		break;
	case ARM_CC_PL:
		close_type = 1;
		r_strbuf_append (&op->esil, "nf,!,?{,");
		break;
	case ARM_CC_VS:
		close_type = 1;
		r_strbuf_append (&op->esil, "vf,?{,");
		break;
	case ARM_CC_VC:
		close_type = 1;
		r_strbuf_append (&op->esil, "vf,!,?{,");
		break;
	case ARM_CC_HI:
		close_type = 1;
		r_strbuf_append (&op->esil, "cf,zf,!,&,?{,");
		break;
	case ARM_CC_LS:
		close_type = 1;
		r_strbuf_append (&op->esil, "cf,!,zf,|,?{,");
		break;
	case ARM_CC_GE:
		close_type = 1;
		r_strbuf_append (&op->esil, "nf,vf,^,!,?{,");
		break;
	case ARM_CC_LT:
		close_type = 1;
		r_strbuf_append (&op->esil, "nf,vf,^,?{,");
		break;
	case ARM_CC_GT:
		// zf == 0 && nf == vf
		close_type = 1;
		r_strbuf_append (&op->esil, "zf,!,nf,vf,^,!,&,?{,");
		break;
	case ARM_CC_LE:
		// zf == 1 || nf != vf
		close_type = 1;
		r_strbuf_append (&op->esil, "zf,nf,vf,^,|,?{,");
		break;
	case ARM_CC_AL:
		// always executed
		break;
	default:
		break;
	}
	return close_cond[close_type];
}

/* arm64 */

static const char *arg(RArchSession *as, csh *handle, cs_insn *insn, char *buf, size_t buf_sz, int n) {
	buf[0] = 0;
	switch (insn->detail->arm.operands[n].type) {
	case ARM_OP_REG:
		if (ISSHIFTED (n)) {
			if (SHIFTTYPEREG (n)) {
				snprintf (buf, buf_sz, "%s,%s,%s",
						cs_reg_name(*handle, LSHIFT2(n)),
						REG (n), DECODE_SHIFT (n));
			} else {
				snprintf (buf, buf_sz, "%u,%s,%s",
						LSHIFT2 (n),
						REG (n), DECODE_SHIFT (n));
			}
		} else {
			snprintf (buf, buf_sz, "%s",
			r_str_getf (cs_reg_name (*handle,
				insn->detail->arm.operands[n].reg)));
		}
		break;
	case ARM_OP_IMM:
		if (as->config->bits == 64) {
			// 64bit only
			snprintf (buf, buf_sz, "%"PFMT64d, (ut64)
					insn->detail->arm.operands[n].imm);
		} else {
			// 32bit only
			snprintf (buf, buf_sz, "%"PFMT64d, (ut64)(ut32)
					insn->detail->arm.operands[n].imm);
		}
		break;
	case ARM_OP_MEM:
		break;
	case ARM_OP_FP:
		snprintf (buf, buf_sz, "%lf", insn->detail->arm.operands[n].fp);
		break;
	default:
		break;
	}
	return buf;
}

#define ARG(x) arg(as, handle, insn, str[x], sizeof (str[x]), x)

#define VEC64(n) insn->detail->arm64.operands[n].vess
#define VEC64_APPEND(sb, n, i) vector64_append(sb, handle, insn, n, i)
#define VEC64_MASK(sh, sz) (bitmask_by_width[63]^(bitmask_by_width[sz>0?sz-1:0]<<sh))

static void vector64_append(RStrBuf *sb, csh *handle, cs_insn *insn, int n, int i) {
	cs_arm64_op op = INSOP64 (n);
	if (op.vector_index != -1) {
		i = op.vector_index;
	}
#if CS_API_MAJOR == 4
	const bool isvessas = (op.vess || op.vas);
#else
	const bool isvessas = op.vas;
#endif
	if (isvessas && i != -1) {
		int size = vector_size (&op);
		int shift = i * size;
		char *regc = "l";
		if (shift >= 64) {
			shift -= 64;
			regc = "h";
		}

		size_t s = sizeof (bitmask_by_width) / sizeof (*bitmask_by_width);
		int width = size > 0? (size - 1) % s: 0;
		if (shift > 0) {
			r_strbuf_appendf (sb, "0x%"PFMT64x",%d,%s%s,>>,&",
				bitmask_by_width[width], shift, REG64 (n), regc);
		} else {
			r_strbuf_appendf (sb, "0x%"PFMT64x",%s%s,&",
				bitmask_by_width[width], REG64 (n), regc);
		}
	} else {
		r_strbuf_appendf (sb, "%s", REG64 (n));
	}
}

#define VEC64_DST_APPEND(sb, n, i) vector64_dst_append(sb, handle, insn, n, i)

static void vector64_dst_append(RStrBuf *sb, csh *handle, cs_insn *insn, int n, int i) {
	cs_arm64_op op = INSOP64 (n);

	if (op.vector_index != -1) {
		i = op.vector_index;
	}
#if CS_API_MAJOR == 4
	const bool isvessas = (op.vess || op.vas);
#else
	const bool isvessas = op.vas;
#endif
	if (isvessas && i != -1) {
		int size = vector_size (&op);
		int shift = i * size;
		char *regc = "l";
		size_t s = sizeof (bitmask_by_width) / sizeof (*bitmask_by_width);
		size_t index = size > 0? (size - 1) % s: 0;
		if (index >= BITMASK_BY_WIDTH_COUNT) {
			index = 0;
		}
		ut64 mask = bitmask_by_width[index];
		if (shift >= 64) {
			shift -= 64;
			regc = "h";
		}
		if (shift > 0 && shift < 64) {
			r_strbuf_appendf (sb, "%d,SWAP,0x%"PFMT64x",&,<<,%s%s,0x%"PFMT64x",&,|,%s%s",
				shift, mask, REG64 (n), regc, VEC64_MASK (shift, size), REG64 (n), regc);
		} else {
			int dimsize = size % 64;
			r_strbuf_appendf (sb, "0x%"PFMT64x",&,%s%s,0x%"PFMT64x",&,|,%s%s",
				mask, REG64 (n), regc, VEC64_MASK (shift, dimsize), REG64 (n), regc);
		}
	} else {
		r_strbuf_append (sb, REG64 (n));
	}
}

#define SHIFTED_IMM64(n, sz) shifted_imm64(handle, insn, n, sz)

static ut64 shifted_imm64(csh *handle, cs_insn *insn, int n, int sz) {
	cs_arm64_op op = INSOP64 (n);
	int sft = op.shift.value;
	switch (op.shift.type) {
	case ARM64_SFT_MSL:
		return (IMM64 (n) << sft) | ((1 << sft) - 1);
	case ARM64_SFT_LSL:
		return IMM64 (n) << sft;
	case ARM64_SFT_LSR:
		return IMM64 (n) >> sft;
	case ARM64_SFT_ROR:
		return (IMM64 (n) >> sft)|(IMM64 (n) << (sz - sft));
	case ARM64_SFT_ASR:
		switch (sz) {
		case 8: return (st8)IMM64 (n) >> sft;
		case 16: return (st16)IMM64 (n) >> sft;
		case 32: return (st32)IMM64 (n) >> sft;
		default: return (st64)IMM64 (n) >> sft;
		}
	default:
		return IMM64 (n);
	}
}

#define ARG64_APPEND(sb, n) arg64_append (sb, handle, insn, n, -1, 0)
#define ARG64_SIGN_APPEND(sb, n, s) arg64_append (sb, handle, insn, n, -1, s)
#define VECARG64_APPEND(sb, n, i, s) arg64_append (sb, handle, insn, n, i, s)
#define COMMA(sb) r_strbuf_append (sb, ",")

static void arg64_append(RStrBuf *sb, csh *handle, cs_insn *insn, int n, int i, int sign) {
	cs_arm64_op op = INSOP64 (n);

	int size = 64;
	if (ISREG64 (n)) {
		size = REGSIZE64 (n) * 8;
	}

	if (ISIMM64 (n)) {
		if (!ISSHIFTED64 (n)) {
			ut64 imm = SHIFTED_IMM64 (n, size);
			r_strbuf_appendf (sb, "0x%"PFMT64x, imm);
			return;
		}
	}
	const char *rn = (ISMEM64 (n) && HASMEMINDEX64 (n))
		? MEMINDEX64 (n): REG64 (n);
	int shift = LSHIFT2_64 (n);
	int signext = EXT64 (n);
	if (sign && !signext) {
		signext = size;
	}
	if (signext) {
		r_strbuf_appendf (sb, "%d,", signext);
	}
	if (shift) {
		r_strbuf_appendf (sb, "%d,", shift);
	}

#if CS_API_MAJOR == 4
	const bool isvessas = (op.vess || op.vas);
#else
	const bool isvessas = op.vas;
#endif
	if (isvessas) {
		VEC64_APPEND (sb, n, i);
	} else {
		if (n > 0 && ISIMM64 (n) && !ISMEM64 (n)) {
			r_strbuf_appendf (sb, "%d", (int)IMM64 (n));
		} else {
			r_strbuf_append (sb, rn);
		}
	}

	if (shift) {
		r_strbuf_appendf (sb, ",%s", DECODE_SHIFT64 (n));
	}
	if (signext) {
		r_strbuf_append (sb, ",~");
	}
}

#define OPCALL(opchar) arm64math(as, op, addr, buf, len, handle, insn, opchar, 0, 0)
#define OPCALL_NEG(opchar) arm64math(as, op, addr, buf, len, handle, insn, opchar, 1, 0)
#define OPCALL_SIGN(opchar, sign) arm64math(as, op, addr, buf, len, handle, insn, opchar, 0, sign)

static void arm64math(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, const char *opchar, int negate, int sign) {
	cs_arm64_op dst = INSOP64 (0);
	int i, c = (OPCOUNT64 () > 2) ? 1 : 0;

	if (dst.vas) {
		int end = vas_count (dst.vas);
		for (i = 0; i < end; i++) {
			VECARG64_APPEND (&op->esil, 2, i, sign);
			if (negate) {
				r_strbuf_append (&op->esil, ",-1,^");
			}
			COMMA (&op->esil);
			VECARG64_APPEND (&op->esil, 1, i, sign);
			r_strbuf_appendf (&op->esil, ",%s,", opchar);
			VEC64_DST_APPEND (&op->esil, 0, i);
			r_strbuf_append (&op->esil, ",=");
			if (i < end - 1) {
				COMMA (&op->esil);
			}
		}
	} else {
		VECARG64_APPEND (&op->esil, c + 1, -1, sign);
		if (negate) {
			r_strbuf_append (&op->esil, ",-1,^");
		}
		COMMA (&op->esil);
		VECARG64_APPEND (&op->esil, c, -1, sign);
		r_strbuf_appendf (&op->esil, ",%s,", opchar);
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
	}
}

#define FPOPCALL(opchar) arm64fpmath(as, op, addr, buf, len, handle, insn, opchar, 0)
#define FPOPCALL_NEGATE(opchar) arm64fpmath(as, op, addr, buf, len, handle, insn, opchar, 1)

// floating point math instruction helper
static void arm64fpmath(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, const char *opchar, int negate) {
	int i, size = REGSIZE64 (1)*8;

	cs_arm64_op dst = INSOP64 (0);
	int start = -1;
	int end = 0;
	int convert = size == 64 ? 0 : 1;
	if (dst.vas) {
		start = 0;
		end = vas_count(dst.vas);
	}

	for (i = start; i < end; i++) {
		if (convert) {
			r_strbuf_appendf (&op->esil, "%d,DUP,", size);
		}
		VEC64_APPEND (&op->esil, 2, i);
		if (convert) {
			r_strbuf_append (&op->esil, ",F2D");
		}
		if (negate) {
			r_strbuf_append (&op->esil, ",-F");
		}
		if (convert) {
			r_strbuf_appendf (&op->esil, ",%d", size);
		}
		COMMA (&op->esil);
		VEC64_APPEND (&op->esil, 1, i);
		if (convert) {
			r_strbuf_appendf (&op->esil, ",F2D,F%s,D2F,", opchar);
		} else {
			r_strbuf_appendf (&op->esil, ",F%s,", opchar);
		}
		VEC64_DST_APPEND (&op->esil, 0, i);
		r_strbuf_append (&op->esil, ",=");
		if (i < end - 1) {
			COMMA (&op->esil);
		}
	}
}

static int analop64_esil(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn) {
	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");

	const char *postfix = arm_prefix_cond (op, insn->detail->arm64.cc);

	switch (insn->id) {
	case ARM64_INS_BRK:
		r_strbuf_setf (&op->esil, "0,%d,TRAP", (int) (IMM64 (0) & 0xffff));
		break;
	case ARM64_INS_REV:
	case ARM64_INS_REV64:
	// these REV* instructions were almost right, except in the cases like rev x0, x0
	// where the use of |= caused copies of the value to be erroneously present
	{
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		int size = REGSIZE64 (1);
		if (size == 8) {
			r_strbuf_setf (&op->esil,
				"56,0xff,%s,&,<<,tmp,=,"
				"48,0xff,8,%s,>>,&,<<,tmp,|=,"
				"40,0xff,16,%s,>>,&,<<,tmp,|=,"
				"32,0xff,24,%s,>>,&,<<,tmp,|=,"
				"24,0xff,32,%s,>>,&,<<,tmp,|=,"
				"16,0xff,40,%s,>>,&,<<,tmp,|=,"
				"8,0xff,48,%s,>>,&,<<,tmp,|=,"
				"0xff,56,%s,>>,&,tmp,|=,tmp,%s,=",
				r1, r1, r1, r1,
				r1, r1, r1, r1, r0);
		} else {
			r_strbuf_setf (&op->esil,
				"24,0xff,%s,&,<<,tmp,=,"
				"16,0xff,8,%s,>>,&,<<,tmp,|=,"
				"8,0xff,16,%s,>>,&,<<,tmp,|=,"
				"0xff,24,%s,>>,&,tmp,|=,tmp,%s,=",
				r1, r1, r1, r1, r0);
		}
		break;
	}
	case ARM64_INS_REV32:
		r_strbuf_setf (&op->esil,
			"24,0x000000ff000000ff,%s,&,<<,tmp,=,"
			"16,0x000000ff000000ff,8,%s,>>,&,<<,tmp,|=,"
			"8,0x000000ff000000ff,16,%s,>>,&,<<,tmp,|=,"
			"0x000000ff000000ff,24,%s,>>,&,tmp,|=,tmp,%s,=",
			REG64 (1), REG64 (1), REG64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_REV16:
		r_strbuf_setf (&op->esil,
			"8,0xff00ff00ff00ff00,%s,&,>>,tmp,=,"
			"8,0x00ff00ff00ff00ff,%s,&,<<,tmp,|=,tmp,%s,=",
			REG64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_ADR:
		// TODO: must be 21bit signed
		r_strbuf_setf (&op->esil,
			"%"PFMT64d",%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_SMADDL:
		r_strbuf_setf (&op->esil, "%d,%s,~,%d,%s,~,*,%s,+,%s,=",
			REGBITS64 (1), REG64 (2), REGBITS64 (1), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_UMADDL:
	case ARM64_INS_MADD:
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,+,%s,=",
			REG64 (2), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_MSUB:
		r_strbuf_setf (&op->esil, "%s,%s,*,%s,-,%s,=",
			REG64 (2), REG64 (1), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_MNEG:
		r_strbuf_setf (&op->esil, "%s,%s,*,0,-,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_ADDG:
#endif
	case ARM64_INS_ADD:
	case ARM64_INS_ADC: // Add with carry.
		OPCALL ("+");
		break;
	case ARM64_INS_SUB:
		OPCALL ("-");
		break;
	case ARM64_INS_SBC:
		// TODO have to check this more, VEX does not work
		r_strbuf_setf (&op->esil, "%s,cf,+,%s,-,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_SMULL2:
	case ARM64_INS_SMULL:
		OPCALL_SIGN ("*", REGBITS64 (1));
		break;
	case ARM64_INS_UMULL2:
	case ARM64_INS_UMULL:
	case ARM64_INS_MUL:
		OPCALL ("*");
		break;
	case ARM64_INS_UMULH:
		r_strbuf_setf (&op->esil, "%s,%s,L*,SWAP,%s,=",
			REG64 (2), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_SMULH:
		// TODO this needs to be a 128 bit sign ext to be right
		r_strbuf_setf (&op->esil, "%d,%s,~,%d,%s,~,L*,SWAP,%s,=",
			REGBITS64 (1), REG64 (2), REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_AND:
		OPCALL ("&");
		break;
	case ARM64_INS_ORR:
		OPCALL ("|");
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_NAND:
		OPCALL_NEG ("&");
		break;
	case ARM64_INS_ADDS:
	case ARM64_INS_ADCS:
		OPCALL ("+");
		SET_FLAGS();
		break;
	case ARM64_INS_SUBS:
		OPCALL ("-");
		SET_FLAGS();
		break;
	case ARM64_INS_ANDS:
		OPCALL ("&");
		SET_FLAGS();
		break;
	case ARM64_INS_NANDS:
		OPCALL_NEG ("&");
		SET_FLAGS();
		break;
	case ARM64_INS_ORRS:
		OPCALL ("|");
		SET_FLAGS();
		break;
	case ARM64_INS_EORS:
		OPCALL ("^");
		SET_FLAGS();
		break;
	case ARM64_INS_ORNS:
		OPCALL_NEG ("|");
		SET_FLAGS();
		break;
#endif
	case ARM64_INS_EOR:
		OPCALL ("^");
		break;
	case ARM64_INS_ORN:
		OPCALL_NEG ("|");
		break;
	case ARM64_INS_EON:
		OPCALL_NEG ("^");
		break;
	case ARM64_INS_LSR:
	{
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64(2)) {
			if (LSHIFT2_64 (2) || EXT64 (2)) {
				ARG64_APPEND (&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64d",%s,>>,%s,=", i2 % (ut64)size, r1, r0);
		}
		//OPCALL (">>");
		break;
	}
	case ARM64_INS_LSL:
	{
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64 (2)) {
			if (LSHIFT2_64 (2) || EXT64 (2)) {
				ARG64_APPEND (&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,<<,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,<<,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64d",%s,<<,%s,=", i2 % (ut64)size, r1, r0);
		}
		//OPCALL ("<<");
		break;
	}
	case ARM64_INS_ROR:
		OPCALL (">>>");
		break;
	case ARM64_INS_NOP:
		r_strbuf_set (&op->esil, ",");
		break;
	case ARM64_INS_MOV:
	case ARM64_INS_FMOV:
	{
		cs_arm64_op dst = INSOP64 (0);
		cs_arm64_op src = INSOP64 (1);

		if (dst.vas && src.vas) {
			r_strbuf_setf (&op->esil, "%sh,%sh,=,%sl,%sl,=",
				REG64 (1), REG64 (0), REG64 (1), REG64 (0));
		} else {
			ARG64_APPEND (&op->esil, 1);
			r_strbuf_append (&op->esil, ",");
			VEC64_DST_APPEND (&op->esil, 0, -1);
			r_strbuf_append (&op->esil, ",=");
		}
		break;
	}
	case ARM64_INS_FCMP:
	case ARM64_INS_FCMPE:
	case ARM64_INS_FCCMP:
	case ARM64_INS_FCCMPE:
		if (ISREG64 (1)) {
			r_strbuf_setf (&op->esil,
				"%d,%s,F2D,NAN,%d,%s,F2D,NAN,|,vf,:="
				",%d,%s,F2D,%d,%s,F2D,F==,vf,|,zf,:="
				",%d,%s,F2D,%d,%s,F2D,F<,vf,|,nf,:=",
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (1), REGBITS64 (1), REG64 (0)
			);
		} else {
			r_strbuf_setf (&op->esil,
				"%d,%s,F2D,NAN,vf,:="
				",0,I2D,%d,%s,F2D,F==,vf,|,zf,:="
				",0,I2D,%d,%s,F2D,F<,vf,|,nf,:=",
				REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (0),
				REGBITS64 (1), REG64 (0)
			);
		}

		if (insn->id == ARM64_INS_FCCMP || insn->id == ARM64_INS_FCCMPE) {
			r_strbuf_append (&op->esil, ",");
			arm_prefix_cond (op, insn->detail->arm64.cc);
			r_strbuf_appendf (&op->esil, "}{,pstate,1,28,1,<<,-,&,0x%"PFMT64x",|,pstate,:=", IMM64(2) << 28);
		}
		break;
	case ARM64_INS_FCVT:
		r_strbuf_setf (&op->esil, "%d,%d,%s,F2D,D2F,%s,=",
			REGBITS64 (0), REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_SCVTF:
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (0));
		ARG64_SIGN_APPEND (&op->esil, 1, REGBITS64 (1));
		r_strbuf_append (&op->esil, ",I2D,D2F,");
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
		break;
	case ARM64_INS_UCVTF:
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (0));
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_append (&op->esil, ",U2D,D2F,");
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
		break;
	case ARM64_INS_FCVTAU:
	case ARM64_INS_FCVTAS:
	case ARM64_INS_FCVTMU:
	case ARM64_INS_FCVTMS:
	case ARM64_INS_FCVTNU:
	case ARM64_INS_FCVTNS:
	case ARM64_INS_FCVTPU:
	case ARM64_INS_FCVTPS:
	case ARM64_INS_FCVTZU:
	case ARM64_INS_FCVTZS:
		// TODO: unsigned int won't be right, idk entirely what it even means
		// also the rounding mode... idk i hate floats
		r_strbuf_setf (&op->esil, "%d,", REGBITS64 (1));
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_append (&op->esil, ",F2D,D2I,");
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
		break;
	case ARM64_INS_FRINTA:
	case ARM64_INS_FRINTI:
	case ARM64_INS_FRINTN:
	case ARM64_INS_FRINTX:
	case ARM64_INS_FRINTZ:
	case ARM64_INS_FRINTP:
	case ARM64_INS_FRINTM:
	{
		char* rounder = "ROUND";
		if (insn->id == ARM64_INS_FRINTM) {
			rounder = "FLOOR";
		} else if (insn->id == ARM64_INS_FRINTP) {
			rounder = "CEIL";
		}
		r_strbuf_setf (&op->esil, "%d,DUP,", REGBITS64 (1));
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",F2D,%s,D2F,", rounder);
		VEC64_DST_APPEND (&op->esil, 0, -1);
		r_strbuf_append (&op->esil, ",=");
		break;
	}
	case ARM64_INS_FABS:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,DUP,0,I2D,F<,?{,-F,},D2F,%s,=",
			REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_FNEG:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_FMIN:
		r_strbuf_setf (&op->esil, "%d,%s,F2D,%d,%s,F2D,F<,?{,%s,}{,%s,},%s,=",
			REGBITS64 (2), REG64 (2),
			REGBITS64 (1), REG64 (1), REG64 (1), REG64 (2), REG64 (0));
		break;
	case ARM64_INS_FMAX:
		r_strbuf_setf (&op->esil, "%d,%s,F2D,%d,%s,F2D,F<,!,?{,%s,}{,%s,},%s,=",
			REGBITS64 (2), REG64 (2),
			REGBITS64 (1), REG64 (1), REG64 (1), REG64 (2), REG64 (0));
		break;
	case ARM64_INS_FADD:
		FPOPCALL ("+");
		break;
	case ARM64_INS_FSUB:
		FPOPCALL ("-");
		break;
	case ARM64_INS_FMUL:
		FPOPCALL ("*");
		break;
	case ARM64_INS_FNMUL:
		FPOPCALL_NEGATE ("*");
		break;
	case ARM64_INS_FMADD:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,%d,%s,F2D,F+,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_FNMADD:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,-F,%d,%s,F2D,F+,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_FMSUB:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,%d,%s,F2D,F-,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_FNMSUB:
		r_strbuf_setf (&op->esil, "%d,DUP,%s,F2D,%d,%s,F2D,F*,-F,%d,%s,F2D,F-,-F,D2F,%s,=",
			REGBITS64 (1), REG64 (1),
			REGBITS64 (2), REG64 (2),
			REGBITS64 (3), REG64 (3), REG64 (0));
		break;
	case ARM64_INS_FDIV:
		FPOPCALL ("/");
		break;
	case ARM64_INS_SDIV:
		r_strbuf_setf (&op->esil, "%s,!,?{,0,%s,=,}{,", REG64 (2), REG64 (0));
		OPCALL_SIGN ("~/", REGBITS64 (1));
		r_strbuf_append (&op->esil, ",}");
		break;
	case ARM64_INS_UDIV:
		/* TODO: support WZR XZR to specify 32, 64bit op */
		// arm64 does not have a div-by-zero exception, just quietly sets R0 to 0
		r_strbuf_setf (&op->esil, "%s,!,?{,0,%s,=,}{,", REG64 (2), REG64 (0));
		OPCALL("/");
		r_strbuf_append (&op->esil, ",}");
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_BRAA:
	case ARM64_INS_BRAAZ:
	case ARM64_INS_BRAB:
	case ARM64_INS_BRABZ:
		r_strbuf_setf (&op->esil, "%s,pc,+,%s,+,pc,:=", REG64 (0), REG64(1));
		break;
#endif
	case ARM64_INS_BR:
		r_strbuf_setf (&op->esil, "%s,pc,:=", REG64 (0));
		break;
	case ARM64_INS_B:
		/* capstone precompute resulting address, using PC + IMM */
		r_strbuf_appendf (&op->esil, "%"PFMT64d",pc,:=", IMM64 (0));
		break;
	case ARM64_INS_BL:
		r_strbuf_setf (&op->esil, "pc,lr,:=,%"PFMT64d",pc,:=", IMM64 (0));
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_BLRAA:
	case ARM64_INS_BLRAAZ:
	case ARM64_INS_BLRAB:
	case ARM64_INS_BLRABZ:
#endif
	case ARM64_INS_BLR:
		r_strbuf_setf (&op->esil, "pc,lr,:=,%s,pc,:=", REG64 (0));
		break;
	case ARM64_INS_CLZ:
	{
		/*
		from https://en.wikipedia.org/wiki/Find_first_set modified for up to size 64
		function clz3 (x)
			if x = 0 return 32
			n ← 0
			if (x & 0xFFFF0000) = 0: n ← n + 16, x ← x << 16
			if (x & 0xFF000000) = 0: n ← n +  8, x ← x <<  8
			if (x & 0xF0000000) = 0: n ← n +  4, x ← x <<  4
			if (x & 0xC0000000) = 0: n ← n +  2, x ← x <<  2
			if (x & 0x80000000) = 0: n ← n +  1
			return n
		*/

		int size = 8 * REGSIZE64 (0);
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);

		if (size == 32) {
			r_strbuf_setf (&op->esil,
			"%s,tmp,=,0,"
			"tmp,0xffff0000,&,!,?{,16,tmp,<<=,16,+,},"
			"tmp,0xff000000,&,!,?{,8,tmp,<<=,8,+,},"
			"tmp,0xf0000000,&,!,?{,4,tmp,<<=,4,+,},"
			"tmp,0xc0000000,&,!,?{,2,tmp,<<=,2,+,},"
			"tmp,0x80000000,&,!,?{,1,+,},"
			"%s,!,?{,32,%s,=,}{,%s,=,}",
			r1, r1, r0, r0);
		} else {
			r_strbuf_setf (&op->esil,
			"%s,tmp,=,0,"
			"tmp,0xffffffff00000000,&,!,?{,32,tmp,<<=,32,+,},"
			"tmp,0xffff000000000000,&,!,?{,16,tmp,<<=,16,+,},"
			"tmp,0xff00000000000000,&,!,?{,8,tmp,<<=,8,+,},"
			"tmp,0xf000000000000000,&,!,?{,4,tmp,<<=,4,+,},"
			"tmp,0xc000000000000000,&,!,?{,2,tmp,<<=,2,+,},"
			"tmp,0x8000000000000000,&,!,?{,1,+,},"
			"%s,!,?{,64,%s,=,}{,%s,=,}",
			r1, r1, r0, r0);
		}
		break;
	}
	case ARM64_INS_LDRH:
	case ARM64_INS_LDUR:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDURH:
	case ARM64_INS_LDR:
	case ARM64_INS_LDRB:
	case ARM64_INS_LDXR:
	case ARM64_INS_LDXRB:
	case ARM64_INS_LDXRH:
	case ARM64_INS_LDAXR:
	case ARM64_INS_LDAXRB:
	case ARM64_INS_LDAXRH:
	case ARM64_INS_LDAR:
	case ARM64_INS_LDARB:
	case ARM64_INS_LDARH:
	{
		int size = REGSIZE64 (0);
		switch (insn->id) {
		case ARM64_INS_LDRB:
		case ARM64_INS_LDARB:
		case ARM64_INS_LDAXRB:
		case ARM64_INS_LDXRB:
		case ARM64_INS_LDURB:
			size = 1;
			break;
		case ARM64_INS_LDRH:
		case ARM64_INS_LDARH:
		case ARM64_INS_LDXRH:
		case ARM64_INS_LDAXRH:
		case ARM64_INS_LDURH:
			size = 2;
			break;
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
			size = 4;
			break;
		default:
			break;
		}
		op->ptrsize = size;
		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				if (LSHIFT2_64 (1) || EXT64 (1)) {
					ARG64_APPEND (&op->esil, 1);
					r_strbuf_appendf (&op->esil, ",%s,+,[%d],%s,=",
							MEMBASE64 (1), size, REG64 (0));
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,+,[%d],%s,=",
							MEMBASE64 (1), MEMINDEX64 (1), size, REG64 (0));
				}
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%s,%d,%"PFMT64d",%s,+",
							MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%"PFMT64d",%s,-",
							-(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%"PFMT64d",%s,+",
							MEMDISP64 (1), MEMBASE64 (1));
				}
				r_strbuf_append (&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64 ()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",[%d],%s,=", size, REG64 (0));

				if (ISPOSTINDEX64 ()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64d",+,%s,=", IMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%s,[%d],%s,=",
						REG64 (1), size, REG64 (0));
				} else if (OPCOUNT64 () == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.
					*/
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%s,%s,+,[%d],%s,=",
							REG64 (1), REG64 (2), size, REG64 (0));
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%"PFMT64d",[%d],%s,=",
					IMM64 (1), size, REG64 (0));
			}
		}
		break;
	}
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRSH:
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDURSB:
	case ARM64_INS_LDURSH:
	case ARM64_INS_LDURSW:
	{
		// handle the sign extended instrs here
		int size = 0;
		switch (insn->id) {
		case ARM64_INS_LDRSB:
		case ARM64_INS_LDURSB:
			size = 1;
			break;
		case ARM64_INS_LDRSH:
		case ARM64_INS_LDURSH:
			size = 2;
			break;
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDURSW:
			size = 4;
			break;
		default:
			size = REGSIZE64 (0);
			break;
		}
		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				if (LSHIFT2_64 (1) || EXT64 (1)) {
					r_strbuf_appendf (&op->esil, "%d,%s,", size*8, MEMBASE64 (1));
					ARG64_APPEND (&op->esil, 1);
					r_strbuf_appendf (&op->esil, ",+,[%d],~,%s,=", size, REG64 (0));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%s,%s,+,[%d],~,%s,=",
							size*8, MEMBASE64 (1), MEMINDEX64 (1), size, REG64 (0));
				}
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%d,%s,%d,%"PFMT64d",%s",
							size*8, MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%d,%"PFMT64d",%s,-",
							size*8, -(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%"PFMT64d",%s,+",
							size*8, MEMDISP64 (1), MEMBASE64 (1));
				}

				r_strbuf_append (&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64 ()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",[%d],~,%s,=", size, REG64 (0));

				if (ISPOSTINDEX64 ()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64d",+,%s,=", IMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%d,%s,[%d],~,%s,=",
						size * 8, REG64 (1), size, REG64 (0));
				} else if (OPCOUNT64 () == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.
					*/
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%d,%s,%s,+,[%d],~,%s,=",
							size * 8, REG64 (1), REG64 (2), size, REG64 (0));
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%d,%"PFMT64d",[%d],~,%s,=",
					size * 8, IMM64 (1), size, REG64 (0));
			}
		}
		break;
	}
	case ARM64_INS_CCMP:
	case ARM64_INS_CMP: // cmp w8, 0xd
		ARG64_APPEND (&op->esil, 1);
		COMMA (&op->esil);
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_appendf (&op->esil, ",==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=",
			REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) - 1);

		if (insn->id == ARM64_INS_CCMP || insn->id == ARM64_INS_CCMN) {
			r_strbuf_append (&op->esil, ",");
			arm_prefix_cond (op, insn->detail->arm64.cc);
			r_strbuf_appendf (&op->esil, "}{,pstate,1,28,1,<<,-,&,28,%"PFMT64d",<<,|,pstate,:=", IMM64 (2));
		}
		break;
	case ARM64_INS_CMN:
	case ARM64_INS_CCMN:
		ARG64_APPEND (&op->esil, 1);
		COMMA (&op->esil);
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_appendf (&op->esil, ",-1,*,==,$z,zf,:=,%d,$s,nf,:=,%d,$b,!,cf,:=,%d,$o,vf,:=",
			REGBITS64 (0) - 1, REGBITS64 (0), REGBITS64 (0) - 1);

		if (insn->id == ARM64_INS_CCMN) {
			r_strbuf_append (&op->esil, ",");
			arm_prefix_cond (op, insn->detail->arm64.cc);
			r_strbuf_appendf (&op->esil, "}{,pstate,1,28,1,<<,-,&,28,%"PFMT64d",<<,|,pstate,:=", IMM64 (2));
		}
		break;
	case ARM64_INS_TST: // tst w8, 0xd
		r_strbuf_append (&op->esil, "0,");
		ARG64_APPEND (&op->esil, 1);
		COMMA (&op->esil);
		ARG64_APPEND (&op->esil, 0);
		r_strbuf_appendf (&op->esil,
			",&,==" // (Wn & #imm) == 0
			// NZCV := result<datasize-1>:IsZeroBit(result):'00'
			",%d,$s,nf,:="
			",$z,zf,:="
			",0,cf,:="
			",0,vf,:=",
			REGBITS64 (0) - 1);
		break;
	case ARM64_INS_FCSEL:
	case ARM64_INS_CSEL: // csel Wd, Wn, Wm --> Wd := (cond) ? Wn : Wm
		r_strbuf_appendf (&op->esil, "%s,}{,%s,},%s,=", REG64 (1), REG64 (2), REG64 (0));
		postfix = "";
		break;
	case ARM64_INS_CSET: // cset Wd --> Wd := (cond) ? 1 : 0
		r_strbuf_appendf (&op->esil, "1,}{,0,},%s,=", REG64 (0));
		postfix = "";
		break;
	case ARM64_INS_CINC: // cinc Wd, Wn --> Wd := (cond) ? (Wn+1) : Wn
		r_strbuf_appendf (&op->esil, "1,%s,+,}{,%s,},%s,=", REG64 (1), REG64 (1), REG64 (0));
		postfix = "";
		break;
	case ARM64_INS_CSINC: // csinc Wd, Wn, Wm --> Wd := (cond) ? Wn : (Wm+1)
		r_strbuf_appendf (&op->esil, "%s,}{,1,%s,+,},%s,=", REG64 (1), REG64 (2), REG64 (0));
		postfix = "";
		break;
	case ARM64_INS_STXRB:
	case ARM64_INS_STXRH:
	case ARM64_INS_STXR:
	case ARM64_INS_STLXR:
	case ARM64_INS_STLXRH:
	case ARM64_INS_STLXRB:
	{
		int size = REGSIZE64 (1);
		switch (insn->id) {
			case ARM64_INS_STLXRB:
			case ARM64_INS_STXRB:
				size = 1;
				break;
			case ARM64_INS_STLXRH:
			case ARM64_INS_STXRH:
				size = 2;
				break;
			default:
				size = 8;
				break;
		}
		r_strbuf_setf (&op->esil, "0,%s,=,%s,%s,%"PFMT64d",+,=[%d]",
			REG64 (0), REG64 (1), MEMBASE64 (1), MEMDISP64 (1), size);
		break;
	}
	case ARM64_INS_STRB:
	case ARM64_INS_STRH:
	case ARM64_INS_STUR:
	case ARM64_INS_STURB:
	case ARM64_INS_STURH:
	case ARM64_INS_STR: // str x6, [x6,0xf90]
	{
		op->type = R_ANAL_OP_TYPE_STORE;
		int size = REGSIZE64 (0);
		if (insn->id == ARM64_INS_STRB || insn->id == ARM64_INS_STURB) {
			size = 1;
		} else if (insn->id == ARM64_INS_STRH || insn->id == ARM64_INS_STURH) {
			size = 2;
		}
		if (ISMEM64 (1)) {
			if (HASMEMINDEX64 (1)) {
				if (LSHIFT2_64 (1) || EXT64 (1)) {
					r_strbuf_appendf (&op->esil, "%s,%s,", REG64 (0), MEMBASE64 (1));
					ARG64_APPEND (&op->esil, 1);
					r_strbuf_appendf (&op->esil, ",+,=[%d]", size);
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,%s,+,=[%d]",
							REG64 (0), MEMBASE64 (1), MEMINDEX64 (1), size);
				}
			} else {
				if (LSHIFT2_64 (1)) {
					r_strbuf_appendf (&op->esil, "%s,%s,%d,%"PFMT64d",%s,+",
							REG64 (0), MEMBASE64 (1), LSHIFT2_64 (1), MEMDISP64 (1), DECODE_SHIFT64 (1));
				} else if ((int)MEMDISP64 (1) < 0) {
					r_strbuf_appendf (&op->esil, "%s,%"PFMT64d",%s,-",
							REG64 (0), -(st64)MEMDISP64 (1), MEMBASE64 (1));
				} else {
					r_strbuf_appendf (&op->esil, "%s,%"PFMT64d",%s,+",
							REG64 (0), MEMDISP64 (1), MEMBASE64 (1));
				}

				r_strbuf_append (&op->esil, ",DUP,tmp,=");

				// I assume the DUPs here previously were to handle preindexing
				// but it was never finished?
				if (ISPREINDEX64 ()) {
					r_strbuf_appendf (&op->esil, ",tmp,%s,=", REG64 (1));
				}

				r_strbuf_appendf (&op->esil, ",=[%d]", size);

				if (ISPOSTINDEX64 ()) {
					if (ISREG64 (2)) { // not sure if register valued post indexing exists?
						r_strbuf_appendf (&op->esil, ",tmp,%s,+,%s,=", REG64 (2), REG64 (1));
					} else {
						r_strbuf_appendf (&op->esil, ",tmp,%"PFMT64d",+,%s,=", IMM64 (2), REG64 (1));
					}
				}
			}
			op->refptr = 4;
			op->disp = MEMDISP64 (1);
		} else {
			if (ISREG64 (1)) {
				if (OPCOUNT64 () == 2) {
					r_strbuf_setf (&op->esil, "%s,%s,=[%d]",
						REG64 (0), REG64 (1), size);
				} else if (OPCOUNT64 () == 3) {
					/*
						This seems like a capstone bug:
						instructions like
							ldr x16, [x13, x9]
							ldrb w2, [x19, x23]
						are not detected as ARM64_OP_MEM type and
						fall in this case instead.
					*/
					if (ISREG64 (2)) {
						r_strbuf_setf (&op->esil, "%s,%s,%s,+,=[%d]",
							REG64 (0), REG64 (1), REG64 (2), size);
					}
				}
			} else {
				r_strbuf_setf (&op->esil, "%s,%"PFMT64d",=[%d]",
					REG64 (0), IMM64 (1), size);
			}
		}
		break;
	}
	case ARM64_INS_BIC:
	if (OPCOUNT64 () == 2) {
		if (REGSIZE64 (0) == 4) {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&=",
					REG64 (1), REG64 (0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,0xffffffffffffffff,^,%s,&=",
					REG64 (1), REG64 (0));
		}
	} else {
		if (REGSIZE64 (0) == 4) {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&,%s,=",
					REG64 (2), REG64 (1), REG64 (0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,0xffffffffffffffff,^,%s,&,%s,=",
					REG64 (2), REG64 (1), REG64 (0));
		}
	}
	break;
	case ARM64_INS_CBZ:
		r_strbuf_setf (&op->esil, "%s,!,?{,%"PFMT64d",pc,:=,}",
				REG64 (0), IMM64 (1));
		break;
	case ARM64_INS_CBNZ:
		r_strbuf_setf (&op->esil, "%s,?{,%"PFMT64d",pc,:=,}",
				REG64 (0), IMM64 (1));
		break;
	case ARM64_INS_TBZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%" PFMT64d ",1,<<,%s,&,!,?{,%"PFMT64d",pc,:=,}",
				IMM64 (1), REG64 (0), IMM64 (2));
		break;
	case ARM64_INS_TBNZ:
		// tbnz x0, 4, label
		// if ((1<<4) & x0) goto label;
		r_strbuf_setf (&op->esil, "%" PFMT64d ",1,<<,%s,&,?{,%"PFMT64d",pc,:=,}",
				IMM64 (1), REG64 (0), IMM64 (2));
		break;
	case ARM64_INS_STNP:
	case ARM64_INS_STP: // stp x6, x7, [x6,0xf90]
	{
		int disp = (int)MEMDISP64 (2);
		op->disp = disp;
		char sign = (disp >= 0)?'+':'-';
		st64 abs = (disp >= 0)? MEMDISP64 (2): -(st64)MEMDISP64 (2);
		int size = REGSIZE64 (0);
		// Pre-index case
		if (ISPREINDEX64 ()) {
			// "stp x2, x3, [x8, 0x20]!
			// "32,x8,+=,x2,x8,=[8],x3,x8,8,+,=[8]",
			r_strbuf_setf (&op->esil,
					"%" PFMT64d ",%s,%c=,%s,%s,=[%d],%s,%s,%d,+,=[%d]",
					abs, MEMBASE64 (2), sign,
					REG64 (0), MEMBASE64 (2), size,
					REG64 (1), MEMBASE64 (2), size, size);
		// Post-index case
		} else if (ISPOSTINDEX64 ()) {
			int val = IMM64 (3);
			sign = (val >= 0)?'+':'-';
			abs = (val >= 0)? val: -val;
			// "stp x4, x5, [x8], 0x10"
			// "x4,x8,=[],x5,x8,8,+,=[],16,x8,+="
			r_strbuf_setf (&op->esil,
					"%s,%s,=[%d],%s,%s,%d,+,=[%d],%" PFMT64d ",%s,%c=",
					REG64 (0), MEMBASE64 (2), size,
					REG64 (1), MEMBASE64 (2), size, size,
					abs, MEMBASE64 (2), sign);
		// Everything else
		} else {
			r_strbuf_setf (&op->esil,
					"%s,%s,%"PFMT64d",%c,=[%d],"
					"%s,%s,%"PFMT64d",%c,%d,+,=[%d]",
					REG64 (0), MEMBASE64 (2), abs, sign, size,
					REG64 (1), MEMBASE64 (2), abs, sign, size, size);
		}
		break;
	}
	case ARM64_INS_LDP: // ldp x29, x30, [sp], 0x10
	{
		const int disp = (int)MEMDISP64 (2);
		char sign = (disp >= 0)? '+': '-';
		ut64 abs = (ut64)((disp >= 0)? MEMDISP64 (2): (st64)(-disp));
		const int size = REGSIZE64 (0);
		// Pre-index case
		// x2,x8,32,+,=[8],x3,x8,32,+,8,+,=[8]
		if (ISPREINDEX64 ()) {
			// "ldp x0, x1, [x8, -0x10]!"
			// 16,x8,-=,x8,[8],x0,=,x8,8,+,[8],x1,=
			r_strbuf_setf (&op->esil,
					"%"PFMT64d",%s,%c=,"
					"%s,[%d],%s,=,"
					"%d,%s,+,[%d],%s,=",
					abs, MEMBASE64 (2), sign,
					MEMBASE64 (2), size, REG64 (0),
					size, MEMBASE64 (2), size, REG64 (1));
		// Post-index case
		} else if (ISPOSTINDEX64 ()) {
			int val = IMM64 (3);
			sign = (val >= 0)?'+':'-';
			abs = (val >= 0)? val: -val;
			// ldp x4, x5, [x8], -0x10
			// x8,[8],x4,=,x8,8,+,[8],x5,=,16,x8,+=
			r_strbuf_setf (&op->esil,
					"%s,[%d],%s,=,"
					"%s,%d,+,[%d],%s,=,"
					"%" PFMT64d ",%s,%c=",
					MEMBASE64 (2), size, REG64 (0),
					MEMBASE64 (2), size, size, REG64 (1),
					abs, MEMBASE64 (2), sign);
		} else {
			r_strbuf_setf (&op->esil,
					"%"PFMT64d",%s,%c,[%d],%s,=,"
					"%d,%"PFMT64d",%s,%c,+,[%d],%s,=",
					abs, MEMBASE64 (2), sign, size, REG64 (0),
					size, abs, MEMBASE64 (2), sign, size, REG64 (1));
		}
		break;
	}
	case ARM64_INS_ADRP:
		r_strbuf_setf (&op->esil, "%"PFMT64d",%s,=", IMM64 (1), REG64 (0));
		break;
	case ARM64_INS_EXTR:
		// from VEX
		/*
			01 | t0 = GET:I64(x4)
			02 | t1 = GET:I64(x0)
			03 | t4 = Shr64(t1,0x20)
			04 | t5 = Shl64(t0,0x20)
			05 | t3 = Or64(t5,t4)
			06 | PUT(x4) = t3
		*/
		r_strbuf_setf (&op->esil, "%" PFMT64d ",%s,>>,%" PFMT64d ",%s,<<,|,%s,=",
			IMM64 (3), REG64 (2), IMM64 (3), REG64 (1), REG64 (0));
		break;
	case ARM64_INS_RBIT:
		// slightly shorter expression to reverse bits
		r_strbuf_setf (&op->esil, "0,tmp,=,0,DUP,DUP,DUP,%d,-,%s,>>,1,&,<<,tmp,+=,%d,-,?{,++,4,GOTO,},tmp,%s,=",
			REGBITS64 (1)-1, REG64 (1), REGBITS64 (1)-1, REG64 (0));
		break;
	case ARM64_INS_MVN:
	case ARM64_INS_MOVN:
	{
		cs_arm64_op dst = INSOP64 (0);
		cs_arm64_op src = INSOP64 (1);

		if (dst.vas && src.vas) {
			r_strbuf_setf (&op->esil, "%sh,-1,^,%sh,=,%sl,-1,^,%sl,=",
				REG64 (1), REG64 (0), REG64 (1), REG64 (0));
		} else {
			ARG64_APPEND (&op->esil, 1);
			r_strbuf_append (&op->esil, ",-1,^,");
			VEC64_DST_APPEND (&op->esil, 0, -1);
			r_strbuf_append (&op->esil, ",=");
		}
		break;
	}
	case ARM64_INS_MOVK: // movk w8, 0x1290
	{
		ut64 shift = LSHIFT2_64 (1);
		if (shift < 0) {
			shift = 0;
		} else if (shift > 48) {
			shift = 48;
		}
		ut64 shifted_imm = IMM64 (1) << shift;
		ut64 mask = ~(0xffffULL << shift);

		r_strbuf_setf (&op->esil, "0x%"PFMT64x",%s,&,%"PFMT64u",|,%s,=",
			mask,
			REG64 (0),
			shifted_imm,
			REG64 (0));

		break;
	}
	case ARM64_INS_MOVZ:
		r_strbuf_setf (&op->esil, "%"PFMT64u",%s,=",
			SHIFTED_IMM64 (1, REGSIZE64 (0)*8),
			REG64 (0));
		break;
	/* ASR, SXTB, SXTH and SXTW are alias for SBFM */
	case ARM64_INS_ASR:
	{
		//OPCALL (">>>>");
		const char *r0 = REG64 (0);
		const char *r1 = REG64 (1);
		const int size = REGSIZE64 (0)*8;

		if (ISREG64 (2)) {
			if (LSHIFT2_64 (2)) {
				ARG64_APPEND (&op->esil, 2);
				r_strbuf_appendf (&op->esil, ",%d,%%,%s,>>>>,%s,=", size, r1, r0);
			} else {
				const char *r2 = REG64 (2);
				r_strbuf_setf (&op->esil, "%d,%s,%%,%s,>>>>,%s,=", size, r2, r1, r0);
			}
		} else {
			ut64 i2 = IMM64 (2);
			r_strbuf_setf (&op->esil, "%"PFMT64d",%s,>>>>,%s,=", i2 % (ut64)size, r1, r0);
		}
		break;
	}
	case ARM64_INS_SXTB:
		if (arm64_reg_width(REGID64 (0)) == 32) {
			r_strbuf_setf (&op->esil, "0xffffffff,8,0xff,%s,&,~,&,%s,=",
				REG64 (1), REG64 (0));
		} else {
			r_strbuf_setf (&op->esil, "8,0xff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		}
		break;
	case ARM64_INS_SXTH: /* halfword */
		if (arm64_reg_width(REGID64 (0)) == 32) {
			r_strbuf_setf (&op->esil, "0xffffffff,16,0xffff,%s,&,~,&,%s,=",
				REG64 (1), REG64 (0));
		} else {
			r_strbuf_setf (&op->esil, "16,0xffff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		}
		break;
	case ARM64_INS_SXTW: /* word */
		r_strbuf_setf (&op->esil, "32,0xffffffff,%s,&,~,%s,=",
				REG64 (1), REG64 (0));
		break;
	case ARM64_INS_UXTB:
		r_strbuf_setf (&op->esil, "%s,0xff,&,%s,=", REG64 (1), REG64 (0));
		break;
	case ARM64_INS_UXTH:
		r_strbuf_setf (&op->esil, "%s,0xffff,&,%s,=", REG64 (1), REG64 (0));
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_RETAA:
	case ARM64_INS_RETAB:
	case ARM64_INS_ERETAA:
	case ARM64_INS_ERETAB:
#endif
	case ARM64_INS_RET:
		r_strbuf_set (&op->esil, "lr,pc,:=");
		break;
	case ARM64_INS_ERET:
		r_strbuf_set (&op->esil, "lr,pc,:=");
		break;
	case ARM64_INS_BFI: // bfi w8, w8, 2, 1
	case ARM64_INS_BFXIL:
	{
		if (OPCOUNT64 () >= 3 && ISIMM64 (3) && IMM64 (3) > 0) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			ut64 mask = bitmask_by_width[index];
			ut64 shift = IMM64 (2);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,lsb,mask,src,&,<<,|,dst,=
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,&,%"PFMT64u",%"PFMT64u",%s,&,<<,|,%s,=",
				notmask, REG64 (0), shift, mask, REG64 (1), REG64 (0));
		}
		break;
	}
	case ARM64_INS_SBFIZ:
		if (IMM64 (3) > 0 && IMM64 (3) <= 64 - IMM64 (2)) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%"PFMT64u",&,~,<<,%s,=",
					IMM64 (2), IMM64 (3), REG64 (1), (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_INS_UBFIZ:
		if (IMM64 (3) > 0 && IMM64 (3) <= 64 - IMM64 (2)) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64d ",%s,%"PFMT64u",&,<<,%s,=",
					IMM64 (2), REG64 (1), (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_INS_SBFX:
		if (IMM64 (3) > 0 && IMM64 (3) <= 64 - IMM64 (2)) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64d ",%" PFMT64d ",%s,%" PFMT64d ",%"PFMT64u",<<,&,>>,~,%s,=",
				IMM64 (3), IMM64 (2), REG64 (1), IMM64 (2) , (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_INS_UBFX:
		if (IMM64 (3) > 0 && IMM64 (3) <= 64 - IMM64 (2)) {
			size_t index = IMM64 (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%" PFMT64d ",%s,%" PFMT64d ",%"PFMT64u",<<,&,>>,%s,=",
				IMM64 (2), REG64 (1), IMM64 (2) , (ut64)bitmask_by_width[index], REG64 (0));
		}
		break;
	case ARM64_INS_NEG:
#if CS_API_MAJOR > 3
	case ARM64_INS_NEGS:
#endif
		ARG64_APPEND (&op->esil, 1);
		r_strbuf_appendf (&op->esil, ",0,-,%s,=", REG64 (0));
		break;
	case ARM64_INS_SVC:
		r_strbuf_setf (&op->esil, "%" PFMT64u ",$", IMM64 (0));
		break;
	}

	r_strbuf_append (&op->esil, postfix);

	return 0;
}

#define MATH32(opchar) arm32math(as, op, addr, buf, len, handle, insn, pcdelta, str, opchar, 0)
#define MATH32_NEG(opchar) arm32math(as, op, addr, buf, len, handle, insn, pcdelta, str, opchar, 1)
#define MATH32AS(opchar) arm32mathaddsub(as, op, addr, buf, len, handle, insn, pcdelta, str, opchar)

static void arm32math(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len,
	csh *handle, cs_insn *insn, int pcdelta, RStringShort str[32], const char *opchar, int negate) {
	const char *dest = ARG(0);
	const char *op1;
	const char *op2;
	bool rotate_imm = OPCOUNT() > 3;
	if (OPCOUNT() > 2) {
		op1 = ARG(1);
		op2 = ARG(2);
	} else {
		op1 = dest;
		op2 = ARG(1);
	}
	// right operand
	if (rotate_imm) {
		r_strbuf_appendf (&op->esil, "%s,", ARG(3));
	}
	if (!strcmp (op2, "pc")) {
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x, addr + pcdelta);
	} else {
		r_strbuf_append (&op->esil, op2);
	}
	if (rotate_imm) {
		r_strbuf_append (&op->esil, ",>>>");
	}
	if (negate) {
		r_strbuf_append (&op->esil, ",-1,^");
	}
	if (!strcmp (op1, "pc")) {
		r_strbuf_appendf (&op->esil, ",0x%"PFMT64x",%s,0xffffffff,&,%s,=", addr + pcdelta, opchar, dest);
	} else {
		if (ISSHIFTED(1)) {
			r_strbuf_appendf (&op->esil, ",0xffffffff,&,%s,=", dest);
		} else {
			r_strbuf_appendf (&op->esil, ",%s,%s,0xffffffff,&,%s,=", op1, opchar, dest);
		}
	}
}

static void arm32mathaddsub(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len,
	csh *handle, cs_insn *insn, int pcdelta, RStringShort str[32], const char *opchar) {
	const char *dst = ARG (0);
	const char *src;
	bool noflags = false;
	if (!strcmp (dst, "pc")) {	//this is because strbuf_prepend doesn't exist and E_TOO_LAZY
		//		r_strbuf_append (&op->esil, "$$,pc,:=,");
		noflags = true;
	}
	if (OPCOUNT () == 3) {
		r_strbuf_appendf (&op->esil, "%s,0xffffffff,&,%s,=,", ARG (1), dst);
		src = ARG (2);
	} else {
		//		src = (!strcmp (ARG(1), "pc"))? "$$": ARG(1);
		src = ARG (1);
	}
	r_strbuf_appendf (&op->esil, "%s,%s,%s,0xffffffff,&,%s,=", src, dst, opchar, dst);
	if (noflags) {
		return;
	}
	r_strbuf_appendf (&op->esil, ",$z,zf,:=,%s,cf,:=,vf,=,0,nf,=",
		(!strcmp (opchar, "+")? "30,$c,31,$c,^,31,$c": "30,$c,31,$c,^,32,$b"));
}

static int analop_esil(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, csh *handle, cs_insn *insn, bool thumb) {
	int i;
	const char *postfix = NULL;
	RStringShort str[32] = {{0}};
	int msr_flags;
	int pcdelta = (thumb? 4: 8);
	ut32 mask = UT32_MAX;
	int str_ldr_bytes = 4;
	unsigned int width = 0;

	r_strbuf_init (&op->esil);
	r_strbuf_set (&op->esil, "");
	postfix = arm_prefix_cond (op, insn->detail->arm.cc);

	switch (insn->id) {
	case ARM_INS_CLZ:
		r_strbuf_appendf (&op->esil, "%s,!,?{,32,%s,=,BREAK,},"
			"0,%s,=,%s,%s,<<,0x80000000,&,!,?{,1,%s,+=,11,GOTO,}",
			REG (1), REG (0), REG (0), REG (0), REG (1), REG (0));
		break;
	case ARM_INS_IT:
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x",pc,:=", addr + 2);
		break;
	case ARM_INS_BKPT:
		r_strbuf_setf (&op->esil, "%d,%d,TRAP", IMM (0), IMM (0));
		break;
	case ARM_INS_NOP:
		r_strbuf_set (&op->esil, ",");
		break;
	case ARM_INS_BL:
	case ARM_INS_BLX:
		r_strbuf_append (&op->esil, "pc,lr,:=,");
		/* fallthrough */
	case ARM_INS_BX:
	case ARM_INS_BXJ:
	case ARM_INS_B:
		if (ISREG (0) && REGID (0) == ARM_REG_PC) {
			r_strbuf_appendf (&op->esil, "0x%" PFMT64x ",pc,:=",
				(ut64)((addr & ~3LL) + pcdelta));
		} else {
			if (ISIMM (0)) {
				r_strbuf_appendf (&op->esil, "%s,pc,:=", ARG (0));
			} else {
				r_strbuf_appendf (&op->esil, "%d,%s,-,pc,:=", thumb, ARG (0));
			}
		}
		break;
	case ARM_INS_UDF:
		r_strbuf_setf (&op->esil, "%s,TRAP", ARG (0));
		break;
	case ARM_INS_SADD16:
	case ARM_INS_SADD8:
		MATH32AS ("+");
		break;
	case ARM_INS_ADDW:
	case ARM_INS_ADD:
		MATH32 ("+");
		break;
	case ARM_INS_ADC:
		if (OPCOUNT () == 2) {
			r_strbuf_appendf (&op->esil, "cf,%s,+=,%s,%s,+=", ARG (0), ARG (1), ARG (0));
		} else {
			r_strbuf_appendf (&op->esil, "cf,%s,+=,%s,%s,+,%s,+=", ARG (0), ARG (2), ARG (1), ARG (0));
		}
		break;
	case ARM_INS_SSUB16:
	case ARM_INS_SSUB8:
		MATH32AS ("-");
		break;
	case ARM_INS_SUBW:
	case ARM_INS_SUB:
		MATH32 ("-");
		break;
	case ARM_INS_SBC:
		if (OPCOUNT () == 2) {
			r_strbuf_appendf (&op->esil, "cf,%s,-=,%s,%s,-=", ARG (0), ARG (1), ARG (0));
		} else {
			r_strbuf_appendf (&op->esil, "cf,%s,-=,%s,%s,+,%s,-=", ARG (0), ARG (2), ARG (1), ARG (0));
		}
		break;
	case ARM_INS_MUL:
		MATH32 ("*");
		break;
	case ARM_INS_AND:
		MATH32 ("&");
		break;
	case ARM_INS_ORR:
		MATH32 ("|");
		break;
	case ARM_INS_EOR:
		MATH32 ("^");
		break;
	case ARM_INS_ORN:
		MATH32_NEG ("|");
		break;
	case ARM_INS_LSR:
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT () == 2) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG (1), ARG (0), ARG (1));
			} else {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG (2), ARG (1), ARG (2));
			}
		}
		MATH32 (">>");
		break;
	case ARM_INS_LSL:
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT () == 2) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,32,-,%s,>>,cf,:=,},", ARG (1), ARG (1), ARG (0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,32,-,%s,>>,cf,:=,},", ARG (2), ARG (2), ARG (1));
			}
		}
		MATH32 ("<<");
		break;
	case ARM_INS_ROR:
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT () == 2) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<<,&,!,!,cf,:=,},", ARG (1), ARG (0), ARG (1));
			} else {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<<,&,!,!,cf,:=,},", ARG (2), ARG (1), ARG (2));
			}
		}
		MATH32 (">>>");
		break;
	case ARM_INS_SVC:
		r_strbuf_setf (&op->esil, "%s,$", ARG (0));
		break;
	case ARM_INS_PUSH:
#if 0
PUSH { r4, r5, r6, r7, lr }
4,sp,-=,lr,sp,=[4],
4,sp,-=,r7,sp,=[4],
4,sp,-=,r6,sp,=[4],
4,sp,-=,r5,sp,=[4],
4,sp,-=,r4,sp,=[4]

20,sp,-=,r4,sp,=[4],r5,sp,4,+,=[4],r6,sp,8,+,=[4],r7,sp,12,+,=[4],lr,sp,16,+,=[4]
#endif
		r_strbuf_setf (&op->esil, "%d,sp,-=,%s,sp,=[4]", insn->detail->arm.op_count * 4, REG (0));
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, ",%s,sp,%d,+,=[4]", REG (i), i * 4);
		}
		break;
	case ARM_INS_STMDA:
	case ARM_INS_STMDB:
	case ARM_INS_STM:
	case ARM_INS_STMIB: {
		int direction = (insn->id == ARM_INS_STMDA || insn->id == ARM_INS_STMDB ? -1 : 1);
		int offset = direction > 0 ? -1 : -insn->detail->arm.op_count;
		if (insn->id == ARM_INS_STMDA || insn->id == ARM_INS_STMIB) {
			offset++;
		}
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%s,%d,+,=[4],",
				REG (i), ARG (0), (i + offset) * 4);
		}
		if (ISWRITEBACK32 ()) { //writeback, reg should be incremented
			r_strbuf_appendf (&op->esil, "%d,%s,+=,",
				direction * (insn->detail->arm.op_count - 1) * 4, ARG (0));
		}
		break;
	}
	case ARM_INS_VSTMIA:
		r_strbuf_set (&op->esil, "");
		width = 0;
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%d,%s,+,=[%d],",
				REG (i), width, ARG (0), REGSIZE32 (i));
			width += REGSIZE32 (i);
		}
		// increment if writeback
		if (ISWRITEBACK32 ()) {
			r_strbuf_appendf (&op->esil, "%d,%s,+=,", width, ARG (0));
		}
		break;
	case ARM_INS_VSTMDB:
		r_strbuf_set (&op->esil, "");
		width = 0;
		for (i = insn->detail->arm.op_count - 1; i > 0; i--) {
			width += REGSIZE32 (i);
			r_strbuf_appendf (&op->esil, "%s,%d,%s,-,=[%d],",
				REG (i), width, ARG (0), REGSIZE32 (i));
		}
		// decrement writeback is mandatory for VSTMDB
		r_strbuf_appendf (&op->esil, "%d,%s,-=,", width, ARG (0));
		break;
	case ARM_INS_VLDMIA:
		r_strbuf_set (&op->esil, "");
		width = 0;
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%d,%s,+,[%d],%s,=,",
				width, ARG (0), REGSIZE32 (i), REG (i));
			width += REGSIZE32 (i);
		}
		// increment if writeback
		if (ISWRITEBACK32 ()) {
			r_strbuf_appendf (&op->esil, "%d,%s,+=,", width, ARG (0));
		}
		break;
	case ARM_INS_VLDMDB:
		r_strbuf_set (&op->esil, "");
		width = 0;
		for (i = insn->detail->arm.op_count - 1; i > 0; i--) {
			width += REGSIZE32 (i);
			r_strbuf_appendf (&op->esil, "%d,%s,-,[%d],%s,=,",
				width, ARG (0), REGSIZE32 (i), REG (i));
		}
		// decrement writeback is mandatory for VLDMDB
		r_strbuf_appendf (&op->esil, "%d,%s,-=,", width, ARG (0));
		break;
	case ARM_INS_ASR:
		// suffix 'S' forces conditional flag to be updated
		if (insn->detail->arm.update_flags) {
			if (OPCOUNT () == 2) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG (1), ARG (0), ARG (1));
			} else if (OPCOUNT () == 3) {
				r_strbuf_appendf (&op->esil, "%s,!,!,?{,%s,1,%s,-,0x1,<<,&,!,!,cf,:=,},", ARG (2), ARG (1), ARG (2));
			}
		}
		if (OPCOUNT () == 2) {
			if (ISSHIFTED (1)) {
				r_strbuf_appendf (&op->esil, "%s,%s,=", ARG (1), ARG (0));
			} else {
				r_strbuf_appendf (&op->esil, "%s,%s,>>>>,%s,=", ARG (1), ARG (0), ARG (0));
			}
		} else if (OPCOUNT () == 3) {
			r_strbuf_appendf (&op->esil, "%s,%s,>>>>,%s,=", ARG (2), ARG (1), ARG (0));
		}
		break;
	case ARM_INS_POP:
#if 0
POP { r4,r5, r6}
r6,r5,r4,3,sp,[*],12,sp,+=
#endif
		for (i = insn->detail->arm.op_count; i > 0; i--) {
			r_strbuf_appendf (&op->esil, "%s,", REG (i - 1));
		}
		r_strbuf_appendf (&op->esil, "%d,sp,[*],",
			insn->detail->arm.op_count);
		r_strbuf_appendf (&op->esil, "%d,sp,+=",
			4 * insn->detail->arm.op_count);
		break;
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDM:
	case ARM_INS_LDMIB: {
		int direction = (insn->id == ARM_INS_LDMDA || insn->id == ARM_INS_LDMDB) ? -1 : 1;
		int offset = direction > 0 ? -1 : -insn->detail->arm.op_count;
		if (insn->id == ARM_INS_LDMDA || insn->id == ARM_INS_LDMIB) {
			offset++;
		}
		for (i = 1; i < insn->detail->arm.op_count; i++) {
			r_strbuf_appendf (&op->esil, "%s,%d,+,[4],%s,=,", ARG (0), (i + offset) * 4, REG (i));
		}
		if (ISWRITEBACK32 ()) {
			r_strbuf_appendf (&op->esil, "%d,%s,+=,",
				direction * (insn->detail->arm.op_count - 1) * 4, ARG (0));
		}
		break;
	}
	case ARM_INS_CMP:
		r_strbuf_appendf (&op->esil, "%s,%s,==", ARG (1), ARG (0));
		break;
	case ARM_INS_CMN:
		r_strbuf_appendf (&op->esil, "%s,%s,^,!,!,zf,=", ARG (1), ARG (0));
		break;
	case ARM_INS_MOVT:
		r_strbuf_appendf (&op->esil, "16,%s,<<,%s,|=", ARG (1), REG (0));
		break;
	case ARM_INS_ADR:
		r_strbuf_appendf (&op->esil, "0x%"PFMT64x",%s,+,0xfffffffc,&,%s,=",
			addr + pcdelta, ARG (1), REG (0));
		break;
	case ARM_INS_MOV:
	case ARM_INS_VMOV:
	case ARM_INS_MOVW:
		if (as->config->bits == 16) {
			MATH32 ("=");
		} else {
			r_strbuf_appendf (&op->esil, "%s,%s,=", ARG (1), REG (0));
		}
		break;
	case ARM_INS_CBZ:
		r_strbuf_appendf (&op->esil, "%s,!,?{,%" PFMT32u ",pc,:=,}",
			REG (0), IMM (1));
		break;
	case ARM_INS_CBNZ:
		r_strbuf_appendf (&op->esil, "%s,?{,%" PFMT32u ",pc,:=,}",
			REG (0), IMM (1));
		break;
		// Encapsulated STR/H/B into a code section
	case ARM_INS_STRT:
	case ARM_INS_STR:
	case ARM_INS_STRHT:
	case ARM_INS_STRH:
	case ARM_INS_STRBT:
	case ARM_INS_STRB:
	case ARM_INS_STRD:
	//case ARM_INS_STLXRB: // capstone has no STLXR?
		switch (insn->id) {
		case ARM_INS_STRD:
			str_ldr_bytes = 8; // just an indication, won't be used in esil code
			break;
		case ARM_INS_STRHT:
		case ARM_INS_STRH:
			str_ldr_bytes = 2;
			break;
		case ARM_INS_STRBT:
		case ARM_INS_STRB:
			str_ldr_bytes = 1;
			break;
		default:
			str_ldr_bytes = 4;
		}
		if (OPCOUNT() == 2) {
			if (ISMEM(1) && !HASMEMINDEX(1)) {
				int disp = MEMDISP (1);
				char sign = (disp >= 0)?'+':'-';
				disp = (disp >= 0)? disp: -disp;
				r_strbuf_appendf (&op->esil, "%s,0x%x,%s,%c,0xffffffff,&,=[%d]",
						  REG(0), disp, MEMBASE(1), sign, str_ldr_bytes);
				if (ISWRITEBACK32 ()) {
					r_strbuf_appendf (&op->esil, ",%d,%s,%c,%s,=",
							  disp, MEMBASE(1), sign, MEMBASE(1));
				}
			}
			if (HASMEMINDEX (1)) {	// e.g. 'str r2, [r3, r1]'
				if (ISSHIFTED (1)) { // e.g. 'str r2, [r3, r1, lsl 4]'
					switch (SHIFTTYPE (1)) {
					case ARM_SFT_LSL:
						r_strbuf_appendf (&op->esil, "%s,%s,%d,%s,<<,+,0xffffffff,&,=[%d]",
								  REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32 ()) { // e.g. 'str r2, [r3, r1, lsl 4]!'
							r_strbuf_appendf (&op->esil, ",%s,%d,%s,<<,+,%s,=",
									  MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_LSR:
						r_strbuf_appendf (&op->esil, "%s,%s,%d,%s,>>,+,0xffffffff,&,=[%d]",
								  REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32 ()) {
							r_strbuf_appendf (&op->esil, ",%s,%d,%s,>>,+,%s,=",
									  MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_ASR:
						r_strbuf_appendf (&op->esil, "%s,%s,%d,%s,>>>>,+,0xffffffff,&,=[%d]",
								  REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32 ()) {
							r_strbuf_appendf (&op->esil, ",%s,%d,%s,>>>>,+,%s,=",
									  MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_ROR:
						r_strbuf_appendf (&op->esil, "%s,%s,%d,%s,>>>,+,0xffffffff,&,=[%d]",
								  REG(0), MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), str_ldr_bytes);
						if (ISWRITEBACK32 ()) {
							r_strbuf_appendf (&op->esil, ",%s,%d,%s,>>>,+,%s,=",
									  MEMBASE(1), SHIFTVALUE(1), MEMINDEX(1), MEMBASE(1));
						}
						break;
					case ARM_SFT_RRX: // ROR with single bit shift, using previous cf rather than new cf
						//TODO: r2 doesn't mark this as a shift, it falls through to no shift
						break;
					default:
						// Hopefully nothing here
						break;
					}
				} else { // No shift
					r_strbuf_appendf (&op->esil, "%s,%s,%s,+,0xffffffff,&,=[%d]",
							  REG(0), MEMINDEX(1), MEMBASE(1), str_ldr_bytes);
					if (ISWRITEBACK32 ()) {
						r_strbuf_appendf (&op->esil, ",%s,%s,+,%s,=",
								  MEMINDEX(1), MEMBASE(1), MEMBASE(1));
					}
				}
			}
		}
		if (OPCOUNT() == 3) { // e.g. 'str r2, [r3], 4
			if (ISIMM (2) && str_ldr_bytes != 8) { // e.g. 'str r2, [r3], 4
				r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%d,%s,+=",
					       REG(0), MEMBASE(1), str_ldr_bytes, IMM(2), MEMBASE(1));
			} else if (str_ldr_bytes != 8) {
				// if (ISREG(2)) // e.g. 'str r2, [r3], r1
				if (ISSHIFTED (2)) { // e.g. 'str r2, [r3], r1, lsl 4'
					switch (SHIFTTYPE (2)) {
					case ARM_SFT_LSL:
						r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,<<,+,%s,=",
							       REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(2), REG(2), MEMBASE(1));
						break;
					case ARM_SFT_LSR:
						r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,>>,+,%s,=",
							       REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(2), REG(2), MEMBASE(1));
						break;
					case ARM_SFT_ASR:
						r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,>>>>,+,%s,=",
							       REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(2), REG(2), MEMBASE(1));
						break;
					case ARM_SFT_ROR:
						r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%d,%s,>>>,+,%s,=",
							       REG(0), MEMBASE(1), str_ldr_bytes, MEMBASE(1), SHIFTVALUE(2), REG(2), MEMBASE(1));
						break;
					case ARM_SFT_RRX:
						//TODO
						break;
					default:
						// Hopefully nothing here
						break;
					}
				} else { // No shift
					r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,%s,+=",
						       REG(0), MEMBASE(1), str_ldr_bytes, REG(2), MEMBASE(1));
				}
			}
			if (ISREG (1) && str_ldr_bytes == 8) { // e.g. 'strd r2, r3, [r4]', normally should be the only case for ISREG(1).
				if (!HASMEMINDEX(2)) {
					int disp = MEMDISP (2);
					char sign = (disp >= 0)?'+':'-';
					disp = (disp >= 0)? disp: -disp;
					r_strbuf_appendf (&op->esil, "%s,%d,%s,%c,0xffffffff,&,=[4],%s,4,%d,+,%s,%c,0xffffffff,&,=[4]",
							  REG(0), disp, MEMBASE(2), sign, REG(1), disp, MEMBASE(2), sign);
					if (ISWRITEBACK32 ()) {
						r_strbuf_appendf (&op->esil, ",%d,%s,%c,%s,=",
								  disp, MEMBASE(2), sign, MEMBASE(2));
					}
				} else {
					if (ISSHIFTED (2)) {
						// it seems strd does not support SHIFT which is good, but have a check nonetheless
					} else {
						r_strbuf_appendf (&op->esil, "%s,%s,+,0xffffffff,&,=[4],%s,4,%s,+,0xffffffff,&,=[4]",
								  REG(0), MEMBASE(2), REG(1), MEMBASE(2));
						if (ISWRITEBACK32 ()) {
							const char sign = ISMEMINDEXSUB(2) ? '-' : '+';
							r_strbuf_appendf (&op->esil, ",%s,%s,%c=",
									  MEMINDEX(2), MEMBASE(2), sign);
						}
					}
				}
			}
		}
		if (OPCOUNT() == 4) { // e.g. 'strd r2, r3, [r4], 4' or 'strd r2, r3, [r4], r5'
			if (ISIMM (3)) { // e.g. 'strd r2, r3, [r4], 4'
				r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,4,%s,+,0xffffffff,&,=[%d],%d,%s,+=,",
					       REG(0), MEMBASE(2), str_ldr_bytes, REG(1), MEMBASE(2), str_ldr_bytes, IMM(3), MEMBASE(2));
			}
			if (ISREG(3)) { // e.g. 'strd r2, r3, [r4], r5'
				if (ISSHIFTED(3)) {
					// same as above
				} else {
					r_strbuf_appendf (&op->esil, "%s,%s,0xffffffff,&,=[%d],%s,4,%s,+,0xffffffff,&,=[%d],%s,%s,+=",
						       REG(0), MEMBASE(2), str_ldr_bytes, REG(1), MEMBASE(2), str_ldr_bytes, REG(3), MEMBASE(2));
				}
			}
		}
		break;
	case ARM_INS_TST:
		r_strbuf_appendf (&op->esil, "0,%s,%s,&,==", ARG(1), ARG(0));
		break;
	case ARM_INS_LDRD:
		addr &= ~3LL;
		if (MEMDISP (2) < 0) {
			if (REGBASE (2) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP (2);
				r_strbuf_appendf (&op->esil, "0x%"PFMT64x",2,2,0x%"PFMT64x
					",>>,<<,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
					(ut64)MEMDISP (2), addr + pcdelta, REG (0), REG (1));
			} else {
				int disp = MEMDISP (2);
				// not refptr, because we can't grab the reg value statically op->refptr = 4;
				if (disp < 0) {
					r_strbuf_appendf (&op->esil, "0x%"PFMT64x
						",%s,-,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						(ut64)-disp, MEMBASE (2), REG (0), REG (1));
				} else {
					r_strbuf_appendf (&op->esil, "0x%"PFMT64x
						",%s,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						(ut64)disp, MEMBASE (2), REG (0), REG (1));
				}
			}
		} else {
			if (REGBASE (2) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP (2);
				if (HASMEMINDEX (2) || ISREG (2)) {
					const char op_index = ISMEMINDEXSUB (2)? '-': '+';
					r_strbuf_appendf (&op->esil, "%s,2,2,0x%"PFMT64x
						",>>,<<,%c,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						MEMINDEX (2), addr + pcdelta, op_index, REG (0), REG (1));
				} else {
					r_strbuf_appendf (&op->esil, "2,2,0x%"PFMT64x
						",>>,<<,%d,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						addr + pcdelta, MEMDISP (2), REG (0), REG (1));
				}
			} else {
				if (HASMEMINDEX (2)) { // e.g. `ldrd r2, r3 [r4, r1]`
					const char op_index = ISMEMINDEXSUB (2)? '-': '+';
					r_strbuf_appendf (&op->esil, "%s,%s,%c,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						MEMINDEX (2), MEMBASE (2), op_index, REG (0), REG (1));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%s,+,0xffffffff,&,DUP,[4],%s,=,4,+,[4],%s,=",
						MEMDISP (2), MEMBASE (2), REG (0), REG (1));
				}
				if (ISWRITEBACK32 ()) {
					if (ISPOSTINDEX32 ()) {
						if (ISIMM (3)) {
							r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
								MEMBASE (2), IMM (3), MEMBASE (2));
						} else {
							const char op_index = ISMEMINDEXSUB (3)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%s,%s,%c,%s,=",
								REG (3), MEMBASE (2), op_index, MEMBASE (2));
						}
					} else if (ISPREINDEX32 ()) {
						if (HASMEMINDEX (2)) {
							const char op_index = ISMEMINDEXSUB (2)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%s,%s,%c,%s,=",
								MEMINDEX (2), MEMBASE (2), op_index, MEMBASE (2));
						} else {
							r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
								MEMBASE (2), MEMDISP (2), MEMBASE (2));
						}
					}
				}
			}
		}
		break;
	case ARM_INS_LDRB:
		if (ISMEM(1) && LSHIFT2(1)) {
			r_strbuf_appendf (&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[1],0x%x,&,%s,=",
				MEMBASE (1), LSHIFT2 (1), MEMINDEX (1), mask, REG (0));
		} else if (HASMEMINDEX (1)) {
			r_strbuf_appendf (&op->esil, "%s,%s,+,0xffffffff,&,[1],%s,=",
				MEMINDEX (1), MEMBASE (1), REG (0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,%d,+,[1],%s,=",
				MEMBASE (1), MEMDISP (1), REG (0));
		}
		if (ISWRITEBACK32 ()) {
			if (ISIMM(2)) {
				r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
					MEMBASE (1), IMM (2), MEMBASE (1));
			} else {
				r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
					MEMBASE (1), MEMDISP (1), MEMBASE (1));
			}
		}
		break;
	case ARM_INS_SXTH:
		r_strbuf_appendf (&op->esil,
			"15,%s,>>,1,&,?{,15,-1,<<,%s,0xffff,&,|,%s,:=,}{,%s,0xffff,%s,:=,}",
			REG (1), REG (1), REG (0), REG (1), REG (0));
		break;
	case ARM_INS_SXTB:
		r_strbuf_appendf (&op->esil,
			"7,%s,>>,1,&,?{,7,-1,<<,%s,0xff,&,|,%s,:=,}{,%s,0xff,&,%s,:=,}",
			REG (1), REG (1), REG (0), REG (1), REG (0));
		break;
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		// intentional fallthrough
	case ARM_INS_LDRHT:
	case ARM_INS_LDRH:
	case ARM_INS_LDRT:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDR:
		switch (insn->id) {
		case ARM_INS_LDRHT:
		case ARM_INS_LDRH:
		case ARM_INS_LDRSH:
		case ARM_INS_LDRSHT:
			mask = UT16_MAX;
			break;
		default:
			mask = UT32_MAX;
			break;
		}
		addr &= ~3LL;
		if (MEMDISP (1) < 0) {
			if (REGBASE (1) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP(1);
				r_strbuf_appendf (&op->esil, "0x%"PFMT64x",2,2,0x%"PFMT64x
					",>>,<<,+,0xffffffff,&,[4],0x%x,&,%s,=",
					(ut64)MEMDISP(1), addr + pcdelta, mask, REG(0));
			} else {
				int disp = MEMDISP(1);
				// not refptr, because we can't grab the reg value statically op->refptr = 4;
				if (disp < 0) {
					r_strbuf_appendf (&op->esil, "0x%"PFMT64x",%s,-,0xffffffff,&,[4],0x%x,&,%s,=",
							(ut64)-disp, MEMBASE(1), mask, REG(0));
				} else {
					r_strbuf_appendf (&op->esil, "0x%"PFMT64x",%s,+,0xffffffff,&,[4],0x%x,&,%s,=",
							(ut64)disp, MEMBASE(1), mask, REG(0));
				}
			}
		} else {
			if (REGBASE(1) == ARM_REG_PC) {
				op->refptr = 4;
				op->ptr = addr + pcdelta + MEMDISP(1);
				if (ISMEM(1) && LSHIFT2(1)) {
					r_strbuf_appendf (&op->esil, "2,2,0x%"PFMT64x
						",>>,<<,%d,%s,<<,+,0xffffffff,&,[4],0x%x,&,%s,=",
						addr + pcdelta, LSHIFT2(1), MEMINDEX(1), mask, REG(0));
				} else {
					if (ISREG(1)) {
						const char op_index = ISMEMINDEXSUB (1)? '-': '+';
						r_strbuf_appendf (&op->esil, "%s,2,2,0x%"PFMT64x
							",>>,<<,%c,0xffffffff,&,[4],0x%x,&,%s,=",
							MEMINDEX (1), addr + pcdelta, op_index, mask, REG (0));
					} else {
						r_strbuf_appendf (&op->esil, "2,2,0x%"PFMT64x
							",>>,<<,%d,+,0xffffffff,&,[4],0x%x,&,%s,=",
							addr + pcdelta, MEMDISP(1), mask, REG(0));
					}
				}
			} else {
				if (ISMEM(1) && LSHIFT2(1)) {
					r_strbuf_appendf (&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[4],0x%x,&,%s,=",
						MEMBASE (1), LSHIFT2 (1), MEMINDEX (1), mask, REG (0));
				} else if (HASMEMINDEX(1)) {	// e.g. `ldr r2, [r3, r1]`
					const char op_index = ISMEMINDEXSUB (1)? '-': '+';
					r_strbuf_appendf (&op->esil, "%s,%s,%c,0xffffffff,&,[4],0x%x,&,%s,=",
						MEMINDEX (1), MEMBASE (1), op_index, mask, REG (0));
				} else {
					r_strbuf_appendf (&op->esil, "%d,%s,+,0xffffffff,&,[4],0x%x,&,%s,=",
						MEMDISP (1), MEMBASE (1), mask, REG (0));
				}
				if (ISWRITEBACK32 ()) {
					if (ISPOSTINDEX32 ()) {
						if (ISIMM (2)) {
							r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
								MEMBASE (1), IMM (2), MEMBASE (1));
						} else {
							const char op_index = ISMEMINDEXSUB (2)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%d,%s,<<,%s,%c,%s,=",
								LSHIFT2 (2), REG (2), MEMBASE (1), op_index, MEMBASE (1));
						}
					} else if (ISPREINDEX32 ()) {
						if (HASMEMINDEX (1)) {
							const char op_index = ISMEMINDEXSUB (1)? '-': '+';
							r_strbuf_appendf (&op->esil, ",%d,%s,<<,%s,%c,%s,=",
								LSHIFT2 (1), MEMINDEX (1), MEMBASE (1), op_index, MEMBASE (1));
						} else {
							r_strbuf_appendf (&op->esil, ",%s,%d,+,%s,=",
								MEMBASE (1), MEMDISP (1), MEMBASE (1));
						}
					}
				}
			}
		}
		break;
	case ARM_INS_MRS:
		// TODO: esil for MRS
		break;
	case ARM_INS_MSR:
		msr_flags = insn->detail->arm.operands[0].reg >> 4;
		r_strbuf_append (&op->esil, "0,");
		if (msr_flags & 1) {
			r_strbuf_append (&op->esil, "0xff,|,");
		}
		if (msr_flags & 2) {
			r_strbuf_append (&op->esil, "0xff00,|,");
		}
		if (msr_flags & 4) {
			r_strbuf_append (&op->esil, "0xff0000,|,");
		}
		if (msr_flags & 8) {
			r_strbuf_append (&op->esil, "0xff000000,|,");
		}
		r_strbuf_appendf (&op->esil, "DUP,!,SWAP,&,%s,SWAP,cpsr,&,|,cpsr,=", REG(1));
		break;
	case ARM_INS_UBFX:
		if (IMM (3) > 0 && IMM (3) <= 32 - IMM (2)) {
			size_t index = IMM (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			r_strbuf_appendf (&op->esil, "%d,%s,%d,%"PFMT64u",<<,&,>>,%s,=",
				IMM(2), REG(1), IMM(2), bitmask_by_width[index], REG(0));
		}
		break;
	case ARM_INS_UXTB:
		r_strbuf_appendf (&op->esil, "%s,0xff,&,%s,=", ARG(1), REG(0));
		break;
	case ARM_INS_RSB:
		if (OPCOUNT () == 2) {
			r_strbuf_appendf (&op->esil, "%s,%s,-=", ARG(0), ARG(1));
		} else if (OPCOUNT () == 3) {
			r_strbuf_appendf (&op->esil, "%s,%s,-,%s,=", ARG(1), ARG(2), ARG(0));
		}
		break;
	case ARM_INS_BIC:
		if (OPCOUNT () == 2) {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&=", ARG(1), ARG(0));
		} else {
			r_strbuf_appendf (&op->esil, "%s,0xffffffff,^,%s,&,%s,=", ARG(2), ARG(1), ARG(0));
		}
		break;
	case ARM_INS_SMMLA:
		r_strbuf_appendf (&op->esil, "32,%s,%s,*,>>,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_SMMLAR:
		r_strbuf_appendf (&op->esil, "32,0x80000000,%s,%s,*,+,>>,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_UMULL:
		r_strbuf_appendf (&op->esil, "32,%s,%s,*,DUP,0xffffffff,&,%s,=,>>,%s,=",
			REG(2), REG(3), REG(0), REG(1));
		break;
	case ARM_INS_MLS:
		r_strbuf_appendf (&op->esil, "%s,%s,*,%s,-,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_MLA:
		r_strbuf_appendf (&op->esil, "%s,%s,*,%s,+,0xffffffff,&,%s,=",
			REG(1), REG(2), REG(3), REG(0));
		break;
	case ARM_INS_MVN:
		r_strbuf_appendf (&op->esil, "-1,%s,^,0xffffffff,&,%s,=",
			ARG(1), REG(0));
		break;
	case ARM_INS_BFI:
	{
		if (OPCOUNT() >= 3 && ISIMM(3) && IMM(3) > 0 && IMM(3) < 64) {
			size_t index = IMM (3) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			ut64 mask = bitmask_by_width[index];
			ut64 shift = IMM(2);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,lsb,mask,src,&,<<,|,dst,=
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,&,%"PFMT64u",%"PFMT64u",%s,&,<<,|,0xffffffff,&,%s,=",
				notmask, REG(0), shift, mask, REG(1), REG(0));
		}
		break;
	}
	case ARM_INS_BFC:
	{
		if (OPCOUNT() >= 2 && ISIMM(2) && IMM(2) > 0 && IMM(2) < 64) {
			size_t index = IMM (2) - 1;
			if (index >= BITMASK_BY_WIDTH_COUNT) {
				index = 0;
			}
			ut64 mask = bitmask_by_width[IMM(2) - 1];
			ut64 shift = IMM(1);
			ut64 notmask = ~(mask << shift);
			// notmask,dst,&,dst,=
			r_strbuf_setf (&op->esil, "%"PFMT64u",%s,&,0xffffffff,&,%s,=",
				notmask, REG(0), REG(0));
		}
		break;
	}
	case ARM_INS_REV:
	{
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		r_strbuf_setf (&op->esil,
			"24,0xff,%s,&,<<,%s,=,"
			"16,0xff,8,%s,>>,&,<<,%s,|=,"
			"8,0xff,16,%s,>>,&,<<,%s,|=,"
			"0xff,24,%s,>>,&,%s,|=,",
			r1, r0, r1, r0, r1, r0, r1, r0);
		break;
	}
	case ARM_INS_REV16:
	{
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		r_strbuf_setf (&op->esil,
			"8,0xff00ff00,%s,&,>>,%s,=,"
			"8,0x00ff00ff,%s,&,<<,%s,|=,",
			r1, r0, r1, r0);
		break;
	}
	case ARM_INS_REVSH:
	{
		const char *r0 = REG(0);
		const char *r1 = REG(1);
		r_strbuf_setf (&op->esil,
			"8,0xff00,%s,&,>>,%s,=,"
			"8,0x00ff,%s,&,<<,%s,|=,"
			"0x8000,%s,&,?{,"
				"0xffff0000,%s,|=,"
			"}",
			r1, r0, r1, r0, r0, r0);
		break;
	}
	case ARM_INS_TBB:
		r_strbuf_appendf (&op->esil, "%s,%s,+,0xffffffff,&,DUP,[1],1,SWAP,<<,+,pc,+=",
			MEMBASE (0), MEMINDEX (0));
		break;
	case ARM_INS_TBH:
		r_strbuf_appendf (&op->esil, "%s,%d,%s,<<,+,0xffffffff,&,[2],1,SWAP,<<,pc,+=",
			MEMBASE (0), LSHIFT2 (0), MEMINDEX (0));
		break;
	default:
		break;
	}
	// Update flags if required...TODO different instructions update different flags, but this should fix
	// many errors
	if (insn->detail->arm.update_flags) {
		switch(insn->id) {
		case ARM_INS_CMP:
			r_strbuf_append (&op->esil, ",$z,zf,:=,31,$s,nf,:=,32,$b,!,cf,:=,31,$o,vf,:=");
			break;
		case ARM_INS_ADD:
		case ARM_INS_RSB:
		case ARM_INS_SUB:
		case ARM_INS_SBC:
		case ARM_INS_ADC:
		case ARM_INS_CMN:
			r_strbuf_append (&op->esil, ",$z,zf,:=,31,$s,nf,:=,31,$c,cf,:=,31,$o,vf,:=");
			break;
		default:
			r_strbuf_append (&op->esil, ",$z,zf,:=,31,$s,nf,:=");
		}
	}

	r_strbuf_append (&op->esil, postfix);

	return 0;
}

static int cond_cs2r2(int cc) {
	if (cc == ARM_CC_AL || cc < 0) {
		cc = R_ANAL_CONDTYPE_AL;
	} else {
		switch (cc) {
		case ARM_CC_EQ: cc = R_ANAL_CONDTYPE_EQ; break;
		case ARM_CC_NE: cc = R_ANAL_CONDTYPE_NE; break;
		case ARM_CC_HS: cc = R_ANAL_CONDTYPE_HS; break;
		case ARM_CC_LO: cc = R_ANAL_CONDTYPE_LO; break;
		case ARM_CC_MI: cc = R_ANAL_CONDTYPE_MI; break;
		case ARM_CC_PL: cc = R_ANAL_CONDTYPE_PL; break;
		case ARM_CC_VS: cc = R_ANAL_CONDTYPE_VS; break;
		case ARM_CC_VC: cc = R_ANAL_CONDTYPE_VC; break;
		case ARM_CC_HI: cc = R_ANAL_CONDTYPE_HI; break;
		case ARM_CC_LS: cc = R_ANAL_CONDTYPE_LS; break;
		case ARM_CC_GE: cc = R_ANAL_CONDTYPE_GE; break;
		case ARM_CC_LT: cc = R_ANAL_CONDTYPE_LT; break;
		case ARM_CC_GT: cc = R_ANAL_CONDTYPE_GT; break;
		case ARM_CC_LE: cc = R_ANAL_CONDTYPE_LE; break;
		}
	}
	return cc;
}

static void anop64(csh handle, RAnalOp *op, cs_insn *insn) {
	ut64 addr = op->addr;

	/* grab family */
	if (cs_insn_group (handle, insn, ARM64_GRP_CRC )) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
#if CS_API_MAJOR < 6
	// XXX - Can't find ARM64 feature crypto in cs6 arm64
	} else if (cs_insn_group (handle, insn, ARM64_GRP_CRYPTO)) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
#endif
#if CS_API_MAJOR >= 4
	} else if (cs_insn_group (handle, insn, ARM64_GRP_PRIVILEGE)) {
		op->family = R_ANAL_OP_FAMILY_PRIV;
#endif
	} else if (cs_insn_group (handle, insn, ARM64_GRP_NEON)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
	} else if (cs_insn_group (handle, insn, ARM64_GRP_FPARMV8)) {
		op->family = R_ANAL_OP_FAMILY_FPU;
	} else {
		op->family = R_ANAL_OP_FAMILY_CPU;
	}

	op->cond = cond_cs2r2 (insn->detail->arm64.cc);
	if (op->cond == R_ANAL_CONDTYPE_NV) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return;
	}

	switch (insn->detail->arm64.cc) {
	case ARM64_CC_GE:
	case ARM64_CC_GT:
	case ARM64_CC_LE:
	case ARM64_CC_LT:
		op->sign = true;
		break;
	default:
		break;
	}

	switch (insn->id) {
#if CS_API_MAJOR > 4
	case ARM64_INS_UDF:
		op->type = R_ANAL_OP_TYPE_ILL;
		break;
	case ARM64_INS_PACDA:
	case ARM64_INS_PACDB:
	case ARM64_INS_PACDZA:
	case ARM64_INS_PACDZB:
	case ARM64_INS_PACGA:
	case ARM64_INS_PACIA:
	case ARM64_INS_PACIA1716:
	case ARM64_INS_PACIASP:
	case ARM64_INS_PACIAZ:
	case ARM64_INS_PACIB:
	case ARM64_INS_PACIB1716:
	case ARM64_INS_PACIBSP:
	case ARM64_INS_PACIBZ:
	case ARM64_INS_PACIZA:
	case ARM64_INS_PACIZB:
	case ARM64_INS_AUTDA:
	case ARM64_INS_AUTDB:
	case ARM64_INS_AUTDZA:
	case ARM64_INS_AUTDZB:
	case ARM64_INS_AUTIA:
	case ARM64_INS_AUTIA1716:
	case ARM64_INS_AUTIASP:
	case ARM64_INS_AUTIAZ:
	case ARM64_INS_AUTIB:
	case ARM64_INS_AUTIB1716:
	case ARM64_INS_AUTIBSP:
	case ARM64_INS_AUTIBZ:
	case ARM64_INS_AUTIZA:
	case ARM64_INS_AUTIZB:
	case ARM64_INS_XPACD:
	case ARM64_INS_XPACI:
	case ARM64_INS_XPACLRI:
		op->type = R_ANAL_OP_TYPE_CMP;
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		break;
#endif
	case ARM64_INS_SVC:
		op->type = R_ANAL_OP_TYPE_SWI;
		op->val = IMM64(0);
		break;
	case ARM64_INS_ADRP:
	case ARM64_INS_ADR:
		op->type = R_ANAL_OP_TYPE_LEA;
		op->ptr = IMM64(1);
		break;
	case ARM64_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
		break;
	case ARM64_INS_SUB:
		if (ISREG64(0) && (arm64_reg) REGID64(0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM64(1)) {
				//sub sp, 0x54
				op->stackptr = IMM(1);
			} else if (ISIMM64(2) && ISREG64(1) && (arm64_reg) REGID64(1) == ARM64_REG_SP) {
				//sub sp, sp, 0x10
				op->stackptr = IMM64(2);
			}
			op->val = op->stackptr;
		} else {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_MSUB:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM64_INS_FDIV:
	case ARM64_INS_SDIV:
	case ARM64_INS_UDIV:
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case ARM64_INS_MUL:
	case ARM64_INS_SMULL:
	case ARM64_INS_FMUL:
	case ARM64_INS_UMULL:
		/* TODO: if next instruction is also a MUL, cycles are /=2 */
		/* also known as Register Indexing Addressing */
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_ADDG:
#endif
	case ARM64_INS_ADD:
		if (ISREG64 (0) && (arm64_reg) REGID64 (0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM64 (1)) {
				//add sp, 0x54
				op->stackptr = -(st64)IMM (1);
			} else if (ISIMM64 (2) && ISREG64 (1) && (arm64_reg) REGID64 (1) == ARM64_REG_SP) {
				//add sp, sp, 0x10
				op->stackptr = -(st64)IMM64 (2);
			}
			// op->val = op->stackptr;
		} else if ((arm64_reg) REGID64 (0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		} else {
			if (ISIMM64 (2)) {
				op->val = IMM64 (2);
			} else {
				op->val = 0;
			}
		}
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM64_INS_ADC:
	//case ARM64_INS_ADCS:
	case ARM64_INS_UMADDL:
	case ARM64_INS_SMADDL:
	case ARM64_INS_FMADD:
	case ARM64_INS_MADD:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM64_INS_CSEL:
	case ARM64_INS_FCSEL:
	case ARM64_INS_CSET:
	case ARM64_INS_CINC:
		op->type = R_ANAL_OP_TYPE_CMOV;
		break;
#if 0
	case ARM64_INS_BTI:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		break;
#endif
	case ARM64_INS_MOV:
		if ((arm64_reg) REGID64(0) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_RESET;
			op->stackptr = 0;
		}
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_MOVI:
	case ARM64_INS_MOVK:
	case ARM64_INS_MOVN:
	case ARM64_INS_SMOV:
	case ARM64_INS_UMOV:
	case ARM64_INS_FMOV:
	case ARM64_INS_SBFX:
	case ARM64_INS_UBFX:
	case ARM64_INS_UBFM:
	case ARM64_INS_BFI:
	case ARM64_INS_SBFIZ:
	case ARM64_INS_UBFIZ:
	case ARM64_INS_BIC:
	case ARM64_INS_BFXIL:
		op->type = R_ANAL_OP_TYPE_MOV;
		if (ISIMM64 (1)) {
			op->val = IMM64(1);
		}
		break;
	case ARM64_INS_MRS:
	case ARM64_INS_MSR:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	case ARM64_INS_MOVZ:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 8;
		op->val = IMM64(1);
		break;
	case ARM64_INS_UXTB:
	case ARM64_INS_SXTB:
		op->type = R_ANAL_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM64_INS_UXTH:
	case ARM64_INS_SXTH:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM64_INS_UXTW:
	case ARM64_INS_SXTW:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->ptr = 0LL;
		op->ptrsize = 4;
		break;
	case ARM64_INS_BRK:
	case ARM64_INS_HLT:
		op->type = R_ANAL_OP_TYPE_TRAP;
		// hlt stops the process, not skips some cycles like in x86
		break;
	case ARM64_INS_DMB:
	case ARM64_INS_DSB:
	case ARM64_INS_ISB:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		// intentional fallthrough
	case ARM64_INS_IC: // instruction cache invalidate
	case ARM64_INS_DC: // data cache invalidate
		op->type = R_ANAL_OP_TYPE_SYNC; // or cache
		break;
	//  XXX unimplemented instructions
	case ARM64_INS_DUP:
	case ARM64_INS_XTN:
	case ARM64_INS_XTN2:
	case ARM64_INS_REV64:
	case ARM64_INS_EXT:
	case ARM64_INS_INS:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_INS_LSL:
		op->cycles = 1;
		/* fallthru */
	case ARM64_INS_SHL:
	case ARM64_INS_USHLL:
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ARM64_INS_LSR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ARM64_INS_ASR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case ARM64_INS_NEG:
#if CS_API_MAJOR > 3
	case ARM64_INS_NEGS:
#endif
		op->type = R_ANAL_OP_TYPE_NOT;
		break;
	case ARM64_INS_CMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		if (ISIMM64 (1)) {
			op->val = IMM64 (1);
		}
		break;
	case ARM64_INS_FCMP:
	case ARM64_INS_CCMP:
	case ARM64_INS_CCMN:
	case ARM64_INS_CMN:
	case ARM64_INS_TST:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM64_INS_ROR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case ARM64_INS_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case ARM64_INS_ORR:
	case ARM64_INS_ORN:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case ARM64_INS_EOR:
	case ARM64_INS_EON:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ARM64_INS_STRB:
	case ARM64_INS_STURB:
	case ARM64_INS_STUR:
	case ARM64_INS_STR:
	case ARM64_INS_STP:
	case ARM64_INS_STNP:
	case ARM64_INS_STXR:
	case ARM64_INS_STXRH:
	case ARM64_INS_STLXR:
	case ARM64_INS_STLXRH:
	case ARM64_INS_STXRB:
		op->type = R_ANAL_OP_TYPE_STORE;
		if (ISPREINDEX64 () && (arm64_reg) REGBASE64 (2) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP64 (2);
		} else if (ISPOSTINDEX64 () && (arm64_reg) REGID64 (2) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)IMM64 (3);
		} else if (ISPREINDEX64 () && (arm64_reg) REGBASE64 (1) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP64 (1);
		} else if (ISPOSTINDEX64 () && (arm64_reg) REGID64 (1) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)IMM64 (2);
		}
		break;
	case ARM64_INS_LDUR:
	case ARM64_INS_LDURB:
	case ARM64_INS_LDRSW:
	case ARM64_INS_LDRSB:
	case ARM64_INS_LDRSH:
	case ARM64_INS_LDR:
	case ARM64_INS_LDURSW:
	case ARM64_INS_LDP:
	case ARM64_INS_LDNP:
	case ARM64_INS_LDPSW:
	case ARM64_INS_LDRH:
	case ARM64_INS_LDRB:
		op->type = R_ANAL_OP_TYPE_LOAD;
		if (ISPREINDEX64 () && (arm64_reg) REGBASE64 (2) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP64 (2);
		} else if (ISPOSTINDEX64 () && (arm64_reg) REGID64 (2) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)IMM64 (3);
		} else if (ISPREINDEX64 () && (arm64_reg) REGBASE64 (1) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)MEMDISP64 (1);
		} else if (ISPOSTINDEX64 () && (arm64_reg) REGID64 (1) == ARM64_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			op->stackptr = -(st64)IMM64 (2);
		}
		if (REGID(0) == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_MJMP;
			if ((arm_cc)insn->detail->arm.cc != ARM_CC_AL) {
				op->type = R_ANAL_OP_TYPE_MCJMP;
			}
		} else {
			op->type = R_ANAL_OP_TYPE_LOAD;
		}
		switch (insn->id) {
		case ARM64_INS_LDPSW:
		case ARM64_INS_LDRSW:
		case ARM64_INS_LDRSH:
		case ARM64_INS_LDRSB:
			op->sign = true;
			break;
		}
		if ((arm64_reg) REGBASE64(1) == ARM64_REG_X29) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = MEMDISP64(1);
		} else {
			if (ISMEM64 (1)) {
				// op->type = R_ANAL_OP_TYPE_LEA;
				op->disp = MEMDISP64 (1);
				op->refptr = 8;
			} else if (ISIMM64 (1)) {
				// op->type = R_ANAL_OP_TYPE_LEA;
				op->ptr = IMM64 (1);
				op->refptr = 8;
			} else {
				int d = (int)MEMDISP64(1);
				op->ptr = (d < 0)? -d: d;
				op->refptr = 4;
			}
		}
		break;
#if CS_API_MAJOR > 4
	case ARM64_INS_IRG:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM64_INS_BLRAA:
	case ARM64_INS_BLRAAZ:
	case ARM64_INS_BLRAB:
	case ARM64_INS_BLRABZ:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RCALL;
		break;
	case ARM64_INS_BRAA:
	case ARM64_INS_BRAAZ:
	case ARM64_INS_BRAB:
	case ARM64_INS_BRABZ:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RJMP;
		op->reg = cs_reg_name (handle, insn->detail->arm64.operands[0].reg);
		op->ireg = cs_reg_name (handle, insn->detail->arm64.operands[1].reg);
		break;
	case ARM64_INS_LDRAA:
	case ARM64_INS_LDRAB:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_LOAD;
		break;
	case ARM64_INS_RETAA:
	case ARM64_INS_RETAB:
	case ARM64_INS_ERETAA:
	case ARM64_INS_ERETAB:
		op->family = R_ANAL_OP_FAMILY_SECURITY;
		op->type = R_ANAL_OP_TYPE_RET;
		break;
#endif
	case ARM64_INS_ERET:
		op->family = R_ANAL_OP_FAMILY_PRIV;
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case ARM64_INS_RET:
		op->type = R_ANAL_OP_TYPE_RET;
		break;
	case ARM64_INS_BL: // bl 0x89480
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM64(0);
		op->fail = addr + 4;
		break;
	case ARM64_INS_BLR: // blr x0
		op->type = R_ANAL_OP_TYPE_RCALL;
		op->fail = addr + 4;
		//op->jump = IMM64(0);
		break;
	case ARM64_INS_CBZ:
	case ARM64_INS_CBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM64(1);
		op->fail = addr + op->size;
		break;
	case ARM64_INS_TBZ:
	case ARM64_INS_TBNZ:
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM64(2);
		op->fail = addr + op->size;
		break;
	case ARM64_INS_BR:
		// op->type = R_ANAL_OP_TYPE_UJMP; // RJMP ?
		op->type = R_ANAL_OP_TYPE_RJMP;
		op->eob = true;
		op->reg = cs_reg_name (handle, insn->detail->arm64.operands[0].reg);
		break;
	case ARM64_INS_B:
		// BX LR == RET
		if ((arm64_reg) insn->detail->arm64.operands[0].reg == ARM64_REG_LR) {
			op->type = R_ANAL_OP_TYPE_RET;
		} else if (insn->detail->arm64.cc) {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->jump = IMM64(0);
			op->fail = addr + op->size;
		} else {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->jump = IMM64(0);
		}
		break;
	default:
		R_LOG_DEBUG ("ARM64 analysis: Op type %d at 0x%" PFMT64x " not handled", insn->id, op->addr);
		break;
	}
}

static void anal_itblock(RArchSession *as, cs_insn *insn) {
	size_t i, size =  r_str_nlen (insn->mnemonic, 5);
	HtUU *ht_itblock = ht_itblock_for_session (as);
	HtUU *ht_it = ht_it_for_session (as);
	ht_uu_update (ht_itblock, insn->address,  size);
	for (i = 1; i < size; i++) {
		switch (insn->mnemonic[i]) {
		case 0x74: //'t'
			ht_uu_update (ht_it, insn->address + (i * insn->size), insn->detail->arm.cc);
			break;
		case 0x65: //'e'
			ht_uu_update (ht_it, insn->address + (i * insn->size), (insn->detail->arm.cc % 2)?
				insn->detail->arm.cc + 1: insn->detail->arm.cc - 1);
			break;
		default:
			break;
		}
	}
}

static void check_itblock(RArchSession *as, cs_insn *insn) {
	HtUU *ht_itblock = ht_itblock_for_session (as);
	HtUU *ht_it = ht_it_for_session (as);
	bool found;
	ut64 itlen = ht_uu_find (ht_itblock, insn->address, &found);
	if (found) {
		size_t x;
		for (x = 1; x < itlen; x++) {
			ht_uu_delete (ht_it, insn->address + (x*insn->size));
		}
		ht_uu_delete (ht_itblock, insn->address);
	}
}

static void anop32(RArchSession *as, csh handle, RAnalOp *op, cs_insn *insn, bool thumb, const ut8 *buf, int len) {
	const ut64 addr = op->addr;
	const int pcdelta = thumb? 4: 8;
	int i;

	op->cond = cond_cs2r2 (insn->detail->arm.cc);
	if (op->cond == R_ANAL_CONDTYPE_NV) {
		op->type = R_ANAL_OP_TYPE_NOP;
		return;
	}
	op->cycles = 1;
	/* grab family */
	if (cs_insn_group (handle, insn, ARM_GRP_CRC)) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
#if CS_API_MAJOR < 6
	// XXX - I can't find crypto in cs6
	} else if (cs_insn_group (handle, insn, ARM_GRP_CRYPTO)) {
		op->family = R_ANAL_OP_FAMILY_CRYPTO;
#endif
#if CS_API_MAJOR >= 4
	} else if (cs_insn_group (handle, insn, ARM_GRP_PRIVILEGE)) {
		op->family = R_ANAL_OP_FAMILY_PRIV;
#if CS_API_MAJOR < 6
	// XXX - I can't find virtualization in cs6
	} else if (cs_insn_group (handle, insn, ARM_GRP_VIRTUALIZATION)) {
		op->family = R_ANAL_OP_FAMILY_VIRT;
#endif
#endif
	} else if (cs_insn_group (handle, insn, ARM_GRP_NEON)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
	} else if (cs_insn_group (handle, insn, ARM_GRP_FPARMV8)) {
		op->family = R_ANAL_OP_FAMILY_FPU;
#if CS_API_MAJOR < 6
	// XXX - I can't find thumb2dsp in cs6
	} else if (cs_insn_group (handle, insn, ARM_GRP_THUMB2DSP)) {
		op->family = R_ANAL_OP_FAMILY_VEC;
#endif
	} else {
		op->family = R_ANAL_OP_FAMILY_CPU;
	}

	if (insn->id != ARM_INS_IT) {
		check_itblock (as, insn);
	}

	switch (insn->id) {
#if 0

If PC is specified for Rn, the value used is the address of the instruction plus 4.

These instructions cause a PC-relative forward branch using a table of single byte offsets (TBB) or halfword offsets (TBH). Rn provides a pointer to the table, and Rm supplies an index into the table. The branch length is twice the value of the byte (TBB) or the halfword (TBH) returned from the table. The target of the branch table must be in the same execution state.

jmp $$ + 4 + ( [delta] * 2 )

#endif
	case ARM_INS_TBH: // half word table
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->cycles = 2;
		op->ptrsize = 2;
		op->ireg = r_str_getf (cs_reg_name (handle, INSOP (0).mem.index));
		break;
	case ARM_INS_TBB: // byte jump table
		op->type = R_ANAL_OP_TYPE_UJMP;
		op->cycles = 2;
		op->ptrsize = 1;
		op->ireg = r_str_getf (cs_reg_name (handle, INSOP (0).mem.index));
		break;
	case ARM_INS_PLD:
		op->type = R_ANAL_OP_TYPE_LEA; // not really a lea, just a prefetch
		if (ISMEM (0)) {
			int regBase = REGBASE(0);
			int delta = MEMDISP(0);
			if (regBase == ARM_REG_PC) {
				op->ptr = addr + 4 + delta;
			} else {
				// exotic pld
			}
		}
		break;
	case ARM_INS_IT:
		anal_itblock (as, insn);
		op->cycles = 2;
		break;
	case ARM_INS_BKPT:
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->cycles = 4;
		break;
	case ARM_INS_NOP:
		op->type = R_ANAL_OP_TYPE_NOP;
		op->cycles = 1;
		break;
	case ARM_INS_POP:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = -4LL * insn->detail->arm.op_count;
		// fallthrough
	case ARM_INS_FLDMDBX:
	case ARM_INS_FLDMIAX:
	case ARM_INS_LDMDA:
	case ARM_INS_LDMDB:
	case ARM_INS_LDMIB:
	case ARM_INS_LDM:
		op->type = R_ANAL_OP_TYPE_POP;
		op->cycles = 2;
		for (i = 0; i < insn->detail->arm.op_count; i++) {
			if (insn->detail->arm.operands[i].type == ARM_OP_REG &&
					insn->detail->arm.operands[i].reg == ARM_REG_PC) {
				if ((arm_cc)insn->detail->arm.cc == ARM_CC_AL) {
					op->type = R_ANAL_OP_TYPE_RET;
				} else {
					op->type = R_ANAL_OP_TYPE_CRET;
				}
				break;
			}
		}
		break;
	case ARM_INS_SUB:
		if (ISREG (0) && REGID (0) == ARM_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM (1)) {
				//0x0000bf4e      95b0           sub sp, 0x54
				op->stackptr = IMM (1);
			} else if (ISIMM (2) && ISREG (1) && REGID (1) == ARM_REG_SP) {
				// 0x00008254    10d04de2     sub sp, sp, 0x10
				op->stackptr = IMM (2);
			}
			op->val = op->stackptr;
		} else {
			op->val = IMM64 (2);
		}
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM_INS_SUBW:
	case ARM_INS_SSUB8:
	case ARM_INS_SSUB16:
		op->type = R_ANAL_OP_TYPE_SUB;
		break;
	case ARM_INS_ADD:
		if (ISREG (0) && REGID (0) == ARM_REG_SP) {
			op->stackop = R_ANAL_STACK_INC;
			if (ISIMM (1)) {
				//add sp, 0x54
				op->stackptr = -(st64)IMM (1);
			} else if (ISIMM (2) && ISREG (1) && REGID (1) == ARM_REG_SP) {
				//add sp, sp, 0x10
				op->stackptr = -(st64)IMM (2);
			}
			// op->val = op->stackptr;
		} else {
			ut64 v = IMM (2);
			if (v) {
				op->val = v;
			}
		}
		op->cycles = 1;
		// fallthru
	case ARM_INS_ADC:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ADD;
		if (REGID (0) == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_RJMP;
			if (REGID (1) == ARM_REG_PC && (arm_cc)insn->detail->arm.cc != ARM_CC_AL) {
				op->type = R_ANAL_OP_TYPE_RCJMP;
				op->fail = addr+op->size;
				op->jump = ((addr & ~3LL) + (thumb? 4: 8) + MEMDISP(1)) & UT64_MAX;
				op->ptr = (addr & ~3LL) + (thumb? 4: 8) + MEMDISP(1);
				op->refptr = 4;
				op->reg = r_str_getf (cs_reg_name (handle, INSOP (2).reg));
				break;
			}
		}
		break;
	case ARM_INS_ADDW:
	case ARM_INS_SADD8:
	case ARM_INS_SADD16:
		op->type = R_ANAL_OP_TYPE_ADD;
		break;
	case ARM_INS_SDIV:
	case ARM_INS_UDIV:
		op->cycles = 4;
		/* fall-thru */
	case ARM_INS_VDIV:
		op->type = R_ANAL_OP_TYPE_DIV;
		break;
	case ARM_INS_MUL:
	case ARM_INS_SMULL:
	case ARM_INS_UMULL:
		/* TODO: if next instruction is also a MUL, cycles are /=2 */
		/* also known as Register Indexing Addressing */
		op->cycles = 4;
		/* fall-thru */
	case ARM_INS_VMUL:
		op->type = R_ANAL_OP_TYPE_MUL;
		break;
	case ARM_INS_TRAP:
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->cycles = 2;
		break;
	case ARM_INS_MOV:
		if (REGID(0) == ARM_REG_PC) {
			if (REGID(1) == ARM_REG_LR) {
				op->type = op->cond == R_ANAL_CONDTYPE_AL ? R_ANAL_OP_TYPE_RET : R_ANAL_OP_TYPE_CRET;
			} else {
				op->type = op->cond == R_ANAL_CONDTYPE_AL ? R_ANAL_OP_TYPE_RJMP : R_ANAL_OP_TYPE_RCJMP;
			}
		} else {
			op->type = op->cond == R_ANAL_CONDTYPE_AL ? R_ANAL_OP_TYPE_MOV : R_ANAL_OP_TYPE_CMOV;
		}
		if (ISIMM(1)) {
			op->val = IMM(1);
		}
		break;
	case ARM_INS_MOVT:
	case ARM_INS_MOVW:
	case ARM_INS_VMOVL:
	case ARM_INS_VMOVN:
	case ARM_INS_VQMOVUN:
	case ARM_INS_VQMOVN:
	case ARM_INS_SBFX:
	case ARM_INS_UBFX:
	case ARM_INS_BIC:
	case ARM_INS_BFI:
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM_INS_VMOV:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_FPU;
		op->cycles = 2;
		break;
	case ARM_INS_UDF:
		op->type = R_ANAL_OP_TYPE_TRAP;
		op->cycles = 4;
		break;
	case ARM_INS_SVC:
		if ((arm_cc)insn->detail->arm.cc == ARM_CC_AL) {
			op->type = R_ANAL_OP_TYPE_SWI;
		} else {
			op->type = R_ANAL_OP_TYPE_CSWI;
		}
		op->val = IMM (0);
		break;
	case ARM_INS_ROR:
	case ARM_INS_RRX:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_ROR;
		break;
	case ARM_INS_AND:
		op->type = R_ANAL_OP_TYPE_AND;
		break;
	case ARM_INS_ORR:
	case ARM_INS_ORN:
		op->type = R_ANAL_OP_TYPE_OR;
		break;
	case ARM_INS_EOR:
		op->type = R_ANAL_OP_TYPE_XOR;
		break;
	case ARM_INS_CMP:
	case ARM_INS_CMN:
	case ARM_INS_TST:
		if (ISIMM(1)) {
			op->val = IMM(1);
		}
		op->reg = r_str_getf (cs_reg_name (handle, INSOP (0).reg));
		/* fall-thru */
	case ARM_INS_VCMP:
		op->type = R_ANAL_OP_TYPE_CMP;
		break;
	case ARM_INS_LSL:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SHL;
		break;
	case ARM_INS_LSR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SHR;
		break;
	case ARM_INS_ASR:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_SAR;
		break;
	case ARM_INS_PUSH:
		op->stackop = R_ANAL_STACK_INC;
		op->stackptr = 4LL * insn->detail->arm.op_count;
		op->type = R_ANAL_OP_TYPE_PUSH;
		break;
	case ARM_INS_STM:
	case ARM_INS_STMDA:
	case ARM_INS_STMDB:
		op->type = R_ANAL_OP_TYPE_PUSH;
// 0x00008160    04202de5     str r2, [sp, -4]!
// 0x000082a0    28000be5     str r0, [fp, -0x28]
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = MEMDISP(1);
		}
		break;
	case ARM_INS_STREX:
	case ARM_INS_STREXB:
	case ARM_INS_STREXD:
	case ARM_INS_STREXH:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		/* fall-thru */
	case ARM_INS_STR:
	case ARM_INS_STRB:
	case ARM_INS_STRD:
	case ARM_INS_STRBT:
	case ARM_INS_STRH:
	case ARM_INS_STRHT:
	case ARM_INS_STRT:
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_STORE;
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_SET;
			op->stackptr = 0;
			op->ptr = (ut64)-MEMDISP (1);
		}
		break;
	case ARM_INS_SXTB:
	case ARM_INS_SXTH:
		op->cycles = 1;
		op->type = R_ANAL_OP_TYPE_MOV;
		break;
	case ARM_INS_LDREX:
	case ARM_INS_LDREXB:
	case ARM_INS_LDREXD:
	case ARM_INS_LDREXH:
		op->family = R_ANAL_OP_FAMILY_THREAD;
		/* fall-thru */
	case ARM_INS_LDR:
	case ARM_INS_LDRD:
	case ARM_INS_LDRB:
	case ARM_INS_LDRBT:
	case ARM_INS_LDRH:
	case ARM_INS_LDRHT:
	case ARM_INS_LDRSB:
	case ARM_INS_LDRSBT:
	case ARM_INS_LDRSH:
	case ARM_INS_LDRSHT:
	case ARM_INS_LDRT:
		op->cycles = 4;
// 0x000082a8    28301be5     ldr r3, [fp, -0x28]
		if (REGID(0) == ARM_REG_PC) {
			op->type = R_ANAL_OP_TYPE_MJMP;
			if ((arm_cc)insn->detail->arm.cc != ARM_CC_AL) {
				//op->type = R_ANAL_OP_TYPE_MCJMP;
				op->type = R_ANAL_OP_TYPE_MCJMP;
			}
		} else {
			op->type = R_ANAL_OP_TYPE_LOAD;
		}
		switch (insn->id) {
		case ARM_INS_LDRB:
			op->ptrsize = 1;
			break;
		case ARM_INS_LDRH:
		case ARM_INS_LDRHT:
			op->ptrsize = 2;
			break;
		}
		if (REGBASE(1) == ARM_REG_FP) {
			op->stackop = R_ANAL_STACK_GET;
			op->stackptr = 0;
			op->ptr = -MEMDISP (1);
		} else if (REGBASE(1) == ARM_REG_PC) {
			op->ptr = (addr & ~3LL) + (thumb? 4: 8) + MEMDISP (1);
			op->refptr = 4;
			if (REGID(0) == ARM_REG_PC && (arm_cc)insn->detail->arm.cc != ARM_CC_AL) {
				//op->type = R_ANAL_OP_TYPE_MCJMP;
				op->type = R_ANAL_OP_TYPE_UCJMP;
				op->fail = addr+op->size;
				op->jump = ((addr & ~3LL) + (thumb? 4: 8) + MEMDISP (1)) & UT64_MAX;
				op->ireg = r_str_getf (cs_reg_name (handle, INSOP (1).mem.index));
				break;
			}
		}
		break;
	case ARM_INS_MRS:
	case ARM_INS_MSR:
		op->type = R_ANAL_OP_TYPE_MOV;
		op->family = R_ANAL_OP_FAMILY_PRIV;
		break;
	case ARM_INS_BLX:
		op->cycles = 4;
		if (ISREG(0)) {
			/* blx reg */
			op->type = R_ANAL_OP_TYPE_RCALL;
		} else {
			/* blx label */
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = IMM(0) & UT32_MAX;
			op->fail = addr + op->size;
			op->hint.new_bits = as->config->bits == 32? 16 : 32;
			//switch instruction set always with blx label
			// r_anal_hint_set_bits (a, op->jump, a->config->bits == 32? 16 : 32);
		}
		break;
	case ARM_INS_BL:
		/* bl label */
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = IMM(0) & UT32_MAX;
		op->fail = addr + op->size;
		op->hint.new_bits = as->config->bits;
		break;
	case ARM_INS_CBZ:
	case ARM_INS_CBNZ:
		op->cycles = 4;
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = IMM (1) & UT32_MAX;
		op->fail = addr + op->size;
		if (op->jump == op->fail) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		}
		break;
	case ARM_INS_B:
		/* b.cc label */
		op->cycles = 4;
		if ((arm_cc)insn->detail->arm.cc == ARM_CC_INVALID) {
			op->type = R_ANAL_OP_TYPE_ILL;
			op->fail = addr+op->size;
		} else if ((arm_cc)insn->detail->arm.cc == ARM_CC_AL) {
			op->type = R_ANAL_OP_TYPE_JMP;
			op->fail = UT64_MAX;
		} else {
			op->type = R_ANAL_OP_TYPE_CJMP;
			op->fail = addr+op->size;
		}
		op->jump = IMM(0) & UT32_MAX;
		// propagate bits to create correctly hints ranges
		op->hint.new_bits = as->config->bits;
		break;
	case ARM_INS_BX:
	case ARM_INS_BXJ:
		/* bx reg */
		op->cycles = 4;
		switch (REGID(0)) {
		case ARM_REG_LR:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case ARM_REG_IP:
			op->type = R_ANAL_OP_TYPE_UJMP;
			break;
		case ARM_REG_PC:
			// bx pc is well known without ESIL
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->jump = (addr & ~3LL) + pcdelta;
			op->hint.new_bits = 32;
			break;
		default:
			op->type = R_ANAL_OP_TYPE_UJMP;
			op->eob = true;
			break;
		}
		break;
	case ARM_INS_ADR:
		op->cycles = 2;
		op->type = R_ANAL_OP_TYPE_LEA;
		// Set the pointer address and align it
		op->ptr = IMM(1) + addr + 4 - (addr%4);
		op->refptr = 1;
		break;
	case ARM_INS_UXTAB:
	case ARM_INS_UXTAB16:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM_INS_UXTAH:
		op->type = R_ANAL_OP_TYPE_ADD;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	case ARM_INS_UXTB:
	case ARM_INS_UXTB16:
		op->type = R_ANAL_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 1;
		break;
	case ARM_INS_UXTH:
		op->type = R_ANAL_OP_TYPE_CAST;
		op->ptr = 0LL;
		op->ptrsize = 2;
		break;
	default:
		R_LOG_DEBUG ("ARM analysis: Op type %d at 0x%" PFMT64x " not handled", insn->id, op->addr);
		break;
	}
#if 0
	// TODO needs rewrite
	bool found = 0;
	ut64 itcond;
	HtUU *ht_it = ht_it_for_session (as);
	itcond = ht_uu_find (ht_it,  addr, &found);
	if (found) {
		insn->detail->arm.cc = itcond;
		insn->detail->arm.update_flags = 0;
		free (op->mnemonic);
		op->mnemonic = r_str_newf ("%s%s%s%s",
			r_arch_optype_tostring (op->type),
			cc_name (itcond),
			insn->op_str[0]? " ": "",
			insn->op_str);
		op->cond = itcond;
	}
#endif
}

#if 1
// TODO arch plugins should NOT set register values
static inline bool is_valid(arm_reg reg) {
	return reg != ARM_REG_INVALID;
}

// XXX this function is a disaster
static int parse_reg_name(const char **reg_base, const char **reg_delta, csh handle, cs_insn *insn, int reg_num) {
	cs_arm_op armop = INSOP (reg_num);
	switch (armop.type) {
	case ARM_OP_REG:
		*reg_base = cs_reg_name (handle, armop.reg);
		break;
	case ARM_OP_MEM:
		if (is_valid (armop.mem.base) && is_valid (armop.mem.index)) {
			*reg_base = cs_reg_name (handle, armop.mem.base);
			*reg_delta = cs_reg_name (handle, armop.mem.index);
		} else if (is_valid (armop.mem.base)) {
			*reg_base = cs_reg_name (handle, armop.mem.base);
		} else if (is_valid (armop.mem.index)) {
			*reg_base = cs_reg_name (handle, armop.mem.index);
		}
		break;
	default:
		break;
	}

	return 0;
}

static bool is_valid64(arm64_reg reg) {
	return reg != ARM64_REG_INVALID;
}

static const char *reg_list[] = {
	"x0", "x1", "x2", "x3", "x4",
	"x5", "x6", "x7", "x8", "x9",
	"x10", "x11", "x12", "x13", "x14",
	"x15", "x16", "x17", "x18", "x19",
	"x20", "x21", "x22", "x23", "x24",
	"x25", "x26", "x27", "x28", "x29",
	"x30"
};

static int parse_reg64_name(const char** reg_base, const char **reg_delta, csh handle, cs_insn *insn, int reg_num) {
	cs_arm64_op armop = INSOP64 (reg_num);
	switch (armop.type) {
	case ARM64_OP_REG:
		*reg_base = cs_reg_name (handle, armop.reg);
		break;
	case ARM64_OP_MEM:
		if (is_valid64 (armop.mem.base) && is_valid64 (armop.mem.index)) {
			*reg_base = cs_reg_name (handle, armop.mem.base);
			*reg_delta = cs_reg_name (handle, armop.mem.index);
		} else if (is_valid64 (armop.mem.base)) {
			*reg_base = cs_reg_name (handle, armop.mem.base);
		} else if (is_valid64 (armop.mem.index)) {
			*reg_base = cs_reg_name (handle, armop.mem.index);
		}
		break;
	default:
		break;
	}
	if (*reg_base && **reg_base == 'w') {
		*reg_base = reg_list [atoi ((*reg_base) + 1)]; // XXX dont use atoi
	}
	return 0;
}
#endif

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
	case R_ANAL_OP_TYPE_RJMP:
	case R_ANAL_OP_TYPE_MJMP:
	case R_ANAL_OP_TYPE_UCALL:
		op->direction = R_ANAL_OP_DIR_EXEC;
		break;
	default:
		break;
	}
}

#if 1
// TODO arch plugins should NOT set register values
static void set_src_dst(RAnalValue *val, csh *handle, cs_insn *insn, int x, int bits) {
	if (!val) {
		return;
	}
	cs_arm_op armop = INSOP (x);
	cs_arm64_op arm64op = INSOP64 (x);
	if (bits == 64) {
		parse_reg64_name ((const char **)&val->reg, (const char **)&val->regdelta, *handle, insn, x);
	} else {
		parse_reg_name ((const char**)&val->reg, (const char**)&val->regdelta, *handle, insn, x);
	}
	if (bits == 64) {
		switch (arm64op.type) {
		case ARM64_OP_REG:
			break;
		case ARM64_OP_MEM:
			val->delta = arm64op.mem.disp;
			break;
		case ARM64_OP_IMM:
			val->imm = arm64op.imm;
			break;
		default:
			break;
		}
	} else {
		switch (armop.type) {
		case ARM_OP_REG:
			break;
		case ARM_OP_MEM:
			val->mul = armop.mem.scale;
			val->delta = armop.mem.disp;
			break;
		case ARM_OP_IMM:
			val->imm = armop.imm;
			break;
		default:
			break;
		}
	}
}
#endif

static void create_src_dst(RAnalOp *op) {
	r_vector_push (&op->srcs, NULL);
	r_vector_push (&op->srcs, NULL);
	r_vector_push (&op->srcs, NULL);
	r_vector_push (&op->dsts, NULL);
}

static void op_fillval(RArchSession *as, RAnalOp *op, csh handle, cs_insn *insn, int bits) {
	create_src_dst (op);
	int i;
	int count = bits == 64 ? insn->detail->arm64.op_count : insn->detail->arm.op_count;
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
		for (i = 1; i < count; i++) {
			if (bits == 64) {
				cs_arm64_op arm64op = INSOP64 (i);
				if (arm64op.access == CS_AC_WRITE) {
					continue;
				}
			} else {
				cs_arm_op armop = INSOP (i);
				if (armop.access == CS_AC_WRITE) {
					continue;
				}
			}
			break;
		}
		// TODO arch plugins should NOT set register values
		{
			int j;
			for (j = 0; j < 3; j++, i++) {
				set_src_dst (r_vector_at (&op->srcs, j), &handle, insn, i, bits);
			}
			set_src_dst (r_vector_at (&op->dsts, 0), &handle, insn, 0, bits);
		}
		break;
	case R_ANAL_OP_TYPE_STORE:
		if (count > 2) {
			if (bits == 64) {
				cs_arm64_op arm64op = INSOP64 (count - 1);
				if ((arm64_op_type) arm64op.type == ARM64_OP_IMM) {
					count--;
				}
			} else {
				cs_arm_op armop = INSOP (count - 1);
				if (armop.type == ARM_OP_IMM) {
					count--;
				}
			}
		}
		// TODO arch plugins should NOT set register values
		{
			set_src_dst (r_vector_at (&op->dsts, 0), &handle, insn, --count, bits);
			int j;
			for (j = 0; j < 3 && j < count; j++) {
				set_src_dst (r_vector_at (&op->srcs, j), &handle, insn, j, bits);
			}
		}
		break;
	default:
		break;
	}
	if ((bits == 64) && HASMEMINDEX64 (1)) {
		op->ireg = r_str_getf (cs_reg_name (handle, INSOP64 (1).mem.index));
	} else if (HASMEMINDEX (1)) {
		op->ireg = r_str_getf (cs_reg_name (handle, INSOP (1).mem.index));
		op->scale = INSOP (1).mem.scale;
	}
}

static inline bool is_valid_mnemonic(const char *m) {
	return !r_str_startswith (m, "hint") && !r_str_startswith (m, "udf");
}

static int analop(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	csh *cs_handle = cs_handle_for_session (as);
	cs_insn *insn = NULL;
	op->size = (as->config->bits == 16)? 2: 4;
	op->addr = addr;
	if (!buf) {
		buf = op->bytes;
		len = op->size;
	}
	int n = cs_disasm (*cs_handle, (ut8*)buf, len, addr, 1, &insn);
	if (n > 0 && is_valid_mnemonic (insn->mnemonic)) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			free (op->mnemonic);
			op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic,
				insn->op_str[0]? " ": "",
				insn->op_str);
			r_str_replace_char (op->mnemonic, '#', '\x00');
		}
		//bool thumb = cs_insn_group (cs_handle, insn, ARM_GRP_THUMB);
		bool thumb = as->config->bits == 16;
		op->size = insn->size;
		op->id = insn->id;
		if (as->config->bits == 64) {
			anop64 (*cs_handle, op, insn);
			if (mask & R_ARCH_OP_MASK_OPEX) {
				opex64 (&op->opex, *cs_handle, insn);
			}
			if (mask & R_ARCH_OP_MASK_ESIL) {
				analop64_esil (as, op, addr, buf, len, cs_handle, insn);
			}
		} else {
			anop32 (as, *cs_handle, op, insn, thumb, (ut8*)buf, len);
			if (mask & R_ARCH_OP_MASK_OPEX) {
				opex (&op->opex, *cs_handle, insn);
			}
			if (mask & R_ARCH_OP_MASK_ESIL) {
				analop_esil (as, op, addr, buf, len, cs_handle, insn, thumb);
			}
		}
		set_opdir (op);
		if (mask & R_ARCH_OP_MASK_VAL) {
			op_fillval (as, op, *cs_handle, insn, as->config->bits);
		}
		cs_free (insn, n);
	} else {
		cs_free (insn, n);
		op->size = 4;
		op->type = R_ANAL_OP_TYPE_ILL;
		if (len < 4) {
			if (mask & R_ARCH_OP_MASK_DISASM) {
				free (op->mnemonic);
				op->mnemonic = strdup ("invalid");
			}
			return -1;
		}
		hacky_arm_anal (as, op, buf, len);
		if (mask & R_ARCH_OP_MASK_DISASM) {
			if (hacky_arm_asm (as, op, buf, len) < 1) {
				free (op->mnemonic);
				op->mnemonic = strdup ("invalid");
			} else if (op->type == R_ANAL_OP_TYPE_ILL) {
				op->type = R_ANAL_OP_TYPE_UNK;	// this is because hacky_arm_anal and hacky_arm_asm work differently
			}
		}
	}
	return true;
}

static bool plugin_changed(RArchSession *as) {
	PluginData *pd = as->data;
	if (as->config->bits != pd->bits) {
		return true;
	}
	if (R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config) != pd->bigendian) {
		return true;
	}
	if (pd->cpu && as->config->cpu && strcmp (pd->cpu, as->config->cpu)) {
		return true;
	}
	return false;
}

static bool init(RArchSession *as);
static bool fini(RArchSession *as);

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	if (plugin_changed (as)) {
		fini (as);
		init (as);
	}
	csh *handle = cs_handle_for_session (as);
	if (as->config->syntax == R_ARCH_SYNTAX_REGNUM) {
		cs_option (*handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
	} else {
		cs_option (*handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_DEFAULT);
	}
	return analop (as, op, op->addr, op->bytes, op->size, mask) >= 1;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_DATA_ALIGN:
	case R_ARCH_INFO_INVOP_SIZE:
	case R_ARCH_INFO_MAXOP_SIZE:
		break;
	case R_ARCH_INFO_MINOP_SIZE:
	case R_ARCH_INFO_CODE_ALIGN:
		if (as->config && as->config->bits == 16) {
			return 2;
		}
		break;
	}
	return 4; // XXX
}

#include "preludes.inc.c"

extern char *r_arm_cs_mnemonics(RArchSession *as, csh *cs_handle, int id, bool json);
extern char *r_arm64_cs_mnemonics(RArchSession *as, csh *cs_handle, int id, bool json);

static char *arm_mnemonics(RArchSession *as, int id, bool json) {
	csh *cs_handle = cs_handle_for_session (as);
	if (as->config->bits == 64) {
		return r_arm64_cs_mnemonics (as, cs_handle, id, json);
	}
	return r_arm_cs_mnemonics (as, cs_handle, id, json);
}

extern bool r_arm_arch_cs_init(RArchSession *as, csh *cs_handle);
extern bool r_arm64_arch_cs_init(RArchSession *as, csh *cs_handle);

static inline bool cs_init(RArchSession *as, csh *cs_handle) {
	if (as->config->bits == 64) {
		return r_arm64_arch_cs_init (as, cs_handle);
	}
	return r_arm_arch_cs_init (as, cs_handle);
}

static bool init(RArchSession* as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (PluginData);
	csh *cs_handle = cs_handle_for_session (as);
	if (!cs_init (as, cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}

	PluginData *pd = as->data;
	pd->bits = as->config->bits;
	pd->bigendian = R_ARCH_CONFIG_IS_BIG_ENDIAN (as->config);
	pd->cpu = as->config->cpu? strdup (as->config->cpu): NULL;
	pd->ht_it = ht_uu_new0 ();
	if (!pd->ht_it) {
		R_LOG_ERROR ("Cannot initialize 'ht_it'");
		cs_close (&(pd->cs_handle));
		R_FREE (as->data);
		return false;
	}

	pd->ht_itblock = ht_uu_new0 ();
	if (!pd->ht_itblock) {
		R_LOG_ERROR ("Cannot initialize 'ht_itblock'");
		ht_uu_free (pd->ht_it);
		cs_close (&(pd->cs_handle));
		R_FREE (as->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);

	PluginData *pd = (PluginData*) as->data;
	ht_uu_free (pd->ht_itblock);
	ht_uu_free (pd->ht_it);
	free (pd->cpu);
	cs_close (&(pd->cs_handle));
	R_FREE (as->data);
	return true;
}

const RArchPlugin r_arch_plugin_arm_cs = {
	.meta = {
		.name = "arm",
		.desc = "Capstone ARM analyzer",
		.license = "Apache-2.0",
	},
	.arch = "arm",
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.cpus = "cortex,v8",
#if 0
	// made obsolete by "e anal.mask = true"
	.anal_mask = anal_mask,
#endif
	.preludes = anal_preludes,
	.decode = decode,
	.init = init,
	.fini = fini,
	.info = archinfo,
	.regs = regs,
	.mnemonics = arm_mnemonics,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_arm_cs,
	.version = R2_VERSION
};
#endif
