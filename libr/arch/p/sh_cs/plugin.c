/* radare2 - LGPL - Copyright 2023-2025 - pancake */

#include <r_arch.h>
#include <r_lib.h>
#include <capstone/capstone.h>

#if CS_VERSION_MAJOR >= 5
#include <capstone/sh.h>

#if CS_API_MAJOR < 2
#error Old Capstone not supported
#endif

#define INSOP(n) insn->detail->sh.operands[n]

#define CSINC SH
#define CSINC_MODE 0
	// CS_MODE_BIG_ENDIAN
#include "../capstone.inc.c"

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	cs_sh *x = &insn->detail->sh;
	for (i = 0; i < x->op_count; i++) {
		cs_sh_op *op = x->operands + i;
		pj_o (pj);
		switch (op->type) {
		case SH_OP_REG:
			pj_ks (pj, "type", "reg");
			pj_ks (pj, "value", cs_reg_name (handle, op->reg));
			break;
		case SH_OP_IMM:
			pj_ks (pj, "type", "imm");
			pj_ki (pj, "value", op->imm);
			break;
		case SH_OP_MEM:
			pj_ks (pj, "type", "mem");
			switch (op->mem.address) {
			case SH_OP_MEM_INVALID:
				pj_ks (pj, "addr", "invalid");
				break;
			case SH_OP_MEM_REG_IND:   /// <= Register indirect
				pj_ks (pj, "addr", "reg.ind");
				break;
			case SH_OP_MEM_REG_POST:  /// <= Register post increment
				pj_ks (pj, "addr", "reg.post");
				break;
			case SH_OP_MEM_REG_PRE:   /// <= Register pre decrement
				pj_ks (pj, "addr", "reg.pre");
				break;
			case SH_OP_MEM_REG_DISP:  /// <= displacement
				pj_ks (pj, "addr", "reg.disp");
				break;
			case SH_OP_MEM_REG_R0:    /// <= R0 indexed
				pj_ks (pj, "addr", "gbr.r0");
				break;
			case SH_OP_MEM_GBR_DISP:  /// <= GBR based displacement
				pj_ks (pj, "addr", "gbr.disp");
				break;
			case SH_OP_MEM_GBR_R0:    /// <= GBR based R0 indexed
				pj_ks (pj, "addr", "gbr.r0");
				break;
			case SH_OP_MEM_PCR:       /// <= PC relative
				pj_ks (pj, "addr", "pcr");
				break;
			case SH_OP_MEM_TBR_DISP:  /// <= TBR based displaysment
				pj_ks (pj, "addr", "tbr.disp");
				break;
			}
			if (op->mem.reg != SH_REG_INVALID) {
				pj_ks (pj, "reg", cs_reg_name (handle, op->mem.reg));
			}
			pj_ki (pj, "disp", op->mem.disp);
			break;
		default:
			pj_ks (pj, "type", "invalid");
			break;
		}
		pj_end (pj); /* o operand */
	}
	pj_end (pj); /* a operands */
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

static csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;

	csh handle = cs_handle_for_session (as);
	if (handle == 0) {
		return false;
	}

	op->size = 2;
	cs_insn *insn;
	int n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		if (mask & R_ARCH_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = r_str_newf ("%s%s%s",
				insn->mnemonic, insn->op_str[0]? " ": "",
				insn->op_str);
			op->mnemonic = r_str_replace (op->mnemonic, ",", ", ", true);
			// op->mnemonic = r_str_replace (op->mnemonic, "@", "", true);
			op->mnemonic = r_str_replace (op->mnemonic, "#", "", true);
		}
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
#if 0
		case XCORE_INS_DRET:
		case XCORE_INS_KRET:
		case XCORE_INS_RETSP:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case XCORE_INS_DCALL:
		case XCORE_INS_KCALL:
		case XCORE_INS_ECALLF:
		case XCORE_INS_ECALLT:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = INSOP(0).imm;
			break;
		/* ??? */
		case XCORE_INS_BL:
		case XCORE_INS_BLA:
		case XCORE_INS_BLAT:
		case XCORE_INS_BT:
		case XCORE_INS_BF:
		case XCORE_INS_BU:
		case XCORE_INS_BRU:
			op->type = R_ANAL_OP_TYPE_CALL;
			op->jump = INSOP(0).imm;
			break;
		case XCORE_INS_SUB:
		case XCORE_INS_LSUB:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case XCORE_INS_ADD:
		case XCORE_INS_LADD:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
#endif
		case SH_INS_ADD_r:
		case SH_INS_ADD:
		case SH_INS_ADDC:
		case SH_INS_ADDV:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case SH_INS_AND:
		case SH_INS_BAND:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case SH_INS_BANDNOT:
		case SH_INS_BCLR:
		case SH_INS_BF:
		case SH_INS_BF_S:
		case SH_INS_BLD:
		case SH_INS_BLDNOT:
		case SH_INS_BOR:
		case SH_INS_BORNOT:
			break;
		case SH_INS_BRA:
		case SH_INS_BRAF:
			op->type = R_ANAL_OP_TYPE_JMP;
			// XXX op->jump = insn->detail->sh.operands[0].mem.address;
			break;
		case SH_INS_BSET:
		case SH_INS_BSR:
			op->type = R_ANAL_OP_TYPE_CALL;
			break;
		case SH_INS_BSRF:
		case SH_INS_BST:
		case SH_INS_BT:
		case SH_INS_BT_S:
		case SH_INS_BXOR:
		case SH_INS_CLIPS:
		case SH_INS_CLIPU:
		case SH_INS_CLRDMXY:
		case SH_INS_CLRMAC:
		case SH_INS_CLRS:
		case SH_INS_CLRT:
			break;
		case SH_INS_CMP_EQ:
		case SH_INS_CMP_GE:
		case SH_INS_CMP_GT:
		case SH_INS_CMP_HI:
		case SH_INS_CMP_HS:
		case SH_INS_CMP_PL:
		case SH_INS_CMP_PZ:
		case SH_INS_CMP_STR:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case SH_INS_DIV0S:
		case SH_INS_DIV0U:
		case SH_INS_DIV1:
		case SH_INS_DIVS:
		case SH_INS_DIVU:
			op->type = R_ANAL_OP_TYPE_DIV;
			break;
		case SH_INS_DMULS_L:
		case SH_INS_DMULU_L:
		case SH_INS_DT:
		case SH_INS_EXTS_B:
		case SH_INS_EXTS_W:
		case SH_INS_EXTU_B:
		case SH_INS_EXTU_W:
		case SH_INS_FABS:
		case SH_INS_FADD:
		case SH_INS_FCMP_EQ:
		case SH_INS_FCMP_GT:
		case SH_INS_FCNVDS:
		case SH_INS_FCNVSD:
		case SH_INS_FDIV:
		case SH_INS_FIPR:
		case SH_INS_FLDI0:
		case SH_INS_FLDI1:
		case SH_INS_FLDS:
		case SH_INS_FLOAT:
		case SH_INS_FMAC:
		case SH_INS_FMOV:
		case SH_INS_FMUL:
		case SH_INS_FNEG:
		case SH_INS_FPCHG:
		case SH_INS_FRCHG:
		case SH_INS_FSCA:
		case SH_INS_FSCHG:
		case SH_INS_FSQRT:
		case SH_INS_FSRRA:
		case SH_INS_FSTS:
		case SH_INS_FSUB:
		case SH_INS_FTRC:
		case SH_INS_FTRV:
		case SH_INS_ICBI:
			break;
		case SH_INS_JMP:
		case SH_INS_JSR:
		case SH_INS_JSR_N:
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case SH_INS_LDBANK:
		case SH_INS_LDC:
		case SH_INS_LDRC:
		case SH_INS_LDRE:
		case SH_INS_LDRS:
		case SH_INS_LDS:
		case SH_INS_LDTLB:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case SH_INS_MAC_L:
		case SH_INS_MAC_W:
		case SH_INS_MOV:
		case SH_INS_MOVA:
		case SH_INS_MOVCA:
		case SH_INS_MOVCO:
		case SH_INS_MOVI20:
		case SH_INS_MOVI20S:
		case SH_INS_MOVLI:
		case SH_INS_MOVML:
		case SH_INS_MOVMU:
		case SH_INS_MOVRT:
		case SH_INS_MOVT:
		case SH_INS_MOVU:
		case SH_INS_MOVUA:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case SH_INS_MUL_L:
		case SH_INS_MULR:
		case SH_INS_MULS_W:
		case SH_INS_MULU_W:
			op->type = R_ANAL_OP_TYPE_MUL;
			break;
		case SH_INS_NEG:
		case SH_INS_NEGC:
		case SH_INS_NOT:
		case SH_INS_NOTT:
			op->type = R_ANAL_OP_TYPE_NOT;
			break;
		case SH_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case SH_INS_OCBI:
		case SH_INS_OCBP:
		case SH_INS_OCBWB:
		case SH_INS_OR:
		case SH_INS_PREF:
		case SH_INS_PREFI:
		case SH_INS_RESBANK:
		case SH_INS_ROTCL:
		case SH_INS_ROTCR:
		case SH_INS_ROTL:
		case SH_INS_ROTR:
		case SH_INS_RTE:
		case SH_INS_RTS:
		case SH_INS_RTS_N:
		case SH_INS_RTV_N:
		case SH_INS_SETDMX:
		case SH_INS_SETDMY:
		case SH_INS_SETRC:
		case SH_INS_SETS:
		case SH_INS_SETT:
		case SH_INS_SHAD:
		case SH_INS_SHAL:
		case SH_INS_SHAR:
		case SH_INS_SHLD:
		case SH_INS_SHLL:
		case SH_INS_SHLL16:
		case SH_INS_SHLL2:
		case SH_INS_SHLL8:
		case SH_INS_SHLR:
		case SH_INS_SHLR16:
		case SH_INS_SHLR2:
		case SH_INS_SHLR8:
			break;
		case SH_INS_SLEEP:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case SH_INS_STBANK:
			break;
		case SH_INS_STC:
		case SH_INS_STS:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case SH_INS_SUB:
		case SH_INS_SUBC:
		case SH_INS_SUBV:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case SH_INS_SWAP_B:
		case SH_INS_SWAP_W:
		case SH_INS_SYNCO:
		case SH_INS_TAS:
			break;
		case SH_INS_TRAPA:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case SH_INS_TST:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case SH_INS_XOR:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case SH_INS_XTRCT:
		case SH_INS_DSP:
			break;
		case SH_INS_ENDING:   // <-- mark the end of the list of instructions
		case SH_INS_INVALID:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		}
		cs_free (insn, n);
	}
	return op->size > 0;
}

static int archinfo(RArchSession *as, ut32 q) {
	return 2;
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

static bool init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	as->data = R_NEW0 (CapstonePluginData);
	CapstonePluginData *cpd = (CapstonePluginData*)as->data;
	if (!r_arch_cs_init (as, &cpd->cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}
	return true;
}

static bool fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	CapstonePluginData *cpd = as->data;
	cs_close (&cpd->cs_handle);
	R_FREE (as->data);
	return true;
}

static char *regs(RArchSession *s) {
	const char * const p =
#include "../sh/regs.h"
	;
	return strdup (p);
}

const RArchPlugin r_arch_plugin_sh_cs = {
	.meta = {
		.name = "sh.cs",
		.desc = "Hitachi Super-H (capstone)",
		.license = "Apache-2.0",
	},
	.arch = "sh",
	.bits = R_SYS_BITS_PACK1 (32),
	.decode = decode,
	.info = archinfo,
	.regs = regs,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_sh_cs,
	.version = R2_VERSION
};
#endif

#else

const RArchPlugin r_arch_plugin_sh_cs = {
	0
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = 0,
	.data = &r_arch_plugin_sh_cs,
	.version = -1
};
#endif
#endif
