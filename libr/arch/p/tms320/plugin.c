/*
 * TMS320 disassembly analyzer
 *
 * Written by Ilya V. Matveychikov <i.matveychikov@milabs.ru>
 *
 * Distributed under LGPL
 */

#include <r_arch.h>
#include "tms320_dasm.h"

typedef struct plugin_data_t PluginData;

static tms320_dasm_t *tms320_engine_for_session(RArchSession *as);

typedef int (* TMS_ANAL_OP_FN)(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask);

static int tms320_c54x_op(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask);
static int tms320_c55x_op(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask);

static int tms320_c55x_plus_op(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *_buf, int len, RAnalOpMask mask) {
	if (!_buf || len < 1) {
		return 0;
	}
	ut8 buf[16] = {0};
	memcpy (buf, _buf, R_MIN (len, sizeof (buf)));
	ut16 _ins = r_read_le16 (buf);
	ut16 *ins = &_ins;

	op->size = 1;

	tms320_dasm_t *engine = tms320_engine_for_session (as);
	int ins_len = tms320_dasm (engine, buf, len);
	if (ins_len <= 0) {
		return 0;
	}
	op->size = ins_len;
	op->addr = addr;
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = strdup (engine->syntax);
	}

	if (ins_len == 1) {
		if (*ins == 0x20) {
			op->type = R_ANAL_OP_TYPE_NOP;
		} else if (*ins == 0x21) {
			op->type = R_ANAL_OP_TYPE_RET;
		}
	} else if (ins_len >= 4 && buf[0] == 0xD8) {
		//  BCC conditional absolute jump
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];
	} else if (ins_len >= 2 && buf[0] == 0x6A) {
		//  BCC conditional relative jump
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + ((st8)buf[1]) + ins_len;
	} else if (ins_len >= 3 && buf[0] == 0x9A) {
		// BCC conditional relative jump
		op->type = R_ANAL_OP_TYPE_CJMP;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;
	} else if (ins_len >= 4 && buf[0] == 0x9C) {
		// B unconditional absolute jump
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];
	} else if (ins_len >= 3 && buf[0] == 0x68) {
		// B unconditional relative jump
		op->type = R_ANAL_OP_TYPE_JMP;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;
 	} else if (ins_len == 2 && buf[0] == 0x02) {
		// CALL unconditional absolute call with acumulator register ACx

		op->type = R_ANAL_OP_TYPE_UCALL;
		op->fail = addr + ins_len;
 	} else if (ins_len >= 3 && buf[0] == 0x69) {
		// CALL unconditional relative call
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;
 	} else if (ins_len >= 3 && buf[0] == 0x9D) {
		// CALL unconditional absolute call
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];
 	} else if (ins_len >= 3 && buf[0] == 0x9B) {
		// CALLCC conditional relative call
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = addr + (st16)((buf[1] << 8) | buf[2]) + ins_len;
 	} else if (ins_len >= 4 && buf[0] == 0xD9) {
		// CALLCC conditional absolute call
		op->type = R_ANAL_OP_TYPE_CALL;
		op->jump = (buf[1] << 16) | (buf[2] << 8) | buf[3];
	} else {
		op->type = R_ANAL_OP_TYPE_UNK;
	}
	return op->size;
}

// c64x
#include <capstone/capstone.h>

#ifdef CAPSTONE_TMS320C64X_H
#define CAPSTONE_HAS_TMS320C64X 1
#else
#define CAPSTONE_HAS_TMS320C64X 0
#warning Cannot find capstone-tms320c64x support
#endif

#if CS_API_MAJOR < 2
#undef CAPSONT_HAS_TMS320C64X
#define CAPSTONE_HAS_TMS320C64X 0
#endif


#if CAPSTONE_HAS_TMS320C64X

#define INSOP(n) insn->detail->tms320c64x.operands[n]
#define INSCC insn->detail->tms320c64x.cc

static void opex(RStrBuf *buf, csh handle, cs_insn *insn) {
	int i;
	PJ *pj = pj_new ();
	if (!pj) {
		return;
	}
	pj_o (pj);
	pj_ka (pj, "operands");
	if (insn->detail) {
		cs_tms320c64x *x = &insn->detail->tms320c64x;
		for (i = 0; i < x->op_count; i++) {
			cs_tms320c64x_op *op = x->operands + i;
			pj_o (pj);
			switch (op->type) {
			case TMS320C64X_OP_REG:
				pj_ks (pj, "type", "reg");
				pj_ks (pj, "value", cs_reg_name (handle, op->reg));
				break;
			case TMS320C64X_OP_IMM:
				pj_ks (pj, "type", "imm");
				pj_ki (pj, "value", op->imm);
				break;
			case TMS320C64X_OP_MEM:
				pj_ks (pj, "type", "mem");
				if (op->mem.base != SPARC_REG_INVALID) {
					pj_ks (pj, "base", cs_reg_name (handle, op->mem.base));
				}
				pj_kN (pj, "disp", (st64)op->mem.disp);
				break;
			default:
				pj_ks (pj, "type", "invalid");
				break;
			}
			pj_end (pj); /* o operand */
		}
	}
	pj_end (pj); /* a operands */
	pj_end (pj);

	r_strbuf_init (buf);
	r_strbuf_append (buf, pj_string (pj));
	pj_free (pj);
}

#define CSINC_MODE CS_MODE_BIG_ENDIAN
#define CSINC TMS320C64X
#include "../capstone.inc.c"

typedef struct plugin_data_t {
	CapstonePluginData cpd;
	tms320_dasm_t engine;
} PluginData;

static tms320_dasm_t *tms320_engine_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	PluginData *pd = as->data;
	return &pd->engine;
}

static csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, 0);
	CapstonePluginData *pd = as->data;
	return pd->cs_handle;
}

static int tms320c64x_analop(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	csh handle = cs_handle_for_session (as);
	if (handle == 0) {
		return -1;
	}
	int ret = cs_open (CS_ARCH_TMS320C64X, 0, &handle);
	if (ret != CS_ERR_OK) {
		return -1;
	}
	cs_insn *insn = NULL;
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	int n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
	} else {
		if (mask & R_ARCH_OP_MASK_OPEX) {
			opex (&op->opex, handle, insn);
		}
		if (mask & R_ARCH_OP_MASK_DISASM) {
			// this is a bug in capstone, disassembling needs to use detail=off to avoid appending the instruction suffix
			cs_insn *deinsn = NULL;
			cs_option (handle, CS_OPT_DETAIL, CS_OPT_OFF);
			int n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &deinsn);
			if (n > 0) {
				char *str = r_str_newf ("%s%s%s", deinsn->mnemonic, deinsn->op_str[0]? " ": "", deinsn->op_str);
				r_str_replace_char (str, '%', 0);
				r_str_case (str, false);
				op->mnemonic = str;
			} else {
				op->mnemonic = strdup ("invalid");
			}
			cs_free (deinsn, n);
		}
		op->size = insn->size;
		op->id = insn->id;
		switch (insn->id) {
		case TMS320C64X_INS_INVALID:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		case TMS320C64X_INS_AND:
		case TMS320C64X_INS_ANDN:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case TMS320C64X_INS_NOT:
			op->type = R_ANAL_OP_TYPE_NOT;
			break;
		case TMS320C64X_INS_NEG:
			op->type = R_ANAL_OP_TYPE_NOT;
			break;
		case TMS320C64X_INS_SWAP2:
		case TMS320C64X_INS_SWAP4:
		op->type = R_ANAL_OP_TYPE_MOV;
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case TMS320C64X_INS_BNOP:
		case TMS320C64X_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case TMS320C64X_INS_CMPEQ:
		case TMS320C64X_INS_CMPEQ2:
		case TMS320C64X_INS_CMPEQ4:
		case TMS320C64X_INS_CMPGT:
		case TMS320C64X_INS_CMPGT2:
		case TMS320C64X_INS_CMPGTU4:
		case TMS320C64X_INS_CMPLT:
		case TMS320C64X_INS_CMPLTU:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case TMS320C64X_INS_B:
			op->type = R_ANAL_OP_TYPE_JMP;
			// higher 32bits of the 64bit address is lost, lets clone
			if (insn->detail) {
				op->jump = INSOP(0).imm + (addr & 0xFFFFFFFF00000000);
			}
			break;
		case TMS320C64X_INS_LDB:
		case TMS320C64X_INS_LDBU:
		case TMS320C64X_INS_LDDW:
		case TMS320C64X_INS_LDH:
		case TMS320C64X_INS_LDHU:
		case TMS320C64X_INS_LDNDW:
		case TMS320C64X_INS_LDNW:
		case TMS320C64X_INS_LDW:
		case TMS320C64X_INS_LMBD:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case TMS320C64X_INS_STB:
		case TMS320C64X_INS_STDW:
		case TMS320C64X_INS_STH:
		case TMS320C64X_INS_STNDW:
		case TMS320C64X_INS_STNW:
		case TMS320C64X_INS_STW:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case TMS320C64X_INS_OR:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case TMS320C64X_INS_SSUB:
		case TMS320C64X_INS_SUB:
		case TMS320C64X_INS_SUB2:
		case TMS320C64X_INS_SUB4:
		case TMS320C64X_INS_SUBAB:
		case TMS320C64X_INS_SUBABS4:
		case TMS320C64X_INS_SUBAH:
		case TMS320C64X_INS_SUBAW:
		case TMS320C64X_INS_SUBC:
		case TMS320C64X_INS_SUBU:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case TMS320C64X_INS_ADD:
		case TMS320C64X_INS_ADD2:
		case TMS320C64X_INS_ADD4:
		case TMS320C64X_INS_ADDAB:
		case TMS320C64X_INS_ADDAD:
		case TMS320C64X_INS_ADDAH:
		case TMS320C64X_INS_ADDAW:
		case TMS320C64X_INS_ADDK:
		case TMS320C64X_INS_ADDKPC:
		case TMS320C64X_INS_ADDU:
		case TMS320C64X_INS_SADD:
		case TMS320C64X_INS_SADD2:
		case TMS320C64X_INS_SADDU4:
		case TMS320C64X_INS_SADDUS2:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		}
		cs_free (insn, n);
	}
	return op->size;
}
#endif

static bool match(const char * str, const char *token) {
	return !strncasecmp (str, token, strlen (token));
}

static int tms320_c54x_op(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	tms320_dasm_t *engine = tms320_engine_for_session (as);
	op->size = tms320_dasm (engine, buf, len);
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = strdup (engine->syntax);
	}
	return op->size;
}

static int tms320_c55x_op(RArchSession *as, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	tms320_dasm_t *engine = tms320_engine_for_session (as);
	const char *str = engine->syntax;

	op->delay = 0;
	op->size = tms320_dasm (engine, buf, len);
	op->type = R_ANAL_OP_TYPE_NULL;

	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = strdup (str);
	}

	str = strstr (str, "||") ? str + 3 : str;
	if (match (str, "B ")) {
		op->type = R_ANAL_OP_TYPE_JMP;
		if (match (str, "B AC")) {
			op->type = R_ANAL_OP_TYPE_UJMP;
		}
	} else if (match (str, "BCC ") || match (str, "BCCU ")) {
		op->type = R_ANAL_OP_TYPE_CJMP;
	} else if (match (str, "CALL ")) {
		op->type = R_ANAL_OP_TYPE_CALL;
		if (match (str, "CALL AC")) {
			op->type = R_ANAL_OP_TYPE_UCALL;
		}
	} else if (match (str, "CALLCC ")) {
		op->type = R_ANAL_OP_TYPE_CCALL;
	} else if (match (str, "RET")) {
		op->type = R_ANAL_OP_TYPE_RET;
		if (match (str, "RETCC")) {
			op->type = R_ANAL_OP_TYPE_CRET;
		}
	} else if (match (str, "MOV ")) {
		op->type = R_ANAL_OP_TYPE_MOV;
	} else if (match (str, "PSHBOTH ")) {
		op->type = R_ANAL_OP_TYPE_UPUSH;
	} else if (match (str, "PSH ")) {
		op->type = R_ANAL_OP_TYPE_PUSH;
	} else if (match (str, "POPBOTH ") || match (str, "POP ")) {
		op->type = R_ANAL_OP_TYPE_POP;
	} else if (match (str, "CMP ")) {
		op->type = R_ANAL_OP_TYPE_CMP;
	} else if (match (str, "CMPAND ")) {
		op->type = R_ANAL_OP_TYPE_ACMP;
	} else if (match (str, "NOP")) {
		op->type = R_ANAL_OP_TYPE_NOP;
	} else if (match (str, "INTR ")) {
		op->type = R_ANAL_OP_TYPE_SWI;
	} else if (match (str, "TRAP ")) {
		op->type = R_ANAL_OP_TYPE_TRAP;
	} else if (match (str, "INVALID")) {
		op->type = R_ANAL_OP_TYPE_UNK;
	}

	return op->size;
}

static bool decode(RArchSession *as, RAnalOp *op, RAnalOpMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	op->size = 2;
	const char *cpu = as->config->cpu;
#ifdef CAPSTONE_TMS320C64X_H
	// default to c64x if available
	TMS_ANAL_OP_FN aop = tms320c64x_analop;
#else
	TMS_ANAL_OP_FN aop = tms320_c55x_op;
#endif
	if (R_STR_ISNOTEMPTY (cpu)) {
		tms320_dasm_t *engine = tms320_engine_for_session (as);
		if (!r_str_casecmp (cpu, "c64x")) {
#ifdef CAPSTONE_TMS320C64X_H
			aop = tms320c64x_analop;
#else
			return false;
#endif
		} else if (!r_str_casecmp (cpu, "c54x")) {
			tms320_f_set_cpu (engine, TMS320_F_CPU_C54X);
			aop = tms320_c54x_op;
		} else if (!r_str_casecmp (cpu, "c55x")) {
			tms320_f_set_cpu (engine, TMS320_F_CPU_C55X);
			aop = tms320_c55x_op;
		} else if (!r_str_casecmp (cpu, "c55x+")) {
			tms320_f_set_cpu (engine, TMS320_F_CPU_C55X_PLUS);
			aop = tms320_c55x_plus_op;
		}
	}
	ut8 mbuf[4];
	const ut8 *lbuf = buf;
	if (len > 3 && as->config->big_endian & R_SYS_ENDIAN_BIG) {
		mbuf[0] = buf[3];
		mbuf[1] = buf[2];
		mbuf[2] = buf[1];
		mbuf[3] = buf[0];
		lbuf = mbuf;
	}
	return aop (as, op, addr, lbuf, len, mask) > 0;
}

static bool tms320_init(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, false);
	if (as->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}

	as->data = R_NEW0 (PluginData);
	PluginData *pd = as->data;
	if (!r_arch_cs_init (as, &pd->cpd.cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (as->data);
		return false;
	}

	if (!tms320_dasm_init (&pd->engine)) {
		R_LOG_ERROR ("Cannot initialize tms320 engine");
		return false;
	}

	return true;
}

static bool tms320_fini(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as && as->data, false);

	PluginData *pd = as->data;
	cs_close (&pd->cpd.cs_handle);

	if (!tms320_dasm_fini (&pd->engine)) {
		R_LOG_ERROR ("Cannot shutdown tms320 engine");
	}

	R_FREE (as->data);
	return true;
}

static char *mnemonics(RArchSession *s, int id, bool json) {
	CapstonePluginData *cpd = (CapstonePluginData*)s->data;
	return r_arch_cs_mnemonics (s, cpd->cs_handle, id, json);
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_DATA_ALIGN:
		return 2;
	case R_ARCH_INFO_CODE_ALIGN:
		return 2;
	case R_ARCH_INFO_MAXOP_SIZE:
		return 8;
	case R_ARCH_INFO_INVOP_SIZE:
		return 2;
	case R_ARCH_INFO_MINOP_SIZE:
		return 2;
	}
	return 4;
}

const RArchPlugin r_arch_plugin_tms320 = {
	.meta = {
		.name = "tms320",
		.license = "LGPL-3.0-only",
#if CAPSTONE_HAS_TMS320C64X
		.desc = "TMS320 DSP family (c54x,c55x,c55x+,c64x)",
#else
		.desc = "TMS320 DSP family (c54x,c55x,c55x+)",
#endif
	},
	.arch = "tms320",
	.bits = R_SYS_BITS_PACK1 (32),
	.init = tms320_init,
	.fini = tms320_fini,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.info = archinfo,
#if CAPSTONE_HAS_TMS320C64X
	.cpus = "c54x,c55x,c55x+,c64x",
	.mnemonics = mnemonics,
#else
	.cpus = "c54x,c55x,c55x+",
#endif
	.decode = decode,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_tms320,
	.version = R2_VERSION
};
#endif
