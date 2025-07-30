/* radare - LGPL - Copyright 2018-2025 - pancake, Sylvain Pelissier */

#include <r_arch.h>
#include <capstone/capstone.h>

#if CS_API_MAJOR >= 5 || (CS_API_MAJOR >= 4 && CS_API_MINOR >= 1)
#define CAPSTONE_HAS_MOS65XX 1
#else
#define CAPSTONE_HAS_MOS65XX 0
#endif

#if CAPSTONE_HAS_MOS65XX
#include <capstone/mos65xx.h>

#define CSINC MOS65XX
#include "../capstone.inc.c"

typedef struct plugin_data_t {
	CapstonePluginData cpd;
#if USE_ITER_API
	cs_insn *insn;
	int n;
#endif
} PluginData;

static inline csh cs_handle_for_session(RArchSession *as) {
	R_RETURN_VAL_IF_FAIL (as, 0);
	CapstonePluginData *cpd = as->data;
	return cpd->cs_handle;
}

static bool decode(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	const ut64 addr = op->addr;
	const ut8 *buf = op->bytes;
	const int len = op->size;
	csh handle = cs_handle_for_session (as);
	if (!handle) {
		return false;
	}

	int n;
	op->cycles = 1; // aprox
	// capstone-next
#if USE_ITER_API
	PluginData *pd = as->data;
	{
		ut64 naddr = addr;
		size_t size = len;
		n = cs_disasm_iter (handle, (const uint8_t**)&buf, &size, (uint64_t*)&naddr, pd->insn);
		pd->n = n;
	}
	cs_insn *insn = pd->insn;
#else
	cs_insn *insn = NULL;
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
#endif
	if (n < 1) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			op->mnemonic = strdup ("invalid");
		}
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			char *str = r_str_newf ("%s%s%s", insn->mnemonic, insn->op_str[0]? " ": "", insn->op_str);
			op->mnemonic = str;
		}
		op->nopcode = 1;
		op->size = insn->size;
		op->id = insn->id;
		op->family = R_ANAL_OP_FAMILY_CPU; // almost everything is CPU
		op->prefix = 0;
		op->cond = 0;
		switch (insn->id) {
		case MOS65XX_INS_INVALID:
			op->type = R_ANAL_OP_TYPE_ILL;
			break;
		case MOS65XX_INS_ADC:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case MOS65XX_INS_AND:
			op->type = R_ANAL_OP_TYPE_AND;
			break;
		case MOS65XX_INS_ASL:
			op->type = R_ANAL_OP_TYPE_SHL;
			break;
		case MOS65XX_INS_BCC:
		case MOS65XX_INS_BCS:
		case MOS65XX_INS_BEQ:
		case MOS65XX_INS_BIT:
		case MOS65XX_INS_BMI:
		case MOS65XX_INS_BNE:
		case MOS65XX_INS_BPL:
			op->type = R_ANAL_OP_TYPE_CJMP;
			break;
		case MOS65XX_INS_BRK:
			op->type = R_ANAL_OP_TYPE_TRAP;
			break;
		case MOS65XX_INS_BVC:
		case MOS65XX_INS_BVS:
			op->type = R_ANAL_OP_TYPE_RCJMP;
			break;
		case MOS65XX_INS_CLC:
		case MOS65XX_INS_CLD:
		case MOS65XX_INS_CLI:
		case MOS65XX_INS_CLV:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case MOS65XX_INS_CPX:
		case MOS65XX_INS_CPY:
		case MOS65XX_INS_CMP:
			op->type = R_ANAL_OP_TYPE_CMP;
			break;
		case MOS65XX_INS_DEC:
		case MOS65XX_INS_DEX:
		case MOS65XX_INS_DEY:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case MOS65XX_INS_EOR:
			op->type = R_ANAL_OP_TYPE_XOR;
			break;
		case MOS65XX_INS_INC:
		case MOS65XX_INS_INX:
		case MOS65XX_INS_INY:
			op->type = R_ANAL_OP_TYPE_ADD;
			break;
		case MOS65XX_INS_JMP:
			op->type = R_ANAL_OP_TYPE_JMP;
			break;
		case MOS65XX_INS_JSR:
			op->type = R_ANAL_OP_TYPE_RJMP;
			break;
		case MOS65XX_INS_LDA:
		case MOS65XX_INS_LDX:
		case MOS65XX_INS_LDY:
			op->type = R_ANAL_OP_TYPE_LOAD;
			break;
		case MOS65XX_INS_LSR:
		case MOS65XX_INS_NOP:
			op->type = R_ANAL_OP_TYPE_NOP;
			break;
		case MOS65XX_INS_ORA:
			op->type = R_ANAL_OP_TYPE_OR;
			break;
		case MOS65XX_INS_PHA:
		case MOS65XX_INS_PLA:
		case MOS65XX_INS_PHP:
		case MOS65XX_INS_PLP:
			op->type = R_ANAL_OP_TYPE_PUSH;
			break;
		case MOS65XX_INS_ROL:
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		case MOS65XX_INS_ROR:
			op->type = R_ANAL_OP_TYPE_ROR;
			break;
		case MOS65XX_INS_RTI:
		case MOS65XX_INS_RTS:
			op->type = R_ANAL_OP_TYPE_RET;
			break;
		case MOS65XX_INS_SBC:
			op->type = R_ANAL_OP_TYPE_SUB;
			break;
		case MOS65XX_INS_SEC:
		case MOS65XX_INS_SED:
		case MOS65XX_INS_SEI:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		case MOS65XX_INS_STA:
		case MOS65XX_INS_STX:
		case MOS65XX_INS_STY:
			op->type = R_ANAL_OP_TYPE_STORE;
			break;
		case MOS65XX_INS_TAX:
		case MOS65XX_INS_TAY:
		case MOS65XX_INS_TSX:
		case MOS65XX_INS_TXA:
		case MOS65XX_INS_TXS:
		case MOS65XX_INS_TYA:
			op->type = R_ANAL_OP_TYPE_MOV;
			break;
		}
	}
#if !USE_ITER_API
	cs_free (insn, n);
#endif
	return op->size > 0;
}

static char *regs(RArchSession *as) {
	char *p =
		"=PC	pc\n"
		"=SP	sp\n"
		"=A0	y\n"
		"=A1	x\n"
		"gpr	a	.8	0	0\n"
		"gpr	x	.8	1	0\n"
		"gpr	y	.8	2	0\n"

		"gpr	flags	.8	3	0\n"
		"gpr	C	.1	.24	0\n"
		"gpr	Z	.1	.25	0\n"
		"gpr	I	.1	.26	0\n"
		"gpr	D	.1	.27	0\n"
		// bit 4 (.28) is NOT a real flag.
		// "gpr	B	.1	.28	0\n"
		// bit 5 (.29) is not used
		"gpr	V	.1	.30	0\n"
		"gpr	N	.1	.31	0\n"
		"gpr	sp	.8	4	0\n"
		"gpr	pc	.16	5	0\n";
	return strdup (p);
}

static char *mnemonics(RArchSession *as, int id, bool json) {
	CapstonePluginData *cpd = as->data;
	return r_arch_cs_mnemonics (as, cpd->cs_handle, id, json);
}

static bool init(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	if (s->data) {
		R_LOG_WARN ("Already initialized");
		return false;
	}
	s->data = R_NEW0 (PluginData);
	PluginData *pd = s->data;
	if (!r_arch_cs_init (s, &pd->cpd.cs_handle)) {
		R_LOG_ERROR ("Cannot initialize capstone");
		R_FREE (s->data);
		return false;
	}
#if USE_ITER_API
	pd->insn = cs_malloc (pd->cpd.cs_handle);
	if (!pd->insn) {
		R_LOG_ERROR ("Failed to allocate memory for 6502_cs plugin");
		cs_close (&pd->cpd.cs_handle);
		R_FREE (s->data);
		return false;
	}
#endif
	return true;
}

static bool fini(RArchSession *s) {
	R_RETURN_VAL_IF_FAIL (s, false);
	PluginData *pd = s->data;
#if USE_ITER_API
	cs_free (pd->insn, pd->n);
#endif
	cs_close (&pd->cpd.cs_handle);
	R_FREE (s->data);
	return true;
}

const RArchPlugin r_arch_plugin_6502_cs = {
	.meta = {
		.name = "6502.cs",
		.desc = "Capstone mos65xx 8 bit microprocessors",
		.author = "pancake,Sylvain Pelissier",
		.license = "LGPL-3.0-only",
	},
	.arch = "6502",
	.bits = R_SYS_BITS_PACK1 (8),
	.decode = decode,
	.regs = regs,
	.mnemonics = mnemonics,
	.init = init,
	.fini = fini,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_6502_cs,
	.version = R2_VERSION
};
#endif
#else
// empty plugin
const RArchPlugin r_arch_plugin_6502_cs = {
	.meta = {
		.name = "6502.cs",
		.author = "pancake,Sylvain Pelissier",
		.desc = "Capstone mos65xx (not supported)",
		.license = "LGPL-3.0-only",
	},
	.arch = "6502",
	.bits = R_SYS_BITS_PACK1 (8),
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.version = R2_VERSION
};
#endif
#endif
