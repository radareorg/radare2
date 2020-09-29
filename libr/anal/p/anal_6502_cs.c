/* radare - LGPL - Copyright 2018 - pancake */

#include <string.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>
#include <r_anal.h>
#include <capstone.h>

#if CS_API_MAJOR >= 4 && CS_API_MINOR >= 1
#define CAPSTONE_HAS_MOS65XX 1
#else
#define CAPSTONE_HAS_MOS65XX 0
#endif

#if CAPSTONE_HAS_MOS65XX
#include <mos65xx.h>

static csh handle = 0;

static int analop(RAnal *a, RAnalOp *op, ut64 addr, const ut8 *buf, int len, RAnalOpMask mask) {
	static int omode = 0;
#if USE_ITER_API
	static
#endif
	cs_insn *insn = NULL;
	int mode = 0;
	int n, ret;

	if (handle && mode != omode) {
		cs_close (&handle);
		handle = 0;
	}
	omode = mode;
	if (handle == 0) {
		ret = cs_open (CS_ARCH_MOS65XX, mode, &handle);
		if (ret != CS_ERR_OK) {
			handle = 0;
			return 0;
		}
	}
	op->cycles = 1; // aprox
	cs_option (handle, CS_OPT_DETAIL, CS_OPT_ON);
	// capstone-next
#if USE_ITER_API
	{
		ut64 naddr = addr;
		size_t size = len;
		if (!insn) {
			insn = cs_malloc (handle);
		}
		n = cs_disasm_iter (handle, (const uint8_t**)&buf,
			&size, (uint64_t*)&naddr, insn);
	}
#else
	n = cs_disasm (handle, (const ut8*)buf, len, addr, 1, &insn);
#endif
	if (n < 1) {
		op->type = R_ANAL_OP_TYPE_ILL;
	} else {
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
		case MOS65XX_INS_CLC:
		case MOS65XX_INS_CLD:
		case MOS65XX_INS_CLI:
		case MOS65XX_INS_CLV:
		case MOS65XX_INS_CPX:
		case MOS65XX_INS_CPY:
			break;
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
			break;
		case MOS65XX_INS_ROL:
			op->type = R_ANAL_OP_TYPE_SHR;
			break;
		case MOS65XX_INS_ROR:
			op->type = R_ANAL_OP_TYPE_ROR;
			break;
		case MOS65XX_INS_RTI:
		case MOS65XX_INS_RTS:
		case MOS65XX_INS_SBC:
		case MOS65XX_INS_SEC:
		case MOS65XX_INS_SED:
		case MOS65XX_INS_SEI:
		case MOS65XX_INS_STA:
		case MOS65XX_INS_STX:
		case MOS65XX_INS_STY:
		case MOS65XX_INS_TAX:
		case MOS65XX_INS_TAY:
		case MOS65XX_INS_TSX:
		case MOS65XX_INS_TXA:
		case MOS65XX_INS_TXS:
		case MOS65XX_INS_TYA:
			break;
		}
	}
#if !USE_ITER_API
	cs_free (insn, n);
#endif
	//cs_close (&handle);
	return op->size;
}

static bool set_reg_profile(RAnal *anal) {
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
	return r_reg_set_profile_string (anal->reg, p);
}

RAnalPlugin r_anal_plugin_6502_cs = {
	.name = "6502.cs",
	.desc = "Capstone mos65xx analysis plugin",
	.license = "LGPL3",
	.arch = "6502",
	.bits = 8,
	.op = &analop,
	.set_reg_profile = &set_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.data = &r_anal_plugin_6502_cs,
	.version = R2_VERSION
};
#endif
#else
//  empty plugin
RAnalPlugin r_anal_plugin_6502_cs = {
	.name = "6502.cs",
	.desc = "Capstone mos65xx analysis plugin (not supported)",
	.license = "LGPL3",
	.arch = "6502",
	.bits = 8,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ANAL,
	.version = R2_VERSION
};
#endif
#endif
