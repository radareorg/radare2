/* radare2 - LGPL - Copyright 2018 - courk */

#include "pic_midrange.h"

static const PicMidrangeOpInfo
	pic_midrange_op_info[PIC_MIDRANGE_OPCODE_INVALID] = {
		{"nop", PIC_MIDRANGE_OP_ARGS_NONE},
		{"return", PIC_MIDRANGE_OP_ARGS_NONE},
		{"retfie", PIC_MIDRANGE_OP_ARGS_NONE},
		{"option", PIC_MIDRANGE_OP_ARGS_NONE},
		{"sleep", PIC_MIDRANGE_OP_ARGS_NONE},
		{"clrwdt", PIC_MIDRANGE_OP_ARGS_NONE},
		{"tris", PIC_MIDRANGE_OP_ARGS_2F},
		{"movwf", PIC_MIDRANGE_OP_ARGS_7F},
		{"clr", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"subwf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"decf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"iorwf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"andwf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"xorwf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"addwf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"movf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"comf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"incf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"decfsz", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"rrf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"rlf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"swapf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"incfsz", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"bcf", PIC_MIDRANGE_OP_ARGS_3B_7F},
		{"bsf", PIC_MIDRANGE_OP_ARGS_3B_7F},
		{"btfsc", PIC_MIDRANGE_OP_ARGS_3B_7F},
		{"btfss", PIC_MIDRANGE_OP_ARGS_3B_7F},
		{"call", PIC_MIDRANGE_OP_ARGS_11K},
		{"goto", PIC_MIDRANGE_OP_ARGS_11K},
		{"movlw", PIC_MIDRANGE_OP_ARGS_8K},
		{"retlw", PIC_MIDRANGE_OP_ARGS_8K},
		{"iorlw", PIC_MIDRANGE_OP_ARGS_8K},
		{"andlw", PIC_MIDRANGE_OP_ARGS_8K},
		{"xorlw", PIC_MIDRANGE_OP_ARGS_8K},
		{"sublw", PIC_MIDRANGE_OP_ARGS_8K},
		{"addlw", PIC_MIDRANGE_OP_ARGS_8K},
		{"reset", PIC_MIDRANGE_OP_ARGS_NONE},
		{"callw", PIC_MIDRANGE_OP_ARGS_NONE},
		{"brw", PIC_MIDRANGE_OP_ARGS_NONE},
		{"moviw", PIC_MIDRANGE_OP_ARGS_1N_2M},
		{"movwi", PIC_MIDRANGE_OP_ARGS_1N_2M},
		{"movlb", PIC_MIDRANGE_OP_ARGS_4K},
		{"lslf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"lsrf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"asrf", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"subwfb", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"addwfc", PIC_MIDRANGE_OP_ARGS_1D_7F},
		{"addfsr", PIC_MIDRANGE_OP_ARGS_1N_6K},
		{"movlp", PIC_MIDRANGE_OP_ARGS_7F},
		{"bra", PIC_MIDRANGE_OP_ARGS_9K},
		{"moviw", PIC_MIDRANGE_OP_ARGS_1N_6K},
		{"movwi", PIC_MIDRANGE_OP_ARGS_1N_6K}};

static const char *PicMidrangeFsrOps[] = {"++FSR%d", "--FSR%d", "FSR%d++",
					  "FSR%d--"};

PicMidrangeOpcode pic_midrange_get_opcode (ut16 instr) {
	if (instr & (1 << 14)) {
		return PIC_MIDRANGE_OPCODE_INVALID;
	}

	switch (instr >> 11) { // 3 first MSB bits
	case 0x4: return PIC_MIDRANGE_OPCODE_CALL;
	case 0x5: return PIC_MIDRANGE_OPCODE_GOTO;
	}

	switch (instr >> 10) { // 4 first MSB bits
	case 0x4: return PIC_MIDRANGE_OPCODE_BCF;
	case 0x5: return PIC_MIDRANGE_OPCODE_BSF;
	case 0x6: return PIC_MIDRANGE_OPCODE_BTFSC;
	case 0x7: return PIC_MIDRANGE_OPCODE_BTFSS;
	}

	switch (instr >> 9) { // 5 first MSB bits
	case 0x19: return PIC_MIDRANGE_OPCODE_BRA;
	}

	switch (instr >> 8) { // 6 first MSB bits
	case 0x1: return PIC_MIDRANGE_OPCODE_CLR;
	case 0x2: return PIC_MIDRANGE_OPCODE_SUBWF;
	case 0x3: return PIC_MIDRANGE_OPCODE_DECF;
	case 0x4: return PIC_MIDRANGE_OPCODE_IORWF;
	case 0x5: return PIC_MIDRANGE_OPCODE_ANDWF;
	case 0x6: return PIC_MIDRANGE_OPCODE_XORWF;
	case 0x7: return PIC_MIDRANGE_OPCODE_ADDWF;
	case 0x8: return PIC_MIDRANGE_OPCODE_MOVF;
	case 0x9: return PIC_MIDRANGE_OPCODE_COMF;
	case 0xa: return PIC_MIDRANGE_OPCODE_INCF;
	case 0xb: return PIC_MIDRANGE_OPCODE_DECFSZ;
	case 0xc: return PIC_MIDRANGE_OPCODE_RRF;
	case 0xd: return PIC_MIDRANGE_OPCODE_RLF;
	case 0xe: return PIC_MIDRANGE_OPCODE_SWAPF;
	case 0xf: return PIC_MIDRANGE_OPCODE_INCFSZ;
	case 0x38: return PIC_MIDRANGE_OPCODE_IORLW;
	case 0x39: return PIC_MIDRANGE_OPCODE_ANDLW;
	case 0x3a: return PIC_MIDRANGE_OPCODE_XORLW;
	case 0x30: return PIC_MIDRANGE_OPCODE_MOVLW;
	case 0x34: return PIC_MIDRANGE_OPCODE_RETLW;
	case 0x3c: return PIC_MIDRANGE_OPCODE_SUBLW;
	case 0x3e: return PIC_MIDRANGE_OPCODE_ADDLW;
	case 0x35: return PIC_MIDRANGE_OPCODE_LSLF;
	case 0x36: return PIC_MIDRANGE_OPCODE_LSRF;
	case 0x37: return PIC_MIDRANGE_OPCODE_ASRF;
	case 0x3b: return PIC_MIDRANGE_OPCODE_SUBWFB;
	case 0x3d: return PIC_MIDRANGE_OPCODE_ADDWFC;
	}

	switch (instr >> 7) { // 7 first MSB bits
	case 0x1: return PIC_MIDRANGE_OPCODE_MOVWF;
	case 0x62: return PIC_MIDRANGE_OPCODE_ADDFSR;
	case 0x63: return PIC_MIDRANGE_OPCODE_MOVLP;
	case 0x7e: return PIC_MIDRANGE_OPCODE_MOVIW_2;
	case 0x7f: return PIC_MIDRANGE_OPCODE_MOVWI_2;
	}

	switch (instr >> 5) { // 9 first MSB bits
	case 0x1: return PIC_MIDRANGE_OPCODE_MOVLB;
	}

	switch (instr >> 3) { // 11 first MSB bits
	case 0x2: return PIC_MIDRANGE_OPCODE_MOVIW_1;
	case 0x3: return PIC_MIDRANGE_OPCODE_MOVWI_1;
	}

	switch (instr >> 2) { // 12 first MSB bits
	case 0x19: return PIC_MIDRANGE_OPCODE_TRIS;
	}

	switch (instr) {
	case 0x0: return PIC_MIDRANGE_OPCODE_NOP;
	case 0x1: return PIC_MIDRANGE_OPCODE_RESET;
	case 0xa: return PIC_MIDRANGE_OPCODE_CALLW;
	case 0xb: return PIC_MIDRANGE_OPCODE_BRW;
	case 0x8: return PIC_MIDRANGE_OPCODE_RETURN;
	case 0x9: return PIC_MIDRANGE_OPCODE_RETFIE;
	case 0x62: return PIC_MIDRANGE_OPCODE_OPTION;
	case 0x63: return PIC_MIDRANGE_OPCODE_SLEEP;
	case 0x64: return PIC_MIDRANGE_OPCODE_CLRWDT;
	}

	return PIC_MIDRANGE_OPCODE_INVALID;
}

const PicMidrangeOpInfo *pic_midrange_get_op_info (PicMidrangeOpcode opcode) {
	if (opcode >= PIC_MIDRANGE_OPCODE_INVALID) {
		return NULL;
	}
	return &pic_midrange_op_info[opcode];
}

int pic_midrange_disassemble (RAsmOp *op, char *opbuf, const ut8 *b, int l) {
	char fsr_op[6];
	st16 branch;

#define EMIT_INVALID {\
		op->size = 2; \
		strcpy (opbuf, "invalid"); \
		return 1; \
	}
	if (!b || l < 2) {
		EMIT_INVALID
	}

	ut16 instr = r_read_le16 (b);
	PicMidrangeOpcode opcode = pic_midrange_get_opcode (instr);
	if (opcode == PIC_MIDRANGE_OPCODE_INVALID) {
		EMIT_INVALID
	}

	const PicMidrangeOpInfo *op_info = pic_midrange_get_op_info (opcode);
	if (!op_info) {
		EMIT_INVALID
	}

#undef EMIT_INVALID

	op->size = 2;

	const char *buf_asm = NULL;
	switch (op_info->args) {
	case PIC_MIDRANGE_OP_ARGS_NONE:
		buf_asm = op_info->mnemonic;
		break;
	case PIC_MIDRANGE_OP_ARGS_2F:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_MIDRANGE_OP_ARGS_2F_MASK_F);
		break;
	case PIC_MIDRANGE_OP_ARGS_7F:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_MIDRANGE_OP_ARGS_7F_MASK_F);
		break;
	case PIC_MIDRANGE_OP_ARGS_1D_7F:
		buf_asm = sdb_fmt ("%s 0x%x, %c", op_info->mnemonic,
			  instr & PIC_MIDRANGE_OP_ARGS_1D_7F_MASK_F,
			  (instr & PIC_MIDRANGE_OP_ARGS_1D_7F_MASK_D) >> 7 ?  'f' : 'w');
		break;
	case PIC_MIDRANGE_OP_ARGS_1N_6K:
		if (opcode == PIC_MIDRANGE_OPCODE_ADDFSR) {
			buf_asm = sdb_fmt ( "%s FSR%d, 0x%x", op_info->mnemonic,
					(instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_N) >>
					6, instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_K);
		} else {
			buf_asm = sdb_fmt ("%s 0x%x[FSR%d]", op_info->mnemonic,
				instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_K,
				(instr & PIC_MIDRANGE_OP_ARGS_1N_6K_MASK_N) >> 6);
		}
		break;
	case PIC_MIDRANGE_OP_ARGS_3B_7F:
		buf_asm = sdb_fmt ("%s 0x%x, %d", op_info->mnemonic, instr & PIC_MIDRANGE_OP_ARGS_3B_7F_MASK_F,
			  (instr & PIC_MIDRANGE_OP_ARGS_3B_7F_MASK_B) >> 7);
		break;
	case PIC_MIDRANGE_OP_ARGS_4K:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_MIDRANGE_OP_ARGS_4K_MASK_K);
		break;
	case PIC_MIDRANGE_OP_ARGS_8K:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_MIDRANGE_OP_ARGS_8K_MASK_K);
		break;
	case PIC_MIDRANGE_OP_ARGS_9K:
		branch = (instr & PIC_MIDRANGE_OP_ARGS_9K_MASK_K);
		branch |= ((branch & 0x100) ? 0xfe00 : 0);
		buf_asm = sdb_fmt ("%s %s0x%x",
			  op_info->mnemonic, branch < 0 ? "-" : "",
			  branch < 0 ? -branch : branch);
		break;
	case PIC_MIDRANGE_OP_ARGS_11K:
		buf_asm = sdb_fmt ("%s 0x%x", op_info->mnemonic, instr & PIC_MIDRANGE_OP_ARGS_11K_MASK_K);
		break;
	case PIC_MIDRANGE_OP_ARGS_1N_2M:
		snprintf (
			fsr_op, sizeof (fsr_op),
			PicMidrangeFsrOps[instr &
					  PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_M],
			(instr & PIC_MIDRANGE_OP_ARGS_1N_2M_MASK_N) >> 2);
		buf_asm = sdb_fmt ("%s %s", op_info->mnemonic, fsr_op);
		break;
	}
	if (buf_asm) {
		strcpy (opbuf, buf_asm);
	}
	return op->size;
}
