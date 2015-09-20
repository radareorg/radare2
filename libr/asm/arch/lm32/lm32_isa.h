/* lm32 support for radare2
 * 2-clause BSD
 * Copyright 2015 Felix Held */
#ifndef INCLUDE_LM32_ISA_H
#define INCLUDE_LM32_ISA_H

#include <r_types.h>

#define RAsmLm32RegNameLength	8
#define RAsmLm32OpNameLength	12

typedef struct r_asm_lm32_csr_t {
	ut8 number;
	char name[RAsmLm32RegNameLength];
} RAsmLm32Csr;

#define  RAsmLm32CsrNumber	21

static const RAsmLm32Csr RAsmLm32Csrs[RAsmLm32CsrNumber] = {
	{0x00, "IE"},
	{0x01, "IM"},
	{0x02, "IP"},
	{0x03, "ICC"},
	{0x04, "DCC"},
	{0x05, "CC"},
	{0x06, "CFG"},
	{0x07, "EBA"},
	{0x08, "DC"},
	{0x09, "DEBA"},
	{0x0a, "CFG2"},
	{0x0e, "JTX"},
	{0x0f, "JRX"},
	{0x10, "BP0"},
	{0x11, "BP1"},
	{0x12, "BP2"},
	{0x13, "BP3"},
	{0x18, "WP0"},
	{0x19, "WP1"},
	{0x1a, "WP2"},
	{0x1b, "WP3"},
};

typedef struct r_asm_lm32_reg_t {
	ut8 number;
	char name[RAsmLm32RegNameLength];
} RAsmLm32Reg;

#define RAsmLm32RegNumber	39

static const RAsmLm32Reg RAsmLm32Regs[RAsmLm32RegNumber] = {
	{0x00, "r0"},
	{0x00, "zero"},
	{0x01, "r1"},
	{0x02, "r2"},
	{0x03, "r3"},
	{0x04, "r4"},
	{0x05, "r5"},
	{0x06, "r6"},
	{0x07, "r7"},
	{0x08, "r8"},
	{0x09, "r9"},
	{0x0a, "r10"},
	{0x0b, "r11"},
	{0x0c, "r12"},
	{0x0d, "r13"},
	{0x0e, "r14"},
	{0x0f, "r15"},
	{0x10, "r16"},
	{0x11, "r17"},
	{0x12, "r18"},
	{0x13, "r19"},
	{0x14, "r20"},
	{0x15, "r21"},
	{0x16, "r22"},
	{0x17, "r23"},
	{0x18, "r24"},
	{0x19, "r25"},
	{0x1a, "gp"},
	{0x1a, "r26"},
	{0x1b, "fp"},
	{0x1b, "r27"},
	{0x1c, "sp"},
	{0x1c, "r28"},
	{0x1d, "ra"},
	{0x1d, "r29"},
	{0x1e, "ea"},
	{0x1e, "r30"},
	{0x1f, "ba"},
	{0x1f, "r31"},
};

typedef enum r_asm_lm32_instr_type_t {
	reserved,
	reg_imm16_signextend,
	reg_imm16_shift2_signextend,
	reg_imm16_zeroextend,
	reg_imm5,
	raise_instr,
	one_reg,
	two_regs,
	three_regs,
	reg_csr, //wcsr
	csr_reg, //rcsr
	imm26,
} RAsmLm32InstructionType;

enum r_asm_lm32_opcode_list_t {
	lm32_op_srui = 0x00,
	lm32_op_nori = 0x01,
	lm32_op_muli = 0x02,
	lm32_op_sh = 0x03,
	lm32_op_lb = 0x04,
	lm32_op_sri = 0x05,
	lm32_op_xori = 0x06,
	lm32_op_lh = 0x07,
	lm32_op_andi = 0x08,
	lm32_op_xnori = 0x09,
	lm32_op_lw = 0x0a,
	lm32_op_lhu = 0x0b,
	lm32_op_sb = 0x0c,
	lm32_op_addi = 0x0d,
	lm32_op_ori = 0x0e,
	lm32_op_sli = 0x0f,
	lm32_op_lbu = 0x10,
	lm32_op_be = 0x11,
	lm32_op_bg = 0x12,
	lm32_op_bge = 0x13,
	lm32_op_bgeu = 0x14,
	lm32_op_bgu = 0x15,
	lm32_op_sw = 0x16,
	lm32_op_bne = 0x17,
	lm32_op_andhi = 0x18,
	lm32_op_cmpei = 0x19,
	lm32_op_cmpgi = 0x1a,
	lm32_op_cmpgei = 0x1b,
	lm32_op_cmpgeui = 0x1c,
	lm32_op_cmpgui = 0x1d,
	lm32_op_orhi = 0x1e,
	lm32_op_cmpnei = 0x1f,
	lm32_op_sru = 0x20,
	lm32_op_nor = 0x21,
	lm32_op_mul = 0x22,
	lm32_op_divu = 0x23,
	lm32_op_rcsr = 0x24,
	lm32_op_sr = 0x25,
	lm32_op_xor = 0x26,
	lm32_op_div = 0x27,
	lm32_op_and = 0x28,
	lm32_op_xnor = 0x29,
	lm32_op_reserved1 = 0x2a,
	lm32_op_raise = 0x2b,
	lm32_op_sextb = 0x2c,
	lm32_op_add = 0x2d,
	lm32_op_or = 0x2e,
	lm32_op_sl = 0x2f,
	lm32_op_b = 0x30,
	lm32_op_modu = 0x31,
	lm32_op_sub = 0x32,
	lm32_op_reserved2 = 0x33,
	lm32_op_wcsr = 0x34,
	lm32_op_mod = 0x35,
	lm32_op_call = 0x36,
	lm32_op_sexth = 0x37,
	lm32_op_bi = 0x38,
	lm32_op_cmpe = 0x39,
	lm32_op_cmpg = 0x3a,
	lm32_op_cmpge = 0x3b,
	lm32_op_cmpgeu = 0x3c,
	lm32_op_cmpgu = 0x3d,
	lm32_op_calli = 0x3e,
	lm32_op_cmpne = 0x3f,
};

typedef struct r_asm_lm32_opcode {
	RAsmLm32InstructionType type;
	char name[RAsmLm32OpNameLength];
} RAsmLm32Opcode;

#define RAsmLm32OpcodeNumber	0x40

static const RAsmLm32Opcode RAsmLm32OpcodeList[RAsmLm32OpcodeNumber] = {
	{reg_imm5, "srui"}, //0x00
	{reg_imm16_zeroextend, "nori"}, //0x01
	{reg_imm16_signextend, "muli"}, //0x02
	{reg_imm16_signextend, "sh"}, //0x03
	{reg_imm16_signextend, "lb"}, //0x04
	{reg_imm5, "sri"}, //0x05
	{reg_imm16_zeroextend, "xori"}, //0x06
	{reg_imm16_signextend, "lh"}, //0x07
	{reg_imm16_zeroextend, "andi"}, //0x08
	{reg_imm16_zeroextend, "xnori"}, //0x09
	{reg_imm16_signextend, "lw"}, //0x0a
	{reg_imm16_signextend, "lhu"}, //0x0b
	{reg_imm16_signextend, "sb"}, //0x0c
	{reg_imm16_signextend, "addi"}, //0x0d
	{reg_imm16_zeroextend, "ori"}, //0x0e
	{reg_imm5, "sli"}, //0x0f
	{reg_imm16_signextend, "lbu"}, //0x10
	{reg_imm16_shift2_signextend, "be"}, //0x11
	{reg_imm16_shift2_signextend, "bg"}, //0x12
	{reg_imm16_shift2_signextend, "bge"}, //0x13
	{reg_imm16_shift2_signextend, "bgeu"}, //0x14
	{reg_imm16_shift2_signextend, "bgu"}, //0x15
	{reg_imm16_signextend, "sw"}, //0x16
	{reg_imm16_shift2_signextend, "bne"}, //0x17
	{reg_imm16_zeroextend, "andhi"}, //0x18
	{reg_imm16_signextend, "cmpei"}, //0x19
	{reg_imm16_signextend, "cmpgi"}, //0x1a
	{reg_imm16_signextend, "cmpgei"}, //0x1b
	{reg_imm16_zeroextend, "cmpgeui"}, //0x1c
	{reg_imm16_zeroextend, "cmpgui"}, //0x1d
	{reg_imm16_zeroextend, "orhi"}, //0x1e
	{reg_imm16_signextend, "cmpnei"}, //0x1f
	{three_regs, "sru"}, //0x20
	{three_regs, "nor"}, //0x21
	{three_regs, "mul"}, //0x22
	{three_regs, "divu"}, //0x23
	{csr_reg, "rcsr"}, //0x24
	{three_regs, "sr"}, //0x25
	{three_regs, "xor"}, //0x26
	{three_regs, "div"}, //0x27
	{three_regs, "and"}, //0x28
	{three_regs, "xnor"}, //0x29
	{reserved, "reserved"}, //0x2a
	{raise_instr, "raise"}, //0x2b (break, scall)
	{two_regs, "sextb"}, //0x2c
	{three_regs, "add"}, //0x2d
	{three_regs, "or"}, //0x2e
	{three_regs, "sl"}, //0x2f
	{one_reg, "b"}, //0x30
	{three_regs, "modu"}, //0x31
	{three_regs, "sub"}, //0x32
	{reserved, "reserved"}, //0x33
	{reg_csr, "wcsr"}, //0x34
	{three_regs, "mod"}, //0x35
	{one_reg, "call"}, //0x36
	{two_regs, "sexth"}, //0x37
	{imm26, "bi"}, //0x38
	{three_regs, "cmpe"}, //0x39
	{three_regs, "cmpg"}, //0x3a
	{three_regs, "cmpge"}, //0x3b
	{three_regs, "cmpgeu"}, //0x3c
	{three_regs, "cmpgu"}, //0x3d
	{imm26, "calli"}, //0x3e
	{three_regs, "cmpne"}, //0x3f
};

typedef struct r_asm_lm32_instruction {
	//address of this instruction
	ut32 addr;
	//instruction dword
	ut32 value;

	//op code
	ut8 op;
	//op type and name
	RAsmLm32Opcode op_decode;
	//dest is the destination register (the one right after most commands)
	ut8 dest_reg;
	char dest_reg_str[RAsmLm32RegNameLength];
	//src0 is the leftmost source register
	ut8 src0_reg;
	char src0_reg_str[RAsmLm32RegNameLength];
	//src1 is the second (rightmost) source register
	ut8 src1_reg;
	char src1_reg_str[RAsmLm32RegNameLength];
	//control and status register number
	ut8 csr;
	char csr_reg_str[RAsmLm32RegNameLength];
	//immediates in expanded form
	st32 immediate;
	//set if the command has a second string representation
	bool pseudoInstruction;
} RAsmLm32Instruction;


/*
 * register number field name convention
 * bits 25..21 -> reg u (either a register or a csr number)
 * bits 20..16 -> reg v
 * bits 15..11 -> reg w
 */
static const int RAsmLm32OpShift = 26;
static const ut32 RAsmLm32OpMask = 0xfc000000;
static const int RAsmLm32RegUShift = 21;
static const ut32 RAsmLm32RegUMask = 0x03e00000;
static const int RAsmLm32RegVShift = 16;
static const ut32 RAsmLm32RegVMask = 0x001f0000;
static const int RAsmLm32RegWShift = 11;
static const ut32 RAsmLm32RegWMask = 0x0000f800;
static const ut32 RAsmLm32Imm5Mask = 0x0000001f;
static const ut32 RAsmLm32Imm16Mask = 0x0000ffff;
static const ut32 RAsmLm32Imm16SignBitPos = 15;
static const ut32 RAsmLm32Imm26Mask = 0x03ffffff;
static const ut32 RAsmLm32Imm26SignBitPos = 25;

static const ut32 RAsmLm32InstrImm5InvalidBitsMask = 0x0000ffe0;
static const ut32 RAsmLm32InstrOneRegInvalidBitsMask = 0x001fffff;
static const ut32 RAsmLm32InstrTwoRegsInvalidBitsMask = 0x001f07ff;
static const ut32 RAsmLm32InstrWcsrInvalidBitsMask = 0x0000ffff;


//common helper functions

static ut8 extract_opcode(ut32 instr_dword) {
	return (instr_dword & RAsmLm32OpMask) >> RAsmLm32OpShift;
}

static ut8 extract_reg_u(ut32 instr_dword) {
	return (instr_dword & RAsmLm32RegUMask) >> RAsmLm32RegUShift;
}

static ut8 extract_reg_v(ut32 instr_dword) {
	return (instr_dword & RAsmLm32RegVMask) >> RAsmLm32RegVShift;
}

static ut8 extract_reg_w(ut32 instr_dword) {
	return (instr_dword & RAsmLm32RegWMask) >> RAsmLm32RegWShift;
}

static ut8 extract_imm5(ut32 instr_dword) {
	return instr_dword & RAsmLm32Imm5Mask;
}

static ut16 extract_imm16(ut32 instr_dword) {
	return instr_dword & RAsmLm32Imm16Mask;
}

static ut32 extract_imm26(ut32 instr_dword) {
	return instr_dword & RAsmLm32Imm26Mask;
}

#endif //INCLUDE_LM32_ISA_H
