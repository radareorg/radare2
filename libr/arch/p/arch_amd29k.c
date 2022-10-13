/* radare2 - BSD - Copyright 2013-2022 - pancake, condret */

#include <r_arch.h>
#include <r_lib.h>

#define CPU_29000 "29000"
#define CPU_29050 "29050"

typedef struct amd29k_instr_s {
	const char *mnemonic;
	ut64 op_type;
	ut32 operands[6];
	char type[6];
} amd29k_instr_t;

typedef void (*amd29k_decode)(amd29k_instr_t *instruction, const ut8 *buffer);

typedef struct amd29k_instruction_s {
	const char *cpu;
	const char *mnemonic;
	ut64 op_type;
	ut8 mask;
	amd29k_decode decode;
} amd29k_instruction_t;

enum amd29k_types {
	AMD29K_TYPE_UNK = 0,
	AMD29K_TYPE_REG,
	AMD29K_TYPE_IMM,
	AMD29K_TYPE_JMP,
};

#define CPU_ANY "*"

#define N_AMD29K_INSTRUCTIONS 207

#define AMD29K_GET_TYPE(x, i) ((x)->type[(i)])
#define AMD29K_GET_VALUE(x, i) ((x)->operands[(i)])
#define AMD29K_SET_VALUE(x, i, v, t) ((x)->operands[(i)] = (v)); ((x)->type[(i)] = (t))
#define AMD29K_SET_INVALID(x, i) ((x)->type[(i)] = AMD29K_TYPE_UNK)
#define AMD29K_HAS_BIT(x) (((x)[0] & 1))
// Global registers
#define AMD29K_IS_REG_GR(x) ((x) >= 0 && (x) < 128)
// Local registers
#define AMD29K_IS_REG_LR(x) ((x) >= 128 && (x) < 256)
#define AMD29K_REGNAME(x) (AMD29K_IS_REG_GR (x)? "gr": "lr")
#define AMD29K_LR(x) (AMD29K_IS_REG_GR (x)? (x): (x) - 127)

static void decode_ra_rb_rci(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	if (AMD29K_HAS_BIT (buffer)) {
		AMD29K_SET_VALUE (instruction, 2, buffer[3], AMD29K_TYPE_IMM);
	} else {
		AMD29K_SET_VALUE (instruction, 2, buffer[3], AMD29K_TYPE_REG);
	}
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_rb_rc(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 2, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_imm16(amd29k_instr_t *instruction, const ut8 *buffer) {
	int word = (buffer[1] << 8) + buffer[3];
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, word, AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_i16_sh2(amd29k_instr_t *instruction, const ut8 *buffer) {
	int word = (buffer[1] << 10) + (buffer[3] << 2);
	if (word & 0x20000) {
		word = (int) (0xfffc0000 | word);
	}
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	if (AMD29K_HAS_BIT (buffer)) {
		AMD29K_SET_VALUE (instruction, 1, word, AMD29K_TYPE_IMM);
	} else {
		AMD29K_SET_VALUE (instruction, 1, (ut32) word, AMD29K_TYPE_JMP);
	}
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_imm16_sh2(amd29k_instr_t *instruction, const ut8 *buffer) {
	int word = (buffer[1] << 10) + (buffer[3] << 2);
	if (word & 0x20000) {
		word = (int) (0xfffc0000 | word);
	}
	AMD29K_SET_VALUE (instruction, 0, word, AMD29K_HAS_BIT (buffer)? AMD29K_TYPE_JMP: AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 1);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_load_store(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, ((buffer[1] & 0x80) >> 7), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 1, (buffer[1] & 0x7F), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 2, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 3, buffer[3], AMD29K_HAS_BIT (buffer)? AMD29K_TYPE_IMM: AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_calli(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_rc_ra_imm(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 2, (buffer[3] & 3), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_clz(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[3], AMD29K_HAS_BIT (buffer)? AMD29K_TYPE_IMM: AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_convert(amd29k_instr_t *instruction, const ut8 *buffer) {
	// lambda w,ea: (w >> 24,[decode_byte1(w), decode_byte2(w), ('imm',False,(w&0x80)>>7), ('imm',False,(w&0x70)>>4), ('imm',False,(w&0xC)>>2), ('imm',False, w&3)])
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 2, ((buffer[3] & 0x80) >> 7), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 3, ((buffer[3] & 0x70) >> 4), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 4, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 5, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
}

static void decode_rc_ra(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_dmac_fmac(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, ((buffer[1] & 0x3c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 1, (buffer[1] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 2, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 3, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_rb(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_rb(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 1);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_rc_imm(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 2, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_imm(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 2, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_mfsr(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_mtsr(amd29k_instr_t *instruction, const ut8 *buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_none(amd29k_instr_t *instruction, const ut8 *buffer) {
	// lambda w,ea: (w >> 24, None)
	AMD29K_SET_INVALID (instruction, 0);
	AMD29K_SET_INVALID (instruction, 1);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

const amd29k_instruction_t amd29k_instructions[N_AMD29K_INSTRUCTIONS] = {
	{ CPU_ANY, "illegal", R_ARCH_OP_TYPE_NULL, 0x00, decode_none },
	{ CPU_ANY, "add", R_ARCH_OP_TYPE_ADD, 0x14, decode_ra_rb_rci },
	{ CPU_ANY, "add", R_ARCH_OP_TYPE_ADD, 0x15, decode_ra_rb_rci },
	{ CPU_ANY, "addc", R_ARCH_OP_TYPE_ADD, 0x1C, decode_ra_rb_rci },
	{ CPU_ANY, "addc", R_ARCH_OP_TYPE_ADD, 0x1D, decode_ra_rb_rci },
	{ CPU_ANY, "addcs", R_ARCH_OP_TYPE_ADD, 0x18, decode_ra_rb_rci },
	{ CPU_ANY, "addcs", R_ARCH_OP_TYPE_ADD, 0x19, decode_ra_rb_rci },
	{ CPU_ANY, "addcu", R_ARCH_OP_TYPE_ADD, 0x1A, decode_ra_rb_rci },
	{ CPU_ANY, "addcu", R_ARCH_OP_TYPE_ADD, 0x1B, decode_ra_rb_rci },
	{ CPU_ANY, "adds", R_ARCH_OP_TYPE_ADD, 0x10, decode_ra_rb_rci },
	{ CPU_ANY, "adds", R_ARCH_OP_TYPE_ADD, 0x11, decode_ra_rb_rci },
	{ CPU_ANY, "addu", R_ARCH_OP_TYPE_ADD, 0x12, decode_ra_rb_rci },
	{ CPU_ANY, "addu", R_ARCH_OP_TYPE_ADD, 0x13, decode_ra_rb_rci },
	{ CPU_ANY, "and", R_ARCH_OP_TYPE_AND, 0x90, decode_ra_rb_rci },
	{ CPU_ANY, "and", R_ARCH_OP_TYPE_AND, 0x91, decode_ra_rb_rci },
	{ CPU_ANY, "andn", R_ARCH_OP_TYPE_AND, 0x9C, decode_ra_rb_rci },
	{ CPU_ANY, "andn", R_ARCH_OP_TYPE_AND, 0x9D, decode_ra_rb_rci },
	{ CPU_ANY, "aseq", R_ARCH_OP_TYPE_CMP, 0x70, decode_ra_rb_rci },
	{ CPU_ANY, "asge", R_ARCH_OP_TYPE_CMP, 0x5C, decode_ra_rb_rci },
	{ CPU_ANY, "asge", R_ARCH_OP_TYPE_CMP, 0x5D, decode_ra_rb_rci },
	{ CPU_ANY, "asgeu", R_ARCH_OP_TYPE_CMP, 0x5E, decode_ra_rb_rci },
	{ CPU_ANY, "asgeu", R_ARCH_OP_TYPE_CMP, 0x5F, decode_ra_rb_rci },
	{ CPU_ANY, "asgt", R_ARCH_OP_TYPE_CMP, 0x58, decode_ra_rb_rci },
	{ CPU_ANY, "asgt", R_ARCH_OP_TYPE_CMP, 0x59, decode_ra_rb_rci },
	{ CPU_ANY, "asgtu", R_ARCH_OP_TYPE_CMP, 0x5A, decode_ra_rb_rci },
	{ CPU_ANY, "asgtu", R_ARCH_OP_TYPE_CMP, 0x5B, decode_ra_rb_rci },
	{ CPU_ANY, "asle", R_ARCH_OP_TYPE_CMP, 0x54, decode_ra_rb_rci },
	{ CPU_ANY, "asle", R_ARCH_OP_TYPE_CMP, 0x55, decode_ra_rb_rci },
	{ CPU_ANY, "asleu", R_ARCH_OP_TYPE_CMP, 0x56, decode_ra_rb_rci },
	{ CPU_ANY, "asleu", R_ARCH_OP_TYPE_CMP, 0x57, decode_ra_rb_rci },
	{ CPU_ANY, "aslt", R_ARCH_OP_TYPE_CMP, 0x50, decode_ra_rb_rci },
	{ CPU_ANY, "aslt", R_ARCH_OP_TYPE_CMP, 0x51, decode_ra_rb_rci },
	{ CPU_ANY, "asltu", R_ARCH_OP_TYPE_CMP, 0x52, decode_ra_rb_rci },
	{ CPU_ANY, "asltu", R_ARCH_OP_TYPE_CMP, 0x53, decode_ra_rb_rci },
	{ CPU_ANY, "asneq", R_ARCH_OP_TYPE_CMP, 0x72, decode_ra_rb_rci },
	{ CPU_ANY, "asneq", R_ARCH_OP_TYPE_CMP, 0x73, decode_ra_rb_rci },
	{ CPU_ANY, "call", R_ARCH_OP_TYPE_CALL, 0xA8, decode_ra_i16_sh2 },
	{ CPU_ANY, "call", R_ARCH_OP_TYPE_CALL, 0xA9, decode_ra_i16_sh2 },
	{ CPU_ANY, "calli", R_ARCH_OP_TYPE_ICALL, 0xC8, decode_calli },
	{ CPU_29050, "class", R_ARCH_OP_TYPE_NULL, 0xE6, decode_rc_ra_imm },
	{ CPU_ANY, "clz", R_ARCH_OP_TYPE_NULL, 0x08, decode_clz },
	{ CPU_ANY, "clz", R_ARCH_OP_TYPE_NULL, 0x09, decode_clz },
	{ CPU_ANY, "const", R_ARCH_OP_TYPE_MOV, 0x03, decode_ra_imm16 },
	{ CPU_ANY, "consth", R_ARCH_OP_TYPE_MOV, 0x02, decode_ra_imm16 },
	{ CPU_ANY, "consthz", R_ARCH_OP_TYPE_MOV, 0x05, decode_ra_imm16 },
	{ CPU_ANY, "constn", R_ARCH_OP_TYPE_MOV, 0x01, decode_ra_imm16 },
	{ CPU_29050, "convert", R_ARCH_OP_TYPE_NULL, 0xE4, decode_convert },
	{ CPU_ANY, "cpbyte", R_ARCH_OP_TYPE_CMP, 0x2E, decode_ra_rb_rci },
	{ CPU_ANY, "cpbyte", R_ARCH_OP_TYPE_CMP, 0x2F, decode_ra_rb_rci },
	{ CPU_ANY, "cpeq", R_ARCH_OP_TYPE_CMP, 0x60, decode_ra_rb_rci },
	{ CPU_ANY, "cpeq", R_ARCH_OP_TYPE_CMP, 0x61, decode_ra_rb_rci },
	{ CPU_ANY, "cpge", R_ARCH_OP_TYPE_CMP, 0x4C, decode_ra_rb_rci },
	{ CPU_ANY, "cpge", R_ARCH_OP_TYPE_CMP, 0x4D, decode_ra_rb_rci },
	{ CPU_ANY, "cpgeu", R_ARCH_OP_TYPE_CMP, 0x4E, decode_ra_rb_rci },
	{ CPU_ANY, "cpgeu", R_ARCH_OP_TYPE_CMP, 0x4F, decode_ra_rb_rci },
	{ CPU_ANY, "cpgt", R_ARCH_OP_TYPE_CMP, 0x48, decode_ra_rb_rci },
	{ CPU_ANY, "cpgt", R_ARCH_OP_TYPE_CMP, 0x49, decode_ra_rb_rci },
	{ CPU_ANY, "cpgtu", R_ARCH_OP_TYPE_CMP, 0x4A, decode_ra_rb_rci },
	{ CPU_ANY, "cpgtu", R_ARCH_OP_TYPE_CMP, 0x4B, decode_ra_rb_rci },
	{ CPU_ANY, "cple", R_ARCH_OP_TYPE_CMP, 0x44, decode_ra_rb_rci },
	{ CPU_ANY, "cple", R_ARCH_OP_TYPE_CMP, 0x45, decode_ra_rb_rci },
	{ CPU_ANY, "cpleu", R_ARCH_OP_TYPE_CMP, 0x46, decode_ra_rb_rci },
	{ CPU_ANY, "cpleu", R_ARCH_OP_TYPE_CMP, 0x47, decode_ra_rb_rci },
	{ CPU_ANY, "cplt", R_ARCH_OP_TYPE_CMP, 0x40, decode_ra_rb_rci },
	{ CPU_ANY, "cplt", R_ARCH_OP_TYPE_CMP, 0x41, decode_ra_rb_rci },
	{ CPU_ANY, "cpltu", R_ARCH_OP_TYPE_CMP, 0x42, decode_ra_rb_rci },
	{ CPU_ANY, "cpltu", R_ARCH_OP_TYPE_CMP, 0x43, decode_ra_rb_rci },
	{ CPU_ANY, "cpneq", R_ARCH_OP_TYPE_CMP, 0x62, decode_ra_rb_rci },
	{ CPU_ANY, "cpneq", R_ARCH_OP_TYPE_CMP, 0x63, decode_ra_rb_rci },
	{ CPU_29000, "cvdf", R_ARCH_OP_TYPE_NULL, 0xE9, decode_rc_ra },
	{ CPU_29000, "cvdint", R_ARCH_OP_TYPE_NULL, 0xE7, decode_rc_ra },
	{ CPU_29000, "cvfd", R_ARCH_OP_TYPE_NULL, 0xE8, decode_rc_ra },
	{ CPU_29000, "cvfint", R_ARCH_OP_TYPE_NULL, 0xE6, decode_rc_ra },
	{ CPU_29000, "cvintd", R_ARCH_OP_TYPE_NULL, 0xE5, decode_rc_ra },
	{ CPU_29000, "cvintf", R_ARCH_OP_TYPE_NULL, 0xE4, decode_rc_ra },
	{ CPU_ANY, "dadd", R_ARCH_OP_TYPE_NULL, 0xF1, decode_ra_rb_rc },
	{ CPU_ANY, "ddiv", R_ARCH_OP_TYPE_DIV, 0xF7, decode_ra_rb_rc },
	{ CPU_ANY, "deq", R_ARCH_OP_TYPE_CMP, 0xEB, decode_ra_rb_rc },
	{ CPU_29050, "dge", R_ARCH_OP_TYPE_CMP, 0xEF, decode_ra_rb_rc },
	{ CPU_ANY, "dgt", R_ARCH_OP_TYPE_CMP, 0xED, decode_ra_rb_rc },
	{ CPU_ANY, "div", R_ARCH_OP_TYPE_DIV, 0x6A, decode_ra_rb_rci },
	{ CPU_ANY, "div", R_ARCH_OP_TYPE_DIV, 0x6B, decode_ra_rb_rci },
	{ CPU_ANY, "div0", R_ARCH_OP_TYPE_DIV, 0x68, decode_ra_rb_rci },
	{ CPU_ANY, "div0", R_ARCH_OP_TYPE_DIV, 0x69, decode_ra_rb_rci },
	{ CPU_ANY, "divide", R_ARCH_OP_TYPE_DIV, 0xE1, decode_ra_rb_rc },
	{ CPU_29050, "dividu", R_ARCH_OP_TYPE_DIV, 0xE3, decode_ra_rb_rc },
	{ CPU_ANY, "divl", R_ARCH_OP_TYPE_DIV, 0x6C, decode_ra_rb_rci },
	{ CPU_ANY, "divl", R_ARCH_OP_TYPE_DIV, 0x6D, decode_ra_rb_rci },
	{ CPU_ANY, "divrem", R_ARCH_OP_TYPE_DIV, 0x6E, decode_ra_rb_rci },
	{ CPU_ANY, "divrem", R_ARCH_OP_TYPE_DIV, 0x6F, decode_ra_rb_rci },
	{ CPU_29000, "dlt", R_ARCH_OP_TYPE_CMP, 0xEF, decode_ra_rb_rc },
	{ CPU_29050, "dmac", R_ARCH_OP_TYPE_NULL, 0xD9, decode_dmac_fmac },
	{ CPU_29050, "dmsm", R_ARCH_OP_TYPE_NULL, 0xDB, decode_ra_rb_rc },
	{ CPU_ANY, "dmul", R_ARCH_OP_TYPE_MUL, 0xF5, decode_ra_rb_rc },
	{ CPU_ANY, "dsub", R_ARCH_OP_TYPE_SUB, 0xF3, decode_ra_rb_rc },
	{ CPU_ANY, "emulate", R_ARCH_OP_TYPE_NULL, 0xF8, decode_ra_rb_rci },
	{ CPU_ANY, "exbyte", R_ARCH_OP_TYPE_NULL, 0x0A, decode_ra_rb_rci },
	{ CPU_ANY, "exbyte", R_ARCH_OP_TYPE_NULL, 0x0B, decode_ra_rb_rci },
	{ CPU_ANY, "exhw", R_ARCH_OP_TYPE_NULL, 0x7C, decode_ra_rb_rci },
	{ CPU_ANY, "exhw", R_ARCH_OP_TYPE_NULL, 0x7D, decode_ra_rb_rci },
	{ CPU_ANY, "exhws", R_ARCH_OP_TYPE_NULL, 0x7E, decode_rc_ra },
	{ CPU_ANY, "extract", R_ARCH_OP_TYPE_NULL, 0x7A, decode_ra_rb_rci },
	{ CPU_ANY, "extract", R_ARCH_OP_TYPE_NULL, 0x7B, decode_ra_rb_rci },
	{ CPU_ANY, "fadd", R_ARCH_OP_TYPE_ADD, 0xF0, decode_ra_rb_rc },
	{ CPU_ANY, "fdiv", R_ARCH_OP_TYPE_DIV, 0xF6, decode_ra_rb_rc },
	{ CPU_29050, "fdmul", R_ARCH_OP_TYPE_MUL, 0xF9, decode_ra_rb_rc },
	{ CPU_ANY, "feq", R_ARCH_OP_TYPE_CMP, 0xEA, decode_ra_rb_rc },
	{ CPU_29050, "fge", R_ARCH_OP_TYPE_CMP, 0xEE, decode_ra_rb_rc },
	{ CPU_ANY, "fgt", R_ARCH_OP_TYPE_CMP, 0xEC, decode_ra_rb_rc },
	{ CPU_29000, "flt", R_ARCH_OP_TYPE_CMP, 0xEE, decode_ra_rb_rc },
	{ CPU_29050, "fmac", R_ARCH_OP_TYPE_NULL, 0xD8, decode_dmac_fmac },
	{ CPU_29050, "fmsm", R_ARCH_OP_TYPE_NULL, 0xDA, decode_ra_rb_rc },
	{ CPU_ANY, "fmul", R_ARCH_OP_TYPE_MUL, 0xF4, decode_ra_rb_rc },
	{ CPU_ANY, "fsub", R_ARCH_OP_TYPE_SUB, 0xF2, decode_ra_rb_rc },
	{ CPU_ANY, "halt", R_ARCH_OP_TYPE_RET, 0x89, decode_none },
	{ CPU_ANY, "inbyte", R_ARCH_OP_TYPE_NULL, 0x0C, decode_ra_rb_rci },
	{ CPU_ANY, "inbyte", R_ARCH_OP_TYPE_NULL, 0x0D, decode_ra_rb_rci },
	{ CPU_ANY, "inhw", R_ARCH_OP_TYPE_NULL, 0x78, decode_ra_rb_rci },
	{ CPU_ANY, "inhw", R_ARCH_OP_TYPE_NULL, 0x79, decode_ra_rb_rci },
	{ CPU_ANY, "inv", R_ARCH_OP_TYPE_NULL, 0x9F, decode_none },
	{ CPU_ANY, "iret", R_ARCH_OP_TYPE_RET, 0x88, decode_none },
	{ CPU_ANY, "iretinv", R_ARCH_OP_TYPE_RET, 0x8C, decode_none },
	{ CPU_ANY, "jmp", R_ARCH_OP_TYPE_JMP, 0xA0, decode_imm16_sh2 },
	{ CPU_ANY, "jmp", R_ARCH_OP_TYPE_JMP, 0xA1, decode_imm16_sh2 },
	{ CPU_ANY, "jmpf", R_ARCH_OP_TYPE_CJMP, 0xA4, decode_ra_i16_sh2 },
	{ CPU_ANY, "jmpf", R_ARCH_OP_TYPE_CJMP, 0xA5, decode_ra_i16_sh2 },
	{ CPU_ANY, "jmpfdec", R_ARCH_OP_TYPE_CJMP, 0xB4, decode_ra_i16_sh2 },
	{ CPU_ANY, "jmpfdec", R_ARCH_OP_TYPE_CJMP, 0xB5, decode_ra_i16_sh2 },
	{ CPU_ANY, "jmpfi", R_ARCH_OP_TYPE_RCJMP, 0xC4, decode_ra_rb },
	{ CPU_ANY, "jmpi", R_ARCH_OP_TYPE_RJMP, 0xC0, decode_rb },
	{ CPU_ANY, "jmpt", R_ARCH_OP_TYPE_CJMP, 0xAC, decode_ra_i16_sh2 },
	{ CPU_ANY, "jmpti", R_ARCH_OP_TYPE_RCJMP, 0xCC, decode_ra_rb },
	{ CPU_29050, "mfacc", R_ARCH_OP_TYPE_NULL, 0xE9, decode_rc_imm },
	{ CPU_29050, "mtacc", R_ARCH_OP_TYPE_NULL, 0xE8, decode_ra_imm },
	{ CPU_ANY, "mfsr", R_ARCH_OP_TYPE_NULL, 0xC6, decode_mfsr },
	{ CPU_ANY, "mftlb", R_ARCH_OP_TYPE_NULL, 0xB6, decode_rc_ra },
	{ CPU_ANY, "mtsr", R_ARCH_OP_TYPE_NULL, 0xCE, decode_mtsr },
	{ CPU_ANY, "mtsrim", R_ARCH_OP_TYPE_NULL, 0x04, decode_ra_imm16 },
	{ CPU_ANY, "mttlb", R_ARCH_OP_TYPE_NULL, 0xBE, decode_ra_rb },
	{ CPU_ANY, "mul", R_ARCH_OP_TYPE_MUL, 0x64, decode_ra_rb_rci },
	{ CPU_ANY, "mul", R_ARCH_OP_TYPE_MUL, 0x65, decode_ra_rb_rci },
	{ CPU_ANY, "mull", R_ARCH_OP_TYPE_MUL, 0x66, decode_ra_rb_rci },
	{ CPU_ANY, "mull", R_ARCH_OP_TYPE_MUL, 0x67, decode_ra_rb_rci },
	{ CPU_29050, "multiplu", R_ARCH_OP_TYPE_MUL, 0xE2, decode_ra_rb_rc },
	{ CPU_ANY, "multiply", R_ARCH_OP_TYPE_MUL, 0xE0, decode_ra_rb_rc },
	{ CPU_29050, "multm", R_ARCH_OP_TYPE_MUL, 0xDE, decode_ra_rb_rc },
	{ CPU_29050, "multmu", R_ARCH_OP_TYPE_MUL, 0xDF, decode_ra_rb_rc },
	{ CPU_ANY, "mulu", R_ARCH_OP_TYPE_MUL, 0x74, decode_ra_rb_rci },
	{ CPU_ANY, "mulu", R_ARCH_OP_TYPE_MUL, 0x75, decode_ra_rb_rci },
	{ CPU_ANY, "nand", R_ARCH_OP_TYPE_AND, 0x9A, decode_ra_rb_rci },
	{ CPU_ANY, "nand", R_ARCH_OP_TYPE_AND, 0x9B, decode_ra_rb_rci },
	{ CPU_ANY, "nor", R_ARCH_OP_TYPE_NOR, 0x98, decode_ra_rb_rci },
	{ CPU_ANY, "nor", R_ARCH_OP_TYPE_NOR, 0x99, decode_ra_rb_rci },
	{ CPU_ANY, "or", R_ARCH_OP_TYPE_OR, 0x92, decode_ra_rb_rci },
	{ CPU_ANY, "or", R_ARCH_OP_TYPE_OR, 0x93, decode_ra_rb_rci },
	{ CPU_29050, "orn", R_ARCH_OP_TYPE_OR, 0xAA, decode_ra_rb_rci },
	{ CPU_29050, "orn", R_ARCH_OP_TYPE_OR, 0xAB, decode_ra_rb_rci },
	{ CPU_ANY, "setip", R_ARCH_OP_TYPE_NULL, 0x9E, decode_ra_rb_rc },
	{ CPU_ANY, "sll", R_ARCH_OP_TYPE_SHL, 0x80, decode_ra_rb_rci },
	{ CPU_ANY, "sll", R_ARCH_OP_TYPE_SHL, 0x81, decode_ra_rb_rci },
	{ CPU_29050, "sqrt", R_ARCH_OP_TYPE_NULL, 0xE5, decode_rc_ra_imm },
	{ CPU_ANY, "sra", R_ARCH_OP_TYPE_SHR, 0x86, decode_ra_rb_rci },
	{ CPU_ANY, "sra", R_ARCH_OP_TYPE_SHR, 0x87, decode_ra_rb_rci },
	{ CPU_ANY, "srl", R_ARCH_OP_TYPE_SAL, 0x82, decode_ra_rb_rci },
	{ CPU_ANY, "srl", R_ARCH_OP_TYPE_SAL, 0x83, decode_ra_rb_rci },
	{ CPU_ANY, "load", R_ARCH_OP_TYPE_LOAD, 0x16, decode_load_store },
	{ CPU_ANY, "load", R_ARCH_OP_TYPE_LOAD, 0x17, decode_load_store },
	{ CPU_ANY, "loadl", R_ARCH_OP_TYPE_LOAD, 0x06, decode_load_store },
	{ CPU_ANY, "loadl", R_ARCH_OP_TYPE_LOAD, 0x07, decode_load_store },
	{ CPU_ANY, "loadm", R_ARCH_OP_TYPE_LOAD, 0x36, decode_load_store },
	{ CPU_ANY, "loadm", R_ARCH_OP_TYPE_LOAD, 0x37, decode_load_store },
	{ CPU_ANY, "loadset", R_ARCH_OP_TYPE_LOAD, 0x26, decode_load_store },
	{ CPU_ANY, "loadset", R_ARCH_OP_TYPE_LOAD, 0x27, decode_load_store },
	{ CPU_ANY, "store", R_ARCH_OP_TYPE_STORE, 0x1E, decode_load_store },
	{ CPU_ANY, "store", R_ARCH_OP_TYPE_STORE, 0x1F, decode_load_store },
	{ CPU_ANY, "storel", R_ARCH_OP_TYPE_STORE, 0x0E, decode_load_store },
	{ CPU_ANY, "storel", R_ARCH_OP_TYPE_STORE, 0x0F, decode_load_store },
	{ CPU_ANY, "storem", R_ARCH_OP_TYPE_STORE, 0x3E, decode_load_store },
	{ CPU_ANY, "storem", R_ARCH_OP_TYPE_STORE, 0x3F, decode_load_store },
	{ CPU_ANY, "sub", R_ARCH_OP_TYPE_SUB, 0x24, decode_ra_rb_rci },
	{ CPU_ANY, "sub", R_ARCH_OP_TYPE_SUB, 0x25, decode_ra_rb_rci },
	{ CPU_ANY, "subc", R_ARCH_OP_TYPE_SUB, 0x2C, decode_ra_rb_rci },
	{ CPU_ANY, "subc", R_ARCH_OP_TYPE_SUB, 0x2D, decode_ra_rb_rci },
	{ CPU_ANY, "subcs", R_ARCH_OP_TYPE_SUB, 0x28, decode_ra_rb_rci },
	{ CPU_ANY, "subcs", R_ARCH_OP_TYPE_SUB, 0x29, decode_ra_rb_rci },
	{ CPU_ANY, "subcu", R_ARCH_OP_TYPE_SUB, 0x2A, decode_ra_rb_rci },
	{ CPU_ANY, "subcu", R_ARCH_OP_TYPE_SUB, 0x2B, decode_ra_rb_rci },
	{ CPU_ANY, "subr", R_ARCH_OP_TYPE_SUB, 0x34, decode_ra_rb_rci },
	{ CPU_ANY, "subr", R_ARCH_OP_TYPE_SUB, 0x35, decode_ra_rb_rci },
	{ CPU_ANY, "subrc", R_ARCH_OP_TYPE_SUB, 0x3C, decode_ra_rb_rci },
	{ CPU_ANY, "subrc", R_ARCH_OP_TYPE_SUB, 0x3D, decode_ra_rb_rci },
	{ CPU_ANY, "subrcs", R_ARCH_OP_TYPE_SUB, 0x38, decode_ra_rb_rci },
	{ CPU_ANY, "subrcs", R_ARCH_OP_TYPE_SUB, 0x39, decode_ra_rb_rci },
	{ CPU_ANY, "subrcu", R_ARCH_OP_TYPE_SUB, 0x3A, decode_ra_rb_rci },
	{ CPU_ANY, "subrcu", R_ARCH_OP_TYPE_SUB, 0x3B, decode_ra_rb_rci },
	{ CPU_ANY, "subrs", R_ARCH_OP_TYPE_SUB, 0x30, decode_ra_rb_rci },
	{ CPU_ANY, "subrs", R_ARCH_OP_TYPE_SUB, 0x31, decode_ra_rb_rci },
	{ CPU_ANY, "subru", R_ARCH_OP_TYPE_SUB, 0x32, decode_ra_rb_rci },
	{ CPU_ANY, "subru", R_ARCH_OP_TYPE_SUB, 0x33, decode_ra_rb_rci },
	{ CPU_ANY, "subs", R_ARCH_OP_TYPE_SUB, 0x20, decode_ra_rb_rci },
	{ CPU_ANY, "subs", R_ARCH_OP_TYPE_SUB, 0x21, decode_ra_rb_rci },
	{ CPU_ANY, "subu", R_ARCH_OP_TYPE_SUB, 0x22, decode_ra_rb_rci },
	{ CPU_ANY, "subu", R_ARCH_OP_TYPE_SUB, 0x23, decode_ra_rb_rci },
	{ CPU_ANY, "xnor", R_ARCH_OP_TYPE_XOR, 0x96, decode_ra_rb_rci },
	{ CPU_ANY, "xnor", R_ARCH_OP_TYPE_XOR, 0x97, decode_ra_rb_rci },
	{ CPU_ANY, "xor", R_ARCH_OP_TYPE_XOR, 0x94, decode_ra_rb_rci },
	{ CPU_ANY, "xor", R_ARCH_OP_TYPE_XOR, 0x95, decode_ra_rb_rci },
};

static bool is_cpu(const char *cpu, const amd29k_instruction_t *in) {
	return cpu[0] == in->cpu[0] &&
	       cpu[1] == in->cpu[1] &&
	       cpu[2] == in->cpu[2] &&
	       cpu[3] == in->cpu[3] &&
	       cpu[4] == in->cpu[4];
}

bool amd29k_instr_decode(const ut8 *buffer, const ut32 buffer_size, amd29k_instr_t *instruction, const char *cpu) {
	if (!buffer || buffer_size < 4 || !instruction || (cpu && strlen (cpu) < 5)) {
		return false;
	}
	if (!cpu) {
		cpu = CPU_29000;
	}
	if (buffer[0] == 0x70 && buffer[1] == 0x40 && buffer[2] == 0x01 && buffer[3] == 0x01) {
		decode_none (instruction, buffer);
		instruction->mnemonic = "nop";
		instruction->op_type = R_ARCH_OP_TYPE_NOP;
		return true;
	}
	int i;
	for (i = 0; i < N_AMD29K_INSTRUCTIONS; i++) {
		const amd29k_instruction_t *in = &amd29k_instructions[i];
		if (in->cpu[0] == '*' && in->mask == buffer[0]) {
			in->decode (instruction, buffer);
			instruction->mnemonic = in->mnemonic;
			instruction->op_type = in->op_type;
			return true;
		} else if (in->cpu[0] != '*' && in->mask == buffer[0] && is_cpu (cpu, in)) {
			in->decode (instruction, buffer);
			instruction->mnemonic = in->mnemonic;
			instruction->op_type = in->op_type;
			return true;
		}
	}
	return false;
}

#define AMD29K_IS_6(a, b, c, d, e, f) (t0 == (a) && t1 == (b) && t2 == (c) && t3 == (d) && t4 == (e) && t5 == (f))
#define AMD29K_IS_1(a) AMD29K_IS_6 (a, (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK))
#define AMD29K_IS_2(a, b) AMD29K_IS_6 (a, b, (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK))
#define AMD29K_IS_3(a, b, c) AMD29K_IS_6 (a, b, c, (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK))
#define AMD29K_IS_4(a, b, c, d) AMD29K_IS_6 (a, b, c, d, (AMD29K_TYPE_UNK), (AMD29K_TYPE_UNK))
#define AMD29K_IS_5(a, b, c, d, e) AMD29K_IS_6 (a, b, c, d, e, (AMD29K_TYPE_UNK))

bool amd29k_instr_is_ret(amd29k_instr_t *instruction) {
	if (instruction && !strcmp (instruction->mnemonic, "calli") &&
		instruction->operands[0] == 128 && instruction->operands[1] == 128) {
		return true;
	}
	return false;
}


ut64 amd29k_instr_jump(ut64 address, amd29k_instr_t *instruction) {
	if (!instruction) {
		return UT64_MAX;
	}
	int t0 = AMD29K_GET_TYPE (instruction, 0);
	int t1 = AMD29K_GET_TYPE (instruction, 1);
	int t2 = AMD29K_GET_TYPE (instruction, 2);
	int t3 = AMD29K_GET_TYPE (instruction, 3);
	int t4 = AMD29K_GET_TYPE (instruction, 4);
	int t5 = AMD29K_GET_TYPE (instruction, 5);

	int v0 = AMD29K_GET_VALUE (instruction, 0);
	int v1 = AMD29K_GET_VALUE (instruction, 1);
	if (AMD29K_IS_1 (AMD29K_TYPE_JMP)) {
		return address + ((int) v0);
	} else if (AMD29K_IS_2 (AMD29K_TYPE_REG, AMD29K_TYPE_JMP)) {
		return address + ((int) v1);
	}
	return UT64_MAX;
}

void amd29k_instr_print(char *string, int string_size, ut64 address, amd29k_instr_t *instruction) {
	if (!string || string_size < 0 || !instruction) {
		return;
	}
	int t0 = AMD29K_GET_TYPE (instruction, 0);
	int t1 = AMD29K_GET_TYPE (instruction, 1);
	int t2 = AMD29K_GET_TYPE (instruction, 2);
	int t3 = AMD29K_GET_TYPE (instruction, 3);
	int t4 = AMD29K_GET_TYPE (instruction, 4);
	int t5 = AMD29K_GET_TYPE (instruction, 5);

	int v0 = AMD29K_GET_VALUE (instruction, 0);
	int v1 = AMD29K_GET_VALUE (instruction, 1);
	int v2 = AMD29K_GET_VALUE (instruction, 2);
	int v3 = AMD29K_GET_VALUE (instruction, 3);
	int v4 = AMD29K_GET_VALUE (instruction, 4);
	int v5 = AMD29K_GET_VALUE (instruction, 5);

	if (AMD29K_IS_1 (AMD29K_TYPE_REG)) {
		const char *p0 = AMD29K_REGNAME (v0);
		snprintf (string, string_size, "%s %s%d", instruction->mnemonic, p0, AMD29K_LR (v0));

	} else if (AMD29K_IS_1 (AMD29K_TYPE_IMM)) {
		if (v0 >= 0) {
			snprintf (string, string_size, "%s 0x%x", instruction->mnemonic, v0);
		} else {
			v0 = 0 - v0;
			snprintf (string, string_size, "%s -0x%x", instruction->mnemonic, v0);
		}

	} else if (AMD29K_IS_1 (AMD29K_TYPE_JMP)) {
		ut64 ptr = address + ((int) v0);
		snprintf (string, string_size, "%s 0x%" PFMT64x, instruction->mnemonic, ptr);

	} else if (AMD29K_IS_2 (AMD29K_TYPE_REG, AMD29K_TYPE_REG)) {
		const char *p0 = AMD29K_REGNAME (v0);
		const char *p1 = AMD29K_REGNAME (v1);
		snprintf (string, string_size, "%s %s%d %s%d", instruction->mnemonic, p0,
			AMD29K_LR (v0), p1, AMD29K_LR (v1));

	} else if (AMD29K_IS_2 (AMD29K_TYPE_REG, AMD29K_TYPE_IMM)) {
		const char *p0 = AMD29K_REGNAME (v0);
		if (v1 >= 0) {
			snprintf (string, string_size, "%s %s%d 0x%x", instruction->mnemonic,
				p0, AMD29K_LR (v0), v1);
		} else {
			v1 = 0 - v1;
			snprintf (string, string_size, "%s %s%d -0x%x", instruction->mnemonic,
				p0, AMD29K_LR (v0), v1);
		}

	} else if (AMD29K_IS_2 (AMD29K_TYPE_REG, AMD29K_TYPE_JMP)) {
		const char *p0 = AMD29K_REGNAME (v0);
		ut64 ptr = address + ((int) v1);
		snprintf (string, string_size, "%s %s%d 0x%" PFMT64x, instruction->mnemonic,
			p0, AMD29K_LR (v0), ptr);

	} else if (AMD29K_IS_3 (AMD29K_TYPE_REG, AMD29K_TYPE_REG, AMD29K_TYPE_REG)) {
		const char *p0 = AMD29K_REGNAME (v0);
		const char *p1 = AMD29K_REGNAME (v1);
		const char *p2 = AMD29K_REGNAME (v2);
		snprintf (string, string_size, "%s %s%d %s%d %s%d", instruction->mnemonic, p0,
			AMD29K_LR (v0), p1, AMD29K_LR (v1), p2, AMD29K_LR (v2));

	} else if (AMD29K_IS_3 (AMD29K_TYPE_REG, AMD29K_TYPE_REG, AMD29K_TYPE_IMM)) {
		const char *p0 = AMD29K_REGNAME (v0);
		const char *p1 = AMD29K_REGNAME (v1);
		if (v2 >= 0) {
			snprintf (string, string_size, "%s %s%d %s%d 0x%x", instruction->mnemonic,
				p0, AMD29K_LR (v0), p1, AMD29K_LR (v1), v2);
		} else {
			v2 = 0 - v2;
			snprintf (string, string_size, "%s %s%d %s%d -0x%x", instruction->mnemonic,
				p0, AMD29K_LR (v0), p1, AMD29K_LR (v1), v2);
		}

	} else if (AMD29K_IS_4 (AMD29K_TYPE_IMM, AMD29K_TYPE_IMM, AMD29K_TYPE_REG, AMD29K_TYPE_REG)) {
		const char *p2 = AMD29K_REGNAME (v2);
		const char *p3 = AMD29K_REGNAME (v3);
		snprintf (string, string_size, "%s %d %d %s%d %s%d", instruction->mnemonic, v0, v1,
			p2, AMD29K_LR (v2), p3, AMD29K_LR (v3));

	} else if (AMD29K_IS_6 (AMD29K_TYPE_REG, AMD29K_TYPE_REG, AMD29K_TYPE_IMM, AMD29K_TYPE_IMM,
		AMD29K_TYPE_IMM, AMD29K_TYPE_IMM)) {
		const char *p0 = AMD29K_REGNAME (v0);
		const char *p1 = AMD29K_REGNAME (v1);
		snprintf (string, string_size, "%s %s%d %s%d %d %d %d %d", instruction->mnemonic,
			p0, AMD29K_LR (v0), p1, AMD29K_LR (v1), v2, v3, v4, v5);

	} else {
		snprintf (string, string_size, "%s", instruction->mnemonic);
	}
	return;
}

#undef AMD29K_IS_6
#undef AMD29K_IS_1
#undef AMD29K_IS_2
#undef AMD29K_IS_3
#undef AMD29K_IS_4
#undef AMD29K_IS_5
static bool set_reg_profile(RArchConfig *cfg, RReg *reg) {
	const char * const p =
		"=PC	pc\n"
		"=SP	gp1\n"
		"=BP	gp2\n"
		"=SR	gp3\n"		// status register ??
		"=SN	gp4\n"		// also for ret
		"=A0	lr1\n"		// also for ret
		"=A1	lr2\n"
		"=A2	lr3\n"
		"=A3	lr4\n"
		"=A4	lr5\n"
		"=A5	lr6\n"
		"=A6	lr7\n"
		"gpr	gp0     .32 0 0\n"
		"gpr	gp1     .32 8 0\n"
		"gpr	gp2     .32 16 0\n"
		"gpr	gp3     .32 24 0\n"
		"gpr	gp4     .32 32 0\n"
		"gpr	gp5     .32 40 0\n"
		"gpr	gp6     .32 48 0\n"
		"gpr	gp7     .32 56 0\n"
		"gpr	gp8     .32 64 0\n"
		"gpr	gp9     .32 72 0\n"
		"gpr	gp10    .32 80 0\n"
		"gpr	gp11    .32 88 0\n"
		"gpr	gp12    .32 96 0\n"
		"gpr	gp13    .32 104 0\n"
		"gpr	gp14    .32 112 0\n"
		"gpr	gp15    .32 120 0\n"
		"gpr	gp16    .32 128 0\n"
		"gpr	gp17    .32 136 0\n"
		"gpr	gp18    .32 144 0\n"
		"gpr	gp19    .32 152 0\n"
		"gpr	gp20    .32 160 0\n"
		"gpr	gp21    .32 168 0\n"
		"gpr	gp22    .32 176 0\n"
		"gpr	gp23    .32 184 0\n"
		"gpr	gp24    .32 192 0\n"
		"gpr	gp25    .32 200 0\n"
		"gpr	gp26    .32 208 0\n"
		"gpr	gp27    .32 216 0\n"
		"gpr	gp28    .32 224 0\n"
		"gpr	gp29    .32 232 0\n"
		"gpr	gp30    .32 240 0\n"
		"gpr	gp31    .32 248 0\n"
		"gpr	gp32    .32 256 0\n"
		"gpr	gp33    .32 264 0\n"
		"gpr	gp34    .32 272 0\n"
		"gpr	gp35    .32 280 0\n"
		"gpr	gp36    .32 288 0\n"
		"gpr	gp37    .32 296 0\n"
		"gpr	gp38    .32 304 0\n"
		"gpr	gp39    .32 312 0\n"
		"gpr	gp40    .32 320 0\n"
		"gpr	gp41    .32 328 0\n"
		"gpr	gp42    .32 336 0\n"
		"gpr	gp43    .32 344 0\n"
		"gpr	gp44    .32 352 0\n"
		"gpr	gp45    .32 360 0\n"
		"gpr	gp46    .32 368 0\n"
		"gpr	gp47    .32 376 0\n"
		"gpr	gp48    .32 384 0\n"
		"gpr	gp49    .32 392 0\n"
		"gpr	gp50    .32 400 0\n"
		"gpr	gp51    .32 408 0\n"
		"gpr	gp52    .32 416 0\n"
		"gpr	gp53    .32 424 0\n"
		"gpr	gp54    .32 432 0\n"
		"gpr	gp55    .32 440 0\n"
		"gpr	gp56    .32 448 0\n"
		"gpr	gp57    .32 456 0\n"
		"gpr	gp58    .32 464 0\n"
		"gpr	gp59    .32 472 0\n"
		"gpr	gp60    .32 480 0\n"
		"gpr	gp61    .32 488 0\n"
		"gpr	gp62    .32 496 0\n"
		"gpr	gp63    .32 504 0\n"
		"gpr	gp64    .32 512 0\n"
		"gpr	gp65    .32 520 0\n"
		"gpr	gp66    .32 528 0\n"
		"gpr	gp67    .32 536 0\n"
		"gpr	gp68    .32 544 0\n"
		"gpr	gp69    .32 552 0\n"
		"gpr	gp70    .32 560 0\n"
		"gpr	gp71    .32 568 0\n"
		"gpr	gp72    .32 576 0\n"
		"gpr	gp73    .32 584 0\n"
		"gpr	gp74    .32 592 0\n"
		"gpr	gp75    .32 600 0\n"
		"gpr	gp76    .32 608 0\n"
		"gpr	gp77    .32 616 0\n"
		"gpr	gp78    .32 624 0\n"
		"gpr	gp79    .32 632 0\n"
		"gpr	gp80    .32 640 0\n"
		"gpr	gp81    .32 648 0\n"
		"gpr	gp82    .32 656 0\n"
		"gpr	gp83    .32 664 0\n"
		"gpr	gp84    .32 672 0\n"
		"gpr	gp85    .32 680 0\n"
		"gpr	gp86    .32 688 0\n"
		"gpr	gp87    .32 696 0\n"
		"gpr	gp88    .32 704 0\n"
		"gpr	gp89    .32 712 0\n"
		"gpr	gp90    .32 720 0\n"
		"gpr	gp91    .32 728 0\n"
		"gpr	gp92    .32 736 0\n"
		"gpr	gp93    .32 744 0\n"
		"gpr	gp94    .32 752 0\n"
		"gpr	gp95    .32 760 0\n"
		"gpr	gp96    .32 768 0\n"
		"gpr	gp97    .32 776 0\n"
		"gpr	gp98    .32 784 0\n"
		"gpr	gp99    .32 792 0\n"
		"gpr	gp100   .32 800 0\n"
		"gpr	gp101   .32 808 0\n"
		"gpr	gp102   .32 816 0\n"
		"gpr	gp103   .32 824 0\n"
		"gpr	gp104   .32 832 0\n"
		"gpr	gp105   .32 840 0\n"
		"gpr	gp106   .32 848 0\n"
		"gpr	gp107   .32 856 0\n"
		"gpr	gp108   .32 864 0\n"
		"gpr	gp109   .32 872 0\n"
		"gpr	gp110   .32 880 0\n"
		"gpr	gp111   .32 888 0\n"
		"gpr	gp112   .32 896 0\n"
		"gpr	gp113   .32 904 0\n"
		"gpr	gp114   .32 912 0\n"
		"gpr	gp115   .32 920 0\n"
		"gpr	gp116   .32 928 0\n"
		"gpr	gp117   .32 936 0\n"
		"gpr	gp118   .32 944 0\n"
		"gpr	gp119   .32 952 0\n"
		"gpr	gp120   .32 960 0\n"
		"gpr	gp121   .32 968 0\n"
		"gpr	gp122   .32 976 0\n"
		"gpr	gp123   .32 984 0\n"
		"gpr	gp124   .32 992 0\n"
		"gpr	gp125   .32 1000 0\n"
		"gpr	gp126   .32 1008 0\n"
		"gpr	gp127   .32 1016 0\n"
		"gpr	lr1     .32 1024 0\n"
		"gpr	lr2     .32 1032 0\n"
		"gpr	lr3     .32 1040 0\n"
		"gpr	lr4     .32 1048 0\n"
		"gpr	lr5     .32 1056 0\n"
		"gpr	lr6     .32 1064 0\n"
		"gpr	lr7     .32 1072 0\n"
		"gpr	lr8     .32 1080 0\n"
		"gpr	lr9     .32 1088 0\n"
		"gpr	lr10    .32 1096 0\n"
		"gpr	lr11    .32 1104 0\n"
		"gpr	lr12    .32 1112 0\n"
		"gpr	lr13    .32 1120 0\n"
		"gpr	lr14    .32 1128 0\n"
		"gpr	lr15    .32 1136 0\n"
		"gpr	lr16    .32 1144 0\n"
		"gpr	lr17    .32 1152 0\n"
		"gpr	lr18    .32 1160 0\n"
		"gpr	lr19    .32 1168 0\n"
		"gpr	lr20    .32 1176 0\n"
		"gpr	lr21    .32 1184 0\n"
		"gpr	lr22    .32 1192 0\n"
		"gpr	lr23    .32 1200 0\n"
		"gpr	lr24    .32 1208 0\n"
		"gpr	lr25    .32 1216 0\n"
		"gpr	lr26    .32 1224 0\n"
		"gpr	lr27    .32 1232 0\n"
		"gpr	lr28    .32 1240 0\n"
		"gpr	lr29    .32 1248 0\n"
		"gpr	lr30    .32 1256 0\n"
		"gpr	lr31    .32 1264 0\n"
		"gpr	lr32    .32 1272 0\n"
		"gpr	lr33    .32 1280 0\n"
		"gpr	lr34    .32 1288 0\n"
		"gpr	lr35    .32 1296 0\n"
		"gpr	lr36    .32 1304 0\n"
		"gpr	lr37    .32 1312 0\n"
		"gpr	lr38    .32 1320 0\n"
		"gpr	lr39    .32 1328 0\n"
		"gpr	lr40    .32 1336 0\n"
		"gpr	lr41    .32 1344 0\n"
		"gpr	lr42    .32 1352 0\n"
		"gpr	lr43    .32 1360 0\n"
		"gpr	lr44    .32 1368 0\n"
		"gpr	lr45    .32 1376 0\n"
		"gpr	lr46    .32 1384 0\n"
		"gpr	lr47    .32 1392 0\n"
		"gpr	lr48    .32 1400 0\n"
		"gpr	lr49    .32 1408 0\n"
		"gpr	lr50    .32 1416 0\n"
		"gpr	lr51    .32 1424 0\n"
		"gpr	lr52    .32 1432 0\n"
		"gpr	lr53    .32 1440 0\n"
		"gpr	lr54    .32 1448 0\n"
		"gpr	lr55    .32 1456 0\n"
		"gpr	lr56    .32 1464 0\n"
		"gpr	lr57    .32 1472 0\n"
		"gpr	lr58    .32 1480 0\n"
		"gpr	lr59    .32 1488 0\n"
		"gpr	lr60    .32 1496 0\n"
		"gpr	lr61    .32 1504 0\n"
		"gpr	lr62    .32 1512 0\n"
		"gpr	lr63    .32 1520 0\n"
		"gpr	lr64    .32 1528 0\n"
		"gpr	lr65    .32 1536 0\n"
		"gpr	lr66    .32 1544 0\n"
		"gpr	lr67    .32 1552 0\n"
		"gpr	lr68    .32 1560 0\n"
		"gpr	lr69    .32 1568 0\n"
		"gpr	lr70    .32 1576 0\n"
		"gpr	lr71    .32 1584 0\n"
		"gpr	lr72    .32 1592 0\n"
		"gpr	lr73    .32 1600 0\n"
		"gpr	lr74    .32 1608 0\n"
		"gpr	lr75    .32 1616 0\n"
		"gpr	lr76    .32 1624 0\n"
		"gpr	lr77    .32 1632 0\n"
		"gpr	lr78    .32 1640 0\n"
		"gpr	lr79    .32 1648 0\n"
		"gpr	lr80    .32 1656 0\n"
		"gpr	lr81    .32 1664 0\n"
		"gpr	lr82    .32 1672 0\n"
		"gpr	lr83    .32 1680 0\n"
		"gpr	lr84    .32 1688 0\n"
		"gpr	lr85    .32 1696 0\n"
		"gpr	lr86    .32 1704 0\n"
		"gpr	lr87    .32 1712 0\n"
		"gpr	lr88    .32 1720 0\n"
		"gpr	lr89    .32 1728 0\n"
		"gpr	lr90    .32 1736 0\n"
		"gpr	lr91    .32 1744 0\n"
		"gpr	lr92    .32 1752 0\n"
		"gpr	lr93    .32 1760 0\n"
		"gpr	lr94    .32 1768 0\n"
		"gpr	lr95    .32 1776 0\n"
		"gpr	lr96    .32 1784 0\n"
		"gpr	lr97    .32 1792 0\n"
		"gpr	lr98    .32 1800 0\n"
		"gpr	lr99    .32 1808 0\n"
		"gpr	lr100   .32 1816 0\n"
		"gpr	lr101   .32 1824 0\n"
		"gpr	lr102   .32 1832 0\n"
		"gpr	lr103   .32 1840 0\n"
		"gpr	lr104   .32 1848 0\n"
		"gpr	lr105   .32 1856 0\n"
		"gpr	lr106   .32 1864 0\n"
		"gpr	lr107   .32 1872 0\n"
		"gpr	lr108   .32 1880 0\n"
		"gpr	lr109   .32 1888 0\n"
		"gpr	lr110   .32 1896 0\n"
		"gpr	lr111   .32 1904 0\n"
		"gpr	lr112   .32 1912 0\n"
		"gpr	lr113   .32 1920 0\n"
		"gpr	lr114   .32 1928 0\n"
		"gpr	lr115   .32 1936 0\n"
		"gpr	lr116   .32 1944 0\n"
		"gpr	lr117   .32 1952 0\n"
		"gpr	lr118   .32 1960 0\n"
		"gpr	lr119   .32 1968 0\n"
		"gpr	lr120   .32 1976 0\n"
		"gpr	lr121   .32 1984 0\n"
		"gpr	lr122   .32 1992 0\n"
		"gpr	lr123   .32 2000 0\n"
		"gpr	lr124   .32 2008 0\n"
		"gpr	lr125   .32 2016 0\n"
		"gpr	lr126   .32 2024 0\n"
		"gpr	lr127   .32 2032 0\n"
		"gpr	lr128   .32 2040 0\n";
	return r_reg_set_profile_string (reg, p);
}

static int archinfo(RArchConfig *cfg, ut32 q) {
	if (q == R_ARCH_INFO_JMPMID) {
		return -1;
	}
	return 4;
}

static int decode(RArchConfig *cfg, RArchOp *op, ut64 addr, const ut8 *buf, int len, ut32 mask, void *user) {
	op->size = 4;
	op->eob = false;

	// delayed branch is bugged as hell. disabled for now.

	amd29k_instr_t instruction = {
		0
	};
	if (amd29k_instr_decode (buf, len, &instruction, cfg->cpu)) {
		if (mask & R_ARCH_OP_MASK_DISASM) {
			const int buf_asm_len = 64;
			char *buf_asm = calloc (buf_asm_len, 1);
			if (buf_asm) {
				amd29k_instr_print (buf_asm, buf_asm_len, addr, &instruction);
				op->mnemonic = buf_asm;
			}
		}

		op->type = instruction.op_type;
		switch (op->type) {
		case R_ARCH_OP_TYPE_JMP:
			op->jump = amd29k_instr_jump (addr, &instruction);
			// op->delay = 1;
			break;
		case R_ARCH_OP_TYPE_CJMP:
			op->jump = amd29k_instr_jump (addr, &instruction);
			op->fail = addr + 4;
			// op->delay = 1;
			break;
		case R_ARCH_OP_TYPE_ICALL:
			if (amd29k_instr_is_ret (&instruction)) {
				op->type = R_ARCH_OP_TYPE_RET;
				op->eob = true;
			}
			// op->delay = 1;
			break;
		case R_ARCH_OP_TYPE_RET:
			op->eob = true;
			// op->delay = 1;
			break;
		default:
			op->delay = 0;
			break;
		}
	}

	return op->size;
}

RArchPlugin r_arch_plugin_amd29k = {
	.name = "amd29k",
	.desc = "AMD 29k decoder",
	.license = "BSD",
	.arch = "amd29k",
	.bits = R_SYS_BITS_32,
	.addr_bits = R_SYS_BITS_32,
	.esil = false,
	.info = archinfo,
	.decode = &decode,
	.set_reg_profile = &set_reg_profile,
	.cpus = CPU_29000 ","CPU_29050,
	.endian = R_SYS_ENDIAN_LITTLE,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_amd29k,
	.version = R2_VERSION
};
#endif
