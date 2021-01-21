#include "amd29k.h"
#include "amd29k_internal.h"
#include <stdio.h>
#include <string.h>
#include <r_anal.h>

#define CPU_ANY "*"

#define N_AMD29K_INSTRUCTIONS 207

#define AMD29K_GET_TYPE(x,i) ((x)->type[(i)])
#define AMD29K_GET_VALUE(x,i) ((x)->operands[(i)])
#define AMD29K_SET_VALUE(x,i,v,t) ((x)->operands[(i)]=(v));((x)->type[(i)]=(t))
#define AMD29K_SET_INVALID(x,i) ((x)->type[(i)]=AMD29K_TYPE_UNK)
#define AMD29K_HAS_BIT(x) (((x)[0] & 1))
// Global registers
#define AMD29K_IS_REG_GR(x) ((x)>=0&&(x)<128)
// Local registers
#define AMD29K_IS_REG_LR(x) ((x)>=128&&(x)<256)
#define AMD29K_REGNAME(x) (AMD29K_IS_REG_GR(x)?"gr":"lr")
#define AMD29K_LR(x) (AMD29K_IS_REG_GR(x)?(x):(x)-127)

static void decode_ra_rb_rci(amd29k_instr_t* instruction, const ut8* buffer) {
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

static void decode_ra_rb_rc(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 2, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_imm16(amd29k_instr_t* instruction, const ut8* buffer) {
	int word = (buffer[1] << 8) + buffer[3];
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, word, AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_i16_sh2(amd29k_instr_t* instruction, const ut8* buffer) {
	int word = (buffer[1] << 10) + (buffer[3] << 2);
	if (word & 0x20000) {
		word = (int)(0xfffc0000 | word);
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

static void decode_imm16_sh2(amd29k_instr_t* instruction, const ut8* buffer) {
	int word = (buffer[1] << 10) + (buffer[3] << 2);
	if (word & 0x20000) {
		word = (int)(0xfffc0000 | word);
	}
	AMD29K_SET_VALUE (instruction, 0, word, AMD29K_HAS_BIT (buffer) ? AMD29K_TYPE_JMP : AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 1);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_load_store(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, ((buffer[1] & 0x80) >> 7), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 1, (buffer[1] & 0x7F), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 2, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 3, buffer[3], AMD29K_HAS_BIT (buffer) ? AMD29K_TYPE_IMM : AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_calli(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_rc_ra_imm(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 2, (buffer[3] & 3), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_clz(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[3], AMD29K_HAS_BIT (buffer) ? AMD29K_TYPE_IMM : AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_convert(amd29k_instr_t* instruction, const ut8* buffer) {
	// lambda w,ea: (w >> 24,[decode_byte1(w), decode_byte2(w), ('imm',False,(w&0x80)>>7), ('imm',False,(w&0x70)>>4), ('imm',False,(w&0xC)>>2), ('imm',False, w&3)])
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 2, ((buffer[3] & 0x80) >> 7), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 3, ((buffer[3] & 0x70) >> 4), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 4, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 5, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
}

static void decode_rc_ra(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_dmac_fmac(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, ((buffer[1] & 0x3c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 1, (buffer[1] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 2, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 3, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_rb(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_rb(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 1);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_rc_imm(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 2, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_ra_imm(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, ((buffer[3] & 0x0c) >> 2), AMD29K_TYPE_IMM);
	AMD29K_SET_VALUE (instruction, 2, (buffer[3] & 0x03), AMD29K_TYPE_IMM);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_mfsr(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[1], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_mtsr(amd29k_instr_t* instruction, const ut8* buffer) {
	AMD29K_SET_VALUE (instruction, 0, buffer[2], AMD29K_TYPE_REG);
	AMD29K_SET_VALUE (instruction, 1, buffer[3], AMD29K_TYPE_REG);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

static void decode_none(amd29k_instr_t* instruction, const ut8* buffer) {
	// lambda w,ea: (w >> 24, None)
	AMD29K_SET_INVALID (instruction, 0);
	AMD29K_SET_INVALID (instruction, 1);
	AMD29K_SET_INVALID (instruction, 2);
	AMD29K_SET_INVALID (instruction, 3);
	AMD29K_SET_INVALID (instruction, 4);
	AMD29K_SET_INVALID (instruction, 5);
}

const amd29k_instruction_t amd29k_instructions[N_AMD29K_INSTRUCTIONS] = {
	{ CPU_ANY,   "illegal",   R_ANAL_OP_TYPE_NULL, 0x00 , decode_none       , NULL },
	{ CPU_ANY,   "add",       R_ANAL_OP_TYPE_ADD,  0x14 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "add",       R_ANAL_OP_TYPE_ADD,  0x15 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "addc",      R_ANAL_OP_TYPE_ADD,  0x1C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "addc",      R_ANAL_OP_TYPE_ADD,  0x1D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "addcs",     R_ANAL_OP_TYPE_ADD,  0x18 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "addcs",     R_ANAL_OP_TYPE_ADD,  0x19 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "addcu",     R_ANAL_OP_TYPE_ADD,  0x1A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "addcu",     R_ANAL_OP_TYPE_ADD,  0x1B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "adds",      R_ANAL_OP_TYPE_ADD,  0x10 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "adds",      R_ANAL_OP_TYPE_ADD,  0x11 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "addu",      R_ANAL_OP_TYPE_ADD,  0x12 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "addu",      R_ANAL_OP_TYPE_ADD,  0x13 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "and",       R_ANAL_OP_TYPE_AND,  0x90 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "and",       R_ANAL_OP_TYPE_AND,  0x91 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "andn",      R_ANAL_OP_TYPE_AND,  0x9C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "andn",      R_ANAL_OP_TYPE_AND,  0x9D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "aseq",      R_ANAL_OP_TYPE_CMP,  0x70 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asge",      R_ANAL_OP_TYPE_CMP,  0x5C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asge",      R_ANAL_OP_TYPE_CMP,  0x5D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asgeu",     R_ANAL_OP_TYPE_CMP,  0x5E , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asgeu",     R_ANAL_OP_TYPE_CMP,  0x5F , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asgt",      R_ANAL_OP_TYPE_CMP,  0x58 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asgt",      R_ANAL_OP_TYPE_CMP,  0x59 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asgtu",     R_ANAL_OP_TYPE_CMP,  0x5A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asgtu",     R_ANAL_OP_TYPE_CMP,  0x5B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asle",      R_ANAL_OP_TYPE_CMP,  0x54 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asle",      R_ANAL_OP_TYPE_CMP,  0x55 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asleu",     R_ANAL_OP_TYPE_CMP,  0x56 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asleu",     R_ANAL_OP_TYPE_CMP,  0x57 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "aslt",      R_ANAL_OP_TYPE_CMP,  0x50 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "aslt",      R_ANAL_OP_TYPE_CMP,  0x51 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asltu",     R_ANAL_OP_TYPE_CMP,  0x52 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asltu",     R_ANAL_OP_TYPE_CMP,  0x53 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asneq",     R_ANAL_OP_TYPE_CMP,  0x72 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "asneq",     R_ANAL_OP_TYPE_CMP,  0x73 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "call",      R_ANAL_OP_TYPE_CALL, 0xA8 , decode_ra_i16_sh2 , NULL },
	{ CPU_ANY,   "call",      R_ANAL_OP_TYPE_CALL, 0xA9 , decode_ra_i16_sh2 , NULL },
	{ CPU_ANY,   "calli",    R_ANAL_OP_TYPE_ICALL, 0xC8 , decode_calli      , NULL },
	{ CPU_29050, "class",     R_ANAL_OP_TYPE_NULL, 0xE6 , decode_rc_ra_imm  , NULL },
	{ CPU_ANY,   "clz",       R_ANAL_OP_TYPE_NULL, 0x08 , decode_clz        , NULL },
	{ CPU_ANY,   "clz",       R_ANAL_OP_TYPE_NULL, 0x09 , decode_clz        , NULL },
	{ CPU_ANY,   "const",     R_ANAL_OP_TYPE_MOV,  0x03 , decode_ra_imm16   , NULL },
	{ CPU_ANY,   "consth",    R_ANAL_OP_TYPE_MOV,  0x02 , decode_ra_imm16   , NULL },
	{ CPU_ANY,   "consthz",   R_ANAL_OP_TYPE_MOV,  0x05 , decode_ra_imm16   , NULL },
	{ CPU_ANY,   "constn",    R_ANAL_OP_TYPE_MOV,  0x01 , decode_ra_imm16   , NULL },
	{ CPU_29050, "convert",   R_ANAL_OP_TYPE_NULL, 0xE4 , decode_convert    , NULL },
	{ CPU_ANY,   "cpbyte",    R_ANAL_OP_TYPE_CMP,  0x2E , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpbyte",    R_ANAL_OP_TYPE_CMP,  0x2F , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpeq",      R_ANAL_OP_TYPE_CMP,  0x60 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpeq",      R_ANAL_OP_TYPE_CMP,  0x61 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpge",      R_ANAL_OP_TYPE_CMP,  0x4C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpge",      R_ANAL_OP_TYPE_CMP,  0x4D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpgeu",     R_ANAL_OP_TYPE_CMP,  0x4E , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpgeu",     R_ANAL_OP_TYPE_CMP,  0x4F , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpgt",      R_ANAL_OP_TYPE_CMP,  0x48 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpgt",      R_ANAL_OP_TYPE_CMP,  0x49 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpgtu",     R_ANAL_OP_TYPE_CMP,  0x4A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpgtu",     R_ANAL_OP_TYPE_CMP,  0x4B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cple",      R_ANAL_OP_TYPE_CMP,  0x44 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cple",      R_ANAL_OP_TYPE_CMP,  0x45 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpleu",     R_ANAL_OP_TYPE_CMP,  0x46 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpleu",     R_ANAL_OP_TYPE_CMP,  0x47 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cplt",      R_ANAL_OP_TYPE_CMP,  0x40 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cplt",      R_ANAL_OP_TYPE_CMP,  0x41 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpltu",     R_ANAL_OP_TYPE_CMP,  0x42 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpltu",     R_ANAL_OP_TYPE_CMP,  0x43 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpneq",     R_ANAL_OP_TYPE_CMP,  0x62 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "cpneq",     R_ANAL_OP_TYPE_CMP,  0x63 , decode_ra_rb_rci  , NULL },
	{ CPU_29000, "cvdf",      R_ANAL_OP_TYPE_NULL, 0xE9 , decode_rc_ra      , NULL },
	{ CPU_29000, "cvdint",    R_ANAL_OP_TYPE_NULL, 0xE7 , decode_rc_ra      , NULL },
	{ CPU_29000, "cvfd",      R_ANAL_OP_TYPE_NULL, 0xE8 , decode_rc_ra      , NULL },
	{ CPU_29000, "cvfint",    R_ANAL_OP_TYPE_NULL, 0xE6 , decode_rc_ra      , NULL },
	{ CPU_29000, "cvintd",    R_ANAL_OP_TYPE_NULL, 0xE5 , decode_rc_ra      , NULL },
	{ CPU_29000, "cvintf",    R_ANAL_OP_TYPE_NULL, 0xE4 , decode_rc_ra      , NULL },
	{ CPU_ANY,   "dadd",      R_ANAL_OP_TYPE_NULL, 0xF1 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "ddiv",      R_ANAL_OP_TYPE_DIV,  0xF7 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "deq",       R_ANAL_OP_TYPE_CMP,  0xEB , decode_ra_rb_rc   , NULL },
	{ CPU_29050, "dge",       R_ANAL_OP_TYPE_CMP,  0xEF , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "dgt",       R_ANAL_OP_TYPE_CMP,  0xED , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "div",       R_ANAL_OP_TYPE_DIV,  0x6A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "div",       R_ANAL_OP_TYPE_DIV,  0x6B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "div0",      R_ANAL_OP_TYPE_DIV,  0x68 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "div0",      R_ANAL_OP_TYPE_DIV,  0x69 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "divide",    R_ANAL_OP_TYPE_DIV,  0xE1 , decode_ra_rb_rc   , NULL },
	{ CPU_29050, "dividu",    R_ANAL_OP_TYPE_DIV,  0xE3 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "divl",      R_ANAL_OP_TYPE_DIV,  0x6C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "divl",      R_ANAL_OP_TYPE_DIV,  0x6D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "divrem",    R_ANAL_OP_TYPE_DIV,  0x6E , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "divrem",    R_ANAL_OP_TYPE_DIV,  0x6F , decode_ra_rb_rci  , NULL },
	{ CPU_29000, "dlt",       R_ANAL_OP_TYPE_CMP,  0xEF , decode_ra_rb_rc   , NULL },
	{ CPU_29050, "dmac",      R_ANAL_OP_TYPE_NULL, 0xD9 , decode_dmac_fmac  , NULL },
	{ CPU_29050, "dmsm",      R_ANAL_OP_TYPE_NULL, 0xDB , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "dmul",      R_ANAL_OP_TYPE_MUL,  0xF5 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "dsub",      R_ANAL_OP_TYPE_SUB,  0xF3 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "emulate",   R_ANAL_OP_TYPE_NULL, 0xF8 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "exbyte",    R_ANAL_OP_TYPE_NULL, 0x0A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "exbyte",    R_ANAL_OP_TYPE_NULL, 0x0B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "exhw",      R_ANAL_OP_TYPE_NULL, 0x7C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "exhw",      R_ANAL_OP_TYPE_NULL, 0x7D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "exhws",     R_ANAL_OP_TYPE_NULL, 0x7E , decode_rc_ra      , NULL },
	{ CPU_ANY,   "extract",   R_ANAL_OP_TYPE_NULL, 0x7A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "extract",   R_ANAL_OP_TYPE_NULL, 0x7B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "fadd",      R_ANAL_OP_TYPE_ADD,  0xF0 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "fdiv",      R_ANAL_OP_TYPE_DIV,  0xF6 , decode_ra_rb_rc   , NULL },
	{ CPU_29050, "fdmul",     R_ANAL_OP_TYPE_MUL,  0xF9 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "feq",       R_ANAL_OP_TYPE_CMP,  0xEA , decode_ra_rb_rc   , NULL },
	{ CPU_29050, "fge",       R_ANAL_OP_TYPE_CMP,  0xEE , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "fgt",       R_ANAL_OP_TYPE_CMP,  0xEC , decode_ra_rb_rc   , NULL },
	{ CPU_29000, "flt",       R_ANAL_OP_TYPE_CMP,  0xEE , decode_ra_rb_rc   , NULL },
	{ CPU_29050, "fmac",      R_ANAL_OP_TYPE_NULL, 0xD8 , decode_dmac_fmac  , NULL },
	{ CPU_29050, "fmsm",      R_ANAL_OP_TYPE_NULL, 0xDA , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "fmul",      R_ANAL_OP_TYPE_MUL,  0xF4 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "fsub",      R_ANAL_OP_TYPE_SUB,  0xF2 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "halt",      R_ANAL_OP_TYPE_RET,  0x89 , decode_none       , NULL },
	{ CPU_ANY,   "inbyte",    R_ANAL_OP_TYPE_NULL, 0x0C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "inbyte",    R_ANAL_OP_TYPE_NULL, 0x0D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "inhw",      R_ANAL_OP_TYPE_NULL, 0x78 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "inhw",      R_ANAL_OP_TYPE_NULL, 0x79 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "inv",       R_ANAL_OP_TYPE_NULL, 0x9F , decode_none       , NULL },
	{ CPU_ANY,   "iret",      R_ANAL_OP_TYPE_RET,  0x88 , decode_none       , NULL },
	{ CPU_ANY,   "iretinv",   R_ANAL_OP_TYPE_RET,  0x8C , decode_none       , NULL },
	{ CPU_ANY,   "jmp",       R_ANAL_OP_TYPE_JMP,  0xA0 , decode_imm16_sh2  , NULL },
	{ CPU_ANY,   "jmp",       R_ANAL_OP_TYPE_JMP,  0xA1 , decode_imm16_sh2  , NULL },
	{ CPU_ANY,   "jmpf",      R_ANAL_OP_TYPE_CJMP, 0xA4 , decode_ra_i16_sh2 , NULL },
	{ CPU_ANY,   "jmpf",      R_ANAL_OP_TYPE_CJMP, 0xA5 , decode_ra_i16_sh2 , NULL },
	{ CPU_ANY,   "jmpfdec",   R_ANAL_OP_TYPE_CJMP, 0xB4 , decode_ra_i16_sh2 , NULL },
	{ CPU_ANY,   "jmpfdec",   R_ANAL_OP_TYPE_CJMP, 0xB5 , decode_ra_i16_sh2 , NULL },
	{ CPU_ANY,   "jmpfi",    R_ANAL_OP_TYPE_RCJMP, 0xC4 , decode_ra_rb      , NULL },
	{ CPU_ANY,   "jmpi",      R_ANAL_OP_TYPE_RJMP, 0xC0 , decode_rb         , NULL },
	{ CPU_ANY,   "jmpt",      R_ANAL_OP_TYPE_CJMP, 0xAC , decode_ra_i16_sh2 , NULL },
	{ CPU_ANY,   "jmpti",    R_ANAL_OP_TYPE_RCJMP, 0xCC , decode_ra_rb      , NULL },
	{ CPU_29050, "mfacc",     R_ANAL_OP_TYPE_NULL, 0xE9 , decode_rc_imm     , NULL },
	{ CPU_29050, "mtacc",     R_ANAL_OP_TYPE_NULL, 0xE8 , decode_ra_imm     , NULL },
	{ CPU_ANY,   "mfsr",      R_ANAL_OP_TYPE_NULL, 0xC6 , decode_mfsr       , NULL },
	{ CPU_ANY,   "mftlb",     R_ANAL_OP_TYPE_NULL, 0xB6 , decode_rc_ra      , NULL },
	{ CPU_ANY,   "mtsr",      R_ANAL_OP_TYPE_NULL, 0xCE , decode_mtsr       , NULL },
	{ CPU_ANY,   "mtsrim",    R_ANAL_OP_TYPE_NULL, 0x04 , decode_ra_imm16   , NULL },
	{ CPU_ANY,   "mttlb",     R_ANAL_OP_TYPE_NULL, 0xBE , decode_ra_rb      , NULL },
	{ CPU_ANY,   "mul",       R_ANAL_OP_TYPE_MUL,  0x64 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "mul",       R_ANAL_OP_TYPE_MUL,  0x65 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "mull",      R_ANAL_OP_TYPE_MUL,  0x66 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "mull",      R_ANAL_OP_TYPE_MUL,  0x67 , decode_ra_rb_rci  , NULL },
	{ CPU_29050, "multiplu",  R_ANAL_OP_TYPE_MUL,  0xE2 , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "multiply",  R_ANAL_OP_TYPE_MUL,  0xE0 , decode_ra_rb_rc   , NULL },
	{ CPU_29050, "multm",     R_ANAL_OP_TYPE_MUL,  0xDE , decode_ra_rb_rc   , NULL },
	{ CPU_29050, "multmu",    R_ANAL_OP_TYPE_MUL,  0xDF , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "mulu",      R_ANAL_OP_TYPE_MUL,  0x74 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "mulu",      R_ANAL_OP_TYPE_MUL,  0x75 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "nand",      R_ANAL_OP_TYPE_AND,  0x9A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "nand",      R_ANAL_OP_TYPE_AND,  0x9B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "nor",       R_ANAL_OP_TYPE_NOR,  0x98 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "nor",       R_ANAL_OP_TYPE_NOR,  0x99 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "or",        R_ANAL_OP_TYPE_OR,   0x92 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "or",        R_ANAL_OP_TYPE_OR,   0x93 , decode_ra_rb_rci  , NULL },
	{ CPU_29050, "orn",       R_ANAL_OP_TYPE_OR,   0xAA , decode_ra_rb_rci  , NULL },
	{ CPU_29050, "orn",       R_ANAL_OP_TYPE_OR,   0xAB , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "setip",     R_ANAL_OP_TYPE_NULL, 0x9E , decode_ra_rb_rc   , NULL },
	{ CPU_ANY,   "sll",       R_ANAL_OP_TYPE_SHL,  0x80 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "sll",       R_ANAL_OP_TYPE_SHL,  0x81 , decode_ra_rb_rci  , NULL },
	{ CPU_29050, "sqrt",      R_ANAL_OP_TYPE_NULL, 0xE5 , decode_rc_ra_imm  , NULL },
	{ CPU_ANY,   "sra",       R_ANAL_OP_TYPE_SHR,  0x86 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "sra",       R_ANAL_OP_TYPE_SHR,  0x87 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "srl",       R_ANAL_OP_TYPE_SAL, 0x82 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "srl",       R_ANAL_OP_TYPE_SAL, 0x83 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "load",      R_ANAL_OP_TYPE_LOAD, 0x16 , decode_load_store , NULL },
	{ CPU_ANY,   "load",      R_ANAL_OP_TYPE_LOAD, 0x17 , decode_load_store , NULL },
	{ CPU_ANY,   "loadl",     R_ANAL_OP_TYPE_LOAD, 0x06 , decode_load_store , NULL },
	{ CPU_ANY,   "loadl",     R_ANAL_OP_TYPE_LOAD, 0x07 , decode_load_store , NULL },
	{ CPU_ANY,   "loadm",     R_ANAL_OP_TYPE_LOAD, 0x36 , decode_load_store , NULL },
	{ CPU_ANY,   "loadm",     R_ANAL_OP_TYPE_LOAD, 0x37 , decode_load_store , NULL },
	{ CPU_ANY,   "loadset",   R_ANAL_OP_TYPE_LOAD, 0x26 , decode_load_store , NULL },
	{ CPU_ANY,   "loadset",   R_ANAL_OP_TYPE_LOAD, 0x27 , decode_load_store , NULL },
	{ CPU_ANY,   "store",    R_ANAL_OP_TYPE_STORE, 0x1E , decode_load_store , NULL },
	{ CPU_ANY,   "store",    R_ANAL_OP_TYPE_STORE, 0x1F , decode_load_store , NULL },
	{ CPU_ANY,   "storel",   R_ANAL_OP_TYPE_STORE, 0x0E , decode_load_store , NULL },
	{ CPU_ANY,   "storel",   R_ANAL_OP_TYPE_STORE, 0x0F , decode_load_store , NULL },
	{ CPU_ANY,   "storem",   R_ANAL_OP_TYPE_STORE, 0x3E , decode_load_store , NULL },
	{ CPU_ANY,   "storem",   R_ANAL_OP_TYPE_STORE, 0x3F , decode_load_store , NULL },
	{ CPU_ANY,   "sub",       R_ANAL_OP_TYPE_SUB,  0x24 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "sub",       R_ANAL_OP_TYPE_SUB,  0x25 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subc",      R_ANAL_OP_TYPE_SUB,  0x2C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subc",      R_ANAL_OP_TYPE_SUB,  0x2D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subcs",     R_ANAL_OP_TYPE_SUB,  0x28 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subcs",     R_ANAL_OP_TYPE_SUB,  0x29 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subcu",     R_ANAL_OP_TYPE_SUB,  0x2A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subcu",     R_ANAL_OP_TYPE_SUB,  0x2B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subr",      R_ANAL_OP_TYPE_SUB,  0x34 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subr",      R_ANAL_OP_TYPE_SUB,  0x35 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subrc",     R_ANAL_OP_TYPE_SUB,  0x3C , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subrc",     R_ANAL_OP_TYPE_SUB,  0x3D , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subrcs",    R_ANAL_OP_TYPE_SUB,  0x38 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subrcs",    R_ANAL_OP_TYPE_SUB,  0x39 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subrcu",    R_ANAL_OP_TYPE_SUB,  0x3A , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subrcu",    R_ANAL_OP_TYPE_SUB,  0x3B , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subrs",     R_ANAL_OP_TYPE_SUB,  0x30 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subrs",     R_ANAL_OP_TYPE_SUB,  0x31 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subru",     R_ANAL_OP_TYPE_SUB,  0x32 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subru",     R_ANAL_OP_TYPE_SUB,  0x33 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subs",      R_ANAL_OP_TYPE_SUB,  0x20 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subs",      R_ANAL_OP_TYPE_SUB,  0x21 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subu",      R_ANAL_OP_TYPE_SUB,  0x22 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "subu",      R_ANAL_OP_TYPE_SUB,  0x23 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "xnor",      R_ANAL_OP_TYPE_XOR,  0x96 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "xnor",      R_ANAL_OP_TYPE_XOR,  0x97 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "xor",       R_ANAL_OP_TYPE_XOR,  0x94 , decode_ra_rb_rci  , NULL },
	{ CPU_ANY,   "xor",       R_ANAL_OP_TYPE_XOR,  0x95 , decode_ra_rb_rci  , NULL },
};

static bool is_cpu(const char* cpu, const amd29k_instruction_t *in) {
	return cpu[0] == in->cpu[0] &&
			cpu[1] == in->cpu[1] &&
			cpu[2] == in->cpu[2] &&
			cpu[3] == in->cpu[3] &&
			cpu[4] == in->cpu[4];
}

bool amd29k_instr_decode(const ut8* buffer, const ut32 buffer_size, amd29k_instr_t* instruction, const char* cpu) {
	if (!buffer || buffer_size < 4 || !instruction || (cpu && strlen (cpu) < 5)) {
		return false;
	}
	if (!cpu) {
		cpu = CPU_29000;
	}
	if (buffer[0] == 0x70 && buffer[1] == 0x40 && buffer[2] == 0x01 && buffer[3] == 0x01) {
		decode_none (instruction, buffer);
		instruction->mnemonic = "nop";
		instruction->op_type = R_ANAL_OP_TYPE_NOP;
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
		} else if (in->cpu[0] != '*' && in->mask == buffer[0] && is_cpu(cpu, in)) {
			in->decode (instruction, buffer);
			instruction->mnemonic = in->mnemonic;
			instruction->op_type = in->op_type;
			return true;
		}
	}
	return false;
}

#define AMD29K_IS_6(a,b,c,d,e,f) (t0==(a)&&t1==(b)&&t2==(c)&&t3==(d)&&t4==(e)&&t5==(f))
#define AMD29K_IS_1(a) AMD29K_IS_6(a,(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK))
#define AMD29K_IS_2(a,b) AMD29K_IS_6(a,b,(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK))
#define AMD29K_IS_3(a,b,c) AMD29K_IS_6(a,b,c,(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK))
#define AMD29K_IS_4(a,b,c,d) AMD29K_IS_6(a,b,c,d,(AMD29K_TYPE_UNK),(AMD29K_TYPE_UNK))
#define AMD29K_IS_5(a,b,c,d,e) AMD29K_IS_6(a,b,c,d,e,(AMD29K_TYPE_UNK))

bool amd29k_instr_is_ret(amd29k_instr_t* instruction) {
	if (instruction && !strcmp (instruction->mnemonic, "calli") && instruction->operands[0] == 128 && instruction->operands[1] == 128) {
		return true;
	}
	return false;
}


ut64 amd29k_instr_jump(ut64 address, amd29k_instr_t* instruction) {
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

void amd29k_instr_print(char* string, int string_size, ut64 address, amd29k_instr_t* instruction) {
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
		const char* p0 = AMD29K_REGNAME (v0);
		snprintf(string, string_size, "%s %s%d", instruction->mnemonic, p0, AMD29K_LR (v0));

	} else if (AMD29K_IS_1 (AMD29K_TYPE_IMM)) {
		if (v0 >= 0) {
			snprintf(string, string_size, "%s 0x%x", instruction->mnemonic, v0);
		} else {
			v0 = 0 - v0;
			snprintf(string, string_size, "%s -0x%x", instruction->mnemonic, v0);
		}

	} else if (AMD29K_IS_1 (AMD29K_TYPE_JMP)) {
		ut64 ptr = address + ((int) v0);
		snprintf(string, string_size, "%s 0x%" PFMT64x, instruction->mnemonic, ptr);

	} else if (AMD29K_IS_2 (AMD29K_TYPE_REG, AMD29K_TYPE_REG)) {
		const char* p0 = AMD29K_REGNAME (v0);
		const char* p1 = AMD29K_REGNAME (v1);
		snprintf(string, string_size, "%s %s%d %s%d", instruction->mnemonic, p0, AMD29K_LR (v0), p1, AMD29K_LR (v1));

	} else if (AMD29K_IS_2 (AMD29K_TYPE_REG, AMD29K_TYPE_IMM)) {
		const char* p0 = AMD29K_REGNAME (v0);
		if (v1 >= 0) {
			snprintf(string, string_size, "%s %s%d 0x%x", instruction->mnemonic, p0, AMD29K_LR (v0), v1);
		} else {
			v1 = 0 - v1;
			snprintf(string, string_size, "%s %s%d -0x%x", instruction->mnemonic, p0, AMD29K_LR (v0), v1);
		}

	} else if (AMD29K_IS_2 (AMD29K_TYPE_REG, AMD29K_TYPE_JMP)) {
		const char* p0 = AMD29K_REGNAME (v0);
		ut64 ptr = address + ((int) v1);
		snprintf(string, string_size, "%s %s%d 0x%" PFMT64x, instruction->mnemonic, p0, AMD29K_LR (v0), ptr);

	} else if (AMD29K_IS_3 (AMD29K_TYPE_REG, AMD29K_TYPE_REG, AMD29K_TYPE_REG)) {
		const char* p0 = AMD29K_REGNAME (v0);
		const char* p1 = AMD29K_REGNAME (v1);
		const char* p2 = AMD29K_REGNAME (v2);
		snprintf(string, string_size, "%s %s%d %s%d %s%d", instruction->mnemonic, p0, AMD29K_LR (v0), p1, AMD29K_LR (v1), p2, AMD29K_LR (v2));

	} else if (AMD29K_IS_3 (AMD29K_TYPE_REG, AMD29K_TYPE_REG, AMD29K_TYPE_IMM)) {
		const char* p0 = AMD29K_REGNAME (v0);
		const char* p1 = AMD29K_REGNAME (v1);
		if (v2 >= 0) {
			snprintf(string, string_size, "%s %s%d %s%d 0x%x", instruction->mnemonic, p0, AMD29K_LR (v0), p1, AMD29K_LR (v1), v2);
		} else {
			v2 = 0 - v2;
			snprintf(string, string_size, "%s %s%d %s%d -0x%x", instruction->mnemonic, p0, AMD29K_LR (v0), p1, AMD29K_LR (v1), v2);
		}

	} else if (AMD29K_IS_4 (AMD29K_TYPE_IMM, AMD29K_TYPE_IMM, AMD29K_TYPE_REG, AMD29K_TYPE_REG)) {
		const char* p2 = AMD29K_REGNAME (v2);
		const char* p3 = AMD29K_REGNAME (v3);
		snprintf(string, string_size, "%s %d %d %s%d %s%d", instruction->mnemonic, v0, v1, p2, AMD29K_LR (v2), p3, AMD29K_LR (v3));

	} else if (AMD29K_IS_6 (AMD29K_TYPE_REG, AMD29K_TYPE_REG, AMD29K_TYPE_IMM, AMD29K_TYPE_IMM, AMD29K_TYPE_IMM, AMD29K_TYPE_IMM)) {
		const char* p0 = AMD29K_REGNAME (v0);
		const char* p1 = AMD29K_REGNAME (v1);
		snprintf(string, string_size, "%s %s%d %s%d %d %d %d %d", instruction->mnemonic, p0, AMD29K_LR (v0), p1, AMD29K_LR (v1), v2, v3, v4, v5);

	} else {
		snprintf(string, string_size, "%s", instruction->mnemonic);
	}
	return;
}

#undef AMD29K_IS_6
#undef AMD29K_IS_1
#undef AMD29K_IS_2
#undef AMD29K_IS_3
#undef AMD29K_IS_4
#undef AMD29K_IS_5