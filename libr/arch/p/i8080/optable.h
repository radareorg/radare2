/* radare - MIT - Copyright 2012-2023 - pancake, murphy */


#ifndef I8080_OPTABLE_H
#define I8080_OPTABLE_H

#include <r_anal.h>

// 8-bit register
static const char *reg[] = { "b", "c", "d", "e", "h", "l", "m", "a" };

// 16-bit register
static const char *rp[] = { "b", "d", "h", "sp" };
static const char *push_rp[] = { "b", "d", "h", "psw" };
static const char *rst[] = { "0", "1", "2", "3", "4", "5", "6", "7" };


// XXX TODO - Add Memory argument with an defined address on HL

struct arg_t {
	int type; /* 1 - next byte, 2 - next word, 3 - in opcode */
	int shift;
	int mask;
	const char **fmt;
};

typedef struct i8080_opcode_t {
	int type;
	int size;
	const char *name;
	struct arg_t arg1, arg2;
} i8080_opcode_t;

///http://bitsavers.trailing-edge.com/components/intel/MCS80/98-153B_Intel_8080_Microcomputer_Systems_Users_Manual_197509.pdf
///http://popolony2k.com.br/xtras/programming/asm/nemesis-lonestar/8080-z80-instruction-set.html
///http://dunfield.classiccmp.org/r/8080.txt
///https://tobiasvl.github.io/optable/intel-8080/
///https://pastraiser.com/cpu/i8080/i8080_opcodes.html
///https://www.emulator101.com/8080-by-opcode.html

static i8080_opcode_t i8080_opcodes[] = {
	{ R_ANAL_OP_TYPE_NOP, 1, "nop" }, 				//0x00
	{ R_ANAL_OP_TYPE_LOAD, 3, "lxi", { 3, 4, 3, rp }, { 2 } },	//0x01
	{ R_ANAL_OP_TYPE_STORE, 1, "stax", { 3, 4, 3, rp }},		//0x02
	{ R_ANAL_OP_TYPE_ADD, 1, "inx", { 3, 4, 3, rp } },		//0x03
	{ R_ANAL_OP_TYPE_ADD, 1, "inr", { 3, 3, 7, reg } },		//0x04
	{ R_ANAL_OP_TYPE_SUB, 1, "dcr", { 3, 3, 7, reg } },		//0x05
	{ R_ANAL_OP_TYPE_LOAD, 2, "mvi", { 3, 3, 7, reg }, { 1 } },	//0x06
	{ R_ANAL_OP_TYPE_ROL, 1, "rlc" },				//0x07
	{ R_ANAL_OP_TYPE_NOP, 1, "nop" },				//0x08
	{ R_ANAL_OP_TYPE_ADD, 1, "dad", { 3, 4, 3, rp } },		//0x09
	{ R_ANAL_OP_TYPE_LOAD, 1, "ldax", { 3, 4, 3, rp }},		//0x0a
	{ R_ANAL_OP_TYPE_SUB, 1, "dcx", { 3, 4, 3, rp } },		//0x0b
	{ R_ANAL_OP_TYPE_ADD, 1, "inr", { 3, 3, 7, reg } },  		//0x0c
	{ R_ANAL_OP_TYPE_SUB, 1, "dcr", { 3, 3, 7, reg } },		//0x0d
	{ R_ANAL_OP_TYPE_MOV, 2, "mvi", { 3, 3, 7, reg }, { 1 } },  	//0x0e
	{ R_ANAL_OP_TYPE_ROR, 1, "rrc" },				//0x0f

	{ R_ANAL_OP_TYPE_NOP, 1, "nop" }, 				//0x10
	{ R_ANAL_OP_TYPE_LOAD, 3, "lxi", { 3, 4, 3, rp }, { 2 } },  	//0x11
	{ R_ANAL_OP_TYPE_STORE, 1, "stax", { 3, 4, 3, rp }},		//0x12
	{ R_ANAL_OP_TYPE_ADD, 1, "inx", { 3, 4, 3, rp } },  		//0x13
	{ R_ANAL_OP_TYPE_ADD, 1, "inr", { 3, 3, 7, reg } },  		//0x14
	{ R_ANAL_OP_TYPE_SUB, 1, "dcr", { 3, 3, 7, reg } },		//0x15
	{ R_ANAL_OP_TYPE_LOAD, 2, "mvi", { 3, 3, 7, reg }, { 1 } },	//0x16
	{ R_ANAL_OP_TYPE_ROL, 1, "ral" },				//0x17
	{ R_ANAL_OP_TYPE_NOP, 1, "nop" },				//0x18
	{ R_ANAL_OP_TYPE_ADD, 1, "dad", { 3, 4, 3, rp } },		//0x19
	{ R_ANAL_OP_TYPE_LOAD, 1, "ldax", { 3, 4, 3, rp }},		//0x1a
	{ R_ANAL_OP_TYPE_SUB, 1, "dcx", { 3, 4, 3, rp } },		//0x1b
	{ R_ANAL_OP_TYPE_ADD, 1, "inr", { 3, 3, 7, reg } },  		//0x1c
	{ R_ANAL_OP_TYPE_SUB, 1, "dcr", { 3, 3, 7, reg } },		//0x1d
	{ R_ANAL_OP_TYPE_MOV, 2, "mvi", { 3, 3, 7, reg }, { 1 } },  	//0x1e
	{ R_ANAL_OP_TYPE_ROR, 1, "rar" },				//0x1f

	{ R_ANAL_OP_TYPE_NOP, 1, "nop" }, 				//0x20
	{ R_ANAL_OP_TYPE_LOAD, 3, "lxi", { 3, 4, 3, rp }, { 2 } },  	//0x21
	{ R_ANAL_OP_TYPE_STORE, 3, "shld", { 2 } },			//0x22
	{ R_ANAL_OP_TYPE_ADD, 1, "inx", { 3, 4, 3, rp } },  		//0x23
	{ R_ANAL_OP_TYPE_ADD, 1, "inr", { 3, 3, 7, reg } },  		//0x24
	{ R_ANAL_OP_TYPE_SUB, 1, "dcr", { 3, 3, 7, reg } },		//0x25
	{ R_ANAL_OP_TYPE_LOAD, 2, "mvi", { 3, 3, 7, reg }, { 1 } },	//0x26
	{ R_ANAL_OP_TYPE_ADD, 1, "daa" },				//0x27
	{ R_ANAL_OP_TYPE_NOP, 1, "nop" },				//0x28
	{ R_ANAL_OP_TYPE_ADD, 1, "dad", { 3, 4, 3, rp } },		//0x29
	{ R_ANAL_OP_TYPE_LOAD, 3, "lhld", { 2 } },			//0x2a
	{ R_ANAL_OP_TYPE_SUB, 1, "dcx", { 3, 4, 3, rp } },		//0x2b
	{ R_ANAL_OP_TYPE_ADD, 1, "inr", { 3, 3, 7, reg } },  		//0x2c
	{ R_ANAL_OP_TYPE_SUB, 1, "dcr", { 3, 3, 7, reg } },		//0x2d
	{ R_ANAL_OP_TYPE_MOV, 2, "mvi", { 3, 3, 7, reg }, { 1 } },  	//0x2e
	{ R_ANAL_OP_TYPE_CPL, 1, "cma" },				//0x2f

	{ R_ANAL_OP_TYPE_NOP, 1, "nop" }, 				//0x30
	{ R_ANAL_OP_TYPE_LOAD, 3, "lxi", { 3, 4, 3, rp }, { 2 } },  	//0x31
	{ R_ANAL_OP_TYPE_STORE, 3, "sta", { 2 } },			//0x32
	{ R_ANAL_OP_TYPE_ADD, 1, "inx", { 3, 4, 3, rp } },  		//0x33
	{ R_ANAL_OP_TYPE_ADD, 1, "inr", { 3, 3, 7, reg } },  		//0x34
	{ R_ANAL_OP_TYPE_SUB, 1, "dcr", { 3, 3, 7, reg } },		//0x35
	{ R_ANAL_OP_TYPE_LOAD, 2, "mvi", { 3, 3, 7, reg }, { 1 } },	//0x36
	{ R_ANAL_OP_TYPE_ROL, 1, "stc" },				//0x37
	{ R_ANAL_OP_TYPE_NOP, 1, "nop" },				//0x38
	{ R_ANAL_OP_TYPE_ADD, 1, "dad", { 3, 4, 3, rp } },		//0x39
	{ R_ANAL_OP_TYPE_LOAD, 3, "lda", { 2 } },			//0x3a
	{ R_ANAL_OP_TYPE_SUB, 1, "dcx", { 3, 4, 3, rp } },		//0x3b
	{ R_ANAL_OP_TYPE_ADD, 1, "inr", { 3, 3, 7, reg } },  		//0x3c
	{ R_ANAL_OP_TYPE_SUB, 1, "dcr", { 3, 3, 7, reg } },		//0x3d
	{ R_ANAL_OP_TYPE_MOV, 2, "mvi", { 3, 3, 7, reg }, { 1 } },  	//0x3e
	{ R_ANAL_OP_TYPE_CPL, 1, "cmc" },				//0x3f

	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x40
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x41
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x42
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x43
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x44
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x45
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x46
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x47
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x48
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x49
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x4a
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x4b
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x4c
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x4d
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x4e
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x4f

	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x50
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x51
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x52
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x53
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x54
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x55
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x56
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x57
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x58
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x59
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x5a
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x5b
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x5c
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x5d
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x5e
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x5f

	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x60
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x61
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x62
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x63
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x64
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x65
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x66
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x67
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x68
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x69
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x6a
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x6b
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x6c
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x6d
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x6e
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x6f

	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x70
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x71
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x72
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x73
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x74
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x75
	{ R_ANAL_OP_TYPE_NOP, 1, "hlt" }, 				      //0x76
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x77
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x78
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x79
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x7a
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x7b
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x7c
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x7d
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x7e
	{ R_ANAL_OP_TYPE_MOV, 1, "mov", { 3, 3, 7, reg }, { 3, 0, 7, reg } }, //0x7f

	{ R_ANAL_OP_TYPE_ADD, 1, "add", { 3, 0, 7, reg } }, //0x80
	{ R_ANAL_OP_TYPE_ADD, 1, "add", { 3, 0, 7, reg } }, //0x81
	{ R_ANAL_OP_TYPE_ADD, 1, "add", { 3, 0, 7, reg } }, //0x82
	{ R_ANAL_OP_TYPE_ADD, 1, "add", { 3, 0, 7, reg } }, //0x83
	{ R_ANAL_OP_TYPE_ADD, 1, "add", { 3, 0, 7, reg } }, //0x84
	{ R_ANAL_OP_TYPE_ADD, 1, "add", { 3, 0, 7, reg } }, //0x85
	{ R_ANAL_OP_TYPE_ADD, 1, "add", { 3, 0, 7, reg } }, //0x86
	{ R_ANAL_OP_TYPE_ADD, 1, "add", { 3, 0, 7, reg } }, //0x87
	{ R_ANAL_OP_TYPE_ADD, 1, "adc", { 3, 0, 7, reg } }, //0x88
	{ R_ANAL_OP_TYPE_ADD, 1, "adc", { 3, 0, 7, reg } }, //0x89
	{ R_ANAL_OP_TYPE_ADD, 1, "adc", { 3, 0, 7, reg } }, //0x8a
	{ R_ANAL_OP_TYPE_ADD, 1, "adc", { 3, 0, 7, reg } }, //0x8b
	{ R_ANAL_OP_TYPE_ADD, 1, "adc", { 3, 0, 7, reg } }, //0x8c
	{ R_ANAL_OP_TYPE_ADD, 1, "adc", { 3, 0, 7, reg } }, //0x8d
	{ R_ANAL_OP_TYPE_ADD, 1, "adc", { 3, 0, 7, reg } }, //0x8e
	{ R_ANAL_OP_TYPE_ADD, 1, "adc", { 3, 0, 7, reg } }, //0x8f

	{ R_ANAL_OP_TYPE_SUB, 1, "sub", { 3, 0, 7, reg } }, //0x90
	{ R_ANAL_OP_TYPE_SUB, 1, "sub", { 3, 0, 7, reg } }, //0x91
	{ R_ANAL_OP_TYPE_SUB, 1, "sub", { 3, 0, 7, reg } }, //0x92
	{ R_ANAL_OP_TYPE_SUB, 1, "sub", { 3, 0, 7, reg } }, //0x93
	{ R_ANAL_OP_TYPE_SUB, 1, "sub", { 3, 0, 7, reg } }, //0x94
	{ R_ANAL_OP_TYPE_SUB, 1, "sub", { 3, 0, 7, reg } }, //0x95
	{ R_ANAL_OP_TYPE_SUB, 1, "sub", { 3, 0, 7, reg } }, //0x96
	{ R_ANAL_OP_TYPE_SUB, 1, "sub", { 3, 0, 7, reg } }, //0x97
	{ R_ANAL_OP_TYPE_SUB, 1, "sbb", { 3, 0, 7, reg } }, //0x98
	{ R_ANAL_OP_TYPE_SUB, 1, "sbb", { 3, 0, 7, reg } }, //0x99
	{ R_ANAL_OP_TYPE_SUB, 1, "sbb", { 3, 0, 7, reg } }, //0x9a
	{ R_ANAL_OP_TYPE_SUB, 1, "sbb", { 3, 0, 7, reg } }, //0x9b
	{ R_ANAL_OP_TYPE_SUB, 1, "sbb", { 3, 0, 7, reg } }, //0x9c
	{ R_ANAL_OP_TYPE_SUB, 1, "sbb", { 3, 0, 7, reg } }, //0x9d
	{ R_ANAL_OP_TYPE_SUB, 1, "sbb", { 3, 0, 7, reg } }, //0x9e
	{ R_ANAL_OP_TYPE_SUB, 1, "sbb", { 3, 0, 7, reg } }, //0x9f

	{ R_ANAL_OP_TYPE_AND, 1, "ana", { 3, 0, 7, reg } }, //0xa0
	{ R_ANAL_OP_TYPE_AND, 1, "ana", { 3, 0, 7, reg } }, //0xa1
	{ R_ANAL_OP_TYPE_AND, 1, "ana", { 3, 0, 7, reg } }, //0xa2
	{ R_ANAL_OP_TYPE_AND, 1, "ana", { 3, 0, 7, reg } }, //0xa3
	{ R_ANAL_OP_TYPE_AND, 1, "ana", { 3, 0, 7, reg } }, //0xa4
	{ R_ANAL_OP_TYPE_AND, 1, "ana", { 3, 0, 7, reg } }, //0xa5
	{ R_ANAL_OP_TYPE_AND, 1, "ana", { 3, 0, 7, reg } }, //0xa6
	{ R_ANAL_OP_TYPE_AND, 1, "ana", { 3, 0, 7, reg } }, //0xa7
	{ R_ANAL_OP_TYPE_XOR, 1, "xra", { 3, 0, 7, reg } }, //0xa8
	{ R_ANAL_OP_TYPE_XOR, 1, "xra", { 3, 0, 7, reg } }, //0xa9
	{ R_ANAL_OP_TYPE_XOR, 1, "xra", { 3, 0, 7, reg } }, //0xaa
	{ R_ANAL_OP_TYPE_XOR, 1, "xra", { 3, 0, 7, reg } }, //0xab
	{ R_ANAL_OP_TYPE_XOR, 1, "xra", { 3, 0, 7, reg } }, //0xac
	{ R_ANAL_OP_TYPE_XOR, 1, "xra", { 3, 0, 7, reg } }, //0xad
	{ R_ANAL_OP_TYPE_XOR, 1, "xra", { 3, 0, 7, reg } }, //0xae
	{ R_ANAL_OP_TYPE_XOR, 1, "xra", { 3, 0, 7, reg } }, //0xaf

	{ R_ANAL_OP_TYPE_OR, 1, "ora", { 3, 0, 7, reg } },  //0xb0
	{ R_ANAL_OP_TYPE_OR, 1, "ora", { 3, 0, 7, reg } },  //0xb1
	{ R_ANAL_OP_TYPE_OR, 1, "ora", { 3, 0, 7, reg } },  //0xb2
	{ R_ANAL_OP_TYPE_OR, 1, "ora", { 3, 0, 7, reg } },  //0xb3
	{ R_ANAL_OP_TYPE_OR, 1, "ora", { 3, 0, 7, reg } },  //0xb4
	{ R_ANAL_OP_TYPE_OR, 1, "ora", { 3, 0, 7, reg } },  //0xb5
	{ R_ANAL_OP_TYPE_OR, 1, "ora", { 3, 0, 7, reg } },  //0xb6
	{ R_ANAL_OP_TYPE_OR, 1, "ora", { 3, 0, 7, reg } },  //0xb7
	{ R_ANAL_OP_TYPE_CMP, 1, "cmp", { 3, 0, 7, reg } }, //0xb8
	{ R_ANAL_OP_TYPE_CMP, 1, "cmp", { 3, 0, 7, reg } }, //0xb9
	{ R_ANAL_OP_TYPE_CMP, 1, "cmp", { 3, 0, 7, reg } }, //0xba
	{ R_ANAL_OP_TYPE_CMP, 1, "cmp", { 3, 0, 7, reg } }, //0xbb
	{ R_ANAL_OP_TYPE_CMP, 1, "cmp", { 3, 0, 7, reg } }, //0xbc
	{ R_ANAL_OP_TYPE_CMP, 1, "cmp", { 3, 0, 7, reg } }, //0xbd
	{ R_ANAL_OP_TYPE_CMP, 1, "cmp", { 3, 0, 7, reg } }, //0xbe
	{ R_ANAL_OP_TYPE_CMP, 1, "cmp", { 3, 0, 7, reg } }, //0xbf

	{ R_ANAL_OP_TYPE_CRET, 1, "rnz" },                   //0xc0
	{ R_ANAL_OP_TYPE_POP, 1, "pop", { 3, 4, 3, push_rp } },  //0xc1
	{ R_ANAL_OP_TYPE_CJMP, 3, "jnz", { 2 } },            //0xc2
	{ R_ANAL_OP_TYPE_JMP, 3, "jmp", { 2 } },             //0xc3
	{ R_ANAL_OP_TYPE_CCALL, 3, "cnz", { 2 } },           //0xc4
	{ R_ANAL_OP_TYPE_PUSH, 1, "push", { 3, 4, 3, push_rp } },//0xc5
	{ R_ANAL_OP_TYPE_ADD, 2, "adi", { 1 } },             //0xc6
	{ R_ANAL_OP_TYPE_CALL, 1, "rst", { 3, 3, 7, rst } }, //0xc7
	{ R_ANAL_OP_TYPE_CRET, 1, "rz" },                    //0xc8
	{ R_ANAL_OP_TYPE_RET, 1, "ret" },                    //0xc9
	{ R_ANAL_OP_TYPE_CMP, 3, "jz", { 2 } },              //0xca
	{ R_ANAL_OP_TYPE_UNK, 1, "invalid" },                //0xcb ilegal opcode
	{ R_ANAL_OP_TYPE_CCALL, 3, "cz", { 2 } },            //0xcc
	{ R_ANAL_OP_TYPE_CALL, 3, "call", { 2 } },           //0xcd
	{ R_ANAL_OP_TYPE_ADD, 2, "aci", { 1 } },  //0xce
	{ R_ANAL_OP_TYPE_CALL, 1, "rst", { 3, 3, 7, rst }},  //0xcf

	{ R_ANAL_OP_TYPE_CRET, 1, "rnc" },                       //0xd0
	{ R_ANAL_OP_TYPE_POP, 1, "pop", { 3, 4, 3, push_rp } },  //0xd1
	{ R_ANAL_OP_TYPE_CJMP, 3, "jnc", { 2 } },                //0xd2
	{ R_ANAL_OP_TYPE_IO, 2, "out", { 1 } },                  //0xd3
	{ R_ANAL_OP_TYPE_CCALL, 3, "cnc", { 2 } },               //0xd4
	{ R_ANAL_OP_TYPE_PUSH, 1, "push", { 3, 4, 3, push_rp } },//0xd5
	{ R_ANAL_OP_TYPE_SUB, 2, "sui", { 1 } },                 //0xd6
	{ R_ANAL_OP_TYPE_JMP, 1, "rst", { 3, 3, 7, rst }},       //0xd7
	{ R_ANAL_OP_TYPE_CRET, 1, "rc" },                        //0xd8
	{ R_ANAL_OP_TYPE_UNK, 1, "invalid" },                    //0xd9 ilegal opcode
	{ R_ANAL_OP_TYPE_CJMP, 3, "jc", { 2 } },                 //0xda
	{ R_ANAL_OP_TYPE_IO, 2, "in", { 1 } },                   //0xdb
	{ R_ANAL_OP_TYPE_CCALL, 3, "cc", { 2 } },                //0xdc
	{ R_ANAL_OP_TYPE_UNK, 3, "invalid", { 2 } },             //0xdd ilegal opcode
	{ R_ANAL_OP_TYPE_SUB, 2, "sbi", { 1 } },                 //0xde
	{ R_ANAL_OP_TYPE_CALL, 1, "rst", { 3, 3, 7, rst } },     //0xdf

	{ R_ANAL_OP_TYPE_CRET, 1, "rpo" },                       //0xe0
	{ R_ANAL_OP_TYPE_POP, 1, "pop", { 3, 4, 3, push_rp } },  //0xe1
	{ R_ANAL_OP_TYPE_CJMP, 3, "jpo", { 2 } },                //0xe2
	{ R_ANAL_OP_TYPE_UNK, 1, "xthl" },                       //0xe3
	{ R_ANAL_OP_TYPE_CCALL, 3, "cpo", { 2 } },               //0xe4
	{ R_ANAL_OP_TYPE_PUSH, 1, "push", { 3, 4, 3, push_rp } },//0xe5
	{ R_ANAL_OP_TYPE_AND, 2, "ani", { 1 } },                 //0xe6
	{ R_ANAL_OP_TYPE_JMP, 1, "rst", { 3, 3, 7, rst }},       //0xe7
	{ R_ANAL_OP_TYPE_CRET, 1, "rpe" },                       //0xe8
	{ R_ANAL_OP_TYPE_UNK, 1, "pchl" },                       //0xe9
	{ R_ANAL_OP_TYPE_CJMP, 3, "jpe", { 2 } },                //0xea
	{ R_ANAL_OP_TYPE_MOV, 1, "xchg" },                       //0xeb
	{ R_ANAL_OP_TYPE_CCALL, 3, "cpe", { 2 } },               //0xec
	{ R_ANAL_OP_TYPE_UNK, 3, "invalid", { 2 } },             //0xed ilegal opcode
	{ R_ANAL_OP_TYPE_XOR, 2, "xri", { 1 } },                 //0xee
	{ R_ANAL_OP_TYPE_CALL, 1, "rst", { 3, 3, 7, rst } },     //0xef

	{ R_ANAL_OP_TYPE_CRET, 1, "rp" },                         //0xf0
	{ R_ANAL_OP_TYPE_POP, 1, "pop", { 3, 4, 3, push_rp } },   //0xf1
	{ R_ANAL_OP_TYPE_CJMP, 3, "jp", { 2 } },                  //0xf2
	{ R_ANAL_OP_TYPE_IO, 1, "di" },                           //0xf3
	{ R_ANAL_OP_TYPE_CCALL, 3, "cp", { 2 } },                 //0xf4
	{ R_ANAL_OP_TYPE_PUSH, 1, "push", { 3, 4, 3, push_rp } }, //0xf5
	{ R_ANAL_OP_TYPE_OR, 2, "ori", { 1 } },                   //0xf6
	{ R_ANAL_OP_TYPE_JMP, 1, "rst", { 3, 3, 7, rst }},        //0xf7
	{ R_ANAL_OP_TYPE_CRET, 1, "rm" },                         //0xf8
	{ R_ANAL_OP_TYPE_LOAD, 1, "sphl" },                       //0xf9
	{ R_ANAL_OP_TYPE_CJMP, 3, "jm", { 2 } },                  //0xfa
	{ R_ANAL_OP_TYPE_IO, 1, "ei" },                           //0xfb
	{ R_ANAL_OP_TYPE_CCALL, 3, "cm", { 2 } },                 //0xfc
	{ R_ANAL_OP_TYPE_UNK, 3, "invalid", { 2 } },              //0xfd ilegal opcode
	{ R_ANAL_OP_TYPE_CMP, 2, "cpi", { 1 } },                  //0xfe
	{ R_ANAL_OP_TYPE_CALL, 1, "rst", { 3, 3, 7, rst } },      //0xff
};


#endif
