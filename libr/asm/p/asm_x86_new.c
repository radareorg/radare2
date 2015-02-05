/* Copyright (C) 2015 - aaronpuchert */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

/**
 * Types of operands: we describe them via a bit field. The first two bytes
 * describe the storage: that could be a memory location, an immediate or one
 * of several register types. The third byte masks the registers, since for
 * example FPU commands always have a fixed operand st(0). The fourth byte
 * describes the size of an operand.
 *
 * We implement them as bitfields to allow operations to describe what operands
 * are accepted. For example many accept a register or memory location in the
 * same operand with the same opcode.
 *
 * +--------+--------+--------+--------+
 * |76543210|76543210|76543210|76543210|
 * |    size|spec.reg| xmfdcsg| imm mem|
 * +--------+--------+--------+--------+
 */
#define REGTYPE_SHIFT   8
#define REGMASK_SHIFT  16
#define OPSIZE_SHIFT   24

// Memory operands or immediates
#define OT_MEMORY      (1 << 0)
#define OT_IMMEDIATE   (1 << 4)
#define OT_JMPADDRESS  (1 << 5)
#define OT_MEMADDRESS  (1 << 6)
// OT_MEMORY | OT_MEMADDRESS are written like memory operands in assembly, but
// encoded as immediates. Jump distances shall have an extra flag OT_JMPADDRESS
// because they are relative to the offset.

// Register types - by default, we allow all registers
#define OT_REGALL   (0xff << REGMASK_SHIFT)
#define OT_GPREG      ((1 << (REGTYPE_SHIFT + 0)) | OT_REGALL)
#define OT_SEGMENTREG ((1 << (REGTYPE_SHIFT + 1)) | OT_REGALL)
#define OT_CONTROLREG ((1 << (REGTYPE_SHIFT + 2)) | OT_REGALL)
#define OT_FPUREG     ((1 << (REGTYPE_SHIFT + 4)) | OT_REGALL)
#define OT_DEBUGREG   ((1 << (REGTYPE_SHIFT + 3)) | OT_REGALL)
#define OT_REGMMX     ((1 << (REGTYPE_SHIFT + 5)) | OT_REGALL)
#define OT_REGXMM     ((1 << (REGTYPE_SHIFT + 6)) | OT_REGALL)
// more?

// Register mask
#define OT_REG(num)  ((1 << (REGMASK_SHIFT + (num))) | (0xff << REGTYPE_SHIFT))

#define OT_UNKNOWN    (0 << OPSIZE_SHIFT)
#define OT_BYTE       (1 << OPSIZE_SHIFT)
#define OT_WORD       (2 << OPSIZE_SHIFT)
#define OT_DWORD      (4 << OPSIZE_SHIFT)
#define OT_QWORD      (8 << OPSIZE_SHIFT)
#define OT_OWORD     (16 << OPSIZE_SHIFT)
#define OT_TBYTE     (32 << OPSIZE_SHIFT)

// For register operands, we mostl don't care about the size.
// So let's just set all relevant flags.
#define OT_FPUSIZE  (OT_DWORD | OT_QWORD | OT_TBYTE)
#define OT_XMMSIZE  (OT_DWORD | OT_QWORD | OT_OWORD)

/**
 * Registers. The size isn't a concern here, since Operand already takes care
 * of it. We want them to be numbered in the same way they are encoded in the
 * RM and spec fields of the ModRM byte.
 */
typedef enum register_t {
	X86R_UNDEFINED = -1,
	X86R_EAX = 0, X86R_ECX, X86R_EDX, X86R_EBX, X86R_ESP, X86R_EBP, X86R_ESI, X86R_EDI,
	X86R_AX = 0, X86R_CX, X86R_DX, X86R_BX, X86R_SP, X86R_BP, X86R_SI, X86R_DI,
	X86R_AL = 0, X86R_CL, X86R_DL, X86R_BL, X86R_AH, X86R_CH, X86R_DH, X86R_BH,
//	X86R_RAX = 0, X86R_RCX, X86R_RDX, X86R_RBX, X86R_RSP, X86R_RBP, X86R_RSI, X86R_RDI,
	X86R_CS = 0, X86R_SS, X86R_DS, X86R_ES, X86R_FS, X86R_GS	// Is this the right order?
} Register;

/**
 * Instruction operands.
 */
typedef struct operand_t {
	ut32 type;

	union {
		// Register operand
		Register reg;

		// Memory operand
		struct {
			long offset;
			Register regs[2];
			int scale[2];
		};

		// Constant operand (can be at most 4 bytes)
		ut32 immediate;
	};
} Operand;


/////////////////////
// ASSEMBLY PARSER //
/////////////////////

/**
 * Types of tokens for the parser.
 */
typedef enum tokentype_t {
	TT_EOF,
	TT_WORD,
	TT_NUMBER,
	TT_SPECIAL
} x86newTokenType;

/**
 * Get the next token in str, starting at *begin. Write the index of the first
 * character after the token to *end. Return the type of the token.
 */
static x86newTokenType getToken(const char *str, int *begin, int *end) {
	// Skip whitespace
	while (isspace(str[*begin]))
		++(*begin);


	if (!str[*begin]) {                // null byte
		*end = *begin;
		return TT_EOF;
	}
	else if (isalpha(str[*begin])) {   // word token
		*end = *begin;
		while (isalnum(str[*end]))
			++(*end);
		return TT_WORD;
	}
	else if (isdigit(str[*begin])) {   // number token
		*end = *begin;
		while (isalnum(str[*end]))     // accept alphanumeric characters, because hex.
			++(*end);
		return TT_NUMBER;
	}
	else {                             // special character: [, ], +, *, ...
		*end = *begin + 1;
		return TT_SPECIAL;
	}
}

/**
 * Get the register denoted by str[0]..str[len-1].
 */
static Register parseReg(const char *str, int len, ut32 *type) {
	int i;
	// Must be the same order as in enum register_t
	const char *regs[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", NULL };
	const char *regs8[] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", NULL };
	const char *regs16[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", NULL };
//	const char *regs64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", NULL };

	for (i=0; regs[i]; i++)
		if (!strncasecmp (regs[i], str, len)) {
			*type = (OT_GPREG & OT_REG(i)) | OT_DWORD;
			return i;
		}
	for (i=0; regs8[i]; i++)
		if (!strncasecmp (regs8[i], str, len)) {
			*type = (OT_GPREG & OT_REG(i)) | OT_BYTE;
			return i;
		}
	for (i=0; regs16[i]; i++)
		if (!strncasecmp (regs16[i], str, len)) {
			*type = (OT_GPREG & OT_REG(i)) | OT_WORD;
			return i;
		}
/*	for (i=0; regs64[i]; i++)
		if (!strncasecmp (regs64[i], str, len)) {
			*type = (OT_GPREG & OT_REG(i)) | OT_QWORD;
			return i;
		} */
	return X86R_UNDEFINED;
}

/**
 * Read decimal or hexadecimal number.
 */
static ut64 readNumber(const char *str, x86newTokenType type) {
	int hex = (str[0] == '0' && str[1] == 'x');
	return strtol(str + 2*hex, 0, hex ? 16 : 10);
}

// Parse operand
static int parseOperand(const char *str, Operand *op) {
	int pos;
	int nextpos = 0;
	x86newTokenType last_type;
	int size_token = 1;

	// Reset type
	op->type = 0;

	// Consume tokens denoting the operand size
	while (size_token) {
		pos = nextpos;
		last_type = getToken(str, &pos, &nextpos);

		// Token may indicate size: then skip
		if (!strncasecmp(str + pos, "ptr", 3))
			;
		else if (!strncasecmp(str + pos, "byte", 4))
			op->type |= OT_MEMORY | OT_BYTE;
		else if (!strncasecmp(str + pos, "word", 4))
			op->type |= OT_MEMORY | OT_WORD;
		else if (!strncasecmp(str + pos, "dword", 5))
			op->type |= OT_MEMORY | OT_DWORD;
		else if (!strncasecmp(str + pos, "qword", 5))
			op->type |= OT_MEMORY | OT_QWORD;
		else if (!strncasecmp(str + pos, "oword", 5))
			op->type |= OT_MEMORY | OT_OWORD;
		else if (!strncasecmp(str + pos, "tbyte", 5))
			op->type |= OT_MEMORY | OT_TBYTE;
		else	// the current token doesn't denote a size
			size_token = 0;
	}

	// Next token: register, immediate, or '['
	if (str[pos] == '[') {
		// Don't care about size, if none is given.
		if (!op->type)
			op->type = OT_MEMORY;

		// At the moment, we only accept plain linear combinations:
		// part := address | [factor *] register
		// address := part {+ part}*
		op->offset = op->scale[0] = op->scale[1] = 0;

		ut64 temp = 1;
		Register reg = X86R_UNDEFINED;
		int reg_index = 0;
		while (str[pos] != ']') {
			pos = nextpos;
			last_type = getToken(str, &pos, &nextpos);

			if (last_type == TT_SPECIAL) {
				if (str[pos] == '+' || str[pos] == ']') {
					if (reg != X86R_UNDEFINED) {
						op->regs[reg_index] = reg;
						op->scale[reg_index] = temp;
						++reg_index;
					}
					else
						op->offset += temp;

					temp = 1;
					reg = X86R_UNDEFINED;
				}
				else if (str[pos] == '*') {
					// Something to do here?
					// Seems we are just ignoring '*' or assuming it implicitly.
				}
			}
			else if (last_type == TT_WORD) {
				ut32 reg_type;
				if (reg != X86R_UNDEFINED)
					op->type = 0;	// Make the result invalid
				reg = parseReg(str + pos, nextpos - pos, &reg_type);
				if (!(reg_type & OT_GPREG))
					op->type = 0;	// Make the result invalid
			}
			else {
				ut64 read = readNumber(str + pos, last_type);
				temp *= read;
			}
		}
	}
	else if (last_type == TT_WORD) {   // register
		op->reg = parseReg(str + pos, nextpos - pos, &op->type);
	}
	else {                             // immediate
		// We don't know the size, so let's just set no size flag.
		op->type = OT_IMMEDIATE;
		op->immediate = readNumber(str + pos, last_type);
	}

	return nextpos;
}


///////////////////////
// INSTRUCTION TABLE //
///////////////////////

/**
 * This is the most important structure: it links specific opcodes to mnemonics.
 * Obviously, this is far away from being one-to-one.
 */
typedef struct opcode_t {
	char mnemonic[12];
	ut32 op[3];         // Accepted operands, (implicitly) filled up with 0 = nothing
	size_t op_len;      // Length of opcode
	ut8 opcode[3];      // Opcode bytes
	ut32 special;       // Special encoding
} Opcode;

// Some operations are encoded via opcode + spec field
#define SPECIAL_SPEC 0x00010000
#define SPECIAL_MASK 0x00000007

Opcode opcodes[] = {
	/////// 0x0_ ///////
	{"add", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x00}},
	{"add", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x01}},
	{"add", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x02}},
	{"add", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x03}},
	{"add", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x04}},
	{"add", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x05}},

	{"push", {(OT_SEGMENTREG & OT_REG(X86R_ES))}, 1, {0x06}},
	{"pop", {(OT_SEGMENTREG & OT_REG(X86R_ES))}, 1, {0x07}},

	{"or", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x08}},
	{"or", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x09}},
	{"or", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x0A}},
	{"or", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x0B}},
	{"or", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x0C}},
	{"or", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x0D}},

	{"push", {(OT_SEGMENTREG & OT_REG(X86R_CS))}, 1, {0x0E}},
	// Two byte opcodes start with 0x0F

	/////// 0x1_ ///////
	{"adc", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x10}},
	{"adc", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x11}},
	{"adc", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x12}},
	{"adc", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x13}},
	{"adc", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x14}},
	{"adc", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x15}},

	{"push", {(OT_SEGMENTREG & OT_REG(X86R_SS))}, 1, {0x16}},
	{"pop", {(OT_SEGMENTREG & OT_REG(X86R_SS))}, 1, {0x17}},

	{"sbb", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x18}},
	{"sbb", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x19}},
	{"sbb", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x1A}},
	{"sbb", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x1B}},
	{"sbb", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x1C}},
	{"sbb", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x1D}},

	{"push", {(OT_SEGMENTREG & OT_REG(X86R_DS))}, 1, {0x1E}},
	{"pop", {(OT_SEGMENTREG & OT_REG(X86R_DS))}, 1, {0x1F}},

	/////// 0x2_ ///////
	{"and", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x20}},
	{"and", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x21}},
	{"and", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x22}},
	{"and", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x23}},
	{"and", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x24}},
	{"and", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x25}},

	// 0x26: ES segment prefix
	{"daa", {}, 1, {0x27}},

	{"sub", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x28}},
	{"sub", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x29}},
	{"sub", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x2A}},
	{"sub", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x2B}},
	{"sub", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x2C}},
	{"sub", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x2D}},

	// 0x2E: CS segment prefix
	{"das", {}, 1, {0x2F}},

	/////// 0x3_ ///////
	{"xor", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x30}},
	{"xor", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x31}},
	{"xor", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x32}},
	{"xor", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x33}},
	{"xor", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x34}},
	{"xor", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x35}},

	// 0x36: SS segment prefix
	{"aaa", {}, 1, {0x37}},

	{"cmp", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x38}},
	{"cmp", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x39}},
	{"cmp", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x3A}},
	{"cmp", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x3B}},
	{"cmp", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x3C}},
	{"cmp", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x3D}},

	// 0x3E: DS segment prefix
	{"aas", {}, 1, {0x3F}},

	/////// 0x4_ ///////
	{"inc", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x40}},
	{"inc", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x41}},
	{"inc", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x42}},
	{"inc", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x43}},
	{"inc", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x44}},
	{"inc", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x45}},
	{"inc", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x46}},
	{"inc", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x47}},
	{"dec", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x48}},
	{"dec", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x49}},
	{"dec", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x4A}},
	{"dec", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x4B}},
	{"dec", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x4C}},
	{"dec", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x4D}},
	{"dec", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x4E}},
	{"dec", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x4F}},

	/////// 0x5_ ///////
	{"push", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x50}},
	{"push", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x51}},
	{"push", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x52}},
	{"push", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x53}},
	{"push", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x54}},
	{"push", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x55}},
	{"push", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x56}},
	{"push", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x57}},
	{"pop", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x58}},
	{"pop", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x59}},
	{"pop", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x5A}},
	{"pop", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x5B}},
	{"pop", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x5C}},
	{"pop", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x5D}},
	{"pop", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x5E}},
	{"pop", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x5F}},

	/////// 0x6_ ///////
	{"pusha", {}, 1, {0x60}},	{"pushad", {}, 1, {0x60}},
	{"popa", {}, 1, {0x61}},	{"popad", {}, 1, {0x61}},
	{"bound", {OT_GPREG | OT_DWORD, OT_MEMORY | OT_QWORD}, 1, {0x62}},
	{"arpl", {OT_GPREG | OT_MEMORY | OT_WORD, OT_GPREG | OT_WORD}, 1, {0x63}},
	// 0x64: FS segment prefix
	// 0x65: GS segment prefix
	// 0x66: operand size prefix
	// 0x67: address size prefix
	{"push", {OT_IMMEDIATE | OT_DWORD}, 1, {0x68}},
	{"imul", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x69}},
	{"push", {OT_IMMEDIATE | OT_BYTE}, 1, {0x6A}},
	{"imul", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x6B}},
	{"insb", {}, 1, {0x6C}},
	{"ins", {}, 1, {0x6D}}, {"insd", {}, 1, {0x6D}},
	{"insw", {}, 2, {0x66, 0x6D}},
	{"outsb", {}, 1, {0x6E}},
	{"outs", {}, 1, {0x6F}}, {"outsd", {}, 1, {0x6F}},
	{"outsw", {}, 2, {0x66, 0x6F}},

	/////// 0x7_ ///////
	{"jo", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x70}},
	{"jno", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x71}},
	{"jb", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x72}},
	{"jnae", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x72}},
	{"jc", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x72}},
	{"jnb", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x73}},
	{"jae", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x73}},
	{"jnc", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x73}},
	{"jz", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x74}},
	{"je", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x74}},
	{"jnz", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x75}},
	{"jne", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x75}},
	{"jbe", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x76}},
	{"jna", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x76}},
	{"jnbe", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x77}},
	{"ja", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x77}},
	{"js", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x78}},
	{"jns", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x79}},
	{"jp", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7A}},
	{"jpe", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7A}},
	{"jnp", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7B}},
	{"jpo", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7B}},
	{"jl", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7C}},
	{"jnge", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7C}},
	{"jnl", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7D}},
	{"jge", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7D}},
	{"jle", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7E}},
	{"jng", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7E}},
	{"jnle", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7F}},
	{"jg", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0x7F}},

	/////// 0x8_ ///////
	// 0x80 -- 0x83: immediate group 1
	// 0x84, 0x85: TODO: test
	// 0x86, 0x87: TODO: xchg
	{"mov", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_GPREG | OT_BYTE}, 1, {0x88}},
	{"mov", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_GPREG | OT_DWORD}, 1, {0x89}},
	{"mov", {OT_GPREG | OT_BYTE, OT_GPREG | OT_MEMORY | OT_BYTE}, 1, {0x8A}},
	{"mov", {OT_GPREG | OT_DWORD, OT_GPREG | OT_MEMORY | OT_DWORD}, 1, {0x8B}},
	{"mov", {OT_MEMORY | OT_WORD, OT_SEGMENTREG | OT_WORD}, 1, {0x8C}}, // ?
	{"lea", {OT_GPREG | OT_DWORD, OT_MEMORY | OT_DWORD}, 1, {0x8D}},	// allow all sizes?
	{"mov", {OT_SEGMENTREG | OT_WORD, OT_MEMORY | OT_WORD}, 1, {0x8E}}, // ?
	{"pop", {}, 1, {0x8F}},  // ?

	/////// 0x9_ ///////
	{"nop", {}, 1, {0x90}},
	{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x90}},
	{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x91}},
	{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x92}},
	{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x93}},
	{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x94}},
	{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x95}},
	{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x96}},
	{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x97}},
	{"cbw", {}, 1, {0x98}},
	{"cwde", {}, 2, {0x66, 0x98}},  // ?
	{"cwd", {}, 1, {0x99}},
	{"cdq", {}, 2, {0x66, 0x99}},  // ?
	// 0x9A: TODO far call
	{"wait", {}, 1, {0x9B}},
	{"fwait", {}, 1, {0x9B}},
	{"pushfd", {}, 1, {0x9C}},
	{"popfd", {}, 1, {0x9D}},
	{"sahf", {}, 1, {0x9E}},
	{"lahf", {}, 1, {0x9F}},

	/////// 0xA_ ///////
	{"mov", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_MEMORY | OT_MEMADDRESS | OT_BYTE}, 1, {0xA0}},
	{"mov", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_MEMORY | OT_MEMADDRESS | OT_DWORD}, 1, {0xA1}},
	// 0xA2 -- 0xA3
	{"movsb", {}, 1, {0xA4}},
	{"movsd", {}, 1, {0xA5}},
	{"movsw", {}, 2, {0x66, 0xA5}},
	{"cmpsb", {}, 1, {0xA6}},
	{"cmpsd", {}, 1, {0xA7}},
	{"cmpsw", {}, 2, {0x66, 0xA7}},
	// 0xA8 -- 0xA9: as above
	{"stosb", {}, 1, {0xAA}},
	{"stosd", {}, 1, {0xAB}},
	{"stosw", {}, 2, {0x66, 0xAB}},
	{"lodsb", {}, 1, {0xAC}},
	{"lodsd", {}, 1, {0xAD}},
	{"lodsw", {}, 2, {0x66, 0xAD}},
	{"scasb", {}, 1, {0xAE}},
	{"scasd", {}, 1, {0xAF}},
	{"scasw", {}, 2, {0x66, 0xAF}},

	/////// 0xB_ ///////
	{"mov", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xB0}},
	{"mov", {(OT_GPREG & OT_REG(X86R_CL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xB1}},
	{"mov", {(OT_GPREG & OT_REG(X86R_DL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xB2}},
	{"mov", {(OT_GPREG & OT_REG(X86R_BL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xB3}},
	{"mov", {(OT_GPREG & OT_REG(X86R_AH)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xB4}},
	{"mov", {(OT_GPREG & OT_REG(X86R_CH)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xB5}},
	{"mov", {(OT_GPREG & OT_REG(X86R_DH)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xB6}},
	{"mov", {(OT_GPREG & OT_REG(X86R_BH)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xB7}},
	{"mov", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0xB8}},
	{"mov", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0xB9}},
	{"mov", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0xBA}},
	{"mov", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0xBB}},
	{"mov", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0xBC}},
	{"mov", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0xBD}},
	{"mov", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0xBE}},
	{"mov", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0xBF}},

	/////// 0xC_ ///////
	// 0xC0 -- 0xC1: shift group 2
	{"ret", {OT_IMMEDIATE | OT_WORD}, 1, {0xC2}},
	{"ret", {}, 1, {0xC3}},
	{"les", {OT_GPREG | OT_DWORD, OT_MEMORY | OT_BYTE}, 1, {0xC4}},
	{"lds", {OT_GPREG | OT_DWORD, OT_MEMORY | OT_BYTE}, 1, {0xC5}},
	// 0xC6 -- 0xC7 mov group
	{"enter", {OT_IMMEDIATE | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0xC8}},
	{"leave", {}, 1, {0xC9}},
	{"retf", {OT_IMMEDIATE | OT_WORD}, 1, {0xCA}},
	{"retf", {}, 1, {0xCB}},
	{"int3", {}, 1, {0xCC}},
	{"int", {OT_IMMEDIATE | OT_BYTE}, 1, {0xCD}},
	{"into", {}, 1, {0xCE}},
	{"iretd", {OT_IMMEDIATE | OT_BYTE}, 1, {0xCF}},

	/////// 0xD_ ///////
	// 0xD0 -- 0xD3: shift group 2
	{"aam", {OT_IMMEDIATE | OT_BYTE}, 1, {0xD4}},  // ?
	{"aad", {OT_IMMEDIATE | OT_BYTE}, 1, {0xD5}},  // ?
	// 0xD6: reserved
	{"xlatb", {}, 1, {0xD7}},
	// 0xD8 -- 0xDF: FPU

	/////// 0xE_ ///////
	{"loopne", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0xE0}},
	{"loope", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0xE1}},
	{"loop", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0xE2}},
	{"jcxz", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0xE3}},
	{"jecxz", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0xE3}},
	{"in", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0xE4}},
	{"in", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0xE5}},
	{"out", {OT_IMMEDIATE | OT_BYTE, (OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE}, 1, {0xE6}},
	{"out", {OT_IMMEDIATE | OT_BYTE, (OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0xE7}},
	{"call", {OT_IMMEDIATE | OT_DWORD}, 1, {0xE8}},
	{"jmp", {OT_IMMEDIATE | OT_JMPADDRESS | OT_DWORD}, 1, {0xE9}},
	{"jmp", {OT_IMMEDIATE | OT_JMPADDRESS | OT_DWORD}, 1, {0xEA}},  // ?
	{"jmp", {OT_IMMEDIATE | OT_JMPADDRESS | OT_BYTE}, 1, {0xEB}},
	{"in", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, (OT_GPREG & OT_REG(X86R_DX)) | OT_WORD}, 1, {0xEC}},
	{"in", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_DX)) | OT_WORD}, 1, {0xED}},
	{"out", {(OT_GPREG & OT_REG(X86R_DX)) | OT_WORD, (OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE}, 1, {0xEE}},
	{"out", {(OT_GPREG & OT_REG(X86R_DX)) | OT_WORD, (OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0xEF}},

	/////// 0xF_ ///////
	// 0xF0: lock prefix
	// 0xF1: reserved
	// 0xF2: repne prefix
	// 0xF3: rep(e) prefix
	{"hlt", {}, 1, {0xF4}},
	{"cmc", {}, 1, {0xF5}},
	// 0xF6 -- 0xF7: unary group 3
	{"clc", {}, 1, {0xF8}},
	{"stc", {}, 1, {0xF9}},
	{"cli", {}, 1, {0xFA}},
	{"sti", {}, 1, {0xFB}},
	{"cld", {}, 1, {0xFC}},
	{"std", {}, 1, {0xFD}},
	// 0xFE: group 4
	// 0xFF: group 5

	// TWO BYTE OPCODES

	/////// 0x0F 0x0_ ///////
	{"clts", {}, 2, {0x0F, 0x06}},
	{"wbinvd", {}, 2, {0x0F, 0x09}},
	// ...
	{"movups", {OT_REGXMM | OT_OWORD, OT_REGXMM | OT_MEMORY | OT_OWORD}, 2, {0x0F, 0x10}},
	{"movups", {OT_REGXMM | OT_MEMORY | OT_OWORD, OT_REGXMM | OT_OWORD}, 2, {0x0F, 0x11}},
	// ...
	{"mov", {OT_CONTROLREG, OT_GPREG | OT_MEMORY | OT_DWORD}, 2, {0x0F, 0x20}},
	// ...
	// many more

	// IMMEDIATE GROUP 1
	{"add", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 0},
	{"or", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 1},
	{"adc", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 2},
	{"sbb", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 3},
	{"and", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 4},
	{"sub", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 5},
	{"xor", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 6},
	{"cmp", {OT_GPREG | OT_MEMORY | OT_BYTE, OT_IMMEDIATE | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 7},

	{"add", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 0},
	{"or", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 1},
	{"adc", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 2},
	{"sbb", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 3},
	{"and", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 4},
	{"sub", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 5},
	{"xor", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 6},
	{"cmp", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 7},

	// Are there opcodes starting with 0x82?

	{"add", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 0},
	{"or", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 1},
	{"adc", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 2},
	{"sbb", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 3},
	{"and", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 4},
	{"sub", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 5},
	{"xor", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 6},
	{"cmp", {OT_GPREG | OT_MEMORY | OT_DWORD, OT_IMMEDIATE | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 7},

	// SHIFT GROUP 2
	// TODO

	// FPU OPERATIONS
	{"fadd", {(OT_FPUREG & OT_REG(0)) | OT_FPUSIZE, OT_FPUREG | OT_MEMORY | OT_DWORD}, 1, {0xD8}, SPECIAL_SPEC + 0},
	// ...

	{"fadd", {(OT_FPUREG & OT_REG(0)) | OT_FPUSIZE, OT_MEMORY | OT_QWORD}, 1, {0xDC}, SPECIAL_SPEC + 0},
	{"fadd", {OT_FPUREG, (OT_FPUREG & OT_REG(0)) | OT_FPUSIZE}, 1, {0xDC}, SPECIAL_SPEC + 0},
	// ...

	{"fsin", {}, 2, {0xD9, 0xFE}}
};


/////////////////////////
// ENCODING ALGORITHMS //
/////////////////////////

/**
 * Build ModRM byte.
 * +-----+-------+-------+
 * | 7 6 | 5 4 3 | 2 1 0 |
 * | mod | spec  | reg/m |
 * +-----+-------+-------+
 */
static ut8 make_ModRM(ut8 mod, ut8 spec, ut8 rm) {
	return ((mod & 0x03) << 6) + ((spec & 0x7) << 3) + (rm & 0x7);
}

/**
 * The SIB byte for sophisticated indirect addressing.
 * +-----+-------+-------+
 * | 7 6 | 5 4 3 | 2 1 0 |
 * | sc. | index |  base |
 * +-----+-------+-------+
 */
static ut8 make_SIB(ut8 scale, ut8 index, ut8 base) {
	return ((scale & 0x03) << 6) + ((index & 0x7) << 3) + (base & 0x7);
}

/**
 * Translate scale factor for SIB byte.
 */
static ut8 translate_scale(int scale) {
	switch (scale) {
	case 1:
		return 0;
	case 2:
		return 1;
	case 4:
		return 2;
	case 8:
		return 3;
	default:
		return 0xff;
	}
}

/**
 * Assemble instruction from table with the given operands.
 */
static int write_asm(ut8 *data, Opcode *opcode_ptr, Operand *operands) {
	int l;
	int op_ind;

	// Write opcode
	for (l=0; l<opcode_ptr->op_len; ++l)
		data[l] = opcode_ptr->opcode[l];

	// What operands do we have and how do we encode them?
	Operand *regmem_op = 0;
	Operand *reg_op = 0;

	for (op_ind = 0; op_ind < 3 && opcode_ptr->op[op_ind] != 0; ++op_ind) {
		// If operand can point to memory, it must be encoded via RM and SIB
		// That is, if it isn't just a plain address.
		// TODO: what about two register-only operands?
		if (opcode_ptr->op[op_ind] & OT_MEMORY && !(opcode_ptr->op[op_ind] & (OT_IMMEDIATE | OT_MEMADDRESS))) {
			regmem_op = &operands[op_ind];
			continue;
		}

		// Remaining register operands are encoded via spec field, if that is
		// necessary: sometimes operands are fixed to be a certain register.
		if ((opcode_ptr->op[op_ind] & (0xff << REGTYPE_SHIFT))
				&& !(~opcode_ptr->op[op_ind] & OT_REGALL))
			reg_op = &operands[op_ind];
	}

	// Are there any operands we have to encode?
	if (regmem_op && (opcode_ptr->special || reg_op)) {
		ut8 mod, spec, rm;
		ut8 scale, index, base;

		// If our opcode requires a spec field, then we might have to move an operand
		if (opcode_ptr->special && regmem_op == 0) {
			regmem_op = reg_op;
			reg_op = 0;
		}

		// Write spec
		if (opcode_ptr->special)
			spec = opcode_ptr->special & SPECIAL_MASK;
		else
			spec = reg_op->reg;

		// Analyze register/memory operand.
		if (regmem_op->type & (0xff << REGTYPE_SHIFT)) {
			mod = 3;
			rm = regmem_op->reg;
		}
		else {      // Memory operand
			// Sort registers by scale
			if (regmem_op->scale[1] > regmem_op->scale[0]) {
				int temp1 = regmem_op->scale[0];
				regmem_op->scale[0] = regmem_op->scale[1];
				regmem_op->scale[1] = temp1;

				Register temp2 = regmem_op->regs[0];
				regmem_op->regs[0] = regmem_op->regs[1];
				regmem_op->regs[1] = temp2;
			}

			// If scale[0] = 3, 5, or 9 and scale[1] = 0, redistribute
			if ((regmem_op->scale[0] == 3 || regmem_op->scale[0] == 5 ||
					regmem_op->scale[0] == 9) && regmem_op->scale[1] == 0) {
				--regmem_op->scale[0];
				regmem_op->scale[1] = 1;
				regmem_op->regs[1] = regmem_op->regs[0];
			}

			// Can we do that?
			if ((regmem_op->scale[0] != 0 && translate_scale(regmem_op->scale[0]) == 0xff)
					|| (regmem_op->scale[1] & 0xfffffffe))
				return 0;

			// Which components do we have?
			if (regmem_op->offset) {
				if (regmem_op->scale[0] == 0) {
					mod = 0;
					rm = 5;
				}
				else {
					// Address size: 8 or 32 bit?
					mod = (regmem_op->offset >= -128 && regmem_op->offset < 128) ? 1 : 2;

					if (regmem_op->scale[0] == 1 && regmem_op->scale[1] == 0 && regmem_op->regs[0] != 4) {
						rm = regmem_op->regs[0];
					}
					else {		// Otherwise, we need a SIB byte
						if (regmem_op->scale[1] == 0) {
							if (regmem_op->scale[0] == 1) {
								rm = 4;
								scale = 0;
								index = 4;
								base = regmem_op->regs[0];
							}
							else {
								// Special case
								mod = 0;
								rm = 4;
								scale = translate_scale(regmem_op->scale[0]);
								index = regmem_op->regs[0];
								base = 5;
							}
						}
						else {
							if (regmem_op->regs[0] == 4)
								return 0;
							rm = 4;
							scale = translate_scale(regmem_op->scale[0]);
							index = regmem_op->regs[0];
							base = regmem_op->regs[1];
						}
					}
				}
			}
			else {
				// No offset address
				mod = 0;

				if (regmem_op->scale[0] == 1 && regmem_op->scale[1] == 0 && regmem_op->regs[0] != 4) {
					rm = regmem_op->regs[0];
				}
				else if (regmem_op->scale[0] == 0) {  // Special case: [0x0]
					rm = 5;
				}
				else {      // Otherwise, we need a SIB byte
					if (regmem_op->scale[1] == 0) {
						if (regmem_op->scale[0] != 1)
							return 0;
						scale = 0; // ?
						rm = 4;
						index = 4;
						base = regmem_op->regs[0];
					}
					else {
						if (regmem_op->regs[0] == 4 || regmem_op->regs[1] == 5)
							return 0;
						rm = 4;
						scale = translate_scale(regmem_op->scale[0]);
						index = regmem_op->regs[0];
						base = regmem_op->regs[1];
					}
				}
			}
		}

		// Write ModRM, SIB byte and/or address, if required.
		data[l++] = make_ModRM(mod, spec, rm);
		if (mod != 3 && rm == 4)
			data[l++] = make_SIB(scale, index, base);

		if (regmem_op->type & OT_MEMORY && (mod > 0 || (mod == 0 && rm == 5))) {
			if (mod == 1) {
				data[l++] = *(ut8 *)&regmem_op->offset;
			}
			else {
				ut8 *offset_ptr = (ut8 *)&regmem_op->offset;
				data[l++] = *(offset_ptr + 0);
				data[l++] = *(offset_ptr + 1);
				data[l++] = *(offset_ptr + 2);
				data[l++] = *(offset_ptr + 3);
			}
		}
	}

	// Write immediate(s), if required.
	for (op_ind = 0; op_ind < 3; ++op_ind)
		if (opcode_ptr->op[op_ind] & (OT_IMMEDIATE | OT_MEMADDRESS)) {
			// Careful: the following is a slight HACK and wouldn't work for TBYTE
			// immediates. (If there were any...)
			int i;
			int len = opcode_ptr->op[op_ind] >> OPSIZE_SHIFT;

			// For memory address immediates: the value is somewhere else
			if (opcode_ptr->op[op_ind] & OT_MEMADDRESS) {
				operands[op_ind].immediate = operands[op_ind].offset;
				len = 4; // TODO: real address length
			}

			// For jump address immediates: subtract instruction length
			if (opcode_ptr->op[op_ind] & OT_JMPADDRESS)
				operands[op_ind].immediate -= l + len;

			for (i=0; i<len; ++i)
				data[l++] = *((ut8*)&operands[op_ind].immediate + i);
		}

	// return number of bytes written
	return l;
}

/*
 * Core assemble function.
 */
static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	ut64 offset = a->pc;
	ut8 *data = ao->buf;
	int pos = 0, nextpos;

	char mnemonic[12];
	int mnemonic_len;
	Operand operands[3];

	// Parse mnemonic
	getToken(str, &pos, &nextpos);
	mnemonic_len = (nextpos - pos < sizeof(mnemonic) - 1) ?
	                nextpos - pos : sizeof(mnemonic) - 1;
	strncpy(mnemonic, str + pos, mnemonic_len);
	mnemonic[mnemonic_len] = 0;
	pos = nextpos;

	// Parse operands
	int op_ind = 0;
	x86newTokenType ttype = getToken(str, &pos, &nextpos);
	while (op_ind < 3 && ttype != TT_EOF) {
		// Read operand
		pos += parseOperand(str + pos, &operands[op_ind++]);

		// Skip over ',' (or whatever comes here)
		ttype = getToken(str, &pos, &nextpos);
		pos = nextpos;
	}

	// Fill rest of operands
	for (; op_ind < 3; ++op_ind)
		operands[op_ind].type = 0;

	// Try to assemble: walk through table and find fitting instruction
	Opcode *opcode_ptr;
	for (opcode_ptr = opcodes; opcode_ptr - opcodes < sizeof(opcodes) / sizeof(Opcode); ++opcode_ptr) {
		// Mnemonic match?
		if (strncasecmp(mnemonic, opcode_ptr->mnemonic, strlen(mnemonic)))
			continue;

		// Operands match?
		for (op_ind = 0; op_ind < 3; ++op_ind) {
			// Check if the flags of the operand are contained in the set of
			// allowed flags for that operand.
			if ((opcode_ptr->op[op_ind] & operands[op_ind].type) != operands[op_ind].type)
				break;
		}

		if (op_ind != 3)
			continue;

		// Yeah!
		break;
	}

	// Found nothing? Then return zero.
	if (opcode_ptr - opcodes == sizeof(opcodes) / sizeof(Opcode)) {
		eprintf ("Couldn't assemble instruction (%s)\n", str);
		return 0;
	}

	// If there is a jump operand: subtract offset
	if (opcode_ptr->op[0] & OT_JMPADDRESS)
		operands[0].immediate -= offset;

	return write_asm(data, opcode_ptr, operands);
}

RAsmPlugin r_asm_plugin_x86_new = {
	.name = "x86.new",
	.desc = "x86 handmade new assembler",
	.license = "LGPL3",
	.arch = "x86",
	.bits = 32,		// maybe later: 16, 64
	.init = NULL,
	.fini = NULL,
	.disassemble = NULL,
	.modify = NULL,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_new
};
#endif
