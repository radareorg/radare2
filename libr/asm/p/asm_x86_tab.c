/* Copyright (C) 2015 - aaronpuchert */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <r_types.h>
#include <r_lib.h>
#include <r_asm.h>

/**
 * Types of operands: we describe them via a bit field. The first six bits
 * describe how the operand should be encoded:
 * - in the spec field of ModRM
 * - in the rm field of modrm, together with mod, possibly SIB and displacement
 * - as immediate after the instruction
 * - nowhere at all. Some operands are implied in the opcode.
 *
 * The following ten bits describe what we expect to read in the assembly: this
 * could be a register of a certain kind, a memory location or just a constant.
 *
 * Patterns to combine this information can be found in the OT_[A-Z]*OP macros.
 * For example, OT_REGMEMOP(GP) = OT_GPREG | OT_MEMORY | OT_REGMEM describes an
 * operand that can either be a general purpose register or a memory location,
 * and which will be encoded in the rm field of the ModRM byte. OT_MEMADDROP =
 * OT_MEMORY | OT_IMMEDIATE are written like memory operands in assembly, but
 * encoded as immediates. Jump distances shall have an extra flag OT_JMPADDRESS
 * because they are relative to the current location.
 *
 * The third byte masks the registers, since for example FPU commands always
 * have a fixed operand st(0). The fourth byte describes the size of an operand.
 *
 * We implement them as bitfields to allow operations to describe what operands
 * are accepted. For example many accept a register or memory location in the
 * same operand with the same opcode.
 *
 * +--------+--------+--------+--------+
 * |76543210|76543210|76543210|76543210|
 * |    size|spec.reg| dcxmfsg mi| enc.|
 * +--------+--------+--------+--------+
 */
#define ENCODING_SHIFT 0
#define OPTYPE_SHIFT   6
#define REGMASK_SHIFT  16
#define OPSIZE_SHIFT   24

// How to encode the operand?
#define OT_REGMEM      (1 << (ENCODING_SHIFT + 0))
#define OT_SPECIAL     (1 << (ENCODING_SHIFT + 1))
#define OT_IMMEDIATE   (1 << (ENCODING_SHIFT + 2))
#define OT_JMPADDRESS  (1 << (ENCODING_SHIFT + 3))

// Register indices - by default, we allow all registers
#define OT_REGALL   (0xff << REGMASK_SHIFT)

// Memory or register operands: how is the operand written in assembly code?
#define OT_MEMORY      (1 << (OPTYPE_SHIFT + 0))
#define OT_CONSTANT    (1 << (OPTYPE_SHIFT + 1))
#define OT_GPREG      ((1 << (OPTYPE_SHIFT + 2)) | OT_REGALL)
#define OT_SEGMENTREG ((1 << (OPTYPE_SHIFT + 3)) | OT_REGALL)
#define OT_FPUREG     ((1 << (OPTYPE_SHIFT + 4)) | OT_REGALL)
#define OT_MMXREG     ((1 << (OPTYPE_SHIFT + 5)) | OT_REGALL)
#define OT_XMMREG     ((1 << (OPTYPE_SHIFT + 6)) | OT_REGALL)
#define OT_CONTROLREG ((1 << (OPTYPE_SHIFT + 7)) | OT_REGALL)
#define OT_DEBUGREG   ((1 << (OPTYPE_SHIFT + 8)) | OT_REGALL)
// more?

#define OT_REGTYPE    ((OT_GPREG | OT_SEGMENTREG | OT_FPUREG | OT_MMXREG | OT_XMMREG | OT_CONTROLREG | OT_DEBUGREG) & ~OT_REGALL)

// Register mask
#define OT_REG(num)  ((1 << (REGMASK_SHIFT + (num))) | OT_REGTYPE)

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
static x86newTokenType getToken(const char *str, size_t *begin, size_t *end) {
	// Skip whitespace
	while (isspace((int)str[*begin]))
		++(*begin);

	if (!str[*begin]) {                // null byte
		*end = *begin;
		return TT_EOF;
	}
	else if (isalpha((int)str[*begin])) {   // word token
		*end = *begin;
		while (isalnum((int)str[*end]))
			++(*end);
		return TT_WORD;
	}
	else if (isdigit((int)str[*begin])) {   // number token
		*end = *begin;
		while (isalnum((int)str[*end]))     // accept alphanumeric characters, because hex.
			++(*end);
		return TT_NUMBER;
	}
	else {                             // special character: [, ], +, *, ...
		*end = *begin + 1;
		return TT_SPECIAL;
	}
}

/**
 * Read decimal or hexadecimal number.
 */
static ut64 readNumber(const char *str) {
	int hex = (str[0] == '0' && str[1] == 'x');
	return strtol(str + 2*hex, 0, hex ? 16 : 10);
}

/**
 * Get the register at position pos in str. Increase pos afterwards.
 */
static Register parseReg(const char *str, size_t *pos, ut32 *type) {
	int i;
	// Must be the same order as in enum register_t
	const char *regs[] = { "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", NULL };
	const char *regs8[] = { "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", NULL };
	const char *regs16[] = { "ax", "cx", "dx", "bx", "sp", "bp", "si", "di", NULL };
//	const char *regs64[] = { "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", NULL };

	// Get token (especially the length)
	size_t nextpos, length;
	const char *token;
	getToken(str, pos, &nextpos);
	token = str + *pos;
	length = nextpos - *pos;
	*pos = nextpos;

	// General purpose registers
	if (length == 3 && token[0] == 'e')
		for (i=0; regs[i]; i++)
			if (!strncasecmp (regs[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_DWORD;
				return i;
			}
	if (length == 2 && (token[1] == 'l' || token[1] == 'h'))
		for (i=0; regs8[i]; i++)
			if (!strncasecmp (regs8[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_BYTE;
				return i;
			}
	if (length == 2)
		for (i=0; regs16[i]; i++)
			if (!strncasecmp (regs16[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_WORD;
				return i;
			}
/*	if (token[0] == 'r')
		for (i=0; regs64[i]; i++)
			if (!strncasecmp (regs64[i], token, length)) {
				*type = (OT_GPREG & OT_REG(i)) | OT_QWORD;
				return i;
			} */

	// Numbered registers
	if (!strncasecmp ("st", token, length))
		*type = (OT_FPUREG & ~OT_REGALL);
	if (!strncasecmp ("mm", token, length))
		*type = (OT_MMXREG & ~OT_REGALL);
	if (!strncasecmp ("xmm", token, length))
		*type = (OT_XMMREG & ~OT_REGALL);

	// Now read number, possibly with parantheses
	if (*type & (OT_FPUREG | OT_MMXREG | OT_XMMREG) & ~OT_REGALL) {
		Register reg = X86R_UNDEFINED;

		// pass by '(',if there is one
		if (getToken(str, pos, &nextpos) == TT_SPECIAL && str[*pos] == '(')
			*pos = nextpos;

		// read number
		if (getToken(str, pos, &nextpos) != TT_NUMBER ||
				(reg = readNumber(str + *pos)) > 7)
			eprintf("Too large register index!");
		*pos = nextpos;

		// pass by ')'
		if (getToken(str, pos, &nextpos) == TT_SPECIAL && str[*pos] == ')')
			*pos = nextpos;

		*type |= (OT_REG(reg) & ~OT_REGTYPE);
		return reg;
	}

	return X86R_UNDEFINED;
}

// Parse operand
static int parseOperand(const char *str, Operand *op) {
	size_t pos, nextpos = 0;
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
				ut32 reg_type = 0;

				// We can't multiply registers
				if (reg != X86R_UNDEFINED)
					op->type = 0;	// Make the result invalid

				// Reset nextpos: parseReg wants to parse from the beginning
				nextpos = pos;
				reg = parseReg(str, &nextpos, &reg_type);

				// Addressing only via general purpose registers
				if (!(reg_type & OT_GPREG))
					op->type = 0;	// Make the result invalid
			}
			else {
				ut64 read = readNumber(str + pos);
				temp *= read;
			}
		}
	}
	else if (last_type == TT_WORD) {   // register
		nextpos = pos;
		op->reg = parseReg(str, &nextpos, &op->type);
	}
	else {                             // immediate
		// We don't know the size, so let's just set no size flag.
		op->type = OT_CONSTANT;
		op->immediate = readNumber(str + pos);
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

// Macros for encoding
#define OT_REGMEMOP(type)  (OT_##type##REG | OT_MEMORY | OT_REGMEM)
#define OT_REGONLYOP(type) (OT_##type##REG | OT_REGMEM)
#define OT_MEMONLYOP       (OT_MEMORY | OT_REGMEM)
#define OT_MEMIMMOP        (OT_MEMORY | OT_IMMEDIATE)
#define OT_REGSPECOP(type) (OT_##type##REG | OT_SPECIAL)
#define OT_IMMOP           (OT_CONSTANT | OT_IMMEDIATE)
#define OT_MEMADDROP       (OT_MEMORY | OT_IMMEDIATE)

// Some operations are encoded via opcode + spec field
#define SPECIAL_SPEC 0x00010000
#define SPECIAL_MASK 0x00000007

Opcode opcodes[] = {
	//////////////////////
	// ONE BYTE OPCODES //
	//////////////////////

	/////// 0x0_ ///////
	//{"add", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x00}},
	//{"add", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x01}},
	//{"add", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x02}},
	//{"add", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x03}},
	//{"add", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x04}},
	//{"add", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x05}},
//
	//{"push", {(OT_SEGMENTREG & OT_REG(X86R_ES))}, 1, {0x06}},
	//{"pop", {(OT_SEGMENTREG & OT_REG(X86R_ES))}, 1, {0x07}},
//
	//{"or", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x08}},
	//{"or", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x09}},
	//{"or", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0A}},
	//{"or", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x0B}},
	//{"or", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x0C}},
	//{"or", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x0D}},
//
	//{"push", {(OT_SEGMENTREG & OT_REG(X86R_CS))}, 1, {0x0E}},
	//// Two byte opcodes start with 0x0F
//
	///////// 0x1_ ///////
	//{"adc", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x10}},
	//{"adc", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x11}},
	//{"adc", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x12}},
	//{"adc", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x13}},
	//{"adc", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x14}},
	//{"adc", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x15}},
//
	//{"push", {(OT_SEGMENTREG & OT_REG(X86R_SS))}, 1, {0x16}},
	//{"pop", {(OT_SEGMENTREG & OT_REG(X86R_SS))}, 1, {0x17}},
//
	//{"sbb", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x18}},
	//{"sbb", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x19}},
	//{"sbb", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x1A}},
	//{"sbb", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x1B}},
	//{"sbb", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x1C}},
	//{"sbb", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x1D}},
//
	//{"push", {(OT_SEGMENTREG & OT_REG(X86R_DS))}, 1, {0x1E}},
	//{"pop", {(OT_SEGMENTREG & OT_REG(X86R_DS))}, 1, {0x1F}},
//
	///////// 0x2_ ///////
	//{"and", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x20}},
	//{"and", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x21}},
	//{"and", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x22}},
	//{"and", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x23}},
	//{"and", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x24}},
	//{"and", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x25}},
//
	//// 0x26: ES segment prefix
	//{"daa", {}, 1, {0x27}},
//
	//{"sub", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x28}},
	//{"sub", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x29}},
	//{"sub", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x2A}},
	//{"sub", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x2B}},
	//{"sub", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x2C}},
	//{"sub", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x2D}},
//
	//// 0x2E: CS segment prefix
	//{"das", {}, 1, {0x2F}},
//
	///////// 0x3_ ///////
	//{"xor", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x30}},
	//{"xor", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x31}},
	//{"xor", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x32}},
	//{"xor", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x33}},
	//{"xor", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x34}},
	//{"xor", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x35}},
//
	//// 0x36: SS segment prefix
	//{"aaa", {}, 1, {0x37}},
//
	//{"cmp", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x38}},
	//{"cmp", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x39}},
	//{"cmp", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x3A}},
	//{"cmp", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x3B}},
	//{"cmp", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x3C}},
	//{"cmp", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x3D}},
//
	//// 0x3E: DS segment prefix
	//{"aas", {}, 1, {0x3F}},
//
	///////// 0x4_ ///////
	//{"inc", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x40}},
	//{"inc", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x41}},
	//{"inc", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x42}},
	//{"inc", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x43}},
	//{"inc", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x44}},
	//{"inc", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x45}},
	//{"inc", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x46}},
	//{"inc", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x47}},
	//{"dec", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x48}},
	//{"dec", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x49}},
	//{"dec", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x4A}},
	//{"dec", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x4B}},
	//{"dec", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x4C}},
	//{"dec", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x4D}},
	//{"dec", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x4E}},
	//{"dec", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x4F}},

	///////// 0x5_ ///////
	//{"push", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x50}},
	//{"push", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x51}},
	//{"push", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x52}},
	//{"push", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x53}},
	//{"push", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x54}},
	//{"push", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x55}},
	//{"push", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x56}},
	//{"push", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x57}},
	//{"pop", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x58}},
	//{"pop", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x59}},
	//{"pop", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x5A}},
	//{"pop", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x5B}},
	//{"pop", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x5C}},
	//{"pop", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x5D}},
	//{"pop", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x5E}},
	//{"pop", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x5F}},
//
	///////// 0x6_ ///////
	//{"pusha", {}, 1, {0x60}},	{"pushad", {}, 1, {0x60}},
	//{"popa", {}, 1, {0x61}},	{"popad", {}, 1, {0x61}},
	{"bound", {OT_REGSPECOP(GP) | OT_DWORD, OT_MEMONLYOP | OT_QWORD}, 1, {0x62}},
	{"arpl", {OT_REGMEMOP(GP) | OT_WORD, OT_REGSPECOP(GP) | OT_WORD}, 1, {0x63}},
	// 0x64: FS segment prefix
	// 0x65: GS segment prefix
	// 0x66: operand size prefix
	// 0x67: address size prefix
	//{"push", {OT_IMMOP | OT_DWORD}, 1, {0x68}},
	{"imul", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x69}},
	//{"push", {OT_IMMOP | OT_BYTE}, 1, {0x6A}},
	{"imul", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x6B}},
	//{"insb", {}, 1, {0x6C}},
	//{"ins", {}, 1, {0x6D}}, {"insd", {}, 1, {0x6D}},
	//{"insw", {}, 2, {0x66, 0x6D}},
	//{"outsb", {}, 1, {0x6E}},
	//{"outs", {}, 1, {0x6F}}, {"outsd", {}, 1, {0x6F}},
	//{"outsw", {}, 2, {0x66, 0x6F}},

	/////// 0x7_ ///////
	//{"jo", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x70}},
	//{"jno", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x71}},
	//{"jb", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x72}},
	//{"jnae", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x72}},
	//{"jc", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x72}},
	//{"jnb", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x73}},
	//{"jae", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x73}},
	//{"jnc", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x73}},
	//{"jz", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x74}},
	//{"je", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x74}},
	//{"jnz", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x75}},
	//{"jne", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x75}},
	//{"jbe", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x76}},
	//{"jna", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x76}},
	//{"jnbe", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x77}},
	//{"ja", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x77}},
	//{"js", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x78}},
	//{"jns", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x79}},
	//{"jp", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7A}},
	//{"jpe", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7A}},
	//{"jnp", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7B}},
	//{"jpo", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7B}},
	//{"jl", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7C}},
	//{"jnge", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7C}},
	//{"jnl", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7D}},
	//{"jge", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7D}},
	//{"jle", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7E}},
	//{"jng", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7E}},
	//{"jnle", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7F}},
	//{"jg", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0x7F}},

	/////// 0x8_ ///////
	// 0x80 -- 0x83: immediate group 1
	// 0x84, 0x85: TODO: test
	// 0x86, 0x87: TODO: xchg
	//{"mov", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 1, {0x88}},
	////{"mov", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 1, {0x89}},
	//{"mov", {OT_REGSPECOP(GP) | OT_BYTE, OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x8A}},
	//{"mov", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 1, {0x8B}},
	//{"mov", {OT_MEMONLYOP | OT_WORD, OT_REGSPECOP(SEGMENT) | OT_WORD}, 1, {0x8C}}, // ?
	//{"lea", {OT_REGSPECOP(GP) | OT_DWORD, OT_MEMONLYOP | OT_DWORD}, 1, {0x8D}},	// allow all sizes?
	//{"mov", {OT_REGSPECOP(SEGMENT) | OT_WORD, OT_MEMONLYOP | OT_WORD}, 1, {0x8E}}, // ?
	//{"pop", {}, 1, {0x8F}},  // ?

	/////// 0x9_ ///////
	//{"nop", {}, 1, {0x90}},
	//{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0x90}},
	//{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 1, {0x91}},
	//{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 1, {0x92}},
	//{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 1, {0x93}},
	//{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 1, {0x94}},
	//{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 1, {0x95}},
	//{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 1, {0x96}},
	//{"xchg", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 1, {0x97}},
	//{"cbw", {}, 1, {0x98}},
	//{"cwde", {}, 2, {0x66, 0x98}},  // ?
	//{"cwd", {}, 1, {0x99}},
	//{"cdq", {}, 2, {0x66, 0x99}},  // ?
	// 0x9A: TODO far call
	//{"wait", {}, 1, {0x9B}},
	//{"fwait", {}, 1, {0x9B}},
	//{"pushfd", {}, 1, {0x9C}},
	//{"popfd", {}, 1, {0x9D}},
	//{"sahf", {}, 1, {0x9E}},
	//{"lahf", {}, 1, {0x9F}},

	/////// 0xA_ ///////
	//{"mov", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_MEMIMMOP | OT_BYTE}, 1, {0xA0}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_MEMIMMOP | OT_DWORD}, 1, {0xA1}},
	// 0xA2 -- 0xA3
	//{"movsb", {}, 1, {0xA4}},
	//{"movsd", {}, 1, {0xA5}},
	//{"movsw", {}, 2, {0x66, 0xA5}},
	//{"cmpsb", {}, 1, {0xA6}},
	//{"cmpsd", {}, 1, {0xA7}},
	//{"cmpsw", {}, 2, {0x66, 0xA7}},
	// 0xA8 -- 0xA9: as above
	//{"stosb", {}, 1, {0xAA}},
	//{"stosd", {}, 1, {0xAB}},
	//{"stosw", {}, 2, {0x66, 0xAB}},
	//{"lodsb", {}, 1, {0xAC}},
	//{"lodsd", {}, 1, {0xAD}},
	//{"lodsw", {}, 2, {0x66, 0xAD}},
	//{"scasb", {}, 1, {0xAE}},
	//{"scasd", {}, 1, {0xAF}},
	//{"scasw", {}, 2, {0x66, 0xAF}},

	/////// 0xB_ ///////
	//{"mov", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xB0}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_CL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xB1}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_DL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xB2}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_BL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xB3}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_AH)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xB4}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_CH)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xB5}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_DH)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xB6}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_BH)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xB7}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0xB8}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0xB9}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0xBA}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0xBB}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0xBC}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0xBD}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0xBE}},
	//{"mov", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0xBF}},

	/////// 0xC_ ///////
	// 0xC0 -- 0xC1: shift group 2
	//{"ret", {OT_IMMOP | OT_WORD}, 1, {0xC2}},
	//{"ret", {}, 1, {0xC3}},
	{"les", {OT_REGSPECOP(GP) | OT_DWORD, OT_MEMONLYOP | OT_BYTE}, 1, {0xC4}},
	{"lds", {OT_REGSPECOP(GP) | OT_DWORD, OT_MEMONLYOP | OT_BYTE}, 1, {0xC5}},
	// 0xC6 -- 0xC7 mov group
	{"enter", {OT_IMMOP | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0xC8}},
	//{"leave", {}, 1, {0xC9}},
	//{"retf", {OT_IMMOP | OT_WORD}, 1, {0xCA}},
	//{"retf", {}, 1, {0xCB}},
	//{"int3", {}, 1, {0xCC}},
	//{"int", {OT_IMMOP | OT_BYTE}, 1, {0xCD}},
	//{"into", {}, 1, {0xCE}},
	//{"iretd", {OT_IMMOP | OT_BYTE}, 1, {0xCF}},

	/////// 0xD_ ///////
	// 0xD0 -- 0xD3: shift group 2
	{"aam", {OT_IMMOP | OT_BYTE}, 1, {0xD4}},  // ?
	{"aad", {OT_IMMOP | OT_BYTE}, 1, {0xD5}},  // ?
	// 0xD6: reserved
	//{"xlatb", {}, 1, {0xD7}},
	// 0xD8 -- 0xDF: FPU

	/////// 0xE_ ///////
	{"loopne", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0xE0}},
	{"loope", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0xE1}},
	{"loop", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0xE2}},
	{"jcxz", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0xE3}},
	{"jecxz", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0xE3}},
	//{"in", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0xE4}},
	//{"in", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0xE5}},
	//{"out", {OT_IMMOP | OT_BYTE, (OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE}, 1, {0xE6}},
	//{"out", {OT_IMMOP | OT_BYTE, (OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0xE7}},
	//{"call", {OT_IMMOP | OT_DWORD}, 1, {0xE8}},
	//{"jmp", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0xE9}},
	//{"jmp", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0xEA}},  // ?
	//{"jmp", {OT_IMMOP | OT_JMPADDRESS | OT_BYTE}, 1, {0xEB}},
	//{"in", {(OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE, (OT_GPREG & OT_REG(X86R_DX)) | OT_WORD}, 1, {0xEC}},
	//{"in", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD, (OT_GPREG & OT_REG(X86R_DX)) | OT_WORD}, 1, {0xED}},
	//{"out", {(OT_GPREG & OT_REG(X86R_DX)) | OT_WORD, (OT_GPREG & OT_REG(X86R_AL)) | OT_BYTE}, 1, {0xEE}},
	//{"out", {(OT_GPREG & OT_REG(X86R_DX)) | OT_WORD, (OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 1, {0xEF}},

	/////// 0xF_ ///////
	// 0xF0: lock prefix
	// 0xF1: reserved
	// 0xF2: repne prefix
	// 0xF3: rep(e) prefix
	//{"hlt", {}, 1, {0xF4}},
	//{"cmc", {}, 1, {0xF5}},
	// 0xF6 -- 0xF7: unary group 3
	//{"clc", {}, 1, {0xF8}},
	//{"stc", {}, 1, {0xF9}},
	//{"cli", {}, 1, {0xFA}},
	//{"sti", {}, 1, {0xFB}},
	//{"cld", {}, 1, {0xFC}},
	//{"std", {}, 1, {0xFD}},
	// 0xFE: group 4
	// 0xFF: group 5

	//////////////////////
	// TWO BYTE OPCODES //
	//////////////////////

	/////// 0x0F 0x0_ ///////
	// 0x0F 0x00: group 6
	// 0x0F 0x01: group 7
	{"lar", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x02}},
	{"lsl", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x03}},
	// 0x0F 0x04-0x05: reserved
	//{"clts", {}, 2, {0x0F, 0x06}},
	// 0x0F 0x07: reserved
	//{"invd", {}, 2, {0x0F, 0x08}},
	//{"wbinvd", {}, 2, {0x0F, 0x09}},
	// 0x0F 0x0A: reserved
	//{"ud2", {}, 2, {0x0F, 0x0B}},
	// 0x0F 0x0C: reserved
	//{"prefetch", {}, 2, {0x0F, 0x0D}},
	//{"femms", {}, 2, {0x0F, 0x0E}},
	// 0x0F 0x0F: 3DNow! prefix

	/////// 0x0F 0x1_ ///////
	{"movups", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x10}},
	{"movups", {OT_REGMEMOP(XMM) | OT_OWORD, OT_REGSPECOP(XMM) | OT_OWORD}, 2, {0x0F, 0x11}},
	{"movlps", {OT_REGSPECOP(XMM) | OT_QWORD, OT_REGMEMOP(XMM) | OT_QWORD}, 2, {0x0F, 0x12}},
	{"movlps", {OT_REGMEMOP(XMM) | OT_QWORD, OT_REGSPECOP(XMM) | OT_QWORD}, 2, {0x0F, 0x13}},
	{"unpcklps", {OT_REGSPECOP(XMM) | OT_QWORD, OT_REGMEMOP(XMM) | OT_QWORD}, 2, {0x0F, 0x14}},
	{"unpckhps", {OT_REGSPECOP(XMM) | OT_QWORD, OT_REGMEMOP(XMM) | OT_QWORD}, 2, {0x0F, 0x15}},
	{"movhps", {OT_REGSPECOP(XMM) | OT_QWORD, OT_REGMEMOP(XMM) | OT_QWORD}, 2, {0x0F, 0x16}},
	{"movhps", {OT_REGMEMOP(XMM) | OT_QWORD, OT_REGSPECOP(XMM) | OT_QWORD}, 2, {0x0F, 0x17}},
	// 0x0F 0x18: group 16
	// 0x0F 0x19-0x1F: reserved

	/////// 0x0F 0x2_ ///////
	//{"mov", {OT_CONTROLREG, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x20}},
	//{"mov", {OT_REGMEMOP(GP) | OT_DWORD, OT_DEBUGREG}, 2, {0x0F, 0x21}},
	//{"mov", {OT_REGMEMOP(GP) | OT_DWORD, OT_CONTROLREG}, 2, {0x0F, 0x22}},
	//{"mov", {OT_DEBUGREG, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x23}},
	// 0x0F 0x24-0x27: reserved
	{"movaps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x28}},
	{"movaps", {OT_REGMEMOP(XMM) | OT_OWORD, OT_REGSPECOP(XMM) | OT_OWORD}, 2, {0x0F, 0x29}},
	{"cvtpi2ps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x2A}},
	{"movntps", {OT_MEMONLYOP | OT_OWORD, OT_REGSPECOP(XMM) | OT_OWORD}, 2, {0x0F, 0x2B}},
	{"cvttps2pi", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x2C}},
	{"cvtps2pi", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x2D}},
	{"ucomiss", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x2E}},
	{"comiss", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x2F}},

	/////// 0x0F 0x3_ ///////
	//{"wrmsr", {}, 2, {0x0F, 0x30}},
	//{"rdtsc", {}, 2, {0x0F, 0x31}},
	//{"rdmsr", {}, 2, {0x0F, 0x32}},
	//{"rdpmc", {}, 2, {0x0F, 0x33}},
	//{"sysenter", {}, 2, {0x0F, 0x34}},
	//{"sysexit", {}, 2, {0x0F, 0x35}},
	// 0x0F 0x36-0x3F: reserved

	/////// 0x0F 0x4_ ///////
	{"cmovo", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x40}},
	{"cmovno", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x41}},
	{"cmovb", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x42}},
	{"cmovnae", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x42}},
	{"cmovc", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x42}},
	{"cmovnb", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x43}},
	{"cmovae", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x43}},
	{"cmovnc", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x43}},
	{"cmovz", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x44}},
	{"cmove", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x44}},
	{"cmovnz", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x45}},
	{"cmovne", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x45}},
	{"cmovbe", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x46}},
	{"cmovna", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x46}},
	{"cmovnbe", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x47}},
	{"cmova", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x47}},
	{"cmovs", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x48}},
	{"cmovns", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x49}},
	{"cmovp", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4A}},
	{"cmovpe", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4A}},
	{"cmovnp", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4B}},
	{"cmovpo", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4B}},
	{"cmovl", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4C}},
	{"cmovnge", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4C}},
	{"cmovnl", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4D}},
	{"cmovge", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4D}},
	{"cmovle", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4E}},
	{"cmovng", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4E}},
	{"cmovnle", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4F}},
	{"cmovg", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0x4F}},

	/////// 0x0F 0x5_ ///////
	{"movmskps", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGONLYOP(XMM) | OT_OWORD}, 2, {0x0F, 0x50}},
	{"sqrtps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x51}},
	{"rsqrtps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x52}},
	{"rcpps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x53}},
	{"andps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x54}},
	{"andnps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x55}},
	{"orps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x56}},
	{"xorps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x57}},
	{"addps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x58}},
	{"mulps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x59}},
	{"cvtps2pd", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x5A}},
	{"cvtdq2ps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x5B}},
	{"subps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x5C}},
	{"minps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x5D}},
	{"divps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x5E}},
	{"maxps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD}, 2, {0x0F, 0x5F}},

	/////// 0x0F 0x6_ ///////
	{"punpcklbw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x60}},
	{"punpcklwd", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x61}},
	{"punpckldq", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x62}},
	{"packsswb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x63}},
	{"pcmpgtb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x64}},
	{"pcmpgtw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x65}},
	{"pcmpgtd", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x66}},
	{"packuswb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x67}},
	{"punpckhbw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x68}},
	{"punpckhwd", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x69}},
	{"punpckhdq", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x6A}},
	{"packssdw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x6B}},
	// 0x0F 0x6C-0x6D: reserved
	{"movd", {OT_REGSPECOP(MMX) | OT_DWORD, OT_REGONLYOP(GP) | OT_DWORD}, 2, {0x0F, 0x6E}},
	{"movq", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x6F}},

	/////// 0x0F 0x7_ ///////
	{"pshufw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD, OT_IMMOP | OT_BYTE}, 2, {0x0F, 0x70}},
	// 0x0F 0x71: group 12
	// 0x0F 0x72: group 13
	// 0x0F 0x73: group 14
	{"pcmpeqb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x74}},
	{"pcmpeqw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x75}},
	{"pcmpeqd", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0x76}},
	{"emms", {}, 2, {0x0F, 0x77}},
	// 0x0F 0x77-0x7D: MMX UD TODO: what is that?
	{"movd", {OT_REGONLYOP(GP) | OT_DWORD, OT_REGSPECOP(MMX) | OT_DWORD}, 2, {0x0F, 0x7E}},
	{"movq", {OT_REGMEMOP(MMX) | OT_QWORD, OT_REGSPECOP(MMX) | OT_QWORD}, 2, {0x0F, 0x7F}},

	/////// 0x0F 0x8_ ///////
	//{"jo", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x80}},
	//{"jno", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x81}},
	//{"jb", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x82}},
	//{"jnae", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x82}},
	//{"jc", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x82}},
	//{"jnb", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x83}},
	//{"jae", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x83}},
	//{"jnc", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x83}},
	//{"jz", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x84}},
	//{"je", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x84}},
	//{"jnz", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x85}},
	//{"jne", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x85}},
	//{"jbe", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x86}},
	//{"jna", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x86}},
	//{"jnbe", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x87}},
	//{"ja", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x87}},
	//{"js", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x88}},
	//{"jns", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x89}},
	//{"jp", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8A}},
	//{"jpe", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8A}},
	//{"jnp", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8B}},
	//{"jpo", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8B}},
	//{"jl", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8C}},
	//{"jnge", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8C}},
	//{"jnl", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8D}},
	//{"jge", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8D}},
	//{"jle", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8E}},
	//{"jng", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8E}},
	//{"jnle", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8F}},
	//{"jg", {OT_IMMOP | OT_JMPADDRESS | OT_DWORD}, 1, {0x0F, 0x8F}},

	/////// 0x0F 0x9_ ///////
	// TODO: what is the value of spec for these instructions?
	{"seto", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x90}},
	{"setno", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x91}},
	{"setb", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x92}},
	{"setnae", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x92}},
	{"setc", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x92}},
	{"setnb", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x93}},
	{"setae", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x93}},
	{"setnc", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x93}},
	{"setz", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x94}},
	{"sete", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x94}},
	{"setnz", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x95}},
	{"setne", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x95}},
	{"setbe", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x96}},
	{"setna", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x96}},
	{"setnbe", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x97}},
	{"seta", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x97}},
	{"sets", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x98}},
	{"setns", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x99}},
	{"setp", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9A}},
	{"setpe", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9A}},
	{"setnp", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9B}},
	{"setpo", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9B}},
	{"setl", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9C}},
	{"setnge", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9C}},
	{"setnl", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9D}},
	{"setge", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9D}},
	{"setle", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9E}},
	{"setng", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9E}},
	{"setnle", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9F}},
	{"setg", {OT_REGMEMOP(GP) | OT_BYTE}, 1, {0x0F, 0x9F}},

	/////// 0x0F 0xA_ ///////
	//{"push", {(OT_SEGMENTREG & OT_REG(X86R_FS))}, 2, {0x0F, 0xA0}},
	//{"pop", {(OT_SEGMENTREG & OT_REG(X86R_FS))}, 2, {0x0F, 0xA1}},
	//{"cpuid", {}, 2, {0x0F, 0xA2}},
	//{"bt", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 2, {0x0F, 0xA3}},
	{"shld", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 2, {0x0F, 0xA4}},
	{"shld", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD, (OT_GPREG & OT_REG(X86R_CL)) | OT_BYTE}, 2, {0x0F, 0xA5}},
	// 0x0F 0xA6-0xA7: reserved
	//{"push", {(OT_SEGMENTREG & OT_REG(X86R_GS))}, 2, {0x0F, 0xA8}},
	//{"pop", {(OT_SEGMENTREG & OT_REG(X86R_GS))}, 2, {0x0F, 0xA9}},
	//{"rsm", {}, 2, {0x0F, 0xAA}},
	{"bts", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 2, {0x0F, 0xAB}},
	{"shrd", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 2, {0x0F, 0xAC}},
	{"shrd", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD, (OT_GPREG & OT_REG(X86R_CL)) | OT_BYTE}, 2, {0x0F, 0xAD}},
	// 0x0F 0xAE: group 15
	{"imul", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0xAF}}, // ?

	/////// 0x0F 0xB_ ///////
	{"cmpxchg", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 2, {0x0F, 0xB0}},
	{"cmpxchg", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 2, {0x0F, 0xB1}},
	{"lss", {OT_REGSPECOP(GP) | OT_DWORD, OT_MEMONLYOP}, 2, {0x0F, 0xB2}},
	{"btr", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 2, {0x0F, 0xB3}},
	{"lfs", {OT_REGSPECOP(GP) | OT_DWORD, OT_MEMONLYOP}, 2, {0x0F, 0xB4}},
	{"lgs", {OT_REGSPECOP(GP) | OT_DWORD, OT_MEMONLYOP}, 2, {0x0F, 0xB5}},
	{"movzx", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_BYTE}, 2, {0x0F, 0xB6}},
	{"movzx", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_WORD}, 2, {0x0F, 0xB7}},
	// 0x0F 0xB8: reserved
	// 0x0F 0xB9: group 10
	// 0x0F 0xBA: group 8
	{"btc", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 2, {0x0F, 0xBB}},
	{"bsf", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0xBC}},
	{"bsr", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_DWORD}, 2, {0x0F, 0xBD}},
	{"movsx", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_BYTE}, 2, {0x0F, 0xBE}},
	{"movsx", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGMEMOP(GP) | OT_WORD}, 2, {0x0F, 0xBF}},

	/////// 0x0F 0xC_ ///////
	{"xadd", {OT_REGMEMOP(GP) | OT_BYTE, OT_REGSPECOP(GP) | OT_BYTE}, 2, {0x0F, 0xC0}},
	{"xadd", {OT_REGMEMOP(GP) | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 2, {0x0F, 0xC1}},
	{"cmpps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD, OT_IMMOP | OT_BYTE}, 2, {0x0F, 0xC2}},
	{"movnti", {OT_MEMONLYOP | OT_DWORD, OT_REGSPECOP(GP) | OT_DWORD}, 2, {0x0F, 0xC3}},
	{"pinsrw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGONLYOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 2, {0x0F, 0xC4}},
	{"pextrw", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGONLYOP(MMX) | OT_QWORD, OT_IMMOP | OT_BYTE}, 2, {0x0F, 0xC5}},
	{"shufps", {OT_REGSPECOP(XMM) | OT_OWORD, OT_REGMEMOP(XMM) | OT_OWORD, OT_IMMOP | OT_BYTE}, 2, {0x0F, 0xC6}},
	// 0x0F 0xB7: group 9
	//{"bswap", {(OT_GPREG & OT_REG(X86R_EAX)) | OT_DWORD}, 2, {0x0F, 0xC8}},
	//{"bswap", {(OT_GPREG & OT_REG(X86R_ECX)) | OT_DWORD}, 2, {0x0F, 0xC9}},
	//{"bswap", {(OT_GPREG & OT_REG(X86R_EDX)) | OT_DWORD}, 2, {0x0F, 0xCA}},
	//{"bswap", {(OT_GPREG & OT_REG(X86R_EBX)) | OT_DWORD}, 2, {0x0F, 0xCB}},
	//{"bswap", {(OT_GPREG & OT_REG(X86R_ESP)) | OT_DWORD}, 2, {0x0F, 0xCC}},
	//{"bswap", {(OT_GPREG & OT_REG(X86R_EBP)) | OT_DWORD}, 2, {0x0F, 0xCD}},
	//{"bswap", {(OT_GPREG & OT_REG(X86R_ESI)) | OT_DWORD}, 2, {0x0F, 0xCE}},
	//{"bswap", {(OT_GPREG & OT_REG(X86R_EDI)) | OT_DWORD}, 2, {0x0F, 0xCF}},

	/////// 0x0F 0xD_ ///////
	// 0x0F 0xD0: reserved
	{"psrlw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xD1}},
	{"psrld", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xD2}},
	{"psrlq", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xD3}},
	// 0x0F 0xD4: reserved
	{"pmulw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xD5}},
	// 0x0F 0xD6: reserved
	{"pmovmskb", {OT_REGSPECOP(GP) | OT_DWORD, OT_REGONLYOP(MMX) | OT_QWORD}, 2, {0x0F, 0xD7}},
	{"psubusb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xD8}},
	{"psubusw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xD9}},
	{"pminub", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xDA}},
	{"pand", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xDB}},
	{"paddusb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xDC}},
	{"paddusw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xDD}},
	{"pmaxub", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xDE}},
	{"pandn", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xDF}},

	/////// 0x0F 0xE_ ///////
	{"pavgb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE0}},
	{"psraw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE1}},
	{"psrad", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE2}},
	{"pavgw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE3}},
	{"pmulhuw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE4}},
	{"pmulhw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE5}},
	// 0x0F 0xE6: reserved
	{"movntq", {OT_MEMONLYOP | OT_QWORD, OT_REGSPECOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE7}},
	{"psubsb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE8}},
	{"psubsw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xE9}},
	{"pminsw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xEA}},
	{"por", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xEB}},
	{"paddsb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xEC}},
	{"paddsw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xED}},
	{"pmaxsw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xEE}},
	{"pxor", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xEF}},

	/////// 0x0F 0xF_ ///////
	// 0x0F 0xF0: reserved
	{"psllw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xF1}},
	{"pslld", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xF2}},
	{"pshllq", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xF3}},
	// 0x0F 0xF4: reserved
	{"pmaddwd", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xF5}},
	{"psadbw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xF6}},
	{"maskmovq", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGONLYOP(MMX) | OT_QWORD}, 2, {0x0F, 0xF7}},
	{"psubb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xF8}},
	{"psubw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xF9}},
	{"psubd", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xFA}},
	// 0x0F 0xFB: reserved
	{"paddb", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xFC}},
	{"paddw", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xFD}},
	{"paddd", {OT_REGSPECOP(MMX) | OT_QWORD, OT_REGMEMOP(MMX) | OT_QWORD}, 2, {0x0F, 0xFE}},
	// 0x0F 0xFF: reserved

	////////////////////////
	// THREE BYTE OPCODES //
	////////////////////////

	// TODO

	///////////////////////////////////////////
	// OPERATIONS WITH ADDITIONAL SPEC FIELD //
	///////////////////////////////////////////

	// IMMEDIATE GROUP 1
	//{"add", {OT_REGMEMOP(GP) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 0},
	//{"or", {OT_REGMEMOP(GP) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 1},
	//{"adc", {OT_REGMEMOP(GP) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 2},
	//{"sbb", {OT_REGMEMOP(GP) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 3},
	//{"and", {OT_REGMEMOP(GP) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 4},
	//{"sub", {OT_REGMEMOP(GP) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 5},
	//{"xor", {OT_REGMEMOP(GP) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 6},
	//{"cmp", {OT_REGMEMOP(GP) | OT_BYTE, OT_IMMOP | OT_BYTE}, 1, {0x80}, SPECIAL_SPEC + 7},
//
	//{"add", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 0},
	//{"or", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 1},
	//{"adc", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 2},
	//{"sbb", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 3},
	//{"and", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 4},
	//{"sub", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 5},
	//{"xor", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 6},
	//{"cmp", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_DWORD}, 1, {0x81}, SPECIAL_SPEC + 7},

	// Are there opcodes starting with 0x82?

	//{"add", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 0},
	//{"or", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 1},
	//{"adc", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 2},
	//{"sbb", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 3},
	//{"and", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 4},
	//{"sub", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 5},
	//{"xor", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 6},
	//{"cmp", {OT_REGMEMOP(GP) | OT_DWORD, OT_IMMOP | OT_BYTE}, 1, {0x83}, SPECIAL_SPEC + 7},

	// SHIFT GROUP 2
	// TODO

	////////////////////
	// FPU OPERATIONS //
	////////////////////
	{"fadd", {(OT_FPUREG & OT_REG(0)) | OT_FPUSIZE, OT_REGMEMOP(FPU) | OT_DWORD}, 1, {0xD8}, SPECIAL_SPEC + 0},
	// ...

	{"fadd", {(OT_FPUREG & OT_REG(0)) | OT_FPUSIZE, OT_MEMONLYOP | OT_QWORD}, 1, {0xDC}, SPECIAL_SPEC + 0},
	{"fadd", {OT_REGONLYOP(FPU), (OT_FPUREG & OT_REG(0)) | OT_FPUSIZE}, 1, {0xDC}, SPECIAL_SPEC + 0},
	// ...

	//{"fsin", {}, 2, {0xD9, 0xFE}}
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
	size_t l;
	int op_ind;

	// Write opcode
	for (l=0; l<opcode_ptr->op_len; ++l)
		data[l] = opcode_ptr->opcode[l];

	// Find register/memory- and spec-encoded operands
	Operand *regmem_op = 0;
	Operand *spec_op = 0;

	for (op_ind = 0; op_ind < 3 && opcode_ptr->op[op_ind] != 0; ++op_ind) {
		if (opcode_ptr->op[op_ind] & OT_REGMEM)
			regmem_op = &operands[op_ind];

		if (opcode_ptr->op[op_ind] & OT_SPECIAL)
			spec_op = &operands[op_ind];
	}

	// Are there any operands we have to encode?
	if (regmem_op && (opcode_ptr->special || spec_op)) {
		ut8 mod = 0, spec = 0, rm = 0;
		ut8 scale = 0, index = 0, base = 0;

		// Write spec
		if (opcode_ptr->special)
			spec = opcode_ptr->special & SPECIAL_MASK;
		else
			spec = spec_op->reg;

		// Analyze register/memory operand.
		if (regmem_op->type & OT_REGTYPE) {
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
			if (regmem_op->offset || regmem_op->regs[0] == X86R_EBP) {
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

		if (regmem_op->type & OT_MEMORY &&
				(mod > 0 || (mod == 0 && rm == 5) || (mod == 0 && rm == 4 && base == 5))) {
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
		if (opcode_ptr->op[op_ind] & OT_IMMEDIATE) {
			// Careful: the following is a slight HACK and wouldn't work for TBYTE
			// immediates. (If there were any...)
			int i;
			int len = opcode_ptr->op[op_ind] >> OPSIZE_SHIFT;

			// For memory address immediates: the value is somewhere else
			if (opcode_ptr->op[op_ind] & OT_MEMORY) {
				operands[op_ind].immediate = operands[op_ind].offset;
				// TODO: make noise if indirect addressing components are present.
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
	size_t pos = 0, nextpos;
	x86newTokenType ttype;
	char mnemonic[12];
	int op_ind, mnemonic_len;
	Opcode *opcode_ptr;
	Operand operands[3];

	// Parse mnemonic
	(void)getToken(str, &pos, &nextpos);
	mnemonic_len = (nextpos - pos < sizeof(mnemonic) - 1) ?
	                nextpos - pos : sizeof(mnemonic) - 1;
	strncpy(mnemonic, str + pos, mnemonic_len);
	mnemonic[mnemonic_len] = 0;
	pos = nextpos;

	// Parse operands
	op_ind = 0;
	ttype = getToken(str, &pos, &nextpos);
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
	for (opcode_ptr = opcodes; opcode_ptr - opcodes < sizeof(opcodes) / sizeof(Opcode); ++opcode_ptr) {
		// Mnemonic match?
		if (strncasecmp(mnemonic, opcode_ptr->mnemonic, strlen(mnemonic)))
			continue;

		// Operands match?
		for (op_ind = 0; op_ind < 3; ++op_ind) {
			// Check if the flags of the operand are contained in the set of
			// allowed flags for that operand.
			if ((opcode_ptr->op[op_ind] & operands[op_ind].type) != operands[op_ind].type
					|| (opcode_ptr->op[op_ind] && !operands[op_ind].type))
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

RAsmPlugin r_asm_plugin_x86_tab = {
	.name = "x86.tab",
	.desc = "x86 table lookup assembler",
	.license = "LGPL3",
	.arch = "x86",
	.bits = 32,		// maybe later: 16, 64
	.endian = R_SYS_ENDIAN_LITTLE,
	.assemble = &assemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_x86_tab,
	.version = R2_VERSION
};
#endif
