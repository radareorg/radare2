/* radare - LGPL - Copyright 2010-2018 - pancake, dark_k3y */
/* AVR assembler realization by Alexander Bolshev aka @dark_k3y, LGPL -- 2015,
   heavily based (and using!) on disassemble module */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_asm.h>

#include "../arch/avr/avr_disasm.h"
#include "../arch/avr/avr_instructionset.h"
#include "../arch/avr/disasm.h"

static int disassemble(RAsm *a, RAsmOp *op, const ut8 *buf, int len) {
	char buf_asm[32] = {0};
	op->size = avr_decode (buf_asm, a->pc, buf, len);
	if (*buf_asm == '.') {
		*buf_asm = 0;
	}
	r_strbuf_set (&op->buf_asm, buf_asm);
	return op->size;
}

extern instructionInfo instructionSet[AVR_TOTAL_INSTRUCTIONS];

#define MAX_TOKEN_SIZE 32
#define TOKEN_DELIM " ,\t"

/* the next few functions and structures uses for detecting
   AVR special regs, like X+, -Y, Z+3 in st(d), ld(d) and
   (e)lpm instructions */
struct _specialregs {
	char reg[4];
	int operandType;
};
typedef struct _specialregs specialregs;

#define REGS_TABLE 9

// radare tolower instruction in rasm, so we use 'x' instead of 'X' etc.
specialregs RegsTable[REGS_TABLE] = {
	{"-x", OPERAND_XP}, {"x", OPERAND_X}, {"x+", OPERAND_XP},
	{"-y", OPERAND_YP}, {"y", OPERAND_Y}, {"y+", OPERAND_YP},
	{"-z", OPERAND_ZP}, {"z", OPERAND_Z}, {"z+", OPERAND_ZP},
};

static int parse_specialreg(const char *reg) {
	const int len = strlen (reg);
	int i, found = -1;

	if (len > 0) {
		for (i = 0; i < REGS_TABLE; i++) {
			if (!strncmp (RegsTable[i].reg, reg, 4)) {
				found = RegsTable[i].operandType;
				break;
			}
		}
		/* radare tolower instruction in rasm, so we use 'y' instead of 'Y'
		and so on for other registers */
		if (found == -1 && reg[1] == '+') {
			if (reg[0] == 'y' && len > 2) {
				found = OPERAND_YPQ;
			} else if (reg[0] == 'z' && len > 2) {
				found = OPERAND_ZPQ;
			}
		}
		if (found == -1 && reg[2] == '+') {
			if (reg[0] == 'y' && len > 2) {
				found = OPERAND_YPQ;
			} else if (reg[0] == 'z' && len > 2) {
				found = OPERAND_ZPQ;
			}
		}
	}
	return found;
}

/* gets the number from string
   duplicate from asm_x86_nz.c -- may be create a generic function? */
static int getnum(RAsm *a, const char *s) {
	if (!s) {
		return 0;
	}
	if (*s == '$') {
		s++;
	}
	return r_num_math (a->num, s);
}

/* this function searches from instruction in instructionSet table
   (see avr_disasm.h for more info)
   returns index of the instruction in the table */
static int search_instruction(RAsm *a, char instr[3][MAX_TOKEN_SIZE], int args) {
	int i, op1 = 0, op2 = 0;

	for (i = 0; i < AVR_TOTAL_INSTRUCTIONS - 1; i++) {
		// check instruction mnemonic
		if (!strncmp (instr[0], instructionSet[i].mnemonic, MAX_TOKEN_SIZE)) {
			// in AVR instructions could have different opcodes based on number of arguments
			if (instructionSet[i].numOperands == args) {
				/* because st Z+ and st Z (and so on...) are instructions with DIFFERENT opcodes
				   we handling all this instruction manually, by pre-parsing the arguments */
				if (args != 2) {
					return i; // it's 0- or 1- arg instruction
				}
				// handling (e)lpm instruction with 2 args
				if (instructionSet[i].opcodeMask >= 0x9004 &&
					instructionSet[i].opcodeMask <= 0x9007) {
					if (instructionSet[i].operandTypes[1] == parse_specialreg (instr[2])) {
						return i;
					}
					// handling ld & ldd instruction with 2 args
				} else if (instructionSet[i].mnemonic[0] == 'l'
					&& instructionSet[i].mnemonic[1] == 'd'
					&& (instructionSet[i].mnemonic[2] == 'd' || instructionSet[i].mnemonic[2] == '\0')) {
					if (instructionSet[i].operandTypes[1] == parse_specialreg (instr[2])) {
						return i;
					}
					// handling lds command, distinguishing long from 16-bit version
				} else if (instructionSet[i].mnemonic[0] == 'l'
					&& instructionSet[i].mnemonic[1] == 'd'
					&& instructionSet[i].mnemonic[2] == 's'
					&& instructionSet[i].operandTypes[1] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
					// ineffective, but needed for lds/sts and other cases
					if (strlen(instr[2]) > 0) {
						op2 = getnum (a, instr[2]);
						if (op2 > 127) {
							return i;
						}
					}
				// handling st & std instruction with 2 args
				} else if (instructionSet[i].mnemonic[0] == 's'
					&& instructionSet[i].mnemonic[1] == 't'
					&& (instructionSet[i].mnemonic[2] == 'd' || instructionSet[i].mnemonic[2] == '\0')) {

					if (instructionSet[i].operandTypes[0] == parse_specialreg (instr[1])) {
						return i;
					}
					// handling sts long command
				} else if (instructionSet[i].mnemonic[0] == 's'
					&& instructionSet[i].mnemonic[1] == 't'
					&& instructionSet[i].mnemonic[2] == 's'
					&& instructionSet[i].operandTypes[0] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
					// same for 1st operand of sts
					if (strlen(instr[1]) > 0) {
						op1 = getnum (a, instr[1]);
						if (op1 > 127) {
							return i;
						}
					}
				} else {
					return i; // it's not st/ld/lpm-like instruction with 2 args
				}
			}
		}
	}
	return -1;
}

// Packs certain bits of data according to mask, used to pack operands by their encoding in the opcode.
static uint16_t packDataByMask(uint16_t data, uint16_t mask) {
	int i, j;
	uint16_t result = 0;

	/* i counts through every bit of the mask,
	 * j counts through every bit of the original */
	for (i = 0, j = 0; i < 16; i++) {
		// If the mask has a bit in this position
		if (mask & (1<<i)) {
			/* If there is a data bit with this mask bit counter(j),
			 * then toggle that bit in the extracted data (result) by mask offset(i).*/
			if ((data & (1<<j)) != 0) {
				result |= (1<<i);
			}
			// Increment the original data bit count.
			j++;
		}
	}
	return result;
}

static int parse_registerpair(const char *operand) {
	int res = -1;
	char *first, *second, *op;
	int fnum, snum;

	op = strdup (operand);
	first = strtok (op, ":");

	if (!first || strlen (first) < 2) {
		free (op);
		return -1;
	}

	second = strtok (NULL, ":");

	/* the next code handles two possible different representation of pair
	   by pair rx+1:rx
	   or by even register rx
	   this is a bit ugly, code-duplicating, however stable
	   anyway FIXME if you have better idea */
	if (second && strlen (second) < 2) {
		/* the pair is set by pair
		   this is currently useless, cause rasm2 filters ':' from assembler
		   however, this bug soon will be fixed */
		if (first[0] == 'r' && second[0] == 'r') {
			fnum = atoi(first+1);
			snum = atoi(second+1);
			if (fnum > snum && snum >= 0 && snum <= 30) {
				res = snum / 2;
			}
		} else if (first[0] >= 'x' && first[0] <= 'z'
			 && second[0] >= 'x' && second[0] <= 'z'
			 && first[1] == 'h' && second[1] == 'l') {
			// convert to register pair number by inversing and invert (and adding 12)
			res = (2 - ('z' - first[0])) + 12;
		}
	} else {
		// the pair by even register (first)
		if (first[0] == 'r') {
			snum = atoi(first+1);
			if (snum >= 0 && snum <= 30) {
				res = snum / 2;
			}
		} else if (first[0] >= 'x' && first[0] <= 'z') {
			res = (2 - ('z' - first[0])) + 12;
		}
	}
	free (op);
	return res;
}

// assembles instruction argument (operand) based on its type
static int assemble_operand(RAsm *a, const char *operand, int type, uint32_t *res) {
	int ret = -1;
	int temp;

	switch (type) {
	case OPERAND_REGISTER_EVEN_PAIR:
		*res = parse_registerpair(operand);
		if (*res > 0) {
			ret = 0;
		}
		break;
	case OPERAND_REGISTER_EVEN_PAIR_STARTR24:
		*res = parse_registerpair(operand);
		// encoding in 2 bits for r25:r24 and upper pairs
		if (*res >= 12) {
			*res -= 12;
			ret = 0;
		}
		break;
	case OPERAND_BRANCH_ADDRESS:
	case OPERAND_RELATIVE_ADDRESS: // TODO: <-- check for negative (should be correct, but...)
		temp = getnum (a, operand); // return pure number
		/* the argument could be:
		- target address (will be calculated in according to current pc of assemble), ex: 0x4, 200, 0x1000
		or
		- relative address, ex: +2, -1, +60, -49 */
		if(a->pc || (operand[0] != '+' && operand[0] != '-')) { // for series of commands
			/* +2 from documentation:
			If Rd != Rr (Z = 0) then PC <- PC + k + 1, else PC <- PC + 1 */
			temp -= a->pc + 2;
		}
		temp /= 2; // in WORDs
		if (temp >= -64 && temp <= 63) {
			ret = 0;
		}
		*res = temp;
		break;
	case OPERAND_IO_REGISTER:
	case OPERAND_BIT:
	case OPERAND_DES_ROUND:
	case OPERAND_LONG_ABSOLUTE_ADDRESS:
	case OPERAND_DATA:
		*res = getnum(a, operand); // return pure number
		ret = 0;
		break;
	case OPERAND_COMPLEMENTED_DATA:
		*res = getnum(a, operand); // return pure number
		*res = ~(*res) & 0xFF; // complement it
		ret = 0;
		break;
	case OPERAND_MX:
	case OPERAND_X:
	case OPERAND_XP:
	case OPERAND_MY:
	case OPERAND_Y:
	case OPERAND_YP:
	case OPERAND_MZ:
	case OPERAND_Z:
	case OPERAND_ZP:
		*res = 0; //do nothing, operand is already encoded in opcode
		ret = 0;
		break;

	case OPERAND_YPQ:
	case OPERAND_ZPQ:
		if (strlen(operand) > 2) {
			/* return argument after '+' sign
			   we've already checked presence of '+' in parse_specialreg */
			*res = getnum(a, operand + 2);
			ret = 0;
		}
		break;

	case OPERAND_REGISTER:
		if (strlen(operand) > 1) {
			// returns register number (r__)
			*res = getnum(a, operand + 1);
			if (*res <= 32) {
				ret = 0;
			}
		}
		break;
	case OPERAND_REGISTER_STARTR16:
		if (strlen(operand) > 1) {
			// returns register number (r__)
			*res = getnum(a, operand + 1);
			if (*res >= 16 && *res <= 32) {
				*res -= 16;
				ret = 0;
			}
		}
		break;
	default:
		ret = -1;
	}

	return ret;
}

static int assemble(RAsm *a, RAsmOp *ao, const char *str) {
	char tokens[3][MAX_TOKEN_SIZE];
	char *token;
	uint32_t coded = 0;
	int len  = 0;
	uint32_t op1 = 0, op2 = 0;
	unsigned int tokens_cnt = 0;
	int instr_idx = -1;

	// simple tokenizer -- creates an array of maximum three tokens
	// the delimiters are ' ' and ','
	token = strtok ((char *)str, TOKEN_DELIM);
	while (token != NULL && tokens_cnt < 3) {
		memset (tokens[tokens_cnt], 0, MAX_TOKEN_SIZE);
		strncpy (tokens[tokens_cnt], token, MAX_TOKEN_SIZE-1);
		token = strtok (NULL, TOKEN_DELIM);
		tokens_cnt += 1;
	}

	if (tokens_cnt > 0) {
		// find nearest instruction that looks like supplied
		instr_idx = search_instruction (a, tokens, tokens_cnt - 1);

		if (instr_idx >= 0) {
			// no operands -- just return opcode mask
			if (instructionSet[instr_idx].numOperands == 0 && tokens_cnt == 1) {
				coded = instructionSet[instr_idx].opcodeMask;
				len = 2;
			/* for 1 or 2 operands (args) there are two cases:
			   1) for 2-byte instruction we use following scheme:
				mask | (packed first operand) [| (packed second operand)]
				packing is done by predefind operator mask
			   2) for 4-byte instruction we:
			 	get first 6 bits of long operand and masking them in the same way as (1)
				ORing with the last 16 bits(/2 for jmp/call) */
			} else if (instructionSet[instr_idx].numOperands == 1 && tokens_cnt == 2) {

				if (assemble_operand (a, tokens[1], instructionSet[instr_idx].operandTypes[0], &op1) >= 0) {
					// jmp and call has 4-byte opcode
					if (instructionSet[instr_idx].operandTypes[0] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
						op1 = op1/2;
						coded = instructionSet[instr_idx].opcodeMask
						| packDataByMask((op1 >> 16), instructionSet[instr_idx].operandMasks[0]);
						// memory addressed in bytes for jumps
						coded |= ((uint16_t)op1) << 16;
						len = 4;
					} else {
						// see avr_disasm.h for OPERAND_REGISTER_GHOST description
						// e.g. clr r0 == eor r0, r0
						if (instructionSet[instr_idx].operandTypes[1] == OPERAND_REGISTER_GHOST) {
							coded = instructionSet[instr_idx].opcodeMask
							| packDataByMask(op1, instructionSet[instr_idx].operandMasks[0])
							| packDataByMask(op1, instructionSet[instr_idx].operandMasks[1]);
						} else {
							coded = instructionSet[instr_idx].opcodeMask
							| packDataByMask(op1, instructionSet[instr_idx].operandMasks[0]);
						}

						len = 2;
					}
				}

			} else if (instructionSet[instr_idx].numOperands == 2 && tokens_cnt == 3) {
				if (assemble_operand(a, tokens[1], instructionSet[instr_idx].operandTypes[0], &op1) >= 0 &&
				   assemble_operand(a, tokens[2], instructionSet[instr_idx].operandTypes[1], &op2) >= 0) {

					coded = instructionSet[instr_idx].opcodeMask
						| packDataByMask(op1, instructionSet[instr_idx].operandMasks[0])
						| packDataByMask(op2, instructionSet[instr_idx].operandMasks[1]);

					len = 2;

					// handling lds/sts instructions
					if (instructionSet[instr_idx].operandTypes[0] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
						coded |= ((uint16_t)op1) << 16;
						len = 4;
					} else if (instructionSet[instr_idx].operandTypes[1] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
						coded |= ((uint16_t)op2) << 16;
						len = 4;
					}
				}
			}
		}
	}

	// copying result to radare struct
	if (len > 0) {
		r_strbuf_setbin (&ao->buf, (const ut8*)&coded, len);
	}
	return len;
}

// AVR assembler realization ends
RAsmPlugin r_asm_plugin_avr = {
	.name = "avr",
	.arch = "avr",
	.license = "GPL",
	.bits = 8|16,
	.endian = R_SYS_ENDIAN_LITTLE | R_SYS_ENDIAN_BIG,
	.desc = "AVR Atmel",
	.disassemble = &disassemble,
	.assemble = &assemble,
	.cpus =
		"ATmega8," // First one is default
		"ATmega1280,"
		"ATmega1281,"
		"ATmega168,"
		"ATmega2560,"
		"ATmega2561,"
		"ATmega328p,"
		"ATmega32u4,"
		"ATmega48,"
		"ATmega640,"
		"ATmega88,"
		"ATxmega128a4u"
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_avr,
	.version = R2_VERSION
};
#endif
