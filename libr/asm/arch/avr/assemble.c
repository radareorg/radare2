#include "r_asm.h"
#include "format.h"
#include "assemble.h"

extern instructionInfo instructionSet[AVR_TOTAL_INSTRUCTIONS];


typedef struct {
	char ens[3][MAX_TOKEN_SIZE];
} AvrToken;
static int search_instruction(RAnal *a, AvrToken *tok, int args);
// char instr[3][MAX_TOKEN_SIZE], int args);
/* the next few functions and structures uses for detecting
   AVR special regs, like X+, -Y, Z+3 in st(d), ld(d) and
   (e)lpm instructions */
struct _specialregs {
	char reg[4];
	int operandType;
};
typedef struct _specialregs specialregs;

#define REGS_TABLE 9

/* gets the number from string
   duplicate from asm_x86_nz.c -- may be create a generic function? */
static int getnum(const char *s) {
	if (!s || !*s) {
		return 0;
	}
	if (*s == '$') {
		s++;
	}
	return sdb_atoi (s);
}

// radare tolower instruction in rasm, so we use 'x' instead of 'X' etc.
specialregs RegsTable[REGS_TABLE] = {
	{"-x", OPERAND_XP}, {"x", OPERAND_X}, {"x+", OPERAND_XP},
	{"-y", OPERAND_YP}, {"y", OPERAND_Y}, {"y+", OPERAND_YP},
	{"-z", OPERAND_ZP}, {"z", OPERAND_Z}, {"z+", OPERAND_ZP},
};


int avr_encode(RAnal *a, ut64 pc, const char *str, ut8 *outbuf, int outlen) {
	AvrToken tok;
	char *token;
	uint32_t coded = 0;
	int len  = 0;
	uint32_t op1 = 0, op2 = 0;
	unsigned int tokens_cnt = 0;
	int instr_idx = -1;

	// simple tokenizer -- creates an array of maximum three tokens
	// the delimiters are ' ' and ','
	token = strtok ((char *)str, TOKEN_DELIM);
	while (token && tokens_cnt < 3) {
		memset (tok.ens[tokens_cnt], 0, MAX_TOKEN_SIZE);
		strncpy (tok.ens[tokens_cnt], token, MAX_TOKEN_SIZE-1);
		token = strtok (NULL, TOKEN_DELIM);
		tokens_cnt += 1;
	}

	if (tokens_cnt > 0) {
		// find nearest instruction that looks like supplied
		instr_idx = search_instruction (a, &tok, tokens_cnt - 1);

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

				if (assemble_operand (pc, tok.ens[1], instructionSet[instr_idx].operandTypes[0], &op1) >= 0) {
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
				if (assemble_operand(pc, tok.ens[1], instructionSet[instr_idx].operandTypes[0], &op1) >= 0 &&
				   assemble_operand(pc, tok.ens[2], instructionSet[instr_idx].operandTypes[1], &op2) >= 0) {

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
		memcpy (outbuf, (const ut8*)&coded, len);
	}
	return len;
}

static int assemble_general_io_operand(const char *operand, uint32_t *res) {
	/*@
		 requires strcmp (operand, "spl") == 0 || strcmp (operand, "0x3d") == 0 ||
		 strcmp (operand, "sph") == 0 || strcmp (operand, "0x3e") == 0 ||
		 strcmp (operand, "sreg") == 0 || strcmp (operand, "0x3f") == 0

		 behavior case_spl
		     assumes strcmp (operand, "spl") == 0 || strcmp (operand, "0x3d") == 0
		     ensure *res == 0x3d
		 behavior case_sph
		     assumes strcmp (operand, "sph") == 0 || strcmp (operand, "0x3e") == 0
		     ensure *res == 0x3d
		 behavior case_sreg
		     assumes strcmp (operand, "sreg") == 0 || strcmp (operand, "0x3f") == 0
		     ensure *res == 0x3d

		 complete behaviors;
	     disjoint behaviors;
	*/
	int ret = -1;
	if (!strcmp (operand, "spl") || !strcmp (operand, "0x3d")) {
		*res = 0x3d;
		ret = 0;
	} else if (!strcmp (operand, "sph") || !strcmp (operand, "0x3e")) {
		*res = 0x3e;
		ret = 0;
	} else if (!strcmp (operand, "sreg") || !strcmp (operand, "0x3f")) {
		*res = 0x3f;
		ret = 0;
	}/* else {
		*res = getnum (operand); // return pure number
		ret = 0;
	}*/

	return ret;
}

// assembles instruction argument (operand) based on its type
int assemble_operand(ut64 pc, const char *operand, int type, uint32_t *res) {
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
		temp = getnum (operand); // return pure number
		/* the argument could be:
		- target address (will be calculated in according to current pc of assemble), ex: 0x4, 200, 0x1000
		or
		- relative address, ex: +2, -1, +60, -49 */
		if (pc || (operand[0] != '+' && operand[0] != '-')) { // for series of commands
			/* +2 from documentation:
			If Rd != Rr (Z = 0) then PC <- PC + k + 1, else PC <- PC + 1 */
			temp -= pc + 2;
		}
		temp /= 2; // in WORDs
		if (temp >= -64 && temp <= 63) {
			ret = 0;
		}
		*res = temp;
		break;
	case OPERAND_IO_REGISTER:
		assemble_general_io_operand (operand, res);
		ret = 0;
		break;
	case OPERAND_BIT:
	case OPERAND_DES_ROUND:
	case OPERAND_LONG_ABSOLUTE_ADDRESS:
	case OPERAND_DATA:
		*res = getnum (operand); // return pure number
		ret = 0;
		break;
	case OPERAND_COMPLEMENTED_DATA:
		*res = getnum (operand); // return pure number
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
		if (strlen (operand) > 2) {
			/* return argument after '+' sign
			   we've already checked presence of '+' in parse_specialreg */
			*res = getnum (operand + 2);
			ret = 0;
		}
		break;
	case OPERAND_REGISTER:
		if (strlen (operand) > 1) {
			// returns register number (r__)
			*res = getnum (operand + 1);
			if (*res <= 32) {
				ret = 0;
			}
		}
		break;
	case OPERAND_REGISTER_STARTR16:
		if (strlen (operand) > 1) {
			// returns register number (r__)
			*res = getnum (operand + 1);
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

// Packs certain bits of data according to mask, used to pack operands by their encoding in the opcode.
uint16_t packDataByMask(uint16_t data, uint16_t mask) {
	int i, j;
	uint16_t result = 0;

	/* i counts through every bit of the mask,
	 * j counts through every bit of the original */
	for (i = 0, j = 0; i < 16; i++) {
		// If the mask has a bit in this position
		if (mask & (1 << i)) {
			/* If there is a data bit with this mask bit counter(j),
			 * then toggle that bit in the extracted data (result) by mask offset(i).*/
			if ((data & (1 << j)) != 0) {
				result |= (1 << i);
			}
			// Increment the original data bit count.
			j++;
		}
	}
	return result;
}

/* this function searches from instruction in instructionSet table
   (see avr_disasm.h for more info)
   returns index of the instruction in the table */
static int search_instruction(RAnal *a, AvrToken *tok, int args) {
	int i, op1 = 0, op2 = 0;

	for (i = 0; i < AVR_TOTAL_INSTRUCTIONS - 1; i++) {
		// check instruction mnemonic
		if (!strncmp (tok->ens[0], instructionSet[i].mnemonic, MAX_TOKEN_SIZE)) {
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
					if (instructionSet[i].operandTypes[1] == parse_specialreg (tok->ens[2])) {
						return i;
					}
					// handling ld & ldd instruction with 2 args
				} else if (instructionSet[i].mnemonic[0] == 'l'
					&& instructionSet[i].mnemonic[1] == 'd'
					&& (instructionSet[i].mnemonic[2] == 'd' || instructionSet[i].mnemonic[2] == '\0')) {
					if (instructionSet[i].operandTypes[1] == parse_specialreg (tok->ens[2])) {
						return i;
					}
					// handling lds command, distinguishing long from 16-bit version
				} else if (instructionSet[i].mnemonic[0] == 'l'
					&& instructionSet[i].mnemonic[1] == 'd'
					&& instructionSet[i].mnemonic[2] == 's'
					&& instructionSet[i].operandTypes[1] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
					// ineffective, but needed for lds/sts and other cases
					if (strlen (tok->ens[2]) > 0) {
						op2 = getnum (tok->ens[2]);
						if (op2 > 127) {
							return i;
						}
					}
				// handling st & std instruction with 2 args
				} else if (instructionSet[i].mnemonic[0] == 's'
					&& instructionSet[i].mnemonic[1] == 't'
					&& (instructionSet[i].mnemonic[2] == 'd' || instructionSet[i].mnemonic[2] == '\0')) {

					if (instructionSet[i].operandTypes[0] == parse_specialreg (tok->ens[1])) {
						return i;
					}
					// handling sts long command
				} else if (instructionSet[i].mnemonic[0] == 's'
					&& instructionSet[i].mnemonic[1] == 't'
					&& instructionSet[i].mnemonic[2] == 's'
					&& instructionSet[i].operandTypes[0] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
					// same for 1st operand of sts
					if (strlen (tok->ens[1]) > 0) {
						op1 = getnum (tok->ens[1]);
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

int parse_specialreg(const char *reg) {
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
