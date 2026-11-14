#include "r_asm.h"
#include "format.h"
#include "assemble.h"
#include <errno.h>

extern instructionInfo instructionSet[AVR_TOTAL_INSTRUCTIONS];


typedef struct {
	char ens[3][MAX_TOKEN_SIZE];
} AvrToken;
static int search_instruction(RArchSession *as, AvrToken *tok, int args);
// char instr[3][MAX_TOKEN_SIZE], int args);
/* the next few functions and structures uses for detecting
 * AVR special regs, like X+, -Y, Z+3 in st(d), ld(d) and
 * (e)lpm instructions */
struct _specialregs {
	char reg[4];
	int operandType;
};
typedef struct _specialregs specialregs;

#define REGS_TABLE 9

static bool getnum(const char *s, st64 *value) {
	if (*s == '$') {
		s++;
	}
	char *end;
	errno = 0;
	st64 number = strtoll (s, &end, 0);
	if (errno == ERANGE || end == s || *end) {
		return false;
	}
	*value = number;
	return true;
}

// radare tolower instruction in rasm, so we use 'x' instead of 'X' etc.
specialregs RegsTable[REGS_TABLE] = {
	{ "-x", OPERAND_MX}, { "x", OPERAND_X}, { "x+", OPERAND_XP},
	{ "-y", OPERAND_MY}, { "y", OPERAND_Y}, { "y+", OPERAND_YP},
	{ "-z", OPERAND_MZ}, { "z", OPERAND_Z}, { "z+", OPERAND_ZP},
};


// Negative 8-bit data is encoded in two's complement.
static bool operand_fits(st64 value, int type, ut16 mask) {
	int bits;
	switch (type) {
	case OPERAND_DATA:
		bits = r_bits_popcount32 (mask);
		return value >= (bits == 8? -128: 0) && value < (1LL << bits);
	case OPERAND_REGISTER:
	case OPERAND_REGISTER_STARTR16:
	case OPERAND_REGISTER_EVEN_PAIR:
	case OPERAND_REGISTER_EVEN_PAIR_STARTR24:
	case OPERAND_IO_REGISTER:
	case OPERAND_BIT:
	case OPERAND_DES_ROUND:
	case OPERAND_YPQ:
	case OPERAND_ZPQ:
		return value >= 0 && value < (1LL << r_bits_popcount32 (mask));
	case OPERAND_BRANCH_ADDRESS:
	case OPERAND_RELATIVE_ADDRESS:
		bits = r_bits_popcount32 (mask);
		return value >= -(1LL << (bits - 1)) && value < (1LL << (bits - 1));
	case OPERAND_LONG_ABSOLUTE_ADDRESS:
		return value >= 0 && value <= 0xffff;
	default:
		return true;
	}
}

int avr_encode(RArchSession *as, ut64 pc, const char *str, ut8 *outbuf) {
	AvrToken tok = {0};
	char *token;
	char *save_ptr = NULL;
	ut32 coded = 0;
	int len  = 0;
	st64 op1 = 0, op2 = 0;
	unsigned int tokens_cnt = 0;
	int instr_idx = -1;

	// simple tokenizer -- creates an array of maximum three tokens
	// the delimiters are ' ' and ','
	token = r_str_tok_r ((char *)str, TOKEN_DELIM, &save_ptr);
	while (token && tokens_cnt < 3) {
		if (strlen (token) >= MAX_TOKEN_SIZE) {
			return 0;
		}
		strcpy (tok.ens[tokens_cnt], token);
		token = r_str_tok_r (NULL, TOKEN_DELIM, &save_ptr);
		tokens_cnt += 1;
	}

	if (token) {
		return 0;
	}
	if (tokens_cnt > 0) {
		// find nearest instruction that looks like supplied
		instr_idx = search_instruction (as, &tok, tokens_cnt - 1);

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
						if (op1 < 0 || op1 > 0x7ffffe || (op1 & 1)) {
							return 0;
						}
						op1 = op1/2;
						coded = instructionSet[instr_idx].opcodeMask
						| packDataByMask((op1 >> 16), instructionSet[instr_idx].operandMasks[0]);
						// memory addressed in bytes for jumps
						coded |= (ut32)(ut16)op1 << 16;
						len = 4;
					} else if (!operand_fits (op1, instructionSet[instr_idx].operandTypes[0], instructionSet[instr_idx].operandMasks[0])) {
						return 0;
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
				if (assemble_operand (pc, tok.ens[1], instructionSet[instr_idx].operandTypes[0], &op1) < 0 ||
					assemble_operand (pc, tok.ens[2], instructionSet[instr_idx].operandTypes[1], &op2) < 0) {
					return 0;
				}
				if (operand_fits (op1, instructionSet[instr_idx].operandTypes[0], instructionSet[instr_idx].operandMasks[0]) &&
				   operand_fits (op2, instructionSet[instr_idx].operandTypes[1], instructionSet[instr_idx].operandMasks[1])) {

					coded = instructionSet[instr_idx].opcodeMask
						| packDataByMask(op1, instructionSet[instr_idx].operandMasks[0])
						| packDataByMask(op2, instructionSet[instr_idx].operandMasks[1]);

					len = 2;

					// handling lds/sts instructions
					if (instructionSet[instr_idx].operandTypes[0] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
						coded |= (ut32)(ut16)op1 << 16;
						len = 4;
					} else if (instructionSet[instr_idx].operandTypes[1] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
						coded |= (ut32)(ut16)op2 << 16;
						len = 4;
					}
				}
			}
		}
	}

	// copying result to radare struct
	switch (len) {
	case 4:	outbuf[3] = (ut8)(coded >> 24);  // fallthrough
	case 3: outbuf[2] = (ut8)(coded >> 16);
	case 2: outbuf[1] = (ut8)(coded >> 8);
	case 1: outbuf[0] = (ut8)coded;
	}

	return len;
}

static int assemble_general_io_operand(const char *operand, st64 *res) {
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
	}

	return ret;
}

// assembles instruction argument (operand) based on its type
int assemble_operand(ut64 pc, const char *operand, int type, st64 *res) {
	st64 value;
	switch (type) {
	case OPERAND_REGISTER_EVEN_PAIR:
		value = parse_registerpair (operand);
		if (value < 0) {
			return -1;
		}
		break;
	case OPERAND_REGISTER_EVEN_PAIR_STARTR24:
		value = parse_registerpair (operand);
		if (value < 12) {
			return -1;
		}
		value -= 12;
		break;
	case OPERAND_BRANCH_ADDRESS:
	case OPERAND_RELATIVE_ADDRESS:
		if (!getnum (operand, &value)) {
			return -1;
		}
		// An explicit sign denotes a displacement; otherwise this is a target address.
		if (operand[0] != '+' && operand[0] != '-') {
			if (value < 0 || pc > ST64_MAX - 2) {
				return -1;
			}
			value -= (st64)pc + 2;
		}
		if (value & 1) {
			return -1;
		}
		value /= 2;
		break;
	case OPERAND_IO_REGISTER:
		if (assemble_general_io_operand (operand, &value) < 0 && !getnum (operand, &value)) {
			return -1;
		}
		break;
	case OPERAND_BIT:
	case OPERAND_DES_ROUND:
	case OPERAND_LONG_ABSOLUTE_ADDRESS:
	case OPERAND_DATA:
		if (!getnum (operand, &value)) {
			return -1;
		}
		break;
	case OPERAND_COMPLEMENTED_DATA:
		if (!getnum (operand, &value) || value < -128 || value > 0xff) {
			return -1;
		}
		value = ~value & 0xff;
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
		value = 0;
		break;
	case OPERAND_YPQ:
	case OPERAND_ZPQ:
		if (strlen (operand) <= 2 || !getnum (operand + 2, &value)) {
			return -1;
		}
		break;
	case OPERAND_REGISTER:
	case OPERAND_REGISTER_STARTR16:
		if (*operand != 'r' || !getnum (operand + 1, &value)) {
			return -1;
		}
		if (type == OPERAND_REGISTER_STARTR16) {
			if (value < 16) {
				return -1;
			}
			value -= 16;
		}
		break;
	default:
		return -1;
	}
	*res = value;
	return 0;
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
 * (see avr_disasm.h for more info)
 * returns index of the instruction in the table */
static int search_instruction(RArchSession *as, AvrToken *tok, int args) {
	int i;

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
				// handling st & std instruction with 2 args
				} else if (instructionSet[i].mnemonic[0] == 's'
					&& instructionSet[i].mnemonic[1] == 't'
					&& (instructionSet[i].mnemonic[2] == 'd' || instructionSet[i].mnemonic[2] == '\0')) {

					if (instructionSet[i].operandTypes[0] == parse_specialreg (tok->ens[1])) {
						return i;
					}
				} else {
					// lds/sts select the 32-bit entry before the reduced-core encoding.
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
