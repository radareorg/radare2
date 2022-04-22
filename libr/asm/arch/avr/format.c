/*
 * vAVRdisasm - AVR program disassembler.
 * Version 1.6 - February 2010.
 * Written by Vanya A. Sergeev - <vsergeev@gmail.com>
 *
 * Copyright (C) 2007 Vanya A. Sergeev
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * format_disasm.c - Formatting of disassembled instructions, with regard to the
 *  several formatting features this disassembler supports.
 *
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "format.h"
#include "r_util.h"
#include "avr_disasm.h"

/* Formats a disassembled operand with its prefix (such as 'R' to indicate a register) into the
 * pointer to a C-string strOperand, which must be free'd after it has been used.
 * I decided to format the disassembled operands individually into strings for maximum flexibility,
 * and so that the printing of the formatted operand is not hard coded into the format operand code.
 * If an addressLabelPrefix is specified in formattingOptions (option is set and string is not NULL),
 * it will print the relative branch/jump/call with this prefix and the destination address as the label. */
static int formatDisassembledOperand(RAsm *a, avrDisassembleContext *context, char *strOperand, int strOperandSize, int operandNum, const disassembledInstruction dInstruction, formattingOptions fOptions);
static int analFormatDisassembledOperand(RAnal *a, avrDisassembleContext *context, char *strOperand, int strOperandSize, int operandNum, const disassembledInstruction dInstruction, formattingOptions fOptions);


/* Prints a disassembled instruction, formatted with options set in the formattingOptions structure. */
int printDisassembledInstruction(RAsm *a, avrDisassembleContext *context, char *out, int out_len, const disassembledInstruction dInstruction, formattingOptions fOptions) {
	//char fmt[64];
	int retVal, i;
	char strOperand[256];
	*out = '\0';

	/* If we just found a long instruction, there is nothing to be printed yet, since we don't
	 * have the entire long address ready yet. */
	if (context->status == AVR_LONG_INSTRUCTION_FOUND) {
		return 0;
	}

	RStrBuf *sb = r_strbuf_new (dInstruction.instruction->mnemonic);
	if (dInstruction.instruction->numOperands > 0) {
		r_strbuf_append (sb, " ");
	}

	for (i = 0; i < dInstruction.instruction->numOperands; i++) {
		/* If we're not on the first operand, but not on the last one either, print a comma separating
		 * the operands. */
		if (i > 0 && i != dInstruction.instruction->numOperands) {
			r_strbuf_append (sb, ", ");
		}
		/* Format the disassembled operand into the string strOperand, and print it */
		retVal = formatDisassembledOperand (a, context, strOperand, sizeof (strOperand), i, dInstruction, fOptions);
		if (retVal < 0) {
			r_strbuf_free (sb);
			return retVal;
		}
		/* Print the operand and free if it's not NULL */
		r_strbuf_append (sb, strOperand);
	}
	const char *src = r_strbuf_get (sb);
	r_str_ncpy (out, src, out_len);
	r_strbuf_free (sb);
	return 1;
}

/* Prints a disassembled instruction, formatted with options set in the formattingOptions structure. */
int analPrintDisassembledInstruction(RAnal *a, avrDisassembleContext *context, char *out, int out_len, const disassembledInstruction dInstruction, formattingOptions fOptions) {
	//char fmt[64];
	int retVal, i;
	char strOperand[256];

	/* If we just found a long instruction, there is nothing to be printed yet, since we don't
	 * have the entire long address ready yet. */
	if (context->status == AVR_LONG_INSTRUCTION_FOUND) {
		return 0;
	}

	RStrBuf *sb = r_strbuf_new (dInstruction.instruction->mnemonic);
	if (dInstruction.instruction->numOperands > 0) {
		r_strbuf_append (sb, " ");
	}
	for (i = 0; i < dInstruction.instruction->numOperands; i++) {
		/* If we're not on the first operand, but not on the last one either, print a comma separating
		 * the operands. */
		if (i > 0 && i != dInstruction.instruction->numOperands) {
			r_strbuf_append (sb, ", ");
		}
		/* Format the disassembled operand into the string strOperand, and print it */
		retVal = analFormatDisassembledOperand (a, context, strOperand, sizeof (strOperand), i, dInstruction, fOptions);
		if (retVal < 0) {
			r_strbuf_free (sb);
			return retVal;
		}
		/* Print the operand and free if it's not NULL */
		r_strbuf_append (sb, strOperand);
	}
	char *src = r_strbuf_get (sb);
	r_str_ncpy (out, src, out_len);
	r_strbuf_free (sb);
	return 1;
}


static int formatDisassembledOperand(RAsm *a, avrDisassembleContext *context, char *strOperand, int strOperandSize, int operandNum, const disassembledInstruction dInstruction, formattingOptions fOptions) {
	char binary[9];
	int retVal;

	if (operandNum >= AVR_MAX_NUM_OPERANDS)
		return 0;

	switch (dInstruction.instruction->operandTypes[operandNum]) {
	case OPERAND_NONE:
	case OPERAND_REGISTER_GHOST:
		strOperand = NULL;
		retVal = 0;
		break;
	case OPERAND_REGISTER:
	case OPERAND_REGISTER_STARTR16:
	case OPERAND_REGISTER_EVEN_PAIR_STARTR24:
	case OPERAND_REGISTER_EVEN_PAIR:
		retVal = sprintf (strOperand, "%s%d", OPERAND_PREFIX_REGISTER,
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_DATA:
	case OPERAND_COMPLEMENTED_DATA:
		if (fOptions.options & FORMAT_OPTION_DATA_BIN) {
			int i;
			for (i = 7; i >= 0; i--) {
				if (dInstruction.operands[operandNum] & (1<<i))
					binary[7-i] = '1';
				else
					binary[7-i] = '0';
			}
			binary[8] = '\0';
			retVal = sprintf(strOperand, "%s%s",
				OPERAND_PREFIX_DATA_BIN, binary);
		} else if (fOptions.options & FORMAT_OPTION_DATA_DEC) {
			retVal = sprintf(strOperand, "%s%d",
				OPERAND_PREFIX_DATA_DEC,
				dInstruction.operands[operandNum]);
		} else {
			retVal = sprintf(strOperand, "%s%02x",
				OPERAND_PREFIX_DATA_HEX,
				dInstruction.operands[operandNum]);
		}
		break;
	case OPERAND_BIT:
		retVal = sprintf(strOperand, "%s%d", OPERAND_PREFIX_BIT,
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_BRANCH_ADDRESS:
	case OPERAND_RELATIVE_ADDRESS:
#if 0
		/* If we have an address label, print it, otherwise just print the
		 * relative distance to the destination address. */
		if ((fOptions.options & FORMAT_OPTION_ADDRESS_LABEL) && fOptions.addressLabelPrefix) {
			retVal = sprintf(strOperand, "%s%0*X",
				fOptions.addressLabelPrefix,
				fOptions.addressFieldWidth,
				dInstruction.address+dInstruction.operands[operandNum]+2);
		} else {
#endif
#if 0
			/* Check if the operand is greater than 0 so we can print the + sign. */
			if (dInstruction.operands[operandNum] > 0) {
				//retVal = sprintf(strOperand, "%s+%d", OPERAND_PREFIX_BRANCH_ADDRESS, dInstruction.operands[operandNum]);
				//retVal = sprintf(strOperand, "%s+%d (0x%08x)", OPERAND_PREFIX_BRANCH_ADDRESS, dInstruction.operands[operandNum],
				//	dInstruction.address + dInstruction.operands[operandNum]);
				retVal = sprintf(strOperand, "0x%x", dInstruction.address + dInstruction.operands[operandNum]);
			} else {
			/* Since the operand variable is signed, the negativeness of the distance
			 * to the destination address has been taken care of in disassembleOperands() */
//					retVal = sprintf(strOperand, "%s%d", OPERAND_PREFIX_BRANCH_ADDRESS, dInstruction.operands[operandNum]);
			}
#endif
			retVal = sprintf(strOperand, "0x%x",
				dInstruction.address + dInstruction.operands[operandNum]);
		//}
		break;
	case OPERAND_LONG_ABSOLUTE_ADDRESS:
		retVal = sprintf(strOperand, "%s%0*x",
			OPERAND_PREFIX_ABSOLUTE_ADDRESS,
			fOptions.addressFieldWidth, context->longAddress);
		break;
	case OPERAND_IO_REGISTER:
	{
		const char *current_register = NULL;
		bool is_register_found = false;

		switch (dInstruction.operands[operandNum]) {
		case 0x3d:
			current_register = "spl";//check the architecture for spl
			is_register_found = true;
			break;
		case 0x3e:
			current_register = "sph";
			is_register_found = true;
			break;
		case 0x3f:
			current_register = "sreg";
			is_register_found = true;
			break;
		}

		if (!strcmp (r_str_get (a->config->cpu), "ATmega328p")) {
			switch (dInstruction.operands[operandNum]) {
			case 0x03:
				current_register = "pinb";
				is_register_found = true;
				break;
			case 0x04:
				current_register = "ddrb";
				is_register_found = true;
				break;
			case 0x05:
				current_register = "portb";
				is_register_found = true;
				break;
			case 0x06:
				current_register = "pinc";
				is_register_found = true;
				break;
			case 0x07:
				current_register = "ddrc";
				is_register_found = true;
				break;
			case 0x08:
				current_register = "portc";
				is_register_found = true;
				break;
			case 0x09:
				current_register = "pind";
				is_register_found = true;
				break;
			case 0x0a:
				current_register = "ddrd";
				is_register_found = true;
				break;
			case 0x0b:
				current_register = "portd";
				is_register_found = true;
				break;
			case 0x15:
				current_register = "tifr0";
				is_register_found = true;
				break;
			case 0x016:
				current_register = "tifr1";
				is_register_found = true;
				break;
			case 0x17:
				current_register = "tifr2";
				is_register_found = true;
				break;
			case 0x1b:
				current_register = "pcifr";
				is_register_found = true;
				break;
			case 0x1c:
				current_register = "eifr";
				is_register_found = true;
				break;
			case 0x1d:
				current_register = "eimsk";
				is_register_found = true;
				break;
			case 0x1e:
				current_register = "gpior0";
				is_register_found = true;
				break;
			case 0x1f:
				current_register = "eecr";
				is_register_found = true;
				break;
			case 0x20:
				current_register = "eedr";
				is_register_found = true;
				break;
			case 0x21:
				current_register = "eear";
				is_register_found = true;
				break;
			case 0x22:
				current_register = "eearh";
				is_register_found = true;
				break;
			case 0x23:
				current_register = "gtccr";
				is_register_found = true;
				break;
			case 0x24:
				current_register = "tccr0a";
				is_register_found = true;
				break;
			case 0x25:
				current_register = "tccr0b";
				is_register_found = true;
				break;
			case 0x26:
				current_register = "tcnt0";
				is_register_found = true;
				break;
			case 0x27:
				current_register = "otcr0a";
				is_register_found = true;
				break;
			case 0x28:
				current_register = "otcr0b";
				is_register_found = true;
				break;
			case 0x2a:
				current_register = "gpior1";
				is_register_found = true;
				break;
			case 0x2b:
				current_register = "gpior2";
				is_register_found = true;
				break;
			case 0x2c:
				current_register = "spcr";
				is_register_found = true;
				break;
			case 0x2d:
				current_register = "spsr";
				is_register_found = true;
				break;
			case 0x2e:
				current_register = "spdr";
				is_register_found = true;
				break;
			case 030:
				current_register = "acsr";
				is_register_found = true;
				break;
			case 0x33:
				current_register = "smcr";
				is_register_found = true;
				break;
			case 0x34:
				current_register = "mcusr";
				is_register_found = true;
				break;
			case 0x35:
				current_register = "mcucr";
				is_register_found = true;
				break;
			case 0x37:
				current_register = "spmcsr";
				is_register_found = true;
				break;
			/*case 0x60:
				current_register = "wdtcsr";
				is_register_found = true;
				break;
			case 0x61:
				current_register = "clkpr";
				is_register_found = true;
				break;
			case 0x64:
				current_register = "prr";
				is_register_found = true;
				break;
			case 0x66:
				current_register = "osccal";
				is_register_found = true;
				break;
			case 0x68:
				current_register = "pcicr";
				is_register_found = true;
				break;*/
			default:
				if (is_register_found == false) {
					retVal = snprintf (strOperand, strOperandSize, "0x%x", dInstruction.operands[operandNum]);
				}
				break;
			}
		}
		if (!strcmp (r_str_get (a->config->cpu), "AT90S1200")) {
			switch (dInstruction.operands[operandNum]) {
			case 0x08:
				current_register = "acsr";
				is_register_found = true;
				break;
			case 0x10:
				current_register = "pind";
				is_register_found = true;
				break;
			case 0x11:
				current_register = "ddrd";
				is_register_found = true;
				break;
			case 0x12:
				current_register = "portd";
				is_register_found = true;
				break;
			default:
				break;
			}
		}
		if (is_register_found) {
			retVal = r_str_ncpy (strOperand, current_register, strOperandSize);
		} else {
			retVal = snprintf (strOperand, 5, "0x%x", dInstruction.operands[operandNum]);
		}
		break;
	}
	case OPERAND_WORD_DATA:
		retVal = sprintf (strOperand, "%s%0*x",
			OPERAND_PREFIX_WORD_DATA,
			fOptions.addressFieldWidth,
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_DES_ROUND:
		retVal = sprintf (strOperand, "%s%02x",
			OPERAND_PREFIX_WORD_DATA,
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_YPQ:
		retVal = sprintf(strOperand, "y+%d",
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_ZPQ:
		retVal = sprintf(strOperand, "z+%d",
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_X: retVal = sprintf(strOperand, "x"); break;
	case OPERAND_XP: retVal = sprintf(strOperand, "x+"); break;
	case OPERAND_MX: retVal = sprintf(strOperand, "-x"); break;
	case OPERAND_Y: retVal = sprintf(strOperand, "y"); break;
	case OPERAND_YP: retVal = sprintf(strOperand, "y+"); break;
	case OPERAND_MY: retVal = sprintf(strOperand, "-y"); break;
	case OPERAND_Z: retVal = sprintf(strOperand, "z"); break;
	case OPERAND_ZP: retVal = sprintf(strOperand, "z+"); break;
	case OPERAND_MZ: retVal = sprintf(strOperand, "-z"); break;
	/* This is impossible by normal operation. */
	default: return ERROR_UNKNOWN_OPERAND;
	}
	return retVal <0? ERROR_MEMORY_ALLOCATION_ERROR: 0;
}

/* Formats a disassembled operand with its prefix (such as 'R' to indicate a register) into the
 * pointer to a C-string strOperand, which must be free'd after it has been used.
 * I decided to format the disassembled operands individually into strings for maximum flexibility,
 * and so that the printing of the formatted operand is not hard coded into the format operand code.
 * If an addressLabelPrefix is specified in formattingOptions (option is set and string is not NULL),
 * it will print the relative branch/jump/call with this prefix and the destination address as the label. */
static int analFormatDisassembledOperand(RAnal *a, avrDisassembleContext *context, char *strOperand, int strOperandSize, int operandNum, const disassembledInstruction dInstruction, formattingOptions fOptions) {
	char binary[9];
	int retVal;

	if (operandNum >= AVR_MAX_NUM_OPERANDS)
		return 0;

	switch (dInstruction.instruction->operandTypes[operandNum]) {
	case OPERAND_NONE:
	case OPERAND_REGISTER_GHOST:
		strOperand = NULL;
		retVal = 0;
		break;
	case OPERAND_REGISTER:
	case OPERAND_REGISTER_STARTR16:
	case OPERAND_REGISTER_EVEN_PAIR_STARTR24:
	case OPERAND_REGISTER_EVEN_PAIR:
		retVal = snprintf (strOperand, strOperandSize, "%s%d", OPERAND_PREFIX_REGISTER,
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_DATA:
	case OPERAND_COMPLEMENTED_DATA:
		if (fOptions.options & FORMAT_OPTION_DATA_BIN) {
			int i;
			for (i = 7; i >= 0; i--) {
				if (dInstruction.operands[operandNum] & (1<<i))
					binary[7-i] = '1';
				else
					binary[7-i] = '0';
			}
			binary[8] = '\0';
			retVal = snprintf (strOperand, strOperandSize, "%s%s",
				OPERAND_PREFIX_DATA_BIN, binary);
		} else if (fOptions.options & FORMAT_OPTION_DATA_DEC) {
			retVal = snprintf (strOperand, strOperandSize, "%s%d",
				OPERAND_PREFIX_DATA_DEC,
				dInstruction.operands[operandNum]);
		} else {
			retVal = snprintf (strOperand, strOperandSize, "%s%02x",
				OPERAND_PREFIX_DATA_HEX,
				dInstruction.operands[operandNum]);
		}
		break;
	case OPERAND_BIT:
		retVal = snprintf (strOperand, strOperandSize, "%s%d", OPERAND_PREFIX_BIT,
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_BRANCH_ADDRESS:
	case OPERAND_RELATIVE_ADDRESS:
#if 0
		/* If we have an address label, print it, otherwise just print the
		 * relative distance to the destination address. */
		if ((fOptions.options & FORMAT_OPTION_ADDRESS_LABEL) && fOptions.addressLabelPrefix) {
			retVal = sprintf(strOperand, "%s%0*X",
				fOptions.addressLabelPrefix,
				fOptions.addressFieldWidth,
				dInstruction.address+dInstruction.operands[operandNum]+2);
		} else {
#endif
#if 0
			/* Check if the operand is greater than 0 so we can print the + sign. */
			if (dInstruction.operands[operandNum] > 0) {
				//retVal = sprintf(strOperand, "%s+%d", OPERAND_PREFIX_BRANCH_ADDRESS, dInstruction.operands[operandNum]);
				//retVal = sprintf(strOperand, "%s+%d (0x%08x)", OPERAND_PREFIX_BRANCH_ADDRESS, dInstruction.operands[operandNum],
				//	dInstruction.address + dInstruction.operands[operandNum]);
				retVal = sprintf(strOperand, "0x%x", dInstruction.address + dInstruction.operands[operandNum]);
			} else {
			/* Since the operand variable is signed, the negativeness of the distance
			 * to the destination address has been taken care of in disassembleOperands() */
//					retVal = sprintf(strOperand, "%s%d", OPERAND_PREFIX_BRANCH_ADDRESS, dInstruction.operands[operandNum]);
			}
#endif
			retVal = snprintf (strOperand, strOperandSize, "0x%x",
				dInstruction.address + dInstruction.operands[operandNum]);
		//}
		break;
	case OPERAND_LONG_ABSOLUTE_ADDRESS:
		retVal = snprintf (strOperand, strOperandSize, "%s%0*x",
			OPERAND_PREFIX_ABSOLUTE_ADDRESS,
			fOptions.addressFieldWidth, context->longAddress);
		break;
	case OPERAND_IO_REGISTER:
	{
		const char *current_register = NULL;
		bool is_register_found = false;

		switch (dInstruction.operands[operandNum]) {
		case 0x3d:
			current_register = "spl";//check the architecture for spl
			is_register_found = true;
			break;
		case 0x3e:
			current_register = "sph";
			is_register_found = true;
			break;
		case 0x3f:
			current_register = "sreg";
			is_register_found = true;
			break;
		}

		if (!strcmp (r_str_get (a->cpu), "ATmega328p")) {
			switch (dInstruction.operands[operandNum]) {
			case 0x03:
				current_register = "pinb";
				is_register_found = true;
				break;
			case 0x04:
				current_register = "ddrb";
				is_register_found = true;
				break;
			case 0x05:
				current_register = "portb";
				is_register_found = true;
				break;
			case 0x06:
				current_register = "pinc";
				is_register_found = true;
				break;
			case 0x07:
				current_register = "ddrc";
				is_register_found = true;
				break;
			case 0x08:
				current_register = "portc";
				is_register_found = true;
				break;
			case 0x09:
				current_register = "pind";
				is_register_found = true;
				break;
			case 0x0a:
				current_register = "ddrd";
				is_register_found = true;
				break;
			case 0x0b:
				current_register = "portd";
				is_register_found = true;
				break;
			case 0x15:
				current_register = "tifr0";
				is_register_found = true;
				break;
			case 0x016:
				current_register = "tifr1";
				is_register_found = true;
				break;
			case 0x17:
				current_register = "tifr2";
				is_register_found = true;
				break;
			case 0x1b:
				current_register = "pcifr";
				is_register_found = true;
				break;
			case 0x1c:
				current_register = "eifr";
				is_register_found = true;
				break;
			case 0x1d:
				current_register = "eimsk";
				is_register_found = true;
				break;
			case 0x1e:
				current_register = "gpior0";
				is_register_found = true;
				break;
			case 0x1f:
				current_register = "eecr";
				is_register_found = true;
				break;
			case 0x20:
				current_register = "eedr";
				is_register_found = true;
				break;
			case 0x21:
				current_register = "eear";
				is_register_found = true;
				break;
			case 0x22:
				current_register = "eearh";
				is_register_found = true;
				break;
			case 0x23:
				current_register = "gtccr";
				is_register_found = true;
				break;
			case 0x24:
				current_register = "tccr0a";
				is_register_found = true;
				break;
			case 0x25:
				current_register = "tccr0b";
				is_register_found = true;
				break;
			case 0x26:
				current_register = "tcnt0";
				is_register_found = true;
				break;
			case 0x27:
				current_register = "otcr0a";
				is_register_found = true;
				break;
			case 0x28:
				current_register = "otcr0b";
				is_register_found = true;
				break;
			case 0x2a:
				current_register = "gpior1";
				is_register_found = true;
				break;
			case 0x2b:
				current_register = "gpior2";
				is_register_found = true;
				break;
			case 0x2c:
				current_register = "spcr";
				is_register_found = true;
				break;
			case 0x2d:
				current_register = "spsr";
				is_register_found = true;
				break;
			case 0x2e:
				current_register = "spdr";
				is_register_found = true;
				break;
			case 030:
				current_register = "acsr";
				is_register_found = true;
				break;
			case 0x33:
				current_register = "smcr";
				is_register_found = true;
				break;
			case 0x34:
				current_register = "mcusr";
				is_register_found = true;
				break;
			case 0x35:
				current_register = "mcucr";
				is_register_found = true;
				break;
			case 0x37:
				current_register = "spmcsr";
				is_register_found = true;
				break;
			/*case 0x60:
				current_register = "wdtcsr";
				is_register_found = true;
				break;
			case 0x61:
				current_register = "clkpr";
				is_register_found = true;
				break;
			case 0x64:
				current_register = "prr";
				is_register_found = true;
				break;
			case 0x66:
				current_register = "osccal";
				is_register_found = true;
				break;
			case 0x68:
				current_register = "pcicr";
				is_register_found = true;
				break;*/
			default:
				break;
			}
		}


		if (is_register_found) {
			r_str_ncpy (strOperand, current_register, strOperandSize);
			retVal = strlen (strOperand);
		} else {
			retVal = snprintf (strOperand, strOperandSize, "0x%x", dInstruction.operands[operandNum]);
		}
		break;
	}
	case OPERAND_WORD_DATA:
		retVal = sprintf (strOperand, "%s%0*x",
			OPERAND_PREFIX_WORD_DATA,
			fOptions.addressFieldWidth,
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_DES_ROUND:
		retVal = sprintf (strOperand, "%s%02x",
			OPERAND_PREFIX_WORD_DATA,
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_YPQ:
		retVal = snprintf (strOperand, strOperandSize, "y+%d",
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_ZPQ:
		retVal = snprintf (strOperand, strOperandSize, "z+%d",
			dInstruction.operands[operandNum]);
		break;
	case OPERAND_X: retVal = snprintf (strOperand, strOperandSize, "x"); break;
	case OPERAND_XP: retVal = snprintf (strOperand, strOperandSize, "x+"); break;
	case OPERAND_MX: retVal = snprintf (strOperand, strOperandSize, "-x"); break;
	case OPERAND_Y: retVal = snprintf (strOperand, strOperandSize, "y"); break;
	case OPERAND_YP: retVal = snprintf (strOperand, strOperandSize, "y+"); break;
	case OPERAND_MY: retVal = snprintf (strOperand, strOperandSize, "-y"); break;
	case OPERAND_Z: retVal = snprintf (strOperand, strOperandSize, "z"); break;
	case OPERAND_ZP: retVal = snprintf (strOperand, strOperandSize, "z+"); break;
	case OPERAND_MZ: retVal = snprintf (strOperand, strOperandSize, "-z"); break;
	/* This is impossible by normal operation. */
	default: return ERROR_UNKNOWN_OPERAND;
	}
	return retVal < 0? ERROR_MEMORY_ALLOCATION_ERROR: 0;
}

int parse_registerpair(const char *operand) {
		int res = -1;
		char *op = strdup (operand);
		char *first = strtok (op, ":");

		if (!first || strlen (first) < 2) {
			free (op);
			return -1;
		}

		char *second = strtok (NULL, ":");

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
				int fnum = atoi (first + 1);
				int snum = atoi (second + 1);
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
				int snum = atoi(first+1);
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
