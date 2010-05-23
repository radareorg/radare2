/*
 * vAVRdisasm - AVR program disassembler.
 * Version 1.4 - June 2009.
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
 * format_disasm.h - Header file to formatting of disassembled instructions, with
 *  regard to the several formatting features this disasssembler supports.
 *
 */
 
#include "avr_disasm.h"
#include "errorcodes.h"

#ifndef FORMAT_DISASM_H
#define FORMAT_DISASM_H

/* AVR Operand prefixes
 * In order to keep the disassembler as straightforward as possible,
 * but still have some fundamental formatting options, I decided to hardcode
 * the operand prefixes. Feel free to change them here.  */
#define OPERAND_PREFIX_REGISTER			"R"	/* i.e. mov R0, R2 */
#define OPERAND_PREFIX_DATA_HEX			"0x"	/* i.e. ldi R16, 0x3D */
#define OPERAND_PREFIX_DATA_BIN			"0b"	/* i.e. ldi R16, 0b00111101 */
#define OPERAND_PREFIX_DATA_DEC			""	/* i.e. ldi R16, 61  */
#define OPERAND_PREFIX_BIT			"" 	/* i.e. bset 7 */
#define OPERAND_PREFIX_IO_REGISTER		"$"	/* i.e. out $39, R16 */
#define OPERAND_PREFIX_ABSOLUTE_ADDRESS 	"0x"	/* i.e. call 0x23 */
#define OPERAND_PREFIX_BRANCH_ADDRESS 		"."	/* i.e. rcall .+4 */
#define OPERAND_PREFIX_DES_ROUND		"0x"	/* i.e. des 0x01 */
#define OPERAND_PREFIX_WORD_DATA		"0x"	/* i.e. .DW 0x1234 */

/* Enumeration for different types of formatting options supported by this disassembler. */
/* Formatting Options Toggle Bits:
 * FORMAT_OPTION_ADDRESS_LABEL: creates address labels with the prefix set in the string addressLabelPrefix.
 * FORMAT_OPTION_ADDRESS: Prints the address of the instruction alongside the instruction (i.e. 1C inc R0 )
 * FORMAT_OPTION_DESTINATION_ADDRESS_COMMENT: Creates a comment after every relative branch/jump/call that
 *  includes the destination address of the instruction.
 */
enum AVR_Formatting_Options {
	FORMAT_OPTION_ADDRESS_LABEL = 1,
	FORMAT_OPTION_ADDRESS = 2,
	FORMAT_OPTION_DESTINATION_ADDRESS_COMMENT = 4,
	FORMAT_OPTION_DATA_HEX = 8,
	FORMAT_OPTION_DATA_BIN = 16,
	FORMAT_OPTION_DATA_DEC = 32,
};

/* See avr_disasm.c for more information on these variables. */
//extern int AVR_Long_Instruction;
//extern uint32_t AVR_Long_Address;

/* Structure to hold various formatting options supported
 * by this disassembler. */
struct _formattingOptions {
	/* Options with AVR_Formatting_Options bits set. */
	int options;
	/* The prefix for address labels,
	 * if they are enabled in options. */
	char addressLabelPrefix[8];
	/* Space field width for address, i.e. "001C"
 	 * has an address field width of 4. */
	int addressFieldWidth;
};
typedef struct _formattingOptions formattingOptions;


/* Prints a disassembled instruction, formatted with options set in the formattingOptions structure. */
static int printDisassembledInstruction(char *out, const disassembledInstruction dInstruction, formattingOptions fOptions);

#endif
