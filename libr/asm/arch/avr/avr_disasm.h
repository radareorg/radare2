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
 * avr_disasm.h - Header file for AVR instruction disassembly into 
 *  disassembledInstruction structure.
 *
 */

#ifndef AVR_DISASM_H
#define AVR_DISASM_H

#include <stdint.h>
#include "avr_instructionset.h"

/* OPERAND_REGISTER_GHOST:
 * Some instructions, like clr, only have one instruction when written in assembly,
 * such as clr R16. However, when encoded, the instruction becomes eor R16, R16. So although
 * OPERAND_REGISTER_GHOST has an operand mask, the actual register value is never displayed
 * in disassembly. */

/* These defines go along with AVR_Long_Instruction, and help the program keep track of when
 * a long instruction has been encountered and when it is to be printed. See avrdisam.c for more
 * information on these variables. */
#define AVR_LONG_INSTRUCTION_FOUND	1
#define AVR_LONG_INSTRUCTION_PRINT	2


/* The raw assembed instruction as extracted from the program file. */
struct _assembledInstruction {
	uint32_t address;
	uint16_t opcode;
};
typedef struct _assembledInstruction assembledInstruction;

/* The disassembled/decoded instruction. */
struct _disassembledInstruction {
	uint32_t address;
	/* A convenient pointer to the instructionSet, so we can refer 
	 * the general details of the instruction stored in there. */
	instructionInfo *instruction;
	/* Notice that operands can be signed!
	 * This is in order to support the decoding of negative
	 * relative branch/jump/call distances. */
	int32_t operands[AVR_MAX_NUM_OPERANDS];
	/* A pointer to an alternate disassembledInstruction,
	 * so we can find all instructions with the same encoding. */
	struct _disassembledInstruction *alternateInstruction;
};
typedef struct _disassembledInstruction disassembledInstruction;

/* The disassembler/decoder instruction context */
struct _avrDisassembleContext {
	/* Variable to keep track of long instructions that have been found and are to be printed. */
	int status;
	/* Variable to hold the address of the long instructions */
	uint32_t longAddress;
	/* A copy of the AVR long instruction, we need to keep this so we know information about the
	 * instruction (mnemonic, operands) after we've read the next 16-bits from the program file. */
	disassembledInstruction longInstruction;
};
typedef struct _avrDisassembleContext avrDisassembleContext;

/* Disassembles an assembled instruction, including its operands. */
int disassembleInstruction(avrDisassembleContext *context, disassembledInstruction *dInstruction, const assembledInstruction aInstruction);

#endif

