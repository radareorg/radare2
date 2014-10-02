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
 * avr_disasm.c - AVR instruction disassembly into disassembledInstruction structure.
 *
 */

#include <stdlib.h>
#include <stdint.h>
#include "avr_disasm.h"
#include "errorcodes.h"

/* AVR instructionSet is defined in avrinstructionset.c */
extern instructionInfo instructionSet[AVR_TOTAL_INSTRUCTIONS];

/* Ugly public variables that are shared across format_disasm.c and avr_disasm.c. As much as
 * I didn't want to do it (and instead would have liked to find a clean & clever solution that
 * doesn't expose anything between the two interfaces), for now this was the quickest (and cleanest?)
 * way to get this special case (32-bit opcode) taken care of. */
/* Variable to keep track of long instructions that have been found and are to be printed. */
int AVR_Long_Instruction = 0;
/* Variable to hold the address of the long instructions */
static uint32_t AVR_Long_Address;
/* A copy of the AVR long instruction, we need to keep this so we know information about the
 * instruction (mnemonic, operands) after we've read the next 16-bits from the program file. */
static disassembledInstruction longInstruction;

/* Disassembles/decodes operands back to their original form. */
static int disassembleOperands(disassembledInstruction *dInstruction);
/* Extracts certain bits of data from a mask, used to extract operands from their encoding in the opcode. */
static uint16_t extractDataFromMask(uint16_t data, uint16_t mask);
/* Look up an instruction by it's opcode in the instructionSet,
 * starting from index offset. Always returns a valid instruction
 * index because the last instruction in the instruction set database
 * is set to be a generic data word (.DW). */
static int lookupInstruction(uint16_t opcode, int offset);


/* Disassembles an assembled instruction, including its operands. */
int disassembleInstruction(disassembledInstruction *dInstruction, const assembledInstruction aInstruction) {
	int insidx, i;
	
	if (dInstruction == NULL)
		return ERROR_INVALID_ARGUMENTS;
	
	
	/* Look up the instruction */
	insidx = lookupInstruction(aInstruction.opcode, 0);
	if (insidx == AVR_TOTAL_INSTRUCTIONS) {
		// invalid instruction
		return 0;
	}

	/*** AVR SPECIFIC */
	/* If a long instruction was found in the last instruction disassembly,
	 * extract the rest of the address, and indicate that it is to be printed */
	if (AVR_Long_Instruction == AVR_LONG_INSTRUCTION_FOUND) {
		AVR_Long_Instruction = AVR_LONG_INSTRUCTION_PRINT;
		AVR_Long_Address |= aInstruction.opcode;
		/* We must multiply by two, because every instruction is 2 bytes,
		 * so in order to jump/call to the right address (which increments by
		 * two for every instruction), we must multiply this distance by two. */
		//printf ("ii=%d\n", insidx);
                if(!strcmp(longInstruction.instruction->mnemonic,"call")||
                   !strcmp(longInstruction.instruction->mnemonic,"jmp"))
	        {
			AVR_Long_Address *= 2;
                }
		*dInstruction = longInstruction;
		return 0;
	/* If a long instruction was printed in the last instruction disassembly,
	 * reset the AVR_Call_Instruction variable back to zero. */
	} else if (AVR_Long_Instruction == AVR_LONG_INSTRUCTION_PRINT) {
		AVR_Long_Instruction = 0;
	}

	/* Copy over the address, and reference to the instruction, set
	 * the equivilant-encoded but different instruction to NULL for now. */
	dInstruction->address = aInstruction.address;
	dInstruction->instruction = &instructionSet[insidx];
	dInstruction->alternateInstruction = NULL;
	
	/* Copy out each operand, extracting the operand data from the original
	 * opcode using the operand mask. */
	for (i = 0; i < instructionSet[insidx].numOperands; i++) {
		dInstruction->operands[i] = extractDataFromMask(aInstruction.opcode, dInstruction->instruction->operandMasks[i]);
		/*** AVR SPECIFIC */
		/* If this is an instruction with a long absolute operand, indicate that a long instruction has been found,
		 * and extract the first part of the long address. */
		if (dInstruction->instruction->operandTypes[i] == OPERAND_LONG_ABSOLUTE_ADDRESS) {
			AVR_Long_Instruction = AVR_LONG_INSTRUCTION_FOUND;
			AVR_Long_Address = dInstruction->operands[i] << 16;
			longInstruction = *dInstruction;
		}
	}
	
	/* Disassemble operands */
	if (disassembleOperands(dInstruction) < 0)
		return ERROR_INVALID_ARGUMENTS; /* Only possible error for disassembleOperands() */

	if (AVR_Long_Instruction == AVR_LONG_INSTRUCTION_FOUND) {
		/* If we found a long instruction (32-bit one),
		 * Copy this instruction over to our special longInstruction variable, that
		 * will exist even after we move onto the next 16-bits */
		longInstruction = *dInstruction;
	}

	return 0;
}

/* Extracts certain bits of data from a mask, used to extract operands from their encoding in the opcode. */
static uint16_t extractDataFromMask(uint16_t data, uint16_t mask) {
	int i, j;
	uint16_t result = 0;
	
	/* i counts through every bit of the data,
	 * j counts through every bit of the data we're copying out. */
	for (i = 0, j = 0; i < 16; i++) {
		/* If the mask has a bit in this position */
		if (mask & (1<<i)) {
			/* If there is a data bit with this mask bit,
			 * then toggle that bit in the extracted data (result).
			 * Notice that it uses its own bit counter j. */
			if (((mask & (1<<i)) & data) != 0)
				result |= (1<<j);
			/* Increment the extracted data bit count. */
			j++;
		}
	}
	
	return result;
}

/* Look up an instruction by it's opcode in the instructionSet,
 * starting from index offset. Always returns a valid instruction
 * index because the last instruction in the instruction set database
 * is set to be a generic data word (.DW). */
static int lookupInstruction(uint16_t opcode, int offset) {
	uint16_t opcodeSearch, operandTemp;
	int insidx, ghostRegisterConfirmed, i, j;
	
	for (insidx = offset; insidx < AVR_TOTAL_INSTRUCTIONS; insidx++) {
		opcodeSearch = opcode;
		/* If we have a ghost register operand (OPERAND_REGISTER_GHOST),
		 * we need to confirm that all of the other register operands are the same */
		ghostRegisterConfirmed = 1;
		/* We want to mask out all of the operands. We don't count up to
		 * instructionSet[insidx].numOperands because some instructions,
		 * such as clr R16, are actually encoded with two operands (so as eor R16,R16),
		 * and we want to screen out both operands to get the most simplest form of 
		 * the instruction. */ 
		for (i = 0; i < AVR_MAX_NUM_OPERANDS; i++) {
			if (instructionSet[insidx].operandTypes[i] == OPERAND_REGISTER_GHOST) {
				/* Grab the first operand */
				operandTemp = extractDataFromMask(opcode, instructionSet[insidx].operandMasks[0]);
				/* Compare the remaining operands to the first */
				for (j = 1; j < AVR_MAX_NUM_OPERANDS; j++) {
					if (extractDataFromMask(opcode, instructionSet[insidx].operandMasks[i]) !=
							operandTemp)
						ghostRegisterConfirmed = 0;
				}
			} 
			opcodeSearch &= ~(instructionSet[insidx].operandMasks[i]);
		}
		/* If we encountered a ghost register and were unable confirm that
		 * all register operands were equal (in this case ghostRegisterConfirmed
		 * would have changed), then move the match-search onto the next instruction. */
		if (ghostRegisterConfirmed == 0)
			continue;

		if (opcodeSearch == instructionSet[insidx].opcodeMask) 
			break;
	}
	/* It's impossible not to find an instruction, because the last instruction ".DW",
	 * specifies a word of data at the addresses, instead of an instruction. 
	 * Its operand 2 mask, 0x0000, will set opcode search to 0x0000, and this will always
	 * match with the opcodeMask of 0x0000. */
	return insidx;
}

/* Disassembles/decodes operands back to their original form. */
static int disassembleOperands(disassembledInstruction *dInstruction) {
	int i;
	
	/* This should never happen */
	if (dInstruction == NULL)
		return ERROR_INVALID_ARGUMENTS;
	if (dInstruction->instruction == NULL)
		return ERROR_INVALID_ARGUMENTS;
	
	/* For each operand, decode its original value. */
	for (i = 0; i < dInstruction->instruction->numOperands; i++) {
		switch (dInstruction->instruction->operandTypes[i]) {
		case OPERAND_BRANCH_ADDRESS:
			/* K is 7 bits, so maximum value it can store is 127 decimal.
			 * However, a branch's operand, -64 <= k <= +63,
			 * can go 64 back (-64) or 63 forward (+63). Range: 64+63 = 127.
			 * In order to preserve the negative, the branch distance
			 * is stored in two's complement form.*/
			/* First we multiply by two, because every instruction is 2 bytes,
			 * so in order to branch to the right address (which increments by
			 * two for every instruction), we must multiply this distance
			 * by two. */
			/* Next, we check for the signed bit (MSB), which would indicate a
			 * negative. If the number is signed, we would reverse the two's
			 * complement (invert bits, add 1, and then only use the 7 bits that 
			 * matter), otherwise, the number represents a positive distance and
			 * no bit manipulation is necessary. */
			dInstruction->operands[i] <<= 1;
			if (dInstruction->operands[i] & 0x80) {
				/* We can't just print out the signed operand because the type's capacity
				 * is 16 bits, and the operand data's signedness only starts at 0x80.
				 * Therefore we must convert to the positive value and then make the entire
				 * short negative. */
				dInstruction->operands[i] = (~dInstruction->operands[i]+1)&0x7F;
				dInstruction->operands[i] = -dInstruction->operands[i]+2;
			} else {
				dInstruction->operands[i] += 2;
			}
			break;
		case OPERAND_RELATIVE_ADDRESS:
			/* k is 12 bits, so maximum value it can store is 4095 decimal.
			 * However, a relative jump/call's operand, -2K <= k < +2K,
			 * can go 2048 back (-2048) or 2047 forward (+2047). Range: 2048+2047 = 4095.
			 * In order to preserve the negative, the jump/call distance
			 * is stored in two's complement form.*/
			/* First we multiply by two, because every instruction is 2 bytes,
			 * so in order to jump/call to the right address (which increments by
			 * two for every instruction), we must multiply this distance
			 * by two. */
			/* Next, we check for the signed bit (MSB), which would indicate a
			 * negative. If the number is signed, we would reverse the two's
			 * complement (invert bits, add 1, and then only use the 12 bits that 
			 * matter), otherwise, the number represents a positive distance and
			 * no bit manipulation is necessary. */
			dInstruction->operands[i] <<= 1;
			if (dInstruction->operands[i] & 0x1000) {
				/* We can't just print out the signed operand because the type's capacity
				 * is 16 bits, and the operand data's signedness only starts at 0x1000.
				 * Therefore we must convert to the positive value and then make the entire
				 * short negative. */
				dInstruction->operands[i] = (~dInstruction->operands[i]+1)&0xFFF;
				dInstruction->operands[i] = -dInstruction->operands[i]+2;
			} else {
				dInstruction->operands[i] += 2;
			}
			break;
		case OPERAND_REGISTER_STARTR16:
			dInstruction->operands[i] = 16 + dInstruction->operands[i] ;
			break;
		case OPERAND_REGISTER_EVEN_PAIR:
			dInstruction->operands[i] = dInstruction->operands[i] * 2;
			break;
		case OPERAND_REGISTER_EVEN_PAIR_STARTR24:
			dInstruction->operands[i] = 24 + (dInstruction->operands[i] * 2);
			break;
		case OPERAND_COMPLEMENTED_DATA:
			dInstruction->operands[i] = ~dInstruction->operands[i] & 0xFF;
			break;
		default:
			break;
		}
	}
	return 0;
}

