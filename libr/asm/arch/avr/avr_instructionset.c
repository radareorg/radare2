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
 * avrinstructionset.c - AVR instruction set data structure stored in an
 *  array of instruction info structures, as defined in avrdisasm.h.
 *
 */

#include "avr_disasm.h"

/* Sorted by number of operands so disassembler can find the most
 * simplifed form of an instruction first.
 * i.e. clr R16 instead of eor R16, R16 */
/* I decided to have the operand masks and types here in the
 * main instruction set data structure of the disassembler for clean
 * opcode recognition and operand extraction. It's much more straight
 * forward to work with numbers (duh) then manipulating ugly operand 
 * strings such as "000011rdddddrrrr" for the add instruction. */
/* This was my first disassembler, and my program ended evolving with this
 * data structure. Turns out it makes code quite clear, and it generalizes the
 * entire disassembly process, but development probably took about 2x longer
 * instead of hard coding the disassembly for different types of operands. */
/* But this disassembler model can be applied to virtually any 16-bit
 * or less opcode architecture, making it very flexible in nature--I don't
 * have to rewrite all of the operand disassembly code for interpreting 
 * different r, d, K, k, s, etc. characters in the opcode, which all stand 
 * for a different operand type, because they are clearly written out 
 * in the instruction set data structure.
 */ 
instructionInfo instructionSet[AVR_TOTAL_INSTRUCTIONS] = {
	{"break", 0x9598, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"clc", 0x9488, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"clh", 0x94d8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"cli", 0x94f8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"cln", 0x94a8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"cls", 0x94c8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"clt", 0x94e8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"clv", 0x94b8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"clz", 0x9498, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"eicall", 0x9519, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"eijmp", 0x9419, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"elpm", 0x95d8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"icall", 0x9509, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"ijmp", 0x9409, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"lpm", 0x95c8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"nop", 0x0000, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"ret", 0x9508, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"reti", 0x9518, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"sec", 0x9408, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"seh", 0x9458, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"sei", 0x9478, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"sen", 0x9428, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"ses", 0x9448, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"set", 0x9468, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"sev", 0x9438, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"sez", 0x9418, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"sleep", 0x9588, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"spm", 0x95e8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"spm", 0x95f8, 1, {0x0000, 0x0000}, {OPERAND_ZP, OPERAND_NONE}},
	{"wdr", 0x95a8, 0, {0x0000, 0x0000}, {OPERAND_NONE, OPERAND_NONE}},
	{"des", 0x940b, 1, {0x00f0, 0x0000}, {OPERAND_DES_ROUND, OPERAND_NONE}},
	{"asr", 0x9405, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"bclr", 0x9488, 1, {0x0070, 0x0000}, {OPERAND_BIT, OPERAND_NONE}},
	{"brcc", 0xf400, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brcs", 0xf000, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"breq", 0xf001, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brge", 0xf404, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brhc", 0xf405, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brhs", 0xf005, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brid", 0xf407, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brie", 0xf007, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brlo", 0xf000, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brlt", 0xf004, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brmi", 0xf002, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brne", 0xf401, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brpl", 0xf402, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brsh", 0xf400, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brtc", 0xf406, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brts", 0xf006, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brvc", 0xf403, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"brvs", 0xf003, 1, {0x03f8, 0x0000}, {OPERAND_BRANCH_ADDRESS, OPERAND_NONE}},
	{"bset", 0x9408, 1, {0x0070, 0x0000}, {OPERAND_BIT, OPERAND_NONE}},
	{"call", 0x940e, 1, {0x01f1, 0x0000}, {OPERAND_LONG_ABSOLUTE_ADDRESS, OPERAND_NONE}},
	{"clr", 0x2400, 1, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER_GHOST}}, 
	{"com", 0x9400, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"dec", 0x940a, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"inc", 0x9403, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"jmp", 0x940c, 1, {0x01f1, 0x0000}, {OPERAND_LONG_ABSOLUTE_ADDRESS, OPERAND_NONE}},
	{"lpm", 0x9004, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_Z}},
	{"lpm", 0x9005, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_ZP}},
	{"lsl", 0x0c00, 1, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER_GHOST}},
	{"lsr", 0x9406, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"neg", 0x9401, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"pop", 0x900f, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"push", 0x920f, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"rcall", 0xd000, 1, {0x0fff, 0x0000}, {OPERAND_RELATIVE_ADDRESS, OPERAND_NONE}},
	{"rjmp", 0xc000, 1, {0x0fff, 0x0000}, {OPERAND_RELATIVE_ADDRESS, OPERAND_NONE}},
	{"rol", 0x1c00, 1, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER_GHOST}},
	{"ror", 0x9407, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"ser", 0xef0f, 1, {0x00f0, 0x0000}, {OPERAND_REGISTER_STARTR16, OPERAND_NONE}},
	{"swap", 0x9402, 1, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_NONE}},
	{"tst", 0x2000, 1, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER_GHOST}},
	
	{"adc", 0x1c00, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"add", 0x0c00, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"adiw", 0x9600, 2, {0x0030, 0x00cf}, {OPERAND_REGISTER_EVEN_PAIR_STARTR24, OPERAND_DATA}},
	{"and", 0x2000, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"andi", 0x7000, 2, {0x00f0, 0x0f0f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{"bld", 0xf800, 2, {0x01f0, 0x0007}, {OPERAND_REGISTER, OPERAND_BIT}},
	{"brbc", 0xf400, 2, {0x0007, 0x03f8}, {OPERAND_BIT, OPERAND_BRANCH_ADDRESS}},
	{"brbs", 0xf000, 2, {0x0007, 0x03f8}, {OPERAND_BIT, OPERAND_BRANCH_ADDRESS}},
	{"bst", 0xfa00, 2, {0x01f0, 0x0007}, {OPERAND_REGISTER, OPERAND_BIT}},
	{"cbi", 0x9800, 2, {0x00f8, 0x0007}, {OPERAND_IO_REGISTER, OPERAND_BIT}},
	{"cbr", 0x7000, 2, {0x00f0, 0x0f0f}, {OPERAND_REGISTER_STARTR16, OPERAND_COMPLEMENTED_DATA}},
	{"cp", 0x1400, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"cpc", 0x0400, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"cpi", 0x3000, 2, {0x00f0, 0x0f0f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{"cpse", 0x1000, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"elpm", 0x9006, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_Z}},
	{"elpm", 0x9007, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_ZP}},
	{"eor", 0x2400, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"fmul", 0x0308, 2, {0x0070, 0x0007}, {OPERAND_REGISTER_STARTR16, OPERAND_REGISTER_STARTR16}},
	{"fmuls", 0x0380, 2, {0x0070, 0x0007}, {OPERAND_REGISTER_STARTR16, OPERAND_REGISTER_STARTR16}},
	{"fmulsu", 0x0388, 2, {0x0070, 0x0007}, {OPERAND_REGISTER_STARTR16, OPERAND_REGISTER_STARTR16}},
	{"in", 0xb000, 2, {0x01f0, 0x060f}, {OPERAND_REGISTER, OPERAND_DATA}},
	{"ld", 0x900c, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_X}},
	{"ld", 0x900d, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_XP}},
	{"ld", 0x900e, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_MX}},
	{"ld", 0x8008, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_Y}},
	{"ld", 0x9009, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_YP}},
	{"ld", 0x900a, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_MY}},
	{"ld", 0x8000, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_Z}},
	{"ld", 0x9001, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_ZP}},
	{"ld", 0x9002, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_MZ}},
	{"ldd", 0x8008, 2, {0x01f0, 0x2c07}, {OPERAND_REGISTER, OPERAND_YPQ}},
	{"ldd", 0x8000, 2, {0x01f0, 0x2c07}, {OPERAND_REGISTER, OPERAND_ZPQ}},
	{"ldi", 0xe000, 2, {0x00f0, 0x0f0f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{"lds", 0x9000, 2, {0x01f0, 0x0000}, {OPERAND_REGISTER, OPERAND_LONG_ABSOLUTE_ADDRESS}},
	{"lds", 0xA000, 2, {0x00f0, 0x070f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{"mov", 0x2c00, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"movw", 0x0100, 2, {0x00f0, 0x000f}, {OPERAND_REGISTER_EVEN_PAIR, OPERAND_REGISTER_EVEN_PAIR}},
	{"mul", 0x9c00, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"muls", 0x0200, 2, {0x00f0, 0x000f}, {OPERAND_REGISTER_STARTR16, OPERAND_REGISTER_STARTR16}},
	{"mulsu", 0x0300, 2, {0x0070, 0x0007}, {OPERAND_REGISTER_STARTR16, OPERAND_REGISTER_STARTR16}},
	{"or", 0x2800, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"ori", 0x6000, 2, {0x00f0, 0x0f0f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{"out", 0xb800, 2, {0x060f, 0x01f0}, {OPERAND_IO_REGISTER, OPERAND_REGISTER}},
	{"sbc", 0x0800, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"sbci", 0x4000, 2, {0x00f0, 0x0f0f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{"sbi", 0x9a00, 2, {0x00f8, 0x0007}, {OPERAND_IO_REGISTER, OPERAND_BIT}},
	{"sbic", 0x9900, 2, {0x00f8, 0x0007}, {OPERAND_IO_REGISTER, OPERAND_BIT}},
	{"sbis", 0x9b00, 2, {0x00f8, 0x0007}, {OPERAND_IO_REGISTER, OPERAND_BIT}},
	{"sbiw", 0x9700, 2, {0x0030, 0x00cf}, {OPERAND_REGISTER_EVEN_PAIR_STARTR24, OPERAND_DATA}},
	{"sbr", 0x6000, 2, {0x00f0, 0x0f0f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{"sbrc", 0xfc00, 2, {0x01f0, 0x0007}, {OPERAND_REGISTER, OPERAND_BIT}},
	{"sbrs", 0xfe00, 2, {0x01f0, 0x0007}, {OPERAND_REGISTER, OPERAND_BIT}},
	{"st", 0x920c, 2, {0x0000, 0x01f0}, {OPERAND_X, OPERAND_REGISTER}},
	{"st", 0x920d, 2, {0x0000, 0x01f0}, {OPERAND_XP, OPERAND_REGISTER}},
	{"st", 0x920e, 2, {0x0000, 0x01f0}, {OPERAND_MX, OPERAND_REGISTER}},
	{"st", 0x8208, 2, {0x0000, 0x01f0}, {OPERAND_Y, OPERAND_REGISTER}},
	{"st", 0x9209, 2, {0x0000, 0x01f0}, {OPERAND_YP, OPERAND_REGISTER}},
	{"st", 0x920a, 2, {0x0000, 0x01f0}, {OPERAND_MY, OPERAND_REGISTER}},
	{"st", 0x8200, 2, {0x0000, 0x01f0}, {OPERAND_Z, OPERAND_REGISTER}},
	{"st", 0x9201, 2, {0x0000, 0x01f0}, {OPERAND_ZP, OPERAND_REGISTER}},
	{"st", 0x9202, 2, {0x0000, 0x01f0}, {OPERAND_MZ, OPERAND_REGISTER}},
	{"std", 0x8208, 2, {0x2c07, 0x01f0}, {OPERAND_YPQ, OPERAND_REGISTER}},
	{"std", 0x8200, 2, {0x2c07, 0x01f0}, {OPERAND_ZPQ, OPERAND_REGISTER}},
	{"sts", 0x9200, 2, {0x0000, 0x01f0}, {OPERAND_LONG_ABSOLUTE_ADDRESS, OPERAND_REGISTER}},
	{"sts", 0xA800, 2, {0x00f0, 0x070f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{"sub", 0x1800, 2, {0x01f0, 0x020f}, {OPERAND_REGISTER, OPERAND_REGISTER}},
	{"subi", 0x5000, 2, {0x00f0, 0x0f0f}, {OPERAND_REGISTER_STARTR16, OPERAND_DATA}},
	{".word", 0x0000, 1, {0xFFFF, 0x0000}, {OPERAND_WORD_DATA, OPERAND_NONE}},
};
