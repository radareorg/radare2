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
 * errorcodesdisasm.h - All error codes that can take place during disassembler
 *  operation.
 *
 */

#ifndef ERRORCODES_DISASM_H
#define ERRORCODES_DISASM_H

/* Enumerations for AVR Disassembler Error Codes,
 * this also includes error codes for errors during
 * reading, formatting, and printing the disassembly. */
/* They are all defined here so there is no conflict
 * in interpreting error codes (in case different
 * parts of the program assigned the same return value
 * to different error codes. */
enum AVR_Disassembler_Error_Codes {
	ERROR_INVALID_ARGUMENTS = -1,
	ERROR_UNKNOWN_OPERAND = -3,
	ERROR_FILE_READING_ERROR = -4,
	ERROR_FILE_WRITING_ERROR = -5,
	ERROR_MEMORY_ALLOCATION_ERROR = -6,
	ERROR_IRRECOVERABLE = -7,	
};

#endif

