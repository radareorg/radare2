//
// BeaEngine 3.0 - x86 & x86-64 disassembler library
//
// Copyright 2006-2009, BeatriX
// File coded by BeatriX
//
// This file is part of BeaEngine.
//
//    BeaEngine is free software: you can redistribute it and/or modify
//    it under the terms of the GNU Lesser General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    BeaEngine is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU Lesser General Public License for more details.
//
//    You should have received a copy of the GNU Lesser General Public License
//    along with BeaEngine.  If not, see <http://www.gnu.org/licenses/>.

#ifndef __UNIX__
#include <windows.h>
#endif
#include <stdio.h>
#include <string.h>
#include "BeaEngine.h"
#include "Includes/protos.h"
#include "Includes/internal_datas.h"
#include "Includes/instr_set/Data_opcode.h"
#include "Includes/instr_set/opcodes_A_M.c"
#include "Includes/instr_set/opcodes_N_Z.c"
#include "Includes/instr_set/opcodes_Grp1.c"
#include "Includes/instr_set/opcodes_Grp2.c"
#include "Includes/instr_set/opcodes_Grp3.c"
#include "Includes/instr_set/opcodes_Grp4.c"
#include "Includes/instr_set/opcodes_Grp5.c"
#include "Includes/instr_set/opcodes_Grp6.c"
#include "Includes/instr_set/opcodes_Grp7.c"
#include "Includes/instr_set/opcodes_Grp8.c"
#include "Includes/instr_set/opcodes_Grp9.c"
#include "Includes/instr_set/opcodes_Grp12.c"
#include "Includes/instr_set/opcodes_Grp13.c"
#include "Includes/instr_set/opcodes_Grp14.c"
#include "Includes/instr_set/opcodes_Grp15.c"
#include "Includes/instr_set/opcodes_Grp16.c"
#include "Includes/instr_set/opcodes_FPU.c"
#include "Includes/instr_set/opcodes_MMX.c"
#include "Includes/instr_set/opcodes_SSE.c"
#include "Includes/instr_set/opcodes_prefixes.c"
#include "Includes/Routines_ModRM.c"
#include "Includes/Routines_Disasm.c"

void BeaEngine(void){return;}
