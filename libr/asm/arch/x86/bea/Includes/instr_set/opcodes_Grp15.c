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

// ====================================================================
//
// ====================================================================
void __stdcall G15_(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (REGOPCODE == 0) {
        MOD_RM(&(*pMyDisasm).Argument1);
        if (MOD_ != 0x3) {
            OpSize = 5;
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + STATE_MANAGEMENT;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fxsave ");
            (*pMyDisasm).Argument1.ArgSize = 512;
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + MMX_REG + SSE_REG;
            (*pMyDisasm).Argument2.ArgSize = 512;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else if (REGOPCODE == 1) {
        MOD_RM(&(*pMyDisasm).Argument2);
        if (MOD_ != 0x3) {
            OpSize = 105;
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + STATE_MANAGEMENT;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fxrstor ");
            (*pMyDisasm).Argument2.ArgSize = 512;
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + MMX_REG + SSE_REG;
            (*pMyDisasm).Argument1.ArgSize = 512;
        }
        else {
            FailDecode(pMyDisasm);
        }

    }
    else if (REGOPCODE == 2) {
        MOD_RM(&(*pMyDisasm).Argument2);
        if (MOD_ != 0x3) {
            OpSize = 103;
            (*pMyDisasm).Instruction.Category = SSE_INSTRUCTION + STATE_MANAGEMENT;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ldmxcsr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG1;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            FailDecode(pMyDisasm);
        }

    }
    else if (REGOPCODE == 3) {
        MOD_RM(&(*pMyDisasm).Argument1);
        if (MOD_ != 0x3) {
            OpSize = 3;
            (*pMyDisasm).Instruction.Category = SSE_INSTRUCTION + STATE_MANAGEMENT;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "stmxcsr ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SPECIAL_REG + REG1;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            FailDecode(pMyDisasm);
        }

    }

    else if (REGOPCODE == 4) {
        MOD_RM(&(*pMyDisasm).Argument1);
        if (MOD_ != 0x3) {
            OpSize = 5;
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + STATE_MANAGEMENT;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xsave ");
            (*pMyDisasm).Argument1.ArgSize = 512;
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + MMX_REG + SSE_REG;
            (*pMyDisasm).Argument2.ArgSize = 512;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }

    else if (REGOPCODE == 5) {
        MOD_ = ((*((BYTE*) (EIP_ + 1))) >> 6) & 0x3;
        if (MOD_ == 0x3) {
            (*pMyDisasm).Instruction.Category = SSE2_INSTRUCTION + CACHEABILITY_CONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lfence ");
        }
        else {
            OpSize = 105;
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + STATE_MANAGEMENT;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xrstor ");
            (*pMyDisasm).Argument2.ArgSize = 512;
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + MMX_REG + SSE_REG;
            (*pMyDisasm).Argument1.ArgSize = 512;
        }

    }
    else if (REGOPCODE == 6) {
        MOD_ = ((*((BYTE*) (EIP_ + 1))) >> 6) & 0x3;
        if (MOD_ == 0x3) {
            (*pMyDisasm).Instruction.Category = SSE2_INSTRUCTION + CACHEABILITY_CONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mfence ");
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else if (REGOPCODE == 7) {
        MOD_ = ((*((BYTE*) (EIP_ + 1))) >> 6) & 0x3;
        if (MOD_ == 0x3) {
            (*pMyDisasm).Instruction.Category = SSE2_INSTRUCTION + CACHEABILITY_CONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sfence ");
        }
        else {
            OperandSize = 8;
            MOD_RM(&(*pMyDisasm).Argument2);
            OperandSize = 32;
            OpSize = 101;
            (*pMyDisasm).Instruction.Category = SSE2_INSTRUCTION + CACHEABILITY_CONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "clflush ");
        }

    }

    else {
        FailDecode(pMyDisasm);
    }
    EIP_+= DECALAGE_EIP + 2;
}
