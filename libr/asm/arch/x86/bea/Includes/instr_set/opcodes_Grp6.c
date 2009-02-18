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
//      0f00h
// ====================================================================
void __stdcall G6_(PDISASM pMyDisasm)
{
    long OperandSizeOld = 0;

    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    OperandSizeOld = OperandSize;
    OperandSize = 16;
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    MOD_ = ((*((BYTE*) (EIP_ + 1))) >> 6) & 0x3;

    if (REGOPCODE == 0) {
        if ((OperandSizeOld == 64) && (MOD_ == 0x3)) {
            OperandSize = OperandSizeOld;
        }
        else {
            OpSize = 2;
        }
        MOD_RM(&(*pMyDisasm).Argument1);
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sldt ");
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + MEMORY_MANAGEMENT_REG + REG1;
        (*pMyDisasm).Argument2.ArgSize = 16;
        OperandSize = OperandSizeOld;
        EIP_+= DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 1) {
        if ((OperandSizeOld == 64) && (MOD_ == 0x3)) {
            OperandSize = OperandSizeOld;
        }
        else {
            OpSize = 2;
        }
        MOD_RM(&(*pMyDisasm).Argument1);
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "str ");
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + MEMORY_MANAGEMENT_REG + REG3;
        (*pMyDisasm).Argument2.ArgSize = 16;
        OperandSize = OperandSizeOld;
        EIP_+= DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 2) {
        OpSize = 102;
        MOD_RM(&(*pMyDisasm).Argument2);
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lldt ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + MEMORY_MANAGEMENT_REG + REG1;
        (*pMyDisasm).Argument1.ArgSize = 16;
        OperandSize = OperandSizeOld;
        EIP_+= DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 3) {
        OpSize = 102;
        MOD_RM(&(*pMyDisasm).Argument2);
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ltr ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + MEMORY_MANAGEMENT_REG + REG3;
        (*pMyDisasm).Argument1.ArgSize = 16;
        OperandSize = OperandSizeOld;
        EIP_+= DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 4) {
        OpSize = 102;
        MOD_RM(&(*pMyDisasm).Argument1);
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "verr ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 16;
        OperandSize = OperandSizeOld;
        EIP_+= DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 5) {
        OpSize = 102;
        MOD_RM(&(*pMyDisasm).Argument1);
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "verw ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 16;
        OperandSize = OperandSizeOld;
        EIP_+= DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 6) {
        FailDecode(pMyDisasm);
        OperandSize = OperandSizeOld;
    }
    else {
        FailDecode(pMyDisasm);
        OperandSize = OperandSizeOld;
    }
}

