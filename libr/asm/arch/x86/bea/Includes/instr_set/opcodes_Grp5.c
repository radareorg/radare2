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
//      0ffh
// ====================================================================
void __stdcall G5_Ev(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (REGOPCODE == 0) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        Ev(pMyDisasm);
        FillFlags(pMyDisasm, 40);
    }
    else if (REGOPCODE == 1) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        Ev(pMyDisasm);
        FillFlags(pMyDisasm, 30);
    }
    else if (REGOPCODE == 2) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
        (*pMyDisasm).Instruction.BranchType = CallType;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "call ");
        if (Architecture == 64) {
            OperandSize = 64;
        }
        if (OperandSize == 64) {
            OpSize = 104;
        }
        else if (OperandSize == 32) {
            OpSize = 103;
        }
        else {
            OpSize = 102;
        }
        MOD_RM(&(*pMyDisasm).Argument2);
        EIP_ += DECALAGE_EIP + 2;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
        (*pMyDisasm).Instruction.BranchType = CallType;
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lcall ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "call far ");
        }
        OpSize = 107;
        MOD_RM(&(*pMyDisasm).Argument2);
        EIP_ += DECALAGE_EIP + 2;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
        (*pMyDisasm).Instruction.BranchType = JmpType;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jmp ");
        if (Architecture == 64) {
            OperandSize = 64;
        }
        if (OperandSize == 64) {
            OpSize = 104;
        }
        else if (OperandSize == 32) {
            OpSize = 103;
        }
        else {
            OpSize = 102;
        }
        MOD_RM(&(*pMyDisasm).Argument2);
        EIP_ += DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
        (*pMyDisasm).Instruction.BranchType = CallType;
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ljmp ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jmp far ");
        }
        OpSize = 107;
        MOD_RM(&(*pMyDisasm).Argument2);
        EIP_ += DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
        if (Architecture == 64) {
            OperandSize = 64;
        }
        if (OperandSize == 64) {
            OpSize = 104;
        }
        else if (OperandSize == 32) {
            OpSize = 103;
        }
        else {
            OpSize = 102;
        }
        MOD_RM(&(*pMyDisasm).Argument2);
        EIP_ += DECALAGE_EIP + 2;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
    }
    else {
        FailDecode(pMyDisasm);
    }
}

