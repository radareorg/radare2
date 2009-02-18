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
//      0f6h
// ====================================================================
void __stdcall G3_Eb(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (REGOPCODE == 0) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
        EbIb(pMyDisasm);
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm, 104);
    }
    else if (REGOPCODE == 1) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
        EbIb(pMyDisasm);
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm, 104);
    }
    else if (REGOPCODE == 2) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "not ");
        Eb(pMyDisasm);
        FillFlags(pMyDisasm, 73);
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "neg ");
        Eb(pMyDisasm);
        FillFlags(pMyDisasm, 71);
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mul ");
        OpSize = 101;
        OperandSize = 8;
        MOD_RM(&(*pMyDisasm).Argument2);
        OperandSize = 32;
        EIP_ += DECALAGE_EIP + 2;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm, 70);
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "imul ");
        OpSize = 101;
        OperandSize = 8;
        MOD_RM(&(*pMyDisasm).Argument2);
        OperandSize = 32;
        EIP_ += DECALAGE_EIP + 2;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm, 38);
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "div ");
        OpSize = 101;
        OperandSize = 8;
        MOD_RM(&(*pMyDisasm).Argument2);
        OperandSize = 32;
        EIP_ += DECALAGE_EIP + 2;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm, 31);
    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "idiv ");
        OpSize = 101;
        OperandSize = 8;
        MOD_RM(&(*pMyDisasm).Argument2);
        OperandSize = 32;
        EIP_ += DECALAGE_EIP + 2;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm, 37);
    }
}

// ====================================================================
//      0f7h
// ====================================================================
void __stdcall G3_Ev(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (REGOPCODE == 0) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
        EvIv(pMyDisasm);
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm, 104);
    }
    else if (REGOPCODE == 1) {
        FailDecode(pMyDisasm);
    }
    else if (REGOPCODE == 2) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "not ");
        Ev(pMyDisasm);
        FillFlags(pMyDisasm, 73);
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "neg ");
        Ev(pMyDisasm);
        FillFlags(pMyDisasm, 71);
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mul ");
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
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm, 70);
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "imul ");
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
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm, 38);
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "div ");
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
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm, 31);
    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "idiv ");
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
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm, 37);
    }
}
