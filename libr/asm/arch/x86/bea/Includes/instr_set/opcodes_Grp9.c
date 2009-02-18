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
//      0fc7h
// ====================================================================
void __stdcall G9_(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    OpSize = 104;
    MOD_RM(&(*pMyDisasm).Argument2);
    if (REGOPCODE == 1) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmpxchg8b ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm, 23);
        EIP_ += DECALAGE_EIP + 2;
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
        if (OperandSize == 16) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmclear ");
        }
        else if (PrefRepe == 1) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmxon ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmptrld ");
        }
        EIP_ += DECALAGE_EIP + 2;

    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmptrst ");
        EIP_ += DECALAGE_EIP + 2;
    }
    else {
        FailDecode(pMyDisasm);
    }

}
