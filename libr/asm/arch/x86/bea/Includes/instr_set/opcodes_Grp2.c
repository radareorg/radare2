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
//      0c0h
// ====================================================================
void __stdcall G2_EbIb(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    EbIb(pMyDisasm);
    if (REGOPCODE == 0) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rol ");
        FillFlags(pMyDisasm, 88);
    }
    else if (REGOPCODE == 1) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ror ");
        FillFlags(pMyDisasm, 88);
    }
    else if (REGOPCODE == 2) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcl ");
        FillFlags(pMyDisasm, 81);
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcr ");
        FillFlags(pMyDisasm, 81);
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shl ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shr ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sal ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sar ");
        FillFlags(pMyDisasm, 92);
    }
}


// ====================================================================
//      0c1h
// ====================================================================
void __stdcall G2_EvIb(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    EvIb(pMyDisasm);
    if (REGOPCODE == 0) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rol ");
        FillFlags(pMyDisasm, 88);
    }
    else if (REGOPCODE == 1) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ror ");
        FillFlags(pMyDisasm, 88);
    }
    else if (REGOPCODE == 2) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcl ");
        FillFlags(pMyDisasm, 81);
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcr ");
        FillFlags(pMyDisasm, 81);
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shl ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shr ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sal ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sar ");
        FillFlags(pMyDisasm, 92);
    }
}

// ====================================================================
//      0d0h
// ====================================================================
void __stdcall G2_Eb1(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    OpSize = 1;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument1);
    OperandSize = 32;
    (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, "1 ");
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Instruction.Immediat = 1;
    if (REGOPCODE == 0) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rol ");
        FillFlags(pMyDisasm, 87);
    }
    else if (REGOPCODE == 1) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ror ");
        FillFlags(pMyDisasm, 87);
    }
    else if (REGOPCODE == 2) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcl ");
        FillFlags(pMyDisasm, 80);
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcr ");
        FillFlags(pMyDisasm, 80);
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shl ");
        FillFlags(pMyDisasm, 91);
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shr ");
        FillFlags(pMyDisasm, 91);
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sal ");
        FillFlags(pMyDisasm, 91);
    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sar ");
        FillFlags(pMyDisasm, 91);
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//      0d1h
// ====================================================================
void __stdcall G2_Ev1(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (OperandSize == 64) {
        OpSize = 4;
    }
    else if (OperandSize == 32) {
        OpSize = 3;
    }
    else {
        OpSize = 2;
    }
    MOD_RM(&(*pMyDisasm).Argument1);
    (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, "1 ");
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Instruction.Immediat = 1;
    if (REGOPCODE == 0) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rol ");
        FillFlags(pMyDisasm, 87);
    }
    else if (REGOPCODE == 1) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ror ");
        FillFlags(pMyDisasm, 87);
    }
    else if (REGOPCODE == 2) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcl ");
        FillFlags(pMyDisasm, 80);
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcr ");
        FillFlags(pMyDisasm, 80);
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shl ");
        FillFlags(pMyDisasm, 91);
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shr ");
        FillFlags(pMyDisasm, 91);
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sal ");
        FillFlags(pMyDisasm, 91);
    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sar ");
        FillFlags(pMyDisasm, 91);
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//      0d2h
// ====================================================================
void __stdcall G2_EbCL(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    OpSize = 1;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument1);
    OperandSize = 32;
    (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers8Bits[1]);
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument2.ArgSize = 8;
    if (REGOPCODE == 0) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rol ");
        FillFlags(pMyDisasm, 88);
    }
    else if (REGOPCODE == 1) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ror ");
        FillFlags(pMyDisasm, 88);
    }
    else if (REGOPCODE == 2) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcl ");
        FillFlags(pMyDisasm, 81);
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcr ");
        FillFlags(pMyDisasm, 81);
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shl ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shr ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sal ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sar ");
        FillFlags(pMyDisasm, 92);
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//      0d3h
// ====================================================================
void __stdcall G2_EvCL(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (OperandSize == 64) {
        OpSize = 4;
    }
    else if (OperandSize == 32) {
        OpSize = 3;
    }
    else {
        OpSize = 2;
    }
    MOD_RM(&(*pMyDisasm).Argument1);
    (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers8Bits[1]);
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument2.ArgSize = 8;
    if (REGOPCODE == 0) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rol ");
        FillFlags(pMyDisasm, 88);
    }
    else if (REGOPCODE == 1) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ror ");
        FillFlags(pMyDisasm, 88);
    }
    else if (REGOPCODE == 2) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcl ");
        FillFlags(pMyDisasm, 81);
    }
    else if (REGOPCODE == 3) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rcr ");
        FillFlags(pMyDisasm, 81);
    }
    else if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shl ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 5) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shr ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 6) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sal ");
        FillFlags(pMyDisasm, 92);
    }
    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sar ");
        FillFlags(pMyDisasm, 92);
    }
    EIP_ += DECALAGE_EIP + 2;
}
