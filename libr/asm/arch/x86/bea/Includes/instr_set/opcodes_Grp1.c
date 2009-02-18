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
//      80h
// ====================================================================
void __stdcall G1_EbIb(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    EbIb(pMyDisasm);
    if (REGOPCODE == 0) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
        FillFlags(pMyDisasm, 5);
    }
    else if (REGOPCODE == 1) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
        FillFlags(pMyDisasm, 74);
    }
    else if (REGOPCODE == 2) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
        FillFlags(pMyDisasm, 4);
    }
    else if (REGOPCODE == 3) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
        FillFlags(pMyDisasm, 93);
    }
    else if (REGOPCODE == 4) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
        FillFlags(pMyDisasm, 6);
    }
    else if (REGOPCODE == 5) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
        FillFlags(pMyDisasm, 103);
    }

    else if (REGOPCODE == 6) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
        FillFlags(pMyDisasm, 113);
    }

    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
        FillFlags(pMyDisasm, 20);
        (*pMyDisasm).Argument1.AccessMode = READ;
    }
}

// ====================================================================
//      82h
// ====================================================================
void __stdcall G1_EbIb2(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        G1_EbIb(pMyDisasm);
    }
}

// ====================================================================
//      81h
// ====================================================================
void __stdcall G1_EvIv(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    EvIv(pMyDisasm);
    if (REGOPCODE == 0) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
        FillFlags(pMyDisasm, 5);
    }
    else if (REGOPCODE == 1) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
        FillFlags(pMyDisasm, 74);
    }
    else if (REGOPCODE == 2) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
        FillFlags(pMyDisasm, 4);
    }
    else if (REGOPCODE == 3) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
        FillFlags(pMyDisasm, 93);
    }
    else if (REGOPCODE == 4) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
        FillFlags(pMyDisasm, 6);
    }
    else if (REGOPCODE == 5) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
        FillFlags(pMyDisasm, 103);
    }

    else if (REGOPCODE == 6) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
        FillFlags(pMyDisasm, 113);
    }

    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
        FillFlags(pMyDisasm, 20);
        (*pMyDisasm).Argument1.AccessMode = READ;
    }
}

// ====================================================================
//      83h
// ====================================================================
void __stdcall G1_EvIb(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    EvIb(pMyDisasm);
    if (REGOPCODE == 0) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
        FillFlags(pMyDisasm, 5);
    }
    else if (REGOPCODE == 1) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
        FillFlags(pMyDisasm, 74);
    }
    else if (REGOPCODE == 2) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
        FillFlags(pMyDisasm, 4);
    }
    else if (REGOPCODE == 3) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
        FillFlags(pMyDisasm, 93);
    }
    else if (REGOPCODE == 4) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
        FillFlags(pMyDisasm, 6);
    }
    else if (REGOPCODE == 5) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
        FillFlags(pMyDisasm, 103);
    }

    else if (REGOPCODE == 6) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
        FillFlags(pMyDisasm, 113);
    }

    else if (REGOPCODE == 7) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
        FillFlags(pMyDisasm, 20);
        (*pMyDisasm).Argument1.AccessMode = READ;
    }
}
