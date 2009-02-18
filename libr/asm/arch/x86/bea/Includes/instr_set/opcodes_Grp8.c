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
//      0fbah
// ====================================================================
void __stdcall G8_EvIb(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    EvIb(pMyDisasm);
    if (REGOPCODE == 4) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bt ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm, 11);
    }
    else if (REGOPCODE == 5) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bts ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm, 11);
    }
    else if (REGOPCODE == 6) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "btr ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm, 11);
    }
    else if (REGOPCODE == 7) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "btc ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm, 11);
    }
    else {
        FailDecode(pMyDisasm);
    }
}
