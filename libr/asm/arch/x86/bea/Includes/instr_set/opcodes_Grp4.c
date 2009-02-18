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
//      0feh
// ====================================================================
void __stdcall G4_Eb(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (REGOPCODE == 0) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        Eb(pMyDisasm);
        FillFlags(pMyDisasm, 40);
    }
    else if (REGOPCODE == 1) {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        Eb(pMyDisasm);
        FillFlags(pMyDisasm, 30);
    }
    else {
        FailDecode(pMyDisasm);
    }
}

