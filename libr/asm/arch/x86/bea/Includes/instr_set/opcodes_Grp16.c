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
void __stdcall G16_(PDISASM pMyDisasm)
{
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (REGOPCODE == 0) {
        MOD_RM(&(*pMyDisasm).Argument2);
        if (MOD_ != 0x3) {
            OpSize = 101;
            (*pMyDisasm).Instruction.Category = SSE_INSTRUCTION + CACHEABILITY_CONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "prefetchNTA ");
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else if (REGOPCODE == 1) {
        MOD_RM(&(*pMyDisasm).Argument2);
        if (MOD_ != 0x3) {
            OpSize = 101;
            (*pMyDisasm).Instruction.Category = SSE_INSTRUCTION + CACHEABILITY_CONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "prefetchT0 ");
        }
        else {
            FailDecode(pMyDisasm);
        }

    }
    else if (REGOPCODE == 2) {
        MOD_RM(&(*pMyDisasm).Argument2);
        if (MOD_ != 0x3) {
            OpSize = 101;
            (*pMyDisasm).Instruction.Category = SSE_INSTRUCTION + CACHEABILITY_CONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "prefetchT1 ");
        }
        else {
            FailDecode(pMyDisasm);
        }

    }
    else if (REGOPCODE == 3) {
        MOD_RM(&(*pMyDisasm).Argument2);
        if (MOD_ != 0x3) {
            OpSize = 101;
            (*pMyDisasm).Instruction.Category = SSE_INSTRUCTION + CACHEABILITY_CONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "prefetchT2 ");
        }
        else {
            FailDecode(pMyDisasm);
        }

    }

    else {
        FailDecode(pMyDisasm);
    }
    EIP_+= DECALAGE_EIP + 2;
}
