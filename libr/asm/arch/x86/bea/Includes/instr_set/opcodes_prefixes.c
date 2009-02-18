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
//      Legacy Prefix F0h - Group 1
// ====================================================================
void __stdcall PrefLock(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.LockPrefix = InvalidPrefix;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lock ");
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
    OperandSize = 32;
}

// ====================================================================
//      Legacy Prefix F2h - Group 1
// ====================================================================
void __stdcall PrefREPNE(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    if (PrefRepne == 0) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "repne ");
    }
    (*pMyDisasm).Prefix.RepnePrefix = SuperfluousPrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    PrefRepne = 1;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
    PrefRepne = 0;
}

// ====================================================================
//      Legacy Prefix F3h - Group 1
// ====================================================================
void __stdcall PrefREPE(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    if (PrefRepe == 0) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "repe ");
    }
    (*pMyDisasm).Prefix.RepPrefix = SuperfluousPrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    PrefRepe = 1;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
    PrefRepe = 0;
}

// ====================================================================
//      Escape prefix 0Fh
// ====================================================================
void __stdcall PrefSEGCS(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.DSPrefix = InUsePrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
}

// ====================================================================
//      Legacy Prefix 3Eh - Group 2
// ====================================================================
void __stdcall PrefSEGDS(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.FSPrefix = InUsePrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
}

// ====================================================================
//      Legacy Prefix 26h - Group 2
// ====================================================================
void __stdcall PrefSEGES(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.CSPrefix = InUsePrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
}

// ====================================================================
//      Legacy Prefix 64h - Group 2
// ====================================================================
void __stdcall PrefSEGFS(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.FSPrefix = InUsePrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    SEGMENTFS = 1;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
}

// ====================================================================
//      Legacy Prefix 65h - Group 2
// ====================================================================
void __stdcall PrefSEGGS(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.GSPrefix = InUsePrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
}


// ====================================================================
//      Legacy Prefix 36h - Group 2
// ====================================================================
void __stdcall PrefSEGSS(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.SSPrefix = InUsePrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
}

// ====================================================================
//      Legacy Prefix 66h - Group 3
// ====================================================================
void __stdcall PrefOpSize(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.OperandSize = InUsePrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    OperandSize = 16;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
    OperandSize = 32;
}

// ====================================================================
//      Legacy Prefix 67h - Group 4
// ====================================================================
void __stdcall PrefAdSize(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    (*pMyDisasm).Prefix.AddressSize = InUsePrefix;
    EIP_++;
    (*pMyDisasm).Prefix.Number++;
    NB_PREFIX++;
    AddressSize = AddressSize >> 1;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
    AddressSize = AddressSize << 1;
}

// ====================================================================
//      Escape Prefix 0Fh - two bytes opcodes
// ====================================================================
void __stdcall Esc_2byte(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    EIP_++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_) + 0x0F00;
    (void) opcode_map2[*((BYTE*) EIP_)](pMyDisasm);
}

// ====================================================================
//      Escape Prefix 0F38h - three bytes opcodes
// ====================================================================
void __stdcall Esc_tableA4(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    EIP_++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_) + 0x0F3800;
    (void) opcode_map3[*((BYTE*) EIP_)](pMyDisasm);
}
// ====================================================================
//      Escape Prefix 0F3Ah - three bytes opcodes
// ====================================================================
void __stdcall Esc_tableA5(PDISASM pMyDisasm)
{
    if (!Security(0)) return;
    EIP_++;
    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_) + 0x0F3A00;
    (void) opcode_map4[*((BYTE*) EIP_)](pMyDisasm);
}
