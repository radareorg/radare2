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
//      90h
// ====================================================================
void __stdcall nop_(PDISASM pMyDisasm)
{
    if (PrefRepe == 1) {
        (*pMyDisasm).Instruction.Category = SSE2_INSTRUCTION + CACHEABILITY_CONTROL;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pause ");
        EIP_++;
    }
    else {
        if (REX.B_ == 1) {
            if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
                (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
            }
            (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 64;
            (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0+8];
            (*pMyDisasm).Argument2.ArgSize = 64;
            EIP_++;
        }
        else {
            (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + MISCELLANEOUS_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "nop ");
            EIP_++;
        }
    }
}

// =======================================
//
// =======================================
void __stdcall nop_Ev(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + MISCELLANEOUS_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "nop ");
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

// =======================================
//
// =======================================
void __stdcall hint_nop(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + MISCELLANEOUS_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "hint_nop ");
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

// =======================================
//      08h
// =======================================
void __stdcall or_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,74);
}

// =======================================
//      09h
// =======================================
void __stdcall or_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,74);
}

// =======================================
//      0ah
// =======================================
void __stdcall or_GbEb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
    GbEb(pMyDisasm);
    FillFlags(pMyDisasm,74);
}

// =======================================
//      0bh
// =======================================
void __stdcall or_GvEv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,74);
}

// =======================================
//      0ch
// =======================================
void __stdcall or_ALIb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
    ALIb(pMyDisasm);
    FillFlags(pMyDisasm,74);
}

// =======================================
//      0dh
// =======================================
void __stdcall or_eAX_Iv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "or ");
    eAX_Iv(pMyDisasm);
    FillFlags(pMyDisasm,74);
}


// =======================================
//      06eh
// =======================================
void __stdcall outsb_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "outsb ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
    (*pMyDisasm).Argument1.ArgSize = 16;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_++;
    FillFlags(pMyDisasm, 76);
}

// =======================================
//      06fh
// =======================================
void __stdcall outsw_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    if (OperandSize >= 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "outsd ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.AccessMode = READ;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
        (*pMyDisasm).Argument2.ArgSize = 32;
        EIP_++;
        FillFlags(pMyDisasm, 76);
    }

    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "outsw ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.AccessMode = READ;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
        (*pMyDisasm).Argument2.ArgSize = 16;
        EIP_++;
        FillFlags(pMyDisasm, 76);
    }
}

// =======================================
//
// =======================================
void __stdcall out_IbAL(PDISASM pMyDisasm)
{
    long MyNumber;

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "out ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument1.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers8Bits[0]);
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}

// =======================================
//
// =======================================
void __stdcall out_Ib_eAX(PDISASM pMyDisasm)
{
    long MyNumber;

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "out ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument1.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    if (OperandSize == 32) {
        (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[0]);
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[0]);
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
    EIP_ += 2;
}


// =======================================
//
// =======================================
void __stdcall out_DXAL(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "out ");
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[2]);
    (*pMyDisasm).Argument1.ArgSize = 16;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers8Bits[0]);
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ ++;
}

// =======================================
//
// =======================================
void __stdcall out_DXeAX(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "out ");
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[2]);
    (*pMyDisasm).Argument1.ArgSize = 16;
    (*pMyDisasm).Argument1.AccessMode = READ;
    if (OperandSize == 32) {
        (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[0]);
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[0]);
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
    EIP_ ++;
}

// =======================================
//      8fh
// =======================================
void __stdcall pop_Ev(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    if (REGOPCODE == 0) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
        if (Architecture == 64) {
            OperandSize = 64;
            OpSize = 4;
            MOD_RM(&(*pMyDisasm).Argument1);
            EIP_ += DECALAGE_EIP + 2;
            (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
            (*pMyDisasm).Argument2.ArgSize = 64;
            (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
            (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        }
        else if (OperandSize == 32) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            EIP_ += DECALAGE_EIP + 2;
            (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
            (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        }
        else {
            OpSize = 2;
            MOD_RM(&(*pMyDisasm).Argument1);
            EIP_ += DECALAGE_EIP + 2;
            (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
            (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        }
    }
    else {
        FailDecode(pMyDisasm);
    }
}

// =======================================
//      58h
// =======================================
void __stdcall pop_eax(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0+8];
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 32;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 16;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      59h
// =======================================
void __stdcall pop_ecx(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[1+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[1+0+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+8];
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[1+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1];
            (*pMyDisasm).Argument1.ArgSize = 32;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[1+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+8];
            (*pMyDisasm).Argument1.ArgSize = 16;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      5ah
// =======================================
void __stdcall pop_edx(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[2+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];

        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[2+0+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+8];
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[2+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];
            (*pMyDisasm).Argument1.ArgSize = 32;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[2+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];
            (*pMyDisasm).Argument1.ArgSize = 16;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      5bh
// =======================================
void __stdcall pop_ebx(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[3+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[3+0+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+8];
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[3+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3];
            (*pMyDisasm).Argument1.ArgSize = 32;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[3+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3];
            (*pMyDisasm).Argument1.ArgSize = 16;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      5ch
// =======================================
void __stdcall pop_esp(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[4+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[4+0+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+8];
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[4+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4];
            (*pMyDisasm).Argument1.ArgSize = 32;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[4+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4];
            (*pMyDisasm).Argument1.ArgSize = 16;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      5dh
// =======================================
void __stdcall pop_ebp(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[5+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[5+0+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+8];
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[5+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5];
            (*pMyDisasm).Argument1.ArgSize = 32;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[5+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5];
            (*pMyDisasm).Argument1.ArgSize = 16;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      5eh
// =======================================
void __stdcall pop_esi(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[6+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[6+0+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+8];
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[6+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6];
            (*pMyDisasm).Argument1.ArgSize = 32;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[6+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6];
            (*pMyDisasm).Argument1.ArgSize = 16;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      5fh
// =======================================
void __stdcall pop_edi(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[7+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[7+0+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+8];
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[7+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7];
            (*pMyDisasm).Argument1.ArgSize = 32;
            (*pMyDisasm).Argument2.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[7+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7];
            (*pMyDisasm).Argument1.ArgSize = 16;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//
// =======================================
void __stdcall pop_es(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[0]);
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[0];
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall pop_ss(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[2]);
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[2];
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall pop_ds(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[3]);
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[3];
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall pop_fs(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[4]);
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[4];
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall pop_gs(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pop ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[5]);
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[5];
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//      9dh
// =======================================
void __stdcall popfd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;

    if (Architecture == 64) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "popfq ");
        EIP_++;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
        FillFlags(pMyDisasm, 78);
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "popfd ");
        EIP_++;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
        FillFlags(pMyDisasm, 78);
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "popf ");
        EIP_++;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
        FillFlags(pMyDisasm, 78);
    }
}

// =======================================
//      9dh
// =======================================
void __stdcall popad_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;

    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "popad ");
        EIP_++;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG1 + REG2 + REG3 + REG4 + REG5 + REG6 + REG7;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "popa ");
        EIP_++;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG1 + REG2 + REG3 + REG4 + REG5 + REG6 + REG7;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
    }
}


// =======================================
//
// =======================================
void __stdcall push_es(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[0]);
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[0];
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall push_ss(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[2]);
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[2];
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall push_ds(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[3]);
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[3];
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall push_fs(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[4]);
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[4];
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall push_gs(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[5]);
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[5];
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}

// =======================================
//
// =======================================
void __stdcall push_cs(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, RegistersSEG[1]);
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SEGMENT_REG + REGS[1];
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
        EIP_++;
    }
}



// =======================================
//      50h
// =======================================
void __stdcall push_eax(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0+8];
        }
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      51h
// =======================================
void __stdcall push_ecx(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[1+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[1+0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+8];
        }
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[1+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1];
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[1+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+8];
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      52h
// =======================================
void __stdcall push_edx(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[2+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];

        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[2+0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+8];
        }
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[2+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[2+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      53h
// =======================================
void __stdcall push_ebx(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[3+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[3+0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+8];
        }
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[3+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3];
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[3+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3];
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      54h
// =======================================
void __stdcall push_esp(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[4+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[4+0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+8];
        }
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[4+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4];
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[4+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4];
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      55h
// =======================================
void __stdcall push_ebp(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[5+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[5+0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+8];
        }
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[5+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5];
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[5+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5];
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      56h
// =======================================
void __stdcall push_esi(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[6+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[6+0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+8];
        }
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[6+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6];
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[6+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6];
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}

// =======================================
//      57h
// =======================================
void __stdcall push_edi(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (REX.B_ == 0) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[7+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7];
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[7+0+8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+8];
        }
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        if (OperandSize == 32) {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[7+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7];
            (*pMyDisasm).Argument2.ArgSize = 32;
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy((char*) &(*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[7+0]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7];
            (*pMyDisasm).Argument2.ArgSize = 16;
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
    }
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
}


// =======================================
//      68h
// =======================================
void __stdcall push_Iv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;

    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (Architecture == 64) {
        if (!Security(5)) return;
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.8X",*((DWORD*) (EIP_ + 1)));
        ImmediatSize = 32;
        (*pMyDisasm).Instruction.Immediat = *((DWORD*) (EIP_ + 1));
        EIP_ += 5;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.8X",*((DWORD*) (EIP_ + 1)));
        ImmediatSize = 32;
        (*pMyDisasm).Instruction.Immediat = *((DWORD*) (EIP_ + 1));
        EIP_ += 5;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
    }
    else {
        if (!Security(3)) return;
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.8X",*((DWORD*) (EIP_ + 1)));
        ImmediatSize = 16;
        (*pMyDisasm).Instruction.Immediat = *((DWORD*) (EIP_ + 1));
        EIP_ += 3;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;
    }
}

// =======================================
//      6ah
// =======================================
void __stdcall push_Ib(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "push ");
    if (!Security(1)) return;
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X",*((BYTE*) (EIP_ + 1)));
    ImmediatSize = 8;
    (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_ + 1));
    EIP_ += 2;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.ArgSize = 32;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = REGISTER_TYPE + GENERAL_REG + REG4;

}


// =======================================
//      9ch
// =======================================
void __stdcall pushfd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;

    if (Architecture == 64) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pushfq ");
        EIP_++;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
        FillFlags(pMyDisasm, 78);
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pushfd ");
        EIP_++;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
        FillFlags(pMyDisasm, 78);
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pushf ");
        EIP_++;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
        FillFlags(pMyDisasm, 78);
    }
}


// =======================================
//      60h
// =======================================
void __stdcall pushad_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;

    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pushad ");
        EIP_++;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG1 + REG2 + REG3 + REG4 + REG5 + REG6 + REG7;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pusha ");
        EIP_++;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG1 + REG2 + REG3 + REG4 + REG5 + REG6 + REG7;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG4;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
    }
}

// =======================================
//      0c2h
// =======================================
void __stdcall retn_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = RetType;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "retn ");
    if (!Security(3)) return;
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument1.ArgMnemonic,"%.4X",*((WORD*) (EIP_ + 1)));
    ImmediatSize = 16;
    (*pMyDisasm).Instruction.Immediat = *((WORD*) (EIP_ + 1));
    EIP_+=3;
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument1.ArgSize = 16;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
}

// =======================================
//      0c3h
// =======================================
void __stdcall ret_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = RetType;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ret ");
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.ArgSize = 32;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
}

// =======================================
//
// =======================================
void __stdcall retf_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = RetType;
    if (SYNTAX_ == ATSyntax) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lret ");
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "retf ");
    }
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "retf ");
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.ArgSize = 32;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG4;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
}

// =======================================
//
// =======================================
void __stdcall retf_Iw(PDISASM pMyDisasm)
{
    int i = 0;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = RetType;
    if (SYNTAX_ == ATSyntax) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lret ");
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic,"$");
        i++;
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "retf ");
    }
    if (!Security(3)) return;
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument1.ArgMnemonic+i,"%.4X",*((WORD*) (EIP_ + 1)));
    ImmediatSize = 16;
    (*pMyDisasm).Instruction.Immediat = *((WORD*) (EIP_ + 1));
    EIP_+=3;
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument1.ArgSize = 16;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
}

// =======================================
//
// =======================================
void __stdcall rdtsc_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rdtsc ");
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
    (*pMyDisasm).Argument1.ArgSize = 32;
}

// =======================================
//
// =======================================
void __stdcall rdmsr_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rdmsr ");
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
    (*pMyDisasm).Argument1.ArgSize = 32;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument2.ArgSize = 32;
}

// =======================================
//
// =======================================
void __stdcall rdpmc_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rdpmc ");
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG2;
    (*pMyDisasm).Argument1.ArgSize = 32;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument2.ArgSize = 32;
}

// =======================================
//
// =======================================
void __stdcall rsm_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rsm ");
    EIP_++;
    FillFlags(pMyDisasm, 89);
}

// =======================================
//
// =======================================
void __stdcall sysenter_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sysenter ");
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall sysexit_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sysexit ");
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall sahf_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sahf ");
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 32;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgSize = 8;
}

// =======================================
//
// =======================================
void __stdcall salc_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = UNDOCUMENTED_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "salc ");
    EIP_++;
}


// =======================================
//      0ach
// =======================================
void __stdcall scasb_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "scasb ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG7;
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG7;
    EIP_++;
    FillFlags(pMyDisasm, 94);
}

// =======================================
//      0adh
// =======================================
void __stdcall scas_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "scasq ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument1.AccessMode = READ;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 94);
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "scasd ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument1.AccessMode = READ;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 94);
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "scasw ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.AccessMode = READ;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 94);
    }
}

// =======================================
//
// =======================================
void __stdcall stc_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "stc ");
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 1;
    FillFlags(pMyDisasm, 98);
}

// =======================================
//
// =======================================
void __stdcall sti_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sti ");
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 1;
    FillFlags(pMyDisasm, 100);
}


// =======================================
//      0aah
// =======================================
void __stdcall stos_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "stosb ");
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG7;
    EIP_++;
    FillFlags(pMyDisasm, 101);
}

// =======================================
//      0abh
// =======================================
void __stdcall stosw_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "stosq ");
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 101);
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "stosd ");
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 101);
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "stosw ");
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 101);
    }
}

// =======================================
//
// =======================================
void __stdcall syscall_(PDISASM pMyDisasm)
{
    if (OperandSize == 64) {
        (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "syscall ");
        EIP_++;
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG1 + REG11;
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else {
        FailDecode(pMyDisasm);
    }
}

// =======================================
//
// =======================================
void __stdcall sysret_(PDISASM pMyDisasm)
{
    if (OperandSize == 64) {
        (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sysret ");
        EIP_++;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG1 + REG11;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else {
        FailDecode(pMyDisasm);
    }
}



// =======================================
//      18h
// =======================================
void __stdcall sbb_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,93);
}

// =======================================
//      19h
// =======================================
void __stdcall sbb_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,93);
}

// =======================================
//      1ah
// =======================================
void __stdcall sbb_GbEb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
    GbEb(pMyDisasm);
    FillFlags(pMyDisasm,93);
}

// =======================================
//      1bh
// =======================================
void __stdcall sbb_GvEv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,93);
}

// =======================================
//      1ch
// =======================================
void __stdcall sbb_ALIb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
    ALIb(pMyDisasm);
    FillFlags(pMyDisasm,93);
}

// =======================================
//      1dh
// =======================================
void __stdcall sbb_eAX_Iv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sbb ");
    eAX_Iv(pMyDisasm);
    FillFlags(pMyDisasm,93);
}

// =======================================
//      0f90h
// =======================================
void __stdcall seto_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "seto ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f91h
// =======================================
void __stdcall setno_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setno ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setb ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setnb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setnb ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall sete_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sete ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setne_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setne ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setbe_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setbe ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setnbe_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setnbe ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall sets_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sets ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setns_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setns ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setp_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setp ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setnp_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setnp ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setge_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setnl ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setnge_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setl ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setle_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setle ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}

// =======================================
//      0f90h
// =======================================
void __stdcall setnle_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "setnle ");
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_+= DECALAGE_EIP + 2;
    FillFlags(pMyDisasm,95);
}


// =======================================
//      0fa4h
// =======================================
void __stdcall shld_EvGvIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shld ");
    EvGv(pMyDisasm);
    EIP_+= 1;
    if (!Security(0)) return;
    third_arg = 1;
    (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_- 1));
    (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument3.ArgMnemonic, "%.8X", *((BYTE*) (EIP_- 1)));
    (*pMyDisasm).Argument3.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument3.ArgSize = 8;
    ImmediatSize = 8;
    FillFlags(pMyDisasm, 97);
}


// =======================================
//
// =======================================
void __stdcall shld_EvGvCL(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shld ");
    EvGv(pMyDisasm);
    third_arg = 2;
    (void) strcpy ((*pMyDisasm).Argument3.ArgMnemonic, Registers8Bits[1]);
    (*pMyDisasm).Argument3.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument3.ArgSize = 8;
    FillFlags(pMyDisasm, 97);
}

// =======================================
//      0fach
// =======================================
void __stdcall shrd_EvGvIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shrd ");
    EvGv(pMyDisasm);
    EIP_+= 1;
    if (!Security(0)) return;
    third_arg = 1;
    (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_- 1));
    (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument3.ArgMnemonic, "%.8X", *((BYTE*) (EIP_- 1)));
    (*pMyDisasm).Argument3.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument3.ArgSize = 8;
    ImmediatSize = 8;
    FillFlags(pMyDisasm, 97);
}


// =======================================
//
// =======================================
void __stdcall shrd_EvGvCL(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SHIFT_ROTATE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "shrd ");
    EvGv(pMyDisasm);
    third_arg = 2;
    (void) strcpy ((*pMyDisasm).Argument3.ArgMnemonic, Registers8Bits[1]);
    (*pMyDisasm).Argument3.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument3.ArgSize = 8;
    FillFlags(pMyDisasm, 97);
}


// =======================================
//
// =======================================
void __stdcall std_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "std ");
    EIP_++;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 1;
    FillFlags(pMyDisasm, 99);
}


// =======================================
//      28h
// =======================================
void __stdcall sub_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,103);
}

// =======================================
//      29h
// =======================================
void __stdcall sub_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,103);
}

// =======================================
//      2ah
// =======================================
void __stdcall sub_GbEb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
    GbEb(pMyDisasm);
    FillFlags(pMyDisasm,103);
}

// =======================================
//      2bh
// =======================================
void __stdcall sub_GvEv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,103);
}

// =======================================
//      2ch
// =======================================
void __stdcall sub_ALIb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
    ALIb(pMyDisasm);
    FillFlags(pMyDisasm,103);
}

// =======================================
//      2dh
// =======================================
void __stdcall sub_eAX_Iv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sub ");
    eAX_Iv(pMyDisasm);
    FillFlags(pMyDisasm,103);
}

// =======================================
//      84h
// =======================================
void __stdcall test_EbGb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
    (*pMyDisasm).Argument1.AccessMode = READ;
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,104);
}

// =======================================
//      85h
// =======================================
void __stdcall test_EvGv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
    (*pMyDisasm).Argument1.AccessMode = READ;
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,104);
}

// =======================================
//      86h
// =======================================
void __stdcall test_GbEb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
    (*pMyDisasm).Argument1.AccessMode = READ;
    GbEb(pMyDisasm);
    FillFlags(pMyDisasm,104);
}

// =======================================
//      87h
// =======================================
void __stdcall test_GvEv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
    (*pMyDisasm).Argument1.AccessMode = READ;
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,104);
}

// =======================================
//      88h
// =======================================
void __stdcall test_ALIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
    (*pMyDisasm).Argument1.AccessMode = READ;
    ALIb(pMyDisasm);
    FillFlags(pMyDisasm,104);
}

// =======================================
//      89h
// =======================================
void __stdcall test_eAX_Iv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "test ");
    (*pMyDisasm).Argument1.AccessMode = READ;
    eAX_Iv(pMyDisasm);
    FillFlags(pMyDisasm,104);
}

// =======================================
//
// =======================================
void __stdcall ud2_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + MISCELLANEOUS_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ud2 ");
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall vmread_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmread ");
    EvGv(pMyDisasm);
}

// =======================================
//
// =======================================
void __stdcall vmwrite_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmwrite ");
    GvEv(pMyDisasm);
}

// =======================================
//
// =======================================
void __stdcall wbinvd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "wbinvd ");
    EIP_++;
}

// =======================================
//      9Bh
// =======================================
void __stdcall wait_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "wait ");
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall wrmsr_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "wrmsr ");
    EIP_++;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG1 + REG2;
    (*pMyDisasm).Argument2.ArgSize = 32;
}


// =======================================
//      0fc0h
// =======================================
void __stdcall xadd_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xadd ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,110);
}

// =======================================
//      0fc1h
// =======================================
void __stdcall xadd_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xadd ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,110);
}

// =======================================
//      91h
// =======================================
void __stdcall xchg_ecx(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[1+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[1]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[1+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[1]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[1+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[1]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
}


// =======================================
//      92h
// =======================================
void __stdcall xchg_edx(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[2+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[2]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[2+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[2]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[2+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[2]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
}


// =======================================
//      93h
// =======================================
void __stdcall xchg_ebx(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG3;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[3+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[3]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[3+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[3]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[3+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[3]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
}


// =======================================
//      94h
// =======================================
void __stdcall xchg_esp(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG4;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[4+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[4]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[4+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[4]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[4+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[4]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
}


// =======================================
//      95h
// =======================================
void __stdcall xchg_ebp(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG5;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[5+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[5]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[5+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[5]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[5+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[5]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
}


// =======================================
//      96h
// =======================================
void __stdcall xchg_esi(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG6;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[6+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[6]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[6+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[6]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[6+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[6]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
}


// =======================================
//      97h
// =======================================
void __stdcall xchg_edi(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG7;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[7+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[7]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[7+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[7]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        if (REX.B_ == 1) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[7+8]);
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[7]);
        }
        EIP_++;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
}

// =======================================
//      0d7h
// =======================================
void __stdcall xlat_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + MISCELLANEOUS_INSTRUCTION;
    if (AddressSize == 64) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xlat ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 8;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG3;
        (*pMyDisasm).Argument2.ArgSize = 64;
        EIP_++;
    }
    else if (AddressSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xlat ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 8;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG3;
        (*pMyDisasm).Argument2.ArgSize = 32;
        EIP_++;
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xlatb ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 8;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG3;
        (*pMyDisasm).Argument2.ArgSize = 16;
        EIP_++;
    }
}


// =======================================
//      30h
// =======================================
void __stdcall xor_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,113);
}

// =======================================
//      31h
// =======================================
void __stdcall xor_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,113);
}

// =======================================
//      32h
// =======================================
void __stdcall xor_GbEb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
    GbEb(pMyDisasm);
    FillFlags(pMyDisasm,113);
}

// =======================================
//      33h
// =======================================
void __stdcall xor_GvEv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,113);
}

// =======================================
//      34h
// =======================================
void __stdcall xor_ALIb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
    ALIb(pMyDisasm);
    FillFlags(pMyDisasm,113);
}

// =======================================
//      35h
// =======================================
void __stdcall xor_eAX_Iv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xor ");
    eAX_Iv(pMyDisasm);
    FillFlags(pMyDisasm,113);
}


// =======================================
//      86h
// =======================================
void __stdcall xchg_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,113);
    (*pMyDisasm).Argument2.AccessMode = WRITE;
}

// =======================================
//      87h
// =======================================
void __stdcall xchg_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xchg ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,113);
    (*pMyDisasm).Argument2.AccessMode = WRITE;
}
