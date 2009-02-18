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

void __stdcall FailDecode(PDISASM pMyDisasm)
{
	(void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "??? ");
	ERROR_OPCODE = 1;
}
// ====================================================================
//
// ====================================================================
void __stdcall aaa_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Archi == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "aaa ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 8;
        EIP_++;
    };
}

// ====================================================================
//
// ====================================================================
void __stdcall aad_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Archi == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "aad ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 16;
        EIP_+=2;
    };
}

// ====================================================================
//
// ====================================================================
void __stdcall aam_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Archi == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "aam ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 16;
        EIP_+=2;
    };
}

// =======================================
//
// =======================================
void __stdcall aas_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Archi == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "aas ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 8;
        EIP_++;
    };
}

// =======================================
//      00h
// =======================================
void __stdcall add_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,5);
}

// =======================================
//      01h
// =======================================
void __stdcall add_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,5);
}

// =======================================
//      02h
// =======================================
void __stdcall add_GbEb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
    GbEb(pMyDisasm);
    FillFlags(pMyDisasm,5);
}

// =======================================
//      03h
// =======================================
void __stdcall add_GvEv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,5);
}

// =======================================
//      04h
// =======================================
void __stdcall add_ALIb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
    ALIb(pMyDisasm);
    FillFlags(pMyDisasm,5);
}

// =======================================
//      05h
// =======================================
void __stdcall add_eAX_Iv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "add ");
    eAX_Iv(pMyDisasm);
    FillFlags(pMyDisasm,5);
}

// =======================================
//      10h
// =======================================
void __stdcall adc_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,4);
}

// =======================================
//      11h
// =======================================
void __stdcall adc_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,4);
}

// =======================================
//      12h
// =======================================
void __stdcall adc_GbEb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
    GbEb(pMyDisasm);
    FillFlags(pMyDisasm,4);
}

// =======================================
//      13h
// =======================================
void __stdcall adc_GvEv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,4);
}

// =======================================
//      14h
// =======================================
void __stdcall adc_ALIb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
    ALIb(pMyDisasm);
    FillFlags(pMyDisasm,4);
}

// =======================================
//      15h
// =======================================
void __stdcall adc_eAX_Iv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "adc ");
    eAX_Iv(pMyDisasm);
    FillFlags(pMyDisasm,4);
}

// =======================================
//      20h
// =======================================
void __stdcall and_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,6);
}

// =======================================
//      21h
// =======================================
void __stdcall and_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,6);
}

// =======================================
//      22h
// =======================================
void __stdcall and_GbEb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
    GbEb(pMyDisasm);
    FillFlags(pMyDisasm,6);
}

// =======================================
//      23h
// =======================================
void __stdcall and_GvEv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,6);
}

// =======================================
//      24h
// =======================================
void __stdcall and_ALIb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
    ALIb(pMyDisasm);
    FillFlags(pMyDisasm,6);
}

// =======================================
//      25h
// =======================================
void __stdcall and_eAX_Iv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + LOGICAL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "and ");
    eAX_Iv(pMyDisasm);
    FillFlags(pMyDisasm,6);
}

// =======================================
//
// =======================================
void __stdcall arpl_(PDISASM pMyDisasm)
{

    if (Architecture == 64) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movsxd ");
        GvEv(pMyDisasm);
        FillFlags(pMyDisasm,69);
    }
    else {
        (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "arpl ");
        OperandSize = 16;
        EvGv(pMyDisasm);
        OperandSize = 32;
        FillFlags(pMyDisasm,7);
    }

}

// =======================================
//      62h
// =======================================
void __stdcall bound_(PDISASM pMyDisasm)
{

    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bound ");
        GvEv(pMyDisasm);
        OpSize = 103;
        (*pMyDisasm).Argument1.AccessMode = READ;
        FillFlags(pMyDisasm,8);
    }

}

// =======================================
//      0fc8h
// =======================================
void __stdcall bswap_eax(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bswap ");
    if (OperandSize == 64) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
        }
    }
    else {
        (*pMyDisasm).Argument1.ArgSize = 32;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
        }
    }
    EIP_++;
    FillFlags(pMyDisasm,10);

}


// =======================================
//      0fc8h
// =======================================
void __stdcall bswap_ecx(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bswap ");
    if (OperandSize == 64) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[1+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[1+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+0];
        }
    }
    else {
        (*pMyDisasm).Argument1.ArgSize = 32;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[1+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[1+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+0];
        }
    }
    EIP_++;
    FillFlags(pMyDisasm,10);

}


// =======================================
//      0fc8h
// =======================================
void __stdcall bswap_edx(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bswap ");
    if (OperandSize == 64) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[2+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[2+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+0];
        }
    }
    else {
        (*pMyDisasm).Argument1.ArgSize = 32;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[2+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[2+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+0];
        }
    }
    EIP_++;
    FillFlags(pMyDisasm,10);

}


// =======================================
//      0fc8h
// =======================================
void __stdcall bswap_ebx(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bswap ");
    if (OperandSize == 64) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[3+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[3+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+0];
        }
    }
    else {
        (*pMyDisasm).Argument1.ArgSize = 32;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[3+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[3+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+0];
        }
    }
    EIP_++;
    FillFlags(pMyDisasm,10);

}


// =======================================
//      0fc8h
// =======================================
void __stdcall bswap_esp(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bswap ");
    if (OperandSize == 64) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[4+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[4+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+0];
        }
    }
    else {
        (*pMyDisasm).Argument1.ArgSize = 32;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[4+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[4+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+0];
        }
    }
    EIP_++;
    FillFlags(pMyDisasm,10);

}


// =======================================
//      0fc8h
// =======================================
void __stdcall bswap_ebp(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bswap ");
    if (OperandSize == 64) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[5+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[5+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+0];
        }
    }
    else {
        (*pMyDisasm).Argument1.ArgSize = 32;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[5+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[5+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+0];
        }
    }
    EIP_++;
    FillFlags(pMyDisasm,10);

}


// =======================================
//      0fc8h
// =======================================
void __stdcall bswap_esi(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bswap ");
    if (OperandSize == 64) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[6+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[6+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+0];
        }
    }
    else {
        (*pMyDisasm).Argument1.ArgSize = 32;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[6+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[6+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+0];
        }
    }
    EIP_++;
    FillFlags(pMyDisasm,10);

}


// =======================================
//      0fc8h
// =======================================
void __stdcall bswap_edi(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bswap ");
    if (OperandSize == 64) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[7+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[7+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+0];
        }
    }
    else {
        (*pMyDisasm).Argument1.ArgSize = 32;
        if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[7+8]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+8];
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[7+0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+0];
        }
    }
    EIP_++;
    FillFlags(pMyDisasm,10);

}

// =======================================
//      0fbch
// =======================================
void __stdcall bsf_GvEv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bsf ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,9);
}

// =======================================
//      0fbdh
// =======================================
void __stdcall bsr_GvEv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bsr ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,9);
}

// =======================================
//      0fbbh
// =======================================
void __stdcall btc_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "btc ");
    EvGv(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,11);
}

// =======================================
//      0fa3h
// =======================================
void __stdcall bt_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bt ");
    EvGv(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,11);
}

// =======================================
//      0fb3h
// =======================================
void __stdcall btr_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "btr ");
    EvGv(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,11);
}

// =======================================
//      0fabh
// =======================================
void __stdcall bts_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + BIT_BYTE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "bts ");
    EvGv(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,11);
}

// =======================================
//      e8h
// =======================================
void __stdcall call_(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = CallType;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "call ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1)) + 5 + NB_PREFIX;
        CalculateRelativeAddress(&MyAddress, MyNumber);
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
        if (MyAddress >= 0x80000000) {
            (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SDWORD*) (EIP_+1)) + 3 + NB_PREFIX;
        CalculateRelativeAddress(&MyAddress, MyNumber);
        MyAddress = MyAddress & 0xffff;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
        (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
    }
}

// =======================================
//
// =======================================
void __stdcall callf_(PDISASM pMyDisasm)
{
    long MyNumber;
    int i = 0;
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
        (*pMyDisasm).Instruction.BranchType = CallType;
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lcall ");
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic,"$");
            i++;
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "call far ");
        }
        if (OperandSize ==32) {
            if (!Security(7)) return;
            MyNumber = *((WORD*) (EIP_+5));
            i += CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic+i, "%.4X", MyNumber);
        }
        else {
            if (!Security(5)) return;
            MyNumber = *((WORD*) (EIP_+3));
            i += CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic+i, "%.4X", MyNumber);
        }
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic+i, " , $");
            i+=4;
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic+i, " : ");
            i+=3;
        }
        MyNumber = *((DWORD*) (EIP_+1));
        if (OperandSize == 16) {
            MyNumber = MyNumber & 0xffff;
        }
        i += CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic+i, "%.8X", MyNumber);
        if (OperandSize == 32) {
            EIP_+=7;
        }
        else {
            EIP_+=5;
        }
        (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG4;

    }
}

// =======================================
//      99h
// =======================================
void __stdcall cdq_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    if (OperandSize == 64) {
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cqto ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cqo ");
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else if (OperandSize ==32) {
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cltd ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cdq ");
        }
        (*pMyDisasm).Argument1.ArgSize = 32;
    }
    else {
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cwtd ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cwd ");
        }
        (*pMyDisasm).Argument1.ArgSize = 16;
    }
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall clts_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "clts ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + CR_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 1;
    FillFlags(pMyDisasm, 17);
    EIP_++;
}


// =======================================
//      F5h
// =======================================
void __stdcall cmc_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmc ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 1;
    FillFlags(pMyDisasm, 18);
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall cmovo_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovo ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovno_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovno ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovb ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovnb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovnb ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmove_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmove ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovne_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovne ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovbe_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovbe ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovnbe_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovnbe ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovs_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovs ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovns_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovns ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovp_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovp ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovnp_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovnp ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovl_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovl ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovnl_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovnl ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovle_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovle ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmovnle_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmovnle ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm, 19);
}

// =======================================
//
// =======================================
void __stdcall cmpx_EbGb(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmpxchg ");
    EbGb(pMyDisasm);
    FillFlags(pMyDisasm,22);
}

// =======================================
//
// =======================================
void __stdcall cmpx_EvGv(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
        (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmpxchg ");
    EvGv(pMyDisasm);
    FillFlags(pMyDisasm,22);
}

// =======================================
//      38h
// =======================================
void __stdcall cmp_EbGb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
    EbGb(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,20);
}

// =======================================
//      39h
// =======================================
void __stdcall cmp_EvGv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
    EvGv(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,20);
}

// =======================================
//      3ah
// =======================================
void __stdcall cmp_GbEb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
    GbEb(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,20);
}

// =======================================
//      3bh
// =======================================
void __stdcall cmp_GvEv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
    GvEv(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,20);
}

// =======================================
//      3ch
// =======================================
void __stdcall cmp_ALIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
    ALIb(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,20);
}

// =======================================
//      3dh
// =======================================
void __stdcall cmp_eAX_Iv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmp ");
    eAX_Iv(pMyDisasm);
    (*pMyDisasm).Argument1.AccessMode = READ;
    FillFlags(pMyDisasm,20);
}

// =======================================
//      a6h
// =======================================
void __stdcall cmpsb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmpsb ");
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
    FillFlags(pMyDisasm,21);
    EIP_++;
}

// =======================================
//      a7h
// =======================================
void __stdcall cmps_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
    if (Architecture == 64) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmpsq ");
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmpsd ");
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cmpsw ");
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
    FillFlags(pMyDisasm,21);
    EIP_++;
}

// =======================================
//      98h
// =======================================
void __stdcall cwde_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    if (OperandSize == 64) {
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cltq ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cdqe ");
        }
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cwtl ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cwde ");
        }
        (*pMyDisasm).Argument1.ArgSize = 32;
    }
    else {
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cbtw ");
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cbw ");
        }
        (*pMyDisasm).Argument1.ArgSize = 16;
    }
    EIP_++;
}

// =======================================
//      f8h
// =======================================
void __stdcall clc_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "clc ");
    (*pMyDisasm).Argument1.ArgSize = 1;
    FillFlags(pMyDisasm, 14);
    EIP_++;
}

// =======================================
//      f8h
// =======================================
void __stdcall cld_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cld ");
    (*pMyDisasm).Argument1.ArgSize = 1;
    FillFlags(pMyDisasm, 15);
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall cli_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cli ");
    (*pMyDisasm).Argument1.ArgSize = 1;
    FillFlags(pMyDisasm, 16);
    EIP_++;
}

// =======================================
//      0fa2h
// =======================================
void __stdcall cpuid_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + MISCELLANEOUS_INSTRUCTION;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0 + REG1 + REG2 + REG3;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "cpuid ");
    (*pMyDisasm).Argument1.ArgSize = 32;
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall daa_(PDISASM pMyDisasm)
{

    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "daa ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm,28);
        EIP_++;
    }

}

// =======================================
//
// =======================================
void __stdcall das_(PDISASM pMyDisasm)
{

    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "das ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 8;
        FillFlags(pMyDisasm,29);
        EIP_++;
    }

}

// =======================================
//      48h
// =======================================
void __stdcall dec_eax(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 1;
        REX.R_ = 0;
        REX.X_ = 0;
        REX.B_ = 0;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        OperandSize = 64;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 30);
    }
}

// =======================================
//      49h
// =======================================
void __stdcall dec_ecx(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 1;
        REX.R_ = 0;
        REX.X_ = 0;
        REX.B_ = 1;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        OperandSize = 64;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[1]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[1]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 30);
    }
}

// =======================================
//      4ah
// =======================================
void __stdcall dec_edx(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 1;
        REX.R_ = 0;
        REX.X_ = 1;
        REX.B_ = 0;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        OperandSize = 64;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[2]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[2]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 30);
    }
}

// =======================================
//      4bh
// =======================================
void __stdcall dec_ebx(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 1;
        REX.R_ = 0;
        REX.X_ = 1;
        REX.B_ = 1;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        OperandSize = 64;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[3]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[3]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 30);
    }
}

// =======================================
//      4ch
// =======================================
void __stdcall dec_esp(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 1;
        REX.R_ = 1;
        REX.X_ = 0;
        REX.B_ = 0;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        OperandSize = 64;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[4]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[4]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 30);
    }
}

// =======================================
//      4dh
// =======================================
void __stdcall dec_ebp(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 1;
        REX.R_ = 1;
        REX.X_ = 0;
        REX.B_ = 1;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        OperandSize = 64;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[5]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[5]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 30);
    }
}

// =======================================
//      4eh
// =======================================
void __stdcall dec_esi(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 1;
        REX.R_ = 1;
        REX.X_ = 1;
        REX.B_ = 0;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        OperandSize = 64;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[6]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[6]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 30);
    }
}

// =======================================
//      4fh
// =======================================
void __stdcall dec_edi(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 1;
        REX.R_ = 1;
        REX.X_ = 1;
        REX.B_ = 1;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        OperandSize = 64;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "dec ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[7]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[7]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 30);
    }
}

// =======================================
//      0c8h
// =======================================
void __stdcall enter_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "enter ");
    (void) CopyFormattedNumber ((char*) (*pMyDisasm).Argument1.ArgMnemonic,"%.4X", *((WORD*) (EIP_+1)));
    (*pMyDisasm).Argument1.ArgSize = 16;
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (void) CopyFormattedNumber ((char*) (*pMyDisasm).Argument2.ArgMnemonic,"%.2X", *((BYTE*) (EIP_+3)));
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    EIP_+=4;
}

// =======================================
//
// =======================================
void __stdcall femms_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = AMD_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "femms ");
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall hlt_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "hlt ");
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall invd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "invd ");
    EIP_++;
}

// =======================================
//      40h
// =======================================
void __stdcall inc_eax(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 0;
        REX.R_ = 0;
        REX.X_ = 0;
        REX.B_ = 0;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 40);
    }
}

// =======================================
//      41h
// =======================================
void __stdcall inc_ecx(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 0;
        REX.R_ = 0;
        REX.X_ = 0;
        REX.B_ = 1;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[1]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[1]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[1+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 40);
    }
}

// =======================================
//      42h
// =======================================
void __stdcall inc_edx(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 0;
        REX.R_ = 0;
        REX.X_ = 1;
        REX.B_ = 0;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[2]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[2]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 40);
    }
}

// =======================================
//      43h
// =======================================
void __stdcall inc_ebx(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 0;
        REX.R_ = 0;
        REX.X_ = 1;
        REX.B_ = 1;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[3]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[3]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[3+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 40);
    }
}

// =======================================
//      44h
// =======================================
void __stdcall inc_esp(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 0;
        REX.R_ = 1;
        REX.X_ = 0;
        REX.B_ = 0;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[4]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[4]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[4+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 40);
    }
}

// =======================================
//      45h
// =======================================
void __stdcall inc_ebp(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 0;
        REX.R_ = 1;
        REX.X_ = 0;
        REX.B_ = 1;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[5]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[5]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[5+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 40);
    }
}

// =======================================
//      46h
// =======================================
void __stdcall inc_esi(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 0;
        REX.R_ = 1;
        REX.X_ = 1;
        REX.B_ = 0;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[6]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[6]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[6+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 40);
    }
}

// =======================================
//      47h
// =======================================
void __stdcall inc_edi(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        if (!Security(0)) return;
        REX.W_ = 0;
        REX.R_ = 1;
        REX.X_ = 1;
        REX.B_ = 1;
        REX.state = InUsePrefix;
        EIP_++;
        NB_PREFIX++;
        (*pMyDisasm).Prefix.Number++;
        (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
        (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
        OperandSize = 32;
        (*pMyDisasm).Argument2.AccessMode = WRITE;
    }
    else {
        if ((*pMyDisasm).Prefix.LockPrefix == InvalidPrefix) {
            (*pMyDisasm).Prefix.LockPrefix = InUsePrefix;
        }
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "inc ");
        if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[7]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+0];
            (*pMyDisasm).Argument1.ArgSize = 32;
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[7]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[7+0];
            (*pMyDisasm).Argument1.ArgSize = 16;
        }
        EIP_++;
        FillFlags(pMyDisasm, 40);
    }
}
// =======================================
//
// =======================================
void __stdcall iret_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = RetType;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "iret ");
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall in_ALDX(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "in ");
    (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers8Bits[0]);
    (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[2]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];
    (*pMyDisasm).Argument2.ArgSize = 16;
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall in_ALIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "in ");
    ALIb(pMyDisasm);
}

// =======================================
//
// =======================================
void __stdcall in_eAX_Ib(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "in ");
    if (!Security(1)) return;
    ImmediatSize = 8;
    (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_+1));
    (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.2X", *((BYTE*) (EIP_+1)));
    (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers8Bits[0]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_+=2;
}

// =======================================
//
// =======================================
void __stdcall insb_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "insb ");
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
    (*pMyDisasm).Argument2.ArgSize = 16;
    EIP_++;
    FillFlags(pMyDisasm, 41);


}

// =======================================
//
// =======================================
void __stdcall ins_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    if (OperandSize >= 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "insd ");
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
        (*pMyDisasm).Argument2.ArgSize = 16;
        EIP_++;
        FillFlags(pMyDisasm, 41);
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "insw ");
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
        (*pMyDisasm).Argument2.ArgSize = 16;
        EIP_++;
        FillFlags(pMyDisasm, 41);
    }
}

// =======================================
//
// =======================================
void __stdcall into_(PDISASM pMyDisasm)
{
    if (Architecture == 64) {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "into ");
        EIP_++;
        FillFlags(pMyDisasm, 43);
    }
}

// =======================================
//      0edh
// =======================================
void __stdcall in_eAX(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + InOutINSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "in ");
    if (OperandSize >=32) {
        (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[2]);
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
    else {
        (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[2]);
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[0];
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REGS[2];
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
    EIP_++;
}

// =======================================
//      0cdh
// =======================================
void __stdcall int_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "int ");
    if (!Security(1)) return;
    ImmediatSize = 8;
    (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_+1));
    (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.2X", *((BYTE*) (EIP_+1)));
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument1.ArgSize = 8;
    EIP_+=2;
    FillFlags(pMyDisasm, 42);
}

// =======================================
//      0f1h
// =======================================
void __stdcall int1_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "int1 ");
    EIP_++;
    FillFlags(pMyDisasm, 42);
}

// =======================================
//      0cch
// =======================================
void __stdcall int3_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "int3 ");
    EIP_++;
    FillFlags(pMyDisasm, 42);
}

// =======================================
//      69h
// =======================================
void __stdcall imul_GvEvIv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "imul ");
    if (OperandSize >= 32) {
        if (OperandSize == 64) {
            OpSize = 104;
        }
        else {
            OpSize = 103;
        }
        MOD_RM(&(*pMyDisasm).Argument2);
        Reg_Opcode(&(*pMyDisasm).Argument1);
        EIP_+= DECALAGE_EIP + 6;
        if (!Security(0)) return;
        third_arg = 1;
        (*pMyDisasm).Instruction.Immediat = *((DWORD*) (EIP_- 4));
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument3.ArgMnemonic, "%.8X", *((DWORD*) (EIP_- 4)));
        (*pMyDisasm).Argument3.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument3.ArgSize = 32;
        ImmediatSize = 32;
        FillFlags(pMyDisasm, 38);
    }
    else {
        OpSize = 102;
        MOD_RM(&(*pMyDisasm).Argument2);
        Reg_Opcode(&(*pMyDisasm).Argument1);
        EIP_+= DECALAGE_EIP + 4;
        if (!Security(0)) return;
        third_arg = 1;
        (*pMyDisasm).Instruction.Immediat = *((WORD*) (EIP_- 2));
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument3.ArgMnemonic, "%.4X", *((WORD*) (EIP_- 2)));
        (*pMyDisasm).Argument3.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument3.ArgSize = 16;
        ImmediatSize = 16;
        FillFlags(pMyDisasm, 38);
    }
}

// =======================================
//      6bh
// =======================================
void __stdcall imul_GvEvIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "imul ");
    if (OperandSize >= 32) {
        if (OperandSize == 64) {
            OpSize = 104;
        }
        else {
            OpSize = 103;
        }
        MOD_RM(&(*pMyDisasm).Argument2);
        Reg_Opcode(&(*pMyDisasm).Argument1);
        EIP_+= DECALAGE_EIP + 3;
        if (!Security(0)) return;
        third_arg = 1;
        (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_- 1));
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument3.ArgMnemonic, "%.2X", *((BYTE*) (EIP_- 1)));
        (*pMyDisasm).Argument3.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument3.ArgSize = 8;
        ImmediatSize = 8;
        FillFlags(pMyDisasm, 38);
    }
    else {
        OpSize = 102;
        MOD_RM(&(*pMyDisasm).Argument2);
        Reg_Opcode(&(*pMyDisasm).Argument1);
        EIP_+= DECALAGE_EIP + 3;
        if (!Security(0)) return;
        third_arg = 1;
        (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_- 1));
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument3.ArgMnemonic, "%.2X", *((BYTE*) (EIP_- 1)));
        (*pMyDisasm).Argument3.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument3.ArgSize = 8;
        ImmediatSize = 8;
        FillFlags(pMyDisasm, 38);
    }
}

// =======================================
//      0fafh
// =======================================
void __stdcall imul_GvEv(PDISASM pMyDisasm)
{

    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "imul ");
    GvEv(pMyDisasm);
    FillFlags(pMyDisasm,38);
}

// =======================================
//      70h
// =======================================
void __stdcall jo_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JO;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jo ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      71h
// =======================================
void __stdcall jno_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNO;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jno ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      72h
// =======================================
void __stdcall jc_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JC;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jc ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      73h
// =======================================
void __stdcall jnc_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNC;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jnc ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}
// =======================================
//      74h
// =======================================
void __stdcall je_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "je ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      75h
// =======================================
void __stdcall jne_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jne ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      76h
// =======================================
void __stdcall jbe_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JB;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jbe ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      77h
// =======================================
void __stdcall jnbe_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNB;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jnbe ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      78h
// =======================================
void __stdcall js_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JS;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "js ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      79h
// =======================================
void __stdcall jns_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNS;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jns ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      7ah
// =======================================
void __stdcall jp_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JP;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jp ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      7bh
// =======================================
void __stdcall jnp_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNP;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jnp ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      7ch
// =======================================
void __stdcall jl_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JL;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jl ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      7dh
// =======================================
void __stdcall jnl_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNL;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jnl ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      7eh
// =======================================
void __stdcall jle_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JL;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jle ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}

// =======================================
//      7fh
// =======================================
void __stdcall jnle_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNL;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jnle ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}


// =======================================
//      0f80h
// =======================================
void __stdcall jo_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JO;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jo ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}


// =======================================
//      0f81h
// =======================================
void __stdcall jno_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNO;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jno ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f82h
// =======================================
void __stdcall jc_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JC;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jc ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f83h
// =======================================
void __stdcall jnc_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNC;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jnc ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f84h
// =======================================
void __stdcall je_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "je ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f85h
// =======================================
void __stdcall jne_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jne ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}
// =======================================
//      0f86h
// =======================================
void __stdcall jbe_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JB;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jbe ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}


// =======================================
//      0f87h
// =======================================
void __stdcall ja_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JA;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ja ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f88h
// =======================================
void __stdcall js_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JS;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "js ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f89h
// =======================================
void __stdcall jns_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNS;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jns ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f8ah
// =======================================
void __stdcall jp_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JP;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jp ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f8bh
// =======================================
void __stdcall jnp_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNP;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jnp ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f8ch
// =======================================
void __stdcall jl_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JL;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jl ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f8dh
// =======================================
void __stdcall jnl_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNL;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jnl ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f8eh
// =======================================
void __stdcall jle_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNG;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jng ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0f8fh
// =======================================
void __stdcall jnle_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JG;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jg ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 6 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 4 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0e3h
// =======================================
void __stdcall jecxz_(PDISASM pMyDisasm)
{
    long long MyAddress;
    signed long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JECXZ;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jecxz ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SBYTE*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=2;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SBYTE*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=2;
        FillFlags(pMyDisasm,49);
    }
}

// =======================================
//      0e9h
// =======================================
void __stdcall jmp_near(PDISASM pMyDisasm)
{
    long long MyAddress;
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JmpType;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jmp ");
    if (OperandSize >= 32) {
        if (!Security(5)) return;
        MyNumber = *((SDWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 5 + MyNumber);
        if (MyAddress >= 0x100000000) {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
        }
        else {
            (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
        }
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=5;
        FillFlags(pMyDisasm,49);
    }
    else {
        if (!Security(3)) return;
        MyNumber = *((SWORD*) (EIP_+1));
        CalculateRelativeAddress(&MyAddress, NB_PREFIX + 3 + MyNumber);
        MyAddress = MyAddress & 0xffff;
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
        (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
        (*pMyDisasm).Instruction.AddrValue = MyAddress;
        EIP_+=3;
        FillFlags(pMyDisasm,49);
    }
}


// =======================================
//      0ebh
// =======================================
void __stdcall jmp_short(PDISASM pMyDisasm)
{
    long long MyAddress = 0;
    signed long MyNumber = 0;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JmpType;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jmp ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (OperandSize == 16) MyAddress = MyAddress & 0xffff;
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.ArgType = CONSTANT_TYPE + RELATIVE_;
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm,49);
}


// =======================================
//
// =======================================
void __stdcall jmp_far(PDISASM pMyDisasm)
{
    long MyNumber;
    int i = 0;
    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
        (*pMyDisasm).Instruction.BranchType = CallType;
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ljmp ");
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic,"$");
            i++;
        }
        else {
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "jmp far ");
        }
        if (OperandSize ==32) {
            if (!Security(7)) return;
            MyNumber = *((WORD*) (EIP_+5));
            i += CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic+i, "%.4X", MyNumber);
        }
        else {
            if (!Security(5)) return;
            MyNumber = *((WORD*) (EIP_+3));
            i += CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic+i, "%.4X", MyNumber);
        }
        if (SYNTAX_ == ATSyntax) {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic+i, " , $");
            i+=4;
        }
        else {
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic+i, " : ");
            i+=3;
        }
        MyNumber = *((DWORD*) (EIP_+1));
        if (OperandSize == 16) {
            MyNumber = MyNumber & 0xffff;
        }
        i += CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic+i, "%.8X", MyNumber);
        if (OperandSize == 32) {
            EIP_+=7;
        }
        else {
            EIP_+=5;
        }
    }
}

// =======================================
//
// =======================================
void __stdcall lahf_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + FLAG_CONTROL_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lahf ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SPECIAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall lar_GvEw(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lar ");
    GvEw(pMyDisasm);
    FillFlags(pMyDisasm, 53);
}

// =======================================
//
// =======================================
void __stdcall lds_GvM(PDISASM pMyDisasm)
{

    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SEGMENT_REGISTER;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lds ");
        if (OperandSize == 32) {
            OpSize = 107;
            MOD_RM(&(*pMyDisasm).Argument2);
            Reg_Opcode(&(*pMyDisasm).Argument1);
            EIP_+= DECALAGE_EIP + 2;
        }
        else {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            Reg_Opcode(&(*pMyDisasm).Argument1);
            EIP_+= DECALAGE_EIP + 2;
        }
    }
}

// =======================================
//      0c9h
// =======================================
void __stdcall leave_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "leave ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG4;
    (*pMyDisasm).Argument1.ArgSize = 32;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + SPECIAL_REG + REG5;
    (*pMyDisasm).Argument2.ArgSize = 32;
    EIP_++;
}

// =======================================
//
// =======================================
void __stdcall lea_GvM(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + MISCELLANEOUS_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lea ");
    if (OperandSize >= 32) {
        if (OperandSize == 64) {
            OpSize = 104;
        }
        else {
            OpSize = 103;
        }
        MOD_RM(&(*pMyDisasm).Argument2);
        Reg_Opcode(&(*pMyDisasm).Argument1);
        EIP_+= DECALAGE_EIP + 2;
    }
    else {
        OpSize = 102;
        MOD_RM(&(*pMyDisasm).Argument2);
        Reg_Opcode(&(*pMyDisasm).Argument1);
        EIP_+= DECALAGE_EIP + 2;
    }

}

// =======================================
//
// =======================================
void __stdcall les_GvM(PDISASM pMyDisasm)
{

    if (Architecture == 64) {
        FailDecode(pMyDisasm);
    }
    else {
        (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SEGMENT_REGISTER;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "les ");
        if (OperandSize == 32) {
            OpSize = 107;
            MOD_RM(&(*pMyDisasm).Argument2);
            Reg_Opcode(&(*pMyDisasm).Argument1);
            EIP_+= DECALAGE_EIP + 2;
        }
        else {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            Reg_Opcode(&(*pMyDisasm).Argument1);
            EIP_+= DECALAGE_EIP + 2;
        }
    }
}

// =======================================
//      0ach
// =======================================
void __stdcall lodsb_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lodsb ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG6;
    EIP_++;
    FillFlags(pMyDisasm, 59);
}

// =======================================
//      0adh
// =======================================
void __stdcall lodsw_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lodsq ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG6;
        EIP_++;
        FillFlags(pMyDisasm, 59);
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lodsd ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG6;
        EIP_++;
        FillFlags(pMyDisasm, 59);
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lodsw ");
        (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG6;
        EIP_++;
        FillFlags(pMyDisasm, 59);
    }
}

// =======================================
//      0adh
// =======================================
void __stdcall loop_(PDISASM pMyDisasm)
{
    signed long MyNumber;
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "loop ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG1;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm, 60);
}

// =======================================
//
// =======================================
void __stdcall loopne_(PDISASM pMyDisasm)
{
    signed long MyNumber;
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JNE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "loopne ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG1;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm, 61);
}

// =======================================
//
// =======================================
void __stdcall loope_(PDISASM pMyDisasm)
{
    signed long MyNumber;
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + CONTROL_TRANSFER;
    (*pMyDisasm).Instruction.BranchType = JE;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "loope ");
    if (!Security(1)) return;
    MyNumber = *((SBYTE*) (EIP_+1));
    CalculateRelativeAddress(&MyAddress, NB_PREFIX + 2 + MyNumber);
    if (MyAddress >= 0x100000000) {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
    }
    else {
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
    }
    (*pMyDisasm).Argument1.AccessMode = READ;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG1;
    (*pMyDisasm).Instruction.AddrValue = MyAddress;
    EIP_+=2;
    FillFlags(pMyDisasm, 61);
}

// =======================================
//
// =======================================
void __stdcall lsl_GvEw(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lsl ");
    GvEw(pMyDisasm);
    FillFlags(pMyDisasm, 62);
}

// =======================================
//
// =======================================
void __stdcall lss_Mp(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SEGMENT_REGISTER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lss ");
    GvEv(pMyDisasm);
}

// =======================================
//
// =======================================
void __stdcall lfs_Mp(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SEGMENT_REGISTER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lfs ");
    GvEv(pMyDisasm);
}

// =======================================
//
// =======================================
void __stdcall lgs_Mp(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + SEGMENT_REGISTER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lgs ");
    GvEv(pMyDisasm);
}

// =======================================
//
// =======================================
void __stdcall mov_RdCd(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    MOD_RM(&(*pMyDisasm).Argument1);
    if (MOD_ == 3) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
        CR_ = 1;
        Reg_Opcode(&(*pMyDisasm).Argument2);
        CR_ = 0;
        FillFlags(pMyDisasm,67);
        EIP_ += DECALAGE_EIP + 2;
    }
    else {
        FailDecode(pMyDisasm);
    }
}


// =======================================
//
// =======================================
void __stdcall mov_RdDd(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    MOD_RM(&(*pMyDisasm).Argument1);
    if (MOD_ == 3) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
        DR_ = 1;
        Reg_Opcode(&(*pMyDisasm).Argument2);
        DR_ = 0;
        FillFlags(pMyDisasm,67);
        EIP_ += DECALAGE_EIP + 2;
    }
    else {
        FailDecode(pMyDisasm);
    }
}

// =======================================
//
// =======================================
void __stdcall mov_CdRd(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    MOD_RM(&(*pMyDisasm).Argument2);
    if (MOD_ == 3) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
        CR_ = 1;
        Reg_Opcode(&(*pMyDisasm).Argument1);
        CR_ = 0;
        FillFlags(pMyDisasm,67);
        EIP_ += DECALAGE_EIP + 2;
    }
    else {
        FailDecode(pMyDisasm);
    }
}

// =======================================
//
// =======================================
void __stdcall mov_DdRd(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    MOD_RM(&(*pMyDisasm).Argument2);
    if (MOD_ == 3) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
        DR_ = 1;
        Reg_Opcode(&(*pMyDisasm).Argument1);
        DR_ = 0;
        FillFlags(pMyDisasm,67);
        EIP_ += DECALAGE_EIP + 2;
    }
    else {
        FailDecode(pMyDisasm);
    }
}

// =======================================
//      88h
// =======================================
void __stdcall mov_EbGb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    EbGb(pMyDisasm);
}

// =======================================
//      89h
// =======================================
void __stdcall mov_EvGv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    EvGv(pMyDisasm);
}

// =======================================
//      8ah
// =======================================
void __stdcall mov_GbEb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    GbEb(pMyDisasm);
}

// =======================================
//      8bh
// =======================================
void __stdcall mov_GvEv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    GvEv(pMyDisasm);
}

// =======================================
//      0a0h
// =======================================
void __stdcall mov_ALOb(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    OpSize = 101;
    RM_ = 5;
    MOD_ = 0;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE ;
    (*pMyDisasm).Argument2.ArgSize = 8;
    if (AddressSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Argument2.Memory.Displacement = MyAddress;
    }
    else if (AddressSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Argument2.Memory.Displacement = MyAddress;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Argument2.Memory.Displacement = MyAddress;
    }

    if (REX.B_ == 0) {
        (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers8Bits[0]);
    }
    else {
        (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers8Bits[0+8]);
    }

}

// =======================================
//      0a1h
// =======================================
void __stdcall mov_eAXOv(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    RM_ = 5;
    MOD_ = 0;
    if (AddressSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Argument2.Memory.Displacement = MyAddress;
    }
    else if (AddressSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Argument2.Memory.Displacement = MyAddress;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Argument2.Memory.Displacement = MyAddress;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            OpSize = 104;
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        }
        else if (OperandSize == 32) {
            OpSize = 103;
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        }
        else {
            OpSize = 102;
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        }
    }
    else {
        if (OperandSize == 64) {
            OpSize = 104;
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0+8]);
        }
        else if (OperandSize == 32) {
            OpSize = 103;
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0+8]);
        }
        else {
            OpSize = 102;
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0+8]);
        }
    }
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE ;
    if (OpSize == 104) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OpSize == 103) {
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else if (OpSize == 102) {
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

}

// =======================================
//      0a2h
// =======================================
void __stdcall mov_ObAL(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    OpSize = 1;
    RM_ = 5;
    MOD_ = 0;
    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE ;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgSize = 8;
    if (AddressSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Argument1.Memory.Displacement = MyAddress;
    }
    else if (AddressSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Argument1.Memory.Displacement = MyAddress;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Argument1.Memory.Displacement = MyAddress;
    }

    if (REX.B_ == 0) {
        (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers8Bits[0]);
    }
    else {
        (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers8Bits[0+8]);
    }

}

// =======================================
//      0a3h
// =======================================
void __stdcall mov_OveAX(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    RM_ = 5;
    MOD_ = 0;
    if (AddressSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Argument1.Memory.Displacement = MyAddress;
    }
    else if (AddressSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Argument1.Memory.Displacement = MyAddress;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument1.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Argument1.Memory.Displacement = MyAddress;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            OpSize = 4;
            (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[0]);
        }
        else if (OperandSize == 32) {
            OpSize = 3;
            (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[0]);
        }
        else {
            OpSize = 2;
            (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[0]);
        }
    }
    else {
        if (OperandSize == 64) {
            OpSize = 4;
            (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers64Bits[0+8]);
        }
        else if (OperandSize == 32) {
            OpSize = 3;
            (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers32Bits[0+8]);
        }
        else {
            OpSize = 2;
            (void) strcpy ((char*) (*pMyDisasm).Argument2.ArgMnemonic, Registers16Bits[0+8]);
        }
    }

    (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE ;
    if (OpSize == 104) {
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OpSize == 103) {
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else if (OpSize == 102) {
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
}

// =======================================
//      0b0h
// =======================================
void __stdcall mov_ALIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    ALIb(pMyDisasm);
}

// =======================================
//      0b1h
// =======================================
void __stdcall mov_CLIb(PDISASM pMyDisasm)
{
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers8BitsLegacy[1]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}

// =======================================
//      0b2h
// =======================================
void __stdcall mov_DLIb(PDISASM pMyDisasm)
{
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers8BitsLegacy[2]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}

// =======================================
//      0b3h
// =======================================
void __stdcall mov_BLIb(PDISASM pMyDisasm)
{
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers8BitsLegacy[3]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG3;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}

// =======================================
//      0b4h
// =======================================
void __stdcall mov_AHIb(PDISASM pMyDisasm)
{
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers8BitsLegacy[4]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}

// =======================================
//      0b5h
// =======================================
void __stdcall mov_CHIb(PDISASM pMyDisasm)
{
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers8BitsLegacy[5]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}

// =======================================
//      0b6h
// =======================================
void __stdcall mov_DHIb(PDISASM pMyDisasm)
{
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers8BitsLegacy[6]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}

// =======================================
//      0b7h
// =======================================
void __stdcall mov_BHIb(PDISASM pMyDisasm)
{
    long MyNumber;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers8BitsLegacy[7]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG3;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}


// =======================================
//      0a4h
// =======================================
void __stdcall movs_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movsb ");
    (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
    (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
    (*pMyDisasm).Argument2.ArgSize = 8;
    (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG6 + REG7;
    EIP_++;
    FillFlags(pMyDisasm, 68);
}

// =======================================
//      0a5h
// =======================================
void __stdcall movsw_(PDISASM pMyDisasm)
{
    if ((*pMyDisasm).Prefix.RepnePrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepnePrefix = InUsePrefix;
    }
    if ((*pMyDisasm).Prefix.RepPrefix == SuperfluousPrefix) {
        (*pMyDisasm).Prefix.RepPrefix = InUsePrefix;
    }
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION;
    if (OperandSize == 64) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movsq ");
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
        (*pMyDisasm).Argument2.ArgSize = 64;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG6 + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 68);
    }
    else if (OperandSize == 32) {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movsd ");
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG6 + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 68);
    }
    else {
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movsw ");
        (*pMyDisasm).Argument1.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument1.Memory.BaseRegister = REG7;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgType = MEMORY_TYPE;
        (*pMyDisasm).Argument2.Memory.BaseRegister = REG6;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Instruction.ImplicitModifiedRegs = GENERAL_REG + REG6 + REG7;
        EIP_++;
        FillFlags(pMyDisasm, 68);
    }
}

// =======================================
//      0fb6h
// =======================================
void __stdcall movzx_GvEb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movzx ");
    GvEb(pMyDisasm);
}


// =======================================
//      0fbeh
// =======================================
void __stdcall movsx_GvEb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movsx ");
    GvEb(pMyDisasm);
}

// =======================================
//      0fbfh
// =======================================
void __stdcall movsx_GvEw(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movsx ");
    GvEw(pMyDisasm);
}

// =======================================
//      0fb7h
// =======================================
void __stdcall movzx_GvEw(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movzx ");
    GvEw(pMyDisasm);
}

// =======================================
//      0b8h
// =======================================
void __stdcall mov_EAX(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
        EIP_+=9;
        (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        }
    }
    else {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0+8]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0+8]);
        }
    }

}

// =======================================
//      0b9h
// =======================================
void __stdcall mov_ECX(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG1;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
        (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
        EIP_+=9;
        (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[1+0]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[1+0]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[1+0]);
        }
    }
    else {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[1+0+8]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[1+0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[1+0+8]);
        }
    }

}

// =======================================
//      0bah
// =======================================
void __stdcall mov_EDX(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG2;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[2+0]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[2+0]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[2+0]);
        }
    }
    else {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[2+0+8]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[2+0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[2+0+8]);
        }
    }

}

// =======================================
//      0bbh
// =======================================
void __stdcall mov_EBX(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG3;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[3+0]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[3+0]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[3+0]);
        }
    }
    else {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[3+0+8]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[3+0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[3+0+8]);
        }
    }

}

// =======================================
//      0bch
// =======================================
void __stdcall mov_ESP(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG4;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[4+0]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[4+0]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[4+0]);
        }
    }
    else {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[4+0+8]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[4+0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[4+0+8]);
        }
    }

}

// =======================================
//      0bdh
// =======================================
void __stdcall mov_EBP(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG5;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[5+0]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[5+0]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[5+0]);
        }
    }
    else {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[5+0+8]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[5+0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[5+0+8]);
        }
    }

}

// =======================================
//      0beh
// =======================================
void __stdcall mov_ESI(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG6;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[6+0]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[6+0]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[6+0]);
        }
    }
    else {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[6+0+8]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[6+0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[6+0+8]);
        }
    }

}

// =======================================
//      0bfh
// =======================================
void __stdcall mov_EDI(PDISASM pMyDisasm)
{
    long long MyAddress;
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG7;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(9)) return;
        MyAddress = *((unsigned long long *) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%I64X", MyAddress);
       EIP_+=9;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        MyAddress = *((DWORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.8X", MyAddress);
       EIP_+=5;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else {
        if (!Security(3)) return;
        MyAddress = *((WORD*) (EIP_+1));
       (void) CopyFormattedNumber((char*) (*pMyDisasm).Argument2.ArgMnemonic, "%.4X", MyAddress);
       EIP_+=3;
       (*pMyDisasm).Instruction.Immediat = MyAddress;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
    }

    if (REX.B_ == 0) {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[7+0]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[7+0]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[7+0]);
        }
    }
    else {
        if (OperandSize == 64) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[7+0+8]);
        }
        else if (OperandSize == 32) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[7+0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[7+0+8]);
        }
    }

}
// =======================================
//      0c6h
// =======================================
void __stdcall mov_EbIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    EbIb(pMyDisasm);
}

// =======================================
//      0c7h
// =======================================
void __stdcall mov_EvIv(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    EvIv(pMyDisasm);
}

// =======================================
//      08ch
// =======================================
void __stdcall mov_EwSreg(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    OpSize = 2;
    OperandSize = 16;
    MOD_RM(&(*pMyDisasm).Argument1);
    OperandSize = 32;
    SEG_ = 1;
    Reg_Opcode(&(*pMyDisasm).Argument2);
    SEG_ = 0;
    EIP_ += DECALAGE_EIP + 2;
}

// =======================================
//      08eh
// =======================================
void __stdcall mov_SregEw(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = GENERAL_PURPOSE_INSTRUCTION + DATA_TRANSFER;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mov ");
    OpSize = 102;
    OperandSize = 16;
    MOD_RM(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    SEG_ = 1;
    Reg_Opcode(&(*pMyDisasm).Argument1);
    SEG_ = 0;
    EIP_ += DECALAGE_EIP + 2;
}
