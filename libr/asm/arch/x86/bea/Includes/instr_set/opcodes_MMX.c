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

void __stdcall emms_(PDISASM pMyDisasm)
{
	(*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + STATE_MANAGEMENT;
    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "emms ");
	EIP_++;
}

// ====================================================================
//      0x 0f 7e
// ====================================================================
void __stdcall movd_EP(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + DATA_TRANSFER;
    // ========= 0xf3
    if (PrefRepe == 1) {
        (*pMyDisasm).Prefix.RepPrefix = MandatoryPrefix;
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq ");
        SSE_ = 1;
        MOD_RM(&(*pMyDisasm).Argument2);
        Reg_Opcode(&(*pMyDisasm).Argument1);
        SSE_ = 0;
        EIP_+= DECALAGE_EIP + 2;
    }
    // ========== 0x66
    else if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        if (REX.W_ == 1) {
            OpSize = 4;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq ");
            MOD_RM(&(*pMyDisasm).Argument1);
            SSE_ = 1;
            Reg_Opcode(&(*pMyDisasm).Argument2);
            SSE_ = 0;
            EIP_+= DECALAGE_EIP + 2;
        }
        else {
            OpSize = 3;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movd ");
            MOD_RM(&(*pMyDisasm).Argument1);
            SSE_ = 1;
            Reg_Opcode(&(*pMyDisasm).Argument2);
            SSE_ = 0;
            EIP_+= DECALAGE_EIP + 2;
        }
    }
    else {
        if (REX.W_ == 1) {
            OpSize = 4;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq ");
            MOD_RM(&(*pMyDisasm).Argument1);
            MMX_ = 1;
            Reg_Opcode(&(*pMyDisasm).Argument2);
            MMX_ = 0;
            EIP_+= DECALAGE_EIP + 2;
        }
        else {
            OpSize = 3;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movd ");
            MOD_RM(&(*pMyDisasm).Argument1);
            MMX_ = 1;
            Reg_Opcode(&(*pMyDisasm).Argument2);
            MMX_ = 0;
            EIP_+= DECALAGE_EIP + 2;
        }
    }
}


// ====================================================================
//      0x 0f 6e
// ====================================================================
void __stdcall movd_PE(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + DATA_TRANSFER;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        if (REX.W_ == 1) {
            OpSize = 104;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq ");
            MOD_RM(&(*pMyDisasm).Argument2);
            SSE_ = 1;
            Reg_Opcode(&(*pMyDisasm).Argument1);
            SSE_ = 0;
            EIP_+= DECALAGE_EIP + 2;
        }
        else {
            OpSize = 103;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movd ");
            MOD_RM(&(*pMyDisasm).Argument2);
            SSE_ = 1;
            Reg_Opcode(&(*pMyDisasm).Argument1);
            SSE_ = 0;
            EIP_+= DECALAGE_EIP + 2;
        }
    }
    else {
        if (REX.W_ == 1) {
            OpSize = 104;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq ");
            MOD_RM(&(*pMyDisasm).Argument2);
            MMX_ = 1;
            Reg_Opcode(&(*pMyDisasm).Argument1);
            MMX_ = 0;
            EIP_+= DECALAGE_EIP + 2;
        }
        else {
            OpSize = 103;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movd ");
            MOD_RM(&(*pMyDisasm).Argument2);
            MMX_ = 1;
            Reg_Opcode(&(*pMyDisasm).Argument1);
            MMX_ = 0;
            EIP_+= DECALAGE_EIP + 2;
        }
    }
}



// ====================================================================
//      0x 0f 6f
// ====================================================================
void __stdcall movq_PQ(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + DATA_TRANSFER;
    // ========= 0xf3
    if (PrefRepe == 1) {
        (*pMyDisasm).Prefix.RepPrefix = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movdqu ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    // ========== 0x66
    else if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movdqa ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}


// ====================================================================
//      0x 0f 7f
// ====================================================================
void __stdcall movq_QP(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + DATA_TRANSFER;
    // ========= 0xf3
    if (PrefRepe == 1) {
        (*pMyDisasm).Prefix.RepPrefix = MandatoryPrefix;
        OpSize = 8;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movdqu ");
        SSE_ = 1;
        ExGx(pMyDisasm);
        SSE_ = 0;
    }
    // ========== 0x66
    else if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 8;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movdqa ");
        SSE_ = 1;
        ExGx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 4;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq ");
        MMX_ = 1;
        ExGx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f d6
// ====================================================================
void __stdcall movq_WV(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + DATA_TRANSFER;
    // ========= 0xf2
    if (PrefRepne == 1) {
        (*pMyDisasm).Prefix.RepnePrefix = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movdq2q ");
        MMX_ = 1;
        Reg_Opcode(&(*pMyDisasm).Argument1);
        MMX_ = 0;
        SSE_ = 1;
        MOD_RM(&(*pMyDisasm).Argument2);
        SSE_ = 0;
        EIP_+= DECALAGE_EIP + 2;

    }
    // ========= 0xf3
    else if (PrefRepe == 1) {
        (*pMyDisasm).Prefix.RepPrefix = MandatoryPrefix;
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq2dq ");
        MMX_ = 1;
        Reg_Opcode(&(*pMyDisasm).Argument1);
        MMX_ = 0;
        SSE_ = 1;
        MOD_RM(&(*pMyDisasm).Argument2);
        SSE_ = 0;
        EIP_+= DECALAGE_EIP + 2;
    }
    // ========== 0x66
    else if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 4;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "movq ");
        SSE_ = 1;
        ExGx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        FailDecode(pMyDisasm);
    }
}


// ====================================================================
//      0x 0f 38 1c
// ====================================================================
void __stdcall pabsb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pabsb ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pabsb ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 38 1e
// ====================================================================
void __stdcall pabsd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pabsd ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pabsd ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 38 1d
// ====================================================================
void __stdcall pabsw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pabsw ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pabsw ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 63
// ====================================================================
void __stdcall packsswb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "packsswb ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "packsswb ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 6b
// ====================================================================
void __stdcall packssdw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "packssdw ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "packssdw ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 67
// ====================================================================
void __stdcall packuswb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "packuswb ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "packuswb ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f fc
// ====================================================================
void __stdcall paddb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddb ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddb ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f fd
// ====================================================================
void __stdcall paddw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddw ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddw ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f fe
// ====================================================================
void __stdcall paddd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddd ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddd ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f ec
// ====================================================================
void __stdcall paddsb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddsb ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddsb ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f ed
// ====================================================================
void __stdcall paddsw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddsw ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddsw ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f dc
// ====================================================================
void __stdcall paddusb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddusb ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddusb ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f dd
// ====================================================================
void __stdcall paddusw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddusw ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "paddusw ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f db
// ====================================================================
void __stdcall pand_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + LOGICAL_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pand ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pand ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}
// ====================================================================
//      0x 0f df
// ====================================================================
void __stdcall pandn_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + LOGICAL_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pandn ");
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pandn ");
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 74
// ====================================================================
void __stdcall pcmpeqb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + COMPARISON_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpeqb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpeqb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 75
// ====================================================================
void __stdcall pcmpeqw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + COMPARISON_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpeqw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpeqw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 76
// ====================================================================
void __stdcall pcmpeqd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + COMPARISON_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpeqd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpeqd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 64
// ====================================================================
void __stdcall pcmpgtb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + COMPARISON_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpgtb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpgtb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 65
// ====================================================================
void __stdcall pcmpgtw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + COMPARISON_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpgtw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpgtw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 66
// ====================================================================
void __stdcall pcmpgtd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + COMPARISON_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpgtd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pcmpgtd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f e5
// ====================================================================
void __stdcall pmulhw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pmulhw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pmulhw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f d5
// ====================================================================
void __stdcall pmullw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pmullw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pmullw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f f5
// ====================================================================
void __stdcall pmaddwd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pmaddwd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pmaddwd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f eb
// ====================================================================
void __stdcall por_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + LOGICAL_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "por ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "por ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f f1
// ====================================================================
void __stdcall psllw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + SHIFT_ROTATE;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psllw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psllw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f f2
// ====================================================================
void __stdcall pslld_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + SHIFT_ROTATE;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pslld ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pslld ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f f3
// ====================================================================
void __stdcall psllq_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + SHIFT_ROTATE;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psllq ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psllq ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f d1
// ====================================================================
void __stdcall psrlw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + SHIFT_ROTATE;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psrlw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psrlw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f d2
// ====================================================================
void __stdcall psrld_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + SHIFT_ROTATE;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psrld ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psrld ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f d3
// ====================================================================
void __stdcall psrlq_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + SHIFT_ROTATE;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psrlq ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psrlq ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f e1
// ====================================================================
void __stdcall psraw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + SHIFT_ROTATE;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psraw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psraw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f e2
// ====================================================================
void __stdcall psrad_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + SHIFT_ROTATE;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psrad ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psrad ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f f8
// ====================================================================
void __stdcall psubb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f f9
// ====================================================================
void __stdcall psubw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f fa
// ====================================================================
void __stdcall psubd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f e8
// ====================================================================
void __stdcall psubsb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubsb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubsb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f e9
// ====================================================================
void __stdcall psubsw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubsw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubsw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f d8
// ====================================================================
void __stdcall psubusb_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubusb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubusb ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f d9
// ====================================================================
void __stdcall psubusw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + ARITHMETIC_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubusw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "psubusw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 68
// ====================================================================
void __stdcall punpckhbw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpckhbw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpckhbw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 69
// ====================================================================
void __stdcall punpckhwd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpckhwd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpckhwd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 6a
// ====================================================================
void __stdcall punpckhdq_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpckhdq ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpckhdq ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 60
// ====================================================================
void __stdcall punpcklbw_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpcklbw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpcklbw ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 61
// ====================================================================
void __stdcall punpcklwd_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpcklwd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpcklwd ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f 62
// ====================================================================
void __stdcall punpckldq_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + CONVERSION_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpckldq ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "punpckldq ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}

// ====================================================================
//      0x 0f ef
// ====================================================================
void __stdcall pxor_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = MMX_INSTRUCTION + LOGICAL_INSTRUCTION;
    // ========== 0x66
    if (OperandSize == 16) {
        (*pMyDisasm).Prefix.OperandSize = MandatoryPrefix;
        OpSize = 108;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pxor ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        SSE_ = 1;
        GxEx(pMyDisasm);
        SSE_ = 0;
    }
    else {
        OpSize = 104;
        (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "pxor ");
        (*pMyDisasm).Argument1.AccessMode = READ;
        MMX_ = 1;
        GxEx(pMyDisasm);
        MMX_ = 0;
    }
}
