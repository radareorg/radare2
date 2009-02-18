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
int __stdcall Disasm (PDISASM pMyDisasm) {

    InitVariables(pMyDisasm);
    (void) AnalyzeOpcode(pMyDisasm);
    FixArgSizeForMemoryOperand(pMyDisasm);
    FixREXPrefixes(pMyDisasm);
    FillSegmentsRegisters(pMyDisasm);
    if (SYNTAX_ == ATSyntax) {
        BuildCompleteInstructionATSyntax(pMyDisasm);
    }
    else {
        BuildCompleteInstruction(pMyDisasm);
    }
    if (ERROR_OPCODE) {
        return -1;
    }
    else {
        return EIP_ - (*pMyDisasm).EIP;
    }
}

// ====================================================================
//
// ====================================================================
void __stdcall InitVariables (PDISASM pMyDisasm) {
    ERROR_OPCODE = 0;
    EIP_ = (*pMyDisasm).EIP;
    EIP_REAL = EIP_;
    EIP_VA = (*pMyDisasm).VirtualAddr;
    EndOfBlock = 0;
    if ((*pMyDisasm).SecurityBlock != 0) EndOfBlock = EIP_ + (*pMyDisasm).SecurityBlock;
    OperandSize = 32;
    OpSize = 0;
    AddressSize = 32;
    SEGMENTFS = 0;
    third_arg = 0;
    Architecture = (*pMyDisasm).Archi;
    (*pMyDisasm).Prefix.Number = 0;
    NB_PREFIX = 0;
    if (Architecture == 64) AddressSize = 64;
	(void) memset (&(*pMyDisasm).Argument1, 0, sizeof (ARGTYPE));
	(void) memset (&(*pMyDisasm).Argument2, 0, sizeof (ARGTYPE));
	(void) memset (&(*pMyDisasm).Argument3, 0, sizeof (ARGTYPE));
    (void) memset (&(*pMyDisasm).Prefix, 0, sizeof (PREFIXINFO));
    REX.W_ = 0;
    REX.B_ = 0;
    REX.X_ = 0;
    REX.R_ = 0;
    REX.state = 0;
    (*pMyDisasm).Argument1.AccessMode = WRITE;
    (*pMyDisasm).Argument2.AccessMode = READ;
    (*pMyDisasm).Argument3.AccessMode = READ;
    (void) memset (&(*pMyDisasm).Instruction, 0, sizeof (INSTRTYPE));
    TAB_ = (*pMyDisasm).Options & 0xff;
    SYNTAX_ = (*pMyDisasm).Options & 0xff00;
    FORMATNUMBER = (*pMyDisasm).Options & 0xff0000;
    SEGMENTREGS = (*pMyDisasm).Options & 0xff000000;

}
// ====================================================================
//
// ====================================================================
void __stdcall FixArgSizeForMemoryOperand (PDISASM pMyDisasm) {

    if (OpSize == 101) {
        (*pMyDisasm).Argument2.ArgSize = 8;
    }
    else if (OpSize == 102) {
        (*pMyDisasm).Argument2.ArgSize = 16;
    }
    else if (OpSize == 103) {
        (*pMyDisasm).Argument2.ArgSize = 32;
    }
    else if (OpSize == 104) {
        (*pMyDisasm).Argument2.ArgSize = 64;
    }
    else if (OpSize == 105) {
        (*pMyDisasm).Argument2.ArgSize = 0;
    }
    else if (OpSize == 106) {
        (*pMyDisasm).Argument2.ArgSize = 80;
    }
    else if (OpSize == 107) {
        (*pMyDisasm).Argument2.ArgSize = 48;
    }
    else if (OpSize == 108) {
        (*pMyDisasm).Argument2.ArgSize = 128;
    }


    if (OpSize == 1) {
        (*pMyDisasm).Argument1.ArgSize = 8;
    }
    else if (OpSize == 2) {
        (*pMyDisasm).Argument1.ArgSize = 16;
    }
    else if (OpSize == 3) {
        (*pMyDisasm).Argument1.ArgSize = 32;
    }
    else if (OpSize == 4) {
        (*pMyDisasm).Argument1.ArgSize = 64;
    }
    else if (OpSize == 5) {
        (*pMyDisasm).Argument1.ArgSize = 0;
    }
    else if (OpSize == 6) {
        (*pMyDisasm).Argument1.ArgSize = 80;
    }
    else if (OpSize == 7) {
        (*pMyDisasm).Argument1.ArgSize = 48;
    }
    else if (OpSize == 8) {
        (*pMyDisasm).Argument1.ArgSize = 128;
    }

}

// ====================================================================
//
// ====================================================================
void __stdcall FixREXPrefixes (PDISASM pMyDisasm) {

    (*pMyDisasm).Prefix.REX.W_ = REX.W_;
    (*pMyDisasm).Prefix.REX.R_ = REX.R_;
    (*pMyDisasm).Prefix.REX.X_ = REX.X_;
    (*pMyDisasm).Prefix.REX.B_ = REX.B_;
    (*pMyDisasm).Prefix.REX.state = REX.state;

}

// ====================================================================
//
// ====================================================================
int __stdcall AnalyzeOpcode (PDISASM pMyDisasm) {

    (*pMyDisasm).Instruction.Opcode = *((BYTE*) EIP_);
    (void) opcode_map1[*((BYTE*) EIP_)](pMyDisasm);
    return 1;
}
// ====================================================================
//
// ====================================================================
void __stdcall EbGb(PDISASM pMyDisasm)
{
    OpSize = 1;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument1);
    Reg_Opcode(&(*pMyDisasm).Argument2);
    OperandSize = 32;
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall GbEb(PDISASM pMyDisasm)
{
    OpSize = 101;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument2);
    Reg_Opcode(&(*pMyDisasm).Argument1);
    OperandSize = 32;
    EIP_ += DECALAGE_EIP + 2;
}
// ====================================================================
//
// ====================================================================
void __stdcall EvGv(PDISASM pMyDisasm)
{
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
    Reg_Opcode(&(*pMyDisasm).Argument2);
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall ExGx(PDISASM pMyDisasm)
{
    MOD_RM(&(*pMyDisasm).Argument1);
    Reg_Opcode(&(*pMyDisasm).Argument2);
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall EvIv(PDISASM pMyDisasm)
{
    if (OperandSize >= 32) {
        OpSize = 3;
        MOD_RM(&(*pMyDisasm).Argument1);
        EIP_ += DECALAGE_EIP + 6;
        if (!Security(0)) return;
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.8X",*((DWORD*) (EIP_ - 4)));
        ImmediatSize = 32;
        (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument2.ArgSize = 32;
        (*pMyDisasm).Instruction.Immediat = *((DWORD*) (EIP_ - 4));
    }
    else {
        OpSize = 2;
        MOD_RM(&(*pMyDisasm).Argument1);
        EIP_ += DECALAGE_EIP + 4;
        if (!Security(0)) return;
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.4X",*((WORD*) (EIP_ - 2)));
        ImmediatSize = 16;
        (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
        (*pMyDisasm).Argument2.ArgSize = 16;
        (*pMyDisasm).Instruction.Immediat = *((WORD*) (EIP_ - 2));
    }
}

// ====================================================================
//
// ====================================================================
void __stdcall EvIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    if (OperandSize >= 32) {
        OpSize = 3;
        MOD_RM(&(*pMyDisasm).Argument1);
        EIP_ += DECALAGE_EIP + 3;
        if (!Security(0)) return;
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X",*((BYTE*) (EIP_ - 1)));
        ImmediatSize = 8;
        (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_ - 1));
    }
    else {
        OpSize = 2;
        MOD_RM(&(*pMyDisasm).Argument1);
        EIP_ += DECALAGE_EIP + 3;
        if (!Security(0)) return;
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X",*((BYTE*) (EIP_ - 1)));
        ImmediatSize = 8;
        (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_ - 1));
    }
}
// ====================================================================
//
// ====================================================================
void __stdcall EbIb(PDISASM pMyDisasm)
{
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    OpSize = 1;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument1);
    OperandSize = 32;
    EIP_ += DECALAGE_EIP + 3;
    if (!Security(0)) return;
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X",*((BYTE*) (EIP_ - 1)));
    ImmediatSize = 8;
    (*pMyDisasm).Instruction.Immediat = *((BYTE*) (EIP_ - 1));
}

// ====================================================================
//
// ====================================================================
void __stdcall Eb(PDISASM pMyDisasm)
{
    OpSize = 1;
    OperandSize = 8;
    MOD_RM(&(*pMyDisasm).Argument1);
    OperandSize = 32;
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall Ev(PDISASM pMyDisasm)
{
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
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall GvEv(PDISASM pMyDisasm)
{
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
    Reg_Opcode(&(*pMyDisasm).Argument1);
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall GvEb(PDISASM pMyDisasm)
{
    if (OperandSize == 64) {
        OpSize = 101;
        OperandSize = 8;
        MOD_RM(&(*pMyDisasm).Argument2);
        OperandSize = 64;
    }
    else if (OperandSize == 32) {
        OpSize = 101;
        OperandSize = 8;
        MOD_RM(&(*pMyDisasm).Argument2);
        OperandSize = 32;
    }
    else {
        OpSize = 101;
        MOD_RM(&(*pMyDisasm).Argument2);
    }
    Reg_Opcode(&(*pMyDisasm).Argument1);
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall GxEx(PDISASM pMyDisasm)
{
    MOD_RM(&(*pMyDisasm).Argument2);
    Reg_Opcode(&(*pMyDisasm).Argument1);
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall GvEw(PDISASM pMyDisasm)
{
    OpSize = 102;
    MOD_RM(&(*pMyDisasm).Argument2);
    Reg_Opcode(&(*pMyDisasm).Argument1);
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall ALIb(PDISASM pMyDisasm)
{
    long MyNumber;
    if (!Security(2)) return;
    ImmediatSize = 8;
    MyNumber = *((BYTE*) (EIP_ + 1));
    (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.2X", MyNumber);
    (*pMyDisasm).Instruction.Immediat = MyNumber;
    (void) strcpy((char*) &(*pMyDisasm).Argument1.ArgMnemonic, Registers8Bits[0]);
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument1.ArgSize = 8;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    (*pMyDisasm).Argument2.ArgSize = 8;
    EIP_ += 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall eAX_Iv(PDISASM pMyDisasm)
{
    long MyNumber;
    (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + GENERAL_REG + REG0;
    (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
    if (OperandSize == 64) {
        if (!Security(5)) return;
        ImmediatSize = 32;
        (*pMyDisasm).Argument1.ArgSize = 64;
        (*pMyDisasm).Argument2.ArgSize = 32;
        MyNumber = *((DWORD*) (EIP_ + 1));
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.8X", MyNumber);
        (*pMyDisasm).Instruction.Immediat = MyNumber;
         if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers64Bits[0]);
        }
        EIP_+= 5;
    }
    else if (OperandSize == 32) {
        if (!Security(5)) return;
        ImmediatSize = 32;
        (*pMyDisasm).Argument1.ArgSize = 32;
        (*pMyDisasm).Argument2.ArgSize = 32;
        MyNumber = *((DWORD*) (EIP_ + 1));
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.8X", MyNumber);
        (*pMyDisasm).Instruction.Immediat = MyNumber;
         if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers32Bits[0]);
        }
        EIP_+= 5;
    }
    else {
        if (!Security(3)) return;
        ImmediatSize = 16;
        (*pMyDisasm).Argument1.ArgSize = 16;
        (*pMyDisasm).Argument2.ArgSize = 16;
        MyNumber = *((WORD*) (EIP_ + 1));
        (void) CopyFormattedNumber((char*) &(*pMyDisasm).Argument2.ArgMnemonic,"%.8X", MyNumber);
        (*pMyDisasm).Instruction.Immediat = MyNumber;
         if (REX.B_ == 1) {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0+8]);
        }
        else {
            (void) strcpy ((char*) (*pMyDisasm).Argument1.ArgMnemonic, Registers16Bits[0]);
        }
        EIP_+= 3;
    }

}

// ====================================================================
//
// ====================================================================
int __stdcall Security(int len)
{
    if ((EndOfBlock != 0) && (EIP_ + len > EndOfBlock)) {
        return 0;
    }
    return 1;
}

// ====================================================================
//
// ====================================================================
void __stdcall FillFlags(PDISASM pMyDisasm, int index)
{
    (*pMyDisasm).Instruction.Flags = EFLAGS_TABLE[index];
}
// ====================================================================
//
// ====================================================================
void __stdcall CalculateRelativeAddress(long long * pMyAddress, signed long MyNumber)
{
    RelativeAddress = 1;
    if (EIP_VA != 0) {
        *pMyAddress = EIP_VA + (long long) MyNumber;
    }
    else {
        *pMyAddress = EIP_REAL + (long long) MyNumber;
    }
}

// ====================================================================
//
// ====================================================================
int __stdcall CopyFormattedNumber(char* pBuffer,char* pFormat, long long MyNumber)
{
    int i = 0;
    if (FORMATNUMBER == PrefixedNumeral) {
        (void) strcpy(pBuffer, "0x");
        (void) sprintf (pBuffer+2, pFormat, MyNumber);
        i += strlen(pBuffer);
    }
    else {
        (void) sprintf (pBuffer+i, pFormat, MyNumber);
        i += strlen(pBuffer);
        (void) strcpy(pBuffer+i, "h");
        i++;
    }
    return i;
}

// ====================================================================
//
// ====================================================================
void __stdcall FillSegmentsRegisters(PDISASM pMyDisasm)
{
    if (((*pMyDisasm).Prefix.LockPrefix == InUsePrefix) && ((*pMyDisasm).Argument1.ArgType != MEMORY_TYPE)) {
        (*pMyDisasm).Prefix.LockPrefix = InvalidPrefix;
    }
    if ((*pMyDisasm).Instruction.Category == GENERAL_PURPOSE_INSTRUCTION + STRING_INSTRUCTION) {
        (*pMyDisasm).Argument1.SegmentReg = ESReg;
        (*pMyDisasm).Argument2.SegmentReg = DSReg;
        // =============== override affects Arg2
        if ((*pMyDisasm).Argument2.ArgType == MEMORY_TYPE) {
            if ((*pMyDisasm).Prefix.FSPrefix == InUsePrefix) {
                (*pMyDisasm).Argument2.SegmentReg = FSReg;
            }
            else if ((*pMyDisasm).Prefix.GSPrefix == InUsePrefix) {
                (*pMyDisasm).Argument2.SegmentReg = GSReg;
            }
            else if ((*pMyDisasm).Prefix.CSPrefix == InUsePrefix) {
                (*pMyDisasm).Argument2.SegmentReg = CSReg;
            }
            else if ((*pMyDisasm).Prefix.ESPrefix == InUsePrefix) {
                (*pMyDisasm).Argument2.SegmentReg = ESReg;
            }
            else if ((*pMyDisasm).Prefix.SSPrefix == InUsePrefix) {
                (*pMyDisasm).Argument2.SegmentReg = SSReg;
            }
            else {
                (*pMyDisasm).Argument2.SegmentReg = DSReg;
            }
        }
    }
    else {
        if ((*pMyDisasm).Argument1.ArgType == MEMORY_TYPE) {
            if (((*pMyDisasm).Argument1.Memory.BaseRegister == REG4) || ((*pMyDisasm).Argument1.Memory.BaseRegister == REG5)) {
                (*pMyDisasm).Argument1.SegmentReg = SSReg;
                // ========== override is invalid here
                if ((*pMyDisasm).Prefix.FSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = FSReg;
                    (*pMyDisasm).Prefix.FSPrefix = InvalidPrefix;
                }
                else if ((*pMyDisasm).Prefix.GSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = GSReg;
                    (*pMyDisasm).Prefix.GSPrefix = InvalidPrefix;
                }
                else if ((*pMyDisasm).Prefix.CSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = CSReg;
                    (*pMyDisasm).Prefix.CSPrefix = InvalidPrefix;
                }
                else if ((*pMyDisasm).Prefix.ESPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = ESReg;
                    (*pMyDisasm).Prefix.ESPrefix = InvalidPrefix;
                }
                else if ((*pMyDisasm).Prefix.SSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = SSReg;
                    (*pMyDisasm).Prefix.SSPrefix = InvalidPrefix;
                }
            }
            else {
                (*pMyDisasm).Argument1.SegmentReg = DSReg;
                // ============= test if there is override
                if ((*pMyDisasm).Prefix.FSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = FSReg;
                }
                else if ((*pMyDisasm).Prefix.GSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = GSReg;
                }
                else if ((*pMyDisasm).Prefix.CSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = CSReg;
                }
                else if ((*pMyDisasm).Prefix.ESPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = ESReg;
                }
                else if ((*pMyDisasm).Prefix.SSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument1.SegmentReg = SSReg;
                }
            }
        }

        if ((*pMyDisasm).Argument2.ArgType == MEMORY_TYPE) {
            if (((*pMyDisasm).Argument2.Memory.BaseRegister == REG4) || ((*pMyDisasm).Argument2.Memory.BaseRegister == REG5)) {
                (*pMyDisasm).Argument2.SegmentReg = SSReg;
                // ========== override is invalid here
                if ((*pMyDisasm).Prefix.FSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = FSReg;
                    (*pMyDisasm).Prefix.FSPrefix = InvalidPrefix;
                }
                else if ((*pMyDisasm).Prefix.GSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = GSReg;
                    (*pMyDisasm).Prefix.GSPrefix = InvalidPrefix;
                }
                else if ((*pMyDisasm).Prefix.CSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = CSReg;
                    (*pMyDisasm).Prefix.CSPrefix = InvalidPrefix;
                }
                else if ((*pMyDisasm).Prefix.ESPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = ESReg;
                    (*pMyDisasm).Prefix.ESPrefix = InvalidPrefix;
                }
                else if ((*pMyDisasm).Prefix.SSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = SSReg;
                    (*pMyDisasm).Prefix.SSPrefix = InvalidPrefix;
                }
            }
            else {
                (*pMyDisasm).Argument2.SegmentReg = DSReg;
                // ============= test if there is override
                if ((*pMyDisasm).Prefix.FSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = FSReg;
                }
                else if ((*pMyDisasm).Prefix.GSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = GSReg;
                }
                else if ((*pMyDisasm).Prefix.CSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = CSReg;
                }
                else if ((*pMyDisasm).Prefix.ESPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = ESReg;
                }
                else if ((*pMyDisasm).Prefix.SSPrefix == InUsePrefix) {
                    (*pMyDisasm).Argument2.SegmentReg = SSReg;
                }
            }
        }
    }
}
// ====================================================================
//
// ====================================================================
void __stdcall BuildCompleteInstruction(PDISASM pMyDisasm)
{
    int i = 0;
    // =============== Copy Instruction Mnemonic
    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr, (char*) &(*pMyDisasm).Instruction.Mnemonic);
    i = strlen((char*) &(*pMyDisasm).CompleteInstr);

    // =============== if TAB = 1, add tabulation
    if (TAB_ == 1) {
       (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, space_tab[10-i]);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
    }
    // =============== if Arg1.IsMemoryType, add decoration - example == "dword ptr ds:["
    if ((OpSize >0) && (OpSize < 99)) {
        if (SYNTAX_ == NasmSyntax) {
            (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, NasmPrefixes[OpSize-1]);
            i = strlen((char*) &(*pMyDisasm).CompleteInstr);
            if ((SEGMENTREGS != 0) || (SEGMENTFS != 0)){
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "[");
                i++;
                if (SEGMENTREGS != 0) {
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[(*pMyDisasm).Argument1.SegmentReg-1]);
                }
                else {
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[3]);
                }
                i = strlen((char*) &(*pMyDisasm).CompleteInstr);
            }
            else {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "[");
                i++;
            }
        }
        else {
            if (SYNTAX_ == MasmSyntax) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, MasmPrefixes[OpSize-1]);
                i = strlen((char*) &(*pMyDisasm).CompleteInstr);
            }
            else {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, GoAsmPrefixes[OpSize-1]);
                i = strlen((char*) &(*pMyDisasm).CompleteInstr);
            }
            if ((SEGMENTREGS != 0) || (SEGMENTFS != 0)){
                if (SEGMENTREGS != 0) {
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[(*pMyDisasm).Argument1.SegmentReg-1]);
                }
                else {
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[3]);
                }
                i = strlen((char*) &(*pMyDisasm).CompleteInstr);
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "[");
                i++;
            }
            else {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "[");
                i++;
            }
        }
        // =============== add Arg1.Mnemonic
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, (char*) &(*pMyDisasm).Argument1.ArgMnemonic);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "]");
        i++;
    }
    // =============== add Arg1.Mnemonic
    else {
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, (char*) &(*pMyDisasm).Argument1.ArgMnemonic);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
    }

    // =============== if Arg2.Exists and Arg1.Exists , add","
    if (((BYTE)*((BYTE*) &(*pMyDisasm).Argument1.ArgMnemonic) != 0) && ((BYTE)*((BYTE*) &(*pMyDisasm).Argument2.ArgMnemonic) != 0)) {
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, " , ");
        i += 3;
    }

    // =============== if Arg2.IsMemoryType, add decoration - example == "dword ptr ds:["
    if ((OpSize >100) && (OpSize < 199)) {
        OpSize -= 100;
        if (SYNTAX_ == NasmSyntax) {
            (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, NasmPrefixes[OpSize-1]);
            i = strlen((char*) &(*pMyDisasm).CompleteInstr);
            if ((SEGMENTREGS != 0) || (SEGMENTFS != 0)){
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "[");
                i++;
                if (SEGMENTREGS != 0) {
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[(*pMyDisasm).Argument2.SegmentReg-1]);
                }
                else {
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[3]);
                }
                i = strlen((char*) &(*pMyDisasm).CompleteInstr);
            }
            else {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "[");
                i++;
            }
        }
        else {
            if (SYNTAX_ == MasmSyntax) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, MasmPrefixes[OpSize-1]);
                i = strlen((char*) &(*pMyDisasm).CompleteInstr);
            }
            else {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, GoAsmPrefixes[OpSize-1]);
                i = strlen((char*) &(*pMyDisasm).CompleteInstr);
            }
            if ((SEGMENTREGS != 0) || (SEGMENTFS != 0)){
                if (SEGMENTREGS != 0) {
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[(*pMyDisasm).Argument2.SegmentReg-1]);
                }
                else {
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[3]);
                }
                i = strlen((char*) &(*pMyDisasm).CompleteInstr);
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "[");
                i++;
            }
            else {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "[");
                i++;
            }
        }
        // =============== add Arg2.ArgMnemonic
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, (char*) &(*pMyDisasm).Argument2.ArgMnemonic);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "]");
        i++;
    }
    // =============== add Arg2.ArgMnemonic
    else {
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, (char*) &(*pMyDisasm).Argument2.ArgMnemonic);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
    }


    // =============== if Arg3.Exists
    if (third_arg != 0) {
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, " , ");
        i += 3;
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, (char*) &(*pMyDisasm).Argument3.ArgMnemonic);
    }



}

// ====================================================================
//
// ====================================================================
void __stdcall BuildCompleteInstructionATSyntax(PDISASM pMyDisasm)
{
    int i = 0;
    // =============== Copy Instruction Mnemonic
    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr, (char*) &(*pMyDisasm).Instruction.Mnemonic);
    i = strlen((char*) &(*pMyDisasm).CompleteInstr);

    // =============== suffix the mnemonic
    if (OpSize != 0) {
        if (OpSize > 99) OpSize -= 100;
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[OpSize-1]);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
    }
    else {
        if ((*pMyDisasm).Argument1.ArgType != NO_ARGUMENT) {
            if ((*pMyDisasm).Argument1.ArgSize == 8) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[0]);
            }
            else if ((*pMyDisasm).Argument1.ArgSize == 16) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[1]);
            }
            else if ((*pMyDisasm).Argument1.ArgSize == 32) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[2]);
            }
            else if ((*pMyDisasm).Argument1.ArgSize == 64) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[3]);
            }
            i = strlen((char*) &(*pMyDisasm).CompleteInstr);
        }
        else if ((*pMyDisasm).Argument1.ArgType != NO_ARGUMENT) {
            if ((*pMyDisasm).Argument1.ArgSize == 8) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[0]);
            }
            else if ((*pMyDisasm).Argument1.ArgSize == 16) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[1]);
            }
            else if ((*pMyDisasm).Argument1.ArgSize == 32) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[2]);
            }
            else if ((*pMyDisasm).Argument1.ArgSize == 64) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i-1, ATSuffixes[3]);
            }
            i = strlen((char*) &(*pMyDisasm).CompleteInstr);
        }
    }
    // =============== if TAB = 1, add tabulation
    if (TAB_ == 1) {
       (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, space_tab[10-i]);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
    }

    // =============== if Arg3.Exists, display it
    if (third_arg != 0) {
        if ((*pMyDisasm).Argument3.ArgType & REGISTER_TYPE) {
            (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "%");
            i++;
        }
        else if ((*pMyDisasm).Argument3.ArgType & CONSTANT_TYPE) {
            (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "$");
            i++;
        }
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, (char*) &(*pMyDisasm).Argument3.ArgMnemonic);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
    }

    // =============== if Arg3.Exists and Arg2.Exists , display " , "
    if ((third_arg != 0) && (*((BYTE*) &(*pMyDisasm).Argument2.ArgMnemonic) != 0)) {
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, " , ");
        i += 3;
    }

    // =============== if Arg2 exists, display it
    if (*((BYTE*) &(*pMyDisasm).Argument2.ArgMnemonic) != 0) {
        if ((*pMyDisasm).Argument2.ArgType & CONSTANT_TYPE) {
            (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "$");
            i++;
        }
        else {
            if ((*pMyDisasm).Instruction.BranchType != 0) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "*");
                i++;
            }
            if ((*pMyDisasm).Argument2.ArgType & REGISTER_TYPE) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "%");
                i++;
            }
            else if ((*pMyDisasm).Argument2.ArgType & CONSTANT_TYPE) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "$");
                i++;
            }
            else {
                if ((SEGMENTREGS != 0) || (SEGMENTFS != 0)){
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "%");
                    i++;
                    if (SEGMENTREGS != 0) {
                        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[(*pMyDisasm).Argument2.SegmentReg-1]);
                    }
                    else {
                        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[3]);
                    }
                    i = strlen((char*) &(*pMyDisasm).CompleteInstr);
                }
            }
        }
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, (char*) &(*pMyDisasm).Argument2.ArgMnemonic);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
    }

    // =============== if Arg2.Exists and Arg1.Exists , display " , "
    if (((BYTE)*((BYTE*) &(*pMyDisasm).Argument1.ArgMnemonic) != 0) && ((BYTE)*((BYTE*) &(*pMyDisasm).Argument2.ArgMnemonic) != 0)) {
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, " , ");
        i += 3;
    }

    // =============== if Arg1 exists, display it
    if (*((BYTE*) &(*pMyDisasm).Argument1.ArgMnemonic) != 0) {
        if ((*pMyDisasm).Argument1.ArgType & CONSTANT_TYPE) {
            (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "$");
            i++;
        }
        else {
            if ((*pMyDisasm).Instruction.BranchType != 0) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "*");
                i++;
            }
            if ((*pMyDisasm).Argument1.ArgType & REGISTER_TYPE) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "%");
                i++;
            }
            else if ((*pMyDisasm).Argument1.ArgType & CONSTANT_TYPE) {
                (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "$");
                i++;
            }
            else {
                if ((SEGMENTREGS != 0) || (SEGMENTFS != 0)){
                    (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, "%");
                    i++;
                    if (SEGMENTREGS != 0) {
                        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[(*pMyDisasm).Argument1.SegmentReg-1]);
                    }
                    else {
                        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, SegmentRegs[3]);
                    }
                    i = strlen((char*) &(*pMyDisasm).CompleteInstr);
                }
            }
        }
        (void) strcpy ((char*) &(*pMyDisasm).CompleteInstr+i, (char*) &(*pMyDisasm).Argument1.ArgMnemonic);
        i = strlen((char*) &(*pMyDisasm).CompleteInstr);
    }
}
