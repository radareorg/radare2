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
//      0f01h
// ====================================================================
void __stdcall G7_(PDISASM pMyDisasm)
{
    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
    REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
    MOD_ = ((*((BYTE*) (EIP_ + 1))) >> 6) & 0x3;
    RM_  = (*((BYTE*) (EIP_ + 1))) & 0x7;
    if (REGOPCODE == 0) {
        if (MOD_ == 0x3) {
            if (RM_ == 0x1) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmcall ");
            }
            else if (RM_ == 0x2) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmlaunch ");
            }
            else if (RM_ == 0x3) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmresume ");
            }
            else if (RM_ == 0x4) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmxoff ");
            }
            else {
                FailDecode(pMyDisasm);
            }
        }
        else {
            OpSize = 7;
            MOD_RM(&(*pMyDisasm).Argument1);
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sgdt ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + MEMORY_MANAGEMENT_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 48;
            EIP_+= DECALAGE_EIP + 2;
        }
    }
    else if (REGOPCODE == 1) {
        if (MOD_ == 0x3) {
            if (RM_ == 0x01) {
                (*pMyDisasm).Instruction.Category = SSE3_INSTRUCTION + AGENT_SYNCHRONISATION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "monitor ");
            }
            else if (RM_ == 0x1) {
                (*pMyDisasm).Instruction.Category = SSE3_INSTRUCTION + AGENT_SYNCHRONISATION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "mwait ");
            }
            else {
                FailDecode(pMyDisasm);
            }
        }
        else {
            OpSize = 7;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "sidt ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + MEMORY_MANAGEMENT_REG + REG2;
            (*pMyDisasm).Argument2.ArgSize = 48;
            EIP_+= DECALAGE_EIP + 2;
        }
    }
    else if (REGOPCODE == 2) {
        if (MOD_ == 0x3) {
            if (RM_ == 0x0) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xgetbv ");
            }
            else if (RM_ == 0x1) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "xsetbv ");
            }
            else {
                FailDecode(pMyDisasm);
            }
        }
        else {
            OpSize = 107;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lgdt ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + MEMORY_MANAGEMENT_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 48;
            EIP_+= DECALAGE_EIP + 2;
        }
    }
    else if (REGOPCODE == 3) {
        if (MOD_ == 0x3) {
            if (RM_ == 0x0) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmrun ");
            }
            else if (RM_ == 0x1) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmmcall ");
            }
            else if (RM_ == 0x2) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmload ");
            }
            else if (RM_ == 0x3) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "vmsave ");
            }
            else if (RM_ == 0x4) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "stgi ");
            }
            else if (RM_ == 0x5) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "clgi ");
            }
            else if (RM_ == 0x5) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "skinit ");
            }
            else if (RM_ == 0x5) {
                (*pMyDisasm).Instruction.Category = VM_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "invlpga ");
            }
            else {
                FailDecode(pMyDisasm);
            }
        }
        else {
            OpSize = 107;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lidt ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + MEMORY_MANAGEMENT_REG + REG2;
            (*pMyDisasm).Argument1.ArgSize = 48;
            EIP_+= DECALAGE_EIP + 2;
        }
    }

    else if (REGOPCODE == 4) {
        if (MOD_ == 0x3) {
            FailDecode(pMyDisasm);
        }
        else {
            OpSize = 102;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "smsw ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + CR_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 16;
            EIP_+= DECALAGE_EIP + 2;
        }
    }

    else if (REGOPCODE == 6) {
        if (MOD_ == 0x3) {
            FailDecode(pMyDisasm);
        }
        else {
            OpSize = 2;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "lmsw ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + CR_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 16;
            EIP_+= DECALAGE_EIP + 2;
        }
    }
    else if (REGOPCODE == 7) {
        if (MOD_ == 0x3) {
            if (Architecture == 64) {
                if (RM_ == 0x0) {
                    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
                    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "swapgs ");
                    EIP_+= DECALAGE_EIP + 2;
                }
                else if (RM_ == 0x1) {
                    (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
                    (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "rdtscp ");
                    EIP_+= DECALAGE_EIP + 2;
                }
                else {
                    FailDecode(pMyDisasm);
                }
            }
            else {
                FailDecode(pMyDisasm);
            }
        }
        else {
            OpSize = 101;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = SYSTEM_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "invlpg ");
            EIP_+= DECALAGE_EIP + 2;
        }
    }
    else {
        FailDecode(pMyDisasm);
    }


}

