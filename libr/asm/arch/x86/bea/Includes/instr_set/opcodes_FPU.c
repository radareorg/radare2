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
void __stdcall D8_(PDISASM pMyDisasm)
{
    long MyMODRM;
    char (*pRegistersFPU)[8][8] ;

    DECALAGE_EIP = 0;
    if (!Security(1)) {return;}
    MyMODRM = *((BYTE*) (EIP_+1));
    pRegistersFPU = &RegistersFPU_Masm;
    if (SYNTAX_ == NasmSyntax) {
        pRegistersFPU = &RegistersFPU_Nasm;
    }
    if (MyMODRM <= 0xbf) {
        OpSize = 103;
        REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
        if (REGOPCODE == 0) {
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fadd ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 1) {
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fmul ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 2) {
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcom ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
            (*pMyDisasm).Argument1.AccessMode = READ;
        }
        else if (REGOPCODE == 3) {
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcomp ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
            (*pMyDisasm).Argument1.AccessMode = READ;
        }
        else if (REGOPCODE == 4) {
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsub ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 5) {
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsubr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 6) {
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdiv ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 7) {
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdivr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else {
        if ((MyMODRM & 0xf0) == 0xc0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fadd ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fmul ");
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xd0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcom ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcomp ");
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xe0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsub ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsubr ");
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xf0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdiv ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdivr ");
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
    }
    EIP_ += DECALAGE_EIP + 2;
}

// ====================================================================
//
// ====================================================================
void __stdcall D9_(PDISASM pMyDisasm)
{
    long MyMODRM;
    char (*pRegistersFPU)[8][8] ;

    DECALAGE_EIP = 0;
    if (!Security(1)) {return;}
    MyMODRM = *((BYTE*) (EIP_+1));
    pRegistersFPU = &RegistersFPU_Masm;
    if (SYNTAX_ == NasmSyntax) {
        pRegistersFPU = &RegistersFPU_Nasm;
    }
    if (MyMODRM <= 0xbf) {

        REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
        if (REGOPCODE == 0) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fld ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 2) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fst ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 3) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 4) {
            OpSize = 105;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fldenv ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 5) {
            OpSize = 102;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fldcw ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 6) {
            OpSize = 5;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstenv ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 7) {
            OpSize = 2;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstcw ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else {
        if ((MyMODRM & 0xf0) == 0xc0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fld ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fxch ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xd0) {
            if ((MyMODRM & 0xf) ==0) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fnop ");
            }
            else if (((MyMODRM & 0xf) >=0x8) && ((MyMODRM & 0xf) <=0xf)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstp1 ");
                (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
                (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
                (*pMyDisasm).Argument2.ArgSize = 80;
            }
            else {
                FailDecode(pMyDisasm);
            }

        }
        else if ((MyMODRM & 0xf0) == 0xe0) {
            if ((MyMODRM & 0xf) ==0) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fchs ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==1) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fabs ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==4) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ftst ");
            }
            else if ((MyMODRM & 0xf) ==5) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fxam ");
            }
            else if ((MyMODRM & 0xf) ==8) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOAD_CONSTANTS;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fld1 ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
                (*pMyDisasm).Argument2.ArgSize = 80;

            }
            else if ((MyMODRM & 0xf) ==9) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOAD_CONSTANTS;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fldl2t ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
                (*pMyDisasm).Argument2.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xa) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOAD_CONSTANTS;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fldl2e ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
                (*pMyDisasm).Argument2.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xb) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOAD_CONSTANTS;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fldpi ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
                (*pMyDisasm).Argument2.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xc) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOAD_CONSTANTS;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fldlg2 ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
                (*pMyDisasm).Argument2.ArgSize = 80;
            }

            else if ((MyMODRM & 0xf) ==0xd) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOAD_CONSTANTS;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fldln2 ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
                (*pMyDisasm).Argument2.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xe) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOAD_CONSTANTS;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fldz ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument2.ArgType = CONSTANT_TYPE + ABSOLUTE_;
                (*pMyDisasm).Argument2.ArgSize = 80;
            }

            else {
                FailDecode(pMyDisasm);
            }
        }
        else if ((MyMODRM & 0xf0) == 0xf0) {
            if ((MyMODRM & 0xf) ==0) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOGARITHMIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "f2xm1 ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==1) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOGARITHMIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fyl2x ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==2) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + TRIGONOMETRIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fptan ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==3) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + TRIGONOMETRIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fpatan ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==4) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fxtract ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==5) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fprem1 ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==6) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdecstp ");
            }
            else if ((MyMODRM & 0xf) ==7) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fincftp ");
            }
            else if ((MyMODRM & 0xf) ==8) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fprem ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==9) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOGARITHMIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fyl2xp1 ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xa) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsqrt ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xb) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + TRIGONOMETRIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsincos ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xc) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "frndint ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xd) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + LOGARITHMIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fscale ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xe) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + TRIGONOMETRIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsin ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else if ((MyMODRM & 0xf) ==0xf) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + TRIGONOMETRIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcos ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
            }
            else {
                FailDecode(pMyDisasm);
            }
        }
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//
// ====================================================================
void __stdcall DA_(PDISASM pMyDisasm)
{
    long MyMODRM;
    char (*pRegistersFPU)[8][8] ;

    DECALAGE_EIP = 0;
    if (!Security(1)) {return;}
    MyMODRM = *((BYTE*) (EIP_+1));
    pRegistersFPU = &RegistersFPU_Masm;
    if (SYNTAX_ == NasmSyntax) {
        pRegistersFPU = &RegistersFPU_Nasm;
    }
    if (MyMODRM <= 0xbf) {

        REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
        if (REGOPCODE == 0) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fiadd ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 1) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fimul ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 2) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ficom ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
            (*pMyDisasm).Argument1.AccessMode = READ;
        }
        else if (REGOPCODE == 3) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ficomp ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
            (*pMyDisasm).Argument1.AccessMode = READ;
        }
        else if (REGOPCODE == 4) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fisub ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 5) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fisubr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 6) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fidiv ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 7) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fidivr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else {
        if ((MyMODRM & 0xf0) == 0xc0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcmovb ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcmove ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xd0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcmovbe ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcmovu ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;

        }
        else if (MyMODRM == 0xe9) {
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fucompp ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (*pMyDisasm).Argument1.AccessMode = READ;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//
// ====================================================================
void __stdcall DB_(PDISASM pMyDisasm)
{
    long MyMODRM;
    char (*pRegistersFPU)[8][8] ;

    DECALAGE_EIP = 0;
    if (!Security(1)) {return;}
    MyMODRM = *((BYTE*) (EIP_+1));
    pRegistersFPU = &RegistersFPU_Masm;
    if (SYNTAX_ == NasmSyntax) {
        pRegistersFPU = &RegistersFPU_Nasm;
    }
    if (MyMODRM <= 0xbf) {

        REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
        if (REGOPCODE == 0) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fild ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 1) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fisttp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 2) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fist ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 3) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fistp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 5) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fld ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 7) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else {
        if ((MyMODRM & 0xf0) == 0xc0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcmovnb ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcmovne ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xd0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcmovnbe ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcmovnu ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xe0) {

            if ((MyMODRM & 0xf) ==0) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + UNSUPPORTED_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "feni ");
            }
            else if ((MyMODRM & 0xf) ==1) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + UNSUPPORTED_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdisi ");
            }
            else if ((MyMODRM & 0xf) ==2) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fclex ");
            }
            else if ((MyMODRM & 0xf) ==3) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fpinit ");
            }
            else if ((MyMODRM & 0xf) ==4) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + UNSUPPORTED_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsetpm ");
            }
            else if ((MyMODRM & 0xf) ==5) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "frstpm ");
            }
            else if (((MyMODRM & 0xf) >=0x8) && ((MyMODRM & 0xf) <=0xf)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fucomi ");
                (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument1.AccessMode = READ;
                (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
                (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
                (*pMyDisasm).Argument2.ArgSize = 80;
            }
            else {
                FailDecode(pMyDisasm);
            }
        }
        else if ((MyMODRM & 0xf0) == 0xf0) {
            if (((MyMODRM & 0xf) >=0x0) && ((MyMODRM & 0xf) <=0x7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcomi ");
                (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument1.AccessMode = READ;
                (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
                (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
                (*pMyDisasm).Argument2.ArgSize = 80;
            }
            else {
                FailDecode(pMyDisasm);
            }
        }
        else {
                FailDecode(pMyDisasm);
        }
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//
// ====================================================================
void __stdcall DC_(PDISASM pMyDisasm)
{
    long MyMODRM;
    char (*pRegistersFPU)[8][8] ;

    DECALAGE_EIP = 0;
    if (!Security(1)) {return;}
    MyMODRM = *((BYTE*) (EIP_+1));
    pRegistersFPU = &RegistersFPU_Masm;
    if (SYNTAX_ == NasmSyntax) {
        pRegistersFPU = &RegistersFPU_Nasm;
    }
    if (MyMODRM <= 0xbf) {

        REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
        if (REGOPCODE == 0) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fadd ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 1) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fmul ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 2) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcom ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
            (*pMyDisasm).Argument1.AccessMode = READ;
        }
        else if (REGOPCODE == 3) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcomp ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
            (*pMyDisasm).Argument1.AccessMode = READ;
        }
        else if (REGOPCODE == 4) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsub ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 5) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsubr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 6) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdiv ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 7) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdivr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else {
        if ((MyMODRM & 0xf0) == 0xc0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fadd ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fmul ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xd0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcom2 ");
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument1.AccessMode = READ;
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcomp3 ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
                (*pMyDisasm).Argument1.ArgSize = 80;
                (*pMyDisasm).Argument1.AccessMode = READ;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;

        }
        else if ((MyMODRM & 0xf0) == 0xe0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsubr ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsub ");
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xf0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdivr ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdiv ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;

        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//
// ====================================================================
void __stdcall DD_(PDISASM pMyDisasm)
{
    long MyMODRM;
    char (*pRegistersFPU)[8][8] ;

    DECALAGE_EIP = 0;
    if (!Security(1)) {return;}
    MyMODRM = *((BYTE*) (EIP_+1));
    pRegistersFPU = &RegistersFPU_Masm;
    if (SYNTAX_ == NasmSyntax) {
        pRegistersFPU = &RegistersFPU_Nasm;
    }
    if (MyMODRM <= 0xbf) {

        REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
        if (REGOPCODE == 0) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fld ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 1) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fisttp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 2) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fst ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 3) {
            OpSize = 3;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 4) {
            OpSize = 105;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "frstor ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 108*8;
        }
        else if (REGOPCODE == 6) {
            OpSize = 5;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsave ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 108*8;
        }
        else if (REGOPCODE == 7) {
            OpSize = 2;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstsw ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG;
            (*pMyDisasm).Argument2.ArgSize = 16;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else {
        if ((MyMODRM & 0xf0) == 0xc0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ffree ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fxch4 ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xd0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fst ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstp ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;

        }
        else if ((MyMODRM & 0xf0) == 0xe0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fucom ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fucomp ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }

        else {
            FailDecode(pMyDisasm);
        }
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//
// ====================================================================
void __stdcall DE_(PDISASM pMyDisasm)
{
    long MyMODRM;
    char (*pRegistersFPU)[8][8] ;

    DECALAGE_EIP = 0;
    if (!Security(1)) {return;}
    MyMODRM = *((BYTE*) (EIP_+1));
    pRegistersFPU = &RegistersFPU_Masm;
    if (SYNTAX_ == NasmSyntax) {
        pRegistersFPU = &RegistersFPU_Nasm;
    }
    if (MyMODRM <= 0xbf) {

        REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
        if (REGOPCODE == 0) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fiadd ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 1) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fimul ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 2) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ficom ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 3) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ficomp ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 4) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fisub ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 5) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fisubr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 6) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fidiv ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 7) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fidivr ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else {
        if ((MyMODRM & 0xf0) == 0xc0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "faddp ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fmulp ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xd0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcomp5 ");
                (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
                (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
                (*pMyDisasm).Argument1.ArgSize = 80;
                (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
                (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
                (*pMyDisasm).Argument2.ArgSize = 80;
            }
            else if (MyMODRM == 0xd1){
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcompp ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }


        }
        else if ((MyMODRM & 0xf0) == 0xe0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsubrp ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fsubp ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xf0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdivrp ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + ARITHMETIC_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fdivp ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;

        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    EIP_ += DECALAGE_EIP + 2;
}


// ====================================================================
//
// ====================================================================
void __stdcall DF_(PDISASM pMyDisasm)
{
    long MyMODRM;
    char (*pRegistersFPU)[8][8] ;

    DECALAGE_EIP = 0;
    if (!Security(1)) {return;}
    MyMODRM = *((BYTE*) (EIP_+1));
    pRegistersFPU = &RegistersFPU_Masm;
    if (SYNTAX_ == NasmSyntax) {
        pRegistersFPU = &RegistersFPU_Nasm;
    }
    if (MyMODRM <= 0xbf) {

        REGOPCODE = ((*((BYTE*) (EIP_ + 1))) >> 3) & 0x7;
        if (REGOPCODE == 0) {
            OpSize = 102;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fild ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 1) {
            OpSize = 2;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fisttp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 2) {
            OpSize = 2;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fist ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 3) {
            OpSize = 2;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fistp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if (REGOPCODE == 4) {
            OpSize = 105;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fbld ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 5) {
            OpSize = 103;
            MOD_RM(&(*pMyDisasm).Argument2);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fild ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 6) {
            OpSize = 5;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fbstp ");
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument1.ArgSize = 80;
        }
        else if (REGOPCODE == 7) {
            OpSize = 4;
            MOD_RM(&(*pMyDisasm).Argument1);
            (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
            (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fistp ");
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REG0;
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    else {
        if ((MyMODRM & 0xf0) == 0xc0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "ffreep ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fxch7 ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;
        }
        else if ((MyMODRM & 0xf0) == 0xd0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstp8 ");
            }
            else {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + DATA_TRANSFER;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstp9 ");
                (*pMyDisasm).Argument2.AccessMode = WRITE;
            }
            (void) strcpy ((*pMyDisasm).Argument1.ArgMnemonic, (*pRegistersFPU)[0]);
            (*pMyDisasm).Argument1.ArgType = REGISTER_TYPE + FPU_REG + REGS[0];
            (*pMyDisasm).Argument1.ArgSize = 80;
            (void) strcpy ((*pMyDisasm).Argument2.ArgMnemonic, (*pRegistersFPU)[(MyMODRM & 0xf)%8]);
            (*pMyDisasm).Argument2.ArgType = REGISTER_TYPE + FPU_REG + REGS[(MyMODRM & 0xf)%8];
            (*pMyDisasm).Argument2.ArgSize = 80;

        }
        else if ((MyMODRM & 0xf0) == 0xe0) {
            if (MyMODRM == 0xe0) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + FPUCONTROL;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fstsw ");
            }
            else {
                FailDecode(pMyDisasm);
            }
        }

        else if ((MyMODRM & 0xf0) == 0xf0) {
            if (((MyMODRM & 0xf) >=0) && ((MyMODRM & 0xf) <=7)) {
                (*pMyDisasm).Instruction.Category = FPU_INSTRUCTION + COMPARISON_INSTRUCTION;
                (void) strcpy ((*pMyDisasm).Instruction.Mnemonic, "fcomip ");
            }
            else {
                FailDecode(pMyDisasm);
            }

        }
        else {
            FailDecode(pMyDisasm);
        }
    }
    EIP_ += DECALAGE_EIP + 2;
}
