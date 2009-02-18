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

#define SBYTE signed char
#define SWORD signed short
#define SDWORD signed long

static long long EIP_, EIP_VA, EIP_REAL;
static long OperandSize;
static long OpSize;
static long AddressSize;
static int MOD_, RM_, INDEX_, SCALE_, BASE_, MMX_, SSE_, CR_, DR_, SEG_, REGOPCODE;
static long DECALAGE_EIP;
static long FORMATNUMBER;
static long SYNTAX_;
static long long EndOfBlock;
static int RelativeAddress;
static long Architecture;
static long ImmediatSize;
static long NB_PREFIX;
static long PrefRepe, PrefRepne;
static long SEGMENTREGS, SEGMENTFS;
static long third_arg;
static long TAB_;
static long ERROR_OPCODE;


EFLStruct EFLAGS_TABLE[] = {
    {UN_, UN_, UN_, MO_, UN_, MO_, 0  , 0  , 0  , 0  , 0},  // 0 - AAA
    {UN_, MO_, MO_, UN_, MO_, UN_, 0  , 0  , 0  , 0  , 0},  // 1 - AAD
    {UN_, MO_, MO_, UN_, MO_, UN_, 0  , 0  , 0  , 0  , 0},  // 2 - AAM
    {UN_, UN_, UN_, MO_, UN_, MO_, 0  , 0  , 0  , 0  , 0},  // 3 - AAS
    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 4 - ADC
    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 5 - ADD
    {RE_, MO_, MO_, UN_, MO_, RE_, 0  , 0  , 0  , 0  , 0},  // 6 - AND
    {0  , 0  , MO_, 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 7 - ARPL
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 8 - BOUND
    {UN_, UN_, MO_, UN_, UN_, UN_, 0  , 0  , 0  , 0  , 0},  // 9 - BSF/BSR

    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 10 - BSWAP
    {UN_, UN_, UN_, UN_, UN_, MO_, 0  , 0  , 0  , 0  , 0},  // 11 - BT/BTS/BTR/BTC
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 12 - CALL
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 13 - CBW
    {0  , 0  , 0  , 0  , 0  , RE_, 0  , 0  , 0  , 0  , 0},  // 14 - CLC
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , RE_, 0  , 0},  // 15 - CLD
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , RE_, 0  , 0  , 0},  // 16 - CLI
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 17 - CLTS
    {0  , 0  , 0  , 0  , 0  , MO_, 0  , 0  , 0  , 0  , 0},  // 18 - CMC
    {TE_, TE_, TE_, 0  , TE_, TE_, 0  , 0  , 0  , 0  , 0},  // 19 - CMOVcc

    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 20 - CMP
    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 21 - CMPS
    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 22 - CMPXCHG
    {0  , 0  , MO_, 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 23 - CMPXCHGG8B
    {RE_, RE_, MO_, RE_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 24 - COMSID
    {RE_, RE_, MO_, RE_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 25 - COMISS
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 26 - CPUID
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 27 - CWD
    {UN_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 28 - DAA
    {UN_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 29 - DAS

    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 30 - DEC
    {UN_, UN_, UN_, UN_, UN_, UN_, 0  , 0  , 0  , 0  , 0},  // 31 - DIV
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 32 - ENTER
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 33 - ESC
    {0  , 0  , TE_, 0  , TE_, TE_, 0  , 0  , 0  , 0  , 0},  // 34 - FCMOV
    {0  , 0  , MO_, 0  , MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 35 - FCOMI FCOMIP FUCMI FUCMIP
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 36 - HLT
    {UN_, UN_, UN_, UN_, UN_, UN_, 0  , 0  , 0  , 0  , 0},  // 37 - IDIV
    {MO_, UN_, UN_, UN_, UN_, MO_, 0  , 0  , 0  , 0  , 0},  // 38 - IMUL
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 39 - IN

    {MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0  , 0},  // 40 - INC
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , TE_, 0  , 0},  // 41 - INS
    {0  , 0  , 0  , 0  , 0  , 0  , RE_, 0  , 0  , RE_, 0},  // 42 - INT
    {TE_, 0  , 0  , 0  , 0  , 0  , RE_, 0  , 0  , RE_, 0},  // 43 - INTO
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 44 - INVD
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 45 - INVLPG
    {RE_, RE_, MO_, RE_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 46 - UCOMSID
    {RE_, RE_, MO_, RE_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 47 - UCOMISS
    {PR_, PR_, PR_, PR_, PR_, PR_, PR_, PR_, PR_, TE_, 0},  // 48 - IRET
    {TE_, TE_, TE_, 0  , TE_, TE_, 0  , 0  , 0  , 0  , 0},  // 49 - Jcc

    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 50 - JCXZ
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 51 - JMP
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 52 - LAHF
    {0  , 0  , MO_, 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 53 - LAR
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 54 - LDS LES LSS LFS LGS
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 55 - LEA
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 56 - LEAVE
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 57 - LGDT LIDT LLDT LMSW
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 58 - LOCK
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , TE_, 0  , 0},  // 59 - LODS

    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 60 - LOOP
    {0  , 0  , TE_, 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 61 - LOOPE LOOPNE
    {0  , 0  , MO_, 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 62 - LSL
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 63 - LTR
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 64 - MONITOR
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 65 - MWAIT
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 66 - MOV
    {UN_, UN_, UN_, UN_, UN_, UN_, 0  , 0  , 0  , 0  , 0},  // 67 - MOV control, debug, test
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , TE_, 0  , 0},  // 68 - MOVS
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 69 - MOVSX MOVZX

    {MO_, UN_, UN_, UN_, UN_, MO_, 0  , 0  , 0  , 0  , 0},  // 70 - MUL
    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 71 - NEG
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 72 - NOP
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 73 - NOT
    {RE_, MO_, MO_, UN_, MO_, RE_, 0  , 0  , 0  , 0  , 0},  // 74 - OR
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 75 - OUT
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , TE_, 0  , 0},  // 76 - OUTS
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 77 - POP POPA
    {PR_, PR_, PR_, PR_, PR_, PR_, PR_, PR_, PR_, PR_, 0},  // 78 - POPF
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 79 - PUSH PUSHA PUSHF

    {MO_, 0  , 0  , 0  , 0  , MO_, 0  , 0  , 0  , 0  , 0},  // 80 - RCL RCR 1
    {UN_, 0  , 0  , 0  , 0  , MO_, 0  , 0  , 0  , 0  , 0},  // 81 - RCL RCR
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 82 - RDMSR
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 83 - RDPMC
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 84 - RDTSC
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 85 - REP REPE REPNE
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 86 - RET
    {MO_, 0  , 0  , 0  , 0  , MO_, 0  , 0  , 0  , 0  , 0},  // 87 - ROL ROR 1
    {UN_, 0  , 0  , 0  , 0  , MO_, 0  , 0  , 0  , 0  , 0},  // 88 - ROL ROR
    {MO_, MO_, MO_, MO_, MO_, MO_, MO_, MO_, MO_, MO_, MO_},  // 89 - RSM

    {0  , PR_, PR_, PR_, PR_, PR_, 0  , 0  , 0  , 0  , 0},  // 90 - SAHF
    {MO_, MO_, MO_, 0  , MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 91 - SAL SAR SHL SHR 1
    {0  , MO_, MO_, 0  , MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 92 - SAL SAR SHL SHR
    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 93 - SBB
    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 94 - SCAS
    {TE_, TE_, TE_, 0  , TE_, TE_, 0  , 0  , 0  , 0  , 0},  // 95 - SETcc
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 96 - SGDT SIDT SLDT SMSW
    {UN_, MO_, MO_, UN_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 97 - SHLD SHRD
    {0  , 0  , 0  , 0  , 0  , SE_, 0  , 0  , 0  , 0  , 0},  // 98 - STC
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , SE_, 0  , 0},  // 99 - STD

    {0  , 0  , 0  , 0  , 0  , 0  , 0  , SE_, 0  , 0  , 0},  // 100 - STI
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 101 - STOS
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 102 - STR
    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 103 - SUB
    {RE_, MO_, MO_, UN_, MO_, RE_, 0  , 0  , 0  , 0  , 0},  // 104 - TEST
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 105 - UD2
    {0  , 0  , MO_, 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 106 - VERR VERRW
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 107 - WAIT
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 108 - WBINVD
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 109 - WRMSR

    {MO_, MO_, MO_, MO_, MO_, MO_, 0  , 0  , 0  , 0  , 0},  // 110 - XADD
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 111 - XCHG
    {0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0  , 0},  // 112 - XLAT
    {RE_, MO_, MO_, UN_, MO_, RE_, 0  , 0  , 0  , 0  , 0},  // 113 - XOR

    {RE_, RE_, MO_, RE_, RE_, RE_, 0  , 0  , 0  , 0  , 0}  // 114 - POPCNT


    };
// =====================================================
// To make a tabulation between mnemonic and first argument
// =====================================================
char space_tab[11][16] = {
    " ",
    "  ",
    "   ",
    "    ",
    "     ",
    "      ",
    "       ",
    "        ",
    "         ",
    "          ",
    "           ",

};
// =====================================================
// Segment registers
// =====================================================
char SegmentRegs[6][4] = {
    "cs:",      // +0
    "ds:",      // +1
    "es:",      // +2
    "fs:",      // +3
    "gs:",      // +4
    "ss:",      // +5
};
// =====================================================
// AT&T Suffixes
// =====================================================
char ATSuffixes[8][4] = {
    "b ",      // OpSize == 1
    "w ",      // OpSize == 2
    "l ",     // OpSize == 3
    "q ",     // OpSize == 4
    " ",          // OpSize == 5 (multibytes)
    "t ",     // OpSize == 6
    " ",          // OpSize == 7 (fword)
    " ",          // OpSize == 8 (dqword)
};

// =====================================================
// MASM Prefixes for MemoryType
// =====================================================

char MasmPrefixes[8][16] = {
    "byte ptr ",      // OpSize == 1
    "word ptr ",      // OpSize == 2
    "dword ptr ",     // OpSize == 3
    "qword ptr ",     // OpSize == 4
    " ",          // OpSize == 5 (multibytes)
    "tbyte ptr ",     // OpSize == 6
    "fword ptr ",          // OpSize == 7 (fword)
    "dqword ptr ",          // OpSize == 8 (dqword)
};

// =====================================================
// NASM Prefixes for MemoryType
// =====================================================
char NasmPrefixes[8][8] = {
    "byte ",      // OpSize == 1
    "word ",      // OpSize == 2
    "dword ",     // OpSize == 3
    "qword ",     // OpSize == 4
    " ",          // OpSize == 5 (multibytes)
    "tword ",     // OpSize == 6
    " ",          // OpSize == 7 (fword)
    " ",          // OpSize == 8 (dqword)
};



// =====================================================
// GOASM Prefixes for MemoryType
// =====================================================
char GoAsmPrefixes[8][4] = {
    "b ",      // OpSize == 1
    "w ",      // OpSize == 2
    "d ",     // OpSize == 3
    "q ",     // OpSize == 4
    " ",          // OpSize == 5 (multibytes)
    "t ",     // OpSize == 6
    " ",          // OpSize == 7 (fword)
    " ",          // OpSize == 8 (dqword)
};


// =====================================================
// Segment registers
// =====================================================
char RegistersSEG[16][8] = {
    "es",      // +0
    "cs",      // +1
    "ss",      // +2
    "ds",      // +3
    "fs",      // +4
    "gs",      // +5
    "seg?",
    "seg?",
    "seg?",
    "seg?",
    "seg?",
    "seg?",
    "seg?",
    "seg?",
    "seg?",
    "seg?",
};

// =====================================================
// FPU Registers
// =====================================================
char RegistersFPU_Masm[8][8] = {
    "st(0)",      // +0
    "st(1)",      // +1
    "st(2)",      // +2
    "st(3)",      // +3
    "st(4)",      // +4
    "st(5)",      // +5
    "st(6)",      // +6
    "st(7)",      // +7
};

char RegistersFPU_Nasm[8][8] = {
    "st0",      // +0
    "st1",      // +1
    "st2",      // +2
    "st3",      // +3
    "st4",      // +4
    "st5",      // +5
    "st6",      // +6
    "st7",      // +7
};

// =====================================================
// debug registers
// =====================================================
char RegistersDR[16][8] = {
    "dr0",      // +0
    "dr1",      // +1
    "dr2",      // +2
    "dr3",      // +3
    "dr4",      // +4
    "dr5",      // +5
    "dr6",      // +6
    "dr7",      // +7
    "dr8",       // +8
    "dr9",       // +9
    "dr10",      // +10
    "dr11",      // +11
    "dr12",      // +12
    "dr13",      // +13
    "dr14",      // +14
    "dr15",      // +15
};

// =====================================================
// debug registers - AT&T syntax
// =====================================================
char RegistersDR_AT[16][8] = {
    "db0",      // +0
    "db1",      // +1
    "db2",      // +2
    "db3",      // +3
    "db4",      // +4
    "db5",      // +5
    "db6",      // +6
    "db7",      // +7
    "db8",       // +8
    "db9",       // +9
    "db10",      // +10
    "db11",      // +11
    "db12",      // +12
    "db13",      // +13
    "db14",      // +14
    "db15",      // +15
};


// =====================================================
// control registers
// =====================================================
char RegistersCR[16][8] = {
    "cr0",      // +0
    "cr1",      // +1
    "cr2",      // +2
    "cr3",      // +3
    "cr4",      // +4
    "cr5",      // +5
    "cr6",      // +6
    "cr7",      // +7
    "cr8",       // +8
    "cr9",       // +9
    "cr10",      // +10
    "cr11",      // +11
    "cr12",      // +12
    "cr13",      // +13
    "cr14",      // +14
    "cr15",      // +15
};



// =====================================================
// 64 bits registers
// =====================================================
char Registers64Bits[16][4] = {
    "rax",      // +0
    "rcx",      // +1
    "rdx",      // +2
    "rbx",      // +3
    "rsp",      // +4
    "rbp",      // +5
    "rsi",      // +6
    "rdi",      // +7
    "r8",       // +8
    "r9",       // +9
    "r10",      // +10
    "r11",      // +11
    "r12",      // +12
    "r13",      // +13
    "r14",      // +14
    "r15",      // +15
};

// =====================================================
// 32 bits registers
// =====================================================
char Registers32Bits[16][8] = {
    "eax",
    "ecx",
    "edx",
    "ebx",
    "esp",
    "ebp",
    "esi",
    "edi",
    "r8d",
    "r9d",
    "r10d",
    "r11d",
    "r12d",
    "r13d",
    "r14d",
    "r15d",
};

// =====================================================
// 16 bits registers
// =====================================================
char Registers16Bits[16][8] = {
    "ax",
    "cx",
    "dx",
    "bx",
    "sp",
    "bp",
    "si",
    "di",
    "r8w",
    "r9w",
    "r10w",
    "r11w",
    "r12w",
    "r13w",
    "r14w",
    "r15w",
};
// =====================================================
// 8 bits registers
// =====================================================
char Registers8BitsLegacy[8][4] = {
    "al",
    "cl",
    "dl",
    "bl",
    "ah",
    "ch",
    "dh",
    "bh",
};

long REGS8BITS[] = {
    REG0,
    REG1,
    REG2,
    REG3,
    REG0,
    REG1,
    REG2,
    REG3,
};

// =====================================================
// 8 bits registers
// =====================================================
char Registers8Bits[16][8] = {
    "al",
    "cl",
    "dl",
    "bl",
    "spl",
    "bpl",
    "sil",
    "dil",
    "r8L",
    "r9L",
    "r10L",
    "r11L",
    "r12L",
    "r13L",
    "r14L",
    "r15L",
};
// =====================================================
// MMX Registers
// =====================================================
char RegistersMMX[8][4] = {
    "mm0",
    "mm1",
    "mm2",
    "mm3",
    "mm4",
    "mm5",
    "mm6",
    "mm7",
};

// =====================================================
// SSE Registers
// =====================================================
char RegistersSSE[16][8] = {
    "xmm0",
    "xmm1",
    "xmm2",
    "xmm3",
    "xmm4",
    "xmm5",
    "xmm6",
    "xmm7",
    "xmm8",     // SSE3, SSSE3, SSE4
    "xmm9",     // SSE3, SSSE3, SSE4
    "xmm10",    // SSE3, SSSE3, SSE4
    "xmm11",    // SSE3, SSSE3, SSE4
    "xmm12",    // SSE3, SSSE3, SSE4
    "xmm13",    // SSE3, SSSE3, SSE4
    "xmm14",    // SSE3, SSSE3, SSE4
    "xmm15",    // SSE3, SSSE3, SSE4
};

long REGS[] = {
    REG0,        // REG0
    REG1,        // REG1
    REG2,        // REG2
    REG3,        // REG3
    REG4,       // REG4
    REG5,       // REG5
    REG6,       // REG6
    REG7,       // REG7
    REG8,      // REG8
    REG9,      // REG9
    REG10,      // REG10
    REG11,      // REG11
    REG12,     // REG12
    REG13,     // REG13
    REG14,     // REG14
    REG15,     // REG15
};

char BXSI_[] = "bx+si";
char BXDI_[] = "bx+di";
char BPSI_[] = "bp+si";
char BPDI_[] = "bp+di";

static REX_Struct REX;

