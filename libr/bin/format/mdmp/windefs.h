#ifndef WINDEFS_H 
#define WINDEFS_H

#if __WINDOWS__
#include <windows.h>
#endif

#define EXCEPTION_MAXIMUM_PARAMETERS 15
#define MAXIMUM_SUPPORTED_EXTENSION 512

#define SIZE_OF_80387_REGISTERS 80
typedef struct {
	ut32   ControlWord;
	ut32   StatusWord;
	ut32   TagWord;
	ut32   ErrorOffset;
	ut32   ErrorSelector;
	ut32   DataOffset;
	ut32   DataSelector;
	ut8    RegisterArea[SIZE_OF_80387_REGISTERS];
	ut32   Spare0;
} WINDOWS_FLOATING_SAVE_AREA;

typedef struct {
        ut16 wYear;
        ut16 wMonth;
        ut16 wDayOfWeek;
        ut16 wDay;
        ut16 wHour;
        ut16 wMinute;
        ut16 wSecond;
        ut16 wMilliseconds;
} WINDOWS_SYSTEMTIME;

typedef struct {
        long Bias;
        ut16 StandardName[32];
        WINDOWS_SYSTEMTIME StandardDate;
        long StandardBias;
        ut16 DaylightName[32];
        WINDOWS_SYSTEMTIME DaylightDate;
        long DaylightBias;
} WINDOWS_TIME_ZONE_INFORMATION;

/* 128bit types */
typedef struct {
	ut64 Low;
	st64 High;
} M128A, *PM128A;

typedef struct _NEON128 {
	ut64 Low;
	st64 High;
} NEON128, *PNEON128;

typedef struct _FLOAT128 {
	ut64 Low;
	st64 High;
} FLOAT128, *PFLOAT128;

typedef struct _CONTEXT_TYPE_I386 {
	ut32 ContextFlags;

	ut32   Dr0;
	ut32   Dr1;
	ut32   Dr2;
	ut32   Dr3;
	ut32   Dr6;
	ut32   Dr7;

	WINDOWS_FLOATING_SAVE_AREA FloatSave;

	ut32   SegGs;
	ut32   SegFs;
	ut32   SegEs;
	ut32   SegDs;

	ut32   Edi;
	ut32   Esi;
	ut32   Ebx;
	ut32   Edx;
	ut32   Ecx;
	ut32   Eax;

	ut32   Ebp;
	ut32   Eip;
	ut32   SegCs;
	ut32   EFlags;
	ut32   Esp;
	ut32   SegSs;

	ut8 ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];
} CONTEXT_TYPE_I386, *PCONTEXT_TYPE_I386;

typedef struct _CONTEXT_TYPE_IA64 {
	ut32 ContextFlags;
	ut32 Fill1[3];

	ut64 DbI0;
	ut64 DbI1;
	ut64 DbI2;
	ut64 DbI3;
	ut64 DbI4;
	ut64 DbI5;
	ut64 DbI6;
	ut64 DbI7;

	ut64 DbD0;
	ut64 DbD1;
	ut64 DbD2;
	ut64 DbD3;
	ut64 DbD4;
	ut64 DbD5;
	ut64 DbD6;
	ut64 DbD7;

	FLOAT128 FltS0;
	FLOAT128 FltS1;
	FLOAT128 FltS2;
	FLOAT128 FltS3;
	FLOAT128 FltT0;
	FLOAT128 FltT1;
	FLOAT128 FltT2;
	FLOAT128 FltT3;
	FLOAT128 FltT4;
	FLOAT128 FltT5;
	FLOAT128 FltT6;
	FLOAT128 FltT7;
	FLOAT128 FltT8;
	FLOAT128 FltT9;

	FLOAT128 FltS4;
	FLOAT128 FltS5;
	FLOAT128 FltS6;
	FLOAT128 FltS7;
	FLOAT128 FltS8;
	FLOAT128 FltS9;
	FLOAT128 FltS10;
	FLOAT128 FltS11;
	FLOAT128 FltS12;
	FLOAT128 FltS13;
	FLOAT128 FltS14;
	FLOAT128 FltS15;
	FLOAT128 FltS16;
	FLOAT128 FltS17;
	FLOAT128 FltS18;
	FLOAT128 FltS19;

	FLOAT128 FltF32;
	FLOAT128 FltF33;
	FLOAT128 FltF34;
	FLOAT128 FltF35;
	FLOAT128 FltF36;
	FLOAT128 FltF37;
	FLOAT128 FltF38;
	FLOAT128 FltF39;

	FLOAT128 FltF40;
	FLOAT128 FltF41;
	FLOAT128 FltF42;
	FLOAT128 FltF43;
	FLOAT128 FltF44;
	FLOAT128 FltF45;
	FLOAT128 FltF46;
	FLOAT128 FltF47;
	FLOAT128 FltF48;
	FLOAT128 FltF49;

	FLOAT128 FltF50;
	FLOAT128 FltF51;
	FLOAT128 FltF52;
	FLOAT128 FltF53;
	FLOAT128 FltF54;
	FLOAT128 FltF55;
	FLOAT128 FltF56;
	FLOAT128 FltF57;
	FLOAT128 FltF58;
	FLOAT128 FltF59;

	FLOAT128 FltF60;
	FLOAT128 FltF61;
	FLOAT128 FltF62;
	FLOAT128 FltF63;
	FLOAT128 FltF64;
	FLOAT128 FltF65;
	FLOAT128 FltF66;
	FLOAT128 FltF67;
	FLOAT128 FltF68;
	FLOAT128 FltF69;

	FLOAT128 FltF70;
	FLOAT128 FltF71;
	FLOAT128 FltF72;
	FLOAT128 FltF73;
	FLOAT128 FltF74;
	FLOAT128 FltF75;
	FLOAT128 FltF76;
	FLOAT128 FltF77;
	FLOAT128 FltF78;
	FLOAT128 FltF79;

	FLOAT128 FltF80;
	FLOAT128 FltF81;
	FLOAT128 FltF82;
	FLOAT128 FltF83;
	FLOAT128 FltF84;
	FLOAT128 FltF85;
	FLOAT128 FltF86;
	FLOAT128 FltF87;
	FLOAT128 FltF88;
	FLOAT128 FltF89;

	FLOAT128 FltF90;
	FLOAT128 FltF91;
	FLOAT128 FltF92;
	FLOAT128 FltF93;
	FLOAT128 FltF94;
	FLOAT128 FltF95;
	FLOAT128 FltF96;
	FLOAT128 FltF97;
	FLOAT128 FltF98;
	FLOAT128 FltF99;

	FLOAT128 FltF100;
	FLOAT128 FltF101;
	FLOAT128 FltF102;
	FLOAT128 FltF103;
	FLOAT128 FltF104;
	FLOAT128 FltF105;
	FLOAT128 FltF106;
	FLOAT128 FltF107;
	FLOAT128 FltF108;
	FLOAT128 FltF109;

	FLOAT128 FltF110;
	FLOAT128 FltF111;
	FLOAT128 FltF112;
	FLOAT128 FltF113;
	FLOAT128 FltF114;
	FLOAT128 FltF115;
	FLOAT128 FltF116;
	FLOAT128 FltF117;
	FLOAT128 FltF118;
	FLOAT128 FltF119;

	FLOAT128 FltF120;
	FLOAT128 FltF121;
	FLOAT128 FltF122;
	FLOAT128 FltF123;
	FLOAT128 FltF124;
	FLOAT128 FltF125;
	FLOAT128 FltF126;
	FLOAT128 FltF127;

	ut64 StFPSR;

	ut64 IntGp;
	ut64 IntT0;
	ut64 IntT1;
	ut64 IntS0;
	ut64 IntS1;
	ut64 IntS2;
	ut64 IntS3;
	ut64 IntV0;
	ut64 IntT2;
	ut64 IntT3;
	ut64 IntT4;
	ut64 IntSp;
	ut64 IntTeb;
	ut64 IntT5;
	ut64 IntT6;
	ut64 IntT7;
	ut64 IntT8;
	ut64 IntT9;
	ut64 IntT10;
	ut64 IntT11;
	ut64 IntT12;
	ut64 IntT13;
	ut64 IntT14;
	ut64 IntT15;
	ut64 IntT16;
	ut64 IntT17;
	ut64 IntT18;
	ut64 IntT19;
	ut64 IntT20;
	ut64 IntT21;
	ut64 IntT22;

	ut64 IntNats;

	ut64 Preds;

	ut64 BrRp;
	ut64 BrS0;
	ut64 BrS1;
	ut64 BrS2;
	ut64 BrS3;
	ut64 BrS4;
	ut64 BrT0;
	ut64 BrT1;

	ut64 ApUNAT;
	ut64 ApLC;
	ut64 ApEC;
	ut64 ApCCV;
	ut64 ApDCR;

	ut64 RsPFS;
	ut64 RsBSP;
	ut64 RsBSPSTORE;
	ut64 RsRSC;
	ut64 RsRNAT;

	ut64 StIPSR;
	ut64 StIIP;
	ut64 StIFS;

	ut64 StFCR;
	ut64 Eflag;
	ut64 SegCSD;
	ut64 SegSSD;
	ut64 Cflag;
	ut64 StFSR;
	ut64 StFIR;
	ut64 StFDR;

	ut64 UNUSEDPACK;

} CONTEXT_TYPE_IA64, *PCONTEXT_TYPE_IA64;

#define ARM_MAX_BREAKPOINTS 8
#define ARM_MAX_WATCHPOINTS 1

typedef struct _CONTEXT_TYPE_ARM {
	ut32 ContextFlags;

	ut32 R0;
	ut32 R1;
	ut32 R2;
	ut32 R3;
	ut32 R4;
	ut32 R5;
	ut32 R6;
	ut32 R7;
	ut32 R8;
	ut32 R9;
	ut32 R10;
	ut32 R11;
	ut32 R12;

	ut32 Sp;
	ut32 Lr;
	ut32 Pc;
	ut32 Cpsr;

	ut32 Fpscr;
	ut32 Padding;
	union {
		NEON128 Q[16];
		ut64 D[32];
		ut32 S[32];
	};

	ut32 Bvr[ARM_MAX_BREAKPOINTS];
	ut32 Bcr[ARM_MAX_BREAKPOINTS];
	ut32 Wvr[ARM_MAX_WATCHPOINTS];
	ut32 Wcr[ARM_MAX_WATCHPOINTS];
	ut32 Padding2[2];
} CONTEXT_TYPE_ARM, *PCONTEXT_TYPE_ARM;

typedef struct _XSAVE_FORMAT32 {
	ut16 ControlWord;
	ut16 StatusWord;
	ut8 TagWord;
	ut8 Reserved1;
	ut16 ErrorOpcode;
	ut32 ErrorOffset;
	ut16 ErrorSelector;
	ut16 Reserved2;
	ut32 DataOffset;
	ut16 DataSelector;
	ut16 Reserved3;
	ut32 MxCsr;
	ut32 MxCsr_Mask;
	M128A FloatRegisters[8];
	M128A XmmRegisters[8];
	ut8 Reserved4[224];
} XSAVE_FORMAT32, *PXSAVE_FORMAT32;

typedef XSAVE_FORMAT32 XMM_SAVE_AREA32, *PXMM_SAVE_AREA32;

typedef struct _CONTEXT_TYPE_AMD64 {
	ut64 P1Home;
	ut64 P2Home;
	ut64 P3Home;
	ut64 P4Home;
	ut64 P5Home;
	ut64 P6Home;

	ut32 ContextFlags;
	ut32 MxCsr;

	ut16 SegCs;
	ut16 SegDs;
	ut16 SegEs;
	ut16 SegFs;
	ut16 SegGs;
	ut16 SegSs;
	ut32 EFlags;

	ut64 Dr0;
	ut64 Dr1;
	ut64 Dr2;
	ut64 Dr3;
	ut64 Dr6;
	ut64 Dr7;

	ut64 Rax;
	ut64 Rcx;
	ut64 Rdx;
	ut64 Rbx;
	ut64 Rsp;
	ut64 Rbp;
	ut64 Rsi;
	ut64 Rdi;
	ut64 R8;
	ut64 R9;
	ut64 R10;
	ut64 R11;
	ut64 R12;
	ut64 R13;
	ut64 R14;
	ut64 R15;

	ut64 Rip;

	union {
		XMM_SAVE_AREA32 FltSave;
		struct {
			M128A Header[2];
			M128A Legacy[8];
			M128A Xmm0;
			M128A Xmm1;
			M128A Xmm2;
			M128A Xmm3;
			M128A Xmm4;
			M128A Xmm5;
			M128A Xmm6;
			M128A Xmm7;
			M128A Xmm8;
			M128A Xmm9;
			M128A Xmm10;
			M128A Xmm11;
			M128A Xmm12;
			M128A Xmm13;
			M128A Xmm14;
			M128A Xmm15;
		};
	};

	M128A VectorRegister[26];
	ut64 VectorControl;

	ut64 DebugControl;
	ut64 LastBranchToRip;
	ut64 LastBranchFromRip;
	ut64 LastExceptionToRip;
	ut64 LastExceptionFromRip;
} CONTEXT_TYPE_AMD64, *PCONTEXT_TYPE_AMD64;

typedef struct _EXCEPTION_RECORD32 {
	ut32 ExceptionCode;
	ut32 ExceptionFlags;
	ut32 ExceptionRecord;
	ut32 ExceptionAddress;
	ut32 NumberParameters;
	ut32 ExceptionInformation[EXCEPTION_MAXIMUM_PARAMETERS];
} EXCEPTION_RECORD32, *PEXCEPTION_RECORD32;

typedef struct _EXCEPTION_POINTERS_I386 {
	PEXCEPTION_RECORD32 ExceptionRecord;
	PCONTEXT_TYPE_I386 ContextRecord;
} EXCEPTION_POINTERS_I386, *PEXCEPTION_POINTERS_I386;

#endif
