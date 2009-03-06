#ifndef _BEA_ENGINE_
#define _BEA_ENGINE_

#ifdef __UNIX__
#define BYTE unsigned char
#define WORD unsigned short
#define DWORD unsigned long
#define __stdcall 
#endif

#define INSTRUCT_LENGTH 64

#pragma pack(1)
typedef struct {
   BYTE W_;
   BYTE R_;
   BYTE X_;
   BYTE B_;
   BYTE state;
} REX_Struct  ;
#pragma pack()

#pragma pack(1)
typedef struct {
   int Number;
   int NbUndefined;
   BYTE LockPrefix;
   BYTE OperandSize;
   BYTE AddressSize;
   BYTE RepnePrefix;
   BYTE RepPrefix;
   BYTE FSPrefix;
   BYTE SSPrefix;
   BYTE GSPrefix;
   BYTE ESPrefix;
   BYTE CSPrefix;
   BYTE DSPrefix;
   REX_Struct REX;
} PREFIXINFO  ;
#pragma pack()

#pragma pack(1)
typedef struct {
   BYTE OF_;
   BYTE SF_;
   BYTE ZF_;
   BYTE AF_;
   BYTE PF_;
   BYTE CF_;
   BYTE TF_;
   BYTE IF_;
   BYTE DF_;
   BYTE NT_;
   BYTE RF_;
   BYTE alignment;
} EFLStruct  ;
#pragma pack()

#pragma pack(4)
typedef struct {
   long BaseRegister;
   long IndexRegister;
   long Scale;
   long long Displacement;
} MEMORYTYPE ;
#pragma pack()


#pragma pack(1)
typedef struct  {
   long Category;
   long Opcode;
   char Mnemonic[16];
   long BranchType;
   EFLStruct Flags;
   long long AddrValue;
   long long Immediat;
   long ImplicitModifiedRegs;
} INSTRTYPE;
#pragma pack()

#pragma pack(4)
typedef struct  {
   char ArgMnemonic[32];
   long ArgType;
   long ArgSize;
   long AccessMode;
   MEMORYTYPE Memory;
   long SegmentReg;
} ARGTYPE;
#pragma pack()



#pragma pack(1)
typedef struct _Disasm {
   long long EIP;
   long long VirtualAddr;
   long SecurityBlock;
   char CompleteInstr[INSTRUCT_LENGTH];
   long Archi;
   long Options;
   INSTRTYPE Instruction;
   ARGTYPE Argument1;
   ARGTYPE Argument2;
   ARGTYPE Argument3;
   PREFIXINFO Prefix;
} DISASM, *PDISASM, *LPDISASM;
#pragma pack()

#define ESReg 1
#define DSReg 2
#define FSReg 3
#define GSReg 4
#define CSReg 5
#define SSReg 6

#define InvalidPrefix 4
#define SuperfluousPrefix 2
#define NotUsedPrefix 0
#define MandatoryPrefix 8
#define InUsePrefix 1

enum INSTRUCTION_TYPE
{
  GENERAL_PURPOSE_INSTRUCTION = 0x10000,
  FPU_INSTRUCTION = 0x20000,
  MMX_INSTRUCTION = 0x40000,
  SSE_INSTRUCTION = 0x80000,
  SSE2_INSTRUCTION = 0x100000,
  SSE3_INSTRUCTION = 0x200000,
  SSSE3_INSTRUCTION = 0x400000,
  SSE41_INSTRUCTION = 0x800000,
  SSE42_INSTRUCTION = 0x1000000,
  SYSTEM_INSTRUCTION = 0x2000000,
  VM_INSTRUCTION = 0x4000000,
  UNDOCUMENTED_INSTRUCTION = 0x8000000,
  AMD_INSTRUCTION = 0x10000000,
  ILLEGAL_INSTRUCTION = 0x20000000,
  INCOMPATIBLE_TYPE = 0x80000000,


    DATA_TRANSFER = 0x1,
    ARITHMETIC_INSTRUCTION,
    LOGICAL_INSTRUCTION,
    SHIFT_ROTATE,
    BIT_BYTE,
    CONTROL_TRANSFER,
    STRING_INSTRUCTION,
    InOutINSTRUCTION,
    ENTER_LEAVE_INSTRUCTION,
    FLAG_CONTROL_INSTRUCTION,
    SEGMENT_REGISTER,
    MISCELLANEOUS_INSTRUCTION,
    COMPARISON_INSTRUCTION,
    LOGARITHMIC_INSTRUCTION,
    TRIGONOMETRIC_INSTRUCTION,
    UNSUPPORTED_INSTRUCTION,
    LOAD_CONSTANTS,
    FPUCONTROL,
    STATE_MANAGEMENT,
    CONVERSION_INSTRUCTION,
    SHUFFLE_UNPACK,
    PACKED_SINGLE_PRECISION,
    SIMD128bits,
    SIMD64bits,
    CACHEABILITY_CONTROL,
    FP_INTEGER_CONVERSION,
    SPECIALIZED_128bits,
    SIMD_FP_PACKED,
    SIMD_FP_HORIZONTAL ,
    AGENT_SYNCHRONISATION,
    PACKED_ALIGN_RIGHT  ,
    PACKED_SIGN,
    PACKED_BLENDING_INSTRUCTION,
    PACKED_TEST,
    PACKED_MINMAX,
    HORIZONTAL_SEARCH,
    PACKED_EQUALITY,
    STREAMING_LOAD,
    INSERTION_EXTRACTION,
    DOT_PRODUCT,
    SAD_INSTRUCTION,
    ACCELERATOR_INSTRUCTION,    // crc32, popcnt (sse4.2)
    ROUND_INSTRUCTION

};

enum EFLAGS_STATES
{
  TE_ = 1,
  MO_ = 2,
  RE_ = 4,
  SE_ = 8,
  UN_ = 0x10,
  PR_ = 0x20
};

enum BRANCH_TYPE
{
  JO = 1,
  JC,
  JE,
  JA,
  JS,
  JP,
  JL,
  JG,
  JB,
  JECXZ,
  JmpType,
  CallType,
  RetType,
  JNO = -1,
  JNC = -2,
  JNE = -3,
  JNA = -4,
  JNS = -5,
  JNP = -6,
  JNL = -7,
  JNG = -8,
  JNB = -9
};

enum ARGUMENTS_TYPE
{
  NO_ARGUMENT = 0x10000000,
  REGISTER_TYPE = 0x20000000,
  MEMORY_TYPE = 0x40000000,
  CONSTANT_TYPE = 0x80000000,

  MMX_REG = 0x10000,
  GENERAL_REG = 0x20000,
  FPU_REG = 0x40000,
  SSE_REG = 0x80000,
  CR_REG = 0x100000,
  DR_REG = 0x200000,
  SPECIAL_REG = 0x400000,
  MEMORY_MANAGEMENT_REG = 0x800000,
  SEGMENT_REG = 0x1000000,

  RELATIVE_ = 0x4000000,
  ABSOLUTE_ = 0x8000000,

  READ = 0x1,
  WRITE = 0x2,

  REG0 = 0x1,
  REG1 = 0x2,
  REG2 = 0x4,
  REG3 = 0x8,
  REG4 = 0x10,
  REG5 = 0x20,
  REG6 = 0x40,
  REG7 = 0x80,
  REG8 = 0x100,
  REG9 = 0x200,
  REG10 = 0x400,
  REG11 = 0x800,
  REG12 = 0x1000,
  REG13 = 0x2000,
  REG14 = 0x4000,
  REG15 = 0x8000,
};

enum SPECIAL_INFO
{
  UNKNOWN_OPCODE = -1,
  OUT_OF_BLOCK = 0,

  // === mask = 0xff
  NoTabulation      = 0x00000000,
  Tabulation        = 0x00000001,

  // === mask = 0xff00
  MasmSyntax        = 0x00000000,
  GoAsmSyntax       = 0x00000100,
  NasmSyntax        = 0x00000200,
  ATSyntax          = 0x00000400,

  // === mask = 0xff0000
  PrefixedNumeral   = 0x00010000,
  SuffixedNumeral   = 0x00000000,

  // === mask = 0xff000000
  ShowSegmentRegs   = 0x01000000
};


#ifdef __cplusplus
extern "C"
#endif
int __stdcall Disasm(LPDISASM pDisAsm);

#endif
