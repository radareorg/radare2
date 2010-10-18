//////////////////////////////////////////////////////////////
//
// x86 Instruction Manipulator: Decoder/Generator/Encoder v1.0
//
// (x) Pluf
//
//////////////////////////////////////////////////////////////

#include <r_types.h>
#define _CRT_SECURE_NO_WARNINGS
#if __WINDOWS__
# include <windows.h>
#elif __UNIX__
# include <string.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#include "x86im.h"

#ifdef __X86IM_USE_FMT__

#include "x86im_fmt.h"

char *tbl_imn_gpi[]=
{
    "AAA",
    "AAD",
    "AAM",
    "AAS",
    "BOUND",
    "BSWAP",
    "CLC",
    "CLD",
    "CLI",
    "CLTS",
    "CMC",
    "CMPS*",
    "CPUID",
    "DAA",
    "DAS",
    "HLT",
    "INSS*",
    "INVD",
    "INVLPG",
    "IRET",
    "JCXZ",
    "LAHF",
    "LDS",
    "LEA",
    "LEAVE",
    "LES",
    "LFS",
    "LGDT",
    "LGS",
    "LIDT",
    "LODS*",
    "LSS",
    "MOVS*",
    "NOP",
    "OUTS*",
    "RDMSR",
    "RDPMC",
    "RDTSC",
    "RSM",
    "SAHF",
    "SCAS*",
    "SGDT",
    "SIDT",
    "STC",
    "STD",
    "STI",
    "STOS*",
    "UD2",
    "WAIT",
    "WBINVD",
    "WRMSR",
    "XLAT",
    "CMPXCHG8B",
    "ENTER",
    "SYSENTER",
    "SYSEXIT",
    "CONVA",
    "CONVB",
    "INT",
    "INT3",
    "INTO",
    "LOOP",
    "LOOPE",
    "LOOPNE",
    "ADC",
    "ADD",
    "AND",
    "ARPL",
    "MOVSXD",
    "BSF",
    "BSR",
    "BT",
    "BTC",
    "BTR",
    "BTS",
    "CALL",
    "CALL FAR",
    "CMP",
    "CMPXCHG",
    "DEC",
    "DIV",
    "IDIV",
    "IMUL",
    "IN",
    "INC",
    "JCC SHORT",
    "JCC",
    "JMP SHORT",
    "JMP",
    "JMP FAR",
    "LAR",
    "LLDT",
    "LMSW",
    "LSL",
    "LTR",
    "MOV",
    "MOVSX",
    "MOVZX",
    "MUL",
    "NEG",
    "NOT",
    "OR",
    "OUT",
    "POP",
    "POPAD",
    "POPF",
    "PUSH",
    "PUSHAD",
    "PUSHF",
    "RCL",
    "RCR",
    "RET NEAR",
    "RET FAR",
    "ROL",
    "ROR",
    "SAR",
    "SBB",
    "SETCC",
    "SHL",
    "SHLD",
    "SHR",
    "SHRD",
    "SLDT",
    "SMSW",
    "STR",
    "SUB",
    "TEST",
    "VERR",
    "VERW",
    "XADD",
    "XCHG",
    "XOR",
    "CMOVCC",
    "SYSCALL",
    "SYSRET",
    "SWAPGS",
    "SAL"
};

char *tbl_imn_fpu[]=
{
    "F2XM1",
    "FABS",
    "FBLD",
    "FBSTP",
    "FCHS",
    "FNCLEX",
    "FCOMPP",
    "FCOMIP",
    "FCOS",
    "FDECSTP",
    "FFREE",
    "FINCSTP",
    "FNINIT",
    "FLD1",
    "FLDCW",
    "FLDENV",
    "FLDL2E",
    "FLDL2T",
    "FLDLG2",
    "FLDLN2",
    "FLDPI",
    "FLDZ",
    "FNOP",
    "FPATAN",
    "FPREM",
    "FPREM1",
    "FPTAN",
    "FRNDINT",
    "FRSTOR",
    "FNSAVE",
    "FSCALE",
    "FSIN",
    "FSINCOS",
    "FSQRT",
    "FNSTCW",
    "FNSTENV",
    "FTST",
    "FUCOM",
    "FUCOMP",
    "FUCOMPP",
    "FUCOMI",
    "FUCOMIP",
    "FXAM",
    "FXCH",
    "FXTRACT",
    "FYL2X",
    "FYL2XP1",
    "FADDP",
    "FDIVP",
    "FDIVRP",
    "FMULP",
    "FSUBP",
    "FSUBRP",
    "FCOMI",
    "FADD",
    "FCOM",
    "FCOMP",
    "FDIV",
    "FDIVR",
    "FIADD",
    "FICOM",
    "FICOMP",
    "FIDIV",
    "FIDIVR",
    "FILD",
    "FIMUL",
    "FIST",
    "FISTP",
    "FISUB",
    "FISUBR",
    "FLD",
    "FMUL",
    "FST",
    "FSTP",
    "FNSTSW",
    "FSUB",
    "FSUBR",
    "FCMOVB",
    "FCMOVE",
    "FCMOVBE",
    "FCMOVU",
    "FCMOVNB",
    "FCMOVNE",
    "FCMOVNBE",
    "FCMOVNU",
    "FXSAVE",
    "FXRSTOR",
    "FCOM2",
    "FCOMP3",
    "FCOMP5",
    "FXCH4",
    "FXCH7",
    "FSTP1",
    "FSTP8",
    "FSTP9",
    "FFREEP"
};

char *tbl_imn_mmx[]=
{
    "EMMS",
    "MOVD",
    "MOVQ",
    "PACKSSDW",
    "PACKSSWB",
    "PACKUSWB",
    "PADD",
    "PADDS",
    "PADDUS",
    "PAND",
    "PANDN",
    "PCMPEQ",
    "PCMPGT",
    "PMADDWD",
    "PMULHW",
    "PMULLW",
    "POR",
    "PSLLW",
    "PSLLD",
    "PSLLQ",
    "PSRAW",
    "PSRAD",
    "PSRLW",
    "PSRLD",
    "PSRLQ",
    "PSUB",
    "PSUBS",
    "PSUBUS",
    "PUNPCKH",
    "PUNPCKL",
    "PXOR"
};

char *tbl_imn_3dn[]=
{
    "PI2FW",
    "PI2FD",
    "PF2IW",
    "PF2ID",
    "PFNACC",
    "PFPNACC",
    "PFCMPGE",
    "PFMIN",
    "PFRCP",
    "PFRSQRT",
    "PFSUB",
    "PFADD",
    "PFCMPGT",
    "PFMAX",
    "PFRCPIT1",
    "PFRSQIT1",
    "PFSUBR",
    "PFACC",
    "PFCMPEQ",
    "PFMUL",
    "PFRCPIT2",
    "PMULHRW",
    "PSWAPD",
    "PAVGUSB"
};

char *tbl_imn_sse[]=
{
    "MOVMSKPS",
    "LDMXCSR",
    "STMXCSR",
    "MASKMOVQ",
    "MOVNTPS",
    "MOVNTQ",
    "PREFETCH",
    "SFENCE",
    "ADDPS",
    "ADDSS",
    "ANDNPS",
    "ANDPS",
    "CMPPS",
    "CMPSS",
    "COMISS",
    "CVTPI2PS",
    "CVTPS2PI",
    "CVTSI2SS",
    "CVTSS2SI",
    "CVTTPS2PI",
    "CVTTSS2SI",
    "DIVPS",
    "DIVSS",
    "MAXPS",
    "MAXSS",
    "MINPS",
    "MINSS",
    "MOVAPS",
    "MOVLHPS",
    "MOVHPS",
    "MOVHLPS",
    "MOVLPS",
    "MOVSS",
    "MOVUPS",
    "MULPS",
    "MULSS",
    "ORPS",
    "RCPPS",
    "RCPSS",
    "RSQRTPS",
    "RSQRTSS",
    "SHUFPS",
    "SQRTPS",
    "SQRTSS",
    "SUBPS",
    "SUBSS",
    "UCOMISS",
    "UNPCKHPS",
    "UNPCKLPS",
    "XORPS",
    "PEXTRW",
    "PMOVMSKB",
    "PAVGB",
    "PAVGW",
    "PINSRW",
    "PMAXSW",
    "PMAXUB",
    "PMINSW",
    "PMINUB",
    "PMULHUW",
    "PSADBW",
    "PSHUFW"
};

char *tbl_imn_sse2[]=
{
    "MOVMSKPD",
    "MASKMOVDQU",
    "CLFLUSH",
    "MOVNTPD",
    "MOVNTDQ",
    "MOVNTI",
    "PAUSE",
    "LFENCE",
    "MFENCE",
    "ADDPD",
    "ADDSD",
    "ANDNPD",
    "ANDPD",
    "CMPPD",
    "CMPSD",
    "COMISD",
    "CVTPI2PD",
    "CVTPD2PI",
    "CVTSI2SD",
    "CVTSD2SI",
    "CVTTPD2PI",
    "CVTTSD2SI",
    "CVTPD2PS",
    "CVTPS2PD",
    "CVTSD2SS",
    "CVTSS2SD",
    "CVTPD2DQ",
    "CVTTPD2DQ",
    "CVTDQ2PD",
    "CVTPS2DQ",
    "CVTTPS2DQ",
    "CVTDQ2PS",
    "DIVPD",
    "DIVSD",
    "MAXPD",
    "MAXSD",
    "MINPD",
    "MINSD",
    "MOVAPD",
    "MOVHPD",
    "MOVLPD",
    "MOVSD",
    "MOVUPD",
    "MULPD",
    "MULSD",
    "ORPD",
    "SHUFPD",
    "SQRTPD",
    "SQRTSD",
    "SUBPD",
    "SUBSD",
    "UCOMISD",
    "UNPCKHPD",
    "UNPCKLPD",
    "XORPD",
    "MOVQ2DQ",
    "MOVDQ2Q",
    "PSLLDQ",
    "PSRLDQ",
    "MOVDQA",
    "MOVDQU",
    "PADDQ",
    "PMULUDQ",
    "PSHUFLW",
    "PSHUFHW",
    "PSHUFD",
    "PSUBQ",
    "PUNPCKHQDQ",
    "PUNPCKLQDQ"
};

char *tbl_imn_sse3[]=
{
    "MONITOR",
    "MWAIT",
    "LDDQU",
    "ADDSUBPD",
    "ADDSUBPS",
    "HADDPD",
    "HADDPS",
    "HSUBPD",
    "HSUBPS",
    "FISTTP",
    "MOVDDUP",
    "MOVSHDUP",
    "MOVSLDUP",
    "PABS",
    "PALIGNR",
    "PHADDSW",
    "PHSUBSW",
    "PMADDUBSW",
    "PMULHRSW",
    "PSHUFB",
    "PSIGN",
    "PHADD",
    "PHSUB"
};

char **tbl_imn[]=
{
    tbl_imn_gpi,
    tbl_imn_fpu,
    tbl_imn_mmx,
    tbl_imn_3dn,
    tbl_imn_sse,
    tbl_imn_sse2,
    tbl_imn_sse3
};

char *tbl_reg_gpr8[]=
{
    "AL",
    "CL",
    "DL",
    "BL",
    "AH",
    "CH",
    "DH",
    "BH",
    "R8B",
    "R9B",
    "R10B",
    "R11B",
    "R12B",
    "R13B",
    "R14B",
    "R15B"
};

char *tbl_reg_gpr8B[]=
{
    "SPL",
    "BPL",
    "SIL",
    "DIL"
};

char *tbl_reg_gpr16[]=
{
    "AX",
    "CX",
    "DX",
    "BX",
    "SP",
    "BP",
    "SI",
    "DI",
    "R8W",
    "R9W",
    "R10W",
    "R11W",
    "R12W",
    "R13W",
    "R14W",
    "R15W"
};

char *tbl_reg_gpr32[]=
{
    "EAX",
    "ECX",
    "EDX",
    "EBX",
    "ESP",
    "EBP",
    "ESI",
    "EDI",
    "R8D",
    "R9D",
    "R10D",
    "R11D",
    "R12D",
    "R13D",
    "R14D",
    "R15D"
};

char *tbl_reg_gpr64[]=
{
    "RAX",
    "RCX",
    "RDX",
    "RBX",
    "RSP",
    "RBP",
    "RSI",
    "RDI",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15"
};

char *tbl_reg_srg[]=
{
    "ES",
    "CS",
    "SS",
    "DS",
    "FS",
    "GS",
    "??6",
    "??7",
    "??8",
    "??9",
    "??10",
    "??11",
    "??12",
    "??13",
    "??14",
    "??15"
};

char *tbl_reg_crg[]=
{
    "CR0",
    "CR1",
    "CR2",
    "CR3",
    "CR4",
    "CR5",
    "CR6",
    "CR7",
    "CR8",
    "CR9",
    "CR10",
    "CR11",
    "CR12",
    "CR13",
    "CR14",
    "CR15"
};

char *tbl_reg_drg[]=
{
    "DR0",
    "DR1",
    "DR2",
    "DR3",
    "DR4",
    "DR5",
    "DR6",
    "DR7",
    "DR8",
    "DR9",
    "DR10",
    "DR11",
    "DR12",
    "DR13",
    "DR14",
    "DR15"
};

char *tbl_reg_str[]=
{
    "ST0",
    "ST1",
    "ST2",
    "ST3",
    "ST4",
    "ST5",
    "ST6",
    "ST7",
    "??8",
    "??9",
    "??10",
    "??11",
    "??12",
    "??13",
    "??14",
    "??15"
};

char *tbl_reg_mxr[]=
{
    "MM0",
    "MM1",
    "MM2",
    "MM3",
    "MM4",
    "MM5",
    "MM6",
    "MM7",
    "??8",
    "??9",
    "??10",
    "??11",
    "??12",
    "??13",
    "??14",
    "??15"
};

char *tbl_reg_xmr[]=
{
    "XMM0",
    "XMM1",
    "XMM2",
    "XMM3",
    "XMM4",
    "XMM5",
    "XMM6",
    "XMM7",
    "XMM8",
    "XMM9",
    "XMM10",
    "XMM11",
    "XMM12",
    "XMM13",
    "XMM14",
    "XMM15"
};

char **tbl_reg[]=
{
    tbl_reg_gpr8,
    tbl_reg_gpr16,
    tbl_reg_gpr8B,
    tbl_reg_gpr32,
    tbl_reg_xmr,
    tbl_reg_crg,
    tbl_reg_drg,
    tbl_reg_gpr64,
    NULL,   // rip = FIX this
    tbl_reg_mxr,
    tbl_reg_srg,
    tbl_reg_str,
};

char *tbl_tttn[]=
{
    "O",
    "NO",
    "B",
    "NB",
    "E",
    "NE",
    "BE",
    "NBE",
    "S",
    "NS",
    "P",
    "NP",
    "L",
    "NL",
    "LE",
    "NLE"
};

char *x86f_get_imn( __in x86im_instr_object *io )
{
    return ( char * )( ( tbl_imn[ ( io->mnm >> 8 ) & 0xFF ] )[ io->mnm & 0xFF ] );
}

char *x86f_get_reg( __in unsigned short reg )
{
    return ( char * )( ( tbl_reg[ ( X86IM_IO_ROP_GET_GR( reg )-1 ) >> 4 ] )[ X86IM_IO_ROP_GET_ID( reg ) ] );
}

void x86im_fmt_format_prefix( __in x86im_instr_object *io,
                    __out char *pfx )
{
    char *tbl_pfx[]= { "LOCK", "REP", "REPNE" };

    memset( pfx, 0, 256 );

    if ( io->prefix & 0x7 )
    {
        if ( io->somimp == 0 ||
             !( io->somimp & io->prefix ) )
        {
            strcpy( pfx, tbl_pfx[ ( io->prefix & 0x7 ) >> 1 ] );

            if ( X86IM_IO_IP_HAS_REPE( io ) &&
                ( io->id == X86IM_IO_ID_CMPSX ||
                  io->id == X86IM_IO_ID_SCASX ) )
            {
                pfx[3] = 'E';
            }
        }
    }
}

void x86im_fmt_format_name( __in x86im_instr_object *io,
                   __in char *name )
{
    char size[6]= {"BWDQER"};
    unsigned int i;
    char *tbl_conv[]=
    {
        "CBW",
        "CWDE",
        "CDQE",
        "CWD",
        "CDQ",
        "CQO"
    };

    memset( name, 0, 256 );
    strcpy( name, x86f_get_imn( io ) );

    if ( X86IM_IO_IF_HAS_NZ( io ) || X86IM_IO_IF_HAS_NC( io ) )
    {
        if ( name[4] == '*' )
        {
            i = io->def_opsz >> 1;
            if ( i & 4 )
            {
                --i;
            }

            name[4] = size[i];
        }
        else if ( io->mnm == X86IM_IO_IMN_JCXZ )
        {
            if ( io->def_adsz != 2 )
            {
                if ( io->def_adsz == 4 )
                {
                    *( DWORD * )&name[1] = *( DWORD * )"ECXZ";
                }
                else
                {
                    *( DWORD * )&name[1] = *( DWORD * )"RCXZ";
                }
            }
        }
        else if ( io->mnm == X86IM_IO_IMN_PUSHF ||
                  io->mnm == X86IM_IO_IMN_POPF )
        {
            i = 4;
            if ( io->mnm == X86IM_IO_IMN_PUSHF )
            {
                ++i;
            }

            if ( io->def_opsz == 4 )
            {
                name[i] = 'D';
            }
            if ( io->def_opsz == 8 )
            {
                name[i] = 'Q';
            }
        }
        else if ( io->mnm == X86IM_IO_IMN_IRET )
        {
            if ( io->def_opsz == 4 )
            {
                name[4] = 'D';
            }
            if ( io->def_opsz == 8 )
            {
                name[4] = 'Q';
            }
        }
        else if ( io->mnm == X86IM_IO_IMN_CONVERT_A ||
                  io->mnm == X86IM_IO_IMN_CONVERT_B )
        {
            i = ( io->def_opsz / 2 ) >> 1;
            if ( i & 4 )
            {
                --i;
            }
            if ( io->mnm == X86IM_IO_IMN_CONVERT_B )
            {
                i += 3;
            }

            strcpy( name, tbl_conv[ i ] );
        }
        else if ( X86IM_IO_IF_HAS_TTTN( io ) )
        {
            if ( io->mnm == X86IM_IO_IMN_JCC )
            {
                strcpy( &name[1], tbl_tttn[ io->tttn_fld ] );
            }
            else if ( io->mnm == X86IM_IO_IMN_SETCC )
            {
                strcpy( &name[3], tbl_tttn[ io->tttn_fld ] );
            }
            else
            {
                strcpy( &name[4], tbl_tttn[ io->tttn_fld ] );
            }
        }
        else if ( io->mnm == X86IM_IO_IMN_ARPL &&
                  X86IM_IO_IS_MODE_64BIT( io ) )
        {
            strcpy( name, ( char * )( ( tbl_imn[ X86IM_IO_IMNG_GPI ] )[ X86IM_IO_IMN_MOVSXD  ] ) );
        }
        else if ( io->mnm == X86IM_IO_IMN_CMPXCHGXX )
        {
            if ( io->def_opsz == 8 )
            {
                *( DWORD *)&name[7] = *( DWORD * )"16B";
            }
            else
            {
                *( WORD *)&name[7] = *( WORD *)"8B";
            }
        }
        else if ( io->mnm == X86IM_IO_IMN_SYSRET )
        {
            if ( io->def_opsz == 8 )
            {
                name[6] = 'Q';
            }
        }
        else if ( X86IM_IO_IS_IG_MMX( io ) ||
                  X86IM_IO_IS_IG_SSE( io ) ||
                  X86IM_IO_IS_IG_SSE2( io ) ||
                  X86IM_IO_IS_IG_SSE3( io ) )
        {
            if ( io->mnm == X86IM_IO_IMN_PREFETCH )
            {
                if ( X86IM_IO_GET_MODRM_FLD_REG( io->modrm ) & 0x3 )
                {
                    name[ 8 ] = 'T';
                    name[ 9 ] = ( unsigned char )0x2F + X86IM_IO_GET_MODRM_FLD_REG( io->modrm );
                }
                else
                {
                    *( unsigned long *)( name + 8 ) = *( DWORD * )"NTA";
                }
            }
            else
            {
                switch( io->mnm )
                {
                case X86IM_IO_IMN_PCMPGT: case X86IM_IO_IMN_PCMPEQ:
                case X86IM_IO_IMN_PSUBUS: case X86IM_IO_IMN_PADDUS:
                case X86IM_IO_IMN_PSUBS:  case X86IM_IO_IMN_PADDS:
                case X86IM_IO_IMN_PSUB:   case X86IM_IO_IMN_PADD:
                case X86IM_IO_IMN_PHADD:  case X86IM_IO_IMN_PHSUB:
                case X86IM_IO_IMN_PSIGN:  case X86IM_IO_IMN_PABS:

                    name[ strlen( name ) ] = size[ io->gg_fld ];
                    break;

                case X86IM_IO_IMN_PUNPCKL: case X86IM_IO_IMN_PUNPCKH:

                    *( unsigned short * )( name + strlen( name ) ) = *( unsigned short * )( size + io->gg_fld );
                    break;
                }
            }
        }
    }
}

void x86im_fmt_format_operand( __in x86im_instr_object *io,
                     __out char *dst,
                     __out char *src )
{
    unsigned int i;
    char *p, ptr[ 256 ];
    char *tbl_memopsz[]=
    {
	    "BYTE PTR",
        "WORD PTR",
        "DWORD PTR",
        "FWORD PTR",
        "QWORD PTR",
        "TBYTE PTR",
        "OWORD PTR",
        ""
    };

    memset( dst, 0, 256 );
    memset( src, 0, 256 );
    memset( ptr, 0, 256 );

    if ( X86IM_IO_IF_HAS_IMP_OP( io ) || X86IM_IO_IF_HAS_EXP_OP( io ) )
    {
        if ( X86IM_IO_IF_HAS_MEM_OP( io ) )
        {
            i = 0;

            if ( X86IM_IO_MOP_AMC_HAS_BASE( io ) )
            {
                strcpy( ptr, io->mem_base == X86IM_IO_ROP_ID_RIP ? "RIP": x86f_get_reg( io->mem_base ) );

                ++i;
            }

            if ( X86IM_IO_MOP_AMC_HAS_INDEX( io ) )
            {
                sprintf( ptr + strlen( ptr ),
                         "%s%s",
                         i ? "+": "",
                         x86f_get_reg( io->mem_index ) );

                if ( X86IM_IO_MOP_AMC_HAS_SCALE( io ) )
                {
                    sprintf( ptr + strlen( ptr ),
                             "*%d",
                             io->mem_scale );
                }

                ++i;
            }

            if ( X86IM_IO_MOP_AMC_HAS_DISP( io ) )
            {
                if ( X86IM_IO_MOP_AMC_HAS_DISP64( io ) )
                {
                    p = "%s%"PFMT64x;
                }
                else
                {
                    p = "%s%X";
                }

                sprintf( ptr + strlen( ptr ),
                         p,
                         i ? "+": "",
                         io->disp );
            }

            if ( X86IM_IO_MOP_IS_SRC( io ) )
            {
                p = src;
            }
            else
            {
                p = dst;
            }

            switch( io->mem_size )
            {
                case X86IM_IO_MOP_SZ_BYTE_PTR:   i = 0;
                                    break;
                case X86IM_IO_MOP_SZ_WORD_PTR:   i = 1;
                                    break;
                case X86IM_IO_MOP_SZ_DWORD_PTR:  i = 2;
                                    break;
                case X86IM_IO_MOP_SZ_FWORD_PTR:  i = 3;
                                    break;
                case X86IM_IO_MOP_SZ_QWORD_PTR:  i = 4;
                                    break;
                case X86IM_IO_MOP_SZ_TBYTE_PTR:  i = 5;
                                    break;
                case X86IM_IO_MOP_SZ_OWORD_PTR:  i = 6;
                                    break;
                default:            i = 7; break;
            }

            sprintf( p,
                     "%s %s:[%s]",
                     tbl_memopsz[ i ],
                     tbl_reg_srg[ X86IM_IO_ROP_GET_ID( io->seg ) ],
                     ptr );
        }

        if ( X86IM_IO_IF_HAS_REG_OP( io ) )
        {
            for ( i = 0;
                  i < io->rop_count;
                  i++ )
            {
                if ( X86IM_IO_ROP_IS_DST( io->rop[ i ] ) )
                {
                    p = dst;
                }
                else
                {
                    p = src;
                }

                if ( p[0] )
                {
                    strcat( p, "," );
                }

                strcat( p, x86f_get_reg( ( unsigned short )io->rop[ i ] ) );
            }
        }

        if ( X86IM_IO_IF_HAS_IMM_OP( io ) )
        {
            if ( io->imm_size )
            {
                if ( src[0] != 0 && dst[0] != 0 )
                {
                    sprintf( src,
                             "%s,%lX",
                             src,
                             ( unsigned long ) io->imm );
                }
                else if ( src[0] == 0 && dst[0] != 0 )
                {
                    if ( io->imm_size == X86IM_IO_IM_SZ_QWORD )
                    {
                        sprintf( src, "%"PFMT64x, io->imm );
                    }
                    else
                    {
                        sprintf( src, "%lX", ( unsigned long ) io->imm );
                    }
                }
                else if ( io->id == X86IM_IO_ID_OUT_IM )
                {
                    strcpy( dst, src );
                    sprintf( src, "%lX,%s",
                             ( unsigned long ) io->imm,
                             dst );
                    dst[0] = 0x0;
                }
                else if ( src[0] == 0 && dst[0] == 0 )
                {
                    if ( X86IM_IO_IF_HAS_SEL( io ) )
                    {
                        sprintf( dst, "%02X:", io->selector );
                    }

                    if ( io->imm_size == 8 )
                    {
                        sprintf( dst + strlen(dst), "%"PFMT64x, io->imm );
                    }
                    else if ( io->imm_size == 3 )
                    {
                        sprintf( dst + strlen(dst),
                                 "%X,%X",
                                 ( unsigned short )io->imm,
                                 ( unsigned char )( io->imm >> 16 ) );
                    }
                    else
                    {
                        sprintf( dst + strlen(dst), "%"PFMT64x, io->imm );
                    }
                }
            }
        }
    }
}

unsigned int x86im_fmt( __in x86im_instr_object *io )
{
    unsigned int ret = 0;
    char *data,
         *pfx,
         *name,
         *dst,
         *src;

    data = ( char * ) calloc( 1, 4096 );
    if ( data )
    {
        pfx  = data;
        name = pfx  + 256;
        dst  = name + 256;
        src  = dst  + 256;

        x86im_fmt_format_prefix( io, pfx );
        x86im_fmt_format_name( io, name );
        x86im_fmt_format_operand( io, dst, src );

        io->data = ( char * ) calloc( 1, 256 );
        if ( io->data )
        {
            ret = sprintf( io->data,
                           "%s %s %s%s%s",
                           pfx,
                           name,
                           dst,
                           dst[0] && src[0]? ",": "",
                           src );
        }

        free( data );
    }

    return ret;
}

#endif
