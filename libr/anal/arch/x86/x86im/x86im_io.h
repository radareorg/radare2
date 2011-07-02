//////////////////////////////////////////////////////////////
//
// x86 Instruction Manipulator: Decoder/Generator/Encoder v1.0
//
// (x) Pluf
//
//////////////////////////////////////////////////////////////

#ifndef __X86IM_IO_H__
#define __X86IM_IO_H__

// instr id

// GPI

#define X86IM_IO_ID_AAA                                 0x0000
#define X86IM_IO_ID_AAD                                 0x0001
#define X86IM_IO_ID_AAM                                 0x0002
#define X86IM_IO_ID_AAS                                 0x0003
#define X86IM_IO_ID_BOUND                               0x0004
#define X86IM_IO_ID_BSWAP                               0x0005
#define X86IM_IO_ID_CLC                                 0x0006
#define X86IM_IO_ID_CLD                                 0x0007
#define X86IM_IO_ID_CLI                                 0x0008
#define X86IM_IO_ID_CLTS                                0x0009
#define X86IM_IO_ID_CMC                                 0x000A
#define X86IM_IO_ID_CMPSX                               0x000B
#define X86IM_IO_ID_CPUID                               0x000C
#define X86IM_IO_ID_DAA                                 0x000D
#define X86IM_IO_ID_DAS                                 0x000E
#define X86IM_IO_ID_HLT                                 0x000F
#define X86IM_IO_ID_INSX                                0x0010
#define X86IM_IO_ID_INVD                                0x0011
#define X86IM_IO_ID_INVLPG                              0x0012
#define X86IM_IO_ID_IRET                                0x0013
#define X86IM_IO_ID_JCXZ                                0x0014
#define X86IM_IO_ID_LAHF                                0x0015
#define X86IM_IO_ID_LDS                                 0x0016
#define X86IM_IO_ID_LEA                                 0x0017
#define X86IM_IO_ID_LEAVE                               0x0018
#define X86IM_IO_ID_LES                                 0x0019
#define X86IM_IO_ID_LFS                                 0x001A
#define X86IM_IO_ID_LGDT                                0x001B
#define X86IM_IO_ID_LGS                                 0x001C
#define X86IM_IO_ID_LIDT                                0x001D
#define X86IM_IO_ID_LODSX                               0x001E
#define X86IM_IO_ID_LSS                                 0x001F
#define X86IM_IO_ID_MOVSX                               0x0020
#define X86IM_IO_ID_NOP                                 0x0021
#define X86IM_IO_ID_OUTSX                               0x0022
#define X86IM_IO_ID_RDMSR                               0x0023
#define X86IM_IO_ID_RDPMC                               0x0024
#define X86IM_IO_ID_RDTSC                               0x0025
#define X86IM_IO_ID_RSM                                 0x0026
#define X86IM_IO_ID_SAHF                                0x0027
#define X86IM_IO_ID_SCASX                               0x0028
#define X86IM_IO_ID_SGDT                                0x0029
#define X86IM_IO_ID_SIDT                                0x002A
#define X86IM_IO_ID_STC                                 0x002B
#define X86IM_IO_ID_STD                                 0x002C
#define X86IM_IO_ID_STI                                 0x002D
#define X86IM_IO_ID_STOSX                               0x002E
#define X86IM_IO_ID_UD2                                 0x002F
#define X86IM_IO_ID_WAIT                                0x0030
#define X86IM_IO_ID_WBINVD                              0x0031
#define X86IM_IO_ID_WRMSR                               0x0032
#define X86IM_IO_ID_XLAT                                0x0033
#define X86IM_IO_ID_CMPXCHGXX                           0x0034
#define X86IM_IO_ID_ENTER                               0x0035
#define X86IM_IO_ID_SYSENTER                            0x0036
#define X86IM_IO_ID_SYSEXIT                             0x0037
#define X86IM_IO_ID_CONVERT_A                           0x0038   // CBW/CWDE/CDQE
#define X86IM_IO_ID_CONVERT_B                           0x0039   // CWD/CDQ/CQO
#define X86IM_IO_ID_SYSCALL                             0x0430
#define X86IM_IO_ID_SYSRET                              0x0431
#define X86IM_IO_ID_SWAPGS                              0x0432

#define X86IM_IO_IS_GPI_INT(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0040 )
#define X86IM_IO_ID_INTN                                0x0040+0
#define X86IM_IO_ID_INT3                                0x0040+1
#define X86IM_IO_ID_INTO                                0x0040+2

#define X86IM_IO_IS_GPI_LOOP(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0050 )
#define X86IM_IO_ID_LOOP                                0x0050+0
#define X86IM_IO_ID_LOOPE                               0x0050+1
#define X86IM_IO_ID_LOOPNE                              0x0050+2

#define X86IM_IO_IS_GPI_ADC(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0060 )
#define X86IM_IO_ID_ADC_MM_RG                           0x0060+0
#define X86IM_IO_ID_ADC_R2_R1                           0x0060+1
#define X86IM_IO_ID_ADC_RG_MM                           0x0060+2
#define X86IM_IO_ID_ADC_R1_R2                           0x0060+3
#define X86IM_IO_ID_ADC_MM_IM                           0x0060+4
#define X86IM_IO_ID_ADC_RG_IM                           0x0060+5
#define X86IM_IO_ID_ADC_AC_IM                           0x0060+6

#define X86IM_IO_IS_GPI_ADD(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0070 )
#define X86IM_IO_ID_ADD_MM_RG                           0x0070+0
#define X86IM_IO_ID_ADD_R2_R1                           0x0070+1
#define X86IM_IO_ID_ADD_RG_MM                           0x0070+2
#define X86IM_IO_ID_ADD_R1_R2                           0x0070+3
#define X86IM_IO_ID_ADD_MM_IM                           0x0070+4
#define X86IM_IO_ID_ADD_RG_IM                           0x0070+5
#define X86IM_IO_ID_ADD_AC_IM                           0x0070+6

#define X86IM_IO_IS_GPI_AND(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0080 )
#define X86IM_IO_ID_AND_MM_RG                           0x0080+0
#define X86IM_IO_ID_AND_R2_R1                           0x0080+1
#define X86IM_IO_ID_AND_RG_MM                           0x0080+2
#define X86IM_IO_ID_AND_R1_R2                           0x0080+3
#define X86IM_IO_ID_AND_MM_IM                           0x0080+4
#define X86IM_IO_ID_AND_RG_IM                           0x0080+5
#define X86IM_IO_ID_AND_AC_IM                           0x0080+6

#define X86IM_IO_IS_GPI_ARPL(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0090 )
#define X86IM_IO_ID_ARPL_MM_RG                          0x0090+0 // ARPL: MOVSXD_RG_MM en 64bit mode
#define X86IM_IO_ID_ARPL_R1_R2                          0x0090+1 //       MOVSXD_R1_R2 en 64bit mode

#define X86IM_IO_IS_GPI_BSF(x)                          ( ( (x)->id & 0xFFF0 ) == 0x00A0 )
#define X86IM_IO_ID_BSF_RG_MM                           0x00A0+0
#define X86IM_IO_ID_BSF_R1_R2                           0x00A0+1

#define X86IM_IO_IS_GPI_BSR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x00B0 )
#define X86IM_IO_ID_BSR_RG_MM                           0x00B0+0
#define X86IM_IO_ID_BSR_R1_R2                           0x00B0+1

#define X86IM_IO_IS_GPI_BT(x)                           ( ( (x)->id & 0xFFF0 ) == 0x00C0 )
#define X86IM_IO_ID_BT_MM_IM                            0x00C0+0
#define X86IM_IO_ID_BT_RG_IM                            0x00C0+1
#define X86IM_IO_ID_BT_MM_RG                            0x00C0+2
#define X86IM_IO_ID_BT_R1_R2                            0x00C0+3

#define X86IM_IO_IS_GPI_BTC(x)                          ( ( (x)->id & 0xFFF0 ) == 0x00D0 )
#define X86IM_IO_ID_BTC_MM_IM                           0x00D0+0
#define X86IM_IO_ID_BTC_RG_IM                           0x00D0+1
#define X86IM_IO_ID_BTC_MM_RG                           0x00D0+2
#define X86IM_IO_ID_BTC_R1_R2                           0x00D0+3

#define X86IM_IO_IS_GPI_BTR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x00E0 )
#define X86IM_IO_ID_BTR_MM_IM                           0x00E0+0
#define X86IM_IO_ID_BTR_RG_IM                           0x00E0+1
#define X86IM_IO_ID_BTR_MM_RG                           0x00E0+2
#define X86IM_IO_ID_BTR_R1_R2                           0x00E0+3

#define X86IM_IO_IS_GPI_BTS(x)                          ( ( (x)->id & 0xFFF0 ) == 0x00F0 )
#define X86IM_IO_ID_BTS_MM_IM                           0x00F0+0
#define X86IM_IO_ID_BTS_RG_IM                           0x00F0+1
#define X86IM_IO_ID_BTS_MM_RG                           0x00F0+2
#define X86IM_IO_ID_BTS_R1_R2                           0x00F0+3

#define X86IM_IO_IS_GPI_CALL(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0100 )
#define X86IM_IO_ID_IS_GPI_CALL_NEAR(x)                 ( ( (x)->id & 0xFFFC ) == 0x0100 )
#define X86IM_IO_ID_IS_GPI_CALL_FAR(x)                  ( ( (x)->id & 0xFFFC ) == 0x0104 )
#define X86IM_IO_ID_CALL_N_R                            0x0100+0
#define X86IM_IO_ID_CALL_N_AI_MM                        0x0100+1
#define X86IM_IO_ID_CALL_N_AI_RG                        0x0100+2
#define X86IM_IO_ID_CALL_F_A                            0x0104+0
#define X86IM_IO_ID_CALL_F_AI_MM                        0x0104+1

#define X86IM_IO_IS_GPI_CMP(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0110 )
#define X86IM_IO_ID_CMP_MM_RG                           0x0110+0
#define X86IM_IO_ID_CMP_R1_R2                           0x0110+1
#define X86IM_IO_ID_CMP_RG_MM                           0x0110+2
#define X86IM_IO_ID_CMP_R2_R1                           0x0110+3
#define X86IM_IO_ID_CMP_MM_IM                           0x0110+4
#define X86IM_IO_ID_CMP_RG_IM                           0x0110+5
#define X86IM_IO_ID_CMP_AC_IM                           0x0110+6

#define X86IM_IO_IS_GPI_CMPXCHG(x)                      ( ( (x)->id & 0xFFF0 ) == 0x0120 )
#define X86IM_IO_ID_CMPXCHG_MM_RG                       0x0120+0
#define X86IM_IO_ID_CMPXCHG_R1_R2                       0x0120+1

#define X86IM_IO_IS_GPI_DEC(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0130 )
#define X86IM_IO_ID_DEC_MM                              0x0130+0
#define X86IM_IO_ID_DEC_RG1                             0x0130+1
#define X86IM_IO_ID_DEC_RG2                             0x0130+2

#define X86IM_IO_IS_GPI_DIV(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0140 )
#define X86IM_IO_ID_DIV_AC_MM                           0x0140+0
#define X86IM_IO_ID_DIV_AC_RG                           0x0140+1

#define X86IM_IO_IS_GPI_IDIV(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0150 )
#define X86IM_IO_ID_IDIV_AC_MM                          0x0150+0
#define X86IM_IO_ID_IDIV_AC_RG                          0x0150+1

#define X86IM_IO_IS_GPI_IMUL(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0160 )
#define X86IM_IO_ID_IMUL_AC_MM                          0x0160+0
#define X86IM_IO_ID_IMUL_AC_RG                          0x0160+1
#define X86IM_IO_ID_IMUL_RG_MM                          0x0160+2
#define X86IM_IO_ID_IMUL_R1_R2                          0x0160+3
#define X86IM_IO_ID_IMUL_MM_IM_RG                       0x0160+4
#define X86IM_IO_ID_IMUL_R1_R2_IM                       0x0160+5

#define X86IM_IO_IS_GPI_IN(x)                           ( ( (x)->id & 0xFFF0 ) == 0x0170 )
#define X86IM_IO_ID_IN_IM                               0x0170+0
#define X86IM_IO_ID_IN_RG                               0x0170+1

#define X86IM_IO_IS_GPI_INC(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0180 )
#define X86IM_IO_ID_INC_MM                              0x0180+0
#define X86IM_IO_ID_INC_RG1                             0x0180+1
#define X86IM_IO_ID_INC_RG2                             0x0180+2

#define X86IM_IO_IS_GPI_JCC(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0190 )
#define X86IM_IO_ID_JCC_S                               0x0190+0
#define X86IM_IO_ID_JCC_N                               0x0190+1

#define X86IM_IO_IS_GPI_JMP(x)                          ( ( (x)->id & 0xFFF0 ) == 0x01A0 )
#define X86IM_IO_ID_IS_GPI_JMP_NEAR(x)                  ( ( (x)->id & 0xFFFC ) == 0x01A0 )
#define X86IM_IO_ID_IS_GPI_JMP_FAR(x)                   ( ( (x)->id & 0xFFFC ) == 0x01A4 )
#define X86IM_IO_ID_JMP_N_R_S                           0x01A0+0
#define X86IM_IO_ID_JMP_N_R                             0x01A0+1
#define X86IM_IO_ID_JMP_N_AI_MM                         0x01A0+2
#define X86IM_IO_ID_JMP_N_AI_RG                         0x01A0+3
#define X86IM_IO_ID_JMP_F_A                             0x01A4+0
#define X86IM_IO_ID_JMP_F_AI_MM                         0x01A4+1

#define X86IM_IO_IS_GPI_LAR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x01B0 )
#define X86IM_IO_ID_LAR_RG_MM                           0x01B0+0
#define X86IM_IO_ID_LAR_R1_R2                           0x01B0+1

#define X86IM_IO_IS_GPI_LLDT(x)                         ( ( (x)->id & 0xFFF0 ) == 0x01C0 )
#define X86IM_IO_ID_LLDT_MM                             0x01C0+0
#define X86IM_IO_ID_LLDT_RG                             0x01C0+1

#define X86IM_IO_IS_GPI_LMSW(x)                         ( ( (x)->id & 0xFFF0 ) == 0x01D0 )
#define X86IM_IO_ID_LMSW_MM                             0x01D0+0
#define X86IM_IO_ID_LMSW_RG                             0x01D0+1

#define X86IM_IO_IS_GPI_LSL(x)                          ( ( (x)->id & 0xFFF0 ) == 0x01E0 )
#define X86IM_IO_ID_LSL_RG_MM                           0x01E0+0
#define X86IM_IO_ID_LSL_R1_R2                           0x01E0+1

#define X86IM_IO_IS_GPI_LTR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x01F0 )
#define X86IM_IO_ID_LTR_MM                              0x01F0+0
#define X86IM_IO_ID_LTR_RG                              0x01F0+1

#define X86IM_IO_IS_GPI_MOV(x)                          ( ( (x)->id & 0xFFC0 ) == 0x0200 )
#define X86IM_IO_IS_GPI_MOV_CRG(x)                      ( ( (x)->id & 0xFFF8 ) == 0x0210 )
#define X86IM_IO_IS_GPI_MOV_DRG(x)                      ( ( (x)->id & 0xFFF8 ) == 0x0218 )
#define X86IM_IO_IS_GPI_MOV_SRG(x)                      ( ( (x)->id & 0xFFF0 ) == 0x0220 )
#define X86IM_IO_ID_MOV_MM_RG                           0x0200+0
#define X86IM_IO_ID_MOV_R2_R1                           0x0200+1
#define X86IM_IO_ID_MOV_RG_MM                           0x0200+2
#define X86IM_IO_ID_MOV_R1_R2                           0x0200+3
#define X86IM_IO_ID_MOV_MM_IM                           0x0200+4
#define X86IM_IO_ID_MOV_RG_IM                           0x0200+5
#define X86IM_IO_ID_MOV_AC_IM                           0x0200+6
#define X86IM_IO_ID_MOV_AC_MM                           0x0200+7
#define X86IM_IO_ID_MOV_MM_AC                           0x0200+8
#define X86IM_IO_ID_MOV_CR0_RG                          0x0210+0
#define X86IM_IO_ID_MOV_CR2_RG                          0x0210+1
#define X86IM_IO_ID_MOV_CR3_RG                          0x0210+2
#define X86IM_IO_ID_MOV_CR4_RG                          0x0210+3
#define X86IM_IO_ID_MOV_RG_CRX                          0x0210+4
#define X86IM_IO_ID_MOV_CRX_RG                          0x0210+5
#define X86IM_IO_ID_MOV_DRX_RG                          0x0218+0
#define X86IM_IO_ID_MOV_RG_DRX                          0x0218+1
#define X86IM_IO_ID_MOV_SR_MM                           0x0220+0
#define X86IM_IO_ID_MOV_SR_RG                           0x0220+1
#define X86IM_IO_ID_MOV_MM_SR                           0x0220+2
#define X86IM_IO_ID_MOV_RG_SR                           0x0220+3

#define X86IM_IO_IS_GPI_MOVSX(x)                        ( ( (x)->id & 0xFFF0 ) == 0x0230 )
#define X86IM_IO_ID_MOVSX_RG_MM8                        0x0230+0
#define X86IM_IO_ID_MOVSX_R1_R28                        0x0230+1
#define X86IM_IO_ID_MOVSX_RG_MM16                       0x0230+2
#define X86IM_IO_ID_MOVSX_R1_R216                       0x0230+3

#define X86IM_IO_IS_GPI_MOVZX(x)                        ( ( (x)->id & 0xFFF0 ) == 0x0240 )
#define X86IM_IO_ID_MOVZX_RG_MM8                        0x0240+0
#define X86IM_IO_ID_MOVZX_R1_R28                        0x0240+1
#define X86IM_IO_ID_MOVZX_RG_MM16                       0x0240+2
#define X86IM_IO_ID_MOVZX_R1_R216                       0x0240+3

#define X86IM_IO_IS_GPI_MUL(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0250 )
#define X86IM_IO_ID_MUL_AC_MM                           0x0250+0
#define X86IM_IO_ID_MUL_AC_RG                           0x0250+1

#define X86IM_IO_IS_GPI_NEG(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0260 )
#define X86IM_IO_ID_NEG_MM                              0x0260+0
#define X86IM_IO_ID_NEG_RG                              0x0260+1

#define X86IM_IO_IS_GPI_NOT(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0270 )
#define X86IM_IO_ID_NOT_MM                              0x0270+0
#define X86IM_IO_ID_NOT_RG                              0x0270+1

#define X86IM_IO_IS_GPI_OR(x)                           ( ( (x)->id & 0xFFF0 ) == 0x0280 )
#define X86IM_IO_ID_OR_MM_RG                            0x0280+0
#define X86IM_IO_ID_OR_R2_R1                            0x0280+1
#define X86IM_IO_ID_OR_RG_MM                            0x0280+2
#define X86IM_IO_ID_OR_R1_R2                            0x0280+3
#define X86IM_IO_ID_OR_MM_IM                            0x0280+4
#define X86IM_IO_ID_OR_RG_IM                            0x0280+5
#define X86IM_IO_ID_OR_AC_IM                            0x0280+6

#define X86IM_IO_IS_GPI_OUT(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0290 )
#define X86IM_IO_ID_OUT_IM                              0x0290+0
#define X86IM_IO_ID_OUT_RG                              0x0290+1

#define X86IM_IO_IS_GPI_POP(x)                          ( ( (x)->id & 0xFFF0 ) == 0x02A0 )
#define X86IM_IO_ID_POP_MM                              0x02A0+0
#define X86IM_IO_ID_POP_RG1                             0x02A0+1
#define X86IM_IO_ID_POP_RG2                             0x02A0+2
#define X86IM_IO_ID_POP_SR2                             0x02A0+3
#define X86IM_IO_ID_POP_SR1                             0x02A0+4
#define X86IM_IO_ID_POPAD                               0x02A0+5
#define X86IM_IO_ID_POPF                                0x02A0+6

#define X86IM_IO_IS_GPI_PUSH(x)                         ( ( (x)->id & 0xFFF0 ) == 0x02B0 )
#define X86IM_IO_ID_PUSH_MM                             0x02B0+0
#define X86IM_IO_ID_PUSH_RG1                            0x02B0+1
#define X86IM_IO_ID_PUSH_RG2                            0x02B0+2
#define X86IM_IO_ID_PUSH_IM                             0x02B0+3
#define X86IM_IO_ID_PUSH_SR1                            0x02B0+4
#define X86IM_IO_ID_PUSH_SR2                            0x02B0+5
#define X86IM_IO_ID_PUSHAD                              0x02B0+6
#define X86IM_IO_ID_PUSHF                               0x02B0+7

#define X86IM_IO_IS_GPI_RCL(x)                          ( ( (x)->id & 0xFFF0 ) == 0x02C0 )
#define X86IM_IO_ID_RCL_MM_1                            0x02C0+0
#define X86IM_IO_ID_RCL_RG_1                            0x02C0+1
#define X86IM_IO_ID_RCL_MM_CL                           0x02C0+2
#define X86IM_IO_ID_RCL_RG_CL                           0x02C0+3
#define X86IM_IO_ID_RCL_MM_IM                           0x02C0+4
#define X86IM_IO_ID_RCL_RG_IM                           0x02C0+5

#define X86IM_IO_IS_GPI_RCR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x02D0 )
#define X86IM_IO_ID_RCR_MM_1                            0x02D0+0
#define X86IM_IO_ID_RCR_RG_1                            0x02D0+1
#define X86IM_IO_ID_RCR_MM_CL                           0x02D0+2
#define X86IM_IO_ID_RCR_RG_CL                           0x02D0+3
#define X86IM_IO_ID_RCR_MM_IM                           0x02D0+4
#define X86IM_IO_ID_RCR_RG_IM                           0x02D0+5

#define X86IM_IO_IS_GPI_RET(x)                          ( ( (x)->id & 0xFFF0 ) == 0x02E0 )
#define X86IM_IO_IS_GPI_RET_NEAR(x)                     ( ( (x)->id & 0xFFFC ) == 0x02E0 )
#define X86IM_IO_IS_GPI_RET_FAR(x)                      ( ( (x)->id & 0xFFFC ) == 0x02E4 )
#define X86IM_IO_ID_RET_N                               0x02E0+0
#define X86IM_IO_ID_RET_N_IM                            0x02E0+1
#define X86IM_IO_ID_RET_F                               0x02E4+0
#define X86IM_IO_ID_RET_F_IM                            0x02E4+1

#define X86IM_IO_IS_GPI_ROL(x)                          ( ( (x)->id & 0xFFF0 ) == 0x02F0 )
#define X86IM_IO_ID_ROL_MM_1                            0x02F0+0
#define X86IM_IO_ID_ROL_RG_1                            0x02F0+1
#define X86IM_IO_ID_ROL_MM_CL                           0x02F0+2
#define X86IM_IO_ID_ROL_RG_CL                           0x02F0+3
#define X86IM_IO_ID_ROL_MM_IM                           0x02F0+4
#define X86IM_IO_ID_ROL_RG_IM                           0x02F0+5

#define X86IM_IO_IS_GPI_ROR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0300 )
#define X86IM_IO_ID_ROR_MM_1                            0x0300+0
#define X86IM_IO_ID_ROR_RG_1                            0x0300+1
#define X86IM_IO_ID_ROR_MM_CL                           0x0300+2
#define X86IM_IO_ID_ROR_RG_CL                           0x0300+3
#define X86IM_IO_ID_ROR_MM_IM                           0x0300+4
#define X86IM_IO_ID_ROR_RG_IM                           0x0300+5

#define X86IM_IO_IS_GPI_SAR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0310 )
#define X86IM_IO_IS_GPI_SAL(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0310 )
#define X86IM_IO_ID_SAR_MM_1                            0x0310+0
#define X86IM_IO_ID_SAR_RG_1                            0x0310+1
#define X86IM_IO_ID_SAR_MM_CL                           0x0310+2
#define X86IM_IO_ID_SAR_RG_CL                           0x0310+3
#define X86IM_IO_ID_SAR_MM_IM                           0x0310+4
#define X86IM_IO_ID_SAR_RG_IM                           0x0310+5

#define X86IM_IO_IS_GPI_SBB(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0320 )
#define X86IM_IO_ID_SBB_MM_RG                           0x0320+0
#define X86IM_IO_ID_SBB_R2_R1                           0x0320+1
#define X86IM_IO_ID_SBB_RG_MM                           0x0320+2
#define X86IM_IO_ID_SBB_R1_R2                           0x0320+3
#define X86IM_IO_ID_SBB_MM_IM                           0x0320+4
#define X86IM_IO_ID_SBB_RG_IM                           0x0320+5
#define X86IM_IO_ID_SBB_AC_IM                           0x0320+6

#define X86IM_IO_IS_GPI_SETCC(x)                        ( ( (x)->id & 0xFFF0 ) == 0x0330 )
#define X86IM_IO_ID_SETCC_MM                            0x0330+0
#define X86IM_IO_ID_SETCC_RG                            0x0330+1

#define X86IM_IO_IS_GPI_SHL(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0340 )
#define X86IM_IO_ID_SHL_MM_1                            0x0340+0
#define X86IM_IO_ID_SHL_RG_1                            0x0340+1
#define X86IM_IO_ID_SHL_MM_CL                           0x0340+2
#define X86IM_IO_ID_SHL_RG_CL                           0x0340+3
#define X86IM_IO_ID_SHL_MM_IM                           0x0340+4
#define X86IM_IO_ID_SHL_RG_IM                           0x0340+5

#define X86IM_IO_IS_GPI_SHLD(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0350 )
#define X86IM_IO_ID_SHLD_MM_RG_IM                       0x0350+0
#define X86IM_IO_ID_SHLD_R1_R2_IM                       0x0350+1
#define X86IM_IO_ID_SHLD_MM_RG_CL                       0x0350+2
#define X86IM_IO_ID_SHLD_R1_R2_CL                       0x0350+3

#define X86IM_IO_IS_GPI_SHR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0360 )
#define X86IM_IO_ID_SHR_MM_1                            0x0360+0
#define X86IM_IO_ID_SHR_RG_1                            0x0360+1
#define X86IM_IO_ID_SHR_MM_CL                           0x0360+2
#define X86IM_IO_ID_SHR_RG_CL                           0x0360+3
#define X86IM_IO_ID_SHR_MM_IM                           0x0360+4
#define X86IM_IO_ID_SHR_RG_IM                           0x0360+5

#define X86IM_IO_IS_GPI_SHRD(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0370 )
#define X86IM_IO_ID_SHRD_MM_RG_IM                       0x0370+0
#define X86IM_IO_ID_SHRD_R1_R2_IM                       0x0370+1
#define X86IM_IO_ID_SHRD_MM_RG_CL                       0x0370+2
#define X86IM_IO_ID_SHRD_R1_R2_CL                       0x0370+3

#define X86IM_IO_IS_GPI_SLDT(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0380 )
#define X86IM_IO_ID_SLDT_MM                             0x0380+0
#define X86IM_IO_ID_SLDT_RG                             0x0380+1

#define X86IM_IO_IS_GPI_SMSW(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0390 )
#define X86IM_IO_ID_SMSW_MM                             0x0390+0
#define X86IM_IO_ID_SMSW_RG                             0x0390+1

#define X86IM_IO_IS_GPI_STR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x03A0 )
#define X86IM_IO_ID_STR_MM                              0x03A0+0
#define X86IM_IO_ID_STR_RG                              0x03A0+1

#define X86IM_IO_IS_GPI_SUB(x)                          ( ( (x)->id & 0xFFF0 ) == 0x03B0 )
#define X86IM_IO_ID_SUB_MM_RG                           0x03B0+0 // SUB
#define X86IM_IO_ID_SUB_R2_R1                           0x03B0+1
#define X86IM_IO_ID_SUB_RG_MM                           0x03B0+2
#define X86IM_IO_ID_SUB_R1_R2                           0x03B0+3
#define X86IM_IO_ID_SUB_MM_IM                           0x03B0+4
#define X86IM_IO_ID_SUB_RG_IM                           0x03B0+5
#define X86IM_IO_ID_SUB_AC_IM                           0x03B0+6

#define X86IM_IO_IS_GPI_TEST(x)                         ( ( (x)->id & 0xFFF0 ) == 0x03C0 )
#define X86IM_IO_ID_TEST_MM_R1                          0x03C0+0
#define X86IM_IO_ID_TEST_R1_R2                          0x03C0+1
#define X86IM_IO_ID_TEST_MM_IM                          0x03C0+2
#define X86IM_IO_ID_TEST_RG_IM                          0x03C0+3
#define X86IM_IO_ID_TEST_AC_IM                          0x03C0+4

#define X86IM_IO_IS_GPI_VERR(x)                         ( ( (x)->id & 0xFFF0 ) == 0x03D0 )
#define X86IM_IO_ID_VERR_MM                             0x03D0+0
#define X86IM_IO_ID_VERR_RG                             0x03D0+1

#define X86IM_IO_IS_GPI_VERW(x)                         ( ( (x)->id & 0xFFF0 ) == 0x03E0 )
#define X86IM_IO_ID_VERW_MM                             0x03E0+0
#define X86IM_IO_ID_VERW_RG                             0x03E0+1

#define X86IM_IO_IS_GPI_XADD(x)                         ( ( (x)->id & 0xFFF0 ) == 0x03F0 )
#define X86IM_IO_ID_XADD_MM_RG                          0x03F0+0
#define X86IM_IO_ID_XADD_R1_R2                          0x03F0+1

#define X86IM_IO_IS_GPI_XCHG(x)                         ( ( (x)->id & 0xFFF0 ) == 0x0400 )
#define X86IM_IO_ID_XCHG_MM_RG                          0x0400+0
#define X86IM_IO_ID_XCHG_R1_R2                          0x0400+1
#define X86IM_IO_ID_XCHG_AC_RG                          0x0400+2

#define X86IM_IO_IS_GPI_XOR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x0410 )
#define X86IM_IO_ID_XOR_MM_RG                           0x0410+0
#define X86IM_IO_ID_XOR_R2_R1                           0x0410+1
#define X86IM_IO_ID_XOR_RG_MM                           0x0410+2
#define X86IM_IO_ID_XOR_R1_R2                           0x0410+3
#define X86IM_IO_ID_XOR_MM_IM                           0x0410+4
#define X86IM_IO_ID_XOR_RG_IM                           0x0410+5
#define X86IM_IO_ID_XOR_AC_IM                           0x0410+6

#define X86IM_IO_IS_GPI_CMOVCC(x)                       ( ( (x)->id & 0xFFF0 ) == 0x0420 )
#define X86IM_IO_ID_CMOVCC_RG_MM                        0x0420+0
#define X86IM_IO_ID_CMOVCC_R1_R2                        0x0420+1

// FPU

#define X86IM_IO_ID_F2XM1                               0x1000
#define X86IM_IO_ID_FABS                                0x1001
#define X86IM_IO_ID_FBLD                                0x1002
#define X86IM_IO_ID_FBSTP                               0x1003
#define X86IM_IO_ID_FCHS                                0x1004
#define X86IM_IO_ID_FNCLEX                              0x1005
#define X86IM_IO_ID_FCOMPP                              0x1006
#define X86IM_IO_ID_FCOMIP                              0x1007
#define X86IM_IO_ID_FCOS                                0x1008
#define X86IM_IO_ID_FDECSTP                             0x1009
#define X86IM_IO_ID_FFREE                               0x100A
#define X86IM_IO_ID_FINCSTP                             0x100B
#define X86IM_IO_ID_FNINIT                              0x100C
#define X86IM_IO_ID_FLD1                                0x100D
#define X86IM_IO_ID_FLDCW                               0x100E
#define X86IM_IO_ID_FLDENV                              0x100F
#define X86IM_IO_ID_FLDL2E                              0x1010
#define X86IM_IO_ID_FLDL2T                              0x1011
#define X86IM_IO_ID_FLDLG2                              0x1012
#define X86IM_IO_ID_FLDLN2                              0x1013
#define X86IM_IO_ID_FLDPI                               0x1014
#define X86IM_IO_ID_FLDZ                                0x1015
#define X86IM_IO_ID_FNOP                                0x1016
#define X86IM_IO_ID_FPATAN                              0x1017
#define X86IM_IO_ID_FPREM                               0x1018
#define X86IM_IO_ID_FPREM1                              0x1019
#define X86IM_IO_ID_FPTAN                               0x101A
#define X86IM_IO_ID_FRNDINT                             0x101B
#define X86IM_IO_ID_FRSTOR                              0x101C
#define X86IM_IO_ID_FNSAVE                              0x101D
#define X86IM_IO_ID_FSCALE                              0x101E
#define X86IM_IO_ID_FSIN                                0x101F
#define X86IM_IO_ID_FSINCOS                             0x1020
#define X86IM_IO_ID_FSQRT                               0x1021
#define X86IM_IO_ID_FNSTCW                              0x1022
#define X86IM_IO_ID_FNSTENV                             0x1023
#define X86IM_IO_ID_FTST                                0x1024
#define X86IM_IO_ID_FUCOM_STX                           0x1025
#define X86IM_IO_ID_FUCOMP_STX                          0x1026
#define X86IM_IO_ID_FUCOMPP                             0x1027
#define X86IM_IO_ID_FUCOMI_ST0_STX                      0x1028
#define X86IM_IO_ID_FUCOMIP                             0x1029
#define X86IM_IO_ID_FXAM                                0x102A
#define X86IM_IO_ID_FXCH                                0x102B
#define X86IM_IO_ID_FXTRACT                             0x102C
#define X86IM_IO_ID_FYL2X                               0x102D
#define X86IM_IO_ID_FYL2XP1                             0x102E
#define X86IM_IO_ID_FXSAVE                              0x11C0
#define X86IM_IO_ID_FXRSTOR                             0x11C1
#define X86IM_IO_ID_FFREEP                              0x11C2
#define X86IM_IO_ID_FXCH4                               0x11C3
#define X86IM_IO_ID_FXCH7                               0x11C5

#define X86IM_IO_ID_FADDP_STX_ST0                       0x1030
#define X86IM_IO_ID_FDIVP_STX_ST0                       0x1031
#define X86IM_IO_ID_FDIVRP_STX_ST0                      0x1032
#define X86IM_IO_ID_FMULP_STX_ST0                       0x1033
#define X86IM_IO_ID_FSUBP_STX_ST0                       0x1034
#define X86IM_IO_ID_FSUBRP_STX_ST0                      0x1035
#define X86IM_IO_ID_FCOMI_ST0_STX                       0x1036

#define X86IM_IO_IS_FPU_FADD(x)                         ( ( (x)->id & 0xFFF0 ) == 0x1040 )
#define X86IM_IO_ID_FADD_MM32FP                         0x1040+0
#define X86IM_IO_ID_FADD_MM64FP                         0x1040+1
#define X86IM_IO_ID_FADD_ST0_STX                        0x1040+2
#define X86IM_IO_ID_FADD_STX_ST0                        0x1040+3

#define X86IM_IO_IS_FPU_FCOM(x)                         ( ( (x)->id & 0xFFF0 ) == 0x1050 )
#define X86IM_IO_ID_FCOM_MM32FP                         0x1050+0
#define X86IM_IO_ID_FCOM_MM64FP                         0x1050+1
#define X86IM_IO_ID_FCOM_STX                            0x1050+2
#define X86IM_IO_ID_FCOM2_STX_ST0                       0x1050+3

#define X86IM_IO_IS_FPU_FCOMP(x)                        ( ( (x)->id & 0xFFF0 ) == 0x1060 )
#define X86IM_IO_ID_FCOMP_MM32FP                        0x1060+0
#define X86IM_IO_ID_FCOMP_MM64FP                        0x1060+1
#define X86IM_IO_ID_FCOMP_STX                           0x1060+2
#define X86IM_IO_ID_FCOMP3                              0x1060+3
#define X86IM_IO_ID_FCOMP5                              0x1060+4

#define X86IM_IO_IS_FPU_FDIV(x)                         ( ( (x)->id & 0xFFF0 ) == 0x1070 )
#define X86IM_IO_ID_FDIV_MM32FP                         0x1070+0
#define X86IM_IO_ID_FDIV_MM64FP                         0x1070+1
#define X86IM_IO_ID_FDIV_ST0_STX                        0x1070+2
#define X86IM_IO_ID_FDIV_STX_ST0                        0x1070+3

#define X86IM_IO_IS_FPU_FDIVR(x)                        ( ( (x)->id & 0xFFF0 ) == 0x1080 )
#define X86IM_IO_ID_FDIVR_MM32FP                        0x1080+0
#define X86IM_IO_ID_FDIVR_MM64FP                        0x1080+1
#define X86IM_IO_ID_FDIVR_ST0_STX                       0x1080+2
#define X86IM_IO_ID_FDIVR_STX_ST0                       0x1080+3

#define X86IM_IO_IS_FPU_FIADD(x)                        ( ( (x)->id & 0xFFF0 ) == 0x1090 )
#define X86IM_IO_ID_FIADD_MM16I                         0x1090+0
#define X86IM_IO_ID_FIADD_MM32I                         0x1090+1

#define X86IM_IO_IS_FPU_FICOM(x)                        ( ( (x)->id & 0xFFF0 ) == 0x10A0 )
#define X86IM_IO_ID_FICOM_MM16I                         0x10A0+0
#define X86IM_IO_ID_FICOM_MM32I                         0x10A0+1

#define X86IM_IO_IS_FPU_FICOMP(x)                       ( ( (x)->id & 0xFFF0 ) == 0x10B0 )
#define X86IM_IO_ID_FICOMP_MM16I                        0x10B0+0
#define X86IM_IO_ID_FICOMP_MM32I                        0x10B0+1

#define X86IM_IO_IS_FPU_FIDIV(x)                        ( ( (x)->id & 0xFFF0 ) == 0x10C0 )
#define X86IM_IO_ID_FIDIV_MM16I                         0x10C0+0
#define X86IM_IO_ID_FIDIV_MM32I                         0x10C0+1

#define X86IM_IO_IS_FPU_FIDIVR(x)                       ( ( (x)->id & 0xFFF0 ) == 0x10D0 )
#define X86IM_IO_ID_FIDIVR_MM16I                        0x10D0+0
#define X86IM_IO_ID_FIDIVR_MM32I                        0x10D0+1

#define X86IM_IO_IS_FPU_FILD(x)                         ( ( (x)->id & 0xFFF0 ) == 0x10E0 )
#define X86IM_IO_ID_FILD_MM16I                          0x10E0+0
#define X86IM_IO_ID_FILD_MM32I                          0x10E0+1
#define X86IM_IO_ID_FILD_MM64I                          0x10E0+2

#define X86IM_IO_IS_FPU_FIMUL(x)                        ( ( (x)->id & 0xFFF0 ) == 0x10F0 )
#define X86IM_IO_ID_FIMUL_MM16I                         0x10F0+0
#define X86IM_IO_ID_FIMUL_MM32I                         0x10F0+1

#define X86IM_IO_IS_FPU_FIST(x)                         ( ( (x)->id & 0xFFF0 ) == 0x1100 )
#define X86IM_IO_ID_FIST_MM16I                          0x1100+0
#define X86IM_IO_ID_FIST_MM32I                          0x1100+1

#define X86IM_IO_IS_FPU_FISTP(x)                        ( ( (x)->id & 0xFFF0 ) == 0x1110 )
#define X86IM_IO_ID_FISTP_MM16I                         0x1110+0
#define X86IM_IO_ID_FISTP_MM32I                         0x1110+1
#define X86IM_IO_ID_FISTP_MM64I                         0x1110+2

#define X86IM_IO_IS_FPU_FISUB(x)                        ( ( (x)->id & 0xFFF0 ) == 0x1120 )
#define X86IM_IO_ID_FISUB_MM16I                         0x1120+0
#define X86IM_IO_ID_FISUB_MM32I                         0x1120+1

#define X86IM_IO_IS_FPU_FISUBR(x)                       ( ( (x)->id & 0xFFF0 ) == 0x1130 )
#define X86IM_IO_ID_FISUBR_MM16I                        0x1130+0
#define X86IM_IO_ID_FISUBR_MM32I                        0x1130+1

#define X86IM_IO_IS_FPU_FLD(x)                          ( ( (x)->id & 0xFFF0 ) == 0x1140 )
#define X86IM_IO_ID_FLD_MM32FP                          0x1140+0
#define X86IM_IO_ID_FLD_MM64FP                          0x1140+1
#define X86IM_IO_ID_FLD_MM80FP                          0x1140+2
#define X86IM_IO_ID_FLD_STX                             0x1140+3

#define X86IM_IO_IS_FPU_FMUL(x)                         ( ( (x)->id & 0xFFF0 ) == 0x1150 )
#define X86IM_IO_ID_FMUL_MM32FP                         0x1150+0
#define X86IM_IO_ID_FMUL_MM64FP                         0x1150+1
#define X86IM_IO_ID_FMUL_ST0_STX                        0x1150+2
#define X86IM_IO_ID_FMUL_STX_ST0                        0x1150+3

#define X86IM_IO_IS_FPU_FST(x)                          ( ( (x)->id & 0xFFF0 ) == 0x1160 )
#define X86IM_IO_ID_FST_MM32FP                          0x1160+0
#define X86IM_IO_ID_FST_MM64FP                          0x1160+1
#define X86IM_IO_ID_FST_STX                             0x1160+2

#define X86IM_IO_IS_FPU_FSTP(x)                         ( ( (x)->id & 0xFFF0 ) == 0x1170 )
#define X86IM_IO_ID_FSTP_MM32FP                         0x1170+0
#define X86IM_IO_ID_FSTP_MM64FP                         0x1170+1
#define X86IM_IO_ID_FSTP_MM80FP                         0x1170+2
#define X86IM_IO_ID_FSTP_STX                            0x1170+3
#define X86IM_IO_ID_FSTP1                               0x1170+4
#define X86IM_IO_ID_FSTP8                               0x1170+5
#define X86IM_IO_ID_FSTP9                               0x1170+6

#define X86IM_IO_IS_FPU_FNSTSW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x1180 )
#define X86IM_IO_ID_FNSTSW_MB2                          0x1180+0
#define X86IM_IO_ID_FNSTSW_AX                           0x1180+1

#define X86IM_IO_IS_FPU_FSUB(x)                         ( ( (x)->id & 0xFFF0 ) == 0x1190 )
#define X86IM_IO_ID_FSUB_MM32FP                         0x1190+0
#define X86IM_IO_ID_FSUB_MM64FP                         0x1190+1
#define X86IM_IO_ID_FSUB_ST0_STX                        0x1190+2
#define X86IM_IO_ID_FSUB_STX_ST0                        0x1190+3

#define X86IM_IO_IS_FPU_FSUBR(x)                        ( ( (x)->id & 0xFFF0 ) == 0x11A0 )
#define X86IM_IO_ID_FSUBR_MM32FP                        0x11A0+0
#define X86IM_IO_ID_FSUBR_MM64FP                        0x11A0+1
#define X86IM_IO_ID_FSUBR_ST0_STX                       0x11A0+2
#define X86IM_IO_ID_FSUBR_STX_ST0                       0x11A0+3

#define X86IM_IO_IS_FPU_FCMOVCC(x)                      ( ( (x)->id & 0xFFF0 ) == 0x11B0 )
#define X86IM_IO_ID_FCMOVB_ST0_STX                      0x11B0+0
#define X86IM_IO_ID_FCMOVE_ST0_STX                      0x11B0+1
#define X86IM_IO_ID_FCMOVBE_ST0_STX                     0x11B0+2
#define X86IM_IO_ID_FCMOVU_ST0_STX                      0x11B0+3
#define X86IM_IO_ID_FCMOVNB_ST0_STX                     0x11B0+4
#define X86IM_IO_ID_FCMOVNE_ST0_STX                     0x11B0+5
#define X86IM_IO_ID_FCMOVNBE_ST0_STX                    0x11B0+6
#define X86IM_IO_ID_FCMOVNU_ST0_STX                     0x11B0+7

// MMX

#define X86IM_IO_ID_EMMS                                0x2000

#define X86IM_IO_IS_MMX_MOVD(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2010 )
#define X86IM_IO_ID_MOVD_MMXRG_MM                       0x2010+0
#define X86IM_IO_ID_MOVD_MMXRG_RG                       0x2010+1
#define X86IM_IO_ID_MOVD_MM_MMXRG                       0x2010+2
#define X86IM_IO_ID_MOVD_RG_MMXRG                       0x2010+3

#define X86IM_IO_IS_MMX_MOVQ(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2020 )
#define X86IM_IO_ID_MOVQ_MMXR1_MMXR2                    0x2020+0
#define X86IM_IO_ID_MOVQ_MMXRG_MM                       0x2020+1
#define X86IM_IO_ID_MOVQ_MMXR2_MMXR1                    0x2020+2
#define X86IM_IO_ID_MOVQ_MM_MMXRG                       0x2020+3

#define X86IM_IO_IS_MMX_PACKSSDW(x)                     ( ( (x)->id & 0xFFF0 ) == 0x2030 )
#define X86IM_IO_ID_PACKSSDW_MMXR1_MMXR2                0x2030+0
#define X86IM_IO_ID_PACKSSDW_MMXRG_MM                   0x2030+1

#define X86IM_IO_IS_MMX_PACKSSWB(x)                     ( ( (x)->id & 0xFFF0 ) == 0x2040 )
#define X86IM_IO_ID_PACKSSWB_MMXR1_MMXR2                0x2040+0
#define X86IM_IO_ID_PACKSSWB_MMXRG_MM                   0x2040+1

#define X86IM_IO_IS_MMX_PACKUSWB(x)                     ( ( (x)->id & 0xFFF0 ) == 0x2050 )
#define X86IM_IO_ID_PACKUSWB_MMXR1_MMXR2                0x2050+0
#define X86IM_IO_ID_PACKUSWB_MMXRG_MM                   0x2050+1

#define X86IM_IO_IS_MMX_PADD(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2060 )
#define X86IM_IO_ID_PADDB_MMXR1_MMXR2                   0x2060+0
#define X86IM_IO_ID_PADDB_MMXRG_MM                      0x2060+1
#define X86IM_IO_ID_PADDW_MMXR1_MMXR2                   0x2060+2
#define X86IM_IO_ID_PADDW_MMXRG_MM                      0x2060+3
#define X86IM_IO_ID_PADDD_MMXR1_MMXR2                   0x2060+4
#define X86IM_IO_ID_PADDD_MMXRG_MM                      0x2060+5

#define X86IM_IO_IS_MMX_PADDS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x2070 )
#define X86IM_IO_ID_PADDSB_MMXR1_MMXR2                  0x2070+0
#define X86IM_IO_ID_PADDSB_MMXRG_MM                     0x2070+1
#define X86IM_IO_ID_PADDSW_MMXR1_MMXR2                  0x2070+2
#define X86IM_IO_ID_PADDSW_MMXRG_MM                     0x2070+3

#define X86IM_IO_IS_MMX_PADDUS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x2080 )
#define X86IM_IO_ID_PADDUSB_MMXR1_MMXR2                 0x2080+0
#define X86IM_IO_ID_PADDUSB_MMXRG_MM                    0x2080+1
#define X86IM_IO_ID_PADDUSW_MMXR1_MMXR2                 0x2080+2
#define X86IM_IO_ID_PADDUSW_MMXRG_MM                    0x2080+3

#define X86IM_IO_IS_MMX_PAND(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2090 )
#define X86IM_IO_ID_PAND_MMXR1_MMXR2                    0x2090+0
#define X86IM_IO_ID_PAND_MMXRG_MM                       0x2090+1

#define X86IM_IO_IS_MMX_PANDN(x)                        ( ( (x)->id & 0xFFF0 ) == 0x20A0 )
#define X86IM_IO_ID_PANDN_MMXR1_MMXR2                   0x20A0+0
#define X86IM_IO_ID_PANDN_MMXRG_MM                      0x20A0+1

#define X86IM_IO_IS_MMX_PCMPEQ(x)                       ( ( (x)->id & 0xFFF0 ) == 0x20B0 )
#define X86IM_IO_ID_PCMPEQB_MMXR1_MMXR2                 0x20B0+0
#define X86IM_IO_ID_PCMPEQB_MMXRG_MM                    0x20B0+1
#define X86IM_IO_ID_PCMPEQW_MMXR1_MMXR2                 0x20B0+2
#define X86IM_IO_ID_PCMPEQW_MMXRG_MM                    0x20B0+3
#define X86IM_IO_ID_PCMPEQD_MMXR1_MMXR2                 0x20B0+4
#define X86IM_IO_ID_PCMPEQD_MMXRG_MM                    0x20B0+5

#define X86IM_IO_IS_MMX_PCMPGT(x)                       ( ( (x)->id & 0xFFF0 ) == 0x20C0 )
#define X86IM_IO_ID_PCMPGTB_MMXR1_MMXR2                 0x20C0+0
#define X86IM_IO_ID_PCMPGTB_MMXRG_MM                    0x20C0+1
#define X86IM_IO_ID_PCMPGTW_MMXR1_MMXR2                 0x20C0+2
#define X86IM_IO_ID_PCMPGTW_MMXRG_MM                    0x20C0+3
#define X86IM_IO_ID_PCMPGTD_MMXR1_MMXR2                 0x20C0+4
#define X86IM_IO_ID_PCMPGTD_MMXRG_MM                    0x20C0+5

#define X86IM_IO_IS_MMX_PMADDWD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x20D0 )
#define X86IM_IO_ID_PMADDWD_MMXR1_MMXR2                 0x20D0+0
#define X86IM_IO_ID_PMADDWD_MMXRG_MM                    0x20D0+1

#define X86IM_IO_IS_MMX_PMULHW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x20E0 )
#define X86IM_IO_ID_PMULHW_MMXR1_MMXR2                  0x20E0+0
#define X86IM_IO_ID_PMULHW_MMXRG_MM                     0x20E0+1

#define X86IM_IO_IS_MMX_PMULLW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x20F0 )
#define X86IM_IO_ID_PMULLW_MMXR1_MMXR2                  0x20F0+0
#define X86IM_IO_ID_PMULLW_MMXRG_MM                     0x20F0+1

#define X86IM_IO_IS_MMX_POR(x)                          ( ( (x)->id & 0xFFF0 ) == 0x2100 )
#define X86IM_IO_ID_POR_MMXR1_MMXR2                     0x2100+0
#define X86IM_IO_ID_POR_MMXRG_MM                        0x2100+1

#define X86IM_IO_IS_MMX_PSLL(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2110 )
#define X86IM_IO_ID_PSLLW_MMXR1_MMXR2                   0x2110+0
#define X86IM_IO_ID_PSLLW_MMXRG_MM                      0x2110+1
#define X86IM_IO_ID_PSLLW_MMXRG_IMM8                    0x2110+2
#define X86IM_IO_ID_PSLLD_MMXR1_MMXR2                   0x2110+3
#define X86IM_IO_ID_PSLLD_MMXRG_MM                      0x2110+4
#define X86IM_IO_ID_PSLLD_MMXRG_IMM8                    0x2110+5
#define X86IM_IO_ID_PSLLQ_MMXR1_MMXR2                   0x2110+6
#define X86IM_IO_ID_PSLLQ_MMXRG_MM                      0x2110+7
#define X86IM_IO_ID_PSLLQ_MMXRG_IMM8                    0x2110+8

#define X86IM_IO_IS_MMX_PSRA(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2120 )
#define X86IM_IO_ID_PSRAW_MMXR1_MMXR2                   0x2120+0
#define X86IM_IO_ID_PSRAW_MMXRG_MM                      0x2120+1
#define X86IM_IO_ID_PSRAW_MMXRG_IMM8                    0x2120+2
#define X86IM_IO_ID_PSRAD_MMXR1_MMXR2                   0x2120+3
#define X86IM_IO_ID_PSRAD_MMXRG_MM                      0x2120+4
#define X86IM_IO_ID_PSRAD_MMXRG_IMM8                    0x2120+5

#define X86IM_IO_IS_MMX_PSRL(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2130 )
#define X86IM_IO_ID_PSRLW_MMXR1_MMXR2                   0x2130+0
#define X86IM_IO_ID_PSRLW_MMXRG_MM                      0x2130+1
#define X86IM_IO_ID_PSRLW_MMXRG_IMM8                    0x2130+2
#define X86IM_IO_ID_PSRLD_MMXR1_MMXR2                   0x2130+3
#define X86IM_IO_ID_PSRLD_MMXRG_MM                      0x2130+4
#define X86IM_IO_ID_PSRLD_MMXRG_IMM8                    0x2130+5
#define X86IM_IO_ID_PSRLQ_MMXR1_MMXR2                   0x2130+6
#define X86IM_IO_ID_PSRLQ_MMXRG_MM                      0x2130+7
#define X86IM_IO_ID_PSRLQ_MMXRG_IMM8                    0x2130+8

#define X86IM_IO_IS_MMX_PSUB(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2140 )
#define X86IM_IO_ID_PSUBB_MMXR1_MMXR2                   0x2140+0
#define X86IM_IO_ID_PSUBB_MMXRG_MM                      0x2140+1
#define X86IM_IO_ID_PSUBW_MMXR1_MMXR2                   0x2140+2
#define X86IM_IO_ID_PSUBW_MMXRG_MM                      0x2140+3
#define X86IM_IO_ID_PSUBD_MMXR1_MMXR2                   0x2140+4
#define X86IM_IO_ID_PSUBD_MMXRG_MM                      0x2140+5

#define X86IM_IO_IS_MMX_PSUBS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x2150 )
#define X86IM_IO_ID_PSUBSB_MMXR1_MMXR2                  0x2150+0
#define X86IM_IO_ID_PSUBSB_MMXRG_MM                     0x2150+1
#define X86IM_IO_ID_PSUBSW_MMXR1_MMXR2                  0x2150+2
#define X86IM_IO_ID_PSUBSW_MMXRG_MM                     0x2150+3

#define X86IM_IO_IS_MMX_PSUBUS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x2160 )
#define X86IM_IO_ID_PSUBUSB_MMXR1_MMXR2                 0x2160+0
#define X86IM_IO_ID_PSUBUSB_MMXRG_MM                    0x2160+1
#define X86IM_IO_ID_PSUBUSW_MMXR1_MMXR2                 0x2160+2
#define X86IM_IO_ID_PSUBUSW_MMXRG_MM                    0x2160+3

#define X86IM_IO_IS_MMX_PUNPCKH(x)                      ( ( (x)->id & 0xFFF0 ) == 0x2170 )
#define X86IM_IO_ID_PUNPCKHBW_MMXR1_MMXR2               0x2170+0
#define X86IM_IO_ID_PUNPCKHBW_MMXRG_MM                  0x2170+1
#define X86IM_IO_ID_PUNPCKHWD_MMXR1_MMXR2               0x2170+2
#define X86IM_IO_ID_PUNPCKHWD_MMXRG_MM                  0x2170+3
#define X86IM_IO_ID_PUNPCKHDQ_MMXR1_MMXR2               0x2170+4
#define X86IM_IO_ID_PUNPCKHDQ_MMXRG_MM                  0x2170+5

#define X86IM_IO_IS_MMX_PUNPCKL(x)                      ( ( (x)->id & 0xFFF0 ) == 0x2180 )
#define X86IM_IO_ID_PUNPCKLBW_MMXR1_MMXR2               0x2180+0
#define X86IM_IO_ID_PUNPCKLBW_MMXRG_MM32                0x2180+1
#define X86IM_IO_ID_PUNPCKLWD_MMXR1_MMXR2               0x2180+2
#define X86IM_IO_ID_PUNPCKLWD_MMXRG_MM32                0x2180+3
#define X86IM_IO_ID_PUNPCKLDQ_MMXR1_MMXR2               0x2180+4
#define X86IM_IO_ID_PUNPCKLDQ_MMXRG_MM32                0x2180+5

#define X86IM_IO_IS_MMX_PXOR(x)                         ( ( (x)->id & 0xFFF0 ) == 0x2190 )
#define X86IM_IO_ID_PXOR_MMXR1_MMXR2                    0x2190+0
#define X86IM_IO_ID_PXOR_MMXRG_MM                       0x2190+1

// 3DNOW

#define X86IM_IO_IS_3DNOW_PI2FW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x3000 )
#define X86IM_IO_ID_PI2FW_MMXR1_MMXR2                   0x3000+0
#define X86IM_IO_ID_PI2FW_MMXRG_MM                      0x3000+1

#define X86IM_IO_IS_3DNOW_PI2FD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x3010 )
#define X86IM_IO_ID_PI2FD_MMXR1_MMXR2                   0x3010+0
#define X86IM_IO_ID_PI2FD_MMXRG_MM                      0x3010+1

#define X86IM_IO_IS_3DNOW_PF2IW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x3020 )
#define X86IM_IO_ID_PF2IW_MMXR1_MMXR2                   0x3020+0
#define X86IM_IO_ID_PF2IW_MMXRG_MM                      0x3020+1

#define X86IM_IO_IS_3DNOW_PF2ID(x)                      ( ( (x)->id & 0xFFF0 ) == 0x3030 )
#define X86IM_IO_ID_PF2ID_MMXR1_MMXR2                   0x3030+0
#define X86IM_IO_ID_PF2ID_MMXRG_MM                      0x3030+1

#define X86IM_IO_IS_3DNOW_PFNACC(x)                     ( ( (x)->id & 0xFFF0 ) == 0x3040 )
#define X86IM_IO_ID_PFNACC_MMXR1_MMXR2                  0x3040+0
#define X86IM_IO_ID_PFNACC_MMXRG_MM                     0x3040+1

#define X86IM_IO_IS_3DNOW_PFPNACC(x)                    ( ( (x)->id & 0xFFF0 ) == 0x3050 )
#define X86IM_IO_ID_PFPNACC_MMXR1_MMXR2                 0x3050+0
#define X86IM_IO_ID_PFPNACC_MMXRG_MM                    0x3050+1

#define X86IM_IO_IS_3DNOW_PFCMPGE(x)                    ( ( (x)->id & 0xFFF0 ) == 0x3060 )
#define X86IM_IO_ID_PFCMPGE_MMXR1_MMXR2                 0x3060+0
#define X86IM_IO_ID_PFCMPGE_MMXRG_MM                    0x3060+1

#define X86IM_IO_IS_3DNOW_PFMIN(x)                      ( ( (x)->id & 0xFFF0 ) == 0x3070 )
#define X86IM_IO_ID_PFMIN_MMXR1_MMXR2                   0x3070+0
#define X86IM_IO_ID_PFMIN_MMXRG_MM                      0x3070+1

#define X86IM_IO_IS_3DNOW_PFRCP(x)                      ( ( (x)->id & 0xFFF0 ) == 0x3080 )
#define X86IM_IO_ID_PFRCP_MMXR1_MMXR2                   0x3080+0
#define X86IM_IO_ID_PFRCP_MMXRG_MM                      0x3080+1

#define X86IM_IO_IS_3DNOW_PFRSQRT(x)                    ( ( (x)->id & 0xFFF0 ) == 0x3090 )
#define X86IM_IO_ID_PFRSQRT_MMXR1_MMXR2                 0x3090+0
#define X86IM_IO_ID_PFRSQRT_MMXRG_MM                    0x3090+1

#define X86IM_IO_IS_3DNOW_PFSUB(x)                      ( ( (x)->id & 0xFFF0 ) == 0x30A0 )
#define X86IM_IO_ID_PFSUB_MMXR1_MMXR2                   0x30A0+0
#define X86IM_IO_ID_PFSUB_MMXRG_MM                      0x30A0+1

#define X86IM_IO_IS_3DNOW_PFADD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x30B0 )
#define X86IM_IO_ID_PFADD_MMXR1_MMXR2                   0x30B0+0
#define X86IM_IO_ID_PFADD_MMXRG_MM                      0x30B0+1

#define X86IM_IO_IS_3DNOW_PFCMPGT(x)                    ( ( (x)->id & 0xFFF0 ) == 0x30C0 )
#define X86IM_IO_ID_PFCMPGT_MMXR1_MMXR2                 0x30C0+0
#define X86IM_IO_ID_PFCMPGT_MMXRG_MM                    0x30C0+1

#define X86IM_IO_IS_3DNOW_PFMAX(x)                      ( ( (x)->id & 0xFFF0 ) == 0x30D0 )
#define X86IM_IO_ID_PFMAX_MMXR1_MMXR2                   0x30D0+0
#define X86IM_IO_ID_PFMAX_MMXRG_MM                      0x30D0+1

#define X86IM_IO_IS_3DNOW_PFRCPIT1(x)                   ( ( (x)->id & 0xFFF0 ) == 0x30E0 )
#define X86IM_IO_ID_PFRCPIT1_MMXR1_MMXR2                0x30E0+0
#define X86IM_IO_ID_PFRCPIT1_MMXRG_MM                   0x30E0+1

#define X86IM_IO_IS_3DNOW_PFRSQIT1(x)                   ( ( (x)->id & 0xFFF0 ) == 0x30F0 )
#define X86IM_IO_ID_PFRSQIT1_MMXR1_MMXR2                0x30F0+0
#define X86IM_IO_ID_PFRSQIT1_MMXRG_MM                   0x30F0+1

#define X86IM_IO_IS_3DNOW_PFSUBR(x)                     ( ( (x)->id & 0xFFF0 ) == 0x3100 )
#define X86IM_IO_ID_PFSUBR_MMXR1_MMXR2                  0x3100+0
#define X86IM_IO_ID_PFSUBR_MMXRG_MM                     0x3100+1

#define X86IM_IO_IS_3DNOW_PFACC(x)                      ( ( (x)->id & 0xFFF0 ) == 0x3110 )
#define X86IM_IO_ID_PFACC_MMXR1_MMXR2                   0x3110+0
#define X86IM_IO_ID_PFACC_MMXRG_MM                      0x3110+1

#define X86IM_IO_IS_3DNOW_PFCMPEQ(x)                    ( ( (x)->id & 0xFFF0 ) == 0x3120 )
#define X86IM_IO_ID_PFCMPEQ_MMXR1_MMXR2                 0x3120+0
#define X86IM_IO_ID_PFCMPEQ_MMXRG_MM                    0x3120+1

#define X86IM_IO_IS_3DNOW_PFMUL(x)                      ( ( (x)->id & 0xFFF0 ) == 0x3130 )
#define X86IM_IO_ID_PFMUL_MMXR1_MMXR2                   0x3130+0
#define X86IM_IO_ID_PFMUL_MMXRG_MM                      0x3130+1

#define X86IM_IO_IS_3DNOW_PFRCPIT2(x)                   ( ( (x)->id & 0xFFF0 ) == 0x3140 )
#define X86IM_IO_ID_PFRCPIT2_MMXR1_MMXR2                0x3140+0
#define X86IM_IO_ID_PFRCPIT2_MMXRG_MM                   0x3140+1

#define X86IM_IO_IS_3DNOW_PMULHRW(x)                    ( ( (x)->id & 0xFFF0 ) == 0x3150 )
#define X86IM_IO_ID_PMULHRW_MMXR1_MMXR2                 0x3150+0
#define X86IM_IO_ID_PMULHRW_MMXRG_MM                    0x3150+1

#define X86IM_IO_IS_3DNOW_PSWAPD(x)                     ( ( (x)->id & 0xFFF0 ) == 0x3160 )
#define X86IM_IO_ID_PSWAPD_MMXR1_MMXR2                  0x3160+0
#define X86IM_IO_ID_PSWAPD_MMXRG_MM                     0x3160+1

#define X86IM_IO_IS_3DNOW_PAVGUSB(x)                    ( ( (x)->id & 0xFFF0 ) == 0x3170 )
#define X86IM_IO_ID_PAVGUSB_MMXR1_MMXR2                 0x3170+0
#define X86IM_IO_ID_PAVGUSB_MMXRG_MM                    0x3170+1

// SSE

#define X86IM_IO_ID_MOVMSKPS_R1_XMMR2                   0x4000
#define X86IM_IO_ID_LDMXCSR_MM32                        0x4001
#define X86IM_IO_ID_STMXCSR_MM32                        0x4002
#define X86IM_IO_ID_MASKMOVQ_MMXR1_MMXR2                0x4003
#define X86IM_IO_ID_MOVNTPS_MM_XMMRG                    0x4004
#define X86IM_IO_ID_MOVNTQ_MM_MMXRG                     0x4005
#define X86IM_IO_ID_PREFETCHT0                          0x4006
#define X86IM_IO_ID_PREFETCHT1                          0x4007
#define X86IM_IO_ID_PREFETCHT2                          0x4008
#define X86IM_IO_ID_PREFETCHNTA                         0x4009
#define X86IM_IO_ID_SFENCE                              0x400A

#define X86IM_IO_IS_SSE_ADDPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4010 )
#define X86IM_IO_ID_ADDPS_XMMR1_XMMR2                   0x4010+0
#define X86IM_IO_ID_ADDPS_XMMRG_MM                      0x4010+1

#define X86IM_IO_IS_SSE_ADDSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4020 )
#define X86IM_IO_ID_ADDSS_XMMR1_XMMR2                   0x4020+0
#define X86IM_IO_ID_ADDSS_XMMRG_MM32                    0x4020+1

#define X86IM_IO_IS_SSE_ANDNPS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4030 )
#define X86IM_IO_ID_ANDNPS_XMMR1_XMMR2                  0x4030+0
#define X86IM_IO_ID_ANDNPS_XMMRG_MM                     0x4030+1

#define X86IM_IO_IS_SSE_ANDPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4040 )
#define X86IM_IO_ID_ANDPS_XMMR1_XMMR2                   0x4040+0
#define X86IM_IO_ID_ANDPS_XMMRG_MM                      0x4040+1

#define X86IM_IO_IS_SSE_CMPPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4050 )
#define X86IM_IO_ID_CMPPS_XMMR1_XMMR2_IMM8              0x4050+0
#define X86IM_IO_ID_CMPPS_XMMRG_MM_IMM8                 0x4050+1

#define X86IM_IO_IS_SSE_CMPSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4060 )
#define X86IM_IO_ID_CMPSS_XMMR1_XMMR2_IMM8              0x4060+0
#define X86IM_IO_ID_CMPSS_XMMRG_MM32_IMM8               0x4060+1

#define X86IM_IO_IS_SSE_COMISS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4070 )
#define X86IM_IO_ID_COMISS_XMMR1_XMMR2                  0x4070+0
#define X86IM_IO_ID_COMISS_XMMRG_MM32                   0x4070+1

#define X86IM_IO_IS_SSE_CVTPI2PS(x)                     ( ( (x)->id & 0xFFF0 ) == 0x4080 )
#define X86IM_IO_ID_CVTPI2PS_XMMR1_MMXR2                0x4080+0
#define X86IM_IO_ID_CVTPI2PS_XMMRG_MM64                 0x4080+1

#define X86IM_IO_IS_SSE_CVTPS2PI(x)                     ( ( (x)->id & 0xFFF0 ) == 0x4090 )
#define X86IM_IO_ID_CVTPS2PI_MMXR1_XMMR2                0x4090+0
#define X86IM_IO_ID_CVTPS2PI_MMXRG_MM                   0x4090+1

#define X86IM_IO_IS_SSE_CVTSI2SS(x)                     ( ( (x)->id & 0xFFF0 ) == 0x40A0 )
#define X86IM_IO_ID_CVTSI2SS_XMMR1_R2                   0x40A0+0
#define X86IM_IO_ID_CVTSI2SS_XMMRG_MM                   0x40A0+1

#define X86IM_IO_IS_SSE_CVTSS2SI(x)                     ( ( (x)->id & 0xFFF0 ) == 0x40B0 )
#define X86IM_IO_ID_CVTSS2SI_R1_XMMR2                   0x40B0+0
#define X86IM_IO_ID_CVTSS2SI_RG_MM32                    0x40B0+1

#define X86IM_IO_IS_SSE_CVTTPS2PI(x)                    ( ( (x)->id & 0xFFF0 ) == 0x40C0 )
#define X86IM_IO_ID_CVTTPS2PI_MMXR1_XMMR2               0x40C0+0
#define X86IM_IO_ID_CVTTPS2PI_MMXRG_MM64                0x40C0+1

#define X86IM_IO_IS_SSE_CVTTSS2SI(x)                    ( ( (x)->id & 0xFFF0 ) == 0x40D0 )
#define X86IM_IO_ID_CVTTSS2SI_R1_XMMR2                  0x40D0+0
#define X86IM_IO_ID_CVTTSS2SI_RG_MM32                   0x40D0+1

#define X86IM_IO_IS_SSE_DIVPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x40E0 )
#define X86IM_IO_ID_DIVPS_XMMR1_XMMR2                   0x40E0+0
#define X86IM_IO_ID_DIVPS_XMMRG_MM                      0x40E0+1

#define X86IM_IO_IS_SSE_DIVSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x40F0 )
#define X86IM_IO_ID_DIVSS_XMMR1_XMMR2                   0x40F0+0
#define X86IM_IO_ID_DIVSS_XMMRG_MM32                    0x40F0+1

#define X86IM_IO_IS_SSE_MAXPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4100 )
#define X86IM_IO_ID_MAXPS_XMMR1_XMMR2                   0x4100+0
#define X86IM_IO_ID_MAXPS_XMMRG_MM                      0x4100+1

#define X86IM_IO_IS_SSE_MAXSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4110 )
#define X86IM_IO_ID_MAXSS_XMMR1_XMMR2                   0x4110+0
#define X86IM_IO_ID_MAXSS_XMMRG_MM32                    0x4110+1

#define X86IM_IO_IS_SSE_MINPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4120 )
#define X86IM_IO_ID_MINPS_XMMR1_XMMR2                   0x4120+0
#define X86IM_IO_ID_MINPS_XMMRG_MM                      0x4120+1

#define X86IM_IO_IS_SSE_MINSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4130 )
#define X86IM_IO_ID_MINSS_XMMR1_XMMR2                   0x4130+0
#define X86IM_IO_ID_MINSS_XMMRG_MM32                    0x4130+1

#define X86IM_IO_IS_SSE_MOVAPS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4140 )
#define X86IM_IO_ID_MOVAPS_XMMR1_XMMR2                  0x4140+0
#define X86IM_IO_ID_MOVAPS_XMMRG_MM                     0x4140+1
#define X86IM_IO_ID_MOVAPS_XMMR2_XMMR1                  0x4140+2
#define X86IM_IO_ID_MOVAPS_MM_XMMRG                     0x4140+3

#define X86IM_IO_ID_MOVLHPS_XMMR1_XMMR2                 0x4150+0xF // MOVLHPS ( =MOVHPS special case )

#define X86IM_IO_ID_IS_SSE_MOVHPS(x)                    ( ( (x)->id & 0xFFF0 ) == 0x4160 )
#define X86IM_IO_ID_MOVHPS_XMMRG_MM64                   0x4160+0 // MOVHPS (=MOVLHPS_XMMR1_XMMR2)
#define X86IM_IO_ID_MOVHPS_MM64_XMMRG                   0x4160+1

#define X86IM_IO_ID_MOVHLPS_XMMR1_XMMR2                 0x4170+0xF // MOVHLPS ( =MOVLPS special case )

#define X86IM_IO_ID_IS_SSE_MOVLPS(x)                    ( ( (x)->id & 0xFFF0 ) == 0x4180 )
#define X86IM_IO_ID_MOVLPS_XMMRG_MM64                   0x4180+0
#define X86IM_IO_ID_MOVLPS_MM64_XMMRG                   0x4180+1

#define X86IM_IO_IS_SSE_MOVSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4190 )
#define X86IM_IO_ID_MOVSS_XMMR1_XMMR2                   0x4190+0
#define X86IM_IO_ID_MOVSS_XMMRG_MM                      0x4190+1
#define X86IM_IO_ID_MOVSS_XMMR2_XMMR1                   0x4190+2
#define X86IM_IO_ID_MOVSS_MM_XMMRG                      0x4190+3

#define X86IM_IO_IS_SSE_MOVUPS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x41A0 )
#define X86IM_IO_ID_MOVUPS_XMMR1_XMMR2                  0x41A0+0
#define X86IM_IO_ID_MOVUPS_XMMRG_MM                     0x41A0+1
#define X86IM_IO_ID_MOVUPS_XMMR2_XMMR1                  0x41A0+2
#define X86IM_IO_ID_MOVUPS_MM_XMMRG                     0x41A0+3

#define X86IM_IO_IS_SSE_MULPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x41B0 )
#define X86IM_IO_ID_MULPS_XMMR1_XMMR2                   0x41B0+0
#define X86IM_IO_ID_MULPS_XMMRG_MM                      0x41B0+1

#define X86IM_IO_IS_SSE_MULSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x41C0 )
#define X86IM_IO_ID_MULSS_XMMR1_XMMR2                   0x41C0+0
#define X86IM_IO_ID_MULSS_XMMRG_MM                      0x41C0+1

#define X86IM_IO_IS_SSE_ORPS(x)                         ( ( (x)->id & 0xFFF0 ) == 0x41D0 )
#define X86IM_IO_ID_ORPS_XMMR1_XMMR2                    0x41D0+0
#define X86IM_IO_ID_ORPS_XMMRG_MM                       0x41D0+1

#define X86IM_IO_IS_SSE_RCPPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x41E0 )
#define X86IM_IO_ID_RCPPS_XMMR1_XMMR2                   0x41E0+0
#define X86IM_IO_ID_RCPPS_XMMRG_MM                      0x41E0+1

#define X86IM_IO_IS_SSE_RCPSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x41F0 )
#define X86IM_IO_ID_RCPSS_XMMR1_XMMR2                   0x41F0+0
#define X86IM_IO_ID_RCPSS_XMMRG_MM32                    0x41F0+1

#define X86IM_IO_IS_SSE_RSQRTPS(x)                      ( ( (x)->id & 0xFFF0 ) == 0x4200 )
#define X86IM_IO_ID_RSQRTPS_XMMR1_XMMR2                 0x4200+0
#define X86IM_IO_ID_RSQRTPS_XMMRG_MM                    0x4200+1

#define X86IM_IO_IS_SSE_RSQRTSS(x)                      ( ( (x)->id & 0xFFF0 ) == 0x4210 )
#define X86IM_IO_ID_RSQRTSS_XMMR1_XMMR2                 0x4210+0
#define X86IM_IO_ID_RSQRTSS_XMMRG_MM32                  0x4210+1

#define X86IM_IO_IS_SSE_SHUFPS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4220 )
#define X86IM_IO_ID_SHUFPS_XMMR1_XMMR2_IMM8             0x4220+0
#define X86IM_IO_ID_SHUFPS_XMMRG_MM_IMM8                0x4220+1

#define X86IM_IO_IS_SSE_SQRTPS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4230 )
#define X86IM_IO_ID_SQRTPS_XMMR1_XMMR2                  0x4230+0
#define X86IM_IO_ID_SQRTPS_XMMRG_MM                     0x4230+1

#define X86IM_IO_IS_SSE_SQRTSS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4240 )
#define X86IM_IO_ID_SQRTSS_XMMR1_XMMR2                  0x4240+0
#define X86IM_IO_ID_SQRTSS_XMMRG_MM32                   0x4240+1

#define X86IM_IO_IS_SSE_SUBPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4250 )
#define X86IM_IO_ID_SUBPS_XMMR1_XMMR2                   0x4250+0
#define X86IM_IO_ID_SUBPS_XMMRG_MM                      0x4250+1

#define X86IM_IO_IS_SSE_SUBSS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x4260 )
#define X86IM_IO_ID_SUBSS_XMMR1_XMMR2                   0x4260+0
#define X86IM_IO_ID_SUBSS_XMMRG_MM32                    0x4260+1

#define X86IM_IO_IS_SSE_UCOMISS(x)                      ( ( (x)->id & 0xFFF0 ) == 0x4270 )
#define X86IM_IO_ID_UCOMISS_XMMR1_XMMR2                 0x4270+0
#define X86IM_IO_ID_UCOMISS_XMMRG_MM32                  0x4270+1

#define X86IM_IO_IS_SSE_UNPCKHPS(x)                     ( ( (x)->id & 0xFFF0 ) == 0x4280 )
#define X86IM_IO_ID_UNPCKHPS_XMMR1_XMMR2                0x4280+0
#define X86IM_IO_ID_UNPCKHPS_XMMRG_MM                   0x4280+1

#define X86IM_IO_IS_SSE_UNPCKLPS(x)                     ( ( (x)->id & 0xFFF0 ) == 0x4290 )
#define X86IM_IO_ID_UNPCKLPS_XMMR1_XMMR2                0x4290+0
#define X86IM_IO_ID_UNPCKLPS_XMMRG_MM                   0x4290+1

#define X86IM_IO_IS_SSE_XORPS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x42A0 )
#define X86IM_IO_ID_XORPS_XMMR1_XMMR2                   0x42A0+0
#define X86IM_IO_ID_XORPS_XMMRG_MM                      0x42A0+1

#define X86IM_IO_ID_PEXTRW_R1_MMXR2_IMM8                0x42B0
#define X86IM_IO_ID_PMOVMSKB_R1_MMXR2                   0x42B1

#define X86IM_IO_IS_SSE_PAVG(x)                         ( ( (x)->id & 0xFFF0 ) == 0x42C0 )
#define X86IM_IO_ID_PAVGB_MMXR1_MMXR2                   0x42C0+0
#define X86IM_IO_ID_PAVGB_MMXRG_MM64                    0x42C0+1
#define X86IM_IO_ID_PAVGW_MMXR1_MMXR2                   0x42C0+2
#define X86IM_IO_ID_PAVGW_MMXRG_MM64                    0x42C0+3

#define X86IM_IO_IS_SSE_PINSRW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x42D0 )
#define X86IM_IO_ID_PINSRW_MMXR1_R2_IMM8                0x42D0+0
#define X86IM_IO_ID_PINSRW_MMXRG_MM16_IMM8              0x42D0+1

#define X86IM_IO_IS_SSE_PMAXSW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x42E0 )
#define X86IM_IO_ID_PMAXSW_MMXR1_MMXR2                  0x42E0+0
#define X86IM_IO_ID_PMAXSW_MMXRG_MM64                   0x42E0+1

#define X86IM_IO_IS_SSE_PMAXUB(x)                       ( ( (x)->id & 0xFFF0 ) == 0x42F0 )
#define X86IM_IO_ID_PMAXUB_MMXR1_MMXR2                  0x42F0+0
#define X86IM_IO_ID_PMAXUB_MMXRG_MM64                   0x42F0+1

#define X86IM_IO_IS_SSE_PMINSW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4300 )
#define X86IM_IO_ID_PMINSW_MMXR1_MMXR2                  0x4300+0
#define X86IM_IO_ID_PMINSW_MMXRG_MM64                   0x4300+1

#define X86IM_IO_IS_SSE_PMINUB(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4310 )
#define X86IM_IO_ID_PMINUB_MMXR1_MMXR2                  0x4310+0
#define X86IM_IO_ID_PMINUB_MMXRG_MM64                   0x4310+1

#define X86IM_IO_IS_SSE_PMULHUW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x4320 )
#define X86IM_IO_ID_PMULHUW_MMXR1_MMXR2                 0x4320+0
#define X86IM_IO_ID_PMULHUW_MMXRG_MM64                  0x4320+1

#define X86IM_IO_IS_SSE_PSADBW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4330 )
#define X86IM_IO_ID_PSADBW_MMXR1_MMXR2                  0x4330+0
#define X86IM_IO_ID_PSADBW_MMXRG_MM64                   0x4330+1

#define X86IM_IO_IS_SSE_PSHUFW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x4340 )
#define X86IM_IO_ID_PSHUFW_MMXR1_MMXR2_IMM8             0x4340+0
#define X86IM_IO_ID_PSHUFW_MMXRG_MM64_IMM8              0x4340+1

// SSE2

#define X86IM_IO_ID_MOVMSKPD_R1_XMMR2                   0x5000
#define X86IM_IO_ID_MASKMOVDQU_XMMR1_XMMR2              0x5001
#define X86IM_IO_ID_CLFLUSH_MM8                         0x5002
#define X86IM_IO_ID_MOVNTPD_MM_XMMRG                    0x5003
#define X86IM_IO_ID_MOVNTDQ_MM_XMMRG                    0x5004
#define X86IM_IO_ID_MOVNTI_MM_RG                        0x5005
#define X86IM_IO_ID_PAUSE                               0x5006
#define X86IM_IO_ID_LFENCE                              0x5007
#define X86IM_IO_ID_MFENCE                              0x5008

#define X86IM_IO_IS_SSE2_ADDPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5010 )
#define X86IM_IO_ID_ADDPD_XMMR1_XMMR2                   0x5010+0
#define X86IM_IO_ID_ADDPD_XMMRG_MM                      0x5010+1

#define X86IM_IO_IS_SSE2_ADDSD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5020 )
#define X86IM_IO_ID_ADDSD_XMMR1_XMMR2                   0x5020+0
#define X86IM_IO_ID_ADDSD_XMMRG_MM64                    0x5020+1

#define X86IM_IO_IS_SSE2_ANDNPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5030 )
#define X86IM_IO_ID_ANDNPD_XMMR1_XMMR2                  0x5030+0
#define X86IM_IO_ID_ANDNPD_XMMRG_MM                     0x5030+1

#define X86IM_IO_IS_SSE2_ANDPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5040 )
#define X86IM_IO_ID_ANDPD_XMMR1_XMMR2                   0x5040+0
#define X86IM_IO_ID_ANDPD_XMMRG_MM                      0x5040+1

#define X86IM_IO_IS_SSE2_CMPPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5050 )
#define X86IM_IO_ID_CMPPD_XMMR1_XMMR2_IMM8              0x5050+0
#define X86IM_IO_ID_CMPPD_XMMRG_MM_IMM8                 0x5050+1

#define X86IM_IO_IS_SSE2_CMPSD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5060 )
#define X86IM_IO_ID_CMPSD_XMMR1_XMMR2_IMM8              0x5060+0
#define X86IM_IO_ID_CMPSD_XMMRG_MM64_IMM8               0x5060+1

#define X86IM_IO_IS_SSE2_COMISD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5070 )
#define X86IM_IO_ID_COMISD_XMMR1_XMMR2                  0x5070+0
#define X86IM_IO_ID_COMISD_XMMRG_MM64                   0x5070+1

#define X86IM_IO_IS_SSE2_CVTPI2PD(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5080 )
#define X86IM_IO_ID_CVTPI2PD_XMMR1_MMXR2                0x5080+0
#define X86IM_IO_ID_CVTPI2PD_XMMRG_MM64                 0x5080+1

#define X86IM_IO_IS_SSE2_CVTPD2PI(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5090 )
#define X86IM_IO_ID_CVTPD2PI_MMXR1_XMMR2                0x5090+0
#define X86IM_IO_ID_CVTPD2PI_MMXRG_MM                   0x5090+1

#define X86IM_IO_IS_SSE2_CVTSI2SD(x)                    ( ( (x)->id & 0xFFF0 ) == 0x50A0 )
#define X86IM_IO_ID_CVTSI2SD_XMMR1_R2                   0x50A0+0
#define X86IM_IO_ID_CVTSI2SD_XMMRG_MM                   0x50A0+1

#define X86IM_IO_IS_SSE2_CVTSD2SI(x)                    ( ( (x)->id & 0xFFF0 ) == 0x50B0 )
#define X86IM_IO_ID_CVTSD2SI_R1_XMMR2                   0x50B0+0
#define X86IM_IO_ID_CVTSD2SI_RG_MM64                    0x50B0+1

#define X86IM_IO_IS_SSE2_CVTTPD2PI(x)                   ( ( (x)->id & 0xFFF0 ) == 0x50C0 )
#define X86IM_IO_ID_CVTTPD2PI_MMXR1_XMMR2               0x50C0+0
#define X86IM_IO_ID_CVTTPD2PI_MMXRG_MM                  0x50C0+1

#define X86IM_IO_IS_SSE2_CVTTSD2SI(x)                   ( ( (x)->id & 0xFFF0 ) == 0x50D0 )
#define X86IM_IO_ID_CVTTSD2SI_R1_XMMR2                  0x50D0+0
#define X86IM_IO_ID_CVTTSD2SI_RG_MM64                   0x50D0+1

#define X86IM_IO_IS_SSE2_CVTPD2PS(x)                    ( ( (x)->id & 0xFFF0 ) == 0x50E0 )
#define X86IM_IO_ID_CVTPD2PS_XMMR1_XMMR2                0x50E0+0
#define X86IM_IO_ID_CVTPD2PS_XMMRG_MM                   0x50E0+1

#define X86IM_IO_IS_SSE2_CVTPS2PD(x)                    ( ( (x)->id & 0xFFF0 ) == 0x50F0 )
#define X86IM_IO_ID_CVTPS2PD_XMMR1_XMMR2                0x50F0+0
#define X86IM_IO_ID_CVTPS2PD_XMMRG_MM64                 0x50F0+1

#define X86IM_IO_IS_SSE2_CVTSD2SS(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5100 )
#define X86IM_IO_ID_CVTSD2SS_XMMR1_XMMR2                0x5100+0
#define X86IM_IO_ID_CVTSD2SS_XMMRG_MM64                 0x5100+1

#define X86IM_IO_IS_SSE2_CVTSS2SD(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5110 )
#define X86IM_IO_ID_CVTSS2SD_XMMR1_XMMR2                0x5110+0
#define X86IM_IO_ID_CVTSS2SD_XMMRG_MM32                 0x5110+1

#define X86IM_IO_IS_SSE2_CVTPD2DQ(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5120 )
#define X86IM_IO_ID_CVTPD2DQ_XMMR1_XMMR2                0x5120+0
#define X86IM_IO_ID_CVTPD2DQ_XMMRG_MM                   0x5120+1

#define X86IM_IO_IS_SSE2_CVTTPD2DQ(x)                   ( ( (x)->id & 0xFFF0 ) == 0x5130 )
#define X86IM_IO_ID_CVTTPD2DQ_XMMR1_XMMR2               0x5130+0
#define X86IM_IO_ID_CVTTPD2DQ_XMMRG_MM                  0x5130+1

#define X86IM_IO_IS_SSE2_CVTDQ2PD(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5140 )
#define X86IM_IO_ID_CVTDQ2PD_XMMR1_XMMR2                0x5140+0
#define X86IM_IO_ID_CVTDQ2PD_XMMRG_MM64                 0x5140+1

#define X86IM_IO_IS_SSE2_CVTPS2DQ(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5150 )
#define X86IM_IO_ID_CVTPS2DQ_XMMR1_XMMR2                0x5150+0
#define X86IM_IO_ID_CVTPS2DQ_XMMRG_MM                   0x5150+1

#define X86IM_IO_IS_SSE2_CVTTPS2DQ(x)                   ( ( (x)->id & 0xFFF0 ) == 0x5160 )
#define X86IM_IO_ID_CVTTPS2DQ_XMMR1_XMMR2               0x5160+0
#define X86IM_IO_ID_CVTTPS2DQ_XMMRG_MM                  0x5160+1

#define X86IM_IO_IS_SSE2_CVTDQ2PS(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5170 )
#define X86IM_IO_ID_CVTDQ2PS_XMMR1_XMMR2                0x5170+0
#define X86IM_IO_ID_CVTDQ2PS_XMMRG_MM                   0x5170+1

#define X86IM_IO_IS_SSE2_DIVPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5180 )
#define X86IM_IO_ID_DIVPD_XMMR1_XMMR2                   0x5180+0
#define X86IM_IO_ID_DIVPD_XMMRG_MM                      0x5180+1

#define X86IM_IO_IS_SSE2_DIVSD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5190 )
#define X86IM_IO_ID_DIVSD_XMMR1_XMMR2                   0x5190+0
#define X86IM_IO_ID_DIVSD_XMMRG_MM64                    0x5190+1

#define X86IM_IO_IS_SSE2_MAXPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x51A0 )
#define X86IM_IO_ID_MAXPD_XMMR1_XMMR2                   0x51A0+0
#define X86IM_IO_ID_MAXPD_XMMRG_MM                      0x51A0+1

#define X86IM_IO_IS_SSE2_MAXSD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x51B0 )
#define X86IM_IO_ID_MAXSD_XMMR1_XMMR2                   0x51B0+0
#define X86IM_IO_ID_MAXSD_XMMRG_MM64                    0x51B0+1

#define X86IM_IO_IS_SSE2_MINPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x51C0 )
#define X86IM_IO_ID_MINPD_XMMR1_XMMR2                   0x51C0+0
#define X86IM_IO_ID_MINPD_XMMRG_MM                      0x51C0+1

#define X86IM_IO_IS_SSE2_MINSD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x51D0 )
#define X86IM_IO_ID_MINSD_XMMR1_XMMR2                   0x51D0+0
#define X86IM_IO_ID_MINSD_XMMRG_MM64                    0x51D0+1

#define X86IM_IO_IS_SSE2_MOVAPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x51E0 )
#define X86IM_IO_ID_MOVAPD_XMMR1_XMMR2                  0x51E0+0
#define X86IM_IO_ID_MOVAPD_XMMRG_MM                     0x51E0+1
#define X86IM_IO_ID_MOVAPD_XMMR2_XMMR1                  0x51E0+2
#define X86IM_IO_ID_MOVAPD_MM_XMMRG                     0x51E0+3

#define X86IM_IO_IS_SSE2_MOVHPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x51F0 )
#define X86IM_IO_ID_MOVHPD_XMMRG_MM64                   0x51F0+0
#define X86IM_IO_ID_MOVHPD_MM64_XMMRG                   0x51F0+1

#define X86IM_IO_IS_SSE2_MOVLPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5200 )
#define X86IM_IO_ID_MOVLPD_XMMRG_MM64                   0x5200+0
#define X86IM_IO_ID_MOVLPD_MM64_XMMRG                   0x5200+1

#define X86IM_IO_IS_SSE2_MOVSD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5210 )
#define X86IM_IO_ID_MOVSD_XMMR1_XMMR2                   0x5210+0
#define X86IM_IO_ID_MOVSD_XMMRG_MM64                    0x5210+1
#define X86IM_IO_ID_MOVSD_XMMR2_XMMR1                   0x5210+2
#define X86IM_IO_ID_MOVSD_MM64_XMMRG                    0x5210+3

#define X86IM_IO_IS_SSE2_MOVUPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5220 )
#define X86IM_IO_ID_MOVUPD_XMMR1_XMMR2                  0x5220+0
#define X86IM_IO_ID_MOVUPD_XMMRG_MM                     0x5220+1
#define X86IM_IO_ID_MOVUPD_XMMR2_XMMR1                  0x5220+2
#define X86IM_IO_ID_MOVUPD_MM_XMMRG                     0x5220+3

#define X86IM_IO_IS_SSE2_MULPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5230 )
#define X86IM_IO_ID_MULPD_XMMR1_XMMR2                   0x5230+0
#define X86IM_IO_ID_MULPD_XMMRG_MM                      0x5230+1

#define X86IM_IO_IS_SSE2_MULSD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5240 )
#define X86IM_IO_ID_MULSD_XMMR1_XMMR2                   0x5240+0
#define X86IM_IO_ID_MULSD_XMMRG_MM64                    0x5240+1

#define X86IM_IO_IS_SSE2_ORPD(x)                        ( ( (x)->id & 0xFFF0 ) == 0x5250 )
#define X86IM_IO_ID_ORPD_XMMR1_XMMR2                    0x5250+0
#define X86IM_IO_ID_ORPD_XMMRG_MM                       0x5250+1

#define X86IM_IO_IS_SSE2_SHUFPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5260 )
#define X86IM_IO_ID_SHUFPD_XMMR1_XMMR2_IMM8             0x5260+0
#define X86IM_IO_ID_SHUFPD_XMMRG_MM_IMM8                0x5260+1

#define X86IM_IO_IS_SSE2_SQRTPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5270 )
#define X86IM_IO_ID_SQRTPD_XMMR1_XMMR2                  0x5270+0
#define X86IM_IO_ID_SQRTPD_XMMRG_MM                     0x5270+1

#define X86IM_IO_IS_SSE2_SQRTSD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5280 )
#define X86IM_IO_ID_SQRTSD_XMMR1_XMMR2                  0x5280+0
#define X86IM_IO_ID_SQRTSD_XMMRG_MM64                   0x5280+1

#define X86IM_IO_IS_SSE2_SUBPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5290 )
#define X86IM_IO_ID_SUBPD_XMMR1_XMMR2                   0x5290+0
#define X86IM_IO_ID_SUBPD_XMMRG_MM                      0x5290+1

#define X86IM_IO_IS_SSE2_SUBSD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x52A0 )
#define X86IM_IO_ID_SUBSD_XMMR1_XMMR2                   0x52A0+0
#define X86IM_IO_ID_SUBSD_XMMRG_MM64                    0x52A0+1

#define X86IM_IO_IS_SSE2_UCOMISD(x)                     ( ( (x)->id & 0xFFF0 ) == 0x52B0 )
#define X86IM_IO_ID_UCOMISD_XMMR1_XMMR2                 0x52B0+0
#define X86IM_IO_ID_UCOMISD_XMMRG_MM64                  0x52B0+1

#define X86IM_IO_IS_SSE2_UNPCKHPD(x)                    ( ( (x)->id & 0xFFF0 ) == 0x52C0 )
#define X86IM_IO_ID_UNPCKHPD_XMMR1_XMMR2                0x52C0+0
#define X86IM_IO_ID_UNPCKHPD_XMMRG_MM                   0x52C0+1

#define X86IM_IO_IS_SSE2_UNPCKLPD(x)                    ( ( (x)->id & 0xFFF0 ) == 0x52D0 )
#define X86IM_IO_ID_UNPCKLPD_XMMR1_XMMR2                0x52D0+0
#define X86IM_IO_ID_UNPCKLPD_XMMRG_MM                   0x52D0+1

#define X86IM_IO_IS_SSE2_XORPD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x52E0 )
#define X86IM_IO_ID_XORPD_XMMR1_XMMR2                   0x52E0+0
#define X86IM_IO_ID_XORPD_XMMRG_MM                      0x52E0+1

#define X86IM_IO_ID_MOVQ2DQ_XMMR1_MMXR2                 0x52F0
#define X86IM_IO_ID_MOVDQ2Q_MMXR1_XMMR2                 0x52F1
#define X86IM_IO_ID_PEXTRW_R1_XMMR2_IMM8                0x52F2
#define X86IM_IO_ID_PMOVMSKB_R1_XMMR2                   0x52F3
#define X86IM_IO_ID_PSLLDQ_XMMRG_IMM8                   0x52F4
#define X86IM_IO_ID_PSRLDQ_XMMRG_IMM8                   0x52F5

#define X86IM_IO_IS_SSE2_MOVD(x)                        ( ( (x)->id & 0xFFF0 ) == 0x5300 )
#define X86IM_IO_ID_MOVD_XMMRG_RG                       0x5300+0
#define X86IM_IO_ID_MOVD_XMMRG_MM                       0x5300+1
#define X86IM_IO_ID_MOVD_RG_XMMRG                       0x5300+2
#define X86IM_IO_ID_MOVD_MM_XMMRG                       0x5300+3

#define X86IM_IO_IS_SSE2_MOVDQA(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5310 )
#define X86IM_IO_ID_MOVDQA_XMMR1_XMMR2                  0x5310+0
#define X86IM_IO_ID_MOVDQA_XMMRG_MM                     0x5310+1
#define X86IM_IO_ID_MOVDQA_XMMR2_XMMR1                  0x5310+2
#define X86IM_IO_ID_MOVDQA_MM_XMMRG                     0x5310+3

#define X86IM_IO_IS_SSE2_MOVDQU(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5320 )
#define X86IM_IO_ID_MOVDQU_XMMR1_XMMR2                  0x5320+0
#define X86IM_IO_ID_MOVDQU_XMMRG_MM                     0x5320+1
#define X86IM_IO_ID_MOVDQU_XMMR2_XMMR1                  0x5320+2
#define X86IM_IO_ID_MOVDQU_MM_XMMRG                     0x5320+3

#define X86IM_IO_IS_SSE2_MOVQ(x)                        ( ( (x)->id & 0xFFF0 ) == 0x5330 )
#define X86IM_IO_ID_MOVQ_XMMR1_XMMR2                    0x5330+0
#define X86IM_IO_ID_MOVQ_XMMRG_MM64                     0x5330+1
#define X86IM_IO_ID_MOVQ_XMMR2_XMMR1                    0x5330+2
#define X86IM_IO_ID_MOVQ_MM64_XMMRG                     0x5330+3

#define X86IM_IO_IS_SSE2_PACKSSDW(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5340 )
#define X86IM_IO_ID_PACKSSDW_XMMR1_XMMR2                0x5340+0
#define X86IM_IO_ID_PACKSSDW_XMMRG_MM                   0x5340+1

#define X86IM_IO_IS_SSE2_PACKSSWB(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5350 )
#define X86IM_IO_ID_PACKSSWB_XMMR1_XMMR2                0x5350+0
#define X86IM_IO_ID_PACKSSWB_XMMRG_MM                   0x5350+1

#define X86IM_IO_IS_SSE2_PACKUSWB(x)                    ( ( (x)->id & 0xFFF0 ) == 0x5360 )
#define X86IM_IO_ID_PACKUSWB_XMMR1_XMMR2                0x5360+0
#define X86IM_IO_ID_PACKUSWB_XMMRG_MM                   0x5360+1

#define X86IM_IO_IS_SSE2_PADDQ(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5370 )
#define X86IM_IO_ID_PADDQ_MMXR1_MMXR2                   0x5370+0
#define X86IM_IO_ID_PADDQ_MMXRG_MM64                    0x5370+1
#define X86IM_IO_ID_PADDQ_XMMR1_XMMR2                   0x5370+2
#define X86IM_IO_ID_PADDQ_XMMRG_MM                      0x5370+3

#define X86IM_IO_IS_SSE2_PADD(x)                        ( ( (x)->id & 0xFFF0 ) == 0x5380 )
#define X86IM_IO_ID_PADDB_XMMR1_XMMR2                   0x5380+0
#define X86IM_IO_ID_PADDB_XMMRG_MM                      0x5380+1
#define X86IM_IO_ID_PADDW_XMMR1_XMMR2                   0x5380+2
#define X86IM_IO_ID_PADDW_XMMRG_MM                      0x5380+3
#define X86IM_IO_ID_PADDD_XMMR1_XMMR2                   0x5380+4
#define X86IM_IO_ID_PADDD_XMMRG_MM                      0x5380+5

#define X86IM_IO_IS_SSE2_PADDS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5390 )
#define X86IM_IO_ID_PADDSB_XMMR1_XMMR2                  0x5390+0
#define X86IM_IO_ID_PADDSB_XMMRG_MM                     0x5390+1
#define X86IM_IO_ID_PADDSW_XMMR1_XMMR2                  0x5390+2
#define X86IM_IO_ID_PADDSW_XMMRG_MM                     0x5390+3

#define X86IM_IO_IS_SSE2_PADDUS(x)                      ( ( (x)->id & 0xFFF0 ) == 0x53A0 )
#define X86IM_IO_ID_PADDUSB_XMMR1_XMMR2                 0x53A0+0
#define X86IM_IO_ID_PADDUSB_XMMRG_MM                    0x53A0+1
#define X86IM_IO_ID_PADDUSW_XMMR1_XMMR2                 0x53A0+2
#define X86IM_IO_ID_PADDUSW_XMMRG_MM                    0x53A0+3

#define X86IM_IO_IS_SSE2_PAND(x)                        ( ( (x)->id & 0xFFF0 ) == 0x53B0 )
#define X86IM_IO_ID_PAND_XMMR1_XMMR2                    0x53B0+0
#define X86IM_IO_ID_PAND_XMMRG_MM                       0x53B0+1

#define X86IM_IO_IS_SSE2_PANDN(x)                       ( ( (x)->id & 0xFFF0 ) == 0x53C0 )
#define X86IM_IO_ID_PANDN_XMMR1_XMMR2                   0x53C0+0
#define X86IM_IO_ID_PANDN_XMMRG_MM                      0x53C0+1

#define X86IM_IO_IS_SSE2_PAVGB(x)                       ( ( (x)->id & 0xFFF0 ) == 0x53D0 )
#define X86IM_IO_ID_PAVGB_XMMR1_XMMR2                   0x53D0+0
#define X86IM_IO_ID_PAVGB_XMMRG_MM                      0x53D0+1

#define X86IM_IO_IS_SSE2_PAVGW(x)                       ( ( (x)->id & 0xFFF0 ) == 0x53E0 )
#define X86IM_IO_ID_PAVGW_XMMR1_XMMR2                   0x53E0+0
#define X86IM_IO_ID_PAVGW_XMMRG_MM                      0x53E0+1

#define X86IM_IO_IS_SSE2_PCMPEQ(x)                      ( ( (x)->id & 0xFFF0 ) == 0x53F0 )
#define X86IM_IO_ID_PCMPEQB_XMMR1_XMMR2                 0x53F0+0
#define X86IM_IO_ID_PCMPEQB_XMMRG_MM                    0x53F0+1
#define X86IM_IO_ID_PCMPEQW_XMMR1_XMMR2                 0x53F0+2
#define X86IM_IO_ID_PCMPEQW_XMMRG_MM                    0x53F0+3
#define X86IM_IO_ID_PCMPEQD_XMMR1_XMMR2                 0x53F0+4
#define X86IM_IO_ID_PCMPEQD_XMMRG_MM                    0x53F0+5

#define X86IM_IO_IS_SSE2_PCMPGT(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5400 )
#define X86IM_IO_ID_PCMPGTB_XMMR1_XMMR2                 0x5400+0
#define X86IM_IO_ID_PCMPGTB_XMMRG_MM                    0x5400+1
#define X86IM_IO_ID_PCMPGTW_XMMR1_XMMR2                 0x5400+2
#define X86IM_IO_ID_PCMPGTW_XMMRG_MM                    0x5400+3
#define X86IM_IO_ID_PCMPGTD_XMMR1_XMMR2                 0x5400+4
#define X86IM_IO_ID_PCMPGTD_XMMRG_MM                    0x5400+5

#define X86IM_IO_IS_SSE2_PINSRW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5410 )
#define X86IM_IO_ID_PINSRW_XMMR1_R2_IMM8                0x5410+0
#define X86IM_IO_ID_PINSRW_XMMRG_MM16_IMM8              0x5410+1

#define X86IM_IO_IS_SSE2_PMADDWD(x)                     ( ( (x)->id & 0xFFF0 ) == 0x5420 )
#define X86IM_IO_ID_PMADDWD_XMMR1_XMMR2                 0x5420+0
#define X86IM_IO_ID_PMADDWD_XMMRG_MM                    0x5420+1

#define X86IM_IO_IS_SSE2_PMAXSW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5430 )
#define X86IM_IO_ID_PMAXSW_XMMR1_XMMR2                  0x5430+0
#define X86IM_IO_ID_PMAXSW_XMMRG_MM                     0x5430+1

#define X86IM_IO_IS_SSE2_PMAXUB(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5440 )
#define X86IM_IO_ID_PMAXUB_XMMR1_XMMR2                  0x5440+0
#define X86IM_IO_ID_PMAXUB_XMMRG_MM                     0x5440+1

#define X86IM_IO_IS_SSE2_PMINSW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5450 )
#define X86IM_IO_ID_PMINSW_XMMR1_XMMR2                  0x5450+0
#define X86IM_IO_ID_PMINSW_XMMRG_MM                     0x5450+1

#define X86IM_IO_IS_SSE2_PMINUB(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5460 )
#define X86IM_IO_ID_PMINUB_XMMR1_XMMR2                  0x5460+0
#define X86IM_IO_ID_PMINUB_XMMRG_MM                     0x5460+1

#define X86IM_IO_IS_SSE2_PMULHUW(x)                     ( ( (x)->id & 0xFFF0 ) == 0x5470 )
#define X86IM_IO_ID_PMULHUW_XMMR1_XMMR2                 0x5470+0
#define X86IM_IO_ID_PMULHUW_XMMRG_MM                    0x5470+1

#define X86IM_IO_IS_SSE2_PMULHW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5480 )
#define X86IM_IO_ID_PMULHW_XMMR1_XMMR2                  0x5480+0
#define X86IM_IO_ID_PMULHW_XMMRG_MM                     0x5480+1

#define X86IM_IO_IS_SSE2_PMULLW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5490 )
#define X86IM_IO_ID_PMULLW_XMMR1_XMMR2                  0x5490+0
#define X86IM_IO_ID_PMULLW_XMMRG_MM                     0x5490+1

#define X86IM_IO_IS_SSE2_PMULUDQ(x)                     ( ( (x)->id & 0xFFF0 ) == 0x54A0 )
#define X86IM_IO_ID_PMULUDQ_MMXR1_MMXR2                 0x54A0+0
#define X86IM_IO_ID_PMULUDQ_MMXRG_MM64                  0x54A0+1
#define X86IM_IO_ID_PMULUDQ_XMMR1_XMMR2                 0x54A0+2
#define X86IM_IO_ID_PMULUDQ_XMMRG_MM                    0x54A0+3

#define X86IM_IO_IS_SSE2_POR(x)                         ( ( (x)->id & 0xFFF0 ) == 0x54B0 )
#define X86IM_IO_ID_POR_XMMR1_XMMR2                     0x54B0+0
#define X86IM_IO_ID_POR_XMMRG_MM                        0x54B0+1

#define X86IM_IO_IS_SSE2_PSADBW(x)                      ( ( (x)->id & 0xFFF0 ) == 0x54C0 )
#define X86IM_IO_ID_PSADBW_XMMR1_XMMR2                  0x54C0+0
#define X86IM_IO_ID_PSADBW_XMMRG_MM                     0x54C0+1

#define X86IM_IO_IS_SSE2_PSHUFLW(x)                     ( ( (x)->id & 0xFFF0 ) == 0x54D0 )
#define X86IM_IO_ID_PSHUFLW_XMMR1_XMMR2_IMM8            0x54D0+0
#define X86IM_IO_ID_PSHUFLW_XMMRG_MM_IMM8               0x54D0+1

#define X86IM_IO_IS_SSE2_PSHUFHW(x)                     ( ( (x)->id & 0xFFF0 ) == 0x54E0 )
#define X86IM_IO_ID_PSHUFHW_XMMR1_XMMR2_IMM8            0x54E0+0
#define X86IM_IO_ID_PSHUFHW_XMMRG_MM_IMM8               0x54E0+1

#define X86IM_IO_IS_SSE2_PSHUFD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x54F0 )
#define X86IM_IO_ID_PSHUFD_XMMR1_XMMR2_IMM8             0x54F0+0
#define X86IM_IO_ID_PSHUFD_XMMRG_MM_IMM8                0x54F0+1

#define X86IM_IO_IS_SSE2_PSLL(x)                        ( ( (x)->id & 0xFFF0 ) == 0x5500 )
#define X86IM_IO_ID_PSLLW_XMMR1_XMMR2                   0x5500+0
#define X86IM_IO_ID_PSLLW_XMMRG_MM                      0x5500+1
#define X86IM_IO_ID_PSLLD_XMMR1_XMMR2                   0x5500+2
#define X86IM_IO_ID_PSLLD_XMMRG_MM                      0x5500+3
#define X86IM_IO_ID_PSLLQ_XMMR1_XMMR2                   0x5500+4
#define X86IM_IO_ID_PSLLQ_XMMRG_MM                      0x5500+5
#define X86IM_IO_ID_PSLLW_XMMRG_IMM8                    0x5500+6
#define X86IM_IO_ID_PSLLD_XMMRG_IMM8                    0x5500+7
#define X86IM_IO_ID_PSLLQ_XMMRG_IMM8                    0x5500+8

#define X86IM_IO_IS_SSE2_PSRA(x)                        ( ( (x)->id & 0xFFF0 ) == 0x5510 )
#define X86IM_IO_ID_PSRAW_XMMR1_XMMR2                   0x5510+0
#define X86IM_IO_ID_PSRAW_XMMRG_MM                      0x5510+1
#define X86IM_IO_ID_PSRAD_XMMR1_XMMR2                   0x5510+2
#define X86IM_IO_ID_PSRAD_XMMRG_MM                      0x5510+3
#define X86IM_IO_ID_PSRAW_XMMRG_IMM8                    0x5510+4
#define X86IM_IO_ID_PSRAD_XMMRG_IMM8                    0x5510+5

#define X86IM_IO_IS_SSE2_PSRL(x)                        ( ( (x)->id & 0xFFF0 ) == 0x5520 )
#define X86IM_IO_ID_PSRLW_XMMR1_XMMR2                   0x5520+0
#define X86IM_IO_ID_PSRLW_XMMRG_MM                      0x5520+1
#define X86IM_IO_ID_PSRLD_XMMR1_XMMR2                   0x5520+2
#define X86IM_IO_ID_PSRLD_XMMRG_MM                      0x5520+3
#define X86IM_IO_ID_PSRLQ_XMMR1_XMMR2                   0x5520+4
#define X86IM_IO_ID_PSRLQ_XMMRG_MM                      0x5520+5
#define X86IM_IO_ID_PSRLW_XMMRG_IMM8                    0x5520+6
#define X86IM_IO_ID_PSRLD_XMMRG_IMM8                    0x5520+7
#define X86IM_IO_ID_PSRLQ_XMMRG_IMM8                    0x5520+8

#define X86IM_IO_IS_SSE2_PSUBQ(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5530 )
#define X86IM_IO_ID_PSUBQ_MMXR1_MMXR2                   0x5530+0
#define X86IM_IO_ID_PSUBQ_MMXRG_MM64                    0x5530+1
#define X86IM_IO_ID_PSUBQ_XMMR1_XMMR2                   0x5530+2
#define X86IM_IO_ID_PSUBQ_XMMRG_MM                      0x5530+3

#define X86IM_IO_IS_SSE2_PSUB(x)                        ( ( (x)->id & 0xFFF0 ) == 0x5540 )
#define X86IM_IO_ID_PSUBB_XMMR1_XMMR2                   0x5540+0
#define X86IM_IO_ID_PSUBB_XMMRG_MM                      0x5540+1
#define X86IM_IO_ID_PSUBW_XMMR1_XMMR2                   0x5540+2
#define X86IM_IO_ID_PSUBW_XMMRG_MM                      0x5540+3
#define X86IM_IO_ID_PSUBD_XMMR1_XMMR2                   0x5540+4
#define X86IM_IO_ID_PSUBD_XMMRG_MM                      0x5540+5

#define X86IM_IO_IS_SSE2_PSUBS(x)                       ( ( (x)->id & 0xFFF0 ) == 0x5550 )
#define X86IM_IO_ID_PSUBSB_XMMR1_XMMR2                  0x5550+0
#define X86IM_IO_ID_PSUBSB_XMMRG_MM                     0x5550+1
#define X86IM_IO_ID_PSUBSW_XMMR1_XMMR2                  0x5550+2
#define X86IM_IO_ID_PSUBSW_XMMRG_MM                     0x5550+3

#define X86IM_IO_IS_SSE2_PSUBUS(x)                      ( ( (x)->id & 0xFFF0 ) == 0x5560 )
#define X86IM_IO_ID_PSUBUSB_XMMR1_XMMR2                 0x5560+0
#define X86IM_IO_ID_PSUBUSB_XMMRG_MM                    0x5560+1
#define X86IM_IO_ID_PSUBUSW_XMMR1_XMMR2                 0x5560+2
#define X86IM_IO_ID_PSUBUSW_XMMRG_MM                    0x5560+3

#define X86IM_IO_IS_SSE2_PUNPCKH(x)                     ( ( (x)->id & 0xFFF0 ) == 0x5570 )
#define X86IM_IO_ID_PUNPCKHBW_XMMR1_XMMR2               0x5570+0
#define X86IM_IO_ID_PUNPCKHBW_XMMRG_MM                  0x5570+1
#define X86IM_IO_ID_PUNPCKHWD_XMMR1_XMMR2               0x5570+2
#define X86IM_IO_ID_PUNPCKHWD_XMMRG_MM                  0x5570+3
#define X86IM_IO_ID_PUNPCKHDQ_XMMR1_XMMR2               0x5570+4
#define X86IM_IO_ID_PUNPCKHDQ_XMMRG_MM                  0x5570+5

#define X86IM_IO_IS_SSE2_PUNPCKHQDQ(x)                  ( ( (x)->id & 0xFFF0 ) == 0x5580 )
#define X86IM_IO_ID_PUNPCKHQDQ_XMMR1_XMMR2              0x5580+0
#define X86IM_IO_ID_PUNPCKHQDQ_XMMRG_MM                 0x5580+1

#define X86IM_IO_IS_SSE2_PUNPCKL(x)                     ( ( (x)->id & 0xFFF0 ) == 0x5590 )
#define X86IM_IO_ID_PUNPCKLBW_XMMR1_XMMR2               0x5590+0
#define X86IM_IO_ID_PUNPCKLBW_XMMRG_MM                  0x5590+1
#define X86IM_IO_ID_PUNPCKLWD_XMMR1_XMMR2               0x5590+2
#define X86IM_IO_ID_PUNPCKLWD_XMMRG_MM                  0x5590+3
#define X86IM_IO_ID_PUNPCKLDQ_XMMR1_XMMR2               0x5590+4
#define X86IM_IO_ID_PUNPCKLDQ_XMMRG_MM                  0x5590+5

#define X86IM_IO_IS_SSE2_PUNPCKLQDQ(x)                  ( ( (x)->id & 0xFFF0 ) == 0x55A0 )
#define X86IM_IO_ID_PUNPCKLQDQ_XMMR1_XMMR2              0x55A0+0
#define X86IM_IO_ID_PUNPCKLQDQ_XMMRG_MM                 0x55A0+1

#define X86IM_IO_IS_SSE2_PXOR(x)                        ( ( (x)->id & 0xFFF0 ) == 0x55B0 )
#define X86IM_IO_ID_PXOR_XMMR1_XMMR2                    0x55B0+0
#define X86IM_IO_ID_PXOR_XMMRG_MM                       0x55B0+1

// SSE3

#define X86IM_IO_ID_MONITOR                             0x6000
#define X86IM_IO_ID_MWAIT                               0x6001
#define X86IM_IO_ID_LDDQU_XMMRG_MM                      0x6002

#define X86IM_IO_IS_SSE3_ADDSUBPD(x)                    ( ( (x)->id & 0xFFF0 ) == 0x6010 )
#define X86IM_IO_ID_ADDSUBPD_XMMR1_XMMR2                0x6010+0
#define X86IM_IO_ID_ADDSUBPD_XMMRG_MM                   0x6010+1

#define X86IM_IO_IS_SSE3_ADDSUBPS(x)                    ( ( (x)->id & 0xFFF0 ) == 0x6020 )
#define X86IM_IO_ID_ADDSUBPS_XMMR1_XMMR2                0x6020+0
#define X86IM_IO_ID_ADDSUBPS_XMMRG_MM                   0x6020+1

#define X86IM_IO_IS_SSE3_HADDPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x6030 )
#define X86IM_IO_ID_HADDPD_XMMR1_XMMR2                  0x6030+0
#define X86IM_IO_ID_HADDPD_XMMRG_MM                     0x6030+1

#define X86IM_IO_IS_SSE3_HADDPS(x)                      ( ( (x)->id & 0xFFF0 ) == 0x6040 )
#define X86IM_IO_ID_HADDPS_XMMR1_XMMR2                  0x6040+0
#define X86IM_IO_ID_HADDPS_XMMRG_MM                     0x6040+1

#define X86IM_IO_IS_SSE3_HSUBPD(x)                      ( ( (x)->id & 0xFFF0 ) == 0x6050 )
#define X86IM_IO_ID_HSUBPD_XMMR1_XMMR2                  0x6050+0
#define X86IM_IO_ID_HSUBPD_XMMRG_MM                     0x6050+1

#define X86IM_IO_IS_SSE3_HSUBPS(x)                      ( ( (x)->id & 0xFFF0 ) == 0x6060 )
#define X86IM_IO_ID_HSUBPS_XMMR1_XMMR2                  0x6060+0
#define X86IM_IO_ID_HSUBPS_XMMRG_MM                     0x6060+1

#define X86IM_IO_IS_SSE3_FISTTP(x)                      ( ( (x)->id & 0xFFF0 ) == 0x6070 )
#define X86IM_IO_ID_FISTTP_MM16I                        0x6070+0
#define X86IM_IO_ID_FISTTP_MM32I                        0x6070+1
#define X86IM_IO_ID_FISTTP_MM64I                        0x6070+2

#define X86IM_IO_IS_SSE3_MOVDDUP(x)                     ( ( (x)->id & 0xFFF0 ) == 0x6080 )
#define X86IM_IO_ID_MOVDDUP_XMMR1_XMMR2                 0x6080+0
#define X86IM_IO_ID_MOVDDUP_XMMRG_MM64                  0x6080+1

#define X86IM_IO_IS_SSE3_MOVSHDUP(x)                    ( ( (x)->id & 0xFFF0 ) == 0x6090 )
#define X86IM_IO_ID_MOVSHDUP_XMMR1_XMMR2                0x6090+0
#define X86IM_IO_ID_MOVSHDUP_XMMRG_MM                   0x6090+1

#define X86IM_IO_IS_SSE3_MOVSLDUP(x)                    ( ( (x)->id & 0xFFF0 ) == 0x60A0 )
#define X86IM_IO_ID_MOVSLDUP_XMMR1_XMMR2                0x60A0+0
#define X86IM_IO_ID_MOVSLDUP_XMMRG_MM                   0x60A0+1

#define X86IM_IO_IS_SSE3_PABS(x)                        ( ( (x)->id & 0xFFF0 ) == 0x60B0 )
#define X86IM_IO_ID_PABSB_MMXR1_MMXR2                   0x60B0+0
#define X86IM_IO_ID_PABSB_MMXRG_MM                      0x60B0+1
#define X86IM_IO_ID_PABSW_MMXR1_MMXR2                   0x60B0+2
#define X86IM_IO_ID_PABSW_MMXRG_MM                      0x60B0+3
#define X86IM_IO_ID_PABSD_MMXR1_MMXR2                   0x60B0+4
#define X86IM_IO_ID_PABSD_MMXRG_MM                      0x60B0+5
#define X86IM_IO_ID_PABSB_XMMR1_XMMR2                   0x60B0+6
#define X86IM_IO_ID_PABSB_XMMRG_MM                      0x60B0+7
#define X86IM_IO_ID_PABSW_XMMR1_XMMR2                   0x60B0+8
#define X86IM_IO_ID_PABSW_XMMRG_MM                      0x60B0+9
#define X86IM_IO_ID_PABSD_XMMR1_XMMR2                   0x60B0+0xA
#define X86IM_IO_ID_PABSD_XMMRG_MM                      0x60B0+0xB

#define X86IM_IO_IS_SSE3_PALIGNR(x)                     ( ( (x)->id & 0xFFF0 ) == 0x60C0 )
#define X86IM_IO_ID_PALIGNR_MMXR1_MMXR2_IMM8            0x60C0+0
#define X86IM_IO_ID_PALIGNR_MMXRG_MM_IMM8               0x60C0+1
#define X86IM_IO_ID_PALIGNR_XMMR1_XMMR2_IMM8            0x60C0+2
#define X86IM_IO_ID_PALIGNR_XMMRG_MM_IMM8               0x60C0+3

#define X86IM_IO_IS_SSE3_PHADDSW(x)                     ( ( (x)->id & 0xFFF0 ) == 0x60D0 )
#define X86IM_IO_ID_PHADDSW_MMXR1_MMXR2                 0x60D0+0
#define X86IM_IO_ID_PHADDSW_MMXRG_MM                    0x60D0+1
#define X86IM_IO_ID_PHADDSW_XMMR1_XMMR2                 0x60D0+2
#define X86IM_IO_ID_PHADDSW_XMMRG_MM                    0x60D0+3

#define X86IM_IO_IS_SSE3_PHSUBSW(x)                     ( ( (x)->id & 0xFFF0 ) == 0x60E0 )
#define X86IM_IO_ID_PHSUBSW_MMXR1_MMXR2                 0x60E0+0
#define X86IM_IO_ID_PHSUBSW_MMXRG_MM                    0x60E0+1
#define X86IM_IO_ID_PHSUBSW_XMMR1_XMMR2                 0x60E0+2
#define X86IM_IO_ID_PHSUBSW_XMMRG_MM                    0x60E0+3

#define X86IM_IO_IS_SSE3_PMADDUBSW(x)                   ( ( (x)->id & 0xFFF0 ) == 0x60F0 )
#define X86IM_IO_ID_PMADDUBSW_MMXR1_MMXR2               0x60F0+0
#define X86IM_IO_ID_PMADDUBSW_MMXRG_MM                  0x60F0+1
#define X86IM_IO_ID_PMADDUBSW_XMMR1_XMMR2               0x60F0+2
#define X86IM_IO_ID_PMADDUBSW_XMMRG_MM                  0x60F0+3

#define X86IM_IO_IS_SSE3_PMULHRSW(x)                    ( ( (x)->id & 0xFFF0 ) == 0x6100 )
#define X86IM_IO_ID_PMULHRSW_MMXR1_MMXR2                0x6100+0
#define X86IM_IO_ID_PMULHRSW_MMXRG_MM                   0x6100+1
#define X86IM_IO_ID_PMULHRSW_XMMR1_XMMR2                0x6100+2
#define X86IM_IO_ID_PMULHRSW_XMMRG_MM                   0x6100+3

#define X86IM_IO_IS_SSE3_PSHUFB(x)                      ( ( (x)->id & 0xFFF0 ) == 0x6110 )
#define X86IM_IO_ID_PSHUFB_MMXR1_MMXR2                  0x6110+0
#define X86IM_IO_ID_PSHUFB_MMXRG_MM                     0x6110+1
#define X86IM_IO_ID_PSHUFB_XMMR1_XMMR2                  0x6110+2
#define X86IM_IO_ID_PSHUFB_XMMRG_MM                     0x6110+3

#define X86IM_IO_IS_SSE3_PSIGN(x)                       ( ( (x)->id & 0xFFF0 ) == 0x6120 )
#define X86IM_IO_ID_PSIGNB_MMXR1_MMXR2                  0x6120+0
#define X86IM_IO_ID_PSIGNB_MMXRG_MM                     0x6120+1
#define X86IM_IO_ID_PSIGNW_MMXR1_MMXR2                  0x6120+2
#define X86IM_IO_ID_PSIGNW_MMXRG_MM                     0x6120+3
#define X86IM_IO_ID_PSIGND_MMXR1_MMXR2                  0x6120+4
#define X86IM_IO_ID_PSIGND_MMXRG_MM                     0x6120+5
#define X86IM_IO_ID_PSIGNB_XMMR1_XMMR2                  0x6120+6
#define X86IM_IO_ID_PSIGNB_XMMRG_MM                     0x6120+7
#define X86IM_IO_ID_PSIGNW_XMMR1_XMMR2                  0x6120+8
#define X86IM_IO_ID_PSIGNW_XMMRG_MM                     0x6120+9
#define X86IM_IO_ID_PSIGND_XMMR1_XMMR2                  0x6120+0xA
#define X86IM_IO_ID_PSIGND_XMMRG_MM                     0x6120+0xB

#define X86IM_IO_IS_SSE3_PHADD(x)                       ( ( (x)->id & 0xFFF0 ) == 0x6130 )
#define X86IM_IO_ID_PHADDW_MMXR1_MMXR2                  0x6130+2
#define X86IM_IO_ID_PHADDW_MMXRG_MM                     0x6130+3
#define X86IM_IO_ID_PHADDD_MMXR1_MMXR2                  0x6130+4
#define X86IM_IO_ID_PHADDD_MMXRG_MM                     0x6130+5
#define X86IM_IO_ID_PHADDW_XMMR1_XMMR2                  0x6130+8
#define X86IM_IO_ID_PHADDW_XMMRG_MM                     0x6130+9
#define X86IM_IO_ID_PHADDD_XMMR1_XMMR2                  0x6130+0xA
#define X86IM_IO_ID_PHADDD_XMMRG_MM                     0x6130+0xB

#define X86IM_IO_IS_SSE3_PHSUB(x)                       ( ( (x)->id & 0xFFF0 ) == 0x6140 )
#define X86IM_IO_ID_PHSUBW_MMXR1_MMXR2                  0x6140+2
#define X86IM_IO_ID_PHSUBW_MMXRG_MM                     0x6140+3
#define X86IM_IO_ID_PHSUBD_MMXR1_MMXR2                  0x6140+4
#define X86IM_IO_ID_PHSUBD_MMXRG_MM                     0x6140+5
#define X86IM_IO_ID_PHSUBW_XMMR1_XMMR2                  0x6140+8
#define X86IM_IO_ID_PHSUBW_XMMRG_MM                     0x6140+9
#define X86IM_IO_ID_PHSUBD_XMMR1_XMMR2                  0x6140+0xA
#define X86IM_IO_ID_PHSUBD_XMMRG_MM                     0x6140+0xB

// instr grp & subgrp ( io.grp )

#define X86IM_IO_GET_GR(x)                              ( (x)->grp & 0xF0 ) // get instr grp
#define X86IM_IO_GET_SGR(x)                             ( (x)->grp & 0x0F ) // get instr sub grp

#define X86IM_IO_GR_GPI                                 0x00                    // GPI sub groups:
#define X86IM_IO_SGR_GPI_TRANSF                         X86IM_IO_GR_GPI+0x0     // data transfer instructions
#define X86IM_IO_SGR_GPI_BARITH                         X86IM_IO_GR_GPI+0x1     // binary arithmetic instructions
#define X86IM_IO_SGR_GPI_DARITH                         X86IM_IO_GR_GPI+0x2     // decimal arithmetic instructions
#define X86IM_IO_SGR_GPI_LOGIC                          X86IM_IO_GR_GPI+0x3     // logical instructions
#define X86IM_IO_SGR_GPI_SHIFT                          X86IM_IO_GR_GPI+0x4     // shift instructions
#define X86IM_IO_SGR_GPI_ROTAT                          X86IM_IO_GR_GPI+0x5     // rotate instructions
#define X86IM_IO_SGR_GPI_BB                             X86IM_IO_GR_GPI+0x6     // bit and byte instructions
#define X86IM_IO_SGR_GPI_BRANCH                         X86IM_IO_GR_GPI+0x7     // control transfer instructions
#define X86IM_IO_SGR_GPI_STRING                         X86IM_IO_GR_GPI+0x8     // string instructions
#define X86IM_IO_SGR_GPI_IO                             X86IM_IO_GR_GPI+0x9     // i/o instructions
#define X86IM_IO_SGR_GPI_FCTL                           X86IM_IO_GR_GPI+0xA     // flag control instructions
#define X86IM_IO_SGR_GPI_SEGM                           X86IM_IO_GR_GPI+0xB     // segment instructions
#define X86IM_IO_SGR_GPI_STACK                          X86IM_IO_GR_GPI+0xC     // stack instructions
#define X86IM_IO_SGR_GPI_SYSTEM                         X86IM_IO_GR_GPI+0xD     // system/privileged instructions
#define X86IM_IO_SGR_GPI_MISC                           X86IM_IO_GR_GPI+0xE     // miscellaneous instructions
#define X86IM_IO_IS_IG_GPI(x)                           ( X86IM_IO_GET_GR(x) == X86IM_IO_GR_GPI )

#define X86IM_IO_GR_FPU                                 0x10                    // FPU sub groups:
#define X86IM_IO_SGR_FPU_TRANSF_FP                      X86IM_IO_GR_FPU+0x0     // data transfer instructions - floating point
#define X86IM_IO_SGR_FPU_TRANSF_I                       X86IM_IO_GR_FPU+0x1     // data transfer instructions - integer
#define X86IM_IO_SGR_FPU_TRANSF_PD                      X86IM_IO_GR_FPU+0x2     // data transfer instructions - packed decimal
#define X86IM_IO_SGR_FPU_ARITH                          X86IM_IO_GR_FPU+0x3     // basic arithmetic instructions
#define X86IM_IO_SGR_FPU_COCL                           X86IM_IO_GR_FPU+0x4     // comparison and classification instructions
#define X86IM_IO_SGR_FPU_TRIGO                          X86IM_IO_GR_FPU+0x5     // trigonometric instructions
#define X86IM_IO_SGR_FPU_LES                            X86IM_IO_GR_FPU+0x6     // logarithmic, exponential, scale instructions
#define X86IM_IO_SGR_FPU_LOADC                          X86IM_IO_GR_FPU+0x7     // load constant instructions
#define X86IM_IO_SGR_FPU_CTRL                           X86IM_IO_GR_FPU+0x8     // x87 FPU control instructions
#define X86IM_IO_IS_IG_FPU(x)                           ( X86IM_IO_GET_GR(x) == X86IM_IO_GR_FPU )

#define X86IM_IO_GR_MMX                                 0x20                    // MMX sub groups:
#define X86IM_IO_SGR_MMX_TRANSF                         X86IM_IO_GR_MMX+0x0     // data transfer instructions
#define X86IM_IO_SGR_MMX_CONV                           X86IM_IO_GR_MMX+0x1     // conversion instructions
#define X86IM_IO_SGR_MMX_PARITH                         X86IM_IO_GR_MMX+0x2     // packed arithmetic instructions
#define X86IM_IO_SGR_MMX_COMP                           X86IM_IO_GR_MMX+0x3     // comparison instructions
#define X86IM_IO_SGR_MMX_LOGIC                          X86IM_IO_GR_MMX+0x4     // logical instructions
#define X86IM_IO_SGR_MMX_SHIFT                          X86IM_IO_GR_MMX+0x5     // shift and rotate instructions
#define X86IM_IO_SGR_MMX_STATE                          X86IM_IO_GR_MMX+0x6     // state management instructions
#define X86IM_IO_IS_IG_MMX(x)                           ( X86IM_IO_GET_GR(x) == X86IM_IO_GR_MMX )

#define X86IM_IO_GR_3DNOW                               0x30
#define X86IM_IO_IS_IG_3DNOW(x)                         ( X86IM_IO_GET_GR(x) == X86IM_IO_GR_3DNOW )

#define X86IM_IO_GR_SSE                                 0x40                    // SSE sub groups:
#define X86IM_IO_SGR_SSE_TRANSF                         X86IM_IO_GR_SSE+0x0     // data transfer instructions
#define X86IM_IO_SGR_SSE_ARITH                          X86IM_IO_GR_SSE+0x1     // packed arithmetic instructions
#define X86IM_IO_SGR_SSE_COMP                           X86IM_IO_GR_SSE+0x2     // comparison instructions
#define X86IM_IO_SGR_SSE_LOGIC                          X86IM_IO_GR_SSE+0x3     // logical instructions
#define X86IM_IO_SGR_SSE_SHUFFLE                        X86IM_IO_GR_SSE+0x4     // shuffle instructions
#define X86IM_IO_SGR_SSE_UNPACK                         X86IM_IO_GR_SSE+0x5     // unpack instructions
#define X86IM_IO_SGR_SSE_CONV                           X86IM_IO_GR_SSE+0x6     // conversion instructions
#define X86IM_IO_SGR_SSE_STATE                          X86IM_IO_GR_SSE+0x7     // MXCSR state management instructions
#define X86IM_IO_SGR_SSE_MISC                           X86IM_IO_GR_SSE+0x8     // cacheability control, prefetch, and instruction ordering instructions
#define X86IM_IO_SGR_SSE_MMXEXT                         X86IM_IO_GR_SSE+0x9     // 64Bit SIMD integer instructions - MMX extension
#define X86IM_IO_IS_IG_SSE(x)                           ( X86IM_IO_GET_GR(x) == X86IM_IO_GR_SSE )

#define X86IM_IO_GR_SSE2                                0x50                    // SSE2 sub groups:
#define X86IM_IO_SGR_SSE2_TRANSF                        X86IM_IO_GR_SSE2+0x0    // data movement instructions
#define X86IM_IO_SGR_SSE2_ARITH                         X86IM_IO_GR_SSE2+0x1    // packed arithmetic instructions
#define X86IM_IO_SGR_SSE2_LOGIC                         X86IM_IO_GR_SSE2+0x2    // logical instructions
#define X86IM_IO_SGR_SSE2_COMP                          X86IM_IO_GR_SSE2+0x3    // compare instructions
#define X86IM_IO_SGR_SSE2_SHUFFLE                       X86IM_IO_GR_SSE2+0x4    // shuffle instructions
#define X86IM_IO_SGR_SSE2_UNPACK                        X86IM_IO_GR_SSE2+0x5    // unpack instructions
#define X86IM_IO_SGR_SSE2_CONV                          X86IM_IO_GR_SSE2+0x6    // conversion instructions
#define X86IM_IO_SGR_SSE2_SSEEXT                        X86IM_IO_GR_SSE2+0x7    // packed single-precision floating-point instructions - SSE extension
#define X86IM_IO_SGR_SSE2_MISC                          X86IM_IO_GR_SSE2+0x8    // cacheability control and ordering instructions
#define X86IM_IO_SGR_SSE2_MMXEXT                        X86IM_IO_GR_SSE2+0x9    //
#define X86IM_IO_IS_IG_SSE2(x)                          ( X86IM_IO_GET_GR(x) == X86IM_IO_GR_SSE2 )

#define X86IM_IO_GR_SSE3                                0x60
#define X86IM_IO_IS_IG_SSE3(x)                          ( X86IM_IO_GET_GR(x) == X86IM_IO_GR_SSE3 )

// instr mnemonics ( io.mnm )

#define X86IM_IO_IMNG_GPI                               0x0000

#define X86IM_IO_IMN_AAA                                X86IM_IO_IMNG_GPI+0
#define X86IM_IO_IMN_AAD                                X86IM_IO_IMNG_GPI+1
#define X86IM_IO_IMN_AAM                                X86IM_IO_IMNG_GPI+2
#define X86IM_IO_IMN_AAS                                X86IM_IO_IMNG_GPI+3
#define X86IM_IO_IMN_BOUND                              X86IM_IO_IMNG_GPI+4
#define X86IM_IO_IMN_BSWAP                              X86IM_IO_IMNG_GPI+5
#define X86IM_IO_IMN_CLC                                X86IM_IO_IMNG_GPI+6
#define X86IM_IO_IMN_CLD                                X86IM_IO_IMNG_GPI+7
#define X86IM_IO_IMN_CLI                                X86IM_IO_IMNG_GPI+8
#define X86IM_IO_IMN_CLTS                               X86IM_IO_IMNG_GPI+9
#define X86IM_IO_IMN_CMC                                X86IM_IO_IMNG_GPI+10
#define X86IM_IO_IMN_CMPS_                              X86IM_IO_IMNG_GPI+11
#define X86IM_IO_IMN_CPUID                              X86IM_IO_IMNG_GPI+12
#define X86IM_IO_IMN_DAA                                X86IM_IO_IMNG_GPI+13
#define X86IM_IO_IMN_DAS                                X86IM_IO_IMNG_GPI+14
#define X86IM_IO_IMN_HLT                                X86IM_IO_IMNG_GPI+15
#define X86IM_IO_IMN_INS_                               X86IM_IO_IMNG_GPI+16
#define X86IM_IO_IMN_INVD                               X86IM_IO_IMNG_GPI+17
#define X86IM_IO_IMN_INVLPG                             X86IM_IO_IMNG_GPI+18
#define X86IM_IO_IMN_IRET                               X86IM_IO_IMNG_GPI+19
#define X86IM_IO_IMN_JCXZ                               X86IM_IO_IMNG_GPI+20
#define X86IM_IO_IMN_LAHF                               X86IM_IO_IMNG_GPI+21
#define X86IM_IO_IMN_LDS                                X86IM_IO_IMNG_GPI+22
#define X86IM_IO_IMN_LEA                                X86IM_IO_IMNG_GPI+23
#define X86IM_IO_IMN_LEAVE                              X86IM_IO_IMNG_GPI+24
#define X86IM_IO_IMN_LES                                X86IM_IO_IMNG_GPI+25
#define X86IM_IO_IMN_LFS                                X86IM_IO_IMNG_GPI+26
#define X86IM_IO_IMN_LGDT                               X86IM_IO_IMNG_GPI+27
#define X86IM_IO_IMN_LGS                                X86IM_IO_IMNG_GPI+28
#define X86IM_IO_IMN_LIDT                               X86IM_IO_IMNG_GPI+29
#define X86IM_IO_IMN_LODS_                              X86IM_IO_IMNG_GPI+30
#define X86IM_IO_IMN_LSS                                X86IM_IO_IMNG_GPI+31
#define X86IM_IO_IMN_MOVS_                              X86IM_IO_IMNG_GPI+32
#define X86IM_IO_IMN_NOP                                X86IM_IO_IMNG_GPI+33
#define X86IM_IO_IMN_OUTS_                              X86IM_IO_IMNG_GPI+34
#define X86IM_IO_IMN_RDMSR                              X86IM_IO_IMNG_GPI+35
#define X86IM_IO_IMN_RDPMC                              X86IM_IO_IMNG_GPI+36
#define X86IM_IO_IMN_RDTSC                              X86IM_IO_IMNG_GPI+37
#define X86IM_IO_IMN_RSM                                X86IM_IO_IMNG_GPI+38
#define X86IM_IO_IMN_SAHF                               X86IM_IO_IMNG_GPI+39
#define X86IM_IO_IMN_SCAS_                              X86IM_IO_IMNG_GPI+40
#define X86IM_IO_IMN_SGDT                               X86IM_IO_IMNG_GPI+41
#define X86IM_IO_IMN_SIDT                               X86IM_IO_IMNG_GPI+42
#define X86IM_IO_IMN_STC                                X86IM_IO_IMNG_GPI+43
#define X86IM_IO_IMN_STD                                X86IM_IO_IMNG_GPI+44
#define X86IM_IO_IMN_STI                                X86IM_IO_IMNG_GPI+45
#define X86IM_IO_IMN_STOS_                              X86IM_IO_IMNG_GPI+46
#define X86IM_IO_IMN_UD2                                X86IM_IO_IMNG_GPI+47
#define X86IM_IO_IMN_WAIT                               X86IM_IO_IMNG_GPI+48
#define X86IM_IO_IMN_WBINVD                             X86IM_IO_IMNG_GPI+49
#define X86IM_IO_IMN_WRMSR                              X86IM_IO_IMNG_GPI+50
#define X86IM_IO_IMN_XLAT                               X86IM_IO_IMNG_GPI+51
#define X86IM_IO_IMN_CMPXCHGXX                          X86IM_IO_IMNG_GPI+52
#define X86IM_IO_IMN_ENTER                              X86IM_IO_IMNG_GPI+53
#define X86IM_IO_IMN_SYSENTER                           X86IM_IO_IMNG_GPI+54
#define X86IM_IO_IMN_SYSEXIT                            X86IM_IO_IMNG_GPI+55
#define X86IM_IO_IMN_CONVERT_A                          X86IM_IO_IMNG_GPI+56
#define X86IM_IO_IMN_CONVERT_B                          X86IM_IO_IMNG_GPI+57
#define X86IM_IO_IMN_INT                                X86IM_IO_IMNG_GPI+58
#define X86IM_IO_IMN_INT3                               X86IM_IO_IMNG_GPI+59
#define X86IM_IO_IMN_INTO                               X86IM_IO_IMNG_GPI+60
#define X86IM_IO_IMN_LOOP                               X86IM_IO_IMNG_GPI+61
#define X86IM_IO_IMN_LOOPE                              X86IM_IO_IMNG_GPI+62
#define X86IM_IO_IMN_LOOPNE                             X86IM_IO_IMNG_GPI+63
#define X86IM_IO_IMN_ADC                                X86IM_IO_IMNG_GPI+64
#define X86IM_IO_IMN_ADD                                X86IM_IO_IMNG_GPI+65
#define X86IM_IO_IMN_AND                                X86IM_IO_IMNG_GPI+66
#define X86IM_IO_IMN_ARPL                               X86IM_IO_IMNG_GPI+67
#define X86IM_IO_IMN_MOVSXD                             X86IM_IO_IMNG_GPI+68  // =ARPL
#define X86IM_IO_IMN_BSF                                X86IM_IO_IMNG_GPI+69
#define X86IM_IO_IMN_BSR                                X86IM_IO_IMNG_GPI+70
#define X86IM_IO_IMN_BT                                 X86IM_IO_IMNG_GPI+71
#define X86IM_IO_IMN_BTC                                X86IM_IO_IMNG_GPI+72
#define X86IM_IO_IMN_BTR                                X86IM_IO_IMNG_GPI+73
#define X86IM_IO_IMN_BTS                                X86IM_IO_IMNG_GPI+74
#define X86IM_IO_IMN_CALL                               X86IM_IO_IMNG_GPI+75
#define X86IM_IO_IMN_CALL_FAR                           X86IM_IO_IMNG_GPI+76
#define X86IM_IO_IMN_CMP                                X86IM_IO_IMNG_GPI+77
#define X86IM_IO_IMN_CMPXCHG                            X86IM_IO_IMNG_GPI+78
#define X86IM_IO_IMN_DEC                                X86IM_IO_IMNG_GPI+79
#define X86IM_IO_IMN_DIV                                X86IM_IO_IMNG_GPI+80
#define X86IM_IO_IMN_IDIV                               X86IM_IO_IMNG_GPI+81
#define X86IM_IO_IMN_IMUL                               X86IM_IO_IMNG_GPI+82
#define X86IM_IO_IMN_IN                                 X86IM_IO_IMNG_GPI+83
#define X86IM_IO_IMN_INC                                X86IM_IO_IMNG_GPI+84
#define X86IM_IO_IMN_JCC_SHORT                          X86IM_IO_IMNG_GPI+85
#define X86IM_IO_IMN_JCC                                X86IM_IO_IMNG_GPI+86
#define X86IM_IO_IMN_JMP_SHORT                          X86IM_IO_IMNG_GPI+87
#define X86IM_IO_IMN_JMP                                X86IM_IO_IMNG_GPI+88
#define X86IM_IO_IMN_JMP_FAR                            X86IM_IO_IMNG_GPI+89
#define X86IM_IO_IMN_LAR                                X86IM_IO_IMNG_GPI+90
#define X86IM_IO_IMN_LLDT                               X86IM_IO_IMNG_GPI+91
#define X86IM_IO_IMN_LMSW                               X86IM_IO_IMNG_GPI+92
#define X86IM_IO_IMN_LSL                                X86IM_IO_IMNG_GPI+93
#define X86IM_IO_IMN_LTR                                X86IM_IO_IMNG_GPI+94
#define X86IM_IO_IMN_MOV                                X86IM_IO_IMNG_GPI+95
#define X86IM_IO_IMN_MOVSX                              X86IM_IO_IMNG_GPI+96
#define X86IM_IO_IMN_MOVZX                              X86IM_IO_IMNG_GPI+97
#define X86IM_IO_IMN_MUL                                X86IM_IO_IMNG_GPI+98
#define X86IM_IO_IMN_NEG                                X86IM_IO_IMNG_GPI+99
#define X86IM_IO_IMN_NOT                                X86IM_IO_IMNG_GPI+100
#define X86IM_IO_IMN_OR                                 X86IM_IO_IMNG_GPI+101
#define X86IM_IO_IMN_OUT                                X86IM_IO_IMNG_GPI+102
#define X86IM_IO_IMN_POP                                X86IM_IO_IMNG_GPI+103
#define X86IM_IO_IMN_POPAD                              X86IM_IO_IMNG_GPI+104
#define X86IM_IO_IMN_POPF                               X86IM_IO_IMNG_GPI+105
#define X86IM_IO_IMN_PUSH                               X86IM_IO_IMNG_GPI+106
#define X86IM_IO_IMN_PUSHAD                             X86IM_IO_IMNG_GPI+107
#define X86IM_IO_IMN_PUSHF                              X86IM_IO_IMNG_GPI+108
#define X86IM_IO_IMN_RCL                                X86IM_IO_IMNG_GPI+109
#define X86IM_IO_IMN_RCR                                X86IM_IO_IMNG_GPI+110
#define X86IM_IO_IMN_RET_NEAR                           X86IM_IO_IMNG_GPI+111
#define X86IM_IO_IMN_RET_FAR                            X86IM_IO_IMNG_GPI+112
#define X86IM_IO_IMN_ROL                                X86IM_IO_IMNG_GPI+113
#define X86IM_IO_IMN_ROR                                X86IM_IO_IMNG_GPI+114
#define X86IM_IO_IMN_SAR                                X86IM_IO_IMNG_GPI+115 // =SAL
#define X86IM_IO_IMN_SBB                                X86IM_IO_IMNG_GPI+116
#define X86IM_IO_IMN_SETCC                              X86IM_IO_IMNG_GPI+117
#define X86IM_IO_IMN_SHL                                X86IM_IO_IMNG_GPI+118
#define X86IM_IO_IMN_SHLD                               X86IM_IO_IMNG_GPI+119
#define X86IM_IO_IMN_SHR                                X86IM_IO_IMNG_GPI+120
#define X86IM_IO_IMN_SHRD                               X86IM_IO_IMNG_GPI+121
#define X86IM_IO_IMN_SLDT                               X86IM_IO_IMNG_GPI+122
#define X86IM_IO_IMN_SMSW                               X86IM_IO_IMNG_GPI+123
#define X86IM_IO_IMN_STR                                X86IM_IO_IMNG_GPI+124
#define X86IM_IO_IMN_SUB                                X86IM_IO_IMNG_GPI+125
#define X86IM_IO_IMN_TEST                               X86IM_IO_IMNG_GPI+126
#define X86IM_IO_IMN_VERR                               X86IM_IO_IMNG_GPI+127
#define X86IM_IO_IMN_VERW                               X86IM_IO_IMNG_GPI+128
#define X86IM_IO_IMN_XADD                               X86IM_IO_IMNG_GPI+129
#define X86IM_IO_IMN_XCHG                               X86IM_IO_IMNG_GPI+130
#define X86IM_IO_IMN_XOR                                X86IM_IO_IMNG_GPI+131
#define X86IM_IO_IMN_CMOVCC                             X86IM_IO_IMNG_GPI+132
#define X86IM_IO_IMN_SYSCALL                            X86IM_IO_IMNG_GPI+133
#define X86IM_IO_IMN_SYSRET                             X86IM_IO_IMNG_GPI+134
#define X86IM_IO_IMN_SWAPGS                             X86IM_IO_IMNG_GPI+135
#define X86IM_IO_IMN_SAL                                X86IM_IO_IMNG_GPI+136

#define X86IM_IO_IMNG_FPU                               0x0100

#define X86IM_IO_IMN_F2XM1                              X86IM_IO_IMNG_FPU+0
#define X86IM_IO_IMN_FABS                               X86IM_IO_IMNG_FPU+1
#define X86IM_IO_IMN_FBLD                               X86IM_IO_IMNG_FPU+2
#define X86IM_IO_IMN_FBSTP                              X86IM_IO_IMNG_FPU+3
#define X86IM_IO_IMN_FCHS                               X86IM_IO_IMNG_FPU+4
#define X86IM_IO_IMN_FNCLEX                             X86IM_IO_IMNG_FPU+5
#define X86IM_IO_IMN_FCOMPP                             X86IM_IO_IMNG_FPU+6
#define X86IM_IO_IMN_FCOMIP                             X86IM_IO_IMNG_FPU+7
#define X86IM_IO_IMN_FCOS                               X86IM_IO_IMNG_FPU+8
#define X86IM_IO_IMN_FDECSTP                            X86IM_IO_IMNG_FPU+9
#define X86IM_IO_IMN_FFREE                              X86IM_IO_IMNG_FPU+10
#define X86IM_IO_IMN_FINCSTP                            X86IM_IO_IMNG_FPU+11
#define X86IM_IO_IMN_FNINIT                             X86IM_IO_IMNG_FPU+12
#define X86IM_IO_IMN_FLD1                               X86IM_IO_IMNG_FPU+13
#define X86IM_IO_IMN_FLDCW                              X86IM_IO_IMNG_FPU+14
#define X86IM_IO_IMN_FLDENV                             X86IM_IO_IMNG_FPU+15
#define X86IM_IO_IMN_FLDL2E                             X86IM_IO_IMNG_FPU+16
#define X86IM_IO_IMN_FLDL2T                             X86IM_IO_IMNG_FPU+17
#define X86IM_IO_IMN_FLDLG2                             X86IM_IO_IMNG_FPU+18
#define X86IM_IO_IMN_FLDLN2                             X86IM_IO_IMNG_FPU+19
#define X86IM_IO_IMN_FLDPI                              X86IM_IO_IMNG_FPU+20
#define X86IM_IO_IMN_FLDZ                               X86IM_IO_IMNG_FPU+21
#define X86IM_IO_IMN_FNOP                               X86IM_IO_IMNG_FPU+22
#define X86IM_IO_IMN_FPATAN                             X86IM_IO_IMNG_FPU+23
#define X86IM_IO_IMN_FPREM                              X86IM_IO_IMNG_FPU+24
#define X86IM_IO_IMN_FPREM1                             X86IM_IO_IMNG_FPU+25
#define X86IM_IO_IMN_FPTAN                              X86IM_IO_IMNG_FPU+26
#define X86IM_IO_IMN_FRNDINT                            X86IM_IO_IMNG_FPU+27
#define X86IM_IO_IMN_FRSTOR                             X86IM_IO_IMNG_FPU+28
#define X86IM_IO_IMN_FNSAVE                             X86IM_IO_IMNG_FPU+29
#define X86IM_IO_IMN_FSCALE                             X86IM_IO_IMNG_FPU+30
#define X86IM_IO_IMN_FSIN                               X86IM_IO_IMNG_FPU+31
#define X86IM_IO_IMN_FSINCOS                            X86IM_IO_IMNG_FPU+32
#define X86IM_IO_IMN_FSQRT                              X86IM_IO_IMNG_FPU+33
#define X86IM_IO_IMN_FNSTCW                             X86IM_IO_IMNG_FPU+34
#define X86IM_IO_IMN_FNSTENV                            X86IM_IO_IMNG_FPU+35
#define X86IM_IO_IMN_FTST                               X86IM_IO_IMNG_FPU+36
#define X86IM_IO_IMN_FUCOM                              X86IM_IO_IMNG_FPU+37
#define X86IM_IO_IMN_FUCOMP                             X86IM_IO_IMNG_FPU+38
#define X86IM_IO_IMN_FUCOMPP                            X86IM_IO_IMNG_FPU+39
#define X86IM_IO_IMN_FUCOMI                             X86IM_IO_IMNG_FPU+40
#define X86IM_IO_IMN_FUCOMIP                            X86IM_IO_IMNG_FPU+41
#define X86IM_IO_IMN_FXAM                               X86IM_IO_IMNG_FPU+42
#define X86IM_IO_IMN_FXCH                               X86IM_IO_IMNG_FPU+43
#define X86IM_IO_IMN_FXTRACT                            X86IM_IO_IMNG_FPU+44
#define X86IM_IO_IMN_FYL2X                              X86IM_IO_IMNG_FPU+45
#define X86IM_IO_IMN_FYL2XP1                            X86IM_IO_IMNG_FPU+46
#define X86IM_IO_IMN_FADDP                              X86IM_IO_IMNG_FPU+47
#define X86IM_IO_IMN_FDIVP                              X86IM_IO_IMNG_FPU+48
#define X86IM_IO_IMN_FDIVRP                             X86IM_IO_IMNG_FPU+49
#define X86IM_IO_IMN_FMULP                              X86IM_IO_IMNG_FPU+50
#define X86IM_IO_IMN_FSUBP                              X86IM_IO_IMNG_FPU+51
#define X86IM_IO_IMN_FSUBRP                             X86IM_IO_IMNG_FPU+52
#define X86IM_IO_IMN_FCOMI                              X86IM_IO_IMNG_FPU+53
#define X86IM_IO_IMN_FADD                               X86IM_IO_IMNG_FPU+54
#define X86IM_IO_IMN_FCOM                               X86IM_IO_IMNG_FPU+55
#define X86IM_IO_IMN_FCOMP                              X86IM_IO_IMNG_FPU+56
#define X86IM_IO_IMN_FDIV                               X86IM_IO_IMNG_FPU+57
#define X86IM_IO_IMN_FDIVR                              X86IM_IO_IMNG_FPU+58
#define X86IM_IO_IMN_FIADD                              X86IM_IO_IMNG_FPU+59
#define X86IM_IO_IMN_FICOM                              X86IM_IO_IMNG_FPU+60
#define X86IM_IO_IMN_FICOMP                             X86IM_IO_IMNG_FPU+61
#define X86IM_IO_IMN_FIDIV                              X86IM_IO_IMNG_FPU+62
#define X86IM_IO_IMN_FIDIVR                             X86IM_IO_IMNG_FPU+63
#define X86IM_IO_IMN_FILD                               X86IM_IO_IMNG_FPU+64
#define X86IM_IO_IMN_FIMUL                              X86IM_IO_IMNG_FPU+65
#define X86IM_IO_IMN_FIST                               X86IM_IO_IMNG_FPU+66
#define X86IM_IO_IMN_FISTP                              X86IM_IO_IMNG_FPU+67
#define X86IM_IO_IMN_FISUB                              X86IM_IO_IMNG_FPU+68
#define X86IM_IO_IMN_FISUBR                             X86IM_IO_IMNG_FPU+69
#define X86IM_IO_IMN_FLD                                X86IM_IO_IMNG_FPU+70
#define X86IM_IO_IMN_FMUL                               X86IM_IO_IMNG_FPU+71
#define X86IM_IO_IMN_FST                                X86IM_IO_IMNG_FPU+72
#define X86IM_IO_IMN_FSTP                               X86IM_IO_IMNG_FPU+73
#define X86IM_IO_IMN_FNSTSW                             X86IM_IO_IMNG_FPU+74
#define X86IM_IO_IMN_FSUB                               X86IM_IO_IMNG_FPU+75
#define X86IM_IO_IMN_FSUBR                              X86IM_IO_IMNG_FPU+76
#define X86IM_IO_IMN_FCMOVB                             X86IM_IO_IMNG_FPU+77
#define X86IM_IO_IMN_FCMOVE                             X86IM_IO_IMNG_FPU+78
#define X86IM_IO_IMN_FCMOVBE                            X86IM_IO_IMNG_FPU+79
#define X86IM_IO_IMN_FCMOVU                             X86IM_IO_IMNG_FPU+80
#define X86IM_IO_IMN_FCMOVNB                            X86IM_IO_IMNG_FPU+81
#define X86IM_IO_IMN_FCMOVNE                            X86IM_IO_IMNG_FPU+82
#define X86IM_IO_IMN_FCMOVNBE                           X86IM_IO_IMNG_FPU+83
#define X86IM_IO_IMN_FCMOVNU                            X86IM_IO_IMNG_FPU+84
#define X86IM_IO_IMN_FXSAVE                             X86IM_IO_IMNG_FPU+85
#define X86IM_IO_IMN_FXRSTOR                            X86IM_IO_IMNG_FPU+86
#define X86IM_IO_IMN_FCOM2                              X86IM_IO_IMNG_FPU+87
#define X86IM_IO_IMN_FCOMP3                             X86IM_IO_IMNG_FPU+88
#define X86IM_IO_IMN_FCOMP5                             X86IM_IO_IMNG_FPU+89
#define X86IM_IO_IMN_FXCH4                              X86IM_IO_IMNG_FPU+90
#define X86IM_IO_IMN_FXCH7                              X86IM_IO_IMNG_FPU+91
#define X86IM_IO_IMN_FSTP1                              X86IM_IO_IMNG_FPU+92
#define X86IM_IO_IMN_FSTP8                              X86IM_IO_IMNG_FPU+93
#define X86IM_IO_IMN_FSTP9                              X86IM_IO_IMNG_FPU+94
#define X86IM_IO_IMN_FFREEP                             X86IM_IO_IMNG_FPU+95

#define X86IM_IO_IMNG_MMX                               0x0200

#define X86IM_IO_IMN_EMMS                               X86IM_IO_IMNG_MMX+0
#define X86IM_IO_IMN_MOVD                               X86IM_IO_IMNG_MMX+1
#define X86IM_IO_IMN_MOVQ                               X86IM_IO_IMNG_MMX+2
#define X86IM_IO_IMN_PACKSSDW                           X86IM_IO_IMNG_MMX+3
#define X86IM_IO_IMN_PACKSSWB                           X86IM_IO_IMNG_MMX+4
#define X86IM_IO_IMN_PACKUSWB                           X86IM_IO_IMNG_MMX+5
#define X86IM_IO_IMN_PADD                               X86IM_IO_IMNG_MMX+6
#define X86IM_IO_IMN_PADDS                              X86IM_IO_IMNG_MMX+7
#define X86IM_IO_IMN_PADDUS                             X86IM_IO_IMNG_MMX+8
#define X86IM_IO_IMN_PAND                               X86IM_IO_IMNG_MMX+9
#define X86IM_IO_IMN_PANDN                              X86IM_IO_IMNG_MMX+10
#define X86IM_IO_IMN_PCMPEQ                             X86IM_IO_IMNG_MMX+11
#define X86IM_IO_IMN_PCMPGT                             X86IM_IO_IMNG_MMX+12
#define X86IM_IO_IMN_PMADDWD                            X86IM_IO_IMNG_MMX+13
#define X86IM_IO_IMN_PMULHW                             X86IM_IO_IMNG_MMX+14
#define X86IM_IO_IMN_PMULLW                             X86IM_IO_IMNG_MMX+15
#define X86IM_IO_IMN_POR                                X86IM_IO_IMNG_MMX+16
#define X86IM_IO_IMN_PSLLW                              X86IM_IO_IMNG_MMX+17
#define X86IM_IO_IMN_PSLLD                              X86IM_IO_IMNG_MMX+18
#define X86IM_IO_IMN_PSLLQ                              X86IM_IO_IMNG_MMX+19
#define X86IM_IO_IMN_PSRAW                              X86IM_IO_IMNG_MMX+20
#define X86IM_IO_IMN_PSRAD                              X86IM_IO_IMNG_MMX+21
#define X86IM_IO_IMN_PSRLW                              X86IM_IO_IMNG_MMX+22
#define X86IM_IO_IMN_PSRLD                              X86IM_IO_IMNG_MMX+23
#define X86IM_IO_IMN_PSRLQ                              X86IM_IO_IMNG_MMX+24
#define X86IM_IO_IMN_PSUB                               X86IM_IO_IMNG_MMX+25
#define X86IM_IO_IMN_PSUBS                              X86IM_IO_IMNG_MMX+26
#define X86IM_IO_IMN_PSUBUS                             X86IM_IO_IMNG_MMX+27
#define X86IM_IO_IMN_PUNPCKH                            X86IM_IO_IMNG_MMX+28
#define X86IM_IO_IMN_PUNPCKL                            X86IM_IO_IMNG_MMX+29
#define X86IM_IO_IMN_PXOR                               X86IM_IO_IMNG_MMX+30

#define X86IM_IO_IMNG_3DN                               0x0300

#define X86IM_IO_IMN_PI2FW                              X86IM_IO_IMNG_3DN+0
#define X86IM_IO_IMN_PI2FD                              X86IM_IO_IMNG_3DN+1
#define X86IM_IO_IMN_PF2IW                              X86IM_IO_IMNG_3DN+2
#define X86IM_IO_IMN_PF2ID                              X86IM_IO_IMNG_3DN+3
#define X86IM_IO_IMN_PFNACC                             X86IM_IO_IMNG_3DN+4
#define X86IM_IO_IMN_PFPNACC                            X86IM_IO_IMNG_3DN+5
#define X86IM_IO_IMN_PFCMPGE                            X86IM_IO_IMNG_3DN+6
#define X86IM_IO_IMN_PFMIN                              X86IM_IO_IMNG_3DN+7
#define X86IM_IO_IMN_PFRCP                              X86IM_IO_IMNG_3DN+8
#define X86IM_IO_IMN_PFRSQRT                            X86IM_IO_IMNG_3DN+9
#define X86IM_IO_IMN_PFSUB                              X86IM_IO_IMNG_3DN+10
#define X86IM_IO_IMN_PFADD                              X86IM_IO_IMNG_3DN+11
#define X86IM_IO_IMN_PFCMPGT                            X86IM_IO_IMNG_3DN+12
#define X86IM_IO_IMN_PFMAX                              X86IM_IO_IMNG_3DN+13
#define X86IM_IO_IMN_PFRCPIT1                           X86IM_IO_IMNG_3DN+14
#define X86IM_IO_IMN_PFRSQIT1                           X86IM_IO_IMNG_3DN+15
#define X86IM_IO_IMN_PFSUBR                             X86IM_IO_IMNG_3DN+16
#define X86IM_IO_IMN_PFACC                              X86IM_IO_IMNG_3DN+17
#define X86IM_IO_IMN_PFCMPEQ                            X86IM_IO_IMNG_3DN+18
#define X86IM_IO_IMN_PFMUL                              X86IM_IO_IMNG_3DN+19
#define X86IM_IO_IMN_PFRCPIT2                           X86IM_IO_IMNG_3DN+20
#define X86IM_IO_IMN_PMULHRW                            X86IM_IO_IMNG_3DN+21
#define X86IM_IO_IMN_PSWAPD                             X86IM_IO_IMNG_3DN+22
#define X86IM_IO_IMN_PAVGUSB                            X86IM_IO_IMNG_3DN+23

#define X86IM_IO_IMNG_SSE                               0x0400

#define X86IM_IO_IMN_MOVMSKPS                           X86IM_IO_IMNG_SSE+0
#define X86IM_IO_IMN_LDMXCSR                            X86IM_IO_IMNG_SSE+1
#define X86IM_IO_IMN_STMXCSR                            X86IM_IO_IMNG_SSE+2
#define X86IM_IO_IMN_MASKMOVQ                           X86IM_IO_IMNG_SSE+3
#define X86IM_IO_IMN_MOVNTPS                            X86IM_IO_IMNG_SSE+4
#define X86IM_IO_IMN_MOVNTQ                             X86IM_IO_IMNG_SSE+5
#define X86IM_IO_IMN_PREFETCH                           X86IM_IO_IMNG_SSE+6
#define X86IM_IO_IMN_SFENCE                             X86IM_IO_IMNG_SSE+7
#define X86IM_IO_IMN_ADDPS                              X86IM_IO_IMNG_SSE+8
#define X86IM_IO_IMN_ADDSS                              X86IM_IO_IMNG_SSE+9
#define X86IM_IO_IMN_ANDNPS                             X86IM_IO_IMNG_SSE+10
#define X86IM_IO_IMN_ANDPS                              X86IM_IO_IMNG_SSE+11
#define X86IM_IO_IMN_CMPPS                              X86IM_IO_IMNG_SSE+12
#define X86IM_IO_IMN_CMPSS                              X86IM_IO_IMNG_SSE+13
#define X86IM_IO_IMN_COMISS                             X86IM_IO_IMNG_SSE+14
#define X86IM_IO_IMN_CVTPI2PS                           X86IM_IO_IMNG_SSE+15
#define X86IM_IO_IMN_CVTPS2PI                           X86IM_IO_IMNG_SSE+16
#define X86IM_IO_IMN_CVTSI2SS                           X86IM_IO_IMNG_SSE+17
#define X86IM_IO_IMN_CVTSS2SI                           X86IM_IO_IMNG_SSE+18
#define X86IM_IO_IMN_CVTTPS2PI                          X86IM_IO_IMNG_SSE+19
#define X86IM_IO_IMN_CVTTSS2SI                          X86IM_IO_IMNG_SSE+20
#define X86IM_IO_IMN_DIVPS                              X86IM_IO_IMNG_SSE+21
#define X86IM_IO_IMN_DIVSS                              X86IM_IO_IMNG_SSE+22
#define X86IM_IO_IMN_MAXPS                              X86IM_IO_IMNG_SSE+23
#define X86IM_IO_IMN_MAXSS                              X86IM_IO_IMNG_SSE+24
#define X86IM_IO_IMN_MINPS                              X86IM_IO_IMNG_SSE+25
#define X86IM_IO_IMN_MINSS                              X86IM_IO_IMNG_SSE+26
#define X86IM_IO_IMN_MOVAPS                             X86IM_IO_IMNG_SSE+27
#define X86IM_IO_IMN_MOVLHPS                            X86IM_IO_IMNG_SSE+28
#define X86IM_IO_IMN_MOVHPS                             X86IM_IO_IMNG_SSE+29
#define X86IM_IO_IMN_MOVHLPS                            X86IM_IO_IMNG_SSE+30
#define X86IM_IO_IMN_MOVLPS                             X86IM_IO_IMNG_SSE+31
#define X86IM_IO_IMN_MOVSS                              X86IM_IO_IMNG_SSE+32
#define X86IM_IO_IMN_MOVUPS                             X86IM_IO_IMNG_SSE+33
#define X86IM_IO_IMN_MULPS                              X86IM_IO_IMNG_SSE+34
#define X86IM_IO_IMN_MULSS                              X86IM_IO_IMNG_SSE+35
#define X86IM_IO_IMN_ORPS                               X86IM_IO_IMNG_SSE+36
#define X86IM_IO_IMN_RCPPS                              X86IM_IO_IMNG_SSE+37
#define X86IM_IO_IMN_RCPSS                              X86IM_IO_IMNG_SSE+38
#define X86IM_IO_IMN_RSQRTPS                            X86IM_IO_IMNG_SSE+39
#define X86IM_IO_IMN_RSQRTSS                            X86IM_IO_IMNG_SSE+40
#define X86IM_IO_IMN_SHUFPS                             X86IM_IO_IMNG_SSE+41
#define X86IM_IO_IMN_SQRTPS                             X86IM_IO_IMNG_SSE+42
#define X86IM_IO_IMN_SQRTSS                             X86IM_IO_IMNG_SSE+43
#define X86IM_IO_IMN_SUBPS                              X86IM_IO_IMNG_SSE+44
#define X86IM_IO_IMN_SUBSS                              X86IM_IO_IMNG_SSE+45
#define X86IM_IO_IMN_UCOMISS                            X86IM_IO_IMNG_SSE+46
#define X86IM_IO_IMN_UNPCKHPS                           X86IM_IO_IMNG_SSE+47
#define X86IM_IO_IMN_UNPCKLPS                           X86IM_IO_IMNG_SSE+48
#define X86IM_IO_IMN_XORPS                              X86IM_IO_IMNG_SSE+49
#define X86IM_IO_IMN_PEXTRW                             X86IM_IO_IMNG_SSE+50
#define X86IM_IO_IMN_PMOVMSKB                           X86IM_IO_IMNG_SSE+51
#define X86IM_IO_IMN_PAVGB                              X86IM_IO_IMNG_SSE+52
#define X86IM_IO_IMN_PAVGW                              X86IM_IO_IMNG_SSE+53
#define X86IM_IO_IMN_PINSRW                             X86IM_IO_IMNG_SSE+54
#define X86IM_IO_IMN_PMAXSW                             X86IM_IO_IMNG_SSE+55
#define X86IM_IO_IMN_PMAXUB                             X86IM_IO_IMNG_SSE+56
#define X86IM_IO_IMN_PMINSW                             X86IM_IO_IMNG_SSE+57
#define X86IM_IO_IMN_PMINUB                             X86IM_IO_IMNG_SSE+58
#define X86IM_IO_IMN_PMULHUW                            X86IM_IO_IMNG_SSE+59
#define X86IM_IO_IMN_PSADBW                             X86IM_IO_IMNG_SSE+60
#define X86IM_IO_IMN_PSHUFW                             X86IM_IO_IMNG_SSE+61

#define X86IM_IO_IMNG_SSE2                              0x0500

#define X86IM_IO_IMN_MOVMSKPD                           X86IM_IO_IMNG_SSE2+0
#define X86IM_IO_IMN_MASKMOVDQU                         X86IM_IO_IMNG_SSE2+1
#define X86IM_IO_IMN_CLFLUSH                            X86IM_IO_IMNG_SSE2+2
#define X86IM_IO_IMN_MOVNTPD                            X86IM_IO_IMNG_SSE2+3
#define X86IM_IO_IMN_MOVNTDQ                            X86IM_IO_IMNG_SSE2+4
#define X86IM_IO_IMN_MOVNTI                             X86IM_IO_IMNG_SSE2+5
#define X86IM_IO_IMN_PAUSE                              X86IM_IO_IMNG_SSE2+6
#define X86IM_IO_IMN_LFENCE                             X86IM_IO_IMNG_SSE2+7
#define X86IM_IO_IMN_MFENCE                             X86IM_IO_IMNG_SSE2+8
#define X86IM_IO_IMN_ADDPD                              X86IM_IO_IMNG_SSE2+9
#define X86IM_IO_IMN_ADDSD                              X86IM_IO_IMNG_SSE2+10
#define X86IM_IO_IMN_ANDNPD                             X86IM_IO_IMNG_SSE2+11
#define X86IM_IO_IMN_ANDPD                              X86IM_IO_IMNG_SSE2+12
#define X86IM_IO_IMN_CMPPD                              X86IM_IO_IMNG_SSE2+13
#define X86IM_IO_IMN_CMPSD                              X86IM_IO_IMNG_SSE2+14
#define X86IM_IO_IMN_COMISD                             X86IM_IO_IMNG_SSE2+15
#define X86IM_IO_IMN_CVTPI2PD                           X86IM_IO_IMNG_SSE2+16
#define X86IM_IO_IMN_CVTPD2PI                           X86IM_IO_IMNG_SSE2+17
#define X86IM_IO_IMN_CVTSI2SD                           X86IM_IO_IMNG_SSE2+18
#define X86IM_IO_IMN_CVTSD2SI                           X86IM_IO_IMNG_SSE2+19
#define X86IM_IO_IMN_CVTTPD2PI                          X86IM_IO_IMNG_SSE2+20
#define X86IM_IO_IMN_CVTTSD2SI                          X86IM_IO_IMNG_SSE2+21
#define X86IM_IO_IMN_CVTPD2PS                           X86IM_IO_IMNG_SSE2+22
#define X86IM_IO_IMN_CVTPS2PD                           X86IM_IO_IMNG_SSE2+23
#define X86IM_IO_IMN_CVTSD2SS                           X86IM_IO_IMNG_SSE2+24
#define X86IM_IO_IMN_CVTSS2SD                           X86IM_IO_IMNG_SSE2+25
#define X86IM_IO_IMN_CVTPD2DQ                           X86IM_IO_IMNG_SSE2+26
#define X86IM_IO_IMN_CVTTPD2DQ                          X86IM_IO_IMNG_SSE2+27
#define X86IM_IO_IMN_CVTDQ2PD                           X86IM_IO_IMNG_SSE2+28
#define X86IM_IO_IMN_CVTPS2DQ                           X86IM_IO_IMNG_SSE2+29
#define X86IM_IO_IMN_CVTTPS2DQ                          X86IM_IO_IMNG_SSE2+30
#define X86IM_IO_IMN_CVTDQ2PS                           X86IM_IO_IMNG_SSE2+31
#define X86IM_IO_IMN_DIVPD                              X86IM_IO_IMNG_SSE2+32
#define X86IM_IO_IMN_DIVSD                              X86IM_IO_IMNG_SSE2+33
#define X86IM_IO_IMN_MAXPD                              X86IM_IO_IMNG_SSE2+34
#define X86IM_IO_IMN_MAXSD                              X86IM_IO_IMNG_SSE2+35
#define X86IM_IO_IMN_MINPD                              X86IM_IO_IMNG_SSE2+36
#define X86IM_IO_IMN_MINSD                              X86IM_IO_IMNG_SSE2+37
#define X86IM_IO_IMN_MOVAPD                             X86IM_IO_IMNG_SSE2+38
#define X86IM_IO_IMN_MOVHPD                             X86IM_IO_IMNG_SSE2+39
#define X86IM_IO_IMN_MOVLPD                             X86IM_IO_IMNG_SSE2+40
#define X86IM_IO_IMN_MOVSD                              X86IM_IO_IMNG_SSE2+41
#define X86IM_IO_IMN_MOVUPD                             X86IM_IO_IMNG_SSE2+42
#define X86IM_IO_IMN_MULPD                              X86IM_IO_IMNG_SSE2+43
#define X86IM_IO_IMN_MULSD                              X86IM_IO_IMNG_SSE2+44
#define X86IM_IO_IMN_ORPD                               X86IM_IO_IMNG_SSE2+45
#define X86IM_IO_IMN_SHUFPD                             X86IM_IO_IMNG_SSE2+46
#define X86IM_IO_IMN_SQRTPD                             X86IM_IO_IMNG_SSE2+47
#define X86IM_IO_IMN_SQRTSD                             X86IM_IO_IMNG_SSE2+48
#define X86IM_IO_IMN_SUBPD                              X86IM_IO_IMNG_SSE2+49
#define X86IM_IO_IMN_SUBSD                              X86IM_IO_IMNG_SSE2+50
#define X86IM_IO_IMN_UCOMISD                            X86IM_IO_IMNG_SSE2+51
#define X86IM_IO_IMN_UNPCKHPD                           X86IM_IO_IMNG_SSE2+52
#define X86IM_IO_IMN_UNPCKLPD                           X86IM_IO_IMNG_SSE2+53
#define X86IM_IO_IMN_XORPD                              X86IM_IO_IMNG_SSE2+54
#define X86IM_IO_IMN_MOVQ2DQ                            X86IM_IO_IMNG_SSE2+55
#define X86IM_IO_IMN_MOVDQ2Q                            X86IM_IO_IMNG_SSE2+56
#define X86IM_IO_IMN_PSLLDQ                             X86IM_IO_IMNG_SSE2+57
#define X86IM_IO_IMN_PSRLDQ                             X86IM_IO_IMNG_SSE2+58
#define X86IM_IO_IMN_MOVDQA                             X86IM_IO_IMNG_SSE2+59
#define X86IM_IO_IMN_MOVDQU                             X86IM_IO_IMNG_SSE2+60
#define X86IM_IO_IMN_PADDQ                              X86IM_IO_IMNG_SSE2+61
#define X86IM_IO_IMN_PMULUDQ                            X86IM_IO_IMNG_SSE2+62
#define X86IM_IO_IMN_PSHUFLW                            X86IM_IO_IMNG_SSE2+63
#define X86IM_IO_IMN_PSHUFHW                            X86IM_IO_IMNG_SSE2+64
#define X86IM_IO_IMN_PSHUFD                             X86IM_IO_IMNG_SSE2+65
#define X86IM_IO_IMN_PSUBQ                              X86IM_IO_IMNG_SSE2+66
#define X86IM_IO_IMN_PUNPCKHQDQ                         X86IM_IO_IMNG_SSE2+67
#define X86IM_IO_IMN_PUNPCKLQDQ                         X86IM_IO_IMNG_SSE2+68

#define X86IM_IO_IMNG_SSE3                              0x0600

#define X86IM_IO_IMN_MONITOR                            X86IM_IO_IMNG_SSE3+0
#define X86IM_IO_IMN_MWAIT                              X86IM_IO_IMNG_SSE3+1
#define X86IM_IO_IMN_LDDQU                              X86IM_IO_IMNG_SSE3+2
#define X86IM_IO_IMN_ADDSUBPD                           X86IM_IO_IMNG_SSE3+3
#define X86IM_IO_IMN_ADDSUBPS                           X86IM_IO_IMNG_SSE3+4
#define X86IM_IO_IMN_HADDPD                             X86IM_IO_IMNG_SSE3+5
#define X86IM_IO_IMN_HADDPS                             X86IM_IO_IMNG_SSE3+6
#define X86IM_IO_IMN_HSUBPD                             X86IM_IO_IMNG_SSE3+7
#define X86IM_IO_IMN_HSUBPS                             X86IM_IO_IMNG_SSE3+8
#define X86IM_IO_IMN_FISTTP                             X86IM_IO_IMNG_SSE3+9
#define X86IM_IO_IMN_MOVDDUP                            X86IM_IO_IMNG_SSE3+10
#define X86IM_IO_IMN_MOVSHDUP                           X86IM_IO_IMNG_SSE3+11
#define X86IM_IO_IMN_MOVSLDUP                           X86IM_IO_IMNG_SSE3+12
#define X86IM_IO_IMN_PABS                               X86IM_IO_IMNG_SSE3+13
#define X86IM_IO_IMN_PALIGNR                            X86IM_IO_IMNG_SSE3+14
#define X86IM_IO_IMN_PHADDSW                            X86IM_IO_IMNG_SSE3+15
#define X86IM_IO_IMN_PHSUBSW                            X86IM_IO_IMNG_SSE3+16
#define X86IM_IO_IMN_PMADDUBSW                          X86IM_IO_IMNG_SSE3+17
#define X86IM_IO_IMN_PMULHRSW                           X86IM_IO_IMNG_SSE3+18
#define X86IM_IO_IMN_PSHUFB                             X86IM_IO_IMNG_SSE3+19
#define X86IM_IO_IMN_PSIGN                              X86IM_IO_IMNG_SSE3+20
#define X86IM_IO_IMN_PHADD                              X86IM_IO_IMNG_SSE3+21
#define X86IM_IO_IMN_PHSUB                              X86IM_IO_IMNG_SSE3+22

#define X86IM_IO_TN_CONDITION(x)                        ( ( (x)->tttn_fld >> 1 ) & 0x7 )
#define X86IM_IO_TN_USE(x)                              ( (x)->tttn_fld & 0x1 )

#define X86IM_IO_TN_USE_NEGATION                        1
#define X86IM_IO_TN_USE_CONDITION                       0

#define X86IM_IO_TN_O                                   0x00 // n=0 overflow
#define X86IM_IO_TN_NO                                  0x01 // n=1 no overflow
#define X86IM_IO_TN_B                                   0x02 // n=0 below
#define X86IM_IO_TN_C                                   0x02 // n=0 carry
#define X86IM_IO_TN_NAE                                 0x02 // n=0 not above or equal
#define X86IM_IO_TN_AE                                  0x03 // n=1 above or equal
#define X86IM_IO_TN_NB                                  0x03 // n=1 not below
#define X86IM_IO_TN_NC                                  0x03 // n=1 not carry
#define X86IM_IO_TN_E                                   0x04 // n=0 equal
#define X86IM_IO_TN_Z                                   0x04 // n=0 zero
#define X86IM_IO_TN_NE                                  0x05 // n=1 not equal
#define X86IM_IO_TN_NZ                                  0x05 // n=1 not zero
#define X86IM_IO_TN_BE                                  0x06 // n=0 below or equal
#define X86IM_IO_TN_NA                                  0x06 // n=0 not above
#define X86IM_IO_TN_A                                   0x07 // n=1 above
#define X86IM_IO_TN_NBE                                 0x07 // n=1 not below or equal
#define X86IM_IO_TN_S                                   0x08 // n=0 sign
#define X86IM_IO_TN_NS                                  0x09 // n=1 not sign
#define X86IM_IO_TN_P                                   0x0A // n=0 parity
#define X86IM_IO_TN_PE                                  0x0A // n=0 parity even
#define X86IM_IO_TN_NP                                  0x0B // n=1 not parity
#define X86IM_IO_TN_PO                                  0x0B // n=1 parity odd
#define X86IM_IO_TN_L                                   0x0C // n=0 less than
#define X86IM_IO_TN_NGE                                 0x0C // n=0 not greater than or equal to
#define X86IM_IO_TN_NL                                  0x0D // n=1 not less than
#define X86IM_IO_TN_GE                                  0x0D // n=1 greater than or equal to
#define X86IM_IO_TN_LE                                  0x0E // n=0 less than or equal to
#define X86IM_IO_TN_NG                                  0x0E // n=0 not greater than
#define X86IM_IO_TN_NLE                                 0x0F // n=1 not les than or equal to
#define X86IM_IO_TN_G                                   0x0F // n=1 greater than

// x86io.rop[x]:
//
// byte 0       0-3b = reg ID
//              4-7b = reg GRP
// byte 1-3     reg flags

// reg id & grp:

#define X86IM_IO_ROP_GR_GPR                             0x00 // general purpose registers: 8/16/32/64

#define X86IM_IO_ROP_SGR_GPR_8                          0x10 // 8bit GPR: low/high
#define X86IM_IO_ROP_ID_AL                              0x00
#define X86IM_IO_ROP_ID_CL                              0x01
#define X86IM_IO_ROP_ID_DL                              0x02
#define X86IM_IO_ROP_ID_BL                              0x03
#define X86IM_IO_ROP_ID_AH                              0x04
#define X86IM_IO_ROP_ID_CH                              0x05
#define X86IM_IO_ROP_ID_DH                              0x06
#define X86IM_IO_ROP_ID_BH                              0x07
#define X86IM_IO_ROP_ID_R8B                             0x08
#define X86IM_IO_ROP_ID_R9B                             0x09
#define X86IM_IO_ROP_ID_R10B                            0x0A
#define X86IM_IO_ROP_ID_R11B                            0x0B
#define X86IM_IO_ROP_ID_R12B                            0x0C
#define X86IM_IO_ROP_ID_R13B                            0x0D
#define X86IM_IO_ROP_ID_R14B                            0x0E
#define X86IM_IO_ROP_ID_R15B                            0x0F

#define X86IM_IO_ROP_SGR_GPR_8B                         0x30 // 8bit GPR: new 8b regs if REX prefix
#define X86IM_IO_ROP_ID_SPL                             0x00
#define X86IM_IO_ROP_ID_BPL                             0x01
#define X86IM_IO_ROP_ID_SIL                             0x02
#define X86IM_IO_ROP_ID_DIL                             0x03

#define X86IM_IO_ROP_SGR_GPR_16                         0x20 // 16bit GPR
#define X86IM_IO_ROP_ID_AX                              0x00
#define X86IM_IO_ROP_ID_CX                              0x01
#define X86IM_IO_ROP_ID_DX                              0x02
#define X86IM_IO_ROP_ID_BX                              0x03
#define X86IM_IO_ROP_ID_SP                              0x04
#define X86IM_IO_ROP_ID_BP                              0x05
#define X86IM_IO_ROP_ID_SI                              0x06
#define X86IM_IO_ROP_ID_DI                              0x07
#define X86IM_IO_ROP_ID_R8W                             0x08
#define X86IM_IO_ROP_ID_R9W                             0x09
#define X86IM_IO_ROP_ID_R10W                            0x0A
#define X86IM_IO_ROP_ID_R11W                            0x0B
#define X86IM_IO_ROP_ID_R12W                            0x0C
#define X86IM_IO_ROP_ID_R13W                            0x0D
#define X86IM_IO_ROP_ID_R14W                            0x0E
#define X86IM_IO_ROP_ID_R15W                            0x0F

#define X86IM_IO_ROP_SGR_GPR_32                         0x40 // 32bit GPR
#define X86IM_IO_ROP_ID_EAX                             0x00
#define X86IM_IO_ROP_ID_ECX                             0x01
#define X86IM_IO_ROP_ID_EDX                             0x02
#define X86IM_IO_ROP_ID_EBX                             0x03
#define X86IM_IO_ROP_ID_ESP                             0x04
#define X86IM_IO_ROP_ID_EBP                             0x05
#define X86IM_IO_ROP_ID_ESI                             0x06
#define X86IM_IO_ROP_ID_EDI                             0x07
#define X86IM_IO_ROP_ID_R8D                             0x08
#define X86IM_IO_ROP_ID_R9D                             0x09
#define X86IM_IO_ROP_ID_R10D                            0x0A
#define X86IM_IO_ROP_ID_R11D                            0x0B
#define X86IM_IO_ROP_ID_R12D                            0x0C
#define X86IM_IO_ROP_ID_R13D                            0x0D
#define X86IM_IO_ROP_ID_R14D                            0x0E
#define X86IM_IO_ROP_ID_R15D                            0x0F

#define X86IM_IO_ROP_SGR_GPR_64                         0x80 // 64bit GPR
#define X86IM_IO_ROP_ID_RAX                             0x00
#define X86IM_IO_ROP_ID_RCX                             0x01
#define X86IM_IO_ROP_ID_RDX                             0x02
#define X86IM_IO_ROP_ID_RBX                             0x03
#define X86IM_IO_ROP_ID_RSP                             0x04
#define X86IM_IO_ROP_ID_RBP                             0x05
#define X86IM_IO_ROP_ID_RSI                             0x06
#define X86IM_IO_ROP_ID_RDI                             0x07
#define X86IM_IO_ROP_ID_R8                              0x08
#define X86IM_IO_ROP_ID_R9                              0x09
#define X86IM_IO_ROP_ID_R10                             0x0A
#define X86IM_IO_ROP_ID_R11                             0x0B
#define X86IM_IO_ROP_ID_R12                             0x0C
#define X86IM_IO_ROP_ID_R13                             0x0D
#define X86IM_IO_ROP_ID_R14                             0x0E
#define X86IM_IO_ROP_ID_R15                             0x0F

#define X86IM_IO_ROP_GR_SRG                             0xB0 // segment registers
#define X86IM_IO_ROP_ID_ES                              0x00
#define X86IM_IO_ROP_ID_CS                              0x01
#define X86IM_IO_ROP_ID_SS                              0x02
#define X86IM_IO_ROP_ID_DS                              0x03
#define X86IM_IO_ROP_ID_FS                              0x04
#define X86IM_IO_ROP_ID_GS                              0x05

#define X86IM_IO_ROP_GR_CRG                             0x60 // control registers
#define X86IM_IO_ROP_ID_CR0                             0x00
#define X86IM_IO_ROP_ID_CR1                             0x01
#define X86IM_IO_ROP_ID_CR2                             0x02
#define X86IM_IO_ROP_ID_CR3                             0x03
#define X86IM_IO_ROP_ID_CR4                             0x04
#define X86IM_IO_ROP_ID_CR5                             0x05
#define X86IM_IO_ROP_ID_CR6                             0x06
#define X86IM_IO_ROP_ID_CR7                             0x07
#define X86IM_IO_ROP_ID_CR8                             0x08
#define X86IM_IO_ROP_ID_CR9                             0x09
#define X86IM_IO_ROP_ID_CR10                            0x0A
#define X86IM_IO_ROP_ID_CR11                            0x0B
#define X86IM_IO_ROP_ID_CR12                            0x0C
#define X86IM_IO_ROP_ID_CR13                            0x0D
#define X86IM_IO_ROP_ID_CR14                            0x0E
#define X86IM_IO_ROP_ID_CR15                            0x0F

#define X86IM_IO_ROP_GR_DRG                             0x70 // debug registers
#define X86IM_IO_ROP_ID_DR0                             0x00
#define X86IM_IO_ROP_ID_DR1                             0x01
#define X86IM_IO_ROP_ID_DR2                             0x02
#define X86IM_IO_ROP_ID_DR3                             0x03
#define X86IM_IO_ROP_ID_DR4                             0x04
#define X86IM_IO_ROP_ID_DR5                             0x05
#define X86IM_IO_ROP_ID_DR6                             0x06
#define X86IM_IO_ROP_ID_DR7                             0x07
#define X86IM_IO_ROP_ID_DR8                             0x08
#define X86IM_IO_ROP_ID_DR9                             0x09
#define X86IM_IO_ROP_ID_DR10                            0x0A
#define X86IM_IO_ROP_ID_DR11                            0x0B
#define X86IM_IO_ROP_ID_DR12                            0x0C
#define X86IM_IO_ROP_ID_DR13                            0x0D
#define X86IM_IO_ROP_ID_DR14                            0x0E
#define X86IM_IO_ROP_ID_DR15                            0x0F

#define X86IM_IO_ROP_GR_STR                             0xC0 // fpu registers
#define X86IM_IO_ROP_ID_ST0                             0x00
#define X86IM_IO_ROP_ID_ST1                             0x01
#define X86IM_IO_ROP_ID_ST2                             0x02
#define X86IM_IO_ROP_ID_ST3                             0x03
#define X86IM_IO_ROP_ID_ST4                             0x04
#define X86IM_IO_ROP_ID_ST5                             0x05
#define X86IM_IO_ROP_ID_ST6                             0x06
#define X86IM_IO_ROP_ID_ST7                             0x07

#define X86IM_IO_ROP_GR_MXR                             0xA0 // mmx registers
#define X86IM_IO_ROP_ID_MMX0                            0x00
#define X86IM_IO_ROP_ID_MMX1                            0x01
#define X86IM_IO_ROP_ID_MMX2                            0x02
#define X86IM_IO_ROP_ID_MMX3                            0x03
#define X86IM_IO_ROP_ID_MMX4                            0x04
#define X86IM_IO_ROP_ID_MMX5                            0x05
#define X86IM_IO_ROP_ID_MMX6                            0x06
#define X86IM_IO_ROP_ID_MMX7                            0x07

#define X86IM_IO_ROP_GR_XMR                             0x50 // xmm registers
#define X86IM_IO_ROP_ID_XMM0                            0x00
#define X86IM_IO_ROP_ID_XMM1                            0x01
#define X86IM_IO_ROP_ID_XMM2                            0x02
#define X86IM_IO_ROP_ID_XMM3                            0x03
#define X86IM_IO_ROP_ID_XMM4                            0x04
#define X86IM_IO_ROP_ID_XMM5                            0x05
#define X86IM_IO_ROP_ID_XMM6                            0x06
#define X86IM_IO_ROP_ID_XMM7                            0x07
#define X86IM_IO_ROP_ID_XMM8                            0x08
#define X86IM_IO_ROP_ID_XMM9                            0x09
#define X86IM_IO_ROP_ID_XMM10                           0x0A
#define X86IM_IO_ROP_ID_XMM11                           0x0B
#define X86IM_IO_ROP_ID_XMM12                           0x0C
#define X86IM_IO_ROP_ID_XMM13                           0x0D
#define X86IM_IO_ROP_ID_XMM14                           0x0E
#define X86IM_IO_ROP_ID_XMM15                           0x0F

#define X86IM_IO_ROP_ID_RIP                             0x90 // RIP: grp+id

#define X86IM_IO_ROP_GET_ID(x)                          ( (x) & 0x0F )              // get register id
#define X86IM_IO_ROP_GET_ID32(x)                        ( (x) & 0x07 )              // get register id ( 32bit )
#define X86IM_IO_ROP_GET_ID64(x)                        X86IM_IO_ROP_GET_ID(x)      // get register id ( extended )
#define X86IM_IO_ROP_SET_ID(x,id)                       ( (x) |= ( (id) & 0x0F ) )  // set register id
#define X86IM_IO_ROP_GET_GR(x)                          ( (x) & 0xF0 )              // get register group
#define X86IM_IO_ROP_SET_GR(x,gr)                       ( (x) |= ( (gr) & 0xF0 ) )  // set register group

#define X86IM_IO_ROP_IS_GPR(x)                          ( X86IM_IO_ROP_IS_GPR8(x) || X86IM_IO_ROP_IS_GPR8B(x) || X86IM_IO_ROP_IS_GPR16(x) || X86IM_IO_ROP_IS_GPR32(x) || X86IM_IO_ROP_IS_GPR64(x) )
#define X86IM_IO_ROP_IS_GPR8(x)                         ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_SGR_GPR_8 )
#define X86IM_IO_ROP_IS_GPR8B(x)                        ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_SGR_GPR_8B )
#define X86IM_IO_ROP_IS_GPR16(x)                        ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_SGR_GPR_16 )
#define X86IM_IO_ROP_IS_GPR32(x)                        ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_SGR_GPR_32 )
#define X86IM_IO_ROP_IS_GPR64(x)                        ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_SGR_GPR_64 )
#define X86IM_IO_ROP_IS_SRG(x)                          ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_GR_SRG )
#define X86IM_IO_ROP_IS_CRG(x)                          ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_GR_CRG )
#define X86IM_IO_ROP_IS_DRG(x)                          ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_GR_DRG )
#define X86IM_IO_ROP_IS_STR(x)                          ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_GR_STR )
#define X86IM_IO_ROP_IS_MXR(x)                          ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_GR_MXR )
#define X86IM_IO_ROP_IS_XMR(x)                          ( X86IM_IO_ROP_GET_GR(x) == X86IM_IO_ROP_GR_XMR )

// reg flags:

#define X86IM_IO_ROP_DST                                0x00000100  // reg is destination ( +w )
#define X86IM_IO_ROP_SRC                                0x00000200  // reg is source ( +r )
#define X86IM_IO_ROP_EXP                                0x00000400  // reg is explicit
#define X86IM_IO_ROP_IMP                                0x00000800  // reg is implicit

#define X86IM_IO_ROP_IS_DST(x)                          ( (x) & X86IM_IO_ROP_DST )
#define X86IM_IO_ROP_IS_SRC(x)                          ( (x) & X86IM_IO_ROP_SRC )
#define X86IM_IO_ROP_IS_EXP(x)                          ( (x) & X86IM_IO_ROP_EXP )
#define X86IM_IO_ROP_IS_IMP(x)                          ( (x) & X86IM_IO_ROP_IMP )

#define X86IM_IO_ROP_SET_DST(x)                         ( (x) |= X86IM_IO_ROP_DST )
#define X86IM_IO_ROP_SET_SRC(x)                         ( (x) |= X86IM_IO_ROP_SRC )
#define X86IM_IO_ROP_SET_EXP(x)                         ( (x) |= X86IM_IO_ROP_EXP )
#define X86IM_IO_ROP_SET_IMP(x)                         ( (x) |= X86IM_IO_ROP_IMP )

#define X86IM_IO_ROP_UNSET_DST(x)                       ( (x) = ( ( (x) | X86IM_IO_ROP_DST ) ^ X86IM_IO_ROP_DST ) )
#define X86IM_IO_ROP_UNSET_SRC(x)                       ( (x) = ( ( (x) | X86IM_IO_ROP_SRC ) ^ X86IM_IO_ROP_SRC ) )
#define X86IM_IO_ROP_UNSET_EXP(x)                       ( (x) = ( ( (x) | X86IM_IO_ROP_EXP ) ^ X86IM_IO_ROP_EXP ) )
#define X86IM_IO_ROP_UNSET_IMP(x)                       ( (x) = ( ( (x) | X86IM_IO_ROP_IMP ) ^ X86IM_IO_ROP_IMP ) )

#define X86IM_IO_ROP_LOCATION_MODRM                     0x00003000  // mask
#define X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM             0x00001000  // "modrm byte - r/m field"
#define X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG             0x00002000  // "modrm byte - reg field"
#define X86IM_IO_ROP_LOCATION_SIB                       0x0000C000  // mask
#define X86IM_IO_ROP_LOCATION_SIB_FLD_SDX               0x00004000  // "sib byte - index field"
#define X86IM_IO_ROP_LOCATION_SIB_FLD_SBS               0x00008000  // "sib byte - base field"
#define X86IM_IO_ROP_LOCATION_OPCODE                    0x00070000  // mask
#define X86IM_IO_ROP_LOCATION_OPCODE_OP3                0x00010000  // "opcode - field 3bits (0,1,2)"
#define X86IM_IO_ROP_LOCATION_OPCODE_OPS2               0x00020000  // "opcode - field 2bits (3,4) seg reg sr1"
#define X86IM_IO_ROP_LOCATION_OPCODE_OPS3               0x00040000  // "opcode - field 3bits (3,4,5) seg reg sr2"

#define X86IM_IO_ROP_IS_LOCATED_IN_MODRM(x)             ( (x) & X86IM_IO_ROP_LOCATION_MODRM )
#define X86IM_IO_ROP_IS_LOCATED_IN_SIB(x)               ( (x) & X86IM_IO_ROP_LOCATION_SIB )
#define X86IM_IO_ROP_IS_LOCATED_IN_OPCODE(x)            ( (x) & X86IM_IO_ROP_LOCATION_OPCODE )

#define X86IM_IO_ROP_IS_LOCATION_MODRM_FLD_MRM(x)       ( (x) & X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM )
#define X86IM_IO_ROP_IS_LOCATION_MODRM_FLD_MRG(x)       ( (x) & X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG )
#define X86IM_IO_ROP_IS_LOCATION_SIB_FLD_SDX(x)         ( (x) & X86IM_IO_ROP_LOCATION_SIB_FLD_SDX )
#define X86IM_IO_ROP_IS_LOCATION_SIB_FLD_SBS(x)         ( (x) & X86IM_IO_ROP_LOCATION_SIB_FLD_SBS )
#define X86IM_IO_ROP_IS_LOCATION_OPCODE_OP3(x)          ( (x) & X86IM_IO_ROP_LOCATION_OPCODE_OP3 )
#define X86IM_IO_ROP_IS_LOCATION_OPCODE_OPS2(x)         ( (x) & X86IM_IO_ROP_LOCATION_OPCODE_OPS2 )
#define X86IM_IO_ROP_IS_LOCATION_OPCODE_OPS3(x)         ( (x) & X86IM_IO_ROP_LOCATION_OPCODE_OPS3 )

#define X86IM_IO_ROP_SET_LOCATION_MODRM_FLD_MRM(x)      ( (x) |= X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM )
#define X86IM_IO_ROP_SET_LOCATION_MODRM_FLD_MRG(x)      ( (x) |= X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG )
#define X86IM_IO_ROP_SET_LOCATION_SIB_FLD_SDX(x)        ( (x) |= X86IM_IO_ROP_LOCATION_SIB_FLD_SDX )
#define X86IM_IO_ROP_SET_LOCATION_SIB_FLD_SBS(x)        ( (x) |= X86IM_IO_ROP_LOCATION_SIB_FLD_SBS )
#define X86IM_IO_ROP_SET_LOCATION_OPCODE_OP3(x)         ( (x) |= X86IM_IO_ROP_LOCATION_OPCODE_OP3 )
#define X86IM_IO_ROP_SET_LOCATION_OPCODE_OPS2(x)        ( (x) |= X86IM_IO_ROP_LOCATION_OPCODE_OPS2 )
#define X86IM_IO_ROP_SET_LOCATION_OPCODE_OPS3(x)        ( (x) |= X86IM_IO_ROP_LOCATION_OPCODE_OPS3 )

#define X86IM_IO_ROP_UNSET_LOCATION_MODRM_FLD_MRM(x)    ( (x) = ( ( (x) | X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM ) ^ X86IM_IO_ROP_LOCATION_MODRM_FLD_MRM ) )
#define X86IM_IO_ROP_UNSET_LOCATION_MODRM_FLD_MRG(x)    ( (x) = ( ( (x) | X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG ) ^ X86IM_IO_ROP_LOCATION_MODRM_FLD_MRG ) )
#define X86IM_IO_ROP_UNSET_LOCATION_SIB_FLD_SDX(x)      ( (x) = ( ( (x) | X86IM_IO_ROP_LOCATION_SIB_FLD_SDX ) ^ X86IM_IO_ROP_LOCATION_SIB_FLD_SDX ) )
#define X86IM_IO_ROP_UNSET_LOCATION_SIB_FLD_SBS(x)      ( (x) = ( ( (x) | X86IM_IO_ROP_LOCATION_SIB_FLD_SBS ) ^ X86IM_IO_ROP_LOCATION_SIB_FLD_SBS ) )
#define X86IM_IO_ROP_UNSET_LOCATION_OPCODE_OP3(x)       ( (x) = ( ( (x) | X86IM_IO_ROP_LOCATION_OPCODE_OP3 ) ^ X86IM_IO_ROP_LOCATION_OPCODE_OP3 ) )
#define X86IM_IO_ROP_UNSET_LOCATION_OPCODE_OPS2(x)      ( (x) = ( ( (x) | X86IM_IO_ROP_LOCATION_OPCODE_OPS2 ) ^ X86IM_IO_ROP_LOCATION_OPCODE_OPS2 ) )
#define X86IM_IO_ROP_UNSET_LOCATION_OPCODE_OPS3(x)      ( (x) = ( ( (x) | X86IM_IO_ROP_LOCATION_OPCODE_OPS3 ) ^ X86IM_IO_ROP_LOCATION_OPCODE_OPS3 ) )

#define X86IM_IO_GET_MODRM_FLD_MOD(x)                   ( ( (x) >> 6 ) & 0x3 )  // mod field: bits 7,6   : 0/1/2 // x = byte ( unsigned char )
#define X86IM_IO_GET_MODRM_FLD_REG(x)                   ( ( (x) >> 3 ) & 0x7 )  // reg field: bits 5,4,3
#define X86IM_IO_GET_MODRM_FLD_RM(x)                    ( (x) & 0x7 )           // r/m field: bits 2,1,0

#define X86IM_IO_SET_MODRM_FLD_MOD(x,v)                 ( (x) |= ( ( (v) & 0x3 ) << 6 ) )    // x,v = byte ( unsigned char )
#define X86IM_IO_SET_MODRM_FLD_REG(x,v)                 ( (x) |= ( ( (v) & 0x7 ) << 3 ) )
#define X86IM_IO_SET_MODRM_FLD_RM(x,v)                  ( (x) |= ( (v) & 0x7 ) )

#define X86IM_IO_GET_SIB_FLD_SCALE(x)                   ( ( (x) >> 6 ) & 0x3 )  // scale field ( 0/2/4/8 ): bits 7,6 // x = byte ( unsigned char )
#define X86IM_IO_GET_SIB_FLD_INDEX(x)                   ( ( (x) >> 3 ) & 0x7 )  // index field: bits 5,4,3
#define X86IM_IO_GET_SIB_FLD_BASE(x)                    ( (x) & 0x7 )           // base field: bits 2,1,0

#define X86IM_IO_SET_SIB_FLD_SCALE(x,v)                 ( (x) |= ( ( (v) & 0x3 ) << 6 ) )    // x,v = byte ( unsigned char )
#define X86IM_IO_SET_SIB_FLD_INDEX(x,v)                 ( (x) |= ( ( (v) & 0x7 ) << 3 ) )
#define X86IM_IO_SET_SIB_FLD_BASE(x,v)                  ( (x) |= ( (v) & 0x7 ) )

// immediate size

#define X86IM_IO_IM_SZ_BYTE                             1 // imm8
#define X86IM_IO_IM_SZ_WORD                             2 // imm16
#define X86IM_IO_IM_SZ_DWORD                            4 // imm32
#define X86IM_IO_IM_SZ_QWORD                            8 // imm64

#define X86IM_IO_IM_SIGNED(x)                           ( ( (x)->imm >> ( (x)->imm_size * 8 ) ) & 0x1 )

// disp size

#define X86IM_IO_DP_SZ_BYTE                             1 // disp8
#define X86IM_IO_DP_SZ_WORD                             2 // disp16
#define X86IM_IO_DP_SZ_DWORD                            4 // disp32
#define X86IM_IO_DP_SZ_QWORD                            8 // disp64

#define X86IM_IO_DP_SIGNED(x)                           ( ( (x)->imm >> ( (x)->imm_size * 8 ) ) & 0x1 )

// memory operand flags

#define X86IM_IO_MOP_SRC                                0x0001  // mem op is source
#define X86IM_IO_MOP_DST                                0x0002  // mem op is destination
#define X86IM_IO_MOP_SOD                                0x0004  // mem op can be src or dst ( ejem cmpxchg8/16b )
#define X86IM_IO_MOP_MOF                                0x0008  // mem op is a moffset: disp only

#define X86IM_IO_MOP_IS_SRC(x)                          ( (x)->mem_flags & X86IM_IO_MOP_SRC )
#define X86IM_IO_MOP_IS_DST(x)                          ( (x)->mem_flags & X86IM_IO_MOP_DST )
#define X86IM_IO_MOP_IS_SOD(x)                          ( (x)->mem_flags & X86IM_IO_MOP_SOD )
#define X86IM_IO_MOP_IS_MOF(x)                          ( (x)->mem_flags & X86IM_IO_MOP_MOF )

#define X86IM_IO_MOP_SET_SRC(x)                         ( (x)->mem_flags |= X86IM_IO_MOP_SRC )
#define X86IM_IO_MOP_SET_DST(x)                         ( (x)->mem_flags |= X86IM_IO_MOP_DST )
#define X86IM_IO_MOP_SET_SOD(x)                         ( (x)->mem_flags |= X86IM_IO_MOP_SOD )
#define X86IM_IO_MOP_SET_MOF(x)                         ( (x)->mem_flags |= X86IM_IO_MOP_MOF )

#define X86IM_IO_MOP_UNSET_SRC(x)                       ( (x)->mem_flags = ( ( (x)->mem_flags | X86IM_IO_MOP_SRC ) ^ X86IM_IO_MOP_SRC ) )
#define X86IM_IO_MOP_UNSET_DST(x)                       ( (x)->mem_flags = ( ( (x)->mem_flags | X86IM_IO_MOP_DST ) ^ X86IM_IO_MOP_DST ) )
#define X86IM_IO_MOP_UNSET_SOD(x)                       ( (x)->mem_flags = ( ( (x)->mem_flags | X86IM_IO_MOP_SOD ) ^ X86IM_IO_MOP_SOD ) )
#define X86IM_IO_MOP_UNSET_MOF(x)                       ( (x)->mem_flags = ( ( (x)->mem_flags | X86IM_IO_MOP_MOF ) ^ X86IM_IO_MOP_MOF ) )

// memory operand size

#define X86IM_IO_MOP_SZ_BYTE_PTR                        1
#define X86IM_IO_MOP_SZ_WORD_PTR                        2
#define X86IM_IO_MOP_SZ_DWORD_PTR                       4
#define X86IM_IO_MOP_SZ_FWORD_PTR                       6
#define X86IM_IO_MOP_SZ_QWORD_PTR                       8
#define X86IM_IO_MOP_SZ_TBYTE_PTR                       10
#define X86IM_IO_MOP_SZ_OWORD_PTR                       16
#define X86IM_IO_MOP_SZ_FPUENVA_PTR                     14  // (fpu env): 14b
#define X86IM_IO_MOP_SZ_FPUENVB_PTR                     28  // (fpu env): 28b
#define X86IM_IO_MOP_SZ_FPUSTA_PTR                      94  // (fpu/mmx state): 94b
#define X86IM_IO_MOP_SZ_FPUSTB_PTR                      108 // (fpu/mmx state): 108b
#define X86IM_IO_MOP_SZ_FXST_PTR                        512 // (fpu/mmx/xmm/mxcsr state): 512b

// addressing mode & components

#define X86IM_IO_MOP_AMDF                               0x0000  // default addressing mode: depends on addr-sz
#define X86IM_IO_MOP_AM16                               0x0001  // 16bit addressing mode
#define X86IM_IO_MOP_AM32                               0x0002  // 32bit addressing mode
#define X86IM_IO_MOP_AM64                               0x0004  // 64bit addressing mode

#define X86IM_IO_MOP_HAS_AM16(x)                        ( (x)->mem_am & X86IM_IO_MOP_AM16 )
#define X86IM_IO_MOP_HAS_AM32(x)                        ( (x)->mem_am & X86IM_IO_MOP_AM32 )
#define X86IM_IO_MOP_HAS_AM64(x)                        ( (x)->mem_am & X86IM_IO_MOP_AM64 )

#define X86IM_IO_MOP_SET_AM(x,f)                        ( (x)->mem_am |= (f) )

#define X86IM_IO_MOP_SET_AM16(x)                        ( (x)->mem_am |= X86IM_IO_MOP_AM16 )
#define X86IM_IO_MOP_SET_AM32(x)                        ( (x)->mem_am |= X86IM_IO_MOP_AM32 )
#define X86IM_IO_MOP_SET_AM64(x)                        ( (x)->mem_am |= X86IM_IO_MOP_AM64 )

#define X86IM_IO_MOP_AMC_INDEX                          0x0100  // mem op has index
#define X86IM_IO_MOP_AMC_SCALE                          0x0200  // mem op has scale
#define X86IM_IO_MOP_AMC_BASE                           0x0400  // mem op has base

#define X86IM_IO_MOP_AMC_HAS_INDEX(x)                   ( (x)->mem_am & X86IM_IO_MOP_AMC_INDEX )
#define X86IM_IO_MOP_AMC_HAS_SCALE(x)                   ( (x)->mem_am & X86IM_IO_MOP_AMC_SCALE )
#define X86IM_IO_MOP_AMC_HAS_BASE(x)                    ( (x)->mem_am & X86IM_IO_MOP_AMC_BASE )

#define X86IM_IO_MOP_AMC_SET_INDEX(x)                   ( (x)->mem_am |= X86IM_IO_MOP_AMC_INDEX )
#define X86IM_IO_MOP_AMC_SET_SCALE(x)                   ( (x)->mem_am |= X86IM_IO_MOP_AMC_SCALE )
#define X86IM_IO_MOP_AMC_SET_BASE(x)                    ( (x)->mem_am |= X86IM_IO_MOP_AMC_BASE )

#define X86IM_IO_MOP_AMC_UNSET_INDEX(x)                 ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_INDEX ) ^ X86IM_IO_MOP_AMC_INDEX ) )
#define X86IM_IO_MOP_AMC_UNSET_SCALE(x)                 ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_SCALE ) ^ X86IM_IO_MOP_AMC_SCALE ) )
#define X86IM_IO_MOP_AMC_UNSET_BASE(x)                  ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_BASE ) ^ X86IM_IO_MOP_AMC_BASE ) )

#define X86IM_IO_MOP_AMC_DISP                           0x0078  // mem op has dispXX
#define X86IM_IO_MOP_AMC_DISP8                          0x0008  // mem op has disp8
#define X86IM_IO_MOP_AMC_DISP16                         0x0010  // mem op has disp16
#define X86IM_IO_MOP_AMC_DISP32                         0x0020  // mem op has disp32
#define X86IM_IO_MOP_AMC_DISP64                         0x0040  // mem op has disp64: moffset only

#define X86IM_IO_MOP_AMC_HAS_DISP(x)                    ( (x)->mem_am & X86IM_IO_MOP_AMC_DISP )
#define X86IM_IO_MOP_AMC_HAS_DISPX(x,d)                 ( (x)->mem_am & ( (d) & X86IM_IO_MOP_AMC_DISP ) )

#define X86IM_IO_MOP_AMC_HAS_DISP8(x)                   ( (x)->mem_am & X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AMC_HAS_DISP16(x)                  ( (x)->mem_am & X86IM_IO_MOP_AMC_DISP16 )
#define X86IM_IO_MOP_AMC_HAS_DISP32(x)                  ( (x)->mem_am & X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AMC_HAS_DISP64(x)                  ( (x)->mem_am & X86IM_IO_MOP_AMC_DISP64 )

#define X86IM_IO_MOP_AMC_SET_DISP(x,d)                  ( (x)->mem_am |= ( (d) & X86IM_IO_MOP_AMC_DISP ) )

#define X86IM_IO_MOP_AMC_SET_DISP8(x)                   ( (x)->mem_am |= X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AMC_SET_DISP16(x)                  ( (x)->mem_am |= X86IM_IO_MOP_AMC_DISP16 )
#define X86IM_IO_MOP_AMC_SET_DISP32(x)                  ( (x)->mem_am |= X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AMC_SET_DISP64(x)                  ( (x)->mem_am |= X86IM_IO_MOP_AMC_DISP64 )

#define X86IM_IO_MOP_AMC_UNSET_DISP(x,d)                ( (x)->mem_am = ( ( (x)->mem_am | ( (d) & X86IM_IO_MOP_AMC_DISP ) ) ^ ( (d) & X86IM_IO_MOP_AMC_DISP ) ) )

#define X86IM_IO_MOP_AMC_UNSET_DISP8(x)                 ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_DISP8 ) ^ X86IM_IO_MOP_AMC_DISP8 ) )
#define X86IM_IO_MOP_AMC_UNSET_DISP16(x)                ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_DISP16 ) ^ X86IM_IO_MOP_AMC_DISP16 ) )
#define X86IM_IO_MOP_AMC_UNSET_DISP32(x)                ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_DISP32 ) ^ X86IM_IO_MOP_AMC_DISP32 ) )
#define X86IM_IO_MOP_AMC_UNSET_DISP64(x)                ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_DISP64 ) ^ X86IM_IO_MOP_AMC_DISP64 ) )

#define X86IM_IO_MOP_AMC_SIB1				            0x1000
#define X86IM_IO_MOP_AMC_SIB2					        0x2000
#define X86IM_IO_MOP_AMC_SIB3						    0x4000
#define X86IM_IO_MOP_AMC_SIB4						    0x8000
#define X86IM_IO_MOP_AMC_SIB                            0xF000

#define X86IM_IO_MOP_AMC_HAS_SIB(x)                     ( (x)->mem_am & X86IM_IO_MOP_AMC_SIB )
#define X86IM_IO_MOP_AMC_HAS_SIBX(x,s)                  ( (x)->mem_am & (s) )

#define X86IM_IO_MOP_AMC_HAS_SIB1(x)                    ( (x)->mem_am & X86IM_IO_MOP_AMC_SIB1 )
#define X86IM_IO_MOP_AMC_HAS_SIB2(x)                    ( (x)->mem_am & X86IM_IO_MOP_AMC_SIB2 )
#define X86IM_IO_MOP_AMC_HAS_SIB3(x)                    ( (x)->mem_am & X86IM_IO_MOP_AMC_SIB3 )
#define X86IM_IO_MOP_AMC_HAS_SIB4(x)                    ( (x)->mem_am & X86IM_IO_MOP_AMC_SIB4 )

#define X86IM_IO_MOP_AMC_SET_SIB(x,s)                   ( (x)->mem_am |= ( (s) & X86IM_IO_MOP_AMC_SIB ) )

#define X86IM_IO_MOP_AMC_SET_SIB1(x)                    ( (x)->mem_am |= X86IM_IO_MOP_AMC_SIB1 )
#define X86IM_IO_MOP_AMC_SET_SIB2(x)                    ( (x)->mem_am |= X86IM_IO_MOP_AMC_SIB2 )
#define X86IM_IO_MOP_AMC_SET_SIB3(x)                    ( (x)->mem_am |= X86IM_IO_MOP_AMC_SIB3 )
#define X86IM_IO_MOP_AMC_SET_SIB4(x)                    ( (x)->mem_am |= X86IM_IO_MOP_AMC_SIB4 )

#define X86IM_IO_MOP_AMC_UNSET_SIB(x,s)                 ( (x)->mem_am = ( ( (x)->mem_am | ( (s) & X86IM_IO_MOP_AMC_SIB ) ) ^ ( (s) & X86IM_IO_MOP_AMC_SIB ) ) )

#define X86IM_IO_MOP_AMC_UNSET_SIB1(x)                  ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_SIB1 ) ^ X86IM_IO_MOP_AMC_SIB1 ) )
#define X86IM_IO_MOP_AMC_UNSET_SIB2(x)                  ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_SIB2 ) ^ X86IM_IO_MOP_AMC_SIB2 ) )
#define X86IM_IO_MOP_AMC_UNSET_SIB3(x)                  ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_SIB3 ) ^ X86IM_IO_MOP_AMC_SIB3 ) )
#define X86IM_IO_MOP_AMC_UNSET_SIB4(x)                  ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_SIB4 ) ^ X86IM_IO_MOP_AMC_SIB4 ) )

#define X86IM_IO_MOP_AMC_RIPREL                         0x0080  // 64bit rip relative addressing mode

#define X86IM_IO_MOP_AMC_HAS_RIPREL(x)                  ( (x)->mem_am & X86IM_IO_MOP_AMC_RIPREL )
#define X86IM_IO_MOP_AMC_SET_RIPREL(x)                  ( (x)->mem_am |= X86IM_IO_MOP_AMC_RIPREL )
#define X86IM_IO_MOP_AMC_UNSET_RIPREL(x)                ( (x)->mem_am = ( ( (x)->mem_am | X86IM_IO_MOP_AMC_RIPREL ) ^ X86IM_IO_MOP_AMC_RIPREL ) )

#define X86IM_IO_MOP_AM_16_BASE_INDEX                   ( X86IM_IO_MOP_AM16 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_INDEX  )
#define X86IM_IO_MOP_AM_16_BASE                         ( X86IM_IO_MOP_AM16 | X86IM_IO_MOP_AMC_BASE )
#define X86IM_IO_MOP_AM_16_DISP16                       ( X86IM_IO_MOP_AM16 | X86IM_IO_MOP_AMC_DISP16 )
#define X86IM_IO_MOP_AM_16_BASE_INDEX_DISP8             ( X86IM_IO_MOP_AM16 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AM_16_BASE_DISP8                   ( X86IM_IO_MOP_AM16 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AM_16_BASE_INDEX_DISP16            ( X86IM_IO_MOP_AM16 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP16 )
#define X86IM_IO_MOP_AM_16_BASE_DISP16                  ( X86IM_IO_MOP_AM16 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP16 )
#define X86IM_IO_MOP_AM_16_MOFFSET                      ( X86IM_IO_MOP_AM16 | X86IM_IO_MOP_AMC_DISP16 ) // special case: 16bit addr

#define X86IM_IO_MOP_AM_32_DISP32                       ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_32_RIP_DISP32                   ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_RIPREL | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_32_BASE                         ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE )
#define X86IM_IO_MOP_AM_32_BASE_DISP8                   ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AM_32_BASE_DISP32                  ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_32_INDEX_DISP32                 ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_32_SINDEX_DISP32                ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_32_BASE_INDEX                   ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX )
#define X86IM_IO_MOP_AM_32_BASE_INDEX_DISP8             ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AM_32_BASE_INDEX_DISP32            ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_32_BASE_SINDEX                  ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_INDEX )
#define X86IM_IO_MOP_AM_32_BASE_SINDEX_DISP8            ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AM_32_BASE_SINDEX_DISP32           ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_32_BASE_SIB1                    ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SIB1 )
#define X86IM_IO_MOP_AM_32_BASE_SIB2                    ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SIB2 )
#define X86IM_IO_MOP_AM_32_BASE_SIB3                    ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SIB3 )
#define X86IM_IO_MOP_AM_32_BASE_SIB4                    ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SIB4 )
#define X86IM_IO_MOP_AM_32_BASE_DISP8_SIB1              ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 | X86IM_IO_MOP_AMC_SIB1 )
#define X86IM_IO_MOP_AM_32_BASE_DISP8_SIB2              ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 | X86IM_IO_MOP_AMC_SIB2 )
#define X86IM_IO_MOP_AM_32_BASE_DISP8_SIB3              ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 | X86IM_IO_MOP_AMC_SIB3 )
#define X86IM_IO_MOP_AM_32_BASE_DISP8_SIB4              ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 | X86IM_IO_MOP_AMC_SIB4 )
#define X86IM_IO_MOP_AM_32_BASE_DISP32_SIB1             ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB1 )
#define X86IM_IO_MOP_AM_32_BASE_DISP32_SIB2             ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB2 )
#define X86IM_IO_MOP_AM_32_BASE_DISP32_SIB3             ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB3 )
#define X86IM_IO_MOP_AM_32_BASE_DISP32_SIB4             ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB4 )
#define X86IM_IO_MOP_AM_32_DISP32_SIB1                  ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB1 )
#define X86IM_IO_MOP_AM_32_DISP32_SIB2                  ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB2 )
#define X86IM_IO_MOP_AM_32_DISP32_SIB3                  ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB3 )
#define X86IM_IO_MOP_AM_32_DISP32_SIB4                  ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_DISP32 | X86IM_IO_MOP_AMC_SIB4 )
#define X86IM_IO_MOP_AM_32_MOFFSET                      ( X86IM_IO_MOP_AM32 | X86IM_IO_MOP_AMC_DISP32 ) // special case: 32bit addr

#define X86IM_IO_MOP_AM_64_DISP32                       ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_64_RIP_DISP32                   ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_RIPREL | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_64_BASE                         ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE )
#define X86IM_IO_MOP_AM_64_BASE_DISP8                   ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AM_64_BASE_DISP32                  ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_64_INDEX_DISP32                 ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_64_SINDEX_DISP32                ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_64_BASE_INDEX                   ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX )
#define X86IM_IO_MOP_AM_64_BASE_INDEX_DISP8             ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AM_64_BASE_INDEX_DISP32            ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_64_BASE_SINDEX                  ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_INDEX )
#define X86IM_IO_MOP_AM_64_BASE_SINDEX_DISP8            ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP8 )
#define X86IM_IO_MOP_AM_64_BASE_SINDEX_DISP32           ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_BASE | X86IM_IO_MOP_AMC_SCALE | X86IM_IO_MOP_AMC_INDEX | X86IM_IO_MOP_AMC_DISP32 )
#define X86IM_IO_MOP_AM_64_MOFFSET                      ( X86IM_IO_MOP_AM64 | X86IM_IO_MOP_AMC_DISP64 ) // special case: 64bit addr

// instr prefixes

#define X86IM_IO_IP_VALUE_LOCK                          0xF0
#define X86IM_IO_IP_VALUE_REPE                          0xF3
#define X86IM_IO_IP_VALUE_REPN                          0xF2
#define X86IM_IO_IP_VALUE_OPSZ                          0x66
#define X86IM_IO_IP_VALUE_ADSZ                          0x67
#define X86IM_IO_IP_VALUE_SGES                          0x26
#define X86IM_IO_IP_VALUE_SGCS                          0x2E
#define X86IM_IO_IP_VALUE_SGSS                          0x36
#define X86IM_IO_IP_VALUE_SGDS                          0x3E
#define X86IM_IO_IP_VALUE_SGFS                          0x64
#define X86IM_IO_IP_VALUE_SGGS                          0x65

#define X86IM_IO_IP_LOCK                                0x0001  // instr has lock prefix
#define X86IM_IO_IP_REPE                                0x0002  // instr has repe prefix
#define X86IM_IO_IP_REPN                                0x0004  // instr has repn prefix
#define X86IM_IO_IP_OPSZ                                0x0008  // instr has opsz prefix
#define X86IM_IO_IP_ADSZ                                0x0010  // instr has adsz prefix
#define X86IM_IO_IP_SGXS                                0x3F00  // instr has seg prefix:
#define X86IM_IO_IP_SGES                                0x0100  // instr has seg-ES prefix
#define X86IM_IO_IP_SGCS                                0x0200  // instr has seg-CS prefix
#define X86IM_IO_IP_SGSS                                0x0400  // instr has seg-SS prefix
#define X86IM_IO_IP_SGDS                                0x0800  // instr has seg-DS prefix
#define X86IM_IO_IP_SGFS                                0x1000  // instr has seg-FS prefix
#define X86IM_IO_IP_SGGS                                0x2000  // instr has seg-GS prefix
#define X86IM_IO_IP_REX                                 0x0040  // isntr has REX prefix

#define X86IM_IO_IP_F0                                  X86IM_IO_IP_LOCK
#define X86IM_IO_IP_F3                                  X86IM_IO_IP_REPE
#define X86IM_IO_IP_F2                                  X86IM_IO_IP_REPN
#define X86IM_IO_IP_66                                  X86IM_IO_IP_OPSZ
#define X86IM_IO_IP_67                                  X86IM_IO_IP_ADSZ
#define X86IM_IO_IP_26                                  X86IM_IO_IP_SGES
#define X86IM_IO_IP_2E                                  X86IM_IO_IP_SGCS
#define X86IM_IO_IP_36                                  X86IM_IO_IP_SGSS
#define X86IM_IO_IP_3E                                  X86IM_IO_IP_SGDS
#define X86IM_IO_IP_64                                  X86IM_IO_IP_SGFS
#define X86IM_IO_IP_65                                  X86IM_IO_IP_SGGS
#define X86IM_IO_IP_40                                  X86IM_IO_IP_REX

#define X86IM_IO_IP_HAS(x,p)                            ( (x)->prefix & ( (p) & 0xFFFF ) )

#define X86IM_IO_IP_HAS_LOCK(x)                         ( (x)->prefix & X86IM_IO_IP_LOCK )
#define X86IM_IO_IP_HAS_REPE(x)                         ( (x)->prefix & X86IM_IO_IP_REPE )
#define X86IM_IO_IP_HAS_REPN(x)                         ( (x)->prefix & X86IM_IO_IP_REPN )
#define X86IM_IO_IP_HAS_OPSZ(x)                         ( (x)->prefix & X86IM_IO_IP_OPSZ )
#define X86IM_IO_IP_HAS_ADSZ(x)                         ( (x)->prefix & X86IM_IO_IP_ADSZ )
#define X86IM_IO_IP_HAS_SGXS(x)                         ( (x)->prefix & X86IM_IO_IP_SGXS )
#define X86IM_IO_IP_HAS_SGES(x)                         ( (x)->prefix & X86IM_IO_IP_SGES )
#define X86IM_IO_IP_HAS_SGCS(x)                         ( (x)->prefix & X86IM_IO_IP_SGCS )
#define X86IM_IO_IP_HAS_SGSS(x)                         ( (x)->prefix & X86IM_IO_IP_SGSS )
#define X86IM_IO_IP_HAS_SGDS(x)                         ( (x)->prefix & X86IM_IO_IP_SGDS )
#define X86IM_IO_IP_HAS_SGFS(x)                         ( (x)->prefix & X86IM_IO_IP_SGFS )
#define X86IM_IO_IP_HAS_SGGS(x)                         ( (x)->prefix & X86IM_IO_IP_SGGS )
#define X86IM_IO_IP_HAS_REX(x)                          ( (x)->prefix & X86IM_IO_IP_REX  )

#define X86IM_IO_IP_SET(x,p)                            ( (x)->prefix |= ( (p) & 0xFFFF ) )

#define X86IM_IO_IP_SET_LOCK(x)                         ( (x)->prefix |= X86IM_IO_IP_LOCK )
#define X86IM_IO_IP_SET_REPE(x)                         ( (x)->prefix |= X86IM_IO_IP_REPE )
#define X86IM_IO_IP_SET_REPN(x)                         ( (x)->prefix |= X86IM_IO_IP_REPN )
#define X86IM_IO_IP_SET_OPSZ(x)                         ( (x)->prefix |= X86IM_IO_IP_OPSZ )
#define X86IM_IO_IP_SET_ADSZ(x)                         ( (x)->prefix |= X86IM_IO_IP_ADSZ )
#define X86IM_IO_IP_SET_SGES(x)                         ( (x)->prefix |= X86IM_IO_IP_SGES )
#define X86IM_IO_IP_SET_SGCS(x)                         ( (x)->prefix |= X86IM_IO_IP_SGCS )
#define X86IM_IO_IP_SET_SGSS(x)                         ( (x)->prefix |= X86IM_IO_IP_SGSS )
#define X86IM_IO_IP_SET_SGDS(x)                         ( (x)->prefix |= X86IM_IO_IP_SGDS )
#define X86IM_IO_IP_SET_SGFS(x)                         ( (x)->prefix |= X86IM_IO_IP_SGFS )
#define X86IM_IO_IP_SET_SGGS(x)                         ( (x)->prefix |= X86IM_IO_IP_SGGS )
#define X86IM_IO_IP_SET_REX(x)                          ( (x)->prefix |= X86IM_IO_IP_REX  )

#define X86IM_IO_IP_UNSET(x,p)                          ( (x)->prefix = ( ( (x)->prefix | ( (p) & 0xFFFF ) ) ^ ( (p) & 0xFFFF ) ) )

#define X86IM_IO_IP_UNSET_LOCK(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_LOCK ) ^ X86IM_IO_IP_LOCK ) )
#define X86IM_IO_IP_UNSET_REPE(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_REPE ) ^ X86IM_IO_IP_REPE ) )
#define X86IM_IO_IP_UNSET_REPN(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_REPN ) ^ X86IM_IO_IP_REPN ) )
#define X86IM_IO_IP_UNSET_OPSZ(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_OPSZ ) ^ X86IM_IO_IP_OPSZ ) )
#define X86IM_IO_IP_UNSET_ADSZ(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_ADSZ ) ^ X86IM_IO_IP_ADSZ ) )
#define X86IM_IO_IP_UNSET_SGES(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_SGES ) ^ X86IM_IO_IP_SGES ) )
#define X86IM_IO_IP_UNSET_SGCS(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_SGCS ) ^ X86IM_IO_IP_SGCS ) )
#define X86IM_IO_IP_UNSET_SGSS(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_SGSS ) ^ X86IM_IO_IP_SGSS ) )
#define X86IM_IO_IP_UNSET_SGDS(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_SGDS ) ^ X86IM_IO_IP_SGDS ) )
#define X86IM_IO_IP_UNSET_SGFS(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_SGFS ) ^ X86IM_IO_IP_SGFS ) )
#define X86IM_IO_IP_UNSET_SGGS(x)                       ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_SGGS ) ^ X86IM_IO_IP_SGGS ) )
#define X86IM_IO_IP_UNSET_REX(x)                        ( (x)->prefix = ( ( (x)->prefix | X86IM_IO_IP_REX  ) ^ X86IM_IO_IP_REX  ) )

// rex prefix

#define X86IM_IO_IP_REX_BIT_W                           0x8 // 48
#define X86IM_IO_IP_REX_BIT_R                           0x4 // 44
#define X86IM_IO_IP_REX_BIT_X                           0x2 // 42
#define X86IM_IO_IP_REX_BIT_B                           0x1 // 41

#define X86IM_IO_IP_HAS_REX_W(x)                        ( ( (x)->rexp >> 0x3 ) & 0x1 )  // W: 0/1
#define X86IM_IO_IP_HAS_REX_R(x)                        ( ( (x)->rexp >> 0x2 ) & 0x1 )  // R: 0/1
#define X86IM_IO_IP_HAS_REX_X(x)                        ( ( (x)->rexp >> 0x1 ) & 0x1 )  // X: 0/1
#define X86IM_IO_IP_HAS_REX_B(x)                        ( ( (x)->rexp & 0x1 ) )         // B: 0/1

#define X86IM_IO_IP_SET_REX_W(x)                        ( (x)->rexp |= X86IM_IO_IP_REX_BIT_W )
#define X86IM_IO_IP_SET_REX_R(x)                        ( (x)->rexp |= X86IM_IO_IP_REX_BIT_R )
#define X86IM_IO_IP_SET_REX_X(x)                        ( (x)->rexp |= X86IM_IO_IP_REX_BIT_X )
#define X86IM_IO_IP_SET_REX_B(x)                        ( (x)->rexp |= X86IM_IO_IP_REX_BIT_B )

#define X86IM_IO_IP_UNSET_REX_W(x)                      ( (x)->rexp = ( ( (x)->rexp | X86IM_IO_IP_REX_BIT_W ) ^ X86IM_IO_IP_REX_BIT_W ) )
#define X86IM_IO_IP_UNSET_REX_R(x)                      ( (x)->rexp = ( ( (x)->rexp | X86IM_IO_IP_REX_BIT_R ) ^ X86IM_IO_IP_REX_BIT_R ) )
#define X86IM_IO_IP_UNSET_REX_X(x)                      ( (x)->rexp = ( ( (x)->rexp | X86IM_IO_IP_REX_BIT_X ) ^ X86IM_IO_IP_REX_BIT_X ) )
#define X86IM_IO_IP_UNSET_REX_B(x)                      ( (x)->rexp = ( ( (x)->rexp | X86IM_IO_IP_REX_BIT_B ) ^ X86IM_IO_IP_REX_BIT_B ) )

// prefix order

#define X86IM_IO_IP_GET_LOCK_POS(x)                     ( (x)->prefix_order & 0xF )
#define X86IM_IO_IP_GET_REP_POS(x)                      ( ( (x)->prefix_order >> 6  ) & 0x7 )
#define X86IM_IO_IP_GET_OPSZ_POS(x)                     ( ( (x)->prefix_order >> 12 ) & 0x7 )
#define X86IM_IO_IP_GET_ADSZ_POS(x)                     ( ( (x)->prefix_order >> 18 ) & 0x7 )
#define X86IM_IO_IP_GET_SGXS_POS(x)                     ( ( (x)->prefix_order >> 24 ) & 0x7 )

#define X86IM_IO_IP_SET_LOCK_POS(x,p)                   ( (x)->prefix_order |= ( (p) & 0x7 ) )
#define X86IM_IO_IP_SET_REP_POS(x,p)                    ( (x)->prefix_order |= ( ( (p) & 0x7 ) << 6 ) )
#define X86IM_IO_IP_SET_OPSZ_POS(x,p)                   ( (x)->prefix_order |= ( ( (p) & 0x7 ) << 12 ) )
#define X86IM_IO_IP_SET_ADSZ_POS(x,p)                   ( (x)->prefix_order |= ( ( (p) & 0x7 ) << 18 ) )
#define X86IM_IO_IP_SET_SGXS_POS(x,p)                   ( (x)->prefix_order |= ( ( (p) & 0x7 ) << 24 ) )

// instruction flags

#define X86IM_IO_IF_PFX                                 0x00000001  // instr has valid prefix
#define X86IM_IO_IF_SGP                                 0x00000002  // instr has seg reg prefix
#define X86IM_IO_IF_SEL                                 0x00000004  // instr has explicit segment selector
#define X86IM_IO_IF_MEM_OP                              0x00000008  // instr has memory operand
#define X86IM_IO_IF_REG_OP                              0x00000010  // instr has register(s) operand
#define X86IM_IO_IF_IMM_OP                              0x00000020  // instr has immediate operand
#define X86IM_IO_IF_EXP_OP                              0x00000040  // instr has some explicit operand
#define X86IM_IO_IF_IMP_OP                              0x00000080  // instr has some implicit operand
#define X86IM_IO_IF_MODRM                               0x00000100  // instr has modrm byte: x86di.modrm
#define X86IM_IO_IF_SIB                                 0x00000200  // instr has sib byte: x86di.sib
#define X86IM_IO_IF_3DNS                                0x00000400  // instr is 3dnow instr and has suffix byte
#define X86IM_IO_IF_SOMI                                0x00000800  // instr is SOMI: check IF_MP for prefix
#define X86IM_IO_IF_MP                                  0x00001000  // instr is SOMI and has mandatory prefix
#define X86IM_IO_IF_WBIT                                0x00002000  // instr has w_bit: x86di.w_bit
#define X86IM_IO_IF_SBIT                                0x00004000  // instr has s_bit: x86di.s_bit
#define X86IM_IO_IF_DBIT                                0x00008000  // instr has d_bit: x86di.d_bit
#define X86IM_IO_IF_TTTN                                0x00010000  // instr has tttn field: x86di.tttn_fld
#define X86IM_IO_IF_GGFLD                               0x00020000  // instr has gg field: x86di.gg_fld( mmx/ssex instr only )
#define X86IM_IO_IF_NZ                                  0x00040000  // instr name depends on size
#define X86IM_IO_IF_NC                                  0x00080000  // instr name depends on condicion

#define X86IM_IO_IF_HAS(x,f)                            ( (x)->flags & (f) )

#define X86IM_IO_IF_HAS_PFX(x)                          ( ( (x)->flags >> 0x00 ) & 0x1 )
#define X86IM_IO_IF_HAS_SGP(x)                          ( ( (x)->flags >> 0x01 ) & 0x1 )
#define X86IM_IO_IF_HAS_SEL(x)                          ( ( (x)->flags >> 0x02 ) & 0x1 )
#define X86IM_IO_IF_HAS_MEM_OP(x)                       ( ( (x)->flags >> 0x03 ) & 0x1 )
#define X86IM_IO_IF_HAS_REG_OP(x)                       ( ( (x)->flags >> 0x04 ) & 0x1 )
#define X86IM_IO_IF_HAS_IMM_OP(x)                       ( ( (x)->flags >> 0x05 ) & 0x1 )
#define X86IM_IO_IF_HAS_EXP_OP(x)                       ( ( (x)->flags >> 0x06 ) & 0x1 )
#define X86IM_IO_IF_HAS_IMP_OP(x)                       ( ( (x)->flags >> 0x07 ) & 0x1 )
#define X86IM_IO_IF_HAS_MODRM(x)                        ( ( (x)->flags >> 0x08 ) & 0x1 )
#define X86IM_IO_IF_HAS_SIB(x)                          ( ( (x)->flags >> 0x09 ) & 0x1 )
#define X86IM_IO_IF_HAS_3DNS(x)                         ( ( (x)->flags >> 0x0A ) & 0x1 )
#define X86IM_IO_IF_HAS_SOMI(x)                         ( ( (x)->flags >> 0x0B ) & 0x1 )
#define X86IM_IO_IF_HAS_MP(x)                           ( ( (x)->flags >> 0x0C ) & 0x1 )
#define X86IM_IO_IF_HAS_WBIT(x)                         ( ( (x)->flags >> 0x0D ) & 0x1 )
#define X86IM_IO_IF_HAS_SBIT(x)                         ( ( (x)->flags >> 0x0E ) & 0x1 )
#define X86IM_IO_IF_HAS_DBIT(x)                         ( ( (x)->flags >> 0x0F ) & 0x1 )
#define X86IM_IO_IF_HAS_TTTN(x)                         ( ( (x)->flags >> 0x10 ) & 0x1 )
#define X86IM_IO_IF_HAS_GGFLD(x)                        ( ( (x)->flags >> 0x11 ) & 0x1 )
#define X86IM_IO_IF_HAS_NZ(x)                           ( ( (x)->flags >> 0x12 ) & 0x1 )
#define X86IM_IO_IF_HAS_NC(x)                           ( ( (x)->flags >> 0x13 ) & 0x1 )

#define X86IM_IO_IF_SET(x,f)                            ( (x)->flags |= (f) )

#define X86IM_IO_IF_SET_PFX(x)                          ( (x)->flags |= X86IM_IO_IF_PFX )
#define X86IM_IO_IF_SET_SGP(x)                          ( (x)->flags |= X86IM_IO_IF_SGP )
#define X86IM_IO_IF_SET_SEL(x)                          ( (x)->flags |= X86IM_IO_IF_SEL )
#define X86IM_IO_IF_SET_MEM_OP(x)                       ( (x)->flags |= X86IM_IO_IF_MEM_OP )
#define X86IM_IO_IF_SET_REG_OP(x)                       ( (x)->flags |= X86IM_IO_IF_REG_OP )
#define X86IM_IO_IF_SET_IMM_OP(x)                       ( (x)->flags |= X86IM_IO_IF_IMM_OP )
#define X86IM_IO_IF_SET_EXP_OP(x)                       ( (x)->flags |= X86IM_IO_IF_EXP_OP )
#define X86IM_IO_IF_SET_IMP_OP(x)                       ( (x)->flags |= X86IM_IO_IF_IMP_OP )
#define X86IM_IO_IF_SET_MODRM(x)                        ( (x)->flags |= X86IM_IO_IF_MODRM )
#define X86IM_IO_IF_SET_SIB(x)                          ( (x)->flags |= X86IM_IO_IF_SIB )
#define X86IM_IO_IF_SET_3DNS(x)                         ( (x)->flags |= X86IM_IO_IF_3DNS )
#define X86IM_IO_IF_SET_SOMI(x)                         ( (x)->flags |= X86IM_IO_IF_SOMI )
#define X86IM_IO_IF_SET_MP(x)                           ( (x)->flags |= X86IM_IO_IF_MP )
#define X86IM_IO_IF_SET_WBIT(x)                         ( (x)->flags |= X86IM_IO_IF_WBIT )
#define X86IM_IO_IF_SET_SBIT(x)                         ( (x)->flags |= X86IM_IO_IF_SBIT )
#define X86IM_IO_IF_SET_DBIT(x)                         ( (x)->flags |= X86IM_IO_IF_DBIT )
#define X86IM_IO_IF_SET_TTTN(x)                         ( (x)->flags |= X86IM_IO_IF_TTTN )
#define X86IM_IO_IF_SET_GGFLD(x)                        ( (x)->flags |= X86IM_IO_IF_GGFLD )
#define X86IM_IO_IF_SET_NZ(x)                           ( (x)->flags |= X86IM_IO_IF_NZ )
#define X86IM_IO_IF_SET_NC(x)                           ( (x)->flags |= X86IM_IO_IF_NC )

#define X86IM_IO_IF_UNSET(x,f)                          ( (x)->flags = ( ( (x)->flags | (f) ) ^ (f) ) )

#define X86IM_IO_IF_UNSET_PFX(x)                        ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_PFX ) ^ X86IM_IO_IF_PFX ) )
#define X86IM_IO_IF_UNSET_SGP(x)                        ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_SGP ) ^ X86IM_IO_IF_SGP ) )
#define X86IM_IO_IF_UNSET_SEL(x)                        ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_SEL ) ^ X86IM_IO_IF_SEL ) )
#define X86IM_IO_IF_UNSET_MEM_OP(x)                     ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_MEM_OP ) ^ X86IM_IO_IF_MEM_OP ) )
#define X86IM_IO_IF_UNSET_REG_OP(x)                     ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_REG_OP ) ^ X86IM_IO_IF_REG_OP ) )
#define X86IM_IO_IF_UNSET_IMM_OP(x)                     ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_IMM_OP ) ^ X86IM_IO_IF_IMM_OP ) )
#define X86IM_IO_IF_UNSET_EXP_OP(x)                     ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_EXP_OP ) ^ X86IM_IO_IF_EXP_OP ) )
#define X86IM_IO_IF_UNSET_IMP_OP(x)                     ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_IMP_OP ) ^ X86IM_IO_IF_IMP_OP ) )
#define X86IM_IO_IF_UNSET_MODRM(x)                      ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_MODRM ) ^ X86IM_IO_IF_MODRM ) )
#define X86IM_IO_IF_UNSET_SIB(x)                        ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_SIB ) ^ X86IM_IO_IF_SIB ) )
#define X86IM_IO_IF_UNSET_3DNS(x)                       ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_3DNS ) ^ X86IM_IO_IF_3DNS ) )
#define X86IM_IO_IF_UNSET_SOMI(x)                       ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_SOMI ) ^ X86IM_IO_IF_SOMI ) )
#define X86IM_IO_IF_UNSET_MP(x)                         ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_MP ) ^ X86IM_IO_IF_MP ) )
#define X86IM_IO_IF_UNSET_WBIT(x)                       ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_WBIT ) ^ X86IM_IO_IF_WBIT ) )
#define X86IM_IO_IF_UNSET_SBIT(x)                       ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_SBIT ) ^ X86IM_IO_IF_SBIT ) )
#define X86IM_IO_IF_UNSET_DBIT(x)                       ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_DBIT ) ^ X86IM_IO_IF_DBIT ) )
#define X86IM_IO_IF_UNSET_TTTN(x)                       ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_TTTN ) ^ X86IM_IO_IF_TTTN ) )
#define X86IM_IO_IF_UNSET_GGFLD(x)                      ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_GGFLD ) ^ X86IM_IO_IF_GGFLD ) )
#define X86IM_IO_IF_UNSET_NZ(x)                         ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_NZ ) ^ X86IM_IO_IF_NZ ) )
#define X86IM_IO_IF_UNSET_NC(x)                         ( (x)->flags = ( ( (x)->flags | X86IM_IO_IF_BC ) ^ X86IM_IO_IF_NC ) )

#define X86IM_IO_SET_3DNS(x,s)                          ( (x)->opcode[2] = ( (s) & 0xFF ) )
#define X86IM_IO_GET_3DNS(x)                            ( (x)->opcode[2] )  // get 3dnow prefix/id ( como opcode3 )

// instr mode 32/64bit

#define X86IM_IO_MODE_64BIT                             0x00040000
#define X86IM_IO_MODE_32BIT                             0x00080000

#define X86IM_IO_IS_MODE_32BIT(x)                       ( (x)->mode & X86IM_IO_MODE_32BIT )
#define X86IM_IO_IS_MODE_64BIT(x)                       ( (x)->mode & X86IM_IO_MODE_64BIT )

#define X86IM_IO_SET_MODE(x,m)                          ( (x)->mode |= ( (m) & (X86IM_IO_MODE_32BIT|X86IM_IO_MODE_64BIT) ) )
#define X86IM_IO_SET_MODE_32BIT(x)                      ( (x)->mode |= X86IM_IO_MODE_32BIT )
#define X86IM_IO_SET_MODE_64BIT(x)                      ( (x)->mode |= X86IM_IO_MODE_64BIT )

// XXX: This is not fucking portable. at least not standard, and not supported by GCC
//#pragma pack( push, 1 )

typedef struct _x86im_instr_object                      // x86 decoded/generated instruction:
{
    unsigned long mode;                                 // mode: 32/64bits
    unsigned long flags;                                // instr flags
    unsigned long id;                                   // instr id
    unsigned long grp;                                  // instr grp & subgrp
    unsigned long mnm;                                  // instr mnemonic

    unsigned long len;                                  // total instr length

    unsigned char def_opsz;                             // default operand size: 1/2/4/8
    unsigned char def_adsz;                             // default address size: 16bit = 2 | 32bit = 4 | 64bit = 8

    unsigned char opcode[3];                            // instr opcodes: up to 3
    unsigned char opcode_count;                         // instr opcode count

    unsigned short prefix;                              // instr prefixes ( mask )
    unsigned char prefix_values[4];                     // prefixes
    unsigned char prefix_count;                         // instr prefix count
    unsigned long prefix_order;                         // instr prefix order
    unsigned char rexp;                                 // REX prefix
    unsigned char somimp;                               // mandatory prefix: SOMI instr only: 0x66|0xF2|0xF3
    unsigned char n3did;                                // 3dnow instr id
    unsigned char seg;                                  // implicit segment register used by mem operands:

    unsigned char w_bit;                                // wide bit value: 0/1 - if IF_WBIT
    unsigned char s_bit;                                // sign-extend bit value: 0/1 - if IF_SBIT
    unsigned char d_bit;                                // direction bit value: 0/1 - if IF_DBIT
    unsigned char gg_fld;                               // granularity field value: 0-2 ( mmx ) - if IF_GGFLD
    unsigned char tttn_fld;                             // condition test field value: if IF_TTTN

    unsigned short selector;                            // explicit segment selector used by CALL/JMP far: IF_SEL

    unsigned long imm_size;                             // imm size: 0 | (1/2/4/8)
    unsigned long long imm;                             // imm value: 64bit max value ( if imm_size != 0 )

    unsigned long disp_size;                            // disp size: 0 | (1/2/4/8)
    unsigned long long disp;                            // disp value: 64bit max value ( if disp_size != 0 )

    unsigned char mem_flags;                            // mem flags: src/dst/..
    unsigned short mem_am;                              // addressing mode
    unsigned short mem_size;                            // operand size ( xxx ptr )
    unsigned char mem_base;                             // base reg : grp+id
    unsigned char mem_index;                            // index reg: grp+id
    unsigned char mem_scale;                            // scale reg: grp+id

    unsigned char modrm;                                // modrm byte value & fields: if IF_MODRM
    unsigned char sib;                                  // sib byte value & fields: if IF_SIB

    unsigned long rop[4];                               // imp/exp reg op array
    unsigned char rop_count;                            // imp/exp reg op count

    unsigned int status;
    void *data;

} x86im_instr_object;

// #pragma pack( pop )

#endif  // __X86IM_IO_H__
